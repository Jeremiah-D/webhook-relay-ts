/**
 * WR-57: scheduled delivery — the `deliver_at` delay queue.
 *
 * An inbound event may declare a future delivery time via the
 * `x-deliver-at` header (epoch ms, or an HTTP-date). Until that instant
 * arrives the delivery is *parked*: it is not attempted, and the parking
 * consumes nothing — no attempt is counted, no retry-budget token is
 * spent (WR-38), no quota token (WR-15), no circuit-breaker verdict
 * (WR-10), and no backoff timer or jitter is scheduled (WR-02). When the
 * instant arrives the item is handed back to the queue's normal path, so
 * retry / dead-letter / circuit / quota / budget / SSE delivery events
 * all apply from the first *actual* attempt.
 *
 * Parking is in-memory only: like the WR-50 pause and the WR-52 delivery
 * window, the clock is injectable so tests pin time deterministically.
 * Unlike the WR-49 durable queue, a parked item is *not* journaled — a
 * restart does not recover it (documented honestly in the README).
 *
 * Timer hygiene: exactly one timer is ever armed (for the heap head), the
 * default factory unrefs it so a far-future `deliver_at` never pins the
 * process open, and delays are clamped to `2^31 - 1` ms — Node would
 * otherwise collapse an overflowing `setTimeout` to ~1ms with a warning.
 * A clamped fire that finds the head not yet due simply re-arms.
 */

import type { RetryItem } from "./retry.ts";
import { newTraceId } from "./trace.ts";
import { parseCronExpression, nextCronOccurrence, type CronExpression } from "./cron.ts";

/** Inbound header declaring a future delivery time. */
export const DELIVER_AT_HEADER = "x-deliver-at";

/** Largest delay a single `setTimeout` can hold without overflowing. */
const MAX_TIMER_MS = 2 ** 31 - 1;

/** Epoch-ms integers, optional leading `-` (a pre-1970 instant is past-due). */
const EPOCH_MS_RE = /^-?\d+$/;

/**
 * The three HTTP-date shapes from RFC 9110 §5.6.7 — IMF-fixdate, RFC 850,
 * and asctime. `Date.parse` is far more lenient than any of these (it
 * reads `"1.5"` as a month.day date), so the shape gate runs first: a
 * value that is neither an epoch-ms integer nor one of these shapes is
 * rejected, and `Date.parse` only converts, never validates.
 */
const HTTP_DATE_RES = [
  /^[A-Za-z]{3}, \d{2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2} GMT$/, // IMF-fixdate
  /^[A-Za-z]+, \d{2}-[A-Za-z]{3}-\d{2} \d{2}:\d{2}:\d{2} GMT$/, // RFC 850
  /^[A-Za-z]{3} [A-Za-z]{3} {1,2}\d{1,2} \d{2}:\d{2}:\d{2} \d{4}$/, // asctime
];

/**
 * Parse an `x-deliver-at` header value: a decimal epoch-ms integer, or an
 * HTTP-date (IMF-fixdate / RFC 850 / asctime, per RFC 9110). Returns
 * `undefined` for an absent header. Anything else — empty, fractional,
 * non-numeric, a non-HTTP-date string, or an epoch outside the
 * safe-integer range — throws `RangeError` so the intake can answer 400
 * fail-fast and never enqueue the event.
 */
export function parseDeliverAtHeader(
  value: string | string[] | undefined
): number | undefined {
  const raw = Array.isArray(value) ? value[0] : value;
  if (raw === undefined) return undefined;
  const v = raw.trim();
  if (v.length === 0) {
    throw new RangeError("x-deliver-at must not be empty");
  }
  if (EPOCH_MS_RE.test(v)) {
    const n = Number(v);
    if (!Number.isSafeInteger(n)) {
      throw new RangeError(`x-deliver-at epoch ms is not a safe integer: ${v}`);
    }
    return n;
  }
  if (!HTTP_DATE_RES.some((re) => re.test(v))) {
    throw new RangeError(`x-deliver-at is neither epoch ms nor a valid HTTP-date: ${v}`);
  }
  const t = Date.parse(v);
  if (Number.isNaN(t)) {
    throw new RangeError(`x-deliver-at HTTP-date does not parse to a time: ${v}`);
  }
  return t;
}

/** Operator-facing metadata for one parked delivery. The payload is never exposed. */
export interface ScheduledDeliveryInfo {
  id: string;
  targetUrl: string;
  /** End-to-end trace ID (see `src/trace.ts`), minted at intake like every other delivery. */
  traceId: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  /** Absolute delivery time, epoch ms. One-shot (WR-57) only. */
  deliverAt?: number;
  /** ISO-8601 rendering of `deliverAt`. One-shot (WR-57) only. */
  deliverAtIso?: string;
  /** Delivery lane; present only when set. */
  priority?: RetryItem["priority"];
  /**
   * WR-80: present and true for cron-recurring schedules. Recurring
   * entries carry `cron` / `nextAt` instead of `deliverAt`.
   */
  recurring?: boolean;
  /** Original cron expression text; present when `recurring`. */
  cron?: string;
  /** Next fire instant, epoch ms; present when `recurring`. */
  nextAt?: number;
  /** ISO-8601 rendering of `nextAt`; present when `recurring`. */
  nextAtIso?: string;
  /** True when the schedule is paused; present when `recurring`. */
  paused?: boolean;
}

/** Scheduled-delivery counters: currently parked plus cumulative. */
export interface ScheduledStats {
  /** Deliveries currently parked, waiting for their `deliver_at`. */
  pending: number;
  /** Cumulative deliveries ever parked. */
  scheduled: number;
  /** Cumulative parked deliveries whose `deliver_at` arrived. */
  due: number;
  /** Cumulative parked deliveries canceled before their `deliver_at`. */
  canceled: number;
  /** WR-80: cron-recurring schedules currently registered (paused included). */
  recurring: number;
  /** WR-80: cumulative cron occurrences ever generated. */
  fired: number;
}

/** Injection points for {@link ScheduledDeliveryQueue}. */
export interface ScheduledQueueOptions {
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
  /**
   * Scheduler factory; defaults to an unref'd real `setTimeout` so a
   * parked far-future delivery never pins the process open (same hygiene
   * as `src/autoreplay.ts` / `src/downstream-probe.ts`).
   */
  setTimer?: (fn: () => void, ms: number) => { clear(): void };
  clearTimer?: (handle: { clear(): void }) => void;
  /**
   * Called with the parked items whose `deliverAt` arrived, in deliverAt
   * order (FIFO among equal instants). The items are already removed from
   * the scheduler when this fires — the callee routes them into the
   * normal delivery path.
   */
  onDue?: (items: RetryItem[]) => void;
}

interface HeapNode {
  /** One-shot item id, or recurring schedule id (the two namespaces are disjoint). */
  id: string;
  /** Fire instant, epoch ms: `deliverAt` for one-shots, next cron fire for recurring. */
  at: number;
  /** Tie-break: FIFO among equal fire instants. */
  seq: number;
  /** True for recurring-schedule nodes (reinserted after every fire). */
  recurring: boolean;
}

interface ParkedEntry {
  item: RetryItem;
  deliverAt: number;
}

/**
 * WR-80: a registered recurring schedule. The intake-time item is the
 * *template*: every cycle generates a fresh delivery from it (fresh id,
 * fresh traceId — see {@link buildOccurrence}), so per-cycle deliveries
 * are independent events that each walk the normal delivery path.
 */
interface RecurringEntry {
  template: RetryItem;
  cron: CronExpression;
  /** Original cron expression text (operator display / audit). */
  cronSource: string;
  nextAt: number;
  paused: boolean;
  /** 1-based count of occurrences generated so far (also the occurrence id suffix). */
  firedCount: number;
  createdAt: number;
}

/**
 * In-memory delay queue: parked deliveries ordered by `deliverAt` in a
 * binary min-heap, with exactly one timer armed for the head. Parking is
 * eager-delete (cancel removes the heap node in O(log n) via an index
 * map), so the heap never accumulates garbage.
 *
 * Lifecycle is driven by the owner (the `RetryQueue`): the scheduler
 * starts disarmed, `arm()` arms the head timer, `disarm()` clears the
 * timer but keeps the heap (for `stop()`), and `clear()` drops everything
 * (for `shutdown()` — parked-but-not-due deliveries are dropped exactly
 * like backoff-waiting ones, since they were never delivered).
 */
export class ScheduledDeliveryQueue {
  private readonly now: () => number;
  private readonly setTimer: (fn: () => void, ms: number) => { clear(): void };
  private readonly clearTimer: (handle: { clear(): void }) => void;
  private readonly onDue?: (items: RetryItem[]) => void;
  private readonly items = new Map<string, ParkedEntry>();
  /** WR-80: recurring schedules, keyed by schedule id. */
  private readonly schedules = new Map<string, RecurringEntry>();
  private readonly heap: HeapNode[] = [];
  private readonly index = new Map<string, number>();
  private seq = 0;
  private armed = false;
  private timer: { clear(): void } | undefined;
  private armedId: string | undefined;
  private totalScheduled = 0;
  private totalDue = 0;
  private totalCanceled = 0;
  /** WR-80: cumulative cron occurrences generated. */
  private totalFired = 0;

  constructor(opts: ScheduledQueueOptions = {}) {
    if (opts.now !== undefined && typeof opts.now !== "function") {
      throw new RangeError(`scheduled.now must be a function, got ${typeof opts.now}`);
    }
    if (opts.setTimer !== undefined && typeof opts.setTimer !== "function") {
      throw new RangeError("scheduled.setTimer must be a function");
    }
    if (opts.clearTimer !== undefined && typeof opts.clearTimer !== "function") {
      throw new RangeError("scheduled.clearTimer must be a function");
    }
    if (opts.onDue !== undefined && typeof opts.onDue !== "function") {
      throw new RangeError("scheduled.onDue must be a function");
    }
    this.now = opts.now ?? Date.now;
    this.setTimer =
      opts.setTimer ??
      ((fn, ms) => {
        const t = setTimeout(fn, ms);
        // A parked delivery must never pin the process open just because
        // its deliver_at is far in the future.
        (t as unknown as { unref?: () => unknown }).unref?.();
        return { clear: () => clearTimeout(t) };
      });
    this.clearTimer = opts.clearTimer ?? ((h) => h.clear());
    this.onDue = opts.onDue;
  }

  /**
   * Park `item` until its `deliverAt` (epoch ms, must be in the future).
   * Throws `RangeError` on a non-finite / past-due `deliverAt` and
   * `Error` on a duplicate id. The item is copied; later mutations of
   * the caller's object do not affect the parked entry.
   */
  park(item: RetryItem): void {
    const deliverAt = item.deliverAt;
    if (typeof deliverAt !== "number" || !Number.isFinite(deliverAt)) {
      throw new RangeError(
        `deliver_at must be a finite epoch-ms number, got ${String(deliverAt)}`
      );
    }
    if (typeof item.id !== "string" || item.id.length === 0) {
      throw new RangeError("scheduled item id must be a non-empty string");
    }
    if (this.items.has(item.id)) {
      throw new Error(`Duplicate scheduled id: ${item.id}`);
    }
    if (this.schedules.has(item.id)) {
      throw new Error(`Duplicate scheduled id: ${item.id} is already a recurring schedule`);
    }
    const at = this.now();
    if (deliverAt <= at) {
      throw new RangeError(
        `deliver_at must be in the future to park (deliverAt=${deliverAt}, now=${at}); ` +
          "past-due items take the normal delivery path, never the delay queue"
      );
    }
    this.items.set(item.id, { item: { ...item }, deliverAt });
    this.pushNode({ id: item.id, at: deliverAt, seq: this.seq++, recurring: false });
    this.totalScheduled += 1;
    // Re-arm only when the newcomer became the head — otherwise the armed
    // timer already covers it.
    if (this.armed && this.heap[0].id === item.id) this.rearm();
  }

  /**
   * Cancel a parked delivery: it will never be delivered. Returns `true`
   * when a parked item was canceled, `false` for an unknown id
   * (including ids that already fired or were never scheduled).
   */
  cancel(id: string): boolean {
    const entry = this.items.get(id);
    if (entry === undefined) return false;
    this.items.delete(id);
    const i = this.index.get(id);
    if (i !== undefined) this.removeAt(i);
    this.totalCanceled += 1;
    if (this.armed && this.armedId === id) this.rearm();
    return true;
  }

  /**
   * WR-80: register a recurring cron schedule. `item` is the *template* —
   * copied at registration; every cycle generates a fresh delivery from it
   * (see {@link buildOccurrence}). `item.id` becomes the schedule id and
   * must be unique across one-shot items and schedules. Returns the
   * schedule id. Throws `RangeError` on an invalid cron expression and
   * `Error` on a duplicate id. A `deliverAt` on the template is ignored —
   * recurring and one-shot parking are disjoint (a request declaring both
   * headers is rejected at intake).
   */
  addRecurring(item: RetryItem, cronExpression: string): string {
    if (typeof item.id !== "string" || item.id.length === 0) {
      throw new RangeError("recurring schedule item id must be a non-empty string");
    }
    if (this.items.has(item.id) || this.schedules.has(item.id)) {
      throw new Error(`Duplicate scheduled id: ${item.id}`);
    }
    const cron = parseCronExpression(cronExpression);
    const at = this.now();
    const nextAt = nextCronOccurrence(cron, at);
    const { deliverAt: _ignored, ...rest } = item;
    this.schedules.set(item.id, {
      template: { ...rest },
      cron,
      cronSource: cron.source,
      nextAt,
      paused: false,
      firedCount: 0,
      createdAt: at,
    });
    this.pushNode({ id: item.id, at: nextAt, seq: this.seq++, recurring: true });
    if (this.armed && this.heap[0].id === item.id) this.rearm();
    return item.id;
  }

  /**
   * WR-80: pause a recurring schedule — no further occurrences are
   * generated until {@link resumeSchedule}. Already-generated deliveries
   * are unaffected. Returns `true` on a real pause, `false` for an
   * unknown schedule id (a paused schedule returns `true` again).
   */
  pauseSchedule(id: string): boolean {
    const entry = this.schedules.get(id);
    if (entry === undefined) return false;
    if (!entry.paused) {
      entry.paused = true;
      const i = this.index.get(id);
      if (i !== undefined) this.removeAt(i);
      if (this.armed && this.armedId === id) this.rearm();
    }
    return true;
  }

  /**
   * WR-80: resume a paused schedule. The next occurrence is computed from
   * *now* — cycles missed while paused are skipped, never backfilled
   * (cron semantics). Returns `true` on a real resume, `false` for an
   * unknown id (an already-running schedule returns `true`, unchanged).
   */
  resumeSchedule(id: string): boolean {
    const entry = this.schedules.get(id);
    if (entry === undefined) return false;
    if (entry.paused) {
      entry.paused = false;
      entry.nextAt = nextCronOccurrence(entry.cron, this.now());
      this.pushNode({ id, at: entry.nextAt, seq: this.seq++, recurring: true });
      if (this.armed && this.heap[0].id === id) this.rearm();
    }
    return true;
  }

  /** WR-80: next fire instant of a recurring schedule, or `undefined` when unknown/paused. */
  nextFireAt(id: string): number | undefined {
    const entry = this.schedules.get(id);
    return entry !== undefined && !entry.paused ? entry.nextAt : undefined;
  }

  /** True when `id` is currently parked (one-shot) or registered (recurring). */
  has(id: string): boolean {
    return this.items.has(id) || this.schedules.has(id);
  }

  /** Deliveries currently parked. */
  pendingCount(): number {
    return this.items.size;
  }

  /**
   * Pending scheduled deliveries, earliest fire first: operator metadata
   * only (id, targetUrl, traceId, tenant, priority) — the payload is never
   * exposed. One-shot entries carry `deliverAt`; recurring schedules
   * (WR-80) carry `recurring: true` plus `cron` / `nextAt` / `paused`.
   */
  list(): ScheduledDeliveryInfo[] {
    const out: ScheduledDeliveryInfo[] = [];
    for (const { item, deliverAt } of this.items.values()) {
      out.push({
        id: item.id,
        targetUrl: item.targetUrl,
        traceId: item.traceId as string,
        ...(item.tenantId === undefined ? {} : { tenant: item.tenantId }),
        deliverAt,
        deliverAtIso: new Date(deliverAt).toISOString(),
        ...(item.priority === undefined ? {} : { priority: item.priority }),
      });
    }
    for (const [id, entry] of this.schedules) {
      const t = entry.template;
      out.push({
        id,
        targetUrl: t.targetUrl,
        traceId: t.traceId as string,
        ...(t.tenantId === undefined ? {} : { tenant: t.tenantId }),
        ...(t.priority === undefined ? {} : { priority: t.priority }),
        recurring: true,
        cron: entry.cronSource,
        nextAt: entry.nextAt,
        nextAtIso: new Date(entry.nextAt).toISOString(),
        paused: entry.paused,
      });
    }
    // Heap order is not sorted order — sort the snapshot deterministically.
    const fireAt = (e: ScheduledDeliveryInfo) => e.deliverAt ?? e.nextAt ?? 0;
    out.sort((a, b) => fireAt(a) - fireAt(b) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
    return out;
  }

  /** Currently parked plus cumulative scheduled / due / canceled (WR-80 adds recurring / fired). */
  stats(): ScheduledStats {
    return {
      pending: this.items.size,
      scheduled: this.totalScheduled,
      due: this.totalDue,
      canceled: this.totalCanceled,
      recurring: this.schedules.size,
      fired: this.totalFired,
    };
  }

  /** Arm the head timer (called by the owner's `start()`). */
  arm(): void {
    this.armed = true;
    this.rearm();
  }

  /**
   * Clear the armed timer but keep the heap (called by the owner's
   * `stop()`); the next `arm()` resumes from the head.
   */
  disarm(): void {
    this.armed = false;
    this.clearArmedTimer();
  }

  /**
   * Drop everything: clear the timer and forget all parked items and
   * recurring schedules (called by the owner's `shutdown()`).
   * Parked-but-not-due deliveries are dropped exactly like backoff-waiting
   * ones — they were never delivered — and recurring registrations are
   * in-memory only: a restart does not recover them (documented honestly
   * in the README, same as WR-57 parking). Cumulative counters reset with
   * everything else.
   */
  clear(): void {
    this.disarm();
    this.items.clear();
    this.schedules.clear();
    this.heap.length = 0;
    this.index.clear();
    this.totalScheduled = 0;
    this.totalDue = 0;
    this.totalCanceled = 0;
    this.totalFired = 0;
  }

  private clearArmedTimer(): void {
    if (this.timer !== undefined) {
      this.clearTimer(this.timer);
      this.timer = undefined;
    }
    this.armedId = undefined;
  }

  private rearm(): void {
    this.clearArmedTimer();
    if (!this.armed || this.heap.length === 0) return;
    const head = this.heap[0];
    // Clamp: Node collapses a setTimeout delay > 2^31-1 to ~1ms with a
    // warning. A clamped fire that finds the head not yet due simply
    // re-arms (see onTimerFire), so a far-future fire instant wakes the
    // scheduler periodically without ever delivering early.
    const ms = Math.max(0, Math.min(head.at - this.now(), MAX_TIMER_MS));
    this.armedId = head.id;
    this.timer = this.setTimer(() => this.onTimerFire(), ms);
  }

  private onTimerFire(): void {
    this.timer = undefined;
    this.armedId = undefined;
    const at = this.now();
    const due: RetryItem[] = [];
    while (this.heap.length > 0 && this.heap[0].at <= at) {
      const node = this.popHead()!;
      if (node.recurring) {
        // WR-80: a cron fire generates one fresh delivery from the
        // template, then the schedule is reinserted at its next
        // occurrence — computed from *now*, so cycles missed while the
        // process was busy are skipped, never backfilled. Reinsert before
        // handing items over: a throwing onDue must not lose the schedule.
        const entry = this.schedules.get(node.id);
        // Eager deletion keeps the heap clean; a missing or paused entry
        // means the schedule went away on the same tick as the fire.
        if (entry === undefined || entry.paused) continue;
        entry.firedCount += 1;
        due.push(this.buildOccurrence(node.id, entry));
        this.totalFired += 1;
        entry.nextAt = nextCronOccurrence(entry.cron, at);
        this.pushNode({ id: node.id, at: entry.nextAt, seq: this.seq++, recurring: true });
        continue;
      }
      // Eager deletion keeps the heap clean; a missing entry means the
      // item was canceled on the same tick as the fire — skip it.
      const entry = this.items.get(node.id);
      if (entry === undefined) continue;
      this.items.delete(node.id);
      due.push(entry.item);
      this.totalDue += 1;
    }
    // Re-arm before handing items over: a throwing onDue must not leave
    // the scheduler without a timer for the remaining heap.
    this.rearm();
    if (due.length > 0) this.onDue?.(due);
    // No due items: a spurious/early fire (or a clamped far-future fire
    // instant) — the rearm above already covers the current head.
  }

  /**
   * WR-80: build one cron occurrence from the schedule template. The
   * occurrence is an independent delivery: a fresh id (`<scheduleId>#<n>`),
   * a fresh traceId, and `scheduleId` marking it as cron-generated (the
   * owner audits `scheduled_fired` on it). `deliverAt` never survives onto
   * an occurrence (recurring and one-shot parking are disjoint), and
   * `enqueuedAt` is stripped so the WR-76 end-to-end deadline clock starts
   * fresh per cycle — each occurrence gets an independent deadline.
   */
  private buildOccurrence(scheduleId: string, entry: RecurringEntry): RetryItem {
    const { deliverAt: _d, enqueuedAt: _e, traceId: _t, id: _i, ...rest } = entry.template;
    return {
      ...rest,
      id: `${scheduleId}#${entry.firedCount}`,
      traceId: newTraceId(),
      scheduleId,
    };
  }

  // -- binary min-heap (by deliverAt, FIFO tie-break) with an index map --

  private less(a: HeapNode, b: HeapNode): boolean {
    return a.at < b.at || (a.at === b.at && a.seq < b.seq);
  }

  private swap(i: number, j: number): void {
    const h = this.heap;
    const t = h[i];
    h[i] = h[j];
    h[j] = t;
    this.index.set(h[i].id, i);
    this.index.set(h[j].id, j);
  }

  private siftUp(i: number): void {
    const h = this.heap;
    while (i > 0) {
      const p = (i - 1) >> 1;
      if (this.less(h[p], h[i])) break;
      this.swap(i, p);
      i = p;
    }
  }

  private siftDown(i: number): void {
    const h = this.heap;
    for (;;) {
      const l = 2 * i + 1;
      const r = l + 1;
      let m = i;
      if (l < h.length && this.less(h[l], h[m])) m = l;
      if (r < h.length && this.less(h[r], h[m])) m = r;
      if (m === i) break;
      this.swap(i, m);
      i = m;
    }
  }

  private pushNode(node: HeapNode): void {
    this.heap.push(node);
    this.index.set(node.id, this.heap.length - 1);
    this.siftUp(this.heap.length - 1);
  }

  private popHead(): HeapNode | undefined {
    const h = this.heap;
    if (h.length === 0) return undefined;
    const head = h[0];
    const last = h.pop()!;
    this.index.delete(head.id);
    if (h.length > 0) {
      h[0] = last;
      this.index.set(last.id, 0);
      this.siftDown(0);
    }
    return head;
  }

  private removeAt(i: number): void {
    const h = this.heap;
    const node = h[i];
    const last = h.pop()!;
    this.index.delete(node.id);
    if (i < h.length) {
      h[i] = last;
      this.index.set(last.id, i);
      this.siftUp(i);
      this.siftDown(i);
    }
  }
}
