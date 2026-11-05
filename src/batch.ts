import { randomUUID } from "node:crypto";
import type { RetryItem } from "./retry.ts";

/**
 * Batch delivery merging.
 *
 * When enabled, normal-priority items bound for the same endpoint are held
 * for a short window and merged into a single HTTP delivery instead of one
 * request per event. The point is downstream QPS reduction: a payment
 * provider sending 200 settlement notifications in a burst becomes a handful
 * of batch requests instead of 200 individual ones.
 *
 * Wire contract (uniform): every flushed batch — even a batch holding a
 * single event — is delivered as one item whose payload is the envelope and
 * whose headers are `content-type: application/json` plus `x-batch-id` /
 * `x-batch-size`. A downstream that opts into batching therefore always
 * sees the same shape. The default envelope is JSON:
 *
 *   { "batch_id": "batch:<uuid>", "batched_at": "<iso>",
 *     "events": [ { "id", "payload" (base64), "payload_bytes", "headers" } ] }
 *
 * Payloads ride as base64 because they are arbitrary bytes; per-event
 * headers ride inside the envelope (notably each event's own `x-signature`),
 * so the downstream can still verify every event individually.
 *
 * Semantics worth knowing:
 * - Urgent items bypass batching entirely — the fast lane must not wait.
 * - A flushed batch is one delivery unit: retries and the dead-letter entry
 *   apply to the whole batch, and a replayed batch re-sends every event.
 * - `stop()` flushes pending batches into the queue (they stay queued,
 *   unscheduled, like backoff-waiting items); `shutdown()` flushes and
 *   gives each batch one immediate attempt before draining.
 * - Latency SLO clocks start when the merged batch item is queued, i.e. at
 *   flush time — the batching delay itself is by design, not lateness.
 */

export interface BatchEnvelopeInput {
  /** Server-generated batch id (`batch:<uuid>`). */
  batchId: string;
  /** The merged items, in arrival order. */
  items: RetryItem[];
}

/** Options for batch delivery merging. Disabled unless set. */
export interface BatchOptions {
  /**
   * How long (ms) to hold items for one endpoint before flushing the batch.
   * The window starts with the first buffered item. Default: 250.
   * Must be > 0.
   */
  windowMs?: number;
  /**
   * Flush as soon as this many items for one endpoint are buffered,
   * without waiting for the window to elapse. Default: 50.
   * Must be an integer >= 1.
   */
  maxBatchSize?: number;
  /**
   * Build the wire payload for a flushed batch. Defaults to the JSON
   * envelope described above. A custom envelope lets a downstream that
   * speaks its own batch dialect (e.g. NDJSON) plug in.
   */
  envelope?: (input: BatchEnvelopeInput) => Buffer;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
}

export interface BatchTimers {
  setTimer: (fn: () => void, ms: number) => { clear(): void };
  clearTimer: (handle: { clear(): void }) => void;
}

/**
 * WR-333: partial patch for a live batch-merge revision. Omitted fields
 * keep their live values; an empty patch is a no-op. Merged values are
 * validated against the construction gates (`windowMs` finite > 0,
 * `maxBatchSize` an integer >= 1) — an illegal patch throws `RangeError`
 * and the live values are left untouched.
 */
export interface BatchConfigRevision {
  windowMs?: number;
  maxBatchSize?: number;
}

export interface ResolvedBatchOptions {
  windowMs: number;
  maxBatchSize: number;
  envelope: (input: BatchEnvelopeInput) => Buffer;
  now: () => number;
  setTimer: (fn: () => void, ms: number) => { clear(): void };
  clearTimer: (handle: { clear(): void }) => void;
}

export function resolveBatchOptions(opts: BatchOptions, timers: BatchTimers): ResolvedBatchOptions {
  const windowMs = opts.windowMs ?? 250;
  const maxBatchSize = opts.maxBatchSize ?? 50;
  if (!Number.isFinite(windowMs) || windowMs <= 0) {
    throw new RangeError(`batch.windowMs must be > 0, got ${opts.windowMs}`);
  }
  if (!Number.isInteger(maxBatchSize) || maxBatchSize < 1) {
    throw new RangeError(`batch.maxBatchSize must be an integer >= 1, got ${opts.maxBatchSize}`);
  }
  return {
    windowMs,
    maxBatchSize,
    envelope: opts.envelope ?? defaultEnvelope,
    now: opts.now ?? Date.now,
    setTimer: timers.setTimer,
    clearTimer: timers.clearTimer,
  };
}

/** Default JSON envelope; see the module doc for the contract. */
export function defaultEnvelope({ batchId, items }: BatchEnvelopeInput): Buffer {
  return Buffer.from(
    JSON.stringify({
      batch_id: batchId,
      batched_at: new Date().toISOString(),
      events: items.map((it) => ({
        id: it.id,
        payload: it.payload.toString("base64"),
        payload_bytes: it.payload.length,
        headers: it.headers,
      })),
    })
  );
}

/** Fresh batch id for a flushed batch. */
export function newBatchId(): string {
  return `batch:${randomUUID()}`;
}

/**
 * Per-endpoint batch collector: buffers items, flushes on window expiry or
 * when `maxBatchSize` is reached. The queue owns delivery; the collector
 * only decides *when* a group of items becomes one merged item.
 */
export class BatchCollector {
  private readonly buffers = new Map<string, { items: RetryItem[]; timer: { clear(): void } }>();
  private readonly bufferedIds = new Set<string>();
  private readonly opts: ResolvedBatchOptions;
  private readonly onFlush: (endpoint: string, items: RetryItem[]) => void;

  constructor(opts: ResolvedBatchOptions, onFlush: (endpoint: string, items: RetryItem[]) => void) {
    this.opts = opts;
    this.onFlush = onFlush;
  }

  /** True when `id` is sitting in a batch buffer (not yet flushed). */
  has(id: string): boolean {
    return this.bufferedIds.has(id);
  }

  /** Buffer `item`; flushes early when the endpoint hits `maxBatchSize`. */
  add(item: RetryItem): void {
    let buf = this.buffers.get(item.targetUrl);
    if (!buf) {
      const endpoint = item.targetUrl;
      const timer = this.opts.setTimer(() => this.flushEndpoint(endpoint), this.opts.windowMs);
      buf = { items: [], timer };
      this.buffers.set(endpoint, buf);
    }
    buf.items.push(item);
    this.bufferedIds.add(item.id);
    if (buf.items.length >= this.opts.maxBatchSize) {
      this.flushEndpoint(item.targetUrl);
    }
  }

  /** Endpoints with a live buffer. */
  endpoints(): string[] {
    return [...this.buffers.keys()];
  }

  /** Items still inside a window (`endpoint` narrows to one endpoint). */
  bufferedCount(endpoint?: string): number {
    if (endpoint !== undefined) return this.buffers.get(endpoint)?.items.length ?? 0;
    let n = 0;
    for (const b of this.buffers.values()) n += b.items.length;
    return n;
  }

  /** Flush one endpoint's buffer now (no-op when there is none). */
  flushEndpoint(endpoint: string): void {
    const buf = this.buffers.get(endpoint);
    if (!buf) return;
    this.buffers.delete(endpoint);
    this.opts.clearTimer(buf.timer);
    for (const it of buf.items) this.bufferedIds.delete(it.id);
    if (buf.items.length === 0) return;
    this.onFlush(endpoint, buf.items);
  }

  /** Flush every endpoint's buffer now. */
  flushAll(): void {
    for (const endpoint of this.endpoints()) this.flushEndpoint(endpoint);
  }

  /**
   * WR-333: revise the live merge window and/or cap at runtime (partial —
   * omitted fields keep their live values). The merged values are
   * validated against the construction gates first — reusing the
   * `resolveBatchOptions` error text — so an illegal patch throws
   * `RangeError` and the live values are left completely untouched.
   *
   * A window change only affects the next buffer: a timer already armed
   * runs out on the old window (WR-311 in-flight-timer precedent).
   * Tightening `maxBatchSize` flushes any buffer already over the new
   * cap at once (WR-329 bucket-clamping semantics); loosening never
   * flushes early. Returns the live values after the revision.
   */
  retune(patch: BatchConfigRevision): { windowMs: number; maxBatchSize: number } {
    const nextWindowMs = patch.windowMs ?? this.opts.windowMs;
    const nextMaxBatchSize = patch.maxBatchSize ?? this.opts.maxBatchSize;
    // Validate-then-apply: the merged values must pass the construction
    // gates before either live value moves.
    if (!Number.isFinite(nextWindowMs) || nextWindowMs <= 0) {
      throw new RangeError(`batch.windowMs must be > 0, got ${patch.windowMs}`);
    }
    if (!Number.isInteger(nextMaxBatchSize) || nextMaxBatchSize < 1) {
      throw new RangeError(`batch.maxBatchSize must be an integer >= 1, got ${patch.maxBatchSize}`);
    }
    // `opts` is `private readonly`, which only forbids reassigning the
    // field — its properties are the live values and are rewritten here
    // in place, so every holder of the same resolved object (notably
    // `RetryQueue.batchResolved`) reads the new values immediately.
    this.opts.windowMs = nextWindowMs;
    this.opts.maxBatchSize = nextMaxBatchSize;
    for (const endpoint of this.endpoints()) {
      if (this.bufferedCount(endpoint) >= nextMaxBatchSize) this.flushEndpoint(endpoint);
    }
    return this.current();
  }

  /** Live merge window / cap snapshot. */
  current(): { windowMs: number; maxBatchSize: number } {
    return { windowMs: this.opts.windowMs, maxBatchSize: this.opts.maxBatchSize };
  }
}
