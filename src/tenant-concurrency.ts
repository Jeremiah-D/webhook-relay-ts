/**
 * Per-tenant outbound concurrency cap (WR-140).
 *
 * The relay-level global gate (`GlobalConcurrencyGate`, WR-51) bounds
 * in-flight deliveries *across the whole relay*; this gate bounds them
 * *per tenant* — at most N deliveries executing concurrently for one
 * `x-tenant-id` tenant, aggregated across all of that tenant's endpoints.
 * The per-endpoint limiter (WR-06, per (tenant, endpoint)) still applies
 * inside: a dispatch needs a slot from each gate it passes.
 *
 * Why per-tenant: a SaaS tenant fanning out across dozens of endpoints
 * can saturate the relay's global cap (or its own downstream) while
 * another tenant's deliveries starve behind it in the global FIFO. The
 * per-tenant cap is the fairness valve between tenants — one tenant's
 * flood queues against its own cap and never occupies another tenant's
 * slots, because each tenant gets an independent gate instance (the
 * WR-48 isolation convention: independent per-tenant state, lazily
 * created, tenants that never appear cost nothing).
 *
 * Semantics (deliberately identical to `GlobalConcurrencyGate`):
 * - FIFO: when the tenant's cap is hit, excess dispatches wait in arrival
 *   order; the oldest waiter dispatches when a slot frees. Waiters are
 *   never dropped, never consume retry budget, and never touch the
 *   circuit breaker — waiting is neutral.
 * - Placement: the queue acquires the tenant gate after the WR-51
 *   global gate and before the per-endpoint limiter — the last
 *   tenant-granularity gate before the sender — and releases it when the
 *   attempt settles (success, failure-scheduled, or dead-lettered); see
 *   `RetryQueue.deliver()`. The urgent lane bypasses the per-endpoint
 *   limiter and this gate alike (both are tenant policy, not relay-level
 *   capacity); it still passes the global gate.
 * - Shutdown: `releaseWaiters()` wakes every waiter with a no-op
 *   release so `stop()`/`shutdown()` never hang on the gate — woken
 *   waiters observe the stopped queue through the normal liveness check
 *   and bail out. No timers are involved (promise FIFO only), so there
 *   is nothing to unref.
 * - Tenant-less deliveries never touch this gate at all: with no
 *   `x-tenant-id` the dispatch path is byte-for-byte the pre-WR-140
 *   behavior (global gate + per-endpoint limiter only).
 * - Runtime revision (WR-328): `retune()` moves one tenant's cap live
 *   — widening pumps out FIFO waiters at once, tightening never revokes
 *   a held slot (new acquisitions queue until in-flight drains back to
 *   the cap) — and `TenantConcurrencyGates.reviseTenant()` records a
 *   per-tenant override on top of the construction default, removable
 *   with `removeTenant()` (the tenant falls back to the default cap).
 */

import { assertValidTenantId } from "./tenant.ts";

/** Snapshot of one tenant's dispatch gate. */
export interface TenantConcurrencyStats {
  /** The tenant id (WR-48 `x-tenant-id`). */
  tenant: string;
  /** Configured per-tenant cap (`Infinity` = unlimited). */
  maxConcurrent: number;
  /** Dispatches currently holding one of this tenant's slots. */
  inFlight: number;
  /** Dispatches queued FIFO for one of this tenant's slots. */
  queuedDepth: number;
  /** Cumulative dispatches that had to wait for one of this tenant's slots. */
  waitsTotal: number;
}

/** Shared validation: a positive integer, or `Infinity` for "no cap". */
export function assertTenantConcurrencyLimit(tenantMaxConcurrent: number): void {
  if (
    !(
      tenantMaxConcurrent === Infinity ||
      (Number.isInteger(tenantMaxConcurrent) && tenantMaxConcurrent >= 1)
    )
  ) {
    throw new RangeError(
      `tenantMaxConcurrent must be a positive integer or Infinity, got ${tenantMaxConcurrent}`
    );
  }
}

/**
 * WR-328: one live per-tenant concurrency revision. `tenant` is the
 * tenant id (`""` = the default tenant, the WR-312/WR-48 convention).
 * `maxConcurrent` is the live cap after the call; `previous` is the
 * effective cap before the revision (on a read it equals the live cap);
 * `overridden` says whether the tenant carries an explicit override
 * after the call.
 */
export interface TenantConcurrencySnapshot {
  /** Tenant id; `""` is the default tenant. */
  tenant: string;
  /** Live per-tenant cap (`Infinity` = unlimited). */
  maxConcurrent: number;
  /** Effective cap before the revision (a read: same as live). */
  previous: number;
  /** Whether the tenant carries an explicit override after the call. */
  overridden: boolean;
}

/**
 * Validate a tenant id for a concurrency revision (WR-328): a string
 * (anything else is a `RangeError` — unlike `assertValidTenantId`,
 * which throws `TypeError` for non-strings); the empty string is the
 * default tenant; any other id follows the WR-48 charset rule.
 */
export function assertTenantConcurrencyTenant(tenant: string): void {
  if (typeof tenant !== "string") {
    throw new RangeError(`tenant must be a string, got ${typeof tenant}`);
  }
  if (tenant === "") return;
  assertValidTenantId(tenant);
}

/**
 * One tenant's dispatch gate: at most `maxConcurrent` deliveries in
 * flight for this tenant across all its endpoints; excess acquisitions
 * wait in FIFO order.
 *
 * Callers must re-check their own liveness after `acquire()` resolves
 * (the queue may have stopped — see `releaseWaiters()` — while they
 * waited) and must always call the returned release function exactly
 * once. Releases cascade to the next waiter, so no one hangs.
 */
export class TenantConcurrencyGate {
  private maxConcurrent: number;
  private inFlight = 0;
  private readonly waiters: Array<(release: () => void) => void> = [];
  private waitsTotal = 0;

  constructor(maxConcurrent: number = Infinity) {
    assertTenantConcurrencyLimit(maxConcurrent);
    this.maxConcurrent = maxConcurrent;
  }

  /** The configured cap (`Infinity` = unlimited). */
  cap(): number {
    return this.maxConcurrent;
  }

  /**
   * WR-328: revise the cap live — the same semantics as
   * `GlobalConcurrencyGate.retune` (WR-313). An illegal value throws
   * `RangeError` and the live cap is untouched; the current cap is a
   * silent no-op.
   *
   * - Tightening never revokes a held slot: in-flight dispatches run
   *   to completion under the old cap. New acquisitions queue until
   *   `inFlight` is back at (or below) the new cap — a release while
   *   `inFlight` is still above the cap drains the count instead of
   *   handing the slot to a waiter (see `release()`).
   * - Widening pumps out waiters immediately, in FIFO order: each
   *   grant takes a fresh slot (`inFlight += 1`) and resolves the
   *   oldest waiter with the usual release function.
   * - Revising to `Infinity` wakes every waiter; revising from
   *   `Infinity` to a finite cap starts limiting at once, with
   *   in-flight dispatches unaffected.
   */
  retune(newCap: number): number {
    assertTenantConcurrencyLimit(newCap);
    if (newCap === this.maxConcurrent) {
      return this.maxConcurrent;
    }
    this.maxConcurrent = newCap;
    while (this.waiters.length > 0 && this.inFlight < this.maxConcurrent) {
      // A fresh slot: the waiter takes it (in-flight grows), unlike
      // release(), where the slot transfers and the count is unchanged.
      this.inFlight += 1;
      const next = this.waiters.shift()!;
      next(() => this.release());
    }
    return this.maxConcurrent;
  }

  /**
   * Resolve when one of the tenant's dispatch slots is free. The waiter
   * count (`waitsTotal`) increments only when the acquisition actually
   * waits — an immediately granted slot is not a wait. Always call the
   * returned function exactly once to hand the slot on.
   */
  acquire(): Promise<() => void> {
    if (this.inFlight < this.maxConcurrent) {
      this.inFlight += 1;
      return Promise.resolve(() => this.release());
    }
    this.waitsTotal += 1;
    return new Promise<() => void>((resolve) => {
      this.waiters.push((release) => resolve(release));
    });
  }

  private release(): void {
    // WR-328: after a tightening retune the in-flight count can sit
    // above the new cap. A release then drains the count instead of
    // transferring the slot: a waiter is a new acquisition, and new
    // acquisitions queue until inFlight is back at (or below) the cap.
    // In steady state inFlight never exceeds the cap, so this guard
    // changes nothing outside a retune.
    const next = this.inFlight <= this.maxConcurrent ? this.waiters.shift() : undefined;
    if (next) {
      // Slot transfers from the releaser to the oldest waiter; the
      // in-flight count is unchanged (no increment here).
      next(() => this.release());
      return;
    }
    this.inFlight -= 1;
  }

  /**
   * Fail-safe for `stop()`/`shutdown()`: wake every waiter with a
   * no-op release. Woken waiters must re-check liveness (the queue is
   * stopped) and bail out instead of dispatching — the no-op release
   * keeps the in-flight count truthful since no slot was ever held.
   * Waiters that arrive after this call queue normally; the queue only
   * calls it while stopping, when no new dispatch should start anyway.
   */
  releaseWaiters(): void {
    const pending = this.waiters.splice(0);
    for (const wake of pending) wake(() => {});
  }

  /** Dispatches currently holding one of this tenant's slots. */
  inFlightCount(): number {
    return this.inFlight;
  }

  /** Dispatches currently queued FIFO for one of this tenant's slots. */
  queuedDepth(): number {
    return this.waiters.length;
  }

  /** Cumulative dispatches that had to wait for one of this tenant's slots. */
  waitedTotal(): number {
    return this.waitsTotal;
  }

  /** Point-in-time snapshot for operator observability (no tenant label). */
  stats(): Omit<TenantConcurrencyStats, "tenant"> {
    return {
      maxConcurrent: this.maxConcurrent,
      inFlight: this.inFlight,
      queuedDepth: this.waiters.length,
      waitsTotal: this.waitsTotal,
    };
  }
}

/**
 * The per-tenant aggregate: one independent `TenantConcurrencyGate` per
 * tenant id, created lazily on first use — a tenant that never appears
 * costs nothing, and one tenant's waiters can never occupy another
 * tenant's slots (the WR-48 isolation convention).
 *
 * The cap is validated once, at construction; every lazily created gate
 * inherits it. WR-328 adds per-tenant overrides: `reviseTenant()`
 * records one tenant's own live cap (a gate already dispatching is
 * retuned in place, a tenant not yet seen is only recorded and its
 * first gate is built at the new cap); `removeTenant()` drops the
 * override and the tenant falls back to the construction default.
 */
export class TenantConcurrencyGates {
  private readonly maxConcurrent: number;
  private readonly gates = new Map<string, TenantConcurrencyGate>();
  /** WR-328: per-tenant live caps, keyed by tenant id (`""` = default tenant). */
  private readonly overrides = new Map<string, number>();

  constructor(maxConcurrent: number = Infinity) {
    assertTenantConcurrencyLimit(maxConcurrent);
    this.maxConcurrent = maxConcurrent;
  }

  /** The configured per-tenant cap (`Infinity` = unlimited). */
  cap(): number {
    return this.maxConcurrent;
  }

  private gateFor(tenant: string): TenantConcurrencyGate {
    let g = this.gates.get(tenant);
    if (g === undefined) {
      g = new TenantConcurrencyGate(this.overrides.get(tenant) ?? this.maxConcurrent);
      this.gates.set(tenant, g);
    }
    return g;
  }

  /**
   * WR-328: revise (or set) one tenant's live cap. The tenant id is
   * validated first (`RangeError` on a malformed id — including a
   * non-string), then the cap (`RangeError` on an illegal value) —
   * either failure leaves the live caps completely untouched.
   * Revising to the tenant's effective current cap is a silent no-op
   * (no override is recorded, no gate is created). Otherwise the
   * override is recorded and an existing gate is retuned in place
   * (tightening never revokes a held slot, widening pumps out FIFO
   * waiters at once); a tenant not yet seen gets its gate built at
   * the new cap on first dispatch. Other tenants and the default cap
   * are untouched. Returns the tenant's live cap.
   */
  reviseTenant(tenant: string, newCap: number): number {
    assertTenantConcurrencyTenant(tenant);
    assertTenantConcurrencyLimit(newCap);
    const existing = this.gates.get(tenant);
    const current = existing?.cap() ?? this.overrides.get(tenant) ?? this.maxConcurrent;
    if (newCap === current) return current;
    this.overrides.set(tenant, newCap);
    if (existing !== undefined) {
      existing.retune(newCap);
    } else {
      this.gates.set(tenant, new TenantConcurrencyGate(newCap));
    }
    return newCap;
  }

  /**
   * WR-328: the live effective cap for `tenant` and whether the tenant
   * carries an explicit override. Read-only: unlike `reviseTenant` it
   * never creates a gate, so a read cannot conjure state. A tenant
   * never revised reports the construction default with
   * `overridden: false`.
   */
  getTenant(tenant: string): { maxConcurrent: number; overridden: boolean } {
    const gate = this.gates.get(tenant);
    return {
      maxConcurrent: gate?.cap() ?? this.overrides.get(tenant) ?? this.maxConcurrent,
      overridden: this.overrides.has(tenant),
    };
  }

  /** WR-328: whether `tenant` carries an explicit override. */
  hasOverride(tenant: string): boolean {
    return this.overrides.has(tenant);
  }

  /**
   * WR-328: remove one tenant's override — the tenant falls back to
   * the construction default cap. An existing gate is retuned in
   * place to the default (in-flight dispatches and waiters are
   * preserved: tightening drains, widening pumps out FIFO waiters).
   * Returns `true` when an override was removed, `false` when the
   * tenant had none. A malformed tenant id throws `RangeError`.
   */
  removeTenant(tenant: string): boolean {
    assertTenantConcurrencyTenant(tenant);
    if (!this.overrides.has(tenant)) return false;
    this.overrides.delete(tenant);
    const gate = this.gates.get(tenant);
    if (gate !== undefined) gate.retune(this.maxConcurrent);
    return true;
  }

  /**
   * Acquire a slot in `tenant`'s own gate. The tenant id comes from the
   * already-validated `x-tenant-id` header (WR-48); tenant-less
   * deliveries never reach this gate (the queue skips it entirely).
   */
  acquire(tenant: string): Promise<() => void> {
    return this.gateFor(tenant).acquire();
  }

  /**
   * Fail-safe for `stop()`/`shutdown()`: wake every tenant's waiters —
   * see `TenantConcurrencyGate.releaseWaiters()`.
   */
  releaseWaiters(): void {
    for (const g of this.gates.values()) g.releaseWaiters();
  }

  /**
   * One snapshot row per tenant seen so far, in first-seen order; empty
   * when no tenant has ever dispatched through the gate.
   */
  stats(): TenantConcurrencyStats[] {
    const out: TenantConcurrencyStats[] = [];
    for (const [tenant, g] of this.gates) out.push({ tenant, ...g.stats() });
    return out;
  }
}
