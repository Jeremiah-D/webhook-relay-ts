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
 */

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
  private readonly maxConcurrent: number;
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
    const next = this.waiters.shift();
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
 * inherits it.
 */
export class TenantConcurrencyGates {
  private readonly maxConcurrent: number;
  private readonly gates = new Map<string, TenantConcurrencyGate>();

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
      g = new TenantConcurrencyGate(this.maxConcurrent);
      this.gates.set(tenant, g);
    }
    return g;
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
