/**
 * Relay-level global outbound concurrency cap (WR-51).
 *
 * The per-endpoint limiter (`EndpointConcurrencyLimiter`, WR-06) bounds
 * in-flight deliveries *per downstream*; this gate bounds them *across
 * the whole relay — the total number of deliveries executing concurrently,
 * regardless of endpoint or tenant. The two compose: a dispatch needs a
 * slot from each.
 *
 * Why relay-level: a fan-out relay can have hundreds of healthy
 * endpoints each within their own limit while the relay itself runs out
 * of sockets, memory, or file descriptors. The global cap is the
 * backpressure valve for the relay's own resources.
 *
 * Semantics:
 * - FIFO: when the cap is hit, excess dispatches wait in arrival order;
 *   the oldest waiter dispatches when a slot frees. Waiters are never
 *   dropped, never consume retry budget, and never touch the circuit
 *   breaker — waiting is neutral, exactly like the per-endpoint limiter.
 * - Placement: the queue acquires the gate immediately before invoking
 *   the sender and releases it when the attempt settles (success,
 *   failure-scheduled, or dead-lettered) — see `RetryQueue.deliver()`.
 *   Acquiring last means quota/circuit/budget verdicts and lane
 *   ordering are all settled before a global slot is taken, and a
 *   paused endpoint never holds a slot while parked. The urgent lane
 *   bypasses the *per-endpoint* limiter but not this gate: the cap is
 *   relay-level capacity, not per-endpoint policy.
 * - Shutdown: `releaseWaiters()` wakes every waiter with a no-op
 *   release so `stop()`/`shutdown()` never hang on the gate — woken
 *   waiters observe the stopped queue through the normal liveness check
 *   and bail out. No timers are involved (promise FIFO only), so there
 *   is nothing to unref.
 */

/** Snapshot of the relay-level global dispatch gate. */
export interface GlobalConcurrencyStats {
  /** Configured cap (`Infinity` = unlimited). */
  maxConcurrent: number;
  /** Dispatches currently holding a global slot. */
  inFlight: number;
  /** Dispatches queued FIFO for a slot. */
  queuedDepth: number;
  /** Cumulative dispatches that had to wait for a slot. */
  waitsTotal: number;
}

/** Shared validation: a positive integer, or `Infinity` for "no cap". */
export function assertGlobalConcurrencyLimit(globalMaxConcurrent: number): void {
  if (
    !(
      globalMaxConcurrent === Infinity ||
      (Number.isInteger(globalMaxConcurrent) && globalMaxConcurrent >= 1)
    )
  ) {
    throw new RangeError(
      `globalMaxConcurrent must be a positive integer or Infinity, got ${globalMaxConcurrent}`
    );
  }
}

/**
 * Relay-wide dispatch gate: at most `maxConcurrent` deliveries in flight
 * across all endpoints; excess acquisitions wait in FIFO order.
 *
 * Callers must re-check their own liveness after `acquire()` resolves
 * (the queue may have stopped — see `releaseWaiters()` — while they
 * waited) and must always call the returned release function exactly
 * once. Releases cascade to the next waiter, so no one hangs.
 */
export class GlobalConcurrencyGate {
  private readonly maxConcurrent: number;
  private inFlight = 0;
  private readonly waiters: Array<(release: () => void) => void> = [];
  private waitsTotal = 0;

  constructor(maxConcurrent: number = Infinity) {
    assertGlobalConcurrencyLimit(maxConcurrent);
    this.maxConcurrent = maxConcurrent;
  }

  /** The configured cap (`Infinity` = unlimited). */
  cap(): number {
    return this.maxConcurrent;
  }

  /**
   * Resolve when a global dispatch slot is free. The waiter count
   * (`waitsTotal`) increments only when the acquisition actually waits —
   * an immediately granted slot is not a wait. Always call the returned
   * function exactly once to hand the slot on.
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

  /** Dispatches currently holding a global slot. */
  inFlightCount(): number {
    return this.inFlight;
  }

  /** Dispatches currently queued FIFO for a slot. */
  queuedDepth(): number {
    return this.waiters.length;
  }

  /** Cumulative dispatches that had to wait for a slot. */
  waitedTotal(): number {
    return this.waitsTotal;
  }

  /** Point-in-time snapshot for operator observability. */
  stats(): GlobalConcurrencyStats {
    return {
      maxConcurrent: this.maxConcurrent,
      inFlight: this.inFlight,
      queuedDepth: this.waiters.length,
      waitsTotal: this.waitsTotal,
    };
  }
}
