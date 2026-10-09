/**
 * Global retry budget (WR-38): retry-storm protection for a downstream
 * fleet that fails all at once.
 *
 * The per-endpoint circuit breaker (WR-10) trips per endpoint; the retry
 * budget is the global counterpart — one token bucket for the whole
 * queue. Every *scheduled retry* (a failed attempt that will be tried
 * again; first attempts are never gated) costs one token; when the bucket
 * is empty the retry is parked until the next token refill — never
 * dropped, never burned against the item's attempt budget, never
 * touching the circuit breaker. Retries resume automatically when the
 * budget recovers, so a thundering herd of backlogged retries spreads
 * itself over the refill window instead of stampeding a recovering
 * downstream.
 *
 * Zero dependencies. Clock-injectable for deterministic tests.
 */

/** Options for the global retry budget (see {@link RetryQueueOptions.retryBudget}). */
export interface RetryBudgetOptions {
  /**
   * Maximum scheduled retries per minute across all endpoints. Each
   * scheduled retry consumes one token; when the bucket is empty the retry
   * waits for the refill window. Must be a finite number > 0. Default:
   * 6000 (generous — a guard rail, not a throttle).
   */
  retriesPerMinute?: number;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
}

/** Default global retry budget: generous enough to stay out of the way. */
export const DEFAULT_RETRY_BUDGET_PER_MINUTE = 6000;

/**
 * Global retry budget: a single token bucket sized to one minute of
 * retries (`retriesPerMinute`), refilled lazily. This is a protective
 * gate, not a failure: parked retries are rescheduled, not counted
 * against the item's attempt budget or the circuit breaker.
 */
export class RetryBudget {
  private readonly perMinute: number;
  private tokens: number;
  private updatedMs: number;
  private readonly now: () => number;

  constructor(retriesPerMinute: number = DEFAULT_RETRY_BUDGET_PER_MINUTE, now: () => number = Date.now) {
    if (!Number.isFinite(retriesPerMinute) || retriesPerMinute <= 0) {
      throw new RangeError(`retriesPerMinute must be a finite number > 0, got ${retriesPerMinute}`);
    }
    this.perMinute = retriesPerMinute;
    this.now = now;
    // A fresh budget starts full: the first minute of budget is available
    // immediately, then refills continuously.
    this.tokens = retriesPerMinute;
    this.updatedMs = now();
  }

  /** Configured per-minute budget. */
  limit(): number {
    return this.perMinute;
  }

  private refill(): void {
    const at = this.now();
    const elapsedMs = Math.max(0, at - this.updatedMs);
    this.tokens = Math.min(this.perMinute, this.tokens + (elapsedMs * this.perMinute) / 60_000);
    this.updatedMs = at;
  }

  /**
   * Consume one token for a scheduled retry. Returns `false` when the
   * budget is exhausted — the caller should park and re-schedule, never
   * drop.
   */
  take(): boolean {
    this.refill();
    if (this.tokens < 1) return false;
    this.tokens -= 1;
    return true;
  }

  /**
   * Milliseconds until one token is available (0 when a token is already
   * available). Used to re-schedule a parked retry at the earliest honest
   * moment.
   */
  msUntilToken(): number {
    this.refill();
    if (this.tokens >= 1) return 0;
    const needed = 1 - this.tokens;
    return Math.ceil((needed * 60_000) / this.perMinute);
  }
}
