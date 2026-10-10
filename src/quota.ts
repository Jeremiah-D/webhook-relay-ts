export interface QuotaOptions {
  /**
   * Maximum deliveries per minute per endpoint. Each send attempt consumes
   * one token; when the bucket is empty the attempt is re-scheduled for
   * the next token refill — never dropped, and never burned against the
   * retry budget. Must be a finite number > 0. Unset means unlimited.
   */
  deliveriesPerMinute?: number;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
}

/**
 * Per-endpoint delivery quota: a token bucket sized to one minute of
 * budget (`deliveriesPerMinute`), refilled lazily. When one tenant's flood
 * exhausts its endpoint's budget, further attempts wait for the refill
 * window instead of hammering the downstream — automatic per-tenant
 * throttling. This is a protective gate, not a failure: delayed attempts
 * are rescheduled, not counted against the retry budget or the circuit
 * breaker.
 */
export class EndpointQuota {
  private readonly perMinute: number;
  private readonly buckets = new Map<string, { tokens: number; updatedMs: number }>();
  private readonly now: () => number;
  /**
   * Per-endpoint runtime overrides (WR-32 hot reload). An endpoint without
   * an override uses the constructor default. Raising a limit lets lazy
   * refills accrue faster toward the new burst; lowering clamps the bucket
   * on the next refill. Queued/delayed attempts pick the new budget up at
   * their next re-check — nothing in flight is cancelled.
   */
  private readonly endpointLimits = new Map<string, number>();

  constructor(deliveriesPerMinute: number, now: () => number = Date.now) {
    if (!Number.isFinite(deliveriesPerMinute) || deliveriesPerMinute <= 0) {
      throw new RangeError(`deliveriesPerMinute must be a finite number > 0, got ${deliveriesPerMinute}`);
    }
    this.perMinute = deliveriesPerMinute;
    this.now = now;
  }

  /** Configured per-minute budget for `endpoint` (override wins over default). */
  limit(endpoint?: string): number {
    if (endpoint !== undefined) {
      const o = this.endpointLimits.get(endpoint);
      if (o !== undefined) return o;
    }
    return this.perMinute;
  }

  /**
   * Override the per-minute budget for one endpoint at runtime.
   * Illegal values throw `RangeError` and leave the current budget intact.
   */
  setEndpointLimit(endpoint: string, deliveriesPerMinute: number): void {
    if (!Number.isFinite(deliveriesPerMinute) || deliveriesPerMinute <= 0) {
      throw new RangeError(`deliveriesPerMinute must be a finite number > 0, got ${deliveriesPerMinute}`);
    }
    this.endpointLimits.set(endpoint, deliveriesPerMinute);
  }

  private refill(endpoint: string): { tokens: number; updatedMs: number } {
    const cap = this.limit(endpoint);
    const at = this.now();
    let b = this.buckets.get(endpoint);
    if (!b) {
      // A new endpoint starts with a full bucket: the first minute of
      // budget is available immediately, then refills continuously.
      b = { tokens: cap, updatedMs: at };
      this.buckets.set(endpoint, b);
    } else {
      const elapsedMs = Math.max(0, at - b.updatedMs);
      b.tokens = Math.min(cap, b.tokens + (elapsedMs * cap) / 60_000);
      b.updatedMs = at;
    }
    return b;
  }

  /**
   * Consume one token for `endpoint`. Returns `false` when the budget is
   * exhausted — the caller should delay and retry, never drop.
   */
  take(endpoint: string): boolean {
    const b = this.refill(endpoint);
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  }

  /**
   * Milliseconds until one token is available for `endpoint` (0 when a
   * token is already available). Used to re-schedule a delayed attempt at
   * the earliest honest moment.
   */
  msUntilToken(endpoint: string): number {
    const b = this.refill(endpoint);
    if (b.tokens >= 1) return 0;
    const needed = 1 - b.tokens;
    return Math.ceil((needed * 60_000) / this.perMinute);
  }
}

/** Per-endpoint quota observability. */
export interface QuotaStats {
  endpoint: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  /** Attempts delayed (rescheduled) because the endpoint's budget was exhausted. */
  delayed: number;
}
