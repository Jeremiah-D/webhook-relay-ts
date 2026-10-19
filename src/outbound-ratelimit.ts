import {
  TenantRateLimiter,
  type TenantRateLimitVerdict,
} from "./tenant-ratelimit.ts";

/**
 * Tuning for the per-endpoint outbound token-bucket rate limiter (WR-154).
 */
export interface OutboundRateLimitOptions {
  /**
   * Refill rate in tokens per second. Must be a finite number > 0.
   * Each send attempt consumes one token.
   */
  refillRps: number;
  /**
   * Bucket capacity (max burst). Must be a finite number > 0. A new
   * endpoint starts with a full bucket, so the first burst of budget is
   * available immediately, then it refills continuously at `refillRps`.
   */
  burst: number;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
}

/** One endpoint's outbound rate-limit state, for stats/operators. */
export interface OutboundRateLimitStats {
  /** Downstream endpoint (physical `targetUrl` at dispatch). */
  endpoint: string;
  /** Cumulative over-limit decisions (delays) for this endpoint. */
  throttled: number;
  /** The refill rate in tokens per second currently in effect. */
  refillRps: number;
  /** The burst currently in effect. */
  burst: number;
}

function assertPositiveRate(name: string, value: number | undefined): number {
  if (value === undefined || !Number.isFinite(value) || value <= 0) {
    throw new RangeError(
      `outboundRateLimit.${name} must be a finite number > 0, got ${value}`
    );
  }
  return value;
}

/**
 * Per-endpoint outbound token-bucket rate limiting (WR-154).
 *
 * A token bucket per endpoint (`targetUrl`, tenant-agnostic) paces
 * outbound delivery attempts: each send attempt costs one token, and an
 * over-limit attempt is rescheduled for the next token refill — never
 * dropped, never charged to the retry budget, and never shown to the
 * circuit breaker as an outcome. Throttling only paces; it never stops
 * delivery (that is WR-150 endpoint auto-disable's job, which this gate
 * is orthogonal to).
 *
 * The bucket mechanics are exactly the WR-97 per-(tenant, endpoint)
 * limiter's, with the tenant pinned to the default scope: a new endpoint
 * starts with a full bucket, refills are lazy (computed on `take()`),
 * and a backward clock never grants extra budget. Reusing the one
 * implementation keeps both limiters' semantics identical instead of
 * letting a second hand-rolled bucket drift.
 */
export class OutboundRateLimiter {
  private readonly inner: TenantRateLimiter;
  private readonly refillRps: number;
  private readonly burst: number;

  constructor(opts: OutboundRateLimitOptions) {
    if (opts === null || typeof opts !== "object" || Array.isArray(opts)) {
      throw new RangeError(
        `outboundRateLimit options must be an object, got ${JSON.stringify(opts)}`
      );
    }
    this.refillRps = assertPositiveRate("refillRps", opts.refillRps);
    this.burst = assertPositiveRate("burst", opts.burst);
    this.inner = new TenantRateLimiter({
      burst: this.burst,
      refillPerSecond: this.refillRps,
      mode: "queue",
      now: opts.now,
    });
  }

  /** The refill rate in tokens per second. */
  refillPerSecond(): number {
    return this.refillRps;
  }

  /** The bucket capacity (max burst). */
  burstSize(): number {
    return this.burst;
  }

  /**
   * Try to consume one token for `endpoint`. On success the token is
   * spent; on denial nothing is spent — the caller should delay and
   * retry, never drop.
   */
  take(endpoint: string): TenantRateLimitVerdict {
    return this.inner.take(undefined, endpoint);
  }

  /**
   * One row per endpoint that has taken at least once, in first-seen
   * order. Rows that never denied report `throttled: 0` — the
   * Prometheus exposition filters those out (activity-gated), but
   * operators can still see the configured rate per endpoint.
   */
  stats(): OutboundRateLimitStats[] {
    return this.inner.stats().map((s) => ({
      endpoint: s.endpoint,
      throttled: s.limited,
      refillRps: this.refillRps,
      burst: this.burst,
    }));
  }
}
