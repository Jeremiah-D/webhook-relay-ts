/**
 * Inbound rate limiting (WR-22): dual-dimension token buckets guarding the
 * webhook intake — per-sender IP and per-endpoint.
 *
 * Each dimension is a token bucket sized to one second of budget, refilled
 * lazily (same pattern as `src/quota.ts`'s `EndpointQuota`, but per-second
 * and admission-side). A request must hold a token in *both* buckets to be
 * admitted; the check is peek-then-consume so a request rejected by one
 * dimension never burns a token in the other.
 *
 * Zero dependencies. The clock is injectable for deterministic tests.
 */

export interface InboundRateLimitOptions {
  /**
   * Per-sender-IP budget: requests per second from one IP. Must be a finite
   * number > 0 when set. Unset means unlimited on this dimension.
   */
  perIpPerSecond?: number;
  /**
   * Per-endpoint budget: requests per second accepted for one endpoint
   * (`forwardUrl`). Must be a finite number > 0 when set. Unset means
   * unlimited on this dimension.
   */
  perEndpointPerSecond?: number;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
}

/** Which dimension rejected the request. */
export type RateLimitDimension = "ip" | "endpoint";

export type RateLimitVerdict =
  | { ok: true }
  | {
      ok: false;
      /** The first exhausted dimension (`ip` is checked before `endpoint`). */
      dimension: RateLimitDimension;
      /**
       * Milliseconds until the exhausted dimension has a token again —
       * the honest `Retry-After` value.
       */
      retryAfterMs: number;
    };

interface Bucket {
  tokens: number;
  updatedMs: number;
}

export class InboundRateLimiter {
  private readonly ipLimit?: number;
  private readonly endpointLimit?: number;
  private readonly ipBuckets = new Map<string, Bucket>();
  private readonly endpointBuckets = new Map<string, Bucket>();
  private readonly now: () => number;

  constructor(opts: InboundRateLimitOptions = {}) {
    const { perIpPerSecond, perEndpointPerSecond } = opts;
    for (const [name, v] of [
      ["perIpPerSecond", perIpPerSecond],
      ["perEndpointPerSecond", perEndpointPerSecond],
    ] as const) {
      if (v !== undefined && (!Number.isFinite(v) || v <= 0)) {
        throw new RangeError(`${name} must be a finite number > 0, got ${v}`);
      }
    }
    this.ipLimit = perIpPerSecond;
    this.endpointLimit = perEndpointPerSecond;
    this.now = opts.now ?? Date.now;
  }

  /** The configured per-IP budget (undefined = unlimited). */
  perIpLimit(): number | undefined {
    return this.ipLimit;
  }

  /** The configured per-endpoint budget (undefined = unlimited). */
  perEndpointLimit(): number | undefined {
    return this.endpointLimit;
  }

  private refill(buckets: Map<string, Bucket>, key: string, perSecond: number): Bucket {
    const at = this.now();
    let b = buckets.get(key);
    if (!b) {
      // A new key starts with a full bucket: the first second of budget is
      // available immediately, then it refills continuously.
      b = { tokens: perSecond, updatedMs: at };
      buckets.set(key, b);
    } else {
      // Clamp clock skew at zero: a backward clock never grants extra budget.
      const elapsedMs = Math.max(0, at - b.updatedMs);
      b.tokens = Math.min(perSecond, b.tokens + (elapsedMs * perSecond) / 1000);
      b.updatedMs = at;
    }
    return b;
  }

  private peek(buckets: Map<string, Bucket>, key: string, perSecond: number): boolean {
    return this.refill(buckets, key, perSecond).tokens >= 1;
  }

  private consume(buckets: Map<string, Bucket>, key: string, perSecond: number): void {
    this.refill(buckets, key, perSecond).tokens -= 1;
  }

  /** Milliseconds until `key`'s bucket in `buckets` has one token (0 if it already does). */
  private msUntilToken(buckets: Map<string, Bucket>, key: string, perSecond: number): number {
    const b = this.refill(buckets, key, perSecond);
    if (b.tokens >= 1) return 0;
    return Math.ceil(((1 - b.tokens) * 1000) / perSecond);
  }

  /**
   * Try to admit one request from `ip` for `endpoint`. Both dimensions are
   * peeked first so a rejection never burns the other dimension's token.
   * The IP dimension is checked first: a single abusive sender is the
   * cheaper thing to name.
   */
  take(ip: string, endpoint: string): RateLimitVerdict {
    if (this.ipLimit !== undefined && !this.peek(this.ipBuckets, ip, this.ipLimit)) {
      return {
        ok: false,
        dimension: "ip",
        retryAfterMs: this.msUntilToken(this.ipBuckets, ip, this.ipLimit),
      };
    }
    if (this.endpointLimit !== undefined && !this.peek(this.endpointBuckets, endpoint, this.endpointLimit)) {
      return {
        ok: false,
        dimension: "endpoint",
        retryAfterMs: this.msUntilToken(this.endpointBuckets, endpoint, this.endpointLimit),
      };
    }
    if (this.ipLimit !== undefined) this.consume(this.ipBuckets, ip, this.ipLimit);
    if (this.endpointLimit !== undefined) this.consume(this.endpointBuckets, endpoint, this.endpointLimit);
    return { ok: true };
  }

  /** Requests currently tracked (distinct keys ever seen) per dimension. */
  trackedKeys(): { ip: number; endpoint: number } {
    return { ip: this.ipBuckets.size, endpoint: this.endpointBuckets.size };
  }
}
