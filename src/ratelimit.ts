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
  /**
   * Opt-in adaptive inbound throttling (WR-136): when the retry queue's
   * pending depth crosses `queueDepthHigh`, the per-endpoint budget is
   * scaled down toward `minPerEndpointPerSecond` (linear in depth); the
   * full budget is restored only after depth falls back below
   * `queueDepthLow` (hysteresis — the band in between keeps the current
   * state, so the budget doesn't flap at the threshold). Unset means
   * disabled: the limiter behaves exactly like the WR-22 original.
   */
  adaptiveInbound?: AdaptiveInboundOptions;
}

/**
 * Adaptive inbound throttling (WR-136): scale the per-endpoint intake
 * budget with the retry queue's pending depth, so a wide downstream
 * outage stops feeding the backlog at full speed instead of making the
 * pile deeper. The IP dimension is untouched — this is strictly about
 * protecting the endpoint's delivery pipeline.
 */
export interface AdaptiveInboundOptions {
  /**
   * Floor for the effective per-endpoint budget (requests/sec), reached
   * at or above `queueDepthHigh`. Must be > 0 and <= the configured
   * `perEndpointPerSecond`.
   */
  minPerEndpointPerSecond: number;
  /**
   * Pending depth that engages the throttle. Must be finite and
   * strictly greater than `queueDepthLow`.
   */
  queueDepthHigh: number;
  /**
   * Pending depth below which the full budget is restored. Must be
   * finite and >= 0.
   */
  queueDepthLow: number;
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
  // WR-136 adaptive throttle state.
  private readonly adaptive?: AdaptiveInboundOptions;
  private readonly depthProvider?: () => number;
  private throttled = false;

  /**
   * `depthProvider` is a second constructor argument (not part of
   * `opts`) on purpose: it is an ambient runtime dependency
   * (`() => queue.pendingCount()`), not serializable config, so it
   * stays out of the options bag that config snapshots persist.
   */
  constructor(opts: InboundRateLimitOptions = {}, depthProvider?: () => number) {
    const { perIpPerSecond, perEndpointPerSecond, adaptiveInbound } = opts;
    for (const [name, v] of [
      ["perIpPerSecond", perIpPerSecond],
      ["perEndpointPerSecond", perEndpointPerSecond],
    ] as const) {
      if (v !== undefined && (!Number.isFinite(v) || v <= 0)) {
        throw new RangeError(`${name} must be a finite number > 0, got ${v}`);
      }
    }
    if (adaptiveInbound !== undefined) {
      const a = adaptiveInbound;
      for (const [name, v] of [
        ["adaptiveInbound.minPerEndpointPerSecond", a.minPerEndpointPerSecond],
        ["adaptiveInbound.queueDepthHigh", a.queueDepthHigh],
        ["adaptiveInbound.queueDepthLow", a.queueDepthLow],
      ] as const) {
        if (!Number.isFinite(v)) {
          throw new RangeError(`${name} must be a finite number, got ${v}`);
        }
      }
      if (a.minPerEndpointPerSecond <= 0) {
        throw new RangeError(
          `adaptiveInbound.minPerEndpointPerSecond must be > 0, got ${a.minPerEndpointPerSecond}`
        );
      }
      if (a.queueDepthLow < 0) {
        throw new RangeError(
          `adaptiveInbound.queueDepthLow must be >= 0, got ${a.queueDepthLow}`
        );
      }
      if (a.queueDepthHigh <= a.queueDepthLow) {
        throw new RangeError(
          `adaptiveInbound.queueDepthHigh (${a.queueDepthHigh}) must be > queueDepthLow (${a.queueDepthLow})`
        );
      }
      if (perEndpointPerSecond === undefined) {
        throw new RangeError("adaptiveInbound requires perEndpointPerSecond to be set");
      }
      if (a.minPerEndpointPerSecond > perEndpointPerSecond) {
        throw new RangeError(
          `adaptiveInbound.minPerEndpointPerSecond (${a.minPerEndpointPerSecond}) must be <= perEndpointPerSecond (${perEndpointPerSecond})`
        );
      }
    }
    this.ipLimit = perIpPerSecond;
    this.endpointLimit = perEndpointPerSecond;
    this.adaptive = adaptiveInbound;
    this.depthProvider = depthProvider;
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
   * cheaper thing to name. The endpoint dimension enforces the WR-136
   * effective budget (adaptive throttle) when configured — the
   * rejection/`retryAfterMs` semantics are unchanged, computed against
   * that effective budget.
   */
  take(ip: string, endpoint: string): RateLimitVerdict {
    const endpointLimit = this.effectiveEndpointPerSecond();
    if (this.ipLimit !== undefined && !this.peek(this.ipBuckets, ip, this.ipLimit)) {
      return {
        ok: false,
        dimension: "ip",
        retryAfterMs: this.msUntilToken(this.ipBuckets, ip, this.ipLimit),
      };
    }
    if (endpointLimit !== undefined && !this.peek(this.endpointBuckets, endpoint, endpointLimit)) {
      return {
        ok: false,
        dimension: "endpoint",
        retryAfterMs: this.msUntilToken(this.endpointBuckets, endpoint, endpointLimit),
      };
    }
    if (this.ipLimit !== undefined) this.consume(this.ipBuckets, ip, this.ipLimit);
    if (endpointLimit !== undefined) this.consume(this.endpointBuckets, endpoint, endpointLimit);
    return { ok: true };
  }

  /**
   * Evaluate the adaptive throttle (WR-136) and return the currently
   * effective per-endpoint budget. Runs on every `take` and every
   * `adaptiveStats()` call — `depthProvider` is O(1) (`queue.size`), so
   * there is no caching staleness to manage.
   *
   * Hysteresis: depth >= queueDepthHigh engages the throttle, depth <
   * queueDepthLow releases it; the band between keeps the current
   * state. When throttled, the effective budget interpolates linearly
   * between the full budget (at queueDepthLow) and the floor (at
   * queueDepthHigh); depth above queueDepthHigh pins at the floor.
   *
   * Bucket sizing follows the effective budget on the next refill —
   * tokens already granted are never revoked, and an over-full bucket
   * is re-capped by `refill`'s Math.min, so a shrink takes effect at
   * refill granularity rather than reaching back into admitted bursts.
   */
  private evaluateAdaptive(): { effective: number; depth: number } {
    const a = this.adaptive!;
    const full = this.endpointLimit!;
    const depth = this.depthProvider !== undefined ? this.depthProvider() : 0;
    if (depth >= a.queueDepthHigh) this.throttled = true;
    else if (depth < a.queueDepthLow) this.throttled = false;
    if (!this.throttled) return { effective: full, depth };
    const span = a.queueDepthHigh - a.queueDepthLow;
    const ratio = (depth - a.queueDepthLow) / span;
    return {
      effective: Math.max(
        a.minPerEndpointPerSecond,
        full - (full - a.minPerEndpointPerSecond) * ratio
      ),
      depth,
    };
  }

  /**
   * The budget the endpoint dimension enforces right now: the configured
   * `perEndpointPerSecond`, or the adaptive effective budget when the
   * WR-136 throttle is on. `undefined` when the dimension is unlimited.
   */
  private effectiveEndpointPerSecond(): number | undefined {
    if (this.adaptive === undefined) return this.endpointLimit;
    return this.evaluateAdaptive().effective;
  }

  /**
   * Snapshot of the adaptive throttle (WR-136) for operator
   * observability. Evaluates the current depth first, so the numbers are
   * as fresh as the last `take`. `enabled` is false unless
   * `adaptiveInbound` was configured; `throttled`,
   * `effectivePerEndpointPerSecond`, and `pendingDepth` are meaningful
   * only then. The depth read also drives hysteresis, so a stats poll
   * can flip `throttled` — same as a `take` would.
   */
  adaptiveStats(): {
    enabled: boolean;
    throttled: boolean;
    effectivePerEndpointPerSecond?: number;
    pendingDepth?: number;
  } {
    if (this.adaptive === undefined) return { enabled: false, throttled: false };
    const { effective, depth } = this.evaluateAdaptive();
    return {
      enabled: true,
      throttled: this.throttled,
      effectivePerEndpointPerSecond: effective,
      pendingDepth: depth,
    };
  }

  /** Requests currently tracked (distinct keys ever seen) per dimension. */
  trackedKeys(): { ip: number; endpoint: number } {
    return { ip: this.ipBuckets.size, endpoint: this.endpointBuckets.size };
  }
}
