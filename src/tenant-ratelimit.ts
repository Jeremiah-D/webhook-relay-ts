import { splitTenantScopeKey, tenantScopeKey } from "./tenant.ts";

/**
 * Per-tenant outbound rate limiting (WR-97).
 *
 * A token bucket per (tenant, endpoint) scope paces *outbound* delivery
 * attempts, so one tenant's flood cannot starve the shared downstream or
 * crowd out another tenant's deliveries. This is the outbound counterpart
 * to the WR-22 inbound limiter and the per-(tenant, endpoint) sibling of
 * the WR-15 endpoint quota — same lazy-refill token-bucket mechanics,
 * tenant-scoped via the WR-48 `tenantScopeKey` convention.
 *
 * Configuration has two levels: tenant-level defaults (`burst`,
 * `refillPerSecond`) apply to every tenant's bucket, and `endpoints`
 * overrides replace either field for one endpoint (the physical
 * `targetUrl` at dispatch, the content-route-resolved `targetUrl` at
 * intake). An endpoint without an override uses the tenant-level
 * defaults; a bucket whose endpoint config shrinks clamps to the new
 * burst on the next refill, exactly like the WR-15 quota.
 *
 * Over-limit behavior is modal (`mode`):
 *
 * - `"queue"` (default): the enforcement point is the dispatch path. An
 *   over-limit *attempt* is rescheduled for the next token refill — never
 *   dropped, never charged to the retry budget, never shown to the
 *   circuit breaker as an outcome. It composes with WR-91 in-flight
 *   coalescing: the rescheduled delivery keeps its full lifecycle and
 *   still dispatches through the coalescing sender, so it may merge with
 *   an in-flight identical attempt once a token frees up.
 * - `"reject-429"`: the enforcement point is the intake path. An
 *   over-limit *admission* is answered 429 with a `retry-after` header
 *   (the WR-22 convention) and audited as `rejected` with reason
 *   `rate_limited` — the webhook sender gets honest backpressure instead
 *   of a 202 for a delivery that would sit throttled. The token is
 *   consumed at admission, so the dispatch path never re-checks in this
 *   mode: one delivery, one token. (Per-cycle deliveries minted by
 *   WR-80 recurring schedules are admission-checked at registration, not
 *   re-checked per cycle; in `queue` mode they are paced at dispatch
 *   like any other delivery.)
 *
 * Orthogonality with WR-94 AIMD: the limiter paces *rate* (deliveries
 * per second), AIMD paces *concurrency* (simultaneous in-flight
 * attempts). A rate-limit wait is never a delivery outcome — it feeds
 * neither the AIMD controller nor the WR-59 adaptive backoff nor the
 * circuit breaker — exactly like the WR-15 quota gate.
 *
 * Observability: every denial bumps the scope's `limited` counter,
 * exported to Prometheus as `relay_tenant_ratelimited_total{endpoint,
 * tenant}` (activity-gated — absent until the first denial) and to OTLP
 * as a `rate_limited` event (WR-83) with `relay.retry_after_ms`.
 *
 * Disabled by default (backward compatible): the queue never constructs
 * a limiter unless `tenantRateLimit` is set. Illegal configs throw
 * `RangeError` at construction, never mid-delivery. Zero dependencies
 * (`./tenant.ts` only). The clock is injectable for deterministic tests.
 */

/** What happens to an over-limit delivery. */
export type TenantRateLimitMode = "queue" | "reject-429";

/** Per-endpoint config override: each set field wins over the tenant-level default. */
export interface TenantRateLimitEndpointOverride {
  /**
   * Bucket capacity for this endpoint (max burst). Must be a finite
   * number > 0 when set. Unset falls back to the tenant-level `burst`.
   */
  burst?: number;
  /**
   * Refill rate in tokens per second for this endpoint. Must be a finite
   * number > 0 when set. Unset falls back to the tenant-level
   * `refillPerSecond`.
   */
  refillPerSecond?: number;
}

/** Tuning for {@link TenantRateLimiter}. All values are validated up front. */
export interface TenantRateLimitOptions {
  /**
   * Default bucket capacity (max burst) per (tenant, endpoint). Must be
   * a finite number > 0. Required when the option is set — a rate limit
   * with no rate is a misconfiguration, so this fails fast.
   */
  burst: number;
  /**
   * Default refill rate in tokens per second per (tenant, endpoint).
   * Must be a finite number > 0. Required when the option is set.
   */
  refillPerSecond: number;
  /**
   * Per-endpoint overrides, keyed by exact `targetUrl`. Each set field
   * overrides the tenant-level default for that endpoint (only); unset
   * fields fall back to the defaults.
   */
  endpoints?: Record<string, TenantRateLimitEndpointOverride>;
  /**
   * Over-limit behavior: `"queue"` reschedules the attempt for the next
   * token refill (never dropped); `"reject-429"` answers the intake 429
   * with `retry-after`. Default: `"queue"`.
   */
  mode?: TenantRateLimitMode;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
}

export type TenantRateLimitVerdict =
  | { ok: true }
  | {
      ok: false;
      /**
       * Milliseconds until the scope's bucket holds a token again — the
       * honest `Retry-After` value.
       */
      retryAfterMs: number;
    };

/** One (tenant, endpoint) scope's rate-limit state, for stats/operators. */
export interface TenantRateLimitStats {
  /** Downstream endpoint (physical `targetUrl` at dispatch). */
  endpoint: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  /** Cumulative over-limit decisions (denials) for this scope. */
  limited: number;
  /** The burst currently in effect for this scope (override-aware). */
  burst: number;
  /** The refill rate currently in effect for this scope (override-aware). */
  refillPerSecond: number;
}

interface Bucket {
  tokens: number;
  updatedMs: number;
}

function assertRate(name: string, value: number | undefined, what: string): number {
  if (value === undefined || !Number.isFinite(value) || value <= 0) {
    throw new RangeError(`${what} must be a finite number > 0, got ${value}`);
  }
  return value;
}

/**
 * Per-(tenant, endpoint) outbound token buckets (WR-97).
 *
 * Buckets are keyed by the WR-48 `tenantScopeKey`, so the default
 * (tenant-less) scope keys plain endpoints — byte-identical to a
 * tenant-unaware limiter — while a tenant prefixes its id. Buckets are
 * created lazily on first `take()` and start full: the first burst of
 * budget is available immediately, then refills continuously.
 */
export class TenantRateLimiter {
  private readonly defaultBurst: number;
  private readonly defaultRefillPerSecond: number;
  private readonly endpointOverrides = new Map<string, { burst?: number; refillPerSecond?: number }>();
  private readonly runMode: TenantRateLimitMode;
  private readonly now: () => number;
  private readonly buckets = new Map<string, Bucket>();
  /** Cumulative denials per scope key (WR-48 `tenantScopeKey`). */
  private readonly denied = new Map<string, number>();

  constructor(opts: TenantRateLimitOptions) {
    if (opts === null || typeof opts !== "object" || Array.isArray(opts)) {
      throw new RangeError(`tenantRateLimit options must be an object, got ${JSON.stringify(opts)}`);
    }
    this.defaultBurst = assertRate("burst", opts.burst, "tenantRateLimit.burst");
    this.defaultRefillPerSecond = assertRate(
      "refillPerSecond",
      opts.refillPerSecond,
      "tenantRateLimit.refillPerSecond"
    );
    if (opts.mode !== undefined && opts.mode !== "queue" && opts.mode !== "reject-429") {
      throw new RangeError(
        `tenantRateLimit.mode must be "queue" or "reject-429", got ${JSON.stringify(opts.mode)}`
      );
    }
    this.runMode = opts.mode ?? "queue";
    if (opts.endpoints !== undefined) {
      if (opts.endpoints === null || typeof opts.endpoints !== "object" || Array.isArray(opts.endpoints)) {
        throw new RangeError(`tenantRateLimit.endpoints must be a record of targetUrl -> override`);
      }
      for (const [endpoint, override] of Object.entries(opts.endpoints)) {
        if (endpoint.length === 0) {
          throw new RangeError(`tenantRateLimit.endpoints keys must be non-empty target URLs`);
        }
        if (override === null || typeof override !== "object" || Array.isArray(override)) {
          throw new RangeError(
            `tenantRateLimit.endpoints[${JSON.stringify(endpoint)}] must be an object`
          );
        }
        if (override.burst !== undefined) assertRate("burst", override.burst, `tenantRateLimit.endpoints[${JSON.stringify(endpoint)}].burst`);
        if (override.refillPerSecond !== undefined)
          assertRate(
            "refillPerSecond",
            override.refillPerSecond,
            `tenantRateLimit.endpoints[${JSON.stringify(endpoint)}].refillPerSecond`
          );
        this.endpointOverrides.set(endpoint, {
          ...(override.burst !== undefined ? { burst: override.burst } : {}),
          ...(override.refillPerSecond !== undefined ? { refillPerSecond: override.refillPerSecond } : {}),
        });
      }
    }
    this.now = opts.now ?? Date.now;
  }

  /** The configured over-limit mode (`"queue"` by default). */
  mode(): TenantRateLimitMode {
    return this.runMode;
  }

  /** Endpoints carrying a per-endpoint config override. */
  configuredEndpoints(): string[] {
    return [...this.endpointOverrides.keys()];
  }

  /** The burst in effect for `endpoint` (override wins over the tenant-level default). */
  burstFor(endpoint: string): number {
    return this.endpointOverrides.get(endpoint)?.burst ?? this.defaultBurst;
  }

  /** The refill rate in effect for `endpoint` (override wins over the tenant-level default). */
  refillPerSecondFor(endpoint: string): number {
    return this.endpointOverrides.get(endpoint)?.refillPerSecond ?? this.defaultRefillPerSecond;
  }

  private refill(key: string, endpoint: string): Bucket {
    const cap = this.burstFor(endpoint);
    const rate = this.refillPerSecondFor(endpoint);
    const at = this.now();
    let b = this.buckets.get(key);
    if (!b) {
      // A new scope starts with a full bucket: the first burst of budget
      // is available immediately, then it refills continuously.
      b = { tokens: cap, updatedMs: at };
      this.buckets.set(key, b);
    } else {
      // Clamp clock skew at zero: a backward clock never grants extra budget.
      const elapsedMs = Math.max(0, at - b.updatedMs);
      b.tokens = Math.min(cap, b.tokens + (elapsedMs * rate) / 1000);
      b.updatedMs = at;
    }
    return b;
  }

  /**
   * Try to consume one token for (`tenant`, `endpoint`). On success the
   * token is spent; on denial nothing is spent and the scope's `limited`
   * counter is bumped — the caller decides what the denial means
   * (reschedule in `queue` mode, 429 in `reject-429` mode).
   */
  take(tenant: string | undefined, endpoint: string): TenantRateLimitVerdict {
    const key = tenantScopeKey(tenant, endpoint);
    const b = this.refill(key, endpoint);
    if (b.tokens >= 1) {
      b.tokens -= 1;
      return { ok: true };
    }
    this.denied.set(key, (this.denied.get(key) ?? 0) + 1);
    const rate = this.refillPerSecondFor(endpoint);
    return { ok: false, retryAfterMs: Math.ceil(((1 - b.tokens) * 1000) / rate) };
  }

  /**
   * One row per (tenant, endpoint) scope that has taken at least once,
   * in first-seen order. Rows carry `tenant` only when set. Scopes that
   * never denied report `limited: 0` — the Prometheus exposition filters
   * those out (activity-gated), but operators can still see the
   * override-resolved config per scope.
   */
  stats(): TenantRateLimitStats[] {
    const rows: TenantRateLimitStats[] = [];
    for (const key of this.buckets.keys()) {
      const { tenant, endpoint } = splitTenantScopeKey(key);
      rows.push({
        endpoint,
        ...(tenant === undefined ? {} : { tenant }),
        limited: this.denied.get(key) ?? 0,
        burst: this.burstFor(endpoint),
        refillPerSecond: this.refillPerSecondFor(endpoint),
      });
    }
    return rows;
  }
}
