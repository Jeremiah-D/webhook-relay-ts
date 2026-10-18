/**
 * Per-tenant inbound rate limiting (WR-141).
 *
 * A token bucket per `x-tenant-id` paces *inbound* webhook admissions, so
 * one tenant's flood cannot crowd out another tenant's intake or burn
 * verifier CPU on requests that will be rejected anyway. This is the
 * inbound counterpart to the WR-22 limiter (per-sender-IP +
 * per-endpoint) and is orthogonal to the WR-97 per-(tenant, endpoint)
 * *outbound* limiter: WR-141 guards the intake (before signature
 * verification), WR-97 paces dispatch.
 *
 * Enforcement point: after the WR-22 limiter, before signature
 * verification — a rejected request never reaches the verifier, never
 * enqueues, burns no retry budget, and never trips a breaker. Over-limit
 * admissions are answered 429 with a `retry-after` header (the WR-22
 * convention: ceiling seconds, minimum 1) and audited as `rejected`
 * with reason `tenant_rate_limited`.
 *
 * Mechanics mirror `src/ratelimit.ts`: a per-second bucket per tenant
 * (burst = one second of budget), refilled lazily, peek-then-consume so
 * a rejected request never burns a token, clock-skew clamped at zero so
 * a backward clock never grants extra budget. The clock is injectable
 * for deterministic tests. Invalid budgets throw `RangeError` at
 * construction. Unset = unlimited: the intake path is byte-identical.
 *
 * Tenants are keyed by the already-validated `x-tenant-id` (WR-48
 * charset `[A-Za-z0-9_-]`, safe in labels and log lines). Requests
 * without the header never touch the limiter.
 */

export interface InboundTenantRateLimitOptions {
  /**
   * Per-tenant budget: requests per second admitted for one `x-tenant-id`.
   * Must be a finite number > 0 when set. Unset means unlimited on this
   * dimension.
   */
  perTenantPerSecond?: number;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
}

export type InboundTenantRateLimitVerdict =
  | { ok: true }
  | {
      ok: false;
      /**
       * Milliseconds until the tenant's bucket has a token again — the
       * honest `Retry-After` value.
       */
      retryAfterMs: number;
    };

interface Bucket {
  tokens: number;
  updatedMs: number;
}

export class InboundTenantRateLimiter {
  private readonly perTenant?: number;
  private readonly buckets = new Map<string, Bucket>();
  private readonly now: () => number;

  constructor(opts: InboundTenantRateLimitOptions = {}) {
    const { perTenantPerSecond } = opts;
    if (
      perTenantPerSecond !== undefined &&
      (!Number.isFinite(perTenantPerSecond) || perTenantPerSecond <= 0)
    ) {
      throw new RangeError(
        `perTenantPerSecond must be a finite number > 0, got ${perTenantPerSecond}`
      );
    }
    this.perTenant = perTenantPerSecond;
    this.now = opts.now ?? Date.now;
  }

  /** The configured per-tenant budget (undefined = unlimited). */
  perTenantLimit(): number | undefined {
    return this.perTenant;
  }

  private refill(key: string, perSecond: number): Bucket {
    const at = this.now();
    let b = this.buckets.get(key);
    if (!b) {
      // A new tenant starts with a full bucket: the first second of
      // budget is available immediately, then it refills continuously.
      b = { tokens: perSecond, updatedMs: at };
      this.buckets.set(key, b);
    } else {
      // Clamp clock skew at zero: a backward clock never grants extra budget.
      const elapsedMs = Math.max(0, at - b.updatedMs);
      b.tokens = Math.min(perSecond, b.tokens + (elapsedMs * perSecond) / 1000);
      b.updatedMs = at;
    }
    return b;
  }

  private peek(key: string, perSecond: number): boolean {
    return this.refill(key, perSecond).tokens >= 1;
  }

  private consume(key: string, perSecond: number): void {
    this.refill(key, perSecond).tokens -= 1;
  }

  /** Milliseconds until `key`'s bucket has one token (0 if it already does). */
  private msUntilToken(key: string, perSecond: number): number {
    const b = this.refill(key, perSecond);
    if (b.tokens >= 1) return 0;
    return Math.ceil(((1 - b.tokens) * 1000) / perSecond);
  }

  /**
   * Try to admit one request for `tenant`. Peek-then-consume: a rejected
   * request never burns a token. `tenant` must be a validated tenant id
   * (see `assertValidTenantId` in `src/tenant.ts`); the limiter itself
   * does not re-validate.
   */
  take(tenant: string): InboundTenantRateLimitVerdict {
    const limit = this.perTenant;
    if (limit === undefined) return { ok: true };
    if (!this.peek(tenant, limit)) {
      return { ok: false, retryAfterMs: this.msUntilToken(tenant, limit) };
    }
    this.consume(tenant, limit);
    return { ok: true };
  }

  /** Tenants currently tracked (distinct ids ever seen). */
  trackedTenants(): number {
    return this.buckets.size;
  }
}

/**
 * Denial counters by tenant. Renders to Prometheus exposition text;
 * renders `""` when nothing was denied, keeping `GET /metrics`
 * byte-identical for relays that never enable the limiter (the
 * `IpAclMetrics` pattern for intake admission metrics).
 */
export class InboundTenantRateLimitMetrics {
  private readonly limited = new Map<string, number>();

  /** Record one denial for `tenant`. */
  record(tenant: string): void {
    this.limited.set(tenant, (this.limited.get(tenant) ?? 0) + 1);
  }

  /** Prometheus text exposition (0.0.4) of the counters; `""` when empty. */
  render(): string {
    if (this.limited.size === 0) return "";
    const esc = (v: string): string =>
      v.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, '\\"');
    const lines = [
      "# HELP relay_inbound_tenant_limited_total Inbound webhook requests rejected by the per-tenant inbound rate limiter (WR-141), by tenant.",
      "# TYPE relay_inbound_tenant_limited_total counter",
    ];
    for (const [tenant, n] of this.limited) {
      lines.push(`relay_inbound_tenant_limited_total{tenant="${esc(tenant)}"} ${n}`);
    }
    return lines.join("\n") + "\n";
  }
}
