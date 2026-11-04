/**
 * Per-tenant retry budget (WR-200): retry-storm protection scoped to one
 * tenant.
 *
 * The global retry budget (WR-38) is one token bucket for the whole queue;
 * the per-endpoint overrides (WR-125) give single endpoints their own
 * buckets. This module is the tenant counterpart: every tenant gets its
 * own token bucket sized to one minute of *scheduled retries* (a failed
 * attempt that will be tried again; first attempts are never gated).
 * Every scheduled retry costs one token from its tenant's bucket; when a
 * tenant's bucket is empty that tenant's retries are parked until the
 * next token refill — never dropped, never burned against the item's
 * attempt budget, never touching the circuit breaker. Other tenants are
 * unaffected, so a retry storm in one tenant parks only that tenant's
 * retries instead of starving the rest of the relay.
 *
 * Buckets are created lazily on first use: a tenant that never schedules
 * a retry costs nothing. The default (tenant-less) tenant gets its own
 * bucket too — keyed by the empty string, which can never collide with a
 * real tenant id (WR-48 requires 1–64 chars).
 *
 * Orthogonal to:
 * - WR-38 (global retry budget — the cross-tenant master gate; a tenant
 *   park never consumes a global token, and a global park still gates
 *   every tenant),
 * - WR-125 (per-endpoint retry-budget overrides — gate first),
 * - WR-137 (per-tenant *delivery* budget, a monthly billing dimension —
 *   this is a per-minute *retry* scheduling gate).
 *
 * The gate order for one scheduled retry is: per-endpoint override
 * (WR-125) -> per-tenant (this module) -> global (WR-38).
 *
 * Zero dependencies beyond the shared token-bucket implementation.
 * Clock-injectable for deterministic tests.
 */

import { RetryBudget } from "./retry-budget.ts";
import { assertValidTenantId } from "./tenant.ts";

/** Options for the per-tenant retry budget (see `RetryQueueOptions.tenantRetryBudget`). */
export interface TenantRetryBudgetOptions {
  /**
   * Default maximum scheduled retries per minute *per tenant*. Each
   * scheduled retry consumes one token from its tenant's bucket; when
   * the bucket is empty the retry waits for the refill window. Must be
   * a finite number > 0. Default: 6000 (generous — a guard rail, not a
   * throttle; mirrors WR-38).
   */
  retriesPerMinute?: number;
  /**
   * Per-tenant overrides: tenant id -> retries-per-minute. A tenant with
   * an override gates on its own bucket size; tenants without one use
   * the default. Each value must be a finite number > 0; illegal values
   * throw `RangeError` at construction. Opt-in: absent by default.
   */
  perTenantRetriesPerMinute?: Record<string, number>;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
}

/** Default per-tenant retry budget: generous enough to stay out of the way. */
export const DEFAULT_TENANT_RETRY_BUDGET_PER_MINUTE = 6000;

/** Tenant key for the default (tenant-less) tenant. Never a real tenant id. */
export const DEFAULT_TENANT_KEY = "";

/**
 * Per-tenant retry budget: one lazily-created `RetryBudget` token bucket
 * per tenant. The caller decides what to do with a denied retry (the
 * retry queue reschedules it without consuming the attempt budget).
 */
export class TenantRetryBudget {
  /** Mutable (WR-326): the live default, revised by `reviseDefault()`. */
  private defaultPerMinute: number;
  private readonly overrides = new Map<string, number>();
  private readonly buckets = new Map<string, RetryBudget>();
  private readonly now: () => number;

  constructor(opts: TenantRetryBudgetOptions = {}) {
    const perMinute = opts.retriesPerMinute ?? DEFAULT_TENANT_RETRY_BUDGET_PER_MINUTE;
    if (!Number.isFinite(perMinute) || perMinute <= 0) {
      throw new RangeError(`tenantRetryBudget.retriesPerMinute must be a finite number > 0, got ${perMinute}`);
    }
    this.defaultPerMinute = perMinute;
    const perTenant = opts.perTenantRetriesPerMinute;
    if (perTenant !== undefined) {
      if (typeof perTenant !== "object" || perTenant === null || Array.isArray(perTenant)) {
        throw new RangeError(
          "tenantRetryBudget.perTenantRetriesPerMinute must be a record of tenantId -> retriesPerMinute"
        );
      }
      for (const [tenant, rate] of Object.entries(perTenant)) {
        // Throws TypeError/RangeError on a malformed tenant id.
        assertValidTenantId(tenant);
        if (!Number.isFinite(rate) || rate <= 0) {
          throw new RangeError(
            `tenantRetryBudget.perTenantRetriesPerMinute[${JSON.stringify(tenant)}] must be a finite number > 0, got ${rate}`
          );
        }
        this.overrides.set(tenant, rate);
      }
    }
    this.now = opts.now ?? Date.now;
  }

  /** Bucket key for a tenant; `undefined` is the default tenant. */
  private key(tenant: string | undefined): string {
    return tenant ?? DEFAULT_TENANT_KEY;
  }

  private budgetFor(tenant: string | undefined): RetryBudget {
    const k = this.key(tenant);
    let b = this.buckets.get(k);
    if (b === undefined) {
      b = new RetryBudget(this.overrides.get(k) ?? this.defaultPerMinute, this.now);
      this.buckets.set(k, b);
    }
    return b;
  }

  /**
   * Consume one token for a scheduled retry of `tenant`. Returns `false`
   * when the tenant's budget is exhausted — the caller should park and
   * re-schedule, never drop.
   */
  take(tenant: string | undefined): boolean {
    return this.budgetFor(tenant).take();
  }

  /**
   * Milliseconds until one token is available for `tenant` (0 when a
   * token is already available). Used to re-schedule a parked retry at
   * the earliest honest moment.
   */
  msUntilToken(tenant: string | undefined): number {
    return this.budgetFor(tenant).msUntilToken();
  }

  /** Configured default per-minute budget (before overrides). */
  defaultLimit(): number {
    return this.defaultPerMinute;
  }

  /** Effective per-minute budget for `tenant` (override or default). */
  limitFor(tenant: string | undefined): number {
    const b = this.buckets.get(this.key(tenant));
    if (b !== undefined) return b.limit();
    return this.overrides.get(this.key(tenant)) ?? this.defaultPerMinute;
  }

  /** Whether `tenant` carries an explicit override. */
  hasOverride(tenant: string): boolean {
    return this.overrides.has(tenant);
  }

  /**
   * WR-326: revise the default per-minute budget live — the rate every
   * tenant without an override gates on. An illegal value throws
   * `RangeError` and the live default and buckets are untouched;
   * revising to the current default is a silent no-op. Every already
   * created bucket without an override is retuned in place (tightening
   * clamps at once, widening never tops a bucket up); buckets with an
   * override keep their own rate, and tenants not yet seen pick the
   * new default up lazily at their first `take()`. Returns the live
   * default.
   */
  reviseDefault(newPerMinute: number): number {
    if (!Number.isFinite(newPerMinute) || newPerMinute <= 0) {
      throw new RangeError(
        `tenantRetryBudget.retriesPerMinute must be a finite number > 0, got ${newPerMinute}`
      );
    }
    if (newPerMinute === this.defaultPerMinute) return this.defaultPerMinute;
    this.defaultPerMinute = newPerMinute;
    for (const [key, bucket] of this.buckets) {
      if (this.overrides.has(key)) continue;
      bucket.retune(newPerMinute);
    }
    return this.defaultPerMinute;
  }

  /**
   * WR-326: revise (or set) one tenant's override live. The tenant id
   * is validated first (`TypeError`/`RangeError` on a malformed id),
   * then the rate (`RangeError` on an illegal value) — either failure
   * leaves the live budget completely untouched. Revising to the
   * tenant's effective current rate is a silent no-op (no override is
   * recorded). Otherwise the override is recorded and an existing
   * bucket is retuned in place (tightening clamps at once, widening
   * never tops it up); a tenant not yet seen is only recorded, and
   * its first `take()` builds a bucket at the new rate. Other tenants
   * and the default are untouched. Returns the tenant's live rate.
   */
  reviseTenant(tenant: string, newPerMinute: number): number {
    assertValidTenantId(tenant);
    if (!Number.isFinite(newPerMinute) || newPerMinute <= 0) {
      throw new RangeError(
        `tenantRetryBudget.perTenantRetriesPerMinute[${JSON.stringify(tenant)}] must be a finite number > 0, got ${newPerMinute}`
      );
    }
    const current = this.limitFor(tenant);
    if (newPerMinute === current) return current;
    this.overrides.set(tenant, newPerMinute);
    const bucket = this.buckets.get(tenant);
    if (bucket !== undefined) bucket.retune(newPerMinute);
    return newPerMinute;
  }

  /**
   * WR-326: remove one tenant's override — the tenant falls back to
   * the live default rate. An existing bucket is retuned in place to
   * the default (token state preserved, bucket kept), so in-flight
   * retries are unaffected. Returns `true` when an override was
   * removed, `false` when the tenant had none. A malformed tenant id
   * throws `TypeError`/`RangeError`.
   */
  removeTenant(tenant: string): boolean {
    assertValidTenantId(tenant);
    if (!this.overrides.has(tenant)) return false;
    this.overrides.delete(tenant);
    const bucket = this.buckets.get(tenant);
    if (bucket !== undefined) bucket.retune(this.defaultPerMinute);
    return true;
  }

  /** Tenant ids with an explicit override. */
  configuredTenants(): string[] {
    return [...this.overrides.keys()];
  }
}
