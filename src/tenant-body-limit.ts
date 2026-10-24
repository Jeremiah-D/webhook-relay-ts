import { assertValidTenantId } from "./tenant.ts";

/**
 * Per-tenant inbound body budgets (WR-203): tenant id -> max body bytes.
 * Layered on top of the WR-25 global `maxBodyBytes` and the WR-102
 * per-endpoint rules — when the inbound `x-tenant-id` header claims a
 * tenant with a configured budget, that budget governs the request's
 * intake instead of the endpoint/global budget.
 */
export type TenantBodyLimits = Record<string, number>;

/**
 * Validate a per-tenant body-budget map. Throws `RangeError` on anything
 * illegal — at server construction, never mid-request. Tenant ids go
 * through the WR-48 validator so a typo'd key fails fast instead of
 * silently never matching; values must be positive integers like
 * `maxBodyBytes`.
 */
export function assertValidTenantBodyLimits(limits: unknown): void {
  if (limits === null || typeof limits !== "object" || Array.isArray(limits)) {
    throw new RangeError(
      `tenantBodyLimits must be a record of tenant id -> max body bytes, got ${JSON.stringify(limits)}`
    );
  }
  for (const [tenant, bytes] of Object.entries(limits as Record<string, unknown>)) {
    try {
      assertValidTenantId(tenant);
    } catch (err) {
      throw new RangeError(
        `tenantBodyLimits: invalid tenant id ${JSON.stringify(tenant)}: ${(err as Error).message}`
      );
    }
    if (!Number.isInteger(bytes) || (bytes as number) <= 0) {
      throw new RangeError(
        `tenantBodyLimits[${JSON.stringify(tenant)}]: max body bytes must be a positive integer, got ${JSON.stringify(bytes)}`
      );
    }
  }
}

/**
 * Look up a tenant's configured budget. `undefined` when the tenant is
 * unset or has no override — the caller falls back to the endpoint rule /
 * global budget. The lookup is `hasOwnProperty`-guarded so a crafted
 * header value can never resolve through the prototype chain.
 */
export function selectTenantBodyLimit(
  tenant: string | undefined,
  limits: TenantBodyLimits | undefined
): number | undefined {
  if (tenant === undefined || limits === undefined) return undefined;
  if (!Object.prototype.hasOwnProperty.call(limits, tenant)) return undefined;
  return limits[tenant];
}

/** A tenant's budget that actually applies to one request's intake. */
export interface TenantBodyBudget {
  /** The validated tenant id the budget was selected for. */
  tenant: string;
  /** Max body bytes for this request's intake. */
  bytes: number;
}

/**
 * Resolve the per-tenant body budget for one inbound request from its
 * raw `x-tenant-id` header — before a single body byte is read and before
 * signature verification (the WR-25 checkpoint). An absent, invalid, or
 * unconfigured tenant id yields `undefined` (the endpoint/global budget
 * applies); full WR-48 tenant validation still happens after
 * verification, so unauthenticated callers learn nothing new — this only
 * sizes the intake buffer.
 */
export function resolveTenantBodyBudget(
  tenantHeader: string | string[] | undefined,
  limits: TenantBodyLimits | undefined
): TenantBodyBudget | undefined {
  const raw = Array.isArray(tenantHeader) ? tenantHeader[0] : tenantHeader;
  if (typeof raw !== "string" || raw === "") return undefined;
  try {
    assertValidTenantId(raw);
  } catch {
    // Invalid tenant id: no budget override here; the WR-48 400 after
    // verification still applies unchanged.
    return undefined;
  }
  const bytes = selectTenantBodyLimit(raw, limits);
  return bytes === undefined ? undefined : { tenant: raw, bytes };
}
