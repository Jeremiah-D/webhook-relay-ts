/**
 * Multi-tenant delivery isolation (WR-48).
 *
 * An inbound `x-tenant-id` header assigns the webhook to a tenant. The
 * tenant then scopes the per-(tenant, endpoint) isolation primitives:
 *
 * - the concurrency limiter (WR-06),
 * - the delivery quota (WR-15),
 * - the circuit breaker (WR-10),
 * - the accepted→delivered latency tracker (WR-13),
 *
 * each gets an independent instance per tenant, so one tenant's flood or
 * downstream outage cannot consume another tenant's concurrency budget,
 * quota, or trip its breaker. Delivery counters, circuit gauges, latency
 * histograms, audit events, and SSE delivery events all carry the tenant
 * as a label when one is set.
 *
 * Requests without the header run in the default tenant: the exact same
 * code paths with unscoped keys, so behavior is byte-for-byte identical
 * to before tenants existed.
 *
 * Deliberately shared (documented, not an oversight): the urgent-lane
 * token bucket and the DRR lane scheduler (dispatch-order mechanisms on
 * the shared physical downstream), the global retry budget (global by
 * design, WR-38), failover target routing, downstream health probes, and
 * batch merging — all of which are properties of the downstream, not of
 * the tenant.
 */

/** Inbound header claiming the tenant for one webhook. */
export const TENANT_ID_HEADER = "x-tenant-id";

/**
 * Validate a tenant id: 1–64 chars of `[A-Za-z0-9_-]` (the same charset
 * as trace IDs, so the value is safe in labels, log lines, and URLs).
 * Throws `TypeError` for non-strings, `RangeError` for bad values — the
 * server answers 400 and never enqueues.
 */
export function assertValidTenantId(id: string): void {
  if (typeof id !== "string") {
    throw new TypeError(`tenant id must be a string, got ${typeof id}`);
  }
  if (id.length === 0 || id.length > 64 || !/^[A-Za-z0-9_-]+$/.test(id)) {
    throw new RangeError(
      "tenant id must be 1-64 chars of [A-Za-z0-9_-]"
    );
  }
}

/**
 * Tenant scope key for per-(tenant, endpoint) state. The default
 * (tenant-less) scope keys plain endpoints — byte-identical to the
 * pre-tenant relay — while a tenant prefixes its id. `\n` cannot appear
 * in a tenant id (charset `[A-Za-z0-9_-]`) or in a URL, so the split is
 * unambiguous.
 */
export function tenantScopeKey(tenant: string | undefined, endpoint: string): string {
  return tenant === undefined ? endpoint : `${tenant}\n${endpoint}`;
}

/** Inverse of {@link tenantScopeKey}. */
export function splitTenantScopeKey(key: string): { tenant?: string; endpoint: string } {
  const i = key.indexOf("\n");
  return i < 0 ? { endpoint: key } : { tenant: key.slice(0, i), endpoint: key.slice(i + 1) };
}
