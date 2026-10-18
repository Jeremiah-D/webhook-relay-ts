/**
 * Operator health summary (WR-87): one human-readable JSON aggregate over
 * the relay's per-endpoint health signals — circuit state and
 * consecutive-failure streaks (WR-10), quota exhaustion (WR-15),
 * downstream probe state (WR-34), the global retry-budget headroom
 * (WR-38), and the top-N tenants by delivery volume (WR-78 usage meter).
 *
 * Pure read aggregation: it only calls the queue's stats getters and the
 * usage meter's snapshot, so it has zero write impact. It complements
 * `/metrics` (machine-readable exposition) with a human-readable view —
 * one call answers "which endpoints are unhealthy and who is driving
 * volume" instead of correlating five series by hand.
 */

import type { CircuitState, CircuitStats } from "./circuit.ts";
import type { QuotaStats } from "./quota.ts";
import type { ProbeEndpointStats } from "./downstream-probe.ts";
import type { TenantUsage } from "./usage.ts";
import { tenantScopeKey } from "./tenant.ts";

/** WR-10 circuit snapshot for one (tenant, endpoint) row. */
export interface HealthSummaryCircuit {
  state: CircuitState;
  /** Consecutive failures since the last success (0 once closed). */
  consecutiveFailures: number;
  /** Total closed->open and half_open->open trips since construction. */
  trips: number;
  /** ms epoch when the circuit last opened; absent when never tripped. */
  openedAtMs?: number;
}

/** WR-34 downstream probe snapshot (endpoint-scoped, not per tenant). */
export interface HealthSummaryProbe {
  success: number;
  failure: number;
  /** Consecutive failures since the last success (0 once healthy). */
  consecutiveFailures: number;
  /** ms epoch of the last completed round; absent before the first round. */
  lastProbeAtMs?: number;
}

/** One merged health row. */
export interface HealthSummaryEndpoint {
  endpoint: string;
  /** Tenant id; absent for the default tenant (WR-48 row convention). */
  tenant?: string;
  /** WR-10 circuit state; absent when the breaker is disabled. */
  circuit?: HealthSummaryCircuit;
  /** WR-15 quota delays (attempts parked on an exhausted budget); absent when the quota is disabled or never exhausted. */
  quotaDelayed?: number;
  /**
   * WR-34 downstream probe state. The prober is endpoint-scoped, so the
   * same probe object repeats on every tenant row of that endpoint —
   * read it as endpoint-global, not per tenant. Absent when probing is
   * disabled.
   */
  probe?: HealthSummaryProbe;
}

/** WR-38 global retry-budget headroom. */
export interface HealthSummaryRetryBudget {
  /** Configured retries-per-minute budget. */
  retriesPerMinute: number;
  /** Retries parked because the budget was exhausted. */
  depleted: number;
}

/** WR-136 adaptive inbound throttle snapshot (intake self-protection). */
export interface HealthSummaryInboundRateLimit {
  /** Whether the throttle has engaged (queue depth at/above the high mark). */
  throttled: boolean;
  /** Per-endpoint budget currently enforced (requests/sec). */
  effectivePerEndpointPerSecond: number;
  /** Retry-queue pending depth the snapshot was taken at. */
  pendingDepth: number;
}

/** One WR-78 usage row, trimmed to the fields a health reader needs. */
export interface HealthSummaryTenantUsage {
  tenant: string;
  windowMs: number;
  delivered: number;
  failed: number;
  retried: number;
  deadLetter: number;
  bytesIn: number;
  bytesOut: number;
  urgent: number;
}

/** The `GET /health/summary` response body. */
export interface HealthSummary {
  /** ISO-8601 instant the snapshot was taken. */
  at: string;
  /** Global retry budget (WR-38); absent when the budget is disabled. */
  retryBudget?: HealthSummaryRetryBudget;
  /**
   * Adaptive inbound throttle (WR-136); absent when the adaptive
   * limiter is unconfigured.
   */
  inboundRateLimit?: HealthSummaryInboundRateLimit;
  /** One row per (tenant, endpoint) with any health signal, first-seen order. */
  endpoints: HealthSummaryEndpoint[];
  /** Top tenants by delivery volume in the usage window (WR-78); empty when usage metering is unconfigured. */
  tenantUsageTop: HealthSummaryTenantUsage[];
}

export interface HealthSummaryInput {
  circuits: CircuitStats[];
  quotas: QuotaStats[];
  probes: ProbeEndpointStats[];
  /** `undefined` when the global retry budget is disabled. */
  retryBudget?: HealthSummaryRetryBudget;
  /** `undefined` (or empty) when usage metering is unconfigured. */
  usage?: TenantUsage[];
  /**
   * WR-136 adaptive inbound throttle state; `undefined` when the
   * adaptive limiter is not configured.
   */
  inboundRateLimit?: HealthSummaryInboundRateLimit;
  /** Rows to keep in `tenantUsageTop`. Default 10. */
  topTenants?: number;
}

function deliveryTotal(u: TenantUsage): number {
  return u.delivered + u.failed + u.retried + u.deadLetter;
}

/**
 * Merge the relay's health signals into one snapshot. All inputs are
 * already-aggregated getters — this function never touches the queue or
 * any mutable state.
 */
export function buildHealthSummary(input: HealthSummaryInput): HealthSummary {
  const topTenants = input.topTenants ?? 10;
  if (!Number.isInteger(topTenants) || topTenants < 1) {
    throw new RangeError(`topTenants must be an integer >= 1, got ${input.topTenants}`);
  }

  // Merge keyed by the WR-48 tenant scope key so the same (tenant,
  // endpoint) rows line up exactly like `getCircuitStats`/`getQuotaStats`.
  const rows = new Map<string, HealthSummaryEndpoint>();
  const rowFor = (tenant: string | undefined, endpoint: string): HealthSummaryEndpoint => {
    const key = tenantScopeKey(tenant, endpoint);
    let row = rows.get(key);
    if (row === undefined) {
      row = tenant === undefined ? { endpoint } : { endpoint, tenant };
      rows.set(key, row);
    }
    return row;
  };

  for (const c of input.circuits) {
    rowFor(c.tenant, c.endpoint).circuit = {
      state: c.state,
      consecutiveFailures: c.consecutiveFailures,
      trips: c.trips,
      ...(c.openedAtMs !== undefined ? { openedAtMs: c.openedAtMs } : {}),
    };
  }
  for (const q of input.quotas) {
    rowFor(q.tenant, q.endpoint).quotaDelayed = q.delayed;
  }
  // Probes are endpoint-scoped: fan the same probe state out to every
  // tenant row of that endpoint, and add a tenant-less row when the
  // endpoint has no other health signal yet.
  for (const p of input.probes) {
    const probe: HealthSummaryProbe = {
      success: p.success,
      failure: p.failure,
      consecutiveFailures: p.consecutiveFailures,
      ...(p.lastProbeAtMs !== undefined ? { lastProbeAtMs: p.lastProbeAtMs } : {}),
    };
    let fannedOut = false;
    for (const row of rows.values()) {
      if (row.endpoint === p.endpoint) {
        row.probe = probe;
        fannedOut = true;
      }
    }
    if (!fannedOut) {
      rows.set(tenantScopeKey(undefined, p.endpoint), { endpoint: p.endpoint, probe });
    }
  }

  // Top-N tenants by delivery volume (deliveries dominate bytes for a
  // health reader); ties break by tenant name for a deterministic order.
  const tenantUsageTop: HealthSummaryTenantUsage[] = (input.usage ?? [])
    .slice()
    .sort(
      (a, b) =>
        deliveryTotal(b) - deliveryTotal(a) ||
        (a.tenant < b.tenant ? -1 : a.tenant > b.tenant ? 1 : 0)
    )
    .slice(0, topTenants)
    .map((u) => ({
      tenant: u.tenant,
      windowMs: u.windowMs,
      delivered: u.delivered,
      failed: u.failed,
      retried: u.retried,
      deadLetter: u.deadLetter,
      bytesIn: u.bytesIn,
      bytesOut: u.bytesOut,
      urgent: u.urgent,
    }));

  return {
    at: new Date().toISOString(),
    ...(input.retryBudget !== undefined
      ? {
          retryBudget: {
            retriesPerMinute: input.retryBudget.retriesPerMinute,
            depleted: input.retryBudget.depleted,
          },
        }
      : {}),
    ...(input.inboundRateLimit !== undefined
      ? {
          inboundRateLimit: {
            throttled: input.inboundRateLimit.throttled,
            effectivePerEndpointPerSecond: input.inboundRateLimit.effectivePerEndpointPerSecond,
            pendingDepth: input.inboundRateLimit.pendingDepth,
          },
        }
      : {}),
    endpoints: [...rows.values()],
    tenantUsageTop,
  };
}
