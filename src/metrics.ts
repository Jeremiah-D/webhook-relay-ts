/**
 * Prometheus text exposition (0.0.4), hand-written, zero dependencies —
 * the metrics surface for `GET /metrics`:
 *
 * - `relay_deliveries_total{endpoint,status}`: counter per delivery outcome.
 *   `status` is one of:
 *   - `delivered`: a delivery attempt succeeded;
 *   - `failed`: a delivery attempt failed (every failure, including the
 *     final one that exhausts the retry budget);
 *   - `retried`: a failure was followed by a scheduled retry
 *     (`failed` minus the budget-exhausting final failures);
 *   - `dead_letter`: the item exhausted `maxAttempts`.
 * - `relay_endpoint_circuit_state{endpoint}`: gauge, 0 = closed,
 *   1 = half_open, 2 = open. Present only for endpoints that tripped.
 * - `relay_delivery_latency_seconds_{bucket,sum,count}{endpoint}`:
 *   histogram of accepted→delivered latency (seconds). Present only when
 *   latency tracking is enabled (`RetryQueueOptions.latency`); bucket
 *   bounds come from `MetricsOptions.histogramBucketsMs`.
 * - `relay_probe_total{endpoint,result}`: counter of downstream
 *   health-probe outcomes (`result` = `success` / `failure`), present only
 *   when active probing is enabled (`RetryQueueOptions.probe`).
 * - `relay_probe_consecutive_failures{endpoint}`: gauge of the current
 *   consecutive probe-failure streak per endpoint (0 = healthy), present
 *   only when active probing is enabled.
 * - `relay_starvation_guard_activations{endpoint}`: counter of
 *   starvation-guard activation episodes (the deficit round-robin lane
 *   scheduler started deferring urgent dispatches while normal demand was
 *   backlogged), present only for endpoints where the guard activated.
 * - `relay_failover_switches_total{endpoint,from,to}`: counter of
 *   active/standby failover switches (WR-39) by logical endpoint,
 *   present only for (endpoint, from, to) triples that actually switched.
 * - `relay_retry_budget_depleted_total`: counter of retries parked because
 *   the global retry budget (WR-38) was exhausted. Present only when the
 *   budget is enabled. No endpoint label — the budget is global.
 *
 * Cardinality note: labels are per endpoint (`targetUrl`), so a relay
 * fanning out to many distinct downstream URLs grows the series count —
 * the same tradeoff the JSON operator endpoints already make.
 */

/** One endpoint's delivery counters, in Prometheus label order. */
export interface DeliveryCountersInput {
  endpoint: string;
  /** Tenant id (WR-48); when set it is rendered as a `tenant` label. */
  tenant?: string;
  delivered: number;
  failed: number;
  retried: number;
  deadLetter: number;
}

export interface CircuitStateInput {
  endpoint: string;
  /** Tenant id (WR-48); when set it is rendered as a `tenant` label. */
  tenant?: string;
  state: "closed" | "half_open" | "open";
}

export interface LatencyHistogramInput {
  endpoint: string;
  /** Tenant id (WR-48); when set it is rendered as a `tenant` label. */
  tenant?: string;
  /** Ascending bucket upper bounds in seconds, without +Inf. */
  bucketBounds: number[];
  /** Cumulative sample counts per bound (same length as `bucketBounds`). */
  bucketCounts: number[];
  /** Sum of all samples, in seconds. */
  sum: number;
  /** Total sample count (also the +Inf bucket). */
  count: number;
}

export interface MetricsInput {
  deliveries: DeliveryCountersInput[];
  circuits: CircuitStateInput[];
  latencyHistograms: LatencyHistogramInput[];
  /** Present only when active downstream probing is enabled. */
  probes?: ProbeMetricsInput[];
  /** Present only for endpoints where the starvation guard activated. */
  starvationGuard?: StarvationGuardMetricsInput[];
  /** Present only for (endpoint, from, to) triples that actually switched. */
  failover?: FailoverMetricsInput[];
  /** Present only when the global retry budget (WR-38) is enabled. */
  retryBudgetDepleted?: number;
}

/** One endpoint's starvation-guard activation count, in Prometheus label order. */
export interface StarvationGuardMetricsInput {
  endpoint: string;
  activations: number;
}

/** One failover switch count, in Prometheus label order. */
export interface FailoverMetricsInput {
  /** Logical endpoint (the configured primary `targetUrl`). */
  endpoint: string;
  /** Target deliveries were going to before the switch. */
  from: string;
  /** Target deliveries go to after the switch. */
  to: string;
  switches: number;
}

/** One endpoint's health-probe counters, in Prometheus label order. */
export interface ProbeMetricsInput {
  endpoint: string;
  success: number;
  failure: number;
  /** Current consecutive-failure streak (0 once healthy). */
  consecutiveFailures: number;
}

/** Escape a label value per the Prometheus exposition format. */
function escapeLabelValue(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, '\\"');
}

/**
 * WR-48: the `tenant="…"` label fragment for a series, or `""` when the
 * input carries no tenant — so the default tenant's exposition is
 * byte-identical to the pre-tenant relay.
 */
function tenantLabel(tenant: string | undefined): string {
  return tenant === undefined ? "" : `,tenant="${escapeLabelValue(tenant)}"`;
}

/** Render the snapshot in Prometheus text exposition format (0.0.4). */
export function renderPrometheus(input: MetricsInput): string {
  const lines: string[] = [];
  lines.push("# HELP relay_deliveries_total Deliveries by endpoint and outcome.");
  lines.push("# TYPE relay_deliveries_total counter");
  for (const d of input.deliveries) {
    const ep = escapeLabelValue(d.endpoint);
    const tl = tenantLabel(d.tenant);
    lines.push(`relay_deliveries_total{endpoint="${ep}"${tl},status="delivered"} ${d.delivered}`);
    lines.push(`relay_deliveries_total{endpoint="${ep}"${tl},status="failed"} ${d.failed}`);
    lines.push(`relay_deliveries_total{endpoint="${ep}"${tl},status="retried"} ${d.retried}`);
    lines.push(`relay_deliveries_total{endpoint="${ep}"${tl},status="dead_letter"} ${d.deadLetter}`);
  }
  if (input.circuits.length > 0) {
    lines.push(
      "# HELP relay_endpoint_circuit_state Endpoint circuit breaker state (0=closed, 1=half_open, 2=open)."
    );
    lines.push("# TYPE relay_endpoint_circuit_state gauge");
    for (const c of input.circuits) {
      const n = c.state === "closed" ? 0 : c.state === "half_open" ? 1 : 2;
      lines.push(
        `relay_endpoint_circuit_state{endpoint="${escapeLabelValue(c.endpoint)}"${tenantLabel(c.tenant)}} ${n}`
      );
    }
  }
  if (input.latencyHistograms.length > 0) {
    lines.push("# HELP relay_delivery_latency_seconds Accepted-to-delivered latency by endpoint.");
    lines.push("# TYPE relay_delivery_latency_seconds histogram");
    for (const h of input.latencyHistograms) {
      const ep = escapeLabelValue(h.endpoint);
      const tl = tenantLabel(h.tenant);
      for (let i = 0; i < h.bucketBounds.length; i++) {
        lines.push(
          `relay_delivery_latency_seconds_bucket{endpoint="${ep}"${tl},le="${h.bucketBounds[i]}"} ${h.bucketCounts[i]}`
        );
      }
      lines.push(`relay_delivery_latency_seconds_bucket{endpoint="${ep}"${tl},le="+Inf"} ${h.count}`);
      lines.push(`relay_delivery_latency_seconds_sum{endpoint="${ep}"${tl}} ${h.sum}`);
      lines.push(`relay_delivery_latency_seconds_count{endpoint="${ep}"${tl}} ${h.count}`);
    }
  }
  if (input.probes !== undefined && input.probes.length > 0) {
    lines.push("# HELP relay_probe_total Downstream health-probe outcomes by endpoint.");
    lines.push("# TYPE relay_probe_total counter");
    lines.push(
      "# HELP relay_probe_consecutive_failures Current consecutive probe failures by endpoint."
    );
    lines.push("# TYPE relay_probe_consecutive_failures gauge");
    for (const p of input.probes) {
      const ep = escapeLabelValue(p.endpoint);
      lines.push(`relay_probe_total{endpoint="${ep}",result="success"} ${p.success}`);
      lines.push(`relay_probe_total{endpoint="${ep}",result="failure"} ${p.failure}`);
      lines.push(`relay_probe_consecutive_failures{endpoint="${ep}"} ${p.consecutiveFailures}`);
    }
  }
  if (input.starvationGuard !== undefined && input.starvationGuard.length > 0) {
    lines.push(
      "# HELP relay_starvation_guard_activations Starvation-guard activation episodes by endpoint."
    );
    lines.push("# TYPE relay_starvation_guard_activations counter");
    for (const s of input.starvationGuard) {
      lines.push(
        `relay_starvation_guard_activations{endpoint="${escapeLabelValue(s.endpoint)}"} ${s.activations}`
      );
    }
  }
  if (input.failover !== undefined && input.failover.length > 0) {
    lines.push(
      "# HELP relay_failover_switches_total Failover target switches by logical endpoint (from -> to)."
    );
    lines.push("# TYPE relay_failover_switches_total counter");
    for (const f of input.failover) {
      lines.push(
        `relay_failover_switches_total{endpoint="${escapeLabelValue(f.endpoint)}",from="${escapeLabelValue(f.from)}",to="${escapeLabelValue(f.to)}"} ${f.switches}`
      );
    }
  }
  if (input.retryBudgetDepleted !== undefined) {
    lines.push(
      "# HELP relay_retry_budget_depleted_total Retries parked because the global retry budget was exhausted."
    );
    lines.push("# TYPE relay_retry_budget_depleted_total counter");
    lines.push(`relay_retry_budget_depleted_total ${input.retryBudgetDepleted}`);
  }
  return lines.join("\n") + "\n";
}
