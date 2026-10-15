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
 * - `relay_endpoint_circuit_error_rate{endpoint}`: gauge, the rolling-window
 *   failure rate in [0, 1] (WR-104 error-rate trip mode). Present only for
 *   error-rate-mode endpoints with at least one recorded outcome.
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
 * - `relay_weighted_dispatch_total{endpoint,target}`: counter of
 *   dispatches routed to each physical target by logical endpoint
 *   (WR-66 weighted multi-target dispatch), present only when weighted
 *   mode is in use and only for (endpoint, target) pairs that actually
 *   received a dispatch.
 * - `relay_retry_budget_depleted_total`: counter of retries parked because
 *   the global retry budget (WR-38) was exhausted. Present only when the
 *   budget is enabled. No endpoint label — the budget is global.
 * - `relay_global_concurrency_wait_total`: counter of dispatches that had
 *   to wait for a relay-level global concurrency slot (WR-51). Present
 *   only when the cap is configured (finite). No endpoint label — the
 *   cap is relay-wide.
 * - `relay_scheduled_total` / `relay_scheduled_due_total` /
 *   `relay_scheduled_canceled_total`: counters of deliveries parked for a
 *   future `deliver_at` (WR-57), of parked deliveries whose instant
 *   arrived, and of parked deliveries canceled before it. Present only
 *   once a delivery has actually been parked. No endpoint label — the
 *   delay queue is relay-wide.
 * - `relay_slo_risk_seconds{endpoint}`: gauge of predicted SLO headroom
 *   remaining before breach, in seconds (WR-71 early warning). Present
 *   only for endpoints currently elevated by the SLO-risk predictor —
 *   absent entirely when the predictor is disabled or nothing is at risk.
 * - `relay_cert_expiry_seconds{endpoint,kind}`: gauge of seconds until the
 *   observed TLS certificate expires (negative when already expired;
 *   WR-73). `kind` is `downstream` (the peer's certificate, captured at
 *   handshake time) or `client` (the relay's own mTLS client certificate,
 *   checked at config load). Present only for endpoints whose certificate
 *   was actually observed — absent entirely when the monitor is disabled
 *   or nothing was observed yet.
 * - `relay_ocsp_total{endpoint,status}`: counter of outbound OCSP
 *   revocation check outcomes (WR-101), by endpoint. `status` is one of:
 *   - `good`: the peer's certificate is not revoked;
 *   - `revoked`: the peer's certificate is revoked (the delivery was
 *     rejected before a single payload byte was written);
 *   - `unknown`: the responder had no verdict for the certificate
 *     (handled per the endpoint's fail-open/fail-closed mode);
 *   - `error`: the revocation status could not be determined (no
 *     stapled response, no/failing responder, malformed response).
 *   Present only for endpoints where a check actually ran — absent
 *   entirely when the feature is off.
 * - `relay_otlp_exports_total{event_type,status}`: counter of delivery/SLO
 *   events exported to the OTLP collector (WR-83), by event type
 *   (`delivered` / `retrying` / `dead_letter` / `slo_missed` /
 *   `rate_limited` — WR-97) and export outcome (`success` = collector
 *   answered 2xx, `failure` = a failed POST attempt). Present only when
 *   OTLP export is enabled (`RetryQueueOptions.otlp`).
 * - `relay_otlp_buffered`: gauge of delivery/SLO events currently
 *   buffered for OTLP export. Present only when OTLP export is enabled.
 * - `relay_shadow_total{endpoint,shadow_target,result}`: counter of
 *   shadow-target mirrored delivery outcomes (WR-85 dry-run mirroring),
 *   by logical endpoint and shadow target (`result` = `delivered` /
 *   `failed`). Present only once a shadow target has actually received a
 *   mirrored copy — absent entirely when the feature is off.
 * - `relay_dead_letter_escalations_total{endpoint}`: counter of
 *   dead-letter storm escalation alerts (WR-93) dispatched per
 *   (tenant, endpoint) scope, with a `tenant` label when the scope is
 *   tenant-scoped. Activity-gated: present only for scopes that
 *   actually escalated — absent entirely when the feature is off.
 * - `relay_endpoint_auto_pauses_total{endpoint}`: counter of
 *   stale-endpoint auto-pauses (WR-100) per logical endpoint.
 *   Activity-gated: present only for endpoints that have actually been
 *   auto-paused — absent entirely when the feature is off.
 * - `relay_tenant_ratelimited_total{endpoint,tenant}`: counter of
 *   over-limit decisions (denials) by the per-(tenant, endpoint)
 *   outbound rate limiter (WR-97) — every denied `take()`, in both
 *   `queue` and `reject-429` modes. Activity-gated: present only for
 *   scopes that actually denied — absent entirely when the feature is
 *   off. The `tenant` label is omitted for the default tenant (the
 *   WR-48 convention).
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

/**
 * One error-rate-mode endpoint's rolling-window failure rate (WR-104),
 * in Prometheus label order.
 */
export interface CircuitErrorRateInput {
  endpoint: string;
  /** Tenant id (WR-48); when set it is rendered as a `tenant` label. */
  tenant?: string;
  /** Current rolling-window failure rate in [0, 1]. */
  errorRate: number;
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

/**
 * One shadow target's mirror counters (WR-85), in Prometheus label order.
 */
export interface ShadowMetricsInput {
  /** Logical endpoint (the configured primary `targetUrl`). */
  endpoint: string;
  /** Tenant id (WR-48); when set it is rendered as a `tenant` label. */
  tenant?: string;
  /** The shadow downstream URL that received the mirrored copy. */
  shadowTarget: string;
  /** Cumulative mirrored copies the shadow target answered (transport success). */
  delivered: number;
  /** Cumulative mirrored copies that failed (any error — silent, never retried). */
  failed: number;
}

/**
 * One (tenant, endpoint) scope's dead-letter storm escalation count
 * (WR-93), in Prometheus label order.
 */
export interface DeadLetterEscalationMetricsInput {
  /** Downstream endpoint whose dead letters piled up. */
  endpoint: string;
  /** Tenant id (WR-48); when set it is rendered as a `tenant` label. */
  tenant?: string;
  /** Cumulative escalation alerts dispatched for this scope. */
  escalations: number;
}

/** One endpoint's stale-endpoint auto-pause count (WR-100). */
export interface StalePauseMetricsInput {
  /** Auto-paused endpoint (logical `targetUrl`). */
  endpoint: string;
  /** Cumulative auto-pauses for this endpoint. */
  pauses: number;
}

/**
 * One endpoint's adaptive concurrency limit (WR-94), in Prometheus label
 * order. Only finite limits are rendered — a gauge cannot hold Infinity.
 */
export interface AdaptiveConcurrencyMetricsInput {
  /** Downstream endpoint (physical `targetUrl`). */
  endpoint: string;
  /** Tenant id (WR-48); when set it is rendered as a `tenant` label. */
  tenant?: string;
  /** The endpoint's current AIMD concurrency limit. */
  limit: number;
}

/**
 * One (tenant, endpoint) scope's outbound rate-limit denials (WR-97), in
 * Prometheus label order.
 */
export interface TenantRateLimitMetricsInput {
  /** Downstream endpoint (physical `targetUrl` at dispatch). */
  endpoint: string;
  /** Tenant id (WR-48); when set it is rendered as a `tenant` label. */
  tenant?: string;
  /** Cumulative over-limit decisions (denials) for this scope. */
  limited: number;
}

export interface MetricsInput {
  deliveries: DeliveryCountersInput[];
  circuits: CircuitStateInput[];
  /**
   * Present only for error-rate-mode (WR-104) endpoints with at least
   * one recorded outcome — activity-gated, so a relay that never enables
   * the mode exposes no `relay_endpoint_circuit_error_rate` series at
   * all.
   */
  circuitErrorRates?: CircuitErrorRateInput[];
  latencyHistograms: LatencyHistogramInput[];
  /** Present only when active downstream probing is enabled. */
  probes?: ProbeMetricsInput[];
  /** Present only for endpoints where the starvation guard activated. */
  starvationGuard?: StarvationGuardMetricsInput[];
  /** Present only for (endpoint, from, to) triples that actually switched. */
  failover?: FailoverMetricsInput[];
  /**
   * Present only when weighted multi-target dispatch (WR-66) is in use;
   * one series per (endpoint, target) pair that actually received a
   * dispatch.
   */
  weighted?: WeightedMetricsInput[];
  /** Present only when the global retry budget (WR-38) is enabled. */
  retryBudgetDepleted?: number;
  /** Present only when the relay-level global concurrency cap (WR-51) is configured (finite). */
  globalConcurrencyWaits?: number;
  /** Present only once a delivery has been parked for a future deliver_at (WR-57). */
  scheduled?: ScheduledMetricsInput;
  /**
   * Present only for endpoints currently elevated by the SLO-risk
   * predictor (WR-71); absent entirely when the predictor is disabled or
   * nothing is at risk.
   */
  sloRisk?: SloRiskMetricsInput[];
  /**
   * Present only for endpoints whose TLS certificate was observed by the
   * WR-73 expiry monitor (handshake peer certs plus the relay's own mTLS
   * client certs); absent entirely when the monitor is disabled or
   * nothing was observed yet.
   */
  certExpiry?: CertExpiryMetricsInput[];
  /**
   * Present only for endpoints where a delivery's end-to-end deadline
   * (WR-76) actually expired; absent entirely when the deadline is
   * unconfigured or nothing has expired yet.
   */
  deliveryDeadlineExceeded?: DeliveryDeadlineExceededInput[];
  /**
   * Present only once a shadow target has actually received a mirrored
   * copy (WR-85 dry-run mirroring); absent entirely when the feature is
   * off — the same activity-gated convention as the probe series.
   */
  shadow?: ShadowMetricsInput[];
  /**
   * Present only for (tenant, endpoint) scopes that actually dispatched a
   * dead-letter storm escalation alert (WR-93); absent entirely when the
   * feature is off — the same activity-gated convention as the probe
   * series.
   */
  escalation?: DeadLetterEscalationMetricsInput[];
  /**
   * Present only for endpoints that have actually been auto-paused by
   * the stale-endpoint sweep (WR-100); absent entirely when the feature
   * is off — the same activity-gated convention as the probe series.
   */
  stalePause?: StalePauseMetricsInput[];
  /**
   * Present only for endpoints where an OCSP revocation check (WR-101)
   * actually ran; absent entirely when the feature is off — the same
   * activity-gated convention as the probe series.
   */
  ocsp?: OcspMetricsInput[];
  /**
   * Present only when OTLP delivery-event export (WR-83) is enabled
   * (`RetryQueueOptions.otlp`); absent entirely otherwise — the same
   * "optional sections only emit series when enabled" convention as the
   * probe series. `buffered` is the current local export buffer depth;
   * `exports` carries one row per (event_type, status) pair that
   * actually exported.
   */
  otlp?: {
    exports: OtlpExportCountInput[];
    buffered: number;
  };
  /**
   * Present only when adaptive outbound concurrency (WR-94) is enabled;
   * one gauge series per (tenant, endpoint) with a recorded outcome —
   * absent entirely when the feature is off, so an untouched relay's
   * exposition is byte-identical.
   */
  adaptiveConcurrency?: AdaptiveConcurrencyMetricsInput[];
  /**
   * Present only when per-tenant outbound rate limiting (WR-97) is
   * enabled; one counter series per (tenant, endpoint) scope that
   * actually denied — absent entirely when the feature is off, so an
   * untouched relay's exposition is byte-identical.
   */
  tenantRateLimited?: TenantRateLimitMetricsInput[];
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

/** One weighted-dispatch count, in Prometheus label order. */
export interface WeightedMetricsInput {
  /** Logical endpoint. */
  endpoint: string;
  /** Physical target the dispatch was routed to. */
  target: string;
  /** Cumulative dispatches to this target. */
  dispatched: number;
}

/** One endpoint's health-probe counters, in Prometheus label order. */
export interface ProbeMetricsInput {
  endpoint: string;
  success: number;
  failure: number;
  /** Current consecutive-failure streak (0 once healthy). */
  consecutiveFailures: number;
}

/** One relay's scheduled-delivery counters (WR-57), in a fixed order. */
export interface ScheduledMetricsInput {
  /** Cumulative deliveries parked for a future deliver_at. */
  scheduled: number;
  /** Cumulative parked deliveries whose deliver_at arrived. */
  due: number;
  /** Cumulative parked deliveries canceled before their deliver_at. */
  canceled: number;
}

/** One endpoint's predicted SLO headroom (WR-71), in Prometheus label order. */
export interface SloRiskMetricsInput {
  endpoint: string;
  /** Tenant id (WR-48); when set it is rendered as a `tenant` label. */
  tenant?: string;
  /** Predicted SLO headroom remaining before breach, in seconds (>= 0). */
  headroomSeconds: number;
}

/**
 * One endpoint's observed TLS certificate expiry (WR-73), in Prometheus
 * label order.
 */
export interface CertExpiryMetricsInput {
  /** The delivery `targetUrl` (downstream) or the `tlsClientCerts` key (client). */
  endpoint: string;
  /** `"downstream"` = the peer's certificate; `"client"` = the relay's own mTLS client certificate. */
  kind: "downstream" | "client";
  /** Seconds until the certificate expires (< 0 when already expired). */
  expirySeconds: number;
}

/** One endpoint's guarded-compression byte savings (WR-75), in Prometheus label order. */
export interface CompressedBytesSavedInput {
  endpoint: string;
  /** Cumulative payload bytes saved by gzip compression (original minus compressed). */
  bytesSaved: number;
}

/** One endpoint's delivery-deadline expirations (WR-76), in Prometheus label order. */
export interface DeliveryDeadlineExceededInput {
  endpoint: string;
  /** Tenant id (WR-48); when set it is rendered as a `tenant` label. */
  tenant?: string;
  /** Cumulative deliveries dead-lettered because their deadline expired. */
  exceeded: number;
}

/**
 * One (event_type, status) cumulative OTLP export outcome counter
 * (WR-83), in Prometheus label order.
 */
export interface OtlpExportCountInput {
  /** Relay event type that was exported. */
  eventType: "delivered" | "retrying" | "dead_letter" | "slo_missed" | "rate_limited";
  /** Export outcome: `success` = the collector answered 2xx. */
  status: "success" | "failure";
  /** Cumulative count for this (event_type, status) pair. */
  count: number;
}

/**
 * Render just the guarded-compression byte-savings block (WR-75) as
 * exposition lines; `[]` when the series is empty, so callers can keep
 * their output byte-identical until the first byte is actually saved.
 */
export function renderCompressedBytesSavedBlock(series: CompressedBytesSavedInput[]): string[] {
  if (series.length === 0) return [];
  const lines = [
    "# HELP relay_compressed_bytes_saved_total Outbound payload bytes saved by guarded gzip compression (WR-75), by endpoint.",
    "# TYPE relay_compressed_bytes_saved_total counter",
  ];
  for (const s of series) {
    lines.push(
      `relay_compressed_bytes_saved_total{endpoint="${escapeLabelValue(s.endpoint)}"} ${s.bytesSaved}`
    );
  }
  return lines;
}
export function renderCertExpiryBlock(series: CertExpiryMetricsInput[]): string[] {
  if (series.length === 0) return [];
  const lines = [
    "# HELP relay_cert_expiry_seconds Seconds until the observed TLS certificate expires, by endpoint (negative when already expired).",
    "# TYPE relay_cert_expiry_seconds gauge",
  ];
  for (const c of series) {
    lines.push(
      `relay_cert_expiry_seconds{endpoint="${escapeLabelValue(c.endpoint)}",kind="${c.kind}"} ${c.expirySeconds}`
    );
  }
  return lines;
}

/**
 * Render just the adaptive-concurrency limit block (WR-94) as exposition
 * lines; `[]` when the series is empty, so callers can keep their output
 * byte-identical until the first outcome is actually recorded.
 */
export function renderAdaptiveConcurrencyBlock(series: AdaptiveConcurrencyMetricsInput[]): string[] {
  if (series.length === 0) return [];
  const lines = [
    "# HELP relay_adaptive_concurrency_limit Current AIMD outbound concurrency limit by endpoint (WR-94).",
    "# TYPE relay_adaptive_concurrency_limit gauge",
  ];
  for (const s of series) {
    lines.push(
      `relay_adaptive_concurrency_limit{endpoint="${escapeLabelValue(s.endpoint)}"${tenantLabel(s.tenant)}} ${s.limit}`
    );
  }
  return lines;
}

/**
 * Render just the per-tenant outbound rate-limit denial block (WR-97) as
 * exposition lines; `[]` when the series is empty, so callers can keep
 * their output byte-identical until the first denial actually happens.
 */
export function renderTenantRateLimitedBlock(series: TenantRateLimitMetricsInput[]): string[] {
  if (series.length === 0) return [];
  const lines = [
    "# HELP relay_tenant_ratelimited_total Over-limit decisions (denials) by the per-(tenant, endpoint) outbound rate limiter (WR-97), in queue and reject-429 modes.",
    "# TYPE relay_tenant_ratelimited_total counter",
  ];
  for (const s of series) {
    lines.push(
      `relay_tenant_ratelimited_total{endpoint="${escapeLabelValue(s.endpoint)}"${tenantLabel(s.tenant)}} ${s.limited}`
    );
  }
  return lines;
}

/** One endpoint's outbound OCSP revocation check outcomes (WR-101), in Prometheus label order. */
export interface OcspMetricsInput {
  /** The delivery `targetUrl` whose peer was checked. */
  endpoint: string;
  /** Check outcome: `good` / `revoked` / `unknown` / `error`. */
  status: "good" | "revoked" | "unknown" | "error";
  /** Cumulative checks with this outcome. */
  count: number;
}

/**
 * Render just the OCSP outcome block (WR-101) as exposition lines; `[]`
 * when the series is empty, so callers can keep their output
 * byte-identical until the first check actually runs.
 */
export function renderOcspBlock(series: OcspMetricsInput[]): string[] {
  if (series.length === 0) return [];
  const lines = [
    "# HELP relay_ocsp_total Outbound OCSP revocation check outcomes by endpoint (WR-101).",
    "# TYPE relay_ocsp_total counter",
  ];
  for (const s of series) {
    lines.push(
      `relay_ocsp_total{endpoint="${escapeLabelValue(s.endpoint)}",status="${s.status}"} ${s.count}`
    );
  }
  return lines;
}

/**
 * Render just the error-rate gauge block (WR-104) as exposition lines;
 * `[]` when the series is empty, so callers can keep their output
 * byte-identical until the first error-rate-mode outcome is recorded.
 */
export function renderCircuitErrorRateBlock(series: CircuitErrorRateInput[]): string[] {
  if (series.length === 0) return [];
  const lines = [
    "# HELP relay_endpoint_circuit_error_rate Rolling-window failure rate by endpoint (WR-104 error-rate trip mode; present only for error-rate-mode endpoints with at least one recorded outcome).",
    "# TYPE relay_endpoint_circuit_error_rate gauge",
  ];
  for (const s of series) {
    lines.push(
      `relay_endpoint_circuit_error_rate{endpoint="${escapeLabelValue(s.endpoint)}"${tenantLabel(s.tenant)}} ${s.errorRate}`
    );
  }
  return lines;
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
  // WR-104: activity-gated like the circuit-state gauge — the error-rate
  // gauge appears only for error-rate-mode endpoints with a recorded
  // outcome, so a relay on the default consecutive-failures mode exposes
  // no `relay_endpoint_circuit_error_rate` series at all.
  lines.push(...renderCircuitErrorRateBlock(input.circuitErrorRates ?? []));
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
  if (input.weighted !== undefined && input.weighted.length > 0) {
    lines.push(
      "# HELP relay_weighted_dispatch_total Weighted multi-target dispatches by logical endpoint and physical target."
    );
    lines.push("# TYPE relay_weighted_dispatch_total counter");
    for (const w of input.weighted) {
      lines.push(
        `relay_weighted_dispatch_total{endpoint="${escapeLabelValue(w.endpoint)}",target="${escapeLabelValue(w.target)}"} ${w.dispatched}`
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
  if (input.globalConcurrencyWaits !== undefined) {
    lines.push(
      "# HELP relay_global_concurrency_wait_total Dispatches that waited for a relay-level global concurrency slot."
    );
    lines.push("# TYPE relay_global_concurrency_wait_total counter");
    lines.push(`relay_global_concurrency_wait_total ${input.globalConcurrencyWaits}`);
  }
  if (input.scheduled !== undefined) {
    lines.push(
      "# HELP relay_scheduled_total Deliveries parked for a future deliver_at (WR-57)."
    );
    lines.push("# TYPE relay_scheduled_total counter");
    lines.push(`relay_scheduled_total ${input.scheduled.scheduled}`);
    lines.push(
      "# HELP relay_scheduled_due_total Parked deliveries whose deliver_at arrived and entered the normal delivery path."
    );
    lines.push("# TYPE relay_scheduled_due_total counter");
    lines.push(`relay_scheduled_due_total ${input.scheduled.due}`);
    lines.push(
      "# HELP relay_scheduled_canceled_total Parked deliveries canceled before their deliver_at."
    );
    lines.push("# TYPE relay_scheduled_canceled_total counter");
    lines.push(`relay_scheduled_canceled_total ${input.scheduled.canceled}`);
  }
  if (input.sloRisk !== undefined && input.sloRisk.length > 0) {
    lines.push(
      "# HELP relay_slo_risk_seconds Predicted SLO headroom remaining before breach, by endpoint (WR-71 early warning; 0 = breach predicted now)."
    );
    lines.push("# TYPE relay_slo_risk_seconds gauge");
    for (const r of input.sloRisk) {
      lines.push(
        `relay_slo_risk_seconds{endpoint="${escapeLabelValue(r.endpoint)}"${tenantLabel(r.tenant)}} ${r.headroomSeconds}`
      );
    }
  }
  // WR-73: activity-gated like the slo-risk gauge — the series appears
  // only once the monitor has actually observed a certificate.
  lines.push(...renderCertExpiryBlock(input.certExpiry ?? []));
  // WR-94: activity-gated the same way — the series appears only once an
  // adaptive outcome has been recorded for an endpoint.
  lines.push(...renderAdaptiveConcurrencyBlock(input.adaptiveConcurrency ?? []));
  // WR-97: activity-gated the same way — the series appears only once a
  // (tenant, endpoint) scope has actually been rate-limited.
  lines.push(...renderTenantRateLimitedBlock(input.tenantRateLimited ?? []));
  // WR-76: activity-gated the same way — the series appears only once a
  // delivery deadline has actually expired.
  if (input.deliveryDeadlineExceeded !== undefined && input.deliveryDeadlineExceeded.length > 0) {
    lines.push(
      "# HELP relay_delivery_deadline_exceeded_total Deliveries dead-lettered because the per-endpoint end-to-end delivery deadline (WR-76) expired before delivery."
    );
    lines.push("# TYPE relay_delivery_deadline_exceeded_total counter");
    for (const d of input.deliveryDeadlineExceeded) {
      lines.push(
        `relay_delivery_deadline_exceeded_total{endpoint="${escapeLabelValue(d.endpoint)}"${tenantLabel(d.tenant)}} ${d.exceeded}`
      );
    }
  }
  // WR-85: activity-gated like the probe series — the shadow series
  // appears only once a shadow target has actually received a mirrored
  // copy, so a relay with the feature off exposes no `relay_shadow_*`
  // series at all.
  if (input.shadow !== undefined && input.shadow.length > 0) {
    lines.push(
      "# HELP relay_shadow_total Shadow-target mirrored delivery outcomes (WR-85 dry-run mirroring), by logical endpoint and shadow target."
    );
    lines.push("# TYPE relay_shadow_total counter");
    for (const s of input.shadow) {
      const labels = `endpoint="${escapeLabelValue(s.endpoint)}"${tenantLabel(s.tenant)},shadow_target="${escapeLabelValue(s.shadowTarget)}"`;
      lines.push(`relay_shadow_total{${labels},result="delivered"} ${s.delivered}`);
      lines.push(`relay_shadow_total{${labels},result="failed"} ${s.failed}`);
    }
  }
  // WR-93: activity-gated like the probe series — the series appears only
  // for scopes that actually dispatched an escalation alert, so a relay
  // with the feature off exposes no `relay_dead_letter_escalations_total`
  // series at all.
  if (input.escalation !== undefined && input.escalation.length > 0) {
    lines.push(
      "# HELP relay_dead_letter_escalations_total Dead-letter storm escalation alerts (WR-93) dispatched per (tenant, endpoint) scope."
    );
    lines.push("# TYPE relay_dead_letter_escalations_total counter");
    for (const s of input.escalation) {
      const labels = `endpoint="${escapeLabelValue(s.endpoint)}"${tenantLabel(s.tenant)}`;
      lines.push(`relay_dead_letter_escalations_total{${labels}} ${s.escalations}`);
    }
  }
  // WR-100: activity-gated like the escalation series — the series
  // appears only for endpoints that have actually been auto-paused, so
  // a relay with the feature off exposes no
  // `relay_endpoint_auto_pauses_total` series at all.
  if (input.stalePause !== undefined && input.stalePause.length > 0) {
    lines.push(
      "# HELP relay_endpoint_auto_pauses_total Stale-endpoint auto-pauses (WR-100) per logical endpoint."
    );
    lines.push("# TYPE relay_endpoint_auto_pauses_total counter");
    for (const s of input.stalePause) {
      lines.push(`relay_endpoint_auto_pauses_total{endpoint="${escapeLabelValue(s.endpoint)}"} ${s.pauses}`);
    }
  }
  // WR-101: activity-gated like the probe series — the OCSP series
  // appears only once a revocation check has actually run for an
  // endpoint, so a relay with the feature off exposes no
  // `relay_ocsp_total` series at all.
  lines.push(...renderOcspBlock(input.ocsp ?? []));
  // WR-83: emitted only when OTLP export is enabled — the same
  // "optional sections only emit series when enabled" convention as the
  // probe series. The buffered gauge is always present then (even at 0);
  // export counters appear per (event_type, status) pair that exported.
  if (input.otlp !== undefined) {
    lines.push(
      "# HELP relay_otlp_exports_total Delivery/SLO events exported to the OTLP collector (WR-83), by event type and export outcome (success = collector answered 2xx)."
    );
    lines.push("# TYPE relay_otlp_exports_total counter");
    for (const e of input.otlp.exports) {
      lines.push(
        `relay_otlp_exports_total{event_type="${e.eventType}",status="${e.status}"} ${e.count}`
      );
    }
    lines.push(
      "# HELP relay_otlp_buffered Delivery/SLO events currently buffered for OTLP export (WR-83)."
    );
    lines.push("# TYPE relay_otlp_buffered gauge");
    lines.push(`relay_otlp_buffered ${input.otlp.buffered}`);
  }
  return lines.join("\n") + "\n";
}
