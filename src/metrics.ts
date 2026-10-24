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
 * - `relay_websocket_connections{origin}`: gauge, active pooled WebSocket
 *   connections (WR-105). `relay_websocket_messages_out_total` /
 *   `relay_websocket_messages_in_total{origin}`: counters of delivery
 *   messages sent and replies received. `relay_websocket_checkouts_total
 *   {origin,result}`: pool checkouts (`result` = `created` / `reused`).
 *   `relay_websocket_ping_rtt_seconds{origin}`: gauge, mean recent
 *   keep-alive ping RTT (only origins with a completed probe).
 *   `relay_websocket_deflate_ratio{origin}`: gauge, mean permessage-deflate
 *   wire/plain byte ratio (only origins with a compressed delivery).
 *   All present only once a WebSocket delivery has actually run — absent
 *   entirely otherwise.
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
 * - `relay_canary_rollout_events_total{endpoint,candidate,event}`:
 *   counter of canary rollout transitions (WR-214) by logical endpoint,
 *   candidate, and event, present only for triples that actually
 *   transitioned.
 * - `relay_weighted_dispatch_total{endpoint,target}`: counter of
 *   dispatches routed to each physical target by logical endpoint
 *   (WR-66 weighted multi-target dispatch), present only when weighted
 *   mode is in use and only for (endpoint, target) pairs that actually
 *   received a dispatch.
 * - `relay_retry_budget_depleted_total`: counter of retries parked because
 *   the retry budget (WR-38) was exhausted. Present only when the
 *   budget is enabled. The unlabeled series is the relay-wide total;
 *   WR-125 adds one `{endpoint}`-labeled series per endpoint that
 *   actually had a retry parked, so an operator can see whether the
 *   parking came from one endpoint's own override budget or the shared
 *   global bucket.
 * - `relay_global_concurrency_wait_total`: counter of dispatches that had
 *   to wait for a relay-level global concurrency slot (WR-51). Present
 *   only when the cap is configured (finite). No endpoint label — the
 *   cap is relay-wide.
 * - `relay_tenant_concurrency_wait_total{tenant}`: counter of dispatches
 *   that had to wait for a per-tenant concurrency slot (WR-140), by
 *   tenant. Present only when the per-tenant cap is configured (finite),
 *   and only for tenants that actually waited (activity-gated).
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
 * - `relay_endpoint_health_score{endpoint}`: gauge of the per-endpoint
 *   0–100 health score (WR-179; 100 = healthy). Present only for
 *   endpoints with at least one recorded delivery outcome — absent
 *   entirely when health scoring is off.
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
 * - `relay_quorum_total{endpoint,status}`: counter of quorum fan-outs
 *   (WR-106 M-of-N downstream acknowledgement) by terminal state
 *   (`status` = `satisfied` / `failed`).
 *   `relay_quorum_acknowledged_total{endpoint}`: counter of target
 *   acknowledgements across fan-outs.
 *   `relay_quorum_target_dead_letters_total{endpoint}`: counter of
 *   fan-out targets that exhausted their own retry lifecycle without
 *   acknowledging. All activity-gated: present only for endpoints with a
 *   recorded acknowledgement or loss — absent entirely when the feature
 *   is off.
 * - `relay_quorum_evicted_total`: counter of settled quorum fan-outs
 *   archived and evicted from memory by the retention window (WR-109).
 *   Activity-gated: present only once the first eviction has actually
 *   happened.
 * - `relay_ordered_head_blocked_total{endpoint}`: counter of follower
 *   dispatches held behind the head of an ordered-delivery line (WR-113).
 *   `relay_ordered_head_of_line_parked_total{endpoint}`: counter of
 *   heads poison-parked into the dead-letter list after exceeding
 *   `maxHeadOfLineHoldMs`.
 *   `relay_ordered_urgent_bypassed_total{endpoint}`: counter of urgent
 *   items that bypassed the ordered gate. All activity-gated: present
 *   only for ordered endpoints with recorded activity — absent entirely
 *   when the feature is off.
 * - `relay_assertion_failures_total{endpoint}`: counter of downstream
 *   response assertion failures (WR-118). Activity-gated: present only
 *   for (tenant, endpoint) scopes with a recorded failure — absent
 *   entirely when the feature is off.
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

/** One endpoint's ordered-delivery counters (WR-113), in Prometheus label order. */
export interface OrderedMetricsInput {
  /** Ordered endpoint (logical `targetUrl`). */
  endpoint: string;
  /** Cumulative follower dispatches held behind the head of the line. */
  headBlocked: number;
  /** Cumulative heads poison-parked into the dead-letter list. */
  headOfLineParked: number;
  /** Cumulative urgent items that bypassed the ordered gate. */
  urgentBypassed: number;
}

/** One endpoint's response-assertion failure count (WR-118), in Prometheus label order. */
export interface AssertionFailureMetricsInput {
  endpoint: string;
  /** Tenant id (WR-48); when set it is rendered as a `tenant` label. */
  tenant?: string;
  /** Cumulative response-assertion failures for this scope. */
  failures: number;
}

/** One endpoint's stale-endpoint auto-pause count (WR-100). */
export interface StalePauseMetricsInput {
  /** Auto-paused endpoint (logical `targetUrl`). */
  endpoint: string;
  /** Cumulative auto-pauses for this endpoint. */
  pauses: number;
}

/** One endpoint's auto-disable count (WR-150). */
export interface EndpointDisableMetricsInput {
  /** Auto-disabled endpoint (physical `targetUrl`). */
  endpoint: string;
  /** Cumulative auto-disables for this endpoint. */
  disables: number;
}

/** One endpoint's queue-depth breach count (WR-153), in Prometheus label order. */
export interface QueueDepthBreachMetricsInput {
  /** Endpoint whose depth reached its threshold (logical `targetUrl`). */
  endpoint: string;
  /** Cumulative breach episodes for this endpoint. */
  breaches: number;
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

/**
 * One endpoint's outbound token-bucket rate-limit denials (WR-154), in
 * Prometheus label order.
 */
export interface OutboundRateLimitMetricsInput {
  /** Downstream endpoint (physical `targetUrl` at dispatch). */
  endpoint: string;
  /** Cumulative over-limit decisions (delays) for this endpoint. */
  throttled: number;
}

/**
 * One tenant's dispatch-gate waits (WR-140), in Prometheus label order.
 */
export interface TenantConcurrencyWaitMetricsInput {
  /** Tenant id (WR-48), always set — rendered as the `tenant` label. */
  tenant: string;
  /** Cumulative dispatches that waited for one of this tenant's slots. */
  waits: number;
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
  /**
   * WR-145: present only for endpoints that actually ran drills; one
   * series per (endpoint, outcome) — activity-gated, so exposition is
   * byte-identical to the pre-WR-145 shape until the first drill.
   */
  dryRun?: DryRunMetricsInput[];
  /** Present only for (endpoint, from, to) triples that actually switched. */
  failover?: FailoverMetricsInput[];
  /**
   * WR-214: present only for (endpoint, candidate, event) triples that
   * actually transitioned.
   */
  canary?: CanaryRolloutMetricsInput[];
  /**
   * Present only when weighted multi-target dispatch (WR-66) is in use;
   * one series per (endpoint, target) pair that actually received a
   * dispatch.
   */
  weighted?: WeightedMetricsInput[];
  /**
   * Present only when consistent-hash sticky routing (WR-202) is in use;
   * one series per (endpoint, target) pair that actually received a
   * dispatch.
   */
  consistentHash?: ConsistentHashMetricsInput[];
  /** Present only when the global retry budget (WR-38) is enabled. */
  retryBudgetDepleted?: number;
  /**
   * WR-125: per-endpoint retry-budget park counts. Present only for
   * endpoints that actually had a retry parked — activity-gated, so
   * exposition is byte-identical to the pre-WR-125 shape until the
   * first park.
   */
  retryBudgetDepletedByEndpoint?: Array<{ endpoint: string; depleted: number }>;
  /**
   * WR-200: per-tenant retry-budget park counts. Present only for
   * tenants that actually had a retry parked — activity-gated, so
   * exposition is byte-identical to the pre-WR-200 shape until the
   * first park.
   */
  tenantRetryBudgetDepletedByTenant?: Array<{ tenant?: string; depleted: number }>;
  /** Present only when the relay-level global concurrency cap (WR-51) is configured (finite). */
  globalConcurrencyWaits?: number;
  /** Present only when the relay-level global outbound rate limit (WR-167) is configured. */
  globalRateDelayed?: number;
  /** Present only once a delivery has been parked for a future deliver_at (WR-57). */
  scheduled?: ScheduledMetricsInput;
  /**
   * Present only for endpoints currently elevated by the SLO-risk
   * predictor (WR-71); absent entirely when the predictor is disabled or
   * nothing is at risk.
   */
  sloRisk?: SloRiskMetricsInput[];
  /**
   * Present only for endpoints with at least one recorded delivery
   * outcome when outbound endpoint health scoring is enabled (WR-179);
   * absent entirely when the feature is off — the same activity-gated
   * convention as the SLO-risk series.
   */
  endpointHealth?: EndpointHealthMetricsInput[];
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
   * Present only for endpoints that have actually been auto-disabled
   * (WR-150); absent entirely when the feature is off — the same
   * activity-gated convention as the stale-pause series.
   */
  endpointDisable?: EndpointDisableMetricsInput[];
  /**
   * Present only while at least one endpoint is currently auto-disabled
   * (WR-150); absent entirely otherwise — the same activity-gated
   * convention as the stale-pause series.
   */
  endpointDisabledNow?: string[];
  /**
   * Present only for endpoints whose backlog depth has actually reached
   * a configured threshold (WR-153); absent entirely when the feature
   * is off or no breach has happened — the same activity-gated
   * convention as the stale-pause series.
   */
  queueDepthBreach?: QueueDepthBreachMetricsInput[];
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
  /**
   * Present only when per-endpoint outbound token-bucket rate limiting
   * (WR-154) is enabled; one counter series per endpoint that actually
   * throttled — absent entirely when the feature is off, so an
   * untouched relay's exposition is byte-identical.
   */
  outboundRateLimited?: OutboundRateLimitMetricsInput[];
  /**
   * Present only when the per-tenant concurrency cap (WR-140) is
   * configured (finite); one counter series per tenant that actually
   * waited for a tenant slot — activity-gated, so a relay whose tenants
   * never waited exposes no `relay_tenant_concurrency_wait_total` series
   * at all.
   */
  tenantConcurrencyWaits?: TenantConcurrencyWaitMetricsInput[];
  /**
   * Present only when quorum fan-out (WR-106) is enabled; one series per
   * (tenant, endpoint) with a recorded acknowledgement or loss — absent
   * entirely when the feature is off, so an untouched relay's exposition
   * is byte-identical.
   */
  quorum?: QuorumMetricsInput[];
  /**
   * Present only when a settled quorum fan-out has actually been evicted
   * by the retention window (WR-109); cumulative since construction.
   * Absent until the first eviction, so an untouched relay's exposition
   * is byte-identical.
   */
  quorumEvicted?: number;
  /**
   * Present only when per-endpoint ordered delivery (WR-113) is
   * enabled; one counter series per endpoint with recorded ordered
   * activity (a held follower, a poison-parked head, or an urgent
   * bypass) — absent entirely when the feature is off, so an untouched
   * relay's exposition is byte-identical.
   */
  ordered?: OrderedMetricsInput[];
  /**
   * Present only when per-endpoint response assertions (WR-118) are
   * configured; one counter series per (tenant, endpoint) scope with a
   * recorded assertion failure — absent entirely when the feature is
   * off, so an untouched relay's exposition is byte-identical.
   */
  assertionFailures?: AssertionFailureMetricsInput[];
  /**
   * WR-137: per-tenant monthly delivery budget (see `src/budget.ts`).
   * One gauge row per tenant with a configured budget — the month's
   * counted deliveries (`relay_tenant_budget_deliveries_total`) and the
   * configured allowance (`relay_tenant_budget_deliveries_limit`).
   * Absent entirely when no tenant carries a budget, so a relay without
   * budgets renders byte-identical exposition to the pre-WR-137 shape.
   */
  tenantBudget?: TenantBudgetMetricsInput[];
}

/** One endpoint's starvation-guard activation count, in Prometheus label order. */
export interface StarvationGuardMetricsInput {
  endpoint: string;
  activations: number;
}

/** One endpoint's drill outcome counts, in Prometheus label order (WR-145). */
export interface DryRunMetricsInput {
  endpoint: string;
  tenant?: string;
  /** One of `delivered` / `retrying` / `exhausted` / `failed`. */
  outcome: string;
  count: number;
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

/** One canary rollout transition count, in Prometheus label order. */
export interface CanaryRolloutMetricsInput {
  /** Logical endpoint (the configured primary `targetUrl`). */
  endpoint: string;
  /** The candidate target being ramped toward. */
  candidate: string;
  /** One of `canary_step_advanced` / `canary_rolled_back` / `canary_promoted`. */
  event: string;
  count: number;
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

/** One consistent-hash dispatch count, in Prometheus label order. */
export interface ConsistentHashMetricsInput {
  /** Logical endpoint. */
  endpoint: string;
  /** Physical target the sticky key was routed to. */
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
 * One endpoint's health score (WR-179), in Prometheus label order.
 */
export interface EndpointHealthMetricsInput {
  /** Downstream endpoint (physical `targetUrl`). */
  endpoint: string;
  /** Tenant id (WR-48); when set it is rendered as a `tenant` label. */
  tenant?: string;
  /** Current 0–100 health score (100 = healthy). */
  score: number;
}

/**
 * Render just the endpoint-health score block (WR-179) as exposition
 * lines; `[]` when the series is empty, so callers keep their output
 * byte-identical until the first delivery outcome is actually recorded.
 */
export function renderEndpointHealthBlock(series: EndpointHealthMetricsInput[]): string[] {
  if (series.length === 0) return [];
  const lines = [
    "# HELP relay_endpoint_health_score Outbound endpoint health score (WR-179; 0-100, 100 = healthy), by endpoint.",
    "# TYPE relay_endpoint_health_score gauge",
  ];
  for (const s of series) {
    lines.push(
      `relay_endpoint_health_score{endpoint="${escapeLabelValue(s.endpoint)}"${tenantLabel(s.tenant)}} ${s.score}`
    );
  }
  return lines;
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
 * Render just the per-tenant concurrency wait block (WR-140) as
 * exposition lines; `[]` when the series is empty, so callers can keep
 * their output byte-identical until the first tenant actually waits.
 */
export function renderTenantConcurrencyWaitBlock(series: TenantConcurrencyWaitMetricsInput[]): string[] {
  if (series.length === 0) return [];
  const lines = [
    "# HELP relay_tenant_concurrency_wait_total Dispatches that waited for a per-tenant concurrency slot (WR-140), by tenant.",
    "# TYPE relay_tenant_concurrency_wait_total counter",
  ];
  for (const s of series) {
    lines.push(
      `relay_tenant_concurrency_wait_total{tenant="${escapeLabelValue(s.tenant)}"} ${s.waits}`
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

/**
 * Render just the per-endpoint outbound token-bucket rate-limit denial
 * block (WR-154) as exposition lines; `[]` when the series is empty, so
 * callers can keep their output byte-identical until the first denial
 * actually happens.
 */
export function renderOutboundRateLimitedBlock(series: OutboundRateLimitMetricsInput[]): string[] {
  if (series.length === 0) return [];
  const lines = [
    "# HELP relay_ratelimit_throttled_total Over-limit decisions (delays) by the per-endpoint outbound token-bucket rate limiter (WR-154), queue mode.",
    "# TYPE relay_ratelimit_throttled_total counter",
  ];
  for (const s of series) {
    lines.push(
      `relay_ratelimit_throttled_total{endpoint="${escapeLabelValue(s.endpoint)}"} ${s.throttled}`
    );
  }
  return lines;
}

/**
 * One tenant's monthly delivery budget state (WR-137), in Prometheus
 * label order.
 */
export interface TenantBudgetMetricsInput {
  /** Tenant id (WR-48), or `"default"` for the default tenant. */
  tenant: string;
  /** Deliveries counted against the budget in the current UTC month. */
  used: number;
  /** Configured monthly allowance (deliveries per UTC month). */
  budget: number;
}

/**
 * Render just the per-tenant monthly delivery budget block (WR-137) as
 * exposition lines: `relay_tenant_budget_deliveries_total{tenant}`
 * (gauge — this month's counted deliveries) and
 * `relay_tenant_budget_deliveries_limit{tenant}` (gauge — the configured
 * allowance), so operators can watch usage against budget. `[]` when the
 * series is empty, so callers keep byte-identical output until the first
 * budget is configured.
 */
export function renderTenantBudgetBlock(series: TenantBudgetMetricsInput[]): string[] {
  if (series.length === 0) return [];
  const lines = [
    "# HELP relay_tenant_budget_deliveries_total Monthly delivered deliveries counted against the tenant delivery budget (WR-137).",
    "# TYPE relay_tenant_budget_deliveries_total gauge",
  ];
  for (const s of series) {
    lines.push(
      `relay_tenant_budget_deliveries_total{tenant="${escapeLabelValue(s.tenant)}"} ${s.used}`
    );
  }
  lines.push(
    "# HELP relay_tenant_budget_deliveries_limit Configured monthly delivery budget, in deliveries per UTC month (WR-137).",
    "# TYPE relay_tenant_budget_deliveries_limit gauge"
  );
  for (const s of series) {
    lines.push(
      `relay_tenant_budget_deliveries_limit{tenant="${escapeLabelValue(s.tenant)}"} ${s.budget}`
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
 * One endpoint's quorum fan-out counters (WR-106), in Prometheus label
 * order.
 */
export interface QuorumMetricsInput {
  /** The logical endpoint (the admitted `targetUrl`). */
  endpoint: string;
  /** Tenant id (WR-48); when set it is rendered as a `tenant` label. */
  tenant?: string;
  /** Cumulative fan-outs that reached their quorum. */
  satisfied: number;
  /** Cumulative fan-outs whose quorum became unreachable. */
  failed: number;
  /** Cumulative target acknowledgements across fan-outs. */
  acknowledged: number;
  /** Cumulative targets that exhausted their retry lifecycle. */
  targetDeadLetters: number;
}

/**
 * Render just the quorum fan-out block (WR-106) as exposition lines;
 * `[]` when the series is empty, so callers keep their output
 * byte-identical until the first acknowledgement or loss is actually
 * recorded.
 */
export function renderQuorumBlock(series: QuorumMetricsInput[]): string[] {
  if (series.length === 0) return [];
  const lines = [
    "# HELP relay_quorum_total Quorum fan-outs (WR-106 M-of-N downstream acknowledgement) by logical endpoint and terminal state (satisfied = M targets acknowledged, failed = quorum became unreachable).",
    "# TYPE relay_quorum_total counter",
  ];
  for (const s of series) {
    const labels = `endpoint="${escapeLabelValue(s.endpoint)}"${tenantLabel(s.tenant)}`;
    lines.push(`relay_quorum_total{${labels},status="satisfied"} ${s.satisfied}`);
    lines.push(`relay_quorum_total{${labels},status="failed"} ${s.failed}`);
  }
  lines.push(
    "# HELP relay_quorum_acknowledged_total Cumulative target acknowledgements across quorum fan-outs (WR-106), by logical endpoint."
  );
  lines.push("# TYPE relay_quorum_acknowledged_total counter");
  for (const s of series) {
    lines.push(
      `relay_quorum_acknowledged_total{endpoint="${escapeLabelValue(s.endpoint)}"${tenantLabel(s.tenant)}} ${s.acknowledged}`
    );
  }
  lines.push(
    "# HELP relay_quorum_target_dead_letters_total Cumulative fan-out targets (WR-106) that exhausted their own retry lifecycle without acknowledging, by logical endpoint."
  );
  lines.push("# TYPE relay_quorum_target_dead_letters_total counter");
  for (const s of series) {
    lines.push(
      `relay_quorum_target_dead_letters_total{endpoint="${escapeLabelValue(s.endpoint)}"${tenantLabel(s.tenant)}} ${s.targetDeadLetters}`
    );
  }
  return lines;
}

/**
 * Render the WR-109 quorum retention-eviction counter as exposition
 * lines; `[]` when no settled fan-out has been evicted yet, so callers
 * keep their output byte-identical until the first eviction is actually
 * recorded. The counter is global (not per endpoint): an evicted
 * fan-out is already gone from the per-fanout state, and what an
 * operator needs is the cumulative count.
 */
export function renderQuorumEvictedBlock(evicted?: number): string[] {
  if (evicted === undefined || evicted <= 0) return [];
  return [
    "# HELP relay_quorum_evicted_total Settled quorum fan-outs (WR-109) archived and evicted from memory by the retention window (retention_ttl: verdict older than quorumRetentionMs; lru_cap: oldest verdict while retained settled fan-outs exceeded quorumMaxFanouts), cumulative since construction.",
    "# TYPE relay_quorum_evicted_total counter",
    `relay_quorum_evicted_total ${evicted}`,
  ];
}

/**
 * One origin's WebSocket gateway counters (WR-105), in Prometheus label
 * order. The origin key is `<scheme>//<host>` (host includes the port).
 */
export interface WebSocketOriginMetricsInput {
  /** Origin grouping key: `<scheme>//<host>`. */
  origin: string;
  /** Live pooled connections for this origin right now. */
  activeConnections: number;
  /** Delivery messages sent. */
  messagesOut: number;
  /** Delivery replies received. */
  messagesIn: number;
  /** Pool checkouts that opened a fresh connection. */
  created: number;
  /** Pool checkouts that reused a pooled connection. */
  reused: number;
  /**
   * Mean recent keep-alive ping RTT in seconds; absent when no probe has
   * completed yet for this origin.
   */
  pingRttSeconds?: number;
  /**
   * Mean permessage-deflate wire/plain byte ratio in (0, 1]; absent when
   * nothing was compressed for this origin yet.
   */
  compressionRatio?: number;
  /**
   * Multiplexed deliveries sent on this origin's connections (WR-204);
   * absent when multiplexing never ran here, so untouched origins keep
   * their old shape.
   */
  muxOut?: number;
  /**
   * Multiplexed replies routed back by correlation ID (WR-204); absent
   * when multiplexing never ran here.
   */
  muxIn?: number;
}

/**
 * Render just the WebSocket gateway block (WR-105) as exposition lines;
 * `[]` when the series is empty, so callers can keep their output
 * byte-identical until the first WebSocket delivery actually runs.
 */
export function renderWebSocketBlock(series: WebSocketOriginMetricsInput[]): string[] {
  if (series.length === 0) return [];
  const originOf = (s: WebSocketOriginMetricsInput): string =>
    `origin="${escapeLabelValue(s.origin)}"`;
  const lines = [
    "# HELP relay_websocket_connections Active pooled WebSocket connections by origin.",
    "# TYPE relay_websocket_connections gauge",
  ];
  for (const s of series) {
    lines.push(`relay_websocket_connections{${originOf(s)}} ${s.activeConnections}`);
  }
  lines.push(
    "# HELP relay_websocket_messages_out_total WebSocket delivery messages sent, by origin."
  );
  lines.push("# TYPE relay_websocket_messages_out_total counter");
  for (const s of series) {
    lines.push(`relay_websocket_messages_out_total{${originOf(s)}} ${s.messagesOut}`);
  }
  lines.push(
    "# HELP relay_websocket_messages_in_total WebSocket delivery replies received, by origin."
  );
  lines.push("# TYPE relay_websocket_messages_in_total counter");
  for (const s of series) {
    lines.push(`relay_websocket_messages_in_total{${originOf(s)}} ${s.messagesIn}`);
  }
  lines.push(
    "# HELP relay_websocket_checkouts_total WebSocket pool checkouts by origin and result (created = opened a fresh connection, reused = served from the pool)."
  );
  lines.push("# TYPE relay_websocket_checkouts_total counter");
  for (const s of series) {
    lines.push(`relay_websocket_checkouts_total{${originOf(s)},result="created"} ${s.created}`);
    lines.push(`relay_websocket_checkouts_total{${originOf(s)},result="reused"} ${s.reused}`);
  }
  const withRtt = series.filter((s) => s.pingRttSeconds !== undefined);
  if (withRtt.length > 0) {
    lines.push(
      "# HELP relay_websocket_ping_rtt_seconds Mean recent keep-alive ping round-trip time, by origin."
    );
    lines.push("# TYPE relay_websocket_ping_rtt_seconds gauge");
    for (const s of withRtt) {
      lines.push(`relay_websocket_ping_rtt_seconds{${originOf(s)}} ${s.pingRttSeconds}`);
    }
  }
  const withRatio = series.filter((s) => s.compressionRatio !== undefined);
  if (withRatio.length > 0) {
    lines.push(
      "# HELP relay_websocket_deflate_ratio Mean permessage-deflate wire/plain byte ratio by origin (smaller = better compression)."
    );
    lines.push("# TYPE relay_websocket_deflate_ratio gauge");
    for (const s of withRatio) {
      lines.push(`relay_websocket_deflate_ratio{${originOf(s)}} ${s.compressionRatio}`);
    }
  }
  // WR-204: multiplexed delivery/reply counters — only rendered for
  // origins that actually multiplexed, so everyone else stays
  // byte-identical.
  const withMux = series.filter((s) => s.muxOut !== undefined || s.muxIn !== undefined);
  if (withMux.length > 0) {
    lines.push(
      "# HELP relay_websocket_multiplexed_total WebSocket deliveries sent as multiplexed envelope frames and replies routed back by correlation ID, by origin and direction."
    );
    lines.push("# TYPE relay_websocket_multiplexed_total counter");
    for (const s of withMux) {
      lines.push(
        `relay_websocket_multiplexed_total{${originOf(s)},direction="out"} ${s.muxOut ?? 0}`
      );
      lines.push(
        `relay_websocket_multiplexed_total{${originOf(s)},direction="in"} ${s.muxIn ?? 0}`
      );
    }
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
  if (input.dryRun !== undefined && input.dryRun.length > 0) {
    lines.push(
      "# HELP relay_dry_run_deliveries_total Drill (dry-run) delivery outcomes by endpoint. Drill traffic is fully isolated from real-traffic counters."
    );
    lines.push("# TYPE relay_dry_run_deliveries_total counter");
    for (const d of input.dryRun) {
      const tenantLabel = d.tenant === undefined ? "" : `,tenant="${escapeLabelValue(d.tenant)}"`;
      lines.push(
        `relay_dry_run_deliveries_total{endpoint="${escapeLabelValue(d.endpoint)}"${tenantLabel},outcome="${escapeLabelValue(d.outcome)}"} ${d.count}`
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
  if (input.canary !== undefined && input.canary.length > 0) {
    lines.push(
      "# HELP relay_canary_rollout_events_total Canary rollout transitions by logical endpoint, candidate, and event."
    );
    lines.push("# TYPE relay_canary_rollout_events_total counter");
    for (const c of input.canary) {
      lines.push(
        `relay_canary_rollout_events_total{endpoint="${escapeLabelValue(c.endpoint)}",candidate="${escapeLabelValue(c.candidate)}",event="${escapeLabelValue(c.event)}"} ${c.count}`
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
  if (input.consistentHash !== undefined && input.consistentHash.length > 0) {
    lines.push(
      "# HELP relay_consistent_hash_dispatch_total Consistent-hash sticky-routing dispatches by logical endpoint and physical target."
    );
    lines.push("# TYPE relay_consistent_hash_dispatch_total counter");
    for (const c of input.consistentHash) {
      lines.push(
        `relay_consistent_hash_dispatch_total{endpoint="${escapeLabelValue(c.endpoint)}",target="${escapeLabelValue(c.target)}"} ${c.dispatched}`
      );
    }
  }
  if (input.retryBudgetDepleted !== undefined) {
    lines.push(
      "# HELP relay_retry_budget_depleted_total Retries parked because the retry budget was exhausted."
    );
    lines.push("# TYPE relay_retry_budget_depleted_total counter");
    lines.push(`relay_retry_budget_depleted_total ${input.retryBudgetDepleted}`);
    // WR-125: per-endpoint split — one series per endpoint that actually
    // had a retry parked; the unlabeled global row above is retained.
    for (const row of input.retryBudgetDepletedByEndpoint ?? []) {
      lines.push(
        `relay_retry_budget_depleted_total{endpoint="${escapeLabelValue(row.endpoint)}"} ${row.depleted}`
      );
    }
  }
  if (input.tenantRetryBudgetDepletedByTenant !== undefined) {
    lines.push(
      "# HELP relay_tenant_retry_budget_depleted_total Retries parked because the tenant's own retry budget was exhausted."
    );
    lines.push("# TYPE relay_tenant_retry_budget_depleted_total counter");
    // WR-200: one series per tenant that actually had a retry parked;
    // the default (tenant-less) tenant renders as an empty label set.
    // (`tenantLabel` appends `,tenant="…"` after another label, so the
    // sole-label form is spelled out here.)
    for (const row of input.tenantRetryBudgetDepletedByTenant) {
      const label =
        row.tenant === undefined ? "" : `tenant="${escapeLabelValue(row.tenant)}"`;
      lines.push(`relay_tenant_retry_budget_depleted_total{${label}} ${row.depleted}`);
    }
  }
  if (input.globalConcurrencyWaits !== undefined) {
    lines.push(
      "# HELP relay_global_concurrency_wait_total Dispatches that waited for a relay-level global concurrency slot."
    );
    lines.push("# TYPE relay_global_concurrency_wait_total counter");
    lines.push(`relay_global_concurrency_wait_total ${input.globalConcurrencyWaits}`);
  }
  if (input.globalRateDelayed !== undefined) {
    lines.push(
      "# HELP relay_global_rate_delayed_total Dispatches delayed by the relay-level global outbound rate limit."
    );
    lines.push("# TYPE relay_global_rate_delayed_total counter");
    lines.push(`relay_global_rate_delayed_total ${input.globalRateDelayed}`);
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
  // WR-179: activity-gated like the SLO-risk gauge — the series appears
  // only once an endpoint has recorded at least one delivery outcome.
  lines.push(...renderEndpointHealthBlock(input.endpointHealth ?? []));
  // WR-73: activity-gated like the slo-risk gauge — the series appears
  // only once the monitor has actually observed a certificate.
  lines.push(...renderCertExpiryBlock(input.certExpiry ?? []));
  // WR-94: activity-gated the same way — the series appears only once an
  // adaptive outcome has been recorded for an endpoint.
  lines.push(...renderAdaptiveConcurrencyBlock(input.adaptiveConcurrency ?? []));
  // WR-97: activity-gated the same way — the series appears only once a
  // (tenant, endpoint) scope has actually been rate-limited.
  lines.push(...renderTenantRateLimitedBlock(input.tenantRateLimited ?? []));
  // WR-154: activity-gated the same way — the series appears only once
  // an endpoint has actually been throttled.
  lines.push(...renderOutboundRateLimitedBlock(input.outboundRateLimited ?? []));
  // WR-140: activity-gated the same way — the series appears only once
  // a tenant has actually waited for a tenant concurrency slot.
  lines.push(...renderTenantConcurrencyWaitBlock(input.tenantConcurrencyWaits ?? []));
  // WR-137: activity-gated the same way — the budget gauges appear only
  // once a tenant budget is configured, so a relay without budgets
  // exposes no `relay_tenant_budget_*` series at all.
  lines.push(...renderTenantBudgetBlock(input.tenantBudget ?? []));
  // WR-106: activity-gated the same way — the quorum series appears only
  // once a target has actually acknowledged or died, so a relay with the
  // feature off exposes no `relay_quorum_*` series at all.
  lines.push(...renderQuorumBlock(input.quorum ?? []));
  // WR-109: activity-gated the same way — the eviction counter appears
  // only once a settled fan-out has actually been evicted.
  lines.push(...renderQuorumEvictedBlock(input.quorumEvicted));
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
  // WR-150: activity-gated like the stale-pause series — the counter
  // appears only for endpoints that have actually been auto-disabled,
  // and the gauge only while at least one endpoint is disabled, so a
  // relay with the feature off exposes no
  // `relay_endpoint_auto_disable*` series at all.
  if (input.endpointDisable !== undefined && input.endpointDisable.length > 0) {
    lines.push(
      "# HELP relay_endpoint_auto_disables_total Endpoint auto-disables (WR-150) per endpoint."
    );
    lines.push("# TYPE relay_endpoint_auto_disables_total counter");
    for (const s of input.endpointDisable) {
      lines.push(`relay_endpoint_auto_disables_total{endpoint="${escapeLabelValue(s.endpoint)}"} ${s.disables}`);
    }
  }
  if (input.endpointDisabledNow !== undefined && input.endpointDisabledNow.length > 0) {
    lines.push(
      "# HELP relay_endpoint_disabled Whether the endpoint is currently auto-disabled (WR-150)."
    );
    lines.push("# TYPE relay_endpoint_disabled gauge");
    for (const endpoint of input.endpointDisabledNow) {
      lines.push(`relay_endpoint_disabled{endpoint="${escapeLabelValue(endpoint)}"} 1`);
    }
  }
  // WR-153: activity-gated like the auto-disable series — the counter
  // appears only for endpoints whose depth has actually reached a
  // configured threshold, so a relay with the feature off exposes no
  // `relay_queue_depth_breach_total` series at all.
  if (input.queueDepthBreach !== undefined && input.queueDepthBreach.length > 0) {
    lines.push(
      "# HELP relay_queue_depth_breach_total Queue-depth threshold breaches (WR-153) per endpoint."
    );
    lines.push("# TYPE relay_queue_depth_breach_total counter");
    for (const s of input.queueDepthBreach) {
      lines.push(
        `relay_queue_depth_breach_total{endpoint="${escapeLabelValue(s.endpoint)}"} ${s.breaches}`
      );
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
  // WR-113: activity-gated like the stale-pause series — the ordered
  // series appear only for ordered endpoints with recorded activity, so
  // a relay with the feature off exposes no `relay_ordered_*` series at
  // all.
  if (input.ordered !== undefined && input.ordered.length > 0) {
    lines.push(
      "# HELP relay_ordered_head_blocked_total Follower dispatches held behind the head of an ordered-delivery line (WR-113)."
    );
    lines.push("# TYPE relay_ordered_head_blocked_total counter");
    lines.push(
      "# HELP relay_ordered_head_of_line_parked_total Heads poison-parked into the dead-letter list after exceeding maxHeadOfLineHoldMs (WR-113)."
    );
    lines.push("# TYPE relay_ordered_head_of_line_parked_total counter");
    lines.push(
      "# HELP relay_ordered_urgent_bypassed_total Urgent items that bypassed the ordered gate (WR-113)."
    );
    lines.push("# TYPE relay_ordered_urgent_bypassed_total counter");
    for (const s of input.ordered) {
      const ep = escapeLabelValue(s.endpoint);
      lines.push(`relay_ordered_head_blocked_total{endpoint="${ep}"} ${s.headBlocked}`);
      lines.push(`relay_ordered_head_of_line_parked_total{endpoint="${ep}"} ${s.headOfLineParked}`);
      lines.push(`relay_ordered_urgent_bypassed_total{endpoint="${ep}"} ${s.urgentBypassed}`);
    }
  }
  // WR-118: activity-gated like the ordered series — the assertion
  // series appear only for (tenant, endpoint) scopes with a recorded
  // failure, so a relay with the feature off exposes no
  // `relay_assertion_failures_total` series at all.
  if (input.assertionFailures !== undefined && input.assertionFailures.length > 0) {
    lines.push(
      "# HELP relay_assertion_failures_total Downstream response assertion failures by endpoint (WR-118)."
    );
    lines.push("# TYPE relay_assertion_failures_total counter");
    for (const s of input.assertionFailures) {
      const ep = escapeLabelValue(s.endpoint);
      lines.push(
        `relay_assertion_failures_total{endpoint="${ep}"${tenantLabel(s.tenant)}} ${s.failures}`
      );
    }
  }
  return lines.join("\n") + "\n";
}
