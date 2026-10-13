import {
  DeadLetterAutoReplayer,
  type AutoReplayOptions,
  type DeadLetterAutoReplayAuditEvent,
} from "./autoreplay.ts";
import {
  DeadLetterRetentionSweeper,
  resolveRetentionTtl,
  type DeadLetterPurgeResult,
  type DeadLetterPurgedEvent,
  type DeadLetterRetentionOptions,
} from "./deadletter-retention.ts";
import { EndpointCircuitBreaker, type CircuitBreakerOptions, type CircuitState, type CircuitStats } from "./circuit.ts";
import {
  DownstreamProber,
  type ProbeAuditEvent,
  type ProbeEndpointStats,
  type ProbeOptions,
} from "./downstream-probe.ts";
import type { EncryptedPayload, PayloadEncryptor } from "./encrypt.ts";
import type { FieldMask } from "./masking.ts";
import {
  HttpDeliveryError,
  classifyFailure,
  parseRetryAfterMs,
  type ClassifiedFailure,
  type FailureClass,
} from "./failure.ts";
import {
  LatencyTracker,
  type EndpointLatencyStats,
  type LatencyTrackerOptions,
} from "./latency.ts";
import {
  SloRiskPredictor,
  type SloRiskInfo,
  type SloRiskObservation,
  type SloRiskOptions,
} from "./slo-risk.ts";
import { EndpointDeliveryWindow, parseDeliveryWindowSpec, type DeliveryWindowOptions, type DeliveryWindowStats } from "./delivery-window.ts";
export { parseDeliveryWindowSpec, EndpointDeliveryWindow };
export type { DeliveryWindowOptions, DeliveryWindowStats };
import {
  ScheduledDeliveryQueue,
  parseDeliverAtHeader,
  DELIVER_AT_HEADER,
  type ScheduledQueueOptions,
  type ScheduledStats,
  type ScheduledDeliveryInfo,
} from "./scheduled.ts";
export { ScheduledDeliveryQueue, parseDeliverAtHeader, DELIVER_AT_HEADER };
export type { ScheduledQueueOptions, ScheduledStats, ScheduledDeliveryInfo };
export { CRON_HEADER, parseCronExpression, nextCronOccurrence } from "./cron.ts";
export type { CronExpression } from "./cron.ts";
import {
  ShadowDispatcher,
  type ShadowDeliveredInfo,
  type ShadowFailedInfo,
  type ShadowTargetConfig,
  type ShadowTargetStats,
  type ShadowTargetsConfig,
} from "./shadow.ts";
export type {
  ShadowDeliveredInfo,
  ShadowFailedInfo,
  ShadowTargetConfig,
  ShadowTargetStats,
  ShadowTargetsConfig,
};
import { EndpointQuota, type QuotaOptions, type QuotaStats } from "./quota.ts";
import { ReplayEgressGate, type ReplayEgressOptions, DEFAULT_REPLAY_EGRESS_RPS } from "./replay-egress.ts";
import { RetryBudget, type RetryBudgetOptions } from "./retry-budget.ts";
import {
  AdaptiveBackoffController,
  type AdaptiveBackoffEndpointStats,
  type AdaptiveBackoffOptions,
} from "./adaptive-backoff.ts";
import {
  BatchCollector,
  newBatchId,
  resolveBatchOptions,
  type BatchEnvelopeInput,
  type BatchOptions,
  type ResolvedBatchOptions,
} from "./batch.ts";
import {
  CompletionCallbacker,
  createBoundAddressSelfCheck,
  isSelfCallbackTarget,
  resolveCompletionCallbackConfig,
  type CompletionCallbackFailedInfo,
  type CompletionCallbackOptions,
  type CompletionReceipt,
  type TerminalDeliveryState,
} from "./callback.ts";
import { TENANT_ID_HEADER, assertValidTenantId, tenantScopeKey, splitTenantScopeKey } from "./tenant.ts";
import { newTraceId, TRACE_ID_HEADER } from "./trace.ts";
import { QueueJournal, type CompactItem, type QueueRestoredInfo } from "./durable-queue.ts";
import {
  assertValidEndpointConfigPatch,
  type ConfigChange,
  type EndpointConfigPatch,
} from "./hotreload.ts";
import {
  FailoverManager,
  type FailoverConfig,
  type FailoverEndpointStats,
  type FailoverSwitchEvent,
} from "./failover.ts";
import {
  WeightedDispatcher,
  type WeightedConfig,
  type WeightedEndpointStats,
  type WeightedTargetConfig,
} from "./weighted.ts";
import {
  GlobalConcurrencyGate,
  type GlobalConcurrencyStats,
} from "./global-concurrency.ts";
import {
  renderPrometheus,
  type CircuitStateInput,
  type CertExpiryMetricsInput,
  type DeliveryCountersInput,
  type DeliveryDeadlineExceededInput,
  type FailoverMetricsInput,
  type LatencyHistogramInput,
  type ProbeMetricsInput,
  type ShadowMetricsInput,
  type SloRiskMetricsInput,
  type StarvationGuardMetricsInput,
  type WeightedMetricsInput,
} from "./metrics.ts";
import {
  summarizeDeadLetterFailure,
  summarizeDownstreamResponse,
  type DownstreamResponseSummary,
} from "./response-summary.ts";
import { OtlpExporter, type OtlpExporterOptions, type OtlpStats } from "./otlp.ts";

export { TRACE_ID_HEADER };
export { renderPrometheus };
export { TENANT_ID_HEADER, assertValidTenantId, tenantScopeKey, splitTenantScopeKey };
export type { DeliveryCountersInput, CircuitStateInput, LatencyHistogramInput, StarvationGuardMetricsInput, SloRiskMetricsInput, CertExpiryMetricsInput };
export { HttpDeliveryError, classifyFailure, parseRetryAfterMs };
export type { FailureClass, ClassifiedFailure };
export type { DownstreamResponseSummary };
export type { FailoverConfig, FailoverEndpointStats, FailoverSwitchEvent };
export type { WeightedConfig, WeightedEndpointStats, WeightedTargetConfig };
export type { WeightedMetricsInput };
export { CompletionCallbacker, createBoundAddressSelfCheck, isSelfCallbackTarget, resolveCompletionCallbackConfig };
export { GlobalConcurrencyGate };
export type { GlobalConcurrencyStats };
export type {
  CompletionCallbackFailedInfo,
  CompletionCallbackOptions,
  CompletionReceipt,
  TerminalDeliveryState,
};

export type { CircuitBreakerOptions, CircuitState, CircuitStats };
export type { EncryptedPayload, PayloadEncryptor };
export type { EndpointLatencyStats, LatencyTrackerOptions };
export type { SloRiskInfo, SloRiskObservation, SloRiskOptions };
export type { FieldMask, FieldMaskRule, MaskStrategy };
export type { QuotaOptions, QuotaStats };
export type { ReplayEgressOptions };
export { ReplayEgressGate, DEFAULT_REPLAY_EGRESS_RPS };
export type { RetryBudgetOptions } from "./retry-budget.ts";
export { RetryBudget, DEFAULT_RETRY_BUDGET_PER_MINUTE } from "./retry-budget.ts";
export type { AdaptiveBackoffOptions, AdaptiveBackoffEndpointStats } from "./adaptive-backoff.ts";
export {
  AdaptiveBackoffController,
  DEFAULT_ADAPTIVE_MIN_BASE_MS,
  DEFAULT_ADAPTIVE_MAX_BASE_MS,
  DEFAULT_ADAPTIVE_UP_FACTOR,
  DEFAULT_ADAPTIVE_DOWN_FACTOR,
} from "./adaptive-backoff.ts";
export type { BatchEnvelopeInput, BatchOptions };
export type { AutoReplayOptions, DeadLetterAutoReplayAuditEvent };
export type {
  DeadLetterRetentionOptions,
  DeadLetterPurgedEvent,
  DeadLetterPurgeInfo,
  DeadLetterPurgeResult,
};
export { DeadLetterRetentionSweeper, resolveRetentionTtl };
export type { OtlpExporterOptions, OtlpStats } from "./otlp.ts";

/**
 * Delivery priority of an item.
 *
 * - `"normal"` (default): the standard lane — exponential backoff with
 *   jitter, bounded by the per-endpoint concurrency limiter.
 * - `"urgent"`: the fast lane — skips the exponential backoff (a fixed
 *   `urgent.retryDelayMs` between attempts) and bypasses the per-endpoint
 *   concurrency limiter, so an urgent delivery never waits behind queued
 *   normal deliveries. Each urgent attempt costs one token from the
 *   endpoint's bucket (`urgent.maxUrgentPerSecond`); when the bucket is
 *   empty the item degrades to the normal lane instead of being dropped.
 */
export type DeliveryPriority = "normal" | "urgent";

export interface RetryItem {
  id: string;
  payload: Buffer;
  targetUrl: string;
  headers: Record<string, string | string[] | undefined>;
  /** Delivery lane; defaults to `"normal"` when unset. */
  priority?: DeliveryPriority;
  /**
   * End-to-end trace ID (see `src/trace.ts`): threads the item through
   * receive → delivery → retries → dead-letter, and appears in every audit
   * event, delivery event, and the downstream `x-trace-id` header. When
   * unset, `enqueue()` mints one, so it is always populated on the delivery
   * path and in dead-letter entries.
   */
  traceId?: string;
  /**
   * Tenant id (WR-48; see `src/tenant.ts`), from the inbound `x-tenant-id`
   * header. Scopes the per-(tenant, endpoint) isolation primitives
   * (concurrency limiter, quota, circuit breaker, latency tracker) and is
   * carried as a label on audit events, SSE delivery events, and metrics.
   * Unset = the default tenant: identical code paths with unscoped keys,
   * so behavior matches the pre-tenant relay exactly.
   */
  tenantId?: string;
  /**
   * WR-57: future delivery time (epoch ms), from the inbound `x-deliver-at`
   * header. When set and in the future, the item is parked in the
   * deliver_at delay queue instead of entering the normal path: nothing is
   * attempted and nothing is consumed (no attempt, no retry budget, no
   * quota, no circuit verdict) until the instant arrives. A past-due value
   * takes the normal path like any other delivery.
   */
  deliverAt?: number;
  /**
   * WR-80: marks a delivery generated by a cron-recurring schedule (the
   * schedule id from `x-schedule-cron` registration). Set by the
   * scheduler on every occurrence — never by callers. The owner audits
   * `scheduled_fired` on items carrying it.
   */
  scheduleId?: string;
  /**
   * WR-44: attempts consumed *before* the in-flight dispatch (0-based),
   * maintained by the queue on its stored entry. The queue hands the
   * sender a spread copy, so the sender-bound item carries the index of
   * the attempt about to be dispatched — the 1-based attempt number the
   * downstream sees is `attempt + 1`. Used to derive the
   * `x-relay-idempotency-key` header when outbound idempotency keys are
   * enabled. Unset on items you enqueue yourself; the sender must treat
   * a missing value as attempt 1 (`(item.attempt ?? 0) + 1`).
   */
  attempt?: number;
  /**
   * WR-76: ms epoch when the item entered the deliverable queue
   * (`enqueueNow`), stamped by the queue — the start of the
   * end-to-end delivery deadline clock. A caller-supplied value is
   * honored (hand-built items, tests); otherwise the queue stamps
   * `deliveryDeadline.now()` at admission. Dead-letter replays refresh
   * it: a replay starts a fresh delivery cycle with a fresh deadline,
   * exactly like the WR-13 latency clock restart.
   */
  enqueuedAt?: number;
}

/** Options for the urgent delivery lane (see {@link DeliveryPriority}). */
export interface UrgentLaneOptions {
  /**
   * Fixed delay in ms between urgent retries — the fast lane skips the
   * exponential backoff entirely. Default: 0 (immediate). Must be >= 0.
   */
  retryDelayMs?: number;
  /**
   * Maximum urgent attempts per second per endpoint (token bucket; burst
   * capacity is one full second of tokens). The abuse guard for the fast
   * lane: without it a flood of `urgent` items could hammer a downstream.
   * Default: 100. Must be > 0.
   */
  maxUrgentPerSecond?: number;
  /**
   * WR-35 starvation guard: the minimum share of per-endpoint dispatch
   * turns guaranteed to the normal lane while normal deliveries are
   * backlogged for a dispatch slot (deficit round-robin; see
   * {@link LaneScheduler}). Default: 0.2 (20%). Must be in the open
   * interval (0, 1) — anything else throws `RangeError` at construction.
   * Overridable per endpoint via
   * {@link RetryQueue.setEndpointMinNormalShare}.
   */
  minNormalShare?: number;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
}

/** Tuning for the Prometheus metrics surface (`GET /metrics`). */
export interface MetricsOptions {
  /**
   * Histogram bucket upper bounds in ms for accepted→delivered latency
   * (`relay_delivery_latency_seconds_*`). Default:
   * `[50, 100, 250, 500, 1000, 2500, 5000, 10000]`. Must be a non-empty
   * strictly ascending list of finite positive numbers. The histogram is
   * only emitted when latency tracking is enabled (`latency` option); the
   * delivery counters and circuit gauges are always collected.
   */
  histogramBucketsMs?: number[];
  /**
   * Opt-in dead-letter auto-replay scheduler (see `src/autoreplay.ts`):
   * `DeadLetterAutoReplayer` ticks `intervalMs` apart, replaying the whole
   * dead-letter list with the same fresh-budget semantics as a manual
   * replay (`POST /dead-letter/replay`), backing off exponentially between
   * consecutive empty rounds and stopping permanently after `maxRounds`
   * consecutive empty rounds (audited as `dead_letter_auto_replay`).
   * Disabled by default: when unset (or `enabled: false`) nothing is ever
   * replayed automatically. Invalid values throw `RangeError`. The
   * scheduler starts on `start()` and stops on `stop()` / `shutdown()`.
   */
  autoReplay?: AutoReplayOptions;
  /**
   * Called with the `dead_letter_auto_replay` audit event when the
   * auto-replay scheduler stops on rounds exhaustion. The server wires
   * this to its audit log; a raw queue without it simply loses the event
   * (nothing else is affected).
   */
  onAutoReplayAudit?: (event: DeadLetterAutoReplayAuditEvent) => void;
  /**
   * WR-80: called with the `scheduled_fired` audit event every time a
   * cron-recurring schedule generates an occurrence. The server wires this
   * to its audit log; a raw queue without it simply loses the event
   * (nothing else is affected).
   */
  onScheduledFired?: (event: ScheduledFiredEvent) => void;
}

/**
 * WR-80: one cron occurrence generated. The occurrence is an independent
 * delivery (fresh id + fresh traceId); `nextAt` is the *following*
 * cycle's fire instant, for operator visibility.
 */
export interface ScheduledFiredEvent {
  event: "scheduled_fired";
  /** The recurring schedule that fired. */
  scheduleId: string;
  /** The generated occurrence's delivery id (`<scheduleId>#<n>`). */
  id: string;
  /** Fresh trace ID minted for this occurrence. */
  traceId: string;
  targetUrl: string;
  tenant?: string;
  priority?: RetryItem["priority"];
  /** Epoch ms of the next scheduled fire after this occurrence. */
  nextAt: number;
}

/** Fired when a delivery's accepted→delivered latency exceeds the SLO budget. */
export interface SloMissInfo {
  id: string;
  /** End-to-end trace ID of the slow delivery. */
  traceId: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  endpoint: string;
  latencyMs: number;
  sloMs: number;
}

/** {@link LatencyTrackerOptions} plus the SLO-miss hook and the SLO-risk predictor. */
export interface LatencyOptions extends LatencyTrackerOptions {
  /** Called once per delivery whose accepted→delivered latency exceeds `sloMs`. */
  onSloMiss?: (info: SloMissInfo) => void;
  /**
   * WR-71: SLO-breach prediction and early warning (see `src/slo-risk.ts`).
   * When set, every `enqueue` and every delivered sample feeds the
   * per-endpoint predictor, which fires `onSloRisk` before the budget is
   * actually breached. Disabled by default (`undefined`) — the relay then
   * behaves exactly as before, with no predictor instances and no
   * `relay_slo_risk_seconds` series.
   */
  sloRisk?: SloRiskOptions;
}

/** One row of {@link RetryQueue.getSloRiskStats}. All JSON-serializable. */
export interface SloRiskStatsRow {
  endpoint: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  /** Whether the endpoint is currently in the elevated risk state. */
  atRisk: boolean;
  /** `max(latencyPressure, backlogPressure)`; 1.0 = predicted breach. */
  score: number;
  /** Predicted accepted→delivered latency for a newly accepted delivery, ms. */
  predictedLatencyMs: number;
  /** p95 of the rolling latency window behind the prediction, ms. */
  p95Ms: number;
  /** Smoothed per-endpoint backlog (queued + in-flight + backoff-waiting). */
  backlogEwma: number;
  /** Predicted SLO headroom remaining, in seconds (>= 0). */
  headroomSeconds: number;
}

/**
 * Delivery lifecycle event, emitted for operator observability (see
 * {@link RetryQueue.subscribeDeliveryEvents}). Exactly three kinds:
 *
 * - `"delivered"`: a delivery attempt succeeded (`attempts` = total attempts
 *   used, including the successful one).
 * - `"retrying"`: an attempt failed and a retry was scheduled (`attempts` =
 *   attempts consumed so far, `error` = the failure).
 * - `"dead_letter"`: every attempt was exhausted and the item moved to the
 *   dead-letter list.
 *
 * Parking a delivery because the endpoint's circuit is open or its quota
 * bucket is empty is *not* a `retrying` event: no attempt was consumed.
 */
export type DeliveryEventType = "delivered" | "retrying" | "dead_letter";

export interface DeliveryEvent {
  type: DeliveryEventType;
  id: string;
  /** End-to-end trace ID (see `src/trace.ts`), always populated. */
  traceId: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  targetUrl: string;
  /** Attempts consumed so far (including the successful one for `delivered`). */
  attempts: number;
  /**
   * Outbound payload bytes for the delivery this event describes (WR-78
   * usage metering). Always populated by the queue; absent on events
   * constructed by hand (e.g. in tests).
   */
  bytesOut?: number;
  /** ISO-8601 timestamp when the event fired. */
  at: string;
  /** Failure message; present for `retrying` and `dead_letter`. */
  error?: string;
}

/** Fired every time a batch is flushed (one merged item enqueued). */
export interface BatchInfo {
  batchId: string;
  endpoint: string;
  /** Events merged into this batch. */
  size: number;
  /**
   * Trace IDs of the merged member events, in member order. The merged
   * delivery itself carries a fresh trace ID (see `RetryItem.traceId`), so
   * this is the correlation key back to the original inbound events.
   */
  traceIds: string[];
}

export type Sender = (item: RetryItem) => Promise<DownstreamResponse | void>;

/**
 * A downstream HTTP response, as observed by the sender. A sender that can
 * see the response (the default sender always can) returns it on transport
 * success so {@link ResponseValidator}s can check its semantics; senders
 * that cannot simply resolve with `undefined`, in which case validation
 * is skipped for that delivery.
 */
export interface DownstreamResponse {
  /** HTTP status code the downstream returned (2xx on this path). */
  statusCode: number;
  /**
   * Captured response body. The default sender caps the capture at
   * `RESPONSE_CAPTURE_MAX_BYTES` (64 KiB) — enough for semantic markers
   * like `{"ok":false}` — and sets `truncated` when it cut bytes off.
   */
  body: Buffer;
  /** True when the body was cut at the sender's capture cap. */
  truncated: boolean;
  /**
   * WR-62: the downstream's `content-encoding` response header value,
   * when the endpoint opted into response decompression and the
   * downstream sent one. The `body` above is already decoded (when the
   * coding was known); unset on the plain path. Custom senders never
   * set it.
   */
  contentEncoding?: string;
  /**
   * WR-54: time-to-first-byte in ms — measured by the sender from the
   * request being issued to the downstream's first response bytes
   * arriving. Documented as a "首响应头到达耗时" (first-response-header
   * arrival) approximation: it covers connection setup + request write +
   * server think time, not kernel-to-user dispatch. Unset when the sender
   * did not measure it (custom senders, WebSocket/H2 paths) — the audit
   * summary then marks TTFB `"unavailable"` instead of fabricating one.
   */
  timeToFirstByteMs?: number;
}

/**
 * Per-endpoint downstream response semantic validator (WR-37). Some
 * downstreams answer `200 OK` with a body that still means failure —
 * `{"ok":false}`, an `"error"` field, a payment gateway's error code.
 * The validator runs after the transport succeeded (2xx) and decides
 * whether the body actually means success:
 *
 * - return `true`: the response is a genuine success;
 * - return `false`: semantic failure (generic);
 * - return a `string`: semantic failure with that reason;
 * - throw: fail-closed — treated as a semantic failure.
 *
 * A semantic failure follows the normal retry / dead-letter / circuit
 * path: it is classified `"retryable"`, consecutive semantic failures
 * trip the circuit breaker (WR-10), and the accepted→delivered latency
 * clock keeps running until the item is delivered or dead-lettered
 * (WR-13). The failure is audited with reason `semantic_failed`.
 */
export type ResponseValidator = (response: DownstreamResponse) => boolean | string;

/** Structured delivery failure: the 2xx response failed semantic validation. */
export class SemanticDeliveryError extends Error {
  /** The validator's reason, or a generic marker when it returned `false`. */
  readonly reason: string;
  constructor(reason: string) {
    super(`Downstream response failed semantic validation: ${reason}`);
    this.name = "SemanticDeliveryError";
    this.reason = reason;
  }
}

/** Fired when a delivery attempt fails downstream semantic validation. */
export interface SemanticFailureInfo {
  /** Delivery id. */
  id: string;
  /** End-to-end trace ID. */
  traceId: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  /** Downstream endpoint (`targetUrl`). */
  endpoint: string;
  /** Attempts consumed so far, including this one. */
  attempts: number;
  /** The validator's reason (`"validator returned false"` when it returned `false`). */
  reason: string;
}

/** Fired when the global retry budget (WR-38) parks a retry. */
export interface RetryBudgetDepletedInfo {
  /** Delivery id. */
  id: string;
  /** End-to-end trace ID. */
  traceId: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  /** Downstream endpoint (`targetUrl`). */
  endpoint: string;
  /** Attempts consumed so far (the failed attempt is already counted). */
  attempts: number;
  /** Milliseconds the retry was parked for. */
  waitMs: number;
}

/**
 * Fired when a delivery attempt fails and a retry is scheduled (WR-43).
 * The raw material for per-trace delivery snapshots
 * (`GET /deliveries/:traceId`): every non-terminal failure yields one line
 * carrying the error and the scheduled delay, so the operator can
 * reconstruct the retry trajectory instead of guessing it from attempt
 * counts.
 */
export interface AttemptFailedInfo {
  /** Delivery id. */
  id: string;
  /** End-to-end trace ID. */
  traceId: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  /** Physical downstream target the failed attempt went to. */
  endpoint: string;
  /** Attempts consumed so far (the failed attempt is already counted). */
  attempts: number;
  /** Failure message of the failed attempt. */
  error: string;
  /** Milliseconds until the retry runs (after budget parking, if any). */
  nextDelayMs: number;
}

/**
 * Jitter strategy for the retry backoff.
 *
 * - `"additive"` (default): uniform(0, `jitterMs`) added on top of the
 *   exponential term. Preserves the original behavior.
 * - `"full"`: uniform(0, min(`maxDelayMs`, `baseDelayMs * 2^attempt`)) — the
 *   AWS-style "full jitter". This is the recommended anti-thundering-herd
 *   choice: when many deliveries fail at once (e.g. a downstream outage),
 *   their retry schedules spread across the whole window instead of
 *   clustering on the exponential grid.
 */
export type JitterStrategy = "additive" | "full";

/** Global retry budget (WR-38) observability. */
export interface RetryBudgetStats {
  /** Configured retries-per-minute budget. */
  retriesPerMinute: number;
  /** Retries parked because the budget was exhausted. */
  depleted: number;
}

/**
 * A dead-lettered delivery: the original {@link RetryItem} plus the
 * metadata an operator needs to diagnose and replay it.
 *
 * When the queue is configured with a `payloadEncryptor`, the payload is
 * sealed at rest: `payload` is empty, `encryptedPayload` holds the envelope,
 * and `payloadBytes` records the original length (the operator endpoint
 * never exposes raw payloads either way).
 */
export interface DeadLetterEntry extends RetryItem {
  /** Attempts consumed before the item was dead-lettered. */
  attempts: number;
  /** Last delivery error message. */
  lastError: string;
  /**
   * Classification of the final failure (see `src/failure.ts`):
   * `"non_retryable"` means the item was dead-lettered immediately —
   * a poison payload that would never succeed — without burning the
   * rest of the retry budget; `"retryable"` means every attempt was
   * genuinely spent against a transient failure.
   */
  failureClass: FailureClass;
  /** ISO-8601 timestamp when the item entered the dead-letter list. */
  deadLetteredAt: string;
  /** Original payload byte length (also when encrypted). */
  payloadBytes: number;
  /** Sealed payload envelope; present only when `payloadEncryptor` is set. */
  encryptedPayload?: EncryptedPayload;
  /**
   * WR-39: the logical endpoint (the configured primary `targetUrl`) when
   * the entry was dead-lettered on a failover standby. `targetUrl` above
   * is the physical target the final attempt actually went to; a replay
   * re-resolves from this field so it follows the *current* active target
   * instead of pinning to the standby. Absent when failover is not
   * configured or the primary served the delivery.
   */
  failoverEndpoint?: string;
}

/** Selector for batch dead-letter replays (see {@link RetryQueue.replayDeadLetters}). */
export interface DeadLetterReplayFilter {
  /**
   * Only entries dead-lettered for this endpoint (exact `targetUrl` match).
   * Unset: entries for every endpoint are eligible.
   */
  endpoint?: string;
  /**
   * WR-86: only entries dead-lettered for this tenant (exact tenant-id
   * match, WR-48). Unset: every tenant's entries are eligible — including
   * the default tenant's. A replay that omits `tenant` therefore keeps the
   * pre-tenant behavior byte-for-byte.
   */
  tenant?: string;
  /**
   * Only these dead-letter ids — a subset of what the filter would
   * otherwise match. Unset: every matched entry is replayed.
   */
  ids?: string[];
}

/**
 * Dry-run preview of the dead letters a batch replay would pick up:
 * operator metadata only. The payload itself is never exposed here
 * (not even its encrypted envelope), so a dry run is safe to review in a
 * reconciliation workflow before any real replay.
 */
export interface DeadLetterReplayPreview {
  id: string;
  endpoint: string;
  /** Tenant id (WR-86/WR-48); absent for the default tenant. */
  tenant?: string;
  attempts: number;
  lastError: string;
  deadLetteredAt: string;
  payloadBytes: number;
}

/** A dead-letter entry that could not be re-queued. */
export interface DeadLetterReplayFailure {
  id: string;
  error: string;
}

/** Outcome of {@link RetryQueue.replayDeadLetters}. */
export interface DeadLetterBatchReplayResult {
  /** Ids successfully re-queued with a fresh attempt budget. */
  replayed: string[];
  /**
   * Entries that could not be re-queued (e.g. a sealed payload that no
   * longer decrypts); they stay in the dead-letter list untouched.
   */
  failed: DeadLetterReplayFailure[];
  /**
   * Ids matched but held back by the WR-68 replay egress throttle (this
   * call's per-endpoint budget was exhausted). They stay in the
   * dead-letter list — nothing is dropped — and the next replay call
   * (manual or a WR-31 auto round) picks them up. Empty when the egress
   * gate is not configured.
   */
  throttled: string[];
}

/** Dead-letter observability snapshot (see {@link RetryQueue.getDeadLetterStats}). */
export interface DeadLetterStats {
  /** Entries currently live in the dead-letter list. */
  total: number;
  /** Entries auto-purged by the retention sweep (WR-64) since construction. */
  purged: number;
  /**
   * Entries held back by the WR-68 replay egress throttle since
   * construction (cumulative; each is still live in the list until a
   * later replay re-queues it).
   */
  throttled: number;
  /** Live entries per logical endpoint (first-seen order). */
  byEndpoint: Array<{ endpoint: string; count: number }>;
  /**
   * WR-86: live entries per (tenant, endpoint) pair (first-seen order).
   * `tenant` is absent for the default tenant. Operators running several
   * tenants against one relay can see whose dead letters are whose —
   * the unscoped `byEndpoint` row stays the sum across tenants, so old
   * consumers of this shape keep working.
   */
  byTenantEndpoint: Array<{ tenant?: string; endpoint: string; count: number }>;
}

/**
 * Per-endpoint end-to-end delivery deadline (WR-76): the SLO clock for a
 * delivery runs from queue admission (`RetryItem.enqueuedAt`) to delivery
 * confirmation — the full chain, not a connection or read timeout.
 *
 * Design intent: the deadline is an end-to-end SLO, not a retry budget.
 * It is orthogonal to the retry backoff — a delivery may retry normally
 * while inside its deadline, and the moment the deadline passes the item
 * stops: no further backoff is scheduled and the remaining retry budget
 * is not consumed. Time parked in the urgent fast lane (WR-12), the
 * quota hold (WR-15), the circuit-breaker hold (WR-10), the manual pause
 * (WR-50), and the delivery window (WR-52) all counts toward the
 * deadline — only the by-design holds *before* queue admission (the
 * WR-09 batch window, the WR-57 deliver_at delay) do not, the same
 * convention as the WR-13 accepted→delivered latency clock.
 */
export interface DeliveryDeadlineOptions {
  /**
   * Per-endpoint deadline in ms: exact `targetUrl` (the logical endpoint)
   * -> milliseconds from queue admission to delivery confirmation.
   * Endpoints absent from the record have no deadline — the feature is
   * opt-in per endpoint, unset means off. Every value must be a finite
   * number > 0; anything else throws `RangeError` at construction.
   */
  deadlines?: Record<string, number>;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
}

/** Fired when a delivery's end-to-end deadline expires before delivery (WR-76). */
export interface DeliveryDeadlineExceededInfo {
  /** Delivery id. */
  id: string;
  /** End-to-end trace ID. */
  traceId: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  /** Logical downstream endpoint (`targetUrl`). */
  endpoint: string;
  /** Attempts actually consumed before the deadline expired (never fabricated). */
  attempts: number;
  /** Milliseconds elapsed from queue admission to expiry. */
  elapsedMs: number;
  /** The endpoint's configured deadline in ms. */
  deadlineMs: number;
}

/**
 * The terminal error carried into the dead-letter entry when a
 * delivery's end-to-end deadline expires (WR-76). Classified
 * `"retryable"` — the payload was not poison, the relay simply ran out
 * of SLO — so the dead-letter record reads honestly.
 */
export class DeliveryDeadlineExceededError extends Error {
  /** Logical endpoint whose deadline expired. */
  readonly endpoint: string;
  /** Milliseconds elapsed from queue admission to expiry. */
  readonly elapsedMs: number;
  /** The endpoint's configured deadline in ms. */
  readonly deadlineMs: number;
  constructor(endpoint: string, elapsedMs: number, deadlineMs: number) {
    super(
      `delivery deadline exceeded for ${endpoint}: ${Math.round(elapsedMs)}ms elapsed (deadline ${deadlineMs}ms)`
    );
    this.name = "DeliveryDeadlineExceededError";
    this.endpoint = endpoint;
    this.elapsedMs = elapsedMs;
    this.deadlineMs = deadlineMs;
  }
}

export interface RetryQueueOptions {
  /** Sender function; defaults to a no-op success sender. Injectable for tests. */
  sender?: Sender;
  /** Base delay in ms for the exponential backoff. Default: 1000. Must be > 0. */
  baseDelayMs?: number;
  /** Maximum delay in ms between attempts. Default: 60000. Must be > 0. */
  maxDelayMs?: number;
  /** Total attempts per item (initial try + retries). Default: 5. Must be >= 1. */
  maxAttempts?: number;
  /** Jitter added to each delay in ms (uniform 0..jitterMs). Default: 100. Must be >= 0. */
  jitterMs?: number;
  /** Jitter strategy; see {@link JitterStrategy}. Default: "additive". */
  jitterStrategy?: JitterStrategy;
  /**
   * Adaptive backoff (WR-59; see `src/adaptive-backoff.ts`): scales the
   * exponential backoff's *base* per endpoint from recent delivery
   * outcomes — consecutive retryable failures double it toward
   * `maxBaseMs`, successes halve it back toward `minBaseMs`. The
   * exponent, jitter strategy (WR-02), and `maxDelayMs` cap are
   * untouched. Composes orthogonally with the global retry budget
   * (WR-38): the budget gate runs before the backoff is computed, so a
   * budget-parked retry waits on the budget, not on an inflated base.
   * Disabled by default (absent = the classic fixed-base backoff).
   * Invalid values throw `RangeError` at construction.
   */
  adaptiveBackoff?: AdaptiveBackoffOptions;
  /**
   * Random source in [0, 1) used for jitter; defaults to `Math.random`.
   * Injectable so tests can verify jitter bounds deterministically.
   */
  random?: () => number;
  /**
   * Scheduler factory; defaults to the real setTimeout. Injectable so tests
   * can run deterministically. Returns a handle with an `unref`-style
   * `clear()` method. Also accepts a clearTimer to cancel pending timeouts.
   */
  setTimer?: (fn: () => void, ms: number) => { clear(): void };
  clearTimer?: (handle: { clear(): void }) => void;
  /**
   * Maximum concurrent in-flight deliveries per endpoint (`targetUrl`).
   * Deliveries beyond the limit wait in FIFO order for a slot. Default:
   * `Infinity` (no limit). Must be a positive integer or `Infinity`.
   */
  maxConcurrentPerEndpoint?: number;
  /**
   * Callback when an item exhausts all attempts and moves to dead-letter —
   * or is dead-lettered immediately as non-retryable. `failureClass` is
   * the classification of the final failure (see `src/failure.ts`); it is
   * an optional fourth parameter so existing callbacks keep compiling.
   * `summary` is the WR-54 response summary of the last attempt — only
   * the status code is known (from the failing HTTP response), the rest
   * is honestly `"unavailable"`. Also optional, for the same reason.
   */
  onDeadLetter?: (
    item: RetryItem,
    attempts: number,
    lastError: unknown,
    failureClass?: FailureClass,
    summary?: DownstreamResponseSummary
  ) => void;
  /**
   * Callback when an item is successfully delivered. `summary` is the
   * WR-54 downstream response summary (status code, byte count, TTFB,
   * body fingerprint); an optional third parameter so existing callbacks
   * keep compiling. A custom sender returning `void` still yields a
   * summary — every field honestly marked `"unavailable"`.
   */
  onDelivered?: (item: RetryItem, attempts: number, summary?: DownstreamResponseSummary) => void;
  /**
   * Per-endpoint circuit breaker (see `src/circuit.ts`). When set,
   * `failureThreshold` consecutive delivery failures trip the endpoint's
   * circuit open for `cooldownMs`: attempts made while the circuit is open
   * are parked — rescheduled without consuming the retry budget — instead
   * of hammering a down endpoint. After the cooldown a single half-open
   * probe is let through; its success closes the circuit, its failure
   * re-opens it and restarts the cooldown. Disabled by default.
   */
  circuitBreaker?: CircuitBreakerOptions;
  /**
   * Called on every circuit state transition
   * (closed->open, open->half_open, half_open->closed, half_open->open).
   * Takes precedence over `circuitBreaker.onStateChange` when both are set.
   * The fourth argument is the tenant (WR-48) whose breaker instance
   * transitioned; absent for the default tenant.
   */
  onCircuitStateChange?: (
    endpoint: string,
    from: CircuitState,
    to: CircuitState,
    tenant?: string
  ) => void;
  /**
   * Opt-in active health probing of downstream endpoints (see
   * `src/downstream-probe.ts`). When set, each listed endpoint gets a timed HEAD (or
   * GET) request every `intervalMs` on a lightweight path — independent
   * of the delivery queue, so probes never consume the retry budget and
   * never touch the latency tracker, quota, or batching. Each probe
   * outcome is reported to the circuit breaker exactly like a delivery
   * outcome: `failureThreshold` consecutive probe failures trip the
   * circuit open *before* real deliveries have to fail, and a success
   * resets the counter like any success (a success never closes an open
   * circuit early — recovery still flows through cooldown → half-open).
   * Probe outcomes are counted in the Prometheus exposition
   * (`relay_probe_total`, `relay_probe_consecutive_failures`) and audited
   * via `onProbeAudit`. Disabled by default.
   */
  probe?: ProbeOptions;
  /**
   * Called for every probe outcome worth auditing: `probe_failed` on each
   * failed probe (with the current consecutive-failure streak) and
   * `probe_recovered` when a failing endpoint answers again. The server
   * routes these into the audit log; library users get the hook directly.
   */
  onProbeAudit?: (event: ProbeAuditEvent) => void;
  /**
   * Called after `updateEndpointConfig` applies a hot-reload patch, with
   * the endpoint and the before/after diff of every patched field. The
   * server routes this into the audit log as `endpoint_config_updated`;
   * library users get the same observability hook directly.
   */
  onConfigChange?: (endpoint: string, changes: ConfigChange[]) => void;
  /**
   * Seals dead-letter payloads at rest: when set, a dead-lettered item's
   * `payload` is replaced by an `encryptedPayload` envelope (default
   * {@link AesGcmEncryptor} via `node:crypto`, zero dependencies) and
   * `replayDeadLetter` transparently decrypts before re-queueing. Unset by
   * default, in which case dead-letter payloads are kept in the clear.
   */
  payloadEncryptor?: PayloadEncryptor;
  /**
   * WR-54: opt-in full downstream response body capture in the audit
   * trail. Off by default — a delivery's audit footprint is just the
   * response summary (status code, byte count, TTFB, body fingerprint),
   * never the body, so sensitive downstream payloads never land on disk
   * unasked. When `true`, the full captured body is sealed with the WR-11
   * `payloadEncryptor` and stored as `response_summary.capturedBody` (an
   * `EncryptedPayload` envelope) on every `delivered` audit event.
   * Requires `payloadEncryptor`: enabling capture without one throws
   * `RangeError` at construction (fail-fast — logging response bodies in
   * the clear would silently defeat the default). Dead-letter events
   * never carry a body: a failed attempt has nothing worth capturing.
   */
  responseBodyCapture?: boolean;
  /**
   * WR-72: field-level masking for captured response bodies (see
   * `src/masking.ts`). When set and the endpoint has rules, a JSON
   * response body is masked *before* the WR-11 encryptor seals it into
   * `response_summary.capturedBody` — raw values never reach the
   * ciphertext. Non-JSON bodies pass through untouched (field paths
   * cannot apply). The summary's `bodyFingerprintSha256` still covers
   * the original bytes, so correlation/dedup keep working on what the
   * downstream actually sent.
   */
  fieldMask?: FieldMask;
  /**
   * Urgent delivery lane for items with `priority: "urgent"` (see
   * {@link DeliveryPriority}). The lane is always available when an item is
   * marked urgent; these options only tune it (defaults are sane: immediate
   * retries, 100 urgent attempts/sec per endpoint).
   */
  urgent?: UrgentLaneOptions;
  /**
   * Accepted→delivered latency SLO tracking (see `src/latency.ts`). When
   * set, `enqueue()` starts each delivery's clock, a successful `deliver()`
   * samples it into the endpoint's rolling window, dead-lettered items are
   * discarded without sampling, and `onSloMiss` fires per delivery slower
   * than `sloMs`. Disabled by default.
   */
  latency?: LatencyOptions;
  /**
   * Per-endpoint delivery quota (see `src/quota.ts`). When set, each send
   * attempt costs one token from the endpoint's per-minute bucket; an
   * attempt that finds an empty bucket is rescheduled for the next token
   * refill — never dropped, and never counted against the retry budget or
   * the circuit breaker. Disabled (unlimited) by default.
   */
  quota?: QuotaOptions;
  /**
   * Batch delivery merging (see `src/batch.ts`). When set, normal-priority
   * items for the same endpoint are held for `windowMs` and merged into a
   * single delivery with a JSON envelope (uniform contract: even a lone
   * item is wrapped). Urgent items bypass batching and go out immediately.
   * Disabled by default.
   */
  batch?: BatchOptions;
  /**
   * Per-endpoint downstream response semantic validators (WR-37; see
   * {@link ResponseValidator}). Either a single validator applied to every
   * endpoint, or a record mapping exact `targetUrl` to its validator (the
   * same exact-match convention as `tlsPins`). Non-function values throw
   * `TypeError` at construction. Disabled by default.
   */
  responseValidators?: ResponseValidator | Record<string, ResponseValidator>;
  /**
   * Called once per delivery attempt that fails downstream semantic
   * validation. The server audits these as `failed` with
   * `reason: "semantic_failed"`.
   */
  onSemanticFailure?: (info: SemanticFailureInfo) => void;
  /**
   * Global retry budget (WR-38; see `src/retry-budget.ts`). Caps scheduled
   * *retries* — not first attempts — at `retriesPerMinute` per minute,
   * across all endpoints. When the budget is exhausted, a failed attempt's
   * retry is parked until the next token refill: never dropped, and the
   * parking itself consumes neither the item's retry budget nor a circuit
   * event. Retries resume automatically when the budget recovers.
   * Disabled by default; a present-but-empty object uses a generous
   * default budget.
   */
  retryBudget?: RetryBudgetOptions;
  /**
   * Called once per retry parked by the global retry budget. The server
   * audits these as `retry_budget_depleted`.
   */
  onRetryBudgetDepleted?: (info: RetryBudgetDepletedInfo) => void;
  /**
   * Called once per failed attempt that schedules a retry — i.e. every
   * non-terminal failure. The server audits these as `retrying` (with the
   * error and the scheduled delay) so `GET /deliveries/:traceId` can
   * render the retry trajectory. Failures that dead-letter instead of
   * retrying go through `onDeadLetter`, not here.
   */
  onAttemptFailed?: (info: AttemptFailedInfo) => void;
  /**
   * Called every time a batch is flushed — i.e. a group of buffered events
   * became one merged delivery item. The server audits this as
   * `batch_flushed`.
   */
  onBatch?: (info: BatchInfo) => void;
  /**
   * Called once per starvation-guard activation episode (see
   * {@link StarvationGuardAuditEvent}): the deficit round-robin lane
   * scheduler started deferring urgent dispatches while normal deliveries
   * were backlogged. Edge-triggered — one call when the guard engages,
   * not one per deferred dispatch. The server audits these as
   * `starvation_guard_activated`; library users get the hook directly.
   */
  onStarvationGuardAudit?: (event: StarvationGuardAuditEvent) => void;
  /**
   * Prometheus metrics tuning (see `src/metrics.ts`). Delivery counters
   * (`relay_deliveries_total`) and circuit gauges
   * (`relay_endpoint_circuit_state`) are always collected; the latency
   * histogram needs `latency` enabled too. Served by the operator
   * `GET /metrics` endpoint; `renderMetrics()` renders the exposition text
   * for embedding or testing.
   */
  metrics?: MetricsOptions;
  /**
   * Per-endpoint active/standby failover (see `src/failover.ts`): a
   * record of primary `targetUrl` -> `{ standbys, failureThreshold?,
   * autoFailback?, failbackIntervalMs? }`. When the active target's
   * circuit opens or it fails `failureThreshold` times in a row,
   * dispatches move to the next standby (audited as `failover_switched`,
   * counted in `relay_failover_switches_total`); with `autoFailback`
   * (default) the primary gets a probationary canary once the quiet
   * period passes. In-flight deliveries keep the target they were
   * dispatched with — a switch never cancels or reroutes them. Invalid
   * configs throw `RangeError` at construction.
   */
  failover?: FailoverConfig;
  /**
   * Failover clock in ms; defaults to `Date.now`. Injectable for
   * deterministic tests (drives the failback quiet period).
   */
  failoverNow?: () => number;
  /**
   * Called on every failover switch (to a standby, failback to the
   * primary, or manual reset). Edge-triggered — one call per switch, not
   * one per failed attempt. The server audits these as
   * `failover_switched`; library users get the hook directly.
   */
  onFailoverSwitch?: (event: FailoverSwitchEvent) => void;
  /**
   * Weighted multi-target outbound dispatch (see `src/weighted.ts`),
   * opt-in per endpoint: a record of logical endpoint -> `{ targets: [{
   * targetUrl, weight }], failureThreshold?, recoveryIntervalMs? }`.
   * Every dispatch for a configured endpoint is spread across its
   * physical targets with a smooth weighted round-robin (zero
   * dependencies); only healthy targets join the rotation (circuit
   * breaker state plus the dispatcher's own consecutive-failure counter,
   * so it works with the breaker disabled). When every target is
   * unhealthy the first configured target is pinned and the normal
   * retry / dead-letter machinery owns the outcome. Weights are tunable
   * at runtime through `updateEndpointConfig` (`weighted` patch).
   * Mutually exclusive with `failover` per endpoint: configuring both
   * for the same endpoint throws `RangeError` at construction. Invalid
   * configs throw `RangeError` at construction.
   */
  weighted?: WeightedConfig;
  /**
   * Weighted dispatch clock in ms; defaults to `Date.now`. Injectable
   * for deterministic tests (drives the recovery interval).
   */
  weightedNow?: () => number;
  /**
   * Delivery completion callbacks (WR-47; see `src/callback.ts`). Opt-in:
   * when a delivery reaches a terminal state (`delivered` or
   * `dead_letter`), the relay POSTs a signed receipt (traceId,
   * WR-44-style idempotency key, WR-26-style `x-relay-signature`) to the
   * caller's URL — the active counterpart to the passive
   * `GET /deliveries/:traceId` query. Disabled by default.
   */
  completionCallback?: CompletionCallbackOptions;
  /**
   * Called once when a completion receipt exhausts its attempts
   * (`maxAttempts`, at most 3). The server audits these as
   * `callback_failed`. Receipts never enter the retry queue or the
   * dead-letter list — a failing callback cannot recurse.
   */
  onCompletionCallbackFailed?: (info: CompletionCallbackFailedInfo) => void;
  /**
   * Durable delivery queue (WR-49; see `src/durable-queue.ts`). Opt-in:
   * when set to a directory path, pending and backoff-waiting deliveries
   * plus the dead-letter list are journaled to `<dir>/queue.jsonl`
   * (append-only JSONL, fsync'd per append) and restored on restart —
   * retries resume with their remaining backoff and consumed attempts are
   * preserved. Payloads are sealed with the WR-11 `payloadEncryptor`
   * when one is configured, base64-encoded in the clear otherwise (the
   * same at-rest rule as the dead-letter list). Unset (or empty) means
   * disabled: purely in-memory behavior, exactly as before. A set but
   * invalid value throws `RangeError` at construction; an uncreatable
   * directory throws (fail-fast: crash recovery that cannot write is a
   * misconfiguration, not a degradation).
   */
  durableQueueDir?: string;
  /**
   * Clock (ms epoch) for durable-queue retry resume math; defaults to
   * `Date.now`. Injectable so tests can verify remaining-backoff resume
   * deterministically.
   */
  durableQueueNow?: () => number;
  /**
   * Called once after a journal recovery at construction (only when
   * `durableQueueDir` is set and recovery ran — even when it restored
   * nothing). The server audits this as `queue_restored`.
   */
  onQueueRestored?: (info: QueueRestoredInfo) => void;
  /**
   * Called once per endpoint pause-state transition (see
   * {@link RetryQueue.pauseEndpoint}). Edge-triggered: a pause of an
   * already-paused endpoint is a no-op and does not fire. The server
   * audits transitions as `endpoint_paused` / `endpoint_resumed`;
   * library users get the same hook directly.
   */
  onEndpointPaused?: (info: EndpointPauseInfo) => void;
  /**
   * Called once per endpoint resume transition (see
   * {@link RetryQueue.resumeEndpoint}). Edge-triggered like
   * `onEndpointPaused`.
   */
  onEndpointResumed?: (info: EndpointPauseInfo) => void;
  /**
   * Relay-level cap on concurrent in-flight deliveries *across all
   * endpoints* (see {@link GlobalConcurrencyGate}). Orthogonal to
   * `maxConcurrentPerEndpoint` (WR-06, per endpoint): both gates compose
   * — a dispatch needs a slot from each. When the cap is hit, excess
   * dispatches wait FIFO: never dropped, never burning retry budget,
   * never touching the circuit breaker. The urgent lane bypasses the
   * per-endpoint limiter but not this gate — the cap is relay-level
   * capacity. Default: `Infinity` (unlimited, exactly the pre-WR-51
   * behavior). Must be a positive integer or `Infinity`; anything else
   * throws `RangeError` at construction.
   */
  globalMaxConcurrent?: number;
  /**
   * Per-endpoint delivery time windows ("quiet hours"; WR-52, see
   * `src/delivery-window.ts`): exact `targetUrl` -> window spec
   * (`"HH:MM-HH:MM"` in UTC, e.g. `"09:00-18:00"` for daytime-only
   * deliveries). Opt-in: endpoints without a configured window are always
   * deliverable. A delivery due outside its endpoint's window is parked
   * until the window opens — never dropped, never consuming the retry
   * budget, a quota token, or a circuit-breaker verdict, and never
   * dead-lettered for being out of window. Disabled (undefined) by
   * default: purely backward-compatible. Invalid specs throw `RangeError`
   * at construction. Reachable over HTTP via
   * `opts.retry.deliveryWindow` on the relay server.
   */
  deliveryWindow?: DeliveryWindowOptions;
  /**
   * Timed delivery (WR-57; see `src/scheduled.ts`): clock/timer injection
   * for the deliver_at delay queue. The feature itself is always on — an
   * inbound `x-deliver-at` header parks the delivery until its instant —
   * these options only make the scheduler deterministic in tests.
   * Reachable over HTTP via the `x-deliver-at` request header on the
   * relay server.
   */
  scheduled?: ScheduledQueueOptions;
  /**
   * Dead-letter retention TTL (WR-64; see
   * `src/deadletter-retention.ts`): per-endpoint opt-in TTL in ms —
   * `retentionMs` as a number (every endpoint) or a record of exact
   * `targetUrl` -> TTL (only listed endpoints). A background sweep every
   * `sweepIntervalMs` (default 60s, unref'd) purges entries older than
   * their endpoint's TTL, auditing each as `dead_letter_purged`
   * (id/endpoint/attempts/deadLetteredAt — never the payload) and
   * skipping entries currently claimed by a WR-23 batch replay or the
   * WR-31 auto-replay. Disabled by default: dead letters live until
   * replayed manually. Invalid values throw `RangeError` at
   * construction. Reachable over HTTP via the `deadLetterRetention`
   * server option; stats via `getDeadLetterStats()` /
   * `GET /dead-letter/stats`.
   */
  deadLetterRetention?: DeadLetterRetentionOptions;
  /**
   * Called once per dead-letter entry auto-purged by the retention
   * sweep. The server audits these as `dead_letter_purged`; library
   * users get the hook directly.
   */
  onDeadLetterPurged?: (event: DeadLetterPurgedEvent) => void;
  /**
   * Dead-letter replay egress throttle (WR-68; see
   * `src/replay-egress.ts`). Opt-in per-endpoint RPS cap on the
   * *re-queue* admission of `replayDeadLetters` — manual, operator
   * (`POST /dead-letter/replay`), and WR-31 auto-replay rounds all draw
   * from the same shared bucket, so a big backlog replays at a bounded
   * rate instead of stampeding the downstream. Entries beyond the
   * budget are held back in the dead-letter list (nothing dropped, FIFO
   * preserved) and reported in the batch result's `throttled` field and
   * `getDeadLetterStats().throttled`; the next replay call picks them
   * up. The single-id `replayDeadLetter(id)` escape hatch is not gated.
   * Once re-queued, entries walk the normal path — circuit breaker,
   * quota, weighted dispatch, failover — untouched and independent.
   * Disabled by default (absent = unlimited, exactly the pre-WR-68
   * behavior). A present-but-empty object uses the default
   * `replaysPerSecond` (10). Invalid values throw `RangeError` at
   * construction.
   */
  replayEgress?: ReplayEgressOptions;
  /**
   * Per-endpoint end-to-end delivery deadline (WR-76; see
   * {@link DeliveryDeadlineOptions}): exact `targetUrl` -> ms from queue
   * admission to delivery confirmation. When the deadline expires the
   * item is audited as `delivery_deadline_exceeded` and dead-lettered
   * immediately with its actual attempt count — no further backoff is
   * scheduled and the remaining retry budget is untouched. The expired
   * dead-letter entry carries a normal `deadLetteredAt` timestamp, so it
   * participates in the WR-64 retention sweep like any other dead
   * letter. Disabled by default (absent = no deadline, exactly the
   * pre-WR-76 behavior). Invalid values throw `RangeError` at
   * construction. Reachable over HTTP via `opts.retry.deliveryDeadline`
   * on the relay server.
   */
  deliveryDeadline?: DeliveryDeadlineOptions;
  /**
   * Called once per delivery whose end-to-end deadline expires before
   * delivery. The server audits these as `delivery_deadline_exceeded`;
   * library users get the hook directly.
   */
  onDeliveryDeadlineExceeded?: (info: DeliveryDeadlineExceededInfo) => void;
  /**
   * WR-85: shadow-target dry-run mirroring (see `src/shadow.ts`).
   * Per-endpoint opt-in: exact `targetUrl` -> shadow target list. After
   * every main delivery *attempt* completes (success or failure), the
   * relay asynchronously mirrors the identical wire request (same
   * payload, signature headers, idempotency key, compression encoding —
   * an independent sender copy rebuilds it from the same item with only
   * the `targetUrl` swapped) to each shadow target, for downstream
   * migration / contract verification without touching production
   * traffic. Shadow outcomes are only *observed*: the
   * `onShadowDelivered` / `onShadowFailed` hooks (audited as
   * `shadow_delivered` / `shadow_failed` by the server) and the
   * `relay_shadow_total` metrics counter. A shadow copy never triggers a
   * main retry, never dead-letters, never trips the circuit breaker,
   * never consumes a quota token, and never pollutes the main delivery
   * counters; a shadow failure is silent (recorded, not retried).
   * Disabled by default (absent = zero behavior change). Invalid values
   * throw `RangeError` at construction. Reachable over HTTP via the
   * `shadowTargets` server option.
   */
  shadowTargets?: ShadowTargetsConfig;
  /**
   * Called once per mirrored copy a shadow target answers (transport
   * success). The server audits these as `shadow_delivered`; library
   * users get the hook directly.
   */
  onShadowDelivered?: (info: ShadowDeliveredInfo) => void;
  /**
   * Called once per mirrored copy that fails to reach a shadow target.
   * Silent by design: the failure is recorded (audit + metrics) and
   * never retried, never escalated. The server audits these as
   * `shadow_failed`; library users get the hook directly.
   */
  onShadowFailed?: (info: ShadowFailedInfo) => void;
  /**
   * OTLP/HTTP JSON delivery-event export (WR-83; see `src/otlp.ts`).
   * Opt-in: exports the `delivered` / `retrying` / `dead_letter`
   * delivery events (WR-16) plus `slo_missed` latency events (WR-13) to
   * a configurable collector endpoint as OTLP logs JSON
   * (`Content-Type: application/json`). Sampling is configurable
   * (default 1.0 = everything); export failures are buffered locally
   * (bounded, drop-oldest) and retried on an unref'd background timer,
   * so export can never block or break the delivery path. Disabled by
   * default (absent = zero behavior change). Invalid values throw
   * `RangeError` at construction.
   */
  otlp?: OtlpExporterOptions;
}

/**
 * Fired on an endpoint pause/resume transition (WR-50). Pause is keyed by
 * the logical endpoint (`targetUrl` as enqueued) and applies across
 * tenants — pausing a downstream holds every tenant's deliveries to it.
 */
export interface EndpointPauseInfo {
  /** The paused/resumed endpoint (logical `targetUrl`). */
  endpoint: string;
}

/**
 * Effective hot-reloadable config for one (tenant, endpoint) — the
 * WR-88 config-snapshot read shape. Returned by
 * `RetryQueue.endpointConfig`: `maxConcurrentPerEndpoint` is always the
 * effective value (override or queue default, `Infinity` when unlimited);
 * circuit-breaker/quota rows are present only when the endpoint carries
 * an override; weighted targets only when weighted dispatch is enabled
 * for the endpoint.
 */
export interface EndpointConfigState {
  /** Effective concurrency limit; `Infinity` when unlimited. */
  maxConcurrentPerEndpoint: number;
  /** Effective trip/cooldown thresholds; present only with an override. */
  circuitBreaker?: { failureThreshold: number; cooldownMs: number };
  /** Effective per-minute budget; present only with an override. */
  quota?: { deliveriesPerMinute: number };
  /** Weighted target list; present only when weighted dispatch is on. */
  weighted?: { targets: Array<{ targetUrl: string; weight: number }> };
}

interface Scheduled {
  handle: { clear(): void };
}

const noopSender: Sender = async () => {};

/**
 * Shared validation for concurrency limits: a positive integer, or
 * `Infinity` for "no limit". Used at construction and at runtime
 * (WR-32 hot reload) so both paths enforce the same rule.
 */
function assertConcurrencyLimit(maxConcurrentPerEndpoint: number): void {
  if (
    !(
      maxConcurrentPerEndpoint === Infinity ||
      (Number.isInteger(maxConcurrentPerEndpoint) && maxConcurrentPerEndpoint >= 1)
    )
  ) {
    throw new RangeError(
      `maxConcurrentPerEndpoint must be a positive integer or Infinity, got ${maxConcurrentPerEndpoint}`
    );
  }
}

/**
 * WR-50: shared endpoint-name validation for the pause/resume operator
 * surface — the same fail-fast rule as `updateEndpointConfig`: a
 * non-empty string, never a silent no-op on garbage.
 */
function assertValidPauseEndpoint(endpoint: string, method: string): void {
  if (typeof endpoint !== "string" || endpoint.length === 0) {
    throw new RangeError(`${method}: endpoint must be a non-empty string`);
  }
}

/**
 * WR-48 tenant scope key. The default (tenant-less) scope keys plain
 * endpoints — byte-identical to the pre-tenant relay — while a tenant
 * prefixes its id. (Implementation lives in `src/tenant.ts` so the server
 * can scope its dedup keys the same way.)
 */
/** Map key for a tenant's private instance (`""` = the default tenant). */
function tenantInstanceKey(tenant: string | undefined): string {
  return tenant ?? "";
}

/**
 * The inner per-endpoint map for `tenant` inside a two-level
 * tenant -> endpoint map, creating it on first use. Nested maps keep the
 * endpoint bytes verbatim — no string encoding, so a newline (or any byte)
 * in an endpoint can never corrupt the tenant split.
 */
function innerFor<K, V>(outer: Map<string, Map<K, V>>, tenant: string | undefined): Map<K, V> {
  const k = tenantInstanceKey(tenant);
  let inner = outer.get(k);
  if (inner === undefined) {
    inner = new Map<K, V>();
    outer.set(k, inner);
  }
  return inner;
}

/**
 * Per-endpoint concurrency gate: at most `max` deliveries in flight to the
 * same endpoint (`targetUrl`) at once; excess acquisitions wait in FIFO
 * order. This keeps one slow or rate-limited downstream from being hammered
 * by parallel redeliveries, while other endpoints keep their own budget.
 *
 * Callers must check their own liveness after `acquire()` resolves (the
 * queue may have stopped while they waited) and must always call the
 * returned release function exactly once, even when bailing out — releases
 * cascade to the next waiter, so no one hangs.
 */
export class EndpointConcurrencyLimiter {
  private readonly defaultMax: number;
  /**
   * Per-endpoint runtime overrides (WR-32 hot reload). Endpoints without
   * an override use `defaultMax`.
   */
  private readonly endpointMax = new Map<string, number>();
  private readonly inFlight = new Map<string, number>();
  private readonly waiters = new Map<string, Array<() => void>>();

  constructor(maxConcurrentPerEndpoint: number = Infinity) {
    assertConcurrencyLimit(maxConcurrentPerEndpoint);
    this.defaultMax = maxConcurrentPerEndpoint;
  }

  /** Effective concurrency limit for `endpoint` (override wins over default). */
  maxFor(endpoint: string): number {
    return this.endpointMax.get(endpoint) ?? this.defaultMax;
  }

  /**
   * Endpoints carrying a runtime concurrency-limit override (WR-32).
   * Used by the WR-88 config snapshot to enumerate the configured
   * keyspace.
   */
  configuredEndpoints(): string[] {
    return [...this.endpointMax.keys()];
  }

  /** Whether `endpoint` carries a runtime override. */
  hasEndpointOverride(endpoint: string): boolean {
    return this.endpointMax.has(endpoint);
  }

  /**
   * Drop the runtime override so `endpoint` falls back to the queue
   * default. Used by the WR-88 apply rollback to restore the exact
   * pre-apply override state. Never throws for unknown endpoints.
   */
  clearEndpointOverride(endpoint: string): void {
    this.endpointMax.delete(endpoint);
  }

  /**
   * Override the concurrency limit for one endpoint at runtime.
   * Raising it immediately grants slots to queued waiters in FIFO order;
   * lowering it below the current in-flight count never revokes running
   * deliveries — new acquisitions simply queue until the count drains.
   * Illegal values throw `RangeError` and leave the current limit intact.
   */
  setEndpointMax(endpoint: string, maxConcurrentPerEndpoint: number): void {
    assertConcurrencyLimit(maxConcurrentPerEndpoint);
    this.endpointMax.set(endpoint, maxConcurrentPerEndpoint);
    this.grantWaiting(endpoint);
  }

  /**
   * Resolve when a slot for `endpoint` is free. Always call the returned
   * function exactly once to hand the slot on.
   */
  acquire(endpoint: string): Promise<() => void> {
    const n = this.inFlight.get(endpoint) ?? 0;
    if (n < this.maxFor(endpoint)) {
      this.inFlight.set(endpoint, n + 1);
      return Promise.resolve(() => this.release(endpoint));
    }
    return new Promise<() => void>((resolve) => {
      const wake = (): void => {
        // Slot transfers from the releaser to this waiter; the in-flight
        // count is unchanged (no increment here).
        resolve(() => this.release(endpoint));
      };
      const q = this.waiters.get(endpoint);
      if (q) q.push(wake);
      else this.waiters.set(endpoint, [wake]);
    });
  }

  /** Hand newly-freed headroom to queued waiters after a limit raise. */
  private grantWaiting(endpoint: string): void {
    const max = this.maxFor(endpoint);
    let n = this.inFlight.get(endpoint) ?? 0;
    const q = this.waiters.get(endpoint);
    while (q && q.length > 0 && n < max) {
      n += 1;
      this.inFlight.set(endpoint, n);
      const wake = q.shift()!;
      if (q.length === 0) this.waiters.delete(endpoint);
      wake(); // transfers the newly-created slot; count already incremented
    }
  }

  private release(endpoint: string): void {
    const q = this.waiters.get(endpoint);
    const next = q?.shift();
    if (q && q.length === 0) this.waiters.delete(endpoint);
    if (next) {
      next(); // slot transfers to the waiter; in-flight count unchanged
      return;
    }
    const n = (this.inFlight.get(endpoint) ?? 1) - 1;
    if (n <= 0) this.inFlight.delete(endpoint);
    else this.inFlight.set(endpoint, n);
  }

  /** Current in-flight delivery count for `endpoint`. */
  inFlightCount(endpoint: string): number {
    return this.inFlight.get(endpoint) ?? 0;
  }

  /** Deliveries currently queued waiting for a slot on `endpoint`. */
  queuedCount(endpoint: string): number {
    return this.waiters.get(endpoint)?.length ?? 0;
  }

  /** Snapshot of every endpoint with in-flight or queued deliveries. */
  stats(): Array<{ endpoint: string; inFlight: number; queued: number }> {
    const endpoints = new Set([...this.inFlight.keys(), ...this.waiters.keys()]);
    return [...endpoints].map((endpoint) => ({
      endpoint,
      inFlight: this.inFlightCount(endpoint),
      queued: this.queuedCount(endpoint),
    }));
  }
}

/**
 * Per-endpoint token bucket guarding the urgent lane: `ratePerSecond`
 * tokens refill every second, and the bucket holds at most one second of
 * tokens (burst == rate). Refills lazily on each `take`, so idle endpoints
 * cost nothing. A monotonic-ish clock is assumed; backward jumps are
 * clamped to zero refill rather than granting extra tokens.
 */
export class UrgentRateLimiter {
  private readonly ratePerSecond: number;
  private readonly buckets = new Map<string, { tokens: number; updatedMs: number }>();
  private readonly now: () => number;

  constructor(ratePerSecond: number, now: () => number = Date.now) {
    if (!Number.isFinite(ratePerSecond) || ratePerSecond <= 0) {
      throw new RangeError(`maxUrgentPerSecond must be > 0, got ${ratePerSecond}`);
    }
    this.ratePerSecond = ratePerSecond;
    this.now = now;
  }

  /**
   * Consume one token for `endpoint`. Returns false when the bucket is
   * empty — the caller should degrade to the normal lane, never drop.
   */
  take(endpoint: string): boolean {
    const at = this.now();
    let b = this.buckets.get(endpoint);
    if (!b) {
      b = { tokens: this.ratePerSecond, updatedMs: at };
      this.buckets.set(endpoint, b);
    } else {
      const elapsedMs = Math.max(0, at - b.updatedMs);
      b.tokens = Math.min(this.ratePerSecond, b.tokens + (elapsedMs * this.ratePerSecond) / 1000);
      b.updatedMs = at;
    }
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  }

  /** Tokens currently available for `endpoint` (0 when the endpoint is unknown). */
  available(endpoint: string): number {
    return this.buckets.get(endpoint)?.tokens ?? 0;
  }
}

/** Per-endpoint fast-lane counters. */
export interface UrgentStats {
  endpoint: string;
  /** Urgent deliveries that succeeded on the fast lane. */
  delivered: number;
  /** Retries scheduled on the fast lane (fixed delay, no backoff). */
  retried: number;
  /** Urgent attempts that found an empty bucket and degraded to the normal lane. */
  throttled: number;
}

/**
 * Fired once per starvation-guard activation episode: the deficit
 * round-robin scheduler (WR-35, see {@link LaneScheduler}) started
 * deferring urgent dispatches because normal deliveries were backlogged
 * for a dispatch slot. Edge-triggered — a sustained flood produces one
 * event when the guard engages, not one per deferred dispatch (the same
 * transition-auditing convention as the circuit breaker). The server
 * audits these as `starvation_guard_activated`; library users get the
 * hook directly.
 */
export interface StarvationGuardAuditEvent {
  event: "starvation_guard_activated";
  /** The endpoint whose lanes the guard rebalanced. */
  endpoint: string;
  /** Normal deliveries waiting for a dispatch slot when the guard engaged. */
  waitingNormal: number;
  /** Urgent deliveries parked by the guard when it engaged. */
  waitingUrgent: number;
  /** Effective minimum normal share of dispatch turns, in (0, 1). */
  minNormalShare: number;
}

/** Per-endpoint lane-scheduler counters (WR-35 starvation guard). */
export interface LaneStats {
  endpoint: string;
  /** Effective minimum normal share of dispatch turns, in (0, 1). */
  minNormalShare: number;
  /** Dispatch turns granted to the normal lane. */
  normalTurns: number;
  /** Dispatch turns granted to the urgent lane. */
  urgentTurns: number;
  /** Guard activation episodes (urgent deferred while normal was backlogged). */
  guardActivations: number;
}

/** A delivery lane for the deficit round-robin dispatch scheduler. */
export type Lane = "normal" | "urgent";

/** Shared validation for the starvation-guard share: the open interval (0, 1). */
function assertMinNormalShare(minNormalShare: number): void {
  if (!Number.isFinite(minNormalShare) || minNormalShare <= 0 || minNormalShare >= 1) {
    throw new RangeError(`minNormalShare must be in the open interval (0, 1), got ${minNormalShare}`);
  }
}

/** Options for {@link LaneScheduler}. */
export interface LaneSchedulerOptions {
  /**
   * Default minimum normal share of dispatch turns, in (0, 1).
   * Default: 0.2. Invalid values throw `RangeError`.
   */
  minNormalShare?: number;
  /** Called once per guard-activation episode (edge-triggered). */
  onActivation?: (event: StarvationGuardAuditEvent) => void;
}

interface LaneEndpointState {
  minNormalShare: number;
  /** Earned-but-unspent urgent dispatch turns. */
  deficitUrgent: number;
  /** Parked urgent turn requests, FIFO. */
  waitersUrgent: Array<() => void>;
  /**
   * Normal turns granted but not yet recorded as dispatched. Covers the
   * handoff between the concurrency limiter granting a slot and the
   * dispatch actually starting: without it the backlog probe would see a
   * transient zero (the successor was shifted out of the limiter queue
   * but hasn't dispatched yet) and work-conservingly release every parked
   * urgent turn one dispatch early. Actively dispatching (in-flight)
   * normals are *not* counted — only waiting or imminent demand.
   */
  undispatchedNormal: Set<symbol>;
  /** Whether urgent is currently being deferred (episode latch). */
  guardActive: boolean;
  activations: number;
  turnsNormal: number;
  turnsUrgent: number;
}

/**
 * Deficit round-robin lane gate (WR-35): starvation protection for the
 * normal lane while the urgent fast lane (WR-12) is under load.
 *
 * Both lanes take a dispatch turn here before invoking the sender. The
 * normal lane is *never* delayed by the gate — its waits stay exactly the
 * ones it already had (concurrency limiter, quota, circuit, backoff). The
 * urgent lane is granted immediately whenever no normal demand is
 * backlogged (work-conserving: a lone lane is never throttled). While
 * normal deliveries are backlogged for a dispatch slot, every normal
 * *dispatch* (see {@link LaneScheduler.recordNormalDispatch}) earns the
 * urgent lane `(1 - minNormalShare) / minNormalShare` turns of deficit,
 * and urgent turns are granted FIFO only while deficit allows — so over
 * any sustained contention window the normal lane keeps at least
 * `minNormalShare` of dispatch turns.
 *
 * The gate is ordering-only: it never sheds a delivery, never burns an
 * urgent token-bucket token, and never consumes retry budget — it composes
 * with the WR-12 `UrgentRateLimiter` without double rate-limiting (the
 * bucket still bounds the urgent *rate*; the gate only paces the urgent
 * *share* while normal is backlogged). Deficit accrues only while urgent
 * demand is actually backlogged (no retroactive credit for idle periods,
 * per classic DRR), and resets when the normal backlog drains.
 */
export class LaneScheduler {
  private readonly defaultShare: number;
  private readonly onActivation?: (event: StarvationGuardAuditEvent) => void;
  private readonly states = new Map<string, LaneEndpointState>();

  constructor(opts: LaneSchedulerOptions = {}) {
    const share = opts.minNormalShare ?? 0.2;
    assertMinNormalShare(share);
    this.defaultShare = share;
    this.onActivation = opts.onActivation;
  }

  private stateFor(endpoint: string): LaneEndpointState {
    let st = this.states.get(endpoint);
    if (!st) {
      st = {
        minNormalShare: this.defaultShare,
        deficitUrgent: 0,
        waitersUrgent: [],
        undispatchedNormal: new Set(),
        guardActive: false,
        activations: 0,
        turnsNormal: 0,
        turnsUrgent: 0,
      };
      this.states.set(endpoint, st);
    }
    return st;
  }

  /** Effective minimum normal share for `endpoint` (override wins over default). */
  shareFor(endpoint: string): number {
    return this.stateFor(endpoint).minNormalShare;
  }

  /**
   * Override the minimum normal share for one endpoint at runtime.
   * Invalid values throw `RangeError` and leave the current share intact.
   */
  setEndpointMinNormalShare(endpoint: string, minNormalShare: number): void {
    assertMinNormalShare(minNormalShare);
    this.stateFor(endpoint).minNormalShare = minNormalShare;
    this.pump(endpoint);
  }

  /**
   * Normal demand visible to the scheduler: turns granted but not yet
   * recorded as dispatched. Because the queue takes the turn *before* the
   * concurrency limiter, this set is exactly the waiting set — the
   * limiter's FIFO, the limiter-to-dispatch handoff, everything short of
   * the sender invocation. Actively dispatching (in-flight) normals are
   * not demand — they're being served.
   */
  private backlogOf(st: LaneEndpointState): number {
    return st.undispatchedNormal.size;
  }

  /**
   * Take a dispatch turn for `lane` on `endpoint`. Resolves with a release
   * function the caller must invoke exactly once when the dispatch
   * settles — releasing re-runs the scheduler, so parked urgent turns may
   * become affordable and a drained normal backlog releases them all.
   *
   * The normal lane is never delayed here: its waits stay exactly the ones
   * it already had (concurrency limiter, quota, circuit, backoff). A
   * granted normal turn is tracked as undispatched until
   * {@link LaneScheduler.recordNormalDispatch} runs, so the handoff never
   * looks like a drained backlog.
   */
  acquireTurn(endpoint: string, lane: Lane): Promise<() => void> {
    const st = this.stateFor(endpoint);
    if (lane === "normal") {
      st.turnsNormal += 1;
      const token = Symbol();
      st.undispatchedNormal.add(token);
      this.pump(endpoint);
      return Promise.resolve(() => {
        // Idempotent: a turn whose dispatch was recorded was already
        // removed from the undispatched set there.
        st.undispatchedNormal.delete(token);
        this.releaseTurn(endpoint);
      });
    }
    return new Promise<() => void>((resolve) => {
      st.waitersUrgent.push(() => resolve(() => this.releaseTurn(endpoint)));
      this.pump(endpoint);
    });
  }

  /**
   * Record that a normal dispatch is starting (called after the limiter
   * granted its slot and the liveness check passed, right before the
   * sender is invoked). Each dispatch earns the urgent lane
   * `(1 - minNormalShare) / minNormalShare` turns of deficit — but only
   * while urgent demand is actually backlogged (classic DRR grants quantum
   * to backlogged flows only; idle periods earn no retroactive credit).
   *
   * The pump runs *before* this dispatch leaves the undispatched set, so
   * a successor shifted out of the limiter queue mid-handoff still counts
   * as backlogged demand instead of triggering a work-conserving release.
   */
  recordNormalDispatch(endpoint: string): void {
    const st = this.stateFor(endpoint);
    if (st.waitersUrgent.length > 0) {
      st.deficitUrgent += (1 - st.minNormalShare) / st.minNormalShare;
    }
    this.pump(endpoint);
    // Normal dispatches leave the limiter in FIFO order, matching
    // turn-grant order, so the oldest undispatched turn is this dispatch's.
    // (Only the set's size feeds the backlog probe; order is bookkeeping.)
    const oldest = st.undispatchedNormal.values().next().value;
    if (oldest !== undefined) st.undispatchedNormal.delete(oldest);
  }

  /** Release a dispatch turn; re-runs the scheduler for the endpoint. */
  private releaseTurn(endpoint: string): void {
    // The turn carries no capacity — releasing only re-runs the
    // scheduler, so a drained normal backlog work-conservingly releases
    // parked urgent turns.
    this.pump(endpoint);
  }

  private pump(endpoint: string): void {
    const st = this.states.get(endpoint);
    if (!st) return;
    const backlog = this.backlogOf(st);
    if (backlog === 0) {
      // Work-conserving: no normal demand — every parked urgent turn goes
      // immediately, and earned deficit resets (no credit is carried
      // across idle periods).
      const waiting = st.waitersUrgent.splice(0);
      st.deficitUrgent = 0;
      st.turnsUrgent += waiting.length;
      for (const grant of waiting) grant();
      st.guardActive = false;
      return;
    }
    // Contention: serve affordable urgent turns FIFO.
    while (st.waitersUrgent.length > 0 && st.deficitUrgent >= 1) {
      const grant = st.waitersUrgent.shift()!;
      st.deficitUrgent -= 1;
      st.turnsUrgent += 1;
      grant();
    }
    if (st.waitersUrgent.length > 0) {
      // Urgent dispatches are being deferred while normal demand is
      // backlogged: the guard is engaged. Edge-triggered — one activation
      // per episode, not one per deferred dispatch.
      if (!st.guardActive) {
        st.guardActive = true;
        st.activations += 1;
        this.onActivation?.({
          event: "starvation_guard_activated",
          endpoint,
          waitingNormal: backlog,
          waitingUrgent: st.waitersUrgent.length,
          minNormalShare: st.minNormalShare,
        });
      }
    } else {
      st.guardActive = false;
    }
  }

  /** Per-endpoint lane counters, in first-seen endpoint order. */
  stats(): LaneStats[] {
    return [...this.states.entries()].map(([endpoint, st]) => ({
      endpoint,
      minNormalShare: st.minNormalShare,
      normalTurns: st.turnsNormal,
      urgentTurns: st.turnsUrgent,
      guardActivations: st.activations,
    }));
  }
}

/**
 * RetryQueue holds outbound deliveries and retries them with exponential
 * backoff + jitter. Items that exhaust `maxAttempts` are moved to an
 * in-memory dead-letter list for later inspection.
 */
export class RetryQueue {
  private readonly sender: Sender;
  /**
   * Backoff parameters are deliberately *not* readonly: WR-32 hot reload
   * retunes them at runtime. `delayForAttempt` reads them at schedule
   * time, so retries scheduled before an update keep their old delay and
   * only future scheduling sees the new values.
   */
  private baseDelayMs: number;
  private maxDelayMs: number;
  private maxAttempts: number;
  private jitterMs: number;
  private jitterStrategy: JitterStrategy;
  private readonly random: () => number;
  private readonly setTimer: (fn: () => void, ms: number) => { clear(): void };
  private readonly clearTimer: (handle: { clear(): void }) => void;
  private readonly onDeadLetter?: (
    item: RetryItem,
    attempts: number,
    lastError: unknown,
    failureClass?: FailureClass,
    summary?: DownstreamResponseSummary
  ) => void;
  private readonly onDelivered?: (
    item: RetryItem,
    attempts: number,
    summary?: DownstreamResponseSummary
  ) => void;
  /**
   * WR-48: per-tenant circuit breaker instances, keyed by tenant
   * (`""` = the default tenant). One tenant's downstream outage trips
   * only its own breaker — another tenant's deliveries to the same
   * endpoint keep flowing. Lazily created so a tenant that never appears
   * costs nothing.
   */
  private readonly breakers = new Map<string, EndpointCircuitBreaker>();
  private readonly circuitBreakerOpts?: CircuitBreakerOptions;
  private readonly circuitBreakerOnStateChange?: (
    endpoint: string,
    from: CircuitState,
    to: CircuitState,
    tenant?: string
  ) => void;
  private readonly onConfigChange?: (endpoint: string, changes: ConfigChange[]) => void;
  /** WR-50: operator pause/resume transition hooks (audited by the server). */
  private readonly onEndpointPaused?: (info: EndpointPauseInfo) => void;
  private readonly onEndpointResumed?: (info: EndpointPauseInfo) => void;
  /**
   * WR-50: operator pause set, keyed by logical endpoint (`targetUrl` as
   * enqueued). A paused endpoint's deliveries are parked: they stay
   * queued with their attempt counts intact, no delivery attempt is
   * scheduled, no retry budget is consumed, the circuit breaker is not
   * touched, and nothing moves to dead-letter. Orthogonal to the WR-10
   * circuit: pausing never changes breaker state, and breaker
   * transitions never unpause.
   */
  private readonly pausedEndpoints = new Set<string>();
  /**
   * WR-50: parked deliveries — item id → absolute next-dispatch time
   * (ms epoch). An item lands here instead of getting a timer when
   * `schedule()` runs for a paused endpoint, when `pauseEndpoint`
   * disarms an armed timer, or when `deliver()` bails on a mid-wait
   * pause. `resumeEndpoint` re-arms each entry with its remaining delay
   * (`nextAt - now`, floored at 0), so a backoff window interrupted by
   * the pause continues instead of restarting — and attempt counts are
   * never reset. Parked timing is in-memory only: a restart resumes
   * parked items promptly (attempt counts survive via the WR-49
   * journal; the remaining backoff does not).
   */
  private readonly parked = new Map<string, number>();
  /**
   * WR-50: absolute fire time (ms epoch) of every armed retry timer.
   * Lets `pauseEndpoint` park an in-backoff item with its *remaining*
   * delay instead of restarting the backoff on resume. Maintained
   * alongside `timers`; entries for settled items are dropped where the
   * queue entry is dropped.
   */
  private readonly armedNextAt = new Map<string, number>();
  /** Attempts parked because the endpoint's circuit was open. */
  private circuitBlocked = 0;
  private readonly payloadEncryptor?: PayloadEncryptor;
  /** WR-54: opt-in sealed response-body capture on `delivered` audit events. */
  private readonly responseBodyCapture: boolean;
  /** WR-72: field-level masking for captured response bodies. */
  private readonly fieldMask?: FieldMask;
  private readonly urgentRetryDelayMs: number;
  private readonly urgentLimiter: UrgentRateLimiter;
  private readonly urgentStats = new Map<string, { delivered: number; retried: number; throttled: number }>();
  /**
   * Deficit round-robin lane gate (WR-35): paces urgent dispatches while
   * normal deliveries are backlogged, guaranteeing the normal lane its
   * `minNormalShare` of dispatch turns. Ordering-only — never a second
   * rate limit on top of the urgent token bucket.
   */
  private readonly laneScheduler: LaneScheduler;
  private readonly onStarvationGuardAudit?: (event: StarvationGuardAuditEvent) => void;
  /**
   * WR-48: per-tenant latency trackers, keyed by tenant (`""` = default).
   * Accepted→delivered latency is sampled per (tenant, endpoint) so one
   * tenant's slow downstream does not pollute another's SLO picture.
   */
  private readonly latencies = new Map<string, LatencyTracker>();
  private readonly latencyOpts?: LatencyOptions;
  private readonly onSloMiss?: (info: SloMissInfo) => void;
  /**
   * WR-71: per-tenant SLO-breach predictors, keyed by tenant (`""` =
   * default) — mirrors `latencies` above.
   */
  private readonly sloRisks = new Map<string, SloRiskPredictor>();
  private readonly sloRiskOpts?: SloRiskOptions;
  private readonly onSloRisk?: (info: SloRiskInfo) => void;
  /**
   * WR-71: per-(tenant, endpoint) pending deliveries (queued + in-flight
   * + backoff-waiting), keyed by tenant instance key then logical
   * `targetUrl`. Maintained alongside `queue` so the predictor can read
   * the backlog in O(1) instead of scanning the queue per observation.
   */
  private readonly pendingByEndpoint = new Map<string, Map<string, number>>();
  /**
   * WR-48: per-tenant quota instances, keyed by tenant (`""` = default).
   * Each tenant gets its own per-endpoint delivery budget.
   */
  private readonly quotas = new Map<string, EndpointQuota>();
  private readonly quotaDeliveriesPerMinute?: number;
  private readonly quotaNow: () => number;
  /** Attempts rescheduled because the endpoint's quota bucket was empty. Keyed by scoped key (WR-48). */
  private readonly quotaStats = new Map<string, Map<string, number>>();
  /**
   * WR-52: per-endpoint delivery time windows ("quiet hours"). Shared
   * across tenants like the WR-50 pause switch — the window is a property
   * of the downstream, not of the sender.
   */
  private readonly deliveryWindow?: EndpointDeliveryWindow;
  /**
   * WR-57: the deliver_at delay queue. Always available (the header is a
   * per-request contract); `opts.scheduled` only injects the clock and
   * timers for deterministic tests. Starts disarmed; `start()` arms it.
   */
  private readonly scheduler: ScheduledDeliveryQueue;
  private readonly scheduledNow: () => number;
  /** Attempts parked outside an endpoint's delivery window. Keyed by scoped key (WR-48). */
  private readonly deliveryWindowStats = new Map<string, Map<string, number>>();
  /** WR-76: per-endpoint delivery deadline in ms (exact logical `targetUrl` match); undefined when disabled. */
  private readonly deliveryDeadlines?: Map<string, number>;
  /** WR-76: clock for the deadline; defaults to `Date.now`. Injectable for deterministic tests. */
  private readonly deadlineNow: () => number;
  private readonly onDeliveryDeadlineExceeded?: (info: DeliveryDeadlineExceededInfo) => void;
  /** WR-80: cron occurrence audit hook. */
  private readonly onScheduledFired?: (event: ScheduledFiredEvent) => void;
  /** WR-76: cumulative deadline expirations per (tenant, endpoint) — see `src/metrics.ts`. */
  private readonly deliveryDeadlineExceeded = new Map<string, Map<string, number>>();
  /**
   * WR-37: per-endpoint response semantic validators (exact `targetUrl`
   * match) plus an optional global fallback. Validators run after a 2xx
   * transport success; a failing verdict becomes a `SemanticDeliveryError`
   * and follows the normal retry / dead-letter / circuit path.
   */
  private readonly endpointResponseValidators = new Map<string, ResponseValidator>();
  private readonly globalResponseValidator?: ResponseValidator;
  private readonly onSemanticFailure?: (info: SemanticFailureInfo) => void;
  /** WR-38: global retry budget; undefined when disabled. */
  private readonly retryBudget?: RetryBudget;
  /** WR-59: adaptive backoff options; undefined when disabled. */
  private readonly adaptiveBackoffOpts?: AdaptiveBackoffOptions;
  /** WR-59: per-tenant adaptive backoff controllers (WR-48 scoping). */
  private readonly adaptiveBackoffs = new Map<string, AdaptiveBackoffController>();
  private readonly onRetryBudgetDepleted?: (info: RetryBudgetDepletedInfo) => void;
  private readonly onAttemptFailed?: (info: AttemptFailedInfo) => void;
  /** Retries parked because the global retry budget was exhausted. */
  private retryBudgetDepleted = 0;
  private readonly batcher?: BatchCollector;
  private readonly batchResolved?: ResolvedBatchOptions;
  private readonly onBatch?: (info: BatchInfo) => void;
  /** Per-endpoint flushed-batch counters. */
  private readonly batchStats = new Map<string, { batches: number; events: number }>();
  /** Prometheus delivery counters per (tenant, endpoint) — see `src/metrics.ts`. Outer key is the tenant (`""` = default), inner key the plain endpoint. */
  private readonly deliveryCounters = new Map<
    string,
    Map<string, { delivered: number; failed: number; retried: number; deadLetter: number }>
  >();
  /** Last observed circuit state per (tenant, endpoint) — only endpoints that tripped. */
  private readonly circuitStates = new Map<string, Map<string, "closed" | "half_open" | "open">>();
  /** Histogram bucket upper bounds in ms (validated ascending). */
  private readonly histBucketsMs: number[];
  /** Per-endpoint latency histogram: per-bucket individual counts + sum. */
  private readonly latencyHist = new Map<
    string,
    Map<string, { counts: number[]; sumMs: number; count: number }>
  >();
  private readonly deliveryEventListeners = new Set<(e: DeliveryEvent) => void>();
  /** Opt-in dead-letter auto-replay scheduler; undefined when disabled. */
  private readonly autoReplayer?: DeadLetterAutoReplayer;
  /** WR-64: opt-in dead-letter retention sweeper; undefined when disabled. */
  private readonly retentionSweeper?: DeadLetterRetentionSweeper;
  /**
   * Dead-letter ids currently claimed by a replay operation (WR-23
   * batch replay, including the WR-31 auto-replay, which runs through
   * the same batch replay), with claim counts. The retention sweep
   * skips claimed ids so a purge never deletes an entry out from under
   * an in-progress replay. Counted because a batch replay claims every
   * matched id for its whole run while the per-entry replay inside it
   * claims/releases its own id — the batch-level claim must survive the
   * inner release.
   */
  private readonly deadLetterReplayInFlight = new Map<string, number>();

  /** Claim a dead-letter id against retention purges (ref-counted). */
  private claimReplay(id: string): void {
    this.deadLetterReplayInFlight.set(id, (this.deadLetterReplayInFlight.get(id) ?? 0) + 1);
  }

  /** Release one replay claim on a dead-letter id. */
  private releaseReplay(id: string): void {
    const n = (this.deadLetterReplayInFlight.get(id) ?? 1) - 1;
    if (n <= 0) this.deadLetterReplayInFlight.delete(id);
    else this.deadLetterReplayInFlight.set(id, n);
  }

  /** Whether any replay operation currently claims the id. */
  private isClaimedByReplay(id: string): boolean {
    return this.deadLetterReplayInFlight.has(id);
  }
  /** Entries auto-purged by the retention sweep since construction. */
  private deadLetterPurged = 0;
  private readonly onDeadLetterPurged?: (event: DeadLetterPurgedEvent) => void;
  /** WR-68: shared replay egress gate; undefined when not configured. */
  private readonly replayEgress?: ReplayEgressGate;
  /** WR-68: cumulative entries held back by the egress gate. */
  private replayEgressThrottled = 0;
  private readonly prober?: DownstreamProber;
  /** WR-83: OTLP delivery-event exporter; undefined when not configured. */
  private readonly otlpExporter?: OtlpExporter;
  /**
   * WR-85: shadow-target dry-run mirroring dispatcher; undefined when
   * `shadowTargets` is unset (zero behavior change).
   */
  private readonly shadow?: ShadowDispatcher;
  /** WR-39: active/standby target selection; undefined when not configured. */
  private readonly failover?: FailoverManager;
  private readonly onFailoverSwitch?: (event: FailoverSwitchEvent) => void;
  /** `relay_failover_switches_total`, one counter per (endpoint, from, to). */
  private readonly failoverSwitchCounts = new Map<
    string,
    { endpoint: string; from: string; to: string; switches: number }
  >();
  /** WR-66: smooth weighted round-robin routing; undefined when not configured. */
  private readonly weighted?: WeightedDispatcher;
  /** WR-47: completion-receipt sender; undefined when the feature is off. */
  private readonly callbacker?: CompletionCallbacker;

  private readonly queue = new Map<string, RetryItem & { attempt: number }>();
  private readonly timers = new Map<string, Scheduled>();
  private readonly deadLetter: DeadLetterEntry[] = [];
  /**
   * WR-49: opt-in durable queue journal (undefined when
   * `durableQueueDir` is unset). Every state transition with a
   * crash-recovery meaning — enqueue, retry armed, delivered,
   * dead-lettered, replayed — is journaled before the in-memory
   * mutation, so a crash between the two can only redeliver
   * (at-least-once), never lose.
   */
  private readonly durable?: QueueJournal;
  private readonly durableDir?: string;
  private readonly durableNow: () => number;
  /**
   * Armed retry fire-times per item (ms epoch), tracked so compaction
   * can rewrite truthful `retry` lines. Cleared when the timer fires,
   * when the item leaves the queue, and when timers are dropped
   * (`stop()`/`shutdown()`).
   */
  private readonly durablePendingRetry = new Map<string, number>();
  /**
   * Pending-retry fire-times recovered from the journal, consumed once by
   * the first `start()` so restored retries resume with their remaining
   * backoff instead of firing immediately.
   */
  private readonly restoredNextAt = new Map<string, number>();
  private durableRestoredItems = 0;
  private durableRestoredDeadLetters = 0;
  private durableSkippedLines = 0;
  /**
   * WR-48: per-tenant concurrency limiters, keyed by tenant (`""` =
   * default). Each tenant gets its own per-endpoint in-flight budget, so
   * one tenant's slow downstream cannot starve another's deliveries.
   */
  private readonly limiters = new Map<string, EndpointConcurrencyLimiter>();
  private readonly maxConcurrentPerEndpoint: number;
  /**
   * WR-51: relay-level global dispatch gate (one instance — the cap is
   * relay-wide, across endpoints and tenants). Always constructed; with
   * the default `Infinity` cap every acquisition grants immediately, so
   * unconfigured behavior is byte-for-byte the pre-WR-51 behavior.
   */
  private readonly globalGate: GlobalConcurrencyGate;
  private readonly globalMaxConcurrent: number;
  /** Deliveries currently executing (inside `deliver()`), for graceful drain. */
  private readonly inFlight = new Set<Promise<void>>();
  private running = false;

  constructor(opts: RetryQueueOptions = {}) {
    this.sender = opts.sender ?? noopSender;
    this.baseDelayMs = opts.baseDelayMs ?? 1000;
    this.maxDelayMs = opts.maxDelayMs ?? 60000;
    this.maxAttempts = opts.maxAttempts ?? 5;
    this.jitterMs = opts.jitterMs ?? 100;
    this.jitterStrategy = opts.jitterStrategy ?? "additive";
    this.random = opts.random ?? Math.random;
    if (!Number.isFinite(this.baseDelayMs) || this.baseDelayMs <= 0) {
      throw new RangeError(`baseDelayMs must be > 0, got ${this.baseDelayMs}`);
    }
    if (!Number.isFinite(this.maxDelayMs) || this.maxDelayMs <= 0) {
      throw new RangeError(`maxDelayMs must be > 0, got ${this.maxDelayMs}`);
    }
    if (!Number.isInteger(this.maxAttempts) || this.maxAttempts < 1) {
      throw new RangeError(`maxAttempts must be an integer >= 1, got ${this.maxAttempts}`);
    }
    if (!Number.isFinite(this.jitterMs) || this.jitterMs < 0) {
      throw new RangeError(`jitterMs must be >= 0, got ${this.jitterMs}`);
    }
    if (this.jitterStrategy !== "additive" && this.jitterStrategy !== "full") {
      throw new RangeError(`jitterStrategy must be "additive" or "full", got ${this.jitterStrategy}`);
    }
    this.setTimer =
      opts.setTimer ?? ((fn, ms) => {
        const t = setTimeout(fn, ms);
        return { clear: () => clearTimeout(t) };
      });
    this.clearTimer = opts.clearTimer ?? ((h) => h.clear());
    this.onDeadLetter = opts.onDeadLetter;
    this.onDeadLetterPurged = opts.onDeadLetterPurged;
    this.onDelivered = opts.onDelivered;
    this.onConfigChange = opts.onConfigChange;
    this.onEndpointPaused = opts.onEndpointPaused;
    this.onEndpointResumed = opts.onEndpointResumed;
    // WR-48: the limiter is per-tenant now; instances are created lazily
    // by `limiterFor()` so tenants that never appear cost nothing. The
    // limit itself is still validated eagerly, at construction.
    this.maxConcurrentPerEndpoint = opts.maxConcurrentPerEndpoint ?? Infinity;
    assertConcurrencyLimit(this.maxConcurrentPerEndpoint);
    // WR-51: invalid values throw here, at construction — never mid-delivery.
    this.globalMaxConcurrent = opts.globalMaxConcurrent ?? Infinity;
    this.globalGate = new GlobalConcurrencyGate(this.globalMaxConcurrent);
    // WR-52: invalid window specs throw here, at construction — an invalid
    // quiet-hours config is a misconfiguration, never a runtime surprise.
    if (opts.deliveryWindow !== undefined) {
      this.deliveryWindow = new EndpointDeliveryWindow(opts.deliveryWindow);
    }
    // WR-76: invalid deadlines throw here, at construction — a typo must
    // not silently leave an endpoint without its SLO. `undefined` (no
    // deadlines) keeps the exact pre-WR-76 behavior.
    if (opts.deliveryDeadline?.deadlines !== undefined) {
      const deadlines = new Map<string, number>();
      const raw = opts.deliveryDeadline.deadlines;
      if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
        throw new RangeError("deliveryDeadline.deadlines must be a record of targetUrl -> ms");
      }
      for (const [endpoint, ms] of Object.entries(raw)) {
        if (endpoint.length === 0) {
          throw new RangeError("deliveryDeadline.deadlines keys must be non-empty endpoint URLs");
        }
        if (typeof ms !== "number" || !Number.isFinite(ms) || ms <= 0) {
          throw new RangeError(
            `deliveryDeadline.deadlines[${JSON.stringify(endpoint)}] must be a finite number > 0, got ${String(ms)}`
          );
        }
        deadlines.set(endpoint, ms);
      }
      this.deliveryDeadlines = deadlines;
    }
    this.deadlineNow = opts.deliveryDeadline?.now ?? Date.now;
    this.onDeliveryDeadlineExceeded = opts.onDeliveryDeadlineExceeded;
    // WR-80: cron occurrence audit hook (the server wires it to its audit log).
    // WR-85: opt-in shadow-target dry-run mirroring. The dispatcher
    // validates eagerly — `RangeError` at construction, never
    // mid-delivery. Absent = the relay behaves exactly as before: no
    // mirror calls, no shadow metrics series, no audit events.
    this.shadow =
      opts.shadowTargets !== undefined
        ? new ShadowDispatcher(opts.shadowTargets, {
            sender: this.sender,
            onDelivered: opts.onShadowDelivered,
            onFailed: opts.onShadowFailed,
          })
        : undefined;
    this.onScheduledFired = opts.onScheduledFired;
    // WR-57: the deliver_at delay queue is always on; the option only
    // injects clock/timers (the module validates their shapes).
    this.scheduledNow = opts.scheduled?.now ?? Date.now;
    this.scheduler = new ScheduledDeliveryQueue({
      now: this.scheduledNow,
      setTimer: opts.scheduled?.setTimer,
      clearTimer: opts.scheduled?.clearTimer,
      onDue: (items) => this.releaseScheduled(items),
    });
    // Wrap the caller's state-change hook so the metrics gauge always sees
    // the latest circuit state, even when nobody subscribes to the hook.
    // The wrapper is installed per tenant instance in `breakerFor()`.
    this.circuitBreakerOpts = opts.circuitBreaker;
    this.circuitBreakerOnStateChange = opts.onCircuitStateChange ?? opts.circuitBreaker?.onStateChange;
    this.payloadEncryptor = opts.payloadEncryptor;
    // WR-54: fail-fast — capturing response bodies without an encryptor
    // would log them in the clear; refuse at construction, never
    // mid-delivery.
    this.responseBodyCapture = opts.responseBodyCapture ?? false;
    this.fieldMask = opts.fieldMask;
    if (this.responseBodyCapture && this.payloadEncryptor === undefined) {
      throw new RangeError(
        "responseBodyCapture requires a payloadEncryptor: refusing to audit response bodies in the clear"
      );
    }
    this.urgentRetryDelayMs = opts.urgent?.retryDelayMs ?? 0;
    if (!Number.isFinite(this.urgentRetryDelayMs) || this.urgentRetryDelayMs < 0) {
      throw new RangeError(`urgent.retryDelayMs must be >= 0, got ${opts.urgent?.retryDelayMs}`);
    }
    this.urgentLimiter = new UrgentRateLimiter(
      opts.urgent?.maxUrgentPerSecond ?? 100,
      opts.urgent?.now ?? Date.now
    );
    this.onStarvationGuardAudit = opts.onStarvationGuardAudit;
    // WR-39: built after the breaker so the manager can read live circuit
    // state for the "circuit open" switch trigger. Invalid configs throw
    // here, at construction — never mid-delivery.
    // WR-48: routing is per-endpoint (shared downstream), while breakers
    // are per-tenant. A target counts as open when any tenant's breaker
    // says so — a real failure signal from any tenant's deliveries should
    // move the shared routing. WR-66 reuses the same reader for weighted
    // dispatch health filtering.
    const routingCircuitState = (target: string): CircuitState => {
      let seen: CircuitState = "closed";
      for (const b of this.breakers.values()) {
        const s = b.state(target);
        if (s === "open") return "open";
        if (s === "half_open") seen = "half_open";
      }
      return seen;
    };
    // WR-66: weighted multi-target dispatch and WR-39 failover are
    // mutually exclusive per endpoint — "share traffic" and "ordered
    // standby" routing must never both claim the same endpoint. Fail-fast
    // at construction, house style.
    if (opts.weighted !== undefined && opts.failover !== undefined) {
      for (const endpoint of Object.keys(opts.weighted)) {
        if (Object.prototype.hasOwnProperty.call(opts.failover, endpoint)) {
          throw new RangeError(
            `weighted and failover are mutually exclusive for endpoint ${JSON.stringify(endpoint)}: configure only one`
          );
        }
      }
    }
    this.weighted =
      opts.weighted !== undefined
        ? new WeightedDispatcher(opts.weighted, {
            now: opts.weightedNow ?? Date.now,
            circuitState: routingCircuitState,
          })
        : undefined;
    this.failover =
      opts.failover !== undefined
        ? new FailoverManager(opts.failover, {
            now: opts.failoverNow ?? Date.now,
            circuitState: routingCircuitState,
            onSwitch: (event) => this.recordFailoverSwitch(event),
          })
        : undefined;
    this.onFailoverSwitch = opts.onFailoverSwitch;    this.laneScheduler = new LaneScheduler({
      minNormalShare: opts.urgent?.minNormalShare ?? 0.2,
      onActivation: (event) => this.onStarvationGuardAudit?.(event),
    });
    // WR-47: invalid callback configs throw here, at construction — never
    // mid-delivery. The runtime loop check (against the actually bound
    // address) is installed later via `setCompletionCallbackSelfCheck`,
    // because the server does not know its listen port yet at this point.
    const callbackConfig = resolveCompletionCallbackConfig(opts.completionCallback);
    this.callbacker =
      callbackConfig === undefined
        ? undefined
        : new CompletionCallbacker(callbackConfig, {
            onFailed: (info) => opts.onCompletionCallbackFailed?.(info),
          });
    this.latencyOpts = opts.latency;
    this.onSloMiss = opts.latency?.onSloMiss;
    if (opts.otlp !== undefined) {
      // WR-83: opt-in OTLP export. The exporter validates eagerly —
      // `RangeError` at construction, never mid-delivery. Delivery
      // events are observed through the public subscription (the
      // exporter's `record()` never throws and never blocks), and the
      // caller's slo-miss hook is wrapped so misses export alongside
      // delivery events while still firing exactly once.
      this.otlpExporter = new OtlpExporter(opts.otlp);
      const exporter = this.otlpExporter;
      this.subscribeDeliveryEvents((event) => {
        try {
          exporter.record({
            eventType: event.type,
            eventId: event.id,
            traceId: event.traceId,
            endpoint: event.targetUrl,
            attempts: event.attempts,
            error: event.error,
            tenant: event.tenant,
          });
        } catch {
          // Unreachable by contract (`record()` never throws) — the
          // delivery path must never see an export throw.
        }
      });
      const callerOnSloMiss = this.onSloMiss;
      this.onSloMiss = (info) => {
        callerOnSloMiss?.(info);
        try {
          exporter.record({
            eventType: "slo_missed",
            eventId: info.id,
            traceId: info.traceId,
            endpoint: info.endpoint,
            tenant: info.tenant,
            sloMs: info.sloMs,
            latencyMs: info.latencyMs,
          });
        } catch {
          // Same contract as above: export never breaks the hook path.
        }
      };
    }
    this.sloRiskOpts = opts.latency?.sloRisk;
    this.onSloRisk = opts.latency?.sloRisk?.onSloRisk;
    if (this.sloRiskOpts !== undefined) {
      // Eager validation: invalid predictor config throws at
      // construction, never mid-request. (The per-tenant instances stay
      // lazy, like the latency trackers.)
      new SloRiskPredictor(this.sloRiskOpts);
    }
    // WR-48: latency trackers and quotas are per-tenant now; instances are
    // created lazily by `latencyFor()` / `quotaFor()`.
    this.quotaDeliveriesPerMinute = opts.quota?.deliveriesPerMinute;
    this.quotaNow = opts.quota?.now ?? Date.now;
    // WR-48: the default tenant's breaker/quota/latency instances are
    // created eagerly (as before), so option validation still throws at
    // construction and probe outcomes behave identically with no tenant in
    // play; other tenants' instances stay lazy.
    this.breakerFor(undefined);
    this.quotaFor(undefined);
    this.latencyFor(undefined);
    // WR-37: normalize the response validators — either a single global
    // validator or a record of exact-targetUrl → validator. Bad values
    // throw at construction, never mid-delivery.
    const validators = opts.responseValidators;
    if (validators !== undefined) {
      if (typeof validators === "function") {
        this.globalResponseValidator = validators;
      } else if (validators !== null && typeof validators === "object" && !Array.isArray(validators)) {
        for (const [endpoint, v] of Object.entries(validators)) {
          if (typeof v !== "function") {
            throw new TypeError(
              `responseValidators[${JSON.stringify(endpoint)}] must be a function, got ${typeof v}`
            );
          }
          this.endpointResponseValidators.set(endpoint, v);
        }
      } else {
        throw new TypeError("responseValidators must be a ResponseValidator or a record of ResponseValidators");
      }
    }
    this.onSemanticFailure = opts.onSemanticFailure;
    // WR-38: a present-but-empty object means "enabled with the generous
    // default budget"; absent means disabled. RangeError comes from the
    // RetryBudget constructor on an illegal budget.
    this.retryBudget =
      opts.retryBudget !== undefined
        ? new RetryBudget(opts.retryBudget.retriesPerMinute, opts.retryBudget.now ?? Date.now)
        : undefined;
    this.onRetryBudgetDepleted = opts.onRetryBudgetDepleted;
    // WR-59: opt-in adaptive backoff. The default tenant's controller is
    // created eagerly so invalid options throw at construction, never
    // mid-delivery; other tenants' controllers stay lazy (WR-48). The
    // resting base is read live from `baseDelayMs`, so a WR-32 hot-reload
    // of the fixed base stays in sync for endpoints with no outcomes yet.
    this.adaptiveBackoffOpts = opts.adaptiveBackoff;
    if (opts.adaptiveBackoff !== undefined) {
      this.adaptiveBackoffFor(undefined);
    }
    this.onAttemptFailed = opts.onAttemptFailed;
    this.onBatch = opts.onBatch;
    const histBuckets = opts.metrics?.histogramBucketsMs ?? [50, 100, 250, 500, 1000, 2500, 5000, 10000];
    if (
      histBuckets.length === 0 ||
      histBuckets.some((b) => !Number.isFinite(b) || b <= 0) ||
      histBuckets.some((b, i) => i > 0 && b <= histBuckets[i - 1])
    ) {
      throw new RangeError(
        `metrics.histogramBucketsMs must be a non-empty strictly ascending list of finite positive numbers, got ${JSON.stringify(histBuckets)}`
      );
    }
    this.histBucketsMs = [...histBuckets];
    if (opts.batch) {
      this.batchResolved = resolveBatchOptions(opts.batch, {
        setTimer: this.setTimer,
        clearTimer: this.clearTimer,
      });
      this.batcher = new BatchCollector(this.batchResolved, (endpoint, items) =>
        this.flushBatch(endpoint, items)
      );
    }
    if (opts.autoReplay !== undefined) {
      // Constructed even with `enabled: false` so the operator surface can
      // always report a status; it only ticks when enabled and started.
      this.autoReplayer = new DeadLetterAutoReplayer({
        ...opts.autoReplay,
        replayAll: () => this.replayDeadLetters(),
        onAudit: opts.onAutoReplayAudit,
      });
    }
    if (opts.deadLetterRetention !== undefined) {
      // The sweeper validates eagerly (illegal values throw RangeError)
      // but only arms when a TTL is actually configured.
      this.retentionSweeper = new DeadLetterRetentionSweeper({
        ...opts.deadLetterRetention,
        owner: {
          listEntries: () => this.deadLetter,
          removeEntry: (id) => this.removeDeadLetterEntry(id),
          isClaimedByReplay: (id) => this.isClaimedByReplay(id),
          onPurged: (event) => this.onDeadLetterPurged?.(event),
        },
      });
    }
    if (opts.replayEgress !== undefined) {
      // WR-68: constructed eagerly so invalid values throw RangeError at
      // construction, never mid-replay. Manual replays, the operator
      // `POST /dead-letter/replay`, and the WR-31 auto-replayer all flow
      // through `replayDeadLetters`, so they share this one gate.
      this.replayEgress = new ReplayEgressGate(opts.replayEgress);
    }
    if (opts.probe !== undefined) {
      // A probe outcome feeds the circuit breaker exactly like a delivery
      // outcome: consecutive probe failures trip the circuit early, a
      // success resets the counter. Probes never touch anything else —
      // no retry budget, no latency samples, no quota.
      this.prober = new DownstreamProber({
        ...opts.probe,
        recordOutcome: (endpoint, ok) => {
          // WR-48: probes measure the downstream itself (shared across
          // tenants), so a probe outcome feeds every tenant's breaker
          // instance for that endpoint.
          for (const b of this.breakers.values()) {
            if (ok) b.recordSuccess(endpoint);
            else b.recordFailure(endpoint);
          }
        },
        onAudit: opts.onProbeAudit,
      });
    }
    // WR-49: opt-in durable queue. Recovery runs here, at construction,
    // so a restarted process resumes delivery from the journal before it
    // serves anything. Corrupt lines are skipped and counted — a torn
    // write never prevents recovery of the rest.
    this.durableNow = opts.durableQueueNow ?? Date.now;
    if (opts.durableQueueDir !== undefined) {
      if (typeof opts.durableQueueDir !== "string" || opts.durableQueueDir.length === 0) {
        throw new RangeError(
          `durableQueueDir must be a non-empty string, got ${JSON.stringify(opts.durableQueueDir)}`
        );
      }
      this.durableDir = opts.durableQueueDir;
      this.durable = new QueueJournal(opts.durableQueueDir, this.payloadEncryptor);
      const rec = this.durable.recover();
      this.durableSkippedLines = rec.skippedLines;
      for (const item of rec.items) {
        this.queue.set(item.id, { ...item, attempt: item.attempt });
        this.bumpPending(item.tenantId, item.targetUrl, 1);
        if (item.nextAt !== undefined) this.restoredNextAt.set(item.id, item.nextAt);
        // A recovery restarts the accepted→delivered clock: the sample
        // measures the post-restart delivery, not the pre-crash wait.
        this.latencyFor(item.tenantId)?.recordAccepted(item.id);
        this.durableRestoredItems += 1;
      }
      for (const entry of rec.deadLetters) {
        this.deadLetter.push(entry);
        this.durableRestoredDeadLetters += 1;
      }
      opts.onQueueRestored?.({
        dir: opts.durableQueueDir,
        restoredItems: this.durableRestoredItems,
        restoredDeadLetters: this.durableRestoredDeadLetters,
        restoredRetries: this.restoredNextAt.size,
        skippedLines: rec.skippedLines,
      });
      // Recovery rewrites the journal down to live state: superseded
      // lines from before the crash never accumulate.
      this.compactDurable(true);
    }
  }

  /**
   * WR-48: the calling tenant's circuit breaker, created on first use.
   * `undefined` when the breaker is not configured. State changes are
   * recorded under the tenant-scoped key and the tenant is passed to the
   * user hook, so metrics and audits can label them.
   */
  private breakerFor(tenant: string | undefined): EndpointCircuitBreaker | undefined {
    if (this.circuitBreakerOpts === undefined) return undefined;
    const key = tenantInstanceKey(tenant);
    let b = this.breakers.get(key);
    if (b === undefined) {
      const t = tenant;
      b = new EndpointCircuitBreaker({
        ...this.circuitBreakerOpts,
        onStateChange: (endpoint, from, to) => {
          innerFor(this.circuitStates, t).set(endpoint, to);
          this.circuitBreakerOnStateChange?.(endpoint, from, to, t);
        },
      });
      this.breakers.set(key, b);
    }
    return b;
  }

  /** WR-48: the calling tenant's quota instance; `undefined` when quotas are off. */
  private quotaFor(tenant: string | undefined): EndpointQuota | undefined {
    if (this.quotaDeliveriesPerMinute === undefined) return undefined;
    const key = tenantInstanceKey(tenant);
    let q = this.quotas.get(key);
    if (q === undefined) {
      q = new EndpointQuota(this.quotaDeliveriesPerMinute, this.quotaNow);
      this.quotas.set(key, q);
    }
    return q;
  }

  /** WR-48: the calling tenant's concurrency limiter (always present). */
  private limiterFor(tenant: string | undefined): EndpointConcurrencyLimiter {
    const key = tenantInstanceKey(tenant);
    let l = this.limiters.get(key);
    if (l === undefined) {
      l = new EndpointConcurrencyLimiter(this.maxConcurrentPerEndpoint);
      this.limiters.set(key, l);
    }
    return l;
  }

  /** WR-48: the calling tenant's latency tracker; `undefined` when latency tracking is off. */
  private latencyFor(tenant: string | undefined): LatencyTracker | undefined {
    if (this.latencyOpts === undefined) return undefined;
    const key = tenantInstanceKey(tenant);
    let l = this.latencies.get(key);
    if (l === undefined) {
      l = new LatencyTracker(this.latencyOpts);
      this.latencies.set(key, l);
    }
    return l;
  }

  /**
   * WR-71: the calling tenant's SLO-risk predictor; `undefined` when the
   * predictor is disabled. The queue's `onSloRisk` wrapper re-attaches the
   * tenant (mirroring how the server wraps `onSloMiss` for auditing).
   */
  private sloRiskFor(tenant: string | undefined): SloRiskPredictor | undefined {
    if (this.sloRiskOpts === undefined) return undefined;
    const key = tenantInstanceKey(tenant);
    let p = this.sloRisks.get(key);
    if (p === undefined) {
      const onSloRisk = this.onSloRisk;
      p = new SloRiskPredictor({
        ...this.sloRiskOpts,
        onSloRisk:
          onSloRisk === undefined
            ? undefined
            : (info) => onSloRisk({ ...info, ...(tenant === undefined ? {} : { tenant }) }),
      });
      this.sloRisks.set(key, p);
    }
    return p;
  }

  /** WR-71: adjust the per-(tenant, endpoint) pending count; zero rows are dropped. */
  private bumpPending(tenantId: string | undefined, targetUrl: string, delta: number): void {
    const inner = innerFor(this.pendingByEndpoint, tenantId);
    const next = (inner.get(targetUrl) ?? 0) + delta;
    if (next <= 0) inner.delete(targetUrl);
    else inner.set(targetUrl, next);
  }

  /** WR-71: current pending count for one (tenant, endpoint). */
  private pendingFor(tenantId: string | undefined, targetUrl: string): number {
    return this.pendingByEndpoint.get(tenantInstanceKey(tenantId))?.get(targetUrl) ?? 0;
  }

  /**
   * WR-71: feed one observation into the endpoint's SLO-risk predictor.
   * The endpoint key is the *logical* `targetUrl` — the same key the
   * pending counters use. In the default single-target setup it coincides
   * with the physical target the latency samples carry; with failover /
   * weighted dispatch active the latency side degrades gracefully (no
   * samples under the logical key → cold-start guard → no latency-driven
   * risk) while the backlog trend still evaluates.
   */
  private evaluateSloRisk(tenantId: string | undefined, endpoint: string): void {
    const predictor = this.sloRiskFor(tenantId);
    if (predictor === undefined) return;
    const tracker = this.latencyFor(tenantId);
    if (tracker === undefined) return; // Unreachable: sloRisk nests under latency.
    const row = tracker.stats(endpoint)[0];
    const obs: SloRiskObservation = {
      backlog: this.pendingFor(tenantId, endpoint),
      ...(row === undefined ? {} : { stats: { p95: row.p95, min: row.min, count: row.count } }),
      concurrency: this.limiterFor(tenantId).maxFor(endpoint),
      sloMs: tracker.sloMs,
    };
    predictor.observe(endpoint, obs);
  }

  /**
   * WR-59: the calling tenant's adaptive backoff controller; `undefined`
   * when adaptive backoff is disabled. Outcomes are keyed by the physical
   * target — the same key the circuit breaker uses — so the base tracks
   * the downstream that was actually hit.
   */
  private adaptiveBackoffFor(tenant: string | undefined): AdaptiveBackoffController | undefined {
    if (this.adaptiveBackoffOpts === undefined) return undefined;
    const key = tenantInstanceKey(tenant);
    let c = this.adaptiveBackoffs.get(key);
    if (c === undefined) {
      c = new AdaptiveBackoffController(() => this.baseDelayMs, this.adaptiveBackoffOpts);
      this.adaptiveBackoffs.set(key, c);
    }
    return c;
  }

  /**
   * WR-48: default-tenant views of the per-tenant instances, preserving the
   * pre-tenant private field names (`breaker`, `quota`, `limiter`,
   * `latency`) that white-box tests reach for. New code should use the
   * `*For(tenant)` accessors above.
   */
  private get breaker(): EndpointCircuitBreaker | undefined {
    return this.breakerFor(undefined);
  }
  private get quota(): EndpointQuota | undefined {
    return this.quotaFor(undefined);
  }
  private get limiter(): EndpointConcurrencyLimiter {
    return this.limiterFor(undefined);
  }
  private get latency(): LatencyTracker | undefined {
    return this.latencyFor(undefined);
  }
  private get adaptiveBackoff(): AdaptiveBackoffController | undefined {
    return this.adaptiveBackoffFor(undefined);
  }

  private recordQuotaStat(tenant: string | undefined, endpoint: string): void {
    const inner = innerFor(this.quotaStats, tenant);
    inner.set(endpoint, (inner.get(endpoint) ?? 0) + 1);
  }

  /** WR-52: count one window-outside park for the (tenant, endpoint) row. */
  private recordDeliveryWindowStat(tenant: string | undefined, endpoint: string): void {
    const inner = innerFor(this.deliveryWindowStats, tenant);
    inner.set(endpoint, (inner.get(endpoint) ?? 0) + 1);
  }

  private recordUrgentStat(endpoint: string, kind: "delivered" | "retried" | "throttled"): void {
    let s = this.urgentStats.get(endpoint);
    if (!s) {
      s = { delivered: 0, retried: 0, throttled: 0 };
      this.urgentStats.set(endpoint, s);
    }
    s[kind] += 1;
  }

  /** Increment one Prometheus delivery counter for (tenant, endpoint). */
  private recordDelivery(
    tenant: string | undefined,
    endpoint: string,
    kind: "delivered" | "failed" | "retried" | "deadLetter"
  ): void {
    const inner = innerFor(this.deliveryCounters, tenant);
    let c = inner.get(endpoint);
    if (!c) {
      c = { delivered: 0, failed: 0, retried: 0, deadLetter: 0 };
      inner.set(endpoint, c);
    }
    c[kind] += 1;
  }

  /** Count one failover switch for `relay_failover_switches_total{endpoint,from,to}` and fan out the hook. */
  private recordFailoverSwitch(event: FailoverSwitchEvent): void {
    const key = JSON.stringify([event.endpoint, event.from, event.to]);
    const prev = this.failoverSwitchCounts.get(key);
    if (prev) prev.switches += 1;
    else
      this.failoverSwitchCounts.set(key, {
        endpoint: event.endpoint,
        from: event.from,
        to: event.to,
        switches: 1,
      });
    this.onFailoverSwitch?.(event);
  }

  /** Bucket one accepted→delivered sample into the (tenant, endpoint) latency histogram. */
  private recordLatencySample(tenant: string | undefined, endpoint: string, latencyMs: number): void {
    const inner = innerFor(this.latencyHist, tenant);
    let h = inner.get(endpoint);
    if (!h) {
      h = { counts: new Array(this.histBucketsMs.length).fill(0), sumMs: 0, count: 0 };
      inner.set(endpoint, h);
    }
    const idx = this.histBucketsMs.findIndex((b) => latencyMs <= b);
    // A sample above the last bound lands in +Inf only (the `count` series).
    if (idx >= 0) h.counts[idx] += 1;
    h.sumMs += latencyMs;
    h.count += 1;
  }

  /**
   * WR-72: mask configured PII fields in a captured response body *before*
   * WR-11 sealing. Only JSON bodies can take field paths; anything else is
   * sealed as-is (a documented limitation, not a silent drop).
   */
  private maskResponseBody(endpoint: string, body: Buffer): Buffer {
    const mask = this.fieldMask;
    if (mask === undefined || !mask.hasRules(endpoint)) return body;
    let parsed: unknown;
    try {
      parsed = JSON.parse(body.toString("utf8"));
    } catch {
      return body;
    }
    if (parsed === null || typeof parsed !== "object") return body;
    return Buffer.from(JSON.stringify(mask.maskJson(endpoint, parsed)), "utf8");
  }

  /** Number of items currently pending (queued or awaiting retry). */
  pendingCount(): number {
    return this.queue.size;
  }

  /**
   * Subscribe to delivery lifecycle events (`delivered` / `retrying` /
   * `dead_letter`). Returns an unsubscribe function. The server wires this
   * to its SSE endpoint (`GET /events`); listeners run synchronously on the
   * delivery path, so keep them fast and non-blocking.
   */
  subscribeDeliveryEvents(listener: (e: DeliveryEvent) => void): () => void {
    this.deliveryEventListeners.add(listener);
    return () => {
      this.deliveryEventListeners.delete(listener);
    };
  }

  private emitDeliveryEvent(event: DeliveryEvent): void {
    for (const listener of this.deliveryEventListeners) listener(event);
  }

  /**
   * Per-endpoint batch counters: batches flushed, events merged, and items
   * still sitting inside a batch window. Empty when batching is disabled.
   */
  getBatchStats(): Array<{ endpoint: string; batches: number; events: number; buffered: number }> {
    if (!this.batcher) return [];
    const endpoints = new Set([...this.batchStats.keys(), ...this.batcher.endpoints()]);
    return [...endpoints].map((endpoint) => ({
      endpoint,
      batches: this.batchStats.get(endpoint)?.batches ?? 0,
      events: this.batchStats.get(endpoint)?.events ?? 0,
      buffered: this.batcher!.bufferedCount(endpoint),
    }));
  }

  /** Merge a flushed batch window into one delivery item and queue it. */
  private flushBatch(endpoint: string, items: RetryItem[]): void {
    const batchId = newBatchId();
    const body = this.batchResolved!.envelope({ batchId, items });
    let s = this.batchStats.get(endpoint);
    if (!s) {
      s = { batches: 0, events: 0 };
      this.batchStats.set(endpoint, s);
    }
    s.batches += 1;
    s.events += items.length;
    this.enqueueNow({
      id: batchId,
      payload: body,
      targetUrl: endpoint,
      headers: {
        "content-type": "application/json",
        "x-batch-id": batchId,
        "x-batch-size": String(items.length),
      },
    });
    this.onBatch?.({
      batchId,
      endpoint,
      size: items.length,
      traceIds: items.map((i) => i.traceId ?? ""),
    });
  }

  /** Items that exhausted all attempts, in dead-letter order. */
  getDeadLetter(): DeadLetterEntry[] {
    return [...this.deadLetter];
  }

  /**
   * The opt-in dead-letter auto-replay scheduler, or `undefined` when no
   * `autoReplay` option was configured. The server exposes it through the
   * `POST/GET /dead-letter/auto-replay/*` operator endpoints.
   */
  getAutoReplayer(): DeadLetterAutoReplayer | undefined {
    return this.autoReplayer;
  }

  /**
   * The opt-in downstream health prober, or `undefined` when no `probe`
   * option was configured. Library users (and tests) can drive
   * `runRound()` directly; the server runs it on its schedule.
   */
  getProber(): DownstreamProber | undefined {
    return this.prober;
  }

  /**
   * Per-endpoint health-probe counters (`success` / `failure` /
   * `consecutiveFailures` / `lastProbeAtMs`). Empty when probing is
   * disabled.
   */
  getProbeStats(): ProbeEndpointStats[] {
    return this.prober?.stats() ?? [];
  }

  /**
   * WR-83: OTLP export snapshot (`enabled` / `buffered` / `dropped` /
   * `exported` / `lastError`). `enabled` is false (and every counter 0)
   * when the `otlp` option was never set.
   */
  getOtlpStats(): OtlpStats {
    return (
      this.otlpExporter?.stats() ?? { enabled: false, buffered: 0, dropped: 0, exported: 0 }
    );
  }

  /**
   * Move a dead-lettered item back into the queue with a fresh attempt
   * budget (attempts reset to 0, scheduled immediately when running).
   * Returns false when no dead-letter entry matches `id`. A replay that
   * fails (e.g. a sealed payload that no longer decrypts) leaves the entry
   * in the dead-letter list and rethrows, so the operator can inspect and
   * retry it again after fixing the cause.
   */
  replayDeadLetter(id: string): boolean {
    // Claim the id for the whole synchronous run so the retention sweep
    // (WR-64) never purges the entry out from under an in-progress replay.
    this.claimReplay(id);
    try {
      const idx = this.deadLetter.findIndex((e) => e.id === id);
      if (idx < 0) return false;
      const [entry] = this.deadLetter.splice(idx, 1);
      try {
        this.requeueDeadLetter(entry);
      } catch (err) {
        // The entry was already removed from the list: put it back so a
        // failed replay never loses the dead letter.
        this.deadLetter.splice(Math.min(idx, this.deadLetter.length), 0, entry);
        throw err;
      }
      // WR-49: the re-queued item journaled its own `enqueue` inside
      // requeueDeadLetter; this line supersedes the `dead_letter` line.
      this.durable?.appendReplayed(id);
      this.compactDurable();
      return true;
    } finally {
      this.releaseReplay(id);
    }
  }

  /** Re-queue a dead-letter entry that has already been removed from the list. */
  private requeueDeadLetter(entry: DeadLetterEntry): void {
    const {
      attempts: _attempts,
      lastError: _lastError,
      deadLetteredAt: _ts,
      encryptedPayload,
      payloadBytes: _payloadBytes,
      failoverEndpoint,
      // WR-76: a replay starts a fresh delivery cycle — drop the original
      // admission instant and stamp a new one below, exactly like the
      // WR-13 latency clock restart.
      enqueuedAt: _enqueuedAt,
      ...item
    } = entry;
    let payload = item.payload;
    if (encryptedPayload) {
      if (!this.payloadEncryptor) {
        throw new Error("replayDeadLetter: entry payload is encrypted but no payloadEncryptor is configured");
      }
      payload = this.payloadEncryptor.decrypt(encryptedPayload);
    }
    // WR-39: replays re-enter through the logical endpoint so the next
    // dispatch resolves the *current* active target instead of pinning to
    // whatever standby served the dead-lettered attempt.
    const requeued = {
      ...item,
      payload,
      targetUrl: failoverEndpoint ?? item.targetUrl,
      attempt: 0,
      enqueuedAt: this.deadlineNow(),
    };
    // WR-49: journal before the in-memory mutation, like enqueueNow.
    this.durable?.appendEnqueue(requeued);
    this.queue.set(item.id, requeued);
    this.bumpPending(item.tenantId, requeued.targetUrl, 1);
    // A replay starts a fresh delivery cycle: restart the latency clock so
    // the sample measures the replayed attempt, not the original one.
    // WR-48: the replay keeps the dead letter's tenant, so the clock
    // restarts on the same tenant's tracker.
    this.latencyFor(item.tenantId)?.recordAccepted(item.id);
    if (this.running) {
      this.schedule(item.id, 0);
    }
    this.compactDurable();
  }

  /** Replay every dead-lettered item. Returns the number replayed. */
  replayAllDeadLetters(): number {
    const ids = this.deadLetter.map((e) => e.id);
    let replayed = 0;
    for (const id of ids) {
      if (this.replayDeadLetter(id)) replayed += 1;
    }
    return replayed;
  }

  /**
   * Run one dead-letter retention sweep immediately (WR-64): purge every
   * entry whose per-endpoint TTL has expired, skipping entries currently
   * claimed by a WR-23 batch replay or the WR-31 auto-replay. Each purge
   * is journaled (WR-49) and reported via `onDeadLetterPurged`. The
   * armed sweep timer calls this on its schedule; calling it directly is
   * safe and does not disturb the schedule. Returns
   * `{ purged: [], skipped: [] }` when retention is not configured.
   */
  purgeExpiredDeadLetters(): DeadLetterPurgeResult {
    return this.retentionSweeper?.sweepNow() ?? { purged: [], skipped: [] };
  }

  /**
   * The opt-in dead-letter retention sweeper, or `undefined` when no
   * `deadLetterRetention` option was configured.
   */
  getRetentionSweeper(): DeadLetterRetentionSweeper | undefined {
    return this.retentionSweeper;
  }

  /**
   * Dead-letter observability snapshot: live entry count, entries
   * auto-purged by the retention sweep since construction, entries held
   * back by the WR-68 replay egress throttle (cumulative), and live
   * entries per logical endpoint (first-seen order). Served over HTTP
   * as `GET /dead-letter/stats`.
   */
  getDeadLetterStats(): DeadLetterStats {
    const byEndpoint = new Map<string, number>();
    const byTenantEndpoint = new Map<string, { tenant?: string; endpoint: string; count: number }>();
    for (const e of this.deadLetter) {
      const endpoint = e.failoverEndpoint ?? e.targetUrl;
      byEndpoint.set(endpoint, (byEndpoint.get(endpoint) ?? 0) + 1);
      // WR-86: the key separates tenants, so one tenant's dead letters can
      // never leak into another tenant's count. `\n` cannot appear in a
      // tenant id (WR-48 charset) or a URL, matching `tenantScopeKey`.
      const key = e.tenantId === undefined ? endpoint : `${e.tenantId}\n${endpoint}`;
      const row = byTenantEndpoint.get(key);
      if (row) row.count += 1;
      else
        byTenantEndpoint.set(key, {
          ...(e.tenantId !== undefined ? { tenant: e.tenantId } : {}),
          endpoint,
          count: 1,
        });
    }
    return {
      total: this.deadLetter.length,
      purged: this.deadLetterPurged,
      throttled: this.replayEgressThrottled,
      byEndpoint: [...byEndpoint].map(([endpoint, count]) => ({ endpoint, count })),
      byTenantEndpoint: [...byTenantEndpoint.values()],
    };
  }

  /**
   * The opt-in WR-68 replay egress gate, or `undefined` when no
   * `replayEgress` option was configured.
   */
  getReplayEgressGate(): ReplayEgressGate | undefined {
    return this.replayEgress;
  }

  /**
   * Remove a dead-letter entry for retention purging (WR-64). Journaled
   * (WR-49: the `purged` line supersedes the `dead_letter` line, so a
   * restarted process never resurrects the entry) and counted toward
   * `getDeadLetterStats().purged`. Returns the removed entry, or
   * `undefined` when the id is already gone.
   */
  private removeDeadLetterEntry(id: string): DeadLetterEntry | undefined {
    const idx = this.deadLetter.findIndex((e) => e.id === id);
    if (idx < 0) return undefined;
    const [entry] = this.deadLetter.splice(idx, 1);
    this.durable?.appendPurged(id);
    this.deadLetterPurged += 1;
    this.compactDurable();
    return entry;
  }

  /** Dead-letter entries matching `filter`, in dead-letter order. */
  private matchDeadLetters(filter: DeadLetterReplayFilter): DeadLetterEntry[] {
    const ids = filter.ids !== undefined ? new Set(filter.ids) : undefined;
    return this.deadLetter.filter(
      (e) =>
        // WR-39: an entry dead-lettered on a failover standby also matches
        // its logical endpoint, so operators filter by the endpoint they
        // configured, not the physical target that happened to serve it.
        (filter.endpoint === undefined ||
          e.targetUrl === filter.endpoint ||
          e.failoverEndpoint === filter.endpoint) &&
        // WR-86: exact tenant match. Omitting `tenant` keeps the
        // pre-tenant behavior — every tenant's entries are eligible.
        (filter.tenant === undefined || e.tenantId === filter.tenant) &&
        (ids === undefined || ids.has(e.id))
    );
  }

  /**
   * Batch replay of dead letters with a dry-run preview mode.
   *
   * With `dryRun: true` this returns the dead letters the filter would pick
   * up as metadata-only previews — no side effects: nothing is re-queued,
   * nothing is audited, and payloads are never touched (let alone
   * decrypted). Use it in a payment-reconciliation review before committing
   * to a real replay.
   *
   * A real replay processes the matched entries grouped by endpoint (each
   * endpoint's backlog together, in dead-letter order) and replays them
   * with a fresh attempt budget, like {@link RetryQueue.replayDeadLetter}.
   * Every entry is replayed independently: one failure cannot stop or roll
   * back the others — failures stay in the dead-letter list and are
   * reported in `failed` with their error.
   */
  replayDeadLetters(
    filter: DeadLetterReplayFilter,
    opts: { dryRun: true }
  ): DeadLetterReplayPreview[];
  replayDeadLetters(
    filter?: DeadLetterReplayFilter,
    opts?: { dryRun?: false }
  ): DeadLetterBatchReplayResult;
  replayDeadLetters(
    filter: DeadLetterReplayFilter = {},
    opts: { dryRun?: boolean } = {}
  ): DeadLetterReplayPreview[] | DeadLetterBatchReplayResult {
    if (opts.dryRun === true) {
      return this.matchDeadLetters(filter).map((e) => ({
        id: e.id,
        endpoint: e.targetUrl,
        ...(e.tenantId !== undefined ? { tenant: e.tenantId } : {}),
        attempts: e.attempts,
        lastError: e.lastError,
        deadLetteredAt: e.deadLetteredAt,
        payloadBytes: e.payloadBytes,
      }));
    }
    // WR-64: claim every matched id for the whole batch so the retention
    // sweep skips them — the sweep can never interleave inside this
    // synchronous loop, but the claim is what a reentrant caller (e.g. a
    // decrypt hook that sweeps mid-batch) observes. The WR-31 auto-replay
    // runs through this same method, so its rounds are covered too.
    const matched = this.matchDeadLetters(filter);
    for (const entry of matched) this.claimReplay(entry.id);
    try {
      // Group by endpoint (first-seen order): each endpoint's backlog is
      // replayed together so the downstream pressure stays grouped instead
      // of interleaved across endpoints.
      const groups = new Map<string, DeadLetterEntry[]>();
      for (const entry of matched) {
        const group = groups.get(entry.targetUrl);
        if (group) group.push(entry);
        else groups.set(entry.targetUrl, [entry]);
      }
      const replayed: string[] = [];
      const failed: DeadLetterReplayFailure[] = [];
      const throttled: string[] = [];
      const seen = new Set<string>();
      for (const entries of groups.values()) {
        for (const entry of entries) {
          seen.add(entry.id);
          // WR-68: the shared egress gate throttles re-queue admission.
          // The bucket is keyed by the *logical* endpoint the entry will
          // be re-queued on (`failoverEndpoint ?? targetUrl` — the same
          // key `getDeadLetterStats` groups by), so a standby failover
          // does not buy extra budget. A held-back entry stays in the
          // dead-letter list — nothing is dropped, FIFO order is
          // preserved — and the next replay call picks it up. The gate is
          // orthogonal to breaker/quota/weighted/limiter: it only paces
          // re-queue admission, never the delivery path.
          const egressEndpoint = entry.failoverEndpoint ?? entry.targetUrl;
          if (this.replayEgress && !this.replayEgress.take(egressEndpoint)) {
            throttled.push(entry.id);
            this.replayEgressThrottled += 1;
            continue;
          }
          try {
            if (this.replayDeadLetter(entry.id)) {
              replayed.push(entry.id);
            } else {
              failed.push({ id: entry.id, error: "dead-letter entry no longer present" });
            }
          } catch (err) {
            failed.push({ id: entry.id, error: err instanceof Error ? err.message : String(err) });
          }
        }
      }
      // Like the single-item endpoint (which 404s on an unknown id), report
      // requested ids that match nothing instead of silently ignoring them —
      // a typo in `ids` should be visible, not invisible.
      if (filter.ids !== undefined) {
        for (const id of filter.ids) {
          if (!seen.has(id)) failed.push({ id, error: "unknown dead-letter id" });
        }
      }
      return { replayed, failed, throttled };
    } finally {
      for (const entry of matched) this.releaseReplay(entry.id);
    }
  }

  enqueue(item: RetryItem): void {
    if (this.queue.has(item.id) || this.batcher?.has(item.id) || this.scheduler.has(item.id)) {
      throw new Error(`Duplicate item id: ${item.id}`);
    }
    // Mint the trace ID up front so even batch-buffered items (which skip
    // `enqueueNow` until flush) carry one, and `flushBatch` can correlate
    // the merged delivery back to its members.
    const traced: RetryItem = { ...item, traceId: item.traceId ?? newTraceId() };
    // WR-57: a future deliver_at parks the item in the delay queue instead
    // of entering the normal path — no batching (a batch window would blur
    // the per-event deliver_at), no attempt counting, and no budget, quota,
    // or circuit consumption until the instant arrives. A past-due value
    // falls through to the normal path below.
    if (traced.deliverAt !== undefined && traced.deliverAt > this.scheduledNow()) {
      this.scheduler.park(traced);
      return;
    }
    // The urgent lane is never batched: an urgent delivery must go out
    // immediately, not wait for a batch window.
    if (this.batcher && traced.priority !== "urgent") {
      this.batcher.add(traced);
      return;
    }
    this.enqueueNow(traced);
  }

  /**
   * WR-57: the delay queue hands due items back. Each enters the normal
   * path via `enqueueNow` — the accepted→delivered latency clock starts
   * here (the parking delay is by design, not lateness, exactly like the
   * WR-09 batch window), attempt counting starts at the first *actual*
   * dispatch, and retry / dead-letter / circuit / quota / budget plus the
   * SSE delivery-event stream all apply from here.
   *
   * WR-80: items carrying `scheduleId` are cron occurrences — each is
   * audited as `scheduled_fired` (via `onScheduledFired`) before entering
   * the normal path, with the *next* cycle's fire instant attached.
   */
  private releaseScheduled(items: RetryItem[]): void {
    for (const item of items) {
      if (item.scheduleId !== undefined) {
        this.onScheduledFired?.({
          event: "scheduled_fired",
          scheduleId: item.scheduleId,
          id: item.id,
          traceId: item.traceId as string,
          targetUrl: item.targetUrl,
          ...(item.tenantId !== undefined ? { tenant: item.tenantId } : {}),
          ...(item.priority !== undefined ? { priority: item.priority } : {}),
          nextAt: this.scheduler.nextFireAt(item.scheduleId) ?? 0,
        });
      }
      this.enqueueNow(item);
    }
  }

  /**
   * Cancel a parked deliver_at delivery (WR-57): the item is dropped from
   * the delay queue and will never be delivered. Returns `true` on a real
   * cancellation, `false` for an unknown id — including ids that already
   * fired or were never scheduled.
   */
  cancelScheduled(id: string): boolean {
    return this.scheduler.cancel(id);
  }

  /** True when `id` is currently parked in the deliver_at delay queue (WR-57). */
  isScheduled(id: string): boolean {
    return this.scheduler.has(id);
  }

  /**
   * Pending scheduled deliveries (WR-57), earliest deliver_at first:
   * operator metadata only (id, targetUrl, deliverAt, traceId, tenant,
   * priority) — the payload is never exposed.
   */
  getScheduled(): ScheduledDeliveryInfo[] {
    return this.scheduler.list();
  }

  /**
   * Scheduled-delivery counters (WR-57): currently parked (`pending`) plus
   * cumulative parked / released-due / canceled; WR-80 adds `recurring`
   * (registered cron schedules) and `fired` (cumulative occurrences).
   */
  getScheduledStats(): ScheduledStats {
    return this.scheduler.stats();
  }

  /**
   * WR-80: register a recurring cron schedule. `template.id` becomes the
   * schedule id (unique across queued and scheduled ids); every cycle
   * generates one fresh delivery (`<id>#<n>`, fresh traceId) into the
   * normal path. Returns the schedule id. Throws `RangeError` on an
   * invalid cron expression, `Error` on a duplicate id.
   */
  addRecurringDelivery(template: RetryItem, cronExpression: string): string {
    if (this.queue.has(template.id)) {
      throw new Error(`Duplicate item id: ${template.id}`);
    }
    return this.scheduler.addRecurring(template, cronExpression);
  }

  /**
   * WR-80: pause a recurring schedule — no further occurrences until
   * {@link resumeSchedule}. Already-generated deliveries are unaffected.
   * Returns `false` for an unknown schedule id.
   */
  pauseSchedule(id: string): boolean {
    return this.scheduler.pauseSchedule(id);
  }

  /**
   * WR-80: resume a paused schedule; the next occurrence is computed from
   * now (missed cycles are skipped, never backfilled). Returns `false`
   * for an unknown schedule id.
   */
  resumeSchedule(id: string): boolean {
    return this.scheduler.resumeSchedule(id);
  }

  /** WR-80: next fire instant of a recurring schedule, or `undefined` when unknown/paused. */
  nextScheduleFire(id: string): number | undefined {
    return this.scheduler.nextFireAt(id);
  }

  private enqueueNow(item: RetryItem): void {
    if (this.queue.has(item.id)) {
      throw new Error(`Duplicate item id: ${item.id}`);
    }
    // A defensive second mint: items enqueued through paths that skip
    // `enqueue()` (replayed dead letters keep their original traceId via
    // spread, flushed batches arrive here already traced) still land with a
    // trace ID rather than an undefined one.
    // WR-76: stamp the queue-admission instant — the start of the
    // end-to-end delivery deadline clock. A caller-supplied `enqueuedAt`
    // is honored (hand-built items, deterministic tests); batch-window
    // and deliver_at parking end here, so by-design holds before this
    // point never count against the deadline.
    const stored = {
      ...item,
      traceId: item.traceId ?? newTraceId(),
      attempt: 0,
      enqueuedAt: item.enqueuedAt ?? this.deadlineNow(),
    };
    // WR-49: journal before the in-memory mutation — a crash between the
    // two redelivers (at-least-once), never loses.
    this.durable?.appendEnqueue(stored);
    this.queue.set(item.id, stored);
    // Start the latency clock only after the item is really queued — a
    // duplicate-id throw must not leave a stale pending record behind.
    // (Batched items start their clock at flush time, when the merged item
    // is queued: the batching delay is by design, not lateness.)
    // WR-48: per-tenant tracker.
    this.latencyFor(item.tenantId)?.recordAccepted(item.id);
    // WR-71: the backlog changed — feed the SLO-risk predictor.
    this.bumpPending(item.tenantId, stored.targetUrl, 1);
    this.evaluateSloRisk(item.tenantId, stored.targetUrl);
    if (this.running) {
      this.schedule(item.id, 0);
    }
    this.compactDurable();
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    for (const id of this.queue.keys()) {
      // WR-50: already-parked items keep their recorded next-dispatch
      // time across the restart instead of being re-parked as due-now.
      if (this.parked.has(id)) continue;
      // WR-49: items restored from the journal resume with their
      // remaining backoff (nextAt - now, floored at 0) instead of firing
      // immediately; everything else schedules at once, as before.
      const nextAt = this.restoredNextAt.get(id);
      this.schedule(id, nextAt === undefined ? 0 : Math.max(0, nextAt - this.durableNow()));
    }
    this.restoredNextAt.clear();
    // Opt-in only: undefined when `autoReplay` was never configured, and
    // a no-op when constructed with `enabled: false`.
    this.autoReplayer?.start();
    // Opt-in only: undefined when `deadLetterRetention` was never
    // configured, and a no-op when no TTL is set.
    this.retentionSweeper?.start();
    // Opt-in only: undefined when `probe` was never configured.
    this.prober?.start();
    // WR-83: opt-in only — re-arm a pending OTLP export retry timer
    // (cleared by `stop()`) when records are still buffered.
    this.otlpExporter?.resume();
    // WR-57: arm the deliver_at delay queue — parked items whose instant
    // already passed while stopped fire immediately (past-due semantics).
    this.scheduler.arm();
  }

  stop(): void {
    this.autoReplayer?.stop();
    this.retentionSweeper?.stop();
    this.prober?.stop();
    this.callbacker?.stop();
    // WR-83: opt-in only — clear the export retry timer and kick off one
    // best-effort flush (fire-and-forget; `stop()` is synchronous).
    this.otlpExporter?.stop();
    // WR-57: disarm the delay-queue timer but keep the heap — parked items
    // stay parked with their absolute deliver_at; the next start() re-arms.
    this.scheduler.disarm();
    this.running = false;
    for (const [id, s] of this.timers) {
      this.clearTimer(s.handle);
      this.timers.delete(id);
    }
    // No timer is armed anymore, so no fire-time is meaningful either.
    // Parked (WR-50) items stay parked: the next start() reschedules
    // everything in the queue, pause-aware.
    this.armedNextAt.clear();
    // WR-51: wake global-gate waiters — with the queue stopped their
    // liveness check bails them out instead of dispatching, so a stop
    // never leaves a deliver parked on the gate across a restart.
    this.globalGate.releaseWaiters();
    // The timers are gone, so no retry fire-time is armed anymore; the
    // next start() (or a restart, via the journaled enqueue lines)
    // schedules fresh.
    this.durablePendingRetry.clear();
    // A batch window is not a delivery: flush pending batches into the queue
    // so accepted events are never silently dropped by a stop. They stay
    // queued (unscheduled) until the next start(), like backoff-waiting
    // items.
    this.batcher?.flushAll();
  }

  /**
   * Graceful shutdown: stop scheduling new attempts, then wait for the
   * deliveries already in flight to settle. Items still waiting on a backoff
   * timer are dropped (they were never delivered); the caller is expected to
   * exit the process afterwards.
   *
   * @param timeoutMs maximum time to wait for in-flight deliveries.
   * @returns `true` when every in-flight delivery settled within the timeout,
   * `false` on timeout — in which case the caller should force-exit so a hung
   * downstream cannot pin the process forever.
   */
  async shutdown(timeoutMs = 30_000): Promise<boolean> {
    // Buffered batches were accepted (202) but never queued: flush them now
    // and give each merged batch one immediate delivery attempt, so a
    // deploy landing inside a batch window does not silently strand them.
    // A forced attempt that needs to reschedule (retry, quota/circuit park)
    // stays queued instead — `schedule()` is a no-op once the queue is
    // stopped — the same contract as backoff-waiting items.
    const batchIds: string[] = [];
    if (this.batcher && this.batcher.bufferedCount() > 0) {
      const before = new Set(this.queue.keys());
      this.batcher.flushAll();
      for (const id of this.queue.keys()) {
        if (!before.has(id)) batchIds.push(id);
      }
    }
    // An auto-replay timer must not fire mid-shutdown: a round would
    // re-queue dead letters the operator expected to stay parked. The
    // timer is unref'd anyway; this is about not doing work, not process
    // lifetime.
    this.autoReplayer?.stop();
    // Same for the retention sweep: no purges mid-shutdown — an entry
    // whose TTL expired during the drain window stays visible for the
    // operator's post-mortem instead of vanishing.
    this.retentionSweeper?.stop();
    // Same for the health prober: no new probe rounds mid-shutdown.
    this.prober?.stop();
    // WR-57: parked-but-not-due deliveries are dropped, exactly like
    // backoff-waiting ones — they were never delivered. (The delay queue
    // is in-memory only; a restart does not recover it either.)
    this.scheduler.clear();
    this.running = false;
    for (const [id, s] of this.timers) {
      this.clearTimer(s.handle);
      this.timers.delete(id);
    }
    this.armedNextAt.clear();
    // WR-51: wake global-gate waiters before draining — woken waiters see
    // the stopped queue and bail out, so shutdown() waits only for
    // deliveries genuinely in flight instead of hanging on the gate.
    this.globalGate.releaseWaiters();
    this.durablePendingRetry.clear();
    // WR-83: best-effort OTLP export flush — bounded (1s) so a dead
    // collector can never pin shutdown; the exporter clears its own
    // timers. Buffered records that don't make it are dropped with the
    // process, exactly like backoff-waiting items.
    await this.otlpExporter?.shutdown(1000);
    // WR-49: leave the journal compact — a shutdown is the natural
    // checkpoint; the next boot recovers from live state only.
    this.compactDurable(true);
    for (const id of batchIds) {      const p = this.deliver(id, true);
      // `deliver` never rejects (sender errors are caught internally), but
      // track both outcomes so a bug can never leak a hanging shutdown.
      this.inFlight.add(p);
      p.then(
        () => this.inFlight.delete(p),
        () => this.inFlight.delete(p)
      );
    }
    if (this.inFlight.size === 0) return true;
    let timer: { clear(): void } | undefined;
    try {
      await Promise.race([
        Promise.allSettled([...this.inFlight]),
        new Promise<void>((resolve) => {
          timer = this.setTimer(resolve, timeoutMs);
        }),
      ]);
    } finally {
      if (timer) this.clearTimer(timer);
    }
    return this.inFlight.size === 0;
  }

  /** Number of deliveries currently executing (not just scheduled). */
  inFlightCount(): number {
    return this.inFlight.size;
  }

  /**
   * Backoff for the *next* retry given the completed attempt index (0-based).
   *
   * WR-59: with adaptive backoff enabled and an `endpoint` given, the base
   * is the endpoint's current adaptive base (per its recent delivery
   * outcomes); otherwise the configured fixed base. `tenant` selects the
   * tenant's controller (WR-48); omit it for the default tenant. The
   * global retry budget (WR-38) gates before this is computed — the two
   * compose orthogonally.
   */
  delayForAttempt(attempt: number, endpoint?: string, tenant?: string): number {
    const base =
      endpoint !== undefined
        ? (this.adaptiveBackoffFor(tenant)?.baseFor(endpoint) ?? this.baseDelayMs)
        : this.baseDelayMs;
    const cap = Math.min(this.maxDelayMs, base * 2 ** attempt);
    if (this.jitterStrategy === "full") {
      return this.random() * cap;
    }
    const jitter = this.jitterMs > 0 ? this.random() * this.jitterMs : 0;
    return Math.min(this.maxDelayMs, base * 2 ** attempt + jitter);
  }

  /** Current backoff parameters (reflects any hot-reload updates). */
  retryConfig(): { baseDelayMs: number; maxDelayMs: number; maxAttempts: number; jitterMs: number; jitterStrategy: JitterStrategy } {
    return {
      baseDelayMs: this.baseDelayMs,
      maxDelayMs: this.maxDelayMs,
      maxAttempts: this.maxAttempts,
      jitterMs: this.jitterMs,
      jitterStrategy: this.jitterStrategy,
    };
  }

  /** Whether the circuit-breaker subsystem is enabled (queue-level). */
  circuitBreakerConfigured(): boolean {
    return this.circuitBreakerOpts !== undefined;
  }

  /** Whether the per-endpoint quota subsystem is enabled (queue-level). */
  quotaConfigured(): boolean {
    return this.quotaDeliveriesPerMinute !== undefined;
  }

  /**
   * Whether weighted dispatch is enabled for `endpoint`. Tenant-agnostic,
   * like `updateEndpointConfig`'s weighted path.
   */
  weightedHasEndpoint(endpoint: string): boolean {
    return this.weighted?.hasEndpoint(endpoint) ?? false;
  }

  /**
   * Effective hot-reloadable config for one (tenant, endpoint) — the
   * WR-88 snapshot read path. Reads the same effective values
   * `updateEndpointConfig` reports as `from`: overrides win over
   * defaults, and circuit-breaker/quota rows appear only when the
   * endpoint carries an override. Weighted targets appear when weighted
   * dispatch is enabled for the endpoint.
   */
  endpointConfig(tenant: string | undefined, endpoint: string): EndpointConfigState {
    const state: EndpointConfigState = {
      maxConcurrentPerEndpoint: this.limiterFor(tenant).maxFor(endpoint),
    };
    const breaker = this.breakerFor(tenant);
    if (breaker !== undefined && breaker.configuredEndpoints().includes(endpoint)) {
      const t = breaker.thresholdsFor(endpoint);
      state.circuitBreaker = { failureThreshold: t.failureThreshold, cooldownMs: t.cooldownMs };
    }
    const quota = this.quotaFor(tenant);
    if (quota !== undefined && quota.configuredEndpoints().includes(endpoint)) {
      state.quota = { deliveriesPerMinute: quota.limit(endpoint) };
    }
    const w = this.weighted?.stats().find((s) => s.endpoint === endpoint);
    if (w !== undefined) {
      state.weighted = {
        targets: w.targets.map((t) => ({ targetUrl: t.targetUrl, weight: t.weight })),
      };
    }
    return state;
  }

  /**
   * Every (tenant, endpoint) pair carrying config state — the WR-88
   * snapshot keyspace. Default-tenant rows omit `tenant`. Weighted
   * dispatch is endpoint-scoped (not per-tenant), so its rows are
   * tenant-less.
   */
  configuredEndpoints(): Array<{ tenant?: string; endpoint: string }> {
    const seen = new Set<string>();
    const out: Array<{ tenant?: string; endpoint: string }> = [];
    const add = (tenant: string | undefined, endpoint: string): void => {
      const key = `${tenant ?? ""}\n${endpoint}`;
      if (seen.has(key)) return;
      seen.add(key);
      out.push(tenant === undefined ? { endpoint } : { tenant, endpoint });
    };
    for (const [key, limiter] of this.limiters) {
      for (const endpoint of limiter.configuredEndpoints()) add(key === "" ? undefined : key, endpoint);
    }
    for (const [key, breaker] of this.breakers) {
      for (const endpoint of breaker.configuredEndpoints()) add(key === "" ? undefined : key, endpoint);
    }
    for (const [key, quota] of this.quotas) {
      for (const endpoint of quota.configuredEndpoints()) add(key === "" ? undefined : key, endpoint);
    }
    if (this.weighted !== undefined) {
      for (const s of this.weighted.stats()) add(undefined, s.endpoint);
    }
    return out;
  }

  /**
   * Which hot-reloadable fields carry an explicit runtime override for
   * one (tenant, endpoint) — the WR-88 apply rollback uses this to
   * restore the exact pre-apply override state (overrides that did not
   * exist are removed again, not frozen to their effective value).
   */
  endpointConfigOverrides(
    tenant: string | undefined,
    endpoint: string
  ): { maxConcurrentPerEndpoint: boolean; circuitBreaker: boolean; quota: boolean } {
    return {
      maxConcurrentPerEndpoint: this.limiterFor(tenant).hasEndpointOverride(endpoint),
      circuitBreaker: this.breakerFor(tenant)?.hasEndpointOverride(endpoint) ?? false,
      quota: this.quotaFor(tenant)?.hasEndpointOverride(endpoint) ?? false,
    };
  }

  /**
   * Drop one runtime override so the endpoint falls back to the queue
   * default. Used by the WR-88 apply rollback. Never throws for unknown
   * endpoints; `tenant` scopes to that tenant's instance (WR-48).
   */
  clearEndpointConfigOverride(
    tenant: string | undefined,
    endpoint: string,
    field: "maxConcurrentPerEndpoint" | "circuitBreaker" | "quota"
  ): void {
    if (field === "maxConcurrentPerEndpoint") {
      this.limiterFor(tenant).clearEndpointOverride(endpoint);
    } else if (field === "circuitBreaker") {
      this.breakerFor(tenant)?.clearEndpointOverride(endpoint);
    } else {
      this.quotaFor(tenant)?.clearEndpointOverride(endpoint);
    }
  }

  /**
   * Hot-reload one endpoint's delivery configuration at runtime (WR-32).
   *
   * The whole patch is validated first: an illegal value throws
   * `RangeError` and the previous configuration is left completely
   * intact (no partial application). Patching `circuitBreaker` or
   * `quota` while that subsystem is disabled also throws `RangeError`.
   *
   * Applied changes take effect immediately for all *future* scheduling
   * decisions — already-scheduled retry timers keep the delay they were
   * scheduled with, and in-flight deliveries are never revoked (a
   * lowered concurrency limit only gates new acquisitions). Returns the
   * before/after diff of every patched field, and reports it through
   * `onConfigChange` (audited by the server as `endpoint_config_updated`).
   */
  /**
   * Apply a runtime config patch to one endpoint (WR-32 hot reload).
   * WR-48: pass `tenant` to patch that tenant's instance; without it the
   * default tenant's instance is patched (pre-tenant behavior). Invalid
   * values throw `RangeError` and leave the current config intact.
   */
  updateEndpointConfig(endpoint: string, patch: EndpointConfigPatch = {}, tenant?: string): ConfigChange[] {
    if (typeof endpoint !== "string" || endpoint.length === 0) {
      throw new RangeError("updateEndpointConfig: endpoint must be a non-empty string");
    }
    assertValidEndpointConfigPatch(patch);
    const breaker = this.breakerFor(tenant);
    const quota = this.quotaFor(tenant);
    const limiter = this.limiterFor(tenant);
    if (patch.circuitBreaker !== undefined && breaker === undefined) {
      throw new RangeError("updateEndpointConfig: circuitBreaker is not enabled; cannot patch circuit thresholds");
    }
    if (patch.quota !== undefined && quota === undefined) {
      throw new RangeError("updateEndpointConfig: quota is not enabled; cannot patch quota limits");
    }

    const changes: ConfigChange[] = [];
    const rec = (field: string, from: unknown, to: unknown): void => {
      changes.push({ field, from, to });
    };

    if (patch.maxConcurrentPerEndpoint !== undefined) {
      rec("maxConcurrentPerEndpoint", limiter.maxFor(endpoint), patch.maxConcurrentPerEndpoint);
      limiter.setEndpointMax(endpoint, patch.maxConcurrentPerEndpoint);
    }
    if (patch.circuitBreaker !== undefined) {
      const before = breaker!.thresholdsFor(endpoint);
      if (patch.circuitBreaker.failureThreshold !== undefined) {
        rec("circuitBreaker.failureThreshold", before.failureThreshold, patch.circuitBreaker.failureThreshold);
      }
      if (patch.circuitBreaker.cooldownMs !== undefined) {
        rec("circuitBreaker.cooldownMs", before.cooldownMs, patch.circuitBreaker.cooldownMs);
      }
      breaker!.setEndpointThresholds(endpoint, patch.circuitBreaker);
    }
    if (patch.quota !== undefined && patch.quota.deliveriesPerMinute !== undefined) {
      rec("quota.deliveriesPerMinute", quota!.limit(endpoint), patch.quota.deliveriesPerMinute);
      quota!.setEndpointLimit(endpoint, patch.quota.deliveriesPerMinute);
    }
    if (patch.weighted !== undefined) {
      // WR-66: runtime weight retuning. The patch was validated
      // structurally by assertValidEndpointConfigPatch; setWeights
      // re-validates the full per-endpoint config before applying, so an
      // illegal list throws RangeError and leaves the running config
      // completely intact — zero partial application.
      if (this.weighted === undefined || !this.weighted.hasEndpoint(endpoint)) {
        throw new RangeError(
          "updateEndpointConfig: weighted dispatch is not enabled for this endpoint; cannot patch weights"
        );
      }
      const before = this.weighted.stats().find((s) => s.endpoint === endpoint);
      rec(
        "weighted.targets",
        before?.targets.map((t) => ({ targetUrl: t.targetUrl, weight: t.weight })) ?? [],
        patch.weighted.targets.map((t) => ({ targetUrl: t.targetUrl, weight: t.weight }))
      );
      this.weighted.setWeights(endpoint, patch.weighted.targets);
    }
    if (patch.retry !== undefined) {
      const r = patch.retry;
      const before = this.retryConfig();
      if (r.baseDelayMs !== undefined) {
        rec("retry.baseDelayMs", before.baseDelayMs, r.baseDelayMs);
        this.baseDelayMs = r.baseDelayMs;
      }
      if (r.maxDelayMs !== undefined) {
        rec("retry.maxDelayMs", before.maxDelayMs, r.maxDelayMs);
        this.maxDelayMs = r.maxDelayMs;
      }
      if (r.maxAttempts !== undefined) {
        rec("retry.maxAttempts", before.maxAttempts, r.maxAttempts);
        this.maxAttempts = r.maxAttempts;
      }
      if (r.jitterMs !== undefined) {
        rec("retry.jitterMs", before.jitterMs, r.jitterMs);
        this.jitterMs = r.jitterMs;
      }
      if (r.jitterStrategy !== undefined) {
        rec("retry.jitterStrategy", before.jitterStrategy, r.jitterStrategy);
        this.jitterStrategy = r.jitterStrategy;
      }
    }

    this.onConfigChange?.(endpoint, changes);
    return changes;
  }

  private schedule(id: string, delayMs: number): void {
    if (!this.running || !this.queue.has(id)) return;
    const entry = this.queue.get(id)!;
    // WR-50: a paused endpoint parks instead of arming a timer — the
    // item stays queued with its attempt count intact; `resumeEndpoint`
    // re-arms it with the recorded delay.
    if (this.pausedEndpoints.has(entry.targetUrl)) {
      const existing = this.timers.get(id);
      if (existing) {
        this.clearTimer(existing.handle);
        this.timers.delete(id);
      }
      this.armedNextAt.delete(id);
      this.park(id, delayMs);
      return;
    }
    const existing = this.timers.get(id);
    if (existing) {
      this.clearTimer(existing.handle);
    }
    const handle = this.setTimer(() => {
      this.timers.delete(id);
      this.armedNextAt.delete(id);
      this.durablePendingRetry.delete(id);
      const p = this.deliver(id);
      // `deliver` never rejects (sender errors are caught internally), but
      // track both outcomes so a bug can never leak a hanging shutdown.
      this.inFlight.add(p);
      p.then(
        () => this.inFlight.delete(p),
        () => this.inFlight.delete(p)
      );
    }, delayMs);
    this.timers.set(id, { handle });
    // WR-50: absolute fire time, so a pause mid-backoff can park the
    // item with its *remaining* delay.
    this.armedNextAt.set(id, Date.now() + Math.max(0, delayMs));
    // WR-49: every armed timer is journaled with its absolute fire time,
    // so a restart resumes the *remaining* backoff instead of restarting
    // it — and the consumed attempt count travels with it.
    if (this.durable !== undefined) {
      const nextAt = this.durableNow() + delayMs;
      this.durablePendingRetry.set(id, nextAt);
      this.durable.appendRetry(id, this.queue.get(id)?.attempt ?? 0, nextAt);
      this.compactDurable();
    }
  }

  /**
   * @param force bypass the `running` checks: used by `shutdown()` for the
   * one immediate attempt it grants flushed batches. A forced delivery that
   * needs to reschedule (retry, quota/circuit park) stays queued instead —
   * `schedule()` is a no-op once the queue is stopped.
   */
  private async deliver(id: string, force = false): Promise<void> {
    const entry = this.queue.get(id);
    if (!entry || (!this.running && !force)) return;
    // `enqueue()`/`enqueueNow()` guarantee every queued item carries a
    // trace ID, so it is safe to thread it through all downstream events.
    const traceId = entry.traceId as string;
    // WR-48: the tenant scopes the isolation primitives below (quota,
    // breaker, limiter, latency). `undefined` = the default tenant, which
    // keys plain endpoints exactly as before.
    const tenant = entry.tenantId;
    // WR-39: the logical endpoint (`entry.targetUrl`, the configured
    // primary) never changes on the queued item, so replays always
    // re-resolve against the *current* active target. `target` is the
    // physical target this attempt goes to; the sender gets a copy pinned
    // to it, so an in-flight delivery keeps its old target across a
    // mid-flight switch — switches never cancel or reroute in-flight work.
    // WR-66: weighted dispatch (opt-in per endpoint, mutually exclusive
    // with failover) resolves first; it returns undefined when the
    // endpoint has no weighted config, falling through to failover / the
    // endpoint itself.
    const logicalEndpoint = entry.targetUrl;
    const weightedTarget = this.weighted?.resolveTarget(logicalEndpoint);
    const target = weightedTarget ?? this.failover?.resolveTarget(logicalEndpoint) ?? logicalEndpoint;
    // WR-76: the end-to-end delivery deadline is checked before every
    // dispatch — ahead of the pause/window/quota/circuit gates, because
    // time parked behind any of them still counts toward the SLO (the
    // deadline is an end-to-end SLO, not a retry budget). When it fires
    // the item is audited and dead-lettered immediately with its *actual*
    // attempt count — no further backoff is scheduled and the remaining
    // retry budget is untouched. Items predating the feature (a journal
    // restored from before WR-76) have no admission instant: stamp it now
    // rather than expiring a just-restored delivery.
    if (entry.enqueuedAt === undefined) entry.enqueuedAt = this.deadlineNow();
    const deadlineMs = this.deliveryDeadlines?.get(logicalEndpoint);
    if (deadlineMs !== undefined) {
      const elapsedMs = this.deadlineNow() - entry.enqueuedAt;
      if (elapsedMs >= deadlineMs) {
        this.expireDeliveryDeadline(entry, id, traceId, tenant, logicalEndpoint, target, elapsedMs, deadlineMs);
        return;
      }
    }
    // WR-50: the pause lands before any gate is touched — a timer that
    // fired in the same tick as the pause parks instead of dispatching,
    // so a paused delivery consumes no quota token, no breaker verdict,
    // and no urgent-lane token. It was due now, so it resumes promptly.
    if (this.pausedEndpoints.has(logicalEndpoint)) {
      this.park(id, 0);
      return;
    }
    // WR-52: delivery time window ("quiet hours") — second only to the
    // manual pause. Outside a configured window the delivery is parked
    // until the window opens: it stays queued with its attempt count
    // intact and consumes nothing — no quota token, no breaker verdict,
    // no retry-budget token, no dead-letter. The re-schedule targets the
    // window's opening instant (inclusive open edge), so boundary races
    // resolve as "flush at window open".
    if (this.deliveryWindow !== undefined && !this.deliveryWindow.isOpen(logicalEndpoint)) {
      this.recordDeliveryWindowStat(tenant, logicalEndpoint);
      this.deliveryWindow.noteDelayed(logicalEndpoint);
      this.schedule(id, this.deliveryWindow.msUntilOpen(logicalEndpoint));
      return;
    }
    // Per-endpoint quota first: an exhausted budget delays the attempt
    // (rescheduled at the next token refill) instead of burning the retry
    // budget or tripping the circuit against a downstream we are
    // voluntarily throttling. A little jitter keeps many delayed items
    // from re-checking in lockstep. WR-48: the budget is per
    // (tenant, endpoint).
    const quota = this.quotaFor(tenant);
    if (quota && !quota.take(target)) {
      this.recordQuotaStat(tenant, target);
      this.schedule(id, quota.msUntilToken(target) + this.random() * 50);
      return;
    }
    let probe = false;
    const breaker = this.breakerFor(tenant);
    if (breaker) {
      const verdict = breaker.shouldAllow(target);
      if (!verdict.allowed) {
        // Circuit open (or its probe slot busy): park the attempt until the
        // cooldown elapses instead of burning the retry budget against a
        // known-down endpoint. A little jitter keeps many parked items from
        // re-checking in lockstep.
        this.circuitBlocked += 1;
        this.schedule(id, breaker.retryInMs(target) + this.random() * 100);
        return;
      }
      probe = verdict.probe;
    }
    // Fast-lane admission: every urgent attempt costs one token from the
    // endpoint's bucket. An empty bucket degrades the item to the normal
    // lane — the delivery still happens, just with exponential backoff —
    // so the lane can never be used to flood a downstream.
    if (entry.priority === "urgent" && !this.urgentLimiter.take(target)) {
      this.recordUrgentStat(target, "throttled");
      entry.priority = "normal";
    }
    const fastLane = entry.priority === "urgent";
    // WR-35 starvation guard: both lanes take a dispatch turn from the
    // deficit round-robin scheduler at the actual dispatch point, *before*
    // the concurrency limiter. Turn-first matters: the granted turn marks
    // the delivery as backlogged demand (see `undispatchedNormal`) from
    // grant time, so the scheduler never sees a transient "drained"
    // backlog while a normal delivery moves from the limiter queue to its
    // dispatch. The fast lane still bypasses the concurrency limiter below
    // (its bound stays the token bucket above — the gate adds no second
    // rate limit), but while normal deliveries are backlogged, urgent
    // turns are paced so normal keeps at least minNormalShare of dispatch
    // turns. Work-conserving: with no normal backlog an urgent turn is
    // granted immediately, and the normal lane is never delayed by the
    // gate at all.
    const releaseTurn = await this.laneScheduler.acquireTurn(
      target,
      fastLane ? "urgent" : "normal"
    );
    // The fast lane bypasses the per-endpoint concurrency limiter entirely:
    // an urgent delivery never waits behind queued normal deliveries. Its
    // own bound is the token bucket above. WR-48: the limiter is per
    // (tenant, endpoint).
    const release = fastLane ? undefined : await this.limiterFor(tenant).acquire(target);
    // WR-51: released by the finally below; undefined until the global
    // gate is acquired. Declared outside the try on purpose: besides
    // early bail-outs, Node v24.20.0 has a scope bug where a `const`
    // declared inside a `try` block is invisible in its `finally`
    // (ReferenceError, not TDZ) — hoisting is the workaround.
    let releaseGlobalSlot: (() => void) | undefined;
    try {
      // The queue may have stopped, or the item may have been settled, while
      // we waited for a turn or a concurrency slot. Bail out; the releases
      // cascade to the next waiters so nobody hangs.
      if ((!this.running && !force) || !this.queue.has(id)) {
        if (probe) breaker?.cancelProbe(target);
        return;
      }
      // WR-50: a pause that landed mid-wait parks the delivery instead of
      // dispatching it — no attempt is made, nothing is consumed, the
      // item stays queued for `resumeEndpoint`. (In-flight deliveries
      // are never cancelled; only future scheduling is held.)
      if (this.pausedEndpoints.has(logicalEndpoint)) {
        if (probe) breaker?.cancelProbe(target);
        this.park(id, 0);
        return;
      }
      // A normal dispatch earns the urgent lane its proportional deficit
      // (only while urgent demand is backlogged) — the DRR earning event.
      if (!fastLane) this.laneScheduler.recordNormalDispatch(target);
      // WR-51: relay-level global dispatch gate — the last acquisition
      // before the sender, so quota/circuit/budget verdicts and lane
      // ordering are all settled before a global slot is taken, and a
      // paused endpoint (checked above) never holds a slot while parked.
      // The urgent lane bypasses the per-endpoint limiter but NOT this
      // gate: the cap is relay-level capacity, not per-endpoint policy.
      releaseGlobalSlot = await this.globalGate.acquire();
      // The gate may have woken us via releaseWaiters() during
      // stop()/shutdown(), or the pause may have landed while we waited:
      // re-check liveness before touching the sender. The finally below
      // releases the slot on every path, exactly once.
      if ((!this.running && !force) || !this.queue.has(id)) {
        if (probe) breaker?.cancelProbe(target);
        return;
      }
      if (this.pausedEndpoints.has(logicalEndpoint)) {
        if (probe) breaker?.cancelProbe(target);
        this.park(id, 0);
        return;
      }
      // WR-85: the exact wire copy this attempt sends. Shadow targets
      // receive this same item (payload, headers, 0-based `attempt`
      // index) with only the `targetUrl` swapped, so an independent
      // sender copy rebuilds the identical wire request (signature,
      // idempotency key, compression). Captured before the attempt so
      // the failure path's `entry.attempt += 1` cannot leak into the
      // mirrored attempt number.
      const wireCopy: RetryItem = { ...entry, targetUrl: target };
      // WR-85: mirror-once guard — the success path mirrors right after
      // the sender settles, but a later throw in the same attempt (e.g.
      // a failed WR-37 response validation) lands in the catch below,
      // which mirrors failures: the flag keeps it exactly one mirror per
      // shadow target per attempt.
      let shadowMirrored = false;
      const mirrorShadow = (): void => {
        if (shadowMirrored) return;
        shadowMirrored = true;
        // Fire-and-forget: the main path never waits, and shadow
        // outcomes never touch retry / dead-letter / circuit / quota
        // bookkeeping or the main delivery counters.
        this.shadow?.mirror(logicalEndpoint, wireCopy, tenant, traceId, entry.attempt + 1);
      };
      try {
        // Pinned copy: the sender sees the physical target chosen above,
        // so a failover switch mid-flight cannot reroute this attempt.
        const response = await this.sender(wireCopy);
        // WR-85: the main attempt completed — mirror the wire copy to
        // the shadow targets.
        mirrorShadow();
        // WR-54: summarize the downstream response for the audit trail. A
        // `void` sender (no response visibility) yields an honest
        // all-"unavailable" summary — never fabricated numbers.
        const responseSummary = summarizeDownstreamResponse(response);
        if (this.responseBodyCapture && response !== undefined) {
          // Opt-in full body capture: sealed with the WR-11 encryptor
          // before it ever touches the audit log. The constructor
          // guarantees an encryptor exists when this flag is on.
          // WR-72: masking runs before sealing — the raw values never
          // reach the ciphertext.
          const encryptor = this.payloadEncryptor as PayloadEncryptor;
          responseSummary.capturedBody = encryptor.encrypt(
            this.maskResponseBody(target, response.body)
          );
        }
        // WR-37: the transport succeeded (2xx); the validator decides
        // whether the body actually means success. A failing verdict
        // becomes a SemanticDeliveryError, which the catch below treats
        // like any retryable delivery failure — classified "retryable",
        // so consecutive semantic failures trip the circuit breaker and
        // the accepted→delivered latency clock keeps running.
        const validator =
          this.endpointResponseValidators.get(target) ??
          this.endpointResponseValidators.get(logicalEndpoint) ??
          this.globalResponseValidator;
        if (validator !== undefined && response !== undefined) {
          let verdict: boolean | string;
          try {
            verdict = validator(response);
          } catch (verr) {
            // Fail-closed: a throwing validator never accidentally
            // blesses a response it could not evaluate.
            throw new SemanticDeliveryError(verr instanceof Error ? verr.message : String(verr));
          }
          if (verdict !== true) {
            throw new SemanticDeliveryError(
              typeof verdict === "string" && verdict.length > 0 ? verdict : "validator returned false"
            );
          }
        }
        breaker?.recordSuccess(target);
        // WR-59: a delivered attempt cools the endpoint's adaptive base
        // toward the floor.
        this.adaptiveBackoffFor(tenant)?.recordOutcome(target, true);
        this.failover?.recordOutcome(logicalEndpoint, target, true);
        // WR-66: an answering target is a healthy target — same rule as
        // failover; non_retryable delivery outcomes feed both routers so
        // their per-target health counters agree.
        this.weighted?.recordOutcome(logicalEndpoint, target, true);
        // WR-49: journal before the in-memory delete — a crash between the
        // two redelivers (at-least-once), never loses.
        if (this.durable !== undefined) {
          this.durable.appendDelivered(id);
          this.durablePendingRetry.delete(id);
          this.compactDurable();
        }
        this.queue.delete(id);
        this.bumpPending(entry.tenantId, entry.targetUrl, -1);
        this.armedNextAt.delete(id);
        this.recordDelivery(tenant, target, "delivered");
        if (fastLane) this.recordUrgentStat(target, "delivered");
        const latency = this.latencyFor(tenant);
        const latencyMs = latency?.recordDelivered(entry.id, target);
        if (latencyMs !== undefined) {
          // The histogram samples the same delivery the JSON latency stats
          // do — accepted→delivered, dead letters excluded by `discard()`.
          // WR-48: the histogram is per (tenant, endpoint).
          this.recordLatencySample(tenant, target, latencyMs);
        }
        if (latencyMs !== undefined && latency && latencyMs > latency.sloMs) {
          this.onSloMiss?.({
            id: entry.id,
            traceId,
            ...(tenant === undefined ? {} : { tenant }),
            endpoint: target,
            latencyMs,
            sloMs: latency.sloMs,
          });
        }
        // WR-71: one sample landed and the backlog shrank — re-evaluate
        // the SLO risk for the logical endpoint.
        this.evaluateSloRisk(tenant, entry.targetUrl);
        // The hooks see the physical target the delivery actually went to.
        this.onDelivered?.({ ...entry, targetUrl: target }, entry.attempt + 1, responseSummary);
        this.emitDeliveryEvent({
          type: "delivered",
          id: entry.id,
          traceId,
          ...(tenant === undefined ? {} : { tenant }),
          targetUrl: target,
          attempts: entry.attempt + 1,
          bytesOut: entry.payload.length,
          at: new Date().toISOString(),
        });
        // WR-47: terminal state — fire the completion receipt (opt-in).
        this.callbacker?.notifyDelivered({
          id: entry.id,
          traceId,
          tenantId: tenant,
          targetUrl: target,
          attempts: entry.attempt + 1,
        });
      } catch (err) {
        // WR-85: the main attempt completed as a failure — mirror the
        // same wire copy before any classification, retry scheduling, or
        // dead-letter handling; the shadow copy must never influence
        // those paths. `mirrorShadow` is idempotent per attempt (see
        // above).
        mirrorShadow();
        const classified = classifyFailure(err);
        const error = err instanceof Error ? err.message : String(err);
        const at = new Date().toISOString();
        if (err instanceof SemanticDeliveryError) {
          // WR-37: the downstream answered 2xx but the body said no.
          // Audited as `failed` with reason `semantic_failed`; the
          // failure then follows the normal retry / dead-letter /
          // circuit path below.
          this.onSemanticFailure?.({
            id: entry.id,
            traceId,
            ...(tenant === undefined ? {} : { tenant }),
            endpoint: target,
            attempts: entry.attempt + 1,
            reason: err.reason,
          });
        }
        if (classified.failureClass === "non_retryable") {
          // Poison payload (e.g. a 400 from the downstream): retrying can
          // never succeed, so dead-letter immediately instead of burning
          // the rest of the retry budget and the backoff clock. The
          // endpoint is *not* sick — it answered, it just said no — so the
          // circuit records a success rather than a failure (this also
          // settles a half-open probe exactly once, as the breaker
          // requires). Failover agrees: an answering target is a healthy
          // target.
          breaker?.recordSuccess(target);
          // WR-59: the downstream answered (poison payload, not a sick
          // endpoint) — cools the adaptive base like any success.
          this.adaptiveBackoffFor(tenant)?.recordOutcome(target, true);
          this.failover?.recordOutcome(logicalEndpoint, target, true);
          this.weighted?.recordOutcome(logicalEndpoint, target, true);
          this.recordDelivery(tenant, target, "failed");
          entry.attempt += 1;
          this.moveToDeadLetter(entry, id, err, classified, at, traceId, target);
          return;
        }
        breaker?.recordFailure(target);
        // WR-59: a retryable failure heats the endpoint's adaptive base
        // toward the ceiling.
        this.adaptiveBackoffFor(tenant)?.recordOutcome(target, false);
        this.failover?.recordOutcome(logicalEndpoint, target, false);
        this.weighted?.recordOutcome(logicalEndpoint, target, false);
        this.recordDelivery(tenant, target, "failed");
        entry.attempt += 1;
        if (entry.attempt >= this.maxAttempts) {
          this.moveToDeadLetter(entry, id, err, classified, at, traceId, target);
        } else {
          // A downstream-supplied `Retry-After` (429/503) wins over every
          // lane's own delay: ignoring the backpressure signal the
          // downstream explicitly sent would be perverse.
          let retryDelayMs = classified.retryAfterMs;
          if (retryDelayMs === undefined) {
            if (fastLane && this.urgentLimiter.take(target)) {
              // Skip the exponential backoff: fixed fast-lane retry delay.
              this.recordUrgentStat(target, "retried");
              retryDelayMs = this.urgentRetryDelayMs;
            } else {
              if (fastLane) {
                // Fast-lane retry would exceed the endpoint's urgent rate:
                // degrade to normal backoff instead of dropping the delivery.
                this.recordUrgentStat(target, "throttled");
                entry.priority = "normal";
              }
              retryDelayMs = this.delayForAttempt(entry.attempt, target, tenant);
            }
          }
          this.recordDelivery(tenant, target, "retried");
          this.emitDeliveryEvent({
            type: "retrying",
            id: entry.id,
            traceId,
            ...(tenant === undefined ? {} : { tenant }),
            targetUrl: target,
            attempts: entry.attempt,
            bytesOut: entry.payload.length,
            at,
            error,
          });
          // WR-38: gate every newly scheduled retry on the global retry
          // budget. When the budget is exhausted the retry is parked
          // until the next token refill instead of joining a retry
          // storm: the failure above was already accounted (attempt +
          // circuit), and the parking itself is neutral — it consumes
          // neither another attempt, a budget token, nor a circuit
          // event. Retries resume automatically when the budget refills.
          let scheduledDelayMs = retryDelayMs;
          // WR-50: a retry for a paused endpoint parks without touching
          // the global budget — `schedule()` below parks it, and the
          // parking itself must consume neither a budget token, another
          // attempt, nor a circuit event.
          if (
            this.retryBudget !== undefined &&
            !this.pausedEndpoints.has(logicalEndpoint) &&
            !this.retryBudget.take()
          ) {
            const waitMs = this.retryBudget.msUntilToken() + this.random() * 50;
            this.retryBudgetDepleted += 1;
            this.onRetryBudgetDepleted?.({
              id: entry.id,
              traceId,
              ...(tenant === undefined ? {} : { tenant }),
              endpoint: target,
              attempts: entry.attempt,
              waitMs: Math.max(0, Math.round(waitMs)),
            });
            scheduledDelayMs = waitMs;
          }
          // WR-43: report the failure after the final delay is known, so
          // the audited `retrying` line carries the true scheduled delay
          // (budget parking included).
          this.onAttemptFailed?.({
            id: entry.id,
            traceId,
            ...(tenant === undefined ? {} : { tenant }),
            endpoint: target,
            attempts: entry.attempt,
            error,
            nextDelayMs: Math.max(0, Math.round(scheduledDelayMs)),
          });
          this.schedule(id, scheduledDelayMs);
        }
      }
    } finally {
      // WR-51: the global slot brackets the attempt exactly — released
      // once the attempt has settled (success, failure-scheduled, or
      // dead-lettered), handing it to the oldest waiter. Outermost
      // resource first, then the turn and the limiter slot as before.
      // Undefined when the gate was never acquired (early bail-out):
      // nothing to release.
      releaseGlobalSlot?.();
      // Released in reverse acquisition order: the turn first, so the
      // scheduler still sees the limiter-queued successor as backlogged
      // (no transient dip that would work-conservingly release every
      // parked urgent turn one dispatch early), then the limiter slot.
      // Releasing the turn re-runs the lane scheduler: parked urgent
      // turns may have become affordable, and a drained normal backlog
      // releases them all (work-conserving).
      releaseTurn();
      release?.();
    }
  }

  /**
   * WR-76: expire one delivery whose end-to-end deadline passed before
   * its next dispatch. The expiry is audited (`delivery_deadline_exceeded`
   * via the hook — the server writes the audit event), counted in
   * `relay_delivery_deadline_exceeded_total`, and the item moves straight
   * to the dead-letter list with its actual attempt count: no backoff is
   * scheduled, no retry budget is consumed, and no circuit verdict is
   * recorded (the endpoint was never attempted — there is no failure
   * signal to feed the breaker). The dead-letter entry carries a normal
   * `deadLetteredAt`, so it participates in the WR-64 retention sweep
   * like any other dead letter.
   */
  private expireDeliveryDeadline(
    entry: RetryItem & { attempt: number },
    id: string,
    traceId: string,
    tenant: string | undefined,
    logicalEndpoint: string,
    target: string,
    elapsedMs: number,
    deadlineMs: number
  ): void {
    const at = new Date().toISOString();
    const err = new DeliveryDeadlineExceededError(logicalEndpoint, elapsedMs, deadlineMs);
    const inner = innerFor(this.deliveryDeadlineExceeded, tenant);
    inner.set(logicalEndpoint, (inner.get(logicalEndpoint) ?? 0) + 1);
    this.onDeliveryDeadlineExceeded?.({
      id: entry.id,
      traceId,
      ...(tenant === undefined ? {} : { tenant }),
      endpoint: logicalEndpoint,
      attempts: entry.attempt,
      elapsedMs: Math.max(0, Math.round(elapsedMs)),
      deadlineMs,
    });
    // Classified "retryable": the payload was not poison — the relay
    // simply ran out of SLO — so the dead-letter record reads honestly.
    this.moveToDeadLetter(entry, id, err, { failureClass: "retryable" }, at, traceId, target);
  }

  /**
   * Move `entry` to the dead-letter list, recording the failure
   * classification so operators can tell poison payloads (`"non_retryable"`,
   * dead-lettered on the first attempt) from exhausted transient failures
   * (`"retryable"`). Shared by the poison fast path and the
   * budget-exhausted path above.
   */
  private moveToDeadLetter(
    entry: RetryItem & { attempt: number },
    id: string,
    err: unknown,
    classified: ClassifiedFailure,
    at: string,
    traceId: string,
    target: string
  ): void {
    const error = err instanceof Error ? err.message : String(err);
    const encryptedPayload = this.payloadEncryptor?.encrypt(entry.payload);
    // The dead letter records the physical target the final attempt went
    // to; `failoverEndpoint` remembers the logical endpoint so a replay
    // re-resolves against the *current* active target instead of pinning
    // to the standby.
    const logicalEndpoint = entry.targetUrl;
    const dlEntry: DeadLetterEntry = {
      id: entry.id,
      traceId,
      // Sealed at rest when an encryptor is configured; kept in the
      // clear otherwise (existing behavior).
      payload: encryptedPayload ? Buffer.alloc(0) : entry.payload,
      targetUrl: target,
      headers: entry.headers,
      // Kept so a replayed item re-enters the same delivery lane.
      priority: entry.priority,
      // WR-48: kept so a replay re-enters the same tenant's isolation
      // scope (breaker/quota/limiter instances).
      ...(entry.tenantId !== undefined ? { tenantId: entry.tenantId } : {}),
      attempts: entry.attempt,
      lastError: error,
      failureClass: classified.failureClass,
      deadLetteredAt: new Date().toISOString(),
      payloadBytes: entry.payload.length,
      ...(encryptedPayload ? { encryptedPayload } : {}),
      ...(logicalEndpoint !== target ? { failoverEndpoint: logicalEndpoint } : {}),
    };
    // WR-49: journal before the in-memory mutation — a crash between the
    // two leaves the dead letter recoverable, never lost.
    if (this.durable !== undefined) {
      this.durable.appendDeadLetter(dlEntry);
      this.durablePendingRetry.delete(id);
      this.compactDurable();
    }
    this.queue.delete(id);
    this.bumpPending(entry.tenantId, entry.targetUrl, -1);
    this.armedNextAt.delete(id);
    this.recordDelivery(entry.tenantId, target, "deadLetter");
    // Never delivered: drop the pending clock without sampling.
    this.latencyFor(entry.tenantId)?.discard(entry.id);
    this.deadLetter.push(dlEntry);
    // WR-54: the last attempt's response summary — only the status code
    // survives (from the failing HTTP response); a failed attempt has no
    // usable body and no meaningful TTFB, so those stay "unavailable".
    const responseSummary = summarizeDeadLetterFailure(err);
    this.onDeadLetter?.({ ...entry, targetUrl: target }, entry.attempt, err, classified.failureClass, responseSummary);
    this.emitDeliveryEvent({
      type: "dead_letter",
      id: entry.id,
      traceId,
      ...(entry.tenantId === undefined ? {} : { tenant: entry.tenantId }),
      targetUrl: target,
      attempts: entry.attempt,
      bytesOut: entry.payload.length,
      at,
      error,
    });
    // WR-47: terminal state — fire the completion receipt (opt-in).
    this.callbacker?.notifyDeadLetter({
      id: entry.id,
      traceId,
      tenantId: entry.tenantId,
      targetUrl: target,
      attempts: entry.attempt,
      error,
    });
  }

  /** Per-(tenant, endpoint) concurrency snapshot: in-flight and queued deliveries. Rows carry `tenant` only when set. */
  getConcurrencyStats(): Array<{ endpoint: string; tenant?: string; inFlight: number; queued: number }> {
    const out: Array<{ endpoint: string; tenant?: string; inFlight: number; queued: number }> = [];
    for (const [key, limiter] of this.limiters) {
      const tenant = key === "" ? undefined : key;
      for (const row of limiter.stats()) {
        out.push(tenant === undefined ? row : { ...row, tenant });
      }
    }
    return out;
  }

  /**
   * Relay-level global dispatch gate snapshot (WR-51): the configured
   * cap, current in-flight dispatches, FIFO waiters queued for a slot,
   * and the cumulative waiter count (also exported as
   * `relay_global_concurrency_wait_total` in the Prometheus exposition
   * when the cap is configured).
   */
  getGlobalConcurrencyStats(): GlobalConcurrencyStats {
    return this.globalGate.stats();
  }

  /**
   * Per-endpoint urgent-lane counters (`delivered` / `retried` /
   * `throttled`). Empty when no urgent delivery has been attempted.
   */
  getUrgentStats(): UrgentStats[] {
    return [...this.urgentStats.entries()].map(([endpoint, s]) => ({ endpoint, ...s }));
  }

  /**
   * WR-85: per-(tenant, endpoint, shadow target) mirror counters
   * (`delivered` / `failed`). Empty when the feature is off or no shadow
   * copy has landed yet. Also rendered as `relay_shadow_total` in
   * `renderMetrics()`.
   */
  getShadowStats(): ShadowTargetStats[] {
    return this.shadow?.stats() ?? [];
  }

  /**
   * Install the runtime loop check for completion callbacks (WR-47). The
   * server derives the predicate from the actually bound listen address,
   * so a callback URL that resolves to this relay — even one not declared
   * in `selfOrigins` — is refused before every receipt POST. No-op when
   * completion callbacks are not configured.
   */
  setCompletionCallbackSelfCheck(fn: (url: string) => boolean): void {
    this.callbacker?.setSelfCheck(fn);
  }

  /**
   * Per-endpoint lane-scheduler counters (WR-35 starvation guard):
   * effective `minNormalShare`, dispatch turns granted to each lane, and
   * guard activation episodes. Empty when no delivery has taken a turn yet.
   */
  getLaneStats(): LaneStats[] {
    return this.laneScheduler.stats();
  }

  /**
   * Override the starvation-guard minimum normal share for one endpoint at
   * runtime (WR-35). Invalid values throw `RangeError` and leave the
   * current share intact.
   */
  setEndpointMinNormalShare(endpoint: string, minNormalShare: number): void {
    this.laneScheduler.setEndpointMinNormalShare(endpoint, minNormalShare);
  }

  /**
   * Per-(tenant, endpoint) accepted→delivered latency distribution
   * (p50/p95/p99) plus SLO attainment. Empty when latency tracking is
   * disabled or no delivery has completed yet. With `endpoint` set, only
   * that endpoint is returned; with `tenant` set, only that tenant's
   * rows. Rows carry `tenant` only when set.
   */
  getLatencyStats(endpoint?: string, tenant?: string): EndpointLatencyStats[] {
    const out: EndpointLatencyStats[] = [];
    for (const [key, tracker] of this.latencies) {
      if (tenant !== undefined && key !== tenant) continue;
      const t = key === "" ? undefined : key;
      for (const row of tracker.stats(endpoint)) {
        out.push(t === undefined ? row : { ...row, tenant: t });
      }
    }
    return out;
  }

  /**
   * WR-71: per-(tenant, endpoint) SLO-risk snapshot — one row per endpoint
   * with at least one risk evaluation (endpoints still in cold start are
   * omitted). Rows carry `tenant` only when set. Empty when the predictor
   * is disabled or nothing has been evaluated yet.
   */
  getSloRiskStats(tenant?: string): SloRiskStatsRow[] {
    const out: SloRiskStatsRow[] = [];
    for (const [key, predictor] of this.sloRisks) {
      if (tenant !== undefined && key !== tenant) continue;
      const t = key === "" ? undefined : key;
      for (const row of predictor.snapshot()) {
        out.push(t === undefined ? row : { ...row, tenant: t });
      }
    }
    return out;
  }

  /**
   * Prometheus text exposition of the collected metrics (see
   * `src/metrics.ts`): per-endpoint delivery counters
   * (`relay_deliveries_total`), circuit gauges for endpoints that tripped
   * (`relay_endpoint_circuit_state`), the accepted→delivered latency
   * histogram (`relay_delivery_latency_seconds_*`) when latency tracking
   * is enabled, and the downstream health-probe series
   * (`relay_probe_total`, `relay_probe_consecutive_failures`) when
   * probing is enabled, and the starvation-guard activation counter
   * (`relay_starvation_guard_activations`) for endpoints where the WR-35
   * lane guard engaged, and the global retry-budget depletion counter
   * (`relay_retry_budget_depleted_total`) when the WR-38 budget is enabled,
   * and the global-concurrency wait counter
   * (`relay_global_concurrency_wait_total`) when the WR-51 cap is
   * configured, and the scheduled-delivery counters
   * (`relay_scheduled_total`, `relay_scheduled_due_total`,
   * `relay_scheduled_canceled_total`) once a delivery has actually been
   * parked for a future deliver_at (WR-57), and the SLO-risk headroom gauge
   * (`relay_slo_risk_seconds`) for endpoints currently elevated by the
   * WR-71 predictor.
   */
  renderMetrics(): string {
    // WR-48: counters are keyed by (tenant, endpoint); the tenant becomes
    // a series label only when set, so the default tenant's exposition is
    // byte-identical to the pre-tenant relay.
    const deliveries: DeliveryCountersInput[] = [];
    for (const [tenantKey, inner] of this.deliveryCounters) {
      const tenant = tenantKey === "" ? undefined : tenantKey;
      for (const [endpoint, c] of inner) {
        deliveries.push({
          endpoint,
          ...(tenant === undefined ? {} : { tenant }),
          delivered: c.delivered,
          failed: c.failed,
          retried: c.retried,
          deadLetter: c.deadLetter,
        });
      }
    }
    const circuits: CircuitStateInput[] = [];
    for (const [tenantKey, inner] of this.circuitStates) {
      const tenant = tenantKey === "" ? undefined : tenantKey;
      for (const [endpoint, state] of inner) {
        circuits.push({ endpoint, ...(tenant === undefined ? {} : { tenant }), state });
      }
    }
    const latencyHistograms: LatencyHistogramInput[] = [];
    if (this.latencyOpts !== undefined) {
      for (const [tenantKey, inner] of this.latencyHist) {
        const tenant = tenantKey === "" ? undefined : tenantKey;
        for (const [endpoint, h] of inner) {
          const bucketCounts: number[] = [];
          let cumulative = 0;
          for (const n of h.counts) {
            cumulative += n;
            bucketCounts.push(cumulative);
          }
          latencyHistograms.push({
            endpoint,
            ...(tenant === undefined ? {} : { tenant }),
            bucketBounds: this.histBucketsMs.map((b) => b / 1000),
            bucketCounts,
            sum: h.sumMs / 1000,
            count: h.count,
          });
        }
      }
    }
    const probes: ProbeMetricsInput[] = (this.prober?.stats() ?? []).map((s) => ({
      endpoint: s.endpoint,
      success: s.success,
      failure: s.failure,
      consecutiveFailures: s.consecutiveFailures,
    }));
    // Only endpoints where the guard actually engaged get a series (the
    // same convention as the circuit-state gauge).
    const starvationGuard: StarvationGuardMetricsInput[] = this.laneScheduler
      .stats()
      .filter((s) => s.guardActivations > 0)
      .map((s) => ({ endpoint: s.endpoint, activations: s.guardActivations }));
    // WR-39: one series per (endpoint, from, to) triple that actually
    // switched; absent entirely when failover is unconfigured or never
    // fired.
    const failover: FailoverMetricsInput[] = [...this.failoverSwitchCounts.values()];
    // WR-66: one series per (endpoint, target) pair that actually
    // received a dispatch; absent entirely when weighted mode is not in
    // use. The dispatcher's own cumulative counts are the source — the
    // queue does not keep a parallel counter.
    const weighted: WeightedMetricsInput[] = (this.weighted?.stats() ?? []).flatMap((s) =>
      s.targets
        .filter((t) => t.dispatched > 0)
        .map((t) => ({ endpoint: s.endpoint, target: t.targetUrl, dispatched: t.dispatched }))
    );
    // WR-57: the scheduled-delivery counters appear once a delivery has
    // actually been parked — activity-gated, like the starvation-guard
    // series, so an untouched relay's exposition is unchanged.
    const scheduledStats = this.scheduler.stats();
    // WR-71: one gauge series per currently elevated (tenant, endpoint) —
    // activity-gated the same way, so a relay that never predicted risk
    // exposes no `relay_slo_risk_seconds` series at all.
    const sloRisk: SloRiskMetricsInput[] = [];
    for (const [tenantKey, predictor] of this.sloRisks) {
      const tenant = tenantKey === "" ? undefined : tenantKey;
      for (const row of predictor.atRisk()) {
        sloRisk.push({
          endpoint: row.endpoint,
          ...(tenant === undefined ? {} : { tenant }),
          headroomSeconds: row.headroomSeconds,
        });
      }
    }
    // WR-76: per-(tenant, endpoint) deadline expirations, in first-seen
    // order — activity-gated, so the series stays absent until a
    // deadline actually expires.
    const deliveryDeadlineExceeded: DeliveryDeadlineExceededInput[] = [];
    for (const [tenantKey, inner] of this.deliveryDeadlineExceeded) {
      const tenant = tenantKey === "" ? undefined : tenantKey;
      for (const [endpoint, exceeded] of inner) {
        deliveryDeadlineExceeded.push({
          endpoint,
          ...(tenant === undefined ? {} : { tenant }),
          exceeded,
        });
      }
    }
    // WR-85: one series per (tenant, endpoint, shadow target) that has
    // actually received a mirrored copy — activity-gated, so the series
    // stays absent until the first shadow delivery lands.
    const shadow: ShadowMetricsInput[] = (this.shadow?.stats() ?? []).map((s) => ({
      endpoint: s.endpoint,
      ...(s.tenant === undefined ? {} : { tenant: s.tenant }),
      shadowTarget: s.shadowTarget,
      delivered: s.delivered,
      failed: s.failed,
    }));
    return renderPrometheus({
      deliveries,
      circuits,
      latencyHistograms,
      probes,
      starvationGuard,
      failover,
      // WR-66: activity-gated (see above) — weighted mode's series stay
      // absent until a dispatch has actually been weighted.
      ...(weighted.length > 0 ? { weighted } : {}),
      ...(this.retryBudget !== undefined ? { retryBudgetDepleted: this.retryBudgetDepleted } : {}),
      // WR-51: the wait counter is exposed only when the cap is
      // configured (finite) — the default unlimited gate never waits,
      // so the series stays absent exactly like the other opt-in
      // counters.
      ...(this.globalMaxConcurrent !== Infinity
        ? { globalConcurrencyWaits: this.globalGate.waitedTotal() }
        : {}),
      // WR-57: activity-gated (see above).
      ...(scheduledStats.scheduled > 0
        ? {
            scheduled: {
              scheduled: scheduledStats.scheduled,
              due: scheduledStats.due,
              canceled: scheduledStats.canceled,
            },
          }
        : {}),
      // WR-71: activity-gated (see above) — the gauge appears only while
      // at least one endpoint is elevated.
      ...(sloRisk.length > 0 ? { sloRisk } : {}),
      // WR-76: activity-gated (see above).
      ...(deliveryDeadlineExceeded.length > 0 ? { deliveryDeadlineExceeded } : {}),
      // WR-85: activity-gated (see above).
      ...(shadow.length > 0 ? { shadow } : {}),
      // WR-83: enabled-gated — the OTLP series appear only when OTLP
      // export is configured, exactly like the probe series.
      ...(this.otlpExporter !== undefined
        ? {
            otlp: {
              exports: this.otlpExporter.exportCounts().map((c) => ({
                eventType: c.eventType,
                status: c.status,
                count: c.count,
              })),
              buffered: this.otlpExporter.stats().buffered,
            },
          }
        : {}),
    });
  }

  /**
   * Per-(tenant, endpoint) circuit state (`state`, `consecutiveFailures`,
   * `trips`). Empty when the circuit breaker is disabled. Rows carry
   * `tenant` only when set.
   */
  getCircuitStats(): CircuitStats[] {
    const out: CircuitStats[] = [];
    for (const [key, breaker] of this.breakers) {
      const tenant = key === "" ? undefined : key;
      for (const row of breaker.stats()) {
        out.push(tenant === undefined ? row : { ...row, tenant });
      }
    }
    return out;
  }

  /**
   * WR-39: per-endpoint failover state (`activeTarget`, `targets`,
   * `switches`, `consecutiveFailures`). Empty when failover is not
   * configured.
   */
  getFailoverStats(): FailoverEndpointStats[] {
    return this.failover?.stats() ?? [];
  }

  /**
   * WR-39: manually return `endpoint` to its primary target (clears a
   * pending failback canary and the failure count). Returns false when
   * the endpoint has no failover config. A switch that actually moves
   * traffic is audited as `failover_switched` with reason `"manual"`.
   */
  resetFailover(endpoint: string): boolean {
    return this.failover?.resetFailover(endpoint) ?? false;
  }

  /**
   * WR-66: per-endpoint weighted dispatch state — per-target
   * `{ weight, effectiveWeight, dispatched, consecutiveFailures,
   * healthy }` in config order. Empty when weighted dispatch is not
   * configured.
   */
  getWeightedStats(): WeightedEndpointStats[] {
    return this.weighted?.stats() ?? [];
  }

  /**
   * Per-(tenant, endpoint) delivery-window counters (WR-52): `delayed` —
   * deliveries parked outside the endpoint's window until it opened —
   * plus the configured window spec and whether the window is open at
   * the injected clock's current time. Empty when the feature is disabled
   * or no attempt has been parked yet. Rows carry `tenant` only when set.
   */
  getDeliveryWindowStats(): DeliveryWindowStats[] {
    const rows: DeliveryWindowStats[] = [];
    for (const [tenantKey, inner] of this.deliveryWindowStats) {
      const tenant = tenantKey === "" ? undefined : tenantKey;
      for (const [endpoint, delayed] of inner) {
        const spec = this.deliveryWindow?.specFor(endpoint);
        rows.push({
          endpoint,
          ...(tenant === undefined ? {} : { tenant }),
          window: spec?.raw ?? "",
          delayed,
          open: this.deliveryWindow?.isOpen(endpoint) ?? true,
        });
      }
    }
    return rows;
  }

  /**
   * WR-52: set (or replace) the delivery window for one endpoint at
   * runtime — the same hot-reload convention as the other per-endpoint
   * overrides. An invalid spec or a non-string/empty endpoint throws
   * `RangeError` and leaves the current window intact. Returns `false`
   * when the delivery-window feature is disabled.
   */
  setEndpointDeliveryWindow(endpoint: string, spec: string): boolean {
    if (this.deliveryWindow === undefined) return false;
    this.deliveryWindow.setEndpointWindow(endpoint, spec);
    return true;
  }

  /**
   * WR-52: remove the delivery window for one endpoint at runtime — it
   * becomes always deliverable. Returns `false` when the feature is
   * disabled or no window was configured.
   */
  deleteEndpointDeliveryWindow(endpoint: string): boolean {
    return this.deliveryWindow?.deleteEndpointWindow(endpoint) ?? false;
  }

  /** Attempts parked because the endpoint's circuit was open. */
  circuitBlockedCount(): number {
    return this.circuitBlocked;
  }

  /**
   * Pause deliveries to `endpoint` (WR-50 operator switch).
   *
   * From this point on, deliveries to the endpoint are parked: queued
   * items stay queued (attempt counts untouched), no delivery attempt is
   * scheduled, no retry budget is consumed, the circuit breaker is not
   * touched, and nothing moves to dead-letter. Newly accepted events for
   * the endpoint park as well. Armed backoff timers are disarmed and
   * re-parked with their remaining delay; a delivery already in flight
   * is *not* cancelled — it settles normally.
   *
   * The endpoint does not need to be known: pausing a never-seen endpoint
   * is allowed and pre-emptive — any future delivery to it parks
   * immediately (useful to hold a downstream before a deploy). Pause is
   * keyed by the logical `targetUrl` and applies across tenants.
   *
   * Idempotent: pausing an already-paused endpoint is a no-op returning
   * `false` (no duplicate audit event). Returns `true` on a real
   * transition. An empty/non-string endpoint throws `RangeError`.
   */
  pauseEndpoint(endpoint: string): boolean {
    assertValidPauseEndpoint(endpoint, "pauseEndpoint");
    if (this.pausedEndpoints.has(endpoint)) return false;
    this.pausedEndpoints.add(endpoint);
    // Disarm armed backoff timers and park them with their remaining
    // delay. Items without an armed timer are either inside `deliver()`
    // — they park themselves at the pause checks there — or the queue
    // is stopped, in which case `start()` parks everything pause-aware.
    // (A delivery already past the pause checks keeps its attempt: the
    // pause holds future scheduling, it never cancels in-flight work.)
    for (const [id, t] of this.timers) {
      const entry = this.queue.get(id);
      if (entry === undefined || entry.targetUrl !== endpoint) continue;
      this.clearTimer(t.handle);
      this.timers.delete(id);
      // A backoff interrupted mid-window resumes with its *remaining*
      // delay, not a restarted one.
      this.parked.set(id, this.armedNextAt.get(id) ?? Date.now());
      this.armedNextAt.delete(id);
    }
    this.onEndpointPaused?.({ endpoint });
    return true;
  }

  /**
   * Resume deliveries to `endpoint` (WR-50 operator switch). Parked items
   * automatically resume scheduling with their remaining delays and
   * their original attempt counts — the pause froze their lifecycle, it
   * did not reset it.
   *
   * Idempotent: resuming a non-paused endpoint is a no-op returning
   * `false`. Returns `true` on a real transition. An empty/non-string
   * endpoint throws `RangeError`.
   */
  resumeEndpoint(endpoint: string): boolean {
    assertValidPauseEndpoint(endpoint, "resumeEndpoint");
    if (!this.pausedEndpoints.delete(endpoint)) return false;
    const now = Date.now();
    for (const [id, nextAt] of this.parked) {
      const entry = this.queue.get(id);
      if (entry === undefined || entry.targetUrl !== endpoint) {
        // Settled (or another endpoint's) while parked: drop the stale record.
        if (entry === undefined) this.parked.delete(id);
        continue;
      }
      this.parked.delete(id);
      if (this.running) {
        this.schedule(id, Math.max(0, nextAt - now));
      }
      // Stopped: `start()` schedules every queued item, so nothing to do.
    }
    this.onEndpointResumed?.({ endpoint });
    return true;
  }

  /** Currently paused endpoints, in pause order. Empty when nothing is paused. */
  getPausedEndpoints(): string[] {
    return [...this.pausedEndpoints];
  }

  /** True when `endpoint` is currently paused (WR-50). */
  isEndpointPaused(endpoint: string): boolean {
    return this.pausedEndpoints.has(endpoint);
  }

  /**
   * Park `id` instead of arming a retry timer: record its absolute
   * next-dispatch time so `resumeEndpoint` can continue the original
   * backoff window. Any armed timer must already be cleared by the
   * caller (`pauseEndpoint` disarms; `schedule()` clears-then-parks).
   */
  private park(id: string, delayMs: number): void {
    this.parked.set(id, Date.now() + Math.max(0, delayMs));
  }

  /**
   * Per-(tenant, endpoint) quota counters (`delayed`). Empty when the quota
   * is disabled or no attempt has been delayed yet. Rows carry `tenant`
   * only when set.
   */
  getQuotaStats(): QuotaStats[] {
    const rows: QuotaStats[] = [];
    for (const [tenantKey, inner] of this.quotaStats) {
      const tenant = tenantKey === "" ? undefined : tenantKey;
      for (const [endpoint, delayed] of inner) {
        rows.push(tenant === undefined ? { endpoint, delayed } : { endpoint, tenant, delayed });
      }
    }
    return rows;
  }

  /**
   * Global retry budget (WR-38) snapshot. `undefined` when the budget is
   * disabled; otherwise the configured per-minute budget and the number
   * of retries parked because the budget was exhausted.
   */
  getRetryBudgetStats(): RetryBudgetStats | undefined {
    return this.retryBudget === undefined
      ? undefined
      : { retriesPerMinute: this.retryBudget.limit(), depleted: this.retryBudgetDepleted };
  }

  /**
   * WR-59: per-(tenant, endpoint) adaptive backoff state — the current
   * backoff base each endpoint's recent outcomes have earned. `undefined`
   * when adaptive backoff is disabled. Rows carry `tenant` only when set.
   * Endpoints with no recorded outcomes are absent: they use the resting
   * base (`baseDelayMs`, hot-reload aware).
   */
  getAdaptiveBackoffStats(): AdaptiveBackoffEndpointStats[] | undefined {
    if (this.adaptiveBackoffOpts === undefined) return undefined;
    const rows: AdaptiveBackoffEndpointStats[] = [];
    for (const [tenantKey, controller] of this.adaptiveBackoffs) {
      const tenant = tenantKey === "" ? undefined : tenantKey;
      for (const row of controller.stats()) {
        rows.push(tenant === undefined ? row : { ...row, tenant });
      }
    }
    return rows;
  }

  /** Durable delivery queue (WR-49) snapshot. */
  getDurableQueueStats(): DurableQueueStats {
    return {
      enabled: this.durable !== undefined,
      ...(this.durableDir !== undefined ? { dir: this.durableDir } : {}),
      liveItems: this.queue.size,
      deadLetters: this.deadLetter.length,
      journalAppends: this.durable?.appends ?? 0,
      journalWriteErrors: this.durable?.errors ?? 0,
      restoredItems: this.durableRestoredItems,
      restoredDeadLetters: this.durableRestoredDeadLetters,
      skippedLines: this.durableSkippedLines,
    };
  }

  /**
   * Rewrite the journal down to live state when superseded lines have
   * piled up (amortized), or unconditionally with `force`. Builds the
   * live set from the in-memory queue, so items journaled after the last
   * recovery are never dropped.
   */
  private compactDurable(force = false): void {
    const d = this.durable;
    if (d === undefined || (!force && !d.shouldCompact)) return;
    const items: CompactItem[] = [];
    for (const entry of this.queue.values()) {
      const nextAt = this.durablePendingRetry.get(entry.id);
      items.push({
        id: entry.id,
        payload: entry.payload,
        targetUrl: entry.targetUrl,
        headers: entry.headers,
        priority: entry.priority,
        traceId: entry.traceId,
        tenantId: entry.tenantId,
        attempt: entry.attempt,
        // WR-76: the deadline clock survives compaction restarts.
        ...(entry.enqueuedAt !== undefined ? { enqueuedAt: entry.enqueuedAt } : {}),
        ...(nextAt !== undefined ? { nextAt } : {}),
      });
    }
    d.compact(items, [...this.deadLetter], force);
  }
}

/** Durable delivery queue (WR-49) snapshot; see `getDurableQueueStats`. */
export interface DurableQueueStats {
  enabled: boolean;
  dir?: string;
  liveItems: number;
  deadLetters: number;
  journalAppends: number;
  journalWriteErrors: number;
  restoredItems: number;
  restoredDeadLetters: number;
  skippedLines: number;
}
