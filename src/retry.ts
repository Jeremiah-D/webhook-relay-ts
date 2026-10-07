import { EndpointCircuitBreaker, type CircuitBreakerOptions, type CircuitState, type CircuitStats } from "./circuit.ts";
import type { EncryptedPayload, PayloadEncryptor } from "./encrypt.ts";
import {
  LatencyTracker,
  type EndpointLatencyStats,
  type LatencyTrackerOptions,
} from "./latency.ts";
import { EndpointQuota, type QuotaOptions, type QuotaStats } from "./quota.ts";
import {
  BatchCollector,
  newBatchId,
  resolveBatchOptions,
  type BatchEnvelopeInput,
  type BatchOptions,
  type ResolvedBatchOptions,
} from "./batch.ts";
import { newTraceId, TRACE_ID_HEADER } from "./trace.ts";
import {
  renderPrometheus,
  type CircuitStateInput,
  type DeliveryCountersInput,
  type LatencyHistogramInput,
} from "./metrics.ts";

export { TRACE_ID_HEADER };
export { renderPrometheus };
export type { DeliveryCountersInput, CircuitStateInput, LatencyHistogramInput };

export type { CircuitBreakerOptions, CircuitState, CircuitStats };
export type { EncryptedPayload, PayloadEncryptor };
export type { EndpointLatencyStats, LatencyTrackerOptions };
export type { QuotaOptions, QuotaStats };
export type { BatchEnvelopeInput, BatchOptions };

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
}

/** Fired when a delivery's accepted→delivered latency exceeds the SLO budget. */
export interface SloMissInfo {
  id: string;
  /** End-to-end trace ID of the slow delivery. */
  traceId: string;
  endpoint: string;
  latencyMs: number;
  sloMs: number;
}

/** {@link LatencyTrackerOptions} plus the SLO-miss hook. */
export interface LatencyOptions extends LatencyTrackerOptions {
  /** Called once per delivery whose accepted→delivered latency exceeds `sloMs`. */
  onSloMiss?: (info: SloMissInfo) => void;
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
  targetUrl: string;
  /** Attempts consumed so far (including the successful one for `delivered`). */
  attempts: number;
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

export type Sender = (item: RetryItem) => Promise<void>;

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
  /** ISO-8601 timestamp when the item entered the dead-letter list. */
  deadLetteredAt: string;
  /** Original payload byte length (also when encrypted). */
  payloadBytes: number;
  /** Sealed payload envelope; present only when `payloadEncryptor` is set. */
  encryptedPayload?: EncryptedPayload;
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
  /** Callback when an item exhausts all attempts and moves to dead-letter. */
  onDeadLetter?: (item: RetryItem, attempts: number, lastError: unknown) => void;
  /** Callback when an item is successfully delivered. */
  onDelivered?: (item: RetryItem, attempts: number) => void;
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
   */
  onCircuitStateChange?: (endpoint: string, from: CircuitState, to: CircuitState) => void;
  /**
   * Seals dead-letter payloads at rest: when set, a dead-lettered item's
   * `payload` is replaced by an `encryptedPayload` envelope (default
   * {@link AesGcmEncryptor} via `node:crypto`, zero dependencies) and
   * `replayDeadLetter` transparently decrypts before re-queueing. Unset by
   * default, in which case dead-letter payloads are kept in the clear.
   */
  payloadEncryptor?: PayloadEncryptor;
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
   * Called every time a batch is flushed — i.e. a group of buffered events
   * became one merged delivery item. The server audits this as
   * `batch_flushed`.
   */
  onBatch?: (info: BatchInfo) => void;
  /**
   * Prometheus metrics tuning (see `src/metrics.ts`). Delivery counters
   * (`relay_deliveries_total`) and circuit gauges
   * (`relay_endpoint_circuit_state`) are always collected; the latency
   * histogram needs `latency` enabled too. Served by the operator
   * `GET /metrics` endpoint; `renderMetrics()` renders the exposition text
   * for embedding or testing.
   */
  metrics?: MetricsOptions;
}

interface Scheduled {
  handle: { clear(): void };
}

const noopSender: Sender = async () => {};

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
  private readonly max: number;
  private readonly inFlight = new Map<string, number>();
  private readonly waiters = new Map<string, Array<() => void>>();

  constructor(maxConcurrentPerEndpoint: number = Infinity) {
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
    this.max = maxConcurrentPerEndpoint;
  }

  /**
   * Resolve when a slot for `endpoint` is free. Always call the returned
   * function exactly once to hand the slot on.
   */
  acquire(endpoint: string): Promise<() => void> {
    const n = this.inFlight.get(endpoint) ?? 0;
    if (n < this.max) {
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
 * RetryQueue holds outbound deliveries and retries them with exponential
 * backoff + jitter. Items that exhaust `maxAttempts` are moved to an
 * in-memory dead-letter list for later inspection.
 */
export class RetryQueue {
  private readonly sender: Sender;
  private readonly baseDelayMs: number;
  private readonly maxDelayMs: number;
  private readonly maxAttempts: number;
  private readonly jitterMs: number;
  private readonly jitterStrategy: JitterStrategy;
  private readonly random: () => number;
  private readonly setTimer: (fn: () => void, ms: number) => { clear(): void };
  private readonly clearTimer: (handle: { clear(): void }) => void;
  private readonly onDeadLetter?: (item: RetryItem, attempts: number, lastError: unknown) => void;
  private readonly onDelivered?: (item: RetryItem, attempts: number) => void;
  private readonly breaker?: EndpointCircuitBreaker;
  /** Attempts parked because the endpoint's circuit was open. */
  private circuitBlocked = 0;
  private readonly payloadEncryptor?: PayloadEncryptor;
  private readonly urgentRetryDelayMs: number;
  private readonly urgentLimiter: UrgentRateLimiter;
  private readonly urgentStats = new Map<string, { delivered: number; retried: number; throttled: number }>();
  private readonly latency?: LatencyTracker;
  private readonly onSloMiss?: (info: SloMissInfo) => void;
  private readonly quota?: EndpointQuota;
  /** Attempts rescheduled because the endpoint's quota bucket was empty. */
  private readonly quotaStats = new Map<string, number>();
  private readonly batcher?: BatchCollector;
  private readonly batchResolved?: ResolvedBatchOptions;
  private readonly onBatch?: (info: BatchInfo) => void;
  /** Per-endpoint flushed-batch counters. */
  private readonly batchStats = new Map<string, { batches: number; events: number }>();
  /** Prometheus delivery counters per endpoint (see `src/metrics.ts`). */
  private readonly deliveryCounters = new Map<
    string,
    { delivered: number; failed: number; retried: number; deadLetter: number }
  >();
  /** Last observed circuit state per endpoint (only endpoints that tripped). */
  private readonly circuitStates = new Map<string, "closed" | "half_open" | "open">();
  /** Histogram bucket upper bounds in ms (validated ascending). */
  private readonly histBucketsMs: number[];
  /** Per-endpoint latency histogram: per-bucket individual counts + sum. */
  private readonly latencyHist = new Map<string, { counts: number[]; sumMs: number; count: number }>();
  private readonly deliveryEventListeners = new Set<(e: DeliveryEvent) => void>();

  private readonly queue = new Map<string, RetryItem & { attempt: number }>();
  private readonly timers = new Map<string, Scheduled>();
  private readonly deadLetter: DeadLetterEntry[] = [];
  private readonly limiter: EndpointConcurrencyLimiter;
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
    this.onDelivered = opts.onDelivered;
    this.limiter = new EndpointConcurrencyLimiter(opts.maxConcurrentPerEndpoint);
    // Wrap the caller's state-change hook so the metrics gauge always sees
    // the latest circuit state, even when nobody subscribes to the hook.
    const userOnStateChange = opts.onCircuitStateChange ?? opts.circuitBreaker?.onStateChange;
    this.breaker = opts.circuitBreaker
      ? new EndpointCircuitBreaker({
          ...opts.circuitBreaker,
          onStateChange: (endpoint, from, to) => {
            this.circuitStates.set(endpoint, to);
            userOnStateChange?.(endpoint, from, to);
          },
        })
      : undefined;
    this.payloadEncryptor = opts.payloadEncryptor;
    this.urgentRetryDelayMs = opts.urgent?.retryDelayMs ?? 0;
    if (!Number.isFinite(this.urgentRetryDelayMs) || this.urgentRetryDelayMs < 0) {
      throw new RangeError(`urgent.retryDelayMs must be >= 0, got ${opts.urgent?.retryDelayMs}`);
    }
    this.urgentLimiter = new UrgentRateLimiter(
      opts.urgent?.maxUrgentPerSecond ?? 100,
      opts.urgent?.now ?? Date.now
    );
    this.latency = opts.latency ? new LatencyTracker(opts.latency) : undefined;
    this.onSloMiss = opts.latency?.onSloMiss;
    this.quota =
      opts.quota?.deliveriesPerMinute !== undefined
        ? new EndpointQuota(opts.quota.deliveriesPerMinute, opts.quota.now ?? Date.now)
        : undefined;
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
  }

  private recordQuotaStat(endpoint: string): void {
    this.quotaStats.set(endpoint, (this.quotaStats.get(endpoint) ?? 0) + 1);
  }

  private recordUrgentStat(endpoint: string, kind: "delivered" | "retried" | "throttled"): void {
    let s = this.urgentStats.get(endpoint);
    if (!s) {
      s = { delivered: 0, retried: 0, throttled: 0 };
      this.urgentStats.set(endpoint, s);
    }
    s[kind] += 1;
  }

  /** Increment one Prometheus delivery counter for `endpoint`. */
  private recordDelivery(endpoint: string, kind: "delivered" | "failed" | "retried" | "deadLetter"): void {
    let c = this.deliveryCounters.get(endpoint);
    if (!c) {
      c = { delivered: 0, failed: 0, retried: 0, deadLetter: 0 };
      this.deliveryCounters.set(endpoint, c);
    }
    c[kind] += 1;
  }

  /** Bucket one accepted→delivered sample into the endpoint's latency histogram. */
  private recordLatencySample(endpoint: string, latencyMs: number): void {
    let h = this.latencyHist.get(endpoint);
    if (!h) {
      h = { counts: new Array(this.histBucketsMs.length).fill(0), sumMs: 0, count: 0 };
      this.latencyHist.set(endpoint, h);
    }
    const idx = this.histBucketsMs.findIndex((b) => latencyMs <= b);
    // A sample above the last bound lands in +Inf only (the `count` series).
    if (idx >= 0) h.counts[idx] += 1;
    h.sumMs += latencyMs;
    h.count += 1;
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
   * Move a dead-lettered item back into the queue with a fresh attempt
   * budget (attempts reset to 0, scheduled immediately when running).
   * Returns false when no dead-letter entry matches `id`.
   */
  replayDeadLetter(id: string): boolean {
    const idx = this.deadLetter.findIndex((e) => e.id === id);
    if (idx < 0) return false;
    const [entry] = this.deadLetter.splice(idx, 1);
    const {
      attempts: _attempts,
      lastError: _lastError,
      deadLetteredAt: _ts,
      encryptedPayload,
      payloadBytes: _payloadBytes,
      ...item
    } = entry;
    let payload = item.payload;
    if (encryptedPayload) {
      if (!this.payloadEncryptor) {
        throw new Error("replayDeadLetter: entry payload is encrypted but no payloadEncryptor is configured");
      }
      payload = this.payloadEncryptor.decrypt(encryptedPayload);
    }
    this.queue.set(item.id, { ...item, payload, attempt: 0 });
    // A replay starts a fresh delivery cycle: restart the latency clock so
    // the sample measures the replayed attempt, not the original one.
    this.latency?.recordAccepted(item.id);
    if (this.running) {
      this.schedule(item.id, 0);
    }
    return true;
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

  enqueue(item: RetryItem): void {
    if (this.queue.has(item.id) || this.batcher?.has(item.id)) {
      throw new Error(`Duplicate item id: ${item.id}`);
    }
    // Mint the trace ID up front so even batch-buffered items (which skip
    // `enqueueNow` until flush) carry one, and `flushBatch` can correlate
    // the merged delivery back to its members.
    const traced: RetryItem = { ...item, traceId: item.traceId ?? newTraceId() };
    // The urgent lane is never batched: an urgent delivery must go out
    // immediately, not wait for a batch window.
    if (this.batcher && traced.priority !== "urgent") {
      this.batcher.add(traced);
      return;
    }
    this.enqueueNow(traced);
  }

  private enqueueNow(item: RetryItem): void {
    if (this.queue.has(item.id)) {
      throw new Error(`Duplicate item id: ${item.id}`);
    }
    // A defensive second mint: items enqueued through paths that skip
    // `enqueue()` (replayed dead letters keep their original traceId via
    // spread, flushed batches arrive here already traced) still land with a
    // trace ID rather than an undefined one.
    this.queue.set(item.id, { ...item, traceId: item.traceId ?? newTraceId(), attempt: 0 });
    // Start the latency clock only after the item is really queued — a
    // duplicate-id throw must not leave a stale pending record behind.
    // (Batched items start their clock at flush time, when the merged item
    // is queued: the batching delay is by design, not lateness.)
    this.latency?.recordAccepted(item.id);
    if (this.running) {
      this.schedule(item.id, 0);
    }
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    for (const id of this.queue.keys()) {
      this.schedule(id, 0);
    }
  }

  stop(): void {
    this.running = false;
    for (const [id, s] of this.timers) {
      this.clearTimer(s.handle);
      this.timers.delete(id);
    }
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
    this.running = false;
    for (const [id, s] of this.timers) {
      this.clearTimer(s.handle);
      this.timers.delete(id);
    }
    for (const id of batchIds) {
      const p = this.deliver(id, true);
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

  /** Backoff for the *next* retry given the completed attempt index (0-based). */
  delayForAttempt(attempt: number): number {
    const cap = Math.min(this.maxDelayMs, this.baseDelayMs * 2 ** attempt);
    if (this.jitterStrategy === "full") {
      return this.random() * cap;
    }
    const jitter = this.jitterMs > 0 ? this.random() * this.jitterMs : 0;
    return Math.min(this.maxDelayMs, this.baseDelayMs * 2 ** attempt + jitter);
  }

  private schedule(id: string, delayMs: number): void {
    if (!this.running || !this.queue.has(id)) return;
    const existing = this.timers.get(id);
    if (existing) {
      this.clearTimer(existing.handle);
    }
    const handle = this.setTimer(() => {
      this.timers.delete(id);
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
    // Per-endpoint quota first: an exhausted budget delays the attempt
    // (rescheduled at the next token refill) instead of burning the retry
    // budget or tripping the circuit against a downstream we are
    // voluntarily throttling. A little jitter keeps many delayed items
    // from re-checking in lockstep.
    if (this.quota && !this.quota.take(entry.targetUrl)) {
      this.recordQuotaStat(entry.targetUrl);
      this.schedule(id, this.quota.msUntilToken(entry.targetUrl) + this.random() * 50);
      return;
    }
    let probe = false;
    if (this.breaker) {
      const verdict = this.breaker.shouldAllow(entry.targetUrl);
      if (!verdict.allowed) {
        // Circuit open (or its probe slot busy): park the attempt until the
        // cooldown elapses instead of burning the retry budget against a
        // known-down endpoint. A little jitter keeps many parked items from
        // re-checking in lockstep.
        this.circuitBlocked += 1;
        this.schedule(id, this.breaker.retryInMs(entry.targetUrl) + this.random() * 100);
        return;
      }
      probe = verdict.probe;
    }
    // Fast-lane admission: every urgent attempt costs one token from the
    // endpoint's bucket. An empty bucket degrades the item to the normal
    // lane — the delivery still happens, just with exponential backoff —
    // so the lane can never be used to flood a downstream.
    if (entry.priority === "urgent" && !this.urgentLimiter.take(entry.targetUrl)) {
      this.recordUrgentStat(entry.targetUrl, "throttled");
      entry.priority = "normal";
    }
    const fastLane = entry.priority === "urgent";
    // The fast lane bypasses the per-endpoint concurrency limiter entirely:
    // an urgent delivery never waits behind queued normal deliveries. Its
    // own bound is the token bucket above.
    const release = fastLane ? undefined : await this.limiter.acquire(entry.targetUrl);
    try {
      // The queue may have stopped, or the item may have been settled, while
      // we waited for a concurrency slot. Bail out; the release cascades to
      // the next waiter so nobody hangs.
      if ((!this.running && !force) || !this.queue.has(id)) {
        if (probe) this.breaker?.cancelProbe(entry.targetUrl);
        return;
      }
      try {
        await this.sender(entry);
        this.breaker?.recordSuccess(entry.targetUrl);
        this.queue.delete(id);
        this.recordDelivery(entry.targetUrl, "delivered");
        if (fastLane) this.recordUrgentStat(entry.targetUrl, "delivered");
        const latencyMs = this.latency?.recordDelivered(entry.id, entry.targetUrl);
        if (latencyMs !== undefined) {
          // The histogram samples the same delivery the JSON latency stats
          // do — accepted→delivered, dead letters excluded by `discard()`.
          this.recordLatencySample(entry.targetUrl, latencyMs);
        }
        if (latencyMs !== undefined && this.latency && latencyMs > this.latency.sloMs) {
          this.onSloMiss?.({ id: entry.id, traceId, endpoint: entry.targetUrl, latencyMs, sloMs: this.latency.sloMs });
        }
        this.onDelivered?.(entry, entry.attempt + 1);
        this.emitDeliveryEvent({
          type: "delivered",
          id: entry.id,
          traceId,
          targetUrl: entry.targetUrl,
          attempts: entry.attempt + 1,
          at: new Date().toISOString(),
        });
      } catch (err) {
        this.breaker?.recordFailure(entry.targetUrl);
        this.recordDelivery(entry.targetUrl, "failed");
        entry.attempt += 1;
        const error = err instanceof Error ? err.message : String(err);
        const at = new Date().toISOString();
        if (entry.attempt >= this.maxAttempts) {
          this.queue.delete(id);
          this.recordDelivery(entry.targetUrl, "deadLetter");
          // Never delivered: drop the pending clock without sampling.
          this.latency?.discard(entry.id);
          const encryptedPayload = this.payloadEncryptor?.encrypt(entry.payload);
          this.deadLetter.push({
            id: entry.id,
            traceId,
            // Sealed at rest when an encryptor is configured; kept in the
            // clear otherwise (existing behavior).
            payload: encryptedPayload ? Buffer.alloc(0) : entry.payload,
            targetUrl: entry.targetUrl,
            headers: entry.headers,
            // Kept so a replayed item re-enters the same delivery lane.
            priority: entry.priority,
            attempts: entry.attempt,
            lastError: err instanceof Error ? err.message : String(err),
            deadLetteredAt: new Date().toISOString(),
            payloadBytes: entry.payload.length,
            ...(encryptedPayload ? { encryptedPayload } : {}),
          });
          this.onDeadLetter?.(entry, entry.attempt, err);
          this.emitDeliveryEvent({
            type: "dead_letter",
            id: entry.id,
            traceId,
            targetUrl: entry.targetUrl,
            attempts: entry.attempt,
            at,
            error,
          });
        } else if (fastLane && this.urgentLimiter.take(entry.targetUrl)) {
          // Skip the exponential backoff: fixed fast-lane retry delay.
          this.recordUrgentStat(entry.targetUrl, "retried");
          this.recordDelivery(entry.targetUrl, "retried");
          this.emitDeliveryEvent({
            type: "retrying",
            id: entry.id,
            traceId,
            targetUrl: entry.targetUrl,
            attempts: entry.attempt,
            at,
            error,
          });
          this.schedule(id, this.urgentRetryDelayMs);
        } else {
          if (fastLane) {
            // Fast-lane retry would exceed the endpoint's urgent rate:
            // degrade to normal backoff instead of dropping the delivery.
            this.recordUrgentStat(entry.targetUrl, "throttled");
            entry.priority = "normal";
          }
          this.recordDelivery(entry.targetUrl, "retried");
          this.emitDeliveryEvent({
            type: "retrying",
            id: entry.id,
            traceId,
            targetUrl: entry.targetUrl,
            attempts: entry.attempt,
            at,
            error,
          });
          this.schedule(id, this.delayForAttempt(entry.attempt));
        }
      }
    } finally {
      release?.();
    }
  }

  /** Per-endpoint concurrency snapshot: in-flight and queued deliveries. */
  getConcurrencyStats(): Array<{ endpoint: string; inFlight: number; queued: number }> {
    return this.limiter.stats();
  }

  /**
   * Per-endpoint urgent-lane counters (`delivered` / `retried` /
   * `throttled`). Empty when no urgent delivery has been attempted.
   */
  getUrgentStats(): UrgentStats[] {
    return [...this.urgentStats.entries()].map(([endpoint, s]) => ({ endpoint, ...s }));
  }

  /**
   * Per-endpoint accepted→delivered latency distribution (p50/p95/p99) plus
   * SLO attainment. Empty when latency tracking is disabled or no delivery
   * has completed yet. With `endpoint` set, only that endpoint is returned.
   */
  getLatencyStats(endpoint?: string): EndpointLatencyStats[] {
    return this.latency?.stats(endpoint) ?? [];
  }

  /**
   * Prometheus text exposition of the collected metrics (see
   * `src/metrics.ts`): per-endpoint delivery counters
   * (`relay_deliveries_total`), circuit gauges for endpoints that tripped
   * (`relay_endpoint_circuit_state`), and the accepted→delivered latency
   * histogram (`relay_delivery_latency_seconds_*`) when latency tracking
   * is enabled.
   */
  renderMetrics(): string {
    const deliveries: DeliveryCountersInput[] = [...this.deliveryCounters.entries()].map(
      ([endpoint, c]) => ({
        endpoint,
        delivered: c.delivered,
        failed: c.failed,
        retried: c.retried,
        deadLetter: c.deadLetter,
      })
    );
    const circuits: CircuitStateInput[] = [...this.circuitStates.entries()].map(
      ([endpoint, state]) => ({ endpoint, state })
    );
    const latencyHistograms: LatencyHistogramInput[] = [];
    if (this.latency) {
      for (const [endpoint, h] of this.latencyHist) {
        const bucketCounts: number[] = [];
        let cumulative = 0;
        for (const n of h.counts) {
          cumulative += n;
          bucketCounts.push(cumulative);
        }
        latencyHistograms.push({
          endpoint,
          bucketBounds: this.histBucketsMs.map((b) => b / 1000),
          bucketCounts,
          sum: h.sumMs / 1000,
          count: h.count,
        });
      }
    }
    return renderPrometheus({ deliveries, circuits, latencyHistograms });
  }

  /**
   * Per-endpoint circuit state (`state`, `consecutiveFailures`, `trips`).
   * Empty when the circuit breaker is disabled.
   */
  getCircuitStats(): CircuitStats[] {
    return this.breaker?.stats() ?? [];
  }

  /** Attempts parked because the endpoint's circuit was open. */
  circuitBlockedCount(): number {
    return this.circuitBlocked;
  }

  /**
   * Per-endpoint quota counters (`delayed`). Empty when the quota is
   * disabled or no attempt has been delayed yet.
   */
  getQuotaStats(): QuotaStats[] {
    return [...this.quotaStats.entries()].map(([endpoint, delayed]) => ({ endpoint, delayed }));
  }
}
