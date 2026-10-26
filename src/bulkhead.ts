/**
 * Per-endpoint bulkhead concurrency isolation (WR-227).
 *
 * The bulkhead pattern, applied per downstream endpoint: each endpoint
 * gets an *independent* in-flight cap plus a *bounded* FIFO queue. When
 * one endpoint saturates, its excess requests fail fast instead of
 * piling up behind it — and, crucially, they never occupy another
 * endpoint's capacity, because bulkheads do not share state.
 *
 * How this differs from the existing gates (read before reaching for
 * this module):
 * - WR-06 `EndpointConcurrencyLimiter` (retry.ts) is a per-endpoint
 *   cap with an *unbounded* FIFO wait: excess acquisitions wait
 *   forever, are never dropped, and produce no rejection record. The
 *   bulkhead is the fail-fast counterpart: the queue is bounded, an
 *   over-full queue rejects immediately, and a waiter that sits too
 *   long times out — both rejections are audited.
 * - WR-51 `GlobalConcurrencyGate` (global-concurrency.ts) is the same
 *   unbounded-FIFO shape at relay scope: one shared cap across all
 *   endpoints. The bulkhead is per-endpoint isolation, not a global
 *   cap; the two compose (a dispatch could hold a slot from each).
 * - WR-94 adaptive concurrency (adaptive-concurrency.ts) *tunes* the
 *   per-endpoint cap up and down from outcomes (AIMD). The bulkhead
 *   never tunes anything: its cap is a hard ceiling, and its novelty
 *   is what happens past the ceiling (bounded queue + rejection).
 * - WR-38 global retry budget (retry-budget.ts) budgets *retry
 *   attempts* across the relay. The bulkhead budgets *in-flight
 *   slots* per endpoint; a bulkhead rejection is not a retry attempt
 *   and consumes no retry budget — it is backpressure, reported as
 *   such.
 *
 * Semantics:
 * - Independent per-endpoint state: saturating endpoint A can neither
 *   block nor reject traffic to endpoint B. Endpoints that never
 *   appear cost nothing (lazily created, WR-48 isolation convention).
 * - Bounded queue: when the in-flight cap is hit, at most `maxQueue`
 *   acquisitions wait FIFO. The `maxQueue + 1`-th waiter is rejected
 *   immediately with reason `queue_full` — fail fast, no slot held,
 *   no timer started.
 * - Queue timeout: a waiter that waits longer than `queueTimeoutMs`
 *   is removed from the queue and rejected with reason
 *   `queue_timeout`. A queue timeout is transient downstream
 *   backpressure, so the rejection error classifies as `retryable`
 *   (see `failure.ts`: the normal backoff lane) — the caller may
 *   schedule another attempt; it must not dead-letter the payload.
 *   A `queue_full` rejection is likewise transient backpressure and
 *   carries the same classification.
 * - Release frees the oldest queued waiter: the slot transfers to it
 *   (in-flight count unchanged) and its timeout timer is cleared, so
 *   a granted waiter can never later time out.
 * - Audit: every rejection is appended to an in-memory audit trail
 *   (`rejections()`), recording endpoint, reason, and queue wait, so
 *   operators can see which downstream is shedding load and why.
 * - Fail-closed config: invalid values throw `RangeError` at
 *   construction. A bulkhead must never silently run uncapped: a
 *   non-positive or non-integer cap, a negative queue bound, or a
 *   negative/non-finite timeout is a construction error, not a
 *   fallback to `Infinity` or zero.
 * - Release is idempotent: calling the returned release function more
 *   than once is a no-op after the first call, so a double-release
 *   can never hand the same slot to two waiters.
 */

/** Why a bulkhead acquisition was rejected. */
export type BulkheadRejectionReason = "queue_full" | "queue_timeout";

/** One audited bulkhead rejection. */
export interface BulkheadRejection {
  /** The endpoint whose bulkhead rejected the acquisition. */
  endpoint: string;
  /** Why it was rejected. */
  reason: BulkheadRejectionReason;
  /** Milliseconds the acquisition spent queued before rejection (0 for `queue_full`). */
  queuedMs: number;
  /** Wall-clock time of the rejection (`Date.now()`). */
  atMs: number;
}

/** Point-in-time snapshot of one endpoint's bulkhead. */
export interface BulkheadStats {
  /** The endpoint this row describes. */
  endpoint: string;
  /** Configured in-flight cap. */
  maxConcurrent: number;
  /** Configured queue bound. */
  maxQueue: number;
  /** Acquisitions currently holding a slot. */
  inFlight: number;
  /** Acquisitions currently queued FIFO for a slot. */
  queuedDepth: number;
  /** Cumulative acquisitions that had to wait for a slot. */
  waitsTotal: number;
  /** Cumulative rejections (queue_full + queue_timeout). */
  rejectionsTotal: number;
}

/** Configuration for one endpoint's bulkhead. */
export interface BulkheadOptions {
  /**
   * Max in-flight acquisitions for the endpoint. Must be a positive
   * integer — unlike the WR-06/WR-51 gates, `Infinity` is not
   * accepted: an uncapped bulkhead is a misconfiguration, and
   * fail-closed construction rejects it.
   */
  maxConcurrent: number;
  /**
   * Max acquisitions waiting FIFO for a slot. 0 means no queue at
   * all: any acquisition past the cap rejects immediately. Must be a
   * non-negative integer.
   */
  maxQueue: number;
  /**
   * Max milliseconds a waiter may sit queued before it is rejected
   * with `queue_timeout`. Must be a non-negative finite number; 0
   * means a waiter that cannot be granted immediately times out on
   * the next timer tick.
   */
  queueTimeoutMs: number;
}

/** Upper bound on the retained in-memory audit trail (oldest dropped first). */
const MAX_AUDIT_ENTRIES = 1000;

/** Shared validation: fail closed on anything that is not a usable bulkhead. */
export function assertBulkheadOptions(options: BulkheadOptions): void {
  if (!Number.isInteger(options.maxConcurrent) || options.maxConcurrent < 1) {
    throw new RangeError(
      `bulkhead maxConcurrent must be a positive integer, got ${options.maxConcurrent}`
    );
  }
  if (!Number.isInteger(options.maxQueue) || options.maxQueue < 0) {
    throw new RangeError(
      `bulkhead maxQueue must be a non-negative integer, got ${options.maxQueue}`
    );
  }
  if (
    typeof options.queueTimeoutMs !== "number" ||
    !Number.isFinite(options.queueTimeoutMs) ||
    options.queueTimeoutMs < 0
  ) {
    throw new RangeError(
      `bulkhead queueTimeoutMs must be a non-negative finite number, got ${options.queueTimeoutMs}`
    );
  }
}

/**
 * Rejection thrown when a bulkhead acquisition fails fast. Carries
 * `failureClass: "retryable"` so retry-queue consumers classify it
 * like any other transient downstream backpressure (429/5xx/timeout):
 * another attempt may be scheduled with backoff; the payload is not
 * poison and must not be dead-lettered for this reason alone.
 */
export class BulkheadRejectedError extends Error {
  /** The endpoint whose bulkhead rejected the acquisition. */
  readonly endpoint: string;
  /** Why it was rejected. */
  readonly reason: BulkheadRejectionReason;
  /** Milliseconds spent queued before rejection (0 for `queue_full`). */
  readonly queuedMs: number;
  /** Failure classification for retry-queue consumers. */
  readonly failureClass = "retryable" as const;

  constructor(endpoint: string, reason: BulkheadRejectionReason, queuedMs: number) {
    super(
      `bulkhead rejected ${endpoint}: ${reason} after ${queuedMs}ms queued`
    );
    this.name = "BulkheadRejectedError";
    this.endpoint = endpoint;
    this.reason = reason;
    this.queuedMs = queuedMs;
  }
}

interface Waiter {
  resolve: (release: () => void) => void;
  reject: (err: BulkheadRejectedError) => void;
  enqueuedAtMs: number;
  timer: ReturnType<typeof setTimeout>;
}

/**
 * One endpoint's bulkhead: at most `maxConcurrent` acquisitions in
 * flight, at most `maxQueue` waiting FIFO. Excess acquisitions fail
 * fast with an audited `BulkheadRejectedError` instead of waiting
 * unboundedly — the property WR-06 deliberately does not have.
 *
 * Callers must call the returned release function exactly once (it is
 * idempotent, so an accidental second call is harmless but pointless).
 */
export class EndpointBulkhead {
  private readonly endpoint: string;
  private readonly options: BulkheadOptions;
  private inFlight = 0;
  private readonly waiters: Waiter[] = [];
  private waitsTotal = 0;
  private rejectionsTotal = 0;
  private readonly audit: BulkheadRejection[] = [];

  constructor(endpoint: string, options: BulkheadOptions) {
    assertBulkheadOptions(options);
    this.endpoint = endpoint;
    this.options = { ...options };
  }

  /** The endpoint this bulkhead guards. */
  name(): string {
    return this.endpoint;
  }

  /** The configured in-flight cap. */
  cap(): number {
    return this.options.maxConcurrent;
  }

  /** The configured queue bound. */
  queueBound(): number {
    return this.options.maxQueue;
  }

  /**
   * Resolve with a release function when a slot is free, or reject
   * with `BulkheadRejectedError` when the queue is full or the wait
   * times out. An immediately granted slot is not a wait and starts
   * no timer.
   */
  acquire(): Promise<() => void> {
    if (this.inFlight < this.options.maxConcurrent) {
      this.inFlight += 1;
      return Promise.resolve(this.onceRelease());
    }
    if (this.waiters.length >= this.options.maxQueue) {
      const err = new BulkheadRejectedError(this.endpoint, "queue_full", 0);
      this.record(err);
      return Promise.reject(err);
    }
    this.waitsTotal += 1;
    const enqueuedAtMs = Date.now();
    return new Promise<() => void>((resolve, reject) => {
      const waiter: Waiter = {
        resolve,
        reject,
        enqueuedAtMs,
        timer: setTimeout(() => {
          const i = this.waiters.indexOf(waiter);
          if (i < 0) return; // Already granted; timer cleared on grant.
          this.waiters.splice(i, 1);
          const err = new BulkheadRejectedError(
            this.endpoint,
            "queue_timeout",
            Date.now() - enqueuedAtMs
          );
          this.record(err);
          reject(err);
        }, this.options.queueTimeoutMs),
      };
      // Deliberately not unref'd: the timer is the waiter's only wake
      // source, and unref'ing it could let the loop drain before the
      // timeout fires. It is cleared on grant, so it never outlives
      // the wait.
      this.waiters.push(waiter);
    });
  }

  private onceRelease(): () => void {
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.release();
    };
  }

  private release(): void {
    const next = this.waiters.shift();
    if (next) {
      // Slot transfers from the releaser to the oldest waiter; the
      // in-flight count is unchanged, and the granted waiter can no
      // longer time out.
      clearTimeout(next.timer);
      next.resolve(this.onceRelease());
      return;
    }
    this.inFlight -= 1;
  }

  private record(err: BulkheadRejectedError): void {
    this.rejectionsTotal += 1;
    this.audit.push({
      endpoint: err.endpoint,
      reason: err.reason,
      queuedMs: err.queuedMs,
      atMs: Date.now(),
    });
    if (this.audit.length > MAX_AUDIT_ENTRIES) {
      this.audit.splice(0, this.audit.length - MAX_AUDIT_ENTRIES);
    }
  }

  /** Acquisitions currently holding a slot. */
  inFlightCount(): number {
    return this.inFlight;
  }

  /** Acquisitions currently queued FIFO for a slot. */
  queuedDepth(): number {
    return this.waiters.length;
  }

  /** Cumulative acquisitions that had to wait for a slot. */
  waitedTotal(): number {
    return this.waitsTotal;
  }

  /** Cumulative rejections (queue_full + queue_timeout). */
  rejectedTotal(): number {
    return this.rejectionsTotal;
  }

  /** The audited rejection trail, oldest first (a copy). */
  rejections(): BulkheadRejection[] {
    return [...this.audit];
  }

  /** Point-in-time snapshot for operator observability. */
  stats(): BulkheadStats {
    return {
      endpoint: this.endpoint,
      maxConcurrent: this.options.maxConcurrent,
      maxQueue: this.options.maxQueue,
      inFlight: this.inFlight,
      queuedDepth: this.waiters.length,
      waitsTotal: this.waitsTotal,
      rejectionsTotal: this.rejectionsTotal,
    };
  }
}

/**
 * The per-endpoint aggregate: one independent `EndpointBulkhead` per
 * endpoint, created lazily on first use — an endpoint that never
 * appears costs nothing, and one endpoint's saturation can never
 * occupy another endpoint's slots (the WR-48 isolation convention).
 *
 * The config is validated once, at construction; every lazily created
 * bulkhead inherits it.
 */
export class EndpointBulkheads {
  private readonly options: BulkheadOptions;
  private readonly bulkheads = new Map<string, EndpointBulkhead>();

  constructor(options: BulkheadOptions) {
    assertBulkheadOptions(options);
    this.options = { ...options };
  }

  private bulkheadFor(endpoint: string): EndpointBulkhead {
    let b = this.bulkheads.get(endpoint);
    if (b === undefined) {
      b = new EndpointBulkhead(endpoint, this.options);
      this.bulkheads.set(endpoint, b);
    }
    return b;
  }

  /**
   * Acquire a slot in `endpoint`'s own bulkhead. Rejects with
   * `BulkheadRejectedError` when that endpoint's queue is full or the
   * wait times out; other endpoints are entirely unaffected.
   */
  acquire(endpoint: string): Promise<() => void> {
    return this.bulkheadFor(endpoint).acquire();
  }

  /** One snapshot row per endpoint seen so far, in first-seen order. */
  stats(): BulkheadStats[] {
    return [...this.bulkheads.values()].map((b) => b.stats());
  }

  /** The combined audited rejection trail across endpoints, oldest first. */
  rejections(): BulkheadRejection[] {
    const out: BulkheadRejection[] = [];
    for (const b of this.bulkheads.values()) out.push(...b.rejections());
    return out.sort((a, b2) => a.atMs - b2.atMs);
  }
}
