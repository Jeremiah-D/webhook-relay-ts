/**
 * WR-166: adaptive outbound timeout.
 *
 * A static per-attempt timeout is always a compromise: set it tight and
 * a legitimately slow endpoint gets killed mid-call; set it loose and a
 * hung fast endpoint holds a pool slot for the whole budget. This module
 * derives the per-attempt timeout from the endpoint's own recent latency
 * instead: `p99 * (1 + marginRatio)`, clamped to `[minTimeoutMs,
 * maxTimeoutMs]`.
 *
 * - A slow endpoint's p99 is high, so the timeout floats *above* its
 *   observed latency — the margin is headroom against false kills.
 * - A stable fast endpoint's p99 is low, so the timeout tightens — a
 *   hung request trips the adaptive cap instead of holding a connection
 *   for the whole static budget.
 * - Cold start (fewer than `minSamples` samples) falls back to
 *   `baseTimeoutMs`: the relay behaves exactly like the static
 *   configuration until it has evidence.
 *
 * Sampling basis: the module reuses {@link LatencyTracker} (WR-13) with
 * its accepted→delivered clock. That clock includes queue wait and
 * backoff between attempts, so the derived cap is conservative — the
 * margin exists precisely to absorb that slop. It is *not* a measurement
 * of a single downstream call; treat the timeout as a defensive ceiling,
 * not a precise SLO.
 *
 * Enforcement: the queue stamps the computed cap on the wire copy as
 * `RetryItem.adaptiveTimeoutMs`; the default sender enforces it exactly
 * like the WR-99 deadline budget (request destroyed on fire, typed
 * {@link AdaptiveTimeoutError}). The error carries no `statusCode`, so
 * `classifyFailure` routes it to `"retryable"` via the default
 * fallthrough — the normal backoff / circuit-breaker / dead-letter
 * path. No new failure class: an adaptive timeout is a transient
 * downstream condition, exactly like any other timeout. It composes with
 * the WR-99 deadline budget and WR-143 phase budgets — each arms its own
 * timer and the tightest fires first.
 *
 * Opt-in: when `RetryQueueOptions.adaptiveTimeout` is absent the wire
 * copy carries no adaptive timeout and behavior is byte-identical to the
 * static configuration. Custom (injected) senders simply ignore the
 * stamped field — same limitation as `deadlineBudgetMs`.
 *
 * Zero dependencies.
 */

import { LatencyTracker } from "./latency.ts";

/** Options for {@link AdaptiveTimeout}. */
export interface AdaptiveTimeoutOptions {
  /**
   * Cold-start per-attempt timeout in ms: used until `minSamples`
   * accepted→delivered samples exist for the endpoint, and the fallback
   * when the feature is misconfigured. Must be a finite number > 0.
   */
  baseTimeoutMs: number;
  /**
   * Headroom above the endpoint's recent p99: the timeout is
   * `p99 * (1 + marginRatio)`. Default: 0.5 (50% headroom). Must be a
   * finite number >= 0. Larger values kill slow endpoints less often
   * but tighten fast endpoints less.
   */
  marginRatio?: number;
  /**
   * Floor for the derived timeout in ms: the cap never tightens below
   * this, no matter how fast the endpoint is. Default: 100. Must be a
   * finite number > 0.
   */
  minTimeoutMs?: number;
  /**
   * Ceiling for the derived timeout in ms: the cap never loosens past
   * this, no matter how slow the endpoint is. Default:
   * `4 * baseTimeoutMs`. Must be a finite number > 0 and >=
   * `minTimeoutMs`.
   */
  maxTimeoutMs?: number;
  /**
   * Samples required before the timeout adapts (cold-start guard).
   * Default: 10. Must be an integer >= 1.
   */
  minSamples?: number;
  /**
   * Rolling sample window per endpoint, forwarded to the underlying
   * {@link LatencyTracker}. Default: 1024. Must be an integer >= 1.
   */
  maxSamplesPerEndpoint?: number;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
}

/** Per-endpoint adaptive timeout view. All JSON-serializable. */
export interface AdaptiveTimeoutEndpointStats {
  endpoint: string;
  /** The timeout the next dispatch to this endpoint will be capped at. */
  timeoutMs: number;
  /** Samples currently in the rolling window. */
  samples: number;
  /** Recent p99 the timeout was derived from (`baseTimeoutMs` basis when cold). */
  p99Ms: number;
}

/**
 * The error a timeout-enforcing sender rejects with when the adaptive
 * per-attempt cap fires mid-call. Carries no `statusCode`, so
 * `classifyFailure` routes it to `"retryable"` — the normal backoff /
 * circuit-breaker / dead-letter path. The payload never rides along:
 * the error carries the target and the cap, never payload bytes.
 */
export class AdaptiveTimeoutError extends Error {
  /** Physical target the attempt was bound for. */
  readonly targetUrl: string;
  /** The adaptive cap (ms) the attempt was held to. */
  readonly timeoutMs: number;
  constructor(targetUrl: string, timeoutMs: number) {
    super(
      `adaptive outbound timeout: downstream call to ${targetUrl} ` +
        `exceeded ${Math.max(0, Math.round(timeoutMs))}ms (p99-derived) budget`
    );
    this.name = "AdaptiveTimeoutError";
    this.targetUrl = targetUrl;
    this.timeoutMs = timeoutMs;
  }
}

/** Validate an {@link AdaptiveTimeoutOptions}. Throws `RangeError` on anything invalid. */
export function assertValidAdaptiveTimeoutOptions(opts: unknown): void {
  if (opts === null || typeof opts !== "object" || Array.isArray(opts)) {
    throw new RangeError(`adaptiveTimeout must be an options object, got ${String(opts)}`);
  }
  const o = opts as Record<string, unknown>;
  const base = o.baseTimeoutMs;
  if (typeof base !== "number" || !Number.isFinite(base) || base <= 0) {
    throw new RangeError(`adaptiveTimeout.baseTimeoutMs must be a finite number > 0, got ${String(base)}`);
  }
  const margin = o.marginRatio ?? 0.5;
  if (typeof margin !== "number" || !Number.isFinite(margin) || margin < 0) {
    throw new RangeError(`adaptiveTimeout.marginRatio must be a finite number >= 0, got ${String(o.marginRatio)}`);
  }
  const min = o.minTimeoutMs ?? 100;
  if (typeof min !== "number" || !Number.isFinite(min) || min <= 0) {
    throw new RangeError(`adaptiveTimeout.minTimeoutMs must be a finite number > 0, got ${String(o.minTimeoutMs)}`);
  }
  const max = o.maxTimeoutMs ?? 4 * (base as number);
  if (typeof max !== "number" || !Number.isFinite(max) || max <= 0) {
    throw new RangeError(`adaptiveTimeout.maxTimeoutMs must be a finite number > 0, got ${String(o.maxTimeoutMs)}`);
  }
  if (max < min) {
    throw new RangeError(
      `adaptiveTimeout.maxTimeoutMs (${max}) must be >= minTimeoutMs (${min})`
    );
  }
  const minSamples = o.minSamples ?? 10;
  if (!Number.isInteger(minSamples) || (minSamples as number) < 1) {
    throw new RangeError(`adaptiveTimeout.minSamples must be an integer >= 1, got ${String(o.minSamples)}`);
  }
  const maxSamples = o.maxSamplesPerEndpoint ?? 1024;
  if (!Number.isInteger(maxSamples) || (maxSamples as number) < 1) {
    throw new RangeError(
      `adaptiveTimeout.maxSamplesPerEndpoint must be an integer >= 1, got ${String(o.maxSamplesPerEndpoint)}`
    );
  }
  if (o.now !== undefined && typeof o.now !== "function") {
    throw new RangeError(`adaptiveTimeout.now must be a function, got ${String(o.now)}`);
  }
}

/**
 * Per-endpoint adaptive outbound timeout, derived from recent
 * accepted→delivered latency percentiles.
 *
 * The queue feeds the same delivery-lifecycle events as the WR-13
 * latency tracker (`recordAccepted` on admission, `recordDelivered` on
 * success, `discard` on dead letter) and reads the next dispatch's cap
 * via `timeoutFor()`.
 */
export class AdaptiveTimeout {
  private readonly baseTimeoutMs: number;
  private readonly marginRatio: number;
  private readonly minTimeoutMs: number;
  private readonly maxTimeoutMs: number;
  private readonly minSamples: number;
  private readonly tracker: LatencyTracker;

  constructor(opts: AdaptiveTimeoutOptions) {
    assertValidAdaptiveTimeoutOptions(opts);
    this.baseTimeoutMs = opts.baseTimeoutMs;
    this.marginRatio = opts.marginRatio ?? 0.5;
    this.minTimeoutMs = opts.minTimeoutMs ?? 100;
    this.maxTimeoutMs = opts.maxTimeoutMs ?? 4 * opts.baseTimeoutMs;
    this.minSamples = opts.minSamples ?? 10;
    // The tracker's own SLO bookkeeping is irrelevant here — only the
    // rolling p99 window is used — so sloMs just needs to be valid.
    this.tracker = new LatencyTracker({
      sloMs: this.baseTimeoutMs,
      maxSamplesPerEndpoint: opts.maxSamplesPerEndpoint ?? 1024,
      now: opts.now,
    });
  }

  /** Mark a delivery accepted: starts its latency clock. */
  recordAccepted(id: string): void {
    this.tracker.recordAccepted(id);
  }

  /** Mark a delivery delivered: appends its latency to the endpoint's window. */
  recordDelivered(id: string, endpoint: string): void {
    this.tracker.recordDelivered(id, endpoint);
  }

  /** Drop a pending accepted record without sampling (e.g. dead-lettered). */
  discard(id: string): void {
    this.tracker.discard(id);
  }

  /**
   * The per-attempt timeout (ms) for the next dispatch to `endpoint`:
   * `clamp(p99 * (1 + marginRatio), minTimeoutMs, maxTimeoutMs)`, or
   * `baseTimeoutMs` while the endpoint is cold (fewer than `minSamples`
   * samples).
   */
  timeoutFor(endpoint: string): number {
    const [s] = this.tracker.stats(endpoint);
    if (s === undefined || s.count < this.minSamples) return this.baseTimeoutMs;
    const adaptive = s.p99 * (1 + this.marginRatio);
    return Math.min(this.maxTimeoutMs, Math.max(this.minTimeoutMs, adaptive));
  }

  /** Per-endpoint adaptive timeout view for operator observability. */
  stats(): AdaptiveTimeoutEndpointStats[] {
    return this.tracker.stats().map((s) => ({
      endpoint: s.endpoint,
      timeoutMs: this.timeoutFor(s.endpoint),
      samples: s.count,
      p99Ms: s.count < this.minSamples ? this.baseTimeoutMs : s.p99,
    }));
  }
}

/**
 * Read the stamped per-attempt adaptive timeout off a wire item.
 * Returns `undefined` when the queue did not stamp one (feature off) —
 * the sender then keeps its current behavior untouched.
 */
export function readAdaptiveTimeoutMs(item: { adaptiveTimeoutMs?: unknown }): number | undefined {
  const v = item.adaptiveTimeoutMs;
  return typeof v === "number" && Number.isFinite(v) && v > 0 ? v : undefined;
}
