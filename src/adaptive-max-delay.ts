/**
 * WR-196: adaptive retry-backoff cap.
 *
 * The backoff cap (`maxDelayMs`) is normally a fixed constant: every
 * endpoint's worst-case wait between attempts is the same, whether the
 * endpoint usually answers in 50ms or in 20s. A fixed cap is wrong in
 * both directions:
 *
 * - a chronically slow endpoint's retries sleep the full cap even
 *   though its natural rhythm is slower — wasted recovery time;
 * - a healthy-fast endpoint hit by a transient storm is allowed to
 *   sleep up to the same generous cap, so retries stay sparse long
 *   after the downstream has recovered.
 *
 * This module derives the cap per endpoint from its own recent
 * *successful*-delivery latency: `clamp(p99 * (1 + marginRatio),
 * floorMs, ceilMs)`. Cold start (fewer than `minSamples` samples) uses
 * `baseMaxDelayMs` — the queue's configured `maxDelayMs` — so behavior
 * is byte-identical to the static configuration until there is evidence.
 *
 * Storm tightening: failures never enter the p99 window (only successes
 * are sampled), so a prolonged outage does not drag the p99 anywhere —
 * instead each retryable failure multiplies the adapted cap by
 * `tightenFactor` (default 0.8), walking it down toward `floorMs`. A
 * backoff storm therefore converges the cap on the floor, and the first
 * successes after recovery walk it back up to the endpoint's p99 in one
 * step (the p99 itself was never polluted by the storm).
 *
 * Sampling basis: the module reuses {@link LatencyTracker} (WR-13) with
 * its accepted→delivered clock. That clock includes queue wait and
 * backoff between attempts, so the derived cap is conservative — the
 * margin exists precisely to absorb that slop. It is *not* a measurement
 * of a single backoff wait; treat the cap as a defensive ceiling, not a
 * precise SLO.
 *
 * Composition: orthogonal to WR-59 (which adapts the backoff *base*)
 * and to WR-143 (per-attempt phase budgets, which cap a single attempt
 * while this caps the wait *between* attempts). Policy-assigned
 * endpoints (WR-172) skip adaptation — explicit operator intent beats
 * auto-tuning, exactly like WR-59.
 *
 * Opt-in: when `RetryQueueOptions.adaptiveMaxDelay` is absent the queue
 * keeps the fixed `maxDelayMs` everywhere. No clock, no randomness in
 * the adaptation itself — given the same outcome sequence the caps are
 * deterministic; the injected `now` only drives the latency clock.
 *
 * Zero dependencies.
 */

import { LatencyTracker } from "./latency.ts";

/** Floor for the adapted cap in ms (storm-converged minimum). */
export const DEFAULT_ADAPTIVE_MAX_DELAY_FLOOR_MS = 1000;
/** Headroom above the endpoint's recent success p99: cap = p99 * (1 + margin). */
export const DEFAULT_ADAPTIVE_MAX_DELAY_MARGIN_RATIO = 0.5;
/** Samples required before the cap adapts (cold-start guard). */
export const DEFAULT_ADAPTIVE_MAX_DELAY_MIN_SAMPLES = 10;
/** Multiplicative tighten per retryable failure, in (0, 1). */
export const DEFAULT_ADAPTIVE_MAX_DELAY_TIGHTEN_FACTOR = 0.8;

/** Options for {@link AdaptiveMaxDelay}. */
export interface AdaptiveMaxDelayOptions {
  /**
   * Headroom above the endpoint's recent successful-delivery p99: the
   * relaxed cap is `p99 * (1 + marginRatio)`. Default: 0.5 (50%
   * headroom). Must be a finite number >= 0.
   */
  marginRatio?: number;
  /**
   * Floor for the adapted cap in ms: a backoff storm converges the cap
   * here, never below. Default: 1000. Must be a finite number > 0.
   */
  floorMs?: number;
  /**
   * Ceiling for the adapted cap in ms: the cap never relaxes past this,
   * no matter how slow the endpoint is. Default: `4 * baseMaxDelayMs`.
   * Must be a finite number > 0 and >= `floorMs`.
   */
  ceilMs?: number;
  /**
   * Samples required before the cap adapts (cold-start guard).
   * Default: 10. Must be an integer >= 1.
   */
  minSamples?: number;
  /**
   * Rolling sample window per endpoint, forwarded to the underlying
   * {@link LatencyTracker}. Default: 1024. Must be an integer >= 1.
   */
  maxSamplesPerEndpoint?: number;
  /**
   * Multiplicative tighten applied per retryable failure, in the open
   * interval (0, 1): `cap = max(floorMs, cap * tightenFactor)`.
   * Default: 0.8. Must be > 0 and < 1.
   */
  tightenFactor?: number;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
}

/** Per-endpoint adaptive cap view. All JSON-serializable. */
export interface AdaptiveMaxDelayEndpointStats {
  /** The endpoint (physical `targetUrl`) this row describes. */
  endpoint: string;
  /** The backoff cap (ms) the next retry wait to this endpoint is bounded by. */
  capMs: number;
  /** Successful-delivery samples currently in the rolling window. */
  samples: number;
  /** Recent success p99 the cap was derived from (`baseMaxDelayMs` basis when cold). */
  p99Ms: number;
}

function assertAdaptiveMaxDelayOptions(
  initialMaxMs: number,
  opts: AdaptiveMaxDelayOptions
): {
  marginRatio: number;
  floorMs: number;
  ceilMs: number;
  minSamples: number;
  maxSamplesPerEndpoint: number;
  tightenFactor: number;
} {
  if (!Number.isFinite(initialMaxMs) || initialMaxMs <= 0) {
    throw new RangeError(
      `adaptiveMaxDelay: initial max delay must be > 0, got ${initialMaxMs}`
    );
  }
  const marginRatio = opts.marginRatio ?? DEFAULT_ADAPTIVE_MAX_DELAY_MARGIN_RATIO;
  if (!Number.isFinite(marginRatio) || marginRatio < 0) {
    throw new RangeError(
      `adaptiveMaxDelay.marginRatio must be a finite number >= 0, got ${opts.marginRatio}`
    );
  }
  const floorMs = opts.floorMs ?? DEFAULT_ADAPTIVE_MAX_DELAY_FLOOR_MS;
  if (!Number.isFinite(floorMs) || floorMs <= 0) {
    throw new RangeError(
      `adaptiveMaxDelay.floorMs must be a finite number > 0, got ${opts.floorMs}`
    );
  }
  const ceilMs = opts.ceilMs ?? 4 * initialMaxMs;
  if (!Number.isFinite(ceilMs) || ceilMs <= 0) {
    throw new RangeError(
      `adaptiveMaxDelay.ceilMs must be a finite number > 0, got ${opts.ceilMs}`
    );
  }
  if (ceilMs < floorMs) {
    throw new RangeError(
      `adaptiveMaxDelay.ceilMs (${ceilMs}) must be >= floorMs (${floorMs})`
    );
  }
  const minSamples = opts.minSamples ?? DEFAULT_ADAPTIVE_MAX_DELAY_MIN_SAMPLES;
  if (!Number.isInteger(minSamples) || minSamples < 1) {
    throw new RangeError(
      `adaptiveMaxDelay.minSamples must be an integer >= 1, got ${opts.minSamples}`
    );
  }
  const maxSamplesPerEndpoint = opts.maxSamplesPerEndpoint ?? 1024;
  if (!Number.isInteger(maxSamplesPerEndpoint) || maxSamplesPerEndpoint < 1) {
    throw new RangeError(
      `adaptiveMaxDelay.maxSamplesPerEndpoint must be an integer >= 1, got ${opts.maxSamplesPerEndpoint}`
    );
  }
  const tightenFactor = opts.tightenFactor ?? DEFAULT_ADAPTIVE_MAX_DELAY_TIGHTEN_FACTOR;
  if (!Number.isFinite(tightenFactor) || tightenFactor <= 0 || tightenFactor >= 1) {
    throw new RangeError(
      `adaptiveMaxDelay.tightenFactor must be in the open interval (0, 1), got ${opts.tightenFactor}`
    );
  }
  return { marginRatio, floorMs, ceilMs, minSamples, maxSamplesPerEndpoint, tightenFactor };
}

/**
 * Per-endpoint adaptive retry-backoff cap (WR-196), derived from recent
 * successful-delivery latency percentiles.
 *
 * The queue feeds the same delivery-lifecycle events as the WR-13
 * latency tracker (`recordAccepted` on admission, `recordDelivered` on
 * success, `discard` on dead letter), plus `recordFailure` on each
 * retryable failure (the storm signal), and reads the next retry's cap
 * via `capFor()`.
 */
export class AdaptiveMaxDelay {
  private readonly marginRatio: number;
  private readonly floorMs: number;
  private readonly ceilMs: number;
  private readonly minSamples: number;
  /**
   * The resting cap, read live: endpoints with no samples use it, so a
   * queue-level hot-reload of `maxDelayMs` (WR-32) stays in sync without
   * touching adapted endpoints.
   */
  private readonly baseMaxDelay: () => number;
  private readonly tightenFactor: number;
  private readonly tracker: LatencyTracker;
  /** The currently adapted cap per endpoint (only for warm endpoints). */
  private readonly caps = new Map<string, number>();

  constructor(baseMaxDelayMs: number | (() => number), opts: AdaptiveMaxDelayOptions = {}) {
    const initial = typeof baseMaxDelayMs === "function" ? baseMaxDelayMs() : baseMaxDelayMs;
    const { marginRatio, floorMs, ceilMs, minSamples, maxSamplesPerEndpoint, tightenFactor } =
      assertAdaptiveMaxDelayOptions(initial, opts);
    this.marginRatio = marginRatio;
    this.floorMs = floorMs;
    this.ceilMs = ceilMs;
    this.minSamples = minSamples;
    this.baseMaxDelay =
      typeof baseMaxDelayMs === "function" ? baseMaxDelayMs : () => baseMaxDelayMs;
    this.tightenFactor = tightenFactor;
    // The tracker's own SLO bookkeeping is irrelevant here — only the
    // rolling p99 window is used — so sloMs just needs to be valid.
    this.tracker = new LatencyTracker({
      sloMs: initial,
      maxSamplesPerEndpoint,
      now: opts.now,
    });
  }

  /** Mark a delivery accepted: starts its latency clock. */
  recordAccepted(id: string): void {
    this.tracker.recordAccepted(id);
  }

  /**
   * Mark a delivery delivered: samples its accepted→delivered latency
   * and, once the endpoint is warm, relaxes the adapted cap to the
   * p99-derived target. Failures never reach this path — the p99 stays
   * clean through a storm.
   */
  recordDelivered(id: string, endpoint: string): void {
    if (this.tracker.recordDelivered(id, endpoint) === undefined) return;
    const target = this.p99Target(endpoint);
    if (target !== undefined) this.caps.set(endpoint, target);
  }

  /**
   * Feed one retryable failure for `endpoint` (the storm signal): the
   * adapted cap tightens multiplicatively toward `floorMs`. Cold
   * endpoints are untouched — with no evidence the resting cap stands.
   */
  recordFailure(endpoint: string): void {
    const target = this.p99Target(endpoint);
    if (target === undefined) return;
    const current = this.caps.get(endpoint) ?? target;
    this.caps.set(endpoint, Math.max(this.floorMs, current * this.tightenFactor));
  }

  /** Drop a pending accepted record without sampling (e.g. dead-lettered). */
  discard(id: string): void {
    this.tracker.discard(id);
  }

  /**
   * The backoff cap (ms) for the next retry wait to `endpoint`: the
   * adapted cap when warm, the resting `baseMaxDelayMs` when cold.
   */
  capFor(endpoint: string): number {
    const target = this.p99Target(endpoint);
    if (target === undefined) return this.baseMaxDelay();
    return this.caps.get(endpoint) ?? target;
  }

  /** Forget an endpoint's adapted cap (`undefined` = all endpoints). */
  reset(endpoint?: string): void {
    if (endpoint === undefined) {
      this.caps.clear();
      return;
    }
    this.caps.delete(endpoint);
  }

  /** Per-endpoint adaptive cap view for operator observability. */
  stats(): AdaptiveMaxDelayEndpointStats[] {
    return this.tracker.stats().map((s) => ({
      endpoint: s.endpoint,
      capMs: this.capFor(s.endpoint),
      samples: s.count,
      p99Ms: s.count < this.minSamples ? this.baseMaxDelay() : s.p99,
    }));
  }

  /**
   * The p99-derived cap target for `endpoint`, clamped to
   * `[floorMs, ceilMs]` — or `undefined` while the endpoint is cold.
   */
  private p99Target(endpoint: string): number | undefined {
    const [s] = this.tracker.stats(endpoint);
    if (s === undefined || s.count < this.minSamples) return undefined;
    return Math.min(this.ceilMs, Math.max(this.floorMs, s.p99 * (1 + this.marginRatio)));
  }
}

/** Validate an {@link AdaptiveMaxDelayOptions} against a base cap. Throws `RangeError` on anything invalid. */
export function assertValidAdaptiveMaxDelayOptions(
  baseMaxDelayMs: number,
  opts: unknown
): void {
  if (opts === null || typeof opts !== "object" || Array.isArray(opts)) {
    throw new RangeError(`adaptiveMaxDelay must be an options object, got ${String(opts)}`);
  }
  assertAdaptiveMaxDelayOptions(baseMaxDelayMs, opts as AdaptiveMaxDelayOptions);
  const o = opts as Record<string, unknown>;
  if (o.now !== undefined && typeof o.now !== "function") {
    throw new RangeError(`adaptiveMaxDelay.now must be a function, got ${String(o.now)}`);
  }
}
