/**
 * Online changepoint detection for per-endpoint delivery latency (WR-177).
 *
 * Complements the fixed-threshold SLO alerting of `src/latency.ts` (WR-13):
 * a fixed threshold only fires after latency crosses a hard line, while a
 * downstream can degrade *below* that line for a long time. This module
 * watches the accepted→delivered latency stream per endpoint with a
 * Page-Hinkley test and fires `onLatencyRegimeChange` when the *distribution*
 * shifts — endpoint, detection time, and before/after p50/p95 included.
 *
 * It is orthogonal to WR-13 (fixed SLO thresholds on the same stream) and
 * to `src/source-baseline.ts` (inbound source anomaly detection): this one
 * only looks at outbound delivery latency regime shifts.
 *
 * Zero dependencies. The clock is injectable for deterministic tests.
 */

/** Direction of a detected latency regime change. */
export type ChangepointDirection = "increase" | "decrease";

/** Nearest-rank p50/p95 snapshot of one regime's samples. */
export interface RegimeSnapshot {
  p50: number;
  p95: number;
  /** Samples in the snapshot (bounded by `windowSamples`). */
  count: number;
}

/** One detected latency regime change. */
export interface LatencyRegimeChange {
  /** The endpoint whose latency distribution shifted. */
  endpoint: string;
  direction: ChangepointDirection;
  /** Detection time, from the injected clock. */
  detectedAtMs: number;
  /** Latency regime before the change point. */
  before: RegimeSnapshot;
  /** Latency regime after the change point. */
  after: RegimeSnapshot;
}

/** Options for {@link LatencyChangepointDetector}. */
export interface ChangepointOptions {
  /**
   * Minimum mean shift (ms) worth detecting. Default: 100. Raise this on
   * spiky endpoints where small sustained shifts are noise.
   */
  deltaMs?: number;
  /**
   * Alarm threshold on the Page-Hinkley cumulative sum. Default: 300.
   * A larger threshold needs a longer or bigger shift before alarming;
   * a smaller one alarms faster but is more outlier-sensitive.
   */
  lambda?: number;
  /**
   * Observations used to estimate the baseline before detection starts.
   * Default: 10. The baseline mean is the *median* of these samples, so a
   * single outlier during warmup cannot poison the baseline.
   */
  warmupSamples?: number;
  /**
   * Bounded window for the before/after percentile snapshots.
   * Default: 50 (must be ≥ 2).
   */
  windowSamples?: number;
  /** Called on every detected regime change. */
  onLatencyRegimeChange?: (change: LatencyRegimeChange) => void;
  /** Clock source for `detectedAtMs`; defaults to Date.now. Injectable for tests. */
  nowMs?: () => number;
}

export const DEFAULT_CHANGEPOINT_DELTA_MS = 100;
export const DEFAULT_CHANGEPOINT_LAMBDA = 300;
export const DEFAULT_CHANGEPOINT_WARMUP_SAMPLES = 10;
export const DEFAULT_CHANGEPOINT_WINDOW_SAMPLES = 50;

/** Nearest-rank percentile over a pre-sorted sample array. */
function nearestRank(sorted: number[], p: number): number {
  const rank = Math.ceil((p / 100) * sorted.length);
  return sorted[Math.min(Math.max(rank, 1), sorted.length) - 1];
}

function snapshotOf(values: number[]): RegimeSnapshot {
  const sorted = [...values].sort((a, b) => a - b);
  return { p50: nearestRank(sorted, 50), p95: nearestRank(sorted, 95), count: values.length };
}

interface TrackedSample {
  seq: number;
  value: number;
}

/**
 * Page-Hinkley changepoint detector for one endpoint's latency stream.
 *
 * Formulation (one-sided, applied symmetrically to both directions):
 * with a running mean μₙ, the increase statistic is
 *   S⁺ₙ = max(0, S⁺ₙ₋₁ + (xₙ − μₙ − δ/2))
 * and the decrease statistic mirrors it with (μₙ − xₙ − δ/2).
 * An alarm fires when either exceeds λ. The running mean keeps the
 * detector adaptive: after an alarm the baseline is re-estimated from the
 * new regime, so a second shift is detected against the *new* normal
 * rather than the stale one.
 *
 * Memory is bounded: at most `2 * windowSamples` recent samples are kept.
 * Honest limitation: the adaptive mean absorbs per-sample drifts smaller
 * than δ/2 that persist without a plateau — tune δ/λ for the endpoint's
 * noise floor.
 */
export class LatencyChangepointDetector {
  private readonly endpoint: string;
  private readonly deltaMs: number;
  private readonly lambda: number;
  private readonly warmupSamples: number;
  private readonly windowSamples: number;
  private readonly onChange?: (change: LatencyRegimeChange) => void;
  private readonly nowMs: () => number;

  private seq = 0;
  /** Samples since the last (re)start — the running mean's inertia. */
  private n = 0;
  private mean = 0;
  private sumInc = 0;
  private sumDec = 0;
  /** seq at which the current positive run began (for before/after split). */
  private runStartSeq = 1;
  private inRun = false;
  private samples: TrackedSample[] = [];
  private warmup: number[] = [];

  constructor(endpoint: string, options: ChangepointOptions = {}) {
    if (typeof endpoint !== "string" || endpoint === "") {
      throw new RangeError("LatencyChangepointDetector: endpoint must be a non-empty string");
    }
    const deltaMs = options.deltaMs ?? DEFAULT_CHANGEPOINT_DELTA_MS;
    if (!Number.isFinite(deltaMs) || deltaMs <= 0) {
      throw new RangeError("LatencyChangepointDetector: `deltaMs` must be a positive number");
    }
    const lambda = options.lambda ?? DEFAULT_CHANGEPOINT_LAMBDA;
    if (!Number.isFinite(lambda) || lambda <= 0) {
      throw new RangeError("LatencyChangepointDetector: `lambda` must be a positive number");
    }
    const warmupSamples = options.warmupSamples ?? DEFAULT_CHANGEPOINT_WARMUP_SAMPLES;
    if (!Number.isInteger(warmupSamples) || warmupSamples < 1) {
      throw new RangeError("LatencyChangepointDetector: `warmupSamples` must be an integer >= 1");
    }
    const windowSamples = options.windowSamples ?? DEFAULT_CHANGEPOINT_WINDOW_SAMPLES;
    if (!Number.isInteger(windowSamples) || windowSamples < 2) {
      throw new RangeError("LatencyChangepointDetector: `windowSamples` must be an integer >= 2");
    }
    if (options.onLatencyRegimeChange !== undefined && typeof options.onLatencyRegimeChange !== "function") {
      throw new RangeError("LatencyChangepointDetector: `onLatencyRegimeChange` must be a function");
    }
    this.endpoint = endpoint;
    this.deltaMs = deltaMs;
    this.lambda = lambda;
    this.warmupSamples = warmupSamples;
    this.windowSamples = windowSamples;
    this.onChange = options.onLatencyRegimeChange;
    this.nowMs = options.nowMs ?? Date.now;
  }

  /**
   * Observe one accepted→delivered latency sample (ms). Returns the
   * detected {@link LatencyRegimeChange} when this sample triggers an
   * alarm, otherwise `undefined`. The optional
   * `onLatencyRegimeChange` callback fires on the same event.
   */
  observe(latencyMs: number): LatencyRegimeChange | undefined {
    if (!Number.isFinite(latencyMs) || latencyMs < 0) {
      throw new RangeError("LatencyChangepointDetector.observe: latencyMs must be a non-negative number");
    }
    this.seq += 1;
    const sample: TrackedSample = { seq: this.seq, value: latencyMs };
    this.samples.push(sample);
    const cap = this.windowSamples * 2;
    if (this.samples.length > cap) {
      this.samples.splice(0, this.samples.length - cap);
    }

    if (this.n < this.warmupSamples) {
      // Baseline estimation: no detection yet.
      this.warmup.push(latencyMs);
      this.n += 1;
      if (this.n === this.warmupSamples) {
        // Median baseline — robust to a single warmup outlier.
        const sorted = [...this.warmup].sort((a, b) => a - b);
        this.mean = nearestRank(sorted, 50);
        this.warmup = [];
      }
      return undefined;
    }

    this.n += 1;
    this.mean += (latencyMs - this.mean) / this.n;

    const half = this.deltaMs / 2;
    this.sumInc = Math.max(0, this.sumInc + (latencyMs - this.mean - half));
    this.sumDec = Math.max(0, this.sumDec + (this.mean - latencyMs - half));

    if (!this.inRun && (this.sumInc > 0 || this.sumDec > 0)) {
      this.inRun = true;
      this.runStartSeq = this.seq;
    } else if (this.inRun && this.sumInc === 0 && this.sumDec === 0) {
      this.inRun = false;
    }

    let direction: ChangepointDirection | undefined;
    if (this.sumInc > this.lambda) {
      direction = "increase";
    } else if (this.sumDec > this.lambda) {
      direction = "decrease";
    }
    if (direction === undefined) {
      return undefined;
    }

    const change = this.buildChange(direction);

    // Restart against the new regime: the after-window becomes the new
    // baseline, so the next shift is measured against the new normal.
    this.mean = change.afterMean;
    this.n = Math.max(change.event.after.count, 1);
    this.sumInc = 0;
    this.sumDec = 0;
    this.inRun = false;
    this.runStartSeq = this.seq + 1;
    this.samples = this.samples.filter((s) => s.seq >= change.afterSeqStart);

    this.onChange?.(change.event);
    return change.event;
  }

  private buildChange(direction: ChangepointDirection): {
    event: LatencyRegimeChange;
    afterMean: number;
    afterSeqStart: number;
  } {
    const recent = this.samples.slice(-this.windowSamples * 2);
    let beforeVals = recent
      .filter((s) => s.seq < this.runStartSeq)
      .slice(-this.windowSamples)
      .map((s) => s.value);
    let afterVals = recent
      .filter((s) => s.seq >= this.runStartSeq)
      .slice(-this.windowSamples)
      .map((s) => s.value);
    if (afterVals.length === 0) {
      // Cannot happen in practice (the alarming sample is always in the
      // run), but never build a snapshot from nothing.
      afterVals = [recent[recent.length - 1].value];
    }
    if (beforeVals.length === 0) {
      // The run outgrew the retained window: fall back to the oldest
      // retained samples — the best available old-regime approximation.
      beforeVals = recent.slice(0, this.windowSamples).map((s) => s.value);
    }
    const afterSeqStart =
      recent.find((s) => s.seq >= this.runStartSeq)?.seq ?? this.runStartSeq;
    const event: LatencyRegimeChange = {
      endpoint: this.endpoint,
      direction,
      detectedAtMs: this.nowMs(),
      before: snapshotOf(beforeVals),
      after: snapshotOf(afterVals),
    };
    return { event, afterMean: meanOf(afterVals), afterSeqStart };
  }
}

function meanOf(values: number[]): number {
  return values.reduce((a, b) => a + b, 0) / values.length;
}

/**
 * Per-endpoint registry of changepoint detectors. One call site feeds
 * accepted→delivered latency samples; each endpoint gets an isolated
 * detector, so a regime change on one endpoint never alarms another.
 */
export class LatencyChangepointMonitor {
  private readonly detectors = new Map<string, LatencyChangepointDetector>();
  private readonly options: ChangepointOptions;

  constructor(options: ChangepointOptions = {}) {
    this.options = options;
  }

  /**
   * Observe one accepted→delivered latency sample for `endpoint`.
   * Returns the detected change, if any. Lazily creates the endpoint's
   * detector on first use.
   */
  observe(endpoint: string, latencyMs: number): LatencyRegimeChange | undefined {
    let d = this.detectors.get(endpoint);
    if (!d) {
      d = new LatencyChangepointDetector(endpoint, this.options);
      this.detectors.set(endpoint, d);
    }
    return d.observe(latencyMs);
  }

  /** Endpoints with a live detector. */
  endpoints(): string[] {
    return [...this.detectors.keys()];
  }
}
