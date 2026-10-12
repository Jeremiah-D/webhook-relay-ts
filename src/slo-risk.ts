/**
 * WR-71: SLO-breach prediction and early warning.
 *
 * The WR-13 latency tracker reports a delivery that *already* missed its
 * SLO (`onSloMiss` / `slo_missed`). This predictor warns *before* the
 * breach, from two complementary signals:
 *
 * 1. **Latency pressure** — the rolling p95 of accepted→delivered latency
 *    (WR-13) creeping toward the SLO budget. Recent experience: reactive,
 *    but early — it fires at `warnRatio` of the budget (default 0.8),
 *    not at the breach.
 * 2. **Backlog pressure** — a forward projection of the queueing delay a
 *    newly accepted delivery is about to experience: the per-endpoint
 *    backlog's EWMA (plus its smoothed trend projected `trendHorizon`
 *    observation steps ahead) × the unloaded service time (the rolling
 *    `min` — a delivery that sailed through unqueued approximates pure
 *    service time) ÷ the endpoint's dispatch concurrency. With unbounded
 *    concurrency there is no queueing delay, so this term is honestly 0.
 *
 * `score = max(latencyPressure, backlogPressure)`; 1.0 means "breach
 * predicted". The state machine fires `onSloRisk` once per transition
 * (`elevated` → `cleared`) with hysteresis (`clearRatio`), so a score
 * hovering at the threshold does not flap the callback.
 *
 * Evaluation is event-driven — every `enqueue` and every delivered sample
 * feeds one observation — so no timers are involved and the whole thing is
 * deterministic under an injected clock. Cold start (fewer than
 * `minSamples` delivered samples) never fires: the predictor keeps its
 * backlog EWMA warm but withholds judgment until it has latency evidence.
 */

/** Options for {@link SloRiskPredictor}. */
export interface SloRiskOptions {
  /**
   * Fraction of the SLO budget at which risk fires, in (0, 1].
   * Default: 0.8 — warn while there is still 20% headroom.
   */
  warnRatio?: number;
  /**
   * EWMA smoothing factor for backlog samples and for the backlog trend,
   * in (0, 1]. Higher values react faster to bursts. Default: 0.2.
   */
  ewmaAlpha?: number;
  /**
   * Delivered latency samples required before any evaluation. Guards the
   * cold start: without latency evidence there is no service-time
   * estimate. Must be an integer >= 1. Default: 3.
   */
  minSamples?: number;
  /**
   * Hysteresis for recovery: an elevated endpoint clears only once its
   * score drops below `warnRatio * clearRatio`, in (0, 1). Default: 0.7.
   */
  clearRatio?: number;
  /**
   * How many observation steps ahead the smoothed backlog trend is
   * projected (>= 0). 0 ignores the trend and uses the backlog level
   * alone. Default: 3.
   */
  trendHorizon?: number;
  /** Called once per risk-state transition (`elevated` / `cleared`). */
  onSloRisk?: (info: SloRiskInfo) => void;
}

/** One risk-state transition. All JSON-serializable. */
export interface SloRiskInfo {
  endpoint: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  /** `"elevated"` when risk fires, `"cleared"` on recovery. */
  state: "elevated" | "cleared";
  /**
   * `max(latencyPressure, backlogPressure)` — normalized so 1.0 is a
   * predicted breach and `warnRatio` is the fire threshold.
   */
  score: number;
  /** Predicted accepted→delivered latency for a newly accepted delivery, ms. */
  predictedLatencyMs: number;
  /** p95 of the rolling latency window behind the prediction, ms. */
  p95Ms: number;
  /** Smoothed per-endpoint backlog (queued + in-flight + backoff-waiting). */
  backlogEwma: number;
  /** The SLO budget the score was computed against, ms. */
  sloMs: number;
}

/** One observation fed into {@link SloRiskPredictor.observe}. */
export interface SloRiskObservation {
  /** Current per-endpoint backlog (queued + in-flight + backoff-waiting). */
  backlog: number;
  /**
   * Rolling latency stats for the endpoint. `undefined` (or below
   * `minSamples`) means cold start: the backlog EWMA still updates, but
   * no risk is evaluated.
   */
  stats?: { p95: number; min: number; count: number };
  /** Per-endpoint dispatch concurrency (`Infinity` = unbounded). */
  concurrency: number;
  /** SLO budget in ms. */
  sloMs: number;
}

interface EndpointState {
  backlogEwma: number;
  trendEwma: number;
  initialized: boolean;
  /** True once at least one evaluation ran (score/prediction are meaningful). */
  evaluated: boolean;
  atRisk: boolean;
  score: number;
  predictedLatencyMs: number;
  p95Ms: number;
  sloMs: number;
}

function checkRatio(name: string, value: number | undefined, def: number, upperInclusive: boolean): number {
  const v = value ?? def;
  const ok = Number.isFinite(v) && v > 0 && (upperInclusive ? v <= 1 : v < 1);
  if (!ok) {
    throw new RangeError(
      `${name} must be in ${upperInclusive ? "(0, 1]" : "(0, 1)"}, got ${value}`
    );
  }
  return v;
}

/**
 * Per-endpoint SLO-breach predictor. One instance serves every endpoint;
 * tenants get separate instances (see `RetryQueue`, mirroring the
 * per-tenant `LatencyTracker`).
 */
export class SloRiskPredictor {
  private readonly warnRatio: number;
  private readonly alpha: number;
  private readonly minSamples: number;
  private readonly clearRatio: number;
  private readonly trendHorizon: number;
  private readonly onSloRisk?: (info: SloRiskInfo) => void;
  private readonly endpoints = new Map<string, EndpointState>();

  constructor(opts: SloRiskOptions = {}) {
    this.warnRatio = checkRatio("warnRatio", opts.warnRatio, 0.8, true);
    this.alpha = checkRatio("ewmaAlpha", opts.ewmaAlpha, 0.2, true);
    const minSamples = opts.minSamples ?? 3;
    if (!Number.isInteger(minSamples) || minSamples < 1) {
      throw new RangeError(`minSamples must be an integer >= 1, got ${opts.minSamples}`);
    }
    this.minSamples = minSamples;
    this.clearRatio = checkRatio("clearRatio", opts.clearRatio, 0.7, false);
    const trendHorizon = opts.trendHorizon ?? 3;
    if (!Number.isFinite(trendHorizon) || trendHorizon < 0) {
      throw new RangeError(`trendHorizon must be >= 0, got ${opts.trendHorizon}`);
    }
    this.trendHorizon = trendHorizon;
    this.onSloRisk = opts.onSloRisk;
  }

  /**
   * Feed one observation for `endpoint`. Returns the transition info when
   * this observation flips the risk state, `undefined` otherwise (the
   * callback fires exactly on the returned transitions).
   */
  observe(endpoint: string, obs: SloRiskObservation): SloRiskInfo | undefined {
    let st = this.endpoints.get(endpoint);
    if (st === undefined) {
      st = {
        backlogEwma: 0,
        trendEwma: 0,
        initialized: false,
        evaluated: false,
        atRisk: false,
        score: 0,
        predictedLatencyMs: 0,
        p95Ms: 0,
        sloMs: obs.sloMs,
      };
      this.endpoints.set(endpoint, st);
    }
    // The backlog EWMA updates on every observation — including cold
    // start — so the trend is already warm when latency evidence arrives.
    if (!st.initialized) {
      st.backlogEwma = obs.backlog;
      st.trendEwma = 0;
      st.initialized = true;
    } else {
      const prev = st.backlogEwma;
      st.backlogEwma = this.alpha * obs.backlog + (1 - this.alpha) * prev;
      st.trendEwma = this.alpha * (obs.backlog - prev) + (1 - this.alpha) * st.trendEwma;
    }
    const stats = obs.stats;
    if (stats === undefined || stats.count < this.minSamples) return undefined;

    // Forward queueing projection: only the *growing* part of the trend
    // counts — a draining backlog is good news, not risk.
    const serviceMs = Math.max(1, stats.min);
    const projectedBacklog = Math.max(
      0,
      st.backlogEwma + Math.max(0, st.trendEwma) * this.trendHorizon
    );
    const queueWaitMs =
      obs.concurrency === Infinity
        ? 0
        : (projectedBacklog * serviceMs) / Math.max(1, obs.concurrency);
    const predicted = serviceMs + queueWaitMs;
    const score = Math.max(stats.p95 / obs.sloMs, predicted / obs.sloMs);
    st.evaluated = true;
    st.score = score;
    st.predictedLatencyMs = predicted;
    st.p95Ms = stats.p95;
    st.sloMs = obs.sloMs;

    const info = (state: "elevated" | "cleared"): SloRiskInfo => ({
      endpoint,
      state,
      score,
      predictedLatencyMs: predicted,
      p95Ms: stats.p95,
      backlogEwma: st!.backlogEwma,
      sloMs: obs.sloMs,
    });
    if (!st.atRisk && score >= this.warnRatio) {
      st.atRisk = true;
      const i = info("elevated");
      this.onSloRisk?.(i);
      return i;
    }
    if (st.atRisk && score < this.warnRatio * this.clearRatio) {
      st.atRisk = false;
      const i = info("cleared");
      this.onSloRisk?.(i);
      return i;
    }
    return undefined;
  }

  /**
   * Currently elevated endpoints with their predicted SLO headroom in
   * seconds (`max(0, sloMs - predicted) / 1000`) — the source of the
   * `relay_slo_risk_seconds` gauge. Empty when nothing is at risk, so the
   * series stays absent exactly like the other activity-gated series.
   */
  atRisk(): Array<{
    endpoint: string;
    score: number;
    predictedLatencyMs: number;
    headroomSeconds: number;
  }> {
    const out: Array<{
      endpoint: string;
      score: number;
      predictedLatencyMs: number;
      headroomSeconds: number;
    }> = [];
    for (const [endpoint, st] of this.endpoints) {
      if (!st.atRisk) continue;
      out.push({
        endpoint,
        score: st.score,
        predictedLatencyMs: st.predictedLatencyMs,
        headroomSeconds: Math.max(0, st.sloMs - st.predictedLatencyMs) / 1000,
      });
    }
    return out;
  }

  /**
   * One row per endpoint with at least one evaluation (operator view;
   * see `RetryQueue.getSloRiskStats`). Endpoints still in cold start are
   * omitted — their score would be meaningless.
   */
  snapshot(): Array<{
    endpoint: string;
    atRisk: boolean;
    score: number;
    predictedLatencyMs: number;
    p95Ms: number;
    backlogEwma: number;
    headroomSeconds: number;
  }> {
    const out: Array<{
      endpoint: string;
      atRisk: boolean;
      score: number;
      predictedLatencyMs: number;
      p95Ms: number;
      backlogEwma: number;
      headroomSeconds: number;
    }> = [];
    for (const [endpoint, st] of this.endpoints) {
      if (!st.evaluated) continue;
      out.push({
        endpoint,
        atRisk: st.atRisk,
        score: st.score,
        predictedLatencyMs: st.predictedLatencyMs,
        p95Ms: st.p95Ms,
        backlogEwma: st.backlogEwma,
        headroomSeconds: Math.max(0, st.sloMs - st.predictedLatencyMs) / 1000,
      });
    }
    return out;
  }
}
