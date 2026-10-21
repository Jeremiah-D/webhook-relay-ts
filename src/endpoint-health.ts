/**
 * WR-179: outbound endpoint health scoring.
 *
 * Per-endpoint 0–100 health score, a weighted aggregation of three
 * complementary signals:
 *
 * 1. **Success-rate EWMA** — over recent delivery outcomes (1 = success,
 *    0 = failure), smoothed with `ewmaAlpha`. This is the dominant
 *    signal: an endpoint that keeps answering is healthy.
 * 2. **p95 latency deviation** — the rolling p95 of delivered-latency
 *    samples (accepted→delivered, the same lifecycle the WR-13 tracker
 *    measures) judged against `sloMs`: p95 <= `sloMs` scores full marks,
 *    then degrades linearly to 0 at 2× `sloMs`.
 * 3. **Circuit-open penalty** — while the endpoint's circuit reports
 *    `open` (read live through the `circuitState` provider, never
 *    cached), `circuitOpenPenalty` points are subtracted (the default of
 *    100 grades an open endpoint at 0: a tripped breaker *is* the health
 *    verdict). `half_open` is scored without penalty — a probing
 *    endpoint has not been judged yet.
 *
 * Score = 100 × (successWeight × successEwma + latencyWeight ×
 * latencyTerm) / (successWeight + latencyWeight), minus the open penalty,
 * clamped to [0, 100] and rounded to 2 decimals. Cold start (no outcomes
 * yet) scores 100 — an unseen endpoint is healthy until proven
 * otherwise, the same posture as the WR-119 inbound reputation.
 *
 * Thresholds use hysteresis, symmetric with the WR-119 convention: the
 * score must fall *strictly below* `degradeThreshold` to degrade and
 * climb *strictly above* `recoverThreshold` to recover — a score
 * oscillating between the two lines cannot flap. The downgrade fires
 * `onEndpointDegraded` once per degradation episode (edge-triggered)
 * carrying `{ endpoint, score, consecutiveLowScores }`; the upgrade
 * fires `onEndpointRecovered`. `consecutiveLowScores` counts consecutive
 * score evaluations strictly below `degradeThreshold` — the operator
 * endpoint (`GET /endpoint-health`) exposes it live, so a prolonged
 * degradation reads as a growing count, not just a boolean.
 *
 * Evaluation is event-driven — every recorded outcome re-evaluates the
 * score — so no timers are involved and the whole thing is deterministic
 * under an injected clock. Opt-in: the caller only constructs the
 * tracker when the feature is enabled; unset = zero behavior change.
 *
 * Zero dependencies. The clock is injectable for deterministic tests.
 */

import type { CircuitState } from "./circuit.ts";

/** Options for {@link EndpointHealthTracker}. */
export interface EndpointHealthOptions {
  /**
   * EWMA smoothing factor for the success-rate term, in (0, 1]. Higher
   * values react faster to outcome streaks. Default: 0.2.
   */
  ewmaAlpha?: number;
  /**
   * Rolling delivered-latency sample window per endpoint: only the
   * newest N samples feed the p95 term. Default: 256. Must be an integer
   * >= 1.
   */
  maxLatencySamples?: number;
  /**
   * SLO budget in ms the p95 term is judged against: p95 <= `sloMs` is
   * full marks, p95 >= 2× `sloMs` is zero. Default: 5000. Must be > 0.
   */
  sloMs?: number;
  /**
   * Weight of the success-rate EWMA term in the aggregation. Default:
   * 0.7 — reliability is the primary health signal. Must be finite and
   * >= 0; at least one of the two weights must be > 0.
   */
  successWeight?: number;
  /**
   * Weight of the p95-latency term in the aggregation. Default: 0.3 —
   * a latency modifier on top of reliability. Must be finite and >= 0;
   * at least one of the two weights must be > 0.
   */
  latencyWeight?: number;
  /**
   * Points subtracted from the score while the endpoint's circuit is
   * open (read live through `circuitState`, never cached). Default: 100
   * — an open endpoint grades at 0. Must be finite and >= 0.
   */
  circuitOpenPenalty?: number;
  /**
   * A score strictly below this degrades the endpoint (edge-triggered,
   * once per episode). Default: 40. Must be a finite number in [0, 100]
   * and strictly below `recoverThreshold` — the gap is the hysteresis
   * that prevents flapping.
   */
  degradeThreshold?: number;
  /**
   * A degraded endpoint whose score climbs strictly above this recovers.
   * Default: 70. Must be a finite number in [0, 100] and strictly above
   * `degradeThreshold`.
   */
  recoverThreshold?: number;
  /**
   * Called once per degradation episode: the score fell strictly below
   * `degradeThreshold`. The info carries the consecutive low-score
   * count (1 at the crossing) so alerting can grade severity.
   */
  onEndpointDegraded?: (info: EndpointDegradedInfo) => void;
  /**
   * Called once per recovery: a degraded endpoint's score climbed
   * strictly above `recoverThreshold`.
   */
  onEndpointRecovered?: (info: EndpointRecoveredInfo) => void;
  /**
   * The endpoint's current circuit state, used for the open-penalty
   * term. The queue wires its own breaker here. Defaults to a provider
   * that always reports `"closed"` (no penalty).
   */
  circuitState?: (endpoint: string) => CircuitState;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
}

/** Fail with a RangeError naming the offending input. */
function invalid(where: string, detail: string): never {
  throw new RangeError(`endpointHealth: ${where}: ${detail}`);
}

/**
 * Validate endpoint health options. Throws RangeError on a bad EWMA
 * alpha, sample window, SLO budget, non-finite/negative weights (or both
 * weights zero), negative penalty, thresholds outside [0, 100], or
 * thresholds without a strict degrade < recover gap — fail fast at
 * startup, never mid-request.
 */
export function assertValidEndpointHealthOptions(opts: EndpointHealthOptions | undefined): void {
  if (opts === undefined) return;
  if (opts === null || typeof opts !== "object") {
    throw new RangeError("endpointHealth: expected an options object");
  }
  const inOpenUnit = (name: string, v: number | undefined, upperInclusive: boolean): void => {
    if (v === undefined) return;
    const ok = typeof v === "number" && Number.isFinite(v) && v > 0 && (upperInclusive ? v <= 1 : v < 1);
    if (!ok) {
      invalid(name, `expected a finite number in ${upperInclusive ? "(0, 1]" : "(0, 1)"}, got ${v}`);
    }
  };
  inOpenUnit("ewmaAlpha", opts.ewmaAlpha, true);
  if (opts.maxLatencySamples !== undefined) {
    if (!Number.isInteger(opts.maxLatencySamples) || opts.maxLatencySamples < 1) {
      invalid("maxLatencySamples", `expected an integer >= 1, got ${opts.maxLatencySamples}`);
    }
  }
  if (opts.sloMs !== undefined && (!Number.isFinite(opts.sloMs) || opts.sloMs <= 0)) {
    invalid("sloMs", `expected a finite number > 0, got ${opts.sloMs}`);
  }
  for (const name of ["successWeight", "latencyWeight"] as const) {
    const v = opts[name];
    if (v !== undefined && (typeof v !== "number" || !Number.isFinite(v) || v < 0)) {
      invalid(name, `expected a finite number >= 0, got ${v}`);
    }
  }
  if ((opts.successWeight ?? 0.7) + (opts.latencyWeight ?? 0.3) <= 0) {
    invalid("successWeight/latencyWeight", "at least one weight must be > 0");
  }
  if (
    opts.circuitOpenPenalty !== undefined &&
    (typeof opts.circuitOpenPenalty !== "number" ||
      !Number.isFinite(opts.circuitOpenPenalty) ||
      opts.circuitOpenPenalty < 0)
  ) {
    invalid("circuitOpenPenalty", `expected a finite number >= 0, got ${opts.circuitOpenPenalty}`);
  }
  for (const name of ["degradeThreshold", "recoverThreshold"] as const) {
    const v = opts[name];
    if (v !== undefined && (typeof v !== "number" || !Number.isFinite(v) || v < 0 || v > 100)) {
      invalid(name, `expected a finite number in [0, 100], got ${v}`);
    }
  }
  const degrade = opts.degradeThreshold ?? 40;
  const recover = opts.recoverThreshold ?? 70;
  if (degrade >= recover) {
    invalid(
      "degradeThreshold/recoverThreshold",
      `degradeThreshold (${degrade}) must be strictly below recoverThreshold (${recover})`
    );
  }
  for (const name of ["onEndpointDegraded", "onEndpointRecovered", "circuitState", "now"] as const) {
    if (opts[name] !== undefined && typeof opts[name] !== "function") {
      invalid(name, "expected a function");
    }
  }
}

/**
 * Fired once per degradation episode: the endpoint's score fell strictly
 * below `degradeThreshold`. All JSON-serializable.
 */
export interface EndpointDegradedInfo {
  /** The degraded endpoint (physical `targetUrl`). */
  endpoint: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  /** The score at the crossing instant, in [0, 100]. */
  score: number;
  /**
   * Consecutive score evaluations strictly below `degradeThreshold`
   * (1 at the crossing; the live count keeps growing on the operator
   * view while the endpoint stays low).
   */
  consecutiveLowScores: number;
  /** The ms timestamp of the crossing (the tracker's clock). */
  at: number;
}

/**
 * Fired once per recovery: a degraded endpoint's score climbed strictly
 * above `recoverThreshold`. All JSON-serializable.
 */
export interface EndpointRecoveredInfo {
  /** The recovered endpoint (physical `targetUrl`). */
  endpoint: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  /** The score at the crossing instant, in [0, 100]. */
  score: number;
  /** The ms timestamp of the crossing (the tracker's clock). */
  at: number;
}

/** A threshold crossing: the caller's cue to alert or audit. */
export type EndpointHealthTransition =
  | ({ kind: "degraded" } & EndpointDegradedInfo)
  | ({ kind: "recovered" } & EndpointRecoveredInfo);

/** One row of {@link EndpointHealthTracker.snapshot}. All JSON-serializable. */
export interface EndpointHealthStatsRow {
  /** The endpoint (physical `targetUrl`). */
  endpoint: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  /** Current 0–100 health score; 100 when never observed. */
  score: number;
  /** Whether the endpoint is currently degraded. */
  degraded: boolean;
  /** Consecutive score evaluations strictly below `degradeThreshold`. */
  consecutiveLowScores: number;
  /** Current success-rate EWMA in [0, 1] (starts at 1 = pristine). */
  successEwma: number;
  /** Rolling p95 of delivered-latency samples in ms; absent before the first sample. */
  p95Ms?: number;
  /** The endpoint's circuit state as seen by the scorer (the open-penalty term). */
  circuitState: CircuitState;
}

interface EndpointState {
  /**
   * Success-rate EWMA in [0, 1]. Starts at 1 (pristine) so the first
   * outcomes blend in smoothly — a single blip never craters the score
   * on its own; the EWMA earns its smoothing from the first sample.
   */
  ewma: number;
  /** Rolling delivered-latency samples, newest last, capped at `maxLatencySamples`. */
  samples: number[];
  /** Whether the endpoint is currently degraded. */
  degraded: boolean;
  /** Consecutive score evaluations strictly below `degradeThreshold`. */
  consecutiveLowScores: number;
}

/** Pristine score: no outcomes recorded yet — healthy until proven otherwise. */
const PRISTINE_SCORE = 100;

/** Nearest-rank percentile over a pre-sorted sample array (the WR-13 convention). */
function percentile(sorted: number[], p: number): number {
  const rank = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.min(sorted.length - 1, Math.max(0, rank))];
}

/**
 * Per-endpoint outbound health tracker: weighted 0–100 scores with
 * hysteresis thresholding. Construct once per tenant at first use
 * (invalid config throws RangeError there); `recordOutcome` /
 * `recordLatency` / `score` / `snapshot` are then safe to call per
 * delivery — they never throw on hostile input (an endpoint key is an
 * opaque string).
 */
export class EndpointHealthTracker {
  private readonly ewmaAlpha: number;
  private readonly maxLatencySamples: number;
  private readonly sloMs: number;
  private readonly successWeight: number;
  private readonly latencyWeight: number;
  private readonly circuitOpenPenalty: number;
  private readonly degradeThreshold: number;
  private readonly recoverThreshold: number;
  private readonly onEndpointDegraded?: (info: EndpointDegradedInfo) => void;
  private readonly onEndpointRecovered?: (info: EndpointRecoveredInfo) => void;
  private readonly circuitState: (endpoint: string) => CircuitState;
  private readonly now: () => number;
  private readonly endpoints = new Map<string, EndpointState>();

  constructor(opts: EndpointHealthOptions = {}) {
    assertValidEndpointHealthOptions(opts);
    this.ewmaAlpha = opts.ewmaAlpha ?? 0.2;
    this.maxLatencySamples = opts.maxLatencySamples ?? 256;
    this.sloMs = opts.sloMs ?? 5000;
    this.successWeight = opts.successWeight ?? 0.7;
    this.latencyWeight = opts.latencyWeight ?? 0.3;
    this.circuitOpenPenalty = opts.circuitOpenPenalty ?? 100;
    this.degradeThreshold = opts.degradeThreshold ?? 40;
    this.recoverThreshold = opts.recoverThreshold ?? 70;
    this.onEndpointDegraded = opts.onEndpointDegraded;
    this.onEndpointRecovered = opts.onEndpointRecovered;
    this.circuitState = opts.circuitState ?? (() => "closed");
    this.now = opts.now ?? Date.now;
  }

  private stateFor(endpoint: string): EndpointState {
    let s = this.endpoints.get(endpoint);
    if (!s) {
      s = { ewma: 1, samples: [], degraded: false, consecutiveLowScores: 0 };
      this.endpoints.set(endpoint, s);
    }
    return s;
  }

  /** The p95 term in [0, 1]: 1 at or under `sloMs`, 0 at or beyond 2× `sloMs`. */
  private latencyTerm(s: EndpointState): number {
    if (s.samples.length === 0) return 1; // no latency evidence yet — don't punish
    const sorted = [...s.samples].sort((a, b) => a - b);
    const p95 = percentile(sorted, 95);
    if (p95 <= this.sloMs) return 1;
    return Math.max(0, 1 - (p95 - this.sloMs) / this.sloMs);
  }

  /** Current 0–100 score for an endpoint state (rounded to 2 decimals for stable exposition). */
  private scoreOf(endpoint: string, s: EndpointState): number {
    const totalWeight = this.successWeight + this.latencyWeight;
    const successTerm = s.ewma;
    let score = (PRISTINE_SCORE * (this.successWeight * successTerm + this.latencyWeight * this.latencyTerm(s))) / totalWeight;
    // Read live, never cached: a tripped breaker *is* the health
    // verdict. half_open carries no penalty — a probing endpoint has not
    // been judged yet.
    if (this.circuitState(endpoint) === "open") {
      score = Math.max(0, score - this.circuitOpenPenalty);
    }
    return Math.round(Math.max(0, Math.min(PRISTINE_SCORE, score)) * 100) / 100;
  }

  /**
   * Run the hysteresis state machine for `endpoint` against its current
   * score. Returns the threshold crossing (if any); the matching
   * callback fires exactly on the returned transitions.
   */
  private evaluate(endpoint: string, s: EndpointState): EndpointHealthTransition | undefined {
    const at = this.now();
    const score = this.scoreOf(endpoint, s);
    if (score < this.degradeThreshold) {
      s.consecutiveLowScores += 1;
      if (!s.degraded) {
        s.degraded = true;
        const info: EndpointDegradedInfo = { endpoint, score, consecutiveLowScores: s.consecutiveLowScores, at };
        this.onEndpointDegraded?.(info);
        return { kind: "degraded", ...info };
      }
      return undefined;
    }
    // At or above the degrade line the low streak breaks — the
    // hysteresis band counts as healthy-ish, not as accumulating damage.
    s.consecutiveLowScores = 0;
    if (s.degraded && score > this.recoverThreshold) {
      s.degraded = false;
      const info: EndpointRecoveredInfo = { endpoint, score, at };
      this.onEndpointRecovered?.(info);
      return { kind: "recovered", ...info };
    }
    return undefined;
  }

  /**
   * Record one delivery outcome for `endpoint` (leader-only, like the
   * circuit-breaker verdict): `ok` updates the success-rate EWMA and
   * `latencyMs` (when a finite non-negative number) appends a
   * delivered-latency sample to the p95 window. Re-evaluates the score
   * and returns the threshold crossing (if any). Never throws.
   */
  recordOutcome(
    endpoint: string,
    ok: boolean,
    latencyMs?: number
  ): EndpointHealthTransition | undefined {
    const ep = String(endpoint);
    const s = this.stateFor(ep);
    const sample = ok ? 1 : 0;
    s.ewma = this.ewmaAlpha * sample + (1 - this.ewmaAlpha) * s.ewma;
    if (typeof latencyMs === "number" && Number.isFinite(latencyMs) && latencyMs >= 0) {
      s.samples.push(latencyMs);
      if (s.samples.length > this.maxLatencySamples) s.samples.shift();
    }
    return this.evaluate(ep, s);
  }

  /** Current 0–100 score for `endpoint`; 100 when never observed. */
  score(endpoint: string): number {
    const s = this.endpoints.get(String(endpoint));
    if (!s) return PRISTINE_SCORE;
    return this.scoreOf(String(endpoint), s);
  }

  /** Whether `endpoint` is currently degraded. */
  isDegraded(endpoint: string): boolean {
    return this.endpoints.get(String(endpoint))?.degraded ?? false;
  }

  /** Endpoints with at least one recorded outcome. */
  trackedEndpoints(): number {
    return this.endpoints.size;
  }

  /**
   * One row per endpoint with at least one recorded outcome (operator
   * view; see `RetryQueue.getEndpointHealthStats`). The circuit state
   * is read live per endpoint so the row always reflects the penalty
   * term behind the score.
   */
  snapshot(): EndpointHealthStatsRow[] {
    const out: EndpointHealthStatsRow[] = [];
    for (const [endpoint, s] of this.endpoints) {
      const row: EndpointHealthStatsRow = {
        endpoint,
        score: this.scoreOf(endpoint, s),
        degraded: s.degraded,
        consecutiveLowScores: s.consecutiveLowScores,
        circuitState: this.circuitState(endpoint),
      };
      row.successEwma = Math.round(s.ewma * 10000) / 10000;
      if (s.samples.length > 0) {
        const sorted = [...s.samples].sort((a, b) => a - b);
        row.p95Ms = percentile(sorted, 95);
      }
      out.push(row);
    }
    return out;
  }
}
