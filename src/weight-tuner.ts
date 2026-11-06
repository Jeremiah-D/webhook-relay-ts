import { WeightedDispatcher, type WeightedTargetConfig } from "./weighted.ts";

/**
 * WR-201: adaptive weight tuning on top of WR-66 weighted dispatch.
 *
 * Static weights answer "what share does each target deserve in the
 * steady state"; the tuner answers "how should the shares move while
 * targets drift". It is a closed-loop controller that periodically
 * nudges each weighted endpoint's per-target weights toward their
 * WR-179 health scores:
 *
 * - **Signal**: a `healthOf(endpoint, target)` provider returning a
 *   0-100 score. The queue wires WR-179's per-target scores (recorded
 *   per physical target, leader-only, like the breaker verdicts), but
 *   any scorer works — the tuner never touches the health machinery.
 * - **Smoothing**: per-target scores pass through an EWMA so one
 *   unlucky delivery cannot swing the traffic share.
 * - **Hysteresis**: a retune applies only when at least one target's
 *   smoothed score has drifted at least `hysteresisPoints` from the
 *   score its current weights were tuned against — small wiggles move
 *   nothing, so weights cannot flap.
 * - **Bounded steps**: a single round moves a target at most
 *   `maxStepRatio` of its current weight, so a bad signal (a stale or
 *   skewed scorer) degrades traffic gradually, not in one jump.
 * - **Manual precedence**: any weight change made outside the tuner
 *   (the WR-32 `updateEndpointConfig` `weighted` patch, or a direct
 *   `dispatcher.setWeights`) wins outright — the tuner re-baselines
 *   to it and never fights it. The wiring also calls
 *   `noteManualWeights` explicitly after hot-reload patches.
 *
 * The target law is deliberately simple and relative: each target's
 * new weight is derived from its *manual baseline* weight, scaled by
 * its smoothed health — a target at full health keeps exactly its
 * configured share, so equal health means zero drift and the tuner is
 * a no-op in the steady state. A target scoring 0 keeps a small
 * `minWeightFloor` share (it stays in the rotation for health
 * exclusion to observe, exactly like WR-66's recovery canary), never
 * a zero weight (WR-66 forbids non-positive weights).
 *
 * The tuner is pure routing policy: it never sends anything, only
 * calls `dispatcher.setWeights`. Every applied retune fires
 * `onWeightsRetuned` with before/after weights, which the server
 * audits as `weight_retuned`. Opt-in: the queue only builds the
 * tuner when `weightTuning` is configured.
 *
 * Zero dependencies. The clock is injectable for deterministic tests.
 */

/** Default EWMA smoothing factor for per-target health scores. */
export const DEFAULT_WEIGHT_TUNE_EWMA_ALPHA = 0.3;
/** Default single-round relative change bound (25% of current weight). */
export const DEFAULT_WEIGHT_TUNE_MAX_STEP_RATIO = 0.25;
/** Default hysteresis: smoothed score must drift this many points to retune. */
export const DEFAULT_WEIGHT_TUNE_HYSTERESIS_POINTS = 5;
/** Default minimum share a zero-health target keeps, relative to baseline. */
export const DEFAULT_WEIGHT_TUNE_MIN_FLOOR = 0.05;
/** Default retune interval when the sweeper arms the schedule. */
export const DEFAULT_WEIGHT_TUNE_INTERVAL_MS = 60_000;
/**
 * Default skip threshold: when every target's new weight is within this
 * relative distance of its current weight, the round is a no-op.
 */
export const DEFAULT_WEIGHT_TUNE_EPSILON = 0.02;

/** One retune round's audit record. */
export interface WeightsRetunedInfo {
  /** Logical endpoint whose weights moved. */
  endpoint: string;
  /** ms epoch of the retune. */
  at: number;
  /** Weights before the round, in config order. */
  before: WeightedTargetConfig[];
  /** Weights after the round, in config order. */
  after: WeightedTargetConfig[];
  /** Per-target WR-179 score sampled this round. */
  scores: Record<string, number>;
  /** Per-target EWMA-smoothed scores the round was computed from. */
  smoothed: Record<string, number>;
}

/** Options for {@link WeightTuner}. */
export interface WeightTunerOptions {
  /** The WR-66 dispatcher whose weights are tuned. Required. */
  dispatcher: WeightedDispatcher;
  /**
   * 0-100 health score per (endpoint, target). The queue wires WR-179's
   * per-target scores; unknown targets should read 100 (healthy until
   * proven otherwise, the WR-179 cold-start posture).
   */
  healthOf: (endpoint: string, target: string) => number;
  /** Clock in ms; defaults to `Date.now`. Injectable for tests. */
  now?: () => number;
  /**
   * EWMA smoothing factor for the per-target scores, in (0, 1].
   * Default: 0.3.
   */
  ewmaAlpha?: number;
  /**
   * Maximum relative change of one target's weight per round, in
   * (0, 1]. Default: 0.25 — a single round moves a target at most 25%
   * of its current weight.
   */
  maxStepRatio?: number;
  /**
   * Smoothed-score drift, in points, that must be reached before a
   * round applies — the anti-flap hysteresis. Default: 5. Must be >= 0.
   */
  hysteresisPoints?: number;
  /**
   * Minimum share a zero-health target keeps, as a fraction of its
   * baseline weight, in [0, 1). Default: 0.05.
   */
  minWeightFloor?: number;
  /**
   * Relative no-op threshold in [0, 1): when every target's computed
   * weight is within this of its current weight the round applies
   * nothing. Default: 0.02.
   */
  retuneEpsilon?: number;
  /** Called on every applied retune (audited as `weight_retuned`). */
  onWeightsRetuned?: (info: WeightsRetunedInfo) => void;
}

/** Options for {@link WeightTuneSweeper}. */
export interface WeightTuneSweeperOptions {
  /** The tuner the sweeper drives. Required. */
  tuner: WeightTuner;
  /**
   * Interval between retune rounds in ms. Default:
   * 60_000. Must be finite and > 0.
   */
  retuneIntervalMs?: number;
  /**
   * Scheduler factory; defaults to an unref'd real setTimeout (an armed
   * sweep must never pin the process open). Injectable for tests.
   */
  setTimer?: (fn: () => void, ms: number) => { clear(): void };
  clearTimer?: (handle: { clear(): void }) => void;
}

/**
 * Queue-level weight-tuning configuration: the tuner knobs plus the
 * sweeper schedule, consumed by `RetryQueue`'s `weightTuning` option.
 */
export interface WeightTuningOptions {
  /** Retune interval in ms (default 60_000); finite and > 0. */
  retuneIntervalMs?: number;
  /** EWMA smoothing factor in (0, 1] (default 0.3). */
  ewmaAlpha?: number;
  /** Single-round relative change bound in (0, 1] (default 0.25). */
  maxStepRatio?: number;
  /** Hysteresis in score points, >= 0 (default 5). */
  hysteresisPoints?: number;
  /** Zero-health floor as baseline fraction in [0, 1) (default 0.05). */
  minWeightFloor?: number;
  /** Relative no-op threshold in [0, 1) (default 0.02). */
  retuneEpsilon?: number;
  /** Clock in ms; defaults to `Date.now`. */
  now?: () => number;
  /** Scheduler factory; defaults to an unref'd real setTimeout. */
  setTimer?: (fn: () => void, ms: number) => { clear(): void };
  clearTimer?: (handle: { clear(): void }) => void;
  /** Called on every applied retune (the server audits `weight_retuned`). */
  onWeightsRetuned?: (info: WeightsRetunedInfo) => void;
}

/**
 * WR-340: live weight-tuner config — the five controller inputs, after
 * any revision. The sweeper interval lives on the queue-level
 * {@link WeightTuningConfig} instead.
 */
export interface WeightTunerConfig {
  /** EWMA smoothing factor in (0, 1]. */
  ewmaAlpha: number;
  /** Single-round relative change bound in (0, 1]. */
  maxStepRatio: number;
  /** Hysteresis in score points, >= 0. */
  hysteresisPoints: number;
  /** Zero-health floor as baseline fraction in [0, 1). */
  minWeightFloor: number;
  /** Relative no-op threshold in [0, 1). */
  retuneEpsilon: number;
}

/**
 * WR-340: a partial revision of the tuner config (all five inputs, at
 * least one field set). Omitted fields keep their live values; an empty
 * patch is a `RangeError`.
 */
export type WeightTunerRevision = Partial<WeightTunerConfig>;

/**
 * WR-340: live queue-level weight-tuning config — the five tuner inputs
 * plus the sweeper interval, after any revision.
 */
export interface WeightTuningConfig extends WeightTunerConfig {
  /** Interval between retune rounds in ms; finite and > 0. */
  retuneIntervalMs: number;
}

/**
 * WR-340: a partial revision of the queue-level weight-tuning config
 * (all six inputs, at least one field set). Omitted fields keep their
 * live values; an empty patch is a `RangeError`.
 */
export type WeightTuningRevision = Partial<WeightTuningConfig>;

interface EndpointTuneState {
  /** Operator-configured weights: the reference every round derives from. */
  baseline: Map<string, number>;
  /** Weights the tuner last applied (or observed, after a manual change). */
  lastApplied: Map<string, number>;
  /** EWMA-smoothed per-target scores. */
  smoothed: Map<string, number>;
  /** Smoothed scores the current weights were tuned against. */
  scoreAtApply: Map<string, number>;
}

function checkAlpha(where: string, v: number | undefined, dflt: number): number {
  if (v === undefined) return dflt;
  if (typeof v !== "number" || !Number.isFinite(v) || v <= 0 || v > 1) {
    throw new RangeError(`weightTuning: ${where} must be a finite number in (0, 1], got ${String(v)}`);
  }
  return v;
}

function checkUnitInterval(where: string, v: number | undefined, dflt: number, inclusiveZero: boolean): number {
  if (v === undefined) return dflt;
  const ok = typeof v === "number" && Number.isFinite(v) && (inclusiveZero ? v >= 0 : v > 0) && v < 1;
  if (!ok) {
    throw new RangeError(
      `weightTuning: ${where} must be a finite number in ${inclusiveZero ? "[0" : "(0"}, 1), got ${String(v)}`
    );
  }
  return v;
}

function checkHysteresis(v: number | undefined): number {
  if (v === undefined) return DEFAULT_WEIGHT_TUNE_HYSTERESIS_POINTS;
  if (typeof v !== "number" || !Number.isFinite(v) || v < 0) {
    throw new RangeError(`weightTuning: hysteresisPoints must be a finite number >= 0, got ${String(v)}`);
  }
  return v;
}

function clampScore(v: number): number {
  if (!Number.isFinite(v)) return 100;
  if (v < 0) return 0;
  if (v > 100) return 100;
  return v;
}

function sameTargets(a: Map<string, number>, b: Map<string, number>, epsilon: number): boolean {
  if (a.size !== b.size) return false;
  for (const [k, v] of a) {
    const w = b.get(k);
    if (w === undefined) return false;
    if (Math.abs(v - w) / w > epsilon) return false;
  }
  return true;
}

/**
 * Adaptive weight tuner: closed-loop retuning of WR-66 weighted
 * dispatch weights against WR-179-style per-target health scores.
 * See the module docstring for the control law.
 */
export class WeightTuner {
  private readonly dispatcher: WeightedDispatcher;
  private readonly healthOf: (endpoint: string, target: string) => number;
  private readonly now: () => number;
  // WR-340: live-revisable via `retune(patch)` (the constructor still
  // validates every value through the same gates), so these are
  // deliberately not `readonly`. The per-endpoint `states` stay
  // untouched by a revision — smoothed scores, baselines, and score
  // references are never reset or recomputed.
  private ewmaAlpha: number;
  private maxStepRatio: number;
  private hysteresisPoints: number;
  private minWeightFloor: number;
  private retuneEpsilon: number;
  private readonly onWeightsRetuned?: (info: WeightsRetunedInfo) => void;
  private readonly states = new Map<string, EndpointTuneState>();

  constructor(opts: WeightTunerOptions) {
    if (opts === null || typeof opts !== "object") {
      throw new RangeError(`weightTuning: options must be an object, got ${String(opts)}`);
    }
    if (!(opts.dispatcher instanceof WeightedDispatcher)) {
      throw new RangeError("weightTuning: dispatcher must be a WeightedDispatcher");
    }
    if (typeof opts.healthOf !== "function") {
      throw new RangeError("weightTuning: healthOf must be a function");
    }
    this.dispatcher = opts.dispatcher;
    this.healthOf = opts.healthOf;
    this.now = opts.now ?? Date.now;
    this.ewmaAlpha = checkAlpha("ewmaAlpha", opts.ewmaAlpha, DEFAULT_WEIGHT_TUNE_EWMA_ALPHA);
    this.maxStepRatio = checkAlpha("maxStepRatio", opts.maxStepRatio, DEFAULT_WEIGHT_TUNE_MAX_STEP_RATIO);
    this.hysteresisPoints = checkHysteresis(opts.hysteresisPoints);
    this.minWeightFloor = checkUnitInterval(
      "minWeightFloor",
      opts.minWeightFloor,
      DEFAULT_WEIGHT_TUNE_MIN_FLOOR,
      true
    );
    this.retuneEpsilon = checkUnitInterval(
      "retuneEpsilon",
      opts.retuneEpsilon,
      DEFAULT_WEIGHT_TUNE_EPSILON,
      true
    );
    this.onWeightsRetuned = opts.onWeightsRetuned;
  }

  /**
   * WR-340: revise the live tuner parameters (partial — omitted fields
   * keep their live values). Merge-then-validate reusing the
   * construction gates: an illegal patch throws `RangeError` and the
   * live values are left completely untouched, and an empty patch is a
   * `RangeError`. A patch equal to the live values is a silent no-op.
   * A real revision only affects the next retune round — the EWMA
   * smoothing, hysteresis gate, target law, and step clamp all read
   * the live values, while the smoothed scores, baselines, and score
   * references are untouched (no recompute, no re-baseline). Returns
   * the live config after the revision.
   */
  retune(patch: WeightTunerRevision): WeightTunerConfig;
  /**
   * Run one tuning round for `endpoint`. Returns the audit record when
   * weights were applied, `undefined` when the round was a no-op (not
   * weighted, single target, manual change re-baselined, hysteresis
   * not reached, or changes below the no-op threshold). Manual weight
   * changes always win: they re-baseline the tuner and skip the round.
   */
  retune(endpoint: string): WeightsRetunedInfo | undefined;
  retune(arg: WeightTunerRevision | string): WeightTunerConfig | WeightsRetunedInfo | undefined {
    if (typeof arg !== "string") {
      const patch = arg;
      if (patch === null || typeof patch !== "object" || Array.isArray(patch)) {
        throw new RangeError(
          `weightTuning revision must be an object, got ${JSON.stringify(patch)}`
        );
      }
      if (
        patch.ewmaAlpha === undefined &&
        patch.maxStepRatio === undefined &&
        patch.hysteresisPoints === undefined &&
        patch.minWeightFloor === undefined &&
        patch.retuneEpsilon === undefined
      ) {
        throw new RangeError(
          "weightTuning revision must set at least one of ewmaAlpha, maxStepRatio, hysteresisPoints, minWeightFloor, retuneEpsilon"
        );
      }
      // Merge-then-validate: the merged values must pass the
      // construction gates before any live value moves.
      const next: WeightTunerConfig = {
        ewmaAlpha: checkAlpha("ewmaAlpha", patch.ewmaAlpha ?? this.ewmaAlpha, DEFAULT_WEIGHT_TUNE_EWMA_ALPHA),
        maxStepRatio: checkAlpha(
          "maxStepRatio",
          patch.maxStepRatio ?? this.maxStepRatio,
          DEFAULT_WEIGHT_TUNE_MAX_STEP_RATIO
        ),
        hysteresisPoints: checkHysteresis(patch.hysteresisPoints ?? this.hysteresisPoints),
        minWeightFloor: checkUnitInterval(
          "minWeightFloor",
          patch.minWeightFloor ?? this.minWeightFloor,
          DEFAULT_WEIGHT_TUNE_MIN_FLOOR,
          true
        ),
        retuneEpsilon: checkUnitInterval(
          "retuneEpsilon",
          patch.retuneEpsilon ?? this.retuneEpsilon,
          DEFAULT_WEIGHT_TUNE_EPSILON,
          true
        ),
      };
      if (
        next.ewmaAlpha === this.ewmaAlpha &&
        next.maxStepRatio === this.maxStepRatio &&
        next.hysteresisPoints === this.hysteresisPoints &&
        next.minWeightFloor === this.minWeightFloor &&
        next.retuneEpsilon === this.retuneEpsilon
      ) {
        return this.snapshot();
      }
      this.ewmaAlpha = next.ewmaAlpha;
      this.maxStepRatio = next.maxStepRatio;
      this.hysteresisPoints = next.hysteresisPoints;
      this.minWeightFloor = next.minWeightFloor;
      this.retuneEpsilon = next.retuneEpsilon;
      return this.snapshot();
    }
    const endpoint = arg;
    const row = this.dispatcher.stats().find((s) => s.endpoint === endpoint);
    if (row === undefined) return undefined;
    // A single target has no shares to tune — the ratio is degenerate.
    if (row.targets.length < 2) return undefined;
    const current = new Map(row.targets.map((t) => [t.targetUrl, t.weight] as const));
    const scores = new Map<string, number>();
    for (const t of row.targets) scores.set(t.targetUrl, clampScore(this.healthOf(endpoint, t.targetUrl)));

    let st = this.states.get(endpoint);
    if (st === undefined || !sameTargets(st.lastApplied, current, this.retuneEpsilon)) {
      // First sight, or an out-of-band weight change (WR-32 hot reload,
      // direct setWeights): the operator's weights are the truth. Re-
      // baseline and seed the score references — the round is skipped so
      // the tuner can never fight a manual edit.
      st = {
        baseline: new Map(current),
        lastApplied: new Map(current),
        smoothed: new Map(scores),
        scoreAtApply: new Map(scores),
      };
      this.states.set(endpoint, st);
      return undefined;
    }

    // EWMA the scores; the round is computed from the smoothed series.
    for (const [target, score] of scores) {
      const prev = st.smoothed.get(target) ?? score;
      st.smoothed.set(target, this.ewmaAlpha * score + (1 - this.ewmaAlpha) * prev);
    }

    // Hysteresis: nothing moves until some target's smoothed score has
    // drifted at least hysteresisPoints from the score its weights were
    // tuned against — small wiggles cannot flap the traffic shares.
    let drift = 0;
    for (const [target, smoothed] of st.smoothed) {
      const ref = st.scoreAtApply.get(target) ?? smoothed;
      const d = Math.abs(smoothed - ref);
      if (d > drift) drift = d;
    }
    if (drift < this.hysteresisPoints) return undefined;

    // Desired weights derive from the manual baseline, scaled by
    // smoothed health: a fully healthy target keeps exactly its
    // configured share, so equal health means zero drift.
    const before = [...current.entries()].map(([targetUrl, weight]) => ({ targetUrl, weight }));
    const after: WeightedTargetConfig[] = [];
    for (const t of row.targets) {
      const baseline = st.baseline.get(t.targetUrl) ?? t.weight;
      const smoothed = st.smoothed.get(t.targetUrl) ?? 100;
      const healthRatio = this.minWeightFloor + (1 - this.minWeightFloor) * (smoothed / 100);
      const desired = baseline * healthRatio;
      // Bound the single-round step so a bad signal degrades traffic
      // gradually, never in one jump.
      const ratio = desired / t.weight;
      const clamped = Math.min(1 + this.maxStepRatio, Math.max(1 - this.maxStepRatio, ratio));
      after.push({ targetUrl: t.targetUrl, weight: t.weight * clamped });
    }

    // No-op threshold: changes at or below epsilon move nothing — a
    // zero-change round never re-applies or re-audits identical weights.
    let moved = false;
    for (const t of after) {
      const cur = current.get(t.targetUrl) ?? t.weight;
      if (Math.abs(t.weight - cur) / cur > this.retuneEpsilon) {
        moved = true;
        break;
      }
    }
    if (!moved) return undefined;

    this.dispatcher.setWeights(endpoint, after);
    st.lastApplied = new Map(after.map((t) => [t.targetUrl, t.weight] as const));
    st.scoreAtApply = new Map(st.smoothed);
    const info: WeightsRetunedInfo = {
      endpoint,
      at: this.now(),
      before,
      after: after.map((t) => ({ targetUrl: t.targetUrl, weight: t.weight })),
      scores: Object.fromEntries(scores),
      smoothed: Object.fromEntries(st.smoothed),
    };
    try {
      this.onWeightsRetuned?.(info);
    } catch {
      // A throwing observer must never break the tuning round — the
      // weights are already applied; the audit hook is best-effort.
    }
    return info;
  }

  /** WR-340: live tuner config snapshot (the five controller inputs). */
  snapshot(): WeightTunerConfig {
    return {
      ewmaAlpha: this.ewmaAlpha,
      maxStepRatio: this.maxStepRatio,
      hysteresisPoints: this.hysteresisPoints,
      minWeightFloor: this.minWeightFloor,
      retuneEpsilon: this.retuneEpsilon,
    };
  }

  /** Run one tuning round for every weighted endpoint. */
  retuneAll(): WeightsRetunedInfo[] {
    const out: WeightsRetunedInfo[] = [];
    for (const row of this.dispatcher.stats()) {
      const info = this.retune(row.endpoint);
      if (info !== undefined) out.push(info);
    }
    return out;
  }

  /**
   * Record an operator-driven weight change: the manual weights become
   * the new baseline and the score references reseed, so the next
   * automatic round derives from the operator's truth. The queue calls
   * this after WR-32 `weighted` patches; direct dispatcher edits are
   * also detected (and re-baselined) on the next round.
   */
  noteManualWeights(endpoint: string, targets: WeightedTargetConfig[]): void {
    const current = new Map(targets.map((t) => [t.targetUrl, t.weight] as const));
    const scores = new Map<string, number>();
    for (const t of targets) scores.set(t.targetUrl, clampScore(this.healthOf(endpoint, t.targetUrl)));
    this.states.set(endpoint, {
      baseline: new Map(current),
      lastApplied: new Map(current),
      smoothed: new Map(scores),
      scoreAtApply: new Map(scores),
    });
  }

  /** Endpoints the tuner has seen (have tuning state). */
  tunedEndpoints(): string[] {
    return [...this.states.keys()];
  }
}

/**
 * Periodic retune sweeper (WR-201). Arms `tuner.retuneAll()` every
 * `retuneIntervalMs`, unref'd by default so the schedule never pins the
 * process open. `start()`/`stop()` mirror the other sweepers
 * (stale-pause, retention, prober); `sweepNow()` runs one round
 * immediately for tests and operator tooling.
 */
export class WeightTuneSweeper {
  private readonly tuner: WeightTuner;
  // WR-340: live-revisable via `setRetuneIntervalMs`, so deliberately
  // not `readonly`. `arm()` reads it on every arming, so a revision
  // re-arms the schedule on the new interval.
  private intervalMs: number;
  private readonly setTimer: (fn: () => void, ms: number) => { clear(): void };
  private readonly clearTimer: (handle: { clear(): void }) => void;
  private started = false;
  private timer?: { clear(): void };

  constructor(opts: WeightTuneSweeperOptions) {
    if (opts === null || typeof opts !== "object") {
      throw new RangeError(`weightTuning: options must be an object, got ${String(opts)}`);
    }
    if (!(opts.tuner instanceof WeightTuner)) {
      throw new RangeError("weightTuning: tuner must be a WeightTuner");
    }
    const ms = opts.retuneIntervalMs ?? DEFAULT_WEIGHT_TUNE_INTERVAL_MS;
    if (!Number.isFinite(ms) || ms <= 0) {
      throw new RangeError(`weightTuning: retuneIntervalMs must be a finite number > 0, got ${String(opts.retuneIntervalMs)}`);
    }
    this.tuner = opts.tuner;
    this.intervalMs = ms;
    this.setTimer =
      opts.setTimer ??
      ((fn, ms2) => {
        const t = setTimeout(fn, ms2);
        t.unref?.();
        return { clear: () => clearTimeout(t) };
      });
    this.clearTimer = opts.clearTimer ?? ((h) => h.clear());
  }

  /** Whether the sweep schedule is currently armed. */
  isRunning(): boolean {
    return this.started && this.timer !== undefined;
  }

  /** WR-340: live retune interval in ms. */
  retuneIntervalMs(): number {
    return this.intervalMs;
  }

  /**
   * WR-340: revise the retune interval at runtime. While the sweeper
   * is running the pending timer is cleared and re-armed on the new
   * interval, so the next round follows the new rhythm; a round
   * already fired is unaffected (its callback re-arms itself on the
   * new interval). While stopped only the value changes — the next
   * `start()` arms on it. An illegal value throws `RangeError` and
   * the live interval is untouched; revising to the live interval is
   * a silent no-op.
   */
  setRetuneIntervalMs(ms: number): void {
    if (!Number.isFinite(ms) || ms <= 0) {
      throw new RangeError(`weightTuning: retuneIntervalMs must be a finite number > 0, got ${String(ms)}`);
    }
    if (ms === this.intervalMs) return;
    this.intervalMs = ms;
    if (this.timer !== undefined) {
      this.clearTimer(this.timer);
      this.timer = undefined;
      this.arm();
    }
  }

  /** Arm the retune schedule. Idempotent. */
  start(): void {
    if (this.started) return;
    this.started = true;
    this.arm();
  }

  /** Disarm the retune schedule. Idempotent. */
  stop(): void {
    this.started = false;
    if (this.timer !== undefined) {
      this.clearTimer(this.timer);
      this.timer = undefined;
    }
  }

  /**
   * Run one retune round immediately, outside the schedule. Safe to
   * call directly — it does not disturb the armed schedule.
   */
  sweepNow(): WeightsRetunedInfo[] {
    return this.tuner.retuneAll();
  }

  private arm(): void {
    if (!this.started) return;
    this.timer = this.setTimer(() => {
      this.timer = undefined;
      try {
        this.tuner.retuneAll();
      } finally {
        this.arm();
      }
    }, this.intervalMs);
  }
}
