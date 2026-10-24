/**
 * Endpoint canary rollout (WR-214).
 *
 * A staged, self-rollbacking promotion of one candidate target for a
 * logical endpoint (the configured primary `targetUrl`). Traffic ramps
 * to the candidate in percentage steps — each step holds for `dwellMs`
 * — and the candidate is promoted to the permanent target only after
 * the final 100% step's dwell elapses (a ramp capped below 100% holds
 * its split instead of promoting). While a step runs, the candidate's
 * own outcomes spend a per-step error budget: too many consecutive
 * failures, or a failure rate above `maxStepFailureRate` once
 * `minStepSamples` outcomes exist, rolls the endpoint back to the
 * primary immediately. A rollback is terminal until the operator
 * reconfigures — a sick candidate is never silently retried.
 *
 * Orthogonality (the backlog's explicit non-goals):
 * - WR-39 failover is reactive (a sick active target is abandoned for a
 *   standby); this is proactive (a healthy primary is deliberately
 *   drained toward a candidate). Its probationary failback canary is a
 *   single-probe trust check, not a stepped ramp with a budget.
 * - WR-66 weighted dispatch is static traffic sharing; a rollout ends
 *   in promotion or rollback, never in a steady split.
 * - WR-147 error-budget burn-rate alerting only *notifies* — it never
 *   blocks, delays, or reroutes a delivery. The per-step budget here
 *   *acts*: breaching it moves traffic back to the primary.
 *
 * The manager is pure routing state — it never sends anything itself.
 * The retry queue asks `resolveTarget()` on every dispatch and reports
 * outcomes via `recordOutcome()`; the queue's own dispatch pinning
 * means an in-flight delivery keeps the target it was dispatched with
 * across a mid-flight promotion or rollback, exactly like WR-39.
 */

/** Default ramp: 1% -> 5% -> 25% -> 50% -> 100%. */
export const DEFAULT_CANARY_STEPS = [1, 5, 25, 50, 100];
/** Default dwell per step: 60 seconds of real traffic before advancing. */
export const DEFAULT_CANARY_DWELL_MS = 60_000;
/** Default consecutive candidate failures that burn the step budget. */
export const DEFAULT_CANARY_MAX_CONSECUTIVE_FAILURES = 5;
/** Default step failure rate that burns the budget (10% of attempts). */
export const DEFAULT_CANARY_MAX_STEP_FAILURE_RATE = 0.1;
/** Default outcomes before the failure-rate trigger can fire. */
export const DEFAULT_CANARY_MIN_STEP_SAMPLES = 10;

/** Canary rollout tuning for one logical endpoint (keyed by primary `targetUrl`). */
export interface CanaryRolloutEndpointConfig {
  /**
   * The candidate `targetUrl` traffic ramps toward. Required. Must not
   * equal the primary and must not itself be a configured primary
   * (chained rollouts are rejected at startup, like WR-39).
   */
  candidate: string;
  /**
   * Ramp percentages, strictly increasing, each in (0, 100].
   * Default: [1, 5, 25, 50, 100]. The rollout promotes only after the
   * final step's dwell elapses — a config whose last step is below
   * 100% never promotes, it just holds that split until rollback or
   * reconfiguration.
   */
  steps?: number[];
  /** Dwell per step in ms. Default: 60_000. Must be > 0. */
  dwellMs?: number;
  /**
   * Consecutive candidate failures that roll back immediately.
   * Default: 5. Must be an integer >= 1.
   */
  maxConsecutiveStepFailures?: number;
  /**
   * Step failure rate that rolls back once `minStepSamples` candidate
   * outcomes exist. Default: 0.1. Must be in (0, 1].
   */
  maxStepFailureRate?: number;
  /** Outcomes before the failure-rate trigger can fire. Default: 10. Must be an integer >= 1. */
  minStepSamples?: number;
}

/** Canary rollout configuration: primary `targetUrl` -> its rollout config. */
export type CanaryRolloutConfig = Record<string, CanaryRolloutEndpointConfig>;

/** Why a rollout rolled back. */
export type CanaryRollbackReason = "consecutive_failures" | "failure_rate";

/** Canary rollout lifecycle states. */
export type CanaryRolloutState = "rolling" | "promoted" | "rolled_back";

/** Audited on every rollout transition (the server writes these events). */
export interface CanaryRolloutEvent {
  event: "canary_step_advanced" | "canary_rolled_back" | "canary_promoted";
  /** Logical endpoint: the configured primary `targetUrl`. */
  endpoint: string;
  /** The candidate target being ramped toward. */
  candidate: string;
  /** 0-based step index the rollout is now on (steps.length on promotion). */
  step: number;
  /** Percentage of traffic the current step sends to the candidate (100 on promotion). */
  percent: number;
  /** Set only on `canary_rolled_back`. */
  reason?: CanaryRollbackReason;
  /** Candidate outcomes observed in the step that rolled back. */
  stepSamples?: number;
  /** Candidate failures observed in the step that rolled back. */
  stepFailures?: number;
  /** ISO-8601 timestamp of the transition. */
  at: string;
}

/** Observable snapshot of one endpoint's rollout state. */
export interface CanaryRolloutEndpointStats {
  /** Logical endpoint (the configured primary `targetUrl`). */
  endpoint: string;
  /** The candidate target being ramped toward. */
  candidate: string;
  state: CanaryRolloutState;
  /** 0-based step index (steps.length once promoted). */
  step: number;
  /** Current step's percentage (100 once promoted, 0 once rolled back). */
  percent: number;
  /** Candidate outcomes observed in the current step. */
  stepSamples: number;
  /** Candidate failures observed in the current step. */
  stepFailures: number;
  /** Total dispatches ever sent to the candidate. */
  candidateDispatched: number;
}

export interface CanaryRolloutManagerOptions {
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
  /**
   * Random source in [0, 1) for the per-dispatch sampling coin flip.
   * Defaults to `Math.random`. Injectable so tests drive the ramp
   * deterministically (WR-02 jitter convention).
   */
  random?: () => number;
  /** Called on every rollout transition (step advance, rollback, promotion). */
  onEvent?: (event: CanaryRolloutEvent) => void;
}

interface EndpointRolloutState {
  candidate: string;
  steps: number[];
  dwellMs: number;
  maxConsecutiveStepFailures: number;
  maxStepFailureRate: number;
  minStepSamples: number;
  state: CanaryRolloutState;
  stepIndex: number;
  stepStartedAtMs: number;
  stepSamples: number;
  stepFailures: number;
  consecutiveFailures: number;
  candidateDispatched: number;
}

/**
 * Validate a canary rollout config. Throws `RangeError` on anything
 * illegal — at construction, never mid-delivery.
 */
export function assertValidCanaryRolloutConfig(config: CanaryRolloutConfig): void {
  if (config === null || typeof config !== "object" || Array.isArray(config)) {
    throw new RangeError(
      `canaryRollouts must be a record of primary targetUrl -> rollout config, got ${JSON.stringify(config)}`
    );
  }
  const primaries = new Set(Object.keys(config));
  for (const [endpoint, cfg] of Object.entries(config)) {
    const where = `canaryRollouts[${JSON.stringify(endpoint)}]`;
    if (endpoint.length === 0) {
      throw new RangeError("canaryRollouts endpoint (primary targetUrl) must be a non-empty string");
    }
    if (cfg === null || typeof cfg !== "object" || Array.isArray(cfg)) {
      throw new RangeError(`${where} must be an object, got ${JSON.stringify(cfg)}`);
    }
    const { candidate, steps, dwellMs, maxConsecutiveStepFailures, maxStepFailureRate, minStepSamples } = cfg;
    if (typeof candidate !== "string" || candidate.length === 0) {
      throw new RangeError(`${where}.candidate must be a non-empty targetUrl`);
    }
    if (candidate === endpoint) {
      throw new RangeError(`${where}: the candidate must not equal the primary targetUrl`);
    }
    if (primaries.has(candidate)) {
      throw new RangeError(
        `${where}: candidate ${JSON.stringify(candidate)} is itself a configured primary — chained rollouts are not supported`
      );
    }
    const resolvedSteps = steps ?? DEFAULT_CANARY_STEPS;
    if (!Array.isArray(resolvedSteps) || resolvedSteps.length === 0) {
      throw new RangeError(`${where}.steps must be a non-empty array of percentages`);
    }
    let prev = 0;
    for (const p of resolvedSteps) {
      if (typeof p !== "number" || !Number.isFinite(p) || p <= 0 || p > 100 || p <= prev) {
        throw new RangeError(
          `${where}.steps must be strictly increasing percentages in (0, 100], got ${JSON.stringify(resolvedSteps)}`
        );
      }
      prev = p;
    }
    if (dwellMs !== undefined && (!Number.isFinite(dwellMs) || dwellMs <= 0)) {
      throw new RangeError(`${where}.dwellMs must be > 0, got ${JSON.stringify(dwellMs)}`);
    }
    if (
      maxConsecutiveStepFailures !== undefined &&
      (!Number.isInteger(maxConsecutiveStepFailures) || maxConsecutiveStepFailures < 1)
    ) {
      throw new RangeError(
        `${where}.maxConsecutiveStepFailures must be an integer >= 1, got ${JSON.stringify(maxConsecutiveStepFailures)}`
      );
    }
    if (
      maxStepFailureRate !== undefined &&
      (typeof maxStepFailureRate !== "number" ||
        !Number.isFinite(maxStepFailureRate) ||
        maxStepFailureRate <= 0 ||
        maxStepFailureRate > 1)
    ) {
      throw new RangeError(
        `${where}.maxStepFailureRate must be in (0, 1], got ${JSON.stringify(maxStepFailureRate)}`
      );
    }
    if (minStepSamples !== undefined && (!Number.isInteger(minStepSamples) || minStepSamples < 1)) {
      throw new RangeError(
        `${where}.minStepSamples must be an integer >= 1, got ${JSON.stringify(minStepSamples)}`
      );
    }
  }
}

/**
 * Staged candidate promotion for logical endpoints. Pure routing state
 * — it never sends anything itself; the retry queue asks
 * `resolveTarget()` on every dispatch and reports outcomes via
 * `recordOutcome()`.
 */
export class CanaryRolloutManager {
  private readonly states = new Map<string, EndpointRolloutState>();
  private readonly now: () => number;
  private readonly random: () => number;
  private readonly onEvent?: (event: CanaryRolloutEvent) => void;

  constructor(config: CanaryRolloutConfig, opts: CanaryRolloutManagerOptions = {}) {
    assertValidCanaryRolloutConfig(config);
    this.now = opts.now ?? Date.now;
    this.random = opts.random ?? Math.random;
    this.onEvent = opts.onEvent;
    for (const [endpoint, cfg] of Object.entries(config)) {
      this.states.set(endpoint, {
        candidate: cfg.candidate,
        steps: [...(cfg.steps ?? DEFAULT_CANARY_STEPS)],
        dwellMs: cfg.dwellMs ?? DEFAULT_CANARY_DWELL_MS,
        maxConsecutiveStepFailures:
          cfg.maxConsecutiveStepFailures ?? DEFAULT_CANARY_MAX_CONSECUTIVE_FAILURES,
        maxStepFailureRate: cfg.maxStepFailureRate ?? DEFAULT_CANARY_MAX_STEP_FAILURE_RATE,
        minStepSamples: cfg.minStepSamples ?? DEFAULT_CANARY_MIN_STEP_SAMPLES,
        state: "rolling",
        stepIndex: 0,
        stepStartedAtMs: this.now(),
        stepSamples: 0,
        stepFailures: 0,
        consecutiveFailures: 0,
        candidateDispatched: 0,
      });
    }
  }

  /**
   * The physical target the next dispatch for `endpoint` should go to,
   * or `undefined` when the endpoint has no rollout config (zero
   * behavior change when canary rollout is not configured for it).
   * A promoted endpoint permanently resolves to its candidate; a
   * rolled-back endpoint permanently resolves to its primary.
   */
  resolveTarget(endpoint: string): string | undefined {
    const st = this.states.get(endpoint);
    if (!st) return undefined;
    if (st.state === "promoted") return st.candidate;
    if (st.state === "rolled_back") return endpoint;
    this.maybeAdvance(st, endpoint);
    if (st.state === "promoted") return st.candidate;
    if (st.state === "rolled_back") return endpoint;
    const percent = st.steps[st.stepIndex];
    const toCandidate = this.random() * 100 < percent;
    if (toCandidate) st.candidateDispatched += 1;
    return toCandidate ? st.candidate : endpoint;
  }

  /**
   * Report one delivery outcome for a physical target. Only candidate
   * outcomes spend the step budget — primary outcomes are the safe
   * baseline, and primary health is the breaker/failover's job, not
   * the rollout's. Outcomes for unknown endpoints, non-rolling
   * rollouts, and non-candidate targets are no-ops.
   */
  recordOutcome(endpoint: string, target: string, ok: boolean): void {
    const st = this.states.get(endpoint);
    if (!st || st.state !== "rolling" || target !== st.candidate) return;
    st.stepSamples += 1;
    if (ok) {
      st.consecutiveFailures = 0;
      return;
    }
    st.stepFailures += 1;
    st.consecutiveFailures += 1;
    let reason: CanaryRollbackReason | undefined;
    if (st.consecutiveFailures >= st.maxConsecutiveStepFailures) {
      reason = "consecutive_failures";
    } else if (
      st.stepSamples >= st.minStepSamples &&
      st.stepFailures / st.stepSamples > st.maxStepFailureRate
    ) {
      reason = "failure_rate";
    }
    if (reason === undefined) return;
    st.state = "rolled_back";
    this.emit(st, endpoint, {
      event: "canary_rolled_back",
      step: st.stepIndex,
      percent: 0,
      reason,
      stepSamples: st.stepSamples,
      stepFailures: st.stepFailures,
    });
  }

  /** Observable snapshot of every configured endpoint's rollout state. */
  stats(): CanaryRolloutEndpointStats[] {
    const rows: CanaryRolloutEndpointStats[] = [];
    for (const [endpoint, st] of this.states) {
      rows.push({
        endpoint,
        candidate: st.candidate,
        state: st.state,
        step: st.state === "promoted" ? st.steps.length : st.stepIndex,
        percent: st.state === "promoted" ? 100 : st.state === "rolled_back" ? 0 : st.steps[st.stepIndex],
        stepSamples: st.stepSamples,
        stepFailures: st.stepFailures,
        candidateDispatched: st.candidateDispatched,
      });
    }
    return rows;
  }

  /**
   * Advance the step clock: when the current step's dwell has elapsed,
   * move to the next step (fresh budget counters) or promote when the
   * final 100% step's dwell elapses. A rollout whose last step is below
   * 100% holds that split forever — it never silently promotes past
   * the configured ceiling. Advancement is lazy — it happens on the
   * next dispatch, so a rollout with no traffic simply waits.
   */
  private maybeAdvance(st: EndpointRolloutState, endpoint: string): void {
    while (st.state === "rolling" && this.now() - st.stepStartedAtMs >= st.dwellMs) {
      if (st.stepIndex >= st.steps.length - 1) {
        if (st.steps[st.stepIndex] !== 100) return;
        st.state = "promoted";
        this.emit(st, endpoint, {
          event: "canary_promoted",
          step: st.steps.length,
          percent: 100,
        });
        return;
      }
      st.stepIndex += 1;
      st.stepStartedAtMs = this.now();
      st.stepSamples = 0;
      st.stepFailures = 0;
      st.consecutiveFailures = 0;
      this.emit(st, endpoint, {
        event: "canary_step_advanced",
        step: st.stepIndex,
        percent: st.steps[st.stepIndex],
      });
    }
  }

  private emit(
    st: EndpointRolloutState,
    endpoint: string,
    partial: Omit<CanaryRolloutEvent, "endpoint" | "candidate" | "at">
  ): void {
    this.onEvent?.({
      ...partial,
      endpoint,
      candidate: st.candidate,
      at: new Date(this.now()).toISOString(),
    });
  }
}
