import type { CircuitState } from "./circuit.ts";

/**
 * Weighted multi-target outbound dispatch (WR-66).
 *
 * WR-39 failover (active/standby) answers "which target is *up*"; weighted
 * mode answers "how is traffic *shared*" across several healthy physical
 * targets under one logical endpoint. Opt-in per endpoint: while failover
 * keeps an ordered primary+standbys list and only moves on failure,
 * weighted mode spreads every dispatch across the configured targets with
 * a hand-written smooth weighted round-robin (nginx-style, zero
 * dependencies) — weights 5:3:2 over ten dispatches yield exactly 5/3/2,
 * and the sequence stays smooth (no target starves for a whole cycle).
 *
 * Health filtering: only healthy physical targets join the rotation. The
 * signals are the codebase's own, never a parallel health universe:
 * - the circuit breaker's state for the target (`open` = excluded;
 *   `half_open` = included, so the breaker's probe delivery can settle and
 *   the outcome re-admits or re-excludes). WR-34 probe outcomes already
 *   feed the breaker, so probes are covered through it.
 * - the dispatcher's own per-target consecutive-failure counter, so
 *   exclusion works with the breaker disabled too (mirrors
 *   `FailoverManager`). A downstream that *answers* — even with a 4xx —
 *   counts as a success: it is up, it just refused this payload.
 *
 * Recovery: a counter-excluded target rejoins once `recoveryIntervalMs`
 * has passed since its last failure (default 30s, mirroring the failover
 * failback quiet period) — its next outcome alone decides: success resets
 * the counter, failure re-excludes for another interval. This guarantees
 * liveness with the breaker disabled, where no half-open probe exists.
 *
 * All-unhealthy fallback: when every target is unhealthy the dispatcher
 * pins to the *first* configured target instead of dropping the delivery
 * (the failover equivalent of "钉死最后一个走正常重试/死信") — the
 * queue's normal retry / dead-letter machinery owns the outcome from
 * there.
 *
 * Weights are tunable at runtime through the WR-32 hot-reload path
 * (`RetryQueue.updateEndpointConfig` with a `weighted` patch): validated
 * before apply, zero partial application, one `endpoint_config_updated`
 * audit event. Changing the weights resets the smooth-WRR accumulators
 * (stale accumulators would bias the new distribution); health counters
 * and cumulative dispatch counts survive.
 *
 * Mutual exclusion with WR-39 failover is fail-fast at startup: an
 * endpoint may be weighted *or* have failover standbys, never both —
 * mixing "share traffic" with "ordered standby" routing is a
 * misconfiguration, not a feature.
 */

/** Default consecutive retryable failures before a target leaves the rotation. */
export const DEFAULT_WEIGHTED_FAILURE_THRESHOLD = 5;
/**
 * Default quiet period after a target's last failure before it rejoins
 * the rotation (the recovery canary). Mirrors the failover failback
 * default.
 */
export const DEFAULT_WEIGHTED_RECOVERY_INTERVAL_MS = 30_000;

/** One physical target and its share of the endpoint's dispatches. */
export interface WeightedTargetConfig {
  /** Physical `targetUrl` this target's dispatches go to. */
  targetUrl: string;
  /** Positive finite share weight — relative, not a percentage. */
  weight: number;
}

/** Weighted dispatch tuning for one logical endpoint (keyed by endpoint). */
export interface WeightedEndpointConfig {
  /** The physical targets sharing this endpoint's dispatches. Required, non-empty. */
  targets: WeightedTargetConfig[];
  /**
   * Consecutive retryable failures that exclude the target from the
   * rotation. Default: 5. Must be an integer >= 1.
   */
  failureThreshold?: number;
  /**
   * Quiet period in ms after a target's last failure before it becomes
   * eligible again (recovery canary). Default: 30_000. Must be > 0.
   */
  recoveryIntervalMs?: number;
}

/** Weighted dispatch configuration: logical endpoint -> its target config. */
export type WeightedConfig = Record<string, WeightedEndpointConfig>;

/** Observable snapshot of one physical target's weighted state. */
export interface WeightedTargetStats {
  /** Physical target URL. */
  targetUrl: string;
  /** Configured weight. */
  weight: number;
  /**
   * Effective weight used by the smooth-WRR pick. No dynamic degradation
   * is applied — health exclusion handles sick targets — so this equals
   * the configured weight.
   */
  effectiveWeight: number;
  /** Cumulative dispatches routed to this target since construction. */
  dispatched: number;
  /** Consecutive retryable failures since the last success (0 once healthy). */
  consecutiveFailures: number;
  /** Whether the target currently joins the rotation. */
  healthy: boolean;
}

/** Observable snapshot of one endpoint's weighted state. */
export interface WeightedEndpointStats {
  /** Logical endpoint. */
  endpoint: string;
  /** Targets in config order. */
  targets: WeightedTargetStats[];
}

export interface WeightedDispatcherOptions {
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
  /**
   * Current breaker state for a target. The queue wires its own breaker
   * here (OR-ed across tenants, like failover); without a breaker every
   * target reads `"closed"` and only the failure-count trigger applies.
   */
  circuitState?: (target: string) => CircuitState;
}

/**
 * Validate one endpoint's target list (shape + weights). Throws
 * `RangeError` on anything illegal — at construction / before apply,
 * never mid-delivery.
 */
export function assertValidWeightedTargets(targets: unknown): void {
  if (!Array.isArray(targets) || targets.length === 0) {
    throw new RangeError(
      `weighted targets must be a non-empty array, got ${JSON.stringify(targets)}`
    );
  }
  const seen = new Set<string>();
  let total = 0;
  for (const t of targets) {
    const where = "weighted target";
    if (t === null || typeof t !== "object" || Array.isArray(t)) {
      throw new RangeError(`${where} must be an object, got ${JSON.stringify(t)}`);
    }
    const { targetUrl, weight } = t as { targetUrl: unknown; weight: unknown };
    if (typeof targetUrl !== "string" || targetUrl.length === 0) {
      throw new RangeError(`${where}.targetUrl must be a non-empty string, got ${JSON.stringify(targetUrl)}`);
    }
    if (seen.has(targetUrl)) {
      throw new RangeError(`${where}: duplicate targetUrl ${JSON.stringify(targetUrl)}`);
    }
    seen.add(targetUrl);
    if (typeof weight !== "number" || !Number.isFinite(weight) || weight <= 0) {
      throw new RangeError(
        `${where} ${JSON.stringify(targetUrl)}: weight must be a finite number > 0, got ${JSON.stringify(weight)}`
      );
    }
    total += weight;
  }
  if (!(total > 0)) {
    throw new RangeError("weighted targets must have a positive total weight");
  }
}

/**
 * Validate a weighted dispatch config. Throws `RangeError` on anything
 * illegal — at construction, never mid-delivery.
 */
export function assertValidWeightedConfig(config: WeightedConfig): void {
  if (config === null || typeof config !== "object" || Array.isArray(config)) {
    throw new RangeError(
      `weighted must be a record of endpoint -> target config, got ${JSON.stringify(config)}`
    );
  }
  for (const [endpoint, cfg] of Object.entries(config)) {
    const where = `weighted[${JSON.stringify(endpoint)}]`;
    if (endpoint.length === 0) {
      throw new RangeError("weighted endpoint must be a non-empty string");
    }
    if (cfg === null || typeof cfg !== "object" || Array.isArray(cfg)) {
      throw new RangeError(`${where} must be an object, got ${JSON.stringify(cfg)}`);
    }
    assertValidWeightedTargets(cfg.targets);
    const { failureThreshold, recoveryIntervalMs } = cfg;
    if (
      failureThreshold !== undefined &&
      (!Number.isInteger(failureThreshold) || failureThreshold < 1)
    ) {
      throw new RangeError(
        `${where}.failureThreshold must be an integer >= 1, got ${JSON.stringify(failureThreshold)}`
      );
    }
    if (
      recoveryIntervalMs !== undefined &&
      (!Number.isFinite(recoveryIntervalMs) || recoveryIntervalMs <= 0)
    ) {
      throw new RangeError(
        `${where}.recoveryIntervalMs must be > 0, got ${JSON.stringify(recoveryIntervalMs)}`
      );
    }
  }
}

interface EndpointWeightedState {
  /** Physical targets in config order; replaced atomically on weight updates. */
  targets: WeightedTargetConfig[];
  failureThreshold: number;
  recoveryIntervalMs: number;
  /** Smooth-WRR accumulator per target (reset on weight changes). */
  currentWeight: Map<string, number>;
  /** Own consecutive-failure counter per target (works breaker-less). */
  consecutiveFailures: Map<string, number>;
  /** ms epoch of each target's last recorded failure. */
  lastFailureAtMs: Map<string, number>;
  /** Cumulative dispatches per target. */
  dispatched: Map<string, number>;
}

/**
 * Smooth weighted round-robin target selection per logical endpoint.
 * Pure routing state — it never sends anything itself; the retry queue
 * asks `resolveTarget()` on every dispatch and reports outcomes via
 * `recordOutcome()`.
 */
export class WeightedDispatcher {
  private readonly states = new Map<string, EndpointWeightedState>();
  private readonly now: () => number;
  private readonly circuitState: (target: string) => CircuitState;

  constructor(config: WeightedConfig, opts: WeightedDispatcherOptions = {}) {
    assertValidWeightedConfig(config);
    this.now = opts.now ?? Date.now;
    this.circuitState = opts.circuitState ?? (() => "closed");
    for (const [endpoint, cfg] of Object.entries(config)) {
      this.states.set(endpoint, this.freshState(cfg));
    }
  }

  /** Whether `endpoint` has weighted dispatch configured. */
  hasEndpoint(endpoint: string): boolean {
    return this.states.has(endpoint);
  }

  /**
   * The physical target the next dispatch for `endpoint` should go to.
   * Returns `undefined` when the endpoint has no weighted config (the
   * caller falls through to failover / the endpoint itself — zero
   * behavior change when weighted mode is not configured).
   *
   * Smooth weighted round-robin over the *healthy* targets: each pick
   * adds every candidate's weight to its accumulator, takes the max, and
   * subtracts the pool's total weight from the winner. Deterministic
   * given the weights and the pick history — no randomness, so shares
   * are exact per weight cycle. When every target is unhealthy the first
   * configured target is pinned (documented fallback — the queue's
   * retry / dead-letter machinery owns the outcome).
   */
  resolveTarget(endpoint: string): string | undefined {
    const st = this.states.get(endpoint);
    if (!st) return undefined;
    const healthy = st.targets.filter((t) => this.isHealthy(st, t.targetUrl));
    const pool = healthy.length > 0 ? healthy : [st.targets[0]];
    let total = 0;
    let best = pool[0];
    let bestCurrent = -Infinity;
    for (const t of pool) {
      const current = this.currentOf(st, t.targetUrl) + t.weight;
      this.currentWeightSet(st, t.targetUrl, current);
      total += t.weight;
      if (current > bestCurrent) {
        best = t;
        bestCurrent = current;
      }
    }
    this.currentWeightSet(st, best.targetUrl, bestCurrent - total);
    st.dispatched.set(best.targetUrl, (st.dispatched.get(best.targetUrl) ?? 0) + 1);
    return best.targetUrl;
  }

  /**
   * Report a delivery outcome for `target` (the physical target the
   * attempt went to). A target that *answered* — even with a 4xx —
   * counts as a success: it is up, it just refused this payload.
   * Outcomes for unknown endpoints or targets no longer configured are
   * ignored (stale, e.g. recorded after a weight update removed them).
   */
  recordOutcome(endpoint: string, target: string, ok: boolean): void {
    const st = this.states.get(endpoint);
    if (!st || !st.targets.some((t) => t.targetUrl === target)) return;
    if (ok) {
      st.consecutiveFailures.set(target, 0);
    } else {
      st.consecutiveFailures.set(target, (st.consecutiveFailures.get(target) ?? 0) + 1);
      st.lastFailureAtMs.set(target, this.now());
    }
  }

  /**
   * Replace the target list for `endpoint` at runtime (WR-32). Validated
   * *before* anything mutates: an illegal list throws `RangeError` and
   * the previous configuration is left completely intact — zero partial
   * application. The smooth-WRR accumulators reset (stale accumulators
   * would bias the new distribution); per-target health counters and
   * cumulative dispatch counts survive for targets still present.
   */
  setWeights(endpoint: string, targets: WeightedTargetConfig[]): void {
    const st = this.states.get(endpoint);
    if (!st) {
      throw new RangeError(
        `weighted dispatch is not configured for endpoint ${JSON.stringify(endpoint)}`
      );
    }
    assertValidWeightedTargets(targets);
    st.targets = targets.map((t) => ({ targetUrl: t.targetUrl, weight: t.weight }));
    for (const t of st.targets) {
      st.currentWeight.set(t.targetUrl, 0);
    }
  }

  /** Snapshot of every endpoint with weighted dispatch configured. */
  stats(): WeightedEndpointStats[] {
    return [...this.states.entries()].map(([endpoint, st]) => ({
      endpoint,
      targets: st.targets.map((t) => ({
        targetUrl: t.targetUrl,
        weight: t.weight,
        effectiveWeight: t.weight,
        dispatched: st.dispatched.get(t.targetUrl) ?? 0,
        consecutiveFailures: st.consecutiveFailures.get(t.targetUrl) ?? 0,
        healthy: this.isHealthy(st, t.targetUrl),
      })),
    }));
  }

  private freshState(cfg: WeightedEndpointConfig): EndpointWeightedState {
    const st: EndpointWeightedState = {
      targets: cfg.targets.map((t) => ({ targetUrl: t.targetUrl, weight: t.weight })),
      failureThreshold: cfg.failureThreshold ?? DEFAULT_WEIGHTED_FAILURE_THRESHOLD,
      recoveryIntervalMs: cfg.recoveryIntervalMs ?? DEFAULT_WEIGHTED_RECOVERY_INTERVAL_MS,
      currentWeight: new Map(),
      consecutiveFailures: new Map(),
      lastFailureAtMs: new Map(),
      dispatched: new Map(),
    };
    for (const t of st.targets) {
      st.currentWeight.set(t.targetUrl, 0);
      st.consecutiveFailures.set(t.targetUrl, 0);
    }
    return st;
  }

  private currentOf(st: EndpointWeightedState, target: string): number {
    return st.currentWeight.get(target) ?? 0;
  }

  private currentWeightSet(st: EndpointWeightedState, target: string, value: number): void {
    st.currentWeight.set(target, value);
  }

  /**
   * Whether `target` joins the rotation. The breaker's `open` state
   * always excludes; `half_open` always includes (the breaker's probe
   * delivery must run so its outcome can re-admit or re-exclude).
   * Otherwise the dispatcher's own consecutive-failure counter applies —
   * after `failureThreshold` failures the target is out until
   * `recoveryIntervalMs` has passed since its last failure (the recovery
   * canary), so exclusion works with the breaker disabled too.
   */
  private isHealthy(st: EndpointWeightedState, target: string): boolean {
    const circuit = this.circuitState(target);
    if (circuit === "open") return false;
    if (circuit === "half_open") return true;
    const failures = st.consecutiveFailures.get(target) ?? 0;
    if (failures < st.failureThreshold) return true;
    const lastFailure = st.lastFailureAtMs.get(target) ?? 0;
    return this.now() - lastFailure >= st.recoveryIntervalMs;
  }
}
