import type { CircuitState } from "./circuit.ts";

/**
 * Per-endpoint active/standby failover (WR-39).
 *
 * One logical endpoint (the configured primary `targetUrl`) owns an
 * ordered list of physical targets: the primary plus its standbys. The
 * queue resolves the *active* target on every dispatch, so a switch never
 * touches queued items — in-flight deliveries keep the target they were
 * dispatched with (the sender receives a copy pinned to that target) and
 * replays always re-resolve against the current active target.
 *
 * Switching is lazy and edge-triggered: the manager only moves when a
 * dispatch observes the active target down, so a burst of failures
 * produces exactly one audited switch, never a flap per attempt.
 *
 * Triggers (checked at dispatch time):
 * - the active target's circuit breaker is `open`, or
 * - `failureThreshold` consecutive retryable delivery failures on the
 *   active target (the manager's own counter, independent of the
 *   breaker's — it works with the breaker disabled too). A downstream
 *   that *answers* (even with a 4xx) counts as a success: it is up, it
 *   just refused this payload.
 *
 * Failback is a probationary canary, never blind trust: once
 * `failbackIntervalMs` has passed since the last switch and
 * `autoFailback` is on, the next dispatch goes to the primary. Its first
 * outcome alone decides — success keeps the primary, failure re-switches
 * to the standby immediately. While the canary is unconfirmed every
 * dispatch stays on it, so there is no mid-probation flapping.
 */

/** Default consecutive failures on the active target before switching. */
export const DEFAULT_FAILOVER_FAILURE_THRESHOLD = 5;
/** Default quiet period after a switch before the primary gets a canary. */
export const DEFAULT_FAILOVER_FAILBACK_INTERVAL_MS = 30_000;

/** Failover tuning for one logical endpoint (keyed by primary `targetUrl`). */
export interface FailoverTargetConfig {
  /**
   * Ordered standby `targetUrl`s, tried in order after the primary.
   * Required, non-empty. A standby must not equal the primary, must not
   * repeat, and must not itself be a configured primary (chained
   * failover is rejected at startup rather than silently ignored).
   */
  standbys: string[];
  /**
   * Consecutive retryable failures on the active target that trigger a
   * switch. Default: 5. Must be an integer >= 1.
   */
  failureThreshold?: number;
  /**
   * When true (default), the primary gets a probationary canary delivery
   * once `failbackIntervalMs` has passed since the last switch. When
   * false, the relay stays on the standby until `resetFailover()` is
   * called.
   */
  autoFailback?: boolean;
  /**
   * Quiet period in ms after a switch before the primary becomes
   * eligible for a failback canary. Default: 30_000. Must be > 0.
   */
  failbackIntervalMs?: number;
}

/** Failover configuration: primary `targetUrl` -> its target config. */
export type FailoverConfig = Record<string, FailoverTargetConfig>;

/** Why a failover switch happened. */
export type FailoverSwitchReason =
  | "circuit_open"
  | "failure_threshold"
  | "failback"
  | "manual";

/** Audited on every failover switch (the server writes `failover_switched`). */
export interface FailoverSwitchEvent {
  event: "failover_switched";
  /** Logical endpoint: the configured primary `targetUrl`. */
  endpoint: string;
  /** Target deliveries were going to before the switch. */
  from: string;
  /** Target deliveries go to after the switch. */
  to: string;
  reason: FailoverSwitchReason;
  /** ISO-8601 timestamp of the switch. */
  at: string;
}

/** Observable snapshot of one endpoint's failover state. */
export interface FailoverEndpointStats {
  /** Logical endpoint (the configured primary `targetUrl`). */
  endpoint: string;
  /** Where new dispatches currently go. */
  activeTarget: string;
  /** `[primary, ...standbys]`, in try order. */
  targets: string[];
  /** Total switches (automatic + manual) since construction. */
  switches: number;
  /** Consecutive retryable failures observed on the active target. */
  consecutiveFailures: number;
}

export interface FailoverManagerOptions {
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
  /**
   * Current breaker state for a target. The queue wires its own breaker
   * here; without a breaker every target reads `"closed"` and only the
   * failure-count trigger applies.
   */
  circuitState?: (target: string) => CircuitState;
  /** Called on every switch (automatic failover/failback and manual reset). */
  onSwitch?: (event: FailoverSwitchEvent) => void;
}

interface EndpointFailoverState {
  targets: string[];
  failureThreshold: number;
  autoFailback: boolean;
  failbackIntervalMs: number;
  activeIndex: number;
  consecutiveFailures: number;
  switches: number;
  lastSwitchAtMs: number;
  /**
   * Set while a failback canary is unconfirmed: the primary is on
   * probation and its first outcome alone decides. `previousIndex` is
   * where to return if the canary fails.
   */
  canary: { previousIndex: number } | undefined;
}

/**
 * Validate a failover config. Throws `RangeError` on anything illegal —
 * at construction, never mid-delivery.
 */
export function assertValidFailoverConfig(config: FailoverConfig): void {
  if (config === null || typeof config !== "object" || Array.isArray(config)) {
    throw new RangeError(
      `failover must be a record of primary targetUrl -> target config, got ${JSON.stringify(config)}`
    );
  }
  const primaries = new Set(Object.keys(config));
  for (const [endpoint, cfg] of Object.entries(config)) {
    const where = `failover[${JSON.stringify(endpoint)}]`;
    if (endpoint.length === 0) {
      throw new RangeError("failover endpoint (primary targetUrl) must be a non-empty string");
    }
    if (cfg === null || typeof cfg !== "object" || Array.isArray(cfg)) {
      throw new RangeError(`${where} must be an object, got ${JSON.stringify(cfg)}`);
    }
    const { standbys, failureThreshold, autoFailback, failbackIntervalMs } = cfg;
    if (!Array.isArray(standbys) || standbys.length === 0) {
      throw new RangeError(`${where}.standbys must be a non-empty array of target URLs`);
    }
    const seen = new Set<string>();
    for (const s of standbys) {
      if (typeof s !== "string" || s.length === 0) {
        throw new RangeError(`${where}.standbys must contain only non-empty strings`);
      }
      if (s === endpoint) {
        throw new RangeError(`${where}: a standby must not equal the primary targetUrl`);
      }
      if (primaries.has(s)) {
        throw new RangeError(
          `${where}: standby ${JSON.stringify(s)} is itself a configured primary — chained failover is not supported`
        );
      }
      if (seen.has(s)) {
        throw new RangeError(`${where}: duplicate standby ${JSON.stringify(s)}`);
      }
      seen.add(s);
    }
    if (
      failureThreshold !== undefined &&
      (!Number.isInteger(failureThreshold) || failureThreshold < 1)
    ) {
      throw new RangeError(
        `${where}.failureThreshold must be an integer >= 1, got ${JSON.stringify(failureThreshold)}`
      );
    }
    if (autoFailback !== undefined && typeof autoFailback !== "boolean") {
      throw new RangeError(`${where}.autoFailback must be a boolean, got ${JSON.stringify(autoFailback)}`);
    }
    if (
      failbackIntervalMs !== undefined &&
      (!Number.isFinite(failbackIntervalMs) || failbackIntervalMs <= 0)
    ) {
      throw new RangeError(
        `${where}.failbackIntervalMs must be > 0, got ${JSON.stringify(failbackIntervalMs)}`
      );
    }
  }
}

/**
 * Active/standby target selection for logical endpoints. Pure routing
 * state — it never sends anything itself; the retry queue asks
 * `resolveTarget()` on every dispatch and reports outcomes via
 * `recordOutcome()`.
 */
export class FailoverManager {
  private readonly states = new Map<string, EndpointFailoverState>();
  private readonly now: () => number;
  private readonly circuitState: (target: string) => CircuitState;
  private readonly onSwitch?: (event: FailoverSwitchEvent) => void;

  constructor(config: FailoverConfig, opts: FailoverManagerOptions = {}) {
    assertValidFailoverConfig(config);
    this.now = opts.now ?? Date.now;
    this.circuitState = opts.circuitState ?? (() => "closed");
    this.onSwitch = opts.onSwitch;
    for (const [endpoint, cfg] of Object.entries(config)) {
      this.states.set(endpoint, {
        targets: [endpoint, ...cfg.standbys],
        failureThreshold: cfg.failureThreshold ?? DEFAULT_FAILOVER_FAILURE_THRESHOLD,
        autoFailback: cfg.autoFailback ?? true,
        failbackIntervalMs: cfg.failbackIntervalMs ?? DEFAULT_FAILOVER_FAILBACK_INTERVAL_MS,
        activeIndex: 0,
        consecutiveFailures: 0,
        switches: 0,
        lastSwitchAtMs: this.now(),
        canary: undefined,
      });
    }
  }

  /**
   * The physical target the next dispatch for `endpoint` should go to.
   * Endpoints without failover config resolve to themselves (zero behavior
   * change when failover is not configured).
   */
  resolveTarget(endpoint: string): string {
    const st = this.states.get(endpoint);
    if (!st) return endpoint;
    // Failback canary: the quiet period has passed, so give the primary
    // one probationary delivery. Its outcome alone decides (see
    // `recordOutcome`); until then every dispatch stays on it.
    if (
      st.activeIndex > 0 &&
      st.autoFailback &&
      st.canary === undefined &&
      this.now() - st.lastSwitchAtMs >= st.failbackIntervalMs
    ) {
      this.switchTo(st, endpoint, 0, "failback");
      return st.targets[0];
    }
    if (st.canary !== undefined) return st.targets[st.activeIndex];
    const active = st.targets[st.activeIndex];
    const circuitOpen = this.circuitState(active) === "open";
    const thresholdHit = st.consecutiveFailures >= st.failureThreshold;
    if ((circuitOpen || thresholdHit) && st.activeIndex < st.targets.length - 1) {
      this.switchTo(st, endpoint, st.activeIndex + 1, circuitOpen ? "circuit_open" : "failure_threshold");
      return st.targets[st.activeIndex];
    }
    // Every target is down: keep trying the last one rather than dropping
    // the delivery — the queue's normal retry / dead-letter machinery owns
    // the outcome from here.
    return active;
  }

  /**
   * Report a delivery outcome for `target` (the physical target the
   * attempt went to). A target that *answered* — even with a 4xx — counts
   * as a success: it is up, it just refused this payload. Outcomes for a
   * target we already switched away from are stale and ignored.
   */
  recordOutcome(endpoint: string, target: string, ok: boolean): void {
    const st = this.states.get(endpoint);
    if (!st || target !== st.targets[st.activeIndex]) return;
    if (st.canary !== undefined) {
      // The failback canary: its outcome alone decides.
      const previousIndex = st.canary.previousIndex;
      if (ok) {
        st.consecutiveFailures = 0;
      } else {
        // Probation failed — the primary is still sick. Back to the
        // standby immediately; the next canary waits a full interval.
        this.switchTo(st, endpoint, previousIndex, "failure_threshold");
        return;
      }
      st.canary = undefined;
      return;
    }
    if (ok) st.consecutiveFailures = 0;
    else st.consecutiveFailures += 1;
  }

  /**
   * Manually return `endpoint` to its primary (clears probation and the
   * failure count). Returns false when the endpoint has no failover
   * config. Emits a `failover_switched` event with reason `"manual"` when
   * it actually moves traffic.
   */
  resetFailover(endpoint: string): boolean {
    const st = this.states.get(endpoint);
    if (!st) return false;
    const from = st.targets[st.activeIndex];
    st.activeIndex = 0;
    st.consecutiveFailures = 0;
    st.canary = undefined;
    st.lastSwitchAtMs = this.now();
    if (from !== st.targets[0]) {
      st.switches += 1;
      this.onSwitch?.({
        event: "failover_switched",
        endpoint,
        from,
        to: st.targets[0],
        reason: "manual",
        at: new Date(this.now()).toISOString(),
      });
    }
    return true;
  }

  /** Snapshot of every endpoint with failover configured. */
  stats(): FailoverEndpointStats[] {
    return [...this.states.entries()].map(([endpoint, st]) => ({
      endpoint,
      activeTarget: st.targets[st.activeIndex],
      targets: [...st.targets],
      switches: st.switches,
      consecutiveFailures: st.consecutiveFailures,
    }));
  }

  private switchTo(
    st: EndpointFailoverState,
    endpoint: string,
    newIndex: number,
    reason: FailoverSwitchReason
  ): void {
    const from = st.targets[st.activeIndex];
    const to = st.targets[newIndex];
    const previousIndex = st.activeIndex;
    st.activeIndex = newIndex;
    st.consecutiveFailures = 0;
    st.switches += 1;
    st.lastSwitchAtMs = this.now();
    // A failback is probationary: the first outcome on the primary
    // decides whether it stays.
    st.canary = newIndex === 0 && previousIndex !== 0 ? { previousIndex } : undefined;
    this.onSwitch?.({
      event: "failover_switched",
      endpoint,
      from,
      to,
      reason,
      at: new Date(this.now()).toISOString(),
    });
  }
}
