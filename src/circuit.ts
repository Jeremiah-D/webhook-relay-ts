/** Health state of one endpoint's circuit. */
export type CircuitState = "closed" | "open" | "half_open";

/**
 * How the breaker decides to trip open (WR-104):
 * - `"consecutive-failures"` (default, WR-10): `failureThreshold`
 *   consecutive delivery failures trip the circuit. Fast for hard-down
 *   endpoints, but a single blip trips a low-threshold breaker.
 * - `"error-rate"`: a rolling window of the last `errorRateWindowSize`
 *   delivery outcomes trips the circuit only when the window holds at
 *   least `errorRateMinSamples` outcomes and the failure rate reaches
 *   `errorRateThreshold`. A lone 1/1 failure can never trip it — the
 *   mode exists to stop jittery endpoints from flapping the breaker.
 *
 * Half-open probe semantics are identical in both modes: one probe
 * (up to `halfOpenMaxInFlight`) after the cooldown, a success closes,
 * a failure re-opens immediately and restarts the cooldown.
 */
export type CircuitTripMode = "consecutive-failures" | "error-rate";

export interface CircuitBreakerOptions {
  /**
   * Consecutive delivery failures that trip the circuit open.
   * Default: 5. Must be an integer >= 1.
   */
  failureThreshold?: number;
  /**
   * Trip decision mode (WR-104). Default: "consecutive-failures".
   */
  tripMode?: CircuitTripMode;
  /**
   * Rolling-window size (delivery outcomes) for `"error-rate"` mode.
   * Default: 20. Must be an integer >= 2.
   */
  errorRateWindowSize?: number;
  /**
   * Failure rate in the rolling window that trips the circuit in
   * `"error-rate"` mode. Default: 0.5. Must be in (0, 1].
   */
  errorRateThreshold?: number;
  /**
   * Minimum outcomes in the window before `"error-rate"` mode may trip.
   * Default: min(10, `errorRateWindowSize`). Must be an integer >= 2 and
   * <= `errorRateWindowSize` — the >= 2 floor is what structurally
   * prevents a 1/1 jitter from opening the circuit.
   */
  errorRateMinSamples?: number;
  /**
   * Cooldown in ms after the circuit opens before a half-open probe is
   * allowed through. Default: 30000. Must be > 0.
   */
  cooldownMs?: number;
  /**
   * Concurrent half-open probes allowed per endpoint. Default: 1.
   * Must be an integer >= 1.
   */
  halfOpenMaxInFlight?: number;
  /**
   * How long (ms) a parked attempt waits before re-checking a half-open
   * circuit whose probe slot is busy. Default: 1000. Must be > 0.
   */
  halfOpenRetryMs?: number;
  /** Clock source; defaults to Date.now. Injectable for tests. */
  nowMs?: () => number;
  /**
   * Called on every state transition: closed->open, open->half_open,
   * half_open->closed, half_open->open.
   */
  onStateChange?: (endpoint: string, from: CircuitState, to: CircuitState) => void;
}

/** Observable snapshot of one endpoint's circuit. */
export interface CircuitStats {
  endpoint: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  state: CircuitState;
  /** Consecutive failures since the last success (0 once closed). */
  consecutiveFailures: number;
  /** ms epoch when the circuit last opened; absent when never tripped. */
  openedAtMs?: number;
  /** Total closed->open and half_open->open trips since construction. */
  trips: number;
  /** Effective trip mode for this endpoint (constructor default or runtime override). */
  tripMode: CircuitTripMode;
  /**
   * Current rolling-window failure rate in [0, 1] (0 when the window is
   * empty). Maintained in both modes so consecutive-failure endpoints
   * still get an observable error rate; only `"error-rate"` mode trips
   * on it.
   */
  errorRate: number;
  /** Delivery outcomes currently held in the rolling window. */
  errorRateSamples: number;
}

/**
 * Runtime-adjustable trip/cooldown thresholds for one endpoint
 * (WR-32 hot reload, WR-104 mode switching). All fields optional; only
 * the provided ones change. The merged effective values are validated
 * as a unit — e.g. a patch that leaves `errorRateMinSamples` above the
 * new `errorRateWindowSize` throws `RangeError`.
 */
export interface CircuitThresholdPatch {
  failureThreshold?: number;
  cooldownMs?: number;
  tripMode?: CircuitTripMode;
  errorRateWindowSize?: number;
  errorRateThreshold?: number;
  errorRateMinSamples?: number;
}

/** Effective thresholds for one endpoint after merging runtime overrides. */
export interface ResolvedCircuitThresholds {
  failureThreshold: number;
  cooldownMs: number;
  tripMode: CircuitTripMode;
  errorRateWindowSize: number;
  errorRateThreshold: number;
  errorRateMinSamples: number;
}

interface CircuitRecord {
  state: CircuitState;
  consecutiveFailures: number;
  openedAtMs?: number;
  trips: number;
  halfOpenInFlight: number;
  /**
   * Rolling outcome window (WR-104): `true` = delivery failure. Kept in
   * both modes, capped at the endpoint's effective
   * `errorRateWindowSize`; only `"error-rate"` mode trips on it.
   */
  window: boolean[];
}

/**
 * Per-endpoint circuit breaker: `failureThreshold` consecutive delivery
 * failures trip an endpoint's circuit open for `cooldownMs` — or, in
 * WR-104 `"error-rate"` mode, a rolling window of the last
 * `errorRateWindowSize` outcomes trips it once the window holds at least
 * `errorRateMinSamples` outcomes and the failure rate reaches
 * `errorRateThreshold`. Once the cooldown elapses a single half-open
 * probe is let through — a success closes the circuit, a failure
 * re-opens it and restarts the cooldown (identical in both modes).
 *
 * The breaker only *observes* outcomes and *advises* (`shouldAllow`); the
 * caller decides what to do with a parked attempt (the retry queue
 * reschedules it without consuming the retry budget) and reports each
 * delivery via `recordSuccess` / `recordFailure`. A probe permit granted by
 * `shouldAllow` must be settled exactly once: `recordSuccess` /
 * `recordFailure` when the probe ran, `cancelProbe` when it was granted but
 * never executed (e.g. the queue stopped while waiting for a slot).
 */
/**
 * Validate and resolve the trip/cooldown thresholds shared by the
 * constructor and the runtime overrides. `values` carries the raw
 * (possibly partial) inputs and `where` names the call site in error
 * messages; `base` supplies the already-resolved defaults the partial
 * values merge over. Throws `RangeError` on any illegal value and
 * returns the fully resolved thresholds.
 */
function resolveCircuitThresholds(
  values: CircuitThresholdPatch,
  where: string,
  base: ResolvedCircuitThresholds
): ResolvedCircuitThresholds {
  const failureThreshold = values.failureThreshold ?? base.failureThreshold;
  const cooldownMs = values.cooldownMs ?? base.cooldownMs;
  const tripMode = values.tripMode ?? base.tripMode;
  const errorRateWindowSize = values.errorRateWindowSize ?? base.errorRateWindowSize;
  const errorRateThreshold = values.errorRateThreshold ?? base.errorRateThreshold;
  const errorRateMinSamples =
    values.errorRateMinSamples ?? Math.min(base.errorRateMinSamples, errorRateWindowSize);
  if (!Number.isInteger(failureThreshold) || failureThreshold < 1) {
    throw new RangeError(
      `${where}: failureThreshold must be an integer >= 1, got ${values.failureThreshold}`
    );
  }
  if (tripMode !== "consecutive-failures" && tripMode !== "error-rate") {
    throw new RangeError(
      `${where}: tripMode must be "consecutive-failures" or "error-rate", got ${JSON.stringify(values.tripMode)}`
    );
  }
  if (!Number.isInteger(errorRateWindowSize) || errorRateWindowSize < 2) {
    throw new RangeError(
      `${where}: errorRateWindowSize must be an integer >= 2, got ${values.errorRateWindowSize}`
    );
  }
  if (!Number.isFinite(errorRateThreshold) || errorRateThreshold <= 0 || errorRateThreshold > 1) {
    throw new RangeError(
      `${where}: errorRateThreshold must be in (0, 1], got ${values.errorRateThreshold}`
    );
  }
  if (
    !Number.isInteger(errorRateMinSamples) ||
    errorRateMinSamples < 2 ||
    errorRateMinSamples > errorRateWindowSize
  ) {
    throw new RangeError(
      `${where}: errorRateMinSamples must be an integer in [2, errorRateWindowSize] (got ${values.errorRateMinSamples} with window size ${errorRateWindowSize})`
    );
  }
  if (!Number.isFinite(cooldownMs) || cooldownMs <= 0) {
    throw new RangeError(`${where}: cooldownMs must be > 0, got ${values.cooldownMs}`);
  }
  return {
    failureThreshold,
    cooldownMs,
    tripMode,
    errorRateWindowSize,
    errorRateThreshold,
    errorRateMinSamples,
  };
}

/** Constructor defaults before any option is applied. */
const CIRCUIT_DEFAULTS: ResolvedCircuitThresholds = {
  failureThreshold: 5,
  cooldownMs: 30_000,
  tripMode: "consecutive-failures",
  errorRateWindowSize: 20,
  errorRateThreshold: 0.5,
  errorRateMinSamples: 10,
};

export class EndpointCircuitBreaker {
  private readonly failureThreshold: number;
  private readonly tripMode: CircuitTripMode;
  private readonly errorRateWindowSize: number;
  private readonly errorRateThreshold: number;
  private readonly errorRateMinSamples: number;
  private readonly cooldownMs: number;
  private readonly halfOpenMaxInFlight: number;
  private readonly halfOpenRetryMs: number;
  private readonly nowMs: () => number;
  private readonly onStateChange?: (endpoint: string, from: CircuitState, to: CircuitState) => void;
  private readonly records = new Map<string, CircuitRecord>();
  /**
   * Per-endpoint threshold overrides installed at runtime (WR-32 hot
   * reload, WR-104 mode switching). An endpoint without an override uses
   * the constructor defaults; overrides never touch existing records — a
   * closed circuit stays closed, an open circuit keeps its `openedAtMs`
   * and only the *remaining* cooldown is recomputed against the new
   * value. Switching `tripMode` at runtime is seamless in both
   * directions: the rolling window and the consecutive-failure counter
   * are maintained in every mode, so the new mode trips on live history
   * instead of a cold start.
   */
  private readonly endpointOverrides = new Map<string, ResolvedCircuitThresholds>();

  constructor(opts: CircuitBreakerOptions = {}) {
    const resolved = resolveCircuitThresholds(opts, "constructor", CIRCUIT_DEFAULTS);
    this.failureThreshold = resolved.failureThreshold;
    this.tripMode = resolved.tripMode;
    this.errorRateWindowSize = resolved.errorRateWindowSize;
    this.errorRateThreshold = resolved.errorRateThreshold;
    this.errorRateMinSamples = resolved.errorRateMinSamples;
    this.cooldownMs = resolved.cooldownMs;
    this.halfOpenMaxInFlight = opts.halfOpenMaxInFlight ?? 1;
    this.halfOpenRetryMs = opts.halfOpenRetryMs ?? 1000;
    this.nowMs = opts.nowMs ?? Date.now;
    this.onStateChange = opts.onStateChange;
    if (!Number.isInteger(this.halfOpenMaxInFlight) || this.halfOpenMaxInFlight < 1) {
      throw new RangeError(`halfOpenMaxInFlight must be an integer >= 1, got ${opts.halfOpenMaxInFlight}`);
    }
    if (!Number.isFinite(this.halfOpenRetryMs) || this.halfOpenRetryMs <= 0) {
      throw new RangeError(`halfOpenRetryMs must be > 0, got ${opts.halfOpenRetryMs}`);
    }
  }

  /** Current state for `endpoint` (`"closed"` when never seen). */
  state(endpoint: string): CircuitState {
    return this.records.get(endpoint)?.state ?? "closed";
  }

  /**
   * Override the trip/cooldown thresholds for one endpoint at runtime.
   * Takes effect immediately for all future trip decisions and cooldown
   * math; in-flight probes and parked attempts are untouched. The patch
   * merges over the current effective values and the merged result is
   * validated as a unit — illegal combinations (e.g. an inherited
   * `errorRateMinSamples` above a shrunk `errorRateWindowSize` is
   * clamped down, an explicitly provided one that does not fit throws)
   * throw `RangeError` and leave the previous thresholds intact. The
   * stored override is the resolved effective set, so `thresholdsFor`
   * can never return an inconsistent combination. Switching `tripMode`
   * is seamless: the rolling window and the consecutive-failure counter
   * are maintained in both modes, so the new mode trips on live history;
   * only a shrunk window trims the stored outcomes.
   */
  setEndpointThresholds(endpoint: string, patch: CircuitThresholdPatch): void {
    const effective = resolveCircuitThresholds(patch, "setEndpointThresholds", this.thresholdsFor(endpoint));
    this.endpointOverrides.set(endpoint, effective);
    const rec = this.records.get(endpoint);
    if (rec !== undefined) {
      while (rec.window.length > effective.errorRateWindowSize) rec.window.shift();
    }
  }

  /**
   * Endpoints carrying a runtime threshold override (WR-32). Used by the
   * WR-88 config snapshot to enumerate the configured keyspace.
   */
  configuredEndpoints(): string[] {
    return [...this.endpointOverrides.keys()];
  }

  /** Whether `endpoint` carries a runtime override. */
  hasEndpointOverride(endpoint: string): boolean {
    return this.endpointOverrides.has(endpoint);
  }

  /**
   * Drop the runtime override so `endpoint` falls back to the constructor
   * defaults. Used by the WR-88 apply rollback. Never throws for unknown
   * endpoints.
   */
  clearEndpointOverride(endpoint: string): void {
    this.endpointOverrides.delete(endpoint);
  }

  /**
   * Effective thresholds for `endpoint`: runtime overrides win over the
   * constructor defaults.
   */
  thresholdsFor(endpoint: string): ResolvedCircuitThresholds {
    const o = this.endpointOverrides.get(endpoint);
    return {
      failureThreshold: o?.failureThreshold ?? this.failureThreshold,
      cooldownMs: o?.cooldownMs ?? this.cooldownMs,
      tripMode: o?.tripMode ?? this.tripMode,
      errorRateWindowSize: o?.errorRateWindowSize ?? this.errorRateWindowSize,
      errorRateThreshold: o?.errorRateThreshold ?? this.errorRateThreshold,
      errorRateMinSamples: o?.errorRateMinSamples ?? this.errorRateMinSamples,
    };
  }

  /**
   * Whether a delivery to `endpoint` may start now. When `allowed` and
   * `probe` are both true, the caller holds the half-open probe slot and
   * must settle it via `recordSuccess` / `recordFailure` / `cancelProbe`.
   */
  shouldAllow(endpoint: string): { allowed: boolean; probe: boolean } {
    const rec = this.recordFor(endpoint);
    if (rec.state === "closed") {
      return { allowed: true, probe: false };
    }
    if (rec.state === "open") {
      if (this.nowMs() - (rec.openedAtMs ?? 0) < this.thresholdsFor(endpoint).cooldownMs) {
        return { allowed: false, probe: false };
      }
      this.transition(endpoint, rec, "half_open");
    }
    // half_open: exactly one probe at a time (up to halfOpenMaxInFlight).
    if (rec.halfOpenInFlight < this.halfOpenMaxInFlight) {
      rec.halfOpenInFlight += 1;
      return { allowed: true, probe: true };
    }
    return { allowed: false, probe: false };
  }

  /** Report a successful delivery. Resets the failure count; a half-open probe closes the circuit. */
  recordSuccess(endpoint: string): void {
    const rec = this.records.get(endpoint);
    if (!rec) return;
    if (rec.state === "half_open") {
      // Probe succeeded: close and start the next episode with a fresh
      // rolling window — pre-trip outcomes must not haunt the new cycle.
      rec.halfOpenInFlight = 0;
      rec.consecutiveFailures = 0;
      rec.window.length = 0;
      this.transition(endpoint, rec, "closed");
    } else if (rec.state === "closed") {
      rec.consecutiveFailures = 0;
      this.pushOutcome(rec, endpoint, false);
    }
    // A success reported while open means the caller bypassed shouldAllow;
    // ignore it rather than corrupting the cooldown.
  }

  /** Report a failed delivery. Trips (or re-trips) the circuit at the threshold. */
  recordFailure(endpoint: string): void {
    const rec = this.recordFor(endpoint);
    if (rec.state === "half_open") {
      // Probe failed: re-open and restart the cooldown. The probe is the
      // verdict — it never feeds the rolling window, so half-open
      // semantics are identical in both trip modes.
      rec.halfOpenInFlight = 0;
      this.trip(endpoint, rec);
      return;
    }
    if (rec.state === "open") return; // already open; cooldown keeps running
    rec.consecutiveFailures += 1;
    this.pushOutcome(rec, endpoint, true);
    const t = this.thresholdsFor(endpoint);
    if (t.tripMode === "error-rate") {
      // The minSamples floor is what stops a lone 1/1 failure from
      // tripping: the rate only counts once the window has enough
      // history to mean something.
      if (rec.window.length >= t.errorRateMinSamples && this.errorRateOf(rec) >= t.errorRateThreshold) {
        this.trip(endpoint, rec);
      }
    } else if (rec.consecutiveFailures >= t.failureThreshold) {
      this.trip(endpoint, rec);
    }
  }

  /**
   * Release a probe permit granted by `shouldAllow` that never executed.
   * The state is unchanged; the slot becomes available to the next attempt.
   */
  cancelProbe(endpoint: string): void {
    const rec = this.records.get(endpoint);
    if (rec && rec.state === "half_open" && rec.halfOpenInFlight > 0) {
      rec.halfOpenInFlight -= 1;
    }
  }

  /**
   * How long (ms) a parked attempt should wait before re-checking the
   * circuit: the remaining cooldown while open, `halfOpenRetryMs` while a
   * probe is in flight, 0 when closed.
   */
  retryInMs(endpoint: string): number {
    const rec = this.records.get(endpoint);
    if (!rec || rec.state === "closed") return 0;
    if (rec.state === "half_open") return this.halfOpenRetryMs;
    return Math.max(0, (rec.openedAtMs ?? 0) + this.thresholdsFor(endpoint).cooldownMs - this.nowMs());
  }

  /** Snapshot of every endpoint the breaker has observed. */
  stats(): CircuitStats[] {
    return [...this.records.entries()].map(([endpoint, rec]) => {
      const t = this.thresholdsFor(endpoint);
      return {
        endpoint,
        state: rec.state,
        consecutiveFailures: rec.consecutiveFailures,
        ...(rec.openedAtMs !== undefined ? { openedAtMs: rec.openedAtMs } : {}),
        trips: rec.trips,
        tripMode: t.tripMode,
        errorRate: this.errorRateOf(rec),
        errorRateSamples: rec.window.length,
      };
    });
  }

  private recordFor(endpoint: string): CircuitRecord {
    let rec = this.records.get(endpoint);
    if (!rec) {
      rec = { state: "closed", consecutiveFailures: 0, trips: 0, halfOpenInFlight: 0, window: [] };
      this.records.set(endpoint, rec);
    }
    return rec;
  }

  /** Failure rate over the endpoint's current rolling window (0 when empty). */
  private errorRateOf(rec: CircuitRecord): number {
    if (rec.window.length === 0) return 0;
    let failures = 0;
    for (const failed of rec.window) if (failed) failures++;
    return failures / rec.window.length;
  }

  /**
   * Append one closed-state outcome to the endpoint's rolling window,
   * keeping it capped at the effective window size (oldest evicted).
   */
  private pushOutcome(rec: CircuitRecord, endpoint: string, failed: boolean): void {
    rec.window.push(failed);
    const size = this.thresholdsFor(endpoint).errorRateWindowSize;
    while (rec.window.length > size) rec.window.shift();
  }

  private trip(endpoint: string, rec: CircuitRecord): void {
    rec.openedAtMs = this.nowMs();
    rec.trips += 1;
    // Each trip episode starts with a fresh window: the cooldown is the
    // reset boundary, not a continuation of pre-trip history.
    rec.window.length = 0;
    this.transition(endpoint, rec, "open");
  }

  private transition(endpoint: string, rec: CircuitRecord, to: CircuitState): void {
    const from = rec.state;
    if (from === to) return;
    rec.state = to;
    this.onStateChange?.(endpoint, from, to);
  }
}
