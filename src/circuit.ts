/** Health state of one endpoint's circuit. */
export type CircuitState = "closed" | "open" | "half_open";

export interface CircuitBreakerOptions {
  /**
   * Consecutive delivery failures that trip the circuit open.
   * Default: 5. Must be an integer >= 1.
   */
  failureThreshold?: number;
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
  state: CircuitState;
  /** Consecutive failures since the last success (0 once closed). */
  consecutiveFailures: number;
  /** ms epoch when the circuit last opened; absent when never tripped. */
  openedAtMs?: number;
  /** Total closed->open and half_open->open trips since construction. */
  trips: number;
}

interface CircuitRecord {
  state: CircuitState;
  consecutiveFailures: number;
  openedAtMs?: number;
  trips: number;
  halfOpenInFlight: number;
}

/**
 * Per-endpoint circuit breaker: `failureThreshold` consecutive delivery
 * failures trip an endpoint's circuit open for `cooldownMs`; once the
 * cooldown elapses a single half-open probe is let through — a success
 * closes the circuit, a failure re-opens it and restarts the cooldown.
 *
 * The breaker only *observes* outcomes and *advises* (`shouldAllow`); the
 * caller decides what to do with a parked attempt (the retry queue
 * reschedules it without consuming the retry budget) and reports each
 * delivery via `recordSuccess` / `recordFailure`. A probe permit granted by
 * `shouldAllow` must be settled exactly once: `recordSuccess` /
 * `recordFailure` when the probe ran, `cancelProbe` when it was granted but
 * never executed (e.g. the queue stopped while waiting for a slot).
 */
export class EndpointCircuitBreaker {
  private readonly failureThreshold: number;
  private readonly cooldownMs: number;
  private readonly halfOpenMaxInFlight: number;
  private readonly halfOpenRetryMs: number;
  private readonly nowMs: () => number;
  private readonly onStateChange?: (endpoint: string, from: CircuitState, to: CircuitState) => void;
  private readonly records = new Map<string, CircuitRecord>();

  constructor(opts: CircuitBreakerOptions = {}) {
    this.failureThreshold = opts.failureThreshold ?? 5;
    this.cooldownMs = opts.cooldownMs ?? 30_000;
    this.halfOpenMaxInFlight = opts.halfOpenMaxInFlight ?? 1;
    this.halfOpenRetryMs = opts.halfOpenRetryMs ?? 1000;
    this.nowMs = opts.nowMs ?? Date.now;
    this.onStateChange = opts.onStateChange;
    if (!Number.isInteger(this.failureThreshold) || this.failureThreshold < 1) {
      throw new RangeError(`failureThreshold must be an integer >= 1, got ${opts.failureThreshold}`);
    }
    if (!Number.isFinite(this.cooldownMs) || this.cooldownMs <= 0) {
      throw new RangeError(`cooldownMs must be > 0, got ${opts.cooldownMs}`);
    }
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
      if (this.nowMs() - (rec.openedAtMs ?? 0) < this.cooldownMs) {
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
      rec.halfOpenInFlight = 0;
      rec.consecutiveFailures = 0;
      this.transition(endpoint, rec, "closed");
    } else if (rec.state === "closed") {
      rec.consecutiveFailures = 0;
    }
    // A success reported while open means the caller bypassed shouldAllow;
    // ignore it rather than corrupting the cooldown.
  }

  /** Report a failed delivery. Trips (or re-trips) the circuit at the threshold. */
  recordFailure(endpoint: string): void {
    const rec = this.recordFor(endpoint);
    if (rec.state === "half_open") {
      // Probe failed: re-open and restart the cooldown.
      rec.halfOpenInFlight = 0;
      this.trip(endpoint, rec);
      return;
    }
    if (rec.state === "open") return; // already open; cooldown keeps running
    rec.consecutiveFailures += 1;
    if (rec.consecutiveFailures >= this.failureThreshold) {
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
    return Math.max(0, (rec.openedAtMs ?? 0) + this.cooldownMs - this.nowMs());
  }

  /** Snapshot of every endpoint the breaker has observed. */
  stats(): CircuitStats[] {
    return [...this.records.entries()].map(([endpoint, rec]) => ({
      endpoint,
      state: rec.state,
      consecutiveFailures: rec.consecutiveFailures,
      ...(rec.openedAtMs !== undefined ? { openedAtMs: rec.openedAtMs } : {}),
      trips: rec.trips,
    }));
  }

  private recordFor(endpoint: string): CircuitRecord {
    let rec = this.records.get(endpoint);
    if (!rec) {
      rec = { state: "closed", consecutiveFailures: 0, trips: 0, halfOpenInFlight: 0 };
      this.records.set(endpoint, rec);
    }
    return rec;
  }

  private trip(endpoint: string, rec: CircuitRecord): void {
    rec.openedAtMs = this.nowMs();
    rec.trips += 1;
    this.transition(endpoint, rec, "open");
  }

  private transition(endpoint: string, rec: CircuitRecord, to: CircuitState): void {
    const from = rec.state;
    if (from === to) return;
    rec.state = to;
    this.onStateChange?.(endpoint, from, to);
  }
}
