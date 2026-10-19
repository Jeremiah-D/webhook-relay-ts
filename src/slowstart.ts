/**
 * WR-148: circuit-breaker slow-start recovery ramp.
 *
 * When a circuit breaker trips, the endpoint is known-down. When it
 * recovers (half-open probe succeeds -> closed), restoring the full
 * concurrency limit at once risks a thundering herd against a
 * downstream that just came back to life. The {@link SlowStartController}
 * paces the recovery: on the breaker-close event the endpoint's
 * effective concurrency limit drops to `floor` (default 1) and climbs a
 * curve — `1 -> 2 -> 4` exponential (default) or `+1` additive — on each
 * successful delivery, until it reaches the ceiling, at which point the
 * ramp completes and the endpoint runs at the full limit again. A
 * failure during the ramp drops the limit back to the floor instantly
 * and the ramp restarts — the endpoint has to re-prove itself.
 *
 * Relationship to the sibling controllers:
 * - WR-10 circuit breaker: orthogonal state machine — it decides
 *   open/closed; the ramp only starts on its close event.
 * - WR-94 AIMD adaptive concurrency: orthogonal — AIMD is
 *   *outcome-driven* window adjustment of the steady-state limit, the
 *   ramp is *event-driven* (breaker-close) recovery pacing. The
 *   effective per-endpoint limit is `min(fixed, adaptive, ramp)`.
 * - WR-06 fixed cap: the ramp ceiling defaults to it, so the ramp can
 *   never climb past the configured static limit.
 *
 * The controller is purely outcome-driven: no clock, no timers, no
 * randomness — the same outcome sequence always yields the same limits,
 * so tests are deterministic by construction (same philosophy as the
 * WR-94 controller). Disabled by default: the queue only consults it
 * when `RetryQueueOptions.slowStart` is set, and the ramp only ever
 * starts on a breaker-close event, so without a circuit breaker
 * configured the feature is a complete no-op.
 */

/** Shape of the recovery curve. */
export type SlowStartCurve = "exponential" | "additive";

/** Default curve: `1 -> 2 -> 4 -> ...` doubling per success. */
export const DEFAULT_SLOW_START_CURVE: SlowStartCurve = "exponential";
/** Default concurrency the ramp starts (and falls back to) per endpoint. */
export const DEFAULT_SLOW_START_FLOOR = 1;

/** Tuning for {@link SlowStartController}. */
export interface SlowStartOptions {
  /**
   * Recovery curve: `"exponential"` (default) doubles the limit per
   * successful delivery (`1 -> 2 -> 4 -> ...`); `"additive"` adds one per
   * success (`1 -> 2 -> 3 -> ...`).
   */
  curve?: SlowStartCurve;
  /**
   * Concurrency the ramp starts at on a breaker-close event, and falls
   * back to on a failure mid-ramp. Default: 1. Must be a positive
   * integer.
   */
  floor?: number;
  /**
   * Ceiling the ramp climbs toward; reaching it completes the ramp and
   * restores the full limit. The queue defaults it to the endpoint's
   * fixed concurrency cap, so the ramp can never exceed the static
   * limit. Must be a positive integer or `Infinity`, and >= `floor`.
   */
  maxLimit?: number;
}

/** One endpoint's slow-start ramp state. */
export interface SlowStartEndpointStats {
  /** The endpoint (physical `targetUrl`) this row describes. */
  endpoint: string;
  /** Tenant id (WR-48); the queue adds it — absent for the default tenant. */
  tenant?: string;
  /** The endpoint's current ramp limit. */
  limit: number;
  /** The floor the ramp starts/falls back to. */
  floor: number;
  /** The ceiling the ramp climbs toward. */
  ceiling: number;
  /** The recovery curve in effect. */
  curve: SlowStartCurve;
}

export function assertSlowStartOptions(opts: SlowStartOptions): {
  curve: SlowStartCurve;
  floor: number;
  maxLimit: number;
} {
  const curve = opts.curve ?? DEFAULT_SLOW_START_CURVE;
  if (curve !== "exponential" && curve !== "additive") {
    throw new RangeError(
      `slowStart.curve must be "exponential" or "additive", got ${JSON.stringify(opts.curve)}`
    );
  }
  const floor = opts.floor ?? DEFAULT_SLOW_START_FLOOR;
  if (!Number.isInteger(floor) || floor < 1) {
    throw new RangeError(`slowStart.floor must be a positive integer, got ${opts.floor}`);
  }
  const maxLimit = opts.maxLimit ?? Infinity;
  if (maxLimit !== Infinity && (!Number.isInteger(maxLimit) || maxLimit < 1)) {
    throw new RangeError(
      `slowStart.maxLimit must be a positive integer or Infinity, got ${opts.maxLimit}`
    );
  }
  if (maxLimit < floor) {
    throw new RangeError(
      `slowStart.maxLimit (${maxLimit}) must be >= floor (${floor})`
    );
  }
  return { curve, floor, maxLimit };
}

/**
 * Per-endpoint slow-start recovery controller (WR-148).
 *
 * Pure outcome bookkeeping: `onCircuitClosed` starts the ramp,
 * `recordOutcome` steps it, `limitFor` reads the effective limit,
 * `stats` snapshots it. No clock, no randomness.
 */
export class SlowStartController {
  private readonly curve: SlowStartCurve;
  private readonly floor: number;
  private readonly maxLimit: number;
  /**
   * Endpoints currently mid-ramp, mapped to their present limit. An
   * endpoint with no entry runs at the full limit (`maxLimit`).
   */
  private readonly ramps = new Map<string, number>();

  constructor(opts: SlowStartOptions = {}) {
    const cfg = assertSlowStartOptions(opts);
    this.curve = cfg.curve;
    this.floor = cfg.floor;
    this.maxLimit = cfg.maxLimit;
  }

  /**
   * Start (or restart) the recovery ramp for `endpoint`: the effective
   * limit drops to the floor and climbs from there. Called by the queue
   * on the breaker's half_open -> closed transition — a fresh recovery
   * episode always starts at the floor, even if a previous ramp was
   * still climbing.
   */
  onCircuitClosed(endpoint: string): void {
    this.ramps.set(endpoint, this.floor);
  }

  /**
   * Feed one delivery outcome for `endpoint` into the ramp. A success
   * steps the limit up the curve — reaching the ceiling completes the
   * ramp (the endpoint is back at full limit and the entry is dropped).
   * A failure drops the limit back to the floor immediately and the ramp
   * stays active: the endpoint must re-prove itself from the floor.
   * Endpoints with no active ramp ignore outcomes entirely.
   */
  recordOutcome(endpoint: string, success: boolean): void {
    const current = this.ramps.get(endpoint);
    if (current === undefined) return;
    if (!success) {
      // Instant fallback: a mid-ramp failure restarts the climb at the
      // floor — the downstream flinched, so pacing restarts.
      this.ramps.set(endpoint, this.floor);
      return;
    }
    const next = this.curve === "exponential" ? current * 2 : current + 1;
    if (next >= this.maxLimit) {
      // Ramp complete: the ceiling is the full limit, so no entry is
      // needed — `limitFor` falls back to `maxLimit` anyway.
      this.ramps.delete(endpoint);
    } else {
      this.ramps.set(endpoint, next);
    }
  }

  /**
   * The endpoint's current effective ramp limit — the climbing limit
   * while a recovery is ramping, the ceiling (`maxLimit`) otherwise.
   * The queue folds this into `min(fixed, adaptive, ramp)`, so an
   * inactive ramp is always a no-op in that `min()`.
   */
  limitFor(endpoint: string): number {
    return this.ramps.get(endpoint) ?? this.maxLimit;
  }

  /** Whether `endpoint` is currently mid-ramp. */
  ramping(endpoint: string): boolean {
    return this.ramps.has(endpoint);
  }

  /** Forget an endpoint's ramp state (`undefined` = all endpoints). */
  reset(endpoint?: string): void {
    if (endpoint === undefined) {
      this.ramps.clear();
      return;
    }
    this.ramps.delete(endpoint);
  }

  /**
   * One row per endpoint currently mid-ramp. Endpoints at the full
   * limit are absent — they need no pacing.
   */
  stats(): SlowStartEndpointStats[] {
    const rows: SlowStartEndpointStats[] = [];
    for (const [endpoint, limit] of this.ramps) {
      rows.push({
        endpoint,
        limit,
        floor: this.floor,
        ceiling: this.maxLimit,
        curve: this.curve,
      });
    }
    return rows;
  }
}
