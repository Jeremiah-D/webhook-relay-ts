/**
 * WR-59: adaptive retry backoff.
 *
 * The classic exponential backoff (`base * 2^attempt`) uses one fixed base
 * for every endpoint. That is wrong in both directions: a fixed base that
 * is right for a healthy endpoint hammers a sick one (too dense during a
 * wide outage), and a base tuned for outages recovers too slowly when the
 * downstream comes back.
 *
 * The {@link AdaptiveBackoffController} scales the *base* per endpoint
 * from recent delivery outcomes, while the exponent, jitter strategy
 * (WR-02), and max-delay cap keep working exactly as before:
 *
 * - each retryable failure doubles the endpoint's base (up to
 *   `maxBaseMs`) — consecutive failures push it toward the ceiling, so a
 *   sick endpoint is retried progressively less often;
 * - each success halves the base (down to `minBaseMs`) — a high success
 *   rate converges the base back to the floor, so recovery is quick;
 * - the base is always clamped to `[minBaseMs, maxBaseMs]`.
 *
 * Outcomes are the only input — no clock, no randomness — so the
 * controller is deterministic by construction and needs no injectable
 * clock for tests. It composes orthogonally with the global retry budget
 * (WR-38): the budget gate runs *before* the backoff is computed, so a
 * budget-parked retry waits on the budget, not on an inflated base.
 *
 * Disabled by default (backward compatible): the queue only consults the
 * controller when `adaptiveBackoff` is configured.
 */

/** Floor for the adaptive base, in ms. */
export const DEFAULT_ADAPTIVE_MIN_BASE_MS = 100;
/** Ceiling for the adaptive base, in ms. */
export const DEFAULT_ADAPTIVE_MAX_BASE_MS = 30_000;
/** Base multiplier applied per retryable failure. */
export const DEFAULT_ADAPTIVE_UP_FACTOR = 2;
/** Base multiplier applied per success. */
export const DEFAULT_ADAPTIVE_DOWN_FACTOR = 0.5;

/** Tuning for {@link AdaptiveBackoffController}. */
export interface AdaptiveBackoffOptions {
  /**
   * Floor for the adaptive base in ms: a high success rate converges the
   * base here. Default: 100. Must be > 0.
   */
  minBaseMs?: number;
  /**
   * Ceiling for the adaptive base in ms: consecutive failures push the
   * base here, never beyond. Default: 30000. Must be >= `minBaseMs`.
   */
  maxBaseMs?: number;
  /**
   * Multiplier applied to the base per retryable failure. Default: 2.
   * Must be > 1.
   */
  upFactor?: number;
  /**
   * Multiplier applied to the base per success. Default: 0.5. Must be in
   * the open interval (0, 1).
   */
  downFactor?: number;
}

/** One endpoint's adaptive backoff state. */
export interface AdaptiveBackoffEndpointStats {
  /** The endpoint (physical `targetUrl`) this row describes. */
  endpoint: string;
  /** Tenant id (WR-48); the queue adds it — absent for the default tenant. */
  tenant?: string;
  /** The endpoint's current backoff base in ms. */
  baseMs: number;
  /** Current consecutive-failure streak (resets on success). */
  consecutiveFailures: number;
  /** Current consecutive-success streak (resets on failure). */
  consecutiveSuccesses: number;
}

function assertAdaptiveBackoffOptions(
  initialBaseMs: number,
  opts: AdaptiveBackoffOptions
): { minBaseMs: number; maxBaseMs: number; upFactor: number; downFactor: number } {
  if (!Number.isFinite(initialBaseMs) || initialBaseMs <= 0) {
    throw new RangeError(`adaptiveBackoff: initial base must be > 0, got ${initialBaseMs}`);
  }
  const minBaseMs = opts.minBaseMs ?? DEFAULT_ADAPTIVE_MIN_BASE_MS;
  if (!Number.isFinite(minBaseMs) || minBaseMs <= 0) {
    throw new RangeError(`adaptiveBackoff.minBaseMs must be > 0, got ${opts.minBaseMs}`);
  }
  const maxBaseMs = opts.maxBaseMs ?? DEFAULT_ADAPTIVE_MAX_BASE_MS;
  if (!Number.isFinite(maxBaseMs) || maxBaseMs < minBaseMs) {
    throw new RangeError(
      `adaptiveBackoff.maxBaseMs must be >= minBaseMs (${minBaseMs}), got ${opts.maxBaseMs}`
    );
  }
  const upFactor = opts.upFactor ?? DEFAULT_ADAPTIVE_UP_FACTOR;
  if (!Number.isFinite(upFactor) || upFactor <= 1) {
    throw new RangeError(`adaptiveBackoff.upFactor must be > 1, got ${opts.upFactor}`);
  }
  const downFactor = opts.downFactor ?? DEFAULT_ADAPTIVE_DOWN_FACTOR;
  if (!Number.isFinite(downFactor) || downFactor <= 0 || downFactor >= 1) {
    throw new RangeError(
      `adaptiveBackoff.downFactor must be in the open interval (0, 1), got ${opts.downFactor}`
    );
  }
  return { minBaseMs, maxBaseMs, upFactor, downFactor };
}

/**
 * Per-endpoint adaptive backoff-base controller (WR-59).
 *
 * Pure outcome bookkeeping: `recordOutcome` moves the base, `baseFor`
 * reads it, `stats` snapshots it. No clock, no randomness — the same
 * outcome sequence always yields the same bases.
 */
export class AdaptiveBackoffController {
  private readonly minBaseMs: number;
  private readonly maxBaseMs: number;
  private readonly upFactor: number;
  private readonly downFactor: number;
  /**
   * The resting base, read live: endpoints with no recorded outcomes use
   * it, so a queue-level hot-reload of `baseDelayMs` (WR-32) stays in
   * sync without touching adapted endpoints.
   */
  private readonly initialBase: () => number;
  private readonly bases = new Map<string, number>();
  private readonly consecutiveFailures = new Map<string, number>();
  private readonly consecutiveSuccesses = new Map<string, number>();

  constructor(initialBaseMs: number | (() => number), opts: AdaptiveBackoffOptions = {}) {
    const initial = typeof initialBaseMs === "function" ? initialBaseMs() : initialBaseMs;
    const { minBaseMs, maxBaseMs, upFactor, downFactor } = assertAdaptiveBackoffOptions(initial, opts);
    this.minBaseMs = minBaseMs;
    this.maxBaseMs = maxBaseMs;
    this.upFactor = upFactor;
    this.downFactor = downFactor;
    this.initialBase =
      typeof initialBaseMs === "function" ? initialBaseMs : () => initialBaseMs;
  }

  /**
   * Feed one delivery outcome for `endpoint` into the controller.
   * `success` follows the circuit breaker's convention: a transport-level
   * success (including a downstream that answered with a
   * non-retryable rejection — the endpoint is healthy, the payload was
   * not) cools the base; a retryable failure heats it.
   */
  recordOutcome(endpoint: string, success: boolean): void {
    const current = this.bases.get(endpoint) ?? this.initialBase();
    if (success) {
      this.bases.set(endpoint, Math.max(this.minBaseMs, current * this.downFactor));
      this.consecutiveFailures.set(endpoint, 0);
      this.consecutiveSuccesses.set(endpoint, (this.consecutiveSuccesses.get(endpoint) ?? 0) + 1);
    } else {
      this.bases.set(endpoint, Math.min(this.maxBaseMs, current * this.upFactor));
      this.consecutiveSuccesses.set(endpoint, 0);
      this.consecutiveFailures.set(endpoint, (this.consecutiveFailures.get(endpoint) ?? 0) + 1);
    }
  }

  /**
   * The endpoint's current backoff base in ms — the adapted base, or the
   * resting base when no outcome has been recorded for it yet.
   */
  baseFor(endpoint: string): number {
    return this.bases.get(endpoint) ?? this.initialBase();
  }

  /** Forget an endpoint's adapted state (`undefined` = all endpoints). */
  reset(endpoint?: string): void {
    if (endpoint === undefined) {
      this.bases.clear();
      this.consecutiveFailures.clear();
      this.consecutiveSuccesses.clear();
      return;
    }
    this.bases.delete(endpoint);
    this.consecutiveFailures.delete(endpoint);
    this.consecutiveSuccesses.delete(endpoint);
  }

  /**
   * One row per endpoint with a recorded outcome. Endpoints that never
   * reported an outcome are absent — they use the resting base (see
   * {@link baseFor}).
   */
  stats(): AdaptiveBackoffEndpointStats[] {
    const rows: AdaptiveBackoffEndpointStats[] = [];
    for (const [endpoint, baseMs] of this.bases) {
      rows.push({
        endpoint,
        baseMs,
        consecutiveFailures: this.consecutiveFailures.get(endpoint) ?? 0,
        consecutiveSuccesses: this.consecutiveSuccesses.get(endpoint) ?? 0,
      });
    }
    return rows;
  }
}
