/**
 * WR-94: adaptive outbound concurrency (AIMD).
 *
 * The fixed per-endpoint concurrency cap (WR-06) protects the relay from
 * over-committing, but it is static: the same cap that is right for a
 * healthy downstream starves a sick one of recovery room (too many
 * concurrent attempts against a struggling endpoint) or throttles a
 * strong one below its real capacity. The {@link AdaptiveConcurrencyController}
 * adds a second, *outcome-driven* cap per endpoint using the classic AIMD
 * (additive-increase / multiplicative-decrease) scheme from congestion
 * control:
 *
 * - outcomes accumulate in a bounded window (`windowSize` recent outcomes
 *   per endpoint);
 * - when a full window's failure rate stays below `failureRateThreshold`,
 *   the limit grows additively (`+increaseStep`) — probing for more
 *   headroom one step at a time;
 * - when a full window's failure rate reaches the threshold, the limit is
 *   cut multiplicatively (`×decreaseFactor`) — backing off fast from a
 *   sick downstream;
 * - the limit is always clamped to `[minLimit, maxLimit]`.
 *
 * Failure accounting follows the same convention as the circuit breaker,
 * the adaptive backoff (WR-59), failover, and weighted dispatch: a
 * retryable failure (429/5xx/timeout/DNS — anything `classifyFailure`
 * marks `"retryable"`) heats the controller; a success — including a
 * downstream that answered with a *non-retryable* rejection (the endpoint
 * is healthy, the payload was not) — cools it. WR-30 4xx semantic
 * rejections are therefore never counted as congestion signals.
 *
 * Composition:
 * - WR-06 fixed cap: the effective per-endpoint limit is
 *   `min(fixed, adaptive)` — the adaptive limit can only ever tighten the
 *   fixed cap, never exceed it.
 * - WR-59 adaptive backoff: orthogonal — backoff tunes *delay*, AIMD tunes
 *   *concurrency*; both read the same outcome stream.
 * - Urgent lane: bypasses the per-endpoint limiter like the fixed cap, so
 *   its outcomes still feed the controller (a sick downstream is a sick
 *   downstream) but its dispatch is not gated by it.
 *
 * Disabled by default (backward compatible): the queue only consults the
 * controller when `adaptiveConcurrency` is configured.
 */

/** Floor for the adaptive limit: it never drops below this. */
export const DEFAULT_ADAPTIVE_MIN_LIMIT = 1;
/** Additive increase per healthy window. */
export const DEFAULT_ADAPTIVE_INCREASE_STEP = 1;
/** Multiplicative decrease factor applied per congested window. */
export const DEFAULT_ADAPTIVE_DECREASE_FACTOR = 0.5;
/** Failure rate in a full window that marks the endpoint congested. */
export const DEFAULT_ADAPTIVE_FAILURE_RATE_THRESHOLD = 0.2;
/** Recent outcomes evaluated per adjustment step. */
export const DEFAULT_ADAPTIVE_WINDOW_SIZE = 20;

/** Tuning for {@link AdaptiveConcurrencyController}. */
export interface AdaptiveConcurrencyOptions {
  /**
   * Floor for the adaptive limit. Default: 1. Must be a positive integer.
   */
  minLimit?: number;
  /**
   * Ceiling for the adaptive limit. Default: the queue's
   * `maxConcurrentPerEndpoint` (so the adaptive limit can never exceed the
   * fixed cap even without explicit configuration). Must be a positive
   * integer or `Infinity`, and >= `minLimit`.
   */
  maxLimit?: number;
  /**
   * The limit an endpoint starts with, before any outcome is recorded.
   * Default: `maxLimit` (behave like the fixed cap until congestion is
   * observed). Must be an integer in `[minLimit, maxLimit]`.
   */
  initialLimit?: number;
  /**
   * Additive increase applied per healthy window. Default: 1. Must be a
   * positive integer.
   */
  increaseStep?: number;
  /**
   * Multiplicative factor applied to the limit per congested window.
   * Default: 0.5. Must be in the open interval (0, 1).
   */
  decreaseFactor?: number;
  /**
   * Failure rate in a full window at or above which the endpoint counts
   * as congested. Default: 0.2. Must be in [0, 1].
   */
  failureRateThreshold?: number;
  /**
   * Recent outcomes per endpoint evaluated at each adjustment step.
   * Default: 20. Must be a positive integer.
   */
  windowSize?: number;
}

/** One endpoint's adaptive concurrency state. */
export interface AdaptiveConcurrencyEndpointStats {
  /** The endpoint (physical `targetUrl`) this row describes. */
  endpoint: string;
  /** Tenant id (WR-48); the queue adds it — absent for the default tenant. */
  tenant?: string;
  /** The endpoint's current adaptive concurrency limit. */
  limit: number;
  /** Outcomes recorded in the current (incomplete) window. */
  windowOutcomes: number;
  /** Failures among the current window's outcomes. */
  windowFailures: number;
  /** The window size one adjustment step evaluates. */
  windowSize: number;
}

function assertPositiveInteger(name: string, value: number | undefined, fallback: number): number {
  const v = value ?? fallback;
  if (!Number.isInteger(v) || v < 1) {
    throw new RangeError(`adaptiveConcurrency.${name} must be a positive integer, got ${value}`);
  }
  return v;
}

export function assertAdaptiveConcurrencyOptions(
  opts: AdaptiveConcurrencyOptions,
  /** Ceiling default when `maxLimit` is unset (the queue's fixed cap). */
  defaultMaxLimit: number
): {
  minLimit: number;
  maxLimit: number;
  initialLimit: number;
  increaseStep: number;
  decreaseFactor: number;
  failureRateThreshold: number;
  windowSize: number;
} {
  const minLimit = assertPositiveInteger("minLimit", opts.minLimit, DEFAULT_ADAPTIVE_MIN_LIMIT);
  let maxLimit = opts.maxLimit ?? defaultMaxLimit;
  if (maxLimit !== Infinity && (!Number.isInteger(maxLimit) || maxLimit < 1)) {
    throw new RangeError(
      `adaptiveConcurrency.maxLimit must be a positive integer or Infinity, got ${opts.maxLimit}`
    );
  }
  if (maxLimit < minLimit) {
    throw new RangeError(
      `adaptiveConcurrency.maxLimit (${maxLimit}) must be >= minLimit (${minLimit})`
    );
  }
  let initialLimit = opts.initialLimit ?? maxLimit;
  const initialOk =
    initialLimit === Infinity
      ? maxLimit === Infinity
      : Number.isInteger(initialLimit) && initialLimit >= minLimit && initialLimit <= maxLimit;
  if (!initialOk) {
    throw new RangeError(
      `adaptiveConcurrency.initialLimit must be an integer in [minLimit, maxLimit] ([${minLimit}, ${maxLimit}]), got ${opts.initialLimit}`
    );
  }
  const increaseStep = assertPositiveInteger(
    "increaseStep",
    opts.increaseStep,
    DEFAULT_ADAPTIVE_INCREASE_STEP
  );
  const decreaseFactor = opts.decreaseFactor ?? DEFAULT_ADAPTIVE_DECREASE_FACTOR;
  if (!Number.isFinite(decreaseFactor) || decreaseFactor <= 0 || decreaseFactor >= 1) {
    throw new RangeError(
      `adaptiveConcurrency.decreaseFactor must be in the open interval (0, 1), got ${opts.decreaseFactor}`
    );
  }
  const failureRateThreshold = opts.failureRateThreshold ?? DEFAULT_ADAPTIVE_FAILURE_RATE_THRESHOLD;
  if (
    !Number.isFinite(failureRateThreshold) ||
    failureRateThreshold < 0 ||
    failureRateThreshold > 1
  ) {
    throw new RangeError(
      `adaptiveConcurrency.failureRateThreshold must be in [0, 1], got ${opts.failureRateThreshold}`
    );
  }
  const windowSize = assertPositiveInteger(
    "windowSize",
    opts.windowSize,
    DEFAULT_ADAPTIVE_WINDOW_SIZE
  );
  return { minLimit, maxLimit, initialLimit, increaseStep, decreaseFactor, failureRateThreshold, windowSize };
}

/**
 * Per-endpoint adaptive concurrency controller (WR-94).
 *
 * Pure outcome bookkeeping: `recordOutcome` moves the limit, `limitFor`
 * reads it, `stats` snapshots it. No clock, no randomness — the same
 * outcome sequence always yields the same limits, so tests are
 * deterministic by construction.
 */
export class AdaptiveConcurrencyController {
  private readonly minLimit: number;
  private readonly maxLimit: number;
  private readonly increaseStep: number;
  private readonly decreaseFactor: number;
  private readonly failureRateThreshold: number;
  private readonly windowSize: number;
  private readonly initialLimit: number;
  private readonly limits = new Map<string, number>();
  /** Recent outcomes per endpoint: `true` = success, `false` = failure. */
  private readonly windows = new Map<string, boolean[]>();

  constructor(opts: AdaptiveConcurrencyOptions = {}, defaultMaxLimit: number = Infinity) {
    const cfg = assertAdaptiveConcurrencyOptions(opts, defaultMaxLimit);
    this.minLimit = cfg.minLimit;
    this.maxLimit = cfg.maxLimit;
    this.initialLimit = cfg.initialLimit;
    this.increaseStep = cfg.increaseStep;
    this.decreaseFactor = cfg.decreaseFactor;
    this.failureRateThreshold = cfg.failureRateThreshold;
    this.windowSize = cfg.windowSize;
  }

  /**
   * Feed one delivery outcome for `endpoint` into the controller. The
   * failure convention matches the circuit breaker and WR-59: retryable
   * failures (429/5xx/timeout) heat the controller; successes — including
   * non-retryable downstream rejections (an answering endpoint is a
   * healthy endpoint) — cool it.
   */
  recordOutcome(endpoint: string, success: boolean): void {
    let window = this.windows.get(endpoint);
    if (window === undefined) {
      window = [];
      this.windows.set(endpoint, window);
    }
    window.push(success);
    if (window.length < this.windowSize) return;
    // A full window triggers exactly one adjustment step, then clears —
    // the same failures must never punish the limit twice.
    const failures = window.reduce((n, ok) => n + (ok ? 0 : 1), 0);
    const failureRate = failures / window.length;
    window.length = 0;
    let limit = this.limits.get(endpoint) ?? this.initialLimit;
    if (failureRate >= this.failureRateThreshold) {
      limit = Math.max(this.minLimit, Math.floor(limit * this.decreaseFactor));
    } else {
      limit = Math.min(this.maxLimit, limit + this.increaseStep);
    }
    this.limits.set(endpoint, limit);
  }

  /**
   * The endpoint's current adaptive concurrency limit — the adapted limit,
   * or the initial limit when no full outcome window has been evaluated
   * yet.
   */
  limitFor(endpoint: string): number {
    return this.limits.get(endpoint) ?? this.initialLimit;
  }

  /** Forget an endpoint's adapted state (`undefined` = all endpoints). */
  reset(endpoint?: string): void {
    if (endpoint === undefined) {
      this.limits.clear();
      this.windows.clear();
      return;
    }
    this.limits.delete(endpoint);
    this.windows.delete(endpoint);
  }

  /**
   * One row per endpoint with at least one recorded outcome. Endpoints
   * that never reported an outcome are absent — they use the initial
   * limit (see {@link limitFor}).
   */
  stats(): AdaptiveConcurrencyEndpointStats[] {
    const rows: AdaptiveConcurrencyEndpointStats[] = [];
    for (const [endpoint, window] of this.windows) {
      rows.push({
        endpoint,
        limit: this.limits.get(endpoint) ?? this.initialLimit,
        windowOutcomes: window.length,
        windowFailures: window.reduce((n, ok) => n + (ok ? 0 : 1), 0),
        windowSize: this.windowSize,
      });
    }
    return rows;
  }
}
