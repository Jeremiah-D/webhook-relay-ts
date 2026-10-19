/**
 * Endpoint auto-disable (WR-150).
 *
 * The circuit breaker (WR-10) is transient fault handling: it sheds load
 * for a cooldown, then probes back. Auto-disable is the human-intervention
 * gate sitting one level above it — when an endpoint fails
 * `failureThreshold` consecutive deliveries, the relay concludes the
 * downstream is not coming back on its own and *disables* the endpoint:
 *
 * - New deliveries to a disabled endpoint dead-letter immediately with
 *   `failureClass: "endpoint_disabled"` — no attempt is made, no retry
 *   budget is burned, no backoff is scheduled. They are terminal, not
 *   parked (compare the WR-50 pause, which holds deliveries for a later
 *   resume).
 * - The endpoint stays disabled until an operator re-enables it
 *   (`RetryQueue.enableEndpoint`, `POST /endpoints/enable`). Successes
 *   cannot clear it, because a disabled endpoint is never attempted.
 *   The re-enable resets the failure streak, like the WR-100 resume
 *   restarting the idle clock.
 *
 * Orthogonality with the breaker is structural, not just documented:
 * the breaker records its own consecutive-failure streak and trips on its
 * own thresholds; this tracker keeps a *separate* streak fed from the
 * same leader-only failure verdicts. A breaker opening and closing does
 * not touch the disable streak, and a disable does not open the breaker.
 * Both stay off when their options are unset — the queue constructs this
 * tracker only when `endpointAutoDisable` is configured, so an unset
 * option is byte-identical to the pre-WR-150 behavior (zero behavior
 * change, zero hot-path cost beyond one undefined check).
 *
 * The failure window is optional: `windowMs` bounds how far back a
 * failure counts toward the streak. The default (`Infinity`) is pure
 * consecutive-failures — any success resets. A finite window additionally
 * prunes failures older than the window, so a slow drip of failures can
 * never disable an endpoint that mostly works.
 *
 * Zero dependencies (pure data + validation).
 */

/** Options for {@link EndpointAutoDisable}. */
export interface EndpointAutoDisableOptions {
  /**
   * Consecutive delivery failures that auto-disable the endpoint.
   * Default: 5. Must be an integer >= 1.
   */
  failureThreshold?: number;
  /**
   * Rolling window (ms) a failure counts toward the streak. Failures
   * older than the window are pruned before the threshold is checked.
   * Default: `Infinity` (pure consecutive-failures). Must be a finite
   * number > 0, or `Infinity`.
   */
  windowMs?: number;
  /** Clock source; defaults to Date.now. Injectable for tests. */
  nowMs?: () => number;
}

/** Observable snapshot of one endpoint's auto-disable state. */
export interface EndpointDisableStatsRow {
  /** The endpoint (physical `targetUrl` that earned the verdicts). */
  endpoint: string;
  /** Whether the endpoint is currently auto-disabled. */
  disabled: boolean;
  /** Consecutive failures since the last success (0 once reset). */
  consecutiveFailures: number;
  /** ms epoch when the endpoint was last auto-disabled; absent when never disabled. */
  disabledAtMs?: number;
  /** Total auto-disable transitions since construction. */
  autoDisables: number;
  /** ms epoch of the last recorded failure; absent when the endpoint never failed. */
  lastFailureAtMs?: number;
}

/** Outcome of one {@link EndpointAutoDisable.recordFailure} call. */
export interface DisableFailureOutcome {
  /** True when this failure newly disabled the endpoint (edge-triggered). */
  disabled: boolean;
  /** Consecutive failures after recording this one. */
  consecutiveFailures: number;
  /** Effective failure threshold. */
  failureThreshold: number;
}

function describeValue(value: unknown): string {
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" || typeof value === "boolean" || value === null) {
    return String(value);
  }
  return typeof value;
}

function assertValidEndpoint(endpoint: unknown, method: string): asserts endpoint is string {
  if (typeof endpoint !== "string" || endpoint.length === 0) {
    throw new RangeError(`${method}: endpoint must be a non-empty string`);
  }
}

function assertValidThreshold(failureThreshold: unknown): asserts failureThreshold is number {
  if (
    !(typeof failureThreshold === "number" && Number.isInteger(failureThreshold) && failureThreshold >= 1)
  ) {
    throw new RangeError(
      `endpoint auto-disable: \`failureThreshold\` must be an integer >= 1, got ${describeValue(failureThreshold)}`
    );
  }
}

function assertValidWindowMs(windowMs: unknown): asserts windowMs is number {
  if (
    !(
      typeof windowMs === "number" &&
      (windowMs === Infinity || (Number.isFinite(windowMs) && windowMs > 0))
    )
  ) {
    throw new RangeError(
      `endpoint auto-disable: \`windowMs\` must be a finite number > 0 or Infinity, got ${describeValue(windowMs)}`
    );
  }
}

interface FailureStreak {
  /** Failure timestamps inside the window (empty when the window is infinite — the count alone suffices). */
  failures: number[];
  /** Consecutive failures since the last success. */
  count: number;
}

/**
 * Per-endpoint consecutive-failure tracker with a disable gate.
 *
 * Feed it the same leader-only verdicts the circuit breaker gets (one
 * physical attempt, one verdict): `recordSuccess` on a delivered attempt
 * or an answering downstream (the non-retryable path), `recordFailure`
 * on a retryable failure. Query `isDisabled` on the dispatch path.
 */
export class EndpointAutoDisable {
  private readonly failureThreshold: number;
  private readonly windowMs: number;
  private readonly nowMs: () => number;
  private readonly streaks = new Map<string, FailureStreak>();
  private readonly disabledAt = new Map<string, number>();
  private readonly autoDisableCounts = new Map<string, number>();
  private readonly lastFailureAt = new Map<string, number>();

  constructor(opts: EndpointAutoDisableOptions = {}) {
    const failureThreshold = opts.failureThreshold ?? 5;
    const windowMs = opts.windowMs ?? Infinity;
    assertValidThreshold(failureThreshold);
    assertValidWindowMs(windowMs);
    if (opts.nowMs !== undefined && typeof opts.nowMs !== "function") {
      throw new RangeError(
        `endpoint auto-disable: \`nowMs\` must be a function, got ${describeValue(opts.nowMs)}`
      );
    }
    this.failureThreshold = failureThreshold;
    this.windowMs = windowMs;
    this.nowMs = opts.nowMs ?? Date.now;
  }

  /** Effective failure threshold (constructor default or override). */
  get threshold(): number {
    return this.failureThreshold;
  }

  private streakFor(endpoint: string): FailureStreak {
    let streak = this.streaks.get(endpoint);
    if (streak === undefined) {
      streak = { failures: [], count: 0 };
      this.streaks.set(endpoint, streak);
    }
    return streak;
  }

  private prune(streak: FailureStreak, now: number): void {
    if (this.windowMs === Infinity) return;
    const cutoff = now - this.windowMs;
    while (streak.failures.length > 0 && streak.failures[0]! <= cutoff) {
      streak.failures.shift();
    }
    streak.count = streak.failures.length;
  }

  /**
   * Record a delivered attempt (or an answering downstream — the
   * non-retryable verdict). Resets the consecutive-failure streak. A
   * no-op on the disabled gate itself: a disabled endpoint is never
   * attempted, so only an operator re-enable clears it.
   */
  recordSuccess(endpoint: string): void {
    assertValidEndpoint(endpoint, "recordSuccess");
    if (this.disabledAt.has(endpoint)) return;
    const streak = this.streaks.get(endpoint);
    if (streak === undefined) return;
    streak.failures = [];
    streak.count = 0;
  }

  /**
   * Record a retryable delivery failure. Returns the outcome — when
   * `disabled` is true the caller must treat the endpoint as disabled
   * from here on (dead-letter new deliveries, audit the transition).
   * Edge-triggered: failures past the threshold do not re-fire.
   */
  recordFailure(endpoint: string): DisableFailureOutcome {
    assertValidEndpoint(endpoint, "recordFailure");
    const now = this.nowMs();
    const streak = this.streakFor(endpoint);
    this.prune(streak, now);
    if (this.windowMs === Infinity) {
      streak.count += 1;
    } else {
      streak.failures.push(now);
      streak.count = streak.failures.length;
    }
    this.lastFailureAt.set(endpoint, now);
    if (streak.count >= this.failureThreshold && !this.disabledAt.has(endpoint)) {
      this.disabledAt.set(endpoint, now);
      this.autoDisableCounts.set(endpoint, (this.autoDisableCounts.get(endpoint) ?? 0) + 1);
      return { disabled: true, consecutiveFailures: streak.count, failureThreshold: this.failureThreshold };
    }
    return { disabled: false, consecutiveFailures: streak.count, failureThreshold: this.failureThreshold };
  }

  /** True when the endpoint is currently auto-disabled. */
  isDisabled(endpoint: string): boolean {
    assertValidEndpoint(endpoint, "isDisabled");
    return this.disabledAt.has(endpoint);
  }

  /** Consecutive failures since the last success (0 once reset). */
  consecutiveFailures(endpoint: string): number {
    assertValidEndpoint(endpoint, "consecutiveFailures");
    const streak = this.streaks.get(endpoint);
    if (streak === undefined) return 0;
    this.prune(streak, this.nowMs());
    return streak.count;
  }

  /**
   * Operator re-enable: clears the disabled gate and resets the failure
   * streak (the operator's attention is a fresh start, like the WR-100
   * resume restarting the idle clock). Idempotent: re-enabling a
   * non-disabled endpoint is a no-op returning `false`. Returns `true`
   * on a real transition.
   */
  enable(endpoint: string): boolean {
    assertValidEndpoint(endpoint, "enable");
    if (!this.disabledAt.delete(endpoint)) return false;
    const streak = this.streaks.get(endpoint);
    if (streak !== undefined) {
      streak.failures = [];
      streak.count = 0;
    }
    return true;
  }

  /** Snapshot rows for every endpoint that has recorded a verdict, in first-seen order. */
  getStats(): EndpointDisableStatsRow[] {
    const rows: EndpointDisableStatsRow[] = [];
    for (const [endpoint, streak] of this.streaks) {
      this.prune(streak, this.nowMs());
      rows.push({
        endpoint,
        disabled: this.disabledAt.has(endpoint),
        consecutiveFailures: streak.count,
        ...(this.disabledAt.get(endpoint) === undefined
          ? {}
          : { disabledAtMs: this.disabledAt.get(endpoint)! }),
        autoDisables: this.autoDisableCounts.get(endpoint) ?? 0,
        ...(this.lastFailureAt.get(endpoint) === undefined
          ? {}
          : { lastFailureAtMs: this.lastFailureAt.get(endpoint)! }),
      });
    }
    return rows;
  }
}
