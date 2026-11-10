import type { ReplayTimerHandle } from "./autoreplay.ts";

/**
 * Stale-endpoint auto-pause (WR-100), embedded in {@link RetryQueueOptions}.
 *
 * Configuration rot is hygiene, not an outage: an endpoint that has seen
 * no successful delivery for `staleAfterDays` *and* has nothing pending
 * is auto-paused through the exact WR-50 operator-switch mechanism
 * (parking semantics, no retry-budget burn, no breaker verdict, no
 * dead-letter, in-flight untouched) and audited as `endpoint_auto_paused`.
 * The operator re-enables it with the ordinary `resumeEndpoint` /
 * `POST /endpoints/resume` path; resuming restarts the idle clock.
 *
 * Off by default — the option object must be present to arm the feature
 * (opt-in, same convention as the WR-52 delivery windows). Invalid
 * values throw `RangeError` at construction, never mid-sweep.
 */
export interface StalePauseOptions {
  /**
   * Idle days after which a quiet endpoint is auto-paused. "Idle" is
   * measured from the last *successful* delivery — a semantic
   * (validator-rejected) or non-retryable (4xx poison) outcome is not
   * success, see WR-30 — or, for an endpoint that never delivered, from
   * its first sighting. Resuming an endpoint restarts the clock from
   * the resume instant. Default 30. Must be a finite number > 0;
   * anything else throws `RangeError` at construction.
   */
  staleAfterDays?: number;
  /**
   * Interval in ms between staleness sweeps; default 60_000. The sweep
   * timer is unref'd, so an armed sweeper never pins the process open.
   * Must be a finite number > 0; anything else throws `RangeError` at
   * construction.
   */
  sweepIntervalMs?: number;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
  /**
   * Scheduler factory; defaults to an unref'd real `setTimeout` so an
   * armed sweep never pins the process open. Injectable so tests can
   * drive sweeps deterministically.
   */
  setTimer?: (fn: () => void, ms: number) => ReplayTimerHandle;
  clearTimer?: (handle: ReplayTimerHandle) => void;
}

/** Payload of the `endpoint_auto_paused` audit event. */
export interface StaleEndpointPausedEvent {
  event: "endpoint_auto_paused";
  /**
   * The auto-paused endpoint (logical `targetUrl`). Pausing applies
   * across tenants — like a manual WR-50 pause — so there is no
   * per-tenant variant of this event.
   */
  endpoint: string;
  /** Whole idle days observed at trigger time (floored). */
  idleDays: number;
  /** The configured idle threshold that was crossed, in days. */
  staleAfterDays: number;
  /**
   * ISO-8601 instant of the last successful delivery. Absent when the
   * endpoint never delivered — then the idle window is measured from
   * its first sighting instead.
   */
  lastSuccessfulDeliveryAt?: string;
  /** ISO-8601 instant of the auto-pause transition. */
  at: string;
}

/** One endpoint auto-paused by a sweep. */
export interface StaleEndpointPausedInfo {
  endpoint: string;
  /** Idle ms observed at trigger time. */
  idleMs: number;
}

/** Outcome of {@link StalePauseSweeper.sweepNow}. */
export interface StalePauseSweepResult {
  /** Endpoints auto-paused this sweep, in sweep order. */
  paused: StaleEndpointPausedInfo[];
}

/**
 * The queue-side contract the sweeper needs. All state mutations stay in
 * the owning `RetryQueue`; the sweeper only decides *which* endpoints are
 * stale and calls back to pause/audit them.
 */
export interface StalePauseOwner {
  /** Every known logical endpoint (`targetUrl` as enqueued). */
  knownEndpoints(): string[];
  /**
   * The endpoint's idle baseline in ms — the last successful delivery,
   * or its first sighting when it never delivered, or the last resume
   * instant. `undefined` when the endpoint is unknown.
   */
  idleBaselineMs(endpoint: string): number | undefined;
  /**
   * Current pending (not-yet-terminal) delivery count for the endpoint,
   * across all tenants: queued, retrying, batch-buffered, and
   * deliver_at-parked items all count. An endpoint with anything pending
   * is never auto-paused — the pause must not strand work.
   */
  pendingCount(endpoint: string): number;
  /** Whether the endpoint is currently paused (manual or auto). */
  isPaused(endpoint: string): boolean;
  /**
   * Attempt the WR-50 auto-pause transition for a stale endpoint: same
   * parking mechanics as `pauseEndpoint`, composed with the
   * `endpoint_auto_paused` audit event (with `idleMs`), the cumulative
   * metric, and the `onAutoPaused` hook. Returns the composed audit
   * event on a real transition, `undefined` when the endpoint was
   * already paused (a manual hold wins; no double processing).
   */
  autoPauseStale(endpoint: string, idleMs: number): StaleEndpointPausedEvent | undefined;
}

/** Default idle days before auto-pause: 30. */
export const DEFAULT_STALE_AFTER_DAYS = 30;
/** Default sweep interval: 60 s. */
export const DEFAULT_STALE_SWEEP_INTERVAL_MS = 60_000;
/** Milliseconds in a day. */
export const MS_PER_DAY = 86_400_000;

/**
 * WR-378: a partial live revision of the two stale-pause knobs —
 * omitted fields keep their live values. `now`, the timer factory, and
 * the owner are never revisable: a retune carries them forward
 * untouched.
 */
export type StalePauseRevision = Partial<
  Pick<StalePauseOptions, "staleAfterDays" | "sweepIntervalMs">
>;

/** WR-378: the two live stale-pause knobs, all required. */
export interface StalePauseConfig {
  staleAfterDays: number;
  sweepIntervalMs: number;
}

function assertStaleAfterDays(value: unknown): asserts value is number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    throw new RangeError(`stalePause.staleAfterDays must be a finite number > 0, got ${String(value)}`);
  }
}

/**
 * Validate `staleAfterDays` and return it in ms. Throws `RangeError` on
 * any illegal value. `undefined` falls back to the 30-day default.
 */
export function resolveStaleAfterMs(staleAfterDays: StalePauseOptions["staleAfterDays"]): number {
  if (staleAfterDays === undefined) return DEFAULT_STALE_AFTER_DAYS * MS_PER_DAY;
  assertStaleAfterDays(staleAfterDays);
  return staleAfterDays * MS_PER_DAY;
}

/**
 * Stale-endpoint auto-pause sweeper (WR-100).
 *
 * Every `sweepIntervalMs` the sweeper scans the owner's known endpoints
 * and auto-pauses those whose idle baseline is at least `staleAfterMs`
 * in the past *and* that have nothing pending. Already-paused endpoints
 * are skipped outright — a manual operator hold is never re-processed
 * (and never re-audited) by the sweep.
 *
 * This is deliberately *not* the WR-10 circuit breaker: the breaker is
 * transient fault handling (fast fail, half-open recovery); auto-pause
 * is configuration-rot hygiene for endpoints that simply stopped
 * receiving successful traffic. Paused endpoints still accept inbound
 * events — they park in the durable queue, they are not discarded —
 * and resume through the ordinary WR-50 path.
 *
 * The sweep is purely additive: delivery, retry, breaker, and
 * dead-letter paths are untouched, and the transition reuses the exact
 * WR-50 parking semantics.
 */
export class StalePauseSweeper {
  // WR-378: not readonly — `retune()` moves the two knobs in place so
  // the threshold and the sweep cadence are live-revisable. `now`, the
  // timer factory, and the owner stay readonly: they are never revised.
  private staleAfterMs: number;
  private staleAfterDaysValue: number;
  private sweepIntervalMs: number;
  private readonly now: () => number;
  private readonly setTimer: (fn: () => void, ms: number) => ReplayTimerHandle;
  private readonly clearTimer: (handle: ReplayTimerHandle) => void;
  private readonly owner: StalePauseOwner;

  private started = false;
  private timer?: ReplayTimerHandle;

  constructor(opts: StalePauseOptions & { owner: StalePauseOwner }) {
    this.staleAfterMs = resolveStaleAfterMs(opts.staleAfterDays);
    this.staleAfterDaysValue = opts.staleAfterDays ?? DEFAULT_STALE_AFTER_DAYS;
    this.sweepIntervalMs = opts.sweepIntervalMs ?? DEFAULT_STALE_SWEEP_INTERVAL_MS;
    if (!Number.isFinite(this.sweepIntervalMs) || this.sweepIntervalMs <= 0) {
      throw new RangeError(
        `stalePause.sweepIntervalMs must be a finite number > 0, got ${String(opts.sweepIntervalMs)}`
      );
    }
    this.now = opts.now ?? Date.now;
    this.setTimer =
      opts.setTimer ??
      ((fn, ms) => {
        // Unref'd: an armed sweep must never pin the process open just
        // because stale-endpoint auto-pause is configured.
        const t = setTimeout(fn, ms);
        t.unref?.();
        return { clear: () => clearTimeout(t) };
      });
    this.clearTimer = opts.clearTimer ?? ((h) => h.clear());
    this.owner = opts.owner;
  }

  /** Whether the sweep schedule is currently armed. */
  isRunning(): boolean {
    return this.started && this.timer !== undefined;
  }

  /** Whether auto-pause is configured (the sweep can actually pause). */
  isEnabled(): boolean {
    return true;
  }

  /** The configured idle threshold in days (for audit/stats composition). */
  staleAfterDays(): number {
    return this.staleAfterDaysValue;
  }

  /**
   * WR-378: revise the two stale-pause knobs at runtime — no restart.
   * The patch must be a non-empty object; the merged values are
   * re-validated with the same two gates (and the same error text) as
   * construction, so an illegal patch throws `RangeError` and the live
   * values are left completely intact. Revising to the live values is
   * a silent no-op. Takes effect on the next `sweepNow()`: a tightened
   * threshold pauses endpoints already past the new threshold on the
   * next sweep, a widened one leaves them unpaused, and an already
   * paused endpoint is never resumed by a revision — resuming still
   * goes through the ordinary `resumeEndpoint` path. Revising
   * `sweepIntervalMs` while the sweeper is started clears the pending
   * timer and re-arms immediately at the new interval, so even a
   * timer already waiting is rescheduled; while stopped, the new
   * interval simply applies at the next `start()`. The idle baselines
   * (last success / first sighting / resume instant) are never
   * recomputed. Returns the live config.
   */
  retune(patch: StalePauseRevision): StalePauseConfig {
    if (patch === null || typeof patch !== "object" || Array.isArray(patch)) {
      throw new RangeError(`stalePause revision must be an object, got ${JSON.stringify(patch)}`);
    }
    if (Object.keys(patch).length === 0) {
      throw new RangeError("stalePause revision must not be empty");
    }
    // Validate-then-apply: both merged values must pass the
    // construction gates before any live value moves.
    const nextDays = patch.staleAfterDays ?? this.staleAfterDaysValue;
    const nextIntervalMs = patch.sweepIntervalMs ?? this.sweepIntervalMs;
    const nextStaleAfterMs = resolveStaleAfterMs(nextDays);
    if (!Number.isFinite(nextIntervalMs) || nextIntervalMs <= 0) {
      throw new RangeError(
        `stalePause.sweepIntervalMs must be a finite number > 0, got ${String(patch.sweepIntervalMs)}`
      );
    }
    if (nextDays === this.staleAfterDaysValue && nextIntervalMs === this.sweepIntervalMs) {
      return this.config();
    }
    const intervalChanged = nextIntervalMs !== this.sweepIntervalMs;
    this.staleAfterDaysValue = nextDays;
    this.staleAfterMs = nextStaleAfterMs;
    this.sweepIntervalMs = nextIntervalMs;
    if (intervalChanged && this.started) {
      // Clear the pending timer and re-arm at the new interval now —
      // otherwise the new cadence would only take effect after the
      // timer armed under the old interval fires.
      this.clearPending();
      this.arm();
    }
    return this.config();
  }

  /**
   * WR-378: the live two-knob config. A snapshot — mutating the
   * returned object never moves the sweeper.
   */
  config(): StalePauseConfig {
    return {
      staleAfterDays: this.staleAfterDaysValue,
      sweepIntervalMs: this.sweepIntervalMs,
    };
  }

  /** Arm the sweep schedule. Idempotent. */
  start(): void {
    if (this.started) return;
    this.started = true;
    this.arm();
  }

  /** Disarm the sweep schedule. Idempotent. */
  stop(): void {
    this.started = false;
    this.clearPending();
  }

  /**
   * Run one sweep immediately, outside the schedule: auto-pause every
   * known endpoint whose idle baseline is at least `staleAfterMs` in the
   * past and that has nothing pending, skipping already-paused
   * endpoints. Safe to call directly (tests, operator tooling) — it
   * does not disturb the armed schedule.
   */
  sweepNow(): StalePauseSweepResult {
    const paused: StaleEndpointPausedInfo[] = [];
    const nowMs = this.now();
    // Snapshot: autoPauseStale pauses the endpoint but never removes it
    // from the known set, so iteration is safe.
    for (const endpoint of this.owner.knownEndpoints()) {
      if (this.owner.isPaused(endpoint)) continue; // manual hold wins; never re-process
      const baseline = this.owner.idleBaselineMs(endpoint);
      if (baseline === undefined) continue;
      const idleMs = nowMs - baseline;
      if (idleMs < this.staleAfterMs) continue;
      if (this.owner.pendingCount(endpoint) > 0) continue; // work outstanding: never strand it
      const event = this.owner.autoPauseStale(endpoint, idleMs);
      if (event !== undefined) paused.push({ endpoint, idleMs });
    }
    return { paused };
  }

  private arm(): void {
    this.clearPending();
    if (!this.started) return;
    this.timer = this.setTimer(() => {
      this.timer = undefined;
      this.sweepNow();
      this.arm();
    }, this.sweepIntervalMs);
  }

  private clearPending(): void {
    if (this.timer) {
      this.clearTimer(this.timer);
      this.timer = undefined;
    }
  }
}
