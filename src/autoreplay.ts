import type { DeadLetterBatchReplayResult } from "./retry.ts";

/**
 * A timer handle matching the shape {@link RetryQueue} uses for its
 * injectable scheduler (`setTimer` / `clearTimer` in `src/retry.ts`).
 */
export interface ReplayTimerHandle {
  clear(): void;
}

/** Opt-in dead-letter auto-replay tuning, embedded in {@link RetryQueueOptions}. */
export interface AutoReplayOptions {
  /**
   * Master switch; default `false`. The scheduler is strictly opt-in so
   * existing embeddings keep their exact current behavior: nothing is ever
   * replayed automatically unless the operator asks for it.
   */
  enabled?: boolean;
  /**
   * Base interval in ms between rounds; default 60_000. The actual wait
   * before a round is `min(intervalMs * 2^consecutiveEmptyRounds,
   * maxIntervalMs)`. Must be a finite number > 0.
   */
  intervalMs?: number;
  /**
   * How many *consecutive* rounds with zero successfully replayed items the
   * scheduler tolerates before stopping permanently; default 10. Any round
   * that replays >= 1 item resets the counter to 0. Must be an integer
   * >= 1. Reaching it emits the `dead_letter_auto_replay` audit event and
   * stops the schedule until an operator resumes or reconfigures it.
   */
  maxRounds?: number;
  /**
   * Cap in ms for the exponential backoff wait between rounds; default
   * 3_600_000 (1h). Must be finite, > 0, and >= `intervalMs`.
   */
  maxIntervalMs?: number;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
  /**
   * Scheduler factory; defaults to an unref'd real `setTimeout` so a
   * scheduled round never pins the process open. Injectable so tests can
   * drive rounds deterministically.
   */
  setTimer?: (fn: () => void, ms: number) => ReplayTimerHandle;
  clearTimer?: (handle: ReplayTimerHandle) => void;
}

/**
 * WR-344: partial live revision of the auto-replay schedule cadence —
 * the three round-rhythm inputs (`intervalMs` / `maxRounds` /
 * `maxIntervalMs`). Omitted fields keep their live values; `enabled`
 * is deliberately absent — enabling/disabling still needs a restart.
 */
export interface AutoReplayScheduleRevision {
  /** Base interval in ms between rounds; must be a finite number > 0. */
  intervalMs?: number;
  /** Consecutive empty rounds tolerated before stopping; integer >= 1. */
  maxRounds?: number;
  /** Cap in ms for the exponential backoff wait; finite, > 0, >= `intervalMs`. */
  maxIntervalMs?: number;
}

/**
 * WR-344: the three live cadence inputs of the auto-replay schedule,
 * all required — the snapshot `DeadLetterAutoReplayer.config()` returns
 * and `retune()` accepts partial patches of.
 */
export interface AutoReplayScheduleConfig {
  intervalMs: number;
  maxRounds: number;
  maxIntervalMs: number;
}

/** Round outcome reported by {@link DeadLetterAutoReplayer.triggerOnce}. */
export interface AutoReplayRoundResult {
  /** Ids re-queued with a fresh attempt budget this round. */
  replayed: string[];
  /** Entries that could not be re-queued; they stay dead-lettered. */
  failed: DeadLetterBatchReplayResult["failed"];
  /**
   * Ids held back by the WR-68 replay egress throttle this round (still
   * in the dead-letter list; nothing dropped). A round that only
   * throttled counts as progress for the empty-round accounting — the
   * backlog is being worked, not poison.
   */
  throttled: string[];
  /** Consecutive empty rounds *after* accounting this round. */
  consecutiveEmptyRounds: number;
  /** Whether the scheduler stopped permanently as a result of this round. */
  stopped: boolean;
}

/** Payload of the `dead_letter_auto_replay` audit event. */
export interface DeadLetterAutoReplayAuditEvent {
  event: "dead_letter_auto_replay";
  /** Why the scheduler stopped; today the only stop reason. */
  reason: "rounds_exhausted";
  /** Consecutive empty rounds that triggered the stop (=== `maxRounds`). */
  consecutiveEmptyRounds: number;
  /** Total items the scheduler successfully replayed before stopping. */
  totalReplayed: number;
  /** ISO-8601 timestamp of the round that triggered the stop. */
  lastRunAt: string;
}

/**
 * The constructor's three validation gates, shared with `retune()` so a
 * live revision is checked against exactly the same rules as the
 * construction values: `intervalMs` finite > 0, `maxRounds` an integer
 * >= 1, `maxIntervalMs` finite > 0 and >= `intervalMs`.
 */
function assertAutoReplaySchedule(intervalMs: number, maxRounds: number, maxIntervalMs: number): void {
  if (!Number.isFinite(intervalMs) || intervalMs <= 0) {
    throw new RangeError(`autoReplay.intervalMs must be a finite number > 0, got ${intervalMs}`);
  }
  if (!Number.isInteger(maxRounds) || maxRounds < 1) {
    throw new RangeError(`autoReplay.maxRounds must be an integer >= 1, got ${maxRounds}`);
  }
  if (!Number.isFinite(maxIntervalMs) || maxIntervalMs <= 0 || maxIntervalMs < intervalMs) {
    throw new RangeError(
      `autoReplay.maxIntervalMs must be a finite number > 0 and >= intervalMs (${intervalMs}), got ${maxIntervalMs}`
    );
  }
}

/**
 * Dead-letter auto-replay scheduler (WR-31).
 *
 * Opt-in timed replays of the dead-letter list: each round calls the same
 * batch replay an operator would invoke by hand (`POST
 * /dead-letter/replay` with no filter), so the *fresh-budget semantics are
 * identical to a manual replay* — a replayed entry re-enters the queue
 * with its attempt counter reset to 0 and walks the normal delivery path
 * (exponential backoff, circuit breaker, quota, downstream `Retry-After`
 * honoring). A replayed item that delivers leaves the dead letter for
 * good; a replayed item that fails again walks back into the dead letter
 * through the normal path. The scheduler never replays anything twice per
 * round and never invents its own delivery semantics.
 *
 * **Rounds counting.** `maxRounds` counts *consecutive* rounds that replay
 * zero items successfully. Entries that fail to re-queue (`failed`) do not
 * count as successes — a poison backlog keeps counting as empty. Any
 * round with >= 1 successfully replayed item resets the counter to 0.
 * Reaching `maxRounds` stops the scheduler *permanently* (no further
 * rounds, scheduled or otherwise) and emits the `dead_letter_auto_replay`
 * audit event — the operator resumes explicitly (`resume()` / the
 * `/dead-letter/auto-replay/resume` endpoint), which resets the counter
 * and restarts the schedule.
 *
 * **Backoff.** The wait before the next round is
 * `min(intervalMs * 2^consecutiveEmptyRounds, maxIntervalMs)`: a healthy
 * backlog that keeps replaying successfully stays on the base interval,
 * while a persistently empty (or poison-only) dead letter backs off
 * exponentially so the scheduler does not spin on nothing.
 *
 * **Manual control.** `triggerOnce()` runs one round immediately, outside
 * the schedule — a paused scheduler stays paused, and a stopped
 * (rounds-exhausted) scheduler ignores it; otherwise it goes through the
 * exact same accounting as a scheduled round (an empty trigger increments
 * the counter, a successful one resets it, and it can itself trigger the
 * exhaustion stop). `pause()` freezes the schedule with all state
 * retained; `resume()` continues where it left off.
 *
 * **Timer hygiene.** The timer is unref'd by default, so a configured but
 * idle scheduler never keeps the process alive; `stop()` clears any
 * pending timer and is wired into `RetryQueue.stop()` / `shutdown()`.
 */
export class DeadLetterAutoReplayer {
  private readonly enabled: boolean;
  /** WR-344: live-revisable via `retune()` — `enabled` stays readonly. */
  private intervalMs: number;
  private maxRounds: number;
  private maxIntervalMs: number;
  private readonly now: () => number;
  private readonly setTimer: (fn: () => void, ms: number) => ReplayTimerHandle;
  private readonly clearTimer: (handle: ReplayTimerHandle) => void;
  private readonly replayAll: () => DeadLetterBatchReplayResult;
  // WR-411: live-revisable via `reviseAuditCallback()` (the queue's
  // `reviseAutoReplayAuditCallback` delegates here), so this is
  // deliberately not `readonly` — swapping the observer never touches
  // the round cadence, the counters, the `stopped` latch, or `retune`.
  private onAudit?: (event: DeadLetterAutoReplayAuditEvent) => void;

  private running = false;
  private paused = false;
  /** Set when `maxRounds` consecutive empty rounds exhausted the budget. */
  private stopped = false;
  private consecutiveEmptyRounds = 0;
  private totalReplayed = 0;
  private lastRunAt?: string;
  private nextRunAt?: string;
  private timer?: ReplayTimerHandle;

  constructor(
    opts: AutoReplayOptions & {
      /** Replays every dead letter with fresh-budget semantics; provided by the owner. */
      replayAll: () => DeadLetterBatchReplayResult;
      /** Called once when the scheduler stops on rounds exhaustion. */
      onAudit?: (event: DeadLetterAutoReplayAuditEvent) => void;
    }
  ) {
    this.enabled = opts.enabled ?? false;
    this.intervalMs = opts.intervalMs ?? 60_000;
    this.maxRounds = opts.maxRounds ?? 10;
    this.maxIntervalMs = opts.maxIntervalMs ?? 3_600_000;
    this.now = opts.now ?? Date.now;
    assertAutoReplaySchedule(this.intervalMs, this.maxRounds, this.maxIntervalMs);
    this.setTimer =
      opts.setTimer ??
      ((fn, ms) => {
        // Unref'd: a configured scheduler must never pin the process open
        // just because a round is scheduled.
        const t = setTimeout(fn, ms);
        t.unref?.();
        return { clear: () => clearTimeout(t) };
      });
    this.clearTimer = opts.clearTimer ?? ((h) => h.clear());
    this.replayAll = opts.replayAll;
    this.onAudit = opts.onAudit;
  }

  /** Whether the scheduler was constructed with `enabled: true`. */
  isEnabled(): boolean {
    return this.enabled;
  }

  /** Whether the schedule is currently ticking (started, not paused/stopped). */
  isRunning(): boolean {
    return this.running && !this.paused && !this.stopped;
  }

  /**
   * WR-344: live revision of the schedule cadence (partial — omitted
   * fields keep their live values). The merged values are re-validated
   * with the constructor's same three gates, so an illegal patch
   * throws `RangeError` and the live values — and the pending timer —
   * are completely untouched; an empty patch is a `RangeError`, as is a
   * non-object patch. Revising to the live values is a silent no-op
   * (no re-arm, no audit). A real revision re-arms a running
   * scheduler's pending timer on the new cadence — the wait recomputes
   * from the new values and the current `consecutiveEmptyRounds`, and
   * `nextRunAt` updates — while a round already in flight finishes
   * against the `maxRounds` it started with. A paused scheduler only
   * stores the values (`resume()` arms on them); a rounds-exhausted
   * scheduler only stores them too (`resume()` resets the counters,
   * then arms on the new values). `consecutiveEmptyRounds`,
   * `totalReplayed`, `stopped`, and `lastRunAt` are never reset or
   * recomputed here, and the `now` / `setTimer` / `clearTimer`
   * injections are never revised. Returns the live config.
   */
  retune(patch: AutoReplayScheduleRevision): AutoReplayScheduleConfig {
    if (patch === null || typeof patch !== "object" || Array.isArray(patch)) {
      throw new RangeError(`autoReplay schedule revision must be an object, got ${JSON.stringify(patch)}`);
    }
    if (patch.intervalMs === undefined && patch.maxRounds === undefined && patch.maxIntervalMs === undefined) {
      throw new RangeError(
        "autoReplay schedule revision must set at least one of intervalMs, maxRounds, maxIntervalMs"
      );
    }
    const intervalMs = patch.intervalMs ?? this.intervalMs;
    const maxRounds = patch.maxRounds ?? this.maxRounds;
    const maxIntervalMs = patch.maxIntervalMs ?? this.maxIntervalMs;
    // Validate-then-apply: an illegal patch leaves the live values — and
    // the pending timer — completely untouched.
    assertAutoReplaySchedule(intervalMs, maxRounds, maxIntervalMs);
    if (
      intervalMs === this.intervalMs &&
      maxRounds === this.maxRounds &&
      maxIntervalMs === this.maxIntervalMs
    ) {
      return this.config();
    }
    this.intervalMs = intervalMs;
    this.maxRounds = maxRounds;
    this.maxIntervalMs = maxIntervalMs;
    // Re-arm the pending timer on the new cadence when running;
    // scheduleNext() is a no-op for a paused, stopped, or not-yet-started
    // scheduler, which is exactly the values-only behavior those want.
    this.scheduleNext();
    return this.config();
  }

  /**
   * WR-411: live-redirect the rounds-exhaustion audit observer. The new
   * callback takes effect from the next exhaustion stop; a stop already
   * reported is never re-emitted, and the round cadence, the counters
   * (`consecutiveEmptyRounds`, `totalReplayed`), the `stopped` latch,
   * and `retune` are untouched — only the observation moves. `null`
   * clears back to no observer (the scheduler still stops on rounds
   * exhaustion — only the forwarding stops). A
   * non-function value throws `RangeError` and the live callback is
   * untouched; replacing with the same reference (or clearing when
   * already unset) is a silent no-op.
   */
  reviseAuditCallback(cb: ((event: DeadLetterAutoReplayAuditEvent) => void) | null): void {
    if (cb !== null && typeof cb !== "function") {
      throw new RangeError("reviseAuditCallback: handler must be a function or null");
    }
    const next = cb ?? undefined;
    if (next === this.onAudit) return;
    this.onAudit = next;
  }

  /**
   * WR-344: snapshot of the live schedule cadence — a fresh object,
   * never a live reference, so mutating the return cannot move the
   * scheduler.
   */
  config(): AutoReplayScheduleConfig {
    return {
      intervalMs: this.intervalMs,
      maxRounds: this.maxRounds,
      maxIntervalMs: this.maxIntervalMs,
    };
  }

  /** Start the schedule. Idempotent; a no-op when disabled. */
  start(): void {
    if (!this.enabled || this.running) return;
    this.running = true;
    this.scheduleNext();
  }

  /**
   * Permanent stop: clears any pending timer and ends the schedule. The
   * scheduler only runs again after `resume()` (which also resets the
   * rounds counter, for the rounds-exhausted case) or `start()` after a
   * reconfiguration.
   */
  stop(): void {
    this.clearPending();
    this.running = false;
  }

  /**
   * Freeze the schedule with all state retained: pending rounds stop, but
   * `consecutiveEmptyRounds`, `totalReplayed`, and `stopped` are kept, so a
   * later `resume()` continues exactly where it left off.
   */
  pause(): void {
    this.paused = true;
    this.clearPending();
    this.nextRunAt = undefined;
  }

  /**
   * Resume after `pause()` (counters continue) or after a rounds-exhausted
   * stop (the counter resets to 0 and the schedule restarts — the
   * operator's explicit "try again" signal). Returns whether the scheduler
   * was restarted from an exhausted stop.
   */
  resume(): { restarted: boolean } {
    const restarted = this.stopped;
    this.paused = false;
    if (this.stopped) {
      this.stopped = false;
      this.consecutiveEmptyRounds = 0;
    }
    if (this.enabled) {
      this.running = true;
      this.scheduleNext();
    }
    return { restarted };
  }

  /**
   * Run one round immediately, outside the schedule. It goes through the
   * same accounting as a scheduled round: an empty round increments
   * `consecutiveEmptyRounds`, a round replaying >= 1 item resets it to 0,
   * and it can itself trigger the rounds-exhausted stop. A paused
   * scheduler stays paused (only this round runs); a stopped
   * (rounds-exhausted) or disabled scheduler ignores the call.
   */
  triggerOnce(): AutoReplayRoundResult {
    if (!this.enabled || this.stopped) {
      return {
        replayed: [],
        failed: [],
        throttled: [],
        consecutiveEmptyRounds: this.consecutiveEmptyRounds,
        stopped: this.stopped,
      };
    }
    // The trigger replaces the pending scheduled round: run it now, then
    // reschedule from the post-round counter.
    this.clearPending();
    return this.doRound();
  }

  /** Observability snapshot for the operator status endpoint. */
  status(): {
    enabled: boolean;
    paused: boolean;
    stopped: boolean;
    consecutiveEmptyRounds: number;
    totalReplayed: number;
    lastRunAt: string | null;
    nextRunAt: string | null;
  } {
    return {
      enabled: this.enabled,
      paused: this.paused,
      stopped: this.stopped,
      consecutiveEmptyRounds: this.consecutiveEmptyRounds,
      totalReplayed: this.totalReplayed,
      lastRunAt: this.lastRunAt ?? null,
      nextRunAt: this.nextRunAt ?? null,
    };
  }

  /** Wait before the next round, given the current empty-rounds count. */
  private nextWaitMs(): number {
    return Math.min(this.intervalMs * 2 ** this.consecutiveEmptyRounds, this.maxIntervalMs);
  }

  private clearPending(): void {
    if (this.timer) {
      this.clearTimer(this.timer);
      this.timer = undefined;
    }
    this.nextRunAt = undefined;
  }

  private scheduleNext(): void {
    this.clearPending();
    if (!this.enabled || !this.running || this.paused || this.stopped) return;
    const wait = this.nextWaitMs();
    this.nextRunAt = new Date(this.now() + wait).toISOString();
    this.timer = this.setTimer(() => {
      this.timer = undefined;
      this.doRound();
    }, wait);
  }

  /**
   * One round: replay the whole dead letter with the same fresh-budget
   * semantics as a manual `replayDeadLetters()` call, then account it.
   */
  private doRound(): AutoReplayRoundResult {
    // WR-344: the exhaustion verdict belongs to the round as triggered —
    // a retune landing mid-round must not re-judge it against the new
    // budget; the next round reads the revised value.
    const maxRounds = this.maxRounds;
    let replayed: string[] = [];
    let failed: DeadLetterBatchReplayResult["failed"] = [];
    let throttled: string[] = [];
    try {
      const result = this.replayAll();
      replayed = result.replayed;
      failed = result.failed;
      throttled = result.throttled ?? [];
    } catch {
      // A replay-layer throw must not kill the scheduler: it counts as an
      // empty round, exactly like a round where every entry failed to
      // re-queue. (replayDeadLetters itself never throws for per-entry
      // failures; this is a last-resort guard.)
    }
    this.totalReplayed += replayed.length;
    this.lastRunAt = new Date(this.now()).toISOString();
    // WR-68: a round that only throttled entries counts as progress — the
    // egress gate paced the backlog, nothing poisoned it — so it resets
    // the empty-round counter like any round that moved work.
    if (replayed.length > 0 || throttled.length > 0) {
      this.consecutiveEmptyRounds = 0;
    } else {
      this.consecutiveEmptyRounds += 1;
    }
    if (this.consecutiveEmptyRounds >= maxRounds) {
      this.stopped = true;
      this.clearPending();
      this.onAudit?.({
        event: "dead_letter_auto_replay",
        reason: "rounds_exhausted",
        consecutiveEmptyRounds: this.consecutiveEmptyRounds,
        totalReplayed: this.totalReplayed,
        lastRunAt: this.lastRunAt,
      });
    } else {
      this.scheduleNext();
    }
    return {
      replayed,
      failed,
      throttled,
      consecutiveEmptyRounds: this.consecutiveEmptyRounds,
      stopped: this.stopped,
    };
  }
}
