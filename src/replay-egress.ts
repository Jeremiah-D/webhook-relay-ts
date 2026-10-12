/**
 * Dead-letter replay egress throttle (WR-68).
 *
 * A burst of dead-letter replays — manual (`replayDeadLetters`), operator
 * (`POST /dead-letter/replay`), or automatic (the WR-31 auto-replayer) — is
 * itself a traffic spike at the downstream: every replayed entry re-enters
 * the queue with a fresh attempt budget and immediately walks the normal
 * delivery path. This module puts one shared per-endpoint token bucket in
 * front of the *re-queue* step so a big backlog replays at a bounded rate
 * instead of stampeding the endpoint.
 *
 * Sharing matters: manual replays and the WR-31 auto-replayer both call
 * `RetryQueue.replayDeadLetters`, and the bucket lives on the queue, so
 * every replay path draws from the same per-endpoint budget — a manual
 * replay and an auto round running back to back cannot double-spend the
 * rate. `DeadLetterAutoReplayAuditEvent` round accounting treats a round
 * that only throttled entries as progress (not an empty round), so a
 * throttled-but-healthy backlog never trips the rounds-exhausted stop.
 *
 * Burst semantics: a replay that matches more entries than the bucket
 * currently holds does not drop anything — throttled entries stay in the
 * dead-letter list (their FIFO position preserved) and are reported in
 * `DeadLetterBatchReplayResult.throttled` and the cumulative
 * `DeadLetterStats.throttled` counter (served by `GET
 * /dead-letter/stats`). The next replay call — manual or an auto-replay
 * round — picks them up.
 *
 * Orthogonality: the gate only throttles the *re-queue* admission. Once
 * an entry re-enters the queue it walks the normal path — circuit breaker
 * (WR-10), per-endpoint quota (WR-15), weighted dispatch (WR-66), failover
 * (WR-39) — all untouched and independent. The single-id
 * `replayDeadLetter(id)` operator escape hatch is deliberately *not*
 * gated: an operator replaying one entry by hand is not a storm.
 *
 * Zero dependencies, injectable clock for deterministic tests.
 */

/** Opt-in replay egress tuning, embedded in `RetryQueueOptions`. */
export interface ReplayEgressOptions {
  /**
   * Maximum dead-letter replays admitted per second per endpoint
   * (logical endpoint: `failoverEndpoint ?? targetUrl`). Default: 10. Must
   * be a finite number > 0 — invalid values throw `RangeError` at
   * construction, never mid-replay.
   */
  replaysPerSecond?: number;
  /** Clock in ms; defaults to `Date.now`. Injectable for tests. */
  now?: () => number;
}

export const DEFAULT_REPLAY_EGRESS_RPS = 10;

function assertReplayEgressRps(replaysPerSecond: number): void {
  if (!Number.isFinite(replaysPerSecond) || replaysPerSecond <= 0) {
    throw new RangeError(
      `replayEgress.replaysPerSecond must be a finite number > 0, got ${replaysPerSecond}`
    );
  }
}

/**
 * Shared per-endpoint replay egress gate: a token bucket sized to one
 * second of budget, refilled lazily on read. `take()` consumes one token
 * for an endpoint; when the bucket is empty the caller holds the entry
 * back (never drops it) and retries on the next replay call.
 */
export class ReplayEgressGate {
  private readonly perSecond: number;
  private readonly buckets = new Map<string, { tokens: number; updatedMs: number }>();
  private readonly now: () => number;

  constructor(opts: ReplayEgressOptions = {}) {
    const perSecond = opts.replaysPerSecond ?? DEFAULT_REPLAY_EGRESS_RPS;
    assertReplayEgressRps(perSecond);
    this.perSecond = perSecond;
    this.now = opts.now ?? Date.now;
  }

  /** Configured per-second budget (every endpoint shares the same budget). */
  limit(): number {
    return this.perSecond;
  }

  private refill(endpoint: string): { tokens: number; updatedMs: number } {
    const at = this.now();
    let b = this.buckets.get(endpoint);
    if (!b) {
      // A new endpoint starts with a full bucket: the first second of
      // budget is available immediately, then refills continuously.
      b = { tokens: this.perSecond, updatedMs: at };
      this.buckets.set(endpoint, b);
    } else {
      const elapsedMs = Math.max(0, at - b.updatedMs);
      b.tokens = Math.min(this.perSecond, b.tokens + (elapsedMs * this.perSecond) / 1000);
      b.updatedMs = at;
    }
    return b;
  }

  /**
   * Consume one replay token for `endpoint`. Returns `false` when the
   * budget is exhausted — the caller holds the entry back for a later
   * replay call, never drops it, and never touches the retry budget,
   * circuit breaker, quota, or failover state.
   */
  take(endpoint: string): boolean {
    const b = this.refill(endpoint);
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  }

  /**
   * Milliseconds until one token is available for `endpoint` (0 when a
   * token is already available). Useful for sizing operator dashboards;
   * the replay path itself does not sleep — it returns `throttled` and
   * lets the next replay call pick the entries up.
   */
  msUntilToken(endpoint: string): number {
    const b = this.refill(endpoint);
    if (b.tokens >= 1) return 0;
    const needed = 1 - b.tokens;
    return Math.ceil((needed * 1000) / this.perSecond);
  }
}
