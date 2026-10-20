/**
 * WR-167: relay-level global outbound rate limit.
 *
 * The per-endpoint quota (`EndpointQuota`, WR-15) bounds deliveries per
 * downstream; this gate bounds them *across the whole relay* — the total
 * dispatch rate in messages per second, regardless of endpoint or
 * tenant. The two compose: a dispatch needs a token from each.
 *
 * Why relay-level: a fan-out relay can have dozens of healthy endpoints
 * each within their own quota while the relay itself saturates the
 * shared egress bandwidth or the aggregate downstream QPS budget. The
 * global rate is the backpressure valve for the relay's own egress.
 *
 * Semantics:
 * - Token bucket: one token per dispatch, refilled continuously at
 *   `messagesPerSec`. The bucket starts full (`maxBurst` tokens), so a
 *   quiet relay can burst a second's worth immediately.
 * - FIFO: when the bucket is empty, excess dispatches wait in arrival
 *   order for the next refill. Waiters are never dropped, never consume
 *   retry budget, and never touch the circuit breaker — waiting is
 *   neutral, exactly like the per-endpoint quota and the WR-51
 *   concurrency gate.
 * - Placement: the queue acquires the gate right after the WR-35 lane
 *   turn and before the WR-51 global concurrency gate, so quota /
 *   circuit / budget verdicts are still unsettled (they come later) but
 *   no concurrency slot is held while waiting for a token. The urgent
 *   lane does not bypass this gate: it is relay-level egress capacity,
 *   not per-endpoint policy (same rationale as the WR-51 global gate).
 * - Shutdown: `releaseWaiters()` wakes every waiter without consuming a
 *   token — woken waiters observe the stopped queue through the normal
 *   liveness check and bail out. The single head timer is cleared, so a
 *   stop never leaves a deliver parked on the gate across a restart.
 *
 * The clock and the timer are injectable for deterministic tests.
 * Zero dependencies.
 */

/** Options for {@link GlobalRateLimiter}. */
export interface GlobalRateLimitOptions {
  /**
   * Global dispatches per second across the whole relay. Each send
   * attempt consumes one token. Must be a finite number > 0.
   */
  messagesPerSec: number;
  /**
   * Bucket capacity in tokens (one token = one dispatch). Default:
   * `messagesPerSec` — one full second of budget, so a quiet relay can
   * burst a second's worth immediately. Must be a finite number > 0.
   */
  maxBurst?: number;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
  /**
   * Timer factory for the head waiter's refill wait. Defaults to
   * `setTimeout` with `unref` so a waiting gate never pins process
   * exit. Injectable for deterministic tests.
   */
  setTimer?: (fn: () => void, ms: number) => unknown;
  /** Clears a timer created by `setTimer`. Defaults to `clearTimeout`. */
  clearTimer?: (handle: unknown) => void;
}

/** Point-in-time snapshot for operator observability. */
export interface GlobalRateLimitStats {
  /** Configured global rate (messages/second). */
  messagesPerSec: number;
  /** Bucket capacity in tokens. */
  maxBurst: number;
  /** Cumulative dispatches that had to wait for a token. */
  delayedTotal: number;
  /** Dispatches currently queued FIFO for a token. */
  queuedDepth: number;
  /** Tokens currently available (fractional, informational). */
  availableTokens: number;
}

/** Validate a {@link GlobalRateLimitOptions}. Throws `RangeError` on anything invalid. */
export function assertValidGlobalRateLimit(opts: unknown): void {
  if (opts === null || typeof opts !== "object" || Array.isArray(opts)) {
    throw new RangeError(`globalRateLimit must be an options object, got ${String(opts)}`);
  }
  const o = opts as Record<string, unknown>;
  const rate = o.messagesPerSec;
  if (typeof rate !== "number" || !Number.isFinite(rate) || rate <= 0) {
    throw new RangeError(
      `globalRateLimit.messagesPerSec must be a finite number > 0, got ${String(rate)}`
    );
  }
  const burst = o.maxBurst ?? rate;
  if (typeof burst !== "number" || !Number.isFinite(burst) || burst <= 0) {
    throw new RangeError(`globalRateLimit.maxBurst must be a finite number > 0, got ${String(o.maxBurst)}`);
  }
  if (o.now !== undefined && typeof o.now !== "function") {
    throw new RangeError(`globalRateLimit.now must be a function, got ${String(o.now)}`);
  }
  if (o.setTimer !== undefined && typeof o.setTimer !== "function") {
    throw new RangeError(`globalRateLimit.setTimer must be a function, got ${String(o.setTimer)}`);
  }
  if (o.clearTimer !== undefined && typeof o.clearTimer !== "function") {
    throw new RangeError(`globalRateLimit.clearTimer must be a function, got ${String(o.clearTimer)}`);
  }
}

/**
 * Relay-wide dispatch rate gate: at most `messagesPerSec` dispatches per
 * second across all endpoints and tenants; excess acquisitions wait in
 * FIFO order for the next token refill.
 *
 * Callers must re-check their own liveness after `acquire()` resolves
 * (the queue may have stopped while they waited) — see
 * `releaseWaiters()`.
 */
export class GlobalRateLimiter {
  private readonly messagesPerSec: number;
  private readonly maxBurst: number;
  /** Tokens per millisecond. */
  private readonly perMs: number;
  private readonly now: () => number;
  private readonly setTimer: (fn: () => void, ms: number) => unknown;
  private readonly clearTimer: (handle: unknown) => void;
  private tokens: number;
  private updatedMs: number;
  private readonly waiters: Array<() => void> = [];
  private headTimer: unknown = undefined;
  private delayedTotal = 0;

  constructor(opts: GlobalRateLimitOptions) {
    assertValidGlobalRateLimit(opts);
    this.messagesPerSec = opts.messagesPerSec;
    this.maxBurst = opts.maxBurst ?? opts.messagesPerSec;
    this.perMs = opts.messagesPerSec / 1000;
    this.now = opts.now ?? Date.now;
    this.setTimer =
      opts.setTimer ??
      ((fn, ms) => {
        const t = setTimeout(fn, ms);
        // A rate-gate wait must never pin process exit; the queue also
        // clears this timer on stop()/shutdown() via releaseWaiters().
        (t as unknown as { unref?: () => void }).unref?.();
        return t;
      });
    this.clearTimer = opts.clearTimer ?? ((h) => clearTimeout(h as NodeJS.Timeout));
    // Start full: a quiet relay bursts a second's worth immediately.
    this.tokens = this.maxBurst;
    this.updatedMs = this.now();
  }

  /** Tokens currently available (fractional, informational). */
  availableTokens(): number {
    this.refill();
    return this.tokens;
  }

  /** Refill the bucket from the elapsed wall clock (clamped at capacity). */
  private refill(): void {
    const at = this.now();
    // A backward clock jump never un-refills: clamp the elapsed delta
    // at zero so time never runs backwards for the bucket.
    const elapsedMs = Math.max(0, at - this.updatedMs);
    this.updatedMs = at;
    this.tokens = Math.min(this.maxBurst, this.tokens + elapsedMs * this.perMs);
  }

  /**
   * Resolve when a global dispatch token is available. The waiter count
   * (`delayedTotal`) increments only when the acquisition actually waits
   * — an immediately granted token is not a delay. Tokens are consumed
   * on grant.
   */
  acquire(): Promise<void> {
    this.refill();
    if (this.waiters.length === 0 && this.tokens >= 1) {
      this.tokens -= 1;
      return Promise.resolve();
    }
    this.delayedTotal += 1;
    return new Promise<void>((resolve) => {
      this.waiters.push(resolve);
      // One timer drives the head waiter only; each grant re-arms for
      // the next waiter. New arrivals always queue behind (FIFO) even
      // if a token became available in the meantime.
      if (this.waiters.length === 1) this.armHeadTimer();
    });
  }

  /** Arm the head waiter's timer for the instant its token refills. */
  private armHeadTimer(): void {
    this.refill();
    const waitMs = Math.max(0, Math.ceil((1 - this.tokens) / this.perMs));
    this.headTimer = this.setTimer(() => {
      this.headTimer = undefined;
      this.refill();
      const resolve = this.waiters.shift();
      if (resolve === undefined) return;
      // Grant even if a backward clock left the bucket short: the timer
      // already waited the computed interval, so liveness beats exactness
      // (a clock jump must never deadlock the gate).
      this.tokens = Math.max(0, this.tokens - 1);
      resolve();
      if (this.waiters.length > 0) this.armHeadTimer();
    }, waitMs);
  }

  /**
   * Fail-safe for `stop()`/`shutdown()`: clear the head timer and wake
   * every waiter without consuming a token. Woken waiters must re-check
   * liveness (the queue is stopped) and bail out instead of dispatching.
   */
  releaseWaiters(): void {
    if (this.headTimer !== undefined) {
      this.clearTimer(this.headTimer);
      this.headTimer = undefined;
    }
    const pending = this.waiters.splice(0);
    for (const wake of pending) wake();
  }

  /** Cumulative dispatches that had to wait for a token. */
  delayedTotalCount(): number {
    return this.delayedTotal;
  }

  /** Dispatches currently queued FIFO for a token. */
  queuedDepth(): number {
    return this.waiters.length;
  }

  /** Point-in-time snapshot for operator observability. */
  stats(): GlobalRateLimitStats {
    return {
      messagesPerSec: this.messagesPerSec,
      maxBurst: this.maxBurst,
      delayedTotal: this.delayedTotal,
      queuedDepth: this.waiters.length,
      availableTokens: this.availableTokens(),
    };
  }
}
