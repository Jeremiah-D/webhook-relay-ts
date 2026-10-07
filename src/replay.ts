/**
 * Replay protection for inbound webhooks.
 *
 * A signed webhook can be captured and re-sent: the signature still verifies,
 * so signature checks alone cannot tell a replay from the original. The
 * {@link ReplayGuard} closes that hole with a nonce + timestamp window:
 *
 * - the sender attaches a unique `x-nonce` per webhook (its idempotency key),
 * - an optional `x-timestamp` (unix seconds) must fall inside the window
 *   around "now" (rejects both stale replays and far-future clock abuse),
 * - a nonce seen once inside the window is rejected on resend
 *   (`duplicate_nonce`), and
 * - nonces expire with the window, so the guard's memory is bounded; a
 *   `maxEntries` cap evicts the oldest entries as defense in depth.
 *
 * Timestamp validation is intentionally separate from the signature-layer
 * tolerance in `verify.ts`: a verifier accepts a *signed* timestamp, while
 * this guard decides whether a *seen* delivery may be processed again.
 */
export type ReplayRejectReason =
  | "missing_nonce"
  | "expired_timestamp"
  | "future_timestamp"
  | "duplicate_nonce";

export interface ReplayCheckResult {
  ok: boolean;
  /** Present (and a machine-readable value) when `ok` is false. */
  reason?: ReplayRejectReason;
}

export interface ReplayGuardOptions {
  /**
   * Sliding window in seconds: nonces are remembered this long, and the
   * `x-timestamp` must be within ±window of now. Default: 300. Must be > 0.
   */
  windowSec?: number;
  /**
   * Maximum remembered nonces; beyond this the oldest entries are evicted.
   * Default: 100000. Must be an integer >= 1.
   */
  maxEntries?: number;
  /** Clock source in ms; defaults to `Date.now`. Injectable for tests. */
  nowMs?: () => number;
}

export class ReplayGuard {
  private readonly windowMs: number;
  private readonly maxEntries: number;
  private readonly nowMs: () => number;
  /**
   * nonce -> expiry timestamp (ms). Insertion-ordered, which the
   * oldest-first eviction relies on.
   */
  private readonly seen = new Map<string, number>();

  constructor(opts: ReplayGuardOptions = {}) {
    this.windowMs = (opts.windowSec ?? 300) * 1000;
    this.maxEntries = opts.maxEntries ?? 100000;
    this.nowMs = opts.nowMs ?? Date.now;
    if (!Number.isFinite(this.windowMs) || this.windowMs <= 0) {
      throw new RangeError(`windowSec must be > 0, got ${opts.windowSec}`);
    }
    if (!Number.isInteger(this.maxEntries) || this.maxEntries < 1) {
      throw new RangeError(`maxEntries must be an integer >= 1, got ${opts.maxEntries}`);
    }
  }

  /** Nonces currently remembered (after pruning expired ones). */
  size(): number {
    this.prune(this.nowMs());
    return this.seen.size;
  }

  /**
   * Validate a `(nonce, timestampMs)` pair. Records the nonce on success.
   * Never throws on bad input: unusable values are rejections, not errors.
   */
  check(nonce: string | undefined | null, timestampMs?: number): ReplayCheckResult {
    const now = this.nowMs();
    this.prune(now);

    if (typeof nonce !== "string" || nonce.length === 0) {
      return { ok: false, reason: "missing_nonce" };
    }
    if (timestampMs !== undefined) {
      if (!Number.isFinite(timestampMs)) {
        return { ok: false, reason: "expired_timestamp" };
      }
      const skew = now - timestampMs;
      if (skew > this.windowMs) {
        return { ok: false, reason: "expired_timestamp" };
      }
      if (skew < -this.windowMs) {
        return { ok: false, reason: "future_timestamp" };
      }
    }
    if (this.seen.has(nonce)) {
      return { ok: false, reason: "duplicate_nonce" };
    }
    this.seen.set(nonce, now + this.windowMs);
    while (this.seen.size > this.maxEntries) {
      const oldest = this.seen.keys().next();
      if (oldest.done) break;
      this.seen.delete(oldest.value);
    }
    return { ok: true };
  }

  private prune(now: number): void {
    for (const [nonce, expiry] of this.seen) {
      if (expiry <= now) {
        this.seen.delete(nonce);
      }
    }
  }
}
