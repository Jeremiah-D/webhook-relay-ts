/**
 * WR-149: dead-letter replay idempotency guard.
 *
 * The payment-callback nightmare: the downstream *did* process the
 * event, but the response was lost, so the relay retried, exhausted its
 * budget, and dead-lettered the item. Replaying that dead letter now
 * would repeat the business action (a duplicate charge, a duplicate
 * payout). WR-14 dedup only guards *inbound* duplicates — it cannot
 * see replays.
 *
 * The {@link ReplayIdempotencyGuard} keeps a bounded outcome index of
 * delivered events keyed by `(endpoint, sha256(payload))` with their
 * delivery timestamps. Before `replayDeadLetter(s)` re-queues an entry,
 * the queue asks the guard: when the same (endpoint, payload) was
 * delivered *after* the entry was dead-lettered, the downstream already
 * holds a newer copy, so the replay is suppressed (audited as
 * `replay_skipped_delivered`) and the entry stays dead-lettered for
 * operator review. An explicit `force` replays anyway (audited as
 * `replay_forced`), and dry-run previews mark the would-be-skipped rows
 * (`will_skip`).
 *
 * The index is in-memory and bounded: `maxEntries` caps the pairs (the
 * oldest are evicted first) and records older than `windowMs` are
 * swept — a process restart clears it, so the guard degrades to
 * plain replay after a crash (fail-open by design: a missing record
 * never blocks a replay, it only fails to suppress one). The clock is
 * injectable for deterministic tests.
 */

import { createHash } from "node:crypto";

/** Default: how long a delivered record suppresses a later replay. */
export const DEFAULT_REPLAY_IDEMPOTENCY_WINDOW_MS = 24 * 60 * 60 * 1000;
/** Default: maximum tracked (endpoint, payload-hash) pairs. */
export const DEFAULT_REPLAY_IDEMPOTENCY_MAX_ENTRIES = 10_000;

/** Tuning for {@link ReplayIdempotencyGuard}. */
export interface ReplayIdempotencyOptions {
  /**
   * How long (ms) a delivered (endpoint, payload) record suppresses
   * replaying a dead letter of the same pair. Default: 86400000 (24h).
   * Must be > 0.
   */
  windowMs?: number;
  /**
   * Maximum tracked pairs; the oldest records are evicted first when
   * the cap is exceeded, so memory stays bounded. Default: 10000. Must
   * be an integer >= 1.
   */
  maxEntries?: number;
  /** Clock in ms; defaults to `Date.now`. Injectable for tests. */
  now?: () => number;
}

/** Observable snapshot of the guard. */
export interface ReplayIdempotencyStats {
  /** Distinct (endpoint, payload-hash) pairs currently tracked. */
  trackedPairs: number;
  /**
   * Timestamp (ms epoch) of the oldest tracked record; absent when the
   * index is empty.
   */
  oldestRecordAtMs?: number;
  /** Tenant id (WR-48); the queue adds it — absent for the default tenant. */
  tenant?: string;
}

/** SHA-256 hex digest of the payload bytes (string or Buffer). */
export function sha256Hex(input: Buffer | string): string {
  return createHash("sha256").update(input).digest("hex");
}

/**
 * Bounded outcome index of delivered (endpoint, payload) pairs
 * (WR-149). Pure bookkeeping: `recordDelivered` indexes a delivery,
 * `deliveredAtMs` answers whether (and when) a pair was delivered, and
 * eviction keeps the index bounded by age (`windowMs`) and count
 * (`maxEntries`).
 */
export class ReplayIdempotencyGuard {
  private readonly windowMs: number;
  private readonly maxEntries: number;
  private readonly now: () => number;
  /**
   * Composite key `${endpoint}\n${sha256Hex(payload)}` -> delivered-at
   * ms. Insertion-ordered: the head is the oldest record, which is what
   * eviction walks. Endpoint URLs cannot contain a raw newline and the
   * hash is hex, so the separator is unambiguous.
   */
  private readonly records = new Map<string, number>();

  constructor(opts: ReplayIdempotencyOptions = {}) {
    const windowMs = opts.windowMs ?? DEFAULT_REPLAY_IDEMPOTENCY_WINDOW_MS;
    if (!Number.isFinite(windowMs) || windowMs <= 0) {
      throw new RangeError(`replayIdempotency.windowMs must be > 0, got ${opts.windowMs}`);
    }
    const maxEntries = opts.maxEntries ?? DEFAULT_REPLAY_IDEMPOTENCY_MAX_ENTRIES;
    if (!Number.isInteger(maxEntries) || maxEntries < 1) {
      throw new RangeError(
        `replayIdempotency.maxEntries must be an integer >= 1, got ${opts.maxEntries}`
      );
    }
    this.windowMs = windowMs;
    this.maxEntries = maxEntries;
    this.now = opts.now ?? Date.now;
  }

  /**
   * Index one delivered event. Re-delivering the same pair refreshes its
   * timestamp (moved to the tail) — recency is what the replay check
   * compares against.
   */
  recordDelivered(endpoint: string, payload: Buffer | string): void {
    const key = compositeKey(endpoint, sha256Hex(payload));
    const nowMs = this.now();
    this.records.delete(key);
    this.records.set(key, nowMs);
    this.evict(nowMs);
  }

  /**
   * When the pair was last delivered (ms epoch), or `undefined` when
   * never recorded or already expired. Expired records are swept
   * lazily on insert only — a stale read here returns `undefined`
   * without mutating, so reads stay cheap.
   */
  deliveredAtMs(endpoint: string, payload: Buffer | string): number | undefined {
    const ts = this.records.get(compositeKey(endpoint, sha256Hex(payload)));
    if (ts === undefined) return undefined;
    if (this.now() - ts >= this.windowMs) return undefined;
    return ts;
  }

  /** Forget tracked pairs (`undefined` = all pairs). */
  reset(endpoint?: string): void {
    if (endpoint === undefined) {
      this.records.clear();
      return;
    }
    const prefix = `${endpoint}\n`;
    for (const key of this.records.keys()) {
      if (key.startsWith(prefix)) this.records.delete(key);
    }
  }

  /** Snapshot of the index. */
  stats(): ReplayIdempotencyStats {
    const first = this.records.values().next();
    return {
      trackedPairs: this.records.size,
      ...(first.done ? {} : { oldestRecordAtMs: first.value }),
    };
  }

  /**
   * Evict expired records from the head, then enforce the count cap.
   * Insertion order is chronological (modulo clock adjustments), so the
   * head holds the oldest records and the walk stops at the first
   * record that is both in-window and within the cap.
   */
  private evict(nowMs: number): void {
    const cutoff = nowMs - this.windowMs;
    for (const [key, ts] of this.records) {
      if (this.records.size <= this.maxEntries && ts >= cutoff) break;
      this.records.delete(key);
    }
  }
}

function compositeKey(endpoint: string, payloadHash: string): string {
  return `${endpoint}\n${payloadHash}`;
}
