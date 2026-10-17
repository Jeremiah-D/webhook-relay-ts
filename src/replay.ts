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
 *
 * Durable journal (WR-122): with `journalDir` set, every accepted nonce is
 * appended as JSONL (`<dir>/nonces.jsonl`, keyed by `(scope, nonce)`) and the
 * window is rebuilt from disk at construction, so a process restart does not
 * reopen the replay window. Journaling is opt-in; without it the guard is
 * purely in-memory, exactly the WR-05 behavior.
 *
 * The journal write is asynchronous and batched — `check()` never blocks on
 * disk. The trade-off is explicit: a crash between accept and flush can lose
 * the tail of the journal, reopening the window for those nonces. Call
 * `await guard.flush()` when the tail must be durable (e.g. before a
 * planned restart). Journal I/O never throws on the hot path; failures are
 * counted in {@link ReplayGuard.journalStats}.
 */
import { appendFile } from "node:fs/promises";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";

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
  /**
   * Opt-in: directory holding the nonce journal (`nonces.jsonl`). Created
   * recursively when missing. When set, accepted nonces are journaled and
   * the window is recovered from disk at construction, surviving restarts.
   * Unset by default — the guard is then purely in-memory.
   */
  journalDir?: string;
}

/** One journal line. `scope` is `""` for unscoped checks. */
interface JournalRecord {
  v: 1;
  nonce: string;
  scope: string;
  expiresAtMs: number;
}

/** Journal file name inside `journalDir`. */
export const REPLAY_JOURNAL_FILE = "nonces.jsonl";

/** Temp file used for atomic journal rewrites (same dir, so rename is atomic). */
const JOURNAL_TMP_SUFFIX = ".tmp";

/**
 * Amortization: a compaction pass (dropping expired journal lines) runs at
 * most every this many appends, so the journal cannot grow without bound
 * while the hot path stays O(1) amortized.
 */
const COMPACT_EVERY_APPENDS = 1024;

export interface ReplayJournalStats {
  /** Whether a journal directory is configured. */
  enabled: boolean;
  /** Nonces recovered from the journal at construction. */
  recovered: number;
  /** Journal lines skipped as corrupt during recovery. */
  corruptLines: number;
  /** Failed journal writes/rewrites (counted, never thrown). */
  journalErrors: number;
  /** Accepted nonces waiting for the next async flush. */
  pendingLines: number;
}

export class ReplayGuard {
  private readonly windowMs: number;
  private readonly maxEntries: number;
  private readonly nowMs: () => number;
  /**
   * memory key -> expiry timestamp (ms). The key is the nonce for unscoped
   * checks, or `scope + "\0" + nonce` for scoped ones. Insertion-ordered,
   * which the oldest-first eviction relies on.
   */
  private readonly seen = new Map<string, number>();
  private readonly journalPath?: string;
  /** Serialized journal lines accepted but not yet flushed to disk. */
  private pending: string[] = [];
  /** Serializes concurrent flush() calls so batches keep file order. */
  private flushChain: Promise<void> = Promise.resolve();
  private appendsSinceCompact = 0;
  private recovered = 0;
  private corruptLines = 0;
  private journalErrors = 0;

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
    if (opts.journalDir !== undefined) {
      if (typeof opts.journalDir !== "string" || opts.journalDir.length === 0) {
        throw new RangeError("journalDir must be a non-empty string");
      }
      // A missing directory is normal on first boot; an *uncreatable* one
      // is an operator misconfiguration and throws, fail-fast.
      mkdirSync(opts.journalDir, { recursive: true });
      this.journalPath = join(opts.journalDir, REPLAY_JOURNAL_FILE);
      this.recover();
    }
  }

  /** Nonces currently remembered (after pruning expired ones). */
  size(): number {
    this.prune(this.nowMs());
    return this.seen.size;
  }

  /** Durability stats for the journal (zeros when no journal is configured). */
  journalStats(): ReplayJournalStats {
    return {
      enabled: this.journalPath !== undefined,
      recovered: this.recovered,
      corruptLines: this.corruptLines,
      journalErrors: this.journalErrors,
      pendingLines: this.pending.length,
    };
  }

  /**
   * Validate a `(nonce, timestampMs)` pair. Records the nonce on success
   * (memory + journal when configured). Never throws on bad input: unusable
   * values are rejections, not errors.
   *
   * `scope` namespaces the nonce — the duplicate check is per
   * `(scope, nonce)` pair. The relay server passes the resolved `targetUrl`,
   * so the same nonce value reused by an unrelated sender/target pair is not
   * a false-positive replay. Unscoped callers keep the legacy global-nonce
   * behavior.
   */
  check(
    nonce: string | undefined | null,
    timestampMs?: number,
    scope?: string
  ): ReplayCheckResult {
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
    const key = scope ? `${scope}\0${nonce}` : nonce;
    if (this.seen.has(key)) {
      return { ok: false, reason: "duplicate_nonce" };
    }
    const expiresAtMs = now + this.windowMs;
    this.seen.set(key, expiresAtMs);
    while (this.seen.size > this.maxEntries) {
      const oldest = this.seen.keys().next();
      if (oldest.done) break;
      this.seen.delete(oldest.value);
    }
    if (this.journalPath !== undefined) {
      const record: JournalRecord = {
        v: 1,
        nonce,
        scope: scope ?? "",
        expiresAtMs,
      };
      this.pending.push(JSON.stringify(record) + "\n");
      this.appendsSinceCompact += 1;
      // Async: the check() caller never waits for disk. Batches are
      // serialized through flush() so file order matches accept order.
      void this.scheduleFlush();
      if (this.appendsSinceCompact >= Math.max(COMPACT_EVERY_APPENDS, this.maxEntries)) {
        this.appendsSinceCompact = 0;
        void this.flush().then(() => this.compact());
      }
    }
    return { ok: true };
  }

  /**
   * Wait until every accepted nonce is durable on disk. Use before a
   * planned restart when the journal tail must survive. Never throws:
   * failures are counted in `journalStats().journalErrors`.
   */
  flush(): Promise<void> {
    if (this.journalPath === undefined) return Promise.resolve();
    const run = this.flushChain.then(() => this.drainPending());
    // Keep the chain alive for the next caller even if this run failed.
    this.flushChain = run.catch(() => undefined);
    return run;
  }

  private scheduleFlush(): void {
    // setImmediate: the current (signature-verification) tick finishes
    // before any disk I/O starts.
    setImmediate(() => {
      void this.flush();
    });
  }

  private async drainPending(): Promise<void> {
    if (this.pending.length === 0 || this.journalPath === undefined) return;
    const batch = this.pending;
    this.pending = [];
    try {
      await appendFile(this.journalPath, batch.join(""), "utf8");
    } catch {
      this.journalErrors += batch.length;
    }
  }

  private prune(now: number): void {
    for (const [nonce, expiry] of this.seen) {
      if (expiry <= now) {
        this.seen.delete(nonce);
      }
    }
  }

  /**
   * Rebuild the window from the journal: expired entries are dropped
   * (against the guard's clock, so tests stay deterministic), corrupt lines
   * are skipped and counted. When anything was dropped, the journal is
   * rewritten compacted (atomic rename) so restarts do not accumulate dead
   * lines. Never throws — an unreadable journal degrades to an empty
   * window, counted in `journalErrors`.
   */
  private recover(): void {
    let raw: string;
    try {
      raw = readFileSync(this.journalPath as string, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return; // first boot
      this.journalErrors += 1;
      return;
    }
    const now = this.nowMs();
    const kept: JournalRecord[] = [];
    let dropped = 0;
    for (const line of raw.split("\n")) {
      if (line.trim() === "") continue;
      const rec = parseJournalRecord(line);
      if (rec === undefined) {
        this.corruptLines += 1;
        dropped += 1;
        continue;
      }
      if (rec.expiresAtMs <= now) {
        dropped += 1; // window already passed — forget it
        continue;
      }
      kept.push(rec);
      const key = rec.scope ? `${rec.scope}\0${rec.nonce}` : rec.nonce;
      this.seen.set(key, rec.expiresAtMs);
      // File order is accept order (oldest first), so the same
      // oldest-first eviction as the live path keeps the newest entries.
      while (this.seen.size > this.maxEntries) {
        const oldest = this.seen.keys().next();
        if (oldest.done) break;
        this.seen.delete(oldest.value);
      }
      this.recovered += 1;
    }
    if (dropped > 0) {
      this.rewriteJournal(kept);
    }
  }

  /**
   * Drop expired lines from the journal (amortized; see
   * COMPACT_EVERY_APPENDS). The memory window is authoritative for
   * admission — the journal is only a recovery aid, so a failed rewrite
   * merely wastes disk, never weakens protection.
   */
  private compact(): void {
    if (this.journalPath === undefined) return;
    let raw: string;
    try {
      raw = readFileSync(this.journalPath, "utf8");
    } catch {
      this.journalErrors += 1;
      return;
    }
    const now = this.nowMs();
    const kept: JournalRecord[] = [];
    for (const line of raw.split("\n")) {
      if (line.trim() === "") continue;
      const rec = parseJournalRecord(line);
      if (rec !== undefined && rec.expiresAtMs > now) kept.push(rec);
    }
    this.rewriteJournal(kept);
  }

  /** Rewrite the journal from parsed records via temp-file + atomic rename. */
  private rewriteJournal(records: JournalRecord[]): void {
    if (this.journalPath === undefined) return;
    const tmp = this.journalPath + JOURNAL_TMP_SUFFIX;
    try {
      const data = records.map((r) => JSON.stringify(r) + "\n").join("");
      writeFileSync(tmp, data, "utf8");
      renameSync(tmp, this.journalPath);
    } catch {
      this.journalErrors += 1;
    }
  }
}

/** Parse one journal line; `undefined` for corrupt lines (never throws). */
function parseJournalRecord(line: string): JournalRecord | undefined {
  let obj: Record<string, unknown>;
  try {
    obj = JSON.parse(line) as Record<string, unknown>;
  } catch {
    return undefined;
  }
  if (typeof obj["nonce"] !== "string" || (obj["nonce"] as string).length === 0) {
    return undefined;
  }
  if (!Number.isFinite(obj["expiresAtMs"])) return undefined;
  const scope = obj["scope"];
  if (scope !== undefined && typeof scope !== "string") return undefined;
  return {
    v: 1,
    nonce: obj["nonce"] as string,
    scope: typeof scope === "string" ? scope : "",
    expiresAtMs: obj["expiresAtMs"] as number,
  };
}
