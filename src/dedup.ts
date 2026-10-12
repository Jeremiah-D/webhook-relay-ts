import { createHash } from "node:crypto";
import {
  mkdirSync,
  existsSync,
  writeFileSync,
  openSync,
  writeSync,
  fsyncSync,
  closeSync,
  readFileSync,
} from "node:fs";
import { join } from "node:path";
import type { PayloadEncryptor, EncryptedPayload } from "./encrypt.ts";
import type { StoredPayload } from "./durable-queue.ts";

export interface DedupOptions {
  /**
   * How long (ms) a seen (endpoint, payload-hash) pair suppresses
   * duplicates. Default: 300000 (5 minutes). Must be > 0.
   */
  windowMs?: number;
  /**
   * Maximum tracked pairs; the oldest entries are evicted first when the
   * cap is exceeded, so memory stays bounded under a flood of distinct
   * payloads. Default: 10000. Must be an integer >= 1.
   */
  maxEntries?: number;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
  /**
   * Opt-in journal directory for crash-safe dedup (WR-79). When set,
   * first-sight (endpoint, payload-hash) pairs are appended to
   * `<journalDir>/dedup.jsonl` (fsync'd per line), and a new instance
   * recovers unexpired pairs on construction — a process restart no
   * longer re-delivers duplicates (the payment-callback guard survives
   * crashes). Corrupt lines are skipped and counted, never fatal.
   *
   * The journal follows the durable queue's journal convention
   * (`src/durable-queue.ts`): append-only JSONL, fsync per line, touch on
   * open, recovery always compacts, writes never throw (counted as
   * `writeErrors`), and an uncreatable directory throws at construction
   * (fail-fast operator misconfiguration).
   *
   * Unset = pure in-memory (default, backward compatible).
   */
  journalDir?: string;
  /**
   * Optional encryptor sealing journaled dedup keys (WR-11
   * `PayloadEncryptor`). Endpoint URLs can embed secrets in query
   * strings; sealing keeps them off the disk in the clear. Lines sealed
   * with a rotated-away key are skipped as corrupt on recover and
   * counted.
   */
  journalEncryptor?: PayloadEncryptor;
}

/** Journal file name inside the journal directory. */
export const DEDUP_JOURNAL_FILE = "dedup.jsonl";

/** Rewrite the journal when superseded lines reach this many appends. */
const DEDUP_JOURNAL_COMPACT_THRESHOLD = 4096;

type DedupJournalLine = {
  v: 1;
  op: "seen";
  /** ms epoch of first sight; window arithmetic happens on recover. */
  at: number;
  /**
   * The dedup key (`<endpoint>\n<payloadHash>`), sealed or base64 — the
   * same envelope convention as the durable queue journal.
   */
  key: StoredPayload;
};

interface DedupRecovery {
  /** Unexpired pairs, oldest first (file order). */
  entries: Array<{ key: string; at: number }>;
  /** Lines skipped as corrupt (torn writes, bad JSON, undecryptable keys). */
  corruptLines: number;
}

function isSealedPayload(v: StoredPayload): v is EncryptedPayload {
  return (v as EncryptedPayload).alg !== undefined;
}

/**
 * Append-only JSONL journal for the dedup window. All methods are
 * synchronous and never throw: durability first, intake never blocked on
 * the disk. Follows the `QueueJournal` convention in
 * `src/durable-queue.ts`.
 */
class DedupJournal {
  private readonly path: string;
  private readonly encryptor?: PayloadEncryptor;
  private linesWritten = 0;
  private linesAtLastCompact = 0;
  private writeErrors = 0;

  /**
   * `dir` is created (recursively) when missing — a missing directory is
   * normal on first boot; an *uncreatable* one is an operator
   * misconfiguration and throws, fail-fast at construction.
   */
  constructor(dir: string, encryptor?: PayloadEncryptor) {
    mkdirSync(dir, { recursive: true });
    this.path = join(dir, DEDUP_JOURNAL_FILE);
    this.encryptor = encryptor;
    // Touch the file so a missing journal reads as "no history", not an error.
    if (!existsSync(this.path)) {
      writeFileSync(this.path, "");
    }
  }

  /** Total appends since this journal was opened. */
  get appends(): number {
    return this.linesWritten;
  }

  /** Appends/compactions that failed (counted, never thrown). */
  get errors(): number {
    return this.writeErrors;
  }

  /** True when appends since the last compaction hit the threshold. */
  get shouldCompact(): boolean {
    return this.linesWritten - this.linesAtLastCompact >= DEDUP_JOURNAL_COMPACT_THRESHOLD;
  }

  private sealKey(key: string): StoredPayload {
    const buf = Buffer.from(key, "utf8");
    if (this.encryptor) return this.encryptor.encrypt(buf);
    return { encoding: "base64", data: buf.toString("base64") };
  }

  private appendLine(line: DedupJournalLine): void {
    try {
      const fd = openSync(this.path, "a");
      try {
        writeSync(fd, JSON.stringify(line) + "\n");
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      this.linesWritten += 1;
    } catch {
      // The in-memory window is authoritative; a failed journal write
      // degrades to non-durable dedup, never an intake failure.
      this.writeErrors += 1;
    }
  }

  /** Journal one first-sight pair. Never throws. */
  appendSeen(key: string, atMs: number): void {
    this.appendLine({ v: 1, op: "seen", at: Math.round(atMs), key: this.sealKey(key) });
  }

  private openKey(stored: StoredPayload | undefined): string | undefined {
    try {
      if (stored === undefined) return undefined;
      if (isSealedPayload(stored)) {
        // Sealed but no encryptor configured (key removed between
        // restarts): undecryptable, counts as corrupt.
        if (this.encryptor === undefined) return undefined;
        return this.encryptor.decrypt(stored).toString("utf8");
      }
      const plain = stored as { encoding?: unknown; data?: unknown };
      if (plain.encoding !== "base64" || typeof plain.data !== "string") return undefined;
      return Buffer.from(plain.data, "base64").toString("utf8");
    } catch {
      return undefined;
    }
  }

  /**
   * Fold the journal into live pairs. Malformed lines, unknown shapes,
   * and keys that no longer decrypt (e.g. the encryptor key was rotated
   * between restarts) are skipped and counted — a corrupt line never
   * prevents recovery of the rest. Only pairs still inside the window
   * (anchored at recover time) are restored, so a key first seen before
   * the crash keeps exactly the remainder of its original window.
   * Recovery always compacts: the file is rewritten with live pairs only.
   */
  recover(windowMs: number, nowMs: number): DedupRecovery {
    const entries: Array<{ key: string; at: number }> = [];
    let corruptLines = 0;
    let text: string;
    try {
      text = readFileSync(this.path, "utf8");
    } catch {
      // Unreadable journal reads as "no history", never fatal.
      return { entries, corruptLines };
    }
    for (const raw of text.split("\n")) {
      if (raw === "") continue;
      let line: unknown;
      try {
        line = JSON.parse(raw);
      } catch {
        corruptLines += 1;
        continue;
      }
      const rec = line as Partial<DedupJournalLine> | null;
      if (
        rec === null ||
        typeof rec !== "object" ||
        rec.v !== 1 ||
        rec.op !== "seen" ||
        typeof rec.at !== "number" ||
        !Number.isFinite(rec.at)
      ) {
        corruptLines += 1;
        continue;
      }
      const key = this.openKey(rec.key);
      if (key === undefined) {
        corruptLines += 1;
        continue;
      }
      if (nowMs - rec.at < windowMs) entries.push({ key, at: rec.at });
    }
    this.compact(entries);
    return { entries, corruptLines };
  }

  /**
   * Rewrite the journal keeping only `entries` (oldest first). Never
   * throws; a failed compaction just leaves the old file in place.
   */
  compact(entries: Array<{ key: string; at: number }>): void {
    try {
      const fd = openSync(this.path, "w");
      try {
        for (const { key, at } of entries) {
          writeSync(
            fd,
            JSON.stringify({ v: 1, op: "seen", at, key: this.sealKey(key) } satisfies DedupJournalLine) +
              "\n"
          );
        }
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      this.linesAtLastCompact = this.linesWritten;
    } catch {
      this.writeErrors += 1;
    }
  }
}

/**
 * Idempotent delivery deduplicator: within `windowMs`, a payload hash
 * already accepted for an endpoint is a duplicate — the repeat webhook is
 * acknowledged but never delivered, so an upstream retry (e.g. a repeated
 * payment callback) cannot cause a duplicate business action.
 *
 * The key is `(targetUrl, sha256(payload))`: the same payload forwarded to
 * a different endpoint is a different delivery, and headers do not affect
 * the identity of the event. Entries expire lazily out of the window, and
 * the oldest entries are evicted past `maxEntries`, so a flood of distinct
 * payloads cannot grow memory unboundedly.
 *
 * With `journalDir` set (WR-79), first-sight pairs are journaled to disk
 * and restored on construction — the dedup window survives process
 * restarts. Without it the window is pure in-memory (default).
 *
 * This is inbound-side dedup (the server checks before enqueueing), not a
 * replacement for the nonce/timestamp replay guard (`src/replay.ts`):
 * the guard rejects exact replays by header, the deduplicator suppresses
 * the same business event arriving under a new id.
 */
export class DeliveryDeduplicator {
  private readonly windowMs: number;
  private readonly maxEntries: number;
  private readonly now: () => number;
  /** Insertion-ordered: key -> ms timestamp when first seen. */
  private readonly seen = new Map<string, number>();
  private readonly journal?: DedupJournal;
  private checked = 0;
  private suppressed = 0;
  private journalRecovered = 0;
  private journalCorruptLines = 0;
  private journaledSinceOpen = 0;

  constructor(opts: DedupOptions = {}) {
    this.windowMs = opts.windowMs ?? 300_000;
    this.maxEntries = opts.maxEntries ?? 10_000;
    this.now = opts.now ?? Date.now;
    if (!Number.isFinite(this.windowMs) || this.windowMs <= 0) {
      throw new RangeError(`windowMs must be > 0, got ${opts.windowMs}`);
    }
    if (!Number.isInteger(this.maxEntries) || this.maxEntries < 1) {
      throw new RangeError(`maxEntries must be an integer >= 1, got ${opts.maxEntries}`);
    }
    if (opts.journalDir !== undefined) {
      this.journal = new DedupJournal(opts.journalDir, opts.journalEncryptor);
      const { entries, corruptLines } = this.journal.recover(this.windowMs, this.now());
      // Enforce the memory cap on recovered state: keep the newest pairs.
      for (const { key, at } of entries.slice(-this.maxEntries)) {
        this.seen.set(key, at);
      }
      this.journalRecovered = Math.min(entries.length, this.maxEntries);
      this.journalCorruptLines = corruptLines;
    }
  }

  /** SHA-256 hex digest of a payload (the stable half of the dedup key). */
  static hashPayload(payload: Buffer): string {
    return createHash("sha256").update(payload).digest("hex");
  }

  /**
   * Record `(endpoint, payloadHash)`. Returns `true` when the pair was
   * already seen inside the window — the delivery must be suppressed —
   * `false` on first sight (deliver it). A pair seen again *after* its
   * window expired counts as new and restarts the window.
   */
  check(endpoint: string, payloadHash: string): boolean {
    const at = this.now();
    this.evictExpired(at);
    this.checked += 1;
    const key = `${endpoint}\n${payloadHash}`;
    const firstSeen = this.seen.get(key);
    if (firstSeen !== undefined && at - firstSeen < this.windowMs) {
      this.suppressed += 1;
      return true;
    }
    // Re-seen after expiry: delete + set keeps the insertion order fresh so
    // oldest-eviction drops the truly oldest pairs.
    if (firstSeen !== undefined) this.seen.delete(key);
    this.seen.set(key, at);
    while (this.seen.size > this.maxEntries) {
      const oldest = this.seen.keys().next();
      if (oldest.done) break;
      this.seen.delete(oldest.value);
    }
    if (this.journal !== undefined) {
      this.journal.appendSeen(key, at);
      this.journaledSinceOpen += 1;
      // Amortized compaction: `seen` holds only live pairs (expired were
      // evicted above), so the file stays proportional to the window.
      if (this.journal.shouldCompact) {
        this.journal.compact([...this.seen].map(([k, ts]) => ({ key: k, at: ts })));
      }
    }
    return false;
  }

  private evictExpired(at: number): void {
    // Insertion-ordered: once a pair is still inside its window, every
    // later pair is newer and also inside its window.
    for (const [key, ts] of this.seen) {
      if (at - ts >= this.windowMs) this.seen.delete(key);
      else break;
    }
  }

  /**
   * Observability: pairs checked, duplicates suppressed, pairs tracked.
   * `journal` is present only when `journalDir` was configured: pairs
   * restored at construction, journal lines skipped as corrupt during
   * recovery, journal writes that failed (counted, never thrown), and
   * first-sight pairs journaled since this instance opened.
   */
  stats(): {
    checked: number;
    suppressed: number;
    tracked: number;
    journal?: {
      recovered: number;
      corruptLines: number;
      writeErrors: number;
      journaled: number;
    };
  } {
    const base = {
      checked: this.checked,
      suppressed: this.suppressed,
      tracked: this.seen.size,
    };
    if (this.journal === undefined) return base;
    return {
      ...base,
      journal: {
        recovered: this.journalRecovered,
        corruptLines: this.journalCorruptLines,
        writeErrors: this.journal.errors,
        journaled: this.journaledSinceOpen,
      },
    };
  }
}
