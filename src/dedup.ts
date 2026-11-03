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
   *
   * Cannot be combined with `store` (WR-108): passing both throws
   * `RangeError` at construction.
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
  /**
   * Pluggable backing store for the dedup window (WR-108). Default: a new
   * `InMemoryDedupStore` capped at `maxEntries`. A custom store (e.g. a
   * Redis adapter shared across processes so duplicates stay suppressed
   * across restarts and instances) owns expiry, eviction, and durability,
   * and MUST honor the caller-supplied clock: `check()` passes `now()`
   * through as `nowMs` and the store must never consult its own clock, so
   * behavior stays deterministic and testable.
   *
   * Mutually exclusive with `journalDir`: passing both throws `RangeError`
   * at construction. `journalDir` is the *default* store's durability
   * story; a custom store brings its own (Redis persistence, …).
   */
  store?: DedupStore;
}

/** Journal file name inside the journal directory. */
export const DEDUP_JOURNAL_FILE = "dedup.jsonl";

/**
 * Partial dedup-window revision (WR-308): the runtime patch
 * `DeliveryDeduplicator.retune()` / `RelayServer.setDedupWindow()`
 * accept. Omitted fields keep their live values; an empty patch is a
 * no-op. Merged values are validated against the construction gates
 * (`windowMs` finite > 0, `maxEntries` an integer >= 1) — an illegal
 * patch throws `RangeError` and the live values are left untouched.
 */
export interface DedupWindowRevision {
  windowMs?: number;
  maxEntries?: number;
}

/** Rewrite the journal when superseded lines reach this many appends. */
const DEDUP_JOURNAL_COMPACT_THRESHOLD = 4096;

/**
 * Pluggable backing store for the dedup window (WR-108). The store owns
 * expiry and eviction; the deduplicator owns the key shape
 * (`<endpoint>\n<sha256(payload)>`) and the checked/suppressed counters.
 */
export interface DedupStore {
  /**
   * Returns `true` when `key` was seen inside `[nowMs - windowMs, nowMs]`
   * (suppress the delivery), `false` on first sight or after expiry
   * (remember it and restart the window). The store MUST use the
   * caller-supplied `nowMs` — never its own clock — so behavior stays
   * deterministic and testable. Must never throw on normal inputs. May be
   * async: remote stores (e.g. Redis) resolve their answer later.
   */
  checkAndRemember(key: string, nowMs: number, windowMs: number): boolean | Promise<boolean>;
  /** Keys currently tracked (observability). May be async like the above. */
  size(): number | Promise<number>;
}

/**
 * The default `DedupStore` (WR-108): the exact in-memory map that
 * `DeliveryDeduplicator` used before stores were pluggable, moved here
 * verbatim. Insertion-ordered map of key -> ms timestamp when first seen;
 * lazy expiry inside `checkAndRemember`; the oldest entries are evicted
 * past `maxEntries` so memory stays bounded under a flood of distinct
 * payloads; a key re-seen after its window expired refreshes its insertion
 * order so oldest-eviction drops the truly oldest pairs.
 */
export class InMemoryDedupStore implements DedupStore {
  /** Mutable (WR-308): the live cap, revised by `retune()`. */
  private maxEntries: number;
  /** Insertion-ordered: key -> ms timestamp when first seen. */
  private readonly seen = new Map<string, number>();

  constructor(opts: { maxEntries: number }) {
    if (!Number.isInteger(opts.maxEntries) || opts.maxEntries < 1) {
      throw new RangeError(`maxEntries must be an integer >= 1, got ${opts.maxEntries}`);
    }
    this.maxEntries = opts.maxEntries;
  }

  /**
   * Revise the eviction cap in place (WR-308). The merged value is
   * validated against the construction gate — an illegal cap throws
   * `RangeError` and the live cap is left untouched. A tightened cap
   * takes effect on the next `checkAndRemember`, which evicts the
   * oldest entries past the new cap; a widened cap simply admits more.
   */
  retune(opts: { maxEntries?: number }): void {
    const next = opts.maxEntries ?? this.maxEntries;
    if (!Number.isInteger(next) || next < 1) {
      throw new RangeError(`maxEntries must be an integer >= 1, got ${opts.maxEntries}`);
    }
    this.maxEntries = next;
  }

  checkAndRemember(key: string, nowMs: number, windowMs: number): boolean {
    this.evictExpired(nowMs, windowMs);
    const firstSeen = this.seen.get(key);
    if (firstSeen !== undefined && nowMs - firstSeen < windowMs) {
      return true;
    }
    // Re-seen after expiry: delete + set keeps the insertion order fresh so
    // oldest-eviction drops the truly oldest pairs.
    if (firstSeen !== undefined) this.seen.delete(key);
    this.seen.set(key, nowMs);
    while (this.seen.size > this.maxEntries) {
      const oldest = this.seen.keys().next();
      if (oldest.done) break;
      this.seen.delete(oldest.value);
    }
    return false;
  }

  private evictExpired(at: number, windowMs: number): void {
    // Insertion-ordered: once a pair is still inside its window, every
    // later pair is newer and also inside its window.
    for (const [key, ts] of this.seen) {
      if (at - ts >= windowMs) this.seen.delete(key);
      else break;
    }
  }

  size(): number {
    return this.seen.size;
  }

  /**
   * Live pairs (as of the last check), oldest first. Not part of the
   * `DedupStore` contract — it feeds the WR-79 journal's amortized
   * compaction, which only runs on the default-store path.
   */
  liveEntries(): Array<{ key: string; at: number }> {
    return [...this.seen].map(([key, at]) => ({ key, at }));
  }

  /**
   * Insert a pair with its original first-sight timestamp. Not part of the
   * `DedupStore` contract — it replays WR-79 journal recovery history the
   * store never saw, so recovery keeps each pair's remaining window.
   */
  restore(key: string, atMs: number): void {
    this.seen.set(key, atMs);
  }
}

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
 * WR-108: the window's backing store is pluggable (`DedupOptions.store`,
 * default `InMemoryDedupStore`). `check()` and `stats()` are async because
 * a custom store may be remote — e.g. a Redis adapter shared across
 * processes, where duplicates stay suppressed across instances. `store`
 * and `journalDir` are mutually exclusive: a custom store owns its own
 * durability (Redis persistence, …), `journalDir` is the default store's.
 *
 * WR-308: the window and cap are revisable at runtime via `retune()` —
 * the next `check()` judges by the new values, no restart, no re-judged
 * admissions, and the WR-79 journal is never rewritten.
 *
 * This is inbound-side dedup (the server checks before enqueueing), not a
 * replacement for the nonce/timestamp replay guard (`src/replay.ts`):
 * the guard rejects exact replays by header, the deduplicator suppresses
 * the same business event arriving under a new id.
 */
export class DeliveryDeduplicator {
  /** Mutable (WR-308): the live window, revised by `retune()`. */
  private windowMs: number;
  /** Mutable (WR-308): the live cap, revised by `retune()`. */
  private maxEntries: number;
  private readonly now: () => number;
  private readonly store: DedupStore;
  /**
   * The concrete default store, set only when no custom `store` was
   * injected — the only path where the WR-79 journal may be configured.
   */
  private readonly defaultStore?: InMemoryDedupStore;
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
    if (opts.store !== undefined) {
      // Fail-fast on a store that cannot satisfy the contract.
      if (opts.store === null || typeof opts.store !== "object") {
        throw new TypeError(
          `store must implement DedupStore, got ${opts.store === null ? "null" : typeof opts.store}`
        );
      }
      if (typeof opts.store.checkAndRemember !== "function" || typeof opts.store.size !== "function") {
        throw new TypeError("store must implement DedupStore.checkAndRemember() and size()");
      }
      if (opts.journalDir !== undefined) {
        throw new RangeError(
          "store and journalDir are mutually exclusive (WR-108): journalDir is the default " +
            "store's durability story; a custom DedupStore owns its own durability (e.g. Redis persistence)"
        );
      }
      this.store = opts.store;
    } else {
      const mem = new InMemoryDedupStore({ maxEntries: this.maxEntries });
      this.store = mem;
      this.defaultStore = mem;
    }
    if (opts.journalDir !== undefined) {
      // Reachable only on the default-store path (`store` + `journalDir`
      // throws above), so `defaultStore` is always set here.
      this.journal = new DedupJournal(opts.journalDir, opts.journalEncryptor);
      const { entries, corruptLines } = this.journal.recover(this.windowMs, this.now());
      // Enforce the memory cap on recovered state: keep the newest pairs.
      for (const { key, at } of entries.slice(-this.maxEntries)) {
        this.defaultStore!.restore(key, at);
      }
      this.journalRecovered = Math.min(entries.length, this.maxEntries);
      this.journalCorruptLines = corruptLines;
    }
  }

  /** The live window and cap (WR-308). */
  current(): { windowMs: number; maxEntries: number } {
    return { windowMs: this.windowMs, maxEntries: this.maxEntries };
  }

  /**
   * Revise the dedup window and/or cap in place (WR-308), without
   * restarting the relay: an operator tightens the window during a
   * retry storm or widens it while a flaky upstream re-pushes, and the
   * next `check()` judges by the new values.
   *
   * Semantics, deliberately fail-closed throughout:
   *
   *   - Partial: omitted fields keep their live values; an empty patch
   *     (or values equal to the live ones) changes nothing. Merged
   *     values are validated against the construction gates before
   *     anything applies — an illegal patch throws `RangeError` and the
   *     live values are left completely untouched.
   *   - The window takes effect on the next `check()`: `check()` passes
   *     the live `windowMs` to the store on every call, so in-flight
   *     admissions are never re-judged and already-suppressed events
   *     are never revived. Tightening expires old pairs on their next
   *     check; widening re-admits pairs the store still holds (lazy
   *     expiry never deleted them) under the new window.
   *   - The cap takes effect on the next `check()` too: the default
   *     store evicts the oldest entries past the new cap there.
   *     Widening simply admits more pairs.
   *   - A custom store owns its own cap (WR-108): revising
   *     `maxEntries` with one installed throws `RangeError` and
   *     applies nothing. The window is still revisable — it is the
   *     deduplicator, not the store, that passes `windowMs` per check.
   *   - The journal (WR-79) is not rewritten: journaled pairs are
   *     re-judged against the live window on the next check, exactly
   *     like in-memory pairs.
   *
   * Returns the live values after the revision.
   */
  retune(patch: DedupWindowRevision): { windowMs: number; maxEntries: number } {
    const nextWindowMs = patch.windowMs ?? this.windowMs;
    const nextMaxEntries = patch.maxEntries ?? this.maxEntries;
    // Validate-then-apply: the merged values must pass the construction
    // gates before either live value moves.
    if (!Number.isFinite(nextWindowMs) || nextWindowMs <= 0) {
      throw new RangeError(`windowMs must be > 0, got ${patch.windowMs}`);
    }
    if (!Number.isInteger(nextMaxEntries) || nextMaxEntries < 1) {
      throw new RangeError(`maxEntries must be an integer >= 1, got ${patch.maxEntries}`);
    }
    if (patch.maxEntries !== undefined && this.defaultStore === undefined) {
      throw new RangeError(
        "maxEntries cannot be revised with a custom DedupStore: the cap belongs to the store — " +
          "revise the window only, or restart with a store whose cap fits"
      );
    }
    this.windowMs = nextWindowMs;
    if (patch.maxEntries !== undefined) {
      this.defaultStore!.retune({ maxEntries: nextMaxEntries });
    }
    this.maxEntries = nextMaxEntries;
    return this.current();
  }

  /** SHA-256 hex digest of a payload (the stable half of the dedup key). */
  static hashPayload(payload: Buffer): string {
    return createHash("sha256").update(payload).digest("hex");
  }

  /**
   * Record `(endpoint, payloadHash)`. Resolves `true` when the pair was
   * already seen inside the window — the delivery must be suppressed —
   * `false` on first sight (deliver it). A pair seen again *after* its
   * window expired counts as new and restarts the window. Async (WR-108):
   * a custom store may answer from across the network.
   */
  async check(endpoint: string, payloadHash: string): Promise<boolean> {
    const at = this.now();
    this.checked += 1;
    const key = `${endpoint}\n${payloadHash}`;
    if (await this.store.checkAndRemember(key, at, this.windowMs)) {
      this.suppressed += 1;
      return true;
    }
    if (this.journal !== undefined) {
      this.journal.appendSeen(key, at);
      this.journaledSinceOpen += 1;
      // Amortized compaction: the store holds only live pairs (expired
      // were evicted above), so the file stays proportional to the window.
      if (this.journal.shouldCompact) {
        this.journal.compact(this.defaultStore!.liveEntries());
      }
    }
    return false;
  }

  /**
   * Observability: pairs checked, duplicates suppressed, pairs tracked,
   * and the live window/cap (WR-308 — `windowMs`/`maxEntries` always
   * report the values the next `check()` will judge by).
   * `journal` is present only when `journalDir` was configured: pairs
   * restored at construction, journal lines skipped as corrupt during
   * recovery, journal writes that failed (counted, never thrown), and
   * first-sight pairs journaled since this instance opened. Async (WR-108):
   * the store's `size()` may be remote.
   */
  async stats(): Promise<{
    checked: number;
    suppressed: number;
    tracked: number;
    windowMs: number;
    maxEntries: number;
    journal?: {
      recovered: number;
      corruptLines: number;
      writeErrors: number;
      journaled: number;
    };
  }> {
    const base = {
      checked: this.checked,
      suppressed: this.suppressed,
      tracked: await this.store.size(),
      windowMs: this.windowMs,
      maxEntries: this.maxEntries,
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
