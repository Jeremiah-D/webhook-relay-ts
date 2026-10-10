/**
 * Durable delivery queue journal (WR-49).
 *
 * Opt-in crash recovery for {@link RetryQueue}: pending and backoff-waiting
 * deliveries plus the dead-letter list are journaled to an append-only
 * JSONL file, so a process restart resumes delivery instead of losing
 * accepted work. Disabled by default — without `durableQueueDir` the
 * queue keeps its existing purely in-memory behavior.
 *
 * Journal protocol (one JSON object per line, `v: 1`):
 * - `enqueue`   — an item entered the live queue (full snapshot; attempt 0).
 * - `retry`     — a retry/backoff timer was armed: `{id, attempt, nextAt}`
 *                 where `attempt` is the attempts consumed so far and
 *                 `nextAt` the absolute ms epoch the timer fires at.
 * - `delivered` — terminal success; the item leaves the journal.
 * - `dead_letter` — the item moved to the dead-letter list (full entry).
 * - `replayed`  — a dead letter was re-queued; the dead-letter line is
 *                 superseded (the re-queued item gets its own `enqueue`).
 *
 * Recovery folds the lines in order; the latest line per id wins. A
 * restored retry resumes with its *remaining* backoff (`nextAt - now`,
 * floored at 0) and its consumed attempt count is preserved — attempts
 * are never reset by a restart.
 *
 * Payload secrecy: the payload is sealed with the queue's WR-11
 * `PayloadEncryptor` when one is configured (the same encryptor that
 * seals dead-letter payloads); without an encryptor the payload is stored
 * base64-encoded in the clear — exactly the dead-letter behavior, and
 * equally worth an encryptor in production.
 *
 * Durability: every append is followed by an fsync before the call
 * returns, so a returned enqueue/retry/dead-letter is crash-durable.
 * Journal appends never throw — a full disk or a torn write degrades to
 * in-memory-only delivery and is counted in `writeErrors`, never a
 * delivery failure. Crash-safety ordering: journal lines are written
 * *before* the in-memory mutation they describe, so a crash between the
 * two can only cause a redelivery (at-least-once), never a loss.
 *
 * The journal compacts itself: superseded lines are rewritten away when
 * they outnumber live state (amortized), and recovery always compacts.
 */

import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { join } from "node:path";
import type { PayloadEncryptor, EncryptedPayload } from "./encrypt.ts";
import type { RetryItem, DeadLetterEntry } from "./retry.ts";

/** Journal file name inside the durable queue directory. */
export const DURABLE_QUEUE_FILE = "queue.jsonl";

/** How many superseded lines trigger an amortized compaction pass. */
export const DURABLE_QUEUE_COMPACT_THRESHOLD = 4096;

/** Payload as stored in the journal: sealed, or base64 in the clear. */
export type StoredPayload = EncryptedPayload | { encoding: "base64"; data: string };

/** The live-queue item snapshot carried by an `enqueue` line. */
export interface JournalEnqueueItem {
  id: string;
  payload: StoredPayload;
  targetUrl: string;
  headers: Record<string, string | string[] | undefined>;
  priority?: "normal" | "urgent";
  traceId?: string;
  tenantId?: string;
}

/** The dead-letter snapshot carried by a `dead_letter` line. */
export interface JournalDeadLetter {
  id: string;
  traceId?: string;
  payload: StoredPayload;
  targetUrl: string;
  headers: Record<string, string | string[] | undefined>;
  priority?: "normal" | "urgent";
  tenantId?: string;
  attempts: number;
  lastError: string;
  failureClass: string;
  deadLetteredAt: string;
  payloadBytes: number;
  failoverEndpoint?: string;
}

export type QueueJournalLine =
  | { v: 1; op: "enqueue"; id: string; item: JournalEnqueueItem }
  | { v: 1; op: "retry"; id: string; attempt: number; nextAt: number }
  | { v: 1; op: "delivered"; id: string }
  | { v: 1; op: "dead_letter"; id: string; entry: JournalDeadLetter }
  | { v: 1; op: "replayed"; id: string };

/** One live item recovered from the journal. */
export interface RecoveredItem {
  id: string;
  payload: Buffer;
  targetUrl: string;
  headers: Record<string, string | string[] | undefined>;
  priority?: "normal" | "urgent";
  traceId?: string;
  tenantId?: string;
  /** Attempts consumed before the crash — never reset by recovery. */
  attempt: number;
  /** Absolute ms epoch the pending retry fires at, if a retry was armed. */
  nextAt?: number;
}

/** What `QueueJournal.recover()` found. */
export interface QueueRecovery {
  items: RecoveredItem[];
  deadLetters: DeadLetterEntry[];
  /** Lines skipped as corrupt (torn writes, bad JSON, undecryptable payloads). */
  skippedLines: number;
  /** Journal lines read (including superseded ones, pre-compaction). */
  linesRead: number;
}

/** True when `v` looks like a sealed {@link EncryptedPayload}. */
function isSealed(v: StoredPayload): v is EncryptedPayload {
  return (v as EncryptedPayload).alg !== undefined;
}

/**
 * Append-only JSONL journal for the delivery queue. All methods are
 * synchronous and never throw: durability first, delivery never blocked
 * on the disk.
 */
export class QueueJournal {
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
    this.path = join(dir, DURABLE_QUEUE_FILE);
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

  /** Appends that failed (counted, never thrown). */
  get errors(): number {
    return this.writeErrors;
  }

  /** True when superseded lines outnumber the compaction threshold. */
  get shouldCompact(): boolean {
    return this.linesWritten - this.linesAtLastCompact >= DURABLE_QUEUE_COMPACT_THRESHOLD;
  }

  private seal(payload: Buffer): StoredPayload {
    if (this.encryptor) return this.encryptor.encrypt(payload);
    return { encoding: "base64", data: payload.toString("base64") };
  }

  private append(line: QueueJournalLine): void {
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
      // The in-memory queue is authoritative; a failed journal write
      // degrades to non-durable delivery, never a delivery failure.
      this.writeErrors += 1;
    }
  }

  appendEnqueue(item: RetryItem & { attempt: number }): void {
    this.append({
      v: 1,
      op: "enqueue",
      id: item.id,
      item: {
        id: item.id,
        payload: this.seal(item.payload),
        targetUrl: item.targetUrl,
        headers: item.headers,
        ...(item.priority !== undefined ? { priority: item.priority } : {}),
        ...(item.traceId !== undefined ? { traceId: item.traceId } : {}),
        ...(item.tenantId !== undefined ? { tenantId: item.tenantId } : {}),
      },
    });
  }

  appendRetry(id: string, attempt: number, nextAtMs: number): void {
    this.append({ v: 1, op: "retry", id, attempt, nextAt: Math.round(nextAtMs) });
  }

  appendDelivered(id: string): void {
    this.append({ v: 1, op: "delivered", id });
  }

  appendDeadLetter(entry: DeadLetterEntry): void {
    // WR-11: when the payload was sealed at dead-letter time,
    // `entry.payload` is an empty placeholder and the envelope rides
    // along; otherwise the clear payload is journaled like an enqueue.
    const payload: StoredPayload =
      entry.encryptedPayload !== undefined
        ? entry.encryptedPayload
        : this.seal(entry.payload);
    this.append({
      v: 1,
      op: "dead_letter",
      id: entry.id,
      entry: {
        id: entry.id,
        payload,
        targetUrl: entry.targetUrl,
        headers: entry.headers,
        ...(entry.priority !== undefined ? { priority: entry.priority } : {}),
        ...(entry.traceId !== undefined ? { traceId: entry.traceId } : {}),
        ...(entry.tenantId !== undefined ? { tenantId: entry.tenantId } : {}),
        attempts: entry.attempts,
        lastError: entry.lastError,
        failureClass: entry.failureClass,
        deadLetteredAt: entry.deadLetteredAt,
        payloadBytes: entry.payloadBytes,
        ...(entry.failoverEndpoint !== undefined
          ? { failoverEndpoint: entry.failoverEndpoint }
          : {}),
      },
    });
  }

  appendReplayed(id: string): void {
    this.append({ v: 1, op: "replayed", id });
  }

  /**
   * Fold the journal into live items + dead letters. Malformed lines,
   * unknown ops, and payloads that no longer decrypt (e.g. the encryptor
   * key was rotated between restarts) are skipped and counted — a corrupt
   * line never prevents recovery of the rest.
   */
  recover(): QueueRecovery {
    let raw = "";
    try {
      raw = readFileSync(this.path, "utf8");
    } catch {
      return { items: [], deadLetters: [], skippedLines: 0, linesRead: 0 };
    }
    const live = new Map<string, RecoveredItem & { hasRetry: boolean }>();
    const dead = new Map<string, DeadLetterEntry>();
    let skippedLines = 0;
    let linesRead = 0;
    for (const text of raw.split("\n")) {
      if (text.trim() === "") continue;
      linesRead += 1;
      let line: QueueJournalLine;
      try {
        line = JSON.parse(text) as QueueJournalLine;
      } catch {
        skippedLines += 1;
        continue;
      }
      if (!line || line.v !== 1 || typeof line.id !== "string") {
        skippedLines += 1;
        continue;
      }
      switch (line.op) {
        case "enqueue": {
          const payload = this.openPayload(line.item?.payload);
          if (payload === undefined || typeof line.item?.targetUrl !== "string") {
            skippedLines += 1;
            break;
          }
          live.set(line.id, {
            id: line.id,
            payload,
            targetUrl: line.item.targetUrl,
            headers: line.item.headers ?? {},
            priority: line.item.priority,
            traceId: line.item.traceId,
            tenantId: line.item.tenantId,
            attempt: 0,
            hasRetry: false,
          });
          break;
        }
        case "retry": {
          const cur = live.get(line.id);
          if (
            cur === undefined ||
            !Number.isInteger(line.attempt) ||
            line.attempt < 0 ||
            !Number.isFinite(line.nextAt)
          ) {
            skippedLines += 1;
            break;
          }
          cur.attempt = line.attempt;
          cur.nextAt = line.nextAt;
          cur.hasRetry = true;
          break;
        }
        case "delivered":
          live.delete(line.id);
          break;
        case "dead_letter": {
          const stored = line.entry?.payload;
          if (stored === undefined || typeof line.entry?.targetUrl !== "string") {
            skippedLines += 1;
            break;
          }
          // A sealed dead-letter payload restores sealed: like the live
          // WR-11 dead-letter list, decryption waits for replay. Only a
          // clear payload needs opening here.
          const sealed = isSealed(stored);
          const payload = sealed ? Buffer.alloc(0) : this.openPayload(stored);
          if (payload === undefined) {
            skippedLines += 1;
            break;
          }
          live.delete(line.id);
          const e = line.entry;
          dead.set(line.id, {
            id: line.id,
            traceId: e.traceId,
            payload,
            targetUrl: e.targetUrl,
            headers: e.headers ?? {},
            priority: e.priority,
            tenantId: e.tenantId,
            attempts: e.attempts,
            lastError: e.lastError,
            failureClass: e.failureClass as DeadLetterEntry["failureClass"],
            deadLetteredAt: e.deadLetteredAt,
            payloadBytes: e.payloadBytes,
            ...(sealed ? { encryptedPayload: stored } : {}),
            ...(e.failoverEndpoint !== undefined ? { failoverEndpoint: e.failoverEndpoint } : {}),
          });
          break;
        }
        case "replayed":
          dead.delete(line.id);
          break;
        default:
          skippedLines += 1;
      }
    }
    // Strip the fold bookkeeping before handing items out.
    const items = [...live.values()].map(({ hasRetry: _h, ...rest }) => rest);
    return { items, deadLetters: [...dead.values()], skippedLines, linesRead };
  }

  /**
   * Rewrite the journal keeping only live state: one `enqueue` (+ one
   * `retry` when a retry is pending) per live item, one `dead_letter`
   * per dead letter. The queue supplies its in-memory live state, so
   * compaction never depends on a prior recover and cannot drop items
   * journaled after the last recovery. Called after every recovery and
   * amortized during operation; `force` rewrites unconditionally (e.g.
   * on shutdown).
   */
  compact(items: CompactItem[], deadLetters: DeadLetterEntry[], force = false): void {
    if (!force && this.linesWritten - this.linesAtLastCompact < DURABLE_QUEUE_COMPACT_THRESHOLD) {
      return;
    }
    try {
      const lines: string[] = [];
      const push = (l: QueueJournalLine) => lines.push(JSON.stringify(l) + "\n");
      for (const item of items) {
        push({
          v: 1,
          op: "enqueue",
          id: item.id,
          item: {
            id: item.id,
            payload: this.seal(item.payload),
            targetUrl: item.targetUrl,
            headers: item.headers,
            ...(item.priority !== undefined ? { priority: item.priority } : {}),
            ...(item.traceId !== undefined ? { traceId: item.traceId } : {}),
            ...(item.tenantId !== undefined ? { tenantId: item.tenantId } : {}),
          },
        });
        if (item.nextAt !== undefined) {
          push({ v: 1, op: "retry", id: item.id, attempt: item.attempt, nextAt: Math.round(item.nextAt) });
        }
      }
      for (const entry of deadLetters) {
        const payload: StoredPayload =
          entry.encryptedPayload !== undefined ? entry.encryptedPayload : this.seal(entry.payload);
        push({
          v: 1,
          op: "dead_letter",
          id: entry.id,
          entry: {
            id: entry.id,
            payload,
            targetUrl: entry.targetUrl,
            headers: entry.headers,
            ...(entry.priority !== undefined ? { priority: entry.priority } : {}),
            ...(entry.traceId !== undefined ? { traceId: entry.traceId } : {}),
            ...(entry.tenantId !== undefined ? { tenantId: entry.tenantId } : {}),
            attempts: entry.attempts,
            lastError: entry.lastError,
            failureClass: entry.failureClass,
            deadLetteredAt: entry.deadLetteredAt,
            payloadBytes: entry.payloadBytes,
            ...(entry.failoverEndpoint !== undefined
              ? { failoverEndpoint: entry.failoverEndpoint }
              : {}),
          },
        });
      }
      const fd = openSync(this.path, "w");
      try {
        for (const l of lines) writeSync(fd, l);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      this.linesAtLastCompact = this.linesWritten;
    } catch {
      this.writeErrors += 1;
    }
  }

  /**
   * Open one stored payload back into bytes. Returns `undefined` when the
   * payload cannot be opened (sealed but no encryptor configured, or a
   * rotated key): the caller skips the line and counts it.
   */
  private openPayload(stored: StoredPayload | undefined): Buffer | undefined {
    if (!stored || typeof stored !== "object") return undefined;
    try {
      if (isSealed(stored)) {
        if (!this.encryptor) return undefined;
        return this.encryptor.decrypt(stored);
      }
      if (stored.encoding === "base64" && typeof stored.data === "string") {
        return Buffer.from(stored.data, "base64");
      }
      return undefined;
    } catch {
      return undefined;
    }
  }
}

/** Info delivered to `onQueueRestored` after a journal recovery. */
export interface QueueRestoredInfo {
  dir: string;
  restoredItems: number;
  restoredDeadLetters: number;
  /** Restored items that had a retry timer armed at crash time. */
  restoredRetries: number;
  skippedLines: number;
}

/** Live item data for a compaction pass (supplied by the queue). */
export interface CompactItem {
  id: string;
  payload: Buffer;
  targetUrl: string;
  headers: Record<string, string | string[] | undefined>;
  priority?: "normal" | "urgent";
  traceId?: string;
  tenantId?: string;
  attempt: number;
  /** Absolute ms epoch of the armed retry timer, when one is pending. */
  nextAt?: number;
}
