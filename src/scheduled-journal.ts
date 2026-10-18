/**
 * Durable scheduled-delivery journal (WR-133).
 *
 * Opt-in crash recovery for the WR-57 `deliver_at` delay queue: parked
 * one-shot deliveries are journaled to an append-only JSONL file, so a
 * process restart resumes them instead of losing accepted work. Disabled
 * by default — without `durableScheduledDir` the scheduler keeps its
 * existing purely in-memory behavior (documented honestly in the README).
 *
 * Journal protocol (one JSON object per line, `v: 1`):
 * - `park`   — a one-shot item was parked: `{id, deliverAt, item}` where
 *              `item` is the delivery snapshot (see below).
 * - `cancel` — a parked item was canceled: tombstone, never resurrected.
 * - `fired`  — the item's instant arrived and it left the journal for the
 *              normal delivery path (superseded).
 *
 * Recovery folds the lines in order; the latest line per id wins. Items
 * past-due at recovery (`deliverAt <= now`) skip the delay queue and go
 * straight to the normal delivery path — past-due semantics match the
 * live intake (see `RetryQueue.enqueue`: a past-due `deliver_at` never
 * parks). Nothing is attempted while parked, so a recovered item always
 * carries zero consumed attempts — `attempts` is intentionally absent
 * from the journal (contrast the WR-49 queue journal, whose retry lines
 * preserve consumed attempts).
 *
 * Recurring cron schedules (WR-80) are NOT journaled: future occurrences
 * do not exist yet as deliveries, and the registrations stay in-memory —
 * the same honest limitation the WR-57 docs already carry.
 *
 * Payload secrecy: the same rule as the WR-49 durable queue — sealed with
 * the queue's WR-11 `PayloadEncryptor` when one is configured, and
 * base64-encoded in the clear otherwise (equally worth an encryptor in
 * production).
 *
 * Durability: every append is followed by an fsync before the call
 * returns, so a returned `park` is crash-durable. Journal appends never
 * throw — a full disk degrades to in-memory-only parking and is counted
 * in `writeErrors`, never a delivery failure. Crash-safety ordering:
 * `park` and `cancel` lines are written *before* the in-memory mutation
 * they describe, so a crash between the two can only cause a redelivery
 * (at-least-once), never a loss. `fired` is the deliberate exception —
 * it is written *after* the item entered the normal delivery path: a
 * crash in between leaves the `park` line live and recovery re-parks
 * (at-least-once), while the reverse order could lose the delivery
 * entirely.
 *
 * The journal compacts itself: superseded lines are rewritten away when
 * they outnumber live state (amortized), and recovery always compacts.
 * Compaction rewrites the original `park` line texts verbatim — payloads
 * are never re-encrypted, so a rotated key cannot strand live items.
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
import type { RetryItem } from "./retry.ts";
import type { TraceContext } from "./trace-context.ts";

/** Journal file name inside the durable scheduled-delivery directory. */
export const SCHEDULED_JOURNAL_FILE = "scheduled.jsonl";

/** How many superseded lines trigger an amortized compaction pass. */
export const SCHEDULED_JOURNAL_COMPACT_THRESHOLD = 4096;

/** Payload as stored in the journal: sealed, or base64 in the clear. */
export type ScheduledStoredPayload =
  | EncryptedPayload
  | { encoding: "base64"; data: string };

/** The parked-item snapshot carried by a `park` line. */
export interface ScheduledJournalItem {
  id: string;
  /** Absolute fire instant, epoch ms (rounded at journal time). */
  deliverAt: number;
  payload: ScheduledStoredPayload;
  targetUrl: string;
  headers: Record<string, string | string[] | undefined>;
  priority?: "normal" | "urgent";
  traceId?: string;
  tenantId?: string;
  /** WR-76: queue-admission instant; the deadline clock survives restarts. */
  enqueuedAt?: number;
  /** WR-98: caller-propagated W3C trace context; validated on recover. */
  traceContext?: TraceContext;
  /** WR-107: mesh hops already traversed; the hop count survives restarts. */
  meshHops?: number;
}

export type ScheduledJournalLine =
  | { v: 1; op: "park"; id: string; deliverAt: number; item: ScheduledJournalItem }
  | { v: 1; op: "cancel"; id: string }
  | { v: 1; op: "fired"; id: string };

/** One parked item recovered from the journal. */
export interface RecoveredScheduledItem {
  id: string;
  payload: Buffer;
  targetUrl: string;
  headers: Record<string, string | string[] | undefined>;
  deliverAt: number;
  priority?: "normal" | "urgent";
  traceId?: string;
  tenantId?: string;
  enqueuedAt?: number;
  traceContext?: TraceContext;
  meshHops?: number;
}

/** What `ScheduledDeliveryJournal.recover()` found. */
export interface ScheduledJournalRecovery {
  items: RecoveredScheduledItem[];
  /** Lines skipped as corrupt (torn writes, bad JSON, undecryptable payloads). */
  skippedLines: number;
  /** Journal lines read (including superseded ones, pre-compaction). */
  linesRead: number;
}

/** True when `v` looks like a sealed {@link EncryptedPayload}. */
function isSealed(v: ScheduledStoredPayload): v is EncryptedPayload {
  return (v as EncryptedPayload).alg !== undefined;
}

/**
 * Defensive shape check for a journaled trace context — the journal is
 * untrusted input (it may predate the feature or be hand-edited), so a
 * malformed value is dropped rather than trusted (same rule as the WR-49
 * queue journal).
 */
function isTraceContext(value: unknown): value is TraceContext {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.traceId === "string" &&
    typeof v.spanId === "string" &&
    typeof v.sampled === "boolean" &&
    (v.traceState === undefined || typeof v.traceState === "string")
  );
}

/**
 * Append-only JSONL journal for parked scheduled deliveries. All methods
 * are synchronous and never throw: durability first, delivery never
 * blocked on the disk.
 */
export class ScheduledDeliveryJournal {
  private readonly path: string;
  private readonly encryptor?: PayloadEncryptor;
  private linesWritten = 0;
  private linesAtLastCompact = 0;
  private writeErrors = 0;

  /**
   * `dir` is created (recursively) when missing — a missing directory is
   * normal on first boot; an *uncreatable* one is an operator
   * misconfiguration and throws, fail-fast at construction (same rule as
   * the WR-49 `QueueJournal`).
   */
  constructor(dir: string, encryptor?: PayloadEncryptor) {
    mkdirSync(dir, { recursive: true });
    this.path = join(dir, SCHEDULED_JOURNAL_FILE);
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
    return this.linesWritten - this.linesAtLastCompact >= SCHEDULED_JOURNAL_COMPACT_THRESHOLD;
  }

  private seal(payload: Buffer): ScheduledStoredPayload {
    if (this.encryptor) return this.encryptor.encrypt(payload);
    return { encoding: "base64", data: payload.toString("base64") };
  }

  private append(line: ScheduledJournalLine): void {
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
      // The in-memory scheduler is authoritative; a failed journal write
      // degrades to non-durable parking, never a delivery failure.
      this.writeErrors += 1;
    }
  }

  /**
   * Journal a one-shot item entering the delay queue. The item's
   * `deliverAt` must be set (the caller parks only future instants).
   */
  appendPark(item: RetryItem): void {
    const deliverAt = item.deliverAt;
    if (typeof deliverAt !== "number" || !Number.isFinite(deliverAt)) {
      // Fail-closed on a programming error: parking without a fire
      // instant must never be silently unjournaled. This throws out of
      // `appendPark` (unlike disk failures) because it signals a bug in
      // the caller, not a disk problem.
      throw new RangeError(
        `scheduled journal: cannot park item ${item.id} without a finite deliverAt`
      );
    }
    this.append({
      v: 1,
      op: "park",
      id: item.id,
      deliverAt: Math.round(deliverAt),
      item: {
        id: item.id,
        deliverAt: Math.round(deliverAt),
        payload: this.seal(item.payload),
        targetUrl: item.targetUrl,
        headers: item.headers,
        ...(item.priority !== undefined ? { priority: item.priority } : {}),
        ...(item.traceId !== undefined ? { traceId: item.traceId } : {}),
        ...(item.tenantId !== undefined ? { tenantId: item.tenantId } : {}),
        ...(item.enqueuedAt !== undefined ? { enqueuedAt: item.enqueuedAt } : {}),
        ...(item.traceContext !== undefined && isTraceContext(item.traceContext)
          ? { traceContext: item.traceContext }
          : {}),
        ...(item.meshHops !== undefined ? { meshHops: item.meshHops } : {}),
      },
    });
  }

  /** A parked item was canceled: tombstone, never resurrected. */
  appendCancel(id: string): void {
    this.append({ v: 1, op: "cancel", id });
  }

  /**
   * The item's instant arrived and it left the journal for the normal
   * delivery path. The caller writes this *after* the item entered the
   * normal path (see the module doc): a crash in between re-parks
   * (at-least-once) instead of losing the delivery.
   */
  appendFired(id: string): void {
    this.append({ v: 1, op: "fired", id });
  }

  /**
   * Fold the journal into live parked items. Malformed lines, unknown
   * ops, and payloads that no longer decrypt (e.g. the encryptor key was
   * rotated between restarts) are skipped and counted — a corrupt line
   * never prevents recovery of the rest. The journal is compacted down
   * to the recovered live state before returning.
   */
  recover(): ScheduledJournalRecovery {
    const folded = this.fold();
    const items: RecoveredScheduledItem[] = [];
    let skippedLines = folded.skippedLines;
    for (const [id, journalItem] of folded.live) {
      const payload = this.unseal(journalItem.payload);
      if (payload === undefined) {
        skippedLines += 1;
        continue;
      }
      items.push({
        id,
        payload,
        targetUrl: journalItem.targetUrl,
        headers: journalItem.headers ?? {},
        deliverAt: journalItem.deliverAt,
        ...(journalItem.priority !== undefined ? { priority: journalItem.priority } : {}),
        ...(journalItem.traceId !== undefined ? { traceId: journalItem.traceId } : {}),
        ...(journalItem.tenantId !== undefined ? { tenantId: journalItem.tenantId } : {}),
        ...(journalItem.enqueuedAt !== undefined ? { enqueuedAt: journalItem.enqueuedAt } : {}),
        ...(journalItem.traceContext !== undefined && isTraceContext(journalItem.traceContext)
          ? { traceContext: journalItem.traceContext }
          : {}),
        ...(journalItem.meshHops !== undefined ? { meshHops: journalItem.meshHops } : {}),
      });
    }
    // Recovery rewrites the journal down to live state: superseded lines
    // from before the crash never accumulate.
    this.rewrite([...folded.liveText.values()]);
    return { items, skippedLines, linesRead: folded.linesRead };
  }

  /**
   * Amortized compaction: rewrite the journal down to its current live
   * state when superseded lines outnumber the threshold. The original
   * `park` line texts are rewritten verbatim — payloads are never
   * re-encrypted, so a rotated key cannot strand live items.
   */
  maybeCompact(): void {
    if (!this.shouldCompact) return;
    this.compact();
  }

  /** Forced compaction: rewrite the journal down to its live state now. */
  compact(): void {
    this.rewrite([...this.fold().liveText.values()]);
  }

  /** Fold the journal: latest line per id wins; keeps live lines' original texts. */
  private fold(): {
    live: Map<string, ScheduledJournalItem>;
    liveText: Map<string, string>;
    skippedLines: number;
    linesRead: number;
  } {
    const live = new Map<string, ScheduledJournalItem>();
    const liveText = new Map<string, string>();
    let skippedLines = 0;
    let linesRead = 0;
    let raw = "";
    try {
      raw = readFileSync(this.path, "utf8");
    } catch {
      return { live, liveText, skippedLines, linesRead };
    }
    for (const text of raw.split("\n")) {
      if (text.trim() === "") continue;
      linesRead += 1;
      let line: ScheduledJournalLine;
      try {
        line = JSON.parse(text) as ScheduledJournalLine;
      } catch {
        skippedLines += 1;
        continue;
      }
      if (!line || line.v !== 1 || typeof line.id !== "string" || line.id.length === 0) {
        skippedLines += 1;
        continue;
      }
      switch (line.op) {
        case "park": {
          const item = line.item;
          if (
            item === undefined ||
            typeof item.deliverAt !== "number" ||
            !Number.isFinite(item.deliverAt) ||
            typeof item.targetUrl !== "string" ||
            item.targetUrl.length === 0
          ) {
            skippedLines += 1;
            continue;
          }
          live.set(line.id, item);
          liveText.set(line.id, text);
          break;
        }
        case "cancel":
        case "fired":
          // Tombstones supersede any earlier park line; a line for an
          // unknown id is a harmless no-op (e.g. a cancel raced a fire).
          live.delete(line.id);
          liveText.delete(line.id);
          break;
        default:
          skippedLines += 1;
      }
    }
    return { live, liveText, skippedLines, linesRead };
  }

  /** Rewrite the journal file to exactly `lines` (one JSONL object each). */
  private rewrite(lines: string[]): void {
    try {
      const fd = openSync(this.path, "w");
      try {
        if (lines.length > 0) writeSync(fd, lines.join("\n") + "\n");
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      this.linesAtLastCompact = this.linesWritten;
    } catch {
      this.writeErrors += 1;
    }
  }

  private unseal(stored: ScheduledStoredPayload): Buffer | undefined {
    try {
      if (isSealed(stored)) {
        if (this.encryptor === undefined) return undefined;
        return this.encryptor.decrypt(stored);
      }
      if (
        stored !== null &&
        typeof stored === "object" &&
        (stored as { encoding?: unknown }).encoding === "base64" &&
        typeof (stored as { data?: unknown }).data === "string"
      ) {
        return Buffer.from((stored as { data: string }).data, "base64");
      }
      return undefined;
    } catch {
      // An undecryptable payload (e.g. the key was rotated between
      // restarts) fails the item, not the recovery.
      return undefined;
    }
  }
}
