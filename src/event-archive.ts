/**
 * Delivery-event archive (WR-55).
 *
 * Persistent history for the delivery lifecycle events the queue emits
 * (`delivered` / `retrying` / `dead_letter`, see
 * {@link RetryQueue.subscribeDeliveryEvents}). The server subscribes a
 * {@link DeliveryEventArchiver} to its queue when `eventArchive` is
 * configured, and serves the history at `GET /events/archive`.
 *
 * Relationship to the other event surfaces:
 * - `GET /events` (SSE, WR-16) is the **live stream**: in-memory
 *   subscriptions, real-time frames, no replay of past events.
 * - The archive is the **durable event history**: every subscribed event is
 *   appended to `<dir>/events.jsonl` and survives process restarts.
 * - The audit log (`GET /audit`) records **operator actions** (accepted,
 *   replayed, paused, config changes…); the archive records the **delivery
 *   event stream**. Decoupled by design — they answer different questions.
 *
 * Line format: one JSON object per line —
 * `{seq, type, id, traceId, tenant?, targetUrl, attempts, at, error?}`.
 * `seq` (WR-123) is a dense, strictly increasing per-event sequence
 * assigned at record time: it is the SSE `Last-Event-ID` cursor for
 * reconnect replay. Lines written before WR-123 (no `seq`) are assigned
 * seqs in file order once, at construction — after that every line has
 * one. Rolling retention may evict old lines, so `seq` is dense only
 * between retention passes; `minSeq`/`maxSeq` always describe what is
 * actually on disk.
 *
 * Rolling retention (both opt-in):
 * - `maxAgeMs`: lines whose event `at` is older than `now - maxAgeMs` are
 *   dropped.
 * - `maxBytes`: when the file grows past this many bytes, the oldest lines
 *   (file order — appends are chronological) are dropped first. The newest
 *   line is always kept, so a pathologically small `maxBytes` degrades to a
 *   one-line archive instead of an empty one.
 * Retention runs amortized on the append path (a full pass at most every
 * {@link RETENTION_CHECK_EVERY} appends, or immediately when `maxBytes` is
 * exceeded), plus once at construction so a restart applies pending
 * retention. Use {@link DeliveryEventArchiver.compactNow} to force a pass.
 *
 * Crash semantics (at-least-once, honestly not exactly-once):
 * - Appends are synchronous and never throw: a failed write is counted in
 *   `writeErrors` and swallowed, so a full disk can never fail a delivery.
 *   Appends are *not* fsync'd — an OS crash may lose the unwritten tail.
 *   (Delivery state itself is unaffected; the archive is observability.)
 * - Retention rewrites via "write temp file + fsync + atomic rename", so a
 *   crash before the rename leaves the previous complete file: retention
 *   simply didn't happen and is retried later — never half-applied.
 * - The archive never dedupes: if the same event is recorded twice (two
 *   archiver instances on one queue, a double `record()` call), both lines
 *   persist and queries return both. A torn line from a crash mid-append is
 *   skipped on read. Queries therefore see every successfully appended
 *   event *at least* once, but must not assume exactly-once.
 * - Restart recovery: opening the same directory re-reads `events.jsonl`,
 *   so history survives restarts; a stale `events.jsonl.tmp` from a crash
 *   mid-retention is removed at construction (it is never the source of
 *   truth).
 */

import {
  appendFileSync,
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
  writeSync,
} from "node:fs";
import { join } from "node:path";
import type { DeliveryEvent, DeliveryEventType } from "./retry.ts";

/** What a WR-188 sealed segment file name carries: `<yyyymmdd>-seq-<min>-<max>.jsonl`. */
export interface SealedSegmentName {
  /** UTC date of the earliest sealed event, `yyyymmdd`. */
  date: string;
  /** Smallest event seq sealed in the segment. */
  seqMin: number;
  /** Largest event seq sealed in the segment. */
  seqMax: number;
}

/**
 * WR-188: parse a sealed segment file name back into its date/seq-range.
 * Returns `undefined` for anything that is not a sealed segment
 * (temp files, the live `events.jsonl`, uploaded markers, …).
 */
export function parseSealedSegmentName(fileName: string): SealedSegmentName | undefined {
  const m = /^(\d{8})-seq-(\d+)-(\d+)(?:-\d+)?\.jsonl$/.exec(fileName);
  if (m === null) return undefined;
  const seqMin = Number(m[2]);
  const seqMax = Number(m[3]);
  if (!Number.isSafeInteger(seqMin) || !Number.isSafeInteger(seqMax) || seqMin < 1 || seqMax < seqMin) {
    return undefined;
  }
  return { date: m[1], seqMin, seqMax };
}

/** Archive file name inside the archive directory. */
export const EVENT_ARCHIVE_FILE = "events.jsonl";

/** Temp file used for atomic retention rewrites (same directory, so rename is atomic). */
const ARCHIVE_TMP_SUFFIX = ".tmp";

/** Amortization: a full retention pass runs at most this often on the append path. */
const RETENTION_CHECK_EVERY = 64;

/**
 * Minimal event source surface — satisfied by {@link RetryQueue} and by
 * test fakes. Duck-typed so this module has no runtime dependency on
 * `retry.ts`.
 */
export interface DeliveryEventSource {
  subscribeDeliveryEvents(listener: (e: DeliveryEvent) => void): () => void;
}

export interface EventArchiveOptions {
  /** Directory holding `events.jsonl`. Created recursively when missing. */
  dir: string;
  /** Opt-in: drop lines whose event `at` predates `now - maxAgeMs`. */
  maxAgeMs?: number;
  /** Opt-in: drop oldest lines first when the file exceeds this many bytes. */
  maxBytes?: number;
  /** Event source to subscribe at construction (e.g. the server's queue). */
  source?: DeliveryEventSource;
  /**
   * WR-188: opt-in segment sealing. When a retention pass evicts lines,
   * they are written verbatim to one sealed segment file under this
   * directory instead of being discarded, so the archive's time/size
   * rolling becomes a cold-storage pipeline (see `src/archive-s3.ts`
   * for the S3-compatible offload). Unset: evicted lines are dropped,
   * exactly as before. The directory is created recursively when
   * missing; an uncreatable directory throws at construction.
   */
  sealedDir?: string;
  /**
   * WR-188: fired once per sealed segment, after the segment file is
   * durably written and the live archive rewritten. Error-isolated:
   * a throwing listener is swallowed — sealing/upload bookkeeping can
   * never fail a retention pass (and therefore never a delivery).
   * The server wires this to the S3 offloader's fire-and-forget scan.
   */
  onSegmentSealed?: (localPath: string) => void;
}

/** Filters for {@link DeliveryEventArchiver.query}. All filters are ANDed. */
export interface EventArchiveQuery {
  /** ISO-8601 lower bound (inclusive) on the event `at`. */
  since?: string;
  /** ISO-8601 upper bound (inclusive) on the event `at`. */
  until?: string;
  /** Exact match on `targetUrl`. */
  endpoint?: string;
  /** One of `delivered` / `retrying` / `dead_letter`. */
  event?: DeliveryEventType;
}

export interface EventArchiveStats {
  /** Successful appends since this archiver was opened. */
  appends: number;
  /** Failed appends/retention writes (counted, never thrown). */
  writeErrors: number;
  /** Current on-disk size of `events.jsonl`, best-effort. */
  bytes: number;
  /** WR-188: sealed segment files written since this archiver was opened. */
  sealedSegments: number;
}

/** What `DeliveryEventArchiver.seqRange` reports about the retained history. */
export interface EventArchiveSeqRange {
  /** Smallest `seq` currently retained (1-based; 0 when the archive is empty). */
  minSeq: number;
  /** Largest `seq` currently retained (0 when the archive is empty). */
  maxSeq: number;
  /** Number of events currently retained. */
  total: number;
}

export class DeliveryEventArchiver {
  private readonly path: string;
  private readonly maxAgeMs?: number;
  private readonly maxBytes?: number;
  private readonly unsubscribe?: () => void;
  private readonly sealedDir?: string;
  private readonly onSegmentSealed?: (localPath: string) => void;
  private appends = 0;
  private writeErrors = 0;
  private bytes = 0;
  private sealedSegments = 0;
  private appendsSinceRetain = 0;
  /**
   * WR-123: monotonic event sequence state. `nextSeq` is the last assigned
   * seq (the next `record()` assigns `nextSeq + 1`); `minSeq`/`total` track
   * what retention currently keeps on disk. Recovered from the file at
   * construction, so seqs stay dense and increasing across restarts.
   */
  private nextSeq = 0;
  private minSeq = 0;
  private totalEvents = 0;

  /**
   * `dir` is created (recursively) when missing — a missing directory is
   * normal on first boot; an *uncreatable* one is an operator
   * misconfiguration and throws, fail-fast at construction. Invalid
   * retention values throw `RangeError` at startup, never mid-request.
   */
  constructor(options: EventArchiveOptions) {
    const { dir, maxAgeMs, maxBytes, source, sealedDir, onSegmentSealed } = options;
    if (maxAgeMs !== undefined && (!Number.isFinite(maxAgeMs) || maxAgeMs <= 0)) {
      throw new RangeError("DeliveryEventArchiver: `maxAgeMs` must be a positive finite number");
    }
    if (maxBytes !== undefined && (!Number.isInteger(maxBytes) || maxBytes <= 0)) {
      throw new RangeError("DeliveryEventArchiver: `maxBytes` must be a positive integer");
    }
    if (sealedDir !== undefined && (typeof sealedDir !== "string" || sealedDir === "")) {
      throw new RangeError("DeliveryEventArchiver: `sealedDir` must be a non-empty string when set");
    }
    if (onSegmentSealed !== undefined && typeof onSegmentSealed !== "function") {
      throw new RangeError("DeliveryEventArchiver: `onSegmentSealed` must be a function when set");
    }
    mkdirSync(dir, { recursive: true });
    if (sealedDir !== undefined) {
      // Sealed segments are cold storage for evicted lines; an
      // uncreatable directory is an operator misconfiguration and throws
      // here, fail-fast, never mid-retention.
      mkdirSync(sealedDir, { recursive: true });
      this.sealedDir = sealedDir;
    }
    this.onSegmentSealed = onSegmentSealed;
    this.path = join(dir, EVENT_ARCHIVE_FILE);
    // A stale temp file is debris from a crash mid-retention, never the
    // source of truth — remove it so a later pass starts clean.
    try {
      rmSync(this.path + ARCHIVE_TMP_SUFFIX, { force: true });
    } catch {
      /* best effort */
    }
    // Touch the file so a missing archive reads as "no history", not an error.
    if (!existsSync(this.path)) {
      writeFileSync(this.path, "");
    }
    try {
      this.bytes = statSync(this.path).size;
    } catch {
      this.bytes = 0;
    }
    this.maxAgeMs = maxAgeMs;
    this.maxBytes = maxBytes;
    if (source !== undefined) {
      const listener = (event: DeliveryEvent): void => this.record(event);
      this.unsubscribe = source.subscribeDeliveryEvents(listener);
    }
    // Restart applies pending retention once, so a reboot does not
    // resurrect lines the policy would already have dropped.
    if (maxAgeMs !== undefined || maxBytes !== undefined) {
      this.retain();
    }
    // WR-123: recover the monotonic sequence from disk (assigning seqs to
    // any pre-WR-123 lines that lack one), so the Last-Event-ID cursor
    // stays dense and increasing across restarts.
    this.recoverSeq();
  }

  /** Unsubscribe from the event source. The file stays on disk. */
  close(): void {
    this.unsubscribe?.();
  }

  get stats(): EventArchiveStats {
    return {
      appends: this.appends,
      writeErrors: this.writeErrors,
      bytes: this.bytes,
      sealedSegments: this.sealedSegments,
    };
  }

  /**
   * Append one event. Never throws: a failed write is counted in
   * `writeErrors` and swallowed, so archiving can never fail a delivery.
   * Runs on the queue's synchronous delivery path — kept O(1).
   *
   * WR-123: assigns the next monotonic `seq`, stamps it on the passed event
   * as `event.eventSeq` (the archiver subscribes before the server's SSE
   * handlers, so live frames carry the same seq the archive persists), and
   * returns it. The stamp is what makes `Last-Event-ID` resume work across
   * restarts: the cursor is durable, not a process-local counter.
   */
  record(event: DeliveryEvent): number {
    const seq = this.nextSeq + 1;
    const line =
      JSON.stringify({
        seq,
        type: event.type,
        id: event.id,
        traceId: event.traceId,
        ...(event.tenant !== undefined ? { tenant: event.tenant } : {}),
        targetUrl: event.targetUrl,
        attempts: event.attempts,
        at: event.at,
        ...(event.error !== undefined ? { error: event.error } : {}),
      }) + "\n";
    try {
      appendFileSync(this.path, line, "utf8");
    } catch {
      // The delivery path is authoritative; a failed archive write degrades
      // to unarchived history, never a delivery failure. The seq is not
      // consumed on failure, so the next successful record keeps density.
      this.writeErrors += 1;
      return this.nextSeq;
    }
    // Stamp only on success: a failed append must not hand out a seq that
    // has no line on disk, or a reconnect could 210 on a gap we created.
    this.nextSeq = seq;
    event.eventSeq = seq;
    if (this.minSeq === 0) this.minSeq = seq;
    this.totalEvents += 1;
    this.appends += 1;
    this.bytes += Buffer.byteLength(line, "utf8");
    this.appendsSinceRetain += 1;
    const overBytes = this.maxBytes !== undefined && this.bytes > this.maxBytes;
    const ageCheckDue = this.maxAgeMs !== undefined && this.appendsSinceRetain >= RETENTION_CHECK_EVERY;
    if (overBytes || ageCheckDue) {
      this.retain();
    }
    return seq;
  }

  /** Force a retention pass now. Never throws; failures are counted. */
  compactNow(): void {
    this.retain();
  }

  /**
   * Query the archive. Throws `Error` on invalid `since`/`until` (the
   * server maps this to 400). Returns events sorted by `at` ascending;
   * ties keep file order (stable sort). Corrupt lines are skipped.
   */
  query(filter: EventArchiveQuery = {}): DeliveryEvent[] {
    const sinceMs = filter.since === undefined ? NaN : Date.parse(filter.since);
    const untilMs = filter.until === undefined ? NaN : Date.parse(filter.until);
    if (
      (filter.since !== undefined && Number.isNaN(sinceMs)) ||
      (filter.until !== undefined && Number.isNaN(untilMs))
    ) {
      throw new Error("DeliveryEventArchiver.query: since/until must be valid ISO-8601 timestamps");
    }
    let raw: string;
    try {
      raw = readFileSync(this.path, "utf8");
    } catch {
      return [];
    }
    const out: DeliveryEvent[] = [];
    for (const rawLine of raw.split("\n")) {
      if (rawLine.trim() === "") continue;
      let obj: Record<string, unknown>;
      try {
        obj = JSON.parse(rawLine) as Record<string, unknown>;
      } catch {
        continue; // torn line from a crash mid-append — skip, never fail a query
      }
      if (obj["type"] !== "delivered" && obj["type"] !== "retrying" && obj["type"] !== "dead_letter") {
        continue;
      }
      const at = typeof obj["at"] === "string" ? obj["at"] : "";
      const atMs = Date.parse(at);
      if (!Number.isNaN(sinceMs) && (Number.isNaN(atMs) || atMs < sinceMs)) continue;
      if (!Number.isNaN(untilMs) && (Number.isNaN(atMs) || atMs > untilMs)) continue;
      if (filter.endpoint !== undefined && obj["targetUrl"] !== filter.endpoint) continue;
      if (filter.event !== undefined && obj["type"] !== filter.event) continue;
      out.push({
        type: obj["type"] as DeliveryEventType,
        id: String(obj["id"] ?? ""),
        traceId: String(obj["traceId"] ?? ""),
        ...(typeof obj["tenant"] === "string" ? { tenant: obj["tenant"] } : {}),
        targetUrl: String(obj["targetUrl"] ?? ""),
        attempts: typeof obj["attempts"] === "number" ? obj["attempts"] : 0,
        at,
        ...(typeof obj["error"] === "string" ? { error: obj["error"] } : {}),
        ...(typeof obj["seq"] === "number" ? { eventSeq: obj["seq"] } : {}),
      });
    }
    // Stable sort: equal `at` keeps file (chronological) order.
    out.sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : 0));
    return out;
  }

  /**
   * WR-123: the retained sequence range — the `Last-Event-ID` cursor space.
   * `minSeq` is 0 and `total` is 0 when the archive is empty.
   */
  seqRange(): EventArchiveSeqRange {
    return { minSeq: this.minSeq, maxSeq: this.nextSeq, total: this.totalEvents };
  }

  /**
   * WR-123: events with `seq` strictly greater than `afterSeq`, in archive
   * (chronological) order — the reconnect replay set. `limit` bounds how
   * much history one reconnect may pull; when the gap is larger the result
   * is `truncated` and the caller must answer 210 Gone (the client rebuilds
   * from `GET /events/archive`) instead of replaying a partial gap.
   * Corrupt lines are skipped, exactly like `query()`.
   */
  eventsAfter(
    afterSeq: number,
    limit = 10_000
  ): { events: DeliveryEvent[]; truncated: boolean } & EventArchiveSeqRange {
    let raw: string;
    try {
      raw = readFileSync(this.path, "utf8");
    } catch {
      return { events: [], truncated: false, ...this.seqRange() };
    }
    const out: DeliveryEvent[] = [];
    let truncated = false;
    for (const rawLine of raw.split("\n")) {
      if (rawLine.trim() === "") continue;
      let obj: Record<string, unknown>;
      try {
        obj = JSON.parse(rawLine) as Record<string, unknown>;
      } catch {
        continue; // torn line from a crash mid-append — skip, never fail a replay
      }
      if (obj["type"] !== "delivered" && obj["type"] !== "retrying" && obj["type"] !== "dead_letter") {
        continue;
      }
      const seq = obj["seq"];
      if (typeof seq !== "number" || seq <= afterSeq) continue;
      if (out.length >= limit) {
        truncated = true;
        break;
      }
      const at = typeof obj["at"] === "string" ? obj["at"] : "";
      out.push({
        type: obj["type"] as DeliveryEventType,
        id: String(obj["id"] ?? ""),
        traceId: String(obj["traceId"] ?? ""),
        ...(typeof obj["tenant"] === "string" ? { tenant: obj["tenant"] } : {}),
        targetUrl: String(obj["targetUrl"] ?? ""),
        attempts: typeof obj["attempts"] === "number" ? obj["attempts"] : 0,
        at,
        ...(typeof obj["error"] === "string" ? { error: obj["error"] } : {}),
        eventSeq: seq,
      });
    }
    return { events: out, truncated, ...this.seqRange() };
  }

  /**
   * WR-123: rebuild the monotonic sequence state from disk. Lines that
   * predate the `seq` field (written before WR-123) have no cursor a client
   * could have observed, so when any line lacks a valid seq the whole file
   * is renumbered 1..N in file order via one atomic rewrite — after
   * construction every retained line has a dense, increasing seq and file
   * order == seq order. Corrupt lines are kept verbatim (they stay out of
   * cursor replay but remain visible to `query()`), exactly the
   * fail-safe-toward-evidence policy `retain()` uses. Never throws.
   */
  private recoverSeq(): void {
    let raw: string;
    try {
      raw = readFileSync(this.path, "utf8");
    } catch {
      return;
    }
    const lines: string[] = [];
    let needsResequence = false;
    for (const rawLine of raw.split("\n")) {
      if (rawLine.trim() === "") continue;
      lines.push(rawLine);
      try {
        const s = (JSON.parse(rawLine) as { seq?: unknown }).seq;
        if (!(typeof s === "number" && Number.isInteger(s) && s >= 1)) {
          needsResequence = true;
        }
      } catch {
        /* corrupt line: kept verbatim, never carries a seq */
      }
    }
    if (needsResequence && lines.length > 0) {
      let seq = 0;
      const rewritten: string[] = [];
      for (const rawLine of lines) {
        let obj: Record<string, unknown> | undefined;
        try {
          obj = JSON.parse(rawLine) as Record<string, unknown>;
        } catch {
          rewritten.push(rawLine);
          continue;
        }
        seq += 1;
        obj["seq"] = seq;
        rewritten.push(JSON.stringify(obj));
      }
      const tmp = this.path + ARCHIVE_TMP_SUFFIX;
      try {
        writeFileSync(tmp, rewritten.join("\n") + "\n", "utf8");
        renameSync(tmp, this.path);
      } catch {
        this.writeErrors += 1;
        return;
      }
      try {
        this.bytes = statSync(this.path).size;
      } catch {
        /* best effort */
      }
      this.nextSeq = seq;
      this.minSeq = 1;
      this.totalEvents = seq;
      return;
    }
    // All lines sequenced: recover the range from disk.
    let maxSeq = 0;
    let minSeq = 0;
    let total = 0;
    for (const rawLine of lines) {
      try {
        const s = (JSON.parse(rawLine) as { seq?: unknown }).seq;
        if (typeof s === "number" && Number.isInteger(s) && s >= 1) {
          total += 1;
          if (s > maxSeq) maxSeq = s;
          if (minSeq === 0 || s < minSeq) minSeq = s;
        }
      } catch {
        /* kept-verbatim corrupt line: no seq */
      }
    }
    this.nextSeq = maxSeq;
    this.minSeq = minSeq;
    this.totalEvents = total;
  }

  /**
   * WR-123: recompute the retained cursor range from a set of kept seqs
   * (0 = line without a seq, e.g. a corrupt line kept verbatim — it holds
   * no cursor). `nextSeq` is deliberately untouched: seqs are never reused.
   */
  private syncSeqRange(seqs: number[]): void {
    let minSeq = 0;
    let total = 0;
    for (const s of seqs) {
      if (s >= 1) {
        total += 1;
        if (minSeq === 0 || s < minSeq) minSeq = s;
      }
    }
    this.minSeq = minSeq;
    this.totalEvents = total;
  }

  /**
   * Apply the retention policy: read all lines, drop what the policy
   * rejects, and rewrite via temp-file + atomic rename. Never throws —
   * failures are counted in `writeErrors` and the previous complete file
   * is left in place. Skips the rewrite entirely when nothing would be
   * dropped.
   */
  private retain(): void {
    this.appendsSinceRetain = 0;
    let raw: string;
    try {
      raw = readFileSync(this.path, "utf8");
    } catch {
      this.writeErrors += 1;
      return;
    }
    const parsed: Array<{ line: string; atMs: number; seq: number }> = [];
    for (const rawLine of raw.split("\n")) {
      if (rawLine.trim() === "") continue;
      let atMs = NaN;
      let seq = 0;
      try {
        const obj = JSON.parse(rawLine) as { at?: unknown; seq?: unknown };
        atMs = typeof obj.at === "string" ? Date.parse(obj.at) : NaN;
        if (typeof obj.seq === "number" && Number.isInteger(obj.seq) && obj.seq >= 1) {
          seq = obj.seq;
        }
      } catch {
        /* corrupt line: fail-safe toward evidence — kept, never ages out */
      }
      parsed.push({ line: rawLine, atMs, seq });
    }
    const cutoff = this.maxAgeMs !== undefined ? Date.now() - this.maxAgeMs : Number.NEGATIVE_INFINITY;
    let kept = parsed.filter((p) => Number.isNaN(p.atMs) || p.atMs >= cutoff);
    if (this.maxBytes !== undefined) {
      let size = 0;
      for (const p of kept) size += Buffer.byteLength(p.line, "utf8") + 1;
      let drop = 0;
      // Oldest first (file order); the newest line is always kept.
      while (kept.length - drop > 1 && size > this.maxBytes) {
        size -= Buffer.byteLength(kept[drop].line, "utf8") + 1;
        drop += 1;
      }
      kept = kept.slice(drop);
    }
    if (kept.length === parsed.length) {
      // Nothing to drop — but re-sync the byte counter against reality.
      try {
        this.bytes = statSync(this.path).size;
      } catch {
        /* best effort */
      }
      return;
    }
    // WR-188: seal the evicted lines before they leave the live file.
    // The seal is written first; if the seal write fails the lines are
    // still dropped (fail-safe toward bounded local growth) and the
    // failure is counted in `writeErrors`.
    const keptSet = new Set(kept);
    const evicted = parsed.filter((p) => !keptSet.has(p));
    const sealedPath = this.sealEvicted(evicted);
    // WR-123: retention evicts the oldest lines, so the cursor range moves.
    // It is recomputed after the atomic rename, from what actually
    // survived; nextSeq (the high-water mark) is untouched — seqs are
    // never reused.
    const tmp = this.path + ARCHIVE_TMP_SUFFIX;
    try {
      const data = kept.length > 0 ? kept.map((p) => p.line).join("\n") + "\n" : "";
      const fd = openSync(tmp, "w");
      try {
        writeSync(fd, data, null, "utf8");
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      renameSync(tmp, this.path);
      this.bytes = Buffer.byteLength(data, "utf8");
      this.syncSeqRange(kept.map((p) => p.seq));
      // WR-188: the seal is durable and the live file no longer holds the
      // lines — fire the notification (error-isolated: bookkeeping must
      // never fail a retention pass, and therefore never a delivery).
      if (sealedPath !== undefined && this.onSegmentSealed !== undefined) {
        try {
          this.onSegmentSealed(sealedPath);
        } catch {
          /* swallowed — see the option's contract */
        }
      }
    } catch {
      // The pre-retention file is untouched — retention is retried later,
      // never half-applied.
      this.writeErrors += 1;
      try {
        rmSync(tmp, { force: true });
      } catch {
        /* best effort */
      }
    }
  }

  /**
   * WR-188: write the evicted lines verbatim to one sealed segment file
   * under `sealedDir`. The name is deterministic —
   * `<yyyymmdd>-seq-<minSeq>-<maxSeq>.jsonl` from the earliest evicted
   * event's UTC date and the sealed seq range — so the S3 offloader can
   * derive a deterministic object key, and a re-run of the offloader
   * over the same segment uploads to the same key (idempotent PUT).
   * Written via temp file + fsync + atomic rename, exactly like
   * `retain()`. Never throws: failures are counted in `writeErrors`
   * and the caller drops the lines anyway (fail-safe toward bounded
   * local growth). Returns the sealed file path, or `undefined` when
   * sealing is disabled or the write failed.
   */
  private sealEvicted(
    evicted: Array<{ line: string; atMs: number; seq: number }>
  ): string | undefined {
    if (this.sealedDir === undefined || evicted.length === 0) return undefined;
    const seqs = evicted.map((p) => p.seq).filter((s) => s >= 1);
    const dates = evicted
      .map((p) => p.atMs)
      .filter((ms) => Number.isFinite(ms));
    const stampMs = dates.length > 0 ? Math.min(...dates) : Date.now();
    const d = new Date(stampMs);
    const yyyymmdd =
      `${d.getUTCFullYear()}` +
      `${String(d.getUTCMonth() + 1).padStart(2, "0")}` +
      `${String(d.getUTCDate()).padStart(2, "0")}`;
    const range =
      seqs.length > 0
        ? `seq-${Math.min(...seqs)}-${Math.max(...seqs)}`
        : `noseq-${evicted.length}`;
    // Seqs are never reused, so segment names are naturally disjoint;
    // the suffix loop is only belt-and-braces against a hand-placed
    // file with the same name.
    let name = `${yyyymmdd}-${range}.jsonl`;
    let target = join(this.sealedDir, name);
    for (let i = 2; existsSync(target); i += 1) {
      name = `${yyyymmdd}-${range}-${i}.jsonl`;
      target = join(this.sealedDir, name);
    }
    const data = evicted.map((p) => p.line).join("\n") + "\n";
    const tmp = target + ARCHIVE_TMP_SUFFIX;
    try {
      const fd = openSync(tmp, "w");
      try {
        writeSync(fd, data, null, "utf8");
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }
      renameSync(tmp, target);
    } catch {
      this.writeErrors += 1;
      try {
        rmSync(tmp, { force: true });
      } catch {
        /* best effort */
      }
      return undefined;
    }
    this.sealedSegments += 1;
    return target;
  }
}
