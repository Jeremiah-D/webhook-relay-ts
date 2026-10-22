/**
 * Per-endpoint delivery watermark (WR-185).
 *
 * Downstream-outage observation ("下游断点续投观测"): how far each
 * delivery endpoint has confirmed. The relay assigns every item a
 * per-endpoint monotonic **ingress seq** when it enters the deliverable
 * queue (`enqueueNow` — inbound receive order for normal admissions), and
 * each successful delivery advances the endpoint's **watermark**: the
 * maximum *consecutive* delivered seq. Out-of-order deliveries are
 * buffered and the watermark advances by the consecutive prefix.
 *
 * Per endpoint:
 * - `ingressSeq` — highest assigned ingress seq (0 when nothing assigned).
 * - `watermark` — max consecutive delivered seq (0 when nothing delivered).
 * - `lag` — `ingressSeq - watermark`: admissions the downstream has not
 *   yet confirmed. A downstream outage freezes the watermark while the
 *   lag grows; catching up after the outage drains it back toward 0.
 *
 * Persistence: append-only JSONL journal (`<dir>/watermarks.jsonl`)
 * recording every `assigned` and `delivered` event; recovery at
 * construction replays the journal (in file order), so the watermark
 * survives process restarts. Torn/corrupt lines are skipped and counted —
 * a bad line never prevents recovery of the rest. An amortized compaction
 * rewrites the journal down to one snapshot line per endpoint when it
 * grows past `COMPACT_AFTER_BYTES` (atomic temp-file + rename, so a
 * crash mid-compaction leaves the previous complete journal).
 *
 * Crash semantics (at-least-once, honestly not exactly-once):
 * - Appends are synchronous and never throw: a failed write is counted in
 *   `writeErrors` and swallowed, so a full disk can never fail a
 *   delivery. Appends are *not* fsync'd — an OS crash may lose the
 *   unwritten tail. (Delivery state itself is unaffected; the watermark is
 *   observability.)
 * - A delivery confirmed downstream but whose journal line was lost is
 *   simply re-confirmed on redelivery: `markDelivered` is idempotent and
 *   the watermark never regresses.
 *
 * Orthogonality (deliberate, by design):
 * - WR-49 (durable queue) journals *pending* items — what is still owed.
 * - WR-55 (event archive) journals the delivery *event history*.
 * - This module tracks *confirmed-delivery progress* only: it never reads
 *   the durable queue or the event archive, and neither reads it.
 *
 * Endpoint key: the delivery `targetUrl`, consistent with the other
 * per-endpoint observability surfaces (circuit stats, quota stats,
 * SLO risk). The key is the logical endpoint the item was enqueued with —
 * the same key the queue stamps the ingress seq under — so failover or
 * weighted physical-target resolution cannot split one endpoint's
 * watermark in two.
 */
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { join } from "node:path";

/** Journal file name inside the watermark directory. */
export const WATERMARK_JOURNAL_FILE = "watermarks.jsonl";

/** Temp file used for atomic compaction rewrites (same directory, so rename is atomic). */
export const WATERMARK_JOURNAL_TMP = "watermarks.jsonl.tmp";

/** Journal version written by this implementation. Unknown versions fail the line, not the file. */
const JOURNAL_VERSION = 1;

/** Rewrite the journal down to snapshots once it grows past this many bytes since the last compaction. */
export const WATERMARK_COMPACT_AFTER_BYTES = 1 << 20; // 1 MiB

/** Per-endpoint delivery-watermark row, as served by `GET /watermarks`. */
export interface WatermarkEndpointStats {
  /** The delivery endpoint (targetUrl). */
  endpoint: string;
  /** Highest assigned ingress seq — the received count (0 when nothing assigned). */
  ingressSeq: number;
  /** Max consecutive delivered seq (0 when nothing delivered). */
  watermark: number;
  /** `ingressSeq - watermark`: admissions not yet confirmed downstream. */
  lag: number;
}

interface EndpointState {
  /** Next ingress seq to hand out (1-based). */
  nextSeq: number;
  /** Max consecutive delivered seq. */
  watermark: number;
  /** Delivered seqs ahead of the watermark (out-of-order buffer). */
  delivered: Set<number>;
}

type JournalEvent =
  | { v: number; t: "assigned"; e: string; seq: number }
  | { v: number; t: "delivered"; e: string; seq: number }
  | { v: number; t: "snapshot"; e: string; nextSeq: number; wm: number; delivered: number[] };

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export class DeliveryWatermark {
  private readonly dir: string;
  private readonly file: string;
  private readonly endpoints = new Map<string, EndpointState>();
  private bytesSinceCompact = 0;
  private writeErrors = 0;
  private skippedLines = 0;

  /**
   * Opens (creating) `dir` and replays `<dir>/watermarks.jsonl`.
   * Throws `RangeError` on an invalid `dir`; throws when the directory
   * cannot be created (fail-fast: a watermark that cannot persist is a
   * misconfiguration, not a degradation).
   */
  constructor(dir: string) {
    if (typeof dir !== "string" || dir.length === 0) {
      throw new RangeError(`watermark dir must be a non-empty string, got ${JSON.stringify(dir)}`);
    }
    this.dir = dir;
    mkdirSync(dir, { recursive: true });
    this.file = join(dir, WATERMARK_JOURNAL_FILE);
    // A stale temp file from a crash mid-compaction is never the source
    // of truth — remove it so it cannot confuse a later recovery.
    try {
      rmSync(join(dir, WATERMARK_JOURNAL_TMP), { force: true });
    } catch {
      // Best effort: a leftover temp file is harmless (it is never read).
    }
    this.recover();
  }

  private stateFor(endpoint: string): EndpointState {
    let st = this.endpoints.get(endpoint);
    if (st === undefined) {
      st = { nextSeq: 1, watermark: 0, delivered: new Set() };
      this.endpoints.set(endpoint, st);
    }
    return st;
  }

  /**
   * Assigns the endpoint's next ingress seq (inbound receive order) and
   * journals it. Seqs start at 1 and are strictly increasing per
   * endpoint.
   */
  assign(endpoint: string): number {
    const st = this.stateFor(endpoint);
    const seq = st.nextSeq;
    st.nextSeq += 1;
    this.append({ v: JOURNAL_VERSION, t: "assigned", e: endpoint, seq });
    return seq;
  }

  /**
   * Records a confirmed downstream delivery of `seq` for `endpoint`.
   * Idempotent: a duplicate confirmation (redelivery after a crash, or
   * the same item reported twice) never moves the watermark twice and
   * never regresses it. Returns `true` when the watermark advanced.
   */
  markDelivered(endpoint: string, seq: number): boolean {
    if (!Number.isInteger(seq) || seq < 1) return false;
    const st = this.stateFor(endpoint);
    if (seq >= st.nextSeq) {
      // A delivery for a seq we never assigned — our assignment record is
      // incomplete (e.g. the journal was wiped while the process kept
      // running). Fast-forward the assignment cursor so future assigns
      // stay strictly increasing; the seq itself still counts as
      // delivered below.
      st.nextSeq = seq + 1;
    }
    const advanced = this.recordDelivered(st, seq);
    this.append({ v: JOURNAL_VERSION, t: "delivered", e: endpoint, seq });
    return advanced;
  }

  /**
   * Per-endpoint watermark snapshot, sorted by endpoint:
   * `{ endpoint, ingressSeq, watermark, lag }` with
   * `lag = ingressSeq - watermark`.
   */
  getWatermarkStats(): WatermarkEndpointStats[] {
    const rows: WatermarkEndpointStats[] = [];
    for (const [endpoint, st] of this.endpoints) {
      const ingressSeq = st.nextSeq - 1;
      rows.push({ endpoint, ingressSeq, watermark: st.watermark, lag: ingressSeq - st.watermark });
    }
    rows.sort((a, b) => (a.endpoint < b.endpoint ? -1 : a.endpoint > b.endpoint ? 1 : 0));
    return rows;
  }

  /** Cumulative journal write failures (writes never throw). */
  getWriteErrors(): number {
    return this.writeErrors;
  }

  /** Journal lines skipped during recovery (torn/corrupt). */
  getSkippedLines(): number {
    return this.skippedLines;
  }

  /**
   * Force a compaction pass: rewrite the journal as one snapshot line per
   * endpoint. Used by tests; the append path triggers it amortized.
   */
  compactNow(): void {
    const lines: string[] = [];
    for (const [endpoint, st] of this.endpoints) {
      const snap: JournalEvent = {
        v: JOURNAL_VERSION,
        t: "snapshot",
        e: endpoint,
        nextSeq: st.nextSeq,
        wm: st.watermark,
        delivered: [...st.delivered].sort((a, b) => a - b),
      };
      lines.push(JSON.stringify(snap));
    }
    const tmp = join(this.dir, WATERMARK_JOURNAL_TMP);
    try {
      writeFileSync(tmp, lines.length === 0 ? "" : lines.join("\n") + "\n");
      renameSync(tmp, this.file);
      this.bytesSinceCompact = 0;
    } catch {
      this.writeErrors += 1;
      try {
        rmSync(tmp, { force: true });
      } catch {
        // Best effort.
      }
    }
  }

  // --- internals ---

  /** Buffers a confirmed seq and advances the watermark by the consecutive prefix. */
  private recordDelivered(st: EndpointState, seq: number): boolean {
    if (seq <= st.watermark) return false; // already counted — never double-count
    st.delivered.add(seq);
    let advanced = st.watermark;
    while (st.delivered.has(advanced + 1)) {
      advanced += 1;
      st.delivered.delete(advanced);
    }
    if (advanced === st.watermark) return false;
    st.watermark = advanced;
    return true;
  }

  private append(evt: JournalEvent): void {
    const line = JSON.stringify(evt) + "\n";
    try {
      appendFileSync(this.file, line);
      this.bytesSinceCompact += Buffer.byteLength(line);
      if (this.bytesSinceCompact >= WATERMARK_COMPACT_AFTER_BYTES) this.compactNow();
    } catch {
      // Observability must never fail a delivery: count and swallow.
      this.writeErrors += 1;
    }
  }

  private recover(): void {
    if (!existsSync(this.file)) return;
    let raw: string;
    try {
      raw = readFileSync(this.file, "utf8");
    } catch {
      this.skippedLines += 1;
      return;
    }
    for (const line of raw.split("\n")) {
      if (line.trim() === "") continue;
      const evt = parseJournalLine(line);
      if (evt === undefined) {
        this.skippedLines += 1;
        continue;
      }
      this.applyJournalEvent(evt);
    }
  }

  private applyJournalEvent(evt: JournalEvent): void {
    const st = this.stateFor(evt.e);
    if (evt.t === "snapshot") {
      st.nextSeq = evt.nextSeq;
      st.watermark = evt.wm;
      st.delivered = new Set(evt.delivered);
      return;
    }
    if (evt.t === "assigned") {
      if (evt.seq >= st.nextSeq) st.nextSeq = evt.seq + 1;
      return;
    }
    // "delivered"
    if (evt.seq >= st.nextSeq) st.nextSeq = evt.seq + 1;
    this.recordDelivered(st, evt.seq);
  }
}

/** Parses one journal line; returns `undefined` for torn/corrupt/unknown lines. */
function parseJournalLine(line: string): JournalEvent | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    return undefined;
  }
  if (!isRecord(parsed) || parsed.v !== JOURNAL_VERSION) return undefined;
  if (typeof parsed.e !== "string" || parsed.e.length === 0) return undefined;
  if (parsed.t === "assigned" || parsed.t === "delivered") {
    if (!Number.isInteger(parsed.seq) || (parsed.seq as number) < 1) return undefined;
    return { v: JOURNAL_VERSION, t: parsed.t, e: parsed.e, seq: parsed.seq as number };
  }
  if (parsed.t === "snapshot") {
    if (!Number.isInteger(parsed.nextSeq) || (parsed.nextSeq as number) < 1) return undefined;
    if (!Number.isInteger(parsed.wm) || (parsed.wm as number) < 0) return undefined;
    if (!Array.isArray(parsed.delivered)) return undefined;
    const delivered: number[] = [];
    for (const s of parsed.delivered as unknown[]) {
      if (!Number.isInteger(s) || (s as number) < 1) return undefined;
      delivered.push(s as number);
    }
    return { v: JOURNAL_VERSION, t: "snapshot", e: parsed.e, nextSeq: parsed.nextSeq as number, wm: parsed.wm as number, delivered };
  }
  return undefined;
}
