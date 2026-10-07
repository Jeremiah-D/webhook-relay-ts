import { appendFileSync, closeSync, openSync, readFileSync, readSync, statSync } from "node:fs";
import { isEncryptedPayload, type PayloadEncryptor } from "./encrypt.ts";

export type { PayloadEncryptor };

/** Options for {@link AuditLog}. */
export interface AuditLogOptions {
  /**
   * When set, a `payload` field (Buffer or string) on an appended event is
   * sealed into an {@link EncryptedPayload} envelope before the line hits
   * disk, and transparently decrypted back on `readAll`/`query`. Unset by
   * default: payloads are stored as plain JSON.
   */
  payloadEncryptor?: PayloadEncryptor;
}

/** Filters for {@link AuditLog.query}. All filters are ANDed together. */
export interface AuditQuery {
  /** Keep only these event names (e.g. `"delivered"`); a single name or a list. */
  event?: string | string[];
  /**
   * Keep only entries for this endpoint. Matches the `targetUrl` field of
   * delivery events (`accepted` / `delivered` / `dead_letter`), or an
   * explicit `endpoint` field when present.
   */
  endpoint?: string;
  /** ISO-8601 lower bound (inclusive). Invalid values throw. */
  since?: string;
  /** ISO-8601 upper bound (inclusive). Invalid values throw. */
  until?: string;
  /**
   * Maximum entries returned. When the log holds more matches, the most
   * recent `limit` matches are returned, still in chronological order.
   * Must be a positive integer.
   */
  limit?: number;
  /**
   * Keep only entries carrying this trace ID (see `src/trace.ts`) — the
   * correlation key for one event across `accepted` / `delivered` /
   * `dead_letter` / `rejected` / `duplicate_suppressed` / `slo_missed` /
   * `batch_flushed` audit lines.
   */
  traceId?: string;
}

/** One indexed JSONL line: its searchable fields plus its byte span. */
interface IndexEntry {
  /** Millisecond epoch of the line's `ts`, or NaN when missing/invalid. */
  tsMs: number;
  event?: string;
  endpoint?: string;
  traceId?: string;
  offset: number;
  length: number;
}

/**
 * Append-only JSONL audit log. Each line is a JSON object containing the
 * caller's event fields plus an ISO-8601 `ts` timestamp. Kept dependency-free
 * so the log can be inspected with plain `jq`/text tools.
 *
 * `query()` filters the log without re-parsing it: a lazily maintained
 * index maps each complete line to its searchable fields (`ts`, `event`,
 * `endpoint`) and its byte span in the file, so only matching lines are
 * read back. The index tracks the file size to detect appends (only the new
 * tail is scanned) and truncation/rotation (the index is rebuilt).
 */
export class AuditLog {
  private readonly path: string;
  private readonly payloadEncryptor?: PayloadEncryptor;
  private index: IndexEntry[] = [];
  /** Byte offset up to which the file has been indexed. */
  private indexedBytes = 0;

  constructor(path: string, opts: AuditLogOptions = {}) {
    this.path = path;
    this.payloadEncryptor = opts.payloadEncryptor;
  }

  /** Whether appended `payload` fields are sealed at rest. */
  hasPayloadEncryptor(): boolean {
    return this.payloadEncryptor !== undefined;
  }

  append(event: object): void {
    const line = JSON.stringify({ ts: new Date().toISOString(), ...this.sealPayload(event) });
    appendFileSync(this.path, line + "\n", "utf8");
  }

  /**
   * Seal a Buffer/string `payload` field into an encrypted envelope before
   * the line hits disk. Non-payload fields pass through untouched.
   */
  private sealPayload(event: object): object {
    if (!this.payloadEncryptor) return event;
    const rec = event as Record<string, unknown>;
    const p = rec.payload;
    const isBuffer = Buffer.isBuffer(p);
    if (!isBuffer && typeof p !== "string") return event;
    const plain = isBuffer ? p : Buffer.from(p, "utf8");
    return {
      ...rec,
      payload: this.payloadEncryptor.encrypt(plain),
      payloadEncrypted: true,
      payloadEncoding: isBuffer ? "buffer" : "utf8",
      payloadBytes: plain.length,
    };
  }

  /**
   * Restore a sealed `payload` envelope to the shape an unencrypted append
   * would have produced (string stays a string; a Buffer comes back as its
   * `{ type: "Buffer", data: [...] }` JSON form). Crypto failures throw —
   * a silent wrong-key read would be worse than a loud one.
   */
  private openPayload(entry: Record<string, unknown>): Record<string, unknown> {
    if (!this.payloadEncryptor || entry.payloadEncrypted !== true) return entry;
    if (!isEncryptedPayload(entry.payload)) {
      throw new Error("AuditLog: payloadEncrypted entry has a malformed payload envelope");
    }
    const plain = this.payloadEncryptor.decrypt(entry.payload);
    return {
      ...entry,
      payload: entry.payloadEncoding === "utf8" ? plain.toString("utf8") : plain.toJSON(),
    };
  }

  readAll(): object[] {
    let raw: string;
    try {
      raw = readFileSync(this.path, "utf8");
    } catch {
      return [];
    }
    const out: object[] = [];
    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (trimmed.length === 0) continue;
      let parsed: unknown;
      try {
        parsed = JSON.parse(trimmed);
      } catch {
        // Skip malformed lines; never let one bad line break reads.
        continue;
      }
      // Crypto failures propagate: a silent wrong-key read is worse than a loud one.
      out.push(this.openPayload(parsed as Record<string, unknown>));
    }
    return out;
  }

  /**
   * Return entries matching `filter`, oldest first. Uses the byte-offset
   * index so only matching lines are read from disk. Throws on invalid
   * `since`/`until`/`limit` values.
   */
  query(filter: AuditQuery = {}): object[] {
    const sinceMs = filter.since === undefined ? NaN : Date.parse(filter.since);
    const untilMs = filter.until === undefined ? NaN : Date.parse(filter.until);
    if (
      (filter.since !== undefined && Number.isNaN(sinceMs)) ||
      (filter.until !== undefined && Number.isNaN(untilMs))
    ) {
      throw new Error("AuditLog.query: since/until must be valid ISO-8601 timestamps");
    }
    if (
      filter.limit !== undefined &&
      (!Number.isInteger(filter.limit) || filter.limit < 1)
    ) {
      throw new Error("AuditLog.query: limit must be a positive integer");
    }
    const events =
      filter.event === undefined ? undefined : Array.isArray(filter.event) ? filter.event : [filter.event];

    this.ensureIndex();

    let matches = this.index.filter((e) => {
      if (events !== undefined && (e.event === undefined || !events.includes(e.event))) return false;
      if (filter.endpoint !== undefined && e.endpoint !== filter.endpoint) return false;
      if (filter.traceId !== undefined && e.traceId !== filter.traceId) return false;
      // Lines without a parseable `ts` can only match unfiltered time ranges.
      if (!Number.isNaN(sinceMs) && (Number.isNaN(e.tsMs) || e.tsMs < sinceMs)) return false;
      if (!Number.isNaN(untilMs) && (Number.isNaN(e.tsMs) || e.tsMs > untilMs)) return false;
      return true;
    });
    if (filter.limit !== undefined) {
      matches = matches.slice(-filter.limit);
    }
    if (matches.length === 0) return [];

    const fd = openSync(this.path, "r");
    try {
      return matches.map((m) => {
        const buf = Buffer.alloc(m.length);
        let read = 0;
        while (read < buf.length) {
          const n = readSync(fd, buf, read, buf.length - read, m.offset + read);
          if (n === 0) break; // Truncated mid-read; parse what we have.
          read += n;
        }
        return this.openPayload(JSON.parse(buf.subarray(0, read).toString("utf8")));
      });
    } finally {
      closeSync(fd);
    }
  }

  /** Rebuild the index tail when the file grew, or the whole index when it shrank. */
  private ensureIndex(): void {
    let size: number;
    try {
      size = statSync(this.path).size;
    } catch {
      this.index = [];
      this.indexedBytes = 0;
      return;
    }
    if (size < this.indexedBytes) {
      // Truncated or rotated: offsets no longer mean anything.
      this.index = [];
      this.indexedBytes = 0;
    }
    if (size === this.indexedBytes) return;

    const fd = openSync(this.path, "r");
    try {
      const tailLen = size - this.indexedBytes;
      const tail = Buffer.alloc(tailLen);
      let read = 0;
      while (read < tailLen) {
        const n = readSync(fd, tail, read, tailLen - read, this.indexedBytes + read);
        if (n === 0) break;
        read += n;
      }
      const base = this.indexedBytes;
      let lineStart = 0;
      let completeEnd = base;
      for (let i = 0; i < read; i++) {
        if (tail[i] === 0x0a) {
          const len = i - lineStart;
          if (len > 0) {
            this.indexLine(tail.subarray(lineStart, i), base + lineStart);
          }
          lineStart = i + 1;
          completeEnd = base + lineStart;
        }
      }
      // A trailing partial line (no newline yet) is left for the next scan,
      // so a later append can never be double-indexed.
      this.indexedBytes = completeEnd;
    } finally {
      closeSync(fd);
    }
  }

  /** Parse one complete JSONL line into the index; malformed lines are skipped. */
  private indexLine(line: Buffer, offset: number): void {
    let obj: unknown;
    try {
      obj = JSON.parse(line.toString("utf8"));
    } catch {
      return;
    }
    if (!obj || typeof obj !== "object") return;
    const rec = obj as Record<string, unknown>;
    const ts = typeof rec.ts === "string" ? Date.parse(rec.ts) : NaN;
    const event = typeof rec.event === "string" ? rec.event : undefined;
    const endpoint =
      typeof rec.targetUrl === "string"
        ? rec.targetUrl
        : typeof rec.endpoint === "string"
          ? rec.endpoint
          : undefined;
    const traceId = typeof rec.traceId === "string" ? rec.traceId : undefined;
    this.index.push({ tsMs: ts, event, endpoint, traceId, offset, length: line.length });
  }
}
