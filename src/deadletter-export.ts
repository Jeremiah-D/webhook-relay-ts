/**
 * Dead-letter export (WR-128).
 *
 * Operators reconcile poisoned deliveries against downstream systems, and
 * for that they need the dead letters *with their payloads* — not just
 * the metadata `GET /dead-letter` exposes. This module is the export
 * engine behind the operator endpoint `GET /dead-letter/export`:
 *
 * - filter by `(endpoint, tenant, since, until)` — `since`/`until` are
 *   inclusive bounds on `deadLetteredAt`, accepted as ms-epoch digits or
 *   ISO-8601 strings (the same convention as `AuditLog.query`, which
 *   takes ISO strings; here both spellings are accepted because an
 *   operator paging a large export usually works in epoch ms);
 * - two wire formats via `format`: `jsonl` (default) or `csv`;
 * - payloads sealed at rest (WR-11) are transparently decrypted through
 *   the queue's decryptor — the export never sees the envelope;
 * - per-row payloads are truncated past `maxPayloadBytes` (default
 *   64 KiB) so one giant payload cannot blow the export's memory; CSV
 *   cells carry a `...[truncated]` marker, JSONL rows a
 *   `payloadTruncated` flag;
 * - one response carries at most `rowLimit` rows (default 10_000). A
 *   filter matching more than that, requested without a `cursor`,
 *   answers 409 (`needsPaging`) and asks the operator to page: `cursor`
 *   is an *inclusive* start id — the id of the first entry of the page
 *   — so the first page is reachable without a sentinel value, `hasMore`
 *   / `nextCursor` chain the rest, and an unknown cursor is a 400.
 *
 * The module is pure (no I/O): the caller supplies a
 * {@link DeadLetterExportSource} — the live queue in production,
 * hand-built entries in tests — and streams the rendered rows itself.
 * Zero dependencies.
 */

import type { DeadLetterEntry } from "./retry.ts";

/** Maximum rows in one export response. Larger exports answer 409 and ask the operator to page with `cursor`. */
export const DEAD_LETTER_EXPORT_ROW_LIMIT = 10_000;

/** Default per-row payload cap: bigger payloads are truncated with a marker. */
export const DEAD_LETTER_EXPORT_DEFAULT_MAX_PAYLOAD_BYTES = 64 * 1024;

/** Appended to a CSV payload cell cut by truncation. */
export const DEAD_LETTER_EXPORT_TRUNCATION_MARKER = "...[truncated]";

/** Wire formats for the export. */
export type DeadLetterExportFormat = "jsonl" | "csv";

/** Thrown when `cursor` names no entry in the filtered export. */
export class InvalidExportCursorError extends Error {
  constructor(cursor: string) {
    super(`dead-letter export: unknown cursor "${cursor}"`);
    this.name = "InvalidExportCursorError";
  }
}

/** Filter for {@link planDeadLetterExport}. All fields optional. */
export interface DeadLetterExportFilter {
  /** Only entries dead-lettered for this endpoint (exact `targetUrl` match). */
  endpoint?: string;
  /** Only entries dead-lettered for this tenant (exact `tenantId` match). */
  tenant?: string;
  /** Inclusive lower bound on `deadLetteredAt`, ms epoch. */
  since?: number;
  /** Inclusive upper bound on `deadLetteredAt`, ms epoch. */
  until?: number;
}

/** What the export engine needs from the queue. */
export interface DeadLetterExportSource {
  /** Live dead-letter entries in stable insertion order. */
  entries(): DeadLetterEntry[];
  /**
   * Open an entry's payload for export: sealed entries (WR-11) are
   * transparently decrypted, cleartext entries returned as-is. Throws
   * when a sealed payload cannot be opened.
   */
  decrypt(entry: DeadLetterEntry): Buffer;
}

/** Options for {@link planDeadLetterExport}. */
export interface DeadLetterExportOptions {
  /** Wire format; default `"jsonl"`. */
  format?: DeadLetterExportFormat;
  /**
   * Inclusive start id: the page begins *at* this entry. Unknown ids
   * throw {@link InvalidExportCursorError}. Unset: the page begins at
   * the first matched entry.
   */
  cursor?: string;
  /** Per-row payload truncation cap; default {@link DEAD_LETTER_EXPORT_DEFAULT_MAX_PAYLOAD_BYTES}. */
  maxPayloadBytes?: number;
  /** Rows per response; default {@link DEAD_LETTER_EXPORT_ROW_LIMIT}. Exposed for tests. */
  rowLimit?: number;
}

/** One exported row, before wire rendering. */
export interface DeadLetterExportRow {
  id: string;
  targetUrl: string;
  tenant?: string;
  attempts: number;
  lastError: string;
  deadLetteredAt: string;
  payloadBytes: number;
  failureClass: string;
  traceId?: string;
  /** True when the payload was sealed at rest (WR-11). */
  encrypted: boolean;
  /** `"utf8"` when the (possibly truncated) payload decoded cleanly, `"base64"` otherwise. */
  payloadEncoding: "utf8" | "base64";
  /** True when the payload was cut to `maxPayloadBytes`. */
  payloadTruncated: boolean;
  /** Set when sealed-payload decryption failed; `payload` is `""` then. */
  payloadError?: string;
  /** The (decrypted, truncated) payload. */
  payload: string;
}

/**
 * Parse a `since`/`until` query value: ms-epoch digits or an ISO-8601
 * string. Returns `undefined` for an absent value; throws `RangeError`
 * for anything else — the server maps it to a 400. ISO input must carry
 * a full `YYYY-MM-DD` date part: `Date.parse` alone is too lenient
 * (it reads `"12.5"` as a month/day), so the shape is checked first.
 */
export function parseDeadLetterExportTime(
  raw: string | undefined,
  name: "since" | "until"
): number | undefined {
  if (raw === undefined) return undefined;
  const invalid = (): RangeError =>
    new RangeError(
      `dead-letter export: \`${name}\` must be a non-negative ms epoch or an ISO-8601 timestamp`
    );
  const text = raw.trim();
  if (/^\d+$/.test(text)) {
    const ms = Number(text);
    if (!Number.isSafeInteger(ms) || ms < 0) throw invalid();
    return ms;
  }
  if (!/^\d{4}-\d{2}-\d{2}(?:[T ].*)?$/.test(text)) throw invalid();
  const ms = Date.parse(text);
  if (Number.isNaN(ms)) throw invalid();
  return ms;
}

/** True when `entry` passes every set field of `filter`. */
export function matchDeadLetterExport(
  entry: DeadLetterEntry,
  filter: DeadLetterExportFilter
): boolean {
  if (filter.endpoint !== undefined && entry.targetUrl !== filter.endpoint) return false;
  if (filter.tenant !== undefined && entry.tenantId !== filter.tenant) return false;
  if (filter.since !== undefined || filter.until !== undefined) {
    const at = Date.parse(entry.deadLetteredAt);
    if (Number.isNaN(at)) return false;
    if (filter.since !== undefined && at < filter.since) return false;
    if (filter.until !== undefined && at > filter.until) return false;
  }
  return true;
}

/**
 * Build one export row: decrypt (transparently), truncate past
 * `maxPayloadBytes`, and encode as UTF-8 when the bytes decode cleanly,
 * base64 otherwise. A decryption failure marks the row
 * (`payloadError: "decrypt_failed"`, empty payload) instead of failing
 * the whole export — one undecryptable entry must not nuke a 10k-row
 * download.
 */
export function buildDeadLetterExportRow(
  entry: DeadLetterEntry,
  decrypt: (entry: DeadLetterEntry) => Buffer,
  maxPayloadBytes: number
): DeadLetterExportRow {
  let raw: Buffer;
  let payloadError: string | undefined;
  try {
    raw = decrypt(entry);
  } catch {
    raw = Buffer.alloc(0);
    payloadError = "decrypt_failed";
  }
  let payloadTruncated = false;
  if (raw.length > maxPayloadBytes) {
    raw = raw.subarray(0, maxPayloadBytes);
    payloadTruncated = true;
  }
  // UTF-8 round-trip check: truncating mid-codepoint (or a genuinely
  // binary payload) falls back to base64 rather than emitting mojibake.
  const asUtf8 = raw.toString("utf8");
  const payloadEncoding: "utf8" | "base64" = Buffer.from(asUtf8, "utf8").equals(raw)
    ? "utf8"
    : "base64";
  return {
    id: entry.id,
    targetUrl: entry.targetUrl,
    ...(entry.tenantId !== undefined ? { tenant: entry.tenantId } : {}),
    attempts: entry.attempts,
    lastError: entry.lastError,
    deadLetteredAt: entry.deadLetteredAt,
    payloadBytes: entry.payloadBytes,
    failureClass: entry.failureClass,
    ...(entry.traceId !== undefined ? { traceId: entry.traceId } : {}),
    encrypted: entry.encryptedPayload !== undefined,
    payloadEncoding,
    payloadTruncated,
    ...(payloadError !== undefined ? { payloadError } : {}),
    payload: payloadEncoding === "utf8" ? asUtf8 : raw.toString("base64"),
  };
}

/** Fixed, limited CSV column set — the export never grows columns. */
const CSV_COLUMNS = [
  "id",
  "endpoint",
  "tenant",
  "attempts",
  "last_error",
  "dead_lettered_at",
  "payload_bytes",
  "failure_class",
  "encrypted",
  "payload_truncated",
  "payload",
] as const;

function csvCell(value: string): string {
  return /[",\r\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

/** The stream preamble: empty for JSONL, the header line for CSV. */
export function renderDeadLetterExportHeader(format: DeadLetterExportFormat): string {
  return format === "csv" ? `${CSV_COLUMNS.join(",")}\n` : "";
}

/** Render one row (without the header) for the wire format. */
export function renderDeadLetterExportRow(
  row: DeadLetterExportRow,
  format: DeadLetterExportFormat
): string {
  if (format === "jsonl") {
    return (
      JSON.stringify({
        id: row.id,
        targetUrl: row.targetUrl,
        ...(row.tenant !== undefined ? { tenant: row.tenant } : {}),
        attempts: row.attempts,
        lastError: row.lastError,
        deadLetteredAt: row.deadLetteredAt,
        payloadBytes: row.payloadBytes,
        failureClass: row.failureClass,
        ...(row.traceId !== undefined ? { traceId: row.traceId } : {}),
        encrypted: row.encrypted,
        payloadEncoding: row.payloadEncoding,
        payloadTruncated: row.payloadTruncated,
        ...(row.payloadError !== undefined ? { payloadError: row.payloadError } : {}),
        payload: row.payload,
      }) + "\n"
    );
  }
  const payloadCell = row.payloadTruncated
    ? row.payload + DEAD_LETTER_EXPORT_TRUNCATION_MARKER
    : row.payload;
  return (
    [
      row.id,
      row.targetUrl,
      row.tenant ?? "",
      String(row.attempts),
      row.lastError,
      row.deadLetteredAt,
      String(row.payloadBytes),
      row.failureClass,
      row.encrypted ? "true" : "false",
      row.payloadTruncated ? "true" : "false",
      payloadCell,
    ]
      .map(csvCell)
      .join(",") + "\n"
  );
}

/** The export plan for one response: which page, and whether the operator must page. */
export interface DeadLetterExportPlan {
  format: DeadLetterExportFormat;
  maxPayloadBytes: number;
  /** Entries matching the filter, before paging. */
  totalMatched: number;
  /** Entries in this page, in dead-letter insertion order. Empty when `needsPaging`. */
  entries: DeadLetterEntry[];
  /** True when more entries follow this page. */
  hasMore: boolean;
  /** Inclusive cursor for the next page; set only when `hasMore`. */
  nextCursor?: string;
  /**
   * True when the filter matched more than `rowLimit` rows and no
   * `cursor` was given: the server must answer 409 and ask the operator
   * to page, rather than silently return a truncated export.
   */
  needsPaging: boolean;
  /** Inclusive cursor of the first matched entry — the page-1 anchor for the 409 hint. */
  firstCursor?: string;
}

/**
 * Filter + page the dead-letter list. Pure: no I/O, no mutation. Throws
 * {@link InvalidExportCursorError} for an unknown cursor, `RangeError`
 * for an invalid format / `maxPayloadBytes` / `rowLimit` — all client
 * errors the server maps to 400.
 */
export function planDeadLetterExport(
  source: DeadLetterExportSource,
  filter: DeadLetterExportFilter,
  opts: DeadLetterExportOptions = {}
): DeadLetterExportPlan {
  const format = opts.format ?? "jsonl";
  if (format !== "jsonl" && format !== "csv") {
    throw new RangeError(`dead-letter export: format must be "jsonl" or "csv", got "${format}"`);
  }
  const maxPayloadBytes = opts.maxPayloadBytes ?? DEAD_LETTER_EXPORT_DEFAULT_MAX_PAYLOAD_BYTES;
  if (!Number.isInteger(maxPayloadBytes) || maxPayloadBytes <= 0) {
    throw new RangeError(
      `dead-letter export: maxPayloadBytes must be a positive integer, got ${maxPayloadBytes}`
    );
  }
  const rowLimit = opts.rowLimit ?? DEAD_LETTER_EXPORT_ROW_LIMIT;
  if (!Number.isInteger(rowLimit) || rowLimit <= 0) {
    throw new RangeError(
      `dead-letter export: rowLimit must be a positive integer, got ${rowLimit}`
    );
  }
  const matched = source.entries().filter((e) => matchDeadLetterExport(e, filter));
  let startIndex = 0;
  if (opts.cursor !== undefined) {
    const idx = matched.findIndex((e) => e.id === opts.cursor);
    if (idx < 0) throw new InvalidExportCursorError(opts.cursor);
    startIndex = idx;
  }
  const totalMatched = matched.length;
  const remaining = totalMatched - startIndex;
  const needsPaging = opts.cursor === undefined && remaining > rowLimit;
  const entries = needsPaging ? [] : matched.slice(startIndex, startIndex + rowLimit);
  const hasMore = !needsPaging && remaining > rowLimit;
  return {
    format,
    maxPayloadBytes,
    totalMatched,
    entries,
    hasMore,
    ...(hasMore ? { nextCursor: matched[startIndex + rowLimit].id } : {}),
    needsPaging,
    ...(needsPaging ? { firstCursor: matched[0].id } : {}),
  };
}

/**
 * Render a whole page (header + rows) into one string. Handy for tests
 * and small exports; the server streams row-by-row instead to keep a
 * 10k-row response off the heap.
 */
export function renderDeadLetterExportPage(
  plan: DeadLetterExportPlan,
  decrypt: (entry: DeadLetterEntry) => Buffer
): string {
  let out = renderDeadLetterExportHeader(plan.format);
  for (const entry of plan.entries) {
    out += renderDeadLetterExportRow(
      buildDeadLetterExportRow(entry, decrypt, plan.maxPayloadBytes),
      plan.format
    );
  }
  return out;
}
