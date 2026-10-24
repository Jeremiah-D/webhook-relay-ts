import { appendFileSync, closeSync, mkdirSync, openSync, readdirSync, readFileSync, readSync, renameSync, statSync, writeFileSync } from "node:fs";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { join } from "node:path";
import { isEncryptedPayload, type PayloadEncryptor } from "./encrypt.ts";
import type { FieldMask } from "./masking.ts";
import { randomId, type SecretHit, type SecretScanner } from "./secret-scan.ts";

export type { PayloadEncryptor };
export type { FieldMask, FieldMaskRule, MaskStrategy } from "./masking.ts";
export type { SecretHit, SecretPattern, SecretScannerOptions } from "./secret-scan.ts";

/** Options for {@link AuditLog}. */
export interface AuditLogOptions {
  /**
   * When set, a `payload` field (Buffer or string) on an appended event is
   * sealed into an {@link EncryptedPayload} envelope before the line hits
   * disk, and transparently decrypted back on `readAll`/`query`. Unset by
   * default: payloads are stored as plain JSON.
   */
  payloadEncryptor?: PayloadEncryptor;
  /**
   * WR-72: field-level masking for audit payloads. When set, the
   * `payload` field of an appended event is masked (when JSON-shaped)
   * *before* `payloadEncryptor` seals it — masking always runs first, so
   * raw values reach neither the ciphertext nor a plaintext line. The
   * endpoint comes from the event's `targetUrl` (delivery events) or
   * `endpoint` field; events naming neither are never masked. Unset by
   * default: payloads are stored as received.
   */
  fieldMask?: FieldMask;
  /**
   * WR-183: secret-leak scanner for audit-persisted payloads. When set,
   * the `payload` field of an appended event is scanned for secret shapes
   * *before* the WR-72 field mask runs (the raw value is inspected, but
   * only the pattern name and field path ever reach the audit trail).
   * Each hit appends a `secret_leak_suspected` alert event carrying
   * `{ pattern, path }` — never the secret value. Alert events carry no
   * payload and are never re-scanned. Unset by default: no scanning.
   * The server installs one via `setSecretScanner()` when the `secretScan`
   * option is enabled.
   */
  secretScanner?: SecretScanner;
  /**
   * WR-184: key for the HMAC-SHA256 tamper-evident chain. `{ id }` names
   * the key era, `{ key }` is the raw key bytes (a string is UTF-8
   * encoded). When unset, a random 32-byte key is generated at
   * construction — its id is visible via `getAuditKeyId()`, and rotation
   * via `rotateAuditKey()` keeps old keys for verifying older links.
   * The WR-77 SHA-256 chain is unkeyed; the HMAC chain adds keyed
   * non-repudiation (an attacker with file-write access cannot forge
   * links without the key).
   */
  auditKey?: { id: string; key: string | Buffer };
  /**
   * WR-190: opt-in segment sealing for the audit log (see the class
   * comment for the contract). When set, the live file is sealed into
   * deterministic segment files (`<yyyymmdd>-seq-<min>-<max>.jsonl`)
   * under this directory whenever `sealMaxBytes` or `sealMaxAgeMs`
   * trips — the same naming convention as WR-188's archive segments.
   * The directory is created at construction. Unset: no sealing,
   * byte-identical behavior.
   */
  sealedDir?: string;
  /**
   * WR-190: seal the live file once it reaches this many bytes. The
   * seal runs at the start of the next `append()` — the tripping line
   * always lands in the new segment. Requires `sealedDir`.
   */
  sealMaxBytes?: number;
  /**
   * WR-190: seal the live file once its oldest line reaches this age in
   * milliseconds (file mtime at construction, or construction time for
   * a missing/empty file). Requires `sealedDir`.
   */
  sealMaxAgeMs?: number;
  /**
   * WR-190: first handler fired (error-isolated) with each sealed
   * segment's local path. The server registers its S3 offload scan
   * here when `auditS3` is configured; more handlers can be added with
   * `onAuditSegmentSealed()`.
   */
  onAuditSegmentSealed?: (localPath: string) => void;
  /**
   * WR-209: per-tenant audit retention (see {@link AuditRetentionOptions}).
   * When set, `pruneExpiredAuditEntries()` drops live-file entries older
   * than their tenant's retention (tenant override, else the global
   * default) and appends an `audit_pruned` event with per-tenant counts.
   * Unset by default: pruning is a no-op and behavior is unchanged.
   */
  auditRetention?: AuditRetentionOptions;
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
  /**
   * Keep only entries carrying this tenant id (WR-48). Matches the
   * `tenant` field that delivery-lifecycle and intake audit events carry
   * when the inbound request claimed a tenant.
   */
  tenant?: string;
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

/**
 * WR-209: per-tenant audit retention tuning, embedded in
 * {@link AuditLogOptions}. Retention is expressed in days: an entry is
 * expired once `now - ts` reaches its tenant's retention. The tenant
 * override always beats the global default; a tenant with neither an
 * override nor a default never expires. Sealed segments (WR-190) are
 * immutable compliance archives and are never pruned — retention covers
 * the live file only. Orthogonal to dead-letter retention (WR-64), which
 * governs the retry queue's dead-letter list, not the audit log.
 */
export interface AuditRetentionOptions {
  /**
   * Global default retention in days. Governs entries with no tenant
   * field and tenants absent from `tenants`. Unset: such entries never
   * expire.
   */
  defaultDays?: number;
  /**
   * Per-tenant retention in days, keyed by exact tenant id (the `tenant`
   * field delivery-lifecycle and intake audit events carry, WR-48).
   * A tenant listed here is governed by its override, never the global
   * default.
   */
  tenants?: Record<string, number>;
}

/** WR-209: per-tenant retention lookup after validation: tenant id → days, or `undefined` when the tenant never expires. */
export type RetentionDaysFor = (tenant: string | undefined) => number | undefined;

function assertRetentionDays(value: unknown, where: string): asserts value is number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    throw new RangeError(`${where} must be a finite number > 0, got ${String(value)}`);
  }
}

/**
 * WR-209: validate `auditRetention` and build the retention lookup.
 * Throws `RangeError` on any illegal value — fail-closed: a bad
 * retention config is a startup bug, never a silent no-prune or a
 * prune-everything. Returns `undefined` when retention is not
 * configured at all, so pruning stays a no-op.
 */
export function resolveAuditRetention(
  retention: AuditRetentionOptions | undefined
): RetentionDaysFor | undefined {
  if (retention === undefined) return undefined;
  if (retention === null || Array.isArray(retention) || typeof retention !== "object") {
    throw new RangeError(`AuditLog: \`auditRetention\` must be an object, got ${String(retention)}`);
  }
  if (retention.defaultDays !== undefined) {
    assertRetentionDays(retention.defaultDays, "auditRetention.defaultDays");
  }
  const perTenant = new Map<string, number>();
  if (retention.tenants !== undefined) {
    if (
      retention.tenants === null ||
      Array.isArray(retention.tenants) ||
      typeof retention.tenants !== "object"
    ) {
      throw new RangeError("auditRetention.tenants must be a Record<string, number>");
    }
    for (const [tenant, days] of Object.entries(retention.tenants)) {
      if (tenant.length === 0) {
        throw new RangeError("auditRetention.tenants keys must be non-empty tenant ids");
      }
      assertRetentionDays(days, `auditRetention.tenants[${JSON.stringify(tenant)}]`);
      perTenant.set(tenant, days);
    }
  }
  const defaultDays = retention.defaultDays;
  return (tenant) => {
    if (tenant !== undefined) {
      const override = perTenant.get(tenant);
      if (override !== undefined) return override;
    }
    return defaultDays;
  };
}

/**
 * WR-209: payload of the `audit_pruned` audit event, appended by
 * {@link AuditLog.pruneExpiredAuditEntries} after every pruning run
 * that drops at least one entry. Counts only — never entry ids,
 * payloads, endpoints, or any other entry content.
 */
export interface AuditPrunedEvent {
  event: "audit_pruned";
  /** Total entries pruned by this run. */
  pruned: number;
  /** Pruned entries per tenant id (only tenants with at least one prune). */
  prunedByTenant: Record<string, number>;
  /** Pruned entries that carried no tenant field. */
  prunedWithoutTenant: number;
}

/** WR-209: outcome of {@link AuditLog.pruneExpiredAuditEntries} — the {@link AuditPrunedEvent} payload minus the event name. */
export interface AuditPruneResult {
  pruned: number;
  prunedByTenant: Record<string, number>;
  prunedWithoutTenant: number;
}

/**
 * WR-77: the first break in an audit-log hash chain, as reported by
 * {@link AuditLog.verifyChain}.
 */
export interface AuditChainBreak {
  /** 1-based physical line number in the file where continuity first breaks. */
  line: number;
  /**
   * Machine-readable reason:
   * - `missing_chain_fields` — the line has no (or malformed) `prevHash`/`hash`
   *   fields, so nothing can be verified from here on;
   * - `prev_mismatch` — the line's `prevHash` does not equal the previous
   *   link's `hash`: a line was deleted, or foreign lines were spliced in;
   * - `hash_mismatch` — the line's content was rewritten: the stored `hash`
   *   does not match a recomputation over the line's own fields.
   */
  reason: "missing_chain_fields" | "prev_mismatch" | "hash_mismatch";
}

/** Result of {@link AuditLog.verifyChain}. JSON-serializable for the operator endpoint. */
export interface AuditChainVerification {
  /** False when a break was found; corrupt lines alone do not fail verification. */
  ok: boolean;
  /** Number of non-blank physical lines scanned. */
  lines: number;
  /** Lines whose chain links verified cleanly. */
  checked: number;
  /**
   * 1-based line numbers of segments that were not valid JSON objects.
   * Reported truthfully, but skipped: a corrupt line never breaks chain
   * continuity (orthogonal to the WR-04 index, which also skips bad lines).
   */
  corruptLines: number[];
  /** The first break, when `ok` is false. */
  firstBreak?: AuditChainBreak;
  /**
   * Hex SHA-256 of the newest verified link — the trusted head. `ok: false`
   * reports the head of the trusted prefix; an empty log reports the
   * genesis value.
   */
  head: string;
}

/**
 * WR-77: genesis `prevHash` for the first link — 32 zero bytes, hex-encoded,
 * following the LG-11 hash-chain convention in ledger-api-go.
 */
const CHAIN_GENESIS = "00".repeat(32);

const CHAIN_HASH_RE = /^[0-9a-f]{64}$/;

/**
 * WR-77: deterministic canonical JSON for hashing: object keys sorted
 * recursively, no insignificant whitespace. Applied to the JSON round-trip
 * of the line body at both `append` and `verifyChain` time, so key order in
 * the file can never affect the hash.
 */
function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  switch (typeof value) {
    case "object": {
      const rec = value as Record<string, unknown>;
      const keys = Object.keys(rec).sort();
      return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(rec[k])}`).join(",")}}`;
    }
    case "string":
      return JSON.stringify(value);
    case "number":
    case "boolean":
      return String(value);
    default:
      // Unreachable for values that survived a JSON round-trip.
      return "null";
  }
}

/**
 * WR-77: `SHA-256(prevHash || canonicalBody)` (LG-11 convention). `prevHash`
 * is a fixed 64-hex-char string, so the concatenation is unambiguous.
 */
function hashAuditLink(prevHash: string, canonicalBody: string): string {
  return createHash("sha256").update(prevHash, "utf8").update(canonicalBody, "utf8").digest("hex");
}

/**
 * WR-184: the first break in the HMAC chain, as reported by
 * {@link AuditLog.verifyHmacChain}.
 */
export interface HmacChainBreak {
  /** 1-based physical line number in the file where continuity first breaks. */
  line: number;
  /**
   * Machine-readable reason:
   * - `missing_hmac_fields` — the line has no (or malformed) `hmacPrev` /
   *   `hmac` / `hmacKeyId` fields, so nothing keyed can be verified from here
   *   on (pre-WR-184 lines, or foreign lines spliced in);
   * - `unknown_key` — the line's `hmacKeyId` names a key this instance does
   *   not hold (e.g. a log written by a previous process whose random
   *   startup key was never shared — configure `auditKey` explicitly when
   *   the HMAC chain must survive restarts);
   * - `hmac_prev_mismatch` — the line's `hmacPrev` does not equal the
   *   previous link's `hmac`: a line was deleted, or foreign lines were
   *   spliced in;
   * - `hmac_mismatch` — the line's content was rewritten: the stored
   *   `hmac` does not match a recomputation over the line's own fields
   *   with its era's key.
   */
  reason: "missing_hmac_fields" | "unknown_key" | "hmac_prev_mismatch" | "hmac_mismatch";
}

/** Result of {@link AuditLog.verifyHmacChain}. JSON-serializable for the operator endpoint. */
export interface HmacChainVerification {
  /** False when a break was found; corrupt lines alone do not fail verification. */
  ok: boolean;
  /** Number of non-blank physical lines scanned. */
  lines: number;
  /** Lines whose HMAC links verified cleanly. */
  checked: number;
  /**
   * 1-based line numbers of segments that were not valid JSON objects.
   * Reported truthfully, but skipped: a corrupt line never breaks chain
   * continuity, orthogonally to the WR-04 index which also skips bad lines.
   */
  corruptLines: number[];
  /** The first break, when `ok` is false. */
  firstBreak?: HmacChainBreak;
  /**
   * Hex HMAC of the newest verified link — the trusted head. `ok: false`
   * reports the head of the trusted prefix; an empty log reports the
   * genesis value.
   */
  head: string;
  /** The HMAC key id this instance currently appends with. */
  hmacKeyId: string;
}

/** WR-184: genesis `hmacPrev` for the first HMAC link — 32 zero bytes, hex. */
const HMAC_CHAIN_GENESIS = "00".repeat(32);

const HMAC_CHAIN_HASH_RE = /^[0-9a-f]{64}$/;

/**
 * WR-184: `HMAC-SHA256(key, prevHmac || canonicalBody)`. `prevHmac` is a
 * fixed 64-hex-char string, so the concatenation is unambiguous; the same
 * canonical body the WR-77 chain hashes is reused, so one strip of the
 * chain fields serves both verifications.
 */
function hmacAuditLink(key: Buffer, prevHmac: string, canonicalBody: string): string {
  return createHmac("sha256", key).update(prevHmac, "utf8").update(canonicalBody, "utf8").digest("hex");
}

/** WR-183: the alert event name — never re-scanned, never carries a payload. */
const SECRET_LEAK_EVENT = "secret_leak_suspected";

/** One indexed JSONL line: its searchable fields plus its byte span. */
interface IndexEntry {
  /** Millisecond epoch of the line's `ts`, or NaN when missing/invalid. */
  tsMs: number;
  event?: string;
  endpoint?: string;
  tenant?: string;
  traceId?: string;
  offset: number;
  length: number;
}

/** Parse JSON strictly: only objects/arrays qualify; anything else is not maskable. */
function tryParseJson(text: string): unknown {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return undefined;
  }
  return parsed === null || typeof parsed !== "object" ? undefined : parsed;
}

/**
 * WR-72: split a payload into its JSON value plus a re-encoder that
 * restores the original shape (Buffer stays a Buffer, string stays a
 * string, a parsed value stays parsed). Returns `undefined` when the
 * payload is not JSON-shaped — field paths cannot apply to it.
 */
function maskablePayload(
  payload: unknown
): { value: unknown; reencode: (masked: unknown) => unknown } | undefined {
  if (Buffer.isBuffer(payload)) {
    const value = tryParseJson(payload.toString("utf8"));
    if (value === undefined) return undefined;
    return { value, reencode: (masked) => Buffer.from(JSON.stringify(masked), "utf8") };
  }
  if (typeof payload === "string") {
    const value = tryParseJson(payload);
    if (value === undefined) return undefined;
    return { value, reencode: (masked) => JSON.stringify(masked) };
  }
  if (payload !== null && typeof payload === "object") {
    return { value: payload, reencode: (masked) => masked };
  }
  return undefined;
}

/**
 * Append-only JSONL audit log. Each line is a JSON object containing the
 * caller's event fields plus an ISO-8601 `ts` timestamp. Kept dependency-free
 * so the log can be inspected with plain `jq`/text tools.
 *
 * WR-77: every line also carries a tamper-evident hash-chain link
 * (`prevHash` / `hash`, SHA-256 over the previous link's hash plus a
 * canonical JSON of the line body — the LG-11 convention from
 * ledger-api-go). `verifyChain()` recomputes the chain and reports the
 * first break (rewritten, deleted, or spliced lines) with its line number.
 *
 * `query()` filters the log without re-parsing it: a lazily maintained
 * index maps each complete line to its searchable fields (`ts`, `event`,
 * `endpoint`) and its byte span in the file, so only matching lines are
 * read back. The index tracks the file size to detect appends (only the new
 * tail is scanned) and truncation/rotation (the index is rebuilt).
 *
 * WR-186: `subscribe()` adds an in-memory live listener, fanned out
 * synchronously at the end of every `append()` — the operator
 * `GET /events/audit` SSE stream is built on it. Fan-out never touches the
 * file: it is orthogonal to the WR-90 audit webhook sink, which tails the
 * JSONL file. A throwing listener can neither break the append path nor
 * starve the other listeners.
 *
 * WR-190: opt-in segment sealing for audit cold storage (compliance
 * retention). With `sealedDir` set, the live file is sealed verbatim into
 * `<sealedDir>/<yyyymmdd>-seq-<min>-<max>.jsonl` (a `-<n>` dedupe suffix
 * when the name is taken) whenever `sealMaxBytes` or `sealMaxAgeMs`
 * trips — the seal runs at the start of the tripping `append()`, so the
 * tripping line always lands in the new live file. The segment date is
 * the UTC date of its earliest line's `ts` (current UTC date when
 * unparseable); `min`/`max` are the segment's 1-based line numbers
 * (`1..N`, mirroring the WR-188 archive convention byte-for-byte).
 *
 * Rotation semantics, stated honestly:
 * - The seal writes the segment with an atomic tmp+rename, then
 *   truncates the live file. Every line lands in exactly one segment —
 *   no line is dropped and none is sealed twice.
 * - Both chains restart at genesis in the new live file (the seal
 *   resets the tip bookkeeping), so each sealed segment is
 *   independently verifiable: run `verifyChain()`/`verifyHmacChain()`
 *   against the segment file itself. A live-file verification only ever
 *   covers its current segment — stitch segments by name order for a
 *   full-history audit.
 * - The seal is best-effort: a failed seal never blocks `append()` —
 *   the live file is left untouched and the threshold stays tripped, so
 *   the next `append()` retries it.
 * - Sealed segments are fired to `onAuditSegmentSealed` handlers
 *   (error-isolated), which the server hooks to its S3 offload scan.
 * - Interaction with the WR-90 audit webhook sink (`src/audit-sink.ts`):
 *   the sink tails by path + byte offset with a persisted cursor; on a
 *   seal the live file shrinks, the sink sees `size < cursor` and
 *   rewinds to offset 0 — it then forwards only the new live file's
 *   lines, which it has not forwarded yet. Sealed lines were already
 *   forwarded before the seal, so a seal neither duplicates nor loses
 *   webhook deliveries.
 * - Single-writer assumption: sealing reads the whole live file, then
 *   truncates it. Run sealing on at most one `AuditLog` instance per
 *   live file — concurrent appends landing between the seal's read and
 *   its truncate would be dropped. (The server's single injected
 *   `AuditLog` is the intended shape; plain appends from several
 *   instances remain safe, as they always were.)
 *
 * WR-209: per-tenant audit retention. `pruneExpiredAuditEntries()` is a
 * manual, operator-driven API — there is no background sweep timer for
 * the audit log (unlike the WR-64 dead-letter sweeper, which the queue
 * owns), so a maintenance job or operator call drives pruning on its own
 * schedule. Pruning rewrites the live file with only the surviving
 * lines, re-chained from genesis under the current audit key era: deleting
 * a prefix would otherwise leave a permanent chain break at the cut, and
 * re-chaining covers only survivors' bodies (unchanged) — the operation
 * itself is attested by the `audit_pruned` event appended right after,
 * which chains onto the re-chained tip. Sealed segments are untouched.
 * Lines without a parseable `ts` and malformed lines are never pruned
 * (fail-closed: never purge blind), and a run that prunes nothing neither
 * rewrites the file nor appends an event.
 */

/** WR-186: a live audit-event listener. Receives the parsed JSONL line. */
export type AuditEventListener = (event: Record<string, unknown>) => void;

/** WR-190: a sealed-segment handler. Receives the segment's local path. */
export type AuditSegmentSealedHandler = (localPath: string) => void;

/**
 * WR-190: a parsed sealed audit-segment file name
 * (`<yyyymmdd>-seq-<min>-<max>[-<n>].jsonl`).
 */
export interface AuditSealedSegmentName {
  /** UTC date (`yyyymmdd`) of the segment's earliest line. */
  date: string;
  /** 1-based first line number in the segment. */
  seqMin: number;
  /** 1-based last line number in the segment. */
  seqMax: number;
  /** Dedupe suffix (`-<n>`) when the bare name was taken. */
  dup?: number;
}

const AUDIT_SEALED_SEGMENT_NAME_RE = /^(\d{8})-seq-(\d+)-(\d+)(?:-(\d+))?\.jsonl$/;

/**
 * WR-190: parse a sealed audit-segment file name. Returns `undefined`
 * for names that do not follow the sealing convention — the S3
 * offloader uploads those under `<prefix>misc/` instead.
 */
export function parseAuditSealedSegmentName(fileName: string): AuditSealedSegmentName | undefined {
  const m = AUDIT_SEALED_SEGMENT_NAME_RE.exec(fileName);
  if (m === null) return undefined;
  const seqMin = Number(m[2]);
  const seqMax = Number(m[3]);
  if (
    !Number.isSafeInteger(seqMin) ||
    !Number.isSafeInteger(seqMax) ||
    seqMin < 1 ||
    seqMax < seqMin
  ) {
    return undefined;
  }
  const dup = m[4] === undefined ? undefined : Number(m[4]);
  if (dup !== undefined && (!Number.isSafeInteger(dup) || dup < 2)) return undefined;
  return { date: m[1], seqMin, seqMax, ...(dup === undefined ? {} : { dup }) };
}

/**
 * WR-190: the segment date for a seal — the UTC `yyyymmdd` of the
 * earliest line's `ts`, falling back to the current UTC date when the
 * line has no parseable timestamp.
 */
function auditSealedSegmentDate(firstLine: string): string {
  let ts: unknown;
  try {
    ts = (JSON.parse(firstLine) as Record<string, unknown>).ts;
  } catch {
    ts = undefined;
  }
  const ms = typeof ts === "string" ? Date.parse(ts) : NaN;
  const d = Number.isNaN(ms) ? new Date() : new Date(ms);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}`;
}

export class AuditLog {
  private readonly path: string;
  private readonly payloadEncryptor?: PayloadEncryptor;
  private fieldMask?: FieldMask;
  private index: IndexEntry[] = [];
  /** Byte offset up to which the file has been indexed. */
  private indexedBytes = 0;
  /**
   * WR-77: hex hash of the newest chain link written (by anyone), or null
   * when unknown. `chainFileBytes` is the file size that tip was derived
   * from — any size change re-derives the tip, so rotation, truncation, or
   * another AuditLog instance appending to the same file can never fork
   * the chain silently.
   */
  private chainHead: string | null = null;
  private chainFileBytes = 0;
  /**
   * WR-184: hex HMAC of the newest HMAC link written (by anyone), or null
   * when unknown. `hmacFileBytes` is the file size that tip was derived
   * from — any size change re-derives the tip, so rotation, truncation, or
   * another AuditLog instance appending to the same file can never fork
   * the HMAC chain silently. Mirrors the WR-77 `chainHead` bookkeeping.
   */
  private hmacHead: string | null = null;
  private hmacFileBytes = 0;
  /** WR-183: secret-leak scanner for audit-persisted payloads. */
  private secretScanner?: SecretScanner;
  /**
   * WR-184: hmacKeyId → key bytes. The current key is appended with; retired
   * keys are retained so `verifyHmacChain()` can verify links from before
   * a rotation.
   */
  private readonly auditKeys = new Map<string, Buffer>();
  /** WR-184: the HMAC key id new appends are sealed under. */
  private currentKeyId: string;
  /** WR-186: in-memory live listeners, fanned out at the end of `append()`. */
  private readonly auditEventListeners = new Set<AuditEventListener>();
  /**
   * WR-209: per-tenant retention lookup (`undefined` disables pruning
   * entirely — the default, byte-identical behavior).
   */
  private readonly retentionDaysFor?: RetentionDaysFor;
  /**
   * WR-190: local dir holding sealed audit segments (unset disables
   * sealing entirely); the rolling thresholds; handlers fired with
   * each sealed segment's local path.
   */
  private readonly auditSealedDir?: string;
  private readonly auditSealMaxBytes?: number;
  private readonly auditSealMaxAgeMs?: number;
  private readonly auditSegmentSealedHandlers = new Set<AuditSegmentSealedHandler>();
  /**
   * WR-190: epoch ms the current live segment started — the live file's
   * mtime at construction when it exists and is non-empty, else
   * construction time. Reset to now after every seal.
   */
  private auditSegmentStartMs: number;

  constructor(path: string, opts: AuditLogOptions = {}) {
    this.path = path;
    this.payloadEncryptor = opts.payloadEncryptor;
    this.fieldMask = opts.fieldMask;
    this.secretScanner = opts.secretScanner;
    if (opts.auditKey !== undefined) {
      this.currentKeyId = this.registerAuditKey(opts.auditKey.id, opts.auditKey.key);
    } else {
      // WR-184: no key configured — generate a random 32-byte key at
      // startup. Links it seals verify within this instance; share the
      // key (or configure `auditKey`) when the HMAC chain must survive
      // restarts or be verifiable by another process.
      this.currentKeyId = randomId("auto");
      this.auditKeys.set(this.currentKeyId, randomBytes(32));
    }
    // WR-190: opt-in audit-log segment sealing. Fail fast on bad
    // shapes — sealing is off by default, and a half-configured seal
    // (thresholds without a directory) is a config bug, not a default.
    if (opts.sealedDir !== undefined) {
      if (typeof opts.sealedDir !== "string" || opts.sealedDir.length === 0) {
        throw new RangeError("AuditLog: `sealedDir` must be a non-empty string when set");
      }
      this.auditSealedDir = opts.sealedDir;
      mkdirSync(opts.sealedDir, { recursive: true });
    }
    for (const name of ["sealMaxBytes", "sealMaxAgeMs"] as const) {
      const value = opts[name];
      if (value !== undefined && (!Number.isFinite(value) || value <= 0)) {
        throw new RangeError(`AuditLog: \`${name}\` must be a positive finite number when set`);
      }
    }
    if (
      (opts.sealMaxBytes !== undefined || opts.sealMaxAgeMs !== undefined) &&
      this.auditSealedDir === undefined
    ) {
      throw new RangeError("AuditLog: `sealMaxBytes`/`sealMaxAgeMs` require `sealedDir` to be set");
    }
    this.auditSealMaxBytes = opts.sealMaxBytes;
    this.auditSealMaxAgeMs = opts.sealMaxAgeMs;
    if (opts.onAuditSegmentSealed !== undefined) {
      if (typeof opts.onAuditSegmentSealed !== "function") {
        throw new RangeError("AuditLog: `onAuditSegmentSealed` must be a function when set");
      }
      this.auditSegmentSealedHandlers.add(opts.onAuditSegmentSealed);
    }
    // WR-209: fail-closed validation — an illegal retention config throws
    // here, at construction, never mid-prune.
    this.retentionDaysFor = resolveAuditRetention(opts.auditRetention);
    this.auditSegmentStartMs = this.initialAuditSegmentStartMs();
  }

  /**
   * WR-190: the current live segment's start — the live file's mtime at
   * construction when it exists and is non-empty, else now. A
   * pre-existing file counts as "already aging" from its mtime, so a
   * restart does not reset the age clock.
   */
  private initialAuditSegmentStartMs(): number {
    if (this.auditSealedDir === undefined) return Date.now();
    try {
      const st = statSync(this.path);
      return st.size > 0 ? st.mtimeMs : Date.now();
    } catch {
      return Date.now();
    }
  }

  /** Validate and register a key; returns the key id. */
  private registerAuditKey(id: unknown, key: unknown): string {
    if (typeof id !== "string" || id.length === 0) {
      throw new RangeError("auditKey.id must be a non-empty string");
    }
    const keyBytes =
      Buffer.isBuffer(key) ? key : typeof key === "string" ? Buffer.from(key, "utf8") : null;
    if (keyBytes === null || keyBytes.length === 0) {
      throw new RangeError(`auditKey ${JSON.stringify(String(id))} must have a non-empty key`);
    }
    this.auditKeys.set(id, keyBytes);
    return id;
  }

  /**
   * WR-184: rotate the HMAC chain key. New appends are sealed under the
   * returned key id; the old key is retained so `verifyHmacChain()` still
   * verifies pre-rotation links (each link is verified with its own
   * era's key; the `hmacPrev` linkage carries across the rotation so the
   * chain stays continuous). The key is random 32 bytes when omitted.
   */
  rotateAuditKey(key?: string | Buffer): string {
    const id = randomId("rot");
    this.currentKeyId = this.registerAuditKey(id, key ?? randomBytes(32));
    return this.currentKeyId;
  }

  /** WR-184: the key id new appends are currently sealed under. */
  getAuditKeyId(): string {
    return this.currentKeyId;
  }

  /** Whether appended `payload` fields are sealed at rest. */
  hasPayloadEncryptor(): boolean {
    return this.payloadEncryptor !== undefined;
  }

  /**
   * WR-90: file path of the JSONL log. The audit-event webhook sink
   * (`src/audit-sink.ts`) tails this file; nothing else should need it.
   */
  get filePath(): string {
    return this.path;
  }

  /**
   * WR-190: sealed-segment directory, or `undefined` when sealing is
   * off. The server requires this to be set when its `auditS3` option
   * is configured.
   */
  get sealedDir(): string | undefined {
    return this.auditSealedDir;
  }

  /**
   * WR-72: attach (or replace) the field mask after construction. The
   * server uses this so one mask can back both the audit log and the
   * retry queue from a single option.
   */
  setFieldMask(mask: FieldMask): void {
    this.fieldMask = mask;
  }

  /** Whether appended `payload` fields are masked before persistence. */
  hasFieldMask(): boolean {
    return this.fieldMask !== undefined;
  }

  append(event: object): void {
    // WR-190: roll the live file into a sealed segment when a size/age
    // threshold tripped, *before* the new line lands — the tripping
    // line always opens the new live segment. Sealing is best-effort
    // (see `maybeSealAuditSegment`): it can never block an audit write.
    this.maybeSealAuditSegment();
    // WR-183: scan the raw payload for secret shapes *before* the WR-72
    // field mask runs. The scan sees the raw value, but only the pattern
    // name and field path ever reach the audit trail — the alert event
    // appended below carries no secret values, and the persisted line is
    // masked first, so masking still lands before anything hits disk.
    const hits = this.scanForSecrets(event);
    // WR-72: masking runs before sealing — the raw values never reach
    // the ciphertext or the plaintext line.
    // WR-77: the WR-11 encryptor seals first, then the chain hashes the
    // sealed line: the hash covers the ciphertext envelope, never plaintext.
    const body = {
      ts: new Date().toISOString(),
      ...this.sealPayload(this.applyFieldMask(event)),
    };
    // Hash the JSON round-trip of the body: canonicalJson then sees exactly
    // what lands on disk, so verifyChain's recomputation matches byte for byte.
    const canonicalBody = canonicalJson(JSON.parse(JSON.stringify(body)));
    const prevHash = this.chainPrevHash();
    const hash = hashAuditLink(prevHash, canonicalBody);
    // WR-184: the HMAC chain seals the same canonical body under the
    // current key era. It is layered on the WR-77 chain (computed first,
    // over the body without any chain fields), and verifyChain strips
    // these fields back out before its own recomputation.
    const hmacPrev = this.hmacChainPrev();
    const key = this.auditKeys.get(this.currentKeyId);
    if (key === undefined) throw new Error("AuditLog: current audit key is not registered");
    const hmac = hmacAuditLink(key, hmacPrev, canonicalBody);
    const line = JSON.stringify({ ...body, prevHash, hash, hmacPrev, hmac, hmacKeyId: this.currentKeyId });
    appendFileSync(this.path, line + "\n", "utf8");
    this.chainHead = hash;
    this.hmacHead = hmac;
    try {
      const size = statSync(this.path).size;
      this.chainFileBytes = size;
      this.hmacFileBytes = size;
    } catch {
      this.chainFileBytes = 0;
      this.hmacFileBytes = 0;
    }
    // WR-186: in-memory fan-out for live subscribers (e.g. the operator
    // `GET /events/audit` SSE stream). Fires before the WR-183 alert
    // recursion below so delivery order matches file order. Errors in a
    // subscriber are isolated — they can never break or slow the append
    // path (each subscriber is try/caught inside).
    this.notifyAuditSubscribers(line);
    // WR-183: alert after the line lands — the alert references the
    // persisted line, and its own append is never re-scanned.
    if (hits.length > 0) this.appendSecretLeakAlert(event, hits);
  }

  /**
   * WR-186: subscribe to audit events as they are appended. The listener
   * receives the parsed JSONL line (the same object `query()` would
   * return), fired synchronously at the end of each `append()`. Returns
   * an unsubscribe function. A listener that throws never affects the
   * append path or the other listeners — errors are swallowed per
   * subscriber, mirroring `RetryQueue.subscribeDeliveryEvents`.
   */
  subscribe(listener: AuditEventListener): () => void {
    this.auditEventListeners.add(listener);
    return () => {
      this.auditEventListeners.delete(listener);
    };
  }

  /**
   * WR-190: register a handler fired (error-isolated) with each sealed
   * segment's local path, mirroring WR-186's `subscribe()`. Returns an
   * unsubscribe function. The server uses this to hook its S3 offload
   * scan when `auditS3` is configured; the constructor's
   * `onAuditSegmentSealed` option registers the first handler. A handler
   * that throws can neither break the append path nor starve the other
   * handlers.
   */
  onAuditSegmentSealed(handler: AuditSegmentSealedHandler): () => void {
    if (typeof handler !== "function") {
      throw new RangeError("AuditLog: onAuditSegmentSealed handler must be a function");
    }
    this.auditSegmentSealedHandlers.add(handler);
    return () => {
      this.auditSegmentSealedHandlers.delete(handler);
    };
  }

  /** WR-190: error-isolated fan-out of one sealed segment's local path. */
  private notifyAuditSegmentSealed(localPath: string): void {
    for (const handler of this.auditSegmentSealedHandlers) {
      try {
        handler(localPath);
      } catch {
        // One misbehaving handler never breaks append() or the others.
      }
    }
  }

  /**
   * WR-190: size/age rolling seal of the live audit file, evaluated at
   * the start of every `append()`. Sealing is best-effort and never
   * throws: a failed seal leaves the live file untouched and the
   * threshold stays tripped, so the next `append()` retries it — an
   * audit write is never sacrificed for bookkeeping.
   */
  private maybeSealAuditSegment(): void {
    if (this.auditSealedDir === undefined) return;
    if (this.auditSealMaxBytes === undefined && this.auditSealMaxAgeMs === undefined) return;
    let size = 0;
    try {
      size = statSync(this.path).size;
    } catch {
      return; // No live file yet — nothing to seal.
    }
    if (size === 0) return;
    const tripped =
      (this.auditSealMaxBytes !== undefined && size >= this.auditSealMaxBytes) ||
      (this.auditSealMaxAgeMs !== undefined &&
        Date.now() - this.auditSegmentStartMs >= this.auditSealMaxAgeMs);
    if (!tripped) return;
    try {
      this.sealAuditSegment();
    } catch {
      // Swallowed on purpose: see the doc comment above.
    }
  }

  /**
   * WR-190: seal the live file into
   * `<sealedDir>/<yyyymmdd>-seq-<min>-<max>.jsonl` and truncate the live
   * file. The segment is written with an atomic tmp+rename first, so a
   * crash between the write and the truncate costs a re-seal (idempotent
   * name), never lost lines. The sealed lines are written verbatim —
   * byte-identical to the live file — so chain verifiers see the same
   * bytes the live file once held.
   *
   * Rotation restarts both chains at genesis in the new live file: the
   * segment stays independently verifiable (its 1-based line numbers
   * `1..N` match the genesis-restarted chain it carries), and a
   * live-file `verifyChain()` only ever covers its current segment.
   */
  private sealAuditSegment(): void {
    const sealedDir = this.auditSealedDir;
    if (sealedDir === undefined) return;
    const raw = readFileSync(this.path, "utf8");
    // AuditLog.append always terminates lines with "\n"; drop the final
    // empty split and keep only non-empty segments. A foreign partial
    // line without a trailing newline is sealed too — dropping bytes
    // silently would be worse than carrying a line the writer intended
    // to finish, and sealing is a single-writer operation (documented on
    // the class comment).
    const lines = raw.split("\n").filter((segment) => segment.length > 0);
    if (lines.length === 0) return;
    const date = auditSealedSegmentDate(lines[0]);
    let taken: Set<string>;
    try {
      taken = new Set(readdirSync(sealedDir));
    } catch {
      taken = new Set();
    }
    let name = `${date}-seq-1-${lines.length}.jsonl`;
    if (taken.has(name)) {
      let dup = 2;
      while (taken.has(`${date}-seq-1-${lines.length}-${dup}.jsonl`)) dup++;
      name = `${date}-seq-1-${lines.length}-${dup}.jsonl`;
    }
    const tmp = join(sealedDir, `${name}.${process.pid}.tmp`);
    writeFileSync(tmp, lines.join("\n") + "\n", "utf8");
    renameSync(tmp, join(sealedDir, name));
    // The segment is durable: now truncate the live file and restart
    // this instance's segment bookkeeping at genesis.
    writeFileSync(this.path, "", "utf8");
    this.index = [];
    this.indexedBytes = 0;
    this.chainHead = null;
    this.chainFileBytes = 0;
    this.hmacHead = null;
    this.hmacFileBytes = 0;
    this.auditSegmentStartMs = Date.now();
    this.notifyAuditSegmentSealed(join(sealedDir, name));
  }

  /** WR-186: current number of live subscribers (operator bookkeeping). */
  get subscriberCount(): number {
    return this.auditEventListeners.size;
  }

  /**
   * WR-186: synchronous in-memory fan-out of one just-persisted JSONL line.
   * Never touches the file — the WR-90 webhook sink remains the only
   * file-tailed consumer. Never throws: a corrupt line (cannot happen for
   * a line just written) and every subscriber's errors are isolated.
   */
  private notifyAuditSubscribers(line: string): void {
    if (this.auditEventListeners.size === 0) return;
    let event: Record<string, unknown>;
    try {
      event = JSON.parse(line) as Record<string, unknown>;
    } catch {
      return;
    }
    for (const listener of this.auditEventListeners) {
      try {
        listener(event);
      } catch {
        // One misbehaving subscriber never breaks append() or the others.
      }
    }
  }

  /**
   * WR-183: scan an appended event's payload for secret shapes. Alert
   * events are never re-scanned; a scan failure degrades to "no hits",
   * never a dropped audit line.
   */
  private scanForSecrets(event: object): SecretHit[] {
    if (this.secretScanner === undefined) return [];
    if ((event as Record<string, unknown>).event === SECRET_LEAK_EVENT) return [];
    return this.secretScanner.scanEventPayload(event);
  }

  /**
   * WR-183: attach (or replace) the secret scanner after construction.
   * The server uses this so one scanner backs both the inbound intake
   * scan and the audit-log scan from a single option.
   */
  setSecretScanner(scanner: SecretScanner): void {
    this.secretScanner = scanner;
  }

  /**
   * WR-183: append the `secret_leak_suspected` alert. Carries only the
   * pattern name and field path per hit — never the secret value. The
   * alert rides the normal append path (chain links included) but is
   * exempt from re-scanning, since it carries no payload. `source`
   * records where the hit was seen: `"audit"` for audit-persisted
   * payloads, `"inbound"` for the intake scan in `admitOneEvent`.
   */
  reportSecretLeak(
    context: Record<string, unknown>,
    hits: SecretHit[],
    source: "inbound" | "audit"
  ): void {
    if (hits.length === 0) return;
    const alert: Record<string, unknown> = { event: SECRET_LEAK_EVENT, source };
    for (const f of ["id", "traceId", "tenant", "targetUrl", "endpoint"] as const) {
      if (typeof context[f] === "string") alert[f] = context[f];
    }
    alert.hits = hits.map((h) => ({ pattern: h.pattern, path: h.path }));
    this.append(alert);
  }

  private appendSecretLeakAlert(event: object, hits: SecretHit[]): void {
    this.reportSecretLeak(event as Record<string, unknown>, hits, "audit");
  }

  /**
   * WR-77: the `prevHash` for the next appended link. Re-derives the tip
   * from the file whenever this instance has no tip yet or the file size
   * changed since (rotation, truncation, or another writer appending).
   */
  private chainPrevHash(): string {
    let size = 0;
    try {
      size = statSync(this.path).size;
    } catch {
      // Missing file: nothing chained yet.
    }
    if (this.chainHead === null || size !== this.chainFileBytes) {
      this.chainHead = this.readTipHash();
      this.chainFileBytes = size;
    }
    return this.chainHead;
  }

  /**
   * WR-184: the `hmacPrev` for the next appended HMAC link. Re-derives the
   * tip from the file whenever this instance has no tip yet or the file
   * size changed since (rotation, truncation, or another writer appending).
   * A newest line that predates the HMAC chain (or is corrupt) restarts the
   * chain at genesis rather than forging continuity — the same rule as the
   * WR-77 `chainPrevHash`.
   */
  private hmacChainPrev(): string {
    let size = 0;
    try {
      size = statSync(this.path).size;
    } catch {
      // Missing file: nothing chained yet.
    }
    if (this.hmacHead === null || size !== this.hmacFileBytes) {
      this.hmacHead = this.readHmacTip();
      this.hmacFileBytes = size;
    }
    return this.hmacHead;
  }

  /**
   * WR-77: scan the file tail for the newest complete line carrying a
   * well-formed `hash` link. A newest line that predates the chain (or is
   * corrupt) restarts the chain at genesis rather than forging continuity.
   */
  private readTipHash(): string {
    let raw: string;
    try {
      raw = readFileSync(this.path, "utf8");
    } catch {
      return CHAIN_GENESIS;
    }
    const segments = raw.split("\n");
    for (let i = segments.length - 1; i >= 0; i--) {
      if (segments[i].trim().length === 0) continue;
      let obj: unknown;
      try {
        obj = JSON.parse(segments[i]);
      } catch {
        continue;
      }
      if (!obj || typeof obj !== "object") continue;
      const hash = (obj as Record<string, unknown>).hash;
      if (typeof hash === "string" && CHAIN_HASH_RE.test(hash)) return hash;
      return CHAIN_GENESIS;
    }
    return CHAIN_GENESIS;
  }

  /**
   * WR-184: scan the file tail for the newest complete line carrying a
   * well-formed `hmac` link.
   */
  private readHmacTip(): string {
    let raw: string;
    try {
      raw = readFileSync(this.path, "utf8");
    } catch {
      return HMAC_CHAIN_GENESIS;
    }
    const segments = raw.split("\n");
    for (let i = segments.length - 1; i >= 0; i--) {
      if (segments[i].trim().length === 0) continue;
      let obj: unknown;
      try {
        obj = JSON.parse(segments[i]);
      } catch {
        continue;
      }
      if (!obj || typeof obj !== "object") continue;
      const hmac = (obj as Record<string, unknown>).hmac;
      if (typeof hmac === "string" && HMAC_CHAIN_HASH_RE.test(hmac)) return hmac;
      return HMAC_CHAIN_GENESIS;
    }
    return HMAC_CHAIN_GENESIS;
  }

  /**
   * WR-77: recompute the tamper-evident hash chain over the whole file.
   * Detects rewritten lines (`hash_mismatch`), deleted lines or spliced-in
   * foreign lines (`prev_mismatch`), and lines that carry no usable link at
   * all (`missing_chain_fields`), reporting the 1-based line number of the
   * first break. Corrupt (non-JSON) lines are reported in `corruptLines`
   * but skipped: they never break chain continuity, orthogonally to the
   * WR-04 line-offset index which also skips bad lines. Blank padding
   * lines are ignored entirely.
   */
  verifyChain(): AuditChainVerification {
    let raw: string;
    try {
      raw = readFileSync(this.path, "utf8");
    } catch {
      return { ok: true, lines: 0, checked: 0, corruptLines: [], head: CHAIN_GENESIS };
    }
    const corruptLines: number[] = [];
    let expectedPrev = CHAIN_GENESIS;
    let lines = 0;
    let checked = 0;
    let firstBreak: AuditChainBreak | undefined;
    const segments = raw.split("\n");
    for (let i = 0; i < segments.length; i++) {
      const segment = segments[i];
      if (i === segments.length - 1 && segment.length === 0) break; // trailing newline
      if (segment.trim().length === 0) continue; // blank padding: ignored
      const lineNo = i + 1;
      lines++;
      let obj: unknown;
      let wellFormed = true;
      try {
        obj = JSON.parse(segment);
      } catch {
        wellFormed = false;
      }
      if (!wellFormed || !obj || typeof obj !== "object" || Array.isArray(obj)) {
        corruptLines.push(lineNo);
        continue;
      }
      if (firstBreak !== undefined) continue; // keep scanning: corrupt lines are still reported
      const rec = obj as Record<string, unknown>;
      const prevHash = rec.prevHash;
      const hash = rec.hash;
      if (
        typeof prevHash !== "string" ||
        typeof hash !== "string" ||
        !CHAIN_HASH_RE.test(prevHash) ||
        !CHAIN_HASH_RE.test(hash)
      ) {
        firstBreak = { line: lineNo, reason: "missing_chain_fields" };
        continue;
      }
      if (prevHash !== expectedPrev) {
        firstBreak = { line: lineNo, reason: "prev_mismatch" };
        continue;
      }
      const { prevHash: _prev, hash: _hash, hmacPrev: _hp, hmac: _hm, hmacKeyId: _kid, ...body } = rec;
      if (hashAuditLink(prevHash, canonicalJson(body)) !== hash) {
        firstBreak = { line: lineNo, reason: "hash_mismatch" };
        continue;
      }
      expectedPrev = hash;
      checked++;
    }
    return {
      ok: firstBreak === undefined,
      lines,
      checked,
      corruptLines,
      ...(firstBreak === undefined ? {} : { firstBreak }),
      head: expectedPrev,
    };
  }

  /**
   * WR-184: recompute the keyed HMAC-SHA256 chain over the whole file.
   * Detects rewritten lines (`hmac_mismatch`), deleted lines or spliced-in
   * foreign lines (`hmac_prev_mismatch`), lines that carry no usable HMAC
   * link (`missing_hmac_fields` — including pre-WR-184 lines), and lines
   * sealed under a key this instance does not hold (`unknown_key`).
   * Each link is verified with its own era's key (keyed by the line's
   * `hmacKeyId`), so a key rotation does not break verification of older
   * links. Like WR-77's `verifyChain`, corrupt (non-JSON) lines are
   * reported in `corruptLines` but skipped — they never break chain
   * continuity, and tampered lines are reported without halting reads.
   */
  verifyHmacChain(): HmacChainVerification {
    let raw: string;
    try {
      raw = readFileSync(this.path, "utf8");
    } catch {
      return {
        ok: true,
        lines: 0,
        checked: 0,
        corruptLines: [],
        head: HMAC_CHAIN_GENESIS,
        hmacKeyId: this.currentKeyId,
      };
    }
    const corruptLines: number[] = [];
    let expectedPrev = HMAC_CHAIN_GENESIS;
    let lines = 0;
    let checked = 0;
    let firstBreak: HmacChainBreak | undefined;
    const segments = raw.split("\n");
    for (let i = 0; i < segments.length; i++) {
      const segment = segments[i];
      if (i === segments.length - 1 && segment.length === 0) break; // trailing newline
      if (segment.trim().length === 0) continue; // blank padding: ignored
      const lineNo = i + 1;
      lines++;
      let obj: unknown;
      let wellFormed = true;
      try {
        obj = JSON.parse(segment);
      } catch {
        wellFormed = false;
      }
      if (!wellFormed || !obj || typeof obj !== "object" || Array.isArray(obj)) {
        corruptLines.push(lineNo);
        continue;
      }
      if (firstBreak !== undefined) continue; // keep scanning: corrupt lines are still reported
      const rec = obj as Record<string, unknown>;
      const hmacPrev = rec.hmacPrev;
      const hmac = rec.hmac;
      const hmacKeyId = rec.hmacKeyId;
      if (
        typeof hmacPrev !== "string" ||
        typeof hmac !== "string" ||
        typeof hmacKeyId !== "string" ||
        !HMAC_CHAIN_HASH_RE.test(hmacPrev) ||
        !HMAC_CHAIN_HASH_RE.test(hmac) ||
        hmacKeyId.length === 0
      ) {
        firstBreak = { line: lineNo, reason: "missing_hmac_fields" };
        continue;
      }
      if (hmacPrev !== expectedPrev) {
        firstBreak = { line: lineNo, reason: "hmac_prev_mismatch" };
        continue;
      }
      const key = this.auditKeys.get(hmacKeyId);
      if (key === undefined) {
        firstBreak = { line: lineNo, reason: "unknown_key" };
        continue;
      }
      const { prevHash: _p, hash: _h, hmacPrev: _hp, hmac: _hm, hmacKeyId: _k, ...body } = rec;
      if (hmacAuditLink(key, hmacPrev, canonicalJson(body)) !== hmac) {
        firstBreak = { line: lineNo, reason: "hmac_mismatch" };
        continue;
      }
      expectedPrev = hmac;
      checked++;
    }
    return {
      ok: firstBreak === undefined,
      lines,
      checked,
      corruptLines,
      ...(firstBreak === undefined ? {} : { firstBreak }),
      head: expectedPrev,
      hmacKeyId: this.currentKeyId,
    };
  }

  /**
   * WR-72: mask configured PII fields in the event's `payload` before it
   * is persisted. Only JSON-shaped payloads (Buffer, string, or an
   * already-parsed value) can take field paths; anything else passes
   * through untouched. Returns the event unchanged when no mask is
   * configured, the event names no endpoint, or the endpoint has no
   * rules.
   */
  private applyFieldMask(event: object): object {
    if (this.fieldMask === undefined) return event;
    const rec = event as Record<string, unknown>;
    const endpoint =
      typeof rec.targetUrl === "string"
        ? rec.targetUrl
        : typeof rec.endpoint === "string"
          ? rec.endpoint
          : undefined;
    if (endpoint === undefined || !this.fieldMask.hasRules(endpoint)) return event;
    if (!("payload" in rec)) return event;
    const maskable = maskablePayload(rec.payload);
    if (maskable === undefined) return event;
    return {
      ...rec,
      payload: maskable.reencode(this.fieldMask.maskJson(endpoint, maskable.value)),
    };
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
   * WR-209: prune live-file entries past their tenant's retention
   * (tenant override, else the global default). Returns the prune
   * counts; when at least one entry is pruned, the live file is
   * rewritten atomically (tmp+rename) with only the surviving lines —
   * re-chained from genesis under the current audit key era, so
   * `verifyChain()`/`verifyHmacChain()` stay clean across the cut —
   * and an `audit_pruned` event carrying only the counts is appended
   * (it chains onto the re-chained tip). A run that prunes nothing
   * touches neither the file nor the event stream, and with no
   * retention configured this is a pure no-op. Lines without a
   * parseable `ts`, malformed lines, and entries whose tenant has no
   * retention are always kept. Sealed segments are never touched.
   * Single-writer assumption, as with sealing: do not prune from two
   * instances against the same live file concurrently.
   */
  pruneExpiredAuditEntries(nowMs: number = Date.now()): AuditPruneResult {
    const empty: AuditPruneResult = { pruned: 0, prunedByTenant: {}, prunedWithoutTenant: 0 };
    const retentionDaysFor = this.retentionDaysFor;
    if (retentionDaysFor === undefined) return empty;
    let raw: string;
    try {
      raw = readFileSync(this.path, "utf8");
    } catch {
      return empty; // Missing file: nothing to prune.
    }
    const segments = raw.split("\n");
    if (segments.length > 0 && segments[segments.length - 1].length === 0) {
      segments.pop(); // trailing newline: not a line
    }
    const survivors: string[] = [];
    const prunedByTenant: Record<string, number> = {};
    let prunedWithoutTenant = 0;
    let pruned = 0;
    for (const line of segments) {
      let obj: unknown;
      try {
        obj = JSON.parse(line);
      } catch {
        survivors.push(line); // malformed: kept, never purged blind
        continue;
      }
      if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
        survivors.push(line);
        continue;
      }
      const rec = obj as Record<string, unknown>;
      const tsMs = typeof rec.ts === "string" ? Date.parse(rec.ts) : NaN;
      if (!Number.isFinite(tsMs)) {
        survivors.push(line); // unparseable timestamp: kept
        continue;
      }
      const tenant = typeof rec.tenant === "string" ? rec.tenant : undefined;
      const days = retentionDaysFor(tenant);
      if (days === undefined) {
        survivors.push(line); // no retention for this tenant: kept
        continue;
      }
      if (nowMs - tsMs < days * 86400_000) {
        survivors.push(line); // unexpired: kept
        continue;
      }
      pruned++;
      if (tenant === undefined) {
        prunedWithoutTenant++;
      } else {
        prunedByTenant[tenant] = (prunedByTenant[tenant] ?? 0) + 1;
      }
    }
    if (pruned === 0) return empty;

    // Re-chain the survivors from genesis: deleting the expired prefix
    // would otherwise strand every survivor's `prevHash`/`hmacPrev` and
    // leave a permanent chain break. Bodies are untouched; only the
    // chain fields are recomputed, under the current key era. Malformed
    // lines ride through verbatim — `verifyChain()` skips them without
    // breaking continuity, as it always has.
    const key = this.auditKeys.get(this.currentKeyId);
    if (key === undefined) throw new Error("AuditLog: current audit key is not registered");
    let prevHash = CHAIN_GENESIS;
    let prevHmac = HMAC_CHAIN_GENESIS;
    const rechained: string[] = [];
    for (const line of survivors) {
      let obj: unknown;
      try {
        obj = JSON.parse(line);
      } catch {
        rechained.push(line);
        continue;
      }
      if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
        rechained.push(line);
        continue;
      }
      const { prevHash: _p, hash: _h, hmacPrev: _hp, hmac: _hm, hmacKeyId: _k, ...body } =
        obj as Record<string, unknown>;
      const canonicalBody = canonicalJson(JSON.parse(JSON.stringify(body)));
      const thisPrevHash = prevHash;
      const hash = hashAuditLink(thisPrevHash, canonicalBody);
      const hmacPrev = prevHmac;
      const hmac = hmacAuditLink(key, hmacPrev, canonicalBody);
      prevHash = hash;
      prevHmac = hmac;
      rechained.push(
        JSON.stringify({ ...body, prevHash: thisPrevHash, hash, hmacPrev, hmac, hmacKeyId: this.currentKeyId })
      );
    }
    const tmp = `${this.path}.${process.pid}.tmp`;
    writeFileSync(tmp, rechained.length > 0 ? rechained.join("\n") + "\n" : "", "utf8");
    renameSync(tmp, this.path);
    this.index = [];
    this.indexedBytes = 0;
    this.chainHead = null;
    this.chainFileBytes = 0;
    this.hmacHead = null;
    this.hmacFileBytes = 0;
    const result: AuditPruneResult = { pruned, prunedByTenant, prunedWithoutTenant };
    this.append({ event: "audit_pruned", ...result });
    return result;
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
      if (filter.tenant !== undefined && e.tenant !== filter.tenant) return false;
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
    const tenant = typeof rec.tenant === "string" ? rec.tenant : undefined;
    this.index.push({ tsMs: ts, event, endpoint, tenant, traceId, offset, length: line.length });
  }
}
