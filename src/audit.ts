import { appendFileSync, closeSync, openSync, readFileSync, readSync, statSync } from "node:fs";
import { createHash, createHmac, randomBytes } from "node:crypto";
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
 */
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
    // WR-183: alert after the line lands — the alert references the
    // persisted line, and its own append is never re-scanned.
    if (hits.length > 0) this.appendSecretLeakAlert(event, hits);
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
