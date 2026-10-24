/**
 * Dead-letter S3 archive offload (WR-206).
 *
 * Poisoned deliveries land in the retry queue's dead-letter list *with
 * their payloads* — and for regulated flows those payloads are
 * compliance evidence that must survive the process. This module
 * offloads dead-letter entries to S3-compatible storage (AWS S3,
 * MinIO, R2, …) as one payload-bearing JSON document per entry:
 *
 * - the source is a {@link DeadLetterExportSource} (the same interface
 *   the WR-128 local export uses): `entries()` lists the live dead
 *   letters in insertion order, `decrypt(entry)` opens WR-11 sealed
 *   payloads transparently — the offloader never sees an envelope;
 * - documents carry the *full* payload (decrypted, never truncated:
 *   this is cold compliance retention, not an operator download), with
 *   `payloadEncoding` (`"utf8"` / `"base64"`, the WR-128 convention) so
 *   binary payloads survive the JSON document;
 * - object keys are deterministic —
 *   `<prefix><yyyymmdd>/deadletter-<entryId>.json` from the entry's
 *   `deadLetteredAt` — so re-uploading the same entry is an idempotent
 *   PUT to the same key, never a duplicate object;
 * - signing reuses the WR-116 SigV4 pipeline (`signAwsSigV4`); the
 *   endpoint config carries `secretRef` (a reference, never the raw
 *   secret), resolved per upload through an injected `SecretResolver`;
 * - the transport is `node:http(s)` only — zero new dependencies;
 * - uploads never touch the delivery path: `scanAndUpload()` is meant
 *   to run fire-and-forget (an operator cron, or a detached timer) —
 *   it never throws, every failure is counted in `stats().uploadFailures`
 *   and retried on the next scan;
 * - an uploaded entry is marked `<entryId>.uploaded` (in memory, plus
 *   an optional `markerDir` of marker files so the mark survives a
 *   restart); `deleteLocalAfterUpload: true` opts into purging the
 *   entry from the local dead-letter store as well;
 * - `dryRun: true` rehearses: intended keys are recorded in
 *   `dryRunKeys`, zero network I/O, no markers written, no local state
 *   touched (the archive-s3 dry-run convention).
 *
 * Orthogonal to `src/archive-s3.ts` (WR-188: offloads the
 * delivery-event archive — payload-free metadata lines) and to
 * `src/deadletter-export.ts` (WR-128: local CSV/JSONL operator
 * download of dead letters with payloads).
 */

import { createHash } from "node:crypto";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import {
  defaultSecretResolver,
  signAwsSigV4,
  type SecretResolver,
} from "./sigv4.ts";
import type { DeadLetterEntry } from "./retry.ts";
import type { DeadLetterExportSource } from "./deadletter-export.ts";

/** Suffix for the upload markers (`<entryId>.uploaded`). */
export const DEAD_LETTER_S3_UPLOADED_SUFFIX = ".uploaded";

/** Default per-PUT timeout. */
export const DEAD_LETTER_S3_REQUEST_TIMEOUT_MS = 30_000;

/** Archive document version, for forward-compatible readers. */
export const DEAD_LETTER_S3_DOCUMENT_VERSION = 1;

/**
 * What the offloader needs from the dead-letter store: the WR-128
 * export source plus an optional purge hook for the
 * `deleteLocalAfterUpload` opt-in.
 */
export interface DeadLetterS3Source extends DeadLetterExportSource {
  /**
   * Remove an entry from the local dead-letter store after its archive
   * upload succeeded. Called only when `deleteLocalAfterUpload` is set.
   * Returns `true` when the entry was actually removed. Failures are
   * best-effort and never fail the upload.
   */
  purge?(id: string): boolean;
}

/** Per-endpoint S3 offload configuration (WR-206). */
export interface DeadLetterS3OffloadConfig {
  /**
   * Store endpoint, e.g. `https://s3.us-east-1.amazonaws.com` or
   * `http://localhost:9000` for MinIO. No trailing slash. The scheme
   * selects the transport (`node:https` / `node:http`).
   */
  endpoint: string;
  /** Bucket holding the archived dead letters. Must already exist. */
  bucket: string;
  /** AWS region for the SigV4 credential scope, e.g. `us-east-1`. */
  region: string;
  /**
   * Key prefix inside the bucket, e.g. `relay-deadletters/`. Defaults
   * to `''` (bucket root). Normalized to slash-terminated internally.
   */
  keyPrefix?: string;
  /** AWS access key id. Not secret — safe to log/audit. */
  accessKeyId: string;
  /**
   * Secret-store reference naming where the secret access key lives
   * (WR-116 convention: an environment variable name with the
   * default resolver). Never the raw secret — config snapshots,
   * audit logs and stats can never leak key material.
   */
  secretRef: string;
  /**
   * Resolves `secretRef` to key material per upload attempt (so a
   * rotation takes effect without a restart). Defaults to
   * `defaultSecretResolver` (environment variable lookup).
   */
  secretResolver?: SecretResolver;
  /**
   * Optional directory holding `<entryId>.uploaded` marker files, so
   * the uploaded mark survives a process restart. Created on demand.
   * Unset: marks live in memory only (still correct — re-uploading is
   * an idempotent PUT to a deterministic key).
   */
  markerDir?: string;
  /**
   * Opt-in: purge the entry from the local dead-letter store (via
   * `source.purge`) after a successful upload. Default `false` — the
   * entry stays and is only marked uploaded. Requires the source to
   * provide `purge`; without it the flag is a no-op.
   */
  deleteLocalAfterUpload?: boolean;
  /**
   * Rehearsal mode: `scanAndUpload()` records the intended object keys
   * in `dryRunKeys` and performs zero network I/O — no markers, no
   * purges, no stat changes to the uploaded/failed counters.
   */
  dryRun?: boolean;
  /** Per-request timeout in ms; default {@link DEAD_LETTER_S3_REQUEST_TIMEOUT_MS}. */
  requestTimeoutMs?: number;
}

/** One archived dead-letter entry: payload-bearing, decrypted, full bytes. */
export interface DeadLetterArchiveDocument {
  /** Archive document version ({@link DEAD_LETTER_S3_DOCUMENT_VERSION}). */
  v: number;
  id: string;
  targetUrl: string;
  tenantId?: string;
  attempts: number;
  lastError: string;
  deadLetteredAt: string;
  failureClass: string;
  traceId?: string;
  /** True when the payload was sealed at rest (WR-11). */
  encrypted: boolean;
  /** `"utf8"` when the payload decoded cleanly, `"base64"` otherwise. */
  payloadEncoding: "utf8" | "base64";
  /** Set when sealed-payload decryption failed; `payload` is `""` then. */
  payloadError?: string;
  /** The full (decrypted) payload — never truncated: compliance cold retention. */
  payload: string;
  /** Original payload byte length (also when encrypted). */
  payloadBytes: number;
}

/** One upload attempt's outcome. */
export interface DeadLetterUploadResult {
  /** The dead-letter entry's id. */
  entry: string;
  /** Deterministic object key the entry uploads to. */
  key: string;
  /** `true` when the document is durably stored (or rehearsed, in dry-run). */
  ok: boolean;
  /** `true` only in dry-run mode: no network I/O happened. */
  dryRun?: boolean;
  /** Present when `ok` is false: endpoint + status/transport detail, never key material. */
  error?: string;
}

/** Introspection counters (WR-206). */
export interface DeadLetterS3Stats {
  /** Entries successfully uploaded (real, not dry-run). */
  uploaded: number;
  /** Upload attempts that failed (counted, retried on the next scan). */
  uploadFailures: number;
  /** Entries currently awaiting upload. */
  pending: number;
}

/** Thrown for hard offload failures on the explicit `uploadEntry()` path. */
export class DeadLetterS3Error extends Error {
  readonly entry: string;
  constructor(entry: string, message: string) {
    super(`deadletter-s3[${entry}]: ${message}`);
    this.name = "DeadLetterS3Error";
    this.entry = entry;
  }
}

const REGION_RE = /^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$/;

/**
 * Validate an offload config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-upload.
 */
export function assertValidDeadLetterS3Config(
  cfg: unknown,
  label: string
): asserts cfg is DeadLetterS3OffloadConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  if (typeof c.endpoint !== "string" || c.endpoint === "") {
    throw new RangeError(at("`endpoint` must be a non-empty URL"));
  }
  let parsed: URL;
  try {
    parsed = new URL(c.endpoint);
  } catch {
    throw new RangeError(at("`endpoint` is not a valid URL"));
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new RangeError(at("`endpoint` must be an http(s) URL"));
  }
  if (c.endpoint.endsWith("/")) {
    throw new RangeError(at("`endpoint` must not end with a slash"));
  }
  if (typeof c.bucket !== "string" || c.bucket === "") {
    throw new RangeError(at("`bucket` must be a non-empty string"));
  }
  if (typeof c.region !== "string" || !REGION_RE.test(c.region)) {
    throw new RangeError(at("`region` must look like an AWS region (e.g. `us-east-1`)"));
  }
  if (c.keyPrefix !== undefined && typeof c.keyPrefix !== "string") {
    throw new RangeError(at("`keyPrefix` must be a string when set"));
  }
  if (typeof c.accessKeyId !== "string" || c.accessKeyId === "") {
    throw new RangeError(at("`accessKeyId` must be a non-empty string"));
  }
  if (typeof c.secretRef !== "string" || c.secretRef === "") {
    throw new RangeError(at("`secretRef` must be a non-empty string (a reference, never the raw secret)"));
  }
  if (c.secretResolver !== undefined && typeof c.secretResolver !== "function") {
    throw new RangeError(at("`secretResolver` must be a function when set"));
  }
  if (c.markerDir !== undefined && (typeof c.markerDir !== "string" || c.markerDir === "")) {
    throw new RangeError(at("`markerDir` must be a non-empty string when set"));
  }
  if (
    c.requestTimeoutMs !== undefined &&
    (!Number.isFinite(c.requestTimeoutMs) || c.requestTimeoutMs <= 0)
  ) {
    throw new RangeError(at("`requestTimeoutMs` must be a positive finite number"));
  }
}

function normalizeKeyPrefix(prefix: string): string {
  const trimmed = prefix.replace(/^\/+/, "");
  if (trimmed === "") return "";
  return trimmed.endsWith("/") ? trimmed : `${trimmed}/`;
}

function encodeS3Key(key: string): string {
  return key.split("/").map(encodeURIComponent).join("/");
}

/** `yyyymmdd` in UTC from the entry's `deadLetteredAt`, or `unknown-date`. */
function archiveDatePart(deadLetteredAt: string): string {
  const ms = Date.parse(deadLetteredAt);
  if (Number.isNaN(ms)) return "unknown-date";
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}`;
}

/**
 * Build the payload-bearing archive document for one dead-letter
 * entry. Sealed payloads (WR-11) are decrypted through the source's
 * decryptor; a decryption failure marks the document
 * (`payloadError: "decrypt_failed"`, empty payload) instead of failing
 * the upload — one undecryptable entry must not nuke the whole scan.
 * The payload is embedded in full: this is compliance cold retention,
 * not a bounded operator download.
 */
export function buildDeadLetterArchiveDocument(
  entry: DeadLetterEntry,
  decrypt: (entry: DeadLetterEntry) => Buffer
): DeadLetterArchiveDocument {
  let raw: Buffer;
  let payloadError: string | undefined;
  try {
    raw = decrypt(entry);
  } catch {
    raw = Buffer.alloc(0);
    payloadError = "decrypt_failed";
  }
  // UTF-8 round-trip check: a binary payload falls back to base64
  // rather than emitting mojibake into the JSON document.
  const asUtf8 = raw.toString("utf8");
  const payloadEncoding: "utf8" | "base64" = Buffer.from(asUtf8, "utf8").equals(raw)
    ? "utf8"
    : "base64";
  return {
    v: DEAD_LETTER_S3_DOCUMENT_VERSION,
    id: entry.id,
    targetUrl: entry.targetUrl,
    ...(entry.tenantId !== undefined ? { tenantId: entry.tenantId } : {}),
    attempts: entry.attempts,
    lastError: entry.lastError,
    deadLetteredAt: entry.deadLetteredAt,
    failureClass: entry.failureClass,
    ...(entry.traceId !== undefined ? { traceId: entry.traceId } : {}),
    encrypted: entry.encryptedPayload !== undefined,
    payloadEncoding,
    ...(payloadError !== undefined ? { payloadError } : {}),
    payload: payloadEncoding === "utf8" ? asUtf8 : raw.toString("base64"),
    payloadBytes: entry.payloadBytes,
  };
}

/**
 * S3-compatible offloader for dead-letter entries (WR-206).
 *
 * The offloader is passive: the retry queue accumulates dead letters,
 * and someone — an operator cron, a detached timer — runs
 * `scanAndUpload()` fire-and-forget. All per-entry failures are
 * counted in `uploadFailures` and retried on the next scan;
 * `scanAndUpload()` itself never throws, so archive bookkeeping can
 * never fail a delivery.
 */
export class DeadLetterS3Offloader {
  private readonly cfg: DeadLetterS3OffloadConfig;
  private readonly source: DeadLetterS3Source;
  private readonly keyPrefix: string;
  private readonly secretResolver: SecretResolver;
  private readonly requestTimeoutMs: number;
  private readonly uploadedIds = new Set<string>();
  private uploaded = 0;
  private uploadFailures = 0;
  private readonly dryRunKeys: string[] = [];

  constructor(config: DeadLetterS3OffloadConfig, source: DeadLetterS3Source) {
    assertValidDeadLetterS3Config(config, "DeadLetterS3Offloader");
    if (source === null || typeof source !== "object") {
      throw new RangeError("DeadLetterS3Offloader: `source` must be an object");
    }
    if (typeof source.entries !== "function" || typeof source.decrypt !== "function") {
      throw new RangeError(
        "DeadLetterS3Offloader: `source` must implement DeadLetterExportSource (entries/decrypt)"
      );
    }
    this.cfg = config;
    this.source = source;
    this.keyPrefix = normalizeKeyPrefix(config.keyPrefix ?? "");
    this.secretResolver = config.secretResolver ?? defaultSecretResolver;
    this.requestTimeoutMs = config.requestTimeoutMs ?? DEAD_LETTER_S3_REQUEST_TIMEOUT_MS;
    this.loadMarkers();
  }

  /** Dead-letter entries not yet marked uploaded, in insertion order. */
  pendingEntries(): DeadLetterEntry[] {
    return this.source.entries().filter((e) => !this.uploadedIds.has(e.id));
  }

  /**
   * Deterministic object key for an entry:
   * `<prefix><yyyymmdd>/deadletter-<entryId>.json`. The entry id is
   * URI-encoded so ids containing `/` cannot escape the date prefix.
   */
  entryObjectKey(entry: DeadLetterEntry): string {
    return `${this.keyPrefix}${archiveDatePart(entry.deadLetteredAt)}/deadletter-${encodeURIComponent(entry.id)}.json`;
  }

  /** Intended keys from dry-run scans, in scan order. */
  getDryRunKeys(): string[] {
    return [...this.dryRunKeys];
  }

  get stats(): DeadLetterS3Stats {
    return {
      uploaded: this.uploaded,
      uploadFailures: this.uploadFailures,
      pending: this.pendingEntries().length,
    };
  }

  /**
   * Upload one dead-letter entry. Throws `DeadLetterS3Error` on any
   * failure (missing secret, transport error, non-2xx status).
   * Idempotent: the object key is deterministic, so a retry of the
   * same entry is a PUT to the same key — no duplicate objects.
   */
  async uploadEntry(entry: DeadLetterEntry): Promise<DeadLetterUploadResult> {
    const key = this.entryObjectKey(entry);
    if (this.cfg.dryRun === true) {
      this.dryRunKeys.push(key);
      return { entry: entry.id, key, ok: true, dryRun: true };
    }
    const body = Buffer.from(
      JSON.stringify(buildDeadLetterArchiveDocument(entry, (e) => this.source.decrypt(e)))
    );
    const secret = this.secretResolver(this.cfg.secretRef);
    if (secret === undefined || secret === "") {
      throw new DeadLetterS3Error(
        entry.id,
        `secret unavailable (secretRef "${this.cfg.secretRef}" did not resolve)`
      );
    }
    const payloadHash = createHash("sha256").update(body).digest("hex");
    const signed = signAwsSigV4({
      method: "PUT",
      url: this.objectUrl(key),
      body,
      credentials: { accessKeyId: this.cfg.accessKeyId, secretAccessKey: secret },
      region: this.cfg.region,
      service: "s3",
      extraSignedHeaders: { "x-amz-content-sha256": payloadHash },
    });
    const status = await this.putObject(key, body, signed, payloadHash);
    if (status < 200 || status >= 300) {
      throw new DeadLetterS3Error(
        entry.id,
        `PUT ${this.cfg.endpoint}/${this.cfg.bucket}/${key} -> HTTP ${status}`
      );
    }
    this.markUploaded(entry.id);
    this.uploaded += 1;
    return { entry: entry.id, key, ok: true };
  }

  /**
   * Scan the dead-letter store and upload every pending entry.
   * Never throws: each entry's failure is counted in `uploadFailures`
   * and returned in its result — the next scan retries it.
   */
  async scanAndUpload(): Promise<DeadLetterUploadResult[]> {
    const results: DeadLetterUploadResult[] = [];
    for (const entry of this.pendingEntries()) {
      try {
        results.push(await this.uploadEntry(entry));
      } catch (err) {
        this.uploadFailures += 1;
        results.push({
          entry: entry.id,
          key: this.entryObjectKey(entry),
          ok: false,
          error: (err as Error).message,
        });
      }
    }
    return results;
  }

  private objectUrl(key: string): string {
    return `${this.cfg.endpoint}/${this.cfg.bucket}/${encodeS3Key(key)}`;
  }

  private putObject(
    key: string,
    body: Buffer,
    signed: { authorization: string; amzDate: string },
    payloadHash: string
  ): Promise<number> {
    return new Promise((resolve, reject) => {
      const url = new URL(this.objectUrl(key));
      const requestFn = url.protocol === "https:" ? httpsRequest : httpRequest;
      const fail = (message: string): void => {
        reject(new DeadLetterS3Error(basename(key), `PUT transport failed: ${message}`));
      };
      let req;
      try {
        req = requestFn(
          {
            protocol: url.protocol,
            hostname: url.hostname,
            port: url.port === "" ? undefined : Number(url.port),
            path: `${url.pathname}${url.search}`,
            method: "PUT",
            headers: {
              authorization: signed.authorization,
              "x-amz-date": signed.amzDate,
              "x-amz-content-sha256": payloadHash,
              "content-type": "application/json",
              "content-length": String(body.length),
            },
          },
          (res) => {
            // Drain the response body so the socket can be reused.
            res.on("data", () => undefined);
            res.on("end", () => resolve(res.statusCode ?? 0));
          }
        );
      } catch (err) {
        fail((err as Error).message);
        return;
      }
      req.on("error", (err) => fail(err.message));
      req.setTimeout(this.requestTimeoutMs, () => {
        req.destroy();
        fail(`timed out after ${this.requestTimeoutMs}ms`);
      });
      req.end(body);
    });
  }

  /**
   * Mark an entry as uploaded: the in-memory set plus an optional
   * `<entryId>.uploaded` marker file. Failures are best-effort and
   * never thrown — the marker is bookkeeping, not the upload. With
   * `deleteLocalAfterUpload`, the entry is additionally purged from
   * the local dead-letter store (also best-effort: an un-purgeable
   * entry is simply re-marked on the next scan).
   */
  private markUploaded(entryId: string): void {
    this.uploadedIds.add(entryId);
    try {
      if (this.cfg.markerDir !== undefined) {
        mkdirSync(this.cfg.markerDir, { recursive: true });
        writeFileSync(
          join(this.cfg.markerDir, `${encodeURIComponent(entryId)}${DEAD_LETTER_S3_UPLOADED_SUFFIX}`),
          ""
        );
      }
    } catch {
      /* best effort: the entry will be re-uploaded (idempotent key) */
    }
    if (this.cfg.deleteLocalAfterUpload === true && this.source.purge !== undefined) {
      try {
        this.source.purge(entryId);
      } catch {
        /* best effort */
      }
    }
  }

  /** Rehydrate the uploaded set from marker files (best effort). */
  private loadMarkers(): void {
    if (this.cfg.markerDir === undefined) return;
    let names: string[];
    try {
      names = readdirSync(this.cfg.markerDir);
    } catch {
      return; // no markers yet — a fresh deploy must not error
    }
    const suffix = DEAD_LETTER_S3_UPLOADED_SUFFIX;
    for (const name of names) {
      if (!name.endsWith(suffix)) continue;
      try {
        this.uploadedIds.add(decodeURIComponent(name.slice(0, -suffix.length)));
      } catch {
        /* skip unparseable marker names */
      }
    }
  }
}
