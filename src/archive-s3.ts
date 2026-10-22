/**
 * Delivery-event archive S3-compatible offload (WR-188).
 *
 * The archive's time/size rolling retention (WR-55) evicts the oldest
 * lines from the live `events.jsonl`; with `DeliveryEventArchiver`
 * `sealedDir` set, those evicted lines are sealed first into
 * deterministic segment files — `<yyyymmdd>-seq-<minSeq>-<maxSeq>.jsonl`
 * — instead of being discarded. This module uploads those sealed
 * segments to S3-compatible storage (AWS S3, MinIO, R2, …), giving the
 * archive a cold-storage tail:
 *
 * - signing reuses the WR-116 SigV4 pipeline (`signAwsSigV4`): every
 *   PUT carries `Authorization` + `x-amz-date` (+ `x-amz-content-sha256`
 *   as a signed header); the endpoint config carries `secretRef` (a
 *   reference, never the raw secret), resolved per upload through an
 *   injected `SecretResolver` — the same reference/plumbing split as
 *   WR-116;
 * - object keys are deterministic — `<prefix><yyyymmdd>/events-<min>-<max>.jsonl`
 *   derived from the segment file name — so re-uploading the same
 *   segment is an idempotent PUT to the same key, never a duplicate
 *   object;
 * - the transport is `node:http(s)` only — zero new dependencies;
 * - uploads never touch the delivery path: `DeliveryEventArchiver`
 *   fires `onSegmentSealed` (error-isolated) and the offloader's
 *   `scanAndUpload()` runs fire-and-forget; every failure is counted
 *   in `stats().uploadFailures` and retried on the next scan —
 *   uploading can never fail a delivery;
 * - an uploaded segment is marked `<name>.jsonl.uploaded` by default
 *   (local bytes kept); `deleteLocalAfterUpload: true` opts into
 *   deleting the local copy instead;
 * - `dryRun: true` rehearses: intended keys are recorded in
 *   `dryRunKeys`, zero network I/O, no markers written, no local
 *   files touched (the EB-163 `DryRunS3Client` convention).
 *
 * Orthogonal to `src/deadletter-export.ts` (WR-128, local CSV/JSONL
 * export of dead letters with payloads) and to EB-163 (durable-log
 * segment offload in realtime-event-bus, another repo): this module
 * offloads the *delivery-event archive*, payload-free metadata lines.
 */

import { createHash } from "node:crypto";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { readFileSync, readdirSync, renameSync, rmSync } from "node:fs";
import { basename, join } from "node:path";
import {
  defaultSecretResolver,
  signAwsSigV4,
  type SecretResolver,
} from "./sigv4.ts";
import { parseSealedSegmentName } from "./event-archive.ts";

/** Suffix marking a sealed segment as uploaded (local bytes kept). */
export const ARCHIVE_UPLOADED_SUFFIX = ".uploaded";

/** Default per-PUT timeout. */
export const ARCHIVE_S3_REQUEST_TIMEOUT_MS = 30_000;

/** Per-endpoint S3 offload configuration (WR-188). */
export interface ArchiveS3OffloadConfig {
  /**
   * Local directory holding sealed segments (the archiver's
   * `sealedDir`). Must exist by the time `scanAndUpload()` runs —
   * the archiver creates it; a missing directory reads as "nothing
   * pending", never an error.
   */
  sealedDir: string;
  /**
   * Store endpoint, e.g. `https://s3.us-east-1.amazonaws.com` or
   * `http://localhost:9000` for MinIO. No trailing slash. The scheme
   * selects the transport (`node:https` / `node:http`).
   */
  endpoint: string;
  /** Bucket holding the offloaded segments. Must already exist. */
  bucket: string;
  /** AWS region for the SigV4 credential scope, e.g. `us-east-1`. */
  region: string;
  /**
   * Key prefix inside the bucket, e.g. `relay-archives/`. Defaults to
   * `''` (bucket root). Normalized to slash-terminated internally.
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
   * Opt-in: delete the local segment file after a successful upload.
   * Default `false` — the segment is renamed to
   * `<name>.jsonl.uploaded` and the local bytes are kept.
   */
  deleteLocalAfterUpload?: boolean;
  /**
   * Rehearsal mode: `scanAndUpload()` records the intended object keys
   * in `dryRunKeys` and performs zero network I/O — no markers, no
   * deletions, no stat changes to the uploaded/failed counters.
   */
  dryRun?: boolean;
  /** Per-request timeout in ms; default {@link ARCHIVE_S3_REQUEST_TIMEOUT_MS}. */
  requestTimeoutMs?: number;
}

/** One upload attempt's outcome. */
export interface ArchiveUploadResult {
  /** The sealed segment's file name (not the full path). */
  segment: string;
  /** Deterministic object key the segment uploads to. */
  key: string;
  /** `true` when the bytes are durably stored (or rehearsed, in dry-run). */
  ok: boolean;
  /** `true` only in dry-run mode: no network I/O happened. */
  dryRun?: boolean;
  /** Present when `ok` is false: endpoint + status/transport detail, never key material. */
  error?: string;
}

/** Introspection counters (WR-188). */
export interface ArchiveS3Stats {
  /** Segments successfully uploaded (real, not dry-run). */
  uploaded: number;
  /** Upload attempts that failed (counted, retried on the next scan). */
  uploadFailures: number;
  /** Segments currently awaiting upload. */
  pending: number;
}

/** Thrown for hard offload failures on the explicit `uploadSegment()` path. */
export class ArchiveS3Error extends Error {
  readonly segment: string;
  constructor(segment: string, message: string) {
    super(`archive-s3[${segment}]: ${message}`);
    this.name = "ArchiveS3Error";
    this.segment = segment;
  }
}

const REGION_RE = /^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$/;

/**
 * Validate an offload config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-upload.
 */
export function assertValidArchiveS3Config(
  cfg: unknown,
  label: string
): asserts cfg is ArchiveS3OffloadConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  if (typeof c.sealedDir !== "string" || c.sealedDir === "") {
    throw new RangeError(at("`sealedDir` must be a non-empty string"));
  }
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

/**
 * S3-compatible offloader for sealed archive segments (WR-188).
 *
 * The offloader is passive: the archiver seals segments, and someone —
 * the server's fire-and-forget `onSegmentSealed` hook, an operator
 * cron, or an explicit call — runs `scanAndUpload()`. All per-segment
 * failures are counted in `uploadFailures` and retried on the next
 * scan; `scanAndUpload()` itself never throws, so upload bookkeeping
 * can never fail a delivery.
 */
export class ArchiveS3Offloader {
  private readonly cfg: ArchiveS3OffloadConfig;
  private readonly keyPrefix: string;
  private readonly secretResolver: SecretResolver;
  private readonly requestTimeoutMs: number;
  private uploaded = 0;
  private uploadFailures = 0;
  private readonly dryRunKeys: string[] = [];

  constructor(config: ArchiveS3OffloadConfig) {
    assertValidArchiveS3Config(config, "ArchiveS3Offloader");
    this.cfg = config;
    this.keyPrefix = normalizeKeyPrefix(config.keyPrefix ?? "");
    this.secretResolver = config.secretResolver ?? defaultSecretResolver;
    this.requestTimeoutMs = config.requestTimeoutMs ?? ARCHIVE_S3_REQUEST_TIMEOUT_MS;
  }

  /** Sealed segments awaiting upload, sorted by name (== chronological). */
  pendingSegments(): string[] {
    let names: string[];
    try {
      names = readdirSync(this.cfg.sealedDir);
    } catch {
      // A missing sealed dir reads as "nothing pending" — a fresh
      // deploy with no sealed segments yet must not error.
      return [];
    }
    return names
      .filter(
        (n) =>
          n.endsWith(".jsonl") &&
          !n.endsWith(".jsonl" + ".tmp") &&
          !n.endsWith(ARCHIVE_UPLOADED_SUFFIX)
      )
      .sort();
  }

  /**
   * Deterministic object key for a segment file name:
   * `<prefix><yyyymmdd>/events-<minSeq>-<maxSeq>.jsonl`. Names that do
   * not parse as sealed segments land under `<prefix>misc/` instead —
   * they are still uploaded, never silently skipped.
   */
  segmentObjectKey(fileName: string): string {
    const parsed = parseSealedSegmentName(fileName);
    if (parsed !== undefined) {
      return `${this.keyPrefix}${parsed.date}/events-${parsed.seqMin}-${parsed.seqMax}.jsonl`;
    }
    return `${this.keyPrefix}misc/${fileName}`;
  }

  /** Intended keys from dry-run scans, in scan order. */
  getDryRunKeys(): string[] {
    return [...this.dryRunKeys];
  }

  get stats(): ArchiveS3Stats {
    return {
      uploaded: this.uploaded,
      uploadFailures: this.uploadFailures,
      pending: this.pendingSegments().length,
    };
  }

  /**
   * Upload one sealed segment. Throws `ArchiveS3Error` on any failure
   * (missing secret, transport error, non-2xx status). Idempotent: the
   * object key is deterministic, so a retry of the same segment is a
   * PUT to the same key — no duplicate objects.
   */
  async uploadSegment(fileName: string): Promise<ArchiveUploadResult> {
    const key = this.segmentObjectKey(fileName);
    if (this.cfg.dryRun === true) {
      this.dryRunKeys.push(key);
      return { segment: fileName, key, ok: true, dryRun: true };
    }
    const localPath = join(this.cfg.sealedDir, fileName);
    let body: Buffer;
    try {
      body = readFileSync(localPath);
    } catch (err) {
      throw new ArchiveS3Error(fileName, `cannot read sealed segment: ${(err as Error).message}`);
    }
    const secret = this.secretResolver(this.cfg.secretRef);
    if (secret === undefined || secret === "") {
      throw new ArchiveS3Error(
        fileName,
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
      throw new ArchiveS3Error(fileName, `PUT ${this.cfg.endpoint}/${this.cfg.bucket}/${key} -> HTTP ${status}`);
    }
    this.markUploaded(localPath);
    this.uploaded += 1;
    return { segment: fileName, key, ok: true };
  }

  /**
   * Scan the sealed directory and upload every pending segment.
   * Never throws: each segment's failure is counted in
   * `uploadFailures` and returned in its result — the next scan
   * retries it.
   */
  async scanAndUpload(): Promise<ArchiveUploadResult[]> {
    const results: ArchiveUploadResult[] = [];
    for (const fileName of this.pendingSegments()) {
      try {
        results.push(await this.uploadSegment(fileName));
      } catch (err) {
        this.uploadFailures += 1;
        results.push({
          segment: fileName,
          key: this.segmentObjectKey(fileName),
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
        reject(new ArchiveS3Error(basename(key), `PUT transport failed: ${message}`));
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
   * Mark a segment as uploaded: keep the local bytes under
   * `<name>.jsonl.uploaded` (the default), or delete them when
   * `deleteLocalAfterUpload` is set. Failures are best-effort and
   * never thrown — the marker is bookkeeping, not the upload.
   */
  private markUploaded(localPath: string): void {
    try {
      if (this.cfg.deleteLocalAfterUpload === true) {
        rmSync(localPath, { force: true });
      } else {
        renameSync(localPath, `${localPath}${ARCHIVE_UPLOADED_SUFFIX}`);
      }
    } catch {
      /* best effort: the segment will be re-uploaded (idempotent key) */
    }
  }
}
