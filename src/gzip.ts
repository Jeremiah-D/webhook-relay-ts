import { createGunzip, gzipSync } from "node:zlib";
import { renderCompressedBytesSavedBlock } from "./metrics.ts";

/**
 * Outbound/inbound gzip compression (WR-40), zero new dependencies
 * (`node:zlib` only).
 *
 * Outbound: per-endpoint opt-in — when the payload reaches the
 * threshold, the sender compresses it, stamps `Content-Encoding: gzip`,
 * and sets `Content-Length` to the compressed size. The relay signature
 * (`x-relay-signature`) covers the compressed wire bytes, exactly what
 * the downstream receives.
 *
 * Inbound: a webhook posted with `Content-Encoding: gzip` is
 * transparently decompressed *after* signature verification (the
 * signature covers the raw wire bytes the sender signed) and *before*
 * version routing / dedup / enqueue, so everything downstream sees the
 * canonical plain payload. Decompression is streaming and capped at the
 * inbound body budget — a gzip bomb can never blow past `maxBodyBytes`
 * in memory.
 */

/** Default payload size (bytes) at which outbound compression kicks in. */
export const DEFAULT_COMPRESS_THRESHOLD_BYTES = 1024;

/** Per-endpoint outbound compression tuning. Presence of the endpoint key opts it in. */
export interface CompressOutboundOptions {
  /**
   * Payloads smaller than this are sent as-is. Default: 1024. Must be a
   * positive integer.
   */
  thresholdBytes?: number;
}

/** Validate a `compressOutbound` record. Throws `RangeError` on bad values. */
export function assertValidCompressOutboundConfig(
  config: Record<string, CompressOutboundOptions>
): void {
  if (config === null || typeof config !== "object" || Array.isArray(config)) {
    throw new RangeError("compressOutbound must be a record of targetUrl -> options");
  }
  for (const [endpoint, opts] of Object.entries(config)) {
    const where = `compressOutbound[${JSON.stringify(endpoint)}]`;
    if (opts === null || typeof opts !== "object" || Array.isArray(opts)) {
      throw new RangeError(`${where} must be an object`);
    }
    if (
      opts.thresholdBytes !== undefined &&
      (!Number.isInteger(opts.thresholdBytes) || opts.thresholdBytes <= 0)
    ) {
      throw new RangeError(
        `${where}.thresholdBytes must be a positive integer, got ${JSON.stringify(opts.thresholdBytes)}`
      );
    }
  }
}

/**
 * Compress `payload` for one endpoint when opted in and worthwhile.
 * Returns the wire bytes plus the `content-encoding` value to stamp
 * (absent when the payload goes out as-is). Never compresses when the
 * compressed form is not smaller — tiny or incompressible payloads
 * would only grow.
 */
export function maybeCompressOutbound(
  payload: Buffer,
  opts?: CompressOutboundOptions
): { body: Buffer; contentEncoding?: "gzip" } {
  if (opts === undefined) return { body: payload };
  const threshold = opts.thresholdBytes ?? DEFAULT_COMPRESS_THRESHOLD_BYTES;
  if (payload.length < threshold) return { body: payload };
  const compressed = gzipSync(payload);
  if (compressed.length >= payload.length) return { body: payload };
  return { body: compressed, contentEncoding: "gzip" };
}

/** True when a `content-encoding` header value (string or array) names gzip. */
export function isGzipContentEncoding(
  header: string | string[] | undefined
): boolean {
  if (header === undefined) return false;
  const values = Array.isArray(header) ? header : [header];
  return values.some((v) =>
    v
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .includes("gzip")
  );
}

/** Thrown by `gunzipCapped` when the decompressed body exceeds the budget. */
export class DecompressionTooLargeError extends Error {
  readonly maxBytes: number;
  constructor(maxBytes: number) {
    super(`decompressed body exceeds ${maxBytes} bytes`);
    this.name = "DecompressionTooLargeError";
    this.maxBytes = maxBytes;
  }
}

/** Thrown by the capped decoders when the body is not valid compressed data. */
export class DecompressionFailedError extends Error {
  constructor(cause: unknown, coding = "gzip") {
    super(`${coding} decompression failed: ${cause instanceof Error ? cause.message : String(cause)}`);
    this.name = "DecompressionFailedError";
  }
}

/**
 * Streaming gunzip with a hard cap on decompressed bytes: the output
 * never exceeds `maxBytes` in memory, so a decompression bomb is cut off
 * instead of blowing up the process. Rejects with
 * `DecompressionTooLargeError` past the cap, `DecompressionFailedError`
 * on corrupt input.
 */
export function gunzipCapped(body: Buffer, maxBytes: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const gunzip = createGunzip();
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    const done = (err?: Error, result?: Buffer): void => {
      if (settled) return;
      settled = true;
      gunzip.destroy();
      if (err !== undefined) reject(err);
      else resolve(result ?? Buffer.alloc(0));
    };
    gunzip.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        done(new DecompressionTooLargeError(maxBytes));
        return;
      }
      chunks.push(chunk);
    });
    gunzip.on("end", () => done(undefined, Buffer.concat(chunks)));
    gunzip.on("error", (err) => done(new DecompressionFailedError(err)));
    gunzip.end(body);
  });
}

/* ------------------------------------------------------------------ *
 * WR-75: guarded outbound gzip compression (`compressThreshold`).
 *
 * Design intent — how this differs from WR-40 (`compressOutbound`):
 *
 * - WR-40 is threshold-only, fire-and-forget compression: when the
 *   payload reaches `thresholdBytes` it is gzipped, whatever the content
 *   type, and a downstream that answers 415 is the operator's problem
 *   (the 415 classifies `non_retryable` and the item dead-letters on the
 *   first attempt). Operators who already rely on that behavior keep it
 *   byte-identical.
 * - WR-75 is *guarded* compression: the payload must additionally pass a
 *   content-type whitelist (default `application/json` — batch envelopes
 *   and relay payloads are JSON by contract), and when a guarded
 *   delivery is answered 415 the sender resends it once as plaintext
 *   *inside the same delivery attempt* (no retry budget consumed, no
 *   circuit event). A 415 on the plaintext resend — or any other
 *   failure — follows the normal classify → retry / dead-letter path.
 *
 * When both records configure the same endpoint, the guarded path wins:
 * it is the safer superset, and running two compression decisions per
 * delivery would be exactly the "two switches doing the same thing"
 * anti-pattern. The fallback resend always goes out fully plaintext
 * (both compressions skipped).
 *
 * Transport scope: the guarded path engages only on the HTTP/1.1 and
 * HTTP/2 delivery paths. WebSocket deliveries keep their own
 * compression story — RFC 7692 permessage-deflate (`src/deflate.ts`) —
 * and never pass through here, so the two mechanisms cannot disagree
 * about who compressed what.
 * ------------------------------------------------------------------ */

/** Default content types eligible for guarded outbound compression. */
export const DEFAULT_GUARDED_COMPRESS_CONTENT_TYPES = ["application/json"];

/**
 * Per-endpoint guarded outbound compression tuning (WR-75). Presence of
 * the endpoint key opts it in (exact `targetUrl` match, the same
 * convention as `compressOutbound`).
 */
export interface GuardedCompressOptions {
  /**
   * Payloads smaller than this are sent as-is. Default: 1024. Must be a
   * positive integer.
   */
  thresholdBytes?: number;
  /**
   * Content types eligible for compression, matched on the media type
   * (the part before `;`, case-insensitive). Default:
   * `["application/json"]`. Must be a non-empty array of non-empty
   * strings — an empty whitelist would silently disable compression, so
   * it is rejected at startup instead.
   */
  contentTypeWhitelist?: string[];
}

/** Validate a `compressThreshold` record. Throws `RangeError` on bad values. */
export function assertValidGuardedCompressConfig(
  config: Record<string, GuardedCompressOptions>
): void {
  if (config === null || typeof config !== "object" || Array.isArray(config)) {
    throw new RangeError("compressThreshold must be a record of targetUrl -> options");
  }
  for (const [endpoint, opts] of Object.entries(config)) {
    const where = `compressThreshold[${JSON.stringify(endpoint)}]`;
    if (opts === null || typeof opts !== "object" || Array.isArray(opts)) {
      throw new RangeError(`${where} must be an object`);
    }
    if (
      opts.thresholdBytes !== undefined &&
      (!Number.isInteger(opts.thresholdBytes) || opts.thresholdBytes <= 0)
    ) {
      throw new RangeError(
        `${where}.thresholdBytes must be a positive integer, got ${JSON.stringify(opts.thresholdBytes)}`
      );
    }
    if (opts.contentTypeWhitelist !== undefined) {
      if (
        !Array.isArray(opts.contentTypeWhitelist) ||
        opts.contentTypeWhitelist.length === 0 ||
        opts.contentTypeWhitelist.some(
          (t) => typeof t !== "string" || t.trim().length === 0
        )
      ) {
        throw new RangeError(
          `${where}.contentTypeWhitelist must be a non-empty array of non-empty content-type strings`
        );
      }
    }
  }
}

/**
 * The effective outbound content type for the whitelist check: the
 * item's `content-type` header when present, else `application/json` —
 * relay payloads (events, batch envelopes) are JSON by contract, and an
 * absent header must not silently opt a JSON body out of compression.
 */
export function outboundContentType(
  headers: Record<string, string | string[] | undefined>
): string {
  const raw = headers["content-type"];
  const first = Array.isArray(raw) ? raw[0] : raw;
  return first ?? "application/json";
}

/** Normalize a content-type value to its bare media type for comparison. */
function mediaTypeOf(contentType: string): string {
  return contentType.split(";")[0]!.trim().toLowerCase();
}

/** Outcome of the guarded compression decision (WR-75). */
export interface GuardedCompressDecision {
  /** Wire bytes: the gzipped payload, or the original when not compressed. */
  body: Buffer;
  /** `"gzip"` when the payload was compressed (stamp `Content-Encoding`). */
  contentEncoding?: "gzip";
  /**
   * Payload bytes saved by compression (`payload.length - body.length`);
   * 0 when the payload went out as-is. Feeds
   * `relay_compressed_bytes_saved_total`.
   */
  bytesSaved: number;
}

/**
 * Guarded compression decision for one endpoint (WR-75): compress when
 * opted in, the content type passes the whitelist, the payload reaches
 * the threshold, and the compressed form is actually smaller. Never
 * compresses otherwise — the three guards are what separate this from
 * the WR-40 fire-and-forget path.
 */
export function guardedCompressOutbound(
  payload: Buffer,
  contentType: string | undefined,
  opts?: GuardedCompressOptions
): GuardedCompressDecision {
  if (opts === undefined) return { body: payload, bytesSaved: 0 };
  const whitelist = opts.contentTypeWhitelist ?? DEFAULT_GUARDED_COMPRESS_CONTENT_TYPES;
  if (!whitelist.some((t) => mediaTypeOf(t) === mediaTypeOf(contentType ?? "application/json"))) {
    return { body: payload, bytesSaved: 0 };
  }
  const threshold = opts.thresholdBytes ?? DEFAULT_COMPRESS_THRESHOLD_BYTES;
  if (payload.length < threshold) return { body: payload, bytesSaved: 0 };
  const compressed = gzipSync(payload);
  if (compressed.length >= payload.length) return { body: payload, bytesSaved: 0 };
  return { body: compressed, contentEncoding: "gzip", bytesSaved: payload.length - compressed.length };
}

/**
 * WR-75: cumulative per-endpoint byte savings from guarded outbound
 * compression. Owned by the relay server (like `CertExpiryMonitor`): the
 * default sender notes every guarded-compressed transmission, and the
 * server renders the counter into `GET /metrics`.
 *
 * Counting rule: savings are recorded per compressed transmission —
 * when a 415 triggers the plaintext fallback resend, the compressed
 * attempt's savings were real wire bytes not sent, and the plaintext
 * resend records nothing. The counter is monotonic per endpoint.
 */
export class OutboundCompressionTracker {  private readonly saved = new Map<string, number>();

  /** Record `bytesSaved` (> 0) for a guarded-compressed transmission to `endpoint`. */
  noteSaved(endpoint: string, bytesSaved: number): void {
    if (bytesSaved <= 0) return;
    this.saved.set(endpoint, (this.saved.get(endpoint) ?? 0) + bytesSaved);
  }

  /** Per-endpoint cumulative savings, in first-seen order. Empty until the first compressed delivery. */
  stats(): Array<{ endpoint: string; bytesSaved: number }> {
    return [...this.saved.entries()].map(([endpoint, bytesSaved]) => ({ endpoint, bytesSaved }));
  }

  /**
   * Prometheus exposition for `relay_compressed_bytes_saved_total`;
   * `""` until the first byte is saved, so an untouched relay's
   * exposition is byte-identical to before.
   */
  render(): string {
    const lines = renderCompressedBytesSavedBlock(this.stats());
    return lines.length === 0 ? "" : lines.join("\n") + "\n";
  }
}

/** Fired when a guarded-compressed delivery is answered 415 and resent as plaintext (WR-75). */
export interface GzipFallbackInfo {
  /** Delivery id. */
  id: string;
  /** End-to-end trace ID. */
  traceId?: string;
  /** Downstream endpoint (`targetUrl`). */
  endpoint: string;
  /** Payload bytes the compressed attempt saved before the fallback. */
  bytesSaved: number;
}
