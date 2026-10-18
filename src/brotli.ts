import { brotliCompressSync } from "node:zlib";
import { DEFAULT_COMPRESS_THRESHOLD_BYTES } from "./gzip.ts";

/**
 * Outbound brotli compression (WR-142), zero new dependencies
 * (`node:zlib` only).
 *
 * Outbound: per-endpoint opt-in — when the payload reaches the
 * threshold, the sender compresses it with brotli, stamps
 * `Content-Encoding: br`, and sets `Content-Length` to the compressed
 * size. The relay signature (`x-relay-signature`) covers the compressed
 * wire bytes, exactly what the downstream receives.
 *
 * Precedence (see `buildWireRequest` in `src/server.ts`): an endpoint
 * opted into `compressBrotli` uses the brotli path *instead of* both
 * gzip paths (WR-40 `compressOutbound`, WR-75 `compressThreshold`) —
 * compression is never stacked. WebSocket deliveries never pass through
 * here: they keep their RFC 7692 permessage-deflate story
 * (`src/deflate.ts`).
 *
 * Failure behavior is fire-and-forget like WR-40: no content-type
 * whitelist, no 415→plaintext fallback. An endpoint whose downstream
 * may answer 415 to compressed bodies should use the guarded
 * `compressThreshold` path instead. Byte savings feed the same
 * `OutboundCompressionTracker` (and the same
 * `relay_compressed_bytes_saved_total` exposition) as the gzip paths.
 *
 * Inbound: webhooks posted with `Content-Encoding: br` are
 * transparently decompressed on the intake path (WR-62,
 * `decodeResponseBody` in `src/response-encoding.ts`) — no inbound
 * *request* brotli decode is added here (that belongs to WR-62's
 * inbound-decode work).
 */

/** Per-endpoint outbound brotli compression tuning. Presence of the endpoint key opts it in. */
export interface BrotliCompressOptions {
  /**
   * Payloads smaller than this are sent as-is. Default: 1024. Must be a
   * positive integer.
   */
  thresholdBytes?: number;
}

/** Validate a `compressBrotli` record. Throws `RangeError` on bad values. */
export function assertValidBrotliCompressConfig(
  config: Record<string, BrotliCompressOptions>
): void {
  if (config === null || typeof config !== "object" || Array.isArray(config)) {
    throw new RangeError("compressBrotli must be a record of targetUrl -> options");
  }
  for (const [endpoint, opts] of Object.entries(config)) {
    const where = `compressBrotli[${JSON.stringify(endpoint)}]`;
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

/** Outcome of the outbound brotli compression decision (WR-142). */
export interface BrotliCompressDecision {
  /** Wire bytes: the brotli-compressed payload, or the original when not compressed. */
  body: Buffer;
  /** `"br"` when the payload was compressed (stamp `Content-Encoding`). */
  contentEncoding?: "br";
  /**
   * Payload bytes saved by compression (`payload.length - body.length`);
   * 0 when the payload went out as-is. Feeds
   * `relay_compressed_bytes_saved_total` (the same tracker as the gzip
   * paths).
   */
  bytesSaved: number;
}

/**
 * Compress `payload` with brotli for one opted-in endpoint, when
 * worthwhile. Returns the wire bytes plus the `content-encoding` value
 * to stamp (absent when the payload goes out as-is). Never compresses
 * when the brotli form is not smaller — tiny or incompressible payloads
 * would only grow.
 */
export function maybeCompressBrotliOutbound(
  payload: Buffer,
  opts?: BrotliCompressOptions
): BrotliCompressDecision {
  if (opts === undefined) return { body: payload, bytesSaved: 0 };
  const threshold = opts.thresholdBytes ?? DEFAULT_COMPRESS_THRESHOLD_BYTES;
  if (payload.length < threshold) return { body: payload, bytesSaved: 0 };
  const compressed = brotliCompressSync(payload);
  if (compressed.length >= payload.length) return { body: payload, bytesSaved: 0 };
  return { body: compressed, contentEncoding: "br", bytesSaved: payload.length - compressed.length };
}
