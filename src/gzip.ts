import { createGunzip, gzipSync } from "node:zlib";

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

/** Thrown by `gunzipCapped` when the body is not valid gzip data. */
export class DecompressionFailedError extends Error {
  constructor(cause: unknown) {
    super(`gzip decompression failed: ${cause instanceof Error ? cause.message : String(cause)}`);
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
