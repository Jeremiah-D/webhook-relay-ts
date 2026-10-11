import { createInflate, createBrotliDecompress } from "node:zlib";
import {
  gunzipCapped,
  DecompressionTooLargeError,
  DecompressionFailedError,
} from "./gzip.ts";

/**
 * Outbound response compression negotiation (WR-62), zero new
 * dependencies (`node:zlib` only).
 *
 * Some downstreams answer with compressed bodies when the client
 * advertises `Accept-Encoding`. The relay can opt in per endpoint: it
 * then sends `Accept-Encoding: gzip, deflate, br` and transparently
 * decodes the response *before* the WR-37 responseValidator (and the
 * audit summary) ever sees the body — a validator written against the
 * downstream's plain JSON keeps working whether the downstream
 * compressed or not.
 *
 * Safety rules:
 * - Every decode stage is hard-capped (`maxDecompressedBytes`, default
 *   64 KiB): a compression bomb is cut off in memory instead of blowing
 *   up the process, and surfaces as a retryable delivery failure.
 * - A downstream that ignores `Accept-Encoding` and answers plaintext
 *   (or an encoding we do not know) is passed through untouched — a
 *   delivery is never lost because of negotiation.
 * - A wire capture cut at the cap cannot be decoded (a truncated
 *   compressed stream is corrupt by definition): the raw bytes travel
 *   on with `truncated: true`, exactly like the uncompressed path.
 */

/**
 * The `Accept-Encoding` value advertised when an endpoint opts in
 * without overriding it. Order is preference order (most preferred
 * first), per RFC 9110 §12.5.3.
 */
export const DEFAULT_OUTBOUND_ACCEPT_ENCODING = "gzip, deflate, br";

/** Per-endpoint outbound response decompression tuning. Presence of the endpoint key opts it in. */
export interface ResponseCompressionOptions {
  /**
   * Override the advertised `Accept-Encoding` value. Default:
   * `"gzip, deflate, br"`. Must be a non-empty string.
   */
  acceptEncoding?: string;
  /**
   * Hard cap on decompressed response bytes per decode stage. Default:
   * 65536 (the sender's response capture cap — the same memory bound as
   * the uncompressed path). Must be a positive integer.
   */
  maxDecompressedBytes?: number;
}

/** Validate a `responseCompression` record. Throws `RangeError` on bad values. */
export function assertValidResponseCompressionConfig(
  config: Record<string, ResponseCompressionOptions>
): void {
  if (config === null || typeof config !== "object" || Array.isArray(config)) {
    throw new RangeError("responseCompression must be a record of targetUrl -> options");
  }
  for (const [endpoint, opts] of Object.entries(config)) {
    const where = `responseCompression[${JSON.stringify(endpoint)}]`;
    if (opts === null || typeof opts !== "object" || Array.isArray(opts)) {
      throw new RangeError(`${where} must be an object`);
    }
    if (
      opts.acceptEncoding !== undefined &&
      (typeof opts.acceptEncoding !== "string" || opts.acceptEncoding.trim() === "")
    ) {
      throw new RangeError(`${where}.acceptEncoding must be a non-empty string`);
    }
    if (
      opts.maxDecompressedBytes !== undefined &&
      (!Number.isInteger(opts.maxDecompressedBytes) || opts.maxDecompressedBytes <= 0)
    ) {
      throw new RangeError(
        `${where}.maxDecompressedBytes must be a positive integer, got ${JSON.stringify(
          opts.maxDecompressedBytes
        )}`
      );
    }
  }
}

/**
 * Streaming inflate (zlib wrapper) with a hard cap on decompressed
 * bytes — the `deflate` counterpart to `gunzipCapped`. Rejects with
 * `DecompressionTooLargeError` past the cap, `DecompressionFailedError`
 * on corrupt input.
 */
export function inflateCapped(body: Buffer, maxBytes: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const inflate = createInflate();
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    const done = (err?: Error, result?: Buffer): void => {
      if (settled) return;
      settled = true;
      inflate.destroy();
      if (err !== undefined) reject(err);
      else resolve(result ?? Buffer.alloc(0));
    };
    inflate.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        done(new DecompressionTooLargeError(maxBytes));
        return;
      }
      chunks.push(chunk);
    });
    inflate.on("end", () => done(undefined, Buffer.concat(chunks)));
    inflate.on("error", (err) => done(new DecompressionFailedError(err, "deflate")));
    inflate.end(body);
  });
}

/**
 * Streaming brotli decompression with a hard cap on decompressed bytes.
 * Rejects with `DecompressionTooLargeError` past the cap,
 * `DecompressionFailedError` on corrupt input.
 */
export function brotliDecompressCapped(body: Buffer, maxBytes: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const brotli = createBrotliDecompress();
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    const done = (err?: Error, result?: Buffer): void => {
      if (settled) return;
      settled = true;
      brotli.destroy();
      if (err !== undefined) reject(err);
      else resolve(result ?? Buffer.alloc(0));
    };
    brotli.on("data", (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        done(new DecompressionTooLargeError(maxBytes));
        return;
      }
      chunks.push(chunk);
    });
    brotli.on("end", () => done(undefined, Buffer.concat(chunks)));
    brotli.on("error", (err) => done(new DecompressionFailedError(err, "br")));
    brotli.end(body);
  });
}

/** The outcome of decoding a downstream response body. */
export interface DecodedResponseBody {
  /** The body the WR-37 validator (and audit) should see. */
  body: Buffer;
  /**
   * The downstream's `content-encoding` header value, when one was sent
   * (whether or not we could decode it).
   */
  contentEncoding?: string;
  /** True when at least one coding actually transformed the body. */
  decoded: boolean;
}

/**
 * Decode a downstream response body per its `content-encoding` header.
 * Codings are listed in application order (RFC 9110 §8.4), so they are
 * decoded in reverse; each stage is capped at `maxBytes`. `identity` is
 * a no-op. An unknown coding — or no header at all — passes the wire
 * bytes through untouched (`decoded: false`): negotiation must never
 * lose a delivery. Rejects with `DecompressionTooLargeError` /
 * `DecompressionFailedError` on corrupt or over-budget input (the sender
 * treats those as retryable delivery failures).
 */
export async function decodeResponseBody(
  wire: Buffer,
  contentEncoding: string | string[] | undefined,
  maxBytes: number
): Promise<DecodedResponseBody> {
  const rawValue = Array.isArray(contentEncoding)
    ? contentEncoding.join(", ")
    : contentEncoding;
  if (rawValue === undefined || rawValue.trim() === "") {
    return { body: wire, decoded: false };
  }
  const normalized = rawValue.trim();
  const codings = normalized
    .split(",")
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s.length > 0);
  let body = wire;
  let transformed = false;
  for (let i = codings.length - 1; i >= 0; i--) {
    const coding = codings[i];
    if (coding === "identity") continue;
    if (coding === "gzip" || coding === "x-gzip") {
      body = await gunzipCapped(body, maxBytes);
    } else if (coding === "deflate") {
      body = await inflateCapped(body, maxBytes);
    } else if (coding === "br") {
      body = await brotliDecompressCapped(body, maxBytes);
    } else {
      // Unknown coding: pass the wire bytes through untouched rather
      // than hand the validator undecodable garbage.
      return { body: wire, contentEncoding: normalized, decoded: false };
    }
    transformed = true;
  }
  return { body, contentEncoding: normalized, decoded: transformed };
}
