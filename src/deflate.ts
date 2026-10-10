import {
  createDeflateRaw,
  createInflateRaw,
  constants as zlibConstants,
} from "node:zlib";

/**
 * WebSocket permessage-deflate (RFC 7692) for the WebSocket downstream
 * path (WR-46, see `src/websocket.ts`). Zero new dependencies
 * (`node:zlib` only).
 *
 * Negotiation model (deliberately strict, documented in `websocket.ts`):
 * the relay *offers* `permessage-deflate` with both no-context-takeover
 * parameters required:
 *
 *   Sec-WebSocket-Extensions: permessage-deflate;
 *     client_no_context_takeover; server_no_context_takeover
 *
 * Requiring `server_no_context_takeover` keeps decompression to one
 * independent inflate per message — no persistent inflater state rides
 * pooled connections, so a poisoned or half-read stream can never leak
 * into the next delivery. If the downstream answers `permessage-deflate`
 * without both parameters, the handshake fails (plain `Error` →
 * retryable) instead of silently mis-negotiating: per RFC 7692 §7.1.2.2
 * a server must not select the extension while rejecting the client's
 * required parameters.
 *
 * Wire form (RFC 7692 §7.2.1): compress with raw DEFLATE ending in a
 * `Z_SYNC_FLUSH`, then strip the trailing empty stored block
 * (`00 00 ff ff`); set RSV1 on the frame. Decompression appends the
 * trailer back and inflates. Context is never reused across messages,
 * so every message compresses and decompresses independently.
 *
 * Compression is opportunistic: payloads below `thresholdBytes` go out
 * untouched, and a payload whose compressed form is not smaller than the
 * original also goes out untouched — deflate must never expand the wire.
 */

/** The exact offer the relay sends on the upgrade request. */
export const PERMESSAGE_DEFLATE_OFFER =
  "permessage-deflate; client_no_context_takeover; server_no_context_takeover";

/** The 4 trailer octets stripped after compression, re-appended before inflation. */
const DEFLATE_TRAILER = Buffer.from([0x00, 0x00, 0xff, 0xff]);

/** Default payload size (bytes) at which permessage-deflate kicks in. */
export const DEFAULT_DEFLATE_THRESHOLD_BYTES = 1024;

/** Tuning for permessage-deflate. Presence of the option object (or `true`) opts in. */
export interface PerMessageDeflateOptions {
  /**
   * Payloads smaller than this are sent as-is. Default: 1024. Must be a
   * positive integer.
   */
  thresholdBytes?: number;
}

/** Validated deflate options, or `undefined` when the extension is off. */
export interface ResolvedPerMessageDeflate {
  thresholdBytes: number;
}

/**
 * Validate the `permessageDeflate` pool option once, at startup.
 * `true` enables with defaults; `false`/`undefined` disables.
 * Throws `RangeError` on bad values.
 */
export function resolvePerMessageDeflate(
  opt: boolean | PerMessageDeflateOptions | undefined
): ResolvedPerMessageDeflate | undefined {
  if (opt === undefined || opt === false) return undefined;
  if (opt === true) return { thresholdBytes: DEFAULT_DEFLATE_THRESHOLD_BYTES };
  if (opt === null || typeof opt !== "object" || Array.isArray(opt)) {
    throw new RangeError("permessageDeflate must be a boolean or an options object");
  }
  // Note: `??` is not used here on purpose — an explicit null must fail
  // validation like any other non-integer, matching compressOutbound.
  const thresholdBytes =
    opt.thresholdBytes === undefined ? DEFAULT_DEFLATE_THRESHOLD_BYTES : opt.thresholdBytes;
  if (!Number.isInteger(thresholdBytes) || thresholdBytes <= 0) {
    throw new RangeError(
      `permessageDeflate.thresholdBytes must be a positive integer, got ${JSON.stringify(opt.thresholdBytes)}`
    );
  }
  return { thresholdBytes };
}

/** Parameters the relay honors from the server's extension response. */
export interface NegotiatedDeflate {
  /**
   * LZ77 window bits for *our* compressor (from the server's
   * `client_max_window_bits`, default 15). `server_max_window_bits` is
   * accepted but ignored: a stream produced with a smaller window always
   * inflates under a 15-bit window.
   */
  windowBits: number;
}

/**
 * Parse the server's `Sec-WebSocket-Extensions` response header after we
 * offered {@link PERMESSAGE_DEFLATE_OFFER}.
 *
 * Returns `null` when the server did not select permessage-deflate (the
 * connection then works uncompressed). Returns the negotiated parameters
 * when it did. Throws when the server selected permessage-deflate but
 * violated the negotiation: missing either required no-context-takeover
 * parameter, an out-of-range `client_max_window_bits`, or an unknown
 * parameter — the handshake must fail rather than run on parameters we
 * cannot honor.
 */
export function negotiatePerMessageDeflate(
  responseHeader: string | undefined
): NegotiatedDeflate | null {
  if (responseHeader === undefined || responseHeader.trim() === "") return null;
  // Split extensions on commas; parameter values here are simple tokens
  // or quoted strings without commas, so a plain split is sound.
  for (const ext of responseHeader.split(",")) {
    const tokens = ext.split(";").map((t) => t.trim());
    if (tokens[0].toLowerCase() !== "permessage-deflate") continue;
    let clientNoTakeover = false;
    let serverNoTakeover = false;
    let windowBits = 15;
    for (const token of tokens.slice(1)) {
      const eq = token.indexOf("=");
      const name = (eq < 0 ? token : token.slice(0, eq)).trim().toLowerCase();
      const rawValue = eq < 0 ? "" : token.slice(eq + 1).trim();
      // Strip one layer of DQUOTE, per RFC 6455 quoted-string values.
      const value =
        rawValue.length >= 2 && rawValue.startsWith('"') && rawValue.endsWith('"')
          ? rawValue.slice(1, -1)
          : rawValue;
      if (name === "client_no_context_takeover") {
        clientNoTakeover = true;
      } else if (name === "server_no_context_takeover") {
        serverNoTakeover = true;
      } else if (name === "client_max_window_bits") {
        const bits = Number(value);
        if (!Number.isInteger(bits) || bits < 8 || bits > 15) {
          throw new Error(
            `websocket: bad permessage-deflate client_max_window_bits ${JSON.stringify(value)}`
          );
        }
        windowBits = bits;
      } else if (name === "server_max_window_bits") {
        // Accepted, ignored: safe for inflation (see NegotiatedDeflate).
      } else {
        throw new Error(`websocket: unsupported permessage-deflate parameter ${JSON.stringify(name)}`);
      }
    }
    if (!clientNoTakeover || !serverNoTakeover) {
      throw new Error(
        "websocket: permessage-deflate response lacks a required no_context_takeover parameter"
      );
    }
    return { windowBits };
  }
  return null;
}

/**
 * Compress one message per RFC 7692 §7.2.1: fresh raw-deflate context,
 * `Z_SYNC_FLUSH` terminator, trailing `00 00 ff ff` stripped. Never
 * reuses context across messages (we offered `client_no_context_takeover`
 * and must honor it). Resolves to the exact wire bytes for an RSV1 frame.
 */
export function compressMessage(payload: Buffer, windowBits = 15): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    if (!Number.isInteger(windowBits) || windowBits < 8 || windowBits > 15) {
      reject(new Error(`websocket: windowBits out of range: ${windowBits}`));
      return;
    }
    const deflate = createDeflateRaw({ windowBits });
    const chunks: Buffer[] = [];
    deflate.on("error", (err) => {
      deflate.destroy();
      reject(err);
    });
    // The write callback fires once the payload reached the native
    // layer; only then is the flush guaranteed to cover all of it.
    deflate.write(payload, () => {
      deflate.flush(zlibConstants.Z_SYNC_FLUSH, () => {
        let chunk: Buffer | null;
        // Drain synchronously: at flush completion every output byte is
        // already in the readable buffer, so read() cannot miss any.
        while ((chunk = deflate.read()) !== null) chunks.push(chunk);
        deflate.destroy();
        const full = Buffer.concat(chunks);
        // The sync flush always ends the stream with the empty stored
        // block 00 00 ff ff; strip it per RFC 7692 §7.2.1.
        resolve(full.subarray(0, full.length - DEFLATE_TRAILER.length));
      });
    });
  });
}

/**
 * Decompress one RSV1 message: append the `00 00 ff ff` trailer stripped
 * by the compressor, then inflate with a fresh context (the server
 * negotiated `server_no_context_takeover`, so messages are independent).
 * Rejects on corrupt input — a tampered compressed frame fails the
 * delivery instead of producing garbage bytes.
 */
export function decompressMessage(payload: Buffer): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const inflate = createInflateRaw();
    const chunks: Buffer[] = [];
    inflate.on("error", (err) => {
      inflate.destroy();
      reject(new Error(`websocket: permessage-deflate decompression failed: ${err.message}`));
    });
    // write() (not end()): ending the stream would Z_FINISH the inflate
    // and reject the unterminated sync-flushed stream with Z_BUF_ERROR.
    inflate.write(payload, () => {
      inflate.write(DEFLATE_TRAILER, () => {
        inflate.flush(zlibConstants.Z_SYNC_FLUSH, () => {
          let chunk: Buffer | null;
          while ((chunk = inflate.read()) !== null) chunks.push(chunk);
          inflate.destroy();
          resolve(Buffer.concat(chunks));
        });
      });
    });
  });
}

/**
 * Opportunistic compression for one outbound message: compress when the
 * payload reaches `thresholdBytes` *and* the compressed form is strictly
 * smaller — otherwise return the original bytes. Never expands the wire.
 */
export async function maybeCompressMessage(
  payload: Buffer,
  thresholdBytes: number,
  windowBits = 15
): Promise<{ bytes: Buffer; compressed: boolean }> {
  if (payload.length < thresholdBytes) return { bytes: payload, compressed: false };
  const compressed = await compressMessage(payload, windowBits);
  if (compressed.length >= payload.length) return { bytes: payload, compressed: false };
  return { bytes: compressed, compressed: true };
}
