import { createHmac, timingSafeEqual } from "node:crypto";

export type Scheme = "sha256" | "timestamped";

export interface ParsedSignature {
  scheme: Scheme;
  signature: Buffer;
  timestamp?: number;
}

const HEX_RE = /^[0-9a-fA-F]+$/;

/**
 * Parse a signature header in one of the two supported formats:
 *   - `sha256=<hex>`                  (plain HMAC-SHA256 of the raw body)
 *   - `t=<unix_ts>,v1=<hex>`          (timestamped; signature covers `<ts>.<rawBody>`)
 */
export function parseSignatureHeader(header: string): ParsedSignature {
  if (!header || typeof header !== "string") {
    throw new Error("Missing signature header");
  }

  if (header.startsWith("sha256=")) {
    const hex = header.slice("sha256=".length).trim();
    if (!HEX_RE.test(hex) || hex.length === 0 || hex.length % 2 !== 0) {
      throw new Error("Invalid sha256 signature format");
    }
    return { scheme: "sha256", signature: Buffer.from(hex, "hex") };
  }

  const parts = header.split(",");
  if (parts.length === 2 && parts[0].startsWith("t=") && parts[1].startsWith("v1=")) {
    const ts = Number(parts[0].slice(2));
    const hex = parts[1].slice("v1=".length).trim();
    if (!Number.isInteger(ts) || ts <= 0) {
      throw new Error("Invalid timestamp in signature header");
    }
    if (!HEX_RE.test(hex) || hex.length === 0 || hex.length % 2 !== 0) {
      throw new Error("Invalid v1 signature format");
    }
    return { scheme: "timestamped", signature: Buffer.from(hex, "hex"), timestamp: ts };
  }

  throw new Error("Unsupported signature header format");
}

function hmacSha256(secret: string, data: Buffer): Buffer {
  return createHmac("sha256", secret).update(data).digest();
}

export interface VerifyOptions {
  /** Maximum age/lead of a timestamped signature in seconds. Default: 300. */
  toleranceSec?: number;
  /** Clock source for timestamp checks; defaults to Date.now. Injectable for tests. */
  nowMs?: () => number;
}

/**
 * Verify a webhook payload against the given signature header using
 * constant-time comparison. Returns true on success, false otherwise
 * (never throws on invalid headers or mismatches).
 */
export function verifySignature(
  rawBody: Buffer,
  header: string,
  secret: string,
  opts: VerifyOptions = {}
): boolean {
  let parsed: ParsedSignature;
  try {
    parsed = parseSignatureHeader(header);
  } catch {
    return false;
  }

  if (parsed.scheme === "timestamped") {
    const toleranceSec = opts.toleranceSec ?? 300;
    const nowSec = Math.floor((opts.nowMs ?? Date.now)() / 1000);
    const ts = parsed.timestamp as number;
    if (Math.abs(nowSec - ts) > toleranceSec) {
      return false;
    }
  }

  const signed =
    parsed.scheme === "timestamped"
      ? Buffer.concat([Buffer.from(`${parsed.timestamp}.`, "utf8"), rawBody])
      : rawBody;

  const expected = hmacSha256(secret, signed);
  if (expected.length !== parsed.signature.length) {
    return false;
  }
  return timingSafeEqual(expected, parsed.signature);
}

/** Helper to build a `sha256=<hex>` header (useful for tests/clients). */
export function signSha256(rawBody: Buffer, secret: string): string {
  return `sha256=${hmacSha256(secret, rawBody).toString("hex")}`;
}

/** Helper to build a `t=<ts>,v1=<hex>` header (useful for tests/clients). */
export function signTimestamped(
  rawBody: Buffer,
  secret: string,
  timestamp: number = Math.floor(Date.now() / 1000)
): string {
  const signed = Buffer.concat([Buffer.from(`${timestamp}.`, "utf8"), rawBody]);
  return `t=${timestamp},v1=${hmacSha256(secret, signed).toString("hex")}`;
}
