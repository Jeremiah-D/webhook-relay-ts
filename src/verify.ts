import {
  createHmac,
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  timingSafeEqual,
  verify as cryptoVerify,
} from "node:crypto";

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
 * A signature verifier: one named scheme that decides whether a raw payload
 * is authentic. Implementations must never throw from `verify` — unparsable
 * headers, wrong keys, and crypto errors all mean `false`.
 */
export interface Verifier {
  /** Unique scheme name, e.g. `"hmac-sha256"` or `"ed25519"`. */
  readonly name: string;
  /** Return true when `header` authenticates `rawBody`. Never throws. */
  verify(rawBody: Buffer, header: string, opts?: VerifyOptions): boolean;
}

/** Default verifier: HMAC-SHA256 in the `sha256=` / timestamped formats. */
export class HmacSha256Verifier implements Verifier {
  readonly name = "hmac-sha256";

  private readonly secret: string;

  constructor(secret: string) {
    this.secret = secret;
  }

  verify(rawBody: Buffer, header: string, opts: VerifyOptions = {}): boolean {
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

    const expected = hmacSha256(this.secret, signed);
    if (expected.length !== parsed.signature.length) {
      return false;
    }
    return timingSafeEqual(expected, parsed.signature);
  }
}

/**
 * Asymmetric verifier slot: Ed25519 over the raw body.
 * Header format: `ed25519=<hex>`, where the signature covers `rawBody`
 * exactly. Construct with a PEM-encoded public key; the holder of the
 * matching private key signs with {@link signEd25519}.
 */
export class Ed25519Verifier implements Verifier {
  readonly name = "ed25519";

  private readonly publicKey: ReturnType<typeof createPublicKey>;

  constructor(publicKeyPem: string) {
    this.publicKey = createPublicKey(publicKeyPem);
  }

  verify(rawBody: Buffer, header: string): boolean {
    try {
      if (!header.startsWith("ed25519=")) {
        return false;
      }
      const hex = header.slice("ed25519=".length).trim();
      if (!HEX_RE.test(hex) || hex.length === 0 || hex.length % 2 !== 0) {
        return false;
      }
      return cryptoVerify(null, rawBody, this.publicKey, Buffer.from(hex, "hex"));
    } catch {
      return false;
    }
  }
}

/** Build an `ed25519=<hex>` header with a PEM-encoded Ed25519 private key. */
export function signEd25519(rawBody: Buffer, privateKeyPem: string): string {
  const sig = cryptoSign(null, rawBody, createPrivateKey(privateKeyPem));
  return `ed25519=${sig.toString("hex")}`;
}

const verifierRegistry = new Map<string, Verifier>();

/**
 * Register a named verifier so it can be selected by scheme name.
 * Overwrites any verifier already registered under the same name.
 */
export function registerVerifier(v: Verifier): void {
  if (!v || typeof v.name !== "string" || v.name === "" || typeof v.verify !== "function") {
    throw new Error("registerVerifier: verifier needs a non-empty name and a verify method");
  }
  verifierRegistry.set(v.name, v);
}

export function getVerifier(name: string): Verifier | undefined {
  return verifierRegistry.get(name);
}

export function verifierNames(): string[] {
  return [...verifierRegistry.keys()];
}

/**
 * Verify with the registered verifier `name`. Unknown names and verifier
 * errors mean `false` (never throws).
 */
export function verifyWith(
  rawBody: Buffer,
  header: string,
  name: string,
  opts: VerifyOptions = {}
): boolean {
  const v = verifierRegistry.get(name);
  if (!v) {
    return false;
  }
  try {
    return v.verify(rawBody, header, opts);
  } catch {
    return false;
  }
}

/**
 * Verify a webhook payload against the given signature header using
 * constant-time comparison. Returns true on success, false otherwise
 * (never throws on invalid headers or mismatches).
 *
 * This is the HMAC-SHA256 default; for other schemes use a {@link Verifier}
 * (e.g. {@link Ed25519Verifier}) or resolve one from the registry with
 * {@link verifyWith}.
 */
export function verifySignature(
  rawBody: Buffer,
  header: string,
  secret: string,
  opts: VerifyOptions = {}
): boolean {
  return new HmacSha256Verifier(secret).verify(rawBody, header, opts);
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
