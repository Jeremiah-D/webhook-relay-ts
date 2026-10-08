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

/** One HMAC key in a rotation set. */
export interface SigningKey {
  /** Stable identifier, surfaced in audit events and the `x-key-id` header hint. */
  id: string;
  /** The HMAC secret itself. */
  secret: string;
  /** The key used to sign new webhooks. When unset, the first key is primary. */
  primary?: boolean;
  /**
   * Millisecond epoch at which this key was rotated out. A retired key
   * still verifies inside the grace window; outside it, its signatures are
   * rejected. Undefined means the key is still in service.
   */
  retiredAtMs?: number;
}

/** Options for {@link RotatingHmacVerifier}. */
export interface RotationConfig {
  /** The key set: at least one key, ids unique, secrets non-empty. */
  keys: SigningKey[];
  /**
   * Grace period in ms during which a retired key still verifies.
   * Default: 86_400_000 (24h).
   */
  graceMs?: number;
  /** Clock source for retirement checks; defaults to Date.now. Injectable for tests. */
  nowMs?: () => number;
}

/** Options accepted by {@link RotatingHmacVerifier.verifyDetailed}. */
export interface VerifyDetailOptions extends VerifyOptions {
  /**
   * Hint naming the signing key (carried by the `x-key-id` header). When
   * set, only that key is tried — no fallback to other keys.
   */
  keyId?: string;
}

/** Rich result of {@link RotatingHmacVerifier.verifyDetailed}. Never throws. */
export interface VerifyDetail {
  ok: boolean;
  /** Id of the key whose signature matched; undefined when `ok` is false. */
  keyId?: string;
}

/** Default grace period for retired keys: 24h. */
export const DEFAULT_KEY_GRACE_MS = 86_400_000;

/**
 * HMAC-SHA256 verifier with key rotation: several keys coexist, one is the
 * primary for new signatures, and retired keys stay verifiable inside a
 * grace window. Verification tries the primary key first, then the other
 * still-active keys — unless the caller names a key (via the `x-key-id`
 * header hint), in which case only that key is tried.
 *
 * `verify` keeps the plain {@link Verifier} contract (boolean); use
 * {@link verifyDetailed} to learn which key id verified, for audit trails.
 * Never throws from verification paths.
 */
export class RotatingHmacVerifier implements Verifier {
  readonly name = "hmac-sha256-rotating";

  private readonly keys: { id: string; verifier: HmacSha256Verifier; retiredAtMs?: number }[];
  private readonly primaryId: string;
  private readonly graceMs: number;
  private readonly nowMs: () => number;

  constructor(config: RotationConfig) {
    const keys = config?.keys;
    if (!Array.isArray(keys) || keys.length === 0) {
      throw new Error("RotatingHmacVerifier: `keys` must be a non-empty array");
    }
    const seen = new Set<string>();
    let primaries = 0;
    this.keys = keys.map((k, i) => {
      if (!k || typeof k.id !== "string" || k.id === "") {
        throw new Error(`RotatingHmacVerifier: key[${i}] needs a non-empty id`);
      }
      if (typeof k.secret !== "string" || k.secret === "") {
        throw new Error(`RotatingHmacVerifier: key[${i}] (${k.id}) needs a non-empty secret`);
      }
      if (seen.has(k.id)) {
        throw new Error(`RotatingHmacVerifier: duplicate key id "${k.id}"`);
      }
      seen.add(k.id);
      if (k.retiredAtMs !== undefined && (!Number.isFinite(k.retiredAtMs) || k.retiredAtMs < 0)) {
        throw new Error(`RotatingHmacVerifier: key "${k.id}" has an invalid retiredAtMs`);
      }
      if (k.primary === true) primaries++;
      return { id: k.id, verifier: new HmacSha256Verifier(k.secret), retiredAtMs: k.retiredAtMs };
    });
    if (primaries > 1) {
      throw new Error("RotatingHmacVerifier: at most one key may be primary");
    }
    const primary = keys.find((k) => k.primary === true) ?? keys[0];
    this.primaryId = primary.id;

    const graceMs = config.graceMs ?? DEFAULT_KEY_GRACE_MS;
    if (!Number.isFinite(graceMs) || graceMs < 0) {
      throw new Error("RotatingHmacVerifier: `graceMs` must be a non-negative number");
    }
    this.graceMs = graceMs;
    this.nowMs = config.nowMs ?? Date.now;
  }

  /** Whether the key is still in service or retired within the grace window. */
  private isActive(key: { retiredAtMs?: number }): boolean {
    if (key.retiredAtMs === undefined) return true;
    return this.nowMs() - key.retiredAtMs <= this.graceMs;
  }

  /** Try order: primary first, then the remaining keys in config order. */
  private tryOrder(): { id: string; verifier: HmacSha256Verifier; retiredAtMs?: number }[] {
    const primary = this.keys.find((k) => k.id === this.primaryId);
    return [primary!, ...this.keys.filter((k) => k.id !== this.primaryId)];
  }

  verifyDetailed(rawBody: Buffer, header: string, opts: VerifyDetailOptions = {}): VerifyDetail {
    try {
      const hint = typeof opts.keyId === "string" && opts.keyId.trim() !== "" ? opts.keyId : undefined;
      if (hint !== undefined) {
        const key = this.keys.find((k) => k.id === hint);
        if (!key || !this.isActive(key)) return { ok: false };
        return key.verifier.verify(rawBody, header, opts) ? { ok: true, keyId: key.id } : { ok: false };
      }
      for (const key of this.tryOrder()) {
        if (!this.isActive(key)) continue;
        if (key.verifier.verify(rawBody, header, opts)) {
          return { ok: true, keyId: key.id };
        }
      }
      return { ok: false };
    } catch {
      return { ok: false };
    }
  }

  verify(rawBody: Buffer, header: string, opts: VerifyOptions = {}): boolean {
    return this.verifyDetailed(rawBody, header, opts).ok;
  }
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

/**
 * One per-endpoint verifier rule (WR-29): inbound requests whose path
 * matches `pattern` are verified with `verifier` instead of the server's
 * global verifier. Patterns are exact (`/hooks/stripe`) or prefix
 * (`/hooks/*`, which also matches `/hooks` itself); the first matching
 * rule in config order wins. One relay can therefore front several
 * upstreams that sign differently — e.g. Ed25519 for a Solana program's
 * callbacks and HMAC-SHA256 for a legacy PSP — without weakening any of
 * them, and unmatched paths fall back to the global verifier.
 */
export interface EndpointVerifierRule {
  /** Request path pattern: exact (`/hooks/stripe`) or prefix (`/hooks/*`). */
  pattern: string;
  /** The verifier trusted for this endpoint. */
  verifier: Verifier;
}

/**
 * Validate endpoint verifier rules at startup. Throws RangeError on a
 * non-array, a pattern that is not a `/`-rooted path, or a verifier
 * without a usable name/verify — fail fast, never mid-request.
 */
export function assertValidEndpointVerifierRules(rules: EndpointVerifierRule[] | undefined): void {
  if (rules === undefined) return;
  if (!Array.isArray(rules)) {
    throw new RangeError("endpointVerifiers: expected an array of { pattern, verifier } rules");
  }
  rules.forEach((rule, i) => {
    const where = `endpointVerifiers[${i}]`;
    if (!rule || typeof rule.pattern !== "string" || rule.pattern === "" || !rule.pattern.startsWith("/")) {
      throw new RangeError(
        `${where}: pattern must be a path starting with "/" (exact) or ending with "/*" (prefix)`
      );
    }
    const v = rule.verifier;
    if (!v || typeof v.name !== "string" || v.name === "" || typeof v.verify !== "function") {
      throw new RangeError(`${where}: verifier needs a non-empty name and a verify method`);
    }
  });
}

/**
 * Select the verifier for an inbound request path: the first matching
 * rule's verifier, or `undefined` when nothing matches (the caller falls
 * back to the global verifier). Never throws.
 */
export function selectEndpointVerifier(
  pathname: string,
  rules: EndpointVerifierRule[] | undefined
): Verifier | undefined {
  if (rules === undefined) return undefined;
  for (const rule of rules) {
    if (rule.pattern.endsWith("/*")) {
      const prefix = rule.pattern.slice(0, -2);
      if (pathname === prefix || pathname.startsWith(prefix + "/")) {
        return rule.verifier;
      }
    } else if (pathname === rule.pattern) {
      return rule.verifier;
    }
  }
  return undefined;
}
