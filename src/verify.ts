import {
  constants as cryptoConstants,
  createHash,
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

/** RSA-PSS salt length in bytes (WR-110): fixed at 32 with SHA-256. */
export const RSA_PSS_SALT_LENGTH = 32;

const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;

/**
 * SHA-256 fingerprint (lowercase hex) of a public key's SPKI DER encoding —
 * the stable key identity used for audit trails. Never throws on a real
 * KeyObject.
 */
export function publicKeyFingerprint(publicKey: ReturnType<typeof createPublicKey>): string {
  const der = publicKey.export({ type: "spki", format: "der" });
  return createHash("sha256")
    .update(der as Buffer)
    .digest("hex");
}

/**
 * Asymmetric verifier slot: RSA-PSS over the raw body (WR-110).
 * Header format: `rsa-sha256=<base64>`, where the signature covers
 * `rawBody` exactly with SHA-256 and a 32-byte PSS salt. Construct with
 * a PEM-encoded RSA public key; the holder of the matching private key
 * signs with {@link signRsaPss}. The PSS salt is random per signature,
 * so two signatures over the same body differ — both verify.
 * Never throws from `verify`.
 */
export class RsaPssVerifier implements Verifier {
  readonly name = "rsa-pss";

  private readonly publicKey: ReturnType<typeof createPublicKey>;

  constructor(publicKeyPem: string) {
    if (typeof publicKeyPem !== "string" || publicKeyPem.trim() === "") {
      throw new Error("RsaPssVerifier: publicKeyPem must be a non-empty PEM string");
    }
    this.publicKey = createPublicKey(publicKeyPem);
  }

  /** SHA-256 hex fingerprint of the SPKI DER — the stable key identity for audit. */
  get fingerprint(): string {
    return publicKeyFingerprint(this.publicKey);
  }

  verify(rawBody: Buffer, header: string): boolean {
    try {
      if (typeof header !== "string" || !header.startsWith("rsa-sha256=")) {
        return false;
      }
      const b64 = header.slice("rsa-sha256=".length).trim();
      if (b64 === "" || b64.length % 4 !== 0 || !BASE64_RE.test(b64)) {
        return false;
      }
      const sig = Buffer.from(b64, "base64");
      if (sig.length === 0) {
        return false;
      }
      return cryptoVerify(
        "sha256",
        rawBody,
        {
          key: this.publicKey,
          padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
          saltLength: RSA_PSS_SALT_LENGTH,
        },
        sig
      );
    } catch {
      return false;
    }
  }
}

/** Build an `rsa-sha256=<base64>` header with a PEM-encoded RSA private key. */
export function signRsaPss(rawBody: Buffer, privateKeyPem: string): string {
  const sig = cryptoSign("sha256", rawBody, {
    key: createPrivateKey(privateKeyPem),
    padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
    saltLength: RSA_PSS_SALT_LENGTH,
  });
  return `rsa-sha256=${sig.toString("base64")}`;
}

/**
 * RSA-PSS verifier with key rotation (WR-110): several RSA public keys
 * coexist and every inbound signature is tried against each in config
 * order — during a rotation window the old and the new key both verify
 * in parallel, so upstreams can cut over without downtime. The first
 * matching key wins. `verify` keeps the plain {@link Verifier} contract
 * (boolean); {@link verifyDetailed} reports the SHA-256 fingerprint of
 * the key that matched, for audit trails — the server surfaces it as
 * `keyId`, exactly like the HMAC rotation's key id (there is no
 * `x-key-id` hint for RSA: public keys are tried, not selected).
 * Never throws from verification paths.
 */
export class RotatingRsaPssVerifier implements Verifier {
  readonly name = "rsa-pss-rotating";

  private readonly keys: { fingerprint: string; verifier: RsaPssVerifier }[];

  constructor(publicKeyPems: string[]) {
    if (!Array.isArray(publicKeyPems) || publicKeyPems.length === 0) {
      throw new Error("RotatingRsaPssVerifier: `publicKeyPems` must be a non-empty array");
    }
    const seen = new Set<string>();
    this.keys = publicKeyPems.map((pem, i) => {
      const where = `RotatingRsaPssVerifier: publicKeyPems[${i}]`;
      if (typeof pem !== "string" || pem.trim() === "") {
        throw new Error(`${where} must be a non-empty PEM string`);
      }
      let verifier: RsaPssVerifier;
      try {
        verifier = new RsaPssVerifier(pem);
      } catch {
        throw new Error(`${where} is not a valid PEM public key`);
      }
      const fingerprint = verifier.fingerprint;
      if (seen.has(fingerprint)) {
        throw new Error(`${where} duplicates an earlier key`);
      }
      seen.add(fingerprint);
      return { fingerprint, verifier };
    });
  }

  /** Fingerprints of the configured keys, in try order. */
  get keyFingerprints(): string[] {
    return this.keys.map((k) => k.fingerprint);
  }

  verifyDetailed(rawBody: Buffer, header: string, _opts: VerifyDetailOptions = {}): VerifyDetail {
    try {
      for (const k of this.keys) {
        if (k.verifier.verify(rawBody, header)) {
          return { ok: true, keyId: k.fingerprint };
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

/** Default timestamp tolerance for Stripe-style signatures: 300s (matches Stripe). */
export const DEFAULT_STRIPE_TOLERANCE_SEC = 300;

/**
 * Parsed Stripe-style signature header:
 * `t=<unix_ts>,v1=<hex>[,v1=<hex>...]`.
 */
export interface StripeSignatureHeader {
  /** Unix timestamp (seconds) from the `t=` field. */
  timestamp: number;
  /** One signature per `v1=` field, in header order. */
  signatures: Buffer[];
}

/**
 * Parse a Stripe-style signature header. Stripe sends the timestamp and one
 * signature per signing secret as `t=<unix_ts>,v1=<hex>[,v1=<hex>...]` —
 * during a secret rotation the header may carry several `v1` values and any
 * one of them authenticates. Throws on malformed input; callers that must
 * never throw (like {@link StripeSignatureVerifier.verify}) convert parse
 * failures to `false`.
 */
export function parseStripeSignatureHeader(header: string): StripeSignatureHeader {
  if (!header || typeof header !== "string") {
    throw new Error("StripeSignatureVerifier: missing signature header");
  }
  const parts = header.split(",");
  if (parts.length < 2 || !parts[0].startsWith("t=")) {
    throw new Error("StripeSignatureVerifier: header must start with t=<unix_ts>");
  }
  const ts = Number(parts[0].slice(2).trim());
  if (!Number.isInteger(ts) || ts <= 0) {
    throw new Error("StripeSignatureVerifier: invalid t=<unix_ts> timestamp");
  }
  const signatures = parts.slice(1).map((p) => {
    const field = p.trim();
    if (!field.startsWith("v1=")) {
      throw new Error("StripeSignatureVerifier: expected v1=<hex> fields after t=");
    }
    const hex = field.slice(3).trim();
    if (hex === "" || hex.length % 2 !== 0 || !HEX_RE.test(hex)) {
      throw new Error("StripeSignatureVerifier: invalid v1=<hex> signature");
    }
    return Buffer.from(hex, "hex");
  });
  if (signatures.length === 0) {
    throw new Error("StripeSignatureVerifier: at least one v1=<hex> signature is required");
  }
  return { timestamp: ts, signatures };
}

/** Options for {@link StripeSignatureVerifier}. */
export interface StripeSignatureConfig {
  /**
   * HMAC-SHA256 signing secret(s). Pass an array when the relay holds both
   * the old and the new secret during a rotation — any configured secret
   * matching any `v1` value authenticates.
   */
  secrets: string | string[];
  /**
   * Maximum age/lead of the `t=` timestamp in seconds. Default: 300.
   * A missing timestamp (unparsable header) or an out-of-tolerance
   * timestamp is rejected — replay protection.
   */
  toleranceSec?: number;
  /** Clock source for timestamp checks; defaults to Date.now. Injectable for tests. */
  nowMs?: () => number;
}

/**
 * Stripe-style webhook signature verifier (WR-176). Header format:
 * `t=<unix_ts>,v1=<hex>[,v1=<hex>...]`; the signed payload is
 * `<t>.<rawBody>` (HMAC-SHA256, hex). Multiple `v1` values and multiple
 * configured secrets are both tolerated for key rotation — any
 * (secret, v1) pair that matches authenticates.
 *
 * The timestamp is mandatory and must be within `toleranceSec` (default
 * 300s) of now, both directions — a missing or stale timestamp is an
 * explicit rejection (replay protection), never a silent pass.
 *
 * Register it with {@link registerVerifier} and select it per endpoint
 * with an {@link EndpointVerifierRule}, so a Stripe-style upstream can
 * coexist with {@link HmacSha256Verifier} and {@link Ed25519Verifier}
 * upstreams behind one relay:
 *
 * ```ts
 * registerVerifier(new StripeSignatureVerifier({ secrets: STRIPE_WEBHOOK_SECRET }));
 * const server = createRelayServer({
 *   secret, // global fallback
 *   endpointVerifiers: [
 *     { pattern: "/hooks/stripe", verifier: new StripeSignatureVerifier({ secrets: STRIPE_WEBHOOK_SECRET }) },
 *     { pattern: "/hooks/*", verifier: new HmacSha256Verifier(secret) },
 *   ],
 * });
 * ```
 *
 * Never throws from `verify` — unparsable headers, wrong keys, and crypto
 * errors all mean `false`.
 */
export class StripeSignatureVerifier implements Verifier {
  readonly name = "stripe-signature";

  private readonly secrets: string[];
  private readonly toleranceSec: number;
  private readonly nowMs: () => number;

  constructor(config: StripeSignatureConfig) {
    const secrets = Array.isArray(config?.secrets) ? config.secrets : [config?.secrets];
    if (
      secrets.length === 0 ||
      secrets.some((s) => typeof s !== "string" || s === "")
    ) {
      throw new Error(
        "StripeSignatureVerifier: `secrets` must be a non-empty string or an array of non-empty strings"
      );
    }
    const toleranceSec = config?.toleranceSec ?? DEFAULT_STRIPE_TOLERANCE_SEC;
    if (!Number.isFinite(toleranceSec) || toleranceSec < 0) {
      throw new Error("StripeSignatureVerifier: `toleranceSec` must be a non-negative number");
    }
    this.secrets = secrets;
    this.toleranceSec = toleranceSec;
    this.nowMs = config?.nowMs ?? Date.now;
  }

  verify(rawBody: Buffer, header: string, opts: VerifyOptions = {}): boolean {
    try {
      const parsed = parseStripeSignatureHeader(header);
      const toleranceSec = opts.toleranceSec ?? this.toleranceSec;
      const nowSec = Math.floor((opts.nowMs ?? this.nowMs)() / 1000);
      // A missing timestamp never reaches here (the parse throws); an
      // out-of-tolerance timestamp is an explicit replay-protection reject.
      if (Math.abs(nowSec - parsed.timestamp) > toleranceSec) {
        return false;
      }
      const signed = Buffer.concat([Buffer.from(`${parsed.timestamp}.`, "utf8"), rawBody]);
      for (const secret of this.secrets) {
        const expected = hmacSha256(secret, signed);
        for (const sig of parsed.signatures) {
          if (expected.length === sig.length && timingSafeEqual(expected, sig)) {
            return true;
          }
        }
      }
      return false;
    } catch {
      return false;
    }
  }
}

/**
 * Build a `t=<ts>,v1=<hex>[,v1=<hex>...]` header (useful for tests and for
 * senders that need Stripe-style signatures). `extraSecrets` signs the same
 * payload with additional secrets, emulating a rotation window where the
 * upstream sends several `v1` values.
 */
export function signStripe(
  rawBody: Buffer,
  secret: string,
  timestamp: number = Math.floor(Date.now() / 1000),
  extraSecrets: string[] = []
): string {
  const v1 = (s: string): string => {
    const signed = Buffer.concat([Buffer.from(`${timestamp}.`, "utf8"), rawBody]);
    return `v1=${hmacSha256(s, signed).toString("hex")}`;
  };
  return [`t=${timestamp}`, v1(secret), ...extraSecrets.map(v1)].join(",");
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

/**
 * Per-endpoint inbound body size limit rule (WR-102). Mirrors
 * `EndpointVerifierRule` (WR-29): exact path (`/hooks/payments`) or prefix
 * (`/hooks/*`, which also matches `/hooks` itself); the first matching
 * rule in config order wins via `selectEndpointBodyLimit`, and paths with
 * no match fall back to the global `maxBodyBytes`. A rule may be tighter
 * or looser than the global budget — e.g. a fat settlement webhook on
 * `/hooks/ledger` gets a bigger budget than the default 1 MiB.
 */
export interface EndpointBodyLimitRule {
  /** Request path pattern: exact (`/hooks/payments`) or prefix (`/hooks/*`). */
  pattern: string;
  /** Body size budget in bytes for this endpoint. Positive integer. */
  maxBodyBytes: number;
}

/**
 * Validate endpoint body limit rules at startup. Throws RangeError on a
 * non-array, a pattern that is not a `/`-rooted path, or a
 * non-positive-integer `maxBodyBytes` — fail fast, never mid-request.
 */
export function assertValidEndpointBodyLimitRules(rules: EndpointBodyLimitRule[] | undefined): void {
  if (rules === undefined) return;
  if (!Array.isArray(rules)) {
    throw new RangeError("endpointBodyLimits: expected an array of { pattern, maxBodyBytes } rules");
  }
  rules.forEach((rule, i) => {
    const where = `endpointBodyLimits[${i}]`;
    if (
      !rule ||
      typeof rule.pattern !== "string" ||
      rule.pattern === "" ||
      !rule.pattern.startsWith("/")
    ) {
      throw new RangeError(
        `${where}: pattern must be a path starting with "/" (exact) or ending with "/*" (prefix)`
      );
    }
    if (!Number.isInteger(rule.maxBodyBytes) || rule.maxBodyBytes <= 0) {
      throw new RangeError(`${where}: maxBodyBytes must be a positive integer`);
    }
  });
}

/**
 * Select the inbound body budget for a request path: the first matching
 * rule's `maxBodyBytes`, or `undefined` when nothing matches (the caller
 * falls back to the global `maxBodyBytes`). Never throws.
 */
export function selectEndpointBodyLimit(
  pathname: string,
  rules: EndpointBodyLimitRule[] | undefined
): number | undefined {
  if (rules === undefined) return undefined;
  for (const rule of rules) {
    if (rule.pattern.endsWith("/*")) {
      const prefix = rule.pattern.slice(0, -2);
      if (pathname === prefix || pathname.startsWith(prefix + "/")) {
        return rule.maxBodyBytes;
      }
    } else if (pathname === rule.pattern) {
      return rule.maxBodyBytes;
    }
  }
  return undefined;
}
