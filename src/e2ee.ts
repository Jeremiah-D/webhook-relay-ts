import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  type KeyObject,
} from "node:crypto";

/**
 * WR-58: outbound end-to-end encryption for deliveries.
 *
 * The relay never holds a downstream's private key. Each delivery to an
 * encrypted endpoint is sealed with a fresh ephemeral X25519 keypair:
 *
 *   1. ECDH — `diffieHellman(ephemeralPrivate, downstreamPublic)` gives
 *      the shared secret (per-delivery forward secrecy: the ephemeral
 *      key is discarded after sealing);
 *   2. HKDF-SHA256 — the shared secret is expanded into a 32-byte
 *      content key, bound to this relay's scheme via the salt/info
 *      strings, so the raw ECDH output is never used as a cipher key
 *      directly;
 *   3. AES-256-GCM — the wire payload is sealed under the derived key
 *      with a fresh random 12-byte IV per delivery; the 16-byte auth tag
 *      makes tampering fail loudly on open.
 *
 * The downstream holds its X25519 private key, reads the relay's
 * ephemeral public key (`epk`) from the envelope, and runs the same
 * derivation in reverse (see {@link unsealOutboundPayload}). `node:crypto`
 * only — zero dependencies.
 *
 * Wire form: the sealed body is a JSON envelope (see
 * {@link SealedOutboundEnvelope}), stamped with the
 * {@link E2EE_HEADER} header (`x-relay-encryption`). The relay signs the
 * *ciphertext* wire bytes with `x-relay-signature` (WR-26) — signature
 * and encryption stay orthogonal: authenticity from the relay, secrecy
 * for the downstream.
 */

/** Value of the {@link E2EE_HEADER} header on sealed outbound requests. */
export const E2EE_ALGORITHM = "x25519-hkdf-sha256/aes-256-gcm";

/** Header marking a sealed outbound request. */
export const E2EE_HEADER = "x-relay-encryption";

/** Algorithm id recorded inside the sealed envelope. */
export const E2EE_ENVELOPE_ALG = "x25519-hkdf-sha256+aes-256-gcm";

/** HKDF salt binding the derivation to this relay's E2EE scheme. */
const HKDF_SALT = Buffer.from("webhook-relay-ts/e2ee/v1", "utf8");
/** HKDF info string for the outbound-payload content key. */
const HKDF_INFO = Buffer.from("outbound-payload-seal", "utf8");

/** DER prefix of an RFC 8410 X25519 PKCS#8 private key (`302e020100300506032b656e04220420`). */
const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");

/** A portable X25519 keypair: base64 of the raw 32-byte keys. */
export interface X25519KeyPair {
  /** base64 of the raw 32-byte public key (this is what gets provisioned per endpoint). */
  publicKey: string;
  /** base64 of the raw 32-byte private key (stays with the downstream — never give this to the relay). */
  privateKey: string;
}

/** Generate a fresh X25519 keypair (`node:crypto` only). */
export function generateX25519KeyPair(): X25519KeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("x25519");
  return {
    publicKey: Buffer.from(publicKey.export({ format: "jwk" }).x as string, "base64url").toString("base64"),
    privateKey: Buffer.from(privateKey.export({ format: "jwk" }).d as string, "base64url").toString("base64"),
  };
}

/**
 * Strict base64 decode: unlike `Buffer.from(s, "base64")` (which silently
 * drops out-of-alphabet characters), this rejects anything that is not
 * canonical base64, so a typo'd key fails at startup instead of decoding
 * to a truncated key.
 */
function decodeBase64Strict(value: string, label: string): Buffer {
  if (typeof value !== "string" || value.length === 0 || value.length % 4 !== 0) {
    throw new RangeError(`${label}: expected base64, got ${typeof value === "string" ? JSON.stringify(value.slice(0, 24)) : typeof value}`);
  }
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    throw new RangeError(`${label}: not valid base64`);
  }
  return Buffer.from(value, "base64");
}

function decodeRawKey(value: string, label: string): Buffer {
  const raw = decodeBase64Strict(value, label);
  if (raw.length !== 32) {
    throw new RangeError(`${label}: X25519 keys are 32 bytes, got ${raw.length}`);
  }
  return raw;
}

/**
 * Parse a base64-encoded raw 32-byte X25519 public key into a `KeyObject`
 * (throws `RangeError` on anything invalid — fail fast at startup, never
 * mid-delivery). The JWK import additionally rejects byte strings that
 * are not valid curve points.
 */
export function parseX25519PublicKey(base64Key: string, label = "x25519 public key"): KeyObject {
  const raw = decodeRawKey(base64Key, label);
  try {
    return createPublicKey({
      key: { kty: "OKP", crv: "X25519", x: raw.toString("base64url") },
      format: "jwk",
    });
  } catch (err) {
    throw new RangeError(`${label}: not a valid X25519 public key (${err instanceof Error ? err.message : String(err)})`);
  }
}

/**
 * Parse a base64-encoded raw 32-byte X25519 private key into a `KeyObject`
 * (throws `RangeError` on anything invalid). Node's JWK import needs the
 * public half alongside the private scalar, so the raw key is wrapped in
 * its RFC 8410 PKCS#8 DER form instead — the private seed alone suffices.
 */
export function parseX25519PrivateKey(base64Key: string, label = "x25519 private key"): KeyObject {
  const raw = decodeRawKey(base64Key, label);
  try {
    return createPrivateKey({
      key: Buffer.concat([X25519_PKCS8_PREFIX, raw]),
      format: "der",
      type: "pkcs8",
    });
  } catch (err) {
    throw new RangeError(`${label}: not a valid X25519 private key (${err instanceof Error ? err.message : String(err)})`);
  }
}

/** Derive the 32-byte AES content key from the ECDH shared secret. */
function deriveContentKey(sharedSecret: Buffer): Buffer {
  return hkdfSync("sha256", sharedSecret, HKDF_SALT, HKDF_INFO, 32);
}

/**
 * The sealed wire envelope: JSON-serializable. `epk` carries the relay's
 * ephemeral X25519 public key (base64) so the downstream can run the ECDH
 * from its side; `iv`/`ct`/`tag` are the AES-256-GCM parameters and
 * ciphertext (base64). `innerEncoding` records the content encoding the
 * plaintext had *before* sealing (e.g. `"gzip"` from WR-40) — the HTTP
 * `content-encoding` header is dropped when a body is sealed, because the
 * wire bytes are the envelope, not the gzip stream.
 */
export interface SealedOutboundEnvelope {
  alg: typeof E2EE_ENVELOPE_ALG;
  /** base64 relay ephemeral X25519 public key (raw 32 bytes). */
  epk: string;
  /** base64 12-byte AES-GCM IV. */
  iv: string;
  /** base64 ciphertext. */
  ct: string;
  /** base64 16-byte AES-GCM auth tag. */
  tag: string;
  /** Content encoding of the plaintext before sealing, if any. */
  innerEncoding?: string;
}

/** True when `v` has the shape of a {@link SealedOutboundEnvelope}. */
export function isSealedOutboundEnvelope(v: unknown): v is SealedOutboundEnvelope {
  if (!v || typeof v !== "object") return false;
  const e = v as Record<string, unknown>;
  return (
    e.alg === E2EE_ENVELOPE_ALG &&
    typeof e.epk === "string" &&
    typeof e.iv === "string" &&
    typeof e.ct === "string" &&
    typeof e.tag === "string" &&
    (e.innerEncoding === undefined || typeof e.innerEncoding === "string")
  );
}

/**
 * Seal `plaintext` for the holder of `downstreamPublicKey` (a parsed
 * {@link parseX25519PublicKey} key). Returns the JSON envelope bytes ready
 * for the wire. A fresh ephemeral keypair and IV are used per call, so
 * identical plaintexts seal to different envelopes. Never throws on valid
 * input.
 */
export function sealOutboundPayload(
  plaintext: Buffer,
  downstreamPublicKey: KeyObject,
  innerEncoding?: string
): Buffer {
  const ephemeral = generateKeyPairSync("x25519");
  const sharedSecret = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: downstreamPublicKey });
  const key = deriveContentKey(sharedSecret);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const epk = Buffer.from(ephemeral.publicKey.export({ format: "jwk" }).x as string, "base64url").toString("base64");
  const envelope: SealedOutboundEnvelope = {
    alg: E2EE_ENVELOPE_ALG,
    epk,
    iv: iv.toString("base64"),
    ct: ct.toString("base64"),
    tag: cipher.getAuthTag().toString("base64"),
    ...(innerEncoding !== undefined ? { innerEncoding } : {}),
  };
  return Buffer.from(JSON.stringify(envelope), "utf8");
}

/** The opened side of {@link sealOutboundPayload}. */
export interface UnsealedOutboundPayload {
  /** The original plaintext bytes. */
  plaintext: Buffer;
  /** Content encoding the plaintext had before sealing, if any. */
  innerEncoding?: string;
}

/**
 * Open a sealed envelope (see {@link sealOutboundPayload}) with the
 * downstream's private key (a parsed {@link parseX25519PrivateKey} key).
 * Throws on any mismatch — wrong envelope shape, unknown `alg`, invalid
 * `epk`, bad IV/tag lengths, or a failed auth tag (tampered ciphertext or
 * wrong key). Never returns garbage silently.
 */
export function unsealOutboundPayload(
  envelopeBytes: Buffer,
  downstreamPrivateKey: KeyObject
): UnsealedOutboundPayload {
  let envelope: unknown;
  try {
    envelope = JSON.parse(envelopeBytes.toString("utf8"));
  } catch {
    throw new Error("unsealOutboundPayload: envelope is not valid JSON");
  }
  if (!isSealedOutboundEnvelope(envelope)) {
    throw new Error("unsealOutboundPayload: not a sealed outbound envelope");
  }
  try {
    const epk = parseX25519PublicKey(envelope.epk, "envelope.epk");
    const iv = decodeBase64Strict(envelope.iv, "envelope.iv");
    const tag = decodeBase64Strict(envelope.tag, "envelope.tag");
    if (iv.length !== 12) throw new Error(`bad IV length: ${iv.length}`);
    if (tag.length !== 16) throw new Error(`bad auth tag length: ${tag.length}`);
    const sharedSecret = diffieHellman({ privateKey: downstreamPrivateKey, publicKey: epk });
    const key = deriveContentKey(sharedSecret);
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([
      decipher.update(decodeBase64Strict(envelope.ct, "envelope.ct")),
      decipher.final(),
    ]);
    return { plaintext, ...(envelope.innerEncoding !== undefined ? { innerEncoding: envelope.innerEncoding } : {}) };
  } catch (err) {
    throw new Error(
      `unsealOutboundPayload failed: ${err instanceof Error ? err.message : String(err)}`
    );
  }
}
