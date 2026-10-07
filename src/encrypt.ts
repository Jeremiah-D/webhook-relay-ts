import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

/**
 * Encrypted payload envelope. JSON-serializable, so it can be stored inline
 * in the dead-letter list or an audit-log line without leaking plaintext.
 */
export interface EncryptedPayload {
  /** Algorithm id, e.g. `"aes-256-gcm"` or `"none"`. */
  alg: string;
  /** base64 nonce/IV ("" when the scheme needs none). */
  iv: string;
  /** base64 ciphertext. */
  data: string;
  /** base64 authentication tag (AEAD schemes). */
  tag?: string;
}

/**
 * A payload encryptor: one named scheme that seals raw payload bytes into
 * an {@link EncryptedPayload} and opens them back up. Implementations must
 * throw from `decrypt` on tampered or unrecognized envelopes (never return
 * garbage silently).
 */
export interface PayloadEncryptor {
  /** Unique scheme name, e.g. `"aes-256-gcm"`. */
  readonly name: string;
  /** Seal `plaintext` into a JSON-serializable envelope. Never throws on valid input. */
  encrypt(plaintext: Buffer): EncryptedPayload;
  /** Open `envelope` back into the original bytes. Throws on any mismatch. */
  decrypt(envelope: EncryptedPayload): Buffer;
}

/** True when `v` has the shape of an {@link EncryptedPayload}. */
export function isEncryptedPayload(v: unknown): v is EncryptedPayload {
  if (!v || typeof v !== "object") return false;
  const e = v as Record<string, unknown>;
  return (
    typeof e.alg === "string" &&
    typeof e.iv === "string" &&
    typeof e.data === "string" &&
    (e.tag === undefined || typeof e.tag === "string")
  );
}

/**
 * AES-256-GCM payload encryption, `node:crypto` only. Each `encrypt` uses a
 * fresh random 12-byte IV, so identical plaintexts produce different
 * envelopes; the 16-byte auth tag makes tampering fail `decrypt` loudly.
 */
export class AesGcmEncryptor implements PayloadEncryptor {
  readonly name = "aes-256-gcm";
  private readonly key: Buffer;

  /** `key` must be exactly 32 bytes (throws `RangeError` otherwise). */
  constructor(key: Buffer) {
    if (!Buffer.isBuffer(key) || key.length !== 32) {
      throw new RangeError(
        `AesGcmEncryptor needs a 32-byte key, got ${Buffer.isBuffer(key) ? `${key.length} bytes` : typeof key}`
      );
    }
    this.key = Buffer.from(key); // copy: later mutation of the caller's buffer can't weaken us
  }

  encrypt(plaintext: Buffer): EncryptedPayload {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    const data = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return {
      alg: this.name,
      iv: iv.toString("base64"),
      data: data.toString("base64"),
      tag: cipher.getAuthTag().toString("base64"),
    };
  }

  decrypt(envelope: EncryptedPayload): Buffer {
    try {
      if (!isEncryptedPayload(envelope) || envelope.alg !== this.name) {
        throw new Error(`unsupported envelope alg: ${(envelope as { alg?: unknown }).alg}`);
      }
      const iv = Buffer.from(envelope.iv, "base64");
      const tag = Buffer.from(envelope.tag ?? "", "base64");
      if (iv.length !== 12) throw new Error(`bad IV length: ${iv.length}`);
      if (tag.length !== 16) throw new Error(`bad auth tag length: ${tag.length}`);
      const decipher = createDecipheriv("aes-256-gcm", this.key, iv);
      decipher.setAuthTag(tag);
      return Buffer.concat([
        decipher.update(Buffer.from(envelope.data, "base64")),
        decipher.final(),
      ]);
    } catch (err) {
      throw new Error(
        `AesGcmEncryptor.decrypt failed: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }
}

/** Generate a fresh 32-byte key for {@link AesGcmEncryptor}. */
export function randomAes256Key(): Buffer {
  return randomBytes(32);
}

/**
 * Passthrough encryptor for tests and fixtures. The "ciphertext" is the
 * plaintext base64'd — it protects nothing. Never use in production.
 */
export class NoopEncryptor implements PayloadEncryptor {
  readonly name = "none";

  encrypt(plaintext: Buffer): EncryptedPayload {
    return { alg: this.name, iv: "", data: plaintext.toString("base64") };
  }

  decrypt(envelope: EncryptedPayload): Buffer {
    if (!isEncryptedPayload(envelope) || envelope.alg !== this.name) {
      throw new Error(`NoopEncryptor: unsupported envelope alg: ${(envelope as { alg?: unknown }).alg}`);
    }
    return Buffer.from(envelope.data, "base64");
  }
}
