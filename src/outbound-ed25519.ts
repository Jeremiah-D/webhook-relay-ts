/**
 * Outbound Ed25519 asymmetric request signing (WR-124).
 *
 * WR-26 signs outbound deliveries with HMAC-SHA256 under a shared secret;
 * that works when the relay and the downstream can both hold the secret.
 * Some downstreams — a bank's verification service, a partner's settlement
 * hook — cannot or will not hold a shared signing secret. This module
 * gives them the asymmetric alternative: the relay holds an Ed25519
 * private key and stamps every outbound delivery with
 * `x-relay-ed25519-signature: ed25519=<hex>` (plus the optional
 * `x-relay-ed25519-key-id`); the downstream verifies with the public key
 * alone, using `node:crypto` — zero external dependencies on either side.
 *
 * The Ed25519 stamp coexists with the WR-26 HMAC stamp: the relay sends
 * both, and the downstream accepts the delivery when *either* signature
 * verifies. Inbound `x-relay-ed25519-signature` /
 * `x-relay-ed25519-key-id` headers are always stripped from the forwarded
 * header set (see `createDefaultSender` in `src/server.ts`), so a sender
 * can never smuggle a forged relay signature downstream — exactly like
 * the HMAC headers.
 *
 * Rotation reuses the WR-67 (`src/secret-rotation.ts`) convention: the
 * relay cuts its signing key over to the new private key atomically, and
 * the downstream's {@link RotatingEd25519Verifier} keeps the previous
 * public key verifiable inside a grace window measured from
 * `previousRetiredAtMs`. Signatures made with the old key still verify
 * during the window; after it, `isRotationComplete()` reports the
 * rotation done and the old public key is dropped.
 */

import {
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  type KeyObject,
} from "node:crypto";
import { Ed25519Verifier, type Verifier } from "./verify.ts";

/** Outbound header carrying the Ed25519 signature (`ed25519=<hex>`). */
export const ED25519_SIGNATURE_HEADER = "x-relay-ed25519-signature";

/** Outbound header carrying the Ed25519 signing key id. */
export const ED25519_KEY_ID_HEADER = "x-relay-ed25519-key-id";

/** Default grace window for a retired Ed25519 key: 24h, matching WR-20/WR-67. */
export const DEFAULT_ED25519_ROTATION_GRACE_MS = 86_400_000;

/** Which side of an Ed25519 rotation verified a signature. */
export type Ed25519KeyVersion = "current" | "previous";

/**
 * One Ed25519 key the relay signs outbound deliveries with, embedded in
 * `OutboundSigningConfig` (see `src/server.ts`).
 */
export interface Ed25519OutboundKeyConfig {
  /**
   * PEM-encoded Ed25519 private key. Non-empty; parsed once at startup
   * (fail fast), never per delivery. Generate with
   * `generateKeyPairSync("ed25519")` from `node:crypto` — the matching
   * public key is the only thing the downstream ever needs.
   */
  privateKey: string;
  /**
   * Stable identifier surfaced in the `x-relay-ed25519-key-id` header, so
   * the downstream can attribute the signature (and, during a rotation,
   * select between the current and previous public key). Optional.
   */
  keyId?: string;
}

/**
 * A validated Ed25519 outbound signing key: the private key parsed once
 * at startup, the id stamped per delivery.
 */
export interface CompiledEd25519OutboundKey {
  privateKey: KeyObject;
  keyId?: string;
}

function parseEd25519PrivateKey(pem: string, where: string): KeyObject {
  let key: KeyObject;
  try {
    key = createPrivateKey(pem);
  } catch {
    throw new RangeError(`${where}: \`privateKey\` is not a valid PEM private key`);
  }
  if (key.asymmetricKeyType !== "ed25519") {
    throw new RangeError(
      `${where}: \`privateKey\` must be an Ed25519 private key, got ${key.asymmetricKeyType ?? "unknown"}`
    );
  }
  return key;
}

/**
 * Validate an Ed25519 outbound signing config and parse the private key
 * once. Throws `RangeError` on invalid values — call at startup, never
 * mid-delivery.
 */
export function compileEd25519OutboundKey(
  cfg: Ed25519OutboundKeyConfig,
  where: string
): CompiledEd25519OutboundKey {
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(`${where} must be an object`);
  }
  if (typeof cfg.privateKey !== "string" || cfg.privateKey.trim() === "") {
    throw new RangeError(`${where}: \`privateKey\` must be a non-empty PEM string`);
  }
  if (cfg.keyId !== undefined && (typeof cfg.keyId !== "string" || cfg.keyId === "")) {
    throw new RangeError(`${where}: \`keyId\` must be a non-empty string when set`);
  }
  return { privateKey: parseEd25519PrivateKey(cfg.privateKey, where), keyId: cfg.keyId };
}

/**
 * Build the `x-relay-ed25519-signature` header value (`ed25519=<hex>`)
 * for `rawBody` with a compiled key. The signature covers the exact wire
 * bytes the downstream receives — call it on the final body, after
 * compression / E2EE sealing / transforms, exactly where the HMAC stamp
 * is applied.
 */
export function signEd25519Outbound(rawBody: Buffer, compiled: CompiledEd25519OutboundKey): string {
  return `ed25519=${cryptoSign(null, rawBody, compiled.privateKey).toString("hex")}`;
}

/** Options for {@link RotatingEd25519Verifier}. */
export interface Ed25519RotationConfig {
  /**
   * PEM-encoded Ed25519 public key that verifies new signatures — the
   * relay's current signing key. Non-empty. Always tried first.
   */
  currentPublicKey: string;
  /**
   * Stable id of the current key, matched against the sender's
   * `x-relay-ed25519-key-id` hint. Optional.
   */
  currentKeyId?: string;
  /**
   * PEM-encoded Ed25519 public key of the retired signing key: tried only
   * inside its grace window. Omit (or clear after `isRotationComplete()`)
   * once the rotation is done.
   */
  previousPublicKey?: string;
  /**
   * Stable id of the previous key, matched against the key-id hint.
   * Optional; must differ from `currentKeyId` when both are set.
   */
  previousKeyId?: string;
  /**
   * Grace window in ms, measured from `previousRetiredAtMs`, during which
   * `previousPublicKey` still verifies. Default:
   * {@link DEFAULT_ED25519_ROTATION_GRACE_MS} (24h).
   */
  graceMs?: number;
  /**
   * Millisecond epoch at which `previousPublicKey` was retired. Defaults
   * to construction time: when the config is applied, the rotation is
   * assumed to have just begun. Operators who rotate across restarts
   * should pin this to the real retirement moment so the window does
   * not silently restart on every deploy.
   */
  previousRetiredAtMs?: number;
  /** Clock source for grace checks; defaults to Date.now. Injectable for tests. */
  nowMs?: () => number;
}

/** Options accepted by {@link RotatingEd25519Verifier.verifyDetailed}. */
export interface Ed25519RotationVerifyOptions {
  /**
   * The sender's `x-relay-ed25519-key-id` header value. When it names the
   * current or previous key id, only that key is tried; an unknown id
   * fails closed — never falls back across a sender bug.
   */
  keyId?: string;
}

/** Result of {@link RotatingEd25519Verifier.verifyDetailed}. Never throws. */
export interface Ed25519RotationVerifyResult {
  ok: boolean;
  /** Which key verified; undefined when `ok` is false. */
  version?: Ed25519KeyVersion;
}

function parseEd25519PublicKey(pem: string, where: string): Ed25519Verifier {
  if (typeof pem !== "string" || pem.trim() === "") {
    throw new RangeError(`${where} must be a non-empty PEM string`);
  }
  let key: KeyObject;
  try {
    key = createPublicKey(pem);
  } catch {
    throw new RangeError(`${where} is not a valid PEM public key`);
  }
  if (key.asymmetricKeyType !== "ed25519") {
    throw new RangeError(
      `${where} must be an Ed25519 public key, got ${key.asymmetricKeyType ?? "unknown"}`
    );
  }
  return new Ed25519Verifier(pem);
}

/**
 * Ed25519 verifier with key rotation (WR-124), reusing the WR-67
 * (`src/secret-rotation.ts`) convention for the downstream side of an
 * outbound-signing key rotation: the current public key is always tried
 * first, and the previous public key stays verifiable inside a grace
 * window measured from `previousRetiredAtMs`. The relay cuts its signing
 * key over atomically (it always signs with a single private key); this
 * verifier is what the downstream — e.g. a bank's verification service —
 * runs so in-flight deliveries signed with the old key keep verifying
 * while the cutover propagates.
 *
 * Implements {@link Verifier}, so it can be registered and selected by
 * name like any other verifier. Verification never throws: unparsable
 * headers, wrong keys, expired grace windows, and unknown key-id hints
 * all mean `false`.
 */
export class RotatingEd25519Verifier implements Verifier {
  readonly name = "ed25519-dual-rotation";

  private readonly current: Ed25519Verifier;
  private readonly currentKeyId?: string;
  private readonly previous?: Ed25519Verifier;
  private readonly previousKeyId?: string;
  private readonly graceMs: number;
  private readonly retiredAtMs: number;
  private readonly nowMs: () => number;

  constructor(config: Ed25519RotationConfig) {
    if (config === null || typeof config !== "object") {
      throw new RangeError("Ed25519RotationConfig must be an object");
    }
    this.current = parseEd25519PublicKey(
      config.currentPublicKey,
      "Ed25519RotationConfig: `currentPublicKey`"
    );
    if (
      config.currentKeyId !== undefined &&
      (typeof config.currentKeyId !== "string" || config.currentKeyId === "")
    ) {
      throw new RangeError(
        "Ed25519RotationConfig: `currentKeyId` must be a non-empty string when set"
      );
    }
    this.currentKeyId = config.currentKeyId;
    if (config.previousPublicKey !== undefined) {
      this.previous = parseEd25519PublicKey(
        config.previousPublicKey,
        "Ed25519RotationConfig: `previousPublicKey`"
      );
    }
    if (
      config.previousKeyId !== undefined &&
      (typeof config.previousKeyId !== "string" || config.previousKeyId === "")
    ) {
      throw new RangeError(
        "Ed25519RotationConfig: `previousKeyId` must be a non-empty string when set"
      );
    }
    this.previousKeyId = config.previousKeyId;
    if (
      this.currentKeyId !== undefined &&
      this.previousKeyId !== undefined &&
      this.currentKeyId === this.previousKeyId
    ) {
      throw new RangeError(
        "Ed25519RotationConfig: `currentKeyId` and `previousKeyId` must differ"
      );
    }
    const graceMs = config.graceMs ?? DEFAULT_ED25519_ROTATION_GRACE_MS;
    if (!Number.isFinite(graceMs) || graceMs < 0) {
      throw new RangeError("Ed25519RotationConfig: `graceMs` must be a non-negative finite number");
    }
    this.graceMs = graceMs;
    const nowMs = config.nowMs ?? Date.now;
    const retiredAtMs = config.previousRetiredAtMs ?? nowMs();
    if (!Number.isFinite(retiredAtMs) || retiredAtMs < 0) {
      throw new RangeError(
        "Ed25519RotationConfig: `previousRetiredAtMs` must be a non-negative epoch ms"
      );
    }
    this.retiredAtMs = retiredAtMs;
    this.nowMs = nowMs;
  }

  /** Whether the previous key is still inside its grace window. */
  previousInGrace(): boolean {
    if (this.previous === undefined) return false;
    // Grace boundary is inclusive, matching RotatingHmacVerifier (WR-20):
    // exactly `graceMs` old still verifies, 1ms older does not.
    return this.nowMs() - this.retiredAtMs <= this.graceMs;
  }

  /**
   * Whether the rotation is complete: a previous key is configured but
   * its grace window has fully elapsed. The operator can then clear
   * `previousPublicKey` from the config — old-key signatures are
   * rejected from here on.
   */
  isRotationComplete(): boolean {
    return this.previous !== undefined && !this.previousInGrace();
  }

  verifyDetailed(
    rawBody: Buffer,
    header: string,
    opts: Ed25519RotationVerifyOptions = {}
  ): Ed25519RotationVerifyResult {
    try {
      const hint =
        typeof opts.keyId === "string" && opts.keyId.trim() !== "" ? opts.keyId.trim() : undefined;
      if (hint !== undefined) {
        // A key-id claim that names neither side fails closed: never fall
        // back across a sender bug.
        if (hint === this.currentKeyId) {
          return this.current.verify(rawBody, header)
            ? { ok: true, version: "current" }
            : { ok: false };
        }
        if (hint === this.previousKeyId) {
          if (!this.previousInGrace()) return { ok: false };
          return this.previous!.verify(rawBody, header)
            ? { ok: true, version: "previous" }
            : { ok: false };
        }
        return { ok: false };
      }
      // No hint: current key first, previous as fallback inside its grace.
      if (this.current.verify(rawBody, header)) {
        return { ok: true, version: "current" };
      }
      if (this.previousInGrace() && this.previous!.verify(rawBody, header)) {
        return { ok: true, version: "previous" };
      }
      return { ok: false };
    } catch {
      return { ok: false };
    }
  }

  /** `true` when `header` authenticates `rawBody` under either rotation key. Never throws. */
  verify(rawBody: Buffer, header: string, opts: Ed25519RotationVerifyOptions = {}): boolean {
    return this.verifyDetailed(rawBody, header, opts).ok;
  }
}
