import { createHash, X509Certificate } from "node:crypto";

/**
 * Outbound TLS certificate pinning (WR-21).
 *
 * Each endpoint (a delivery `targetUrl`) can carry a whitelist of SPKI
 * fingerprints — SHA-256 over the DER-encoded SubjectPublicKeyInfo of the
 * server's leaf certificate. When pins are configured for an endpoint, the
 * pin whitelist *replaces* the default PKI chain verification for that
 * endpoint: the pin is the trust anchor. That is what makes pinning useful
 * against a compromised CA or a MITM holding a valid-but-unexpected
 * certificate — and it is also what makes a misconfigured pin fail loudly
 * instead of silently trusting the wrong server.
 *
 * Why the pin check cannot live in `checkServerIdentity`: Node runs the
 * OpenSSL chain verification before that callback, so a certificate the
 * chain rejects (self-signed, private CA) never reaches it — and with
 * `rejectUnauthorized: false` Node skips the callback entirely. The sender
 * therefore verifies the peer certificate itself on the socket's
 * `secureConnect`, *before* a single payload byte is written. A mismatch
 * destroys the request with {@link TlsPinMismatchError}, which fails the
 * delivery attempt; the attempt then follows the normal retry / dead-letter
 * path and the mismatch is visible in the audit trail.
 *
 * Pin format (all three spellings are accepted and equivalent):
 *
 * - `"sha256/<base64>"` (HPKP style)
 * - `"sha256:<base64>"`
 * - bare `"<base64>"` — the raw base64 of the 32-byte SHA-256 digest
 *
 * Zero dependencies (`node:crypto` only).
 */

/** The error a pinned delivery fails with when the handshake presents an unknown key. */
export class TlsPinMismatchError extends Error {
  /** The endpoint whose pin whitelist rejected the presented key. */
  readonly endpoint: string;
  /** Base64 SHA-256 of the SPKI the server actually presented. */
  readonly presented: string;

  constructor(endpoint: string, presented: string) {
    super(
      `TLS pin mismatch for ${endpoint}: presented SPKI sha256/${presented} is not in the pin whitelist`
    );
    this.name = "TlsPinMismatchError";
    this.endpoint = endpoint;
    this.presented = presented;
  }
}

/**
 * SHA-256 (base64) of the DER-encoded SubjectPublicKeyInfo extracted from a
 * DER-encoded leaf certificate. Pinning the SPKI — not the whole cert —
 * survives routine certificate renewals that keep the same keypair.
 */
export function spkiFingerprint(certDer: Buffer): string {
  const spkiDer = new X509Certificate(certDer).publicKey.export({ type: "spki", format: "der" });
  return createHash("sha256").update(spkiDer).digest("base64");
}

/** Strip an optional `sha256:`/`sha256/` scheme prefix; returns the bare base64 digest. */
export function normalizePin(pin: string): string {
  const m = /^sha256[:/](.+)$/i.exec(pin.trim());
  return (m ? m[1] : pin).trim();
}

function isWellFormedPin(pin: string): boolean {
  const bare = normalizePin(pin);
  if (bare.length === 0) return false;
  let bytes: Buffer;
  try {
    bytes = Buffer.from(bare, "base64");
  } catch {
    return false;
  }
  // 32 bytes of digest; also reject strings that don't round-trip, so a
  // typo like a truncated digest fails at config time, not at 3am.
  return bytes.length === 32 && bytes.toString("base64") === bare;
}

/**
 * Validate a pin whitelist the way a constructor would: non-empty, every
 * entry a well-formed 32-byte base64 digest. Throws `RangeError` on the
 * first problem so a bad config fails at startup, never mid-delivery.
 */
export function assertValidPins(pins: readonly string[]): void {
  if (pins.length === 0) {
    throw new RangeError("TLS pin whitelist must not be empty: refusing to pin to nothing");
  }
  for (const pin of pins) {
    if (!isWellFormedPin(pin)) {
      throw new RangeError(`malformed TLS pin (expected sha256/<base64 of 32 bytes>), got ${JSON.stringify(pin)}`);
    }
  }
}

/** True when the presented leaf certificate's SPKI matches any whitelisted pin. */
export function pinMatches(certDer: Buffer, pins: readonly string[]): boolean {
  const presented = spkiFingerprint(certDer);
  return pins.some((p) => normalizePin(p) === presented);
}
