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

/**
 * Live revision patch for the outbound TLS pin whitelist (WR-429):
 * `targetUrl` → `string[] | null`. `null` removes that endpoint's pins
 * entirely (it falls back to default PKI validation); an omitted
 * endpoint keeps its live value. At least one field must be present —
 * an empty patch throws `RangeError`.
 *
 * This revises only the WHITELIST map (which endpoints carry which
 * pins). The pin-validation semantics are untouched: a pin is still a
 * 32-byte base64 SPKI digest in any of the three accepted spellings,
 * and the whitelist still replaces PKI verification for its endpoint.
 */
export type TlsPinsRevision = Record<string, string[] | null>;

/** One endpoint's pin change, as returned by `reviseTlsPinsMap`. */
export interface TlsPinChange {
  /** The exact `targetUrl` whose pins changed. */
  endpoint: string;
  /** Pins live before the revision (`null` when none existed). */
  previous: string[] | null;
  /** Pins live after the revision (`null` when cleared). */
  current: string[] | null;
}

/**
 * Whether two pin whitelists are the same whitelist: the same digests
 * after normalizing the `sha256:`/`sha256/` spelling. Order is
 * irrelevant — the whitelist is a set, so reordering changes nothing
 * on the wire.
 */
function samePins(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false;
  const sortedA = a.map(normalizePin).sort();
  const sortedB = b.map(normalizePin).sort();
  return sortedA.every((pin, i) => pin === sortedB[i]);
}

/**
 * Live-revise the outbound TLS pin whitelist map at runtime (WR-429),
 * no restart. The whole patch is validated first (every non-null entry
 * goes through `assertValidPins` — the startup gate — so a malformed
 * pin, an empty whitelist, or a non-array value rejects the whole patch
 * with `RangeError`, zero partial application); at least one field is
 * required, otherwise `RangeError`.
 *
 * A `null` entry clears that endpoint's pins (it falls back to default
 * PKI validation); an omitted endpoint keeps its live value. Adding
 * pins for an endpoint that had none creates the binding — adding pins
 * only tightens validation, so unlike WR-428 this is not an error when
 * unconfigured.
 *
 * A patch entry is a no-op when the endpoint already carries the same
 * pins (same digests after normalization, any order or spelling);
 * clearing an endpoint with no pins is likewise a no-op. Returns one
 * entry per endpoint whose pins actually changed — an empty array when
 * the whole patch was a no-op, so the caller can stay silent. The map
 * is mutated in place (never replaced) and each stored list is a fresh
 * copy, so a delivery whose wire request was already built keeps the
 * pin array it started with — the revision takes effect from the next
 * handshake.
 */
export function reviseTlsPinsMap(
  live: Map<string, string[]>,
  patch: TlsPinsRevision
): TlsPinChange[] {
  if (patch === null || typeof patch !== "object" || Array.isArray(patch)) {
    throw new RangeError(
      "reviseTlsPins: patch must be a Record<exact targetUrl, string[] | null>"
    );
  }
  const entries = Object.entries(patch);
  if (entries.length === 0) {
    throw new RangeError("reviseTlsPins: patch must contain at least one field");
  }
  for (const [targetUrl, pins] of entries) {
    if (targetUrl === "") {
      throw new RangeError(
        "reviseTlsPins: targetUrl must be a non-empty exact target URL"
      );
    }
    if (pins !== null) {
      if (!Array.isArray(pins)) {
        throw new RangeError(
          `reviseTlsPins: pins for ${targetUrl} must be a string[] or null`
        );
      }
      // Validate-then-apply: the whole patch is gated before any entry
      // lands, so a bad pin binds nothing.
      assertValidPins(pins);
    }
  }
  const changes: TlsPinChange[] = [];
  for (const [targetUrl, pins] of entries) {
    const prev = live.get(targetUrl);
    if (pins === null) {
      if (prev === undefined) continue; // Clearing an unpinned endpoint: no-op.
      live.delete(targetUrl);
      changes.push({ endpoint: targetUrl, previous: [...prev], current: null });
    } else {
      if (prev !== undefined && samePins(prev, pins)) continue; // Same-value: no-op.
      live.set(targetUrl, [...pins]);
      changes.push({
        endpoint: targetUrl,
        previous: prev === undefined ? null : [...prev],
        current: [...pins],
      });
    }
  }
  return changes;
}

/**
 * Outbound private-CA trust bundle (WR-163).
 *
 * Validate a PEM CA bundle the way a constructor would: it must contain at
 * least one `CERTIFICATE` block whose DER parses as an X.509 certificate.
 * Throws `RangeError` on the first problem so a bad config fails at
 * startup, never mid-delivery.
 *
 * Semantics (see the `tlsCa` server option): the bundle is per-endpoint and
 * opt-in. It composes with — rather than replaces — the WR-21 pin
 * whitelist:
 *
 * - CA bundle only: Node verifies the server's chain against the bundle
 *   (`rejectUnauthorized` stays on). This is what makes private-PKI
 *   downstreams (self-signed roots, enterprise CAs) reachable — without
 *   the bundle, Node rejects the chain before any application byte is
 *   written (pinning deliberately cannot hook `checkServerIdentity`).
 * - Pins only: unchanged WR-21 behavior — the pin whitelist *replaces*
 *   PKI chain verification (`rejectUnauthorized: false`); the pin is the
 *   trust anchor.
 * - Both: layered — the chain is verified against the private bundle
 *   first, then the SPKI pin check runs on `secureConnect`. A chain
 *   failure and a pin mismatch stay distinguishable in the audit trail
 *   (TLS alert vs `TlsPinMismatchError`).
 */
export function assertValidCaBundle(pem: string): void {
  if (typeof pem !== "string" || pem.trim().length === 0) {
    throw new RangeError("TLS CA bundle must be a non-empty PEM string");
  }
  const blocks = [...pem.matchAll(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g)];
  if (blocks.length === 0) {
    throw new RangeError("TLS CA bundle contains no PEM CERTIFICATE block");
  }
  for (const block of blocks) {
    const b64 = block[1].replace(/\s+/g, "");
    if (b64.length === 0 || !/^[A-Za-z0-9+/=]+$/.test(b64)) {
      throw new RangeError("TLS CA bundle contains a CERTIFICATE block with invalid base64");
    }
    // Node's base64 decoder is lenient (never throws); the charset guard
    // above plus the DER parse below are the real validation.
    const der = Buffer.from(b64, "base64");
    if (der.length === 0) {
      throw new RangeError("TLS CA bundle contains an empty CERTIFICATE block");
    }
    try {
      // The constructor throws on unparseable DER — a garbled block must
      // fail at config time, not when the first delivery handshakes.
      new X509Certificate(der);
    } catch {
      throw new RangeError(
        "TLS CA bundle contains a CERTIFICATE block that is not a parseable X.509 certificate"
      );
    }
  }
}
