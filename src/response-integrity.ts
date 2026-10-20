/**
 * Downstream `Content-Digest` integrity verification (WR-168).
 *
 * An RFC 9530 subset: the relay verifies the downstream's
 * `Content-Digest` response header against the received body, using the
 * `sha-256` and `sha-512` hash algorithms only. The digest is computed
 * over the body the relay actually processes — i.e. after the WR-62
 * content-encoding decode, when the endpoint negotiated response
 * compression — matching what the WR-37 validators and the audit
 * summary see.
 *
 * Semantics (fail-closed, like the WR-37/WR-118 response checks):
 *
 * - no `Content-Digest` header → no opinion; the delivery resolves
 *   exactly as before (the guard is opt-in per endpoint, but a guarded
 *   endpoint's downstream is not required to send the header).
 * - the header lists a supported algorithm → the relay verifies it. The
 *   stronger algorithm wins when several are listed (`sha-512` over
 *   `sha-256`), mirroring cipher-suite negotiation. A mismatch is a
 *   *retryable* delivery failure (`IntegrityMismatchError`), which the
 *   audit trail records as `integrity_mismatch`.
 * - the header lists only unsupported algorithms (e.g. `md5`, `unixsum`)
 *   → the relay cannot establish integrity, so the delivery fails closed
 *   rather than resolving unchecked — an operator who opted into
 *   verification gets a loud failure, never a silent pass.
 * - a structurally malformed header → fails closed for the same reason:
 *   a downstream that emits garbage where a digest should be is not a
 *   downstream whose bytes can be trusted.
 *
 * The comparison uses `crypto.timingSafeEqual` — a network attacker who
 * can tamper with the body can also time the check, so the equality
 * test must not leak prefix information.
 *
 * Zero dependencies (`node:crypto` only).
 */

import { createHash, timingSafeEqual } from "node:crypto";

/** The digest algorithms this module verifies (the RFC 9530 subset). */
export const SUPPORTED_DIGEST_ALGORITHMS = ["sha-512", "sha-256"] as const;

export type SupportedDigestAlgorithm = (typeof SUPPORTED_DIGEST_ALGORITHMS)[number];

/** One parsed `Content-Digest` dictionary member. */
export interface ParsedContentDigest {
  /** The algorithm name exactly as it appeared in the header. */
  algorithm: string;
  /** The decoded digest bytes. */
  digest: Buffer;
}

/**
 * Structured delivery failure: the downstream's `Content-Digest` did
 * not match the received body (WR-168). Thrown by the default sender on
 * the 2xx path, so the retry queue classifies it `"retryable"` — the
 * tamper may be transient (a flapping middlebox), and the WR-10 breaker
 * sees it like any retryable failure. The numeric `statusCode` rides
 * along so the dead-letter `response_summary` stays honest.
 */
export class IntegrityMismatchError extends Error {
  /** The endpoint whose response failed verification. */
  readonly targetUrl: string;
  /** The algorithm that was checked (`"unsupported"` when none was). */
  readonly algorithm: string;
  /** The downstream HTTP status (always 2xx on this path). */
  readonly statusCode: number;

  constructor(targetUrl: string, algorithm: string, detail: string, statusCode: number) {
    super(
      `integrity_mismatch: Content-Digest ${algorithm} verification failed for ${targetUrl}: ${detail}`
    );
    this.name = "IntegrityMismatchError";
    this.targetUrl = targetUrl;
    this.algorithm = algorithm;
    this.statusCode = statusCode;
  }
}

const DIGEST_MEMBER = /^([a-z0-9-]+)=:([A-Za-z0-9+/=]+):$/;

/**
 * Parse an RFC 9530 `Content-Digest` dictionary header into its
 * members. Returns the members in header order. Throws `RangeError`
 * when the header is structurally malformed — a malformed digest
 * header is not a value the relay can verify, so it fails closed at
 * the sender rather than resolving unchecked.
 *
 * Accepts the common wire shape `sha-256=:base64:, sha-512=:base64:`.
 * Members carrying RFC 9530 parameters (e.g. `sha-256=:...:` with
 * trailing `;foo=bar`) are outside the subset and rejected as
 * malformed — no silent partial parsing.
 */
export function parseContentDigest(headerValue: string): ParsedContentDigest[] {
  const members = headerValue
    .split(",")
    .map((m) => m.trim())
    .filter((m) => m.length > 0);
  if (members.length === 0) {
    throw new RangeError("Content-Digest header is empty");
  }
  return members.map((member) => {
    const match = DIGEST_MEMBER.exec(member);
    if (match === null) {
      throw new RangeError(
        `malformed Content-Digest member ${JSON.stringify(member)} (expected "alg=:base64:")`
      );
    }
    const algorithm = match[1] as string;
    let digest: Buffer;
    try {
      digest = Buffer.from(match[2] as string, "base64");
    } catch {
      throw new RangeError(
        `malformed Content-Digest member ${JSON.stringify(member)}: not valid base64`
      );
    }
    if (digest.length === 0) {
      throw new RangeError(
        `malformed Content-Digest member ${JSON.stringify(member)}: empty digest`
      );
    }
    return { algorithm, digest };
  });
}

function isSupported(algorithm: string): algorithm is SupportedDigestAlgorithm {
  return (SUPPORTED_DIGEST_ALGORITHMS as readonly string[]).includes(algorithm);
}

/** The outcome of checking one response body against its header. */
export interface ContentDigestVerdict {
  /** True when the body is accepted (verified, or no header to check). */
  verified: boolean;
  /** The algorithm that was checked; `"unsupported"` when none was usable. */
  algorithm?: string;
  /** Present when `verified` is false — the human-readable reason. */
  reason?: string;
}

/**
 * Check a response body against its `Content-Digest` header value.
 *
 * - header missing/empty → `{ verified: true }` (no opinion).
 * - at least one supported algorithm listed → verify the strongest
 *   (`sha-512` first). Match → verified; mismatch → fail with the
 *   algorithm named.
 * - only unsupported algorithms → fail closed (`algorithm:
 *   "unsupported"`).
 * - structurally malformed header → fail closed.
 *
 * Never throws — a header the parser cannot understand is a failed
 * verification, not an exception, because the sender turns a failed
 * verdict into `IntegrityMismatchError` with the reason attached.
 */
export function verifyContentDigest(
  body: Buffer,
  headerValue: string | string[] | undefined
): ContentDigestVerdict {
  const raw = Array.isArray(headerValue) ? headerValue[0] : headerValue;
  if (raw === undefined || raw.trim() === "") {
    // No header — the guard has no opinion; the delivery resolves as
    // it always did.
    return { verified: true };
  }
  let members: ParsedContentDigest[];
  try {
    members = parseContentDigest(raw);
  } catch (err) {
    return {
      verified: false,
      algorithm: "unsupported",
      reason: `unparseable Content-Digest header: ${(err as Error).message}`,
    };
  }
  const supported = members.filter((m) => isSupported(m.algorithm));
  if (supported.length === 0) {
    const listed = members.map((m) => m.algorithm).join(", ");
    return {
      verified: false,
      algorithm: "unsupported",
      reason: `no supported digest algorithm in Content-Digest (listed: ${listed}; supported: ${SUPPORTED_DIGEST_ALGORITHMS.join(", ")})`,
    };
  }
  // Strongest first — sha-512 before sha-256 (SUPPORTED list order).
  supported.sort(
    (a, b) =>
      SUPPORTED_DIGEST_ALGORITHMS.indexOf(a.algorithm as SupportedDigestAlgorithm) -
      SUPPORTED_DIGEST_ALGORITHMS.indexOf(b.algorithm as SupportedDigestAlgorithm)
  );
  const chosen = supported[0] as ParsedContentDigest;
  const nodeAlgorithm = chosen.algorithm === "sha-512" ? "sha512" : "sha256";
  const computed = createHash(nodeAlgorithm).update(body).digest();
  if (computed.length === chosen.digest.length && timingSafeEqual(computed, chosen.digest)) {
    return { verified: true, algorithm: chosen.algorithm };
  }
  return {
    verified: false,
    algorithm: chosen.algorithm,
    reason: `${chosen.algorithm} digest does not match the received body`,
  };
}
