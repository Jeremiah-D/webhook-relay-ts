import type { Verifier } from "./verify.ts";

/**
 * Inbound signature algorithm negotiation (WR-138).
 *
 * Upstreams name the algorithm they signed with in the
 * `x-signature-alg` header; the relay picks the matching verifier from
 * the operator-configured allowlist instead of always using the global
 * default. This lets one relay front producers that sign differently —
 * e.g. HMAC-SHA256 for a legacy PSP and Ed25519 for a Solana program's
 * callbacks — without weakening either of them.
 */

/** The inbound header that names the signature algorithm the upstream used. */
export const SIGNATURE_ALG_HEADER = "x-signature-alg";

/** Algorithm names the negotiation layer understands. */
export const KNOWN_SIGNATURE_ALGS = ["hmac-sha256", "ed25519"] as const;

/** One entry in the algorithm allowlist. */
export interface SignatureAlgorithmRule {
  /**
   * The negotiated name, as carried by the `x-signature-alg` header:
   * `"hmac-sha256"` or `"ed25519"` (matched case-insensitively).
   */
  alg: string;
  /**
   * The verifier that authenticates this algorithm's signatures, e.g.
   * `new Ed25519Verifier(pem)`. For `"hmac-sha256"` this is typically a
   * `HmacSha256Verifier` (or `RotatingHmacVerifier`) over the shared
   * secret.
   */
  verifier: Verifier;
}

/**
 * Normalize a raw `x-signature-alg` header value: trim + lowercase.
 * Returns `undefined` for a missing, non-string, or blank value — the
 * caller treats that as "no negotiation requested" and keeps the legacy
 * default verifier. Never throws.
 */
export function normalizeSignatureAlg(raw: unknown): string | undefined {
  if (typeof raw !== "string") return undefined;
  const alg = raw.trim().toLowerCase();
  return alg === "" ? undefined : alg;
}

/**
 * Validate the algorithm allowlist at startup. Throws RangeError on a
 * non-array, an empty array, an unknown algorithm name, a duplicate
 * name, or a verifier without a usable name/verify — fail fast, never
 * mid-request.
 */
export function assertValidSignatureAlgorithmRules(
  rules: SignatureAlgorithmRule[] | undefined
): void {
  if (rules === undefined) return;
  if (!Array.isArray(rules) || rules.length === 0) {
    throw new RangeError(
      "signatureAlgorithms: expected a non-empty array of { alg, verifier } rules"
    );
  }
  const known = KNOWN_SIGNATURE_ALGS as readonly string[];
  const seen = new Set<string>();
  rules.forEach((rule, i) => {
    const where = `signatureAlgorithms[${i}]`;
    const alg =
      rule && typeof rule.alg === "string" ? rule.alg.trim().toLowerCase() : "";
    if (!known.includes(alg)) {
      throw new RangeError(
        `${where}: alg must be one of ${KNOWN_SIGNATURE_ALGS.join(", ")}`
      );
    }
    if (seen.has(alg)) {
      throw new RangeError(`${where}: duplicate alg "${alg}"`);
    }
    seen.add(alg);
    const v = rule.verifier;
    if (
      !v ||
      typeof v.name !== "string" ||
      v.name === "" ||
      typeof v.verify !== "function"
    ) {
      throw new RangeError(
        `${where}: verifier needs a non-empty name and a verify method`
      );
    }
  });
}

/**
 * Resolve the verifier for a negotiated algorithm name: the first
 * matching rule's verifier, or `undefined` when the name is not
 * allowlisted (the caller answers 400 `unsupported_algorithm`) or no
 * rules are configured. Never throws.
 */
export function selectSignatureAlgorithmVerifier(
  alg: string,
  rules: SignatureAlgorithmRule[] | undefined
): Verifier | undefined {
  if (rules === undefined || typeof alg !== "string") return undefined;
  const wanted = alg.trim().toLowerCase();
  const rule = rules.find(
    (r) => typeof r.alg === "string" && r.alg.trim().toLowerCase() === wanted
  );
  return rule?.verifier;
}
