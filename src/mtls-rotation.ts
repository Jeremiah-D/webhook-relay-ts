import { assertValidClientCert, type TlsClientCert } from "./mtls.ts";

/**
 * Outbound mTLS client certificate rotation (WR-89).
 *
 * A client certificate is an identity with an expiry date and a
 * provisioning lag: when the relay's identity must change, flipping it
 * atomically bricks every delivery until the downstream trusts the new
 * certificate — and "the downstream trusts it" is verified by the
 * downstream's operators on their own schedule, not the relay's. This
 * module gives one endpoint several coexisting client identities:
 *
 *   - the *primary* — the new certificate, declared first, presented on
 *     every new handshake;
 *   - *retired* certificates — the old identities, each stamped with
 *     `retiredAtMs`, still eligible as handshake *fallbacks* inside a
 *     grace window (default 24h, boundary inclusive, same as WR-20's
 *     signing-key grace and WR-81's E2EE grace).
 *
 * Rotation protocol, from the operator's side:
 *
 *   1. Provision the new certificate downstream (the downstream starts
 *      trusting it — or not yet; that is the point).
 *   2. Declare it first in `certificates`, mark the old one retired with
 *      `retiredAtMs` (ms epoch of the retirement).
 *   3. New handshakes present the new certificate. When a handshake
 *      fails in a way attributable to client-cert rejection (a fatal TLS
 *      alert, or a transport reset with no response received — the
 *      sender owns that classifier, see `isClientCertRejectedError` in
 *      `src/server.ts`), the same delivery attempt retries the handshake
 *      with each in-grace retired certificate, newest first. The first
 *      identity the downstream accepts wins the connection.
 *   4. The id of the certificate actually used is recorded as
 *      `clientCertId` on the `delivered` / `dead_letter` audit events
 *      (and in `response_summary`), so the operator watches the old
 *      identity's traffic drain to zero in the audit trail.
 *   5. Once `isRotationComplete()` — every retired certificate's grace
 *      window has fully elapsed — the operator removes the retired
 *      entries from the config. The rotation is done.
 *
 * Fail-fast: an empty set, duplicate ids, unparsable PEMs, a missing
 * primary (every entry retired), or a negative grace all throw
 * `RangeError` at construction — a broken rotation fails before the
 * first delivery, never mid-handshake at 3am.
 *
 * Composition with the existing outbound machinery:
 * - WR-36 (single client identity): orthogonal — an endpoint uses
 *   either `tlsClientCerts` or rotation, never both (the sender rejects
 *   the combination at startup). The single-identity path is untouched.
 * - WR-21 (pinning): pins verify the *server's* identity, the client
 *   cert proves the *relay's* — the fallback handshake runs under the
 *   same pin whitelist; a pin mismatch never falls back (it is not
 *   about the client identity).
 * - WR-24 (keep-alive pool) / WR-42 (H2 sessions): agents and sessions
 *   are keyed per *actually used* certificate identity
 *   (`|cert:<identity>`), so a connection authenticated as the new
 *   identity can never serve a fallback delivery and vice versa.
 * - WR-73 (cert-expiry): retired certificates whose grace window has
 *   fully elapsed are skipped by the config-load expiry check — they
 *   can never authenticate again, so warning about them would be
 *   unactionable noise. In-grace retired certificates are still
 *   checked: a fallback identity about to expire is actionable.
 *
 * Zero dependencies (`node:crypto` via `src/mtls.ts` only). The clock is
 * injectable for deterministic tests.
 */

/** One client identity in a WR-89 rotation set. */
export interface RotatingClientCert {
  /**
   * Stable operator-chosen key id, surfaced as `clientCertId` in
   * delivery audits and the response summary — the handle the operator
   * greps for while watching a rotation drain.
   */
  id: string;
  /** PEM-encoded client certificate (chain), as a string. */
  cert: string;
  /** PEM-encoded private key, as a string. */
  key: string;
  /** Passphrase for an encrypted private key, when needed. */
  passphrase?: string;
  /**
   * Millisecond epoch at which this certificate was retired. A retired
   * certificate is never used for *new* handshakes, but stays eligible
   * as a handshake fallback inside the grace window — the downstream
   * may not trust the new certificate yet. Undefined means still in
   * service (a candidate for primary).
   */
  retiredAtMs?: number;
}

/** Options for {@link RotatingClientCertSet}. */
export interface RotatingClientCertConfig {
  /**
   * The certificate set: a non-empty array with unique non-empty ids.
   * The new certificate must be declared first — the primary is the
   * first non-retired entry in declaration order; retired entries
   * carry `retiredAtMs`.
   */
  certificates: RotatingClientCert[];
  /**
   * Grace period in ms during which a retired certificate stays
   * eligible as a handshake fallback. Default: 86_400_000 (24h), same
   * as WR-20/WR-81. Must be a non-negative finite number.
   */
  graceMs?: number;
  /** Clock source for retirement checks; defaults to Date.now. Injectable for tests. */
  nowMs?: () => number;
}

/** Default grace period for retired client certificates: 24h, matching WR-20/WR-81. */
export const DEFAULT_CLIENT_CERT_GRACE_MS = 86_400_000;

/** One compiled entry: the validated PEM pair plus its retirement stamp. */
interface CompiledRotatingClientCert {
  id: string;
  cert: TlsClientCert;
  retiredAtMs?: number;
}

/** A primary or fallback handshake candidate: the identity plus its audit id. */
export interface ClientCertCandidate {
  /** The operator-chosen id, audited as `clientCertId` when this candidate is used. */
  id: string;
  /** The PEM identity presented on the handshake. */
  cert: TlsClientCert;
}

/**
 * One endpoint's rotating mTLS client identities. Constructed once at
 * startup (the sender holds the compiled set — rebuilding it per
 * request would silently restart the grace window, the WR-67 lesson).
 * All validation throws `RangeError`.
 */
export class RotatingClientCertSet {
  private readonly certs: CompiledRotatingClientCert[];
  private readonly primaryCert: CompiledRotatingClientCert;
  private readonly graceMs: number;
  private readonly nowMs: () => number;

  constructor(config: RotatingClientCertConfig) {
    const certificates = (config as RotatingClientCertConfig | undefined)?.certificates;
    if (!Array.isArray(certificates) || certificates.length === 0) {
      throw new RangeError("RotatingClientCertSet: `certificates` must be a non-empty array");
    }
    const seen = new Set<string>();
    this.certs = certificates.map((c, i) => {
      const where = `certificates[${i}]`;
      if (c === null || typeof c !== "object") {
        throw new RangeError(`RotatingClientCertSet: ${where} must be an object`);
      }
      if (typeof c.id !== "string" || c.id === "") {
        throw new RangeError(`RotatingClientCertSet: ${where} needs a non-empty string id`);
      }
      if (seen.has(c.id)) {
        throw new RangeError(`RotatingClientCertSet: duplicate certificate id "${c.id}"`);
      }
      seen.add(c.id);
      if (
        c.retiredAtMs !== undefined &&
        (!Number.isFinite(c.retiredAtMs) || c.retiredAtMs < 0)
      ) {
        throw new RangeError(
          `RotatingClientCertSet: certificate "${c.id}" has an invalid retiredAtMs (must be a non-negative epoch ms)`
        );
      }
      // Reuse WR-36's parse check: a garbage cert/key pair fails here, at
      // startup — never mid-handshake.
      const cert: TlsClientCert = {
        cert: c.cert,
        key: c.key,
        ...(c.passphrase !== undefined ? { passphrase: c.passphrase } : {}),
      };
      assertValidClientCert(cert, `RotatingClientCertSet certificate "${c.id}"`);
      return { id: c.id, cert, retiredAtMs: c.retiredAtMs };
    });
    // The new certificate is declared first; the primary is the first
    // non-retired entry in declaration order. A set with no live
    // certificate is a guaranteed outage on every delivery — fail here,
    // not on the first handshake.
    const primary = this.certs.find((c) => c.retiredAtMs === undefined);
    if (primary === undefined) {
      throw new RangeError(
        "RotatingClientCertSet: no non-retired certificate — at least one entry must stay in service as the primary"
      );
    }
    this.primaryCert = primary;
    const graceMs = config.graceMs ?? DEFAULT_CLIENT_CERT_GRACE_MS;
    if (!Number.isFinite(graceMs) || graceMs < 0) {
      throw new RangeError("RotatingClientCertSet: `graceMs` must be a non-negative finite number");
    }
    this.graceMs = graceMs;
    this.nowMs = config.nowMs ?? Date.now;
  }

  /**
   * The certificate new handshakes present: the first non-retired entry
   * in declaration order. Never throws — the constructor guarantees a
   * live primary.
   */
  primary(): ClientCertCandidate {
    return { id: this.primaryCert.id, cert: this.primaryCert.cert };
  }

  /** Whether the certificate still counts as in-rotation: in service, or retired inside the grace window. */
  private isActive(c: CompiledRotatingClientCert): boolean {
    if (c.retiredAtMs === undefined) return true;
    // Grace boundary is inclusive, same as WR-20/WR-81: exactly
    // `graceMs` old is still in rotation, 1ms older is out.
    return this.nowMs() - c.retiredAtMs <= this.graceMs;
  }

  /**
   * Retired certificates still inside their grace window, newest first —
   * the handshake fallback order. The sender tries them only when the
   * primary's handshake fails in a way attributable to client-cert
   * rejection; a fallback that also fails ends the candidate loop — the
   * retry layer, not this loop, decides what happens next.
   */
  fallbacks(): ClientCertCandidate[] {
    return this.certs
      .filter((c) => c.retiredAtMs !== undefined && this.isActive(c))
      .sort((a, b) => (b.retiredAtMs as number) - (a.retiredAtMs as number))
      .map((c) => ({ id: c.id, cert: c.cert }));
  }

  /** Ids of the certificates still in rotation, in declaration order. */
  activeCertIds(): string[] {
    return this.certs.filter((c) => this.isActive(c)).map((c) => c.id);
  }

  /** True while any retired certificate is still inside its grace window — the rotation is in flight. */
  rotationInProgress(): boolean {
    return this.certs.some((c) => c.retiredAtMs !== undefined && this.isActive(c));
  }

  /**
   * Whether the rotation is complete: at least one certificate was
   * retired and every retired certificate's grace window has fully
   * elapsed. The operator then removes the retired entries from the
   * endpoint's config — the rotation is done.
   */
  isRotationComplete(): boolean {
    return this.certs.some((c) => c.retiredAtMs !== undefined) && !this.rotationInProgress();
  }

  /**
   * Certificates that still deserve a WR-73 expiry warning: every
   * non-retired certificate plus retired ones still inside their grace
   * window (a fallback identity about to expire is actionable).
   * Ordered fallback-first with the primary last, so the monitor's
   * per-endpoint gauge — one slot per endpoint — settles on the
   * primary, the identity doing the work, while each expiring
   * certificate still gets its own edge-triggered alert. A retired
   * certificate whose grace window has fully elapsed is excluded: it
   * can never authenticate again, so warning about it would be
   * unactionable noise.
   */
  certificatesForExpiryWatch(): ClientCertCandidate[] {
    const retiredInGrace = this.certs
      .filter((c) => c.retiredAtMs !== undefined && this.isActive(c))
      .sort((a, b) => (b.retiredAtMs as number) - (a.retiredAtMs as number));
    const live = this.certs.filter((c) => c.retiredAtMs === undefined);
    return [...retiredInGrace, ...live].map((c) => ({ id: c.id, cert: c.cert }));
  }
}
