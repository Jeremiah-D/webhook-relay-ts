import { createHash } from "node:crypto";
import { createSecureContext } from "node:tls";

/**
 * Outbound mTLS client certificates (WR-36).
 *
 * Each endpoint (a delivery `targetUrl`) can carry its own client identity:
 * a PEM-encoded certificate + private key, loaded in memory — the config
 * holds the PEM *strings*, never file paths, so rotation is a config
 * change and no secret ever has to live on disk next to the relay. During
 * the TLS handshake the relay presents this certificate, proving to the
 * downstream that the request really comes from this relay (the downstream
 * verifies it against whatever CA it trusts — typically with
 * `requestCert: true` + its own `ca` list).
 *
 * Off by default: endpoints without an entry send no client certificate,
 * exactly as before. Invalid values (empty cert/key, unparseable PEM)
 * throw `RangeError` at startup — a broken identity fails before the first
 * delivery, never mid-handshake at 3am.
 *
 * Composition with the existing outbound machinery:
 * - WR-21 (pinning): pins verify the *server's* identity, the client cert
 *   proves the *relay's* — the two compose on the same endpoint (the
 *   mTLS tests pin the fixture server cert for this reason).
 * - WR-24 (keep-alive pool): the pool keys agents by
 *   `(origin, proxy, pins, client-cert)` — one agent per
 *   `(origin, cert)` — so a connection authenticated as one identity can
 *   never serve an endpoint configured with a different one. A handshake
 *   that fails (wrong cert, server rejects) destroys the socket; the
 *   pool's checkout probe culls dead sockets, so a failed handshake's
 *   connection is never handed to another delivery.
 *
 * Zero dependencies (`node:crypto` only).
 */

/**
 * A client identity for one endpoint: PEM strings held in memory. The
 * `cert` is the PEM-encoded certificate chain (leaf first); `key` is the
 * PEM-encoded private key for it; `passphrase` unlocks an encrypted key.
 */
export interface TlsClientCert {
  /** PEM-encoded client certificate (chain), as a string. */
  cert: string;
  /** PEM-encoded private key, as a string. */
  key: string;
  /** Passphrase for an encrypted private key, when needed. */
  passphrase?: string;
}

/**
 * Validate a client identity the way a constructor would: a real object,
 * non-empty `cert`/`key` strings, a string `passphrase` when given, and —
 * the part that catches typos — the pair must actually build a TLS secure
 * context. Throws `RangeError` on the first problem.
 */
export function assertValidClientCert(cert: TlsClientCert, label: string): void {
  if (typeof cert !== "object" || cert === null) {
    throw new RangeError(`${label}: TLS client certificate must be an object`);
  }
  if (typeof cert.cert !== "string" || cert.cert.trim() === "") {
    throw new RangeError(`${label}: TLS client certificate 'cert' must be a non-empty PEM string`);
  }
  if (typeof cert.key !== "string" || cert.key.trim() === "") {
    throw new RangeError(`${label}: TLS client certificate 'key' must be a non-empty PEM string`);
  }
  if (cert.passphrase !== undefined && typeof cert.passphrase !== "string") {
    throw new RangeError(`${label}: TLS client certificate 'passphrase' must be a string`);
  }
  try {
    // Building the context is the cheapest real parse check: OpenSSL
    // rejects a garbage cert/key pair here, at config time.
    createSecureContext({ cert: cert.cert, key: cert.key, passphrase: cert.passphrase });
  } catch (err) {
    throw new RangeError(
      `${label}: invalid TLS client certificate/key PEM: ${(err as Error).message}`
    );
  }
}

/**
 * Stable identity string for pool keying: SHA-256 over the trimmed cert
 * PEM, truncated to 16 hex chars. Two endpoints sharing the exact same
 * identity share an agent; any difference (rotation included) gets a fresh
 * agent, so a rotated identity never rides a stale connection.
 */
export function clientCertIdentity(cert: TlsClientCert): string {
  return createHash("sha256").update(cert.cert.trim()).digest("hex").slice(0, 16);
}
