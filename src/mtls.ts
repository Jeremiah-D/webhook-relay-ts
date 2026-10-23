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

/**
 * WR-198: target patterns for `tlsClientCerts` keys. Exact `targetUrl`
 * keys keep the WR-36 behavior; the two new kinds pick an identity for
 * every endpoint that matches instead of one endpoint each:
 *
 * - wildcard: a `*.hostname` key (e.g. `*.example.com`) matches exactly
 *   one DNS label under it (`hooks.example.com` matches,
 *   `example.com` and `a.b.example.com` do not — RFC 4592 wildcard
 *   semantics, port- and scheme-agnostic);
 * - path prefix: a key that is a URL with a non-`/` path (e.g.
 *   `https://api.example.com/v1`) matches any target URL under it at a
 *   path-segment boundary (`https://api.example.com/v1/hooks` matches,
 *   `https://api.example.com/v10/x` does not).
 *
 * Resolution priority is exact > wildcard > path prefix > (no identity).
 * Among several matching path prefixes the longest wins. This is
 * orthogonal to WR-73's wildcard-domain *allowlist* (outbound target
 * filtering): that gate decides whether a target may be reached at all,
 * this one selects which client identity the handshake presents.
 */
export type TlsClientCertTargetPatternKind = "exact" | "wildcard" | "prefix";

const WILDCARD_LABEL = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/i;

/**
 * Validate a `tlsClientCerts` config key the way a constructor would: it
 * must be a wildcard `*.hostname` pattern or a parseable `http:`/`https:`
 * URL. Anything else (a bare hostname, a `*foo.com` glob, a key with a
 * path in a wildcard, a non-URL string) throws `RangeError` at startup —
 * a typo in the identity selector fails before the first delivery, never
 * as a silently-uncertified handshake at 3am.
 */
export function assertValidClientCertTargetKey(key: string, label: string): void {
  if (typeof key !== "string" || key === "") {
    throw new RangeError(`${label}: TLS client certificate target key must be a non-empty string`);
  }
  if (key.startsWith("*.")) {
    const rest = key.slice(2);
    if (rest === "" || rest.includes("/") || rest.includes(":") || rest.includes("?") || rest.includes("#")) {
      throw new RangeError(
        `${label}: wildcard target key ${JSON.stringify(key)} must be "*.hostname" with no port or path`
      );
    }
    const labels = rest.toLowerCase().split(".");
    if (labels.some((l) => !WILDCARD_LABEL.test(l))) {
      throw new RangeError(
        `${label}: wildcard target key ${JSON.stringify(key)} holds an invalid hostname`
      );
    }
    return;
  }
  if (key.startsWith("*")) {
    throw new RangeError(
      `${label}: wildcard target key ${JSON.stringify(key)} must start with "*." (e.g. "*.example.com")`
    );
  }
  let url: URL;
  try {
    url = new URL(key);
  } catch {
    throw new RangeError(
      `${label}: TLS client certificate target key ${JSON.stringify(key)} must be a "*.hostname" wildcard or an absolute http(s) URL`
    );
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new RangeError(
      `${label}: TLS client certificate target key ${JSON.stringify(key)} must use http: or https:`
    );
  }
  if (url.hostname === "") {
    throw new RangeError(
      `${label}: TLS client certificate target key ${JSON.stringify(key)} must have a hostname`
    );
  }
}

/** True when the target URL's path is under the pattern's path at a segment boundary. */
function pathPrefixMatches(pattern: string, target: string): boolean {
  if (!target.startsWith(pattern)) return false;
  if (target.length === pattern.length) return true;
  const next = target[pattern.length];
  return next === "/" || next === "?" || next === "#";
}

/**
 * WR-198: resolve the mTLS client identity for a delivery target. Keys of
 * `tlsClientCerts` may be an exact `targetUrl`, a `*.hostname` wildcard,
 * or a path-prefix URL (see the type doc above); priority is
 * exact > wildcard > longest-matching path prefix. Returns `undefined`
 * when nothing matches — the endpoint keeps the pre-WR-198 "no client
 * certificate" behavior. Pure function, safe to call per attempt.
 */
export function resolveClientCertTarget(
  tlsClientCerts: Record<string, TlsClientCert> | undefined,
  targetUrl: string
): TlsClientCert | undefined {
  if (tlsClientCerts === undefined) return undefined;
  const exact = tlsClientCerts[targetUrl];
  if (exact !== undefined) return exact;
  let hostname: string | undefined;
  try {
    hostname = new URL(targetUrl).hostname.toLowerCase();
  } catch {
    return undefined;
  }
  let bestPrefix: TlsClientCert | undefined;
  let bestPrefixLen = -1;
  for (const [key, cert] of Object.entries(tlsClientCerts)) {
    if (key.startsWith("*.")) {
      const suffix = key.slice(1).toLowerCase(); // ".example.com"
      if (hostname.endsWith(suffix) && hostname.length > suffix.length) {
        const label = hostname.slice(0, -suffix.length);
        if (!label.includes(".")) return cert; // one label only
      }
      continue;
    }
    // A key that is a URL with a non-"/" path is a path-prefix pattern;
    // a key with an empty path is exact-only (handled above).
    let keyUrl: URL;
    try {
      keyUrl = new URL(key);
    } catch {
      continue;
    }
    if (keyUrl.pathname !== "/" && keyUrl.pathname !== "") {
      if (pathPrefixMatches(key, targetUrl) && key.length > bestPrefixLen) {
        bestPrefix = cert;
        bestPrefixLen = key.length;
      }
    }
  }
  return bestPrefix;
}
