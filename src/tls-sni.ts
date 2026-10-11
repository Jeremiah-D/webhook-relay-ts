import { isIP } from "node:net";
import { createHash } from "node:crypto";

/**
 * Per-endpoint outbound TLS SNI/ALPN overrides (WR-60).
 *
 * Each endpoint (a delivery `targetUrl`) can override the TLS ClientHello
 * identity it is delivered with:
 *
 * - `servername`: the SNI `servername` sent in the ClientHello. Defaults
 *   to the target URL's host — the CDN / multi-tenant-fronting use case
 *   sets it explicitly, so the relay can connect to one fronting host
 *   while presenting a different name (and, conversely, avoid leaking the
 *   real backend host in the default SNI). An IP literal is rejected at
 *   startup: SNI carries no IP addresses (RFC 6066), and Node would only
 *   warn and ignore it.
 * - `alpnProtocols`: the ALPN protocols offered in the ClientHello, in
 *   preference order. Defaults to `["h2", "http/1.1"]`. Endpoints without
 *   an entry keep the exact current behavior — no `servername` and no
 *   `ALPNProtocols` are set on the request, so Node's defaults apply
 *   untouched (zero behavior change when the option is not configured).
 *
 * What the override does *not* change: certificate verification still
 * anchors on the target URL's host (or the WR-21 pin whitelist when pins
 * are configured for the endpoint) — the override only changes the
 * SNI/ALPN wire values, it never weakens trust. The pin check runs on the
 * socket that was handshaked with the effective servername, and the
 * keep-alive pool (`src/keepalive.ts`) plus the H2 session pool
 * (`src/http2.ts`) key agents/sessions by the effective TLS identity, so
 * a connection handshaked with one SNI can never serve an endpoint
 * configured with a different one.
 *
 * Composition: WR-21 (pinning — pin verification sees the overridden-SNI
 * connection), WR-36 (mTLS client certificates ride the same handshake),
 * WR-42 (H2 sessions are keyed per TLS identity and pass the override to
 * `http2.connect`), WR-27 (proxied endpoints: the TLS handshake runs over
 * the CONNECT tunnel with the overridden SNI/ALPN). Applies to `https:`
 * targets only; entry keys for other schemes are rejected at startup.
 *
 * Zero dependencies (`node:net` + `node:crypto` only).
 */

/**
 * One endpoint's TLS identity override, keyed by exact delivery
 * `targetUrl`. Both fields are optional — `{}` is a valid entry meaning
 * "bind this endpoint to its default TLS identity explicitly".
 */
export interface TlsSniOverride {
  /**
   * SNI `servername` for the ClientHello. Defaults to the target URL's
   * host. Must be a DNS name, never an IP literal.
   */
  servername?: string;
  /**
   * ALPN protocols offered in the ClientHello, in preference order.
   * Defaults to `["h2", "http/1.1"]`. Must be a non-empty array of
   * non-empty protocol names.
   */
  alpnProtocols?: string[];
}

/**
 * The ALPN offer used when an endpoint has an override entry but no
 * explicit `alpnProtocols`. Offering `h2` first is harmless on the
 * HTTP/1.1 path — the agent ignores the negotiated protocol and proceeds
 * with HTTP/1.1 — and it is exactly what the H2 session path needs.
 */
export const DEFAULT_TLS_ALPN_PROTOCOLS: readonly string[] = ["h2", "http/1.1"];

/**
 * The effective TLS identity for one endpoint: an override entry exists
 * for its `targetUrl` and these are the wire values to use.
 */
export interface ResolvedTlsSniOverride {
  /**
   * The SNI servername to send, or `undefined` to keep Node's default.
   * `undefined` only happens when the entry sets no `servername` and the
   * target host is an IP literal — Node sends no SNI for IPs, and passing
   * one explicitly would only trigger a deprecation warning.
   */
  servername: string | undefined;
  /** The ALPN protocols to offer, in preference order (a fresh copy). */
  alpnProtocols: string[];
}

/**
 * Validate one override entry the way a constructor would. Throws
 * `RangeError` on the first problem so a bad config fails at startup,
 * never mid-handshake.
 */
export function assertValidTlsSniOverride(override: unknown, label: string): void {
  if (typeof override !== "object" || override === null || Array.isArray(override)) {
    throw new RangeError(
      `${label}: TLS SNI override must be an object { servername?, alpnProtocols? }`
    );
  }
  const { servername, alpnProtocols } = override as TlsSniOverride;
  if (servername !== undefined) {
    if (typeof servername !== "string" || servername.trim() === "") {
      throw new RangeError(`${label}: 'servername' must be a non-empty string`);
    }
    if (isIP(servername.trim()) !== 0) {
      throw new RangeError(
        `${label}: 'servername' must be a DNS name, not an IP literal (SNI carries no IP addresses)`
      );
    }
  }
  if (alpnProtocols !== undefined) {
    if (!Array.isArray(alpnProtocols) || alpnProtocols.length === 0) {
      throw new RangeError(`${label}: 'alpnProtocols' must be a non-empty array of protocol names`);
    }
    for (const p of alpnProtocols) {
      if (typeof p !== "string" || p.trim() === "") {
        throw new RangeError(`${label}: 'alpnProtocols' entries must be non-empty strings`);
      }
    }
  }
}

/**
 * Resolve the effective TLS identity for a delivery target. Returns
 * `undefined` when `overrides` has no entry for the exact `targetUrl` —
 * the caller then sets nothing and the endpoint keeps the exact current
 * behavior. Otherwise returns the entry with `servername` defaulted to
 * the target host (Node's default for IP literals: no SNI) and
 * `alpnProtocols` defaulted to {@link DEFAULT_TLS_ALPN_PROTOCOLS}.
 */
export function resolveTlsSniOverride(
  targetUrl: string,
  url: URL,
  overrides?: Record<string, TlsSniOverride>
): ResolvedTlsSniOverride | undefined {
  const entry = overrides?.[targetUrl];
  if (entry === undefined) return undefined;
  const servername =
    entry.servername ?? (isIP(url.hostname) !== 0 ? undefined : url.hostname);
  return { servername, alpnProtocols: [...(entry.alpnProtocols ?? DEFAULT_TLS_ALPN_PROTOCOLS)] };
}

/**
 * Pool-key fragment binding an agent/session to one effective TLS
 * identity: SHA-256 over the effective servername and ALPN list,
 * truncated to 16 hex chars — the same binding style as the pin and
 * client-cert fragments. Two endpoints with the same effective identity
 * share the fragment (and may share connections); any difference gets a
 * fresh agent/session, so a connection handshaked with one SNI can never
 * serve an endpoint configured with another.
 */
export function tlsSniPoolKeyFragment(override: ResolvedTlsSniOverride): string {
  return `|sni:${createHash("sha256")
    .update(`${override.servername ?? ""}\n${override.alpnProtocols.join(",")}`)
    .digest("hex")
    .slice(0, 16)}`;
}
