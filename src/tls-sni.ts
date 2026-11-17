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
 *   startup: SNI carries no IP addresses (RFC 6066), and Node rejects
 *   one outright from v25/26 (`ERR_INVALID_ARG_VALUE`).
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
 * The SNI `servername` to pass to `tls.connect` for a handshake to
 * `host`, or `undefined` when `host` is an IP literal. SNI carries no
 * IP addresses (RFC 6066): Node only warned about an IP servername up
 * to v24 (DEP0123) and rejects it outright with `ERR_INVALID_ARG_VALUE`
 * from Node 25/26 — CI's floating `lts/*` moved to Node 26 and the
 * `wss:` pin tests started throwing there. Omitting the option is also
 * Node's default behavior (SNI is sent for DNS names, skipped for IP
 * literals), so DNS hosts pass through unchanged.
 */
export function sniServernameForHost(host: string): string | undefined {
  return isIP(host) === 0 ? host : undefined;
}

/**
 * The effective TLS identity for one endpoint: an override entry exists
 * for its `targetUrl` and these are the wire values to use.
 */
export interface ResolvedTlsSniOverride {
  /**
   * The SNI servername to send, or `undefined` to keep Node's default.
   * `undefined` only happens when the entry sets no `servername` and the
   * target host is an IP literal — Node sends no SNI for IPs, and passing
   * one explicitly is rejected outright from Node 25/26.
   */
  servername: string | undefined;
  /** The ALPN protocols to offer, in preference order (a fresh copy). */
  alpnProtocols: string[];
}

/**
 * WR-436: a live revision patch for one endpoint's TLS SNI/ALPN
 * override (partial — omitted fields keep their live values; `null`
 * clears a field back to its default: `servername` to the target URL's
 * host, `alpnProtocols` to `["h2", "http/1.1"]`). Clearing every field
 * the entry holds deletes the entry: the endpoint falls back to the
 * URL host as SNI with the default ALPN.
 */
export interface TlsSniRevision {
  /**
   * New SNI `servername`, or `null` to clear it back to the target
   * URL's host. Must be a DNS name, never an IP literal, when present.
   */
  servername?: string | null;
  /**
   * New ALPN protocols in preference order, or `null` to clear them
   * back to `["h2", "http/1.1"]`. Must be a non-empty array of
   * non-empty protocol names when present.
   */
  alpnProtocols?: string[] | null;
}

/**
 * WR-436: the outcome of merging a {@link TlsSniRevision} onto the
 * live entry for one endpoint.
 */
export interface TlsSniRevisionChange {
  /**
   * The entry to store for the endpoint, or `undefined` to delete it
   * (the patch cleared every field the entry held). `undefined` with
   * `changed: false` means there was no entry and the patch changed
   * nothing — clearing fields that were never set is a no-op.
   */
  entry: TlsSniOverride | undefined;
  /** False when the patch leaves the live entry exactly as it was. */
  changed: boolean;
}

function sameStringList(a: readonly string[] | undefined, b: readonly string[] | undefined): boolean {
  if (a === undefined || b === undefined) return a === b;
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/**
 * WR-436: merge one live revision patch onto the stored entry for an
 * endpoint. Pure and unit-testable: the caller owns the live record
 * and only applies the returned `entry` when `changed` is true.
 * Validate-first-then-apply — the candidate entry is built and run
 * through {@link assertValidTlsSniOverride} before anything is
 * returned, so an illegal patch (IP-literal servername, empty ALPN)
 * throws `RangeError` and the live record is untouched.
 */
export function reviseTlsSniOverrideMap(
  prev: TlsSniOverride | undefined,
  patch: TlsSniRevision,
  label: string
): TlsSniRevisionChange {
  const candidate: TlsSniOverride = { ...(prev ?? {}) };
  if (patch.servername !== undefined) {
    if (patch.servername === null) delete candidate.servername;
    else candidate.servername = patch.servername;
  }
  if (patch.alpnProtocols !== undefined) {
    if (patch.alpnProtocols === null) delete candidate.alpnProtocols;
    else candidate.alpnProtocols = [...patch.alpnProtocols];
  }
  assertValidTlsSniOverride(candidate, label);
  const same =
    prev !== undefined &&
    prev.servername === candidate.servername &&
    sameStringList(prev.alpnProtocols, candidate.alpnProtocols);
  if (same) return { entry: prev, changed: false };
  const empty = candidate.servername === undefined && candidate.alpnProtocols === undefined;
  if (empty) return { entry: undefined, changed: prev !== undefined };
  return { entry: candidate, changed: true };
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
