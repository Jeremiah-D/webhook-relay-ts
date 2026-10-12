/**
 * Outbound per-endpoint TLS minimum version (WR-74).
 *
 * Each endpoint (a delivery `targetUrl`) can carry a minimum TLS version —
 * `"1.2"` or `"1.3"`. The floor is enforced *observationally*: the
 * handshake runs at whatever the downstream negotiates (Node's own
 * default floor, TLS 1.2, still applies underneath), and on the socket's
 * `secureConnect` the sender compares the negotiated protocol against the
 * floor *before* a single payload byte is written. A negotiation below
 * the floor destroys the request with {@link TlsVersionRejectedError},
 * which fails the delivery attempt; the attempt then follows the normal
 * retry / dead-letter path and the rejection lands in the audit trail
 * (`tls_version_rejected`) plus `relay_tls_version_rejections_total`.
 *
 * Why observe instead of setting `minVersion` on the socket: with the
 * floor set on the TLS options, a below-floor downstream fails the
 * handshake with a generic OpenSSL error and the relay can never tell a
 * version rejection apart from any other handshake failure — the audit
 * event the operator asked for would never fire. Observing the
 * negotiated version keeps the rejection precise and attributable.
 *
 * The keep-alive pool binds the floor into its agent key (see
 * `OutboundConnectionPool.agentFor`), so a connection handshaked under
 * one floor can never serve an endpoint configured with another; the
 * HTTP/2 session pool does the same. Endpoints without a configured
 * floor keep the exact historical behavior (Node defaults).
 *
 * Zero dependencies (`node:crypto` is not even needed here).
 */

/** The outbound TLS versions an endpoint floor can name. */
export type MinTlsVersion = "1.2" | "1.3";

const TLS_VERSION_ORDER: readonly string[] = ["1.2", "1.3"];

/**
 * Validate a configured floor the way a constructor would: only
 * `"1.2"` / `"1.3"` are accepted. Throws `RangeError` on anything else
 * so a bad config fails at startup, never mid-delivery.
 */
export function assertValidMinTlsVersion(value: unknown): asserts value is MinTlsVersion {
  if (value !== "1.2" && value !== "1.3") {
    throw new RangeError(`invalid minTlsVersion (expected "1.2" or "1.3"), got ${JSON.stringify(value)}`);
  }
}

/** Order-compare two `"major.minor"` version strings: -1, 0, or 1. */
export function compareTlsVersions(a: string, b: string): number {
  const rank = (v: string): number => {
    const i = TLS_VERSION_ORDER.indexOf(v);
    if (i !== -1) return i;
    // A future version (e.g. 1.4) sorts above every known floor — a
    // floor can never accidentally reject something newer than it knows.
    const m = /^(\d+)\.(\d+)$/.exec(v);
    if (m) return TLS_VERSION_ORDER.length + Number(m[1]) * 1000 + Number(m[2]);
    // Unparseable sorts below everything: unknown is never "at least".
    return -1;
  };
  const ra = rank(a);
  const rb = rank(b);
  return ra < rb ? -1 : ra > rb ? 1 : 0;
}

/**
 * Parse Node's `TLSSocket.getProtocol()` (`"TLSv1.2"`, `"TLSv1.3"`) into
 * the `"1.2"` / `"1.3"` form `compareTlsVersions` understands.
 * Returns `undefined` when the string is missing or unparseable.
 */
export function parseNegotiatedTlsVersion(protocol: string | undefined): string | undefined {
  if (typeof protocol !== "string") return undefined;
  const m = /^TLSv(\d+)\.(\d+)$/.exec(protocol.trim());
  if (!m) return undefined;
  return `${m[1]}.${m[2]}`;
}

/** The error a delivery fails with when the handshake negotiates below the endpoint's floor. */
export class TlsVersionRejectedError extends Error {
  /** The endpoint whose floor rejected the negotiated version. */
  readonly endpoint: string;
  /** What the handshake actually negotiated (`"TLSv1.2"`, …). */
  readonly negotiated: string;
  /** The configured floor. */
  readonly required: MinTlsVersion;

  constructor(endpoint: string, negotiated: string, required: MinTlsVersion) {
    super(
      `TLS version rejected for ${endpoint}: negotiated ${negotiated} is below the configured minimum TLS ${required}`
    );
    this.name = "TlsVersionRejectedError";
    this.endpoint = endpoint;
    this.negotiated = negotiated;
    this.required = required;
  }
}

/**
 * Enforce one endpoint's floor against the negotiated protocol string.
 * Returns the normalized negotiated version (`"1.2"`, …) when it meets
 * the floor; throws {@link TlsVersionRejectedError} otherwise. An
 * unparseable protocol fails closed — if the version cannot be
 * determined, the floor cannot be verified.
 */
export function assertTlsVersionMeetsFloor(
  endpoint: string,
  protocol: string | undefined,
  floor: MinTlsVersion
): string {
  const negotiated = parseNegotiatedTlsVersion(protocol);
  if (negotiated === undefined || compareTlsVersions(negotiated, floor) < 0) {
    throw new TlsVersionRejectedError(endpoint, protocol ?? "<unknown>", floor);
  }
  return negotiated;
}

/** One recorded floor rejection, for the audit hook. */
export interface TlsVersionRejection {
  endpoint: string;
  negotiatedVersion: string;
  requiredMinVersion: MinTlsVersion;
  at: number;
}

/**
 * Rejection accounting plus Prometheus exposition for the floor
 * (mirrors WR-73's `CertExpiryMonitor`): `recordRejection` counts per
 * (endpoint, negotiated version) and fires the audit hook; `render()`
 * emits `relay_tls_version_rejections_total{endpoint,version}` — an
 * empty string while nothing was rejected, so `GET /metrics` stays
 * byte-identical for relays that never configure a floor.
 */
export class TlsVersionMonitor {
  private readonly counts = new Map<string, { endpoint: string; version: string; n: number }>();
  private readonly hooks: { onRejected?: (r: TlsVersionRejection) => void };

  constructor(hooks: { onRejected?: (r: TlsVersionRejection) => void } = {}) {
    this.hooks = hooks;
  }

  recordRejection(endpoint: string, negotiatedVersion: string, requiredMinVersion: MinTlsVersion): void {
    const key = endpoint + "\u0000" + negotiatedVersion;
    const entry = this.counts.get(key);
    if (entry === undefined) {
      this.counts.set(key, { endpoint, version: negotiatedVersion, n: 1 });
    } else {
      entry.n += 1;
    }
    this.hooks.onRejected?.({ endpoint, negotiatedVersion, requiredMinVersion, at: Date.now() });
  }

  render(): string {
    if (this.counts.size === 0) return "";
    const lines = [
      "# HELP relay_tls_version_rejections_total Outbound deliveries rejected because the negotiated TLS version was below the endpoint's configured minimum.",
      "# TYPE relay_tls_version_rejections_total counter",
    ];
    const esc = (s: string): string => s.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
    for (const { endpoint, version, n } of [...this.counts.values()].sort(
      (a, b) => (a.endpoint < b.endpoint ? -1 : a.endpoint > b.endpoint ? 1 : a.version < b.version ? -1 : 1)
    )) {
      lines.push(`relay_tls_version_rejections_total{endpoint="${esc(endpoint)}",version="${esc(version)}"} ${n}`);
    }
    return lines.join("\n") + "\n";
  }
}
