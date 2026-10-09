/**
 * Inbound API version routing (WR-33).
 *
 * Upstreams evolve: a payment provider ships `v2` webhooks with a
 * reshaped payload while old senders still POST `v1`. Rather than forcing
 * every downstream consumer to speak every dialect, the relay routes on a
 * version prefix in the inbound path (`/v1/...`, `/v2/...`) and runs the
 * payload through a pluggable {@link ApiVersionAdapter} that reshapes it
 * into the *current* schema before anything downstream sees it.
 *
 * The adapter runs on the *verified* payload: signature verification (on
 * the raw body the sender actually signed) happens first, then
 * adaptation, then dedup / enqueue. That ordering has two consequences
 * worth knowing:
 *
 * 1. Dedup hashes the *adapted* payload, so the same business event sent
 *    once as `v1` and once as `v2` suppresses to a single delivery.
 * 2. Headers pass through unchanged — the adapted payload goes out with
 *    the original `x-signature` header. Downstream should verify
 *    `x-relay-signature` (WR-26, computed over the forwarded body), not
 *    the passthrough upstream signature.
 *
 * Paths without a registered version prefix are untouched: the relay
 * behaves exactly as before, and no `version` field appears anywhere.
 */

/** Context handed to a version adapter. */
export interface VersionAdaptContext {
  /** Version label of the matched route, e.g. `"v1"`. */
  version: string;
  /** Full inbound request path, version prefix included. */
  path: string;
  /** Trace ID assigned to this request. */
  traceId: string;
}

/**
 * Reshapes one API version's payload into the current schema. `adapt`
 * receives the verified raw body and must return the adapted body; it may
 * throw to reject the request (the server answers 400 and audits
 * `rejected` with reason `version_adapt_failed` — an unadaptable payload
 * is a sender bug, never a delivery problem, so it never touches the
 * retry queue). Adapters must be synchronous and total on well-formed
 * input: they run on the request path.
 */
export interface ApiVersionAdapter {
  /** Version label recorded in audit events and metrics, e.g. `"v1"`. */
  version: string;
  adapt(payload: Buffer, context: VersionAdaptContext): Buffer;
}

/** One version prefix and the adapter that owns it. */
export interface ApiVersionRoute {
  /**
   * Path prefix owned by this version, e.g. `"/v1"`. A request matches
   * when its path equals the prefix or starts with `prefix + "/"` — so
   * `/v1` matches `/v1` and `/v1/hooks/stripe` but never `/v10`. When
   * several prefixes match, the longest wins.
   */
  prefix: string;
  adapter: ApiVersionAdapter;
}

/** Inbound API version routing config, embedded in `RelayServerOptions`. */
export interface ApiVersionOptions {
  routes: ApiVersionRoute[];
}

/**
 * Route table validation. Throws `RangeError` at startup so a bad route
 * can never fail a request mid-flight.
 */
export function assertValidVersionRoutes(routes: ApiVersionRoute[]): void {
  if (!Array.isArray(routes) || routes.length === 0) {
    throw new RangeError("`versions.routes` must be a non-empty array");
  }
  const seen = new Set<string>();
  for (const route of routes) {
    if (typeof route !== "object" || route === null) {
      throw new RangeError("`versions.routes` entries must be objects");
    }
    const { prefix, adapter } = route;
    if (typeof prefix !== "string" || !prefix.startsWith("/") || prefix.length < 2) {
      throw new RangeError(
        `version route prefix must be a string starting with "/" (e.g. "/v1"), got ${JSON.stringify(prefix)}`
      );
    }
    if (prefix.endsWith("/")) {
      throw new RangeError(
        `version route prefix must not end with "/", got ${JSON.stringify(prefix)}`
      );
    }
    if (seen.has(prefix)) {
      throw new RangeError(`duplicate version route prefix ${JSON.stringify(prefix)}`);
    }
    seen.add(prefix);
    if (typeof adapter !== "object" || adapter === null) {
      throw new RangeError(`version route ${prefix}: adapter must be an object`);
    }
    if (typeof adapter.version !== "string" || adapter.version === "") {
      throw new RangeError(`version route ${prefix}: adapter.version must be a non-empty string`);
    }
    if (typeof adapter.adapt !== "function") {
      throw new RangeError(`version route ${prefix}: adapter.adapt must be a function`);
    }
  }
}

/**
 * Matches inbound paths against the version route table (longest prefix
 * wins, segment-boundary matching only).
 */
export class ApiVersionRouter {
  private readonly routes: ApiVersionRoute[];

  constructor(routes: ApiVersionRoute[]) {
    // Fail fast at startup; a route table that throws mid-request is a bug.
    assertValidVersionRoutes(routes);
    // Longest prefix first so the first match is the winner.
    this.routes = [...routes].sort((a, b) => b.prefix.length - a.prefix.length);
  }

  /** The route owning `pathname`, or `undefined` when unversioned. */
  match(pathname: string): ApiVersionRoute | undefined {
    for (const route of this.routes) {
      if (pathname === route.prefix || pathname.startsWith(route.prefix + "/")) {
        return route;
      }
    }
    return undefined;
  }
}

/** One version's intake counters. */
export interface VersionCounters {
  accepted: number;
  rejected: number;
}

/**
 * Inbound intake counters by API version. Requests that matched no
 * version prefix are counted under `"none"` so the version mix is fully
 * visible. Renders to Prometheus exposition text; renders `""` when
 * nothing was recorded, keeping `GET /metrics` byte-identical for relays
 * that never enable versioning.
 */
export class VersionMetrics {
  private readonly counters = new Map<string, VersionCounters>();

  /** Record one intake for `version` (`"none"` for unversioned requests). */
  record(version: string, outcome: "accepted" | "rejected"): void {
    let c = this.counters.get(version);
    if (!c) {
      c = { accepted: 0, rejected: 0 };
      this.counters.set(version, c);
    }
    c[outcome] += 1;
  }

  /** Prometheus text exposition (0.0.4) of the counters; `""` when empty. */
  render(): string {
    if (this.counters.size === 0) return "";
    const esc = (v: string): string => v.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, '\\"');
    const lines: string[] = [
      "# HELP relay_inbound_version_total Inbound webhook intakes by API version and admission outcome.",
      "# TYPE relay_inbound_version_total counter",
    ];
    for (const [version, c] of this.counters) {
      const v = esc(version);
      lines.push(`relay_inbound_version_total{version="${v}",status="accepted"} ${c.accepted}`);
      lines.push(`relay_inbound_version_total{version="${v}",status="rejected"} ${c.rejected}`);
    }
    return lines.join("\n") + "\n";
  }
}
