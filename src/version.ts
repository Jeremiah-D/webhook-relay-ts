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
  /**
   * WR-144: opt-in sunset moment for this version — epoch milliseconds
   * or an ISO-8601 timestamp string. Once `Date.now()` reaches the
   * moment (inclusive), intakes matching this version are answered
   * `410 Gone` with the RFC 8594 `Sunset` header and audited as
   * `rejected` with reason `version_sunset`; they never enter the retry
   * queue. Absent means the version never sunsets (fully backward
   * compatible). Invalid values throw `RangeError` at startup.
   */
  sunsetAt?: number | string;
}

/** Inbound API version routing config, embedded in `RelayServerOptions`. */
export interface ApiVersionOptions {
  routes: ApiVersionRoute[];
}

/**
 * Normalize a `sunsetAt` value to epoch milliseconds. Throws
 * `RangeError` for anything that is not a usable moment (non-finite or
 * negative numbers, unparseable strings, other types) so a bad sunset
 * can never silently become "already sunset" or "never sunset" at
 * runtime.
 */
export function normalizeVersionSunsetAt(value: unknown): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value === "number") {
    if (!Number.isFinite(value) || value < 0) {
      throw new RangeError(
        `version route sunsetAt must be a finite epoch-ms >= 0, got ${String(value)}`
      );
    }
    return Math.floor(value);
  }
  if (typeof value === "string") {
    const ms = Date.parse(value);
    if (Number.isNaN(ms) || ms < 0) {
      throw new RangeError(
        `version route sunsetAt must be an ISO-8601 timestamp, got ${JSON.stringify(value)}`
      );
    }
    return ms;
  }
  throw new RangeError(
    `version route sunsetAt must be epoch-ms or an ISO-8601 string, got ${typeof value}`
  );
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
    // WR-144: normalize the opt-in sunset moment now — an invalid moment
    // throws at startup, never mid-request.
    normalizeVersionSunsetAt(route.sunsetAt);
  }
}

/**
 * Matches inbound paths against the version route table (longest prefix
 * wins, segment-boundary matching only).
 *
 * WR-144: per-version sunsets live here too. Each route's configured
 * `sunsetAt` seeds a `configured` map at construction; operator
 * hot-updates (the WR-32 convention) write an `overrides` map keyed by
 * prefix — an override of `null` explicitly clears the sunset. The
 * effective sunset for a prefix is `override ?? configured`.
 */
export class ApiVersionRouter {
  private readonly routes: ApiVersionRoute[];
  private readonly configuredSunsets = new Map<string, number>();
  private readonly sunsetOverrides = new Map<string, number | null>();

  constructor(routes: ApiVersionRoute[]) {
    // Fail fast at startup; a route table that throws mid-request is a bug.
    assertValidVersionRoutes(routes);
    // Longest prefix first so the first match is the winner.
    this.routes = [...routes].sort((a, b) => b.prefix.length - a.prefix.length);
    for (const route of routes) {
      const ms = normalizeVersionSunsetAt(route.sunsetAt);
      if (ms !== undefined) this.configuredSunsets.set(route.prefix, ms);
    }
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

  /**
   * The effective sunset moment (epoch ms) for `prefix`, or `undefined`
   * when the version never sunsets. An operator override wins over the
   * configured `sunsetAt`; an override of `null` clears the sunset.
   */
  effectiveSunset(prefix: string): number | undefined {
    if (this.sunsetOverrides.has(prefix)) {
      return this.sunsetOverrides.get(prefix) ?? undefined;
    }
    return this.configuredSunsets.get(prefix);
  }

  /**
   * WR-144: hot-update one version's sunset at runtime (the WR-32
   * convention — immediate effect, no restart). `null` clears the
   * sunset entirely; anything else must be a valid moment. Unknown
   * prefixes and invalid moments throw `RangeError`.
   */
  setSunset(prefix: string, sunsetAt: number | string | null): void {
    if (!this.hasPrefix(prefix)) {
      throw new RangeError(`unknown version route prefix ${JSON.stringify(prefix)}`);
    }
    this.sunsetOverrides.set(
      prefix,
      sunsetAt === null ? null : normalizeVersionSunsetAt(sunsetAt)
    );
  }

  /**
   * WR-144: drop the runtime sunset override for `prefix`, restoring the
   * route's configured `sunsetAt` (or no sunset). Unknown prefixes throw
   * `RangeError`.
   */
  clearSunset(prefix: string): void {
    if (!this.hasPrefix(prefix)) {
      throw new RangeError(`unknown version route prefix ${JSON.stringify(prefix)}`);
    }
    this.sunsetOverrides.delete(prefix);
  }

  /** Current sunset state for every route (operator introspection). */
  sunsetEntries(): Array<{
    prefix: string;
    version: string;
    sunsetAt: number | null;
    source: "config" | "override" | "none";
  }> {
    return this.routes.map((route) => {
      if (this.sunsetOverrides.has(route.prefix)) {
        const v = this.sunsetOverrides.get(route.prefix);
        return {
          prefix: route.prefix,
          version: route.adapter.version,
          sunsetAt: v ?? null,
          source: v === null ? ("none" as const) : ("override" as const),
        };
      }
      const configured = this.configuredSunsets.get(route.prefix);
      return {
        prefix: route.prefix,
        version: route.adapter.version,
        sunsetAt: configured ?? null,
        source: configured === undefined ? ("none" as const) : ("config" as const),
      };
    });
  }

  private hasPrefix(prefix: string): boolean {
    return this.routes.some((route) => route.prefix === prefix);
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
