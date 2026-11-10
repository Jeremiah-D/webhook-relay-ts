import { promises as dnsPromises, type LookupAddress } from "node:dns";
import { isIP } from "node:net";
import type { DnsCache } from "./dns-cache.ts";
import {
  compileGeoIpTable,
  lookupGeoCountry,
  type CompiledGeoIpTableEntry,
  type GeoIpTableEntry,
} from "./geoip.ts";

/**
 * Outbound egress data-residency gate (WR-374).
 *
 * `geoip.ts` (WR-158) only guards the *inbound* path — a `GeoIpInboundPolicy`
 * answers "which country is this client in" for senders dialing *in*. Nothing
 * stops the relay itself from egressing a tenant's payload to a country that
 * tenant's data-residency rules forbid: an endpoint that moves hosting from
 * Frankfurt to a disallowed jurisdiction silently takes the tenant's data
 * with it, and the next delivery just goes there. For tenants with EU data
 * residency requirements that is a compliance hole, not a routing detail.
 *
 * This module is the outbound mirror of WR-158: the same operator-curated
 * CIDR → country table (`geoip.ts`'s `lookupGeoCountry`, zero new
 * dependencies, zero binary GeoIP database) plus the WR-92 `DnsCache` for
 * resolution, applied per tenant before connect:
 *
 * - Each tenant may configure `allowedEgressCountries` — an ISO 3166-1
 *   alpha-2 list. Tenants without an entry are unlimited (opt-in; a relay
 *   without the feature behaves exactly as before).
 * - At delivery time the target hostname is resolved (an IP-literal target
 *   is judged directly, no resolution) and *every* resolved address is
 *   looked up in the table. One address in a disallowed country — or one
 *   address the table does not map at all — refuses the whole delivery
 *   before a single byte is written: the dialer may pick any of the
 *   resolved addresses, so a mixed answer is not a partial pass.
 * - An unmapped IP fails closed (WR-158's convention: what cannot be
 *   proven compliant is not let through), as does an unparsable resolved
 *   address. Both audit as country `"unknown"`.
 * - A refusal throws {@link EgressResidencyBlockedError}, classified
 *   `"non_retryable"` by `classifyFailure` (see `src/failure.ts`) — the
 *   item dead-letters on the first attempt without burning retry budget
 *   or touching the circuit breaker (the endpoint was never contacted,
 *   so the control plane learns nothing, mirroring the WR-115
 *   transform-failure rule and the WR-373 SSRF rule). The block is
 *   reported via `onBlocked` (the server audits it as
 *   `egress_residency_blocked` with tenant, endpoint, and country).
 *   Resolved addresses ride that audit event only — never metrics labels,
 *   and never the error message (which also lands in the `dead_letter`
 *   audit's `error` field).
 * - A dead-lettered item replays normally once the operator relaxes the
 *   tenant's list (`reviseAllowedCountries`, or a config change + restart)
 *   — the gate judges the *current* list on every attempt, so a replay
 *   after a relaxation is served, not re-refused.
 *
 * Composition with the neighbouring guards (each owns one dimension):
 *
 * - WR-158 (inbound GeoIP): the same table, the opposite direction.
 * - WR-373 (outbound SSRF): the same package (`DnsCache` lookup), a
 *   different verdict — SSRF refuses *private* addresses, this gate
 *   refuses *foreign* ones. A delivery passes both: SSRF first (at the
 *   lookup the agent dials), residency second (a pre-flight check in the
 *   sender, before any transport is chosen).
 * - WR-194 (DNS pin): judges whether the resolution *drifted*, not which
 *   country the address is in. A drifted address is still judged here
 *   by its new country.
 * - WR-92 (DNS cache): the resolution layer this gate reuses — cached
 *   answers keep the pre-flight check cheap, and stale-while-revalidate
 *   keeps a resolver hiccup from blocking deliveries the cache can still
 *   answer.
 *
 * Scope notes:
 *
 * - The gate covers every transport the default sender dispatches
 *   (HTTP/1.1, HTTP/2, WebSocket): the check runs in `dispatch`, before
 *   any transport is chosen, so no path can slip past it.
 * - Proxied deliveries are still checked against the *target* hostname's
 *   country — the payload still lands in that country, only via the
 *   proxy. The proxy host's own egress is the proxy operator's
 *   responsibility (the same split WR-373 documents, in the other
 *   direction: the SSRF guard skips proxied targets because it cannot
 *   know what the proxy dials; this gate judges the named destination,
 *   which the relay does know).
 * - With keep-alive pooling (WR-24) an established connection is reused
 *   without re-resolving — a re-bind is therefore caught when the *next
 *   new connection* resolves, not mid-stream on a live connection. That
 *   is the correct semantic (the live connection already went to a
 *   checked address); the gate judges every fresh dispatch, and the
 *   SSRF guard still judges every fresh resolution.
 * - A DNS failure is not a residency verdict: the resolver error
 *   propagates unchanged, and the delivery follows the normal retry /
 *   dead-letter path for it.
 *
 * Zero dependencies (`node:dns` + `node:net` types only, plus the WR-158
 * table and the WR-92 cache).
 */

/** Details of one blocked delivery, delivered to `onBlocked`. */
export interface EgressResidencyBlockedInfo {
  /** The tenant whose allowlist refused the delivery (`undefined` = default tenant). */
  tenant: string | undefined;
  /** The endpoint URL the delivery was headed to. */
  endpoint: string;
  /** The target hostname that was resolved and judged. */
  hostname: string;
  /**
   * The offending country (ISO 3166-1 alpha-2) — `"unknown"` when the
   * resolved address mapped to no country in the operator-curated table
   * (or was unparsable). Audit-only detail beyond this field: the
   * offending addresses themselves.
   */
  country: string;
  /** Every offending resolved address (sorted, deduplicated). Audit-only: never a metrics label. */
  addresses: string[];
  /** ISO-8601 timestamp of the block. */
  at: string;
}

/**
 * The error a residency check fails with when a resolved address is in a
 * disallowed country (or unmapped). Classified `"non_retryable"` by
 * `classifyFailure` — the item dead-letters on the first attempt without
 * burning retry budget or touching the circuit breaker.
 *
 * The message names the hostname and the country only — the offending
 * addresses ride the `egress_residency_blocked` audit event, never the
 * error (which also lands in the `dead_letter` audit's `error` field)
 * and never a metrics label.
 */
export class EgressResidencyBlockedError extends Error {
  /** Stable machine-readable code, in the `NodeJS.ErrnoException` shape. */
  readonly code = "EGEORESIDENCY";
  /** The tenant whose allowlist refused the delivery (`undefined` = default tenant). */
  readonly tenant: string | undefined;
  /** The endpoint URL the delivery was headed to. */
  readonly endpoint: string;
  /** The target hostname that was resolved and judged. */
  readonly hostname: string;
  /** The offending country — `"unknown"` when unmapped or unparsable. */
  readonly country: string;
  /** Every offending resolved address (sorted, deduplicated). Audit-only. */
  readonly addresses: string[];

  constructor(
    tenant: string | undefined,
    endpoint: string,
    hostname: string,
    country: string,
    addresses: string[]
  ) {
    super(
      `Egress residency gate blocked ${hostname}: resolved address is in ${country}, ` +
        `outside ${tenant === undefined ? "the default tenant" : `tenant ${tenant}`}’s allowed egress countries`
    );
    this.name = "EgressResidencyBlockedError";
    this.tenant = tenant;
    this.endpoint = endpoint;
    this.hostname = hostname;
    this.country = country;
    this.addresses = [...addresses];
  }
}

/** Tuning for {@link EgressResidencyGate}. All values are validated up front. */
export interface EgressResidencyOptions {
  /**
   * Operator-curated CIDR → country table, matched in config order
   * (first match wins — the same rule as `geoip.ts`, so overlapping
   * ranges resolve deterministically; document the more specific range
   * first). May be empty or omitted — then every resolved address is
   * unmapped and fails closed for tenants with a list.
   */
  table?: GeoIpTableEntry[];
  /**
   * Per-tenant egress allowlist: tenant id → ISO 3166-1 alpha-2 country
   * codes the tenant's payloads may egress to. Tenants without an entry
   * are unlimited (opt-in). An empty list allows no country — a closed
   * egress for that tenant.
   */
  allowedEgressCountries?: Record<string, string[]>;
  /**
   * The WR-92 cache the gate resolves through (the sender passes its
   * shared cache, so the pre-flight check rides cached answers).
   * Ignored when `resolve` is given. Defaults to the system resolver
   * when neither is given.
   */
  dnsCache?: DnsCache;
  /**
   * Resolver override; receives the hostname, returns the address list
   * (empty = treated as a resolution failure). Injectable for tests.
   * Wins over `dnsCache`.
   */
  resolve?: (hostname: string) => Promise<LookupAddress[]>;
  /** Called once per blocked delivery. */
  onBlocked?: (info: EgressResidencyBlockedInfo) => void;
  /** Clock; defaults to `Date.now`. Injectable for tests. */
  now?: () => number;
}

/** Snapshot from {@link EgressResidencyGate.getStats}. */
export interface EgressResidencyStats {
  /** Deliveries allowed (every resolved address in an allowed country). */
  checked: number;
  /** Deliveries refused before connect. */
  blocked: number;
  /** Blocks by offending country (`"unknown"` = unmapped / unparsable). */
  blocksByCountry: Record<string, number>;
}

const COUNTRY_CODE_RE = /^[A-Z]{2}$/;

/** Fail with a RangeError naming the offending input. */
function invalid(where: string, detail: string): never {
  throw new RangeError(`egressResidency: ${where}: ${detail}`);
}

function dnsError(code: string, hostname: string): NodeJS.ErrnoException {
  const err = new Error(`${code} ${hostname}`) as NodeJS.ErrnoException;
  err.code = code;
  err.hostname = hostname;
  return err;
}

async function defaultResolve(hostname: string): Promise<LookupAddress[]> {
  const records = await dnsPromises.lookup(hostname, { all: true });
  return records.map((r) => ({ address: r.address, family: r.family }));
}

/**
 * Resolve through a WR-92 cache: the cache's `lookup` is callback-style,
 * so promisify it asking for the full address list.
 */
function dnsCacheResolve(cache: DnsCache): (hostname: string) => Promise<LookupAddress[]> {
  return (hostname: string) =>
    new Promise<LookupAddress[]>((resolvePromise, rejectPromise) => {
      cache.lookup(hostname, { all: true }, (err, addresses) => {
        if (err !== null && err !== undefined) {
          rejectPromise(err);
          return;
        }
        if (Array.isArray(addresses)) {
          resolvePromise(addresses);
          return;
        }
        if (typeof addresses === "string" && addresses.length > 0) {
          resolvePromise([{ address: addresses, family: 4 }]);
          return;
        }
        rejectPromise(dnsError("ENOTFOUND", hostname));
      });
    });
}

/** Validate one tenant's country list; returns a deduplicated copy. */
function assertCountryList(tenant: string, countries: unknown): string[] {
  if (!Array.isArray(countries)) {
    invalid(
      `allowedEgressCountries[${JSON.stringify(tenant)}]`,
      `expected an array of uppercase ISO 3166-1 alpha-2 codes, got ${JSON.stringify(countries)}`
    );
  }
  const seen = new Set<string>();
  for (const cc of countries as unknown[]) {
    if (typeof cc !== "string" || !COUNTRY_CODE_RE.test(cc)) {
      invalid(
        `allowedEgressCountries[${JSON.stringify(tenant)}]`,
        `expected an uppercase ISO 3166-1 alpha-2 code, got ${JSON.stringify(cc)}`
      );
    }
    seen.add(cc);
  }
  return [...seen];
}

export class EgressResidencyGate {
  private readonly table: CompiledGeoIpTableEntry[];
  private readonly allowed = new Map<string, ReadonlySet<string>>();
  private readonly resolve: (hostname: string) => Promise<LookupAddress[]>;
  private readonly onBlocked?: (info: EgressResidencyBlockedInfo) => void;
  private readonly now: () => number;
  private checked = 0;
  private blocked = 0;
  private readonly blocksByCountry: Record<string, number> = {};

  constructor(opts: EgressResidencyOptions = {}) {
    if (opts === null || typeof opts !== "object" || Array.isArray(opts)) {
      throw new RangeError("egressResidency: expected { table?, allowedEgressCountries?, dnsCache?, resolve?, onBlocked?, now? }");
    }
    // The table is compiled (and validated) exactly like the inbound
    // WR-158 policy: a bad CIDR or country code throws RangeError at
    // startup, never mid-delivery.
    this.table = compileGeoIpTable(opts.table);
    if (opts.allowedEgressCountries !== undefined) {
      if (
        opts.allowedEgressCountries === null ||
        typeof opts.allowedEgressCountries !== "object" ||
        Array.isArray(opts.allowedEgressCountries)
      ) {
        throw new RangeError(
          "egressResidency.allowedEgressCountries: expected a record of tenant -> country-code array"
        );
      }
      for (const [tenant, countries] of Object.entries(opts.allowedEgressCountries)) {
        if (typeof tenant !== "string" || tenant.length === 0) {
          throw new RangeError("egressResidency.allowedEgressCountries: tenant id must be a non-empty string");
        }
        this.allowed.set(tenant, new Set(assertCountryList(tenant, countries)));
      }
    }
    if (opts.resolve !== undefined && typeof opts.resolve !== "function") {
      throw new RangeError("egressResidency: resolve must be a function");
    }
    if (opts.dnsCache !== undefined) {
      if (
        opts.dnsCache === null ||
        typeof opts.dnsCache !== "object" ||
        typeof (opts.dnsCache as DnsCache).lookup !== "function"
      ) {
        throw new RangeError("egressResidency: dnsCache must be a DnsCache");
      }
    }
    // An explicit resolver wins; otherwise the shared cache; otherwise
    // the system resolver.
    this.resolve =
      opts.resolve ?? (opts.dnsCache !== undefined ? dnsCacheResolve(opts.dnsCache) : defaultResolve);
    if (opts.onBlocked !== undefined && typeof opts.onBlocked !== "function") {
      throw new RangeError("egressResidency: onBlocked must be a function");
    }
    this.onBlocked = opts.onBlocked;
    if (opts.now !== undefined && typeof opts.now !== "function") {
      throw new RangeError("egressResidency: now must be a function");
    }
    this.now = opts.now ?? Date.now;
  }

  /**
   * Judge one delivery before connect: resolve the target hostname and
   * check every resolved address's country against the tenant's
   * allowlist. Resolves (does not throw) when the tenant has no entry
   * (unlimited) or every address is allowed. Throws
   * {@link EgressResidencyBlockedError} on the first violation — the
   * caller dead-letters the item without burning retry budget. A DNS
   * failure propagates unchanged (not a residency verdict — the delivery
   * follows the normal retry path for it).
   */
  async check(tenant: string | undefined, targetUrl: string): Promise<void> {
    const allowed = tenant === undefined ? undefined : this.allowed.get(tenant);
    if (allowed === undefined) return;
    let hostname: string;
    try {
      hostname = new URL(targetUrl).hostname;
    } catch {
      throw new RangeError(
        `egressResidency: unparseable targetUrl ${JSON.stringify(targetUrl)}`
      );
    }
    let addresses: LookupAddress[];
    const family = isIP(hostname);
    if (family === 4 || family === 6) {
      // An IP-literal target is judged directly — no resolution to
      // perform, and none to cache.
      addresses = [{ address: hostname, family }];
    } else {
      addresses = await this.resolve(hostname);
      if (addresses.length === 0) throw dnsError("ENOTFOUND", hostname);
    }
    // Deterministic order: the first offending address (sorted) names
    // the audit's country, and the audit lists every offending address.
    const sorted = [...new Set(addresses.map((a) => a.address))].sort();
    const offending: { address: string; country: string }[] = [];
    for (const address of sorted) {
      let country: string | undefined;
      try {
        country = lookupGeoCountry(address, this.table);
      } catch {
        // Unparsable resolved address: fail closed, country unknown
        // (the WR-158 convention — what cannot be proven compliant is
        // not let through).
        country = undefined;
      }
      if (country === undefined || !allowed.has(country)) {
        offending.push({ address, country: country ?? "unknown" });
      }
    }
    if (offending.length === 0) {
      this.checked += 1;
      return;
    }
    const country = offending[0].country;
    this.blocked += 1;
    this.blocksByCountry[country] = (this.blocksByCountry[country] ?? 0) + 1;
    const offendingAddresses = offending.map((o) => o.address);
    this.onBlocked?.({
      tenant,
      endpoint: targetUrl,
      hostname,
      country,
      addresses: offendingAddresses,
      at: new Date(this.now()).toISOString(),
    });
    throw new EgressResidencyBlockedError(tenant, targetUrl, hostname, country, offendingAddresses);
  }

  /**
   * Live-revise one tenant's allowlist: `countries` replaces the list
   * (validated like the constructor's); `null` clears the tenant's entry
   * back to unlimited. Returns a copy of the new list, or `undefined`
   * when cleared. A same-set revision is a no-op returning a copy.
   * The gate judges the *current* list on every attempt, so a dead
   * letter replays successfully once the operator relaxes the list.
   */
  reviseAllowedCountries(tenant: string, countries: string[] | null): string[] | undefined {
    if (typeof tenant !== "string" || tenant.length === 0) {
      throw new RangeError("egressResidency: tenant must be a non-empty string");
    }
    if (countries === null) {
      this.allowed.delete(tenant);
      return undefined;
    }
    const next = new Set(assertCountryList(tenant, countries));
    const live = this.allowed.get(tenant);
    if (
      live !== undefined &&
      live.size === next.size &&
      [...next].every((cc) => live.has(cc))
    ) {
      return [...live];
    }
    this.allowed.set(tenant, next);
    return [...next];
  }

  /** A copy of one tenant's allowlist, or `undefined` when unlimited. */
  allowedCountries(tenant: string): string[] | undefined {
    const live = this.allowed.get(tenant);
    return live === undefined ? undefined : [...live];
  }

  /** Current counters; `blocksByCountry` is a fresh object on every call. */
  getStats(): EgressResidencyStats {
    return {
      checked: this.checked,
      blocked: this.blocked,
      blocksByCountry: { ...this.blocksByCountry },
    };
  }

  /**
   * Prometheus exposition for `GET /metrics`
   * (`relay_egress_residency_*`). Empty string until the first check —
   * the activity-gated convention, so a relay without the feature
   * exposes no new series. Labels carry only the result and the
   * country — resolved addresses never appear in metrics.
   */
  render(): string {
    if (this.checked + this.blocked === 0) return "";
    const countries = Object.keys(this.blocksByCountry).sort();
    const lines = [
      "# HELP relay_egress_residency_lookups_total Egress data-residency checks (WR-374): checked = allowed (every resolved address in an allowed country), blocked = refused before connect (a resolved address in a disallowed country, or unmapped by the operator-curated GeoIP table).",
      "# TYPE relay_egress_residency_lookups_total counter",
      `relay_egress_residency_lookups_total{result="checked"} ${this.checked}`,
      `relay_egress_residency_lookups_total{result="blocked"} ${this.blocked}`,
      "# HELP relay_egress_residency_blocks_total Egress residency blocks by offending country (WR-374). \"unknown\" = the resolved address mapped to no country in the operator-curated table (fail-closed). Country codes only — resolved addresses never appear in metrics labels.",
      "# TYPE relay_egress_residency_blocks_total counter",
      ...countries.map(
        (c) => `relay_egress_residency_blocks_total{country="${c}"} ${this.blocksByCountry[c]}`
      ),
    ];
    return lines.join("\n") + "\n";
  }
}
