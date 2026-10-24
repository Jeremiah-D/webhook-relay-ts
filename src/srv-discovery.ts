import { promises as dnsPromises, type SrvRecord } from "node:dns";

/**
 * DNS SRV endpoint discovery (WR-211).
 *
 * An endpoint's `targetUrl` names a logical service, not necessarily a
 * host that answers directly: in service-discovery deployments the
 * actual host and port come from DNS SRV records (RFC 2782), e.g.
 * `_https._tcp.events.example.com` answering with the current
 * webhook receivers. Resolving the URL's hostname as an A record
 * would send the delivery to the wrong place — or nowhere — so the
 * relay resolves the SRV set first and rewrites the target to the
 * selected record.
 *
 * Selection follows RFC 2782 exactly:
 *
 * - records are grouped by `priority`; only the lowest-priority group
 *   is eligible (a higher-priority group is backup, never mixed in);
 * - inside the group, selection is weight-proportional: a record's
 *   chance is its `weight` over the group's total weight, drawn with
 *   one uniform random number over that total;
 * - when every weight in the group is zero, selection is uniform over
 *   the group (the RFC 2782 zero-weight rule).
 *
 * Caching follows the WR-92 `dns-cache.ts` convention — a configured
 * TTL (default 60s), bounded entries, activity-gated stats — but with
 * one deliberate difference: there is no stale-while-revalidate here.
 * An expired SRV set is never served while a refresh runs, because a
 * stale SRV answer can point at a decommissioned receiver, and
 * guessing a delivery target is worse than failing the attempt. The
 * failure modes are all fail-closed:
 *
 * - no SRV records, or only a `.` target (RFC 2782: the service is
 *   decidedly not available) → `SrvDiscoveryError`, never a fallback
 *   to the original URL's host;
 * - a resolver error → `SrvDiscoveryError`, never the original host;
 * - an expired cache entry is re-resolved, never served stale.
 *
 * Layering: this is *discovery* (which host:port to use), orthogonal
 * to `src/dns-pin.ts` (whether the resolved addresses are the pinned
 * ones) and to `src/dns-cache.ts` (caching A-record answers for the
 * connection itself). A discovered target still goes through the
 * normal connection path — and therefore through the pin and the
 * cache — once the URL is rewritten.
 *
 * Zero dependencies (`node:dns` only).
 */

/** Tuning for {@link SrvDiscovery}. All values are validated up front. */
export interface SrvDiscoveryOptions {
  /**
   * How long a resolved SRV record set stays fresh, in ms. Default:
   * 60_000 (the WR-92 default). Must be a finite number > 0.
   */
  ttlMs?: number;
  /**
   * Maximum SRV names held. Default: 1024. Must be a positive
   * integer. When full, the entry expiring soonest is evicted.
   */
  maxEntries?: number;
  /** Clock; defaults to `Date.now`. Injectable for tests. */
  now?: () => number;
  /**
   * Uniform random source in `[0, 1)`, used for the RFC 2782 weighted
   * draw. Defaults to `Math.random`. Injectable for deterministic
   * tests; a value outside `[0, 1)` throws `RangeError` at draw time.
   */
  random?: () => number;
  /**
   * Resolver; defaults to `dns.promises.resolveSrv(srvName)`.
   * Injectable for tests — receives the full SRV name
   * (`_service._proto.name`), returns the record set.
   */
  resolve?: (srvName: string) => Promise<SrvRecord[]>;
}

/** One selected SRV target. */
export interface SrvTarget {
  /** Selected host, trailing dot stripped, lowercased. */
  hostname: string;
  /** Selected port, as published by the record. */
  port: number;
  /** Priority group the target was drawn from. */
  priority: number;
  /** Weight the target carried inside its group. */
  weight: number;
  /** Full SRV name the target was resolved from. */
  srvName: string;
}

/** Snapshot from {@link SrvDiscovery.getStats}. */
export interface SrvDiscoveryStats {
  /** SRV names currently cached (record sets, not targets). */
  hosts: number;
  /** `resolve()` calls served (cache hits + misses). */
  lookups: number;
  /** `resolve()` calls served from a fresh cache entry. */
  cacheHits: number;
  /** Resolver invocations (one per cache miss / expired entry). */
  resolverCalls: number;
  /** Resolver failures (each surfaced as `SrvDiscoveryError`). */
  resolverFailures: number;
}

/** Thrown for every discovery failure — never a fallback target. */
export class SrvDiscoveryError extends Error {
  /** Full SRV name that failed to resolve. */
  readonly srvName: string;
  constructor(srvName: string, message: string) {
    super(`srv-discovery[${srvName}]: ${message}`);
    this.name = "SrvDiscoveryError";
    this.srvName = srvName;
  }
}

const DEFAULT_TTL_MS = 60_000;
const DEFAULT_MAX_ENTRIES = 1024;
const LABEL_RE = /^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$/;

interface CacheEntry {
  records: SrvRecord[];
  expiresAt: number;
}

async function defaultResolve(srvName: string): Promise<SrvRecord[]> {
  return dnsPromises.resolveSrv(srvName);
}

function stripTrailingDot(name: string): string {
  return name.endsWith(".") ? name.slice(0, -1) : name;
}

/**
 * Build the full SRV name for a service. `service` and `proto` may be
 * given with or without the leading underscore (`"https"` and
 * `"_https"` are the same service); `name` may carry a trailing dot,
 * which is stripped. Throws `RangeError` on an empty or malformed part.
 */
export function buildSrvName(service: string, proto: string, name: string): string {
  const norm = (part: string, what: string): string => {
    if (typeof part !== "string" || part === "") {
      throw new RangeError(`srv-discovery: ${what} must be a non-empty string`);
    }
    const stripped = part.startsWith("_") ? part.slice(1) : part;
    if (!LABEL_RE.test(stripped.toLowerCase())) {
      throw new RangeError(`srv-discovery: ${what} must look like a DNS label (got ${JSON.stringify(part)})`);
    }
    return `_${stripped.toLowerCase()}`;
  };
  if (typeof name !== "string" || name === "") {
    throw new RangeError("srv-discovery: name must be a non-empty string");
  }
  return `${norm(service, "service")}.${norm(proto, "proto")}.${stripTrailingDot(name).toLowerCase()}`;
}

/**
 * RFC 2782 selection over one record set: lowest priority group only,
 * weight-proportional inside the group, uniform when all weights are
 * zero. `.` targets are ineligible (the service is not available on
 * them). Throws `SrvDiscoveryError` when nothing is eligible.
 */
export function selectSrvTarget(
  records: SrvRecord[],
  srvName: string,
  random: () => number
): SrvTarget {
  const eligible = records.filter((r) => stripTrailingDot(r.name) !== "");
  if (eligible.length === 0) {
    throw new SrvDiscoveryError(srvName, "no SRV records (or only a \".\" target: service not available)");
  }
  const minPriority = Math.min(...eligible.map((r) => r.priority));
  const group = eligible.filter((r) => r.priority === minPriority);
  const totalWeight = group.reduce((sum, r) => sum + r.weight, 0);
  let picked: SrvRecord;
  if (totalWeight === 0) {
    const r = random();
    if (!Number.isFinite(r) || r < 0 || r >= 1) {
      throw new RangeError("srv-discovery: random must return a number in [0, 1)");
    }
    picked = group[Math.floor(r * group.length)];
  } else {
    const r = random();
    if (!Number.isFinite(r) || r < 0 || r >= 1) {
      throw new RangeError("srv-discovery: random must return a number in [0, 1)");
    }
    let draw = r * totalWeight;
    picked = group[group.length - 1];
    for (const record of group) {
      draw -= record.weight;
      if (draw < 0) {
        picked = record;
        break;
      }
    }
  }
  return {
    hostname: stripTrailingDot(picked.name).toLowerCase(),
    port: picked.port,
    priority: picked.priority,
    weight: picked.weight,
    srvName,
  };
}

/**
 * DNS SRV endpoint discovery (WR-211). One instance serves any number
 * of services; the record-set cache is shared across them.
 */
export class SrvDiscovery {
  private readonly ttlMs: number;
  private readonly maxEntries: number;
  private readonly now: () => number;
  private readonly random: () => number;
  private readonly resolveFn: (srvName: string) => Promise<SrvRecord[]>;
  private readonly entries = new Map<string, CacheEntry>();
  private lookups = 0;
  private cacheHits = 0;
  private resolverCalls = 0;
  private resolverFailures = 0;

  constructor(opts: SrvDiscoveryOptions = {}) {
    this.ttlMs = opts.ttlMs ?? DEFAULT_TTL_MS;
    if (!Number.isFinite(this.ttlMs) || this.ttlMs <= 0) {
      throw new RangeError(`SrvDiscovery: ttlMs must be a finite number > 0, got ${opts.ttlMs}`);
    }
    this.maxEntries = opts.maxEntries ?? DEFAULT_MAX_ENTRIES;
    if (!Number.isInteger(this.maxEntries) || this.maxEntries <= 0) {
      throw new RangeError(
        `SrvDiscovery: maxEntries must be a positive integer, got ${opts.maxEntries}`
      );
    }
    if (opts.now !== undefined && typeof opts.now !== "function") {
      throw new RangeError("SrvDiscovery: now must be a function");
    }
    this.now = opts.now ?? Date.now;
    if (opts.random !== undefined && typeof opts.random !== "function") {
      throw new RangeError("SrvDiscovery: random must be a function");
    }
    this.random = opts.random ?? Math.random;
    if (opts.resolve !== undefined && typeof opts.resolve !== "function") {
      throw new RangeError("SrvDiscovery: resolve must be a function");
    }
    this.resolveFn = opts.resolve ?? defaultResolve;
  }

  /** Current counters. */
  getStats(): SrvDiscoveryStats {
    return {
      hosts: this.entries.size,
      lookups: this.lookups,
      cacheHits: this.cacheHits,
      resolverCalls: this.resolverCalls,
      resolverFailures: this.resolverFailures,
    };
  }

  /**
   * Prometheus exposition for `GET /metrics` (`relay_srv_discovery_*`).
   * Empty string until the first lookup — the activity-gated
   * convention, so a relay without the feature exposes no new series.
   */
  render(): string {
    if (this.lookups === 0) return "";
    const lines = [
      "# HELP relay_srv_discovery_lookups_total SRV discovery lookups (WR-211): hit = fresh cached record set reused, miss = resolver invoked.",
      "# TYPE relay_srv_discovery_lookups_total counter",
      `relay_srv_discovery_lookups_total{result="hit"} ${this.cacheHits}`,
      `relay_srv_discovery_lookups_total{result="miss"} ${this.lookups - this.cacheHits}`,
      "# HELP relay_srv_discovery_resolver_failures_total SRV resolver failures surfaced as SrvDiscoveryError (WR-211, fail-closed).",
      "# TYPE relay_srv_discovery_resolver_failures_total counter",
      `relay_srv_discovery_resolver_failures_total ${this.resolverFailures}`,
      "# HELP relay_srv_discovery_hosts SRV names currently held in the discovery cache (WR-211).",
      "# TYPE relay_srv_discovery_hosts gauge",
      `relay_srv_discovery_hosts ${this.entries.size}`,
    ];
    return lines.join("\n") + "\n";
  }

  /** Drop all cached record sets. Counters are kept. */
  clear(): void {
    this.entries.clear();
  }

  /**
   * Resolve one service to a target. A fresh cache entry is reused
   * (the record set, re-selected per call, so weighted targets still
   * spread inside the TTL); an expired entry is re-resolved, never
   * served stale. Throws `SrvDiscoveryError` on an empty record set,
   * a `.`-only set, or a resolver error — never a fallback target.
   */
  async resolve(service: string, proto: string, name: string): Promise<SrvTarget> {
    const srvName = buildSrvName(service, proto, name);
    this.lookups += 1;
    const now = this.now();
    const entry = this.entries.get(srvName);
    if (entry !== undefined && entry.expiresAt > now) {
      this.cacheHits += 1;
      return selectSrvTarget(entry.records, srvName, this.random);
    }
    this.resolverCalls += 1;
    let records: SrvRecord[];
    try {
      records = await this.resolveFn(srvName);
    } catch (err) {
      this.resolverFailures += 1;
      throw new SrvDiscoveryError(srvName, `resolver failed: ${(err as Error).message}`);
    }
    if (!Array.isArray(records) || records.length === 0) {
      this.resolverFailures += 1;
      throw new SrvDiscoveryError(srvName, "no SRV records for this service");
    }
    if (!this.entries.has(srvName) && this.entries.size >= this.maxEntries) {
      this.evictSoonestExpiring();
    }
    this.entries.set(srvName, { records, expiresAt: this.now() + this.ttlMs });
    return selectSrvTarget(records, srvName, this.random);
  }

  /**
   * Rewrite an endpoint `targetUrl` to its SRV-discovered target:
   * scheme, path, and query are preserved; host and port come from
   * the selected record. `name` defaults to the URL's own hostname.
   * Throws `RangeError` for a non-http(s)/ws(s) URL and
   * `SrvDiscoveryError` for every discovery failure — the original
   * host is never returned as a fallback.
   */
  async resolveTargetUrl(
    targetUrl: string,
    srv: { service: string; proto: string; name?: string }
  ): Promise<string> {
    let url: URL;
    try {
      url = new URL(targetUrl);
    } catch {
      throw new RangeError(`srv-discovery: targetUrl is not a valid URL: ${JSON.stringify(targetUrl)}`);
    }
    if (!["http:", "https:", "ws:", "wss:"].includes(url.protocol)) {
      throw new RangeError(
        `srv-discovery: targetUrl must use http:, https:, ws:, or wss: (got ${url.protocol})`
      );
    }
    const target = await this.resolve(srv.service, srv.proto, srv.name ?? url.hostname);
    url.hostname = target.hostname;
    url.port = String(target.port);
    return url.toString();
  }

  private evictSoonestExpiring(): void {
    let victim: string | undefined;
    let victimExpiresAt = Infinity;
    for (const [srvName, entry] of this.entries) {
      if (entry.expiresAt < victimExpiresAt) {
        victim = srvName;
        victimExpiresAt = entry.expiresAt;
      }
    }
    if (victim !== undefined) this.entries.delete(victim);
  }
}
