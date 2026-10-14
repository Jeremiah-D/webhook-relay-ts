import { promises as dnsPromises, type LookupAddress } from "node:dns";
import type { LookupFunction } from "node:net";

/**
 * Outbound DNS resolution cache (WR-92).
 *
 * Every delivery opens (or reuses) a connection, and every new
 * connection pays a DNS lookup. Under high fan-out to a small set of
 * downstreams that lookup is pure overhead — and when the resolver
 * hiccups, deliveries fail for a reason that has nothing to do with the
 * downstream. The cache sits between the relay and the resolver:
 *
 * - per-hostname entries with a configurable TTL (default 60s);
 * - stale-while-revalidate: an expired entry is still served while a
 *   background refresh runs, so a slow or failing resolver never blocks
 *   a delivery that has a usable (if slightly old) address;
 * - single-flight refresh: concurrent expired lookups trigger exactly
 *   one background resolution;
 * - a failed refresh never evicts the stale entry — the relay keeps
 *   serving it (counted as `staleServed` / `refreshFailures`). Only when
 *   the cache holds *no* entry for a hostname does a DNS error reach
 *   the caller, which then follows the normal retry / dead-letter path.
 *
 * The cache is `dns.lookup`-compatible: hand `cache.lookup` to an
 * `http.Agent`'s `lookup` option (the WR-24 pool does this) or to a
 * single `http.request`'s options, and every new connection resolves
 * through it. It is also usable for the WR-34 downstream probes
 * (`ProbeOptions.lookup`).
 *
 * Scope note: the cache covers the HTTP/1.1 delivery path (pooled and
 * one-off) and the probes. The opt-in HTTP/2 session pool and the
 * WebSocket pool manage their own connections and keep the OS resolver.
 *
 * Zero dependencies (`node:dns` + `node:net` types only).
 */

/** Tuning for {@link DnsCache}. All values are validated up front. */
export interface DnsCacheOptions {
  /**
   * How long a resolved entry stays fresh, in ms. Default: 60_000.
   * Must be a finite number > 0.
   */
  ttlMs?: number;
  /**
   * After a background refresh fails, how long to wait before trying
   * again, in ms. Default: 5_000 — bounds the refresh rate during a
   * resolver outage instead of re-resolving on every expired lookup.
   * Must be a finite number >= 0.
   */
  refreshBackoffMs?: number;
  /**
   * Maximum hostnames held. Default: 1024. Must be a positive integer.
   * When full, the entry expiring soonest is evicted.
   */
  maxHosts?: number;
  /** Clock; defaults to `Date.now`. Injectable for tests. */
  now?: () => number;
  /**
   * Resolver; defaults to `dns.promises.lookup(hostname, { all: true })`.
   * Injectable for tests — receives the hostname, returns the address
   * list (empty = treated as a resolution failure).
   */
  resolve?: (hostname: string) => Promise<LookupAddress[]>;
}

/** Snapshot from {@link DnsCache.getStats}. */
export interface DnsCacheStats {
  /** Hostnames currently cached. */
  hosts: number;
  /** Lookups served from a fresh entry. */
  hits: number;
  /** Lookups that resolved on demand (no entry cached). */
  misses: number;
  /** Lookups served from an expired entry while a refresh ran. */
  staleServed: number;
  /** Background refreshes started. */
  refreshes: number;
  /** Background refreshes that failed (stale entry kept serving). */
  refreshFailures: number;
  /**
   * `(hits + staleServed) / (hits + misses + staleServed)` — the share
   * of lookups that avoided a synchronous resolution. 0 when nothing
   * has been looked up yet.
   */
  hitRate: number;
}

interface CacheEntry {
  addresses: LookupAddress[];
  expiresAt: number;
  refreshing: boolean;
  /** Do not start another background refresh before this instant. */
  refreshNotBefore: number;
}

const DEFAULT_TTL_MS = 60_000;
const DEFAULT_REFRESH_BACKOFF_MS = 5_000;
const DEFAULT_MAX_HOSTS = 1024;

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

function normalizeAddresses(records: LookupAddress[]): LookupAddress[] {
  return records.map((r) => ({ address: r.address, family: r.family === 6 ? 6 : 4 }));
}

export class DnsCache {
  private readonly ttlMs: number;
  private readonly refreshBackoffMs: number;
  private readonly maxHosts: number;
  private readonly now: () => number;
  private readonly resolve: (hostname: string) => Promise<LookupAddress[]>;
  private readonly entries = new Map<string, CacheEntry>();
  private hits = 0;
  private misses = 0;
  private staleServed = 0;
  private refreshes = 0;
  private refreshFailures = 0;

  constructor(opts: DnsCacheOptions = {}) {
    this.ttlMs = opts.ttlMs ?? DEFAULT_TTL_MS;
    if (!Number.isFinite(this.ttlMs) || this.ttlMs <= 0) {
      throw new RangeError(`DnsCache: ttlMs must be a finite number > 0, got ${opts.ttlMs}`);
    }
    this.refreshBackoffMs = opts.refreshBackoffMs ?? DEFAULT_REFRESH_BACKOFF_MS;
    if (!Number.isFinite(this.refreshBackoffMs) || this.refreshBackoffMs < 0) {
      throw new RangeError(
        `DnsCache: refreshBackoffMs must be a finite number >= 0, got ${opts.refreshBackoffMs}`
      );
    }
    this.maxHosts = opts.maxHosts ?? DEFAULT_MAX_HOSTS;
    if (!Number.isInteger(this.maxHosts) || this.maxHosts <= 0) {
      throw new RangeError(
        `DnsCache: maxHosts must be a positive integer, got ${opts.maxHosts}`
      );
    }
    if (opts.now !== undefined && typeof opts.now !== "function") {
      throw new RangeError("DnsCache: now must be a function");
    }
    this.now = opts.now ?? Date.now;
    if (opts.resolve !== undefined && typeof opts.resolve !== "function") {
      throw new RangeError("DnsCache: resolve must be a function");
    }
    this.resolve = opts.resolve ?? defaultResolve;
  }

  /**
   * `dns.lookup`-compatible resolver. Safe to hand directly to an
   * `http.Agent` (`new Agent({ lookup: cache.lookup })`) or to a single
   * request's options — it is a bound arrow function, so no `this`
   * context is needed.
   *
   * Serves fresh entries (hit), resolves on a miss, and serves expired
   * entries while refreshing in the background (stale). A resolution
   * error reaches the callback only when no entry exists at all.
   */
  readonly lookup: LookupFunction = (hostname, options, callback): void => {
    const opts = (typeof options === "object" && options !== null ? options : {}) as {
      family?: number;
      all?: boolean;
    };
    if (typeof hostname !== "string" || hostname.length === 0) {
      callback(dnsError("ENOTFOUND", String(hostname)), "", 0);
      return;
    }
    const serve = (addresses: LookupAddress[]): void => {
      const family = opts.family;
      const filtered =
        family === 4 || family === 6 ? addresses.filter((a) => a.family === family) : addresses;
      if (filtered.length === 0) {
        // Honest ENOTFOUND: the resolver gave us nothing usable for the
        // requested family — same signal the OS resolver would produce.
        callback(dnsError("ENOTFOUND", hostname), "", 0);
        return;
      }
      if (opts.all === true) {
        // The `dns.lookup` contract with `{ all: true }` resolves to an
        // address list; the cast is the dual-callback shape this shim
        // supports (single-address otherwise).
        (callback as unknown as (
          err: NodeJS.ErrnoException | null,
          addresses: LookupAddress[]
        ) => void)(null, filtered);
      } else {
        const first = filtered[0];
        callback(null, first.address, first.family);
      }
    };
    const now = this.now();
    const entry = this.entries.get(hostname);
    if (entry !== undefined && entry.expiresAt > now) {
      this.hits += 1;
      serve(entry.addresses);
      return;
    }
    if (entry !== undefined) {
      // Expired: serve stale, refresh in the background. The delivery
      // proceeds on the old address instead of waiting on the resolver.
      this.staleServed += 1;
      serve(entry.addresses);
      this.refreshInBackground(hostname, entry, now);
      return;
    }
    this.misses += 1;
    this.resolveAndCache(hostname).then(
      (addresses) => serve(addresses),
      (err) => callback(asErrno(err, hostname), "", 0)
    );
  };

  /** Current counters; `hitRate` is 0 until the first lookup. */
  getStats(): DnsCacheStats {
    const total = this.hits + this.misses + this.staleServed;
    return {
      hosts: this.entries.size,
      hits: this.hits,
      misses: this.misses,
      staleServed: this.staleServed,
      refreshes: this.refreshes,
      refreshFailures: this.refreshFailures,
      hitRate: total === 0 ? 0 : (this.hits + this.staleServed) / total,
    };
  }

  /**
   * Prometheus exposition for `GET /metrics` (`relay_dns_cache_*`).
   * Empty string until the first lookup — the activity-gated convention,
   * so a relay without the feature exposes no new series.
   */
  render(): string {
    const total = this.hits + this.misses + this.staleServed;
    if (total === 0) return "";
    const lines = [
      "# HELP relay_dns_cache_lookups_total Outbound DNS cache lookup outcomes (WR-92): hit = fresh entry served, miss = resolved on demand, stale = expired entry served while a background refresh ran.",
      "# TYPE relay_dns_cache_lookups_total counter",
      `relay_dns_cache_lookups_total{result="hit"} ${this.hits}`,
      `relay_dns_cache_lookups_total{result="miss"} ${this.misses}`,
      `relay_dns_cache_lookups_total{result="stale"} ${this.staleServed}`,
      "# HELP relay_dns_cache_refresh_failures_total Background DNS refresh failures that kept serving the stale entry (WR-92).",
      "# TYPE relay_dns_cache_refresh_failures_total counter",
      `relay_dns_cache_refresh_failures_total ${this.refreshFailures}`,
      "# HELP relay_dns_cache_hosts Hostnames currently held in the outbound DNS cache (WR-92).",
      "# TYPE relay_dns_cache_hosts gauge",
      `relay_dns_cache_hosts ${this.entries.size}`,
    ];
    return lines.join("\n") + "\n";
  }

  /** Drop all entries and reset the refresh backoff state. Counters are kept. */
  clear(): void {
    this.entries.clear();
  }

  private async resolveAndCache(hostname: string): Promise<LookupAddress[]> {
    const addresses = normalizeAddresses(await this.resolve(hostname));
    if (addresses.length === 0) throw dnsError("ENOTFOUND", hostname);
    if (!this.entries.has(hostname) && this.entries.size >= this.maxHosts) {
      this.evictSoonestExpiring();
    }
    this.entries.set(hostname, {
      addresses,
      expiresAt: this.now() + this.ttlMs,
      refreshing: false,
      refreshNotBefore: 0,
    });
    return addresses;
  }

  private refreshInBackground(hostname: string, entry: CacheEntry, now: number): void {
    if (entry.refreshing || now < entry.refreshNotBefore) return;
    entry.refreshing = true;
    this.refreshes += 1;
    this.resolve(hostname).then(
      (records) => {
        const addresses = normalizeAddresses(records);
        if (addresses.length > 0) {
          // A refresh that resolves empty never evicts the stale entry:
          // an empty answer is not fresher data, it is no data.
          entry.addresses = addresses;
          entry.expiresAt = this.now() + this.ttlMs;
        }
        entry.refreshing = false;
        entry.refreshNotBefore = 0;
      },
      () => {
        // Refresh failed: keep serving the stale entry. Only a lookup
        // with no entry at all surfaces a DNS error to the caller.
        entry.refreshing = false;
        entry.refreshNotBefore = this.now() + this.refreshBackoffMs;
        this.refreshFailures += 1;
      }
    );
  }

  private evictSoonestExpiring(): void {
    let victim: string | undefined;
    let victimExpiresAt = Infinity;
    for (const [hostname, entry] of this.entries) {
      if (entry.expiresAt < victimExpiresAt) {
        victim = hostname;
        victimExpiresAt = entry.expiresAt;
      }
    }
    if (victim !== undefined) this.entries.delete(victim);
  }
}

function asErrno(err: unknown, hostname: string): NodeJS.ErrnoException {
  if (err instanceof Error) {
    const errno = err as NodeJS.ErrnoException;
    if (typeof errno.code === "string") return errno;
    errno.code = "ENOTFOUND";
    errno.hostname = hostname;
    return errno;
  }
  return dnsError("ENOTFOUND", hostname);
}
