import { promises as dnsPromises, type LookupAddress } from "node:dns";
import type { LookupFunction } from "node:net";

/**
 * Outbound DNS resolution pinning (WR-194).
 *
 * DNS hijacking (a compromised or spoofed resolver answering with
 * attacker-controlled IPs) is invisible to the TLS layer when the
 * attacker also holds a valid certificate for the hostname — WR-21's
 * SPKI pinning catches a wrong *key*, not a wrong *address*. This module
 * pins the *resolution result* itself:
 *
 * - the first successful resolution of a hostname establishes the
 *   baseline (the pinned address set);
 * - every later resolution is compared against the baseline; a drift
 *   (any address added or removed) is a pin mismatch.
 *
 * Modes:
 *
 * - `"enforce"` (default, fail-closed): the lookup is refused with
 *   {@link DnsPinMismatchError} — the delivery attempt fails and follows
 *   the normal retry / dead-letter path, and the mismatch is reported
 *   via `onMismatch` (the server audits it as `dns_pin_mismatch`). The
 *   old baseline is kept: the relay never adopts unverified addresses.
 * - `"warn"` (warn-only): the drifted addresses are served anyway, the
 *   mismatch is reported once, and the new set becomes the baseline —
 *   so a legitimate rotation (cloud LB, failover) audits exactly once
 *   instead of spamming the audit log on every lookup.
 *
 * The pin is `dns.lookup`-compatible: hand `pin.lookup` to an
 * `http.Agent`'s `lookup` option or to a single request's options. It
 * wraps an inner `LookupFunction` (e.g. the WR-92 `DnsCache#lookup`) and
 * judges exactly the addresses the connection will use — orthogonal to
 * the cache (which only caches) and to WR-21 TLS pinning (which judges
 * the handshake key, not the address).
 *
 * Scope notes:
 *
 * - Pinning is per hostname; endpoints sharing a hostname share the pin.
 * - The pin always asks the inner lookup for the full address list
 *   (`{ all: true }`) and compares sorted sets, so resolver round-robin
 *   *ordering* never trips it — but a resolver that returns varying
 *   *subsets* (aggressive round-robin) will read as drift. Prefer
 *   `"warn"` for such downstreams, or `reset()` after a verified change.
 * - A resolution *failure* is not a mismatch: the inner error passes
 *   through untouched and the delivery follows the normal DNS-failure
 *   path. Only a *changed successful answer* is judged.
 * - Per-endpoint DoH bindings (WR-170) resolve through their own DoH
 *   caches and are not pin-checked; the pin wraps the shared
 *   pool-level / one-off lookup.
 * - With keep-alive pooling (WR-24, the default), an established pooled
 *   connection is reused without re-resolving — a drift is therefore
 *   detected when the *next new connection* resolves, not mid-stream on
 *   a live connection. That is the correct security semantic (the live
 *   connection already went to the pinned address); the pin guards
 *   every fresh resolution.
 *
 * Zero dependencies (`node:dns` + `node:net` types only).
 */

/** Pin enforcement mode. `"enforce"` refuses drifted lookups; `"warn"` serves them and audits once. */
export type DnsPinMode = "enforce" | "warn";

/** Details of one detected DNS resolution drift, delivered to `onMismatch`. */
export interface DnsPinMismatchInfo {
  /** The hostname whose resolution drifted. */
  hostname: string;
  /** The pinned baseline addresses (sorted, deduplicated). */
  pinned: string[];
  /** The drifted addresses just observed (sorted, deduplicated). */
  observed: string[];
  /** The pin's mode when the drift was detected. */
  mode: DnsPinMode;
  /** ISO-8601 timestamp of the detection. */
  at: string;
}

/** The error a pin-checked lookup fails with when the resolution drifted in `"enforce"` mode. */
export class DnsPinMismatchError extends Error {
  /** Stable machine-readable code, in the `NodeJS.ErrnoException` shape. */
  readonly code = "EDNSPINMISMATCH";
  /** The hostname whose resolution drifted. */
  readonly hostname: string;
  /** The pinned baseline addresses (sorted, deduplicated). */
  readonly pinned: string[];
  /** The drifted addresses just observed (sorted, deduplicated). */
  readonly observed: string[];

  constructor(hostname: string, pinned: string[], observed: string[]) {
    super(
      `DNS pin mismatch for ${hostname}: resolved [${observed.join(", ")}] but pinned [${pinned.join(", ")}]`
    );
    this.name = "DnsPinMismatchError";
    this.hostname = hostname;
    this.pinned = pinned;
    this.observed = observed;
  }
}

/** Tuning for {@link DnsPin}. All values are validated up front. */
export interface DnsPinOptions {
  /**
   * `"enforce"` (default): refuse drifted lookups fail-closed.
   * `"warn"`: serve drifted addresses, audit once per distinct drift,
   * adopt the new baseline.
   */
  mode?: DnsPinMode;
  /**
   * The lookup whose answers are pin-checked (e.g. a WR-92
   * `DnsCache#lookup`). Defaults to the system resolver
   * (`dns.promises.lookup(hostname, { all: true })`).
   */
  inner?: LookupFunction;
  /**
   * Maximum hostnames pinned. Default: 1024. Must be a positive
   * integer. When full, the hostname pinned longest ago is evicted
   * (its next lookup re-baselines).
   */
  maxHosts?: number;
  /** Clock; defaults to `Date.now`. Injectable for tests. */
  now?: () => number;
  /** Called once per detected drift (both modes). */
  onMismatch?: (info: DnsPinMismatchInfo) => void;
}

/** Snapshot from {@link DnsPin.getStats}. */
export interface DnsPinStats {
  /** Hostnames currently pinned. */
  hosts: number;
  /** Lookups pin-checked (baseline hits + first-time baselines). */
  checked: number;
  /** Resolution drifts detected (both modes). */
  mismatches: number;
  /** Lookups refused (`"enforce"` mode drifts). */
  refused: number;
  /** Drifted lookups served with a warning (`"warn"` mode). */
  warned: number;
}

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

/** Normalize to sorted, deduplicated address strings — the pin key. */
function pinKey(records: LookupAddress[]): string[] {
  const seen = new Set<string>();
  for (const r of records) {
    if (typeof r.address === "string" && r.address.length > 0) seen.add(r.address);
  }
  return [...seen].sort();
}

export class DnsPin {
  private readonly mode: DnsPinMode;
  private readonly inner: LookupFunction;
  private readonly maxHosts: number;
  private readonly now: () => number;
  private readonly onMismatch?: (info: DnsPinMismatchInfo) => void;
  /** hostname -> sorted pinned addresses. Insertion order = pin age (for eviction). */
  private readonly pins = new Map<string, string[]>();
  private checked = 0;
  private mismatches = 0;
  private refused = 0;
  private warned = 0;

  constructor(opts: DnsPinOptions = {}) {
    this.mode = opts.mode ?? "enforce";
    if (this.mode !== "enforce" && this.mode !== "warn") {
      throw new RangeError(`DnsPin: mode must be "enforce" or "warn", got ${JSON.stringify(opts.mode)}`);
    }
    if (opts.inner !== undefined && typeof opts.inner !== "function") {
      throw new RangeError("DnsPin: inner must be a function");
    }
    const inner = opts.inner;
    // Default: the system resolver, always answering in the
    // `{ all: true }` list shape — `lookup` below only ever asks the
    // inner for the full list and does its own serving, so the default
    // inner stays shape-simple on purpose.
    const systemInner: LookupFunction = (hostname, _options, callback) => {
      defaultResolve(hostname).then(
        (records) => {
          (callback as unknown as (err: null, addresses: LookupAddress[]) => void)(null, records);
        },
        (err: unknown) => {
          const errno =
            err instanceof Error ? (err as NodeJS.ErrnoException) : dnsError("ENOTFOUND", hostname);
          callback(errno, "", 0);
        }
      );
    };
    this.inner = inner ?? systemInner;
    this.maxHosts = opts.maxHosts ?? DEFAULT_MAX_HOSTS;
    if (!Number.isInteger(this.maxHosts) || this.maxHosts <= 0) {
      throw new RangeError(`DnsPin: maxHosts must be a positive integer, got ${opts.maxHosts}`);
    }
    if (opts.now !== undefined && typeof opts.now !== "function") {
      throw new RangeError("DnsPin: now must be a function");
    }
    this.now = opts.now ?? Date.now;
    if (opts.onMismatch !== undefined && typeof opts.onMismatch !== "function") {
      throw new RangeError("DnsPin: onMismatch must be a function");
    }
    this.onMismatch = opts.onMismatch;
  }

  /**
   * `dns.lookup`-compatible pin-checked resolver. Safe to hand directly
   * to an `http.Agent` (`new Agent({ lookup: pin.lookup })`) or to a
   * single request's options — it is a bound arrow function, so no `this`
   * context is needed.
   *
   * The inner lookup is always asked for the full address list; the pin
   * compares sorted sets against the baseline (first successful answer),
   * then serves the caller in the shape it asked for (single address or
   * `{ all: true }` list, family-filtered). Inner errors pass through
   * untouched — a failed resolution is not a pin judgment.
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
    const serve = (records: LookupAddress[]): void => {
      const family = opts.family;
      const filtered =
        family === 4 || family === 6 ? records.filter((r) => r.family === family) : records;
      if (filtered.length === 0) {
        callback(dnsError("ENOTFOUND", hostname), "", 0);
        return;
      }
      if (opts.all === true) {
        (callback as unknown as (
          err: NodeJS.ErrnoException | null,
          addresses: LookupAddress[]
        ) => void)(null, filtered);
      } else {
        const first = filtered[0];
        callback(null, first.address, first.family);
      }
    };
    // Always judge the whole answer: ask the inner for the full list
    // regardless of what the caller wants served. The cast is the
    // dual-callback shape this shim supports (list on `{ all: true }`,
    // single address otherwise); a non-conforming inner that answers a
    // single address is folded into a one-element list.
    type InnerAllCallback = (
      err: NodeJS.ErrnoException | null,
      addresses: LookupAddress[] | string,
      family?: number
    ) => void;
    (this.inner as unknown as (
      hostname: string,
      options: { all: true },
      callback: InnerAllCallback
    ) => void)(hostname, { all: true }, (err, addresses, family) => {
      if (err !== null && err !== undefined) {
        callback(err, "", 0);
        return;
      }
      const list: LookupAddress[] = Array.isArray(addresses)
        ? addresses
        : typeof addresses === "string" && addresses.length > 0
          ? [{ address: addresses, family: family === 6 ? 6 : 4 }]
          : [];
      const observed = pinKey(list);
      if (observed.length === 0) {
        // Honest ENOTFOUND: the resolver gave us nothing usable — same
        // signal the OS resolver would produce. Not a mismatch.
        callback(dnsError("ENOTFOUND", hostname), "", 0);
        return;
      }
      const pinned = this.pins.get(hostname);
      if (pinned === undefined) {
        // First successful resolution establishes the baseline.
        this.evictIfFull();
        this.pins.set(hostname, observed);
        this.checked += 1;
        serve(list);
        return;
      }
      if (sameSet(pinned, observed)) {
        this.checked += 1;
        serve(list);
        return;
      }
      // Drift detected.
      this.mismatches += 1;
      const info: DnsPinMismatchInfo = {
        hostname,
        pinned: [...pinned],
        observed: [...observed],
        mode: this.mode,
        at: new Date(this.now()).toISOString(),
      };
      if (this.mode === "warn") {
        // Warn-only: serve the drifted answer, audit once, adopt the new
        // baseline so a legitimate rotation does not spam the audit log.
        this.warned += 1;
        this.pins.delete(hostname);
        this.pins.set(hostname, observed);
        this.onMismatch?.(info);
        serve(list);
        return;
      }
      // Enforce (fail-closed): refuse the lookup; the old baseline is
      // kept — the relay never adopts unverified addresses.
      this.refused += 1;
      this.onMismatch?.(info);
      callback(new DnsPinMismatchError(hostname, [...pinned], [...observed]), "", 0);
    });
  };

  /** Current counters. */
  getStats(): DnsPinStats {
    return {
      hosts: this.pins.size,
      checked: this.checked,
      mismatches: this.mismatches,
      refused: this.refused,
      warned: this.warned,
    };
  }

  /** The pinned baseline for a hostname (sorted), or `undefined` when not pinned. */
  getPinned(hostname: string): string[] | undefined {
    const pinned = this.pins.get(hostname);
    return pinned === undefined ? undefined : [...pinned];
  }

  /**
   * Drop pin baselines — `reset(hostname)` for one hostname,
   * `reset()` for all. The next successful lookup re-baselines. The
   * operator escape hatch after verifying a legitimate address change;
   * counters are kept.
   */
  reset(hostname?: string): void {
    if (hostname === undefined) {
      this.pins.clear();
    } else {
      this.pins.delete(hostname);
    }
  }

  /**
   * Prometheus exposition for `GET /metrics` (`relay_dns_pin_*`).
   * Empty string until the first pin-checked lookup — the
   * activity-gated convention, so a relay without the feature exposes
   * no new series.
   */
  render(): string {
    if (this.checked + this.mismatches === 0) return "";
    const lines = [
      "# HELP relay_dns_pin_lookups_total Outbound DNS pin-checked lookups (WR-194): checked = served against a matching baseline (or first-time baseline), refused = drifted lookup refused in enforce mode, warned = drifted lookup served in warn mode.",
      "# TYPE relay_dns_pin_lookups_total counter",
      `relay_dns_pin_lookups_total{result="checked"} ${this.checked}`,
      `relay_dns_pin_lookups_total{result="refused"} ${this.refused}`,
      `relay_dns_pin_lookups_total{result="warned"} ${this.warned}`,
      "# HELP relay_dns_pin_mismatches_total DNS resolution drifts detected against the pinned baseline (WR-194).",
      "# TYPE relay_dns_pin_mismatches_total counter",
      `relay_dns_pin_mismatches_total ${this.mismatches}`,
      "# HELP relay_dns_pin_hosts Hostnames currently pinned (WR-194).",
      "# TYPE relay_dns_pin_hosts gauge",
      `relay_dns_pin_hosts ${this.pins.size}`,
    ];
    return lines.join("\n") + "\n";
  }

  private evictIfFull(): void {
    if (this.pins.size < this.maxHosts) return;
    // Evict the longest-pinned hostname (insertion order = pin age);
    // its next lookup simply re-baselines.
    const oldest = this.pins.keys().next();
    if (!oldest.done) this.pins.delete(oldest.value);
  }
}

function sameSet(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}
