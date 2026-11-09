import { promises as dnsPromises, type LookupAddress } from "node:dns";
import { isIP } from "node:net";
import type { LookupFunction } from "node:net";

/**
 * Outbound SSRF guard (WR-373).
 *
 * The relay dials whatever hostname a tenant or operator configured —
 * and until now nothing checked the *resolved IP* before connecting.
 * `ip-acl.ts` (WR-53) only guards the inbound path, and `dns-pin.ts`
 * (WR-194) only judges whether the resolution *drifted*, not whether
 * the address itself is private. A hostname that resolves (or is later
 * re-bound) to a loopback, RFC 1918, link-local, or cloud-metadata
 * address (169.254.169.254) would be dialed directly — SSRF straight
 * into internal services and credential endpoints.
 *
 * This module wraps the lookup the agent actually dials (the WR-92
 * `DnsCache#lookup`, pin-checked by WR-194 when configured) and
 * classifies *every* resolved address before connect:
 *
 * - loopback (`127.0.0.0/8`, `::1`), RFC 1918 (`10/8`, `172.16/12`,
 *   `192.168/16`), link-local (`169.254.0.0/16`, `fe80::/10`),
 *   unique-local (`fc00::/7`), unspecified (`0.0.0.0/8`, `::`),
 *   multicast (`224.0.0.0/4`, `ff00::/8`) — any hit fails closed.
 *
 * - One private hit refuses the whole lookup with
 *   {@link OutboundSsrfBlockedError} *before* a single payload byte is
 *   written: the attempt fails as `"non_retryable"` (no retry budget
 *   burned, no circuit-breaker touch — the endpoint was never
 *   contacted, so the control plane learns nothing, mirroring the
 *   WR-115 transform-failure rule) and follows the dead-letter path.
 *   The block is reported via `onBlocked` (the server audits it as
 *   `outbound_ssrf_blocked` with hostname, category, and the offending
 *   addresses). Resolved private IPs go into that audit event only —
 *   never into metrics labels, and never into the error message (which
 *   also rides the `dead_letter` audit's `error` field).
 *
 * - Per-endpoint `allowPrivateTargets` (exact `targetUrl` → `true`)
 *   opts an endpoint into intentional private targets: a private hit
 *   is served and reported via `onAllowlisted` (audited as
 *   `outbound_ssrf_allowlisted` on *every* allowlisted lookup).
 *
 * - Through an HTTP CONNECT (WR-27) or SOCKS5 (WR-171) proxy the relay
 *   never dials the target directly — the tunnel agent resolves the
 *   proxy host, not the target — so the guard skips the check and the
 *   skip is reported via `onProxiedSkip` once per endpoint (audited as
 *   `outbound_ssrf_proxy_skipped`). Export-side validation is the
 *   proxy's responsibility, and the README says so.
 *
 * The guard is `dns.lookup`-compatible per endpoint: `bindingFor`
 * returns the bound lookup the pooled agent (or the one-off request)
 * dials through, so the guard judges exactly the addresses the
 * connection will use — no second resolution, no TOCTOU window. The
 * pool key binds the guard mode, so an allowlisted endpoint can never
 * ride a guarded endpoint's agent, or vice versa.
 *
 * Scope notes (mirroring the WR-194 pin):
 *
 * - The guard covers the HTTP/1.1 delivery path (pooled and one-off).
 *   The opt-in HTTP/2 session pool and the WebSocket pool manage their
 *   own connections and keep the OS resolver — they are not
 *   guard-checked.
 * - Per-endpoint DoH bindings (WR-170) *are* guard-checked: the sender
 *   wraps the endpoint's DoH lookup with the same per-endpoint
 *   binding, so a DoH-resolved connection is judged like any other.
 *   Downstream probes (WR-34) resolve through the raw cache lookup
 *   and are not guard-checked, like the pin.
 * - With keep-alive pooling (WR-24, the default), an established
 *   pooled connection is reused without re-resolving — a re-bind is
 *   therefore caught when the *next new connection* resolves, not
 *   mid-stream on a live connection. That is the correct security
 *   semantic (the live connection already went to a checked address);
 *   the guard judges every fresh resolution.
 * - IPv4-mapped IPv6 addresses (`::ffff:10.0.0.1`) are classified by
 *   their embedded IPv4 address — a mapped private address is still
 *   private.
 *
 * Zero dependencies (`node:dns` + `node:net` types only).
 */

/**
 * What a resolved address is, for SSRF purposes. `"public"` is the
 * only category the guard serves without a second thought; every other
 * category except `"public"` is a block (or an allowlisted serve).
 */
export type SsrfAddressCategory =
  | "loopback"
  | "rfc1918"
  | "link-local"
  | "unique-local"
  | "unspecified"
  | "multicast"
  | "unparsable"
  | "public";

/** The guard's verdict for one endpoint: which lookup behaviour applies. */
export type SsrfGuardMode = "guarded" | "allowlisted" | "proxied";

/**
 * The per-endpoint binding the sender hands to the pool / one-off
 * request path: the `dns.lookup`-compatible resolver the agent dials
 * through, plus the mode the pool key binds (see `src/keepalive.ts`).
 */
export interface SsrfGuardAgentBinding {
  /** Pool-key mode: guarded (default), allowlisted, or proxied. */
  mode: SsrfGuardMode;
  /** The `dns.lookup`-compatible resolver the agent dials through. */
  lookup: LookupFunction;
}

/** Details of one blocked lookup, delivered to `onBlocked`. */
export interface OutboundSsrfBlockedInfo {
  /** The hostname whose resolution hit a private address. */
  hostname: string;
  /** Category of the first offending address (sorted for determinism). */
  category: SsrfAddressCategory;
  /** Every offending resolved address (sorted, deduplicated). Audit-only: never a metrics label. */
  addresses: string[];
  /** ISO-8601 timestamp of the block. */
  at: string;
}

/** Details of one allowlisted serve, delivered to `onAllowlisted`. */
export interface OutboundSsrfAllowlistedInfo {
  /** The hostname whose private address was served. */
  hostname: string;
  /** Category of the first private address (sorted for determinism). */
  category: SsrfAddressCategory;
  /** Every private resolved address (sorted, deduplicated). Audit-only: never a metrics label. */
  addresses: string[];
  /** ISO-8601 timestamp of the serve. */
  at: string;
}

/** Details of one proxied skip, delivered to `onProxiedSkip` (once per endpoint). */
export interface OutboundSsrfProxySkippedInfo {
  /** The target hostname (never dialed directly). */
  hostname: string;
  /** The proxy URL the delivery tunnels through. */
  proxyUrl: string;
  /** ISO-8601 timestamp of the skip audit. */
  at: string;
}

/**
 * The error a guard-checked lookup fails with when a resolved address
 * is private. Classified `"non_retryable"` by `classifyFailure` — the
 * item dead-letters on the first attempt without burning retry budget
 * or touching the circuit breaker.
 *
 * The message names the hostname and the category only — the offending
 * addresses ride the `outbound_ssrf_blocked` audit event, never the
 * error (which also lands in the `dead_letter` audit's `error` field)
 * and never a metrics label.
 */
export class OutboundSsrfBlockedError extends Error {
  /** Stable machine-readable code, in the `NodeJS.ErrnoException` shape. */
  readonly code = "ESSRFPRIVATE";
  /** The hostname whose resolution hit a private address. */
  readonly hostname: string;
  /** Category of the first offending address. */
  readonly category: SsrfAddressCategory;
  /** Every offending resolved address (sorted, deduplicated). Audit-only. */
  readonly addresses: string[];

  constructor(hostname: string, category: SsrfAddressCategory, addresses: string[]) {
    super(
      `Outbound SSRF guard blocked ${hostname}: resolved address is ${category}`
    );
    this.name = "OutboundSsrfBlockedError";
    this.hostname = hostname;
    this.category = category;
    this.addresses = [...addresses];
  }
}

/** Tuning for {@link OutboundSsrfGuard}. All values are validated up front. */
export interface OutboundSsrfGuardOptions {
  /**
   * The lookup whose answers are guard-checked (e.g. the WR-194
   * pin-checked WR-92 `DnsCache#lookup`). Defaults to the system
   * resolver (`dns.promises.lookup(hostname, { all: true })`).
   */
  inner?: LookupFunction;
  /**
   * Per-endpoint opt-in for intentional private targets: exact
   * `targetUrl` → `true`. Endpoints without an entry are guarded
   * (private addresses refused). Must be explicit — there is no
   * wildcard, and a hostname allowlist is deliberately not offered:
   * the guard judges resolved IPs, not names.
   */
  allowPrivateTargets?: Record<string, boolean>;
  /** Called once per blocked lookup. */
  onBlocked?: (info: OutboundSsrfBlockedInfo) => void;
  /** Called once per allowlisted serve (every time, not once). */
  onAllowlisted?: (info: OutboundSsrfAllowlistedInfo) => void;
  /** Called once per proxied endpoint (the first binding, not per lookup). */
  onProxiedSkip?: (info: OutboundSsrfProxySkippedInfo) => void;
  /** Clock; defaults to `Date.now`. Injectable for tests. */
  now?: () => number;
}

/** Snapshot from {@link OutboundSsrfGuard.getStats}. */
export interface OutboundSsrfGuardStats {
  /** Lookups served (every address public). */
  checked: number;
  /** Lookups refused (a resolved address was private). */
  blocked: number;
  /** Lookups served despite a private address (allowlisted endpoint). */
  allowlisted: number;
  /** Endpoints whose proxy skip was audited (once each). */
  proxiedSkipped: number;
  /** Blocks by resolved-address category. */
  blocksByCategory: Record<string, number>;
}

/** The blocking categories, in audit/metric order. */
const BLOCKING_CATEGORIES: SsrfAddressCategory[] = [
  "loopback",
  "rfc1918",
  "link-local",
  "unique-local",
  "unspecified",
  "multicast",
  "unparsable",
];

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
 * Classify one resolved address literal. IPv4-mapped IPv6 addresses
 * are classified by their embedded IPv4 address. Unparsable input is
 * `"unparsable"` — fail-closed, never served as public.
 */
export function classifyIpAddress(address: string): SsrfAddressCategory {
  if (typeof address !== "string" || address.length === 0) return "unparsable";
  const family = isIP(address);
  if (family === 4) return classifyIpv4(address);
  if (family === 6) return classifyIpv6(address);
  return "unparsable";
}

function parseIpv4(address: string): number | undefined {
  const parts = address.split(".");
  if (parts.length !== 4) return undefined;
  let value = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return undefined;
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return undefined;
    value = value * 256 + n;
  }
  return value >>> 0;
}

function classifyIpv4(address: string): SsrfAddressCategory {
  const value = parseIpv4(address);
  if (value === undefined) return "unparsable";
  // 0.0.0.0/8 — "this network": unspecified (0.0.0.0 itself included).
  if ((value >>> 24) === 0) return "unspecified";
  // 127.0.0.0/8 — loopback.
  if ((value >>> 24) === 127) return "loopback";
  // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 — RFC 1918.
  if ((value >>> 24) === 10) return "rfc1918";
  if ((value >>> 20) === 0xac1) return "rfc1918";
  if ((value >>> 16) === 0xc0a8) return "rfc1918";
  // 169.254.0.0/16 — link-local (the cloud-metadata range).
  if ((value >>> 16) === 0xa9fe) return "link-local";
  // 224.0.0.0/4 — multicast.
  if ((value >>> 28) === 0xe) return "multicast";
  return "public";
}

/** Parse an IPv6 literal (with `::` expansion and embedded IPv4) to a 128-bit bigint. */
function parseIpv6(address: string): bigint | undefined {
  let head = address;
  let embedded: number | undefined;
  // Embedded IPv4 tail (e.g. `::ffff:10.0.0.1`): the last colon-group
  // is dotted-quad and occupies the low 32 bits.
  const lastColon = address.lastIndexOf(":");
  if (lastColon !== -1 && address.slice(lastColon + 1).includes(".")) {
    embedded = parseIpv4(address.slice(lastColon + 1));
    if (embedded === undefined) return undefined;
    head = address.slice(0, lastColon + 1) + "0:0";
  }
  const halves = head.split("::");
  if (halves.length > 2) return undefined;
  const parseGroups = (s: string): number[] | undefined => {
    if (s === "") return [];
    const out: number[] = [];
    for (const g of s.split(":")) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return undefined;
      out.push(parseInt(g, 16));
    }
    return out;
  };
  let groups: number[];
  if (halves.length === 2) {
    const left = parseGroups(halves[0]);
    const right = parseGroups(halves[1]);
    if (left === undefined || right === undefined) return undefined;
    const missing = 8 - left.length - right.length;
    if (missing < 0) return undefined;
    groups = [...left, ...new Array<number>(missing).fill(0), ...right];
  } else {
    const parsed = parseGroups(head);
    if (parsed === undefined || parsed.length !== 8) return undefined;
    groups = parsed;
  }
  let value = 0n;
  for (const g of groups) value = (value << 16n) | BigInt(g);
  if (embedded !== undefined) {
    // The placeholder `0:0` groups above hold the embedded tail's slot.
    value = (value & ~0xffffffffn) | BigInt(embedded);
  }
  return value;
}

function classifyIpv6(address: string): SsrfAddressCategory {
  const value = parseIpv6(address);
  if (value === undefined) return "unparsable";
  // IPv4-mapped (`::ffff:0:0/96`): judge the embedded IPv4 address.
  if ((value >> 32n) === 0xffffn) {
    return classifyIpv4(
      [
        Number((value >> 24n) & 0xffn),
        Number((value >> 16n) & 0xffn),
        Number((value >> 8n) & 0xffn),
        Number(value & 0xffn),
      ].join(".")
    );
  }
  // :: — unspecified.
  if (value === 0n) return "unspecified";
  // ::1 — loopback.
  if (value === 1n) return "loopback";
  // fe80::/10 — link-local (top 10 bits 1111111010).
  if ((value >> 118n) === 0x3fan) return "link-local";
  // fc00::/7 — unique-local.
  if ((value >> 121n) === 0x7en) return "unique-local";
  // ff00::/8 — multicast.
  if ((value >> 120n) === 0xffn) return "multicast";
  return "public";
}

export class OutboundSsrfGuard {
  private readonly inner: LookupFunction;
  private readonly allowPrivateTargets: Readonly<Record<string, boolean>>;
  private readonly now: () => number;
  private readonly onBlocked?: (info: OutboundSsrfBlockedInfo) => void;
  private readonly onAllowlisted?: (info: OutboundSsrfAllowlistedInfo) => void;
  private readonly onProxiedSkip?: (info: OutboundSsrfProxySkippedInfo) => void;
  /**
   * Bound lookups, per inner lookup and per `(targetUrl, proxyUrl)` —
   * so the same endpoint always dials through the same closure (and
   * the pool's agent creation sees a stable lookup), and the
   * proxy-skip audit fires once per endpoint, not once per attempt.
   */
  private readonly bindings = new WeakMap<LookupFunction, Map<string, SsrfGuardAgentBinding>>();
  /** Endpoints whose proxy skip was already audited. */
  private readonly proxySkipAudited = new Set<string>();
  private checked = 0;
  private blocked = 0;
  private allowlisted = 0;
  private proxiedSkipped = 0;
  private readonly blocksByCategory: Record<string, number> = Object.fromEntries(
    BLOCKING_CATEGORIES.map((c) => [c, 0])
  );

  constructor(opts: OutboundSsrfGuardOptions = {}) {
    if (opts.inner !== undefined && typeof opts.inner !== "function") {
      throw new RangeError("OutboundSsrfGuard: inner must be a function");
    }
    const inner = opts.inner;
    // Default: the system resolver, always answering in the
    // `{ all: true }` list shape — `bindingFor` below only ever asks
    // the inner for the full list and does its own serving, so the
    // default inner stays shape-simple on purpose (mirrors DnsPin).
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
    if (opts.allowPrivateTargets !== undefined) {
      if (
        opts.allowPrivateTargets === null ||
        typeof opts.allowPrivateTargets !== "object" ||
        Array.isArray(opts.allowPrivateTargets)
      ) {
        throw new RangeError("OutboundSsrfGuard: allowPrivateTargets must be a record of targetUrl -> boolean");
      }
      for (const [endpoint, value] of Object.entries(opts.allowPrivateTargets)) {
        if (typeof value !== "boolean") {
          throw new RangeError(
            `OutboundSsrfGuard: allowPrivateTargets for ${endpoint} must be a boolean, got ${JSON.stringify(value)}`
          );
        }
      }
    }
    this.allowPrivateTargets = opts.allowPrivateTargets ?? {};
    if (opts.now !== undefined && typeof opts.now !== "function") {
      throw new RangeError("OutboundSsrfGuard: now must be a function");
    }
    this.now = opts.now ?? Date.now;
    if (opts.onBlocked !== undefined && typeof opts.onBlocked !== "function") {
      throw new RangeError("OutboundSsrfGuard: onBlocked must be a function");
    }
    this.onBlocked = opts.onBlocked;
    if (opts.onAllowlisted !== undefined && typeof opts.onAllowlisted !== "function") {
      throw new RangeError("OutboundSsrfGuard: onAllowlisted must be a function");
    }
    this.onAllowlisted = opts.onAllowlisted;
    if (opts.onProxiedSkip !== undefined && typeof opts.onProxiedSkip !== "function") {
      throw new RangeError("OutboundSsrfGuard: onProxiedSkip must be a function");
    }
    this.onProxiedSkip = opts.onProxiedSkip;
  }

  /**
   * The per-endpoint binding the agent dials through. `targetUrl`
   * selects the endpoint's `allowPrivateTargets` entry; `proxyUrl`
   * (when the delivery tunnels) selects the proxied mode, which skips
   * classification — the relay never dials the target directly — and
   * audits the skip once per endpoint. `innerOverride` wraps a
   * different inner lookup for this endpoint (the per-endpoint DoH
   * lookup, WR-170); without it the guard's own inner is wrapped.
   *
   * The same `(targetUrl, proxyUrl)` always returns the same binding
   * object, so the pool sees a stable lookup across attempts.
   */
  bindingFor(
    targetUrl: string,
    proxyUrl?: string,
    innerOverride?: LookupFunction
  ): SsrfGuardAgentBinding {
    if (typeof targetUrl !== "string" || targetUrl.length === 0) {
      throw new RangeError("OutboundSsrfGuard: targetUrl must be a non-empty string");
    }
    if (proxyUrl !== undefined && typeof proxyUrl !== "string") {
      throw new RangeError("OutboundSsrfGuard: proxyUrl must be a string");
    }
    if (innerOverride !== undefined && typeof innerOverride !== "function") {
      throw new RangeError("OutboundSsrfGuard: innerOverride must be a function");
    }
    const inner = innerOverride ?? this.inner;
    let byInner = this.bindings.get(inner);
    if (byInner === undefined) {
      byInner = new Map<string, SsrfGuardAgentBinding>();
      this.bindings.set(inner, byInner);
    }
    const key = `${targetUrl}\n${proxyUrl ?? ""}`;
    const existing = byInner.get(key);
    if (existing !== undefined) return existing;
    const mode: SsrfGuardMode =
      proxyUrl !== undefined
        ? "proxied"
        : this.allowPrivateTargets[targetUrl] === true
          ? "allowlisted"
          : "guarded";
    if (mode === "proxied") {
      // The skip is a static configuration fact (this endpoint tunnels),
      // so it audits once per endpoint — not once per attempt — while
      // every allowlisted serve still audits every time.
      if (!this.proxySkipAudited.has(targetUrl)) {
        this.proxySkipAudited.add(targetUrl);
        this.proxiedSkipped += 1;
        let hostname = targetUrl;
        try {
          hostname = new URL(targetUrl).hostname;
        } catch {
          // Keep targetUrl as the hostname: the audit still names the
          // endpoint, and the sender only ever binds valid target URLs.
        }
        this.onProxiedSkip?.({
          hostname,
          proxyUrl: proxyUrl as string,
          at: new Date(this.now()).toISOString(),
        });
      }
    }
    const binding: SsrfGuardAgentBinding = {
      mode,
      lookup: this.makeLookup(inner, mode),
    };
    byInner.set(key, binding);
    return binding;
  }

  /** Current counters; `blocksByCategory` is a fresh object on every call. */
  getStats(): OutboundSsrfGuardStats {
    return {
      checked: this.checked,
      blocked: this.blocked,
      allowlisted: this.allowlisted,
      proxiedSkipped: this.proxiedSkipped,
      blocksByCategory: { ...this.blocksByCategory },
    };
  }

  /**
   * Prometheus exposition for `GET /metrics`
   * (`relay_outbound_ssrf_*`). Empty string until the first guarded
   * lookup (or proxy-skip audit) — the activity-gated convention, so
   * a relay without the feature exposes no new series. Labels carry
   * only the result and the category — resolved private IPs never
   * appear in metrics.
   */
  render(): string {
    if (this.checked + this.blocked + this.allowlisted + this.proxiedSkipped === 0) return "";
    const lines = [
      "# HELP relay_outbound_ssrf_lookups_total Outbound SSRF-guarded lookups (WR-373): checked = served (every resolved address public), blocked = refused before connect (a resolved address was private), allowlisted = served despite a private address (endpoint opted into allowPrivateTargets), skipped = proxied endpoint (relay never dials the target directly; audited once per endpoint).",
      "# TYPE relay_outbound_ssrf_lookups_total counter",
      `relay_outbound_ssrf_lookups_total{result="checked"} ${this.checked}`,
      `relay_outbound_ssrf_lookups_total{result="blocked"} ${this.blocked}`,
      `relay_outbound_ssrf_lookups_total{result="allowlisted"} ${this.allowlisted}`,
      `relay_outbound_ssrf_lookups_total{result="skipped"} ${this.proxiedSkipped}`,
      "# HELP relay_outbound_ssrf_blocks_total Outbound SSRF blocks by resolved-address category (WR-373). Categories only — resolved private IPs never appear in metrics labels.",
      "# TYPE relay_outbound_ssrf_blocks_total counter",
      ...BLOCKING_CATEGORIES.map(
        (c) => `relay_outbound_ssrf_blocks_total{category="${c}"} ${this.blocksByCategory[c]}`
      ),
    ];
    return lines.join("\n") + "\n";
  }

  /**
   * The bound `dns.lookup`-compatible resolver for one endpoint.
   * Always asks the inner lookup for the full address list and judges
   * exactly the addresses the connection will use — the same lookup
   * the agent dials, so there is no second resolution and no TOCTOU
   * window. Inner errors pass through untouched (a failed resolution
   * is not a guard judgment); a proxied binding delegates untouched
   * (the tunnel agent never dials the target, and the skip was
   * already audited once at binding time).
   */
  private makeLookup(inner: LookupFunction, mode: SsrfGuardMode): LookupFunction {
    return ((hostname: string, options: unknown, callback: unknown) => {
      const opts = (typeof options === "object" && options !== null ? options : {}) as {
        family?: number;
        all?: boolean;
      };
      const cb = callback as (
        err: NodeJS.ErrnoException | null,
        address: string | LookupAddress[],
        family?: number
      ) => void;
      if (typeof hostname !== "string" || hostname.length === 0) {
        cb(dnsError("ENOTFOUND", String(hostname)), "", 0);
        return;
      }
      if (mode === "proxied") {
        (inner as unknown as LookupFunction)(hostname, options as never, cb as never);
        return;
      }
      const serve = (records: LookupAddress[]): void => {
        const family = opts.family;
        const filtered =
          family === 4 || family === 6 ? records.filter((r) => r.family === family) : records;
        if (filtered.length === 0) {
          cb(dnsError("ENOTFOUND", hostname), "", 0);
          return;
        }
        if (opts.all === true) {
          (cb as unknown as (
            err: NodeJS.ErrnoException | null,
            addresses: LookupAddress[]
          ) => void)(null, filtered);
        } else {
          const first = filtered[0];
          cb(null, first.address, first.family);
        }
      };
      // Always judge the whole answer: ask the inner for the full list
      // regardless of what the caller wants served. A non-conforming
      // inner that answers a single address is folded into a
      // one-element list (the DnsPin shape).
      type InnerAllCallback = (
        err: NodeJS.ErrnoException | null,
        addresses: LookupAddress[] | string,
        family?: number
      ) => void;
      (inner as unknown as (
        hostname: string,
        options: { all: true },
        callback: InnerAllCallback
      ) => void)(hostname, { all: true }, (err, addresses, family) => {
        if (err !== null && err !== undefined) {
          cb(err, "", 0);
          return;
        }
        const list: LookupAddress[] = Array.isArray(addresses)
          ? addresses
          : typeof addresses === "string" && addresses.length > 0
            ? [{ address: addresses, family: family === 6 ? 6 : 4 }]
            : [];
        if (list.length === 0) {
          // Honest ENOTFOUND: the resolver gave us nothing usable —
          // same signal the OS resolver would produce. Not a block.
          cb(dnsError("ENOTFOUND", hostname), "", 0);
          return;
        }
        // Classify every resolved address: any private hit fails the
        // whole lookup, even when a public address is also present
        // (the dialer may pick any of them).
        const hits: { address: string; category: SsrfAddressCategory }[] = [];
        for (const r of list) {
          const category = classifyIpAddress(r.address);
          if (category !== "public") hits.push({ address: r.address, category });
        }
        if (hits.length === 0) {
          this.checked += 1;
          serve(list);
          return;
        }
        hits.sort((a, b) => (a.address < b.address ? -1 : a.address > b.address ? 1 : 0));
        const category = hits[0].category;
        const offending = [...new Set(hits.map((h) => h.address))].sort();
        if (mode === "allowlisted") {
          // Explicit per-endpoint opt-in: serve the private addresses
          // and audit every allowlisted serve (not once — the operator
          // wants a trail of every intentional private dial).
          this.allowlisted += 1;
          this.onAllowlisted?.({
            hostname,
            category,
            addresses: offending,
            at: new Date(this.now()).toISOString(),
          });
          serve(list);
          return;
        }
        // Fail-closed: refuse the lookup before connect. The old
        // answer is never adopted, and no retry budget is burned — the
        // queue classifies the error non_retryable and dead-letters.
        this.blocked += 1;
        this.blocksByCategory[category] = (this.blocksByCategory[category] ?? 0) + 1;
        this.onBlocked?.({
          hostname,
          category,
          addresses: offending,
          at: new Date(this.now()).toISOString(),
        });
        cb(new OutboundSsrfBlockedError(hostname, category, offending), "", 0);
      });
    }) as LookupFunction;
  }
}
