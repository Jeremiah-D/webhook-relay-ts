/**
 * Inbound IP allowlist/denylist (WR-53).
 *
 * A webhook relay is a magnet for internet background radiation: scanners,
 * credential-stuffing botnets, and exploit kits POST garbage at every
 * open port. Signature verification rejects them, but only *after* the
 * body was read and hashed — a hostile IP still costs bandwidth and CPU.
 * The IP ACL is the outermost admission gate: per-endpoint CIDR allow/
 * denylists checked *before* the body is read, before WR-22 rate limiting,
 * and before signature verification, so a denied IP costs us zero
 * bandwidth (the check runs on headers alone) and zero downstream state
 * (a denial never enqueues, so it burns no retry budget and never trips
 * the circuit breaker).
 *
 * - Rules match the inbound request path — exact (`/hooks/stripe`) or
 *   prefix (`/hooks/*`, which also matches `/hooks` itself) — the first
 *   matching rule in config order wins, mirroring WR-29 endpoint
 *   verifiers and WR-41 schema rules. Paths with no matching rule skip
 *   the ACL entirely, so enabling the feature changes nothing for
 *   unlisted endpoints (off by default, zero behavior change).
 * - One rule carries either `allow` or `deny` (CIDR strings), never both:
 *   configuring both is a `RangeError` at startup — an allowlist that
 *   also denies is a config smell, fail fast instead of guessing. Within
 *   a rule the check is deny-first: a deny match rejects; in allow mode
 *   an IP outside every allow CIDR rejects; anything else is admitted.
 * - Client IP resolution honors `x-forwarded-for` only through
 *   explicitly configured `trustedProxies` (CIDR). The default is to
 *   trust nobody but the direct socket peer, so a spoofed XFF header
 *   from an untrusted client is ignored, never honored.
 * - A denial is answered 403 (with `connection: close`, so the client
 *   cannot keep streaming a flood into a dead request) and audited as
 *   `rejected` with reason `ip_denied`, plus the offending IP and the
 *   matched endpoint pattern. Denials also render in the Prometheus
 *   exposition (`relay_inbound_ip_denied_total{endpoint}`).
 *
 * Zero dependencies: IPv4/IPv6 CIDR parsing and prefix matching are
 * hand-written below. IPv4 addresses are compared in IPv4-mapped IPv6
 * space (`::ffff:a.b.c.d`), which does two useful things at once: a
 * dual-stack socket's `::ffff:127.0.0.1` remoteAddress matches a plain
 * `127.0.0.1/32` rule, and a `::/0` deny rule covers IPv4 too.
 */

/** One inbound path pattern and the IP ranges trusted/denied for it. */
export interface EndpointIpAclRule {
  /** Request path pattern: exact (`/hooks/stripe`) or prefix (`/hooks/*`). */
  pattern: string;
  /**
   * CIDR allowlist (IPv4/IPv6, e.g. `"10.0.0.0/8"`, `"2001:db8::/32"`).
   * When set, only IPs inside these ranges are admitted. Mutually
   * exclusive with `deny`.
   */
  allow?: string[];
  /**
   * CIDR denylist (IPv4/IPv6). IPs inside these ranges are rejected.
   * Mutually exclusive with `allow`.
   */
  deny?: string[];
}

/** Options for {@link InboundIpAcl}. */
export interface IpAclOptions {
  /**
   * Per-endpoint rules in config order; the first matching rule wins.
   * Unset (or empty) means no endpoint is guarded — the feature is off.
   */
  rules?: EndpointIpAclRule[];
  /**
   * CIDR ranges of trusted reverse proxies (IPv4/IPv6). When the direct
   * socket peer falls inside one of these ranges, `x-forwarded-for` is
   * parsed and the leftmost untrusted hop becomes the client IP (standard
   * proxy-chain stripping). Default: empty — only the direct socket peer
   * is trusted and `x-forwarded-for` is never honored, which is the
   * spoof-proof posture for a relay that is not behind a known proxy.
   */
  trustedProxies?: string[];
}

/**
 * A parsed CIDR: the network address masked to the prefix, as a 128-bit
 * unsigned integer (IPv4 inputs live in IPv4-mapped `::ffff:0:0/96`
 * space with their prefix shifted by +96).
 */
export interface ParsedCidr {
  /** Masked network address, 128-bit unsigned. */
  network: bigint;
  /** Effective prefix length in bits (0-128; IPv4 inputs are +96). */
  prefix: number;
  /** The address family of the original CIDR string. */
  family: 4 | 6;
  /** The original CIDR string. */
  source: string;
}

/** Admission verdict for one inbound request. */
export type IpAclVerdict =
  | { ok: true }
  | {
      ok: false;
      reason: "ip_denied";
      /** The `pattern` of the rule that denied the request. */
      pattern: string;
    };

const V6_ALL = (1n << 128n) - 1n;
/** The IPv4-mapped IPv6 prefix `::ffff:0:0/96`. */
const V4_MAPPED_PREFIX = 0xffffn << 32n;

/** Fail with a RangeError naming the offending input. */
function invalid(where: string, detail: string): never {
  throw new RangeError(`ipAcl: ${where}: ${detail}`);
}

/** Parse a dotted-quad IPv4 address into a 32-bit unsigned integer. */
function parseIpv4(addr: string, where: string): number {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(addr);
  if (!m) invalid(where, `invalid IPv4 address "${addr}"`);
  let v = 0;
  for (let i = 1; i <= 4; i++) {
    const octet = Number(m[i]);
    if (octet > 255) invalid(where, `IPv4 octet out of range in "${addr}"`);
    v = v * 256 + octet;
  }
  return v >>> 0;
}

/**
 * Parse an IPv6 address (compressed `::`, and an optional IPv4 tail like
 * `::ffff:192.0.2.1`) into a 128-bit unsigned integer. Zone ids
 * (`fe80::1%eth0`) are rejected — they never appear on a server socket's
 * remoteAddress and silently ignoring the zone would be wrong.
 */
function parseIpv6(addr: string, where: string): bigint {
  if (addr === "") invalid(where, "empty IPv6 address");
  if (addr.includes("%")) invalid(where, `zone id not supported in "${addr}"`);
  const halves = addr.split("::");
  if (halves.length > 2) invalid(where, `more than one "::" in "${addr}"`);
  // An IPv4 tail (`::ffff:192.0.2.1`) is only legal as the final 32 bits
  // of the address: in the right half of "::", or at the very end when
  // there is no "::". A tail in the left half ("1.2.3.4::5") can never be
  // final, so it is rejected.
  const expand = (part: string, v4TailAllowed: boolean): number[] => {
    if (part === "") return [];
    const tokens = part.split(":");
    const out: number[] = [];
    tokens.forEach((tok, idx) => {
      if (tok.includes(".")) {
        // Embedded IPv4 tail: must be the last token, counts as 2 groups.
        if (!v4TailAllowed || idx !== tokens.length - 1) {
          invalid(where, `IPv4 tail must be the last group in "${addr}"`);
        }
        const v4 = parseIpv4(tok, where);
        out.push(v4 >>> 16, v4 & 0xffff);
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(tok)) invalid(where, `bad IPv6 group "${tok}" in "${addr}"`);
        out.push(parseInt(tok, 16));
      }
    });
    return out;
  };
  let groups: number[];
  if (halves.length === 1) {
    groups = expand(halves[0], true);
    if (groups.length !== 8) invalid(where, `expected 8 groups in "${addr}", got ${groups.length}`);
  } else {
    const left = expand(halves[0], false);
    const right = expand(halves[1], true);
    if (left.length + right.length >= 8) {
      invalid(where, `"::" in "${addr}" must compress at least one group of zeros`);
    }
    const zeros = new Array(8 - left.length - right.length).fill(0);
    groups = [...left, ...zeros, ...right];
  }
  let ip = 0n;
  for (const g of groups) ip = (ip << 16n) | BigInt(g);
  return ip;
}

/**
 * Parse any IP address string into a 128-bit unsigned integer. IPv4
 * addresses land in IPv4-mapped space (`::ffff:a.b.c.d`), so one
 * comparison routine covers both families. Throws RangeError on garbage.
 */
export function parseIpAddress(ip: string): bigint {
  const where = `IP "${String(ip)}"`;
  if (typeof ip !== "string" || ip === "") invalid(where, "must be a non-empty string");
  if (ip.includes(":")) return parseIpv6(ip, where);
  return V4_MAPPED_PREFIX | BigInt(parseIpv4(ip, where));
}

function prefixMask(prefix: number): bigint {
  if (prefix <= 0) return 0n;
  return (V6_ALL << BigInt(128 - prefix)) & V6_ALL;
}

/**
 * Parse a CIDR string (`"10.0.0.0/8"`, `"2001:db8::/32"`, `"::1"`,
 * `"192.0.2.7"` — a bare address means a single host). Host bits set in
 * the network part are masked off. Throws RangeError on anything that is
 * not a well-formed CIDR: fail fast at startup, never mid-request.
 */
export function parseCidr(cidr: string, where = "CIDR"): ParsedCidr {
  if (typeof cidr !== "string" || cidr === "") {
    invalid(where, `CIDR must be a non-empty string, got ${JSON.stringify(cidr)}`);
  }
  const slash = cidr.lastIndexOf("/");
  let addr = cidr;
  let prefixStr: string | undefined;
  if (slash !== -1) {
    addr = cidr.slice(0, slash);
    prefixStr = cidr.slice(slash + 1);
  }
  if (addr === "") invalid(where, `missing address in "${cidr}"`);
  const maxPrefix = addr.includes(":") ? 128 : 32;
  let prefix = maxPrefix; // bare address = single host
  if (prefixStr !== undefined) {
    if (!/^\d+$/.test(prefixStr)) invalid(where, `bad prefix in "${cidr}"`);
    prefix = Number(prefixStr);
    if (prefix < 0 || prefix > maxPrefix) {
      invalid(where, `prefix out of range 0-${maxPrefix} in "${cidr}"`);
    }
  }
  let network: bigint;
  let family: 4 | 6;
  if (addr.includes(":")) {
    family = 6;
    network = parseIpv6(addr, where) & prefixMask(prefix);
  } else {
    // IPv4: lift into the mapped space and shift the prefix by +96, so a
    // plain "10.0.0.0/8" rule and a "::ffff:10.1.2.3" socket address meet
    // in the same 128-bit comparison.
    family = 4;
    prefix += 96;
    network = (V4_MAPPED_PREFIX | BigInt(parseIpv4(addr, where))) & prefixMask(prefix);
  }
  return { network, prefix, family, source: cidr };
}

/**
 * Whether `ip` (any address string) falls inside `cidr`. An unparseable
 * IP never matches — callers that need fail-closed behavior (like
 * {@link InboundIpAcl.check}) deny on that separately.
 */
export function cidrContains(cidr: ParsedCidr, ip: string): boolean {
  let v: bigint;
  try {
    v = parseIpAddress(ip);
  } catch {
    return false;
  }
  return (v & prefixMask(cidr.prefix)) === cidr.network;
}

/**
 * Validate endpoint IP ACL rules. Throws RangeError on a non-array, a
 * pattern that is not a `/`-rooted path, an `allow`+`deny` pair on the
 * same rule (mutually exclusive — deny-first semantics require one list
 * per rule), an empty list, or any malformed CIDR — fail fast at
 * startup, never mid-request.
 */
export function assertValidEndpointIpAclRules(rules: EndpointIpAclRule[] | undefined): void {
  if (rules === undefined) return;
  if (!Array.isArray(rules)) {
    throw new RangeError("ipAcl.rules: expected an array of { pattern, allow?, deny? } rules");
  }
  rules.forEach((rule, i) => {
    const where = `ipAcl.rules[${i}]`;
    if (!rule || typeof rule.pattern !== "string" || rule.pattern === "" || !rule.pattern.startsWith("/")) {
      throw new RangeError(
        `${where}: pattern must be a path starting with "/" (exact) or ending with "/*" (prefix)`
      );
    }
    for (const key of ["allow", "deny"] as const) {
      const list = rule[key];
      if (list === undefined) continue;
      if (!Array.isArray(list) || list.length === 0) {
        throw new RangeError(`${where}: ${key} must be a non-empty array of CIDR strings`);
      }
      list.forEach((c, j) => parseCidr(c, `${where}.${key}[${j}]`));
    }
    if (rule.allow !== undefined && rule.deny !== undefined) {
      throw new RangeError(
        `${where}: allow and deny are mutually exclusive — split them into two rules (first match wins)`
      );
    }
  });
}

interface CompiledRule {
  pattern: string;
  allow: ParsedCidr[];
  deny: ParsedCidr[];
}

/**
 * Select the rule for an inbound request path: the first matching rule
 * in config order (exact or prefix, same semantics as WR-29/WR-41), or
 * `undefined` when nothing matches. Never throws.
 */
export function selectEndpointIpAclRule<T extends { pattern: string }>(
  pathname: string,
  rules: readonly T[] | undefined
): T | undefined {
  if (rules === undefined) return undefined;
  for (const rule of rules) {
    if (rule.pattern.endsWith("/*")) {
      const prefix = rule.pattern.slice(0, -2);
      if (pathname === prefix || pathname.startsWith(prefix + "/")) {
        return rule;
      }
    } else if (pathname === rule.pattern) {
      return rule;
    }
  }
  return undefined;
}

/**
 * The inbound IP gate: per-endpoint allow/denylists plus trusted-proxy
 * client-IP resolution. Construct once at server startup (invalid config
 * throws RangeError there); `clientIp` + `check` are then safe to call on
 * every request — they never throw on hostile input.
 */
export class InboundIpAcl {
  private readonly rules: CompiledRule[];
  private readonly trustedProxies: ParsedCidr[];

  constructor(opts: IpAclOptions = {}) {
    assertValidEndpointIpAclRules(opts.rules);
    // Pre-parse every CIDR once: the per-request path is pure integer
    // comparison, no parsing, no allocation of note.
    this.rules = (opts.rules ?? []).map((rule) => ({
      pattern: rule.pattern,
      allow: (rule.allow ?? []).map((c) => parseCidr(c)),
      deny: (rule.deny ?? []).map((c) => parseCidr(c)),
    }));
    const proxies = opts.trustedProxies ?? [];
    if (!Array.isArray(proxies)) {
      throw new RangeError("ipAcl.trustedProxies: expected an array of CIDR strings");
    }
    this.trustedProxies = proxies.map((c, i) => parseCidr(c, `ipAcl.trustedProxies[${i}]`));
  }

  /**
   * Resolve the client IP for a request from the socket's remoteAddress
   * and the `x-forwarded-for` header. With no trusted proxies configured
   * (the default) this is always the direct socket peer — a spoofed XFF
   * is ignored, never honored. When the direct peer is itself a trusted
   * proxy and XFF is present, the chain is stripped from the right (the
   * hops closest to the relay): the client is the leftmost untrusted
   * hop, or the leftmost claim when every hop is trusted. Never throws;
   * an unresolvable peer yields `"unknown"`, which {@link check}
   * fail-closes on guarded endpoints.
   */
  clientIp(
    socketIp: string | undefined,
    xForwardedFor: string | string[] | undefined
  ): string {
    const direct = typeof socketIp === "string" && socketIp !== "" ? socketIp : "unknown";
    if (this.trustedProxies.length === 0) return direct;
    let peer: bigint;
    try {
      peer = parseIpAddress(direct);
    } catch {
      return direct;
    }
    if (!this.trustedProxies.some((c) => (peer & prefixMask(c.prefix)) === c.network)) {
      // The direct peer is not a trusted proxy: XFF is untrusted input,
      // ignore it entirely (XFF spoofing protection).
      return direct;
    }
    const raw = Array.isArray(xForwardedFor) ? xForwardedFor[0] : xForwardedFor;
    if (typeof raw !== "string" || raw.trim() === "") return direct;
    const chain = raw
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s !== "");
    if (chain.length === 0) return direct;
    let client = chain[0];
    for (let i = chain.length - 1; i >= 0; i--) {
      let hop: bigint;
      try {
        hop = parseIpAddress(chain[i]);
      } catch {
        // Unparseable hop: stop and keep it — check() fail-closes on
        // unparseable IPs for guarded endpoints.
        client = chain[i];
        break;
      }
      const trusted = this.trustedProxies.some((c) => (hop & prefixMask(c.prefix)) === c.network);
      if (!trusted) {
        client = chain[i];
        break;
      }
      // Trusted hop: keep stripping leftward. If the loop runs out, every
      // hop was trusted and `client` stays the leftmost claim.
    }
    return client;
  }

  /**
   * Admission verdict for `pathname` from client `ip`. Paths with no
   * matching rule are admitted; a matched rule denies on a deny-list hit,
   * or — in allow mode — when the IP is inside no allow range. An
   * unparseable `ip` on a guarded endpoint is denied (fail closed). Never
   * throws.
   */
  check(pathname: string, ip: string): IpAclVerdict {
    const rule = selectEndpointIpAclRule(pathname, this.rules);
    if (rule === undefined) return { ok: true };
    let parsed: bigint | undefined;
    try {
      parsed = parseIpAddress(ip);
    } catch {
      parsed = undefined;
    }
    if (parsed === undefined) {
      return { ok: false, reason: "ip_denied", pattern: rule.pattern };
    }
    const inList = (list: ParsedCidr[]): boolean =>
      list.some((c) => (parsed! & prefixMask(c.prefix)) === c.network);
    // Deny-first: a deny match rejects even if the IP would also be
    // allowed (the lists are mutually exclusive per rule, so this is
    // belt and braces for future shapes).
    if (inList(rule.deny)) return { ok: false, reason: "ip_denied", pattern: rule.pattern };
    if (rule.allow.length > 0 && !inList(rule.allow)) {
      return { ok: false, reason: "ip_denied", pattern: rule.pattern };
    }
    return { ok: true };
  }
}

/**
 * Denial counters by endpoint pattern. Renders to Prometheus exposition
 * text; renders `""` when nothing was denied, keeping `GET /metrics`
 * byte-identical for relays that never enable the IP ACL.
 */
export class IpAclMetrics {
  private readonly denied = new Map<string, number>();

  /** Record one denial for the matched rule's `pattern`. */
  record(pattern: string): void {
    this.denied.set(pattern, (this.denied.get(pattern) ?? 0) + 1);
  }

  /** Prometheus text exposition (0.0.4) of the counters; `""` when empty. */
  render(): string {
    if (this.denied.size === 0) return "";
    const esc = (v: string): string =>
      v.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, '\\"');
    const lines: string[] = [
      "# HELP relay_inbound_ip_denied_total Inbound webhook requests rejected by the IP allowlist/denylist, by endpoint pattern.",
      "# TYPE relay_inbound_ip_denied_total counter",
    ];
    for (const [pattern, n] of this.denied) {
      lines.push(`relay_inbound_ip_denied_total{endpoint="${esc(pattern)}"} ${n}`);
    }
    return lines.join("\n") + "\n";
  }
}
