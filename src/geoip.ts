/**
 * Inbound GeoIP country policy (WR-158).
 *
 * Some senders are only trustworthy from certain jurisdictions — or a
 * relay operator simply wants to cut off the background radiation from
 * regions the business never serves. A GeoIP lookup answers "which
 * country is this IP in", but real GeoIP databases are binary blobs with
 * update cadences, licenses, and a native-module smell this relay does
 * not want. This module is deliberately *config-only*: the operator
 * supplies a small table of `{ cidr, country }` entries (IPv4/IPv6 CIDRs
 * mapping to ISO 3166-1 alpha-2 country codes) plus a policy of
 * `{ default, countries }` — pure configuration, zero dependencies, zero
 * binary downloads. It is a coarse geography filter, not a substitute
 * for a real GeoIP database, and it is honest about that: the README
 * documents it as operator-curated ranges.
 *
 * - The table is matched in config order; the first CIDR containing the
 *   client IP wins, so overlapping ranges are resolved deterministically
 *   (document the more specific range first). CIDR parsing reuses the
 *   hand-written matcher from `src/ip-acl.ts` — IPv4 compares in
 *   IPv4-mapped `::ffff:0:0/96` space, so a dual-stack socket's
 *   `::ffff:127.0.0.1` remoteAddress matches a `127.0.0.1/32` table row.
 * - `lookup(ip)` returns the country code, or `undefined` when no table
 *   entry matches. It throws `RangeError` on an unparseable IP — a
 *   caller never wants to silently treat garbage as "unknown country".
 * - `resolve(ip, table, policy)` returns `"allow"` or `"deny"` and never
 *   throws: an unmapped IP follows `policy.default`, and an unparseable
 *   IP fails closed to `"deny"` (a caller that cannot even parse the
 *   client address must not admit it).
 * - The country-level rule wins over the default: when
 *   `policy.countries[CC]` is set, that verdict applies; otherwise the
 *   default does. There is deliberately no deny-first/allow-first
 *   subtlety — one dimension (the country), one rule, the default.
 *
 * Configuration is validated at startup (`RangeError` on a bad CIDR, a
 * country code that is not two uppercase letters, an illegal default, or
 * a malformed `countries` map) — fail fast at boot, never mid-request.
 */

import { cidrContains, parseCidr, parseIpAddress, type ParsedCidr } from "./ip-acl.ts";

/** One operator-curated CIDR → country row. */
export interface GeoIpTableEntry {
  /**
   * CIDR range (IPv4/IPv6, e.g. `"203.0.113.0/24"`, `"2001:db8::/32"`; a
   * bare address means a single host — the `parseCidr` spellings from
   * `src/ip-acl.ts`).
   */
  cidr: string;
  /**
   * ISO 3166-1 alpha-2 country code, uppercase (e.g. `"US"`, `"DE"`).
   * Anything else is a `RangeError` at startup.
   */
  country: string;
}

/** Country-level admission policy layered over the CIDR→country table. */
export interface GeoPolicy {
  /**
   * Verdict for clients whose country is not listed in `countries` (and
   * the fallback for unmapped IPs; unparseable IPs always fail closed to
   * `"deny"`).
   */
  default: "allow" | "deny";
  /** Per-country verdicts, keyed by uppercase ISO 3166-1 alpha-2 code. */
  countries: Record<string, "allow" | "deny">;
}

/** Options for {@link GeoIpInboundPolicy}. */
export interface GeoIpOptions {
  /**
   * Operator-curated CIDR → country table, matched in config order
   * (first match wins). May be empty or omitted — then every client
   * follows `policy.default`.
   */
  table?: GeoIpTableEntry[];
  /** The admission policy; required when the feature is enabled. */
  policy: GeoPolicy;
}

/** A table row with its CIDR pre-parsed (startup cost, not per-request). */
export interface CompiledGeoIpTableEntry {
  cidr: ParsedCidr;
  country: string;
}

/** Admission verdict for one client IP. */
export type GeoVerdict = "allow" | "deny";

const COUNTRY_CODE_RE = /^[A-Z]{2}$/;

/** Fail with a RangeError naming the offending input. */
function invalid(where: string, detail: string): never {
  throw new RangeError(`geoIp: ${where}: ${detail}`);
}

/**
 * Validate a GeoIP configuration. Throws RangeError on: a missing or
 * non-object options/policy value; a table that is not an array; a row
 * that is not an object; a malformed CIDR; a country code that is not an
 * uppercase ISO 3166-1 alpha-2 string; a `default` other than
 * `"allow"`/`"deny"`; a `countries` map that is not a plain object; or a
 * countries entry whose key/value is not a valid country/verdict —
 * fail fast at startup, never mid-request.
 */
export function assertValidGeoIpOptions(opts: GeoIpOptions | undefined): void {
  if (opts === undefined || opts === null || typeof opts !== "object" || Array.isArray(opts)) {
    throw new RangeError("geoIp: expected { table?, policy }");
  }
  const table = opts.table ?? [];
  if (!Array.isArray(table)) {
    throw new RangeError("geoIp.table: expected an array of { cidr, country } entries");
  }
  table.forEach((entry, i) => {
    const where = `geoIp.table[${i}]`;
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
      throw new RangeError(`${where}: expected an object of { cidr, country }`);
    }
    parseCidr(entry.cidr, `${where}.cidr`);
    if (typeof entry.country !== "string" || !COUNTRY_CODE_RE.test(entry.country)) {
      throw new RangeError(
        `${where}.country: expected an uppercase ISO 3166-1 alpha-2 code, got ${JSON.stringify(entry.country)}`
      );
    }
  });
  const policy = opts.policy;
  if (policy === undefined || policy === null || typeof policy !== "object" || Array.isArray(policy)) {
    throw new RangeError("geoIp.policy: expected { default, countries }");
  }
  if (policy.default !== "allow" && policy.default !== "deny") {
    throw new RangeError(
      `geoIp.policy.default: expected "allow" or "deny", got ${JSON.stringify(policy.default)}`
    );
  }
  const countries = policy.countries;
  if (countries === undefined || countries === null || typeof countries !== "object" || Array.isArray(countries)) {
    throw new RangeError("geoIp.policy.countries: expected an object of { <CC>: \"allow\" | \"deny\" }");
  }
  for (const cc of Object.keys(countries)) {
    if (!COUNTRY_CODE_RE.test(cc)) {
      throw new RangeError(
        `geoIp.policy.countries: country key must be an uppercase ISO 3166-1 alpha-2 code, got ${JSON.stringify(cc)}`
      );
    }
    const verdict = (countries as Record<string, unknown>)[cc];
    if (verdict !== "allow" && verdict !== "deny") {
      throw new RangeError(
        `geoIp.policy.countries[${cc}]: expected "allow" or "deny", got ${JSON.stringify(verdict)}`
      );
    }
  }
}

/**
 * Compile a GeoIP table (validate + pre-parse every CIDR once). The
 * returned rows are in config order — matching is first-match-wins.
 */
export function compileGeoIpTable(table: GeoIpTableEntry[] | undefined): CompiledGeoIpTableEntry[] {
  assertValidGeoIpOptions({ table, policy: { default: "allow", countries: {} } });
  return (table ?? []).map((entry) => ({
    cidr: parseCidr(entry.cidr),
    country: entry.country,
  }));
}

/**
 * Look up the country for `ip` in the compiled table (config order,
 * first match wins). Returns `undefined` when no entry matches.
 * Throws RangeError on an unparseable IP — callers fail closed on that
 * (see {@link resolveGeoVerdict}).
 */
export function lookupGeoCountry(ip: string, table: readonly CompiledGeoIpTableEntry[]): string | undefined {
  // Validate first: cidrContains deliberately never throws (an unparseable
  // IP simply matches nothing), but lookup's contract is to surface garbage
  // as RangeError so callers can fail closed.
  parseIpAddress(ip);
  for (const entry of table) {
    if (cidrContains(entry.cidr, ip)) return entry.country;
  }
  return undefined;
}

/**
 * Admission verdict for `ip`: the country-level rule when
 * `policy.countries[CC]` is set for the looked-up country, otherwise
 * `policy.default`. Never throws — an unmapped IP follows the default,
 * an unparseable IP fails closed to `"deny"`.
 */
export function resolveGeoVerdict(
  ip: string,
  table: readonly CompiledGeoIpTableEntry[],
  policy: GeoPolicy
): GeoVerdict {
  let country: string | undefined;
  try {
    country = lookupGeoCountry(ip, table);
  } catch {
    // Unparseable client IP: fail closed. The audit trail records the IP
    // as-is with country "unknown" (the server maps `undefined` there).
    return "deny";
  }
  if (country !== undefined) {
    const verdict = policy.countries[country];
    if (verdict !== undefined) return verdict;
  }
  return policy.default;
}

/**
 * The inbound GeoIP gate: a validated table + policy, constructed once at
 * server startup (invalid config throws RangeError there); `classify` is
 * then safe to call on every request — it never throws on hostile
 * input.
 */
export class GeoIpInboundPolicy {
  private readonly table: CompiledGeoIpTableEntry[];
  private readonly policy: GeoPolicy;

  constructor(opts: GeoIpOptions) {
    assertValidGeoIpOptions(opts);
    this.table = (opts.table ?? []).map((entry) => ({
      cidr: parseCidr(entry.cidr),
      country: entry.country,
    }));
    this.policy = opts.policy;
  }

  /**
   * Classify a client IP: the country (from the table, `undefined` when
   * unmapped or unparseable) and the admission verdict. Never throws —
   * an unparseable IP fails closed to `deny` with `country: undefined`
   * (the server audits that as `"unknown"`).
   */
  classify(ip: string): { verdict: GeoVerdict; country: string | undefined } {
    let country: string | undefined;
    try {
      country = lookupGeoCountry(ip, this.table);
    } catch {
      // Unparseable client IP: fail closed, country unknown.
      return { verdict: "deny", country: undefined };
    }
    if (country === undefined) {
      // Unmapped IP: the policy default decides.
      return { verdict: this.policy.default, country: undefined };
    }
    const verdict = this.policy.countries[country] ?? this.policy.default;
    return { verdict, country };
  }
}
