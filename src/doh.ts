import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { promises as dnsPromises, type LookupAddress } from "node:dns";
import { randomBytes } from "node:crypto";
import { isIP } from "node:net";

/**
 * DNS-over-HTTPS resolver (WR-170, RFC 8484).
 *
 * The outbound DNS cache (WR-92) resolves through `dns.lookup` by
 * default, which inherits the host's resolver — a single point of
 * failure and, on shared or hostile networks, a single point of
 * observation. This module adds an opt-in DoH path:
 *
 * - `createDohResolver` — wire-format DNS queries (RFC 8484) POSTed to
 *   a DoH endpoint, A and AAAA asked in parallel, answers merged;
 * - `createDohAwareResolver` — tries DoH first and falls back to the
 *   system resolver on any failure, so a DoH outage degrades to the
 *   old behavior instead of failing deliveries. This is the shape that
 *   plugs into `DnsCacheOptions.resolve`.
 *
 * Zero dependencies (`node:http` / `node:https` / `node:dns` /
 * `node:crypto` / `node:net` only). Validation is fail-fast with
 * `RangeError`, matching the rest of the relay; malformed wire data
 * surfaces as `DohProtocolError`.
 */

/** DNS QTYPE for IPv4 host addresses. */
export const QTYPE_A = 1;
/** DNS QTYPE for IPv6 host addresses. */
export const QTYPE_AAAA = 28;

const DNS_MESSAGE_MIME = "application/dns-message";
const DEFAULT_TIMEOUT_MS = 5_000;
const MAX_HOSTNAME_LEN = 253;
const MAX_LABEL_LEN = 63;

/** A DoH endpoint answered with something that is not valid DNS wire format. */
export class DohProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DohProtocolError";
  }
}

/**
 * Validate a DoH endpoint URL. Returns the parsed URL.
 *
 * `http:` is accepted alongside `https:` so tests can run against a
 * local fake DoH server; production deployments must use `https:`
 * (RFC 8484 requires TLS) — the scheme choice is left to the operator
 * and validated again at server startup, not here.
 */
export function assertValidDohUrl(url: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new RangeError(`DoH: invalid endpoint URL ${JSON.stringify(String(url))}`);
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new RangeError(
      `DoH: endpoint scheme must be https: or http:, got ${parsed.protocol}`
    );
  }
  return parsed;
}

const HOSTNAME_RE = /^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*$/;

/**
 * Build a standard DNS query packet (12-byte header, one question).
 * Header: random 16-bit ID, flags 0x0100 (recursion desired), QDCOUNT=1.
 *
 * IP literals are rejected — they never need DoH; the resolver
 * short-circuits them instead.
 */
export function buildDnsQuery(hostname: string, qtype: number): Buffer {
  if (typeof hostname !== "string" || hostname.length === 0) {
    throw new RangeError("DoH: hostname must be a non-empty string");
  }
  if (hostname.length > MAX_HOSTNAME_LEN) {
    throw new RangeError(`DoH: hostname longer than ${MAX_HOSTNAME_LEN} characters`);
  }
  if (isIP(hostname) !== 0) {
    throw new RangeError("DoH: IP literals never need a DoH query");
  }
  if (!HOSTNAME_RE.test(hostname)) {
    throw new RangeError(`DoH: invalid hostname ${JSON.stringify(hostname)}`);
  }
  const labels = hostname.split(".");
  for (const label of labels) {
    if (label.length === 0 || label.length > MAX_LABEL_LEN) {
      throw new RangeError(`DoH: invalid label length in ${JSON.stringify(hostname)}`);
    }
    if (label.startsWith("-") || label.endsWith("-")) {
      throw new RangeError(`DoH: label may not start or end with "-" in ${JSON.stringify(hostname)}`);
    }
  }
  if (!Number.isInteger(qtype) || qtype < 0 || qtype > 0xffff) {
    throw new RangeError(`DoH: qtype must be a 16-bit integer, got ${qtype}`);
  }

  const header = Buffer.alloc(12);
  randomBytes(2).copy(header, 0);
  header.writeUInt16BE(0x0100, 2); // flags: recursion desired
  header.writeUInt16BE(1, 4); // QDCOUNT = 1

  const nameParts: Buffer[] = [];
  for (const label of labels) {
    const bytes = Buffer.from(label, "ascii");
    nameParts.push(Buffer.from([bytes.length]), bytes);
  }
  nameParts.push(Buffer.from([0])); // root terminator

  const tail = Buffer.alloc(4);
  tail.writeUInt16BE(qtype, 0);
  tail.writeUInt16BE(1, 2); // QCLASS IN

  return Buffer.concat([header, ...nameParts, tail]);
}

/**
 * Parse a DNS response packet into `{ address, family }` records.
 * Handles name compression pointers (0xC0..) in answers; collects A
 * and AAAA records and ignores every other RR type. Throws
 * `DohProtocolError` on truncation, garbage, a clear QR bit, or a
 * non-zero RCODE.
 */
export function parseDnsResponse(buf: Buffer): LookupAddress[] {
  if (buf.length < 12) {
    throw new DohProtocolError(`DNS response too short: ${buf.length} bytes`);
  }
  const flags = buf.readUInt16BE(2);
  if ((flags & 0x8000) === 0) {
    throw new DohProtocolError("not a DNS response: QR bit is clear");
  }
  const rcode = flags & 0x000f;
  if (rcode !== 0) {
    throw new DohProtocolError(`DNS query failed with rcode=${rcode}`);
  }
  const qdcount = buf.readUInt16BE(4);
  const ancount = buf.readUInt16BE(6);

  let pos = 12;
  for (let i = 0; i < qdcount; i++) {
    pos = skipName(buf, pos);
    if (pos + 4 > buf.length) {
      throw new DohProtocolError("truncated DNS question section");
    }
    pos += 4; // QTYPE + QCLASS
  }

  const out: LookupAddress[] = [];
  for (let i = 0; i < ancount; i++) {
    pos = skipName(buf, pos);
    if (pos + 10 > buf.length) {
      throw new DohProtocolError("truncated DNS answer header");
    }
    const type = buf.readUInt16BE(pos);
    const cls = buf.readUInt16BE(pos + 2);
    // TTL at pos+4 is not needed for resolution.
    const rdlen = buf.readUInt16BE(pos + 8);
    pos += 10;
    if (pos + rdlen > buf.length) {
      throw new DohProtocolError("truncated DNS rdata");
    }
    if (cls === 1 && type === QTYPE_A && rdlen === 4) {
      out.push({
        address: `${buf[pos]}.${buf[pos + 1]}.${buf[pos + 2]}.${buf[pos + 3]}`,
        family: 4,
      });
    } else if (cls === 1 && type === QTYPE_AAAA && rdlen === 16) {
      out.push({ address: formatIPv6(buf.subarray(pos, pos + 16)), family: 6 });
    }
    // Any other RR type (CNAME, TXT, MX, ...) is ignored: the relay
    // only needs addresses, and following chains is out of scope.
    pos += rdlen;
  }
  return out;
}

/**
 * Advance past a DNS name, following compression pointers only far
 * enough to know where the name ends (2 bytes at the pointer). A
 * pointer terminates the name, so pointer loops cannot hang this walk.
 */
function skipName(buf: Buffer, offset: number): number {
  let pos = offset;
  for (;;) {
    if (pos >= buf.length) {
      throw new DohProtocolError("truncated DNS name");
    }
    const len = buf[pos];
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length) {
        throw new DohProtocolError("truncated DNS name pointer");
      }
      const target = ((len & 0x3f) << 8) | buf[pos + 1];
      if (target >= buf.length) {
        throw new DohProtocolError("DNS name pointer out of bounds");
      }
      return pos + 2;
    }
    if ((len & 0xc0) !== 0) {
      throw new DohProtocolError("invalid DNS name label marker");
    }
    if (len === 0) return pos + 1;
    pos += 1 + len;
  }
}

/** Render 16 rdata bytes as a canonical IPv6 literal with `::` compression. */
function formatIPv6(b: Buffer): string {
  const groups: number[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(b.readUInt16BE(i));
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i <= 8; i++) {
    if (i < 8 && groups[i] === 0) {
      if (curStart === -1) {
        curStart = i;
        curLen = 1;
      } else {
        curLen += 1;
      }
    } else {
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
      curStart = -1;
      curLen = 0;
    }
  }
  const hex = (g: number): string => g.toString(16);
  if (bestLen < 2) return groups.map(hex).join(":");
  const left = groups.slice(0, bestStart).map(hex).join(":");
  const right = groups.slice(bestStart + bestLen).map(hex).join(":");
  return `${left}::${right}`;
}

/** Tuning for {@link createDohResolver}. */
export interface DohResolverOptions {
  /** DoH endpoint URL (`https:` in production; `http:` only for local tests). */
  url: string;
  /** Per-query HTTP timeout in ms. Default: 5000. Must be a finite number > 0. */
  timeoutMs?: number;
  /**
   * Clock; defaults to `Date.now`. Injectable for tests. Reserved for
   * future per-query latency accounting — currently unused.
   */
  now?: () => number;
}

function postDnsMessage(url: URL, body: Buffer, timeoutMs: number): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    const doRequest = url.protocol === "https:" ? httpsRequest : httpRequest;
    let settled = false;
    // `req` is assigned synchronously below, before any timer can fire.
    let req: ReturnType<typeof httpRequest> | undefined;
    const fail = (err: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    };
    const succeed = (buf: Buffer): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(buf);
    };
    const timer = setTimeout(() => {
      fail(new DohProtocolError(`DoH query to ${url.host} timed out after ${timeoutMs}ms`));
      req?.destroy();
    }, timeoutMs);
    // The timer must never keep the process alive on its own.
    timer.unref();
    req = doRequest(
      url,
      {
        method: "POST",
        headers: {
          "content-type": DNS_MESSAGE_MIME,
          accept: DNS_MESSAGE_MIME,
        },
      },
      (res) => {
        const status = res.statusCode ?? 0;
        if (status < 200 || status >= 300) {
          res.resume();
          fail(new DohProtocolError(`DoH server answered HTTP ${status}`));
          return;
        }
        const contentType = res.headers["content-type"] ?? "";
        if (!contentType.includes(DNS_MESSAGE_MIME)) {
          res.resume();
          fail(
            new DohProtocolError(
              `DoH server answered with unexpected content-type ${JSON.stringify(contentType)}`
            )
          );
          return;
        }
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => succeed(Buffer.concat(chunks)));
        res.on("error", fail);
      }
    );
    req.on("error", fail);
    req.end(body);
  });
}

async function queryType(
  url: URL,
  hostname: string,
  qtype: number,
  timeoutMs: number
): Promise<LookupAddress[]> {
  const body = buildDnsQuery(hostname, qtype);
  const raw = await postDnsMessage(url, body, timeoutMs);
  return parseDnsResponse(raw);
}

function notFound(hostname: string): NodeJS.ErrnoException {
  const err = new Error(`ENOTFOUND ${hostname}`) as NodeJS.ErrnoException;
  err.code = "ENOTFOUND";
  err.hostname = hostname;
  return err;
}

/**
 * Build a DoH resolver with the `DnsCacheOptions.resolve` signature:
 * `(hostname) => Promise<LookupAddress[]>`.
 *
 * Each call POSTs A and AAAA queries in parallel (RFC 8484 wire format)
 * and merges the answers, A records first. IP literals short-circuit
 * without any network traffic. An empty answer set is a resolution
 * failure and surfaces as an `ENOTFOUND`-coded error, the same signal
 * the OS resolver produces.
 */
export function createDohResolver(
  opts: DohResolverOptions
): (hostname: string) => Promise<LookupAddress[]> {
  const url = assertValidDohUrl(opts.url);
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new RangeError(
      `DoH: timeoutMs must be a finite number > 0, got ${opts.timeoutMs}`
    );
  }
  if (opts.now !== undefined && typeof opts.now !== "function") {
    throw new RangeError("DoH: now must be a function");
  }
  return async (hostname: string): Promise<LookupAddress[]> => {
    const ipVersion = isIP(hostname);
    if (ipVersion === 4 || ipVersion === 6) {
      return [{ address: hostname, family: ipVersion }];
    }
    const [aRecords, aaaaRecords] = await Promise.all([
      queryType(url, hostname, QTYPE_A, timeoutMs),
      queryType(url, hostname, QTYPE_AAAA, timeoutMs),
    ]);
    const merged = [...aRecords, ...aaaaRecords];
    if (merged.length === 0) throw notFound(hostname);
    return merged;
  };
}

/** Tuning for {@link createDohAwareResolver}. */
export interface DohAwareResolverOptions extends DohResolverOptions {
  /**
   * Called once per DoH failure that triggers a system-DNS fallback.
   * Must never throw into the resolver — a throwing callback is
   * swallowed so telemetry cannot break resolution.
   */
  onFallback?: (info: { hostname: string; error: string; dohUrl: string }) => void;
}

/** Snapshot from the resolver returned by {@link createDohAwareResolver}. */
export interface DohAwareStats {
  /** DoH attempts made. */
  dohQueries: number;
  /** DoH attempts that failed. */
  dohFailures: number;
  /** System-DNS fallbacks taken (one per DoH failure). */
  fallbacks: number;
  /** System-DNS queries issued. */
  systemQueries: number;
}

/**
 * A resolver that tries DoH first and falls back to the system
 * resolver on *any* DoH failure (network error, timeout, protocol
 * error, empty answers). A DoH outage therefore degrades to the
 * pre-WR-170 behavior instead of failing deliveries.
 *
 * This is the shape that plugs into `DnsCacheOptions.resolve`:
 * hand `aware.resolve` to the `DnsCache` constructor.
 *
 * Note: the positional `dohUrl` is authoritative. `opts.url` (inherited
 * from `DohResolverOptions`) is accepted by the type but ignored — pass
 * the endpoint once, positionally.
 */
export function createDohAwareResolver(
  dohUrl: string,
  opts: DohAwareResolverOptions = {}
): { resolve: (hostname: string) => Promise<LookupAddress[]>; getStats: () => DohAwareStats } {
  const doh = createDohResolver({ url: dohUrl, timeoutMs: opts.timeoutMs, now: opts.now });
  const onFallback = opts.onFallback;
  let dohQueries = 0;
  let dohFailures = 0;
  let fallbacks = 0;
  let systemQueries = 0;

  async function resolve(hostname: string): Promise<LookupAddress[]> {
    dohQueries += 1;
    try {
      return await doh(hostname);
    } catch (err) {
      dohFailures += 1;
      fallbacks += 1;
      systemQueries += 1;
      if (onFallback !== undefined) {
        try {
          onFallback({
            hostname,
            error: err instanceof Error ? err.message : String(err),
            dohUrl,
          });
        } catch {
          // Telemetry must never break resolution.
        }
      }
      const records = await dnsPromises.lookup(hostname, { all: true });
      return records.map((r) => ({ address: r.address, family: r.family }));
    }
  }

  function getStats(): DohAwareStats {
    return { dohQueries, dohFailures, fallbacks, systemQueries };
  }

  return { resolve, getStats };
}

/**
 * Look up the DoH endpoint for a target URL by exact match — the same
 * convention as the `proxies` option in WR-27. Returns `undefined`
 * when no entry exists. No validation here; the configured endpoint
 * is validated once at server startup via `assertValidDohUrl`.
 */
export function resolveDohUrl(
  targetUrl: string,
  doh?: Record<string, string>
): string | undefined {
  if (doh === undefined) return undefined;
  return doh[targetUrl];
}
