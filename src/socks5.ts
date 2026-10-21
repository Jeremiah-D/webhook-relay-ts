import { Agent as HttpAgent } from "node:http";
import { Agent as HttpsAgent } from "node:https";
import { connect as tcpConnect, isIP, type Socket } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { createHash } from "node:crypto";

/**
 * Outbound SOCKS5 proxy support (WR-171).
 *
 * Orthogonal to the HTTP CONNECT proxy in `src/proxy.ts` (WR-27): this
 * module speaks RFC 1928 SOCKS5 (no-auth plus RFC 1929 username/password)
 * instead of HTTP `CONNECT`. The integration layer dispatches between the
 * two with {@link isSocks5ProxyUrl}.
 *
 * - proxy URL form: `socks5://[user:pass@]host[:port]`; the port defaults
 *   to 1080 when omitted (the parsed URL is never mutated — callers apply
 *   the default at dial time). The userinfo is the RFC 1929 credential;
 *   an empty userinfo means "offer no-auth only".
 * - `connectViaSocks5` runs the full handshake (greeting, optional
 *   username/password subnegotiation, CONNECT request) and resolves with
 *   the tunneled socket; both `http:` and `https:` targets ride the same
 *   tunnel. For HTTPS the TLS handshake runs over the tunneled socket
 *   (`tls.connect({ socket })`), so end-to-end encryption and the existing
 *   SPKI pinning path work unchanged — the SOCKS5 server sees only the
 *   CONNECT request, never the payload.
 * - tunneled sockets join the keep-alive pool keyed per
 *   `(proxy, scheme, host, port, pins)` via {@link socksPoolKeyFragment},
 *   whose `socks5` prefix keeps SOCKS5 pools from colliding with
 *   HTTP-CONNECT pools on identical URLs.
 *
 * Zero dependencies (`node:http(s)` + `node:net` + `node:tls` +
 * `node:crypto` only). This module must stay importable by `src/proxy.ts`,
 * so it never imports `src/proxy.ts` (no import cycle).
 */

/** Thrown when the SOCKS5 handshake with the proxy fails. */
export class Socks5Error extends Error {
  /** The proxy URL the handshake was attempted against. */
  readonly proxyUrl: string;
  /** The tunnel target. */
  readonly targetHost: string;
  readonly targetPort: number;
  /** Which handshake stage failed (`"method-selection"`, `"auth"`, `"connect"`), when known. */
  readonly stage?: string;
  constructor(
    proxyUrl: string,
    targetHost: string,
    targetPort: number,
    reason: string,
    stage?: string
  ) {
    super(`SOCKS5 ${targetHost}:${targetPort} via ${proxyUrl} failed: ${reason}`);
    this.name = "Socks5Error";
    this.proxyUrl = proxyUrl;
    this.targetHost = targetHost;
    this.targetPort = targetPort;
    this.stage = stage;
  }
}

/**
 * Validate a SOCKS5 proxy URL. Returns the parsed URL. Throws `RangeError`
 * when the value is not a URL, the scheme is not `socks5:` (compared
 * case-insensitively — `URL` parsing lowercases the protocol), or the
 * hostname is missing. The default port is 1080 when the URL carries no
 * explicit port; the URL itself is returned unmodified.
 */
export function assertValidSocks5Url(proxyUrl: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(proxyUrl);
  } catch {
    throw new RangeError(`SOCKS5 proxy: not a valid URL: ${proxyUrl}`);
  }
  if (parsed.protocol !== "socks5:") {
    throw new RangeError(
      `SOCKS5 proxy: only socks5: URLs are supported (got scheme ${parsed.protocol} in ${proxyUrl})`
    );
  }
  if (!parsed.hostname) {
    throw new RangeError(`SOCKS5 proxy: missing hostname: ${proxyUrl}`);
  }
  return parsed;
}

/**
 * True iff `proxyUrl` parses as a URL with a `socks5:` scheme. Never
 * throws — returns false for garbage input. The integration layer uses
 * this to dispatch between the HTTP-CONNECT agent (`src/proxy.ts`) and
 * the SOCKS5 agent here.
 */
export function isSocks5ProxyUrl(proxyUrl: string): boolean {
  try {
    return new URL(proxyUrl).protocol === "socks5:";
  } catch {
    return false;
  }
}

/** Pool-key fragment binding an agent to one SOCKS5 proxy URL. */
export function socksPoolKeyFragment(proxyUrl: string): string {
  return `|socks5:${createHash("sha256").update(proxyUrl).digest("hex").slice(0, 16)}`;
}

export interface ConnectViaSocks5Options {
  /** TCP connect + handshake timeout for the proxy leg. Default: 10_000. Must be > 0. */
  connectTimeoutMs?: number;
}

/** Human-readable reasons for non-zero SOCKS5 CONNECT reply codes (RFC 1928 §6). */
const SOCKS5_REP_REASONS: Record<number, string> = {
  0x01: "general SOCKS server failure",
  0x02: "connection not allowed by ruleset",
  0x03: "network unreachable",
  0x04: "host unreachable",
  0x05: "connection refused",
  0x06: "TTL expired",
  0x07: "command not supported",
  0x08: "address type not supported",
};

const SOCKS5_DEFAULT_PORT = 1080;

/** Encode an IPv6 literal into its 16-byte network form. */
function encodeIPv6Literal(addr: string): Buffer {
  const halves = addr.split("::");
  let head: string[] = [];
  let tail: string[] = [];
  if (halves.length === 2) {
    head = halves[0] === "" ? [] : halves[0].split(":");
    tail = halves[1] === "" ? [] : halves[1].split(":");
  } else {
    head = addr.split(":");
  }
  const missing = 8 - head.length - tail.length;
  const groups = [...head, ...new Array<string>(missing).fill("0"), ...tail];
  const out = Buffer.alloc(16);
  for (let i = 0; i < 8; i++) {
    out.writeUInt16BE(parseInt(groups[i], 16), i * 2);
  }
  return out;
}

/**
 * Encode the ATYP + ADDR portion of a SOCKS5 request: 0x01 for IPv4
 * literals, 0x04 for IPv6 literals, 0x03 plus a length byte for domain
 * names (RFC 1928 §5). Throws `RangeError` for empty/oversized names.
 */
function encodeSocks5Address(host: string): Buffer {
  const version = isIP(host);
  if (version === 4) {
    const octets = host.split(".").map(Number);
    return Buffer.from([0x01, ...octets]);
  }
  if (version === 6) {
    return Buffer.concat([Buffer.from([0x04]), encodeIPv6Literal(host)]);
  }
  const name = Buffer.from(host, "utf8");
  if (name.length === 0 || name.length > 255) {
    throw new RangeError(
      `connectViaSocks5: domain name must be 1-255 UTF-8 bytes, got ${name.length}`
    );
  }
  return Buffer.concat([Buffer.from([0x03, name.length]), name]);
}

/**
 * Open a SOCKS5 tunnel to `targetHost:targetPort` through the proxy at
 * `proxyUrl`. Resolves with the tunneled TCP socket once the proxy
 * answers the CONNECT with REP 0x00; rejects with `Socks5Error` on TCP
 * failure, timeout, method-selection failure (0xFF), username/password
 * rejection, or any non-zero CONNECT reply code.
 *
 * Auth credentials come from the proxy URL's userinfo
 * (`socks5://user:pass@proxy:1080`); when userinfo is present the client
 * offers both no-auth (0x00) and username/password (0x02) and runs the
 * RFC 1929 subnegotiation when the server selects 0x02.
 */
export function connectViaSocks5(
  proxyUrl: string,
  targetHost: string,
  targetPort: number,
  opts: ConnectViaSocks5Options = {}
): Promise<Socket> {
  const proxy = assertValidSocks5Url(proxyUrl);
  const connectTimeoutMs = opts.connectTimeoutMs ?? 10_000;
  if (!Number.isFinite(connectTimeoutMs) || connectTimeoutMs <= 0) {
    throw new RangeError(
      `connectViaSocks5: connectTimeoutMs must be a positive number, got ${opts.connectTimeoutMs}`
    );
  }
  const offerPassword = proxy.username !== "";

  return new Promise<Socket>((resolve, reject) => {
    let settled = false;
    let waiter: ((chunk: Buffer | null) => void) | null = null;
    let pending = Buffer.alloc(0);
    const sock = tcpConnect({
      host: proxy.hostname,
      port: Number(proxy.port) || SOCKS5_DEFAULT_PORT,
    });

    const fail = (err: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      sock.destroy();
      // Wake any in-flight read with EOF; the rejection below carries the
      // real error.
      const w = waiter;
      waiter = null;
      if (w) w(null);
      reject(err);
    };
    const timer = setTimeout(() => {
      fail(
        new Socks5Error(
          proxyUrl,
          targetHost,
          targetPort,
          `timed out after ${connectTimeoutMs}ms`
        )
      );
    }, connectTimeoutMs);
    // The handshake is transient: it must not pin process exit.
    timer.unref();

    sock.on("error", (err) => {
      fail(
        new Socks5Error(
          proxyUrl,
          targetHost,
          targetPort,
          `TCP connect to proxy failed: ${(err as Error).message}`
        )
      );
    });
    sock.on("close", () => {
      if (!settled) {
        fail(
          new Socks5Error(
            proxyUrl,
            targetHost,
            targetPort,
            "proxy closed the connection mid-handshake"
          )
        );
      }
    });

    const onData = (chunk: Buffer): void => {
      if (waiter !== null) {
        const w = waiter;
        waiter = null;
        w(chunk);
      } else {
        pending = Buffer.concat([pending, chunk]);
      }
    };
    sock.on("data", onData);

    const readBytes = async (n: number): Promise<Buffer> => {
      while (pending.length < n) {
        const chunk = await new Promise<Buffer | null>((res) => {
          waiter = res;
        });
        if (chunk === null) throw new Error("proxy connection closed mid-handshake");
        pending = Buffer.concat([pending, chunk]);
      }
      const out = Buffer.from(pending.subarray(0, n));
      pending = pending.subarray(n);
      return out;
    };

    const run = async (): Promise<Socket> => {
      // Greeting: offer no-auth always, plus username/password when the
      // proxy URL carries userinfo (RFC 1928 §3).
      const methods = offerPassword ? [0x00, 0x02] : [0x00];
      sock.write(Buffer.from([0x05, methods.length, ...methods]));

      const sel = await readBytes(2);
      if (sel[0] !== 0x05) {
        throw new Socks5Error(
          proxyUrl,
          targetHost,
          targetPort,
          `proxy replied with an invalid SOCKS version ${sel[0]} in method selection`,
          "method-selection"
        );
      }
      if (sel[1] === 0xff) {
        throw new Socks5Error(
          proxyUrl,
          targetHost,
          targetPort,
          "proxy reports no acceptable authentication method (0xFF)",
          "method-selection"
        );
      }
      if (sel[1] === 0x02) {
        if (!offerPassword) {
          throw new Socks5Error(
            proxyUrl,
            targetHost,
            targetPort,
            "proxy requested username/password auth but the proxy URL carries no userinfo",
            "auth"
          );
        }
        // RFC 1929 username/password subnegotiation.
        const user = Buffer.from(decodeURIComponent(proxy.username), "utf8");
        const pass = Buffer.from(decodeURIComponent(proxy.password), "utf8");
        if (user.length > 255 || pass.length > 255) {
          throw new Socks5Error(
            proxyUrl,
            targetHost,
            targetPort,
            "username or password exceeds the 255-byte RFC 1929 limit",
            "auth"
          );
        }
        sock.write(
          Buffer.concat([
            Buffer.from([0x01, user.length]),
            user,
            Buffer.from([pass.length]),
            pass,
          ])
        );
        const authResp = await readBytes(2);
        if (authResp[0] !== 0x01) {
          throw new Socks5Error(
            proxyUrl,
            targetHost,
            targetPort,
            `proxy replied with an invalid username/password subnegotiation version ${authResp[0]}`,
            "auth"
          );
        }
        if (authResp[1] !== 0x00) {
          throw new Socks5Error(
            proxyUrl,
            targetHost,
            targetPort,
            `username/password authentication rejected (status 0x${authResp[1].toString(16)}) — check the userinfo in the proxy URL`,
            "auth"
          );
        }
      } else if (sel[1] !== 0x00) {
        throw new Socks5Error(
          proxyUrl,
          targetHost,
          targetPort,
          `proxy selected unsupported auth method 0x${sel[1].toString(16).padStart(2, "0")}`,
          "method-selection"
        );
      }

      // CONNECT request (RFC 1928 §4).
      const addrPart = encodeSocks5Address(targetHost);
      const req = Buffer.alloc(4 + addrPart.length + 2);
      req[0] = 0x05;
      req[1] = 0x01;
      req[2] = 0x00;
      addrPart.copy(req, 3);
      req.writeUInt16BE(targetPort, 3 + addrPart.length);
      sock.write(req);

      const head = await readBytes(4);
      if (head[0] !== 0x05) {
        throw new Socks5Error(
          proxyUrl,
          targetHost,
          targetPort,
          `proxy replied with an invalid SOCKS version ${head[0]} in the CONNECT reply`,
          "connect"
        );
      }
      if (head[1] !== 0x00) {
        const reason =
          SOCKS5_REP_REASONS[head[1]] ??
          `unknown reply code 0x${head[1].toString(16).padStart(2, "0")}`;
        throw new Socks5Error(
          proxyUrl,
          targetHost,
          targetPort,
          `CONNECT rejected: ${reason}`,
          "connect"
        );
      }
      // Consume BND.ADDR + BND.PORT (their values are unused).
      const atyp = head[3];
      if (atyp === 0x01) {
        await readBytes(4);
      } else if (atyp === 0x04) {
        await readBytes(16);
      } else if (atyp === 0x03) {
        const len = (await readBytes(1))[0];
        await readBytes(len);
      } else {
        throw new Socks5Error(
          proxyUrl,
          targetHost,
          targetPort,
          `proxy replied with unsupported address type 0x${atyp.toString(16).padStart(2, "0")}`,
          "connect"
        );
      }
      await readBytes(2);
      return sock;
    };

    sock.on("connect", () => {
      run().then(
        (tunneled) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          sock.removeListener("data", onData);
          // A well-behaved proxy sends nothing after the reply, but
          // unshift defensively — tunneled bytes must never be lost.
          if (pending.length > 0) sock.unshift(pending);
          resolve(tunneled);
        },
        (err) =>
          fail(
            err instanceof Socks5Error
              ? err
              : new Socks5Error(proxyUrl, targetHost, targetPort, (err as Error).message)
          )
      );
    });
  });
}

export interface Socks5AgentOptions {
  keepAlive?: boolean;
  keepAliveMsecs?: number;
  maxSockets?: number;
  maxFreeSockets?: number;
  freeSocketTimeout?: number;
  /**
   * `https.Agent` TLS session cache size. The agent caches client TLS
   * sessions and resumes them on later handshakes; on a resumed handshake
   * the server does not re-send its certificate, so pass `0` for pinned
   * endpoints — the pin check must see the peer's SPKI on every new
   * connection.
   */
  maxCachedSessions?: number;
  /** TCP connect + handshake timeout for the proxy leg, per new socket. */
  socksConnectTimeoutMs?: number;
}

/**
 * An `http(s).Agent` whose sockets are SOCKS5 tunnels through `proxyUrl`
 * (see {@link connectViaSocks5}). For `https:` targets the TLS handshake
 * runs over the tunnel via `tls.connect({ socket })`, honoring the merged
 * request/agent options the same way `https.Agent` would — notably
 * `rejectUnauthorized`, `servername` for SNI, and `ALPNProtocols` — so a
 * per-endpoint SNI/ALPN override (see `src/tls-sni.ts`) and the SPKI
 * pinning path apply over the SOCKS5 tunnel exactly as on a direct
 * connection.
 *
 * The returned agent does normal keep-alive bookkeeping on the tunneled
 * sockets, so it drops straight into `OutboundConnectionPool` or serves a
 * single delivery when pooling is disabled.
 */
export function createSocks5Agent(
  scheme: "http" | "https",
  proxyUrl: string,
  opts: Socks5AgentOptions = {}
): HttpAgent {
  assertValidSocks5Url(proxyUrl);
  const { socksConnectTimeoutMs, ...agentOpts } = opts;
  const agent: HttpAgent =
    scheme === "https" ? new HttpsAgent(agentOpts) : new HttpAgent(agentOpts);
  // Async createConnection: return undefined and deliver the socket via
  // `oncreate` once the SOCKS5 handshake (+ TLS handshake) completes.
  // (Verified against Node v24's Agent.createSocket.)
  agent.createConnection = ((options: Record<string, unknown>, oncreate: (err: Error | null, sock?: Socket) => void): undefined => {
    let done = false;
    const cb = (err: Error | null, sock?: Socket): void => {
      if (done) return;
      done = true;
      oncreate(err, sock);
    };
    const targetHost = options.host as string;
    const targetPort = Number(options.port ?? (scheme === "https" ? 443 : 80));
    connectViaSocks5(proxyUrl, targetHost, targetPort, {
      ...(socksConnectTimeoutMs !== undefined
        ? { connectTimeoutMs: socksConnectTimeoutMs }
        : {}),
    }).then(
      (sock) => {
        if (scheme === "http") {
          cb(null, sock);
          return;
        }
        const tlsSock = tlsConnect({
          socket: sock,
          servername: (options.servername as string | undefined) ?? targetHost,
          ALPNProtocols: options.ALPNProtocols as string[] | undefined,
          rejectUnauthorized: options.rejectUnauthorized !== false,
        });
        tlsSock.once("secureConnect", () => cb(null, tlsSock as unknown as Socket));
        tlsSock.once("error", (err) => {
          tlsSock.destroy();
          cb(err);
        });
      },
      (err) => cb(err as Error)
    );
    return undefined;
  }) as typeof agent.createConnection;
  return agent;
}
