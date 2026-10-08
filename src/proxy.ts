import { Agent as HttpAgent } from "node:http";
import { Agent as HttpsAgent } from "node:https";
import { connect as tcpConnect, type Socket } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { createHash } from "node:crypto";

/**
 * Outbound HTTP(S) proxy support (WR-27).
 *
 * Corporate egress often forces outbound traffic through a proxy. This
 * module adds CONNECT tunneling to the default sender:
 *
 * - per-endpoint explicit config (`proxies: { "<exact targetUrl>": "<proxyUrl>" }`)
 *   plus environment fallback (`HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY`,
 *   lowercase variants honored, `NO_PROXY` bypass) — the environment is
 *   read per delivery, so a rotated proxy URL needs no restart;
 * - the tunnel is established with a plain `CONNECT host:port` exchange
 *   (proxy basic auth from the proxy URL's userinfo:
 *   `http://user:pass@proxy:8080`); the proxy itself is plain HTTP —
 *   proxy-over-TLS is out of scope and rejected at validation;
 * - both `http:` and `https:` targets ride the same tunnel: for HTTPS the
 *   TLS handshake runs over the tunneled socket (`tls.connect({ socket })`),
 *   so end-to-end encryption and the existing SPKI pinning path
 *   (`secureConnect` → `verifyFreshPin`) work unchanged — the proxy sees
 *   only the CONNECT line, never the payload;
 * - tunneled sockets join the keep-alive pool (`OutboundConnectionPool`)
 *   keyed per `(proxy, scheme, host, port, pins)`, so one CONNECT serves
 *   many deliveries and a connection through proxy A can never serve an
 *   endpoint routed through proxy B.
 *
 * Zero dependencies (`node:http(s)` + `node:net` + `node:tls` only).
 */

/** Thrown when the CONNECT exchange with the proxy fails. */
export class ProxyConnectError extends Error {
  /** The proxy URL the CONNECT was attempted against. */
  readonly proxyUrl: string;
  /** The tunnel target. */
  readonly targetHost: string;
  readonly targetPort: number;
  /** The proxy's HTTP status, when it answered with one. */
  readonly statusCode?: number;
  constructor(
    proxyUrl: string,
    targetHost: string,
    targetPort: number,
    reason: string,
    statusCode?: number
  ) {
    super(`Proxy CONNECT ${targetHost}:${targetPort} via ${proxyUrl} failed: ${reason}`);
    this.name = "ProxyConnectError";
    this.proxyUrl = proxyUrl;
    this.targetHost = targetHost;
    this.targetPort = targetPort;
    this.statusCode = statusCode;
  }
}

/**
 * Validate a proxy URL. Returns the parsed URL. Throws `RangeError` when
 * the value is not a URL or uses a scheme other than `http:` — the proxy
 * leg itself is plain TCP (proxy-over-TLS is out of scope); TLS to the
 * *target* still happens over the tunnel for `https:` endpoints.
 */
export function assertValidProxyUrl(proxyUrl: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(proxyUrl);
  } catch {
    throw new RangeError(`Outbound proxy: not a valid URL: ${proxyUrl}`);
  }
  if (parsed.protocol !== "http:") {
    throw new RangeError(
      `Outbound proxy: only plain-HTTP proxies are supported (got scheme ${parsed.protocol} in ${proxyUrl})`
    );
  }
  if (!parsed.hostname) {
    throw new RangeError(`Outbound proxy: missing hostname: ${proxyUrl}`);
  }
  return parsed;
}

/** Match `host` against one `NO_PROXY` entry (exact or domain suffix). */
function noProxyEntryMatches(entry: string, host: string): boolean {
  let e = entry.trim().toLowerCase();
  if (e === "" || e === "*") return e === "*";
  // Strip an optional :port suffix (but not IPv6 literals).
  if (!e.startsWith("[")) {
    const colon = e.lastIndexOf(":");
    if (colon !== -1 && /^\d+$/.test(e.slice(colon + 1))) e = e.slice(0, colon);
  }
  const h = host.toLowerCase();
  if (h === e) return true;
  const suffix = e.startsWith(".") ? e : `.${e}`;
  return h.endsWith(suffix);
}

function hostBypassedByNoProxy(host: string): boolean {
  const noProxy = process.env.NO_PROXY ?? process.env.no_proxy;
  if (!noProxy) return false;
  return noProxy.split(",").some((entry) => noProxyEntryMatches(entry, host));
}

function proxyFromEnv(protocol: string): string | undefined {
  const pick = (...names: string[]): string | undefined => {
    for (const name of names) {
      const v = process.env[name];
      if (v !== undefined && v.trim() !== "") return v.trim();
    }
    return undefined;
  };
  if (protocol === "https:") {
    return pick("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy");
  }
  if (protocol === "http:") {
    return pick("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy");
  }
  return undefined;
}

/**
 * Resolve the proxy URL for a delivery target.
 *
 * Precedence: explicit per-endpoint config (exact `targetUrl` match) beats
 * the environment (`HTTPS_PROXY`/`HTTP_PROXY`/`ALL_PROXY` and lowercase
 * variants, chosen by target scheme). `NO_PROXY` bypasses the environment
 * fallback only — an explicit entry always wins, because it is the most
 * specific operator intent. The environment is read at call time — per
 * delivery — so proxy rotation needs no restart. Returns `undefined` when
 * no proxy applies.
 *
 * Throws `RangeError` when the selected proxy URL is invalid (explicit
 * values are validated once at startup by `createDefaultSender`; an
 * invalid *environment* value surfaces here, per delivery, and fails that
 * delivery through the normal retry path).
 */
export function resolveProxyUrl(
  targetUrl: string,
  proxies?: Record<string, string>
): string | undefined {
  const target = new URL(targetUrl);
  if (target.protocol !== "http:" && target.protocol !== "https:") return undefined;
  const explicit = proxies?.[targetUrl];
  if (explicit !== undefined) {
    assertValidProxyUrl(explicit);
    return explicit;
  }
  if (hostBypassedByNoProxy(target.hostname)) return undefined;
  const selected = proxyFromEnv(target.protocol);
  if (selected === undefined) return undefined;
  assertValidProxyUrl(selected);
  return selected;
}

/** Pool-key fragment binding an agent to one proxy URL. */
export function proxyPoolKeyFragment(proxyUrl: string): string {
  return `|proxy:${createHash("sha256").update(proxyUrl).digest("hex").slice(0, 16)}`;
}

export interface ConnectViaProxyOptions {
  /** TCP connect timeout for the proxy leg. Default: 10_000. Must be > 0. */
  connectTimeoutMs?: number;
}

const CONNECT_RESPONSE_HEAD_LIMIT = 8192;

/**
 * Open a CONNECT tunnel to `targetHost:targetPort` through the proxy at
 * `proxyUrl`. Resolves with the tunneled TCP socket once the proxy answers
 * `200`; rejects with `ProxyConnectError` on TCP failure, timeout, `407`
 * (proxy auth required / bad credentials), or any other non-200 status.
 * Proxy basic-auth credentials come from the proxy URL's userinfo.
 */
export function connectViaProxy(
  proxyUrl: string,
  targetHost: string,
  targetPort: number,
  opts: ConnectViaProxyOptions = {}
): Promise<Socket> {
  const proxy = assertValidProxyUrl(proxyUrl);
  const connectTimeoutMs = opts.connectTimeoutMs ?? 10_000;
  if (!Number.isFinite(connectTimeoutMs) || connectTimeoutMs <= 0) {
    throw new RangeError(
      `connectViaProxy: connectTimeoutMs must be a positive number, got ${opts.connectTimeoutMs}`
    );
  }
  return new Promise<Socket>((resolve, reject) => {
    let settled = false;
    const sock = tcpConnect({ host: proxy.hostname, port: Number(proxy.port) || 80 });
    const fail = (err: Error): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      sock.destroy();
      reject(err);
    };
    const timer = setTimeout(() => {
      fail(
        new ProxyConnectError(proxyUrl, targetHost, targetPort, `timed out after ${connectTimeoutMs}ms`)
      );
    }, connectTimeoutMs);
    // The CONNECT exchange is transient: it must not pin process exit.
    timer.unref();

    sock.on("error", (err) => {
      fail(
        new ProxyConnectError(
          proxyUrl,
          targetHost,
          targetPort,
          `TCP connect to proxy failed: ${(err as Error).message}`
        )
      );
    });
    sock.on("connect", () => {
      let head = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n`;
      if (proxy.username !== "") {
        const creds = `${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`;
        head += `Proxy-Authorization: Basic ${Buffer.from(creds).toString("base64")}\r\n`;
      }
      sock.write(`${head}\r\n`);
    });

    let buf = Buffer.alloc(0);
    const onData = (chunk: Buffer): void => {
      if (settled) return;
      buf = Buffer.concat([buf, chunk]);
      const end = buf.indexOf("\r\n\r\n");
      if (end === -1) {
        if (buf.length > CONNECT_RESPONSE_HEAD_LIMIT) {
          fail(
            new ProxyConnectError(
              proxyUrl,
              targetHost,
              targetPort,
              "proxy response head exceeds 8 KiB"
            )
          );
        }
        return;
      }
      const statusLine = buf.subarray(0, end).toString("latin1").split("\r\n")[0] ?? "";
      const rest = buf.subarray(end + 4);
      const m = /^HTTP\/\d(?:\.\d)?\s+(\d{3})/.exec(statusLine);
      const status = m ? Number(m[1]) : 0;
      clearTimeout(timer);
      if (status === 200) {
        settled = true;
        sock.removeListener("data", onData);
        // A well-behaved proxy sends nothing after the 200, but unshift
        // defensively — tunneled bytes must never be lost.
        if (rest.length > 0) sock.unshift(rest);
        resolve(sock);
        return;
      }
      if (status === 407) {
        fail(
          new ProxyConnectError(
            proxyUrl,
            targetHost,
            targetPort,
            "proxy authentication required (407) — check the userinfo in the proxy URL",
            407
          )
        );
        return;
      }
      fail(
        new ProxyConnectError(
          proxyUrl,
          targetHost,
          targetPort,
          `CONNECT rejected with status ${status === 0 ? JSON.stringify(statusLine) : status}`,
          status === 0 ? undefined : status
        )
      );
    };
    sock.on("data", onData);
  });
}

export interface ProxiedAgentOptions {
  keepAlive?: boolean;
  keepAliveMsecs?: number;
  maxSockets?: number;
  maxFreeSockets?: number;
  freeSocketTimeout?: number;
  /** TCP connect timeout for the proxy leg, per new socket. */
  proxyConnectTimeoutMs?: number;
}

/**
 * An `http(s).Agent` whose sockets are CONNECT tunnels through `proxyUrl`
 * (see {@link connectViaProxy}). For `https:` targets the TLS handshake
 * runs over the tunnel via `tls.connect({ socket })`, honoring the merged
 * request/agent options the same way `https.Agent` would — notably
 * `rejectUnauthorized` (the default sender passes `false` there when SPKI
 * pins are configured, making the pin the trust anchor) and `servername`
 * for SNI.
 *
 * The returned agent does normal keep-alive bookkeeping on the tunneled
 * sockets, so it drops straight into `OutboundConnectionPool` or serves a
 * single delivery when pooling is disabled.
 */
export function createProxiedAgent(
  scheme: "http" | "https",
  proxyUrl: string,
  opts: ProxiedAgentOptions = {}
): HttpAgent {
  assertValidProxyUrl(proxyUrl);
  const { proxyConnectTimeoutMs, ...agentOpts } = opts;
  const agent: HttpAgent =
    scheme === "https" ? new HttpsAgent(agentOpts) : new HttpAgent(agentOpts);
  // Async createConnection: return undefined and deliver the socket via
  // `oncreate` once the CONNECT exchange (+ TLS handshake) completes.
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
    connectViaProxy(proxyUrl, targetHost, targetPort, {
      ...(proxyConnectTimeoutMs !== undefined ? { connectTimeoutMs: proxyConnectTimeoutMs } : {}),
    }).then(
      (sock) => {
        if (scheme === "http") {
          cb(null, sock);
          return;
        }
        const tlsSock = tlsConnect({
          socket: sock,
          servername: (options.servername as string | undefined) ?? targetHost,
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
