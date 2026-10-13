import type { Socket } from "node:net";
import type { Agent as HttpAgent } from "node:http";
import type { TLSSocket } from "node:tls";
import { OutboundConnectionPool } from "./keepalive.ts";
import { type TlsClientCert, clientCertIdentity } from "./mtls.ts";
import { type RotatingClientCertSet } from "./mtls-rotation.ts";
import {
  resolveTlsSniOverride,
  type ResolvedTlsSniOverride,
  type TlsSniOverride,
} from "./tls-sni.ts";
import { resolveProxyUrl } from "./proxy.ts";
import { spkiFingerprint, normalizePin } from "./pinning.ts";

/**
 * Outbound connection warm-up (WR-70).
 *
 * The keep-alive pool (WR-24, `src/keepalive.ts`) creates agents lazily:
 * the first delivery to an origin pays the full TCP (+ TLS) handshake.
 * Warm-up pre-establishes connections for a configured endpoint list at
 * relay startup, so the first real deliveries reuse an already-open
 * socket — zero handshake delay on the hot path.
 *
 * How it works: for each endpoint the exact pool agent the delivery path
 * would use is resolved (`pool.agentFor` with the same pins / proxy /
 * client-identity / SNI inputs the sender uses), then sockets are opened
 * through the agent's own `createConnection` — the same funnel every
 * pooled connection comes through — and parked in the agent's free list
 * via the agent's own `getName` bucket key, so a later delivery claims
 * them like any idle pooled socket (health probe, idle reaping, and
 * per-identity keying all apply unchanged).
 *
 * Fidelity notes, stated plainly:
 * - No application bytes are ever sent: warm-up opens the transport
 *   (TCP, plus the TLS handshake for `https:`) and parks the socket.
 * - TLS pins *are* verified during warm-up, against the same whitelist
 *   the delivery path uses: the peer certificate is read after the
 *   handshake and its SPKI fingerprint must be in the whitelist, else
 *   the warm-up fails with `pin_mismatch` and the socket is destroyed.
 *   The verified fingerprint is cached on the pooled socket
 *   (`pool.cachePresentedPin`), which is what the keep-alive pool's
 *   health probe requires before it will hand a pinned socket to a
 *   delivery — without it, warmed pinned sockets would be culled as
 *   fail-closed on first checkout. A warmed-then-reused connection is
 *   never re-verified per request beyond the pool's cached-pin check,
 *   exactly like any pooled pinned connection.
 * - mTLS client certificates *are* presented during warm-up (the warmed
 *   connection must carry the same identity the pool key promises), and
 *   SNI/ALPN overrides are applied to the handshake.
 * - A warm-up failure (refused, timeout, DNS, TLS error, pin mismatch)
 *   is reported per endpoint and never throws: the first delivery to
 *   that origin simply pays the handshake it would have paid without
 *   warm-up.
 *
 * Zero dependencies (`node:http(s)` + `node:net` only).
 */

/** Per-endpoint outbound config maps, mirroring the sender's lookups. */
export interface WarmupEndpointConfig {
  tlsPins?: Record<string, string[]>;
  proxies?: Record<string, string>;
  tlsClientCerts?: Record<string, TlsClientCert>;
  tlsSniOverrides?: Record<string, TlsSniOverride>;
  /**
   * WR-89: compiled rotation sets per endpoint. A rotation endpoint
   * warms the primary identity's agent — the agent new handshakes will
   * actually use.
   */
  tlsClientCertRotations?: Map<string, RotatingClientCertSet>;
}

/** Tuning for {@link warmupOutboundPool}. All values are validated up front. */
export interface WarmupOptions {
  /**
   * Per-connection establishment timeout in ms. Default: 5000. Must be
   * a positive finite number.
   */
  timeoutMs?: number;
  /**
   * Maximum concurrent warm-up connections. Default: 8. Must be a
   * positive integer.
   */
  concurrency?: number;
  /**
   * Sockets to pre-establish per unique origin (pool agent). Default: 1.
   * Must be a positive integer.
   */
  socketsPerOrigin?: number;
}

const DEFAULTS = {
  timeoutMs: 5000,
  concurrency: 8,
  socketsPerOrigin: 1,
} as const;

export interface ResolvedWarmupOptions {
  timeoutMs: number;
  concurrency: number;
  socketsPerOrigin: number;
}

/** Validate warm-up options the way a constructor would; returns the resolved values. */
export function resolveWarmupOptions(opts: WarmupOptions = {}): ResolvedWarmupOptions {
  const timeoutMs = opts.timeoutMs ?? DEFAULTS.timeoutMs;
  const concurrency = opts.concurrency ?? DEFAULTS.concurrency;
  const socketsPerOrigin = opts.socketsPerOrigin ?? DEFAULTS.socketsPerOrigin;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new RangeError(`warmup: timeoutMs must be a positive finite number, got ${timeoutMs}`);
  }
  if (!Number.isInteger(concurrency) || concurrency <= 0) {
    throw new RangeError(`warmup: concurrency must be a positive integer, got ${concurrency}`);
  }
  if (!Number.isInteger(socketsPerOrigin) || socketsPerOrigin <= 0) {
    throw new RangeError(`warmup: socketsPerOrigin must be a positive integer, got ${socketsPerOrigin}`);
  }
  return { timeoutMs, concurrency, socketsPerOrigin };
}

/** One endpoint's warm-up outcome. `ok: false` never throws — the error is data. */
export interface WarmupEndpointResult {
  /** The endpoint string as configured. */
  endpoint: string;
  /** `scheme://host:port` the connection was opened to ("" when the URL was invalid). */
  origin: string;
  ok: boolean;
  /** Present when `ok` is false: `invalid_url`, `unsupported_protocol`, `connect_timeout`, or the socket error. */
  error?: string;
  /** Ms until the socket was established (handshake included). */
  connectMs?: number;
}

export interface WarmupReport {
  results: WarmupEndpointResult[];
  warmed: number;
  failed: number;
  /** Wall-clock ms for the whole warm-up. */
  elapsedMs: number;
}

/** A warm-up target resolved to the exact inputs the sender's pool lookup uses. */
interface ResolvedWarmupTarget {
  endpoint: string;
  url: URL;
  pins: string[] | undefined;
  proxyUrl: string | undefined;
  clientCert: TlsClientCert | undefined;
  tlsSni: ResolvedTlsSniOverride | undefined;
}

/**
 * Resolve one configured endpoint to the pool inputs the delivery path
 * uses, mirroring `defaultSender`'s per-endpoint lookups (exact
 * `targetUrl` match). Returns the failure reason instead of throwing for
 * unusable endpoints — warm-up degrades per endpoint, never at startup.
 */
function resolveWarmupTarget(
  endpoint: string,
  cfg: WarmupEndpointConfig
): ResolvedWarmupTarget | { error: string } {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    return { error: `invalid_url: ${endpoint}` };
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { error: `unsupported_protocol: ${url.protocol} (warm-up covers http:/https: only)` };
  }
  // Mirrors defaultSender: pins and client certs are exact-targetUrl
  // matches, SNI overrides resolve per target, proxies fall back to the
  // environment (read now — a proxy rotation after startup only affects
  // deliveries, which re-resolve per attempt).
  const pins = url.protocol === "https:" ? cfg.tlsPins?.[endpoint] : undefined;
  // WR-89: a rotation endpoint warms the primary identity's agent — the
  // one new handshakes will use — mirroring defaultSender's lookup.
  const clientCert =
    url.protocol === "https:"
      ? (cfg.tlsClientCertRotations?.get(endpoint)?.primary().cert ?? cfg.tlsClientCerts?.[endpoint])
      : undefined;
  const tlsSni = url.protocol === "https:" ? resolveTlsSniOverride(endpoint, url, cfg.tlsSniOverrides) : undefined;
  let proxyUrl: string | undefined;
  try {
    proxyUrl = resolveProxyUrl(endpoint, cfg.proxies);
  } catch (err) {
    return { error: `invalid_proxy: ${(err as Error).message}` };
  }
  return { endpoint, url, pins, proxyUrl, clientCert, tlsSni };
}

function defaultPort(url: URL): number {
  if (url.port !== "") return Number(url.port);
  return url.protocol === "https:" ? 443 : 80;
}

/**
 * Open one socket through the agent's own `createConnection` funnel —
 * the same path every pooled connection takes. Readiness is reported
 * three different ways depending on the agent:
 * - plain `http.Agent`: the callback fires on `connect` (with no
 *   arguments — the socket is the synchronous return value);
 * - plain `https.Agent`: the callback is *not* forwarded on the
 *   non-proxied path (`tls.connect(options)` without cb), so readiness
 *   is awaited via an explicit `secureConnect` listener;
 * - proxied agent (`src/proxy.ts`): returns `undefined` and delivers the
 *   ready socket via the callback after the CONNECT exchange (+ TLS).
 * The settled guard makes the redundant listeners harmless; a socket
 * that arrives after a timeout (or a duplicate) is destroyed, never
 * leaked.
 */
function createConnectionAsync(
  agent: HttpAgent,
  connOpts: Record<string, unknown>,
  timeoutMs: number
): Promise<{ socket: Socket; connectMs: number }> {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    let settled = false;
    let sockRef: Socket | undefined;
    let accepted: Socket | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const done = (err: Error | null, sock?: Socket): void => {
      // The default agents' callback fires with no arguments (a 'connect'
      // / 'secureConnect' listener) — the socket is the synchronous return
      // value, captured in sockRef. The proxied agent delivers it via the
      // callback instead.
      const s = sock ?? sockRef;
      if (settled) {
        if (s !== undefined && s !== accepted) s.destroy();
        return;
      }
      settled = true;
      if (timer !== undefined) clearTimeout(timer);
      if (err != null || s === undefined) {
        sockRef?.destroy();
        reject(err ?? new Error("warmup: connection failed"));
        return;
      }
      accepted = s;
      resolve({ socket: s, connectMs: Date.now() - start });
    };
    timer = setTimeout(() => {
      timer = undefined;
      done(new Error(`warmup: connect_timeout after ${timeoutMs}ms`));
    }, timeoutMs);
    timer.unref();
    let ret: unknown;
    try {
      ret = (agent.createConnection as (o: unknown, cb: (e: Error | null, s?: Socket) => void) => unknown)(
        connOpts,
        done
      );
    } catch (err) {
      done(err as Error);
      return;
    }
    if (ret !== undefined && ret !== null && typeof (ret as Socket).once === "function") {
      // Sync style: the default agents hand back the socket. The
      // explicit readiness listener covers the https agent (which does
      // not forward the callback); on plain http it is redundant with
      // the callback, and the settled guard makes the double-fire
      // harmless. An early failure only emits 'error', so listen for it
      // to settle promptly instead of hanging until the timeout.
      sockRef = ret as Socket;
      const isTls = (sockRef as unknown as { encrypted?: boolean }).encrypted === true;
      sockRef.once("error", (err: Error) => done(err));
      sockRef.once(isTls ? "secureConnect" : "connect", () => done(null, sockRef));
    }
    // Async style (proxied agent): `done` fires via oncreate once the
    // tunnel (+ TLS handshake) is ready.
  });
}

/**
 * Park a warmed socket in the agent's free list under the exact bucket
 * key a real delivery's request would use, then mark it idle (stamped +
 * unref'd) like any settled pooled socket. The bucket key is computed
 * with the agent's own `getName` over the same request options the
 * sender passes — host/port plus the TLS-affecting options
 * (`rejectUnauthorized` for pinned endpoints, the mTLS cert/key) — so a
 * warmed socket can never land in a bucket a delivery won't look in.
 *
 * The socket also gets the `free`-forwarding listener Node's
 * `installListeners` would have attached (we bypassed `createSocket`):
 * when the HTTP parser emits `free` after a keep-alive response
 * completes, it is forwarded into the agent's free handler, so a warmed
 * socket returns to the pool after its first delivery exactly like a
 * normally-pooled socket (with the data guard and error listener the
 * handler installs). Without this, the first delivery would orphan the
 * socket — served once, never reused.
 */
function parkWarmedSocket(
  pool: OutboundConnectionPool,
  agent: HttpAgent,
  url: URL,
  socket: Socket,
  target: ResolvedWarmupTarget
): void {
  // Mirrors deliverViaHttp1's request options: pinned endpoints set
  // rejectUnauthorized: false (the pin is the trust anchor, verified
  // per request), and the client certificate rides the handshake.
  const reqOpts: Record<string, unknown> = {
    host: url.hostname,
    port: defaultPort(url),
    ...(target.pins !== undefined ? { rejectUnauthorized: false } : {}),
    ...(target.tlsSni?.servername !== undefined ? { servername: target.tlsSni.servername } : {}),
    ...(target.clientCert !== undefined
      ? {
          cert: target.clientCert.cert,
          key: target.clientCert.key,
          ...(target.clientCert.passphrase !== undefined ? { passphrase: target.clientCert.passphrase } : {}),
        }
      : {}),
  };
  const getName = (agent as unknown as { getName(o: Record<string, unknown>): string }).getName.bind(agent);
  const name = getName(reqOpts);
  socket.on("free", () => {
    (agent as unknown as { emit(event: string, ...args: unknown[]): void }).emit("free", socket, reqOpts);
  });
  const free = agent.freeSockets as unknown as Record<string, Socket[]>;
  (free[name] ??= []).push(socket);
  pool.markIdle(agent);
}

async function warmOneTarget(
  pool: OutboundConnectionPool,
  target: ResolvedWarmupTarget,
  opts: ResolvedWarmupOptions
): Promise<WarmupEndpointResult> {
  const url = target.url;
  const origin = `${url.protocol}//${url.hostname}:${defaultPort(url)}`;
  let agent: HttpAgent;
  try {
    // The exact agent the delivery path would use for this endpoint —
    // per pin whitelist, proxy, client identity, and TLS identity, so a
    // warmed socket can never serve an endpoint it wasn't warmed for.
    agent = pool.agentFor(
      url,
      target.pins,
      target.proxyUrl,
      target.clientCert !== undefined ? clientCertIdentity(target.clientCert) : undefined,
      target.tlsSni
    );
  } catch (err) {
    return { endpoint: target.endpoint, origin, ok: false, error: (err as Error).message };
  }
  // TLS options mirror deliverViaHttp1: SNI/ALPN overrides apply to the
  // handshake, pinned endpoints use the pin (not PKI) as the trust
  // anchor — the pin itself is verified on first delivery — and the
  // client certificate rides the handshake.
  const connOpts: Record<string, unknown> = {
    host: url.hostname,
    port: defaultPort(url),
    ...(target.tlsSni?.servername !== undefined ? { servername: target.tlsSni.servername } : {}),
    ...(target.tlsSni !== undefined ? { ALPNProtocols: [...target.tlsSni.alpnProtocols] } : {}),
    ...(target.pins !== undefined ? { rejectUnauthorized: false } : {}),
    ...(target.clientCert !== undefined
      ? {
          cert: target.clientCert.cert,
          key: target.clientCert.key,
          ...(target.clientCert.passphrase !== undefined ? { passphrase: target.clientCert.passphrase } : {}),
        }
      : {}),
  };
  let connectMs = 0;
  for (let i = 0; i < opts.socketsPerOrigin; i++) {
    try {
      const { socket, connectMs: ms } = await createConnectionAsync(agent, connOpts, opts.timeoutMs);
      connectMs = ms;
      // Pinned endpoints: verify the peer's SPKI against the whitelist
      // now — the pool's health probe fail-closes a pinned socket with
      // no cached pin, so an unverified warmed socket would be culled on
      // first checkout and the warm-up would be pointless. A mismatch
      // fails the warm-up (the delivery would fail the same way) and
      // the socket is destroyed, never parked.
      if (target.pins !== undefined) {
        const pinError = verifyWarmedPin(pool, socket, target.pins);
        if (pinError !== undefined) {
          socket.destroy();
          return { endpoint: target.endpoint, origin, ok: false, error: pinError };
        }
      }
      parkWarmedSocket(pool, agent, url, socket, target);
    } catch (err) {
      return { endpoint: target.endpoint, origin, ok: false, error: (err as Error).message };
    }
  }
  return { endpoint: target.endpoint, origin, ok: true, connectMs };
}

/**
 * Verify a warmed TLS socket's peer against the endpoint's pin
 * whitelist (the same check `deliverViaHttp1` performs per request) and
 * cache the verified fingerprint on the pooled socket, which the
 * keep-alive pool's pre-reuse health probe requires. Returns the failure
 * reason, or `undefined` when the pin verifies.
 */
function verifyWarmedPin(
  pool: OutboundConnectionPool,
  socket: Socket,
  pins: string[]
): string | undefined {
  let presented: string;
  try {
    const raw = (socket as TLSSocket).getPeerCertificate().raw;
    presented = spkiFingerprint(Buffer.from(raw as Buffer));
  } catch {
    return "warmup: pin_unverifiable (could not read the peer certificate)";
  }
  const allowed = pins.map(normalizePin);
  if (!allowed.includes(presented)) {
    return `warmup: pin_mismatch (peer SPKI not in the endpoint's whitelist)`;
  }
  pool.cachePresentedPin(socket, presented);
  return undefined;
}

/**
 * Pre-establish keep-alive connections for `endpoints` on `pool`.
 * Endpoints sharing an origin (same pool agent) warm it once;
 * `socketsPerOrigin` controls how many sockets each origin gets.
 * Per-endpoint failures are reported in the result — this function never
 * rejects for an endpoint problem, so callers can fire-and-forget it at
 * startup without risking the relay.
 */
export async function warmupOutboundPool(
  pool: OutboundConnectionPool,
  endpoints: string[],
  cfg: WarmupEndpointConfig = {},
  opts: WarmupOptions = {}
): Promise<WarmupReport> {
  const resolved = resolveWarmupOptions(opts);
  const start = Date.now();
  // Dedupe by endpoint string; origins shared across endpoints warm once
  // (the agent is per origin+identity, so agentFor dedupes naturally —
  // track warmed agents to avoid opening duplicate sockets).
  const seenEndpoints = new Set<string>();
  const warmedAgents = new Set<HttpAgent>();
  type Job = { target: ResolvedWarmupTarget } | { failure: WarmupEndpointResult };
  const jobs: Job[] = [];
  for (const endpoint of endpoints) {
    if (seenEndpoints.has(endpoint)) continue;
    seenEndpoints.add(endpoint);
    const t = resolveWarmupTarget(endpoint, cfg);
    if ("error" in t) {
      jobs.push({ failure: { endpoint, origin: "", ok: false, error: t.error } });
    } else {
      jobs.push({ target: t });
    }
  }
  const results: WarmupEndpointResult[] = [];
  // Bounded worker pool over the jobs.
  let next = 0;
  const workers: Promise<void>[] = [];
  const workerCount = Math.min(resolved.concurrency, Math.max(jobs.length, 1));
  for (let w = 0; w < workerCount; w++) {
    workers.push(
      (async () => {
        while (next < jobs.length) {
          const job = jobs[next++];
          if ("failure" in job) {
            results.push(job.failure);
            continue;
          }
          // One agent per unique origin+identity warms once even when
          // several endpoints resolve to it (e.g. same origin listed
          // with and without a path).
          const probe = pool.agentFor(
            job.target.url,
            job.target.pins,
            job.target.proxyUrl,
            job.target.clientCert !== undefined ? clientCertIdentity(job.target.clientCert) : undefined,
            job.target.tlsSni
          );
          if (warmedAgents.has(probe)) {
            results.push({ endpoint: job.target.endpoint, origin: `${job.target.url.protocol}//${job.target.url.hostname}:${defaultPort(job.target.url)}`, ok: true, connectMs: 0 });
            continue;
          }
          warmedAgents.add(probe);
          results.push(await warmOneTarget(pool, job.target, resolved));
        }
      })()
    );
  }
  await Promise.all(workers);
  // Keep result order stable (input order) regardless of worker timing.
  const order = new Map(endpoints.map((e, i) => [e, i]));
  results.sort((a, b) => (order.get(a.endpoint) ?? 0) - (order.get(b.endpoint) ?? 0));
  return {
    results,
    warmed: results.filter((r) => r.ok).length,
    failed: results.filter((r) => !r.ok).length,
    elapsedMs: Date.now() - start,
  };
}
