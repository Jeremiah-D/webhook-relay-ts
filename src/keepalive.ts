import { Agent as HttpAgent } from "node:http";
import { Agent as HttpsAgent } from "node:https";
import type { ClientRequest, ClientRequestArgs } from "node:http";
import type { Socket } from "node:net";
import type { LookupFunction } from "node:net";
import { createHash } from "node:crypto";
import { normalizePin } from "./pinning.ts";
import { createProxiedAgent, proxyPoolKeyFragment } from "./proxy.ts";
import { tlsSniPoolKeyFragment, type ResolvedTlsSniOverride } from "./tls-sni.ts";
import type { MinTlsVersion } from "./tls-version.ts";

/**
 * Outbound keep-alive connection pool (WR-24).
 *
 * High-frequency delivery to the same downstream used to pay a full
 * TCP (+ TLS) handshake per attempt. The pool keeps one `http.Agent` /
 * `https.Agent` per `(scheme, host, port)` — Node's agents already do
 * correct HTTP/1.1 keep-alive bookkeeping — and adds the policy layer a
 * relay needs around them:
 *
 * - per-host connection cap (`maxSocketsPerHost`, `RangeError` on invalid
 *   values — a misconfigured cap fails at startup, never mid-delivery),
 * - idle reaping on an unref'd timer (`idleTimeoutMs`; `0` disables
 *   reaping) so a forgotten pool never pins process exit,
 * - per-endpoint TLS-pin binding: endpoints with a pin whitelist get
 *   their own agent, keyed by a hash of the normalized pins, so a
 *   connection pinned for one whitelist can never serve an endpoint
 *   with a different one. The peer's SPKI fingerprint is still verified
 *   on `secureConnect` for every *new* connection (see
 *   `createDefaultSender`); a reused connection's cached fingerprint is
 *   re-checked against the request's whitelist as a poisoned-socket
 *   guard. Pinned agents disable TLS session resumption
 *   (`maxCachedSessions: 0`): on a resumed handshake the server does not
 *   re-send its certificate, so the pin check would see an empty peer
 *   certificate and fail a healthy endpoint — every pinned connection
 *   does a full handshake instead.
 * - per-endpoint TLS-identity binding (WR-60): endpoints with a
 *   `tlsSniOverrides` entry get their own agent, keyed by a hash of the
 *   effective (servername, ALPN) pair, so a connection handshaked with one
 *   SNI can never serve an endpoint configured with a different one.
 *   Endpoints without an entry share the historical `(scheme, host, port)`
 *   keys, exactly as before.
 * - health probing (WR-28): every idle socket is probed *before* the
 *   agent hands it to a delivery — in the same tick, so there is no race
 *   between the check and the assignment. Sockets the kernel already
 *   knows are dead (FIN/RST processed: destroyed, closed, or half-closed)
 *   or that never finished connecting are culled on the spot and never
 *   serve a delivery; on pinned agents the cached SPKI fingerprint is
 *   additionally re-verified against the pin whitelist, so a poisoned
 *   socket is culled instead of failing the delivery loudly. Probe
 *   outcomes are observable via `getStats()` (`probeHits`/`probeMisses`).
 *   The probe is passive — it sends no bytes, because an active ping
 *   would corrupt HTTP/1.1 framing on a shared socket. That means a
 *   death the kernel has not observed yet (a true network black hole,
 *   RST still in flight) is *not* detectable at checkout; kernel TCP
 *   keep-alives (`keepAliveMsecs`) and the relay's retry layer remain the
 *   backstop for that case. Disable with `healthProbe: false`.
 * - observability: `getStats()` exposes per-endpoint created / reused /
 *   reaped / probeHits / probeMisses counters plus live socket counts.
 * - adaptive sizing (WR-134, opt-in via `adaptiveSockets`): each origin's
 *   socket cap moves inside `[minSockets, maxSockets]` from the agent's
 *   queued-request pressure — scale up on queue depth, scale down when
 *   the queue drains, `cooldownMs` between moves; shrinking only reaps
 *   idle sockets. Unset = the fixed `maxSocketsPerHost` cap, exactly as
 *   before. Note: raising the cap takes effect for new socket decisions
 *   immediately; requests already queued inside the agent drain as
 *   sockets free — Node's agent does not re-evaluate queued requests on
 *   a cap change, so a scale-up shortens the queue for what comes next
 *   rather than instantly serving what is already waiting.
 *
 * Zero dependencies (`node:http(s)` + `node:crypto` only).
 */

/** Tuning for {@link OutboundConnectionPool}. All values are validated up front. */
export interface KeepAlivePoolOptions {
  /**
   * Maximum concurrent sockets per `(scheme, host, port)`. Extra requests
   * queue inside the agent (FIFO) instead of opening more connections.
   * Default: 64. Must be a positive integer.
   */
  maxSocketsPerHost?: number;
  /**
   * Maximum idle sockets kept per `(scheme, host, port)`. Default: 256.
   * Must be a non-negative integer.
   */
  maxFreeSockets?: number;
  /**
   * Idle sockets older than this are destroyed by the reaper. Default:
   * 30_000. `0` disables reaping (sockets live until `destroy()`).
   * Must be a finite number >= 0.
   */
  idleTimeoutMs?: number;
  /**
   * TCP keep-alive probe delay handed to the sockets. Default: 1000.
   * Must be a finite number >= 0.
   */
  keepAliveMsecs?: number;
  /**
   * Probe idle sockets for health before they are reused (default:
   * `true`). When enabled, every idle candidate is checked in the same
   * tick the agent assigns it — dead or half-closed sockets are culled
   * and never handed to a delivery, and probe outcomes are counted in
   * `getStats()`. Set to `false` to hand the agent's free list through
   * untouched. Must be a boolean when provided.
   */
  healthProbe?: boolean;
  /**
   * WR-92: DNS lookup override for new connections (e.g. a shared
   * `DnsCache#lookup`). When set, every pooled agent resolves hostnames
   * through it — the pool key stays the logical `(scheme, host, port)`,
   * while connections are built against the resolved IP. Must be a
   * function when provided.
   */
  lookup?: LookupFunction;
  /**
   * WR-134: adaptive per-origin socket-cap sizing. Opt-in: the fixed
   * `maxSocketsPerHost` becomes the *initial* cap (clamped into
   * `[minSockets, maxSockets]`), and a background evaluator moves each
   * origin's cap inside that interval from the agent's queued-request
   * pressure — scale up when the queue depth reaches
   * `scaleUpQueueDepth`, scale down toward `minSockets` when the queue
   * drains, with `cooldownMs` between moves on one origin. Shrinking
   * only reaps idle sockets (in-flight deliveries are never touched).
   * Unset = disabled: byte-identical fixed-cap behavior, exactly as
   * before.
   */
  adaptiveSockets?: AdaptiveSocketsOptions;
}

/**
 * Tuning for WR-134 adaptive per-origin socket-cap sizing. All values
 * are validated up front (`RangeError` on invalid values).
 */
export interface AdaptiveSocketsOptions {
  /**
   * Lower bound of the adaptive cap. Default: 1. Must be a positive
   * integer.
   */
  minSockets?: number;
  /**
   * Upper bound of the adaptive cap. Default: `maxSocketsPerHost`. Must
   * be a positive integer >= `minSockets`.
   */
  maxSockets?: number;
  /**
   * Queued requests (waiting for a socket) at or above this depth trigger
   * a scale-up. Default: 16. Must be a positive integer.
   */
  scaleUpQueueDepth?: number;
  /**
   * Minimum ms between cap moves on one origin (flap guard). Default:
   * 30_000. Must be a finite number >= 0.
   */
  cooldownMs?: number;
}

const DEFAULTS = {
  maxSocketsPerHost: 64,
  maxFreeSockets: 256,
  idleTimeoutMs: 30_000,
  keepAliveMsecs: 1000,
  healthProbe: true,
} as const;

function assertPositiveInt(name: string, value: number): void {
  if (!Number.isInteger(value) || value <= 0) {
    throw new RangeError(
      `OutboundConnectionPool: ${name} must be a positive integer, got ${value}`
    );
  }
}

function assertNonNegativeInt(name: string, value: number): void {
  if (!Number.isInteger(value) || value < 0) {
    throw new RangeError(
      `OutboundConnectionPool: ${name} must be a non-negative integer, got ${value}`
    );
  }
}

function assertNonNegativeFinite(name: string, value: number): void {
  if (!Number.isFinite(value) || value < 0) {
    throw new RangeError(
      `OutboundConnectionPool: ${name} must be a finite number >= 0, got ${value}`
    );
  }
}

export interface ResolvedKeepAlivePoolOptions {
  maxSocketsPerHost: number;
  maxFreeSockets: number;
  idleTimeoutMs: number;
  keepAliveMsecs: number;
  healthProbe: boolean;
  lookup: LookupFunction | undefined;
  /** WR-134: resolved adaptive sizing; undefined when disabled. */
  adaptive: ResolvedAdaptiveSockets | undefined;
}

/** `AdaptiveSocketsOptions` with defaults applied (what the pool reads). */
export interface ResolvedAdaptiveSockets {
  minSockets: number;
  maxSockets: number;
  scaleUpQueueDepth: number;
  cooldownMs: number;
}

/** Validate pool options the way a constructor would; returns the resolved values. */
export function resolveKeepAlivePoolOptions(
  opts: KeepAlivePoolOptions = {}
): ResolvedKeepAlivePoolOptions {
  const maxSocketsPerHost = opts.maxSocketsPerHost ?? DEFAULTS.maxSocketsPerHost;
  const maxFreeSockets = opts.maxFreeSockets ?? DEFAULTS.maxFreeSockets;
  const idleTimeoutMs = opts.idleTimeoutMs ?? DEFAULTS.idleTimeoutMs;
  const keepAliveMsecs = opts.keepAliveMsecs ?? DEFAULTS.keepAliveMsecs;
  const healthProbe = opts.healthProbe ?? DEFAULTS.healthProbe;
  assertPositiveInt("maxSocketsPerHost", maxSocketsPerHost);
  assertNonNegativeInt("maxFreeSockets", maxFreeSockets);
  assertNonNegativeFinite("idleTimeoutMs", idleTimeoutMs);
  assertNonNegativeFinite("keepAliveMsecs", keepAliveMsecs);
  if (typeof healthProbe !== "boolean") {
    throw new RangeError(
      `OutboundConnectionPool: healthProbe must be a boolean, got ${healthProbe}`
    );
  }
  const lookup = opts.lookup ?? undefined;
  if (lookup !== undefined && typeof lookup !== "function") {
    throw new RangeError("OutboundConnectionPool: lookup must be a function");
  }
  const adaptive = resolveAdaptiveSockets(opts.adaptiveSockets, maxSocketsPerHost);
  return { maxSocketsPerHost, maxFreeSockets, idleTimeoutMs, keepAliveMsecs, healthProbe, lookup, adaptive };
}

/** WR-134: validate the opt-in adaptive sizing block; undefined when disabled. */
function resolveAdaptiveSockets(
  opts: AdaptiveSocketsOptions | undefined,
  maxSocketsPerHost: number
): ResolvedAdaptiveSockets | undefined {
  if (opts === undefined) return undefined;
  if (opts === null || typeof opts !== "object") {
    throw new RangeError(
      `OutboundConnectionPool: adaptiveSockets must be an object, got ${opts === null ? "null" : typeof opts}`
    );
  }
  const minSockets = opts.minSockets ?? 1;
  const maxSockets = opts.maxSockets ?? maxSocketsPerHost;
  const scaleUpQueueDepth = opts.scaleUpQueueDepth ?? 16;
  const cooldownMs = opts.cooldownMs ?? 30_000;
  assertPositiveInt("adaptiveSockets.minSockets", minSockets);
  assertPositiveInt("adaptiveSockets.maxSockets", maxSockets);
  if (maxSockets < minSockets) {
    throw new RangeError(
      `OutboundConnectionPool: adaptiveSockets.maxSockets (${maxSockets}) must be >= adaptiveSockets.minSockets (${minSockets})`
    );
  }
  assertPositiveInt("adaptiveSockets.scaleUpQueueDepth", scaleUpQueueDepth);
  assertNonNegativeFinite("adaptiveSockets.cooldownMs", cooldownMs);
  return { minSockets, maxSockets, scaleUpQueueDepth, cooldownMs };
}

/**
 * Passive transport health check for an idle pooled socket: true when the
 * socket may be handed to a delivery. Catches what the kernel has already
 * observed — destroyed/closed sockets, connections that never finished
 * establishing, and sockets half-closed by the peer (FIN seen) — without
 * sending a byte. A death the kernel has not observed yet (RST still in
 * flight, network black hole) is indistinguishable from a live socket
 * here; that case stays with TCP keep-alives and the retry layer.
 */
export function isSocketReusable(socket: Socket): boolean {
  if (socket.destroyed || socket.closed) return false;
  if (socket.pending || socket.connecting) return false;
  if (socket.readableEnded || socket.writableEnded) return false;
  if (!socket.writable || !socket.readable) return false;
  return true;
}

/** Per-endpoint pool state snapshot. */
export interface PoolEndpointStats {
  /**
   * Pool key: `<scheme>//<host>:<port>`, plus `|proxy:<hash>` when routed
   * through an outbound proxy, `|pins:<hash>` when pinned,
   * `|cert:<hash>` when a client certificate is bound, `|sni:<hash>`
   * when a per-endpoint TLS SNI/ALPN override applies (see
   * `src/tls-sni.ts`), `|tlsmin:<version>` when a TLS floor applies (see
   * `src/tls-version.ts`), and `|ocsp` when the agent serves
   * OCSP-checked endpoints (see `src/ocsp.ts`).
   */
  key: string;
  scheme: "http" | "https";
  host: string;
  port: number;
  /** Whether this agent only serves endpoints with one pin whitelist. */
  pinned: boolean;
  /** Whether this agent only serves endpoints with one client identity. */
  clientCert: boolean;
  /** Sockets ever created for this endpoint. */
  created: number;
  /** Requests served by an already-open socket. */
  reused: number;
  /** Idle sockets destroyed by the reaper. */
  reaped: number;
  /** Sockets currently serving a request. */
  activeSockets: number;
  /** Sockets currently idle in the pool. */
  freeSockets: number;
  /** Idle sockets that passed a pre-reuse health probe. */
  probeHits: number;
  /** Idle sockets culled by the health probe (never handed to a delivery). */
  probeMisses: number;
  /**
   * WR-134: the origin's current socket cap — the fixed
   * `maxSocketsPerHost` when adaptive sizing is disabled, otherwise the
   * adaptively moved cap inside `[minSockets, maxSockets]`.
   */
  currentMaxSockets: number;
  /** WR-134: adaptive scale-up moves applied to this origin. */
  scaleUps: number;
  /** WR-134: adaptive scale-down moves applied to this origin. */
  scaleDowns: number;
}

/** Whole-pool snapshot from {@link OutboundConnectionPool.getStats}. */
export interface KeepAlivePoolStats {
  endpoints: PoolEndpointStats[];
  created: number;
  reused: number;
  reaped: number;
  probeHits: number;
  probeMisses: number;
}

interface PoolEntry {
  key: string;
  scheme: "http" | "https";
  host: string;
  port: number;
  pinned: boolean;
  /** True when this agent is bound to one mTLS client identity. */
  clientCert: boolean;
  /** Normalized pin whitelist for pinned entries; undefined otherwise. */
  pinWhitelist: string[] | undefined;
  agent: HttpAgent;
  /** Every socket ever handed out by this agent (for created/reused accounting). */
  seen: WeakSet<Socket>;
  created: number;
  reused: number;
  reaped: number;
  probeHits: number;
  probeMisses: number;
  /** WR-134: this origin's current socket cap (moves inside [min, max] when adaptive). */
  currentMaxSockets: number;
  /** WR-134: ms epoch of the last cap move on this origin (flap guard). */
  lastScaleAtMs: number;
  /** WR-134: scale-up moves applied. */
  scaleUps: number;
  /** WR-134: scale-down moves applied. */
  scaleDowns: number;
}

function countSockets(table: unknown): number {
  let n = 0;
  for (const sockets of Object.values((table ?? {}) as Record<string, Socket[]>)) {
    n += sockets.length;
  }
  return n;
}

/**
 * WR-134: requests currently queued inside a Node agent, waiting for a
 * socket. `agent.requests` is keyed by the agent's origin name; each
 * entry holds the requests that could not be assigned a socket because
 * the origin is at its cap. This is the queue-pressure signal adaptive
 * sizing scales on. (`addRequest` is deliberately absent from
 * @types/node — `requests` is the same kind of runtime-internal API the
 * checkout probe already relies on.)
 */
function countQueuedRequests(agent: HttpAgent): number {
  let n = 0;
  const requests = (agent as unknown as { requests?: Record<string, unknown[]> }).requests;
  if (requests === undefined) return 0;
  for (const queued of Object.values(requests)) n += queued.length;
  return n;
}

export class OutboundConnectionPool {
  private readonly opts: ResolvedKeepAlivePoolOptions;
  private readonly entries = new Map<string, PoolEntry>();
  private readonly byAgent = new WeakMap<HttpAgent, PoolEntry>();
  /** When each free socket went idle; doubles as the "already stamped" set. */
  private readonly idleSince = new WeakMap<Socket, number>();
  /** SPKI fingerprint presented at handshake, per socket (TLS pin cache). */
  private readonly presentedPins = new WeakMap<Socket, string>();
  private readonly reapTimer: ReturnType<typeof setInterval> | undefined;
  /** WR-134: adaptive cap evaluator; undefined when adaptive sizing is disabled. */
  private readonly adaptiveTimer: ReturnType<typeof setInterval> | undefined;

  constructor(opts: KeepAlivePoolOptions = {}) {
    this.opts = resolveKeepAlivePoolOptions(opts);
    if (this.opts.idleTimeoutMs > 0) {
      // Reap at most once per second; the timer is unref'd so an idle pool
      // never pins process exit.
      const everyMs = Math.max(100, Math.min(this.opts.idleTimeoutMs, 1000));
      this.reapTimer = setInterval(() => this.reap(), everyMs);
      this.reapTimer.unref();
    }
    if (this.opts.adaptive !== undefined) {
      // Evaluate at most once per second, and no slower than the
      // configured cooldown — a move can never be due before the
      // evaluator has had a chance to see it. Unref'd like the reaper.
      const everyMs = Math.max(50, Math.min(1000, this.opts.adaptive.cooldownMs));
      this.adaptiveTimer = setInterval(() => this.evaluateAdaptive(), everyMs);
      this.adaptiveTimer.unref();
    }
  }

  /**
   * The agent serving `url`. Agents are created lazily, one per
   * `(scheme, host, port)`; endpoints with a TLS pin whitelist get a
   * dedicated agent keyed by a hash of the normalized pins, so a
   * connection pinned for one whitelist can never serve another. When
   * `proxyUrl` is set the agent's sockets are CONNECT tunnels through
   * that proxy (see `src/proxy.ts`) and the pool key binds the proxy too,
   * so a tunneled connection can never serve an endpoint routed through a
   * different proxy (or no proxy). `clientCertId` (see
   * `clientCertIdentity` in `src/mtls.ts`) binds the agent to one client
   * identity, so a connection authenticated as one identity can never
   * serve an endpoint configured with a different one — a rotated
   * identity gets a fresh agent instead of riding a stale connection.
   * `tlsSni` (see `resolveTlsSniOverride` in `src/tls-sni.ts`) binds the
   * agent to one effective TLS identity (SNI servername + ALPN offer), so
   * a connection handshaked with one SNI can never serve an endpoint
   * configured with a different one. `minTlsVersion` (see
   * `src/tls-version.ts`) binds the agent to one TLS floor, so a
   * connection handshaked under a lower floor can never serve an
   * endpoint configured with a higher one. `ocsp` (see `src/ocsp.ts`)
   * binds the agent to OCSP-checked endpoints: the agent requests a
   * stapled OCSP response on every handshake (`requestOCSP` is an
   * agent-level TLS option) and disables TLS session resumption
   * (`maxCachedSessions: 0`) — on a resumed TLS 1.3 handshake the
   * server re-sends no certificate, so there would be nothing to
   * check, exactly the pinned-agent rationale. Endpoints without an
   * override entry pass `undefined` and keep the exact historical pool
   * keys.
   */
  agentFor(url: URL, pins?: readonly string[], proxyUrl?: string, clientCertId?: string, tlsSni?: ResolvedTlsSniOverride, minTlsVersion?: MinTlsVersion, ocsp?: boolean, caBundle?: string): HttpAgent {
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new Error(`OutboundConnectionPool: unsupported protocol ${url.protocol}`);
    }
    const scheme = url.protocol === "https:" ? "https" : "http";
    const host = url.hostname;
    const port = url.port === "" ? (scheme === "https" ? 443 : 80) : Number(url.port);
    let key = `${scheme}//${host}:${port}`;
    if (proxyUrl !== undefined) key += proxyPoolKeyFragment(proxyUrl);
    const pinned = pins !== undefined && pins.length > 0;
    const pinWhitelist = pinned ? pins.map(normalizePin).sort() : undefined;
    if (pinned) {
      const digest = createHash("sha256")
        .update(pinWhitelist!.join(","))
        .digest("hex")
        .slice(0, 16);
      key += `|pins:${digest}`;
    }
    if (clientCertId !== undefined) key += `|cert:${clientCertId}`;
    if (tlsSni !== undefined) key += tlsSniPoolKeyFragment(tlsSni);
    // WR-74: a floor-configured endpoint gets its own agent, so a
    // connection handshaked at (say) TLS 1.2 can never be handed to an
    // endpoint demanding TLS 1.3 — the floor check on `secureConnect`
    // would reject every delivery over it instead of the handshake
    // failing once at connect time.
    if (minTlsVersion !== undefined) key += `|tlsmin:${minTlsVersion}`;
    // WR-101: an OCSP-checked endpoint gets its own agent, so a
    // connection handshaked without `requestOCSP` (and, worse, a resumed
    // session carrying no certificate at all) can never silently serve
    // an endpoint that must check revocation.
    if (ocsp === true) key += "|ocsp";
    // WR-163: a private-CA endpoint gets its own agent — a connection
    // handshaked against the private bundle must never serve an endpoint
    // that relies on the public PKI (a reused connection skips the
    // handshake, so the chain check would silently not run), or vice
    // versa. The bundle is hashed, never embedded in the key.
    if (caBundle !== undefined) {
      const digest = createHash("sha256").update(caBundle).digest("hex").slice(0, 16);
      key += `|ca:${digest}`;
    }
    let entry = this.entries.get(key);
    if (entry === undefined) {
      // WR-134: the fixed cap is the *initial* cap, clamped into
      // [minSockets, maxSockets] when adaptive sizing is on.
      const adaptive = this.opts.adaptive;
      const initialMax =
        adaptive === undefined
          ? this.opts.maxSocketsPerHost
          : Math.min(adaptive.maxSockets, Math.max(adaptive.minSockets, this.opts.maxSocketsPerHost));
      const agentOpts = {
        keepAlive: true,
        keepAliveMsecs: this.opts.keepAliveMsecs,
        maxSockets: initialMax,
        maxFreeSockets: this.opts.maxFreeSockets,
        // WR-92: when a DNS cache lookup is configured, every new pooled
        // connection resolves through it — the pool key stays the logical
        // (scheme, host, port), the socket is built against the resolved
        // IP.
        ...(this.opts.lookup !== undefined ? { lookup: this.opts.lookup } : {}),
        // 0 disables Node's internal free-socket reaping: the pool reaps
        // on its own unref'd timer instead, so idle sockets can be
        // unref'd without racing the agent's timer.
        freeSocketTimeout: 0,
        // Pinned endpoints must never resume a TLS session: on a resumed
        // (TLS 1.3 PSK) handshake the server does not re-send its
        // certificate, so `getPeerCertificate()` comes back empty and the
        // pin check — which must see the peer's SPKI on *every* new
        // connection — would fail a healthy endpoint closed. Unpinned
        // endpoints keep the agent's session cache (resumption is safe
        // there: nothing reads the peer certificate).
        ...(pinned && scheme === "https" ? { maxCachedSessions: 0 } : {}),
        // WR-101: OCSP-checked endpoints must never resume a TLS session
        // either: a resumed handshake carries no certificate, so the
        // revocation check would have nothing to evaluate — a fail-closed
        // endpoint would reject every resumed delivery, a fail-open one
        // would alert on every resumed delivery. Full handshakes only.
        ...(ocsp === true && scheme === "https" ? { maxCachedSessions: 0 } : {}),
        // WR-101: ask the server to staple its OCSP response (RFC 6960
        // §4) on every handshake this agent opens. The stapled bytes are
        // read per delivery via `socket.getOCSPResponse()`; endpoints
        // that disable stapling (`useStapled: false`) still get their own
        // agent (resumption stays off) and check via the responder.
        ...(ocsp === true && scheme === "https" ? { requestOCSP: true } : {}),
        // WR-163: the private CA bundle rides every handshake this agent
        // opens, so a pooled connection is always handshaked under the
        // trust store its endpoint was resolved with (the pool key binds
        // this; per-request `ca` in the sender covers one-off agents).
        ...(caBundle !== undefined && scheme === "https" ? { ca: caBundle } : {}),
      };
      const agent: HttpAgent =
        proxyUrl !== undefined
          ? createProxiedAgent(scheme, proxyUrl, agentOpts)
          : scheme === "https"
            ? new HttpsAgent(agentOpts)
            : new HttpAgent(agentOpts);
      entry = { key, scheme, host, port, pinned, clientCert: clientCertId !== undefined, pinWhitelist, agent, seen: new WeakSet(), created: 0, reused: 0, reaped: 0, probeHits: 0, probeMisses: 0, currentMaxSockets: initialMax, lastScaleAtMs: 0, scaleUps: 0, scaleDowns: 0 };
      this.entries.set(key, entry);
      this.byAgent.set(agent, entry);
      if (this.opts.healthProbe) this.installCheckoutProbe(entry);
    }
    return entry.agent;
  }

  /**
   * Install the pre-reuse health probe on a pooled agent: `addRequest` is
   * wrapped so every idle candidate for the request's origin is probed in
   * the same tick the agent assigns a socket. Failures are spliced out of
   * the agent's free list and destroyed before the original `addRequest`
   * runs, so a culled socket can never be handed to the delivery — the
   * agent then opens a fresh connection as if the pool were empty. The
   * patch is an own-property of an agent the pool created, so nothing
   * global is affected.
   */
  private installCheckoutProbe(entry: PoolEntry): void {
    const pool = this;
    const agent = entry.agent;
    // `addRequest` is deliberately absent from @types/node (internal API);
    // it exists at runtime on every Agent and is the single funnel through
    // which requests claim pooled sockets.
    type AddRequestArgs = [
      req: ClientRequest,
      options?: ClientRequestArgs,
      port?: string | number,
      localAddress?: string,
    ];
    const agentAny = agent as unknown as {
      addRequest: (...args: AddRequestArgs) => void;
    };
    const originalAddRequest = agentAny.addRequest.bind(agentAny);
    agentAny.addRequest = (...args: AddRequestArgs) => {
      const free = agent.freeSockets[agent.getName(args[1])];
      if (free !== undefined) {
        for (let i = free.length - 1; i >= 0; i--) {
          const socket = free[i];
          if (pool.probeIdleSocket(agent, socket)) {
            entry.probeHits++;
          } else {
            // Cull: remove from the free list first (the agent cleans up
            // the rest on 'close'), then destroy. Never handed out.
            free.splice(i, 1);
            entry.probeMisses++;
            socket.destroy();
          }
        }
      }
      originalAddRequest(...args);
    };
  }

  /**
   * Health-probe an idle socket that is about to be reused: the passive
   * transport check plus, on pinned agents, re-verification of the cached
   * SPKI fingerprint against the pin whitelist (a pooled socket on a
   * pinned agent without a verified pin is fail-closed, never handed
   * out). True = the socket may serve a delivery.
   */
  probeIdleSocket(agent: HttpAgent, socket: Socket): boolean {
    if (!isSocketReusable(socket)) return false;
    const whitelist = this.byAgent.get(agent)?.pinWhitelist;
    if (whitelist !== undefined) {
      const cached = this.presentedPins.get(socket);
      if (cached === undefined || !whitelist.includes(cached)) return false;
    }
    return true;
  }

  /**
   * Account a socket handed to a request: first sighting counts as
   * `created`, later ones as `reused`. Also re-refs the socket — it may
   * have been unref'd while idle.
   */
  noteSocket(agent: HttpAgent, socket: Socket): void {
    const entry = this.byAgent.get(agent);
    if (entry === undefined) return;
    if (entry.seen.has(socket)) {
      entry.reused++;
    } else {
      entry.seen.add(socket);
      entry.created++;
    }
    socket.ref();
  }

  /**
   * Stamp the agent's free sockets idle (and unref them): call once a
   * request settles. Idempotent — already-stamped sockets keep their
   * original timestamp.
   */
  markIdle(agent: HttpAgent): void {
    const now = Date.now();
    for (const sockets of Object.values(agent.freeSockets)) {
      for (const socket of sockets as Socket[]) {
        if (!this.idleSince.has(socket)) this.idleSince.set(socket, now);
        // An idle pooled socket must not pin process exit; it is re-ref'd
        // in noteSocket() the moment it serves a request again.
        socket.unref();
      }
    }
  }

  /** Record the SPKI fingerprint a socket presented at handshake (TLS pin cache). */
  cachePresentedPin(socket: Socket, fingerprint: string): void {
    this.presentedPins.set(socket, fingerprint);
  }

  /** The cached handshake fingerprint, or undefined for a fresh socket. */
  presentedPin(socket: Socket): string | undefined {
    return this.presentedPins.get(socket);
  }

  /**
   * WR-134: adaptive per-origin cap evaluation, on the pool's unref'd
   * timer. For each origin, the agent's queued-request pressure (requests
   * waiting for a socket inside Node's agent) moves the cap inside
   * [minSockets, maxSockets]: scale up when the queue reaches
   * scaleUpQueueDepth, scale down toward minSockets when the queue
   * drains, with cooldownMs between moves on one origin (flap guard).
   * Shrinking only reaps idle sockets — in-flight deliveries are never
   * touched. A no-op when adaptive sizing is disabled.
   */
  private evaluateAdaptive(): void {
    const adaptive = this.opts.adaptive;
    if (adaptive === undefined) return;
    const now = Date.now();
    for (const entry of this.entries.values()) {
      if (now - entry.lastScaleAtMs < adaptive.cooldownMs) continue;
      const queued = countQueuedRequests(entry.agent);
      if (queued >= adaptive.scaleUpQueueDepth && entry.currentMaxSockets < adaptive.maxSockets) {
        // Multiplicative growth, at least +1: bursts open headroom fast
        // without overshooting on a single queued request.
        const next = Math.min(
          adaptive.maxSockets,
          Math.max(entry.currentMaxSockets + 1, entry.currentMaxSockets * 2)
        );
        this.setEntryMaxSockets(entry, next, now);
        entry.scaleUps += 1;
      } else if (queued === 0 && entry.currentMaxSockets > adaptive.minSockets) {
        // Halve toward the floor: idle capacity is released promptly,
        // while the cooldown stops a sawtooth on bursty traffic.
        const next = Math.max(
          adaptive.minSockets,
          Math.min(entry.currentMaxSockets - 1, Math.ceil(entry.currentMaxSockets / 2))
        );
        this.setEntryMaxSockets(entry, next, now);
        entry.scaleDowns += 1;
        this.shrinkIdleSockets(entry);
      }
    }
  }

  /** Apply a new cap to one origin's agent (Node reads `maxSockets` live). */
  private setEntryMaxSockets(entry: PoolEntry, next: number, nowMs: number): void {
    entry.currentMaxSockets = next;
    entry.lastScaleAtMs = nowMs;
    entry.agent.maxSockets = next;
  }

  /**
   * WR-134: destroy idle (free) sockets on `entry` until its total socket
   * count fits the current cap. Active (in-flight) sockets are never
   * touched — shrinking only reaps idle connections. Reaped sockets
   * count in `reaped`, like the idle-timeout reaper's.
   */
  private shrinkIdleSockets(entry: PoolEntry): void {
    for (const sockets of Object.values(entry.agent.freeSockets)) {
      const list = sockets as Socket[];
      for (let i = list.length - 1; i >= 0; i--) {
        if (
          countSockets(entry.agent.sockets) + countSockets(entry.agent.freeSockets) <=
          entry.currentMaxSockets
        ) {
          return;
        }
        const socket = list[i];
        list.splice(i, 1);
        entry.reaped++;
        socket.destroy();
      }
    }
  }

  getStats(): KeepAlivePoolStats {
    const endpoints = [...this.entries.values()].map((e) => ({
      key: e.key,
      scheme: e.scheme,
      host: e.host,
      port: e.port,
      pinned: e.pinned,
      clientCert: e.clientCert,
      created: e.created,
      reused: e.reused,
      reaped: e.reaped,
      activeSockets: countSockets(e.agent.sockets),
      freeSockets: countSockets(e.agent.freeSockets),
      probeHits: e.probeHits,
      probeMisses: e.probeMisses,
      currentMaxSockets: e.currentMaxSockets,
      scaleUps: e.scaleUps,
      scaleDowns: e.scaleDowns,
    }));
    return {
      endpoints,
      created: endpoints.reduce((n, e) => n + e.created, 0),
      reused: endpoints.reduce((n, e) => n + e.reused, 0),
      reaped: endpoints.reduce((n, e) => n + e.reaped, 0),
      probeHits: endpoints.reduce((n, e) => n + e.probeHits, 0),
      probeMisses: endpoints.reduce((n, e) => n + e.probeMisses, 0),
    };
  }

  /** Destroy every pooled socket and stop the reaper. Idempotent. */
  destroy(): void {
    if (this.reapTimer !== undefined) clearInterval(this.reapTimer);
    if (this.adaptiveTimer !== undefined) clearInterval(this.adaptiveTimer);
    for (const entry of this.entries.values()) entry.agent.destroy();
    this.entries.clear();
  }

  private reap(): void {
    const now = Date.now();
    for (const entry of this.entries.values()) {
      for (const sockets of Object.values(entry.agent.freeSockets)) {
        const list = sockets as Socket[];
        for (let i = list.length - 1; i >= 0; i--) {
          const socket = list[i];
          // Background health sweep (WR-28): cull sockets the kernel
          // already knows are dead even when no new delivery is arriving
          // to trigger the checkout probe. Same fail-closed pin rule as
          // probeIdleSocket: a pooled socket on a pinned agent without a
          // verified cached pin is never handed out.
          if (this.opts.healthProbe && !this.probeIdleSocket(entry.agent, socket)) {
            list.splice(i, 1);
            entry.probeMisses++;
            socket.destroy();
            continue;
          }
          const since = this.idleSince.get(socket);
          if (since === undefined) {
            this.idleSince.set(socket, now);
            continue;
          }
          if (now - since >= this.opts.idleTimeoutMs) {
            // Destroying removes the socket from the agent's free list
            // (the agent cleans up on 'close').
            socket.destroy();
            entry.reaped++;
          }
        }
      }
    }
  }
}
