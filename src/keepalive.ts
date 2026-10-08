import { Agent as HttpAgent } from "node:http";
import { Agent as HttpsAgent } from "node:https";
import type { ClientRequest, ClientRequestArgs } from "node:http";
import type { Socket } from "node:net";
import { createHash } from "node:crypto";
import { normalizePin } from "./pinning.ts";
import { createProxiedAgent, proxyPoolKeyFragment } from "./proxy.ts";

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
 *   guard.
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
  return { maxSocketsPerHost, maxFreeSockets, idleTimeoutMs, keepAliveMsecs, healthProbe };
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
   * through an outbound proxy and `|pins:<hash>` when pinned.
   */
  key: string;
  scheme: "http" | "https";
  host: string;
  port: number;
  /** Whether this agent only serves endpoints with one pin whitelist. */
  pinned: boolean;
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
}

function countSockets(table: unknown): number {
  let n = 0;
  for (const sockets of Object.values((table ?? {}) as Record<string, Socket[]>)) {
    n += sockets.length;
  }
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

  constructor(opts: KeepAlivePoolOptions = {}) {
    this.opts = resolveKeepAlivePoolOptions(opts);
    if (this.opts.idleTimeoutMs > 0) {
      // Reap at most once per second; the timer is unref'd so an idle pool
      // never pins process exit.
      const everyMs = Math.max(100, Math.min(this.opts.idleTimeoutMs, 1000));
      this.reapTimer = setInterval(() => this.reap(), everyMs);
      this.reapTimer.unref();
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
   * different proxy (or no proxy).
   */
  agentFor(url: URL, pins?: readonly string[], proxyUrl?: string): HttpAgent {
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
    let entry = this.entries.get(key);
    if (entry === undefined) {
      const agentOpts = {
        keepAlive: true,
        keepAliveMsecs: this.opts.keepAliveMsecs,
        maxSockets: this.opts.maxSocketsPerHost,
        maxFreeSockets: this.opts.maxFreeSockets,
        // 0 disables Node's internal free-socket reaping: the pool reaps
        // on its own unref'd timer instead, so idle sockets can be
        // unref'd without racing the agent's timer.
        freeSocketTimeout: 0,
      };
      const agent: HttpAgent =
        proxyUrl !== undefined
          ? createProxiedAgent(scheme, proxyUrl, agentOpts)
          : scheme === "https"
            ? new HttpsAgent(agentOpts)
            : new HttpAgent(agentOpts);
      entry = { key, scheme, host, port, pinned, pinWhitelist, agent, seen: new WeakSet(), created: 0, reused: 0, reaped: 0, probeHits: 0, probeMisses: 0 };
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

  getStats(): KeepAlivePoolStats {
    const endpoints = [...this.entries.values()].map((e) => ({
      key: e.key,
      scheme: e.scheme,
      host: e.host,
      port: e.port,
      pinned: e.pinned,
      created: e.created,
      reused: e.reused,
      reaped: e.reaped,
      activeSockets: countSockets(e.agent.sockets),
      freeSockets: countSockets(e.agent.freeSockets),
      probeHits: e.probeHits,
      probeMisses: e.probeMisses,
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
