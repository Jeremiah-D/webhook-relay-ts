import { Agent as HttpAgent } from "node:http";
import { Agent as HttpsAgent } from "node:https";
import type { Socket } from "node:net";
import { createHash } from "node:crypto";
import { normalizePin } from "./pinning.ts";

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
 * - observability: `getStats()` exposes per-endpoint created / reused /
 *   reaped counters plus live socket counts.
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
}

const DEFAULTS = {
  maxSocketsPerHost: 64,
  maxFreeSockets: 256,
  idleTimeoutMs: 30_000,
  keepAliveMsecs: 1000,
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
}

/** Validate pool options the way a constructor would; returns the resolved values. */
export function resolveKeepAlivePoolOptions(
  opts: KeepAlivePoolOptions = {}
): ResolvedKeepAlivePoolOptions {
  const maxSocketsPerHost = opts.maxSocketsPerHost ?? DEFAULTS.maxSocketsPerHost;
  const maxFreeSockets = opts.maxFreeSockets ?? DEFAULTS.maxFreeSockets;
  const idleTimeoutMs = opts.idleTimeoutMs ?? DEFAULTS.idleTimeoutMs;
  const keepAliveMsecs = opts.keepAliveMsecs ?? DEFAULTS.keepAliveMsecs;
  assertPositiveInt("maxSocketsPerHost", maxSocketsPerHost);
  assertNonNegativeInt("maxFreeSockets", maxFreeSockets);
  assertNonNegativeFinite("idleTimeoutMs", idleTimeoutMs);
  assertNonNegativeFinite("keepAliveMsecs", keepAliveMsecs);
  return { maxSocketsPerHost, maxFreeSockets, idleTimeoutMs, keepAliveMsecs };
}

/** Per-endpoint pool state snapshot. */
export interface PoolEndpointStats {
  /** Pool key: `<scheme>//<host>:<port>`, plus `|pins:<hash>` when pinned. */
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
}

/** Whole-pool snapshot from {@link OutboundConnectionPool.getStats}. */
export interface KeepAlivePoolStats {
  endpoints: PoolEndpointStats[];
  created: number;
  reused: number;
  reaped: number;
}

interface PoolEntry {
  key: string;
  scheme: "http" | "https";
  host: string;
  port: number;
  pinned: boolean;
  agent: HttpAgent;
  /** Every socket ever handed out by this agent (for created/reused accounting). */
  seen: WeakSet<Socket>;
  created: number;
  reused: number;
  reaped: number;
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
   * connection pinned for one whitelist can never serve another.
   */
  agentFor(url: URL, pins?: readonly string[]): HttpAgent {
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      throw new Error(`OutboundConnectionPool: unsupported protocol ${url.protocol}`);
    }
    const scheme = url.protocol === "https:" ? "https" : "http";
    const host = url.hostname;
    const port = url.port === "" ? (scheme === "https" ? 443 : 80) : Number(url.port);
    let key = `${scheme}//${host}:${port}`;
    const pinned = pins !== undefined && pins.length > 0;
    if (pinned) {
      const digest = createHash("sha256")
        .update(pins.map(normalizePin).sort().join(","))
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
        scheme === "https" ? new HttpsAgent(agentOpts) : new HttpAgent(agentOpts);
      entry = { key, scheme, host, port, pinned, agent, seen: new WeakSet(), created: 0, reused: 0, reaped: 0 };
      this.entries.set(key, entry);
      this.byAgent.set(agent, entry);
    }
    return entry.agent;
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
    }));
    return {
      endpoints,
      created: endpoints.reduce((n, e) => n + e.created, 0),
      reused: endpoints.reduce((n, e) => n + e.reused, 0),
      reaped: endpoints.reduce((n, e) => n + e.reaped, 0),
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
        for (const socket of sockets as Socket[]) {
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
