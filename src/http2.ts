import {
  connect as h2connect,
  type ClientHttp2Session,
  type ClientHttp2Stream,
} from "node:http2";
import type { TLSSocket } from "node:tls";
import type { Socket } from "node:net";
import { normalizePin, spkiFingerprint } from "./pinning.ts";
import { clientCertIdentity, type TlsClientCert } from "./mtls.ts";
import { createHash } from "node:crypto";

/**
 * Outbound HTTP/2 session reuse (WR-42).
 *
 * On top of the WR-24 HTTP/1.1 keep-alive pool: per `(scheme, host, port)`
 * H2 sessions, so high-concurrency delivery to one origin multiplexes many
 * streams over a single connection instead of queueing behind
 * `maxSocketsPerHost` TCP/TLS handshakes. Two paths:
 *
 * - `http:` targets → h2c (cleartext prior knowledge) via `node:http2`;
 * - `https:` targets → `http2.connect` with TLS. When SPKI pins are
 *   configured (WR-21) the pin whitelist replaces PKI verification
 *   (`rejectUnauthorized: false`) and the peer's SPKI is verified on the
 *   socket's `secureConnect` *before* the session serves a stream — the
 *   same trust-anchor semantics as the HTTP/1.1 path. Client certificates
 *   (WR-36) ride the handshake via the session's TLS options.
 *
 * H2 is opt-in per host and off by default (`enabled: false`): nothing
 * changes for existing deployments. A failed or refused H2 session never
 * loses a delivery — the sender falls back to the HTTP/1.1 keep-alive
 * pool (counted as `fallback` in `getStats()`), and the origin sits out H2
 * for `fallbackCooldownMs` so a broken endpoint doesn't pay a doomed
 * session setup per delivery.
 *
 * Proxy interplay: H2 is bypassed whenever a proxy applies to the
 * endpoint — proxied traffic rides the HTTP/1.1 CONNECT tunnel (see
 * `src/proxy.ts`). Running H2 over a CONNECT tunnel would need a
 * hand-rolled `createConnection` (CONNECT + TLS + h2 framing composed by
 * hand); the H1.1 tunneled path is the battle-tested one, so the pool
 * deliberately does not combine the two. The sender enforces this: an
 * endpoint with a proxy configured never attempts H2.
 *
 * Zero dependencies (`node:http2` + `node:crypto` only).
 */

/** Thrown when an H2 session cannot serve a delivery; the sender falls back to HTTP/1.1. */
export class Http2UnavailableError extends Error {
  /** The underlying error, when there is one. */
  readonly cause?: Error;
  constructor(message: string, cause?: Error) {
    super(`HTTP/2 unavailable: ${message}`);
    this.name = "Http2UnavailableError";
    this.cause = cause;
  }
}

/** Tuning for {@link Http2SessionPool}. All values are validated up front. */
export interface Http2PoolOptions {
  /**
   * Enable HTTP/2 session reuse. Default: `false` — H2 is opt-in, off by
   * default, so existing deployments keep their exact current behavior.
   * Must be a boolean when provided.
   */
  enabled?: boolean;
  /**
   * Hosts eligible for H2, as `"host"` (any port) or `"host:port"` entries.
   * Hostnames are matched case-insensitively. Default: `[]` — with no
   * eligible hosts H2 is never attempted, even when `enabled` is true.
   * Entries must be non-empty strings; malformed entries throw `RangeError`
   * at startup.
   */
  hosts?: string[];
  /**
   * Idle sessions older than this are closed by the reaper. Default:
   * 60_000. `0` disables idle closing (sessions live until `destroy()` or
   * the server closes them). Must be a finite number >= 0.
   */
  sessionIdleTimeoutMs?: number;
  /**
   * After an H2 failure for an origin, skip H2 for that origin this long
   * and serve from the HTTP/1.1 pool instead. Default: 30_000. `0`
   * retries H2 on the very next delivery. Must be a finite number >= 0.
   */
  fallbackCooldownMs?: number;
}

const DEFAULTS = {
  enabled: false,
  sessionIdleTimeoutMs: 60_000,
  fallbackCooldownMs: 30_000,
} as const;

export interface ResolvedHttp2PoolOptions {
  enabled: boolean;
  hosts: string[];
  sessionIdleTimeoutMs: number;
  fallbackCooldownMs: number;
}

function assertNonNegativeFinite(name: string, value: number): void {
  if (!Number.isFinite(value) || value < 0) {
    throw new RangeError(
      `Http2SessionPool: ${name} must be a finite number >= 0, got ${value}`
    );
  }
}

/** Validate one `hosts` entry: `"host"` or `"host:port"` (port 1–65535). */
function normalizeHostEntry(entry: unknown): string {
  if (typeof entry !== "string" || entry.trim() === "") {
    throw new RangeError(
      `Http2SessionPool: hosts entries must be non-empty strings ("host" or "host:port"), got ${JSON.stringify(entry)}`
    );
  }
  const text = entry.trim().toLowerCase();
  // Split off an optional :port suffix (but not IPv6 literals in brackets).
  let host = text;
  let port = "";
  if (text.startsWith("[")) {
    const close = text.indexOf("]");
    if (close === -1) {
      throw new RangeError(`Http2SessionPool: malformed hosts entry ${JSON.stringify(entry)}`);
    }
    host = text.slice(0, close + 1);
    const rest = text.slice(close + 1);
    if (rest !== "") {
      if (!/^:\d+$/.test(rest)) {
        throw new RangeError(`Http2SessionPool: malformed hosts entry ${JSON.stringify(entry)}`);
      }
      port = rest.slice(1);
    }
  } else {
    const colon = text.lastIndexOf(":");
    if (colon !== -1) {
      host = text.slice(0, colon);
      port = text.slice(colon + 1);
    }
  }
  if (host === "" || host === "[") {
    throw new RangeError(`Http2SessionPool: malformed hosts entry ${JSON.stringify(entry)}`);
  }
  if (port !== "" && (!/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65535)) {
    throw new RangeError(
      `Http2SessionPool: hosts entry port must be 1-65535, got ${JSON.stringify(entry)}`
    );
  }
  return port === "" ? host : `${host}:${port}`;
}

/** Validate pool options the way a constructor would; returns the resolved values. */
export function resolveHttp2PoolOptions(opts: Http2PoolOptions = {}): ResolvedHttp2PoolOptions {
  const enabled = opts.enabled ?? DEFAULTS.enabled;
  if (typeof enabled !== "boolean") {
    throw new RangeError(`Http2SessionPool: enabled must be a boolean, got ${enabled}`);
  }
  const rawHosts = opts.hosts ?? [];
  if (!Array.isArray(rawHosts)) {
    throw new RangeError(`Http2SessionPool: hosts must be an array, got ${rawHosts}`);
  }
  // Dedupe so "Example.com" and "example.com" don't double-count.
  const hosts = [...new Set(rawHosts.map(normalizeHostEntry))];
  const sessionIdleTimeoutMs = opts.sessionIdleTimeoutMs ?? DEFAULTS.sessionIdleTimeoutMs;
  const fallbackCooldownMs = opts.fallbackCooldownMs ?? DEFAULTS.fallbackCooldownMs;
  assertNonNegativeFinite("sessionIdleTimeoutMs", sessionIdleTimeoutMs);
  assertNonNegativeFinite("fallbackCooldownMs", fallbackCooldownMs);
  return { enabled, hosts, sessionIdleTimeoutMs, fallbackCooldownMs };
}

/** True when `url`'s (host, port) matches one `hosts` entry. */
export function hostEligible(hosts: readonly string[], url: URL): boolean {
  const host = url.hostname.toLowerCase();
  const port = url.port === "" ? (url.protocol === "https:" ? 443 : 80) : Number(url.port);
  return hosts.some((raw) => {
    const entry = raw.trim().toLowerCase();
    if (entry.startsWith("[")) {
      const close = entry.indexOf("]");
      const eHost = entry.slice(0, close + 1);
      const rest = entry.slice(close + 1);
      if (rest === "") return host === eHost;
      return host === eHost && Number(rest.slice(1)) === port;
    }
    const colon = entry.lastIndexOf(":");
    if (colon === -1) return host === entry;
    return host === entry.slice(0, colon) && Number(entry.slice(colon + 1)) === port;
  });
}

/** Per-origin H2 session state snapshot. */
export interface Http2SessionStats {
  /**
   * Pool key: `<scheme>//<host>:<port>`, plus `|pins:<hash>` when pinned
   * and `|cert:<hash>` when a client certificate is bound — the same
   * binding rules as the HTTP/1.1 pool, so a session pinned or
   * authenticated for one endpoint can never serve another's.
   */
  key: string;
  scheme: "http" | "https";
  host: string;
  port: number;
  /** Whether this session only serves endpoints with one pin whitelist. */
  pinned: boolean;
  /** Whether this session only serves endpoints with one client identity. */
  clientCert: boolean;
  /** Streams currently in flight on the session. */
  activeStreams: number;
  /** Whether the session's socket is currently connected. */
  connected: boolean;
}

/** Whole-pool snapshot from {@link Http2SessionPool.getStats}. */
export interface Http2PoolStats {
  sessions: Http2SessionStats[];
  /** H2 sessions ever established. */
  established: number;
  /** Deliveries served on an already-established session. */
  reused: number;
  /** Deliveries that fell back to the HTTP/1.1 pool. */
  fallback: number;
}

interface Http2Entry {
  key: string;
  scheme: "http" | "https";
  host: string;
  port: number;
  pinned: boolean;
  clientCert: boolean;
  pinWhitelist: string[] | undefined;
  /** SPKI fingerprint verified at session establishment (pinned entries). */
  verifiedPin: string | undefined;
  cert: TlsClientCert | undefined;
  session: ClientHttp2Session | undefined;
  connecting: Promise<ClientHttp2Session> | undefined;
  /** Origin sits out H2 until this timestamp (after a failure). */
  cooldownUntil: number;
  lastUsed: number;
}

export class Http2SessionPool {
  private readonly opts: ResolvedHttp2PoolOptions;
  private readonly entries = new Map<string, Http2Entry>();
  /** In-flight stream count per session (for idle unref + the reaper). */
  private readonly activeStreams = new WeakMap<ClientHttp2Session, number>();
  private established = 0;
  private reused = 0;
  private fallback = 0;
  private readonly reapTimer: ReturnType<typeof setInterval> | undefined;

  constructor(opts: Http2PoolOptions = {}) {
    this.opts = resolveHttp2PoolOptions(opts);
    if (this.opts.sessionIdleTimeoutMs > 0) {
      const everyMs = Math.max(100, Math.min(this.opts.sessionIdleTimeoutMs, 1000));
      this.reapTimer = setInterval(() => this.reap(), everyMs);
      this.reapTimer.unref();
    }
  }

  /**
   * Whether `url` may attempt H2: the pool is enabled and the host is
   * eligible. The sender checks this before every delivery; proxied
   * endpoints never reach it (the sender routes those to HTTP/1.1 first).
   */
  eligibleFor(url: URL): boolean {
    if (url.protocol !== "http:" && url.protocol !== "https:") return false;
    return this.opts.enabled && hostEligible(this.opts.hosts, url);
  }

  /**
   * The H2 session serving `url` — established on first use, then shared
   * by every later delivery to the same `(scheme, host, port, pins,
   * cert)`. Concurrent first deliveries share the in-flight connect.
   * Throws {@link Http2UnavailableError} when H2 cannot serve the
   * delivery (not eligible, origin in fallback cooldown, connect failed,
   * or pin verification failed) — the caller falls back to HTTP/1.1.
   */
  async sessionFor(url: URL, pins?: readonly string[], clientCert?: TlsClientCert): Promise<ClientHttp2Session> {
    if (!this.eligibleFor(url)) {
      throw new Http2UnavailableError(`${url.host} is not eligible for HTTP/2`);
    }
    const scheme = url.protocol === "https:" ? "https" : "http";
    const host = url.hostname;
    const port = url.port === "" ? (scheme === "https" ? 443 : 80) : Number(url.port);
    let key = `${scheme}//${host}:${port}`;
    const pinned = pins !== undefined && pins.length > 0;
    const pinWhitelist = pinned ? pins.map(normalizePin).sort() : undefined;
    if (pinned) {
      key += `|pins:${createHash("sha256").update(pinWhitelist!.join(",")).digest("hex").slice(0, 16)}`;
    }
    if (clientCert !== undefined) key += `|cert:${clientCertIdentity(clientCert)}`;
    let entry = this.entries.get(key);
    if (entry === undefined) {
      entry = {
        key, scheme, host, port, pinned,
        clientCert: clientCert !== undefined,
        pinWhitelist, verifiedPin: undefined, cert: clientCert,
        session: undefined, connecting: undefined, cooldownUntil: 0,
        lastUsed: Date.now(),
      };
      this.entries.set(key, entry);
    }
    if (Date.now() < entry.cooldownUntil) {
      throw new Http2UnavailableError(`${key} is in fallback cooldown`);
    }
    const live = entry.session;
    if (live !== undefined && !live.destroyed && !live.closed) {
      // Poisoned-session guard (mirrors the keep-alive pool): a session
      // on a pinned entry whose verified pin no longer matches the
      // whitelist is destroyed, never handed out.
      if (entry.pinWhitelist !== undefined) {
        const verified = entry.verifiedPin;
        if (verified === undefined || !entry.pinWhitelist.includes(verified)) {
          this.dropSession(entry, live, "pin re-verification failed on reuse");
          throw new Http2UnavailableError(`${key}: cached pin failed re-verification`);
        }
      }
      entry.lastUsed = Date.now();
      this.reused++;
      return live;
    }
    if (entry.connecting !== undefined) {
      const shared = await entry.connecting;
      this.reused++;
      return shared;
    }
    entry.connecting = this.establish(entry).then(
      (session) => {
        entry!.connecting = undefined;
        entry!.session = session;
        entry!.lastUsed = Date.now();
        this.established++;
        return session;
      },
      (err) => {
        entry!.connecting = undefined;
        entry!.cooldownUntil = Date.now() + this.opts.fallbackCooldownMs;
        throw err;
      }
    );
    return entry.connecting;
  }

  /**
   * Establish one session: TCP (+ TLS) connect, then — for pinned
   * `https:` origins — verify the peer's SPKI on `secureConnect` before
   * the session serves a stream. Any failure destroys the session and
   * rejects with {@link Http2UnavailableError}.
   */
  private establish(entry: Http2Entry): Promise<ClientHttp2Session> {
    return new Promise<ClientHttp2Session>((resolve, reject) => {
      const authority = `${entry.scheme}://${entry.host}:${entry.port}`;
      const session =
        entry.scheme === "https"
          ? h2connect(authority, {
              ALPNProtocols: ["h2"],
              // Pinned origins use the pin as the trust anchor (same as
              // the HTTP/1.1 path); unpinned origins keep PKI verification.
              rejectUnauthorized: entry.pinWhitelist === undefined,
              ...(entry.cert !== undefined
                ? {
                    cert: entry.cert.cert,
                    key: entry.cert.key,
                    ...(entry.cert.passphrase !== undefined
                      ? { passphrase: entry.cert.passphrase }
                      : {}),
                  }
                : {}),
            })
          : h2connect(authority);
      let ready = false;
      const fail = (err: Error): void => {
        if (ready) return; // handed to the persistent handlers below
        session.destroy();
        reject(
          err instanceof Http2UnavailableError
            ? err
            : new Http2UnavailableError(`${entry.key}: ${err.message}`, err)
        );
      };
      session.once("error", fail);
      session.once("close", () => fail(new Error("session closed before establishment")));
      const onReady = (): void => {
        ready = true;
        session.removeListener("error", fail);
        this.attachSession(entry, session);
        resolve(session);
      };
      if (entry.scheme === "https") {
        const sock = session.socket as TLSSocket;
        const verify = (): void => {
          if (entry.pinWhitelist === undefined) {
            onReady();
            return;
          }
          let presented: string;
          try {
            const raw = (sock.getPeerCertificate() as { raw?: unknown }).raw;
            presented = spkiFingerprint(Buffer.from(raw as Buffer));
          } catch (err) {
            fail(new Error(`could not read peer certificate: ${(err as Error).message}`));
            return;
          }
          if (entry.pinWhitelist.includes(presented)) {
            // Pinning is about server identity, and this session proved
            // it — cache the handshake result for the reuse guard.
            entry.verifiedPin = presented;
            onReady();
          } else {
            // Fail the session, not the delivery: the sender falls back
            // to HTTP/1.1, whose pin path fails loudly with
            // TlsPinMismatchError — one place owns that error.
            fail(new Error(`presented SPKI sha256/${presented} is not in the pin whitelist`));
          }
        };
        const already = sock.getPeerCertificate() as { raw?: unknown };
        if (already && already.raw) verify();
        else sock.once("secureConnect", verify);
      } else {
        session.once("connect", onReady);
      }
    });
  }

  /**
   * Persistent session handlers: evict + cooldown on error, graceful
   * drain on server GOAWAY (in-flight streams finish; new deliveries
   * establish a fresh session — no cooldown, a GOAWAY is a normal
   * server-side rotation, not a failure).
   */
  private attachSession(entry: Http2Entry, session: ClientHttp2Session): void {
    session.on("error", () => this.dropSession(entry, session, "session error"));
    session.on("close", () => {
      if (entry.session === session) entry.session = undefined;
    });
    session.on("goaway", () => {
      if (entry.session === session) {
        entry.session = undefined;
        // Graceful: pending streams drain, then the session closes.
        session.close();
      }
    });
    // A cached session must not pin process exit while idle; streams
    // re-ref it via acquireStream/releaseStream. The socket reference can
    // go away once the session is destroyed — guard every touch.
    (session.socket as Socket | undefined)?.unref();
  }

  /** Evict a broken session and park the origin for `fallbackCooldownMs`. */
  private dropSession(entry: Http2Entry, session: ClientHttp2Session, reason: string): void {
    if (entry.session === session) entry.session = undefined;
    entry.cooldownUntil = Date.now() + this.opts.fallbackCooldownMs;
    try {
      session.destroy(new Http2UnavailableError(`${entry.key}: ${reason}`));
    } catch {
      // destroy() with no listener edge cases — the session is gone either way.
    }
  }

  /**
   * Mark one stream starting on `session`: re-refs the socket so an
   * in-flight delivery is never at the mercy of the idle unref. Pair with
   * {@link Http2SessionPool.releaseStream}.
   */
  acquireStream(session: ClientHttp2Session): void {
    this.activeStreams.set(session, (this.activeStreams.get(session) ?? 0) + 1);
    (session.socket as Socket | undefined)?.ref();
  }

  /** Mark one stream settled; unrefs the socket when the session goes idle. */
  releaseStream(session: ClientHttp2Session): void {
    const n = Math.max(0, (this.activeStreams.get(session) ?? 1) - 1);
    this.activeStreams.set(session, n);
    if (n === 0) (session.socket as Socket | undefined)?.unref();
  }

  /** Record one delivery served via the HTTP/1.1 fallback path. */
  noteFallback(): void {
    this.fallback++;
  }

  getStats(): Http2PoolStats {
    const sessions = [...this.entries.values()]
      .filter((e) => e.session !== undefined)
      .map((e) => ({
        key: e.key,
        scheme: e.scheme,
        host: e.host,
        port: e.port,
        pinned: e.pinned,
        clientCert: e.clientCert,
        activeStreams: this.activeStreams.get(e.session!) ?? 0,
        connected:
          e.session !== undefined && !e.session.destroyed && !e.session.closed,
      }));
    return { sessions, established: this.established, reused: this.reused, fallback: this.fallback };
  }

  /** Close every session and stop the reaper. Idempotent. */
  destroy(): void {
    if (this.reapTimer !== undefined) clearInterval(this.reapTimer);
    for (const entry of this.entries.values()) {
      try {
        entry.session?.close();
      } catch {
        // Already gone — nothing to close.
      }
      entry.session = undefined;
      entry.connecting = undefined;
    }
    this.entries.clear();
  }

  private reap(): void {
    if (this.opts.sessionIdleTimeoutMs === 0) return;
    const now = Date.now();
    for (const entry of this.entries.values()) {
      const session = entry.session;
      if (session === undefined) continue;
      if ((this.activeStreams.get(session) ?? 0) > 0) continue;
      if (now - entry.lastUsed >= this.opts.sessionIdleTimeoutMs) {
        entry.session = undefined;
        try {
          session.close();
        } catch {
          // Already gone — nothing to close.
        }
      }
    }
  }
}

/** A single outbound HTTP/2 stream request, for `deliverViaHttp2`-style callers. */
export interface Http2RequestOptions {
  /** `:method` — always POST for deliveries, but kept explicit. */
  method: string;
  /** `:path` including query string. */
  path: string;
  /** Regular headers (no pseudo-headers). */
  headers: Record<string, string | string[]>;
  /** Request body. */
  body: Buffer;
  /** Cap on captured response body bytes (default 64 KiB). */
  captureMaxBytes?: number;
}

/** One completed HTTP/2 request/response exchange. */
export interface Http2Response {
  statusCode: number;
  headers: Record<string, string | string[] | undefined>;
  /** Response body, cut at `captureMaxBytes`. */
  body: Buffer;
  /** True when the body was cut at the cap. */
  truncated: boolean;
}

const DEFAULT_CAPTURE_MAX_BYTES = 64 * 1024;

/**
 * Run one request/response exchange on an established session: send the
 * headers + body, capture the response (body capped at `captureMaxBytes`).
 * Rejects with {@link Http2UnavailableError} when the stream fails before
 * response headers arrive (safe for the caller to retry over HTTP/1.1);
 * later failures reject with the raw error for the retry layer to decide.
 */
export function runHttp2Stream(
  session: ClientHttp2Session,
  opts: Http2RequestOptions
): Promise<Http2Response> {
  const cap = opts.captureMaxBytes ?? DEFAULT_CAPTURE_MAX_BYTES;
  return new Promise<Http2Response>((resolve, reject) => {
    let settled = false;
    let gotResponse = false;
    let req: ClientHttp2Stream;
    const fail = (err: Error): void => {
      if (settled) return;
      settled = true;
      reject(
        gotResponse
          ? err
          : new Http2UnavailableError(`stream failed before response: ${err.message}`, err)
      );
    };
    try {
      req = session.request({
        ":method": opts.method,
        ":path": opts.path,
        ...opts.headers,
      });
    } catch (err) {
      fail(err as Error);
      return;
    }
    req.on("response", (headers) => {
      gotResponse = true;
      const statusCode = Number(headers[":status"] ?? 0);
      const chunks: Buffer[] = [];
      let captured = 0;
      let truncated = false;
      req.on("data", (chunk: Buffer) => {
        if (captured < cap) {
          const room = cap - captured;
          if (chunk.length > room) {
            chunks.push(chunk.subarray(0, room));
            captured += room;
            truncated = true;
          } else {
            chunks.push(chunk);
            captured += chunk.length;
          }
        } else {
          truncated = true;
        }
      });
      req.on("end", () => {
        if (settled) return;
        settled = true;
        resolve({
          statusCode,
          headers: headers as Record<string, string | string[] | undefined>,
          body: Buffer.concat(chunks),
          truncated,
        });
      });
      req.on("error", fail);
    });
    req.on("error", fail);
    req.on("close", () => fail(new Error("stream closed before completing")));
    req.end(opts.body);
  });
}
