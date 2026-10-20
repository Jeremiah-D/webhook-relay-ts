import { lookup as dnsLookup, promises as dnsPromises, type LookupAddress } from "node:dns";
import { Socket, type LookupFunction } from "node:net";
import { connect as tlsConnect } from "node:tls";

/**
 * Outbound Happy Eyeballs connection racing (RFC 8305, WR-164).
 *
 * The keep-alive pool (WR-24) used to let Node open new pooled
 * connections with its built-in sequential connect: the OS resolver's
 * address order decided which address family was tried first, and in a
 * dual-stack environment where IPv6 is routed but unusable, every new
 * connection paid a full TCP handshake timeout before IPv4 was even
 * attempted — dragging deliveries behind a black hole.
 *
 * This module races the addresses instead, per RFC 8305 §3.1:
 *
 * - resolve all addresses (`{ all: true }`), group by family;
 * - start with IPv6, and after the Connection Attempt Delay (default
 *   250ms, configurable) start racing IPv4 while IPv6 is still pending;
 *   remaining addresses keep joining the race on the same delay;
 * - the first connected socket wins; every loser is destroyed, never
 *   handed to a delivery;
 * - a fast failure (ECONNREFUSED) starts the next attempt immediately
 *   instead of waiting out the delay — fail fast, don't wait to race.
 *
 * The race only covers *new* TCP connections. Pooled reuse, TLS pin
 * verification (WR-21, on `secureConnect`), mTLS client identities
 * (WR-36, via the agent's TLS options), and OCSP/CA/SNI bindings all
 * ride above it and are untouched — the pool installs the racer as the
 * agent's `createConnection`, and for `https:` the winning TCP socket
 * is wrapped with the exact TLS options the default agent would have
 * used. Proxied agents (WR-27) keep their CONNECT-tunnel `createConnection`:
 * racing to the proxy itself is out of scope.
 *
 * Opt-in via `KeepAlivePoolOptions.happyEyeballs`; unset keeps the
 * historical sequential behavior byte-for-byte.
 *
 * Zero dependencies (`node:dns` + `node:net` + `node:tls` only).
 */

/** Tuning for {@link connectWithHappyEyeballs}. All values are validated up front. */
export interface HappyEyeballsOptions {
  /**
   * Connection Attempt Delay in ms (RFC 8305 §3.1 — the "preferred"
   * default there is 250ms, adopted here). After this long without the
   * current attempt connecting, the next address joins the race. A fast
   * connection failure starts the next attempt immediately regardless.
   * Default: 250. Must be a finite number >= 0.
   */
  connectionAttemptDelayMs?: number;
  /**
   * Lookup override, `dns.lookup`-compatible (e.g. a shared
   * `DnsCache#lookup`). Defaults to the OS resolver. The pool passes
   * its own `lookup` through here so raced connections honor the DNS
   * cache; an explicit per-feature lookup wins over the pool's.
   */
  lookup?: LookupFunction;
}

/** `HappyEyeballsOptions` with defaults applied (what the racer reads). */
export interface ResolvedHappyEyeballsOptions {
  connectionAttemptDelayMs: number;
  lookup: LookupFunction;
}

/** Observable race outcomes, shared per pool. */
export interface HappyEyeballsStats {
  /** Races started (one per new connection through a raced agent). */
  races: number;
  /** Races won by an IPv6 attempt. */
  v6Wins: number;
  /** Races won by an IPv4 attempt. */
  v4Wins: number;
}

/** RFC 8305 §3.1's preferred Connection Attempt Delay. */
export const DEFAULT_CONNECTION_ATTEMPT_DELAY_MS = 250;

/** The OS resolver, as a `LookupFunction` default. */
export const defaultHappyEyeballsLookup: LookupFunction = dnsLookup;

async function defaultResolveAll(hostname: string): Promise<LookupAddress[]> {
  const records = await dnsPromises.lookup(hostname, { all: true });
  return records.map((r) => ({ address: r.address, family: r.family === 6 ? 6 : 4 }));
}

function resolveLookupAll(lookup: LookupFunction): (hostname: string) => Promise<LookupAddress[]> {
  if (lookup === dnsLookup) return defaultResolveAll;
  return (hostname: string) =>
    new Promise<LookupAddress[]>((resolve, reject) => {
      lookup(hostname, { all: true }, (err, addresses) => {
        if (err !== null && err !== undefined) {
          reject(err);
          return;
        }
        const list = (addresses ?? []) as LookupAddress[];
        resolve(list.map((a) => ({ address: a.address, family: a.family === 6 ? 6 : 4 })));
      });
    });
}

/** Validate feature options the way a constructor would; returns the resolved values. */
export function resolveHappyEyeballsOptions(
  opts: HappyEyeballsOptions | undefined,
  fallbackLookup?: LookupFunction
): ResolvedHappyEyeballsOptions | undefined {
  if (opts === undefined) return undefined;
  if (opts === null || typeof opts !== "object") {
    throw new RangeError(
      `happyEyeballs: options must be an object, got ${opts === null ? "null" : typeof opts}`
    );
  }
  const connectionAttemptDelayMs = opts.connectionAttemptDelayMs ?? DEFAULT_CONNECTION_ATTEMPT_DELAY_MS;
  if (!Number.isFinite(connectionAttemptDelayMs) || connectionAttemptDelayMs < 0) {
    throw new RangeError(
      `happyEyeballs: connectionAttemptDelayMs must be a finite number >= 0, got ${opts.connectionAttemptDelayMs}`
    );
  }
  const lookup = opts.lookup ?? fallbackLookup ?? defaultHappyEyeballsLookup;
  if (typeof lookup !== "function") {
    throw new RangeError("happyEyeballs: lookup must be a function");
  }
  return { connectionAttemptDelayMs, lookup };
}

/**
 * Race TCP connection attempts to `hostname:port` per RFC 8305 §3.1 and
 * resolve with the winning connected `net.Socket`.
 *
 * Addresses are interleaved IPv6-first (`v6[0], v4[0], v6[1], v4[1],
 * ...`); the first attempt starts immediately, each subsequent attempt
 * starts after `connectionAttemptDelayMs` unless an earlier attempt
 * fails fast (which starts the next one immediately). The first socket
 * to emit `'connect'` wins — every other attempt is destroyed before
 * the promise resolves, so losers can never serve a delivery. When no
 * address connects, the promise rejects with the *first* attempt's
 * error (the IPv6-first error is the most representative of what the
 * application intended to try).
 *
 * `stats`, when given, counts the race and the winning family.
 */
export function connectWithHappyEyeballs(
  hostname: string,
  port: number,
  opts: ResolvedHappyEyeballsOptions,
  stats?: HappyEyeballsStats
): Promise<Socket> {
  return new Promise<Socket>((resolve, reject) => {
    let settled = false;
    const attempts: Socket[] = [];
    let timer: ReturnType<typeof setTimeout> | undefined;
    let firstError: unknown;
    // Ordered race list: IPv6 first, then interleaved per family.
    let queue: LookupAddress[] = [];

    const clearTimer = (): void => {
      if (timer !== undefined) {
        clearTimeout(timer);
        timer = undefined;
      }
    };

    const destroyAll = (): void => {
      for (const sock of attempts) {
        if (!sock.destroyed) sock.destroy();
      }
    };

    const destroyLosers = (winner: Socket): void => {
      for (const sock of attempts) {
        if (sock !== winner && !sock.destroyed) sock.destroy();
      }
    };

    const onWin = (sock: Socket, family: number): void => {
      if (settled) return;
      settled = true;
      clearTimer();
      destroyLosers(sock);
      if (stats !== undefined) {
        stats.races += 1;
        if (family === 6) stats.v6Wins += 1;
        else stats.v4Wins += 1;
      }
      resolve(sock);
    };

    const onFail = (err: unknown): void => {
      if (settled) return;
      if (firstError === undefined) firstError = err;
      // Fail fast: a dead address must not burn the whole Connection
      // Attempt Delay before the next family gets its chance.
      startNext();
    };

    const finishFailed = (): void => {
      if (settled) return;
      settled = true;
      clearTimer();
      destroyAll();
      if (stats !== undefined) stats.races += 1;
      reject(firstError instanceof Error ? firstError : new Error(String(firstError)));
    };

    const armTimer = (): void => {
      if (queue.length === 0 || settled) return;
      clearTimer();
      timer = setTimeout(() => {
        timer = undefined;
        if (!settled) startNext();
      }, opts.connectionAttemptDelayMs);
      // The race belongs to an in-flight delivery: keep the delay timer
      // referenced so a hung first attempt cannot strand the race — the
      // timer is cleared the moment the race settles, so it never pins
      // an idle process.
    };

    const startNext = (): void => {
      if (settled) return;
      clearTimer();
      const next = queue.shift();
      if (next === undefined) {
        // No addresses left to try. If no attempt is still pending, the
        // race is lost; otherwise the pending attempts decide.
        if (attempts.every((s) => s.destroyed)) finishFailed();
        return;
      }
      const sock = new Socket();
      attempts.push(sock);
      let connected = false;
      const onConnect = (): void => {
        connected = true;
        onWin(sock, next.family);
      };
      const onError = (err: Error): void => {
        if (!sock.destroyed) sock.destroy();
        onFail(err);
      };
      // A close that arrives without 'connect' and without 'error' (a
      // peer that accepts then immediately FINs, for example) is a
      // failed attempt too — never leave the race hanging on it.
      const onClose = (hadError: boolean): void => {
        if (!hadError && !connected) onFail(new Error("socket closed before connect"));
      };
      sock.once("connect", onConnect);
      sock.once("error", onError);
      sock.once("close", onClose);
      try {
        // An IP literal: no resolver involved, the family is already
        // decided. Node picks the right address family from the literal.
        sock.connect(port, next.address);
      } catch (err) {
        onError(err as Error);
        return;
      }
      armTimer();
    };

    resolveLookupAll(opts.lookup)(hostname).then(
      (addresses) => {
        const v6 = addresses.filter((a) => a.family === 6);
        const v4 = addresses.filter((a) => a.family !== 6);
        const interleaved: LookupAddress[] = [];
        for (let i = 0; i < Math.max(v6.length, v4.length); i++) {
          if (i < v6.length) interleaved.push(v6[i]);
          if (i < v4.length) interleaved.push(v4[i]);
        }
        if (interleaved.length === 0) {
          if (!settled) {
            settled = true;
            clearTimer();
            if (stats !== undefined) stats.races += 1;
            reject(new Error(`happyEyeballs: no addresses for ${hostname}`));
          }
          return;
        }
        queue = interleaved;
        startNext();
      },
      (err) => {
        if (!settled) {
          settled = true;
          if (stats !== undefined) stats.races += 1;
          reject(err);
        }
      }
    );
  });
}

/**
 * Build an `http.Agent`-compatible `createConnection` that races new
 * TCP connections with {@link connectWithHappyEyeballs}.
 *
 * - `http:` agents get the winning TCP socket directly;
 * - `https:` agents wrap the winner with `tls.connect`, spreading the
 *   agent's own options — so pin whitelists, mTLS client certificates,
 *   private CA bundles, TLS floors, OCSP, and SNI overrides behave
 *   exactly as with the default `createConnection`. The TLS handshake
 *   itself is *not* raced (RFC 8305 races the TCP connect); a failed
 *   handshake surfaces on the TLS socket exactly as before.
 *
 * The callback form matches `Agent#createConnection(options,
 * oncreate)`; a raced failure reaches `oncreate` as the error, which
 * the agent turns into the request's `'error'` — the same path a
 * refused sequential connect takes today.
 */
export function makeHappyEyeballsCreateConnection(
  scheme: "http" | "https",
  opts: ResolvedHappyEyeballsOptions,
  stats?: HappyEyeballsStats
): (options: Record<string, unknown>, oncreate: (err: Error | null, socket: unknown) => void) => void {
  return (options, oncreate): void => {
    const hostname = String(options.host ?? options.hostname ?? "");
    const port = Number(options.port ?? (scheme === "https" ? 443 : 80));
    connectWithHappyEyeballs(hostname, port, opts, stats).then(
      (tcpSocket) => {
        if (scheme === "http") {
          oncreate(null, tcpSocket);
          return;
        }
        let tlsSocket: unknown;
        try {
          tlsSocket = tlsConnect({
            ...(options as object),
            socket: tcpSocket,
            servername: (options.servername as string | undefined) ?? hostname,
          });
        } catch (err) {
          tcpSocket.destroy();
          oncreate(err as Error, undefined);
          return;
        }
        oncreate(null, tlsSocket);
      },
      (err) => oncreate(err as Error, undefined)
    );
  };
}
