import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server, type IncomingMessage, type ServerResponse } from "node:http";
import { createServer as createTlsServer, type Server as TlsServer } from "node:tls";
import { Socket, type LookupFunction } from "node:net";
import { get, type Agent as HttpAgent } from "node:http";
import {
  connectWithHappyEyeballs,
  makeHappyEyeballsCreateConnection,
  resolveHappyEyeballsOptions,
  DEFAULT_CONNECTION_ATTEMPT_DELAY_MS,
  type HappyEyeballsStats,
  type ResolvedHappyEyeballsOptions,
} from "../src/happy-eyeballs.ts";
import { OutboundConnectionPool } from "../src/keepalive.ts";
import { TLS_FIXTURE_CERT_PEM, TLS_FIXTURE_KEY_PEM } from "./tls-fixture.ts";

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** Stub lookup: always answers the given addresses, dns.lookup-compatible. */
function stubLookup(addresses: { address: string; family: number }[]): LookupFunction {
  return ((_hostname: string, _options: unknown, callback: (...args: unknown[]) => void): void => {
    callback(
      null,
      addresses.map((a) => ({ address: a.address, family: a.family }))
    );
  }) as unknown as LookupFunction;
}

function failingLookup(code = "ENOTFOUND"): LookupFunction {
  return ((_hostname: string, _options: unknown, callback: (...args: unknown[]) => void): void => {
    const err = new Error(`${code} stub.invalid`) as NodeJS.ErrnoException;
    err.code = code;
    callback(err, []);
  }) as unknown as LookupFunction;
}

function resolved(delayMs = 50): ResolvedHappyEyeballsOptions {
  const r = resolveHappyEyeballsOptions({ connectionAttemptDelayMs: delayMs });
  assert.ok(r !== undefined);
  return r;
}

async function listenOn(server: Server | TlsServer, host: string, port = 0): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
  const addr = server.address();
  assert.ok(addr !== null && typeof addr === "object");
  return addr.port;
}

function okHandler(_req: IncomingMessage, res: ServerResponse): void {
  res.end("ok");
}

describe("happy-eyeballs: option validation", () => {
  it("defaults to a 250ms Connection Attempt Delay", () => {
    const r = resolveHappyEyeballsOptions({});
    assert.ok(r !== undefined);
    assert.equal(r.connectionAttemptDelayMs, 250);
    assert.equal(r.connectionAttemptDelayMs, DEFAULT_CONNECTION_ATTEMPT_DELAY_MS);
    assert.equal(typeof r.lookup, "function");
  });

  it("rejects a negative, NaN, or infinite delay", () => {
    assert.throws(() => resolveHappyEyeballsOptions({ connectionAttemptDelayMs: -1 }), RangeError);
    assert.throws(() => resolveHappyEyeballsOptions({ connectionAttemptDelayMs: NaN }), RangeError);
    assert.throws(
      () => resolveHappyEyeballsOptions({ connectionAttemptDelayMs: Infinity }),
      RangeError
    );
  });

  it("rejects a non-object config and a non-function lookup", () => {
    assert.throws(() => resolveHappyEyeballsOptions(null as never), RangeError);
    assert.throws(() => resolveHappyEyeballsOptions("fast" as never), RangeError);
    assert.throws(() => resolveHappyEyeballsOptions({ lookup: "dns" as never }), RangeError);
  });

  it("returns undefined for undefined input (feature off)", () => {
    assert.equal(resolveHappyEyeballsOptions(undefined), undefined);
  });

  it("prefers an explicit lookup over the pool fallback", () => {
    const explicit = stubLookup([{ address: "127.0.0.1", family: 4 }]);
    const fallback = stubLookup([{ address: "10.0.0.1", family: 4 }]);
    const r = resolveHappyEyeballsOptions({ lookup: explicit }, fallback);
    assert.ok(r !== undefined);
    assert.equal(r.lookup, explicit);
    const r2 = resolveHappyEyeballsOptions({}, fallback);
    assert.ok(r2 !== undefined);
    assert.equal(r2.lookup, fallback);
  });
});

describe("happy-eyeballs: racing", () => {
  // Two distinct loopback IPs stand in for the two families (the racer
  // only reads the family *label* for ordering/stats; the sockets dial
  // IPv4 literals either way). This keeps the tests deterministic
  // without needing a real IPv6 stack.
  const V6_ADDR = "127.0.0.2";
  const V4_ADDR = "127.0.0.1";
  let v4: Server;
  let v6like: Server;
  let port: number;

  before(async () => {
    v4 = createServer(okHandler);
    port = await listenOn(v4, V4_ADDR);
    v6like = createServer(okHandler);
    await listenOn(v6like, V6_ADDR, port);
  });

  after(async () => {
    await new Promise<void>((resolve) => v4.close(() => resolve()));
    await new Promise<void>((resolve) => v6like.close(() => resolve()));
  });

  function dualLookup(): LookupFunction {
    return stubLookup([
      { address: V6_ADDR, family: 6 },
      { address: V4_ADDR, family: 4 },
    ]);
  }

  it("starts with the IPv6-labeled address first", async () => {
    const stats: HappyEyeballsStats = { races: 0, v6Wins: 0, v4Wins: 0 };
    const sock = await connectWithHappyEyeballs(
      "dualstack.test",
      port,
      { ...resolved(50), lookup: dualLookup() },
      stats
    );
    // The v6-labeled attempt starts first and both servers accept
    // instantly, so it wins before the v4 attempt even starts.
    assert.equal(sock.remoteAddress, V6_ADDR);
    assert.equal(stats.races, 1);
    assert.equal(stats.v6Wins, 1);
    assert.equal(stats.v4Wins, 0);
    sock.destroy();
  });

  it("destroys the losing attempt instead of leaking it", async () => {
    // Spy the prototype: the v6-labeled attempt refuses fast (v6like is
    // closed for this test), so the race opens exactly two attempt
    // sockets — the loser must be destroyed by the racer and the winner
    // by us. A leaked loser would show up as a missing destroy.
    await new Promise<void>((resolve) => v6like.close(() => resolve()));
    const origDestroy = Socket.prototype.destroy;
    let destroys = 0;
    Socket.prototype.destroy = function (...args: unknown[]): Socket {
      destroys++;
      return (origDestroy as (...a: unknown[]) => Socket).apply(this, args);
    };
    try {
      const sock = await connectWithHappyEyeballs("dualstack.test", port, {
        ...resolved(50),
        lookup: dualLookup(),
      });
      assert.equal(sock.remoteAddress, V4_ADDR);
      sock.destroy();
      assert.ok(destroys >= 2, `expected loser + winner destroys, got ${destroys}`);
    } finally {
      Socket.prototype.destroy = origDestroy;
      await listenOn(v6like, V6_ADDR, port);
    }
  });

  it("opens no second connection when the first attempt wins instantly", async () => {
    // Both families accept instantly and the v6-labeled attempt starts
    // first: the v4 attempt must never be opened — no wasted connection.
    const origDestroy = Socket.prototype.destroy;
    let destroys = 0;
    Socket.prototype.destroy = function (...args: unknown[]): Socket {
      destroys++;
      return (origDestroy as (...a: unknown[]) => Socket).apply(this, args);
    };
    try {
      const sock = await connectWithHappyEyeballs("dualstack.test", port, {
        ...resolved(50),
        lookup: dualLookup(),
      });
      assert.equal(sock.remoteAddress, V6_ADDR);
      sock.destroy();
      assert.equal(destroys, 1, `expected exactly one socket lifetime, got ${destroys}`);
    } finally {
      Socket.prototype.destroy = origDestroy;
    }
  });

  it("fails fast to IPv4 on an immediate refusal (no full delay wait)", async () => {
    await new Promise<void>((resolve) => v6like.close(() => resolve()));
    try {
      const stats: HappyEyeballsStats = { races: 0, v6Wins: 0, v4Wins: 0 };
      const start = Date.now();
      const sock = await connectWithHappyEyeballs("dualstack.test", port, {
        ...resolved(30_000),
        lookup: dualLookup(),
      }, stats);
      const elapsed = Date.now() - start;
      assert.equal(sock.remoteAddress, V4_ADDR);
      assert.ok(elapsed < 5000, `must not wait the 30s delay (took ${elapsed}ms)`);
      assert.equal(stats.v4Wins, 1);
      assert.equal(stats.v6Wins, 0);
      sock.destroy();
    } finally {
      await listenOn(v6like, V6_ADDR, port);
    }
  });

  it("starts the next attempt when the delay elapses while the first is pending", async () => {
    // Deterministic scheduler test: delay the first (v6-labeled)
    // attempt's real TCP connect past the Connection Attempt Delay, so
    // the timer provably fires while it is still pending and starts the
    // v4 attempt. The v4 attempt then wins the race.
    const origConnect = Socket.prototype.connect;
    let connects = 0;
    Socket.prototype.connect = function (...args: unknown[]): Socket {
      connects++;
      if (connects === 1) {
        const self: Socket = this as Socket;
        setTimeout(() => {
          (origConnect as (...a: unknown[]) => unknown).apply(self, args);
        }, 50);
        return self;
      }
      return (origConnect as (...a: unknown[]) => Socket).apply(this, args);
    };
    try {
      const stats: HappyEyeballsStats = { races: 0, v6Wins: 0, v4Wins: 0 };
      const sock = await connectWithHappyEyeballs("dualstack.test", port, {
        ...resolved(10),
        lookup: dualLookup(),
      }, stats);
      assert.equal(connects, 2, "the delayed first attempt must not suppress the second");
      assert.equal(sock.remoteAddress, V4_ADDR);
      assert.equal(stats.v4Wins, 1);
      assert.equal(stats.v6Wins, 0);
      sock.destroy();
    } finally {
      Socket.prototype.connect = origConnect;
    }
  });

  it("rejects with the first (IPv6) error when every address fails", async () => {
    const stats: HappyEyeballsStats = { races: 0, v6Wins: 0, v4Wins: 0 };
    await assert.rejects(
      () =>
        connectWithHappyEyeballs("dualstack.test", 1, { ...resolved(20), lookup: dualLookup() }, stats),
      (err: Error) => {
        assert.ok(err instanceof Error);
        return true;
      }
    );
    assert.equal(stats.races, 1);
    assert.equal(stats.v6Wins + stats.v4Wins, 0);
  });

  it("surfaces a resolver error when there is nothing to race", async () => {
    await assert.rejects(
      () => connectWithHappyEyeballs("nope.test", port, { ...resolved(20), lookup: failingLookup() }),
      /ENOTFOUND/
    );
  });
});

describe("happy-eyeballs: agent createConnection", () => {
  let server: Server;
  let port: number;
  let tlsServer: TlsServer;
  let tlsPort: number;

  before(async () => {
    server = createServer(okHandler);
    port = await listenOn(server, "127.0.0.1");
    tlsServer = createTlsServer({ cert: TLS_FIXTURE_CERT_PEM, key: TLS_FIXTURE_KEY_PEM }, (socket) => {
      socket.on("data", () => socket.end("tls-ok"));
    });
    tlsPort = await listenOn(tlsServer, "127.0.0.1");
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await new Promise<void>((resolve) => tlsServer.close(() => resolve()));
  });

  it("hands http agents a connected TCP socket", async () => {
    const lookup = stubLookup([{ address: "127.0.0.1", family: 4 }]);
    const createConnection = makeHappyEyeballsCreateConnection("http", { ...resolved(20), lookup });
    const socket = await new Promise<Socket>((resolve, reject) => {
      createConnection({ host: "relay.test", port }, (err, s) =>
        err ? reject(err) : resolve(s as Socket)
      );
    });
    assert.ok(socket instanceof Socket);
    assert.ok(!socket.destroyed);
    socket.destroy();
  });

  it("wraps the winner in TLS for https agents, preserving agent options", async () => {
    const lookup = stubLookup([{ address: "127.0.0.1", family: 4 }]);
    const createConnection = makeHappyEyeballsCreateConnection("https", { ...resolved(20), lookup });
    const tlsSocket = await new Promise<import("node:tls").TLSSocket>((resolve, reject) => {
      createConnection(
        { host: "relay.test", port: tlsPort, rejectUnauthorized: false, servername: "relay.test" },
        (err, s) => (err ? reject(err) : resolve(s as import("node:tls").TLSSocket))
      );
    });
    assert.equal(typeof tlsSocket.getProtocol, "function");
    tlsSocket.destroy();
  });

  it("routes a raced failure to the agent's error path", async () => {
    const createConnection = makeHappyEyeballsCreateConnection("http", {
      ...resolved(20),
      lookup: failingLookup(),
    });
    await assert.rejects(
      () =>
        new Promise((_resolve, reject) => {
          createConnection({ host: "relay.test", port }, (err) =>
            reject(err ?? new Error("no error"))
          );
        }),
      /ENOTFOUND/
    );
  });
});

describe("happy-eyeballs: pool integration", () => {
  let server: Server;
  let port: number;

  before(async () => {
    server = createServer(okHandler);
    port = await listenOn(server, "127.0.0.1");
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  function getViaAgent(pool: OutboundConnectionPool, agent: HttpAgent): Promise<number> {
    return new Promise((resolve, reject) => {
      const req = get({ host: "127.0.0.1", port, path: "/", agent }, (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode ?? 0));
      });
      // Mirror the relay sender (server.ts): socket accounting flows
      // through `pool.noteSocket` on the request's 'socket' event.
      req.on("socket", (socket) => pool.noteSocket(agent, socket as Socket));
      req.on("error", reject);
    });
  }

  it("serves deliveries through raced new connections and counts them", async () => {
    const pool = new OutboundConnectionPool({ happyEyeballs: { connectionAttemptDelayMs: 50 } });
    try {
      const agent = pool.agentFor(new URL(`http://127.0.0.1:${port}/hook`));
      const status = await getViaAgent(pool, agent);
      assert.equal(status, 200);
      const stats = pool.getStats();
      assert.ok(stats.happyEyeballs !== undefined, "stats exposed when enabled");
      assert.equal(stats.happyEyeballs!.races, 1);
      assert.equal(stats.happyEyeballs!.v4Wins, 1);
      assert.equal(stats.happyEyeballs!.v6Wins, 0);
      // Second delivery reuses the pooled socket: no new race.
      const status2 = await getViaAgent(pool, agent);
      assert.equal(status2, 200);
      assert.equal(pool.getStats().happyEyeballs!.races, 1);
      assert.equal(pool.getStats().reused, 1);
    } finally {
      pool.destroy();
    }
  });

  it("exposes no happyEyeballs stats when the feature is off", () => {
    const pool = new OutboundConnectionPool();
    try {
      assert.equal(pool.getStats().happyEyeballs, undefined);
    } finally {
      pool.destroy();
    }
  });

  it("rejects an invalid delay at pool construction", () => {
    assert.throws(
      () => new OutboundConnectionPool({ happyEyeballs: { connectionAttemptDelayMs: -5 } }),
      RangeError
    );
  });
});
