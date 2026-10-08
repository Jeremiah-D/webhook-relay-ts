import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { createServer, type Server } from "node:http";
import { connect as netConnect, type Socket } from "node:net";
import { OutboundConnectionPool, isSocketReusable } from "../src/keepalive.ts";
import { createDefaultSender } from "../src/server.ts";
import { normalizePin } from "../src/pinning.ts";
import {
  TLS_FIXTURE_CERT_PEM,
  TLS_FIXTURE_KEY_PEM,
  TLS_FIXTURE_SPKI_PIN,
} from "./tls-fixture.ts";

const BODY = Buffer.from(JSON.stringify({ event: "probe.check" }));
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

async function listen(server: Server | HttpsServer): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function echoStub(): Server {
  return createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => res.writeHead(200).end("ok"));
  });
}

const item = (targetUrl: string) => ({ id: "p1", payload: BODY, targetUrl, headers: {} });

/** The one free socket for `url`'s pool entry, or undefined. */
function freeSocketOf(pool: OutboundConnectionPool, url: string): Socket | undefined {
  const agent = pool.agentFor(new URL(url));
  const key = Object.keys(agent.freeSockets)[0];
  return key === undefined ? undefined : agent.freeSockets[key]?.[0];
}

async function waitFor(
  cond: () => boolean,
  timeoutMs: number,
  what: string
): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeoutMs) assert.fail(`timed out waiting for: ${what}`);
    await sleep(10);
  }
}

describe("probe: option validation", () => {
  it("rejects non-boolean healthProbe at construction", () => {
    assert.throws(
      () => new OutboundConnectionPool({ healthProbe: "yes" as unknown as boolean }),
      RangeError
    );
    assert.throws(
      () => createDefaultSender(undefined, { healthProbe: 1 as unknown as boolean }),
      RangeError
    );
    assert.doesNotThrow(() => new OutboundConnectionPool({ healthProbe: false }));
    assert.doesNotThrow(() => new OutboundConnectionPool({ healthProbe: true }));
  });
});

describe("probe: isSocketReusable unit checks", () => {
  let stub: Server;
  let port: number;

  before(async () => {
    stub = echoStub();
    port = await listen(stub);
  });
  after(() => stub.close());

  it("a live socket passes; a destroyed socket fails", async () => {
    const sock = netConnect(port, "127.0.0.1");
    await new Promise<void>((resolve) => sock.once("connect", resolve));
    try {
      assert.equal(isSocketReusable(sock), true);
    } finally {
      sock.destroy();
    }
    await new Promise<void>((resolve) => sock.once("close", resolve));
    assert.equal(isSocketReusable(sock), false);
  });

  it("a peer half-closed socket (FIN seen) fails", async () => {
    const killer = createServer();
    const serverSockets = new Set<Socket>();
    killer.on("connection", (s: Socket) => {
      serverSockets.add(s);
      s.on("close", () => serverSockets.delete(s));
    });
    const killerPort = await listen(killer);
    try {
      const sock = netConnect(killerPort, "127.0.0.1");
      await new Promise<void>((resolve) => sock.once("connect", resolve));
      assert.equal(isSocketReusable(sock), true);
      for (const s of serverSockets) s.end(); // graceful FIN, like an idle timeout
      await new Promise<void>((resolve) => sock.once("end", resolve));
      assert.equal(sock.readableEnded, true);
      assert.equal(isSocketReusable(sock), false);
      sock.destroy();
    } finally {
      killer.close();
    }
  });
});

describe("probe: pinned-entry SPKI re-verification", () => {
  it("a pooled socket without a verified pin is fail-closed on pinned agents", async () => {
    const stub = echoStub();
    const port = await listen(stub);
    const pool = new OutboundConnectionPool();
    try {
      const url = `https://127.0.0.1:${port}/hook`;
      const agent = pool.agentFor(new URL(url), [TLS_FIXTURE_SPKI_PIN]);
      const sock = netConnect(port, "127.0.0.1");
      await new Promise<void>((resolve) => sock.once("connect", resolve));
      try {
        // No verified pin cached yet: never hand out on a pinned agent.
        assert.equal(pool.probeIdleSocket(agent, sock), false);
        pool.cachePresentedPin(sock, normalizePin(TLS_FIXTURE_SPKI_PIN));
        assert.equal(pool.probeIdleSocket(agent, sock), true);
        pool.cachePresentedPin(sock, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        assert.equal(pool.probeIdleSocket(agent, sock), false);
      } finally {
        sock.destroy();
      }
    } finally {
      pool.destroy();
      stub.close();
    }
  });
});

describe("probe: checkout culls dead idle sockets", () => {
  let stub: Server;
  let port: number;
  let serverSockets: Set<Socket>;

  before(async () => {
    stub = echoStub();
    serverSockets = new Set();
    stub.on("connection", (s: Socket) => {
      serverSockets.add(s);
      s.on("close", () => serverSockets.delete(s));
    });
    port = await listen(stub);
  });
  after(() => stub.close());

  const url = (): string => `http://127.0.0.1:${port}/hook`;

  it("a client-side dead socket is culled before reuse, never handed to a delivery", async () => {
    const sender = createDefaultSender();
    const pool = sender.pool!;
    try {
      await sender(item(url()));
      await waitFor(() => freeSocketOf(pool, url()) !== undefined, 2000, "free socket");
      // Deterministic dead state: the kernel knows this socket is gone,
      // but the agent's async cleanup has not run yet in this tick.
      freeSocketOf(pool, url())!.destroy();
      await sender(item(url()));
      const stats = pool.getStats();
      assert.equal(stats.created, 2);
      assert.equal(stats.reused, 0);
      assert.ok(stats.probeMisses >= 1, `probeMisses=${stats.probeMisses}`);
      assert.equal(stats.endpoints[0].freeSockets, 1);
      // The fresh connection is healthy: normal reuse resumes and probes hit.
      await sender(item(url()));
      const after = pool.getStats();
      assert.equal(after.reused, 1);
      assert.ok(after.probeHits >= 1, `probeHits=${after.probeHits}`);
    } finally {
      sender.destroy();
    }
  });

  it("a server FIN-idle-timeout socket is never handed to a delivery", async () => {
    const sender = createDefaultSender();
    const pool = sender.pool!;
    try {
      await sender(item(url()));
      await waitFor(() => freeSocketOf(pool, url()) !== undefined, 2000, "free socket");
      for (const s of serverSockets) s.end(); // graceful close, like nginx keepalive_timeout
      await waitFor(() => {
        const s = freeSocketOf(pool, url());
        // The agent may clean up first; either way the dead socket must
        // not serve the next delivery.
        return s === undefined || !isSocketReusable(s);
      }, 2000, "dead socket observed or cleaned up");
      await sender(item(url()));
      const stats = pool.getStats();
      assert.equal(stats.created, 2);
      assert.equal(stats.reused, 0);
    } finally {
      sender.destroy();
    }
  });

  it("healthProbe: false leaves the free list untouched (no probe accounting)", async () => {
    const sender = createDefaultSender(undefined, { healthProbe: false });
    const pool = sender.pool!;
    try {
      await sender(item(url()));
      await waitFor(() => freeSocketOf(pool, url()) !== undefined, 2000, "free socket");
      await sender(item(url()));
      const stats = pool.getStats();
      assert.equal(stats.probeHits, 0);
      assert.equal(stats.probeMisses, 0);
      assert.equal(stats.reused, 1);
    } finally {
      sender.destroy();
    }
  });
});

describe("probe: background sweep culls dead sockets without traffic", () => {
  it("the reaper probe removes a poisoned-pin socket and counts probeMisses", async () => {
    const stub = echoStub();
    const port = await listen(stub);
    const pool = new OutboundConnectionPool();
    try {
      // Pinned agent; inject a live socket into its free list with a
      // poisoned pin cache entry. The agent itself would never clean this
      // up (the socket is alive), so the sweep is the only thing that can
      // observe and cull it — deterministic, no timing race.
      const agent = pool.agentFor(new URL(`https://127.0.0.1:${port}/`), [
        TLS_FIXTURE_SPKI_PIN,
      ]);
      const key = pool.getStats().endpoints[0].key;
      const sock = netConnect(port, "127.0.0.1");
      await new Promise<void>((resolve) => sock.once("connect", resolve));
      pool.cachePresentedPin(sock, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
      (agent.freeSockets as Record<string, Socket[]>)[key] = [sock];
      assert.equal(pool.probeIdleSocket(agent, sock), false);
      // No deliveries at all: the background sweep must find and cull it.
      await waitFor(() => pool.getStats().probeMisses >= 1, 5000, "sweep probeMisses");
      assert.equal(sock.destroyed, true);
      assert.equal(pool.getStats().endpoints[0].freeSockets, 0);
    } finally {
      pool.destroy();
      stub.close();
    }
  });
});

describe("probe: pinned TLS reuse still passes the probe", () => {
  let https: HttpsServer;
  let port: number;

  before(async () => {
    https = createHttpsServer({ key: TLS_FIXTURE_KEY_PEM, cert: TLS_FIXTURE_CERT_PEM }, (req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => res.writeHead(200).end("ok"));
    });
    port = await listen(https);
  });
  after(() => https.close());

  it("a healthy pinned connection is probed, pin re-verified, and reused", async () => {
    const url = `https://127.0.0.1:${port}/hook`;
    const sender = createDefaultSender({ [url]: [TLS_FIXTURE_SPKI_PIN] });
    try {
      await sender(item(url));
      await sender(item(url));
      const stats = sender.pool!.getStats();
      assert.equal(stats.created, 1);
      assert.equal(stats.reused, 1);
      assert.ok(stats.probeHits >= 1, `probeHits=${stats.probeHits}`);
      assert.equal(stats.probeMisses, 0);
      assert.ok(stats.endpoints[0].pinned);
    } finally {
      sender.destroy();
    }
  });
});
