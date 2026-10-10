import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { createServer, type Server } from "node:http";
import type { Socket } from "node:net";
import { OutboundConnectionPool } from "../src/keepalive.ts";
import { createDefaultSender } from "../src/server.ts";
import { TlsPinMismatchError } from "../src/pinning.ts";
import {
  TLS_FIXTURE_CERT_PEM,
  TLS_FIXTURE_KEY_PEM,
  TLS_FIXTURE_SPKI_PIN,
} from "./tls-fixture.ts";

const BODY = Buffer.from(JSON.stringify({ event: "keepalive.probe" }));
const WRONG_PIN = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

async function listen(server: Server | HttpsServer): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

/** Tracks TCP connections accepted by a stub server. */
function trackConnections(server: Server | HttpsServer): {
  sockets: Set<Socket>;
  total: () => number;
  maxConcurrent: () => number;
} {
  const sockets = new Set<Socket>();
  let total = 0;
  let maxConcurrent = 0;
  server.on("connection", (s: Socket) => {
    total++;
    sockets.add(s);
    maxConcurrent = Math.max(maxConcurrent, sockets.size);
    s.on("close", () => sockets.delete(s));
  });
  return { sockets, total: () => total, maxConcurrent: () => maxConcurrent };
}

function echoStub(onRequest?: () => void): Server {
  return createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      onRequest?.();
      res.writeHead(200).end("ok");
    });
  });
}

const item = (targetUrl: string) => ({ id: "k1", payload: BODY, targetUrl, headers: {} });

describe("keepalive: pool option validation", () => {
  it("rejects invalid values with RangeError at construction", () => {
    assert.throws(() => new OutboundConnectionPool({ maxSocketsPerHost: 0 }), RangeError);
    assert.throws(() => new OutboundConnectionPool({ maxSocketsPerHost: 1.5 }), RangeError);
    assert.throws(() => new OutboundConnectionPool({ maxSocketsPerHost: -2 }), RangeError);
    assert.throws(() => new OutboundConnectionPool({ maxFreeSockets: -1 }), RangeError);
    assert.throws(() => new OutboundConnectionPool({ idleTimeoutMs: -1 }), RangeError);
    assert.throws(() => new OutboundConnectionPool({ idleTimeoutMs: NaN }), RangeError);
    assert.throws(() => new OutboundConnectionPool({ keepAliveMsecs: -5 }), RangeError);
    assert.doesNotThrow(() => new OutboundConnectionPool({ idleTimeoutMs: 0 }));
  });

  it("createDefaultSender validates pool options up front", () => {
    assert.throws(() => createDefaultSender(undefined, { maxSocketsPerHost: 0 }), RangeError);
    assert.throws(() => createDefaultSender(undefined, { idleTimeoutMs: -1 }), RangeError);
  });

  it("options reach the underlying agent", () => {
    const pool = new OutboundConnectionPool({ maxSocketsPerHost: 7, maxFreeSockets: 9 });
    const agent = pool.agentFor(new URL("http://127.0.0.1:1/"));
    assert.equal((agent as unknown as { maxSockets: number }).maxSockets, 7);
    assert.equal((agent as unknown as { maxFreeSockets: number }).maxFreeSockets, 9);
    pool.destroy();
  });
});

describe("keepalive: connection reuse over plain HTTP", () => {
  let stub: Server;
  let tracker: ReturnType<typeof trackConnections>;
  let port: number;

  before(async () => {
    stub = echoStub();
    tracker = trackConnections(stub);
    port = await listen(stub);
  });

  after(() => stub.close());

  it("pooling is enabled by default: sequential deliveries share one connection", async () => {
    const sender = createDefaultSender();
    assert.ok(sender.pool instanceof OutboundConnectionPool);
    const url = `http://127.0.0.1:${port}/hook`;
    for (let i = 0; i < 5; i++) await sender(item(url));
    assert.equal(tracker.total(), 1);
    const stats = sender.pool!.getStats();
    assert.equal(stats.endpoints.length, 1);
    assert.equal(stats.created, 1);
    assert.equal(stats.reused, 4);
    assert.equal(stats.reaped, 0);
    assert.equal(stats.endpoints[0].freeSockets, 1);
    assert.equal(stats.endpoints[0].activeSockets, 0);
    sender.destroy();
  });

  it("keepAlive: false opens a fresh connection per delivery (legacy behavior)", async () => {
    const before = tracker.total();
    const sender = createDefaultSender(undefined, false);
    assert.equal(sender.pool, undefined);
    const url = `http://127.0.0.1:${port}/hook`;
    for (let i = 0; i < 3; i++) await sender(item(url));
    assert.equal(tracker.total(), before + 3);
    // destroy() is a safe no-op when pooling is disabled.
    sender.destroy();
  });
});

describe("keepalive: pool policy", () => {
  it("maxSocketsPerHost caps concurrent connections", async () => {
    const stub = createServer((req, res) => {
      setTimeout(() => res.writeHead(200).end("ok"), 60);
    });
    const tracker = trackConnections(stub);
    const port = await listen(stub);
    const sender = createDefaultSender(undefined, { maxSocketsPerHost: 2 });
    try {
      const url = `http://127.0.0.1:${port}/hook`;
      await Promise.all(Array.from({ length: 6 }, () => sender(item(url))));
      assert.ok(tracker.maxConcurrent() <= 2, `saw ${tracker.maxConcurrent()} concurrent connections`);
      assert.equal(sender.pool!.getStats().created, 2);
    } finally {
      sender.destroy();
      stub.close();
    }
  });

  it("idle connections are reaped after idleTimeoutMs", async () => {
    const stub = echoStub();
    const port = await listen(stub);
    const sender = createDefaultSender(undefined, { idleTimeoutMs: 150 });
    try {
      const url = `http://127.0.0.1:${port}/hook`;
      await sender(item(url));
      assert.equal(sender.pool!.getStats().endpoints[0].freeSockets, 1);
      await sleep(600);
      const stats = sender.pool!.getStats();
      assert.equal(stats.endpoints[0].freeSockets, 0);
      assert.equal(stats.reaped, 1);
    } finally {
      sender.destroy();
      stub.close();
    }
  });

  it("a failed connection is never handed to another delivery", async () => {
    const stub = echoStub();
    let connections = 0;
    stub.on("connection", (s: Socket) => {
      connections++;
      // Kill the first connection before it can serve anything.
      if (connections === 1) s.destroy();
    });
    const port = await listen(stub);
    const sender = createDefaultSender();
    try {
      const url = `http://127.0.0.1:${port}/hook`;
      await assert.rejects(() => sender(item(url)));
      await sender(item(url));
      const stats = sender.pool!.getStats();
      assert.equal(stats.created, 2);
      assert.equal(stats.reused, 0);
    } finally {
      sender.destroy();
      stub.close();
    }
  });

  it("origins get separate pools; destroy() closes idle connections", async () => {
    const stubA = echoStub();
    const stubB = echoStub();
    const trackerA = trackConnections(stubA);
    const portA = await listen(stubA);
    const portB = await listen(stubB);
    const sender = createDefaultSender();
    try {
      await sender(item(`http://127.0.0.1:${portA}/hook`));
      await sender(item(`http://127.0.0.1:${portB}/hook`));
      const stats = sender.pool!.getStats();
      assert.equal(stats.endpoints.length, 2);
      assert.equal(stats.created, 2);
      sender.destroy();
      const after = sender.pool!.getStats();
      assert.equal(after.endpoints.length, 0);
      assert.equal(after.created, 0);
      await sleep(100);
      assert.equal(trackerA.sockets.size, 0);
    } finally {
      stubA.close();
      stubB.close();
    }
  });
});

describe("keepalive: TLS pinning over pooled connections", () => {
  let https: HttpsServer;
  let port: number;
  const received: Buffer[] = [];
  let handshakes = 0;
  let tcpConnections = 0;

  before(async () => {
    https = createHttpsServer({ key: TLS_FIXTURE_KEY_PEM, cert: TLS_FIXTURE_CERT_PEM }, (req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        received.push(Buffer.concat(chunks));
        res.writeHead(200).end("ok");
      });
    });
    https.on("secureConnection", () => handshakes++);
    https.on("connection", () => tcpConnections++);
    port = await listen(https);
  });

  after(() => https.close());

  const url = (path: string): string => `https://127.0.0.1:${port}${path}`;

  it("a pinned endpoint reuses one TLS connection across deliveries", async () => {
    const before = handshakes;
    const sender = createDefaultSender({ [url("/hook")]: [TLS_FIXTURE_SPKI_PIN] });
    try {
      for (let i = 0; i < 3; i++) await sender(item(url("/hook")));
      assert.equal(handshakes - before, 1);
      assert.equal(received.length, 3);
      const stats = sender.pool!.getStats();
      assert.equal(stats.created, 1);
      assert.equal(stats.reused, 2);
      assert.ok(stats.endpoints[0].pinned);
    } finally {
      sender.destroy();
    }
  });

  it("a pin mismatch fails every attempt and never pools the bad connection", async () => {
    const tcpBefore = tcpConnections;
    const receivedBefore = received.length;
    const sender = createDefaultSender({ [url("/hook")]: [WRONG_PIN] });
    try {
      await assert.rejects(() => sender(item(url("/hook"))), TlsPinMismatchError);
      await assert.rejects(() => sender(item(url("/hook"))), /pin mismatch/);
      // The mismatched socket is destroyed with the request instead of
      // returning to the pool: each attempt paid for a fresh TCP+TLS
      // handshake (the rejection names the presented SPKI, so the
      // handshake really ran) and failed again. TCP connections — not
      // `secureConnection` — are counted here: the client destroys the
      // socket synchronously inside `secureConnect`, which races the
      // server's `secureConnection` emission.
      assert.equal(tcpConnections - tcpBefore, 2);
      assert.equal(sender.pool!.getStats().created, 2);
      assert.equal(sender.pool!.getStats().reused, 0);
      assert.equal(received.length, receivedBefore);
    } finally {
      sender.destroy();
    }
  });

  it("pinned and unpinned endpoints on the same origin never share a pool", async () => {
    const sender = createDefaultSender({ [url("/a")]: [TLS_FIXTURE_SPKI_PIN] });
    try {
      await sender(item(url("/a")));
      // No pins for /b: default chain verification still rejects the
      // self-signed fixture — pinning never weakens other endpoints.
      await assert.rejects(() => sender(item(url("/b"))), /certificate|self signed|unable to verify/i);
      const stats = sender.pool!.getStats();
      assert.equal(stats.endpoints.length, 2);
      assert.equal(stats.endpoints.filter((e) => e.pinned).length, 1);
      assert.equal(stats.endpoints.filter((e) => !e.pinned).length, 1);
    } finally {
      sender.destroy();
    }
  });

  it("concurrent pinned handshakes never resume TLS sessions", async () => {
    // Regression: the pooled https.Agent used to resume TLS sessions
    // across burst handshakes; on a resumed (TLS 1.3 PSK) handshake the
    // server does not re-send its certificate, so `getPeerCertificate()`
    // came back empty and the pin check failed healthy endpoints with
    // TlsPinMismatchError. Pinned agents now disable the agent's session
    // cache (`maxCachedSessions: 0`), so every handshake is full.
    const sender = createDefaultSender({ [url("/hook")]: [TLS_FIXTURE_SPKI_PIN] });
    try {
      // One warmup delivery, then a burst that forces fresh handshakes.
      await sender(item(url("/hook")));
      const batch: Promise<unknown>[] = [];
      for (let i = 0; i < 30; i++) {
        batch.push(sender(item(url("/hook"))));
      }
      const results = await Promise.all(batch);
      for (const res of results) {
        assert.ok(res && (res as { statusCode: number }).statusCode === 200);
      }
    } finally {
      sender.destroy();
    }
  });
});
