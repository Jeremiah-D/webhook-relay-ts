import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Agent, type Server } from "node:http";
import { OutboundConnectionPool } from "../src/keepalive.ts";

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

/** A stub endpoint that holds every request until `release()` is called. */
function blockingServer() {
  let release!: () => void;
  const arm = () => {
    gate = new Promise<void>((r) => (release = r));
  };
  let gate: Promise<void>;
  arm();
  const server: Server = createServer(async (_req, res) => {
    await gate;
    res.writeHead(200).end("ok");
  });
  return { server, release: () => release(), rearm: arm };
}

/** A stub endpoint that answers every request after `holdMs`. */
function delayedServer(holdMs: number) {
  const server: Server = createServer(async (_req, res) => {
    await sleep(holdMs);
    res.writeHead(200).end("ok");
  });
  return { server };
}

function getOk(agent: Agent, url: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(url, { agent }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode ?? 0));
    });
    req.on("error", reject);
    req.end();
  });
}

describe("WR-134 adaptive per-origin socket-cap sizing", () => {
  let server: Server;
  let release: () => void;
  let rearm: () => void;
  let port: number;

  before(async () => {
    ({ server, release, rearm } = blockingServer());
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    port = (server.address() as { port: number }).port;
  });

  after(async () => {
    server.close();
    await new Promise((r) => setImmediate(r));
  });

  it("scales the cap up under queue pressure", async () => {
    const pool = new OutboundConnectionPool({
      maxSocketsPerHost: 1,
      idleTimeoutMs: 0, // disable the idle reaper: only adaptive shrink may reap here
      adaptiveSockets: { minSockets: 1, maxSockets: 4, scaleUpQueueDepth: 2, cooldownMs: 100 },
    });
    try {
      const agent = pool.agentFor(new URL(`http://127.0.0.1:${port}/up`));
      const target = `http://127.0.0.1:${port}/up`;

      // 4 concurrent requests against a 1-socket cap: 1 active, 3 queued.
      const pending = [getOk(agent, target), getOk(agent, target), getOk(agent, target), getOk(agent, target)];
      await sleep(450); // evaluator runs every 100ms, cooldown 100ms
      const grown = pool.getStats().endpoints[0];
      assert.equal(grown.currentMaxSockets, 4);
      assert.ok(grown.scaleUps >= 2, `expected >= 2 scale-ups, got ${grown.scaleUps}`);

      // The raised cap shortens the queue for what comes next; already-queued
      // requests drain as the socket frees (Node behavior, documented).
      release();
      const statuses = await Promise.all(pending);
      assert.deepEqual(statuses, [200, 200, 200, 200]);
    } finally {
      pool.destroy();
      rearm();
    }
  });

  it("scales the cap down when idle and reaps only idle sockets", async () => {
    const { server: s2 } = delayedServer(300);
    await new Promise<void>((r) => s2.listen(0, "127.0.0.1", r));
    const p2 = (s2.address() as { port: number }).port;
    const pool = new OutboundConnectionPool({
      maxSocketsPerHost: 4,
      idleTimeoutMs: 0, // disable the idle reaper: only adaptive shrink may reap here
      // scaleUpQueueDepth huge: this test exercises scale-down only.
      adaptiveSockets: { minSockets: 1, maxSockets: 8, scaleUpQueueDepth: 1000, cooldownMs: 200 },
    });
    try {
      const agent = pool.agentFor(new URL(`http://127.0.0.1:${p2}/down`));
      const target = `http://127.0.0.1:${p2}/down`;
      // 2 concurrent slow requests: active, never queued.
      const pending = [getOk(agent, target), getOk(agent, target)];
      await sleep(250); // first eval: 4 -> 2 while both are in flight
      const mid = pool.getStats().endpoints[0];
      assert.equal(mid.currentMaxSockets, 2);
      assert.equal(mid.activeSockets, 2); // in-flight deliveries are never touched
      assert.equal(mid.reaped, 0); // nothing idle to reap yet
      await sleep(250); // requests done (~300ms), second eval: 2 -> 1, reaps 1 idle
      const shrunk = pool.getStats().endpoints[0];
      assert.equal(shrunk.currentMaxSockets, 1);
      assert.ok(shrunk.scaleDowns >= 2, `expected >= 2 scale-downs, got ${shrunk.scaleDowns}`);
      assert.equal(shrunk.reaped, 1);
      assert.equal(shrunk.freeSockets, 1);
      const statuses = await Promise.all(pending);
      assert.deepEqual(statuses, [200, 200]); // shrink never broke in-flight requests
    } finally {
      pool.destroy();
      s2.close();
    }
  });

  it("is disabled by default: the fixed cap never moves", async () => {
    const { server: s2, release: rel2 } = blockingServer();
    await new Promise<void>((r) => s2.listen(0, "127.0.0.1", r));
    const p2 = (s2.address() as { port: number }).port;
    const pool = new OutboundConnectionPool({ maxSocketsPerHost: 2, idleTimeoutMs: 0 });
    try {
      const agent = pool.agentFor(new URL(`http://127.0.0.1:${p2}/fixed`));
      const target = `http://127.0.0.1:${p2}/fixed`;
      const pending = [getOk(agent, target), getOk(agent, target), getOk(agent, target)];
      await sleep(350);
      const stats = pool.getStats().endpoints[0];
      assert.equal(stats.currentMaxSockets, 2);
      assert.equal(stats.scaleUps, 0);
      assert.equal(stats.scaleDowns, 0);
      rel2();
      await Promise.all(pending);
    } finally {
      pool.destroy();
      s2.close();
    }
  });

  it("clamps the initial cap into [minSockets, maxSockets]", () => {
    const pool = new OutboundConnectionPool({
      maxSocketsPerHost: 100,
      adaptiveSockets: { minSockets: 1, maxSockets: 8 },
    });
    try {
      pool.agentFor(new URL("http://127.0.0.1:1/clamp"));
      const stats = pool.getStats().endpoints[0];
      assert.equal(stats.currentMaxSockets, 8);
    } finally {
      pool.destroy();
    }
  });

  it("each origin scales independently", async () => {
    const a = blockingServer();
    const b = blockingServer();
    await new Promise<void>((r) => a.server.listen(0, "127.0.0.1", r));
    await new Promise<void>((r) => b.server.listen(0, "127.0.0.1", r));
    const pa = (a.server.address() as { port: number }).port;
    const pb = (b.server.address() as { port: number }).port;
    const pool = new OutboundConnectionPool({
      maxSocketsPerHost: 1,
      idleTimeoutMs: 0,
      adaptiveSockets: { minSockets: 1, maxSockets: 4, scaleUpQueueDepth: 1, cooldownMs: 100 },
    });
    try {
      // Pressure on origin A only.
      const agentA = pool.agentFor(new URL(`http://127.0.0.1:${pa}/a`));
      const pending = [getOk(agentA, `http://127.0.0.1:${pa}/a`), getOk(agentA, `http://127.0.0.1:${pa}/a`)];
      // Origin B sees a single uncontended request.
      const agentB = pool.agentFor(new URL(`http://127.0.0.1:${pb}/b`));
      const single = getOk(agentB, `http://127.0.0.1:${pb}/b`);
      await sleep(350);
      const byPort = new Map(pool.getStats().endpoints.map((e) => [e.port, e]));
      assert.ok((byPort.get(pa)?.currentMaxSockets ?? 0) > 1, "origin A should have scaled up");
      assert.equal(byPort.get(pb)?.currentMaxSockets, 1, "origin B should stay at its initial cap");
      a.release();
      b.release();
      await Promise.all([...pending, single]);
    } finally {
      pool.destroy();
      a.server.close();
      b.server.close();
    }
  });

  it("rejects invalid adaptive options with RangeError", () => {
    const bad: Array<[string, object]> = [
      ["minSockets 0", { minSockets: 0 }],
      ["minSockets negative", { minSockets: -2 }],
      ["maxSockets below minSockets", { minSockets: 4, maxSockets: 2 }],
      ["scaleUpQueueDepth 0", { scaleUpQueueDepth: 0 }],
      ["cooldownMs negative", { cooldownMs: -1 }],
      ["cooldownMs infinite", { cooldownMs: Infinity }],
      ["non-object", "8" as unknown as object],
    ];
    for (const [name, adaptiveSockets] of bad) {
      assert.throws(
        () => new OutboundConnectionPool({ adaptiveSockets: adaptiveSockets as never }),
        RangeError,
        name
      );
    }
    // Sane values are accepted.
    assert.doesNotThrow(
      () =>
        new OutboundConnectionPool({
          adaptiveSockets: { minSockets: 2, maxSockets: 8, scaleUpQueueDepth: 4, cooldownMs: 5000 },
        }).destroy()
    );
  });

  it("exposes currentMaxSockets/scaleUps/scaleDowns in getStats", () => {
    const pool = new OutboundConnectionPool({
      adaptiveSockets: { minSockets: 1, maxSockets: 4 },
    });
    try {
      pool.agentFor(new URL("http://127.0.0.1:1/stats"));
      const e = pool.getStats().endpoints[0];
      assert.equal(e.currentMaxSockets, 4); // maxSocketsPerHost default 64 clamped to max 4
      assert.equal(e.scaleUps, 0);
      assert.equal(e.scaleDowns, 0);
    } finally {
      pool.destroy();
    }
  });
});
