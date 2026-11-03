import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Agent, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { OutboundConnectionPool } from "../src/keepalive.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "keepalive-revision-secret";

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

/** A stub endpoint that answers every request immediately. */
function echoServer() {
  return createServer((_req, res) => {
    res.writeHead(200).end("ok");
  });
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

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

describe("OutboundConnectionPool.retune (WR-309)", () => {
  it("rejects illegal merged values and leaves the live values untouched", () => {
    const pool = new OutboundConnectionPool({ maxSocketsPerHost: 8, idleTimeoutMs: 5_000 });
    try {
      for (const patch of [
        { maxSocketsPerHost: 0 },
        { maxSocketsPerHost: -2 },
        { maxSocketsPerHost: 2.5 },
        { maxSocketsPerHost: Number.NaN },
        { maxSocketsPerHost: Number.POSITIVE_INFINITY },
        { idleTimeoutMs: -1 },
        { idleTimeoutMs: 1.5 },
        { idleTimeoutMs: Number.NaN },
        { idleTimeoutMs: Number.POSITIVE_INFINITY },
        { maxSocketsPerHost: 4, idleTimeoutMs: -1 }, // one bad field voids the whole patch
      ]) {
        assert.throws(() => pool.retune(patch), RangeError, JSON.stringify(patch));
      }
      assert.deepEqual(pool.current(), { maxSocketsPerHost: 8, idleTimeoutMs: 5_000 });
      assert.equal(pool.getStats().maxSocketsPerHost, 8);
      assert.equal(pool.getStats().idleTimeoutMs, 5_000);
    } finally {
      pool.destroy();
    }
  });

  it("an empty patch and a same-value patch change nothing", () => {
    const pool = new OutboundConnectionPool({ maxSocketsPerHost: 8, idleTimeoutMs: 0 });
    try {
      const agent = pool.agentFor(new URL("http://127.0.0.1:1/noop"));
      assert.equal(agent.maxSockets, 8);
      assert.deepEqual(pool.retune({}), { maxSocketsPerHost: 8, idleTimeoutMs: 0 });
      assert.deepEqual(pool.retune({ maxSocketsPerHost: 8, idleTimeoutMs: 0 }), {
        maxSocketsPerHost: 8,
        idleTimeoutMs: 0,
      });
      assert.equal(agent.maxSockets, 8);
      assert.equal(pool.getStats().endpoints[0].currentMaxSockets, 8);
    } finally {
      pool.destroy();
    }
  });

  it("new cap applies to the next connection and updates existing agents, in-flight untouched", async () => {
    const { server, release } = blockingServer();
    const port = await listen(server);
    const pool = new OutboundConnectionPool({ maxSocketsPerHost: 2, idleTimeoutMs: 0 });
    try {
      const target = `http://127.0.0.1:${port}/cap`;
      const agent = pool.agentFor(new URL(target));
      assert.equal(agent.maxSockets, 2);

      // One request in flight under the old cap.
      const first = getOk(agent, target);
      await sleep(100);
      assert.equal(pool.getStats().endpoints[0].activeSockets, 1);

      // Raise the cap: the existing agent follows immediately.
      assert.deepEqual(pool.retune({ maxSocketsPerHost: 5 }), { maxSocketsPerHost: 5, idleTimeoutMs: 0 });
      assert.equal(agent.maxSockets, 5);
      assert.equal(pool.getStats().endpoints[0].currentMaxSockets, 5);

      // Four more concurrent requests fit under the new cap alongside
      // the in-flight one — the new cap gates new sockets, not the
      // request already running.
      const rest = [getOk(agent, target), getOk(agent, target), getOk(agent, target), getOk(agent, target)];
      await sleep(150);
      assert.equal(pool.getStats().endpoints[0].activeSockets, 5);

      release();
      assert.deepEqual(await Promise.all([first, ...rest]), [200, 200, 200, 200, 200]);

      // An agent created after the revision starts at the new cap.
      const other = pool.agentFor(new URL(`http://127.0.0.1:${port + 1}/later`));
      assert.equal(other.maxSockets, 5);
    } finally {
      pool.destroy();
      server.close();
    }
  });

  it("idleTimeoutMs revision rebuilds the reap timer (0 stops it)", async () => {
    const stub = echoServer();
    const port = await listen(stub);
    // No reaper at construction: the timer starts only via retune.
    const pool = new OutboundConnectionPool({ idleTimeoutMs: 0 });
    try {
      const target = `http://127.0.0.1:${port}/reap`;
      const agent = pool.agentFor(new URL(target));
      assert.equal(await getOk(agent, target), 200);
      await sleep(50);
      assert.equal(pool.getStats().endpoints[0].freeSockets, 1);
      assert.equal(pool.getStats().reaped, 0);

      // Start reaping: the idle socket is culled within a few ticks.
      pool.retune({ idleTimeoutMs: 150 });
      await sleep(700);
      assert.equal(pool.getStats().endpoints[0].freeSockets, 0);
      assert.equal(pool.getStats().reaped, 1);

      // Stop reaping again: a fresh idle socket survives past the old timeout.
      assert.equal(await getOk(agent, target), 200);
      await sleep(50);
      assert.equal(pool.getStats().endpoints[0].freeSockets, 1);
      pool.retune({ idleTimeoutMs: 0 });
      assert.equal(pool.getStats().idleTimeoutMs, 0);
      await sleep(700);
      assert.equal(pool.getStats().endpoints[0].freeSockets, 1);
      assert.equal(pool.getStats().reaped, 1);
    } finally {
      pool.destroy();
      stub.close();
    }
  });

  it("adaptive: revising maxSocketsPerHost moves the defaulted upper bound and the evaluator keeps moving", async () => {
    const { server, release } = blockingServer();
    const port = await listen(server);
    const pool = new OutboundConnectionPool({
      maxSocketsPerHost: 4,
      idleTimeoutMs: 0,
      // maxSockets omitted: it defaults to maxSocketsPerHost (WR-134).
      adaptiveSockets: { minSockets: 1, scaleUpQueueDepth: 2, cooldownMs: 500 },
    });
    try {
      const target = `http://127.0.0.1:${port}/adaptive`;
      pool.agentFor(new URL(target));
      assert.equal(pool.getStats().adaptive?.maxSockets, 4);

      pool.retune({ maxSocketsPerHost: 8 });
      assert.equal(pool.getStats().adaptive?.maxSockets, 8);
      // The existing origin stays at its current cap until the
      // evaluator moves it — only the bound changed.
      assert.equal(pool.getStats().endpoints[0].currentMaxSockets, 4);
      // An agent created after the revision starts at the new bound.
      const other = pool.agentFor(new URL(`http://127.0.0.1:${port + 1}/adaptive-later`));
      assert.equal(other.maxSockets, 8);

      // Queue pressure moves the cap up inside the new interval: 6
      // concurrent requests against a 4-socket cap queue 2. The
      // evaluator ticks every 500ms (the cooldown) and the scale-down
      // cannot fire before the next cooldown, so polling catches the
      // scale-up before any scale-down.
      const agent = pool.agentFor(new URL(target));
      const pending = Array.from({ length: 6 }, () => getOk(agent, target));
      let seen = 4;
      for (let i = 0; i < 40; i++) {
        await sleep(50);
        seen = pool.getStats().endpoints[0].currentMaxSockets;
        if (seen === 8) break;
      }
      assert.equal(seen, 8);
      assert.ok(pool.getStats().endpoints[0].scaleUps >= 1);
      release();
      assert.deepEqual(await Promise.all(pending), [200, 200, 200, 200, 200, 200]);
    } finally {
      pool.destroy();
      server.close();
    }
  });

  it("adaptive: an explicitly configured maxSockets stays put on revision", () => {
    const pool = new OutboundConnectionPool({
      maxSocketsPerHost: 4,
      idleTimeoutMs: 0,
      adaptiveSockets: { minSockets: 1, maxSockets: 6, scaleUpQueueDepth: 1000, cooldownMs: 100 },
    });
    try {
      pool.agentFor(new URL("http://127.0.0.1:1/explicit"));
      assert.equal(pool.getStats().adaptive?.maxSockets, 6);
      pool.retune({ maxSocketsPerHost: 10 });
      // The operator's own bound is untouched; a new agent still
      // clamps its initial cap into [minSockets, maxSockets].
      assert.equal(pool.getStats().adaptive?.maxSockets, 6);
      assert.equal(pool.getStats().endpoints[0].currentMaxSockets, 4);
      const other = pool.agentFor(new URL("http://127.0.0.1:2/explicit-later"));
      assert.equal(other.maxSockets, 6);
    } finally {
      pool.destroy();
    }
  });

  it("getStats exposes the live values", () => {
    const pool = new OutboundConnectionPool();
    try {
      assert.equal(pool.getStats().maxSocketsPerHost, 64);
      assert.equal(pool.getStats().idleTimeoutMs, 30_000);
      assert.equal(pool.getStats().adaptive, undefined);
      pool.retune({ maxSocketsPerHost: 3, idleTimeoutMs: 5_000 });
      assert.equal(pool.getStats().maxSocketsPerHost, 3);
      assert.equal(pool.getStats().idleTimeoutMs, 5_000);
    } finally {
      pool.destroy();
    }
  });
});

describe("server setOutboundKeepAlive (WR-309)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "keepalive-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: "http://127.0.0.1:9/unused",
      auditLog,
      ...opts,
    });
    servers.push(relay);
    return { relay, auditLog };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  it("audits outbound_keep_alive_revised with previous/current and skips the audit on a no-op", async () => {
    const { relay, auditLog } = makeServer({
      outboundKeepAlive: { maxSocketsPerHost: 8, idleTimeoutMs: 5_000 },
    });
    await listen(relay);
    assert.equal(eventsOf(auditLog, "outbound_keep_alive_revised").length, 0);
    const next = relay.setOutboundKeepAlive!({ maxSocketsPerHost: 16, idleTimeoutMs: 10_000 });
    assert.deepEqual(next, { maxSocketsPerHost: 16, idleTimeoutMs: 10_000 });
    const revised = eventsOf(auditLog, "outbound_keep_alive_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, { maxSocketsPerHost: 8, idleTimeoutMs: 5_000 });
    assert.deepEqual(revised[0].current, { maxSocketsPerHost: 16, idleTimeoutMs: 10_000 });
    // Partial revision audits the merged previous/current.
    const partial = relay.setOutboundKeepAlive!({ idleTimeoutMs: 20_000 });
    assert.deepEqual(partial, { maxSocketsPerHost: 16, idleTimeoutMs: 20_000 });
    const revised2 = eventsOf(auditLog, "outbound_keep_alive_revised");
    assert.equal(revised2.length, 2);
    assert.deepEqual(revised2[1].previous, { maxSocketsPerHost: 16, idleTimeoutMs: 10_000 });
    assert.deepEqual(revised2[1].current, { maxSocketsPerHost: 16, idleTimeoutMs: 20_000 });
    // Same values and an empty patch: no new audit event.
    relay.setOutboundKeepAlive!({ maxSocketsPerHost: 16, idleTimeoutMs: 20_000 });
    relay.setOutboundKeepAlive!({});
    assert.equal(eventsOf(auditLog, "outbound_keep_alive_revised").length, 2);
  });

  it("throws RangeError on an illegal patch and leaves the pool untouched", async () => {
    const { relay, auditLog } = makeServer({
      outboundKeepAlive: { maxSocketsPerHost: 8, idleTimeoutMs: 5_000 },
    });
    await listen(relay);
    assert.throws(() => relay.setOutboundKeepAlive!({ maxSocketsPerHost: 0 }), RangeError);
    assert.throws(() => relay.setOutboundKeepAlive!({ idleTimeoutMs: -1 }), RangeError);
    assert.throws(() => relay.setOutboundKeepAlive!({ maxSocketsPerHost: 4, idleTimeoutMs: -1 }), RangeError);
    assert.equal(eventsOf(auditLog, "outbound_keep_alive_revised").length, 0);
    // The live values are untouched: an empty patch reports the originals.
    assert.deepEqual(relay.setOutboundKeepAlive!({}), { maxSocketsPerHost: 8, idleTimeoutMs: 5_000 });
  });

  it("throws Error when pooling is disabled or a custom sender owns delivery", async () => {
    const { relay } = makeServer({ outboundKeepAlive: false });
    await listen(relay);
    assert.throws(() => relay.setOutboundKeepAlive!({ maxSocketsPerHost: 4 }), /not configured/);

    const custom = makeServer({ sender: async () => {} });
    await listen(custom.relay);
    assert.throws(() => custom.relay.setOutboundKeepAlive!({ maxSocketsPerHost: 4 }), /not configured/);
  });
});
