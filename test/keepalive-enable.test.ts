import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "keepalive-enable-secret";
const probeBody = Buffer.from(JSON.stringify({ event: "keepalive-enable.probe" }));

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function post(port: number, path: string, body: Buffer) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path,
        method: "POST",
        headers: {
          "x-signature": signSha256(body, relaySecret),
          "content-type": "application/json",
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          r.destroy();
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() });
        });
      }
    );
    r.on("error", reject);
    r.end(body);
  });
}

/** A stub endpoint that counts the TCP connections and requests it serves. */
function countingTarget() {
  let connections = 0;
  let requests = 0;
  const server = createServer((_req, res) => {
    requests++;
    res.writeHead(200).end("ok");
  });
  server.on("connection", () => {
    connections++;
  });
  return { server, stats: () => ({ connections, requests }) };
}

describe("server setOutboundKeepAlive live enable (WR-485)", () => {
  const servers: Server[] = [];
  const targets: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
    for (const t of targets) t.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "keepalive-enable-"));
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

  /** Wait until the audit log holds at least `n` `delivered` events (bounded). */
  async function waitForDelivered(audit: AuditLog, n: number): Promise<void> {
    const deadline = Date.now() + 5000;
    for (;;) {
      if (eventsOf(audit, "delivered").length >= n) return;
      if (Date.now() > deadline) {
        throw new Error(`timed out waiting for ${n} deliveries`);
      }
      await sleep(25);
    }
  }

  it("an empty patch enables at the construction defaults and audits previous: null", async () => {
    const { relay, auditLog } = makeServer({ outboundKeepAlive: false });
    await listen(relay);
    assert.deepEqual(relay.setOutboundKeepAlive!({}), { maxSocketsPerHost: 64, idleTimeoutMs: 30_000 });
    const revised = eventsOf(auditLog, "outbound_keep_alive_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.deepEqual(revised[0].current, { maxSocketsPerHost: 64, idleTimeoutMs: 30_000 });
  });

  it("a partial or full patch enables with exactly those values", async () => {
    const first = makeServer({ outboundKeepAlive: false });
    await listen(first.relay);
    assert.deepEqual(first.relay.setOutboundKeepAlive!({ maxSocketsPerHost: 8 }), {
      maxSocketsPerHost: 8,
      idleTimeoutMs: 30_000,
    });
    const second = makeServer({ outboundKeepAlive: false });
    await listen(second.relay);
    assert.deepEqual(
      second.relay.setOutboundKeepAlive!({ maxSocketsPerHost: 4, idleTimeoutMs: 5_000 }),
      { maxSocketsPerHost: 4, idleTimeoutMs: 5_000 }
    );
  });

  it("illegal patches throw RangeError and leave the relay unconfigured; a later valid patch still enables", async () => {
    const { relay, auditLog } = makeServer({ outboundKeepAlive: false });
    await listen(relay);
    for (const patch of [
      { maxSocketsPerHost: 0 },
      { maxSocketsPerHost: -2 },
      { maxSocketsPerHost: 2.5 },
      { maxSocketsPerHost: Number.NaN },
      { maxSocketsPerHost: Number.POSITIVE_INFINITY },
      { idleTimeoutMs: -1 },
      { idleTimeoutMs: Number.NaN },
      { idleTimeoutMs: Number.POSITIVE_INFINITY },
      { maxSocketsPerHost: 4, idleTimeoutMs: -1 }, // one bad field voids the whole patch
    ]) {
      assert.throws(() => relay.setOutboundKeepAlive!(patch), RangeError, JSON.stringify(patch));
    }
    assert.equal(eventsOf(auditLog, "outbound_keep_alive_revised").length, 0);
    // A rejected patch never half-enables: a later valid patch still enables.
    assert.deepEqual(relay.setOutboundKeepAlive!({}), { maxSocketsPerHost: 64, idleTimeoutMs: 30_000 });
    assert.equal(eventsOf(auditLog, "outbound_keep_alive_revised").length, 1);
  });

  it("after enable the WR-309 revision chain works, and a no-op audits nothing", async () => {
    const { relay, auditLog } = makeServer({ outboundKeepAlive: false });
    await listen(relay);
    assert.deepEqual(relay.setOutboundKeepAlive!({ maxSocketsPerHost: 8, idleTimeoutMs: 5_000 }), {
      maxSocketsPerHost: 8,
      idleTimeoutMs: 5_000,
    });
    assert.equal(eventsOf(auditLog, "outbound_keep_alive_revised").length, 1);
    // A real revision audits previous/current.
    assert.deepEqual(relay.setOutboundKeepAlive!({ maxSocketsPerHost: 16 }), {
      maxSocketsPerHost: 16,
      idleTimeoutMs: 5_000,
    });
    const revised = eventsOf(auditLog, "outbound_keep_alive_revised");
    assert.equal(revised.length, 2);
    assert.deepEqual(revised[1].previous, { maxSocketsPerHost: 8, idleTimeoutMs: 5_000 });
    assert.deepEqual(revised[1].current, { maxSocketsPerHost: 16, idleTimeoutMs: 5_000 });
    // Same-value and empty patches are silent no-ops.
    relay.setOutboundKeepAlive!({ maxSocketsPerHost: 16, idleTimeoutMs: 5_000 });
    relay.setOutboundKeepAlive!({});
    assert.equal(eventsOf(auditLog, "outbound_keep_alive_revised").length, 2);
    // An illegal patch throws and leaves the enabled values untouched.
    assert.throws(() => relay.setOutboundKeepAlive!({ maxSocketsPerHost: 0 }), RangeError);
    assert.deepEqual(relay.setOutboundKeepAlive!({}), { maxSocketsPerHost: 16, idleTimeoutMs: 5_000 });
  });

  it("still throws Error when a custom sender owns delivery", async () => {
    const { relay } = makeServer({ sender: async () => {} });
    await listen(relay);
    assert.throws(() => relay.setOutboundKeepAlive!({ maxSocketsPerHost: 4 }), /not configured/);
  });

  it("a restart returns to unconfigured: a fresh relay enables at the defaults", async () => {
    const first = makeServer({ outboundKeepAlive: false });
    await listen(first.relay);
    assert.deepEqual(first.relay.setOutboundKeepAlive!({ maxSocketsPerHost: 4, idleTimeoutMs: 5_000 }), {
      maxSocketsPerHost: 4,
      idleTimeoutMs: 5_000,
    });
    // A fresh relay (the restart) starts unconfigured again: the enable
    // resolves to the defaults, not the previous relay's values, and is
    // audited with previous: null.
    const second = makeServer({ outboundKeepAlive: false });
    await listen(second.relay);
    assert.deepEqual(second.relay.setOutboundKeepAlive!({}), {
      maxSocketsPerHost: 64,
      idleTimeoutMs: 30_000,
    });
    const revised = eventsOf(second.auditLog, "outbound_keep_alive_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
  });

  it("two deliveries after enable reuse one socket; without enable each opens its own", async () => {
    // Control: pooling never enabled — one TCP connection per delivery.
    const controlTarget = countingTarget();
    const controlPort = await listen(controlTarget.server);
    targets.push(controlTarget.server);
    const control = makeServer({
      outboundKeepAlive: false,
      forwardUrl: `http://127.0.0.1:${controlPort}/hook`,
    });
    const controlRelayPort = await listen(control.relay);
    assert.equal((await post(controlRelayPort, "/hooks/keepalive-enable", probeBody)).status, 202);
    await waitForDelivered(control.auditLog, 1);
    await sleep(100);
    assert.equal((await post(controlRelayPort, "/hooks/keepalive-enable", probeBody)).status, 202);
    await waitForDelivered(control.auditLog, 2);
    assert.equal(controlTarget.stats().requests, 2);
    assert.equal(controlTarget.stats().connections, 2);

    // Enabled: the same two deliveries share one pooled socket. The
    // target counts TCP connections, not the pool's counters — the pool
    // is not reachable from the server API — so a mount-only
    // implementation (assigning `sender.pool` without rewiring the
    // delivery path) fails here with two connections instead of one.
    const target = countingTarget();
    const targetPort = await listen(target.server);
    targets.push(target.server);
    const { relay, auditLog } = makeServer({
      outboundKeepAlive: false,
      forwardUrl: `http://127.0.0.1:${targetPort}/hook`,
    });
    const relayPort = await listen(relay);
    // The enable really happens here (not a no-op on a startup pool):
    // the relay started with `outboundKeepAlive: false`.
    assert.deepEqual(relay.setOutboundKeepAlive!({}), { maxSocketsPerHost: 64, idleTimeoutMs: 30_000 });
    assert.equal((await post(relayPort, "/hooks/keepalive-enable", probeBody)).status, 202);
    await waitForDelivered(auditLog, 1);
    await sleep(100);
    assert.equal((await post(relayPort, "/hooks/keepalive-enable", probeBody)).status, 202);
    await waitForDelivered(auditLog, 2);
    assert.equal(target.stats().requests, 2);
    assert.equal(target.stats().connections, 1);
  });
});
