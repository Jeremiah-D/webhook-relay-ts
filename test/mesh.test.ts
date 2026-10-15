import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RELAY_HOPS_HEADER,
  DEFAULT_MAX_MESH_HOPS,
  assertValidMeshOptions,
  parseRelayHops,
  nextRelayHops,
  MeshMetrics,
} from "../src/mesh.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const BODY = Buffer.from(JSON.stringify({ event: "mesh.probe" }));
const OPERATOR_TOKEN = "mesh-operator-token";

describe("WR-107 mesh header parsing and config", () => {
  it("parses an absent header as 0 hops", () => {
    assert.equal(parseRelayHops(undefined), 0);
  });

  it("parses valid hop counts, taking the first of a repeated header", () => {
    assert.equal(parseRelayHops("0"), 0);
    assert.equal(parseRelayHops("3"), 3);
    assert.equal(parseRelayHops(["2", "9"]), 2);
  });

  it("fail-closes on malformed hop counts", () => {
    for (const bad of ["abc", "1.5", "-1", "", " 3", "3 ", "0x10", "99999999999999999999999"]) {
      assert.throws(() => parseRelayHops(bad), RangeError, JSON.stringify(bad));
    }
  });

  it("validates the mesh option, defaulting maxHops", () => {
    assert.equal(assertValidMeshOptions(undefined), undefined);
    assert.deepEqual(assertValidMeshOptions({}), { maxHops: DEFAULT_MAX_MESH_HOPS });
    assert.deepEqual(assertValidMeshOptions({ maxHops: 3 }), { maxHops: 3 });
    for (const bad of [0, -2, 1.5, Number.NaN]) {
      assert.throws(() => assertValidMeshOptions({ maxHops: bad }), RangeError);
    }
  });

  it("increments the hop count for the outbound stamp", () => {
    assert.equal(nextRelayHops(0), 1);
    assert.equal(nextRelayHops(2), 3);
  });

  it("renders no series when idle (activity-gated)", () => {
    assert.equal(new MeshMetrics().render(), "");
  });

  it("renders forwarded and rejection counters with escaped labels", () => {
    const m = new MeshMetrics();
    m.recordForwarded("http://down/hook");
    m.recordForwarded("http://down/hook");
    m.recordHopLimitRejected('http://we"ird/hook');
    const out = m.render();
    assert.match(out, /relay_mesh_forwarded_total\{endpoint="http:\/\/down\/hook"\} 2/);
    assert.match(out, /relay_mesh_hop_limit_rejections_total\{endpoint="http:\/\/we\\"ird\/hook"\} 1/);
  });
});

describe("WR-107 relay mesh server wiring", () => {
  let stub: Server;
  let stubPort: number;
  let seen: Array<Record<string, unknown>>;
  let stubStatus: number;

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  function post(port: number, path: string, headers: Record<string, string> = {}, body: Buffer = BODY) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest(
        { host: "127.0.0.1", port, path, method: "POST", headers },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () =>
            resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
          );
        }
      );
      r.on("error", reject);
      r.end(body);
    });
  }

  function get(port: number, path: string, headers: Record<string, string> = {}) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest(
        { host: "127.0.0.1", port, path, method: "GET", headers },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () =>
            resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
          );
        }
      );
      r.on("error", reject);
      r.end();
    });
  }

  function readAudit(dir: string): Array<Record<string, unknown>> {
    return readFileSync(join(dir, "audit.jsonl"), "utf8")
      .trim()
      .split("\n")
      .filter((l) => l.length > 0)
      .map((l) => JSON.parse(l) as Record<string, unknown>);
  }

  async function waitFor(fn: () => boolean, ms: number, what: string): Promise<void> {
    const deadline = Date.now() + ms;
    while (!fn() && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok(fn(), what);
  }

  before(async () => {
    seen = [];
    stubStatus = 200;
    stub = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        seen.push({ ...(req.headers as Record<string, unknown>) });
        res.writeHead(stubStatus).end("ok");
      });
    });
    stubPort = await listen(stub);
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  function makeRelay(secret: string, extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "mesh-"));
    const relay = createRelayServer({
      secret,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      operatorToken: OPERATOR_TOKEN,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
      ...extra,
    });
    return { relay, dir };
  }

  async function withRelay(
    secret: string,
    extra: Record<string, unknown>,
    fn: (port: number, dir: string) => Promise<void>
  ) {
    const { relay, dir } = makeRelay(secret, extra);
    const port = await listen(relay);
    try {
      await fn(port, dir);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  }

  function inboundHeaders(secret: string, extra: Record<string, string> = {}): Record<string, string> {
    return {
      "content-type": "application/json",
      "x-signature": signSha256(BODY, secret),
      ...extra,
    };
  }

  async function postAndWaitDelivery(port: number, secret: string, headers: Record<string, string> = {}) {
    seen.length = 0;
    const res = await post(port, "/", inboundHeaders(secret, headers));
    assert.equal(res.status, 202);
    await waitFor(() => seen.length > 0, 5000, "stub received the delivery");
    return seen[0] as Record<string, string>;
  }

  it("mesh disabled: the hops header is stripped and never stamped (zero behavior change)", async () => {
    await withRelay("s-disabled", {}, async (port, dir) => {
      const wire = await postAndWaitDelivery(port, "s-disabled", { [RELAY_HOPS_HEADER]: "5" });
      assert.equal(wire[RELAY_HOPS_HEADER], undefined, "no hops header leaks downstream");
      const accepted = readAudit(dir).find((e) => e.event === "accepted");
      assert.ok(accepted);
      assert.equal("meshHops" in accepted, false, "no meshHops on the audit event");
      const metrics = await get(port, "/metrics", { authorization: `Bearer ${OPERATOR_TOKEN}` });
      assert.equal(metrics.status, 200);
      assert.equal(metrics.text.includes("relay_mesh_"), false, "no mesh series when disabled");
    });
  });

  it("mesh enabled: a direct arrival is stamped x-relay-hops: 1 and audited with meshHops 0", async () => {
    await withRelay("s-basic", { mesh: {} }, async (port, dir) => {
      const wire = await postAndWaitDelivery(port, "s-basic");
      assert.equal(wire[RELAY_HOPS_HEADER], "1");
      const events = readAudit(dir);
      const accepted = events.find((e) => e.event === "accepted");
      const delivered = events.find((e) => e.event === "delivered");
      assert.equal(accepted?.meshHops, 0);
      assert.equal(delivered?.meshHops, 0);
      // traceId still threads end to end (WR-18, untouched by mesh).
      assert.ok(typeof accepted?.traceId === "string" && accepted.traceId.length > 0);
      assert.equal(wire["x-trace-id"], accepted?.traceId);
      const metrics = await get(port, "/metrics", { authorization: `Bearer ${OPERATOR_TOKEN}` });
      assert.match(metrics.text, /relay_mesh_forwarded_total\{endpoint="http:\/\/127\.0\.0\.1:\d+\/hook"\} 1/);
    });
  });

  it("mesh enabled: an inbound hop count is incremented on the wire", async () => {
    await withRelay("s-incr", { mesh: {} }, async (port, dir) => {
      const wire = await postAndWaitDelivery(port, "s-incr", { [RELAY_HOPS_HEADER]: "2" });
      assert.equal(wire[RELAY_HOPS_HEADER], "3");
      const accepted = readAudit(dir).find((e) => e.event === "accepted");
      assert.equal(accepted?.meshHops, 2);
    });
  });

  it("mesh enabled: a malformed hops header is fail-closed 400", async () => {
    await withRelay("s-malformed", { mesh: {} }, async (port, dir) => {
      seen.length = 0;
      const res = await post(port, "/", inboundHeaders("s-malformed", { [RELAY_HOPS_HEADER]: "abc" }));
      assert.equal(res.status, 400);
      const rejected = readAudit(dir).find((e) => e.event === "rejected");
      assert.equal(rejected?.reason, "mesh_hops_invalid");
      assert.equal(seen.length, 0, "never delivered");
    });
  });

  it("mesh enabled: hops at maxHops are rejected 400 and counted", async () => {
    await withRelay("s-maxhops", { mesh: { maxHops: 2 } }, async (port, dir) => {
      // Below the cap: accepted.
      const ok = await post(port, "/", inboundHeaders("s-maxhops", { [RELAY_HOPS_HEADER]: "1" }));
      assert.equal(ok.status, 202);
      // At the cap: rejected, never delivered.
      const res = await post(port, "/", inboundHeaders("s-maxhops", { [RELAY_HOPS_HEADER]: "2" }));
      assert.equal(res.status, 400);
      const rejected = readAudit(dir).find((e) => e.reason === "mesh_hop_limit_exceeded");
      assert.ok(rejected);
      assert.equal(rejected.meshHops, 2);
      assert.equal(rejected.maxHops, 2);
      const metrics = await get(port, "/metrics", { authorization: `Bearer ${OPERATOR_TOKEN}` });
      assert.match(metrics.text, /relay_mesh_hop_limit_rejections_total\{endpoint="[^"]+"\} 1/);
    });
  });

  it("mesh enabled: invalid mesh config fails fast at startup", () => {
    assert.throws(
      () =>
        createRelayServer({
          secret: "s",
          forwardUrl: "http://127.0.0.1:9/hook",
          auditLog: new AuditLog(join(mkdtempSync(join(tmpdir(), "mesh-")), "audit.jsonl")),
          mesh: { maxHops: 0 },
        }),
      RangeError
    );
  });

  it("mesh chain A→B: hops accumulate, traceId threads through, peer signature verifies", async () => {
    const meshSecret = "mesh-shared-relay-secret";
    // Relay B: the downstream mesh peer. Its verifier holds the shared
    // relay secret, so relay A's `x-relay-signature` authenticates the hop.
    const b = makeRelay(meshSecret, { mesh: {} });
    const portB = await listen(b.relay);
    // Relay A: signs outbound with the shared secret (WR-26) and forwards
    // into B's inbound.
    const aDir = mkdtempSync(join(tmpdir(), "mesh-"));
    const relayA = createRelayServer({
      secret: "secret-a",
      forwardUrl: `http://127.0.0.1:${portB}/`,
      auditLog: new AuditLog(join(aDir, "audit.jsonl")),
      operatorToken: OPERATOR_TOKEN,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
      mesh: {},
      outboundSigning: { secret: meshSecret },
    });
    const portA = await listen(relayA);
    try {
      seen.length = 0;
      const res = await post(portA, "/", inboundHeaders("secret-a"));
      assert.equal(res.status, 202);
      const acceptedA = JSON.parse(res.text) as { traceId: string };
      await waitFor(() => seen.length > 0, 5000, "stub received the chained delivery");
      const wire = seen[0] as Record<string, string>;
      // Two mesh traversals: A stamped 1, B stamped 2.
      assert.equal(wire[RELAY_HOPS_HEADER], "2");
      // One end-to-end trace across both relays.
      assert.equal(wire["x-trace-id"], acceptedA.traceId);
      const auditB = readAudit(b.dir);
      const acceptedB = auditB.find((e) => e.event === "accepted");
      assert.equal(acceptedB?.meshHops, 1, "B saw one traversed hop");
      assert.equal(acceptedB?.meshPeer, true, "B authenticated the x-relay-signature peer leg");
      assert.equal(acceptedB?.traceId, acceptedA.traceId, "B kept A's trace id");
      const auditA = readAudit(aDir);
      assert.equal(auditA.find((e) => e.event === "accepted")?.meshHops, 0);
    } finally {
      relayA.close();
      await new Promise((r) => relayA.once("close", r));
      b.relay.close();
      await new Promise((r) => b.relay.once("close", r));
    }
  });

  it("mesh chain A→B: a forged peer signature is rejected 401", async () => {
    const meshSecret = "mesh-shared-relay-secret-2";
    const b = makeRelay(meshSecret, { mesh: {} });
    const portB = await listen(b.relay);
    try {
      // No x-signature, and an x-relay-signature under the wrong key.
      const res = await post(
        portB,
        "/",
        {
          "content-type": "application/json",
          [RELAY_HOPS_HEADER]: "0",
          "x-relay-signature": signSha256(BODY, "wrong-key"),
        }
      );
      assert.equal(res.status, 401);
      const rejected = readAudit(b.dir).find((e) => e.event === "rejected");
      assert.equal(rejected?.reason, "invalid_signature");
    } finally {
      b.relay.close();
      await new Promise((r) => b.relay.once("close", r));
    }
  });

  it("dead-letter replay retains the mesh hop count", async () => {
    await withRelay("s-replay", { mesh: {} }, async (port, dir) => {
      stubStatus = 500;
      try {
        const res = await post(port, "/", inboundHeaders("s-replay", { [RELAY_HOPS_HEADER]: "1" }));
        assert.equal(res.status, 202);
        const auth = { authorization: `Bearer ${OPERATOR_TOKEN}` };
        await waitFor(() => {
          return readAudit(dir).some((e) => e.event === "dead_letter");
        }, 8000, "dead letter recorded");
        const list = await get(port, "/dead-letter", auth);
        assert.equal(list.status, 200);
        const entries = JSON.parse(list.text) as Array<{ id: string }>;
        assert.ok(entries.length >= 1);
        const deadLetter = readAudit(dir).find((e) => e.event === "dead_letter");
        assert.equal(deadLetter?.meshHops, 1, "dead_letter audit carries the hop count");
        // Recover the downstream, then replay: the wire stamp increments
        // from the retained count (1 → 2), not from zero.
        stubStatus = 200;
        seen.length = 0;
        const replay = await post(port, `/dead-letter/${entries[0].id}/replay`, auth);
        assert.equal(replay.status, 200);
        await waitFor(() => seen.length > 0, 5000, "stub received the replayed delivery");
        assert.equal((seen[0] as Record<string, string>)[RELAY_HOPS_HEADER], "2");
      } finally {
        stubStatus = 200;
      }
    });
  });
});
