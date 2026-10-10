import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import { buildDeliverySnapshot } from "../src/delivery-status.ts";

const SECRET = "ds-secret";
const TOKEN = "op-token";
const BODY = Buffer.from(JSON.stringify({ order: "ord_ds", amount: 100 }));

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

async function close(server: Server): Promise<void> {
  server.close();
  await new Promise((r) => server.once("close", r));
}

function request(port: number, path: string, method: string, body?: Buffer, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
    });
    r.on("error", reject);
    if (body) r.end(body);
    else r.end();
  });
}

function post(port: number, body: Buffer, headers: Record<string, string> = {}) {
  return request(port, "/", "POST", body, headers);
}

async function getJson(port: number, path: string, headers: Record<string, string> = {}) {
  const res = await request(port, path, "GET", undefined, headers);
  let json: any = null;
  try {
    json = JSON.parse(res.text);
  } catch {
    // Leave json as null; the status assertion will fail the test.
  }
  return { status: res.status, json };
}

function signedHeaders(body: Buffer, traceId: string): Record<string, string> {
  return {
    "x-signature": signSha256(body, SECRET),
    "x-trace-id": traceId,
    "content-type": "application/json",
  };
}

/** Flaky downstream: fails `failures` times with 500, then answers 200. */
function flakyStub(failures: number) {
  const hits: Array<{ at: number; body: Buffer; status: number }> = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const status = hits.length < failures ? 500 : 200;
      hits.push({ at: Date.now(), body: Buffer.concat(chunks), status });
      res.writeHead(status).end(status === 200 ? "ok" : "boom");
    });
  });
  return { server, hits };
}

async function waitFor(cond: () => boolean, timeoutMs: number, what: string): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond() && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.ok(cond(), `timed out waiting for: ${what}`);
}

function freshAudit(): AuditLog {
  return new AuditLog(join(mkdtempSync(join(tmpdir(), "ds-")), "audit.jsonl"));
}

const auth = { authorization: `Bearer ${TOKEN}` };

describe("GET /deliveries/:traceId (WR-43)", () => {
  it("renders the retry trajectory and the final delivery", async () => {
    const { server: stub, hits } = flakyStub(2);
    const stubPort = await listen(stub);
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: freshAudit(),
      operatorToken: TOKEN,
      retry: { baseDelayMs: 50, maxDelayMs: 1000, maxAttempts: 5, jitterMs: 0 },
    });
    const relayPort = await listen(relay);
    try {
      const res = await post(relayPort, BODY, signedHeaders(BODY, "trace-retry-1"));
      assert.equal(res.status, 202);

      await waitFor(() => hits.length >= 3, 15000, "3 downstream attempts");

      const { status, json } = await getJson(relayPort, "/deliveries/trace-retry-1", auth);
      assert.equal(status, 200);
      assert.equal(json.traceId, "trace-retry-1");
      assert.equal(json.state, "delivered");
      assert.ok(typeof json.id === "string" && json.id.length > 0);
      assert.equal(json.endpoint, `http://127.0.0.1:${stubPort}/hook`);
      assert.deepEqual(
        json.timeline.map((t: any) => t.state),
        ["accepted", "retrying", "retrying", "delivered"]
      );
      assert.equal(json.attempts, 3);
      assert.equal(json.retryCount, 2);
      // Every retrying step carries the failure and the scheduled delay.
      for (const step of json.timeline.filter((t: any) => t.state === "retrying")) {
        assert.ok(typeof step.lastError === "string" && step.lastError.length > 0);
        assert.ok(typeof step.nextDelayMs === "number" && step.nextDelayMs >= 0);
        assert.ok(typeof step.attempts === "number");
      }
      assert.ok(typeof json.latencyMs === "number" && json.latencyMs >= 0);
      assert.ok(typeof json.lastError === "string" && json.lastError.length > 0);
      assert.deepEqual(json.replayed, []);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("shows the dead-letter trajectory and records replays", async () => {
    const { server: stub, hits } = flakyStub(1000);
    const stubPort = await listen(stub);
    const audit = freshAudit();
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      operatorToken: TOKEN,
      retry: { baseDelayMs: 50, maxDelayMs: 1000, maxAttempts: 2, jitterMs: 0 },
    });
    const relayPort = await listen(relay);
    try {
      const res = await post(relayPort, BODY, signedHeaders(BODY, "trace-dl-1"));
      assert.equal(res.status, 202);
      await waitFor(
        () => audit.query({ traceId: "trace-dl-1", event: "dead_letter" }).length >= 1,
        15000,
        "dead_letter audit line"
      );

      let snap = (await getJson(relayPort, "/deliveries/trace-dl-1", auth)).json;
      assert.equal(snap.state, "dead_letter");
      assert.deepEqual(
        snap.timeline.map((t: any) => t.state),
        ["accepted", "retrying", "dead_letter"]
      );
      assert.equal(snap.attempts, 2);
      assert.equal(snap.retryCount, 1);
      assert.equal(snap.timeline[2].failureClass, "retryable");
      assert.ok(typeof snap.lastError === "string" && snap.lastError.length > 0);
      assert.deepEqual(snap.replayed, []);

      // Operator replays the dead letter; the replay record joins the snapshot.
      const list = (await getJson(relayPort, "/dead-letter", auth)).json;
      assert.ok(Array.isArray(list) && list.length >= 1);
      const replay = await request(relayPort, `/dead-letter/${list[0].id}/replay`, "POST", undefined, auth);
      assert.equal(replay.status, 200);
      await waitFor(
        () => (buildDeliverySnapshot(audit, "trace-dl-1")?.replayed.length ?? 0) >= 1,
        15000,
        "replay record in snapshot"
      );
      snap = (await getJson(relayPort, "/deliveries/trace-dl-1", auth)).json;
      assert.equal(snap.replayed.length, 1);
      assert.equal(snap.replayed[0].id, snap.id);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("renders a rejection snapshot for intake-time rejections", async () => {
    const { server: stub } = flakyStub(0);
    const stubPort = await listen(stub);
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: freshAudit(),
      operatorToken: TOKEN,
    });
    const relayPort = await listen(relay);
    try {
      const res = await post(relayPort, BODY, { "x-signature": "bad", "x-trace-id": "trace-rej-1" });
      assert.equal(res.status, 401);
      const { status, json } = await getJson(relayPort, "/deliveries/trace-rej-1", auth);
      assert.equal(status, 200);
      assert.equal(json.state, "rejected");
      assert.equal(json.timeline.length, 1);
      assert.equal(json.timeline[0].state, "rejected");
      assert.ok(typeof json.timeline[0].reason === "string");
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("renders a duplicate-suppression snapshot", async () => {
    const { server: stub } = flakyStub(0);
    const stubPort = await listen(stub);
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: freshAudit(),
      operatorToken: TOKEN,
      dedup: {},
    });
    const relayPort = await listen(relay);
    try {
      const first = await post(relayPort, BODY, signedHeaders(BODY, "trace-dup-1"));
      assert.equal(first.status, 202);
      const second = await post(relayPort, BODY, signedHeaders(BODY, "trace-dup-2"));
      assert.equal(second.status, 202);
      assert.ok(JSON.parse(second.text).duplicate === true);

      const { status, json } = await getJson(relayPort, "/deliveries/trace-dup-2", auth);
      assert.equal(status, 200);
      assert.equal(json.state, "duplicate_suppressed");
      assert.deepEqual(
        json.timeline.map((t: any) => t.state),
        ["duplicate_suppressed"]
      );
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("returns 404 with an audit hint for an unknown traceId", async () => {
    const { server: stub } = flakyStub(0);
    const stubPort = await listen(stub);
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: freshAudit(),
      operatorToken: TOKEN,
    });
    const relayPort = await listen(relay);
    try {
      const { status, json } = await getJson(relayPort, "/deliveries/no-such-trace", auth);
      assert.equal(status, 404);
      assert.equal(json.error, "unknown traceId");
      assert.ok(typeof json.hint === "string" && json.hint.includes("/audit"));
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("is fail-closed without an operator token and rejects bad tokens", async () => {
    const { server: stub } = flakyStub(0);
    const stubPort = await listen(stub);
    const relayNoToken = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: freshAudit(),
    });
    const relayWithToken = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: freshAudit(),
      operatorToken: TOKEN,
    });
    const p1 = await listen(relayNoToken);
    const p2 = await listen(relayWithToken);
    try {
      assert.equal((await getJson(p1, "/deliveries/anything", auth)).status, 404);
      assert.equal(
        (await getJson(p2, "/deliveries/anything", { authorization: "Bearer wrong" })).status,
        403
      );
    } finally {
      await close(relayNoToken);
      await close(relayWithToken);
      await close(stub);
    }
  });
});

describe("buildDeliverySnapshot", () => {
  it("returns null for a trace with no audit lines", () => {
    assert.equal(buildDeliverySnapshot(freshAudit(), "missing"), null);
  });

  it("tolerates a missing accepted line (no id, no latency)", () => {
    const audit = freshAudit();
    audit.append({ event: "delivered", traceId: "t-x", id: "i1", attempts: 1, targetUrl: "http://x/hook" });
    const snap = buildDeliverySnapshot(audit, "t-x");
    assert.ok(snap !== null);
    assert.equal(snap.state, "delivered");
    assert.equal(snap.id, undefined);
    assert.equal(snap.latencyMs, undefined);
    assert.equal(snap.timeline.length, 1);
  });

  it("folds replay records matched by delivery id", () => {
    const audit = freshAudit();
    audit.append({ event: "accepted", traceId: "t-r", id: "i9", targetUrl: "http://x/hook" });
    audit.append({ event: "dead_letter_replayed", id: "i9" });
    const snap = buildDeliverySnapshot(audit, "t-r");
    assert.ok(snap !== null);
    assert.equal(snap.state, "delivering");
    assert.equal(snap.replayed.length, 1);
    assert.equal(snap.replayed[0].id, "i9");
  });
});
