import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256, type Verifier } from "../src/verify.ts";
import { ReplayGuard } from "../src/replay.ts";
import { AuditLog } from "../src/audit.ts";
import type { RetryItem } from "../src/retry.ts";

const SECRET = "relay-secret";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function get(port: number, path: string, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path, method: "GET", headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
      }
    );
    r.on("error", reject);
    r.end();
  });
}

async function postReplay(port: number, id: string, token?: string) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const headers: Record<string, string> = {};
    if (token !== undefined) headers["authorization"] = `Bearer ${token}`;
    const r = httpRequest(
      { host: "127.0.0.1", port, path: `/dead-letter/${encodeURIComponent(id)}/replay`, method: "POST", headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
      }
    );
    r.on("error", reject);
    r.end();
  });
}

function post(port: number, path: string, body: Buffer, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path, method: "POST", headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
      }
    );
    r.on("error", reject);
    r.end(body);
  });
}

describe("server", () => {
  let stub: Server;
  let stubPort: number;
  const received: RetryItem[] = [];
  let receivedRaw: Buffer[] = [];

  before(async () => {
    stub = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        receivedRaw.push(Buffer.concat(chunks));
        received.push({} as RetryItem);
        res.writeHead(200).end("ok");
      });
    });
    stubPort = await listen(stub);
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  it("forwards a valid webhook and audits delivery", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 3 },
    });
    const port = await listen(relay);
    try {
      receivedRaw = [];
      const res = await post(port, "/", BODY, {
        "x-signature": signSha256(BODY, SECRET),
        "content-type": "application/json",
        "x-custom": "yes",
      });
      assert.equal(res.status, 202);
      // Wait for the async forward to land at the stub.
      const deadline = Date.now() + 5000;
      while (receivedRaw.length === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(receivedRaw.length, 1);
      assert.deepEqual(receivedRaw[0], BODY);
      assert.equal(received.length, 1);

      const events = audit.readAll() as Array<Record<string, unknown>>;
      assert.ok(events.some((e) => e.event === "accepted"));
      assert.ok(events.some((e) => e.event === "delivered"));
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("rejects an invalid signature with 401 and never forwards", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 3 },
    });
    const port = await listen(relay);
    try {
      const before = receivedRaw.length;
      const res = await post(port, "/", BODY, { "x-signature": signSha256(BODY, "wrong-secret") });
      assert.equal(res.status, 401);
      await new Promise((r) => setTimeout(r, 300));
      assert.equal(receivedRaw.length, before);

      const events = audit.readAll() as Array<Record<string, unknown>>;
      const rejected = events.filter((e) => e.event === "rejected");
      assert.equal(rejected.length, 1);
      assert.equal(rejected[0].reason, "invalid_signature");
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("honors an injected accept-all verifier (unsigned request accepted)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const acceptAll: Verifier = { name: "accept-all", verify: () => true };
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 3 },
      verifier: acceptAll,
    });
    const port = await listen(relay);
    try {
      const before = receivedRaw.length;
      const res = await post(port, "/", BODY, {}); // no x-signature at all
      assert.equal(res.status, 202);
      const deadline = Date.now() + 5000;
      while (receivedRaw.length === before && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(receivedRaw.length, before + 1);
      assert.deepEqual(receivedRaw[receivedRaw.length - 1], BODY);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("honors an injected reject-all verifier (valid HMAC signature refused)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const rejectAll: Verifier = { name: "reject-all", verify: () => false };
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 3 },
      verifier: rejectAll,
    });
    const port = await listen(relay);
    try {
      const before = receivedRaw.length;
      const res = await post(port, "/", BODY, { "x-signature": signSha256(BODY, SECRET) });
      assert.equal(res.status, 401);
      await new Promise((r) => setTimeout(r, 300));
      assert.equal(receivedRaw.length, before);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });
  it("disables operator endpoints when no operatorToken is set", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 3 },
    });
    const port = await listen(relay);
    try {
      const list = await get(port, "/dead-letter");
      assert.equal(list.status, 404);
      const replay = await postReplay(port, "anything", "some-token");
      assert.equal(replay.status, 404);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("lists and replays dead letters behind the operator token", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      sender: async () => {
        throw new Error("downstream 500");
      },
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
      operatorToken: "op-secret",
    });
    const port = await listen(relay);
    const auth = { authorization: "Bearer op-secret" };
    try {
      // Unauthorized operator access is rejected.
      assert.equal((await get(port, "/dead-letter")).status, 403);
      assert.equal((await get(port, "/dead-letter", { authorization: "Bearer wrong" })).status, 403);
      assert.equal((await postReplay(port, "x")).status, 403);

      // Queue starts empty.
      const empty = await get(port, "/dead-letter", auth);
      assert.equal(empty.status, 200);
      assert.deepEqual(JSON.parse(empty.text), []);

      // A webhook whose delivery always fails ends up dead-lettered.
      const res = await post(port, "/", BODY, { "x-signature": signSha256(BODY, SECRET) });
      assert.equal(res.status, 202);

      let entries: Array<Record<string, unknown>> = [];
      const deadline = Date.now() + 5000;
      while (Date.now() < deadline) {
        const listed = await get(port, "/dead-letter", auth);
        assert.equal(listed.status, 200);
        entries = JSON.parse(listed.text) as Array<Record<string, unknown>>;
        if (entries.length === 1) break;
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(entries.length, 1);
      const entry = entries[0];
      assert.equal(typeof entry.id, "string");
      assert.equal(entry.targetUrl, `http://127.0.0.1:${stubPort}/hook`);
      assert.equal(entry.attempts, 2);
      assert.equal(entry.lastError, "downstream 500");
      assert.ok(!Number.isNaN(Date.parse(entry.deadLetteredAt as string)));
      assert.equal(entry.payloadBytes, BODY.length);
      assert.ok(!("payload" in entry), "listing must not leak raw payloads");

      // Unknown ids 404.
      assert.equal((await postReplay(port, "nope", "op-secret")).status, 404);

      // Manual replay is accepted and audited; the item fails again and
      // returns to the dead-letter list (sender still failing).
      const replayed = await postReplay(port, entry.id as string, "op-secret");
      assert.equal(replayed.status, 200);
      assert.deepEqual(JSON.parse(replayed.text), { id: entry.id, replayed: true });

      const deadline2 = Date.now() + 5000;
      while (Date.now() < deadline2) {
        const listed = await get(port, "/dead-letter", auth);
        const again = JSON.parse(listed.text) as Array<Record<string, unknown>>;
        if (again.length === 1) break;
        await new Promise((r) => setTimeout(r, 25));
      }
      const events = audit.readAll() as Array<Record<string, unknown>>;
      assert.ok(events.some((e) => e.event === "dead_letter"));
      assert.ok(
        events.some((e) => e.event === "dead_letter_replayed" && e.id === entry.id),
        "replay must be audited"
      );
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("disables the audit query endpoint when no operatorToken is set", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 3 },
    });
    const port = await listen(relay);
    try {
      assert.equal((await get(port, "/audit")).status, 404);
      assert.equal((await get(port, "/audit", { authorization: "Bearer x" })).status, 404);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("queries the audit log behind the operator token", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const forwardUrl = `http://127.0.0.1:${stubPort}/hook`;
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 3 },
      operatorToken: "op-secret",
    });
    const port = await listen(relay);
    const auth = { authorization: "Bearer op-secret" };
    try {
      assert.equal((await get(port, "/audit")).status, 403);
      assert.equal((await get(port, "/audit", { authorization: "Bearer wrong" })).status, 403);
      assert.equal((await post(port, "/audit", Buffer.alloc(0), auth)).status, 405);

      const res = await post(port, "/", BODY, { "x-signature": signSha256(BODY, SECRET) });
      assert.equal(res.status, 202);

      // Wait for the delivery to be audited, via the endpoint itself.
      let delivered: Array<Record<string, unknown>> = [];
      const deadline = Date.now() + 5000;
      while (Date.now() < deadline) {
        const q = await get(port, "/audit?event=delivered", auth);
        assert.equal(q.status, 200);
        delivered = JSON.parse(q.text) as Array<Record<string, unknown>>;
        if (delivered.length === 1) break;
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(delivered.length, 1);
      assert.equal(delivered[0].targetUrl, forwardUrl);

      const all = JSON.parse((await get(port, "/audit", auth)).text) as Array<Record<string, unknown>>;
      assert.ok(all.some((e) => e.event === "accepted"));
      assert.ok(all.some((e) => e.event === "delivered"));

      const byEndpoint = JSON.parse(
        (await get(port, `/audit?endpoint=${encodeURIComponent(forwardUrl)}`, auth)).text
      ) as Array<Record<string, unknown>>;
      assert.ok(byEndpoint.length >= 2);

      const none = JSON.parse(
        (await get(port, "/audit?endpoint=http://127.0.0.1:1/nowhere", auth)).text
      ) as Array<unknown>;
      assert.deepEqual(none, []);

      const future = JSON.parse(
        (await get(port, "/audit?since=2999-01-01T00:00:00.000Z", auth)).text
      ) as Array<unknown>;
      assert.deepEqual(future, []);

      const limited = JSON.parse((await get(port, "/audit?limit=1", auth)).text) as Array<
        Record<string, unknown>
      >;
      assert.equal(limited.length, 1);
      assert.equal(limited[0].event, "delivered"); // most recent match kept

      assert.equal((await get(port, "/audit?since=not-a-date", auth)).status, 400);
      assert.equal((await get(port, "/audit?limit=0", auth)).status, 400);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("enforces replay protection when a ReplayGuard is injected", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 3 },
      replay: new ReplayGuard({ windowSec: 60 }),
    });
    const port = await listen(relay);
    const sig = { "x-signature": signSha256(BODY, SECRET) };
    try {
      const before = receivedRaw.length;

      // Signature is still checked before the replay guard.
      assert.equal((await post(port, "/", BODY, { "x-signature": signSha256(BODY, "wrong") })).status, 401);

      // Missing nonce -> 400.
      assert.equal((await post(port, "/", BODY, sig)).status, 400);

      // Fresh nonce -> accepted and forwarded.
      const ok = await post(port, "/", BODY, { ...sig, "x-nonce": "nonce-1" });
      assert.equal(ok.status, 202);

      // Same nonce again -> 409 replay, never forwarded twice.
      const replayed = await post(port, "/", BODY, { ...sig, "x-nonce": "nonce-1" });
      assert.equal(replayed.status, 409);

      // Stale and far-future timestamps -> 400.
      const stale = Math.floor(Date.now() / 1000) - 3600;
      assert.equal((await post(port, "/", BODY, { ...sig, "x-nonce": "nonce-2", "x-timestamp": `${stale}` })).status, 400);
      const future = Math.floor(Date.now() / 1000) + 3600;
      assert.equal((await post(port, "/", BODY, { ...sig, "x-nonce": "nonce-3", "x-timestamp": `${future}` })).status, 400);
      // A non-numeric timestamp also fails the window check.
      assert.equal((await post(port, "/", BODY, { ...sig, "x-nonce": "nonce-4", "x-timestamp": "soon" })).status, 400);

      // A fresh timestamp inside the window is accepted.
      const nowSec = Math.floor(Date.now() / 1000);
      const fresh = await post(port, "/", BODY, { ...sig, "x-nonce": "nonce-5", "x-timestamp": `${nowSec}` });
      assert.equal(fresh.status, 202);

      // Only the two accepted deliveries were forwarded.
      const deadline = Date.now() + 5000;
      while (receivedRaw.length < before + 2 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(receivedRaw.length, before + 2);

      const events = audit.readAll() as Array<Record<string, unknown>>;
      const rejected = events.filter((e) => e.event === "rejected");
      const reasons = rejected.map((e) => e.reason);
      assert.ok(reasons.includes("duplicate_nonce"), "replay must be audited");
      assert.ok(reasons.includes("missing_nonce"));
      assert.ok(reasons.filter((r) => r === "expired_timestamp").length >= 2);
      assert.ok(reasons.includes("future_timestamp"));
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("leaves the receiver unchanged when no ReplayGuard is injected", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 3 },
    });
    const port = await listen(relay);
    try {
      // Legacy unsigned-nonce senders keep working: no nonce required.
      const res = await post(port, "/", BODY, { "x-signature": signSha256(BODY, SECRET) });
      assert.equal(res.status, 202);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("maps x-priority: urgent onto the fast lane and defaults to normal", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const seen: RetryItem[] = [];
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog: audit,
      sender: async (item) => {
        seen.push(item);
      },
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
    });
    const port = await listen(relay);
    try {
      const sig = { "x-signature": signSha256(BODY, SECRET) };
      assert.equal((await post(port, "/", BODY, { ...sig, "x-priority": "urgent" })).status, 202);
      assert.equal((await post(port, "/", BODY, sig)).status, 202);
      assert.equal(
        (await post(port, "/", BODY, { ...sig, "x-priority": "Urgent" })).status,
        202
      ); // case-insensitive
      const deadline = Date.now() + 5000;
      while (seen.length < 3 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(seen.length, 3);
      const byPriority = (p: string | undefined) => seen.filter((i) => i.priority === p).length;
      assert.equal(byPriority("urgent"), 2);
      assert.equal(byPriority(undefined), 1);

      const events = audit.readAll() as Array<Record<string, unknown>>;
      const accepted = events.filter((e) => e.event === "accepted");
      assert.equal(accepted.length, 3);
      assert.equal(accepted.filter((e) => e.priority === "urgent").length, 2);
      assert.ok(accepted.every((e) => e.priority === undefined || e.priority === "urgent"));
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("exposes per-endpoint latency percentiles on the operator GET /latency endpoint", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const forwardUrl = `http://127.0.0.1:${stubPort}/hook`;
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl,
      auditLog: audit,
      operatorToken: "op-token",
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2, latency: { sloMs: 60000 } },
    });
    const port = await listen(relay);
    try {
      assert.equal(
        (await post(port, "/", BODY, { "x-signature": signSha256(BODY, SECRET) })).status,
        202
      );
      // Wait until the delivery samples into the latency tracker.
      const deadline = Date.now() + 5000;
      let stats: Array<Record<string, unknown>> = [];
      while (Date.now() < deadline) {
        const res = await get(port, "/latency", { authorization: "Bearer op-token" });
        assert.equal(res.status, 200);
        stats = JSON.parse(res.text) as Array<Record<string, unknown>>;
        if (stats.length > 0) break;
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(stats.length, 1);
      const s = stats[0];
      assert.equal(s.endpoint, forwardUrl);
      assert.equal(s.count, 1);
      assert.ok(typeof s.p50 === "number" && (s.p50 as number) >= 0);
      assert.equal(s.p95, s.p50);
      assert.equal(s.p99, s.p50);
      assert.equal(s.sloMs, 60000);
      assert.equal(s.withinSlo, 1);
      assert.equal(s.sloAttainment, 1);
      // Endpoint filter narrows the result; unknown endpoints come back empty.
      const filtered = await get(port, "/latency?endpoint=" + encodeURIComponent(forwardUrl), {
        authorization: "Bearer op-token",
      });
      assert.equal(JSON.parse(filtered.text).length, 1);
      const missing = await get(port, "/latency?endpoint=" + encodeURIComponent("http://nope/"), {
        authorization: "Bearer op-token",
      });
      assert.deepEqual(JSON.parse(missing.text), []);
      // Guarded by the shared operator-token check (403 without/with a wrong
      // bearer; 404 when no operatorToken is configured at all — the same
      // fail-closed guard as the other operator endpoints).
      assert.equal((await get(port, "/latency")).status, 403);
      assert.equal((await get(port, "/latency", { authorization: "Bearer wrong" })).status, 403);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("audits an slo_missed event when a delivery exceeds the latency budget", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog: audit,
      // A slow downstream: every delivery takes ~60ms against a 5ms budget.
      sender: async () => {
        await new Promise((r) => setTimeout(r, 60));
      },
      retry: { latency: { sloMs: 5 } },
    });
    const port = await listen(relay);
    try {
      assert.equal(
        (await post(port, "/", BODY, { "x-signature": signSha256(BODY, SECRET) })).status,
        202
      );
      const deadline = Date.now() + 5000;
      let missed: Array<Record<string, unknown>> = [];
      while (Date.now() < deadline) {
        missed = (audit.readAll() as Array<Record<string, unknown>>).filter(
          (e) => e.event === "slo_missed"
        );
        if (missed.length > 0) break;
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(missed.length, 1);
      assert.ok((missed[0].latencyMs as number) > 5);
      assert.equal(missed[0].sloMs, 5);
      assert.equal(typeof missed[0].id, "string");
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });
});

