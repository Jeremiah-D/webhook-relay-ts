import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256, type Verifier } from "../src/verify.ts";
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
});

