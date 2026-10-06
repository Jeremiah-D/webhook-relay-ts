import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
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
});
