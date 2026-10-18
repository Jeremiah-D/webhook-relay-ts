import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const SECRET = "batch-endpoint-secret";

function item(payload: unknown, headers: Record<string, string> = {}) {
  const body = Buffer.from(JSON.stringify(payload));
  return {
    payload: body.toString("base64"),
    headers: { "x-signature": signSha256(body, SECRET), ...headers },
  };
}

function envelope(items: unknown[]) {
  return Buffer.from(JSON.stringify({ events: items }));
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function post(port: number, path: string, body: Buffer, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; json: any; text: string }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path, method: "POST", headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString();
          let json: any;
          try {
            json = JSON.parse(text);
          } catch {
            json = undefined;
          }
          resolve({ status: res.statusCode ?? 0, json, text });
        });
      }
    );
    r.on("error", reject);
    r.end(body);
  });
}

function makeRelay(extra: Record<string, unknown> = {}) {
  const dir = mkdtempSync(join(tmpdir(), "audit-"));
  const audit = new AuditLog(join(dir, "audit.jsonl"));
  const relay = createRelayServer({
    secret: SECRET,
    forwardUrl: "http://127.0.0.1:1/hook",
    auditLog: audit,
    retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
    ...extra,
  } as Parameters<typeof createRelayServer>[0]);
  return { relay, audit };
}

async function withRelay(
  extra: Record<string, unknown>,
  fn: (port: number, audit: AuditLog) => Promise<void>
) {
  const { relay, audit } = makeRelay(extra);
  const port = await listen(relay);
  try {
    await fn(port, audit);
  } finally {
    relay.close();
    await new Promise((r) => relay.once("close", r));
  }
}

describe("POST /batch", () => {
  let stub: Server;
  let stubPort: number;
  let received: number;

  before(async () => {
    stub = createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        received++;
        res.writeHead(200).end("ok");
      });
    });
    stubPort = await listen(stub);
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  it("accepts a batch with per-item signatures only (no envelope signature)", async () => {
    await withRelay({ forwardUrl: `http://127.0.0.1:${stubPort}/hook` }, async (port, audit) => {
      received = 0;
      const res = await post(
        port,
        "/batch",
        envelope([item({ n: 1 }), item({ n: 2 }), item({ n: 3 })])
      );
      assert.equal(res.status, 202);
      assert.equal(res.json.accepted, 3);
      assert.deepEqual(res.json.rejected, []);
      assert.ok(typeof res.json.batchId === "string");
      assert.ok(typeof res.json.traceId === "string");

      const events = audit.readAll() as Array<Record<string, unknown>>;
      const receivedBatch = events.filter((e) => e.event === "batch_received");
      assert.equal(receivedBatch.length, 1);
      assert.equal(receivedBatch[0].total, 3);
      assert.equal(receivedBatch[0].accepted, 3);
      assert.equal(receivedBatch[0].path, "/batch");
      // Every per-item accepted event carries the batchId for correlation.
      const accepted = events.filter((e) => e.event === "accepted");
      assert.equal(accepted.length, 3);
      assert.ok(accepted.every((e) => e.batchId === res.json.batchId));

      // Deliveries actually flow downstream.
      const deadline = Date.now() + 5000;
      while (received < 3 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(received, 3);
    });
  });

  it("reports per-item failures with 207 and keeps admitting the rest", async () => {
    await withRelay({ forwardUrl: `http://127.0.0.1:${stubPort}/hook` }, async (port, audit) => {
      const badBody = Buffer.from(JSON.stringify({ n: "bad" }));
      const res = await post(
        port,
        "/batch",
        envelope([
          item({ n: 1 }),
          { payload: badBody.toString("base64"), headers: { "x-signature": "sha256=00" } },
          item({ n: 3 }),
        ])
      );
      assert.equal(res.status, 207);
      assert.equal(res.json.accepted, 2);
      assert.deepEqual(res.json.rejected, [{ index: 1, reason: "invalid_signature" }]);

      const events = audit.readAll() as Array<Record<string, unknown>>;
      const rejected = events.filter((e) => e.event === "rejected");
      assert.equal(rejected.length, 1);
      assert.equal(rejected[0].reason, "invalid_signature");
      assert.equal(rejected[0].batchId, res.json.batchId);
    });
  });

  it("lowercases per-item header names before admission", async () => {
    await withRelay({ forwardUrl: `http://127.0.0.1:${stubPort}/hook` }, async (port) => {
      const body = Buffer.from(JSON.stringify({ n: 1 }));
      const res = await post(
        port,
        "/batch",
        envelope([
          {
            payload: body.toString("base64"),
            headers: { "X-Signature": signSha256(body, SECRET) },
          },
        ])
      );
      assert.equal(res.status, 202);
      assert.equal(res.json.accepted, 1);
    });
  });

  it("isolates malformed items per item instead of failing the batch", async () => {
    await withRelay({ forwardUrl: `http://127.0.0.1:${stubPort}/hook` }, async (port, audit) => {
      const res = await post(
        port,
        "/batch",
        envelope([item({ n: 1 }), { payload: "!!!not-base64!!!" }, item({ n: 3 })])
      );
      assert.equal(res.status, 207);
      assert.equal(res.json.accepted, 2);
      assert.deepEqual(res.json.rejected, [{ index: 1, reason: "invalid_item" }]);

      const events = audit.readAll() as Array<Record<string, unknown>>;
      const rejected = events.filter(
        (e) => e.event === "rejected" && e.reason === "invalid_item"
      );
      assert.equal(rejected.length, 1);
      assert.equal(rejected[0].index, 1);
    });
  });

  it("rejects the whole batch with 413 when one item exceeds the per-event budget", async () => {
    // The envelope budget is raised via endpointBodyLimits so the
    // oversized item reaches the per-item gate; the per-item budget
    // stays at the global 1000 bytes.
    await withRelay(
      {
        forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
        maxBodyBytes: 1000,
        endpointBodyLimits: [{ pattern: "/batch", maxBodyBytes: 100_000 }],
      },
      async (port, audit) => {
        const big = item({ data: "x".repeat(2000) });
        const res = await post(port, "/batch", envelope([item({ n: 1 }), big]));
        assert.equal(res.status, 413);

        const events = audit.readAll() as Array<Record<string, unknown>>;
        const rejected = events.filter(
          (e) => e.event === "rejected" && e.reason === "item_too_large"
        );
        assert.equal(rejected.length, 1);
        assert.equal(rejected[0].index, 1);
        assert.equal(rejected[0].path, "/batch");
        // Zero per-item admission ran: nothing was accepted.
        assert.ok(!events.some((e) => e.event === "accepted"));
        assert.ok(!events.some((e) => e.event === "batch_received"));
      }
    );
  });

  it("still enforces the envelope budget when no per-endpoint rule exists", async () => {
    await withRelay(
      { forwardUrl: `http://127.0.0.1:${stubPort}/hook`, maxBodyBytes: 100 },
      async (port, audit) => {
        const res = await post(port, "/batch", envelope([item({ n: 1 })]));
        assert.equal(res.status, 413);
        const events = audit.readAll() as Array<Record<string, unknown>>;
        assert.ok(
          events.some((e) => e.event === "rejected" && e.reason === "body_too_large")
        );
      }
    );
  });

  it("answers 400 for malformed envelopes and empty batches", async () => {
    await withRelay({ forwardUrl: `http://127.0.0.1:${stubPort}/hook` }, async (port, audit) => {
      const malformed = await post(port, "/batch", Buffer.from("{nope"));
      assert.equal(malformed.status, 400);

      const empty = await post(port, "/batch", envelope([]));
      assert.equal(empty.status, 400);

      const noEvents = await post(port, "/batch", Buffer.from(JSON.stringify({})));
      assert.equal(noEvents.status, 400);

      const events = audit.readAll() as Array<Record<string, unknown>>;
      // Nothing reached per-item admission.
      assert.ok(!events.some((e) => e.event === "accepted"));
      assert.ok(!events.some((e) => e.event === "batch_received"));
    });
  });

  it("405s non-POST methods", async () => {
    await withRelay({ forwardUrl: `http://127.0.0.1:${stubPort}/hook` }, async (port) => {
      const res = await new Promise<{ status: number }>((resolve, reject) => {
        const r = httpRequest(
          { host: "127.0.0.1", port, path: "/batch", method: "GET" },
          (res) => {
            res.resume();
            res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
          }
        );
        r.on("error", reject);
        r.end();
      });
      assert.equal(res.status, 405);
    });
  });
});
