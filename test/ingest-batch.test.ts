import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer, checkIngestBatchItem } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { ReplayGuard } from "../src/replay.ts";
import { AuditLog } from "../src/audit.ts";
import type { RetryItem } from "../src/retry.ts";

const TEST_KEY = "batch-test-secret";

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
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
        );
      }
    );
    r.on("error", reject);
    r.end(body);
  });
}

/** One signed batch item: base64 payload + per-item headers. */
function item(
  payload: unknown,
  extraHeaders: Record<string, string> = {}
): { payload: string; headers: Record<string, string> } {
  const raw = Buffer.from(JSON.stringify(payload));
  return {
    payload: raw.toString("base64"),
    headers: { "x-signature": signSha256(raw, TEST_KEY), ...extraHeaders },
  };
}

/** POST a signed batch envelope; returns the parsed per-item results. */
async function postBatch(
  port: number,
  events: Array<unknown>,
  extraHeaders: Record<string, string> = {}
): Promise<{ status: number; body: any }> {
  const envelope = Buffer.from(JSON.stringify({ events }));
  const res = await post(port, "/ingest/batch", envelope, {
    "x-signature": signSha256(envelope, TEST_KEY),
    ...extraHeaders,
  });
  return { status: res.status, body: JSON.parse(res.text) };
}

async function closeRelay(relay: Server): Promise<void> {
  relay.close();
  await new Promise<void>((r) => relay.once("close", r));
}

async function waitForSeen(seen: RetryItem[], n: number): Promise<void> {
  const deadline = Date.now() + 5000;
  while (seen.length < n && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.equal(seen.length, n);
}

function makeRelay(extraOpts: Record<string, unknown> = {}) {
  const dir = mkdtempSync(join(tmpdir(), "audit-batch-"));
  const audit = new AuditLog(join(dir, "audit.jsonl"));
  const seen: RetryItem[] = [];
  const relay = createRelayServer({
secret: TEST_KEY,
    forwardUrl: "http://127.0.0.1:1/unused",
    auditLog: audit,
    sender: async (i) => {
      seen.push(i);
    },
    retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
    ...extraOpts,
  });
  return { relay, audit, seen };
}

describe("WR-61 batch inbound ingestion", () => {
  describe("checkIngestBatchItem", () => {
    it("accepts a well-formed item", () => {
      const raw = Buffer.from('{"a":1}');
      const checked = checkIngestBatchItem({
        payload: raw.toString("base64"),
        headers: { "x-signature": "sha256=abc" },
      });
      assert.ok("item" in checked);
      assert.deepEqual(checked.body, raw);
    });

    it("rejects malformed items with machine-readable problems", () => {
      assert.deepEqual(checkIngestBatchItem(null), { problem: "item_must_be_object" });
      assert.deepEqual(checkIngestBatchItem([]), { problem: "item_must_be_object" });
      assert.deepEqual(checkIngestBatchItem({ payload: 42 }), {
        problem: "payload_must_be_base64",
      });
      assert.deepEqual(checkIngestBatchItem({ payload: "!!!not-base64!!!" }), {
        problem: "payload_must_be_base64",
      });
      assert.deepEqual(checkIngestBatchItem({ payload: "abc" }), {
        problem: "payload_must_be_base64",
      }); // bad padding
      assert.deepEqual(
        checkIngestBatchItem({ payload: Buffer.from("x").toString("base64"), headers: [] }),
        { problem: "headers_must_be_object" }
      );
      assert.deepEqual(
        checkIngestBatchItem({
          payload: Buffer.from("x").toString("base64"),
          headers: { "x-signature": 42 },
        }),
        { problem: "header_values_must_be_strings" }
      );
    });
  });

  describe("POST /ingest/batch", () => {
    let ctx: ReturnType<typeof makeRelay>;
    let port: number;
    before(async () => {
      ctx = makeRelay();
      port = await listen(ctx.relay);
    });
    after(async () => closeRelay(ctx.relay));

    it("accepts a batch of signed events and enqueues each with its own id", async () => {
      const { status, body } = await postBatch(port, [
        item({ n: 1 }),
        item({ n: 2 }, { "x-trace-id": "trace-item-2" }),
        item({ n: 3 }, { "x-priority": "urgent" }),
      ]);
      assert.equal(status, 202);
      assert.equal(body.results.length, 3);
      assert.ok(body.results.every((r: any) => r.status === 202));
      assert.ok(body.results.every((r: any) => typeof r.id === "string"));
      // Per-item trace IDs are independent.
      assert.equal(body.results[1].traceId, "trace-item-2");
      assert.notEqual(body.results[0].traceId, body.results[1].traceId);
      assert.notEqual(body.results[0].traceId, body.traceId);

      await waitForSeen(ctx.seen, 3);
      const payloads = ctx.seen.map((i) => JSON.parse(i.payload.toString()));
      assert.deepEqual(payloads, [{ n: 1 }, { n: 2 }, { n: 3 }]);
      assert.equal(ctx.seen.filter((i) => i.priority === "urgent").length, 1);

      const events = ctx.audit.readAll() as Array<Record<string, unknown>>;
      const ingested = events.filter((e) => e.event === "batch_ingested");
      assert.equal(ingested.length, 1);
      assert.equal(ingested[0].total, 3);
      assert.equal(ingested[0].accepted, 3);
      assert.equal(ingested[0].rejected, 0);
      // Every per-item audit event carries the batch id for correlation.
      const accepted = events.filter((e) => e.event === "accepted");
      assert.ok(accepted.length >= 3);
      assert.ok(accepted.every((e) => e.batchId === body.batchId));
    });

    it("rejects the whole batch on a bad envelope signature before splitting", async () => {
      const before = ctx.seen.length;
      const envelope = Buffer.from(JSON.stringify({ events: [item({ n: 1 })] }));
      const res = await post(port, "/ingest/batch", envelope, {
        "x-signature": "sha256=wrong",
      });
      assert.equal(res.status, 401);
      assert.equal(res.text, "Invalid batch signature");
      // Nothing enqueued, no per-item admission ran.
      await new Promise((r) => setTimeout(r, 100));
      assert.equal(ctx.seen.length, before);
      const events = ctx.audit.readAll() as Array<Record<string, unknown>>;
      const rejected = events.filter((e) => e.reason === "invalid_batch_signature");
      assert.equal(rejected.length, 1);
      assert.equal(events.filter((e) => e.event === "batch_ingested").length, 1); // unchanged
    });

    it("isolates per-item failures: 207 with per-item statuses", async () => {
      const good = item({ ok: true });
      const badSig = item({ ok: false });
      badSig.headers["x-signature"] = "sha256=nope";
      const malformed = { payload: "!!!", headers: {} };
      const { status, body } = await postBatch(port, [good, badSig, malformed]);
      assert.equal(status, 207); // multi-status: mixed outcomes
      assert.deepEqual(
        body.results.map((r: any) => r.status),
        [202, 401, 400]
      );
      assert.equal(body.results[1].reason, "invalid_signature");
      assert.equal(body.results[2].reason, "invalid_item");
      // Only the good item was enqueued.
      await waitForSeen(ctx.seen, 4);
      assert.deepEqual(JSON.parse(ctx.seen[3].payload.toString()), { ok: true });

      const events = ctx.audit.readAll() as Array<Record<string, unknown>>;
      const ingested = events.filter((e) => e.event === "batch_ingested").pop();
      assert.equal(ingested?.total, 3);
      assert.equal(ingested?.accepted, 1);
      assert.equal(ingested?.rejected, 2);
    });

    it("rejects malformed envelopes without touching per-item admission", async () => {
      const badJson = Buffer.from("{not json");
      let res = await post(port, "/ingest/batch", badJson, {
        "x-signature": signSha256(badJson, TEST_KEY),
      });
      assert.equal(res.status, 400);
      const noEvents = Buffer.from(JSON.stringify({ events: "nope" }));
      res = await post(port, "/ingest/batch", noEvents, {
        "x-signature": signSha256(noEvents, TEST_KEY),
      });
      assert.equal(res.status, 400);
      const empty = Buffer.from(JSON.stringify({ events: [] }));
      res = await post(port, "/ingest/batch", empty, {
        "x-signature": signSha256(empty, TEST_KEY),
      });
      assert.equal(res.status, 400);
      const events = ctx.audit.readAll() as Array<Record<string, unknown>>;
      assert.ok(events.some((e) => e.reason === "invalid_batch_shape"));
      assert.ok(events.some((e) => e.reason === "empty_batch"));
    });

    it("answers 405 to non-POST", async () => {
      const r = await new Promise<{ status: number }>((resolve, reject) => {
        const req = httpRequest(
          { host: "127.0.0.1", port, path: "/ingest/batch", method: "GET" },
          (res) => resolve({ status: res.statusCode ?? 0 })
        );
        req.on("error", reject);
        req.end();
      });
      assert.equal(r.status, 405);
    });
  });

  describe("per-item pipeline fidelity", () => {
    it("applies the replay guard per item inside one batch", async () => {
      const { relay, seen } = makeRelay({ replay: new ReplayGuard({ windowSec: 60 }) });
      const port = await listen(relay);
      try {
        const { status, body } = await postBatch(port, [
          item({ n: 1 }, { "x-nonce": "batch-nonce-1" }),
          item({ n: 2 }, { "x-nonce": "batch-nonce-1" }),
        ]);
        assert.equal(status, 207);
        assert.deepEqual(
          body.results.map((r: any) => r.status),
          [202, 409]
        );
        assert.equal(body.results[1].reason, "duplicate_nonce");
        await waitForSeen(seen, 1);
      } finally {
        await closeRelay(relay);
      }
    });

    it("applies dedup per item: a repeated payload is acknowledged once", async () => {
      const { relay, audit, seen } = makeRelay({ dedup: { windowMs: 60000 } });
      const port = await listen(relay);
      try {
        const { status, body } = await postBatch(port, [item({ pay: 1 }), item({ pay: 1 })]);
        assert.equal(status, 202);
        assert.deepEqual(
          body.results.map((r: any) => r.status),
          [202, 202]
        );
        assert.equal(body.results[1].duplicate, true);
        await waitForSeen(seen, 1);
        const events = audit.readAll() as Array<Record<string, unknown>>;
        assert.ok(events.some((e) => e.event === "duplicate_suppressed"));
      } finally {
        await closeRelay(relay);
      }
    });

    it("validates the batch-level tenant once and lets items override it", async () => {
      const { relay, audit, seen } = makeRelay();
      const port = await listen(relay);
      try {
        // Invalid batch tenant: the whole batch is rejected up front.
        const env = Buffer.from(JSON.stringify({ events: [item({ n: 1 })] }));
        let res = await post(port, "/ingest/batch", env, {
          "x-signature": signSha256(env, TEST_KEY),
          "x-tenant-id": "bad tenant!!",
        });
        assert.equal(res.status, 400);

        // Valid batch tenant is inherited; a per-item tenant overrides it.
        const r = await postBatch(
          port,
          [item({ n: 1 }), item({ n: 2 }, { "x-tenant-id": "tenant-b" })],
          { "x-tenant-id": "tenant-a" }
        );
        assert.equal(r.status, 202);
        await waitForSeen(seen, 2);
        assert.deepEqual(
          seen.map((i) => i.tenantId),
          ["tenant-a", "tenant-b"]
        );
        const events = audit.readAll() as Array<Record<string, unknown>>;
        const ingested = events.filter((e) => e.event === "batch_ingested").pop();
        assert.equal(ingested?.tenant, "tenant-a");
      } finally {
        await closeRelay(relay);
      }
    });

    it("an unsigned item is rejected 401 like an unsigned single webhook", async () => {
      const { relay, seen } = makeRelay();
      const port = await listen(relay);
      try {
        const raw = Buffer.from(JSON.stringify({ n: 1 }));
        const { status, body } = await postBatch(port, [
          { payload: raw.toString("base64"), headers: {} },
        ]);
        assert.equal(status, 207);
        assert.equal(body.results[0].status, 401);
        assert.equal(body.results[0].reason, "invalid_signature");
        await new Promise((r) => setTimeout(r, 100));
        assert.equal(seen.length, 0);
      } finally {
        await closeRelay(relay);
      }
    });
  });
});
