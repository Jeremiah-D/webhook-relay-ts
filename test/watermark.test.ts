import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { appendFileSync } from "node:fs";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DeliveryWatermark, WATERMARK_JOURNAL_FILE } from "../src/watermark.ts";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: intentionally not named `SECRET` — see repo conventions.
const WEBHOOK_KEY = "wm-test-key";
const TOKEN = "op-token";
const BODY = Buffer.from(JSON.stringify({ event: "payment.succeeded" }));
const FORWARD_URL = "http://127.0.0.1:1/hook"; // never called; the sender is injected

type RelayOptions = Parameters<typeof createRelayServer>[0];

function tmpDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

async function waitFor(cond: () => boolean, timeoutMs = 5000): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeoutMs) throw new Error("timed out waiting for condition");
    await new Promise((r) => setTimeout(r, 10));
  }
}

const ITEM = {
  id: "wm-item-1",
  payload: Buffer.from("hello"),
  targetUrl: "http://localhost:9999/hook",
  headers: { "content-type": "application/json" },
};

describe("DeliveryWatermark (unit)", () => {
  it("assigns per-endpoint monotonic ingress seqs starting at 1", () => {
    const w = new DeliveryWatermark(tmpDir("wm-"));
    assert.equal(w.assign("e1"), 1);
    assert.equal(w.assign("e1"), 2);
    assert.equal(w.assign("e1"), 3);
    // A second endpoint has its own independent counter.
    assert.equal(w.assign("e2"), 1);
    assert.deepEqual(w.getWatermarkStats(), [
      { endpoint: "e1", ingressSeq: 3, watermark: 0, lag: 3 },
      { endpoint: "e2", ingressSeq: 1, watermark: 0, lag: 1 },
    ]);
  });

  it("advances the watermark by the consecutive prefix on out-of-order delivery", () => {
    const w = new DeliveryWatermark(tmpDir("wm-"));
    w.assign("e1");
    w.assign("e1");
    w.assign("e1");
    // Out-of-order arrivals buffer without moving the watermark.
    assert.equal(w.markDelivered("e1", 2), false);
    assert.equal(w.markDelivered("e1", 3), false);
    assert.deepEqual(w.getWatermarkStats(), [
      { endpoint: "e1", ingressSeq: 3, watermark: 0, lag: 3 },
    ]);
    // The missing head closes the gap: 1, 2, 3 all become consecutive.
    assert.equal(w.markDelivered("e1", 1), true);
    assert.deepEqual(w.getWatermarkStats(), [
      { endpoint: "e1", ingressSeq: 3, watermark: 3, lag: 0 },
    ]);
  });

  it("computes lag as received minus watermark", () => {
    const w = new DeliveryWatermark(tmpDir("wm-"));
    w.assign("e1");
    w.assign("e1");
    w.assign("e1");
    w.markDelivered("e1", 1);
    assert.deepEqual(w.getWatermarkStats(), [
      { endpoint: "e1", ingressSeq: 3, watermark: 1, lag: 2 },
    ]);
  });

  it("is idempotent and never regresses the watermark", () => {
    const w = new DeliveryWatermark(tmpDir("wm-"));
    w.assign("e1");
    w.assign("e1");
    assert.equal(w.markDelivered("e1", 1), true);
    assert.equal(w.markDelivered("e1", 2), true);
    // Duplicate confirmation: already counted, watermark untouched.
    assert.equal(w.markDelivered("e1", 1), false);
    assert.equal(w.markDelivered("e1", 2), false);
    assert.deepEqual(w.getWatermarkStats(), [
      { endpoint: "e1", ingressSeq: 2, watermark: 2, lag: 0 },
    ]);
  });

  it("rejects invalid seqs without touching state", () => {
    const w = new DeliveryWatermark(tmpDir("wm-"));
    w.assign("e1");
    assert.equal(w.markDelivered("e1", 0), false);
    assert.equal(w.markDelivered("e1", -1), false);
    assert.equal(w.markDelivered("e1", 1.5), false);
    assert.equal(w.markDelivered("e1", Number.NaN), false);
    assert.deepEqual(w.getWatermarkStats(), [
      { endpoint: "e1", ingressSeq: 1, watermark: 0, lag: 1 },
    ]);
  });

  it("recovers state across restarts from the journal", () => {
    const dir = tmpDir("wm-");
    const w1 = new DeliveryWatermark(dir);
    w1.assign("e1");
    w1.assign("e1");
    w1.assign("e1");
    w1.assign("e2");
    w1.markDelivered("e1", 2);
    w1.markDelivered("e1", 3);
    w1.markDelivered("e2", 1);
    // Simulate a crash before seq 1 of e1 is confirmed: the out-of-order
    // buffer must survive the restart.
    const w2 = new DeliveryWatermark(dir);
    assert.deepEqual(w2.getWatermarkStats(), [
      { endpoint: "e1", ingressSeq: 3, watermark: 0, lag: 3 },
      { endpoint: "e2", ingressSeq: 1, watermark: 1, lag: 0 },
    ]);
    w2.markDelivered("e1", 1);
    assert.deepEqual(w2.getWatermarkStats(), [
      { endpoint: "e1", ingressSeq: 3, watermark: 3, lag: 0 },
      { endpoint: "e2", ingressSeq: 1, watermark: 1, lag: 0 },
    ]);
    // Assignment stays monotonic across the restart.
    assert.equal(w2.assign("e1"), 4);
  });

  it("skips corrupt journal lines on recovery and counts them", () => {
    const dir = tmpDir("wm-");
    const w1 = new DeliveryWatermark(dir);
    w1.assign("e1");
    w1.markDelivered("e1", 1);
    appendFileSync(
      join(dir, WATERMARK_JOURNAL_FILE),
      "this is not json\n{\"v\":999,\"t\":\"assigned\",\"e\":\"e1\",\"seq\":99}\n{\"v\":1,\"t\":\"bogus\"}\n"
    );
    const w2 = new DeliveryWatermark(dir);
    assert.equal(w2.getSkippedLines(), 3);
    assert.deepEqual(w2.getWatermarkStats(), [
      { endpoint: "e1", ingressSeq: 1, watermark: 1, lag: 0 },
    ]);
  });

  it("recovers the same state through a compaction snapshot", () => {
    const dir = tmpDir("wm-");
    const w1 = new DeliveryWatermark(dir);
    w1.assign("e1");
    w1.assign("e1");
    w1.assign("e1");
    w1.markDelivered("e1", 1);
    w1.markDelivered("e1", 3); // buffered out-of-order, must survive compaction
    w1.compactNow();
    const w2 = new DeliveryWatermark(dir);
    assert.deepEqual(w2.getWatermarkStats(), w1.getWatermarkStats());
    assert.equal(w2.assign("e1"), 4);
    // The buffered seq 3 is still remembered: delivering 2 advances to 3.
    assert.equal(w2.markDelivered("e1", 2), true);
    assert.deepEqual(w2.getWatermarkStats(), [
      { endpoint: "e1", ingressSeq: 4, watermark: 3, lag: 1 },
    ]);
  });

  it("keeps future assigns monotonic when a delivery arrives for an unknown endpoint", () => {
    const w = new DeliveryWatermark(tmpDir("wm-"));
    w.markDelivered("fresh", 5);
    // The assignment cursor fast-forwards past the confirmed seq so the
    // next assign can never collide with it.
    assert.equal(w.assign("fresh"), 6);
  });

  it("throws RangeError on an invalid dir", () => {
    assert.throws(() => new DeliveryWatermark(""), RangeError);
    assert.throws(() => new DeliveryWatermark(123 as unknown as string), RangeError);
  });
});

describe("RetryQueue delivery watermark integration", () => {
  it("is disabled by default (backward compatible)", async () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      assert.equal(q.isWatermarkEnabled(), false);
      assert.deepEqual(q.getWatermarkStats(), []);
      q.start();
      q.enqueue({ ...ITEM });
      await waitFor(() => q.pendingCount() === 0);
      // No ingress seq stamped, no watermark tracked.
      assert.deepEqual(q.getWatermarkStats(), []);
    } finally {
      q.stop();
    }
  });

  it("throws RangeError on an invalid watermarkDir", () => {
    assert.throws(() => new RetryQueue({ watermarkDir: "" }), RangeError);
    assert.throws(() => new RetryQueue({ watermarkDir: 42 as unknown as string }), RangeError);
  });

  it("stamps ingress seqs and advances the watermark on delivery end to end", async () => {
    const dir = tmpDir("wm-");
    const delivered: string[] = [];
    const sender: Sender = async (item) => {
      delivered.push(item.id);
    };
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 100,
      jitterMs: 0,
      maxAttempts: 3,
      watermarkDir: dir,
    });
    try {
      assert.equal(q.isWatermarkEnabled(), true);
      q.start();
      q.enqueue({ ...ITEM, id: "a" });
      q.enqueue({ ...ITEM, id: "b" });
      await waitFor(() => q.pendingCount() === 0);
      assert.deepEqual(delivered.sort(), ["a", "b"]);
      const stats = q.getWatermarkStats();
      assert.equal(stats.length, 1);
      assert.equal(stats[0].endpoint, ITEM.targetUrl);
      assert.equal(stats[0].ingressSeq, 2);
      assert.equal(stats[0].watermark, 2);
      assert.equal(stats[0].lag, 0);
    } finally {
      q.stop();
    }
  });

  it("does not advance the watermark for dead-lettered items", async () => {
    const dir = tmpDir("wm-");
    const q = new RetryQueue({
      sender: async () => {
        throw new Error("downstream down");
      },
      baseDelayMs: 10,
      maxDelayMs: 100,
      jitterMs: 0,
      maxAttempts: 1,
      watermarkDir: dir,
    });
    try {
      q.start();
      q.enqueue({ ...ITEM, id: "doomed" });
      await waitFor(() => q.getDeadLetter().length === 1);
      // Received but never confirmed: the watermark freezes, lag grows —
      // exactly the downstream-outage signal this module exists to show.
      assert.deepEqual(q.getWatermarkStats(), [
        { endpoint: ITEM.targetUrl, ingressSeq: 1, watermark: 0, lag: 1 },
      ]);
    } finally {
      q.stop();
    }
  });

  it("restores the watermark across a queue restart", async () => {
    const dir = tmpDir("wm-");
    const mk = () =>
      new RetryQueue({
        sender: async () => {},
        baseDelayMs: 10,
        maxDelayMs: 100,
        jitterMs: 0,
        watermarkDir: dir,
      });
    const q1 = mk();
    q1.start();
    q1.enqueue({ ...ITEM, id: "r1" });
    q1.enqueue({ ...ITEM, id: "r2" });
    await waitFor(() => q1.pendingCount() === 0);
    q1.stop();
    // "Restart": a fresh queue on the same dir recovers the watermark.
    const q2 = mk();
    try {
      assert.deepEqual(q2.getWatermarkStats(), [
        { endpoint: ITEM.targetUrl, ingressSeq: 2, watermark: 2, lag: 0 },
      ]);
      q2.start();
      q2.enqueue({ ...ITEM, id: "r3" });
      await waitFor(() => q2.pendingCount() === 0);
      assert.deepEqual(q2.getWatermarkStats(), [
        { endpoint: ITEM.targetUrl, ingressSeq: 3, watermark: 3, lag: 0 },
      ]);
    } finally {
      q2.stop();
    }
  });
});

describe("GET /watermarks (operator)", () => {
  function makeServer(partial: Partial<RelayOptions> & { sender: Sender }): Server {
    const dir = tmpDir("wm-srv-");
    const { sender, ...rest } = partial;
    return createRelayServer({
      secret: WEBHOOK_KEY,
      forwardUrl: FORWARD_URL,
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      operatorToken: TOKEN,
      ...rest,
      retry: { sender, baseDelayMs: 10, jitterMs: 0, maxAttempts: 3, ...(rest.retry ?? {}) },
    });
  }

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

  function get(port: number, path: string, headers: Record<string, string> = {}) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest({ host: "127.0.0.1", port, path, method: "GET", headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
      });
      r.on("error", reject);
      r.end();
    });
  }

  function post(port: number, path: string, body: Buffer, headers: Record<string, string> = {}) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest({ host: "127.0.0.1", port, path, method: "POST", headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
      });
      r.on("error", reject);
      r.end(body);
    });
  }

  const auth = { authorization: `Bearer ${TOKEN}` };

  it("is guarded like the other operator endpoints (404 fail-closed, 403 on bad bearer)", async () => {
    // No operatorToken at all: fail closed with 404.
    const dir = tmpDir("wm-srv-");
    const disabled = createRelayServer({
      secret: WEBHOOK_KEY,
      forwardUrl: FORWARD_URL,
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      watermarkDir: tmpDir("wm-"),
      retry: { sender: async () => {} },
    });
    const p0 = await listen(disabled);
    try {
      assert.equal((await get(p0, "/watermarks", auth)).status, 404);
    } finally {
      await close(disabled);
    }

    const relay = makeServer({ sender: async () => {}, watermarkDir: tmpDir("wm-") });
    const port = await listen(relay);
    try {
      assert.equal((await get(port, "/watermarks")).status, 403);
      assert.equal((await get(port, "/watermarks", { authorization: "Bearer wrong" })).status, 403);
      assert.equal((await get(port, "/watermarks", auth)).status, 200);
    } finally {
      await close(relay);
    }
  });

  it("404s when the watermark is not configured (without leaking existence)", async () => {
    const relay = makeServer({ sender: async () => {} });
    const port = await listen(relay);
    try {
      const res = await get(port, "/watermarks", auth);
      assert.equal(res.status, 404);
      assert.deepEqual(JSON.parse(res.text), { error: "delivery watermark is not configured" });
    } finally {
      await close(relay);
    }
  });

  it("serves the watermark snapshot end to end", async () => {
    const relay = makeServer({ sender: async () => {}, watermarkDir: tmpDir("wm-") });
    const port = await listen(relay);
    try {
      const posted = await post(port, "/", BODY, { "x-signature": signSha256(BODY, WEBHOOK_KEY) });
      assert.equal(posted.status, 202);

      let ready = false;
      const start = Date.now();
      while (!ready) {
        if (Date.now() - start > 5000) throw new Error("timed out waiting for watermark");
        const res = await get(port, "/watermarks", auth);
        if (res.status === 200) {
          const rows = JSON.parse(res.text) as Array<{
            endpoint: string;
            ingressSeq: number;
            watermark: number;
            lag: number;
          }>;
          ready = rows.some((r) => r.endpoint === FORWARD_URL && r.watermark >= 1);
        }
        if (!ready) await new Promise((r) => setTimeout(r, 10));
      }

      const res = await get(port, "/watermarks", auth);
      assert.equal(res.status, 200);
      const rows = JSON.parse(res.text) as Array<Record<string, unknown>>;
      assert.equal(rows.length, 1);
      const row = rows[0];
      assert.equal(row.endpoint, FORWARD_URL);
      assert.equal(row.ingressSeq, 1);
      assert.equal(row.watermark, 1);
      assert.equal(row.lag, 0);
      assert.deepEqual(Object.keys(row).sort(), ["endpoint", "ingressSeq", "lag", "watermark"]);
    } finally {
      await close(relay);
    }
  });
});
