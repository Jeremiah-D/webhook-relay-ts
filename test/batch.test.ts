import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type AddressInfo, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type BatchInfo, type RetryItem } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const EP1 = "http://127.0.0.1:9/a";
const EP2 = "http://127.0.0.1:9/b";

/** Clock-aware fake timer: `advance(ms)` fires due callbacks in order. */
function fakeClock() {
  let now = 0;
  const pending: Array<{ at: number; fn: () => void; cleared: boolean }> = [];
  const setTimer = (fn: () => void, ms: number) => {
    const job = { at: now + ms, fn, cleared: false };
    pending.push(job);
    return {
      clear: () => {
        job.cleared = true;
      },
    };
  };
  async function advance(ms: number) {
    const target = now + ms;
    for (;;) {
      let next: (typeof pending)[number] | undefined;
      for (const j of pending) {
        if (!j.cleared && j.at <= target && (!next || j.at < next.at)) next = j;
      }
      if (!next) break;
      pending.splice(pending.indexOf(next), 1);
      now = next.at;
      next.fn();
      // Let the async delivery pipeline settle before the next timer.
      await new Promise((r) => setImmediate(r));
    }
    now = target;
    for (let i = pending.length - 1; i >= 0; i--) {
      if (pending[i].cleared) pending.splice(i, 1);
    }
  }
  return { setTimer, advance, now: () => now };
}

function item(
  id: string,
  targetUrl: string,
  payload = id,
  headers: Record<string, string> = {}
): RetryItem {
  return { id, payload: Buffer.from(payload), targetUrl, headers };
}

function makeQueue(
  clock: ReturnType<typeof fakeClock>,
  opts: ConstructorParameters<typeof RetryQueue>[0] = {}
): { q: RetryQueue; sent: RetryItem[]; flushed: BatchInfo[] } {
  const sent: RetryItem[] = [];
  const flushed: BatchInfo[] = [];
  const q = new RetryQueue({
    sender: async (it) => {
      sent.push(it);
    },
    setTimer: clock.setTimer,
    batch: { windowMs: 100, maxBatchSize: 10 },
    onBatch: (info) => flushed.push(info),
    ...opts,
  });
  return { q, sent, flushed };
}

describe("batch delivery merging", () => {
  it("merges same-endpoint items inside the window into one delivery", async () => {
    const clock = fakeClock();
    const { q, sent, flushed } = makeQueue(clock);
    q.start();
    q.enqueue(item("a", EP1, "one", { "x-signature": "sig-a" }));
    q.enqueue(item("b", EP1, "two"));
    q.enqueue(item("c", EP1, "three"));
    assert.equal(sent.length, 0);
    assert.deepEqual(q.getBatchStats(), [{ endpoint: EP1, batches: 0, events: 0, buffered: 3 }]);
    await clock.advance(100);
    assert.equal(sent.length, 1);
    assert.equal(flushed.length, 1);
    assert.equal(flushed[0].endpoint, EP1);
    assert.equal(flushed[0].size, 3);
    assert.ok(flushed[0].batchId.startsWith("batch:"));

    const merged = sent[0];
    assert.equal(merged.id, flushed[0].batchId);
    assert.equal(merged.targetUrl, EP1);
    assert.equal(merged.headers["content-type"], "application/json");
    assert.equal(merged.headers["x-batch-id"], flushed[0].batchId);
    assert.equal(merged.headers["x-batch-size"], "3");

    const env = JSON.parse(merged.payload.toString());
    assert.equal(env.batch_id, flushed[0].batchId);
    assert.match(env.batched_at, /^\d{4}-\d{2}-\d{2}T/);
    assert.equal(env.events.length, 3);
    // Arrival order is preserved.
    assert.equal(env.events[0].id, "a");
    assert.equal(Buffer.from(env.events[0].payload, "base64").toString(), "one");
    assert.equal(env.events[0].payload_bytes, 3);
    // Per-event headers ride inside the envelope (each event's own signature).
    assert.equal(env.events[0].headers["x-signature"], "sig-a");
    assert.equal(Buffer.from(env.events[2].payload, "base64").toString(), "three");

    assert.deepEqual(q.getBatchStats(), [{ endpoint: EP1, batches: 1, events: 3, buffered: 0 }]);
    q.stop();
  });

  it("keeps endpoints separate", async () => {
    const clock = fakeClock();
    const { q, sent } = makeQueue(clock);
    q.start();
    q.enqueue(item("a", EP1));
    q.enqueue(item("b", EP2));
    await clock.advance(100);
    assert.equal(sent.length, 2);
    for (const s of sent) {
      const env = JSON.parse(s.payload.toString());
      assert.equal(env.events.length, 1);
    }
    q.stop();
  });

  it("flushes early when maxBatchSize is reached", async () => {
    const clock = fakeClock();
    const { q, sent, flushed } = makeQueue(clock, { batch: { windowMs: 10_000, maxBatchSize: 2 } });
    q.start();
    q.enqueue(item("a", EP1));
    assert.equal(sent.length, 0);
    q.enqueue(item("b", EP1));
    // Flushed synchronously into the queue; the 0ms delivery timer needs a pump.
    await clock.advance(0);
    assert.equal(sent.length, 1);
    assert.equal(flushed.length, 1);
    assert.equal(flushed[0].size, 2);
    assert.equal(q.getBatchStats()[0].batches, 1);
    q.stop();
  });

  it("urgent items bypass batching", async () => {
    const clock = fakeClock();
    const { q, sent } = makeQueue(clock);
    q.start();
    q.enqueue({ ...item("u", EP1), priority: "urgent" });
    q.enqueue(item("n", EP1));
    await clock.advance(0);
    assert.equal(sent.length, 1);
    // The urgent item goes out raw, not wrapped in an envelope.
    assert.equal(sent[0].id, "u");
    assert.equal(sent[0].payload.toString(), "u");
    await clock.advance(100);
    assert.equal(sent.length, 2);
    // Uniform contract: even a lone normal item is wrapped.
    const env = JSON.parse(sent[1].payload.toString());
    assert.equal(env.events.length, 1);
    assert.equal(env.events[0].id, "n");
    q.stop();
  });

  it("supports a custom envelope", async () => {
    const clock = fakeClock();
    const { q, sent } = makeQueue(clock, {
      batch: {
        windowMs: 50,
        envelope: ({ batchId, items }) => Buffer.from(`${batchId}:${items.map((i) => i.id).join(",")}`),
      },
    });
    q.start();
    q.enqueue(item("a", EP1));
    q.enqueue(item("b", EP1));
    await clock.advance(50);
    assert.equal(sent.length, 1);
    assert.match(sent[0].payload.toString(), /^batch:[0-9a-f-]+:a,b$/);
    q.stop();
  });

  it("retries the whole batch as one unit", async () => {
    const clock = fakeClock();
    const bodies: string[] = [];
    let attempts = 0;
    const { q, sent } = makeQueue(clock, {
      sender: async (it) => {
        attempts += 1;
        bodies.push(it.payload.toString());
        sent.push(it);
        if (attempts < 2) throw new Error("flaky downstream");
      },
      baseDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 3,
      batch: { windowMs: 50 },
    });
    q.start();
    q.enqueue(item("a", EP1, "one"));
    q.enqueue(item("b", EP1, "two"));
    await clock.advance(50); // flush; first attempt fails
    assert.equal(attempts, 1);
    await clock.advance(1000); // backoff 20ms; retry succeeds with the identical batch body
    assert.equal(attempts, 2);
    assert.equal(bodies[0], bodies[1]);
    assert.equal(q.pendingCount(), 0);
    q.stop();
  });

  it("a dead-lettered batch keeps the merged envelope for replay", async () => {
    const clock = fakeClock();
    const { q } = makeQueue(clock, {
      sender: async () => {
        throw new Error("always down");
      },
      baseDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 2,
      batch: { windowMs: 50 },
    });
    q.start();
    q.enqueue(item("a", EP1, "one"));
    q.enqueue(item("b", EP1, "two"));
    await clock.advance(50); // flush + attempt 1
    await clock.advance(1000); // backoff + attempt 2 -> dead letter
    const dead = q.getDeadLetter();
    assert.equal(dead.length, 1);
    assert.ok(dead[0].id.startsWith("batch:"));
    const env = JSON.parse(dead[0].payload.toString());
    assert.equal(env.events.length, 2);
    q.stop();
  });

  it("rejects invalid batch options", () => {
    assert.throws(() => new RetryQueue({ batch: { windowMs: 0 } }), RangeError);
    assert.throws(() => new RetryQueue({ batch: { windowMs: -5 } }), RangeError);
    assert.throws(() => new RetryQueue({ batch: { maxBatchSize: 0 } }), RangeError);
    assert.throws(() => new RetryQueue({ batch: { maxBatchSize: 1.5 } }), RangeError);
  });

  it("rejects a duplicate id while the first is still buffered", () => {
    const clock = fakeClock();
    const { q } = makeQueue(clock);
    q.start();
    q.enqueue(item("a", EP1));
    assert.throws(() => q.enqueue(item("a", EP1)), /Duplicate item id/);
    q.stop();
  });

  it("stop() flushes pending batches into the queue without delivering", async () => {
    const clock = fakeClock();
    const { q, sent } = makeQueue(clock, { batch: { windowMs: 10_000 } });
    q.start();
    q.enqueue(item("a", EP1));
    q.enqueue(item("b", EP1));
    q.stop();
    assert.equal(sent.length, 0);
    assert.equal(q.pendingCount(), 1); // one merged batch item, queued but unscheduled
    q.start();
    await clock.advance(0);
    assert.equal(sent.length, 1);
    q.stop();
  });

  it("shutdown() gives buffered batches one immediate attempt before draining", async () => {
    const clock = fakeClock();
    const { q, sent } = makeQueue(clock, { batch: { windowMs: 10_000 } });
    q.start();
    q.enqueue(item("a", EP1, "one"));
    q.enqueue(item("b", EP1, "two"));
    const drained = await q.shutdown(1000);
    assert.equal(drained, true);
    assert.equal(sent.length, 1);
    const env = JSON.parse(sent[0].payload.toString());
    assert.equal(env.events.length, 2);
    assert.equal(q.pendingCount(), 0);
    q.stop();
  });

  it("getBatchStats is empty when batching is disabled", () => {
    const q = new RetryQueue();
    assert.deepEqual(q.getBatchStats(), []);
    q.stop();
  });
});

describe("batch server integration", () => {
  const SECRET = "batch-secret";

  function post(port: number, body: Buffer) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/",
          method: "POST",
          headers: { "x-signature": signSha256(body, SECRET) },
        },
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

  it("merges inbound webhooks into one downstream request and audits the flush", async () => {
    const received: Buffer[] = [];
    const stub = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        received.push(Buffer.concat(chunks));
        res.writeHead(200).end("ok");
      });
    });
    await new Promise<void>((resolve) => stub.listen(0, "127.0.0.1", resolve));
    const stubPort = (stub.address() as AddressInfo).port;

    const dir = mkdtempSync(join(tmpdir(), "batch-audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      operatorToken: "op",
      retry: { batch: { windowMs: 80, maxBatchSize: 10 }, baseDelayMs: 10, jitterMs: 0 },
    });
    await new Promise<void>((resolve) => relay.listen(0, "127.0.0.1", resolve));
    const port = (relay.address() as AddressInfo).port;

    const close = async (s: Server) => {
      s.close();
      await new Promise((r) => s.once("close", r));
    };
    try {
      for (const n of ["one", "two", "three"]) {
        const res = await post(port, Buffer.from(JSON.stringify({ n })));
        assert.equal(res.status, 202);
      }
      const deadline = Date.now() + 5000;
      while (received.length === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      // Three inbound webhooks became a single downstream request.
      assert.equal(received.length, 1);
      const env = JSON.parse(received[0].toString());
      assert.equal(env.events.length, 3);
      assert.deepEqual(
        env.events.map((e: { payload: string }) => Buffer.from(e.payload, "base64").toString()),
        ['{"n":"one"}', '{"n":"two"}', '{"n":"three"}']
      );
      // The flush is audited for operators.
      const flushed = audit.query({ event: ["batch_flushed"] });
      assert.equal(flushed.length, 1);
      assert.equal((flushed[0] as { size: number }).size, 3);
      assert.ok(((flushed[0] as { batchId: string }).batchId ?? "").startsWith("batch:"));
    } finally {
      await close(relay);
      await close(stub);
    }
  });
});
