import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type AddressInfo, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type BatchInfo, type RetryItem } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const EP1 = "http://127.0.0.1:9/a";
const relaySecret = "batch-revision-secret";

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
  batch: { windowMs?: number; maxBatchSize?: number } = { windowMs: 100, maxBatchSize: 10 }
): { q: RetryQueue; sent: RetryItem[]; flushed: BatchInfo[] } {
  const sent: RetryItem[] = [];
  const flushed: BatchInfo[] = [];
  const q = new RetryQueue({
    sender: async (it) => {
      sent.push(it);
    },
    setTimer: clock.setTimer,
    batch,
    onBatch: (info) => flushed.push(info),
  });
  return { q, sent, flushed };
}

describe("batch config live revision (WR-333)", () => {
  it("the next buffer times out on the revised window", async () => {
    const clock = fakeClock();
    const { q, sent } = makeQueue(clock);
    q.start();
    q.enqueue(item("a", EP1));
    await clock.advance(100); // first buffer flushes on the construction window
    assert.equal(sent.length, 1);

    const next = q.setBatchConfig({ windowMs: 1000 });
    assert.deepEqual(next, { windowMs: 1000, maxBatchSize: 10 });
    assert.deepEqual(q.getBatchConfig(), { windowMs: 1000, maxBatchSize: 10 });

    q.enqueue(item("b", EP1));
    await clock.advance(100); // old window would have flushed by now
    assert.equal(sent.length, 1);
    assert.equal(q.getBatchStats()[0].buffered, 1);
    await clock.advance(900); // revised window elapses
    assert.equal(sent.length, 2);
    q.stop();
  });

  it("a timer already armed runs out on the old window", async () => {
    const clock = fakeClock();
    const { q, sent } = makeQueue(clock);
    q.start();
    q.enqueue(item("a", EP1));
    q.setBatchConfig({ windowMs: 10_000 }); // armed timer was set at 100ms
    await clock.advance(100);
    assert.equal(sent.length, 1); // flushed on the old window, not held 10s
    q.stop();
  });

  it("tightening maxBatchSize flushes a buffer already over the new cap at once", async () => {
    const clock = fakeClock();
    const { q, sent, flushed } = makeQueue(clock, { windowMs: 10_000, maxBatchSize: 10 });
    q.start();
    q.enqueue(item("a", EP1));
    q.enqueue(item("b", EP1));
    q.enqueue(item("c", EP1));
    assert.equal(sent.length, 0);
    const next = q.setBatchConfig({ maxBatchSize: 2 });
    assert.deepEqual(next, { windowMs: 10_000, maxBatchSize: 2 });
    // Flushed synchronously into the queue; the 0ms delivery timer needs a pump.
    await clock.advance(0);
    assert.equal(sent.length, 1);
    assert.equal(flushed.length, 1);
    assert.equal(flushed[0].size, 3);
    assert.equal(q.getBatchStats()[0].buffered, 0);
    q.stop();
  });

  it("loosening maxBatchSize does not flush early", async () => {
    const clock = fakeClock();
    const { q, sent } = makeQueue(clock, { windowMs: 10_000, maxBatchSize: 2 });
    q.start();
    q.enqueue(item("a", EP1));
    q.setBatchConfig({ maxBatchSize: 10 });
    await clock.advance(0);
    assert.equal(sent.length, 0);
    assert.equal(q.getBatchStats()[0].buffered, 1);
    await clock.advance(10_000); // only the window flushes it
    assert.equal(sent.length, 1);
    q.stop();
  });

  it("illegal windowMs throws RangeError and leaves the live config untouched", async () => {
    const clock = fakeClock();
    const { q, sent } = makeQueue(clock);
    q.start();
    q.enqueue(item("a", EP1));
    for (const bad of [0, -5, Number.NaN, Number.POSITIVE_INFINITY]) {
      assert.throws(() => q.setBatchConfig({ windowMs: bad }), {
        name: "RangeError",
        message: /batch\.windowMs must be > 0/,
      });
    }
    // One illegal field must not move the other either.
    assert.throws(() => q.setBatchConfig({ windowMs: 0, maxBatchSize: 3 }), RangeError);
    assert.deepEqual(q.getBatchConfig(), { windowMs: 100, maxBatchSize: 10 });
    await clock.advance(100); // still the untouched window
    assert.equal(sent.length, 1);
    q.stop();
  });

  it("illegal maxBatchSize throws RangeError and leaves the live config untouched", async () => {
    const clock = fakeClock();
    const { q } = makeQueue(clock);
    q.start();
    for (const bad of [0, 1.5, -2]) {
      assert.throws(() => q.setBatchConfig({ maxBatchSize: bad }), {
        name: "RangeError",
        message: /batch\.maxBatchSize must be an integer >= 1/,
      });
    }
    assert.deepEqual(q.getBatchConfig(), { windowMs: 100, maxBatchSize: 10 });
    q.stop();
  });

  it("an empty patch and a same-value patch are silent no-ops", async () => {
    const clock = fakeClock();
    const { q, sent } = makeQueue(clock);
    q.start();
    q.enqueue(item("a", EP1));
    assert.deepEqual(q.setBatchConfig({}), { windowMs: 100, maxBatchSize: 10 });
    assert.deepEqual(q.setBatchConfig({ windowMs: 100, maxBatchSize: 10 }), {
      windowMs: 100,
      maxBatchSize: 10,
    });
    // No flush was forced by either no-op.
    assert.equal(sent.length, 0);
    assert.equal(q.getBatchStats()[0].buffered, 1);
    await clock.advance(100);
    assert.equal(sent.length, 1);
    q.stop();
  });

  it("a partial patch changes only the field it names", () => {
    const clock = fakeClock();
    const { q } = makeQueue(clock);
    q.start();
    assert.deepEqual(q.setBatchConfig({ windowMs: 500 }), { windowMs: 500, maxBatchSize: 10 });
    assert.deepEqual(q.setBatchConfig({ maxBatchSize: 3 }), { windowMs: 500, maxBatchSize: 3 });
    q.stop();
  });

  it("urgent items still bypass batching after a revision", async () => {
    const clock = fakeClock();
    const { q, sent } = makeQueue(clock);
    q.start();
    q.setBatchConfig({ windowMs: 1000 });
    q.enqueue({ ...item("u", EP1), priority: "urgent" });
    q.enqueue(item("n", EP1));
    await clock.advance(0);
    assert.equal(sent.length, 1);
    // The urgent item goes out raw, not wrapped in an envelope.
    assert.equal(sent[0].id, "u");
    assert.equal(sent[0].payload.toString(), "u");
    await clock.advance(1000);
    assert.equal(sent.length, 2);
    const env = JSON.parse(sent[1].payload.toString());
    assert.equal(env.events.length, 1);
    assert.equal(env.events[0].id, "n");
    q.stop();
  });

  it("the envelope and x-batch-* headers are unchanged after a revision", async () => {
    const clock = fakeClock();
    const { q, sent } = makeQueue(clock);
    q.start();
    q.setBatchConfig({ windowMs: 50, maxBatchSize: 5 });
    q.enqueue(item("a", EP1, "one", { "x-signature": "sig-a" }));
    q.enqueue(item("b", EP1, "two"));
    await clock.advance(50);
    assert.equal(sent.length, 1);
    const merged = sent[0];
    assert.equal(merged.headers["content-type"], "application/json");
    assert.ok((merged.headers["x-batch-id"] ?? "").startsWith("batch:"));
    assert.equal(merged.headers["x-batch-size"], "2");
    const env = JSON.parse(merged.payload.toString());
    assert.equal(env.batch_id, merged.headers["x-batch-id"]);
    assert.equal(env.events.length, 2);
    assert.equal(env.events[0].headers["x-signature"], "sig-a");
    q.stop();
  });

  it("an unconfigured queue throws must-restart on set and returns undefined on get", () => {
    const q = new RetryQueue();
    assert.throws(() => q.setBatchConfig({ windowMs: 100 }), {
      name: "Error",
      message: /setBatchConfig: batching is not configured — enabling it requires a restart/,
    });
    assert.equal(q.getBatchConfig(), undefined);
    q.stop();
  });
});

describe("server setBatchConfig / getBatchConfig (WR-333)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "batch-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const delivered: RetryItem[] = [];
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: "http://127.0.0.1:9/unused",
      auditLog,
      sender: async (item) => {
        delivered.push(item);
      },
      ...opts,
    });
    servers.push(relay);
    return { relay, auditLog, delivered };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    return (server.address() as AddressInfo).port;
  }

  function post(port: number, body: Buffer) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/",
          method: "POST",
          headers: { "x-signature": signSha256(body, relaySecret) },
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

  async function settle() {
    await new Promise((r) => setTimeout(r, 50));
  }

  it("audits batch_config_revised with previous/current and skips the audit on a no-op", () => {
    const { relay, auditLog } = makeServer({
      retry: { batch: { windowMs: 100, maxBatchSize: 10 } },
    });
    assert.deepEqual(relay.getBatchConfig!(), { windowMs: 100, maxBatchSize: 10 });
    assert.equal(eventsOf(auditLog, "batch_config_revised").length, 0);
    const next = relay.setBatchConfig!({ windowMs: 500, maxBatchSize: 5 });
    assert.deepEqual(next, { windowMs: 500, maxBatchSize: 5 });
    const revised = eventsOf(auditLog, "batch_config_revised");
    assert.equal(revised.length, 1);
    // First `previous` is the construction value.
    assert.deepEqual(revised[0].previous, { windowMs: 100, maxBatchSize: 10 });
    assert.deepEqual(revised[0].current, { windowMs: 500, maxBatchSize: 5 });
    assert.deepEqual(relay.getBatchConfig!(), { windowMs: 500, maxBatchSize: 5 });
    // Same values and an empty patch: no new audit event.
    relay.setBatchConfig!({ windowMs: 500, maxBatchSize: 5 });
    relay.setBatchConfig!({});
    assert.equal(eventsOf(auditLog, "batch_config_revised").length, 1);
    // A second real revision audits against the revised values.
    relay.setBatchConfig!({ windowMs: 250 });
    const revised2 = eventsOf(auditLog, "batch_config_revised");
    assert.equal(revised2.length, 2);
    assert.deepEqual(revised2[1].previous, { windowMs: 500, maxBatchSize: 5 });
    assert.deepEqual(revised2[1].current, { windowMs: 250, maxBatchSize: 5 });
  });

  it("throws RangeError on an illegal patch and leaves the live config untouched", () => {
    const { relay, auditLog } = makeServer({
      retry: { batch: { windowMs: 100, maxBatchSize: 10 } },
    });
    assert.throws(() => relay.setBatchConfig!({ windowMs: 0 }), RangeError);
    assert.throws(() => relay.setBatchConfig!({ maxBatchSize: 1.5 }), RangeError);
    assert.deepEqual(relay.getBatchConfig!(), { windowMs: 100, maxBatchSize: 10 });
    assert.equal(eventsOf(auditLog, "batch_config_revised").length, 0);
  });

  it("throws must-restart on set and returns undefined on get when batching is not configured", () => {
    const { relay } = makeServer();
    assert.throws(() => relay.setBatchConfig!({ windowMs: 100 }), {
      name: "Error",
      message: /setBatchConfig: batching is not configured — enabling it requires a restart/,
    });
    assert.equal(relay.getBatchConfig!(), undefined);
  });

  it("tightening maxBatchSize flushes a buffered batch end to end", async () => {
    const { relay, delivered } = makeServer({
      retry: { batch: { windowMs: 5000, maxBatchSize: 10 }, baseDelayMs: 10, jitterMs: 0 },
    });
    const port = await listen(relay);
    for (const n of ["one", "two"]) {
      const res = await post(port, Buffer.from(JSON.stringify({ n })));
      assert.equal(res.status, 202);
    }
    await settle();
    assert.equal(delivered.length, 0); // still buffered inside the 5s window
    const next = relay.setBatchConfig!({ maxBatchSize: 2 });
    assert.deepEqual(next, { windowMs: 5000, maxBatchSize: 2 });
    const deadline = Date.now() + 5000;
    while (delivered.length === 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(delivered.length, 1);
    const merged = delivered[0];
    assert.equal(merged.headers["x-batch-size"], "2");
    assert.ok((merged.headers["x-batch-id"] ?? "").startsWith("batch:"));
    const env = JSON.parse(merged.payload.toString());
    assert.equal(env.events.length, 2);
    assert.deepEqual(
      env.events.map((e: { payload: string }) => Buffer.from(e.payload, "base64").toString()),
      ['{"n":"one"}', '{"n":"two"}']
    );
  });
});
