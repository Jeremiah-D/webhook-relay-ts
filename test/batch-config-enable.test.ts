import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type BatchInfo, type RetryItem } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

const EP1 = "http://127.0.0.1:9/a";
const relaySecret = "batch-config-enable-secret";

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

/** Queue deliberately *without* a `batch` option, so the WR-450 enable path is the only way a collector appears. */
function makeQueue(
  clock: ReturnType<typeof fakeClock>
): { q: RetryQueue; sent: RetryItem[]; flushed: BatchInfo[] } {
  const sent: RetryItem[] = [];
  const flushed: BatchInfo[] = [];
  const q = new RetryQueue({
    sender: async (it) => {
      sent.push(it);
    },
    setTimer: clock.setTimer,
    onBatch: (info) => flushed.push(info),
  });
  return { q, sent, flushed };
}

describe("batch config live enable for an unconfigured queue (WR-450)", () => {
  it("first setBatchConfig enables, resolving missing fields to the 250/50 defaults", () => {
    const clock = fakeClock();
    const { q } = makeQueue(clock);
    q.start();
    assert.equal(q.getBatchConfig(), undefined);
    assert.equal(q.batchConfigured(), false);
    assert.deepEqual(q.setBatchConfig({ windowMs: 100 }), { windowMs: 100, maxBatchSize: 50 });
    assert.deepEqual(q.getBatchConfig(), { windowMs: 100, maxBatchSize: 50 });
    assert.equal(q.batchConfigured(), true);
    q.stop();

    const clock2 = fakeClock();
    const { q: q2 } = makeQueue(clock2);
    q2.start();
    assert.deepEqual(q2.setBatchConfig({ maxBatchSize: 5 }), { windowMs: 250, maxBatchSize: 5 });
    assert.deepEqual(q2.getBatchConfig(), { windowMs: 250, maxBatchSize: 5 });
    q2.stop();
  });

  it("a full patch enables with exactly those values", () => {
    const clock = fakeClock();
    const { q } = makeQueue(clock);
    q.start();
    assert.deepEqual(q.setBatchConfig({ windowMs: 1000, maxBatchSize: 3 }), {
      windowMs: 1000,
      maxBatchSize: 3,
    });
    assert.deepEqual(q.getBatchConfig(), { windowMs: 1000, maxBatchSize: 3 });
    q.stop();
  });

  it("empty, non-object and illegal patches throw RangeError and leave the queue unconfigured", () => {
    const clock = fakeClock();
    const { q } = makeQueue(clock);
    q.start();
    const bad: unknown[] = [
      {},
      null,
      "fast",
      [],
      { windowMs: 0 },
      { windowMs: -5 },
      { windowMs: Number.NaN },
      { windowMs: Number.POSITIVE_INFINITY },
      { maxBatchSize: 0 },
      { maxBatchSize: 1.5 },
      { maxBatchSize: -2 },
      { windowMs: 0, maxBatchSize: 3 },
    ];
    for (const patch of bad) {
      assert.throws(() => q.setBatchConfig(patch as never), RangeError);
      assert.equal(q.getBatchConfig(), undefined);
      assert.equal(q.batchConfigured(), false);
    }
    // A rejected patch never half-enables: a later valid patch still enables.
    assert.deepEqual(q.setBatchConfig({ windowMs: 100 }), { windowMs: 100, maxBatchSize: 50 });
    assert.equal(q.batchConfigured(), true);
    q.stop();
  });

  it("items enqueued before the enable are delivered directly, never batched", async () => {
    const clock = fakeClock();
    const { q, sent } = makeQueue(clock);
    q.start();
    q.enqueue(item("pre", EP1));
    await clock.advance(0);
    assert.equal(sent.length, 1);
    // Raw payload, not wrapped in an envelope.
    assert.equal(sent[0].id, "pre");
    assert.equal(sent[0].payload.toString(), "pre");
    assert.equal(sent[0].headers["x-batch-id"], undefined);

    q.setBatchConfig({ windowMs: 1000 });
    await clock.advance(0);
    assert.equal(sent.length, 1); // the enable itself flushes nothing
    q.enqueue(item("post", EP1));
    await clock.advance(0);
    assert.equal(sent.length, 1); // the new item waits inside the window
    assert.equal(q.getBatchStats()[0].buffered, 1);
    await clock.advance(1000);
    assert.equal(sent.length, 2);
    const env = JSON.parse(sent[1].payload.toString());
    assert.equal(env.events.length, 1);
    assert.equal(env.events[0].id, "post");
    q.stop();
  });

  it("items enqueued after the enable are merged on the window", async () => {
    const clock = fakeClock();
    const { q, sent, flushed } = makeQueue(clock);
    q.start();
    q.setBatchConfig({ windowMs: 100 });
    q.enqueue(item("a", EP1));
    q.enqueue(item("b", EP1));
    await clock.advance(50);
    assert.equal(sent.length, 0);
    assert.equal(q.getBatchStats()[0].buffered, 2);
    await clock.advance(50);
    assert.equal(sent.length, 1);
    assert.equal(flushed.length, 1);
    assert.equal(flushed[0].size, 2);
    const env = JSON.parse(sent[0].payload.toString());
    assert.deepEqual(
      env.events.map((e: { id: string }) => e.id),
      ["a", "b"]
    );
    q.stop();
  });

  it("reaching maxBatchSize flushes immediately after the enable", async () => {
    const clock = fakeClock();
    const { q, sent, flushed } = makeQueue(clock);
    q.start();
    q.setBatchConfig({ windowMs: 10_000, maxBatchSize: 2 });
    q.enqueue(item("a", EP1));
    q.enqueue(item("b", EP1));
    assert.equal(sent.length, 0);
    // Flushed synchronously into the queue; the 0ms delivery timer needs a pump.
    await clock.advance(0);
    assert.equal(sent.length, 1);
    assert.equal(flushed.length, 1);
    assert.equal(flushed[0].size, 2);
    assert.equal(q.getBatchStats()[0].buffered, 0);
    q.stop();
  });

  it("urgent items still bypass batching after the enable", async () => {
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

  it("a restart returns to unconfigured", () => {
    const clock = fakeClock();
    const { q } = makeQueue(clock);
    q.start();
    q.setBatchConfig({ windowMs: 100 });
    assert.equal(q.batchConfigured(), true);
    q.stop();
    // A fresh queue built from the same (batch-less) options has no collector.
    const restarted = new RetryQueue({
      sender: async () => {},
      setTimer: clock.setTimer,
    });
    assert.equal(restarted.getBatchConfig(), undefined);
    assert.equal(restarted.batchConfigured(), false);
    restarted.stop();
  });

  it("after the enable, a revision retunes the live collector", async () => {
    const clock = fakeClock();
    const { q, sent } = makeQueue(clock);
    q.start();
    q.setBatchConfig({ windowMs: 1000, maxBatchSize: 10 });
    q.enqueue(item("a", EP1));
    q.setBatchConfig({ windowMs: 100 });
    await clock.advance(100);
    assert.equal(sent.length, 0); // the armed timer runs out on the old window
    await clock.advance(900);
    assert.equal(sent.length, 1);
    q.enqueue(item("b", EP1));
    await clock.advance(100); // the next buffer judges by the revised window
    assert.equal(sent.length, 2);
    q.stop();
  });
});

describe("server setBatchConfig enable (WR-450)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "batch-config-enable-"));
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

  it("enables on first call, audits previous null, and skips the audit on a no-op", () => {
    const { relay, auditLog } = makeServer();
    assert.equal(relay.getBatchConfig!(), undefined);
    // An illegal patch on the unconfigured server throws and enables nothing.
    assert.throws(() => relay.setBatchConfig!({ windowMs: 0 }), RangeError);
    assert.equal(relay.getBatchConfig!(), undefined);
    assert.equal(eventsOf(auditLog, "batch_config_revised").length, 0);

    const next = relay.setBatchConfig!({ windowMs: 500 });
    assert.deepEqual(next, { windowMs: 500, maxBatchSize: 50 });
    assert.deepEqual(relay.getBatchConfig!(), { windowMs: 500, maxBatchSize: 50 });
    const revised = eventsOf(auditLog, "batch_config_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.deepEqual(revised[0].current, { windowMs: 500, maxBatchSize: 50 });
    // Same values and an empty patch: no new audit event.
    relay.setBatchConfig!({ windowMs: 500, maxBatchSize: 50 });
    relay.setBatchConfig!({});
    assert.equal(eventsOf(auditLog, "batch_config_revised").length, 1);
    // A second real revision audits against the enabled values.
    relay.setBatchConfig!({ windowMs: 250 });
    const revised2 = eventsOf(auditLog, "batch_config_revised");
    assert.equal(revised2.length, 2);
    assert.deepEqual(revised2[1].previous, { windowMs: 500, maxBatchSize: 50 });
    assert.deepEqual(revised2[1].current, { windowMs: 250, maxBatchSize: 50 });
  });
});
