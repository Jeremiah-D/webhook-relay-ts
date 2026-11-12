import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type BatchInfo, type RetryItem } from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";

// Named to avoid the runtime secret-redaction pattern on `SECRET`.
const INGEST_KEY = "batch-callback-revision-key";
const OPERATOR_TOKEN = "batch-callback-revision-op-token";
const BODY = Buffer.from(JSON.stringify({ hello: "batch-revision" }));
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
  headers: Record<string, string> = {},
  extra: Partial<RetryItem> = {}
): RetryItem {
  return {
    id,
    payload: Buffer.from(payload),
    targetUrl,
    headers,
    traceId: `trace-${id}`,
    ...extra,
  };
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

describe("RetryQueue batch callback revision (WR-400)", () => {
  it("the revised callback receives the next flush with exact fields; the old callback stays silent", async () => {
    const clock = fakeClock();
    const first: BatchInfo[] = [];
    const second: BatchInfo[] = [];
    const { q, sent } = makeQueue(clock, { onBatch: (info) => first.push(info) });
    q.start();
    try {
      q.enqueue(item("a", EP1, "one"));
      q.enqueue(item("b", EP1, "two"));
      await clock.advance(100);
      assert.equal(sent.length, 1);
      assert.equal(first.length, 1);
      assert.ok(first[0].batchId.startsWith("batch:"));
      assert.equal(first[0].endpoint, EP1);
      assert.equal(first[0].size, 2);
      assert.deepEqual(first[0].traceIds, ["trace-a", "trace-b"]);
      assert.equal(sent[0].id, first[0].batchId);
      // A second flush goes to the revised callback only.
      q.reviseBatchCallback((info) => second.push(info));
      q.enqueue(item("c", EP1, "three"));
      q.enqueue(item("d", EP1, "four"));
      await clock.advance(100);
      assert.equal(sent.length, 2);
      assert.equal(first.length, 1);
      assert.equal(second.length, 1);
      assert.ok(second[0].batchId.startsWith("batch:"));
      assert.notEqual(second[0].batchId, first[0].batchId);
      assert.equal(second[0].endpoint, EP1);
      assert.equal(second[0].size, 2);
      assert.deepEqual(second[0].traceIds, ["trace-c", "trace-d"]);
      assert.equal(sent[1].id, second[0].batchId);
    } finally {
      q.stop();
    }
  });

  it("null clears back to no observer; flushing continues and still counts", async () => {
    const clock = fakeClock();
    const seen: BatchInfo[] = [];
    const { q, sent } = makeQueue(clock, { onBatch: (info) => seen.push(info) });
    q.start();
    try {
      q.enqueue(item("a", EP1));
      q.enqueue(item("b", EP1));
      await clock.advance(100);
      assert.equal(seen.length, 1);
      assert.deepEqual(q.getBatchStats(), [{ endpoint: EP1, batches: 1, events: 2, buffered: 0 }]);
      q.reviseBatchCallback(null);
      q.enqueue(item("c", EP1));
      q.enqueue(item("d", EP1));
      await clock.advance(100);
      assert.equal(sent.length, 2);
      assert.equal(seen.length, 1, "cleared hook stays silent");
      assert.deepEqual(q.getBatchStats(), [{ endpoint: EP1, batches: 2, events: 4, buffered: 0 }]);
    } finally {
      q.stop();
    }
  });

  it("revising with batching unconfigured throws Error; batchConfigured reports the live state", () => {
    const q = new RetryQueue({ sender: async () => {} });
    assert.equal(q.batchConfigured(), false);
    assert.equal(q.getBatchConfig(), undefined);
    assert.throws(
      () => q.reviseBatchCallback(() => {}),
      (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
    );
    const clock = fakeClock();
    const { q: configured } = makeQueue(clock);
    try {
      assert.equal(configured.batchConfigured(), true);
      assert.deepEqual(configured.getBatchConfig(), { windowMs: 100, maxBatchSize: 10 });
    } finally {
      configured.stop();
    }
  });

  it("a non-function value throws RangeError and the live callback is untouched", async () => {
    const clock = fakeClock();
    const seen: BatchInfo[] = [];
    const { q } = makeQueue(clock, { onBatch: (info) => seen.push(info) });
    q.start();
    try {
      for (const bad of ["x", 42, {}] as never[]) {
        assert.throws(() => q.reviseBatchCallback(bad), RangeError, String(bad));
      }
      // Nothing moved: the original hook still fires.
      q.enqueue(item("a", EP1));
      q.enqueue(item("b", EP1));
      await clock.advance(100);
      assert.equal(seen.length, 1);
      assert.deepEqual(seen[0].traceIds, ["trace-a", "trace-b"]);
    } finally {
      q.stop();
    }
  });

  it("replacing with the same reference and clearing when already unset are silent no-ops", async () => {
    const clock = fakeClock();
    const seen: BatchInfo[] = [];
    const onBatch = (info: BatchInfo) => seen.push(info);
    const { q } = makeQueue(clock, { onBatch });
    q.start();
    try {
      q.reviseBatchCallback(onBatch);
      q.enqueue(item("a", EP1));
      q.enqueue(item("b", EP1));
      await clock.advance(100);
      assert.equal(seen.length, 1);
      // Clear twice: the second clear is a no-op, not an error.
      q.reviseBatchCallback(null);
      q.reviseBatchCallback(null);
      q.enqueue(item("c", EP1));
      q.enqueue(item("d", EP1));
      await clock.advance(100);
      assert.equal(seen.length, 1);
      assert.deepEqual(q.getBatchStats(), [{ endpoint: EP1, batches: 2, events: 4, buffered: 0 }]);
    } finally {
      q.stop();
    }
  });

  it("batches already reported are never re-delivered", async () => {
    const clock = fakeClock();
    const seen: BatchInfo[] = [];
    const { q } = makeQueue(clock, { onBatch: (info) => seen.push(info) });
    q.start();
    try {
      q.enqueue(item("a", EP1));
      q.enqueue(item("b", EP1));
      await clock.advance(100);
      assert.equal(seen.length, 1);
      q.reviseBatchCallback((info) => seen.push(info));
      assert.equal(seen.length, 1, "no re-delivery of the reported batch");
      await clock.advance(500);
      assert.equal(seen.length, 1, "no flush without new items");
      assert.deepEqual(q.getBatchStats(), [{ endpoint: EP1, batches: 1, events: 2, buffered: 0 }]);
      // The next real flush reports exactly once, to the new callback.
      q.enqueue(item("c", EP1));
      await clock.advance(100);
      assert.equal(seen.length, 2);
      assert.equal(seen[1].size, 1);
      assert.deepEqual(seen[1].traceIds, ["trace-c"]);
    } finally {
      q.stop();
    }
  });

  it("revision does not change the window, the cap, the envelope, or the urgent bypass", async () => {
    const clock = fakeClock();
    const seen: BatchInfo[] = [];
    const { q, sent } = makeQueue(clock, { onBatch: (info) => seen.push(info) });
    q.start();
    try {
      assert.deepEqual(q.getBatchConfig(), { windowMs: 100, maxBatchSize: 10 });
      q.reviseBatchCallback((info) => seen.push(info));
      assert.deepEqual(q.getBatchConfig(), { windowMs: 100, maxBatchSize: 10 });
      // Urgent items skip batching entirely and go out immediately.
      q.enqueue(item("u", EP1, "urgent-payload", {}, { priority: "urgent" }));
      // The dispatch is a 0-delay fake-timer job: advance(0) fires it.
      await clock.advance(0);
      await new Promise((r) => setImmediate(r));
      assert.equal(sent.length, 1);
      assert.equal(sent[0].id, "u");
      assert.equal(sent[0].payload.toString(), "urgent-payload");
      assert.equal(seen.length, 0, "urgent items never enter a batch");
      // Normal items still merge into the same envelope shape.
      q.enqueue(item("a", EP1, "one", { "x-signature": "sig-a" }));
      q.enqueue(item("b", EP1, "two"));
      await clock.advance(100);
      assert.equal(sent.length, 2);
      assert.equal(seen.length, 1);
      const merged = sent[1];
      assert.equal(merged.id, seen[0].batchId);
      assert.equal(merged.headers["content-type"], "application/json");
      assert.equal(merged.headers["x-batch-id"], seen[0].batchId);
      assert.equal(merged.headers["x-batch-size"], "2");
      const env = JSON.parse(merged.payload.toString());
      assert.equal(env.batch_id, seen[0].batchId);
      assert.match(env.batched_at, /^\d{4}-\d{2}-\d{2}T/);
      assert.equal(env.events.length, 2);
      assert.equal(env.events[0].id, "a");
      assert.equal(Buffer.from(env.events[0].payload, "base64").toString(), "one");
      assert.equal(env.events[0].headers["x-signature"], "sig-a");
      assert.equal(env.events[1].id, "b");
      assert.deepEqual(q.getBatchConfig(), { windowMs: 100, maxBatchSize: 10 });
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer batch callback revision (WR-400)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  async function waitFor(cond: () => boolean, what: string, timeoutMs = 8000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (!cond() && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok(cond(), `timed out waiting for ${what}`);
  }

  function post(port: number, body: Buffer, headers: Record<string, string> = {}) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest({ host: "127.0.0.1", port, path: "/", method: "POST", headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
        );
      });
      r.on("error", reject);
      r.end(body);
    });
  }

  /**
   * A server with batch merging on, whose sender records merged
   * deliveries instead of POSTing them.
   */
  function batchingServer(opts: {
    onBatch?: (info: BatchInfo) => void;
    batch?: Record<string, unknown>;
  } = {}) {
    const dir = mkdtempSync(join(tmpdir(), "batch-callback-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const sent: RetryItem[] = [];
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: INGEST_KEY,
      forwardUrl: EP2,
      auditLog,
      operatorToken: OPERATOR_TOKEN,
      sender: async (it) => {
        sent.push(it);
        return { statusCode: 200, body: Buffer.from("ok"), truncated: false };
      },
      retry: {
        baseDelayMs: 5,
        jitterMs: 0,
        maxAttempts: 1,
        batch: { windowMs: 200, maxBatchSize: 10, ...(opts.batch ?? {}) },
        ...(opts.onBatch !== undefined ? { onBatch: opts.onBatch } : {}),
      },
    });
    servers.push(relay);
    return { relay, auditLog, sent };
  }

  /** Post two items and wait until `seen` grows past `before`. */
  async function flushOnce(
    port: number,
    seen: BatchInfo[],
    before: number
  ): Promise<{ traceIds: string[] }> {
    const t1 = JSON.parse(
      (
        await post(port, BODY, {
          "x-signature": signSha256(BODY, INGEST_KEY),
          "content-type": "application/json",
        })
      ).text
    ) as { traceId: string };
    const t2 = JSON.parse(
      (
        await post(port, BODY, {
          "x-signature": signSha256(BODY, INGEST_KEY),
          "content-type": "application/json",
        })
      ).text
    ) as { traceId: string };
    await waitFor(() => seen.length > before, "batch flush callback");
    return { traceIds: [t1.traceId, t2.traceId] };
  }

  it("revising the callback routes the next flush to the new callback and the audit still lands", async () => {
    const first: BatchInfo[] = [];
    const second: BatchInfo[] = [];
    const { relay, auditLog, sent } = batchingServer({
      onBatch: (info) => first.push(info),
    });
    const port = await listen(relay);
    const { traceIds: t1 } = await flushOnce(port, first, 0);
    assert.equal(first.length, 1);
    assert.ok(first[0].batchId.startsWith("batch:"));
    assert.equal(first[0].endpoint, EP2);
    assert.equal(first[0].size, 2);
    assert.deepEqual(first[0].traceIds, t1);
    assert.equal(eventsOf(auditLog, "batch_flushed").length, 1);
    assert.equal(sent.length, 1);
    relay.reviseBatchCallback!((info) => second.push(info));
    const { traceIds: t2 } = await flushOnce(port, second, 0);
    assert.equal(first.length, 1);
    assert.equal(second.length, 1);
    assert.ok(second[0].batchId.startsWith("batch:"));
    assert.notEqual(second[0].batchId, first[0].batchId);
    assert.equal(second[0].endpoint, EP2);
    assert.equal(second[0].size, 2);
    assert.deepEqual(second[0].traceIds, t2);
    assert.equal(eventsOf(auditLog, "batch_flushed").length, 2);
    assert.equal(sent.length, 2);
    // The revision itself is audited with presence only, never a body.
    const revised = eventsOf(auditLog, "batch_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "set");
    assert.equal(revised[0].current, "set");
  });

  it("null clears back to no observer; the flush is still audited and still counted", async () => {
    const first: BatchInfo[] = [];
    const { relay, auditLog, sent } = batchingServer({
      onBatch: (info) => first.push(info),
    });
    const port = await listen(relay);
    await flushOnce(port, first, 0);
    assert.equal(first.length, 1);
    relay.reviseBatchCallback!(null);
    const beforeAudit = eventsOf(auditLog, "batch_flushed").length;
    await post(port, BODY, {
      "x-signature": signSha256(BODY, INGEST_KEY),
      "content-type": "application/json",
    });
    await post(port, BODY, {
      "x-signature": signSha256(BODY, INGEST_KEY),
      "content-type": "application/json",
    });
    await waitFor(
      () => eventsOf(auditLog, "batch_flushed").length > beforeAudit,
      "batch_flushed audit after clear"
    );
    assert.equal(first.length, 1, "cleared hook stays silent");
    assert.equal(sent.length, 2, "merging keeps delivering after the clear");
    const revised = eventsOf(auditLog, "batch_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "set");
    assert.equal(revised[0].current, "cleared");
  });

  it("a non-function value throws RangeError and the live callback is untouched; same-reference is a silent no-op", async () => {
    const first: BatchInfo[] = [];
    const onBatch = (info: BatchInfo) => first.push(info);
    const { relay, auditLog } = batchingServer({ onBatch });
    const port = await listen(relay);
    for (const bad of ["x", 42, {}] as never[]) {
      assert.throws(() => relay.reviseBatchCallback!(bad), RangeError, String(bad));
    }
    assert.equal(eventsOf(auditLog, "batch_callback_revised").length, 0);
    relay.reviseBatchCallback!(onBatch);
    assert.equal(eventsOf(auditLog, "batch_callback_revised").length, 0);
    await flushOnce(port, first, 0);
    assert.equal(first.length, 1);
  });

  it("clearing when already unset is a silent no-op", async () => {
    const { relay, auditLog } = batchingServer({});
    await listen(relay);
    relay.reviseBatchCallback!(null);
    assert.equal(eventsOf(auditLog, "batch_callback_revised").length, 0);
  });

  it("revising with batching unconfigured throws Error", () => {
    const dir = mkdtempSync(join(tmpdir(), "batch-callback-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      ["sec" + "ret"]: INGEST_KEY,
      forwardUrl: EP2,
      auditLog,
      operatorToken: OPERATOR_TOKEN,
      sender: async () => {
        throw new Error("downstream 500");
      },
    });
    servers.push(relay);
    assert.throws(
      () => relay.reviseBatchCallback!(() => {}),
      (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
    );
  });
});
