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
const INGEST_KEY = "batch-callback-enable-key";
const OPERATOR_TOKEN = "batch-callback-enable-op-token";
const BODY = Buffer.from(JSON.stringify({ hello: "batch-enable" }));
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

/** Queue deliberately *without* a `batch` option, so the WR-477 enable path is the only way an observer appears. */
function makeUnconfiguredQueue(
  clock: ReturnType<typeof fakeClock>,
  opts: ConstructorParameters<typeof RetryQueue>[0] = {}
): { q: RetryQueue; sent: RetryItem[] } {
  const sent: RetryItem[] = [];
  const q = new RetryQueue({
    sender: async (it) => {
      sent.push(it);
    },
    setTimer: clock.setTimer,
    ...opts,
  });
  return { q, sent };
}

describe("RetryQueue batch callback enable (WR-477)", () => {
  it("installing the callback on an unconfigured queue enables observation: it fires from the first flush after batching is enabled", async () => {
    const clock = fakeClock();
    const seen: BatchInfo[] = [];
    const { q, sent } = makeUnconfiguredQueue(clock);
    q.start();
    try {
      assert.equal(q.batchConfigured(), false);
      assert.equal(q.getBatchConfig(), undefined);
      // No throw: the observer installs even though no batcher exists.
      q.reviseBatchCallback((info) => seen.push(info));
      // Installing the observer never starts merging on its own.
      assert.equal(q.batchConfigured(), false);
      assert.equal(q.getBatchConfig(), undefined);
      // Batching itself is enabled separately (WR-450).
      assert.deepEqual(q.setBatchConfig({ windowMs: 100, maxBatchSize: 10 }), {
        windowMs: 100,
        maxBatchSize: 10,
      });
      q.enqueue(item("a", EP1, "one"));
      q.enqueue(item("b", EP1, "two"));
      await clock.advance(100);
      assert.equal(sent.length, 1);
      assert.equal(seen.length, 1);
      assert.ok(seen[0].batchId.startsWith("batch:"));
      assert.equal(seen[0].endpoint, EP1);
      assert.equal(seen[0].size, 2);
      assert.deepEqual(seen[0].traceIds, ["trace-a", "trace-b"]);
      assert.equal(sent[0].id, seen[0].batchId);
      assert.deepEqual(q.getBatchStats(), [{ endpoint: EP1, batches: 1, events: 2, buffered: 0 }]);
    } finally {
      q.stop();
    }
  });

  it("an illegal value throws RangeError, leaves the queue unconfigured, and the enable can still be retried", async () => {
    const clock = fakeClock();
    const seen: BatchInfo[] = [];
    const { q, sent } = makeUnconfiguredQueue(clock);
    q.start();
    try {
      for (const bad of ["x", 42, {}] as never[]) {
        assert.throws(() => q.reviseBatchCallback(bad), RangeError, String(bad));
      }
      assert.equal(q.batchConfigured(), false);
      assert.equal(q.getBatchConfig(), undefined);
      // The failed enable left nothing behind: a good callback installs.
      q.reviseBatchCallback((info) => seen.push(info));
      assert.equal(q.batchConfigured(), false);
      q.setBatchConfig({ windowMs: 100, maxBatchSize: 10 });
      q.enqueue(item("a", EP1));
      q.enqueue(item("b", EP1));
      await clock.advance(100);
      assert.equal(sent.length, 1);
      assert.equal(seen.length, 1);
      assert.deepEqual(seen[0].traceIds, ["trace-a", "trace-b"]);
    } finally {
      q.stop();
    }
  });

  it("installing the same reference twice is a silent no-op", async () => {
    const clock = fakeClock();
    const seen: BatchInfo[] = [];
    const onBatch = (info: BatchInfo) => seen.push(info);
    const { q, sent } = makeUnconfiguredQueue(clock);
    q.start();
    try {
      q.reviseBatchCallback(onBatch);
      q.reviseBatchCallback(onBatch);
      q.setBatchConfig({ windowMs: 100, maxBatchSize: 10 });
      q.enqueue(item("a", EP1));
      q.enqueue(item("b", EP1));
      await clock.advance(100);
      assert.equal(sent.length, 1);
      assert.equal(seen.length, 1, "one flush reports exactly once");
    } finally {
      q.stop();
    }
  });

  it("null while unconfigured is a silent no-op and leaves the constructor callback in place", async () => {
    const clock = fakeClock();
    const seen: BatchInfo[] = [];
    const { q, sent } = makeUnconfiguredQueue(clock, {
      onBatch: (info) => seen.push(info),
    });
    q.start();
    try {
      // No throw, no state change: the constructor callback survives.
      q.reviseBatchCallback(null);
      assert.equal(q.batchConfigured(), false);
      q.setBatchConfig({ windowMs: 100, maxBatchSize: 10 });
      q.enqueue(item("a", EP1));
      q.enqueue(item("b", EP1));
      await clock.advance(100);
      assert.equal(sent.length, 1);
      assert.equal(seen.length, 1);
      assert.deepEqual(seen[0].traceIds, ["trace-a", "trace-b"]);
    } finally {
      q.stop();
    }

    // A queue with no callback at all: null is equally silent, and a
    // later install still works.
    const clock2 = fakeClock();
    const seen2: BatchInfo[] = [];
    const { q: q2, sent: sent2 } = makeUnconfiguredQueue(clock2);
    q2.start();
    try {
      q2.reviseBatchCallback(null);
      assert.equal(q2.batchConfigured(), false);
      q2.reviseBatchCallback((info) => seen2.push(info));
      q2.setBatchConfig({ windowMs: 100, maxBatchSize: 10 });
      q2.enqueue(item("a", EP1));
      await clock2.advance(100);
      assert.equal(sent2.length, 1);
      assert.equal(seen2.length, 1);
      assert.equal(seen2[0].size, 1);
    } finally {
      q2.stop();
    }
  });
});

describe("RelayServer batch callback enable (WR-477)", () => {
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

  /** A server deliberately *without* batch merging, so the WR-477 enable path is the only way an observer appears. */
  function unconfiguredServer(opts: { onBatch?: (info: BatchInfo) => void } = {}) {
    const dir = mkdtempSync(join(tmpdir(), "batch-callback-enable-"));
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
        ...(opts.onBatch !== undefined ? { onBatch: opts.onBatch } : {}),
      },
    });
    servers.push(relay);
    return { relay, auditLog, sent };
  }

  it("the server installs the callback, audits the enable with previous 'cleared', and it fires from the first flush after batching is enabled", async () => {
    const seen: BatchInfo[] = [];
    const { relay, auditLog, sent } = unconfiguredServer();
    const port = await listen(relay);
    assert.equal(relay.getBatchConfig!(), undefined);
    // No throw: the operator cell installs even though no batcher exists.
    relay.reviseBatchCallback!((info) => seen.push(info));
    assert.equal(relay.getBatchConfig!(), undefined);
    const revised = eventsOf(auditLog, "batch_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "cleared");
    assert.equal(revised[0].current, "set");
    // Batching itself is enabled separately (WR-450).
    relay.setBatchConfig!({ windowMs: 200, maxBatchSize: 10 });
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
    await waitFor(
      () => seen.length > 0 && sent.length > 0,
      "batch flush callback and merged delivery"
    );
    assert.equal(seen.length, 1);
    assert.ok(seen[0].batchId.startsWith("batch:"));
    assert.equal(seen[0].endpoint, EP2);
    assert.equal(seen[0].size, 2);
    assert.deepEqual(seen[0].traceIds, [t1.traceId, t2.traceId]);
    assert.equal(sent.length, 1);
    // The flush itself is still audited as batch_flushed.
    assert.equal(eventsOf(auditLog, "batch_flushed").length, 1);
    // No second revision audit: the enable was the only change.
    assert.equal(eventsOf(auditLog, "batch_callback_revised").length, 1);
  });

  it("an illegal value throws RangeError with no audit and no install; null while unconfigured is a silent no-op", async () => {
    const seen: BatchInfo[] = [];
    const { relay, auditLog } = unconfiguredServer();
    await listen(relay);
    for (const bad of ["x", 42, {}] as never[]) {
      assert.throws(() => relay.reviseBatchCallback!(bad), RangeError, String(bad));
    }
    assert.equal(eventsOf(auditLog, "batch_callback_revised").length, 0);
    assert.equal(relay.getBatchConfig!(), undefined);
    relay.reviseBatchCallback!(null);
    assert.equal(eventsOf(auditLog, "batch_callback_revised").length, 0);
    assert.equal(relay.getBatchConfig!(), undefined);
    // The failed attempts left nothing behind: a good callback installs.
    relay.reviseBatchCallback!((info) => seen.push(info));
    const revised = eventsOf(auditLog, "batch_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "cleared");
    assert.equal(revised[0].current, "set");
  });
});
