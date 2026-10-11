import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type Sender, type RetryItem, type RetryQueueOptions } from "../src/retry.ts";
import {
  ScheduledDeliveryQueue,
  parseDeliverAtHeader,
  DELIVER_AT_HEADER,
} from "../src/scheduled.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const URL_A = "http://localhost:9999/a";
const URL_B = "http://localhost:9999/b";

/** Manual timer that also records the scheduled delays. */
function manualTimer() {
  const pending: Array<{ fn: () => void; ms: number }> = [];
  return {
    pendingCount: () => pending.length,
    lastDelay: () => pending[pending.length - 1]?.ms,
    delays: () => pending.map((p) => p.ms),
    setTimer: (fn: () => void, ms: number) => {
      const rec = { fn, ms };
      pending.push(rec);
      return {
        clear: () => {
          const i = pending.indexOf(rec);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    async step() {
      const fns = pending.splice(0);
      for (const f of fns) f.fn();
      await new Promise((r) => setImmediate(r));
    },
  };
}

function item(id: string, targetUrl: string, extra: Partial<RetryItem> = {}): RetryItem {
  return { id, payload: Buffer.from(`payload-${id}`), targetUrl, headers: {}, ...extra };
}

function queueWithClock(opts: {
  sender: Sender;
  now: () => number;
  t: ReturnType<typeof manualTimer>;
  extra?: RetryQueueOptions;
}) {
  return new RetryQueue({
    sender: opts.sender,
    setTimer: opts.t.setTimer,
    maxAttempts: 2,
    baseDelayMs: 50,
    jitterMs: 0,
    scheduled: { now: opts.now, setTimer: opts.t.setTimer },
    ...opts.extra,
  });
}

describe("parseDeliverAtHeader", () => {
  // Fixed instant: Sat, 10 Oct 2026 12:00:00 GMT.
  const T = Date.UTC(2026, 9, 10, 12, 0, 0);

  it("parses epoch-ms integers (trims whitespace, takes the first of an array)", () => {
    assert.equal(parseDeliverAtHeader(String(T)), T);
    assert.equal(parseDeliverAtHeader(`  ${T}  `), T);
    assert.equal(parseDeliverAtHeader([String(T), String(T + 1)]), T);
  });

  it("parses all three HTTP-date shapes", () => {
    // IMF-fixdate, e.g. what Date#toUTCString produces.
    assert.equal(parseDeliverAtHeader(new Date(T).toUTCString()), T);
    // RFC 850: Saturday, 10-Oct-26 12:00:00 GMT
    assert.equal(parseDeliverAtHeader("Saturday, 10-Oct-26 12:00:00 GMT"), T);
    // asctime: Sat Oct 10 12:00:00 2026
    assert.equal(parseDeliverAtHeader("Sat Oct 10 12:00:00 2026"), T);
  });

  it("returns undefined for an absent header", () => {
    assert.equal(parseDeliverAtHeader(undefined), undefined);
  });

  it("rejects illegal values with RangeError", () => {
    for (const bad of [
      "",
      "   ",
      "tomorrow",
      "1.5", // fractional epoch — and NOT a valid HTTP-date shape
      "2027.5", // would be misread by a lenient Date.parse; must fail fast
      "2026-10-10", // ISO is not an HTTP-date
      "2026-10-10T12:00:00Z", // ISO is not an HTTP-date
      "99999999999999999999999", // outside the safe-integer range
      "12:00:00", // not a full date
      "Sat, 10 Oct 2026 25:00:00 GMT", // impossible hour
    ]) {
      assert.throws(() => parseDeliverAtHeader(bad), RangeError, `header ${JSON.stringify(bad)}`);
    }
    assert.throws(() => parseDeliverAtHeader(["", "1"]), RangeError);
  });

  it("exposes the header name", () => {
    assert.equal(DELIVER_AT_HEADER, "x-deliver-at");
  });
});

describe("ScheduledDeliveryQueue", () => {
  it("fires parked items in deliverAt order (min-heap), FIFO on ties", async () => {
    let now = 1_000_000;
    const t = manualTimer();
    const due: string[] = [];
    const q = new ScheduledDeliveryQueue({
      now: () => now,
      setTimer: t.setTimer,
      onDue: (items) => due.push(...items.map((i) => i.id)),
    });
    q.arm();
    const mk = (id: string, at: number) => item(id, URL_A, { deliverAt: at });
    q.park(mk("c", now + 3000));
    q.park(mk("a", now + 1000));
    q.park(mk("b", now + 2000));
    q.park(mk("tie2", now + 1000));
    q.park(mk("tie1", now + 1000));
    // Exactly one timer is ever armed — for the head.
    assert.equal(t.pendingCount(), 1);
    assert.equal(t.lastDelay(), 1000);
    now += 1000;
    await t.step();
    assert.deepEqual(due, ["a", "tie2", "tie1"]);
    assert.equal(t.pendingCount(), 1); // re-armed for b
    now += 1000;
    await t.step();
    assert.deepEqual(due, ["a", "tie2", "tie1", "b"]);
    now += 1000;
    await t.step();
    assert.deepEqual(due, ["a", "tie2", "tie1", "b", "c"]);
    assert.equal(t.pendingCount(), 0); // heap drained
    assert.deepEqual(q.stats(), { pending: 0, scheduled: 5, due: 5, canceled: 0 });
  });

  it("re-arms when an earlier item is parked, and keeps one timer", async () => {
    let now = 1_000_000;
    const t = manualTimer();
    const q = new ScheduledDeliveryQueue({ now: () => now, setTimer: t.setTimer });
    q.arm();
    q.park(item("late", URL_A, { deliverAt: now + 5000 }));
    assert.equal(t.lastDelay(), 5000);
    q.park(item("early", URL_A, { deliverAt: now + 500 }));
    assert.equal(t.pendingCount(), 1); // the old timer was replaced, not added
    assert.equal(t.lastDelay(), 500);
  });

  it("cancel removes the item: true on a real cancel, false for unknown ids", async () => {
    let now = 1_000_000;
    const t = manualTimer();
    const due: string[] = [];
    const q = new ScheduledDeliveryQueue({
      now: () => now,
      setTimer: t.setTimer,
      onDue: (items) => due.push(...items.map((i) => i.id)),
    });
    q.arm();
    q.park(item("x", URL_A, { deliverAt: now + 1000 }));
    q.park(item("y", URL_A, { deliverAt: now + 2000 }));
    assert.equal(q.cancel("nope"), false);
    assert.equal(q.cancel("x"), true); // the armed head: timer re-arms for y
    assert.equal(q.cancel("x"), false); // already gone
    assert.equal(t.pendingCount(), 1);
    assert.equal(t.lastDelay(), 2000);
    now += 5000;
    await t.step();
    assert.deepEqual(due, ["y"]); // x never fires
    assert.deepEqual(q.stats(), { pending: 0, scheduled: 2, due: 1, canceled: 1 });
  });

  it("canceling the only item disarms the timer", () => {
    let now = 1_000_000;
    const t = manualTimer();
    const q = new ScheduledDeliveryQueue({ now: () => now, setTimer: t.setTimer });
    q.arm();
    q.park(item("solo", URL_A, { deliverAt: now + 1000 }));
    assert.equal(t.pendingCount(), 1);
    assert.equal(q.cancel("solo"), true);
    assert.equal(t.pendingCount(), 0);
    assert.equal(q.pendingCount(), 0);
  });

  it("validates parked items with RangeError, duplicates with Error", () => {
    let now = 1_000_000;
    const q = new ScheduledDeliveryQueue({ now: () => now });
    q.arm();
    assert.throws(() => q.park(item("past", URL_A, { deliverAt: now })), RangeError);
    assert.throws(() => q.park(item("past2", URL_A, { deliverAt: now - 1 })), RangeError);
    assert.throws(() => q.park(item("nan", URL_A, { deliverAt: NaN })), RangeError);
    assert.throws(() => q.park(item("inf", URL_A, { deliverAt: Infinity })), RangeError);
    assert.throws(() => q.park(item("nodeliverat", URL_A)), RangeError);
    assert.throws(() => q.park({ ...item("empty", URL_A, { deliverAt: now + 1 }), id: "" }), RangeError);
    q.park(item("dup", URL_A, { deliverAt: now + 1 }));
    assert.throws(() => q.park(item("dup", URL_A, { deliverAt: now + 2 })), Error);
    q.clear();
  });

  it("rejects malformed injection options at construction", () => {
    assert.throws(() => new ScheduledDeliveryQueue({ now: 42 as never }), RangeError);
    assert.throws(() => new ScheduledDeliveryQueue({ setTimer: "x" as never }), RangeError);
    assert.throws(() => new ScheduledDeliveryQueue({ clearTimer: 0 as never }), RangeError);
    assert.throws(() => new ScheduledDeliveryQueue({ onDue: null as never }), RangeError);
  });

  it("disarm keeps the heap; arm resumes; clear drops everything", async () => {
    let now = 1_000_000;
    const t = manualTimer();
    const due: string[] = [];
    const q = new ScheduledDeliveryQueue({
      now: () => now,
      setTimer: t.setTimer,
      onDue: (items) => due.push(...items.map((i) => i.id)),
    });
    q.arm();
    q.park(item("k", URL_A, { deliverAt: now + 1000 }));
    q.disarm(); // stop(): timer cleared, heap kept
    assert.equal(t.pendingCount(), 0);
    assert.equal(q.pendingCount(), 1);
    now += 5000; // the instant passes while disarmed: nothing fires
    await t.step();
    assert.deepEqual(due, []);
    q.arm(); // start(): re-arms; the head is past-due so it fires at once
    assert.equal(t.lastDelay(), 0);
    await t.step();
    assert.deepEqual(due, ["k"]);
    q.park(item("drop", URL_A, { deliverAt: now + 1000 }));
    q.clear(); // shutdown(): parked-but-not-due items are dropped
    assert.equal(q.pendingCount(), 0);
    assert.equal(t.pendingCount(), 0);
    assert.deepEqual(q.stats(), { pending: 0, scheduled: 0, due: 0, canceled: 0 });
  });

  it("clamps far-future delays instead of overflowing setTimeout", async () => {
    let now = 1_000_000;
    const t = manualTimer();
    const due: string[] = [];
    const q = new ScheduledDeliveryQueue({
      now: () => now,
      setTimer: t.setTimer,
      onDue: (items) => due.push(...items.map((i) => i.id)),
    });
    q.arm();
    q.park(item("far", URL_A, { deliverAt: now + 2 ** 33 })); // ~272 years
    assert.equal(t.lastDelay(), 2 ** 31 - 1); // clamped, not overflowed
    await t.step(); // clamped fire: head not due -> re-arms, nothing delivered
    assert.deepEqual(due, []);
    assert.equal(t.pendingCount(), 1);
    q.clear();
  });

  it("lists pending items earliest-first with metadata only (no payload)", () => {
    let now = 1_000_000;
    const q = new ScheduledDeliveryQueue({ now: () => now });
    q.arm();
    q.park(item("b", URL_B, { traceId: "trace-b", deliverAt: now + 2000, tenantId: "t1" }));
    q.park(item("a", URL_A, { traceId: "trace-a", deliverAt: now + 1000, priority: "urgent" }));
    const list = q.list();
    assert.deepEqual(
      list.map((e) => e.id),
      ["a", "b"]
    );
    assert.deepEqual(list[0], {
      id: "a",
      targetUrl: URL_A,
      traceId: "trace-a",
      deliverAt: now + 1000,
      deliverAtIso: new Date(now + 1000).toISOString(),
      priority: "urgent",
    });
    assert.equal(list[1].tenant, "t1");
    for (const e of list) assert.ok(!("payload" in e), "payload must never leak");
    q.clear();
  });

  it("a parked far-future delivery does not pin the process open (unref)", () => {
    // The only honest proof: a child process whose sole pending work is
    // the armed scheduler timer must exit on its own.
    const child = join(
      mkdtempSync(join(tmpdir(), "wr57-unref-")),
      "child.mjs"
    );
    writeFileSync(
      child,
      [
        `const { ScheduledDeliveryQueue } = await import(${JSON.stringify(new URL("../src/scheduled.ts", import.meta.url).href)});`,
        "const q = new ScheduledDeliveryQueue();",
        "q.arm();",
        'q.park({ id: "x", payload: Buffer.from("x"), targetUrl: "http://localhost:1/", headers: {}, traceId: "t", deliverAt: Date.now() + 3600000 });',
        'console.log("parked");',
        "",
      ].join("\n")
    );
    const out = execFileSync(process.execPath, [child], { timeout: 15000, encoding: "utf8" });
    assert.match(out, /parked/); // exited instead of hanging on the timer
  });
});

describe("RetryQueue scheduled delivery (WR-57)", () => {
  it("parks a future deliver_at: nothing attempted until the instant arrives", async () => {
    let now = 1_000_000;
    const t = manualTimer();
    let senderCalls = 0;
    const events: string[] = [];
    const q = queueWithClock({
      sender: async () => {
        senderCalls += 1;
      },
      now: () => now,
      t,
    });
    q.subscribeDeliveryEvents((e) => events.push(e.type));
    q.start();
    q.enqueue(item("s1", URL_A, { deliverAt: now + 5000 }));
    assert.equal(q.isScheduled("s1"), true);
    assert.equal(q.getScheduledStats().pending, 1);
    await t.step();
    await t.step();
    assert.equal(senderCalls, 0); // not attempted
    assert.deepEqual(events, []); // no lifecycle events while parked
    assert.equal(q.pendingCount(), 0); // parked items are not in the delivery queue
    now += 4999;
    await t.step();
    assert.equal(senderCalls, 0); // 1ms early: still parked
    now += 1;
    await t.step(); // scheduler fires -> released into the normal path
    assert.equal(q.isScheduled("s1"), false);
    await t.step(); // the released delivery runs
    assert.equal(senderCalls, 1);
    assert.deepEqual(events, ["delivered"]);
    q.stop();
  });

  it("counts attempts from the first actual delivery, not the parking period", async () => {
    let now = 1_000_000;
    const t = manualTimer();
    const seenAttempts: number[] = [];
    let deliveredAttempts = -1;
    const q = queueWithClock({
      sender: async (it) => {
        seenAttempts.push(it.attempt ?? -1);
      },
      now: () => now,
      t,
      extra: { onDelivered: (_it: RetryItem, attempts: number) => (deliveredAttempts = attempts) },
    });
    q.start();
    q.enqueue(item("s2", URL_A, { deliverAt: now + 2000 }));
    now += 2000;
    await t.step(); // due -> released
    await t.step(); // delivered
    assert.deepEqual(seenAttempts, [0]); // first actual dispatch is attempt 0 (1-based: 1)
    assert.equal(deliveredAttempts, 1); // the parking period counted nothing
    q.stop();
  });

  it("past-due deliver_at takes the normal path immediately", async () => {
    let now = 1_000_000;
    const t = manualTimer();
    let senderCalls = 0;
    const q = queueWithClock({
      sender: async () => {
        senderCalls += 1;
      },
      now: () => now,
      t,
    });
    q.start();
    q.enqueue(item("p1", URL_A, { deliverAt: now - 1 })); // 1ms in the past
    q.enqueue(item("p2", URL_A, { deliverAt: now })); // exactly now
    assert.equal(q.isScheduled("p1"), false);
    assert.equal(q.isScheduled("p2"), false);
    await t.step();
    assert.equal(senderCalls, 2);
    q.stop();
  });

  it("parking consumes no retry budget, quota, circuit verdict, or backoff jitter", async () => {
    let now = 1_000_000;
    const t = manualTimer();
    const randomCalls: number[] = [];
    let senderCalls = 0;
    const q = new RetryQueue({
      sender: async () => {
        senderCalls += 1;
      },
      setTimer: t.setTimer,
      maxAttempts: 2,
      baseDelayMs: 50,
      jitterMs: 100,
      random: () => {
        randomCalls.push(1);
        return 0.5;
      },
      circuitBreaker: { failureThreshold: 2, cooldownMs: 60000 },
      quota: { deliveriesPerMinute: 5 },
      retryBudget: { retriesPerMinute: 10 },
      scheduled: { now: () => now, setTimer: t.setTimer },
    });
    q.start();
    q.enqueue(item("s3", URL_A, { deliverAt: now + 5000 }));
    await t.step();
    assert.equal(senderCalls, 0);
    assert.equal(q.circuitBlockedCount(), 0);
    assert.deepEqual(q.getQuotaStats(), []);
    assert.equal(q.getRetryBudgetStats()?.depleted, 0);
    assert.equal(randomCalls.length, 0); // no jitter drawn for the parking
    // The breaker never saw the parked delivery: no endpoint record at
    // all (records are created lazily on first contact).
    assert.deepEqual(q.getCircuitStats(), []);
    now += 5000;
    await t.step(); // due
    await t.step(); // delivered: now the gates engage normally
    assert.equal(senderCalls, 1);
    q.stop();
  });

  it("a due delivery follows the normal retry then dead-letter path", async () => {
    let now = 1_000_000;
    const t = manualTimer();
    const events: Array<{ type: string; attempts: number }> = [];
    const q = queueWithClock({
      sender: async () => {
        throw new Error("downstream 500");
      },
      now: () => now,
      t,
    });
    q.subscribeDeliveryEvents((e) => events.push({ type: e.type, attempts: e.attempts }));
    q.start();
    q.enqueue(item("s4", URL_A, { deliverAt: now + 1000 }));
    now += 1000;
    await t.step(); // due -> released into the normal path
    assert.deepEqual(events, []); // parking emitted nothing
    await t.step(); // attempt 1 fails -> retry scheduled
    assert.deepEqual(events, [{ type: "retrying", attempts: 1 }]);
    await t.step(); // attempt 2 fails -> dead letter (maxAttempts: 2)
    assert.deepEqual(events, [
      { type: "retrying", attempts: 1 },
      { type: "dead_letter", attempts: 2 },
    ]);
    const dl = q.getDeadLetter();
    assert.equal(dl.length, 1);
    assert.equal(dl[0].attempts, 2);
    assert.equal(dl[0].failureClass, "retryable");
    q.stop();
  });

  it("cancelScheduled: true cancels, false for unknown ids; canceled items never deliver", async () => {
    let now = 1_000_000;
    const t = manualTimer();
    const delivered: string[] = [];
    const q = queueWithClock({
      sender: async (it) => {
        delivered.push(it.id);
      },
      now: () => now,
      t,
    });
    q.start();
    q.enqueue(item("k1", URL_A, { deliverAt: now + 1000 }));
    q.enqueue(item("k2", URL_A, { deliverAt: now + 1000 }));
    assert.equal(q.cancelScheduled("k1"), true);
    assert.equal(q.cancelScheduled("k1"), false); // already canceled
    assert.equal(q.cancelScheduled("never-was"), false);
    assert.deepEqual(q.getScheduledStats(), { pending: 1, scheduled: 2, due: 0, canceled: 1 });
    now += 2000;
    await t.step(); // k2 due
    await t.step(); // k2 delivered; k1 never fires
    assert.deepEqual(delivered, ["k2"]);
    q.stop();
  });

  it("reports pending scheduled metadata without the payload", async () => {
    let now = 1_000_000;
    const t = manualTimer();
    const q = queueWithClock({
      sender: async () => {},
      now: () => now,
      t,
    });
    q.start();
    assert.deepEqual(q.getScheduled(), []);
    q.enqueue(item("m2", URL_B, { traceId: "tt2", deliverAt: now + 3000, tenantId: "t9" }));
    q.enqueue(item("m1", URL_A, { traceId: "tt1", deliverAt: now + 1000 }));
    const list = q.getScheduled();
    assert.deepEqual(
      list.map((e) => e.id),
      ["m1", "m2"] // earliest deliverAt first
    );
    assert.deepEqual(list[0], {
      id: "m1",
      targetUrl: URL_A,
      traceId: "tt1",
      deliverAt: now + 1000,
      deliverAtIso: new Date(now + 1000).toISOString(),
    });
    assert.equal(list[1].tenant, "t9");
    for (const e of list) assert.ok(!("payload" in e));
    assert.deepEqual(q.getScheduledStats(), { pending: 2, scheduled: 2, due: 0, canceled: 0 });
    q.stop();
  });

  it("rejects a duplicate id while it is parked", () => {
    let now = 1_000_000;
    const t = manualTimer();
    const q = queueWithClock({ sender: async () => {}, now: () => now, t });
    q.start();
    q.enqueue(item("dup", URL_A, { deliverAt: now + 1000 }));
    assert.throws(() => q.enqueue(item("dup", URL_A)), Error);
    q.stop();
  });

  it("stop() keeps parked items; start() re-arms; shutdown() drops them", async () => {
    let now = 1_000_000;
    const t = manualTimer();
    let senderCalls = 0;
    const q = queueWithClock({
      sender: async () => {
        senderCalls += 1;
      },
      now: () => now,
      t,
    });
    q.start();
    q.enqueue(item("z1", URL_A, { deliverAt: now + 1000 }));
    q.stop(); // disarms the delay timer, keeps the heap
    assert.equal(t.pendingCount(), 0);
    assert.equal(q.getScheduledStats().pending, 1);
    now += 5000; // the instant passes while stopped
    q.start(); // re-arms; the head is past-due so it releases at once
    await t.step();
    await t.step();
    assert.equal(senderCalls, 1);
    // Shutdown drops parked-but-not-due items like backoff-waiting ones.
    q.enqueue(item("z2", URL_A, { deliverAt: now + 60_000 }));
    assert.equal(q.getScheduledStats().pending, 1);
    await q.shutdown();
    assert.equal(q.getScheduledStats().pending, 0);
    assert.deepEqual(q.getScheduled(), []);
  });

  it("exposes relay_scheduled_* counters in the Prometheus exposition", async () => {
    let now = 1_000_000;
    const t = manualTimer();
    const q = queueWithClock({ sender: async () => {}, now: () => now, t });
    // Untouched: no scheduled series at all.
    assert.ok(!q.renderMetrics().includes("relay_scheduled_"));
    q.start();
    q.enqueue(item("c1", URL_A, { deliverAt: now + 1000 }));
    q.enqueue(item("c2", URL_A, { deliverAt: now + 2000 }));
    assert.equal(q.cancelScheduled("c2"), true);
    now += 1000;
    await t.step(); // c1 due
    const exposition = q.renderMetrics();
    assert.match(exposition, /relay_scheduled_total 2\n/);
    assert.match(exposition, /relay_scheduled_due_total 1\n/);
    assert.match(exposition, /relay_scheduled_canceled_total 1\n/);
    q.stop();
  });
});

describe("server: x-deliver-at intake and GET /scheduled", () => {
  const SECRET = "wr57-secret";
  const BODY = Buffer.from(JSON.stringify({ order: "ord_1" }));

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

  function post(port: number, body: Buffer, headers: Record<string, string> = {}) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest(
        { host: "127.0.0.1", port, path: "/", method: "POST", headers },
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

  function get(port: number, path: string, headers: Record<string, string> = {}) {
    return new Promise<{ status: number; json: unknown }>((resolve, reject) => {
      const r = httpRequest(
        { host: "127.0.0.1", port, path, method: "GET", headers },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => {
            let json: unknown = null;
            try {
              json = JSON.parse(Buffer.concat(chunks).toString());
            } catch {
              // Leave json as null; the status assertion will fail the test.
            }
            resolve({ status: res.statusCode ?? 0, json });
          });
        }
      );
      r.on("error", reject);
      r.end();
    });
  }

  async function waitFor(
    cond: () => boolean | Promise<boolean>,
    timeoutMs: number,
    what: string
  ): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (!(await cond()) && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok(await cond(), `timed out waiting for: ${what}`);
  }

  function signedHeaders(extra: Record<string, string> = {}) {
    return {
      "x-signature": signSha256(BODY, SECRET),
      "content-type": "application/json",
      ...extra,
    };
  }

  async function makeRelay() {
    const hits: Buffer[] = [];
    const stub = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        hits.push(Buffer.concat(chunks));
        res.writeHead(200).end("ok");
      });
    });
    const stubPort = await listen(stub);
    const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "wr57-")), "audit.jsonl"));
    const token = "op-token-wr57";
    const relay = createRelayServer({
secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      operatorToken: token,
      retry: { baseDelayMs: 50, maxDelayMs: 1000, maxAttempts: 3, jitterMs: 0 },
    });
    const relayPort = await listen(relay);
    return { stub, relay, relayPort, hits, audit, token };
  }

  it("answers 400 for an invalid x-deliver-at and never enqueues", async () => {
    const { stub, relay, relayPort, hits, audit, token } = await makeRelay();
    try {
      const res = await post(relayPort, BODY, signedHeaders({ "x-deliver-at": "tomorrow" }));
      assert.equal(res.status, 400);
      const scheduled = await get(relayPort, "/scheduled", { authorization: `Bearer ${token}` });
      assert.equal(scheduled.status, 200);
      assert.deepEqual(scheduled.json, []);
      assert.equal(hits.length, 0);
      const rejected = audit.query({ event: "rejected" }) as Array<{ reason: string }>;
      assert.ok(rejected.some((e) => e.reason === "invalid_deliver_at"));
      assert.equal(audit.query({ event: "accepted" }).length, 0);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("accepts a future epoch-ms deliver_at, lists it on GET /scheduled, then delivers", async () => {
    const { stub, relay, relayPort, hits, audit, token } = await makeRelay();
    try {
      const deliverAt = Date.now() + 400;
      const res = await post(
        relayPort,
        BODY,
        signedHeaders({ "x-deliver-at": String(deliverAt) })
      );
      assert.equal(res.status, 202);
      const body = JSON.parse(res.text) as Record<string, unknown>;
      assert.equal(body.scheduled, true);
      assert.equal(body.deliverAt, new Date(deliverAt).toISOString());
      // Not delivered yet.
      assert.equal(hits.length, 0);

      // Operator query: metadata only, no payload.
      const listed = await get(relayPort, "/scheduled", { authorization: `Bearer ${token}` });
      assert.equal(listed.status, 200);
      const items = listed.json as Array<Record<string, unknown>>;
      assert.equal(items.length, 1);
      assert.equal(items[0].id, body.id);
      assert.ok((items[0].targetUrl as string).endsWith("/hook"));
      assert.equal(items[0].deliverAt, deliverAt);
      assert.equal(items[0].deliverAtIso, new Date(deliverAt).toISOString());
      assert.equal(items[0].traceId, body.traceId);
      assert.ok(!("payload" in items[0]), "payload must never leak to operators");

      // Auth fail-closed: missing/wrong bearer -> 403 while the token is
      // configured (404 only when operator endpoints are disabled — see
      // the last test).
      assert.equal((await get(relayPort, "/scheduled")).status, 403);
      assert.equal(
        (await get(relayPort, "/scheduled", { authorization: "Bearer wrong" })).status,
        403
      );

      // The scheduled audit event is queryable.
      const scheduledEvents = audit.query({ event: "scheduled" }) as Array<{
        deliverAtMs: number;
      }>;
      assert.equal(scheduledEvents.length, 1);
      assert.equal(scheduledEvents[0].deliverAtMs, deliverAt);

      // The instant arrives: the downstream gets the payload, byte-for-byte.
      await waitFor(() => hits.length >= 1, 15000, "scheduled delivery");
      assert.deepEqual(hits[0], BODY);
      // ...and the pending list drains.
      await waitFor(async () => {
        const l = await get(relayPort, "/scheduled", { authorization: `Bearer ${token}` });
        return (l.json as unknown[]).length === 0;
      }, 5000, "scheduled list drained");
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("accepts an HTTP-date deliver_at", async () => {
    const { stub, relay, relayPort, hits, token } = await makeRelay();
    try {
      const deliverAt = Date.now() + 2500; // HTTP-dates have 1s resolution: keep the truncated instant in the future
      const res = await post(
        relayPort,
        BODY,
        signedHeaders({ "x-deliver-at": new Date(deliverAt).toUTCString() })
      );
      assert.equal(res.status, 202);
      assert.equal(JSON.parse(res.text).scheduled, true);
      const listed = await get(relayPort, "/scheduled", { authorization: `Bearer ${token}` });
      assert.equal((listed.json as unknown[]).length, 1);
      await waitFor(() => hits.length >= 1, 15000, "http-date scheduled delivery");
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("a past-due deliver_at takes the normal path (no scheduled flag)", async () => {
    const { stub, relay, relayPort, hits, token } = await makeRelay();
    try {
      const res = await post(
        relayPort,
        BODY,
        signedHeaders({ "x-deliver-at": String(Date.now() - 1000) })
      );
      assert.equal(res.status, 202);
      const body = JSON.parse(res.text) as Record<string, unknown>;
      assert.equal(body.scheduled, undefined);
      await waitFor(() => hits.length >= 1, 15000, "past-due delivery");
      const listed = await get(relayPort, "/scheduled", { authorization: `Bearer ${token}` });
      assert.deepEqual(listed.json, []);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("GET /scheduled is 404 when operator endpoints are disabled (fail closed)", async () => {
    const stub = createServer((_req, res) => res.writeHead(200).end("ok"));
    const stubPort = await listen(stub);
    const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "wr57-")), "audit.jsonl"));
    const relay = createRelayServer({
secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      // No operatorToken: the whole operator surface is disabled.
    });
    const relayPort = await listen(relay);
    try {
      assert.equal((await get(relayPort, "/scheduled")).status, 404);
    } finally {
      await close(relay);
      await close(stub);
    }
  });
});
