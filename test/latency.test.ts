import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { LatencyTracker } from "../src/latency.ts";
import { RetryQueue, type SloMissInfo } from "../src/retry.ts";

/** Deterministic timer: `run()` executes pending callbacks immediately. */
function manualTimer() {
  const pending: Array<() => void> = [];
  return {
    setTimer: (fn: () => void, _ms: number) => {
      pending.push(fn);
      return { clear: () => { const i = pending.indexOf(fn); if (i >= 0) pending.splice(i, 1); } };
    },
    async run() {
      while (pending.length > 0) {
        const fns = pending.splice(0);
        for (const fn of fns) fn();
        await new Promise((r) => setImmediate(r));
      }
    },
  };
}

const ITEM = {
  id: "l-1",
  payload: Buffer.from("x"),
  targetUrl: "http://localhost:9999/hook",
  headers: {},
};

describe("latency tracker", () => {
  it("computes percentiles and SLO attainment over known samples", () => {
    let now = 0;
    const t = new LatencyTracker({ sloMs: 50, now: () => now });
    const latencies = [10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
    latencies.forEach((ms, i) => {
      now = 1000;
      t.recordAccepted(`id-${i}`);
      now = 1000 + ms;
      assert.equal(t.recordDelivered(`id-${i}`, "http://a/hook"), ms);
    });
    const [s] = t.stats();
    assert.equal(s.endpoint, "http://a/hook");
    assert.equal(s.count, 10);
    assert.equal(s.min, 10);
    assert.equal(s.max, 100);
    assert.equal(s.mean, 55);
    // Nearest-rank: p50 -> rank ceil(5)-1 = 4 -> 50; p95/p99 -> rank 9 -> 100.
    assert.equal(s.p50, 50);
    assert.equal(s.p95, 100);
    assert.equal(s.p99, 100);
    assert.equal(s.sloMs, 50);
    assert.equal(s.withinSlo, 5);
    assert.equal(s.sloAttainment, 0.5);
    assert.equal(t.pendingCount(), 0);
  });

  it("isolates endpoints and supports filtering", () => {
    let now = 0;
    const t = new LatencyTracker({ now: () => now });
    now = 0;
    t.recordAccepted("a");
    t.recordAccepted("b");
    now = 10;
    t.recordDelivered("a", "http://a/hook");
    now = 20;
    t.recordDelivered("b", "http://b/hook");
    assert.equal(t.stats().length, 2);
    const [only] = t.stats("http://b/hook");
    assert.equal(only.p50, 20);
    assert.deepEqual(t.stats("http://unknown/hook"), []);
  });

  it("keeps a bounded rolling window per endpoint", () => {
    let now = 0;
    const t = new LatencyTracker({ maxSamplesPerEndpoint: 3, now: () => now });
    for (let i = 1; i <= 5; i++) {
      now = 0;
      t.recordAccepted(`w-${i}`);
      now = i * 10;
      t.recordDelivered(`w-${i}`, "http://a/hook");
    }
    const [s] = t.stats();
    assert.equal(s.count, 3);
    assert.equal(s.min, 30); // oldest samples (10, 20) evicted
    assert.equal(s.max, 50);
  });

  it("discard drops pending records without sampling; unknown ids are no-ops", () => {
    const t = new LatencyTracker();
    t.recordAccepted("x");
    assert.equal(t.pendingCount(), 1);
    t.discard("x");
    assert.equal(t.pendingCount(), 0);
    assert.equal(t.recordDelivered("x", "http://a/hook"), undefined);
    assert.equal(t.recordDelivered("never-seen", "http://a/hook"), undefined);
    assert.deepEqual(t.stats(), []);
  });

  it("a repeated accept restarts the clock (replay measures the newest cycle)", () => {
    let now = 0;
    const t = new LatencyTracker({ now: () => now });
    t.recordAccepted("r");
    now = 100;
    t.recordAccepted("r");
    now = 150;
    assert.equal(t.recordDelivered("r", "http://a/hook"), 50);
  });

  it("clamps clock skew to zero instead of reporting negative latency", () => {
    let now = 100;
    const t = new LatencyTracker({ now: () => now });
    t.recordAccepted("s");
    now = 50; // clock jumped backwards
    assert.equal(t.recordDelivered("s", "http://a/hook"), 0);
  });

  it("rejects invalid configs", () => {
    assert.throws(() => new LatencyTracker({ sloMs: 0 }), RangeError);
    assert.throws(() => new LatencyTracker({ sloMs: -1 }), RangeError);
    assert.throws(() => new LatencyTracker({ maxSamplesPerEndpoint: 0 }), RangeError);
    assert.throws(() => new LatencyTracker({ maxSamplesPerEndpoint: 1.5 }), RangeError);
  });
});

describe("latency queue integration", () => {
  it("samples accepted->delivered latency and fires onSloMiss past the budget", async () => {
    let now = 0;
    const timer = manualTimer();
    const misses: SloMissInfo[] = [];
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      latency: { sloMs: 100, now: () => now, onSloMiss: (info) => misses.push(info) },
      setTimer: timer.setTimer,
    });
    q.start();
    now = 0;
    q.enqueue({ ...ITEM, id: "l-1" });
    now = 250;
    await timer.run();
    const [s] = q.getLatencyStats();
    assert.equal(s.count, 1);
    assert.equal(s.p50, 250);
    assert.equal(s.p95, 250);
    assert.equal(s.sloAttainment, 0);
    assert.equal(misses.length, 1);
    assert.deepEqual(misses[0], {
      id: "l-1",
      traceId: misses[0].traceId,
      endpoint: ITEM.targetUrl,
      latencyMs: 250,
      sloMs: 100,
    });
    assert.match(misses[0].traceId, /^[0-9a-f]{32}$/);
    // A fast delivery samples too, without a miss.
    now = 1000;
    q.enqueue({ ...ITEM, id: "l-2" });
    now = 1020;
    await timer.run();
    assert.equal(q.getLatencyStats()[0].count, 2);
    assert.equal(q.getLatencyStats()[0].sloAttainment, 0.5);
    assert.equal(misses.length, 1);
  });

  it("dead-lettered items are discarded without sampling", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {
        throw new Error("down");
      },
      maxAttempts: 1,
      jitterMs: 0,
      latency: { now: () => 0 },
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue({ ...ITEM, id: "d-1" });
    await timer.run();
    assert.equal(q.getDeadLetter().length, 1);
    assert.deepEqual(q.getLatencyStats(), []);
  });

  it("latency tracking is disabled by default", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({ sender: async () => {}, jitterMs: 0, setTimer: timer.setTimer });
    q.start();
    q.enqueue({ ...ITEM, id: "n-1" });
    await timer.run();
    assert.deepEqual(q.getLatencyStats(), []);
  });
});
