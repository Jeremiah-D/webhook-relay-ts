import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { RetryQueue, UrgentRateLimiter, type RetryItem, type Sender } from "../src/retry.ts";

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

const ITEM: RetryItem = {
  id: "u-1",
  payload: Buffer.from("urgent"),
  targetUrl: "http://localhost:9999/fast",
  headers: {},
};

describe("urgent rate limiter", () => {
  it("grants a burst of rate tokens, then refills over time", () => {
    let nowMs = 0;
    const rl = new UrgentRateLimiter(2, () => nowMs);
    assert.equal(rl.take("e"), true);
    assert.equal(rl.take("e"), true);
    assert.equal(rl.take("e"), false); // burst exhausted
    assert.equal(rl.available("e"), 0);
    nowMs += 500; // half a second refills one token
    assert.equal(rl.take("e"), true);
    assert.equal(rl.take("e"), false);
    nowMs += 1000; // a full second refills back to the burst cap
    assert.equal(rl.take("e"), true);
    assert.equal(rl.take("e"), true);
    assert.equal(rl.take("e"), false);
  });

  it("isolates buckets per endpoint", () => {
    const rl = new UrgentRateLimiter(1, () => 0);
    assert.equal(rl.take("a"), true);
    assert.equal(rl.take("a"), false);
    assert.equal(rl.take("b"), true);
  });

  it("rejects non-positive rates", () => {
    assert.throws(() => new UrgentRateLimiter(0), RangeError);
    assert.throws(() => new UrgentRateLimiter(-5), RangeError);
    assert.throws(() => new UrgentRateLimiter(NaN), RangeError);
  });
});

describe("urgent lane", () => {
  it("urgent retries skip exponential backoff and use the fixed fast-lane delay", async () => {
    const timer = manualTimer();
    const delays: number[] = [];
    let attempts = 0;
    const flaky: Sender = async () => {
      attempts += 1;
      if (attempts < 3) throw new Error("boom");
    };
    const q = new RetryQueue({
      sender: flaky,
      baseDelayMs: 100,
      maxDelayMs: 10000,
      maxAttempts: 5,
      jitterMs: 0,
      urgent: { retryDelayMs: 25 },
      setTimer: (fn, ms) => {
        delays.push(ms);
        return timer.setTimer(fn, ms);
      },
    });
    q.start();
    q.enqueue({ ...ITEM, priority: "urgent" });
    await timer.run();
    assert.equal(attempts, 3);
    assert.equal(q.pendingCount(), 0);
    // Fixed 25ms between urgent retries, not 200/400 exponential.
    assert.deepEqual(delays, [0, 25, 25]);
    const [s] = q.getUrgentStats();
    assert.equal(s.endpoint, ITEM.targetUrl);
    assert.equal(s.delivered, 1);
    assert.equal(s.retried, 2);
    assert.equal(s.throttled, 0);
  });

  it("urgent deliveries bypass the per-endpoint concurrency limiter", async () => {
    const timer = manualTimer();
    let releaseNormal!: () => void;
    const order: string[] = [];
    const sender: Sender = async (item) => {
      if (item.id === "normal-1") {
        await new Promise<void>((r) => {
          releaseNormal = r;
        });
        order.push("normal-done");
      } else {
        order.push("urgent-done");
      }
    };
    const q = new RetryQueue({
      sender,
      maxConcurrentPerEndpoint: 1,
      jitterMs: 0,
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue({ ...ITEM, id: "normal-1" });
    q.enqueue({ ...ITEM, id: "urgent-1", priority: "urgent" });
    await timer.run();
    // The urgent delivery completed while the normal one still holds the
    // only concurrency slot — it never queued behind it.
    assert.ok(order.includes("urgent-done"));
    assert.ok(!order.includes("normal-done"));
    assert.equal(q.inFlightCount(), 1);
    releaseNormal();
    await new Promise((r) => setImmediate(r));
    assert.ok(order.includes("normal-done"));
  });

  it("a throttled urgent retry degrades to the normal backoff lane", async () => {
    let nowMs = 0;
    const timer = manualTimer();
    const delays: number[] = [];
    const q = new RetryQueue({
      sender: async () => {
        throw new Error("down");
      },
      baseDelayMs: 100,
      maxDelayMs: 10000,
      maxAttempts: 5,
      jitterMs: 0,
      // One token per second: the initial attempt consumes it, so the first
      // urgent retry finds an empty bucket and must degrade.
      urgent: { retryDelayMs: 10, maxUrgentPerSecond: 1, now: () => nowMs },
      setTimer: (fn, ms) => {
        delays.push(ms);
        return timer.setTimer(fn, ms);
      },
    });
    q.start();
    q.enqueue({ ...ITEM, id: "t-1", priority: "urgent" });
    await timer.run();
    assert.equal(q.getDeadLetter().length, 1);
    // [initial 0, degraded 200, then normal backoff 400, 800, 1600]
    assert.deepEqual(delays, [0, 200, 400, 800, 1600]);
    const [s] = q.getUrgentStats();
    assert.equal(s.throttled, 1);
    assert.equal(s.retried, 0);
    assert.equal(s.delivered, 0);
  });

  it("urgent admission without a token degrades immediately, never drops", async () => {
    const seen: RetryItem[] = [];
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async (item) => {
        seen.push(item);
      },
      jitterMs: 0,
      // A single token: the second urgent item cannot enter the fast lane.
      urgent: { maxUrgentPerSecond: 1, now: () => 0 },
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue({ ...ITEM, id: "a-1", priority: "urgent" });
    q.enqueue({ ...ITEM, id: "a-2", priority: "urgent" });
    await timer.run();
    // Both were still delivered — the throttled one via the normal lane.
    assert.equal(seen.length, 2);
    const [s] = q.getUrgentStats();
    assert.equal(s.delivered, 1);
    assert.equal(s.throttled, 1);
  });

  it("replaying a dead-lettered urgent item keeps its priority", async () => {
    const timer = manualTimer();
    const priorities: Array<string | undefined> = [];
    const q = new RetryQueue({
      sender: async (item) => {
        priorities.push(item.priority);
        throw new Error("down");
      },
      maxAttempts: 2,
      jitterMs: 0,
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue({ ...ITEM, id: "r-1", priority: "urgent" });
    await timer.run();
    assert.equal(q.getDeadLetter().length, 1);
    priorities.length = 0;
    assert.equal(q.replayDeadLetter("r-1"), true);
    await timer.run();
    assert.deepEqual(priorities, ["urgent", "urgent"]);
  });

  it("normal items are unaffected by the urgent lane", async () => {
    const timer = manualTimer();
    const delays: number[] = [];
    let attempts = 0;
    const q = new RetryQueue({
      sender: async () => {
        attempts += 1;
        if (attempts < 2) throw new Error("boom");
      },
      baseDelayMs: 100,
      maxDelayMs: 10000,
      maxAttempts: 3,
      jitterMs: 0,
      setTimer: (fn, ms) => {
        delays.push(ms);
        return timer.setTimer(fn, ms);
      },
    });
    q.start();
    q.enqueue({ ...ITEM }); // no priority -> normal
    await timer.run();
    assert.equal(attempts, 2);
    assert.deepEqual(delays, [0, 200]);
    assert.deepEqual(q.getUrgentStats(), []);
  });

  it("rejects invalid urgent configs", () => {
    assert.throws(() => new RetryQueue({ urgent: { retryDelayMs: -1 } }), RangeError);
    assert.throws(() => new RetryQueue({ urgent: { retryDelayMs: NaN } }), RangeError);
    assert.throws(() => new RetryQueue({ urgent: { maxUrgentPerSecond: 0 } }), RangeError);
  });
});
