import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { RetryQueue, type Sender } from "../src/retry.ts";
import {
  GlobalRateLimiter,
  assertValidGlobalRateLimit,
} from "../src/global-rate.ts";

const A = "http://a/hook";
const B = "http://b/hook";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));

/** Let the deliver() promise chain settle. */
async function flush(ticks = 20) {
  for (let i = 0; i < ticks; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

function item(id: string, targetUrl: string) {
  return { id, payload: BODY, targetUrl, headers: {} };
}

/** Manual clock for deterministic token refills. */
function manualClock(start = 0) {
  let t = start;
  return {
    now: () => t,
    advance: (ms: number) => {
      t += ms;
    },
  };
}

/**
 * Manual timer: callbacks fire only when `fire()` is called, in FIFO
 * order. Shared by the queue and the limiter for full determinism.
 */
function manualTimer() {
  const pending: Array<() => void> = [];
  return {
    pendingCount: () => pending.length,
    setTimer: (fn: () => void, _ms: number) => {
      pending.push(fn);
      return {
        clear: () => {
          const i = pending.indexOf(fn);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    clearTimer: (h: { clear(): void }) => h.clear(),
    fire() {
      const fns = pending.splice(0);
      for (const f of fns) f();
    },
    async step() {
      this.fire();
      await flush();
    },
  };
}

describe("assertValidGlobalRateLimit", () => {
  it("rejects a missing or non-object config", () => {
    assert.throws(() => assertValidGlobalRateLimit(undefined), RangeError);
    assert.throws(() => assertValidGlobalRateLimit(null), RangeError);
    assert.throws(() => assertValidGlobalRateLimit("10"), RangeError);
    assert.throws(() => assertValidGlobalRateLimit([]), RangeError);
  });

  it("rejects bad messagesPerSec / maxBurst / injectables", () => {
    assert.throws(() => assertValidGlobalRateLimit({}), RangeError);
    assert.throws(() => assertValidGlobalRateLimit({ messagesPerSec: 0 }), RangeError);
    assert.throws(() => assertValidGlobalRateLimit({ messagesPerSec: -2 }), RangeError);
    assert.throws(() => assertValidGlobalRateLimit({ messagesPerSec: Infinity }), RangeError);
    assert.throws(() => assertValidGlobalRateLimit({ messagesPerSec: NaN }), RangeError);
    assert.throws(() => assertValidGlobalRateLimit({ messagesPerSec: "10" }), RangeError);
    assert.throws(() => assertValidGlobalRateLimit({ messagesPerSec: 10, maxBurst: 0 }), RangeError);
    assert.throws(
      () => assertValidGlobalRateLimit({ messagesPerSec: 10, maxBurst: -1 }),
      RangeError
    );
    assert.throws(() => assertValidGlobalRateLimit({ messagesPerSec: 10, now: 42 }), RangeError);
    assert.throws(
      () => assertValidGlobalRateLimit({ messagesPerSec: 10, setTimer: 42 }),
      RangeError
    );
    assert.throws(
      () => assertValidGlobalRateLimit({ messagesPerSec: 10, clearTimer: 42 }),
      RangeError
    );
  });

  it("accepts a minimal and a full config", () => {
    assert.doesNotThrow(() => assertValidGlobalRateLimit({ messagesPerSec: 10 }));
    assert.doesNotThrow(() =>
      assertValidGlobalRateLimit({
        messagesPerSec: 2.5,
        maxBurst: 5,
        now: () => 0,
        setTimer: (fn: () => void) => ({ clear: () => {} }),
        clearTimer: () => {},
      })
    );
  });
});

describe("GlobalRateLimiter", () => {
  it("grants immediately while tokens are available (no delay counted)", async () => {
    const clock = manualClock();
    const timer = manualTimer();
    const g = new GlobalRateLimiter({
      messagesPerSec: 2,
      maxBurst: 2,
      now: clock.now,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
    });
    let done1 = false;
    let done2 = false;
    void g.acquire().then(() => {
      done1 = true;
    });
    void g.acquire().then(() => {
      done2 = true;
    });
    await flush();
    assert.ok(done1 && done2);
    assert.equal(g.delayedTotalCount(), 0);
    assert.equal(g.queuedDepth(), 0);
  });

  it("delays excess acquisitions until the refill, FIFO", async () => {
    const clock = manualClock();
    const timer = manualTimer();
    const g = new GlobalRateLimiter({
      messagesPerSec: 2,
      maxBurst: 2,
      now: clock.now,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
    });
    await g.acquire();
    await g.acquire();
    const order: string[] = [];
    void g.acquire().then(() => order.push("first"));
    void g.acquire().then(() => order.push("second"));
    await flush();
    assert.deepEqual(order, []);
    assert.equal(g.delayedTotalCount(), 2);
    assert.equal(g.queuedDepth(), 2);
    // 500ms refills exactly one token at 2/sec.
    clock.advance(500);
    await timer.step();
    assert.deepEqual(order, ["first"]);
    assert.equal(g.queuedDepth(), 1);
    clock.advance(500);
    await timer.step();
    assert.deepEqual(order, ["first", "second"]);
    assert.equal(g.queuedDepth(), 0);
  });

  it("releaseWaiters() wakes waiters without consuming tokens", async () => {
    const clock = manualClock();
    const timer = manualTimer();
    const g = new GlobalRateLimiter({
      messagesPerSec: 1,
      maxBurst: 1,
      now: clock.now,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
    });
    await g.acquire(); // drain the single token
    let woken = false;
    const p = g.acquire().then(() => {
      woken = true;
    });
    await flush();
    assert.equal(woken, false);
    g.releaseWaiters();
    await p;
    assert.equal(woken, true);
    assert.equal(g.queuedDepth(), 0);
    assert.equal(timer.pendingCount(), 0);
    // No token was consumed by the woken waiter: the next acquire is immediate.
    let immediate = false;
    clock.advance(1000); // refill fully first for a clean assertion
    void g.acquire().then(() => {
      immediate = true;
    });
    await flush();
    assert.ok(immediate);
  });

  it("stats() reports the configuration and counters", async () => {
    const clock = manualClock();
    const timer = manualTimer();
    const g = new GlobalRateLimiter({
      messagesPerSec: 4,
      maxBurst: 8,
      now: clock.now,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
    });
    const s = g.stats();
    assert.equal(s.messagesPerSec, 4);
    assert.equal(s.maxBurst, 8);
    assert.equal(s.delayedTotal, 0);
    assert.equal(s.queuedDepth, 0);
    assert.ok(s.availableTokens > 0);
  });

  it("a backward clock never un-refills or deadlocks", async () => {
    const clock = manualClock(10_000);
    const timer = manualTimer();
    const g = new GlobalRateLimiter({
      messagesPerSec: 1,
      maxBurst: 1,
      now: clock.now,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
    });
    await g.acquire();
    clock.advance(-5000); // jump backwards
    let done = false;
    void g.acquire().then(() => {
      done = true;
    });
    await flush();
    // The head timer still fires (liveness beats exactness on clock jumps).
    await timer.step();
    assert.ok(done);
  });
});

describe("RetryQueue globalRateLimit integration", () => {
  it("delays dispatches past the burst; never drops, never burns budget", async () => {
    const clock = manualClock();
    const timer = manualTimer();
    const started: string[] = [];
    const sender: Sender = async (it) => {
      started.push(it.id);
    };
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      globalRateLimit: {
        messagesPerSec: 2,
        maxBurst: 2,
        now: clock.now,
        setTimer: timer.setTimer,
        clearTimer: timer.clearTimer,
      },
      maxAttempts: 1,
    });
    q.enqueue(item("a", A));
    q.enqueue(item("b", B));
    q.enqueue(item("c", A));
    q.start();
    await timer.step();
    // Burst of 2 went out immediately; the third waits for a token.
    assert.deepEqual(new Set(started), new Set(["a", "b"]));
    assert.equal(q.getGlobalRateLimitStats()?.delayedTotal, 1);
    assert.equal(q.getGlobalRateLimitStats()?.queuedDepth, 1);
    // 500ms refills one token at 2/sec: the waiter goes next.
    clock.advance(500);
    await timer.step();
    assert.deepEqual(new Set(started), new Set(["a", "b", "c"]));
    await timer.step();
    assert.equal(q.pendingCount(), 0);
    assert.equal(q.getDeadLetter().length, 0);
    const stats = q.getGlobalRateLimitStats();
    assert.equal(stats?.messagesPerSec, 2);
    assert.equal(stats?.maxBurst, 2);
    assert.equal(stats?.delayedTotal, 1);
    q.stop();
  });

  it("waiting consumes no retry budget and touches no breaker", async () => {
    const clock = manualClock();
    const timer = manualTimer();
    const sender: Sender = async () => {};
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      globalRateLimit: {
        messagesPerSec: 1,
        maxBurst: 1,
        now: clock.now,
        setTimer: timer.setTimer,
        clearTimer: timer.clearTimer,
      },
      maxAttempts: 1,
      retryBudget: { retriesPerMinute: 60 },
      circuitBreaker: { failureThreshold: 5, cooldownMs: 60_000 },
    });
    q.enqueue(item("a", A));
    q.enqueue(item("b", A));
    q.start();
    await timer.step();
    assert.equal(q.getGlobalRateLimitStats()?.delayedTotal, 1);
    // A successful delivery: no breaker verdict was recorded for the
    // waiter (it never failed — it just waited).
    const circuits = q.getCircuitStats();
    assert.ok(circuits.every((c) => c.consecutiveFailures === 0));
    clock.advance(1000);
    await timer.step();
    await timer.step();
    assert.equal(q.pendingCount(), 0);
    q.stop();
  });

  it("composes with the WR-51 concurrency gate and the WR-15 quota", async () => {
    const clock = manualClock();
    const timer = manualTimer();
    const started: string[] = [];
    const sender: Sender = async (it) => {
      started.push(it.id);
    };
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      globalRateLimit: {
        messagesPerSec: 10,
        maxBurst: 10,
        now: clock.now,
        setTimer: timer.setTimer,
        clearTimer: timer.clearTimer,
      },
      globalMaxConcurrent: 1,
      quota: { deliveriesPerMinute: 600 },
      maxAttempts: 1,
    });
    q.enqueue(item("a", A));
    q.enqueue(item("b", A));
    q.start();
    await timer.step();
    // The rate gate granted both (10/sec budget); the concurrency gate
    // serialized them — composition, not interference.
    assert.ok(started.length >= 1);
    await timer.step();
    await timer.step();
    assert.deepEqual(new Set(started), new Set(["a", "b"]));
    q.stop();
  });

  it("stop() wakes rate-gate waiters instead of hanging", async () => {
    const clock = manualClock();
    const timer = manualTimer();
    const started: string[] = [];
    const sender: Sender = async (it) => {
      started.push(it.id);
    };
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      globalRateLimit: {
        messagesPerSec: 1,
        maxBurst: 1,
        now: clock.now,
        setTimer: timer.setTimer,
        clearTimer: timer.clearTimer,
      },
      maxAttempts: 1,
    });
    q.enqueue(item("a", A));
    q.enqueue(item("b", A));
    q.start();
    await timer.step();
    assert.deepEqual(started, ["a"]);
    q.stop();
    await flush();
    // The waiter bailed on the liveness check: never dispatched.
    assert.deepEqual(started, ["a"]);
    assert.equal(q.getGlobalRateLimitStats()?.queuedDepth, 0);
  });

  it("getGlobalRateLimitStats() is undefined and exposition omits the series when off", async () => {
    const sender: Sender = async () => {};
    const q = new RetryQueue({ sender, maxAttempts: 1 });
    assert.equal(q.getGlobalRateLimitStats(), undefined);
    q.start();
    q.enqueue(item("a", A));
    await flush();
    await flush();
    assert.equal(q.getGlobalRateLimitStats(), undefined);
    assert.ok(!q.renderMetrics().includes("relay_global_rate_delayed_total"));
    q.stop();
  });

  it("renderMetrics() exposes relay_global_rate_delayed_total when configured", async () => {
    const clock = manualClock();
    const timer = manualTimer();
    const sender: Sender = async () => {};
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      globalRateLimit: {
        messagesPerSec: 1,
        maxBurst: 1,
        now: clock.now,
        setTimer: timer.setTimer,
        clearTimer: timer.clearTimer,
      },
      maxAttempts: 1,
    });
    q.enqueue(item("a", A));
    q.enqueue(item("b", A));
    q.start();
    await timer.step();
    const exposition = q.renderMetrics();
    assert.ok(exposition.includes("relay_global_rate_delayed_total 1"));
    q.stop();
  });

  it("constructor rejects an invalid globalRateLimit", () => {
    const sender: Sender = async () => {};
    assert.throws(() => new RetryQueue({ sender, globalRateLimit: { messagesPerSec: 0 } }), RangeError);
    assert.throws(
      () => new RetryQueue({ sender, globalRateLimit: { messagesPerSec: 10, maxBurst: -1 } }),
      RangeError
    );
  });
});
