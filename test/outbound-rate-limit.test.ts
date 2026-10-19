import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { OutboundRateLimiter } from "../src/outbound-ratelimit.ts";

const URL_A = "http://localhost:9999/a";
const URL_B = "http://localhost:9999/b";

/**
 * Manual timer with single-step control: rate-limit delays re-arm
 * timers, so the tests advance one wave at a time instead of draining
 * everything.
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
    async step() {
      const fns = pending.splice(0);
      for (const f of fns) f();
      await new Promise((r) => setImmediate(r));
    },
  };
}

function item(id: string, targetUrl: string) {
  return { id, payload: Buffer.from("x"), targetUrl, headers: {} };
}

describe("OutboundRateLimiter", () => {
  it("rejects invalid configuration", () => {
    assert.throws(() => new OutboundRateLimiter({ refillRps: 0, burst: 1 }), RangeError);
    assert.throws(() => new OutboundRateLimiter({ refillRps: -1, burst: 1 }), RangeError);
    assert.throws(() => new OutboundRateLimiter({ refillRps: Infinity, burst: 1 }), RangeError);
    assert.throws(() => new OutboundRateLimiter({ refillRps: NaN, burst: 1 }), RangeError);
    assert.throws(() => new OutboundRateLimiter({ refillRps: 1, burst: 0 }), RangeError);
    assert.throws(() => new OutboundRateLimiter({ refillRps: 1, burst: -5 }), RangeError);
    assert.throws(() => new OutboundRateLimiter({ refillRps: 1, burst: Infinity }), RangeError);
    // @ts-expect-error intentionally invalid
    assert.throws(() => new OutboundRateLimiter(undefined), RangeError);
    // @ts-expect-error intentionally invalid
    assert.throws(() => new OutboundRateLimiter(null), RangeError);
  });

  it("starts with a full bucket and refills lazily per endpoint", () => {
    let now = 0;
    const l = new OutboundRateLimiter({ refillRps: 2, burst: 2, now: () => now }); // 2 tokens/sec
    assert.equal(l.refillPerSecond(), 2);
    assert.equal(l.burstSize(), 2);
    assert.equal(l.take(URL_A).ok, true);
    assert.equal(l.take(URL_A).ok, true);
    const denied = l.take(URL_A);
    assert.equal(denied.ok, false);
    if (!denied.ok) assert.equal(denied.retryAfterMs, 500); // one token refills in 500ms
    assert.equal(l.take(URL_B).ok, true); // other endpoints have their own budget
    now = 500;
    assert.equal(l.take(URL_A).ok, true); // refilled
  });

  it("clamps backward clock jumps instead of granting extra tokens", () => {
    let now = 10_000;
    const l = new OutboundRateLimiter({ refillRps: 1, burst: 2, now: () => now });
    assert.equal(l.take(URL_A).ok, true);
    now = 0; // clock jumps backward
    assert.equal(l.take(URL_A).ok, true); // only the remaining token, no bonus
    assert.equal(l.take(URL_A).ok, false);
  });

  it("exposes per-endpoint throttle counts in stats", () => {
    let now = 0;
    const l = new OutboundRateLimiter({ refillRps: 1, burst: 1, now: () => now });
    assert.equal(l.take(URL_A).ok, true);
    assert.equal(l.take(URL_A).ok, false);
    assert.equal(l.take(URL_A).ok, false);
    const rows = l.stats();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].endpoint, URL_A);
    assert.equal(rows[0].throttled, 2);
    assert.equal(rows[0].refillRps, 1);
    assert.equal(rows[0].burst, 1);
  });
});

describe("RetryQueue per-endpoint outbound rate limiting", () => {
  it("delays over-limit attempts instead of dropping them, and counts the delay", async () => {
    let now = 0;
    const t = manualTimer();
    let calls = 0;
    const sender: Sender = async () => {
      calls += 1;
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      random: () => 0, // no jitter: delays are exactly retryAfterMs
      outboundRateLimit: { refillRps: 1, burst: 1, now: () => now }, // 1 token/sec
    });
    q.enqueue(item("a", URL_A));
    q.enqueue(item("b", URL_A));
    q.start();
    await t.step();
    assert.equal(calls, 1); // only "a" fit the budget
    assert.equal(q.pendingCount(), 1); // "b" is delayed, not dropped
    assert.deepEqual(q.getOutboundRateLimitStats(), [
      { endpoint: URL_A, throttled: 1, refillRps: 1, burst: 1 },
    ]);
    now += 1000; // one token refills
    await t.step();
    assert.equal(calls, 2); // "b" is delivered once budget is available
    assert.equal(q.pendingCount(), 0);
    q.stop();
  });

  it("rate-limit delays never burn the retry budget: a delayed item is still delivered", async () => {
    let now = 0;
    const t = manualTimer();
    let calls = 0;
    const sender: Sender = async () => {
      calls += 1;
      throw new Error("downstream down");
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      random: () => 0,
      maxAttempts: 1,
      outboundRateLimit: { refillRps: 1, burst: 1, now: () => now },
    });
    q.enqueue(item("a", URL_A));
    q.enqueue(item("b", URL_A));
    q.start();
    await t.step(); // "a" sends (consumes the only token), fails -> dead letter
    assert.equal(q.getDeadLetter().length, 1);
    await t.step(); // "b" finds an empty bucket -> delayed, attempt untouched
    assert.equal(q.getDeadLetter().length, 1);
    assert.equal(calls, 1);
    now += 1000;
    await t.step(); // "b" sends now -> fails on its real attempt -> dead letter
    assert.equal(calls, 2);
    assert.equal(q.getDeadLetter().length, 2);
    assert.ok(
      (q.getOutboundRateLimitStats() ?? []).some((s) => s.endpoint === URL_A && s.throttled >= 1)
    );
    q.stop();
  });

  it("budgets are isolated per endpoint", async () => {
    const t = manualTimer();
    let calls = 0;
    const sender: Sender = async () => {
      calls += 1;
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      random: () => 0,
      outboundRateLimit: { refillRps: 1, burst: 1 },
    });
    q.enqueue(item("a", URL_A));
    q.enqueue(item("b", URL_B));
    q.start();
    await t.step();
    assert.equal(calls, 2); // each endpoint has its own budget
    assert.deepEqual(q.getOutboundRateLimitStats(), [
      { endpoint: URL_A, throttled: 0, refillRps: 1, burst: 1 },
      { endpoint: URL_B, throttled: 0, refillRps: 1, burst: 1 },
    ]);
    q.stop();
  });

  it("unlimited by default: no outboundRateLimit configured means no delays", async () => {
    const t = manualTimer();
    let calls = 0;
    const sender: Sender = async () => {
      calls += 1;
    };
    const q = new RetryQueue({ sender, setTimer: t.setTimer });
    for (let i = 0; i < 10; i++) q.enqueue(item(`i${i}`, URL_A));
    q.start();
    await t.step();
    assert.equal(calls, 10);
    assert.equal(q.getOutboundRateLimitStats(), undefined);
    q.stop();
  });

  it("emits relay_ratelimit_throttled_total only after a throttle (activity-gated)", async () => {
    let now = 0;
    const t = manualTimer();
    const sender: Sender = async () => {};
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      random: () => 0,
      outboundRateLimit: { refillRps: 1, burst: 1, now: () => now },
    });
    assert.ok(!q.renderMetrics().includes("relay_ratelimit_throttled_total"));
    q.enqueue(item("a", URL_A));
    q.enqueue(item("b", URL_A));
    q.start();
    await t.step();
    assert.equal(q.pendingCount(), 1);
    const exposition = q.renderMetrics();
    assert.ok(exposition.includes("# HELP relay_ratelimit_throttled_total"));
    assert.ok(
      exposition.includes(`relay_ratelimit_throttled_total{endpoint="${URL_A}"} 1`)
    );
    q.stop();
  });
});
