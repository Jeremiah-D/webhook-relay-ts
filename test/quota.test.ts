import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { EndpointQuota } from "../src/quota.ts";

const URL_A = "http://localhost:9999/a";
const URL_B = "http://localhost:9999/b";

/**
 * Manual timer with single-step control: quota delays re-arm timers, so
 * the tests advance one wave at a time instead of draining everything.
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

describe("EndpointQuota", () => {
  it("rejects invalid configuration", () => {
    assert.throws(() => new EndpointQuota(0), RangeError);
    assert.throws(() => new EndpointQuota(-1), RangeError);
    assert.throws(() => new EndpointQuota(Infinity), RangeError);
    assert.throws(() => new EndpointQuota(NaN), RangeError);
  });

  it("starts with a full bucket and refills lazily per endpoint", () => {
    let now = 0;
    const q = new EndpointQuota(60, () => now); // 1 token/sec
    assert.equal(q.limit(), 60);
    for (let i = 0; i < 60; i++) assert.equal(q.take(URL_A), true);
    assert.equal(q.take(URL_A), false); // bucket empty
    assert.equal(q.msUntilToken(URL_A), 1000); // one token refills in 1s
    assert.equal(q.take(URL_B), true); // other endpoints have their own budget
    assert.equal(q.msUntilToken(URL_B), 0);
    now = 1000;
    assert.equal(q.take(URL_A), true); // refilled
  });

  it("clamps backward clock jumps instead of granting extra tokens", () => {
    let now = 10_000;
    const q = new EndpointQuota(60, () => now);
    q.take(URL_A);
    now = 0; // clock jumps backward
    assert.equal(q.take(URL_A), true); // only the remaining 59 tokens, no bonus
    for (let i = 0; i < 58; i++) assert.equal(q.take(URL_A), true);
    assert.equal(q.take(URL_A), false);
  });
});

describe("RetryQueue per-endpoint delivery quota", () => {
  it("delays over-budget attempts instead of dropping them, and counts the delay", async () => {
    let now = 0;
    const t = manualTimer();
    let calls = 0;
    const sender: Sender = async () => {
      calls += 1;
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      random: () => 0, // no jitter: quota delays are exactly msUntilToken
      quota: { deliveriesPerMinute: 1, now: () => now }, // 1 token/min
    });
    q.enqueue(item("a", URL_A));
    q.enqueue(item("b", URL_A));
    q.start();
    await t.step();
    assert.equal(calls, 1); // only "a" fit the budget
    assert.equal(q.pendingCount(), 1); // "b" is delayed, not dropped
    assert.deepEqual(q.getQuotaStats(), [{ endpoint: URL_A, delayed: 1 }]);
    now += 60_000; // next minute of budget refills
    await t.step();
    assert.equal(calls, 2); // "b" is delivered once budget is available
    assert.equal(q.pendingCount(), 0);
    q.stop();
  });

  it("quota delays never burn the retry budget: a delayed item is still delivered", async () => {
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
      quota: { deliveriesPerMinute: 1, now: () => now },
    });
    q.enqueue(item("a", URL_A));
    q.enqueue(item("b", URL_A));
    q.start();
    await t.step(); // "a" sends (consumes the only token), fails -> dead letter
    assert.equal(q.getDeadLetter().length, 1);
    await t.step(); // "b" finds an empty bucket -> delayed, attempt untouched
    assert.equal(q.getDeadLetter().length, 1);
    assert.equal(calls, 1);
    now += 60_000;
    await t.step(); // "b" sends now -> fails on its real attempt -> dead letter
    assert.equal(calls, 2);
    assert.equal(q.getDeadLetter().length, 2);
    assert.ok(q.getQuotaStats().some((s) => s.endpoint === URL_A && s.delayed >= 1));
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
      quota: { deliveriesPerMinute: 1 },
    });
    q.enqueue(item("a", URL_A));
    q.enqueue(item("b", URL_B));
    q.start();
    await t.step();
    assert.equal(calls, 2); // each endpoint has its own budget
    assert.deepEqual(q.getQuotaStats(), []);
    q.stop();
  });

  it("unlimited by default: no quota configured means no delays", async () => {
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
    assert.deepEqual(q.getQuotaStats(), []);
    q.stop();
  });

  it("rejects an invalid quota through the queue options", () => {
    assert.throws(() => new RetryQueue({ quota: { deliveriesPerMinute: 0 } }), RangeError);
  });
});
