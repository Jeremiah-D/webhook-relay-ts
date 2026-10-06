import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { RetryQueue, type Sender } from "../src/retry.ts";

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
  id: "item-1",
  payload: Buffer.from("hello"),
  targetUrl: "http://localhost:9999/hook",
  headers: { "content-type": "application/json" },
};

describe("retry", () => {
  it("delivers after transient failures with increasing backoff", async () => {
    const timer = manualTimer();
    const delays: number[] = [];
    const realSetTimer = timer.setTimer;
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
      setTimer: (fn, ms) => {
        delays.push(ms);
        return realSetTimer(fn, ms);
      },
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();
    assert.equal(attempts, 3);
    assert.equal(q.pendingCount(), 0);
    assert.equal(q.getDeadLetter().length, 0);
    // Exponential backoff: base*2^1=200, base*2^2=400
    assert.deepEqual(delays, [0, 200, 400]);
  });

  it("moves to dead letter after maxAttempts are exhausted", async () => {
    const timer = manualTimer();
    let attempts = 0;
    const dead: Array<{ item: unknown; attempts: number }> = [];
    const q = new RetryQueue({
      sender: async () => {
        attempts += 1;
        throw new Error("always fails");
      },
      baseDelayMs: 10,
      maxAttempts: 3,
      jitterMs: 0,
      setTimer: timer.setTimer,
      onDeadLetter: (item, n) => dead.push({ item, attempts: n }),
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();
    assert.equal(attempts, 3);
    assert.equal(q.pendingCount(), 0);
    assert.equal(q.getDeadLetter().length, 1);
    assert.equal(q.getDeadLetter()[0].id, "item-1");
    assert.equal(dead.length, 1);
    assert.equal(dead[0].attempts, 3);
  });

  it("delays are capped at maxDelayMs", () => {
    const q = new RetryQueue({ baseDelayMs: 1000, maxDelayMs: 5000, jitterMs: 0 });
    assert.ok(q.delayForAttempt(0) <= 5000);
    assert.ok(q.delayForAttempt(10) <= 5000);
    assert.equal(q.delayForAttempt(10), 5000);
    assert.equal(q.delayForAttempt(1), 2000);
  });
});
