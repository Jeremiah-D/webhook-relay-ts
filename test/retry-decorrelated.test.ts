import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { assertValidRetryPolicy } from "../src/retry-policy.ts";

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

const URL = "http://localhost:9999/hook";
const ITEM = {
  id: "item-decorrelated-1",
  payload: Buffer.from("hello"),
  targetUrl: URL,
  headers: { "content-type": "application/json" },
};

/** Queue with the decorrelated strategy and a constant random source. */
function decorrelatedQueue(random: () => number, extra: Record<string, unknown> = {}) {
  return new RetryQueue({
    sender: async () => {},
    baseDelayMs: 100,
    maxDelayMs: 10000,
    maxAttempts: 5,
    jitterStrategy: "decorrelated",
    random,
    ...extra,
  });
}

describe("retry: decorrelated jitter (WR-193)", () => {
  it("first step starts at base: random()=0 sleeps base, random()=1 sleeps min(cap, 3*base)", () => {
    const zero = decorrelatedQueue(() => 0);
    // attempt=1: cap = min(10000, 100*2) = 200; walk starts at base=100.
    assert.equal(zero.delayForAttempt(1, undefined, undefined, "s-zero"), 100);
    const one = decorrelatedQueue(() => 1);
    // uniform(100, 300) at its top, capped at 200.
    assert.equal(one.delayForAttempt(1, undefined, undefined, "s-one"), 200);
  });

  it("chains the walk through the sequence key: prev sleep feeds the next step", () => {
    const q = decorrelatedQueue(() => 0.5);
    // step 1: prev=100 -> 100 + 0.5*(300-100) = 200 (cap 200)
    assert.equal(q.delayForAttempt(1, undefined, undefined, "walk"), 200);
    // step 2: prev=200 -> 100 + 0.5*(600-100) = 350 (cap 400)
    assert.equal(q.delayForAttempt(2, undefined, undefined, "walk"), 350);
    // step 3: prev=350 -> 100 + 0.5*(1050-100) = 575 (cap 800)
    assert.equal(q.delayForAttempt(3, undefined, undefined, "walk"), 575);
  });

  it("never exceeds the per-attempt cap, even when 3*prev overshoots it", () => {
    const q = new RetryQueue({
      sender: async () => {},
      baseDelayMs: 100,
      maxDelayMs: 500,
      maxAttempts: 5,
      jitterStrategy: "decorrelated",
      random: () => 1,
    });
    // attempt=1: cap=200, prev=100 -> min(200, 300) = 200
    assert.equal(q.delayForAttempt(1, undefined, undefined, "capped"), 200);
    // attempt=2: cap=400, prev=200 -> min(400, 600) = 400
    assert.equal(q.delayForAttempt(2, undefined, undefined, "capped"), 400);
    // attempt=10: cap=min(500, 102400)=500, prev=400 -> min(500, 1200) = 500
    assert.equal(q.delayForAttempt(10, undefined, undefined, "capped"), 500);
  });

  it("calls without a sequence key are independent first steps from base", () => {
    const q = decorrelatedQueue(() => 0.5);
    const first = q.delayForAttempt(1);
    const second = q.delayForAttempt(1);
    assert.equal(first, second);
    assert.equal(first, 200);
  });

  it("different sequence keys walk independently", () => {
    const q = decorrelatedQueue(() => 0.5);
    assert.equal(q.delayForAttempt(1, undefined, undefined, "a"), 200);
    assert.equal(q.delayForAttempt(1, undefined, undefined, "b"), 200);
    // "a" advanced to 200; "b" is still on its first step.
    assert.equal(q.delayForAttempt(2, undefined, undefined, "a"), 350);
    assert.equal(q.delayForAttempt(2, undefined, undefined, "b"), 350);
  });

  it("runs the decorrelated walk end-to-end through the retry path", async () => {
    const timer = manualTimer();
    const delays: number[] = [];
    const realSetTimer = timer.setTimer;
    let attempts = 0;
    const dead: string[] = [];
    const q = decorrelatedQueue(() => 0.5, {
      sender: async () => {
        attempts += 1;
        throw new Error("always fails");
      },
      maxAttempts: 4,
      setTimer: (fn: () => void, ms: number) => {
        delays.push(ms);
        return realSetTimer(fn, ms);
      },
      onDeadLetter: () => dead.push("dl"),
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();
    assert.equal(attempts, 4);
    assert.deepEqual(dead, ["dl"]);
    // Initial dispatch (0) then the decorrelated walk: 200 -> 350 -> 575.
    assert.deepEqual(delays, [0, 200, 350, 575]);
  });

  it("a named retry policy can select the decorrelated strategy per endpoint", () => {
    const q = decorrelatedQueue(() => 0.5);
    q.registerRetryPolicy("deco", {
      maxAttempts: 5,
      baseDelayMs: 50,
      maxDelayMs: 10000,
      jitterStrategy: "decorrelated",
    });
    q.setEndpointRetryPolicy(URL, "deco");
    // Policy base=50: cap=min(10000, 50*2)=100; prev=50 -> 50 + 0.5*(150-50) = 100.
    assert.equal(q.delayForAttempt(1, URL, undefined, "policy-walk"), 100);
    // Walk continues from the policy-scoped prev: prev=100 -> 50 + 0.5*(300-50) = 175.
    assert.equal(q.delayForAttempt(2, URL, undefined, "policy-walk"), 175);
  });

  it("rejects unknown strategies with RangeError at every entry point", () => {
    // Constructor (also covered in retry.test.ts for "bogus"; here the
    // decorrelated value itself must be accepted).
    decorrelatedQueue(() => 0.5);
    assert.throws(
      () => new RetryQueue({ sender: async () => {}, jitterStrategy: "sometimes" as never }),
      RangeError
    );
    // Named-policy registration.
    assert.throws(
      () =>
        assertValidRetryPolicy("x", {
          maxAttempts: 3,
          baseDelayMs: 100,
          maxDelayMs: 1000,
          jitterStrategy: "sometimes",
        }),
      RangeError
    );
    // Hot-reload endpoint patch.
    const q = new RetryQueue({ sender: async () => {}, baseDelayMs: 100, maxAttempts: 5 });
    assert.throws(
      () => q.updateEndpointConfig(URL, { retry: { jitterStrategy: "sometimes" as never } }),
      RangeError
    );
    // And the hot-reload path accepts "decorrelated".
    const diff = q.updateEndpointConfig(URL, { retry: { jitterStrategy: "decorrelated" } });
    assert.deepEqual(diff, [{ field: "retry.jitterStrategy", from: "additive", to: "decorrelated" }]);
    assert.equal(q.retryConfig().jitterStrategy, "decorrelated");
  });

  it("stays orthogonal to additive and full: their math is unchanged", () => {
    const additive = new RetryQueue({
      sender: async () => {},
      baseDelayMs: 100,
      maxDelayMs: 10000,
      maxAttempts: 5,
      jitterMs: 100,
      jitterStrategy: "additive",
      random: () => 0.5,
    });
    // min(10000, 100*2 + 0.5*100) = 250
    assert.equal(additive.delayForAttempt(1), 250);
    const full = new RetryQueue({
      sender: async () => {},
      baseDelayMs: 100,
      maxDelayMs: 10000,
      maxAttempts: 5,
      jitterStrategy: "full",
      random: () => 0.5,
    });
    // 0.5 * min(10000, 200) = 100
    assert.equal(full.delayForAttempt(1), 100);
  });
});
