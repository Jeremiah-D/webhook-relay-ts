import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  RetryQueue,
  AdaptiveBackoffController,
  DEFAULT_ADAPTIVE_MIN_BASE_MS,
  DEFAULT_ADAPTIVE_MAX_BASE_MS,
  type Sender,
} from "../src/retry.ts";

/**
 * WR-59 tests. The controller is outcome-driven — no clock, no randomness —
 * so unit tests are deterministic by construction; the queue-level tests
 * inject the timer and the jitter random like the other backoff tests.
 */

/** Deterministic timer: `run()` executes pending callbacks immediately. */
function manualTimer() {
  const pending: Array<() => void> = [];
  return {
    setTimer: (fn: () => void, _ms: number) => {
      pending.push(fn);
      return {
        clear: () => {
          const i = pending.indexOf(fn);
          if (i >= 0) pending.splice(i, 1);
        },
      };
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

function item(id: string, tenantId?: string) {
  return {
    id,
    payload: Buffer.from("hello"),
    targetUrl: URL,
    headers: {},
    ...(tenantId !== undefined ? { tenantId } : {}),
  };
}

describe("WR-59 AdaptiveBackoffController (unit)", () => {
  it("starts at the resting base for unknown endpoints", () => {
    const c = new AdaptiveBackoffController(1000, {});
    assert.equal(c.baseFor(URL), 1000);
    assert.deepEqual(c.stats(), []);
  });

  it("doubles per failure toward the ceiling, then clamps", () => {
    const c = new AdaptiveBackoffController(1000, { minBaseMs: 100, maxBaseMs: 8000 });
    c.recordOutcome(URL, false);
    assert.equal(c.baseFor(URL), 2000);
    c.recordOutcome(URL, false);
    assert.equal(c.baseFor(URL), 4000);
    c.recordOutcome(URL, false);
    assert.equal(c.baseFor(URL), 8000);
    c.recordOutcome(URL, false);
    assert.equal(c.baseFor(URL), 8000); // clamped at the ceiling
    const [row] = c.stats();
    assert.equal(row.endpoint, URL);
    assert.equal(row.baseMs, 8000);
    assert.equal(row.consecutiveFailures, 4);
    assert.equal(row.consecutiveSuccesses, 0);
  });

  it("halves per success toward the floor, then clamps", () => {
    const c = new AdaptiveBackoffController(1000, { minBaseMs: 100, maxBaseMs: 8000 });
    for (let i = 0; i < 3; i++) c.recordOutcome(URL, false); // base: 8000
    c.recordOutcome(URL, true);
    assert.equal(c.baseFor(URL), 4000);
    for (let i = 0; i < 10; i++) c.recordOutcome(URL, true);
    assert.equal(c.baseFor(URL), 100); // clamped at the floor
    const [row] = c.stats();
    assert.equal(row.baseMs, 100);
    assert.equal(row.consecutiveFailures, 0);
    assert.equal(row.consecutiveSuccesses, 11);
  });

  it("keeps endpoints independent", () => {
    const c = new AdaptiveBackoffController(1000, {});
    c.recordOutcome("http://a/hook", false);
    c.recordOutcome("http://a/hook", false);
    assert.equal(c.baseFor("http://a/hook"), 4000);
    assert.equal(c.baseFor("http://b/hook"), 1000);
  });

  it("reset() forgets adapted state", () => {
    const c = new AdaptiveBackoffController(1000, {});
    c.recordOutcome(URL, false);
    assert.equal(c.baseFor(URL), 2000);
    c.reset(URL);
    assert.equal(c.baseFor(URL), 1000);
    assert.deepEqual(c.stats(), []);
    c.recordOutcome(URL, false);
    c.reset();
    assert.deepEqual(c.stats(), []);
  });

  it("reads the resting base live (queue hot-reload stays in sync)", () => {
    let base = 1000;
    const c = new AdaptiveBackoffController(() => base, {});
    assert.equal(c.baseFor(URL), 1000);
    base = 250;
    assert.equal(c.baseFor(URL), 250);
    c.recordOutcome(URL, false);
    assert.equal(c.baseFor(URL), 500); // adapted from the live resting base
  });

  it("rejects invalid options with RangeError", () => {
    assert.throws(() => new AdaptiveBackoffController(1000, { minBaseMs: 0 }), RangeError);
    assert.throws(() => new AdaptiveBackoffController(1000, { minBaseMs: -5 }), RangeError);
    assert.throws(
      () => new AdaptiveBackoffController(1000, { minBaseMs: 100, maxBaseMs: 50 }),
      RangeError
    );
    assert.throws(() => new AdaptiveBackoffController(1000, { upFactor: 1 }), RangeError);
    assert.throws(() => new AdaptiveBackoffController(1000, { upFactor: 0.5 }), RangeError);
    assert.throws(() => new AdaptiveBackoffController(1000, { downFactor: 0 }), RangeError);
    assert.throws(() => new AdaptiveBackoffController(1000, { downFactor: 1 }), RangeError);
    assert.throws(() => new AdaptiveBackoffController(0, {}), RangeError);
  });

  it("has sane defaults", () => {
    assert.ok(DEFAULT_ADAPTIVE_MIN_BASE_MS > 0);
    assert.ok(DEFAULT_ADAPTIVE_MAX_BASE_MS >= DEFAULT_ADAPTIVE_MIN_BASE_MS);
    const c = new AdaptiveBackoffController(1000, {});
    for (let i = 0; i < 20; i++) c.recordOutcome(URL, false);
    assert.equal(c.baseFor(URL), DEFAULT_ADAPTIVE_MAX_BASE_MS);
  });
});

describe("WR-59 adaptive backoff (queue)", () => {
  it("is disabled by default: fixed-base backoff, no stats", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
    });
    q.start();
    assert.equal(q.getAdaptiveBackoffStats(), undefined);
    // single-arg delayForAttempt keeps the classic behavior
    assert.equal(q.delayForAttempt(1), 2000);
    q.stop();
  });

  it("grows the base on consecutive failures and exposes it via getStats", async () => {
    const timer = manualTimer();
    const scheduledDelays: number[] = [];
    const alwaysFail: Sender = async () => {
      throw new Error("downstream down");
    };
    const q = new RetryQueue({
      sender: alwaysFail,
      baseDelayMs: 1000,
      maxDelayMs: 60000,
      maxAttempts: 4,
      jitterMs: 0,
      random: () => 0,
      setTimer: (fn, ms) => {
        scheduledDelays.push(ms);
        return timer.setTimer(fn, ms);
      },
      adaptiveBackoff: { minBaseMs: 100, maxBaseMs: 8000 },
    });
    q.start();
    q.enqueue(item("item-1"));
    await timer.run();
    // attempt 1 fails: base 1000 -> 2000, delay = 2000 * 2^1 = 4000
    // attempt 2 fails: base 2000 -> 4000, delay = 4000 * 2^2 = 16000
    // attempt 3 fails: base 4000 -> 8000, delay = 8000 * 2^3 = 64000 -> capped 60000
    assert.deepEqual(scheduledDelays, [0, 4000, 16000, 60000]);
    assert.deepEqual(q.getAdaptiveBackoffStats(), [
      { endpoint: URL, baseMs: 8000, consecutiveFailures: 4, consecutiveSuccesses: 0 },
    ]);
    // delayForAttempt reads the adapted base for the endpoint...
    assert.equal(q.delayForAttempt(0, URL), 8000);
    // ...and the resting base without one.
    assert.equal(q.delayForAttempt(0), 1000);
    q.stop();
  });

  it("cools the base back toward the floor on success", async () => {
    const timer = manualTimer();
    let calls = 0;
    const flaky: Sender = async () => {
      calls += 1;
      if (calls <= 2) throw new Error("downstream down");
    };
    const q = new RetryQueue({
      sender: flaky,
      baseDelayMs: 1000,
      maxDelayMs: 60000,
      maxAttempts: 5,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      adaptiveBackoff: { minBaseMs: 100, maxBaseMs: 8000 },
    });
    q.start();
    q.enqueue(item("item-1"));
    await timer.run();
    assert.equal(calls, 3); // 2 failures + 1 success
    // 1000 -> 2000 -> 4000 (failures), then 4000 -> 2000 (success)
    assert.deepEqual(q.getAdaptiveBackoffStats(), [
      { endpoint: URL, baseMs: 2000, consecutiveFailures: 0, consecutiveSuccesses: 1 },
    ]);
    q.stop();
  });

  it("scopes controllers per tenant", async () => {
    const timer = manualTimer();
    const alwaysFail: Sender = async () => {
      throw new Error("down");
    };
    const q = new RetryQueue({
      sender: alwaysFail,
      baseDelayMs: 1000,
      maxAttempts: 2,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      adaptiveBackoff: {},
    });
    q.start();
    q.enqueue(item("t1-item", "t1"));
    q.enqueue(item("t2-item", "t2"));
    await timer.run();
    const stats = q.getAdaptiveBackoffStats() ?? [];
    // one controller per tenant; each item failed twice (maxAttempts: 2)
    assert.equal(stats.length, 2);
    for (const row of stats) {
      assert.equal(row.baseMs, 4000);
      assert.equal(row.consecutiveFailures, 2);
      assert.ok(row.tenant === "t1" || row.tenant === "t2");
    }
    // the tenant selects the controller in delayForAttempt too
    assert.equal(q.delayForAttempt(0, URL, "t1"), 4000);
    assert.equal(q.delayForAttempt(0, URL), 1000); // default tenant untouched
    q.stop();
  });

  it("composes orthogonally with the global retry budget (WR-38)", async () => {
    const timer = manualTimer();
    const now = { ms: 0 };
    const alwaysFail: Sender = async () => {
      throw new Error("downstream down");
    };
    const q = new RetryQueue({
      sender: alwaysFail,
      baseDelayMs: 1000,
      maxDelayMs: 60000,
      maxAttempts: 5,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      retryBudget: { retriesPerMinute: 1, now: () => now.ms },
      adaptiveBackoff: { minBaseMs: 100, maxBaseMs: 8000 },
    });
    q.start();
    q.enqueue(item("item-1"));
    await timer.run();
    // The 1/min budget parks retries 2..4 while the adaptive base still
    // climbs on every failure: budget gates first, backoff adapts anyway.
    const budget = q.getRetryBudgetStats();
    assert.ok(budget !== undefined && budget.depleted === 3);
    const [row] = q.getAdaptiveBackoffStats() ?? [];
    assert.equal(row.baseMs, 8000); // 5 failures -> ceiling
    assert.equal(row.consecutiveFailures, 5);
    q.stop();
  });

  it("rejects invalid options at construction", () => {
    for (const bad of [
      { minBaseMs: 0 },
      { minBaseMs: 200, maxBaseMs: 100 },
      { upFactor: 1 },
      { downFactor: 2 },
    ]) {
      assert.throws(
        () => new RetryQueue({ sender: async () => {}, adaptiveBackoff: bad }),
        RangeError,
        JSON.stringify(bad)
      );
    }
  });
});
