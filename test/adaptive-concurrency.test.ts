import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  RetryQueue,
  AdaptiveConcurrencyController,
  HttpDeliveryError,
  DEFAULT_ADAPTIVE_MIN_LIMIT,
  DEFAULT_ADAPTIVE_INCREASE_STEP,
  DEFAULT_ADAPTIVE_DECREASE_FACTOR,
  DEFAULT_ADAPTIVE_FAILURE_RATE_THRESHOLD,
  DEFAULT_ADAPTIVE_WINDOW_SIZE,
  type Sender,
} from "../src/retry.ts";

/**
 * WR-94 tests. The controller is outcome-driven — no clock, no randomness
 * — so unit tests are deterministic by construction; the queue-level tests
 * inject the timer like the other backoff/concurrency tests.
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

describe("WR-94 AdaptiveConcurrencyController (unit)", () => {
  it("has sane defaults", () => {
    const c = new AdaptiveConcurrencyController({}, 16);
    assert.equal(c.limitFor("e"), 16); // initial = ceiling
    const s = c.stats();
    assert.equal(s.length, 0); // no outcomes yet → absent
    assert.equal(DEFAULT_ADAPTIVE_MIN_LIMIT, 1);
    assert.equal(DEFAULT_ADAPTIVE_INCREASE_STEP, 1);
    assert.equal(DEFAULT_ADAPTIVE_DECREASE_FACTOR, 0.5);
    assert.equal(DEFAULT_ADAPTIVE_FAILURE_RATE_THRESHOLD, 0.2);
    assert.equal(DEFAULT_ADAPTIVE_WINDOW_SIZE, 20);
  });

  it("additively increases per healthy window, clamped at the ceiling", () => {
    const c = new AdaptiveConcurrencyController(
      { minLimit: 1, maxLimit: 5, initialLimit: 2, increaseStep: 2, windowSize: 3 },
      5
    );
    for (let i = 0; i < 3; i++) c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 4);
    for (let i = 0; i < 3; i++) c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 5); // clamped at maxLimit
    for (let i = 0; i < 3; i++) c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 5); // stays clamped
  });

  it("multiplicatively decreases per congested window, floored at minLimit", () => {
    const c = new AdaptiveConcurrencyController(
      {
        minLimit: 1,
        maxLimit: 64,
        initialLimit: 32,
        decreaseFactor: 0.5,
        failureRateThreshold: 0.5,
        windowSize: 4,
      },
      64
    );
    // 3/4 failures = 0.75 >= 0.5 → 32 * 0.5 = 16
    c.recordOutcome("e", false);
    c.recordOutcome("e", false);
    c.recordOutcome("e", false);
    c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 16);
    // A healthy window below the threshold recovers additively.
    for (let i = 0; i < 4; i++) c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 17);
  });

  it("floors at minLimit under sustained failure", () => {
    const c = new AdaptiveConcurrencyController(
      { minLimit: 2, maxLimit: 100, initialLimit: 100, windowSize: 2 },
      100
    );
    for (let w = 0; w < 10; w++) {
      c.recordOutcome("e", false);
      c.recordOutcome("e", false);
    }
    assert.equal(c.limitFor("e"), 2);
  });

  it("treats failureRate == threshold as congested", () => {
    const c = new AdaptiveConcurrencyController(
      { minLimit: 1, maxLimit: 8, initialLimit: 8, failureRateThreshold: 0.5, windowSize: 2 },
      8
    );
    c.recordOutcome("e", false);
    c.recordOutcome("e", true); // 0.5 == threshold → decrease
    assert.equal(c.limitFor("e"), 4);
  });

  it("evaluates each full window exactly once (no double punishment)", () => {
    const c = new AdaptiveConcurrencyController(
      { minLimit: 1, maxLimit: 100, initialLimit: 100, windowSize: 2 },
      100
    );
    c.recordOutcome("e", false);
    assert.equal(c.limitFor("e"), 100); // window incomplete — no move yet
    c.recordOutcome("e", false);
    assert.equal(c.limitFor("e"), 50); // one step
    c.recordOutcome("e", false);
    assert.equal(c.limitFor("e"), 50); // new window incomplete — no second step
    c.recordOutcome("e", false);
    assert.equal(c.limitFor("e"), 25);
  });

  it("keeps endpoints independent", () => {
    const c = new AdaptiveConcurrencyController({ windowSize: 1 }, 8);
    c.recordOutcome("a", false); // 1.0 >= 0.2 → 8*0.5 = 4
    c.recordOutcome("b", true); // 0.0 < 0.2 → min(8, 8+1) = 8
    assert.equal(c.limitFor("a"), 4);
    assert.equal(c.limitFor("b"), 8);
  });

  it("reset() forgets adapted state", () => {
    const c = new AdaptiveConcurrencyController({ windowSize: 1 }, 8);
    c.recordOutcome("e", false);
    assert.equal(c.limitFor("e"), 4);
    c.reset("e");
    assert.equal(c.limitFor("e"), 8);
    assert.equal(c.stats().length, 0);
  });

  it("stats() exposes the limit and window fill", () => {
    const c = new AdaptiveConcurrencyController({ windowSize: 4 }, 8);
    c.recordOutcome("e", true);
    c.recordOutcome("e", false);
    assert.deepEqual(c.stats(), [
      {
        endpoint: "e",
        limit: 8,
        windowOutcomes: 2,
        windowFailures: 1,
        windowSize: 4,
      },
    ]);
  });

  it("rejects invalid options with RangeError", () => {
    assert.throws(() => new AdaptiveConcurrencyController({ minLimit: 0 }, 8), RangeError);
    assert.throws(() => new AdaptiveConcurrencyController({ maxLimit: 0 }, 8), RangeError);
    assert.throws(
      () => new AdaptiveConcurrencyController({ minLimit: 4, maxLimit: 2 }, 8),
      RangeError
    );
    assert.throws(
      () => new AdaptiveConcurrencyController({ initialLimit: 9, maxLimit: 8 }, 8),
      RangeError
    );
    assert.throws(
      () => new AdaptiveConcurrencyController({ initialLimit: 0 }, 8),
      RangeError
    );
    assert.throws(() => new AdaptiveConcurrencyController({ increaseStep: 0 }, 8), RangeError);
    assert.throws(
      () => new AdaptiveConcurrencyController({ decreaseFactor: 1 }, 8),
      RangeError
    );
    assert.throws(
      () => new AdaptiveConcurrencyController({ decreaseFactor: 0 }, 8),
      RangeError
    );
    assert.throws(
      () => new AdaptiveConcurrencyController({ failureRateThreshold: 1.5 }, 8),
      RangeError
    );
    assert.throws(
      () => new AdaptiveConcurrencyController({ failureRateThreshold: -0.1 }, 8),
      RangeError
    );
    assert.throws(() => new AdaptiveConcurrencyController({ windowSize: 0 }, 8), RangeError);
    // Infinity ceiling is fine; it just never renders a metrics gauge.
    const inf = new AdaptiveConcurrencyController({}, Infinity);
    assert.equal(inf.limitFor("e"), Infinity);
  });
});

describe("WR-94 adaptive concurrency (queue)", () => {
  it("is disabled by default: no stats, no metrics series", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
    });
    q.start();
    assert.equal(q.getAdaptiveConcurrencyStats(), undefined);
    assert.ok(!q.renderMetrics().includes("relay_adaptive_concurrency_limit"));
    q.stop();
  });

  it("rejects invalid options at construction", () => {
    assert.throws(
      () =>
        new RetryQueue({
          sender: async () => {},
          adaptiveConcurrency: { minLimit: 0 },
        }),
      RangeError
    );
    assert.throws(
      () =>
        new RetryQueue({
          sender: async () => {},
          adaptiveConcurrency: { decreaseFactor: 2 },
        }),
      RangeError
    );
  });

  it("heats the limit down on retryable failures and exposes it via getStats + /metrics", async () => {
    const timer = manualTimer();
    const alwaysFail: Sender = async () => {
      throw new Error("downstream down");
    };
    const q = new RetryQueue({
      sender: alwaysFail,
      maxAttempts: 1, // fail fast to dead letter — no timer juggling
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      adaptiveConcurrency: { minLimit: 1, maxLimit: 8, initialLimit: 4, windowSize: 2 },
    });
    q.start();
    q.enqueue(item("f-1"));
    q.enqueue(item("f-2"));
    await timer.run();
    // One congested window (2/2 failures): 4 -> floor(4 * 0.5) = 2.
    assert.deepEqual(q.getAdaptiveConcurrencyStats(), [
      {
        endpoint: URL,
        limit: 2,
        windowOutcomes: 0,
        windowFailures: 0,
        windowSize: 2,
      },
    ]);
    const exposition = q.renderMetrics();
    assert.ok(
      exposition.includes(`relay_adaptive_concurrency_limit{endpoint="${URL}"} 2`),
      exposition
    );
    q.stop();
  });

  it("treats non-retryable downstream rejections as healthy (no congestion)", async () => {
    const timer = manualTimer();
    const poison: Sender = async () => {
      throw new HttpDeliveryError(400);
    };
    const q = new RetryQueue({
      sender: poison,
      maxAttempts: 5,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      adaptiveConcurrency: { minLimit: 1, maxLimit: 4, initialLimit: 2, windowSize: 2 },
    });
    q.start();
    q.enqueue(item("p-1"));
    q.enqueue(item("p-2"));
    await timer.run();
    // Two answering rejections = a healthy window: 2 -> min(4, 2 + 1) = 3.
    const stats = q.getAdaptiveConcurrencyStats();
    assert.equal(stats?.[0]?.limit, 3);
    q.stop();
  });

  it("gates dispatch at min(fixed cap, adaptive limit)", async () => {
    const timer = manualTimer();
    let inFlight = 0;
    let maxInFlight = 0;
    const releases: Array<() => void> = [];
    const blocking: Sender = async () => {
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise<void>((r) => releases.push(r));
      inFlight -= 1;
    };
    const q = new RetryQueue({
      sender: blocking,
      maxAttempts: 1,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      maxConcurrentPerEndpoint: 10, // fixed cap far above the adaptive one
      adaptiveConcurrency: { minLimit: 1, maxLimit: 10, initialLimit: 2, windowSize: 2 },
    });
    q.start();
    q.enqueue(item("g-1"));
    q.enqueue(item("g-2"));
    q.enqueue(item("g-3"));
    await timer.run();
    await new Promise((r) => setImmediate(r));
    // Adaptive limit 2 < fixed 10: only two dispatch.
    assert.equal(inFlight, 2);
    assert.equal(maxInFlight, 2);
    // Resolve both as successes: one healthy window → 2 -> 3.
    releases.splice(0).forEach((r) => r());
    await timer.run();
    await new Promise((r) => setImmediate(r));
    assert.equal(q.getAdaptiveConcurrencyStats()?.[0]?.limit, 3);
    // The third item dispatched once a slot freed; top up and check the
    // new limit gates at 3.
    q.enqueue(item("g-4"));
    q.enqueue(item("g-5"));
    await timer.run();
    await new Promise((r) => setImmediate(r));
    assert.ok(inFlight <= 3, `inFlight=${inFlight}`);
    assert.ok(maxInFlight <= 3, `maxInFlight=${maxInFlight}`);
    releases.splice(0).forEach((r) => r());
    q.stop();
  });

  it("never exceeds the fixed cap even when the adaptive ceiling is higher", async () => {
    const timer = manualTimer();
    let inFlight = 0;
    let maxInFlight = 0;
    const releases: Array<() => void> = [];
    const blocking: Sender = async () => {
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise<void>((r) => releases.push(r));
      inFlight -= 1;
    };
    const q = new RetryQueue({
      sender: blocking,
      maxAttempts: 1,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      maxConcurrentPerEndpoint: 2, // fixed cap below the adaptive ceiling
      adaptiveConcurrency: { minLimit: 1, maxLimit: 100, windowSize: 1000 },
    });
    q.start();
    q.enqueue(item("c-1"));
    q.enqueue(item("c-2"));
    q.enqueue(item("c-3"));
    await timer.run();
    await new Promise((r) => setImmediate(r));
    // Adaptive wants 100, but min(2, 100) = 2.
    assert.equal(inFlight, 2);
    assert.equal(maxInFlight, 2);
    releases.splice(0).forEach((r) => r());
    q.stop();
  });

  it("scopes controllers per tenant", async () => {
    const timer = manualTimer();
    const alwaysFail: Sender = async () => {
      throw new Error("downstream down");
    };
    const q = new RetryQueue({
      sender: alwaysFail,
      maxAttempts: 1,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      adaptiveConcurrency: { minLimit: 1, maxLimit: 8, initialLimit: 4, windowSize: 1 },
    });
    q.start();
    q.enqueue(item("t-1", "acme"));
    q.enqueue(item("t-2"));
    await timer.run();
    const stats = q.getAdaptiveConcurrencyStats() ?? [];
    const byTenant = new Map(stats.map((s) => [s.tenant ?? "", s.limit]));
    assert.equal(byTenant.get("acme"), 2);
    assert.equal(byTenant.get(""), 2);
    q.stop();
  });
});
