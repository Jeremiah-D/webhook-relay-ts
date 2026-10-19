import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { RetryQueue, type Sender, type SlowStartOptions } from "../src/retry.ts";
import { SlowStartController } from "../src/slowstart.ts";

const URL = "http://localhost:9999/hook";

/**
 * Manual timer with single-step control: breaker parking re-arms timers, so
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

function controllableSender() {
  let calls = 0;
  let fail = true;
  const sender: Sender = async () => {
    calls += 1;
    if (fail) throw new Error("downstream down");
  };
  return { sender, calls: () => calls, setFail: (v: boolean) => (fail = v) };
}

describe("SlowStartController", () => {
  it("ramps exponentially 1 -> 2 -> 4 and completes at the ceiling", () => {
    const c = new SlowStartController({ maxLimit: 8 });
    c.onCircuitClosed(URL);
    assert.equal(c.ramping(URL), true);
    assert.equal(c.limitFor(URL), 1);
    c.recordOutcome(URL, true);
    assert.equal(c.limitFor(URL), 2);
    c.recordOutcome(URL, true);
    assert.equal(c.limitFor(URL), 4);
    // Next step would reach the ceiling: the ramp completes and the
    // endpoint runs at the full limit with no entry left.
    c.recordOutcome(URL, true);
    assert.equal(c.ramping(URL), false);
    assert.equal(c.limitFor(URL), 8);
    assert.deepEqual(c.stats(), []);
  });

  it("ramps additively with +1 steps when configured", () => {
    const c = new SlowStartController({ curve: "additive", maxLimit: 4 });
    c.onCircuitClosed(URL);
    assert.equal(c.limitFor(URL), 1);
    c.recordOutcome(URL, true);
    assert.equal(c.limitFor(URL), 2);
    c.recordOutcome(URL, true);
    assert.equal(c.limitFor(URL), 3);
    c.recordOutcome(URL, true);
    assert.equal(c.ramping(URL), false);
    assert.equal(c.limitFor(URL), 4);
  });

  it("drops back to the floor on failure and stays ramping", () => {
    const c = new SlowStartController({ maxLimit: 16 });
    c.onCircuitClosed(URL);
    c.recordOutcome(URL, true);
    c.recordOutcome(URL, true);
    assert.equal(c.limitFor(URL), 4);
    c.recordOutcome(URL, false);
    assert.equal(c.ramping(URL), true);
    assert.equal(c.limitFor(URL), 1);
    // The climb restarts from the floor.
    c.recordOutcome(URL, true);
    assert.equal(c.limitFor(URL), 2);
  });

  it("ignores outcomes when no ramp is active", () => {
    const c = new SlowStartController({ maxLimit: 8 });
    c.recordOutcome(URL, true);
    c.recordOutcome(URL, false);
    assert.equal(c.ramping(URL), false);
    assert.equal(c.limitFor(URL), 8);
  });

  it("restarts the ramp at the floor on a new breaker-close", () => {
    const c = new SlowStartController({ maxLimit: 8 });
    c.onCircuitClosed(URL);
    c.recordOutcome(URL, true);
    assert.equal(c.limitFor(URL), 2);
    // A second recovery episode always starts at the floor, even when
    // the previous ramp was still climbing.
    c.onCircuitClosed(URL);
    assert.equal(c.limitFor(URL), 1);
    assert.equal(c.ramping(URL), true);
  });

  it("rejects illegal configs with RangeError", () => {
    assert.throws(() => new SlowStartController({ floor: 0 }), RangeError);
    assert.throws(() => new SlowStartController({ floor: 1.5 }), RangeError);
    assert.throws(() => new SlowStartController({ maxLimit: 0 }), RangeError);
    assert.throws(() => new SlowStartController({ floor: 4, maxLimit: 3 }), RangeError);
    assert.throws(
      () => new SlowStartController({ curve: "cubic" as SlowStartOptions["curve"] }),
      RangeError
    );
  });

  it("uses floor 1 / exponential / unbounded ceiling by default", () => {
    const c = new SlowStartController();
    c.onCircuitClosed(URL);
    assert.equal(c.limitFor(URL), 1);
    c.recordOutcome(URL, true);
    assert.equal(c.limitFor(URL), 2);
    c.recordOutcome(URL, true);
    assert.equal(c.limitFor(URL), 4);
    assert.equal(c.ramping(URL), true); // no ceiling: never completes
  });

  it("stats() reports the ramp shape and reset() clears it", () => {
    const c = new SlowStartController({ maxLimit: 8 });
    c.onCircuitClosed(URL);
    c.recordOutcome(URL, true);
    assert.deepEqual(c.stats(), [
      { endpoint: URL, limit: 2, floor: 1, ceiling: 8, curve: "exponential" },
    ]);
    c.reset(URL);
    assert.equal(c.ramping(URL), false);
    assert.deepEqual(c.stats(), []);
    c.onCircuitClosed(URL);
    c.reset();
    assert.deepEqual(c.stats(), []);
  });
});

describe("retry queue slow-start", () => {
  function makeQueue(slowStart?: SlowStartOptions) {
    const timer = manualTimer();
    let now = 0;
    const f = controllableSender();
    const q = new RetryQueue({
      sender: f.sender,
      baseDelayMs: 10,
      maxAttempts: 5,
      jitterMs: 0,
      random: () => 0, // deterministic parking delay
      setTimer: timer.setTimer,
      maxConcurrentPerEndpoint: 8,
      circuitBreaker: { failureThreshold: 2, cooldownMs: 1000, nowMs: () => now },
      ...(slowStart === undefined ? {} : { slowStart }),
    });
    return { q, timer, f, advance: (ms: number) => (now += ms) };
  }

  /** Drive the endpoint through trip -> cooldown -> successful half-open probe. */
  async function tripAndRecover(env: ReturnType<typeof makeQueue>) {
    const { q, timer, f, advance } = env;
    q.start();
    q.enqueue({ id: "ss-1", payload: Buffer.from("one"), targetUrl: URL, headers: {} });
    await timer.step(); // attempt 1 fails
    await timer.step(); // attempt 2 fails -> trips open
    assert.equal(q.getCircuitStats()[0].state, "open");
    f.setFail(false);
    advance(1000);
    await timer.step(); // half-open probe succeeds -> closed
    assert.equal(q.getCircuitStats()[0].state, "closed");
  }

  it("paces recovery: ramp starts on half_open->closed and climbs per success", async () => {
    const env = makeQueue({});
    await tripAndRecover(env);
    const { q, timer } = env;
    // The probe's own success stepped the ramp 1 -> 2: the probe was the
    // floor-1 phase, so pacing continues from 2.
    const rows = q.getSlowStartStats()!;
    assert.equal(rows.length, 1);
    assert.equal(rows[0].endpoint, URL);
    assert.equal(rows[0].limit, 2);
    assert.equal(rows[0].floor, 1);
    assert.equal(rows[0].ceiling, 8);
    assert.equal(rows[0].curve, "exponential");
    assert.equal((q as any).limiter.maxFor(URL), 2);

    q.enqueue({ id: "ss-2", payload: Buffer.from("two"), targetUrl: URL, headers: {} });
    await timer.step();
    assert.equal(q.getSlowStartStats()![0].limit, 4);
    assert.equal((q as any).limiter.maxFor(URL), 4);

    q.enqueue({ id: "ss-3", payload: Buffer.from("three"), targetUrl: URL, headers: {} });
    await timer.step();
    // 4 -> 8 reaches the ceiling: the ramp completes and the full limit
    // is restored with no ramp state left.
    assert.deepEqual(q.getSlowStartStats(), []);
    assert.equal((q as any).limiter.maxFor(URL), 8);
    assert.equal(q.getCircuitStats()[0].state, "closed");
  });

  it("a retryable failure mid-ramp drops back to the floor", async () => {
    const env = makeQueue({});
    const { q, timer, f } = env;
    q.start();
    q.enqueue({ id: "ss-a", payload: Buffer.from("x"), targetUrl: URL, headers: {} });
    await timer.step(); // attempt 1 fails
    await timer.step(); // attempt 2 fails -> trips open
    assert.equal(q.getCircuitStats()[0].state, "open");
    f.setFail(false);
    env.advance(1000);
    await timer.step(); // probe succeeds -> closed, ramp starts, item delivered
    assert.equal(q.pendingCount(), 0); // the single item drained: no parked leftovers
    assert.equal(q.getSlowStartStats()![0].limit, 2);

    // One failure stays below the threshold (2): the circuit stays closed,
    // but the ramp drops back to the floor instantly.
    f.setFail(true);
    q.enqueue({ id: "ss-flinch", payload: Buffer.from("x"), targetUrl: URL, headers: {} });
    await timer.step();
    assert.equal(q.getCircuitStats()[0].state, "closed");
    assert.equal(q.getSlowStartStats()![0].limit, 1);
    assert.equal((q as any).limiter.maxFor(URL), 1);
  });

  it("is a no-op without a circuit breaker configured", async () => {
    const timer = manualTimer();
    const f = controllableSender();
    f.setFail(false);
    const q = new RetryQueue({
      sender: f.sender,
      baseDelayMs: 10,
      maxAttempts: 3,
      jitterMs: 0,
      setTimer: timer.setTimer,
      maxConcurrentPerEndpoint: 8,
      slowStart: {},
    });
    q.start();
    q.enqueue({ id: "ss-nb", payload: Buffer.from("x"), targetUrl: URL, headers: {} });
    while (timer.pendingCount() > 0) await timer.step();
    // No breaker-close event can ever fire, so no ramp ever starts.
    assert.deepEqual(q.getSlowStartStats(), []);
    assert.equal((q as any).limiter.maxFor(URL), 8);
    assert.equal(f.calls(), 1);
  });

  it("is disabled by default", () => {
    const { q } = makeQueue();
    assert.equal(q.getSlowStartStats(), undefined);
  });

  it("rejects illegal slowStart options at construction", () => {
    const f = controllableSender();
    assert.throws(
      () => new RetryQueue({ sender: f.sender, slowStart: { floor: 0 } }),
      RangeError
    );
    assert.throws(
      () =>
        new RetryQueue({
          sender: f.sender,
          slowStart: { curve: "cubic" as SlowStartOptions["curve"] },
        }),
      RangeError
    );
  });
});
