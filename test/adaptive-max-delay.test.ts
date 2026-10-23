import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { RetryQueue, type Sender } from "../src/retry.ts";
import {
  AdaptiveMaxDelay,
  assertValidAdaptiveMaxDelayOptions,
  DEFAULT_ADAPTIVE_MAX_DELAY_FLOOR_MS,
} from "../src/adaptive-max-delay.ts";

const A = "http://a/hook";
const B = "http://b/hook";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));

/** Let the deliver() promise chain settle. */
async function flush(ticks = 20) {
  for (let i = 0; i < ticks; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

/** Poll until `cond()` is true (bounded) — robust against scheduling flakes. */
async function waitFor(cond: () => boolean, ticks = 500) {
  for (let i = 0; i < ticks; i++) {
    if (cond()) return;
    await new Promise((r) => setImmediate(r));
  }
  throw new Error("waitFor: condition not met within budget");
}

/** Manual clock for deterministic latency samples. */
function manualClock(start = 0) {
  let t = start;
  return {
    now: () => t,
    advance: (ms: number) => {
      t += ms;
    },
  };
}

/** Feed one successful delivery with a controlled latency. */
function successWithLatency(
  c: AdaptiveMaxDelay,
  clock: { now: () => number; advance: (ms: number) => void },
  id: string,
  endpoint: string,
  latencyMs: number
) {
  c.recordAccepted(id);
  clock.advance(latencyMs);
  c.recordDelivered(id, endpoint);
}

describe("assertValidAdaptiveMaxDelayOptions", () => {
  it("rejects a bad base cap", () => {
    assert.throws(() => assertValidAdaptiveMaxDelayOptions(0, {}), RangeError);
    assert.throws(() => assertValidAdaptiveMaxDelayOptions(-5, {}), RangeError);
    assert.throws(() => assertValidAdaptiveMaxDelayOptions(Infinity, {}), RangeError);
    assert.throws(() => assertValidAdaptiveMaxDelayOptions(NaN, {}), RangeError);
  });

  it("rejects a non-object options bag", () => {
    assert.throws(() => assertValidAdaptiveMaxDelayOptions(1000, undefined), RangeError);
    assert.throws(() => assertValidAdaptiveMaxDelayOptions(1000, null), RangeError);
    assert.throws(() => assertValidAdaptiveMaxDelayOptions(1000, "1000"), RangeError);
    assert.throws(() => assertValidAdaptiveMaxDelayOptions(1000, []), RangeError);
  });

  it("rejects bad margin/floor/ceil/samples/tighten", () => {
    assert.throws(() => assertValidAdaptiveMaxDelayOptions(1000, { marginRatio: -0.1 }), RangeError);
    assert.throws(() => assertValidAdaptiveMaxDelayOptions(1000, { floorMs: 0 }), RangeError);
    assert.throws(() => assertValidAdaptiveMaxDelayOptions(1000, { ceilMs: 0 }), RangeError);
    assert.throws(
      () => assertValidAdaptiveMaxDelayOptions(1000, { floorMs: 500, ceilMs: 100 }),
      RangeError
    );
    assert.throws(() => assertValidAdaptiveMaxDelayOptions(1000, { minSamples: 0 }), RangeError);
    assert.throws(
      () => assertValidAdaptiveMaxDelayOptions(1000, { maxSamplesPerEndpoint: 1.5 }),
      RangeError
    );
    assert.throws(() => assertValidAdaptiveMaxDelayOptions(1000, { tightenFactor: 0 }), RangeError);
    assert.throws(() => assertValidAdaptiveMaxDelayOptions(1000, { tightenFactor: 1 }), RangeError);
    assert.throws(() => assertValidAdaptiveMaxDelayOptions(1000, { tightenFactor: 1.5 }), RangeError);
    assert.throws(() => assertValidAdaptiveMaxDelayOptions(1000, { now: 42 }), RangeError);
  });

  it("accepts a fully populated valid config", () => {
    assertValidAdaptiveMaxDelayOptions(1000, {
      marginRatio: 0.25,
      floorMs: 500,
      ceilMs: 8000,
      minSamples: 3,
      maxSamplesPerEndpoint: 64,
      tightenFactor: 0.5,
      now: () => 0,
    });
  });
});

describe("AdaptiveMaxDelay cold start", () => {
  it("returns the resting cap until minSamples successes exist", () => {
    const clock = manualClock();
    const c = new AdaptiveMaxDelay(60000, { minSamples: 3, now: clock.now });
    assert.equal(c.capFor(A), 60000);
    successWithLatency(c, clock, "i1", A, 100);
    successWithLatency(c, clock, "i2", A, 200);
    assert.equal(c.capFor(A), 60000);
    successWithLatency(c, clock, "i3", A, 300);
    // p99 of [100,200,300] = 300; 300 * 1.5 = 450 < floor 1000 → clamped to floor.
    assert.equal(c.capFor(A), 1000);
  });

  it("reads a live resting cap (hot-reload aware)", () => {
    let base = 60000;
    const clock = manualClock();
    const c = new AdaptiveMaxDelay(() => base, { minSamples: 5, now: clock.now });
    assert.equal(c.capFor(A), 60000);
    base = 30000;
    assert.equal(c.capFor(A), 30000);
  });

  it("keeps endpoints isolated", () => {
    const clock = manualClock();
    const c = new AdaptiveMaxDelay(60000, { minSamples: 2, now: clock.now });
    successWithLatency(c, clock, "a1", A, 2000);
    successWithLatency(c, clock, "a2", A, 2000);
    assert.equal(c.capFor(A), 3000); // p99 2000 * 1.5
    assert.equal(c.capFor(B), 60000); // cold
  });
});

describe("AdaptiveMaxDelay p99-derived cap", () => {
  it("clamps the relaxed cap into [floorMs, ceilMs]", () => {
    const clock = manualClock();
    const c = new AdaptiveMaxDelay(60000, {
      minSamples: 4,
      floorMs: 500,
      ceilMs: 10000,
      marginRatio: 1,
      now: clock.now,
    });
    // Slow endpoint: p99 8000 * 2 = 16000 → clamped to ceil 10000.
    successWithLatency(c, clock, "s1", A, 8000);
    successWithLatency(c, clock, "s2", A, 8000);
    successWithLatency(c, clock, "s3", A, 8000);
    successWithLatency(c, clock, "s4", A, 8000);
    assert.equal(c.capFor(A), 10000);
    // Fast endpoint: p99 100 * 2 = 200 → clamped to floor 500.
    successWithLatency(c, clock, "f1", B, 100);
    successWithLatency(c, clock, "f2", B, 100);
    successWithLatency(c, clock, "f3", B, 100);
    successWithLatency(c, clock, "f4", B, 100);
    assert.equal(c.capFor(B), 500);
  });

  it("tracks the rolling p99 as the latency profile drifts", () => {
    const clock = manualClock();
    const c = new AdaptiveMaxDelay(60000, {
      minSamples: 4,
      maxSamplesPerEndpoint: 4,
      marginRatio: 0,
      floorMs: 1,
      ceilMs: 1e9,
      now: clock.now,
    });
    for (let i = 0; i < 4; i++) successWithLatency(c, clock, `w${i}`, A, 100);
    assert.equal(c.capFor(A), 100);
    // Window slides: oldest 100s evict, p99 moves to 500.
    for (let i = 0; i < 4; i++) successWithLatency(c, clock, `n${i}`, A, 500);
    assert.equal(c.capFor(A), 500);
  });
});

describe("AdaptiveMaxDelay storm tightening", () => {
  it("multiplies the cap toward the floor per retryable failure", () => {
    const clock = manualClock();
    const c = new AdaptiveMaxDelay(60000, {
      minSamples: 2,
      marginRatio: 0,
      floorMs: 1000,
      tightenFactor: 0.5,
      now: clock.now,
    });
    successWithLatency(c, clock, "i1", A, 4000);
    successWithLatency(c, clock, "i2", A, 4000);
    assert.equal(c.capFor(A), 4000);
    c.recordFailure(A);
    assert.equal(c.capFor(A), 2000);
    c.recordFailure(A);
    assert.equal(c.capFor(A), 1000);
    // Never below the floor.
    c.recordFailure(A);
    assert.equal(c.capFor(A), 1000);
  });

  it("ignores failures on cold endpoints", () => {
    const clock = manualClock();
    const c = new AdaptiveMaxDelay(60000, { minSamples: 3, now: clock.now });
    c.recordFailure(A);
    c.recordFailure(A);
    assert.equal(c.capFor(A), 60000);
  });

  it("a success after the storm relaxes the cap back to the p99 target", () => {
    const clock = manualClock();
    const c = new AdaptiveMaxDelay(60000, {
      minSamples: 2,
      marginRatio: 0,
      floorMs: 1000,
      tightenFactor: 0.5,
      now: clock.now,
    });
    successWithLatency(c, clock, "i1", A, 4000);
    successWithLatency(c, clock, "i2", A, 4000);
    c.recordFailure(A); // 4000 → 2000
    assert.equal(c.capFor(A), 2000);
    successWithLatency(c, clock, "i3", A, 4000);
    assert.equal(c.capFor(A), 4000);
  });

  it("failures never enter the p99 window", () => {
    const clock = manualClock();
    const c = new AdaptiveMaxDelay(60000, {
      minSamples: 3,
      marginRatio: 0,
      floorMs: 1,
      ceilMs: 1e9,
      tightenFactor: 0.5,
      now: clock.now,
    });
    successWithLatency(c, clock, "i1", A, 100);
    successWithLatency(c, clock, "i2", A, 100);
    successWithLatency(c, clock, "i3", A, 100);
    for (let i = 0; i < 10; i++) c.recordFailure(A);
    // Storm tightened to the floor...
    assert.equal(c.capFor(A), 1);
    // ...but the p99 window is unpolluted: one success restores 100.
    successWithLatency(c, clock, "i4", A, 100);
    assert.equal(c.capFor(A), 100);
  });
});

describe("AdaptiveMaxDelay bookkeeping", () => {
  it("discard drops the pending clock without sampling", () => {
    const clock = manualClock();
    const c = new AdaptiveMaxDelay(60000, { minSamples: 1, now: clock.now });
    c.recordAccepted("x");
    clock.advance(99999);
    c.discard("x");
    // minSamples 1 but no samples exist → still cold.
    assert.equal(c.capFor(A), 60000);
  });

  it("reset forgets the adapted cap", () => {
    const clock = manualClock();
    const c = new AdaptiveMaxDelay(60000, {
      minSamples: 1,
      marginRatio: 0,
      floorMs: 1,
      ceilMs: 1e9,
      tightenFactor: 0.5,
      now: clock.now,
    });
    successWithLatency(c, clock, "i1", A, 2000);
    assert.equal(c.capFor(A), 2000);
    c.recordFailure(A);
    assert.equal(c.capFor(A), 1000);
    c.reset(A);
    // Warm again from the surviving samples: cap recomputes from p99.
    assert.equal(c.capFor(A), 2000);
    c.reset();
    assert.equal(c.capFor(A), 2000);
  });

  it("stats exposes cap, samples and p99 per endpoint", () => {
    const clock = manualClock();
    const c = new AdaptiveMaxDelay(60000, { minSamples: 2, marginRatio: 0.5, now: clock.now });
    successWithLatency(c, clock, "i1", A, 2000);
    successWithLatency(c, clock, "i2", A, 2000);
    const [row] = c.stats();
    assert.equal(row.endpoint, A);
    assert.equal(row.capMs, 3000);
    assert.equal(row.samples, 2);
    assert.equal(row.p99Ms, 2000);
  });
});

describe("RetryQueue adaptiveMaxDelay integration", () => {
  const okSender: Sender = async () => ({ statusCode: 200, body: Buffer.alloc(0) });

  it("rejects invalid adaptiveMaxDelay at construction", () => {
    assert.throws(
      () => new RetryQueue({ adaptiveMaxDelay: { floorMs: -1 } as never }),
      RangeError
    );
  });

  it("delayForAttempt uses the adapted cap for warm endpoints", async () => {
    const clock = manualClock(1000);
    // The delivery itself consumes 2000ms of manual time, so each
    // success samples a 2000ms accepted→delivered latency.
    const slowOkSender: Sender = async () => {
      clock.advance(2000);
      return { statusCode: 200, body: Buffer.alloc(0) };
    };
    const q = new RetryQueue({
      sender: slowOkSender,
      baseDelayMs: 100,
      maxDelayMs: 60000,
      maxAttempts: 5,
      adaptiveMaxDelay: { minSamples: 2, marginRatio: 0, floorMs: 1, ceilMs: 1e9, now: clock.now },
    });
    q.start();
    try {
      for (let i = 0; i < 2; i++) {
        q.enqueue({ id: `s${i}`, payload: BODY, targetUrl: A, headers: {} });
        await flush();
      }
      await waitFor(() => q.getAdaptiveMaxDelayStats()[0]?.samples === 2);
      const rows = q.getAdaptiveMaxDelayStats();
      assert.equal(rows.length, 1);
      assert.equal(rows[0].capMs, 2000);
      // attempt 10: min(2000, 100*2^10 + jitter) = 2000, not 60000.
      assert.equal(q.delayForAttempt(10, A), 2000);
      // Cold endpoint still sees the fixed cap.
      assert.equal(q.delayForAttempt(10, B), 60000);
      // effectiveRetryConfig reports the adaptive cap too.
      assert.equal(q.effectiveRetryConfig(A).maxDelayMs, 2000);
      assert.equal(q.effectiveRetryConfig(B).maxDelayMs, 60000);
    } finally {
      q.stop();
    }
  });

  it("failure storms tighten the queue's retry waits, recovery relaxes them", async () => {
    const clock = manualClock(1000);
    let calls = 0;
    // Succeeds twice (warming the endpoint at 4000ms), then fails forever.
    const flapping: Sender = async () => {
      calls++;
      clock.advance(4000);
      if (calls <= 2) return { statusCode: 200, body: Buffer.alloc(0) };
      throw new Error("boom");
    };
    const q = new RetryQueue({
      sender: flapping,
      baseDelayMs: 100,
      maxDelayMs: 60000,
      maxAttempts: 50,
      adaptiveMaxDelay: {
        minSamples: 1,
        marginRatio: 0,
        floorMs: 500,
        ceilMs: 1e9,
        tightenFactor: 0.5,
        now: clock.now,
      },
    });
    q.start();
    try {
      q.enqueue({ id: "w0", payload: BODY, targetUrl: A, headers: {} });
      await flush();
      q.enqueue({ id: "w1", payload: BODY, targetUrl: A, headers: {} });
      await flush();
      await waitFor(() => q.getAdaptiveMaxDelayStats()[0]?.samples === 2);
      assert.equal(q.getAdaptiveMaxDelayStats()[0].capMs, 4000);
      const before = q.delayForAttempt(10, A);
      assert.equal(before, 4000);
      // One retryable failure: 4000 -> 2000.
      q.enqueue({ id: "f0", payload: BODY, targetUrl: A, headers: {} });
      await waitFor(() => q.getAdaptiveMaxDelayStats()[0]?.capMs === 2000);
      const after = q.delayForAttempt(10, A);
      assert.equal(after, 2000);
      assert.ok(after >= 500, "never below the floor");
    } finally {
      q.stop();
    }
  });

  it("is disabled by default: fixed cap everywhere", () => {
    const q = new RetryQueue({ sender: okSender, baseDelayMs: 100, maxDelayMs: 60000 });
    assert.deepEqual(q.getAdaptiveMaxDelayStats(), []);
    assert.equal(q.delayForAttempt(10, A), 60000);
    assert.equal(q.effectiveRetryConfig(A).maxDelayMs, 60000);
    q.stop();
  });

  it("named retry policies skip adaptation", () => {
    const q = new RetryQueue({
      sender: okSender,
      baseDelayMs: 100,
      maxDelayMs: 60000,
      adaptiveMaxDelay: { minSamples: 1, now: () => 0 },
    });
    q.registerRetryPolicy("fixed", { baseDelayMs: 100, maxDelayMs: 12345, maxAttempts: 3 });
    q.setEndpointRetryPolicy(A, "fixed");
    // Policy cap wins even though the endpoint is (trivially) warm-eligible.
    assert.equal(q.delayForAttempt(10, A), 12345);
    q.stop();
  });
});
