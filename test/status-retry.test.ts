import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  RetryQueue,
  HttpDeliveryError,
  assertValidStatusRetryPolicy,
  matchStatusRetryPolicy,
  normalizeStatusRetryPolicy,
  statusRetryDelayMs,
  type Sender,
  type StatusRetryPolicyConfig,
} from "../src/retry.ts";

/**
 * Deterministic timer that records every scheduled delay in ms.
 * `run()` executes pending callbacks immediately, like the
 * `manualTimer()` in retry-policy.test.ts, but additionally keeps the
 * delay each callback was scheduled with so tests can assert the exact
 * backoff schedule.
 */
function captureTimer() {
  const pending: Array<{ ms: number; fn: () => void }> = [];
  const delays: number[] = [];
  return {
    delays,
    setTimer: (fn: () => void, ms: number) => {
      delays.push(ms);
      pending.push({ ms, fn });
      return {
        clear: () => {
          const i = pending.findIndex((p) => p.fn === fn);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    async run() {
      while (pending.length > 0) {
        const batch = pending.splice(0);
        for (const p of batch) p.fn();
        await new Promise((r) => setImmediate(r));
      }
    },
  };
}

const ENDPOINT = "http://localhost:9999/status-retry-endpoint";

function throwingSender(err: () => Error): Sender {
  return (async () => {
    throw err();
  }) as Sender;
}

function statusQueue(
  timer: ReturnType<typeof captureTimer>,
  endpointStatusRetryPolicies: Record<string, StatusRetryPolicyConfig> | undefined,
  extra: Record<string, unknown> = {}
) {
  return new RetryQueue({
    sender: throwingSender(() => new HttpDeliveryError(503)),
    baseDelayMs: 1000,
    maxDelayMs: 60000,
    maxAttempts: 5,
    jitterMs: 0,
    random: () => 0,
    setTimer: timer.setTimer,
    ...(endpointStatusRetryPolicies === undefined
      ? {}
      : { endpointStatusRetryPolicies }),
    ...extra,
  });
}

/** Retry delays only (drops the initial dispatch schedule entry). */
function retryDelays(timer: ReturnType<typeof captureTimer>): number[] {
  return timer.delays.slice(1);
}

describe("status-retry validation", () => {
  it("rejects non-object configs", () => {
    for (const bad of [null, undefined, [], "x", 42]) {
      assert.throws(() => assertValidStatusRetryPolicy(bad), RangeError);
    }
    // An empty policy is a valid no-op.
    assertValidStatusRetryPolicy({});
  });

  it("rejects illegal selector keys, accepts exact codes and classes", () => {
    const entry = { baseDelayMs: 100, maxAttempts: 2 };
    for (const key of ["abc", "6xx", "99", "4290", "5x", "", "2Xx", "-1"]) {
      assert.throws(
        () => assertValidStatusRetryPolicy({ [key]: entry }),
        RangeError,
        `key ${key} should be rejected`
      );
    }
    for (const key of ["100", "200", "408", "429", "503", "599", "2xx", "3xx", "4xx", "5xx"]) {
      assertValidStatusRetryPolicy({ [key]: entry });
    }
  });

  it("rejects illegal entry values", () => {
    const good = { baseDelayMs: 100, maxAttempts: 2 };
    const cases: Array<[string, unknown]> = [
      ["baseDelayMs 0", { ...good, baseDelayMs: 0 }],
      ["baseDelayMs negative", { ...good, baseDelayMs: -5 }],
      ["baseDelayMs NaN", { ...good, baseDelayMs: NaN }],
      ["baseDelayMs Infinity", { ...good, baseDelayMs: Infinity }],
      ["maxAttempts 0", { ...good, maxAttempts: 0 }],
      ["maxAttempts negative", { ...good, maxAttempts: -3 }],
      ["maxAttempts fractional", { ...good, maxAttempts: 1.5 }],
      ["maxAttempts string", { ...good, maxAttempts: "3" }],
      ["multiplier 0", { ...good, multiplier: 0 }],
      ["multiplier negative", { ...good, multiplier: -1 }],
      ["multiplier NaN", { ...good, multiplier: NaN }],
      ["null entry", null],
      ["string entry", "x"],
      ["array entry", []],
    ];
    for (const [label, entry] of cases) {
      assert.throws(
        () => assertValidStatusRetryPolicy({ "503": entry as never }),
        RangeError,
        label
      );
    }
    // The full shape passes, and multiplier is optional.
    assertValidStatusRetryPolicy({
      "429": { baseDelayMs: 5000, maxAttempts: 12 },
      "5xx": { baseDelayMs: 500, maxAttempts: 6, multiplier: 3 },
    });
  });

  it("normalize defaults the multiplier and detaches copies", () => {
    const input = { "429": { baseDelayMs: 5000, maxAttempts: 12 } };
    const out = normalizeStatusRetryPolicy(input);
    assert.deepEqual(out, { "429": { baseDelayMs: 5000, maxAttempts: 12, multiplier: 2 } });
    // Mutating the input afterwards cannot touch the normalized copy.
    input["429"].baseDelayMs = 1;
    assert.equal(out["429"].baseDelayMs, 5000);
    // Mutating the output cannot touch the input either.
    out["429"].baseDelayMs = 2;
    assert.equal(normalizeStatusRetryPolicy({ "429": { baseDelayMs: 5000, maxAttempts: 12 } })["429"].baseDelayMs, 5000);
    // An illegal config never returns.
    assert.throws(
      () => normalizeStatusRetryPolicy({ nope: { baseDelayMs: 1, maxAttempts: 1 } }),
      RangeError
    );
  });
});

describe("status-retry matching", () => {
  const a = { baseDelayMs: 500, maxAttempts: 6, multiplier: 3 };
  const b = { baseDelayMs: 200, maxAttempts: 2, multiplier: 2 };

  it("exact selector beats class, class falls back, unknown misses", () => {
    const cfg: StatusRetryPolicyConfig = { "5xx": a, "503": b };
    assert.deepEqual(matchStatusRetryPolicy(cfg, 503), b);
    assert.deepEqual(matchStatusRetryPolicy(cfg, 500), a);
    assert.deepEqual(matchStatusRetryPolicy(cfg, 502), a);
    assert.equal(matchStatusRetryPolicy({ "4xx": a }, 400), a);
    assert.equal(matchStatusRetryPolicy({ "4xx": a }, 200), undefined);
    assert.equal(matchStatusRetryPolicy(cfg, 429), undefined);
    assert.equal(matchStatusRetryPolicy(undefined, 503), undefined);
    assert.equal(matchStatusRetryPolicy(cfg, undefined), undefined);
  });

  it("exponential schedule: base * multiplier^attempt, default 2", () => {
    const plain = { baseDelayMs: 1000, maxAttempts: 3 };
    assert.equal(statusRetryDelayMs(plain, 0), 1000);
    assert.equal(statusRetryDelayMs(plain, 1), 2000);
    assert.equal(statusRetryDelayMs(plain, 2), 4000);
    const steep = { baseDelayMs: 100, maxAttempts: 4, multiplier: 3 };
    assert.equal(statusRetryDelayMs(steep, 0), 100);
    assert.equal(statusRetryDelayMs(steep, 1), 300);
    assert.equal(statusRetryDelayMs(steep, 2), 900);
  });
});

describe("RetryQueue status retry policy", () => {
  it("rejects illegal endpointStatusRetryPolicies at construction", () => {
    const timer = captureTimer();
    assert.throws(
      () => statusQueue(timer, { [ENDPOINT]: { nope: { baseDelayMs: 1, maxAttempts: 1 } } }),
      RangeError
    );
    assert.throws(
      () => statusQueue(timer, { "": { "503": { baseDelayMs: 1, maxAttempts: 1 } } }),
      RangeError
    );
    assert.throws(
      () => statusQueue(timer, "nope" as never),
      RangeError
    );
  });

  it("applies the matched schedule's delay and attempt budget", async () => {
    const timer = captureTimer();
    const q = statusQueue(timer, { [ENDPOINT]: { "503": { baseDelayMs: 5000, maxAttempts: 3 } } });
    q.start();
    q.enqueue({ id: "s1", payload: Buffer.from("x"), targetUrl: ENDPOINT, headers: {} });
    await timer.run();
    // The queue passes the post-increment attempt counter (the same
    // convention as the global delayForAttempt call site): after
    // attempt 1 fails the delay is 5000*2, after attempt 2 it is
    // 5000*4 — the status schedule, not the global 1000-base one.
    assert.deepEqual(retryDelays(timer), [10000, 20000]);
    assert.equal(q.getDeadLetter().length, 1);
    assert.equal(q.getDeadLetter()[0].attempts, 3);
    assert.equal(q.pendingCount(), 0);
    q.stop();
  });

  it("unmatched statuses keep the global schedule", async () => {
    const timer = captureTimer();
    const q = statusQueue(timer, { [ENDPOINT]: { "503": { baseDelayMs: 5000, maxAttempts: 3 } } }, {
      sender: throwingSender(() => new HttpDeliveryError(500)),
    });
    q.start();
    q.enqueue({ id: "s2", payload: Buffer.from("x"), targetUrl: ENDPOINT, headers: {} });
    await timer.run();
    assert.deepEqual(retryDelays(timer), [2000, 4000, 8000, 16000]);
    assert.equal(q.getDeadLetter()[0].attempts, 5);
    q.stop();
  });

  it("class selector falls back for unmatched codes", async () => {
    const timer = captureTimer();
    const q = statusQueue(timer, { [ENDPOINT]: { "5xx": { baseDelayMs: 200, maxAttempts: 2 } } }, {
      sender: throwingSender(() => new HttpDeliveryError(502)),
    });
    q.start();
    q.enqueue({ id: "s3", payload: Buffer.from("x"), targetUrl: ENDPOINT, headers: {} });
    await timer.run();
    assert.deepEqual(retryDelays(timer), [400]);
    assert.equal(q.getDeadLetter()[0].attempts, 2);
    q.stop();
  });

  it("exact selector beats class for the attempt budget too", async () => {
    const timer = captureTimer();
    const q = statusQueue(timer, {
      [ENDPOINT]: {
        "5xx": { baseDelayMs: 100, maxAttempts: 5 },
        "503": { baseDelayMs: 100, maxAttempts: 2 },
      },
    });
    q.start();
    q.enqueue({ id: "s4", payload: Buffer.from("x"), targetUrl: ENDPOINT, headers: {} });
    await timer.run();
    assert.equal(q.getDeadLetter()[0].attempts, 2);
    q.stop();
  });

  it("the status schedule ignores the queue's jitter", async () => {
    const timer = captureTimer();
    const q = statusQueue(timer, { [ENDPOINT]: { "503": { baseDelayMs: 1000, maxAttempts: 2 } } }, {
      jitterMs: 100,
      random: () => 1, // maximum jitter draw
    });
    q.start();
    q.enqueue({ id: "s5", payload: Buffer.from("x"), targetUrl: ENDPOINT, headers: {} });
    await timer.run();
    // Deterministic: no jitter is added to the status schedule (post-
    // increment attempt 1 -> 1000*2).
    assert.deepEqual(retryDelays(timer), [2000]);
    q.stop();
  });

  it("429 Retry-After composes as max(policy delay, retryAfterMs)", async () => {
    // Downstream asks for longer than the policy: its request wins.
    {
      const timer = captureTimer();
      const q = statusQueue(timer, { [ENDPOINT]: { "429": { baseDelayMs: 1000, maxAttempts: 3 } } }, {
        sender: throwingSender(() => new HttpDeliveryError(429, 10_000)),
      });
      q.start();
      q.enqueue({ id: "s6a", payload: Buffer.from("x"), targetUrl: ENDPOINT, headers: {} });
      await timer.run();
      assert.equal(retryDelays(timer)[0], 10_000);
      q.stop();
    }
    // Policy is longer than the downstream's ask: the policy wins.
    {
      const timer = captureTimer();
      const q = statusQueue(timer, { [ENDPOINT]: { "429": { baseDelayMs: 5000, maxAttempts: 3 } } }, {
        sender: throwingSender(() => new HttpDeliveryError(429, 100)),
      });
      q.start();
      q.enqueue({ id: "s6b", payload: Buffer.from("x"), targetUrl: ENDPOINT, headers: {} });
      await timer.run();
      // Post-increment attempt 1: policy delay 5000*2 = 10000 > 100.
      assert.equal(retryDelays(timer)[0], 10000);
      q.stop();
    }
  });

  it("Retry-After alone is unchanged when no policy matches (WR-30)", async () => {
    const timer = captureTimer();
    const q = statusQueue(timer, { [ENDPOINT]: { "503": { baseDelayMs: 5000, maxAttempts: 3 } } }, {
      sender: throwingSender(() => new HttpDeliveryError(429, 7000)),
    });
    q.start();
    q.enqueue({ id: "s7", payload: Buffer.from("x"), targetUrl: ENDPOINT, headers: {} });
    await timer.run();
    assert.equal(retryDelays(timer)[0], 7000);
    q.stop();
  });

  it("non-retryable 4xx dead-letters on the first attempt despite a policy", async () => {
    const timer = captureTimer();
    const q = statusQueue(timer, {
      [ENDPOINT]: {
        "4xx": { baseDelayMs: 100, maxAttempts: 9 },
        "400": { baseDelayMs: 100, maxAttempts: 9 },
      },
    }, {
      sender: throwingSender(() => new HttpDeliveryError(400)),
    });
    q.start();
    q.enqueue({ id: "s8", payload: Buffer.from("x"), targetUrl: ENDPOINT, headers: {} });
    await timer.run();
    // WR-30: first attempt, instant dead-letter — the policy entries are inert.
    assert.equal(q.getDeadLetter().length, 1);
    assert.equal(q.getDeadLetter()[0].attempts, 1);
    assert.equal(q.getDeadLetter()[0].failureClass, "non_retryable");
    assert.equal(timer.delays.length, 1); // only the initial dispatch; no retry scheduled
    q.stop();
  });

  it("non-HTTP failures ignore the policy and keep the global schedule", async () => {
    const timer = captureTimer();
    const q = statusQueue(timer, { [ENDPOINT]: { "503": { baseDelayMs: 5000, maxAttempts: 3 } } }, {
      sender: throwingSender(() => new Error("dns boom")),
    });
    q.start();
    q.enqueue({ id: "s9", payload: Buffer.from("x"), targetUrl: ENDPOINT, headers: {} });
    await timer.run();
    assert.deepEqual(retryDelays(timer), [2000, 4000, 8000, 16000]);
    assert.equal(q.getDeadLetter()[0].attempts, 5);
    q.stop();
  });

  it("the circuit breaker still records failures under a status policy (WR-10)", async () => {
    // The breaker trips exactly on the last attempt: no breaker-open
    // parking loop, the delivery simply dead-letters with the breaker
    // open behind it.
    const timer = captureTimer();
    const q = statusQueue(timer, { [ENDPOINT]: { "503": { baseDelayMs: 10, maxAttempts: 3 } } }, {
      circuitBreaker: { failureThreshold: 3, cooldownMs: 60_000 },
    });
    q.start();
    q.enqueue({ id: "s10", payload: Buffer.from("x"), targetUrl: ENDPOINT, headers: {} });
    await timer.run();
    assert.equal(q.getDeadLetter().length, 1);
    assert.equal(q.getDeadLetter()[0].attempts, 3);
    const row = q.getCircuitStats().find((r) => r.endpoint === ENDPOINT);
    assert.ok(row, "circuit stats should carry the endpoint");
    assert.ok(row!.trips >= 1, "breaker must trip on the status-policy failures");
    assert.equal(row!.state, "open");
    q.stop();
  });

  it("set/clear/statusRetryPolicyFor at runtime", () => {
    const timer = captureTimer();
    const q = statusQueue(timer, undefined);
    assert.equal(q.statusRetryPolicyFor(ENDPOINT), undefined);
    assert.throws(
      () => q.setEndpointStatusRetryPolicy("", { "503": { baseDelayMs: 1, maxAttempts: 1 } }),
      RangeError
    );
    assert.throws(
      () => q.setEndpointStatusRetryPolicy(ENDPOINT, { nope: { baseDelayMs: 1, maxAttempts: 1 } }),
      RangeError
    );
    assert.equal(q.statusRetryPolicyFor(ENDPOINT), undefined);
    q.setEndpointStatusRetryPolicy(ENDPOINT, { "503": { baseDelayMs: 500, maxAttempts: 4 } });
    assert.deepEqual(q.statusRetryPolicyFor(ENDPOINT), {
      "503": { baseDelayMs: 500, maxAttempts: 4, multiplier: 2 },
    });
    // The returned copy is detached: mutating it cannot touch the stored policy.
    const copy = q.statusRetryPolicyFor(ENDPOINT)!;
    copy["503"].maxAttempts = 999;
    assert.equal(q.statusRetryPolicyFor(ENDPOINT)!["503"].maxAttempts, 4);
    assert.equal(q.clearEndpointStatusRetryPolicy(ENDPOINT), true);
    assert.equal(q.statusRetryPolicyFor(ENDPOINT), undefined);
    assert.equal(q.clearEndpointStatusRetryPolicy(ENDPOINT), false);
    q.stop();
  });

  it("updateEndpointConfig applies, audits, and clears the policy (WR-32)", async () => {
    const timer = captureTimer();
    const q = statusQueue(timer, undefined);
    const changes = q.updateEndpointConfig(ENDPOINT, {
      statusRetryPolicy: { "503": { baseDelayMs: 300, maxAttempts: 2 } },
    });
    assert.deepEqual(changes, [
      {
        field: "statusRetryPolicy",
        from: null,
        to: { "503": { baseDelayMs: 300, maxAttempts: 2, multiplier: 2 } },
      },
    ]);
    // The patched schedule governs new deliveries immediately
    // (post-increment attempt 1 -> 300*2).
    q.start();
    q.enqueue({ id: "s11", payload: Buffer.from("x"), targetUrl: ENDPOINT, headers: {} });
    await timer.run();
    assert.deepEqual(retryDelays(timer), [600]);
    assert.equal(q.getDeadLetter()[0].attempts, 2);
    // Detach with null: back to the global schedule.
    const cleared = q.updateEndpointConfig(ENDPOINT, { statusRetryPolicy: null });
    assert.equal(cleared[0].field, "statusRetryPolicy");
    assert.equal(cleared[0].to, null);
    assert.equal(q.statusRetryPolicyFor(ENDPOINT), undefined);
    // An illegal patch throws and leaves the live config untouched.
    assert.throws(
      () => q.updateEndpointConfig(ENDPOINT, { statusRetryPolicy: { nope: { baseDelayMs: 1, maxAttempts: 1 } } }),
      RangeError
    );
    assert.equal(q.statusRetryPolicyFor(ENDPOINT), undefined);
    q.stop();
  });

  it("an illegal hot-reload patch leaves the existing policy intact", () => {
    const timer = captureTimer();
    const q = statusQueue(timer, { [ENDPOINT]: { "503": { baseDelayMs: 300, maxAttempts: 2 } } });
    assert.throws(
      () => q.updateEndpointConfig(ENDPOINT, {
        statusRetryPolicy: { "503": { baseDelayMs: 0, maxAttempts: 2 } },
      }),
      RangeError
    );
    assert.deepEqual(q.statusRetryPolicyFor(ENDPOINT), {
      "503": { baseDelayMs: 300, maxAttempts: 2, multiplier: 2 },
    });
    q.stop();
  });
});
