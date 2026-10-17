import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  RetryQueue,
  RetryBudget,
  type RetryBudgetDepletedInfo,
  type Sender,
} from "../src/retry.ts";

/** Deterministic timer: `run()` executes pending callbacks immediately. */
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
    async run() {
      while (pending.length > 0) {
        const fns = pending.splice(0);
        for (const fn of fns) fn();
        await new Promise((r) => setImmediate(r));
      }
    },
  };
}

const URL_A = "http://localhost:9999/a";
const URL_B = "http://localhost:9999/b";

function item(id: string, targetUrl: string) {
  return { id, payload: Buffer.from("x"), targetUrl, headers: {} };
}

describe("WR-125 per-endpoint retry budget (unit)", () => {
  it("remaining() snapshots the current token count after refill", () => {
    let now = 0;
    const b = new RetryBudget(2, () => now);
    assert.equal(b.remaining(), 2);
    assert.ok(b.take());
    assert.equal(b.remaining(), 1);
    // One token refills after 30s at 2/min; the snapshot is exact.
    now = 30_000;
    assert.equal(b.remaining(), 2);
  });
});

describe("WR-125 per-endpoint retry budget (queue)", () => {
  it("parks only the overridden endpoint; other endpoints are unaffected", async () => {
    const timer = manualTimer();
    const now = { ms: 0 };
    const depleted: RetryBudgetDepletedInfo[] = [];
    let senderCallsA = 0;
    let senderCallsB = 0;
    const sender: Sender = async (it) => {
      if (it.targetUrl === URL_A) senderCallsA += 1;
      else senderCallsB += 1;
      throw new Error("downstream down");
    };
    const q = new RetryQueue({
      sender,
      baseDelayMs: 100,
      maxDelayMs: 5000,
      maxAttempts: 4,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      retryBudget: {
        retriesPerMinute: 6000,
        perEndpointRetriesPerMinute: { [URL_A]: 1 },
        now: () => now.ms,
      },
      onRetryBudgetDepleted: (info) => depleted.push(info),
    });
    q.start();
    q.enqueue(item("a1", URL_A));
    q.enqueue(item("b1", URL_B));
    await timer.run();
    // A: attempt 1 fails -> endpoint bucket (1/min) funds retry 1;
    // attempts 2 and 3 find the endpoint bucket empty -> parked with
    // scope "endpoint"; attempt 4 exhausts maxAttempts -> dead letter.
    // B has no override: its retries are funded by the generous global
    // budget and never park.
    assert.equal(senderCallsA, 4);
    assert.equal(senderCallsB, 4);
    assert.equal(depleted.length, 2);
    assert.ok(depleted.every((d) => d.scope === "endpoint"));
    assert.ok(depleted.every((d) => d.endpoint === URL_A));
    assert.deepEqual(
      depleted.map((d) => d.attempts),
      [2, 3]
    );
    assert.equal(depleted[0].waitMs, 60000);
    const dead = q.getDeadLetter();
    assert.equal(dead.length, 2);
    // Stats: the endpoint row exposes its own budget, park count, and
    // remaining tokens (frozen clock -> exact 0).
    assert.deepEqual(q.getRetryBudgetStats(), {
      retriesPerMinute: 6000,
      depleted: 2,
      endpoints: [{ endpoint: URL_A, retriesPerMinute: 1, depleted: 2, remainingTokens: 0 }],
    });
    // Prometheus: the unlabeled global row is retained, plus one
    // endpoint-labeled series.
    const exposition = q.renderMetrics();
    assert.ok(exposition.includes("relay_retry_budget_depleted_total 2"));
    assert.ok(exposition.includes(`relay_retry_budget_depleted_total{endpoint="${URL_A}"} 2`));
    q.stop();
  });

  it("the global budget still gates endpoints with a generous override", async () => {
    const timer = manualTimer();
    const now = { ms: 0 };
    const depleted: RetryBudgetDepletedInfo[] = [];
    const alwaysFail: Sender = async () => {
      throw new Error("downstream down");
    };
    const q = new RetryQueue({
      sender: alwaysFail,
      baseDelayMs: 100,
      maxDelayMs: 5000,
      maxAttempts: 4,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      retryBudget: {
        retriesPerMinute: 1,
        perEndpointRetriesPerMinute: { [URL_A]: 6000 },
        now: () => now.ms,
      },
      onRetryBudgetDepleted: (info) => depleted.push(info),
    });
    q.start();
    q.enqueue(item("a1", URL_A));
    await timer.run();
    // Attempt 1's retry takes the last global token; attempts 2 and 3
    // park on the *global* bucket even though the endpoint bucket is
    // flush — the global budget stays the final gate.
    assert.equal(depleted.length, 2);
    assert.ok(depleted.every((d) => d.scope === "global"));
    assert.deepEqual(
      depleted.map((d) => d.attempts),
      [2, 3]
    );
    assert.equal(q.getRetryBudgetStats()?.depleted, 2);
    assert.equal(q.getRetryBudgetStats()?.endpoints?.[0].depleted, 2);
    q.stop();
  });

  it("the endpoint bucket gates before the global bucket and never spends it", async () => {
    // The ordering property that makes WR-125 isolation real: when the
    // endpoint bucket is exhausted, the retry parks without consuming a
    // global token — one endpoint's storm cannot drain the shared budget.
    const timer = manualTimer();
    const now = { ms: 0 };
    const depleted: RetryBudgetDepletedInfo[] = [];
    const alwaysFail: Sender = async () => {
      throw new Error("downstream down");
    };
    const q = new RetryQueue({
      sender: alwaysFail,
      baseDelayMs: 100,
      maxDelayMs: 5000,
      maxAttempts: 4,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      retryBudget: {
        retriesPerMinute: 2,
        perEndpointRetriesPerMinute: { [URL_A]: 1 },
        now: () => now.ms,
      },
      onRetryBudgetDepleted: (info) => depleted.push(info),
    });
    q.start();
    q.enqueue(item("a1", URL_A));
    q.enqueue(item("b1", URL_B));
    await timer.run();
    // A attempt 1 spends 1 endpoint token + 1 global token. A attempt 2
    // parks on its own bucket (scope "endpoint") without spending the
    // remaining global token — B's attempt-1 retry is still funded by it.
    // B attempt 2 then exhausts the global budget (scope "global").
    assert.deepEqual(
      depleted.map((d) => [d.endpoint, d.scope, d.attempts]),
      [
        [URL_A, "endpoint", 2],
        [URL_B, "global", 2],
        [URL_A, "endpoint", 3],
        [URL_B, "global", 3],
      ]
    );
    const stats = q.getRetryBudgetStats()!;
    assert.equal(stats.depleted, 4);
    assert.deepEqual(
      stats.endpoints?.map((e) => [e.endpoint, e.depleted]),
      [[URL_A, 2]]
    );
    q.stop();
  });

  it("paused endpoints park without touching any budget (WR-50)", async () => {
    const timer = manualTimer();
    const depleted: RetryBudgetDepletedInfo[] = [];
    const sender: Sender = async () => {};
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      retryBudget: {
        retriesPerMinute: 6000,
        perEndpointRetriesPerMinute: { [URL_A]: 1 },
      },
      onRetryBudgetDepleted: (info) => depleted.push(info),
    });
    q.start();
    q.pauseEndpoint(URL_A);
    q.enqueue(item("a1", URL_A));
    await timer.run();
    assert.deepEqual(depleted, []);
    assert.equal(q.getRetryBudgetStats()?.depleted, 0);
    // The endpoint bucket is untouched: a full token still waits.
    assert.equal(q.getRetryBudgetStats()?.endpoints?.[0].remainingTokens, 1);
    q.stop();
  });

  it("rejects illegal per-endpoint overrides at construction", () => {
    for (const bad of [0, -1, NaN, Infinity]) {
      assert.throws(
        () =>
          new RetryQueue({
            retryBudget: { perEndpointRetriesPerMinute: { [URL_A]: bad } },
          }),
        RangeError,
        `budget ${bad}`
      );
    }
    assert.throws(
      () =>
        new RetryQueue({
          retryBudget: { perEndpointRetriesPerMinute: { "": 5 } },
        }),
      RangeError,
      "empty key"
    );
    assert.throws(
      () =>
        new RetryQueue({
          retryBudget: { perEndpointRetriesPerMinute: "nope" as never },
        }),
      RangeError,
      "non-record"
    );
    assert.throws(
      () =>
        new RetryQueue({
          retryBudget: { perEndpointRetriesPerMinute: [5] as never },
        }),
      RangeError,
      "array"
    );
  });

  it("default-off: no overrides, no endpoint series, unchanged stats shape", async () => {
    const timer = manualTimer();
    const now = { ms: 0 };
    const alwaysFail: Sender = async () => {
      throw new Error("downstream down");
    };
    const q = new RetryQueue({
      sender: alwaysFail,
      baseDelayMs: 100,
      maxDelayMs: 5000,
      maxAttempts: 3,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      retryBudget: { retriesPerMinute: 1, now: () => now.ms },
      onRetryBudgetDepleted: () => {},
    });
    q.start();
    q.enqueue(item("a1", URL_A));
    await timer.run();
    const stats = q.getRetryBudgetStats()!;
    assert.deepEqual(stats, { retriesPerMinute: 1, depleted: 1 });
    assert.ok(!("endpoints" in stats));
    // The global row renders; no endpoint-labeled budget series exists.
    const exposition = q.renderMetrics();
    assert.ok(exposition.includes("relay_retry_budget_depleted_total 1"));
    assert.ok(!exposition.includes("relay_retry_budget_depleted_total{endpoint="));
    q.stop();
  });
});
