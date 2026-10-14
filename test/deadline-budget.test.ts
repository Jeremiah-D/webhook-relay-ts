import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import {
  RetryQueue,
  type DeliveryDeadlineExceededInfo,
  type Sender,
  type SloMissInfo,
} from "../src/retry.ts";
import {
  DeadlineBudgetTimeoutError,
  readDeadlineBudgetMs,
  resolveDeadlineBudget,
} from "../src/deadline-budget.ts";
import { createDefaultSender } from "../src/server.ts";

const URL = "http://localhost:9999/hook";

/** Steppable timer: each `step()` runs the currently pending callbacks once. */
function stepTimer() {
  const pending: Array<() => void> = [];
  return {
    pending,
    setTimer: (fn: () => void, _ms: number) => {
      pending.push(fn);
      return {
        clear: () => {
          const i = pending.indexOf(fn);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    clearTimer: (h: { clear(): void }) => h.clear(),
    async step() {
      const fns = pending.splice(0);
      for (const fn of fns) fn();
      // One macrotask flushes the whole deliver() microtask chain.
      await new Promise((r) => setImmediate(r));
    },
  };
}

const ITEM = {
  id: "item-1",
  payload: Buffer.from("hello"),
  targetUrl: URL,
  headers: { "content-type": "application/json" },
};

const flushReal = async (ms: number) => {
  await new Promise((r) => setTimeout(r, ms));
  await new Promise((r) => setImmediate(r));
};

describe("deadline budget propagation (WR-99)", () => {
  it("rejects invalid budget options at construction", () => {
    assert.throws(
      () =>
        new RetryQueue({
          deliveryDeadline: { deadlines: { [URL]: 1000 }, minAttemptBudgetMs: -1 },
        }),
      RangeError
    );
    assert.throws(
      () =>
        new RetryQueue({
          deliveryDeadline: { deadlines: { [URL]: 1000 }, minAttemptBudgetMs: Number.NaN },
        }),
      RangeError
    );
    assert.throws(
      () =>
        new RetryQueue({
          deliveryDeadline: {
            deadlines: { [URL]: 1000 },
            propagateBudget: "yes" as unknown as boolean,
          },
        }),
      RangeError
    );
    // Valid configs construct fine.
    new RetryQueue({ deliveryDeadline: { deadlines: { [URL]: 1000 } } });
    new RetryQueue({
      deliveryDeadline: { deadlines: { [URL]: 1000 }, propagateBudget: false, minAttemptBudgetMs: 50 },
    });
    new RetryQueue({});
  });

  it("resolveDeadlineBudget: expired iff remaining is at/below the floor", () => {
    // Floor 0 keeps the exact WR-76 semantics: expired iff elapsed >= deadline.
    assert.deepEqual(resolveDeadlineBudget(1000, 999, 0), { expired: false, remainingMs: 1 });
    assert.deepEqual(resolveDeadlineBudget(1000, 1000, 0), { expired: true, remainingMs: 0 });
    assert.deepEqual(resolveDeadlineBudget(1000, 1200, 0), { expired: true, remainingMs: 0 });
    // A positive floor short-circuits dispatches that could not usefully finish.
    assert.deepEqual(resolveDeadlineBudget(1000, 850, 200), { expired: true, remainingMs: 150 });
    assert.deepEqual(resolveDeadlineBudget(1000, 799, 200), { expired: false, remainingMs: 201 });
  });

  it("readDeadlineBudgetMs: ignores absent/non-positive/garbage budgets", () => {
    assert.equal(readDeadlineBudgetMs({}), undefined);
    assert.equal(readDeadlineBudgetMs({ deadlineBudgetMs: 0 }), undefined);
    assert.equal(readDeadlineBudgetMs({ deadlineBudgetMs: -5 }), undefined);
    assert.equal(readDeadlineBudgetMs({ deadlineBudgetMs: Number.NaN }), undefined);
    assert.equal(readDeadlineBudgetMs({ deadlineBudgetMs: "100" }), undefined);
    assert.equal(readDeadlineBudgetMs({ deadlineBudgetMs: 250 }), 250);
  });

  it("short-circuits dispatch at/below minAttemptBudgetMs without calling the downstream", async () => {
    const t = stepTimer();
    let nowMs = 0;
    let senderCalls = 0;
    const expired: DeliveryDeadlineExceededInfo[] = [];
    const q = new RetryQueue({
      sender: async () => {
        senderCalls += 1;
      },
      baseDelayMs: 100,
      maxDelayMs: 10_000,
      maxAttempts: 5,
      jitterMs: 0,
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
      deliveryDeadline: { deadlines: { [URL]: 1000 }, now: () => nowMs, minAttemptBudgetMs: 200 },
      onDeliveryDeadlineExceeded: (info) => expired.push(info),
    });
    q.start();
    q.enqueue({ ...ITEM }); // enqueuedAt = 0
    nowMs = 850; // remaining 150 <= floor 200: pointless to call
    await t.step();
    assert.equal(senderCalls, 0); // no outbound call was issued
    assert.equal(expired.length, 1);
    assert.equal(expired[0].elapsedMs, 850);
    assert.equal(expired[0].deadlineMs, 1000);
    assert.equal(expired[0].attempts, 0);
    const dead = q.getDeadLetter();
    assert.equal(dead.length, 1);
    assert.equal(dead[0].attempts, 0); // actual attempts, not fabricated
    assert.equal(dead[0].failureClass, "retryable");
    await q.stop();
  });

  it("stamps the remaining budget on the wire copy (propagation default on)", async () => {
    const t = stepTimer();
    let nowMs = 0;
    const seen: Array<number | undefined> = [];
    const q = new RetryQueue({
      sender: (async (item) => {
        seen.push(item.deadlineBudgetMs);
      }) as Sender,
      baseDelayMs: 100,
      maxDelayMs: 10_000,
      maxAttempts: 5,
      jitterMs: 0,
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
      deliveryDeadline: { deadlines: { [URL]: 1000 }, now: () => nowMs },
    });
    q.start();
    q.enqueue({ ...ITEM }); // enqueuedAt = 0
    nowMs = 300;
    await t.step(); // dispatch succeeds
    assert.deepEqual(seen, [700]); // 1000 - 300
    assert.equal(q.getDeadLetter().length, 0);
    await q.stop();
  });

  it("propagateBudget:false keeps WR-76 behavior (no stamp, no sender cap)", async () => {
    const t = stepTimer();
    let nowMs = 0;
    const seen: Array<number | undefined> = [];
    const q = new RetryQueue({
      sender: (async (item) => {
        seen.push(item.deadlineBudgetMs);
      }) as Sender,
      baseDelayMs: 100,
      maxDelayMs: 10_000,
      maxAttempts: 5,
      jitterMs: 0,
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
      deliveryDeadline: {
        deadlines: { [URL]: 1000 },
        now: () => nowMs,
        propagateBudget: false,
      },
    });
    q.start();
    q.enqueue({ ...ITEM });
    nowMs = 300;
    await t.step();
    assert.deepEqual(seen, [undefined]);
    assert.equal(q.getDeadLetter().length, 0);
    await q.stop();
  });

  it("mid-call budget timeout dead-letters with the actual attempt count and attributes slo_missed", async () => {
    const t = stepTimer();
    let nowMs = 0;
    let senderCalls = 0;
    const expired: DeliveryDeadlineExceededInfo[] = [];
    const sloMisses: SloMissInfo[] = [];
    // A sender that honors the stamped budget like the default sender
    // does (the default sender's own race is covered by the server-level
    // test below); the budget here is shortened in real time so the test
    // does not wait out the full stamped 1000ms.
    const sender = ((item) => {
      senderCalls += 1;
      const budget = item.deadlineBudgetMs;
      assert.ok(typeof budget === "number" && budget > 0, "budget must be stamped");
      return new Promise((_resolve, reject) => {
        const timer = setTimeout(
          () => reject(new DeadlineBudgetTimeoutError(item.targetUrl, budget)),
          40
        );
        timer.unref();
      });
    }) as Sender;
    const q = new RetryQueue({
      sender,
      baseDelayMs: 100,
      maxDelayMs: 10_000,
      maxAttempts: 5,
      jitterMs: 0,
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
      deliveryDeadline: { deadlines: { [URL]: 1000 }, now: () => nowMs },
      latency: { sloMs: 5000, now: () => nowMs, onSloMiss: (info) => sloMisses.push(info) },
      onDeliveryDeadlineExceeded: (info) => expired.push(info),
    });
    q.start();
    q.enqueue({ ...ITEM });
    await t.step(); // dispatch: attempt runs, budget fires mid-call
    await flushReal(120); // let the real-time budget timer fire + catch run
    assert.equal(senderCalls, 1); // exactly one physical attempt, no retry
    const dead = q.getDeadLetter();
    assert.equal(dead.length, 1);
    assert.equal(dead[0].attempts, 1); // the attempt really happened
    assert.equal(dead[0].failureClass, "retryable");
    assert.ok(dead[0].lastError.includes("delivery deadline exceeded"));
    assert.equal(expired.length, 1);
    assert.equal(expired[0].attempts, 1);
    assert.equal(expired[0].deadlineMs, 1000);
    // WR-99 attribution: the exhaustion lands in the slo_missed channel,
    // marked as budget exhaustion rather than slowness.
    assert.equal(sloMisses.length, 1);
    assert.equal(sloMisses[0].deadlineBudgetExhausted, true);
    assert.equal(sloMisses[0].sloMs, 1000);
    assert.equal(sloMisses[0].endpoint, URL);
    await q.stop();
  });

  it("queue-side expiry also attributes slo_missed with the exhaustion marker", async () => {
    const t = stepTimer();
    let nowMs = 0;
    const sloMisses: SloMissInfo[] = [];
    const q = new RetryQueue({
      sender: (async () => {}) as Sender,
      baseDelayMs: 100,
      maxDelayMs: 10_000,
      maxAttempts: 5,
      jitterMs: 0,
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
      deliveryDeadline: { deadlines: { [URL]: 250 }, now: () => nowMs },
      latency: { sloMs: 5000, now: () => nowMs, onSloMiss: (info) => sloMisses.push(info) },
    });
    q.start();
    q.enqueue({ ...ITEM });
    nowMs = 300; // past the deadline before the next dispatch
    await t.step();
    assert.equal(q.getDeadLetter().length, 1);
    assert.equal(sloMisses.length, 1);
    assert.equal(sloMisses[0].deadlineBudgetExhausted, true);
    assert.equal(sloMisses[0].latencyMs, 300);
    assert.equal(sloMisses[0].sloMs, 250);
    await q.stop();
  });

  it("no slo_missed attribution when latency tracking is not configured", async () => {
    const t = stepTimer();
    let nowMs = 0;
    const q = new RetryQueue({
      sender: (async () => {}) as Sender,
      baseDelayMs: 100,
      maxDelayMs: 10_000,
      maxAttempts: 5,
      jitterMs: 0,
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
      deliveryDeadline: { deadlines: { [URL]: 250 }, now: () => nowMs },
      // No `latency` option: onSloMiss is undefined, expiry degrades to audit+dead letter only.
    });
    q.start();
    q.enqueue({ ...ITEM });
    nowMs = 300;
    await t.step();
    assert.equal(q.getDeadLetter().length, 1); // expiry still works
    await q.stop();
  });
});

describe("deadline budget: default sender enforcement (WR-99)", () => {
  it("caps a hanging downstream call at the stamped budget", async () => {
    // A stub that never responds: without the budget the sender would
    // wait forever (the HTTP/1.1 path has no other per-attempt timeout).
    const server = createServer((_req, _res) => {
      // hang: never write a response
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const addr = server.address();
    assert.ok(addr !== null && typeof addr === "object");
    const target = `http://127.0.0.1:${addr.port}/hook`;
    try {
      const sender = createDefaultSender();
      const item = {
        id: "budget-1",
        payload: Buffer.from("hello"),
        targetUrl: target,
        headers: {},
        deadlineBudgetMs: 60,
      };
      const started = Date.now();
      await assert.rejects(sender(item), (err: unknown) => {
        assert.ok(err instanceof DeadlineBudgetTimeoutError);
        assert.equal(err.targetUrl, target);
        return true;
      });
      const elapsed = Date.now() - started;
      // The attempt was cut at the budget, not left hanging: generous
      // upper bound keeps the test robust on slow CI.
      assert.ok(elapsed < 5000, `budget not enforced, took ${elapsed}ms`);
      (sender as unknown as { destroy(): void }).destroy();
    } finally {
      server.close();
    }
  });

  it("leaves deliveries without a stamped budget untouched", async () => {
    const server = createServer((_req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("ok");
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const addr = server.address();
    assert.ok(addr !== null && typeof addr === "object");
    const target = `http://127.0.0.1:${addr.port}/hook`;
    try {
      const sender = createDefaultSender();
      const res = await sender({
        id: "nobudget-1",
        payload: Buffer.from("hello"),
        targetUrl: target,
        headers: {},
      });
      assert.equal(res?.statusCode, 200);
    } finally {
      server.close();
    }
  });
});
