import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  RetryQueue,
  DeliveryDeadlineExceededError,
  type DeliveryDeadlineExceededInfo,
  type Sender,
} from "../src/retry.ts";

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
      // One macrotask flushes the whole deliver() microtask chain
      // (lane turn, limiter, global gate, sender, catch, reschedule).
      await new Promise((r) => setImmediate(r));
    },
  };
}

const baseOpts = (t: ReturnType<typeof stepTimer>, now: () => number, sender: Sender) => ({
  sender,
  baseDelayMs: 100,
  maxDelayMs: 10_000,
  maxAttempts: 5,
  jitterMs: 0,
  setTimer: t.setTimer,
  clearTimer: t.clearTimer,
  deliveryDeadline: { deadlines: { [URL]: 250 }, now },
});

const ITEM = {
  id: "item-1",
  payload: Buffer.from("hello"),
  targetUrl: URL,
  headers: { "content-type": "application/json" },
};

describe("delivery deadline (WR-76)", () => {
  it("rejects invalid deadline configs at construction", () => {
    for (const deadlines of [
      { [URL]: 0 },
      { [URL]: -100 },
      { [URL]: Number.NaN },
      { [URL]: Number.POSITIVE_INFINITY },
      { [URL]: "250" },
      { "": 250 },
    ]) {
      assert.throws(
        () =>
          new RetryQueue({
            deliveryDeadline: { deadlines: deadlines as Record<string, number> },
          }),
        RangeError,
        JSON.stringify(deadlines)
      );
    }
    assert.throws(
      () =>
        new RetryQueue({
          deliveryDeadline: { deadlines: null as unknown as Record<string, number> },
        }),
      RangeError
    );
    // Valid configs construct fine.
    new RetryQueue({ deliveryDeadline: { deadlines: { [URL]: 1 } } });
    new RetryQueue({});
  });

  it("dead-letters an item whose deadline expired before its next attempt", async () => {
    const t = stepTimer();
    let nowMs = 0;
    let attempts = 0;
    const expired: DeliveryDeadlineExceededInfo[] = [];
    const q2 = new RetryQueue({
      ...baseOpts(t, () => nowMs, async () => {
        attempts += 1;
        throw new Error("boom");
      }),
      onDeliveryDeadlineExceeded: (info) => expired.push(info),
    });
    q2.start();
    q2.enqueue({ ...ITEM });
    await t.step(); // attempt 1 at t=0 fails, retry scheduled
    assert.equal(attempts, 1);
    assert.equal(q2.getDeadLetter().length, 0);
    nowMs = 300; // the deadline (250) passes while the retry is backed off
    await t.step(); // the next dispatch sees the expired deadline instead of attempting
    assert.equal(attempts, 1); // no second attempt was dispatched
    assert.equal(q2.pendingCount(), 0);
    const dead = q2.getDeadLetter();
    assert.equal(dead.length, 1);
    assert.equal(dead[0].id, "item-1");
    assert.equal(dead[0].attempts, 1); // actual attempts, not fabricated
    assert.ok(dead[0].lastError.includes("delivery deadline exceeded"));
    assert.equal(dead[0].failureClass, "retryable");
    assert.ok(dead[0].deadLetteredAt.length > 0); // normal retention semantics apply
    assert.equal(expired.length, 1);
    assert.equal(expired[0].id, "item-1");
    assert.equal(expired[0].endpoint, URL);
    assert.equal(expired[0].attempts, 1);
    assert.equal(expired[0].deadlineMs, 250);
    assert.equal(expired[0].elapsedMs, 300);
    // The counter is exported per endpoint...
    assert.ok(
      q2.renderMetrics().includes(`relay_delivery_deadline_exceeded_total{endpoint="${URL}"} 1`)
    );
    // ...and the item also shows up in the regular dead-letter delivery counter.
    assert.ok(q2.renderMetrics().includes(`status="dead_letter"} 1`));
  });

  it("delivers normally while inside the deadline", async () => {
    const t = stepTimer();
    let nowMs = 0;
    let attempts = 0;
    const expired: DeliveryDeadlineExceededInfo[] = [];
    const q = new RetryQueue({
      ...baseOpts(t, () => nowMs, async () => {
        attempts += 1;
        if (attempts < 3) throw new Error("boom");
      }),
      deliveryDeadline: { deadlines: { [URL]: 10_000 }, now: () => nowMs },
      onDeliveryDeadlineExceeded: (info) => expired.push(info),
    });
    q.start();
    q.enqueue({ ...ITEM });
    await t.step(); // attempt 1 fails
    nowMs = 500;
    await t.step(); // attempt 2 fails
    nowMs = 900;
    await t.step(); // attempt 3 succeeds
    assert.equal(attempts, 3);
    assert.equal(q.pendingCount(), 0);
    assert.equal(q.getDeadLetter().length, 0);
    assert.equal(expired.length, 0);
    assert.ok(!q.renderMetrics().includes("relay_delivery_deadline_exceeded_total"));
  });

  it("counts pause parking toward the deadline", async () => {
    const t = stepTimer();
    let nowMs = 0;
    let attempts = 0;
    const expired: DeliveryDeadlineExceededInfo[] = [];
    const q = new RetryQueue({
      ...baseOpts(t, () => nowMs, async () => {
        attempts += 1;
      }),
      onDeliveryDeadlineExceeded: (info) => expired.push(info),
    });
    q.start();
    q.enqueue({ ...ITEM });
    q.pauseEndpoint(URL);
    await t.step(); // deliver() parks behind the pause — no attempt
    assert.equal(attempts, 0);
    assert.equal(q.pendingCount(), 1);
    nowMs = 600; // the deadline passes while parked
    q.resumeEndpoint(URL);
    await t.step(); // resumed dispatch expires instead of attempting
    assert.equal(attempts, 0);
    assert.equal(q.pendingCount(), 0);
    const dead = q.getDeadLetter();
    assert.equal(dead.length, 1);
    assert.equal(dead[0].attempts, 0);
    assert.equal(expired.length, 1);
    assert.equal(expired[0].attempts, 0);
  });

  it("leaves deliveries alone when no deadline is configured", async () => {
    const t = stepTimer();
    let attempts = 0;
    const q = new RetryQueue({
      sender: async () => {
        attempts += 1;
        throw new Error("always fails");
      },
      baseDelayMs: 10,
      maxAttempts: 3,
      jitterMs: 0,
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
    });
    q.start();
    q.enqueue({ ...ITEM });
    await t.step();
    await t.step();
    await t.step();
    assert.equal(attempts, 3); // full retry budget consumed, no deadline interference
    assert.equal(q.getDeadLetter().length, 1);
    assert.ok(!q.renderMetrics().includes("relay_delivery_deadline_exceeded_total"));
  });

  it("a replay starts a fresh deadline", async () => {
    const t = stepTimer();
    let nowMs = 0;
    let attempts = 0;
    let fail = true;
    const q = new RetryQueue(
      baseOpts(t, () => nowMs, async () => {
        attempts += 1;
        if (fail) throw new Error("boom");
      })
    );
    q.start();
    q.enqueue({ ...ITEM });
    await t.step(); // attempt 1 fails at t=0
    nowMs = 600;
    await t.step(); // expired → dead letter
    assert.equal(q.getDeadLetter().length, 1);
    // A replay re-enters with a fresh admission instant: the same 250ms
    // deadline must not instantly expire the replayed delivery.
    nowMs = 1000;
    fail = false;
    assert.equal(q.replayDeadLetter("item-1"), true);
    await t.step();
    assert.equal(attempts, 2);
    assert.equal(q.pendingCount(), 0);
    assert.equal(q.getDeadLetter().length, 0);
  });

  it("matches the deadline per exact targetUrl only", async () => {
    const t = stepTimer();
    let nowMs = 0;
    let attempts = 0;
    const other = "http://localhost:9999/other";
    const q = new RetryQueue(
      baseOpts(t, () => nowMs, async () => {
        attempts += 1;
        throw new Error("boom");
      })
    );
    q.start();
    q.enqueue({ ...ITEM, id: "a", targetUrl: URL });
    q.enqueue({ ...ITEM, id: "b", targetUrl: other });
    await t.step(); // both attempt once at t=0
    assert.equal(attempts, 2);
    nowMs = 10_000;
    await t.step(); // URL expires; `other` has no deadline and retries
    await t.step();
    const dead = q.getDeadLetter();
    assert.equal(dead.length, 1);
    assert.equal(dead[0].id, "a");
    assert.ok(
      q.renderMetrics().includes(`relay_delivery_deadline_exceeded_total{endpoint="${URL}"} 1`)
    );
    assert.ok(!q.renderMetrics().includes(`endpoint="${other}"} 1`));
  });

  it("labels the counter with the tenant when set", async () => {
    const t = stepTimer();
    let nowMs = 0;
    const q = new RetryQueue(
      baseOpts(t, () => nowMs, async () => {
        throw new Error("boom");
      })
    );
    q.start();
    q.enqueue({ ...ITEM, tenantId: "t1" });
    await t.step();
    nowMs = 500;
    await t.step();
    assert.equal(q.getDeadLetter().length, 1);
    assert.ok(
      q.renderMetrics().includes(`relay_delivery_deadline_exceeded_total{endpoint="${URL}",tenant="t1"} 1`)
    );
  });

  it("DeliveryDeadlineExceededError carries the endpoint, elapsed, and deadline", () => {
    const err = new DeliveryDeadlineExceededError(URL, 1234.6, 250);
    assert.equal(err.name, "DeliveryDeadlineExceededError");
    assert.equal(err.endpoint, URL);
    assert.equal(err.elapsedMs, 1234.6);
    assert.equal(err.deadlineMs, 250);
    assert.ok(err.message.includes(URL));
    assert.ok(err.message.includes("1235ms"));
    assert.ok(err.message.includes("250ms"));
  });
});
