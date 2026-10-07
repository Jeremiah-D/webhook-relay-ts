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

  it("additive jitter uses the injected random source", () => {
    // random() = 0.5, jitterMs = 50 -> delay = base*2^attempt + 25
    const q = new RetryQueue({
      baseDelayMs: 100,
      maxDelayMs: 10000,
      maxAttempts: 3,
      jitterMs: 50,
      random: () => 0.5,
    });
    assert.equal(q.delayForAttempt(0), 125);
    assert.equal(q.delayForAttempt(1), 225);
    assert.equal(q.delayForAttempt(2), 425);
  });

  it("full jitter spreads the delay over [0, min(cap, base*2^attempt)]", () => {
    let r = 0.5;
    const q = new RetryQueue({
      baseDelayMs: 100,
      maxDelayMs: 1000,
      maxAttempts: 3,
      jitterStrategy: "full",
      random: () => r,
    });
    assert.equal(q.delayForAttempt(1), 100); // 0.5 * min(1000, 200)
    r = 0;
    assert.equal(q.delayForAttempt(3), 0); // full jitter may return 0
    r = 0.999;
    assert.equal(q.delayForAttempt(10), 999); // 0.999 * min(1000, 100*2^10)
    // Never exceeds the cap, even at the extreme of the random range.
    for (const attempt of [0, 1, 5, 20]) {
      assert.ok(q.delayForAttempt(attempt) <= 1000, `attempt ${attempt} exceeds cap`);
    }
  });

  it("rejects invalid retry configuration", () => {
    assert.throws(() => new RetryQueue({ baseDelayMs: 0 }), RangeError);
    assert.throws(() => new RetryQueue({ baseDelayMs: -10 }), RangeError);
    assert.throws(() => new RetryQueue({ maxDelayMs: 0 }), RangeError);
    assert.throws(() => new RetryQueue({ maxAttempts: 0 }), RangeError);
    assert.throws(() => new RetryQueue({ maxAttempts: 1.5 }), RangeError);
    assert.throws(() => new RetryQueue({ jitterMs: -1 }), RangeError);
    assert.throws(
      () => new RetryQueue({ jitterStrategy: "bogus" as never }),
      RangeError
    );
    // Sane configs still construct.
    new RetryQueue({ baseDelayMs: 1, maxDelayMs: 1, maxAttempts: 1, jitterMs: 0 });
  });

  it("dead-letter entries carry attempts, lastError, and a timestamp", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {
        throw new Error("downstream down");
      },
      baseDelayMs: 10,
      maxAttempts: 3,
      jitterMs: 0,
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();
    const dead = q.getDeadLetter();
    assert.equal(dead.length, 1);
    assert.equal(dead[0].id, "item-1");
    assert.equal(dead[0].attempts, 3);
    assert.equal(dead[0].lastError, "downstream down");
    assert.ok(!Number.isNaN(Date.parse(dead[0].deadLetteredAt)));
    // Original payload metadata survives the round trip.
    assert.equal(dead[0].targetUrl, ITEM.targetUrl);
    assert.deepEqual(dead[0].payload, ITEM.payload);
  });

  it("replays a dead-lettered item with a fresh attempt budget", async () => {
    const timer = manualTimer();
    let failing = true;
    let deliveries = 0;
    const q = new RetryQueue({
      sender: async () => {
        deliveries += 1;
        if (failing) throw new Error("flaky");
      },
      baseDelayMs: 10,
      maxAttempts: 2,
      jitterMs: 0,
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();
    assert.equal(deliveries, 2);
    assert.equal(q.getDeadLetter().length, 1);

    assert.equal(q.replayDeadLetter("unknown-id"), false);
    assert.equal(q.replayDeadLetter("item-1"), true);
    assert.equal(q.getDeadLetter().length, 0);
    assert.equal(q.pendingCount(), 1);

    failing = false;
    await timer.run();
    assert.equal(deliveries, 3);
    assert.equal(q.pendingCount(), 0);
    assert.equal(q.getDeadLetter().length, 0);
  });

  it("replayAllDeadLetters replays every entry and returns the count", async () => {
    const timer = manualTimer();
    let failing = true;
    const delivered: string[] = [];
    const q = new RetryQueue({
      sender: async (item) => {
        if (failing) throw new Error("flaky");
        delivered.push(item.id);
      },
      baseDelayMs: 10,
      maxAttempts: 2,
      jitterMs: 0,
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue({ ...ITEM, id: "a" });
    q.enqueue({ ...ITEM, id: "b" });
    await timer.run();
    assert.equal(q.getDeadLetter().length, 2);

    assert.equal(q.replayAllDeadLetters(), 2);
    assert.equal(q.getDeadLetter().length, 0);
    assert.equal(q.replayAllDeadLetters(), 0);

    failing = false;
    await timer.run();
    assert.deepEqual(delivered.sort(), ["a", "b"]);
    assert.equal(q.pendingCount(), 0);
  });
});

describe("concurrency", () => {
  const URL = "http://localhost:9999/hook";

  /** Sender that blocks every delivery on one shared gate. */
  function gatedSender() {
    const inFlight = new Set<string>();
    let maxObserved = 0;
    let open!: () => void;
    const gate = new Promise<void>((r) => {
      open = r;
    });
    const sender: Sender = async (item) => {
      inFlight.add(item.id);
      maxObserved = Math.max(maxObserved, inFlight.size);
      await gate;
      inFlight.delete(item.id);
    };
    return { sender, inFlight, maxObserved: () => maxObserved, open: () => open() };
  }

  async function drainUntil(q: RetryQueue, done: () => boolean): Promise<void> {
    for (let i = 0; i < 200 && !done(); i++) {
      await new Promise((r) => setImmediate(r));
    }
    assert.ok(done(), "deliveries did not finish in time");
  }

  it("caps concurrent in-flight deliveries per endpoint", async () => {
    const timer = manualTimer();
    const g = gatedSender();
    const q = new RetryQueue({
      sender: g.sender,
      baseDelayMs: 10,
      maxAttempts: 1,
      jitterMs: 0,
      maxConcurrentPerEndpoint: 2,
      setTimer: timer.setTimer,
    });
    q.start();
    for (let i = 0; i < 5; i++) q.enqueue({ ...ITEM, id: `c-${i}`, targetUrl: URL });
    await timer.run();
    assert.equal(g.maxObserved(), 2);
    assert.equal(g.inFlight.size, 2);
    assert.deepEqual(q.getConcurrencyStats(), [{ endpoint: URL, inFlight: 2, queued: 3 }]);
    g.open();
    await drainUntil(q, () => q.pendingCount() === 0);
    // The remaining deliveries drained through the same 2-slot budget.
    assert.equal(g.maxObserved(), 2);
    assert.equal(q.getDeadLetter().length, 0);
    assert.deepEqual(q.getConcurrencyStats(), []);
  });

  it("queued deliveries start in FIFO order with limit 1", async () => {
    const timer = manualTimer();
    const started: string[] = [];
    const q = new RetryQueue({
      sender: async (item) => {
        started.push(item.id);
      },
      baseDelayMs: 10,
      maxAttempts: 1,
      jitterMs: 0,
      maxConcurrentPerEndpoint: 1,
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue({ ...ITEM, id: "a", targetUrl: URL });
    q.enqueue({ ...ITEM, id: "b", targetUrl: URL });
    q.enqueue({ ...ITEM, id: "c", targetUrl: URL });
    await timer.run();
    assert.deepEqual(started, ["a", "b", "c"]);
    assert.equal(q.pendingCount(), 0);
  });

  it("applies the limit independently per endpoint", async () => {
    const timer = manualTimer();
    const g = gatedSender();
    const q = new RetryQueue({
      sender: g.sender,
      baseDelayMs: 10,
      maxAttempts: 1,
      jitterMs: 0,
      maxConcurrentPerEndpoint: 1,
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue({ ...ITEM, id: "e1", targetUrl: "http://a/hook" });
    q.enqueue({ ...ITEM, id: "e2", targetUrl: "http://b/hook" });
    await timer.run();
    // One slot per endpoint: both deliver at once despite limit 1.
    assert.equal(g.maxObserved(), 2);
    assert.equal(g.inFlight.size, 2);
    g.open();
    await drainUntil(q, () => q.pendingCount() === 0);
    assert.equal(q.getDeadLetter().length, 0);
  });

  it("rejects invalid maxConcurrentPerEndpoint", () => {
    for (const v of [0, -1, 1.5, NaN]) {
      assert.throws(() => new RetryQueue({ maxConcurrentPerEndpoint: v }), RangeError);
    }
    // Sane configs still construct; the default is unlimited.
    new RetryQueue({ maxConcurrentPerEndpoint: 1 });
    new RetryQueue({ maxConcurrentPerEndpoint: Infinity });
    new RetryQueue();
  });

  it("stop() unblocks queued waiters without losing items", async () => {
    const timer = manualTimer();
    const g = gatedSender();
    const q = new RetryQueue({
      sender: g.sender,
      baseDelayMs: 10,
      maxAttempts: 1,
      jitterMs: 0,
      maxConcurrentPerEndpoint: 1,
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue({ ...ITEM, id: "s-a", targetUrl: URL });
    q.enqueue({ ...ITEM, id: "s-b", targetUrl: URL });
    await timer.run();
    assert.equal(g.inFlight.size, 1); // s-a in flight, s-b queued for the slot
    q.stop();
    g.open();
    await drainUntil(q, () => g.inFlight.size === 0);
    // s-a delivered; s-b bailed out of the wait and is still queued.
    assert.equal(q.pendingCount(), 1);
    // A restart picks up where it left off.
    q.start();
    await timer.run();
    await drainUntil(q, () => q.pendingCount() === 0);
    assert.equal(q.getDeadLetter().length, 0);
  });
});
