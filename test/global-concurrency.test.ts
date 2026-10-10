import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { GlobalConcurrencyGate } from "../src/global-concurrency.ts";

const A = "http://a/hook";
const B = "http://b/hook";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));

/**
 * Manual timer with single-step control, mirroring the other feature
 * tests: parking re-arms timers, so tests advance one wave at a time.
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
    clearTimer: (h: { clear(): void }) => h.clear(),
    async step() {
      const fns = pending.splice(0);
      for (const f of fns) f();
      await flush();
    },
  };
}

/** Let the deliver() promise chain (turn -> limiter -> gate -> sender) settle. */
async function flush(ticks = 10) {
  for (let i = 0; i < ticks; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

function item(id: string, targetUrl: string) {
  return { id, payload: BODY, targetUrl, headers: {} };
}

/**
 * A sender that blocks every delivery until its release is called, so
 * in-flight occupancy is fully deterministic.
 */
function blockingSender() {
  const started: string[] = [];
  const releases = new Map<string, () => void>();
  const sender: Sender = async (it) => {
    started.push(it.id);
    await new Promise<void>((r) => releases.set(it.id, r));
  };
  return {
    sender,
    started,
    release: (id: string) => releases.get(id)!(),
    releaseAll: () => {
      for (const r of [...releases.values()]) r();
    },
  };
}

describe("GlobalConcurrencyGate", () => {
  it("grants immediately up to the cap and queues FIFO beyond it", async () => {
    const gate = new GlobalConcurrencyGate(2);
    const order: string[] = [];
    const r1 = await gate.acquire();
    const r2 = await gate.acquire();
    assert.equal(gate.inFlightCount(), 2);
    let w3 = false;
    let w4 = false;
    const p3 = gate.acquire().then((r) => {
      w3 = true;
      order.push("w3");
      return r;
    });
    const p4 = gate.acquire().then((r) => {
      w4 = true;
      order.push("w4");
      return r;
    });
    await flush(3);
    assert.equal(w3, false);
    assert.equal(w4, false);
    assert.equal(gate.queuedDepth(), 2);
    assert.equal(gate.waitedTotal(), 2);
    r1(); // oldest waiter goes first
    const rel3 = await p3;
    await flush(3);
    assert.equal(w3, true);
    assert.equal(w4, false);
    assert.deepEqual(order, ["w3"]);
    r2();
    const rel4 = await p4;
    await flush(3);
    assert.deepEqual(order, ["w3", "w4"]);
    assert.equal(gate.inFlightCount(), 2);
    rel3();
    rel4();
    assert.equal(gate.inFlightCount(), 0);
    assert.equal(gate.queuedDepth(), 0);
  });

  it("validates the cap fail-fast", () => {
    for (const bad of [0, -1, 1.5, NaN, "2" as unknown as number, null as unknown as number]) {
      assert.throws(() => new GlobalConcurrencyGate(bad), RangeError, `cap ${String(bad)}`);
    }
    assert.doesNotThrow(() => new GlobalConcurrencyGate(1));
    assert.doesNotThrow(() => new GlobalConcurrencyGate(Infinity));
    assert.doesNotThrow(() => new GlobalConcurrencyGate());
  });

  it("releaseWaiters wakes every waiter with a no-op release", async () => {
    const gate = new GlobalConcurrencyGate(1);
    const r1 = await gate.acquire();
    let woken = 0;
    const p = gate.acquire().then((release) => {
      woken += 1;
      release(); // no-op: must not corrupt the count
    });
    await flush(3);
    assert.equal(woken, 0);
    gate.releaseWaiters();
    await p;
    assert.equal(woken, 1);
    assert.equal(gate.queuedDepth(), 0);
    assert.equal(gate.inFlightCount(), 1); // r1 still holds the only slot
    r1();
    assert.equal(gate.inFlightCount(), 0);
  });
});

describe("RetryQueue globalMaxConcurrent", () => {
  it("caps in-flight deliveries across endpoints; oldest waiter dispatches first; nothing is dropped", async () => {
    const timer = manualTimer();
    const { sender, started, release, releaseAll } = blockingSender();
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      globalMaxConcurrent: 2,
      jitterMs: 0,
    });
    q.enqueue(item("a", A));
    q.enqueue(item("b", B));
    q.enqueue(item("c", A));
    q.enqueue(item("d", B));
    q.start();
    await timer.step();
    assert.deepEqual(new Set(started), new Set(["a", "b"])); // cap hit
    assert.equal(q.getGlobalConcurrencyStats().inFlight, 2);
    assert.equal(q.getGlobalConcurrencyStats().queuedDepth, 2);
    assert.equal(q.getGlobalConcurrencyStats().waitsTotal, 2);

    release("a"); // oldest waiter (c) goes next
    await flush();
    assert.equal(started[2], "c");
    assert.equal(q.getGlobalConcurrencyStats().queuedDepth, 1);

    release("b"); // then d
    await flush();
    assert.equal(started[3], "d");
    assert.equal(q.getGlobalConcurrencyStats().queuedDepth, 0);

    releaseAll();
    await flush();
    assert.equal(q.pendingCount(), 0); // nothing dropped
    assert.equal(q.getGlobalConcurrencyStats().inFlight, 0);
    assert.equal(q.getDeadLetter().length, 0);
  });

  it("exposes the wait counter in the Prometheus exposition only when configured", async () => {
    const timer = manualTimer();
    const { sender, releaseAll } = blockingSender();
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      globalMaxConcurrent: 1,
      jitterMs: 0,
    });
    q.enqueue(item("a", A));
    q.enqueue(item("b", B));
    q.start();
    await timer.step();
    const exposition = q.renderMetrics();
    assert.match(exposition, /relay_global_concurrency_wait_total 1/);
    assert.equal(q.getGlobalConcurrencyStats().maxConcurrent, 1);
    releaseAll();
    await flush();

    // Default (unlimited): no waiting possible, no series rendered.
    const q2 = new RetryQueue({ sender: async () => {}, jitterMs: 0 });
    assert.ok(!q2.renderMetrics().includes("relay_global_concurrency_wait_total"));
    assert.equal(q2.getGlobalConcurrencyStats().maxConcurrent, Infinity);
    assert.equal(q2.getGlobalConcurrencyStats().queuedDepth, 0);
  });

  it("composes with the per-endpoint limiter: both gates must grant", async () => {
    const timer = manualTimer();
    const { sender, started, release, releaseAll } = blockingSender();
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      maxConcurrentPerEndpoint: 1, // tight per-endpoint…
      globalMaxConcurrent: 10, // …roomy global
      jitterMs: 0,
    });
    q.enqueue(item("a", A));
    q.enqueue(item("b", A)); // same endpoint: serialized by the per-endpoint limiter
    q.enqueue(item("c", B));
    q.start();
    await timer.step();
    assert.deepEqual(new Set(started), new Set(["a", "c"]));
    assert.equal(q.getGlobalConcurrencyStats().inFlight, 2);
    assert.equal(q.getGlobalConcurrencyStats().queuedDepth, 0); // b waits on the limiter, not the gate
    release("a");
    await flush();
    assert.ok(started.includes("b"));
    releaseAll();
    await flush();
    assert.equal(q.pendingCount(), 0);
  });

  it("composes with pause: parked endpoints hold no global slots", async () => {
    const timer = manualTimer();
    const { sender, started, release, releaseAll } = blockingSender();
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      globalMaxConcurrent: 1,
      jitterMs: 0,
    });
    q.pauseEndpoint(B);
    q.enqueue(item("a", A));
    q.enqueue(item("b", B));
    q.start();
    await timer.step();
    assert.deepEqual(started, ["a"]); // b parked: never reached the gate
    assert.equal(q.getGlobalConcurrencyStats().inFlight, 1);
    assert.equal(q.getGlobalConcurrencyStats().queuedDepth, 0);
    assert.equal(q.getGlobalConcurrencyStats().waitsTotal, 0);

    q.resumeEndpoint(B); // b re-arms, but the slot is held: it waits FIFO
    await timer.step();
    await flush();
    assert.deepEqual(started, ["a"]);
    assert.equal(q.getGlobalConcurrencyStats().queuedDepth, 1);
    assert.equal(q.getGlobalConcurrencyStats().waitsTotal, 1);

    release("a");
    await flush();
    assert.deepEqual(started, ["a", "b"]);
    releaseAll();
    await flush();
    assert.equal(q.pendingCount(), 0);
  });

  it("the urgent lane bypasses the per-endpoint limiter but not the global cap", async () => {
    const timer = manualTimer();
    const { sender, started, releaseAll } = blockingSender();
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      globalMaxConcurrent: 1,
      jitterMs: 0,
    });
    q.enqueue({ ...item("u1", A), priority: "urgent" });
    q.enqueue({ ...item("u2", B), priority: "urgent" });
    q.start();
    await timer.step();
    assert.equal(started.length, 1); // second urgent waits on the global gate
    assert.equal(q.getGlobalConcurrencyStats().queuedDepth, 1);
    releaseAll();
    await flush();
    assert.equal(started.length, 2);
    releaseAll(); // u2 started after the first release; release it too
    await flush();
    assert.equal(q.pendingCount(), 0);
  });

  it("rejects invalid caps at construction", () => {
    for (const bad of [0, -1, 1.5, NaN, "2" as unknown as number]) {
      assert.throws(() => new RetryQueue({ globalMaxConcurrent: bad }), RangeError);
    }
    assert.doesNotThrow(() => new RetryQueue({ globalMaxConcurrent: 1 }));
    assert.doesNotThrow(() => new RetryQueue({ globalMaxConcurrent: Infinity }));
    assert.doesNotThrow(() => new RetryQueue({}));
  });

  it("shutdown wakes gate waiters so it drains instead of hanging", async () => {
    // Real timers here: shutdown()'s drain timeout runs on the queue's
    // clock, and a manual timer would never fire it.
    const { sender, release } = blockingSender();
    const q = new RetryQueue({
      sender,
      globalMaxConcurrent: 1,
      jitterMs: 0,
      baseDelayMs: 10,
    });
    q.start();
    q.enqueue(item("a", A));
    q.enqueue(item("b", B)); // waits on the gate
    await poll(() => q.getGlobalConcurrencyStats().queuedDepth === 1);
    const done = q.shutdown(5000);
    await new Promise((r) => setTimeout(r, 20));
    release("a"); // the genuinely in-flight delivery settles
    assert.equal(await done, true); // the waiter bailed instead of pinning shutdown
    assert.equal(q.getGlobalConcurrencyStats().queuedDepth, 0);
  });

  it("shutdown times out (does not hang) when an in-flight delivery never settles", async () => {
    const { sender } = blockingSender(); // never released
    const q = new RetryQueue({ sender, globalMaxConcurrent: 1, jitterMs: 0, baseDelayMs: 10 });
    q.start();
    q.enqueue(item("a", A));
    q.enqueue(item("b", B));
    await poll(() => q.getGlobalConcurrencyStats().queuedDepth === 1);
    const at = Date.now();
    assert.equal(await q.shutdown(150), false);
    assert.ok(Date.now() - at < 5000, "shutdown hung instead of timing out");
  });
});

/** Poll until `cond` holds (real-timer tests); throws on timeout. */
async function poll(cond: () => boolean, timeoutMs = 5000): Promise<void> {
  const at = Date.now();
  while (!cond()) {
    if (Date.now() - at > timeoutMs) throw new Error("poll timed out");
    await new Promise((r) => setTimeout(r, 5));
  }
}
