import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  RetryQueue,
  classifyFailure,
  type Sender,
} from "../src/retry.ts";
import { BulkheadRejectedError } from "../src/bulkhead.ts";

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

/** Let the deliver() promise chain (turn -> limiter -> bulkhead -> sender) settle. */
async function flush(ticks = 10) {
  for (let i = 0; i < ticks; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function item(id: string, targetUrl: string, extra: Record<string, unknown> = {}) {
  return { id, payload: BODY, targetUrl, headers: {}, ...extra };
}

/**
 * A sender that blocks every delivery until its release is called, so
 * in-flight occupancy is fully deterministic. Records the attempt index
 * each dispatch carries, so tests can prove a bulkhead rejection never
 * consumed an attempt.
 */
function blockingSender() {
  const started: string[] = [];
  const attempts: Array<{ id: string; attempt: number }> = [];
  const releases = new Map<string, () => void>();
  const sender: Sender = async (it) => {
    started.push(it.id);
    attempts.push({ id: it.id, attempt: it.attempt ?? 0 });
    await new Promise<void>((r) => releases.set(it.id, r));
  };
  return {
    sender,
    started,
    attempts,
    release: (id: string) => releases.get(id)!(),
    releaseAll: () => {
      for (const r of [...releases.values()]) r();
    },
  };
}

describe("RetryQueue bulkhead wiring (WR-312)", () => {
  it("unconfigured bulkhead changes nothing", async () => {
    const timer = manualTimer();
    const { sender, started, releaseAll } = blockingSender();
    const q = new RetryQueue({ sender, setTimer: timer.setTimer, clearTimer: timer.clearTimer });
    q.enqueue(item("a", A));
    q.enqueue(item("b", A));
    q.start();
    await timer.step();
    // Both dispatch concurrently: no bulkhead, no rejection, no cap.
    assert.deepEqual(new Set(started), new Set(["a", "b"]));
    assert.deepEqual(q.getBulkheadStats(), []);
    assert.deepEqual(q.getBulkheadRejections(), []);
    assert.ok(!q.renderMetrics().includes("relay_bulkhead_rejected_total"));
    releaseAll();
    q.stop();
  });

  it("queue_full rejection reschedules without consuming an attempt and never dead-letters", async () => {
    const timer = manualTimer();
    const { sender, started, attempts, release, releaseAll } = blockingSender();
    const failed: Array<{ attempts: number; error: string }> = [];
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      bulkhead: { maxConcurrent: 1, maxQueue: 0, queueTimeoutMs: 1000 },
      jitterMs: 0,
      onAttemptFailed: (info) => {
        failed.push({ attempts: info.attempts, error: info.error });
      },
    });
    q.enqueue(item("a", A));
    q.enqueue(item("b", A));
    q.start();
    await timer.step();
    // Only a dispatched; b was rejected fail-fast at the bulkhead.
    assert.deepEqual(started, ["a"]);
    assert.equal(failed.length, 1);
    assert.equal(failed[0].attempts, 0);
    assert.match(failed[0].error, /bulkhead rejected http:\/\/a\/hook: queue_full after 0ms queued/);
    // The sender never saw b, so no attempt was consumed.
    assert.deepEqual(attempts, [{ id: "a", attempt: 0 }]);
    // The rejection is audited and counted.
    const rejections = q.getBulkheadRejections();
    assert.equal(rejections.length, 1);
    assert.equal(rejections[0].endpoint, A);
    assert.equal(rejections[0].reason, "queue_full");
    assert.equal(rejections[0].queuedMs, 0);
    assert.equal(typeof rejections[0].atMs, "number");
    assert.equal(q.getBulkheadStats()[0].rejectionsTotal, 1);
    // A retry is scheduled (manual timer armed), not a dead letter.
    assert.equal(timer.pendingCount(), 1);
    assert.equal(q.getDurableQueueStats().deadLetters, 0);
    // Release a, then fire b's retry: b dispatches with attempt still 0.
    release("a");
    await flush();
    await timer.step();
    assert.deepEqual(started, ["a", "b"]);
    assert.deepEqual(attempts, [
      { id: "a", attempt: 0 },
      { id: "b", attempt: 0 },
    ]);
    release("b");
    await flush();
    assert.equal(q.getDurableQueueStats().deadLetters, 0);
    assert.equal(q.getDurableQueueStats().liveItems, 0);
    q.stop();
  });

  it("another endpoint is unaffected while one endpoint saturates", async () => {
    const timer = manualTimer();
    const { sender, started, releaseAll } = blockingSender();
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      bulkhead: { maxConcurrent: 1, maxQueue: 0, queueTimeoutMs: 1000 },
      jitterMs: 0,
    });
    q.enqueue(item("a", A));
    q.enqueue(item("b", A));
    q.enqueue(item("c", B));
    q.start();
    await timer.step();
    // a holds A's only slot and b is rejected; c sails through B's own bulkhead.
    assert.deepEqual(new Set(started), new Set(["a", "c"]));
    assert.equal(q.getBulkheadRejections().length, 1);
    assert.equal(q.getBulkheadRejections()[0].endpoint, A);
    releaseAll();
    q.stop();
  });

  it("queue_timeout rejection reschedules with reason queue_timeout", async () => {
    const timer = manualTimer();
    const { sender, started, release, releaseAll } = blockingSender();
    const failed: Array<{ attempts: number; error: string }> = [];
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      bulkhead: { maxConcurrent: 1, maxQueue: 1, queueTimeoutMs: 10 },
      jitterMs: 0,
      onAttemptFailed: (info) => {
        failed.push({ attempts: info.attempts, error: info.error });
      },
    });
    q.enqueue(item("a", A));
    q.enqueue(item("b", A));
    q.start();
    await timer.step();
    assert.deepEqual(started, ["a"]);
    // b waits in the bulkhead queue; the 10ms timeout rejects it.
    await sleep(50);
    await flush();
    assert.equal(failed.length, 1);
    assert.equal(failed[0].attempts, 0);
    assert.match(failed[0].error, /bulkhead rejected http:\/\/a\/hook: queue_timeout after \d+ms queued/);
    assert.equal(q.getBulkheadRejections()[0].reason, "queue_timeout");
    assert.ok((q.getBulkheadRejections()[0].queuedMs as number) >= 0);
    assert.equal(timer.pendingCount(), 1);
    assert.equal(q.getDurableQueueStats().deadLetters, 0);
    // Release a, then fire b's retry: it dispatches with attempt still 0.
    release("a");
    await flush();
    await timer.step();
    assert.deepEqual(started, ["a", "b"]);
    release("b");
    await flush();
    q.stop();
  });

  it("the fast lane bypasses the bulkhead", async () => {
    const timer = manualTimer();
    const { sender, started, releaseAll } = blockingSender();
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      bulkhead: { maxConcurrent: 1, maxQueue: 0, queueTimeoutMs: 1000 },
      jitterMs: 0,
    });
    q.enqueue(item("a", A));
    q.start();
    await timer.step();
    assert.deepEqual(started, ["a"]);
    // Urgent never waits behind queued normal deliveries — not even at the bulkhead.
    q.enqueue({ ...item("u", A), priority: "urgent" as const });
    await timer.step();
    assert.deepEqual(new Set(started), new Set(["a", "u"]));
    assert.deepEqual(q.getBulkheadRejections(), []);
    releaseAll();
    q.stop();
  });

  it("a settle releases the slot to the oldest bulkhead waiter, FIFO", async () => {
    const timer = manualTimer();
    const { sender, started, release, releaseAll } = blockingSender();
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      bulkhead: { maxConcurrent: 1, maxQueue: 2, queueTimeoutMs: 5000 },
      jitterMs: 0,
    });
    q.enqueue(item("a", A));
    q.enqueue(item("b", A));
    q.enqueue(item("c", A));
    q.start();
    await timer.step();
    assert.deepEqual(started, ["a"]);
    const stats = q.getBulkheadStats();
    assert.equal(stats.length, 1);
    assert.equal(stats[0].inFlight, 1);
    assert.equal(stats[0].queuedDepth, 2);
    assert.equal(stats[0].waitsTotal, 2);
    release("a"); // oldest waiter (b) goes next
    await flush();
    assert.deepEqual(started, ["a", "b"]);
    assert.equal(q.getBulkheadStats()[0].inFlight, 1);
    assert.equal(q.getBulkheadStats()[0].queuedDepth, 1);
    release("b"); // then c
    await flush();
    assert.deepEqual(started, ["a", "b", "c"]);
    assert.equal(q.getBulkheadStats()[0].queuedDepth, 0);
    release("c");
    await flush();
    assert.equal(q.getBulkheadStats()[0].inFlight, 0);
    releaseAll();
    q.stop();
  });

  it("stop() wakes bulkhead waiters without hanging and without a rejection", async () => {
    const timer = manualTimer();
    const { sender, started, releaseAll } = blockingSender();
    const failed: unknown[] = [];
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      bulkhead: { maxConcurrent: 1, maxQueue: 1, queueTimeoutMs: 5000 },
      jitterMs: 0,
      onAttemptFailed: (info) => {
        failed.push(info);
      },
    });
    q.enqueue(item("a", A));
    q.enqueue(item("b", A));
    q.start();
    await timer.step();
    assert.deepEqual(started, ["a"]);
    assert.equal(q.getBulkheadStats()[0].queuedDepth, 1);
    q.stop();
    await flush();
    // The woken waiter bailed out on the liveness check: no dispatch,
    // no rejection, no reschedule — and the queue is drained, not hung.
    assert.deepEqual(started, ["a"]);
    assert.equal(q.getBulkheadStats()[0].queuedDepth, 0);
    assert.deepEqual(failed, []);
    assert.deepEqual(q.getBulkheadRejections(), []);
    releaseAll();
  });

  it("invalid bulkhead config throws RangeError at construction", () => {
    const bad: Array<Record<string, unknown>> = [
      { maxConcurrent: 0, maxQueue: 0, queueTimeoutMs: 0 },
      { maxConcurrent: -1, maxQueue: 0, queueTimeoutMs: 0 },
      { maxConcurrent: 1.5, maxQueue: 0, queueTimeoutMs: 0 },
      { maxConcurrent: Infinity, maxQueue: 0, queueTimeoutMs: 0 },
      { maxConcurrent: NaN, maxQueue: 0, queueTimeoutMs: 0 },
      { maxConcurrent: 1, maxQueue: -1, queueTimeoutMs: 0 },
      { maxConcurrent: 1, maxQueue: 0.5, queueTimeoutMs: 0 },
      { maxConcurrent: 1, maxQueue: 0, queueTimeoutMs: -1 },
      { maxConcurrent: 1, maxQueue: 0, queueTimeoutMs: Infinity },
      { maxConcurrent: 1, maxQueue: 0, queueTimeoutMs: NaN },
    ];
    for (const bulkhead of bad) {
      assert.throws(
        () => new RetryQueue({ bulkhead: bulkhead as never }),
        RangeError,
        `bulkhead ${JSON.stringify(bulkhead)}`
      );
    }
    assert.doesNotThrow(
      () => new RetryQueue({ bulkhead: { maxConcurrent: 1, maxQueue: 0, queueTimeoutMs: 0 } })
    );
  });

  it("classifyFailure maps BulkheadRejectedError to retryable", () => {
    for (const reason of ["queue_full", "queue_timeout"] as const) {
      const classified = classifyFailure(new BulkheadRejectedError(A, reason, 0));
      assert.equal(classified.failureClass, "retryable");
    }
  });

  it("getBulkheadStats and getBulkheadRejections expose per-(tenant, endpoint) rows", async () => {
    const timer = manualTimer();
    const { sender, releaseAll } = blockingSender();
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      bulkhead: { maxConcurrent: 1, maxQueue: 0, queueTimeoutMs: 1000 },
      jitterMs: 0,
    });
    q.enqueue({ ...item("a", A), tenantId: "t1" });
    q.enqueue({ ...item("b", A), tenantId: "t1" });
    q.start();
    await timer.step();
    const stats = q.getBulkheadStats();
    assert.equal(stats.length, 1);
    assert.equal(stats[0].endpoint, A);
    assert.equal(stats[0].tenant, "t1");
    assert.equal(stats[0].maxConcurrent, 1);
    assert.equal(stats[0].maxQueue, 0);
    assert.equal(stats[0].inFlight, 1);
    assert.equal(stats[0].rejectionsTotal, 1);
    const rejections = q.getBulkheadRejections();
    assert.equal(rejections.length, 1);
    assert.equal(rejections[0].tenant, "t1");
    releaseAll();
    q.stop();
  });

  it("per-tenant isolation: same endpoint, different tenants do not share a bulkhead", async () => {
    const timer = manualTimer();
    const { sender, started, releaseAll } = blockingSender();
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      bulkhead: { maxConcurrent: 1, maxQueue: 0, queueTimeoutMs: 1000 },
      jitterMs: 0,
    });
    q.enqueue({ ...item("a1", A), tenantId: "t1" });
    q.enqueue({ ...item("a2", A), tenantId: "t2" });
    q.start();
    await timer.step();
    // t1 holds its own slot; t2's delivery to the same URL is unaffected.
    assert.deepEqual(new Set(started), new Set(["a1", "a2"]));
    assert.deepEqual(q.getBulkheadRejections(), []);
    const tenants = q.getBulkheadStats().map((s) => s.tenant).sort();
    assert.deepEqual(tenants, ["t1", "t2"]);
    releaseAll();
    q.stop();
  });

  it("a bulkhead rejection records no breaker verdict", async () => {
    const timer = manualTimer();
    const { sender, releaseAll } = blockingSender();
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      bulkhead: { maxConcurrent: 1, maxQueue: 0, queueTimeoutMs: 1000 },
      circuitBreaker: { failureThreshold: 1, cooldownMs: 60_000 },
      jitterMs: 0,
    });
    q.enqueue(item("a", A));
    q.enqueue(item("b", A));
    q.start();
    await timer.step();
    // One rejection, zero outcomes: the circuit never learned anything.
    assert.equal(q.getBulkheadRejections().length, 1);
    const circuits = q.getCircuitStats().filter((s) => s.endpoint === A);
    assert.equal(circuits.length, 1);
    assert.equal(circuits[0].state, "closed");
    assert.equal(circuits[0].consecutiveFailures, 0);
    assert.equal(circuits[0].trips, 0);
    releaseAll();
    q.stop();
  });

  it("with maxAttempts 1 a rejection alone never dead-letters", async () => {
    const timer = manualTimer();
    const { sender, started, attempts, release, releaseAll } = blockingSender();
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      bulkhead: { maxConcurrent: 1, maxQueue: 0, queueTimeoutMs: 1000 },
      maxAttempts: 1,
      jitterMs: 0,
    });
    q.enqueue(item("a", A));
    q.enqueue(item("b", A));
    q.start();
    await timer.step();
    // b was rejected with attempt still 0 < maxAttempts 1: rescheduled, not dead-lettered.
    assert.deepEqual(started, ["a"]);
    assert.equal(q.getDurableQueueStats().deadLetters, 0);
    assert.equal(timer.pendingCount(), 1);
    release("a");
    await flush();
    await timer.step();
    assert.deepEqual(started, ["a", "b"]);
    assert.deepEqual(attempts, [
      { id: "a", attempt: 0 },
      { id: "b", attempt: 0 },
    ]);
    release("b");
    await flush();
    assert.equal(q.getDurableQueueStats().deadLetters, 0);
    releaseAll();
    q.stop();
  });

  it("renderMetrics exposes relay_bulkhead_rejected_total{endpoint,reason}", async () => {
    const timer = manualTimer();
    const { sender, releaseAll } = blockingSender();
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      bulkhead: { maxConcurrent: 1, maxQueue: 1, queueTimeoutMs: 10 },
      jitterMs: 0,
    });
    // queue_full on A (maxQueue 1, but cap+queue fill first): block A,
    // queue one waiter, then overflow it.
    q.enqueue(item("a", A));
    q.enqueue(item("b", A));
    q.enqueue(item("c", A));
    // queue_timeout on B: block B, queue one waiter, let it time out.
    q.enqueue(item("d", B));
    q.enqueue(item("e", B));
    q.start();
    await timer.step();
    await sleep(50);
    await flush();
    const metrics = q.renderMetrics();
    assert.match(
      metrics,
      /relay_bulkhead_rejected_total\{endpoint="http:\/\/a\/hook",reason="queue_full"\} 1/
    );
    assert.match(
      metrics,
      /relay_bulkhead_rejected_total\{endpoint="http:\/\/b\/hook",reason="queue_timeout"\} 1/
    );
    releaseAll();
    q.stop();
  });

  it("a failed attempt releases the bulkhead slot to the waiter", async () => {
    const timer = manualTimer();
    const started: string[] = [];
    const releases = new Map<string, () => void>();
    const sender: Sender = async (it) => {
      started.push(it.id);
      if (it.id === "a") throw new Error("downstream 500");
      await new Promise<void>((r) => releases.set(it.id, r));
    };
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      bulkhead: { maxConcurrent: 1, maxQueue: 1, queueTimeoutMs: 5000 },
      jitterMs: 0,
    });
    q.enqueue(item("a", A));
    q.enqueue(item("b", A));
    q.start();
    await timer.step();
    await flush();
    // a failed and was rescheduled; its slot went to b, which is now in flight.
    assert.deepEqual(started, ["a", "b"]);
    assert.equal(q.getBulkheadStats()[0].inFlight, 1);
    assert.equal(q.getBulkheadStats()[0].queuedDepth, 0);
    releases.get("b")!();
    await flush();
    q.stop();
  });
});
