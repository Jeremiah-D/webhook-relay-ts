import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  EndpointBulkhead,
  EndpointBulkheads,
  BulkheadRejectedError,
} from "../src/bulkhead.ts";

const A = "http://a/hook";
const B = "http://b/hook";

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

describe("EndpointBulkhead (WR-227)", () => {
  it("grants up to the cap immediately and queues the rest FIFO", async () => {
    const b = new EndpointBulkhead(A, {
      maxConcurrent: 1,
      maxQueue: 2,
      queueTimeoutMs: 1000,
    });
    const r1 = await b.acquire();
    assert.equal(b.inFlightCount(), 1);
    const p2 = b.acquire();
    const p3 = b.acquire();
    assert.equal(b.queuedDepth(), 2);
    assert.equal(b.waitedTotal(), 2);
    // Neither waiter resolves while the slot is held.
    let p2Done = false;
    void p2.then(() => {
      p2Done = true;
    });
    await sleep(10);
    assert.equal(p2Done, false);
    r1();
    const r2 = await p2;
    assert.equal(b.inFlightCount(), 1);
    assert.equal(b.queuedDepth(), 1);
    r2();
    const r3 = await p3;
    r3();
    assert.equal(b.inFlightCount(), 0);
    assert.equal(b.queuedDepth(), 0);
  });

  it("rejects immediately when the bounded queue is full, with an audit record", async () => {
    const b = new EndpointBulkhead(A, {
      maxConcurrent: 1,
      maxQueue: 1,
      queueTimeoutMs: 1000,
    });
    const r1 = await b.acquire();
    const p2 = b.acquire(); // queued
    // p2 must stay queued (not rejected) while only the queue bound,
    // not the cap-plus-queue, is exceeded: track it without awaiting.
    let p2Rejected = false;
    void p2.then(
      () => {},
      () => {
        p2Rejected = true;
      }
    );
    await sleep(10);
    assert.equal(p2Rejected, false);
    assert.equal(b.queuedDepth(), 1);
    r1(); // release grants p2
    const r2 = await p2;
    // Now fill cap + queue again and overflow.
    const p3 = b.acquire(); // queued (cap held by r2)
    await assert.rejects(b.acquire(), (e: unknown) => {
      assert.ok(e instanceof BulkheadRejectedError);
      assert.equal(e.reason, "queue_full");
      assert.equal(e.endpoint, A);
      assert.equal(e.queuedMs, 0);
      assert.equal(e.failureClass, "retryable");
      return true;
    });
    assert.equal(b.queuedDepth(), 1);
    assert.equal(b.rejectedTotal(), 1);
    const trail = b.rejections();
    assert.equal(trail.length, 1);
    assert.equal(trail[0].reason, "queue_full");
    assert.equal(trail[0].endpoint, A);
    assert.equal(trail[0].queuedMs, 0);
    r2();
    const r3 = await p3;
    r3();
  });

  it("queue timeout rejects as retryable and frees the queue slot", async () => {
    const b = new EndpointBulkhead(A, {
      maxConcurrent: 1,
      maxQueue: 2,
      queueTimeoutMs: 30,
    });
    const r1 = await b.acquire();
    const timedOut = b.acquire();
    await assert.rejects(timedOut, (e: unknown) => {
      assert.ok(e instanceof BulkheadRejectedError);
      assert.equal(e.reason, "queue_timeout");
      assert.equal(e.failureClass, "retryable");
      assert.ok(e.queuedMs >= 25);
      return true;
    });
    assert.equal(b.queuedDepth(), 0);
    assert.equal(b.rejectedTotal(), 1);
    assert.equal(b.rejections()[0].reason, "queue_timeout");
    // The slot is still held by r1; a fresh acquisition queues cleanly.
    const p = b.acquire();
    assert.equal(b.queuedDepth(), 1);
    r1();
    const r2 = await p;
    r2();
    assert.equal(b.inFlightCount(), 0);
  });

  it("release frees the queued waiter and a granted waiter never times out", async () => {
    const b = new EndpointBulkhead(A, {
      maxConcurrent: 1,
      maxQueue: 1,
      queueTimeoutMs: 40,
    });
    const r1 = await b.acquire();
    const p2 = b.acquire();
    await sleep(10);
    r1(); // grants p2 well before its 40ms timeout
    const r2 = await p2;
    await sleep(80); // past the original timeout: must not reject
    assert.equal(b.inFlightCount(), 1);
    assert.equal(b.rejectedTotal(), 0);
    r2();
    assert.equal(b.inFlightCount(), 0);
  });

  it("double release is a no-op and cannot hand one slot to two waiters", async () => {
    const b = new EndpointBulkhead(A, {
      maxConcurrent: 1,
      maxQueue: 1,
      queueTimeoutMs: 1000,
    });
    const r1 = await b.acquire();
    const p2 = b.acquire();
    r1();
    r1(); // second call: no-op
    const r2 = await p2;
    assert.equal(b.inFlightCount(), 1);
    r2();
    assert.equal(b.inFlightCount(), 0);
  });

  it("invalid config fails closed at construction", () => {
    const bad: Array<Record<string, unknown>> = [
      { maxConcurrent: 0, maxQueue: 1, queueTimeoutMs: 100 },
      { maxConcurrent: -1, maxQueue: 1, queueTimeoutMs: 100 },
      { maxConcurrent: 1.5, maxQueue: 1, queueTimeoutMs: 100 },
      { maxConcurrent: Infinity, maxQueue: 1, queueTimeoutMs: 100 },
      { maxConcurrent: NaN, maxQueue: 1, queueTimeoutMs: 100 },
      { maxConcurrent: 1, maxQueue: -1, queueTimeoutMs: 100 },
      { maxConcurrent: 1, maxQueue: 1.5, queueTimeoutMs: 100 },
      { maxConcurrent: 1, maxQueue: 1, queueTimeoutMs: -1 },
      { maxConcurrent: 1, maxQueue: 1, queueTimeoutMs: Infinity },
      { maxConcurrent: 1, maxQueue: 1, queueTimeoutMs: NaN },
    ];
    for (const opts of bad) {
      assert.throws(
        () => new EndpointBulkhead(A, opts as never),
        RangeError,
        JSON.stringify(opts)
      );
    }
    // Boundary values that must NOT throw: cap 1, zero queue, zero timeout.
    new EndpointBulkhead(A, {
      maxConcurrent: 1,
      maxQueue: 0,
      queueTimeoutMs: 0,
    });
  });

  it("maxQueue 0 means any acquisition past the cap rejects immediately", async () => {
    const b = new EndpointBulkhead(A, {
      maxConcurrent: 1,
      maxQueue: 0,
      queueTimeoutMs: 1000,
    });
    const r1 = await b.acquire();
    await assert.rejects(b.acquire(), (e: unknown) => {
      assert.ok(e instanceof BulkheadRejectedError);
      assert.equal(e.reason, "queue_full");
      return true;
    });
    assert.equal(b.queuedDepth(), 0);
    r1();
  });
});

describe("EndpointBulkheads aggregate (WR-227)", () => {
  it("one endpoint saturated does not block or reject another", async () => {
    const gates = new EndpointBulkheads({
      maxConcurrent: 1,
      maxQueue: 0,
      queueTimeoutMs: 1000,
    });
    const rA = await gates.acquire(A);
    // A is saturated with a zero-length queue: A traffic fails fast...
    await assert.rejects(gates.acquire(A), (e: unknown) => {
      assert.ok(e instanceof BulkheadRejectedError);
      assert.equal(e.reason, "queue_full");
      return true;
    });
    // ...while B, with its own independent bulkhead, acquires cleanly.
    const rB = await gates.acquire(B);
    assert.equal(
      gates.stats().find((s) => s.endpoint === A)?.inFlight,
      1
    );
    assert.equal(
      gates.stats().find((s) => s.endpoint === B)?.inFlight,
      1
    );
    assert.equal(
      gates.stats().find((s) => s.endpoint === B)?.rejectionsTotal,
      0
    );
    rA();
    rB();
  });

  it("aggregate stats and audit trail cover all endpoints", async () => {
    const gates = new EndpointBulkheads({
      maxConcurrent: 1,
      maxQueue: 0,
      queueTimeoutMs: 1000,
    });
    const rA = await gates.acquire(A);
    await assert.rejects(gates.acquire(A));
    const rB = await gates.acquire(B);
    await assert.rejects(gates.acquire(B));
    assert.equal(gates.stats().length, 2);
    assert.equal(gates.rejections().length, 2);
    assert.deepEqual(
      gates
        .rejections()
        .map((r) => r.endpoint)
        .sort(),
      [A, B]
    );
    rA();
    rB();
  });
});
