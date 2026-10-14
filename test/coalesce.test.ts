import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { OutboundCoalescer, coalesceKey } from "../src/coalesce.ts";
import { RetryQueue, type DownstreamResponse, type RetryItem, type Sender } from "../src/retry.ts";

const BODY = Buffer.from(JSON.stringify({ event: "payment.succeeded", id: "evt-1" }));
const TARGET = "https://downstream.example.test/hook";

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

async function waitFor(cond: () => boolean, timeoutMs = 2000): Promise<void> {
  const start = Date.now();
  for (;;) {
    if (cond()) return;
    if (Date.now() - start > timeoutMs) throw new Error("waitFor timed out");
    await sleep(5);
  }
}

function item(id: string, overrides: Partial<RetryItem> = {}): RetryItem {
  return { id, payload: BODY, targetUrl: TARGET, headers: {}, ...overrides };
}

const okResponse: DownstreamResponse = { statusCode: 200, body: Buffer.from("ok") };

describe("coalesce: key derivation", () => {
  it("is stable for identical inputs", () => {
    assert.equal(coalesceKey(undefined, TARGET, BODY), coalesceKey(undefined, TARGET, BODY));
  });

  it("differs across payload, target, and tenant", () => {
    const base = coalesceKey(undefined, TARGET, BODY);
    assert.notEqual(base, coalesceKey(undefined, TARGET, Buffer.from("other")));
    assert.notEqual(base, coalesceKey(undefined, "https://other.example.test/hook", BODY));
    assert.notEqual(base, coalesceKey("tenant-a", TARGET, BODY));
    // the default tenant (undefined) and an explicit "" are the same
    // tenant by the queue's convention — they share a key on purpose
    assert.equal(base, coalesceKey("", TARGET, BODY));
  });
});

describe("coalesce: OutboundCoalescer unit", () => {
  it("merges concurrent identical deliveries into one physical attempt", async () => {
    let calls = 0;
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    const inner: Sender = async () => {
      calls++;
      await gate;
      return okResponse;
    };
    const coalescer = new OutboundCoalescer();
    const sender = coalescer.wrap(inner);
    const a = item("a");
    const b = item("b");
    const pa = sender(a);
    const pb = sender(b);
    await waitFor(() => calls === 1);
    await sleep(20); // let the follower attach while the attempt is in flight
    release();
    const [ra, rb] = await Promise.all([pa, pb]);
    assert.equal(calls, 1);
    assert.equal(ra, okResponse);
    assert.equal(rb, okResponse);
    assert.equal(coalescer.wasLeader(a), true);
    assert.equal(coalescer.wasLeader(b), false);
  });

  it("propagates a shared failure to every attached member", async () => {
    const boom = new Error("downstream exploded");
    let calls = 0;
    const inner: Sender = async () => {
      calls++;
      await sleep(30);
      throw boom;
    };
    const coalescer = new OutboundCoalescer();
    const sender = coalescer.wrap(inner);
    const results = await Promise.allSettled([sender(item("a")), sender(item("b")), sender(item("c"))]);
    assert.equal(calls, 1);
    for (const r of results) {
      assert.equal(r.status, "rejected");
      assert.equal((r as PromiseRejectedResult).reason, boom);
    }
  });

  it("starts a new physical attempt once the previous one settles", async () => {
    let calls = 0;
    const inner: Sender = async () => {
      calls++;
      return okResponse;
    };
    const sender = new OutboundCoalescer().wrap(inner);
    await sender(item("a"));
    await sender(item("b"));
    assert.equal(calls, 2);
  });

  it("does not merge different payloads or targets", async () => {
    let calls = 0;
    const inner: Sender = async () => {
      calls++;
      await sleep(20);
      return okResponse;
    };
    const sender = new OutboundCoalescer().wrap(inner);
    await Promise.all([
      sender(item("a")),
      sender(item("b", { payload: Buffer.from("different") })),
      sender(item("c", { targetUrl: "https://other.example.test/hook" })),
      sender(item("d", { tenantId: "tenant-a" })),
    ]);
    assert.equal(calls, 4);
  });

  it("a synchronously-throwing sender does not poison the key", async () => {
    let calls = 0;
    const inner: Sender = (() => {
      calls++;
      if (calls === 1) throw new Error("sync boom");
      return Promise.resolve(okResponse);
    }) as Sender;
    const sender = new OutboundCoalescer().wrap(inner);
    // the wrapper re-throws synchronously, like the inner sender did —
    // inside deliver() this lands in the attempt's try/catch
    assert.throws(() => sender(item("a")), /sync boom/);
    // the failed registration left no in-flight entry behind
    assert.equal((await sender(item("b"))) as unknown, okResponse);
    assert.equal(calls, 2);
  });

  it("maxFollowers bounds attachment; overflow starts its own attempt", async () => {
    let calls = 0;
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    const inner: Sender = async () => {
      calls++;
      await gate;
      return okResponse;
    };
    const sender = new OutboundCoalescer({ maxFollowers: 1 }).wrap(inner);
    const pending = [sender(item("a")), sender(item("b")), sender(item("c"))];
    await waitFor(() => calls === 2);
    release();
    await Promise.all(pending);
    assert.equal(calls, 2);
  });

  it("rejects invalid options with RangeError at construction", () => {
    assert.throws(() => new OutboundCoalescer({ maxFollowers: 0 }), RangeError);
    assert.throws(() => new OutboundCoalescer({ maxFollowers: -2 }), RangeError);
    assert.throws(() => new OutboundCoalescer({ maxFollowers: 1.5 }), RangeError);
    assert.throws(() => new OutboundCoalescer({ maxFollowers: NaN }), RangeError);
  });

  it("wasLeader defaults to true for items that never went through the wrapper", () => {
    assert.equal(new OutboundCoalescer().wasLeader(item("ghost")), true);
  });

  it("getStats reports physical vs merged counts", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    let calls = 0;
    const inner: Sender = async () => {
      calls++;
      await gate;
      return okResponse;
    };
    const coalescer = new OutboundCoalescer();
    const sender = coalescer.wrap(inner);
    assert.deepEqual(coalescer.getStats(), { physicalAttempts: 0, mergedDeliveries: 0, inFlightKeys: 0 });
    const pending = [sender(item("a")), sender(item("b"))];
    await waitFor(() => calls === 1);
    assert.equal(coalescer.getStats().inFlightKeys, 1);
    release();
    await Promise.all(pending);
    assert.deepEqual(coalescer.getStats(), { physicalAttempts: 1, mergedDeliveries: 1, inFlightKeys: 0 });
  });
});

describe("coalesce: RetryQueue integration", () => {
  it("two identical queued deliveries share one physical attempt; each is counted delivered", async () => {
    let calls = 0;
    let release!: (v: DownstreamResponse | void) => void;
    const gate = new Promise<DownstreamResponse | void>((r) => { release = r; });
    const inner: Sender = async () => {
      calls++;
      return gate;
    };
    let delivered = 0;
    const q = new RetryQueue({
      sender: inner,
      coalesce: true,
      onDelivered: () => { delivered++; },
    });
    q.start();
    try {
      q.enqueue(item("a"));
      q.enqueue(item("b"));
      await waitFor(() => calls === 1);
      await sleep(30); // let the second delivery attach while the attempt is in flight
      release(okResponse);
      await waitFor(() => delivered === 2);
      assert.equal(calls, 1);
      const stats = q.getCoalesceStats();
      assert.equal(stats?.physicalAttempts, 1);
      assert.equal(stats?.mergedDeliveries, 1);
    } finally {
      q.stop();
    }
  });

  it("leader-only breaker accounting: one physical failure counts once", async () => {
    const inner: Sender = async () => {
      await sleep(30); // keep the attempt in flight so the second delivery attaches
      throw new Error("connection reset");
    };
    const q = new RetryQueue({
      sender: inner,
      coalesce: true,
      maxAttempts: 1, // fail straight to dead letter — no retry timers to clean up
      circuitBreaker: { failureThreshold: 5, cooldownMs: 60_000 },
    });
    q.start();
    try {
      q.enqueue(item("a"));
      q.enqueue(item("b"));
      // Wait for the physical failure to be recorded — the breaker row
      // appears earlier (at shouldAllow, before the attempt runs).
      await waitFor(
        () => q.getCircuitStats().some((r) => r.endpoint === TARGET && r.consecutiveFailures >= 1),
        3000
      );
      const rows = q.getCircuitStats().filter((r) => r.endpoint === TARGET);
      assert.equal(rows.length, 1);
      // Two logical deliveries failed, but only one physical attempt ran:
      // the breaker must see exactly one consecutive failure.
      assert.equal(rows[0].consecutiveFailures, 1);
      assert.equal(rows[0].state, "closed");
    } finally {
      q.stop();
    }
  });

  it("each member keeps its own attempt count and dead-letter path", async () => {
    const seenAttempts: number[] = [];
    const inner: Sender = async (it) => {
      await sleep(20);
      seenAttempts.push(it.attempt ?? -1);
      throw new Error("always fails");
    };
    let deadLettered = 0;
    const q = new RetryQueue({
      sender: inner,
      coalesce: true,
      maxAttempts: 1,
      onDeadLetter: () => { deadLettered++; },
    });
    q.start();
    try {
      q.enqueue(item("a"));
      q.enqueue(item("b"));
      await waitFor(() => deadLettered === 2, 3000);
      // One physical attempt ran (the leader's 0-based attempt 0) — the
      // follower never touched the inner sender — yet each member ran its
      // own dead-letter path with its own attempt count.
      assert.deepEqual(seenAttempts, [0]);
      assert.equal(q.getDeadLetter().length, 2);
    } finally {
      q.stop();
    }
  });

  it("tenant isolation: different tenants never share a physical attempt", async () => {
    let calls = 0;
    const inner: Sender = async () => {
      calls++;
      return okResponse;
    };
    let delivered = 0;
    const q = new RetryQueue({
      sender: inner,
      coalesce: true,
      onDelivered: () => { delivered++; },
    });
    q.start();
    try {
      q.enqueue(item("a", { tenantId: "tenant-a" }));
      q.enqueue(item("b", { tenantId: "tenant-b" }));
      await waitFor(() => delivered === 2, 3000);
      assert.equal(calls, 2);
    } finally {
      q.stop();
    }
  });

  it("coalesce: false keeps one physical attempt per delivery", async () => {
    let calls = 0;
    const inner: Sender = async () => {
      calls++;
      return okResponse;
    };
    let delivered = 0;
    const q = new RetryQueue({
      sender: inner,
      coalesce: false,
      onDelivered: () => { delivered++; },
    });
    q.start();
    try {
      q.enqueue(item("a"));
      q.enqueue(item("b"));
      await waitFor(() => delivered === 2, 3000);
      assert.equal(calls, 2);
      assert.equal(q.getCoalesceStats(), undefined);
    } finally {
      q.stop();
    }
  });

  it("invalid coalesce options throw RangeError at construction", () => {
    assert.throws(
      () => new RetryQueue({ coalesce: { maxFollowers: 0 } }),
      RangeError
    );
  });
});
