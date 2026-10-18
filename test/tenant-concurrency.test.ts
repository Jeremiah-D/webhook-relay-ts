import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { RetryQueue, type Sender } from "../src/retry.ts";
import {
  TenantConcurrencyGate,
  TenantConcurrencyGates,
} from "../src/tenant-concurrency.ts";

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

/** Let the deliver() promise chain (turn -> gates -> limiter -> sender) settle. */
async function flush(ticks = 10) {
  for (let i = 0; i < ticks; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

function item(id: string, targetUrl: string, tenantId?: string) {
  return { id, payload: BODY, targetUrl, headers: {}, ...(tenantId === undefined ? {} : { tenantId }) };
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

describe("TenantConcurrencyGate", () => {
  it("grants immediately up to the cap and queues FIFO beyond it", async () => {
    const gate = new TenantConcurrencyGate(2);
    const order: string[] = [];
    const r1 = await gate.acquire();
    const r2 = await gate.acquire();
    assert.equal(gate.inFlightCount(), 2);
    // Immediate grants are not waits.
    assert.equal(gate.waitedTotal(), 0);
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
      assert.throws(() => new TenantConcurrencyGate(bad), RangeError, `cap ${String(bad)}`);
    }
    assert.doesNotThrow(() => new TenantConcurrencyGate(1));
    assert.doesNotThrow(() => new TenantConcurrencyGate(Infinity));
    assert.doesNotThrow(() => new TenantConcurrencyGate());
  });

  it("releaseWaiters wakes every waiter with a no-op release", async () => {
    const gate = new TenantConcurrencyGate(1);
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

describe("TenantConcurrencyGates", () => {
  it("isolates tenants: one tenant's flood never occupies another tenant's slots", async () => {
    const gates = new TenantConcurrencyGates(1);
    const rA = await gates.acquire("acme");
    assert.equal(gates.stats().find((s) => s.tenant === "acme")?.inFlight, 1);
    // globex is unaffected by acme's full gate.
    const rB = await gates.acquire("globex");
    assert.equal(gates.stats().find((s) => s.tenant === "globex")?.inFlight, 1);
    // A second acme acquisition waits — on acme's gate only.
    let a2done = false;
    const pA2 = gates.acquire("acme").then((r) => {
      a2done = true;
      return r;
    });
    await flush(3);
    assert.equal(a2done, false);
    assert.equal(gates.stats().find((s) => s.tenant === "acme")?.queuedDepth, 1);
    assert.equal(gates.stats().find((s) => s.tenant === "globex")?.queuedDepth, 0);
    rA();
    const rA2 = await pA2;
    assert.equal(a2done, true);
    rA2();
    rB();
  });

  it("creates gates lazily and reports rows in first-seen order", async () => {
    const gates = new TenantConcurrencyGates(4);
    assert.deepEqual(gates.stats(), []);
    const r1 = await gates.acquire("globex");
    const r2 = await gates.acquire("acme");
    assert.deepEqual(
      gates.stats().map((s) => s.tenant),
      ["globex", "acme"]
    );
    assert.equal(gates.stats()[0].maxConcurrent, 4);
    r1();
    r2();
  });

  it("releaseWaiters wakes every tenant's waiters", async () => {
    const gates = new TenantConcurrencyGates(1);
    const rA = await gates.acquire("acme");
    const rB = await gates.acquire("globex");
    let woken = 0;
    const pA = gates.acquire("acme").then((r) => {
      woken += 1;
      r();
    });
    const pB = gates.acquire("globex").then((r) => {
      woken += 1;
      r();
    });
    await flush(3);
    assert.equal(woken, 0);
    gates.releaseWaiters();
    await Promise.all([pA, pB]);
    assert.equal(woken, 2);
    assert.equal(gates.stats().find((s) => s.tenant === "acme")?.queuedDepth, 0);
    assert.equal(gates.stats().find((s) => s.tenant === "globex")?.queuedDepth, 0);
    rA();
    rB();
  });

  it("validates the cap once, at construction", () => {
    for (const bad of [0, -1, 2.5, NaN]) {
      assert.throws(() => new TenantConcurrencyGates(bad), RangeError, `cap ${String(bad)}`);
    }
    assert.doesNotThrow(() => new TenantConcurrencyGates(1));
    assert.doesNotThrow(() => new TenantConcurrencyGates());
  });
});

describe("RetryQueue tenantMaxConcurrent", () => {
  it("tenant-less deliveries skip the gate entirely (zero behavior change)", async () => {
    const timer = manualTimer();
    const { sender, started, releaseAll } = blockingSender();
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      tenantMaxConcurrent: 1, // would serialize tenants; tenant-less must not feel it
      jitterMs: 0,
    });
    q.enqueue(item("a", A));
    q.enqueue(item("b", B));
    q.enqueue(item("c", A));
    q.start();
    await timer.step();
    // All three dispatch concurrently — no tenant gate in the path.
    assert.deepEqual(new Set(started), new Set(["a", "b", "c"]));
    assert.deepEqual(q.getTenantConcurrencyStats(), []);
    releaseAll();
    await flush();
    assert.equal(q.pendingCount(), 0);
  });

  it("caps in-flight deliveries per tenant across endpoints; oldest waiter first; nothing dropped", async () => {
    const timer = manualTimer();
    const { sender, started, release, releaseAll } = blockingSender();
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      tenantMaxConcurrent: 1,
      jitterMs: 0,
    });
    q.enqueue(item("a1", A, "acme"));
    q.enqueue(item("a2", B, "acme")); // same tenant, other endpoint: still serialized
    q.enqueue(item("a3", A, "acme"));
    q.start();
    await timer.step();
    assert.deepEqual(started, ["a1"]);
    const rows = q.getTenantConcurrencyStats();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].tenant, "acme");
    assert.equal(rows[0].inFlight, 1);
    assert.equal(rows[0].queuedDepth, 2);
    assert.equal(rows[0].waitsTotal, 2);

    release("a1"); // oldest waiter (a2) goes next
    await flush();
    assert.deepEqual(started, ["a1", "a2"]);
    release("a2");
    await flush();
    assert.deepEqual(started, ["a1", "a2", "a3"]);
    releaseAll();
    await flush();
    assert.equal(q.pendingCount(), 0); // nothing dropped
    assert.equal(q.getTenantConcurrencyStats()[0].inFlight, 0);
    assert.equal(q.getDeadLetter().length, 0);
  });

  it("one tenant's flood does not occupy another tenant's slots", async () => {
    const timer = manualTimer();
    const { sender, started, release, releaseAll } = blockingSender();
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      tenantMaxConcurrent: 1,
      jitterMs: 0,
    });
    q.enqueue(item("a1", A, "acme"));
    q.enqueue(item("a2", A, "acme")); // queued on acme's gate…
    q.enqueue(item("b1", B, "globex")); // …but globex proceeds regardless
    q.start();
    await timer.step();
    assert.ok(started.includes("a1"), "acme's first delivery starts");
    assert.ok(started.includes("b1"), "globex is not blocked by acme's full gate");
    assert.ok(!started.includes("a2"), "acme's second delivery waits on acme's gate");
    release("a1");
    await flush();
    assert.ok(started.includes("a2"));
    releaseAll();
    await flush();
    assert.equal(q.pendingCount(), 0);
  });

  it("exposes per-tenant wait counters in the Prometheus exposition, activity-gated", async () => {
    const timer = manualTimer();
    const { sender, started, releaseAll } = blockingSender();
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      tenantMaxConcurrent: 1,
      jitterMs: 0,
    });
    q.enqueue(item("a1", A, "acme"));
    q.enqueue(item("a2", B, "acme")); // waits: counted
    q.enqueue(item("b1", B, "globex")); // never waits: no series
    q.start();
    await timer.step();
    assert.ok(started.includes("a1"));
    const exposition = q.renderMetrics();
    assert.match(exposition, /relay_tenant_concurrency_wait_total\{tenant="acme"\} 1/);
    assert.ok(
      !exposition.includes('relay_tenant_concurrency_wait_total{tenant="globex"}'),
      "tenants that never waited expose no series"
    );
    releaseAll();
    await flush();

    // Default (unlimited): no waiting possible, no series rendered.
    const q2 = new RetryQueue({ sender: async () => {}, jitterMs: 0 });
    q2.enqueue(item("x", A, "acme"));
    assert.ok(!q2.renderMetrics().includes("relay_tenant_concurrency_wait_total"));
    assert.deepEqual(q2.getTenantConcurrencyStats(), []);
  });

  it("the urgent lane bypasses the tenant gate like the per-endpoint limiter", async () => {
    const timer = manualTimer();
    const { sender, started, releaseAll } = blockingSender();
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      tenantMaxConcurrent: 1,
      jitterMs: 0,
    });
    q.enqueue(item("a1", A, "acme")); // holds acme's only slot
    q.enqueue({ ...item("u1", B, "acme"), priority: "urgent" });
    q.start();
    await timer.step();
    assert.ok(started.includes("a1"));
    assert.ok(started.includes("u1"), "urgent never waits behind queued normal deliveries of its tenant");
    assert.equal(q.getTenantConcurrencyStats()[0].waitsTotal, 0);
    releaseAll();
    await flush();
    assert.equal(q.pendingCount(), 0);
  });

  it("stop() wakes tenant-gate waiters instead of hanging", async () => {
    const timer = manualTimer();
    const { sender, started, release } = blockingSender();
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      tenantMaxConcurrent: 1,
      jitterMs: 0,
    });
    q.enqueue(item("a1", A, "acme"));
    q.enqueue(item("a2", B, "acme")); // waits on acme's gate
    q.start();
    await timer.step();
    assert.deepEqual(started, ["a1"]);
    assert.equal(q.getTenantConcurrencyStats()[0].queuedDepth, 1);
    q.stop(); // must not hang on the tenant gate
    await flush();
    assert.equal(q.getTenantConcurrencyStats()[0].queuedDepth, 0);
    assert.ok(!started.includes("a2"), "the woken waiter bails instead of dispatching");
    release("a1");
    await flush();
  });

  it("rejects invalid caps at construction", () => {
    for (const bad of [0, -1, 1.5, NaN, "2" as unknown as number]) {
      assert.throws(() => new RetryQueue({ tenantMaxConcurrent: bad }), RangeError);
    }
    assert.doesNotThrow(() => new RetryQueue({ tenantMaxConcurrent: 1 }));
    assert.doesNotThrow(() => new RetryQueue({ tenantMaxConcurrent: Infinity }));
    assert.doesNotThrow(() => new RetryQueue({}));
  });
});
