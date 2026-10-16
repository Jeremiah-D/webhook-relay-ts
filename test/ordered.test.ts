import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  RetryQueue,
  OrderedTracker,
  assertValidOrderedConfig,
  resolveOrderedConfig,
  type OrderedAuditEvent,
  type RetryItem,
  type Sender,
} from "../src/retry.ts";

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
    /** Fire exactly one pending timer (for tests that interleave clock moves). */
    async runOne() {
      const fn = pending.shift();
      if (fn !== undefined) fn();
      await new Promise((r) => setImmediate(r));
    },
  };
}

const buf = (s: string) => Buffer.from(s);
const EP = "http://localhost:9999/ordered";
const EP2 = "http://localhost:9999/plain";

function item(id: string, targetUrl: string, priority?: "urgent"): RetryItem {
  return { id, payload: buf(id), targetUrl, headers: {}, ...(priority ? { priority } : {}) };
}

async function tick(n = 3) {
  for (let i = 0; i < n; i++) await new Promise((r) => setImmediate(r));
}

describe("assertValidOrderedConfig", () => {
  it("accepts the disabled/absent forms", () => {
    assertValidOrderedConfig(undefined);
    assertValidOrderedConfig(false);
    assertValidOrderedConfig(true);
    assertValidOrderedConfig({});
    assertValidOrderedConfig({ enabled: false });
    assertValidOrderedConfig({ enabled: true });
    assertValidOrderedConfig({ enabled: true, maxHeadOfLineHoldMs: 5000 });
    assertValidOrderedConfig({ enabled: true, maxHeadOfLineHoldMs: Infinity });
    assertValidOrderedConfig({ [EP]: true });
    assertValidOrderedConfig({ [EP]: false });
    assertValidOrderedConfig({ [EP]: { enabled: true, maxHeadOfLineHoldMs: 1000 } });
    assertValidOrderedConfig({ [EP]: { enabled: false } });
  });

  it("rejects illegal values with RangeError at construction", () => {
    const bad: unknown[] = [
      "yes",
      42,
      [],
      null,
      { maxHeadOfLineHoldMs: -1 },
      { maxHeadOfLineHoldMs: 0 },
      { maxHeadOfLineHoldMs: NaN },
      { maxHeadOfLineHoldMs: "soon" },
      { enabled: "yes" },
      { now: 42 },
      { [EP]: "yes" },
      { [EP]: [] },
      { [EP]: { maxHeadOfLineHoldMs: -10 } },
      { [EP]: { enabled: 1 } },
      { "": true },
    ];
    for (const v of bad) {
      assert.throws(() => assertValidOrderedConfig(v), RangeError, `expected RangeError for ${JSON.stringify(v)}`);
    }
  });

  it("rejects illegal values through the RetryQueue constructor", () => {
    assert.throws(() => new RetryQueue({ ordered: "yes" as unknown as boolean }), RangeError);
    assert.throws(() => new RetryQueue({ ordered: { maxHeadOfLineHoldMs: -5 } }), RangeError);
    assert.throws(() => new RetryQueue({ ordered: { maxHeadOfLineHoldMs: 0 } }), RangeError);
    assert.throws(() => new RetryQueue({ ordered: [] as unknown as boolean }), RangeError);
    assert.throws(
      () => new RetryQueue({ ordered: { [EP]: "yes" } as unknown as Record<string, boolean> }),
      RangeError
    );
  });
});

describe("resolveOrderedConfig", () => {
  it("resolves the boolean and options forms", () => {
    assert.equal(resolveOrderedConfig(undefined), undefined);
    assert.equal(resolveOrderedConfig(false), undefined);
    assert.deepEqual(resolveOrderedConfig(true), {
      global: { enabled: true, maxHeadOfLineHoldMs: Infinity },
      endpoints: new Map(),
    });
    const opts = resolveOrderedConfig({ enabled: true, maxHeadOfLineHoldMs: 2500 });
    assert.equal(opts?.global?.maxHeadOfLineHoldMs, 2500);
    // enabled:false (or a record with nothing enabled) means fully disabled.
    assert.equal(resolveOrderedConfig({ enabled: false }), undefined);
    assert.equal(resolveOrderedConfig({ [EP]: false }), undefined);
    assert.equal(resolveOrderedConfig({ [EP]: { enabled: false } }), undefined);
  });

  it("resolves per-endpoint records with exact-targetUrl keys", () => {
    const cfg = resolveOrderedConfig({
      [EP]: true,
      [EP2]: { enabled: true, maxHeadOfLineHoldMs: 5000 },
    });
    assert.equal(cfg?.global, undefined);
    assert.equal(cfg?.endpoints.get(EP)?.maxHeadOfLineHoldMs, Infinity);
    assert.equal(cfg?.endpoints.get(EP2)?.maxHeadOfLineHoldMs, 5000);
    assert.equal(cfg?.endpoints.get("http://localhost:9999/other"), undefined);
  });
});

describe("OrderedTracker", () => {
  it("advances the head on settle and restarts the hold clock", () => {
    let nowMs = 100;
    const t = new OrderedTracker(() => nowMs);
    t.track("e", "a");
    t.track("e", "b");
    assert.equal(t.head("e"), "a");
    assert.equal(t.headBlockedMs("e"), 0);
    nowMs = 250;
    assert.equal(t.headBlockedMs("e"), 150);
    // Settling a non-head leaves the head and its clock alone.
    t.settle("e", "b");
    assert.equal(t.head("e"), "a");
    assert.equal(t.headBlockedMs("e"), 150);
    // Settling the head promotes the next item and restarts its clock.
    t.track("e", "c");
    t.settle("e", "a");
    assert.equal(t.head("e"), "c");
    assert.equal(t.headBlockedMs("e"), 0);
    nowMs = 400;
    assert.equal(t.headBlockedMs("e"), 150);
    assert.equal(t.depth("e"), 1);
  });

  it("keeps lines per endpoint and ignores duplicate tracks", () => {
    const t = new OrderedTracker(() => 0);
    t.track("e1", "a");
    t.track("e2", "b");
    t.track("e1", "a");
    assert.equal(t.head("e1"), "a");
    assert.equal(t.head("e2"), "b");
    assert.equal(t.depth("e1"), 1);
    assert.deepEqual(t.endpoints(), ["e1", "e2"]);
    assert.equal(t.isTracked("e1", "a"), true);
    assert.equal(t.isTracked("e1", "zzz"), false);
    assert.equal(t.head("nope"), undefined);
    assert.equal(t.headBlockedMs("nope"), undefined);
  });
});

describe("ordered delivery", () => {
  it("dispatches in receive order even when the head is slow", async () => {
    const timer = manualTimer();
    const dispatchOrder: string[] = [];
    let releaseHead!: () => void;
    let headDelivered = false;
    let followerSawHeadDelivered = false;
    const sender: Sender = (wire) => {
      dispatchOrder.push(wire.id);
      if (wire.id === "o-a") {
        return new Promise<void>((res) => {
          releaseHead = res;
        });
      }
      // The follower must never be attempted before the head settled.
      followerSawHeadDelivered = headDelivered;
      return Promise.resolve();
    };
    const q = new RetryQueue({
      sender,
      ordered: true,
      setTimer: timer.setTimer,
      onDelivered: (it) => {
        if (it.id === "o-a") headDelivered = true;
      },
    });
    q.start();
    q.enqueue(item("o-a", EP));
    q.enqueue(item("o-b", EP));
    await timer.run();
    // The head dispatched; the follower was held (its timer fired and returned).
    assert.deepEqual(dispatchOrder, ["o-a"]);
    releaseHead();
    await tick();
    await timer.run();
    assert.deepEqual(dispatchOrder, ["o-a", "o-b"]);
    assert.equal(followerSawHeadDelivered, true);
    q.stop();
  });

  it("holds followers behind a retrying head without consuming their attempts", async () => {
    const timer = manualTimer();
    const events: string[] = [];
    const attempts: Record<string, number> = { "r-a": 0, "r-b": 0 };
    const sender: Sender = async (wire) => {
      attempts[wire.id] += 1;
      events.push(`attempt:${wire.id}#${attempts[wire.id]}`);
      if (wire.id === "r-a" && attempts["r-a"] < 3) throw new Error("boom");
    };
    const q = new RetryQueue({
      sender,
      ordered: true,
      baseDelayMs: 10,
      maxDelayMs: 50,
      maxAttempts: 5,
      jitterMs: 0,
      setTimer: timer.setTimer,
      onDelivered: (it) => events.push(`delivered:${it.id}`),
    });
    q.start();
    q.enqueue(item("r-a", EP));
    q.enqueue(item("r-b", EP));
    await timer.run();
    // A failed twice, then delivered; B was attempted only after A settled.
    assert.equal(attempts["r-a"], 3);
    assert.equal(attempts["r-b"], 1);
    const firstB = events.findIndex((e) => e.startsWith("attempt:r-b"));
    const deliveredA = events.findIndex((e) => e === "delivered:r-a");
    assert.ok(firstB > deliveredA, `B attempted before A delivered: ${events.join(",")}`);
    // While A was retrying, B never burned an attempt.
    assert.deepEqual(
      events.filter((e) => e.startsWith("attempt:r-b")).length,
      1
    );
    const stats = q.getOrderedStats();
    assert.equal(stats.length, 1);
    assert.equal(stats[0].endpoint, EP);
    assert.ok(stats[0].headBlockedCount > 0);
    q.stop();
  });

  it("is scoped per endpoint: unordered endpoints are unaffected", async () => {
    const timer = manualTimer();
    const dispatchOrder: string[] = [];
    let releaseOrderedHead!: () => void;
    const sender: Sender = (wire) => {
      dispatchOrder.push(wire.id);
      if (wire.id === "s-a") return new Promise<void>((res) => { releaseOrderedHead = res; });
      return Promise.resolve();
    };
    const q = new RetryQueue({
      sender,
      ordered: { [EP]: true },
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue(item("s-a", EP));
    q.enqueue(item("s-b", EP));
    q.enqueue(item("p-1", EP2));
    q.enqueue(item("p-2", EP2));
    await timer.run();
    // The unordered endpoint's items both dispatched immediately, while the
    // ordered endpoint's follower waited behind its slow head.
    assert.deepEqual(dispatchOrder, ["s-a", "p-1", "p-2"]);
    releaseOrderedHead();
    await tick();
    await timer.run();
    assert.deepEqual(dispatchOrder, ["s-a", "p-1", "p-2", "s-b"]);
    q.stop();
  });

  it("parks a poison head into the dead letter after maxHeadOfLineHoldMs and continues", async () => {
    const timer = manualTimer();
    let nowMs = 0;
    const audits: OrderedAuditEvent[] = [];
    const dead: Array<{ id: string; failureClass?: string; attempts: number }> = [];
    const delivered: string[] = [];
    let attemptsA = 0;
    const sender: Sender = async (wire) => {
      if (wire.id === "p-a") {
        attemptsA += 1;
        throw new Error("boom");
      }
      delivered.push(wire.id);
    };
    const q = new RetryQueue({
      sender,
      ordered: { enabled: true, maxHeadOfLineHoldMs: 1000, now: () => nowMs },
      baseDelayMs: 10,
      maxDelayMs: 50,
      maxAttempts: 10,
      jitterMs: 0,
      setTimer: timer.setTimer,
      onOrderedAudit: (e) => audits.push(e),
      onDeadLetter: (it, attempts, _err, failureClass) =>
        dead.push({ id: it.id, failureClass, attempts }),
    });
    q.start();
    q.enqueue(item("p-a", EP));
    q.enqueue(item("p-b", EP));
    // Attempt 1 for the head: fire its timer, then wait for the attempt
    // to actually settle (bounded wait — the retry timer must be armed
    // before we move the clock, or the drain below would miss it).
    await timer.runOne();
    for (let i = 0; i < 200 && attemptsA < 1; i++) await tick(1);
    assert.equal(attemptsA, 1);
    // The follower's timer fires while the head is retrying: held, no attempt.
    await timer.runOne();
    await tick(2);
    // Head attempted once and failed; follower held. Nothing dead yet.
    assert.deepEqual(dead, []);
    assert.deepEqual(delivered, []);
    // Push the clock past the hold bound; the head's retry dispatch parks it.
    nowMs = 1500;
    await timer.run();
    // Push the clock past the hold bound; the head's retry dispatch parks it.
    nowMs = 1500;
    await timer.run();
    assert.equal(dead.length, 1);
    assert.equal(dead[0].id, "p-a");
    assert.equal(dead[0].failureClass, "head_of_line_timeout");
    assert.equal(dead[0].attempts, 1);
    // The line advanced: the follower was released and delivered.
    assert.deepEqual(delivered, ["p-b"]);
    const park = audits.find((e) => e.kind === "head_of_line_parked");
    assert.ok(park, "expected a head_of_line_parked audit");
    assert.equal(park!.id, "p-a");
    assert.equal(park!.endpoint, EP);
    assert.equal(park!.blockedMs, 1500);
    assert.equal(park!.maxHeadOfLineHoldMs, 1000);
    const stats = q.getOrderedStats();
    assert.equal(stats[0].headOfLineParked, 1);
    q.stop();
  });

  it("lets urgent items bypass the ordered gate, audited as ordered_bypassed", async () => {
    const timer = manualTimer();
    const audits: OrderedAuditEvent[] = [];
    const delivered: string[] = [];
    let aSettled = false;
    let uSawASettled = true;
    const sender: Sender = async (wire) => {
      if (wire.id === "g-a") throw new Error("boom");
      if (wire.id === "g-u") uSawASettled = aSettled;
      delivered.push(wire.id);
    };
    const q = new RetryQueue({
      sender,
      ordered: true,
      baseDelayMs: 10,
      maxDelayMs: 50,
      maxAttempts: 5,
      jitterMs: 0,
      setTimer: timer.setTimer,
      onOrderedAudit: (e) => audits.push(e),
      onDeadLetter: (it) => {
        if (it.id === "g-a") aSettled = true;
      },
    });
    q.start();
    q.enqueue(item("g-a", EP)); // normal head, keeps failing
    q.enqueue(item("g-u", EP, "urgent")); // urgent: must not wait behind the head
    await timer.run();
    assert.deepEqual(delivered, ["g-u"]);
    // The urgent item was attempted while the head was still unsettled.
    assert.equal(uSawASettled, false);
    const bypass = audits.filter((e) => e.kind === "ordered_bypassed");
    assert.equal(bypass.length, 1);
    assert.equal(bypass[0].id, "g-u");
    assert.equal(bypass[0].endpoint, EP);
    const stats = q.getOrderedStats();
    assert.equal(stats[0].urgentBypassed, 1);
    q.stop();
  });

  it("is fully inert when disabled: zero stats, zero series, unchanged behavior", async () => {
    const timer = manualTimer();
    const delivered: string[] = [];
    const q = new RetryQueue({
      sender: async (wire) => {
        delivered.push(wire.id);
      },
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue(item("d-a", EP));
    q.enqueue(item("d-b", EP));
    await timer.run();
    assert.deepEqual(delivered, ["d-a", "d-b"]);
    assert.deepEqual(q.getOrderedStats(), []);
    const metrics = q.renderMetrics();
    assert.ok(!metrics.includes("relay_ordered_"), "no relay_ordered_* series when disabled");
    q.stop();
  });

  it("renders relay_ordered_* series only for ordered endpoints with activity", async () => {
    const timer = manualTimer();
    const audits: OrderedAuditEvent[] = [];
    const q = new RetryQueue({
      sender: async (wire) => {
        if (wire.id === "m-u") return;
        throw new Error("boom");
      },
      ordered: true,
      baseDelayMs: 10,
      maxDelayMs: 50,
      maxAttempts: 3,
      jitterMs: 0,
      setTimer: timer.setTimer,
      onOrderedAudit: (e) => audits.push(e),
    });
    // No activity yet: no series even though the feature is enabled.
    assert.ok(!q.renderMetrics().includes("relay_ordered_"));
    q.start();
    q.enqueue(item("m-a", EP));
    q.enqueue(item("m-b", EP));
    q.enqueue(item("m-u", EP, "urgent"));
    await timer.run();
    const metrics = q.renderMetrics();
    assert.ok(metrics.includes("relay_ordered_head_blocked_total"), metrics);
    assert.ok(metrics.includes("relay_ordered_head_of_line_parked_total"), metrics);
    assert.ok(metrics.includes("relay_ordered_urgent_bypassed_total"), metrics);
    assert.ok(metrics.includes(`endpoint="${EP}"`), metrics);
    // The other endpoint never saw ordered activity: no series for it.
    assert.ok(!metrics.includes(`endpoint="${EP2}"`), metrics);
    q.stop();
  });

  it("default maxHeadOfLineHoldMs is Infinity: the head is held, never timed out", async () => {
    const timer = manualTimer();
    let nowMs = 0;
    const dead: string[] = [];
    const sender: Sender = async () => {
      throw new Error("boom");
    };
    const q = new RetryQueue({
      sender,
      ordered: { enabled: true, now: () => nowMs },
      baseDelayMs: 10,
      maxDelayMs: 50,
      maxAttempts: 3,
      jitterMs: 0,
      setTimer: timer.setTimer,
      onDeadLetter: (it) => dead.push(it.id),
    });
    q.start();
    q.enqueue(item("i-a", EP));
    q.enqueue(item("i-b", EP));
    // A whole day passes; the head must still be held, not poison-parked.
    nowMs = 86_400_000;
    await timer.run();
    // Both exhausted their attempt budgets honestly ("retryable"), in
    // order — no head_of_line_timeout park despite the elapsed day.
    assert.deepEqual(dead, ["i-a", "i-b"]);
    const stats = q.getOrderedStats();
    assert.equal(stats[0].headOfLineParked, 0);
    q.stop();
  });
});
