import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  LaneScheduler,
  RetryQueue,
  type RetryItem,
  type Sender,
  type StarvationGuardAuditEvent,
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
  };
}

/** Let queued microtask chains (limiter grant -> turn grant -> sender) settle. */
async function settle(rounds = 20): Promise<void> {
  for (let i = 0; i < rounds; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

const URL = "http://localhost:9999/guard";

function item(id: string, priority?: "urgent"): RetryItem {
  return {
    id,
    payload: Buffer.from(id),
    targetUrl: URL,
    headers: {},
    ...(priority !== undefined ? { priority } : {}),
  };
}

/** Release every currently-blocked sender, then drain timers/microtasks. */
async function drainRound(
  timer: ReturnType<typeof manualTimer>,
  releases: Map<string, () => void>,
  q: RetryQueue
): Promise<boolean> {
  for (const release of [...releases.values()]) release();
  releases.clear();
  await timer.run();
  await settle();
  return releases.size > 0 || q.pendingCount() > 0;
}

describe("LaneScheduler (deficit round-robin)", () => {
  it("grants urgent immediately with no normal backlog, paces it under contention", async () => {
    const sched = new LaneScheduler({ minNormalShare: 0.25 });
    const releases: Array<() => void> = [];

    // No contention: urgent goes straight through.
    (await sched.acquireTurn("e", "urgent"))();
    // Backlog: two normal turns granted but not yet dispatched.
    releases.push(await sched.acquireTurn("e", "normal"));
    releases.push(await sched.acquireTurn("e", "normal"));

    // Contention: urgent parks until normal dispatches earn it turns.
    let u1Granted = false;
    const u1 = sched.acquireTurn("e", "urgent").then((release) => {
      u1Granted = true;
      return release;
    });
    await settle(5);
    assert.equal(u1Granted, false);
    // One normal dispatch earns (1 - 0.25) / 0.25 = 3 urgent turns.
    sched.recordNormalDispatch("e");
    await settle(5);
    assert.equal(u1Granted, true);
    (await u1)();
    for (const r of releases) r();
    const [s] = sched.stats();
    assert.equal(s.normalTurns, 2);
    assert.equal(s.urgentTurns, 2); // u-0 (uncontended) + u-1
    assert.equal(s.guardActivations, 1);
  });

  it("is work-conserving: a drained backlog releases parked urgent turns", async () => {
    const sched = new LaneScheduler({ minNormalShare: 0.5 });
    // One backlogged normal turn.
    const releaseNormal = await sched.acquireTurn("e", "normal");
    let granted = 0;
    const p1 = sched.acquireTurn("e", "urgent").then((r) => { granted += 1; return r; });
    const p2 = sched.acquireTurn("e", "urgent").then((r) => { granted += 1; return r; });
    await settle(5);
    assert.equal(granted, 0);
    // The normal dispatch earns 1 turn; the backlog then drains, so the
    // second parked urgent goes work-conservingly.
    sched.recordNormalDispatch("e");
    releaseNormal();
    await settle(5);
    assert.equal(granted, 2);
    (await p1)();
    (await p2)();
    const [s] = sched.stats();
    assert.equal(s.guardActivations, 1);
    assert.equal(s.urgentTurns, 2);
  });

  it("validates the share and supports per-endpoint overrides", () => {
    for (const v of [0, 1, -0.1, 1.5, NaN, Infinity, -Infinity]) {
      assert.throws(() => new LaneScheduler({ minNormalShare: v }), RangeError);
    }
    const sched = new LaneScheduler();
    assert.equal(sched.shareFor("e"), 0.2);
    assert.throws(() => sched.setEndpointMinNormalShare("e", 0), RangeError);
    assert.throws(() => sched.setEndpointMinNormalShare("e", 1), RangeError);
    sched.setEndpointMinNormalShare("e", 0.5);
    assert.equal(sched.shareFor("e"), 0.5);
    assert.equal(sched.shareFor("other"), 0.2);
  });
});

describe("starvation guard (WR-35)", () => {
  it("urgent flood cannot starve normal: DRR guarantees minNormalShare of dispatch turns", async () => {
    const timer = manualTimer();
    const releases = new Map<string, () => void>();
    const dispatchOrder: string[] = [];
    const sender: Sender = async (it) => {
      dispatchOrder.push(it.id);
      await new Promise<void>((r) => { releases.set(it.id, r); });
    };
    const audits: StarvationGuardAuditEvent[] = [];
    const q = new RetryQueue({
      sender,
      maxConcurrentPerEndpoint: 1,
      jitterMs: 0,
      urgent: { maxUrgentPerSecond: 10000, now: () => 0, minNormalShare: 0.25 },
      onStarvationGuardAudit: (e) => audits.push(e),
      setTimer: timer.setTimer,
    });
    q.start();
    for (const id of ["n-1", "n-2", "n-3", "n-4"]) q.enqueue(item(id));
    await timer.run();
    await settle();
    // n-1 holds the only slot; n-2..n-4 wait in the limiter FIFO.
    assert.deepEqual(dispatchOrder, ["n-1"]);

    for (let i = 1; i <= 12; i++) q.enqueue(item(`u-${i}`, "urgent"));
    await timer.run();
    await settle();
    // Every urgent turn parked behind the normal backlog: without the
    // guard all 12 would have jumped ahead of n-2..n-4.
    assert.deepEqual(dispatchOrder, ["n-1"]);
    assert.equal(audits.length, 1);
    assert.deepEqual(audits[0], {
      event: "starvation_guard_activated",
      endpoint: URL,
      waitingNormal: 3,
      waitingUrgent: 1,
      minNormalShare: 0.25,
    });

    for (let round = 0; round < 10 && (await drainRound(timer, releases, q)); round++) {
      // release-all is deterministic: microtask FIFO fixes the grant order
    }
    assert.equal(q.pendingCount(), 0);
    // Each normal dispatch earns exactly 3 urgent turns (share 0.25);
    // the last 3 urgents go work-conservingly once normal drains.
    // (The earning normal's sender starts a microtask before the granted
    // urgent senders — grant order is the DRR order; the skew only ever
    // favors normal.)
    assert.deepEqual(dispatchOrder, [
      "n-1",
      "n-2", "u-1", "u-2", "u-3",
      "n-3", "u-4", "u-5", "u-6",
      "n-4", "u-7", "u-8", "u-9",
      "u-10", "u-11", "u-12",
    ]);
    const normals = dispatchOrder.filter((id) => id.startsWith("n-"));
    assert.equal(normals.length / dispatchOrder.length >= 0.25, true);
    // Pacing, not just totals: without the guard every urgent would jump
    // ahead (u-1..u-12 right after n-1); each urgent batch waits for the
    // next normal dispatch instead.
    const idx = (id: string) => dispatchOrder.indexOf(id);
    assert.ok(idx("u-4") > idx("n-3"));
    assert.ok(idx("u-7") > idx("n-4"));
    assert.ok(idx("u-10") > idx("n-4"));

    const [ls] = q.getLaneStats();
    assert.equal(ls.endpoint, URL);
    assert.equal(ls.minNormalShare, 0.25);
    assert.equal(ls.normalTurns, 4);
    assert.equal(ls.urgentTurns, 12);
    assert.equal(ls.guardActivations, 1);

    const line = q
      .renderMetrics()
      .split("\n")
      .find((l) => l.startsWith("relay_starvation_guard_activations{"));
    assert.equal(line, `relay_starvation_guard_activations{endpoint="${URL}"} 1`);
  });

  it("without urgent pressure the gate is a pass-through", async () => {
    const timer = manualTimer();
    const releases = new Map<string, () => void>();
    const dispatchOrder: string[] = [];
    const sender: Sender = async (it) => {
      dispatchOrder.push(it.id);
      await new Promise<void>((r) => { releases.set(it.id, r); });
    };
    const audits: StarvationGuardAuditEvent[] = [];
    const q = new RetryQueue({
      sender,
      maxConcurrentPerEndpoint: 1,
      jitterMs: 0,
      onStarvationGuardAudit: (e) => audits.push(e),
      setTimer: timer.setTimer,
    });
    q.start();
    for (const id of ["n-1", "n-2", "n-3"]) q.enqueue(item(id));
    await timer.run();
    await settle();
    for (let round = 0; round < 10 && (await drainRound(timer, releases, q)); round++) {
      // drain
    }
    // Plain FIFO, zero behavior change from the gate.
    assert.deepEqual(dispatchOrder, ["n-1", "n-2", "n-3"]);
    assert.equal(q.pendingCount(), 0);
    assert.deepEqual(audits, []);
    const [ls] = q.getLaneStats();
    assert.equal(ls.minNormalShare, 0.2);
    assert.equal(ls.normalTurns, 3);
    assert.equal(ls.urgentTurns, 0);
    assert.equal(ls.guardActivations, 0);
    assert.ok(
      !q.renderMetrics().split("\n").some((l) => l.startsWith("relay_starvation_guard_activations{"))
    );
  });

  it("a lone urgent lane is never delayed (work-conserving)", async () => {
    const timer = manualTimer();
    const seen: string[] = [];
    const q = new RetryQueue({
      sender: async (it) => { seen.push(it.id); },
      maxConcurrentPerEndpoint: 1,
      jitterMs: 0,
      urgent: { maxUrgentPerSecond: 10000, now: () => 0 },
      setTimer: timer.setTimer,
    });
    q.start();
    for (let i = 1; i <= 5; i++) q.enqueue(item(`u-${i}`, "urgent"));
    await timer.run();
    await settle();
    assert.deepEqual(seen, ["u-1", "u-2", "u-3", "u-4", "u-5"]);
    const [ls] = q.getLaneStats();
    assert.equal(ls.urgentTurns, 5);
    assert.equal(ls.guardActivations, 0);
  });

  it("composes with the urgent token bucket without double rate-limiting", async () => {
    const timer = manualTimer();
    const seen: string[] = [];
    const q = new RetryQueue({
      sender: async (it) => { seen.push(it.id); },
      maxConcurrentPerEndpoint: 1,
      jitterMs: 0,
      // Frozen clock: exactly one urgent token ever. u-1 takes the fast
      // lane; u-2 finds an empty bucket and degrades to normal (WR-12).
      urgent: { maxUrgentPerSecond: 1, now: () => 0 },
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue(item("u-1", "urgent"));
    q.enqueue(item("n-1"));
    q.enqueue(item("n-2"));
    q.enqueue(item("u-2", "urgent"));
    await timer.run();
    await settle();
    // Normal deliveries are unaffected by the bucket-exhausted urgent:
    // no second rate limit from the lane gate (normal is never delayed).
    assert.deepEqual(seen, ["u-1", "n-1", "n-2", "u-2"]);
    assert.equal(q.pendingCount(), 0);
    const [us] = q.getUrgentStats();
    assert.equal(us.delivered, 1);
    assert.equal(us.throttled, 1);
    const [ls] = q.getLaneStats();
    assert.equal(ls.normalTurns, 3); // n-1, n-2, degraded u-2
    assert.equal(ls.urgentTurns, 1);
    assert.equal(ls.guardActivations, 0);
  });

  it("rejects invalid minNormalShare and supports per-endpoint overrides", () => {
    for (const v of [0, 1, -0.1, 1.5, NaN, Infinity, -Infinity]) {
      assert.throws(() => new RetryQueue({ urgent: { minNormalShare: v } }), RangeError);
    }
    // Boundary-valid values construct fine.
    new RetryQueue({ urgent: { minNormalShare: 0.01 } });
    new RetryQueue({ urgent: { minNormalShare: 0.99 } });
    const q = new RetryQueue({});
    assert.throws(() => q.setEndpointMinNormalShare(URL, 0), RangeError);
    assert.throws(() => q.setEndpointMinNormalShare(URL, 1.2), RangeError);
    q.setEndpointMinNormalShare(URL, 0.5);
    const [ls] = q.getLaneStats();
    assert.equal(ls.endpoint, URL);
    assert.equal(ls.minNormalShare, 0.5);
  });

  it("per-endpoint share override changes the pacing", async () => {
    const timer = manualTimer();
    const releases = new Map<string, () => void>();
    const dispatchOrder: string[] = [];
    const sender: Sender = async (it) => {
      dispatchOrder.push(it.id);
      await new Promise<void>((r) => { releases.set(it.id, r); });
    };
    const q = new RetryQueue({
      sender,
      maxConcurrentPerEndpoint: 1,
      jitterMs: 0,
      urgent: { maxUrgentPerSecond: 10000, now: () => 0 },
      setTimer: timer.setTimer,
    });
    q.setEndpointMinNormalShare(URL, 0.5); // 1:1 pacing
    q.start();
    q.enqueue(item("n-1"));
    q.enqueue(item("n-2"));
    await timer.run();
    await settle();
    q.enqueue(item("u-1", "urgent"));
    q.enqueue(item("u-2", "urgent"));
    await timer.run();
    await settle();
    for (let round = 0; round < 10 && (await drainRound(timer, releases, q)); round++) {
      // drain
    }
    // Share 0.5: each normal dispatch earns exactly 1 urgent turn.
    // (n-2's sender starts a microtask before the granted u-1's — grant
    // order is the DRR order.) Without the guard u-2 would jump ahead of
    // n-2; instead it waits for n-2's dispatch.
    assert.deepEqual(dispatchOrder, ["n-1", "n-2", "u-1", "u-2"]);
    assert.ok(dispatchOrder.indexOf("u-2") > dispatchOrder.indexOf("n-2"));
    const [ls] = q.getLaneStats();
    assert.equal(ls.minNormalShare, 0.5);
    assert.equal(ls.guardActivations, 1);
  });
});
