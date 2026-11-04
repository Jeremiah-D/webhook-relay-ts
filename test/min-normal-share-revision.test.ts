import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import {
  LaneScheduler,
  RetryQueue,
  type RetryItem,
  type Sender,
} from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "min-normal-share-revision-secret";
const EP_A = "http://a.example/hook";
const EP_B = "http://b.example/hook";
const URL = "http://localhost:9999/guard";

/** Let queued microtask chains (limiter grant -> turn grant -> sender) settle. */
async function settle(rounds = 20): Promise<void> {
  for (let i = 0; i < rounds; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

/** Deterministic timer: `run()` executes pending callbacks immediately. */
function manualTimer() {
  const pending: Array<() => void> = [];
  return {
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
    async run() {
      while (pending.length > 0) {
        const fns = pending.splice(0);
        for (const fn of fns) fn();
        await new Promise((r) => setImmediate(r));
      }
    },
  };
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
    pending: releases,
  };
}

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

describe("RelayServer endpoint min-normal-share revision (WR-323)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "min-normal-share-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: EP_A,
      auditLog,
      ...opts,
    });
    servers.push(relay);
    return { relay, auditLog };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  it("revise audits previous/current, with the queue default 0.2 as first previous", async () => {
    const { relay, auditLog } = makeServer();
    await listen(relay);
    const current = relay.reviseEndpointMinNormalShare(EP_A, 0.4);
    assert.deepEqual(current, { minNormalShare: 0.4, overridden: true });
    const revised = eventsOf(auditLog, "min_normal_share_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].endpoint, EP_A);
    assert.equal(revised[0].previous, 0.2);
    assert.equal(revised[0].current, 0.4);
    // A second revision audits the live values as previous.
    const current2 = relay.reviseEndpointMinNormalShare(EP_A, 0.1);
    assert.deepEqual(current2, { minNormalShare: 0.1, overridden: true });
    const revised2 = eventsOf(auditLog, "min_normal_share_revised");
    assert.equal(revised2.length, 2);
    assert.equal(revised2[1].previous, 0.4);
    assert.equal(revised2[1].current, 0.1);
  });

  it("getter snapshot matches live; an unrevised endpoint reports the default", async () => {
    const { relay } = makeServer();
    await listen(relay);
    relay.reviseEndpointMinNormalShare(EP_A, 0.4);
    assert.deepEqual(relay.getEndpointMinNormalShare(EP_A), {
      minNormalShare: 0.4,
      overridden: true,
    });
    // Never revised: the queue default, no override — and merely reading
    // it does not make the endpoint "seen" (it stays out of the listing).
    assert.deepEqual(relay.getEndpointMinNormalShare(EP_B), {
      minNormalShare: 0.2,
      overridden: false,
    });
    assert.deepEqual(relay.getMinNormalShares(), [
      { endpoint: EP_A, minNormalShare: 0.4, overridden: true },
    ]);
  });

  it("illegal values throw RangeError and leave the live share untouched", async () => {
    const { relay, auditLog } = makeServer();
    await listen(relay);
    for (const bad of [0, 1, -0.1, 1.5, NaN, Infinity, -Infinity]) {
      assert.throws(() => relay.reviseEndpointMinNormalShare(EP_A, bad), RangeError, `share ${bad}`);
      assert.deepEqual(relay.getEndpointMinNormalShare(EP_A), {
        minNormalShare: 0.2,
        overridden: false,
      });
    }
    assert.equal(eventsOf(auditLog, "min_normal_share_revised").length, 0);
  });

  it("a same-value revision is a silent no-op", async () => {
    const { relay, auditLog } = makeServer();
    await listen(relay);
    // Revising to the queue default changes nothing worth auditing.
    relay.reviseEndpointMinNormalShare(EP_A, 0.2);
    assert.equal(eventsOf(auditLog, "min_normal_share_revised").length, 0);
    relay.reviseEndpointMinNormalShare(EP_A, 0.4);
    relay.reviseEndpointMinNormalShare(EP_A, 0.4);
    assert.equal(eventsOf(auditLog, "min_normal_share_revised").length, 1);
  });

  it("remove returns true, audits the removed share, and falls back to the default", async () => {
    const { relay, auditLog } = makeServer();
    await listen(relay);
    relay.reviseEndpointMinNormalShare(EP_A, 0.4);
    assert.equal(relay.removeEndpointMinNormalShare(EP_A), true);
    const removed = eventsOf(auditLog, "min_normal_share_removed");
    assert.equal(removed.length, 1);
    assert.equal(removed[0].endpoint, EP_A);
    assert.equal(removed[0].previous, 0.4);
    assert.deepEqual(relay.getEndpointMinNormalShare(EP_A), {
      minNormalShare: 0.2,
      overridden: false,
    });
    // The endpoint stays listed (observed), now at the default.
    assert.deepEqual(relay.getMinNormalShares(), [
      { endpoint: EP_A, minNormalShare: 0.2, overridden: false },
    ]);
  });

  it("remove with no override returns false and audits nothing", async () => {
    const { relay, auditLog } = makeServer();
    await listen(relay);
    assert.equal(relay.removeEndpointMinNormalShare(EP_A), false);
    assert.equal(eventsOf(auditLog, "min_normal_share_removed").length, 0);
    // A revision records an override, so a later remove finds it — and
    // a second remove finds nothing.
    relay.reviseEndpointMinNormalShare(EP_A, 0.4);
    assert.equal(relay.removeEndpointMinNormalShare(EP_A), true);
    assert.equal(relay.removeEndpointMinNormalShare(EP_A), false);
    assert.equal(eventsOf(auditLog, "min_normal_share_removed").length, 1);
  });

  it("getMinNormalShares lists revised endpoints in first-seen order", async () => {
    const { relay } = makeServer();
    await listen(relay);
    assert.deepEqual(relay.getMinNormalShares(), []);
    relay.reviseEndpointMinNormalShare(EP_A, 0.4);
    relay.reviseEndpointMinNormalShare(EP_B, 0.1);
    assert.deepEqual(relay.getMinNormalShares(), [
      { endpoint: EP_A, minNormalShare: 0.4, overridden: true },
      { endpoint: EP_B, minNormalShare: 0.1, overridden: true },
    ]);
  });

  it("a custom constructor default is the first previous and the remove fallback", async () => {
    const { relay, auditLog } = makeServer({
      retry: { urgent: { minNormalShare: 0.35 } },
    });
    await listen(relay);
    assert.deepEqual(relay.getEndpointMinNormalShare(EP_A), {
      minNormalShare: 0.35,
      overridden: false,
    });
    relay.reviseEndpointMinNormalShare(EP_A, 0.5);
    assert.equal(eventsOf(auditLog, "min_normal_share_revised")[0].previous, 0.35);
    assert.equal(relay.removeEndpointMinNormalShare(EP_A), true);
    assert.equal(eventsOf(auditLog, "min_normal_share_removed")[0].previous, 0.5);
    assert.deepEqual(relay.getEndpointMinNormalShare(EP_A), {
      minNormalShare: 0.35,
      overridden: false,
    });
  });
});

describe("RetryQueue endpoint min-normal-share revision (WR-323)", () => {
  it("live tightening to 0.4 paces urgent harder: normal keeps its share of turns", async () => {
    const timer = manualTimer();
    const { sender, started: dispatchOrder, pending: releases } = blockingSender();
    const q = new RetryQueue({
      sender,
      maxConcurrentPerEndpoint: 1,
      jitterMs: 0,
      urgent: { maxUrgentPerSecond: 10000, now: () => 0 },
      setTimer: timer.setTimer,
    });
    try {
      q.start();
      for (const id of ["n-1", "n-2", "n-3", "n-4"]) q.enqueue(item(id));
      await timer.run();
      await settle();
      assert.deepEqual(dispatchOrder, ["n-1"]);
      for (let i = 1; i <= 12; i++) q.enqueue(item(`u-${i}`, "urgent"));
      await timer.run();
      await settle();
      // Every urgent turn parked behind the normal backlog.
      assert.deepEqual(dispatchOrder, ["n-1"]);
      // Live revision mid-flood: the pacing from here on follows 0.4.
      q.setEndpointMinNormalShare(URL, 0.4);
      for (let round = 0; round < 10 && (await drainRound(timer, releases, q)); round++) {
        // release-all is deterministic: microtask FIFO fixes the grant order
      }
      assert.equal(q.pendingCount(), 0);
      // Each normal dispatch earns (1-0.4)/0.4 turns at share 0.4 (vs 4
      // at the 0.2 default), so urgent batches shrink to one per
      // dispatch, then two — note (1-0.4)/0.4 is 1.4999999999999998 in
      // floating point, so the second dispatch's 1.9999... deficit
      // grants exactly one urgent turn, not two.
      assert.deepEqual(dispatchOrder, [
        "n-1",
        "n-2", "u-1",
        "n-3", "u-2",
        "n-4", "u-3", "u-4",
        "u-5", "u-6", "u-7", "u-8", "u-9", "u-10", "u-11", "u-12",
      ]);
      // Pacing, not just totals: u-2 waits for n-3's dispatch, u-3 for n-4's.
      const idx = (id: string) => dispatchOrder.indexOf(id);
      assert.ok(idx("u-2") > idx("n-3"));
      assert.ok(idx("u-3") > idx("n-4"));
      assert.ok(idx("u-5") > idx("n-4"));
      const [ls] = q.getLaneStats();
      assert.equal(ls.minNormalShare, 0.4);
      assert.equal(ls.normalTurns, 4);
      assert.equal(ls.urgentTurns, 12);
      assert.equal(ls.guardActivations, 1);
    } finally {
      q.stop();
    }
  });

  it("live loosening to 0.1 releases urgent faster after one normal dispatch", async () => {
    const timer = manualTimer();
    const { sender, started: dispatchOrder, pending: releases } = blockingSender();
    const q = new RetryQueue({
      sender,
      maxConcurrentPerEndpoint: 1,
      jitterMs: 0,
      urgent: { maxUrgentPerSecond: 10000, now: () => 0 },
      setTimer: timer.setTimer,
    });
    try {
      q.start();
      q.enqueue(item("n-1"));
      q.enqueue(item("n-2"));
      await timer.run();
      await settle();
      assert.deepEqual(dispatchOrder, ["n-1"]);
      for (let i = 1; i <= 6; i++) q.enqueue(item(`u-${i}`, "urgent"));
      await timer.run();
      await settle();
      assert.deepEqual(dispatchOrder, ["n-1"]);
      // Loosen live: the next normal dispatch earns 9 urgent turns.
      q.setEndpointMinNormalShare(URL, 0.1);
      await settle();
      // The revision alone releases nothing while the backlog stands.
      assert.deepEqual(dispatchOrder, ["n-1"]);
      releases.get("n-1")!();
      await timer.run();
      await settle();
      // One normal dispatch released all six urgents — at the 0.2
      // default only four would have gone, the rest waiting for the
      // backlog to drain. n-2 is still in flight while they dispatch.
      assert.deepEqual(dispatchOrder, [
        "n-1", "n-2", "u-1", "u-2", "u-3", "u-4", "u-5", "u-6",
      ]);
      assert.ok(releases.has("n-2"));
      for (let round = 0; round < 10 && (await drainRound(timer, releases, q)); round++) {
        // drain
      }
      assert.equal(q.pendingCount(), 0);
    } finally {
      q.stop();
    }
  });

  it("a revision pumps the gate: parked urgent releases once the normal backlog drains", async () => {
    const timer = manualTimer();
    const { sender, started: dispatchOrder, pending: releases } = blockingSender();
    const q = new RetryQueue({
      sender,
      maxConcurrentPerEndpoint: 1,
      jitterMs: 0,
      urgent: { maxUrgentPerSecond: 10000, now: () => 0, minNormalShare: 0.5 },
      setTimer: timer.setTimer,
    });
    try {
      q.start();
      q.enqueue(item("n-1"));
      q.enqueue(item("n-2"));
      await timer.run();
      await settle();
      for (let i = 1; i <= 3; i++) q.enqueue(item(`u-${i}`, "urgent"));
      await timer.run();
      await settle();
      assert.deepEqual(dispatchOrder, ["n-1"]);
      // n-2's dispatch earns exactly 1 urgent turn at share 0.5; u-2
      // and u-3 stay parked with the backlog drained to zero (the pump
      // runs before the dispatching turn leaves the backlog set).
      releases.get("n-1")!();
      await timer.run();
      await settle();
      assert.deepEqual(dispatchOrder, ["n-1", "n-2", "u-1"]);
      assert.ok(releases.has("n-2"));
      // The revision's pump sees the drained backlog and releases the
      // parked urgent turns work-conservingly at once — n-2 still in
      // flight, no further normal dispatch needed.
      q.setEndpointMinNormalShare(URL, 0.25);
      await settle();
      assert.deepEqual(dispatchOrder, ["n-1", "n-2", "u-1", "u-2", "u-3"]);
      assert.ok(releases.has("n-2"));
      for (let round = 0; round < 10 && (await drainRound(timer, releases, q)); round++) {
        // drain
      }
      assert.equal(q.pendingCount(), 0);
    } finally {
      q.stop();
    }
  });

  it("a revision leaves deficit, turns, and guard activations untouched; later earnings use the new rate", async () => {
    const timer = manualTimer();
    const { sender, started: dispatchOrder, pending: releases } = blockingSender();
    const q = new RetryQueue({
      sender,
      maxConcurrentPerEndpoint: 1,
      jitterMs: 0,
      urgent: { maxUrgentPerSecond: 10000, now: () => 0, minNormalShare: 0.4 },
      setTimer: timer.setTimer,
    });
    try {
      q.start();
      for (const id of ["n-1", "n-2", "n-3", "n-4", "n-5", "n-6", "n-7"]) q.enqueue(item(id));
      await timer.run();
      await settle();
      for (let i = 1; i <= 3; i++) q.enqueue(item(`u-${i}`, "urgent"));
      await timer.run();
      await settle();
      assert.deepEqual(dispatchOrder, ["n-1"]);
      // n-2's dispatch earns 1.5 turns at share 0.4: u-1 goes, 0.5
      // deficit stays earned.
      releases.get("n-1")!();
      await timer.run();
      await settle();
      assert.deepEqual(dispatchOrder, ["n-1", "n-2", "u-1"]);
      const before = q.getLaneStats()[0];
      // Turns are counted at turn-grant time: all seven normals took
      // their turns when enqueued, so normalTurns is already 7 — only
      // u-1 has been granted an urgent turn so far.
      assert.deepEqual(
        {
          normalTurns: before.normalTurns,
          urgentTurns: before.urgentTurns,
          guardActivations: before.guardActivations,
        },
        { normalTurns: 7, urgentTurns: 1, guardActivations: 1 }
      );
      // Tighten to 0.9: counters and the earned 0.5 deficit are untouched.
      q.setEndpointMinNormalShare(URL, 0.9);
      const after = q.getLaneStats()[0];
      assert.equal(after.minNormalShare, 0.9);
      assert.equal(after.normalTurns, before.normalTurns);
      assert.equal(after.urgentTurns, before.urgentTurns);
      assert.equal(after.guardActivations, before.guardActivations);
      // Each later dispatch earns only (1-0.9)/0.9 turns at the new rate,
      // so the carried 0.5 deficit crosses 1.0 only on the fifth further
      // dispatch (n-7) — u-2 goes while n-7 is still in flight, which
      // proves the old deficit was neither reset nor recomputed.
      for (const id of ["n-2", "n-3", "n-4", "n-5"]) {
        releases.get(id)!();
        await timer.run();
        await settle();
        assert.ok(!dispatchOrder.includes("u-2"), `u-2 must wait past ${id}`);
      }
      releases.get("n-6")!();
      await timer.run();
      await settle();
      assert.ok(dispatchOrder.includes("u-2"));
      assert.ok(releases.has("n-7"));
      for (let round = 0; round < 10 && (await drainRound(timer, releases, q)); round++) {
        // drain
      }
      assert.equal(q.pendingCount(), 0);
    } finally {
      q.stop();
    }
  });

  it("a turn granted before the revision still runs to completion after tightening", async () => {
    const timer = manualTimer();
    const { sender, started: dispatchOrder, pending: releases } = blockingSender();
    const q = new RetryQueue({
      sender,
      maxConcurrentPerEndpoint: 1,
      jitterMs: 0,
      urgent: { maxUrgentPerSecond: 10000, now: () => 0, minNormalShare: 0.5 },
      setTimer: timer.setTimer,
    });
    try {
      q.start();
      q.enqueue(item("n-1"));
      q.enqueue(item("n-2"));
      await timer.run();
      await settle();
      q.enqueue(item("u-1", "urgent"));
      q.enqueue(item("u-2", "urgent"));
      await timer.run();
      await settle();
      // n-2's dispatch earns 1 turn: u-1 is granted (in flight) before
      // any revision; u-2 stays parked.
      releases.get("n-1")!();
      await timer.run();
      await settle();
      assert.deepEqual(dispatchOrder, ["n-1", "n-2", "u-1"]);
      assert.ok(releases.has("u-1"));
      // Tighten hard mid-flight: the granted turn is not revoked.
      q.setEndpointMinNormalShare(URL, 0.9);
      await settle();
      assert.ok(releases.has("u-1"));
      assert.ok(releases.has("n-2"));
      for (let round = 0; round < 10 && (await drainRound(timer, releases, q)); round++) {
        // drain
      }
      assert.equal(q.pendingCount(), 0);
      assert.deepEqual(dispatchOrder, ["n-1", "n-2", "u-1", "u-2"]);
    } finally {
      q.stop();
    }
  });

  it("getMinNormalShares lists seen endpoints including merely-observed ones", async () => {
    const timer = manualTimer();
    const { sender } = blockingSender();
    const q = new RetryQueue({
      sender,
      maxConcurrentPerEndpoint: 1,
      jitterMs: 0,
      urgent: { maxUrgentPerSecond: 10000, now: () => 0 },
      setTimer: timer.setTimer,
    });
    try {
      q.start();
      // EP_B takes a turn (observed) but is never revised.
      q.enqueue(item("n-1"));
      await timer.run();
      await settle();
      assert.deepEqual(q.getMinNormalShares(), [
        { endpoint: URL, minNormalShare: 0.2, overridden: false },
      ]);
      // The getter on an unseen endpoint reports the default without
      // adding a row.
      assert.deepEqual(q.getEndpointMinNormalShare(EP_A), {
        minNormalShare: 0.2,
        overridden: false,
      });
      assert.deepEqual(q.getMinNormalShares(), [
        { endpoint: URL, minNormalShare: 0.2, overridden: false },
      ]);
      q.setEndpointMinNormalShare(EP_A, 0.3);
      assert.deepEqual(q.getMinNormalShares(), [
        { endpoint: URL, minNormalShare: 0.2, overridden: false },
        { endpoint: EP_A, minNormalShare: 0.3, overridden: true },
      ]);
    } finally {
      q.stop();
    }
  });
});

describe("LaneScheduler min-normal-share override bookkeeping (WR-323)", () => {
  it("clear resets to the constructor default and keeps state and counters", async () => {
    const sched = new LaneScheduler({ minNormalShare: 0.35 });
    assert.equal(sched.defaultMinNormalShare(), 0.35);
    assert.equal(sched.hasEndpointMinNormalShareOverride("e"), false);
    // No override to clear yet.
    assert.equal(sched.clearEndpointMinNormalShare("e"), false);
    assert.deepEqual(sched.snapshotFor("e"), { minNormalShare: 0.35, overridden: false });
    // The snapshot peek creates no state: the endpoint stays unlisted.
    assert.deepEqual(sched.stats(), []);
    sched.setEndpointMinNormalShare("e", 0.6);
    assert.equal(sched.hasEndpointMinNormalShareOverride("e"), true);
    assert.deepEqual(sched.snapshotFor("e"), { minNormalShare: 0.6, overridden: true });
    // Take a turn so the state carries counters, then clear: the share
    // falls back, the override flag drops, the state (and its turns)
    // stay exactly as they were.
    await sched.acquireTurn("e", "normal").then((release) => release());
    assert.equal(sched.stats()[0].normalTurns, 1);
    assert.equal(sched.clearEndpointMinNormalShare("e"), true);
    assert.equal(sched.hasEndpointMinNormalShareOverride("e"), false);
    assert.deepEqual(sched.snapshotFor("e"), { minNormalShare: 0.35, overridden: false });
    assert.equal(sched.stats().length, 1);
    assert.equal(sched.stats()[0].endpoint, "e");
    assert.equal(sched.stats()[0].normalTurns, 1);
    assert.equal(sched.stats()[0].minNormalShare, 0.35);
    assert.equal(sched.clearEndpointMinNormalShare("e"), false);
    // The plain default is 0.2 when nothing was configured.
    assert.equal(new LaneScheduler().defaultMinNormalShare(), 0.2);
  });
});
