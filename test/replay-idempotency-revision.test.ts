import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Server } from "node:http";
import {
  RetryQueue,
  type ReplayIdempotencyOptions,
  type ReplaySkippedInfo,
  type Sender,
} from "../src/retry.ts";
import { ReplayIdempotencyGuard } from "../src/replay-idempotency.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";

// camelCase on purpose: the runtime redacts a literal `secret:` key in
// test-file writes (see AGENTS.md), so the key is spelled out
// dynamically instead.
const relaySecret = "replay-idempotency-revision-secret";
const operatorToken = "replay-idempotency-revision-token";
const URL = "http://localhost:9999/hook";
const FORWARD = "http://127.0.0.1:1/unused";
const PAYLOAD = Buffer.from(JSON.stringify({ payment: "pi_123", amount: 5000 }));
const PAYLOAD_2 = Buffer.from(JSON.stringify({ payment: "pi_456", amount: 7000 }));
const PAYLOAD_3 = Buffer.from(JSON.stringify({ payment: "pi_789", amount: 9000 }));
const PAYLOAD_4 = Buffer.from(JSON.stringify({ payment: "pi_000", amount: 1000 }));
const PAYLOAD_5 = Buffer.from(JSON.stringify({ payment: "pi_111", amount: 2000 }));

/** Manual timer with single-step control. */
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
    async drain() {
      while (pending.length > 0) {
        const fns = pending.splice(0);
        for (const f of fns) f();
        await new Promise((r) => setImmediate(r));
      }
    },
  };
}

function controllableSender() {
  let fail = true;
  const sender: Sender = async () => {
    if (fail) throw new Error("downstream 500");
  };
  return { sender, setFail: (v: boolean) => (fail = v) };
}

describe("ReplayIdempotencyGuard retune (WR-441)", () => {
  it("widening the window revives an expired-but-not-evicted record", () => {
    let now = 1000;
    const g = new ReplayIdempotencyGuard({ windowMs: 1000, now: () => now });
    g.recordDelivered(URL, PAYLOAD);
    assert.equal(g.deliveredAtMs(URL, PAYLOAD), 1000);
    now = 2500; // 1500ms old: past the 1000ms window.
    assert.equal(g.deliveredAtMs(URL, PAYLOAD), undefined);
    // The record was never evicted (eviction only runs on insert), so
    // widening the window brings it back into suppression.
    assert.deepEqual(g.retune({ windowMs: 5000 }), { windowMs: 5000, maxEntries: 10_000 });
    assert.equal(g.deliveredAtMs(URL, PAYLOAD), 1000);
  });

  it("narrowing the window drops old records from suppression at once", () => {
    let now = 1000;
    const g = new ReplayIdempotencyGuard({ windowMs: 10_000, now: () => now });
    g.recordDelivered(URL, PAYLOAD);
    now = 5000;
    assert.equal(g.deliveredAtMs(URL, PAYLOAD), 1000);
    g.retune({ windowMs: 1000 });
    assert.equal(g.deliveredAtMs(URL, PAYLOAD), undefined);
  });

  it("lowering maxEntries eagerly evicts the oldest records", () => {
    let now = 1000;
    const g = new ReplayIdempotencyGuard({ maxEntries: 3, now: () => now });
    g.recordDelivered(URL, PAYLOAD);
    now = 2000;
    g.recordDelivered(URL, PAYLOAD_2);
    now = 3000;
    g.recordDelivered(URL, PAYLOAD_3);
    assert.equal(g.stats().trackedPairs, 3);
    assert.equal(g.stats().oldestRecordAtMs, 1000);
    assert.deepEqual(g.retune({ maxEntries: 1 }), { windowMs: 86_400_000, maxEntries: 1 });
    assert.equal(g.stats().trackedPairs, 1);
    assert.equal(g.stats().oldestRecordAtMs, 3000);
    assert.equal(g.deliveredAtMs(URL, PAYLOAD_3), 3000);
    assert.equal(g.deliveredAtMs(URL, PAYLOAD), undefined);
    assert.equal(g.deliveredAtMs(URL, PAYLOAD_2), undefined);
  });

  it("raising maxEntries keeps more records", () => {
    let now = 1000;
    const g = new ReplayIdempotencyGuard({ maxEntries: 2, now: () => now });
    g.recordDelivered(URL, PAYLOAD);
    now = 2000;
    g.recordDelivered(URL, PAYLOAD_2);
    now = 3000;
    g.recordDelivered(URL, PAYLOAD_3); // evicts PAYLOAD at the cap.
    assert.equal(g.stats().trackedPairs, 2);
    assert.equal(g.deliveredAtMs(URL, PAYLOAD), undefined);
    g.retune({ maxEntries: 5 });
    now = 4000;
    g.recordDelivered(URL, PAYLOAD_4);
    now = 5000;
    g.recordDelivered(URL, PAYLOAD_5);
    assert.equal(g.stats().trackedPairs, 4);
    assert.equal(g.deliveredAtMs(URL, PAYLOAD_2), 2000);
    assert.equal(g.deliveredAtMs(URL, PAYLOAD_5), 5000);
  });

  it("an illegal retune throws RangeError and the live values and index are untouched", () => {
    let now = 1000;
    const g = new ReplayIdempotencyGuard({ windowMs: 1000, maxEntries: 5, now: () => now });
    g.recordDelivered(URL, PAYLOAD);
    for (const bad of [
      { windowMs: 0 },
      { windowMs: -5 },
      { windowMs: Number.NaN },
      { maxEntries: 0 },
      { maxEntries: 1.5 },
      { maxEntries: Number.NaN },
    ]) {
      assert.throws(() => g.retune(bad), RangeError);
    }
    assert.deepEqual(g.current(), { windowMs: 1000, maxEntries: 5 });
    assert.equal(g.deliveredAtMs(URL, PAYLOAD), 1000);
    assert.equal(g.stats().trackedPairs, 1);
  });

  it("an empty or non-object retune throws RangeError", () => {
    const g = new ReplayIdempotencyGuard({ windowMs: 1000, maxEntries: 5 });
    assert.throws(() => g.retune({}), RangeError);
    assert.throws(() => g.retune(null as never), RangeError);
    assert.throws(() => g.retune("wide" as never), RangeError);
    assert.throws(() => g.retune([] as never), RangeError);
    assert.deepEqual(g.current(), { windowMs: 1000, maxEntries: 5 });
  });

  it("a same-value retune is a no-op returning the live config", () => {
    const g = new ReplayIdempotencyGuard({ windowMs: 1000, maxEntries: 5 });
    assert.deepEqual(g.retune({ windowMs: 1000 }), { windowMs: 1000, maxEntries: 5 });
    assert.deepEqual(g.retune({ windowMs: 1000, maxEntries: 5 }), {
      windowMs: 1000,
      maxEntries: 5,
    });
    assert.deepEqual(g.current(), { windowMs: 1000, maxEntries: 5 });
  });
});

describe("RetryQueue reviseReplayIdempotency (WR-441)", () => {
  function makeQueue(replayIdempotency?: ReplayIdempotencyOptions, guardNow?: () => number) {
    const timer = manualTimer();
    const f = controllableSender();
    const skipped: ReplaySkippedInfo[] = [];
    const q = new RetryQueue({
      sender: f.sender,
      baseDelayMs: 10,
      maxAttempts: 1, // dead-letter on the first failure
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      ...(replayIdempotency === undefined
        ? {}
        : { replayIdempotency: { ...replayIdempotency, ...(guardNow === undefined ? {} : { now: guardNow }) } }),
      onReplaySkipped: (info) => skipped.push(info),
    });
    return { q, timer, f, skipped };
  }

  /**
   * The guard compares millisecond timestamps with a strict `>`, so a
   * delivered record stamped in the *same* millisecond as the
   * dead-lettering must not suppress. Suppression tests run the guard's
   * clock 60s ahead of wall time (delivered records are deterministically
   * newer).
   */
  function aheadClockState() {
    let nowMs = Date.now() + 60_000;
    return { now: () => nowMs, advance: (ms: number) => (nowMs += ms) };
  }

  it("widening the window re-suppresses a replay whose record had expired", async () => {
    const clock = aheadClockState();
    const { q, timer, f, skipped } = makeQueue({ windowMs: 1000 }, clock.now);
    q.start();
    // Dead-letter two copies of the same pair.
    q.enqueue({ id: "rev-a1", payload: PAYLOAD, targetUrl: URL, headers: {} });
    q.enqueue({ id: "rev-a2", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    assert.equal(q.getDeadLetter().length, 2);
    // Deliver the pair once (recorded on the guard clock).
    f.setFail(false);
    q.enqueue({ id: "rev-b", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    // Advance past the 1000ms window: the record is expired, so the
    // first replay is allowed. The sender stays failing so the replay
    // re-dead-letters instead of refreshing the guard record.
    clock.advance(2000);
    f.setFail(true);
    assert.equal(q.replayDeadLetter("rev-a1"), true);
    await timer.drain();
    assert.equal(q.getDeadLetter().length, 2);
    // Widen the window: the never-evicted record revives, and the
    // second copy is suppressed again.
    assert.deepEqual(q.reviseReplayIdempotency({ windowMs: 120_000 }), {
      windowMs: 120_000,
      maxEntries: 10_000,
    });
    assert.equal(q.replayDeadLetter("rev-a2"), false);
    assert.equal(skipped.length, 1);
    assert.equal(skipped[0].id, "rev-a2");
    assert.equal(q.getDeadLetter().length, 2);
  });

  it("narrowing the window un-suppresses a replay at once", async () => {
    const clock = aheadClockState();
    const { q, timer, f, skipped } = makeQueue({ windowMs: 120_000 }, clock.now);
    q.start();
    q.enqueue({ id: "nar-a", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    f.setFail(false);
    q.enqueue({ id: "nar-b", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    clock.advance(2000);
    assert.equal(q.replayDeadLetter("nar-a"), false);
    assert.equal(skipped.length, 1);
    q.reviseReplayIdempotency({ windowMs: 1000 });
    assert.equal(q.replayDeadLetter("nar-a"), true);
    await timer.drain();
    assert.equal(q.pendingCount(), 0);
  });

  it("an illegal patch throws RangeError and the live config and index are untouched", async () => {
    const { q, timer, f } = makeQueue({ windowMs: 1000, maxEntries: 5 });
    q.start();
    f.setFail(false);
    q.enqueue({ id: "ill-a", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    const before = q.getReplayIdempotencyConfig();
    const statsBefore = q.getReplayIdempotencyStats();
    for (const bad of [
      { windowMs: 0 },
      { windowMs: -5 },
      { windowMs: Number.NaN },
      { maxEntries: 0 },
      { maxEntries: 1.5 },
      { maxEntries: Number.NaN },
    ]) {
      assert.throws(() => q.reviseReplayIdempotency(bad), RangeError);
    }
    assert.deepEqual(q.getReplayIdempotencyConfig(), before);
    assert.deepEqual(q.getReplayIdempotencyStats(), statsBefore);
  });

  it("an empty or non-object patch throws RangeError", () => {
    const { q } = makeQueue({ windowMs: 1000 });
    assert.throws(() => q.reviseReplayIdempotency({}), RangeError);
    assert.throws(() => q.reviseReplayIdempotency(null as never), RangeError);
    assert.throws(() => q.reviseReplayIdempotency("wide" as never), RangeError);
    assert.throws(() => q.reviseReplayIdempotency([] as never), RangeError);
    assert.deepEqual(q.getReplayIdempotencyConfig(), { windowMs: 1000, maxEntries: 10_000 });
  });

  it("revising with the guard unconfigured enables it (WR-460)", () => {
    const { q } = makeQueue();
    assert.equal(q.getReplayIdempotencyConfig(), undefined);
    assert.deepEqual(q.reviseReplayIdempotency({ windowMs: 1000 }), {
      windowMs: 1000,
      maxEntries: 10_000,
    });
    assert.deepEqual(q.getReplayIdempotencyConfig(), {
      windowMs: 1000,
      maxEntries: 10_000,
    });
  });

  it("the getter follows the live values and a same-value revision is a no-op", () => {
    const { q } = makeQueue({ windowMs: 1000, maxEntries: 5 });
    assert.deepEqual(q.getReplayIdempotencyConfig(), { windowMs: 1000, maxEntries: 5 });
    assert.deepEqual(q.reviseReplayIdempotency({ windowMs: 2000 }), {
      windowMs: 2000,
      maxEntries: 5,
    });
    assert.deepEqual(q.getReplayIdempotencyConfig(), { windowMs: 2000, maxEntries: 5 });
    assert.deepEqual(q.reviseReplayIdempotency({ maxEntries: 7 }), {
      windowMs: 2000,
      maxEntries: 7,
    });
    assert.deepEqual(q.getReplayIdempotencyConfig(), { windowMs: 2000, maxEntries: 7 });
    assert.deepEqual(q.reviseReplayIdempotency({ windowMs: 2000, maxEntries: 7 }), {
      windowMs: 2000,
      maxEntries: 7,
    });
  });

  it("revision retunes every live tenant guard and guards born later", async () => {
    const clock = aheadClockState();
    const { q, timer, f, skipped } = makeQueue({ windowMs: 1000 }, clock.now);
    q.start();
    // Tenant t1 and the default tenant each dead-letter then deliver
    // the same pair, so each owns a live guard with one record.
    q.enqueue({ id: "t1-dl", payload: PAYLOAD, targetUrl: URL, headers: {}, tenantId: "t1" });
    await timer.drain();
    f.setFail(false);
    q.enqueue({ id: "t1-ok", payload: PAYLOAD, targetUrl: URL, headers: {}, tenantId: "t1" });
    await timer.drain();
    f.setFail(true);
    q.enqueue({ id: "d-dl", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    f.setFail(false);
    q.enqueue({ id: "d-ok", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    // Advance past the 1000ms window: both records are expired, so
    // both replays are allowed (and re-dead-letter, sender failing,
    // without refreshing the guard records).
    clock.advance(2000);
    f.setFail(true);
    assert.equal(q.replayDeadLetter("t1-dl"), true);
    await timer.drain();
    assert.equal(q.replayDeadLetter("d-dl"), true);
    await timer.drain();
    // Widen the window: both live guards retune, both records revive.
    q.reviseReplayIdempotency({ windowMs: 120_000 });
    assert.equal(q.replayDeadLetter("t1-dl"), false);
    assert.equal(q.replayDeadLetter("d-dl"), false);
    assert.equal(skipped.length, 2);
    // A tenant born after the revision starts from the revised values:
    // its record is 2000ms old — past the old 1000ms window, inside
    // the new 120s window — so its replay is suppressed.
    f.setFail(false);
    q.enqueue({ id: "t2-ok", payload: PAYLOAD, targetUrl: URL, headers: {}, tenantId: "t2" });
    await timer.drain();
    f.setFail(true);
    q.enqueue({ id: "t2-dl", payload: PAYLOAD, targetUrl: URL, headers: {}, tenantId: "t2" });
    await timer.drain();
    clock.advance(2000);
    assert.equal(q.replayDeadLetter("t2-dl"), false);
    assert.equal(skipped.length, 3);
  });

  it("revision leaves the index alone: stats are unchanged", async () => {
    const { q, timer, f } = makeQueue({ windowMs: 1000, maxEntries: 5 });
    q.start();
    f.setFail(false);
    q.enqueue({ id: "st-a", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    const before = q.getReplayIdempotencyStats();
    assert.equal(before!.length, 1);
    q.reviseReplayIdempotency({ windowMs: 2000 });
    assert.deepEqual(q.getReplayIdempotencyStats(), before);
  });

  it("replays already decided are never revisited by a revision", async () => {
    const clock = aheadClockState();
    const { q, timer, f, skipped } = makeQueue({}, clock.now);
    q.start();
    q.enqueue({ id: "dec-a", payload: PAYLOAD, targetUrl: URL, headers: {} });
    q.enqueue({ id: "dec-b", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    assert.equal(q.getDeadLetter().length, 2);
    f.setFail(false);
    q.enqueue({ id: "dec-c", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    // Decide both replays: dec-a suppressed, dec-b force-replayed.
    assert.equal(q.replayDeadLetter("dec-a"), false);
    assert.equal(q.replayDeadLetter("dec-b", { force: true }), true);
    await timer.drain();
    assert.deepEqual(
      q.getDeadLetter().map((e) => e.id),
      ["dec-a"]
    );
    // Narrow the window to nothing: the already-decided outcomes
    // stand — dec-a is not spontaneously replayed, dec-b stays gone.
    q.reviseReplayIdempotency({ windowMs: 1 });
    assert.deepEqual(
      q.getDeadLetter().map((e) => e.id),
      ["dec-a"]
    );
    assert.equal(skipped.length, 1);
    // Only a *new* decision sees the new tuning (the guard clock must
    // move for the 1ms window to actually expire the record).
    clock.advance(5000);
    assert.equal(q.replayDeadLetter("dec-a"), true);
    await timer.drain();
    assert.equal(q.getDeadLetter().length, 0);
  });
});

describe("RelayServer reviseReplayIdempotency (WR-441)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "replay-idempotency-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: FORWARD,
      auditLog,
      operatorToken,
      ...opts,
    });
    servers.push(relay);
    return { relay, auditLog };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  it("a real revision audits previous/current exactly and the getter follows live values", () => {
    const { relay, auditLog } = makeServer({ retry: { replayIdempotency: {} } });
    assert.deepEqual(relay.getReplayIdempotencyConfig!(), {
      windowMs: 86_400_000,
      maxEntries: 10_000,
    });
    const next = relay.reviseReplayIdempotency!({ windowMs: 72 * 3_600_000 });
    assert.deepEqual(next, { windowMs: 259_200_000, maxEntries: 10_000 });
    assert.deepEqual(relay.getReplayIdempotencyConfig!(), {
      windowMs: 259_200_000,
      maxEntries: 10_000,
    });
    const revised = eventsOf(auditLog, "replay_idempotency_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, { windowMs: 86_400_000, maxEntries: 10_000 });
    assert.deepEqual(revised[0].current, { windowMs: 259_200_000, maxEntries: 10_000 });
  });

  it("a same-value revision is a silent no-op with no audit event", () => {
    const { relay, auditLog } = makeServer({ retry: { replayIdempotency: {} } });
    relay.reviseReplayIdempotency!({ windowMs: 86_400_000 });
    assert.equal(eventsOf(auditLog, "replay_idempotency_revised").length, 0);
    assert.deepEqual(relay.getReplayIdempotencyConfig!(), {
      windowMs: 86_400_000,
      maxEntries: 10_000,
    });
  });

  it("an illegal or empty patch throws RangeError, no audit, live values untouched", () => {
    const { relay, auditLog } = makeServer({ retry: { replayIdempotency: {} } });
    assert.throws(() => relay.reviseReplayIdempotency!({ windowMs: 0 }), RangeError);
    assert.throws(() => relay.reviseReplayIdempotency!({ maxEntries: 1.5 }), RangeError);
    assert.throws(() => relay.reviseReplayIdempotency!({}), RangeError);
    assert.equal(eventsOf(auditLog, "replay_idempotency_revised").length, 0);
    assert.deepEqual(relay.getReplayIdempotencyConfig!(), {
      windowMs: 86_400_000,
      maxEntries: 10_000,
    });
  });

  it("revising with the guard unconfigured enables it and mounts the getter (WR-460)", () => {
    const { relay, auditLog } = makeServer();
    assert.equal(relay.getReplayIdempotencyConfig, undefined);
    assert.deepEqual(relay.reviseReplayIdempotency!({ windowMs: 1000 }), {
      windowMs: 1000,
      maxEntries: 10_000,
    });
    assert.deepEqual(relay.getReplayIdempotencyConfig!(), {
      windowMs: 1000,
      maxEntries: 10_000,
    });
    const enabled = eventsOf(auditLog, "replay_idempotency_revised");
    assert.equal(enabled.length, 1);
    assert.equal(enabled[0].previous, null);
    assert.deepEqual(enabled[0].current, { windowMs: 1000, maxEntries: 10_000 });
  });
});
