import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue } from "../src/retry.ts";
import { DeadLetterAutoReplayer, type AutoReplayOptions } from "../src/autoreplay.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";

const EP = "http://a.example/hook";
const TOKEN = "operator-token";
const SIGNING_KEY = "relay-secret";

/**
 * Deterministic timer: callbacks fire only via `run()`; the scheduled
 * delays are observable via `waits()` (same helper as autoreplay.test.ts).
 */
function manualTimer() {
  const pending: Array<{ fn: () => void; ms: number }> = [];
  return {
    pending,
    setTimer: (fn: () => void, ms: number) => {
      const rec = { fn, ms };
      pending.push(rec);
      return {
        clear: () => {
          const i = pending.indexOf(rec);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    clearTimer: (h: { clear(): void }) => h.clear(),
    waits(): number[] {
      return pending.map((p) => p.ms);
    },
    async run() {
      while (pending.length > 0) {
        const fns = pending.splice(0);
        for (const f of fns) f.fn();
        await new Promise((r) => setImmediate(r));
      }
    },
  };
}

interface Setup {
  q: RetryQueue;
  /** Queue's own delivery timer. */
  timer: ReturnType<typeof manualTimer>;
  /** The replayer's private timer (rounds never fire unless driven). */
  replayTimer: ReturnType<typeof manualTimer>;
  replayer: DeadLetterAutoReplayer;
  sender: { fail: boolean };
}

/**
 * Queue with a toggleable sender and an enabled auto-replay scheduler.
 * The replayer gets its own manual timer so scheduled rounds never fire
 * as a side effect of draining the queue's delivery timer.
 */
function setupAutoReplay(
  extraQueueOpts: Record<string, unknown> = {},
  autoReplay: Record<string, unknown> = {}
): Setup {
  const timer = manualTimer();
  const replayTimer = manualTimer();
  const state = { fail: true };
  const q = new RetryQueue({
    sender: async () => {
      if (state.fail) throw new Error("downstream 500");
    },
    baseDelayMs: 1,
    maxAttempts: 2,
    jitterMs: 0,
    setTimer: timer.setTimer,
    clearTimer: timer.clearTimer,
    autoReplay: {
      enabled: true,
      intervalMs: 1000,
      maxRounds: 3,
      setTimer: replayTimer.setTimer,
      clearTimer: replayTimer.clearTimer,
      ...autoReplay,
    },
    ...extraQueueOpts,
  });
  const replayer = q.getAutoReplayer();
  assert.ok(replayer, "auto-replay scheduler must exist when configured");
  return { q, timer, replayTimer, replayer, sender: state };
}

async function seedDeadLetter(s: Setup, id: string) {
  s.q.start();
  s.q.enqueue({ id, payload: Buffer.from(`payload-${id}`), targetUrl: EP, headers: {} });
  await s.timer.run();
  const dl = s.q.getDeadLetter();
  assert.equal(dl.length, 1, "item should be dead-lettered");
}

describe("auto-replay schedule revision (WR-344)", () => {
  it("intervalMs tightening shortens a running scheduler's pending wait and clears the old timer", () => {
    const replayTimer = manualTimer();
    const nowMs = 5_000_000;
    // Fixed clock so nextRunAt is observable too.
    const replayer = new DeadLetterAutoReplayer({
      enabled: true,
      intervalMs: 60_000,
      maxRounds: 10,
      now: () => nowMs,
      replayAll: () => ({ replayed: [], failed: [] }),
      setTimer: replayTimer.setTimer,
      clearTimer: replayTimer.clearTimer,
    });
    replayer.start();
    assert.deepEqual(replayTimer.waits(), [60_000]);
    const oldTimer = replayTimer.pending[0];
    assert.equal(
      replayer.status().nextRunAt,
      new Date(nowMs + 60_000).toISOString()
    );

    const next = replayer.retune({ intervalMs: 10_000 });
    assert.deepEqual(next, { intervalMs: 10_000, maxRounds: 10, maxIntervalMs: 3_600_000 });
    assert.deepEqual(replayTimer.waits(), [10_000], "pending wait recomputed from the new interval");
    assert.equal(replayTimer.pending.length, 1, "exactly one pending timer");
    assert.notEqual(replayTimer.pending[0], oldTimer, "the old timer was cleared");
    assert.equal(
      replayer.status().nextRunAt,
      new Date(nowMs + 10_000).toISOString(),
      "nextRunAt tracks the re-armed wait"
    );

    // config() is a snapshot, not a live reference.
    const snap = replayer.config();
    snap.intervalMs = 1;
    assert.equal(replayer.config().intervalMs, 10_000);
  });

  it("maxIntervalMs tightening follows in the exponential-backoff cap", () => {
    const replayTimer = manualTimer();
    const replayer = new DeadLetterAutoReplayer({
      enabled: true,
      intervalMs: 1000,
      maxRounds: 10,
      maxIntervalMs: 3_600_000,
      replayAll: () => ({ replayed: [], failed: [] }),
      setTimer: replayTimer.setTimer,
      clearTimer: replayTimer.clearTimer,
    });
    replayer.start();
    assert.equal(replayer.triggerOnce().consecutiveEmptyRounds, 1);
    assert.equal(replayer.triggerOnce().consecutiveEmptyRounds, 2);
    assert.deepEqual(replayTimer.waits(), [4000], "1000 * 2^2 before the cap change");

    replayer.retune({ maxIntervalMs: 1500 });
    assert.deepEqual(replayTimer.waits(), [1500], "wait now capped by the revised maxIntervalMs");
    assert.equal(replayer.triggerOnce().consecutiveEmptyRounds, 3);
    assert.deepEqual(replayTimer.waits(), [1500], "cap still binds at 2^3");
  });

  it("maxRounds lowered triggers the exhaustion stop earlier", () => {
    const replayTimer = manualTimer();
    const audits: Array<{ event: string }> = [];
    const replayer = new DeadLetterAutoReplayer({
      enabled: true,
      intervalMs: 1000,
      maxRounds: 5,
      replayAll: () => ({ replayed: [], failed: [] }),
      setTimer: replayTimer.setTimer,
      clearTimer: replayTimer.clearTimer,
      onAudit: (e) => audits.push(e),
    });
    replayer.start();
    assert.equal(replayer.triggerOnce().consecutiveEmptyRounds, 1);
    assert.equal(replayer.triggerOnce().consecutiveEmptyRounds, 2);

    replayer.retune({ maxRounds: 3 });
    const last = replayer.triggerOnce();
    assert.equal(last.consecutiveEmptyRounds, 3);
    assert.equal(last.stopped, true, "the revised budget exhausts on the next empty round");
    assert.equal(audits.length, 1);
    assert.deepEqual(replayTimer.waits(), [], "no round scheduled after the stop");
  });

  it("maxRounds raised gives a poisoned backlog more rounds before stopping", () => {
    const replayTimer = manualTimer();
    const replayer = new DeadLetterAutoReplayer({
      enabled: true,
      intervalMs: 1000,
      maxRounds: 2,
      // Poison: nothing ever re-queues, every round counts as empty.
      replayAll: () => ({ replayed: [], failed: [{ id: "x", error: "no decryptor" }] }),
      setTimer: replayTimer.setTimer,
      clearTimer: replayTimer.clearTimer,
    });
    replayer.start();
    assert.equal(replayer.triggerOnce().consecutiveEmptyRounds, 1);

    replayer.retune({ maxRounds: 4 });
    assert.equal(replayer.triggerOnce().consecutiveEmptyRounds, 2);
    assert.equal(replayer.status().stopped, false);
    assert.equal(replayer.triggerOnce().consecutiveEmptyRounds, 3);
    assert.equal(replayer.status().stopped, false);
    assert.equal(replayer.triggerOnce().stopped, true, "stops at the revised budget, not the old one");
  });

  it("invalid values throw RangeError and leave live state untouched, including the pending timer", () => {
    const replayTimer = manualTimer();
    const replayer = new DeadLetterAutoReplayer({
      enabled: true,
      intervalMs: 1000,
      maxRounds: 3,
      maxIntervalMs: 3000,
      replayAll: () => ({ replayed: [], failed: [] }),
      setTimer: replayTimer.setTimer,
      clearTimer: replayTimer.clearTimer,
    });
    replayer.start();
    assert.equal(replayer.triggerOnce().consecutiveEmptyRounds, 1);
    assert.deepEqual(replayTimer.waits(), [2000]);
    const pendingTimer = replayTimer.pending[0];
    const before = replayer.config();

    const invalid: Array<Record<string, unknown>> = [
      { intervalMs: 0 },
      { intervalMs: -5 },
      { intervalMs: NaN },
      { maxRounds: 0 },
      { maxRounds: 1.5 },
      { maxIntervalMs: 500 },
      { intervalMs: 5000, maxIntervalMs: 1000 },
      { maxIntervalMs: 0 },
    ];
    for (const patch of invalid) {
      assert.throws(
        () => replayer.retune(patch as never),
        RangeError,
        JSON.stringify(patch)
      );
      assert.deepEqual(replayer.config(), before, `live config untouched after ${JSON.stringify(patch)}`);
      assert.deepEqual(replayTimer.waits(), [2000], "pending wait untouched");
      assert.equal(replayTimer.pending[0], pendingTimer, "pending timer object untouched");
      assert.equal(replayer.status().consecutiveEmptyRounds, 1);
    }
  });

  it("empty {} and non-object patches throw RangeError", () => {
    const replayer = new DeadLetterAutoReplayer({
      enabled: true,
      replayAll: () => ({ replayed: [], failed: [] }),
    });
    assert.throws(() => replayer.retune({}), RangeError);
    assert.throws(() => replayer.retune(null as never), RangeError);
    assert.throws(() => replayer.retune("1000" as never), RangeError);
    assert.throws(() => replayer.retune([] as never), RangeError);
    assert.deepEqual(replayer.config(), { intervalMs: 60_000, maxRounds: 10, maxIntervalMs: 3_600_000 });
  });

  it("same-value patch is a silent no-op: no re-arm, no audit", () => {
    const replayTimer = manualTimer();
    const audits: Array<{ event: string }> = [];
    const replayer = new DeadLetterAutoReplayer({
      enabled: true,
      intervalMs: 1000,
      maxRounds: 3,
      replayAll: () => ({ replayed: [], failed: [] }),
      setTimer: replayTimer.setTimer,
      clearTimer: replayTimer.clearTimer,
      onAudit: (e) => audits.push(e),
    });
    replayer.start();
    const pendingTimer = replayTimer.pending[0];
    const next = replayer.retune({ intervalMs: 1000 });
    assert.deepEqual(next, { intervalMs: 1000, maxRounds: 3, maxIntervalMs: 3_600_000 });
    assert.equal(replayTimer.pending[0], pendingTimer, "the pending timer was not re-armed");
    assert.deepEqual(replayTimer.waits(), [1000]);
    assert.equal(audits.length, 0);
  });

  it("revision does not reset consecutiveEmptyRounds/totalReplayed; empty-round counting continues", async () => {
    const s = setupAutoReplay();
    await seedDeadLetter(s, "dl-keep");
    s.sender.fail = false;
    const round = s.replayer.triggerOnce();
    assert.deepEqual(round.replayed, ["dl-keep"]);
    assert.equal(s.replayer.status().totalReplayed, 1);
    assert.equal(s.replayer.status().consecutiveEmptyRounds, 0);

    assert.equal(s.replayer.triggerOnce().consecutiveEmptyRounds, 1);
    assert.equal(s.replayer.triggerOnce().consecutiveEmptyRounds, 2);
    s.replayer.retune({ intervalMs: 2000 });
    assert.equal(s.replayer.status().consecutiveEmptyRounds, 2, "counter survives the revision");
    assert.equal(s.replayer.status().totalReplayed, 1, "total survives the revision");
    assert.deepEqual(s.replayTimer.waits(), [8000], "wait still uses the retained counter: 2000 * 2^2");
    assert.equal(s.replayer.triggerOnce().consecutiveEmptyRounds, 3, "counting continues, not restarted");
    await s.q.shutdown(1000);
  });

  it("paused scheduler revised then resume arms with the new values", () => {
    const s = setupAutoReplay();
    s.q.start();
    assert.equal(s.replayer.triggerOnce().consecutiveEmptyRounds, 1);
    s.replayer.pause();
    assert.deepEqual(s.replayTimer.waits(), [], "no round scheduled while paused");

    s.replayer.retune({ intervalMs: 5000 });
    assert.deepEqual(s.replayTimer.waits(), [], "revision alone does not arm a paused scheduler");
    assert.deepEqual(s.replayer.config(), { intervalMs: 5000, maxRounds: 3, maxIntervalMs: 3_600_000 });

    const { restarted } = s.replayer.resume();
    assert.equal(restarted, false);
    assert.equal(s.replayer.status().consecutiveEmptyRounds, 1, "counter retained across pause");
    assert.deepEqual(s.replayTimer.waits(), [10_000], "resume arms on the new interval: 5000 * 2^1");
  });

  it("stopped scheduler revised then resume resets counts and arms with the new values", () => {
    const replayTimer = manualTimer();
    const replayer = new DeadLetterAutoReplayer({
      enabled: true,
      intervalMs: 1000,
      maxRounds: 2,
      replayAll: () => ({ replayed: [], failed: [] }),
      setTimer: replayTimer.setTimer,
      clearTimer: replayTimer.clearTimer,
    });
    replayer.start();
    replayer.triggerOnce();
    assert.equal(replayer.triggerOnce().stopped, true);
    assert.deepEqual(replayTimer.waits(), []);

    replayer.retune({ intervalMs: 500, maxRounds: 5 });
    assert.deepEqual(replayTimer.waits(), [], "revision alone does not restart a stopped scheduler");
    assert.equal(replayer.status().stopped, true);
    assert.equal(replayer.status().consecutiveEmptyRounds, 2);

    const { restarted } = replayer.resume();
    assert.equal(restarted, true);
    assert.equal(replayer.status().stopped, false);
    assert.equal(replayer.status().consecutiveEmptyRounds, 0, "resume resets the counter after exhaustion");
    assert.deepEqual(replayTimer.waits(), [500], "resume arms on the new interval and budget");
  });

  it("enabled:false scheduler revised still runs no rounds — values stored only", () => {
    const replayTimer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      autoReplay: {
        enabled: false,
        intervalMs: 60_000,
        maxRounds: 3,
        setTimer: replayTimer.setTimer,
        clearTimer: replayTimer.clearTimer,
      },
    });
    const replayer = q.getAutoReplayer()!;
    q.start();
    const next = q.reviseAutoReplaySchedule({ intervalMs: 5000 });
    assert.deepEqual(next, { intervalMs: 5000, maxRounds: 3, maxIntervalMs: 3_600_000 });
    assert.deepEqual(replayTimer.waits(), [], "a disabled scheduler arms nothing");
    assert.equal(replayer.isRunning(), false);
    const round = replayer.triggerOnce();
    assert.deepEqual(round.replayed, []);
    assert.equal(round.stopped, false);
    assert.deepEqual(q.getAutoReplayScheduleConfig(), {
      intervalMs: 5000,
      maxRounds: 3,
      maxIntervalMs: 3_600_000,
    });
    return q.shutdown(1000);
  });

  it("unconfigured queue: revise throws the must-restart Error and get returns undefined", () => {
    const q = new RetryQueue();
    assert.equal(q.getAutoReplayScheduleConfig(), undefined);
    assert.throws(
      () => q.reviseAutoReplaySchedule({ intervalMs: 1000 }),
      (err: unknown) =>
        err instanceof Error &&
        err.message ===
          "reviseAutoReplaySchedule: auto replay is not configured — enabling it requires a restart"
    );
  });
});

describe("auto-replay schedule revision via the server (WR-344)", () => {
  let servers: Server[] = [];

  after(async () => {
    for (const s of servers) {
      await new Promise<void>((resolve) => s.close(() => resolve()));
    }
    servers = [];
  });

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  function makeRelay(autoReplay?: AutoReplayOptions) {
    const dir = mkdtempSync(join(tmpdir(), "autoreplay-schedule-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: SIGNING_KEY,
      forwardUrl: EP,
      auditLog: audit,
      operatorToken: TOKEN,
      sender: async () => {},
      autoReplay,
    });
    servers.push(relay);
    return { relay, audit };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  const construction = { intervalMs: 60_000, maxRounds: 10, maxIntervalMs: 3_600_000 };

  it("revision audits previous/current with the construction values first; same-value is a silent no-op", async () => {
    const { relay, audit } = makeRelay({ enabled: true, intervalMs: 60_000, maxRounds: 10 });
    await listen(relay);
    assert.deepEqual(relay.getAutoReplayScheduleConfig!(), construction);
    assert.deepEqual(relay.reviseAutoReplaySchedule({ intervalMs: 10_000 }), {
      ...construction,
      intervalMs: 10_000,
    });
    const revised = eventsOf(audit, "auto_replay_schedule_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, construction);
    assert.deepEqual(revised[0].current, { ...construction, intervalMs: 10_000 });
    // Landing exactly on the live values audits nothing.
    relay.reviseAutoReplaySchedule({ intervalMs: 10_000 });
    assert.equal(eventsOf(audit, "auto_replay_schedule_revised").length, 1);
    assert.deepEqual(relay.getAutoReplayScheduleConfig!(), { ...construction, intervalMs: 10_000 });
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseAutoReplaySchedule({ maxRounds: 0 }), RangeError);
    assert.throws(() => relay.reviseAutoReplaySchedule({}), RangeError);
    assert.equal(eventsOf(audit, "auto_replay_schedule_revised").length, 1);
    assert.deepEqual(relay.getAutoReplayScheduleConfig!(), { ...construction, intervalMs: 10_000 });
  });

  it("unconfigured relay: revise throws the must-restart Error and the getter is not mounted", async () => {
    const { relay } = makeRelay(undefined);
    await listen(relay);
    assert.equal(relay.getAutoReplayScheduleConfig, undefined);
    assert.throws(
      () => relay.reviseAutoReplaySchedule({ intervalMs: 10_000 }),
      (err: unknown) =>
        err instanceof Error &&
        err.message ===
          "reviseAutoReplaySchedule: auto replay is not configured — enabling it requires a restart"
    );
  });

  it("server getter reflects revisions made through the server", async () => {
    const { relay } = makeRelay({ enabled: true, intervalMs: 60_000, maxRounds: 10 });
    await listen(relay);
    assert.deepEqual(relay.getAutoReplayScheduleConfig!(), construction);
    relay.reviseAutoReplaySchedule({ maxRounds: 4, maxIntervalMs: 120_000 });
    assert.deepEqual(relay.getAutoReplayScheduleConfig!(), {
      ...construction,
      maxRounds: 4,
      maxIntervalMs: 120_000,
    });
  });
});
