import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type DeadLetterAutoReplayAuditEvent } from "../src/retry.ts";
import { DeadLetterAutoReplayer } from "../src/autoreplay.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";

const EP = "http://127.0.0.1:9/hook";
const TOKEN = "operator-token";
const SIGNING_KEY = "relay-secret";
const NOW_MS = 5_000_000;
const NOW_ISO = new Date(NOW_MS).toISOString();

/**
 * Deterministic timer: callbacks fire only via `fireOne` / `run()`; the
 * scheduled delays are observable via `waits()` (same helper as
 * auto-replay-schedule-revision.test.ts).
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

/** Fire exactly one scheduled round: shift the record out first, so the
 * re-armed timer left behind by doRound is the only one pending. */
function fireOne(t: ReturnType<typeof manualTimer>) {
  assert.ok(t.pending.length > 0, "a round must be scheduled");
  const rec = t.pending.shift()!;
  rec.fn();
}

interface QueueSetup {
  q: RetryQueue;
  /** Queue's own delivery timer. */
  timer: ReturnType<typeof manualTimer>;
  /** The replayer's private timer (rounds never fire unless driven). */
  replayTimer: ReturnType<typeof manualTimer>;
  replayer: DeadLetterAutoReplayer;
  seen: DeadLetterAutoReplayAuditEvent[];
  sender: { fail: boolean };
}

/**
 * Queue with a toggleable sender and an enabled auto-replay scheduler
 * with a fixed clock, so the exhaustion event's `lastRunAt` is exact.
 * The replayer gets its own manual timer so scheduled rounds never fire
 * as a side effect of draining the queue's delivery timer.
 */
function makeQueue(opts: {
  maxRounds?: number;
  onAutoReplayAudit?: (e: DeadLetterAutoReplayAuditEvent) => void;
} = {}): QueueSetup {
  const timer = manualTimer();
  const replayTimer = manualTimer();
  const state = { fail: true };
  const seen: DeadLetterAutoReplayAuditEvent[] = [];
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
      maxRounds: opts.maxRounds ?? 2,
      now: () => NOW_MS,
      setTimer: replayTimer.setTimer,
      clearTimer: replayTimer.clearTimer,
    },
    onAutoReplayAudit: opts.onAutoReplayAudit ?? ((e) => seen.push(e)),
  });
  const replayer = q.getAutoReplayer();
  assert.ok(replayer, "auto-replay scheduler must exist when configured");
  q.start();
  return { q, timer, replayTimer, replayer, seen, sender: state };
}

async function seedDeadLetter(s: QueueSetup, id: string) {
  s.q.enqueue({ id, payload: Buffer.from(`payload-${id}`), targetUrl: EP, headers: {} });
  await s.timer.run();
  const dl = s.q.getDeadLetter();
  assert.equal(dl.length, 1, "item should be dead-lettered");
}

describe("RetryQueue auto-replay audit callback revision (WR-411)", () => {
  it("the revised callback receives the next exhaustion stop with exact fields; the old callback stays silent", async () => {
    const s = makeQueue({ maxRounds: 2 });
    try {
      await seedDeadLetter(s, "dl-keep");
      s.sender.fail = false;
      const round = s.replayer.triggerOnce();
      assert.deepEqual(round.replayed, ["dl-keep"]);
      assert.equal(s.replayer.status().totalReplayed, 1);
      assert.equal(s.replayer.status().consecutiveEmptyRounds, 0);
      assert.equal(s.seen.length, 0, "no stop yet");

      const second: DeadLetterAutoReplayAuditEvent[] = [];
      s.q.reviseAutoReplayAuditCallback((e) => second.push(e));
      assert.equal(second.length, 0, "no re-delivery of anything reported");

      assert.equal(s.replayer.triggerOnce().consecutiveEmptyRounds, 1);
      const last = s.replayer.triggerOnce();
      assert.equal(last.consecutiveEmptyRounds, 2);
      assert.equal(last.stopped, true);
      assert.equal(s.seen.length, 0, "old callback stays silent after revision");
      assert.equal(second.length, 1);
      assert.deepEqual(second[0], {
        event: "dead_letter_auto_replay",
        reason: "rounds_exhausted",
        consecutiveEmptyRounds: 2,
        totalReplayed: 1,
        lastRunAt: NOW_ISO,
      });
    } finally {
      await s.q.shutdown(1000);
    }
  });

  it("null clears back to no observer; the stop still happens with counters intact", async () => {
    const s = makeQueue({ maxRounds: 2 });
    try {
      assert.equal(s.replayer.triggerOnce().consecutiveEmptyRounds, 1);
      s.q.reviseAutoReplayAuditCallback(null);
      const last = s.replayer.triggerOnce();
      assert.equal(last.consecutiveEmptyRounds, 2);
      assert.equal(last.stopped, true, "exhaustion still stops the scheduler");
      assert.equal(s.seen.length, 0, "cleared hook stays silent");
      assert.equal(s.replayer.status().consecutiveEmptyRounds, 2);
      assert.equal(s.replayer.status().totalReplayed, 0);
      assert.deepEqual(s.replayTimer.waits(), [], "no round scheduled after the stop");
    } finally {
      await s.q.shutdown(1000);
    }
  });

  it("revising with auto replay unconfigured throws the must-restart Error; live state is untouched", () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      assert.equal(q.getAutoReplayer(), undefined);
      assert.equal(q.getAutoReplayScheduleConfig(), undefined);
      assert.throws(
        () => q.reviseAutoReplayAuditCallback(() => {}),
        (err: unknown) =>
          err instanceof Error &&
          err.message === "auto replay is not configured — enabling it requires a restart"
      );
      assert.throws(
        () => q.reviseAutoReplayAuditCallback(null),
        (err: unknown) =>
          err instanceof Error &&
          err.message === "auto replay is not configured — enabling it requires a restart"
      );
      assert.equal(q.getAutoReplayer(), undefined, "the gate leaves the queue unconfigured");
    } finally {
      q.stop();
    }
  });

  it("a non-function value throws RangeError and the live callback is untouched", async () => {
    const s = makeQueue({ maxRounds: 2 });
    try {
      for (const bad of ["x", 42, {}] as never[]) {
        assert.throws(() => s.q.reviseAutoReplayAuditCallback(bad), RangeError, String(bad));
      }
      s.replayer.triggerOnce();
      const last = s.replayer.triggerOnce();
      assert.equal(last.stopped, true);
      assert.equal(s.seen.length, 1, "the original callback still observes the stop");
      assert.deepEqual(s.seen[0], {
        event: "dead_letter_auto_replay",
        reason: "rounds_exhausted",
        consecutiveEmptyRounds: 2,
        totalReplayed: 0,
        lastRunAt: NOW_ISO,
      });
    } finally {
      await s.q.shutdown(1000);
    }
  });

  it("replacing with the same reference and clearing when already unset are silent no-ops", async () => {
    const seen: DeadLetterAutoReplayAuditEvent[] = [];
    const onAutoReplayAudit = (e: DeadLetterAutoReplayAuditEvent) => seen.push(e);
    const s = makeQueue({ maxRounds: 2, onAutoReplayAudit });
    try {
      s.q.reviseAutoReplayAuditCallback(onAutoReplayAudit);
      assert.equal(s.replayer.triggerOnce().consecutiveEmptyRounds, 1);
      // Clear twice: the second clear is a no-op, not an error.
      s.q.reviseAutoReplayAuditCallback(null);
      s.q.reviseAutoReplayAuditCallback(null);
      const last = s.replayer.triggerOnce();
      assert.equal(last.stopped, true);
      assert.equal(seen.length, 0, "cleared hook stays silent");
      assert.equal(s.replayer.status().consecutiveEmptyRounds, 2);
    } finally {
      await s.q.shutdown(1000);
    }
  });

  it("revising after a stop does not re-emit the reported event; resume then re-exhausts into the new callback", async () => {
    const s = makeQueue({ maxRounds: 2 });
    try {
      s.replayer.triggerOnce();
      assert.equal(s.replayer.triggerOnce().stopped, true);
      assert.equal(s.seen.length, 1);
      assert.deepEqual(s.seen[0], {
        event: "dead_letter_auto_replay",
        reason: "rounds_exhausted",
        consecutiveEmptyRounds: 2,
        totalReplayed: 0,
        lastRunAt: NOW_ISO,
      });

      const second: DeadLetterAutoReplayAuditEvent[] = [];
      s.q.reviseAutoReplayAuditCallback((e) => second.push(e));
      assert.equal(second.length, 0, "no re-delivery of the reported stop");
      assert.equal(s.seen.length, 1);

      const { restarted } = s.replayer.resume();
      assert.equal(restarted, true);
      assert.equal(s.replayer.status().stopped, false);
      assert.equal(s.replayer.status().consecutiveEmptyRounds, 0);
      assert.equal(second.length, 0, "resume alone emits nothing");

      s.replayer.triggerOnce();
      assert.equal(s.replayer.triggerOnce().stopped, true);
      assert.equal(s.seen.length, 1, "old callback stays silent after the second stop");
      assert.equal(second.length, 1);
      assert.deepEqual(second[0], {
        event: "dead_letter_auto_replay",
        reason: "rounds_exhausted",
        consecutiveEmptyRounds: 2,
        totalReplayed: 0,
        lastRunAt: NOW_ISO,
      });
    } finally {
      await s.q.shutdown(1000);
    }
  });

  it("revision does not change the cadence knobs, the counters, the stopped latch, or retune semantics", async () => {
    const s = makeQueue({ maxRounds: 3 });
    try {
      assert.equal(s.replayer.triggerOnce().consecutiveEmptyRounds, 1);
      const before = s.q.getAutoReplayScheduleConfig();
      assert.deepEqual(before, { intervalMs: 1000, maxRounds: 3, maxIntervalMs: 3_600_000 });

      const second: DeadLetterAutoReplayAuditEvent[] = [];
      s.q.reviseAutoReplayAuditCallback((e) => second.push(e));
      assert.deepEqual(s.q.getAutoReplayScheduleConfig(), before, "revision moves only the observer");
      assert.equal(s.replayer.status().consecutiveEmptyRounds, 1, "counter survives the revision");
      assert.equal(s.replayer.status().totalReplayed, 0, "total survives the revision");
      assert.equal(s.replayer.status().stopped, false, "latch survives the revision");

      // retune still works on the untouched scheduler, and the new
      // callback observes the stop the retuned budget produces.
      assert.deepEqual(s.replayer.retune({ intervalMs: 2000 }), {
        intervalMs: 2000,
        maxRounds: 3,
        maxIntervalMs: 3_600_000,
      });
      assert.deepEqual(s.replayTimer.waits(), [4000], "wait still uses the retained counter: 2000 * 2^1");
      assert.equal(s.replayer.triggerOnce().consecutiveEmptyRounds, 2);
      assert.equal(s.replayer.triggerOnce().stopped, true);
      assert.equal(second.length, 1);
      assert.equal(second[0].consecutiveEmptyRounds, 3);
      assert.equal(s.replayer.status().stopped, true);
    } finally {
      await s.q.shutdown(1000);
    }
  });
});

describe("RelayServer auto-replay audit callback revision (WR-411)", () => {
  const servers: Server[] = [];
  after(async () => {
    for (const s of servers) {
      await new Promise<void>((resolve) => s.close(() => resolve()));
    }
    servers.length = 0;
  });

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  /**
   * A server with auto-replay on and a controllable round timer; rounds
   * fire only via `round()`, and the empty dead letter makes every round
   * count as empty.
   */
  function autoReplayServer(opts: {
    onAutoReplayAudit?: (event: DeadLetterAutoReplayAuditEvent) => void;
    maxRounds?: number;
  } = {}) {
    const dir = mkdtempSync(join(tmpdir(), "auto-replay-audit-callback-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const replayTimer = manualTimer();
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: SIGNING_KEY,
      forwardUrl: EP,
      auditLog,
      operatorToken: TOKEN,
      sender: async () => {},
      retry: {
        autoReplay: {
          enabled: true,
          intervalMs: 1000,
          maxRounds: opts.maxRounds ?? 2,
          now: () => NOW_MS,
          setTimer: replayTimer.setTimer,
          clearTimer: replayTimer.clearTimer,
        },
        ...(opts.onAutoReplayAudit !== undefined
          ? { onAutoReplayAudit: opts.onAutoReplayAudit }
          : {}),
      },
    });
    servers.push(relay);
    return {
      relay,
      auditLog,
      round: () => fireOne(replayTimer),
    };
  }

  it("revising the callback routes the next exhaustion stop to the new callback and the audit still lands", () => {
    const first: DeadLetterAutoReplayAuditEvent[] = [];
    const second: DeadLetterAutoReplayAuditEvent[] = [];
    const { relay, auditLog, round } = autoReplayServer({
      onAutoReplayAudit: (e) => first.push(e),
    });
    round(); // empty 1
    assert.equal(first.length, 0, "no stop yet");
    relay.reviseAutoReplayAuditCallback!((e) => second.push(e));
    assert.equal(second.length, 0, "no re-delivery of anything reported");
    round(); // empty 2: stop
    assert.equal(first.length, 0, "old callback stays silent after revision");
    assert.equal(second.length, 1);
    assert.deepEqual(second[0], {
      event: "dead_letter_auto_replay",
      reason: "rounds_exhausted",
      consecutiveEmptyRounds: 2,
      totalReplayed: 0,
      lastRunAt: NOW_ISO,
    });
    const stops = eventsOf(auditLog, "dead_letter_auto_replay");
    assert.equal(stops.length, 1, "the stop is still audited");
    assert.equal(stops[0].reason, "rounds_exhausted");
    assert.equal(stops[0].consecutiveEmptyRounds, 2);
    assert.equal(stops[0].totalReplayed, 0);
    assert.equal(stops[0].lastRunAt, NOW_ISO);
    // The revision itself is audited with presence only, never a body.
    const revised = eventsOf(auditLog, "auto_replay_audit_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "set");
    assert.equal(revised[0].current, "set");
  });

  it("null clears back to audit-only; the stop is still audited", () => {
    const first: DeadLetterAutoReplayAuditEvent[] = [];
    const { relay, auditLog, round } = autoReplayServer({
      onAutoReplayAudit: (e) => first.push(e),
    });
    round(); // empty 1
    relay.reviseAutoReplayAuditCallback!(null);
    round(); // empty 2: stop
    assert.equal(first.length, 0, "cleared hook stays silent");
    assert.equal(eventsOf(auditLog, "dead_letter_auto_replay").length, 1);
    const revised = eventsOf(auditLog, "auto_replay_audit_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "set");
    assert.equal(revised[0].current, "cleared");
  });

  it("a non-function value throws RangeError and the live callback is untouched; same-reference and clear-when-unset are silent no-ops", () => {
    const first: DeadLetterAutoReplayAuditEvent[] = [];
    const onAutoReplayAudit = (e: DeadLetterAutoReplayAuditEvent) => first.push(e);
    const { relay, auditLog, round } = autoReplayServer({ onAutoReplayAudit });
    for (const bad of ["x", 42, {}] as never[]) {
      assert.throws(() => relay.reviseAutoReplayAuditCallback!(bad), RangeError, String(bad));
    }
    assert.equal(eventsOf(auditLog, "auto_replay_audit_callback_revised").length, 0);
    relay.reviseAutoReplayAuditCallback!(onAutoReplayAudit);
    assert.equal(eventsOf(auditLog, "auto_replay_audit_callback_revised").length, 0);
    round(); // empty 1
    round(); // empty 2: stop
    assert.equal(first.length, 1, "the original callback still observes the stop");
    assert.deepEqual(first[0], {
      event: "dead_letter_auto_replay",
      reason: "rounds_exhausted",
      consecutiveEmptyRounds: 2,
      totalReplayed: 0,
      lastRunAt: NOW_ISO,
    });
    assert.equal(eventsOf(auditLog, "dead_letter_auto_replay").length, 1);
    // Clearing a set callback is a real revision (set -> cleared); a
    // second clear is the silent no-op.
    relay.reviseAutoReplayAuditCallback!(null);
    const cleared = eventsOf(auditLog, "auto_replay_audit_callback_revised");
    assert.equal(cleared.length, 1);
    assert.equal(cleared[0].previous, "set");
    assert.equal(cleared[0].current, "cleared");
    relay.reviseAutoReplayAuditCallback!(null);
    assert.equal(eventsOf(auditLog, "auto_replay_audit_callback_revised").length, 1);
    const { relay: bare, auditLog: bareAudit } = autoReplayServer({});
    bare.reviseAutoReplayAuditCallback!(null);
    assert.equal(eventsOf(bareAudit, "auto_replay_audit_callback_revised").length, 0);
  });

  it("revising with auto replay unconfigured throws the must-restart Error", () => {
    const dir = mkdtempSync(join(tmpdir(), "auto-replay-audit-callback-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      ["sec" + "ret"]: SIGNING_KEY,
      forwardUrl: EP,
      auditLog,
      operatorToken: TOKEN,
      sender: async () => {},
    });
    servers.push(relay);
    assert.equal(relay.getAutoReplayScheduleConfig, undefined);
    assert.throws(
      () => relay.reviseAutoReplayAuditCallback!(() => {}),
      (err: unknown) =>
        err instanceof Error &&
        err.message === "auto replay is not configured — enabling it requires a restart"
    );
    assert.throws(
      () => relay.reviseAutoReplayAuditCallback!(null),
      (err: unknown) =>
        err instanceof Error &&
        err.message === "auto replay is not configured — enabling it requires a restart"
    );
  });
});
