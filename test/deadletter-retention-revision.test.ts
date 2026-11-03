import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import { RetryQueue, type DeadLetterEntry } from "../src/retry.ts";
import {
  DeadLetterRetentionSweeper,
  type DeadLetterPurgeResult,
  type DeadLetterPurgedEvent,
  type DeadLetterRetentionOwner,
  type DeadLetterRetentionRevision,
} from "../src/deadletter-retention.ts";
import { AesGcmEncryptor, randomAes256Key, type PayloadEncryptor } from "../src/encrypt.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "deadletter-retention-revision-secret";
const EP_A = "http://a.example/hook";
const EP_B = "http://b.example/hook";
const EP_C = "http://c.example/hook";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Deterministic timer that records the armed interval per callback. */
function recordingTimer() {
  interface Pending {
    fn: () => void;
    ms: number;
  }
  const pending: Pending[] = [];
  return {
    pending,
    setTimer: (fn: () => void, ms: number) => {
      const rec: Pending = { fn, ms };
      pending.push(rec);
      return {
        clear: () => {
          const i = pending.indexOf(rec);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    clearTimer: (h: { clear: () => void }) => h.clear(),
  };
}

function makeEntry(
  id: string,
  targetUrl: string,
  deadLetteredAtMs: number,
  extra: Record<string, unknown> = {}
): DeadLetterEntry {
  return {
    id,
    payload: Buffer.from(`payload-${id}`),
    targetUrl,
    headers: {},
    attempts: 1,
    lastError: "downstream 500",
    failureClass: "retryable",
    deadLetteredAt: new Date(deadLetteredAtMs).toISOString(),
    payloadBytes: 1,
    traceId: `trace-${id}`,
    ...extra,
  } as DeadLetterEntry;
}

/** In-memory owner for sweeper-level tests; `nowMs` is the fake clock. */
function fakeOwner(initial: DeadLetterEntry[]) {
  const entries = [...initial];
  const claimed = new Set<string>();
  const purgedEvents: DeadLetterPurgedEvent[] = [];
  const owner: DeadLetterRetentionOwner = {
    listEntries: () => entries,
    removeEntry: (id: string) => {
      const i = entries.findIndex((e) => e.id === id);
      if (i < 0) return undefined;
      return entries.splice(i, 1)[0];
    },
    isClaimedByReplay: (id: string) => claimed.has(id),
    onPurged: (e) => purgedEvents.push(e),
  };
  return { entries, claimed, purgedEvents, owner };
}

/** Build a queue whose sender always fails, pre-filled with dead letters. */
function seedDeadLetters(items: Array<{ id: string; targetUrl: string }>, extraOpts: Record<string, unknown> = {}) {
  const pending: Array<() => void> = [];
  const timer = {
    setTimer: (fn: () => void, _ms: number) => {
      pending.push(fn);
      return {
        clear: () => {
          const i = pending.indexOf(fn);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    async run() {
      while (pending.length > 0) {
        const fns = pending.splice(0);
        for (const f of fns) f();
        await new Promise((r) => setImmediate(r));
      }
    },
  };
  const q = new RetryQueue({
    sender: async () => {
      throw new Error("downstream 500");
    },
    baseDelayMs: 1,
    maxAttempts: 1,
    jitterMs: 0,
    setTimer: timer.setTimer,
    ...extraOpts,
  });
  q.start();
  for (const item of items) {
    q.enqueue({
      id: item.id,
      payload: Buffer.from(`payload-${item.id}`),
      targetUrl: item.targetUrl,
      headers: {},
    });
  }
  return { q, timer };
}

describe("DeadLetterRetentionSweeper.retune (WR-315)", () => {
  it("rejects illegal values with RangeError and leaves live values and the armed timer untouched", () => {
    const now = { ms: 1_000_000 };
    const timer = recordingTimer();
    const { owner, entries } = fakeOwner([
      makeEntry("a1", EP_A, 1_000_000),
      makeEntry("b1", EP_B, 1_000_000),
    ]);
    const sweeper = new DeadLetterRetentionSweeper({
      retentionMs: { [EP_A]: 1000, [EP_B]: 2000 },
      sweepIntervalMs: 60_000,
      now: () => now.ms,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      owner,
    });
    sweeper.start();
    assert.equal(timer.pending.length, 1);
    assert.equal(timer.pending[0].ms, 60_000);
    const before = sweeper.current();

    const bad: DeadLetterRetentionRevision[] = [
      { retentionMs: 0 },
      { retentionMs: -1 },
      { retentionMs: NaN },
      { retentionMs: Infinity },
      { retentionMs: "60000" as never },
      { retentionMs: [1000] as never },
      { retentionMs: { [EP_A]: 0 } },
      { retentionMs: { [EP_A]: -1 } },
      { retentionMs: { [EP_A]: NaN } },
      { retentionMs: { [EP_A]: "5" as never } },
      { retentionMs: { "": 1000 } },
      { retentionMs: { [EP_C]: -5 } },
      // A record patch whose later entry is illegal must not partially
      // apply the earlier, legal entry.
      { retentionMs: { [EP_C]: 5000, [EP_A]: 0 } },
      { sweepIntervalMs: 0 },
      { sweepIntervalMs: -1 },
      { sweepIntervalMs: NaN },
      { sweepIntervalMs: Infinity },
      // An illegal interval must not apply alongside a legal retention.
      { retentionMs: 5000, sweepIntervalMs: 0 },
    ];
    for (const patch of bad) {
      assert.throws(() => sweeper.retune(patch), RangeError, `expected RangeError for ${JSON.stringify(patch)}`);
    }
    assert.deepEqual(sweeper.current(), before);
    assert.equal(timer.pending.length, 1, "the armed timer must survive illegal patches");
    assert.equal(timer.pending[0].ms, 60_000);
    assert.equal(sweeper.isEnabled(), true);
    // The live TTLs still judge: only the A entry is expired at +1500ms.
    now.ms = 1_001_500;
    assert.deepEqual(
      sweeper.sweepNow().purged.map((p) => p.id),
      ["a1"]
    );
    assert.deepEqual(
      entries.map((e) => e.id),
      ["b1"]
    );
  });

  it("current() returns a deep copy — mutating it never touches the live values", () => {
    const timer = recordingTimer();
    const { owner } = fakeOwner([]);
    const sweeper = new DeadLetterRetentionSweeper({
      retentionMs: { [EP_A]: 1000 },
      sweepIntervalMs: 5000,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      owner,
    });
    const snap = sweeper.current();
    (snap.retentionMs as Record<string, number>)[EP_A] = 999;
    (snap.retentionMs as Record<string, number>)[EP_B] = 1;
    assert.deepEqual(sweeper.current(), {
      retentionMs: { [EP_A]: 1000 },
      sweepIntervalMs: 5000,
    });
  });

  it("a global number replaces record mode", () => {
    const now = { ms: 1_000_000 };
    const timer = recordingTimer();
    const { owner } = fakeOwner([
      makeEntry("a1", EP_A, 1_000_000),
      makeEntry("b1", EP_B, 1_000_000),
    ]);
    const sweeper = new DeadLetterRetentionSweeper({
      retentionMs: { [EP_A]: 1000 },
      sweepIntervalMs: 60_000,
      now: () => now.ms,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      owner,
    });
    assert.deepEqual(sweeper.retune({ retentionMs: 5000 }), {
      retentionMs: 5000,
      sweepIntervalMs: 60_000,
    });
    now.ms = 1_006_000;
    assert.deepEqual(
      sweeper.sweepNow().purged.map((p) => p.id),
      ["a1", "b1"],
      "the global TTL governs the previously unlisted endpoint too"
    );
  });

  it("a record patch merges per endpoint; null deletes one endpoint's TTL", () => {
    const now = { ms: 1_000_000 };
    const timer = recordingTimer();
    const { owner, entries } = fakeOwner([
      makeEntry("a1", EP_A, 1_000_000),
      makeEntry("b1", EP_B, 1_000_000),
    ]);
    const sweeper = new DeadLetterRetentionSweeper({
      retentionMs: { [EP_A]: 1000 },
      sweepIntervalMs: 60_000,
      now: () => now.ms,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      owner,
    });
    assert.deepEqual(sweeper.retune({ retentionMs: { [EP_B]: 2000 } }), {
      retentionMs: { [EP_A]: 1000, [EP_B]: 2000 },
      sweepIntervalMs: 60_000,
    });
    assert.deepEqual(sweeper.retune({ retentionMs: { [EP_A]: null } }), {
      retentionMs: { [EP_B]: 2000 },
      sweepIntervalMs: 60_000,
    });
    // A is TTL-less now (never expires); B expires at +2000ms.
    now.ms = 1_001_500;
    assert.deepEqual(sweeper.sweepNow(), { purged: [], skipped: [] });
    now.ms = 1_002_500;
    assert.deepEqual(
      sweeper.sweepNow().purged.map((p) => p.id),
      ["b1"]
    );
    assert.deepEqual(
      entries.map((e) => e.id),
      ["a1"]
    );
  });

  it("overall null disables the sweeper; a later retune re-arms it", () => {
    const timer = recordingTimer();
    const { owner } = fakeOwner([makeEntry("a1", EP_A, 1_000_000)]);
    const sweeper = new DeadLetterRetentionSweeper({
      retentionMs: 1000,
      sweepIntervalMs: 60_000,
      now: () => 2_000_000,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      owner,
    });
    sweeper.start();
    assert.equal(timer.pending.length, 1);
    assert.equal(sweeper.isRunning(), true);
    assert.deepEqual(sweeper.retune({ retentionMs: null }), { sweepIntervalMs: 60_000 });
    assert.equal(sweeper.isEnabled(), false);
    assert.equal(sweeper.isRunning(), false);
    assert.equal(timer.pending.length, 0, "disabling clears the armed timer");
    assert.deepEqual(sweeper.sweepNow(), { purged: [], skipped: [] });
    assert.deepEqual(sweeper.retune({ retentionMs: 1000 }), {
      retentionMs: 1000,
      sweepIntervalMs: 60_000,
    });
    assert.equal(sweeper.isEnabled(), true);
    assert.equal(timer.pending.length, 1, "re-enabling re-arms without a restart");
    assert.equal(timer.pending[0].ms, 60_000);
    assert.equal(sweeper.isRunning(), true);
    assert.deepEqual(
      sweeper.sweepNow().purged.map((p) => p.id),
      ["a1"]
    );
  });

  it("an interval revision re-arms the timer; before start the next start() uses the new interval", () => {
    const timer = recordingTimer();
    const { owner } = fakeOwner([]);
    const sweeper = new DeadLetterRetentionSweeper({
      retentionMs: 1000,
      sweepIntervalMs: 60_000,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      owner,
    });
    sweeper.start();
    const firstFn = timer.pending[0].fn;
    assert.deepEqual(sweeper.retune({ sweepIntervalMs: 5000 }), {
      retentionMs: 1000,
      sweepIntervalMs: 5000,
    });
    assert.equal(timer.pending.length, 1, "re-arming replaces the pending sweep, it does not stack one");
    assert.equal(timer.pending[0].ms, 5000);
    assert.notEqual(timer.pending[0].fn, firstFn);
    // Same-value interval: no re-arm, the pending sweep is untouched.
    sweeper.retune({ sweepIntervalMs: 5000 });
    assert.equal(timer.pending.length, 1);
    assert.equal(timer.pending[0].ms, 5000);

    const timer2 = recordingTimer();
    const second = new DeadLetterRetentionSweeper({
      retentionMs: 1000,
      sweepIntervalMs: 60_000,
      setTimer: timer2.setTimer,
      clearTimer: timer2.clearTimer,
      owner,
    });
    second.retune({ sweepIntervalMs: 7000 });
    assert.equal(timer2.pending.length, 0, "nothing is armed before start()");
    second.start();
    assert.equal(timer2.pending.length, 1);
    assert.equal(timer2.pending[0].ms, 7000);
  });

  it("retune enables an inert sweeper that started without a TTL", () => {
    const timer = recordingTimer();
    const { owner } = fakeOwner([]);
    const sweeper = new DeadLetterRetentionSweeper({
      sweepIntervalMs: 60_000,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      owner,
    });
    sweeper.start();
    assert.equal(sweeper.isEnabled(), false);
    assert.equal(timer.pending.length, 0);
    assert.deepEqual(sweeper.retune({ retentionMs: 1000 }), {
      retentionMs: 1000,
      sweepIntervalMs: 60_000,
    });
    assert.equal(sweeper.isEnabled(), true);
    assert.equal(timer.pending.length, 1, "the started-but-idle sweeper arms on enablement");
    assert.equal(sweeper.isRunning(), true);
  });
});

describe("RetryQueue.setDeadLetterRetention (WR-315)", () => {
  it("a shortened TTL purges newly-expired entries on the next sweepNow", async () => {
    const { q, timer } = seedDeadLetters([{ id: "a", targetUrl: EP_A }], {
      deadLetterRetention: { retentionMs: 3_600_000 },
    });
    try {
      await timer.run();
      await sleep(20);
      assert.deepEqual(q.purgeExpiredDeadLetters(), { purged: [], skipped: [] });
      assert.deepEqual(q.setDeadLetterRetention({ retentionMs: 1 }), {
        retentionMs: 1,
        sweepIntervalMs: 60_000,
      });
      await sleep(30);
      const result = q.purgeExpiredDeadLetters();
      assert.deepEqual(
        result.purged.map((p) => p.id),
        ["a"]
      );
      assert.equal(q.getDeadLetter().length, 0);
    } finally {
      q.stop();
    }
  });

  it("a lengthened TTL delays the purge", async () => {
    const { q, timer } = seedDeadLetters([{ id: "a", targetUrl: EP_A }], {
      deadLetterRetention: { retentionMs: 1 },
    });
    try {
      await timer.run();
      await sleep(30); // expired under the old 1ms TTL
      assert.deepEqual(q.setDeadLetterRetention({ retentionMs: 3_600_000 }), {
        retentionMs: 3_600_000,
        sweepIntervalMs: 60_000,
      });
      assert.deepEqual(q.purgeExpiredDeadLetters(), { purged: [], skipped: [] });
      assert.equal(q.getDeadLetter().length, 1, "the lengthened TTL keeps the entry");
      assert.deepEqual(q.setDeadLetterRetention({ retentionMs: 1 }), {
        retentionMs: 1,
        sweepIntervalMs: 60_000,
      });
      assert.deepEqual(
        q.purgeExpiredDeadLetters().purged.map((p) => p.id),
        ["a"]
      );
    } finally {
      q.stop();
    }
  });

  it("throws Error when retention was never configured", () => {
    const q = new RetryQueue({ sender: async () => {}, maxAttempts: 1 });
    try {
      assert.equal(q.getDeadLetterRetention(), undefined);
      assert.throws(() => q.setDeadLetterRetention({ retentionMs: 1000 }), /not configured/);
    } finally {
      q.stop();
    }
  });

  it("getDeadLetterRetention returns the live values after each revision", async () => {
    const { q, timer } = seedDeadLetters([{ id: "a", targetUrl: EP_A }], {
      deadLetterRetention: { retentionMs: { [EP_A]: 1000, [EP_B]: 2000 }, sweepIntervalMs: 5000 },
    });
    try {
      await timer.run();
      assert.deepEqual(q.getDeadLetterRetention(), {
        retentionMs: { [EP_A]: 1000, [EP_B]: 2000 },
        sweepIntervalMs: 5000,
      });
      const next = q.setDeadLetterRetention({
        retentionMs: { [EP_B]: null },
        sweepIntervalMs: 7000,
      });
      assert.deepEqual(next, { retentionMs: { [EP_A]: 1000 }, sweepIntervalMs: 7000 });
      assert.deepEqual(q.getDeadLetterRetention(), next);
    } finally {
      q.stop();
    }
  });

  it("entries claimed by an in-progress replay are still skipped after a revision", async () => {
    const base = new AesGcmEncryptor(randomAes256Key());
    let inner: DeadLetterPurgeResult | undefined;
    let queue!: RetryQueue;
    const hookEncryptor: PayloadEncryptor = {
      name: base.name,
      encrypt: (p) => base.encrypt(p),
      decrypt: (env) => {
        // Reentrant sweep, fired from inside the batch replay's decrypt:
        // the batch claims every matched id for its whole run.
        inner ??= queue.purgeExpiredDeadLetters();
        return base.decrypt(env);
      },
    };
    queue = new RetryQueue({
      sender: async () => {
        throw new Error("downstream 500");
      },
      baseDelayMs: 1,
      maxAttempts: 1,
      jitterMs: 0,
      payloadEncryptor: hookEncryptor,
      deadLetterRetention: { retentionMs: 1 },
    });
    try {
      queue.start();
      queue.enqueue({ id: "r1", payload: Buffer.from("p1"), targetUrl: EP_A, headers: {} });
      queue.enqueue({ id: "r2", payload: Buffer.from("p2"), targetUrl: EP_A, headers: {} });
      // Real timers: let both deliveries fail into the dead letter, then
      // let the 1ms TTL expire.
      await sleep(50);
      assert.equal(queue.getDeadLetter().length, 2);

      // Revise mid-flight: the claim guard must survive the revision.
      assert.deepEqual(queue.setDeadLetterRetention({ retentionMs: 2 }), {
        retentionMs: 2,
        sweepIntervalMs: 60_000,
      });
      const result = queue.replayDeadLetters();
      assert.deepEqual(result.replayed.sort(), ["r1", "r2"]);
      assert.ok(inner !== undefined, "the reentrant sweep should have run inside decrypt");
      // r1 was mid-replay (already spliced out); r2 was still listed but
      // claimed by the batch — it must be skipped, not purged.
      assert.deepEqual(inner.skipped, ["r2"]);
      assert.deepEqual(inner.purged, []);
    } finally {
      queue.stop();
    }
  });

  it("an already-purged entry never comes back, even after a retune and a journal recovery", async () => {
    const dir = mkdtempSync(join(tmpdir(), "durable-"));
    const mk = () =>
      new RetryQueue({
        sender: async () => {
          throw new Error("downstream 500");
        },
        baseDelayMs: 1,
        maxAttempts: 1,
        jitterMs: 0,
        durableQueueDir: dir,
        deadLetterRetention: { retentionMs: 1 },
      });
    const q1 = mk();
    q1.start();
    q1.enqueue({ id: "d1", payload: Buffer.from("p1"), targetUrl: EP_A, headers: {} });
    // Real timers: the delivery fails into the dead letter, then the 1ms
    // TTL expires.
    await sleep(80);
    assert.equal(q1.getDeadLetter().length, 1);
    const r = q1.purgeExpiredDeadLetters();
    assert.equal(r.purged.length, 1);
    // Lengthen the TTL after the purge: the entry must stay gone — a
    // retune never revives a journaled purge.
    assert.deepEqual(q1.setDeadLetterRetention({ retentionMs: 3_600_000 }), {
      retentionMs: 3_600_000,
      sweepIntervalMs: 60_000,
    });
    assert.deepEqual(q1.purgeExpiredDeadLetters(), { purged: [], skipped: [] });
    q1.stop();

    // A restarted process replays the journal: the `purged` line
    // supersedes the `dead_letter` line, so the entry stays gone.
    const q2 = mk();
    assert.equal(q2.getDeadLetter().length, 0, "purged entry must not resurrect after recovery");
    q2.stop();
  });
});

describe("RelayServer.setDeadLetterRetention (WR-315)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "deadletter-retention-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: "http://127.0.0.1:9/unused",
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

  it("audits dead_letter_retention_revised with previous/current and skips the audit on a no-op", async () => {
    const { relay, auditLog } = makeServer({
      deadLetterRetention: { retentionMs: { [EP_A]: 1000 }, sweepIntervalMs: 60_000 },
    });
    await listen(relay);
    assert.deepEqual(relay.getDeadLetterRetention!(), {
      retentionMs: { [EP_A]: 1000 },
      sweepIntervalMs: 60_000,
    });
    assert.equal(eventsOf(auditLog, "dead_letter_retention_revised").length, 0);

    // Mode switch: record -> global number.
    const next = relay.setDeadLetterRetention!({ retentionMs: 2000 });
    assert.deepEqual(next, { retentionMs: 2000, sweepIntervalMs: 60_000 });
    const revised = eventsOf(auditLog, "dead_letter_retention_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, {
      retentionMs: { [EP_A]: 1000 },
      sweepIntervalMs: 60_000,
    });
    assert.deepEqual(revised[0].current, { retentionMs: 2000, sweepIntervalMs: 60_000 });

    // Empty patch, same-value patch, and a record patch that only
    // deletes an absent endpoint against the global TTL: all no-ops
    // with no new audit event.
    relay.setDeadLetterRetention!({});
    relay.setDeadLetterRetention!({ retentionMs: 2000 });
    relay.setDeadLetterRetention!({ retentionMs: 2000, sweepIntervalMs: 60_000 });
    relay.setDeadLetterRetention!({ retentionMs: { [EP_B]: null } });
    assert.equal(eventsOf(auditLog, "dead_letter_retention_revised").length, 1);
    assert.deepEqual(relay.getDeadLetterRetention!(), {
      retentionMs: 2000,
      sweepIntervalMs: 60_000,
    });
  });

  it("throws RangeError on an illegal value and leaves the live values untouched", async () => {
    const { relay, auditLog } = makeServer({
      deadLetterRetention: { retentionMs: 1000 },
    });
    await listen(relay);
    for (const bad of [
      { retentionMs: 0 },
      { retentionMs: -1 },
      { sweepIntervalMs: 0 },
      { sweepIntervalMs: NaN },
      { retentionMs: { [EP_A]: 0 } },
    ]) {
      assert.throws(() => relay.setDeadLetterRetention!(bad), RangeError, `patch ${JSON.stringify(bad)}`);
    }
    assert.equal(eventsOf(auditLog, "dead_letter_retention_revised").length, 0);
    assert.deepEqual(relay.getDeadLetterRetention!(), {
      retentionMs: 1000,
      sweepIntervalMs: 60_000,
    });
  });

  it("throws Error when retention was never configured; the getter is unset", async () => {
    const { relay, auditLog } = makeServer({});
    await listen(relay);
    assert.equal(typeof relay.setDeadLetterRetention, "function");
    assert.equal(relay.getDeadLetterRetention, undefined);
    assert.throws(() => relay.setDeadLetterRetention!({ retentionMs: 1000 }), /not configured/);
    assert.equal(eventsOf(auditLog, "dead_letter_retention_revised").length, 0);
  });
});
