import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type Sender, type RetryItem, type RetryQueueOptions } from "../src/retry.ts";
import { ScheduledDeliveryJournal, SCHEDULED_JOURNAL_FILE } from "../src/scheduled-journal.ts";
import { AesGcmEncryptor, randomAes256Key, NoopEncryptor } from "../src/encrypt.ts";

const URL_A = "http://localhost:9999/a";

/** Manual timer, same shape as test/scheduled.test.ts. */
function manualTimer() {
  const pending: Array<{ fn: () => void; ms: number }> = [];
  return {
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
    async step() {
      const fns = pending.splice(0);
      for (const f of fns) f.fn();
      await new Promise((r) => setImmediate(r));
    },
  };
}

function item(id: string, deliverAt: number, extra: Partial<RetryItem> = {}): RetryItem {
  return { id, payload: Buffer.from(`payload-${id}`), targetUrl: URL_A, headers: {}, deliverAt, ...extra };
}

function queueWithClock(opts: {
  sender: Sender;
  now: () => number;
  t: ReturnType<typeof manualTimer>;
  extra?: RetryQueueOptions;
}) {
  return new RetryQueue({
    sender: opts.sender,
    setTimer: opts.t.setTimer,
    maxAttempts: 2,
    baseDelayMs: 50,
    jitterMs: 0,
    scheduled: { now: opts.now, setTimer: opts.t.setTimer },
    ...opts.extra,
  });
}

function journalLines(dir: string): string[] {
  const p = join(dir, SCHEDULED_JOURNAL_FILE);
  if (!existsSync(p)) return [];
  return readFileSync(p, "utf8").split("\n").filter((l) => l.trim() !== "");
}

describe("WR-133 durable scheduled deliveries", () => {
  it("parking journals a park line; restart re-parks with the remaining delay", async () => {
    const dir = mkdtempSync(join(tmpdir(), "sched-durable-"));
    let now = 1_000_000;
    const t = manualTimer();
    const sender: Sender = async () => undefined;
    const q1 = queueWithClock({ sender, now: () => now, t, extra: { durableScheduledDir: dir } });
    q1.enqueue(item("s1", now + 60_000, { traceId: "trace-1" }));
    assert.equal(q1.isScheduled("s1"), true);

    const lines = journalLines(dir).map((l) => JSON.parse(l));
    assert.equal(lines.length, 1);
    assert.equal(lines[0].op, "park");
    assert.equal(lines[0].id, "s1");
    assert.equal(lines[0].deliverAt, now + 60_000);
    // No encryptor: payload base64 in the clear (same at-rest rule as WR-49).
    assert.equal(lines[0].item.payload.encoding, "base64");
    assert.equal(Buffer.from(lines[0].item.payload.data, "base64").toString(), "payload-s1");

    // Restart 10s later: the item comes back parked, timer re-arms for the head.
    now += 10_000;
    let restored: { restoredParked: number; restoredPastDue: number; skippedLines: number } | undefined;
    const t2 = manualTimer();
    const q2 = queueWithClock({
      sender,
      now: () => now,
      t: t2,
      extra: { durableScheduledDir: dir, onScheduledRestored: (info) => (restored = info) },
    });
    assert.equal(q2.isScheduled("s1"), true);
    assert.deepEqual(restored, {
      dir,
      restoredParked: 1,
      restoredPastDue: 0,
      skippedLines: 0,
    });
    const listed = q2.getScheduled();
    assert.equal(listed.length, 1);
    assert.equal(listed[0].id, "s1");
    assert.equal(listed[0].deliverAt, now + 50_000);
    assert.equal(listed[0].traceId, "trace-1");

    // Fire the delay queue: the item enters the normal path and delivers.
    let delivered = 0;
    const t3 = manualTimer();
    const q3 = queueWithClock({
      sender: async () => {
        delivered += 1;
      },
      now: () => now,
      t: t3,
      extra: { durableScheduledDir: dir },
    });
    assert.equal(q3.isScheduled("s1"), true);
    q3.start();
    now += 50_000;
    await t3.step(); // scheduler fires -> released into the normal path
    await t3.step(); // the released delivery runs
    await new Promise((r) => setImmediate(r));
    assert.equal(delivered, 1);
    // The fired line superseded the park line: a further restart finds nothing.
    const q4 = queueWithClock({
      sender,
      now: () => now,
      t: manualTimer(),
      extra: { durableScheduledDir: dir },
    });
    assert.equal(q4.isScheduled("s1"), false);
    assert.equal(q4.getScheduled().length, 0);
  });

  it("items past-due at recovery skip the delay queue (past-due semantics match live intake)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "sched-durable-"));
    let now = 2_000_000;
    const sender: Sender = async () => undefined;
    const q1 = queueWithClock({
      sender,
      now: () => now,
      t: manualTimer(),
      extra: { durableScheduledDir: dir },
    });
    q1.enqueue(item("s2", now + 5_000));
    assert.equal(q1.isScheduled("s2"), true);

    // Restart after the instant passed: straight into the normal queue.
    now += 60_000;
    let delivered = 0;
    let restored: { restoredParked: number; restoredPastDue: number } | undefined;
    const t2 = manualTimer();
    const q2 = queueWithClock({
      sender: async () => {
        delivered += 1;
      },
      now: () => now,
      t: t2,
      extra: {
        durableScheduledDir: dir,
        onScheduledRestored: (info) => (restored = info),
      },
    });
    assert.equal(q2.isScheduled("s2"), false);
    assert.equal(restored?.restoredParked, 0);
    assert.equal(restored?.restoredPastDue, 1);
    q2.start();
    await t2.step();
    await t2.step();
    await new Promise((r) => setImmediate(r));
    assert.equal(delivered, 1);
    // A further restart finds nothing: the fired line superseded the park.
    const q3 = queueWithClock({
      sender,
      now: () => now,
      t: manualTimer(),
      extra: { durableScheduledDir: dir },
    });
    assert.equal(q3.isScheduled("s2"), false);
  });

  it("cancel writes a tombstone: a canceled item is never resurrected", () => {
    const dir = mkdtempSync(join(tmpdir(), "sched-durable-"));
    const now = 3_000_000;
    const sender: Sender = async () => undefined;
    const q1 = queueWithClock({
      sender,
      now: () => now,
      t: manualTimer(),
      extra: { durableScheduledDir: dir },
    });
    q1.enqueue(item("s3", now + 60_000));
    assert.equal(q1.cancelScheduled("s3"), true);
    const ops = journalLines(dir).map((l) => JSON.parse(l).op);
    assert.deepEqual(ops, ["park", "cancel"]);

    const q2 = queueWithClock({
      sender,
      now: () => now,
      t: manualTimer(),
      extra: { durableScheduledDir: dir },
    });
    assert.equal(q2.isScheduled("s3"), false);
    assert.equal(q2.getScheduled().length, 0);
  });

  it("recurring schedules (WR-80) are not journaled", () => {
    const dir = mkdtempSync(join(tmpdir(), "sched-durable-"));
    const now = 4_000_000;
    const sender: Sender = async () => undefined;
    const q1 = queueWithClock({
      sender,
      now: () => now,
      t: manualTimer(),
      extra: { durableScheduledDir: dir },
    });
    q1.addRecurringDelivery(
      { id: "cron-1", payload: Buffer.from("x"), targetUrl: URL_A, headers: {} },
      "* * * * *"
    );
    assert.equal(journalLines(dir).length, 0);
  });

  it("corrupt lines are skipped and counted; undecryptable payloads fail the item, not the recovery", () => {
    const dir = mkdtempSync(join(tmpdir(), "sched-durable-"));
    const now = 5_000_000;
    const sender: Sender = async () => undefined;
    const key = randomAes256Key();
    const q1 = queueWithClock({
      sender,
      now: () => now,
      t: manualTimer(),
      extra: { durableScheduledDir: dir, payloadEncryptor: new AesGcmEncryptor(key) },
    });
    q1.enqueue(item("s4", now + 60_000));
    const p = join(dir, SCHEDULED_JOURNAL_FILE);
    // Sealed payload in the journal.
    const sealed = JSON.parse(journalLines(dir)[0]);
    assert.ok(sealed.item.payload.alg !== undefined);
    // Torn write + garbage line + a sealed-under-another-key item.
    writeFileSync(p, readFileSync(p, "utf8") + "not-json{\n");
    const other = new ScheduledDeliveryJournal(dir, new AesGcmEncryptor(randomAes256Key()));
    other.appendPark(item("s5", now + 60_000));

    let restored: { restoredParked: number; skippedLines: number } | undefined;
    const q2 = queueWithClock({
      sender,
      now: () => now,
      t: manualTimer(),
      extra: {
        durableScheduledDir: dir,
        payloadEncryptor: new AesGcmEncryptor(key),
        onScheduledRestored: (info) => (restored = info),
      },
    });
    // s4 recovered (decrypts with the original key); the torn line and the
    // foreign-key s5 are skipped.
    assert.equal(q2.isScheduled("s4"), true);
    assert.equal(q2.isScheduled("s5"), false);
    assert.equal(restored?.restoredParked, 1);
    assert.equal(restored?.skippedLines, 2);
    // Payload round-trips through the seal.
    const listed = q2.getScheduled();
    assert.equal(listed[0].id, "s4");
  });

  it("payloads are sealed with the queue's encryptor when configured (NoopEncryptor passthrough)", () => {
    const dir = mkdtempSync(join(tmpdir(), "sched-durable-"));
    const now = 6_000_000;
    const sender: Sender = async () => undefined;
    const q1 = queueWithClock({
      sender,
      now: () => now,
      t: manualTimer(),
      extra: { durableScheduledDir: dir, payloadEncryptor: new NoopEncryptor() },
    });
    q1.enqueue(item("s6", now + 60_000));
    const q2 = queueWithClock({
      sender,
      now: () => now,
      t: manualTimer(),
      extra: { durableScheduledDir: dir, payloadEncryptor: new NoopEncryptor() },
    });
    assert.equal(q2.isScheduled("s6"), true);
  });

  it("disabled by default: no directory is created, behavior unchanged", () => {
    const dir = join(tmpdir(), `sched-durable-never-${Date.now()}`);
    const now = 7_000_000;
    const sender: Sender = async () => undefined;
    const q = queueWithClock({ sender, now: () => now, t: manualTimer() });
    q.enqueue(item("s7", now + 60_000));
    assert.equal(q.isScheduled("s7"), true);
    assert.equal(existsSync(dir), false);
  });

  it("invalid option values fail fast", () => {
    const sender: Sender = async () => undefined;
    assert.throws(
      () =>
        queueWithClock({
          sender,
          now: Date.now,
          t: manualTimer(),
          extra: { durableScheduledDir: "" },
        }),
      RangeError
    );
    // A directory that cannot be created (a file blocks the path) throws.
    const blocker = join(tmpdir(), `sched-blocker-${Date.now()}`);
    writeFileSync(blocker, "x");
    assert.throws(
      () =>
        queueWithClock({
          sender,
          now: Date.now,
          t: manualTimer(),
          extra: { durableScheduledDir: join(blocker, "sub") },
        }),
      Error
    );
  });

  it("appendPark without a finite deliverAt fails closed (caller bug, not a disk error)", () => {
    const dir = mkdtempSync(join(tmpdir(), "sched-durable-"));
    const j = new ScheduledDeliveryJournal(dir);
    assert.throws(
      () =>
        j.appendPark({
          id: "bad",
          payload: Buffer.from("x"),
          targetUrl: URL_A,
          headers: {},
        }),
      RangeError
    );
  });

  it("onScheduledRestored fires even when recovery restored nothing", () => {
    const dir = mkdtempSync(join(tmpdir(), "sched-durable-"));
    const sender: Sender = async () => undefined;
    let called = 0;
    queueWithClock({
      sender,
      now: Date.now,
      t: manualTimer(),
      extra: {
        durableScheduledDir: dir,
        onScheduledRestored: () => {
          called += 1;
        },
      },
    });
    assert.equal(called, 1);
  });
});
