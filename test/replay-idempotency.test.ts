import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  RetryQueue,
  type Sender,
  type ReplayIdempotencyOptions,
  type ReplaySkippedInfo,
  type ReplayForcedInfo,
} from "../src/retry.ts";
import { ReplayIdempotencyGuard, sha256Hex } from "../src/replay-idempotency.ts";

const URL = "http://localhost:9999/hook";
const PAYLOAD = Buffer.from(JSON.stringify({ payment: "pi_123", amount: 5000 }));

/** Manual timer with single-step control. */
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
    async step() {
      const fns = pending.splice(0);
      for (const f of fns) f();
      await new Promise((r) => setImmediate(r));
    },
    async drain() {
      while (pending.length > 0) await this.step();
    },
  };
}

function controllableSender() {
  let calls = 0;
  let fail = true;
  const sender: Sender = async () => {
    calls += 1;
    if (fail) throw new Error("downstream 500");
  };
  return { sender, calls: () => calls, setFail: (v: boolean) => (fail = v) };
}

describe("ReplayIdempotencyGuard", () => {
  it("suppresses a replay when the pair was delivered after dead-lettering", () => {
    let now = 1000;
    const g = new ReplayIdempotencyGuard({ now: () => now });
    g.recordDelivered(URL, PAYLOAD);
    assert.equal(g.deliveredAtMs(URL, PAYLOAD), 1000);
    // Delivered at 1000, dead-lettered at 500 -> newer copy exists.
    assert.ok((g.deliveredAtMs(URL, PAYLOAD) ?? 0) > 500);
  });

  it("allows a replay when the delivery predates the dead letter", () => {
    let now = 1000;
    const g = new ReplayIdempotencyGuard({ now: () => now });
    g.recordDelivered(URL, PAYLOAD);
    // Delivered at 1000, dead-lettered at 1500 -> the delivery is older.
    assert.ok(!((g.deliveredAtMs(URL, PAYLOAD) ?? 0) > 1500));
  });

  it("a delivery at the same instant as dead-lettering does not suppress (strictly-after)", () => {
    let now = 1000;
    const g = new ReplayIdempotencyGuard({ now: () => now });
    g.recordDelivered(URL, PAYLOAD);
    assert.ok(!((g.deliveredAtMs(URL, PAYLOAD) ?? 0) > 1000));
  });

  it("unknown pairs are never suppressed", () => {
    const g = new ReplayIdempotencyGuard();
    assert.equal(g.deliveredAtMs(URL, PAYLOAD), undefined);
    assert.equal(g.deliveredAtMs("http://other/hook", PAYLOAD), undefined);
    assert.equal(g.deliveredAtMs(URL, Buffer.from("other")), undefined);
  });

  it("records expire after windowMs", () => {
    let now = 0;
    const g = new ReplayIdempotencyGuard({ windowMs: 1000, now: () => now });
    g.recordDelivered(URL, PAYLOAD);
    now = 999;
    assert.equal(g.deliveredAtMs(URL, PAYLOAD), 0);
    now = 1000;
    assert.equal(g.deliveredAtMs(URL, PAYLOAD), undefined);
  });

  it("evicts the oldest pairs past maxEntries", () => {
    const g = new ReplayIdempotencyGuard({ maxEntries: 2 });
    g.recordDelivered(URL, Buffer.from("one"));
    g.recordDelivered(URL, Buffer.from("two"));
    g.recordDelivered(URL, Buffer.from("three"));
    assert.equal(g.deliveredAtMs(URL, Buffer.from("one")), undefined);
    assert.notEqual(g.deliveredAtMs(URL, Buffer.from("two")), undefined);
    assert.notEqual(g.deliveredAtMs(URL, Buffer.from("three")), undefined);
    assert.equal(g.stats().trackedPairs, 2);
  });

  it("re-delivering refreshes the timestamp", () => {
    let now = 1000;
    const g = new ReplayIdempotencyGuard({ windowMs: 500, now: () => now });
    g.recordDelivered(URL, PAYLOAD);
    now = 1400;
    g.recordDelivered(URL, PAYLOAD);
    now = 1500; // 500ms after the refresh, still in-window
    assert.equal(g.deliveredAtMs(URL, PAYLOAD), 1400);
  });

  it("rejects illegal configs with RangeError", () => {
    assert.throws(() => new ReplayIdempotencyGuard({ windowMs: 0 }), RangeError);
    assert.throws(() => new ReplayIdempotencyGuard({ windowMs: -5 }), RangeError);
    assert.throws(() => new ReplayIdempotencyGuard({ maxEntries: 0 }), RangeError);
    assert.throws(() => new ReplayIdempotencyGuard({ maxEntries: 1.5 }), RangeError);
  });

  it("reset() clears per-endpoint or everything", () => {
    const g = new ReplayIdempotencyGuard();
    g.recordDelivered(URL, PAYLOAD);
    g.recordDelivered("http://other/hook", PAYLOAD);
    g.reset(URL);
    assert.equal(g.deliveredAtMs(URL, PAYLOAD), undefined);
    assert.notEqual(g.deliveredAtMs("http://other/hook", PAYLOAD), undefined);
    g.reset();
    assert.equal(g.deliveredAtMs("http://other/hook", PAYLOAD), undefined);
    assert.equal(g.stats().trackedPairs, 0);
  });

  it("stats() reports tracked pairs and the oldest record", () => {
    let now = 100;
    const g = new ReplayIdempotencyGuard({ now: () => now });
    assert.deepEqual(g.stats(), { trackedPairs: 0 });
    g.recordDelivered(URL, PAYLOAD);
    now = 200;
    g.recordDelivered("http://other/hook", PAYLOAD);
    assert.deepEqual(g.stats(), { trackedPairs: 2, oldestRecordAtMs: 100 });
  });

  it("sha256Hex matches the known digest", () => {
    assert.equal(
      sha256Hex("abc"),
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert.equal(sha256Hex(Buffer.from("abc")), sha256Hex("abc"));
  });
});

describe("retry queue replay idempotency", () => {
  function makeQueue(replayIdempotency?: ReplayIdempotencyOptions, guardNow?: () => number) {
    const timer = manualTimer();
    const f = controllableSender();
    const skipped: ReplaySkippedInfo[] = [];
    const forced: ReplayForcedInfo[] = [];
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
      onReplayForced: (info) => forced.push(info),
    });
    return { q, timer, f, skipped, forced };
  }

  /**
   * The guard compares millisecond timestamps with a strict `>`, so a
   * delivered record stamped in the *same* millisecond as the
   * dead-lettering must not suppress. Wall-clock tests would flake on
   * that boundary — suppression tests run the guard's clock 60s ahead
   * of wall time (delivered records are deterministically newer), the
   * predates test runs it 1h behind (deterministically older).
   */
  const aheadClock = () => Date.now() + 60_000;
  const behindClock = () => Date.now() - 3_600_000;

  it("suppresses replaying a dead letter whose pair was delivered later", async () => {
    const { q, timer, f, skipped, forced } = makeQueue({}, aheadClock);
    q.start();
    // Dead-letter item A at T1 (sender failing).
    q.enqueue({ id: "rdl-a", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    assert.equal(q.getDeadLetter().length, 1);
    const deadLetteredAt = q.getDeadLetter()[0].deadLetteredAt;

    // Deliver the same (endpoint, payload) at T2 > T1.
    f.setFail(false);
    q.enqueue({ id: "rdl-b", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    assert.equal(q.pendingCount(), 0);

    // The replay is suppressed: not replayed, still dead-lettered.
    assert.equal(q.replayDeadLetter("rdl-a"), false);
    assert.equal(q.getDeadLetter().length, 1);
    assert.equal(q.getDeadLetter()[0].id, "rdl-a");
    assert.equal(skipped.length, 1);
    assert.equal(skipped[0].id, "rdl-a");
    assert.equal(skipped[0].endpoint, URL);
    assert.equal(skipped[0].deadLetteredAt, deadLetteredAt);
    assert.ok(Date.parse(skipped[0].deliveredAt) > Date.parse(deadLetteredAt));
    assert.equal(forced.length, 0);

    // Explicit force replays anyway.
    assert.equal(q.replayDeadLetter("rdl-a", { force: true }), true);
    assert.equal(q.getDeadLetter().length, 0);
    assert.equal(forced.length, 1);
    assert.equal(forced[0].id, "rdl-a");
    assert.equal(forced[0].endpoint, URL);
    assert.ok(forced[0].deliveredAt !== undefined);
    await timer.drain();
    assert.equal(q.pendingCount(), 0);
  });

  it("allows replaying when the delivered copy predates the dead letter", async () => {
    const { q, timer, f, skipped } = makeQueue({}, behindClock);
    q.start();
    // Deliver at T1 first.
    f.setFail(false);
    q.enqueue({ id: "rdl-first", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    // Dead-letter the same pair at T2 > T1.
    f.setFail(true);
    q.enqueue({ id: "rdl-second", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    assert.equal(q.getDeadLetter().length, 1);

    assert.equal(q.replayDeadLetter("rdl-second"), true);
    assert.equal(skipped.length, 0);
    assert.equal(q.getDeadLetter().length, 0);
  });

  it("allows replaying a pair that was never delivered", async () => {
    const { q, timer, skipped } = makeQueue({});
    q.start();
    q.enqueue({ id: "rdl-never", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    assert.equal(q.getDeadLetter().length, 1);
    assert.equal(q.replayDeadLetter("rdl-never"), true);
    assert.equal(skipped.length, 0);
  });

  it("returns false for unknown ids, unchanged", async () => {
    const { q, skipped } = makeQueue({});
    q.start();
    assert.equal(q.replayDeadLetter("nope"), false);
    assert.equal(skipped.length, 0);
  });

  it("batch replay collects suppressed ids as skipped and previews will_skip", async () => {
    const { q, timer, f, skipped } = makeQueue({}, aheadClock);
    q.start();
    const other = Buffer.from(JSON.stringify({ other: true }));
    q.enqueue({ id: "rdl-x", payload: PAYLOAD, targetUrl: URL, headers: {} });
    q.enqueue({ id: "rdl-y", payload: other, targetUrl: URL, headers: {} });
    await timer.drain();
    assert.equal(q.getDeadLetter().length, 2);

    // A newer delivered copy of rdl-x's pair only.
    f.setFail(false);
    q.enqueue({ id: "rdl-copy", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();

    // Dry-run preview marks the would-be-skipped row.
    const preview = q.replayDeadLetters({}, { dryRun: true }) as Array<Record<string, unknown>>;
    const byId = new Map(preview.map((p) => [p.id, p]));
    assert.equal(byId.get("rdl-x")!.will_skip, true);
    assert.ok(!("will_skip" in byId.get("rdl-y")!));
    assert.equal(q.getDeadLetter().length, 2, "dry-run must not touch dead letters");

    // Executing replay: rdl-x skipped, rdl-y replayed.
    const result = q.replayDeadLetters({});
    assert.deepEqual(result.skipped, ["rdl-x"]);
    assert.deepEqual(result.replayed, ["rdl-y"]);
    assert.deepEqual(result.failed, []);
    assert.deepEqual(result.throttled, []);
    assert.equal(skipped.length, 1);
    assert.equal(q.getDeadLetter().length, 1);
    assert.equal(q.getDeadLetter()[0].id, "rdl-x");

    // Force replays the suppressed entry too.
    const forced = q.replayDeadLetters({}, { force: true });
    assert.deepEqual(forced.skipped, []);
    assert.deepEqual(forced.replayed, ["rdl-x"]);
    assert.equal(q.getDeadLetter().length, 0);
  });

  it("is disabled by default: replays are never suppressed", async () => {
    const { q, timer, f, skipped } = makeQueue();
    assert.equal(q.getReplayIdempotencyStats(), undefined);
    q.start();
    q.enqueue({ id: "rdl-off-a", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    f.setFail(false);
    q.enqueue({ id: "rdl-off-b", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    assert.equal(q.replayDeadLetter("rdl-off-a"), true);
    assert.equal(skipped.length, 0);
  });

  it("rejects illegal replayIdempotency options at construction", () => {
    const f = controllableSender();
    assert.throws(
      () => new RetryQueue({ sender: f.sender, replayIdempotency: { windowMs: 0 } }),
      RangeError
    );
    assert.throws(
      () => new RetryQueue({ sender: f.sender, replayIdempotency: { maxEntries: 0 } }),
      RangeError
    );
  });

  it("getReplayIdempotencyStats exposes the index", async () => {
    const { q, timer, f } = makeQueue({});
    q.start();
    const rows = q.getReplayIdempotencyStats()!;
    assert.deepEqual(rows, []);
    f.setFail(false);
    q.enqueue({ id: "rdl-stat", payload: PAYLOAD, targetUrl: URL, headers: {} });
    await timer.drain();
    const after = q.getReplayIdempotencyStats()!;
    assert.equal(after.length, 1);
    assert.equal(after[0].trackedPairs, 1);
    assert.ok(after[0].oldestRecordAtMs !== undefined);
    assert.ok(!("tenant" in after[0]));
  });
});
