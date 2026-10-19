import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { RetryQueue } from "../src/retry.ts";
import { ReplayEgressGate, DEFAULT_REPLAY_EGRESS_RPS } from "../src/replay-egress.ts";

const EP_A = "http://a.example/hook";
const EP_B = "http://b.example/hook";

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
    async run() {
      while (pending.length > 0) {
        const fns = pending.splice(0);
        for (const f of fns) f();
        await new Promise((r) => setImmediate(r));
      }
    },
  };
}

interface SeededItem {
  id: string;
  targetUrl: string;
}

/** Queue with a failing sender, pre-filled with dead letters; `clock` drives the egress gate. */
function seedDeadLetters(items: SeededItem[], extraOpts: Record<string, unknown> = {}, clock?: { now: number }) {
  const timer = manualTimer();
  const replayEgress =
    (extraOpts as { replayEgress?: { replaysPerSecond?: number } }).replayEgress === undefined
      ? undefined
      : { replaysPerSecond: (extraOpts as { replayEgress: { replaysPerSecond?: number } }).replayEgress.replaysPerSecond, now: () => clock!.now };
  const q = new RetryQueue({
    sender: async () => {
      throw new Error("downstream 500");
    },
    baseDelayMs: 1,
    maxAttempts: 2,
    jitterMs: 0,
    setTimer: timer.setTimer,
    ...(extraOpts as object),
    ...(replayEgress === undefined ? {} : { replayEgress }),
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

describe("WR-68 replay egress gate", () => {
  describe("ReplayEgressGate", () => {
    it("rejects invalid budgets at construction", () => {
      for (const bad of [0, -1, NaN, Infinity, -Infinity]) {
        assert.throws(() => new ReplayEgressGate({ replaysPerSecond: bad as number }), RangeError);
      }
    });

    it("defaults to DEFAULT_REPLAY_EGRESS_RPS", () => {
      assert.equal(new ReplayEgressGate().limit(), DEFAULT_REPLAY_EGRESS_RPS);
      assert.equal(new ReplayEgressGate({}).limit(), DEFAULT_REPLAY_EGRESS_RPS);
    });

    it("token bucket refills lazily with the injectable clock", () => {
      let now = 1_000_000;
      const gate = new ReplayEgressGate({ replaysPerSecond: 2, now: () => now });
      assert.ok(gate.take(EP_A));
      assert.ok(gate.take(EP_A));
      assert.ok(!gate.take(EP_A), "bucket exhausted");
      assert.ok(gate.msUntilToken(EP_A) > 0);
      now += 500; // one token per 500ms at 2 RPS
      assert.ok(gate.take(EP_A), "refill after half a second");
      assert.ok(!gate.take(EP_A));
      now += 10_000;
      assert.equal(gate.msUntilToken(EP_A), 0, "bucket caps at one second of budget, never banks more");
    });

    it("buckets are isolated per endpoint", () => {
      const gate = new ReplayEgressGate({ replaysPerSecond: 1 });
      assert.ok(gate.take(EP_A));
      assert.ok(!gate.take(EP_A));
      assert.ok(gate.take(EP_B), "endpoint B has its own bucket");
    });
  });

  describe("queue wiring", () => {
    it("rejects an invalid replayEgress at construction", () => {
      for (const bad of [0, -5, NaN, Infinity]) {
        assert.throws(
          () => new RetryQueue({ replayEgress: { replaysPerSecond: bad as number } }),
          RangeError
        );
      }
    });

    it("disabled by default: batch replays everything, throttled is empty", async () => {
      const { q, timer } = seedDeadLetters([
        { id: "a", targetUrl: EP_A },
        { id: "b", targetUrl: EP_A },
        { id: "c", targetUrl: EP_A },
      ]);
      await timer.run();
      const result = q.replayDeadLetters();
      assert.deepEqual(result, { replayed: ["a", "b", "c"], failed: [], throttled: [], skipped: [] });
      assert.equal(q.getDeadLetterStats().throttled, 0);
      assert.equal(q.getReplayEgressGate(), undefined);
      q.stop();
    });

    it("holds back entries beyond the per-endpoint budget; nothing is dropped", async () => {
      const clock = { now: 0 };
      const { q, timer } = seedDeadLetters(
        [
          { id: "a", targetUrl: EP_A },
          { id: "b", targetUrl: EP_A },
          { id: "c", targetUrl: EP_A },
          { id: "d", targetUrl: EP_A },
          { id: "e", targetUrl: EP_A },
        ],
        { replayEgress: { replaysPerSecond: 2 } },
        clock
      );
      await timer.run();
      assert.equal(q.getDeadLetter().length, 5);

      const r1 = q.replayDeadLetters();
      assert.deepEqual(r1.replayed, ["a", "b"]);
      assert.deepEqual(r1.failed, []);
      assert.deepEqual(r1.throttled, ["c", "d", "e"]);
      // Held-back entries stay in the dead-letter list, FIFO order intact.
      assert.deepEqual(q.getDeadLetter().map((e) => e.id), ["c", "d", "e"]);

      // One second refills the 2-token budget: the next call picks up the rest.
      clock.now += 1000;
      const r2 = q.replayDeadLetters();
      assert.deepEqual(r2.replayed, ["c", "d"]);
      assert.deepEqual(r2.throttled, ["e"]);
      clock.now += 1000;
      const r3 = q.replayDeadLetters();
      assert.deepEqual(r3.replayed, ["e"]);
      assert.deepEqual(r3.throttled, []);

      // /dead-letter/stats throttled counter is cumulative across calls.
      assert.equal(q.getDeadLetterStats().throttled, 4);
      assert.equal(q.getDeadLetter().length, 0);
      q.stop();
    });

    it("budgets are per endpoint: one endpoint's throttle never starves another", async () => {
      const clock = { now: 0 };
      const { q, timer } = seedDeadLetters(
        [
          { id: "a1", targetUrl: EP_A },
          { id: "a2", targetUrl: EP_A },
          { id: "a3", targetUrl: EP_A },
          { id: "b1", targetUrl: EP_B },
          { id: "b2", targetUrl: EP_B },
        ],
        { replayEgress: { replaysPerSecond: 2 } },
        clock
      );
      await timer.run();
      const r = q.replayDeadLetters();
      assert.deepEqual(r.replayed, ["a1", "a2", "b1", "b2"]);
      assert.deepEqual(r.throttled, ["a3"]);
      q.stop();
    });

    it("single replayDeadLetter(id) is not gated — the operator escape hatch", async () => {
      const clock = { now: 0 };
      const { q, timer } = seedDeadLetters(
        [
          { id: "a", targetUrl: EP_A },
          { id: "b", targetUrl: EP_A },
        ],
        { replayEgress: { replaysPerSecond: 1 } },
        clock
      );
      await timer.run();
      const first = q.replayDeadLetters();
      assert.deepEqual(first.replayed, ["a"]);
      assert.deepEqual(first.throttled, ["b"]);
      // The budget is still empty, but a single hand-picked replay goes through.
      assert.ok(q.replayDeadLetter("b"), "single-id replay bypasses the egress gate");
      assert.equal(q.getDeadLetter().length, 0);
      q.stop();
    });

    it("a throttled-only auto round counts as progress, not an empty round", async () => {
      const clock = { now: 0 };
      const { q, timer } = seedDeadLetters(
        [
          { id: "a", targetUrl: EP_A },
          { id: "b", targetUrl: EP_A },
          { id: "c", targetUrl: EP_A },
        ],
        {
          replayEgress: { replaysPerSecond: 2 },
          autoReplay: { enabled: true, intervalMs: 60_000 },
        },
        clock
      );
      await timer.run();
      const replayer = q.getAutoReplayer();
      assert.ok(replayer);
      // The auto round shares the gate: 2 replayed, 1 throttled.
      const r1 = replayer!.triggerOnce();
      assert.deepEqual(r1.replayed, ["a", "b"]);
      assert.deepEqual(r1.throttled, ["c"]);
      assert.equal(r1.consecutiveEmptyRounds, 0, "throttled-only round is progress, not poison");
      // Budget still empty and the one entry still live: another round
      // throttles again and must not drift toward rounds-exhausted.
      const r2 = replayer!.triggerOnce();
      assert.deepEqual(r2.replayed, []);
      assert.deepEqual(r2.throttled, ["c"]);
      assert.equal(r2.consecutiveEmptyRounds, 0);
      // After a refill the last entry replays and the counter stays at zero.
      clock.now += 1000;
      const r3 = replayer!.triggerOnce();
      assert.deepEqual(r3.replayed, ["c"]);
      assert.equal(r3.consecutiveEmptyRounds, 0);
      q.stop();
    });

    it("exposes the gate for observability", async () => {
      const { q, timer } = seedDeadLetters([{ id: "a", targetUrl: EP_A }], {
        replayEgress: { replaysPerSecond: 7 },
      });
      await timer.run();
      const gate = q.getReplayEgressGate();
      assert.ok(gate instanceof ReplayEgressGate);
      assert.equal(gate!.limit(), 7);
      q.stop();
    });
  });
});
