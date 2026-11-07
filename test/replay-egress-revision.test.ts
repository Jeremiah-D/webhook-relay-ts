import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue } from "../src/retry.ts";
import { ReplayEgressGate } from "../src/replay-egress.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "replay-egress-revision-test-key";
const opToken = "replay-egress-revision-op-token";
const URL_A = "http://localhost:9999/a";
const EP_A = "http://a.example/hook";

const MUST_RESTART =
  "reviseReplayEgress: replay egress is not configured — enabling it requires a restart";

/** Deterministic timer: `run()` executes pending callbacks immediately. */
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
    async run() {
      while (pending.length > 0) {
        const fns = pending.splice(0);
        for (const f of fns) f.fn();
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

describe("ReplayEgressGate.retune (WR-345)", () => {
  it("tightening clamps an existing endpoint's bucket on the next take", () => {
    let now = 1_000_000;
    const gate = new ReplayEgressGate({ replaysPerSecond: 10, now: () => now });
    for (let i = 0; i < 9; i++) assert.ok(gate.take(EP_A));
    // One token left; a full second passes, so the bucket would refill
    // to 10 under the old rate.
    now += 1000;
    assert.deepEqual(gate.retune({ replaysPerSecond: 2 }), { replaysPerSecond: 2 });
    // The next read clamps the balance to the new rate: only 2 takes.
    assert.ok(gate.take(EP_A));
    assert.ok(gate.take(EP_A));
    assert.ok(!gate.take(EP_A), "bucket clamped to the tightened rate");
    assert.equal(gate.msUntilToken(EP_A), 500, "wait follows the live rate");
  });

  it("loosening adds no tokens — the balance only grows back with elapsed time", () => {
    let now = 1_000_000;
    const gate = new ReplayEgressGate({ replaysPerSecond: 2, now: () => now });
    assert.ok(gate.take(EP_A));
    assert.ok(gate.take(EP_A));
    assert.ok(!gate.take(EP_A), "bucket empty");
    assert.deepEqual(gate.retune({ replaysPerSecond: 10 }), { replaysPerSecond: 10 });
    // No top-up: still empty right after the raise.
    assert.ok(!gate.take(EP_A), "loosening must not mint tokens");
    // ...but the wait until the next token follows the new rate.
    assert.equal(gate.msUntilToken(EP_A), 100);
    now += 100;
    assert.ok(gate.take(EP_A), "one token refilled after 100ms at 10 RPS");
  });

  it("rejects illegal values and leaves the live value untouched", () => {
    const gate = new ReplayEgressGate({ replaysPerSecond: 5 });
    for (const bad of [0, -1, NaN, Infinity, -Infinity]) {
      assert.throws(() => gate.retune({ replaysPerSecond: bad as number }), RangeError);
    }
    assert.deepEqual(gate.config(), { replaysPerSecond: 5 });
    assert.equal(gate.limit(), 5);
  });

  it("rejects an empty patch and non-object patches", () => {
    const gate = new ReplayEgressGate({ replaysPerSecond: 5 });
    assert.throws(() => gate.retune({}), RangeError);
    for (const bad of [null, [], "5", 5, undefined]) {
      assert.throws(() => gate.retune(bad as never), RangeError);
    }
    assert.deepEqual(gate.config(), { replaysPerSecond: 5 });
  });

  it("same-value patch is a no-op; config() is a snapshot and limit() follows the live value", () => {
    const gate = new ReplayEgressGate({ replaysPerSecond: 5 });
    assert.deepEqual(gate.retune({ replaysPerSecond: 5 }), { replaysPerSecond: 5 });
    const snap = gate.config();
    snap.replaysPerSecond = 999;
    assert.deepEqual(gate.config(), { replaysPerSecond: 5 }, "mutating the snapshot must not move the gate");
    assert.deepEqual(gate.retune({ replaysPerSecond: 3 }), { replaysPerSecond: 3 });
    assert.equal(gate.limit(), 3);
  });
});

describe("RetryQueue.reviseReplayEgress (WR-345)", () => {
  it("tightening replays fewer entries on the next batch", async () => {
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
    const r1 = q.replayDeadLetters();
    assert.deepEqual(r1.replayed, ["a", "b"]);
    assert.deepEqual(r1.throttled, ["c", "d", "e"]);
    assert.deepEqual(q.reviseReplayEgress({ replaysPerSecond: 1 }), { replaysPerSecond: 1 });
    clock.now += 1000; // one token at the tightened rate (two at the old one)
    const r2 = q.replayDeadLetters();
    assert.deepEqual(r2.replayed, ["c"]);
    assert.deepEqual(r2.throttled, ["d", "e"]);
    q.stop();
  });

  it("loosening replays more entries on the next batch once time has passed", async () => {
    const clock = { now: 0 };
    const { q, timer } = seedDeadLetters(
      [
        { id: "a", targetUrl: EP_A },
        { id: "b", targetUrl: EP_A },
        { id: "c", targetUrl: EP_A },
      ],
      { replayEgress: { replaysPerSecond: 1 } },
      clock
    );
    await timer.run();
    const r1 = q.replayDeadLetters();
    assert.deepEqual(r1.replayed, ["a"]);
    assert.deepEqual(r1.throttled, ["b", "c"]);
    assert.deepEqual(q.reviseReplayEgress({ replaysPerSecond: 10 }), { replaysPerSecond: 10 });
    clock.now += 1000; // a full bucket at the loosened rate (one token at the old one)
    const r2 = q.replayDeadLetters();
    assert.deepEqual(r2.replayed, ["b", "c"]);
    assert.deepEqual(r2.throttled, []);
    q.stop();
  });

  it("revision never resets the cumulative throttled counter", async () => {
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
    q.replayDeadLetters();
    assert.equal(q.getDeadLetterStats().throttled, 3);
    q.reviseReplayEgress({ replaysPerSecond: 1 });
    clock.now += 1000;
    q.replayDeadLetters();
    assert.equal(q.getDeadLetterStats().throttled, 5, "3 + 2 throttled across the revision");
    assert.deepEqual(q.getReplayEgressConfig(), { replaysPerSecond: 1 });
    q.stop();
  });

  it("unconfigured queue throws must-restart and the getter returns undefined", () => {
    const q = new RetryQueue({
      sender: async () => {
        throw new Error("downstream 500");
      },
      baseDelayMs: 1,
      maxAttempts: 2,
      jitterMs: 0,
    });
    assert.equal(q.getReplayEgressConfig(), undefined);
    assert.equal(q.getReplayEgressGate(), undefined);
    assert.throws(() => q.reviseReplayEgress({ replaysPerSecond: 3 }), { name: "Error", message: MUST_RESTART });
    q.stop();
  });

  it("manual replay and the WR-31 auto-replayer share the revised rate", async () => {
    const clock = { now: 0 };
    const timer = manualTimer();
    const replayTimer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {
        throw new Error("downstream 500");
      },
      baseDelayMs: 1,
      maxAttempts: 2,
      jitterMs: 0,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      replayEgress: { replaysPerSecond: 1, now: () => clock.now },
      autoReplay: {
        enabled: true,
        intervalMs: 1000,
        maxRounds: 10,
        setTimer: replayTimer.setTimer,
        clearTimer: replayTimer.clearTimer,
      },
    });
    const replayer = q.getAutoReplayer();
    assert.ok(replayer, "auto-replay scheduler must exist when configured");
    q.start();
    for (const id of ["a", "b"]) {
      q.enqueue({ id, payload: Buffer.from(`payload-${id}`), targetUrl: EP_A, headers: {} });
    }
    await timer.run();
    assert.equal(q.getDeadLetter().length, 2);

    // The manual replay spends the single token; the auto round right
    // after it finds the bucket empty — one shared gate.
    const manual = q.replayDeadLetters();
    assert.deepEqual(manual.replayed, ["a"]);
    assert.deepEqual(manual.throttled, ["b"]);
    const round1 = replayer.triggerOnce();
    assert.deepEqual(round1.replayed, []);
    assert.deepEqual(round1.throttled, ["b"]);

    // Loosen the shared rate: the next auto round admits the held entry.
    q.reviseReplayEgress({ replaysPerSecond: 10 });
    clock.now += 1000;
    const round2 = replayer.triggerOnce();
    assert.deepEqual(round2.replayed, ["b"]);
    assert.deepEqual(round2.throttled, []);
    assert.equal(q.getDeadLetter().length, 0);
    q.stop();
  });

  it("single-id replayDeadLetter(id) still bypasses the gate after revision", async () => {
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
    q.reviseReplayEgress({ replaysPerSecond: 5 });
    // The budget is still empty (loosening adds no tokens), but a single
    // hand-picked replay goes through — the escape hatch is untouched.
    assert.ok(q.replayDeadLetter("b"), "single-id replay bypasses the egress gate");
    q.stop();
  });

  it("getter and limit() follow the live value", async () => {
    const clock = { now: 0 };
    const { q, timer } = seedDeadLetters([{ id: "a", targetUrl: EP_A }], { replayEgress: { replaysPerSecond: 4 } }, clock);
    await timer.run();
    assert.deepEqual(q.getReplayEgressConfig(), { replaysPerSecond: 4 });
    assert.equal(q.getReplayEgressGate()?.limit(), 4);
    assert.deepEqual(q.reviseReplayEgress({ replaysPerSecond: 7 }), { replaysPerSecond: 7 });
    assert.deepEqual(q.getReplayEgressConfig(), { replaysPerSecond: 7 });
    assert.equal(q.getReplayEgressGate()?.limit(), 7);
    q.stop();
  });
});

describe("RelayServer replay egress revision (WR-345)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function listen(server: Server): Promise<number> {
    return new Promise<number>((resolve) => {
      server.listen(0, "127.0.0.1", () => {
        const addr = server.address();
        assert.ok(addr && typeof addr === "object");
        resolve(addr.port);
      });
    });
  }

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "replay-egress-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: signingKey,
      forwardUrl: URL_A,
      auditLog: audit,
      operatorToken: opToken,
      sender: async () => ({ statusCode: 200, body: Buffer.from("ok") }),
      retry: { baseDelayMs: 5, jitterMs: 0, maxAttempts: 2 },
      ...extra,
    });
    servers.push(relay);
    return { relay, audit };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  it("revision audits previous/current exactly; same-value is a silent no-op", async () => {
    const { relay, audit } = makeRelay({ replayEgress: { replaysPerSecond: 5 } });
    await listen(relay);
    // First `previous` is the construction config.
    assert.deepEqual(relay.getReplayEgressConfig!(), { replaysPerSecond: 5 });
    assert.deepEqual(relay.reviseReplayEgress!({ replaysPerSecond: 2 }), { replaysPerSecond: 2 });
    const revised = eventsOf(audit, "replay_egress_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, { replaysPerSecond: 5 });
    assert.deepEqual(revised[0].current, { replaysPerSecond: 2 });
    // Landing exactly on the live values audits nothing.
    relay.reviseReplayEgress!({ replaysPerSecond: 2 });
    assert.equal(eventsOf(audit, "replay_egress_revised").length, 1);
    assert.deepEqual(relay.getReplayEgressConfig!(), { replaysPerSecond: 2 });
    // A second real revision chains previous from the revised values.
    relay.reviseReplayEgress!({ replaysPerSecond: 3 });
    const revised2 = eventsOf(audit, "replay_egress_revised");
    assert.equal(revised2.length, 2);
    assert.deepEqual(revised2[1].previous, { replaysPerSecond: 2 });
    assert.deepEqual(revised2[1].current, { replaysPerSecond: 3 });
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseReplayEgress!({ replaysPerSecond: 0 }), RangeError);
    assert.throws(() => relay.reviseReplayEgress!({}), RangeError);
    assert.throws(() => relay.reviseReplayEgress!(null as never), RangeError);
    assert.equal(eventsOf(audit, "replay_egress_revised").length, 2);
    assert.deepEqual(relay.getReplayEgressConfig!(), { replaysPerSecond: 3 });
    // The getter returns a snapshot, not a live reference.
    const snap = relay.getReplayEgressConfig!();
    snap.replaysPerSecond = 999;
    assert.deepEqual(relay.getReplayEgressConfig!(), { replaysPerSecond: 3 });
  });

  it("first previous is the default 10 when configured with an empty object", async () => {
    const { relay, audit } = makeRelay({ replayEgress: {} });
    await listen(relay);
    assert.deepEqual(relay.getReplayEgressConfig!(), { replaysPerSecond: 10 });
    assert.deepEqual(relay.reviseReplayEgress!({ replaysPerSecond: 4 }), { replaysPerSecond: 4 });
    const revised = eventsOf(audit, "replay_egress_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, { replaysPerSecond: 10 });
    assert.deepEqual(revised[0].current, { replaysPerSecond: 4 });
  });

  it("unconfigured server throws must-restart and mounts no getter", async () => {
    const { relay } = makeRelay({});
    await listen(relay);
    assert.equal(relay.getReplayEgressConfig, undefined);
    assert.throws(() => relay.reviseReplayEgress!({ replaysPerSecond: 3 }), {
      name: "Error",
      message: MUST_RESTART,
    });
  });
});
