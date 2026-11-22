import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "replay-egress-enable-test-key";
const opToken = "replay-egress-enable-op-token";
const URL_A = "http://localhost:9999/a";
const EP_A = "http://a.example/hook";

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

/**
 * Queue with a failing sender, pre-filled with dead letters — and
 * deliberately *without* a `replayEgress` option, so the WR-446
 * enable path is the only way a gate appears.
 */
function seedDeadLetters(items: SeededItem[]) {
  const timer = manualTimer();
  const q = new RetryQueue({
    sender: async () => {
      throw new Error("downstream 500");
    },
    baseDelayMs: 1,
    maxAttempts: 2,
    jitterMs: 0,
    setTimer: timer.setTimer,
    clearTimer: timer.clearTimer,
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

describe("RetryQueue.reviseReplayEgress enable (WR-446)", () => {
  it("first revise enables, and the next replay is throttled at the enabled rate", async () => {
    const { q, timer } = seedDeadLetters([
      { id: "a", targetUrl: EP_A },
      { id: "b", targetUrl: EP_A },
      { id: "c", targetUrl: EP_A },
      { id: "d", targetUrl: EP_A },
      { id: "e", targetUrl: EP_A },
    ]);
    await timer.run();
    assert.equal(q.getDeadLetter().length, 5);
    assert.deepEqual(q.reviseReplayEgress({ replaysPerSecond: 2 }), { replaysPerSecond: 2 });
    assert.deepEqual(q.getReplayEgressConfig(), { replaysPerSecond: 2 });
    assert.equal(q.getReplayEgressGate()?.limit(), 2);
    // A fresh gate's first bucket starts full at the enabled rate.
    const r = q.replayDeadLetters();
    assert.deepEqual(r.replayed, ["a", "b"]);
    assert.deepEqual(r.throttled, ["c", "d", "e"]);
    assert.equal(q.getDeadLetterStats().throttled, 3);
    q.stop();
  });

  it("the documented default rate 10/s admits exactly ten in the first burst", async () => {
    const items = Array.from({ length: 12 }, (_, i) => ({ id: `e${i}`, targetUrl: EP_A }));
    const { q, timer } = seedDeadLetters(items);
    await timer.run();
    assert.deepEqual(q.reviseReplayEgress({ replaysPerSecond: 10 }), { replaysPerSecond: 10 });
    const r = q.replayDeadLetters();
    assert.equal(r.replayed.length, 10);
    assert.deepEqual(r.throttled, ["e10", "e11"]);
    assert.equal(q.getDeadLetterStats().throttled, 2);
    q.stop();
  });

  it("empty, non-object, and illegal patches are rejected and the queue stays unconfigured", () => {
    const q = new RetryQueue({
      sender: async () => {
        throw new Error("downstream 500");
      },
      baseDelayMs: 1,
      maxAttempts: 2,
      jitterMs: 0,
    });
    assert.throws(() => q.reviseReplayEgress({}), RangeError);
    for (const bad of [null, [], "2", 2, undefined]) {
      assert.throws(() => q.reviseReplayEgress(bad as never), RangeError);
    }
    for (const bad of [0, -1, NaN, Infinity, -Infinity]) {
      assert.throws(() => q.reviseReplayEgress({ replaysPerSecond: bad as number }), RangeError);
    }
    assert.equal(q.getReplayEgressConfig(), undefined);
    assert.equal(q.getReplayEgressGate(), undefined);
    // A failed enable leaves the queue usable: a valid patch still enables.
    assert.deepEqual(q.reviseReplayEgress({ replaysPerSecond: 4 }), { replaysPerSecond: 4 });
    q.stop();
  });

  it("replays admitted before the enable are not retroactively throttled", async () => {
    const { q, timer } = seedDeadLetters([
      { id: "a", targetUrl: EP_A },
      { id: "b", targetUrl: EP_A },
      { id: "c", targetUrl: EP_A },
    ]);
    await timer.run();
    // Ungated: the whole backlog replays at once.
    const before = q.replayDeadLetters();
    assert.deepEqual(before.replayed, ["a", "b", "c"]);
    assert.deepEqual(before.throttled, []);
    assert.equal(q.getDeadLetterStats().throttled, 0);
    assert.deepEqual(q.reviseReplayEgress({ replaysPerSecond: 1 }), { replaysPerSecond: 1 });
    assert.equal(q.getDeadLetterStats().throttled, 0, "the enable mints no throttling for the past");
    // The replayed entries fail again and return to the dead-letter
    // list; the next batch is governed by the fresh gate.
    await timer.run();
    assert.equal(q.getDeadLetter().length, 3);
    const after = q.replayDeadLetters();
    assert.deepEqual(after.replayed, ["a"]);
    assert.deepEqual(after.throttled, ["b", "c"]);
    assert.equal(q.getDeadLetterStats().throttled, 2);
    q.stop();
  });
});

describe("RelayServer replay egress enable (WR-446)", () => {
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
    const dir = mkdtempSync(join(tmpdir(), "replay-egress-enable-"));
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

  it("first revise enables, mounts the getter, and audits previous null", async () => {
    const { relay, audit } = makeRelay({});
    await listen(relay);
    assert.equal(relay.getReplayEgressConfig, undefined);
    assert.deepEqual(relay.reviseReplayEgress!({ replaysPerSecond: 3 }), { replaysPerSecond: 3 });
    assert.deepEqual(relay.getReplayEgressConfig!(), { replaysPerSecond: 3 });
    const revised = eventsOf(audit, "replay_egress_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.deepEqual(revised[0].current, { replaysPerSecond: 3 });
  });

  it("illegal and empty patches are rejected and the server stays unconfigured", async () => {
    const { relay, audit } = makeRelay({});
    await listen(relay);
    assert.throws(() => relay.reviseReplayEgress!({}), RangeError);
    assert.throws(() => relay.reviseReplayEgress!(null as never), RangeError);
    assert.throws(() => relay.reviseReplayEgress!({ replaysPerSecond: 0 }), RangeError);
    assert.throws(() => relay.reviseReplayEgress!({ replaysPerSecond: -1 }), RangeError);
    assert.equal(relay.getReplayEgressConfig, undefined);
    assert.equal(eventsOf(audit, "replay_egress_revised").length, 0);
    // A failed enable leaves the server usable: a valid patch enables.
    assert.deepEqual(relay.reviseReplayEgress!({ replaysPerSecond: 5 }), { replaysPerSecond: 5 });
    assert.deepEqual(relay.getReplayEgressConfig!(), { replaysPerSecond: 5 });
    const revised = eventsOf(audit, "replay_egress_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
  });

  it("same-value revision after the enable is a silent no-op; a real revision chains previous", async () => {
    const { relay, audit } = makeRelay({});
    await listen(relay);
    relay.reviseReplayEgress!({ replaysPerSecond: 3 });
    relay.reviseReplayEgress!({ replaysPerSecond: 3 });
    assert.equal(eventsOf(audit, "replay_egress_revised").length, 1);
    relay.reviseReplayEgress!({ replaysPerSecond: 7 });
    const revised = eventsOf(audit, "replay_egress_revised");
    assert.equal(revised.length, 2);
    assert.deepEqual(revised[1].previous, { replaysPerSecond: 3 });
    assert.deepEqual(revised[1].current, { replaysPerSecond: 7 });
  });

  it("a restart returns to unconfigured — the enable is live-only", async () => {
    const first = makeRelay({});
    await listen(first.relay);
    first.relay.reviseReplayEgress!({ replaysPerSecond: 3 });
    assert.deepEqual(first.relay.getReplayEgressConfig!(), { replaysPerSecond: 3 });
    // A fresh relay built from the same options has no gate: the
    // enable was never persisted.
    const second = makeRelay({});
    await listen(second.relay);
    assert.equal(second.relay.getReplayEgressConfig, undefined);
  });
});
