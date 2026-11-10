import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import {
  SenderReputationTracker,
  type ReputationConfig,
} from "../src/reputation.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "reputation-revision-test-key";
const opToken = "reputation-revision-op-token";
const forwardUrl = "http://localhost:9999/hook";

const construction: ReputationConfig = {
  halfLifeMs: 600_000,
  lowThreshold: 40,
  highThreshold: 70,
  verifyFailurePenalty: 25,
  rateLimitPenalty: 5,
  schemaViolationPenalty: 10,
};

/** Controllable clock for the module-level tests. */
function makeClock(startMs = 1_000_000) {
  let at = startMs;
  return {
    now: () => at,
    advance: (ms: number) => {
      at += ms;
    },
  };
}

describe("SenderReputationTracker.retune (WR-379)", () => {
  it("tightening lowThreshold makes the next penalty downgrade", () => {
    const clock = makeClock();
    const tracker = new SenderReputationTracker({ now: clock.now });
    assert.equal(tracker.recordPenalty("s", "verify_failure"), undefined);
    assert.equal(tracker.score("s"), 75);
    // 65 stays below the live high (70), so the merged config is valid.
    assert.deepEqual(tracker.retune({ lowThreshold: 65 }), { ...construction, lowThreshold: 65 });
    const transition = tracker.recordPenalty("s", "verify_failure");
    assert.equal(transition?.kind, "downgraded");
    assert.equal(transition?.score, 50);
    assert.equal(tracker.isDegraded("s"), true);
  });

  it("loosening highThreshold does not upgrade immediately; quiet recovery upgrades past the new high", () => {
    const clock = makeClock();
    const tracker = new SenderReputationTracker({ now: clock.now });
    tracker.recordPenalty("s", "verify_failure");
    tracker.recordPenalty("s", "verify_failure");
    const transition = tracker.recordPenalty("s", "verify_failure");
    assert.equal(transition?.kind, "downgraded");
    assert.equal(tracker.isDegraded("s"), true);
    // 45 stays above the live low (40), so the merged config is valid.
    tracker.retune({ highThreshold: 45 });
    // Still degraded right after loosening: the score has not moved.
    assert.equal(tracker.score("s"), 25);
    assert.equal(tracker.observe("s").transition, undefined);
    assert.equal(tracker.isDegraded("s"), true);
    // One half-life of quiet: demerit 75 -> 37.5, score 62.5 > 45.
    clock.advance(600_000);
    const view = tracker.observe("s");
    assert.equal(view.transition?.kind, "upgraded");
    assert.equal(view.degraded, false);
  });

  it("enlarging the half-life slows later decay", () => {
    const clockA = makeClock();
    const a = new SenderReputationTracker({ now: clockA.now });
    a.recordPenalty("s", "verify_failure");
    clockA.advance(600_000);
    assert.equal(a.score("s"), 87.5);

    const clockB = makeClock();
    const b = new SenderReputationTracker({ now: clockB.now });
    b.recordPenalty("s", "verify_failure");
    b.retune({ halfLifeMs: 1_200_000 });
    clockB.advance(600_000);
    const expected = 100 - 25 * Math.SQRT1_2;
    assert.ok(Math.abs(b.score("s") - expected) < 1e-9, `score=${b.score("s")}, want ${expected}`);
    assert.ok(b.score("s") < a.score("s"));
  });

  it("a penalty weight only governs later penalties", () => {
    const clock = makeClock();
    const tracker = new SenderReputationTracker({ now: clock.now });
    tracker.recordPenalty("s", "verify_failure");
    assert.equal(tracker.score("s"), 75);
    tracker.retune({ verifyFailurePenalty: 5 });
    tracker.recordPenalty("s", "verify_failure");
    // 25 (old weight) + 5 (new weight) = 30 demerit, not 50.
    assert.equal(tracker.score("s"), 70);
  });

  it("illegal values throw RangeError and the live config is untouched", () => {
    const clock = makeClock();
    const tracker = new SenderReputationTracker({ now: clock.now });
    const bad = [
      { halfLifeMs: 0 },
      { halfLifeMs: -1 },
      { halfLifeMs: Number.NaN },
      { halfLifeMs: Number.POSITIVE_INFINITY },
      { lowThreshold: -1 },
      { lowThreshold: 101 },
      { highThreshold: 101 },
      { verifyFailurePenalty: -1 },
      { rateLimitPenalty: Number.NaN },
      { schemaViolationPenalty: Number.POSITIVE_INFINITY },
      // Merged cross-check: patching only low above the live high.
      { lowThreshold: 80 },
      // Merged cross-check: patching only high below the live low.
      { highThreshold: 30 },
      { lowThreshold: 70, highThreshold: 70 },
      { lowThreshold: 80, highThreshold: 70 },
    ];
    for (const patch of bad) {
      assert.throws(() => tracker.retune(patch), RangeError, JSON.stringify(patch));
      assert.deepEqual(tracker.snapshot(), construction);
    }
    assert.throws(() => tracker.retune(null as never), RangeError);
    assert.throws(() => tracker.retune("tighten" as never), RangeError);
    assert.throws(() => tracker.retune({}), RangeError);
    assert.deepEqual(tracker.snapshot(), construction);
  });

  it("a same-value patch is a silent no-op returning the live config", () => {
    const clock = makeClock();
    const tracker = new SenderReputationTracker({ now: clock.now });
    assert.deepEqual(tracker.retune({ lowThreshold: 40 }), construction);
    assert.deepEqual(tracker.retune({ ...construction }), construction);
  });

  it("retune never resets accumulated demerit, score, degraded state, or downgrade counts", () => {
    const clock = makeClock();
    const tracker = new SenderReputationTracker({ now: clock.now });
    tracker.recordPenalty("s", "verify_failure");
    tracker.recordPenalty("s", "verify_failure");
    tracker.recordPenalty("s", "verify_failure");
    assert.equal(tracker.isDegraded("s"), true);
    assert.equal(tracker.metricsSnapshot()[0].downgrades, 1);
    tracker.retune({ halfLifeMs: 300_000, verifyFailurePenalty: 1 });
    assert.equal(tracker.score("s"), 25);
    assert.equal(tracker.isDegraded("s"), true);
    assert.equal(tracker.trackedSenders(), 1);
    assert.equal(tracker.metricsSnapshot()[0].downgrades, 1);
  });
});

describe("RelayServer sender reputation revision (WR-379)", () => {
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
    const dir = mkdtempSync(join(tmpdir(), "reputation-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: signingKey,
      forwardUrl,
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

  it("revision audits previous/current with all six knobs exactly; same-value is a silent no-op", async () => {
    const { relay, audit } = makeRelay({ senderReputation: { ...construction } });
    await listen(relay);
    assert.deepEqual(relay.getSenderReputationConfig!(), construction);
    assert.deepEqual(relay.reviseSenderReputation!({ lowThreshold: 30, verifyFailurePenalty: 10 }), {
      ...construction,
      lowThreshold: 30,
      verifyFailurePenalty: 10,
    });
    const revised = eventsOf(audit, "sender_reputation_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, construction);
    assert.deepEqual(revised[0].current, {
      ...construction,
      lowThreshold: 30,
      verifyFailurePenalty: 10,
    });
    // Landing exactly on the live values audits nothing.
    relay.reviseSenderReputation!({ lowThreshold: 30, verifyFailurePenalty: 10 });
    assert.equal(eventsOf(audit, "sender_reputation_revised").length, 1);
    assert.deepEqual(relay.getSenderReputationConfig!(), {
      ...construction,
      lowThreshold: 30,
      verifyFailurePenalty: 10,
    });
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseSenderReputation!({ lowThreshold: 80 }), RangeError);
    assert.throws(() => relay.reviseSenderReputation!({}), RangeError);
    assert.equal(eventsOf(audit, "sender_reputation_revised").length, 1);
    assert.deepEqual(relay.getSenderReputationConfig!(), {
      ...construction,
      lowThreshold: 30,
      verifyFailurePenalty: 10,
    });
  });

  it("unconfigured relay: revise is always set but throws the must-restart Error, and the getter is not mounted", async () => {
    const { relay } = makeRelay();
    await listen(relay);
    assert.equal(typeof relay.reviseSenderReputation, "function");
    assert.equal(relay.getSenderReputationConfig, undefined);
    assert.throws(
      () => relay.reviseSenderReputation!({ lowThreshold: 30 }),
      /reviseSenderReputation: sender reputation is not configured — enabling it requires a restart/
    );
  });
});
