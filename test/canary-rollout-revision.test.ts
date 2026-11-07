import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type Sender } from "../src/retry.ts";
import {
  CanaryRolloutManager,
  type CanaryRolloutEvent,
} from "../src/canary-rollout.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "canary-rollout-revision-test-key";
const opToken = "canary-rollout-revision-op-token";
const PRIMARY = "http://127.0.0.1:9921/primary";
const CANDIDATE = "http://127.0.0.1:9922/candidate";
const UNKNOWN = "http://127.0.0.1:9929/unknown";

const DEFAULT_TUNING = {
  steps: [1, 5, 25, 50, 100],
  dwellMs: 60_000,
  maxConsecutiveStepFailures: 5,
  maxStepFailureRate: 0.1,
  minStepSamples: 10,
};

/** Manual clock + deterministic coin flip for the manager tests. */
function manualRollout(opts: { nowMs?: number; random?: number } = {}) {
  let nowMs = opts.nowMs ?? 0;
  let randomValue = opts.random ?? 0;
  return {
    now: () => nowMs,
    advance: (ms: number) => {
      nowMs += ms;
    },
    setNow: (ms: number) => {
      nowMs = ms;
    },
    random: () => randomValue,
    setRandom: (v: number) => {
      randomValue = v;
    },
  };
}

describe("canary rollout revision: CanaryRolloutManager (WR-351)", () => {
  it("replacing steps changes the next dispatch's coin flip immediately", () => {
    const clock = manualRollout({ random: 0.6 });
    const m = new CanaryRolloutManager(
      { [PRIMARY]: { candidate: CANDIDATE, steps: [50] } },
      { now: clock.now, random: clock.random }
    );
    assert.equal(m.resolveTarget(PRIMARY), PRIMARY); // 60 >= 50
    assert.deepEqual(m.retune(PRIMARY, { steps: [90] }), {
      steps: [90],
      dwellMs: 60_000,
      maxConsecutiveStepFailures: 5,
      maxStepFailureRate: 0.1,
      minStepSamples: 10,
    });
    assert.equal(m.resolveTarget(PRIMARY), CANDIDATE); // 60 < 90
    assert.equal(m.stats()[0].candidateDispatched, 1);
  });

  it("shortening dwellMs advances on the next dispatch; lengthening it delays the advance", () => {
    const shortenedClock = manualRollout({ random: 0.99 });
    const shortened = new CanaryRolloutManager(
      { [PRIMARY]: { candidate: CANDIDATE, steps: [1, 100], dwellMs: 60_000 } },
      { now: shortenedClock.now, random: shortenedClock.random }
    );
    assert.equal(shortened.resolveTarget(PRIMARY), PRIMARY);
    shortened.retune(PRIMARY, { dwellMs: 1000 });
    shortenedClock.advance(1000);
    assert.equal(shortened.resolveTarget(PRIMARY), CANDIDATE);
    assert.equal(shortened.stats()[0].step, 1);

    const lengthenedClock = manualRollout({ random: 0.99 });
    const lengthened = new CanaryRolloutManager(
      { [PRIMARY]: { candidate: CANDIDATE, steps: [1, 100], dwellMs: 1000 } },
      { now: lengthenedClock.now, random: lengthenedClock.random }
    );
    lengthened.retune(PRIMARY, { dwellMs: 60_000 });
    lengthenedClock.advance(1000); // the old dwell would have advanced here
    assert.equal(lengthened.resolveTarget(PRIMARY), PRIMARY);
    assert.equal(lengthened.stats()[0].step, 0);
    lengthenedClock.advance(59_000);
    assert.equal(lengthened.resolveTarget(PRIMARY), CANDIDATE);
    assert.equal(lengthened.stats()[0].step, 1);
  });

  it("tightening the consecutive-failure gate rolls back on the same-size batch under the new gate", () => {
    const events: CanaryRolloutEvent[] = [];
    const clock = manualRollout({ random: 0 });
    const m = new CanaryRolloutManager(
      { [PRIMARY]: { candidate: CANDIDATE, steps: [100], maxConsecutiveStepFailures: 5 } },
      { now: clock.now, random: clock.random, onEvent: (e) => events.push(e) }
    );
    assert.equal(m.resolveTarget(PRIMARY), CANDIDATE);
    m.recordOutcome(PRIMARY, CANDIDATE, false);
    m.recordOutcome(PRIMARY, CANDIDATE, false);
    assert.equal(m.stats()[0].state, "rolling");
    m.retune(PRIMARY, { maxConsecutiveStepFailures: 3 });
    // The revision starts a new experiment (counters cleared), so the
    // same-size batch is re-run under the tightened gate: 3 failures
    // now burn the budget that used to need 5.
    m.recordOutcome(PRIMARY, CANDIDATE, false);
    m.recordOutcome(PRIMARY, CANDIDATE, false);
    m.recordOutcome(PRIMARY, CANDIDATE, false);
    assert.equal(m.stats()[0].state, "rolled_back");
    assert.equal(events.length, 1);
    assert.equal(events[0].event, "canary_rolled_back");
    assert.equal(events[0].reason, "consecutive_failures");
  });

  it("illegal values throw RangeError and leave the live tuning and step counters intact", () => {
    const clock = manualRollout({ random: 0 });
    const m = new CanaryRolloutManager(
      { [PRIMARY]: { candidate: CANDIDATE, steps: [1, 5, 25], dwellMs: 1000 } },
      { now: clock.now, random: clock.random }
    );
    assert.equal(m.resolveTarget(PRIMARY), CANDIDATE);
    m.recordOutcome(PRIMARY, CANDIDATE, false);
    m.recordOutcome(PRIMARY, CANDIDATE, false);
    const before = m.config(PRIMARY);
    const badPatches = [
      { steps: [] },
      { steps: [5, 5] },
      { steps: [50, 25] },
      { steps: [0] },
      { steps: [101] },
      { steps: [50, "x" as never] },
      { dwellMs: 0 },
      { dwellMs: -1 },
      { maxConsecutiveStepFailures: 0 },
      { maxConsecutiveStepFailures: 1.5 },
      { maxStepFailureRate: 0 },
      { maxStepFailureRate: 1.5 },
      { minStepSamples: 0 },
      // A half-legal patch must not apply the legal half.
      { steps: [1, 2], dwellMs: 0 },
    ];
    for (const patch of badPatches) {
      assert.throws(() => m.retune(PRIMARY, patch), RangeError);
    }
    assert.deepEqual(m.config(PRIMARY), before);
    assert.equal(m.stats()[0].stepSamples, 2);
    assert.equal(m.stats()[0].stepFailures, 2);
  });

  it("empty/non-object patches throw RangeError", () => {
    const m = new CanaryRolloutManager(
      { [PRIMARY]: { candidate: CANDIDATE } },
      { now: () => 0, random: () => 0 }
    );
    assert.throws(() => m.retune(PRIMARY, {}), RangeError);
    assert.throws(() => m.retune(PRIMARY, null as never), RangeError);
    assert.throws(() => m.retune(PRIMARY, "x" as never), RangeError);
    assert.throws(() => m.retune(PRIMARY, [] as never), RangeError);
  });

  it("same-value patch is a no-op: it does not reset the step clock or counters", () => {
    const clock = manualRollout({ random: 0 });
    const m = new CanaryRolloutManager(
      { [PRIMARY]: { candidate: CANDIDATE, steps: [1, 100], dwellMs: 1000 } },
      { now: clock.now, random: clock.random }
    );
    assert.equal(m.resolveTarget(PRIMARY), CANDIDATE);
    m.recordOutcome(PRIMARY, CANDIDATE, false);
    assert.deepEqual(m.retune(PRIMARY, { dwellMs: 1000 }), {
      steps: [1, 100],
      dwellMs: 1000,
      maxConsecutiveStepFailures: 5,
      maxStepFailureRate: 0.1,
      minStepSamples: 10,
    });
    assert.equal(m.stats()[0].stepSamples, 1);
    assert.equal(m.stats()[0].stepFailures, 1);
    // The clock was NOT reset by the no-op: half the dwell has passed,
    // and the advance still lands exactly at the original boundary.
    clock.advance(500);
    m.retune(PRIMARY, { steps: [1, 100] });
    clock.advance(500);
    assert.equal(m.resolveTarget(PRIMARY), CANDIDATE);
    assert.equal(m.stats()[0].step, 1);
  });

  it("terminal states reject revision and the tuning stays put", () => {
    const clock = manualRollout({ random: 0 });
    const promoted = new CanaryRolloutManager(
      { [PRIMARY]: { candidate: CANDIDATE, steps: [100], dwellMs: 1 } },
      { now: clock.now, random: clock.random }
    );
    assert.equal(promoted.resolveTarget(PRIMARY), CANDIDATE);
    clock.advance(1);
    assert.equal(promoted.resolveTarget(PRIMARY), CANDIDATE);
    assert.equal(promoted.stats()[0].state, "promoted");
    const promotedBefore = promoted.config(PRIMARY);
    assert.throws(() => promoted.retune(PRIMARY, { dwellMs: 5000 }), /terminal/);
    assert.deepEqual(promoted.config(PRIMARY), promotedBefore);

    const rolledBack = new CanaryRolloutManager(
      { [PRIMARY]: { candidate: CANDIDATE, steps: [100], maxConsecutiveStepFailures: 2 } },
      { now: () => 0, random: () => 0 }
    );
    assert.equal(rolledBack.resolveTarget(PRIMARY), CANDIDATE);
    rolledBack.recordOutcome(PRIMARY, CANDIDATE, false);
    rolledBack.recordOutcome(PRIMARY, CANDIDATE, false);
    assert.equal(rolledBack.stats()[0].state, "rolled_back");
    const rolledBackBefore = rolledBack.config(PRIMARY);
    assert.throws(() => rolledBack.retune(PRIMARY, { dwellMs: 5000 }), /terminal/);
    assert.deepEqual(rolledBack.config(PRIMARY), rolledBackBefore);
  });

  it("unconfigured endpoints report undefined and throw on retune", () => {
    const m = new CanaryRolloutManager(
      { [PRIMARY]: { candidate: CANDIDATE } },
      { now: () => 0, random: () => 0 }
    );
    assert.equal(m.config(UNKNOWN), undefined);
    assert.throws(
      () => m.retune(UNKNOWN, { dwellMs: 1000 }),
      /no canary rollout configured for endpoint/
    );
  });

  it("shortening steps clamps stepIndex and zeroes the step counters; the new ceiling holds", () => {
    const clock = manualRollout({ random: 0 });
    const m = new CanaryRolloutManager(
      { [PRIMARY]: { candidate: CANDIDATE, steps: [1, 5, 25, 50, 100], dwellMs: 1 } },
      { now: clock.now, random: clock.random }
    );
    assert.equal(m.resolveTarget(PRIMARY), CANDIDATE); // step 0
    clock.advance(1);
    assert.equal(m.resolveTarget(PRIMARY), CANDIDATE); // step 1
    clock.advance(1);
    assert.equal(m.resolveTarget(PRIMARY), CANDIDATE); // step 2
    m.recordOutcome(PRIMARY, CANDIDATE, false);
    m.recordOutcome(PRIMARY, CANDIDATE, false);
    assert.equal(m.stats()[0].stepSamples, 2);

    assert.deepEqual(m.retune(PRIMARY, { steps: [1, 5] }), {
      steps: [1, 5],
      dwellMs: 1,
      maxConsecutiveStepFailures: 5,
      maxStepFailureRate: 0.1,
      minStepSamples: 10,
    });
    assert.equal(m.stats()[0].step, 1); // clamped to the new last step
    assert.equal(m.stats()[0].stepSamples, 0);
    assert.equal(m.stats()[0].stepFailures, 0);
    // The new ramp's last step (5%) is below 100%: it holds forever.
    clock.advance(1);
    assert.equal(m.resolveTarget(PRIMARY), CANDIDATE);
    assert.equal(m.stats()[0].step, 1);
    assert.equal(m.stats()[0].state, "rolling");
  });

  it("revision does not reset candidateDispatched and does not change candidate/primary", () => {
    const clock = manualRollout({ random: 0 });
    const m = new CanaryRolloutManager(
      { [PRIMARY]: { candidate: CANDIDATE, steps: [100] } },
      { now: clock.now, random: clock.random }
    );
    m.resolveTarget(PRIMARY);
    m.resolveTarget(PRIMARY);
    m.resolveTarget(PRIMARY);
    assert.equal(m.stats()[0].candidateDispatched, 3);
    m.retune(PRIMARY, { steps: [50] });
    assert.equal(m.stats()[0].candidateDispatched, 3);
    assert.equal(m.stats()[0].candidate, CANDIDATE);
    assert.equal(m.resolveTarget(PRIMARY), CANDIDATE);
    assert.equal(m.stats()[0].candidateDispatched, 4);
    clock.setRandom(0.99);
    assert.equal(m.resolveTarget(PRIMARY), PRIMARY); // 99 >= 50
    assert.equal(m.stats()[0].candidate, CANDIDATE);
  });

  it("config returns a steps copy, not the live array", () => {
    const m = new CanaryRolloutManager(
      { [PRIMARY]: { candidate: CANDIDATE, steps: [1, 5, 25] } },
      { now: () => 0, random: () => 0 }
    );
    const snapshot = m.config(PRIMARY)!;
    snapshot.steps.push(100);
    assert.deepEqual(m.config(PRIMARY)!.steps, [1, 5, 25]);
  });
});

describe("canary rollout revision: RetryQueue (WR-351)", () => {
  it("configured queue: revise/get round-trip; unconfigured endpoint throws the must-restart Error", () => {
    const q = new RetryQueue({
      sender: async () => ({ statusCode: 200, body: Buffer.from("ok") }),
      canaryRollouts: { [PRIMARY]: { candidate: CANDIDATE } },
      canaryNow: () => 0,
      canaryRandom: () => 0,
    });
    assert.deepEqual(q.getCanaryRollout(PRIMARY), DEFAULT_TUNING);
    assert.deepEqual(q.reviseCanaryRollout(PRIMARY, { steps: [1, 5] }), {
      ...DEFAULT_TUNING,
      steps: [1, 5],
    });
    assert.deepEqual(q.getCanaryRollout(PRIMARY), { ...DEFAULT_TUNING, steps: [1, 5] });
    assert.throws(() => q.reviseCanaryRollout(PRIMARY, { dwellMs: 0 }), RangeError);
    assert.deepEqual(q.getCanaryRollout(PRIMARY), { ...DEFAULT_TUNING, steps: [1, 5] });
    assert.equal(q.getCanaryRollout(UNKNOWN), undefined);
    assert.throws(
      () => q.reviseCanaryRollout(UNKNOWN, { dwellMs: 1000 }),
      /reviseCanaryRollout: canary rollout is not configured for endpoint .* — enabling it requires a restart/
    );
    const bare = new RetryQueue({
      sender: async () => ({ statusCode: 200, body: Buffer.from("ok") }),
    });
    assert.equal(bare.getCanaryRollout(PRIMARY), undefined);
    assert.throws(
      () => bare.reviseCanaryRollout(PRIMARY, { dwellMs: 1000 }),
      /reviseCanaryRollout: canary rollout is not configured for endpoint .* — enabling it requires a restart/
    );
  });
});

describe("canary rollout revision: RelayServer (WR-351)", () => {
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
    const dir = mkdtempSync(join(tmpdir(), "canary-rollout-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: signingKey,
      forwardUrl: PRIMARY,
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

  it("revision audits endpoint/previous/current with the construction values first; same-value is a silent no-op", async () => {
    const { relay, audit } = makeRelay({
      retry: {
        canaryRollouts: {
          [PRIMARY]: { candidate: CANDIDATE, steps: [1, 5, 25], dwellMs: 5000 },
        },
      },
    });
    await listen(relay);
    assert.deepEqual(relay.getCanaryRollout!(PRIMARY), {
      steps: [1, 5, 25],
      dwellMs: 5000,
      maxConsecutiveStepFailures: 5,
      maxStepFailureRate: 0.1,
      minStepSamples: 10,
    });
    assert.deepEqual(
      relay.reviseCanaryRollout!(PRIMARY, { steps: [1, 5], dwellMs: 1000 }),
      {
        steps: [1, 5],
        dwellMs: 1000,
        maxConsecutiveStepFailures: 5,
        maxStepFailureRate: 0.1,
        minStepSamples: 10,
      }
    );
    const revised = eventsOf(audit, "canary_rollout_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].endpoint, PRIMARY);
    assert.deepEqual(revised[0].previous, {
      steps: [1, 5, 25],
      dwellMs: 5000,
      maxConsecutiveStepFailures: 5,
      maxStepFailureRate: 0.1,
      minStepSamples: 10,
    });
    assert.deepEqual(revised[0].current, {
      steps: [1, 5],
      dwellMs: 1000,
      maxConsecutiveStepFailures: 5,
      maxStepFailureRate: 0.1,
      minStepSamples: 10,
    });
    // Landing exactly on the live values audits nothing.
    relay.reviseCanaryRollout!(PRIMARY, { dwellMs: 1000 });
    assert.equal(eventsOf(audit, "canary_rollout_revised").length, 1);
    // An illegal patch throws and leaves the live values and audit untouched.
    assert.throws(() => relay.reviseCanaryRollout!(PRIMARY, { dwellMs: 0 }), RangeError);
    assert.throws(() => relay.reviseCanaryRollout!(PRIMARY, {} as never), RangeError);
    assert.equal(eventsOf(audit, "canary_rollout_revised").length, 1);
    assert.deepEqual(relay.getCanaryRollout!(PRIMARY), {
      steps: [1, 5],
      dwellMs: 1000,
      maxConsecutiveStepFailures: 5,
      maxStepFailureRate: 0.1,
      minStepSamples: 10,
    });
  });

  it("defaults apply when unset; the getter is always set and returns undefined for unconfigured endpoints", async () => {
    const { relay } = makeRelay({
      retry: { canaryRollouts: { [PRIMARY]: { candidate: CANDIDATE } } },
    });
    await listen(relay);
    assert.deepEqual(relay.getCanaryRollout!(PRIMARY), DEFAULT_TUNING);
    assert.equal(relay.getCanaryRollout!(UNKNOWN), undefined);
    assert.throws(
      () => relay.reviseCanaryRollout!(UNKNOWN, { dwellMs: 1000 }),
      /not configured for endpoint .* — enabling it requires a restart/
    );
    const bare = makeRelay();
    await listen(bare.relay);
    assert.equal(bare.relay.getCanaryRollout!(PRIMARY), undefined);
    assert.throws(
      () => bare.relay.reviseCanaryRollout!(PRIMARY, { dwellMs: 1000 }),
      /not configured for endpoint .* — enabling it requires a restart/
    );
  });
});
