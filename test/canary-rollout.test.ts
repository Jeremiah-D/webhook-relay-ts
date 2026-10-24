import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest } from "node:http";
import {
  RetryQueue,
  type CanaryRolloutEvent,
  type Sender,
} from "../src/retry.ts";
import { CanaryRolloutManager, assertValidCanaryRolloutConfig } from "../src/canary-rollout.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const PRIMARY = "http://127.0.0.1:9921/primary";
const CANDIDATE = "http://127.0.0.1:9922/candidate";

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
        for (const fn of fns) fn();
        await new Promise((r) => setImmediate(r));
      }
    },
  };
}

function item(id: string, targetUrl: string = PRIMARY) {
  return { id, payload: Buffer.from("hello"), targetUrl, headers: {} };
}

describe("canary rollout config validation", () => {
  it("rejects illegal configs at construction", () => {
    const bad: Array<[string, object]> = [
      ["empty steps", { [PRIMARY]: { candidate: CANDIDATE, steps: [] } }],
      ["non-increasing steps", { [PRIMARY]: { candidate: CANDIDATE, steps: [25, 25] } }],
      ["decreasing steps", { [PRIMARY]: { candidate: CANDIDATE, steps: [50, 25] } }],
      ["step above 100", { [PRIMARY]: { candidate: CANDIDATE, steps: [101] } }],
      ["zero step", { [PRIMARY]: { candidate: CANDIDATE, steps: [0] } }],
      ["candidate equals primary", { [PRIMARY]: { candidate: PRIMARY } }],
      [
        "chained candidate",
        { [PRIMARY]: { candidate: CANDIDATE }, [CANDIDATE]: { candidate: PRIMARY } },
      ],
      ["zero dwell", { [PRIMARY]: { candidate: CANDIDATE, dwellMs: 0 } }],
      ["zero consecutive threshold", { [PRIMARY]: { candidate: CANDIDATE, maxConsecutiveStepFailures: 0 } }],
      ["zero failure rate", { [PRIMARY]: { candidate: CANDIDATE, maxStepFailureRate: 0 } }],
      ["failure rate above 1", { [PRIMARY]: { candidate: CANDIDATE, maxStepFailureRate: 1.5 } }],
      ["zero min samples", { [PRIMARY]: { candidate: CANDIDATE, minStepSamples: 0 } }],
    ];
    for (const [label, cfg] of bad) {
      assert.throws(() => assertValidCanaryRolloutConfig(cfg as never), RangeError, label);
      assert.throws(() => new CanaryRolloutManager(cfg as never), RangeError, label);
    }
  });

  it("accepts the defaults and a partial config", () => {
    const m = new CanaryRolloutManager({ [PRIMARY]: { candidate: CANDIDATE } });
    const [st] = m.stats();
    assert.equal(st.state, "rolling");
    assert.equal(st.step, 0);
    assert.equal(st.percent, 1);
  });
});

describe("CanaryRolloutManager", () => {
  it("samples by step percentage; unknown endpoints resolve to undefined", () => {
    const m = new CanaryRolloutManager(
      { [PRIMARY]: { candidate: CANDIDATE, steps: [50], dwellMs: 60_000 } },
      { now: () => 0, random: () => 0.49 }
    );
    assert.equal(m.resolveTarget(PRIMARY), CANDIDATE);
    assert.equal(m.resolveTarget("http://127.0.0.1:9999/other"), undefined);
    const m2 = new CanaryRolloutManager(
      { [PRIMARY]: { candidate: CANDIDATE, steps: [50], dwellMs: 60_000 } },
      { now: () => 0, random: () => 0.5 }
    );
    assert.equal(m2.resolveTarget(PRIMARY), PRIMARY);
    assert.equal(m2.stats()[0].candidateDispatched, 0);
  });

  it("advances steps after the dwell and resets the step budget", () => {
    let nowMs = 0;
    const events: CanaryRolloutEvent[] = [];
    const m = new CanaryRolloutManager(
      {
        [PRIMARY]: {
          candidate: CANDIDATE,
          steps: [10, 50, 100],
          dwellMs: 1000,
          maxConsecutiveStepFailures: 1,
        },
      },
      { now: () => nowMs, random: () => 0, onEvent: (e) => events.push(e) }
    );
    assert.equal(m.resolveTarget(PRIMARY), CANDIDATE);
    m.recordOutcome(PRIMARY, CANDIDATE, false);
    // One candidate failure at threshold 1 would roll back — but the
    // dwell test below uses a fresh manager instead; here the rollback
    // must have fired.
    assert.equal(m.stats()[0].state, "rolled_back");
    assert.equal(events[0].event, "canary_rolled_back");

    const m2events: CanaryRolloutEvent[] = [];
    const m2 = new CanaryRolloutManager(
      { [PRIMARY]: { candidate: CANDIDATE, steps: [10, 50, 100], dwellMs: 1000 } },
      { now: () => nowMs, random: () => 0, onEvent: (e) => m2events.push(e) }
    );
    m2.recordOutcome(PRIMARY, CANDIDATE, false);
    nowMs = 1000;
    assert.equal(m2.resolveTarget(PRIMARY), CANDIDATE);
    assert.equal(m2.stats()[0].step, 1);
    assert.equal(m2.stats()[0].percent, 50);
    assert.equal(m2.stats()[0].stepFailures, 0);
    assert.equal(m2events[0].event, "canary_step_advanced");
    assert.equal(m2events[0].step, 1);
    assert.equal(m2events[0].percent, 50);
  });

  it("promotes after the final step's dwell; promotion is sticky", () => {
    let nowMs = 0;
    const events: CanaryRolloutEvent[] = [];
    const m = new CanaryRolloutManager(
      { [PRIMARY]: { candidate: CANDIDATE, steps: [100], dwellMs: 500 } },
      { now: () => nowMs, random: () => 1, onEvent: (e) => events.push(e) }
    );
    assert.equal(m.resolveTarget(PRIMARY), PRIMARY);
    nowMs = 500;
    assert.equal(m.resolveTarget(PRIMARY), CANDIDATE);
    assert.equal(m.stats()[0].state, "promoted");
    assert.equal(m.stats()[0].percent, 100);
    assert.equal(events[0].event, "canary_promoted");
    nowMs = 1_000_000;
    assert.equal(m.resolveTarget(PRIMARY), CANDIDATE);
  });

  it("rolls back on consecutive candidate failures", () => {
    const events: CanaryRolloutEvent[] = [];
    const m = new CanaryRolloutManager(
      {
        [PRIMARY]: {
          candidate: CANDIDATE,
          steps: [100],
          dwellMs: 60_000,
          maxConsecutiveStepFailures: 2,
        },
      },
      { now: () => 0, random: () => 0, onEvent: (e) => events.push(e) }
    );
    m.recordOutcome(PRIMARY, CANDIDATE, false);
    assert.equal(m.stats()[0].state, "rolling");
    m.recordOutcome(PRIMARY, CANDIDATE, false);
    assert.equal(m.stats()[0].state, "rolled_back");
    assert.equal(m.resolveTarget(PRIMARY), PRIMARY);
    assert.equal(events.length, 1);
    assert.equal(events[0].event, "canary_rolled_back");
    assert.equal(events[0].reason, "consecutive_failures");
    assert.equal(events[0].stepSamples, 2);
    assert.equal(events[0].stepFailures, 2);
  });

  it("rolls back on step failure rate once enough samples exist", () => {
    const events: CanaryRolloutEvent[] = [];
    const m = new CanaryRolloutManager(
      {
        [PRIMARY]: {
          candidate: CANDIDATE,
          steps: [100],
          dwellMs: 60_000,
          maxConsecutiveStepFailures: 100,
          maxStepFailureRate: 0.25,
          minStepSamples: 4,
        },
      },
      { now: () => 0, random: () => 0, onEvent: (e) => events.push(e) }
    );
    m.recordOutcome(PRIMARY, CANDIDATE, false);
    m.recordOutcome(PRIMARY, CANDIDATE, true);
    m.recordOutcome(PRIMARY, CANDIDATE, true);
    assert.equal(m.stats()[0].state, "rolling");
    m.recordOutcome(PRIMARY, CANDIDATE, false);
    assert.equal(m.stats()[0].state, "rolled_back");
    assert.equal(events[0].reason, "failure_rate");
  });

  it("primary outcomes neither spend nor reset the candidate budget", () => {
    const m = new CanaryRolloutManager(
      {
        [PRIMARY]: {
          candidate: CANDIDATE,
          steps: [100],
          dwellMs: 60_000,
          maxConsecutiveStepFailures: 2,
        },
      },
      { now: () => 0, random: () => 0 }
    );
    m.recordOutcome(PRIMARY, CANDIDATE, false);
    m.recordOutcome(PRIMARY, PRIMARY, true);
    m.recordOutcome(PRIMARY, CANDIDATE, false);
    assert.equal(m.stats()[0].state, "rolled_back");
  });

  it("a rollout whose last step is below 100% never promotes", () => {
    let nowMs = 0;
    const m = new CanaryRolloutManager(
      { [PRIMARY]: { candidate: CANDIDATE, steps: [50], dwellMs: 100 } },
      { now: () => nowMs, random: () => 0 }
    );
    nowMs = 10_000;
    assert.equal(m.resolveTarget(PRIMARY), CANDIDATE);
    assert.equal(m.stats()[0].state, "rolling");
    assert.equal(m.stats()[0].percent, 50);
  });
});

describe("RetryQueue canary rollout integration", () => {
  it("ramps, promotes, and counts promotion in metrics", async () => {
    const timer = manualTimer();
    const seen: string[] = [];
    const events: CanaryRolloutEvent[] = [];
    let nowMs = 0;
    const sender: Sender = async (item) => {
      seen.push(item.targetUrl);
    };
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 3,
      setTimer: timer.setTimer,
      canaryRollouts: {
        [PRIMARY]: { candidate: CANDIDATE, steps: [50, 100], dwellMs: 1000 },
      },
      canaryNow: () => nowMs,
      canaryRandom: () => 0,
      onCanaryRolloutEvent: (e) => events.push(e),
    });
    q.start();
    q.enqueue(item("a"));
    await timer.run();
    assert.deepEqual(seen, [CANDIDATE]);
    assert.equal(q.getCanaryStats()[0].step, 0);
    nowMs = 1000;
    q.enqueue(item("b"));
    await timer.run();
    assert.deepEqual(seen, [CANDIDATE, CANDIDATE]);
    assert.equal(events[0].event, "canary_step_advanced");
    nowMs = 2000;
    q.enqueue(item("c"));
    await timer.run();
    assert.deepEqual(seen, [CANDIDATE, CANDIDATE, CANDIDATE]);
    assert.equal(events[1].event, "canary_promoted");
    assert.equal(q.getCanaryStats()[0].state, "promoted");
    const exposition = q.renderMetrics();
    assert.match(
      exposition,
      new RegExp(
        `relay_canary_rollout_events_total\\{endpoint="${PRIMARY}",candidate="${CANDIDATE}",event="canary_promoted"\\} 1`
      )
    );
    q.stop();
  });

  it("rolls back to the primary after the step budget burns", async () => {
    const timer = manualTimer();
    const seen: string[] = [];
    const events: CanaryRolloutEvent[] = [];
    const sender: Sender = async (item) => {
      seen.push(item.targetUrl);
      if (item.targetUrl === CANDIDATE) throw new Error("candidate down");
    };
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 5,
      setTimer: timer.setTimer,
      canaryRollouts: {
        [PRIMARY]: {
          candidate: CANDIDATE,
          steps: [100],
          dwellMs: 60_000,
          maxConsecutiveStepFailures: 2,
        },
      },
      canaryNow: () => 0,
      canaryRandom: () => 0,
      onCanaryRolloutEvent: (e) => events.push(e),
    });
    q.start();
    q.enqueue(item("a"));
    await timer.run();
    assert.deepEqual(seen, [CANDIDATE, CANDIDATE, PRIMARY]);
    assert.equal(events.length, 1);
    assert.equal(events[0].event, "canary_rolled_back");
    assert.equal(events[0].reason, "consecutive_failures");
    assert.equal(q.getCanaryStats()[0].state, "rolled_back");
    const exposition = q.renderMetrics();
    assert.match(
      exposition,
      new RegExp(
        `relay_canary_rollout_events_total\\{endpoint="${PRIMARY}",candidate="${CANDIDATE}",event="canary_rolled_back"\\} 1`
      )
    );
    q.stop();
  });

  it("rejects canary rollout combined with another router for the same endpoint", () => {
    const base = {
      sender: (async () => {}) as Sender,
      canaryRollouts: { [PRIMARY]: { candidate: CANDIDATE } },
    };
    assert.throws(
      () => new RetryQueue({ ...base, failover: { [PRIMARY]: { standbys: ["http://127.0.0.1:9923/s"] } } }),
      RangeError
    );
    assert.throws(
      () =>
        new RetryQueue({
          ...base,
          weighted: { [PRIMARY]: { targets: [{ targetUrl: CANDIDATE, weight: 1 }] } },
        }),
      RangeError
    );
  });
});

describe("canary rollout server wiring", () => {
  it("audits step advance and promotion through the relay server", async () => {
    const dir = mkdtempSync(join(tmpdir(), "canary-audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const secret = "test-secret";
    const payload = Buffer.from(JSON.stringify({ n: 1 }));
    let nowMs = 0;
    const server = createRelayServer({
      secret,
      forwardUrl: PRIMARY,
      auditLog: audit,
      sender: async () => {},
      retry: {
        baseDelayMs: 5,
        maxDelayMs: 5,
        jitterMs: 0,
        maxAttempts: 1,
        canaryRollouts: {
          [PRIMARY]: { candidate: CANDIDATE, steps: [50, 100], dwellMs: 1000 },
        },
        canaryNow: () => nowMs,
        canaryRandom: () => 0,
      },
    });
    await new Promise<void>((resolve) => server.listen(0, resolve));
    const port = (server.address() as { port: number }).port;
    try {
      const post = () =>
        new Promise<number>((resolve, reject) => {
          const req = httpRequest(
            {
              port,
              method: "POST",
              path: "/hook",
              headers: {
                "content-type": "application/json",
                "x-signature": signSha256(payload, secret),
              },
            },
            (res) => {
              res.resume();
              res.on("end", () => resolve(res.statusCode ?? 0));
            }
          );
          req.on("error", reject);
          req.end(payload);
        });
      assert.equal(await post(), 202);
      await new Promise((r) => setTimeout(r, 200));
      nowMs = 1000;
      assert.equal(await post(), 202);
      await new Promise((r) => setTimeout(r, 200));
      nowMs = 2000;
      assert.equal(await post(), 202);
      await new Promise((r) => setTimeout(r, 200));
      const events = audit.readAll() as Array<Record<string, unknown>>;
      const advanced = events.filter((e) => e.event === "canary_step_advanced");
      const promoted = events.filter((e) => e.event === "canary_promoted");
      assert.equal(advanced.length, 1);
      assert.equal(advanced[0].endpoint, PRIMARY);
      assert.equal(advanced[0].candidate, CANDIDATE);
      assert.equal(advanced[0].percent, 100);
      assert.equal(promoted.length, 1);
      assert.equal(promoted[0].endpoint, PRIMARY);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
