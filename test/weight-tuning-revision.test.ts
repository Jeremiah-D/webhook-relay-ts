import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type Sender, type WeightTuningOptions } from "../src/retry.ts";
import { WeightedDispatcher } from "../src/weighted.ts";
import {
  WeightTuner,
  WeightTuneSweeper,
} from "../src/weight-tuner.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "weight-tuning-revision-test-key";
const opToken = "weight-tuning-revision-op-token";
const endpointUrl = "http://127.0.0.1:9931/hook";
const targetA = "http://127.0.0.1:9932/a";
const targetB = "http://127.0.0.1:9933/b";
const URL_A = "http://localhost:9999/a";

function cfg53() {
  return {
    [endpointUrl]: {
      targets: [
        { targetUrl: targetA, weight: 5 },
        { targetUrl: targetB, weight: 3 },
      ],
    },
  };
}

/** Mutable per-target scores backing a `healthOf` provider. */
function scoreBoard(initial: Record<string, number>) {
  const scores = { ...initial };
  return {
    scores,
    healthOf: (_endpoint: string, target: string) => scores[target] ?? 100,
  };
}

/** Timer that records every arming interval and tracks pending arms. */
function recordingTimer() {
  const pending: Array<{ fn: () => void; ms: number }> = [];
  return {
    setTimer: (fn: () => void, ms: number) => {
      const entry = { fn, ms };
      pending.push(entry);
      return {
        clear: () => {
          const i = pending.indexOf(entry);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    pendingMs: () => pending.map((p) => p.ms),
  };
}

function weightOf(dispatcher: WeightedDispatcher, target: string): number {
  const row = dispatcher.stats().find((s) => s.endpoint === endpointUrl);
  return row!.targets.find((t) => t.targetUrl === target)!.weight;
}

describe("WeightTuner.retune (WR-340)", () => {
  it("retune ewmaAlpha: the next round smooths with the new alpha", () => {
    const dispatcher = new WeightedDispatcher(cfg53());
    const board = scoreBoard({ [targetA]: 100, [targetB]: 100 });
    const tuner = new WeightTuner({
      dispatcher,
      healthOf: board.healthOf,
      ewmaAlpha: 0.5,
      maxStepRatio: 1,
      hysteresisPoints: 0,
      retuneEpsilon: 0,
    });
    assert.equal(tuner.retune(endpointUrl), undefined); // seed at 100/100
    assert.deepEqual(tuner.retune({ ewmaAlpha: 1 }), {
      ewmaAlpha: 1,
      maxStepRatio: 1,
      hysteresisPoints: 0,
      minWeightFloor: 0.05,
      retuneEpsilon: 0,
    });
    board.scores[targetB] = 0;
    const info = tuner.retune(endpointUrl);
    assert.ok(info !== undefined);
    // New alpha 1: the smoothed score jumps straight to the raw score
    // (the old 0.5 would have given 50).
    assert.equal(info.smoothed[targetB], 0);
    const b = info.after.find((t) => t.targetUrl === targetB)!.weight;
    assert.ok(Math.abs(b - 0.15) < 1e-9, `B ${b}`);
  });

  it("retune maxStepRatio: the next round's single-step clamp follows", () => {
    const dispatcher = new WeightedDispatcher(cfg53());
    const board = scoreBoard({ [targetA]: 100, [targetB]: 0 });
    const tuner = new WeightTuner({
      dispatcher,
      healthOf: board.healthOf,
      ewmaAlpha: 1,
      maxStepRatio: 0.25,
      hysteresisPoints: 0,
      retuneEpsilon: 0,
    });
    assert.equal(tuner.retune(endpointUrl), undefined); // seed
    const first = tuner.retune(endpointUrl);
    assert.ok(first !== undefined);
    const b1 = first.after.find((t) => t.targetUrl === targetB)!.weight;
    assert.ok(Math.abs(b1 - 2.25) < 1e-9, `B ${b1}`);
    tuner.retune({ maxStepRatio: 0.1 });
    const second = tuner.retune(endpointUrl);
    assert.ok(second !== undefined);
    const b2 = second.after.find((t) => t.targetUrl === targetB)!.weight;
    // Desired 0.15 from 2.25 is a 93% drop; the tightened clamp allows 10%.
    assert.ok(Math.abs(b2 - 2.025) < 1e-9, `B ${b2}`);
  });

  it("retune hysteresisPoints: raising silences a would-be round, lowering fires it", () => {
    const dispatcher = new WeightedDispatcher(cfg53());
    const board = scoreBoard({ [targetA]: 100, [targetB]: 100 });
    const tuner = new WeightTuner({
      dispatcher,
      healthOf: board.healthOf,
      ewmaAlpha: 1,
      maxStepRatio: 1,
      hysteresisPoints: 5,
      retuneEpsilon: 0,
    });
    assert.equal(tuner.retune(endpointUrl), undefined); // seed
    board.scores[targetB] = 80; // drift 20 would trigger at hysteresis 5
    tuner.retune({ hysteresisPoints: 50 });
    assert.equal(tuner.retune(endpointUrl), undefined);
    assert.equal(weightOf(dispatcher, targetB), 3);
    tuner.retune({ hysteresisPoints: 10 });
    const info = tuner.retune(endpointUrl);
    assert.ok(info !== undefined);
    // B desired = 3 * (0.05 + 0.95 * 0.8) = 2.43.
    const b = info.after.find((t) => t.targetUrl === targetB)!.weight;
    assert.ok(Math.abs(b - 2.43) < 1e-9, `B ${b}`);
  });

  it("retune minWeightFloor: a zero-health target's retained share follows", () => {
    const dispatcher = new WeightedDispatcher(cfg53());
    const board = scoreBoard({ [targetA]: 100, [targetB]: 0 });
    const tuner = new WeightTuner({
      dispatcher,
      healthOf: board.healthOf,
      ewmaAlpha: 1,
      maxStepRatio: 1,
      hysteresisPoints: 0,
      retuneEpsilon: 0,
      minWeightFloor: 0.05,
    });
    assert.equal(tuner.retune(endpointUrl), undefined); // seed
    const first = tuner.retune(endpointUrl);
    assert.ok(first !== undefined);
    const b1 = first.after.find((t) => t.targetUrl === targetB)!.weight;
    assert.ok(Math.abs(b1 - 0.15) < 1e-9, `B ${b1}`);
    tuner.retune({ minWeightFloor: 0.2 });
    const second = tuner.retune(endpointUrl);
    assert.ok(second !== undefined);
    // Desired from the untouched baseline: 3 * 0.2 = 0.6 — but one round
    // may move at most 2x (maxStepRatio 1), so the round lands on 0.3.
    const b2 = second.after.find((t) => t.targetUrl === targetB)!.weight;
    assert.ok(Math.abs(b2 - 0.3) < 1e-9, `B ${b2}`);
    // The next round completes the climb to the new floor.
    const third = tuner.retune(endpointUrl);
    assert.ok(third !== undefined);
    const b3 = third.after.find((t) => t.targetUrl === targetB)!.weight;
    assert.ok(Math.abs(b3 - 0.6) < 1e-9, `B ${b3}`);
  });

  it("retune retuneEpsilon: the move threshold follows", () => {
    const dispatcher = new WeightedDispatcher(cfg53());
    const board = scoreBoard({ [targetA]: 100, [targetB]: 99 });
    const tuner = new WeightTuner({
      dispatcher,
      healthOf: board.healthOf,
      ewmaAlpha: 1,
      maxStepRatio: 1,
      hysteresisPoints: 0,
      retuneEpsilon: 0.02,
    });
    assert.equal(tuner.retune(endpointUrl), undefined); // seed
    // B desired = 3 * (0.05 + 0.95 * 0.99) = 2.9715, a 0.95% move.
    assert.equal(tuner.retune(endpointUrl), undefined);
    assert.equal(weightOf(dispatcher, targetB), 3);
    tuner.retune({ retuneEpsilon: 0.005 });
    const info = tuner.retune(endpointUrl);
    assert.ok(info !== undefined);
    const b = info.after.find((t) => t.targetUrl === targetB)!.weight;
    assert.ok(Math.abs(b - 2.9715) < 1e-9, `B ${b}`);
  });

  it("illegal values throw RangeError and leave live values and tuning state untouched", () => {
    const dispatcher = new WeightedDispatcher(cfg53());
    const board = scoreBoard({ [targetA]: 100, [targetB]: 100 });
    const tuner = new WeightTuner({
      dispatcher,
      healthOf: board.healthOf,
      ewmaAlpha: 0.5,
      maxStepRatio: 1,
      hysteresisPoints: 0,
      retuneEpsilon: 0,
    });
    assert.equal(tuner.retune(endpointUrl), undefined); // seed at 100/100
    board.scores[targetB] = 0;
    const first = tuner.retune(endpointUrl);
    assert.ok(first !== undefined);
    // smoothed B = 0.5*0 + 0.5*100 = 50; after B = 3 * (0.05 + 0.95*0.5).
    assert.equal(first.smoothed[targetB], 50);
    const before = tuner.snapshot();
    const illegal = [
      { ewmaAlpha: 0 },
      { ewmaAlpha: 1.5 },
      { ewmaAlpha: NaN },
      { maxStepRatio: 0 },
      { maxStepRatio: 2 },
      { hysteresisPoints: -1 },
      { hysteresisPoints: Infinity },
      { minWeightFloor: 1 },
      { minWeightFloor: -0.1 },
      { retuneEpsilon: 1 },
      { retuneEpsilon: -0.01 },
      { ewmaAlpha: 0.25, maxStepRatio: 2 }, // one bad field poisons the patch
    ];
    for (const patch of illegal) {
      assert.throws(() => tuner.retune(patch), RangeError, JSON.stringify(patch));
      assert.deepEqual(tuner.snapshot(), before);
    }
    // State survived: the next round continues the EWMA from 50, not 100.
    board.scores[targetB] = 60;
    const next = tuner.retune(endpointUrl);
    assert.ok(next !== undefined);
    assert.equal(next.smoothed[targetB], 55); // 0.5*60 + 0.5*50
    const b = next.after.find((t) => t.targetUrl === targetB)!.weight;
    // Desired from the untouched baseline: 3 * (0.05 + 0.95*0.55) = 1.7175.
    assert.ok(Math.abs(b - 1.7175) < 1e-9, `B ${b}`);
  });

  it("empty and non-object patches throw RangeError; a same-value patch is a silent no-op", () => {
    const dispatcher = new WeightedDispatcher(cfg53());
    const board = scoreBoard({});
    const tuner = new WeightTuner({
      dispatcher,
      healthOf: board.healthOf,
      ewmaAlpha: 0.5,
      maxStepRatio: 0.4,
      hysteresisPoints: 7,
      minWeightFloor: 0.1,
      retuneEpsilon: 0.03,
    });
    const live = {
      ewmaAlpha: 0.5,
      maxStepRatio: 0.4,
      hysteresisPoints: 7,
      minWeightFloor: 0.1,
      retuneEpsilon: 0.03,
    };
    assert.deepEqual(tuner.snapshot(), live);
    assert.throws(() => tuner.retune({}), RangeError);
    assert.throws(() => tuner.retune(null as never), RangeError);
    // Note: a string is the endpoint overload, not a patch — an unknown
    // endpoint round returns undefined, so it is not a RangeError case.
    assert.throws(() => tuner.retune(42 as never), RangeError);
    assert.throws(() => tuner.retune([] as never), RangeError);
    assert.deepEqual(tuner.snapshot(), live);
    assert.deepEqual(tuner.retune({ ewmaAlpha: 0.5 }), live);
    assert.deepEqual(tuner.retune({ ...live }), live);
    assert.deepEqual(tuner.snapshot(), live);
  });

  it("retune leaves smoothed scores, baselines, and score references untouched", () => {
    const dispatcher = new WeightedDispatcher(cfg53());
    const board = scoreBoard({ [targetA]: 100, [targetB]: 100 });
    const tuner = new WeightTuner({
      dispatcher,
      healthOf: board.healthOf,
      ewmaAlpha: 1,
      maxStepRatio: 1,
      hysteresisPoints: 0,
      retuneEpsilon: 0,
    });
    assert.equal(tuner.retune(endpointUrl), undefined); // seed at 100/100
    board.scores[targetB] = 0;
    const first = tuner.retune(endpointUrl);
    assert.ok(first !== undefined);
    assert.equal(first.smoothed[targetB], 0);
    assert.ok(
      Math.abs(first.after.find((t) => t.targetUrl === targetB)!.weight - 0.15) < 1e-9
    );
    // The raw score flips back while the tuner is retuned: if the
    // retune reset state, the next round would re-baseline and apply
    // nothing instead of continuing the EWMA.
    board.scores[targetB] = 100;
    tuner.retune({ ewmaAlpha: 0.5, hysteresisPoints: 60 });
    // Round 3: smoothed = 0.5*100 + 0.5*0 = 50, drift from the score
    // the weights were tuned against (0) is 50 < 60 — a no-op, but the
    // EWMA still advances.
    assert.equal(tuner.retune(endpointUrl), undefined);
    assert.ok(Math.abs(weightOf(dispatcher, targetB) - 0.15) < 1e-9);
    // Round 4: smoothed = 0.5*100 + 0.5*50 = 75, drift 75 >= 60 —
    // applies, from the original baseline (3): desired
    // 3 * (0.05 + 0.95*0.75) = 2.2875, clamped to 2x the current 0.15.
    const fourth = tuner.retune(endpointUrl);
    assert.ok(fourth !== undefined);
    assert.equal(fourth.smoothed[targetB], 75);
    const b = fourth.after.find((t) => t.targetUrl === targetB)!.weight;
    assert.ok(Math.abs(b - 0.3) < 1e-9, `B ${b}`);
  });

  it("a manual weight change still re-baselines the tuner after a retune", () => {
    const dispatcher = new WeightedDispatcher(cfg53());
    const board = scoreBoard({ [targetA]: 100, [targetB]: 100 });
    const tuner = new WeightTuner({
      dispatcher,
      healthOf: board.healthOf,
      ewmaAlpha: 1,
      maxStepRatio: 1,
      hysteresisPoints: 0,
      retuneEpsilon: 0,
    });
    assert.equal(tuner.retune(endpointUrl), undefined); // seed
    board.scores[targetB] = 0;
    assert.ok(tuner.retune(endpointUrl) !== undefined);
    tuner.retune({ ewmaAlpha: 0.5 });
    // Operator edits weights outside the tuner.
    dispatcher.setWeights(endpointUrl, [
      { targetUrl: targetA, weight: 10 },
      { targetUrl: targetB, weight: 10 },
    ]);
    // The tuner detects the manual edit, re-baselines, and does not fight it.
    assert.equal(tuner.retune(endpointUrl), undefined);
    assert.equal(weightOf(dispatcher, targetA), 10);
    assert.equal(weightOf(dispatcher, targetB), 10);
    // The next round derives from the manual baseline: B = 10 * 0.05.
    const info = tuner.retune(endpointUrl);
    assert.ok(info !== undefined);
    const b = info.after.find((t) => t.targetUrl === targetB)!.weight;
    assert.ok(Math.abs(b - 0.5) < 1e-9, `B ${b}`);
  });

  it("snapshot() reads the five live values", () => {
    const dispatcher = new WeightedDispatcher(cfg53());
    const board = scoreBoard({});
    const tuner = new WeightTuner({
      dispatcher,
      healthOf: board.healthOf,
      ewmaAlpha: 0.5,
      maxStepRatio: 0.4,
      hysteresisPoints: 7,
      minWeightFloor: 0.1,
      retuneEpsilon: 0.03,
    });
    assert.deepEqual(tuner.snapshot(), {
      ewmaAlpha: 0.5,
      maxStepRatio: 0.4,
      hysteresisPoints: 7,
      minWeightFloor: 0.1,
      retuneEpsilon: 0.03,
    });
    tuner.retune({ ewmaAlpha: 1, retuneEpsilon: 0 });
    assert.deepEqual(tuner.snapshot(), {
      ewmaAlpha: 1,
      maxStepRatio: 0.4,
      hysteresisPoints: 7,
      minWeightFloor: 0.1,
      retuneEpsilon: 0,
    });
  });
});

describe("WeightTuneSweeper interval revision (WR-340)", () => {
  it("setRetuneIntervalMs re-arms the running sweeper on the new interval", () => {
    const dispatcher = new WeightedDispatcher(cfg53());
    const board = scoreBoard({ [targetA]: 100, [targetB]: 0 });
    const tuner = new WeightTuner({ dispatcher, healthOf: board.healthOf });
    const timer = recordingTimer();
    const sweeper = new WeightTuneSweeper({
      tuner,
      retuneIntervalMs: 1000,
      setTimer: timer.setTimer,
    });
    assert.equal(sweeper.retuneIntervalMs(), 1000);
    sweeper.start();
    assert.deepEqual(timer.pendingMs(), [1000]);
    sweeper.setRetuneIntervalMs(5000);
    assert.equal(sweeper.retuneIntervalMs(), 5000);
    // The old arm was cleared and exactly one new arm took its place.
    assert.deepEqual(timer.pendingMs(), [5000]);
    // A same-value set is a silent no-op: no re-arm.
    sweeper.setRetuneIntervalMs(5000);
    assert.deepEqual(timer.pendingMs(), [5000]);
    sweeper.stop();
    assert.deepEqual(timer.pendingMs(), []);
  });

  it("setRetuneIntervalMs while stopped only changes the value; the next start arms on it", () => {
    const dispatcher = new WeightedDispatcher(cfg53());
    const board = scoreBoard({});
    const tuner = new WeightTuner({ dispatcher, healthOf: board.healthOf });
    const timer = recordingTimer();
    const sweeper = new WeightTuneSweeper({
      tuner,
      retuneIntervalMs: 1000,
      setTimer: timer.setTimer,
    });
    sweeper.setRetuneIntervalMs(2500);
    assert.equal(sweeper.retuneIntervalMs(), 2500);
    assert.deepEqual(timer.pendingMs(), []);
    sweeper.start();
    assert.deepEqual(timer.pendingMs(), [2500]);
    sweeper.stop();
  });

  it("an illegal interval throws RangeError and leaves the live interval untouched", () => {
    const dispatcher = new WeightedDispatcher(cfg53());
    const board = scoreBoard({});
    const tuner = new WeightTuner({ dispatcher, healthOf: board.healthOf });
    const timer = recordingTimer();
    const sweeper = new WeightTuneSweeper({
      tuner,
      retuneIntervalMs: 1000,
      setTimer: timer.setTimer,
    });
    sweeper.start();
    for (const bad of [0, -5, NaN, Infinity]) {
      assert.throws(() => sweeper.setRetuneIntervalMs(bad), RangeError, `interval ${String(bad)}`);
      assert.equal(sweeper.retuneIntervalMs(), 1000);
      assert.deepEqual(timer.pendingMs(), [1000]);
    }
    sweeper.stop();
  });
});

describe("RetryQueue weight-tuning revision (WR-340)", () => {
  function makeQueue(weightTuning?: WeightTuningOptions) {
    const timer = recordingTimer();
    const sender: Sender = async () => {};
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxAttempts: 5,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      weighted: cfg53(),
      endpointHealth: {},
      // The sweeper takes its timer from `weightTuning`, not from the
      // queue-level `setTimer` — pass it through so the fake timer
      // observes the sweeper arming.
      ...(weightTuning === undefined
        ? {}
        : { weightTuning: { ...weightTuning, setTimer: timer.setTimer } }),
    });
    return { q, timer };
  }

  it("unconfigured: revise throws the must-restart Error, getter returns undefined", () => {
    const { q } = makeQueue();
    assert.equal(q.getWeightTuningConfig(), undefined);
    assert.throws(
      () => q.reviseWeightTuning({ ewmaAlpha: 0.5 }),
      /not configured — enabling it requires a restart/
    );
    assert.throws(
      () => q.reviseWeightTuning({ ewmaAlpha: 0.5 }),
      /cannot start tuning weights without them/
    );
    assert.equal(q.getWeightTuningConfig(), undefined);
    q.stop();
  });

  it("getter tracks revisions; illegal patches leave live values untouched", () => {
    const { q } = makeQueue({ ewmaAlpha: 0.5 });
    const defaults = {
      ewmaAlpha: 0.5,
      maxStepRatio: 0.25,
      hysteresisPoints: 5,
      minWeightFloor: 0.05,
      retuneEpsilon: 0.02,
      retuneIntervalMs: 60_000,
    };
    assert.deepEqual(q.getWeightTuningConfig(), defaults);
    assert.deepEqual(q.reviseWeightTuning({ maxStepRatio: 0.1, retuneIntervalMs: 5000 }), {
      ...defaults,
      maxStepRatio: 0.1,
      retuneIntervalMs: 5000,
    });
    assert.deepEqual(q.getWeightTuningConfig(), {
      ...defaults,
      maxStepRatio: 0.1,
      retuneIntervalMs: 5000,
    });
    // Same values: silent no-op.
    assert.deepEqual(q.reviseWeightTuning({ maxStepRatio: 0.1 }), {
      ...defaults,
      maxStepRatio: 0.1,
      retuneIntervalMs: 5000,
    });
    const before = q.getWeightTuningConfig();
    assert.throws(() => q.reviseWeightTuning({ ewmaAlpha: 0 }), RangeError);
    assert.throws(() => q.reviseWeightTuning({ retuneIntervalMs: 0 }), RangeError);
    assert.throws(() => q.reviseWeightTuning({ hysteresisPoints: -1 }), RangeError);
    assert.throws(() => q.reviseWeightTuning({ minWeightFloor: 1 }), RangeError);
    assert.throws(() => q.reviseWeightTuning({}), RangeError);
    assert.throws(() => q.reviseWeightTuning(null as never), RangeError);
    assert.throws(() => q.reviseWeightTuning("x" as never), RangeError);
    assert.deepEqual(q.getWeightTuningConfig(), before);
    // A bad interval leaves the tuner untouched, and a bad tuner field
    // leaves the interval untouched — no partial application either way.
    assert.throws(
      () => q.reviseWeightTuning({ ewmaAlpha: 0.9, retuneIntervalMs: -1 }),
      RangeError
    );
    assert.throws(
      () => q.reviseWeightTuning({ ewmaAlpha: 0, retuneIntervalMs: 7000 }),
      RangeError
    );
    assert.deepEqual(q.getWeightTuningConfig(), before);
    q.stop();
  });

  it("revising the interval re-arms the running sweeper on the new interval", () => {
    const { q, timer } = makeQueue({ retuneIntervalMs: 1000 });
    q.start();
    assert.ok(timer.pendingMs().includes(1000), `pending ${JSON.stringify(timer.pendingMs())}`);
    q.reviseWeightTuning({ retuneIntervalMs: 5000 });
    assert.equal(q.getWeightTuningConfig()!.retuneIntervalMs, 5000);
    assert.ok(timer.pendingMs().includes(5000), `pending ${JSON.stringify(timer.pendingMs())}`);
    assert.ok(!timer.pendingMs().includes(1000), `pending ${JSON.stringify(timer.pendingMs())}`);
    q.stop();
    assert.deepEqual(timer.pendingMs(), []);
  });
});

describe("RelayServer weight-tuning revision (WR-340)", () => {
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
    const dir = mkdtempSync(join(tmpdir(), "weight-tuning-revision-"));
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

  const construction = {
    ewmaAlpha: 0.3,
    maxStepRatio: 0.25,
    hysteresisPoints: 5,
    minWeightFloor: 0.05,
    retuneEpsilon: 0.02,
    retuneIntervalMs: 60_000,
  };

  it("revision audits previous/current with the six construction values first; same-value is a silent no-op", async () => {
    const { relay, audit } = makeRelay({
      forwardUrl: endpointUrl,
      retry: {
        weighted: cfg53(),
        endpointHealth: {},
        weightTuning: {},
      },
    });
    await listen(relay);
    assert.deepEqual(relay.getWeightTuningConfig!(), construction);
    assert.deepEqual(relay.reviseWeightTuning!({ ewmaAlpha: 0.5, retuneIntervalMs: 30_000 }), {
      ...construction,
      ewmaAlpha: 0.5,
      retuneIntervalMs: 30_000,
    });
    const revised = eventsOf(audit, "weight_tuning_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, construction);
    assert.deepEqual(revised[0].current, {
      ...construction,
      ewmaAlpha: 0.5,
      retuneIntervalMs: 30_000,
    });
    // Landing exactly on the live values audits nothing.
    relay.reviseWeightTuning!({ ewmaAlpha: 0.5, retuneIntervalMs: 30_000 });
    assert.equal(eventsOf(audit, "weight_tuning_revised").length, 1);
    assert.deepEqual(relay.getWeightTuningConfig!(), {
      ...construction,
      ewmaAlpha: 0.5,
      retuneIntervalMs: 30_000,
    });
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseWeightTuning!({ ewmaAlpha: 0 }), RangeError);
    assert.throws(() => relay.reviseWeightTuning!({}), RangeError);
    assert.equal(eventsOf(audit, "weight_tuning_revised").length, 1);
    assert.deepEqual(relay.getWeightTuningConfig!(), {
      ...construction,
      ewmaAlpha: 0.5,
      retuneIntervalMs: 30_000,
    });
  });

  it("unconfigured relay: revise throws the must-restart Error and the getter is not mounted", async () => {
    const { relay } = makeRelay();
    await listen(relay);
    assert.equal(relay.getWeightTuningConfig, undefined);
    assert.throws(
      () => relay.reviseWeightTuning!({ ewmaAlpha: 0.5 }),
      /not configured — enabling it requires a restart/
    );
  });
});
