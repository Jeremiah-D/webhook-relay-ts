import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest } from "node:http";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { WeightedDispatcher } from "../src/weighted.ts";
import {
  WeightTuner,
  WeightTuneSweeper,
  type WeightsRetunedInfo,
} from "../src/weight-tuner.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const endpointUrl = "http://127.0.0.1:9931/hook";
const targetA = "http://127.0.0.1:9932/a";
const targetB = "http://127.0.0.1:9933/b";

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
    pendingCount: () => pending.length,
    async run() {
      while (pending.length > 0) {
        const fns = pending.splice(0);
        for (const fn of fns) fn();
        await new Promise((r) => setImmediate(r));
      }
    },
    // Run exactly one pending callback — `run()` would loop forever on
    // self-re-arming sweepers.
    async runNext() {
      const fn = pending.shift();
      if (fn !== undefined) {
        fn();
        await new Promise((r) => setImmediate(r));
      }
    },
  };
}

function weightOf(dispatcher: WeightedDispatcher, target: string): number {
  const row = dispatcher.stats().find((s) => s.endpoint === endpointUrl);
  return row!.targets.find((t) => t.targetUrl === target)!.weight;
}

describe("WeightTuner", () => {
  it("re-baselines on first sight and applies nothing", () => {
    const dispatcher = new WeightedDispatcher(cfg53());
    const board = scoreBoard({ [targetA]: 100, [targetB]: 20 });
    const retuned: WeightsRetunedInfo[] = [];
    const tuner = new WeightTuner({
      dispatcher,
      healthOf: board.healthOf,
      ewmaAlpha: 1,
      maxStepRatio: 1,
      hysteresisPoints: 0,
      retuneEpsilon: 0,
      onWeightsRetuned: (info) => retuned.push(info),
    });
    // First round seeds the baseline and score references — the tuner
    // must not move anything before it has a reference.
    assert.equal(tuner.retune(endpointUrl), undefined);
    assert.equal(weightOf(dispatcher, targetA), 5);
    assert.equal(weightOf(dispatcher, targetB), 3);
    assert.equal(retuned.length, 0);
    assert.deepEqual(tuner.tunedEndpoints(), [endpointUrl]);
  });

  it("shifts weight toward the healthier target", () => {
    const dispatcher = new WeightedDispatcher(cfg53());
    const board = scoreBoard({ [targetA]: 100, [targetB]: 20 });
    const tuner = new WeightTuner({
      dispatcher,
      healthOf: board.healthOf,
      ewmaAlpha: 1,
      maxStepRatio: 1,
      hysteresisPoints: 0,
      retuneEpsilon: 0,
    });
    assert.equal(tuner.retune(endpointUrl), undefined); // seed
    const info = tuner.retune(endpointUrl);
    assert.ok(info !== undefined);
    assert.equal(info.endpoint, endpointUrl);
    // B at score 20: desired = 3 * (0.05 + 0.95 * 0.2) = 0.72.
    // A at 100 keeps exactly its baseline.
    const afterB = info.after.find((t) => t.targetUrl === targetB)!.weight;
    const afterA = info.after.find((t) => t.targetUrl === targetA)!.weight;
    assert.ok(Math.abs(afterB - 0.72) < 1e-9, `B weight ${afterB}`);
    assert.equal(afterA, 5);
    assert.equal(weightOf(dispatcher, targetB), afterB);
    // before/after are in config order and carry the sampled scores.
    assert.deepEqual(info.before, [
      { targetUrl: targetA, weight: 5 },
      { targetUrl: targetB, weight: 3 },
    ]);
    assert.equal(info.scores[targetB], 20);
    assert.equal(info.smoothed[targetB], 20);
  });

  it("smooths scores with the EWMA before computing weights", () => {
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
    // smoothed B = 0.5*0 + 0.5*100 = 50.
    assert.equal(first.smoothed[targetB], 50);
    const second = tuner.retune(endpointUrl);
    assert.ok(second !== undefined);
    // smoothed B = 0.5*0 + 0.5*50 = 25.
    assert.equal(second.smoothed[targetB], 25);
  });

  it("hysteresis suppresses rounds below the drift threshold", () => {
    const dispatcher = new WeightedDispatcher(cfg53());
    const board = scoreBoard({ [targetA]: 100, [targetB]: 100 });
    const retuned: WeightsRetunedInfo[] = [];
    const tuner = new WeightTuner({
      dispatcher,
      healthOf: board.healthOf,
      ewmaAlpha: 1,
      maxStepRatio: 1,
      hysteresisPoints: 50,
      retuneEpsilon: 0,
      onWeightsRetuned: (info) => retuned.push(info),
    });
    assert.equal(tuner.retune(endpointUrl), undefined); // seed
    board.scores[targetB] = 80; // drift 20 < 50
    assert.equal(tuner.retune(endpointUrl), undefined);
    assert.equal(weightOf(dispatcher, targetB), 3);
    assert.equal(retuned.length, 0);
    board.scores[targetB] = 30; // drift 70 >= 50
    const info = tuner.retune(endpointUrl);
    assert.ok(info !== undefined);
    assert.equal(retuned.length, 1);
  });

  it("bounds single-round steps to maxStepRatio", () => {
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
    // B desired = 3 * 0.05 = 0.15, but one round may move at most 25%.
    const first = tuner.retune(endpointUrl);
    assert.ok(first !== undefined);
    const b1 = first.after.find((t) => t.targetUrl === targetB)!.weight;
    assert.ok(Math.abs(b1 - 2.25) < 1e-9, `B ${b1}`);
    // The next round continues from the new weight, still bounded.
    const second = tuner.retune(endpointUrl);
    assert.ok(second !== undefined);
    const b2 = second.after.find((t) => t.targetUrl === targetB)!.weight;
    assert.ok(Math.abs(b2 - 2.25 * 0.75) < 1e-9, `B ${b2}`);
  });

  it("skips rounds whose changes are below the no-op epsilon", () => {
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
  });

  it("an out-of-band weight change re-baselines the tuner (manual wins)", () => {
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
    // Operator edits weights outside the tuner.
    dispatcher.setWeights(endpointUrl, [
      { targetUrl: targetA, weight: 10 },
      { targetUrl: targetB, weight: 10 },
    ]);
    board.scores[targetB] = 0;
    // The tuner must detect the manual edit, re-baseline, and NOT fight it.
    assert.equal(tuner.retune(endpointUrl), undefined);
    assert.equal(weightOf(dispatcher, targetA), 10);
    assert.equal(weightOf(dispatcher, targetB), 10);
    // The next round derives from the *manual* baseline: B = 10 * 0.05.
    const info = tuner.retune(endpointUrl);
    assert.ok(info !== undefined);
    assert.deepEqual(info.before, [
      { targetUrl: targetA, weight: 10 },
      { targetUrl: targetB, weight: 10 },
    ]);
    const b = info.after.find((t) => t.targetUrl === targetB)!.weight;
    assert.ok(Math.abs(b - 0.5) < 1e-9, `B ${b}`);
  });

  it("noteManualWeights re-baselines explicitly", () => {
    const dispatcher = new WeightedDispatcher(cfg53());
    const board = scoreBoard({ [targetA]: 100, [targetB]: 100 });
    const tuner = new WeightTuner({ dispatcher, healthOf: board.healthOf });
    tuner.noteManualWeights(endpointUrl, [
      { targetUrl: targetA, weight: 7 },
      { targetUrl: targetB, weight: 1 },
    ]);
    // No fight: the first round after an explicit manual note is a no-op
    // even with divergent scores, because the tuner just re-based.
    board.scores[targetB] = 10;
    assert.equal(tuner.retune(endpointUrl), undefined);
    assert.equal(weightOf(dispatcher, targetB), 3); // dispatcher untouched
  });

  it("skips single-target endpoints", () => {
    const dispatcher = new WeightedDispatcher({
      [endpointUrl]: { targets: [{ targetUrl: targetA, weight: 5 }] },
    });
    const board = scoreBoard({ [targetA]: 0 });
    const tuner = new WeightTuner({
      dispatcher,
      healthOf: board.healthOf,
      ewmaAlpha: 1,
      hysteresisPoints: 0,
      retuneEpsilon: 0,
    });
    assert.equal(tuner.retune(endpointUrl), undefined);
    assert.equal(tuner.retune(endpointUrl), undefined);
  });

  it("keeps a floor share for zero-health targets", () => {
    const dispatcher = new WeightedDispatcher(cfg53());
    const board = scoreBoard({ [targetA]: 100, [targetB]: 0 });
    const tuner = new WeightTuner({
      dispatcher,
      healthOf: board.healthOf,
      ewmaAlpha: 1,
      maxStepRatio: 1,
      hysteresisPoints: 0,
      retuneEpsilon: 0,
      minWeightFloor: 0.1,
    });
    assert.equal(tuner.retune(endpointUrl), undefined); // seed
    const info = tuner.retune(endpointUrl);
    assert.ok(info !== undefined);
    const b = info.after.find((t) => t.targetUrl === targetB)!.weight;
    assert.ok(Math.abs(b - 3 * 0.1) < 1e-9, `B ${b}`);
    assert.ok(b > 0);
  });

  it("a throwing onWeightsRetuned does not break the round", () => {
    const dispatcher = new WeightedDispatcher(cfg53());
    const board = scoreBoard({ [targetA]: 100, [targetB]: 0 });
    const tuner = new WeightTuner({
      dispatcher,
      healthOf: board.healthOf,
      ewmaAlpha: 1,
      maxStepRatio: 1,
      hysteresisPoints: 0,
      retuneEpsilon: 0,
      onWeightsRetuned: () => {
        throw new Error("observer down");
      },
    });
    assert.equal(tuner.retune(endpointUrl), undefined); // seed
    const info = tuner.retune(endpointUrl);
    assert.ok(info !== undefined);
    assert.ok(weightOf(dispatcher, targetB) < 3);
  });

  it("retuneAll covers every weighted endpoint", () => {
    const dispatcher = new WeightedDispatcher({
      [endpointUrl]: {
        targets: [
          { targetUrl: targetA, weight: 5 },
          { targetUrl: targetB, weight: 3 },
        ],
      },
      "http://127.0.0.1:9934/other": {
        targets: [
          { targetUrl: targetA, weight: 1 },
          { targetUrl: targetB, weight: 1 },
        ],
      },
    });
    const board = scoreBoard({ [targetA]: 100, [targetB]: 0 });
    const tuner = new WeightTuner({
      dispatcher,
      healthOf: board.healthOf,
      ewmaAlpha: 1,
      maxStepRatio: 1,
      hysteresisPoints: 0,
      retuneEpsilon: 0,
    });
    assert.deepEqual(tuner.retuneAll(), []); // seed round
    const infos = tuner.retuneAll();
    assert.equal(infos.length, 2);
    assert.deepEqual(
      infos.map((i) => i.endpoint).sort(),
      [endpointUrl, "http://127.0.0.1:9934/other"].sort()
    );
  });

  it("rejects invalid options with RangeError", () => {
    const dispatcher = new WeightedDispatcher(cfg53());
    const board = scoreBoard({});
    assert.throws(
      () => new WeightTuner({ dispatcher, healthOf: board.healthOf, ewmaAlpha: 0 }),
      RangeError
    );
    assert.throws(
      () => new WeightTuner({ dispatcher, healthOf: board.healthOf, maxStepRatio: 1.5 }),
      RangeError
    );
    assert.throws(
      () => new WeightTuner({ dispatcher, healthOf: board.healthOf, hysteresisPoints: -1 }),
      RangeError
    );
    assert.throws(
      () => new WeightTuner({ dispatcher, healthOf: board.healthOf, minWeightFloor: 1 }),
      RangeError
    );
    assert.throws(
      () => new WeightTuner({ dispatcher, healthOf: board.healthOf, retuneEpsilon: 1 }),
      RangeError
    );
    assert.throws(
      () => new WeightTuner({ dispatcher: null as never, healthOf: board.healthOf }),
      RangeError
    );
    assert.throws(
      () => new WeightTuner({ dispatcher, healthOf: null as never }),
      RangeError
    );
  });
});

describe("WeightTuneSweeper", () => {
  it("arms periodic rounds and sweepNow runs one immediately", async () => {
    const dispatcher = new WeightedDispatcher(cfg53());
    const board = scoreBoard({ [targetA]: 100, [targetB]: 0 });
    const tuner = new WeightTuner({
      dispatcher,
      healthOf: board.healthOf,
      ewmaAlpha: 1,
      maxStepRatio: 1,
      hysteresisPoints: 0,
      retuneEpsilon: 0,
    });
    const timer = manualTimer();
    const sweeper = new WeightTuneSweeper({
      tuner,
      retuneIntervalMs: 1000,
      setTimer: timer.setTimer,
    });
    assert.equal(sweeper.isRunning(), false);
    sweeper.start();
    assert.equal(sweeper.isRunning(), true);
    assert.equal(timer.pendingCount(), 1);
    // sweepNow seeds the baseline without waiting for the schedule.
    assert.deepEqual(sweeper.sweepNow(), []);
    // The armed timer fires a real round (exactly one — the sweeper
    // re-arms, so `run()` would never terminate).
    await timer.runNext();
    assert.ok(weightOf(dispatcher, targetB) < 3);
    sweeper.stop();
    assert.equal(sweeper.isRunning(), false);
    assert.equal(timer.pendingCount(), 0);
  });

  it("rejects a non-positive retune interval", () => {
    const dispatcher = new WeightedDispatcher(cfg53());
    const board = scoreBoard({});
    const tuner = new WeightTuner({ dispatcher, healthOf: board.healthOf });
    assert.throws(() => new WeightTuneSweeper({ tuner, retuneIntervalMs: 0 }), RangeError);
    assert.throws(() => new WeightTuneSweeper({ tuner, retuneIntervalMs: -5 }), RangeError);
    assert.throws(() => new WeightTuneSweeper({ tuner: null as never }), RangeError);
  });

  it("start is idempotent", () => {
    const dispatcher = new WeightedDispatcher(cfg53());
    const board = scoreBoard({});
    const tuner = new WeightTuner({ dispatcher, healthOf: board.healthOf });
    const timer = manualTimer();
    const sweeper = new WeightTuneSweeper({ tuner, retuneIntervalMs: 1000, setTimer: timer.setTimer });
    sweeper.start();
    sweeper.start();
    assert.equal(timer.pendingCount(), 1);
    sweeper.stop();
  });
});

describe("RetryQueue weight-tuning wiring", () => {
  it("rejects weightTuning without weighted dispatch", () => {
    assert.throws(
      () =>
        new RetryQueue({
          sender: async () => {},
          weightTuning: {},
        }),
      RangeError
    );
  });

  it("retunes against live WR-179 per-target scores", async () => {
    const timer = manualTimer();
    const retuned: WeightsRetunedInfo[] = [];
    // Target B always fails; A always answers.
    const sender: Sender = async (item) => {
      if (item.targetUrl === targetB) throw new Error("target b down");
    };
    const q = new RetryQueue({
      sender,
      baseDelayMs: 5,
      maxDelayMs: 5,
      jitterMs: 0,
      maxAttempts: 1,
      setTimer: timer.setTimer,
      weighted: cfg53(),
      weightedNow: () => 0,
      endpointHealth: {},
      weightTuning: {
        ewmaAlpha: 1,
        maxStepRatio: 1,
        hysteresisPoints: 0,
        retuneEpsilon: 0,
        onWeightsRetuned: (info) => retuned.push(info),
      },
    });
    assert.ok(q.getWeightTuneSweeper() !== undefined);
    q.start();
    for (let i = 0; i < 8; i++) {
      q.enqueue({ id: `t-${i}`, payload: Buffer.from("x"), targetUrl: endpointUrl, headers: {} });
    }
    await timer.run();
    // 5:3 smooth WRR over 8 dispatches: A gets 5 successes, B gets 3 failures.
    const before = q.getWeightedStats()[0].targets.map((t) => t.weight);
    assert.deepEqual(before, [5, 3]);
    assert.deepEqual(q.retuneWeightedTargets(), []); // seed round
    const infos = q.retuneWeightedTargets();
    assert.equal(infos.length, 1);
    const info = infos[0];
    assert.equal(info.endpoint, endpointUrl);
    assert.equal(retuned.length, 1);
    const afterB = q
      .getWeightedStats()[0]
      .targets.find((t) => t.targetUrl === targetB)!.weight;
    const afterA = q
      .getWeightedStats()[0]
      .targets.find((t) => t.targetUrl === targetA)!.weight;
    // B's WR-179 score fell (3 failures); the sick target loses share.
    assert.ok(afterB < 3, `B weight ${afterB}`);
    assert.equal(afterA, 5);
    assert.equal(info.scores[targetA], 100);
    assert.ok(info.scores[targetB] < 100, `B score ${info.scores[targetB]}`);
    q.stop();
  });

  it("updateEndpointConfig weighted patch re-baselines the tuner", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      setTimer: timer.setTimer,
      weighted: cfg53(),
      endpointHealth: {},
      weightTuning: {
        ewmaAlpha: 1,
        maxStepRatio: 1,
        hysteresisPoints: 0,
        retuneEpsilon: 0,
      },
    });
    q.start();
    const changes = q.updateEndpointConfig(endpointUrl, {
      weighted: {
        targets: [
          { targetUrl: targetA, weight: 1 },
          { targetUrl: targetB, weight: 1 },
        ],
      },
    });
    assert.deepEqual(
      changes.map((c) => c.field),
      ["weighted.targets"]
    );
    // Steady state (all scores 100): the round after a manual patch is a no-op.
    assert.deepEqual(q.retuneWeightedTargets(), []);
    const weights = q.getWeightedStats()[0].targets.map((t) => t.weight);
    assert.deepEqual(weights, [1, 1]);
    q.stop();
  });

  it("is a steady-state no-op without endpointHealth", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      setTimer: timer.setTimer,
      weighted: cfg53(),
      weightTuning: {
        ewmaAlpha: 1,
        maxStepRatio: 1,
        hysteresisPoints: 0,
        retuneEpsilon: 0,
      },
    });
    q.start();
    assert.deepEqual(q.retuneWeightedTargets(), []);
    assert.deepEqual(q.retuneWeightedTargets(), []);
    const weights = q.getWeightedStats()[0].targets.map((t) => t.weight);
    assert.deepEqual(weights, [5, 3]);
    q.stop();
  });
});

describe("weight_retuned audit (server wiring)", () => {
  it("audits every applied retune with before/after weights", async () => {
    const dir = mkdtempSync(join(tmpdir(), "weight-tune-audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const secret = "weight-tune-secret";
    const payload = Buffer.from(JSON.stringify({ n: 1 }));
    const server = createRelayServer({
      secret,
      forwardUrl: endpointUrl,
      auditLog: audit,
      sender: async (item) => {
        if (item.targetUrl === targetB) throw new Error("target b down");
      },
      retry: {
        baseDelayMs: 5,
        maxDelayMs: 5,
        jitterMs: 0,
        maxAttempts: 1,
        weighted: cfg53(),
        endpointHealth: {},
        weightTuning: {
          ewmaAlpha: 1,
          maxStepRatio: 1,
          hysteresisPoints: 0,
          retuneEpsilon: 0,
          retuneIntervalMs: 100,
        },
      },
    });
    await new Promise<void>((resolve) => server.listen(0, resolve));
    const port = (server.address() as { port: number }).port;
    const call = (method: string, path: string, body: string, headers: Record<string, string> = {}) =>
      new Promise<{ status: number; text: string }>((resolve, reject) => {
        const req = httpRequest(
          { port, method, path, headers: { "content-type": "application/json", ...headers } },
          (res) => {
            let text = "";
            res.on("data", (c) => (text += c));
            res.on("end", () => resolve({ status: res.statusCode ?? 0, text }));
          }
        );
        req.on("error", reject);
        req.end(body);
      });
    try {
      for (let i = 0; i < 8; i++) {
        const res = await call("POST", "/hook", payload.toString("utf8"), {
          "x-signature": signSha256(payload, secret),
        });
        assert.equal(res.status, 202);
      }
      await new Promise((r) => setTimeout(r, 500));
      // The sweeper fires every 100ms: an early round seeds the baseline,
      // later rounds apply retunes as B's health score falls.
      await new Promise((r) => setTimeout(r, 800));
      const events = audit.readAll() as Array<Record<string, unknown>>;
      const retunes = events.filter((e) => e.event === "weight_retuned");
      assert.ok(retunes.length >= 1, `expected weight_retuned audits, got ${retunes.length}`);
      const ev = retunes[0];
      assert.equal(ev.endpoint, endpointUrl);
      assert.deepEqual(ev.before, [
        { targetUrl: targetA, weight: 5 },
        { targetUrl: targetB, weight: 3 },
      ]);
      const afterB = (ev.after as Array<{ targetUrl: string; weight: number }>).find(
        (t) => t.targetUrl === targetB
      )!.weight;
      assert.ok(afterB < 3, `audited B weight ${afterB}`);
      assert.ok(
        (ev.scores as Record<string, number>)[targetB] < 100,
        `audited B score ${JSON.stringify(ev.scores)}`
      );
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
