import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest } from "node:http";
import {
  RetryQueue,
  type ConfigChange,
  type Sender,
} from "../src/retry.ts";
import {
  WeightedDispatcher,
  assertValidWeightedConfig,
  assertValidWeightedTargets,
} from "../src/weighted.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const endpointUrl = "http://127.0.0.1:9921/hook";
const targetA = "http://127.0.0.1:9922/a";
const targetB = "http://127.0.0.1:9923/b";
const targetC = "http://127.0.0.1:9924/c";

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

function item(id: string, targetUrl: string = endpointUrl) {
  return { id, payload: Buffer.from("hello"), targetUrl, headers: {} };
}

function cfg532() {
  return {
    [endpointUrl]: {
      targets: [
        { targetUrl: targetA, weight: 5 },
        { targetUrl: targetB, weight: 3 },
        { targetUrl: targetC, weight: 2 },
      ],
    },
  };
}

describe("weighted config validation", () => {
  it("accepts a minimal valid config", () => {
    assertValidWeightedConfig({
      [endpointUrl]: { targets: [{ targetUrl: targetA, weight: 1 }] },
    });
  });

  it("rejects a non-record config", () => {
    assert.throws(() => assertValidWeightedConfig(null as never), RangeError);
    assert.throws(() => assertValidWeightedConfig([] as never), RangeError);
    assert.throws(() => assertValidWeightedConfig("x" as never), RangeError);
  });

  it("rejects an empty endpoint key", () => {
    assert.throws(
      () => assertValidWeightedConfig({ "": { targets: [{ targetUrl: targetA, weight: 1 }] } }),
      RangeError
    );
  });

  it("rejects a non-object endpoint config", () => {
    assert.throws(
      () => assertValidWeightedConfig({ [endpointUrl]: "nope" as never }),
      RangeError
    );
  });

  it("rejects empty / non-array target lists", () => {
    assert.throws(
      () => assertValidWeightedTargets([]),
      RangeError
    );
    assert.throws(
      () => assertValidWeightedTargets("nope"),
      RangeError
    );
  });

  it("rejects non-string / empty targetUrl", () => {
    assert.throws(() => assertValidWeightedTargets([{ targetUrl: "", weight: 1 }]), RangeError);
    assert.throws(() => assertValidWeightedTargets([{ targetUrl: 42, weight: 1 }]), RangeError);
    assert.throws(() => assertValidWeightedTargets([{ weight: 1 }]), RangeError);
  });

  it("rejects duplicate targetUrl", () => {
    assert.throws(
      () =>
        assertValidWeightedTargets([
          { targetUrl: targetA, weight: 1 },
          { targetUrl: targetA, weight: 2 },
        ]),
      RangeError
    );
  });

  it("rejects non-positive / non-finite weights", () => {
    for (const weight of [0, -1, NaN, Infinity, -Infinity, "3", undefined]) {
      assert.throws(
        () => assertValidWeightedTargets([{ targetUrl: targetA, weight }]),
        RangeError,
        `weight ${String(weight)}`
      );
    }
  });

  it("accepts fractional weights", () => {
    assertValidWeightedTargets([
      { targetUrl: targetA, weight: 0.5 },
      { targetUrl: targetB, weight: 1.5 },
    ]);
  });

  it("rejects illegal failureThreshold / recoveryIntervalMs", () => {
    assert.throws(
      () =>
        assertValidWeightedConfig({
          [endpointUrl]: { targets: [{ targetUrl: targetA, weight: 1 }], failureThreshold: 0 },
        }),
      RangeError
    );
    assert.throws(
      () =>
        assertValidWeightedConfig({
          [endpointUrl]: { targets: [{ targetUrl: targetA, weight: 1 }], failureThreshold: 1.5 },
        }),
      RangeError
    );
    assert.throws(
      () =>
        assertValidWeightedConfig({
          [endpointUrl]: { targets: [{ targetUrl: targetA, weight: 1 }], recoveryIntervalMs: 0 },
        }),
      RangeError
    );
    assert.throws(
      () =>
        assertValidWeightedConfig({
          [endpointUrl]: { targets: [{ targetUrl: targetA, weight: 1 }], recoveryIntervalMs: -5 },
        }),
      RangeError
    );
  });
});

describe("smooth weighted round-robin", () => {
  it("distributes exactly 5:3:2 over 100 picks", () => {
    const d = new WeightedDispatcher(cfg532());
    const counts = new Map<string, number>();
    for (let i = 0; i < 100; i++) {
      const t = d.resolveTarget(endpointUrl)!;
      counts.set(t, (counts.get(t) ?? 0) + 1);
    }
    assert.equal(counts.get(targetA), 50);
    assert.equal(counts.get(targetB), 30);
    assert.equal(counts.get(targetC), 20);
  });

  it("is smooth — no target starves for a whole cycle", () => {
    const d = new WeightedDispatcher(cfg532());
    const seq: string[] = [];
    for (let i = 0; i < 10; i++) seq.push(d.resolveTarget(endpointUrl)!);
    assert.deepEqual(seq, [
      targetA, targetB, targetC, targetA, targetA,
      targetB, targetA, targetC, targetB, targetA,
    ]);
  });

  it("alternates equal weights and pins a single target", () => {
    const d = new WeightedDispatcher({
      [endpointUrl]: {
        targets: [
          { targetUrl: targetA, weight: 1 },
          { targetUrl: targetB, weight: 1 },
        ],
      },
    });
    const seq: string[] = [];
    for (let i = 0; i < 4; i++) seq.push(d.resolveTarget(endpointUrl)!);
    assert.deepEqual(seq, [targetA, targetB, targetA, targetB]);
    const solo = new WeightedDispatcher({
      [endpointUrl]: { targets: [{ targetUrl: targetA, weight: 7 }] },
    });
    for (let i = 0; i < 3; i++) assert.equal(solo.resolveTarget(endpointUrl), targetA);
  });

  it("returns undefined for an unconfigured endpoint (zero behavior change)", () => {
    const d = new WeightedDispatcher(cfg532());
    assert.equal(d.resolveTarget("http://127.0.0.1:9999/other"), undefined);
    assert.equal(d.hasEndpoint(endpointUrl), true);
    assert.equal(d.hasEndpoint("http://127.0.0.1:9999/other"), false);
  });
});

describe("weighted health filtering", () => {
  it("excludes a target after failureThreshold consecutive failures", () => {
    let nowMs = 1_000;
    const d = new WeightedDispatcher(
      {
        [endpointUrl]: {
          targets: [
            { targetUrl: targetA, weight: 1 },
            { targetUrl: targetB, weight: 1 },
          ],
          failureThreshold: 2,
          recoveryIntervalMs: 30_000,
        },
      },
      { now: () => nowMs }
    );
    d.recordOutcome(endpointUrl, targetA, false);
    // One failure is not enough — still in the rotation.
    const before: string[] = [];
    for (let i = 0; i < 4; i++) before.push(d.resolveTarget(endpointUrl)!);
    assert.ok(before.includes(targetA));
    d.recordOutcome(endpointUrl, targetA, false);
    nowMs += 100;
    const after: string[] = [];
    for (let i = 0; i < 10; i++) after.push(d.resolveTarget(endpointUrl)!);
    assert.ok(!after.includes(targetA));
    assert.ok(after.every((t) => t === targetB));
    const stats = d.stats()[0].targets;
    assert.equal(stats.find((t) => t.targetUrl === targetA)!.consecutiveFailures, 2);
    assert.equal(stats.find((t) => t.targetUrl === targetA)!.healthy, false);
  });

  it("a success resets the consecutive-failure counter", () => {
    let nowMs = 1_000;
    const d = new WeightedDispatcher(
      {
        [endpointUrl]: {
          targets: [
            { targetUrl: targetA, weight: 1 },
            { targetUrl: targetB, weight: 1 },
          ],
          failureThreshold: 2,
          recoveryIntervalMs: 30_000,
        },
      },
      { now: () => nowMs }
    );
    d.recordOutcome(endpointUrl, targetA, false);
    // An answering downstream (even a 4xx) counts as success — resets.
    d.recordOutcome(endpointUrl, targetA, true);
    d.recordOutcome(endpointUrl, targetA, false);
    nowMs += 100;
    const seq: string[] = [];
    for (let i = 0; i < 4; i++) seq.push(d.resolveTarget(endpointUrl)!);
    assert.ok(seq.includes(targetA));
  });

  it("recovery: the target rejoins after the recovery interval", () => {
    let nowMs = 1_000;
    const d = new WeightedDispatcher(
      {
        [endpointUrl]: {
          targets: [
            { targetUrl: targetA, weight: 1 },
            { targetUrl: targetB, weight: 1 },
          ],
          failureThreshold: 1,
          recoveryIntervalMs: 30_000,
        },
      },
      { now: () => nowMs }
    );
    d.recordOutcome(endpointUrl, targetA, false);
    nowMs += 1_000;
    assert.ok(!d.stats()[0].targets.find((t) => t.targetUrl === targetA)!.healthy);
    nowMs += 30_000;
    const stats = d.stats()[0].targets;
    assert.equal(stats.find((t) => t.targetUrl === targetA)!.healthy, true);
    const seq: string[] = [];
    for (let i = 0; i < 4; i++) seq.push(d.resolveTarget(endpointUrl)!);
    assert.ok(seq.includes(targetA));
    // The recovery canary decides: a fresh success fully re-admits.
    d.recordOutcome(endpointUrl, targetA, true);
    assert.equal(d.stats()[0].targets.find((t) => t.targetUrl === targetA)!.consecutiveFailures, 0);
  });

  it("circuit open excludes; half_open re-includes for the breaker probe", () => {
    let aState: "closed" | "open" | "half_open" = "open";
    const d = new WeightedDispatcher(cfg532(), {
      circuitState: (t) => (t === targetA ? aState : "closed"),
    });
    const seq: string[] = [];
    for (let i = 0; i < 6; i++) seq.push(d.resolveTarget(endpointUrl)!);
    assert.ok(!seq.includes(targetA));
    aState = "half_open";
    const probe: string[] = [];
    for (let i = 0; i < 4; i++) probe.push(d.resolveTarget(endpointUrl)!);
    assert.ok(probe.includes(targetA));
  });

  it("pins to the first target when every target is unhealthy", () => {
    let nowMs = 1_000;
    const d = new WeightedDispatcher(
      {
        [endpointUrl]: {
          targets: [
            { targetUrl: targetA, weight: 1 },
            { targetUrl: targetB, weight: 1 },
          ],
          failureThreshold: 1,
          recoveryIntervalMs: 60_000,
        },
      },
      { now: () => nowMs }
    );
    d.recordOutcome(endpointUrl, targetA, false);
    d.recordOutcome(endpointUrl, targetB, false);
    assert.equal(d.resolveTarget(endpointUrl), targetA);
    assert.equal(d.resolveTarget(endpointUrl), targetA);
  });

  it("ignores outcomes for unknown endpoints and removed targets", () => {
    const d = new WeightedDispatcher(cfg532());
    d.recordOutcome("http://127.0.0.1:9999/other", targetA, false);
    d.recordOutcome(endpointUrl, "http://127.0.0.1:9999/gone", false);
    const stats = d.stats()[0].targets;
    assert.ok(stats.every((t) => t.consecutiveFailures === 0 && t.healthy));
  });
});

describe("weighted runtime weight updates (setWeights)", () => {
  it("changes the distribution on the next picks", () => {
    const d = new WeightedDispatcher({
      [endpointUrl]: {
        targets: [
          { targetUrl: targetA, weight: 1 },
          { targetUrl: targetB, weight: 1 },
        ],
      },
    });
    d.setWeights(endpointUrl, [
      { targetUrl: targetA, weight: 3 },
      { targetUrl: targetB, weight: 1 },
    ]);
    const counts = new Map<string, number>();
    for (let i = 0; i < 8; i++) {
      const t = d.resolveTarget(endpointUrl)!;
      counts.set(t, (counts.get(t) ?? 0) + 1);
    }
    assert.equal(counts.get(targetA), 6);
    assert.equal(counts.get(targetB), 2);
  });

  it("rejects an illegal list with zero partial application", () => {
    const d = new WeightedDispatcher({
      [endpointUrl]: {
        targets: [
          { targetUrl: targetA, weight: 1 },
          { targetUrl: targetB, weight: 1 },
        ],
      },
    });
    assert.throws(
      () => d.setWeights(endpointUrl, [{ targetUrl: targetA, weight: 0 }]),
      RangeError
    );
    assert.throws(
      () => d.setWeights(endpointUrl, []),
      RangeError
    );
    // The previous config is completely intact.
    const counts = new Map<string, number>();
    for (let i = 0; i < 4; i++) {
      const t = d.resolveTarget(endpointUrl)!;
      counts.set(t, (counts.get(t) ?? 0) + 1);
    }
    assert.equal(counts.get(targetA), 2);
    assert.equal(counts.get(targetB), 2);
  });

  it("supports adding and removing targets; health counters survive for survivors", () => {
    let nowMs = 1_000;
    const d = new WeightedDispatcher(
      {
        [endpointUrl]: {
          targets: [
            { targetUrl: targetA, weight: 1 },
            { targetUrl: targetB, weight: 1 },
          ],
          failureThreshold: 1,
          recoveryIntervalMs: 30_000,
        },
      },
      { now: () => nowMs }
    );
    d.recordOutcome(endpointUrl, targetB, false);
    d.setWeights(endpointUrl, [
      { targetUrl: targetB, weight: 2 },
      { targetUrl: targetC, weight: 2 },
    ]);
    const stats = d.stats()[0].targets;
    assert.deepEqual(
      stats.map((t) => t.targetUrl),
      [targetB, targetC]
    );
    // targetB's failure streak survives the update — still excluded.
    assert.equal(stats.find((t) => t.targetUrl === targetB)!.consecutiveFailures, 1);
    assert.equal(stats.find((t) => t.targetUrl === targetB)!.healthy, false);
    const seq: string[] = [];
    for (let i = 0; i < 4; i++) seq.push(d.resolveTarget(endpointUrl)!);
    assert.ok(seq.every((t) => t === targetC));
  });

  it("throws for an endpoint without weighted config", () => {
    const d = new WeightedDispatcher(cfg532());
    assert.throws(
      () => d.setWeights("http://127.0.0.1:9999/other", [{ targetUrl: targetA, weight: 1 }]),
      RangeError
    );
  });
});

describe("RetryQueue weighted integration", () => {
  it("spreads deliveries 5:3:2 and exposes per-target stats and metrics", async () => {
    const timer = manualTimer();
    const seen: string[] = [];
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
      weighted: cfg532(),
      weightedNow: () => 0,
    });
    q.start();
    for (let i = 0; i < 10; i++) q.enqueue(item(`w-${i}`));
    await timer.run();
    const counts = new Map<string, number>();
    for (const t of seen) counts.set(t, (counts.get(t) ?? 0) + 1);
    assert.equal(counts.get(targetA), 5);
    assert.equal(counts.get(targetB), 3);
    assert.equal(counts.get(targetC), 2);
    const stats = q.getWeightedStats();
    assert.equal(stats.length, 1);
    assert.equal(stats[0].endpoint, endpointUrl);
    assert.deepEqual(
      stats[0].targets.map((t) => ({ targetUrl: t.targetUrl, weight: t.weight, dispatched: t.dispatched })),
      [
        { targetUrl: targetA, weight: 5, dispatched: 5 },
        { targetUrl: targetB, weight: 3, dispatched: 3 },
        { targetUrl: targetC, weight: 2, dispatched: 2 },
      ]
    );
    assert.ok(stats[0].targets.every((t) => t.healthy));
    const exposition = q.renderMetrics();
    assert.match(
      exposition,
      new RegExp(`relay_weighted_dispatch_total\\{endpoint="${endpointUrl}",target="${targetA}"\\} 5`)
    );
    assert.match(
      exposition,
      new RegExp(`relay_weighted_dispatch_total\\{endpoint="${endpointUrl}",target="${targetB}"\\} 3`)
    );
    assert.match(
      exposition,
      new RegExp(`relay_weighted_dispatch_total\\{endpoint="${endpointUrl}",target="${targetC}"\\} 2`)
    );
    q.stop();
  });

  it("omits relay_weighted_dispatch_total when weighted mode is not in use", () => {
    const q = new RetryQueue({ sender: async () => {} });
    assert.ok(!q.renderMetrics().includes("relay_weighted_dispatch_total"));
    assert.deepEqual(q.getWeightedStats(), []);
    q.stop();
  });

  it("rejects an invalid weighted config at construction", () => {
    assert.throws(
      () =>
        new RetryQueue({
          weighted: { [endpointUrl]: { targets: [{ targetUrl: targetA, weight: 0 }] } },
        }),
      RangeError
    );
  });

  it("rejects weighted + failover on the same endpoint at startup", () => {
    assert.throws(
      () =>
        new RetryQueue({
          weighted: cfg532(),
          failover: { [endpointUrl]: { standbys: [targetB] } },
        }),
      RangeError
    );
  });

  it("allows weighted and failover on different endpoints", () => {
    const other = "http://127.0.0.1:9925/other";
    const q = new RetryQueue({
      weighted: cfg532(),
      failover: { [other]: { standbys: [targetB] } },
    });
    assert.equal(q.getWeightedStats().length, 1);
    assert.equal(q.getFailoverStats().length, 1);
    q.stop();
  });

  it("excludes a sick target from the rotation through real delivery outcomes", async () => {
    const timer = manualTimer();
    const seen: string[] = [];
    const sender: Sender = async (item) => {
      seen.push(item.targetUrl);
      if (item.targetUrl === targetA) throw new Error("target a down");
    };
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 4,
      setTimer: timer.setTimer,
      weighted: {
        [endpointUrl]: {
          targets: [
            { targetUrl: targetA, weight: 1 },
            { targetUrl: targetB, weight: 1 },
          ],
          failureThreshold: 2,
          recoveryIntervalMs: 60_000,
        },
      },
      weightedNow: () => 0,
    });
    q.start();
    q.enqueue(item("sick-1"));
    q.enqueue(item("sick-2"));
    q.enqueue(item("sick-3"));
    await timer.run();
    const countA = seen.filter((t) => t === targetA).length;
    // targetA failed twice in a row and left the rotation — no more attempts hit it.
    assert.equal(countA, 2);
    assert.ok(seen.length > countA);
    const stats = q.getWeightedStats()[0].targets;
    assert.equal(stats.find((t) => t.targetUrl === targetA)!.healthy, false);
    assert.equal(stats.find((t) => t.targetUrl === targetB)!.healthy, true);
    // A later delivery goes only to the healthy target.
    seen.length = 0;
    q.enqueue(item("sick-4"));
    await timer.run();
    assert.ok(seen.length > 0);
    assert.ok(seen.every((t) => t === targetB));
    q.stop();
  });

  it("updateEndpointConfig retunes weights, audits the change, and fails closed on bad patches", async () => {
    const timer = manualTimer();
    const seen: string[] = [];
    const changes: ConfigChange[] = [];
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
      weighted: {
        [endpointUrl]: {
          targets: [
            { targetUrl: targetA, weight: 1 },
            { targetUrl: targetB, weight: 1 },
          ],
        },
      },
      onConfigChange: (_endpoint, c) => changes.push(...c),
    });
    q.start();
    const applied = q.updateEndpointConfig(endpointUrl, {
      weighted: {
        targets: [
          { targetUrl: targetA, weight: 3 },
          { targetUrl: targetB, weight: 1 },
        ],
      },
    });
    assert.equal(applied.length, 1);
    assert.equal(applied[0].field, "weighted.targets");
    assert.deepEqual(applied[0].from, [
      { targetUrl: targetA, weight: 1 },
      { targetUrl: targetB, weight: 1 },
    ]);
    assert.deepEqual(applied[0].to, [
      { targetUrl: targetA, weight: 3 },
      { targetUrl: targetB, weight: 1 },
    ]);
    assert.deepEqual(changes, applied);
    for (let i = 0; i < 8; i++) q.enqueue(item(`rw-${i}`));
    await timer.run();
    const counts = new Map<string, number>();
    for (const t of seen) counts.set(t, (counts.get(t) ?? 0) + 1);
    assert.equal(counts.get(targetA), 6);
    assert.equal(counts.get(targetB), 2);
    // An illegal patch throws and leaves the running weights intact.
    assert.throws(
      () =>
        q.updateEndpointConfig(endpointUrl, {
          weighted: { targets: [{ targetUrl: targetA, weight: -2 }] },
        }),
      RangeError
    );
    seen.length = 0;
    for (let i = 0; i < 4; i++) q.enqueue(item(`rw2-${i}`));
    await timer.run();
    const counts2 = new Map<string, number>();
    for (const t of seen) counts2.set(t, (counts2.get(t) ?? 0) + 1);
    assert.equal(counts2.get(targetA), 3);
    assert.equal(counts2.get(targetB), 1);
    // Patching an endpoint without weighted dispatch is a RangeError.
    assert.throws(
      () =>
        q.updateEndpointConfig("http://127.0.0.1:9999/other", {
          weighted: { targets: [{ targetUrl: targetA, weight: 1 }] },
        }),
      RangeError
    );
    q.stop();
  });
});

describe("weighted server wiring", () => {
  it("splits intake traffic across stub targets and serves the metrics series", async () => {
    const dir = mkdtempSync(join(tmpdir(), "weighted-e2e-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const secret = "weighted-hook-secret";
    const opToken = "op-token-weighted";
    const payload = Buffer.from(JSON.stringify({ n: 1 }));
    const seen: string[] = [];
    const server = createRelayServer({
      secret,
      forwardUrl: endpointUrl,
      auditLog: audit,
      operatorToken: opToken,
      sender: async (item) => {
        seen.push(item.targetUrl);
      },
      retry: {
        baseDelayMs: 5,
        maxDelayMs: 5,
        jitterMs: 0,
        maxAttempts: 2,
        weighted: cfg532(),
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
      for (let i = 0; i < 10; i++) {
        const res = await call("POST", "/hook", payload.toString("utf8"), {
          "x-signature": signSha256(payload, secret),
        });
        assert.equal(res.status, 202);
      }
      await new Promise((r) => setTimeout(r, 500));
      const counts = new Map<string, number>();
      for (const t of seen) counts.set(t, (counts.get(t) ?? 0) + 1);
      assert.equal(counts.get(targetA), 5);
      assert.equal(counts.get(targetB), 3);
      assert.equal(counts.get(targetC), 2);
      const metrics = await call("GET", "/metrics", "", {
        authorization: `Bearer ${opToken}`,
      });
      assert.equal(metrics.status, 200);
      assert.ok(
        metrics.text.includes(
          `relay_weighted_dispatch_total{endpoint="${endpointUrl}",target="${targetA}"} 5`
        )
      );
      // Runtime weight retune over the operator endpoint: audited, 400 on a bad patch.
      const patchRes = await call(
        "POST",
        "/config/endpoint",
        JSON.stringify({
          endpoint: endpointUrl,
          weighted: {
            targets: [
              { targetUrl: targetA, weight: 1 },
              { targetUrl: targetB, weight: 1 },
              { targetUrl: targetC, weight: 1 },
            ],
          },
        }),
        { authorization: `Bearer ${opToken}` }
      );
      assert.equal(patchRes.status, 200);
      const badRes = await call(
        "POST",
        "/config/endpoint",
        JSON.stringify({
          endpoint: endpointUrl,
          weighted: { targets: [{ targetUrl: targetA, weight: 0 }] },
        }),
        { authorization: `Bearer ${opToken}` }
      );
      assert.equal(badRes.status, 400);
      seen.length = 0;
      for (let i = 0; i < 3; i++) {
        const res = await call("POST", "/hook", payload.toString("utf8"), {
          "x-signature": signSha256(payload, secret),
        });
        assert.equal(res.status, 202);
      }
      await new Promise((r) => setTimeout(r, 500));
      const counts2 = new Map<string, number>();
      for (const t of seen) counts2.set(t, (counts2.get(t) ?? 0) + 1);
      assert.equal(counts2.get(targetA), 1);
      assert.equal(counts2.get(targetB), 1);
      assert.equal(counts2.get(targetC), 1);
      const events = audit.readAll() as Array<Record<string, unknown>>;
      const updated = events.filter((e) => e.event === "endpoint_config_updated");
      assert.equal(updated.length, 1);
      assert.equal(updated[0].endpoint, endpointUrl);
      assert.deepEqual((updated[0].changes as Array<Record<string, unknown>>).map((c) => c.field), [
        "weighted.targets",
      ]);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it("rejects weighted + failover on the same endpoint through createRelayServer", () => {
    const dir = mkdtempSync(join(tmpdir(), "weighted-mutex-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    assert.throws(
      () =>
        createRelayServer({
          secret: "weighted-mutex-secret",
          forwardUrl: endpointUrl,
          auditLog: audit,
          retry: {
            weighted: cfg532(),
            failover: { [endpointUrl]: { standbys: [targetB] } },
          },
        }),
      RangeError
    );
  });
});
