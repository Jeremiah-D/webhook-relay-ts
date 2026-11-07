import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SloRiskPredictor, type SloRiskObservation } from "../src/slo-risk.ts";
import { RetryQueue, type SloRiskInfo } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "slo-risk-revision-test-key";
const opToken = "slo-risk-revision-op-token";
const URL_A = "http://localhost:9999/a";
const EP_A = "http://a.example/hook";

const MUST_RESTART =
  "reviseSloRisk: SLO risk prediction is not configured — enabling it requires a restart";

const DEFAULTS = {
  warnRatio: 0.8,
  ewmaAlpha: 0.2,
  minSamples: 3,
  clearRatio: 0.7,
  trendHorizon: 3,
};

function observation(over: Partial<SloRiskObservation> = {}): SloRiskObservation {
  return { backlog: 0, concurrency: Infinity, sloMs: 1000, ...over };
}

function fastStats(count = 5) {
  return { p95: 50, min: 50, count };
}

describe("SloRiskPredictor.retune (WR-347)", () => {
  it("warnRatio tighten elevates on the next observe, not at retune time", () => {
    const seen: SloRiskInfo[] = [];
    const p = new SloRiskPredictor({
      warnRatio: 0.9,
      minSamples: 1,
      onSloRisk: (i) => seen.push(i),
    });
    const slow = observation({ stats: { p95: 850, min: 50, count: 5 } });
    assert.equal(p.observe(EP_A, slow), undefined, "0.85 is below the 0.9 threshold");
    assert.deepEqual(seen, []);
    assert.deepEqual(p.retune({ warnRatio: 0.8 }), { ...DEFAULTS, warnRatio: 0.8, minSamples: 1 });
    assert.deepEqual(seen, [], "retune must not fire the callback");
    const t = p.observe(EP_A, slow);
    assert.equal(t?.state, "elevated");
    assert.equal(t?.score, 0.85);
    assert.equal(seen.length, 1);
  });

  it("warnRatio relax leaves the latch alone until the next observe re-evaluates it", () => {
    const seen: SloRiskInfo[] = [];
    const p = new SloRiskPredictor({
      warnRatio: 0.8,
      clearRatio: 0.7,
      minSamples: 1,
      onSloRisk: (i) => seen.push(i),
    });
    const slow = observation({ stats: { p95: 850, min: 50, count: 5 } });
    assert.equal(p.observe(EP_A, slow)?.state, "elevated");
    assert.equal(seen.length, 1);
    p.retune({ warnRatio: 0.95 });
    assert.equal(p.atRisk().length, 1, "retune must not clear the latch");
    assert.equal(seen.length, 1);
    // Same score: above the new clear line (0.95 * 0.7 = 0.665), still at risk.
    assert.equal(p.observe(EP_A, slow), undefined);
    assert.equal(p.atRisk().length, 1);
    // Below the new clear line — but above the old one (0.56), so this
    // clear proves the next observe re-evaluates under the new threshold.
    const cleared = p.observe(EP_A, observation({ stats: { p95: 600, min: 50, count: 5 } }));
    assert.equal(cleared?.state, "cleared");
    assert.equal(seen.length, 2);
    assert.deepEqual(p.atRisk(), []);
  });

  it("trendHorizon widen grows the forward projection on the next observe", () => {
    // alpha = 1: the EWMA tracks the latest sample exactly, so the
    // trend is sample - prev and every number below is exact.
    // Both start at trendHorizon 0 (the default is 3).
    const control = new SloRiskPredictor({ ewmaAlpha: 1, minSamples: 1, trendHorizon: 0 });
    const retuned = new SloRiskPredictor({ ewmaAlpha: 1, minSamples: 1, trendHorizon: 0 });
    const rising = (backlog: number) =>
      observation({ backlog, concurrency: 1, stats: fastStats() });
    for (const p of [control, retuned]) {
      p.observe(EP_A, rising(0));
      p.observe(EP_A, rising(10));
      // horizon 0: projected 10 -> predicted 50 + 10*50 = 550.
      assert.equal(p.snapshot()[0].predictedLatencyMs, 550);
    }
    retuned.retune({ trendHorizon: 3 });
    assert.equal(retuned.snapshot()[0].predictedLatencyMs, 550, "retune alone changes nothing");
    for (const p of [control, retuned]) p.observe(EP_A, rising(20));
    // EWMA 20, trend 10: control projects 20 -> 1050; retuned projects
    // 20 + 10*3 = 50 -> 2550.
    assert.equal(control.snapshot()[0].predictedLatencyMs, 1050);
    assert.equal(retuned.snapshot()[0].predictedLatencyMs, 2550);
  });

  it("ewmaAlpha change smooths with the new weight and keeps the history", () => {
    const p = new SloRiskPredictor({ ewmaAlpha: 1, minSamples: 1 });
    p.observe(EP_A, observation({ backlog: 0, stats: fastStats() }));
    p.observe(EP_A, observation({ backlog: 100, stats: fastStats() }));
    assert.equal(p.snapshot()[0].backlogEwma, 100);
    p.retune({ ewmaAlpha: 0.5 });
    assert.equal(p.snapshot()[0].backlogEwma, 100, "retune alone changes nothing");
    // New weight on the preserved history: 0.5*0 + 0.5*100 = 50.
    // (Under the old alpha 1 — or after a reset — this would be 0.)
    p.observe(EP_A, observation({ backlog: 0, stats: fastStats() }));
    assert.equal(p.snapshot()[0].backlogEwma, 50);
  });

  it("minSamples raise extends the cold start", () => {
    const p = new SloRiskPredictor({ minSamples: 1 });
    // `observe` returns undefined without a transition, so evaluation
    // is read from the snapshot, not the return value.
    p.observe("e", observation({ stats: fastStats(1) }));
    assert.equal(p.snapshot().length, 1);
    p.retune({ minSamples: 5 });
    // A new endpoint with only 3 samples is back in cold start.
    p.observe("e2", observation({ stats: fastStats(3) }));
    assert.equal(p.snapshot().length, 1);
    p.observe("e2", observation({ stats: fastStats(5) }));
    assert.equal(p.snapshot().length, 2);
    // The old endpoint re-enters cold start under the new gate too.
    p.observe("e", observation({ stats: fastStats(3) }));
    assert.equal(p.snapshot().length, 2);
  });

  it("rejects illegal values and leaves the live config untouched", () => {
    const seen: SloRiskInfo[] = [];
    const p = new SloRiskPredictor({ ...DEFAULTS, onSloRisk: (i) => seen.push(i) });
    const bad: Array<Record<string, unknown>> = [
      { warnRatio: 0 },
      { warnRatio: 1.5 },
      { ewmaAlpha: 0 },
      { clearRatio: 1 },
      { minSamples: 0 },
      { minSamples: 1.5 },
      { trendHorizon: -1 },
    ];
    for (const patch of bad) {
      assert.throws(() => p.retune(patch as never), RangeError);
    }
    assert.deepEqual(p.config(), DEFAULTS);
    // The live predictor still runs on the old values.
    const t = p.observe(EP_A, observation({ stats: { p95: 850, min: 50, count: 5 } }));
    assert.equal(t?.state, "elevated");
    assert.equal(seen.length, 1);
  });

  it("rejects an empty patch and non-object patches", () => {
    const p = new SloRiskPredictor({ ...DEFAULTS });
    assert.throws(() => p.retune({}), RangeError);
    for (const bad of [null, [], "0.8", 2, undefined]) {
      assert.throws(() => p.retune(bad as never), RangeError);
    }
    assert.deepEqual(p.config(), DEFAULTS);
  });

  it("same-value patch is a no-op; config() is a snapshot", () => {
    const p = new SloRiskPredictor({ ...DEFAULTS });
    assert.deepEqual(p.retune({ warnRatio: 0.8 }), DEFAULTS);
    const snap = p.config();
    snap.warnRatio = 0.1;
    snap.minSamples = 99;
    assert.deepEqual(p.config(), DEFAULTS);
    assert.deepEqual(p.retune({ ...DEFAULTS }), DEFAULTS);
  });

  it("revision never resets EWMA/atRisk; the next observe re-evaluates under the new threshold", () => {
    const seen: SloRiskInfo[] = [];
    const p = new SloRiskPredictor({
      warnRatio: 0.8,
      clearRatio: 0.7,
      minSamples: 1,
      ewmaAlpha: 1,
      onSloRisk: (i) => seen.push(i),
    });
    // Backlog pressure elevates: predicted 50 + 30*50 = 1550.
    const t = p.observe(EP_A, observation({ backlog: 30, concurrency: 1, stats: fastStats() }));
    assert.equal(t?.state, "elevated");
    assert.equal(t?.predictedLatencyMs, 1550);
    const before = p.snapshot()[0];
    assert.equal(before.backlogEwma, 30);
    p.retune({ warnRatio: 0.6, ewmaAlpha: 0.5 });
    const after = p.snapshot()[0];
    assert.deepEqual(after, before, "retune must not reset EWMA/score/prediction");
    assert.equal(p.atRisk().length, 1, "latch untouched by retune");
    assert.equal(seen.length, 1);
    // The next observe re-evaluates under the new warnRatio — but the
    // backlog still dominates, so the endpoint stays elevated.
    assert.equal(
      p.observe(EP_A, observation({ backlog: 30, concurrency: 1, stats: fastStats() })),
      undefined
    );
    assert.equal(p.atRisk().length, 1);
    assert.equal(seen.length, 1);
  });

  it("onSloRisk survives a retune unchanged", () => {
    const seen: SloRiskInfo[] = [];
    const p = new SloRiskPredictor({
      warnRatio: 0.8,
      minSamples: 1,
      onSloRisk: (i) => seen.push(i),
    });
    assert.equal(
      p.observe(EP_A, observation({ stats: { p95: 850, min: 50, count: 5 } }))?.state,
      "elevated"
    );
    assert.equal(seen.length, 1);
    p.retune({ warnRatio: 0.9 });
    // The original callback still receives the clear.
    const cleared = p.observe(EP_A, observation({ stats: { p95: 500, min: 50, count: 5 } }));
    assert.equal(cleared?.state, "cleared");
    assert.equal(seen.length, 2);
    assert.equal(seen[1].state, "cleared");
  });
});

/** Deterministic timer: `run()` executes pending callbacks immediately. */
function manualTimer() {
  const pending: Array<() => void> = [];
  return {
    setTimer: (fn: () => void, _ms: number) => {
      pending.push(fn);
      return { clear: () => { const i = pending.indexOf(fn); if (i >= 0) pending.splice(i, 1); } };
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

describe("RetryQueue.reviseSloRisk (WR-347)", () => {
  const URL = "http://127.0.0.1:9999/hook";
  const ITEM = { payload: Buffer.from("x"), targetUrl: URL, headers: {} };

  it("revision retunes every live tenant predictor; later-born tenants start revised", async () => {
    const clock = { now: 0 };
    const timer = manualTimer();
    const risks: SloRiskInfo[] = [];
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      latency: {
        sloMs: 1000,
        now: () => clock.now,
        sloRisk: { warnRatio: 0.8, minSamples: 2, onSloRisk: (r) => risks.push(r) },
      },
      setTimer: timer.setTimer,
    });
    q.start();
    // 700ms samples against a 1000ms budget: score 0.7, below the 0.8
    // threshold, so nothing elevates before the revision.
    async function seed(tenant: string | undefined, prefix: string) {
      for (let i = 0; i < 3; i++) {
        clock.now = i * 10000;
        q.enqueue({
          ...ITEM,
          id: `${prefix}-${i}`,
          ...(tenant === undefined ? {} : { tenantId: tenant }),
        });
        clock.now = i * 10000 + 700;
        await timer.run();
      }
    }
    try {
      await seed(undefined, "d");
      await seed("acme", "a");
      assert.deepEqual(risks, []);
      const rows = q.getSloRiskStats();
      assert.equal(rows.length, 2);
      assert.ok(rows.every((r) => r.atRisk === false));
      assert.deepEqual(q.getSloRiskConfig(), { ...DEFAULTS, minSamples: 2 });

      assert.deepEqual(q.reviseSloRisk({ warnRatio: 0.6 }), { ...DEFAULTS, minSamples: 2, warnRatio: 0.6 });
      assert.deepEqual(q.getSloRiskConfig(), { ...DEFAULTS, minSamples: 2, warnRatio: 0.6 });
      // The retune itself evaluates nothing: acme stays silent.
      assert.deepEqual(risks, []);

      // The default tenant's next observation re-evaluates under 0.6.
      clock.now = 30000;
      q.enqueue({ ...ITEM, id: "d-3" });
      clock.now = 30700;
      await timer.run();
      assert.equal(risks.length, 1);
      assert.equal(risks[0].state, "elevated");
      assert.equal(risks[0].tenant, undefined);

      // A tenant born after the revision starts from the revised values:
      // its 0.7 score elevates under 0.6 (it would not under 0.8).
      await seed("newco", "n");
      assert.equal(risks.length, 2);
      assert.equal(risks[1].state, "elevated");
      assert.equal(risks[1].tenant, "newco");
      const after = q.getSloRiskStats();
      assert.equal(after.length, 3);
      assert.equal(after.find((r) => r.tenant === "acme")?.atRisk, false);
      assert.equal(after.find((r) => r.tenant === undefined)?.atRisk, true);
      assert.equal(after.find((r) => r.tenant === "newco")?.atRisk, true);
    } finally {
      await q.shutdown();
    }
  });

  it("unconfigured queue throws must-restart and the getter returns undefined", async () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      assert.equal(q.getSloRiskConfig(), undefined);
      assert.throws(() => q.reviseSloRisk({ warnRatio: 0.6 }), {
        name: "Error",
        message: MUST_RESTART,
      });
    } finally {
      await q.shutdown();
    }
  });
});

describe("RelayServer SLO-risk revision (WR-347)", () => {
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

  function makeRelay(sloRisk?: Record<string, unknown>) {
    const dir = mkdtempSync(join(tmpdir(), "slo-risk-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the key is spelled out dynamically
      // instead of literally (see AGENTS.md).
      ["sec" + "ret"]: signingKey,
      forwardUrl: URL_A,
      auditLog: audit,
      operatorToken: opToken,
      sender: async () => ({ statusCode: 200, body: Buffer.from("ok") }),
      retry: {
        baseDelayMs: 5,
        jitterMs: 0,
        maxAttempts: 2,
        latency: {
          sloMs: 1000,
          ...(sloRisk === undefined ? {} : { sloRisk }),
        },
      },
    });
    servers.push(relay);
    return { relay, audit };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  it("revision audits previous/current exactly; same-value is a silent no-op", async () => {
    const construction = { ...DEFAULTS };
    const { relay, audit } = makeRelay(construction);
    await listen(relay);
    // First `previous` is the construction config.
    assert.deepEqual(relay.getSloRiskConfig!(), construction);
    assert.deepEqual(relay.reviseSloRisk!({ warnRatio: 0.6 }), {
      ...construction,
      warnRatio: 0.6,
    });
    const revised = eventsOf(audit, "slo_risk_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, construction);
    assert.deepEqual(revised[0].current, { ...construction, warnRatio: 0.6 });
    // Landing exactly on the live values audits nothing.
    relay.reviseSloRisk!({ warnRatio: 0.6 });
    assert.equal(eventsOf(audit, "slo_risk_revised").length, 1);
    assert.deepEqual(relay.getSloRiskConfig!(), { ...construction, warnRatio: 0.6 });
    // A second real revision chains previous from the revised values.
    relay.reviseSloRisk!({ trendHorizon: 5, minSamples: 10 });
    const revised2 = eventsOf(audit, "slo_risk_revised");
    assert.equal(revised2.length, 2);
    assert.deepEqual(revised2[1].previous, { ...construction, warnRatio: 0.6 });
    assert.deepEqual(revised2[1].current, {
      ...construction,
      warnRatio: 0.6,
      trendHorizon: 5,
      minSamples: 10,
    });
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseSloRisk!({ warnRatio: 0 }), RangeError);
    assert.throws(() => relay.reviseSloRisk!({}), RangeError);
    assert.throws(() => relay.reviseSloRisk!(null as never), RangeError);
    assert.equal(eventsOf(audit, "slo_risk_revised").length, 2);
    assert.deepEqual(relay.getSloRiskConfig!(), {
      ...construction,
      warnRatio: 0.6,
      trendHorizon: 5,
      minSamples: 10,
    });
    // The getter returns a snapshot, not a live reference.
    const snap = relay.getSloRiskConfig!();
    snap.minSamples = 999;
    assert.deepEqual(relay.getSloRiskConfig!(), {
      ...construction,
      warnRatio: 0.6,
      trendHorizon: 5,
      minSamples: 10,
    });
  });

  it("first previous is the defaults when configured with an empty object", async () => {
    const { relay, audit } = makeRelay({});
    await listen(relay);
    assert.deepEqual(relay.getSloRiskConfig!(), DEFAULTS);
    assert.deepEqual(relay.reviseSloRisk!({ warnRatio: 0.6 }), {
      ...DEFAULTS,
      warnRatio: 0.6,
    });
    const revised = eventsOf(audit, "slo_risk_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, DEFAULTS);
    assert.deepEqual(revised[0].current, { ...DEFAULTS, warnRatio: 0.6 });
  });

  it("unconfigured server throws must-restart and mounts no getter", async () => {
    const { relay } = makeRelay(undefined);
    await listen(relay);
    assert.equal(relay.getSloRiskConfig, undefined);
    assert.equal(typeof relay.reviseSloRisk, "function", "revise is always set");
    assert.throws(() => relay.reviseSloRisk!({ warnRatio: 0.6 }), {
      name: "Error",
      message: MUST_RESTART,
    });
  });
});
