import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SloRiskPredictor, type SloRiskObservation } from "../src/slo-risk.ts";
import { RetryQueue, type SloRiskInfo } from "../src/retry.ts";
import { renderPrometheus } from "../src/metrics.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

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

const URL = "http://127.0.0.1:9999/hook";
const ITEM = { payload: Buffer.from("x"), targetUrl: URL, headers: {} };

function obs(over: Partial<SloRiskObservation> = {}): SloRiskObservation {
  return { backlog: 0, concurrency: Infinity, sloMs: 1000, ...over };
}

describe("SloRiskPredictor", () => {
  it("rejects invalid configs", () => {
    assert.throws(() => new SloRiskPredictor({ warnRatio: 0 }), RangeError);
    assert.throws(() => new SloRiskPredictor({ warnRatio: 1.5 }), RangeError);
    assert.throws(() => new SloRiskPredictor({ ewmaAlpha: 0 }), RangeError);
    assert.throws(() => new SloRiskPredictor({ ewmaAlpha: 2 }), RangeError);
    assert.throws(() => new SloRiskPredictor({ minSamples: 0 }), RangeError);
    assert.throws(() => new SloRiskPredictor({ minSamples: 1.5 }), RangeError);
    assert.throws(() => new SloRiskPredictor({ clearRatio: 0 }), RangeError);
    assert.throws(() => new SloRiskPredictor({ clearRatio: 1 }), RangeError);
    assert.throws(() => new SloRiskPredictor({ trendHorizon: -1 }), RangeError);
  });

  it("cold start never fires, but the backlog EWMA stays warm", () => {
    const seen: SloRiskInfo[] = [];
    const p = new SloRiskPredictor({ minSamples: 3, onSloRisk: (i) => seen.push(i) });
    // No latency evidence yet: huge backlog, no transition.
    assert.equal(p.observe("e", obs({ backlog: 500, concurrency: 1 })), undefined);
    assert.equal(p.observe("e", obs({ backlog: 500, concurrency: 1 })), undefined);
    assert.deepEqual(seen, []);
    assert.deepEqual(p.atRisk(), []);
    assert.deepEqual(p.snapshot(), []);
    // Latency evidence arrives: the warmed EWMA feeds the projection at once.
    const t = p.observe(
      "e",
      obs({ backlog: 500, concurrency: 1, stats: { p95: 50, min: 50, count: 3 } })
    );
    assert.equal(t?.state, "elevated");
    assert.ok(t!.backlogEwma > 400); // EWMA was tracking the 500 backlog all along
    assert.equal(seen.length, 1);
  });

  it("fires on latency pressure and clears with hysteresis", () => {
    const seen: SloRiskInfo[] = [];
    const p = new SloRiskPredictor({
      warnRatio: 0.8,
      clearRatio: 0.7, // clears below 0.56
      onSloRisk: (i) => seen.push(i),
    });
    const slow = obs({ stats: { p95: 850, min: 50, count: 5 } });
    const t = p.observe("e", slow);
    assert.equal(t?.state, "elevated");
    assert.equal(t?.score, 0.85);
    assert.equal(t?.p95Ms, 850);
    assert.equal(t?.sloMs, 1000);
    // Same score: no repeat fire.
    assert.equal(p.observe("e", slow), undefined);
    assert.equal(seen.length, 1);
    // 0.6 is above the clear line (0.56): still at risk, no transition.
    assert.equal(
      p.observe("e", obs({ stats: { p95: 600, min: 50, count: 5 } })),
      undefined
    );
    assert.equal(p.atRisk().length, 1);
    // 0.5 clears.
    const c = p.observe("e", obs({ stats: { p95: 500, min: 50, count: 5 } }));
    assert.equal(c?.state, "cleared");
    assert.equal(seen.length, 2);
    assert.deepEqual(p.atRisk(), []);
  });

  it("backlog pressure predicts a breach before any delivery misses", () => {
    const seen: SloRiskInfo[] = [];
    // alpha = 1: EWMA tracks the latest sample exactly, trend = sample - prev.
    const p = new SloRiskPredictor({ ewmaAlpha: 1, onSloRisk: (i) => seen.push(i) });
    const fast = { p95: 50, min: 50, count: 5 };
    assert.equal(p.observe("e", obs({ backlog: 0, concurrency: 1, stats: fast })), undefined);
    // 30 deep with 50ms service and 1-wide concurrency: projected queueing
    // = (30 + 30*3) * 50 = 6000ms — breach predicted, nothing missed yet.
    const t = p.observe("e", obs({ backlog: 30, concurrency: 1, stats: fast }));
    assert.equal(t?.state, "elevated");
    assert.ok(t!.score > 1);
    assert.ok(t!.predictedLatencyMs > 1000);
    assert.equal(t?.backlogEwma, 30);
    const [risk] = p.atRisk();
    assert.equal(risk.endpoint, "e");
    assert.equal(risk.headroomSeconds, 0); // predicted past the budget: no headroom left
  });

  it("unbounded concurrency contributes no queueing term", () => {
    const p = new SloRiskPredictor({ onSloRisk: () => { throw new Error("must not fire"); } });
    const fast = { p95: 50, min: 50, count: 5 };
    p.observe("e", obs({ backlog: 0, concurrency: Infinity, stats: fast }));
    // A thousand deep means nothing when dispatch is unbounded.
    assert.equal(
      p.observe("e", obs({ backlog: 1000, concurrency: Infinity, stats: fast })),
      undefined
    );
  });

  it("the smoothed trend amplifies a growing backlog", () => {
    const mk = (trendHorizon: number) =>
      new SloRiskPredictor({ ewmaAlpha: 1, trendHorizon, minSamples: 1 });
    const stats = { p95: 50, min: 50, count: 1 };
    const flat = mk(0);
    flat.observe("e", obs({ backlog: 10, concurrency: 1, stats }));
    // Level-only: projected 12 * 50ms = 600ms queueing -> score 0.65, quiet.
    assert.equal(flat.observe("e", obs({ backlog: 12, concurrency: 1, stats })), undefined);
    const trending = mk(3);
    trending.observe("e", obs({ backlog: 10, concurrency: 1, stats }));
    // Same observations, trend-aware: (12 + 2*3) * 50 = 900ms -> score 0.95, fires.
    const t = trending.observe("e", obs({ backlog: 12, concurrency: 1, stats }));
    assert.equal(t?.state, "elevated");
  });

  it("endpoints are independent", () => {
    const seen: SloRiskInfo[] = [];
    const p = new SloRiskPredictor({ minSamples: 1, onSloRisk: (i) => seen.push(i) });
    p.observe("hot", obs({ backlog: 100, concurrency: 1, stats: { p95: 50, min: 50, count: 1 } }));
    p.observe("cold", obs({ backlog: 0, concurrency: 1, stats: { p95: 50, min: 50, count: 1 } }));
    assert.deepEqual(seen.map((i) => i.endpoint), ["hot"]);
    assert.equal(p.atRisk().length, 1);
    assert.equal(p.snapshot().length, 2);
  });
});

describe("slo-risk queue integration", () => {
  it("is disabled by default: no stats, no series, no callbacks", async () => {
    let now = 0;
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      latency: { sloMs: 1000, now: () => now },
      setTimer: timer.setTimer,
    });
    q.start();
    for (let i = 0; i < 5; i++) {
      now = i * 100;
      q.enqueue({ ...ITEM, id: `d-${i}` });
      now = i * 100 + 50;
      await timer.run();
    }
    assert.deepEqual(q.getSloRiskStats(), []);
    assert.ok(!q.renderMetrics().includes("relay_slo_risk_seconds"));
  });

  it("predicts a backlog-driven breach, then clears after the drain", async () => {
    let now = 0;
    const timer = manualTimer();
    const risks: SloRiskInfo[] = [];
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      maxConcurrentPerEndpoint: 1,
      latency: {
        sloMs: 1000,
        now: () => now,
        sloRisk: { warnRatio: 0.8, minSamples: 2, onSloRisk: (r) => risks.push(r) },
      },
      setTimer: timer.setTimer,
    });
    q.start();
    // Seed three 50ms delivered samples.
    for (let i = 0; i < 3; i++) {
      now = i * 1000;
      q.enqueue({ ...ITEM, id: `seed-${i}` });
      now = i * 1000 + 50;
      await timer.run();
    }
    assert.deepEqual(risks, []);
    // Burst without running timers: the backlog builds, nothing completes.
    for (let i = 0; i < 25; i++) {
      q.enqueue({ ...ITEM, id: `burst-${i}` });
    }
    assert.equal(risks.length, 1);
    assert.equal(risks[0].state, "elevated");
    assert.equal(risks[0].endpoint, URL);
    assert.ok(risks[0].score >= 0.8);
    assert.equal(risks[0].sloMs, 1000);
    assert.ok(risks[0].backlogEwma > 0);
    // The gauge appears only while elevated.
    const exposition = q.renderMetrics();
    assert.ok(exposition.includes(`relay_slo_risk_seconds{endpoint="${URL}"}`));
    const rows = q.getSloRiskStats();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].atRisk, true);
    assert.ok(rows[0].headroomSeconds >= 0);
    // Drain: every delivery shrinks the backlog; the risk clears exactly once.
    await timer.run();
    assert.equal(risks.length, 2);
    assert.equal(risks[1].state, "cleared");
    assert.equal(risks[1].endpoint, URL);
    assert.ok(!q.renderMetrics().includes("relay_slo_risk_seconds"));
    assert.equal(q.getSloRiskStats()[0].atRisk, false);
  });

  it("fires on latency pressure alone when the downstream slows", async () => {
    let now = 0;
    const timer = manualTimer();
    const risks: SloRiskInfo[] = [];
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      latency: {
        sloMs: 1000,
        now: () => now,
        sloRisk: { warnRatio: 0.8, minSamples: 2, onSloRisk: (r) => risks.push(r) },
      },
      setTimer: timer.setTimer,
    });
    q.start();
    for (let i = 0; i < 3; i++) {
      now = i * 10000;
      q.enqueue({ ...ITEM, id: `slow-${i}` });
      now = i * 10000 + 900; // 900ms samples against a 1000ms budget
      await timer.run();
    }
    const elevated = risks.find((r) => r.state === "elevated");
    assert.ok(elevated);
    assert.equal(elevated!.p95Ms, 900);
    assert.ok(elevated!.score >= 0.8);
  });

  it("keeps tenants isolated", async () => {
    let now = 0;
    const timer = manualTimer();
    const risks: SloRiskInfo[] = [];
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      maxConcurrentPerEndpoint: 1,
      latency: {
        sloMs: 1000,
        now: () => now,
        sloRisk: { warnRatio: 0.8, minSamples: 2, onSloRisk: (r) => risks.push(r) },
      },
      setTimer: timer.setTimer,
    });
    q.start();
    for (let i = 0; i < 3; i++) {
      now = i * 1000;
      q.enqueue({ ...ITEM, id: `t-${i}`, tenantId: "acme" });
      now = i * 1000 + 50;
      await timer.run();
    }
    for (let i = 0; i < 25; i++) {
      q.enqueue({ ...ITEM, id: `tb-${i}`, tenantId: "acme" });
    }
    assert.equal(risks.length, 1);
    assert.equal(risks[0].tenant, "acme");
    const rows = q.getSloRiskStats("acme");
    assert.equal(rows.length, 1);
    assert.equal(rows[0].tenant, "acme");
    assert.equal(rows[0].atRisk, true);
  });

  it("rejects invalid predictor config at construction", () => {
    assert.throws(
      () =>
        new RetryQueue({
          sender: async () => {},
          latency: { sloRisk: { warnRatio: 7 } },
        }),
      RangeError
    );
  });
});

describe("slo-risk metrics exposition", () => {
  it("renders the gauge only when the series is present", () => {
    const withRisk = renderPrometheus({
      deliveries: [],
      circuits: [],
      latencyHistograms: [],
      sloRisk: [{ endpoint: "http://a/hook", headroomSeconds: 1.5 }],
    });
    assert.ok(withRisk.includes("# TYPE relay_slo_risk_seconds gauge"));
    assert.ok(withRisk.includes('relay_slo_risk_seconds{endpoint="http://a/hook"} 1.5'));
    const tenantScoped = renderPrometheus({
      deliveries: [],
      circuits: [],
      latencyHistograms: [],
      sloRisk: [{ endpoint: "http://a/hook", tenant: "acme", headroomSeconds: 0 }],
    });
    assert.ok(
      tenantScoped.includes('relay_slo_risk_seconds{endpoint="http://a/hook",tenant="acme"} 0')
    );
    const without = renderPrometheus({ deliveries: [], circuits: [], latencyHistograms: [] });
    assert.ok(!without.includes("relay_slo_risk_seconds"));
  });
});

describe("slo-risk server wiring", () => {
  let stub: Server;
  let stubPort: number;

  // The signing key name avoids the all-caps SECRET identifier (see AGENTS.md).
  const hookKey = "hook-signing-key";

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  function get(port: number, path: string, headers: Record<string, string> = {}) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest(
        { host: "127.0.0.1", port, path, method: "GET", headers },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () =>
            resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
          );
        }
      );
      r.on("error", reject);
      r.end();
    });
  }

  function post(port: number, body: Buffer, headers: Record<string, string>) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest(
        { host: "127.0.0.1", port, path: "/", method: "POST", headers },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () =>
            resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
          );
        }
      );
      r.on("error", reject);
      r.end(body);
    });
  }

  before(async () => {
    // Slow stub: every delivery takes ~60ms against a 50ms SLO budget.
    stub = createServer((req, res) => {
      req.resume();
      req.on("end", () => setTimeout(() => res.writeHead(200).end("ok"), 60));
    });
    stubPort = await listen(stub);
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  it("audits slo_risk transitions and serves GET /slo-risk", async () => {
    const dir = mkdtempSync(join(tmpdir(), "slorisk-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const seen: SloRiskInfo[] = [];
    const operatorToken = "op-token-71";
    const relay = createRelayServer({
      secret: hookKey,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      operatorToken,
      retry: {
        baseDelayMs: 10,
        jitterMs: 0,
        maxAttempts: 2,
        latency: {
          sloMs: 50,
          sloRisk: { warnRatio: 0.8, minSamples: 1, onSloRisk: (r) => seen.push(r) },
        },
      },
    });
    const port = await listen(relay);
    try {
      for (let i = 0; i < 3; i++) {
        const body = Buffer.from(JSON.stringify({ n: i }));
        const res = await post(port, body, {
          "x-signature": signSha256(body, hookKey),
          "content-type": "application/json",
        });
        assert.equal(res.status, 202);
      }
      // Wait for the early warning to land in the audit log.
      const deadline = Date.now() + 8000;
      let events: Array<Record<string, unknown>> = [];
      while (Date.now() < deadline) {
        events = audit.readAll() as Array<Record<string, unknown>>;
        if (events.some((e) => e.event === "slo_risk")) break;
        await new Promise((r) => setTimeout(r, 50));
      }
      const riskEvents = events.filter((e) => e.event === "slo_risk");
      assert.ok(riskEvents.length >= 1, "expected a slo_risk audit event");
      assert.equal(riskEvents[0].state, "elevated");
      assert.equal(riskEvents[0].endpoint, `http://127.0.0.1:${stubPort}/hook`);
      assert.ok((riskEvents[0].score as number) >= 0.8);
      // The caller's hook still fires (the server only wraps it for auditing).
      assert.ok(seen.some((r) => r.state === "elevated"));

      const ok = await get(port, "/slo-risk", { authorization: `Bearer ${operatorToken}` });
      assert.equal(ok.status, 200);
      const rows = JSON.parse(ok.text) as Array<Record<string, unknown>>;
      assert.ok(rows.some((r) => r.atRisk === true));

      const denied = await get(port, "/slo-risk", { authorization: "Bearer wrong" });
      assert.equal(denied.status, 403);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });
});
