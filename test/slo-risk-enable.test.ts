import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type SloRiskInfo } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "slo-risk-enable-test-key";
const opToken = "slo-risk-enable-op-token";
const URL = "http://127.0.0.1:9999/hook";
const ITEM = { payload: Buffer.from("x"), targetUrl: URL, headers: {} };

const DEFAULTS = {
  warnRatio: 0.8,
  ewmaAlpha: 0.2,
  minSamples: 3,
  clearRatio: 0.7,
  trendHorizon: 3,
};

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

describe("RetryQueue.reviseSloRisk live enable (WR-473)", () => {
  /** Queue with latency tracking but no SLO-risk predictor. */
  function makeQueue() {
    const clock = { now: 0 };
    const timer = manualTimer();
    const risks: SloRiskInfo[] = [];
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      latency: { sloMs: 1000, now: () => clock.now },
      setTimer: timer.setTimer,
    });
    q.start();
    let base = 0;
    async function seed(n: number, latencyMs: number, prefix: string) {
      for (let i = 0; i < n; i++) {
        clock.now = base + i * 10000;
        q.enqueue({ ...ITEM, id: `${prefix}-${i}` });
        clock.now = base + i * 10000 + latencyMs;
        await timer.run();
      }
      base += n * 10000;
    }
    return { q, clock, timer, risks, seed };
  }

  it("enables on first revision; missing knobs take the construction defaults", async () => {
    const { q } = makeQueue();
    try {
      assert.equal(q.getSloRiskConfig(), undefined);
      assert.deepEqual(q.reviseSloRisk({ warnRatio: 0.6 }), { ...DEFAULTS, warnRatio: 0.6 });
      assert.deepEqual(q.getSloRiskConfig(), { ...DEFAULTS, warnRatio: 0.6 });
      assert.deepEqual(q.getSloRiskStats(), []);
    } finally {
      await q.shutdown();
    }
  });

  it("the next observe after the enable evaluates; a tightened warnRatio elevates", async () => {
    const { q, risks, seed } = makeQueue();
    try {
      q.reviseSloRisk({ warnRatio: 0.6, minSamples: 2 });
      q.reviseSloRiskCallback((info) => risks.push(info));
      // 700ms samples against a 1000ms budget: score 0.7, above the
      // 0.6 threshold once the cold-start gate passes.
      await seed(2, 700, "d");
      assert.equal(risks.length, 1);
      assert.equal(risks[0].state, "elevated");
      assert.equal(risks[0].score, 0.7);
    } finally {
      await q.shutdown();
    }
  });

  it("the cold-start gate counts from the enable: no fire below minSamples", async () => {
    const { q, risks, seed } = makeQueue();
    try {
      q.reviseSloRisk({ warnRatio: 0.6, minSamples: 3 });
      q.reviseSloRiskCallback((info) => risks.push(info));
      await seed(2, 700, "d");
      assert.deepEqual(risks, [], "2 samples are below the 3-sample cold-start gate");
      assert.deepEqual(q.getSloRiskStats(), []);
      await seed(1, 700, "e");
      assert.equal(risks.length, 1);
      assert.equal(risks[0].state, "elevated");
    } finally {
      await q.shutdown();
    }
  });

  it("illegal knobs throw RangeError and the queue stays unconfigured, still enableable", async () => {
    const { q } = makeQueue();
    try {
      const illegal = [
        { warnRatio: 0 },
        { warnRatio: 1.5 },
        { ewmaAlpha: 0 },
        { ewmaAlpha: 2 },
        { clearRatio: 1 },
        { minSamples: 0 },
        { minSamples: 1.5 },
        { trendHorizon: -1 },
      ];
      for (const patch of illegal) {
        assert.throws(() => q.reviseSloRisk(patch), RangeError);
        assert.equal(q.getSloRiskConfig(), undefined, "an illegal patch must not enable");
      }
      assert.deepEqual(q.reviseSloRisk({ warnRatio: 0.6 }), { ...DEFAULTS, warnRatio: 0.6 });
    } finally {
      await q.shutdown();
    }
  });

  it("an empty patch and non-object patches throw RangeError and the queue stays unconfigured", async () => {
    const { q } = makeQueue();
    try {
      assert.throws(() => q.reviseSloRisk({}), RangeError);
      assert.throws(() => q.reviseSloRisk(null as never), RangeError);
      assert.throws(() => q.reviseSloRisk("nope" as never), RangeError);
      assert.throws(() => q.reviseSloRisk([] as never), RangeError);
      assert.equal(q.getSloRiskConfig(), undefined);
      assert.deepEqual(q.reviseSloRisk({ warnRatio: 0.6 }), { ...DEFAULTS, warnRatio: 0.6 });
    } finally {
      await q.shutdown();
    }
  });

  it("observations from before the enable are never evaluated retroactively", async () => {
    const { q, risks, seed } = makeQueue();
    try {
      // 700ms samples would elevate under a 0.6 threshold — but no
      // predictor exists yet, so nothing is evaluated.
      await seed(3, 700, "d");
      assert.equal(q.getSloRiskConfig(), undefined);
      assert.deepEqual(q.getSloRiskStats(), []);
      // The enable itself evaluates nothing: the predictor starts empty.
      q.reviseSloRisk({ warnRatio: 0.6, minSamples: 2 });
      q.reviseSloRiskCallback((info) => risks.push(info));
      assert.deepEqual(risks, []);
      assert.deepEqual(q.getSloRiskStats(), []);
      // The next observe after the enable evaluates — and elevates,
      // because the live rolling latency window already holds the
      // pre-enable samples (the predictor's own state, not the WR-13
      // tracker, is what starts empty).
      await seed(1, 700, "e");
      assert.equal(risks.length, 1);
      assert.equal(risks[0].state, "elevated");
    } finally {
      await q.shutdown();
    }
  });

  it("enabling without latency tracking throws Error and the queue stays unconfigured", async () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      assert.equal(q.getSloRiskConfig(), undefined);
      assert.throws(() => q.reviseSloRisk({ warnRatio: 0.6 }), {
        name: "Error",
        message: "reviseSloRisk: latency tracking is not configured — enable latency tracking first",
      });
      assert.equal(q.getSloRiskConfig(), undefined);
    } finally {
      await q.shutdown();
    }
  });

  it("enabling unlocks reviseSloRiskCallback; the gate precedes validation while closed", async () => {
    const { q, risks, seed } = makeQueue();
    try {
      // No predictor yet: the gate is still fail-closed, and it
      // precedes validation — even an illegal value throws Error.
      assert.throws(() => q.reviseSloRiskCallback(() => {}), {
        name: "Error",
        message:
          "reviseSloRiskCallback: SLO risk prediction is not configured — enabling it requires a restart",
      });
      assert.throws(() => q.reviseSloRiskCallback("nope" as never), {
        name: "Error",
        message:
          "reviseSloRiskCallback: SLO risk prediction is not configured — enabling it requires a restart",
      });
      // WR-473: enabling sloRisk unlocks the gate — the callback
      // replacement then works on the fresh predictor.
      q.reviseSloRisk({ warnRatio: 0.6, minSamples: 2 });
      q.reviseSloRiskCallback((info) => risks.push(info));
      assert.throws(() => q.reviseSloRiskCallback("nope" as never), RangeError);
      await seed(2, 700, "d");
      assert.equal(risks.length, 1);
      assert.equal(risks[0].state, "elevated");
    } finally {
      await q.shutdown();
    }
  });
});

describe("RelayServer.reviseSloRisk live enable (WR-473)", () => {
  let stub: Server;
  let stubPort: number;
  let stubDelayMs = 60;

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

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  async function waitFor(
    audit: AuditLog,
    event: string,
    pred: (e: Record<string, unknown>) => boolean,
    what: string,
    minCount = 1
  ): Promise<Array<Record<string, unknown>>> {
    const deadline = Date.now() + 8000;
    while (Date.now() < deadline) {
      const events = eventsOf(audit, event);
      if (events.filter(pred).length >= minCount) return events;
      await new Promise((r) => setTimeout(r, 50));
    }
    throw new Error(`timed out waiting for ${what}`);
  }

  /** Relay with latency tracking but no SLO-risk predictor. */
  function makeRelay() {
    const dir = mkdtempSync(join(tmpdir(), "slo-risk-enable-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the key is spelled out dynamically
      // instead of literally (see AGENTS.md).
      ["sec" + "ret"]: signingKey,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      operatorToken: opToken,
      // No custom sender: deliveries go to the stub over real HTTP, so
      // the accepted→delivered latency is the stub's delay.
      retry: {
        baseDelayMs: 5,
        jitterMs: 0,
        maxAttempts: 2,
        latency: { sloMs: 50, maxSamplesPerEndpoint: 5 },
      },
    });
    return { relay, audit };
  }

  before(async () => {
    stub = createServer((req, res) => {
      req.resume();
      req.on("end", () => setTimeout(() => res.writeHead(200).end("ok"), stubDelayMs));
    });
    stubPort = await listen(stub);
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  it("server enable audits slo_risk_revised with previous null and mounts the getter", async () => {
    const { relay, audit } = makeRelay();
    const port = await listen(relay);
    try {
      assert.equal(relay.getSloRiskConfig, undefined);
      assert.equal(typeof relay.reviseSloRisk, "function", "revise is always set");
      assert.deepEqual(relay.reviseSloRisk!({ warnRatio: 0.6 }), { ...DEFAULTS, warnRatio: 0.6 });
      assert.deepEqual(relay.getSloRiskConfig!(), { ...DEFAULTS, warnRatio: 0.6 });
      const revised = eventsOf(audit, "slo_risk_revised");
      assert.equal(revised.length, 1);
      assert.equal(revised[0].previous, null);
      assert.deepEqual(revised[0].current, { ...DEFAULTS, warnRatio: 0.6 });
      // The audit event carries plain data only — never a function.
      assert.deepEqual(JSON.parse(JSON.stringify(revised[0])), revised[0]);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("GET /slo-risk is empty before evaluation and returns rows after the first evaluation", async () => {
    const { relay, audit } = makeRelay();
    const port = await listen(relay);
    try {
      relay.reviseSloRisk!({ warnRatio: 0.8, minSamples: 1 });
      const empty = await get(port, "/slo-risk", { authorization: `Bearer ${opToken}` });
      assert.equal(empty.status, 200);
      assert.deepEqual(JSON.parse(empty.text), []);
      // Slow stub: every delivery takes ~60ms against a 50ms SLO budget.
      for (let i = 0; i < 3; i++) {
        const body = Buffer.from(JSON.stringify({ n: i }));
        const res = await post(port, body, {
          "x-signature": signSha256(body, signingKey),
          "content-type": "application/json",
        });
        assert.equal(res.status, 202);
      }
      await waitFor(audit, "slo_risk", (e) => e.state === "elevated", "elevated audit");
      const ok = await get(port, "/slo-risk", { authorization: `Bearer ${opToken}` });
      assert.equal(ok.status, 200);
      const rows = JSON.parse(ok.text) as Array<Record<string, unknown>>;
      assert.ok(rows.some((r) => r.atRisk === true));
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("the slo_risk audit wrapper is installed by the enable and forwards to a later operator callback", async () => {
    const { relay, audit } = makeRelay();
    const port = await listen(relay);
    const seen: SloRiskInfo[] = [];
    try {
      relay.reviseSloRisk!({ warnRatio: 0.8, minSamples: 1 });
      // No operator callback installed yet: the first elevation is
      // audited as `slo_risk` but reaches no operator.
      stubDelayMs = 60;
      for (let i = 0; i < 3; i++) {
        const body = Buffer.from(JSON.stringify({ n: i }));
        const res = await post(port, body, {
          "x-signature": signSha256(body, signingKey),
          "content-type": "application/json",
        });
        assert.equal(res.status, 202);
      }
      await waitFor(audit, "slo_risk", (e) => e.state === "elevated", "first elevated audit");
      assert.deepEqual(seen, []);
      // Install the operator callback after the first elevation; the
      // wrapper keeps reading the cell, so later transitions arrive.
      relay.reviseSloRiskCallback!((info) => seen.push(info));
      assert.equal(eventsOf(audit, "slo_risk_callback_revised").length, 1);
      // Fast stub: the 5-sample window flushes to fast latencies, so
      // the endpoint clears; then slow again re-elevates it.
      stubDelayMs = 5;
      for (let i = 0; i < 5; i++) {
        const body = Buffer.from(JSON.stringify({ f: i }));
        const res = await post(port, body, {
          "x-signature": signSha256(body, signingKey),
          "content-type": "application/json",
        });
        assert.equal(res.status, 202);
      }
      await waitFor(audit, "slo_risk", (e) => e.state === "cleared", "cleared audit");
      stubDelayMs = 60;
      for (let i = 0; i < 3; i++) {
        const body = Buffer.from(JSON.stringify({ s: i }));
        const res = await post(port, body, {
          "x-signature": signSha256(body, signingKey),
          "content-type": "application/json",
        });
        assert.equal(res.status, 202);
      }
      await waitFor(
        audit,
        "slo_risk",
        (e) => e.state === "elevated",
        "second elevated audit",
        2
      );
      assert.equal(seen.length, 2, "cleared then re-elevated reach the operator callback");
      assert.equal(seen[0].state, "cleared");
      assert.equal(seen[1].state, "elevated");
    } finally {
      stubDelayMs = 60;
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("a second enable is a revision: partial merge audits chained previous, same-value is a silent no-op", async () => {
    const { relay, audit } = makeRelay();
    const port = await listen(relay);
    try {
      relay.reviseSloRisk!({ warnRatio: 0.6 });
      assert.deepEqual(relay.reviseSloRisk!({ trendHorizon: 5, minSamples: 10 }), {
        ...DEFAULTS,
        warnRatio: 0.6,
        trendHorizon: 5,
        minSamples: 10,
      });
      const revised = eventsOf(audit, "slo_risk_revised");
      assert.equal(revised.length, 2);
      assert.equal(revised[0].previous, null);
      assert.deepEqual(revised[1].previous, { ...DEFAULTS, warnRatio: 0.6 });
      assert.deepEqual(revised[1].current, {
        ...DEFAULTS,
        warnRatio: 0.6,
        trendHorizon: 5,
        minSamples: 10,
      });
      relay.reviseSloRisk!({ trendHorizon: 5, minSamples: 10 });
      assert.equal(eventsOf(audit, "slo_risk_revised").length, 2);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("a restart restores the unconfigured construction state", async () => {
    const { relay } = makeRelay();
    const port = await listen(relay);
    try {
      relay.reviseSloRisk!({ warnRatio: 0.6 });
      assert.deepEqual(relay.getSloRiskConfig!(), { ...DEFAULTS, warnRatio: 0.6 });
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
    // A fresh relay from the same construction options has no predictor.
    const fresh = makeRelay();
    const freshPort = await listen(fresh.relay);
    try {
      assert.equal(fresh.relay.getSloRiskConfig, undefined);
      const empty = await get(freshPort, "/slo-risk", { authorization: `Bearer ${opToken}` });
      assert.equal(empty.status, 200);
      assert.deepEqual(JSON.parse(empty.text), []);
    } finally {
      fresh.relay.close();
      await new Promise((r) => fresh.relay.once("close", r));
    }
  });

  it("server enable without latency tracking throws Error and the relay stays unconfigured", async () => {
    const dir = mkdtempSync(join(tmpdir(), "slo-risk-enable-nolat-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      ["sec" + "ret"]: signingKey,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      operatorToken: opToken,
      sender: async () => ({ statusCode: 200, body: Buffer.from("ok") }),
      retry: { baseDelayMs: 5, jitterMs: 0, maxAttempts: 2 },
    });
    const port = await listen(relay);
    try {
      assert.equal(relay.getSloRiskConfig, undefined);
      assert.throws(() => relay.reviseSloRisk!({ warnRatio: 0.6 }), {
        name: "Error",
        message: "reviseSloRisk: latency tracking is not configured — enable latency tracking first",
      });
      assert.equal(relay.getSloRiskConfig, undefined);
      assert.deepEqual(eventsOf(audit, "slo_risk_revised"), []);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });
});
