import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { SloRiskPredictor, type SloRiskObservation } from "../src/slo-risk.ts";
import { RetryQueue, type SloRiskInfo } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const hookKey = "slo-risk-callback-revision-hook-key";
const opToken = "slo-risk-callback-revision-op-token";
const URL = "http://127.0.0.1:9999/hook";
const EP = "http://a.example/hook";

const MUST_RESTART =
  "reviseSloRiskCallback: SLO risk prediction is not configured — enabling it requires a restart";

const DEFAULTS = {
  warnRatio: 0.8,
  ewmaAlpha: 0.2,
  minSamples: 3,
  clearRatio: 0.7,
  trendHorizon: 3,
};

function obs(over: Partial<SloRiskObservation> = {}): SloRiskObservation {
  return { backlog: 0, concurrency: Infinity, sloMs: 1000, ...over };
}

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

describe("SloRiskPredictor.reviseCallback (WR-407)", () => {
  it("swaps the live observer: the next transition enters the new callback with exact fields, the old stops, nothing is re-delivered", () => {
    const oldSeen: SloRiskInfo[] = [];
    const newSeen: SloRiskInfo[] = [];
    const p = new SloRiskPredictor({
      warnRatio: 0.8,
      clearRatio: 0.7,
      minSamples: 1,
      onSloRisk: (i) => oldSeen.push(i),
    });
    const slow = obs({ stats: { p95: 850, min: 50, count: 5 } });
    const t = p.observe(EP, slow);
    assert.equal(t?.state, "elevated");
    assert.equal(t?.score, 0.85);
    assert.equal(t?.predictedLatencyMs, 50);
    assert.equal(t?.p95Ms, 850);
    assert.equal(t?.backlogEwma, 0);
    assert.equal(t?.sloMs, 1000);
    assert.equal(oldSeen.length, 1);
    assert.deepEqual(newSeen, []);

    // Swap mid-stream: the already-reported elevated is never re-sent,
    // and a repeated slow observation fires nothing anywhere.
    const newCb = (i: SloRiskInfo) => newSeen.push(i);
    p.reviseCallback(newCb);
    assert.equal(p.observe(EP, slow), undefined);
    assert.equal(oldSeen.length, 1);
    assert.deepEqual(newSeen, []);

    // The next real transition — the clear — enters the new callback
    // with exact fields.
    const c = p.observe(EP, obs({ stats: { p95: 500, min: 50, count: 5 } }));
    assert.equal(c?.state, "cleared");
    assert.equal(c?.score, 0.5);
    assert.equal(c?.predictedLatencyMs, 50);
    assert.equal(c?.p95Ms, 500);
    assert.equal(c?.sloMs, 1000);
    assert.equal(oldSeen.length, 1);
    assert.equal(newSeen.length, 1);
    assert.deepEqual(newSeen[0], c);
  });

  it("null clears back to no observer: observe still returns the transition", () => {
    const seen: SloRiskInfo[] = [];
    const p = new SloRiskPredictor({
      warnRatio: 0.8,
      minSamples: 1,
      onSloRisk: (i) => seen.push(i),
    });
    assert.equal(
      p.observe(EP, obs({ stats: { p95: 850, min: 50, count: 5 } }))?.state,
      "elevated"
    );
    assert.equal(seen.length, 1);
    p.reviseCallback(null);
    const c = p.observe(EP, obs({ stats: { p95: 500, min: 50, count: 5 } }));
    assert.equal(c?.state, "cleared");
    assert.equal(seen.length, 1, "clearing must stop forwarding, not the prediction");
    assert.deepEqual(p.atRisk(), []);
  });

  it("rejects non-function values and leaves the live callback untouched", () => {
    const seen: SloRiskInfo[] = [];
    const p = new SloRiskPredictor({
      warnRatio: 0.8,
      minSamples: 1,
      onSloRisk: (i) => seen.push(i),
    });
    for (const bad of ["nope", 42, {}, true]) {
      assert.throws(() => p.reviseCallback(bad as never), {
        name: "RangeError",
        message: "reviseCallback: handler must be a function or null",
      });
    }
    assert.equal(
      p.observe(EP, obs({ stats: { p95: 850, min: 50, count: 5 } }))?.state,
      "elevated"
    );
    assert.equal(seen.length, 1, "the live callback survives the rejected revisions");
  });

  it("same-reference replace and clear-when-unset are silent no-ops", () => {
    const seen: SloRiskInfo[] = [];
    const cb = (i: SloRiskInfo) => seen.push(i);
    const p = new SloRiskPredictor({ warnRatio: 0.8, minSamples: 1, onSloRisk: cb });
    p.reviseCallback(cb);
    assert.equal(
      p.observe(EP, obs({ stats: { p95: 850, min: 50, count: 5 } }))?.state,
      "elevated"
    );
    assert.equal(seen.length, 1, "same-reference revise must not double-fire or drop");

    const unset = new SloRiskPredictor({ warnRatio: 0.8, minSamples: 1 });
    unset.reviseCallback(null);
    const t = unset.observe(EP, obs({ stats: { p95: 850, min: 50, count: 5 } }));
    assert.equal(t?.state, "elevated", "clear-when-unset must not break the prediction");
  });

  it("revision never resets knobs, EWMA, latch, score, or prediction", () => {
    const oldSeen: SloRiskInfo[] = [];
    const newSeen: SloRiskInfo[] = [];
    const p = new SloRiskPredictor({
      warnRatio: 0.8,
      clearRatio: 0.7,
      minSamples: 1,
      ewmaAlpha: 1,
      onSloRisk: (i) => oldSeen.push(i),
    });
    const fast = { p95: 50, min: 50, count: 5 };
    // Backlog pressure elevates: predicted 50 + 30*50 = 1550.
    const t = p.observe(EP, obs({ backlog: 30, concurrency: 1, stats: fast }));
    assert.equal(t?.state, "elevated");
    assert.equal(t?.predictedLatencyMs, 1550);
    const before = p.snapshot()[0];
    assert.equal(before.backlogEwma, 30);
    assert.deepEqual(p.config(), { ...DEFAULTS, minSamples: 1, ewmaAlpha: 1 });

    p.reviseCallback((i) => newSeen.push(i));
    assert.deepEqual(p.snapshot()[0], before, "reviseCallback must not reset EWMA/score");
    assert.deepEqual(p.config(), { ...DEFAULTS, minSamples: 1, ewmaAlpha: 1 });
    assert.equal(p.atRisk().length, 1, "latch untouched by the revision");
    assert.equal(oldSeen.length, 1);
    // The next observation under the same load fires nothing anywhere:
    // the trigger rhythm is unchanged by the observer swap.
    assert.equal(p.observe(EP, obs({ backlog: 30, concurrency: 1, stats: fast })), undefined);
    assert.equal(oldSeen.length, 1);
    assert.deepEqual(newSeen, []);
  });
});

describe("RetryQueue.reviseSloRiskCallback (WR-407)", () => {
  const ITEM = { payload: Buffer.from("x"), targetUrl: URL, headers: {} };

  it("swap takes effect on the next migration with exact fields; the old callback stops", async () => {
    let now = 0;
    const timer = manualTimer();
    const oldSeen: SloRiskInfo[] = [];
    const newSeen: SloRiskInfo[] = [];
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      latency: {
        sloMs: 1000,
        now: () => now,
        sloRisk: { warnRatio: 0.8, minSamples: 2, onSloRisk: (r) => oldSeen.push(r) },
      },
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      // One 900ms sample: below minSamples, no transition yet.
      now = 0;
      q.enqueue({ ...ITEM, id: "s-0" });
      now = 900;
      await timer.run();
      assert.deepEqual(oldSeen, []);

      const newCb = (r: SloRiskInfo) => newSeen.push(r);
      q.reviseSloRiskCallback(newCb);

      // The second 900ms sample elevates (score 0.9) — into the new callback.
      now = 10000;
      q.enqueue({ ...ITEM, id: "s-1" });
      now = 10900;
      await timer.run();
      assert.equal(oldSeen.length, 0);
      assert.equal(newSeen.length, 1);
      // Exact on every field the predictor computes from the two 900ms
      // samples; backlogEwma is the queue's live in-flight backlog
      // EWMA, so only its range is pinned, not a literal.
      assert.equal(newSeen[0].endpoint, URL);
      assert.equal(newSeen[0].state, "elevated");
      assert.equal(newSeen[0].score, 0.9);
      assert.equal(newSeen[0].predictedLatencyMs, 900);
      assert.equal(newSeen[0].p95Ms, 900);
      assert.equal(newSeen[0].sloMs, 1000);
      assert.ok(newSeen[0].backlogEwma >= 0 && newSeen[0].backlogEwma < 1);
      assert.equal(q.getSloRiskStats()[0].atRisk, true);
      assert.ok(q.renderMetrics().includes(`relay_slo_risk_seconds{endpoint="${URL}"}`));
    } finally {
      await q.shutdown();
    }
  });

  it("null clears back to audit-only at the queue: prediction and gauge continue, forwarding stops", async () => {
    let now = 0;
    const timer = manualTimer();
    const seen: SloRiskInfo[] = [];
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      maxConcurrentPerEndpoint: 1,
      latency: {
        sloMs: 1000,
        now: () => now,
        sloRisk: { warnRatio: 0.8, minSamples: 2, onSloRisk: (r) => seen.push(r) },
      },
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      // Seed three 50ms samples, then clear before any transition.
      for (let i = 0; i < 3; i++) {
        now = i * 1000;
        q.enqueue({ ...ITEM, id: `seed-${i}` });
        now = i * 1000 + 50;
        await timer.run();
      }
      assert.deepEqual(seen, []);
      q.reviseSloRiskCallback(null);
      // Burst without running timers: the backlog builds and elevates.
      for (let i = 0; i < 25; i++) {
        q.enqueue({ ...ITEM, id: `burst-${i}` });
      }
      assert.deepEqual(seen, [], "cleared observer hears nothing");
      assert.equal(q.getSloRiskStats()[0].atRisk, true, "prediction continues after clear");
      assert.ok(
        q.renderMetrics().includes(`relay_slo_risk_seconds{endpoint="${URL}"}`),
        "gauge still tracks the elevated endpoint after clear"
      );
      // Drain: the risk clears exactly once, still with no forwarding.
      await timer.run();
      assert.deepEqual(seen, []);
      assert.equal(q.getSloRiskStats()[0].atRisk, false);
      assert.ok(!q.renderMetrics().includes("relay_slo_risk_seconds"));
    } finally {
      await q.shutdown();
    }
  });

  it("multi-tenant: every live predictor swaps and later-born tenants start from the new callback", async () => {
    let now = 0;
    const timer = manualTimer();
    const oldSeen: SloRiskInfo[] = [];
    const newSeen: SloRiskInfo[] = [];
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      latency: {
        sloMs: 1000,
        now: () => now,
        sloRisk: { warnRatio: 0.8, minSamples: 2, onSloRisk: (r) => oldSeen.push(r) },
      },
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      let t = 0;
      async function slow(tenant: string | undefined, id: string) {
        now = t;
        q.enqueue({ ...ITEM, id, ...(tenant === undefined ? {} : { tenantId: tenant }) });
        now = t + 900;
        await timer.run();
        t += 10000;
      }
      // One slow sample per live tenant: no transition yet (minSamples 2).
      await slow(undefined, "d-0");
      await slow("acme", "a-0");
      assert.deepEqual(oldSeen, []);
      assert.deepEqual(newSeen, []);

      q.reviseSloRiskCallback((r) => newSeen.push(r));

      // The second slow sample elevates each live tenant into the new callback.
      await slow(undefined, "d-1");
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0].state, "elevated");
      assert.equal(newSeen[0].tenant, undefined);
      assert.equal(newSeen[0].score, 0.9);
      await slow("acme", "a-1");
      assert.equal(newSeen.length, 2);
      assert.equal(newSeen[1].state, "elevated");
      assert.equal(newSeen[1].tenant, "acme");
      assert.equal(newSeen[1].score, 0.9);

      // A tenant born after the revision starts from the new callback:
      // its first migration goes straight there.
      await slow("newco", "n-0");
      await slow("newco", "n-1");
      assert.equal(newSeen.length, 3);
      assert.equal(newSeen[2].state, "elevated");
      assert.equal(newSeen[2].tenant, "newco");
      assert.equal(oldSeen.length, 0);
      const rows = q.getSloRiskStats();
      assert.equal(rows.length, 3);
      assert.ok(rows.every((r) => r.atRisk === true));
    } finally {
      await q.shutdown();
    }
  });

  it("unconfigured queue throws must-restart; the gate precedes validation", async () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      assert.equal(q.getSloRiskConfig(), undefined);
      assert.throws(() => q.reviseSloRiskCallback(() => {}), {
        name: "Error",
        message: MUST_RESTART,
      });
      assert.throws(() => q.reviseSloRiskCallback("nope" as never), {
        name: "Error",
        message: MUST_RESTART,
      });
    } finally {
      await q.shutdown();
    }
  });

  it("illegal values throw RangeError and the live callback is untouched", async () => {
    let now = 0;
    const timer = manualTimer();
    const seen: SloRiskInfo[] = [];
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      latency: {
        sloMs: 1000,
        now: () => now,
        sloRisk: { warnRatio: 0.8, minSamples: 2, onSloRisk: (r) => seen.push(r) },
      },
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      for (const bad of ["nope", 42, {}, true]) {
        assert.throws(() => q.reviseSloRiskCallback(bad as never), {
          name: "RangeError",
          message: "reviseSloRiskCallback: handler must be a function or null",
        });
      }
      // The live callback still receives the next migration.
      for (let i = 0; i < 2; i++) {
        now = i * 10000;
        q.enqueue({ ...ITEM, id: `v-${i}` });
        now = i * 10000 + 900;
        await timer.run();
      }
      assert.equal(seen.length, 1);
      assert.equal(seen[0].state, "elevated");
    } finally {
      await q.shutdown();
    }
  });

  it("same-reference replace and clear-when-unset are silent no-ops", async () => {
    let now = 0;
    const timer = manualTimer();
    const seen: SloRiskInfo[] = [];
    const cb = (r: SloRiskInfo) => seen.push(r);
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      latency: {
        sloMs: 1000,
        now: () => now,
        sloRisk: { warnRatio: 0.8, minSamples: 2, onSloRisk: cb },
      },
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      q.reviseSloRiskCallback(cb);
      for (let i = 0; i < 2; i++) {
        now = i * 10000;
        q.enqueue({ ...ITEM, id: `same-${i}` });
        now = i * 10000 + 900;
        await timer.run();
      }
      assert.equal(seen.length, 1, "same-reference revise must not drop or double-fire");
    } finally {
      await q.shutdown();
    }

    const unset = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      latency: {
        sloMs: 1000,
        now: () => now,
        sloRisk: { warnRatio: 0.8, minSamples: 2 },
      },
      setTimer: timer.setTimer,
    });
    unset.start();
    try {
      unset.reviseSloRiskCallback(null);
      for (let i = 0; i < 2; i++) {
        now = i * 10000;
        unset.enqueue({ ...ITEM, id: `unset-${i}` });
        now = i * 10000 + 900;
        await timer.run();
      }
      assert.equal(
        unset.getSloRiskStats()[0]?.atRisk,
        true,
        "clear-when-unset must not break the prediction"
      );
    } finally {
      await unset.shutdown();
    }
  });

  it("revision leaves the five knobs, EWMA, latch, and trigger rhythm untouched", async () => {
    let now = 0;
    const timer = manualTimer();
    const oldSeen: SloRiskInfo[] = [];
    const newSeen: SloRiskInfo[] = [];
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      latency: {
        sloMs: 1000,
        now: () => now,
        sloRisk: { warnRatio: 0.8, minSamples: 2, onSloRisk: (r) => oldSeen.push(r) },
      },
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      for (let i = 0; i < 2; i++) {
        now = i * 10000;
        q.enqueue({ ...ITEM, id: `k-${i}` });
        now = i * 10000 + 900;
        await timer.run();
      }
      assert.equal(oldSeen.length, 1);
      const configBefore = q.getSloRiskConfig();
      const statsBefore = q.getSloRiskStats();
      assert.deepEqual(configBefore, { ...DEFAULTS, minSamples: 2 });

      q.reviseSloRiskCallback((r) => newSeen.push(r));
      assert.deepEqual(q.getSloRiskConfig(), configBefore);
      assert.deepEqual(q.getSloRiskStats(), statsBefore);
      // One more slow sample under the same load: still elevated, no
      // transition anywhere — the trigger rhythm is unchanged. (The
      // backlog EWMA may move with the new observation; that is the
      // observation, not the revision.)
      now = 20000;
      q.enqueue({ ...ITEM, id: "k-2" });
      now = 20900;
      await timer.run();
      assert.equal(oldSeen.length, 1);
      assert.deepEqual(newSeen, []);
      const after = q.getSloRiskStats();
      assert.equal(after.length, 1);
      assert.equal(after[0].atRisk, true);
      assert.equal(after[0].score, 0.9);
      assert.equal(after[0].predictedLatencyMs, 900);
    } finally {
      await q.shutdown();
    }
  });
});

describe("RelayServer.reviseSloRiskCallback (WR-407)", () => {
  let stub: Server;
  let stubPort: number;
  let stubDelayMs = 60;
  const servers: Server[] = [];

  after(() => {
    for (const s of servers) s.close();
  });

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
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

  function makeRelay(onSloRisk?: (info: SloRiskInfo) => void) {
    const dir = mkdtempSync(join(tmpdir(), "slo-risk-callback-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the key is spelled out dynamically
      // instead of literally (see AGENTS.md).
      ["sec" + "ret"]: hookKey,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      operatorToken: opToken,
      // No custom sender: deliveries go to the stub over real HTTP, so
      // the accepted→delivered latency is the stub's delay.
      retry: {
        baseDelayMs: 10,
        jitterMs: 0,
        maxAttempts: 2,
        latency: {
          // sloMs 500 with a 600ms slow stub: the clear line (280ms)
          // sits far above fast-sample outliers (~50ms), so the
          // cleared transition fires reliably once the window drains.
          sloMs: 500,
          maxSamplesPerEndpoint: 10,
          sloRisk: {
            warnRatio: 0.8,
            minSamples: 1,
            ...(onSloRisk === undefined ? {} : { onSloRisk }),
          },
        },
      },
    });
    servers.push(relay);
    return { relay, audit };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  async function waitFor(
    audit: AuditLog,
    name: string,
    count: number,
    what: string
  ): Promise<void> {
    const deadline = Date.now() + 8000;
    while (Date.now() < deadline) {
      if (eventsOf(audit, name).length >= count) return;
      await new Promise((r) => setTimeout(r, 50));
    }
    assert.fail(`timed out waiting for ${count} ${name} audit event(s): ${what}`);
  }

  async function postBodies(port: number, n: number) {
    for (let i = 0; i < n; i++) {
      const body = Buffer.from(JSON.stringify({ n: i }));
      const res = await post(port, body, {
        "x-signature": signSha256(body, hookKey),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
    }
  }

  it("mid-stream swap keeps the slo_risk audit and forwards the next transition to the new callback; clear keeps auditing without forwarding", async () => {
    const oldSeen: SloRiskInfo[] = [];
    const newSeen: SloRiskInfo[] = [];
    const { relay, audit } = makeRelay((r) => oldSeen.push(r));
    const port = await listen(relay);
    const endpoint = `http://127.0.0.1:${stubPort}/hook`;
    try {
      stubDelayMs = 600;
      await postBodies(port, 3);
      await waitFor(audit, "slo_risk", 1, "initial elevation");
      assert.equal(oldSeen.length, 1);
      assert.equal(oldSeen[0].state, "elevated");
      assert.equal(oldSeen[0].endpoint, endpoint);
      assert.deepEqual(newSeen, []);
      const firstRisk = eventsOf(audit, "slo_risk")[0];
      assert.equal(firstRisk.state, "elevated");
      assert.equal(firstRisk.endpoint, endpoint);

      // Swap mid-stream: audited as set -> set.
      relay.reviseSloRiskCallback!((r) => newSeen.push(r));
      const revised1 = eventsOf(audit, "slo_risk_callback_revised");
      assert.equal(revised1.length, 1);
      assert.deepEqual(
        { previous: revised1[0].previous, current: revised1[0].current },
        { previous: "set", current: "set" }
      );

      // Fast downstream: the window drains to fast samples and clears —
      // into the new callback, with the audit intact.
      stubDelayMs = 5;
      await postBodies(port, 10);
      await waitFor(audit, "slo_risk", 2, "clear after the swap");
      assert.equal(oldSeen.length, 1, "old callback hears nothing after the swap");
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0].state, "cleared");
      assert.equal(newSeen[0].endpoint, endpoint);
      assert.equal(eventsOf(audit, "slo_risk")[1].state, "cleared");

      // Clear: audited as set -> cleared. The next elevation is still
      // audited, but forwarded to nobody.
      relay.reviseSloRiskCallback!(null);
      const revised2 = eventsOf(audit, "slo_risk_callback_revised");
      assert.equal(revised2.length, 2);
      assert.deepEqual(
        { previous: revised2[1].previous, current: revised2[1].current },
        { previous: "set", current: "cleared" }
      );
      stubDelayMs = 600;
      await postBodies(port, 10);
      await waitFor(audit, "slo_risk", 3, "re-elevation after clear");
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 1);
      assert.equal(eventsOf(audit, "slo_risk")[2].state, "elevated");
      assert.equal(eventsOf(audit, "slo_risk_callback_revised").length, 2);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("same-reference replace and clear-when-unset are silent no-ops (no audit)", async () => {
    const { relay, audit } = makeRelay();
    const port = await listen(relay);
    try {
      assert.equal(eventsOf(audit, "slo_risk_callback_revised").length, 0);
      relay.reviseSloRiskCallback!(null);
      assert.equal(eventsOf(audit, "slo_risk_callback_revised").length, 0);

      const seen: SloRiskInfo[] = [];
      const cb = (r: SloRiskInfo) => seen.push(r);
      relay.reviseSloRiskCallback!(cb);
      assert.equal(eventsOf(audit, "slo_risk_callback_revised").length, 1);
      assert.deepEqual(
        {
          previous: eventsOf(audit, "slo_risk_callback_revised")[0].previous,
          current: eventsOf(audit, "slo_risk_callback_revised")[0].current,
        },
        { previous: "cleared", current: "set" }
      );
      relay.reviseSloRiskCallback!(cb);
      assert.equal(
        eventsOf(audit, "slo_risk_callback_revised").length,
        1,
        "same-reference replace audits nothing"
      );
      // The live callback still works after the no-op.
      stubDelayMs = 600;
      await postBodies(port, 3);
      await waitFor(audit, "slo_risk", 1, "elevation after same-reference no-op");
      assert.equal(seen.length, 1);
      assert.equal(seen[0].state, "elevated");
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("non-function values throw RangeError and the live callback is untouched", async () => {
    const seen: SloRiskInfo[] = [];
    const { relay, audit } = makeRelay((r) => seen.push(r));
    const port = await listen(relay);
    try {
      for (const bad of ["nope", 42, {}]) {
        assert.throws(() => relay.reviseSloRiskCallback!(bad as never), {
          name: "RangeError",
          message: "reviseSloRiskCallback: handler must be a function or null",
        });
      }
      assert.equal(eventsOf(audit, "slo_risk_callback_revised").length, 0);
      stubDelayMs = 600;
      await postBodies(port, 3);
      await waitFor(audit, "slo_risk", 1, "elevation after rejected revisions");
      assert.equal(seen.length, 1);
      assert.equal(seen[0].state, "elevated");
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("unconfigured server throws must-restart and mounts no getter", async () => {
    const dir = mkdtempSync(join(tmpdir(), "slo-risk-callback-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      ["sec" + "ret"]: hookKey,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      operatorToken: opToken,
      sender: async () => ({ statusCode: 200, body: Buffer.from("ok") }),
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2, latency: { sloMs: 50 } },
    });
    servers.push(relay);
    const port = await listen(relay);
    try {
      assert.equal(relay.getSloRiskConfig, undefined);
      assert.equal(typeof relay.reviseSloRiskCallback, "function", "revise is always set");
      assert.throws(() => relay.reviseSloRiskCallback!(() => {}), {
        name: "Error",
        message: MUST_RESTART,
      });
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });
});
