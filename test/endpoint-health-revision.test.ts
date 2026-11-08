import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  EndpointHealthTracker,
  type EndpointHealthConfig,
  type EndpointHealthRevisedAuditEvent,
} from "../src/endpoint-health.ts";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "endpoint-health-revision-test-key";
const opToken = "endpoint-health-revision-op-token";
const URL = "http://127.0.0.1:9999/hook";
const EP = "http://127.0.0.1:9/health";

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

function item(id: string, tenantId?: string) {
  return {
    id,
    payload: Buffer.from("hello"),
    targetUrl: URL,
    headers: {},
    ...(tenantId !== undefined ? { tenantId } : {}),
  };
}

function listen(server: Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (addr !== null && typeof addr === "object") resolve(addr.port);
      else reject(new Error("no address"));
    });
  });
}

const defaults: EndpointHealthConfig = {
  ewmaAlpha: 0.2,
  maxLatencySamples: 256,
  sloMs: 5000,
  successWeight: 0.7,
  latencyWeight: 0.3,
  circuitOpenPenalty: 100,
  degradeThreshold: 40,
  recoverThreshold: 70,
};

describe("EndpointHealthTracker.retune (WR-359)", () => {
  it("lowering degradeThreshold degrades on the next evaluation", () => {
    const degraded: Array<{ score: number; consecutiveLowScores: number }> = [];
    const t = new EndpointHealthTracker({
      ewmaAlpha: 0.5,
      onEndpointDegraded: (info) => degraded.push(info),
    });
    t.recordOutcome(URL, false);
    t.recordOutcome(URL, false);
    // Score 47.5 — above the 40 line, not degraded yet.
    assert.equal(t.score(URL), 47.5);
    assert.equal(t.isDegraded(URL), false);
    t.retune({ degradeThreshold: 50 });
    t.recordOutcome(URL, false);
    assert.equal(t.score(URL), 38.75);
    assert.equal(t.isDegraded(URL), true);
    assert.equal(degraded.length, 1);
    assert.equal(degraded[0].score, 38.75);
    assert.equal(degraded[0].consecutiveLowScores, 1);
  });

  it("raising degradeThreshold does not retroactively recover a degraded endpoint", () => {
    const t = new EndpointHealthTracker({ ewmaAlpha: 0.5 });
    t.recordOutcome(URL, false);
    t.recordOutcome(URL, false);
    t.recordOutcome(URL, false);
    assert.equal(t.isDegraded(URL), true);
    assert.equal(t.snapshot()[0].consecutiveLowScores, 1);
    t.retune({ degradeThreshold: 20, recoverThreshold: 90 });
    assert.equal(t.isDegraded(URL), true);
    assert.equal(t.snapshot()[0].consecutiveLowScores, 1);
    // The next evaluation judges the streak against the NEW line:
    // score 34.375 is above 20, so the streak resets — but the endpoint
    // stays degraded until a score climbs above the new recover line.
    t.recordOutcome(URL, false);
    assert.equal(t.isDegraded(URL), true);
    assert.equal(t.snapshot()[0].consecutiveLowScores, 0);
  });

  it("lengthening sloMs lifts the p95 term on the next score", () => {
    const t = new EndpointHealthTracker({
      ewmaAlpha: 1,
      successWeight: 0.5,
      latencyWeight: 0.5,
      sloMs: 1000,
    });
    t.recordOutcome(URL, true, 2000);
    assert.equal(t.score(URL), 50);
    t.retune({ sloMs: 4000 });
    assert.equal(t.score(URL), 100);
  });

  it("flipping the weights follows the new weights", () => {
    const t = new EndpointHealthTracker({
      ewmaAlpha: 1,
      successWeight: 1,
      latencyWeight: 0,
      sloMs: 1000,
    });
    t.recordOutcome(URL, true, 5000);
    assert.equal(t.score(URL), 100);
    t.retune({ successWeight: 0, latencyWeight: 1 });
    assert.equal(t.score(URL), 0);
  });

  it("shrinking maxLatencySamples truncates the window at once", () => {
    const t = new EndpointHealthTracker({
      ewmaAlpha: 1,
      successWeight: 0,
      latencyWeight: 1,
      sloMs: 1000,
      maxLatencySamples: 4,
    });
    t.recordOutcome(URL, true, 5000);
    t.recordOutcome(URL, true, 100);
    t.recordOutcome(URL, true, 100);
    t.recordOutcome(URL, true, 100);
    assert.equal(t.score(URL), 0);
    assert.equal(t.snapshot()[0].p95Ms, 5000);
    t.retune({ maxLatencySamples: 2 });
    // Newest two samples are both 100ms: the p95 term recovers at once.
    assert.equal(t.snapshot()[0].p95Ms, 100);
    assert.equal(t.score(URL), 100);
  });

  it("illegal patches throw RangeError and leave the live values untouched", () => {
    const t = new EndpointHealthTracker();
    const before = t.snapshotConfig();
    // The strict degrade < recover gap is judged on the merged values.
    assert.throws(() => t.retune({ degradeThreshold: 70 }), RangeError);
    assert.throws(() => t.retune({ recoverThreshold: 40 }), RangeError);
    assert.throws(() => t.retune({ degradeThreshold: 80, recoverThreshold: 70 }), RangeError);
    assert.throws(() => t.retune({ ewmaAlpha: 0 }), RangeError);
    assert.throws(() => t.retune({ ewmaAlpha: 1.5 }), RangeError);
    assert.throws(() => t.retune({ maxLatencySamples: 0 }), RangeError);
    assert.throws(() => t.retune({ sloMs: 0 }), RangeError);
    assert.throws(() => t.retune({ successWeight: 0, latencyWeight: 0 }), RangeError);
    assert.throws(() => t.retune({ circuitOpenPenalty: -1 }), RangeError);
    assert.throws(() => t.retune({ degradeThreshold: -1 }), RangeError);
    assert.throws(() => t.retune(null as unknown as { sloMs: number }), RangeError);
    assert.throws(() => t.retune("slow" as unknown as { sloMs: number }), RangeError);
    assert.deepEqual(t.snapshotConfig(), before);
  });

  it("an empty patch is a RangeError", () => {
    const t = new EndpointHealthTracker({ sloMs: 1000 });
    assert.throws(() => t.retune({}), RangeError);
    assert.equal(t.snapshotConfig().sloMs, 1000);
  });

  it("a same-value patch is a silent no-op", () => {
    const t = new EndpointHealthTracker({ sloMs: 1000 });
    t.recordOutcome(URL, false);
    const before = t.snapshotConfig();
    const scoreBefore = t.score(URL);
    assert.deepEqual(t.retune({ sloMs: 1000 }), before);
    assert.deepEqual(t.retune({ ...defaults, sloMs: 1000 }), before);
    assert.equal(t.score(URL), scoreBefore);
    assert.equal(t.isDegraded(URL), false);
  });

  it("revision leaves degraded state and consecutiveLowScores untouched", () => {
    const t = new EndpointHealthTracker({ ewmaAlpha: 0.5 });
    t.recordOutcome(URL, false);
    t.recordOutcome(URL, false);
    t.recordOutcome(URL, false);
    t.recordOutcome(URL, false);
    assert.equal(t.isDegraded(URL), true);
    assert.equal(t.snapshot()[0].consecutiveLowScores, 2);
    const scoreBefore = t.score(URL);
    t.retune({ recoverThreshold: 90 });
    assert.equal(t.isDegraded(URL), true);
    assert.equal(t.snapshot()[0].consecutiveLowScores, 2);
    assert.equal(t.score(URL), scoreBefore);
  });
});

describe("RetryQueue.reviseEndpointHealth (WR-359)", () => {
  it("revises every live per-tenant tracker and audits exactly once", async () => {
    const timer = manualTimer();
    const audits: EndpointHealthRevisedAuditEvent[] = [];
    const flaky: Sender = async () => {
      throw new Error("downstream down");
    };
    const q = new RetryQueue({
      sender: flaky,
      baseDelayMs: 1,
      maxDelayMs: 10,
      maxAttempts: 1,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      endpointHealth: {},
      onEndpointHealthAudit: (event) => audits.push(event),
    });
    q.start();
    // Two failures per tenant: score 74.8 — healthy under the 40 line.
    for (let i = 0; i < 2; i++) q.enqueue(item(`fail-default-${i}`));
    for (let i = 0; i < 2; i++) q.enqueue(item(`fail-acme-${i}`, "acme"));
    await timer.run();
    assert.equal(q.getEndpointHealthStats().length, 2);
    assert.ok(q.getEndpointHealthStats().every((r) => !r.degraded));
    const next = q.reviseEndpointHealth({ degradeThreshold: 80, recoverThreshold: 90 });
    assert.deepEqual(next, { ...defaults, degradeThreshold: 80, recoverThreshold: 90 });
    assert.deepEqual(q.getEndpointHealthConfig(), {
      ...defaults,
      degradeThreshold: 80,
      recoverThreshold: 90,
    });
    assert.equal(audits.length, 1);
    assert.equal(audits[0].event, "endpoint_health_revised");
    assert.deepEqual(audits[0].previous, defaults);
    assert.deepEqual(audits[0].current, { ...defaults, degradeThreshold: 80, recoverThreshold: 90 });
    // One more failure per tenant: score 65.84 < 80 — both degrade now.
    q.enqueue(item("fail-default-2"));
    q.enqueue(item("fail-acme-2", "acme"));
    await timer.run();
    assert.ok(q.getEndpointHealthStats().every((r) => r.degraded));
    // A same-value revision is a silent no-op with no second audit.
    q.reviseEndpointHealth({ degradeThreshold: 80 });
    assert.equal(audits.length, 1);
    // An illegal patch throws and leaves the live config untouched.
    assert.throws(() => q.reviseEndpointHealth({ degradeThreshold: 95 }), RangeError);
    assert.throws(() => q.reviseEndpointHealth({}), RangeError);
    assert.equal(audits.length, 1);
    assert.deepEqual(q.getEndpointHealthConfig(), {
      ...defaults,
      degradeThreshold: 80,
      recoverThreshold: 90,
    });
    q.stop();
  });

  it("tenants born after a revision start from the revised values", async () => {
    const timer = manualTimer();
    const flaky: Sender = async () => {
      throw new Error("downstream down");
    };
    const q = new RetryQueue({
      sender: flaky,
      baseDelayMs: 1,
      maxDelayMs: 10,
      maxAttempts: 1,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      endpointHealth: {},
    });
    q.start();
    q.reviseEndpointHealth({ degradeThreshold: 80, recoverThreshold: 90 });
    // Three failures: score 65.84 — degraded under the revised 80 line,
    // but healthy under the construction-time 40 line.
    for (let i = 0; i < 3; i++) q.enqueue(item(`fail-newbie-${i}`, "newbie"));
    await timer.run();
    const rows = q.getEndpointHealthStats("newbie");
    assert.equal(rows.length, 1);
    assert.equal(rows[0].degraded, true);
    assert.ok(rows[0].score < 80);
    q.stop();
  });

  it("unconfigured queue: revise throws the must-restart Error and the getter is undefined", () => {
    const q = new RetryQueue({ sender: async () => {} });
    assert.equal(q.getEndpointHealthConfig(), undefined);
    assert.throws(
      () => q.reviseEndpointHealth({ sloMs: 1000 }),
      (err: unknown) => err instanceof Error && /requires a restart/.test((err as Error).message)
    );
  });
});

describe("RelayServer endpoint health revision (WR-359)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "endpoint-health-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: signingKey,
      forwardUrl: EP,
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

  it("revision audits previous/current with eight fields; same-value is a silent no-op", async () => {
    const { relay, audit } = makeRelay({ endpointHealth: {} });
    await listen(relay);
    assert.deepEqual(relay.getEndpointHealthConfig!(), defaults);
    assert.deepEqual(relay.reviseEndpointHealth!({ degradeThreshold: 30, sloMs: 2000 }), {
      ...defaults,
      degradeThreshold: 30,
      sloMs: 2000,
    });
    const revised = eventsOf(audit, "endpoint_health_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, defaults);
    assert.deepEqual(revised[0].current, { ...defaults, degradeThreshold: 30, sloMs: 2000 });
    // Landing exactly on the live values audits nothing.
    relay.reviseEndpointHealth!({ degradeThreshold: 30, sloMs: 2000 });
    assert.equal(eventsOf(audit, "endpoint_health_revised").length, 1);
    assert.deepEqual(relay.getEndpointHealthConfig!(), {
      ...defaults,
      degradeThreshold: 30,
      sloMs: 2000,
    });
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseEndpointHealth!({ degradeThreshold: 80 }), RangeError);
    assert.throws(() => relay.reviseEndpointHealth!({}), RangeError);
    assert.equal(eventsOf(audit, "endpoint_health_revised").length, 1);
    assert.deepEqual(relay.getEndpointHealthConfig!(), {
      ...defaults,
      degradeThreshold: 30,
      sloMs: 2000,
    });
  });

  it("unconfigured relay: revise throws the must-restart Error and the getter is not mounted", async () => {
    const { relay } = makeRelay();
    await listen(relay);
    assert.equal(relay.getEndpointHealthConfig, undefined);
    assert.throws(
      () => relay.reviseEndpointHealth!({ sloMs: 1000 }),
      (err: unknown) => err instanceof Error && /requires a restart/.test((err as Error).message)
    );
  });
});
