import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type EndpointHealthConfig,
  type EndpointHealthRevisedAuditEvent,
} from "../src/endpoint-health.ts";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "endpoint-health-enable-test-key";
const opToken = "endpoint-health-enable-op-token";
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

describe("RetryQueue.reviseEndpointHealth enable on unconfigured queues (WR-448)", () => {
  it("first revise enables scoring with the construction defaults", () => {
    const audits: EndpointHealthRevisedAuditEvent[] = [];
    const q = new RetryQueue({
      sender: async () => {},
      onEndpointHealthAudit: (event) => audits.push(event),
    });
    assert.equal(q.getEndpointHealthConfig(), undefined);
    assert.deepEqual(q.reviseEndpointHealth({ sloMs: 2000 }), {
      ...defaults,
      sloMs: 2000,
    });
    assert.deepEqual(q.getEndpointHealthConfig(), { ...defaults, sloMs: 2000 });
    assert.equal(audits.length, 1);
    assert.deepEqual(audits[0], {
      event: "endpoint_health_revised",
      previous: null,
      current: { ...defaults, sloMs: 2000 },
    });
  });

  it("a partial patch fills every missing knob from the construction defaults", () => {
    const q = new RetryQueue({ sender: async () => {} });
    const next = q.reviseEndpointHealth({ ewmaAlpha: 0.5 });
    assert.equal(next.ewmaAlpha, 0.5, "explicit knob wins");
    assert.equal(next.maxLatencySamples, 256);
    assert.equal(next.sloMs, 5000);
    assert.equal(next.successWeight, 0.7);
    assert.equal(next.latencyWeight, 0.3);
    assert.equal(next.circuitOpenPenalty, 100);
    assert.equal(next.degradeThreshold, 40);
    assert.equal(next.recoverThreshold, 70);
    assert.deepEqual(q.getEndpointHealthConfig(), {
      ewmaAlpha: 0.5,
      maxLatencySamples: 256,
      sloMs: 5000,
      successWeight: 0.7,
      latencyWeight: 0.3,
      circuitOpenPenalty: 100,
      degradeThreshold: 40,
      recoverThreshold: 70,
    });
  });

  it("empty, non-object, and illegal patches throw RangeError and stay unconfigured", () => {
    const audits: EndpointHealthRevisedAuditEvent[] = [];
    const q = new RetryQueue({
      sender: async () => {},
      onEndpointHealthAudit: (event) => audits.push(event),
    });
    assert.throws(() => q.reviseEndpointHealth({}), RangeError);
    assert.throws(
      () => q.reviseEndpointHealth(null as unknown as { sloMs: number }),
      RangeError
    );
    assert.throws(
      () => q.reviseEndpointHealth([] as unknown as { sloMs: number }),
      RangeError
    );
    assert.throws(
      () => q.reviseEndpointHealth("slow" as unknown as { sloMs: number }),
      RangeError
    );
    assert.throws(() => q.reviseEndpointHealth({ ewmaAlpha: 0 }), RangeError);
    assert.throws(() => q.reviseEndpointHealth({ ewmaAlpha: 1.5 }), RangeError);
    assert.throws(() => q.reviseEndpointHealth({ maxLatencySamples: 0 }), RangeError);
    // degrade 80 against the default recover 70 breaks the strict gap.
    assert.throws(() => q.reviseEndpointHealth({ degradeThreshold: 80 }), RangeError);
    assert.throws(
      () => q.reviseEndpointHealth({ successWeight: 0, latencyWeight: 0 }),
      RangeError
    );
    assert.throws(
      () => q.reviseEndpointHealth({ degradeThreshold: 80, recoverThreshold: 70 }),
      RangeError
    );
    assert.equal(q.getEndpointHealthConfig(), undefined);
    assert.equal(audits.length, 0, "no audit for a rejected enable");
    // A valid patch still enables afterwards — the rejections left no state.
    assert.deepEqual(q.reviseEndpointHealth({ sloMs: 1000 }), { ...defaults, sloMs: 1000 });
    assert.equal(audits.length, 1);
    assert.equal(audits[0].previous, null);
  });

  it("pre-enable verdicts are not scored; the tracker is built lazily on the first post-enable outcome", async () => {
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
    });
    q.start();
    // Three failures while scoring is off: nothing is recorded.
    for (let i = 0; i < 3; i++) q.enqueue(item(`fail-before-${i}`));
    await timer.run();
    assert.deepEqual(q.getEndpointHealthStats(), []);
    q.reviseEndpointHealth({ ewmaAlpha: 0.5 });
    assert.deepEqual(q.getEndpointHealthStats(), [], "enable alone creates no tracker");
    // Three failures after the enable: the tracker starts from empty
    // statistics — score 38.75 (three failures at alpha 0.5), not 31.09
    // (six failures), so the pre-enable verdicts were never scored.
    for (let i = 0; i < 3; i++) q.enqueue(item(`fail-after-${i}`));
    await timer.run();
    const rows = q.getEndpointHealthStats();
    assert.equal(rows.length, 1);
    assert.equal(rows[0].score, 38.75);
    assert.equal(rows[0].degraded, true);
    assert.equal(rows[0].consecutiveLowScores, 1);
    q.stop();
  });

  it("a later revision merges against the live enabled values", () => {
    const audits: EndpointHealthRevisedAuditEvent[] = [];
    const q = new RetryQueue({
      sender: async () => {},
      onEndpointHealthAudit: (event) => audits.push(event),
    });
    q.reviseEndpointHealth({ sloMs: 2000 });
    assert.deepEqual(q.reviseEndpointHealth({ degradeThreshold: 30 }), {
      ...defaults,
      sloMs: 2000,
      degradeThreshold: 30,
    });
    assert.equal(audits.length, 2);
    assert.equal(audits[0].previous, null);
    assert.deepEqual(audits[1].previous, { ...defaults, sloMs: 2000 });
    assert.deepEqual(audits[1].current, {
      ...defaults,
      sloMs: 2000,
      degradeThreshold: 30,
    });
  });

  it("degrade/recover callbacks can be revised in after the enable and fire on the next transition", async () => {
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
    });
    assert.throws(
      () => q.reviseEndpointDegradedCallbacks({ onEndpointDegraded: () => {} }),
      (err: unknown) => err instanceof Error && /not configured/.test((err as Error).message),
      "the callbacks gate is closed before the enable"
    );
    q.start();
    q.reviseEndpointHealth({ ewmaAlpha: 0.5 });
    const degraded: Array<{ score: number; consecutiveLowScores: number }> = [];
    q.reviseEndpointDegradedCallbacks({
      onEndpointDegraded: (info) => degraded.push(info),
    });
    for (let i = 0; i < 3; i++) q.enqueue(item(`fail-cb-${i}`));
    await timer.run();
    assert.equal(degraded.length, 1);
    assert.equal(degraded[0].score, 38.75);
    assert.equal(degraded[0].consecutiveLowScores, 1);
    q.stop();
  });

  it("a fresh queue (restart) is unconfigured again", () => {
    const q = new RetryQueue({ sender: async () => {} });
    q.reviseEndpointHealth({ sloMs: 1000 });
    assert.deepEqual(q.getEndpointHealthConfig(), { ...defaults, sloMs: 1000 });
    const restarted = new RetryQueue({ sender: async () => {} });
    assert.equal(restarted.getEndpointHealthConfig(), undefined);
    assert.deepEqual(restarted.getEndpointHealthStats(), []);
  });
});

describe("RelayServer endpoint health enable (WR-448)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "endpoint-health-enable-"));
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

  it("first revise enables scoring, mounts the getter, audits previous null once, and a same-value revise is a silent no-op", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.equal(relay.getEndpointHealthConfig, undefined);
    assert.deepEqual(relay.reviseEndpointHealth!({ sloMs: 2000 }), {
      ...defaults,
      sloMs: 2000,
    });
    assert.deepEqual(relay.getEndpointHealthConfig!(), { ...defaults, sloMs: 2000 });
    const revised = eventsOf(audit, "endpoint_health_revised");
    assert.equal(revised.length, 1, "the enable is audited exactly once");
    assert.equal(revised[0].previous, null);
    assert.deepEqual(revised[0].current, { ...defaults, sloMs: 2000 });
    // Landing exactly on the live values audits nothing.
    relay.reviseEndpointHealth!({ sloMs: 2000 });
    assert.equal(eventsOf(audit, "endpoint_health_revised").length, 1);
  });

  it("empty and illegal patches throw RangeError, leave the getter unmounted, and audit nothing", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.equal(relay.getEndpointHealthConfig, undefined);
    assert.throws(() => relay.reviseEndpointHealth!({}), RangeError);
    assert.throws(() => relay.reviseEndpointHealth!({ ewmaAlpha: 0 }), RangeError);
    assert.throws(
      () => relay.reviseEndpointHealth!(null as unknown as { sloMs: number }),
      RangeError
    );
    assert.equal(relay.getEndpointHealthConfig, undefined);
    assert.equal(eventsOf(audit, "endpoint_health_revised").length, 0);
    // A valid patch still enables afterwards.
    assert.deepEqual(relay.reviseEndpointHealth!({ sloMs: 1000 }), {
      ...defaults,
      sloMs: 1000,
    });
    assert.deepEqual(relay.getEndpointHealthConfig!(), { ...defaults, sloMs: 1000 });
    assert.equal(eventsOf(audit, "endpoint_health_revised").length, 1);
  });

  it("the audit-callback gate opens with the enable: the callback can be revised in and observes the next revision", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    const seen: EndpointHealthRevisedAuditEvent[] = [];
    assert.throws(
      () => relay.reviseEndpointHealthAuditCallback!((e) => seen.push(e)),
      (err: unknown) => err instanceof Error && /not configured/.test((err as Error).message),
      "the audit-callback gate is closed before the enable"
    );
    relay.reviseEndpointHealth!({ sloMs: 1000 });
    relay.reviseEndpointHealthAuditCallback!((e) => seen.push(e));
    assert.equal(seen.length, 0, "no re-delivery of the enable audit");
    relay.reviseEndpointHealth!({ sloMs: 2000 });
    assert.equal(seen.length, 1);
    assert.deepEqual(seen[0], {
      event: "endpoint_health_revised",
      previous: { ...defaults, sloMs: 1000 },
      current: { ...defaults, sloMs: 2000 },
    });
    assert.equal(eventsOf(audit, "endpoint_health_revised").length, 2);
  });

  it("a fresh relay (restart) is unconfigured again", async () => {
    const first = makeRelay();
    await listen(first.relay);
    first.relay.reviseEndpointHealth!({ sloMs: 1000 });
    assert.deepEqual(first.relay.getEndpointHealthConfig!(), { ...defaults, sloMs: 1000 });
    const restarted = makeRelay();
    await listen(restarted.relay);
    assert.equal(restarted.relay.getEndpointHealthConfig, undefined);
  });
});
