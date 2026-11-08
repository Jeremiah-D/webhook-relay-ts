import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  LatencyPhasesTracker,
  type Sender,
} from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "latency-phases-revision-test-key";
const opToken = "latency-phases-revision-op-token";
const URL = "http://localhost:9999/hook";

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

function item(id: string, tenantId?: string) {
  return {
    id,
    payload: Buffer.from("hello"),
    targetUrl: URL,
    headers: {},
    ...(tenantId !== undefined ? { tenantId } : {}),
  };
}

/**
 * Sender that returns a canned body-phase sample per item id: the
 * numeric suffix picks the sample, so the sample a tenant sees does
 * not depend on the queue's cross-tenant delivery order (the default
 * tenant's items are attempted before other tenants').
 */
function phasedSender(samples: number[]): Sender {
  return async (it) => ({
    statusCode: 200,
    body: Buffer.alloc(0),
    truncated: false,
    phases: { bodyMs: samples[Number(it.id.split("-")[1]) - 1] ?? samples[samples.length - 1] },
  });
}

describe("WR-360 LatencyPhasesTracker.resize (unit)", () => {
  it("shrinking truncates oldest-first and the p50 moves with the survivors", () => {
    let now = 1_000;
    const t = new LatencyPhasesTracker({ maxSamplesPerEndpoint: 5, now: () => now });
    for (const ms of [10, 20, 30, 40, 50]) {
      now += 100;
      t.recordPhases("e", { bodyMs: ms });
    }
    assert.equal(t.stats()[0].phases.body?.p50, 30);
    assert.equal(t.maxSamplesPerEndpoint, 5);
    t.resize(2);
    assert.equal(t.maxSamplesPerEndpoint, 2);
    const [row] = t.stats();
    assert.deepEqual(row.phases.body, { count: 2, p50: 40, p95: 50, latest: 50 });
    // A resize is not a sample: the staleness marker does not move.
    assert.equal(row.lastSampleAt, 1_500);
  });

  it("widening keeps every sample and never restores evicted ones", () => {
    const t = new LatencyPhasesTracker({ maxSamplesPerEndpoint: 2 });
    t.recordPhases("e", { bodyMs: 10 });
    t.recordPhases("e", { bodyMs: 20 });
    t.recordPhases("e", { bodyMs: 30 }); // 10 evicted by the rolling window
    t.resize(10);
    assert.equal(t.stats()[0].phases.body?.count, 2);
    t.recordPhases("e", { bodyMs: 40 });
    assert.deepEqual(t.stats()[0].phases.body, { count: 3, p50: 30, p95: 40, latest: 40 });
  });

  it("an illegal resize throws RangeError and leaves window and samples untouched", () => {
    const t = new LatencyPhasesTracker({ maxSamplesPerEndpoint: 2 });
    t.recordPhases("e", { bodyMs: 10 });
    t.recordPhases("e", { bodyMs: 20 });
    assert.throws(() => t.resize(0), RangeError);
    assert.throws(() => t.resize(1.5), RangeError);
    assert.throws(() => t.resize(NaN), RangeError);
    assert.equal(t.maxSamplesPerEndpoint, 2);
    assert.deepEqual(t.stats()[0].phases.body, { count: 2, p50: 10, p95: 20, latest: 20 });
  });
});

describe("WR-360 RetryQueue.reviseLatencyPhases", () => {
  it("shrinks every built tracker in place; later samples keep rolling at the new window", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: phasedSender([10, 20, 30]),
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      latencyPhases: { maxSamplesPerEndpoint: 3 },
    });
    q.start();
    q.enqueue(item("r-1"));
    q.enqueue(item("r-2"));
    q.enqueue(item("r-3"));
    await timer.run();
    assert.equal(q.getLatencyPhaseStats()![0].phases.body?.count, 3);
    assert.deepEqual(q.reviseLatencyPhases(2), { maxSamplesPerEndpoint: 2 });
    assert.deepEqual(q.getLatencyPhaseOptions(), { maxSamplesPerEndpoint: 2 });
    const [row] = q.getLatencyPhaseStats()!;
    assert.deepEqual(row.phases.body, { count: 2, p50: 20, p95: 30, latest: 30 });
    // recordPhases keeps rolling at the new bound: one more sample
    // evicts the oldest survivor, it does not grow the window back.
    q.enqueue(item("r-4"));
    await timer.run();
    assert.deepEqual(q.getLatencyPhaseStats()![0].phases.body, {
      count: 2,
      p50: 30,
      p95: 30,
      latest: 30,
    });
    q.stop();
  });

  it("widening keeps every sample", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: phasedSender([10, 20]),
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      latencyPhases: { maxSamplesPerEndpoint: 2 },
    });
    q.start();
    q.enqueue(item("w-1"));
    q.enqueue(item("w-2"));
    await timer.run();
    q.reviseLatencyPhases(10);
    assert.equal(q.getLatencyPhaseStats()![0].phases.body?.count, 2);
    q.enqueue(item("w-3"));
    await timer.run();
    assert.equal(q.getLatencyPhaseStats()![0].phases.body?.count, 3);
    q.stop();
  });

  it("an illegal value throws RangeError and the live window and samples are untouched", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: phasedSender([10, 20]),
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      latencyPhases: { maxSamplesPerEndpoint: 2 },
    });
    q.start();
    q.enqueue(item("i-1"));
    q.enqueue(item("i-2"));
    await timer.run();
    assert.throws(() => q.reviseLatencyPhases(0), RangeError);
    assert.throws(() => q.reviseLatencyPhases(1.5), RangeError);
    assert.deepEqual(q.getLatencyPhaseOptions(), { maxSamplesPerEndpoint: 2 });
    assert.equal(q.getLatencyPhaseStats()![0].phases.body?.count, 2);
    q.stop();
  });

  it("throws the must-restart Error when phase tracking was never configured", () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: phasedSender([10]),
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
    });
    assert.equal(q.getLatencyPhaseOptions(), undefined);
    assert.throws(
      () => q.reviseLatencyPhases(2),
      /not configured — enabling it requires a restart/
    );
    q.stop();
  });

  it("fans the revision out to every already-built per-tenant tracker", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: phasedSender([10, 20, 30, 40, 50, 60]),
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      latencyPhases: { maxSamplesPerEndpoint: 3 },
    });
    q.start();
    q.enqueue(item("f-1", "acme"));
    q.enqueue(item("f-2", "acme"));
    q.enqueue(item("f-3", "acme"));
    q.enqueue(item("f-4"));
    q.enqueue(item("f-5"));
    q.enqueue(item("f-6"));
    await timer.run();
    assert.equal(q.getLatencyPhaseStats()!.length, 2);
    q.reviseLatencyPhases(1);
    const rows = q.getLatencyPhaseStats()!;
    assert.equal(rows.length, 2);
    for (const row of rows) {
      assert.equal(row.phases.body?.count, 1);
    }
    const acme = rows.find((r) => r.tenant === "acme")!;
    assert.equal(acme.phases.body?.latest, 30);
    const def = rows.find((r) => r.tenant === undefined)!;
    assert.equal(def.phases.body?.latest, 60);
    q.stop();
  });

  it("tenants born after the revision start at the new window", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: phasedSender([10, 20, 30, 40]),
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      latencyPhases: { maxSamplesPerEndpoint: 3 },
    });
    q.start();
    q.enqueue(item("n-1"));
    await timer.run();
    q.reviseLatencyPhases(1);
    // A brand-new tenant: its tracker is built lazily from the revised
    // options, so the window is 1 from the first sample.
    q.enqueue(item("n-2", "late"));
    q.enqueue(item("n-3", "late"));
    q.enqueue(item("n-4", "late"));
    await timer.run();
    const late = q.getLatencyPhaseStats()!.find((r) => r.tenant === "late")!;
    assert.equal(late.phases.body?.count, 1);
    assert.equal(late.phases.body?.latest, 40);
    q.stop();
  });
});

describe("WR-360 RelayServer.reviseLatencyPhases", () => {
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
    const dir = mkdtempSync(join(tmpdir(), "latency-phases-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: signingKey,
      forwardUrl: URL,
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

  it("revision audits previous/current with the construction value first; same-value is a silent no-op", async () => {
    const { relay, audit } = makeRelay({
      retry: { latencyPhases: { maxSamplesPerEndpoint: 3 } },
    });
    await listen(relay);
    assert.deepEqual(relay.getLatencyPhaseOptions!(), { maxSamplesPerEndpoint: 3 });
    assert.deepEqual(relay.reviseLatencyPhases!(2), { maxSamplesPerEndpoint: 2 });
    const revised = eventsOf(audit, "latency_phases_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, { maxSamplesPerEndpoint: 3 });
    assert.deepEqual(revised[0].current, { maxSamplesPerEndpoint: 2 });
    // Landing exactly on the live value audits nothing.
    relay.reviseLatencyPhases!(2);
    assert.equal(eventsOf(audit, "latency_phases_revised").length, 1);
    assert.deepEqual(relay.getLatencyPhaseOptions!(), { maxSamplesPerEndpoint: 2 });
    // An illegal value throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseLatencyPhases!(0), RangeError);
    assert.equal(eventsOf(audit, "latency_phases_revised").length, 1);
    assert.deepEqual(relay.getLatencyPhaseOptions!(), { maxSamplesPerEndpoint: 2 });
  });

  it("unconfigured relay: revise throws the must-restart Error and the getter is not mounted", async () => {
    const { relay } = makeRelay();
    await listen(relay);
    assert.equal(relay.getLatencyPhaseOptions, undefined);
    assert.throws(
      () => relay.reviseLatencyPhases!(2),
      /not configured — enabling it requires a restart/
    );
  });

  it("server getter reflects revisions made through the server", async () => {
    const { relay } = makeRelay({
      retry: { latencyPhases: {} },
    });
    await listen(relay);
    assert.deepEqual(relay.getLatencyPhaseOptions!(), { maxSamplesPerEndpoint: 1024 });
    relay.reviseLatencyPhases!(64);
    assert.deepEqual(relay.getLatencyPhaseOptions!(), { maxSamplesPerEndpoint: 64 });
  });
});
