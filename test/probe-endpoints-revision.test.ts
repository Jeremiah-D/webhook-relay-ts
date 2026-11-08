import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DownstreamProber,
  type ProbeAuditEvent,
  type ProbeTimerHandle,
} from "../src/downstream-probe.ts";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "probe-endpoints-revision-test-key";
const opToken = "probe-endpoints-revision-op-token";
const EP = "http://127.0.0.1:9/health";
const EP2 = "http://127.0.0.1:9/other";
const EP3 = "http://127.0.0.1:9/third";

/** Manual timer driver: collect scheduled callbacks, inspect on demand. */
function manualTimers() {
  const scheduled: { fn: () => void; ms: number; cleared: boolean }[] = [];
  return {
    setTimer: (fn: () => void, ms: number): ProbeTimerHandle => {
      const entry = { fn, ms, cleared: false };
      scheduled.push(entry);
      return {
        clear: () => {
          entry.cleared = true;
        },
      };
    },
    clearTimer: (h: ProbeTimerHandle) => h.clear(),
    scheduled,
  };
}

function listen(server: Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      assert.ok(addr && typeof addr === "object");
      resolve(addr.port);
    });
  });
}

describe("DownstreamProber.retuneEndpoints (WR-356)", () => {
  it("adding an endpoint arms it at the live interval with fresh stats", () => {
    const t = manualTimers();
    const prober = new DownstreamProber({
      endpoints: [EP],
      intervalMs: 1000,
      probeRequest: async () => true,
      recordOutcome: () => {},
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
    });
    prober.start();
    assert.equal(t.scheduled.length, 1);
    assert.deepEqual(prober.retuneEndpoints({ add: [EP2] }), [EP, EP2]);
    assert.deepEqual(prober.snapshotEndpoints(), [EP, EP2]);
    // The new endpoint was armed at once, at the live interval.
    assert.equal(t.scheduled.length, 2);
    assert.equal(t.scheduled[1].ms, 1000);
    assert.equal(t.scheduled[1].cleared, false);
    assert.deepEqual(
      prober.stats().map((s) => [s.endpoint, s.success, s.failure, s.consecutiveFailures]),
      [
        [EP, 0, 0, 0],
        [EP2, 0, 0, 0],
      ]
    );
    prober.stop();
  });

  it("removing an endpoint clears its pending timer and drops its stats", async () => {
    const t = manualTimers();
    const prober = new DownstreamProber({
      endpoints: [EP, EP2],
      intervalMs: 1000,
      probeRequest: async () => true,
      recordOutcome: () => {},
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
    });
    prober.start();
    assert.deepEqual(await prober.runRound(EP2), [{ endpoint: EP2, ok: true }]);
    assert.deepEqual(prober.retuneEndpoints({ remove: [EP2] }), [EP]);
    assert.deepEqual(prober.snapshotEndpoints(), [EP]);
    // EP2's pending timer was cleared; EP's was left alone.
    assert.ok(t.scheduled[1].cleared);
    assert.equal(t.scheduled[0].cleared, false);
    assert.deepEqual(
      prober.stats().map((s) => s.endpoint),
      [EP]
    );
    await assert.rejects(() => prober.runRound(EP2), /unknown probe endpoint/);
    prober.stop();
  });

  it("illegal patches throw RangeError and the live list, timers and stats are untouched", async () => {
    const t = manualTimers();
    const prober = new DownstreamProber({
      endpoints: [EP, EP2],
      intervalMs: 1000,
      probeRequest: async () => true,
      recordOutcome: () => {},
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
    });
    prober.start();
    assert.deepEqual(await prober.runRound(), [
      { endpoint: EP, ok: true },
      { endpoint: EP2, ok: true },
    ]);
    const live = [EP, EP2];
    for (const patch of [
      { add: [EP] }, // already probed
      { add: [""] },
      { add: [EP3, EP3] }, // duplicate within add
      { add: [EP3], remove: [EP3, EP3] }, // duplicate within remove
      { remove: ["http://127.0.0.1:9/nope"] }, // unknown endpoint
      { remove: [""] },
      { remove: [EP, EP2] }, // result list would be empty
      { add: [123 as never] },
      { add: "http://127.0.0.1:9/x" as never },
    ]) {
      assert.throws(() => prober.retuneEndpoints(patch), RangeError, JSON.stringify(patch));
    }
    assert.deepEqual(prober.snapshotEndpoints(), live);
    assert.deepEqual(
      prober.stats().map((s) => [s.success, s.failure]),
      [
        [1, 0],
        [1, 0],
      ]
    );
    // No timer was cleared or re-armed by the failed revisions.
    assert.equal(t.scheduled.length, 2);
    assert.ok(t.scheduled.every((s) => s.ms === 1000 && !s.cleared));
    prober.stop();
  });

  it("an empty patch and a non-object patch are RangeErrors", () => {
    const prober = new DownstreamProber({
      endpoints: [EP],
      probeRequest: async () => true,
      recordOutcome: () => {},
    });
    assert.throws(() => prober.retuneEndpoints({}), RangeError);
    assert.throws(() => prober.retuneEndpoints({ add: [], remove: [] }), RangeError);
    assert.throws(() => prober.retuneEndpoints(null as never), RangeError);
    assert.throws(() => prober.retuneEndpoints("fast" as never), RangeError);
    assert.throws(() => prober.retuneEndpoints([] as never), RangeError);
    assert.deepEqual(prober.snapshotEndpoints(), [EP]);
  });

  it("a net-zero patch is a silent no-op: no audit, no timer churn", () => {
    const t = manualTimers();
    const audited: ProbeAuditEvent[] = [];
    const prober = new DownstreamProber({
      endpoints: [EP, EP2],
      intervalMs: 1000,
      probeRequest: async () => true,
      recordOutcome: () => {},
      onAudit: (e) => audited.push(e),
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
    });
    prober.start();
    assert.deepEqual(prober.retuneEndpoints({ add: [EP], remove: [EP] }), [EP, EP2]);
    assert.deepEqual(prober.snapshotEndpoints(), [EP, EP2]);
    assert.equal(audited.length, 0);
    assert.equal(t.scheduled.length, 2);
    assert.ok(t.scheduled.every((s) => s.ms === 1000 && !s.cleared));
    prober.stop();
  });

  it("a real revision audits probe_endpoints_revised with exact previous/current", () => {
    const audited: ProbeAuditEvent[] = [];
    const prober = new DownstreamProber({
      endpoints: [EP],
      probeRequest: async () => true,
      recordOutcome: () => {},
      onAudit: (e) => audited.push(e),
    });
    assert.deepEqual(prober.retuneEndpoints({ add: [EP2, EP3] }), [EP, EP2, EP3]);
    assert.deepEqual(prober.retuneEndpoints({ remove: [EP2] }), [EP, EP3]);
    assert.equal(audited.length, 2);
    assert.deepEqual(audited[0], {
      event: "probe_endpoints_revised",
      previous: [EP],
      current: [EP, EP2, EP3],
    });
    assert.deepEqual(audited[1], {
      event: "probe_endpoints_revised",
      previous: [EP, EP2, EP3],
      current: [EP, EP3],
    });
    prober.stop();
  });

  it("an in-flight round for a removed endpoint settles but its result is discarded", async () => {
    const t = manualTimers();
    const outcomes: [string, boolean][] = [];
    const audited: ProbeAuditEvent[] = [];
    let releaseProbe: ((ok: boolean) => void) | undefined;
    const prober = new DownstreamProber({
      endpoints: [EP, EP2],
      intervalMs: 1000,
      probeRequest: () =>
        new Promise<boolean>((resolve) => {
          releaseProbe = resolve;
        }),
      recordOutcome: (endpoint, ok) => outcomes.push([endpoint, ok]),
      onAudit: (e) => audited.push(e),
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
    });
    prober.start();
    assert.equal(t.scheduled.length, 2);
    // Fire EP's round; it goes in-flight on the deferred probe.
    const roundA = t.scheduled[0].fn();
    // Remove EP while its round is in flight.
    assert.deepEqual(prober.retuneEndpoints({ remove: [EP] }), [EP2]);
    assert.deepEqual(prober.snapshotEndpoints(), [EP2]);
    // The in-flight round still settles on its original flow, but the
    // failure is discarded: no breaker outcome, no probe_failed audit.
    releaseProbe!(false);
    await roundA;
    assert.deepEqual(outcomes, []);
    assert.deepEqual(
      audited.map((e) => e.event),
      ["probe_endpoints_revised"]
    );
    // No timer was re-armed for the removed endpoint — the schedule
    // gained no new entry (the fired EP entry stays listed by the
    // manual driver, EP2's pending timer untouched).
    assert.equal(t.scheduled.length, 2);
    assert.equal(t.scheduled[1].cleared, false);
    assert.deepEqual(
      prober.stats().map((s) => s.endpoint),
      [EP2]
    );
    prober.stop();
  });

  it("an unstarted prober picks added endpoints up on the next start()", () => {
    const t = manualTimers();
    const prober = new DownstreamProber({
      endpoints: [EP],
      intervalMs: 1000,
      probeRequest: async () => true,
      recordOutcome: () => {},
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
    });
    assert.deepEqual(prober.retuneEndpoints({ add: [EP2] }), [EP, EP2]);
    assert.equal(t.scheduled.length, 0);
    prober.start();
    assert.equal(t.scheduled.length, 2);
    assert.ok(t.scheduled.every((s) => s.ms === 1000 && !s.cleared));
    prober.stop();
  });

  it("re-adding an endpoint gives it fresh stats", async () => {
    const prober = new DownstreamProber({
      endpoints: [EP, EP2],
      probeRequest: async () => true,
      recordOutcome: () => {},
    });
    assert.deepEqual(await prober.runRound(EP), [{ endpoint: EP, ok: true }]);
    assert.equal(prober.stats()[0].success, 1);
    prober.retuneEndpoints({ remove: [EP] });
    assert.deepEqual(
      prober.stats().map((s) => s.endpoint),
      [EP2]
    );
    // Re-adding appends after the surviving endpoints, with fresh stats.
    assert.deepEqual(prober.retuneEndpoints({ add: [EP] }), [EP2, EP]);
    assert.deepEqual(
      prober.stats().map((s) => [s.endpoint, s.success, s.failure, s.consecutiveFailures]),
      [
        [EP2, 0, 0, 0],
        [EP, 0, 0, 0],
      ]
    );
    prober.stop();
  });
});

describe("RetryQueue probe endpoints revision (WR-356)", () => {
  const okSender: Sender = async () => ({ statusCode: 200, body: Buffer.alloc(0) });

  it("unconfigured: revise throws the must-restart Error, getter returns undefined", () => {
    const q = new RetryQueue({ sender: okSender });
    assert.equal(q.getProbeEndpoints(), undefined);
    assert.throws(
      () => q.reviseProbeEndpoints({ add: [EP] }),
      /not configured — enabling it requires a restart/
    );
    assert.equal(q.getProbeEndpoints(), undefined);
    q.stop();
  });

  it("getter tracks revisions", () => {
    const q = new RetryQueue({
      sender: okSender,
      probe: {
        endpoints: [EP],
        intervalMs: 60000,
        probeRequest: async () => true,
      },
    });
    assert.deepEqual(q.getProbeEndpoints(), [EP]);
    assert.deepEqual(q.reviseProbeEndpoints({ add: [EP2] }), [EP, EP2]);
    assert.deepEqual(q.getProbeEndpoints(), [EP, EP2]);
    assert.deepEqual(q.reviseProbeEndpoints({ remove: [EP] }), [EP2]);
    assert.deepEqual(q.getProbeEndpoints(), [EP2]);
    q.stop();
  });

  it("re-adding an endpoint resets probe stats but the breaker state follows the old value", async () => {
    const q = new RetryQueue({
      sender: okSender,
      circuitBreaker: { failureThreshold: 2, cooldownMs: 60_000 },
      probe: {
        endpoints: [EP, EP2],
        intervalMs: 60000,
        probeRequest: async () => false,
      },
    });
    const prober = q.getProber()!;
    // Two failing rounds trip the breaker open for EP (EP2 untouched).
    await prober.runRound(EP);
    await prober.runRound(EP);
    const tripped = q.getCircuitStats().find((s) => s.endpoint === EP)!;
    assert.equal(tripped.state, "open");
    assert.equal(tripped.consecutiveFailures, 2);
    assert.equal(tripped.trips, 1);
    assert.equal(prober.stats().find((s) => s.endpoint === EP)!.failure, 2);
    // Removing the endpoint drops its probe stats but not the breaker.
    q.reviseProbeEndpoints({ remove: [EP] });
    assert.deepEqual(
      q.getProbeStats().map((s) => s.endpoint),
      [EP2]
    );
    const stillOpen = q.getCircuitStats().find((s) => s.endpoint === EP)!;
    assert.equal(stillOpen.state, "open");
    assert.equal(stillOpen.trips, 1);
    // Re-adding starts the probe stats over — the breaker still open.
    q.reviseProbeEndpoints({ add: [EP] });
    assert.deepEqual(
      q.getProbeStats().find((s) => s.endpoint === EP)!,
      {
        endpoint: EP,
        success: 0,
        failure: 0,
        consecutiveFailures: 0,
      }
    );
    const afterReAdd = q.getCircuitStats().find((s) => s.endpoint === EP)!;
    assert.equal(afterReAdd.state, "open");
    assert.equal(afterReAdd.trips, 1);
    q.stop();
  });
});

describe("RelayServer probe endpoints revision (WR-356)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "probe-endpoints-revision-"));
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

  it("revision audits previous/current with exact lists; net-zero is a silent no-op", async () => {
    const { relay, audit } = makeRelay({
      retry: {
        probe: {
          endpoints: [EP],
          intervalMs: 60000,
          probeRequest: async () => true,
        },
      },
    });
    await listen(relay);
    assert.deepEqual(relay.getProbeEndpoints!(), [EP]);
    assert.deepEqual(relay.reviseProbeEndpoints!({ add: [EP2] }), [EP, EP2]);
    const revised = eventsOf(audit, "probe_endpoints_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, [EP]);
    assert.deepEqual(revised[0].current, [EP, EP2]);
    // A net-zero patch audits nothing.
    relay.reviseProbeEndpoints!({ add: [EP], remove: [EP] });
    assert.equal(eventsOf(audit, "probe_endpoints_revised").length, 1);
    assert.deepEqual(relay.getProbeEndpoints!(), [EP, EP2]);
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseProbeEndpoints!({ add: [EP] }), RangeError);
    assert.throws(() => relay.reviseProbeEndpoints!({ remove: [EP3] }), RangeError);
    assert.throws(() => relay.reviseProbeEndpoints!({}), RangeError);
    assert.equal(eventsOf(audit, "probe_endpoints_revised").length, 1);
    assert.deepEqual(relay.getProbeEndpoints!(), [EP, EP2]);
  });

  it("unconfigured relay: revise throws the must-restart Error and the getter is not mounted", async () => {
    const { relay } = makeRelay();
    await listen(relay);
    assert.equal(relay.getProbeEndpoints, undefined);
    assert.throws(
      () => relay.reviseProbeEndpoints!({ add: [EP] }),
      /not configured — enabling it requires a restart/
    );
  });
});
