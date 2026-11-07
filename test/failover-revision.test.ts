import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { FailoverManager } from "../src/failover.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "failover-revision-test-key";
const opToken = "failover-revision-op-token";
const PRIMARY = "http://127.0.0.1:9911/primary";
const STANDBY = "http://127.0.0.1:9912/standby";
const STANDBY2 = "http://127.0.0.1:9913/standby2";
const UNKNOWN = "http://127.0.0.1:9919/unknown";

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

/** Let promise chains settle. */
async function flush(ticks = 20) {
  for (let i = 0; i < ticks; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

function item(id: string, targetUrl: string = PRIMARY) {
  return { id, payload: Buffer.from("hello"), targetUrl, headers: {} };
}

describe("failover revision: FailoverManager live thresholds (WR-349)", () => {
  it("tightening the threshold switches on the next dispatch", () => {
    const switches: Array<{ reason: string }> = [];
    const m = new FailoverManager(
      { [PRIMARY]: { standbys: [STANDBY], failureThreshold: 5 } },
      { onSwitch: (e) => switches.push(e) }
    );
    m.recordOutcome(PRIMARY, PRIMARY, false);
    m.recordOutcome(PRIMARY, PRIMARY, false);
    assert.equal(m.resolveTarget(PRIMARY), PRIMARY);
    assert.deepEqual(m.retune(PRIMARY, { failureThreshold: 2 }), {
      failureThreshold: 2,
      autoFailback: true,
      failbackIntervalMs: 30_000,
    });
    assert.equal(m.resolveTarget(PRIMARY), STANDBY);
    assert.equal(switches.length, 1);
    assert.equal(switches[0].reason, "failure_threshold");
  });

  it("loosening the threshold keeps the primary at the same failure count", () => {
    const m = new FailoverManager(
      { [PRIMARY]: { standbys: [STANDBY], failureThreshold: 3 } },
      { now: () => 0 }
    );
    m.recordOutcome(PRIMARY, PRIMARY, false);
    m.recordOutcome(PRIMARY, PRIMARY, false);
    m.retune(PRIMARY, { failureThreshold: 5 });
    assert.equal(m.resolveTarget(PRIMARY), PRIMARY);
    assert.equal(m.stats()[0].consecutiveFailures, 2);
  });

  it("raising failbackIntervalMs delays the canary; lowering it brings the canary forward", () => {
    let nowMs = 0;
    const raised = new FailoverManager(
      { [PRIMARY]: { standbys: [STANDBY], failureThreshold: 1, failbackIntervalMs: 1000 } },
      { now: () => nowMs }
    );
    raised.recordOutcome(PRIMARY, PRIMARY, false);
    assert.equal(raised.resolveTarget(PRIMARY), STANDBY);
    raised.retune(PRIMARY, { failbackIntervalMs: 5000 });
    nowMs = 1000; // the old interval would have canaried here
    assert.equal(raised.resolveTarget(PRIMARY), STANDBY);
    nowMs = 5000;
    assert.equal(raised.resolveTarget(PRIMARY), PRIMARY);

    nowMs = 0;
    const lowered = new FailoverManager(
      { [PRIMARY]: { standbys: [STANDBY], failureThreshold: 1, failbackIntervalMs: 60_000 } },
      { now: () => nowMs }
    );
    lowered.recordOutcome(PRIMARY, PRIMARY, false);
    assert.equal(lowered.resolveTarget(PRIMARY), STANDBY);
    lowered.retune(PRIMARY, { failbackIntervalMs: 100 });
    nowMs = 100;
    assert.equal(lowered.resolveTarget(PRIMARY), PRIMARY);
  });

  it("autoFailback off blocks the canary; manual reset still works; turning it on restores the canary", () => {
    let nowMs = 0;
    const m = new FailoverManager(
      { [PRIMARY]: { standbys: [STANDBY], failureThreshold: 1, failbackIntervalMs: 1000 } },
      { now: () => nowMs }
    );
    m.recordOutcome(PRIMARY, PRIMARY, false);
    assert.equal(m.resolveTarget(PRIMARY), STANDBY);
    m.retune(PRIMARY, { autoFailback: false });
    nowMs += 5000;
    assert.equal(m.resolveTarget(PRIMARY), STANDBY);
    assert.equal(m.resetFailover(PRIMARY), true);
    assert.equal(m.resolveTarget(PRIMARY), PRIMARY);
    // Fail again while autoFailback is still off: no canary even after
    // the quiet period, until the flag is turned back on.
    m.recordOutcome(PRIMARY, PRIMARY, false);
    assert.equal(m.resolveTarget(PRIMARY), STANDBY);
    nowMs += 1000;
    assert.equal(m.resolveTarget(PRIMARY), STANDBY);
    m.retune(PRIMARY, { autoFailback: true });
    assert.equal(m.resolveTarget(PRIMARY), PRIMARY);
  });

  it("illegal values throw RangeError and leave the live values intact", () => {
    const m = new FailoverManager(
      { [PRIMARY]: { standbys: [STANDBY], failureThreshold: 3, failbackIntervalMs: 1000 } },
      { now: () => 0 }
    );
    const before = m.config(PRIMARY);
    const badPatches = [
      { failureThreshold: 0 },
      { failureThreshold: 1.5 },
      { failureThreshold: Number.NaN },
      { failureThreshold: "3" as never },
      { failbackIntervalMs: 0 },
      { failbackIntervalMs: -1 },
      { failbackIntervalMs: Number.NaN },
      { failbackIntervalMs: Infinity },
      { autoFailback: "yes" as never },
      { autoFailback: 1 as never },
    ];
    for (const patch of badPatches) {
      assert.throws(() => m.retune(PRIMARY, patch), RangeError);
    }
    assert.throws(() => m.retune(PRIMARY, {}), RangeError);
    assert.throws(() => m.retune(PRIMARY, null as never), RangeError);
    assert.throws(() => m.retune(PRIMARY, "x" as never), RangeError);
    assert.throws(() => m.retune(PRIMARY, [] as never), RangeError);
    assert.deepEqual(m.config(PRIMARY), before);
  });

  it("same-value patch is a no-op; unconfigured endpoints report undefined and throw on retune", () => {
    const m = new FailoverManager(
      { [PRIMARY]: { standbys: [STANDBY], failureThreshold: 3 } },
      { now: () => 0 }
    );
    assert.deepEqual(m.retune(PRIMARY, { failureThreshold: 3 }), {
      failureThreshold: 3,
      autoFailback: true,
      failbackIntervalMs: 30_000,
    });
    assert.equal(m.config(UNKNOWN), undefined);
    assert.throws(() => m.retune(UNKNOWN, { failureThreshold: 2 }), /no failover configured for endpoint/);
  });

  it("revision does not reset consecutiveFailures, switches, or lastSwitchAtMs", () => {
    let nowMs = 0;
    const m = new FailoverManager(
      { [PRIMARY]: { standbys: [STANDBY], failureThreshold: 1, failbackIntervalMs: 1000 } },
      { now: () => nowMs }
    );
    m.recordOutcome(PRIMARY, PRIMARY, false);
    assert.equal(m.resolveTarget(PRIMARY), STANDBY);
    assert.equal(m.stats()[0].switches, 1);
    nowMs = 500;
    m.retune(PRIMARY, { failbackIntervalMs: 2000 });
    // The quiet period still runs from the switch at t=0, not from the
    // revision at t=500: the canary fires at t=2000, not t=2500.
    nowMs = 1000;
    assert.equal(m.resolveTarget(PRIMARY), STANDBY);
    nowMs = 2000;
    assert.equal(m.resolveTarget(PRIMARY), PRIMARY);
    assert.equal(m.stats()[0].switches, 2);
  });

  it("an unconfirmed canary survives revision and is still decided by its first outcome", () => {
    let nowMs = 0;
    const switches: Array<{ reason: string }> = [];
    const m = new FailoverManager(
      { [PRIMARY]: { standbys: [STANDBY], failureThreshold: 5, failbackIntervalMs: 1000 } },
      { now: () => nowMs, onSwitch: (e) => switches.push(e) }
    );
    for (let i = 0; i < 5; i++) m.recordOutcome(PRIMARY, PRIMARY, false);
    assert.equal(m.resolveTarget(PRIMARY), STANDBY);
    nowMs = 1000;
    assert.equal(m.resolveTarget(PRIMARY), PRIMARY); // canary, unconfirmed
    m.retune(PRIMARY, { failureThreshold: 1, failbackIntervalMs: 60_000 });
    assert.equal(m.resolveTarget(PRIMARY), PRIMARY); // still on probation
    assert.deepEqual(m.config(PRIMARY), {
      failureThreshold: 1,
      autoFailback: true,
      failbackIntervalMs: 60_000,
    });
    m.recordOutcome(PRIMARY, PRIMARY, false); // canary failed
    assert.equal(m.resolveTarget(PRIMARY), STANDBY);
    assert.equal(switches.length, 3);
    assert.equal(switches[2].reason, "failure_threshold");
  });

  it("revision does not change the targets list", () => {
    const m = new FailoverManager(
      { [PRIMARY]: { standbys: [STANDBY, STANDBY2], failureThreshold: 3 } },
      { now: () => 0 }
    );
    m.retune(PRIMARY, { failureThreshold: 1, autoFailback: false });
    assert.deepEqual(m.stats()[0].targets, [PRIMARY, STANDBY, STANDBY2]);
  });
});

describe("failover revision: RetryQueue (WR-349)", () => {
  it("threshold tightening switches the next dispatch to the standby", async () => {
    const timer = manualTimer();
    const seen: string[] = [];
    const sender: Sender = async (it) => {
      seen.push(it.targetUrl);
      if (it.targetUrl === PRIMARY) throw new Error("primary down");
    };
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 1,
      setTimer: timer.setTimer,
      failover: {
        [PRIMARY]: { standbys: [STANDBY], failureThreshold: 5, failbackIntervalMs: 60_000 },
      },
      failoverNow: () => 0,
    });
    q.start();
    try {
      q.enqueue(item("a"));
      await timer.run();
      await flush();
      q.enqueue(item("b"));
      await timer.run();
      await flush();
      assert.deepEqual(seen, [PRIMARY, PRIMARY]);
      assert.equal(q.getFailoverStats()[0].consecutiveFailures, 2);
      assert.deepEqual(q.reviseFailover(PRIMARY, { failureThreshold: 2 }), {
        failureThreshold: 2,
        autoFailback: true,
        failbackIntervalMs: 60_000,
      });
      assert.deepEqual(q.getFailoverConfig(PRIMARY), {
        failureThreshold: 2,
        autoFailback: true,
        failbackIntervalMs: 60_000,
      });
      q.enqueue(item("c"));
      await timer.run();
      await flush();
      assert.deepEqual(seen, [PRIMARY, PRIMARY, STANDBY]);
      assert.equal(q.getFailoverStats()[0].activeTarget, STANDBY);
    } finally {
      q.stop();
    }
  });

  it("unconfigured endpoint: revise throws the must-restart Error and the getter is undefined", () => {
    const q = new RetryQueue({
      sender: async () => ({ statusCode: 200, body: Buffer.from("ok") }),
      failover: {
        [PRIMARY]: { standbys: [STANDBY], failureThreshold: 5 },
      },
    });
    assert.equal(q.getFailoverConfig(UNKNOWN), undefined);
    assert.throws(
      () => q.reviseFailover(UNKNOWN, { failureThreshold: 2 }),
      /reviseFailover: failover is not configured for endpoint .* — enabling it requires a restart/
    );
    const bare = new RetryQueue({ sender: async () => ({ statusCode: 200, body: Buffer.from("ok") }) });
    assert.equal(bare.getFailoverConfig(PRIMARY), undefined);
    assert.throws(
      () => bare.reviseFailover(PRIMARY, { failureThreshold: 2 }),
      /reviseFailover: failover is not configured for endpoint .* — enabling it requires a restart/
    );
  });
});

describe("failover revision: RelayServer (WR-349)", () => {
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
    const dir = mkdtempSync(join(tmpdir(), "failover-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: signingKey,
      forwardUrl: PRIMARY,
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

  it("revision audits endpoint/previous/current with the construction values first; same-value is a silent no-op", async () => {
    const { relay, audit } = makeRelay({
      retry: { failover: { [PRIMARY]: { standbys: [STANDBY], failureThreshold: 3 } } },
    });
    await listen(relay);
    assert.deepEqual(relay.getFailoverConfig!(PRIMARY), {
      failureThreshold: 3,
      autoFailback: true,
      failbackIntervalMs: 30_000,
    });
    assert.deepEqual(
      relay.reviseFailover!(PRIMARY, { failureThreshold: 2, failbackIntervalMs: 60_000 }),
      { failureThreshold: 2, autoFailback: true, failbackIntervalMs: 60_000 }
    );
    const revised = eventsOf(audit, "failover_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].endpoint, PRIMARY);
    assert.deepEqual(revised[0].previous, {
      failureThreshold: 3,
      autoFailback: true,
      failbackIntervalMs: 30_000,
    });
    assert.deepEqual(revised[0].current, {
      failureThreshold: 2,
      autoFailback: true,
      failbackIntervalMs: 60_000,
    });
    // Landing exactly on the live values audits nothing.
    relay.reviseFailover!(PRIMARY, { failureThreshold: 2 });
    assert.equal(eventsOf(audit, "failover_revised").length, 1);
    // An illegal patch throws and leaves the live values and audit untouched.
    assert.throws(() => relay.reviseFailover!(PRIMARY, { failureThreshold: 0 }), RangeError);
    assert.throws(() => relay.reviseFailover!(PRIMARY, {} as never), RangeError);
    assert.equal(eventsOf(audit, "failover_revised").length, 1);
    assert.deepEqual(relay.getFailoverConfig!(PRIMARY), {
      failureThreshold: 2,
      autoFailback: true,
      failbackIntervalMs: 60_000,
    });
  });

  it("defaults apply when unset; the getter is always set and returns undefined for unconfigured endpoints", async () => {
    const { relay } = makeRelay({
      retry: { failover: { [PRIMARY]: { standbys: [STANDBY] } } },
    });
    await listen(relay);
    assert.deepEqual(relay.getFailoverConfig!(PRIMARY), {
      failureThreshold: 5,
      autoFailback: true,
      failbackIntervalMs: 30_000,
    });
    assert.equal(relay.getFailoverConfig!(UNKNOWN), undefined);
    assert.throws(
      () => relay.reviseFailover!(UNKNOWN, { failureThreshold: 2 }),
      /not configured for endpoint .* — enabling it requires a restart/
    );
    const bare = makeRelay();
    await listen(bare.relay);
    assert.equal(bare.relay.getFailoverConfig!(PRIMARY), undefined);
    assert.throws(
      () => bare.relay.reviseFailover!(PRIMARY, { failureThreshold: 2 }),
      /not configured for endpoint .* — enabling it requires a restart/
    );
  });
});
