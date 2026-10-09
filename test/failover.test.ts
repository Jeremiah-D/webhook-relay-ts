import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest } from "node:http";
import {
  RetryQueue,
  type FailoverSwitchEvent,
  type Sender,
} from "../src/retry.ts";
import { FailoverManager, assertValidFailoverConfig } from "../src/failover.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const PRIMARY = "http://127.0.0.1:9911/primary";
const STANDBY = "http://127.0.0.1:9912/standby";
const STANDBY2 = "http://127.0.0.1:9913/standby2";

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

function item(id: string, targetUrl: string = PRIMARY) {
  return { id, payload: Buffer.from("hello"), targetUrl, headers: {} };
}

describe("failover config validation", () => {
  it("accepts a minimal valid config", () => {
    assertValidFailoverConfig({ [PRIMARY]: { standbys: [STANDBY] } });
  });

  it("rejects empty standbys", () => {
    assert.throws(
      () => assertValidFailoverConfig({ [PRIMARY]: { standbys: [] } }),
      RangeError
    );
  });

  it("rejects a standby equal to the primary", () => {
    assert.throws(
      () => assertValidFailoverConfig({ [PRIMARY]: { standbys: [PRIMARY] } }),
      RangeError
    );
  });

  it("rejects duplicate standbys", () => {
    assert.throws(
      () =>
        assertValidFailoverConfig({ [PRIMARY]: { standbys: [STANDBY, STANDBY] } }),
      RangeError
    );
  });

  it("rejects chained failover (standby that is itself a primary)", () => {
    assert.throws(
      () =>
        assertValidFailoverConfig({
          [PRIMARY]: { standbys: [STANDBY] },
          [STANDBY]: { standbys: [STANDBY2] },
        }),
      RangeError
    );
  });

  it("rejects illegal thresholds and intervals", () => {
    assert.throws(
      () =>
        assertValidFailoverConfig({ [PRIMARY]: { standbys: [STANDBY], failureThreshold: 0 } }),
      RangeError
    );
    assert.throws(
      () =>
        assertValidFailoverConfig({ [PRIMARY]: { standbys: [STANDBY], failureThreshold: 1.5 } }),
      RangeError
    );
    assert.throws(
      () =>
        assertValidFailoverConfig({ [PRIMARY]: { standbys: [STANDBY], failbackIntervalMs: -1 } }),
      RangeError
    );
    assert.throws(
      () =>
        assertValidFailoverConfig({
          [PRIMARY]: { standbys: [STANDBY], autoFailback: "yes" as unknown as boolean },
        }),
      RangeError
    );
  });

  it("rejects a non-record config", () => {
    assert.throws(() => assertValidFailoverConfig([] as unknown as never), RangeError);
    assert.throws(() => assertValidFailoverConfig(null as unknown as never), RangeError);
  });

  it("throws at RetryQueue construction, not mid-delivery", () => {
    assert.throws(
      () => new RetryQueue({ failover: { [PRIMARY]: { standbys: [] } } }),
      RangeError
    );
  });
});

describe("FailoverManager", () => {
  it("resolves unconfigured endpoints to themselves", () => {
    const m = new FailoverManager({ [PRIMARY]: { standbys: [STANDBY] } });
    assert.equal(m.resolveTarget("http://unknown/hook"), "http://unknown/hook");
    assert.equal(m.resolveTarget(PRIMARY), PRIMARY);
  });

  it("switches to the standby after failureThreshold consecutive failures", () => {
    const switches: FailoverSwitchEvent[] = [];
    const m = new FailoverManager(
      { [PRIMARY]: { standbys: [STANDBY], failureThreshold: 3 } },
      { onSwitch: (e) => switches.push(e) }
    );
    m.recordOutcome(PRIMARY, PRIMARY, false);
    m.recordOutcome(PRIMARY, PRIMARY, false);
    assert.equal(m.resolveTarget(PRIMARY), PRIMARY);
    m.recordOutcome(PRIMARY, PRIMARY, false);
    assert.equal(m.resolveTarget(PRIMARY), STANDBY);
    assert.equal(switches.length, 1);
    assert.equal(switches[0].reason, "failure_threshold");
    assert.equal(switches[0].endpoint, PRIMARY);
    assert.equal(switches[0].from, PRIMARY);
    assert.equal(switches[0].to, STANDBY);
    assert.equal(switches[0].event, "failover_switched");
  });

  it("a success resets the consecutive-failure count", () => {
    const m = new FailoverManager(
      { [PRIMARY]: { standbys: [STANDBY], failureThreshold: 3 } },
      { now: () => 0 }
    );
    m.recordOutcome(PRIMARY, PRIMARY, false);
    m.recordOutcome(PRIMARY, PRIMARY, false);
    m.recordOutcome(PRIMARY, PRIMARY, true);
    m.recordOutcome(PRIMARY, PRIMARY, false);
    m.recordOutcome(PRIMARY, PRIMARY, false);
    assert.equal(m.resolveTarget(PRIMARY), PRIMARY);
    assert.equal(m.stats()[0].consecutiveFailures, 2);
  });

  it("switches immediately when the circuit is open, without waiting for the threshold", () => {
    const switches: FailoverSwitchEvent[] = [];
    const m = new FailoverManager(
      { [PRIMARY]: { standbys: [STANDBY], failureThreshold: 100 } },
      {
        circuitState: (t) => (t === PRIMARY ? "open" : "closed"),
        onSwitch: (e) => switches.push(e),
      }
    );
    assert.equal(m.resolveTarget(PRIMARY), STANDBY);
    assert.equal(switches.length, 1);
    assert.equal(switches[0].reason, "circuit_open");
  });

  it("walks ordered standbys and parks on the last when all are down", () => {
    const m = new FailoverManager(
      { [PRIMARY]: { standbys: [STANDBY, STANDBY2], failureThreshold: 1 } },
      { now: () => 0 }
    );
    m.recordOutcome(PRIMARY, PRIMARY, false);
    assert.equal(m.resolveTarget(PRIMARY), STANDBY);
    m.recordOutcome(PRIMARY, STANDBY, false);
    assert.equal(m.resolveTarget(PRIMARY), STANDBY2);
    m.recordOutcome(PRIMARY, STANDBY2, false);
    // All targets down: keep trying the last one instead of dropping.
    assert.equal(m.resolveTarget(PRIMARY), STANDBY2);
    assert.equal(m.resolveTarget(PRIMARY), STANDBY2);
    assert.equal(m.stats()[0].switches, 2);
  });

  it("ignores stale outcomes for a target we already switched away from", () => {
    const m = new FailoverManager(
      { [PRIMARY]: { standbys: [STANDBY], failureThreshold: 1 } },
      { now: () => 0 }
    );
    m.recordOutcome(PRIMARY, PRIMARY, false);
    assert.equal(m.resolveTarget(PRIMARY), STANDBY);
    // A late success for the abandoned primary must not disturb the standby.
    m.recordOutcome(PRIMARY, PRIMARY, true);
    assert.equal(m.resolveTarget(PRIMARY), STANDBY);
    assert.equal(m.stats()[0].consecutiveFailures, 0);
  });

  it("failback is a probationary canary: success keeps the primary", () => {
    let nowMs = 0;
    const switches: FailoverSwitchEvent[] = [];
    const m = new FailoverManager(
      {
        [PRIMARY]: { standbys: [STANDBY], failureThreshold: 2, failbackIntervalMs: 1000 },
      },
      { now: () => nowMs, onSwitch: (e) => switches.push(e) }
    );
    m.recordOutcome(PRIMARY, PRIMARY, false);
    m.recordOutcome(PRIMARY, PRIMARY, false);
    assert.equal(m.resolveTarget(PRIMARY), STANDBY);
    assert.equal(switches[0].reason, "failure_threshold");
    nowMs += 999;
    assert.equal(m.resolveTarget(PRIMARY), STANDBY);
    nowMs += 1;
    assert.equal(m.resolveTarget(PRIMARY), PRIMARY);
    assert.equal(switches[1].reason, "failback");
    // While the canary is unconfirmed, dispatches stay on it — no flapping.
    assert.equal(m.resolveTarget(PRIMARY), PRIMARY);
    m.recordOutcome(PRIMARY, PRIMARY, true);
    assert.equal(m.resolveTarget(PRIMARY), PRIMARY);
    // The failure count restarts fresh on the recovered primary.
    m.recordOutcome(PRIMARY, PRIMARY, false);
    assert.equal(m.resolveTarget(PRIMARY), PRIMARY);
    assert.equal(m.stats()[0].consecutiveFailures, 1);
  });

  it("a failed canary re-switches to the standby immediately", () => {
    let nowMs = 0;
    const switches: FailoverSwitchEvent[] = [];
    const m = new FailoverManager(
      {
        [PRIMARY]: { standbys: [STANDBY], failureThreshold: 5, failbackIntervalMs: 1000 },
      },
      { now: () => nowMs, onSwitch: (e) => switches.push(e) }
    );
    for (let i = 0; i < 5; i++) m.recordOutcome(PRIMARY, PRIMARY, false);
    assert.equal(m.resolveTarget(PRIMARY), STANDBY);
    nowMs += 1000;
    assert.equal(m.resolveTarget(PRIMARY), PRIMARY); // canary
    m.recordOutcome(PRIMARY, PRIMARY, false); // canary failed
    assert.equal(m.resolveTarget(PRIMARY), STANDBY);
    assert.equal(switches[switches.length - 1].reason, "failure_threshold");
    assert.equal(switches[switches.length - 1].from, PRIMARY);
    assert.equal(switches[switches.length - 1].to, STANDBY);
    // The next canary waits a full interval from the re-switch.
    nowMs += 999;
    assert.equal(m.resolveTarget(PRIMARY), STANDBY);
    nowMs += 1;
    assert.equal(m.resolveTarget(PRIMARY), PRIMARY);
  });

  it("autoFailback=false stays on the standby until a manual reset", () => {
    let nowMs = 0;
    const switches: FailoverSwitchEvent[] = [];
    const m = new FailoverManager(
      {
        [PRIMARY]: {
          standbys: [STANDBY],
          failureThreshold: 1,
          autoFailback: false,
          failbackIntervalMs: 1,
        },
      },
      { now: () => nowMs, onSwitch: (e) => switches.push(e) }
    );
    m.recordOutcome(PRIMARY, PRIMARY, false);
    assert.equal(m.resolveTarget(PRIMARY), STANDBY);
    nowMs += 1_000_000;
    assert.equal(m.resolveTarget(PRIMARY), STANDBY);
    assert.equal(m.resetFailover("http://unknown/hook"), false);
    assert.equal(m.resetFailover(PRIMARY), true);
    assert.equal(m.resolveTarget(PRIMARY), PRIMARY);
    assert.equal(switches[switches.length - 1].reason, "manual");
    assert.equal(switches[switches.length - 1].to, PRIMARY);
  });
});

describe("RetryQueue failover integration", () => {
  it("switches to the standby after threshold failures; audit hook and metrics fire", async () => {
    const timer = manualTimer();
    const seen: string[] = [];
    const switches: FailoverSwitchEvent[] = [];
    const sender: Sender = async (item) => {
      seen.push(item.targetUrl);
      if (item.targetUrl === PRIMARY) throw new Error("primary down");
    };
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 5,
      setTimer: timer.setTimer,
      failover: {
        [PRIMARY]: { standbys: [STANDBY], failureThreshold: 2, failbackIntervalMs: 60_000 },
      },
      failoverNow: () => 0,
      onFailoverSwitch: (e) => switches.push(e),
    });
    q.start();
    q.enqueue(item("a"));
    await timer.run();
    assert.deepEqual(seen, [PRIMARY, PRIMARY, STANDBY]);
    assert.equal(switches.length, 1);
    assert.equal(switches[0].reason, "failure_threshold");
    assert.equal(switches[0].endpoint, PRIMARY);
    assert.equal(switches[0].from, PRIMARY);
    assert.equal(switches[0].to, STANDBY);
    const stats = q.getFailoverStats();
    assert.equal(stats.length, 1);
    assert.equal(stats[0].activeTarget, STANDBY);
    assert.equal(stats[0].switches, 1);
    const exposition = q.renderMetrics();
    assert.match(
      exposition,
      new RegExp(
        `relay_failover_switches_total\\{endpoint="${PRIMARY}",from="${PRIMARY}",to="${STANDBY}"\\} 1`
      )
    );
    q.stop();
  });

  it("switches on circuit-open even when the failure threshold is unreachable", async () => {
    const timer = manualTimer();
    const seen: string[] = [];
    const switches: FailoverSwitchEvent[] = [];
    const sender: Sender = async (item) => {
      seen.push(item.targetUrl);
      if (item.targetUrl === PRIMARY) throw new Error("primary down");
    };
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 5,
      circuitBreaker: { failureThreshold: 2, cooldownMs: 60_000 },
      setTimer: timer.setTimer,
      failover: {
        [PRIMARY]: { standbys: [STANDBY], failureThreshold: 100, failbackIntervalMs: 60_000 },
      },
      failoverNow: () => 0,
      onFailoverSwitch: (e) => switches.push(e),
    });
    q.start();
    q.enqueue(item("a"));
    await timer.run();
    assert.deepEqual(seen, [PRIMARY, PRIMARY, STANDBY]);
    assert.equal(switches.length, 1);
    assert.equal(switches[0].reason, "circuit_open");
    q.stop();
  });

  it("in-flight deliveries keep the target they were dispatched with", async () => {
    const timer = manualTimer();
    const seen: string[] = [];
    const delivered: Array<{ id: string; target: string }> = [];
    let releasePrimary!: () => void;
    const primaryGate = new Promise<void>((resolve) => {
      releasePrimary = resolve;
    });
    const sender: Sender = async (item) => {
      seen.push(item.targetUrl);
      if (item.id === "in-flight") await primaryGate;
      else if (item.targetUrl === PRIMARY) throw new Error("primary down");
    };
    const switches: FailoverSwitchEvent[] = [];
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 5,
      setTimer: timer.setTimer,
      failover: {
        [PRIMARY]: { standbys: [STANDBY], failureThreshold: 2, failbackIntervalMs: 60_000 },
      },
      failoverNow: () => 0,
      onFailoverSwitch: (e) => switches.push(e),
      onDelivered: (it) => delivered.push({ id: it.id, target: it.targetUrl }),
    });
    q.start();
    q.enqueue(item("in-flight"));
    q.enqueue(item("driver"));
    // Drive the "driver" item through two primary failures while the
    // in-flight delivery is still hanging on the primary.
    await timer.run();
    assert.equal(switches.length, 1, "the switch fired while the first delivery was in flight");
    assert.ok(
      !delivered.some((d) => d.id === "in-flight"),
      "the in-flight delivery has not finished yet"
    );
    releasePrimary();
    // Let the in-flight delivery's promise chain settle (microtasks drain
    // before the next macrotask).
    await new Promise((r) => setImmediate(r));
    await timer.run();
    assert.ok(
      seen.filter((t) => t === PRIMARY).length >= 3,
      `in-flight delivery went to the primary: ${JSON.stringify(seen)}`
    );
    assert.equal(seen[seen.length - 1], STANDBY);
    assert.ok(
      delivered.some((d) => d.id === "in-flight" && d.target === PRIMARY),
      `in-flight delivery completed against the primary: ${JSON.stringify(delivered)}`
    );
    q.stop();
  });

  it("dead letters record the physical target; replays re-resolve the logical endpoint", async () => {
    const timer = manualTimer();
    const seen: string[] = [];
    const sender: Sender = async (item) => {
      seen.push(item.targetUrl);
      throw new Error(`down: ${item.targetUrl}`);
    };
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 2,
      setTimer: timer.setTimer,
      failover: {
        [PRIMARY]: { standbys: [STANDBY], failureThreshold: 1, failbackIntervalMs: 60_000 },
      },
      failoverNow: () => 0,
    });
    q.start();
    q.enqueue(item("a"));
    await timer.run();
    assert.deepEqual(seen, [PRIMARY, STANDBY]);
    const dl = q.getDeadLetter();
    assert.equal(dl.length, 1);
    assert.equal(dl[0].targetUrl, STANDBY);
    assert.equal(dl[0].failoverEndpoint, PRIMARY);
    // Manual reset moves traffic back; the replay must follow the current
    // active target, not pin to the standby that served the dead letter.
    assert.equal(q.resetFailover(PRIMARY), true);
    seen.length = 0;
    assert.equal(q.replayDeadLetter("a"), true);
    await timer.run();
    assert.deepEqual(seen, [PRIMARY, STANDBY]);
    q.stop();
  });

  it("the primary's response validator still applies on the standby", async () => {
    const timer = manualTimer();
    const sender: Sender = async () => ({
      statusCode: 200,
      body: Buffer.from(JSON.stringify({ ok: true })),
      truncated: false,
    });
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 2,
      setTimer: timer.setTimer,
      responseValidators: { [PRIMARY]: () => false },
      failover: {
        [PRIMARY]: { standbys: [STANDBY], failureThreshold: 1, failbackIntervalMs: 60_000 },
      },
      failoverNow: () => 0,
    });
    q.start();
    q.enqueue(item("a"));
    await timer.run();
    // Attempt 1 (primary): transport ok, validator rejects -> semantic
    // failure. Attempt 2 (standby): without validator fallback the 200
    // would succeed; with it the semantic failure repeats -> dead letter.
    const dl = q.getDeadLetter();
    assert.equal(dl.length, 1);
    assert.equal(dl[0].targetUrl, STANDBY);
    q.stop();
  });

  it("failback canary through the queue: failure re-switches immediately", async () => {
    const timer = manualTimer();
    let nowMs = 0;
    const seen: string[] = [];
    const switches: FailoverSwitchEvent[] = [];
    const sender: Sender = async (item) => {
      seen.push(item.targetUrl);
      if (item.targetUrl === PRIMARY) throw new Error("primary down");
    };
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 3,
      setTimer: timer.setTimer,
      failover: {
        [PRIMARY]: { standbys: [STANDBY], failureThreshold: 1, failbackIntervalMs: 1000 },
      },
      failoverNow: () => nowMs,
      onFailoverSwitch: (e) => switches.push(e),
    });
    q.start();
    q.enqueue(item("one"));
    await timer.run();
    assert.deepEqual(seen, [PRIMARY, STANDBY]);
    assert.equal(q.getFailoverStats()[0].activeTarget, STANDBY);
    // Quiet period passes: the next item probes the primary (canary).
    nowMs += 1000;
    q.enqueue(item("two"));
    await timer.run();
    assert.deepEqual(seen, [PRIMARY, STANDBY, PRIMARY, STANDBY]);
    assert.deepEqual(
      switches.map((s) => s.reason),
      ["failure_threshold", "failback", "failure_threshold"]
    );
    assert.equal(q.getFailoverStats()[0].activeTarget, STANDBY);
    q.stop();
  });

  it("without failover config nothing changes: hooks see the queued target", async () => {
    const timer = manualTimer();
    const seen: string[] = [];
    const q = new RetryQueue({
      sender: async (item) => {
        seen.push(item.targetUrl);
      },
      baseDelayMs: 10,
      maxDelayMs: 10,
      jitterMs: 0,
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue(item("a"));
    await timer.run();
    assert.deepEqual(seen, [PRIMARY]);
    assert.deepEqual(q.getFailoverStats(), []);
    assert.ok(!q.renderMetrics().includes("relay_failover_switches_total"));
    q.stop();
  });
});

describe("failover server wiring", () => {
  it("audits failover_switched through the relay server", async () => {
    const dir = mkdtempSync(join(tmpdir(), "failover-audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const secret = "test-secret";
    const payload = Buffer.from(JSON.stringify({ n: 1 }));
    const server = createRelayServer({
      secret,
      forwardUrl: PRIMARY,
      auditLog: audit,
      sender: async (item) => {
        if (item.targetUrl === PRIMARY) throw new Error("primary down");
      },
      retry: {
        baseDelayMs: 5,
        maxDelayMs: 5,
        jitterMs: 0,
        maxAttempts: 2,
        failover: {
          [PRIMARY]: { standbys: [STANDBY], failureThreshold: 1, failbackIntervalMs: 60_000 },
        },
        failoverNow: () => 0,
      },
    });
    await new Promise<void>((resolve) => server.listen(0, resolve));
    const port = (server.address() as { port: number }).port;
    try {
      const post = () =>
        new Promise<number>((resolve, reject) => {
          const req = httpRequest(
            {
              port,
              method: "POST",
              path: "/hook",
              headers: {
                "content-type": "application/json",
                "x-signature": signSha256(payload, secret),
              },
            },
            (res) => {
              res.resume();
              res.on("end", () => resolve(res.statusCode ?? 0));
            }
          );
          req.on("error", reject);
          req.end(payload);
        });
      assert.equal(await post(), 202);
      // Let the two delivery attempts (primary fail -> standby fail ->
      // dead letter) run on real timers.
      await new Promise((r) => setTimeout(r, 300));
      const events = audit.readAll() as Array<Record<string, unknown>>;
      const switched = events.filter((e) => e.event === "failover_switched");
      assert.equal(switched.length, 1);
      assert.equal(switched[0].endpoint, PRIMARY);
      assert.equal(switched[0].from, PRIMARY);
      assert.equal(switched[0].to, STANDBY);
      assert.equal(switched[0].reason, "failure_threshold");
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
