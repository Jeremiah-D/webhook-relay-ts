import { describe, it, before, after } from "node:test";
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
import { RetryQueue } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

const EP = "http://127.0.0.1:9/health";

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

describe("DownstreamProber", () => {
  it("rejects invalid configs at startup", () => {
    const noop = () => {};
    assert.throws(() => new DownstreamProber({ endpoints: [], recordOutcome: noop }), RangeError);
    assert.throws(
      () => new DownstreamProber({ endpoints: [EP, EP], recordOutcome: noop }),
      RangeError
    );
    assert.throws(
      () => new DownstreamProber({ endpoints: [""], recordOutcome: noop }),
      RangeError
    );
    assert.throws(
      () => new DownstreamProber({ endpoints: [EP], intervalMs: 0, recordOutcome: noop }),
      RangeError
    );
    assert.throws(
      () =>
        new DownstreamProber({
          endpoints: [EP],
          method: "POST" as "HEAD",
          recordOutcome: noop,
        }),
      RangeError
    );
    assert.throws(
      () => new DownstreamProber({ endpoints: [EP], timeoutMs: -1, recordOutcome: noop }),
      RangeError
    );
  });

  it("audits every failure with the streak and recovery exactly once", async () => {
    const outcomes: [string, boolean][] = [];
    const audits: ProbeAuditEvent[] = [];
    let healthy = false;
    const prober = new DownstreamProber({
      endpoints: [EP],
      probeRequest: async () => healthy,
      recordOutcome: (endpoint, ok) => outcomes.push([endpoint, ok]),
      onAudit: (e) => audits.push(e),
    });
    await prober.runRound();
    await prober.runRound();
    await prober.runRound();
    assert.deepEqual(outcomes, [
      [EP, false],
      [EP, false],
      [EP, false],
    ]);
    assert.deepEqual(audits, [
      { event: "probe_failed", endpoint: EP, consecutiveFailures: 1 },
      { event: "probe_failed", endpoint: EP, consecutiveFailures: 2 },
      { event: "probe_failed", endpoint: EP, consecutiveFailures: 3 },
    ]);
    let s = prober.stats()[0];
    assert.equal(s.failure, 3);
    assert.equal(s.consecutiveFailures, 3);

    healthy = true;
    await prober.runRound();
    // Recovery is audited once; steady-state healthy probes stay quiet.
    assert.deepEqual(audits.slice(3), [{ event: "probe_recovered", endpoint: EP }]);
    await prober.runRound();
    assert.equal(audits.length, 4);
    s = prober.stats()[0];
    assert.equal(s.success, 2);
    assert.equal(s.consecutiveFailures, 0);
  });

  it("treats a throwing probe implementation as a failure, never a crash", async () => {
    const audits: ProbeAuditEvent[] = [];
    const prober = new DownstreamProber({
      endpoints: [EP],
      probeRequest: async () => {
        throw new Error("boom");
      },
      recordOutcome: () => {},
      onAudit: (e) => audits.push(e),
    });
    const results = await prober.runRound();
    assert.deepEqual(results, [{ endpoint: EP, ok: false }]);
    assert.equal(audits.length, 1);
    assert.equal(prober.stats()[0].consecutiveFailures, 1);
  });

  it("rejects unknown endpoints in runRound", async () => {
    const prober = new DownstreamProber({
      endpoints: [EP],
      probeRequest: async () => true,
      recordOutcome: () => {},
    });
    await assert.rejects(prober.runRound("http://unknown/"), RangeError);
  });

  it("schedules one timer per endpoint on start and clears them on stop", () => {
    const t = manualTimers();
    const prober = new DownstreamProber({
      endpoints: [EP, "http://127.0.0.1:9/other"],
      intervalMs: 1000,
      probeRequest: async () => true,
      recordOutcome: () => {},
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
    });
    prober.start();
    assert.equal(t.scheduled.length, 2);
    assert.ok(t.scheduled.every((s) => s.ms === 1000 && !s.cleared));
    prober.stop();
    assert.ok(t.scheduled.every((s) => s.cleared));
    // Idempotent: starting twice does not double-schedule.
    prober.start();
    prober.start();
    assert.equal(
      t.scheduled.filter((s) => !s.cleared).length,
      2
    );
    prober.stop();
  });

  it("default probeRequest: HEAD 200 is healthy, refused connection is not", async () => {
    const stub = createServer((req, res) => {
      assert.equal(req.method, "HEAD");
      res.writeHead(200).end();
    });
    const port = await listen(stub);
    const url = `http://127.0.0.1:${port}/healthz`;
    try {
      const prober = new DownstreamProber({
        endpoints: [url],
        timeoutMs: 2000,
        recordOutcome: () => {},
      });
      assert.deepEqual(await prober.runRound(), [{ endpoint: url, ok: true }]);
    } finally {
      stub.close();
      await new Promise((r) => stub.once("close", r));
    }
    // Port is closed now: connection refused → failure, no throw.
    const deadUrl = `http://127.0.0.1:${port}/healthz`;
    const dead = new DownstreamProber({
      endpoints: [deadUrl],
      timeoutMs: 2000,
      recordOutcome: () => {},
    });
    assert.deepEqual(await dead.runRound(), [{ endpoint: deadUrl, ok: false }]);
  });
});

describe("RetryQueue downstream-probe integration", () => {
  it("probe failures trip the circuit breaker early", async () => {
    const audits: ProbeAuditEvent[] = [];
    const transitions: string[] = [];
    const q = new RetryQueue({
      sender: async () => {},
      circuitBreaker: { failureThreshold: 3, cooldownMs: 60_000 },
      probe: {
        endpoints: [EP],
        intervalMs: 60_000, // manual rounds only; no timer noise
        probeRequest: async () => false,
      },
      onProbeAudit: (e) => audits.push(e),
      onCircuitStateChange: (endpoint, from, to) => transitions.push(`${from}->${to}`),
    });
    const prober = q.getProber();
    assert.ok(prober);
    await prober!.runRound();
    await prober!.runRound();
    // Not tripped yet at 2 consecutive failures.
    assert.deepEqual(
      q.getCircuitStats().map((s) => s.state),
      ["closed"]
    );
    await prober!.runRound();
    // Third consecutive probe failure trips the breaker — before any
    // real delivery had to fail.
    const stats = q.getCircuitStats();
    assert.equal(stats.length, 1);
    assert.equal(stats[0].endpoint, EP);
    assert.equal(stats[0].state, "open");
    assert.equal(stats[0].consecutiveFailures, 3);
    assert.deepEqual(transitions, ["closed->open"]);
    assert.equal(audits.filter((e) => e.event === "probe_failed").length, 3);
    // Probe outcomes are observable.
    const probeStats = q.getProbeStats();
    assert.equal(probeStats.length, 1);
    assert.equal(probeStats[0].endpoint, EP);
    assert.equal(probeStats[0].success, 0);
    assert.equal(probeStats[0].failure, 3);
    assert.equal(probeStats[0].consecutiveFailures, 3);
    assert.ok(typeof probeStats[0].lastProbeAtMs === "number");
    q.stop();
  });

  it("a successful probe resets the breaker counter like any success", async () => {
    let healthy = false;
    const q = new RetryQueue({
      sender: async () => {},
      circuitBreaker: { failureThreshold: 3, cooldownMs: 60_000 },
      probe: {
        endpoints: [EP],
        probeRequest: async () => healthy,
      },
    });
    const prober = q.getProber()!;
    await prober.runRound();
    await prober.runRound();
    assert.equal(q.getCircuitStats()[0].consecutiveFailures, 2);
    healthy = true;
    await prober.runRound();
    assert.equal(q.getCircuitStats()[0].consecutiveFailures, 0);
    assert.equal(q.getCircuitStats()[0].state, "closed");
    q.stop();
  });

  it("renders relay_probe_* series in the Prometheus exposition", async () => {
    const q = new RetryQueue({
      sender: async () => {},
      probe: { endpoints: [EP], probeRequest: async () => false },
    });
    await q.getProber()!.runRound();
    await q.getProber()!.runRound();
    const text = q.renderMetrics();
    assert.match(
      text,
      new RegExp(`relay_probe_total\\{endpoint="${EP}",result="success"\\} 0`)
    );
    assert.match(
      text,
      new RegExp(`relay_probe_total\\{endpoint="${EP}",result="failure"\\} 2`)
    );
    assert.match(
      text,
      new RegExp(`relay_probe_consecutive_failures\\{endpoint="${EP}"\\} 2`)
    );
    q.stop();
  });

  it("emits no probe series when probing is disabled", () => {
    const q = new RetryQueue({ sender: async () => {} });
    assert.equal(q.getProber(), undefined);
    assert.deepEqual(q.getProbeStats(), []);
    assert.ok(!q.renderMetrics().includes("relay_probe_"));
    q.stop();
  });
});

describe("server downstream health probing", () => {
  async function waitFor(
    audit: AuditLog,
    event: string,
    min: number,
    timeoutMs = 5000
  ): Promise<{ event: string }[]> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const found = audit.query({ event: [event] }) as { event: string }[];
      if (found.length >= min) return found;
      if (Date.now() >= deadline) throw new Error(`timed out waiting for ${min}x ${event}`);
      await new Promise((r) => setTimeout(r, 25));
    }
  }

  it("audits probe failures and trips the circuit from probes alone", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: "s",
      forwardUrl: "http://127.0.0.1:9/hook",
      auditLog: audit,
      retry: {
        circuitBreaker: { failureThreshold: 3, cooldownMs: 60_000 },
        probe: {
          endpoints: ["http://127.0.0.1:9/hook"],
          intervalMs: 50,
          probeRequest: async () => false,
        },
      },
    });
    await listen(relay);
    try {
      const failed = await waitFor(audit, "probe_failed", 3);
      assert.ok(failed.length >= 3);
      const streaks = (failed as { consecutiveFailures: number }[]).map(
        (e) => e.consecutiveFailures
      );
      assert.deepEqual(streaks.slice(0, 3), [1, 2, 3]);
      // The breaker tripped on probe failures alone — no delivery traffic.
      const opened = await waitFor(audit, "circuit_open", 1);
      assert.equal(
        (opened[0] as { endpoint: string }).endpoint,
        "http://127.0.0.1:9/hook"
      );
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("audits probe_recovered when the endpoint answers again", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    let calls = 0;
    const relay = createRelayServer({
      secret: "s",
      forwardUrl: "http://127.0.0.1:9/hook",
      auditLog: audit,
      retry: {
        probe: {
          endpoints: ["http://127.0.0.1:9/hook"],
          intervalMs: 50,
          probeRequest: async () => ++calls > 2,
        },
      },
    });
    await listen(relay);
    try {
      const recovered = await waitFor(audit, "probe_recovered", 1);
      assert.equal(recovered.length, 1);
      const failed = audit.query({ event: ["probe_failed"] });
      assert.equal(failed.length, 2);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });
});
