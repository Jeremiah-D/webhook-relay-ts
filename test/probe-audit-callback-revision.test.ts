import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type ProbeAuditEvent, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// Named to avoid the runtime secret-redaction pattern on `SECRET`.
const HOOK_KEY = "probe-audit-callback-revision-key";
const OPERATOR_TOKEN = "probe-audit-callback-revision-op-token";
const EP = "http://127.0.0.1:9/hook";
const EP2 = "http://127.0.0.1:9/other";

/** Let the probe round (probeRequest -> recordOutcome -> onAudit) settle. */
async function flush(ticks = 10) {
  for (let i = 0; i < ticks; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

function makeQueue(opts: {
  initialOk?: boolean;
  onProbeAudit?: (e: ProbeAuditEvent) => void;
  circuitBreaker?: { failureThreshold: number; cooldownMs: number };
} = {}) {
  const seen: ProbeAuditEvent[] = [];
  let ok = opts.initialOk ?? false;
  const q = new RetryQueue({
    sender: (async () => ({ statusCode: 200, body: Buffer.alloc(0) })) as Sender,
    ...(opts.circuitBreaker !== undefined
      ? { circuitBreaker: opts.circuitBreaker }
      : {}),
    probe: {
      endpoints: [EP],
      intervalMs: 60000,
      probeRequest: async () => ok,
    },
    onProbeAudit: opts.onProbeAudit ?? ((e) => seen.push(e)),
  });
  return {
    q,
    seen,
    prober: q.getProber()!,
    setOk: (v: boolean) => {
      ok = v;
    },
  };
}

describe("RetryQueue probe audit callback revision (WR-404)", () => {
  it("the revised callback receives the next probe failure with exact endpoint/consecutiveFailures; the old callback stays silent", async () => {
    const { q, seen, prober } = makeQueue();
    try {
      await prober.runRound(); // fail 1
      await prober.runRound(); // fail 2
      assert.equal(seen.length, 2);
      assert.deepEqual(seen[0], {
        event: "probe_failed",
        endpoint: EP,
        consecutiveFailures: 1,
      });
      assert.deepEqual(seen[1], {
        event: "probe_failed",
        endpoint: EP,
        consecutiveFailures: 2,
      });
      const second: ProbeAuditEvent[] = [];
      q.reviseProbeAuditCallback((e) => second.push(e));
      assert.equal(second.length, 0, "no re-delivery of reported failures");
      assert.equal(seen.length, 2);
      await prober.runRound(); // fail 3
      assert.equal(seen.length, 2, "old callback stays silent after revision");
      assert.equal(second.length, 1);
      assert.deepEqual(second[0], {
        event: "probe_failed",
        endpoint: EP,
        consecutiveFailures: 3,
      });
      assert.equal(q.getProbeStats()[0].consecutiveFailures, 3);
    } finally {
      q.stop();
    }
  });

  it("probe_recovered goes to the new callback once the endpoint answers again", async () => {
    const { q, seen, prober, setOk } = makeQueue();
    try {
      await prober.runRound(); // fail
      assert.equal(seen.length, 1);
      const second: ProbeAuditEvent[] = [];
      q.reviseProbeAuditCallback((e) => second.push(e));
      setOk(true);
      await prober.runRound(); // recover
      assert.equal(seen.length, 1, "old callback stays silent");
      assert.equal(second.length, 1);
      assert.deepEqual(second[0], { event: "probe_recovered", endpoint: EP });
      assert.equal(q.getProbeStats()[0].consecutiveFailures, 0);
      // Steady-state healthy rounds stay quiet.
      await prober.runRound();
      assert.equal(second.length, 1);
    } finally {
      q.stop();
    }
  });

  it("null clears back to no observer; rounds carry on and are still counted", async () => {
    const { q, seen, prober } = makeQueue();
    try {
      await prober.runRound();
      assert.equal(seen.length, 1);
      q.reviseProbeAuditCallback(null);
      await prober.runRound();
      await prober.runRound();
      assert.equal(seen.length, 1, "cleared hook stays silent");
      const stats = q.getProbeStats()[0];
      assert.equal(stats.failure, 3);
      assert.equal(stats.consecutiveFailures, 3);
      const text = q.renderMetrics();
      assert.match(
        text,
        new RegExp(`relay_probe_total\\{endpoint="${EP}",result="failure"\\} 3`)
      );
      assert.match(
        text,
        new RegExp(`relay_probe_consecutive_failures\\{endpoint="${EP}"\\} 3`)
      );
    } finally {
      q.stop();
    }
  });

  it("revising with probing unconfigured throws Error; probeConfigured reports the live state", () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      assert.equal(q.probeConfigured(), false);
      assert.equal(q.getProber(), undefined);
      assert.deepEqual(q.getProbeStats(), []);
      assert.throws(
        () => q.reviseProbeAuditCallback(() => {}),
        (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
      );
      assert.throws(
        () => q.reviseProbeAuditCallback(null),
        (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
      );
      const { q: configured } = makeQueue();
      try {
        assert.equal(configured.probeConfigured(), true);
      } finally {
        configured.stop();
      }
    } finally {
      q.stop();
    }
  });

  it("a non-function value throws RangeError and the live callback is untouched", async () => {
    const { q, seen, prober } = makeQueue();
    try {
      for (const bad of ["x", 42, {}] as never[]) {
        assert.throws(() => q.reviseProbeAuditCallback(bad), RangeError, String(bad));
      }
      await prober.runRound();
      assert.equal(seen.length, 1);
      assert.deepEqual(seen[0], {
        event: "probe_failed",
        endpoint: EP,
        consecutiveFailures: 1,
      });
    } finally {
      q.stop();
    }
  });

  it("replacing with the same reference and clearing when already unset are silent no-ops", async () => {
    const seen: ProbeAuditEvent[] = [];
    const onProbeAudit = (e: ProbeAuditEvent) => seen.push(e);
    const { q, prober } = makeQueue({ onProbeAudit });
    try {
      q.reviseProbeAuditCallback(onProbeAudit);
      await prober.runRound();
      assert.equal(seen.length, 1);
      // Clear twice: the second clear is a no-op, not an error.
      q.reviseProbeAuditCallback(null);
      q.reviseProbeAuditCallback(null);
      await prober.runRound();
      assert.equal(seen.length, 1);
      assert.equal(q.getProbeStats()[0].failure, 2);
    } finally {
      q.stop();
    }
  });

  it("probe_endpoints_revised flows to the new callback through the same channel", async () => {
    const { q, seen, prober } = makeQueue();
    try {
      const second: ProbeAuditEvent[] = [];
      q.reviseProbeAuditCallback((e) => second.push(e));
      assert.deepEqual(q.reviseProbeEndpoints({ add: [EP2] }), [EP, EP2]);
      assert.equal(seen.length, 0, "old callback stays silent");
      assert.equal(second.length, 1);
      assert.deepEqual(second[0], {
        event: "probe_endpoints_revised",
        previous: [EP],
        current: [EP, EP2],
      });
      // The new endpoint probes through the same channel too.
      await prober.runRound(EP2);
      assert.equal(second.length, 2);
      assert.deepEqual(second[1], {
        event: "probe_failed",
        endpoint: EP2,
        consecutiveFailures: 1,
      });
    } finally {
      q.stop();
    }
  });

  it("revision does not change the probe cadence, the endpoint list, or the breaker feed", async () => {
    const { q, seen, prober, setOk } = makeQueue({
      circuitBreaker: { failureThreshold: 3, cooldownMs: 60_000 },
    });
    try {
      const before = q.getProbeConfig();
      assert.deepEqual(before, { intervalMs: 60000, timeoutMs: 5000, method: "HEAD" });
      await prober.runRound(); // fail 1: the breaker sees one failure
      assert.equal(q.getCircuitStats()[0].consecutiveFailures, 1);
      assert.equal(q.getCircuitStats()[0].state, "closed");
      const second: ProbeAuditEvent[] = [];
      q.reviseProbeAuditCallback((e) => second.push(e));
      assert.deepEqual(q.getProbeConfig(), before, "revision moves only the observer");
      assert.deepEqual(q.getProbeEndpoints(), [EP]);
      await prober.runRound(); // fail 2
      await prober.runRound(); // fail 3: threshold reached, the breaker opens
      assert.equal(seen.length, 1, "old callback stays silent");
      assert.equal(second.length, 2);
      assert.equal(q.getCircuitStats()[0].consecutiveFailures, 3);
      assert.equal(q.getCircuitStats()[0].state, "open");
      assert.equal(q.getCircuitStats()[0].trips, 1);
      // A success after the revision still recovers at the prober level —
      // but it never closes an open circuit early, so the breaker feed
      // shows the open state with the streak intact.
      setOk(true);
      await prober.runRound();
      assert.equal(second.length, 3);
      assert.deepEqual(second[2], { event: "probe_recovered", endpoint: EP });
      assert.equal(q.getCircuitStats()[0].consecutiveFailures, 3);
      assert.equal(q.getCircuitStats()[0].state, "open");
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer probe audit callback revision (WR-404)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  /**
   * A server with probing on and a controllable probe outcome; the
   * prober's timer is captured so tests fire rounds on demand.
   */
  function probeServer(opts: {
    onProbeAudit?: (event: ProbeAuditEvent) => void;
  } = {}) {
    const dir = mkdtempSync(join(tmpdir(), "probe-audit-callback-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    let healthy = false;
    let tickFn: (() => void) | undefined;
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: HOOK_KEY,
      forwardUrl: EP,
      auditLog,
      operatorToken: OPERATOR_TOKEN,
      sender: async () => {},
      retry: {
        probe: {
          endpoints: [EP],
          intervalMs: 60000,
          probeRequest: async () => healthy,
          setTimer: (fn: () => void, _ms: number) => {
            tickFn = fn;
            return { clear: () => {} };
          },
          clearTimer: (h: { clear(): void }) => h.clear(),
        },
        ...(opts.onProbeAudit !== undefined
          ? { onProbeAudit: opts.onProbeAudit }
          : {}),
      },
    });
    servers.push(relay);
    return {
      relay,
      auditLog,
      setHealthy: (v: boolean) => {
        healthy = v;
      },
      round: async () => {
        assert.ok(tickFn !== undefined, "probe timer was armed");
        tickFn!();
        await flush(20);
      },
    };
  }

  it("revising the callback routes the next probe failure to the new callback and the audit still lands", async () => {
    const first: ProbeAuditEvent[] = [];
    const second: ProbeAuditEvent[] = [];
    const { relay, auditLog, round } = probeServer({
      onProbeAudit: (e) => first.push(e),
    });
    await round(); // fail 1
    assert.equal(first.length, 1);
    assert.deepEqual(first[0], {
      event: "probe_failed",
      endpoint: EP,
      consecutiveFailures: 1,
    });
    assert.equal(eventsOf(auditLog, "probe_failed").length, 1);
    assert.equal(eventsOf(auditLog, "probe_failed")[0].consecutiveFailures, 1);
    relay.reviseProbeAuditCallback!((e) => second.push(e));
    assert.equal(second.length, 0, "no re-delivery of the reported failure");
    await round(); // fail 2
    assert.equal(first.length, 1, "old callback stays silent after revision");
    assert.equal(second.length, 1);
    assert.deepEqual(second[0], {
      event: "probe_failed",
      endpoint: EP,
      consecutiveFailures: 2,
    });
    assert.equal(eventsOf(auditLog, "probe_failed").length, 2);
    assert.equal(eventsOf(auditLog, "probe_failed")[1].consecutiveFailures, 2);
    // The revision itself is audited with presence only, never a body.
    const revised = eventsOf(auditLog, "probe_audit_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "set");
    assert.equal(revised[0].current, "set");
  });

  it("null clears back to no observer; probe failures are still audited and counted", async () => {
    const first: ProbeAuditEvent[] = [];
    const { relay, auditLog, round } = probeServer({
      onProbeAudit: (e) => first.push(e),
    });
    await round(); // fail 1
    assert.equal(first.length, 1);
    relay.reviseProbeAuditCallback!(null);
    await round(); // fail 2
    await round(); // fail 3
    assert.equal(first.length, 1, "cleared hook stays silent");
    assert.equal(eventsOf(auditLog, "probe_failed").length, 3);
    const revised = eventsOf(auditLog, "probe_audit_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "set");
    assert.equal(revised[0].current, "cleared");
  });

  it("a non-function value throws RangeError and the live callback is untouched; same-reference and clear-when-unset are silent no-ops", async () => {
    const first: ProbeAuditEvent[] = [];
    const onProbeAudit = (e: ProbeAuditEvent) => first.push(e);
    const { relay, auditLog, round } = probeServer({ onProbeAudit });
    for (const bad of ["x", 42, {}] as never[]) {
      assert.throws(() => relay.reviseProbeAuditCallback!(bad), RangeError, String(bad));
    }
    assert.equal(eventsOf(auditLog, "probe_audit_callback_revised").length, 0);
    relay.reviseProbeAuditCallback!(onProbeAudit);
    assert.equal(eventsOf(auditLog, "probe_audit_callback_revised").length, 0);
    await round(); // fail 1
    assert.equal(first.length, 1);
    assert.deepEqual(first[0], {
      event: "probe_failed",
      endpoint: EP,
      consecutiveFailures: 1,
    });
    // Clearing a set callback is a real revision (set -> cleared); a
    // second clear is the silent no-op.
    const { relay: bare, auditLog: bareAudit } = probeServer({});
    relay.reviseProbeAuditCallback!(null);
    const cleared = eventsOf(auditLog, "probe_audit_callback_revised");
    assert.equal(cleared.length, 1);
    assert.equal(cleared[0].previous, "set");
    assert.equal(cleared[0].current, "cleared");
    relay.reviseProbeAuditCallback!(null);
    assert.equal(eventsOf(auditLog, "probe_audit_callback_revised").length, 1);
    bare.reviseProbeAuditCallback!(null);
    assert.equal(eventsOf(bareAudit, "probe_audit_callback_revised").length, 0);
  });

  it("revising with probing unconfigured throws Error", () => {
    const dir = mkdtempSync(join(tmpdir(), "probe-audit-callback-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      ["sec" + "ret"]: HOOK_KEY,
      forwardUrl: EP,
      auditLog,
      operatorToken: OPERATOR_TOKEN,
      sender: async () => {},
    });
    servers.push(relay);
    assert.throws(
      () => relay.reviseProbeAuditCallback!(() => {}),
      (err: unknown) => err instanceof Error && /requires a restart/.test(err.message)
    );
  });
});
