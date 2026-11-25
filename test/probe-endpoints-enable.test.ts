import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  type ProbeAuditEvent,
  type Sender,
} from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "probe-endpoints-enable-test-key";
const opToken = "probe-endpoints-enable-op-token";
// Port 9 refuses connections: the default probe request fails fast and
// deterministically, with no stubbed probeRequest (the enable path takes
// the construction defaults, including the real HEAD prober).
const EP_FAIL = "http://127.0.0.1:9/health";
const EP2 = "http://127.0.0.1:9/other";
const EP3 = "http://127.0.0.1:9/third";
const DEFAULT_CONFIG = { intervalMs: 30000, timeoutMs: 5000, method: "HEAD" } as const;

const okSender: Sender = async () => ({ statusCode: 200, body: Buffer.alloc(0) });

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Poll until `check()` is true (or time out with a readable message). */
async function waitFor(check: () => boolean, what: string, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (check()) return;
    if (Date.now() >= deadline) throw new Error(`timed out waiting for ${what}`);
    await sleep(25);
  }
}

/** A toggleable downstream: 200 while healthy, 500 while not. */
function toggleServer() {
  let healthy = false;
  const server = createServer((_req, res) => {
    res.writeHead(healthy ? 200 : 500);
    res.end("ok");
  });
  return {
    server,
    setHealthy(v: boolean) {
      healthy = v;
    },
    async url(): Promise<string> {
      const port = await new Promise<number>((resolve) => {
        server.listen(0, "127.0.0.1", () => {
          const addr = server.address();
          assert.ok(addr && typeof addr === "object");
          resolve(addr.port);
        });
      });
      return `http://127.0.0.1:${port}/health`;
    },
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

describe("RetryQueue downstream probe live enable (WR-466)", () => {
  it("first enable returns the list; getters report the list plus the construction defaults", () => {
    const q = new RetryQueue({ sender: okSender });
    try {
      assert.equal(q.probeConfigured(), false);
      assert.equal(q.getProbeEndpoints(), undefined);
      assert.equal(q.getProbeConfig(), undefined);
      assert.equal(q.getProber(), undefined);
      assert.deepEqual(q.getProbeStats(), []);
      assert.deepEqual(q.reviseProbeEndpoints({ add: [EP_FAIL] }), [EP_FAIL]);
      assert.equal(q.probeConfigured(), true);
      assert.deepEqual(q.getProbeEndpoints(), [EP_FAIL]);
      assert.deepEqual(q.getProbeConfig(), { ...DEFAULT_CONFIG });
      assert.ok(q.getProber());
      // A fresh prober starts with empty counters.
      assert.deepEqual(q.getProbeStats(), [
        { endpoint: EP_FAIL, success: 0, failure: 0, consecutiveFailures: 0 },
      ]);
    } finally {
      q.stop();
    }
  });

  it("the enable audits probe_endpoints_revised once with previous [] and the exact current list", () => {
    const audited: ProbeAuditEvent[] = [];
    const q = new RetryQueue({ sender: okSender, onProbeAudit: (e) => audited.push(e) });
    try {
      assert.deepEqual(q.reviseProbeEndpoints({ add: [EP_FAIL, EP2] }), [EP_FAIL, EP2]);
      assert.equal(audited.length, 1);
      assert.deepEqual(audited[0], {
        event: "probe_endpoints_revised",
        previous: [],
        current: [EP_FAIL, EP2],
      });
    } finally {
      q.stop();
    }
  });

  it("illegal patches throw RangeError, stay unconfigured, and a later legal patch still enables", () => {
    const audited: ProbeAuditEvent[] = [];
    const q = new RetryQueue({ sender: okSender, onProbeAudit: (e) => audited.push(e) });
    try {
      const bad: unknown[] = [
        {},
        null,
        "x",
        [],
        { add: [] },
        { add: [""] },
        { add: [EP_FAIL, EP_FAIL] },
        { add: [EP_FAIL], remove: [EP_FAIL] },
        { remove: [EP_FAIL] },
        { add: "x" },
      ];
      for (const patch of bad) {
        assert.throws(
          () => q.reviseProbeEndpoints(patch as never),
          RangeError,
          JSON.stringify(patch)
        );
        assert.equal(q.probeConfigured(), false, JSON.stringify(patch));
        assert.equal(q.getProbeEndpoints(), undefined, JSON.stringify(patch));
        assert.equal(q.getProbeConfig(), undefined, JSON.stringify(patch));
      }
      assert.equal(audited.length, 0);
      // A failed enable leaves nothing behind: a legal patch still enables.
      assert.deepEqual(q.reviseProbeEndpoints({ add: [EP_FAIL] }), [EP_FAIL]);
      assert.equal(q.probeConfigured(), true);
      assert.equal(audited.length, 1);
      assert.deepEqual(audited[0], {
        event: "probe_endpoints_revised",
        previous: [],
        current: [EP_FAIL],
      });
    } finally {
      q.stop();
    }
  });

  it("enable on a stopped queue schedules nothing; start schedules the first round; stop halts", async () => {
    const q = new RetryQueue({ sender: okSender });
    try {
      // Enable while stopped, then shrink the interval: an unstarted
      // prober takes the new value up but arms nothing.
      assert.deepEqual(q.reviseProbeEndpoints({ add: [EP_FAIL] }), [EP_FAIL]);
      assert.deepEqual(q.reviseProbe({ intervalMs: 50 }), { ...DEFAULT_CONFIG, intervalMs: 50 });
      await sleep(150);
      assert.equal(q.getProbeStats()[0].failure, 0);
      // Start arms the schedule at the live interval.
      q.start();
      await waitFor(() => q.getProbeStats()[0].failure >= 1, "first probe round after start");
      // Let any in-flight round settle, then stop: no further rounds.
      await sleep(120);
      const failures = q.getProbeStats()[0].failure;
      assert.ok(failures >= 1);
      q.stop();
      await sleep(250);
      assert.equal(q.getProbeStats()[0].failure, failures);
    } finally {
      q.stop();
    }
  });

  it("enable on a running queue starts probing at once: no burst, first round one interval later", async () => {
    const q = new RetryQueue({ sender: okSender });
    q.start();
    try {
      assert.deepEqual(q.reviseProbeEndpoints({ add: [EP_FAIL] }), [EP_FAIL]);
      // No startup burst: nothing has been probed yet.
      assert.equal(q.getProbeStats()[0].failure, 0);
      // Shrink the interval: a running prober re-arms its pending timer
      // at the new interval — which proves the enable started it.
      assert.deepEqual(q.reviseProbe({ intervalMs: 60 }), { ...DEFAULT_CONFIG, intervalMs: 60 });
      await sleep(30);
      assert.equal(q.getProbeStats()[0].failure, 0);
      await waitFor(() => q.getProbeStats()[0].failure >= 1, "first probe round");
      assert.equal(q.getProbeStats()[0].success, 0);
      assert.equal(q.getProbeStats()[0].consecutiveFailures, 1);
    } finally {
      q.stop();
    }
  });

  it("reviseProbe still throws must-restart before enable and works after", () => {
    const q = new RetryQueue({ sender: okSender });
    try {
      assert.throws(
        () => q.reviseProbe({ intervalMs: 5000 }),
        /not configured — enabling it requires a restart/
      );
      assert.equal(q.getProbeConfig(), undefined);
      q.reviseProbeEndpoints({ add: [EP_FAIL] });
      assert.deepEqual(q.reviseProbe({ intervalMs: 5000 }), {
        intervalMs: 5000,
        timeoutMs: 5000,
        method: "HEAD",
      });
      assert.deepEqual(q.getProbeConfig(), {
        intervalMs: 5000,
        timeoutMs: 5000,
        method: "HEAD",
      });
    } finally {
      q.stop();
    }
  });

  it("after enable, reviseProbeEndpoints still follows WR-356 (add arms, remove stops, net-zero no-ops)", () => {
    const audited: ProbeAuditEvent[] = [];
    const q = new RetryQueue({ sender: okSender, onProbeAudit: (e) => audited.push(e) });
    q.start();
    try {
      assert.deepEqual(q.reviseProbeEndpoints({ add: [EP_FAIL] }), [EP_FAIL]);
      assert.deepEqual(q.reviseProbeEndpoints({ add: [EP2] }), [EP_FAIL, EP2]);
      // The added endpoint starts with fresh stats.
      assert.deepEqual(
        q.getProbeStats().map((s) => [s.endpoint, s.success, s.failure, s.consecutiveFailures]),
        [
          [EP_FAIL, 0, 0, 0],
          [EP2, 0, 0, 0],
        ]
      );
      assert.deepEqual(q.reviseProbeEndpoints({ remove: [EP_FAIL] }), [EP2]);
      assert.deepEqual(
        q.getProbeStats().map((s) => s.endpoint),
        [EP2]
      );
      // Net-zero is a silent no-op: no audit, no change.
      assert.deepEqual(q.reviseProbeEndpoints({ add: [EP2], remove: [EP2] }), [EP2]);
      assert.equal(audited.length, 3);
      // Removing the last endpoint is a RangeError; the list is untouched.
      assert.throws(() => q.reviseProbeEndpoints({ remove: [EP2] }), RangeError);
      assert.deepEqual(q.getProbeEndpoints(), [EP2]);
      assert.deepEqual(
        audited.map((e) => e.event),
        ["probe_endpoints_revised", "probe_endpoints_revised", "probe_endpoints_revised"]
      );
      assert.deepEqual(audited[1], {
        event: "probe_endpoints_revised",
        previous: [EP_FAIL],
        current: [EP_FAIL, EP2],
      });
      assert.deepEqual(audited[2], {
        event: "probe_endpoints_revised",
        previous: [EP_FAIL, EP2],
        current: [EP2],
      });
    } finally {
      q.stop();
    }
  });

  it("enabling unlocks the WR-404 callback gate: probe_failed reaches the new callback", async () => {
    const audited: ProbeAuditEvent[] = [];
    const observed: ProbeAuditEvent[] = [];
    const q = new RetryQueue({ sender: okSender, onProbeAudit: (e) => audited.push(e) });
    try {
      assert.throws(
        () => q.reviseProbeAuditCallback(() => {}),
        /requires a restart/
      );
      q.reviseProbeEndpoints({ add: [EP_FAIL] });
      // The enable itself went to the construction audit channel.
      assert.equal(audited.length, 1);
      q.reviseProbeAuditCallback((e) => observed.push(e));
      await q.getProber()!.runRound(EP_FAIL);
      assert.equal(observed.length, 1);
      assert.deepEqual(observed[0], {
        event: "probe_failed",
        endpoint: EP_FAIL,
        consecutiveFailures: 1,
      });
      // The constructor channel no longer receives rounds (observation
      // moved), but the enable event stays recorded there.
      assert.equal(audited.length, 1);
    } finally {
      q.stop();
    }
  });

  it("probe failures trip the breaker early and a success resets the streak", async () => {
    const toggle = toggleServer();
    const ep = await toggle.url();
    const transitions: string[] = [];
    const q = new RetryQueue({
      sender: okSender,
      circuitBreaker: { failureThreshold: 2, cooldownMs: 60_000 },
      onCircuitStateChange: (_endpoint, from, to) => transitions.push(`${from}->${to}`),
    });
    try {
      q.reviseProbeEndpoints({ add: [ep] });
      const prober = q.getProber()!;
      await prober.runRound(ep);
      await prober.runRound(ep);
      // Two consecutive probe failures trip the breaker — before any
      // real delivery had to fail.
      const tripped = q.getCircuitStats().find((s) => s.endpoint === ep)!;
      assert.equal(tripped.state, "open");
      assert.equal(tripped.consecutiveFailures, 2);
      assert.equal(tripped.trips, 1);
      assert.deepEqual(transitions, ["closed->open"]);
      assert.equal(prober.stats()[0].failure, 2);
      assert.equal(prober.stats()[0].consecutiveFailures, 2);
      // A success resets the probe streak — but never closes an open
      // circuit early.
      toggle.setHealthy(true);
      await prober.runRound(ep);
      const after = prober.stats()[0];
      assert.equal(after.endpoint, ep);
      assert.equal(after.success, 1);
      assert.equal(after.failure, 2);
      assert.equal(after.consecutiveFailures, 0);
      assert.equal(typeof after.lastProbeAtMs, "number");
      const stillOpen = q.getCircuitStats().find((s) => s.endpoint === ep)!;
      assert.equal(stillOpen.state, "open");
      assert.equal(stillOpen.trips, 1);
    } finally {
      q.stop();
      toggle.server.close();
    }
  });

  it("without a breaker, probe outcomes still count in relay_probe_* and audit probe_failed/probe_recovered", async () => {
    const audited: ProbeAuditEvent[] = [];
    const toggle = toggleServer();
    const ep = await toggle.url();
    const q = new RetryQueue({ sender: okSender, onProbeAudit: (e) => audited.push(e) });
    try {
      assert.ok(!q.renderMetrics().includes("relay_probe_"));
      q.reviseProbeEndpoints({ add: [ep] });
      const prober = q.getProber()!;
      await prober.runRound(ep);
      assert.equal(audited.filter((e) => e.event === "probe_failed").length, 1);
      toggle.setHealthy(true);
      await prober.runRound(ep);
      assert.equal(audited.filter((e) => e.event === "probe_recovered").length, 1);
      const text = q.renderMetrics();
      assert.match(
        text,
        new RegExp(`relay_probe_total\\{endpoint="${ep.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}",result="success"\\} 1`)
      );
      assert.match(
        text,
        new RegExp(`relay_probe_total\\{endpoint="${ep.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}",result="failure"\\} 1`)
      );
      assert.match(
        text,
        new RegExp(`relay_probe_consecutive_failures\\{endpoint="${ep.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}"\\} 0`)
      );
    } finally {
      q.stop();
      toggle.server.close();
    }
  });

  it("pre-enable outcomes are not retroactively recorded and the breaker streak is untouched", async () => {
    const failingSender: Sender = async () => {
      throw new Error("downstream down");
    };
    const q = new RetryQueue({
      sender: failingSender,
      circuitBreaker: { failureThreshold: 5, cooldownMs: 60_000 },
      baseDelayMs: 5,
      jitterMs: 0,
      maxAttempts: 1,
    });
    q.start();
    try {
      // One failed delivery before the enable builds a breaker streak.
      q.enqueue({ id: "pre-enable-1", payload: Buffer.from("hi"), targetUrl: EP_FAIL, headers: {} });
      await waitFor(
        () =>
          q.getCircuitStats().find((s) => s.endpoint === EP_FAIL)?.consecutiveFailures === 1,
        "pre-enable delivery failure on the breaker"
      );
      assert.deepEqual(q.getProbeStats(), []);
      // The enable must not touch the breaker streak or invent probe
      // history for the endpoint.
      assert.deepEqual(q.reviseProbeEndpoints({ add: [EP_FAIL] }), [EP_FAIL]);
      assert.deepEqual(q.getProbeStats(), [
        { endpoint: EP_FAIL, success: 0, failure: 0, consecutiveFailures: 0 },
      ]);
      const breaker = q.getCircuitStats().find((s) => s.endpoint === EP_FAIL)!;
      assert.equal(breaker.state, "closed");
      assert.equal(breaker.consecutiveFailures, 1);
      assert.equal(breaker.trips, 0);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer downstream probe live enable (WR-466)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "probe-endpoints-enable-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: signingKey,
      forwardUrl: EP_FAIL,
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

  async function waitForAudit(
    audit: AuditLog,
    event: string,
    min: number,
    timeoutMs = 5000
  ): Promise<Record<string, unknown>[]> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const found = eventsOf(audit, event);
      if (found.length >= min) return found;
      if (Date.now() >= deadline) throw new Error(`timed out waiting for ${min}x ${event}`);
      await sleep(25);
    }
  }

  async function closeRelay(relay: Server): Promise<void> {
    relay.close();
    await new Promise((r) => relay.once("close", r));
  }

  it("enable mounts both getters with exact values and audits the enable once", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    try {
      assert.equal(relay.getProbeEndpoints, undefined);
      assert.equal(relay.getProbeConfig, undefined);
      assert.deepEqual(relay.reviseProbeEndpoints!({ add: [EP_FAIL] }), [EP_FAIL]);
      assert.deepEqual(relay.getProbeEndpoints!(), [EP_FAIL]);
      assert.deepEqual(relay.getProbeConfig!(), { ...DEFAULT_CONFIG });
      const revised = eventsOf(audit, "probe_endpoints_revised");
      assert.equal(revised.length, 1);
      assert.deepEqual(revised[0].previous, []);
      assert.deepEqual(revised[0].current, [EP_FAIL]);
      // The defaults are not a cadence revision: no probe_revised.
      assert.equal(eventsOf(audit, "probe_revised").length, 0);
    } finally {
      await closeRelay(relay);
    }
  });

  it("an illegal enable patch throws RangeError, leaves the getters unmounted, and a later legal patch still enables", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    try {
      for (const bad of [{}, { add: [] }, { remove: [EP_FAIL] }, { add: [EP_FAIL, EP_FAIL] }]) {
        assert.throws(() => relay.reviseProbeEndpoints!(bad as never), RangeError, JSON.stringify(bad));
        assert.equal(relay.getProbeEndpoints, undefined, JSON.stringify(bad));
        assert.equal(relay.getProbeConfig, undefined, JSON.stringify(bad));
      }
      assert.equal(eventsOf(audit, "probe_endpoints_revised").length, 0);
      assert.deepEqual(relay.reviseProbeEndpoints!({ add: [EP_FAIL] }), [EP_FAIL]);
      assert.deepEqual(relay.getProbeEndpoints!(), [EP_FAIL]);
      assert.deepEqual(relay.getProbeConfig!(), { ...DEFAULT_CONFIG });
      assert.equal(eventsOf(audit, "probe_endpoints_revised").length, 1);
    } finally {
      await closeRelay(relay);
    }
  });

  it("reviseProbe throws must-restart before enable and works after", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    try {
      assert.throws(
        () => relay.reviseProbe!({ intervalMs: 5000 }),
        /not configured — enabling it requires a restart/
      );
      relay.reviseProbeEndpoints!({ add: [EP_FAIL] });
      assert.deepEqual(relay.reviseProbe!({ intervalMs: 5000 }), {
        intervalMs: 5000,
        timeoutMs: 5000,
        method: "HEAD",
      });
      assert.deepEqual(relay.getProbeConfig!(), {
        intervalMs: 5000,
        timeoutMs: 5000,
        method: "HEAD",
      });
      const revised = eventsOf(audit, "probe_revised");
      assert.equal(revised.length, 1);
      assert.deepEqual(revised[0].previous, { ...DEFAULT_CONFIG });
      assert.deepEqual(revised[0].current, {
        intervalMs: 5000,
        timeoutMs: 5000,
        method: "HEAD",
      });
    } finally {
      await closeRelay(relay);
    }
  });

  it("enabling unlocks the WR-404 callback gate: probe_failed reaches the new callback", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    try {
      assert.throws(
        () => relay.reviseProbeAuditCallback(() => {}),
        /requires a restart/
      );
      relay.reviseProbeEndpoints!({ add: [EP_FAIL] });
      const observed: ProbeAuditEvent[] = [];
      relay.reviseProbeAuditCallback((e) => observed.push(e));
      // Shrink the interval so the first scheduled round fires promptly.
      relay.reviseProbe!({ intervalMs: 50 });
      const failed = await waitForAudit(audit, "probe_failed", 1);
      assert.ok(failed.length >= 1);
      assert.equal((failed[0] as { endpoint: string }).endpoint, EP_FAIL);
      assert.equal((failed[0] as { consecutiveFailures: number }).consecutiveFailures, 1);
      assert.ok(observed.some((e) => e.event === "probe_failed"));
      assert.deepEqual(
        observed.filter((e) => e.event === "probe_failed")[0],
        { event: "probe_failed", endpoint: EP_FAIL, consecutiveFailures: 1 }
      );
    } finally {
      await closeRelay(relay);
    }
  });
});
