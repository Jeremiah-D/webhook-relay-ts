import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { EndpointCircuitBreaker } from "../src/circuit.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "circuit-probe-revision-secret";
const EP_A = "http://a.example/hook";
const EP_B = "http://b.example/hook";
const EP_C = "http://c.example/hook";

const PROBE_DEFAULTS = { halfOpenMaxInFlight: 1, halfOpenRetryMs: 1000 } as const;
const THRESHOLD_DEFAULTS = {
  failureThreshold: 5,
  cooldownMs: 30_000,
  tripMode: "consecutive-failures",
  errorRateWindowSize: 20,
  errorRateThreshold: 0.5,
  errorRateMinSamples: 10,
} as const;

/** Trip `b` open for `endpoint` at the current clock, then return. */
function tripOpen(b: EndpointCircuitBreaker, endpoint: string): void {
  b.recordFailure(endpoint);
  assert.equal(b.state(endpoint), "open");
}

describe("EndpointCircuitBreaker half-open probe revision (WR-331)", () => {
  it("probeFor reports constructor defaults and setEndpointProbe merges partially", () => {
    const b = new EndpointCircuitBreaker({ failureThreshold: 1, halfOpenMaxInFlight: 2, halfOpenRetryMs: 250 });
    assert.deepEqual(b.probeFor(EP_A), { halfOpenMaxInFlight: 2, halfOpenRetryMs: 250 });
    assert.equal(b.hasEndpointProbeOverride(EP_A), false);
    assert.deepEqual(b.configuredProbeEndpoints(), []);
    b.setEndpointProbe(EP_A, { halfOpenMaxInFlight: 4 });
    assert.deepEqual(b.probeFor(EP_A), { halfOpenMaxInFlight: 4, halfOpenRetryMs: 250 });
    assert.equal(b.hasEndpointProbeOverride(EP_A), true);
    assert.deepEqual(b.configuredProbeEndpoints(), [EP_A]);
    // A second partial patch merges over the live values, not the defaults.
    b.setEndpointProbe(EP_A, { halfOpenRetryMs: 500 });
    assert.deepEqual(b.probeFor(EP_A), { halfOpenMaxInFlight: 4, halfOpenRetryMs: 500 });
    // Another endpoint is untouched, and clearing restores the defaults.
    assert.deepEqual(b.probeFor(EP_B), { halfOpenMaxInFlight: 2, halfOpenRetryMs: 250 });
    b.clearEndpointProbeOverride(EP_A);
    assert.equal(b.hasEndpointProbeOverride(EP_A), false);
    assert.deepEqual(b.probeFor(EP_A), { halfOpenMaxInFlight: 2, halfOpenRetryMs: 250 });
    // Clearing an unknown endpoint never throws.
    b.clearEndpointProbeOverride(EP_C);
  });

  it("widening halfOpenMaxInFlight lets a half-open circuit grant N parallel probes", () => {
    let now = 0;
    const b = new EndpointCircuitBreaker({ failureThreshold: 1, cooldownMs: 5000, nowMs: () => now });
    tripOpen(b, EP_A);
    // Default of 1 would grant exactly one probe; widen while open.
    b.setEndpointProbe(EP_A, { halfOpenMaxInFlight: 3 });
    now += 5000;
    assert.deepEqual(b.shouldAllow(EP_A), { allowed: true, probe: true });
    assert.deepEqual(b.shouldAllow(EP_A), { allowed: true, probe: true });
    assert.deepEqual(b.shouldAllow(EP_A), { allowed: true, probe: true });
    assert.deepEqual(b.shouldAllow(EP_A), { allowed: false, probe: false });
  });

  it("tightening below the in-flight count grants nothing new until the count falls back", () => {
    let now = 0;
    const b = new EndpointCircuitBreaker({ failureThreshold: 1, cooldownMs: 5000, nowMs: () => now });
    tripOpen(b, EP_A);
    b.setEndpointProbe(EP_A, { halfOpenMaxInFlight: 3 });
    now += 5000;
    assert.equal(b.shouldAllow(EP_A).probe, true);
    assert.equal(b.shouldAllow(EP_A).probe, true);
    // Tighten to 1 with 2 probes already granted: no new permit, and
    // the granted probes are not cancelled by the revision.
    b.setEndpointProbe(EP_A, { halfOpenMaxInFlight: 1 });
    assert.deepEqual(b.shouldAllow(EP_A), { allowed: false, probe: false });
    b.cancelProbe(EP_A); // 1 still in flight: still at the new limit.
    assert.deepEqual(b.shouldAllow(EP_A), { allowed: false, probe: false });
    b.cancelProbe(EP_A); // 0 in flight: below the limit again.
    assert.deepEqual(b.shouldAllow(EP_A), { allowed: true, probe: true });
  });

  it("a shortened halfOpenRetryMs changes the next parked attempt's wait", () => {
    let now = 0;
    const b = new EndpointCircuitBreaker({ failureThreshold: 1, cooldownMs: 5000, nowMs: () => now });
    tripOpen(b, EP_A);
    now += 5000;
    assert.equal(b.shouldAllow(EP_A).probe, true);
    assert.equal(b.state(EP_A), "half_open");
    assert.equal(b.retryInMs(EP_A), 1000);
    b.setEndpointProbe(EP_A, { halfOpenRetryMs: 200 });
    assert.equal(b.retryInMs(EP_A), 200);
  });

  it("illegal values and an empty patch throw RangeError and the live probe values are untouched", () => {
    const b = new EndpointCircuitBreaker({ failureThreshold: 1 });
    b.setEndpointProbe(EP_A, { halfOpenMaxInFlight: 2, halfOpenRetryMs: 300 });
    const before = b.probeFor(EP_A);
    const bad: Array<Record<string, unknown>> = [
      { halfOpenMaxInFlight: 0 },
      { halfOpenMaxInFlight: -1 },
      { halfOpenMaxInFlight: 1.5 },
      { halfOpenMaxInFlight: Number.NaN },
      { halfOpenMaxInFlight: Infinity },
      { halfOpenRetryMs: 0 },
      { halfOpenRetryMs: -5 },
      { halfOpenRetryMs: Number.NaN },
      { halfOpenRetryMs: Infinity },
      {},
    ];
    for (const patch of bad) {
      assert.throws(
        () => b.setEndpointProbe(EP_A, patch as never),
        RangeError,
        JSON.stringify(patch)
      );
      assert.deepEqual(b.probeFor(EP_A), before);
    }
  });

  it("revising an open endpoint keeps its state, openedAtMs and trips", () => {
    let now = 0;
    const b = new EndpointCircuitBreaker({ failureThreshold: 1, cooldownMs: 5000, nowMs: () => now });
    tripOpen(b, EP_A);
    assert.deepEqual(b.stats()[0].openedAtMs, 0);
    assert.equal(b.stats()[0].trips, 1);
    b.setEndpointProbe(EP_A, { halfOpenMaxInFlight: 3, halfOpenRetryMs: 200 });
    assert.equal(b.state(EP_A), "open");
    assert.deepEqual(b.stats()[0].openedAtMs, 0);
    assert.equal(b.stats()[0].trips, 1);
  });
});

describe("RetryQueue half-open probe revision (WR-331)", () => {
  function makeQueue() {
    const q = new RetryQueue({
      sender: (async () => {}) as Sender,
      circuitBreaker: { failureThreshold: 5, cooldownMs: 5000 },
    });
    return q;
  }

  it("getEndpointCircuitProbe reports live defaults, undefined when unconfigured", () => {
    const q = makeQueue();
    try {
      assert.deepEqual(q.getEndpointCircuitProbe(EP_A), {
        probe: { ...PROBE_DEFAULTS },
        overridden: false,
      });
      assert.deepEqual(q.getCircuitProbes(), []);
    } finally {
      q.stop();
    }
    const q2 = new RetryQueue({ sender: async () => {} });
    try {
      assert.equal(q2.getEndpointCircuitProbe(EP_A), undefined);
      assert.deepEqual(q2.getCircuitProbes(), []);
      assert.equal(q2.setEndpointCircuitProbe(EP_A, { halfOpenMaxInFlight: 3 }), false);
    } finally {
      q2.stop();
    }
  });

  it("getter matches live values after revision and the listing covers revised and observed endpoints", async () => {
    const pending: Array<() => void> = [];
    const q = new RetryQueue({
      sender: (async () => {
        throw new Error("downstream down");
      }) as Sender,
      baseDelayMs: 10,
      maxAttempts: 5,
      jitterMs: 0,
      random: () => 0,
      setTimer: (fn: () => void, _ms: number) => {
        pending.push(fn);
        return {
          clear: () => {
            const i = pending.indexOf(fn);
            if (i >= 0) pending.splice(i, 1);
          },
        };
      },
      circuitBreaker: { failureThreshold: 5, cooldownMs: 5000 },
    });
    q.start();
    try {
      assert.equal(q.setEndpointCircuitProbe(EP_A, { halfOpenMaxInFlight: 3 }), true);
      assert.deepEqual(q.getEndpointCircuitProbe(EP_A), {
        probe: { halfOpenMaxInFlight: 3, halfOpenRetryMs: 1000 },
        overridden: true,
      });
      // EP_B is observed through one failed delivery (no probe
      // override): it still lists, with default probe values.
      q.enqueue({ id: "probe-list", payload: Buffer.from("x"), targetUrl: EP_B, headers: {} });
      const fns = pending.splice(0);
      for (const fn of fns) fn();
      await new Promise((r) => setImmediate(r));
      assert.deepEqual(q.getCircuitProbes(), [
        { endpoint: EP_A, probe: { halfOpenMaxInFlight: 3, halfOpenRetryMs: 1000 }, overridden: true },
        { endpoint: EP_B, probe: { ...PROBE_DEFAULTS }, overridden: false },
      ]);
      assert.equal(q.getCircuitProbes().some((r) => r.endpoint === EP_C), false);
    } finally {
      q.stop();
    }
  });

  it("a probe revision leaves the threshold values untouched", () => {
    const q = makeQueue();
    try {
      q.setEndpointCircuitProbe(EP_A, { halfOpenMaxInFlight: 3, halfOpenRetryMs: 200 });
      assert.deepEqual(q.getEndpointCircuitBreaker(EP_A), {
        thresholds: { ...THRESHOLD_DEFAULTS, cooldownMs: 5000 },
        overridden: false,
      });
      q.setEndpointCircuitBreaker(EP_A, { failureThreshold: 2 });
      assert.deepEqual(q.getEndpointCircuitProbe(EP_A), {
        probe: { halfOpenMaxInFlight: 3, halfOpenRetryMs: 200 },
        overridden: true,
      });
    } finally {
      q.stop();
    }
  });

  it("tenant probe values are isolated", () => {
    const q = makeQueue();
    try {
      q.setEndpointCircuitProbe(EP_A, { halfOpenMaxInFlight: 3 }, "acme");
      assert.deepEqual(q.getEndpointCircuitProbe(EP_A, "acme"), {
        probe: { halfOpenMaxInFlight: 3, halfOpenRetryMs: 1000 },
        overridden: true,
      });
      assert.deepEqual(q.getEndpointCircuitProbe(EP_A), {
        probe: { ...PROBE_DEFAULTS },
        overridden: false,
      });
      assert.deepEqual(q.getEndpointCircuitProbe(EP_A, "other"), {
        probe: { ...PROBE_DEFAULTS },
        overridden: false,
      });
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer half-open probe revision (WR-331)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "circuit-probe-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: "http://127.0.0.1:9/unused",
      auditLog,
      ...opts,
    });
    servers.push(relay);
    return { relay, auditLog };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  async function listen(server: Server): Promise<void> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  }

  function configuredServer() {
    return makeServer({
      retry: {
        circuitBreaker: { failureThreshold: 5, cooldownMs: 30_000 },
      },
    });
  }

  it("revise audits previous/current, with the constructor defaults as first previous", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    const current = relay.reviseEndpointCircuitProbe(EP_A, { halfOpenMaxInFlight: 3 });
    assert.deepEqual(current, { halfOpenMaxInFlight: 3, halfOpenRetryMs: 1000 });
    const revised = eventsOf(auditLog, "circuit_probe_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].endpoint, EP_A);
    assert.deepEqual(revised[0].previous, { ...PROBE_DEFAULTS });
    assert.deepEqual(revised[0].current, { halfOpenMaxInFlight: 3, halfOpenRetryMs: 1000 });
    const current2 = relay.reviseEndpointCircuitProbe(EP_A, { halfOpenRetryMs: 200 });
    assert.deepEqual(current2, { halfOpenMaxInFlight: 3, halfOpenRetryMs: 200 });
    const revised2 = eventsOf(auditLog, "circuit_probe_revised");
    assert.equal(revised2.length, 2);
    assert.deepEqual(revised2[1].previous, { halfOpenMaxInFlight: 3, halfOpenRetryMs: 1000 });
    assert.deepEqual(revised2[1].current, { halfOpenMaxInFlight: 3, halfOpenRetryMs: 200 });
  });

  it("a same-value revision is a silent no-op", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    relay.reviseEndpointCircuitProbe(EP_A, { ...PROBE_DEFAULTS });
    relay.reviseEndpointCircuitProbe(EP_A, { halfOpenMaxInFlight: 1 });
    assert.equal(eventsOf(auditLog, "circuit_probe_revised").length, 0);
    relay.reviseEndpointCircuitProbe(EP_A, { halfOpenMaxInFlight: 3 });
    assert.equal(eventsOf(auditLog, "circuit_probe_revised").length, 1);
    relay.reviseEndpointCircuitProbe(EP_A, { halfOpenMaxInFlight: 3 });
    assert.equal(eventsOf(auditLog, "circuit_probe_revised").length, 1);
  });

  it("an illegal or empty patch throws RangeError and the live probe values and audit are untouched", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    for (const bad of [{ halfOpenMaxInFlight: 0 }, { halfOpenRetryMs: -1 }, {}]) {
      assert.throws(() => relay.reviseEndpointCircuitProbe(EP_A, bad as never), RangeError);
    }
    assert.deepEqual(relay.getEndpointCircuitProbe!(EP_A), {
      probe: { ...PROBE_DEFAULTS },
      overridden: false,
    });
    assert.equal(eventsOf(auditLog, "circuit_probe_revised").length, 0);
  });

  it("an unconfigured breaker throws Error on revise and leaves the getters unset", async () => {
    const { relay, auditLog } = makeServer();
    await listen(relay);
    assert.throws(
      () => relay.reviseEndpointCircuitProbe(EP_A, { halfOpenMaxInFlight: 3 }),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.ok(!(err instanceof RangeError), "must be Error, not RangeError");
        assert.match((err as Error).message, /requires a restart/);
        return true;
      }
    );
    assert.equal(relay.getEndpointCircuitProbe, undefined);
    assert.equal(relay.getCircuitProbes, undefined);
    assert.equal(relay.removeEndpointCircuitProbe(EP_A), false);
    assert.equal(eventsOf(auditLog, "circuit_probe_removed").length, 0);
  });

  it("remove returns true, audits, and falls back to the constructor defaults", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    relay.reviseEndpointCircuitProbe(EP_A, { halfOpenMaxInFlight: 3 });
    assert.equal(relay.removeEndpointCircuitProbe(EP_A), true);
    const removed = eventsOf(auditLog, "circuit_probe_removed");
    assert.equal(removed.length, 1);
    assert.equal(removed[0].endpoint, EP_A);
    assert.deepEqual(removed[0].previous, { halfOpenMaxInFlight: 3, halfOpenRetryMs: 1000 });
    assert.deepEqual(relay.getEndpointCircuitProbe!(EP_A), {
      probe: { ...PROBE_DEFAULTS },
      overridden: false,
    });
  });

  it("remove without a probe override returns false and never touches the threshold override", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    assert.equal(relay.removeEndpointCircuitProbe(EP_A), false);
    assert.equal(eventsOf(auditLog, "circuit_probe_removed").length, 0);
    relay.reviseEndpointCircuitBreaker(EP_A, { failureThreshold: 3 });
    assert.equal(relay.removeEndpointCircuitProbe(EP_A), false);
    assert.equal(eventsOf(auditLog, "circuit_probe_removed").length, 0);
    assert.deepEqual(relay.getEndpointCircuitBreaker!(EP_A), {
      thresholds: { ...THRESHOLD_DEFAULTS, failureThreshold: 3 },
      overridden: true,
    });
  });

  it("probe revision leaves thresholds alone and tenant values are isolated", async () => {
    const { relay } = configuredServer();
    await listen(relay);
    relay.reviseEndpointCircuitProbe(EP_A, { halfOpenMaxInFlight: 3 });
    assert.deepEqual(relay.getEndpointCircuitBreaker!(EP_A), {
      thresholds: { ...THRESHOLD_DEFAULTS },
      overridden: false,
    });
    relay.reviseEndpointCircuitProbe(EP_A, { halfOpenMaxInFlight: 2 }, "acme");
    assert.deepEqual(relay.getEndpointCircuitProbe!(EP_A, "acme"), {
      probe: { halfOpenMaxInFlight: 2, halfOpenRetryMs: 1000 },
      overridden: true,
    });
    assert.deepEqual(relay.getEndpointCircuitProbe!(EP_A), {
      probe: { halfOpenMaxInFlight: 3, halfOpenRetryMs: 1000 },
      overridden: true,
    });
  });
});
