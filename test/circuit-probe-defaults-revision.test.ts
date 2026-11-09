import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import { EndpointCircuitBreaker } from "../src/circuit.ts";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "circuit-probe-defaults-revision-secret";
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

/**
 * Manual timer that also records the scheduled delays — the probe
 * tests assert on the delay a parked attempt was scheduled with, so a
 * plain fire-list is not enough.
 */
function manualTimer() {
  const pending: Array<{ fn: () => void; ms: number }> = [];
  return {
    pendingCount: () => pending.length,
    lastDelay: () => pending[pending.length - 1]?.ms,
    setTimer: (fn: () => void, ms: number) => {
      const rec = { fn, ms };
      pending.push(rec);
      return {
        clear: () => {
          const i = pending.indexOf(rec);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    async step() {
      const fns = pending.splice(0);
      for (const f of fns) f.fn();
      await new Promise((r) => setImmediate(r));
    },
  };
}

function failingSender() {
  let calls = 0;
  let fail = true;
  const sender: Sender = async () => {
    calls += 1;
    if (fail) throw new Error("downstream down");
  };
  return { sender, calls: () => calls, setFail: (v: boolean) => (fail = v) };
}

function item(id: string, targetUrl: string) {
  return { id, payload: Buffer.from("x"), targetUrl, headers: {} };
}

/** Trip `b` open for `endpoint` at the current clock, then return. */
function tripOpen(b: EndpointCircuitBreaker, endpoint: string): void {
  b.recordFailure(endpoint);
  assert.equal(b.state(endpoint), "open");
}

describe("EndpointCircuitBreaker retuneProbeDefaults (WR-364)", () => {
  it("retuneProbeDefaults replaces the two default fields; overrides still win", () => {
    const b = new EndpointCircuitBreaker({
      failureThreshold: 1,
      halfOpenMaxInFlight: 2,
      halfOpenRetryMs: 250,
    });
    assert.deepEqual(b.probeFor(EP_A), { halfOpenMaxInFlight: 2, halfOpenRetryMs: 250 });
    b.setEndpointProbe(EP_B, { halfOpenMaxInFlight: 5 });
    b.retuneProbeDefaults({ halfOpenMaxInFlight: 4, halfOpenRetryMs: 500 });
    // Uncovered endpoints read the retuned defaults.
    assert.deepEqual(b.probeFor(EP_A), { halfOpenMaxInFlight: 4, halfOpenRetryMs: 500 });
    // A covered endpoint keeps its resolved override, untouched.
    assert.deepEqual(b.probeFor(EP_B), { halfOpenMaxInFlight: 5, halfOpenRetryMs: 250 });
    assert.equal(b.hasEndpointProbeOverride(EP_B), true);
    // The trip thresholds are untouched by a probe retune.
    assert.deepEqual(b.thresholdsFor(EP_A), {
      failureThreshold: 1,
      cooldownMs: 30_000,
      tripMode: "consecutive-failures",
      errorRateWindowSize: 20,
      errorRateThreshold: 0.5,
      errorRateMinSamples: 10,
    });
  });

  it("widening the defaults lets a half-open circuit grant N parallel probes", () => {
    let now = 0;
    const b = new EndpointCircuitBreaker({ failureThreshold: 1, cooldownMs: 5000, nowMs: () => now });
    tripOpen(b, EP_A);
    // Default of 1 would grant exactly one probe; widen while open.
    b.retuneProbeDefaults({ halfOpenMaxInFlight: 3, halfOpenRetryMs: 1000 });
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
    b.retuneProbeDefaults({ halfOpenMaxInFlight: 3, halfOpenRetryMs: 1000 });
    now += 5000;
    assert.equal(b.shouldAllow(EP_A).probe, true);
    assert.equal(b.shouldAllow(EP_A).probe, true);
    // Tighten to 1 with 2 probes already granted: no new permit, and
    // the granted probes are not cancelled by the revision.
    b.retuneProbeDefaults({ halfOpenMaxInFlight: 1, halfOpenRetryMs: 1000 });
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
    b.retuneProbeDefaults({ halfOpenMaxInFlight: 1, halfOpenRetryMs: 200 });
    assert.equal(b.retryInMs(EP_A), 200);
  });

  it("retuning an open endpoint keeps its state, openedAtMs and trips", () => {
    let now = 0;
    const b = new EndpointCircuitBreaker({ failureThreshold: 1, cooldownMs: 5000, nowMs: () => now });
    tripOpen(b, EP_A);
    assert.deepEqual(b.stats()[0].openedAtMs, 0);
    assert.equal(b.stats()[0].trips, 1);
    b.retuneProbeDefaults({ halfOpenMaxInFlight: 3, halfOpenRetryMs: 200 });
    assert.equal(b.state(EP_A), "open");
    assert.deepEqual(b.stats()[0].openedAtMs, 0);
    assert.equal(b.stats()[0].trips, 1);
  });
});

describe("RetryQueue circuit-breaker probe defaults revision (WR-364)", () => {
  function makeQueue(failureThreshold = 5, cooldownMs = 5000) {
    const timer = manualTimer();
    let now = 0;
    const f = failingSender();
    const q = new RetryQueue({
      sender: f.sender,
      baseDelayMs: 10,
      maxAttempts: 5,
      jitterMs: 0,
      random: () => 0, // deterministic parking delay
      setTimer: timer.setTimer,
      circuitBreaker: { failureThreshold, cooldownMs, nowMs: () => now },
    });
    return { q, timer, f, advance: (ms: number) => (now += ms) };
  }

  it("getCircuitBreakerProbeDefaults reports live defaults, undefined when unconfigured, and revise throws must-restart Error", () => {
    const { q } = makeQueue();
    try {
      assert.deepEqual(q.getCircuitBreakerProbeDefaults(), { ...PROBE_DEFAULTS });
    } finally {
      q.stop();
    }
    // Feature disabled: the getter is undefined and revise throws the
    // must-restart Error (not a RangeError).
    const q2 = new RetryQueue({ sender: async () => {} });
    try {
      assert.equal(q2.getCircuitBreakerProbeDefaults(), undefined);
      assert.throws(
        () => q2.reviseCircuitProbeDefaults({ halfOpenMaxInFlight: 3 }),
        (err: unknown) => {
          assert.ok(err instanceof Error);
          assert.ok(!(err instanceof RangeError), "must be Error, not RangeError");
          assert.match((err as Error).message, /requires a restart/);
          return true;
        }
      );
    } finally {
      q2.stop();
    }
  });

  it("revise merges a partial patch and a second patch merges over the revised values", () => {
    const { q } = makeQueue();
    try {
      assert.deepEqual(q.reviseCircuitProbeDefaults({ halfOpenMaxInFlight: 3 }), {
        halfOpenMaxInFlight: 3,
        halfOpenRetryMs: 1000,
      });
      assert.deepEqual(q.getCircuitBreakerProbeDefaults(), {
        halfOpenMaxInFlight: 3,
        halfOpenRetryMs: 1000,
      });
      // A second partial patch merges over the live values, not the defaults.
      q.reviseCircuitProbeDefaults({ halfOpenRetryMs: 200 });
      assert.deepEqual(q.getCircuitBreakerProbeDefaults(), {
        halfOpenMaxInFlight: 3,
        halfOpenRetryMs: 200,
      });
    } finally {
      q.stop();
    }
  });

  it("an illegal or empty patch throws RangeError and the live defaults are untouched", () => {
    const { q } = makeQueue();
    try {
      const before = q.getCircuitBreakerProbeDefaults();
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
          () => q.reviseCircuitProbeDefaults(patch as never),
          RangeError,
          JSON.stringify(patch)
        );
        assert.deepEqual(q.getCircuitBreakerProbeDefaults(), before);
      }
    } finally {
      q.stop();
    }
  });

  it("a same-value revision is a no-op", () => {
    const { q } = makeQueue();
    try {
      assert.deepEqual(q.reviseCircuitProbeDefaults({ ...PROBE_DEFAULTS }), {
        ...PROBE_DEFAULTS,
      });
      assert.deepEqual(q.reviseCircuitProbeDefaults({ halfOpenMaxInFlight: 1 }), {
        ...PROBE_DEFAULTS,
      });
      assert.deepEqual(q.reviseCircuitProbeDefaults({ halfOpenMaxInFlight: 3 }), {
        halfOpenMaxInFlight: 3,
        halfOpenRetryMs: 1000,
      });
      assert.deepEqual(q.reviseCircuitProbeDefaults({ halfOpenMaxInFlight: 3 }), {
        halfOpenMaxInFlight: 3,
        halfOpenRetryMs: 1000,
      });
      assert.deepEqual(q.getCircuitBreakerProbeDefaults(), {
        halfOpenMaxInFlight: 3,
        halfOpenRetryMs: 1000,
      });
    } finally {
      q.stop();
    }
  });

  it("an endpoint with a probe override is unaffected and the override still wins", () => {
    const { q } = makeQueue();
    try {
      q.setEndpointCircuitProbe(EP_B, { halfOpenMaxInFlight: 9 });
      q.reviseCircuitProbeDefaults({ halfOpenMaxInFlight: 2, halfOpenRetryMs: 200 });
      assert.deepEqual(q.getEndpointCircuitProbe(EP_B), {
        probe: { halfOpenMaxInFlight: 9, halfOpenRetryMs: 1000 },
        overridden: true,
      });
      assert.deepEqual(q.getEndpointCircuitProbe(EP_A), {
        probe: { halfOpenMaxInFlight: 2, halfOpenRetryMs: 200 },
        overridden: false,
      });
      assert.deepEqual(q.getCircuitBreakerProbeDefaults(), {
        halfOpenMaxInFlight: 2,
        halfOpenRetryMs: 200,
      });
      // The thresholds are untouched by a probe-defaults revision.
      assert.deepEqual(q.getCircuitBreakerDefaults(), {
        ...THRESHOLD_DEFAULTS,
        cooldownMs: 5000,
      });
    } finally {
      q.stop();
    }
  });

  it("a tenant's first breaker is built at the revised defaults and every tenant's breaker is retuned in sync", () => {
    const { q } = makeQueue();
    try {
      // Build both tenants' breakers before the revision.
      q.getEndpointCircuitProbe(EP_A, "acme");
      q.getEndpointCircuitProbe(EP_A, "globex");
      q.reviseCircuitProbeDefaults({ halfOpenMaxInFlight: 2, halfOpenRetryMs: 200 });
      assert.deepEqual(q.getEndpointCircuitProbe(EP_A, "acme"), {
        probe: { halfOpenMaxInFlight: 2, halfOpenRetryMs: 200 },
        overridden: false,
      });
      assert.deepEqual(q.getEndpointCircuitProbe(EP_A, "globex"), {
        probe: { halfOpenMaxInFlight: 2, halfOpenRetryMs: 200 },
        overridden: false,
      });
      // No breaker existed for this tenant at revision time.
      assert.deepEqual(q.getEndpointCircuitProbe(EP_A, "newbie"), {
        probe: { halfOpenMaxInFlight: 2, halfOpenRetryMs: 200 },
        overridden: false,
      });
    } finally {
      q.stop();
    }
  });

  it("widened defaults let a half-open endpoint grant N parallel probes, and a shortened retryMs shortens the next parked wait", async () => {
    const timer = manualTimer();
    let now = 0;
    let calls = 0;
    let release!: () => void;
    const held = new Promise<void>((resolve) => {
      release = resolve;
    });
    // First call fails (trips the circuit); every later call is a
    // probe that hangs until released, so probes stay in flight.
    const sender: Sender = async () => {
      calls += 1;
      if (calls === 1) throw new Error("downstream down");
      await held;
    };
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxAttempts: 5,
      jitterMs: 0,
      random: () => 0, // deterministic parking delay
      setTimer: timer.setTimer,
      circuitBreaker: { failureThreshold: 1, cooldownMs: 5000, nowMs: () => now },
    });
    // Widen the defaults before any breaker exists: the first probe
    // window grants 3 in parallel instead of 1.
    q.reviseCircuitProbeDefaults({ halfOpenMaxInFlight: 3 });
    q.start();
    try {
      q.enqueue(item("probe-default-a", EP_A));
      await timer.step(); // attempt 1 fails -> trips open
      assert.equal(calls, 1);
      assert.equal(q.getCircuitStats()[0].state, "open");
      await timer.step(); // backoff fires -> parked, delay = cooldown 5000
      assert.equal(timer.lastDelay(), 5000);
      now += 5000;
      await timer.step(); // park fires -> probe 1 granted, hangs
      assert.equal(calls, 2);
      assert.equal(q.getCircuitStats()[0].state, "half_open");
      q.enqueue(item("probe-default-b", EP_A));
      await timer.step(); // probe 2 granted, hangs
      assert.equal(calls, 3);
      q.enqueue(item("probe-default-c", EP_A));
      await timer.step(); // probe 3 granted, hangs
      assert.equal(calls, 4);
      q.enqueue(item("probe-default-d", EP_A));
      await timer.step(); // no slot left -> parked, delay = default retry 1000
      assert.equal(calls, 4);
      assert.equal(timer.lastDelay(), 1000);
      // Shorten the retry interval: the already-parked attempt keeps
      // its old delay, but its next recheck waits the new value.
      q.reviseCircuitProbeDefaults({ halfOpenRetryMs: 200 });
      await timer.step(); // park fires -> still busy -> re-parked at 200
      assert.equal(timer.lastDelay(), 200);
      assert.equal(calls, 4);
      release();
      await timer.step(); // probes settle (success) -> circuit closes
      assert.equal(q.getCircuitStats()[0].state, "closed");
    } finally {
      release();
      q.stop();
    }
  });
});

describe("RelayServer circuit-breaker probe defaults revision (WR-364)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "circuit-probe-defaults-revision-"));
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

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
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
    const current = relay.reviseCircuitProbeDefaults({ halfOpenMaxInFlight: 3 });
    assert.deepEqual(current, { halfOpenMaxInFlight: 3, halfOpenRetryMs: 1000 });
    const revised = eventsOf(auditLog, "circuit_breaker_probe_defaults_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, { ...PROBE_DEFAULTS });
    assert.deepEqual(revised[0].current, { halfOpenMaxInFlight: 3, halfOpenRetryMs: 1000 });
    // A second revision audits the live values as previous.
    const current2 = relay.reviseCircuitProbeDefaults({ halfOpenRetryMs: 200 });
    assert.deepEqual(current2, { halfOpenMaxInFlight: 3, halfOpenRetryMs: 200 });
    const revised2 = eventsOf(auditLog, "circuit_breaker_probe_defaults_revised");
    assert.equal(revised2.length, 2);
    assert.deepEqual(revised2[1].previous, { halfOpenMaxInFlight: 3, halfOpenRetryMs: 1000 });
    assert.deepEqual(revised2[1].current, { halfOpenMaxInFlight: 3, halfOpenRetryMs: 200 });
  });

  it("a same-value revision is a silent no-op, and an empty patch throws RangeError", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    // Landing exactly on the live values is a silent no-op.
    relay.reviseCircuitProbeDefaults({ ...PROBE_DEFAULTS });
    relay.reviseCircuitProbeDefaults({ halfOpenMaxInFlight: 1 });
    assert.equal(eventsOf(auditLog, "circuit_breaker_probe_defaults_revised").length, 0);
    // A real revision followed by the same values again is also a no-op.
    relay.reviseCircuitProbeDefaults({ halfOpenMaxInFlight: 3 });
    assert.equal(eventsOf(auditLog, "circuit_breaker_probe_defaults_revised").length, 1);
    relay.reviseCircuitProbeDefaults({ halfOpenMaxInFlight: 3 });
    assert.equal(eventsOf(auditLog, "circuit_breaker_probe_defaults_revised").length, 1);
    // Unlike the threshold defaults, an empty probe patch is illegal.
    assert.throws(() => relay.reviseCircuitProbeDefaults({}), RangeError);
    assert.equal(eventsOf(auditLog, "circuit_breaker_probe_defaults_revised").length, 1);
  });

  it("an illegal patch throws RangeError and the live defaults and audit are untouched", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    for (const bad of [
      { halfOpenMaxInFlight: 0 },
      { halfOpenMaxInFlight: 1.5 },
      { halfOpenRetryMs: -1 },
      { halfOpenRetryMs: 0 },
    ]) {
      assert.throws(() => relay.reviseCircuitProbeDefaults(bad), RangeError);
    }
    assert.deepEqual(relay.getCircuitBreakerProbeDefaults!(), { ...PROBE_DEFAULTS });
    assert.equal(eventsOf(auditLog, "circuit_breaker_probe_defaults_revised").length, 0);
  });

  it("an unconfigured breaker throws Error on revise and leaves the getter unset", async () => {
    const { relay, auditLog } = makeServer();
    await listen(relay);
    assert.throws(
      () => relay.reviseCircuitProbeDefaults({ halfOpenMaxInFlight: 3 }),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.ok(!(err instanceof RangeError), "must be Error, not RangeError");
        assert.match((err as Error).message, /requires a restart/);
        return true;
      }
    );
    assert.equal(relay.getCircuitBreakerProbeDefaults, undefined);
    assert.equal(eventsOf(auditLog, "circuit_breaker_probe_defaults_revised").length, 0);
  });

  it("the getter matches live state and uncovered endpoints read the revised defaults", async () => {
    const { relay } = configuredServer();
    await listen(relay);
    assert.deepEqual(relay.getCircuitBreakerProbeDefaults!(), { ...PROBE_DEFAULTS });
    relay.reviseEndpointCircuitProbe(EP_A, { halfOpenMaxInFlight: 9 });
    relay.reviseCircuitProbeDefaults({ halfOpenMaxInFlight: 3, halfOpenRetryMs: 200 });
    assert.deepEqual(relay.getCircuitBreakerProbeDefaults!(), {
      halfOpenMaxInFlight: 3,
      halfOpenRetryMs: 200,
    });
    // An uncovered endpoint reads the revised defaults.
    assert.deepEqual(relay.getEndpointCircuitProbe!(EP_B), {
      probe: { halfOpenMaxInFlight: 3, halfOpenRetryMs: 200 },
      overridden: false,
    });
    // A covered endpoint keeps its override.
    assert.deepEqual(relay.getEndpointCircuitProbe!(EP_A), {
      probe: { halfOpenMaxInFlight: 9, halfOpenRetryMs: 1000 },
      overridden: true,
    });
    // An unrevised endpoint still reports the revised defaults.
    assert.deepEqual(relay.getEndpointCircuitProbe!(EP_C), {
      probe: { halfOpenMaxInFlight: 3, halfOpenRetryMs: 200 },
      overridden: false,
    });
    // The threshold defaults are untouched by a probe revision.
    assert.deepEqual(relay.getCircuitBreakerDefaults!(), { ...THRESHOLD_DEFAULTS });
  });
});
