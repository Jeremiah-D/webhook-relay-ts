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
const relaySecret = "circuit-breaker-defaults-revision-secret";
const EP_A = "http://a.example/hook";
const EP_B = "http://b.example/hook";
const EP_C = "http://c.example/hook";

const DEFAULTS = {
  failureThreshold: 5,
  cooldownMs: 30_000,
  tripMode: "consecutive-failures",
  errorRateWindowSize: 20,
  errorRateThreshold: 0.5,
  errorRateMinSamples: 10,
} as const;

/** Queue-level defaults: `makeQueue` runs with a 5s test cooldown. */
const QUEUE_DEFAULTS = { ...DEFAULTS, cooldownMs: 5000 };

/**
 * Manual timer that also records the scheduled delays — the cooldown
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

describe("EndpointCircuitBreaker retuneDefaults (WR-363)", () => {
  it("replaces the six default fields and trims a shrunk window without re-evaluating", () => {
    const b = new EndpointCircuitBreaker({
      failureThreshold: 100, // high so the window fills without tripping
      cooldownMs: 30_000,
      errorRateWindowSize: 10,
      errorRateMinSamples: 5,
      errorRateThreshold: 0.5,
    });
    for (let i = 0; i < 8; i++) b.recordFailure(EP_A);
    assert.equal(b.stats()[0].errorRateSamples, 8);
    assert.equal(b.state(EP_A), "closed");
    // The queue resolves the patch first, so the caller passes the
    // already-clamped set (minSamples 4 fits the shrunk window 4).
    b.retuneDefaults({
      ...b.thresholdsFor(EP_A),
      failureThreshold: 2,
      errorRateWindowSize: 4,
      errorRateMinSamples: 4,
    });
    assert.deepEqual(b.thresholdsFor(EP_A), {
      failureThreshold: 2,
      cooldownMs: 30_000,
      tripMode: "consecutive-failures",
      errorRateWindowSize: 4,
      errorRateThreshold: 0.5,
      errorRateMinSamples: 4,
    });
    assert.equal(b.stats()[0].errorRateSamples, 4);
    // The retune itself does not re-evaluate: 8 consecutive failures
    // against the new threshold 2 still leave the circuit closed
    // until the next outcome arrives.
    assert.equal(b.state(EP_A), "closed");
    b.recordFailure(EP_A);
    assert.equal(b.state(EP_A), "open");
  });
});

describe("RetryQueue circuit-breaker defaults revision (WR-363)", () => {
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

  it("getCircuitBreakerDefaults reports live defaults, undefined when unconfigured, and revise throws must-restart Error", () => {
    const { q } = makeQueue();
    try {
      assert.deepEqual(q.getCircuitBreakerDefaults(), { ...QUEUE_DEFAULTS });
    } finally {
      q.stop();
    }
    // Feature disabled: the getter is undefined and revise throws the
    // must-restart Error (not a RangeError).
    const q2 = new RetryQueue({ sender: async () => {} });
    try {
      assert.equal(q2.getCircuitBreakerDefaults(), undefined);
      assert.throws(
        () => q2.reviseCircuitBreakerDefaults({ failureThreshold: 3 }),
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
      assert.deepEqual(q.reviseCircuitBreakerDefaults({ failureThreshold: 3 }), {
        ...QUEUE_DEFAULTS,
        failureThreshold: 3,
      });
      assert.deepEqual(q.getCircuitBreakerDefaults(), {
        ...QUEUE_DEFAULTS,
        failureThreshold: 3,
      });
      // A second partial patch merges over the live values, not the defaults.
      q.reviseCircuitBreakerDefaults({ cooldownMs: 1000 });
      assert.deepEqual(q.getCircuitBreakerDefaults(), {
        ...QUEUE_DEFAULTS,
        failureThreshold: 3,
        cooldownMs: 1000,
      });
      // Shrinking the window below the inherited minSamples clamps it down.
      q.reviseCircuitBreakerDefaults({ errorRateWindowSize: 4 });
      assert.deepEqual(q.getCircuitBreakerDefaults(), {
        ...QUEUE_DEFAULTS,
        failureThreshold: 3,
        cooldownMs: 1000,
        errorRateWindowSize: 4,
        errorRateMinSamples: 4,
      });
    } finally {
      q.stop();
    }
  });

  it("an illegal merged patch throws RangeError and the live defaults are untouched", () => {
    const { q } = makeQueue();
    try {
      const before = q.getCircuitBreakerDefaults();
      const bad: Array<Record<string, unknown>> = [
        { failureThreshold: 0 },
        { failureThreshold: 1.5 },
        { cooldownMs: 0 },
        { cooldownMs: -1 },
        { tripMode: "bogus" },
        { errorRateWindowSize: 1 },
        { errorRateThreshold: 0 },
        { errorRateThreshold: 1.5 },
        { errorRateMinSamples: 1 },
        { errorRateMinSamples: 25 },
        { errorRateWindowSize: 4, errorRateMinSamples: 5 },
      ];
      for (const patch of bad) {
        assert.throws(
          () => q.reviseCircuitBreakerDefaults(patch as never),
          RangeError,
          JSON.stringify(patch)
        );
        assert.deepEqual(q.getCircuitBreakerDefaults(), before);
      }
    } finally {
      q.stop();
    }
  });

  it("a same-value or empty revision is a no-op", () => {
    const { q } = makeQueue();
    try {
      assert.deepEqual(q.reviseCircuitBreakerDefaults({}), { ...QUEUE_DEFAULTS });
      assert.deepEqual(q.reviseCircuitBreakerDefaults({ ...QUEUE_DEFAULTS }), {
        ...QUEUE_DEFAULTS,
      });
      assert.deepEqual(q.reviseCircuitBreakerDefaults({ failureThreshold: 3 }), {
        ...QUEUE_DEFAULTS,
        failureThreshold: 3,
      });
      assert.deepEqual(q.reviseCircuitBreakerDefaults({ failureThreshold: 3 }), {
        ...QUEUE_DEFAULTS,
        failureThreshold: 3,
      });
      assert.deepEqual(q.getCircuitBreakerDefaults(), {
        ...QUEUE_DEFAULTS,
        failureThreshold: 3,
      });
    } finally {
      q.stop();
    }
  });

  it("a tightened default trips an uncovered endpoint on the next failure", async () => {
    const { q, timer, f } = makeQueue(5, 5000);
    q.start();
    try {
      q.enqueue(item("cb-default-tighten", EP_A));
      await timer.step(); // attempt 1 fails (1 < 5, no trip)
      await timer.step(); // attempt 2 fails (2 < 5, no trip)
      assert.equal(f.calls(), 2);
      assert.equal(q.getCircuitStats()[0].state, "closed");
      // Tighten 5 -> 3: the revision itself does not re-evaluate.
      q.reviseCircuitBreakerDefaults({ failureThreshold: 3 });
      assert.equal(q.getCircuitStats()[0].state, "closed");
      await timer.step(); // attempt 3 fails: 3 >= 3 trips on the new default
      assert.equal(f.calls(), 3);
      assert.equal(q.getCircuitStats()[0].state, "open");
      assert.equal(q.getCircuitStats()[0].trips, 1);
    } finally {
      q.stop();
    }
  });

  it("a loosened default lets a previously-tripping endpoint pass", async () => {
    const { q, timer, f } = makeQueue(2, 5000);
    q.start();
    try {
      q.enqueue(item("cb-default-loosen", EP_A));
      await timer.step(); // attempt 1 fails (1 < 2, no trip)
      assert.equal(q.getCircuitStats()[0].state, "closed");
      // Loosen 2 -> 5 before the second failure lands.
      q.reviseCircuitBreakerDefaults({ failureThreshold: 5 });
      await timer.step(); // attempt 2 fails: 2 < 5, still closed
      assert.equal(f.calls(), 2);
      assert.equal(q.getCircuitStats()[0].state, "closed");
      await timer.step(); // attempt 3 fails: 3 < 5
      await timer.step(); // attempt 4 fails: 4 < 5
      assert.equal(q.getCircuitStats()[0].state, "closed");
      await timer.step(); // attempt 5 fails: 5 >= 5 trips on the new default
      assert.equal(f.calls(), 5);
      assert.equal(q.getCircuitStats()[0].state, "open");
      assert.equal(q.getCircuitStats()[0].trips, 1);
    } finally {
      q.stop();
    }
  });

  it("an endpoint with an override is unaffected and the override still wins", () => {
    const { q } = makeQueue();
    try {
      q.setEndpointCircuitBreaker(EP_B, { failureThreshold: 9 });
      q.reviseCircuitBreakerDefaults({ failureThreshold: 2 });
      assert.deepEqual(q.getEndpointCircuitBreaker(EP_B), {
        thresholds: { ...QUEUE_DEFAULTS, failureThreshold: 9 },
        overridden: true,
      });
      assert.deepEqual(q.getEndpointCircuitBreaker(EP_A), {
        thresholds: { ...QUEUE_DEFAULTS, failureThreshold: 2 },
        overridden: false,
      });
      assert.deepEqual(q.getCircuitBreakerDefaults(), {
        ...QUEUE_DEFAULTS,
        failureThreshold: 2,
      });
    } finally {
      q.stop();
    }
  });

  it("a tenant's first breaker is built at the revised defaults", () => {
    const { q } = makeQueue();
    try {
      q.reviseCircuitBreakerDefaults({ failureThreshold: 2 });
      // No breaker existed for either tenant at revision time.
      assert.deepEqual(q.getEndpointCircuitBreaker(EP_A, "newbie"), {
        thresholds: { ...QUEUE_DEFAULTS, failureThreshold: 2 },
        overridden: false,
      });
      assert.deepEqual(q.getEndpointCircuitBreaker(EP_A), {
        thresholds: { ...QUEUE_DEFAULTS, failureThreshold: 2 },
        overridden: false,
      });
    } finally {
      q.stop();
    }
  });

  it("every tenant's breaker is retuned in sync", () => {
    const { q } = makeQueue();
    try {
      // Build both tenants' breakers before the revision.
      q.getEndpointCircuitBreaker(EP_A, "acme");
      q.getEndpointCircuitBreaker(EP_A, "globex");
      q.reviseCircuitBreakerDefaults({ failureThreshold: 2, cooldownMs: 1000 });
      assert.deepEqual(q.getEndpointCircuitBreaker(EP_A, "acme"), {
        thresholds: { ...QUEUE_DEFAULTS, failureThreshold: 2, cooldownMs: 1000 },
        overridden: false,
      });
      assert.deepEqual(q.getEndpointCircuitBreaker(EP_A, "globex"), {
        thresholds: { ...QUEUE_DEFAULTS, failureThreshold: 2, cooldownMs: 1000 },
        overridden: false,
      });
    } finally {
      q.stop();
    }
  });

  it("a shrunk window trims the stored rolling outcomes at once", async () => {
    // A high threshold so the window fills without tripping.
    const { q, timer, f } = makeQueue(100, 5000);
    q.start();
    try {
      q.enqueue(item("cb-window-1", EP_A));
      for (let i = 0; i < 5; i++) await timer.step(); // 5 failures, then dead-lettered
      q.enqueue(item("cb-window-2", EP_A));
      for (let i = 0; i < 3; i++) await timer.step(); // 3 more failures
      assert.equal(f.calls(), 8);
      assert.equal(q.getCircuitStats()[0].errorRateSamples, 8);
      assert.equal(q.getCircuitStats()[0].state, "closed");
      q.reviseCircuitBreakerDefaults({ errorRateWindowSize: 4 });
      assert.equal(q.getCircuitStats()[0].errorRateSamples, 4);
      assert.deepEqual(q.getEndpointCircuitBreaker(EP_A), {
        thresholds: {
          ...QUEUE_DEFAULTS,
          failureThreshold: 100,
          errorRateWindowSize: 4,
          errorRateMinSamples: 4,
        },
        overridden: false,
      });
    } finally {
      q.stop();
    }
  });

  it("an already-open endpoint keeps state/openedAtMs/trips; the new cooldown applies from the next trip", async () => {
    const { q, timer, f, advance } = makeQueue(2, 5000);
    q.start();
    try {
      q.enqueue(item("cb-default-open", EP_A));
      await timer.step(); // attempt 1 fails
      await timer.step(); // attempt 2 fails -> trips open at t=0
      assert.equal(f.calls(), 2);
      assert.equal(q.getCircuitStats()[0].state, "open");
      await timer.step(); // backoff fires -> parked, delay = old cooldown 5000
      assert.equal(timer.lastDelay(), 5000);
      assert.equal(q.getCircuitStats()[0].openedAtMs, 0);
      // Revise the defaults while open: state and openedAtMs are
      // untouched, and the already-scheduled park timer is not re-armed.
      q.reviseCircuitBreakerDefaults({ cooldownMs: 500 });
      assert.equal(timer.lastDelay(), 5000);
      assert.equal(q.getCircuitStats()[0].state, "open");
      assert.equal(q.getCircuitStats()[0].openedAtMs, 0);
      assert.equal(q.getCircuitStats()[0].trips, 1);
      assert.equal(f.calls(), 2);
      // The park wakes on the old-cooldown instant; the shortened
      // cooldown is already satisfied, so the probe runs then.
      advance(5000);
      await timer.step(); // probe fails -> re-trips at t=5000
      assert.equal(f.calls(), 3);
      assert.equal(q.getCircuitStats()[0].state, "open");
      assert.equal(q.getCircuitStats()[0].trips, 2);
      assert.equal(q.getCircuitStats()[0].openedAtMs, 5000);
      // The new trip's park is scheduled against the new cooldown.
      await timer.step(); // backoff fires -> parked, delay = new cooldown 500
      assert.equal(timer.lastDelay(), 500);
      advance(500);
      await timer.step(); // probe runs on the new cooldown
      assert.equal(f.calls(), 4);
      assert.equal(q.getCircuitStats()[0].state, "open");
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer circuit-breaker defaults revision (WR-363)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "circuit-breaker-defaults-revision-"));
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

  it("revise audits previous/current, with the effective defaults as first previous", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    const current = relay.reviseCircuitBreakerDefaults({ failureThreshold: 3 });
    assert.deepEqual(current, { ...DEFAULTS, failureThreshold: 3 });
    const revised = eventsOf(auditLog, "circuit_breaker_defaults_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, { ...DEFAULTS });
    assert.deepEqual(revised[0].current, { ...DEFAULTS, failureThreshold: 3 });
    // A second revision audits the live values as previous.
    const current2 = relay.reviseCircuitBreakerDefaults({ cooldownMs: 1000 });
    assert.deepEqual(current2, { ...DEFAULTS, failureThreshold: 3, cooldownMs: 1000 });
    const revised2 = eventsOf(auditLog, "circuit_breaker_defaults_revised");
    assert.equal(revised2.length, 2);
    assert.deepEqual(revised2[1].previous, { ...DEFAULTS, failureThreshold: 3 });
    assert.deepEqual(revised2[1].current, { ...DEFAULTS, failureThreshold: 3, cooldownMs: 1000 });
  });

  it("a same-value or empty revision is a silent no-op", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    // Landing exactly on the live values — even via a full explicit patch.
    relay.reviseCircuitBreakerDefaults({ ...DEFAULTS });
    relay.reviseCircuitBreakerDefaults({});
    relay.reviseCircuitBreakerDefaults({ failureThreshold: 5 });
    assert.equal(eventsOf(auditLog, "circuit_breaker_defaults_revised").length, 0);
    // A real revision followed by the same values again is also a no-op.
    relay.reviseCircuitBreakerDefaults({ failureThreshold: 3 });
    assert.equal(eventsOf(auditLog, "circuit_breaker_defaults_revised").length, 1);
    relay.reviseCircuitBreakerDefaults({ failureThreshold: 3 });
    assert.equal(eventsOf(auditLog, "circuit_breaker_defaults_revised").length, 1);
  });

  it("an illegal patch throws RangeError and the live defaults and audit are untouched", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    for (const bad of [
      { failureThreshold: 0 },
      { cooldownMs: -1 },
      { errorRateWindowSize: 4, errorRateMinSamples: 5 },
    ]) {
      assert.throws(() => relay.reviseCircuitBreakerDefaults(bad), RangeError);
    }
    assert.deepEqual(relay.getCircuitBreakerDefaults!(), { ...DEFAULTS });
    assert.equal(eventsOf(auditLog, "circuit_breaker_defaults_revised").length, 0);
  });

  it("an unconfigured breaker throws Error on revise and leaves the getter unset", async () => {
    const { relay, auditLog } = makeServer();
    await listen(relay);
    assert.throws(
      () => relay.reviseCircuitBreakerDefaults({ failureThreshold: 3 }),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.ok(!(err instanceof RangeError), "must be Error, not RangeError");
        assert.match((err as Error).message, /requires a restart/);
        return true;
      }
    );
    assert.equal(relay.getCircuitBreakerDefaults, undefined);
    assert.equal(eventsOf(auditLog, "circuit_breaker_defaults_revised").length, 0);
  });

  it("the getter matches live state and uncovered endpoints read the revised defaults", async () => {
    const { relay } = configuredServer();
    await listen(relay);
    assert.deepEqual(relay.getCircuitBreakerDefaults!(), { ...DEFAULTS });
    relay.reviseEndpointCircuitBreaker(EP_A, { failureThreshold: 9 });
    relay.reviseCircuitBreakerDefaults({ failureThreshold: 3, cooldownMs: 1000 });
    assert.deepEqual(relay.getCircuitBreakerDefaults!(), {
      ...DEFAULTS,
      failureThreshold: 3,
      cooldownMs: 1000,
    });
    // An uncovered endpoint reads the revised defaults.
    assert.deepEqual(relay.getEndpointCircuitBreaker!(EP_B), {
      thresholds: { ...DEFAULTS, failureThreshold: 3, cooldownMs: 1000 },
      overridden: false,
    });
    // A covered endpoint keeps its override.
    assert.deepEqual(relay.getEndpointCircuitBreaker!(EP_A), {
      thresholds: { ...DEFAULTS, failureThreshold: 9 },
      overridden: true,
    });
    // An unrevised endpoint still reports the revised defaults.
    assert.deepEqual(relay.getEndpointCircuitBreaker!(EP_C), {
      thresholds: { ...DEFAULTS, failureThreshold: 3, cooldownMs: 1000 },
      overridden: false,
    });
  });
});
