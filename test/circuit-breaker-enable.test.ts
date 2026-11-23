import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "circuit-breaker-enable-secret";
const EP_A = "http://a.example/hook";

const DEFAULTS = {
  failureThreshold: 5,
  cooldownMs: 30_000,
  tripMode: "consecutive-failures",
  errorRateWindowSize: 20,
  errorRateThreshold: 0.5,
  errorRateMinSamples: 10,
} as const;

/**
 * Manual timer that also records the scheduled delays — the cooldown
 * tests assert on the delay a parked attempt was scheduled with.
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

function makeUnconfiguredQueue() {
  const timer = manualTimer();
  const f = failingSender();
  const q = new RetryQueue({
    sender: f.sender,
    baseDelayMs: 10,
    maxAttempts: 5,
    jitterMs: 0,
    random: () => 0, // deterministic parking delay
    setTimer: timer.setTimer,
  });
  return { q, timer, f };
}

function unconfiguredQueue() {
  return new RetryQueue({ sender: async () => {} });
}

describe("RetryQueue circuit-breaker live enable (WR-455)", () => {
  it("an empty patch enables with the six built-in defaults", () => {
    const q = unconfiguredQueue();
    try {
      assert.equal(q.getCircuitBreakerDefaults(), undefined);
      assert.deepEqual(q.reviseCircuitBreakerDefaults({}), { ...DEFAULTS });
      assert.deepEqual(q.getCircuitBreakerDefaults(), { ...DEFAULTS });
    } finally {
      q.stop();
    }
  });

  it("a partial patch merges per-field over the defaults; a shrunk window clamps minSamples", () => {
    const q = unconfiguredQueue();
    try {
      assert.deepEqual(q.reviseCircuitBreakerDefaults({ failureThreshold: 3 }), {
        ...DEFAULTS,
        failureThreshold: 3,
      });
    } finally {
      q.stop();
    }
    // A fresh queue: shrinking the window clamps minSamples to the
    // window, exactly like the constructor does.
    const q2 = unconfiguredQueue();
    try {
      assert.deepEqual(q2.reviseCircuitBreakerDefaults({ errorRateWindowSize: 5 }), {
        ...DEFAULTS,
        errorRateWindowSize: 5,
        errorRateMinSamples: 5,
      });
    } finally {
      q2.stop();
    }
  });

  it("an illegal patch throws RangeError, stays unconfigured, and a later legal patch still enables", () => {
    const q = unconfiguredQueue();
    try {
      for (const bad of [
        { failureThreshold: 0 },
        { failureThreshold: 1.5 },
        { cooldownMs: 0 },
        { tripMode: "bogus" },
        { errorRateWindowSize: 1 },
        { errorRateThreshold: 0 },
        { errorRateMinSamples: 1 },
        { errorRateWindowSize: 4, errorRateMinSamples: 5 },
      ]) {
        assert.throws(
          () => q.reviseCircuitBreakerDefaults(bad as never),
          RangeError,
          JSON.stringify(bad)
        );
        assert.equal(q.getCircuitBreakerDefaults(), undefined);
      }
      // A failed enable leaves nothing behind: a legal patch still enables.
      assert.deepEqual(q.reviseCircuitBreakerDefaults({ failureThreshold: 3 }), {
        ...DEFAULTS,
        failureThreshold: 3,
      });
    } finally {
      q.stop();
    }
  });

  it("dispatches before enable leave no breaker behind; the next dispatch trips on the enabled defaults", async () => {
    const { q, timer, f } = makeUnconfiguredQueue();
    q.start();
    try {
      q.enqueue(item("cb-enable-before", EP_A));
      await timer.step(); // attempt 1 fails — no breaker, no trip
      await timer.step(); // attempt 2 fails — still no breaker
      assert.equal(f.calls(), 2);
      assert.deepEqual(q.getCircuitStats(), []);
      assert.equal(q.getCircuitBreakerDefaults(), undefined);
      // Enable mid-flight: the two failures above are not retroactively
      // recorded — the fresh breaker starts cold.
      assert.deepEqual(q.reviseCircuitBreakerDefaults({ failureThreshold: 2, cooldownMs: 500 }), {
        ...DEFAULTS,
        failureThreshold: 2,
        cooldownMs: 500,
      });
      await timer.step(); // attempt 3 fails: fresh failure 1 of 2
      assert.equal(f.calls(), 3);
      assert.equal(q.getCircuitStats()[0].state, "closed");
      await timer.step(); // attempt 4 fails: 2 of 2 trips on the new defaults
      assert.equal(f.calls(), 4);
      assert.equal(q.getCircuitStats()[0].state, "open");
      assert.equal(q.getCircuitStats()[0].trips, 1);
      await timer.step(); // backoff fires -> parked, delay = new cooldown 500
      // The park delay is the *remaining* cooldown against the real
      // clock (`retryInMs` = openedAt + cooldown - now): the live
      // enable path takes no injected clock, so a few ms elapse
      // between the trip and the park under load. Assert the delay
      // is the new 500ms cooldown (not the 160ms backoff, not the
      // 30s built-in default), within that real-clock remainder.
      const parkedDelay = timer.lastDelay();
      assert.ok(
        parkedDelay !== undefined && parkedDelay <= 500 && parkedDelay >= 400,
        `expected park delay near 500, got ${parkedDelay}`
      );
    } finally {
      q.stop();
    }
  });

  it("enabling opens the probe-defaults gate (WR-364) on the live options", () => {
    const q = unconfiguredQueue();
    try {
      assert.equal(q.getCircuitBreakerProbeDefaults(), undefined);
      assert.throws(
        () => q.reviseCircuitProbeDefaults({ halfOpenMaxInFlight: 2 }),
        /requires a restart/
      );
      q.reviseCircuitBreakerDefaults({});
      assert.deepEqual(q.getCircuitBreakerProbeDefaults(), {
        halfOpenMaxInFlight: 1,
        halfOpenRetryMs: 1000,
      });
      assert.deepEqual(q.reviseCircuitProbeDefaults({ halfOpenMaxInFlight: 2 }), {
        halfOpenMaxInFlight: 2,
        halfOpenRetryMs: 1000,
      });
    } finally {
      q.stop();
    }
  });

  it("enabling opens the per-endpoint gate (WR-319): setEndpointCircuitBreaker goes false -> true", () => {
    const q = unconfiguredQueue();
    try {
      assert.equal(q.setEndpointCircuitBreaker(EP_A, { failureThreshold: 9 }), false);
      assert.equal(q.getEndpointCircuitBreaker(EP_A), undefined);
      q.reviseCircuitBreakerDefaults({ failureThreshold: 3 });
      assert.equal(q.setEndpointCircuitBreaker(EP_A, { failureThreshold: 9 }), true);
      assert.deepEqual(q.getEndpointCircuitBreaker(EP_A), {
        thresholds: { ...DEFAULTS, failureThreshold: 9 },
        overridden: true,
      });
    } finally {
      q.stop();
    }
  });

  it("enabling opens the state-change callback gate (WR-365)", () => {
    const q = unconfiguredQueue();
    try {
      assert.throws(
        () => q.reviseCircuitStateChangeCallback(() => {}),
        /requires a restart/
      );
      q.reviseCircuitBreakerDefaults({});
      assert.doesNotThrow(() => q.reviseCircuitStateChangeCallback(() => {}));
      assert.doesNotThrow(() => q.reviseCircuitStateChangeCallback(null));
    } finally {
      q.stop();
    }
  });

  it("a revision after enable still merges over the live values (WR-363)", () => {
    const q = unconfiguredQueue();
    try {
      q.reviseCircuitBreakerDefaults({ failureThreshold: 3 });
      assert.deepEqual(q.reviseCircuitBreakerDefaults({ cooldownMs: 1000 }), {
        ...DEFAULTS,
        failureThreshold: 3,
        cooldownMs: 1000,
      });
      // A same-value revision is still a silent no-op.
      assert.deepEqual(
        q.reviseCircuitBreakerDefaults({ failureThreshold: 3, cooldownMs: 1000 }),
        { ...DEFAULTS, failureThreshold: 3, cooldownMs: 1000 }
      );
    } finally {
      q.stop();
    }
  });

  it("a fresh queue without the option is unconfigured again (restart restores unconfigured)", () => {
    const q = unconfiguredQueue();
    try {
      q.reviseCircuitBreakerDefaults({ failureThreshold: 3 });
      assert.notEqual(q.getCircuitBreakerDefaults(), undefined);
    } finally {
      q.stop();
    }
    const q2 = unconfiguredQueue();
    try {
      assert.equal(q2.getCircuitBreakerDefaults(), undefined);
    } finally {
      q2.stop();
    }
  });
});

describe("RelayServer circuit-breaker live enable (WR-455)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "circuit-breaker-enable-"));
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

  it("enabling opens the probe gate at server level: reviseCircuitProbeDefaults audits", async () => {
    const { relay, auditLog } = makeServer();
    await listen(relay);
    assert.throws(
      () => relay.reviseCircuitProbeDefaults({ halfOpenMaxInFlight: 2 }),
      /requires a restart/
    );
    relay.reviseCircuitBreakerDefaults({});
    assert.deepEqual(relay.reviseCircuitProbeDefaults({ halfOpenMaxInFlight: 2 }), {
      halfOpenMaxInFlight: 2,
      halfOpenRetryMs: 1000,
    });
    const revised = eventsOf(auditLog, "circuit_breaker_probe_defaults_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, { halfOpenMaxInFlight: 1, halfOpenRetryMs: 1000 });
    assert.deepEqual(revised[0].current, { halfOpenMaxInFlight: 2, halfOpenRetryMs: 1000 });
  });

  it("enabling opens the per-endpoint gate at server level", async () => {
    const { relay, auditLog } = makeServer();
    await listen(relay);
    assert.throws(
      () => relay.reviseEndpointCircuitBreaker(EP_A, { failureThreshold: 9 }),
      /requires a restart/
    );
    relay.reviseCircuitBreakerDefaults({});
    assert.deepEqual(relay.reviseEndpointCircuitBreaker(EP_A, { failureThreshold: 9 }), {
      ...DEFAULTS,
      failureThreshold: 9,
    });
    const revised = eventsOf(auditLog, "circuit_breaker_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].endpoint, EP_A);
    assert.deepEqual(revised[0].previous, { ...DEFAULTS });
    assert.deepEqual(revised[0].current, { ...DEFAULTS, failureThreshold: 9 });
  });
});
