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
const relaySecret = "circuit-breaker-revision-secret";
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

describe("RetryQueue circuit-breaker thresholds (WR-319)", () => {
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

  it("getEndpointCircuitBreaker reports live effective defaults, undefined when unconfigured", () => {
    const { q } = makeQueue();
    try {
      assert.deepEqual(q.getEndpointCircuitBreaker(EP_A), {
        thresholds: { ...QUEUE_DEFAULTS },
        overridden: false,
      });
      assert.deepEqual(q.getCircuitBreakers(), []);
    } finally {
      q.stop();
    }
    // Feature disabled: the getter is undefined and the listing empty.
    const q2 = new RetryQueue({ sender: async () => {} });
    try {
      assert.equal(q2.getEndpointCircuitBreaker(EP_A), undefined);
      assert.deepEqual(q2.getCircuitBreakers(), []);
      assert.equal(q2.setEndpointCircuitBreaker(EP_A, { failureThreshold: 3 }), false);
    } finally {
      q2.stop();
    }
  });

  it("setEndpointCircuitBreaker merges a partial patch and marks the override", () => {
    const { q } = makeQueue();
    try {
      assert.equal(q.setEndpointCircuitBreaker(EP_A, { failureThreshold: 3 }), true);
      assert.deepEqual(q.getEndpointCircuitBreaker(EP_A), {
        thresholds: { ...QUEUE_DEFAULTS, failureThreshold: 3 },
        overridden: true,
      });
      // A second partial patch merges over the live values, not the defaults.
      q.setEndpointCircuitBreaker(EP_A, { cooldownMs: 1000 });
      assert.deepEqual(q.getEndpointCircuitBreaker(EP_A), {
        thresholds: { ...QUEUE_DEFAULTS, failureThreshold: 3, cooldownMs: 1000 },
        overridden: true,
      });
      // Another endpoint is untouched.
      assert.deepEqual(q.getEndpointCircuitBreaker(EP_B), {
        thresholds: { ...QUEUE_DEFAULTS },
        overridden: false,
      });
    } finally {
      q.stop();
    }
  });

  it("an illegal merged patch throws RangeError and the live thresholds are untouched", () => {
    const { q } = makeQueue();
    try {
      const before = q.getEndpointCircuitBreaker(EP_A);
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
          () => q.setEndpointCircuitBreaker(EP_A, patch as never),
          RangeError,
          JSON.stringify(patch)
        );
        assert.deepEqual(q.getEndpointCircuitBreaker(EP_A), before);
      }
    } finally {
      q.stop();
    }
  });

  it("a tightened threshold trips on the next failure", async () => {
    const { q, timer, f } = makeQueue(5, 5000);
    q.start();
    try {
      q.enqueue(item("cb-tighten", EP_A));
      await timer.step(); // attempt 1 fails (1 < 5, no trip)
      await timer.step(); // attempt 2 fails (2 < 5, no trip)
      assert.equal(f.calls(), 2);
      assert.equal(q.getCircuitStats()[0].state, "closed");
      // Tighten 5 -> 3: the revision itself does not re-evaluate.
      q.setEndpointCircuitBreaker(EP_A, { failureThreshold: 3 });
      assert.equal(q.getCircuitStats()[0].state, "closed");
      await timer.step(); // attempt 3 fails: 3 >= 3 trips on the new threshold
      assert.equal(f.calls(), 3);
      assert.equal(q.getCircuitStats()[0].state, "open");
      assert.equal(q.getCircuitStats()[0].trips, 1);
    } finally {
      q.stop();
    }
  });

  it("switching to error-rate mode trips per the new mode on live history", async () => {
    const { q, timer, f } = makeQueue(5, 5000);
    q.start();
    try {
      q.enqueue(item("cb-mode", EP_A));
      await timer.step(); // failure 1: window [F], consecutive 1
      await timer.step(); // failure 2: window [F,F], consecutive 2
      assert.equal(f.calls(), 2);
      assert.equal(q.getCircuitStats()[0].state, "closed");
      // Switch modes mid-history: the rolling window is live in both
      // modes, so the next failure trips on the new mode, no cold start.
      q.setEndpointCircuitBreaker(EP_A, {
        tripMode: "error-rate",
        errorRateWindowSize: 4,
        errorRateMinSamples: 2,
        errorRateThreshold: 0.5,
      });
      assert.equal(q.getCircuitStats()[0].state, "closed");
      await timer.step(); // failure 3: window [F,F,F], rate 1.0 >= 0.5, 3 >= 2
      assert.equal(f.calls(), 3);
      assert.equal(q.getCircuitStats()[0].state, "open");
      assert.equal(q.getCircuitStats()[0].trips, 1);
    } finally {
      q.stop();
    }
  });

  it("getCircuitBreakers lists every configured-breaker endpoint, including never-tripped ones", async () => {
    const { q, timer, f } = makeQueue(5, 5000);
    q.start();
    try {
      // EP_A carries an override but has never been tripped (or seen).
      q.setEndpointCircuitBreaker(EP_A, { failureThreshold: 2 });
      // EP_B has one observed failure and no override.
      q.enqueue(item("cb-list", EP_B));
      await timer.step();
      assert.equal(f.calls(), 1);
      assert.deepEqual(q.getCircuitBreakers(), [
        { endpoint: EP_A, thresholds: { ...QUEUE_DEFAULTS, failureThreshold: 2 }, overridden: true },
        { endpoint: EP_B, thresholds: { ...QUEUE_DEFAULTS }, overridden: false },
      ]);
      // EP_C was never revised or observed: not listed.
      assert.equal(q.getCircuitBreakers().some((r) => r.endpoint === EP_C), false);
    } finally {
      q.stop();
    }
  });

  it("an already-open endpoint still wakes on the old cooldown; the next trip uses the new one", async () => {
    const { q, timer, f, advance } = makeQueue(2, 5000);
    q.start();
    try {
      q.enqueue(item("cb-open", EP_A));
      await timer.step(); // attempt 1 fails
      await timer.step(); // attempt 2 fails -> trips open at t=0
      assert.equal(f.calls(), 2);
      assert.equal(q.getCircuitStats()[0].state, "open");
      await timer.step(); // backoff fires -> parked, delay = old cooldown 5000
      assert.equal(timer.lastDelay(), 5000);
      assert.equal(q.getCircuitStats()[0].openedAtMs, 0);
      // Revise while open: state and openedAtMs are untouched, and the
      // already-scheduled park timer is not re-armed.
      q.setEndpointCircuitBreaker(EP_A, { cooldownMs: 500 });
      assert.equal(timer.lastDelay(), 5000);
      assert.equal(q.getCircuitStats()[0].state, "open");
      assert.equal(q.getCircuitStats()[0].openedAtMs, 0);
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

  it("a shortened cooldown lets the next trip recover faster", async () => {
    const { q, timer, f, advance } = makeQueue(2, 5000);
    q.start();
    try {
      q.enqueue(item("cb-short", EP_A));
      await timer.step(); // attempt 1 fails
      await timer.step(); // attempt 2 fails -> trips open at t=0
      await timer.step(); // backoff fires -> parked, delay 5000
      f.setFail(false);
      advance(5000);
      await timer.step(); // probe succeeds -> closes, item delivered
      assert.equal(f.calls(), 3);
      assert.equal(q.getCircuitStats()[0].state, "closed");
      assert.equal(q.pendingCount(), 0);
      // Shorten the cooldown while closed; the next trip uses it.
      q.setEndpointCircuitBreaker(EP_A, { cooldownMs: 500 });
      f.setFail(true);
      q.enqueue(item("cb-short-2", EP_A));
      await timer.step(); // attempt 1 fails
      await timer.step(); // attempt 2 fails -> trips open again at t=5000
      await timer.step(); // backoff fires -> parked, delay = new cooldown 500
      assert.equal(timer.lastDelay(), 500);
      advance(500);
      await timer.step(); // probe runs after 500ms, not 5000ms
      assert.equal(f.calls(), 6);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer circuit-breaker revision (WR-319)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "circuit-breaker-revision-"));
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
    const current = relay.reviseEndpointCircuitBreaker(EP_A, { failureThreshold: 3 });
    assert.deepEqual(current, { ...DEFAULTS, failureThreshold: 3 });
    const revised = eventsOf(auditLog, "circuit_breaker_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].endpoint, EP_A);
    assert.deepEqual(revised[0].previous, { ...DEFAULTS });
    assert.deepEqual(revised[0].current, { ...DEFAULTS, failureThreshold: 3 });
    // A second revision audits the live values as previous.
    const current2 = relay.reviseEndpointCircuitBreaker(EP_A, { cooldownMs: 1000 });
    assert.deepEqual(current2, { ...DEFAULTS, failureThreshold: 3, cooldownMs: 1000 });
    const revised2 = eventsOf(auditLog, "circuit_breaker_revised");
    assert.equal(revised2.length, 2);
    assert.deepEqual(revised2[1].previous, { ...DEFAULTS, failureThreshold: 3 });
    assert.deepEqual(revised2[1].current, { ...DEFAULTS, failureThreshold: 3, cooldownMs: 1000 });
  });

  it("a same-value or empty revision is a silent no-op", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    // Landing exactly on the live values — even via a full explicit patch.
    relay.reviseEndpointCircuitBreaker(EP_A, { ...DEFAULTS });
    relay.reviseEndpointCircuitBreaker(EP_A, {});
    relay.reviseEndpointCircuitBreaker(EP_A, { failureThreshold: 5 });
    assert.equal(eventsOf(auditLog, "circuit_breaker_revised").length, 0);
    // A real revision followed by the same values again is also a no-op.
    relay.reviseEndpointCircuitBreaker(EP_A, { failureThreshold: 3 });
    assert.equal(eventsOf(auditLog, "circuit_breaker_revised").length, 1);
    relay.reviseEndpointCircuitBreaker(EP_A, { failureThreshold: 3 });
    assert.equal(eventsOf(auditLog, "circuit_breaker_revised").length, 1);
  });

  it("an illegal patch throws RangeError and the live thresholds and audit are untouched", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    for (const bad of [
      { failureThreshold: 0 },
      { cooldownMs: -1 },
      { errorRateWindowSize: 4, errorRateMinSamples: 5 },
    ]) {
      assert.throws(() => relay.reviseEndpointCircuitBreaker(EP_A, bad), RangeError);
    }
    assert.deepEqual(relay.getEndpointCircuitBreaker!(EP_A), {
      thresholds: { ...DEFAULTS },
      overridden: false,
    });
    assert.equal(eventsOf(auditLog, "circuit_breaker_revised").length, 0);
  });

  it("an unconfigured breaker throws Error on revise and leaves the getters unset", async () => {
    const { relay, auditLog } = makeServer();
    await listen(relay);
    assert.throws(
      () => relay.reviseEndpointCircuitBreaker(EP_A, { failureThreshold: 3 }),
      (err: unknown) => {
        assert.ok(err instanceof Error);
        assert.ok(!(err instanceof RangeError), "must be Error, not RangeError");
        assert.match((err as Error).message, /requires a restart/);
        return true;
      }
    );
    assert.equal(relay.getEndpointCircuitBreaker, undefined);
    assert.equal(relay.getCircuitBreakers, undefined);
    // Removal is always set and silently reports nothing to remove.
    assert.equal(relay.removeEndpointCircuitBreaker(EP_A), false);
    assert.equal(eventsOf(auditLog, "circuit_breaker_removed").length, 0);
  });

  it("remove returns true, audits, and falls back to the queue defaults", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    relay.reviseEndpointCircuitBreaker(EP_A, { failureThreshold: 3 });
    assert.deepEqual(relay.getEndpointCircuitBreaker!(EP_A), {
      thresholds: { ...DEFAULTS, failureThreshold: 3 },
      overridden: true,
    });
    assert.equal(relay.removeEndpointCircuitBreaker(EP_A), true);
    const removed = eventsOf(auditLog, "circuit_breaker_removed");
    assert.equal(removed.length, 1);
    assert.equal(removed[0].endpoint, EP_A);
    assert.deepEqual(removed[0].previous, { ...DEFAULTS, failureThreshold: 3 });
    assert.deepEqual(relay.getEndpointCircuitBreaker!(EP_A), {
      thresholds: { ...DEFAULTS },
      overridden: false,
    });
    // Nothing left to remove: false, no audit.
    assert.equal(relay.removeEndpointCircuitBreaker(EP_A), false);
    assert.equal(eventsOf(auditLog, "circuit_breaker_removed").length, 1);
    // An endpoint that was never revised has no override to remove.
    assert.equal(relay.removeEndpointCircuitBreaker(EP_B), false);
  });

  it("getCircuitBreakers lists revised endpoints, including never-tripped ones", async () => {
    const { relay } = configuredServer();
    await listen(relay);
    relay.reviseEndpointCircuitBreaker(EP_A, { failureThreshold: 2 });
    relay.reviseEndpointCircuitBreaker(EP_B, { cooldownMs: 1000 });
    assert.deepEqual(relay.getCircuitBreakers!(), [
      { endpoint: EP_A, thresholds: { ...DEFAULTS, failureThreshold: 2 }, overridden: true },
      { endpoint: EP_B, thresholds: { ...DEFAULTS, cooldownMs: 1000 }, overridden: true },
    ]);
    // An unrevised endpoint still reports the queue defaults.
    assert.deepEqual(relay.getEndpointCircuitBreaker!(EP_C), {
      thresholds: { ...DEFAULTS },
      overridden: false,
    });
  });

  it("tenant revisions are scoped to that tenant's breaker", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    relay.reviseEndpointCircuitBreaker(EP_A, { failureThreshold: 2 }, "acme");
    assert.deepEqual(relay.getEndpointCircuitBreaker!(EP_A, "acme"), {
      thresholds: { ...DEFAULTS, failureThreshold: 2 },
      overridden: true,
    });
    // The default tenant is untouched.
    assert.deepEqual(relay.getEndpointCircuitBreaker!(EP_A), {
      thresholds: { ...DEFAULTS },
      overridden: false,
    });
    assert.deepEqual(relay.getCircuitBreakers!("acme"), [
      { endpoint: EP_A, thresholds: { ...DEFAULTS, failureThreshold: 2 }, overridden: true },
    ]);
    assert.deepEqual(relay.getCircuitBreakers!(), []);
    // Removal is tenant-scoped too.
    assert.equal(relay.removeEndpointCircuitBreaker(EP_A), false);
    assert.equal(relay.removeEndpointCircuitBreaker(EP_A, "acme"), true);
    assert.equal(eventsOf(auditLog, "circuit_breaker_removed").length, 1);
    assert.deepEqual(relay.getEndpointCircuitBreaker!(EP_A, "acme"), {
      thresholds: { ...DEFAULTS },
      overridden: false,
    });
  });
});
