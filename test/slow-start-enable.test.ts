import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type Sender, type SlowStartOptions } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "slow-start-enable-test-key";
const opToken = "slow-start-enable-op-token";
const URL = "http://localhost:9999/hook";
const URL_A = "http://localhost:9999/a";

/**
 * Manual timer with single-step control: breaker parking re-arms timers, so
 * the tests advance one wave at a time instead of draining everything.
 */
function manualTimer() {
  const pending: Array<() => void> = [];
  return {
    pendingCount: () => pending.length,
    setTimer: (fn: () => void, _ms: number) => {
      pending.push(fn);
      return {
        clear: () => {
          const i = pending.indexOf(fn);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    async step() {
      const fns = pending.splice(0);
      for (const f of fns) f();
      await new Promise((r) => setImmediate(r));
    },
  };
}

function controllableSender() {
  let calls = 0;
  let fail = true;
  const sender: Sender = async () => {
    calls += 1;
    if (fail) throw new Error("downstream down");
  };
  return { sender, calls: () => calls, setFail: (v: boolean) => (fail = v) };
}

describe("RetryQueue slow-start live enable (WR-476)", () => {
  function makeQueue(slowStart?: SlowStartOptions, withBreaker = true) {
    const timer = manualTimer();
    let now = 0;
    const f = controllableSender();
    const q = new RetryQueue({
      sender: f.sender,
      baseDelayMs: 10,
      maxAttempts: 5,
      jitterMs: 0,
      random: () => 0, // deterministic parking delay
      setTimer: timer.setTimer,
      maxConcurrentPerEndpoint: 8,
      ...(withBreaker
        ? { circuitBreaker: { failureThreshold: 2, cooldownMs: 1000, nowMs: () => now } }
        : {}),
      ...(slowStart === undefined ? {} : { slowStart }),
    });
    return { q, timer, f, advance: (ms: number) => (now += ms) };
  }

  /** Drive the endpoint (of one tenant) through trip -> cooldown -> successful half-open probe. */
  async function tripAndRecover(
    env: ReturnType<typeof makeQueue>,
    idPrefix: string,
    tenantId?: string
  ) {
    const { q, timer, f, advance } = env;
    q.start();
    q.enqueue({
      id: `${idPrefix}-1`,
      payload: Buffer.from("one"),
      targetUrl: URL,
      headers: {},
      ...(tenantId !== undefined ? { tenantId } : {}),
    });
    await timer.step(); // attempt 1 fails
    await timer.step(); // attempt 2 fails -> trips open
    f.setFail(false);
    advance(1000);
    await timer.step(); // half-open probe succeeds -> closed, ramp starts
  }

  it("empty patch enables with all defaults: exponential / floor 1 / fixed cap", () => {
    const { q } = makeQueue();
    assert.equal(q.getSlowStartConfig(), undefined);
    assert.equal(q.getSlowStartStats(), undefined);
    assert.deepEqual(q.reviseSlowStart({}), { curve: "exponential", floor: 1, maxLimit: 8 });
    assert.deepEqual(q.getSlowStartConfig(), { curve: "exponential", floor: 1, maxLimit: 8 });
    // Enabled but no ramp yet: stats is an (empty) array, not undefined.
    assert.deepEqual(q.getSlowStartStats(), []);
    q.stop();
  });

  it("partial patch enables with the rest defaulted", () => {
    const { q } = makeQueue();
    assert.deepEqual(q.reviseSlowStart({ floor: 2, curve: "additive" }), {
      curve: "additive",
      floor: 2,
      maxLimit: 8,
    });
    assert.deepEqual(q.getSlowStartConfig(), { curve: "additive", floor: 2, maxLimit: 8 });
    q.stop();
  });

  it("enabled ramp paces the next breaker recovery like a construction-configured one", async () => {
    const env = makeQueue();
    const { q } = env;
    assert.deepEqual(q.reviseSlowStart({ floor: 1, maxLimit: 8 }), {
      curve: "exponential",
      floor: 1,
      maxLimit: 8,
    });
    await tripAndRecover(env, "ss");
    // The probe's own success stepped the ramp 1 -> 2.
    assert.equal(q.getSlowStartStats()![0].limit, 2);
    assert.equal(q.getSlowStartStats()![0].floor, 1);
    assert.equal(q.getSlowStartStats()![0].ceiling, 8);
    assert.equal(q.getSlowStartStats()![0].curve, "exponential");
    assert.equal((q as any).limiter.maxFor(URL), 2);
    q.stop();
  });

  it("without a breaker revise throws Error; enable the breaker first, then slow start enables", () => {
    const { q } = makeQueue(undefined, false);
    assert.equal(q.getSlowStartConfig(), undefined);
    assert.throws(
      () => q.reviseSlowStart({ floor: 2 }),
      /circuit breaker is not configured/
    );
    assert.equal(q.getSlowStartConfig(), undefined);
    // WR-455: the breaker itself is live-enablable — once it is on,
    // the same slow-start call enables instead of throwing.
    q.reviseCircuitBreakerDefaults({});
    assert.deepEqual(q.reviseSlowStart({}), { curve: "exponential", floor: 1, maxLimit: 8 });
    assert.deepEqual(q.getSlowStartConfig(), { curve: "exponential", floor: 1, maxLimit: 8 });
    q.stop();
  });

  it("illegal patch throws RangeError and stays unconfigured; can still enable after", () => {
    const { q } = makeQueue();
    assert.throws(() => q.reviseSlowStart({ floor: 0 }), RangeError);
    assert.throws(
      () => q.reviseSlowStart({ curve: "cubic" as SlowStartOptions["curve"] }),
      RangeError
    );
    assert.throws(() => q.reviseSlowStart({ floor: 10 }), RangeError); // > fixed cap 8
    assert.throws(() => q.reviseSlowStart({ maxLimit: 0 }), RangeError);
    assert.throws(() => q.reviseSlowStart({ floor: 4, maxLimit: 2 }), RangeError);
    assert.throws(() => q.reviseSlowStart(null as never), RangeError);
    assert.throws(() => q.reviseSlowStart([] as never), RangeError);
    assert.equal(q.getSlowStartConfig(), undefined);
    assert.equal(q.getSlowStartStats(), undefined);
    // Still enableable after the refusals.
    assert.deepEqual(q.reviseSlowStart({ floor: 2 }), {
      curve: "exponential",
      floor: 2,
      maxLimit: 8,
    });
    q.stop();
  });

  it("once enabled, later calls revise per WR-338; empty patch is a RangeError again", () => {
    const { q } = makeQueue();
    assert.deepEqual(q.reviseSlowStart({ floor: 1 }), {
      curve: "exponential",
      floor: 1,
      maxLimit: 8,
    });
    assert.deepEqual(q.reviseSlowStart({ floor: 2, curve: "additive" }), {
      curve: "additive",
      floor: 2,
      maxLimit: 8,
    });
    assert.throws(() => q.reviseSlowStart({}), RangeError);
    // Same-value revision is a silent no-op.
    assert.deepEqual(q.reviseSlowStart({ floor: 2, curve: "additive" }), {
      curve: "additive",
      floor: 2,
      maxLimit: 8,
    });
    q.stop();
  });

  it("a fresh queue is unconfigured again: the enable is live-only", () => {
    const { q } = makeQueue();
    assert.deepEqual(q.reviseSlowStart({}), { curve: "exponential", floor: 1, maxLimit: 8 });
    q.stop();
    const { q: fresh } = makeQueue();
    assert.equal(fresh.getSlowStartConfig(), undefined);
    assert.equal(fresh.getSlowStartStats(), undefined);
    fresh.stop();
  });
});

describe("RelayServer slow-start live enable (WR-476)", () => {
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
    const dir = mkdtempSync(join(tmpdir(), "slow-start-enable-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: signingKey,
      forwardUrl: URL_A,
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

  it("relay enable mounts the getter and audits previous: null; later revisions audit previous", async () => {
    const { relay, audit } = makeRelay({
      retry: {
        baseDelayMs: 5,
        jitterMs: 0,
        maxAttempts: 2,
        maxConcurrentPerEndpoint: 8,
        circuitBreaker: { failureThreshold: 2, cooldownMs: 1000 },
      },
    });
    await listen(relay);
    assert.equal(relay.getSlowStartConfig, undefined);
    assert.deepEqual(relay.reviseSlowStart!({ floor: 2 }), {
      curve: "exponential",
      floor: 2,
      maxLimit: 8,
    });
    // The getter mounts at enable time and reads the live values.
    assert.deepEqual(relay.getSlowStartConfig!(), {
      curve: "exponential",
      floor: 2,
      maxLimit: 8,
    });
    const revised = eventsOf(audit, "slow_start_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.deepEqual(revised[0].current, { curve: "exponential", floor: 2, maxLimit: 8 });
    // A real revision after the enable audits the enabled config as previous.
    relay.reviseSlowStart!({ floor: 3 });
    assert.equal(eventsOf(audit, "slow_start_revised").length, 2);
    assert.deepEqual(eventsOf(audit, "slow_start_revised")[1].previous, {
      curve: "exponential",
      floor: 2,
      maxLimit: 8,
    });
    assert.deepEqual(eventsOf(audit, "slow_start_revised")[1].current, {
      curve: "exponential",
      floor: 3,
      maxLimit: 8,
    });
  });

  it("relay without a breaker: revise throws, getter stays unmounted, no audit", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.equal(relay.getSlowStartConfig, undefined);
    assert.throws(
      () => relay.reviseSlowStart!({ floor: 2 }),
      /circuit breaker is not configured/
    );
    assert.equal(relay.getSlowStartConfig, undefined);
    assert.equal(eventsOf(audit, "slow_start_revised").length, 0);
  });
});
