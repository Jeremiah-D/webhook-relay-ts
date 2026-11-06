import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type Sender, type SlowStartOptions } from "../src/retry.ts";
import { SlowStartController } from "../src/slowstart.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "slow-start-revision-test-key";
const opToken = "slow-start-revision-op-token";
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

/** Let the deliver() promise chain settle. */
async function flush(ticks = 20) {
  for (let i = 0; i < ticks; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

describe("SlowStartController.retune (WR-338)", () => {
  it("switching exponential -> additive only changes the next success step", () => {
    const c = new SlowStartController({ floor: 1, maxLimit: 8 });
    c.onCircuitClosed("e");
    assert.equal(c.limitFor("e"), 1);
    c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 2);
    c.retune({ curve: "additive" });
    c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 3); // +1, not x2
  });

  it("switching additive -> exponential only changes the next success step", () => {
    const c = new SlowStartController({ curve: "additive", floor: 1, maxLimit: 8 });
    c.onCircuitClosed("e");
    c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 2);
    c.retune({ curve: "exponential" });
    c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 4); // x2, not +1
  });

  it("raising the floor lifts an active ramp at once", () => {
    const c = new SlowStartController({ floor: 1, maxLimit: 8 });
    c.onCircuitClosed("e");
    assert.equal(c.limitFor("e"), 1);
    assert.deepEqual(c.retune({ floor: 3 }), { curve: "exponential", floor: 3, maxLimit: 8 });
    assert.equal(c.limitFor("e"), 3);
    assert.deepEqual(c.stats(), [
      { endpoint: "e", limit: 3, floor: 3, ceiling: 8, curve: "exponential" },
    ]);
    // The next success climbs from the lifted height.
    c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 6);
  });

  it("lowering the floor leaves ramp heights alone; the next failure falls back to it", () => {
    const c = new SlowStartController({ floor: 2, maxLimit: 8 });
    c.onCircuitClosed("e");
    assert.equal(c.limitFor("e"), 2);
    c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 4);
    c.retune({ floor: 1 });
    assert.equal(c.limitFor("e"), 4);
    c.recordOutcome("e", false);
    assert.equal(c.limitFor("e"), 1); // new floor, not the old one
  });

  it("lowering maxLimit completes an active ramp at or above it at once", () => {
    const c = new SlowStartController({ floor: 1, maxLimit: 8 });
    c.onCircuitClosed("e");
    c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 2);
    c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 4);
    c.retune({ maxLimit: 4 });
    assert.equal(c.limitFor("e"), 4); // back at the full (new) limit
    assert.equal(c.ramping("e"), false);
    assert.deepEqual(c.stats(), []);
  });

  it("raising maxLimit lets the ramp keep climbing past the old ceiling", () => {
    const c = new SlowStartController({ floor: 1, maxLimit: 4 });
    c.onCircuitClosed("e");
    c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 2);
    c.retune({ maxLimit: 16 });
    c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 4); // still ramping, not complete
    assert.equal(c.ramping("e"), true);
    c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 8);
    assert.equal(c.ramping("e"), true);
  });

  it("a new breaker-close starts at the new floor on the new curve", () => {
    const c = new SlowStartController({ floor: 1, maxLimit: 8 });
    c.onCircuitClosed("e");
    c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 2);
    c.retune({ floor: 2, curve: "additive" });
    c.onCircuitClosed("e");
    assert.equal(c.limitFor("e"), 2); // restarted at the new floor
    c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 3); // additive step
  });

  it("illegal values and cross-gates throw RangeError and leave live state untouched", () => {
    const c = new SlowStartController({ floor: 1, maxLimit: 8 });
    c.onCircuitClosed("e");
    c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 2);
    const before = c.snapshot();
    const illegal = [
      { curve: "cubic" as SlowStartOptions["curve"] },
      { floor: 0 },
      { floor: 1.5 },
      { maxLimit: 0 },
      { maxLimit: 0.5 },
      { floor: 10 }, // maxLimit (8) < floor
      { floor: 3, maxLimit: 2 }, // maxLimit < floor
    ];
    for (const patch of illegal) {
      assert.throws(() => c.retune(patch), RangeError, JSON.stringify(patch));
      assert.deepEqual(c.snapshot(), before);
      assert.equal(c.limitFor("e"), 2);
      assert.equal(c.ramping("e"), true);
      assert.equal(c.stats().length, 1);
      assert.equal(c.stats()[0].limit, 2);
    }
  });

  it("empty patch and non-object patches throw RangeError", () => {
    const c = new SlowStartController({ floor: 1, maxLimit: 8 });
    const before = c.snapshot();
    assert.throws(() => c.retune({}), RangeError);
    assert.throws(() => c.retune(null as never), RangeError);
    assert.throws(() => c.retune("x" as never), RangeError);
    assert.throws(() => c.retune(42 as never), RangeError);
    assert.throws(() => c.retune([] as never), RangeError);
    assert.deepEqual(c.snapshot(), before);
  });

  it("a same-value patch is a silent no-op", () => {
    const c = new SlowStartController({ floor: 1, maxLimit: 8 });
    c.onCircuitClosed("e");
    c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 2);
    assert.deepEqual(c.retune({ curve: "exponential", floor: 1, maxLimit: 8 }), {
      curve: "exponential",
      floor: 1,
      maxLimit: 8,
    });
    assert.deepEqual(c.retune({ floor: 1 }), { curve: "exponential", floor: 1, maxLimit: 8 });
    assert.deepEqual(c.snapshot(), { curve: "exponential", floor: 1, maxLimit: 8 });
    assert.equal(c.limitFor("e"), 2);
  });

  it("snapshot() reads the three live values", () => {
    const c = new SlowStartController({ curve: "additive", floor: 2, maxLimit: 16 });
    assert.deepEqual(c.snapshot(), { curve: "additive", floor: 2, maxLimit: 16 });
    c.retune({ curve: "exponential", maxLimit: 32 });
    assert.deepEqual(c.snapshot(), { curve: "exponential", floor: 2, maxLimit: 32 });
  });
});

describe("RetryQueue slow-start revision (WR-338)", () => {
  function makeQueue(slowStart?: SlowStartOptions) {
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
      circuitBreaker: { failureThreshold: 2, cooldownMs: 1000, nowMs: () => now },
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

  it("unconfigured: revise throws the must-restart Error, getter returns undefined", () => {
    const { q } = makeQueue();
    assert.equal(q.getSlowStartConfig(), undefined);
    assert.throws(
      () => q.reviseSlowStart({ floor: 2 }),
      /not configured — enabling it requires a restart/
    );
    assert.throws(
      () => q.reviseSlowStart({ floor: 2 }),
      /cannot start pacing recoveries without one/
    );
    assert.equal(q.getSlowStartConfig(), undefined);
    q.stop();
  });

  it("getter tracks revisions", () => {
    const { q } = makeQueue({ floor: 1, maxLimit: 8 });
    assert.deepEqual(q.getSlowStartConfig(), { curve: "exponential", floor: 1, maxLimit: 8 });
    assert.deepEqual(q.reviseSlowStart({ floor: 2, curve: "additive" }), {
      curve: "additive",
      floor: 2,
      maxLimit: 8,
    });
    assert.deepEqual(q.getSlowStartConfig(), { curve: "additive", floor: 2, maxLimit: 8 });
    q.stop();
  });

  it("raising the floor lifts the active ramp and the next dispatch gates on it", async () => {
    const env = makeQueue({ floor: 1, maxLimit: 8 });
    const { q } = env;
    await tripAndRecover(env, "ss");
    // The probe's own success stepped the ramp 1 -> 2.
    assert.equal(q.getSlowStartStats()![0].limit, 2);
    assert.equal((q as any).limiter.maxFor(URL), 2);
    q.reviseSlowStart({ floor: 3 });
    assert.equal(q.getSlowStartStats()![0].limit, 3);
    assert.equal(q.getSlowStartStats()![0].floor, 3);
    assert.equal((q as any).limiter.maxFor(URL), 3);
    q.stop();
  });

  it("a tenant born after the retune starts its ramp from the revised values", async () => {
    const env = makeQueue({ floor: 1, maxLimit: 8 });
    const { q, timer, f } = env;
    await tripAndRecover(env, "ss-a", "acme");
    const acmeBefore = q.getSlowStartStats()!.find((s) => s.tenant === "acme")!;
    assert.equal(acmeBefore.limit, 2);
    assert.equal(acmeBefore.floor, 1);
    assert.equal(acmeBefore.curve, "exponential");
    q.reviseSlowStart({ floor: 2, curve: "additive" });
    // The existing ramp keeps its height (2 is not below the new floor).
    const acmeAfter = q.getSlowStartStats()!.find((s) => s.tenant === "acme")!;
    assert.equal(acmeAfter.limit, 2);
    assert.equal(acmeAfter.floor, 2);
    assert.equal(acmeAfter.curve, "additive");
    // A new tenant trips and recovers under the revised values.
    f.setFail(true);
    await tripAndRecover(env, "ss-b", "beta");
    const beta = q.getSlowStartStats()!.find((s) => s.tenant === "beta")!;
    assert.equal(beta.limit, 3); // floor 2, probe success steps +1 (additive)
    assert.equal(beta.floor, 2);
    assert.equal(beta.ceiling, 8);
    assert.equal(beta.curve, "additive");
    q.stop();
  });

  it("an illegal queue-level patch leaves every tenant controller untouched", async () => {
    const env = makeQueue({ floor: 1, maxLimit: 8 });
    const { q } = env;
    await tripAndRecover(env, "ss");
    const before = q.getSlowStartConfig();
    const statsBefore = q.getSlowStartStats();
    assert.throws(() => q.reviseSlowStart({ floor: 0 }), RangeError);
    assert.throws(() => q.reviseSlowStart({ curve: "cubic" as SlowStartOptions["curve"] }), RangeError);
    assert.throws(() => q.reviseSlowStart({ floor: 10 }), RangeError);
    assert.throws(() => q.reviseSlowStart({}), RangeError);
    assert.throws(() => q.reviseSlowStart(null as never), RangeError);
    assert.deepEqual(q.getSlowStartConfig(), before);
    assert.deepEqual(q.getSlowStartStats(), statsBefore);
    q.stop();
  });
});

describe("RelayServer slow-start revision (WR-338)", () => {
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
    const dir = mkdtempSync(join(tmpdir(), "slow-start-revision-"));
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

  const construction = { curve: "exponential" as const, floor: 1, maxLimit: 8 };

  it("revision audits previous/current with the construction values first; same-value is a silent no-op", async () => {
    const { relay, audit } = makeRelay({
      retry: { slowStart: { ...construction } },
    });
    await listen(relay);
    assert.deepEqual(relay.getSlowStartConfig!(), construction);
    assert.deepEqual(relay.reviseSlowStart!({ floor: 2 }), { ...construction, floor: 2 });
    const revised = eventsOf(audit, "slow_start_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, construction);
    assert.deepEqual(revised[0].current, { ...construction, floor: 2 });
    // Landing exactly on the live values audits nothing.
    relay.reviseSlowStart!({ floor: 2 });
    assert.equal(eventsOf(audit, "slow_start_revised").length, 1);
    assert.deepEqual(relay.getSlowStartConfig!(), { ...construction, floor: 2 });
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseSlowStart!({ floor: 0 }), RangeError);
    assert.throws(() => relay.reviseSlowStart!({}), RangeError);
    assert.equal(eventsOf(audit, "slow_start_revised").length, 1);
    assert.deepEqual(relay.getSlowStartConfig!(), { ...construction, floor: 2 });
  });

  it("unconfigured relay: revise throws the must-restart Error and the getter is not mounted", async () => {
    const { relay } = makeRelay();
    await listen(relay);
    assert.equal(relay.getSlowStartConfig, undefined);
    assert.throws(
      () => relay.reviseSlowStart!({ floor: 2 }),
      /not configured — enabling it requires a restart/
    );
  });

  it("server getter reflects revisions made through the server", async () => {
    const { relay } = makeRelay({
      retry: { slowStart: { floor: 1, maxLimit: 8 } },
    });
    await listen(relay);
    assert.deepEqual(relay.getSlowStartConfig!(), {
      curve: "exponential",
      floor: 1,
      maxLimit: 8,
    });
    relay.reviseSlowStart!({ floor: 2, curve: "additive" });
    assert.deepEqual(relay.getSlowStartConfig!(), {
      curve: "additive",
      floor: 2,
      maxLimit: 8,
    });
  });
});
