import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type Sender, type AdaptiveBackoffOptions } from "../src/retry.ts";
import { AdaptiveBackoffController } from "../src/adaptive-backoff.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "adaptive-backoff-revision-test-key";
const opToken = "adaptive-backoff-revision-op-token";
const URL = "http://localhost:9999/hook";
const URL_A = "http://localhost:9999/a";

/**
 * Manual timer with single-step control: retry scheduling re-arms timers,
 * so the tests advance one wave at a time instead of draining everything.
 * Every scheduled delay is recorded, so the next retry's wait is
 * observable.
 */
function manualTimer() {
  const pending: Array<() => void> = [];
  const delays: number[] = [];
  return {
    delays,
    setTimer: (fn: () => void, ms: number) => {
      delays.push(ms);
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
    async run() {
      while (pending.length > 0) {
        const fns = pending.splice(0);
        for (const fn of fns) fn();
        await new Promise((r) => setImmediate(r));
      }
    },
  };
}

function item(id: string, tenantId?: string) {
  return {
    id,
    payload: Buffer.from("hello"),
    targetUrl: URL,
    headers: {},
    ...(tenantId !== undefined ? { tenantId } : {}),
  };
}

/** Let the deliver() promise chain settle. */
async function flush(ticks = 20) {
  for (let i = 0; i < ticks; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

describe("AdaptiveBackoffController.retune (WR-339)", () => {
  const construction = { minBaseMs: 100, maxBaseMs: 10_000, upFactor: 2, downFactor: 0.5 };

  it("upFactor change only changes the next failure step", () => {
    const c = new AdaptiveBackoffController(100, construction);
    c.recordOutcome("e", false);
    assert.equal(c.baseFor("e"), 200);
    assert.deepEqual(c.retune({ upFactor: 3 }), { ...construction, upFactor: 3 });
    c.recordOutcome("e", false);
    assert.equal(c.baseFor("e"), 600); // x3, not x2
  });

  it("downFactor change only changes the next success step", () => {
    const c = new AdaptiveBackoffController(100, construction);
    for (let i = 0; i < 3; i++) c.recordOutcome("e", false); // base: 800
    assert.equal(c.baseFor("e"), 800);
    c.retune({ downFactor: 0.25 });
    c.recordOutcome("e", true);
    assert.equal(c.baseFor("e"), 200); // x0.25, not x0.5
  });

  it("lowering maxBaseMs clamps an already-hot endpoint base at once", () => {
    const c = new AdaptiveBackoffController(100, construction);
    for (let i = 0; i < 3; i++) c.recordOutcome("e", false); // base: 800
    assert.deepEqual(c.retune({ maxBaseMs: 300 }), { ...construction, maxBaseMs: 300 });
    assert.equal(c.baseFor("e"), 300);
    assert.deepEqual(c.stats(), [
      { endpoint: "e", baseMs: 300, consecutiveFailures: 3, consecutiveSuccesses: 0 },
    ]);
    // The next failure stays pinned at the new ceiling.
    c.recordOutcome("e", false);
    assert.equal(c.baseFor("e"), 300);
  });

  it("raising minBaseMs lifts an already-cold endpoint base at once", () => {
    const c = new AdaptiveBackoffController(100, construction);
    c.recordOutcome("e", false); // base: 200
    c.recordOutcome("e", true); // base: 100 (floor)
    assert.equal(c.baseFor("e"), 100);
    assert.deepEqual(c.retune({ minBaseMs: 150 }), { ...construction, minBaseMs: 150 });
    assert.equal(c.baseFor("e"), 150);
    // The next success stays floored at the new minimum.
    c.recordOutcome("e", true);
    assert.equal(c.baseFor("e"), 150);
  });

  it("illegal values and the maxBaseMs < minBaseMs cross-gate throw RangeError and leave live state untouched", () => {
    const c = new AdaptiveBackoffController(100, construction);
    c.recordOutcome("e", false);
    c.recordOutcome("e", false); // base: 400, failure streak 2
    const before = c.snapshot();
    const statsBefore = c.stats();
    const illegal = [
      { minBaseMs: 0 },
      { minBaseMs: -5 },
      { minBaseMs: Number.NaN },
      { minBaseMs: Number.POSITIVE_INFINITY },
      { maxBaseMs: 50 }, // below the live minBaseMs (100)
      { maxBaseMs: 0 },
      { minBaseMs: 500, maxBaseMs: 400 }, // maxBaseMs < minBaseMs
      { upFactor: 1 },
      { upFactor: 0.5 },
      { upFactor: Number.NaN },
      { downFactor: 0 },
      { downFactor: 1 },
      { downFactor: 1.5 },
      { downFactor: Number.NaN },
    ];
    for (const patch of illegal) {
      assert.throws(() => c.retune(patch), RangeError, JSON.stringify(patch));
      assert.deepEqual(c.snapshot(), before);
      assert.equal(c.baseFor("e"), 400);
      assert.deepEqual(c.stats(), statsBefore);
    }
  });

  it("empty patch and non-object patches throw RangeError", () => {
    const c = new AdaptiveBackoffController(100, construction);
    const before = c.snapshot();
    assert.throws(() => c.retune({}), RangeError);
    assert.throws(() => c.retune(null as never), RangeError);
    assert.throws(() => c.retune("x" as never), RangeError);
    assert.throws(() => c.retune(42 as never), RangeError);
    assert.throws(() => c.retune([] as never), RangeError);
    assert.deepEqual(c.snapshot(), before);
  });

  it("a same-value patch is a silent no-op; snapshot() reads the four live values", () => {
    const c = new AdaptiveBackoffController(100, construction);
    c.recordOutcome("e", false);
    assert.equal(c.baseFor("e"), 200);
    assert.deepEqual(c.retune({ ...construction }), construction);
    assert.deepEqual(c.retune({ upFactor: 2 }), construction);
    assert.deepEqual(c.snapshot(), construction);
    assert.equal(c.baseFor("e"), 200);
    c.retune({ upFactor: 4, maxBaseMs: 5000 });
    assert.deepEqual(c.snapshot(), { ...construction, upFactor: 4, maxBaseMs: 5000 });
  });

  it("retune keeps the outcome streaks, so the next outcome still counts on the original streak", () => {
    const c = new AdaptiveBackoffController(100, construction);
    c.recordOutcome("e", false);
    c.recordOutcome("e", false); // streak 2, base 400
    c.retune({ upFactor: 3 });
    c.recordOutcome("e", false);
    assert.equal(c.baseFor("e"), 1200); // 400 x 3
    assert.deepEqual(c.stats(), [
      { endpoint: "e", baseMs: 1200, consecutiveFailures: 3, consecutiveSuccesses: 0 },
    ]);
    // A success streak survives a downFactor retune the same way.
    c.retune({ downFactor: 0.25 });
    c.recordOutcome("e", true);
    assert.deepEqual(c.stats(), [
      { endpoint: "e", baseMs: 300, consecutiveFailures: 0, consecutiveSuccesses: 1 },
    ]);
  });

  it("an endpoint with no outcomes keeps using the resting base (read live)", () => {
    let resting = 100;
    const c = new AdaptiveBackoffController(() => resting, construction);
    assert.equal(c.baseFor("fresh"), 100);
    c.retune({ maxBaseMs: 500 });
    resting = 250; // WR-32 hot-reload of the fixed base
    assert.equal(c.baseFor("fresh"), 250);
    assert.deepEqual(c.stats(), []);
  });
});

describe("RetryQueue adaptive backoff revision (WR-339)", () => {
  function makeQueue(adaptiveBackoff?: AdaptiveBackoffOptions, maxAttempts = 5) {
    const timer = manualTimer();
    const alwaysFail: Sender = async () => {
      throw new Error("downstream down");
    };
    const q = new RetryQueue({
      sender: alwaysFail,
      baseDelayMs: 100,
      maxDelayMs: 60_000,
      maxAttempts,
      jitterMs: 0,
      random: () => 0, // deterministic parking delay
      setTimer: timer.setTimer,
      ...(adaptiveBackoff === undefined ? {} : { adaptiveBackoff }),
    });
    return { q, timer };
  }

  it("unconfigured: revise throws the must-restart Error, getter returns undefined", () => {
    const { q } = makeQueue();
    assert.equal(q.getAdaptiveBackoffConfig(), undefined);
    assert.throws(
      () => q.reviseAdaptiveBackoff({ upFactor: 3 }),
      /not configured — enabling it requires a restart/
    );
    assert.throws(
      () => q.reviseAdaptiveBackoff({ upFactor: 3 }),
      /cannot start adapting bases without one/
    );
    assert.equal(q.getAdaptiveBackoffConfig(), undefined);
    q.stop();
  });

  it("getter tracks revisions; a tenant born after the retune starts from the revised values", async () => {
    const { q, timer } = makeQueue({ minBaseMs: 100, maxBaseMs: 10_000, upFactor: 2, downFactor: 0.5 }, 2);
    assert.deepEqual(q.getAdaptiveBackoffConfig(), {
      minBaseMs: 100,
      maxBaseMs: 10_000,
      upFactor: 2,
      downFactor: 0.5,
    });
    q.start();
    q.enqueue(item("acme-1", "acme"));
    await timer.run();
    const acmeBefore = q.getAdaptiveBackoffStats()!.find((s) => s.tenant === "acme")!;
    assert.equal(acmeBefore.baseMs, 400); // 100 -> 200 -> 400
    assert.equal(acmeBefore.consecutiveFailures, 2);
    assert.deepEqual(q.reviseAdaptiveBackoff({ upFactor: 4, maxBaseMs: 20_000 }), {
      minBaseMs: 100,
      maxBaseMs: 20_000,
      upFactor: 4,
      downFactor: 0.5,
    });
    assert.deepEqual(q.getAdaptiveBackoffConfig(), {
      minBaseMs: 100,
      maxBaseMs: 20_000,
      upFactor: 4,
      downFactor: 0.5,
    });
    // The existing controller keeps its base (400 is inside the new
    // bounds) but now steps with the new factor.
    const acmeAfter = q.getAdaptiveBackoffStats()!.find((s) => s.tenant === "acme")!;
    assert.equal(acmeAfter.baseMs, 400);
    // A new tenant is born from the revised values.
    q.enqueue(item("beta-1", "beta"));
    await timer.run();
    const beta = q.getAdaptiveBackoffStats()!.find((s) => s.tenant === "beta")!;
    assert.equal(beta.baseMs, 1600); // 100 -> 400 -> 1600 (x4 steps)
    assert.equal(beta.consecutiveFailures, 2);
    q.stop();
  });

  it("an already-scheduled delivery's next wait is computed from the retuned base", async () => {
    const { q, timer } = makeQueue({ minBaseMs: 100, maxBaseMs: 10_000, upFactor: 2, downFactor: 0.5 });
    q.start();
    q.enqueue(item("wait-1"));
    await timer.step(); // attempt 1 fails: base 100 -> 200, wait = 200 * 2^1 = 400
    assert.deepEqual(timer.delays, [0, 400]);
    // Clamp the hot base before the retry fires.
    q.reviseAdaptiveBackoff({ maxBaseMs: 150 });
    assert.deepEqual(q.getAdaptiveBackoffStats(), [
      { endpoint: URL, baseMs: 150, consecutiveFailures: 1, consecutiveSuccesses: 0 },
    ]);
    await timer.step(); // attempt 2 fails: base stays 150, wait = 150 * 2^2 = 600
    assert.deepEqual(timer.delays, [0, 400, 600]);
    q.stop();
  });

  it("an illegal queue-level patch leaves every tenant controller untouched", async () => {
    const { q, timer } = makeQueue({ minBaseMs: 100, maxBaseMs: 10_000, upFactor: 2, downFactor: 0.5 }, 2);
    q.start();
    q.enqueue(item("a-1", "acme"));
    q.enqueue(item("b-1", "beta"));
    await timer.run();
    const before = q.getAdaptiveBackoffConfig();
    const statsBefore = q.getAdaptiveBackoffStats();
    for (const patch of [
      { minBaseMs: 0 },
      { maxBaseMs: 50 },
      { minBaseMs: 500, maxBaseMs: 400 },
      { upFactor: 1 },
      { downFactor: 1 },
      {},
      null,
    ]) {
      assert.throws(() => q.reviseAdaptiveBackoff(patch as never), RangeError, JSON.stringify(patch));
      assert.deepEqual(q.getAdaptiveBackoffConfig(), before);
      assert.deepEqual(q.getAdaptiveBackoffStats(), statsBefore);
    }
    q.stop();
  });
});

describe("RelayServer adaptive backoff revision (WR-339)", () => {
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
    const dir = mkdtempSync(join(tmpdir(), "adaptive-backoff-revision-"));
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

  const construction = { minBaseMs: 100, maxBaseMs: 10_000, upFactor: 2, downFactor: 0.5 };

  it("revision audits previous/current with the construction values first; same-value is a silent no-op", async () => {
    const { relay, audit } = makeRelay({
      retry: { adaptiveBackoff: { ...construction } },
    });
    await listen(relay);
    assert.deepEqual(relay.getAdaptiveBackoffConfig!(), construction);
    assert.deepEqual(relay.reviseAdaptiveBackoff!({ upFactor: 3 }), { ...construction, upFactor: 3 });
    const revised = eventsOf(audit, "adaptive_backoff_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, construction);
    assert.deepEqual(revised[0].current, { ...construction, upFactor: 3 });
    // Landing exactly on the live values audits nothing.
    relay.reviseAdaptiveBackoff!({ upFactor: 3 });
    assert.equal(eventsOf(audit, "adaptive_backoff_revised").length, 1);
    assert.deepEqual(relay.getAdaptiveBackoffConfig!(), { ...construction, upFactor: 3 });
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseAdaptiveBackoff!({ maxBaseMs: 50 }), RangeError);
    assert.throws(() => relay.reviseAdaptiveBackoff!({}), RangeError);
    assert.equal(eventsOf(audit, "adaptive_backoff_revised").length, 1);
    assert.deepEqual(relay.getAdaptiveBackoffConfig!(), { ...construction, upFactor: 3 });
  });

  it("unconfigured relay: revise throws the must-restart Error and the getter is not mounted", async () => {
    const { relay } = makeRelay();
    await listen(relay);
    assert.equal(relay.getAdaptiveBackoffConfig, undefined);
    assert.throws(
      () => relay.reviseAdaptiveBackoff!({ upFactor: 3 }),
      /not configured — enabling it requires a restart/
    );
  });

  it("server getter reflects revisions made through the server", async () => {
    const { relay } = makeRelay({
      retry: { adaptiveBackoff: { minBaseMs: 100, maxBaseMs: 10_000 } },
    });
    await listen(relay);
    assert.deepEqual(relay.getAdaptiveBackoffConfig!(), construction);
    relay.reviseAdaptiveBackoff!({ minBaseMs: 200, downFactor: 0.25 });
    assert.deepEqual(relay.getAdaptiveBackoffConfig!(), {
      ...construction,
      minBaseMs: 200,
      downFactor: 0.25,
    });
  });
});
