import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type Sender, type AdaptiveBackoffOptions } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "adaptive-backoff-enable-test-key";
const opToken = "adaptive-backoff-enable-op-token";
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

/** Queue deliberately *without* an `adaptiveBackoff` option, so the WR-458 enable path is the only way a controller appears. */
function makeQueue(
  adaptiveBackoff?: AdaptiveBackoffOptions,
  maxAttempts = 5,
  sender?: Sender
) {
  const timer = manualTimer();
  const alwaysFail: Sender = async () => {
    throw new Error("downstream down");
  };
  const q = new RetryQueue({
    sender: sender ?? alwaysFail,
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

const defaults = { minBaseMs: 100, maxBaseMs: 30_000, upFactor: 2, downFactor: 0.5 };

describe("RetryQueue.reviseAdaptiveBackoff live enable for an unconfigured queue (WR-458)", () => {
  it("first enable takes the construction defaults — an empty patch enables", () => {
    const { q } = makeQueue();
    q.start();
    try {
      assert.equal(q.getAdaptiveBackoffConfig(), undefined);
      assert.equal(q.getAdaptiveBackoffStats(), undefined);
      assert.deepEqual(q.reviseAdaptiveBackoff({}), defaults);
      assert.deepEqual(q.getAdaptiveBackoffConfig(), defaults);
      // A fresh controller has no outcomes yet.
      assert.deepEqual(q.getAdaptiveBackoffStats(), []);
      // Endpoints with no outcomes still use the resting base.
      assert.equal(q.delayForAttempt(1, URL), 200);
    } finally {
      q.stop();
    }
  });

  it("an explicit patch enables with the exact four knobs", () => {
    const { q } = makeQueue();
    q.start();
    try {
      assert.deepEqual(
        q.reviseAdaptiveBackoff({
          minBaseMs: 50,
          maxBaseMs: 5000,
          upFactor: 3,
          downFactor: 0.25,
        }),
        { minBaseMs: 50, maxBaseMs: 5000, upFactor: 3, downFactor: 0.25 }
      );
      assert.deepEqual(q.getAdaptiveBackoffConfig(), {
        minBaseMs: 50,
        maxBaseMs: 5000,
        upFactor: 3,
        downFactor: 0.25,
      });
    } finally {
      q.stop();
    }
  });

  it("a partial patch uses the explicit knobs exactly and defaults the rest", () => {
    const { q } = makeQueue();
    q.start();
    try {
      assert.deepEqual(q.reviseAdaptiveBackoff({ upFactor: 4, maxBaseMs: 8000 }), {
        minBaseMs: 100,
        maxBaseMs: 8000,
        upFactor: 4,
        downFactor: 0.5,
      });
    } finally {
      q.stop();
    }
  });

  it("non-object and illegal patches throw RangeError and leave the queue unconfigured — and it can still enable afterwards", () => {
    const { q } = makeQueue();
    q.start();
    try {
      assert.equal(q.getAdaptiveBackoffConfig(), undefined);
      for (const patch of [
        null,
        "1000",
        [],
        { minBaseMs: 0 },
        { minBaseMs: -5 },
        { minBaseMs: Number.NaN },
        { maxBaseMs: 50 },
        { minBaseMs: 500, maxBaseMs: 400 },
        { upFactor: 1 },
        { upFactor: 0.5 },
        { downFactor: 0 },
        { downFactor: 1 },
        { downFactor: 1.5 },
      ]) {
        assert.throws(
          () => q.reviseAdaptiveBackoff(patch as never),
          RangeError,
          JSON.stringify(patch)
        );
        assert.equal(q.getAdaptiveBackoffConfig(), undefined);
        assert.equal(q.getAdaptiveBackoffStats(), undefined);
      }
      // Still unconfigured after every rejection — and the enable path still works.
      assert.deepEqual(q.reviseAdaptiveBackoff({}), defaults);
    } finally {
      q.stop();
    }
  });

  it("a failure before the enable is never recorded; the next wait after the enable steps from the resting base", async () => {
    const { q, timer } = makeQueue();
    q.start();
    try {
      q.enqueue(item("pre-1"));
      await timer.step(); // attempt 1 fails: no controller yet, wait = 100 * 2^1 = 200
      assert.deepEqual(timer.delays, [0, 200]);
      assert.equal(q.getAdaptiveBackoffStats(), undefined);
      assert.deepEqual(
        q.reviseAdaptiveBackoff({
          minBaseMs: 100,
          maxBaseMs: 10_000,
          upFactor: 2,
          downFactor: 0.5,
        }),
        { minBaseMs: 100, maxBaseMs: 10_000, upFactor: 2, downFactor: 0.5 }
      );
      // The fresh controller has no rows: the pre-enable failure is invisible.
      assert.deepEqual(q.getAdaptiveBackoffStats(), []);
      await timer.step(); // attempt 2 fails: base 100 -> 200, wait = 200 * 2^2 = 800
      assert.deepEqual(timer.delays, [0, 200, 800]);
      assert.deepEqual(q.getAdaptiveBackoffStats(), [
        { endpoint: URL, baseMs: 200, consecutiveFailures: 1, consecutiveSuccesses: 0 },
      ]);
    } finally {
      q.stop();
    }
  });

  it("a success after the enable halves the base from the resting base", async () => {
    const succeed: Sender = async () => ({ statusCode: 200, body: Buffer.from("ok") });
    const { q, timer } = makeQueue(undefined, 5, succeed);
    q.start();
    try {
      assert.deepEqual(
        q.reviseAdaptiveBackoff({
          minBaseMs: 10,
          maxBaseMs: 10_000,
          upFactor: 2,
          downFactor: 0.5,
        }),
        { minBaseMs: 10, maxBaseMs: 10_000, upFactor: 2, downFactor: 0.5 }
      );
      q.enqueue(item("ok-1"));
      await timer.run();
      // Resting base 100 halved once, clamped at the 10 floor: 50.
      assert.deepEqual(q.getAdaptiveBackoffStats(), [
        { endpoint: URL, baseMs: 50, consecutiveFailures: 0, consecutiveSuccesses: 1 },
      ]);
    } finally {
      q.stop();
    }
  });

  it("delayForAttempt reads the adapted base after an outcome, the resting base before", async () => {
    const { q, timer } = makeQueue();
    q.start();
    try {
      q.reviseAdaptiveBackoff({
        minBaseMs: 100,
        maxBaseMs: 10_000,
        upFactor: 2,
        downFactor: 0.5,
      });
      assert.equal(q.delayForAttempt(1, URL), 200);
      q.enqueue(item("wait-1"));
      await timer.step(); // attempt 1 fails: base 100 -> 200
      assert.equal(q.delayForAttempt(1, URL), 400);
      assert.equal(q.delayForAttempt(2, URL), 800);
      // A cold endpoint still sees the resting base.
      assert.equal(q.delayForAttempt(1, URL_A), 200);
    } finally {
      q.stop();
    }
  });

  it("a tenant born after the enable starts from the enabled values", async () => {
    const { q, timer } = makeQueue(undefined, 2);
    q.start();
    try {
      q.reviseAdaptiveBackoff({
        minBaseMs: 100,
        maxBaseMs: 10_000,
        upFactor: 2,
        downFactor: 0.5,
      });
      q.enqueue(item("acme-1", "acme"));
      await timer.run();
      const acme = q.getAdaptiveBackoffStats()!.find((s) => s.tenant === "acme")!;
      assert.equal(acme.baseMs, 400); // 100 -> 200 -> 400
      assert.equal(acme.consecutiveFailures, 2);
    } finally {
      q.stop();
    }
  });

  it("after the enable, a revision still follows WR-339 semantics", () => {
    const { q } = makeQueue();
    q.start();
    try {
      q.reviseAdaptiveBackoff({
        minBaseMs: 100,
        maxBaseMs: 10_000,
        upFactor: 2,
        downFactor: 0.5,
      });
      assert.deepEqual(q.reviseAdaptiveBackoff({ upFactor: 3 }), {
        minBaseMs: 100,
        maxBaseMs: 10_000,
        upFactor: 3,
        downFactor: 0.5,
      });
      // An empty patch is still a RangeError; landing on the live
      // values is a silent no-op; an illegal patch leaves live values untouched.
      assert.throws(() => q.reviseAdaptiveBackoff({}), RangeError);
      assert.deepEqual(q.reviseAdaptiveBackoff({ upFactor: 3 }), {
        minBaseMs: 100,
        maxBaseMs: 10_000,
        upFactor: 3,
        downFactor: 0.5,
      });
      assert.throws(() => q.reviseAdaptiveBackoff({ maxBaseMs: 50 }), RangeError);
      assert.deepEqual(q.getAdaptiveBackoffConfig(), {
        minBaseMs: 100,
        maxBaseMs: 10_000,
        upFactor: 3,
        downFactor: 0.5,
      });
    } finally {
      q.stop();
    }
  });

  it("a restart returns to unconfigured", () => {
    const { q } = makeQueue();
    q.start();
    q.reviseAdaptiveBackoff({ upFactor: 3 });
    assert.equal(q.getAdaptiveBackoffConfig()?.upFactor, 3);
    q.stop();
    // A fresh queue built from the same (backoff-less) options has no controller.
    const { q: restarted } = makeQueue();
    assert.equal(restarted.getAdaptiveBackoffConfig(), undefined);
    // …and the enable path works on it again.
    assert.deepEqual(restarted.reviseAdaptiveBackoff({}), defaults);
    restarted.stop();
  });
});

describe("RelayServer reviseAdaptiveBackoff live enable for an unconfigured relay (WR-458)", () => {
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
    const dir = mkdtempSync(join(tmpdir(), "adaptive-backoff-enable-"));
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

  it("server enable audits previous: null, mounts the getter, and a same-value call audits nothing", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.equal(relay.getAdaptiveBackoffConfig, undefined);
    assert.deepEqual(relay.reviseAdaptiveBackoff!({ upFactor: 3 }), {
      ...defaults,
      upFactor: 3,
    });
    assert.notEqual(relay.getAdaptiveBackoffConfig, undefined);
    assert.deepEqual(relay.getAdaptiveBackoffConfig!(), { ...defaults, upFactor: 3 });
    const revised = eventsOf(audit, "adaptive_backoff_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.deepEqual(revised[0].current, { ...defaults, upFactor: 3 });
    // Landing exactly on the enabled values audits nothing.
    relay.reviseAdaptiveBackoff!({ upFactor: 3 });
    assert.equal(eventsOf(audit, "adaptive_backoff_revised").length, 1);
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseAdaptiveBackoff!({ maxBaseMs: 50 }), RangeError);
    assert.equal(eventsOf(audit, "adaptive_backoff_revised").length, 1);
    assert.deepEqual(relay.getAdaptiveBackoffConfig!(), { ...defaults, upFactor: 3 });
  });

  it("server enable with an illegal patch leaves the relay unconfigured — and it can still enable afterwards", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.throws(() => relay.reviseAdaptiveBackoff!({ upFactor: 1 }), RangeError);
    assert.throws(() => relay.reviseAdaptiveBackoff!({ downFactor: 0 }), RangeError);
    assert.throws(() => relay.reviseAdaptiveBackoff!(null as never), RangeError);
    assert.equal(relay.getAdaptiveBackoffConfig, undefined);
    assert.equal(eventsOf(audit, "adaptive_backoff_revised").length, 0);
    assert.deepEqual(relay.reviseAdaptiveBackoff!({}), defaults);
    const revised = eventsOf(audit, "adaptive_backoff_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.deepEqual(revised[0].current, defaults);
  });

  it("after the server enable, a live revision audits previous = the enabled values", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    relay.reviseAdaptiveBackoff!({});
    assert.deepEqual(relay.reviseAdaptiveBackoff!({ upFactor: 4 }), {
      ...defaults,
      upFactor: 4,
    });
    const revised = eventsOf(audit, "adaptive_backoff_revised");
    assert.equal(revised.length, 2);
    assert.deepEqual(revised[1].previous, defaults);
    assert.deepEqual(revised[1].current, { ...defaults, upFactor: 4 });
  });
});
