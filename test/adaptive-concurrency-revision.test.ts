import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  AdaptiveConcurrencyController,
  type Sender,
} from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "adaptive-concurrency-revision-test-key";
const opToken = "adaptive-concurrency-revision-op-token";
const URL_A = "http://localhost:9999/a";

/** Deterministic timer: `run()` executes pending callbacks immediately. */
function manualTimer() {
  const pending: Array<() => void> = [];
  return {
    setTimer: (fn: () => void, _ms: number) => {
      pending.push(fn);
      return {
        clear: () => {
          const i = pending.indexOf(fn);
          if (i >= 0) pending.splice(i, 1);
        },
      };
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
    targetUrl: URL_A,
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

describe("AdaptiveConcurrencyController.retune (WR-337)", () => {
  const base = {
    minLimit: 1,
    maxLimit: 64,
    initialLimit: 8,
    increaseStep: 1,
    decreaseFactor: 0.5,
    failureRateThreshold: 0.2,
    windowSize: 2,
  };

  it("retuning failureRateThreshold makes the next full window decrease earlier or later", () => {
    // Earlier: 1 failure in 4 outcomes is 0.25 — below the 0.5
    // threshold (healthy) but at the retuned 0.25 threshold (congested).
    const earlier = new AdaptiveConcurrencyController(
      { ...base, windowSize: 4, failureRateThreshold: 0.5 },
      64
    );
    earlier.recordOutcome("e", false);
    earlier.recordOutcome("e", true);
    earlier.recordOutcome("e", true);
    assert.deepEqual(earlier.retune({ failureRateThreshold: 0.25 }), {
      ...base,
      windowSize: 4,
      failureRateThreshold: 0.25,
    });
    earlier.recordOutcome("e", true);
    assert.equal(earlier.limitFor("e"), 4); // 8 * 0.5

    // Later: the same window stays healthy under a 0.75 threshold.
    const later = new AdaptiveConcurrencyController(
      { ...base, windowSize: 4, failureRateThreshold: 0.5 },
      64
    );
    later.recordOutcome("e", false);
    later.recordOutcome("e", true);
    later.recordOutcome("e", true);
    later.retune({ failureRateThreshold: 0.75 });
    later.recordOutcome("e", true);
    assert.equal(later.limitFor("e"), 9); // 8 + 1

    // Control: without a retune the same window increases too.
    const control = new AdaptiveConcurrencyController(
      { ...base, windowSize: 4, failureRateThreshold: 0.5 },
      64
    );
    control.recordOutcome("e", false);
    control.recordOutcome("e", true);
    control.recordOutcome("e", true);
    control.recordOutcome("e", true);
    assert.equal(control.limitFor("e"), 9);
  });

  it("retuning decreaseFactor changes the next multiplicative step", () => {
    const c = new AdaptiveConcurrencyController({ ...base, windowSize: 2 }, 64);
    c.retune({ decreaseFactor: 0.25 });
    c.recordOutcome("e", false);
    c.recordOutcome("e", false);
    assert.equal(c.limitFor("e"), 2); // 8 * 0.25, not 8 * 0.5
  });

  it("retuning increaseStep changes the next additive step", () => {
    const c = new AdaptiveConcurrencyController({ ...base, windowSize: 2 }, 64);
    c.retune({ increaseStep: 3 });
    c.recordOutcome("e", true);
    c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 11); // 8 + 3, not 8 + 1
  });

  it("lowering maxLimit clamps an already-adapted limit at once", () => {
    // initialLimit (4) stays inside the new [1, 6]: the retune only
    // moves maxLimit, so the initialLimit cross-gate still passes.
    const c = new AdaptiveConcurrencyController(
      { ...base, initialLimit: 4, increaseStep: 2, windowSize: 2 },
      64
    );
    c.recordOutcome("e", true);
    c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 6);
    c.recordOutcome("e", true);
    c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 8);
    c.recordOutcome("e", true);
    c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 10);
    assert.deepEqual(c.retune({ maxLimit: 6 }), {
      ...base,
      initialLimit: 4,
      increaseStep: 2,
      maxLimit: 6,
    });
    assert.equal(c.limitFor("e"), 6);
    assert.equal(c.stats()[0].limit, 6);
    // The next healthy window stays clamped at the new ceiling.
    c.recordOutcome("e", true);
    c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 6);
  });

  it("raising minLimit floors an already-adapted limit at once", () => {
    const c = new AdaptiveConcurrencyController({ ...base, windowSize: 1 }, 64);
    c.recordOutcome("e", false);
    assert.equal(c.limitFor("e"), 4);
    c.recordOutcome("e", false);
    assert.equal(c.limitFor("e"), 2);
    c.retune({ minLimit: 5 });
    assert.equal(c.limitFor("e"), 5);
    // The next congested window cannot push it back below the floor.
    c.recordOutcome("e", false);
    assert.equal(c.limitFor("e"), 5);
  });

  it("retuning initialLimit only affects endpoints with no adapted limit yet", () => {
    const c = new AdaptiveConcurrencyController(
      { ...base, increaseStep: 2, windowSize: 2 },
      64
    );
    c.recordOutcome("a", true);
    c.recordOutcome("a", true);
    assert.equal(c.limitFor("a"), 10);
    c.retune({ initialLimit: 3 });
    assert.equal(c.limitFor("a"), 10);
    assert.equal(c.limitFor("b"), 3);
  });

  it("lowering windowSize to the partial-window length makes the next outcome evaluate it", () => {
    const c = new AdaptiveConcurrencyController({ ...base, windowSize: 4 }, 64);
    c.recordOutcome("e", false);
    c.recordOutcome("e", false);
    c.recordOutcome("e", false);
    assert.equal(c.limitFor("e"), 8); // window not full yet
    c.retune({ windowSize: 3 });
    assert.equal(c.snapshot().windowSize, 3);
    c.recordOutcome("e", true);
    // 3 failures / 4 outcomes = 0.75 >= 0.2 → one decrease, window cleared.
    assert.equal(c.limitFor("e"), 4);
    assert.equal(c.stats()[0].windowOutcomes, 0);
  });

  it("raising windowSize postpones the next evaluation", () => {
    const c = new AdaptiveConcurrencyController(
      { ...base, windowSize: 2, failureRateThreshold: 0.5 },
      64
    );
    c.recordOutcome("e", false);
    c.retune({ windowSize: 4 });
    c.recordOutcome("e", false);
    assert.equal(c.limitFor("e"), 8); // 2 < 4: no evaluation yet
    c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 8); // 3 < 4: still no evaluation
    c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 4); // 2/4 = 0.5 >= 0.5 → decrease
  });

  it("illegal values and cross-gates throw RangeError and leave live state untouched", () => {
    const c = new AdaptiveConcurrencyController({ ...base }, 64);
    c.recordOutcome("e", true);
    c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 9);
    c.recordOutcome("e", false); // partial window: 1 outcome, 1 failure
    const before = c.snapshot();
    const illegal = [
      { minLimit: 0 },
      { minLimit: 1.5 },
      { maxLimit: 0 },
      { maxLimit: 64.5 },
      { initialLimit: 0 },
      { initialLimit: 100 },
      { increaseStep: 0 },
      { windowSize: 0 },
      { decreaseFactor: 0 },
      { decreaseFactor: 1 },
      { failureRateThreshold: -0.1 },
      { failureRateThreshold: 1.5 },
      { minLimit: 100 }, // maxLimit (64) < minLimit
      { maxLimit: 4 }, // initialLimit (8) out of [1, 4]
    ];
    for (const patch of illegal) {
      assert.throws(() => c.retune(patch), RangeError, JSON.stringify(patch));
      assert.deepEqual(c.snapshot(), before);
      assert.equal(c.limitFor("e"), 9);
      assert.equal(c.stats()[0].windowOutcomes, 1);
      assert.equal(c.stats()[0].windowFailures, 1);
    }
  });

  it("empty patch and non-object patches throw RangeError", () => {
    const c = new AdaptiveConcurrencyController({ ...base }, 64);
    const before = c.snapshot();
    assert.throws(() => c.retune({}), RangeError);
    assert.throws(() => c.retune(null as never), RangeError);
    assert.throws(() => c.retune("x" as never), RangeError);
    assert.throws(() => c.retune(42 as never), RangeError);
    assert.throws(() => c.retune([] as never), RangeError);
    assert.deepEqual(c.snapshot(), before);
  });

  it("a same-value patch is a silent no-op", () => {
    const c = new AdaptiveConcurrencyController({ ...base }, 64);
    c.recordOutcome("e", true);
    c.recordOutcome("e", true);
    assert.equal(c.limitFor("e"), 9);
    assert.deepEqual(c.retune({ ...base }), base);
    assert.deepEqual(c.retune({ increaseStep: 1, windowSize: 2 }), base);
    assert.deepEqual(c.snapshot(), base);
    assert.equal(c.limitFor("e"), 9);
  });

  it("snapshot() reads the seven live values", () => {
    const c = new AdaptiveConcurrencyController(
      { minLimit: 2, maxLimit: 10, initialLimit: 5, increaseStep: 2, decreaseFactor: 0.25, failureRateThreshold: 0.4, windowSize: 7 },
      10
    );
    assert.deepEqual(c.snapshot(), {
      minLimit: 2,
      maxLimit: 10,
      initialLimit: 5,
      increaseStep: 2,
      decreaseFactor: 0.25,
      failureRateThreshold: 0.4,
      windowSize: 7,
    });
    c.retune({ windowSize: 3, increaseStep: 1 });
    assert.deepEqual(c.snapshot(), {
      minLimit: 2,
      maxLimit: 10,
      initialLimit: 5,
      increaseStep: 1,
      decreaseFactor: 0.25,
      failureRateThreshold: 0.4,
      windowSize: 3,
    });
  });
});

describe("RetryQueue adaptive concurrency revision (WR-337)", () => {
  const alwaysFail: Sender = async () => {
    throw new Error("downstream down");
  };

  it("unconfigured: revise throws the must-restart Error, getter returns undefined", () => {
    const q = new RetryQueue({ sender: alwaysFail, baseDelayMs: 100, maxDelayMs: 60000 });
    assert.equal(q.getAdaptiveConcurrencyConfig(), undefined);
    assert.throws(
      () => q.reviseAdaptiveConcurrency({ failureRateThreshold: 0.5 }),
      /not configured — enabling it requires a restart/
    );
    assert.throws(
      () => q.reviseAdaptiveConcurrency({ failureRateThreshold: 0.5 }),
      /cannot start adapting limits without one/
    );
    assert.equal(q.getAdaptiveConcurrencyConfig(), undefined);
    q.stop();
  });

  it("getter tracks revisions", () => {
    const q = new RetryQueue({
      sender: alwaysFail,
      baseDelayMs: 100,
      maxDelayMs: 60000,
      adaptiveConcurrency: {
        minLimit: 1,
        maxLimit: 8,
        initialLimit: 4,
        increaseStep: 1,
        decreaseFactor: 0.5,
        failureRateThreshold: 0.2,
        windowSize: 20,
      },
    });
    assert.deepEqual(q.getAdaptiveConcurrencyConfig(), {
      minLimit: 1,
      maxLimit: 8,
      initialLimit: 4,
      increaseStep: 1,
      decreaseFactor: 0.5,
      failureRateThreshold: 0.2,
      windowSize: 20,
    });
    assert.deepEqual(q.reviseAdaptiveConcurrency({ failureRateThreshold: 0.5, windowSize: 5 }), {
      minLimit: 1,
      maxLimit: 8,
      initialLimit: 4,
      increaseStep: 1,
      decreaseFactor: 0.5,
      failureRateThreshold: 0.5,
      windowSize: 5,
    });
    assert.deepEqual(q.getAdaptiveConcurrencyConfig(), {
      minLimit: 1,
      maxLimit: 8,
      initialLimit: 4,
      increaseStep: 1,
      decreaseFactor: 0.5,
      failureRateThreshold: 0.5,
      windowSize: 5,
    });
    q.stop();
  });

  it("retuning maxLimit clamps the live limit and the next dispatch gates on it", async () => {
    const timer = manualTimer();
    const releases: Array<() => void> = [];
    let inFlight = 0;
    let maxInFlight = 0;
    let mode: "fail" | "block" = "fail";
    const sender: Sender = async () => {
      if (mode === "fail") throw new Error("downstream down");
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise<void>((r) => releases.push(r));
      inFlight -= 1;
    };
    const q = new RetryQueue({
      sender,
      maxAttempts: 1,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      maxConcurrentPerEndpoint: 8,
      adaptiveConcurrency: {
        minLimit: 1,
        maxLimit: 8,
        initialLimit: 8,
        windowSize: 1,
        decreaseFactor: 0.5,
      },
    });
    q.start();
    try {
      q.enqueue(item("d-1"));
      await timer.run();
      await flush();
      assert.equal(q.getAdaptiveConcurrencyStats()![0].limit, 4);
      mode = "block";
      // Lowering maxLimit below the live initialLimit (8) would trip
      // the initialLimit cross-gate, so the patch lowers both at once.
      q.reviseAdaptiveConcurrency({ maxLimit: 2, initialLimit: 2 });
      assert.equal(q.getAdaptiveConcurrencyStats()![0].limit, 2);
      assert.equal((q as any).limiter.maxFor(URL_A), 2);
      q.enqueue(item("d-2"));
      q.enqueue(item("d-3"));
      q.enqueue(item("d-4"));
      q.enqueue(item("d-5"));
      await timer.run();
      await flush();
      assert.equal(inFlight, 2);
      assert.equal(maxInFlight, 2);
      releases.splice(0).forEach((r) => r());
    } finally {
      q.stop();
    }
  });

  it("a tenant born after the retune starts from the revised values", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: alwaysFail,
      maxAttempts: 1,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      adaptiveConcurrency: {
        minLimit: 1,
        maxLimit: 8,
        initialLimit: 8,
        windowSize: 2,
        decreaseFactor: 0.5,
        failureRateThreshold: 0.5,
      },
    });
    q.start();
    try {
      q.enqueue(item("a-1", "acme"));
      q.enqueue(item("a-2", "acme"));
      await timer.run();
      await flush();
      const acme = q.getAdaptiveConcurrencyStats()!.find((s) => s.tenant === "acme")!;
      assert.equal(acme.limit, 4); // 2 failures fill the windowSize-2 window
      q.reviseAdaptiveConcurrency({ windowSize: 4 });
      q.enqueue(item("b-1", "beta"));
      q.enqueue(item("b-2", "beta"));
      await timer.run();
      await flush();
      const beta = q.getAdaptiveConcurrencyStats()!.find((s) => s.tenant === "beta")!;
      assert.equal(beta.limit, 8); // 2 failures < new windowSize 4: no evaluation yet
      assert.equal(beta.windowOutcomes, 2);
      q.enqueue(item("b-3", "beta"));
      q.enqueue(item("b-4", "beta"));
      await timer.run();
      await flush();
      const betaAfter = q.getAdaptiveConcurrencyStats()!.find((s) => s.tenant === "beta")!;
      assert.equal(betaAfter.limit, 4); // 4 failures fill the new window
      assert.equal(betaAfter.windowOutcomes, 0);
    } finally {
      q.stop();
    }
  });

  it("an illegal queue-level patch leaves every tenant controller untouched", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: alwaysFail,
      maxAttempts: 1,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      adaptiveConcurrency: {
        minLimit: 1,
        maxLimit: 8,
        initialLimit: 8,
        windowSize: 2,
        decreaseFactor: 0.5,
        failureRateThreshold: 0.5,
      },
    });
    q.start();
    try {
      q.enqueue(item("a-1", "acme"));
      q.enqueue(item("a-2", "acme"));
      await timer.run();
      await flush();
      const before = q.getAdaptiveConcurrencyConfig();
      const statsBefore = q.getAdaptiveConcurrencyStats();
      assert.throws(() => q.reviseAdaptiveConcurrency({ minLimit: 100 }), RangeError);
      assert.throws(() => q.reviseAdaptiveConcurrency({}), RangeError);
      assert.throws(() => q.reviseAdaptiveConcurrency(null as never), RangeError);
      assert.deepEqual(q.getAdaptiveConcurrencyConfig(), before);
      assert.deepEqual(q.getAdaptiveConcurrencyStats(), statsBefore);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer adaptive concurrency revision (WR-337)", () => {
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
    const dir = mkdtempSync(join(tmpdir(), "adaptive-concurrency-revision-"));
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

  const construction = {
    minLimit: 1,
    maxLimit: 8,
    initialLimit: 4,
    increaseStep: 1,
    decreaseFactor: 0.5,
    failureRateThreshold: 0.2,
    windowSize: 20,
  };

  it("revision audits previous/current with the construction values first; same-value is a silent no-op", async () => {
    const { relay, audit } = makeRelay({
      retry: { adaptiveConcurrency: { ...construction } },
    });
    await listen(relay);
    assert.deepEqual(relay.getAdaptiveConcurrencyConfig!(), construction);
    assert.deepEqual(relay.reviseAdaptiveConcurrency!({ failureRateThreshold: 0.5 }), {
      ...construction,
      failureRateThreshold: 0.5,
    });
    const revised = eventsOf(audit, "adaptive_concurrency_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, construction);
    assert.deepEqual(revised[0].current, { ...construction, failureRateThreshold: 0.5 });
    // Landing exactly on the live values audits nothing.
    relay.reviseAdaptiveConcurrency!({ failureRateThreshold: 0.5 });
    assert.equal(eventsOf(audit, "adaptive_concurrency_revised").length, 1);
    assert.deepEqual(relay.getAdaptiveConcurrencyConfig!(), {
      ...construction,
      failureRateThreshold: 0.5,
    });
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseAdaptiveConcurrency!({ decreaseFactor: 1 }), RangeError);
    assert.throws(() => relay.reviseAdaptiveConcurrency!({}), RangeError);
    assert.equal(eventsOf(audit, "adaptive_concurrency_revised").length, 1);
    assert.deepEqual(relay.getAdaptiveConcurrencyConfig!(), {
      ...construction,
      failureRateThreshold: 0.5,
    });
  });

  it("unconfigured relay: revise throws the must-restart Error and the getter is not mounted", async () => {
    const { relay } = makeRelay();
    await listen(relay);
    assert.equal(relay.getAdaptiveConcurrencyConfig, undefined);
    assert.throws(
      () => relay.reviseAdaptiveConcurrency!({ failureRateThreshold: 0.5 }),
      /not configured — enabling it requires a restart/
    );
  });

  it("server getter reflects revisions made through the server", async () => {
    const { relay } = makeRelay({
      retry: { adaptiveConcurrency: { minLimit: 1, maxLimit: 8, initialLimit: 4, windowSize: 3 } },
    });
    await listen(relay);
    assert.deepEqual(relay.getAdaptiveConcurrencyConfig!(), {
      minLimit: 1,
      maxLimit: 8,
      initialLimit: 4,
      increaseStep: 1,
      decreaseFactor: 0.5,
      failureRateThreshold: 0.2,
      windowSize: 3,
    });
    relay.reviseAdaptiveConcurrency!({ windowSize: 5, decreaseFactor: 0.25 });
    assert.deepEqual(relay.getAdaptiveConcurrencyConfig!(), {
      minLimit: 1,
      maxLimit: 8,
      initialLimit: 4,
      increaseStep: 1,
      decreaseFactor: 0.25,
      failureRateThreshold: 0.2,
      windowSize: 5,
    });
  });
});
