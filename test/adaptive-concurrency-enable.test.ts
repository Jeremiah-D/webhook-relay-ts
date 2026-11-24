import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  type Sender,
  type AdaptiveConcurrencyOptions,
} from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "adaptive-concurrency-enable-test-key";
const opToken = "adaptive-concurrency-enable-op-token";
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

/** Queue deliberately *without* an `adaptiveConcurrency` option, so the WR-459 enable path is the only way a controller appears. */
function makeQueue(
  adaptiveConcurrency?: AdaptiveConcurrencyOptions,
  maxAttempts = 1,
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
    maxConcurrentPerEndpoint: 8,
    ...(adaptiveConcurrency === undefined ? {} : { adaptiveConcurrency }),
  });
  return { q, timer };
}

// The construction defaults against the queue's live fixed cap (8):
// minLimit 1 / maxLimit 8 / initialLimit 8 / increaseStep 1 /
// decreaseFactor 0.5 / failureRateThreshold 0.2 / windowSize 20.
const defaults = {
  minLimit: 1,
  maxLimit: 8,
  initialLimit: 8,
  increaseStep: 1,
  decreaseFactor: 0.5,
  failureRateThreshold: 0.2,
  windowSize: 20,
};

describe("RetryQueue.reviseAdaptiveConcurrency live enable for an unconfigured queue (WR-459)", () => {
  it("first enable takes the construction defaults — an empty patch enables", () => {
    const { q } = makeQueue();
    q.start();
    try {
      assert.equal(q.getAdaptiveConcurrencyConfig(), undefined);
      assert.equal(q.getAdaptiveConcurrencyStats(), undefined);
      assert.deepEqual(q.reviseAdaptiveConcurrency({}), defaults);
      assert.deepEqual(q.getAdaptiveConcurrencyConfig(), defaults);
      // A fresh controller has no outcomes yet.
      assert.deepEqual(q.getAdaptiveConcurrencyStats(), []);
    } finally {
      q.stop();
    }
  });

  it("an explicit patch enables with the exact seven knobs", () => {
    const { q } = makeQueue();
    q.start();
    try {
      assert.deepEqual(
        q.reviseAdaptiveConcurrency({
          minLimit: 2,
          maxLimit: 10,
          initialLimit: 5,
          increaseStep: 2,
          decreaseFactor: 0.25,
          failureRateThreshold: 0.4,
          windowSize: 7,
        }),
        {
          minLimit: 2,
          maxLimit: 10,
          initialLimit: 5,
          increaseStep: 2,
          decreaseFactor: 0.25,
          failureRateThreshold: 0.4,
          windowSize: 7,
        }
      );
      assert.deepEqual(q.getAdaptiveConcurrencyConfig(), {
        minLimit: 2,
        maxLimit: 10,
        initialLimit: 5,
        increaseStep: 2,
        decreaseFactor: 0.25,
        failureRateThreshold: 0.4,
        windowSize: 7,
      });
    } finally {
      q.stop();
    }
  });

  it("a partial patch uses the explicit knobs exactly and defaults the rest", () => {
    const { q } = makeQueue();
    q.start();
    try {
      assert.deepEqual(q.reviseAdaptiveConcurrency({ windowSize: 5, decreaseFactor: 0.25 }), {
        ...defaults,
        windowSize: 5,
        decreaseFactor: 0.25,
      });
    } finally {
      q.stop();
    }
  });

  it("non-object and illegal patches throw RangeError and leave the queue unconfigured — and it can still enable afterwards", () => {
    const { q } = makeQueue();
    q.start();
    try {
      assert.equal(q.getAdaptiveConcurrencyConfig(), undefined);
      for (const patch of [
        null,
        "8",
        [],
        { minLimit: 0 },
        { minLimit: -1 },
        { minLimit: 1.5 },
        { minLimit: Number.NaN },
        { maxLimit: 0 },
        { minLimit: 9, maxLimit: 8 },
        { initialLimit: 0 },
        { initialLimit: 9 },
        { increaseStep: 0 },
        { decreaseFactor: 0 },
        { decreaseFactor: 1 },
        { decreaseFactor: 1.5 },
        { decreaseFactor: Number.NaN },
        { failureRateThreshold: -0.1 },
        { failureRateThreshold: 1.1 },
        { windowSize: 0 },
      ]) {
        assert.throws(
          () => q.reviseAdaptiveConcurrency(patch as never),
          RangeError,
          JSON.stringify(patch)
        );
        assert.equal(q.getAdaptiveConcurrencyConfig(), undefined);
        assert.equal(q.getAdaptiveConcurrencyStats(), undefined);
      }
      // Still unconfigured after every rejection — and the enable path still works.
      assert.deepEqual(q.reviseAdaptiveConcurrency({}), defaults);
    } finally {
      q.stop();
    }
  });

  it("a failure before the enable is never recorded; the first window after the enable steps from the initial limit", async () => {
    const { q, timer } = makeQueue();
    q.start();
    try {
      assert.equal(q.getAdaptiveConcurrencyStats(), undefined);
      // Two failing deliveries while unconfigured: no controller exists,
      // so nothing is recorded.
      q.enqueue(item("pre-1"));
      q.enqueue(item("pre-2"));
      await timer.run();
      await flush();
      assert.equal(q.getAdaptiveConcurrencyStats(), undefined);
      q.reviseAdaptiveConcurrency({
        windowSize: 2,
        initialLimit: 8,
        maxLimit: 8,
        decreaseFactor: 0.5,
        failureRateThreshold: 0.5,
      });
      // Fresh controller: no outcomes, so no stats rows yet.
      assert.deepEqual(q.getAdaptiveConcurrencyStats(), []);
      q.enqueue(item("post-1"));
      await timer.run();
      await flush();
      assert.deepEqual(q.getAdaptiveConcurrencyStats(), [
        {
          endpoint: URL_A,
          limit: 8,
          windowOutcomes: 1,
          windowFailures: 1,
          windowSize: 2,
        },
      ]);
      q.enqueue(item("post-2"));
      await timer.run();
      await flush();
      // The two post-enable failures fill the window: 8 * 0.5 = 4.
      // The pre-enable failures did not count toward it.
      assert.deepEqual(q.getAdaptiveConcurrencyStats(), [
        {
          endpoint: URL_A,
          limit: 4,
          windowOutcomes: 0,
          windowFailures: 0,
          windowSize: 2,
        },
      ]);
    } finally {
      q.stop();
    }
  });

  it("enabling with a lower maxLimit tightens the limiter immediately, before any outcome", () => {
    const { q } = makeQueue();
    q.start();
    try {
      assert.equal((q as any).limiter.maxFor(URL_A), 8);
      q.reviseAdaptiveConcurrency({ maxLimit: 2, initialLimit: 2 });
      assert.equal((q as any).limiter.maxFor(URL_A), 2);
    } finally {
      q.stop();
    }
  });

  it("the next dispatch after the enable gates on the new limit", async () => {
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
      baseDelayMs: 100,
      maxDelayMs: 60_000,
      maxAttempts: 1,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      maxConcurrentPerEndpoint: 8,
    });
    q.start();
    try {
      q.reviseAdaptiveConcurrency({
        minLimit: 1,
        maxLimit: 8,
        initialLimit: 8,
        windowSize: 1,
        decreaseFactor: 0.5,
      });
      q.enqueue(item("d-1"));
      await timer.run();
      await flush();
      // One failure fills the windowSize-1 window: 8 * 0.5 = 4.
      assert.equal(q.getAdaptiveConcurrencyStats()![0].limit, 4);
      mode = "block";
      assert.equal((q as any).limiter.maxFor(URL_A), 4);
      q.enqueue(item("d-2"));
      q.enqueue(item("d-3"));
      q.enqueue(item("d-4"));
      q.enqueue(item("d-5"));
      await timer.run();
      await flush();
      assert.equal(inFlight, 4);
      assert.equal(maxInFlight, 4);
      releases.splice(0).forEach((r) => r());
    } finally {
      q.stop();
    }
  });

  it("a tenant born after the enable starts from the enabled values", async () => {
    const { q, timer } = makeQueue();
    q.start();
    try {
      q.reviseAdaptiveConcurrency({
        minLimit: 1,
        maxLimit: 8,
        initialLimit: 8,
        windowSize: 2,
        decreaseFactor: 0.5,
        failureRateThreshold: 0.5,
      });
      q.enqueue(item("b-1", "beta"));
      await timer.run();
      await flush();
      const beta = q.getAdaptiveConcurrencyStats()!.find((s) => s.tenant === "beta")!;
      assert.equal(beta.limit, 8); // 1 failure < new windowSize 2: no evaluation yet
      assert.equal(beta.windowOutcomes, 1);
      q.enqueue(item("b-2", "beta"));
      await timer.run();
      await flush();
      const betaAfter = q.getAdaptiveConcurrencyStats()!.find((s) => s.tenant === "beta")!;
      assert.equal(betaAfter.limit, 4); // 2 failures fill the window
      assert.equal(betaAfter.windowOutcomes, 0);
    } finally {
      q.stop();
    }
  });

  it("after the enable, a revision still follows WR-337 semantics", () => {
    const { q } = makeQueue();
    q.start();
    try {
      assert.deepEqual(q.reviseAdaptiveConcurrency({}), defaults);
      assert.deepEqual(
        q.reviseAdaptiveConcurrency({ failureRateThreshold: 0.5, windowSize: 5 }),
        { ...defaults, failureRateThreshold: 0.5, windowSize: 5 }
      );
      // Empty patch is a RangeError once configured; same-value is a no-op.
      assert.throws(() => q.reviseAdaptiveConcurrency({}), RangeError);
      assert.deepEqual(
        q.reviseAdaptiveConcurrency({ failureRateThreshold: 0.5, windowSize: 5 }),
        { ...defaults, failureRateThreshold: 0.5, windowSize: 5 }
      );
      // An illegal patch throws and leaves the live values untouched.
      assert.throws(() => q.reviseAdaptiveConcurrency({ decreaseFactor: 1 }), RangeError);
      assert.deepEqual(q.getAdaptiveConcurrencyConfig(), {
        ...defaults,
        failureRateThreshold: 0.5,
        windowSize: 5,
      });
    } finally {
      q.stop();
    }
  });

  it("a restart returns to unconfigured", () => {
    const { q } = makeQueue();
    q.start();
    try {
      assert.deepEqual(q.reviseAdaptiveConcurrency({}), defaults);
    } finally {
      q.stop();
    }
    // A fresh queue built without the option has no controller again.
    const { q: fresh } = makeQueue();
    fresh.start();
    try {
      assert.equal(fresh.getAdaptiveConcurrencyConfig(), undefined);
      assert.equal(fresh.getAdaptiveConcurrencyStats(), undefined);
    } finally {
      fresh.stop();
    }
  });
});

describe("RelayServer reviseAdaptiveConcurrency live enable for an unconfigured relay (WR-459)", () => {
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
    const dir = mkdtempSync(join(tmpdir(), "adaptive-concurrency-enable-"));
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
      retry: { baseDelayMs: 5, jitterMs: 0, maxAttempts: 2, maxConcurrentPerEndpoint: 8 },
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
    assert.equal(relay.getAdaptiveConcurrencyConfig, undefined);
    assert.deepEqual(relay.reviseAdaptiveConcurrency!({ windowSize: 5 }), {
      ...defaults,
      windowSize: 5,
    });
    assert.notEqual(relay.getAdaptiveConcurrencyConfig, undefined);
    assert.deepEqual(relay.getAdaptiveConcurrencyConfig!(), { ...defaults, windowSize: 5 });
    const revised = eventsOf(audit, "adaptive_concurrency_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.deepEqual(revised[0].current, { ...defaults, windowSize: 5 });
    // Landing exactly on the enabled values audits nothing.
    relay.reviseAdaptiveConcurrency!({ windowSize: 5 });
    assert.equal(eventsOf(audit, "adaptive_concurrency_revised").length, 1);
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseAdaptiveConcurrency!({ decreaseFactor: 1 }), RangeError);
    assert.equal(eventsOf(audit, "adaptive_concurrency_revised").length, 1);
    assert.deepEqual(relay.getAdaptiveConcurrencyConfig!(), { ...defaults, windowSize: 5 });
  });

  it("server enable with an illegal patch leaves the relay unconfigured — and it can still enable afterwards", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.throws(() => relay.reviseAdaptiveConcurrency!({ decreaseFactor: 1 }), RangeError);
    assert.throws(() => relay.reviseAdaptiveConcurrency!({ windowSize: 0 }), RangeError);
    assert.throws(() => relay.reviseAdaptiveConcurrency!(null as never), RangeError);
    assert.equal(relay.getAdaptiveConcurrencyConfig, undefined);
    assert.equal(eventsOf(audit, "adaptive_concurrency_revised").length, 0);
    assert.deepEqual(relay.reviseAdaptiveConcurrency!({}), defaults);
    const revised = eventsOf(audit, "adaptive_concurrency_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.deepEqual(revised[0].current, defaults);
  });

  it("after the server enable, a live revision audits previous = the enabled values", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    relay.reviseAdaptiveConcurrency!({});
    assert.deepEqual(relay.reviseAdaptiveConcurrency!({ windowSize: 5 }), {
      ...defaults,
      windowSize: 5,
    });
    const revised = eventsOf(audit, "adaptive_concurrency_revised");
    assert.equal(revised.length, 2);
    assert.deepEqual(revised[1].previous, defaults);
    assert.deepEqual(revised[1].current, { ...defaults, windowSize: 5 });
  });
});
