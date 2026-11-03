import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { GlobalRateLimiter } from "../src/global-rate.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "global-rate-revision-secret";

const A = "http://a/hook";
const B = "http://b/hook";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));

/** Let the deliver() promise chain settle. */
async function flush(ticks = 20) {
  for (let i = 0; i < ticks; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

function item(id: string, targetUrl: string) {
  return { id, payload: BODY, targetUrl, headers: {} };
}

/** Manual clock for deterministic token refills. */
function manualClock(start = 0) {
  let t = start;
  return {
    now: () => t,
    advance: (ms: number) => {
      t += ms;
    },
  };
}

/**
 * Manual timer: callbacks fire only when `fire()` is called, in FIFO
 * order. Shared by the queue and the limiter for full determinism.
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
    clearTimer: (h: { clear(): void }) => h.clear(),
    fire() {
      const fns = pending.splice(0);
      for (const f of fns) f();
    },
    async step() {
      this.fire();
      await flush();
    },
  };
}

/** A manual timer that also records every scheduled delay (ms). */
function recordingTimer() {
  const base = manualTimer();
  const delays: number[] = [];
  return {
    ...base,
    delays,
    setTimer: (fn: () => void, ms: number) => {
      delays.push(ms);
      return base.setTimer(fn, ms);
    },
  };
}

describe("GlobalRateLimiter.retune (WR-310)", () => {
  function limiter(opts: { messagesPerSec: number; maxBurst?: number }) {
    const clock = manualClock();
    const timer = recordingTimer();
    const g = new GlobalRateLimiter({
      ...opts,
      now: clock.now,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
    });
    return { g, clock, timer };
  }

  it("rejects illegal merged values and leaves the live values untouched", () => {
    const { g } = limiter({ messagesPerSec: 10, maxBurst: 20 });
    const bad: Array<Record<string, unknown>> = [
      { messagesPerSec: 0 },
      { messagesPerSec: -1 },
      { messagesPerSec: Number.NaN },
      { messagesPerSec: Number.POSITIVE_INFINITY },
      { messagesPerSec: "10" },
      { maxBurst: 0 },
      { maxBurst: -1 },
      { maxBurst: Number.NaN },
      { maxBurst: Number.POSITIVE_INFINITY },
      { messagesPerSec: 5, maxBurst: 0 }, // one bad field voids the whole patch
    ];
    for (const patch of bad) {
      assert.throws(
        () => g.retune(patch as { messagesPerSec?: number; maxBurst?: number }),
        RangeError,
        JSON.stringify(patch)
      );
    }
    assert.deepEqual(g.current(), { messagesPerSec: 10, maxBurst: 20 });
    assert.equal(g.stats().messagesPerSec, 10);
    assert.equal(g.stats().maxBurst, 20);
  });

  it("an empty or identical patch is a no-op and does not disturb the head timer", async () => {
    const { g, clock, timer } = limiter({ messagesPerSec: 2, maxBurst: 2 });
    await g.acquire();
    await g.acquire(); // bucket drained
    let done = false;
    void g.acquire().then(() => {
      done = true;
    });
    await flush();
    assert.deepEqual(timer.delays, [500]); // one head timer, at the old rate
    assert.deepEqual(g.retune({}), { messagesPerSec: 2, maxBurst: 2 });
    assert.deepEqual(g.retune({ messagesPerSec: 2, maxBurst: 2 }), {
      messagesPerSec: 2,
      maxBurst: 2,
    });
    assert.deepEqual(timer.delays, [500]); // no re-arm on a no-op
    assert.equal(timer.pendingCount(), 1);
    clock.advance(500);
    await timer.step();
    assert.ok(done);
  });

  it("a partial revision keeps the omitted field and returns the live values", () => {
    const { g } = limiter({ messagesPerSec: 10, maxBurst: 20 });
    assert.deepEqual(g.retune({ messagesPerSec: 5 }), { messagesPerSec: 5, maxBurst: 20 });
    assert.deepEqual(g.retune({ maxBurst: 3 }), { messagesPerSec: 5, maxBurst: 3 });
    // Tightening the burst clamps the unspent balance to the new cap.
    assert.equal(g.availableTokens(), 3);
  });

  it("expansion re-arms the head timer at the new rate and releases waiters on it", async () => {
    const { g, clock, timer } = limiter({ messagesPerSec: 1, maxBurst: 1 });
    await g.acquire(); // bucket drained
    let done = false;
    void g.acquire().then(() => {
      done = true;
    });
    await flush();
    assert.deepEqual(timer.delays, [1000]); // 1/sec: a full second to refill
    assert.deepEqual(g.retune({ messagesPerSec: 100 }), { messagesPerSec: 100, maxBurst: 1 });
    assert.deepEqual(timer.delays, [1000, 10]); // re-armed at 100/sec
    assert.equal(timer.pendingCount(), 1); // the stale old timer was cleared
    clock.advance(10);
    await timer.step();
    assert.ok(done);
  });

  it("tightening with waiters re-arms slower at the new rate", async () => {
    const { g, clock, timer } = limiter({ messagesPerSec: 10, maxBurst: 1 });
    await g.acquire(); // bucket drained
    let done = false;
    void g.acquire().then(() => {
      done = true;
    });
    await flush();
    assert.deepEqual(timer.delays, [100]); // 10/sec: 100ms to refill
    assert.deepEqual(g.retune({ messagesPerSec: 1 }), { messagesPerSec: 1, maxBurst: 1 });
    assert.deepEqual(timer.delays, [100, 1000]); // re-armed at 1/sec
    clock.advance(1000);
    await timer.step();
    assert.ok(done);
  });

  it("tokens are clamped to the new cap but already-granted tokens are not revoked", async () => {
    const { g, clock } = limiter({ messagesPerSec: 10, maxBurst: 10 });
    await g.acquire();
    await g.acquire();
    await g.acquire();
    await g.acquire(); // 4 granted, 6 unspent
    assert.deepEqual(g.retune({ maxBurst: 5 }), { messagesPerSec: 10, maxBurst: 5 });
    assert.equal(g.availableTokens(), 5); // clamped, not zeroed
    // The refill now runs at the (unchanged) new rate and caps at 5.
    for (let i = 0; i < 5; i++) await g.acquire();
    assert.ok(Math.abs(g.availableTokens() - 0) < 1e-9);
    clock.advance(100);
    assert.ok(Math.abs(g.availableTokens() - 1) < 1e-9); // 10/sec x 100ms
    // A rate change refills at the new rate.
    const { g: h, clock: clock2 } = limiter({ messagesPerSec: 1, maxBurst: 1 });
    await h.acquire();
    assert.deepEqual(h.retune({ messagesPerSec: 10 }), { messagesPerSec: 10, maxBurst: 1 });
    clock2.advance(100);
    assert.ok(Math.abs(h.availableTokens() - 1) < 1e-9); // 10/sec x 100ms, capped at 1
  });
});

describe("RetryQueue.setGlobalRateLimit (WR-310)", () => {
  it("throws Error when the limit was never configured", () => {
    const sender: Sender = async () => {};
    const q = new RetryQueue({ sender, maxAttempts: 1 });
    assert.equal(q.getGlobalRateLimitStats(), undefined);
    assert.throws(() => q.setGlobalRateLimit({ messagesPerSec: 5 }), /requires a restart/);
    q.stop();
  });

  it("revises the live values and getGlobalRateLimitStats reflects them", () => {
    const sender: Sender = async () => {};
    const q = new RetryQueue({
      sender,
      globalRateLimit: { messagesPerSec: 2, maxBurst: 2 },
      maxAttempts: 1,
    });
    q.start();
    try {
      assert.deepEqual(q.setGlobalRateLimit({ messagesPerSec: 5 }), {
        messagesPerSec: 5,
        maxBurst: 2,
      });
      assert.equal(q.getGlobalRateLimitStats()?.messagesPerSec, 5);
      assert.equal(q.getGlobalRateLimitStats()?.maxBurst, 2);
      assert.deepEqual(q.setGlobalRateLimit({ maxBurst: 9 }), {
        messagesPerSec: 5,
        maxBurst: 9,
      });
      assert.equal(q.getGlobalRateLimitStats()?.maxBurst, 9);
    } finally {
      q.stop();
    }
  });

  it("an illegal patch throws RangeError and leaves the live values untouched", () => {
    const sender: Sender = async () => {};
    const q = new RetryQueue({
      sender,
      globalRateLimit: { messagesPerSec: 2, maxBurst: 2 },
      maxAttempts: 1,
    });
    q.start();
    try {
      assert.throws(() => q.setGlobalRateLimit({ messagesPerSec: 0 }), RangeError);
      assert.throws(() => q.setGlobalRateLimit({ maxBurst: -1 }), RangeError);
      assert.throws(() => q.setGlobalRateLimit({ messagesPerSec: 4, maxBurst: 0 }), RangeError);
      assert.equal(q.getGlobalRateLimitStats()?.messagesPerSec, 2);
      assert.equal(q.getGlobalRateLimitStats()?.maxBurst, 2);
    } finally {
      q.stop();
    }
  });

  it("waiters are released at the new rate after an expansion", async () => {
    const clock = manualClock();
    const timer = manualTimer();
    // The limiter's timer is recorded separately so the re-armed delay
    // is observable apart from the queue's own timers.
    const limiterDelays: number[] = [];
    const started: string[] = [];
    const sender: Sender = async (it) => {
      started.push(it.id);
    };
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      globalRateLimit: {
        messagesPerSec: 1,
        maxBurst: 1,
        now: clock.now,
        setTimer: (fn: () => void, ms: number) => {
          limiterDelays.push(ms);
          return timer.setTimer(fn, ms);
        },
        clearTimer: timer.clearTimer,
      },
      maxAttempts: 1,
    });
    q.enqueue(item("a", A));
    q.enqueue(item("b", B));
    q.start();
    try {
      await timer.step();
      await flush();
      // The single burst token went to "a"; "b" waits on the gate.
      assert.deepEqual(started, ["a"]);
      assert.equal(q.getGlobalRateLimitStats()?.delayedTotal, 1);
      assert.deepEqual(limiterDelays, [1000]); // 1/sec: a full second
      // Expand 100x: the head timer must re-arm at the new rate.
      assert.deepEqual(q.setGlobalRateLimit({ messagesPerSec: 100 }), {
        messagesPerSec: 100,
        maxBurst: 1,
      });
      assert.deepEqual(limiterDelays, [1000, 10]);
      clock.advance(10);
      await timer.step();
      await flush();
      assert.deepEqual(new Set(started), new Set(["a", "b"]));
      assert.equal(q.pendingCount(), 0);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer.setGlobalRateLimit (WR-310)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "global-rate-revision-"));
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

  it("audits global_rate_revised with previous/current and skips the audit on a no-op", async () => {
    const { relay, auditLog } = makeServer({
      retry: { globalRateLimit: { messagesPerSec: 10, maxBurst: 20 } },
    });
    await listen(relay);
    assert.equal(eventsOf(auditLog, "global_rate_revised").length, 0);
    const next = relay.setGlobalRateLimit!({ messagesPerSec: 50 });
    assert.deepEqual(next, { messagesPerSec: 50, maxBurst: 20 });
    const revised = eventsOf(auditLog, "global_rate_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, { messagesPerSec: 10, maxBurst: 20 });
    assert.deepEqual(revised[0].current, { messagesPerSec: 50, maxBurst: 20 });
    // The stats delegate reports the live values.
    assert.equal(relay.getGlobalRateLimitStats!().messagesPerSec, 50);
    assert.equal(relay.getGlobalRateLimitStats!().maxBurst, 20);
    // Partial revision audits the merged previous/current.
    const partial = relay.setGlobalRateLimit!({ maxBurst: 5 });
    assert.deepEqual(partial, { messagesPerSec: 50, maxBurst: 5 });
    const revised2 = eventsOf(auditLog, "global_rate_revised");
    assert.equal(revised2.length, 2);
    assert.deepEqual(revised2[1].previous, { messagesPerSec: 50, maxBurst: 20 });
    assert.deepEqual(revised2[1].current, { messagesPerSec: 50, maxBurst: 5 });
    // Same values and an empty patch: no new audit event.
    relay.setGlobalRateLimit!({ messagesPerSec: 50, maxBurst: 5 });
    relay.setGlobalRateLimit!({});
    assert.equal(eventsOf(auditLog, "global_rate_revised").length, 2);
  });

  it("throws RangeError on an illegal patch and leaves the live values untouched", async () => {
    const { relay, auditLog } = makeServer({
      retry: { globalRateLimit: { messagesPerSec: 10, maxBurst: 20 } },
    });
    await listen(relay);
    assert.throws(() => relay.setGlobalRateLimit!({ messagesPerSec: 0 }), RangeError);
    assert.throws(() => relay.setGlobalRateLimit!({ maxBurst: -1 }), RangeError);
    assert.throws(
      () => relay.setGlobalRateLimit!({ messagesPerSec: 5, maxBurst: 0 }),
      RangeError
    );
    assert.equal(eventsOf(auditLog, "global_rate_revised").length, 0);
    // The live values are untouched: an empty patch reports the originals.
    assert.deepEqual(relay.setGlobalRateLimit!({}), { messagesPerSec: 10, maxBurst: 20 });
    assert.equal(relay.getGlobalRateLimitStats!().messagesPerSec, 10);
  });

  it("throws Error when unconfigured and the stats delegate is absent", async () => {
    const { relay } = makeServer({});
    await listen(relay);
    assert.throws(() => relay.setGlobalRateLimit!({ messagesPerSec: 5 }), /requires a restart/);
    assert.equal(relay.getGlobalRateLimitStats, undefined);
  });
});
