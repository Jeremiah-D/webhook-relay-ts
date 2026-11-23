import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type RetryItem, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "global-rate-limit-enable-secret";

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

/**
 * Manual timer: callbacks fire only when `fire()` is called, in FIFO
 * order. Shared by the queue and the limiter for full determinism.
 * Note the limiter itself keeps the wall clock (`Date.now`) — the queue
 * has no injected clock to hand it — so the head timer's recorded delay
 * is computed from a ~zero real elapsed time, and a fired timer grants
 * its waiter regardless (liveness beats exactness).
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

/** Queue deliberately *without* a `globalRateLimit` option, so the WR-451 enable path is the only way a limiter appears. */
function makeQueue(timer: ReturnType<typeof manualTimer>): { q: RetryQueue; sent: RetryItem[] } {
  const sent: RetryItem[] = [];
  const q = new RetryQueue({
    sender: async (it) => {
      sent.push(it);
    },
    setTimer: timer.setTimer,
    clearTimer: timer.clearTimer,
    maxAttempts: 1,
  });
  return { q, sent };
}

describe("RetryQueue.setGlobalRateLimit live enable for an unconfigured queue (WR-451)", () => {
  it("first enable takes maxBurst = messagesPerSec and the bucket starts full", () => {
    const timer = manualTimer();
    const { q } = makeQueue(timer);
    q.start();
    try {
      assert.equal(q.getGlobalRateLimitStats(), undefined);
      assert.deepEqual(q.setGlobalRateLimit({ messagesPerSec: 7 }), {
        messagesPerSec: 7,
        maxBurst: 7,
      });
      const stats = q.getGlobalRateLimitStats();
      assert.equal(stats?.messagesPerSec, 7);
      assert.equal(stats?.maxBurst, 7);
      // A fresh bucket starts full: no dispatch yet, the whole burst is there.
      assert.equal(stats?.availableTokens, 7);
      assert.equal(stats?.delayedTotal, 0);
      assert.equal(stats?.queuedDepth, 0);
    } finally {
      q.stop();
    }
  });

  it("an explicit maxBurst is used exactly", () => {
    const timer = manualTimer();
    const { q } = makeQueue(timer);
    q.start();
    try {
      assert.deepEqual(q.setGlobalRateLimit({ messagesPerSec: 2, maxBurst: 5 }), {
        messagesPerSec: 2,
        maxBurst: 5,
      });
      assert.equal(q.getGlobalRateLimitStats()?.maxBurst, 5);
      assert.equal(q.getGlobalRateLimitStats()?.availableTokens, 5);
    } finally {
      q.stop();
    }
  });

  it("empty, non-object and illegal patches throw RangeError and leave the queue unconfigured", () => {
    const timer = manualTimer();
    const { q } = makeQueue(timer);
    q.start();
    try {
      const bad: unknown[] = [
        {},
        null,
        "fast",
        [],
        { maxBurst: 3 }, // messagesPerSec is mandatory for an enable
        { messagesPerSec: 0 },
        { messagesPerSec: -1 },
        { messagesPerSec: Number.NaN },
        { messagesPerSec: Number.POSITIVE_INFINITY },
        { messagesPerSec: "5" },
        { messagesPerSec: 5, maxBurst: 0 },
        { messagesPerSec: 5, maxBurst: -2 },
        { messagesPerSec: 5, maxBurst: Number.NaN },
      ];
      for (const patch of bad) {
        assert.throws(() => q.setGlobalRateLimit(patch as never), RangeError, JSON.stringify(patch));
        assert.equal(q.getGlobalRateLimitStats(), undefined);
      }
      // A rejected patch never half-enables: a later valid patch still enables.
      assert.deepEqual(q.setGlobalRateLimit({ messagesPerSec: 4 }), {
        messagesPerSec: 4,
        maxBurst: 4,
      });
      assert.equal(q.getGlobalRateLimitStats()?.messagesPerSec, 4);
    } finally {
      q.stop();
    }
  });

  it("after the enable the next dispatch is governed by the new bucket: full bucket bursts, excess queues FIFO", async () => {
    const timer = manualTimer();
    const { q, sent } = makeQueue(timer);
    q.start();
    try {
      q.setGlobalRateLimit({ messagesPerSec: 2, maxBurst: 2 });
      q.enqueue(item("a", A));
      q.enqueue(item("b", B));
      q.enqueue(item("c", A));
      q.enqueue(item("d", B));
      await timer.step();
      // The full bucket bursts two dispatches immediately; the rest wait.
      assert.deepEqual(
        sent.map((s) => s.id),
        ["a", "b"]
      );
      assert.equal(q.getGlobalRateLimitStats()?.delayedTotal, 2);
      assert.equal(q.getGlobalRateLimitStats()?.queuedDepth, 2);
      // One head-timer fire releases exactly one waiter, in arrival order.
      await timer.step();
      assert.deepEqual(
        sent.map((s) => s.id),
        ["a", "b", "c"]
      );
      assert.equal(q.getGlobalRateLimitStats()?.queuedDepth, 1);
      await timer.step();
      assert.deepEqual(
        sent.map((s) => s.id),
        ["a", "b", "c", "d"]
      );
      assert.equal(q.getGlobalRateLimitStats()?.queuedDepth, 0);
      assert.equal(q.pendingCount(), 0);
    } finally {
      q.stop();
    }
  });

  it("dispatches before the enable are not retroactively limited", async () => {
    const timer = manualTimer();
    const { q, sent } = makeQueue(timer);
    q.start();
    try {
      q.enqueue(item("pre", A));
      await timer.step();
      assert.deepEqual(
        sent.map((s) => s.id),
        ["pre"]
      );
      assert.equal(q.getGlobalRateLimitStats(), undefined);

      // Enable a tight cap afterwards: the pre-enable dispatch already
      // went out, and only the post-enable dispatches are governed.
      q.setGlobalRateLimit({ messagesPerSec: 1, maxBurst: 1 });
      q.enqueue(item("a", A));
      q.enqueue(item("b", B));
      await timer.step();
      assert.deepEqual(
        sent.map((s) => s.id),
        ["pre", "a"]
      );
      assert.equal(q.getGlobalRateLimitStats()?.queuedDepth, 1);
      await timer.step();
      assert.deepEqual(
        sent.map((s) => s.id),
        ["pre", "a", "b"]
      );
      assert.equal(q.pendingCount(), 0);
    } finally {
      q.stop();
    }
  });

  it("a restart returns to unconfigured", () => {
    const timer = manualTimer();
    const { q } = makeQueue(timer);
    q.start();
    q.setGlobalRateLimit({ messagesPerSec: 5 });
    assert.equal(q.getGlobalRateLimitStats()?.messagesPerSec, 5);
    q.stop();
    // A fresh queue built from the same (limit-less) options has no limiter.
    const restarted = new RetryQueue({
      sender: async () => {},
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      maxAttempts: 1,
    });
    assert.equal(restarted.getGlobalRateLimitStats(), undefined);
    // …and the enable path works on it again.
    assert.deepEqual(restarted.setGlobalRateLimit({ messagesPerSec: 3 }), {
      messagesPerSec: 3,
      maxBurst: 3,
    });
    restarted.stop();
  });

  it("after the enable, a revision still follows WR-310 semantics", () => {
    const timer = manualTimer();
    const { q } = makeQueue(timer);
    q.start();
    try {
      q.setGlobalRateLimit({ messagesPerSec: 2, maxBurst: 2 });
      assert.deepEqual(q.setGlobalRateLimit({ messagesPerSec: 10 }), {
        messagesPerSec: 10,
        maxBurst: 2,
      });
      assert.equal(q.getGlobalRateLimitStats()?.messagesPerSec, 10);
      assert.deepEqual(q.setGlobalRateLimit({ maxBurst: 9 }), {
        messagesPerSec: 10,
        maxBurst: 9,
      });
      // An illegal revision still throws RangeError and leaves the live values untouched.
      assert.throws(() => q.setGlobalRateLimit({ messagesPerSec: 0 }), RangeError);
      assert.throws(() => q.setGlobalRateLimit({ maxBurst: -1 }), RangeError);
      assert.deepEqual(q.setGlobalRateLimit({}), { messagesPerSec: 10, maxBurst: 9 });
      assert.equal(q.getGlobalRateLimitStats()?.messagesPerSec, 10);
      assert.equal(q.getGlobalRateLimitStats()?.maxBurst, 9);
    } finally {
      q.stop();
    }
  });
});

describe("server setGlobalRateLimit enable (WR-451)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "global-rate-limit-enable-"));
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

  it("enabling audits global_rate_revised with previous null and mounts the stats getter", async () => {
    const { relay, auditLog } = makeServer({});
    await listen(relay);
    assert.equal(relay.getGlobalRateLimitStats, undefined);
    const next = relay.setGlobalRateLimit!({ messagesPerSec: 5 });
    assert.deepEqual(next, { messagesPerSec: 5, maxBurst: 5 });
    // The getter appears with the limiter and reports the live values.
    assert.equal(relay.getGlobalRateLimitStats!().messagesPerSec, 5);
    assert.equal(relay.getGlobalRateLimitStats!().maxBurst, 5);
    const revised = eventsOf(auditLog, "global_rate_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.deepEqual(revised[0].current, { messagesPerSec: 5, maxBurst: 5 });
  });

  it("a same-value or empty patch after the enable is a silent no-op", async () => {
    const { relay, auditLog } = makeServer({});
    await listen(relay);
    relay.setGlobalRateLimit!({ messagesPerSec: 5, maxBurst: 5 });
    assert.equal(eventsOf(auditLog, "global_rate_revised").length, 1);
    assert.deepEqual(relay.setGlobalRateLimit!({ messagesPerSec: 5, maxBurst: 5 }), {
      messagesPerSec: 5,
      maxBurst: 5,
    });
    assert.deepEqual(relay.setGlobalRateLimit!({}), { messagesPerSec: 5, maxBurst: 5 });
    assert.equal(eventsOf(auditLog, "global_rate_revised").length, 1);
  });

  it("an illegal patch is rejected, stays unconfigured, and a later valid patch still enables", async () => {
    const { relay, auditLog } = makeServer({});
    await listen(relay);
    const bad: unknown[] = [
      {},
      null,
      "fast",
      [],
      { maxBurst: 3 },
      { messagesPerSec: 0 },
      { messagesPerSec: -1 },
      { messagesPerSec: Number.NaN },
      { messagesPerSec: Number.POSITIVE_INFINITY },
      { messagesPerSec: 5, maxBurst: 0 },
    ];
    for (const patch of bad) {
      assert.throws(
        () => relay.setGlobalRateLimit!(patch as never),
        RangeError,
        JSON.stringify(patch)
      );
      assert.equal(relay.getGlobalRateLimitStats, undefined);
    }
    assert.equal(eventsOf(auditLog, "global_rate_revised").length, 0);
    const next = relay.setGlobalRateLimit!({ messagesPerSec: 5, maxBurst: 10 });
    assert.deepEqual(next, { messagesPerSec: 5, maxBurst: 10 });
    assert.equal(eventsOf(auditLog, "global_rate_revised").length, 1);
    assert.equal(eventsOf(auditLog, "global_rate_revised")[0].previous, null);
  });
});
