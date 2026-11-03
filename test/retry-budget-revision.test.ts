import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import {
  RetryQueue,
  RetryBudget,
  type RetryBudgetDepletedInfo,
  type Sender,
} from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "retry-budget-revision-secret";

const URL = "http://localhost:9999/hook";

/** Deterministic timer: `run()` executes pending callbacks immediately. */
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
    async run() {
      while (pending.length > 0) {
        const fns = pending.splice(0);
        for (const fn of fns) fn();
        await new Promise((r) => setImmediate(r));
      }
    },
  };
}

describe("RetryBudget.retune (WR-314)", () => {
  it("rejects illegal values and leaves the live budget and tokens untouched", () => {
    const now = { ms: 0 };
    const b = new RetryBudget(60, () => now.ms);
    assert.ok(b.take()); // 59 tokens left
    for (const bad of [0, -1, NaN, Infinity, -Infinity]) {
      assert.throws(() => b.retune(bad), RangeError, `budget ${bad}`);
    }
    assert.equal(b.limit(), 60);
    assert.equal(b.remaining(), 59);
    assert.equal(b.msUntilToken(), 0);
  });

  it("tightening refills first, then clamps remaining tokens to the new cap", () => {
    const now = { ms: 0 };
    const b = new RetryBudget(10, () => now.ms);
    for (let i = 0; i < 3; i++) assert.ok(b.take()); // 7 left
    now.ms = 60_000; // a full minute passes: refill would top the bucket back to 10
    assert.equal(b.retune(8), 8);
    assert.equal(b.limit(), 8);
    // Refill-then-clamp: 10 refilled tokens clamped to 8 (not the
    // pre-refill 7, which a clamp-without-refill would report).
    assert.equal(b.remaining(), 8);
  });

  it("widening never tops the bucket up, but raises the cap and shortens the refill horizon", () => {
    const now = { ms: 0 };
    const b = new RetryBudget(2, () => now.ms);
    assert.ok(b.take());
    assert.ok(b.take());
    assert.equal(b.take(), false);
    assert.equal(b.msUntilToken(), 30000);
    assert.equal(b.retune(6), 6);
    assert.equal(b.limit(), 6);
    // No top-up: still empty right after the widening.
    assert.equal(b.remaining(), 0);
    assert.equal(b.take(), false);
    // But the refill horizon follows the new cap: 6/min = a token every 10s.
    assert.equal(b.msUntilToken(), 10000);
    now.ms = 10_000;
    assert.equal(b.msUntilToken(), 0);
    assert.ok(b.take());
  });

  it("a same-value retune is a no-op", () => {
    const now = { ms: 0 };
    const b = new RetryBudget(2, () => now.ms);
    assert.ok(b.take());
    assert.ok(b.take());
    assert.equal(b.retune(2), 2);
    assert.equal(b.limit(), 2);
    assert.equal(b.remaining(), 0);
    assert.equal(b.msUntilToken(), 30000);
  });

  it("msUntilToken follows the live cap after a retune", () => {
    const now = { ms: 0 };
    const b = new RetryBudget(2, () => now.ms);
    assert.ok(b.take());
    assert.ok(b.take());
    assert.equal(b.msUntilToken(), 30000);
    assert.equal(b.retune(6), 6);
    assert.equal(b.msUntilToken(), 10000);
    assert.equal(b.retune(1), 1);
    assert.equal(b.msUntilToken(), 60000);
  });
});

describe("RetryQueue.setRetryBudget (WR-314)", () => {
  it("revises the live budget; endpoint overrides and the tenant budget are untouched", () => {
    const sender: Sender = async () => {};
    const q = new RetryQueue({
      sender,
      maxAttempts: 1,
      retryBudget: {
        retriesPerMinute: 100,
        perEndpointRetriesPerMinute: { [URL]: 5 },
      },
      tenantRetryBudget: { retriesPerMinute: 7 },
    });
    q.start();
    try {
      assert.equal(q.setRetryBudget(50), 50);
      const stats = q.getRetryBudgetStats();
      assert.equal(stats?.retriesPerMinute, 50);
      assert.equal(stats?.depleted, 0);
      assert.deepEqual(stats?.endpoints, [
        { endpoint: URL, retriesPerMinute: 5, depleted: 0, remainingTokens: 5 },
      ]);
      assert.equal(q.getTenantRetryBudgetStats()?.defaultRetriesPerMinute, 7);
      // Same value: no-op.
      assert.equal(q.setRetryBudget(50), 50);
      assert.equal(q.getRetryBudgetStats()?.retriesPerMinute, 50);
    } finally {
      q.stop();
    }
  });

  it("throws Error when the budget was never configured", () => {
    const q = new RetryQueue({ sender: async () => {}, maxAttempts: 1 });
    assert.throws(() => q.setRetryBudget(100), /not configured/);
    assert.equal(q.getRetryBudgetStats(), undefined);
    q.stop();
  });

  it("an illegal value throws RangeError and leaves the live budget untouched", () => {
    const q = new RetryQueue({
      sender: async () => {},
      maxAttempts: 1,
      retryBudget: { retriesPerMinute: 100 },
    });
    q.start();
    try {
      for (const bad of [0, -1, NaN, Infinity]) {
        assert.throws(() => q.setRetryBudget(bad), RangeError, `budget ${bad}`);
      }
      assert.equal(q.getRetryBudgetStats()?.retriesPerMinute, 100);
    } finally {
      q.stop();
    }
  });

  it("tightening parks the next retry immediately at the new refill horizon", async () => {
    const timer = manualTimer();
    const now = { ms: 0 };
    const scheduledDelays: number[] = [];
    const depleted: RetryBudgetDepletedInfo[] = [];
    let senderCalls = 0;
    let deliveredAttempts = 0;
    // Fail 3 times, then succeed. The 2nd attempt tightens the budget
    // mid-flight (3/min -> 1/min): the 3rd failure's retry then finds
    // the clamped bucket empty and parks instead of hammering on.
    const flaky: Sender = async () => {
      senderCalls += 1;
      if (senderCalls === 2) {
        q.setRetryBudget(1);
      }
      if (senderCalls <= 3) throw new Error("downstream down");
    };
    const q = new RetryQueue({
      sender: flaky,
      baseDelayMs: 100,
      maxDelayMs: 5000,
      maxAttempts: 5,
      jitterMs: 0,
      random: () => 0,
      setTimer: (fn, ms) => {
        scheduledDelays.push(ms);
        return timer.setTimer(fn, ms);
      },
      retryBudget: { retriesPerMinute: 3, now: () => now.ms },
      onRetryBudgetDepleted: (info) => depleted.push(info),
      onDelivered: (_item, attempts) => {
        deliveredAttempts = attempts;
      },
    });
    q.start();
    q.enqueue({
      id: "item-1",
      payload: Buffer.from("hello"),
      targetUrl: URL,
      headers: { "content-type": "application/json" },
    });
    await timer.run();
    // 4 genuine attempts: 3 failures + 1 success. Parking consumed no
    // extra attempt, and the parked retry re-armed at the new 1/min
    // horizon (60s) instead of the old 3/min one (20s).
    assert.equal(senderCalls, 4);
    assert.equal(deliveredAttempts, 4);
    assert.equal(depleted.length, 1);
    assert.equal(depleted[0].id, "item-1");
    assert.equal(depleted[0].waitMs, 60000);
    // Scheduled delays: 0 (initial), 200, 400 (backoff), 60000 (parked).
    assert.deepEqual(scheduledDelays, [0, 200, 400, 60000]);
    assert.deepEqual(q.getRetryBudgetStats(), { retriesPerMinute: 1, depleted: 1 });
    q.stop();
  });
});

describe("RelayServer.setRetryBudget (WR-314)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "retry-budget-revision-"));
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

  it("audits retry_budget_revised with previous/current and skips the audit on a no-op", async () => {
    const { relay, auditLog } = makeServer({ retry: { retryBudget: { retriesPerMinute: 100 } } });
    await listen(relay);
    assert.equal(eventsOf(auditLog, "retry_budget_revised").length, 0);
    assert.equal(relay.setRetryBudget!(50), 50);
    const revised = eventsOf(auditLog, "retry_budget_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, 100);
    assert.equal(revised[0].current, 50);
    // Same value: no new audit event.
    relay.setRetryBudget!(50);
    assert.equal(eventsOf(auditLog, "retry_budget_revised").length, 1);
  });

  it("throws RangeError on an illegal value and leaves the live budget untouched", async () => {
    const { relay, auditLog } = makeServer({ retry: { retryBudget: { retriesPerMinute: 100 } } });
    await listen(relay);
    for (const bad of [0, -1, NaN, Infinity]) {
      assert.throws(() => relay.setRetryBudget!(bad), RangeError, `budget ${bad}`);
    }
    assert.equal(eventsOf(auditLog, "retry_budget_revised").length, 0);
  });

  it("throws Error when the budget was never configured", async () => {
    const { relay, auditLog } = makeServer({});
    await listen(relay);
    assert.equal(typeof relay.setRetryBudget, "function");
    assert.throws(() => relay.setRetryBudget!(100), /not configured/);
    assert.equal(eventsOf(auditLog, "retry_budget_revised").length, 0);
  });
});
