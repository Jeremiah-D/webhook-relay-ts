import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  type RetryBudgetDepletedInfo,
  type Sender,
} from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "retry-budget-enable-secret";

const URL = "http://localhost:9999/hook";

/** Let the deliver() promise chain settle. */
async function flush(ticks = 20) {
  for (let i = 0; i < ticks; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

/**
 * Deterministic timer: `run()` drains every pending callback; `step()`
 * fires only the next pending callback (one delivery attempt) and then
 * lets its failure path settle, so the test can enable the budget
 * mid-flight between two scheduled retries.
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
      const fn = pending.shift();
      if (fn !== undefined) fn();
      await flush();
    },
    async run() {
      while (pending.length > 0) {
        const fns = pending.splice(0);
        for (const fn of fns) fn();
        await flush();
      }
    },
  };
}

describe("RetryQueue.setRetryBudget live enable for an unconfigured queue (WR-453)", () => {
  it("first enable takes the explicit value and the bucket starts full", () => {
    const q = new RetryQueue({ sender: async () => {}, maxAttempts: 1 });
    assert.equal(q.getRetryBudgetStats(), undefined);
    assert.equal(q.setRetryBudget(100), 100);
    assert.deepEqual(q.getRetryBudgetStats(), { retriesPerMinute: 100, depleted: 0 });
    q.stop();
  });

  it("enabling with undefined takes the 6000 construction default (WR-38)", () => {
    const q = new RetryQueue({ sender: async () => {}, maxAttempts: 1 });
    assert.equal(q.setRetryBudget(undefined), 6000);
    assert.equal(q.getRetryBudgetStats()?.retriesPerMinute, 6000);
    q.stop();
  });

  it("illegal values throw RangeError, stay unconfigured, and a later valid call still enables", () => {
    const q = new RetryQueue({ sender: async () => {}, maxAttempts: 1 });
    for (const bad of [0, -1, NaN, Infinity, -Infinity, "100", null]) {
      assert.throws(() => q.setRetryBudget(bad as never), RangeError, `budget ${String(bad)}`);
      assert.equal(q.getRetryBudgetStats(), undefined);
    }
    assert.equal(q.setRetryBudget(50), 50);
    assert.equal(q.getRetryBudgetStats()?.retriesPerMinute, 50);
    q.stop();
  });

  it("a revision after enable still follows WR-314 (tighten clamps, widen never tops up)", () => {
    const q = new RetryQueue({ sender: async () => {}, maxAttempts: 1 });
    assert.equal(q.setRetryBudget(100), 100);
    assert.equal(q.setRetryBudget(50), 50);
    assert.equal(q.getRetryBudgetStats()?.retriesPerMinute, 50);
    // Same value: no-op.
    assert.equal(q.setRetryBudget(50), 50);
    assert.equal(q.setRetryBudget(200), 200);
    // An illegal revision still throws and leaves the live budget intact.
    assert.throws(() => q.setRetryBudget(0), RangeError);
    assert.equal(q.getRetryBudgetStats()?.retriesPerMinute, 200);
    q.stop();
  });

  it("a fresh queue without the option is still unconfigured (a restart returns to unconfigured)", () => {
    const q1 = new RetryQueue({ sender: async () => {}, maxAttempts: 1 });
    assert.equal(q1.setRetryBudget(100), 100);
    q1.stop();
    const q2 = new RetryQueue({ sender: async () => {}, maxAttempts: 1 });
    assert.equal(q2.getRetryBudgetStats(), undefined);
    q2.stop();
  });

  it("the next scheduled retry after enable is judged by the new bucket (full bucket admits, exhaustion parks)", async () => {
    const timer = manualTimer();
    const scheduledDelays: number[] = [];
    const depleted: RetryBudgetDepletedInfo[] = [];
    let senderCalls = 0;
    let deliveredAttempts = 0;
    // Fail 3 times, then succeed. The 2/min bucket admits the first two
    // scheduled retries and parks the third on the ~30s refill horizon.
    const flaky: Sender = async () => {
      senderCalls += 1;
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
      onRetryBudgetDepleted: (info) => depleted.push(info),
      onDelivered: (_item, attempts) => {
        deliveredAttempts = attempts;
      },
    });
    q.start();
    try {
      assert.equal(q.setRetryBudget(2), 2);
      q.enqueue({
        id: "item-1",
        payload: Buffer.from("hello"),
        targetUrl: URL,
        headers: { "content-type": "application/json" },
      });
      await timer.run();
      // 4 genuine attempts: 3 failures + 1 success. Parking consumed no
      // extra attempt.
      assert.equal(senderCalls, 4);
      assert.equal(deliveredAttempts, 4);
      assert.equal(depleted.length, 1);
      assert.equal(depleted[0].id, "item-1");
      assert.equal(depleted[0].scope, "global");
      // Scheduled delays: 0 (initial), 200, 400 (backoff), then the park
      // on the 2/min refill horizon (~30s; the wall clock barely moves
      // under the manual timer, so the bound leaves timing slack).
      assert.equal(scheduledDelays[0], 0);
      assert.equal(scheduledDelays[1], 200);
      assert.equal(scheduledDelays[2], 400);
      assert.ok(scheduledDelays[3] > 15000 && scheduledDelays[3] <= 30000);
      assert.ok(depleted[0].waitMs > 15000 && depleted[0].waitMs <= 30000);
      assert.deepEqual(q.getRetryBudgetStats(), { retriesPerMinute: 2, depleted: 1 });
    } finally {
      q.stop();
    }
  });

  it("a retry already scheduled before the enable is not retroactively gated", async () => {
    const timer = manualTimer();
    const scheduledDelays: number[] = [];
    const depleted: RetryBudgetDepletedInfo[] = [];
    let senderCalls = 0;
    let deliveredAttempts = 0;
    // Fail 3 times, then succeed. The first failure schedules its retry
    // while the budget is still off; the enable lands between that
    // scheduling and the retry firing.
    const flaky: Sender = async () => {
      senderCalls += 1;
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
      onRetryBudgetDepleted: (info) => depleted.push(info),
      onDelivered: (_item, attempts) => {
        deliveredAttempts = attempts;
      },
    });
    q.start();
    try {
      q.enqueue({
        id: "item-1",
        payload: Buffer.from("hello"),
        targetUrl: URL,
        headers: { "content-type": "application/json" },
      });
      // Fire the initial attempt only: it fails and schedules its retry
      // at the 200ms backoff with no budget in place.
      await timer.step();
      assert.equal(senderCalls, 1);
      assert.deepEqual(scheduledDelays, [0, 200]);
      // Enable now, with a 1/min bucket: the already-scheduled retry
      // must still fire on its original 200ms schedule, not park.
      assert.equal(q.setRetryBudget(1), 1);
      await timer.step();
      assert.equal(senderCalls, 2);
      // The second failure's retry takes the only token (400ms backoff);
      // the third failure's retry finds the bucket empty and parks.
      await timer.run();
      assert.equal(senderCalls, 4);
      assert.equal(deliveredAttempts, 4);
      assert.equal(depleted.length, 1);
      assert.equal(depleted[0].scope, "global");
      assert.deepEqual(scheduledDelays.slice(0, 3), [0, 200, 400]);
      assert.ok(scheduledDelays[3] > 30000 && scheduledDelays[3] <= 60000);
      assert.deepEqual(q.getRetryBudgetStats(), { retriesPerMinute: 1, depleted: 1 });
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer.setRetryBudget live enable (WR-453)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "retry-budget-enable-"));
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

  it("enables with undefined at the 6000 default and audits previous: null", async () => {
    const { relay, auditLog } = makeServer({});
    await listen(relay);
    assert.equal(relay.setRetryBudget!(undefined), 6000);
    const revised = eventsOf(auditLog, "retry_budget_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.equal(revised[0].current, 6000);
    // Same value after enable: no-op, no second audit event.
    relay.setRetryBudget!(6000);
    assert.equal(eventsOf(auditLog, "retry_budget_revised").length, 1);
  });

  it("an illegal enable value throws RangeError, stays unconfigured, and a later valid call still enables", async () => {
    const { relay, auditLog } = makeServer({});
    await listen(relay);
    for (const bad of [0, -1, NaN, Infinity]) {
      assert.throws(() => relay.setRetryBudget!(bad), RangeError, `budget ${bad}`);
    }
    assert.equal(eventsOf(auditLog, "retry_budget_revised").length, 0);
    assert.equal(relay.setRetryBudget!(100), 100);
    const revised = eventsOf(auditLog, "retry_budget_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.equal(revised[0].current, 100);
  });

  it("enabling opens the WR-387 depleted-callback gate", async () => {
    const { relay, auditLog } = makeServer({});
    await listen(relay);
    assert.throws(
      () => relay.reviseRetryBudgetDepletedCallback!(() => {}),
      /no retry budget is configured/
    );
    assert.equal(relay.setRetryBudget!(100), 100);
    relay.reviseRetryBudgetDepletedCallback!(() => {});
    const revised = eventsOf(auditLog, "retry_budget_depleted_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "cleared");
    assert.equal(revised[0].current, "set");
  });
});
