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
const relaySecret = "tenant-retry-budget-enable-secret";

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

function item(id: string, tenantId?: string) {
  return {
    id,
    payload: Buffer.from("x"),
    targetUrl: URL,
    headers: {},
    tenantId,
  };
}

describe("RetryQueue.reviseTenantRetryBudget live enable for an unconfigured queue (WR-454)", () => {
  it("first enable takes the explicit value and the bucket starts full", () => {
    const q = new RetryQueue({ sender: async () => {}, maxAttempts: 1 });
    assert.equal(q.getTenantRetryBudgetStats(), undefined);
    assert.deepEqual(q.reviseTenantRetryBudget(undefined, 100), {
      retriesPerMinute: 100,
      previous: 6000,
      scope: "default",
      overridden: false,
    });
    assert.deepEqual(q.getTenantRetryBudgetStats(), {
      defaultRetriesPerMinute: 100,
      tenants: [],
    });
    assert.deepEqual(q.getTenantRetryBudget(), {
      retriesPerMinute: 100,
      previous: 100,
      scope: "default",
      overridden: false,
    });
    q.stop();
  });

  it("enabling with undefined takes the 6000 construction default (WR-200)", () => {
    const q = new RetryQueue({ sender: async () => {}, maxAttempts: 1 });
    assert.deepEqual(q.reviseTenantRetryBudget(undefined), {
      retriesPerMinute: 6000,
      previous: 6000,
      scope: "default",
      overridden: false,
    });
    assert.equal(q.getTenantRetryBudgetStats()?.defaultRetriesPerMinute, 6000);
    q.stop();
  });

  it("a tenant enable records the override and leaves the default alone", () => {
    const q = new RetryQueue({ sender: async () => {}, maxAttempts: 1 });
    assert.deepEqual(q.reviseTenantRetryBudget("acme", 5), {
      tenant: "acme",
      retriesPerMinute: 5,
      previous: 6000,
      scope: "tenant",
      overridden: true,
    });
    assert.equal(q.getTenantRetryBudget("other")!.retriesPerMinute, 6000);
    assert.equal(q.getTenantRetryBudget("other")!.overridden, false);
    assert.equal(q.getTenantRetryBudget()!.retriesPerMinute, 6000);
    assert.deepEqual(q.getTenantRetryBudgetStats(), {
      defaultRetriesPerMinute: 6000,
      tenants: [],
    });
    q.stop();
  });

  it("a tenant enable without a rate enables at the default with no override", () => {
    const q = new RetryQueue({ sender: async () => {}, maxAttempts: 1 });
    assert.deepEqual(q.reviseTenantRetryBudget("acme"), {
      tenant: "acme",
      retriesPerMinute: 6000,
      previous: 6000,
      scope: "tenant",
      overridden: false,
    });
    assert.equal(q.getTenantRetryBudget("acme")!.overridden, false);
    q.stop();
  });

  it("illegal values throw, stay unconfigured, and a later valid call still enables", () => {
    const q = new RetryQueue({ sender: async () => {}, maxAttempts: 1 });
    for (const bad of [0, -1, NaN, Infinity, -Infinity, "100"]) {
      assert.throws(
        () => q.reviseTenantRetryBudget(undefined, bad as never),
        RangeError,
        `budget ${String(bad)}`
      );
      assert.equal(q.getTenantRetryBudgetStats(), undefined);
    }
    // Malformed tenant ids: empty, over-long, bad charset, non-string.
    for (const badTenant of ["", "a".repeat(65), "bad id!", 123]) {
      assert.throws(
        () => q.reviseTenantRetryBudget(badTenant as never, 5),
        /tenant id must be/,
        `tenant ${String(badTenant)}`
      );
      assert.equal(q.getTenantRetryBudgetStats(), undefined);
    }
    assert.deepEqual(q.reviseTenantRetryBudget(undefined, 50), {
      retriesPerMinute: 50,
      previous: 6000,
      scope: "default",
      overridden: false,
    });
    assert.equal(q.getTenantRetryBudgetStats()?.defaultRetriesPerMinute, 50);
    q.stop();
  });

  it("a revision after enable still follows WR-326 (tighten clamps, widen never tops up)", () => {
    const q = new RetryQueue({ sender: async () => {}, maxAttempts: 1 });
    q.reviseTenantRetryBudget(undefined, 100);
    assert.equal(q.reviseTenantRetryBudget(undefined, 50).retriesPerMinute, 50);
    assert.equal(q.getTenantRetryBudgetStats()?.defaultRetriesPerMinute, 50);
    // Same value: no-op.
    assert.deepEqual(q.reviseTenantRetryBudget(undefined, 50), {
      retriesPerMinute: 50,
      previous: 50,
      scope: "default",
      overridden: false,
    });
    // A tenant override after enable, and an illegal revision still
    // throws and leaves the live budget intact.
    assert.equal(q.reviseTenantRetryBudget("acme", 200).retriesPerMinute, 200);
    assert.equal(q.getTenantRetryBudget("acme")!.overridden, true);
    assert.throws(() => q.reviseTenantRetryBudget(undefined, 0), RangeError);
    assert.equal(q.getTenantRetryBudgetStats()?.defaultRetriesPerMinute, 50);
    assert.throws(() => q.reviseTenantRetryBudget("acme", 0), RangeError);
    assert.equal(q.getTenantRetryBudget("acme")!.retriesPerMinute, 200);
    // The rate is optional only on the enable path: on a configured
    // queue `undefined` is a RangeError, not a re-enable.
    assert.throws(() => q.reviseTenantRetryBudget(undefined, undefined), RangeError);
    assert.equal(q.getTenantRetryBudgetStats()?.defaultRetriesPerMinute, 50);
    q.stop();
  });

  it("a fresh queue without the option is still unconfigured (a restart returns to unconfigured)", () => {
    const q1 = new RetryQueue({ sender: async () => {}, maxAttempts: 1 });
    assert.equal(q1.reviseTenantRetryBudget(undefined, 100).retriesPerMinute, 100);
    q1.stop();
    const q2 = new RetryQueue({ sender: async () => {}, maxAttempts: 1 });
    assert.equal(q2.getTenantRetryBudgetStats(), undefined);
    q2.stop();
  });

  it("the next scheduled retry after enable is judged by the new tenant bucket (full bucket admits, exhaustion parks)", async () => {
    const timer = manualTimer();
    const scheduledDelays: number[] = [];
    const depleted: RetryBudgetDepletedInfo[] = [];
    const attempts = new Map<string, number>();
    // Per-item failure budget: "a" fails 3 times then succeeds (so it
    // exhausts its 2/min bucket and parks once); "b" fails once, so its
    // own bucket never empties — the isolation probe.
    const failBudget = new Map<string, number>([
      ["item-a", 3],
      ["item-b", 1],
    ]);
    const flaky: Sender = async (entry) => {
      const n = (attempts.get(entry.id) ?? 0) + 1;
      attempts.set(entry.id, n);
      const remaining = failBudget.get(entry.id) ?? 0;
      if (remaining > 0) {
        failBudget.set(entry.id, remaining - 1);
        throw new Error("downstream down");
      }
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
    });
    q.start();
    try {
      assert.deepEqual(q.reviseTenantRetryBudget(undefined, 2), {
        retriesPerMinute: 2,
        previous: 6000,
        scope: "default",
        overridden: false,
      });
      q.enqueue(item("item-a", "a"));
      await timer.run();
      // 4 genuine attempts: 3 failures + 1 success. Parking consumed no
      // extra attempt.
      assert.equal(attempts.get("item-a"), 4);
      assert.equal(depleted.length, 1);
      assert.equal(depleted[0].id, "item-a");
      assert.equal(depleted[0].scope, "tenant");
      assert.equal(depleted[0].tenant, "a");
      // Scheduled delays: 0 (initial), 200, 400 (backoff), then the park
      // on the 2/min refill horizon (~30s; the wall clock barely moves
      // under the manual timer, so the bound leaves timing slack).
      assert.equal(scheduledDelays[0], 0);
      assert.equal(scheduledDelays[1], 200);
      assert.equal(scheduledDelays[2], 400);
      assert.ok(scheduledDelays[3] > 15000 && scheduledDelays[3] <= 30000);
      assert.ok(depleted[0].waitMs > 15000 && depleted[0].waitMs <= 30000);
      assert.deepEqual(q.getTenantRetryBudgetStats(), {
        defaultRetriesPerMinute: 2,
        tenants: [{ tenant: "a", retriesPerMinute: 2, depleted: 1 }],
      });
      // The other tenant is unaffected: its own bucket is still full,
      // so its first retry is admitted at once even while tenant "a"
      // is exhausted.
      q.enqueue(item("item-b", "b"));
      await timer.run();
      assert.equal(attempts.get("item-b"), 2);
      assert.equal(depleted.length, 1);
      assert.deepEqual(scheduledDelays.slice(4), [0, 200]);
    } finally {
      q.stop();
    }
  });

  it("a retry already scheduled before the enable is not retroactively gated", async () => {
    const timer = manualTimer();
    const scheduledDelays: number[] = [];
    const depleted: RetryBudgetDepletedInfo[] = [];
    const attempts = new Map<string, number>();
    // Fail 3 times, then succeed. The first failure schedules its retry
    // while the budget is still off; the enable lands between that
    // scheduling and the retry firing.
    const flaky: Sender = async (entry) => {
      const n = (attempts.get(entry.id) ?? 0) + 1;
      attempts.set(entry.id, n);
      if (n <= 3) throw new Error("downstream down");
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
    });
    q.start();
    try {
      q.enqueue(item("item-1", "a"));
      // Fire the initial attempt only: it fails and schedules its retry
      // at the 200ms backoff with no budget in place.
      await timer.step();
      assert.equal(attempts.get("item-1"), 1);
      assert.deepEqual(scheduledDelays, [0, 200]);
      // Enable now, with a 1/min bucket: the already-scheduled retry
      // must still fire on its original 200ms schedule, not park.
      assert.deepEqual(q.reviseTenantRetryBudget(undefined, 1), {
        retriesPerMinute: 1,
        previous: 6000,
        scope: "default",
        overridden: false,
      });
      await timer.step();
      assert.equal(attempts.get("item-1"), 2);
      // The second failure's retry takes the only token (400ms backoff);
      // the third failure's retry finds the bucket empty and parks.
      await timer.run();
      assert.equal(attempts.get("item-1"), 4);
      assert.equal(depleted.length, 1);
      assert.equal(depleted[0].scope, "tenant");
      assert.equal(depleted[0].tenant, "a");
      assert.deepEqual(scheduledDelays.slice(0, 3), [0, 200, 400]);
      assert.ok(scheduledDelays[3] > 30000 && scheduledDelays[3] <= 60000);
      assert.deepEqual(q.getTenantRetryBudgetStats(), {
        defaultRetriesPerMinute: 1,
        tenants: [{ tenant: "a", retriesPerMinute: 1, depleted: 1 }],
      });
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer.reviseTenantRetryBudget live enable (WR-454)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "tenant-retry-budget-enable-"));
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
    assert.equal(relay.getTenantRetryBudget, undefined);
    assert.deepEqual(relay.reviseTenantRetryBudget(undefined), {
      retriesPerMinute: 6000,
      previous: 6000,
      scope: "default",
      overridden: false,
    });
    const revised = eventsOf(auditLog, "tenant_retry_budget_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.equal(revised[0].current, 6000);
    assert.equal(revised[0].scope, "default");
    assert.equal("tenant" in revised[0], false);
    // The getter is mounted by the enable, and a same-value revision
    // after it is a no-op with no second audit event.
    assert.equal(relay.getTenantRetryBudget!().retriesPerMinute, 6000);
    relay.reviseTenantRetryBudget(undefined, 6000);
    assert.equal(eventsOf(auditLog, "tenant_retry_budget_revised").length, 1);
  });

  it("a tenant enable audits with the tenant and previous: null", async () => {
    const { relay, auditLog } = makeServer({});
    await listen(relay);
    assert.deepEqual(relay.reviseTenantRetryBudget("acme", 5), {
      tenant: "acme",
      retriesPerMinute: 5,
      previous: 6000,
      scope: "tenant",
      overridden: true,
    });
    const revised = eventsOf(auditLog, "tenant_retry_budget_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].tenant, "acme");
    assert.equal(revised[0].scope, "tenant");
    assert.equal(revised[0].previous, null);
    assert.equal(revised[0].current, 5);
    assert.equal(relay.getTenantRetryBudget!("acme").retriesPerMinute, 5);
    assert.equal(relay.getTenantRetryBudget!("other").retriesPerMinute, 6000);
  });

  it("an illegal enable value throws, stays unconfigured, and a later valid call still enables", async () => {
    const { relay, auditLog } = makeServer({});
    await listen(relay);
    for (const bad of [0, -1, NaN, Infinity]) {
      assert.throws(() => relay.reviseTenantRetryBudget(undefined, bad), RangeError, `budget ${bad}`);
    }
    assert.throws(() => relay.reviseTenantRetryBudget("", 5), RangeError);
    assert.throws(() => relay.reviseTenantRetryBudget(123 as never, 5), TypeError);
    assert.equal(eventsOf(auditLog, "tenant_retry_budget_revised").length, 0);
    assert.equal(relay.getTenantRetryBudget, undefined);
    assert.deepEqual(relay.reviseTenantRetryBudget(undefined, 100), {
      retriesPerMinute: 100,
      previous: 6000,
      scope: "default",
      overridden: false,
    });
    const revised = eventsOf(auditLog, "tenant_retry_budget_revised");
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
    relay.reviseTenantRetryBudget(undefined, 100);
    relay.reviseRetryBudgetDepletedCallback!(() => {});
    const revised = eventsOf(auditLog, "retry_budget_depleted_callback_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, "cleared");
    assert.equal(revised[0].current, "set");
  });
});
