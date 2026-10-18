import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  TenantBudgetEnforcer,
  budgetMonthOf,
  msUntilBudgetReset,
} from "../src/budget.ts";
import {
  RetryQueue,
  type Sender,
  type TenantBudgetAuditEvent,
} from "../src/retry.ts";

const URL_A = "http://localhost:9999/a";

/**
 * Manual timer with single-step control: budget parks re-arm timers, so
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

function item(id: string, targetUrl: string, tenantId?: string) {
  return { id, payload: Buffer.from("x"), targetUrl, headers: {}, tenantId };
}

describe("TenantBudgetEnforcer", () => {
  it("counts delivered against the current UTC month and gates dispatches", () => {
    const now = Date.UTC(2026, 9, 15, 12, 0, 0);
    const e = new TenantBudgetEnforcer({ now: () => now });
    e.setTenantBudget("acme", { deliveriesPerMonth: 2 });
    e.recordDelivered("acme");
    let v = e.checkOver("acme");
    assert.equal(v.over, false);
    assert.equal(v.used, 1);
    assert.equal(v.budget, 2);
    assert.equal(v.month, "2026-10");
    assert.equal(v.auditDue, false);
    e.recordDelivered("acme");
    v = e.checkOver("acme");
    assert.equal(v.over, true);
    assert.equal(v.auditDue, true);
    assert.equal(v.retryAfterMs, msUntilBudgetReset(now));
    assert.deepEqual(e.snapshot(), [
      { tenant: "acme", month: "2026-10", used: 2, budget: 2, over: true },
    ]);
  });

  it("rejects non-positive and non-integer budgets with RangeError", () => {
    const e = new TenantBudgetEnforcer();
    for (const bad of [0, -1, -100, 1.5, NaN, Infinity]) {
      assert.throws(() => e.setTenantBudget("acme", { deliveriesPerMonth: bad }), RangeError);
    }
    // The failed sets leave no budget behind.
    assert.equal(e.budgetFor("acme"), undefined);
    // Construction-time budgets are validated the same way.
    assert.throws(() => new TenantBudgetEnforcer({ budgets: { acme: 0 } }), RangeError);
  });

  it("validates tenant ids", () => {
    const e = new TenantBudgetEnforcer();
    assert.throws(() => e.setTenantBudget("", { deliveriesPerMonth: 1 }), RangeError);
    assert.throws(() => e.setTenantBudget("has space", { deliveriesPerMonth: 1 }), RangeError);
    assert.throws(() => e.setTenantBudget("x".repeat(65), { deliveriesPerMonth: 1 }), RangeError);
    assert.throws(
      () => e.setTenantBudget(123 as unknown as string, { deliveriesPerMonth: 1 }),
      TypeError
    );
  });

  it("tenants without a budget are unlimited and expose no metrics", () => {
    const e = new TenantBudgetEnforcer();
    const v = e.checkOver("nobody");
    assert.equal(v.over, false);
    assert.equal(v.retryAfterMs, 0);
    assert.equal(v.auditDue, false);
    assert.equal(v.budget, undefined);
    e.recordDelivered("nobody"); // no-op: nothing is tracked without a budget
    assert.equal(e.hasBudgets(), false);
    assert.deepEqual(e.snapshot(), []);
    assert.equal(e.render(), "");
  });

  it("fires the audit once per tenant per month and re-arms on rollover", () => {
    let now = Date.UTC(2026, 9, 20, 12, 0, 0);
    const e = new TenantBudgetEnforcer({ now: () => now });
    e.setTenantBudget("acme", { deliveriesPerMonth: 1 });
    e.recordDelivered("acme");
    assert.equal(e.checkOver("acme").auditDue, true);
    assert.equal(e.checkOver("acme").auditDue, false); // no audit flood
    assert.equal(e.checkOver("acme").auditDue, false);
    now = Date.UTC(2026, 10, 5, 12, 0, 0); // November
    const v = e.checkOver("acme");
    assert.equal(v.over, false); // the counter reset with the month
    assert.equal(v.used, 0);
    assert.equal(v.month, "2026-11");
    e.recordDelivered("acme");
    assert.equal(e.checkOver("acme").auditDue, true); // re-armed for the new month
  });

  it("measures UTC month boundaries", () => {
    assert.equal(budgetMonthOf(Date.UTC(2026, 0, 1)), "2026-01");
    assert.equal(budgetMonthOf(Date.UTC(2026, 11, 31, 23, 59, 59, 999)), "2026-12");
    assert.equal(msUntilBudgetReset(Date.UTC(2026, 0, 31, 23, 59, 59, 500)), 500);
    // February 2026 has 28 days.
    assert.equal(msUntilBudgetReset(Date.UTC(2026, 1, 1, 0, 0, 0, 0)), 28 * 86_400_000);
    // Exactly at a boundary: the full next month lies ahead.
    assert.equal(msUntilBudgetReset(Date.UTC(2026, 2, 1, 0, 0, 0, 0)), 31 * 86_400_000);
  });

  it("renders usage and limit gauges per tenant", () => {
    const now = Date.UTC(2026, 9, 15);
    const e = new TenantBudgetEnforcer({ now: () => now });
    e.setTenantBudget("acme", { deliveriesPerMonth: 100 });
    e.setTenantBudget("globex", { deliveriesPerMonth: 5 });
    e.recordDelivered("acme");
    e.recordDelivered("acme");
    const out = e.render();
    assert.ok(out.includes('relay_tenant_budget_deliveries_total{tenant="acme"} 2'));
    assert.ok(out.includes('relay_tenant_budget_deliveries_limit{tenant="acme"} 100'));
    assert.ok(out.includes('relay_tenant_budget_deliveries_total{tenant="globex"} 0'));
    assert.ok(out.includes("# TYPE relay_tenant_budget_deliveries_total gauge"));
    assert.ok(out.includes("# TYPE relay_tenant_budget_deliveries_limit gauge"));
  });

  it("clearTenantBudget returns the tenant to unlimited", () => {
    const e = new TenantBudgetEnforcer();
    e.setTenantBudget("acme", { deliveriesPerMonth: 1 });
    e.recordDelivered("acme");
    assert.equal(e.checkOver("acme").over, true);
    e.clearTenantBudget("acme");
    assert.equal(e.checkOver("acme").over, false);
    assert.equal(e.budgetFor("acme"), undefined);
    assert.deepEqual(e.snapshot(), []);
    e.clearTenantBudget("ghost"); // never throws for unknown tenants
  });
});

describe("RetryQueue tenant delivery budgets", () => {
  it("parks over-budget dispatches (never drops) and resumes after the month resets", async () => {
    // 500ms before November: the parked retry lands inside the test run.
    let now = Date.UTC(2026, 9, 31, 23, 59, 59, 500);
    const t = manualTimer();
    let calls = 0;
    const audits: TenantBudgetAuditEvent[] = [];
    const sender: Sender = async () => {
      calls += 1;
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      random: () => 0, // no jitter: the park delay is exactly msUntilBudgetReset
      budget: { now: () => now },
      onBudgetExceeded: (e) => audits.push(e),
    });
    q.setTenantBudget("acme", { deliveriesPerMonth: 1 });
    q.enqueue(item("a", URL_A, "acme"));
    q.start();
    await t.step(); // "a" dispatches and succeeds -> used = 1
    assert.equal(calls, 1);
    q.enqueue(item("b", URL_A, "acme"));
    await t.step(); // "b" finds the budget exhausted -> parked, not dropped
    assert.equal(calls, 1);
    assert.equal(q.pendingCount(), 1);
    assert.equal(q.getDeadLetter().length, 0); // never dropped, never dead-lettered
    assert.deepEqual(q.getTenantBudgetStats(), [
      { tenant: "acme", month: "2026-10", used: 1, budget: 1, over: true, delayed: 1 },
    ]);
    // One audit event for the month's first exceedance — and its shape.
    assert.equal(audits.length, 1);
    assert.equal(audits[0].event, "budget_exceeded");
    assert.equal(audits[0].tenant, "acme");
    assert.equal(audits[0].deliveriesPerMonth, 1);
    assert.equal(audits[0].used, 1);
    assert.equal(audits[0].month, "2026-10");
    assert.equal(audits[0].at, new Date(now).toISOString());
    now = Date.UTC(2026, 10, 1, 0, 0, 0, 100); // November: fresh budget
    await t.step(); // "b"'s parked timer fires -> month rolled -> dispatched
    assert.equal(calls, 2);
    assert.equal(q.pendingCount(), 0);
    assert.equal(audits.length, 1); // still one audit — November was not over budget
    q.stop();
  });

  it("budgets the default tenant and exposes the gauges in renderMetrics only when configured", async () => {
    const now = Date.UTC(2026, 9, 15);
    const t = manualTimer();
    let calls = 0;
    const sender: Sender = async () => {
      calls += 1;
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      random: () => 0,
      budget: { now: () => now },
    });
    // No budgets: the exposition is byte-identical to the pre-WR-137 shape.
    assert.ok(!q.renderMetrics().includes("relay_tenant_budget_"));
    q.setTenantBudget("default", { deliveriesPerMonth: 10 });
    const metrics = q.renderMetrics();
    assert.ok(metrics.includes('relay_tenant_budget_deliveries_total{tenant="default"} 0'));
    assert.ok(metrics.includes('relay_tenant_budget_deliveries_limit{tenant="default"} 10'));
    // No x-tenant-id -> the default tenant is counted.
    q.enqueue(item("c", URL_A));
    q.start();
    await t.step();
    assert.equal(calls, 1);
    const stats = q.getTenantBudgetStats();
    assert.equal(stats.length, 1);
    assert.equal(stats[0].tenant, "default");
    assert.equal(stats[0].used, 1);
    assert.equal(stats[0].over, false);
    assert.equal(stats[0].delayed, 0);
    q.stop();
  });
});
