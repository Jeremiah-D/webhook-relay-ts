import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  RetryQueue,
  type Sender,
  type RetryBudgetDepletedInfo,
  type TenantRetryBudgetOptions,
} from "../src/retry.ts";

const URL = "http://localhost:9999/hook";

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

function alwaysFailingSender() {
  let calls = 0;
  const sender: Sender = async () => {
    calls += 1;
    throw new Error("downstream down");
  };
  return { sender, calls: () => calls };
}

function item(id: string, tenantId?: string) {
  return { id, payload: Buffer.from("x"), targetUrl: URL, headers: {}, tenantId };
}

function makeQueue(tenantRetryBudget: TenantRetryBudgetOptions) {
  let now = 0;
  const timer = manualTimer();
  const f = alwaysFailingSender();
  const depleted: RetryBudgetDepletedInfo[] = [];
  const q = new RetryQueue({
    sender: f.sender,
    baseDelayMs: 10,
    maxAttempts: 10,
    jitterMs: 0,
    random: () => 0, // deterministic parking delay
    setTimer: timer.setTimer,
    tenantRetryBudget: { ...tenantRetryBudget, now: () => now },
    onRetryBudgetDepleted: (info) => depleted.push(info),
  });
  return { q, timer, f, depleted, advance: (ms: number) => (now += ms) };
}

describe("RetryQueue per-tenant retry budget (WR-200)", () => {
  it("parks only the exhausted tenant's retries; others are unaffected", async () => {
    // B gets a large override so only A's exhaustion is exercised; every
    // parked retry in this test must belong to tenant A.
    const { q, timer, f, depleted } = makeQueue({
      retriesPerMinute: 2,
      perTenantRetriesPerMinute: { b: 100 },
    });
    q.start();
    try {
      // Tenant A: two scheduled retries consume its 2/min bucket; the
      // third failure parks with scope "tenant".
      q.enqueue(item("a1", "a"));
      await timer.step(); // attempt 1 fails -> retry 1 (budget 1/2)
      await timer.step(); // attempt 2 fails -> retry 2 (budget 2/2)
      await timer.step(); // attempt 3 fails -> parked on tenant budget
      assert.equal(f.calls(), 3);
      assert.equal(depleted.length, 1);
      assert.equal(depleted[0].scope, "tenant");
      assert.equal(depleted[0].tenant, "a");
      assert.ok(depleted[0].waitMs > 0);

      // Tenant B has its own bucket: its retries schedule normally even
      // while A's parked retry keeps re-parking on later steps.
      q.enqueue(item("b1", "b"));
      const callsBefore = f.calls();
      await timer.step();
      await timer.step();
      await timer.step();
      assert.ok(f.calls() > callsBefore + 1, "B's retries must keep flowing");
      assert.ok(
        depleted.every((d) => d.tenant === "a" && d.scope === "tenant"),
        "every park must belong to tenant A"
      );

      // Per-tenant stats + Prometheus series: only A appears.
      const stats = q.getTenantRetryBudgetStats();
      assert.ok(stats !== undefined);
      assert.equal(stats.defaultRetriesPerMinute, 2);
      assert.deepEqual(
        stats.tenants.map((t) => t.tenant),
        ["a"]
      );
      assert.ok(stats.tenants[0].depleted >= 1);
      assert.equal(stats.tenants[0].retriesPerMinute, 2);
      const exposition = q.renderMetrics();
      assert.match(exposition, /relay_tenant_retry_budget_depleted_total\{tenant="a"\}/);
      assert.doesNotMatch(
        exposition,
        /relay_tenant_retry_budget_depleted_total\{tenant="b"\}/
      );
    } finally {
      q.stop();
    }
  });

  it("a parked tenant retry resumes automatically after refill", async () => {
    const { q, timer, f, depleted, advance } = makeQueue({ retriesPerMinute: 2 });
    q.start();
    try {
      q.enqueue(item("a1", "a"));
      await timer.step(); // fail 1
      await timer.step(); // fail 2
      await timer.step(); // fail 3 -> parked
      assert.equal(f.calls(), 3);

      // Still frozen in time: the parked retry re-checks at the refill
      // horizon, dispatches, fails, and parks again (bucket still empty).
      await timer.step();
      assert.equal(f.calls(), 4);

      // One refill window later the retry proceeds on its own and the
      // failure schedules a normal backoff retry (not another park).
      advance(30_000);
      const parkedBefore = depleted.length;
      await timer.step();
      assert.equal(f.calls(), 5, "refill must resume the parked retry");
      assert.equal(depleted.length, parkedBefore, "no new park after refill");
    } finally {
      q.stop();
    }
  });

  it("the default (tenant-less) tenant gets the default budget", async () => {
    const { q, timer, f, depleted } = makeQueue({
      retriesPerMinute: 1,
      perTenantRetriesPerMinute: { vip: 5 },
    });
    q.start();
    try {
      // Default tenant: 1/min — parks on the second scheduled retry.
      q.enqueue(item("d1"));
      await timer.step(); // fail 1 -> retry 1 (budget 1/1)
      await timer.step(); // fail 2 -> parked
      assert.equal(depleted.length, 1);
      assert.equal(depleted[0].tenant, undefined);
      assert.equal(depleted[0].scope, "tenant");

      const stats = q.getTenantRetryBudgetStats();
      assert.equal(stats?.defaultRetriesPerMinute, 1);
      assert.equal(stats?.tenants[0].retriesPerMinute, 1);
      assert.match(q.renderMetrics(), /relay_tenant_retry_budget_depleted_total\{\} 1/);
    } finally {
      q.stop();
    }
  });

  it("per-tenant overrides size individual buckets", async () => {
    // A separate queue: a parked item's re-armed timer would otherwise
    // re-park (and re-count) on every later step.
    const { q, timer, f, depleted } = makeQueue({
      retriesPerMinute: 1,
      perTenantRetriesPerMinute: { vip: 5 },
    });
    q.start();
    try {
      // VIP tenant: 5/min — five retries before the first park.
      q.enqueue(item("v1", "vip"));
      for (let i = 0; i < 5; i++) await timer.step();
      assert.equal(depleted.length, 0, "vip must not have parked yet");
      assert.equal(f.calls(), 5);
      await timer.step(); // 6th failure -> vip parks
      assert.equal(depleted.length, 1);
      assert.equal(depleted[0].tenant, "vip");
      assert.equal(depleted[0].scope, "tenant");

      const stats = q.getTenantRetryBudgetStats();
      const byTenant = new Map(
        (stats?.tenants ?? []).map((t) => [t.tenant ?? "(default)", t])
      );
      assert.equal(byTenant.get("vip")?.retriesPerMinute, 5);
      assert.match(
        q.renderMetrics(),
        /relay_tenant_retry_budget_depleted_total\{tenant="vip"\} 1/
      );
    } finally {
      q.stop();
    }
  });

  it("fail-fast: illegal tenant budget throws RangeError at construction", () => {
    const f = alwaysFailingSender();
    assert.throws(
      () => new RetryQueue({ sender: f.sender, tenantRetryBudget: { retriesPerMinute: 0 } }),
      RangeError
    );
    assert.throws(
      () =>
        new RetryQueue({
          sender: f.sender,
          tenantRetryBudget: { perTenantRetriesPerMinute: { a: -1 } },
        }),
      RangeError
    );
  });

  it("without the option the relay behaves exactly as before", async () => {
    const timer = manualTimer();
    const f = alwaysFailingSender();
    const q = new RetryQueue({
      sender: f.sender,
      baseDelayMs: 10,
      maxAttempts: 10,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
    });
    q.start();
    try {
      q.enqueue(item("a1", "a"));
      await timer.step();
      await timer.step();
      await timer.step();
      assert.equal(f.calls(), 3, "no tenant budget -> retries never park");
      assert.equal(q.getTenantRetryBudgetStats(), undefined);
      assert.doesNotMatch(q.renderMetrics(), /relay_tenant_retry_budget_depleted_total/);
    } finally {
      q.stop();
    }
  });
});
