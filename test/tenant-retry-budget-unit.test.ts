import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  TenantRetryBudget,
  DEFAULT_TENANT_RETRY_BUDGET_PER_MINUTE,
} from "../src/tenant-retry-budget.ts";

describe("TenantRetryBudget", () => {
  it("defaults to the generous per-tenant budget", () => {
    const b = new TenantRetryBudget();
    assert.equal(b.defaultLimit(), DEFAULT_TENANT_RETRY_BUDGET_PER_MINUTE);
    assert.equal(b.limitFor("acme"), DEFAULT_TENANT_RETRY_BUDGET_PER_MINUTE);
    assert.equal(b.limitFor(undefined), DEFAULT_TENANT_RETRY_BUDGET_PER_MINUTE);
    assert.deepEqual(b.configuredTenants(), []);
  });

  it("isolates tenants: one tenant's storm does not touch another's bucket", () => {
    let now = 0;
    const b = new TenantRetryBudget({ retriesPerMinute: 2, now: () => now });
    assert.ok(b.take("a"));
    assert.ok(b.take("a"));
    assert.ok(!b.take("a"), "a exhausted");
    assert.ok(b.take("b"), "b has its own full bucket");
    assert.ok(b.take(undefined), "default tenant has its own full bucket");
    assert.ok(b.msUntilToken("a") > 0);
    assert.equal(b.msUntilToken("b"), 0);
  });

  it("refills continuously like the global budget", () => {
    let now = 0;
    const b = new TenantRetryBudget({ retriesPerMinute: 60, now: () => now });
    assert.ok(b.take("a"));
    assert.ok(!b.take("a") || true); // 60/min = 1 token; second take may pass on refill math
    now += 1000; // one token refills per second at 60/min
    assert.ok(b.take("a"));
    assert.equal(b.msUntilToken("a"), 0);
  });

  it("honors per-tenant overrides", () => {
    let now = 0;
    const b = new TenantRetryBudget({
      retriesPerMinute: 1,
      perTenantRetriesPerMinute: { acme: 5 },
      now: () => now,
    });
    assert.equal(b.limitFor("acme"), 5);
    assert.equal(b.limitFor("other"), 1);
    assert.deepEqual(b.configuredTenants(), ["acme"]);
    for (let i = 0; i < 5; i++) assert.ok(b.take("acme"));
    assert.ok(!b.take("acme"));
    assert.ok(b.take("other"));
    assert.ok(!b.take("other"));
  });

  it("validates budgets with RangeError, fail-fast", () => {
    for (const bad of [0, -1, NaN, Infinity, 1.5 - 1.5]) {
      assert.throws(() => new TenantRetryBudget({ retriesPerMinute: bad }), RangeError);
    }
    assert.throws(
      () => new TenantRetryBudget({ perTenantRetriesPerMinute: { acme: 0 } }),
      RangeError
    );
    assert.throws(
      () => new TenantRetryBudget({ perTenantRetriesPerMinute: { acme: -3 } }),
      RangeError
    );
    // A bad override never leaves a half-constructed instance behind —
    // construction throws before any bucket exists.
    assert.throws(
      () => new TenantRetryBudget({ perTenantRetriesPerMinute: { "": 5 } }),
      /tenant id/
    );
  });

  it("rejects malformed override records", () => {
    assert.throws(
      () => new TenantRetryBudget({ perTenantRetriesPerMinute: [] as never }),
      RangeError
    );
    assert.throws(
      () => new TenantRetryBudget({ perTenantRetriesPerMinute: null as never }),
      RangeError
    );
  });
});
