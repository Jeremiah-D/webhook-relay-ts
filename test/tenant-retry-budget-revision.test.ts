import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import { TenantRetryBudget } from "../src/tenant-retry-budget.ts";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "tenant-retry-budget-revision-secret";
const EP_A = "http://a.example/hook";

describe("TenantRetryBudget live revision (WR-326)", () => {
  it("reviseDefault retunes existing no-override buckets: tightening bites at once, widening never tops up", () => {
    let now = 0;
    const b = new TenantRetryBudget({ retriesPerMinute: 2, now: () => now });
    assert.ok(b.take("a"));
    assert.ok(b.take("a"));
    assert.ok(!b.take("a"), "a drained");
    b.reviseDefault(1);
    assert.ok(!b.take("a"), "tightened bucket stays empty right after the cut");
    now += 60_000;
    assert.ok(b.take("a"), "one token refills in a minute at the new rate");
    assert.ok(!b.take("a"));
    // Widening never tops the bucket up: the drained bucket stays empty
    // until the refill accrues against the new cap.
    b.reviseDefault(60);
    assert.ok(!b.take("a"), "widening adds no tokens");
    now += 1000;
    assert.ok(b.take("a"), "one token refills in a second at 60/min");
    assert.equal(b.defaultLimit(), 60);
  });

  it("a lazily-created bucket is built at the revised default", () => {
    let now = 0;
    const b = new TenantRetryBudget({ retriesPerMinute: 2, now: () => now });
    assert.equal(b.reviseDefault(5), 5);
    for (let i = 0; i < 5; i++) assert.ok(b.take("never-seen"), `take ${i}`);
    assert.ok(!b.take("never-seen"));
    assert.equal(b.limitFor("never-seen"), 5);
  });

  it("reviseTenant moves only that tenant; other tenants and the default are untouched", () => {
    let now = 0;
    const b = new TenantRetryBudget({ retriesPerMinute: 2, now: () => now });
    assert.ok(b.take("other"));
    assert.ok(b.take(undefined));
    assert.equal(b.reviseTenant("acme", 1), 1);
    assert.equal(b.limitFor("acme"), 1);
    assert.equal(b.limitFor("other"), 2);
    assert.equal(b.limitFor(undefined), 2);
    assert.equal(b.defaultLimit(), 2);
    assert.ok(b.take("acme"));
    assert.ok(!b.take("acme"));
    assert.ok(b.take("other"), "other tenant still has its second token");
    // Revising the default leaves the overridden tenant alone.
    assert.equal(b.reviseDefault(3), 3);
    assert.equal(b.limitFor("acme"), 1);
    assert.equal(b.limitFor("other"), 3);
    assert.deepEqual(b.configuredTenants(), ["acme"]);
  });

  it("an unseen tenant's override is recorded first and its first bucket is built at the new rate", () => {
    let now = 0;
    const b = new TenantRetryBudget({ retriesPerMinute: 2, now: () => now });
    assert.equal(b.reviseTenant("newbie", 3), 3);
    assert.ok(b.hasOverride("newbie"));
    assert.equal(b.limitFor("newbie"), 3);
    for (let i = 0; i < 3; i++) assert.ok(b.take("newbie"), `take ${i}`);
    assert.ok(!b.take("newbie"));
    assert.equal(b.limitFor(undefined), 2);
  });

  it("an illegal rate or tenant id throws and the live budget is untouched", () => {
    let now = 0;
    const b = new TenantRetryBudget({ retriesPerMinute: 2, now: () => now });
    assert.ok(b.take("acme"));
    for (const bad of [0, -1, NaN, Infinity]) {
      assert.throws(() => b.reviseDefault(bad), RangeError, `default ${bad}`);
      assert.throws(() => b.reviseTenant("acme", bad), RangeError, `tenant ${bad}`);
    }
    assert.equal(b.defaultLimit(), 2);
    assert.equal(b.limitFor("acme"), 2);
    assert.ok(!b.hasOverride("acme"));
    // Tenant id is validated before the rate: a bad id with a bad rate
    // throws for the id, and nothing moves either way.
    assert.throws(() => b.reviseTenant("", 5), RangeError);
    assert.throws(() => b.reviseTenant("bad id!", 0), RangeError);
    assert.throws(() => b.reviseTenant(undefined as unknown as string, 5), TypeError);
    assert.equal(b.defaultLimit(), 2);
    assert.ok(b.take("acme"), "one token left after the failed revisions");
    assert.ok(!b.take("acme"));
  });

  it("a same-value revision is a no-op and records no override", () => {
    const b = new TenantRetryBudget({ retriesPerMinute: 2 });
    assert.equal(b.reviseDefault(2), 2);
    assert.equal(b.reviseTenant("acme", 2), 2);
    assert.ok(!b.hasOverride("acme"), "revising to the effective rate must not create an override");
    assert.equal(b.limitFor("acme"), 2);
  });

  it("removeTenant returns false without an override and restores the default rate, keeping the bucket", () => {
    let now = 0;
    const b = new TenantRetryBudget({ retriesPerMinute: 2, now: () => now });
    assert.equal(b.removeTenant("never"), false);
    b.reviseTenant("acme", 5);
    assert.ok(b.take("acme"));
    assert.ok(b.take("acme")); // 3 tokens left in the 5/min bucket
    assert.equal(b.removeTenant("acme"), true);
    assert.equal(b.limitFor("acme"), 2);
    assert.ok(!b.hasOverride("acme"));
    // The bucket survived: retuned to the default, tokens clamped to 2.
    assert.ok(b.take("acme"));
    assert.ok(b.take("acme"));
    assert.ok(!b.take("acme"));
    assert.equal(b.removeTenant("acme"), false);
    assert.throws(() => b.removeTenant(""), RangeError);
  });
});

describe("RetryQueue tenant retry budget revision (WR-326)", () => {
  it("revise/get/remove read live values; check order is tenant id, then rate", () => {
    let now = 0;
    const q = new RetryQueue({
      sender: (async () => {}) as Sender,
      tenantRetryBudget: { retriesPerMinute: 60, now: () => now },
    });
    try {
      assert.deepEqual(q.getTenantRetryBudget(), {
        retriesPerMinute: 60,
        previous: 60,
        scope: "default",
        overridden: false,
      });
      assert.deepEqual(q.getTenantRetryBudget("acme"), {
        tenant: "acme",
        retriesPerMinute: 60,
        previous: 60,
        scope: "tenant",
        overridden: false,
      });
      assert.deepEqual(q.reviseTenantRetryBudget(undefined, 30), {
        retriesPerMinute: 30,
        previous: 60,
        scope: "default",
        overridden: false,
      });
      assert.deepEqual(q.reviseTenantRetryBudget("acme", 5), {
        tenant: "acme",
        retriesPerMinute: 5,
        previous: 30,
        scope: "tenant",
        overridden: true,
      });
      // Same effective value: a no-op that records no override.
      assert.deepEqual(q.reviseTenantRetryBudget("other", 30), {
        tenant: "other",
        retriesPerMinute: 30,
        previous: 30,
        scope: "tenant",
        overridden: false,
      });
      // Tenant id is checked before the rate.
      assert.throws(() => q.reviseTenantRetryBudget("bad id!", 0), RangeError);
      assert.throws(() => q.reviseTenantRetryBudget("acme", 0), RangeError);
      assert.equal(q.getTenantRetryBudget("acme")?.retriesPerMinute, 5);
      assert.equal(q.getTenantRetryBudget("acme")?.overridden, true);
      assert.equal(q.removeTenantRetryBudget("never"), false);
      assert.equal(q.removeTenantRetryBudget(""), false);
      assert.equal(q.removeTenantRetryBudget(undefined), false);
      assert.equal(q.removeTenantRetryBudget("acme"), true);
      assert.deepEqual(q.getTenantRetryBudget("acme"), {
        tenant: "acme",
        retriesPerMinute: 30,
        previous: 30,
        scope: "tenant",
        overridden: false,
      });
      assert.equal(q.getTenantRetryBudgetStats()?.defaultRetriesPerMinute, 30);
    } finally {
      q.stop();
    }
  });

  it("an unconfigured queue throws the must-restart Error on revise and reports nothing on get/remove", () => {
    const q = new RetryQueue({ sender: (async () => {}) as Sender });
    try {
      assert.throws(
        () => q.reviseTenantRetryBudget(undefined, 30),
        /tenant retry budget is not configured — enabling it requires a restart/
      );
      assert.throws(
        () => q.reviseTenantRetryBudget("acme", 5),
        /tenant retry budget is not configured — enabling it requires a restart/
      );
      assert.equal(q.getTenantRetryBudget(), undefined);
      assert.equal(q.getTenantRetryBudget("acme"), undefined);
      assert.equal(q.removeTenantRetryBudget("acme"), false);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer tenant retry budget revision (WR-326)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "tenant-retry-budget-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: EP_A,
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

  it("revise audits previous/current, with the constructor default as first previous", async () => {
    const { relay, auditLog } = makeServer({
      retry: { tenantRetryBudget: { retriesPerMinute: 6000 } },
    });
    await listen(relay);
    assert.deepEqual(relay.reviseTenantRetryBudget(undefined, 3000), {
      retriesPerMinute: 3000,
      previous: 6000,
      scope: "default",
      overridden: false,
    });
    let revised = eventsOf(auditLog, "tenant_retry_budget_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].tenant, undefined);
    assert.equal(revised[0].scope, "default");
    assert.equal(revised[0].previous, 6000); // first previous: the constructor default
    assert.equal(revised[0].current, 3000);
    // A tenant revision audits the live effective value as previous.
    assert.deepEqual(relay.reviseTenantRetryBudget("acme", 100), {
      tenant: "acme",
      retriesPerMinute: 100,
      previous: 3000,
      scope: "tenant",
      overridden: true,
    });
    revised = eventsOf(auditLog, "tenant_retry_budget_revised");
    assert.equal(revised.length, 2);
    assert.equal(revised[1].tenant, "acme");
    assert.equal(revised[1].scope, "tenant");
    assert.equal(revised[1].previous, 3000);
    assert.equal(revised[1].current, 100);
  });

  it("a same-value revision is a silent no-op", async () => {
    const { relay, auditLog } = makeServer({
      retry: { tenantRetryBudget: { retriesPerMinute: 6000 } },
    });
    await listen(relay);
    // Landing exactly on the live value — even the constructor default itself.
    relay.reviseTenantRetryBudget(undefined, 6000);
    assert.equal(eventsOf(auditLog, "tenant_retry_budget_revised").length, 0);
    relay.reviseTenantRetryBudget("acme", 6000);
    assert.equal(eventsOf(auditLog, "tenant_retry_budget_revised").length, 0);
    assert.equal(relay.getTenantRetryBudget!("acme").overridden, false);
    relay.reviseTenantRetryBudget("acme", 100);
    assert.equal(eventsOf(auditLog, "tenant_retry_budget_revised").length, 1);
    relay.reviseTenantRetryBudget("acme", 100);
    assert.equal(eventsOf(auditLog, "tenant_retry_budget_revised").length, 1);
  });

  it("an illegal value throws RangeError and the live budget and audit are untouched", async () => {
    const { relay, auditLog } = makeServer({
      retry: { tenantRetryBudget: { retriesPerMinute: 6000 } },
    });
    await listen(relay);
    for (const bad of [0, -1, NaN, Infinity]) {
      assert.throws(() => relay.reviseTenantRetryBudget(undefined, bad), RangeError, `default ${bad}`);
      assert.throws(() => relay.reviseTenantRetryBudget("acme", bad), RangeError, `tenant ${bad}`);
    }
    assert.throws(() => relay.reviseTenantRetryBudget("bad id!", 5), RangeError);
    assert.deepEqual(relay.getTenantRetryBudget!(), {
      retriesPerMinute: 6000,
      previous: 6000,
      scope: "default",
      overridden: false,
    });
    assert.deepEqual(relay.getTenantRetryBudget!("acme"), {
      tenant: "acme",
      retriesPerMinute: 6000,
      previous: 6000,
      scope: "tenant",
      overridden: false,
    });
    assert.equal(eventsOf(auditLog, "tenant_retry_budget_revised").length, 0);
  });

  it("remove returns true, audits, and falls back to the live default; without an override it returns false silently", async () => {
    const { relay, auditLog } = makeServer({
      retry: { tenantRetryBudget: { retriesPerMinute: 6000 } },
    });
    await listen(relay);
    relay.reviseTenantRetryBudget(undefined, 3000);
    relay.reviseTenantRetryBudget("acme", 100);
    assert.equal(relay.getTenantRetryBudget!("acme").retriesPerMinute, 100);
    assert.equal(relay.removeTenantRetryBudget("acme"), true);
    const removed = eventsOf(auditLog, "tenant_retry_budget_removed");
    assert.equal(removed.length, 1);
    assert.equal(removed[0].tenant, "acme");
    assert.equal(removed[0].previous, 100);
    assert.deepEqual(relay.getTenantRetryBudget!("acme"), {
      tenant: "acme",
      retriesPerMinute: 3000,
      previous: 3000,
      scope: "tenant",
      overridden: false,
    });
    // Nothing left to remove: false, no audit.
    assert.equal(relay.removeTenantRetryBudget("acme"), false);
    assert.equal(eventsOf(auditLog, "tenant_retry_budget_removed").length, 1);
    // The default rate cannot be removed, only revised.
    assert.equal(relay.removeTenantRetryBudget(""), false);
    assert.equal(eventsOf(auditLog, "tenant_retry_budget_removed").length, 1);
  });

  it("the getter matches live state and is absent when the budget was never configured", async () => {
    const { relay } = makeServer({
      retry: { tenantRetryBudget: { retriesPerMinute: 6000 } },
    });
    await listen(relay);
    assert.equal(relay.getTenantRetryBudget!("other").retriesPerMinute, 6000);
    relay.reviseTenantRetryBudget("acme", 100);
    assert.equal(relay.getTenantRetryBudget!("acme").retriesPerMinute, 100);
    assert.equal(relay.getTenantRetryBudget!("acme").overridden, true);
    relay.reviseTenantRetryBudget(undefined, 3000);
    assert.equal(relay.getTenantRetryBudget!("other").retriesPerMinute, 3000);
    assert.equal(relay.getTenantRetryBudget!("acme").retriesPerMinute, 100);
    assert.equal(relay.getTenantRetryBudget!().retriesPerMinute, 3000);

    const unconfigured = makeServer({});
    await listen(unconfigured.relay);
    assert.equal(unconfigured.relay.getTenantRetryBudget, undefined);
    assert.throws(
      () => unconfigured.relay.reviseTenantRetryBudget(undefined, 30),
      /tenant retry budget is not configured — enabling it requires a restart/
    );
    assert.equal(unconfigured.relay.removeTenantRetryBudget("acme"), false);
  });
});
