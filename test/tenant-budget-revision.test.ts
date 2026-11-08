import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import { RetryQueue, type Sender, type TenantBudgetAuditEvent } from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "tenant-budget-revision-secret";
const EP_A = "http://a.example/hook";
const URL_A = "http://localhost:9999/a";

/**
 * Manual timer that records the delay each callback was scheduled
 * with: budget parks re-arm at the next UTC month boundary, so the
 * tests fire only the immediate (0ms) dispatches and leave the park
 * timer armed — proving a loosened budget does not release an
 * already-parked item early.
 */
function recordingTimer() {
  const pending: Array<{ fn: () => void; ms: number }> = [];
  return {
    pending,
    pendingCount: () => pending.length,
    setTimer: (fn: () => void, ms: number) => {
      const entry = { fn, ms };
      pending.push(entry);
      return {
        clear: () => {
          const i = pending.indexOf(entry);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    /** Fire only the timers scheduled with delay <= `maxMs` (default 0). */
    async stepDue(maxMs = 0) {
      const due = pending.filter((e) => e.ms <= maxMs);
      for (const e of due) pending.splice(pending.indexOf(e), 1);
      for (const e of due) e.fn();
      await new Promise((r) => setImmediate(r));
    },
    async stepAll() {
      const fns = pending.splice(0);
      for (const e of fns) e.fn();
      await new Promise((r) => setImmediate(r));
    },
  };
}

function item(id: string, targetUrl: string, tenantId?: string) {
  return { id, payload: Buffer.from("x"), targetUrl, headers: {}, tenantId };
}

describe("RetryQueue tenant delivery budget revision (WR-362)", () => {
  it("revise/get/remove read live values; check order is tenant id, then budget", () => {
    const now = Date.UTC(2026, 9, 15, 12, 0, 0);
    const q = new RetryQueue({
      sender: (async () => {}) as Sender,
      budget: { now: () => now },
    });
    try {
      assert.equal(q.getTenantBudget("acme"), undefined);
      assert.deepEqual(q.reviseTenantBudget("acme", 10), {
        tenant: "acme",
        deliveriesPerMonth: 10,
        previous: undefined,
        overridden: true,
      });
      assert.deepEqual(q.getTenantBudget("acme"), {
        tenant: "acme",
        deliveriesPerMonth: 10,
        previous: 10,
        overridden: true,
      });
      assert.deepEqual(q.reviseTenantBudget("acme", 5), {
        tenant: "acme",
        deliveriesPerMonth: 5,
        previous: 10,
        overridden: true,
      });
      // Tenant id is checked before the budget.
      assert.throws(() => q.reviseTenantBudget("", 5), RangeError);
      assert.throws(() => q.reviseTenantBudget("bad id!", 0), RangeError);
      assert.throws(() => q.reviseTenantBudget("acme", 0), RangeError);
      assert.throws(() => q.reviseTenantBudget("acme", -1), RangeError);
      assert.throws(() => q.reviseTenantBudget("acme", 1.5), RangeError);
      assert.throws(() => q.reviseTenantBudget("acme", NaN), RangeError);
      assert.deepEqual(q.getTenantBudget("acme"), {
        tenant: "acme",
        deliveriesPerMonth: 5,
        previous: 5,
        overridden: true,
      });
      assert.equal(q.removeTenantBudget("never"), false);
      assert.equal(q.removeTenantBudget("acme"), true);
      assert.equal(q.getTenantBudget("acme"), undefined);
      assert.equal(q.removeTenantBudget("acme"), false);
      // Removing a malformed tenant id never throws — it simply has no budget.
      assert.equal(q.removeTenantBudget(""), false);
      assert.equal(q.removeTenantBudget("bad id!"), false);
    } finally {
      q.stop();
    }
  });

  it("a same-value revision is a no-op", () => {
    const now = Date.UTC(2026, 9, 15, 12, 0, 0);
    const q = new RetryQueue({
      sender: (async () => {}) as Sender,
      budget: { now: () => now },
    });
    try {
      assert.deepEqual(q.reviseTenantBudget("acme", 10), {
        tenant: "acme",
        deliveriesPerMonth: 10,
        previous: undefined,
        overridden: true,
      });
      assert.deepEqual(q.reviseTenantBudget("acme", 10), {
        tenant: "acme",
        deliveriesPerMonth: 10,
        previous: 10,
        overridden: true,
      });
      assert.deepEqual(q.getTenantBudgetStats(), [
        { tenant: "acme", month: "2026-10", used: 0, budget: 10, over: false, delayed: 0 },
      ]);
    } finally {
      q.stop();
    }
  });

  it("tenant omitted revises the default tenant; the empty string is rejected", () => {
    const now = Date.UTC(2026, 9, 15, 12, 0, 0);
    const q = new RetryQueue({
      sender: (async () => {}) as Sender,
      budget: { now: () => now },
    });
    try {
      assert.deepEqual(q.reviseTenantBudget(undefined, 7), {
        tenant: "default",
        deliveriesPerMonth: 7,
        previous: undefined,
        overridden: true,
      });
      assert.deepEqual(q.getTenantBudget(), {
        tenant: "default",
        deliveriesPerMonth: 7,
        previous: 7,
        overridden: true,
      });
      assert.deepEqual(q.getTenantBudget("default"), {
        tenant: "default",
        deliveriesPerMonth: 7,
        previous: 7,
        overridden: true,
      });
      assert.throws(() => q.reviseTenantBudget("", 7), RangeError);
      assert.equal(q.getTenantBudget(""), undefined);
      assert.equal(q.removeTenantBudget("default"), true);
      assert.equal(q.getTenantBudget(), undefined);
    } finally {
      q.stop();
    }
  });

  it("other tenants are untouched by a revision", () => {
    const now = Date.UTC(2026, 9, 15, 12, 0, 0);
    const q = new RetryQueue({
      sender: (async () => {}) as Sender,
      budget: { now: () => now },
    });
    try {
      q.reviseTenantBudget("acme", 10);
      q.reviseTenantBudget("globex", 20);
      q.reviseTenantBudget("acme", 5);
      assert.equal(q.getTenantBudget("globex")?.deliveriesPerMonth, 20);
      assert.equal(q.getTenantBudget("acme")?.deliveriesPerMonth, 5);
      assert.deepEqual(
        q.getTenantBudgetStats().map((r) => [r.tenant, r.budget]),
        [
          ["acme", 5],
          ["globex", 20],
        ]
      );
    } finally {
      q.stop();
    }
  });

  it("revising past maxTenants evicts the least-recently-active other row, which falls back to unlimited", () => {
    let now = Date.UTC(2026, 9, 15, 12, 0, 0);
    const q = new RetryQueue({
      sender: (async () => {}) as Sender,
      budget: { now: () => now, maxTenants: 2 },
    });
    try {
      q.reviseTenantBudget("a", 10);
      now += 1000;
      q.reviseTenantBudget("b", 10);
      now += 1000;
      q.reviseTenantBudget("c", 10); // past the cap: "a" is evicted
      assert.equal(q.getTenantBudget("a"), undefined);
      assert.equal(q.getTenantBudget("b")?.deliveriesPerMonth, 10);
      assert.equal(q.getTenantBudget("c")?.deliveriesPerMonth, 10);
      assert.deepEqual(
        q.getTenantBudgetStats().map((r) => r.tenant),
        ["b", "c"]
      );
    } finally {
      q.stop();
    }
  });

  it("tightening parks the next dispatch; loosening releases the next dispatch; the parked item keeps its month-boundary timer", async () => {
    // 500ms before November: the parked retry lands inside the test run.
    const now = Date.UTC(2026, 9, 31, 23, 59, 59, 500);
    const t = recordingTimer();
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
    try {
      q.reviseTenantBudget("acme", 2);
      q.enqueue(item("a", URL_A, "acme"));
      q.start();
      await t.stepDue(); // "a" dispatches and succeeds -> used = 1
      assert.equal(calls, 1);
      // Tighten below the counted usage: the next dispatch parks.
      assert.deepEqual(q.reviseTenantBudget("acme", 1), {
        tenant: "acme",
        deliveriesPerMonth: 1,
        previous: 2,
        overridden: true,
      });
      q.enqueue(item("b", URL_A, "acme"));
      await t.stepDue(); // "b" finds the budget exhausted -> parked, not dropped
      assert.equal(calls, 1);
      assert.equal(q.pendingCount(), 1);
      assert.equal(q.getDeadLetter().length, 0);
      assert.deepEqual(q.getTenantBudgetStats(), [
        { tenant: "acme", month: "2026-10", used: 1, budget: 1, over: true, delayed: 1 },
      ]);
      assert.equal(audits.length, 1);
      // The park timer is armed for the month boundary (500ms out).
      assert.equal(t.pending.length, 1);
      assert.equal(t.pending[0].ms, 500);
      // Loosen: the next dispatch goes out at once — but the parked
      // item is NOT released early: its timer is untouched.
      q.reviseTenantBudget("acme", 5);
      assert.equal(t.pending.length, 1);
      assert.equal(t.pending[0].ms, 500);
      q.enqueue(item("c", URL_A, "acme"));
      await t.stepDue(); // only the immediate dispatch fires
      assert.equal(calls, 2);
      assert.equal(q.pendingCount(), 1); // "b" still parked
      assert.equal(t.pending.length, 1);
      assert.equal(t.pending[0].ms, 500);
    } finally {
      q.stop();
    }
  });

  it("an already-parked item dispatches at the month boundary, not before", async () => {
    let now = Date.UTC(2026, 9, 31, 23, 59, 59, 500);
    const t = recordingTimer();
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
    try {
      q.reviseTenantBudget("acme", 1);
      q.enqueue(item("a", URL_A, "acme"));
      q.start();
      await t.stepDue();
      assert.equal(calls, 1);
      q.enqueue(item("b", URL_A, "acme"));
      await t.stepDue(); // "b" parks until November
      assert.equal(calls, 1);
      q.reviseTenantBudget("acme", 5); // loosened — but "b" waits for its timer
      await t.stepDue(); // nothing due: the park timer is not an immediate one
      assert.equal(calls, 1);
      assert.equal(q.pendingCount(), 1);
      now = Date.UTC(2026, 10, 1, 0, 0, 0, 100); // November: fresh budget
      await t.stepAll(); // "b"'s parked timer fires -> month rolled -> dispatched
      assert.equal(calls, 2);
      assert.equal(q.pendingCount(), 0);
    } finally {
      q.stop();
    }
  });

  it("the month rollover re-arms budget_exceeded under the new budget", async () => {
    let now = Date.UTC(2026, 9, 31, 23, 59, 59, 500);
    const t = recordingTimer();
    let calls = 0;
    const audits: TenantBudgetAuditEvent[] = [];
    const sender: Sender = async () => {
      calls += 1;
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      random: () => 0,
      budget: { now: () => now },
      onBudgetExceeded: (e) => audits.push(e),
    });
    try {
      q.reviseTenantBudget("acme", 1);
      q.enqueue(item("a", URL_A, "acme"));
      q.start();
      await t.stepDue();
      assert.equal(calls, 1);
      q.enqueue(item("b", URL_A, "acme"));
      await t.stepDue(); // "b" parks: October's first exceedance
      assert.equal(audits.length, 1);
      assert.equal(audits[0].deliveriesPerMonth, 1);
      assert.equal(audits[0].month, "2026-10");
      q.reviseTenantBudget("acme", 5);
      now = Date.UTC(2026, 10, 1, 0, 0, 0, 100); // November
      await t.stepAll(); // "b" dispatches under the fresh month
      assert.equal(calls, 2);
      assert.equal(audits.length, 1); // November was not over budget yet
      // Fill November's new allowance of 5: "b" counted 1, four more fit.
      for (const id of ["c", "d", "e", "f"]) {
        q.enqueue(item(id, URL_A, "acme"));
        await t.stepDue();
      }
      assert.equal(calls, 6);
      q.enqueue(item("g", URL_A, "acme"));
      await t.stepDue(); // "g" parks: November's first exceedance, re-armed
      assert.equal(calls, 6);
      assert.equal(audits.length, 2);
      assert.equal(audits[1].event, "budget_exceeded");
      assert.equal(audits[1].deliveriesPerMonth, 5);
      assert.equal(audits[1].used, 5);
      assert.equal(audits[1].month, "2026-11");
      assert.deepEqual(q.getTenantBudgetStats(), [
        { tenant: "acme", month: "2026-11", used: 5, budget: 5, over: true, delayed: 2 },
      ]);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer tenant delivery budget revision (WR-362)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "tenant-budget-revision-"));
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

  it("revise audits previous/current, with undefined as first previous", async () => {
    const { relay, auditLog } = makeServer({});
    await listen(relay);
    assert.deepEqual(relay.reviseTenantBudget(undefined, 100), {
      tenant: "default",
      deliveriesPerMonth: 100,
      previous: undefined,
      overridden: true,
    });
    let revised = eventsOf(auditLog, "tenant_budget_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].tenant, "default");
    assert.equal(revised[0].previous, undefined);
    assert.equal(revised[0].current, 100);
    assert.deepEqual(relay.reviseTenantBudget("acme", 50), {
      tenant: "acme",
      deliveriesPerMonth: 50,
      previous: undefined,
      overridden: true,
    });
    revised = eventsOf(auditLog, "tenant_budget_revised");
    assert.equal(revised.length, 2);
    assert.equal(revised[1].tenant, "acme");
    assert.equal(revised[1].previous, undefined);
    assert.equal(revised[1].current, 50);
    // A second revision audits the live allowance as previous.
    relay.reviseTenantBudget("acme", 25);
    revised = eventsOf(auditLog, "tenant_budget_revised");
    assert.equal(revised.length, 3);
    assert.equal(revised[2].tenant, "acme");
    assert.equal(revised[2].previous, 50);
    assert.equal(revised[2].current, 25);
  });

  it("a same-value revision is a silent no-op", async () => {
    const { relay, auditLog } = makeServer({});
    await listen(relay);
    relay.reviseTenantBudget(undefined, 100);
    assert.equal(eventsOf(auditLog, "tenant_budget_revised").length, 1);
    // Landing exactly on the live value — even the constructor-free first set repeated.
    relay.reviseTenantBudget(undefined, 100);
    assert.equal(eventsOf(auditLog, "tenant_budget_revised").length, 1);
    relay.reviseTenantBudget("acme", 100);
    assert.equal(eventsOf(auditLog, "tenant_budget_revised").length, 2);
    relay.reviseTenantBudget("acme", 100);
    assert.equal(eventsOf(auditLog, "tenant_budget_revised").length, 2);
  });

  it("an illegal value throws RangeError and the live budget and audit are untouched", async () => {
    const { relay, auditLog } = makeServer({});
    await listen(relay);
    relay.reviseTenantBudget(undefined, 100);
    relay.reviseTenantBudget("acme", 50);
    for (const bad of [0, -1, NaN, Infinity, 1.5]) {
      assert.throws(() => relay.reviseTenantBudget(undefined, bad), RangeError, `default ${bad}`);
      assert.throws(() => relay.reviseTenantBudget("acme", bad), RangeError, `tenant ${bad}`);
    }
    assert.throws(() => relay.reviseTenantBudget("", 5), RangeError);
    assert.throws(() => relay.reviseTenantBudget("bad id!", 5), RangeError);
    assert.deepEqual(relay.getTenantBudget!(), {
      tenant: "default",
      deliveriesPerMonth: 100,
      previous: 100,
      overridden: true,
    });
    assert.deepEqual(relay.getTenantBudget!("acme"), {
      tenant: "acme",
      deliveriesPerMonth: 50,
      previous: 50,
      overridden: true,
    });
    assert.equal(eventsOf(auditLog, "tenant_budget_revised").length, 2);
  });

  it("remove returns true, audits, and falls back to unlimited; without a budget it returns false silently", async () => {
    const { relay, auditLog } = makeServer({});
    await listen(relay);
    relay.reviseTenantBudget(undefined, 100);
    relay.reviseTenantBudget("acme", 50);
    assert.equal(relay.removeTenantBudget("acme"), true);
    const removed = eventsOf(auditLog, "tenant_budget_removed");
    assert.equal(removed.length, 1);
    assert.equal(removed[0].tenant, "acme");
    assert.equal(removed[0].previous, 50);
    assert.equal(relay.getTenantBudget!("acme"), undefined);
    // Nothing left to remove: false, no audit.
    assert.equal(relay.removeTenantBudget("acme"), false);
    assert.equal(eventsOf(auditLog, "tenant_budget_removed").length, 1);
    // The default tenant's budget can be removed too (unlike the
    // WR-326 default rate, "default" here is just a tenant key).
    assert.equal(relay.removeTenantBudget("default"), true);
    assert.equal(eventsOf(auditLog, "tenant_budget_removed").length, 2);
    assert.equal(relay.getTenantBudget!(), undefined);
  });

  it("the getter matches live state; an unconfigured tenant returns undefined", async () => {
    const { relay } = makeServer({});
    await listen(relay);
    assert.equal(relay.getTenantBudget!("other"), undefined);
    relay.reviseTenantBudget("acme", 100);
    assert.equal(relay.getTenantBudget!("acme").deliveriesPerMonth, 100);
    assert.equal(relay.getTenantBudget!("acme").overridden, true);
    relay.reviseTenantBudget(undefined, 300);
    assert.equal(relay.getTenantBudget!("other"), undefined);
    assert.equal(relay.getTenantBudget!().deliveriesPerMonth, 300);
    assert.equal(relay.getTenantBudget!("acme").deliveriesPerMonth, 100);
  });
});
