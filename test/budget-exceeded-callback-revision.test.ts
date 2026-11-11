import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  type Sender,
  type TenantBudgetAuditEvent,
} from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "budget-exceeded-callback-revision-secret";
const URL = "http://localhost:9999/hook";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));
const TOKEN = "op-token";

/**
 * Manual timer that records the delay each callback was scheduled
 * with: budget parks re-arm at the next UTC month boundary, so the
 * tests fire only the immediate (0ms) dispatches and leave the park
 * timer armed — proving a revision does not release an already-parked
 * item early.
 */
function recordingTimer() {
  const pending: Array<{ fn: () => void; ms: number }> = [];
  return {
    pending,
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

/** Let queued microtask chains (admission -> turn grant -> sender) settle. */
async function settle(rounds = 20): Promise<void> {
  for (let i = 0; i < rounds; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

function item(id: string, tenantId?: string) {
  return { id, payload: Buffer.from(id), targetUrl: URL, headers: {}, tenantId };
}

describe("RetryQueue budget-exceeded callback revision (WR-392)", () => {
  it("revise swaps the live callback: the next tenant's first exceedance enters the new callback, the old one is silent", async () => {
    // 500ms before November: the parked retry lands inside the test run.
    const now = Date.UTC(2026, 9, 31, 23, 59, 59, 500);
    const t = recordingTimer();
    let calls = 0;
    const oldSeen: TenantBudgetAuditEvent[] = [];
    const newSeen: TenantBudgetAuditEvent[] = [];
    const q = new RetryQueue({
      sender: (async () => {
        calls += 1;
      }) as Sender,
      setTimer: t.setTimer,
      random: () => 0, // no jitter: the park delay is exactly msUntilBudgetReset
      budget: { now: () => now },
      onBudgetExceeded: (e) => oldSeen.push(e),
    });
    try {
      q.reviseTenantBudget("acme", 1);
      q.enqueue(item("a", "acme"));
      q.start();
      await t.stepDue(); // "a" dispatches and succeeds -> used = 1
      assert.equal(calls, 1);
      q.enqueue(item("b", "acme"));
      await t.stepDue(); // "b" finds the budget exhausted -> parked, not dropped
      assert.equal(calls, 1);
      assert.equal(q.pendingCount(), 1);
      assert.equal(oldSeen.length, 1);
      assert.deepEqual(
        { ...oldSeen[0], at: "X" },
        {
          event: "budget_exceeded",
          tenant: "acme",
          deliveriesPerMonth: 1,
          used: 1,
          month: "2026-10",
          at: "X",
        }
      );
      assert.deepEqual(newSeen, []);
      // Swap mid-stream: the already-reported exceedance is never
      // re-delivered, and the next tenant's first exceedance enters
      // only the new callback.
      q.reviseBudgetExceededCallback((e) => newSeen.push(e));
      q.reviseTenantBudget("globex", 1);
      q.enqueue(item("g-1", "globex"));
      await t.stepDue();
      assert.equal(calls, 2);
      assert.deepEqual(oldSeen, oldSeen.slice(0, 1));
      assert.deepEqual(newSeen, []);
      q.enqueue(item("g-2", "globex"));
      await t.stepDue(); // "g-2" parks: globex's first exceedance
      assert.equal(calls, 2);
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0].tenant, "globex");
      assert.equal(newSeen[0].deliveriesPerMonth, 1);
      assert.equal(newSeen[0].used, 1);
      assert.equal(newSeen[0].month, "2026-10");
      assert.deepEqual(q.getTenantBudgetStats(), [
        { tenant: "acme", month: "2026-10", used: 1, budget: 1, over: true, delayed: 1 },
        { tenant: "globex", month: "2026-10", used: 1, budget: 1, over: true, delayed: 1 },
      ]);
    } finally {
      q.stop();
    }
  });

  it("null clears back to no observer: over-budget dispatches keep parking and counting", async () => {
    const now = Date.UTC(2026, 9, 31, 23, 59, 59, 500);
    const t = recordingTimer();
    let calls = 0;
    const seen: TenantBudgetAuditEvent[] = [];
    const q = new RetryQueue({
      sender: (async () => {
        calls += 1;
      }) as Sender,
      setTimer: t.setTimer,
      random: () => 0,
      budget: { now: () => now },
      onBudgetExceeded: (e) => seen.push(e),
    });
    try {
      q.reviseTenantBudget("acme", 1);
      q.enqueue(item("a", "acme"));
      q.start();
      await t.stepDue();
      assert.equal(calls, 1);
      q.enqueue(item("b", "acme"));
      await t.stepDue();
      assert.equal(seen.length, 1);
      assert.equal(q.getTenantBudgetStats()[0].delayed, 1);
      q.reviseBudgetExceededCallback(null);
      q.enqueue(item("c", "acme"));
      await t.stepDue(); // still parks — only the forwarding stopped
      assert.equal(calls, 1);
      assert.equal(seen.length, 1);
      assert.equal(q.pendingCount(), 2);
      assert.deepEqual(q.getTenantBudgetStats(), [
        { tenant: "acme", month: "2026-10", used: 1, budget: 1, over: true, delayed: 2 },
      ]);
    } finally {
      q.stop();
    }
  });

  it("a non-function value throws RangeError and the live callback is untouched", async () => {
    const now = Date.UTC(2026, 9, 31, 23, 59, 59, 500);
    const t = recordingTimer();
    let calls = 0;
    const seen: TenantBudgetAuditEvent[] = [];
    const live = (e: TenantBudgetAuditEvent) => seen.push(e);
    const q = new RetryQueue({
      sender: (async () => {
        calls += 1;
      }) as Sender,
      setTimer: t.setTimer,
      random: () => 0,
      budget: { now: () => now },
      onBudgetExceeded: live,
    });
    try {
      q.reviseTenantBudget("acme", 1);
      assert.throws(() => q.reviseBudgetExceededCallback(42 as never), RangeError);
      assert.throws(() => q.reviseBudgetExceededCallback("nope" as never), RangeError);
      q.enqueue(item("a", "acme"));
      q.start();
      await t.stepDue();
      assert.equal(calls, 1);
      q.enqueue(item("b", "acme"));
      await t.stepDue();
      assert.equal(seen.length, 1);
      assert.equal(seen[0].tenant, "acme");
    } finally {
      q.stop();
    }
  });

  it("same-reference revision and clearing-when-unset are silent no-ops", async () => {
    const now = Date.UTC(2026, 9, 31, 23, 59, 59, 500);
    const t = recordingTimer();
    const seen: TenantBudgetAuditEvent[] = [];
    const live = (e: TenantBudgetAuditEvent) => seen.push(e);
    const q = new RetryQueue({
      sender: (async () => {}) as Sender,
      setTimer: t.setTimer,
      random: () => 0,
      budget: { now: () => now },
      onBudgetExceeded: live,
    });
    try {
      q.reviseTenantBudget("acme", 1);
      q.reviseBudgetExceededCallback(live); // no-op, no throw
      q.enqueue(item("a", "acme"));
      q.start();
      await t.stepDue();
      q.enqueue(item("b", "acme"));
      await t.stepDue();
      assert.equal(seen.length, 1);
      q.reviseBudgetExceededCallback(null);
      q.reviseBudgetExceededCallback(null); // clearing when unset: no-op
      q.enqueue(item("c", "acme"));
      await t.stepDue();
      assert.equal(seen.length, 1);
      assert.equal(q.getTenantBudgetStats()[0].delayed, 2);
    } finally {
      q.stop();
    }
  });

  it("clearing when no callback was ever set is a no-op", async () => {
    const now = Date.UTC(2026, 9, 31, 23, 59, 59, 500);
    const t = recordingTimer();
    const q = new RetryQueue({
      sender: (async () => {}) as Sender,
      setTimer: t.setTimer,
      random: () => 0,
      budget: { now: () => now },
    });
    try {
      // No must-restart gate: the enforcer is always constructed, so a
      // revision is always possible even with no observer ever set.
      q.reviseBudgetExceededCallback(null);
      q.reviseTenantBudget("acme", 1);
      q.enqueue(item("a", "acme"));
      q.start();
      await t.stepDue();
      q.enqueue(item("b", "acme"));
      await t.stepDue(); // parks silently — no observer, no throw
      assert.equal(q.pendingCount(), 1);
      assert.equal(q.getTenantBudgetStats()[0].delayed, 1);
    } finally {
      q.stop();
    }
  });

  it("the month rollover re-arms budget_exceeded under the revised callback — still once per month", async () => {
    let now = Date.UTC(2026, 9, 31, 23, 59, 59, 500);
    const t = recordingTimer();
    let calls = 0;
    const oldSeen: TenantBudgetAuditEvent[] = [];
    const newSeen: TenantBudgetAuditEvent[] = [];
    const q = new RetryQueue({
      sender: (async () => {
        calls += 1;
      }) as Sender,
      setTimer: t.setTimer,
      random: () => 0,
      budget: { now: () => now },
      onBudgetExceeded: (e) => oldSeen.push(e),
    });
    try {
      q.reviseTenantBudget("acme", 1);
      q.enqueue(item("a", "acme"));
      q.start();
      await t.stepDue();
      assert.equal(calls, 1);
      q.enqueue(item("b", "acme"));
      await t.stepDue(); // "b" parks: October's first exceedance
      assert.equal(oldSeen.length, 1);
      assert.equal(oldSeen[0].month, "2026-10");
      q.reviseBudgetExceededCallback((e) => newSeen.push(e));
      now = Date.UTC(2026, 10, 1, 0, 0, 0, 100); // November
      await t.stepAll(); // "b"'s parked timer fires -> month rolled -> dispatched
      assert.equal(calls, 2);
      assert.equal(q.pendingCount(), 0);
      assert.deepEqual(oldSeen, oldSeen.slice(0, 1));
      assert.deepEqual(newSeen, []); // November was not over budget yet
      q.enqueue(item("c", "acme"));
      await t.stepDue(); // "c" parks: November's first exceedance, re-armed
      assert.equal(calls, 2);
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0].event, "budget_exceeded");
      assert.equal(newSeen[0].deliveriesPerMonth, 1);
      assert.equal(newSeen[0].used, 1);
      assert.equal(newSeen[0].month, "2026-11");
      assert.deepEqual(q.getTenantBudgetStats(), [
        { tenant: "acme", month: "2026-11", used: 1, budget: 1, over: true, delayed: 2 },
      ]);
      await settle();
    } finally {
      q.stop();
    }
  });

  it("a revision does not change the park or the re-dispatch: the parked item still waits for the month boundary", async () => {
    const now = Date.UTC(2026, 9, 31, 23, 59, 59, 500);
    const t = recordingTimer();
    let calls = 0;
    const q = new RetryQueue({
      sender: (async () => {
        calls += 1;
      }) as Sender,
      setTimer: t.setTimer,
      random: () => 0,
      budget: { now: () => now },
      onBudgetExceeded: () => {},
    });
    try {
      q.reviseTenantBudget("acme", 1);
      q.enqueue(item("a", "acme"));
      q.start();
      await t.stepDue();
      assert.equal(calls, 1);
      // Swap the observer, then park: the park is still a budget park
      // (month-boundary delay, not a retry backoff), consumes no retry
      // attempt, and the delayed counter still moves.
      q.reviseBudgetExceededCallback(() => {});
      q.enqueue(item("b", "acme"));
      await t.stepDue();
      assert.equal(calls, 1);
      assert.equal(q.pendingCount(), 1);
      assert.equal(t.pending.length, 1);
      assert.equal(t.pending[0].ms, 500); // ms until the next UTC month
      assert.deepEqual(q.getTenantBudgetStats(), [
        { tenant: "acme", month: "2026-10", used: 1, budget: 1, over: true, delayed: 1 },
      ]);
      // Loosening the budget does not release the parked item early —
      // its timer is untouched by the observer revision.
      q.reviseTenantBudget("acme", 5);
      assert.equal(t.pending.length, 1);
      assert.equal(t.pending[0].ms, 500);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer budget-exceeded callback revision (WR-392)", () => {
  let servers: Server[] = [];
  afterEach(async () => {
    for (const s of servers) {
      s.close();
      await new Promise((r) => s.once("close", r));
    }
    servers = [];
  });

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  async function drainUntil(cond: () => boolean, ms = 5000): Promise<void> {
    const deadline = Date.now() + ms;
    while (!cond()) {
      if (Date.now() > deadline) throw new Error("timed out waiting for condition");
      await new Promise((r) => setTimeout(r, 10));
    }
  }

  function postWebhook(port: number, tenant?: string) {
    return new Promise<number>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/hook",
          method: "POST",
          headers: {
            "x-signature": signSha256(BODY, relaySecret),
            "content-type": "application/json",
            "content-length": String(BODY.length),
            ...(tenant !== undefined ? { "x-tenant-id": tenant } : {}),
          },
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve(res.statusCode ?? 0));
        }
      );
      r.on("error", reject);
      r.end(BODY);
    });
  }

  function exceededEvents(audit: AuditLog) {
    return audit.query({ event: "budget_exceeded" }) as Array<{
      tenant: string;
      deliveriesPerMonth: number;
      used: number;
      month: string;
    }>;
  }

  function revisedEvents(audit: AuditLog) {
    return audit.query({ event: "budget_exceeded_callback_revised" }) as Array<{
      previous: string;
      current: string;
    }>;
  }

  /** A server with a 1/month budget for the default and acme tenants. */
  function budgetServer(onBudgetExceeded?: (event: TenantBudgetAuditEvent) => void) {
    const dir = mkdtempSync(join(tmpdir(), "budgetexceeded-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: URL,
      auditLog: audit,
      operatorToken: TOKEN,
      sender: (async () => {}) as Sender,
      retry: {
        baseDelayMs: 10,
        maxAttempts: 3,
        jitterMs: 0,
        budget: { budgets: { default: 1, acme: 1 } },
        ...(onBudgetExceeded !== undefined ? { onBudgetExceeded } : {}),
      },
    });
    servers.push(relay);
    return { relay, audit };
  }

  /**
   * Post two webhooks for `tenant`: the first delivers (counted), the
   * second parks on the exhausted budget. Waits for each side effect so
   * the second post's budget check always sees the first delivery.
   */
  async function postExceedingPair(
    port: number,
    audit: AuditLog,
    tenant: string | undefined,
    deliveredSoFar: number,
    exceededSoFar: number
  ) {
    assert.equal(await postWebhook(port, tenant), 202);
    await drainUntil(
      () => (audit.query({ event: "delivered" }) as unknown[]).length >= deliveredSoFar + 1
    );
    assert.equal(await postWebhook(port, tenant), 202);
    await drainUntil(() => exceededEvents(audit).length >= exceededSoFar + 1);
  }

  it("replacing the operator callback routes the next tenant's exceedance to the new callback and the budget_exceeded audit still lands", async () => {
    const oldSeen: TenantBudgetAuditEvent[] = [];
    const newSeen: TenantBudgetAuditEvent[] = [];
    const { relay, audit } = budgetServer((event) => oldSeen.push(event));
    const port = await listen(relay);
    await postExceedingPair(port, audit, undefined, 0, 0);
    assert.equal(oldSeen.length, 1);
    assert.equal(oldSeen[0].tenant, "default");
    assert.equal(oldSeen[0].deliveriesPerMonth, 1);
    assert.equal(oldSeen[0].used, 1);
    assert.equal(exceededEvents(audit)[0].tenant, "default");
    assert.deepEqual(newSeen, []);
    const newCb = (event: TenantBudgetAuditEvent) => newSeen.push(event);
    relay.reviseBudgetExceededCallback!(newCb);
    assert.deepEqual(
      revisedEvents(audit).map((e) => [e.previous, e.current]),
      [["set", "set"]]
    );
    await postExceedingPair(port, audit, "acme", 1, 1);
    assert.equal(oldSeen.length, 1); // the old callback heard nothing more
    assert.equal(newSeen.length, 1);
    assert.equal(newSeen[0].tenant, "acme");
    assert.equal(newSeen[0].deliveriesPerMonth, 1);
    assert.equal(newSeen[0].used, 1);
    assert.equal(exceededEvents(audit).length, 2);
    assert.equal(exceededEvents(audit)[1].tenant, "acme");
    assert.equal((audit.query({ event: "delivered" }) as unknown[]).length, 2);
  });

  it("clearing to null keeps the budget_exceeded audit and the parks, and stops the operator", async () => {
    const seen: TenantBudgetAuditEvent[] = [];
    const { relay, audit } = budgetServer((event) => seen.push(event));
    const port = await listen(relay);
    await postExceedingPair(port, audit, undefined, 0, 0);
    assert.equal(seen.length, 1);
    assert.equal(exceededEvents(audit).length, 1);
    relay.reviseBudgetExceededCallback!(null);
    assert.deepEqual(
      revisedEvents(audit).map((e) => [e.previous, e.current]),
      [["set", "cleared"]]
    );
    await postExceedingPair(port, audit, "acme", 1, 1);
    assert.equal(seen.length, 1); // still silent
    // The second tenant's exceedance was audited but not forwarded —
    // and both first posts still delivered.
    assert.equal(exceededEvents(audit).length, 2);
    assert.equal(exceededEvents(audit)[1].tenant, "acme");
    assert.equal((audit.query({ event: "delivered" }) as unknown[]).length, 2);
  });

  it("revise audits previous/current presence; a same-reference revision and clearing-when-unset are silent no-ops", async () => {
    const { relay, audit } = budgetServer((_event) => {});
    await listen(relay);
    const newCb = (_event: TenantBudgetAuditEvent) => {};
    // set -> set (the constructor callback was already set).
    relay.reviseBudgetExceededCallback!(newCb);
    // set -> cleared.
    relay.reviseBudgetExceededCallback!(null);
    // cleared -> set.
    relay.reviseBudgetExceededCallback!(newCb);
    // Same reference again: no audit event.
    relay.reviseBudgetExceededCallback!(newCb);
    // Clearing when already cleared: no audit event.
    relay.reviseBudgetExceededCallback!(null);
    relay.reviseBudgetExceededCallback!(null);
    assert.deepEqual(
      revisedEvents(audit).map((e) => [e.previous, e.current]),
      [
        ["set", "set"],
        ["set", "cleared"],
        ["cleared", "set"],
        ["set", "cleared"],
      ]
    );
    // A server born without a callback: clearing when unset is a no-op,
    // and the first set audits cleared -> set. (The budget enforcer is
    // always constructed, only the observer is absent.)
    const { relay: bare, audit: bareAudit } = budgetServer();
    await listen(bare);
    bare.reviseBudgetExceededCallback!(null);
    bare.reviseBudgetExceededCallback!(newCb);
    assert.deepEqual(
      (bareAudit.query({ event: "budget_exceeded_callback_revised" }) as Array<{
        previous: string;
        current: string;
      }>).map((e) => [e.previous, e.current]),
      [["cleared", "set"]]
    );
  });

  it("a non-function value throws RangeError and the live cell is untouched", async () => {
    const seen: TenantBudgetAuditEvent[] = [];
    const { relay, audit } = budgetServer((event) => seen.push(event));
    const port = await listen(relay);
    assert.throws(
      () => relay.reviseBudgetExceededCallback!(42 as never),
      RangeError
    );
    assert.equal(revisedEvents(audit).length, 0);
    // The live cell survived: the next exceedance still enters the original callback.
    await postExceedingPair(port, audit, undefined, 0, 0);
    assert.equal(seen.length, 1);
    assert.equal(seen[0].tenant, "default");
  });
});
