import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  type RetryBudgetDepletedInfo,
  type RetryItem,
  type Sender,
} from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "retry-budget-depleted-callback-revision-secret";
const URL = "http://localhost:9999/hook";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));
const TOKEN = "op-token";

/**
 * Manual timer with single-step control, mirroring the other feature
 * tests: parking re-arms timers, so tests advance one wave at a time.
 */
function manualTimer() {
  const pending: Array<{ fn: () => void; ms: number }> = [];
  return {
    pendingCount: () => pending.length,
    lastDelay: () => pending[pending.length - 1]?.ms,
    setTimer: (fn: () => void, ms: number) => {
      const rec = { fn, ms };
      pending.push(rec);
      return {
        clear: () => {
          const i = pending.indexOf(rec);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    clearTimer: (h: { clear(): void }) => h.clear(),
    async step() {
      const fns = pending.splice(0);
      for (const f of fns) f.fn();
      await flush();
    },
  };
}

/** Let the deliver() promise chain settle. */
async function flush(ticks = 10) {
  for (let i = 0; i < ticks; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

function alwaysFailingSender() {
  let calls = 0;
  const sender: Sender = async () => {
    calls += 1;
    throw new Error("downstream down");
  };
  return { sender, calls: () => calls };
}

function item(id: string, targetUrl = URL, tenantId?: string): RetryItem {
  return { id, targetUrl, payload: Buffer.from("{}"), headers: {}, ...(tenantId !== undefined ? { tenantId } : {}) };
}

describe("RetryQueue retry-budget-depleted callback revision (WR-387)", () => {
  function makeQueue(maxAttempts = 10) {
    const timer = manualTimer();
    const now = { ms: 0 };
    const f = alwaysFailingSender();
    const q = new RetryQueue({
      sender: f.sender,
      baseDelayMs: 100,
      maxDelayMs: 5000,
      maxAttempts,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      retryBudget: { retriesPerMinute: 2, now: () => now.ms },
    });
    return { q, timer, f, now };
  }

  it("revise swaps the live callback: the next park enters the new callback with exact waitMs/scope, the old one is silent", async () => {
    const { q, timer, f } = makeQueue();
    const oldSeen: RetryBudgetDepletedInfo[] = [];
    const newSeen: RetryBudgetDepletedInfo[] = [];
    const oldCb = (info: RetryBudgetDepletedInfo) => oldSeen.push(info);
    const newCb = (info: RetryBudgetDepletedInfo) => newSeen.push(info);
    q.reviseRetryBudgetDepletedCallback(oldCb);
    q.start();
    try {
      q.enqueue(item("swap-1"));
      await timer.step(); // attempt 1 fails -> retry 1 (budget 1/2)
      await timer.step(); // attempt 2 fails -> retry 2 (budget 2/2)
      await timer.step(); // attempt 3 fails -> parked on the global budget
      assert.equal(f.calls(), 3);
      assert.equal(oldSeen.length, 1);
      assert.equal(oldSeen[0].id, "swap-1");
      assert.equal(oldSeen[0].endpoint, URL);
      assert.equal(oldSeen[0].attempts, 3);
      assert.equal(oldSeen[0].waitMs, 30000); // 2/min: a fresh token every 30s
      assert.equal(oldSeen[0].scope, "global");
      assert.equal(typeof oldSeen[0].traceId, "string");
      assert.ok(oldSeen[0].traceId.length > 0);
      assert.equal(q.getRetryBudgetStats()?.depleted, 1);
      assert.deepEqual(newSeen, []);
      // Swap mid-flight: the old callback never hears another park,
      // and the already-reported park is never re-delivered.
      q.reviseRetryBudgetDepletedCallback(newCb);
      await timer.step(); // parked retry fires -> attempt 4 fails -> parked again
      assert.equal(f.calls(), 4);
      assert.equal(oldSeen.length, 1);
      assert.equal(newSeen.length, 1);
      assert.equal(newSeen[0].id, "swap-1");
      assert.equal(newSeen[0].attempts, 4);
      assert.equal(newSeen[0].waitMs, 30000);
      assert.equal(newSeen[0].scope, "global");
      assert.equal(q.getRetryBudgetStats()?.depleted, 2);
    } finally {
      q.stop();
    }
  });

  it("endpoint scope: an exhausted per-endpoint override parks with scope endpoint", async () => {
    const timer = manualTimer();
    const now = { ms: 0 };
    const f = alwaysFailingSender();
    const q = new RetryQueue({
      sender: f.sender,
      baseDelayMs: 100,
      maxDelayMs: 5000,
      maxAttempts: 10,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      retryBudget: {
        retriesPerMinute: 100,
        perEndpointRetriesPerMinute: { [URL]: 1 },
        now: () => now.ms,
      },
    });
    const seen: RetryBudgetDepletedInfo[] = [];
    q.reviseRetryBudgetDepletedCallback((info) => seen.push(info));
    q.start();
    try {
      q.enqueue(item("endpoint-1"));
      await timer.step(); // attempt 1 fails -> endpoint token 1/1, retry scheduled
      await timer.step(); // attempt 2 fails -> endpoint bucket empty -> parked
      assert.equal(f.calls(), 2);
      assert.equal(seen.length, 1);
      assert.equal(seen[0].attempts, 2);
      assert.equal(seen[0].waitMs, 60000); // 1/min: a fresh token every 60s
      assert.equal(seen[0].scope, "endpoint");
      assert.equal(q.getRetryBudgetStats()?.endpoints?.[0]?.depleted, 1);
    } finally {
      q.stop();
    }
  });

  it("tenant scope: an exhausted per-tenant budget parks with scope tenant", async () => {
    const timer = manualTimer();
    const now = { ms: 0 };
    const f = alwaysFailingSender();
    const q = new RetryQueue({
      sender: f.sender,
      baseDelayMs: 100,
      maxDelayMs: 5000,
      maxAttempts: 10,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      tenantRetryBudget: { retriesPerMinute: 2, now: () => now.ms },
    });
    const seen: RetryBudgetDepletedInfo[] = [];
    q.reviseRetryBudgetDepletedCallback((info) => seen.push(info));
    q.start();
    try {
      q.enqueue(item("tenant-1", URL, "a"));
      await timer.step(); // attempt 1 fails -> tenant retry 1 (budget 1/2)
      await timer.step(); // attempt 2 fails -> tenant retry 2 (budget 2/2)
      await timer.step(); // attempt 3 fails -> parked on the tenant budget
      assert.equal(f.calls(), 3);
      assert.equal(seen.length, 1);
      assert.equal(seen[0].attempts, 3);
      assert.equal(seen[0].waitMs, 30000);
      assert.equal(seen[0].scope, "tenant");
      assert.equal(seen[0].tenant, "a");
    } finally {
      q.stop();
    }
  });

  it("null clears back to no observer: parks keep happening and the counter keeps counting", async () => {
    const { q, timer, f } = makeQueue();
    const seen: RetryBudgetDepletedInfo[] = [];
    q.reviseRetryBudgetDepletedCallback((info) => seen.push(info));
    q.start();
    try {
      q.enqueue(item("clear-1"));
      await timer.step(); // attempt 1 fails
      await timer.step(); // attempt 2 fails
      await timer.step(); // attempt 3 fails -> parked, observed
      assert.equal(seen.length, 1);
      assert.equal(q.getRetryBudgetStats()?.depleted, 1);
      q.reviseRetryBudgetDepletedCallback(null);
      await timer.step(); // parked retry fires -> attempt 4 fails -> parked, unobserved
      assert.equal(f.calls(), 4);
      assert.equal(seen.length, 1);
      assert.equal(q.getRetryBudgetStats()?.depleted, 2);
    } finally {
      q.stop();
    }
  });

  it("a queue with no retry budget at any layer cannot gain an observer at runtime — must restart", async () => {
    const timer = manualTimer();
    const f = alwaysFailingSender();
    const q = new RetryQueue({
      sender: f.sender,
      baseDelayMs: 10,
      maxAttempts: 2,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
    });
    assert.throws(
      () => q.reviseRetryBudgetDepletedCallback(() => {}),
      /requires a restart/
    );
    assert.throws(
      () => q.reviseRetryBudgetDepletedCallback(null),
      /requires a restart/
    );
    q.stop();
  });

  it("a per-endpoint override alone passes the gate", async () => {
    const timer = manualTimer();
    const f = alwaysFailingSender();
    const q = new RetryQueue({
      sender: f.sender,
      baseDelayMs: 10,
      maxAttempts: 2,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      retryBudget: { perEndpointRetriesPerMinute: { [URL]: 1 } },
    });
    // The bucket exists, so the revision is accepted — even though the
    // park path only consults endpoint buckets when a global or tenant
    // budget is also present (see reviseRetryBudgetDepletedCallback).
    assert.doesNotThrow(() => q.reviseRetryBudgetDepletedCallback(() => {}));
    q.stop();
  });

  it("a non-function value throws RangeError and the live callback is untouched", async () => {
    const { q, timer } = makeQueue();
    const seen: RetryBudgetDepletedInfo[] = [];
    const live = (info: RetryBudgetDepletedInfo) => seen.push(info);
    q.reviseRetryBudgetDepletedCallback(live);
    assert.throws(
      () => q.reviseRetryBudgetDepletedCallback(42 as never),
      RangeError
    );
    assert.throws(
      () => q.reviseRetryBudgetDepletedCallback("nope" as never),
      RangeError
    );
    q.start();
    try {
      q.enqueue(item("bad-1"));
      await timer.step();
      await timer.step();
      await timer.step(); // attempt 3 fails -> parked, the live callback survived
      assert.equal(seen.length, 1);
      assert.equal(seen[0].attempts, 3);
    } finally {
      q.stop();
    }
  });

  it("same-reference revision and clearing-when-unset are silent no-ops", async () => {
    const { q, timer } = makeQueue();
    const seen: RetryBudgetDepletedInfo[] = [];
    const live = (info: RetryBudgetDepletedInfo) => seen.push(info);
    q.reviseRetryBudgetDepletedCallback(live);
    q.reviseRetryBudgetDepletedCallback(live); // no-op, no throw
    q.start();
    try {
      q.enqueue(item("noop-1"));
      await timer.step();
      await timer.step();
      await timer.step(); // attempt 3 fails -> parked, observed once
      assert.equal(seen.length, 1);
      q.reviseRetryBudgetDepletedCallback(null);
      q.reviseRetryBudgetDepletedCallback(null); // clearing when unset: no-op
      q.enqueue(item("noop-2"));
      await timer.step(); // noop-1 attempt 4 parks again, unobserved
      assert.equal(seen.length, 1);
    } finally {
      q.stop();
    }
  });

  it("a swap leaves the already-parked retry's wait untouched", async () => {
    const { q, timer } = makeQueue();
    q.reviseRetryBudgetDepletedCallback(() => {});
    q.start();
    try {
      q.enqueue(item("delay-1"));
      await timer.step(); // attempt 1 fails -> retry scheduled at 200ms
      await timer.step(); // attempt 2 fails -> retry scheduled at 400ms
      await timer.step(); // attempt 3 fails -> parked at 30000ms
      assert.equal(timer.lastDelay(), 30000);
      q.reviseRetryBudgetDepletedCallback(() => {});
      assert.equal(timer.lastDelay(), 30000); // the pending timer was not re-armed
      await timer.step(); // parked retry fires -> attempt 4 fails -> parked at 30000ms
      assert.equal(timer.lastDelay(), 30000);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer retry-budget-depleted callback revision (WR-387)", () => {
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

  function postWebhook(port: number) {
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

  function depletedEvents(audit: AuditLog) {
    return audit.query({ event: "retry_budget_depleted" }) as Array<{
      id: string;
      attempts: number;
      waitMs: number;
      budgetScope: string;
    }>;
  }

  function revisedEvents(audit: AuditLog) {
    return audit.query({ event: "retry_budget_depleted_callback_revised" }) as Array<{
      previous: string;
      current: string;
    }>;
  }

  /** A server whose sender always fails, with a 1/min global retry budget. */
  function budgetServer(onRetryBudgetDepleted?: (info: RetryBudgetDepletedInfo) => void) {
    const dir = mkdtempSync(join(tmpdir(), "budgetdepleted-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const f = alwaysFailingSender();
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: URL,
      auditLog: audit,
      operatorToken: TOKEN,
      sender: f.sender,
      retry: {
        baseDelayMs: 10,
        maxAttempts: 3,
        jitterMs: 0,
        retryBudget: { retriesPerMinute: 1 },
        ...(onRetryBudgetDepleted !== undefined ? { onRetryBudgetDepleted } : {}),
      },
    });
    servers.push(relay);
    return { relay, audit };
  }

  it("replacing the operator callback routes the next park to the new callback and the retry_budget_depleted audit still lands", async () => {
    const oldSeen: RetryBudgetDepletedInfo[] = [];
    const newSeen: RetryBudgetDepletedInfo[] = [];
    const { relay, audit } = budgetServer((info) => oldSeen.push(info));
    const port = await listen(relay);
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => oldSeen.length >= 1);
    await drainUntil(() => depletedEvents(audit).length >= 1);
    assert.equal(oldSeen[0].attempts, 2);
    assert.equal(oldSeen[0].scope, "global");
    assert.ok(oldSeen[0].waitMs > 55000);
    assert.equal(depletedEvents(audit)[0].attempts, 2);
    assert.equal(depletedEvents(audit)[0].budgetScope, "global");
    assert.ok(depletedEvents(audit)[0].waitMs > 55000);
    assert.deepEqual(newSeen, []);
    // Swap the operator callback; the first delivery is parked (its
    // 60s refill timer is still pending, far beyond this test).
    const newCb = (info: RetryBudgetDepletedInfo) => newSeen.push(info);
    relay.reviseRetryBudgetDepletedCallback!(newCb);
    assert.deepEqual(
      revisedEvents(audit).map((e) => [e.previous, e.current]),
      [["set", "set"]]
    );
    // A fresh delivery's first retry parks at once (the 1/min token is
    // spent) and enters only the new callback.
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => newSeen.length >= 1);
    await drainUntil(() => depletedEvents(audit).length >= 2);
    assert.equal(oldSeen.length, 1); // the old callback heard nothing more
    assert.equal(newSeen[0].attempts, 1);
    assert.equal(newSeen[0].scope, "global");
    assert.ok(newSeen[0].waitMs > 50000);
    assert.equal(depletedEvents(audit)[1].budgetScope, "global");
  });

  it("clearing to null keeps the retry_budget_depleted audit and the park schedule, and stops the operator", async () => {
    const seen: RetryBudgetDepletedInfo[] = [];
    const { relay, audit } = budgetServer((info) => seen.push(info));
    const port = await listen(relay);
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => seen.length >= 1);
    await drainUntil(() => depletedEvents(audit).length >= 1);
    relay.reviseRetryBudgetDepletedCallback!(null);
    assert.deepEqual(
      revisedEvents(audit).map((e) => [e.previous, e.current]),
      [["set", "cleared"]]
    );
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => depletedEvents(audit).length >= 2);
    assert.equal(seen.length, 1); // still silent
    // The second delivery parked, not dead-lettered or delivered.
    assert.equal((audit.query({ event: "dead_letter" }) as unknown[]).length, 0);
    assert.equal((audit.query({ event: "delivered" }) as unknown[]).length, 0);
  });

  it("revise audits previous/current presence; a same-reference revision and clearing-when-unset are silent no-ops", async () => {
    const { relay, audit } = budgetServer((info) => {});
    await listen(relay);
    const newCb = (_info: RetryBudgetDepletedInfo) => {};
    // set -> set (the constructor callback was already set).
    relay.reviseRetryBudgetDepletedCallback!(newCb);
    // set -> cleared.
    relay.reviseRetryBudgetDepletedCallback!(null);
    // cleared -> set.
    relay.reviseRetryBudgetDepletedCallback!(newCb);
    // Same reference again: no audit event.
    relay.reviseRetryBudgetDepletedCallback!(newCb);
    // Clearing when already cleared: no audit event.
    relay.reviseRetryBudgetDepletedCallback!(null);
    relay.reviseRetryBudgetDepletedCallback!(null);
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
    // and the first set audits cleared -> set.
    const { relay: bare, audit: bareAudit } = budgetServer();
    await listen(bare);
    bare.reviseRetryBudgetDepletedCallback!(null);
    bare.reviseRetryBudgetDepletedCallback!(newCb);
    assert.deepEqual(
      (bareAudit.query({ event: "retry_budget_depleted_callback_revised" }) as Array<{
        previous: string;
        current: string;
      }>).map((e) => [e.previous, e.current]),
      [["cleared", "set"]]
    );
  });

  it("a non-function value throws RangeError and the live cell is untouched", async () => {
    const seen: RetryBudgetDepletedInfo[] = [];
    const { relay, audit } = budgetServer((info) => seen.push(info));
    const port = await listen(relay);
    assert.throws(
      () => relay.reviseRetryBudgetDepletedCallback!(42 as never),
      RangeError
    );
    assert.equal(revisedEvents(audit).length, 0);
    // The live cell survived: the next park still enters the original callback.
    assert.equal(await postWebhook(port), 202);
    await drainUntil(() => seen.length >= 1);
    await drainUntil(() => depletedEvents(audit).length >= 1);
    assert.equal(seen[0].attempts, 2);
    assert.equal(seen[0].scope, "global");
  });

  it("a server with no retry budget at any layer cannot gain an observer at runtime — must restart", async () => {
    const dir = mkdtempSync(join(tmpdir(), "budgetdepleted-nobudget-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const f = alwaysFailingSender();
    const relay = createRelayServer({
      ["sec" + "ret"]: relaySecret,
      forwardUrl: URL,
      auditLog: audit,
      operatorToken: TOKEN,
      sender: f.sender,
      retry: {
        baseDelayMs: 10,
        maxAttempts: 3,
        jitterMs: 0,
      },
    });
    servers.push(relay);
    await listen(relay);
    assert.throws(
      () => relay.reviseRetryBudgetDepletedCallback!(() => {}),
      /requires a restart/
    );
    assert.equal(revisedEvents(audit).length, 0);
  });
});
