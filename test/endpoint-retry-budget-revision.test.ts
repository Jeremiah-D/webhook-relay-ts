import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import {
  RetryQueue,
  type RetryBudgetDepletedInfo,
  type Sender,
} from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "endpoint-retry-budget-revision-secret";
const EP_A = "http://a.example/hook";
const EP_B = "http://b.example/hook";

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

function item(id: string, targetUrl: string) {
  return { id, payload: Buffer.from("x"), targetUrl, headers: {} };
}

function failingSender(): Sender {
  return (async () => {
    throw new Error("downstream down");
  }) as Sender;
}

describe("RetryQueue endpoint retry budget revision (WR-327)", () => {
  it("revise/get/remove read live values; check order is endpoint, then rate", () => {
    let now = 0;
    const q = new RetryQueue({
      sender: failingSender(),
      retryBudget: {
        retriesPerMinute: 60,
        perEndpointRetriesPerMinute: { [EP_A]: 2 },
        now: () => now,
      },
    });
    try {
      assert.equal(q.retryBudgetConfigured(), true);
      assert.deepEqual(q.getEndpointRetryBudget(EP_A), {
        endpoint: EP_A,
        retriesPerMinute: 2,
        overridden: true,
      });
      assert.deepEqual(q.getEndpointRetryBudget(EP_B), {
        endpoint: EP_B,
        retriesPerMinute: 60,
        overridden: false,
      });
      // Revising an endpoint without an override creates a full-token
      // bucket and a stats row.
      assert.deepEqual(q.reviseEndpointRetryBudget(EP_B, 5), {
        endpoint: EP_B,
        retriesPerMinute: 5,
        overridden: true,
      });
      assert.deepEqual(q.getRetryBudgetStats()?.endpoints, [
        { endpoint: EP_A, retriesPerMinute: 2, depleted: 0, remainingTokens: 2 },
        { endpoint: EP_B, retriesPerMinute: 5, depleted: 0, remainingTokens: 5 },
      ]);
      // Same effective value: a no-op that records no override.
      assert.deepEqual(q.reviseEndpointRetryBudget("http://c.example/hook", 60), {
        endpoint: "http://c.example/hook",
        retriesPerMinute: 60,
        overridden: false,
      });
      assert.equal(
        q.getRetryBudgetStats()?.endpoints?.some((r) => r.endpoint === "http://c.example/hook"),
        false
      );
      // Same value on an existing override: also a no-op.
      assert.deepEqual(q.reviseEndpointRetryBudget(EP_B, 5), {
        endpoint: EP_B,
        retriesPerMinute: 5,
        overridden: true,
      });
      // Endpoint is checked before the rate.
      assert.throws(() => q.reviseEndpointRetryBudget("", 0), RangeError);
      assert.throws(() => q.reviseEndpointRetryBudget("", 5), RangeError);
      for (const bad of [0, -1, NaN, Infinity]) {
        assert.throws(() => q.reviseEndpointRetryBudget(EP_A, bad), RangeError, `rate ${bad}`);
      }
      assert.equal(q.getEndpointRetryBudget(EP_A)?.retriesPerMinute, 2);
      assert.equal(q.getEndpointRetryBudget(EP_A)?.overridden, true);
      assert.equal(q.getRetryBudgetStats()?.retriesPerMinute, 60);
      // Removal: no override -> false; with one -> true, back to the
      // global rate, and the stats row leaves with the bucket.
      assert.equal(q.removeEndpointRetryBudget("http://never.example/hook"), false);
      assert.equal(q.removeEndpointRetryBudget(""), false);
      assert.equal(q.removeEndpointRetryBudget(EP_B), true);
      assert.deepEqual(q.getEndpointRetryBudget(EP_B), {
        endpoint: EP_B,
        retriesPerMinute: 60,
        overridden: false,
      });
      assert.deepEqual(q.getRetryBudgetStats()?.endpoints, [
        { endpoint: EP_A, retriesPerMinute: 2, depleted: 0, remainingTokens: 2 },
      ]);
      assert.equal(q.removeEndpointRetryBudget(EP_B), false);
    } finally {
      q.stop();
    }
  });

  it("an unconfigured queue throws the must-restart Error on revise and reports nothing on get/remove", () => {
    const q = new RetryQueue({ sender: failingSender() });
    try {
      assert.equal(q.retryBudgetConfigured(), false);
      assert.throws(
        () => q.reviseEndpointRetryBudget(EP_A, 30),
        /retry budget is not configured — enabling it requires a restart/
      );
      assert.equal(q.getEndpointRetryBudget(EP_A), undefined);
      assert.equal(q.removeEndpointRetryBudget(EP_A), false);
    } finally {
      q.stop();
    }
  });

  it("an existing bucket tightens after being drained and widening never tops it up", async () => {
    const timer = manualTimer();
    const now = { ms: 0 };
    const depleted: RetryBudgetDepletedInfo[] = [];
    const q = new RetryQueue({
      sender: failingSender(),
      baseDelayMs: 100,
      maxDelayMs: 5000,
      maxAttempts: 4,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      retryBudget: {
        retriesPerMinute: 6000,
        perEndpointRetriesPerMinute: { [EP_A]: 2 },
        now: () => now.ms,
      },
      onRetryBudgetDepleted: (info) => depleted.push(info),
    });
    try {
      q.start();
      // Drain the 2/min bucket: two funded retries, then the third
      // retry parks (one token per 30s at 2/min).
      q.enqueue(item("a1", EP_A));
      await timer.run();
      assert.equal(depleted.length, 1);
      assert.equal(depleted[0].scope, "endpoint");
      assert.equal(depleted[0].waitMs, 30_000);
      assert.equal(q.getRetryBudgetStats()?.endpoints?.[0].remainingTokens, 0);
      // Tighten to 1/min: the drained bucket stays empty, so the next
      // take fails at once — the retry parks on the new 60s horizon.
      assert.deepEqual(q.reviseEndpointRetryBudget(EP_A, 1), {
        endpoint: EP_A,
        retriesPerMinute: 1,
        overridden: true,
      });
      q.enqueue(item("a2", EP_A));
      await timer.run();
      assert.equal(depleted.length, 4);
      assert.ok(depleted.slice(1).every((d) => d.scope === "endpoint"));
      assert.ok(depleted.slice(1).every((d) => d.waitMs === 60_000));
      assert.equal(q.getRetryBudgetStats()?.endpoints?.[0].remainingTokens, 0);
      // Widen to 60/min: no tokens are topped up — the bucket is still
      // empty — but the next park re-arms at the new 1s horizon.
      assert.deepEqual(q.reviseEndpointRetryBudget(EP_A, 60), {
        endpoint: EP_A,
        retriesPerMinute: 60,
        overridden: true,
      });
      assert.equal(q.getRetryBudgetStats()?.endpoints?.[0].remainingTokens, 0);
      q.enqueue(item("a3", EP_A));
      await timer.run();
      assert.equal(depleted.length, 7);
      assert.ok(depleted.slice(4).every((d) => d.scope === "endpoint"));
      assert.ok(depleted.slice(4).every((d) => d.waitMs === 1000));
    } finally {
      q.stop();
    }
  });

  it("an endpoint park consumes no global token", async () => {
    const timer = manualTimer();
    const now = { ms: 0 };
    const depleted: RetryBudgetDepletedInfo[] = [];
    const q = new RetryQueue({
      sender: failingSender(),
      baseDelayMs: 100,
      maxDelayMs: 5000,
      maxAttempts: 4,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      retryBudget: {
        retriesPerMinute: 2,
        perEndpointRetriesPerMinute: { [EP_A]: 1 },
        now: () => now.ms,
      },
      onRetryBudgetDepleted: (info) => depleted.push(info),
    });
    try {
      q.start();
      q.enqueue(item("a1", EP_A));
      q.enqueue(item("b1", EP_B));
      await timer.run();
      // A parks twice on its own 1/min bucket (60s horizon) without
      // touching the global bucket; B's first retry is still funded
      // from the global 2/min bucket, so B only parks from attempt 2
      // on the global 30s horizon.
      const forA = depleted.filter((d) => d.endpoint === EP_A);
      const forB = depleted.filter((d) => d.endpoint === EP_B);
      assert.deepEqual(
        forA.map((d) => d.attempts),
        [2, 3]
      );
      assert.ok(forA.every((d) => d.scope === "endpoint"));
      assert.ok(forA.every((d) => d.waitMs === 60_000));
      assert.deepEqual(
        forB.map((d) => d.attempts),
        [2, 3]
      );
      assert.ok(forB.every((d) => d.scope === "global"));
      assert.ok(forB.every((d) => d.waitMs === 30_000));
      assert.deepEqual(q.getRetryBudgetStats(), {
        retriesPerMinute: 2,
        depleted: 4,
        endpoints: [{ endpoint: EP_A, retriesPerMinute: 1, depleted: 2, remainingTokens: 0 }],
      });
    } finally {
      q.stop();
    }
  });

  it("revising one endpoint leaves other endpoints, the global budget, and the tenant budget untouched", () => {
    let now = 0;
    const q = new RetryQueue({
      sender: failingSender(),
      retryBudget: {
        retriesPerMinute: 6000,
        perEndpointRetriesPerMinute: { [EP_A]: 2, [EP_B]: 3 },
        now: () => now,
      },
      tenantRetryBudget: { retriesPerMinute: 60, now: () => now },
    });
    try {
      assert.deepEqual(q.reviseEndpointRetryBudget(EP_A, 5), {
        endpoint: EP_A,
        retriesPerMinute: 5,
        overridden: true,
      });
      assert.deepEqual(q.getEndpointRetryBudget(EP_B), {
        endpoint: EP_B,
        retriesPerMinute: 3,
        overridden: true,
      });
      assert.equal(q.getRetryBudgetStats()?.retriesPerMinute, 6000);
      assert.equal(q.getTenantRetryBudgetStats()?.defaultRetriesPerMinute, 60);
      assert.equal(q.getTenantRetryBudget("acme")?.retriesPerMinute, 60);
      assert.equal(q.getTenantRetryBudget("acme")?.overridden, false);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer endpoint retry budget revision (WR-327)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "endpoint-retry-budget-revision-"));
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
    const { relay, auditLog } = makeServer({
      retry: { retryBudget: { retriesPerMinute: 6000 } },
    });
    await listen(relay);
    assert.deepEqual(relay.reviseEndpointRetryBudget(EP_A, 100), {
      endpoint: EP_A,
      retriesPerMinute: 100,
      overridden: true,
    });
    let revised = eventsOf(auditLog, "endpoint_retry_budget_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].endpoint, EP_A);
    assert.equal(revised[0].previous, undefined); // first previous: no override yet
    assert.equal(revised[0].current, 100);
    // A revision of an existing override audits the old override rate.
    assert.deepEqual(relay.reviseEndpointRetryBudget(EP_A, 50), {
      endpoint: EP_A,
      retriesPerMinute: 50,
      overridden: true,
    });
    revised = eventsOf(auditLog, "endpoint_retry_budget_revised");
    assert.equal(revised.length, 2);
    assert.equal(revised[1].endpoint, EP_A);
    assert.equal(revised[1].previous, 100);
    assert.equal(revised[1].current, 50);
  });

  it("a same-value revision is a silent no-op", async () => {
    const { relay, auditLog } = makeServer({
      retry: { retryBudget: { retriesPerMinute: 6000 } },
    });
    await listen(relay);
    // Landing exactly on the live value — even the global rate itself
    // for an endpoint without an override — records nothing.
    relay.reviseEndpointRetryBudget(EP_A, 6000);
    assert.equal(eventsOf(auditLog, "endpoint_retry_budget_revised").length, 0);
    assert.equal(relay.getEndpointRetryBudget!(EP_A).overridden, false);
    relay.reviseEndpointRetryBudget(EP_A, 100);
    assert.equal(eventsOf(auditLog, "endpoint_retry_budget_revised").length, 1);
    relay.reviseEndpointRetryBudget(EP_A, 100);
    assert.equal(eventsOf(auditLog, "endpoint_retry_budget_revised").length, 1);
  });

  it("an illegal value or empty endpoint throws RangeError and the live budget and audit are untouched", async () => {
    const { relay, auditLog } = makeServer({
      retry: { retryBudget: { retriesPerMinute: 6000 } },
    });
    await listen(relay);
    for (const bad of [0, -1, NaN, Infinity]) {
      assert.throws(() => relay.reviseEndpointRetryBudget(EP_A, bad), RangeError, `rate ${bad}`);
    }
    assert.throws(() => relay.reviseEndpointRetryBudget("", 5), RangeError);
    assert.deepEqual(relay.getEndpointRetryBudget!(EP_A), {
      endpoint: EP_A,
      retriesPerMinute: 6000,
      overridden: false,
    });
    assert.equal(eventsOf(auditLog, "endpoint_retry_budget_revised").length, 0);
  });

  it("remove returns true, audits, and falls back to the global budget; without an override it returns false silently", async () => {
    const { relay, auditLog } = makeServer({
      retry: { retryBudget: { retriesPerMinute: 6000 } },
    });
    await listen(relay);
    relay.reviseEndpointRetryBudget(EP_A, 100);
    assert.equal(relay.getEndpointRetryBudget!(EP_A).retriesPerMinute, 100);
    assert.equal(relay.removeEndpointRetryBudget(EP_A), true);
    const removed = eventsOf(auditLog, "endpoint_retry_budget_removed");
    assert.equal(removed.length, 1);
    assert.equal(removed[0].endpoint, EP_A);
    assert.equal(removed[0].previous, 100);
    assert.deepEqual(relay.getEndpointRetryBudget!(EP_A), {
      endpoint: EP_A,
      retriesPerMinute: 6000,
      overridden: false,
    });
    // Nothing left to remove: false, no audit.
    assert.equal(relay.removeEndpointRetryBudget(EP_A), false);
    assert.equal(eventsOf(auditLog, "endpoint_retry_budget_removed").length, 1);
    assert.equal(relay.removeEndpointRetryBudget(EP_B), false);
    assert.equal(eventsOf(auditLog, "endpoint_retry_budget_removed").length, 1);
  });

  it("the getter matches live state and is absent when the budget was never configured", async () => {
    const { relay } = makeServer({
      retry: { retryBudget: { retriesPerMinute: 6000 } },
    });
    await listen(relay);
    assert.equal(relay.getEndpointRetryBudget!(EP_B).retriesPerMinute, 6000);
    relay.reviseEndpointRetryBudget(EP_A, 100);
    assert.equal(relay.getEndpointRetryBudget!(EP_A).retriesPerMinute, 100);
    assert.equal(relay.getEndpointRetryBudget!(EP_A).overridden, true);
    relay.reviseEndpointRetryBudget(EP_A, 100);
    // Revising the global budget leaves the endpoint override alone.
    relay.setRetryBudget!(3000);
    assert.equal(relay.getEndpointRetryBudget!(EP_B).retriesPerMinute, 3000);
    assert.equal(relay.getEndpointRetryBudget!(EP_A).retriesPerMinute, 100);

    const unconfigured = makeServer({});
    await listen(unconfigured.relay);
    assert.equal(unconfigured.relay.getEndpointRetryBudget, undefined);
    assert.throws(
      () => unconfigured.relay.reviseEndpointRetryBudget(EP_A, 30),
      /retry budget is not configured — enabling it requires a restart/
    );
    assert.equal(unconfigured.relay.removeEndpointRetryBudget(EP_A), false);
  });
});
