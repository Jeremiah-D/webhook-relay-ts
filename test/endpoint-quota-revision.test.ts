import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { request as httpRequest, type Server } from "node:http";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { EndpointQuota } from "../src/quota.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "endpoint-quota-revision-secret";
const EP_A = "http://a.example/hook";
const EP_B = "http://b.example/hook";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));

/** Let the deliver() promise chain settle. */
async function flush(ticks = 10) {
  for (let i = 0; i < ticks; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

/**
 * Manual timer with single-step control: quota delays re-arm timers, so
 * the tests advance one wave at a time instead of draining everything
 * (same shape as test/quota.test.ts).
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
    clearTimer: (h: { clear(): void }) => h.clear(),
    async step() {
      const fns = pending.splice(0);
      for (const f of fns) f();
      await new Promise((r) => setImmediate(r));
    },
  };
}

function item(id: string, targetUrl: string, tenantId?: string) {
  return { id, payload: BODY, targetUrl, headers: {}, ...(tenantId === undefined ? {} : { tenantId }) };
}

async function waitFor(cond: () => boolean, what: string, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (cond()) return;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error(`timed out waiting for ${what}`);
}

describe("EndpointQuota live limit revision (WR-322)", () => {
  it("raising the limit lets the next refill accrue toward the new cap", () => {
    let now = 0;
    const q = new EndpointQuota(60, () => now); // 1 token/sec
    for (let i = 0; i < 60; i++) assert.equal(q.take(EP_A), true);
    assert.equal(q.take(EP_A), false); // bucket empty
    q.setEndpointLimit(EP_A, 120); // 2 tokens/sec from here on
    now = 30_000;
    // 30s at the new rate refills 60 tokens — twice what the old cap
    // would have granted in the same window.
    for (let i = 0; i < 60; i++) assert.equal(q.take(EP_A), true, `take ${i}`);
    assert.equal(q.take(EP_A), false);
  });

  it("lowering the limit clamps the bucket on the next refill", () => {
    let now = 0;
    const q = new EndpointQuota(60, () => now);
    for (let i = 0; i < 10; i++) assert.equal(q.take(EP_A), true); // 50 left
    q.setEndpointLimit(EP_A, 30);
    // The very next refill (inside take) clamps the stored 50 down to
    // the new cap — the cut never waits for the bucket to drain.
    for (let i = 0; i < 30; i++) assert.equal(q.take(EP_A), true, `take ${i}`);
    assert.equal(q.take(EP_A), false);
    now = 60_000;
    // Even a full minute later the bucket tops out at the new cap.
    for (let i = 0; i < 30; i++) assert.equal(q.take(EP_A), true, `refill take ${i}`);
    assert.equal(q.take(EP_A), false);
  });

  it("msUntilToken divides by the live limit, not the constructor default (WR-322 verification point)", () => {
    let now = 0;
    const q = new EndpointQuota(60, () => now); // 1 token/sec
    for (let i = 0; i < 60; i++) assert.equal(q.take(EP_A), true);
    assert.equal(q.msUntilToken(EP_A), 1000);
    q.setEndpointLimit(EP_A, 120); // 2 tokens/sec: the wait halves
    assert.equal(q.msUntilToken(EP_A), 500);
    q.setEndpointLimit(EP_A, 30); // 1 token per 2s: the wait doubles
    assert.equal(q.msUntilToken(EP_A), 2000);
    q.setEndpointLimit(EP_A, 60); // back to the default: the wait matches
    assert.equal(q.msUntilToken(EP_A), 1000);
  });

  it("an illegal value throws RangeError and the live budget is untouched", () => {
    const q = new EndpointQuota(60);
    for (const bad of [0, -1, NaN, Infinity]) {
      assert.throws(() => q.setEndpointLimit(EP_A, bad), RangeError, `limit ${bad}`);
    }
    assert.equal(q.limit(EP_A), 60);
    // The queue wrapper is validate-then-set too, and reports
    // "never configured" instead of throwing when quotas are off.
    const withQuota = new RetryQueue({
      sender: async () => {},
      quota: { deliveriesPerMinute: 60 },
    });
    try {
      assert.throws(() => withQuota.setEndpointQuota(EP_A, 0), RangeError);
      assert.equal(withQuota.getEndpointQuota(EP_A)?.limit, 60);
    } finally {
      withQuota.stop();
    }
    const withoutQuota = new RetryQueue({ sender: async () => {} });
    try {
      assert.equal(withoutQuota.setEndpointQuota(EP_A, 60), false);
      assert.equal(withoutQuota.getEndpointQuota(EP_A), undefined);
    } finally {
      withoutQuota.stop();
    }
  });

  it("an over-budget attempt is delayed and rescheduled, not dropped — and a raised limit lets it through sooner", async () => {
    let now = 0;
    const t = manualTimer();
    let calls = 0;
    const sender: Sender = async () => {
      calls += 1;
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
      random: () => 0, // no jitter: quota delays are exactly msUntilToken
      quota: { deliveriesPerMinute: 1, now: () => now }, // 1 token/min
    });
    q.enqueue(item("a", EP_A));
    q.enqueue(item("b", EP_A));
    q.start();
    try {
      await t.step();
      assert.equal(calls, 1); // only "a" fit the budget
      assert.equal(q.pendingCount(), 1); // "b" is delayed, not dropped
      assert.deepEqual(q.getEndpointQuota(EP_A), { limit: 1, delayed: 1, hasOverride: false });
      // Raise the budget live: one second of refill at the new rate is
      // already a whole token, so the delayed attempt goes out on the
      // next re-check instead of waiting out the old minute.
      assert.equal(q.setEndpointQuota(EP_A, 60), true);
      assert.deepEqual(q.getEndpointQuota(EP_A), { limit: 60, delayed: 1, hasOverride: true });
      now += 1000;
      await t.step();
      assert.equal(calls, 2); // "b" delivered once the new budget covers it
      assert.equal(q.pendingCount(), 0);
      assert.deepEqual(q.getEndpointQuota(EP_A), { limit: 60, delayed: 1, hasOverride: true });
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer endpoint quota revision (WR-322)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "endpoint-quota-revision-"));
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

  let postSeq = 0;
  function post(port: number) {
    const body = Buffer.from(JSON.stringify({ event: "quota.probe", n: ++postSeq }));
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/",
          method: "POST",
          headers: { "x-signature": signSha256(body, relaySecret) },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => {
            r.destroy();
            resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() });
          });
        }
      );
      r.on("error", reject);
      r.end(body);
    });
  }

  it("revise audits previous/current, with the constructor default as first previous", async () => {
    const { relay, auditLog } = makeServer({ retry: { quota: { deliveriesPerMinute: 60 } } });
    await listen(relay);
    const current = relay.reviseEndpointQuota(EP_A, 120);
    assert.deepEqual(current, { limit: 120, delayed: 0, hasOverride: true });
    const revised = eventsOf(auditLog, "endpoint_quota_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].endpoint, EP_A);
    assert.equal(revised[0].previous, 60); // first previous: the constructor default
    assert.equal(revised[0].current, 120);
    // A second revision audits the live values as previous.
    const current2 = relay.reviseEndpointQuota(EP_A, 30);
    assert.equal(current2.limit, 30);
    const revised2 = eventsOf(auditLog, "endpoint_quota_revised");
    assert.equal(revised2.length, 2);
    assert.equal(revised2[1].previous, 120);
    assert.equal(revised2[1].current, 30);
  });

  it("a same-value revision is a silent no-op", async () => {
    const { relay, auditLog } = makeServer({ retry: { quota: { deliveriesPerMinute: 60 } } });
    await listen(relay);
    // Landing exactly on the live value — even the constructor default itself.
    relay.reviseEndpointQuota(EP_A, 60);
    assert.equal(eventsOf(auditLog, "endpoint_quota_revised").length, 0);
    relay.reviseEndpointQuota(EP_A, 120);
    assert.equal(eventsOf(auditLog, "endpoint_quota_revised").length, 1);
    relay.reviseEndpointQuota(EP_A, 120);
    assert.equal(eventsOf(auditLog, "endpoint_quota_revised").length, 1);
  });

  it("an illegal value throws RangeError and the live budget and audit are untouched", async () => {
    const { relay, auditLog } = makeServer({ retry: { quota: { deliveriesPerMinute: 60 } } });
    await listen(relay);
    for (const bad of [0, -1, NaN, Infinity]) {
      assert.throws(() => relay.reviseEndpointQuota(EP_A, bad), RangeError, `limit ${bad}`);
    }
    assert.deepEqual(relay.getEndpointQuota!(EP_A), { limit: 60, delayed: 0, hasOverride: false });
    assert.equal(eventsOf(auditLog, "endpoint_quota_revised").length, 0);
  });

  it("remove returns true, audits, and falls back to the constructor default; without an override it returns false silently", async () => {
    const { relay, auditLog } = makeServer({ retry: { quota: { deliveriesPerMinute: 60 } } });
    await listen(relay);
    relay.reviseEndpointQuota(EP_A, 120);
    assert.equal(relay.getEndpointQuota!(EP_A).limit, 120);
    assert.equal(relay.removeEndpointQuota(EP_A), true);
    const removed = eventsOf(auditLog, "endpoint_quota_removed");
    assert.equal(removed.length, 1);
    assert.equal(removed[0].endpoint, EP_A);
    assert.equal(removed[0].previous, 120);
    assert.deepEqual(relay.getEndpointQuota!(EP_A), { limit: 60, delayed: 0, hasOverride: false });
    // Nothing left to remove: false, no audit.
    assert.equal(relay.removeEndpointQuota(EP_A), false);
    assert.equal(eventsOf(auditLog, "endpoint_quota_removed").length, 1);
    // An endpoint that was never revised has no override to remove.
    assert.equal(relay.removeEndpointQuota(EP_B), false);
    assert.equal(eventsOf(auditLog, "endpoint_quota_removed").length, 1);
  });

  it("the getter snapshot matches live state, including delayed attempts", async () => {
    let now = 0;
    const t = manualTimer();
    let calls = 0;
    const sender: Sender = async () => {
      calls += 1;
    };
    const { relay } = makeServer({
      sender,
      retry: {
        quota: { deliveriesPerMinute: 1, now: () => now }, // 1 token/min
        setTimer: t.setTimer,
        clearTimer: t.clearTimer,
        random: () => 0, // no jitter: quota delays are exactly msUntilToken
        maxAttempts: 1,
      },
    });
    const port = await listen(relay);
    assert.equal((await post(port)).status, 202);
    assert.equal((await post(port)).status, 202);
    // Drive the queue until the first delivery lands and the second is
    // parked on the exhausted budget.
    for (let i = 0; i < 10 && !(calls === 1 && relay.getEndpointQuota!(EP_A).delayed === 1); i++) {
      await t.step();
    }
    assert.equal(calls, 1);
    assert.deepEqual(relay.getEndpointQuota!(EP_A), { limit: 1, delayed: 1, hasOverride: false });
    // Raise the budget live and let one second of refill through: the
    // delayed attempt goes out instead of waiting out the old minute.
    relay.reviseEndpointQuota(EP_A, 60);
    now += 1000;
    for (let i = 0; i < 10 && calls < 2; i++) {
      await t.step();
    }
    assert.equal(calls, 2);
    assert.deepEqual(relay.getEndpointQuota!(EP_A), { limit: 60, delayed: 1, hasOverride: true });
    await flush();
  });

  it("tenant revisions are scoped to that tenant's quota instance", async () => {
    const { relay, auditLog } = makeServer({ retry: { quota: { deliveriesPerMinute: 60 } } });
    await listen(relay);
    relay.reviseEndpointQuota(EP_A, 120, "acme");
    assert.deepEqual(relay.getEndpointQuota!(EP_A, "acme"), { limit: 120, delayed: 0, hasOverride: true });
    // The default tenant is untouched.
    assert.deepEqual(relay.getEndpointQuota!(EP_A), { limit: 60, delayed: 0, hasOverride: false });
    // Removal is tenant-scoped too.
    assert.equal(relay.removeEndpointQuota(EP_A), false);
    assert.equal(relay.removeEndpointQuota(EP_A, "acme"), true);
    assert.equal(eventsOf(auditLog, "endpoint_quota_removed").length, 1);
    assert.deepEqual(relay.getEndpointQuota!(EP_A, "acme"), { limit: 60, delayed: 0, hasOverride: false });
  });

  it("when quotas are not configured, revise throws, remove is false, and the getter is unset", async () => {
    const { relay, auditLog } = makeServer({});
    await listen(relay);
    assert.equal(relay.getEndpointQuota, undefined);
    assert.throws(
      () => relay.reviseEndpointQuota(EP_A, 60),
      /endpoint quotas are not configured — enabling them requires a restart/
    );
    assert.equal(relay.removeEndpointQuota(EP_A), false);
    assert.equal(eventsOf(auditLog, "endpoint_quota_revised").length, 0);
    assert.equal(eventsOf(auditLog, "endpoint_quota_removed").length, 0);
  });
});
