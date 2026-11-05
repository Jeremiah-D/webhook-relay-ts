import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TenantRateLimiter } from "../src/tenant-ratelimit.ts";
import { RetryQueue, type DownstreamResponse, type RetryItem, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import { TENANT_ID_HEADER } from "../src/tenant.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "tenant-rate-limit-revision-test-key";
const opToken = "tenant-rate-limit-revision-op-token";
const BODY = Buffer.from(JSON.stringify({ event: "payment.succeeded", id: "evt-1" }));
const TARGET = "https://downstream.example.test/hook";
const OTHER = "https://other.example.test/hook";

const okResponse: DownstreamResponse = { statusCode: 200, body: Buffer.from("ok") };

async function flush(ticks = 10) {
  for (let i = 0; i < ticks; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

async function waitFor(cond: () => boolean, timeoutMs = 5000): Promise<void> {
  const start = Date.now();
  for (;;) {
    if (cond()) return;
    if (Date.now() - start > timeoutMs) throw new Error("waitFor timed out");
    await new Promise((r) => setTimeout(r, 10));
  }
}

function item(id: string, overrides: Partial<RetryItem> = {}): RetryItem {
  return { id, payload: BODY, targetUrl: TARGET, headers: {}, ...overrides };
}

/** Manual timer with single-step control, mirroring the other feature tests. */
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
      await flush();
    },
  };
}

describe("TenantRateLimiter.retune (WR-329)", () => {
  it("illegal patches throw RangeError and the live values are untouched", () => {
    let now = 1_000;
    const lim = new TenantRateLimiter({ burst: 10, refillPerSecond: 5, now: () => now });
    const bad = [
      { burst: 0 },
      { burst: -1 },
      { burst: NaN },
      { burst: Infinity },
      { refillPerSecond: 0 },
      { refillPerSecond: -2 },
      { refillPerSecond: NaN },
      { mode: "outer" as never },
      { mode: "QUEUE" as never },
      { mode: 42 as never },
      { burst: "10" as never },
    ];
    for (const patch of bad) {
      assert.throws(() => lim.retune(patch), RangeError, JSON.stringify(patch));
    }
    assert.throws(() => lim.retune(null as never), RangeError);
    assert.throws(() => lim.retune("fast" as never), RangeError);
    assert.deepEqual(lim.current(), { burst: 10, refillPerSecond: 5, mode: "queue", endpoints: {} });
    // The limiter still works at the old values.
    assert.deepEqual(lim.take("acme", TARGET), { ok: true });
  });

  it("an empty patch is a RangeError and the live values are untouched", () => {
    const lim = new TenantRateLimiter({ burst: 10, refillPerSecond: 5 });
    assert.throws(() => lim.retune({}), RangeError);
    assert.throws(() => lim.retuneEndpoint(TARGET, {}), RangeError);
    assert.deepEqual(lim.current(), { burst: 10, refillPerSecond: 5, mode: "queue", endpoints: {} });
  });

  it("tightening the burst clamps the existing bucket balance instead of refilling it", () => {
    let now = 1_000;
    const lim = new TenantRateLimiter({ burst: 3, refillPerSecond: 1, now: () => now });
    assert.deepEqual(lim.take("acme", TARGET), { ok: true });
    assert.deepEqual(lim.take("acme", TARGET), { ok: true });
    // One token left in the bucket; tightening to 2 keeps that one token
    // (a reset-to-full implementation would hand out two).
    assert.equal(lim.retune({ burst: 2 }).burst, 2);
    assert.deepEqual(lim.take("acme", TARGET), { ok: true });
    const denied = lim.take("acme", TARGET);
    assert.equal(denied.ok, false);
    if (!denied.ok) assert.equal(denied.retryAfterMs, 1000);
    // Tightening below the balance clamps it: burst 3 -> take one (2
    // left) -> retune to 1 leaves exactly one token.
    const lim2 = new TenantRateLimiter({ burst: 3, refillPerSecond: 1, now: () => now });
    lim2.take("acme", TARGET);
    lim2.retune({ burst: 1 });
    assert.deepEqual(lim2.take("acme", TARGET), { ok: true });
    assert.equal(lim2.take("acme", TARGET).ok, false);
  });

  it("widening the refill rate shortens retryAfterMs on the next denial", () => {
    let now = 1_000;
    const lim = new TenantRateLimiter({ burst: 1, refillPerSecond: 1, now: () => now });
    assert.deepEqual(lim.take("acme", TARGET), { ok: true });
    const denied = lim.take("acme", TARGET);
    assert.equal(denied.ok, false);
    if (!denied.ok) assert.equal(denied.retryAfterMs, 1000);
    lim.retune({ refillPerSecond: 10 });
    const denied2 = lim.take("acme", TARGET);
    assert.equal(denied2.ok, false);
    if (!denied2.ok) assert.equal(denied2.retryAfterMs, 100);
  });

  it("retuneEndpoint only moves that endpoint; other endpoints and the defaults are untouched", () => {
    let now = 1_000;
    const lim = new TenantRateLimiter({
      burst: 10,
      refillPerSecond: 5,
      endpoints: { [TARGET]: { burst: 2 } },
      now: () => now,
    });
    // Per-field: only burst moves; refill keeps falling back to the
    // live default.
    const next = lim.retuneEndpoint(TARGET, { burst: 1 });
    assert.deepEqual(next.endpoints, { [TARGET]: { burst: 1 } });
    assert.equal(lim.burstFor(TARGET), 1);
    assert.equal(lim.refillPerSecondFor(TARGET), 5);
    assert.equal(lim.burstFor(OTHER), 10);
    assert.equal(lim.refillPerSecondFor(OTHER), 5);
    assert.equal(lim.current().burst, 10);
    assert.equal(lim.current().refillPerSecond, 5);
    // A later defaults revision still moves the endpoint's unset
    // fields (they were never stored as an override).
    lim.retune({ refillPerSecond: 7 });
    assert.equal(lim.refillPerSecondFor(TARGET), 7);
    assert.equal(lim.burstFor(TARGET), 1);
    assert.equal(lim.refillPerSecondFor(OTHER), 7);
    // An illegal endpoint patch leaves everything untouched.
    assert.throws(() => lim.retuneEndpoint(TARGET, { burst: 0 }), RangeError);
    assert.throws(() => lim.retuneEndpoint("", { burst: 1 }), RangeError);
    assert.equal(lim.burstFor(TARGET), 1);
    assert.equal(lim.refillPerSecondFor(TARGET), 7);
  });

  it("removeEndpointOverride: false without an override, true with one, then falls back to the live defaults", () => {
    const lim = new TenantRateLimiter({
      burst: 10,
      refillPerSecond: 5,
      endpoints: { [TARGET]: { burst: 2, refillPerSecond: 1 } },
    });
    assert.equal(lim.removeEndpointOverride(OTHER), false);
    assert.equal(lim.removeEndpointOverride(TARGET), true);
    assert.equal(lim.removeEndpointOverride(TARGET), false);
    assert.deepEqual(lim.current().endpoints, {});
    assert.equal(lim.burstFor(TARGET), 10);
    assert.equal(lim.refillPerSecondFor(TARGET), 5);
    assert.throws(() => lim.removeEndpointOverride(""), RangeError);
  });
});

describe("RetryQueue tenant rate-limit revision (WR-329)", () => {
  it("mode queue -> reject-429: admission starts denying, dispatch never re-checks; back to queue: dispatch pacing resumes", async () => {
    let now = 1_000;
    const timer = manualTimer();
    let delivered = 0;
    const q = new RetryQueue({
      sender: async () => {
        delivered++;
        return okResponse;
      },
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      tenantRateLimit: { burst: 1, refillPerSecond: 1, mode: "queue", now: () => now },
      maxAttempts: 1,
      jitterMs: 0,
      onDelivered: () => undefined,
    });
    q.start();
    try {
      q.enqueue(item("a", { tenantId: "acme" }));
      await timer.step();
      assert.equal(delivered, 1);
      // Switch to reject-429: the bucket is empty, so admission now
      // denies — and the denial is what the intake path answers.
      const switched = q.reviseTenantRateLimit({ mode: "reject-429" });
      assert.equal(switched.mode, "reject-429");
      const denied = q.admitTenantDelivery("acme", TARGET);
      assert.equal(denied?.ok, false);
      if (denied && !denied.ok) assert.equal(denied.retryAfterMs, 1000);
      // A delivery admitted before the switch (or in this mode, one
      // that never needed admission) still dispatches: dispatch never
      // re-checks in reject-429 mode, even with an empty bucket.
      q.enqueue(item("b", { tenantId: "acme" }));
      await timer.step();
      assert.equal(delivered, 2);
      // Switch back to queue: dispatch pacing resumes — the next
      // attempt is parked until a token refills.
      assert.equal(q.reviseTenantRateLimit({ mode: "queue" }).mode, "queue");
      q.enqueue(item("c", { tenantId: "acme" }));
      await timer.step();
      assert.equal(delivered, 2, "over-limit attempt must park, not dispatch");
      assert.ok(timer.pendingCount() >= 1, "a reschedule timer must be parked");
      now += 1500;
      await timer.step();
      assert.equal(delivered, 3);
    } finally {
      q.stop();
    }
  });

  it("stats rows follow the live values after a revision", async () => {
    let delivered = 0;
    const q = new RetryQueue({
      sender: async () => {
        delivered++;
        return okResponse;
      },
      tenantRateLimit: { burst: 2, refillPerSecond: 1 },
      maxAttempts: 1,
      jitterMs: 0,
    });
    q.start();
    try {
      // One dispatch creates the scope's stats row.
      q.enqueue(item("a", { tenantId: "acme" }));
      await waitFor(() => delivered === 1);
      const before = q.getTenantRateLimitStats();
      assert.ok(before !== undefined && before.length >= 1, "expected a stats row");
      const row = before.find((r) => r.endpoint === TARGET);
      assert.ok(row, "expected a row for the target");
      assert.equal(row.burst, 2);
      assert.equal(row.refillPerSecond, 1);
      // Defaults revision moves the row; an endpoint revision moves
      // only that endpoint's row; removal falls back to the live defaults.
      q.reviseTenantRateLimit({ burst: 5, refillPerSecond: 10 });
      assert.equal(q.getTenantRateLimitStats()?.find((r) => r.endpoint === TARGET)?.burst, 5);
      assert.equal(
        q.getTenantRateLimitStats()?.find((r) => r.endpoint === TARGET)?.refillPerSecond,
        10
      );
      q.reviseTenantRateLimitEndpoint(TARGET, { burst: 3 });
      assert.equal(q.getTenantRateLimitStats()?.find((r) => r.endpoint === TARGET)?.burst, 3);
      assert.equal(
        q.getTenantRateLimitStats()?.find((r) => r.endpoint === TARGET)?.refillPerSecond,
        10
      );
      q.removeTenantRateLimitEndpoint(TARGET);
      assert.equal(q.getTenantRateLimitStats()?.find((r) => r.endpoint === TARGET)?.burst, 5);
      assert.equal(
        q.getTenantRateLimitStats()?.find((r) => r.endpoint === TARGET)?.refillPerSecond,
        10
      );
    } finally {
      q.stop();
    }
  });

  it("unconfigured: revisions throw the must-restart Error, the getter is undefined, remove is false", () => {
    const q = new RetryQueue({});
    assert.equal(q.getTenantRateLimit(), undefined);
    assert.throws(() => q.reviseTenantRateLimit({ burst: 1 }), /not configured — enabling it requires a restart/);
    assert.throws(
      () => q.reviseTenantRateLimitEndpoint(TARGET, { burst: 1 }),
      /not configured — enabling it requires a restart/
    );
    assert.equal(q.removeTenantRateLimitEndpoint(TARGET), false);
    assert.equal(q.getTenantRateLimitStats(), undefined);
  });
});

describe("RelayServer tenant rate-limit revision (WR-329)", () => {
  const forwardUrl = TARGET;
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function listen(server: Server): Promise<number> {
    return new Promise<number>((resolve) => {
      server.listen(0, "127.0.0.1", () => {
        const addr = server.address();
        assert.ok(addr && typeof addr === "object");
        resolve(addr.port);
      });
    });
  }

  function close(server: Server): Promise<void> {
    server.close();
    return new Promise((r) => server.once("close", r));
  }

  function post(
    port: number,
    path: string,
    body: Buffer,
    headers: Record<string, string> = {}
  ): Promise<{ status: number; text: string; headers: Record<string, string | string[] | undefined> }> {
    return new Promise((resolve, reject) => {
      const r = httpRequest({ host: "127.0.0.1", port, path, method: "POST", headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString(), headers: res.headers })
        );
      });
      r.on("error", reject);
      r.end(body);
    });
  }

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "tenant-rl-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    let sent = 0;
    const sender: Sender = async () => {
      sent++;
      return okResponse;
    };
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: signingKey,
      forwardUrl,
      auditLog: audit,
      operatorToken: opToken,
      sender,
      retry: { baseDelayMs: 5, jitterMs: 0, maxAttempts: 2 },
      ...extra,
    });
    servers.push(relay);
    return { relay, audit, sent: () => sent };
  }

  function signed(body: Buffer, tenant?: string): Record<string, string> {
    return {
      "x-signature": signSha256(body, signingKey),
      "content-type": "application/json",
      ...(tenant === undefined ? {} : { [TENANT_ID_HEADER]: tenant }),
    };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  it("defaults revision audits previous/current exactly; a same-value revision is a silent no-op", async () => {
    const { relay, audit } = makeRelay({
      retry: { tenantRateLimit: { burst: 50, refillPerSecond: 5 } },
    });
    await listen(relay);
    assert.deepEqual(relay.reviseTenantRateLimit!({ burst: 10 }), {
      burst: 10,
      refillPerSecond: 5,
      mode: "queue",
      endpoints: {},
    });
    let revised = eventsOf(audit, "tenant_rate_limit_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, { burst: 50, refillPerSecond: 5, mode: "queue" });
    assert.deepEqual(revised[0].current, { burst: 10, refillPerSecond: 5, mode: "queue" });
    // Landing exactly on the live values — even the construction
    // defaults themselves — audits nothing.
    relay.reviseTenantRateLimit!({ burst: 10, refillPerSecond: 5, mode: "queue" });
    assert.equal(eventsOf(audit, "tenant_rate_limit_revised").length, 1);
    assert.deepEqual(relay.getTenantRateLimit!(), {
      burst: 10,
      refillPerSecond: 5,
      mode: "queue",
      endpoints: {},
    });
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseTenantRateLimit!({ burst: 0 }), RangeError);
    assert.throws(() => relay.reviseTenantRateLimit!({}), RangeError);
    assert.equal(eventsOf(audit, "tenant_rate_limit_revised").length, 1);
    assert.equal(relay.getTenantRateLimit!().burst, 10);
  });

  it("endpoint revision audits effective previous/current; a same-effective-value revision records no override and no audit", async () => {
    const { relay, audit } = makeRelay({
      retry: { tenantRateLimit: { burst: 50, refillPerSecond: 5 } },
    });
    await listen(relay);
    // No override existed: the first previous is the live defaults.
    assert.deepEqual(relay.reviseTenantRateLimitEndpoint!(forwardUrl, { burst: 200 }), {
      burst: 50,
      refillPerSecond: 5,
      mode: "queue",
      endpoints: { [forwardUrl]: { burst: 200 } },
    });
    let revised = eventsOf(audit, "tenant_rate_limit_endpoint_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].endpoint, forwardUrl);
    assert.deepEqual(revised[0].previous, { burst: 50, refillPerSecond: 5 });
    assert.deepEqual(revised[0].current, { burst: 200, refillPerSecond: 5 });
    // Setting the refill to exactly the live default is a no-op that
    // records no override field.
    relay.reviseTenantRateLimitEndpoint!(forwardUrl, { refillPerSecond: 5 });
    assert.equal(eventsOf(audit, "tenant_rate_limit_endpoint_revised").length, 1);
    assert.deepEqual(relay.getTenantRateLimit!().endpoints, { [forwardUrl]: { burst: 200 } });
    // A real second revision audits the live effective values.
    relay.reviseTenantRateLimitEndpoint!(forwardUrl, { refillPerSecond: 20 });
    revised = eventsOf(audit, "tenant_rate_limit_endpoint_revised");
    assert.equal(revised.length, 2);
    assert.deepEqual(revised[1].previous, { burst: 200, refillPerSecond: 5 });
    assert.deepEqual(revised[1].current, { burst: 200, refillPerSecond: 20 });
    // Illegal endpoint patch: RangeError, live + audit untouched.
    assert.throws(() => relay.reviseTenantRateLimitEndpoint!(forwardUrl, { burst: 0 }), RangeError);
    assert.throws(() => relay.reviseTenantRateLimitEndpoint!("", { burst: 1 }), RangeError);
    assert.equal(eventsOf(audit, "tenant_rate_limit_endpoint_revised").length, 2);
  });

  it("remove returns false without an override and silently; with one it returns true, audits, and falls back to the live defaults", async () => {
    const { relay, audit } = makeRelay({
      retry: { tenantRateLimit: { burst: 50, refillPerSecond: 5 } },
    });
    await listen(relay);
    assert.equal(relay.removeTenantRateLimitEndpoint(forwardUrl), false);
    assert.equal(eventsOf(audit, "tenant_rate_limit_endpoint_removed").length, 0);
    relay.reviseTenantRateLimitEndpoint!(forwardUrl, { burst: 200 });
    assert.equal(relay.removeTenantRateLimitEndpoint(forwardUrl), true);
    const removed = eventsOf(audit, "tenant_rate_limit_endpoint_removed");
    assert.equal(removed.length, 1);
    assert.equal(removed[0].endpoint, forwardUrl);
    assert.deepEqual(removed[0].previous, { burst: 200 });
    assert.deepEqual(relay.getTenantRateLimit!().endpoints, {});
    assert.equal(relay.getTenantRateLimit!().burst, 50);
    assert.equal(relay.getTenantRateLimit!().refillPerSecond, 5);
    // Nothing left to remove: false, no audit.
    assert.equal(relay.removeTenantRateLimitEndpoint(forwardUrl), false);
    assert.equal(eventsOf(audit, "tenant_rate_limit_endpoint_removed").length, 1);
  });

  it("mode queue -> reject-429 answers 429 at intake; other tenants are unaffected", async () => {
    const { relay, audit, sent } = makeRelay({
      retry: { tenantRateLimit: { burst: 1, refillPerSecond: 0.2, mode: "queue" } },
    });
    const port = await listen(relay);
    try {
      // Queue mode never 429s at intake; the first delivery consumes
      // the single token at dispatch.
      assert.equal((await post(port, "/", BODY, signed(BODY, "acme"))).status, 202);
      await waitFor(() => sent() === 1);
      relay.reviseTenantRateLimit!({ mode: "reject-429" });
      const revised = eventsOf(audit, "tenant_rate_limit_revised");
      assert.equal(revised.length, 1);
      assert.equal((revised[0].previous as { mode: string }).mode, "queue");
      assert.equal((revised[0].current as { mode: string }).mode, "reject-429");
      // The bucket is empty (one token, spent at dispatch; 5s refill),
      // so the next intake for acme is answered 429 with retry-after.
      const denied = await post(port, "/", BODY, signed(BODY, "acme"));
      assert.equal(denied.status, 429);
      assert.equal(denied.text, "Too many requests");
      assert.ok(denied.headers["retry-after"] !== undefined, "expected a retry-after header");
      // Another tenant's bucket is untouched.
      assert.equal((await post(port, "/", BODY, signed(BODY, "beta"))).status, 202);
      await waitFor(() => sent() === 2);
    } finally {
      await close(relay);
    }
  });

  it("unconfigured: revisions throw the must-restart Error, the getter is unset, remove is false", async () => {
    const { relay } = makeRelay({});
    await listen(relay);
    assert.equal(relay.getTenantRateLimit, undefined);
    assert.throws(() => relay.reviseTenantRateLimit!({ burst: 1 }), /not configured — enabling it requires a restart/);
    assert.throws(
      () => relay.reviseTenantRateLimitEndpoint!(forwardUrl, { burst: 1 }),
      /not configured — enabling it requires a restart/
    );
    assert.equal(relay.removeTenantRateLimitEndpoint(forwardUrl), false);
  });
});
