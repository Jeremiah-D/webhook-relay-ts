import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type RetryItem, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import { TENANT_ID_HEADER } from "../src/tenant.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "tenant-rate-limit-enable-test-key";
const opToken = "tenant-rate-limit-enable-op-token";
const BODY = Buffer.from(JSON.stringify({ event: "payment.succeeded", id: "evt-1" }));
const TARGET = "https://downstream.example.test/hook";
const OTHER = "https://other.example.test/hook";

const okResponse = { statusCode: 200, body: Buffer.from("ok") };
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

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
    await sleep(10);
  }
}

function item(id: string, tenantId = "acme", targetUrl = TARGET): RetryItem {
  return { id, payload: BODY, targetUrl, headers: {}, tenantId };
}

/**
 * Manual timer with single-step control: rate-limit delays re-arm
 * timers, so the tests advance one wave at a time instead of draining
 * everything. The limiter itself still runs on the real clock after
 * an enable (no `now` can be injected through the enable path), so
 * refill waits use a real `sleep` before the step.
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
      await flush();
    },
  };
}

describe("RetryQueue tenant rate-limit live enable (WR-463)", () => {
  it("enables with both values given; getter returns the full snapshot and stats is []", () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      assert.equal(q.getTenantRateLimit(), undefined);
      assert.equal(q.getTenantRateLimitStats(), undefined);
      assert.deepEqual(q.reviseTenantRateLimit({ burst: 50, refillPerSecond: 5 }), {
        burst: 50,
        refillPerSecond: 5,
        mode: "queue",
        endpoints: {},
      });
      assert.deepEqual(q.getTenantRateLimit(), {
        burst: 50,
        refillPerSecond: 5,
        mode: "queue",
        endpoints: {},
      });
      assert.deepEqual(q.getTenantRateLimitStats(), []);
    } finally {
      q.stop();
    }
  });

  it("explicit reject-429 enable: admission denies, dispatch never re-checks; switching back to queue resumes pacing", async () => {
    const t = manualTimer();
    let delivered = 0;
    const q = new RetryQueue({
      sender: (async () => {
        delivered++;
        return okResponse;
      }) as Sender,
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
      random: () => 0,
      maxAttempts: 1,
      jitterMs: 0,
    });
    q.start();
    try {
      assert.deepEqual(
        q.reviseTenantRateLimit({ burst: 1, refillPerSecond: 1, mode: "reject-429" }),
        { burst: 1, refillPerSecond: 1, mode: "reject-429", endpoints: {} }
      );
      // Admission consumes the single token; the next admission is denied.
      assert.deepEqual(q.admitTenantDelivery("acme", TARGET), { ok: true });
      const denied = q.admitTenantDelivery("acme", TARGET);
      assert.equal(denied?.ok, false);
      if (denied && !denied.ok) assert.equal(denied.retryAfterMs, 1000);
      // A delivery admitted before the switch still dispatches:
      // dispatch never re-checks in reject-429 mode, even with an
      // empty bucket.
      q.enqueue(item("a"));
      await t.step();
      assert.equal(delivered, 1);
      // Switch back to queue: dispatch pacing resumes — the next
      // attempt is parked until a token refills.
      assert.equal(q.reviseTenantRateLimit({ mode: "queue" }).mode, "queue");
      q.enqueue(item("b"));
      await t.step();
      assert.equal(delivered, 1, "over-limit attempt must park, not dispatch");
      assert.ok(t.pendingCount() >= 1, "a reschedule timer must be parked");
      await sleep(1500);
      await t.step();
      assert.equal(delivered, 2);
    } finally {
      q.stop();
    }
  });

  it("a single-field patch throws RangeError, stays unconfigured, and can still enable afterwards", () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      assert.throws(() => q.reviseTenantRateLimit({ burst: 1 }), RangeError);
      assert.throws(() => q.reviseTenantRateLimit({ refillPerSecond: 1 }), RangeError);
      assert.equal(q.getTenantRateLimit(), undefined);
      assert.equal(q.getTenantRateLimitStats(), undefined);
      assert.deepEqual(q.reviseTenantRateLimit({ burst: 2, refillPerSecond: 4 }), {
        burst: 2,
        refillPerSecond: 4,
        mode: "queue",
        endpoints: {},
      });
      assert.deepEqual(q.getTenantRateLimit(), {
        burst: 2,
        refillPerSecond: 4,
        mode: "queue",
        endpoints: {},
      });
    } finally {
      q.stop();
    }
  });

  it("an empty patch throws RangeError and stays unconfigured", () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      assert.throws(() => q.reviseTenantRateLimit({}), RangeError);
      assert.equal(q.getTenantRateLimit(), undefined);
      assert.equal(q.getTenantRateLimitStats(), undefined);
    } finally {
      q.stop();
    }
  });

  it("a non-object patch throws RangeError and stays unconfigured", () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      for (const bad of [null, "fast", 42, [1, 2]] as unknown as Array<Record<string, unknown>>) {
        assert.throws(() => q.reviseTenantRateLimit(bad as never), RangeError);
      }
      assert.equal(q.getTenantRateLimit(), undefined);
      assert.equal(q.getTenantRateLimitStats(), undefined);
    } finally {
      q.stop();
    }
  });

  it("illegal values throw RangeError, stay unconfigured, and can still enable afterwards", () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      const bad = [
        { burst: 0, refillPerSecond: 1 },
        { burst: -1, refillPerSecond: 1 },
        { burst: NaN, refillPerSecond: 1 },
        { burst: Infinity, refillPerSecond: 1 },
        { burst: 1, refillPerSecond: 0 },
        { burst: 1, refillPerSecond: -2 },
        { burst: 1, refillPerSecond: NaN },
        { burst: 1, refillPerSecond: Infinity },
        { burst: "10", refillPerSecond: 1 },
        { burst: 1, refillPerSecond: "5" },
        { burst: 1, refillPerSecond: 1, mode: "outer" },
        { burst: 1, refillPerSecond: 1, mode: "QUEUE" },
        { burst: 1, refillPerSecond: 1, mode: 42 },
      ] as never[];
      for (const patch of bad) {
        assert.throws(() => q.reviseTenantRateLimit(patch), RangeError, JSON.stringify(patch));
        assert.equal(q.getTenantRateLimit(), undefined);
      }
      assert.deepEqual(q.reviseTenantRateLimit({ burst: 3, refillPerSecond: 6 }), {
        burst: 3,
        refillPerSecond: 6,
        mode: "queue",
        endpoints: {},
      });
    } finally {
      q.stop();
    }
  });

  it("after the enable the next take paces by the new bucket: burst exhausted delays, throttles, and emits rate_limited", async () => {
    const posts: string[] = [];
    const collector = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        posts.push(Buffer.concat(chunks).toString());
        res.writeHead(200).end("ok");
      });
    });
    await new Promise<void>((r) => collector.listen(0, "127.0.0.1", r));
    const caddr = collector.address();
    assert.ok(caddr && typeof caddr === "object");
    let calls = 0;
    const q = new RetryQueue({
      sender: (async () => {
        calls += 1;
      }) as Sender,
      maxAttempts: 1,
      otlp: { endpoint: `http://127.0.0.1:${caddr.port}/v1/logs` },
    });
    q.start();
    try {
      // No limiter yet: the first delivery is unlimited.
      q.enqueue(item("pre"));
      await waitFor(() => calls === 1);
      // Enable: 1 token per 100ms, burst 1. The first burst is
      // available immediately; the next attempt must wait for refill.
      assert.deepEqual(q.reviseTenantRateLimit({ burst: 1, refillPerSecond: 10 }), {
        burst: 1,
        refillPerSecond: 10,
        mode: "queue",
        endpoints: {},
      });
      q.enqueue(item("b1"));
      await waitFor(() => calls === 2);
      q.enqueue(item("b2"));
      await waitFor(() => calls === 3);
      const rows = q.getTenantRateLimitStats() ?? [];
      const row = rows.find((s) => s.endpoint === TARGET && s.tenant === "acme");
      assert.ok(row, "expected a stats row for the tenant scope");
      assert.equal(row.limited, 1);
      assert.equal(row.burst, 1);
      assert.equal(row.refillPerSecond, 10);
      assert.ok(
        q
          .renderMetrics()
          .includes(`relay_tenant_ratelimited_total{endpoint="${TARGET}",tenant="acme"} 1`),
        q.renderMetrics()
      );
      await waitFor(() => posts.length > 0, 5000);
      const records = posts.flatMap((p) => {
        const parsed = JSON.parse(p) as {
          resourceLogs: Array<{
            scopeLogs: Array<{ logRecords: Array<{ body: { stringValue: string }; attributes: Array<{ key: string; value: { stringValue?: string; intValue?: string } }> }> }>;
          }>;
        };
        return parsed.resourceLogs.flatMap((rl) => rl.scopeLogs.flatMap((sl) => sl.logRecords));
      });
      const rl = records.find((r) => r.body.stringValue === "rate_limited");
      assert.ok(rl, "expected a rate_limited OTLP record");
      const attrs = Object.fromEntries(rl.attributes.map((a) => [a.key, a.value.stringValue ?? a.value.intValue]));
      assert.equal(attrs["relay.event_type"], "rate_limited");
      assert.equal(attrs["relay.endpoint"], TARGET);
      assert.equal(attrs["relay.tenant"], "acme");
      assert.ok(Number(attrs["relay.retry_after_ms"]) >= 1, JSON.stringify(attrs));
      await waitFor(
        () =>
          q.renderMetrics().includes('relay_otlp_exports_total{event_type="rate_limited",status="success"}'),
        5000
      );
    } finally {
      q.stop();
      collector.close();
      await new Promise((r) => collector.once("close", r));
    }
  });

  it("deliveries before the enable are not retroactively charged: the first burst after the enable is immediately available", async () => {
    const t = manualTimer();
    let calls = 0;
    const q = new RetryQueue({
      sender: (async () => {
        calls += 1;
      }) as Sender,
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
      random: () => 0, // no jitter: delays are exactly retryAfterMs
    });
    q.start();
    try {
      // Hammer the scope five times while unlimited.
      for (let i = 0; i < 5; i++) q.enqueue(item(`pre${i}`));
      await t.step();
      assert.equal(calls, 5);
      // Enable: 1 token/sec, burst 1. No back-charge — the first
      // post-enable attempt still finds a full bucket.
      assert.deepEqual(q.reviseTenantRateLimit({ burst: 1, refillPerSecond: 1 }), {
        burst: 1,
        refillPerSecond: 1,
        mode: "queue",
        endpoints: {},
      });
      q.enqueue(item("after1"));
      await t.step();
      assert.equal(calls, 6);
      // The second post-enable attempt finds the bucket empty.
      q.enqueue(item("after2"));
      await t.step();
      assert.equal(calls, 6);
      assert.equal(q.pendingCount(), 1);
      await sleep(1200); // one token refills on the real clock
      await t.step();
      assert.equal(calls, 7);
      assert.equal(q.pendingCount(), 0);
    } finally {
      q.stop();
    }
  });

  it("after the enable, revisions keep WR-329 semantics: partial merge, tighten clamps, widen never tops up", async () => {
    const t = manualTimer();
    let calls = 0;
    const q = new RetryQueue({
      sender: (async () => {
        calls += 1;
      }) as Sender,
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
      random: () => 0,
    });
    q.start();
    try {
      assert.deepEqual(q.reviseTenantRateLimit({ burst: 2, refillPerSecond: 1 }), {
        burst: 2,
        refillPerSecond: 1,
        mode: "queue",
        endpoints: {},
      });
      q.enqueue(item("a"));
      q.enqueue(item("b"));
      await t.step();
      assert.equal(calls, 2); // both fit the burst; the bucket is empty now
      // Partial merge keeps the live refillPerSecond.
      assert.deepEqual(q.reviseTenantRateLimit({ burst: 1 }), {
        burst: 1,
        refillPerSecond: 1,
        mode: "queue",
        endpoints: {},
      });
      assert.deepEqual(q.getTenantRateLimit(), {
        burst: 1,
        refillPerSecond: 1,
        mode: "queue",
        endpoints: {},
      });
      // Tighten clamps the (empty) balance: the next attempt waits.
      q.enqueue(item("c"));
      await t.step();
      assert.equal(calls, 2);
      assert.equal(q.pendingCount(), 1);
      await sleep(1200); // one token refills at 1/sec
      await t.step();
      assert.equal(calls, 3);
      // Widening never tops a bucket up: the balance is still 0, so
      // the next attempt waits for the next refill instead of
      // spending a topped-up burst.
      assert.deepEqual(q.reviseTenantRateLimit({ burst: 10 }), {
        burst: 10,
        refillPerSecond: 1,
        mode: "queue",
        endpoints: {},
      });
      q.enqueue(item("d"));
      await t.step();
      assert.equal(calls, 3);
      assert.equal(q.pendingCount(), 1);
      await sleep(1200);
      await t.step();
      assert.equal(calls, 4);
      // Empty / same-value revisions are silent no-ops; an illegal
      // revision throws and leaves the live values untouched.
      assert.deepEqual(q.reviseTenantRateLimit({ burst: 10, refillPerSecond: 1, mode: "queue" }), {
        burst: 10,
        refillPerSecond: 1,
        mode: "queue",
        endpoints: {},
      });
      assert.throws(() => q.reviseTenantRateLimit({}), RangeError);
      assert.throws(() => q.reviseTenantRateLimit({ burst: 0 }), RangeError);
      assert.deepEqual(q.getTenantRateLimit(), {
        burst: 10,
        refillPerSecond: 1,
        mode: "queue",
        endpoints: {},
      });
    } finally {
      q.stop();
    }
  });

  it("stats are undefined before the enable, [] after it, and carry an activity row after the first take", async () => {
    const t = manualTimer();
    let calls = 0;
    const q = new RetryQueue({
      sender: (async () => {
        calls += 1;
      }) as Sender,
      setTimer: t.setTimer,
      clearTimer: t.clearTimer,
      random: () => 0,
    });
    q.start();
    try {
      assert.equal(q.getTenantRateLimitStats(), undefined);
      q.reviseTenantRateLimit({ burst: 1, refillPerSecond: 1 });
      assert.deepEqual(q.getTenantRateLimitStats(), []);
      q.enqueue(item("a"));
      await t.step();
      assert.equal(calls, 1);
      assert.deepEqual(q.getTenantRateLimitStats(), [
        { endpoint: TARGET, tenant: "acme", limited: 0, burst: 1, refillPerSecond: 1 },
      ]);
      q.enqueue(item("b"));
      await t.step();
      assert.equal(calls, 1); // denied: the bucket is empty
      assert.deepEqual(q.getTenantRateLimitStats(), [
        { endpoint: TARGET, tenant: "acme", limited: 1, burst: 1, refillPerSecond: 1 },
      ]);
    } finally {
      q.stop();
    }
  });

  it("an endpoint override can be added after the enable", () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      q.reviseTenantRateLimit({ burst: 50, refillPerSecond: 5 });
      assert.deepEqual(q.reviseTenantRateLimitEndpoint(TARGET, { burst: 200 }), {
        burst: 50,
        refillPerSecond: 5,
        mode: "queue",
        endpoints: { [TARGET]: { burst: 200 } },
      });
      assert.equal(q.getTenantRateLimit()?.endpoints[TARGET]?.burst, 200);
      assert.equal(q.getTenantRateLimit()?.endpoints[OTHER], undefined);
      // The override wins for that endpoint; the defaults are untouched.
      assert.deepEqual(q.reviseTenantRateLimitEndpoint(OTHER, { refillPerSecond: 20 }), {
        burst: 50,
        refillPerSecond: 5,
        mode: "queue",
        endpoints: { [TARGET]: { burst: 200 }, [OTHER]: { refillPerSecond: 20 } },
      });
    } finally {
      q.stop();
    }
  });

  it("a restart restores unconfigured: a fresh queue without the option reports no limit", () => {
    const enabled = new RetryQueue({
      sender: async () => {},
      tenantRateLimit: { burst: 1, refillPerSecond: 1 },
    });
    try {
      assert.deepEqual(enabled.getTenantRateLimit(), {
        burst: 1,
        refillPerSecond: 1,
        mode: "queue",
        endpoints: {},
      });
    } finally {
      enabled.stop();
    }
    // A fresh instance is the post-restart state: the live-only
    // enable does not survive it.
    const restarted = new RetryQueue({ sender: async () => {} });
    try {
      assert.equal(restarted.getTenantRateLimit(), undefined);
      assert.equal(restarted.getTenantRateLimitStats(), undefined);
    } finally {
      restarted.stop();
    }
  });
});

describe("RelayServer tenant rate-limit live enable (WR-463)", () => {
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

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "tenant-rl-enable-"));
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
      forwardUrl: TARGET,
      auditLog: audit,
      operatorToken: opToken,
      sender,
      retry: { baseDelayMs: 5, jitterMs: 0, maxAttempts: 2 },
      ...extra,
    });
    servers.push(relay);
    return { relay, audit, sent: () => sent };
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

  it("enable audits previous: null with the exact current values, exactly once, and mounts the getter", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.equal(relay.getTenantRateLimit, undefined);
    assert.deepEqual(relay.reviseTenantRateLimit!({ burst: 50, refillPerSecond: 5 }), {
      burst: 50,
      refillPerSecond: 5,
      mode: "queue",
      endpoints: {},
    });
    assert.deepEqual(relay.getTenantRateLimit!(), {
      burst: 50,
      refillPerSecond: 5,
      mode: "queue",
      endpoints: {},
    });
    const enabled = eventsOf(audit, "tenant_rate_limit_revised");
    assert.equal(enabled.length, 1);
    assert.equal(enabled[0]!.previous, null);
    assert.deepEqual(enabled[0]!.current, { burst: 50, refillPerSecond: 5, mode: "queue" });
  });

  it("illegal enable patches throw RangeError, stay unconfigured and unaudited, and can still enable afterwards", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.throws(() => relay.reviseTenantRateLimit!({ burst: 1 }), RangeError);
    assert.throws(() => relay.reviseTenantRateLimit!({}), RangeError);
    assert.throws(() => relay.reviseTenantRateLimit!({ burst: 0, refillPerSecond: 1 }), RangeError);
    assert.throws(
      () => relay.reviseTenantRateLimit!(null as unknown as { burst: number; refillPerSecond: number }),
      RangeError
    );
    assert.equal(relay.getTenantRateLimit, undefined);
    assert.equal(eventsOf(audit, "tenant_rate_limit_revised").length, 0);
    assert.deepEqual(relay.reviseTenantRateLimit!({ burst: 2, refillPerSecond: 4 }), {
      burst: 2,
      refillPerSecond: 4,
      mode: "queue",
      endpoints: {},
    });
    assert.deepEqual(relay.getTenantRateLimit!(), {
      burst: 2,
      refillPerSecond: 4,
      mode: "queue",
      endpoints: {},
    });
    assert.equal(eventsOf(audit, "tenant_rate_limit_revised").length, 1);
  });

  it("after the enable, revisions audit previous as the enabled values; same-value and illegal revisions audit nothing", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    relay.reviseTenantRateLimit!({ burst: 50, refillPerSecond: 5 });
    assert.deepEqual(relay.reviseTenantRateLimit!({ burst: 10 }), {
      burst: 10,
      refillPerSecond: 5,
      mode: "queue",
      endpoints: {},
    });
    const revised = eventsOf(audit, "tenant_rate_limit_revised");
    assert.equal(revised.length, 2);
    assert.deepEqual(revised[1]!.previous, { burst: 50, refillPerSecond: 5, mode: "queue" });
    assert.deepEqual(revised[1]!.current, { burst: 10, refillPerSecond: 5, mode: "queue" });
    relay.reviseTenantRateLimit!({ burst: 10, refillPerSecond: 5, mode: "queue" });
    assert.equal(eventsOf(audit, "tenant_rate_limit_revised").length, 2);
    assert.throws(() => relay.reviseTenantRateLimit!({ burst: 0 }), RangeError);
    assert.throws(() => relay.reviseTenantRateLimit!({}), RangeError);
    assert.equal(eventsOf(audit, "tenant_rate_limit_revised").length, 2);
    assert.deepEqual(relay.getTenantRateLimit!(), {
      burst: 10,
      refillPerSecond: 5,
      mode: "queue",
      endpoints: {},
    });
  });

  it("reject-429 enable answers 429 at intake; other tenants are unaffected", async () => {
    const { relay, audit, sent } = makeRelay();
    const port = await listen(relay);
    try {
      relay.reviseTenantRateLimit!({ burst: 1, refillPerSecond: 0.2, mode: "reject-429" });
      const enabled = eventsOf(audit, "tenant_rate_limit_revised");
      assert.equal(enabled.length, 1);
      assert.equal(enabled[0]!.previous, null);
      assert.deepEqual(enabled[0]!.current, { burst: 1, refillPerSecond: 0.2, mode: "reject-429" });
      // The first intake for acme consumes the single token.
      assert.equal((await post(port, "/", BODY, signed(BODY, "acme"))).status, 202);
      await waitFor(() => sent() === 1);
      // The bucket is empty (one token, spent at intake; 5s refill),
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

  it("a restart restores unconfigured: a fresh relay without the option mounts no getter", async () => {
    const { relay } = makeRelay({
      retry: { tenantRateLimit: { burst: 1, refillPerSecond: 1 } },
    });
    await listen(relay);
    assert.deepEqual(relay.getTenantRateLimit!(), {
      burst: 1,
      refillPerSecond: 1,
      mode: "queue",
      endpoints: {},
    });
    const { relay: freshRelay } = makeRelay();
    await listen(freshRelay);
    assert.equal(freshRelay.getTenantRateLimit, undefined);
  });
});
