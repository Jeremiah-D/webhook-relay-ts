import { describe, it } from "node:test";
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
const signingKey = "tenant-ratelimit-test-key";
const opToken = "tenant-ratelimit-op-token";
const BODY = Buffer.from(JSON.stringify({ event: "payment.succeeded", id: "evt-1" }));
const TARGET = "https://downstream.example.test/hook";

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

async function waitFor(cond: () => boolean, timeoutMs = 5000): Promise<void> {
  const start = Date.now();
  for (;;) {
    if (cond()) return;
    if (Date.now() - start > timeoutMs) throw new Error("waitFor timed out");
    await sleep(10);
  }
}

function item(id: string, overrides: Partial<RetryItem> = {}): RetryItem {
  return { id, payload: BODY, targetUrl: TARGET, headers: {}, ...overrides };
}

const okResponse: DownstreamResponse = { statusCode: 200, body: Buffer.from("ok") };

describe("tenant-ratelimit: unit", () => {
  it("starts full, denies when exhausted, refills with the injected clock", () => {
    let now = 1_000;
    const lim = new TenantRateLimiter({ burst: 2, refillPerSecond: 1, now: () => now });
    assert.equal(lim.mode(), "queue");
    assert.deepEqual(lim.take("acme", TARGET), { ok: true });
    assert.deepEqual(lim.take("acme", TARGET), { ok: true });
    const denied = lim.take("acme", TARGET);
    assert.equal(denied.ok, false);
    if (!denied.ok) assert.equal(denied.retryAfterMs, 1000);
    // Half a token refilled: still denied, but the wait shrinks honestly.
    now += 500;
    const denied2 = lim.take("acme", TARGET);
    assert.equal(denied2.ok, false);
    if (!denied2.ok) assert.equal(denied2.retryAfterMs, 500);
    now += 500;
    assert.deepEqual(lim.take("acme", TARGET), { ok: true });
  });

  it("isolates buckets per (tenant, endpoint)", () => {
    let now = 1_000;
    const lim = new TenantRateLimiter({ burst: 1, refillPerSecond: 1, now: () => now });
    assert.deepEqual(lim.take("acme", TARGET), { ok: true });
    assert.equal(lim.take("acme", TARGET).ok, false);
    // Another tenant's bucket is untouched…
    assert.deepEqual(lim.take("beta", TARGET), { ok: true });
    // …and so is another endpoint's bucket for the same tenant…
    assert.deepEqual(lim.take("acme", "https://other.example.test/hook"), { ok: true });
    // …and the default (tenant-less) scope keys plain endpoints.
    assert.deepEqual(lim.take(undefined, TARGET), { ok: true });
    assert.equal(lim.take(undefined, TARGET).ok, false);
  });

  it("endpoint overrides win over tenant-level defaults, per field", () => {
    let now = 1_000;
    const lim = new TenantRateLimiter({
      burst: 1,
      refillPerSecond: 1,
      endpoints: {
        [TARGET]: { burst: 3 },
        "https://fast.example.test/hook": { refillPerSecond: 10 },
      },
      now: () => now,
    });
    assert.deepEqual(lim.configuredEndpoints().sort(), [TARGET, "https://fast.example.test/hook"].sort());
    // The overridden endpoint gets its own burst…
    assert.deepEqual(lim.take("acme", TARGET), { ok: true });
    assert.deepEqual(lim.take("acme", TARGET), { ok: true });
    assert.deepEqual(lim.take("acme", TARGET), { ok: true });
    assert.equal(lim.take("acme", TARGET).ok, false);
    // …while other endpoints keep the tenant-level default burst of 1…
    assert.deepEqual(lim.take("acme", "https://plain.example.test/hook"), { ok: true });
    assert.equal(lim.take("acme", "https://plain.example.test/hook").ok, false);
    // …and a refill-only override keeps the default burst but refills faster.
    assert.deepEqual(lim.take("acme", "https://fast.example.test/hook"), { ok: true });
    const denied = lim.take("acme", "https://fast.example.test/hook");
    assert.equal(denied.ok, false);
    if (!denied.ok) assert.equal(denied.retryAfterMs, 100);
    // Stats expose the override-resolved config per scope.
    const rows = lim.stats();
    const targetRow = rows.find((r) => r.endpoint === TARGET && r.tenant === "acme");
    assert.equal(targetRow?.burst, 3);
    assert.equal(targetRow?.refillPerSecond, 1);
    const fastRow = rows.find((r) => r.endpoint === "https://fast.example.test/hook");
    assert.equal(fastRow?.burst, 1);
    assert.equal(fastRow?.refillPerSecond, 10);
  });

  it("counts denials per scope in stats", () => {
    const lim = new TenantRateLimiter({ burst: 1, refillPerSecond: 1 });
    lim.take("acme", TARGET);
    lim.take("acme", TARGET);
    lim.take("acme", TARGET);
    lim.take("beta", TARGET);
    const rows = lim.stats();
    assert.equal(rows.find((r) => r.tenant === "acme")?.limited, 2);
    assert.equal(rows.find((r) => r.tenant === "beta")?.limited, 0);
  });

  it("rejects illegal configs with RangeError", () => {
    const bad: unknown[] = [
      {},
      { burst: 1 },
      { refillPerSecond: 1 },
      { burst: 0, refillPerSecond: 1 },
      { burst: -2, refillPerSecond: 1 },
      { burst: NaN, refillPerSecond: 1 },
      { burst: Infinity, refillPerSecond: 1 },
      { burst: 1, refillPerSecond: 0 },
      { burst: 1, refillPerSecond: Infinity },
      { burst: 1, refillPerSecond: 1, mode: "drop" },
      { burst: 1, refillPerSecond: 1, endpoints: { "": { burst: 2 } } },
      { burst: 1, refillPerSecond: 1, endpoints: { [TARGET]: { burst: 0 } } },
      { burst: 1, refillPerSecond: 1, endpoints: { [TARGET]: { refillPerSecond: -1 } } },
      { burst: 1, refillPerSecond: 1, endpoints: [] },
    ];
    for (const opts of bad) {
      assert.throws(() => new TenantRateLimiter(opts as never), RangeError, JSON.stringify(opts));
    }
    // Sane configs do not throw.
    new TenantRateLimiter({ burst: 1, refillPerSecond: 1 });
    new TenantRateLimiter({ burst: 1.5, refillPerSecond: 0.5, mode: "reject-429", endpoints: { [TARGET]: {} } });
  });
});

describe("tenant-ratelimit: queue mode (RetryQueue integration)", () => {
  it("over-limit attempts wait for refill instead of being dropped", async () => {
    const inner: Sender = async () => okResponse;
    const delivered: string[] = [];
    const attemptsSeen: number[] = [];
    const q = new RetryQueue({
      sender: inner,
      // 10 tokens/s: the second dispatch lands within milliseconds of the
      // first take, so the denial is deterministic (no refill yet).
      tenantRateLimit: { burst: 1, refillPerSecond: 10 },
      maxAttempts: 1,
      onDelivered: (it, attempts) => {
        delivered.push(it.id);
        attemptsSeen.push(attempts);
      },
    });
    q.start();
    try {
      // Distinct payloads: no WR-91 merging — both are real dispatches.
      q.enqueue(item("a"));
      q.enqueue(item("b", { payload: Buffer.from("different") }));
      await waitFor(() => delivered.length === 2);
      assert.deepEqual(delivered.sort(), ["a", "b"]);
      // Nothing was dropped, nothing dead-lettered, and the wait consumed
      // no attempt: both deliveries went out on their first attempt.
      assert.equal(q.getDeadLetter().length, 0);
      assert.deepEqual(attemptsSeen.sort(), [1, 1]);
      const stats = q.getTenantRateLimitStats();
      assert.equal(stats?.length, 1);
      assert.equal(stats?.[0].limited, 1);
      assert.equal(stats?.[0].endpoint, TARGET);
    } finally {
      q.stop();
    }
  });

  it("a rate-limited wait is not a delivery outcome: breaker, AIMD, and backoff stay untouched", async () => {
    const inner: Sender = async () => okResponse;
    let delivered = 0;
    const q = new RetryQueue({
      sender: inner,
      // 10 tokens/s: the second dispatch lands within milliseconds of the
      // first take, so the denial is deterministic (no refill yet).
      tenantRateLimit: { burst: 1, refillPerSecond: 10 },
      circuitBreaker: { failureThreshold: 2, cooldownMs: 60_000 },
      adaptiveConcurrency: { windowSize: 4 },
      adaptiveBackoff: {},
      maxAttempts: 1,
      onDelivered: () => {
        delivered++;
      },
    });
    q.start();
    try {
      q.enqueue(item("a"));
      q.enqueue(item("b", { payload: Buffer.from("different") }));
      await waitFor(() => delivered === 2);
      // One denial happened (the limiter did its job)…
      assert.equal(q.getTenantRateLimitStats()?.[0].limited, 1);
      // …but the wait was never an outcome: the breaker recorded no
      // failure and never tripped, the AIMD window stayed empty, and the
      // backoff saw no failure streak. (The two real successes
      // legitimately feed the outcome streams — successes are outcomes;
      // the throttled wait is not.) Rate paces delivery; outcomes pace
      // congestion control. Note: the breaker row exists because
      // `shouldAllow` runs before the attempt — what matters is it shows
      // zero failures and a closed circuit.
      for (const row of q.getCircuitStats()) {
        assert.equal(row.consecutiveFailures, 0);
        assert.equal(row.trips, 0);
        assert.equal(row.state, "closed");
      }
      const aimd = q.getAdaptiveConcurrencyStats() ?? [];
      // Exactly the two real successes sit in the AIMD window — the
      // throttled wait added no third outcome.
      for (const row of aimd) {
        assert.equal(row.windowOutcomes, 2);
        assert.equal(row.windowFailures, 0);
      }
      const backoff = q.getAdaptiveBackoffStats() ?? [];
      for (const row of backoff) assert.equal(row.consecutiveFailures, 0);
    } finally {
      q.stop();
    }
  });

  it("composes with WR-91 coalescing: identical deliveries still merge, no interference", async () => {
    let calls = 0;
    let release!: () => void;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    const inner: Sender = async () => {
      calls++;
      await gate;
      return okResponse;
    };
    let delivered = 0;
    const q = new RetryQueue({
      sender: inner,
      coalesce: true,
      tenantRateLimit: { burst: 10, refillPerSecond: 10 },
      onDelivered: () => {
        delivered++;
      },
    });
    q.start();
    try {
      q.enqueue(item("a"));
      q.enqueue(item("b"));
      await waitFor(() => calls === 1);
      await sleep(30); // let the second delivery attach while the attempt is in flight
      release();
      await waitFor(() => delivered === 2);
      // One physical attempt for two logical deliveries — the limiter
      // charged the dispatches (per-logical-delivery, like the WR-15
      // quota) but never blocked the merge.
      assert.equal(calls, 1);
      assert.equal(q.getTenantRateLimitStats()?.[0].limited, 0);
      assert.equal(q.getCoalesceStats()?.mergedDeliveries, 1);
    } finally {
      q.stop();
    }
  });

  it("admitTenantDelivery is undefined in queue mode (no intake check)", () => {
    const q = new RetryQueue({ tenantRateLimit: { burst: 1, refillPerSecond: 1 } });
    assert.equal(q.admitTenantDelivery("acme", TARGET), undefined);
    const off = new RetryQueue({});
    assert.equal(off.admitTenantDelivery("acme", TARGET), undefined);
    assert.equal(off.getTenantRateLimitStats(), undefined);
  });

  it("reject-429 mode: admitTenantDelivery consumes at admission; dispatch never re-checks", () => {
    const q = new RetryQueue({
      tenantRateLimit: { burst: 1, refillPerSecond: 1, mode: "reject-429" },
    });
    assert.deepEqual(q.admitTenantDelivery("acme", TARGET), { ok: true });
    const denied = q.admitTenantDelivery("acme", TARGET);
    assert.equal(denied?.ok, false);
    assert.equal(q.getTenantRateLimitStats()?.[0].limited, 1);
  });

  it("Prometheus: relay_tenant_ratelimited_total is activity-gated with endpoint/tenant labels", async () => {
    const inner: Sender = async () => okResponse;
    let delivered = 0;
    const q = new RetryQueue({
      sender: inner,
      // 10 tokens/s: the follow-up dispatches land within milliseconds of
      // the first takes, so the denials are deterministic (no refill yet).
      tenantRateLimit: { burst: 1, refillPerSecond: 10 },
      maxAttempts: 1,
      onDelivered: () => {
        delivered++;
      },
    });
    q.start();
    try {
      // Enabled but untouched: the series stays absent.
      assert.ok(!q.renderMetrics().includes("relay_tenant_ratelimited_total"));
      q.enqueue(item("a", { tenantId: "acme" }));
      q.enqueue(item("b", { tenantId: "acme", payload: Buffer.from("different") }));
      q.enqueue(item("c")); // default tenant
      q.enqueue(item("d", { payload: Buffer.from("third") }));
      await waitFor(() => delivered === 4);
      const exposition = q.renderMetrics();
      assert.ok(
        exposition.includes('relay_tenant_ratelimited_total{endpoint="https://downstream.example.test/hook",tenant="acme"} 1'),
        exposition
      );
      // The default tenant's series carries no tenant label (WR-48).
      assert.ok(
        exposition.includes('relay_tenant_ratelimited_total{endpoint="https://downstream.example.test/hook"} 1'),
        exposition
      );
    } finally {
      q.stop();
    }
  });

  it("OTLP: rate-limit decisions export as rate_limited events with retry_after_ms", async () => {
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
    const inner: Sender = async () => okResponse;
    let delivered = 0;
    const q = new RetryQueue({
      sender: inner,
      // 10 tokens/s: the second dispatch lands within milliseconds of the
      // first take, so the denial is deterministic (no refill yet).
      tenantRateLimit: { burst: 1, refillPerSecond: 10 },
      otlp: { endpoint: `http://127.0.0.1:${caddr.port}/v1/logs` },
      maxAttempts: 1,
      onDelivered: () => {
        delivered++;
      },
    });
    q.start();
    try {
      q.enqueue(item("a", { tenantId: "acme" }));
      q.enqueue(item("b", { tenantId: "acme", payload: Buffer.from("different") }));
      await waitFor(() => delivered === 2);
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
      assert.equal(attrs["relay.tenant"], "acme");
      assert.equal(attrs["relay.endpoint"], TARGET);
      assert.ok(Number(attrs["relay.retry_after_ms"]) >= 1, JSON.stringify(attrs));
      // The export counter carries the new event type (wait for the
      // collector's 2xx to be processed — the counter bumps on response,
      // not on POST arrival).
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
});

describe("tenant-ratelimit: server integration (reject-429 mode)", () => {
  const forwardUrl = "https://downstream.example.test/hook";

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
    const dir = mkdtempSync(join(tmpdir(), "tenant-rl-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    // The injected sender answers 200 immediately: deliveries are
    // counted here, no downstream stub needed.
    let sent = 0;
    const sender: Sender = async () => {
      sent++;
      return okResponse;
    };
    const relay = createRelayServer({
      secret: signingKey,
      forwardUrl,
      auditLog: audit,
      operatorToken: opToken,
      sender,
      retry: { baseDelayMs: 5, jitterMs: 0, maxAttempts: 2 },
      ...extra,
    });
    return { relay, audit, sent: () => sent };
  }

  function signed(body: Buffer, tenant?: string): Record<string, string> {
    return {
      "x-signature": signSha256(body, signingKey),
      "content-type": "application/json",
      ...(tenant === undefined ? {} : { [TENANT_ID_HEADER]: tenant }),
    };
  }

  async function waitForAudit(audit: AuditLog, pred: (e: Record<string, unknown>) => boolean): Promise<void> {
    await waitFor(() =>
      (audit.readAll() as Array<Record<string, unknown>>).some(pred)
    );
  }

  it("answers 429 with retry-after when the tenant's bucket is exhausted", async () => {
    const { relay, audit, sent } = makeRelay({
      tenantRateLimit: { burst: 1, refillPerSecond: 0.2, mode: "reject-429" },
    });
    const port = await listen(relay);
    try {
      const first = await post(port, "/", BODY, signed(BODY, "acme"));
      assert.equal(first.status, 202);
      const second = await post(port, "/", BODY, signed(BODY, "acme"));
      assert.equal(second.status, 429);
      assert.equal(second.text, "Too many requests");
      const retryAfter = second.headers["retry-after"];
      assert.ok(retryAfter !== undefined, "expected a retry-after header");
      assert.ok(Number(retryAfter) >= 1, `retry-after=${retryAfter}`);
      // The rejected webhook never entered the queue: nothing was sent
      // for it, and the audit trail shows the rate-limit rejection.
      await waitForAudit(audit, (e) => e.event === "rejected" && e.reason === "rate_limited");
      const events = audit.readAll() as Array<Record<string, unknown>>;
      const rejected = events.find((e) => e.reason === "rate_limited");
      assert.equal(rejected?.event, "rejected");
      assert.equal(rejected?.tenant, "acme");
      assert.ok(typeof rejected?.retryAfterMs === "number");
      await waitFor(() => sent() === 1, 5000);
      assert.equal(sent(), 1);
    } finally {
      await close(relay);
    }
  });

  it("isolates tenants at intake: one tenant's exhaustion does not 429 another", async () => {
    const { relay } = makeRelay({
      tenantRateLimit: { burst: 1, refillPerSecond: 0.2, mode: "reject-429" },
    });
    const port = await listen(relay);
    try {
      assert.equal((await post(port, "/", BODY, signed(BODY, "acme"))).status, 202);
      assert.equal((await post(port, "/", BODY, signed(BODY, "acme"))).status, 429);
      assert.equal((await post(port, "/", BODY, signed(BODY, "beta"))).status, 202);
      assert.equal((await post(port, "/", BODY, signed(BODY))).status, 202);
    } finally {
      await close(relay);
    }
  });

  it("endpoint overrides apply at intake", async () => {
    const { relay } = makeRelay({
      tenantRateLimit: {
        burst: 1,
        refillPerSecond: 0.2,
        mode: "reject-429",
        endpoints: { [forwardUrl]: { burst: 3 } },
      },
    });
    const port = await listen(relay);
    try {
      assert.equal((await post(port, "/", BODY, signed(BODY, "acme"))).status, 202);
      assert.equal((await post(port, "/", BODY, signed(BODY, "acme"))).status, 202);
      assert.equal((await post(port, "/", BODY, signed(BODY, "acme"))).status, 202);
      assert.equal((await post(port, "/", BODY, signed(BODY, "acme"))).status, 429);
    } finally {
      await close(relay);
    }
  });

  it("queue mode never 429s at intake: over-limit webhooks are accepted and paced at dispatch", async () => {
    const { relay, sent } = makeRelay({
      tenantRateLimit: { burst: 1, refillPerSecond: 1000, mode: "queue" },
    });
    const port = await listen(relay);
    try {
      const first = await post(port, "/", BODY, signed(BODY, "acme"));
      const second = await post(port, "/", BODY, signed(BODY, "acme"));
      assert.equal(first.status, 202);
      assert.equal(second.status, 202);
      // Both deliveries eventually go out — the second waited for a token.
      await waitFor(() => sent() === 2, 5000);
    } finally {
      await close(relay);
    }
  });

  it("records intake denials in Prometheus with the tenant label", async () => {
    const { relay } = makeRelay({
      tenantRateLimit: { burst: 1, refillPerSecond: 0.2, mode: "reject-429" },
    });
    const port = await listen(relay);
    try {
      assert.equal((await post(port, "/", BODY, signed(BODY, "acme"))).status, 202);
      assert.equal((await post(port, "/", BODY, signed(BODY, "acme"))).status, 429);
      const metricsRes = await new Promise<{ status: number; text: string }>((resolve, reject) => {
        const r = httpRequest(
          {
            host: "127.0.0.1",
            port,
            path: "/metrics",
            method: "GET",
            headers: { authorization: `Bearer ${opToken}` },
          },
          (res) => {
            const chunks: Buffer[] = [];
            res.on("data", (c: Buffer) => chunks.push(c));
            res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
          }
        );
        r.on("error", reject);
        r.end();
      });
      assert.equal(metricsRes.status, 200);
      assert.ok(
        metricsRes.text.includes(
          `relay_tenant_ratelimited_total{endpoint="${forwardUrl}",tenant="acme"} 1`
        ),
        metricsRes.text
      );
    } finally {
      await close(relay);
    }
  });
});
