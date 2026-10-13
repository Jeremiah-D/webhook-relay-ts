import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildHealthSummary, type HealthSummaryInput } from "../src/health-summary.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";

const relayKey = "relay-secret";
const opToken = "op-secret";
const BODY = Buffer.from(JSON.stringify({ hello: "health-summary" }));
const EP_A = "http://a.example/hook";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

describe("buildHealthSummary", () => {
  it("merges circuit, quota, and probe signals per (tenant, endpoint)", () => {
    const input: HealthSummaryInput = {
      circuits: [
        { endpoint: EP_A, tenant: "acme", state: "open", consecutiveFailures: 3, trips: 1, openedAtMs: 123 },
        { endpoint: EP_A, state: "closed", consecutiveFailures: 0, trips: 0 },
      ],
      quotas: [{ endpoint: EP_A, tenant: "acme", delayed: 7 }],
      probes: [{ endpoint: EP_A, success: 10, failure: 2, consecutiveFailures: 2 }],
      retryBudget: { retriesPerMinute: 6000, depleted: 42 },
    };
    const summary = buildHealthSummary(input);

    assert.ok(!Number.isNaN(Date.parse(summary.at)), "at is an ISO-8601 instant");
    assert.deepEqual(summary.retryBudget, { retriesPerMinute: 6000, depleted: 42 });
    assert.equal(summary.endpoints.length, 2);

    const acme = summary.endpoints.find((r) => r.tenant === "acme")!;
    assert.equal(acme.endpoint, EP_A);
    assert.deepEqual(acme.circuit, {
      state: "open",
      consecutiveFailures: 3,
      trips: 1,
      openedAtMs: 123,
    });
    assert.equal(acme.quotaDelayed, 7);
    // The prober is endpoint-scoped: the same probe state fans out to
    // every tenant row of that endpoint.
    assert.deepEqual(acme.probe, { success: 10, failure: 2, consecutiveFailures: 2 });

    const def = summary.endpoints.find((r) => r.tenant === undefined)!;
    assert.equal(def.endpoint, EP_A);
    assert.equal(def.circuit?.state, "closed");
    assert.ok(!("quotaDelayed" in def), "quota rows only appear for tenant-scoped quota stats");
    assert.deepEqual(def.probe, acme.probe);
  });

  it("omits optional sections and keeps default-tenant rows tenant-less", () => {
    const summary = buildHealthSummary({ circuits: [], quotas: [], probes: [] });
    assert.deepEqual(summary.endpoints, []);
    assert.deepEqual(summary.tenantUsageTop, []);
    assert.ok(!("retryBudget" in summary), "retry budget absent when disabled");
  });

  it("ranks tenants by delivery volume with a deterministic tiebreak", () => {
    const input: HealthSummaryInput = {
      circuits: [],
      quotas: [],
      probes: [],
      usage: [
        { tenant: "b", windowMs: 3600000, delivered: 5, failed: 0, retried: 0, deadLetter: 0, bytesIn: 1, bytesOut: 1, urgent: 0 },
        { tenant: "a", windowMs: 3600000, delivered: 5, failed: 0, retried: 0, deadLetter: 0, bytesIn: 9, bytesOut: 9, urgent: 0 },
        { tenant: "c", windowMs: 3600000, delivered: 1, failed: 4, retried: 4, deadLetter: 1, bytesIn: 0, bytesOut: 0, urgent: 0 },
      ],
    };
    const [first, second, third] = buildHealthSummary(input).tenantUsageTop;
    // Deliveries dominate: c has 1+4+4+1 = 10. a/b tie at 5 -> name order.
    assert.equal(first.tenant, "c");
    assert.equal(second.tenant, "a");
    assert.equal(third.tenant, "b");

    const top1 = buildHealthSummary({ ...input, topTenants: 1 }).tenantUsageTop;
    assert.deepEqual(top1.map((r) => r.tenant), ["c"]);

    assert.throws(() => buildHealthSummary({ ...input, topTenants: 0 }), RangeError);
  });

  it("a probe-only endpoint yields a tenant-less row", () => {
    const summary = buildHealthSummary({
      circuits: [],
      quotas: [],
      probes: [{ endpoint: EP_A, success: 1, failure: 0, consecutiveFailures: 0 }],
    });
    assert.deepEqual(summary.endpoints, [
      { endpoint: EP_A, probe: { success: 1, failure: 0, consecutiveFailures: 0 } },
    ]);
  });
});

describe("GET /health/summary", () => {
  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  function get(port: number, path: string, headers: Record<string, string> = {}) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest({ host: "127.0.0.1", port, path, method: "GET", headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
      });
      r.on("error", reject);
      r.end();
    });
  }

  it("aggregates circuit state and tenant usage top-N", async () => {
    const dir = mkdtempSync(join(tmpdir(), "health-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: relayKey,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog: audit,
      sender: async () => {
        throw new Error("downstream 500");
      },
      retry: {
        baseDelayMs: 5,
        jitterMs: 0,
        maxAttempts: 1,
        circuitBreaker: { failureThreshold: 1, cooldownMs: 60_000 },
      },
      usage: {},
      operatorToken: opToken,
    });
    const port = await listen(relay);
    const auth = { authorization: `Bearer ${opToken}` };
    try {
      for (const tenant of ["acme", "acme", "globex"] as const) {
        const r = httpRequest(
          {
            host: "127.0.0.1",
            port,
            path: "/",
            method: "POST",
            headers: { "x-signature": signSha256(BODY, relayKey), "x-tenant-id": tenant },
          },
          (res) => res.resume()
        );
        r.on("error", () => {});
        r.end(BODY);
        await sleep(10);
      }

      // Poll until the breaker tripped and usage has both tenants.
      let summary: Record<string, any> | undefined;
      for (let i = 0; i < 100; i++) {
        const res = await get(port, "/health/summary", auth);
        assert.equal(res.status, 200);
        summary = JSON.parse(res.text) as Record<string, any>;
        const open = (summary.endpoints as any[]).some((e) => e.circuit?.state === "open");
        const usage = (summary.tenantUsageTop as any[]).length >= 2;
        if (open && usage) break;
        await sleep(20);
      }
      assert.ok(summary, "summary fetched");
      assert.ok(!Number.isNaN(Date.parse(summary.at as string)));

      const acme = (summary.endpoints as any[]).find((e) => e.tenant === "acme");
      assert.ok(acme, "acme row present");
      assert.equal(acme.circuit.state, "open");
      assert.ok(acme.circuit.consecutiveFailures >= 1, "consecutive-failure streak exposed");

      // Top-N by volume: acme (2 webhooks) outranks globex (1).
      const top = (summary.tenantUsageTop as any[]).map((r) => r.tenant);
      assert.deepEqual(top, ["acme", "globex"]);

      // The summary is pure read: no audit event is emitted for fetching it.
      const auditEvents = audit.readAll().map((e) => e.event);
      assert.ok(!auditEvents.some((e) => String(e).includes("health")), "no health audit event");
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("shares the operator guard: 403 without token, 404 fail-closed without operator auth", async () => {
    const dir = mkdtempSync(join(tmpdir(), "health-guard-"));
    const withToken = createRelayServer({
      secret: relayKey,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      operatorToken: opToken,
    });
    const port = await listen(withToken);
    try {
      assert.equal((await get(port, "/health/summary")).status, 403);
      assert.equal((await get(port, "/health/summary", { authorization: "Bearer wrong" })).status, 403);
      // Scoped keys: a read-only key may read the summary (WR-82 convention).
    } finally {
      withToken.close();
      await new Promise((r) => withToken.once("close", r));
    }

    const dir2 = mkdtempSync(join(tmpdir(), "health-noguard-"));
    const noAuth = createRelayServer({
      secret: relayKey,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog: new AuditLog(join(dir2, "audit.jsonl")),
    });
    const port2 = await listen(noAuth);
    try {
      assert.equal((await get(port2, "/health/summary")).status, 404);
    } finally {
      noAuth.close();
      await new Promise((r) => noAuth.once("close", r));
    }
  });
});
