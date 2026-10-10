import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import { RetryQueue, type RetryItem } from "../src/retry.ts";
import { assertValidTenantId, TENANT_ID_HEADER } from "../src/tenant.ts";

const SECRET = "tenant-test-secret";
const TOKEN = "tenant-op-token";
const BODY = Buffer.from(JSON.stringify({ event: "order.created" }));
const ENDPOINT = "http://127.0.0.1:9/hook";

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

async function close(server: Server): Promise<void> {
  server.close();
  await new Promise((r) => server.once("close", r));
}

function post(port: number, path: string, body: Buffer, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method: "POST", headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
    });
    r.on("error", reject);
    r.end(body);
  });
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

/** Manual timer; `pump(n)` runs at most n waves of scheduled callbacks. */
function makeTimer() {
  const pending: Array<() => void> = [];
  return {
    pending,
    setTimer: (fn: () => void, _ms: number) => {
      pending.push(fn);
      return {
        clear: () => {
          const i = pending.indexOf(fn);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    pump: async (waves: number) => {
      for (let i = 0; i < waves && pending.length > 0; i++) {
        const fns = pending.splice(0);
        for (const fn of fns) fn();
        await new Promise((r) => setImmediate(r));
      }
    },
  };
}

function item(id: string, tenantId?: string): RetryItem {
  return {
    id,
    payload: Buffer.from("x"),
    targetUrl: ENDPOINT,
    headers: {},
    ...(tenantId === undefined ? {} : { tenantId }),
  };
}

describe("tenant id validation", () => {
  it("accepts sane ids", () => {
    for (const id of ["acme", "a", "A-9_z", "x".repeat(64)]) assertValidTenantId(id);
  });

  it("rejects empty, overlong, and weird ids", () => {
    for (const id of ["", "x".repeat(65), "has space", "semi;colon", "dot.name", "slash/x", "ünicode"]) {
      assert.throws(() => assertValidTenantId(id), /tenant/i);
    }
  });

  it("rejects non-strings with TypeError", () => {
    assert.throws(() => assertValidTenantId(42 as never), TypeError);
    assert.throws(() => assertValidTenantId(undefined as never), TypeError);
  });

  it("exposes the header name", () => {
    assert.equal(TENANT_ID_HEADER, "x-tenant-id");
  });
});

describe("per-tenant isolation in RetryQueue", () => {
  it("isolates circuit breakers per tenant", async () => {
    const timer = makeTimer();
    const calls: string[] = [];
    const q = new RetryQueue({
      sender: async (it) => {
        calls.push(it.id);
        if (it.tenantId === "a") throw new Error("boom");
      },
      setTimer: timer.setTimer,
      circuitBreaker: { failureThreshold: 1, cooldownMs: 60_000 },
      maxAttempts: 1,
      baseDelayMs: 1,
      jitterMs: 0,
    });
    q.start();
    try {
      q.enqueue(item("a1", "a"));
      await timer.pump(10);
      // Tenant a tripped its breaker on the first failure.
      const states = q.getCircuitStats();
      assert.ok(
        states.some((s) => s.endpoint === ENDPOINT && s.tenant === "a" && s.state === "open"),
        JSON.stringify(states)
      );
      // Tenant b shares the endpoint but has its own breaker: still delivers.
      q.enqueue(item("b1", "b"));
      await timer.pump(10);
      assert.ok(calls.includes("b1"), `b1 never delivered: ${JSON.stringify(calls)}`);
      const after = q.getCircuitStats();
      assert.ok(
        !after.some((s) => s.endpoint === ENDPOINT && s.tenant === "b" && s.state === "open"),
        JSON.stringify(after)
      );
    } finally {
      q.stop();
    }
  });

  it("isolates quotas per tenant", async () => {
    const timer = makeTimer();
    let nowMs = 1_000_000;
    const delivered: string[] = [];
    const q = new RetryQueue({
      sender: async (it) => {
        delivered.push(it.id);
      },
      setTimer: timer.setTimer,
      quota: { deliveriesPerMinute: 1, now: () => nowMs },
      baseDelayMs: 1,
      jitterMs: 0,
    });
    q.start();
    try {
      q.enqueue(item("a1", "a"));
      q.enqueue(item("a2", "a"));
      q.enqueue(item("b1", "b"));
      await timer.pump(10);
      // One token per tenant: a1 and b1 go through, a2 is parked on a's quota.
      // (Each denied take re-records, so `delayed` counts denials, not items.)
      assert.deepEqual([...delivered].sort(), ["a1", "b1"]);
      const stats = q.getQuotaStats();
      assert.equal(stats.length, 1);
      assert.equal(stats[0].endpoint, ENDPOINT);
      assert.equal(stats[0].tenant, "a");
      assert.ok(stats[0].delayed >= 1);
      // A minute later a's bucket refills and a2 flows.
      nowMs += 61_000;
      await timer.pump(10);
      assert.ok(delivered.includes("a2"), JSON.stringify(delivered));
    } finally {
      q.stop();
    }
  });

  it("isolates the concurrency limiter per tenant", async () => {
    const timer = makeTimer();
    let inflight = 0;
    let maxInflight = 0;
    const releasers: Array<() => void> = [];
    const q = new RetryQueue({
      sender: () => {
        inflight += 1;
        maxInflight = Math.max(maxInflight, inflight);
        return new Promise<void>((resolve) => {
          releasers.push(() => {
            inflight -= 1;
            resolve();
          });
        });
      },
      setTimer: timer.setTimer,
      maxConcurrentPerEndpoint: 1,
      baseDelayMs: 1,
      jitterMs: 0,
    });
    q.start();
    try {
      q.enqueue(item("a1", "a"));
      await timer.pump(5);
      assert.equal(inflight, 1);
      // Same tenant, same endpoint: queued behind the limiter.
      q.enqueue(item("a2", "a"));
      await timer.pump(5);
      assert.equal(inflight, 1);
      // Another tenant: its own limiter, so it starts right away.
      q.enqueue(item("b1", "b"));
      await timer.pump(5);
      assert.equal(inflight, 2);
      assert.equal(maxInflight, 2);
      // Drain: releasing a1 lets the parked a2 take its slot.
      for (let i = 0; i < 10 && q.pendingCount() > 0; i++) {
        for (const r of releasers.splice(0)) r();
        await timer.pump(10);
      }
      assert.equal(q.pendingCount(), 0);
    } finally {
      q.stop();
    }
  });

  it("keeps default-tenant metrics byte-identical (no tenant labels)", async () => {
    const timer = makeTimer();
    const q = new RetryQueue({ sender: async () => {}, setTimer: timer.setTimer });
    q.start();
    try {
      q.enqueue(item("m1"));
      await timer.pump(10);
      const out = q.renderMetrics();
      assert.ok(!out.includes("tenant"), out);
      assert.ok(
        out.includes(`relay_deliveries_total{endpoint="${ENDPOINT}",status="delivered"} 1`),
        out
      );
    } finally {
      q.stop();
    }
  });

  it("labels tenant series in metrics", async () => {
    const timer = makeTimer();
    const q = new RetryQueue({ sender: async () => {}, setTimer: timer.setTimer });
    q.start();
    try {
      q.enqueue(item("t1", "acme"));
      await timer.pump(10);
      const out = q.renderMetrics();
      assert.ok(
        out.includes(`relay_deliveries_total{endpoint="${ENDPOINT}",tenant="acme",status="delivered"} 1`),
        out
      );
    } finally {
      q.stop();
    }
  });

  it("scopes updateEndpointConfig to the tenant", async () => {
    const timer = makeTimer();
    const q = new RetryQueue({
      sender: async () => {},
      setTimer: timer.setTimer,
      circuitBreaker: {},
    });
    q.start();
    try {
      const field = "circuitBreaker.failureThreshold";
      const acme1 = q.updateEndpointConfig(ENDPOINT, { circuitBreaker: { failureThreshold: 9 } }, "acme");
      assert.equal(acme1.find((c) => c.field === field)?.to, 9);
      // The default tenant's instance is untouched by acme's patch.
      const def = q.updateEndpointConfig(ENDPOINT, { circuitBreaker: { failureThreshold: 7 } });
      assert.equal(def.find((c) => c.field === field)?.from, 5);
      // And acme still has its own value.
      const acme2 = q.updateEndpointConfig(ENDPOINT, { circuitBreaker: { failureThreshold: 11 } }, "acme");
      assert.equal(acme2.find((c) => c.field === field)?.from, 9);
    } finally {
      q.stop();
    }
  });
});

describe("tenant-aware relay server", () => {
  let stub: Server;
  let stubPort: number;
  let receivedBodies: Buffer[] = [];
  let receivedTenantHeaders: Array<string | undefined> = [];

  before(async () => {
    stub = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        receivedBodies.push(Buffer.concat(chunks));
        const h = req.headers["x-tenant-id"];
        receivedTenantHeaders.push(Array.isArray(h) ? h[0] : h);
        res.writeHead(200).end("ok");
      });
    });
    stubPort = await listen(stub);
  });

  after(async () => {
    await close(stub);
  });

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "tenant-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      operatorToken: TOKEN,
      retry: { baseDelayMs: 5, jitterMs: 0, maxAttempts: 2 },
      ...extra,
    });
    return { relay, audit };
  }

  async function waitFor(cond: () => boolean, ms = 8000): Promise<void> {
    const deadline = Date.now() + ms;
    while (!cond() && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok(cond(), "timed out waiting for condition");
  }

  function signed(body: Buffer, tenant?: string): Record<string, string> {
    return {
      "x-signature": signSha256(body, SECRET),
      "content-type": "application/json",
      ...(tenant === undefined ? {} : { [TENANT_ID_HEADER]: tenant }),
    };
  }

  const auth = { authorization: `Bearer ${TOKEN}` };

  it("rejects an invalid x-tenant-id with 400 and audits it", async () => {
    const { relay, audit } = makeRelay();
    const port = await listen(relay);
    try {
      receivedBodies = [];
      const res = await post(port, "/", BODY, signed(BODY, "bad tenant!"));
      assert.equal(res.status, 400);
      await waitFor(() =>
        (audit.readAll() as Array<Record<string, unknown>>).some((e) => e.reason === "invalid_tenant_id")
      );
      const events = audit.readAll() as Array<Record<string, unknown>>;
      const rejected = events.find((e) => e.reason === "invalid_tenant_id");
      assert.equal(rejected?.event, "rejected");
      assert.equal(receivedBodies.length, 0);
    } finally {
      await close(relay);
    }
  });

  it("labels audits with the tenant and strips the header downstream", async () => {
    const { relay, audit } = makeRelay();
    const port = await listen(relay);
    try {
      receivedBodies = [];
      receivedTenantHeaders = [];
      const res = await post(port, "/", BODY, signed(BODY, "acme"));
      assert.equal(res.status, 202);
      await waitFor(() =>
        (audit.readAll() as Array<Record<string, unknown>>).some((e) => e.event === "delivered")
      );
      const events = audit.readAll() as Array<Record<string, unknown>>;
      for (const ev of ["accepted", "delivered"]) {
        const e = events.find((x) => x.event === ev);
        assert.ok(e, `missing ${ev}`);
        assert.equal(e.tenant, "acme");
      }
      // The routing header never leaks to the downstream webhook.
      assert.equal(receivedTenantHeaders.length, 1);
      assert.equal(receivedTenantHeaders[0], undefined);
    } finally {
      await close(relay);
    }
  });

  it("scopes dedup per tenant", async () => {
    const { relay } = makeRelay({ dedup: {} });
    const port = await listen(relay);
    try {
      const first = await post(port, "/", BODY, signed(BODY, "acme"));
      assert.equal(first.status, 202);
      const dup = await post(port, "/", BODY, signed(BODY, "acme"));
      assert.equal(dup.status, 202);
      assert.ok(JSON.parse(dup.text).duplicate, dup.text);
      // Same bytes, another tenant: accepted, not suppressed.
      const other = await post(port, "/", BODY, signed(BODY, "beta"));
      assert.equal(other.status, 202);
      assert.ok(!JSON.parse(other.text).duplicate, other.text);
    } finally {
      await close(relay);
    }
  });

  it("filters operator endpoints by tenant", async () => {
    const { relay, audit } = makeRelay({
      retry: { baseDelayMs: 5, jitterMs: 0, maxAttempts: 1, latency: { sloMs: 60_000 } },
    });
    const port = await listen(relay);
    try {
      // One delivery per tenant; both succeed, so /dead-letter stays empty —
      // use the audit + latency + metrics surfaces here.
      await post(port, "/", BODY, signed(BODY, "acme"));
      await post(port, "/", BODY, signed(BODY, "beta"));
      await waitFor(
        () =>
          (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === "delivered")
            .length >= 2
      );

      const auditAcme = await get(port, "/audit?tenant=acme", auth);
      assert.equal(auditAcme.status, 200);
      const acmeEvents = JSON.parse(auditAcme.text) as Array<Record<string, unknown>>;
      assert.ok(acmeEvents.length > 0);
      assert.ok(acmeEvents.every((e) => e.tenant === "acme"), JSON.stringify(acmeEvents));

      const auditAll = await get(port, "/audit", auth);
      const allEvents = JSON.parse(auditAll.text) as Array<Record<string, unknown>>;
      assert.ok(allEvents.some((e) => e.tenant === "acme"));
      assert.ok(allEvents.some((e) => e.tenant === "beta"));

      const latency = await get(port, "/latency?tenant=beta", auth);
      assert.equal(latency.status, 200);
      const rows = JSON.parse(latency.text) as Array<Record<string, unknown>>;
      assert.ok(rows.length > 0);
      assert.ok(rows.every((r) => r.tenant === "beta"), JSON.stringify(rows));

      const metrics = await get(port, "/metrics", auth);
      assert.equal(metrics.status, 200);
      assert.ok(metrics.text.includes('tenant="acme"'), metrics.text);
      assert.ok(metrics.text.includes('tenant="beta"'), metrics.text);
    } finally {
      await close(relay);
    }
  });

  it("filters the dead-letter list by tenant", async () => {
    // Point the relay at a black hole so everything dead-letters.
    const dir = mkdtempSync(join(tmpdir(), "tenant-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: "http://127.0.0.1:1/hook",
      auditLog: audit,
      operatorToken: TOKEN,
      retry: { baseDelayMs: 5, jitterMs: 0, maxAttempts: 1 },
    });
    const port = await listen(relay);
    try {
      await post(port, "/", BODY, signed(BODY, "acme"));
      await post(port, "/", BODY, signed(BODY, "beta"));
      // Poll the dead-letter list until both tenants' rows land.
      {
        const deadline = Date.now() + 8000;
        let count = 0;
        for (;;) {
          const r = await get(port, "/dead-letter", auth);
          count = (JSON.parse(r.text) as unknown[]).length;
          if (count >= 2 || Date.now() > deadline) break;
          await new Promise((r2) => setTimeout(r2, 50));
        }
        assert.ok(count >= 2, "dead-letter rows never reached 2");
      }
      const acme = await get(port, "/dead-letter?tenant=acme", auth);
      const rows = JSON.parse(acme.text) as Array<Record<string, unknown>>;
      assert.equal(rows.length, 1);
      assert.equal(rows[0].tenant, "acme");
    } finally {
      await close(relay);
    }
  });

  it("filters the SSE stream by tenant", async () => {
    const { relay } = makeRelay();
    const port = await listen(relay);
    const frames: Array<{ event?: string; data?: string }> = [];
    let buf = "";
    const req = httpRequest(
      { host: "127.0.0.1", port, path: "/events?tenant=acme", method: "GET", headers: auth },
      (res) => {
        res.on("data", (c: Buffer) => {
          buf += c.toString();
          let idx: number;
          while ((idx = buf.indexOf("\n\n")) >= 0) {
            const raw = buf.slice(0, idx);
            buf = buf.slice(idx + 2);
            const frame: { event?: string; data?: string } = {};
            for (const line of raw.split("\n")) {
              if (line.startsWith("event:")) frame.event = line.slice(6).trim();
              else if (line.startsWith("data:")) frame.data = line.slice(5).trim();
            }
            frames.push(frame);
          }
        });
      }
    );
    req.on("error", () => {});
    req.end();
    try {
      await new Promise((r) => setTimeout(r, 100));
      await post(port, "/", BODY, signed(BODY, "acme"));
      await post(port, "/", BODY, signed(BODY, "beta"));
      await waitFor(
        () => frames.some((f) => f.event === "delivery" && JSON.parse(f.data ?? "{}").tenant === "acme"),
        8000
      );
      await new Promise((r) => setTimeout(r, 300));
      const deliveries = frames.filter((f) => f.event === "delivery");
      assert.ok(deliveries.length > 0);
      assert.ok(
        deliveries.every((f) => JSON.parse(f.data ?? "{}").tenant === "acme"),
        JSON.stringify(deliveries.map((f) => f.data))
      );
    } finally {
      req.destroy();
      await close(relay);
    }
  });

  it("completion callback receipts carry the tenant", async () => {
    const receipts: Array<{ headers: Record<string, string | undefined>; body: unknown }> = [];
    const cbServer = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        receipts.push({
          headers: {
            "x-tenant-id": undefined,
            "x-relay-signature": req.headers["x-relay-signature"] as string,
          },
          body: JSON.parse(Buffer.concat(chunks).toString()),
        });
        res.writeHead(200).end("ok");
      });
    });
    const cbPort = await listen(cbServer);
    const { relay, audit } = makeRelay({
      completionCallback: { url: `http://127.0.0.1:${cbPort}/cb`, secret: "cb-secret" },
    });
    const port = await listen(relay);
    try {
      await post(port, "/", BODY, signed(BODY, "acme"));
      await waitFor(() => receipts.length > 0);
      const receipt = receipts[0].body as Record<string, unknown>;
      assert.equal(receipt.tenant, "acme");
      assert.equal(receipt.terminalState, "delivered");
    } finally {
      await close(relay);
      await close(cbServer);
    }
  });
});
