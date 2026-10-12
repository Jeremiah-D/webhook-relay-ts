import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { UsageMeter, type TenantUsage } from "../src/usage.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const URL = "http://localhost:9999/hook";
const RELAY_KEY = "relay-secret";
const BODY = Buffer.from(JSON.stringify({ event: "payment.succeeded", id: "pay_1" }));

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
      res.on("end", () =>
        resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
      );
    });
    r.on("error", reject);
    r.end();
  });
}

function postHook(port: number, headers: Record<string, string> = {}, body: Buffer = BODY) {
  return new Promise<number>((resolve, reject) => {
    const r = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path: "/",
        method: "POST",
        headers: { "x-signature": signSha256(body, RELAY_KEY), ...headers },
      },
      (res) => {
        res.resume();
        res.on("end", () => resolve(res.statusCode ?? 0));
      }
    );
    r.on("error", reject);
    r.end(body);
  });
}

function relay(opts: { operatorToken?: string; usage?: object }) {
  const dir = mkdtempSync(join(tmpdir(), "usage-"));
  const audit = new AuditLog(join(dir, "audit.jsonl"));
  const server = createRelayServer({
    secret: RELAY_KEY,
    forwardUrl: URL,
    auditLog: audit,
    operatorToken: opts.operatorToken,
    sender: async () => {},
    ...(opts.usage !== undefined ? { usage: opts.usage } : {}),
  });
  return server;
}

describe("UsageMeter", () => {
  it("records inbound and delivery per tenant; tenant-less bills to default", () => {
    let now = 1_000_000;
    const m = new UsageMeter({ now: () => now });
    m.recordInbound({ tenant: "acme", bytesIn: 100 });
    m.recordInbound({ bytesIn: 50, urgent: true });
    m.recordDeliveryEvent({ type: "delivered", tenant: "acme", bytesOut: 100 });
    m.recordDeliveryEvent({ type: "delivered", bytesOut: 50 });

    const rows = m.snapshot();
    assert.equal(rows.length, 2);
    const acme = rows.find((r) => r.tenant === "acme")!;
    assert.deepEqual(acme, {
      tenant: "acme",
      windowMs: 3_600_000,
      delivered: 1,
      failed: 0,
      retried: 0,
      deadLetter: 0,
      bytesIn: 100,
      bytesOut: 100,
      urgent: 0,
    });
    const def = rows.find((r) => r.tenant === "default")!;
    assert.equal(def.delivered, 1);
    assert.equal(def.bytesIn, 50);
    assert.equal(def.urgent, 1);
    assert.equal(def.bytesOut, 50);
  });

  it("translates retrying/dead_letter into retried+failed / dead_letter+failed", () => {
    const m = new UsageMeter();
    m.recordDeliveryEvent({ type: "retrying", tenant: "acme" });
    m.recordDeliveryEvent({ type: "retrying", tenant: "acme" });
    m.recordDeliveryEvent({ type: "dead_letter", tenant: "acme" });
    const [row] = m.snapshot("acme");
    assert.equal(row.retried, 2);
    assert.equal(row.deadLetter, 1);
    assert.equal(row.failed, 3);
    assert.equal(row.failed, row.retried + row.deadLetter);
    assert.equal(row.delivered, 0);
  });

  it("expires samples outside the rolling window", () => {
    let now = 0;
    const m = new UsageMeter({ windowMs: 60_000, now: () => now });
    m.recordInbound({ tenant: "acme", bytesIn: 10 });
    m.recordDeliveryEvent({ type: "delivered", tenant: "acme", bytesOut: 10 });
    assert.equal(m.snapshot("acme").length, 1);
    now = 60_000; // exactly at the window edge: expired
    assert.deepEqual(m.snapshot("acme"), []);
    assert.deepEqual(m.snapshot(), []);
    assert.equal(m.render(), "");
  });

  it("snapshot(tenant) filters to one tenant", () => {
    const m = new UsageMeter();
    m.recordInbound({ tenant: "a", bytesIn: 1 });
    m.recordInbound({ tenant: "b", bytesIn: 2 });
    assert.equal(m.snapshot("a").length, 1);
    assert.equal(m.snapshot("a")[0].tenant, "a");
    assert.equal(m.snapshot("nope").length, 0);
    const all = m.snapshot();
    assert.deepEqual(
      all.map((r) => r.tenant),
      ["a", "b"]
    );
  });

  it("evicts the least-recently-active tenant past maxTenants", () => {
    let now = 0;
    const m = new UsageMeter({ maxTenants: 2, now: () => now });
    m.recordInbound({ tenant: "a", bytesIn: 1 }); // t=0
    now = 1;
    m.recordInbound({ tenant: "b", bytesIn: 1 }); // t=1
    now = 2;
    m.recordInbound({ tenant: "c", bytesIn: 1 }); // evicts "a"
    assert.deepEqual(
      m.snapshot().map((r) => r.tenant),
      ["b", "c"]
    );
    // Touching "b" makes "c" the eviction victim next.
    now = 3;
    m.recordInbound({ tenant: "b", bytesIn: 1 });
    now = 4;
    m.recordInbound({ tenant: "d", bytesIn: 1 });
    assert.deepEqual(
      m.snapshot().map((r) => r.tenant),
      ["b", "d"]
    );
  });

  it("drops the oldest samples past maxEventsPerTenant", () => {
    let now = 0;
    const m = new UsageMeter({ maxEventsPerTenant: 3, now: () => now });
    for (let i = 0; i < 5; i++) {
      now = i;
      m.recordInbound({ tenant: "acme", bytesIn: 10 });
    }
    const [row] = m.snapshot("acme");
    assert.equal(row.bytesIn, 30); // only the 3 newest survive
  });

  it("rejects invalid options and records", () => {
    assert.throws(() => new UsageMeter({ windowMs: 0 }), RangeError);
    assert.throws(() => new UsageMeter({ windowMs: -5 }), RangeError);
    assert.throws(() => new UsageMeter({ maxTenants: 0 }), RangeError);
    assert.throws(() => new UsageMeter({ maxEventsPerTenant: 1.5 }), RangeError);
    const m = new UsageMeter();
    assert.throws(() => m.recordInbound({ bytesIn: -1 }), RangeError);
    assert.throws(() => m.recordDelivery({ type: "delivered", bytesOut: -1 }), RangeError);
  });

  it("render() emits the documented Prometheus series", () => {
    const m = new UsageMeter();
    assert.equal(m.render(), "");
    m.recordInbound({ tenant: "acme", bytesIn: 128, urgent: true });
    m.recordDeliveryEvent({ type: "delivered", tenant: "acme", bytesOut: 120 });
    m.recordDeliveryEvent({ type: "retrying", tenant: "acme" });
    const out = m.render();
    const line = (name: string, labels: string) =>
      out.split("\n").find((l) => l.startsWith(`${name}{${labels}} `));
    assert.equal(line("relay_tenant_deliveries_total", 'tenant="acme",outcome="delivered"'), 'relay_tenant_deliveries_total{tenant="acme",outcome="delivered"} 1');
    assert.equal(line("relay_tenant_deliveries_total", 'tenant="acme",outcome="failed"'), 'relay_tenant_deliveries_total{tenant="acme",outcome="failed"} 1');
    assert.equal(line("relay_tenant_deliveries_total", 'tenant="acme",outcome="retried"'), 'relay_tenant_deliveries_total{tenant="acme",outcome="retried"} 1');
    assert.equal(line("relay_tenant_deliveries_total", 'tenant="acme",outcome="dead_letter"'), 'relay_tenant_deliveries_total{tenant="acme",outcome="dead_letter"} 0');
    assert.equal(line("relay_tenant_bytes_in_total", 'tenant="acme"'), 'relay_tenant_bytes_in_total{tenant="acme"} 128');
    assert.equal(line("relay_tenant_bytes_out_total", 'tenant="acme"'), 'relay_tenant_bytes_out_total{tenant="acme"} 120');
    assert.equal(line("relay_tenant_urgent_total", 'tenant="acme"'), 'relay_tenant_urgent_total{tenant="acme"} 1');
    assert.match(out, /# TYPE relay_tenant_deliveries_total counter/);
  });

  it("render() escapes label values", () => {
    const m = new UsageMeter();
    // Tenant ids from the server are charset-validated, but the meter
    // itself must not emit broken exposition for arbitrary keys.
    m.recordInbound({ tenant: 'a"b\\c', bytesIn: 1 });
    const out = m.render();
    assert.ok(out.includes('tenant="a\\"b\\\\c"'), out);
  });
});

describe("usage operator surface", () => {
  const AUTH = { authorization: "Bearer op-token" };

  async function waitForDelivered(port: number, tenant: string): Promise<TenantUsage[]> {
    const deadline = Date.now() + 5000;
    for (;;) {
      const res = await get(port, `/usage?tenant=${tenant}`, AUTH);
      assert.equal(res.status, 200);
      const rows = JSON.parse(res.text) as TenantUsage[];
      if (rows.length > 0 && rows[0].delivered >= 1) return rows;
      if (Date.now() > deadline) throw new Error(`timed out waiting for ${tenant} usage`);
      await new Promise((r) => setTimeout(r, 25));
    }
  }

  it("GET /usage reports per-tenant intake and delivery", async () => {
    const server = relay({ operatorToken: "op-token", usage: {} });
    const port = await listen(server);
    try {
      assert.equal(await postHook(port, { "x-tenant-id": "acme" }), 202);
      assert.equal(await postHook(port, { "x-tenant-id": "acme", "x-priority": "urgent" }), 202);
      const rows = await waitForDelivered(port, "acme");
      assert.equal(rows.length, 1);
      const row = rows[0];
      assert.equal(row.tenant, "acme");
      assert.equal(row.delivered, 2);
      assert.equal(row.failed, 0);
      assert.equal(row.bytesIn, BODY.length * 2);
      assert.equal(row.bytesOut, BODY.length * 2);
      assert.equal(row.urgent, 1);
      // Unfiltered view carries the same row; unknown tenant is empty.
      const all = JSON.parse((await get(port, "/usage", AUTH)).text) as TenantUsage[];
      assert.deepEqual(
        all.map((r) => r.tenant),
        ["acme"]
      );
      assert.deepEqual(JSON.parse((await get(port, "/usage?tenant=nope", AUTH)).text), []);
    } finally {
      server.close();
    }
  });

  it("tenant-less requests bill to the default tenant", async () => {
    const server = relay({ operatorToken: "op-token", usage: {} });
    const port = await listen(server);
    try {
      assert.equal(await postHook(port), 202);
      const rows = await waitForDelivered(port, "default");
      assert.equal(rows[0].tenant, "default");
      assert.equal(rows[0].delivered, 1);
    } finally {
      server.close();
    }
  });

  it("usage series appear in the Prometheus exposition", async () => {
    const server = relay({ operatorToken: "op-token", usage: {} });
    const port = await listen(server);
    try {
      assert.equal(await postHook(port, { "x-tenant-id": "acme" }), 202);
      await waitForDelivered(port, "acme");
      const res = await get(port, "/metrics", AUTH);
      assert.equal(res.status, 200);
      assert.ok(
        res.text.includes('relay_tenant_deliveries_total{tenant="acme",outcome="delivered"} 1'),
        res.text
      );
      assert.ok(res.text.includes('relay_tenant_bytes_in_total{tenant="acme"}'), res.text);
    } finally {
      server.close();
    }
  });

  it("fails closed: 404 without operatorToken, 403 on bad bearer, 404 when unconfigured", async () => {
    const noToken = relay({});
    const port1 = await listen(noToken);
    try {
      assert.equal((await get(port1, "/usage")).status, 404);
    } finally {
      noToken.close();
    }
    const unconfigured = relay({ operatorToken: "op-token" });
    const port2 = await listen(unconfigured);
    try {
      assert.equal((await get(port2, "/usage", AUTH)).status, 404);
      const configured = relay({ operatorToken: "op-token", usage: {} });
      const port3 = await listen(configured);
      try {
        assert.equal((await get(port3, "/usage", { authorization: "Bearer wrong" })).status, 403);
        assert.equal((await get(port3, "/usage", AUTH)).status, 200);
      } finally {
        configured.close();
      }
    } finally {
      unconfigured.close();
    }
  });

  it("rejects invalid usage options at startup", () => {
    assert.throws(() => relay({ usage: { windowMs: 0 } }), RangeError);
  });
});
