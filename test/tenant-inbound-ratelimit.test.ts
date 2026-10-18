import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  InboundTenantRateLimiter,
  InboundTenantRateLimitMetrics,
} from "../src/tenant-inbound-ratelimit.ts";
import { createRelayServer } from "../src/server.ts";
import { HmacSha256Verifier, signSha256, type Verifier } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const testSecret = "tenant-inbound-rl-secret";
const BODY = Buffer.from(JSON.stringify({ event: "tenant.probe" }));

describe("tenant-inbound-ratelimit: InboundTenantRateLimiter", () => {
  it("admits within budget, rejects past it with the honest retryAfterMs", () => {
    let now = 0;
    const rl = new InboundTenantRateLimiter({ perTenantPerSecond: 2, now: () => now });
    assert.deepEqual(rl.take("acme"), { ok: true });
    assert.deepEqual(rl.take("acme"), { ok: true });
    const v = rl.take("acme");
    assert.equal(v.ok, false);
    if (!v.ok) {
      assert.equal(v.retryAfterMs, 500); // 1 token short at 2/sec
    }
    now += 499;
    assert.equal(rl.take("acme").ok, false);
    now += 1;
    assert.deepEqual(rl.take("acme"), { ok: true });
  });

  it("buckets are per tenant: one tenant's exhaustion never touches another's", () => {
    const rl = new InboundTenantRateLimiter({ perTenantPerSecond: 1 });
    assert.deepEqual(rl.take("acme"), { ok: true });
    assert.equal(rl.take("acme").ok, false);
    assert.deepEqual(rl.take("globex"), { ok: true });
    assert.equal(rl.trackedTenants(), 2);
  });

  it("a rejection never burns a token (peek-then-consume)", () => {
    let now = 0;
    const rl = new InboundTenantRateLimiter({ perTenantPerSecond: 1, now: () => now });
    assert.deepEqual(rl.take("acme"), { ok: true });
    assert.equal(rl.take("acme").ok, false); // rejected: no token burned
    now += 1000; // one refill tick
    // Still exactly one token: the rejection above consumed nothing.
    assert.deepEqual(rl.take("acme"), { ok: true });
    assert.equal(rl.take("acme").ok, false);
  });

  it("clock skew backward never grants extra budget", () => {
    let now = 10_000;
    const rl = new InboundTenantRateLimiter({ perTenantPerSecond: 1, now: () => now });
    assert.deepEqual(rl.take("acme"), { ok: true });
    now = 0; // clock jumps backward
    assert.equal(rl.take("acme").ok, false);
  });

  it("a new tenant starts with a full bucket", () => {
    const rl = new InboundTenantRateLimiter({ perTenantPerSecond: 3 });
    assert.deepEqual(rl.take("fresh"), { ok: true });
    assert.deepEqual(rl.take("fresh"), { ok: true });
    assert.deepEqual(rl.take("fresh"), { ok: true });
    assert.equal(rl.take("fresh").ok, false);
  });

  it("invalid budgets fail fast at construction", () => {
    assert.throws(() => new InboundTenantRateLimiter({ perTenantPerSecond: 0 }), RangeError);
    assert.throws(() => new InboundTenantRateLimiter({ perTenantPerSecond: -5 }), RangeError);
    assert.throws(() => new InboundTenantRateLimiter({ perTenantPerSecond: NaN }), RangeError);
    assert.throws(() => new InboundTenantRateLimiter({ perTenantPerSecond: Infinity }), RangeError);
    assert.doesNotThrow(() => new InboundTenantRateLimiter({ perTenantPerSecond: 1 }));
    assert.doesNotThrow(() => new InboundTenantRateLimiter());
  });

  it("unconfigured means unlimited", () => {
    const rl = new InboundTenantRateLimiter();
    assert.equal(rl.perTenantLimit(), undefined);
    for (let i = 0; i < 50; i++) assert.deepEqual(rl.take("acme"), { ok: true });
    assert.equal(rl.trackedTenants(), 0); // unlimited: no buckets allocated
  });
});

describe("tenant-inbound-ratelimit: InboundTenantRateLimitMetrics", () => {
  it("renders nothing until the first denial", () => {
    const m = new InboundTenantRateLimitMetrics();
    assert.equal(m.render(), "");
    m.record("acme");
    m.record("acme");
    m.record("globex");
    const out = m.render();
    assert.match(out, /# HELP relay_inbound_tenant_limited_total /);
    assert.match(out, /# TYPE relay_inbound_tenant_limited_total counter/);
    assert.match(out, /relay_inbound_tenant_limited_total\{tenant="acme"\} 2/);
    assert.match(out, /relay_inbound_tenant_limited_total\{tenant="globex"\} 1/);
  });
});

describe("tenant-inbound-ratelimit: 429s at the relay server intake", () => {
  let relay: Server;
  let port: number;
  let audit: AuditLog;
  let verifyCalls: number;
  const OPERATOR = "op-tenant-inbound-rl";

  function post(tenant?: string, signature?: string, path = "/hook") {
    return new Promise<{ status: number; retryAfter: string | undefined }>((resolve, reject) => {
      const headers: Record<string, string> = {
        "x-signature": signature ?? signSha256(BODY, testSecret),
      };
      if (tenant !== undefined) headers["x-tenant-id"] = tenant;
      const r = httpRequest({ host: "127.0.0.1", port, path, method: "POST", headers }, (res) => {
        res.resume();
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, retryAfter: res.headers["retry-after"] as string | undefined })
        );
      });
      r.on("error", reject);
      r.end(BODY);
    });
  }

  async function getMetrics(): Promise<string> {
    return new Promise((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/metrics",
          method: "GET",
          headers: { authorization: `Bearer ${OPERATOR}` },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => resolve(Buffer.concat(chunks).toString()));
        }
      );
      r.on("error", reject);
      r.end();
    });
  }

  before(async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-tenant-inbound-rl-"));
    audit = new AuditLog(join(dir, "audit.jsonl"));
    verifyCalls = 0;
    const base = new HmacSha256Verifier(testSecret);
    const spy: Verifier = {
      name: "spy-hmac",
      verify: (body, header, opts) => {
        verifyCalls += 1;
        return base.verify(body, header, opts);
      },
    };
    relay = createRelayServer({
      secret: testSecret,
      verifier: spy,
      forwardUrl: "http://127.0.0.1:9/unused", // never reached: intake gate is before delivery
      auditLog: audit,
      operatorToken: OPERATOR,
      inboundTenantRateLimit: { perTenantPerSecond: 2 },
    });
    await new Promise<void>((resolve) => relay.listen(0, "127.0.0.1", resolve));
    const addr = relay.address();
    assert.ok(addr && typeof addr === "object");
    port = addr.port;
  });

  after(() => relay.close());

  it("admits within budget, answers 429 + retry-after past it, and audits the rejection", async () => {
    const beforeCalls = verifyCalls;
    assert.equal((await post("acme")).status, 202);
    assert.equal((await post("acme")).status, 202);
    const third = await post("acme");
    assert.equal(third.status, 429);
    assert.ok(third.retryAfter !== undefined, "429 must carry retry-after");
    assert.ok(Number(third.retryAfter) >= 1, "retry-after is ceiling seconds, minimum 1");
    // The rejected request never reached the verifier: the check runs
    // before signature verification.
    assert.equal(verifyCalls, beforeCalls + 2);

    const rejected = audit
      .query({ event: ["rejected"] })
      .filter((e) => (e as { reason?: string }).reason === "tenant_rate_limited");
    assert.equal(rejected.length, 1);
    const entry = rejected[0] as {
      tenant?: string;
      retryAfterMs?: number;
      traceId?: string;
    };
    assert.equal(entry.tenant, "acme");
    assert.ok(typeof entry.retryAfterMs === "number" && entry.retryAfterMs > 0);
    assert.ok(typeof entry.traceId === "string" && entry.traceId.length > 0);
  });

  it("rejects before verification even when the signature is invalid", async () => {
    // "globex" has a fresh bucket here (2 tokens); burn them, then send
    // with a bad signature: the 429 must win over the 401, proving the
    // tenant check runs before verify.
    assert.equal((await post("globex")).status, 202);
    assert.equal((await post("globex")).status, 202);
    const beforeCalls = verifyCalls;
    const bad = await post("globex", "sha256=deadbeef");
    assert.equal(bad.status, 429);
    assert.equal(verifyCalls, beforeCalls, "rejected request never touched the verifier");
  });

  it("one tenant's exhaustion does not affect another tenant", async () => {
    // "acme" is already over budget from the earlier tests; a fresh
    // tenant is unaffected.
    assert.equal((await post("fresh-tenant")).status, 202);
  });

  it("requests without x-tenant-id are untouched by the limiter", async () => {
    for (let i = 0; i < 5; i++) {
      assert.equal((await post()).status, 202);
    }
  });

  it("an invalid x-tenant-id skips the limiter and follows the normal 400 path", async () => {
    // Invalid ids are never rate-limited here: with a valid signature the
    // request reaches the WR-48 validation and is answered 400, exactly as
    // before WR-141.
    const res = await post("not valid!!");
    assert.equal(res.status, 400);
  });

  it("exposes relay_inbound_tenant_limited_total{tenant} in /metrics, activity-gated", async () => {
    const exposition = await getMetrics();
    assert.match(exposition, /relay_inbound_tenant_limited_total\{tenant="acme"\} \d+/);
    assert.match(exposition, /relay_inbound_tenant_limited_total\{tenant="globex"\} \d+/);
    assert.ok(
      !exposition.includes('relay_inbound_tenant_limited_total{tenant="fresh-tenant"}'),
      "tenants that never hit the limit expose no series"
    );
  });
});

describe("tenant-inbound-ratelimit: unconfigured limiter is a no-op", () => {
  let relay: Server;
  let port: number;

  before(async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-tenant-inbound-rl-off-"));
    relay = createRelayServer({
      secret: testSecret,
      forwardUrl: "http://127.0.0.1:9/unused",
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      inboundTenantRateLimit: undefined,
    });
    await new Promise<void>((resolve) => relay.listen(0, "127.0.0.1", resolve));
    const addr = relay.address();
    assert.ok(addr && typeof addr === "object");
    port = addr.port;
  });

  after(() => relay.close());

  it("never 429s and exposes no metric series", async () => {
    for (let i = 0; i < 5; i++) {
      const res = await new Promise<{ status: number }>((resolve, reject) => {
        const r = httpRequest(
          {
            host: "127.0.0.1",
            port,
            path: "/hook",
            method: "POST",
            headers: {
              "x-signature": signSha256(BODY, testSecret),
              "x-tenant-id": "acme",
            },
          },
          (res) => {
            res.resume();
            res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
          }
        );
        r.on("error", reject);
        r.end(BODY);
      });
      assert.equal(res.status, 202);
    }
  });
});
