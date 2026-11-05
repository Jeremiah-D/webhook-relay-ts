import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { InboundTenantRateLimiter } from "../src/tenant-inbound-ratelimit.ts";
import { createRelayServer } from "../src/server.ts";
import { HmacSha256Verifier, signSha256, type Verifier } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "inbound-tenant-rate-limit-revision-test-key";
const opToken = "inbound-tenant-rate-limit-revision-op-token";
const URL_A = "http://localhost:9999/a";
const BODY = Buffer.from(JSON.stringify({ event: "tenant.probe" }));

describe("InboundTenantRateLimiter.retune (WR-332)", () => {
  it("tightening clamps the existing bucket balance and the next take 429s sooner", () => {
    let now = 0;
    const rl = new InboundTenantRateLimiter({ perTenantPerSecond: 3, now: () => now });
    assert.deepEqual(rl.take("acme"), { ok: true }); // two tokens left
    assert.equal(rl.retune(1), 1); // clamped to one, not left at two
    assert.deepEqual(rl.take("acme"), { ok: true });
    assert.equal(rl.take("acme").ok, false);

    // Clamping below one token makes the very next take fail at once.
    const rl2 = new InboundTenantRateLimiter({ perTenantPerSecond: 2, now: () => now });
    assert.deepEqual(rl2.take("acme"), { ok: true }); // one token left
    assert.equal(rl2.retune(0.5), 0.5); // clamped to half a token
    const denied = rl2.take("acme");
    assert.equal(denied.ok, false);
    if (!denied.ok) assert.equal(denied.retryAfterMs, 1000); // half a token short at 0.5/sec
  });

  it("widening never tops a bucket up", () => {
    let now = 0;
    const rl = new InboundTenantRateLimiter({ perTenantPerSecond: 1, now: () => now });
    assert.deepEqual(rl.take("acme"), { ok: true }); // bucket empty
    assert.equal(rl.retune(5), 5);
    // Still empty: the wider cap does not grant tokens.
    assert.equal(rl.take("acme").ok, false);
  });

  it("widening shortens retryAfterMs on the next denial", () => {
    let now = 0;
    const rl = new InboundTenantRateLimiter({ perTenantPerSecond: 1, now: () => now });
    assert.deepEqual(rl.take("acme"), { ok: true });
    const denied = rl.take("acme");
    assert.equal(denied.ok, false);
    if (!denied.ok) assert.equal(denied.retryAfterMs, 1000);
    rl.retune(10);
    const deniedFast = rl.take("acme");
    assert.equal(deniedFast.ok, false);
    if (!deniedFast.ok) assert.equal(deniedFast.retryAfterMs, 100);
  });

  it("disabling passes everything and re-enabling restores limiting", () => {
    let now = 0;
    const rl = new InboundTenantRateLimiter({ perTenantPerSecond: 1, now: () => now });
    assert.deepEqual(rl.take("acme"), { ok: true }); // bucket empty
    assert.equal(rl.retune(undefined), undefined);
    for (let i = 0; i < 50; i++) assert.deepEqual(rl.take("acme"), { ok: true });
    assert.equal(rl.trackedTenants(), 1); // disabled buckets are retained, not dropped
    assert.equal(rl.perTenantLimit(), undefined);
    // The clock advanced while disabled, but re-enabling re-clamps via
    // refill: exactly one token, never the five seconds' worth.
    now += 5000;
    assert.equal(rl.retune(1), 1);
    assert.deepEqual(rl.take("acme"), { ok: true });
    assert.equal(rl.take("acme").ok, false);
    now += 1000;
    assert.deepEqual(rl.take("acme"), { ok: true });
  });

  it("illegal values throw RangeError with the construction text and the live value is untouched", () => {
    let now = 0;
    const rl = new InboundTenantRateLimiter({ perTenantPerSecond: 2, now: () => now });
    assert.deepEqual(rl.take("acme"), { ok: true }); // one token left
    const bad = [0, -1, NaN, Infinity, "5" as never, null as never];
    for (const value of bad) {
      assert.throws(() => rl.retune(value), RangeError, JSON.stringify(value));
    }
    assert.throws(
      () => rl.retune(0),
      /perTenantPerSecond must be a finite number > 0, got 0/
    );
    assert.equal(rl.perTenantLimit(), 2);
    // The limiter still works at the old value, with the old balance.
    assert.deepEqual(rl.take("acme"), { ok: true });
    assert.equal(rl.take("acme").ok, false);
  });

  it("a same-value revision is a silent no-op, including undefined == undefined", () => {
    const rl = new InboundTenantRateLimiter({ perTenantPerSecond: 2 });
    assert.equal(rl.retune(2), 2);
    assert.equal(rl.perTenantLimit(), 2);
    const unlim = new InboundTenantRateLimiter();
    assert.equal(unlim.retune(undefined), undefined);
    assert.equal(unlim.perTenantLimit(), undefined);
    for (let i = 0; i < 5; i++) assert.deepEqual(unlim.take("acme"), { ok: true });
  });

  it("one shared value moves every tenant's bucket at once, buckets stay independent", () => {
    let now = 0;
    const rl = new InboundTenantRateLimiter({ perTenantPerSecond: 3, now: () => now });
    assert.deepEqual(rl.take("acme"), { ok: true }); // acme: two left
    assert.deepEqual(rl.take("globex"), { ok: true });
    assert.deepEqual(rl.take("globex"), { ok: true }); // globex: one left
    rl.retune(1); // both clamped to one
    assert.deepEqual(rl.take("acme"), { ok: true });
    assert.equal(rl.take("acme").ok, false);
    assert.deepEqual(rl.take("globex"), { ok: true });
    assert.equal(rl.take("globex").ok, false);
    // Widening refills each bucket independently at the new rate.
    rl.retune(2);
    now += 500; // half a second at 2/sec refills one token per bucket
    assert.deepEqual(rl.take("acme"), { ok: true });
    assert.equal(rl.take("acme").ok, false);
    assert.deepEqual(rl.take("globex"), { ok: true });
    assert.equal(rl.take("globex").ok, false);
  });
});

describe("RelayServer inbound tenant rate-limit revision (WR-332)", () => {
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

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "inbound-tenant-rl-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: signingKey,
      forwardUrl: URL_A,
      auditLog: audit,
      operatorToken: opToken,
      sender: async () => ({ statusCode: 200, body: Buffer.from("ok") }),
      retry: { baseDelayMs: 5, jitterMs: 0, maxAttempts: 2 },
      ...extra,
    });
    servers.push(relay);
    return { relay, audit };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  function post(port: number, tenant?: string, signature?: string) {
    return new Promise<{ status: number; retryAfter: string | undefined }>((resolve, reject) => {
      const headers: Record<string, string> = {
        "x-signature": signature ?? signSha256(BODY, signingKey),
      };
      if (tenant !== undefined) headers["x-tenant-id"] = tenant;
      const r = httpRequest({ host: "127.0.0.1", port, path: "/hook", method: "POST", headers }, (res) => {
        res.resume();
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, retryAfter: res.headers["retry-after"] as string | undefined })
        );
      });
      r.on("error", reject);
      r.end(BODY);
    });
  }

  function getMetrics(port: number): Promise<string> {
    return new Promise((resolve, reject) => {
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
          res.on("end", () => resolve(Buffer.concat(chunks).toString()));
        }
      );
      r.on("error", reject);
      r.end();
    });
  }

  function rejectedEntries(audit: AuditLog): Array<Record<string, unknown>> {
    return (audit.query({ event: ["rejected"] }) as Array<Record<string, unknown>>).filter(
      (e) => e.reason === "tenant_rate_limited"
    );
  }

  it("revision audits previous/current with the construction value first and null for unlimited; same-value is a silent no-op", async () => {
    const { relay, audit } = makeRelay({
      inboundTenantRateLimit: { perTenantPerSecond: 2 },
    });
    await listen(relay);
    assert.equal(relay.getInboundTenantRateLimit!(), 2);
    assert.equal(relay.reviseInboundTenantRateLimit!(4), 4);
    let revised = eventsOf(audit, "inbound_tenant_rate_limit_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, 2);
    assert.equal(revised[0].current, 4);
    // Disabling: current is null (unlimited), not undefined — JSON-safe.
    assert.equal(relay.reviseInboundTenantRateLimit!(undefined), undefined);
    revised = eventsOf(audit, "inbound_tenant_rate_limit_revised");
    assert.equal(revised.length, 2);
    assert.equal(revised[1].previous, 4);
    assert.equal(revised[1].current, null);
    // Re-enabling from unlimited: previous is null.
    assert.equal(relay.reviseInboundTenantRateLimit!(3), 3);
    revised = eventsOf(audit, "inbound_tenant_rate_limit_revised");
    assert.equal(revised.length, 3);
    assert.equal(revised[2].previous, null);
    assert.equal(revised[2].current, 3);
    // Landing exactly on the live value audits nothing.
    relay.reviseInboundTenantRateLimit!(3);
    assert.equal(eventsOf(audit, "inbound_tenant_rate_limit_revised").length, 3);
    assert.equal(relay.getInboundTenantRateLimit!(), 3);
    // An illegal value throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseInboundTenantRateLimit!(0), RangeError);
    assert.throws(() => relay.reviseInboundTenantRateLimit!(NaN), RangeError);
    assert.equal(eventsOf(audit, "inbound_tenant_rate_limit_revised").length, 3);
    assert.equal(relay.getInboundTenantRateLimit!(), 3);
  });

  it("unconfigured relay: revise throws the must-restart Error and the getter is not mounted", async () => {
    const { relay } = makeRelay();
    await listen(relay);
    assert.equal(relay.getInboundTenantRateLimit, undefined);
    assert.throws(
      () => relay.reviseInboundTenantRateLimit!(2),
      /not configured — enabling it requires a restart/
    );
    assert.throws(
      () => relay.reviseInboundTenantRateLimit!(undefined),
      /not configured — enabling it requires a restart/
    );
  });

  it("a 429's retry-after follows the new rate; already-sent values are not recomputed", async () => {
    let now = 0;
    const { relay, audit } = makeRelay({
      inboundTenantRateLimit: { perTenantPerSecond: 1, now: () => now },
    });
    const port = await listen(relay);
    assert.equal((await post(port, "acme")).status, 202);
    const denied1 = await post(port, "acme");
    assert.equal(denied1.status, 429);
    assert.equal(denied1.retryAfter, "1");
    let rejected = rejectedEntries(audit);
    assert.equal(rejected.length, 1);
    assert.equal(rejected[0].retryAfterMs, 1000); // one token short at 1/sec
    // Widen to 10/sec: the next denial is recomputed at the new rate.
    relay.reviseInboundTenantRateLimit!(10);
    const denied2 = await post(port, "acme");
    assert.equal(denied2.status, 429);
    rejected = rejectedEntries(audit);
    assert.equal(rejected.length, 2);
    assert.equal(rejected[1].retryAfterMs, 100);
    // The first denial's recorded value is untouched by the revision.
    assert.equal(rejected[0].retryAfterMs, 1000);
  });

  it("over-limit requests never touch the verifier, before or after a revision", async () => {
    let now = 0;
    let verifyCalls = 0;
    const base = new HmacSha256Verifier(signingKey);
    const spy: Verifier = {
      name: "spy-hmac",
      verify: (body, header, opts) => {
        verifyCalls += 1;
        return base.verify(body, header, opts);
      },
    };
    const { relay } = makeRelay({
      verifier: spy,
      inboundTenantRateLimit: { perTenantPerSecond: 2, now: () => now },
    });
    const port = await listen(relay);
    assert.equal((await post(port, "acme")).status, 202);
    assert.equal((await post(port, "acme")).status, 202);
    assert.equal(verifyCalls, 2);
    // Tighten with the bucket already empty: the next request is still
    // rejected before verification.
    relay.reviseInboundTenantRateLimit!(1);
    const beforeCalls = verifyCalls;
    assert.equal((await post(port, "acme")).status, 429);
    assert.equal(verifyCalls, beforeCalls, "rejected request never touched the verifier");
  });

  it("metrics sequence shape is unchanged by a revision", async () => {
    let now = 0;
    const { relay } = makeRelay({
      inboundTenantRateLimit: { perTenantPerSecond: 1, now: () => now },
    });
    const port = await listen(relay);
    assert.equal((await post(port, "acme")).status, 202);
    assert.equal((await post(port, "acme")).status, 429);
    relay.reviseInboundTenantRateLimit!(2);
    // Still denied (bucket empty at the new rate with no time elapsed),
    // and the denial still lands on the same series.
    assert.equal((await post(port, "acme")).status, 429);
    const exposition = await getMetrics(port);
    assert.match(exposition, /relay_inbound_tenant_limited_total\{tenant="acme"\} 2/);
    // HELP + TYPE + one data row: no new series, no shape change.
    assert.equal(exposition.match(/relay_inbound_tenant_limited_total/g)?.length, 3);
  });
});
