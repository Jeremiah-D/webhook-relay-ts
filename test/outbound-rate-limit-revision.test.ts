import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import { OutboundRateLimiter } from "../src/outbound-ratelimit.ts";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "outbound-rate-limit-revision-test-key";
const opToken = "outbound-rate-limit-revision-op-token";
const URL_A = "http://localhost:9999/a";
const URL_B = "http://localhost:9999/b";

/**
 * Manual timer with single-step control: rate-limit delays re-arm
 * timers, so the tests advance one wave at a time instead of draining
 * everything.
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
    async step() {
      const fns = pending.splice(0);
      for (const f of fns) f();
      await new Promise((r) => setImmediate(r));
    },
  };
}

function item(id: string, targetUrl: string) {
  return { id, payload: Buffer.from("x"), targetUrl, headers: {} };
}

describe("OutboundRateLimiter.retune (WR-330)", () => {
  it("illegal patches throw RangeError and the live values are untouched", () => {
    let now = 1_000;
    const l = new OutboundRateLimiter({ refillRps: 5, burst: 10, now: () => now });
    const bad = [
      { refillRps: 0 },
      { refillRps: -1 },
      { refillRps: NaN },
      { refillRps: Infinity },
      { burst: 0 },
      { burst: -2 },
      { burst: NaN },
      { burst: Infinity },
      { refillRps: "5" as never },
    ];
    for (const patch of bad) {
      assert.throws(() => l.retune(patch), RangeError, JSON.stringify(patch));
    }
    assert.throws(() => l.retune(null as never), RangeError);
    assert.throws(() => l.retune("fast" as never), RangeError);
    assert.equal(l.refillPerSecond(), 5);
    assert.equal(l.burstSize(), 10);
    // The limiter still works at the old values.
    assert.equal(l.take(URL_A).ok, true);
  });

  it("an empty patch is a RangeError and the live values are untouched", () => {
    const l = new OutboundRateLimiter({ refillRps: 5, burst: 10 });
    assert.throws(() => l.retune({}), RangeError);
    assert.equal(l.refillPerSecond(), 5);
    assert.equal(l.burstSize(), 10);
  });

  it("tightening the burst clamps the existing bucket balance instead of refilling it", () => {
    let now = 1_000;
    const l = new OutboundRateLimiter({ refillRps: 1, burst: 3, now: () => now });
    assert.equal(l.take(URL_A).ok, true);
    // Two tokens left; tightening to 1 leaves exactly one token
    // (a reset-to-full implementation would hand out one as well, but
    // the widening case below separates clamp from reset).
    assert.deepEqual(l.retune({ burst: 1 }), { refillRps: 1, burst: 1 });
    assert.equal(l.take(URL_A).ok, true);
    assert.equal(l.take(URL_A).ok, false);
  });

  it("widening never tops a bucket up", () => {
    let now = 1_000;
    const l = new OutboundRateLimiter({ refillRps: 1, burst: 1, now: () => now });
    assert.equal(l.take(URL_A).ok, true); // bucket empty
    assert.deepEqual(l.retune({ burst: 5 }), { refillRps: 1, burst: 5 });
    // Still empty: the wider cap does not grant tokens.
    assert.equal(l.take(URL_A).ok, false);
  });

  it("widening the refill shortens retryAfterMs on the next denial", () => {
    let now = 1_000;
    const l = new OutboundRateLimiter({ refillRps: 1, burst: 1, now: () => now });
    assert.equal(l.take(URL_A).ok, true);
    const denied = l.take(URL_A);
    assert.equal(denied.ok, false);
    if (!denied.ok) assert.equal(denied.retryAfterMs, 1000);
    l.retune({ refillRps: 10 });
    const deniedFast = l.take(URL_A);
    assert.equal(deniedFast.ok, false);
    if (!deniedFast.ok) assert.equal(deniedFast.retryAfterMs, 100);
  });

  it("a same-value revision is a silent no-op returning the live values", () => {
    const l = new OutboundRateLimiter({ refillRps: 5, burst: 10 });
    assert.deepEqual(l.retune({ refillRps: 5 }), { refillRps: 5, burst: 10 });
    assert.deepEqual(l.retune({ burst: 10 }), { refillRps: 5, burst: 10 });
    assert.deepEqual(l.retune({ refillRps: 5, burst: 10 }), { refillRps: 5, burst: 10 });
    assert.equal(l.refillPerSecond(), 5);
    assert.equal(l.burstSize(), 10);
  });

  it("one shared pair moves every endpoint's bucket at once", () => {
    let now = 1_000;
    const l = new OutboundRateLimiter({ refillRps: 1, burst: 2, now: () => now });
    assert.equal(l.take(URL_A).ok, true);
    assert.equal(l.take(URL_A).ok, true); // A empty
    assert.equal(l.take(URL_B).ok, true); // B has one token left
    l.retune({ burst: 1 });
    assert.equal(l.take(URL_A).ok, false); // still empty
    assert.equal(l.take(URL_B).ok, true); // clamped to one, not refilled
    assert.equal(l.take(URL_B).ok, false);
  });

  it("stats() rows report the live refillRps/burst after a revision", () => {
    let now = 1_000;
    const l = new OutboundRateLimiter({ refillRps: 1, burst: 1, now: () => now });
    assert.equal(l.take(URL_A).ok, true);
    l.retune({ refillRps: 4, burst: 8 });
    assert.deepEqual(l.stats(), [{ endpoint: URL_A, throttled: 0, refillRps: 4, burst: 8 }]);
  });
});

describe("RetryQueue outbound rate-limit revision (WR-330)", () => {
  it("unconfigured: revise throws the must-restart Error, getter returns undefined", () => {
    const q = new RetryQueue({ sender: async () => {} });
    assert.equal(q.getOutboundRateLimit(), undefined);
    assert.throws(
      () => q.reviseOutboundRateLimit({ burst: 1 }),
      /not configured — enabling it requires a restart/
    );
    assert.equal(q.getOutboundRateLimitStats(), undefined);
  });

  it("getter tracks revisions and stats rows follow the live values", () => {
    let now = 0;
    const q = new RetryQueue({
      sender: async () => {},
      outboundRateLimit: { refillRps: 1, burst: 1, now: () => now },
    });
    assert.deepEqual(q.getOutboundRateLimit(), { refillRps: 1, burst: 1 });
    assert.deepEqual(q.reviseOutboundRateLimit({ refillRps: 4, burst: 8 }), {
      refillRps: 4,
      burst: 8,
    });
    assert.deepEqual(q.getOutboundRateLimit(), { refillRps: 4, burst: 8 });
    q.stop();
  });

  it("an already-rescheduled delivery is re-judged at the new rate on its next take", async () => {
    let now = 0;
    const t = manualTimer();
    let calls = 0;
    const sender: Sender = async () => {
      calls += 1;
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      random: () => 0, // no jitter: delays are exactly retryAfterMs
      outboundRateLimit: { refillRps: 1, burst: 1, now: () => now }, // 1 token/sec
    });
    q.enqueue(item("a", URL_A));
    q.enqueue(item("b", URL_A));
    q.start();
    await t.step();
    assert.equal(calls, 1); // only "a" fit the budget; "b" is delayed
    assert.equal(q.pendingCount(), 1);
    // Tighten the refill to one token per 10s before "b" re-checks.
    q.reviseOutboundRateLimit({ refillRps: 0.1 });
    now += 1000; // one second at the OLD rate would refill — at the new rate it does not
    await t.step();
    assert.equal(calls, 1); // "b" re-checked at the new rate and stayed delayed
    assert.equal(q.pendingCount(), 1);
    now += 10000; // ten seconds at the new rate refills one token
    await t.step();
    assert.equal(calls, 2);
    assert.equal(q.pendingCount(), 0);
    q.stop();
  });

  it("an in-flight attempt is unaffected by a revision", async () => {
    const t = manualTimer();
    let calls = 0;
    let release!: () => void;
    const sender: Sender = async () => {
      calls += 1;
      await new Promise<void>((r) => {
        release = r;
      });
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      random: () => 0,
      outboundRateLimit: { refillRps: 1, burst: 1 },
    });
    q.enqueue(item("a", URL_A));
    q.start();
    await t.step();
    assert.equal(calls, 1); // attempt in flight
    q.reviseOutboundRateLimit({ refillRps: 10, burst: 10 });
    release();
    await new Promise((r) => setImmediate(r));
    await new Promise((r) => setImmediate(r));
    assert.equal(calls, 1); // delivered exactly once, no duplicate
    assert.equal(q.pendingCount(), 0);
    q.stop();
  });
});

describe("RelayServer outbound rate-limit revision (WR-330)", () => {
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
    const dir = mkdtempSync(join(tmpdir(), "outbound-rl-revision-"));
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

  it("revision audits previous/current with the construction values first; same-value is a silent no-op", async () => {
    const { relay, audit } = makeRelay({
      retry: { outboundRateLimit: { refillRps: 10, burst: 50 } },
    });
    await listen(relay);
    assert.deepEqual(relay.reviseOutboundRateLimit!({ burst: 20 }), {
      refillRps: 10,
      burst: 20,
    });
    let revised = eventsOf(audit, "outbound_rate_limit_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, { refillRps: 10, burst: 50 });
    assert.deepEqual(revised[0].current, { refillRps: 10, burst: 20 });
    // Landing exactly on the live values audits nothing.
    relay.reviseOutboundRateLimit!({ refillRps: 10, burst: 20 });
    assert.equal(eventsOf(audit, "outbound_rate_limit_revised").length, 1);
    assert.deepEqual(relay.getOutboundRateLimit!(), { refillRps: 10, burst: 20 });
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseOutboundRateLimit!({ burst: 0 }), RangeError);
    assert.throws(() => relay.reviseOutboundRateLimit!({}), RangeError);
    assert.equal(eventsOf(audit, "outbound_rate_limit_revised").length, 1);
    assert.equal(relay.getOutboundRateLimit!().burst, 20);
  });

  it("unconfigured relay: revise throws the must-restart Error and the getter is not mounted", async () => {
    const { relay } = makeRelay();
    await listen(relay);
    assert.equal(relay.getOutboundRateLimit, undefined);
    assert.throws(
      () => relay.reviseOutboundRateLimit!({ burst: 1 }),
      /not configured — enabling it requires a restart/
    );
  });

  it("server getter reflects revisions made through the server", async () => {
    const { relay } = makeRelay({
      retry: { outboundRateLimit: { refillRps: 2, burst: 4 } },
    });
    await listen(relay);
    assert.deepEqual(relay.getOutboundRateLimit!(), { refillRps: 2, burst: 4 });
    relay.reviseOutboundRateLimit!({ refillRps: 9 });
    assert.deepEqual(relay.getOutboundRateLimit!(), { refillRps: 9, burst: 4 });
  });
});
