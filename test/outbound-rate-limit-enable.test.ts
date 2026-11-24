import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "outbound-rate-limit-enable-test-key";
const opToken = "outbound-rate-limit-enable-op-token";
const URL_A = "http://localhost:9999/a";
const URL_B = "http://localhost:9999/b";

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

async function waitFor(cond: () => boolean, timeoutMs = 5000): Promise<void> {
  const start = Date.now();
  for (;;) {
    if (cond()) return;
    if (Date.now() - start > timeoutMs) throw new Error("waitFor timed out");
    await sleep(10);
  }
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

describe("RetryQueue outbound rate-limit live enable (WR-462)", () => {
  it("enables with both values given; getter and stats report them at once", () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      assert.equal(q.getOutboundRateLimit(), undefined);
      assert.equal(q.getOutboundRateLimitStats(), undefined);
      assert.deepEqual(q.reviseOutboundRateLimit({ refillRps: 10, burst: 50 }), {
        refillRps: 10,
        burst: 50,
      });
      assert.deepEqual(q.getOutboundRateLimit(), { refillRps: 10, burst: 50 });
      assert.deepEqual(q.getOutboundRateLimitStats(), []);
    } finally {
      q.stop();
    }
  });

  it("a single-field patch throws RangeError, stays unconfigured, and can still enable afterwards", () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      assert.throws(() => q.reviseOutboundRateLimit({ burst: 1 }), RangeError);
      assert.throws(() => q.reviseOutboundRateLimit({ refillRps: 1 }), RangeError);
      assert.equal(q.getOutboundRateLimit(), undefined);
      assert.equal(q.getOutboundRateLimitStats(), undefined);
      assert.deepEqual(q.reviseOutboundRateLimit({ refillRps: 2, burst: 4 }), {
        refillRps: 2,
        burst: 4,
      });
      assert.deepEqual(q.getOutboundRateLimit(), { refillRps: 2, burst: 4 });
    } finally {
      q.stop();
    }
  });

  it("an empty patch throws RangeError and stays unconfigured", () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      assert.throws(() => q.reviseOutboundRateLimit({}), RangeError);
      assert.equal(q.getOutboundRateLimit(), undefined);
      assert.equal(q.getOutboundRateLimitStats(), undefined);
    } finally {
      q.stop();
    }
  });

  it("a non-object patch throws RangeError and stays unconfigured", () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      for (const bad of [null, "fast", 42, [1, 2]] as unknown as Array<Record<string, unknown>>) {
        assert.throws(() => q.reviseOutboundRateLimit(bad as never), RangeError);
      }
      assert.equal(q.getOutboundRateLimit(), undefined);
      assert.equal(q.getOutboundRateLimitStats(), undefined);
    } finally {
      q.stop();
    }
  });

  it("illegal values throw RangeError, stay unconfigured, and can still enable afterwards", () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      const bad: Array<{ refillRps: number; burst: number }> = [
        { refillRps: 0, burst: 1 },
        { refillRps: -1, burst: 1 },
        { refillRps: NaN, burst: 1 },
        { refillRps: Infinity, burst: 1 },
        { refillRps: 1, burst: 0 },
        { refillRps: 1, burst: -2 },
        { refillRps: 1, burst: NaN },
        { refillRps: 1, burst: Infinity },
        { refillRps: "10", burst: 1 } as unknown as { refillRps: number; burst: number },
        { refillRps: 1, burst: "5" } as unknown as { refillRps: number; burst: number },
      ];
      for (const patch of bad) {
        assert.throws(() => q.reviseOutboundRateLimit(patch), RangeError);
        assert.equal(q.getOutboundRateLimit(), undefined);
      }
      assert.deepEqual(q.reviseOutboundRateLimit({ refillRps: 3, burst: 6 }), {
        refillRps: 3,
        burst: 6,
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
      q.enqueue(item("pre", URL_A));
      await waitFor(() => calls === 1);
      // Enable: 1 token per 100ms, burst 1. The first burst is
      // available immediately; the next attempt must wait for refill.
      assert.deepEqual(q.reviseOutboundRateLimit({ refillRps: 10, burst: 1 }), {
        refillRps: 10,
        burst: 1,
      });
      q.enqueue(item("b1", URL_A));
      await waitFor(() => calls === 2);
      q.enqueue(item("b2", URL_A));
      await waitFor(() => calls === 3);
      const rows = q.getOutboundRateLimitStats() ?? [];
      const row = rows.find((s) => s.endpoint === URL_A);
      assert.ok(row, "expected a stats row for the endpoint");
      assert.equal(row.throttled, 1);
      assert.equal(row.refillRps, 10);
      assert.equal(row.burst, 1);
      assert.ok(
        q.renderMetrics().includes('relay_ratelimit_throttled_total{endpoint="http://localhost:9999/a"} 1'),
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
      assert.equal(attrs["relay.endpoint"], URL_A);
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
      random: () => 0, // no jitter: delays are exactly retryAfterMs
    });
    q.start();
    try {
      // Hammer the endpoint five times while unlimited.
      for (let i = 0; i < 5; i++) q.enqueue(item(`pre${i}`, URL_A));
      await t.step();
      assert.equal(calls, 5);
      // Enable: 1 token/sec, burst 1. No back-charge — the first
      // post-enable attempt still finds a full bucket.
      assert.deepEqual(q.reviseOutboundRateLimit({ refillRps: 1, burst: 1 }), {
        refillRps: 1,
        burst: 1,
      });
      q.enqueue(item("after1", URL_A));
      await t.step();
      assert.equal(calls, 6);
      // The second post-enable attempt finds the bucket empty.
      q.enqueue(item("after2", URL_A));
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

  it("after the enable, revisions keep WR-330 semantics: partial merge, tighten clamps, widen never tops up", async () => {
    const t = manualTimer();
    let calls = 0;
    const q = new RetryQueue({
      sender: (async () => {
        calls += 1;
      }) as Sender,
      setTimer: t.setTimer,
      random: () => 0,
    });
    q.start();
    try {
      assert.deepEqual(q.reviseOutboundRateLimit({ refillRps: 1, burst: 2 }), {
        refillRps: 1,
        burst: 2,
      });
      q.enqueue(item("a", URL_A));
      q.enqueue(item("b", URL_A));
      await t.step();
      assert.equal(calls, 2); // both fit the burst; the bucket is empty now
      // Partial merge keeps the live refillRps.
      assert.deepEqual(q.reviseOutboundRateLimit({ burst: 1 }), { refillRps: 1, burst: 1 });
      assert.deepEqual(q.getOutboundRateLimit(), { refillRps: 1, burst: 1 });
      // Tighten clamps the (empty) balance: the next attempt waits.
      q.enqueue(item("c", URL_A));
      await t.step();
      assert.equal(calls, 2);
      assert.equal(q.pendingCount(), 1);
      await sleep(1200); // one token refills at 1/sec
      await t.step();
      assert.equal(calls, 3);
      // Widening never tops a bucket up: the balance is still 0, so
      // the next attempt waits for the next refill instead of
      // spending a topped-up burst.
      assert.deepEqual(q.reviseOutboundRateLimit({ burst: 10 }), { refillRps: 1, burst: 10 });
      q.enqueue(item("d", URL_A));
      await t.step();
      assert.equal(calls, 3);
      assert.equal(q.pendingCount(), 1);
      await sleep(1200);
      await t.step();
      assert.equal(calls, 4);
      // Empty / same-value revisions are silent no-ops; an illegal
      // revision throws and leaves the live values untouched.
      assert.deepEqual(q.reviseOutboundRateLimit({ refillRps: 1, burst: 10 }), {
        refillRps: 1,
        burst: 10,
      });
      assert.throws(() => q.reviseOutboundRateLimit({}), RangeError);
      assert.throws(() => q.reviseOutboundRateLimit({ burst: 0 }), RangeError);
      assert.deepEqual(q.getOutboundRateLimit(), { refillRps: 1, burst: 10 });
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
      random: () => 0,
    });
    q.start();
    try {
      assert.equal(q.getOutboundRateLimitStats(), undefined);
      q.reviseOutboundRateLimit({ refillRps: 1, burst: 1 });
      assert.deepEqual(q.getOutboundRateLimitStats(), []);
      q.enqueue(item("a", URL_A));
      await t.step();
      assert.equal(calls, 1);
      assert.deepEqual(q.getOutboundRateLimitStats(), [
        { endpoint: URL_A, throttled: 0, refillRps: 1, burst: 1 },
      ]);
      q.enqueue(item("b", URL_A));
      await t.step();
      assert.equal(calls, 1); // denied: the bucket is empty
      assert.deepEqual(q.getOutboundRateLimitStats(), [
        { endpoint: URL_A, throttled: 1, refillRps: 1, burst: 1 },
      ]);
    } finally {
      q.stop();
    }
  });

  it("a restart restores unconfigured: a fresh queue without the option reports no limit", () => {
    const enabled = new RetryQueue({
      sender: async () => {},
      outboundRateLimit: { refillRps: 1, burst: 1 },
    });
    try {
      assert.deepEqual(enabled.getOutboundRateLimit(), { refillRps: 1, burst: 1 });
    } finally {
      enabled.stop();
    }
    // A fresh instance is the post-restart state: the live-only
    // enable does not survive it.
    const restarted = new RetryQueue({ sender: async () => {} });
    try {
      assert.equal(restarted.getOutboundRateLimit(), undefined);
      assert.equal(restarted.getOutboundRateLimitStats(), undefined);
    } finally {
      restarted.stop();
    }
  });
});

describe("RelayServer outbound rate-limit live enable (WR-462)", () => {
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
    const dir = mkdtempSync(join(tmpdir(), "outbound-rl-enable-"));
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

  it("enable audits previous: null with the exact current values, exactly once, and mounts the getter", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.equal(relay.getOutboundRateLimit, undefined);
    assert.deepEqual(relay.reviseOutboundRateLimit!({ refillRps: 10, burst: 50 }), {
      refillRps: 10,
      burst: 50,
    });
    assert.deepEqual(relay.getOutboundRateLimit!(), { refillRps: 10, burst: 50 });
    const enabled = eventsOf(audit, "outbound_rate_limit_revised");
    assert.equal(enabled.length, 1);
    assert.equal(enabled[0]!.previous, null);
    assert.deepEqual(enabled[0]!.current, { refillRps: 10, burst: 50 });
  });

  it("illegal enable patches throw RangeError, stay unconfigured and unaudited, and can still enable afterwards", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.throws(() => relay.reviseOutboundRateLimit!({ burst: 1 }), RangeError);
    assert.throws(() => relay.reviseOutboundRateLimit!({}), RangeError);
    assert.throws(() => relay.reviseOutboundRateLimit!({ burst: 0, refillRps: 1 }), RangeError);
    assert.throws(
      () => relay.reviseOutboundRateLimit!(null as unknown as { refillRps: number; burst: number }),
      RangeError
    );
    assert.equal(relay.getOutboundRateLimit, undefined);
    assert.equal(eventsOf(audit, "outbound_rate_limit_revised").length, 0);
    assert.deepEqual(relay.reviseOutboundRateLimit!({ refillRps: 2, burst: 4 }), {
      refillRps: 2,
      burst: 4,
    });
    assert.deepEqual(relay.getOutboundRateLimit!(), { refillRps: 2, burst: 4 });
    assert.equal(eventsOf(audit, "outbound_rate_limit_revised").length, 1);
  });

  it("after the enable, revisions audit previous as the enabled values; same-value and illegal revisions audit nothing", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    relay.reviseOutboundRateLimit!({ refillRps: 10, burst: 50 });
    assert.deepEqual(relay.reviseOutboundRateLimit!({ burst: 20 }), {
      refillRps: 10,
      burst: 20,
    });
    const revised = eventsOf(audit, "outbound_rate_limit_revised");
    assert.equal(revised.length, 2);
    assert.deepEqual(revised[1]!.previous, { refillRps: 10, burst: 50 });
    assert.deepEqual(revised[1]!.current, { refillRps: 10, burst: 20 });
    relay.reviseOutboundRateLimit!({ refillRps: 10, burst: 20 });
    assert.equal(eventsOf(audit, "outbound_rate_limit_revised").length, 2);
    assert.throws(() => relay.reviseOutboundRateLimit!({ burst: 0 }), RangeError);
    assert.throws(() => relay.reviseOutboundRateLimit!({}), RangeError);
    assert.equal(eventsOf(audit, "outbound_rate_limit_revised").length, 2);
    assert.deepEqual(relay.getOutboundRateLimit!(), { refillRps: 10, burst: 20 });
  });

  it("a restart restores unconfigured: a fresh relay without the option mounts no getter", async () => {
    const { relay } = makeRelay({
      retry: { outboundRateLimit: { refillRps: 1, burst: 1 } },
    });
    await listen(relay);
    assert.deepEqual(relay.getOutboundRateLimit!(), { refillRps: 1, burst: 1 });
    const { relay: freshRelay } = makeRelay();
    await listen(freshRelay);
    assert.equal(freshRelay.getOutboundRateLimit, undefined);
  });
});
