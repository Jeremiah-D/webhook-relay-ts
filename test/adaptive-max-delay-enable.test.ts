import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "adaptive-max-delay-enable-test-key";
const opToken = "adaptive-max-delay-enable-op-token";
const URL_A = "http://localhost:9999/a";
const URL_B = "http://localhost:9999/b";
const BODY = Buffer.from(JSON.stringify({ event: "adaptive-max-delay-enable.probe" }));

/** Poll until `cond` holds (5s) — a fixed tick count is not a settled signal under load. */
async function waitFor(cond: () => boolean, what: string, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (cond()) return;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error(`timed out waiting for ${what}`);
}

function item(id: string, targetUrl: string) {
  return { id, payload: BODY, targetUrl, headers: {} };
}

/** Queue deliberately *without* an `adaptiveMaxDelay` option, so the WR-456 enable path is the only way a tracker appears. */
function makeQueue(sender: Sender, extra: Record<string, unknown> = {}): RetryQueue {
  return new RetryQueue({
    sender,
    baseDelayMs: 100,
    jitterMs: 0,
    maxDelayMs: 60000,
    maxAttempts: 1,
    ...extra,
  });
}

const defaultsFor = (maxDelayMs: number) => ({
  marginRatio: 0.5,
  floorMs: 1000,
  ceilMs: 4 * maxDelayMs,
  minSamples: 10,
  maxSamplesPerEndpoint: 1024,
  tightenFactor: 0.8,
});

describe("RetryQueue.reviseAdaptiveMaxDelay live enable for an unconfigured queue (WR-456)", () => {
  it("first enable takes the construction defaults — an empty patch enables", () => {
    const q = makeQueue(async () => {});
    q.start();
    try {
      assert.equal(q.getAdaptiveMaxDelayConfig(), undefined);
      assert.deepEqual(q.reviseAdaptiveMaxDelay({}), defaultsFor(60000));
      assert.deepEqual(q.getAdaptiveMaxDelayConfig(), defaultsFor(60000));
      // A fresh tracker has no samples yet.
      assert.deepEqual(q.getAdaptiveMaxDelayStats(), []);
      // Cold endpoints still see the fixed cap.
      assert.equal(q.effectiveRetryConfig(URL_A).maxDelayMs, 60000);
      assert.equal(q.delayForAttempt(10, URL_A), 60000);
    } finally {
      q.stop();
    }
  });

  it("a partial patch uses the explicit knobs exactly and defaults the rest", () => {
    const q = makeQueue(async () => {});
    q.start();
    try {
      assert.deepEqual(
        q.reviseAdaptiveMaxDelay({
          marginRatio: 1,
          floorMs: 500,
          minSamples: 2,
          maxSamplesPerEndpoint: 64,
        }),
        {
          marginRatio: 1,
          floorMs: 500,
          ceilMs: 240000,
          minSamples: 2,
          maxSamplesPerEndpoint: 64,
          tightenFactor: 0.8,
        }
      );
    } finally {
      q.stop();
    }
  });

  it("non-object and illegal patches throw RangeError and leave the queue unconfigured — and it can still enable afterwards", () => {
    const q = makeQueue(async () => {});
    q.start();
    try {
      assert.equal(q.getAdaptiveMaxDelayConfig(), undefined);
      assert.throws(() => q.reviseAdaptiveMaxDelay(null as never), RangeError);
      assert.throws(() => q.reviseAdaptiveMaxDelay("1000" as never), RangeError);
      assert.throws(() => q.reviseAdaptiveMaxDelay([] as never), RangeError);
      assert.throws(() => q.reviseAdaptiveMaxDelay({ marginRatio: -0.1 }), RangeError);
      assert.throws(() => q.reviseAdaptiveMaxDelay({ floorMs: 0 }), RangeError);
      assert.throws(() => q.reviseAdaptiveMaxDelay({ ceilMs: 500 }), RangeError);
      assert.throws(
        () => q.reviseAdaptiveMaxDelay({ floorMs: 5000, ceilMs: 1000 }),
        RangeError
      );
      assert.throws(() => q.reviseAdaptiveMaxDelay({ minSamples: 0 }), RangeError);
      assert.throws(() => q.reviseAdaptiveMaxDelay({ minSamples: 1.5 }), RangeError);
      assert.throws(() => q.reviseAdaptiveMaxDelay({ maxSamplesPerEndpoint: 0 }), RangeError);
      assert.throws(() => q.reviseAdaptiveMaxDelay({ tightenFactor: 0 }), RangeError);
      assert.throws(() => q.reviseAdaptiveMaxDelay({ tightenFactor: 1 }), RangeError);
      assert.throws(() => q.reviseAdaptiveMaxDelay({ tightenFactor: 1.5 }), RangeError);
      // Still unconfigured after every rejection — and the enable path still works.
      assert.equal(q.getAdaptiveMaxDelayConfig(), undefined);
      assert.deepEqual(q.reviseAdaptiveMaxDelay({}), defaultsFor(60000));
    } finally {
      q.stop();
    }
  });

  it("dispatches before the enable are never sampled; the next dispatch after the enable is cold", async () => {
    let delivered = 0;
    const q = makeQueue(async () => {
      delivered++;
      return { statusCode: 200, body: Buffer.alloc(0) };
    });
    q.start();
    try {
      q.enqueue(item("before", URL_A));
      await waitFor(() => delivered === 1, "pre-enable dispatch to run");
      // The pre-enable delivery left no trace: no tracker, no samples.
      assert.deepEqual(q.getAdaptiveMaxDelayStats(), []);
      assert.equal(q.effectiveRetryConfig(URL_A).maxDelayMs, 60000);
      assert.deepEqual(q.reviseAdaptiveMaxDelay({ minSamples: 2, floorMs: 10 }), {
        ...defaultsFor(60000),
        minSamples: 2,
        floorMs: 10,
      });
      q.enqueue(item("after", URL_A));
      await waitFor(() => delivered === 2, "post-enable dispatch to run");
      // Only the post-enable delivery sampled — one sample, still cold.
      await waitFor(
        () => q.getAdaptiveMaxDelayStats()[0]?.samples === 1,
        "post-enable sample to land"
      );
      assert.equal(q.getAdaptiveMaxDelayStats()[0].capMs, 60000);
      assert.equal(q.effectiveRetryConfig(URL_A).maxDelayMs, 60000);
    } finally {
      q.stop();
    }
  });

  it("after the enable, delivered samples derive the p99 cap for the next retry wait", async () => {
    // A ~2s downstream: two samples warm the endpoint, and the cap
    // relaxes from the 60000 cold fallback to p99 * 1.5 (~3000). The
    // 2s sleep dominates timer slop, so the bounds below are stable
    // under load (unlike a ~100ms sleep, whose slop is comparable).
    const q = makeQueue(
      async () => {
        await new Promise((r) => setTimeout(r, 2000));
        return { statusCode: 200, body: Buffer.alloc(0) };
      },
      { maxAttempts: 1 }
    );
    q.start();
    try {
      assert.deepEqual(
        q.reviseAdaptiveMaxDelay({ minSamples: 2, floorMs: 10, marginRatio: 0.5 }),
        { ...defaultsFor(60000), minSamples: 2, floorMs: 10 }
      );
      // Each sample's latency is accepted→delivered, and acceptance is
      // stamped synchronously at enqueue — so the second delivery must
      // not be enqueued until the first sample lands, or the second
      // sample spans both sleeps.
      q.enqueue(item("s1", URL_A));
      await waitFor(() => q.getAdaptiveMaxDelayStats()[0]?.samples === 1, "first sample lands");
      // One sample is still cold (minSamples 2).
      assert.equal(q.getAdaptiveMaxDelayStats()[0].capMs, 60000);
      assert.equal(q.effectiveRetryConfig(URL_A).maxDelayMs, 60000);
      q.enqueue(item("s2", URL_A));
      await waitFor(() => q.getAdaptiveMaxDelayStats()[0]?.samples === 2, "endpoint warms");
      const rows = q.getAdaptiveMaxDelayStats();
      assert.equal(rows.length, 1);
      assert.equal(rows[0].samples, 2);
      // p99 >= the 2000ms sleep, so the cap is p99 * 1.5 >= 3000 —
      // well under the cold fallback of 60000. The upper bound is the
      // proof the cap is p99-derived, not the cold fallback.
      assert.ok(rows[0].p99Ms >= 2000, `p99 ${rows[0].p99Ms} should reflect the ~2000ms samples`);
      assert.ok(rows[0].capMs >= 3000 && rows[0].capMs < 60000, `warm cap ${rows[0].capMs}`);
      // The live cap surfaces through both read points.
      assert.equal(q.effectiveRetryConfig(URL_A).maxDelayMs, rows[0].capMs);
      assert.equal(q.delayForAttempt(10, URL_A), rows[0].capMs);
      // A cold endpoint still sees the fixed cap.
      assert.equal(q.effectiveRetryConfig(URL_B).maxDelayMs, 60000);
      assert.equal(q.delayForAttempt(10, URL_B), 60000);
    } finally {
      q.stop();
    }
  });

  it("a retry armed before the enable keeps its enqueue-time cap", async () => {
    const callTimes: number[] = [];
    let calls = 0;
    const q = makeQueue(
      async () => {
        calls++;
        callTimes.push(Date.now());
        if (calls === 1) throw new Error("boom");
        return { statusCode: 200, body: Buffer.alloc(0) };
      },
      { maxAttempts: 3 }
    );
    q.start();
    try {
      q.enqueue(item("flaky", URL_A));
      await waitFor(() => calls === 1, "first attempt to fail");
      // The retry is already armed at the pre-enable fixed cap
      // (delayForAttempt(1) = min(60000, 100 * 2) = 200ms); enabling
      // now must not disturb it.
      assert.equal(q.delayForAttempt(1, URL_A), 200);
      q.reviseAdaptiveMaxDelay({ minSamples: 2, floorMs: 10 });
      await waitFor(() => calls === 2, "retry to fire");
      const gap = callTimes[1] - callTimes[0];
      assert.ok(gap >= 50 && gap < 1000, `retry gap ${gap}ms should be the armed ~200ms`);
      // The pre-enable item's whole lifecycle is invisible to the new
      // tracker: its accepted record predates the enable (recordAccepted
      // runs only at enqueue, never per retry attempt), so even the
      // post-enable retry success samples nothing — sampling resumes
      // from the next enqueue, not from the next retry.
      await new Promise((r) => setTimeout(r, 300));
      assert.deepEqual(q.getAdaptiveMaxDelayStats(), []);
      assert.equal(q.effectiveRetryConfig(URL_A).maxDelayMs, 60000);
    } finally {
      q.stop();
    }
  });

  it("the ceiling snapshots at enable time: a later maxDelayMs hot-reload moves only the resting cap", () => {
    const q = makeQueue(async () => {});
    q.start();
    try {
      q.reviseAdaptiveMaxDelay({});
      assert.equal(q.getAdaptiveMaxDelayConfig()!.ceilMs, 240000);
      q.updateEndpointConfig(URL_A, { retry: { maxDelayMs: 10000 } });
      assert.equal(q.retryConfig().maxDelayMs, 10000);
      // The ceiling is still the enable-time snapshot…
      assert.equal(q.getAdaptiveMaxDelayConfig()!.ceilMs, 240000);
      // …while a cold endpoint's resting cap follows the live base.
      assert.equal(q.effectiveRetryConfig(URL_B).maxDelayMs, 10000);
      assert.equal(q.delayForAttempt(10, URL_B), 10000);
    } finally {
      q.stop();
    }
  });

  it("a restart returns to unconfigured", () => {
    const q = makeQueue(async () => {});
    q.start();
    q.reviseAdaptiveMaxDelay({ minSamples: 2 });
    assert.equal(q.getAdaptiveMaxDelayConfig()?.minSamples, 2);
    q.stop();
    // A fresh queue built from the same (cap-less) options has no tracker.
    const restarted = makeQueue(async () => {});
    assert.equal(restarted.getAdaptiveMaxDelayConfig(), undefined);
    // …and the enable path works on it again.
    assert.deepEqual(restarted.reviseAdaptiveMaxDelay({}), defaultsFor(60000));
    restarted.stop();
  });

  it("after the enable, a revision still follows WR-335/WR-352 semantics", () => {
    const q = makeQueue(async () => {});
    q.start();
    try {
      q.reviseAdaptiveMaxDelay({ minSamples: 2 });
      assert.deepEqual(q.reviseAdaptiveMaxDelay({ marginRatio: 1 }), {
        ...defaultsFor(60000),
        marginRatio: 1,
        minSamples: 2,
      });
      assert.deepEqual(q.reviseAdaptiveMaxDelay({ maxSamplesPerEndpoint: 64 }), {
        ...defaultsFor(60000),
        marginRatio: 1,
        minSamples: 2,
        maxSamplesPerEndpoint: 64,
      });
      // An empty patch is still a RangeError; landing on the live
      // values is a silent no-op.
      assert.throws(() => q.reviseAdaptiveMaxDelay({}), RangeError);
      assert.deepEqual(q.reviseAdaptiveMaxDelay({ marginRatio: 1 }), {
        ...defaultsFor(60000),
        marginRatio: 1,
        minSamples: 2,
        maxSamplesPerEndpoint: 64,
      });
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer reviseAdaptiveMaxDelay live enable for an unconfigured relay (WR-456)", () => {
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
    const dir = mkdtempSync(join(tmpdir(), "adaptive-max-delay-enable-"));
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

  it("server enable audits previous: null, mounts the getter, and a same-value call audits nothing", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.equal(relay.getAdaptiveMaxDelayConfig, undefined);
    assert.deepEqual(relay.reviseAdaptiveMaxDelay!({ marginRatio: 1 }), {
      ...defaultsFor(60000),
      marginRatio: 1,
    });
    assert.notEqual(relay.getAdaptiveMaxDelayConfig, undefined);
    assert.deepEqual(relay.getAdaptiveMaxDelayConfig!(), {
      ...defaultsFor(60000),
      marginRatio: 1,
    });
    const revised = eventsOf(audit, "adaptive_max_delay_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.deepEqual(revised[0].current, { ...defaultsFor(60000), marginRatio: 1 });
    // Landing exactly on the enabled values audits nothing.
    relay.reviseAdaptiveMaxDelay!({ marginRatio: 1 });
    assert.equal(eventsOf(audit, "adaptive_max_delay_revised").length, 1);
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseAdaptiveMaxDelay!({ tightenFactor: 1 }), RangeError);
    assert.equal(eventsOf(audit, "adaptive_max_delay_revised").length, 1);
    assert.deepEqual(relay.getAdaptiveMaxDelayConfig!(), {
      ...defaultsFor(60000),
      marginRatio: 1,
    });
  });

  it("server enable with an illegal patch leaves the relay unconfigured — and it can still enable afterwards", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.throws(() => relay.reviseAdaptiveMaxDelay!({ marginRatio: -1 }), RangeError);
    assert.throws(() => relay.reviseAdaptiveMaxDelay!({ tightenFactor: 0 }), RangeError);
    assert.throws(() => relay.reviseAdaptiveMaxDelay!(null as never), RangeError);
    assert.equal(relay.getAdaptiveMaxDelayConfig, undefined);
    assert.equal(eventsOf(audit, "adaptive_max_delay_revised").length, 0);
    assert.deepEqual(relay.reviseAdaptiveMaxDelay!({}), defaultsFor(60000));
    const revised = eventsOf(audit, "adaptive_max_delay_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.deepEqual(revised[0].current, defaultsFor(60000));
  });

  it("after the server enable, a live revision audits previous = the enabled values", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    relay.reviseAdaptiveMaxDelay!({});
    assert.deepEqual(relay.reviseAdaptiveMaxDelay!({ marginRatio: 2 }), {
      ...defaultsFor(60000),
      marginRatio: 2,
    });
    const revised = eventsOf(audit, "adaptive_max_delay_revised");
    assert.equal(revised.length, 2);
    assert.deepEqual(revised[1].previous, defaultsFor(60000));
    assert.deepEqual(revised[1].current, { ...defaultsFor(60000), marginRatio: 2 });
  });
});
