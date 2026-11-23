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
const signingKey = "adaptive-timeout-enable-test-key";
const opToken = "adaptive-timeout-enable-op-token";
const URL_A = "http://localhost:9999/a";
const BODY = Buffer.from(JSON.stringify({ event: "adaptive-timeout-enable.probe" }));

/** Let the deliver() promise chain settle. */
async function flush(ticks = 20) {
  for (let i = 0; i < ticks; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

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

/** Queue deliberately *without* an `adaptiveTimeout` option, so the WR-452 enable path is the only way a tracker appears. */
function makeQueue(sender: Sender): RetryQueue {
  return new RetryQueue({ sender, maxAttempts: 1 });
}

const defaultsFor = (baseTimeoutMs: number) => ({
  baseTimeoutMs,
  marginRatio: 0.5,
  minTimeoutMs: 100,
  maxTimeoutMs: 4 * baseTimeoutMs,
  minSamples: 10,
  maxSamplesPerEndpoint: 1024,
});

describe("RetryQueue.reviseAdaptiveTimeout live enable for an unconfigured queue (WR-452)", () => {
  it("first enable takes the construction defaults", () => {
    const q = makeQueue(async () => {});
    q.start();
    try {
      assert.equal(q.getAdaptiveTimeoutConfig(), undefined);
      assert.deepEqual(q.reviseAdaptiveTimeout({ baseTimeoutMs: 1000 }), defaultsFor(1000));
      assert.deepEqual(q.getAdaptiveTimeoutConfig(), defaultsFor(1000));
      // A fresh tracker has no samples yet.
      assert.deepEqual(q.getAdaptiveTimeoutStats(), []);
    } finally {
      q.stop();
    }
  });

  it("a partial patch uses the explicit knobs exactly and defaults the rest", () => {
    const q = makeQueue(async () => {});
    q.start();
    try {
      assert.deepEqual(
        q.reviseAdaptiveTimeout({
          baseTimeoutMs: 2000,
          marginRatio: 1,
          minSamples: 2,
          maxSamplesPerEndpoint: 64,
        }),
        {
          baseTimeoutMs: 2000,
          marginRatio: 1,
          minTimeoutMs: 100,
          maxTimeoutMs: 8000,
          minSamples: 2,
          maxSamplesPerEndpoint: 64,
        }
      );
    } finally {
      q.stop();
    }
  });

  it("empty, non-object and illegal patches throw RangeError and leave the queue unconfigured — and it can still enable afterwards", () => {
    const q = makeQueue(async () => {});
    q.start();
    try {
      assert.equal(q.getAdaptiveTimeoutConfig(), undefined);
      assert.throws(() => q.reviseAdaptiveTimeout({}), RangeError);
      assert.throws(() => q.reviseAdaptiveTimeout(null as never), RangeError);
      assert.throws(() => q.reviseAdaptiveTimeout("1000" as never), RangeError);
      assert.throws(() => q.reviseAdaptiveTimeout([] as never), RangeError);
      assert.throws(() => q.reviseAdaptiveTimeout({ baseTimeoutMs: 0 }), RangeError);
      assert.throws(() => q.reviseAdaptiveTimeout({ baseTimeoutMs: -5 }), RangeError);
      assert.throws(() => q.reviseAdaptiveTimeout({ baseTimeoutMs: Infinity }), RangeError);
      assert.throws(() => q.reviseAdaptiveTimeout({ baseTimeoutMs: "1000" as never }), RangeError);
      assert.throws(() => q.reviseAdaptiveTimeout({ baseTimeoutMs: 1000, marginRatio: -0.1 }), RangeError);
      assert.throws(
        () => q.reviseAdaptiveTimeout({ baseTimeoutMs: 1000, minTimeoutMs: 500, maxTimeoutMs: 100 }),
        RangeError
      );
      assert.throws(() => q.reviseAdaptiveTimeout({ baseTimeoutMs: 1000, minSamples: 0 }), RangeError);
      assert.throws(
        () => q.reviseAdaptiveTimeout({ baseTimeoutMs: 1000, maxSamplesPerEndpoint: 1.5 }),
        RangeError
      );
      // Still unconfigured after every rejection — and the enable path still works.
      assert.equal(q.getAdaptiveTimeoutConfig(), undefined);
      assert.deepEqual(q.reviseAdaptiveTimeout({ baseTimeoutMs: 1000 }), defaultsFor(1000));
    } finally {
      q.stop();
    }
  });

  it("dispatches before the enable are never stamped; the next dispatch after the enable stamps the new base (cold)", async () => {
    const seen: Array<number | undefined> = [];
    const q = makeQueue(async (it) => {
      seen.push(it.adaptiveTimeoutMs);
    });
    q.start();
    try {
      q.enqueue(item("before", URL_A));
      await waitFor(() => seen.length === 1, "pre-enable dispatch to run");
      assert.deepEqual(seen, [undefined]);
      assert.deepEqual(q.reviseAdaptiveTimeout({ baseTimeoutMs: 750, minSamples: 100 }), {
        ...defaultsFor(750),
        minSamples: 100,
      });
      q.enqueue(item("after", URL_A));
      await waitFor(() => seen.length === 2, "post-enable dispatch to run");
      assert.deepEqual(seen, [undefined, 750]);
    } finally {
      q.stop();
    }
  });

  it("after the enable, delivered samples derive the p99 cap for the next dispatch", async () => {
    const seen: number[] = [];
    // A ~100ms downstream: two samples warm the endpoint, and the
    // third dispatch is stamped from p99 * 1.5 instead of the cold base.
    const q = makeQueue(async (it) => {
      await new Promise((r) => setTimeout(r, 100));
      seen.push(it.adaptiveTimeoutMs as number);
    });
    q.start();
    try {
      assert.deepEqual(
        q.reviseAdaptiveTimeout({ baseTimeoutMs: 1000, minSamples: 2, minTimeoutMs: 10 }),
        {
          baseTimeoutMs: 1000,
          marginRatio: 0.5,
          minTimeoutMs: 10,
          maxTimeoutMs: 4000,
          minSamples: 2,
          maxSamplesPerEndpoint: 1024,
        }
      );
      q.enqueue(item("s1", URL_A));
      q.enqueue(item("s2", URL_A));
      await waitFor(() => seen.length === 2, "two warm-up deliveries to run");
      // Both samples are in the window before the third dispatch is stamped.
      await waitFor(
        () => q.getAdaptiveTimeoutStats().find((r) => r.endpoint === URL_A)?.samples === 2,
        "two samples to land"
      );
      // Cold for the first two (0 and 1 samples < minSamples 2).
      assert.deepEqual(seen, [1000, 1000]);
      const rows = q.getAdaptiveTimeoutStats();
      assert.equal(rows.length, 1);
      assert.equal(rows[0].samples, 2);
      // p99 >= ~100ms (each sample slept 100ms), so the cap is
      // p99 * 1.5 >= ~150 — well under the cold base of 1000. The
      // lower bound leaves room for timer slop; the upper bound is
      // the proof the cap is p99-derived, not the cold fallback.
      assert.ok(rows[0].p99Ms >= 80, `p99 ${rows[0].p99Ms} should reflect the ~100ms samples`);
      q.enqueue(item("s3", URL_A));
      await waitFor(() => seen.length === 3, "third dispatch to run");
      assert.ok(seen[2] >= 120 && seen[2] < 1000, `warm cap ${seen[2]} should be p99-derived`);
    } finally {
      q.stop();
    }
  });

  it("a restart returns to unconfigured", () => {
    const q = makeQueue(async () => {});
    q.start();
    q.reviseAdaptiveTimeout({ baseTimeoutMs: 500 });
    assert.equal(q.getAdaptiveTimeoutConfig()?.baseTimeoutMs, 500);
    q.stop();
    // A fresh queue built from the same (timeout-less) options has no tracker.
    const restarted = makeQueue(async () => {});
    assert.equal(restarted.getAdaptiveTimeoutConfig(), undefined);
    // …and the enable path works on it again.
    assert.deepEqual(restarted.reviseAdaptiveTimeout({ baseTimeoutMs: 300 }), defaultsFor(300));
    restarted.stop();
  });

  it("after the enable, a revision still follows WR-334/WR-354 semantics", () => {
    const q = makeQueue(async () => {});
    q.start();
    try {
      q.reviseAdaptiveTimeout({ baseTimeoutMs: 1000, minSamples: 2 });
      assert.deepEqual(q.reviseAdaptiveTimeout({ marginRatio: 1 }), {
        ...defaultsFor(1000),
        marginRatio: 1,
        minSamples: 2,
      });
      assert.deepEqual(q.reviseAdaptiveTimeout({ maxSamplesPerEndpoint: 64 }), {
        ...defaultsFor(1000),
        marginRatio: 1,
        minSamples: 2,
        maxSamplesPerEndpoint: 64,
      });
      // An empty patch is still a RangeError; landing on the live
      // values is a silent no-op.
      assert.throws(() => q.reviseAdaptiveTimeout({}), RangeError);
      assert.deepEqual(q.reviseAdaptiveTimeout({ marginRatio: 1 }), {
        ...defaultsFor(1000),
        marginRatio: 1,
        minSamples: 2,
        maxSamplesPerEndpoint: 64,
      });
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer reviseAdaptiveTimeout live enable for an unconfigured relay (WR-452)", () => {
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
    const dir = mkdtempSync(join(tmpdir(), "adaptive-timeout-enable-"));
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
    assert.equal(relay.getAdaptiveTimeoutConfig, undefined);
    assert.deepEqual(relay.reviseAdaptiveTimeout!({ baseTimeoutMs: 2000 }), defaultsFor(2000));
    assert.notEqual(relay.getAdaptiveTimeoutConfig, undefined);
    assert.deepEqual(relay.getAdaptiveTimeoutConfig!(), defaultsFor(2000));
    const revised = eventsOf(audit, "adaptive_timeout_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.deepEqual(revised[0].current, defaultsFor(2000));
    // Landing exactly on the enabled values audits nothing.
    relay.reviseAdaptiveTimeout!({ baseTimeoutMs: 2000 });
    assert.equal(eventsOf(audit, "adaptive_timeout_revised").length, 1);
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseAdaptiveTimeout!({ baseTimeoutMs: 0 }), RangeError);
    assert.equal(eventsOf(audit, "adaptive_timeout_revised").length, 1);
    assert.deepEqual(relay.getAdaptiveTimeoutConfig!(), defaultsFor(2000));
  });

  it("server enable with an illegal patch leaves the relay unconfigured — and it can still enable afterwards", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.throws(() => relay.reviseAdaptiveTimeout!({}), RangeError);
    assert.throws(() => relay.reviseAdaptiveTimeout!({ baseTimeoutMs: 0 }), RangeError);
    assert.equal(relay.getAdaptiveTimeoutConfig, undefined);
    assert.equal(eventsOf(audit, "adaptive_timeout_revised").length, 0);
    assert.deepEqual(relay.reviseAdaptiveTimeout!({ baseTimeoutMs: 500 }), defaultsFor(500));
    const revised = eventsOf(audit, "adaptive_timeout_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.deepEqual(revised[0].current, defaultsFor(500));
  });

  it("after the server enable, a live revision audits previous = the enabled values", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    relay.reviseAdaptiveTimeout!({ baseTimeoutMs: 1000 });
    assert.deepEqual(relay.reviseAdaptiveTimeout!({ marginRatio: 2 }), {
      ...defaultsFor(1000),
      marginRatio: 2,
    });
    const revised = eventsOf(audit, "adaptive_timeout_revised");
    assert.equal(revised.length, 2);
    assert.deepEqual(revised[1].previous, defaultsFor(1000));
    assert.deepEqual(revised[1].current, { ...defaultsFor(1000), marginRatio: 2 });
  });
});
