import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AdaptiveTimeout } from "../src/adaptive-timeout.ts";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "adaptive-timeout-window-revision-test-key";
const opToken = "adaptive-timeout-window-revision-op-token";
const URL_A = "http://localhost:9999/a";

/** Manual clock for deterministic latency samples. */
function manualClock(start = 0) {
  let t = start;
  return {
    now: () => t,
    advance: (ms: number) => {
      t += ms;
    },
  };
}

/** Record one latency sample of `ms` for `endpoint`. */
function sample(
  at: AdaptiveTimeout,
  id: string,
  endpoint: string,
  ms: number,
  clock: { advance: (ms: number) => void }
) {
  at.recordAccepted(id);
  clock.advance(ms);
  at.recordDelivered(id, endpoint);
}

describe("AdaptiveTimeout window revision (WR-354)", () => {
  it("narrowing the window rewrites the p99 and the next timeoutFor", () => {
    const clock = manualClock();
    const at = new AdaptiveTimeout({
      baseTimeoutMs: 1000,
      marginRatio: 0.5,
      minTimeoutMs: 1,
      maxTimeoutMs: 1e9,
      minSamples: 1,
      maxSamplesPerEndpoint: 4,
      now: clock.now,
    });
    // Decreasing latencies so the oldest sample is also the largest.
    sample(at, "1", URL_A, 400, clock);
    sample(at, "2", URL_A, 300, clock);
    sample(at, "3", URL_A, 200, clock);
    sample(at, "4", URL_A, 100, clock);
    assert.equal(at.timeoutFor(URL_A), 600); // p99 400 * 1.5
    assert.deepEqual(at.retune({ maxSamplesPerEndpoint: 3 }), {
      baseTimeoutMs: 1000,
      marginRatio: 0.5,
      minTimeoutMs: 1,
      maxTimeoutMs: 1e9,
      minSamples: 1,
      maxSamplesPerEndpoint: 3,
    });
    // The oldest (400) sample was evicted: p99 is now 300.
    const [s] = at.stats();
    assert.equal(s.samples, 3);
    assert.equal(s.p99Ms, 300);
    assert.equal(at.timeoutFor(URL_A), 450);
  });

  it("widening keeps all samples and never restores evicted samples", () => {
    const clock = manualClock();
    const at = new AdaptiveTimeout({
      baseTimeoutMs: 1000,
      marginRatio: 0,
      minTimeoutMs: 1,
      maxTimeoutMs: 1e9,
      minSamples: 1,
      maxSamplesPerEndpoint: 2,
      now: clock.now,
    });
    sample(at, "1", URL_A, 100, clock);
    sample(at, "2", URL_A, 200, clock);
    sample(at, "3", URL_A, 300, clock);
    let [s] = at.stats();
    assert.equal(s.samples, 2);
    assert.equal(s.p99Ms, 300);
    at.retune({ maxSamplesPerEndpoint: 4 });
    [s] = at.stats();
    // The evicted 100 stays gone: still 2 samples, not 3.
    assert.equal(s.samples, 2);
    assert.equal(s.p99Ms, 300);
    sample(at, "4", URL_A, 400, clock);
    sample(at, "5", URL_A, 500, clock);
    [s] = at.stats();
    assert.equal(s.samples, 4);
    assert.equal(s.p99Ms, 500);
    assert.equal(at.timeoutFor(URL_A), 500);
  });

  it("illegal window patches throw RangeError and live values, samples and timeout are untouched", () => {
    const clock = manualClock();
    const at = new AdaptiveTimeout({
      baseTimeoutMs: 1000,
      marginRatio: 0.5,
      minTimeoutMs: 100,
      maxTimeoutMs: 1e9,
      minSamples: 1,
      maxSamplesPerEndpoint: 64,
      now: clock.now,
    });
    sample(at, "i1", URL_A, 4000, clock);
    assert.equal(at.timeoutFor(URL_A), 6000);
    for (const bad of [0, -1, 1.5, NaN]) {
      assert.throws(
        () => at.retune({ maxSamplesPerEndpoint: bad }),
        RangeError,
        `window ${bad}`
      );
    }
    assert.deepEqual(at.snapshot(), {
      baseTimeoutMs: 1000,
      marginRatio: 0.5,
      minTimeoutMs: 100,
      maxTimeoutMs: 1e9,
      minSamples: 1,
      maxSamplesPerEndpoint: 64,
    });
    // The p99 and the derived timeout did not move.
    assert.equal(at.timeoutFor(URL_A), 6000);
    const [s] = at.stats();
    assert.equal(s.samples, 1);
    assert.equal(s.p99Ms, 4000);
  });

  it("a same-value window patch is a silent no-op returning the live config", () => {
    const at = new AdaptiveTimeout({
      baseTimeoutMs: 1000,
      marginRatio: 0.5,
      minTimeoutMs: 100,
      maxTimeoutMs: 4000,
      minSamples: 10,
      maxSamplesPerEndpoint: 64,
    });
    assert.deepEqual(at.retune({ maxSamplesPerEndpoint: 64 }), {
      baseTimeoutMs: 1000,
      marginRatio: 0.5,
      minTimeoutMs: 100,
      maxTimeoutMs: 4000,
      minSamples: 10,
      maxSamplesPerEndpoint: 64,
    });
    assert.deepEqual(at.snapshot(), {
      baseTimeoutMs: 1000,
      marginRatio: 0.5,
      minTimeoutMs: 100,
      maxTimeoutMs: 4000,
      minSamples: 10,
      maxSamplesPerEndpoint: 64,
    });
  });

  it("shrinking the window below minSamples returns the endpoint to cold with the new base", () => {
    const clock = manualClock();
    const at = new AdaptiveTimeout({
      baseTimeoutMs: 1000,
      marginRatio: 0.5,
      minSamples: 2,
      maxSamplesPerEndpoint: 4,
      now: clock.now,
    });
    sample(at, "1", URL_A, 100, clock);
    sample(at, "2", URL_A, 100, clock);
    sample(at, "3", URL_A, 100, clock);
    assert.equal(at.timeoutFor(URL_A), 150); // warm: 3 samples >= 2
    assert.deepEqual(at.retune({ maxSamplesPerEndpoint: 1, baseTimeoutMs: 2000 }), {
      baseTimeoutMs: 2000,
      marginRatio: 0.5,
      minTimeoutMs: 100,
      maxTimeoutMs: 4000,
      minSamples: 2,
      maxSamplesPerEndpoint: 1,
    });
    // One surviving sample < minSamples 2: cold again, new base.
    const [s] = at.stats();
    assert.equal(s.samples, 1);
    assert.equal(at.timeoutFor(URL_A), 2000);
    // Widen the window again, then fresh samples warm it back up from
    // the surviving p99 (a window of 1 could never hold 2 samples).
    at.retune({ maxSamplesPerEndpoint: 4 });
    sample(at, "4", URL_A, 100, clock);
    assert.equal(at.timeoutFor(URL_A), 150);
  });

  it("a window revision leaves in-flight accepted clocks untouched", () => {
    const clock = manualClock();
    const at = new AdaptiveTimeout({
      baseTimeoutMs: 1000,
      marginRatio: 0.5,
      minSamples: 1,
      maxSamplesPerEndpoint: 4,
      now: clock.now,
    });
    at.recordAccepted("in-flight");
    clock.advance(100);
    at.retune({ maxSamplesPerEndpoint: 1 });
    clock.advance(200);
    at.recordDelivered("in-flight", URL_A);
    const [s] = at.stats();
    assert.equal(s.samples, 1);
    assert.equal(s.p99Ms, 300);
    assert.equal(at.timeoutFor(URL_A), 450);
  });
});

describe("RetryQueue adaptive timeout window revision (WR-354)", () => {
  const okSender: Sender = async () => ({ statusCode: 200, body: Buffer.alloc(0) });

  it("unconfigured: a window-only revise throws the must-restart Error, getter returns undefined", () => {
    const q = new RetryQueue({ sender: okSender, baseDelayMs: 100, maxDelayMs: 60000 });
    assert.equal(q.getAdaptiveTimeoutConfig(), undefined);
    assert.throws(
      () => q.reviseAdaptiveTimeout({ maxSamplesPerEndpoint: 10 }),
      /not configured — enabling it requires a restart/
    );
    assert.equal(q.getAdaptiveTimeoutConfig(), undefined);
    q.stop();
  });

  it("getter tracks window revisions", () => {
    const q = new RetryQueue({
      sender: okSender,
      baseDelayMs: 100,
      maxDelayMs: 60000,
      adaptiveTimeout: {
        baseTimeoutMs: 1000,
        marginRatio: 0.5,
        minTimeoutMs: 100,
        maxTimeoutMs: 4000,
        minSamples: 10,
        maxSamplesPerEndpoint: 64,
      },
    });
    assert.deepEqual(q.getAdaptiveTimeoutConfig(), {
      baseTimeoutMs: 1000,
      marginRatio: 0.5,
      minTimeoutMs: 100,
      maxTimeoutMs: 4000,
      minSamples: 10,
      maxSamplesPerEndpoint: 64,
    });
    assert.deepEqual(q.reviseAdaptiveTimeout({ maxSamplesPerEndpoint: 32 }), {
      baseTimeoutMs: 1000,
      marginRatio: 0.5,
      minTimeoutMs: 100,
      maxTimeoutMs: 4000,
      minSamples: 10,
      maxSamplesPerEndpoint: 32,
    });
    assert.deepEqual(q.getAdaptiveTimeoutConfig(), {
      baseTimeoutMs: 1000,
      marginRatio: 0.5,
      minTimeoutMs: 100,
      maxTimeoutMs: 4000,
      minSamples: 10,
      maxSamplesPerEndpoint: 32,
    });
    q.stop();
  });
});

describe("RelayServer adaptive timeout window revision (WR-354)", () => {
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
    const dir = mkdtempSync(join(tmpdir(), "adaptive-timeout-window-revision-"));
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

  const construction = {
    baseTimeoutMs: 1000,
    marginRatio: 0.5,
    minTimeoutMs: 100,
    maxTimeoutMs: 4000,
    minSamples: 10,
    maxSamplesPerEndpoint: 64,
  };

  it("window revision audits previous/current with six fields; same-value window is a silent no-op", async () => {
    const { relay, audit } = makeRelay({
      retry: { adaptiveTimeout: { ...construction } },
    });
    await listen(relay);
    assert.deepEqual(relay.getAdaptiveTimeoutConfig!(), construction);
    assert.deepEqual(relay.reviseAdaptiveTimeout!({ maxSamplesPerEndpoint: 32 }), {
      ...construction,
      maxSamplesPerEndpoint: 32,
    });
    const revised = eventsOf(audit, "adaptive_timeout_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, construction);
    assert.deepEqual(revised[0].current, { ...construction, maxSamplesPerEndpoint: 32 });
    // Landing exactly on the live window audits nothing.
    relay.reviseAdaptiveTimeout!({ maxSamplesPerEndpoint: 32 });
    assert.equal(eventsOf(audit, "adaptive_timeout_revised").length, 1);
    assert.deepEqual(relay.getAdaptiveTimeoutConfig!(), {
      ...construction,
      maxSamplesPerEndpoint: 32,
    });
    // An illegal window throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseAdaptiveTimeout!({ maxSamplesPerEndpoint: 0 }), RangeError);
    assert.equal(eventsOf(audit, "adaptive_timeout_revised").length, 1);
    assert.deepEqual(relay.getAdaptiveTimeoutConfig!(), {
      ...construction,
      maxSamplesPerEndpoint: 32,
    });
  });

  it("server getter reflects window revisions made through the server", async () => {
    const { relay } = makeRelay({
      retry: { adaptiveTimeout: { baseTimeoutMs: 2000, minSamples: 3 } },
    });
    await listen(relay);
    assert.deepEqual(relay.getAdaptiveTimeoutConfig!(), {
      baseTimeoutMs: 2000,
      marginRatio: 0.5,
      minTimeoutMs: 100,
      maxTimeoutMs: 8000,
      minSamples: 3,
      maxSamplesPerEndpoint: 1024,
    });
    relay.reviseAdaptiveTimeout!({ maxSamplesPerEndpoint: 512 });
    assert.deepEqual(relay.getAdaptiveTimeoutConfig!(), {
      baseTimeoutMs: 2000,
      marginRatio: 0.5,
      minTimeoutMs: 100,
      maxTimeoutMs: 8000,
      minSamples: 3,
      maxSamplesPerEndpoint: 512,
    });
  });
});
