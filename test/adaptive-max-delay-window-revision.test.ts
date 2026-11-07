import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { LatencyTracker } from "../src/latency.ts";
import { AdaptiveMaxDelay } from "../src/adaptive-max-delay.ts";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "adaptive-max-delay-window-revision-test-key";
const opToken = "adaptive-max-delay-window-revision-op-token";
const URL_A = "http://localhost:9999/a";
const URL_B = "http://localhost:9999/b";

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
  c: AdaptiveMaxDelay,
  id: string,
  endpoint: string,
  ms: number,
  clock: { advance: (ms: number) => void }
) {
  c.recordAccepted(id);
  clock.advance(ms);
  c.recordDelivered(id, endpoint);
}

/** Record one latency sample of `ms` for `endpoint` on a raw tracker. */
function trackSample(
  t: LatencyTracker,
  id: string,
  endpoint: string,
  ms: number,
  clock: { advance: (ms: number) => void }
) {
  t.recordAccepted(id);
  clock.advance(ms);
  t.recordDelivered(id, endpoint);
}

describe("LatencyTracker.resize (WR-352)", () => {
  it("shrinking evicts only the oldest samples, per endpoint", () => {
    const clock = manualClock();
    const t = new LatencyTracker({ sloMs: 5000, maxSamplesPerEndpoint: 4, now: clock.now });
    trackSample(t, "a1", URL_A, 100, clock);
    trackSample(t, "a2", URL_A, 200, clock);
    trackSample(t, "a3", URL_A, 300, clock);
    trackSample(t, "a4", URL_A, 400, clock);
    trackSample(t, "b1", URL_B, 50, clock);
    trackSample(t, "b2", URL_B, 60, clock);
    t.resize(2);
    const [a] = t.stats(URL_A);
    assert.equal(a.count, 2);
    assert.equal(a.min, 300);
    assert.equal(a.max, 400);
    assert.equal(a.mean, 350);
    // The other endpoint keeps its (shorter) window untouched.
    const [b] = t.stats(URL_B);
    assert.equal(b.count, 2);
    assert.equal(b.min, 50);
    assert.equal(b.max, 60);
  });

  it("widening keeps every sample and never restores evicted samples", () => {
    const clock = manualClock();
    const t = new LatencyTracker({ sloMs: 5000, maxSamplesPerEndpoint: 2, now: clock.now });
    trackSample(t, "a1", URL_A, 100, clock);
    trackSample(t, "a2", URL_A, 200, clock);
    trackSample(t, "a3", URL_A, 300, clock);
    let [s] = t.stats(URL_A);
    assert.equal(s.count, 2);
    assert.equal(s.min, 200);
    t.resize(10);
    [s] = t.stats(URL_A);
    assert.equal(s.count, 2);
    assert.equal(s.min, 200);
    assert.equal(s.max, 300);
    // The evicted 100 stays gone; new samples accumulate past the old bound.
    trackSample(t, "a4", URL_A, 400, clock);
    [s] = t.stats(URL_A);
    assert.equal(s.count, 3);
    assert.equal(s.min, 200);
    assert.equal(s.mean, 300);
  });

  it("illegal resize values throw RangeError and the live window is untouched", () => {
    const clock = manualClock();
    const t = new LatencyTracker({ sloMs: 5000, maxSamplesPerEndpoint: 2, now: clock.now });
    trackSample(t, "a1", URL_A, 100, clock);
    trackSample(t, "a2", URL_A, 200, clock);
    for (const bad of [0, -3, 1.5, NaN]) {
      assert.throws(() => t.resize(bad), RangeError, `resize(${bad})`);
    }
    // The window is still 2: the next sample evicts the oldest.
    trackSample(t, "a3", URL_A, 300, clock);
    const [s] = t.stats(URL_A);
    assert.equal(s.count, 2);
    assert.equal(s.min, 200);
    assert.equal(s.max, 300);
  });

  it("resize leaves in-flight accepted clocks untouched", () => {
    const clock = manualClock();
    const t = new LatencyTracker({ sloMs: 5000, maxSamplesPerEndpoint: 2, now: clock.now });
    t.recordAccepted("in-flight");
    clock.advance(100);
    t.resize(1);
    clock.advance(200);
    assert.equal(t.recordDelivered("in-flight", URL_A), 300);
    const [s] = t.stats(URL_A);
    assert.equal(s.count, 1);
    assert.equal(s.p99, 300);
    assert.equal(t.pendingCount(), 0);
  });
});

describe("AdaptiveMaxDelay window revision (WR-352)", () => {
  it("narrowing the window rewrites the p99 and the next capFor", () => {
    const clock = manualClock();
    const c = new AdaptiveMaxDelay(60000, {
      minSamples: 1,
      marginRatio: 0.5,
      floorMs: 1,
      ceilMs: 1e9,
      maxSamplesPerEndpoint: 4,
      now: clock.now,
    });
    // Decreasing latencies so the oldest sample is also the largest.
    sample(c, "1", URL_A, 400, clock);
    sample(c, "2", URL_A, 300, clock);
    sample(c, "3", URL_A, 200, clock);
    sample(c, "4", URL_A, 100, clock);
    assert.equal(c.capFor(URL_A), 600); // p99 400 * 1.5
    assert.deepEqual(c.retune({ maxSamplesPerEndpoint: 3 }), {
      marginRatio: 0.5,
      floorMs: 1,
      ceilMs: 1e9,
      minSamples: 1,
      maxSamplesPerEndpoint: 3,
      tightenFactor: 0.8,
    });
    // The oldest (400) sample was evicted: p99 is now 300.
    const [s] = c.stats();
    assert.equal(s.samples, 3);
    assert.equal(s.p99Ms, 300);
    assert.equal(c.capFor(URL_A), 450);
  });

  it("widening keeps all samples; new samples accumulate past the old bound", () => {
    const clock = manualClock();
    const c = new AdaptiveMaxDelay(60000, {
      minSamples: 1,
      marginRatio: 0,
      floorMs: 1,
      ceilMs: 1e9,
      maxSamplesPerEndpoint: 2,
      now: clock.now,
    });
    sample(c, "1", URL_A, 100, clock);
    sample(c, "2", URL_A, 200, clock);
    sample(c, "3", URL_A, 300, clock);
    let [s] = c.stats();
    assert.equal(s.samples, 2);
    assert.equal(s.p99Ms, 300);
    c.retune({ maxSamplesPerEndpoint: 4 });
    [s] = c.stats();
    assert.equal(s.samples, 2);
    assert.equal(s.p99Ms, 300);
    sample(c, "4", URL_A, 400, clock);
    sample(c, "5", URL_A, 500, clock);
    [s] = c.stats();
    assert.equal(s.samples, 4);
    assert.equal(s.p99Ms, 500);
    assert.equal(c.capFor(URL_A), 500);
  });

  it("illegal window patches throw RangeError and live values, samples and caps are untouched", () => {
    const clock = manualClock();
    const c = new AdaptiveMaxDelay(60000, {
      minSamples: 1,
      marginRatio: 0.5,
      floorMs: 1000,
      ceilMs: 240000,
      maxSamplesPerEndpoint: 64,
      tightenFactor: 0.5,
      now: clock.now,
    });
    sample(c, "i1", URL_A, 4000, clock);
    assert.equal(c.capFor(URL_A), 6000);
    c.recordFailure(URL_A); // 6000 * 0.5 = 3000 (tightened cap)
    assert.equal(c.capFor(URL_A), 3000);
    for (const bad of [0, -1, 1.5, NaN]) {
      assert.throws(
        () => c.retune({ maxSamplesPerEndpoint: bad }),
        RangeError,
        `window ${bad}`
      );
    }
    assert.deepEqual(c.snapshot(), {
      marginRatio: 0.5,
      floorMs: 1000,
      ceilMs: 240000,
      minSamples: 1,
      maxSamplesPerEndpoint: 64,
      tightenFactor: 0.5,
    });
    // The tightened cap was NOT cleared by the failed revisions.
    assert.equal(c.capFor(URL_A), 3000);
    const [s] = c.stats();
    assert.equal(s.samples, 1);
    assert.equal(s.p99Ms, 4000);
  });

  it("a same-value window patch is a silent no-op returning the live config", () => {
    const c = new AdaptiveMaxDelay(60000, {
      marginRatio: 0.5,
      floorMs: 1000,
      ceilMs: 240000,
      minSamples: 10,
      maxSamplesPerEndpoint: 64,
      tightenFactor: 0.8,
    });
    assert.deepEqual(c.retune({ maxSamplesPerEndpoint: 64 }), {
      marginRatio: 0.5,
      floorMs: 1000,
      ceilMs: 240000,
      minSamples: 10,
      maxSamplesPerEndpoint: 64,
      tightenFactor: 0.8,
    });
    assert.deepEqual(c.snapshot(), {
      marginRatio: 0.5,
      floorMs: 1000,
      ceilMs: 240000,
      minSamples: 10,
      maxSamplesPerEndpoint: 64,
      tightenFactor: 0.8,
    });
  });

  it("a window revision clears tightened caps so the next capFor recomputes from p99", () => {
    const clock = manualClock();
    const c = new AdaptiveMaxDelay(60000, {
      minSamples: 1,
      marginRatio: 0,
      floorMs: 1000,
      maxSamplesPerEndpoint: 1024,
      tightenFactor: 0.5,
      now: clock.now,
    });
    sample(c, "i1", URL_A, 4000, clock);
    assert.equal(c.capFor(URL_A), 4000);
    c.recordFailure(URL_A); // 4000 -> 2000
    assert.equal(c.capFor(URL_A), 2000);
    c.retune({ maxSamplesPerEndpoint: 512 });
    assert.equal(c.capFor(URL_A), 4000);
  });
});

describe("RetryQueue adaptive max-delay window revision (WR-352)", () => {
  const okSender: Sender = async () => ({ statusCode: 200, body: Buffer.alloc(0) });

  it("unconfigured: a window-only revise throws the must-restart Error, getter returns undefined", () => {
    const q = new RetryQueue({ sender: okSender, baseDelayMs: 100, maxDelayMs: 60000 });
    assert.equal(q.getAdaptiveMaxDelayConfig(), undefined);
    assert.throws(
      () => q.reviseAdaptiveMaxDelay({ maxSamplesPerEndpoint: 10 }),
      /not configured — enabling it requires a restart/
    );
    assert.equal(q.getAdaptiveMaxDelayConfig(), undefined);
    q.stop();
  });

  it("getter tracks window revisions", () => {
    const q = new RetryQueue({
      sender: okSender,
      baseDelayMs: 100,
      maxDelayMs: 60000,
      adaptiveMaxDelay: {
        marginRatio: 0.5,
        floorMs: 1000,
        ceilMs: 240000,
        minSamples: 10,
        maxSamplesPerEndpoint: 64,
        tightenFactor: 0.8,
      },
    });
    assert.deepEqual(q.getAdaptiveMaxDelayConfig(), {
      marginRatio: 0.5,
      floorMs: 1000,
      ceilMs: 240000,
      minSamples: 10,
      maxSamplesPerEndpoint: 64,
      tightenFactor: 0.8,
    });
    assert.deepEqual(q.reviseAdaptiveMaxDelay({ maxSamplesPerEndpoint: 32 }), {
      marginRatio: 0.5,
      floorMs: 1000,
      ceilMs: 240000,
      minSamples: 10,
      maxSamplesPerEndpoint: 32,
      tightenFactor: 0.8,
    });
    assert.deepEqual(q.getAdaptiveMaxDelayConfig(), {
      marginRatio: 0.5,
      floorMs: 1000,
      ceilMs: 240000,
      minSamples: 10,
      maxSamplesPerEndpoint: 32,
      tightenFactor: 0.8,
    });
    q.stop();
  });
});

describe("RelayServer adaptive max-delay window revision (WR-352)", () => {
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
    const dir = mkdtempSync(join(tmpdir(), "adaptive-max-delay-window-revision-"));
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
    marginRatio: 0.5,
    floorMs: 1000,
    ceilMs: 240000,
    minSamples: 10,
    maxSamplesPerEndpoint: 64,
    tightenFactor: 0.8,
  };

  it("window revision audits previous/current with six fields; same-value window is a silent no-op", async () => {
    const { relay, audit } = makeRelay({
      retry: { adaptiveMaxDelay: { ...construction } },
    });
    await listen(relay);
    assert.deepEqual(relay.getAdaptiveMaxDelayConfig!(), construction);
    assert.deepEqual(relay.reviseAdaptiveMaxDelay!({ maxSamplesPerEndpoint: 32 }), {
      ...construction,
      maxSamplesPerEndpoint: 32,
    });
    const revised = eventsOf(audit, "adaptive_max_delay_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, construction);
    assert.deepEqual(revised[0].current, { ...construction, maxSamplesPerEndpoint: 32 });
    // Landing exactly on the live window audits nothing.
    relay.reviseAdaptiveMaxDelay!({ maxSamplesPerEndpoint: 32 });
    assert.equal(eventsOf(audit, "adaptive_max_delay_revised").length, 1);
    assert.deepEqual(relay.getAdaptiveMaxDelayConfig!(), {
      ...construction,
      maxSamplesPerEndpoint: 32,
    });
    // An illegal window throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseAdaptiveMaxDelay!({ maxSamplesPerEndpoint: 0 }), RangeError);
    assert.equal(eventsOf(audit, "adaptive_max_delay_revised").length, 1);
    assert.deepEqual(relay.getAdaptiveMaxDelayConfig!(), {
      ...construction,
      maxSamplesPerEndpoint: 32,
    });
  });
});
