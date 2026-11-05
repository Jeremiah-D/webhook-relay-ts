import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AdaptiveMaxDelay } from "../src/adaptive-max-delay.ts";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "adaptive-max-delay-revision-test-key";
const opToken = "adaptive-max-delay-revision-op-token";
const URL_A = "http://localhost:9999/a";
const URL_B = "http://localhost:9999/b";
const probeBody = Buffer.from(JSON.stringify({ event: "adaptive-max-delay-revision.probe" }));
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));

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

/** Let the deliver() promise chain settle. */
async function flush(ticks = 20) {
  for (let i = 0; i < ticks; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

async function waitFor(cond: () => boolean, label: string, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${label}`);
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe("AdaptiveMaxDelay.retune (WR-335)", () => {
  it("retuning marginRatio makes the next capFor use the new p99 multiple", () => {
    const clock = manualClock();
    const c = new AdaptiveMaxDelay(60000, {
      minSamples: 1,
      marginRatio: 0.5,
      floorMs: 1,
      ceilMs: 1e9,
      now: clock.now,
    });
    sample(c, "1", URL_A, 1000, clock);
    assert.equal(c.capFor(URL_A), 1500);
    assert.deepEqual(c.retune({ marginRatio: 1 }), {
      marginRatio: 1,
      floorMs: 1,
      ceilMs: 1e9,
      minSamples: 1,
      tightenFactor: 0.8,
    });
    assert.equal(c.capFor(URL_A), 2000);
  });

  it("retuning floorMs/ceilMs moves the clamp bounds", () => {
    const clock = manualClock();
    const c = new AdaptiveMaxDelay(60000, {
      minSamples: 1,
      marginRatio: 1,
      floorMs: 500,
      ceilMs: 10000,
      now: clock.now,
    });
    sample(c, "s1", URL_A, 8000, clock); // p99 8000 * 2 = 16000, capped at 10000
    sample(c, "f1", URL_B, 100, clock); // p99 100 * 2 = 200, floored at 500
    assert.equal(c.capFor(URL_A), 10000);
    assert.equal(c.capFor(URL_B), 500);
    c.retune({ floorMs: 100 });
    assert.equal(c.capFor(URL_B), 200);
    c.retune({ ceilMs: 20000 });
    assert.equal(c.capFor(URL_A), 16000);
  });

  it("raising minSamples returns a warm endpoint to cold with the resting cap; lowering keeps it warm", () => {
    const clock = manualClock();
    const c = new AdaptiveMaxDelay(60000, {
      minSamples: 3,
      marginRatio: 0.5,
      floorMs: 1,
      ceilMs: 1e9,
      now: clock.now,
    });
    sample(c, "1", URL_A, 100, clock);
    sample(c, "2", URL_A, 100, clock);
    sample(c, "3", URL_A, 100, clock);
    assert.equal(c.capFor(URL_A), 150); // warm: 3 samples
    assert.deepEqual(c.retune({ minSamples: 5 }), {
      marginRatio: 0.5,
      floorMs: 1,
      ceilMs: 1e9,
      minSamples: 5,
      tightenFactor: 0.8,
    });
    assert.equal(c.capFor(URL_A), 60000); // cold again, resting cap
    c.retune({ minSamples: 2 });
    assert.equal(c.capFor(URL_A), 150); // warm again, same p99
  });

  it("retuning tightenFactor changes the next recordFailure step", () => {
    const clock = manualClock();
    const c = new AdaptiveMaxDelay(60000, {
      minSamples: 1,
      marginRatio: 0,
      floorMs: 1000,
      tightenFactor: 0.5,
      now: clock.now,
    });
    sample(c, "i1", URL_A, 4000, clock);
    sample(c, "i2", URL_A, 4000, clock);
    assert.equal(c.capFor(URL_A), 4000);
    c.recordFailure(URL_A); // 4000 * 0.5 = 2000
    assert.equal(c.capFor(URL_A), 2000);
    c.retune({ tightenFactor: 0.25 });
    // The revision cleared the tightened cap: back to the p99 target.
    assert.equal(c.capFor(URL_A), 4000);
    c.recordFailure(URL_A); // 4000 * 0.25 = 1000, the new step
    assert.equal(c.capFor(URL_A), 1000);
  });

  it("a partial patch changes only one value, the rest stay live", () => {
    const c = new AdaptiveMaxDelay(60000, {
      marginRatio: 0.5,
      floorMs: 1000,
      ceilMs: 240000,
      minSamples: 10,
      tightenFactor: 0.8,
    });
    const before = c.snapshot();
    assert.deepEqual(c.retune({ floorMs: 500 }), { ...before, floorMs: 500 });
    assert.deepEqual(c.snapshot(), { ...before, floorMs: 500 });
  });

  it("retune clears tightened caps so the next capFor recomputes from p99", () => {
    const clock = manualClock();
    const c = new AdaptiveMaxDelay(60000, {
      minSamples: 1,
      marginRatio: 0,
      floorMs: 1000,
      tightenFactor: 0.5,
      now: clock.now,
    });
    sample(c, "i1", URL_A, 4000, clock);
    assert.equal(c.capFor(URL_A), 4000);
    c.recordFailure(URL_A); // 4000 -> 2000
    assert.equal(c.capFor(URL_A), 2000);
    c.retune({ marginRatio: 0.5 });
    // Tightened cap dropped; p99 4000 * 1.5 = 6000 under the new formula.
    assert.equal(c.capFor(URL_A), 6000);
  });

  it("retune leaves the rolling samples and p99 unchanged", () => {
    const clock = manualClock();
    const c = new AdaptiveMaxDelay(60000, {
      minSamples: 1,
      marginRatio: 0.5,
      floorMs: 1,
      ceilMs: 1e9,
      now: clock.now,
    });
    sample(c, "1", URL_A, 100, clock);
    sample(c, "2", URL_A, 200, clock);
    sample(c, "3", URL_A, 300, clock);
    const samplesBefore = c.stats().map((s) => ({
      endpoint: s.endpoint,
      samples: s.samples,
      p99Ms: s.p99Ms,
    }));
    assert.deepEqual(samplesBefore, [{ endpoint: URL_A, samples: 3, p99Ms: 300 }]);
    c.retune({
      marginRatio: 2,
      floorMs: 10,
      ceilMs: 99999,
      minSamples: 1,
      tightenFactor: 0.9,
    });
    const samplesAfter = c.stats().map((s) => ({
      endpoint: s.endpoint,
      samples: s.samples,
      p99Ms: s.p99Ms,
    }));
    assert.deepEqual(samplesAfter, samplesBefore);
    // Only the formula inputs moved: p99 300 * (1 + 2) = 900.
    assert.equal(c.capFor(URL_A), 900);
  });

  it("illegal patches throw RangeError and the live values and caps are untouched", () => {
    const clock = manualClock();
    const c = new AdaptiveMaxDelay(60000, {
      minSamples: 1,
      marginRatio: 0.5,
      floorMs: 1000,
      ceilMs: 240000,
      tightenFactor: 0.5,
      now: clock.now,
    });
    sample(c, "i1", URL_A, 4000, clock);
    assert.equal(c.capFor(URL_A), 6000);
    c.recordFailure(URL_A); // 6000 * 0.5 = 3000 (tightened cap)
    assert.equal(c.capFor(URL_A), 3000);
    const bad = [
      { marginRatio: -0.1 },
      { marginRatio: NaN },
      { marginRatio: Infinity },
      { floorMs: 0 },
      { floorMs: -5 },
      { ceilMs: 0 },
      { minSamples: 0 },
      { minSamples: 1.5 },
      { tightenFactor: 0 },
      { tightenFactor: 1 },
      { tightenFactor: 1.5 },
      // Merged ceil < floor (ceil 500 < live floor 1000).
      { ceilMs: 500 },
      // Merged floor > ceil (floor 300000 > live ceil 240000).
      { floorMs: 300000 },
      // Merged ceil < live floor via a floor raise + ceil cut.
      { floorMs: 2000, ceilMs: 1500 },
    ];
    for (const patch of bad) {
      assert.throws(() => c.retune(patch), RangeError, JSON.stringify(patch));
    }
    assert.deepEqual(c.snapshot(), {
      marginRatio: 0.5,
      floorMs: 1000,
      ceilMs: 240000,
      minSamples: 1,
      tightenFactor: 0.5,
    });
    // The tightened cap was NOT cleared by the failed revisions.
    assert.equal(c.capFor(URL_A), 3000);
  });

  it("an empty patch and a non-object patch are RangeErrors", () => {
    const c = new AdaptiveMaxDelay(60000, { minSamples: 1 });
    assert.throws(() => c.retune({}), RangeError);
    assert.throws(() => c.retune(null as never), RangeError);
    assert.throws(() => c.retune("fast" as never), RangeError);
    assert.throws(() => c.retune([] as never), RangeError);
    assert.deepEqual(c.snapshot(), {
      marginRatio: 0.5,
      floorMs: 1000,
      ceilMs: 240000,
      minSamples: 1,
      tightenFactor: 0.8,
    });
  });

  it("a same-value patch is a silent no-op returning the live config", () => {
    const c = new AdaptiveMaxDelay(60000, {
      marginRatio: 0.5,
      floorMs: 1000,
      ceilMs: 240000,
      minSamples: 10,
      tightenFactor: 0.8,
    });
    const live = {
      marginRatio: 0.5,
      floorMs: 1000,
      ceilMs: 240000,
      minSamples: 10,
      tightenFactor: 0.8,
    };
    assert.deepEqual(c.retune({ marginRatio: 0.5 }), live);
    assert.deepEqual(c.retune({ floorMs: 1000, tightenFactor: 0.8 }), live);
    assert.deepEqual(c.snapshot(), live);
  });
});

describe("RetryQueue adaptive max-delay revision (WR-335)", () => {
  const okSender: Sender = async () => ({ statusCode: 200, body: Buffer.alloc(0) });

  it("unconfigured: revise throws the must-restart Error, getter returns undefined", () => {
    const q = new RetryQueue({ sender: okSender, baseDelayMs: 100, maxDelayMs: 60000 });
    assert.equal(q.getAdaptiveMaxDelayConfig(), undefined);
    assert.throws(
      () => q.reviseAdaptiveMaxDelay({ marginRatio: 1 }),
      /not configured — enabling it requires a restart/
    );
    assert.throws(
      () => q.reviseAdaptiveMaxDelay({ marginRatio: 1 }),
      /cannot start deriving p99 caps without one/
    );
    assert.equal(q.getAdaptiveMaxDelayConfig(), undefined);
    q.stop();
  });

  it("getter tracks revisions", () => {
    const q = new RetryQueue({
      sender: okSender,
      baseDelayMs: 100,
      maxDelayMs: 60000,
      adaptiveMaxDelay: {
        marginRatio: 0.5,
        floorMs: 1000,
        ceilMs: 240000,
        minSamples: 10,
        tightenFactor: 0.8,
      },
    });
    assert.deepEqual(q.getAdaptiveMaxDelayConfig(), {
      marginRatio: 0.5,
      floorMs: 1000,
      ceilMs: 240000,
      minSamples: 10,
      tightenFactor: 0.8,
    });
    assert.deepEqual(q.reviseAdaptiveMaxDelay({ marginRatio: 1, minSamples: 5 }), {
      marginRatio: 1,
      floorMs: 1000,
      ceilMs: 240000,
      minSamples: 5,
      tightenFactor: 0.8,
    });
    assert.deepEqual(q.getAdaptiveMaxDelayConfig(), {
      marginRatio: 1,
      floorMs: 1000,
      ceilMs: 240000,
      minSamples: 5,
      tightenFactor: 0.8,
    });
    q.stop();
  });

  it("a wait already scheduled keeps its old cap; the next retry wait uses the new cap", async () => {
    const clock = manualClock(1000);
    const dispatchTimes: number[] = [];
    let calls = 0;
    // Succeeds twice (warming the endpoint at 4000ms), then fails forever.
    const flapping: Sender = async () => {
      calls += 1;
      dispatchTimes.push(Date.now());
      clock.advance(4000);
      if (calls <= 2) return { statusCode: 200, body: Buffer.alloc(0) };
      throw new Error("boom");
    };
    const q = new RetryQueue({
      sender: flapping,
      baseDelayMs: 1000,
      jitterMs: 0,
      maxDelayMs: 60000,
      maxAttempts: 2,
      adaptiveMaxDelay: {
        minSamples: 2,
        marginRatio: 0,
        floorMs: 100,
        ceilMs: 1e9,
        tightenFactor: 0.5,
        now: clock.now,
      },
    });
    q.start();
    try {
      // Enqueue sequentially: each delivery is accepted at the current
      // manual time, so each samples exactly 4000ms.
      q.enqueue({ id: "w0", payload: BODY, targetUrl: URL_A, headers: {} });
      await flush();
      q.enqueue({ id: "w1", payload: BODY, targetUrl: URL_A, headers: {} });
      await flush();
      await waitFor(() => q.getAdaptiveMaxDelayStats()[0]?.samples === 2, "endpoint warms");
      assert.equal(q.getAdaptiveMaxDelayStats()[0].capMs, 4000);
      // Attempt 1 waits min(cap 4000, 1000 * 2) = 2000ms.
      assert.equal(q.delayForAttempt(1, URL_A), 2000);
      q.enqueue({ id: "f0", payload: BODY, targetUrl: URL_A, headers: {} });
      await waitFor(() => calls === 3, "failing attempt dispatched");
      // Let the failure handler arm the retry timer before revising.
      await new Promise((r) => setTimeout(r, 50));
      const failAt = dispatchTimes[2];
      q.reviseAdaptiveMaxDelay({ ceilMs: 100, floorMs: 100 });
      assert.equal(q.getAdaptiveMaxDelayStats()[0].capMs, 100);
      // The next retry wait is bounded by the new cap...
      assert.equal(q.delayForAttempt(1, URL_A), 100);
      assert.equal(q.effectiveRetryConfig(URL_A).maxDelayMs, 100);
      // ...but the already-armed retry still waits out the old 2000ms.
      await waitFor(() => calls === 4, "scheduled retry dispatched");
      const retryGap = dispatchTimes[3] - failAt;
      assert.ok(retryGap >= 1500, `scheduled wait kept its old cap (gap ${retryGap}ms)`);
      assert.ok(retryGap < 4000, `scheduled retry fired on time (gap ${retryGap}ms)`);
    } finally {
      q.stop();
    }
  });

  it("a named policy endpoint still uses its policy cap after a retune", () => {
    const q = new RetryQueue({
      sender: okSender,
      baseDelayMs: 100,
      maxDelayMs: 60000,
      adaptiveMaxDelay: { minSamples: 1, marginRatio: 0.5, now: () => 0 },
    });
    q.registerRetryPolicy("fixed", { baseDelayMs: 100, maxDelayMs: 12345, maxAttempts: 3 });
    q.setEndpointRetryPolicy(URL_A, "fixed");
    q.reviseAdaptiveMaxDelay({ marginRatio: 2, floorMs: 100, ceilMs: 500 });
    // Policy cap wins even after the adaptive config moved.
    assert.equal(q.delayForAttempt(10, URL_A), 12345);
    assert.equal(q.effectiveRetryConfig(URL_A).maxDelayMs, 12345);
    q.stop();
  });
});

describe("RelayServer adaptive max-delay revision (WR-335)", () => {
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
    const dir = mkdtempSync(join(tmpdir(), "adaptive-max-delay-revision-"));
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
    tightenFactor: 0.8,
  };

  it("revision audits previous/current with the construction values first; same-value is a silent no-op", async () => {
    const { relay, audit } = makeRelay({
      retry: { adaptiveMaxDelay: { ...construction } },
    });
    await listen(relay);
    assert.deepEqual(relay.getAdaptiveMaxDelayConfig!(), construction);
    assert.deepEqual(relay.reviseAdaptiveMaxDelay!({ marginRatio: 1 }), {
      ...construction,
      marginRatio: 1,
    });
    const revised = eventsOf(audit, "adaptive_max_delay_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, construction);
    assert.deepEqual(revised[0].current, { ...construction, marginRatio: 1 });
    // Landing exactly on the live values audits nothing.
    relay.reviseAdaptiveMaxDelay!({ marginRatio: 1 });
    assert.equal(eventsOf(audit, "adaptive_max_delay_revised").length, 1);
    assert.deepEqual(relay.getAdaptiveMaxDelayConfig!(), { ...construction, marginRatio: 1 });
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseAdaptiveMaxDelay!({ tightenFactor: 1 }), RangeError);
    assert.throws(() => relay.reviseAdaptiveMaxDelay!({}), RangeError);
    assert.equal(eventsOf(audit, "adaptive_max_delay_revised").length, 1);
    assert.deepEqual(relay.getAdaptiveMaxDelayConfig!(), { ...construction, marginRatio: 1 });
  });

  it("unconfigured relay: revise throws the must-restart Error and the getter is not mounted", async () => {
    const { relay } = makeRelay();
    await listen(relay);
    assert.equal(relay.getAdaptiveMaxDelayConfig, undefined);
    assert.throws(
      () => relay.reviseAdaptiveMaxDelay!({ marginRatio: 1 }),
      /not configured — enabling it requires a restart/
    );
  });

  it("server getter reflects revisions made through the server", async () => {
    const { relay } = makeRelay({
      retry: { adaptiveMaxDelay: { marginRatio: 0.5, floorMs: 1000, ceilMs: 240000, minSamples: 3 } },
    });
    await listen(relay);
    assert.deepEqual(relay.getAdaptiveMaxDelayConfig!(), {
      marginRatio: 0.5,
      floorMs: 1000,
      ceilMs: 240000,
      minSamples: 3,
      tightenFactor: 0.8,
    });
    relay.reviseAdaptiveMaxDelay!({ minSamples: 5, tightenFactor: 0.6 });
    assert.deepEqual(relay.getAdaptiveMaxDelayConfig!(), {
      marginRatio: 0.5,
      floorMs: 1000,
      ceilMs: 240000,
      minSamples: 5,
      tightenFactor: 0.6,
    });
  });
});
