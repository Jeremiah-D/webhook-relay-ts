import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AdaptiveTimeout } from "../src/adaptive-timeout.ts";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "adaptive-timeout-revision-test-key";
const opToken = "adaptive-timeout-revision-op-token";
const URL_A = "http://localhost:9999/a";
const probeBody = Buffer.from(JSON.stringify({ event: "adaptive-timeout-revision.probe" }));

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

function item(id: string, targetUrl: string) {
  return { id, payload: Buffer.from("x"), targetUrl, headers: {} };
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

describe("AdaptiveTimeout.retune (WR-334)", () => {
  it("retuning marginRatio makes the next timeoutFor use the new p99 multiple", () => {
    const clock = manualClock();
    const at = new AdaptiveTimeout({
      baseTimeoutMs: 1000,
      marginRatio: 0.5,
      minSamples: 1,
      now: clock.now,
    });
    sample(at, "1", URL_A, 1000, clock);
    assert.equal(at.timeoutFor(URL_A), 1500);
    assert.deepEqual(at.retune({ marginRatio: 1 }), {
      baseTimeoutMs: 1000,
      marginRatio: 1,
      minTimeoutMs: 100,
      maxTimeoutMs: 4000,
      minSamples: 1,
      maxSamplesPerEndpoint: 1024,
    });
    assert.equal(at.timeoutFor(URL_A), 2000);
  });

  it("retuning baseTimeoutMs changes the cold fallback, not a warm endpoint's cap", () => {
    const clock = manualClock();
    const cold = new AdaptiveTimeout({
      baseTimeoutMs: 1000,
      minSamples: 10,
      now: clock.now,
    });
    assert.equal(cold.timeoutFor(URL_A), 1000);
    cold.retune({ baseTimeoutMs: 2500 });
    assert.equal(cold.timeoutFor(URL_A), 2500);

    const warm = new AdaptiveTimeout({
      baseTimeoutMs: 1000,
      marginRatio: 0.5,
      minSamples: 1,
      now: clock.now,
    });
    sample(warm, "1", URL_A, 100, clock);
    assert.equal(warm.timeoutFor(URL_A), 150);
    warm.retune({ baseTimeoutMs: 5000 });
    // Warm cap is p99-derived (150), not the base — only the cold
    // fallback moved.
    assert.equal(warm.timeoutFor(URL_A), 150);
    assert.equal(warm.timeoutFor("http://cold.example/"), 5000);
  });

  it("retuning min/maxTimeoutMs moves the clamp bounds", () => {
    const clock = manualClock();
    const at = new AdaptiveTimeout({
      baseTimeoutMs: 1000,
      marginRatio: 0.5,
      minTimeoutMs: 200,
      maxTimeoutMs: 500,
      minSamples: 1,
      now: clock.now,
    });
    sample(at, "1", URL_A, 10, clock); // p99=10 -> 15, floored at 200
    sample(at, "2", "http://b/", 10000, clock); // p99=10000 -> 15000, capped at 500
    assert.equal(at.timeoutFor(URL_A), 200);
    assert.equal(at.timeoutFor("http://b/"), 500);
    at.retune({ minTimeoutMs: 50 });
    assert.equal(at.timeoutFor(URL_A), 50);
    at.retune({ maxTimeoutMs: 2000 });
    assert.equal(at.timeoutFor("http://b/"), 2000);
  });

  it("raising minSamples returns a warm endpoint to cold with the new base; lowering keeps it warm", () => {
    const clock = manualClock();
    const at = new AdaptiveTimeout({
      baseTimeoutMs: 1000,
      marginRatio: 0.5,
      minSamples: 3,
      now: clock.now,
    });
    sample(at, "1", URL_A, 100, clock);
    sample(at, "2", URL_A, 100, clock);
    sample(at, "3", URL_A, 100, clock);
    assert.equal(at.timeoutFor(URL_A), 150); // warm: 3 samples
    assert.deepEqual(at.retune({ minSamples: 5, baseTimeoutMs: 2000 }), {
      baseTimeoutMs: 2000,
      marginRatio: 0.5,
      minTimeoutMs: 100,
      maxTimeoutMs: 4000,
      minSamples: 5,
      maxSamplesPerEndpoint: 1024,
    });
    assert.equal(at.timeoutFor(URL_A), 2000); // cold again, new base
    at.retune({ minSamples: 2 });
    assert.equal(at.timeoutFor(URL_A), 150); // warm again, same p99
  });

  it("a partial patch changes only one value, the rest stay live", () => {
    const at = new AdaptiveTimeout({
      baseTimeoutMs: 1000,
      marginRatio: 0.5,
      minTimeoutMs: 100,
      maxTimeoutMs: 4000,
      minSamples: 10,
    });
    const before = at.snapshot();
    assert.deepEqual(at.retune({ marginRatio: 0.25 }), { ...before, marginRatio: 0.25 });
    assert.deepEqual(at.snapshot(), { ...before, marginRatio: 0.25 });
  });

  it("illegal patches throw RangeError and the live values are untouched", () => {
    const clock = manualClock();
    const at = new AdaptiveTimeout({
      baseTimeoutMs: 1000,
      marginRatio: 0.5,
      minTimeoutMs: 100,
      maxTimeoutMs: 4000,
      minSamples: 10,
      now: clock.now,
    });
    const bad = [
      { baseTimeoutMs: 0 },
      { baseTimeoutMs: -1 },
      { baseTimeoutMs: NaN },
      { baseTimeoutMs: Infinity },
      { baseTimeoutMs: "1000" as never },
      { marginRatio: -0.1 },
      { marginRatio: NaN },
      { minTimeoutMs: 0 },
      { maxTimeoutMs: 0 },
      { minSamples: 0 },
      { minSamples: 1.5 },
      { maxSamplesPerEndpoint: 0 },
      { maxSamplesPerEndpoint: 1.5 },
      // Merged max < min (max 50 < live min 100).
      { maxTimeoutMs: 50 },
      // Merged min > max (min 5000 > live max 4000).
      { minTimeoutMs: 5000 },
    ];
    for (const patch of bad) {
      assert.throws(() => at.retune(patch), RangeError, JSON.stringify(patch));
    }
    assert.deepEqual(at.snapshot(), {
      baseTimeoutMs: 1000,
      marginRatio: 0.5,
      minTimeoutMs: 100,
      maxTimeoutMs: 4000,
      minSamples: 10,
      maxSamplesPerEndpoint: 1024,
    });
    assert.equal(at.timeoutFor(URL_A), 1000);
  });

  it("an empty patch and a non-object patch are RangeErrors", () => {
    const at = new AdaptiveTimeout({ baseTimeoutMs: 1000 });
    assert.throws(() => at.retune({}), RangeError);
    assert.throws(() => at.retune(null as never), RangeError);
    assert.throws(() => at.retune("fast" as never), RangeError);
    assert.throws(() => at.retune([] as never), RangeError);
    assert.deepEqual(at.snapshot(), {
      baseTimeoutMs: 1000,
      marginRatio: 0.5,
      minTimeoutMs: 100,
      maxTimeoutMs: 4000,
      minSamples: 10,
      maxSamplesPerEndpoint: 1024,
    });
  });

  it("a same-value patch is a silent no-op returning the live config", () => {
    const at = new AdaptiveTimeout({
      baseTimeoutMs: 1000,
      marginRatio: 0.5,
      minTimeoutMs: 100,
      maxTimeoutMs: 4000,
      minSamples: 10,
    });
    const live = {
      baseTimeoutMs: 1000,
      marginRatio: 0.5,
      minTimeoutMs: 100,
      maxTimeoutMs: 4000,
      minSamples: 10,
      maxSamplesPerEndpoint: 1024,
    };
    assert.deepEqual(at.retune({ marginRatio: 0.5 }), live);
    assert.deepEqual(at.retune({ baseTimeoutMs: 1000, minSamples: 10 }), live);
    assert.deepEqual(at.snapshot(), live);
  });

  it("retune leaves the rolling samples and p99 unchanged", () => {
    const clock = manualClock();
    const at = new AdaptiveTimeout({
      baseTimeoutMs: 1000,
      marginRatio: 0.5,
      minSamples: 1,
      now: clock.now,
    });
    sample(at, "1", URL_A, 100, clock);
    sample(at, "2", URL_A, 200, clock);
    sample(at, "3", URL_A, 300, clock);
    const samplesBefore = at.stats().map((s) => ({
      endpoint: s.endpoint,
      samples: s.samples,
      p99Ms: s.p99Ms,
    }));
    assert.deepEqual(samplesBefore, [{ endpoint: URL_A, samples: 3, p99Ms: 300 }]);
    at.retune({
      marginRatio: 2,
      baseTimeoutMs: 5000,
      minTimeoutMs: 10,
      maxTimeoutMs: 99999,
      minSamples: 1,
    });
    const samplesAfter = at.stats().map((s) => ({
      endpoint: s.endpoint,
      samples: s.samples,
      p99Ms: s.p99Ms,
    }));
    assert.deepEqual(samplesAfter, samplesBefore);
    // Only the formula inputs moved: p99 300 * (1 + 2) = 900.
    assert.equal(at.timeoutFor(URL_A), 900);
  });
});

describe("RetryQueue adaptive timeout revision (WR-334)", () => {
  it("unconfigured: revise throws the must-restart Error, getter returns undefined", () => {
    const q = new RetryQueue({ sender: async () => {} });
    assert.equal(q.getAdaptiveTimeoutConfig(), undefined);
    assert.throws(
      () => q.reviseAdaptiveTimeout({ marginRatio: 1 }),
      /not configured — enabling it requires a restart/
    );
    assert.throws(
      () => q.reviseAdaptiveTimeout({ marginRatio: 1 }),
      /cannot start deriving p99 caps without one/
    );
    assert.equal(q.getAdaptiveTimeoutConfig(), undefined);
  });

  it("getter tracks revisions", () => {
    const q = new RetryQueue({
      sender: async () => {},
      adaptiveTimeout: {
        baseTimeoutMs: 1000,
        marginRatio: 0.5,
        minTimeoutMs: 100,
        maxTimeoutMs: 4000,
        minSamples: 10,
      },
    });
    assert.deepEqual(q.getAdaptiveTimeoutConfig(), {
      baseTimeoutMs: 1000,
      marginRatio: 0.5,
      minTimeoutMs: 100,
      maxTimeoutMs: 4000,
      minSamples: 10,
      maxSamplesPerEndpoint: 1024,
    });
    assert.deepEqual(q.reviseAdaptiveTimeout({ marginRatio: 1, minSamples: 5 }), {
      baseTimeoutMs: 1000,
      marginRatio: 1,
      minTimeoutMs: 100,
      maxTimeoutMs: 4000,
      minSamples: 5,
      maxSamplesPerEndpoint: 1024,
    });
    assert.deepEqual(q.getAdaptiveTimeoutConfig(), {
      baseTimeoutMs: 1000,
      marginRatio: 1,
      minTimeoutMs: 100,
      maxTimeoutMs: 4000,
      minSamples: 5,
      maxSamplesPerEndpoint: 1024,
    });
    q.stop();
  });

  it("an in-flight attempt keeps its stamped cap; the next dispatch uses the new cap", async () => {
    const stamps: Array<number | undefined> = [];
    let calls = 0;
    let release: (() => void) | undefined;
    const sender: Sender = async (it) => {
      calls += 1;
      stamps.push(it.adaptiveTimeoutMs);
      if (calls === 1) {
        await new Promise<void>((r) => {
          release = r;
        });
      }
    };
    const q = new RetryQueue({
      sender,
      // minSamples 100 keeps the endpoint cold, so the stamped cap is
      // always the base — the revision moves it deterministically.
      adaptiveTimeout: { baseTimeoutMs: 1000, minSamples: 100 },
      maxAttempts: 1,
    });
    q.start();
    q.enqueue(item("a", URL_A));
    await waitFor(() => calls === 1, "first dispatch");
    assert.deepEqual(stamps, [1000]); // stamped at dispatch, before the revision
    assert.deepEqual(q.reviseAdaptiveTimeout({ baseTimeoutMs: 2000 }), {
      baseTimeoutMs: 2000,
      marginRatio: 0.5,
      minTimeoutMs: 100,
      maxTimeoutMs: 4000,
      minSamples: 100,
      maxSamplesPerEndpoint: 1024,
    });
    release?.();
    await waitFor(() => q.pendingCount() === 0, "first delivery to settle");
    q.enqueue(item("b", URL_A));
    await waitFor(() => calls === 2, "second dispatch");
    assert.deepEqual(stamps, [1000, 2000]);
    q.stop();
  });
});

describe("RelayServer adaptive timeout revision (WR-334)", () => {
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

  function post(port: number, path: string) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path,
          method: "POST",
          headers: { "x-signature": signSha256(probeBody, signingKey) },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => {
            r.destroy();
            resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() });
          });
        }
      );
      r.on("error", reject);
      r.end(probeBody);
    });
  }

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "adaptive-timeout-revision-"));
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
    maxSamplesPerEndpoint: 1024,
  };

  it("revision audits previous/current with the construction values first; same-value is a silent no-op", async () => {
    const { relay, audit } = makeRelay({
      retry: { adaptiveTimeout: { ...construction } },
    });
    await listen(relay);
    assert.deepEqual(relay.getAdaptiveTimeoutConfig!(), construction);
    assert.deepEqual(relay.reviseAdaptiveTimeout!({ marginRatio: 1 }), {
      ...construction,
      marginRatio: 1,
    });
    const revised = eventsOf(audit, "adaptive_timeout_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, construction);
    assert.deepEqual(revised[0].current, { ...construction, marginRatio: 1 });
    // Landing exactly on the live values audits nothing.
    relay.reviseAdaptiveTimeout!({ marginRatio: 1 });
    assert.equal(eventsOf(audit, "adaptive_timeout_revised").length, 1);
    assert.deepEqual(relay.getAdaptiveTimeoutConfig!(), { ...construction, marginRatio: 1 });
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseAdaptiveTimeout!({ baseTimeoutMs: 0 }), RangeError);
    assert.throws(() => relay.reviseAdaptiveTimeout!({}), RangeError);
    assert.equal(eventsOf(audit, "adaptive_timeout_revised").length, 1);
    assert.deepEqual(relay.getAdaptiveTimeoutConfig!(), { ...construction, marginRatio: 1 });
  });

  it("unconfigured relay: revise throws the must-restart Error and the getter is not mounted", async () => {
    const { relay } = makeRelay();
    await listen(relay);
    assert.equal(relay.getAdaptiveTimeoutConfig, undefined);
    assert.throws(
      () => relay.reviseAdaptiveTimeout!({ marginRatio: 1 }),
      /not configured — enabling it requires a restart/
    );
  });

  it("server getter reflects revisions made through the server", async () => {
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
    relay.reviseAdaptiveTimeout!({ baseTimeoutMs: 3000 });
    assert.deepEqual(relay.getAdaptiveTimeoutConfig!(), {
      baseTimeoutMs: 3000,
      marginRatio: 0.5,
      minTimeoutMs: 100,
      maxTimeoutMs: 8000,
      minSamples: 3,
      maxSamplesPerEndpoint: 1024,
    });
  });

  it("server revision leaves an in-flight stamped cap unchanged; the next dispatch uses the new cap", async () => {
    const stamps: Array<number | undefined> = [];
    let calls = 0;
    let release: (() => void) | undefined;
    const sender: Sender = async (it) => {
      calls += 1;
      stamps.push(it.adaptiveTimeoutMs);
      if (calls === 1) {
        await new Promise<void>((r) => {
          release = r;
        });
      }
      return { statusCode: 200, body: Buffer.from("ok") };
    };
    const { relay, audit } = makeRelay({
      sender,
      retry: {
        baseDelayMs: 5,
        jitterMs: 0,
        maxAttempts: 2,
        // minSamples 100 keeps the endpoint cold, so the stamped cap
        // is always the base — the revision moves it deterministically.
        adaptiveTimeout: { baseTimeoutMs: 1000, minSamples: 100 },
      },
    });
    const port = await listen(relay);
    const res1 = await post(port, "/");
    assert.equal(res1.status, 202);
    await waitFor(() => calls === 1, "first dispatch");
    assert.deepEqual(stamps, [1000]); // stamped at dispatch, before the revision
    assert.deepEqual(relay.reviseAdaptiveTimeout!({ baseTimeoutMs: 2000 }), {
      baseTimeoutMs: 2000,
      marginRatio: 0.5,
      minTimeoutMs: 100,
      maxTimeoutMs: 4000,
      minSamples: 100,
      maxSamplesPerEndpoint: 1024,
    });
    assert.equal(eventsOf(audit, "adaptive_timeout_revised").length, 1);
    release?.();
    await new Promise((r) => setTimeout(r, 150)); // let the first delivery settle
    const res2 = await post(port, "/");
    assert.equal(res2.status, 202);
    await waitFor(() => calls === 2, "second dispatch");
    assert.deepEqual(stamps, [1000, 2000]);
    await flush();
  });
});
