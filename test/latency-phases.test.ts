import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, type AddressInfo } from "node:http";
import { createDefaultSender } from "../src/server.ts";
import {
  RetryQueue,
  LatencyPhasesTracker,
  dominantPhaseOf,
  type DownstreamResponse,
  type Sender,
  type SloMissInfo,
} from "../src/retry.ts";

/**
 * WR-95 tests. The tracker is pure aggregation over sender-measured
 * samples — no clock drives the math — so unit tests feed synthetic
 * samples directly; the injected `now` only stamps the operational
 * `lastSampleAt` marker. Queue tests drive deliveries through the real
 * queue with a synthetic sender; the sender-instrumentation tests use the
 * real H1 sender against a local stub.
 */

/** Deterministic timer: `run()` executes pending callbacks immediately. */
function manualTimer() {
  const pending: Array<() => void> = [];
  return {
    setTimer: (fn: () => void, _ms: number) => {
      pending.push(fn);
      return {
        clear: () => {
          const i = pending.indexOf(fn);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    async run() {
      while (pending.length > 0) {
        const fns = pending.splice(0);
        for (const fn of fns) fn();
        await new Promise((r) => setImmediate(r));
      }
    },
  };
}

const URL = "http://localhost:9999/hook";

function item(id: string, tenantId?: string) {
  return {
    id,
    payload: Buffer.from("hello"),
    targetUrl: URL,
    headers: {},
    ...(tenantId !== undefined ? { tenantId } : {}),
  };
}

describe("WR-95 LatencyPhasesTracker (unit)", () => {
  it("records per-phase samples and exposes p50/p95/latest/count", () => {
    const t = new LatencyPhasesTracker();
    t.recordPhases("e", { connectMs: 10, tlsMs: 30, firstByteMs: 200, bodyMs: 50 });
    t.recordPhases("e", { connectMs: 20, firstByteMs: 300, bodyMs: 60 });
    const [row] = t.stats();
    assert.equal(row.endpoint, "e");
    assert.deepEqual(row.phases.connect, { count: 2, p50: 10, p95: 20, latest: 20 });
    // tls measured once: p50 == p95 == the single sample.
    assert.deepEqual(row.phases.tls, { count: 1, p50: 30, p95: 30, latest: 30 });
    // dns never measured: absent, never fabricated.
    assert.equal(row.phases.dns, undefined);
    assert.ok(row.lastSampleAt > 0);
  });

  it("dominantPhase picks the phase with the largest p50", () => {
    const t = new LatencyPhasesTracker();
    t.recordPhases("e", { connectMs: 10, tlsMs: 30, firstByteMs: 200, bodyMs: 50 });
    assert.equal(t.dominantPhase("e"), "firstByte");
    assert.equal(t.dominantPhase("unknown"), undefined);
    const empty = new LatencyPhasesTracker();
    assert.equal(empty.dominantPhase("e"), undefined);
  });

  it("dominantPhaseOf picks the largest measured duration, ties go to the earliest phase", () => {
    assert.equal(dominantPhaseOf(undefined), undefined);
    assert.equal(dominantPhaseOf({}), undefined);
    assert.equal(
      dominantPhaseOf({ connectMs: 10, tlsMs: 30, firstByteMs: 200, bodyMs: 50 }),
      "firstByte"
    );
    // dnsMs wins when largest, even though usually unavailable.
    assert.equal(dominantPhaseOf({ dnsMs: 500, firstByteMs: 200 }), "dns");
    // Tie: earliest phase in wire order wins.
    assert.equal(dominantPhaseOf({ connectMs: 100, bodyMs: 100 }), "connect");
  });

  it("ignores non-finite or negative samples (a misbehaving sender cannot corrupt the distribution)", () => {
    const t = new LatencyPhasesTracker();
    t.recordPhases("e", {
      connectMs: -5,
      tlsMs: NaN,
      firstByteMs: Infinity,
      bodyMs: 40,
    });
    const [row] = t.stats();
    assert.equal(row.phases.connect, undefined);
    assert.equal(row.phases.tls, undefined);
    assert.equal(row.phases.firstByte, undefined);
    assert.equal(row.phases.body?.count, 1);
  });

  it("evicts the oldest sample past the window", () => {
    const t = new LatencyPhasesTracker({ maxSamplesPerEndpoint: 2 });
    t.recordPhases("e", { bodyMs: 10 });
    t.recordPhases("e", { bodyMs: 20 });
    t.recordPhases("e", { bodyMs: 30 });
    const [row] = t.stats();
    assert.deepEqual(row.phases.body, { count: 2, p50: 20, p95: 30, latest: 30 });
  });

  it("stats(endpoint) filters; endpoints with no samples are omitted", () => {
    const t = new LatencyPhasesTracker();
    t.recordPhases("a", { bodyMs: 10 });
    t.recordPhases("b", {}); // nothing measurable — no row
    assert.equal(t.stats("a").length, 1);
    assert.equal(t.stats("b").length, 0);
    assert.equal(t.stats().length, 1);
  });

  it("uses the injected clock for lastSampleAt", () => {
    let now = 1_000;
    const t = new LatencyPhasesTracker({ now: () => now });
    t.recordPhases("e", { bodyMs: 10 });
    assert.equal(t.stats()[0].lastSampleAt, 1_000);
    now = 2_000;
    t.recordPhases("e", { bodyMs: 20 });
    assert.equal(t.stats()[0].lastSampleAt, 2_000);
  });

  it("rejects an invalid window with RangeError", () => {
    assert.throws(() => new LatencyPhasesTracker({ maxSamplesPerEndpoint: 0 }), RangeError);
    assert.throws(() => new LatencyPhasesTracker({ maxSamplesPerEndpoint: 1.5 }), RangeError);
  });
});

/** Start a trivial 200-OK stub; resolves with its base URL. */
async function startStub(): Promise<{ url: string; close: () => Promise<void> }> {
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;
  return {
    url: `http://127.0.0.1:${port}/hook`,
    close: () => new Promise<void>((r) => server.close(() => r())),
  };
}

describe("WR-95 latency phases (queue)", () => {
  it("is disabled by default: no stats, phases ignored", async () => {
    const timer = manualTimer();
    const withPhases: Sender = async () => ({
      statusCode: 200,
      body: Buffer.alloc(0),
      truncated: false,
      phases: { firstByteMs: 5, bodyMs: 1 },
    });
    const q = new RetryQueue({
      sender: withPhases,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue(item("d-1"));
    await timer.run();
    assert.equal(q.getLatencyPhaseStats(), undefined);
    q.stop();
  });

  it("records sender-measured phases per endpoint and exposes them via getStats", async () => {
    const timer = manualTimer();
    const withPhases: Sender = async () => ({
      statusCode: 200,
      body: Buffer.alloc(0),
      truncated: false,
      phases: { connectMs: 8, tlsMs: 21, firstByteMs: 120, bodyMs: 9 },
    });
    const q = new RetryQueue({
      sender: withPhases,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      latencyPhases: {},
    });
    q.start();
    q.enqueue(item("p-1"));
    q.enqueue(item("p-2"));
    await timer.run();
    const rows = q.getLatencyPhaseStats() ?? [];
    assert.equal(rows.length, 1);
    assert.equal(rows[0].endpoint, URL);
    assert.equal(rows[0].phases.firstByte?.count, 2);
    assert.equal(rows[0].phases.firstByte?.p50, 120);
    assert.equal(rows[0].phases.connect?.p95, 8);
    assert.equal(rows[0].phases.dns, undefined); // never fabricated
    q.stop();
  });

  it("attributes the dominant phase on SLO miss (onSloMiss hook)", async () => {
    const timer = manualTimer();
    const misses: SloMissInfo[] = [];
    const slowish: Sender = async () => {
      // Sleep past the 1ms SLO budget so the miss fires.
      await new Promise((r) => setTimeout(r, 5));
      return {
        statusCode: 200,
        body: Buffer.alloc(0),
        truncated: false,
        phases: { connectMs: 1, firstByteMs: 4, bodyMs: 2 },
      };
    };
    const q = new RetryQueue({
      sender: slowish,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      latency: { sloMs: 1, onSloMiss: (info) => misses.push(info) },
      latencyPhases: {},
    });
    q.start();
    q.enqueue(item("s-1"));
    await timer.run();
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(misses.length, 1);
    assert.equal(misses[0].dominantPhase, "firstByte");
    assert.deepEqual(misses[0].phaseBreakdown, {
      connectMs: 1,
      firstByteMs: 4,
      bodyMs: 2,
    });
    q.stop();
  });

  it("omits attribution when no phase was measurable", async () => {
    const timer = manualTimer();
    const misses: SloMissInfo[] = [];
    const plain: Sender = async () => {
      await new Promise((r) => setTimeout(r, 5));
      return { statusCode: 200, body: Buffer.alloc(0), truncated: false };
    };
    const q = new RetryQueue({
      sender: plain,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      latency: { sloMs: 1, onSloMiss: (info) => misses.push(info) },
      latencyPhases: {},
    });
    q.start();
    q.enqueue(item("u-1"));
    await timer.run();
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(misses.length, 1);
    assert.equal(misses[0].dominantPhase, undefined);
    assert.equal(misses[0].phaseBreakdown, undefined);
    q.stop();
  });

  it("scopes phase trackers per tenant", async () => {
    const timer = manualTimer();
    const withPhases: Sender = async () => ({
      statusCode: 200,
      body: Buffer.alloc(0),
      truncated: false,
      phases: { bodyMs: 7 },
    });
    const q = new RetryQueue({
      sender: withPhases,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      latencyPhases: {},
    });
    q.start();
    q.enqueue(item("n-1", "acme"));
    q.enqueue(item("n-2"));
    await timer.run();
    const rows = q.getLatencyPhaseStats() ?? [];
    const tenants = new Set(rows.map((r) => r.tenant ?? ""));
    assert.ok(tenants.has("acme"));
    assert.ok(tenants.has(""));
    q.stop();
  });
});

describe("WR-95 sender phase measurement (real H1 sender)", () => {
  it("measures phases on a fresh connection; dns stays unavailable", async () => {
    const stub = await startStub();
    // keepAlive=false → one-off agent → fresh connection per delivery.
    // 22 params: (tlsPins, keepAlive=false, …, measureLatencyPhases=true).
    const sender = createDefaultSender(
      undefined, false, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined,
      undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, true
    );
    try {
      const resp = (await sender({
        id: "m-1",
        payload: Buffer.from("{}"),
        targetUrl: stub.url,
        headers: {},
      })) as DownstreamResponse | void;
      assert.ok(resp !== undefined);
      const phases = resp.phases;
      assert.ok(phases !== undefined, "phases should be measured when enabled");
      assert.ok(
        typeof phases.firstByteMs === "number" && phases.firstByteMs >= 0,
        `firstByteMs=${phases.firstByteMs}`
      );
      assert.ok(
        typeof phases.bodyMs === "number" && phases.bodyMs >= 0,
        `bodyMs=${phases.bodyMs}`
      );
      assert.ok(
        typeof phases.connectMs === "number" && phases.connectMs >= 0,
        `connectMs=${phases.connectMs}`
      );
      assert.equal(phases.dnsMs, undefined); // never fabricated
      assert.equal(phases.tlsMs, undefined); // plain http
    } finally {
      sender.destroy();
      await stub.close();
    }
  });

  it("attaches no phases when measurement is off (zero overhead)", async () => {
    const stub = await startStub();
    const sender = createDefaultSender(undefined, false);
    try {
      const resp = (await sender({
        id: "m-2",
        payload: Buffer.from("{}"),
        targetUrl: stub.url,
        headers: {},
      })) as DownstreamResponse | void;
      assert.ok(resp !== undefined);
      assert.equal(resp.phases, undefined);
    } finally {
      sender.destroy();
      await stub.close();
    }
  });

  it("reports connect as unavailable on pooled socket reuse", async () => {
    const stub = await startStub();
    // Default pooling: the first delivery opens the connection, the second
    // reuses it — the reused socket cannot report connect timing.
    // 22 params: (…, keepAlive default, …, measureLatencyPhases=true).
    const sender = createDefaultSender(
      undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined,
      undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, true
    );
    try {
      const first = (await sender({
        id: "r-1",
        payload: Buffer.from("{}"),
        targetUrl: stub.url,
        headers: {},
      })) as DownstreamResponse;
      assert.ok(first.phases?.connectMs !== undefined, "fresh socket measures connect");
      const second = (await sender({
        id: "r-2",
        payload: Buffer.from("{}"),
        targetUrl: stub.url,
        headers: {},
      })) as DownstreamResponse;
      assert.ok(second.phases !== undefined);
      assert.equal(second.phases.connectMs, undefined); // reused — unavailable
      // firstByte/body are always measurable.
      assert.ok(typeof second.phases.firstByteMs === "number");
      assert.ok(typeof second.phases.bodyMs === "number");
    } finally {
      sender.destroy();
      await stub.close();
    }
  });
});
