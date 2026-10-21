import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  EndpointHealthTracker,
  assertValidEndpointHealthOptions,
  type EndpointHealthOptions,
} from "../src/endpoint-health.ts";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { renderPrometheus, type MetricsInput } from "../src/metrics.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

const URL = "http://127.0.0.1:9999/hook";
const OTHER_URL = "http://127.0.0.1:9999/other";

/** Deterministic timer: `run()` executes pending callbacks immediately. */
function manualTimer() {
  const pending: Array<() => void> = [];
  return {
    setTimer: (fn: () => void, _ms: number) => {
      pending.push(fn);
      return { clear: () => { const i = pending.indexOf(fn); if (i >= 0) pending.splice(i, 1); } };
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

function item(id: string, tenantId?: string) {
  return {
    id,
    payload: Buffer.from("hello"),
    targetUrl: URL,
    headers: {},
    ...(tenantId !== undefined ? { tenantId } : {}),
  };
}

describe("EndpointHealthTracker", () => {
  it("rejects invalid configs", () => {
    assert.throws(() => new EndpointHealthTracker({ ewmaAlpha: 0 }), RangeError);
    assert.throws(() => new EndpointHealthTracker({ ewmaAlpha: 1.5 }), RangeError);
    assert.throws(() => new EndpointHealthTracker({ maxLatencySamples: 0 }), RangeError);
    assert.throws(() => new EndpointHealthTracker({ maxLatencySamples: 1.5 }), RangeError);
    assert.throws(() => new EndpointHealthTracker({ sloMs: 0 }), RangeError);
    assert.throws(() => new EndpointHealthTracker({ sloMs: -5 }), RangeError);
    assert.throws(() => new EndpointHealthTracker({ successWeight: -1 }), RangeError);
    assert.throws(() => new EndpointHealthTracker({ latencyWeight: NaN }), RangeError);
    assert.throws(
      () => new EndpointHealthTracker({ successWeight: 0, latencyWeight: 0 }),
      RangeError
    );
    assert.throws(() => new EndpointHealthTracker({ circuitOpenPenalty: -1 }), RangeError);
    assert.throws(() => new EndpointHealthTracker({ degradeThreshold: -1 }), RangeError);
    assert.throws(() => new EndpointHealthTracker({ degradeThreshold: 101 }), RangeError);
    assert.throws(() => new EndpointHealthTracker({ recoverThreshold: 101 }), RangeError);
    // The strict degrade < recover gap is the hysteresis guarantee.
    assert.throws(
      () => new EndpointHealthTracker({ degradeThreshold: 70, recoverThreshold: 70 }),
      RangeError
    );
    assert.throws(
      () => new EndpointHealthTracker({ degradeThreshold: 80, recoverThreshold: 70 }),
      RangeError
    );
    // A lone degradeThreshold that would close the gap also throws.
    assert.throws(() => new EndpointHealthTracker({ degradeThreshold: 70 }), RangeError);
    assert.throws(
      () => new EndpointHealthTracker({ onEndpointDegraded: 42 as never }),
      RangeError
    );
    assert.throws(() => assertValidEndpointHealthOptions(null as never), RangeError);
    // Valid configs construct fine.
    new EndpointHealthTracker({});
    new EndpointHealthTracker({ successWeight: 1, latencyWeight: 0 });
    assertValidEndpointHealthOptions(undefined);
  });

  it("scores a pristine endpoint at 100 with an empty snapshot", () => {
    const t = new EndpointHealthTracker({ now: () => 0 });
    assert.equal(t.score(URL), 100);
    assert.equal(t.isDegraded(URL), false);
    assert.deepEqual(t.snapshot(), []);
    assert.equal(t.trackedEndpoints(), 0);
  });

  it("scores pure successes at 100", () => {
    const t = new EndpointHealthTracker({ now: () => 0 });
    for (let i = 0; i < 10; i++) t.recordOutcome(URL, true, 100);
    assert.equal(t.score(URL), 100);
    assert.equal(t.isDegraded(URL), false);
    const [row] = t.snapshot();
    assert.equal(row.endpoint, URL);
    assert.equal(row.score, 100);
    assert.equal(row.degraded, false);
    assert.equal(row.consecutiveLowScores, 0);
    assert.equal(row.successEwma, 1);
    assert.equal(row.p95Ms, 100);
    assert.equal(row.circuitState, "closed");
  });

  it("degrades on consecutive failures and reports consecutiveLowScores", () => {
    const degraded: Array<{ endpoint: string; score: number; consecutiveLowScores: number }> = [];
    const t = new EndpointHealthTracker({
      now: () => 0,
      onEndpointDegraded: (info) =>
        degraded.push({ endpoint: info.endpoint, score: info.score, consecutiveLowScores: info.consecutiveLowScores }),
    });
    // Defaults: 9 consecutive failures cross the degrade line (score 39.4 < 40).
    for (let i = 0; i < 8; i++) assert.equal(t.recordOutcome(URL, false), undefined);
    assert.equal(t.isDegraded(URL), false);
    const crossing = t.recordOutcome(URL, false);
    assert.equal(crossing?.kind, "degraded");
    assert.equal(t.isDegraded(URL), true);
    // The callback fires exactly once per episode, with the crossing info.
    assert.equal(degraded.length, 1);
    assert.equal(degraded[0].endpoint, URL);
    assert.ok(degraded[0].score < 40);
    assert.equal(degraded[0].consecutiveLowScores, 1);
    // Further low evaluations do not re-fire, but the live count grows.
    for (let i = 0; i < 3; i++) assert.equal(t.recordOutcome(URL, false), undefined);
    assert.equal(degraded.length, 1);
    const [row] = t.snapshot();
    assert.equal(row.degraded, true);
    assert.equal(row.consecutiveLowScores, 4);
    assert.ok(row.score < 40);
  });

  it("applies hysteresis: the band neither degrades nor recovers", () => {
    const recovered: unknown[] = [];
    const t = new EndpointHealthTracker({
      ewmaAlpha: 0.5,
      successWeight: 1,
      latencyWeight: 0,
      now: () => 0,
      onEndpointRecovered: (info) => recovered.push(info),
    });
    t.recordOutcome(URL, false); // ewma 0.5 -> score 50, not yet degraded
    assert.equal(t.isDegraded(URL), false);
    t.recordOutcome(URL, false); // ewma 0.25 -> score 25 < 40, degraded
    assert.equal(t.isDegraded(URL), true);
    t.recordOutcome(URL, true); // ewma 0.625 -> score 62.5, in the band: no recover
    assert.equal(t.isDegraded(URL), true);
    assert.deepEqual(recovered, []);
    const [row] = t.snapshot();
    assert.equal(row.consecutiveLowScores, 0); // the band breaks the low streak
    assert.equal(row.degraded, true);
    t.recordOutcome(URL, true); // ewma 0.8125 -> score 81.25 > 70: recovered
    assert.equal(t.isDegraded(URL), false);
    assert.equal(recovered.length, 1);
    // And a fresh degradation episode fires again.
    t.recordOutcome(URL, false); // ewma 0.40625 -> score 40.625, still in the band
    assert.equal(t.isDegraded(URL), false);
    t.recordOutcome(URL, false); // ewma 0.203 -> score 20.3 < 40: degraded
    assert.equal(t.isDegraded(URL), true);
  });

  it("does not flap on scores hovering at the thresholds", () => {
    const transitions: string[] = [];
    const t = new EndpointHealthTracker({
      ewmaAlpha: 1,
      successWeight: 1,
      latencyWeight: 0,
      now: () => 0,
      onEndpointDegraded: () => transitions.push("degraded"),
      onEndpointRecovered: () => transitions.push("recovered"),
    });
    // With alpha 1 the score jumps between exactly 0 and 100 — the band
    // never holds it, so exactly one transition fires per crossing.
    t.recordOutcome(URL, false);
    t.recordOutcome(URL, false);
    t.recordOutcome(URL, true);
    t.recordOutcome(URL, true);
    assert.deepEqual(transitions, ["degraded", "recovered"]);
  });

  it("grades an open circuit at 0 by default (half_open carries no penalty)", () => {
    let state: "closed" | "open" | "half_open" = "closed";
    const t = new EndpointHealthTracker({
      now: () => 0,
      circuitState: () => state,
    });
    for (let i = 0; i < 5; i++) t.recordOutcome(URL, true, 100);
    assert.equal(t.score(URL), 100);
    state = "open";
    assert.equal(t.score(URL), 0);
    const [row] = t.snapshot();
    assert.equal(row.circuitState, "open");
    assert.equal(row.score, 0);
    // An open circuit drags the next evaluation below the degrade line.
    const crossing = t.recordOutcome(URL, true, 100);
    assert.equal(crossing?.kind, "degraded");
    state = "half_open";
    assert.ok(t.score(URL) > 70); // no penalty while probing
    state = "closed";
    assert.equal(t.score(URL), 100);
  });

  it("honors a custom circuit-open penalty", () => {
    const t = new EndpointHealthTracker({
      now: () => 0,
      circuitOpenPenalty: 30,
      circuitState: () => "open",
    });
    t.recordOutcome(URL, true, 100);
    assert.equal(t.score(URL), 70);
  });

  it("degrades the latency term linearly between sloMs and 2x sloMs", () => {
    const t = new EndpointHealthTracker({ now: () => 0, sloMs: 1000 });
    for (let i = 0; i < 5; i++) t.recordOutcome(URL, true, 1000);
    assert.equal(t.score(URL), 100); // p95 == sloMs: full marks
    const slow = new EndpointHealthTracker({ now: () => 0, sloMs: 1000 });
    for (let i = 0; i < 5; i++) slow.recordOutcome(URL, true, 1500);
    // latencyTerm 0.5 -> 100 * (0.7 * 1 + 0.3 * 0.5) = 85
    assert.equal(slow.score(URL), 85);
    const slower = new EndpointHealthTracker({ now: () => 0, sloMs: 1000 });
    for (let i = 0; i < 5; i++) slower.recordOutcome(URL, true, 5000);
    // latencyTerm 0 -> 100 * 0.7 = 70
    assert.equal(slower.score(URL), 70);
    // No latency samples: the term stays at full marks, never fabricated.
    const noLatency = new EndpointHealthTracker({ now: () => 0, sloMs: 1000 });
    for (let i = 0; i < 5; i++) noLatency.recordOutcome(URL, true);
    assert.equal(noLatency.score(URL), 100);
    assert.equal(noLatency.snapshot()[0].p95Ms, undefined);
  });

  it("tracks endpoints independently", () => {
    const t = new EndpointHealthTracker({ now: () => 0 });
    for (let i = 0; i < 12; i++) t.recordOutcome(URL, false);
    t.recordOutcome(OTHER_URL, true);
    assert.equal(t.isDegraded(URL), true);
    assert.equal(t.isDegraded(OTHER_URL), false);
    assert.equal(t.trackedEndpoints(), 2);
  });

  it("ignores invalid latency samples without failing", () => {
    const t = new EndpointHealthTracker({ now: () => 0 });
    t.recordOutcome(URL, true, NaN);
    t.recordOutcome(URL, true, -5);
    t.recordOutcome(URL, true, Infinity);
    assert.equal(t.score(URL), 100);
    assert.equal(t.snapshot()[0].p95Ms, undefined);
  });

  it("returns the transition from recordOutcome for programmatic use", () => {
    const t = new EndpointHealthTracker({ now: () => 1234, ewmaAlpha: 1, successWeight: 1, latencyWeight: 0 });
    const tr = t.recordOutcome(URL, false);
    assert.equal(tr?.kind, "degraded");
    if (tr?.kind === "degraded") {
      assert.equal(tr.endpoint, URL);
      assert.equal(tr.score, 0);
      assert.equal(tr.consecutiveLowScores, 1);
      assert.equal(tr.at, 1234);
    }
  });
});

describe("WR-179 metrics", () => {
  function baseInput(): MetricsInput {
    return {
      deliveries: [],
      circuits: [],
      latencyHistograms: [],
    };
  }

  it("renders relay_endpoint_health_score when enabled with outcomes", () => {
    const out = renderPrometheus({
      ...baseInput(),
      endpointHealth: [
        { endpoint: URL, score: 92.5 },
        { endpoint: OTHER_URL, tenant: "acme", score: 31.25 },
      ],
    });
    assert.match(out, /# HELP relay_endpoint_health_score /);
    assert.match(out, /# TYPE relay_endpoint_health_score gauge/);
    assert.ok(out.includes(`relay_endpoint_health_score{endpoint="${URL}"} 92.5`));
    assert.ok(
      out.includes(`relay_endpoint_health_score{endpoint="${OTHER_URL}",tenant="acme"} 31.25`)
    );
  });

  it("renders no health series when disabled or without outcomes", () => {
    assert.ok(!renderPrometheus(baseInput()).includes("relay_endpoint_health_score"));
    assert.ok(
      !renderPrometheus({ ...baseInput(), endpointHealth: [] }).includes("relay_endpoint_health_score")
    );
  });

  it("escapes endpoint label values", () => {
    const out = renderPrometheus({
      ...baseInput(),
      endpointHealth: [{ endpoint: 'http://x/"q"\n', score: 50 }],
    });
    assert.ok(out.includes('relay_endpoint_health_score{endpoint="http://x/\\"q\\"\\n"} 50'));
  });
});

describe("WR-179 queue integration", () => {
  it("is disabled by default: no stats, no series", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue(item("item-1"));
    await timer.run();
    assert.deepEqual(q.getEndpointHealthStats(), []);
    assert.ok(!q.renderMetrics().includes("relay_endpoint_health_score"));
    q.stop();
  });

  it("rejects invalid endpointHealth config at construction", () => {
    assert.throws(
      () =>
        new RetryQueue({
          sender: async () => {},
          endpointHealth: { degradeThreshold: 70, recoverThreshold: 70 } as EndpointHealthOptions,
        }),
      RangeError
    );
  });

  it("scores deliveries and exposes the gauge", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      endpointHealth: {},
    });
    q.start();
    q.enqueue(item("item-1"));
    await timer.run();
    const stats = q.getEndpointHealthStats();
    assert.equal(stats.length, 1);
    assert.equal(stats[0].endpoint, URL);
    assert.equal(stats[0].score, 100);
    assert.equal(stats[0].degraded, false);
    assert.ok(q.renderMetrics().includes(`relay_endpoint_health_score{endpoint="${URL}"} 100`));
    q.stop();
  });

  it("degrades after consecutive failures and recovers on success", async () => {
    const timer = manualTimer();
    const degraded: Array<{ endpoint: string; score: number; consecutiveLowScores: number; tenant?: string }> = [];
    const recovered: Array<{ endpoint: string; score: number }> = [];
    let fail = true;
    const flaky: Sender = async () => {
      if (fail) throw new Error("downstream down");
    };
    const q = new RetryQueue({
      sender: flaky,
      baseDelayMs: 1,
      maxDelayMs: 10,
      maxAttempts: 1,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      endpointHealth: {
        onEndpointDegraded: (info) => degraded.push(info),
        onEndpointRecovered: (info) => recovered.push(info),
      },
    });
    q.start();
    for (let i = 0; i < 9; i++) q.enqueue(item(`fail-${i}`));
    await timer.run();
    assert.equal(degraded.length, 1);
    assert.equal(degraded[0].endpoint, URL);
    assert.ok(degraded[0].score < 40);
    assert.equal(degraded[0].consecutiveLowScores, 1);
    assert.equal(degraded[0].tenant, undefined);
    const [row] = q.getEndpointHealthStats();
    assert.equal(row.degraded, true);
    assert.ok(row.consecutiveLowScores >= 1);
    // Successes climb back above the recover line (hysteresis: 4 needed).
    fail = false;
    for (let i = 0; i < 4; i++) q.enqueue(item(`ok-${i}`));
    await timer.run();
    assert.equal(recovered.length, 1);
    assert.equal(recovered[0].endpoint, URL);
    assert.ok(recovered[0].score > 70);
    assert.equal(q.getEndpointHealthStats()[0].degraded, false);
    q.stop();
  });

  it("grades an open circuit at 0 and attributes the tenant", async () => {
    const timer = manualTimer();
    const degraded: Array<{ tenant?: string }> = [];
    const q = new RetryQueue({
      sender: async () => {
        throw new Error("downstream down");
      },
      baseDelayMs: 1,
      maxDelayMs: 10,
      maxAttempts: 1,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      circuitBreaker: { failureThreshold: 1, cooldownMs: 60000 },
      endpointHealth: { onEndpointDegraded: (info) => degraded.push(info) },
    });
    q.start();
    q.enqueue(item("t-1", "acme"));
    await timer.run();
    const stats = q.getEndpointHealthStats();
    assert.equal(stats.length, 1);
    assert.equal(stats[0].endpoint, URL);
    assert.equal(stats[0].tenant, "acme");
    assert.equal(stats[0].score, 0);
    assert.equal(stats[0].circuitState, "open");
    assert.equal(stats[0].degraded, true);
    assert.equal(degraded.length, 1);
    assert.equal(degraded[0].tenant, "acme");
    // The tenant filter narrows the operator view.
    assert.equal(q.getEndpointHealthStats("acme").length, 1);
    assert.deepEqual(q.getEndpointHealthStats("other"), []);
    // The gauge carries the tenant label.
    assert.ok(
      q.renderMetrics().includes(`relay_endpoint_health_score{endpoint="${URL}",tenant="acme"} 0`)
    );
    q.stop();
  });
});

describe("WR-179 operator endpoint", () => {
  let stub: Server;
  let stubPort: number;
  const relaySecret = "test-relay-secret";

  function get(port: number, path: string, headers: Record<string, string> = {}) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest(
        { host: "127.0.0.1", port, path, method: "GET", headers },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () =>
            resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
          );
        }
      );
      r.on("error", reject);
      r.end();
    });
  }

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  before(async () => {
    stub = createServer((req, res) => {
      res.writeHead(200).end("ok");
    });
    stubPort = await listen(stub);
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  it("404s fail-closed without an operatorToken", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const relay = createRelayServer({
      secret: relaySecret,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      retry: { endpointHealth: {} },
    });
    const port = await listen(relay);
    try {
      const res = await get(port, "/endpoint-health");
      assert.equal(res.status, 404);
    } finally {
      relay.close();
    }
  });

  it("serves the health snapshot to a bearer-authenticated operator", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const relay = createRelayServer({
      secret: relaySecret,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      operatorToken: "op-token",
      retry: { endpointHealth: {} },
    });
    const port = await listen(relay);
    try {
      // No outcomes yet: empty snapshot, still 200.
      const empty = await get(port, "/endpoint-health", { authorization: "Bearer op-token" });
      assert.equal(empty.status, 200);
      assert.deepEqual(JSON.parse(empty.text), []);
      // A wrong bearer is 403, not a leak.
      const bad = await get(port, "/endpoint-health", { authorization: "Bearer wrong" });
      assert.equal(bad.status, 403);
      // POST is not allowed on the read-only route (authenticated, so the
      // registry's 405 surfaces instead of the auth layer's 403).
      const postRes = await new Promise<{ status: number }>((resolve, reject) => {
        const r = httpRequest(
          {
            host: "127.0.0.1",
            port,
            path: "/endpoint-health",
            method: "POST",
            headers: { authorization: "Bearer op-token" },
          },
          (res) => {
            res.resume();
            res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
          }
        );
        r.on("error", reject);
        r.end();
      });
      assert.equal(postRes.status, 405);
    } finally {
      relay.close();
    }
  });

  it("is listed in the OpenAPI operator surface", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const relay = createRelayServer({
      secret: relaySecret,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      operatorToken: "op-token",
    });
    const port = await listen(relay);
    try {
      const res = await get(port, "/openapi.json", { authorization: "Bearer op-token" });
      assert.equal(res.status, 200);
      assert.ok(res.text.includes("/endpoint-health"));
    } finally {
      relay.close();
    }
  });
});
