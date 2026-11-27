import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type RetryItem, type SloMissInfo } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "latency-enable-test-key";
const opToken = "latency-enable-op-token";
const URL = "http://127.0.0.1:9999/hook";

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

function item(id: string): RetryItem {
  return { id, targetUrl: URL, payload: Buffer.from("x"), headers: {} };
}

describe("RetryQueue.enableLatency live enable (WR-474)", () => {
  /** Queue constructed without latency tracking, on a fake clock. */
  function makeQueue(sender?: () => Promise<void>, maxAttempts?: number) {
    let now = 0;
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: sender ?? (async () => {}),
      jitterMs: 0,
      ...(maxAttempts === undefined ? {} : { maxAttempts }),
      setTimer: timer.setTimer,
    });
    q.start();
    async function deliver(id: string, latencyMs: number) {
      now = 0;
      q.enqueue(item(id));
      now = latencyMs;
      await timer.run();
    }
    return { q, timer, deliver, nowFn: () => now, setNow: (v: number) => { now = v; } };
  }

  it("empty opts enable with the construction defaults and mount the getter", async () => {
    const { q } = makeQueue();
    try {
      assert.equal(q.latencyConfigured(), false);
      assert.equal(q.getLatencyConfig(), undefined);
      q.enableLatency();
      assert.equal(q.latencyConfigured(), true);
      assert.deepEqual(q.getLatencyConfig(), { sloMs: 5000, maxSamplesPerEndpoint: 1024 });
      // `{}` enables with the same defaults.
      const second = makeQueue();
      try {
        second.q.enableLatency({});
        assert.deepEqual(second.q.getLatencyConfig(), { sloMs: 5000, maxSamplesPerEndpoint: 1024 });
      } finally {
        second.q.stop();
      }
      // The returned config is a snapshot: mutating it never moves the queue.
      const snap = q.getLatencyConfig()!;
      snap.sloMs = 1;
      snap.maxSamplesPerEndpoint = 1;
      assert.deepEqual(q.getLatencyConfig(), { sloMs: 5000, maxSamplesPerEndpoint: 1024 });
    } finally {
      q.stop();
    }
  });

  it("explicit sloMs and maxSamplesPerEndpoint: the third sample evicts the oldest", async () => {
    const { q, deliver, nowFn } = makeQueue();
    try {
      q.enableLatency({ sloMs: 50, maxSamplesPerEndpoint: 2, now: nowFn });
      await deliver("w-1", 10);
      await deliver("w-2", 20);
      await deliver("w-3", 30);
      const [s] = q.getLatencyStats();
      assert.equal(s.count, 2);
      assert.equal(s.min, 20);
      assert.equal(s.max, 30);
      assert.equal(s.p50, 20);
      assert.equal(s.p95, 30);
      assert.equal(s.p99, 30);
      assert.equal(s.sloMs, 50);
      assert.equal(s.withinSlo, 2);
      assert.equal(s.sloAttainment, 1);
    } finally {
      q.stop();
    }
  });

  it("illegal sloMs throws RangeError and the queue stays unconfigured, still enableable", async () => {
    const { q, nowFn } = makeQueue();
    try {
      for (const sloMs of [0, -1, NaN, Infinity, "100" as never]) {
        assert.throws(() => q.enableLatency({ sloMs, now: nowFn }), RangeError);
        assert.equal(q.latencyConfigured(), false, "an illegal sloMs must not enable");
        assert.equal(q.getLatencyConfig(), undefined);
      }
      q.enableLatency({ sloMs: 50, now: nowFn });
      assert.deepEqual(q.getLatencyConfig(), { sloMs: 50, maxSamplesPerEndpoint: 1024 });
    } finally {
      q.stop();
    }
  });

  it("illegal maxSamplesPerEndpoint throws RangeError and the queue stays unconfigured, still enableable", async () => {
    const { q, nowFn } = makeQueue();
    try {
      for (const maxSamplesPerEndpoint of [0, 1.5, NaN]) {
        assert.throws(
          () => q.enableLatency({ maxSamplesPerEndpoint, now: nowFn }),
          RangeError
        );
        assert.equal(q.latencyConfigured(), false, "an illegal window must not enable");
        assert.equal(q.getLatencyConfig(), undefined);
      }
      q.enableLatency({ maxSamplesPerEndpoint: 2, now: nowFn });
      assert.deepEqual(q.getLatencyConfig(), { sloMs: 5000, maxSamplesPerEndpoint: 2 });
    } finally {
      q.stop();
    }
  });

  it("non-object opts throw RangeError and the queue stays unconfigured", async () => {
    const { q, nowFn } = makeQueue();
    try {
      assert.throws(() => q.enableLatency(null as never), RangeError);
      assert.throws(() => q.enableLatency("nope" as never), RangeError);
      assert.throws(() => q.enableLatency([] as never), RangeError);
      assert.equal(q.latencyConfigured(), false);
      assert.equal(q.getLatencyConfig(), undefined);
      q.enableLatency({ now: nowFn });
      assert.deepEqual(q.getLatencyConfig(), { sloMs: 5000, maxSamplesPerEndpoint: 1024 });
    } finally {
      q.stop();
    }
  });

  it("an already-configured queue throws Error and the live config is untouched", async () => {
    // Constructed with latency: enabling is an error, never a revision.
    const timer = manualTimer();
    const configured = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      latency: { sloMs: 100 },
      setTimer: timer.setTimer,
    });
    try {
      assert.throws(() => configured.enableLatency({ sloMs: 50 }), {
        name: "Error",
        message: "enableLatency: latency tracking is already configured",
      });
      assert.deepEqual(configured.getLatencyConfig(), { sloMs: 100, maxSamplesPerEndpoint: 1024 });
    } finally {
      configured.stop();
    }
    // Enabled live: a second enable is the same error, config unchanged.
    const { q, nowFn } = makeQueue();
    try {
      q.enableLatency({ sloMs: 50, now: nowFn });
      assert.throws(() => q.enableLatency({ sloMs: 60 }), {
        name: "Error",
        message: "enableLatency: latency tracking is already configured",
      });
      assert.deepEqual(q.getLatencyConfig(), { sloMs: 50, maxSamplesPerEndpoint: 1024 });
    } finally {
      q.stop();
    }
  });

  it("a delivery enqueued before the enable never samples after it", async () => {
    const { q, timer, setNow, nowFn } = makeQueue();
    const misses: SloMissInfo[] = [];
    try {
      q.enqueue(item("pre-1"));
      q.enableLatency({ sloMs: 100, now: nowFn });
      // The miss observer is installable now — but the pre-enable
      // delivery has no accepted clock, so no miss can fire for it.
      q.reviseSloMissCallback((info) => misses.push(info));
      setNow(250);
      await timer.run();
      assert.deepEqual(q.getLatencyStats(), []);
      assert.ok(!q.renderMetrics().includes("relay_delivery_latency_seconds"));
      assert.deepEqual(misses, []);
    } finally {
      q.stop();
    }
  });

  it("after the enable the next enqueue samples: stats row with percentiles and attainment", async () => {
    const { q, deliver, nowFn } = makeQueue();
    try {
      q.enableLatency({ sloMs: 100, now: nowFn });
      await deliver("s-1", 250);
      const [s] = q.getLatencyStats();
      assert.equal(s.count, 1);
      assert.equal(s.p50, 250);
      assert.equal(s.p95, 250);
      assert.equal(s.p99, 250);
      assert.equal(s.sloMs, 100);
      assert.equal(s.withinSlo, 0);
      assert.equal(s.sloAttainment, 0);
      // A fast delivery samples too, without a miss.
      await deliver("s-2", 20);
      const [s2] = q.getLatencyStats();
      assert.equal(s2.count, 2);
      assert.equal(s2.sloAttainment, 0.5);
    } finally {
      q.stop();
    }
  });

  it("a dead letter after the enable is discarded without sampling", async () => {
    const { q, timer, nowFn } = makeQueue(async () => {
      throw new Error("down");
    }, 1);
    try {
      q.enableLatency({ now: nowFn });
      q.enqueue(item("d-1"));
      await timer.run();
      assert.equal(q.getDeadLetter().length, 1);
      assert.deepEqual(q.getLatencyStats(), []);
      assert.ok(!q.renderMetrics().includes("relay_delivery_latency_seconds"));
    } finally {
      q.stop();
    }
  });

  it("enabling unlocks reviseSloMissCallback; the gate precedes validation while closed", async () => {
    const { q, deliver, nowFn } = makeQueue();
    const seen: SloMissInfo[] = [];
    try {
      assert.throws(() => q.reviseSloMissCallback(() => {}), {
        name: "Error",
        message:
          "reviseSloMissCallback: latency tracking is not configured — enabling SLO-miss observation requires a restart",
      });
      q.enableLatency({ sloMs: 100, now: nowFn });
      q.reviseSloMissCallback((info) => seen.push(info));
      await deliver("g-1", 250);
      assert.equal(seen.length, 1);
      assert.equal(seen[0].id, "g-1");
      assert.equal(seen[0].latencyMs, 250);
      assert.equal(seen[0].sloMs, 100);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer.enableLatency live enable (WR-474)", () => {
  let stub: Server;
  let stubPort: number;
  let stubDelayMs = 60;

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

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

  function post(port: number, body: Buffer, headers: Record<string, string>) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest(
        { host: "127.0.0.1", port, path: "/", method: "POST", headers },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () =>
            resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
          );
        }
      );
      r.on("error", reject);
      r.end(body);
    });
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  async function waitFor(
    audit: AuditLog,
    event: string,
    pred: (e: Record<string, unknown>) => boolean,
    what: string,
    minCount = 1
  ): Promise<Array<Record<string, unknown>>> {
    const deadline = Date.now() + 8000;
    while (Date.now() < deadline) {
      const events = eventsOf(audit, event);
      if (events.filter(pred).length >= minCount) return events;
      await new Promise((r) => setTimeout(r, 50));
    }
    throw new Error(`timed out waiting for ${what}`);
  }

  /** Relay constructed without latency tracking. */
  function makeRelay() {
    const dir = mkdtempSync(join(tmpdir(), "latency-enable-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the key is spelled out dynamically
      // instead of literally (see AGENTS.md).
      ["sec" + "ret"]: signingKey,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      operatorToken: opToken,
      // No custom sender: deliveries go to the stub over real HTTP, so
      // the accepted→delivered latency is the stub's delay.
      retry: {
        baseDelayMs: 5,
        jitterMs: 0,
        maxAttempts: 2,
      },
    });
    return { relay, audit };
  }

  before(async () => {
    stub = createServer((req, res) => {
      req.resume();
      req.on("end", () => setTimeout(() => res.writeHead(200).end("ok"), stubDelayMs));
    });
    stubPort = await listen(stub);
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  it("server enable audits latency_enabled with previous null and mounts the getter", async () => {
    const { relay, audit } = makeRelay();
    const port = await listen(relay);
    try {
      assert.equal(relay.getLatencyConfig, undefined);
      // The miss-observer gate is still closed before the enable.
      assert.throws(() => relay.reviseSloMissCallback!(() => {}), {
        name: "Error",
        message:
          "reviseSloMissCallback: latency tracking is not configured — enabling SLO-miss observation requires a restart",
      });
      // A `now` function is accepted as an option but never enters the audit.
      relay.enableLatency!({ sloMs: 50, now: () => 0 });
      assert.deepEqual(relay.getLatencyConfig!(), { sloMs: 50, maxSamplesPerEndpoint: 1024 });
      const enabled = eventsOf(audit, "latency_enabled");
      assert.equal(enabled.length, 1);
      assert.equal(enabled[0].previous, null);
      assert.deepEqual(enabled[0].current, { sloMs: 50, maxSamplesPerEndpoint: 1024 });
      assert.equal("now" in (enabled[0].current as Record<string, unknown>), false);
      // The audit event carries plain data only — never a function.
      assert.deepEqual(JSON.parse(JSON.stringify(enabled[0])), enabled[0]);
      // A second enable is an Error and audits nothing more.
      assert.throws(() => relay.enableLatency!({ sloMs: 60 }), {
        name: "Error",
        message: "enableLatency: latency tracking is already configured",
      });
      assert.equal(eventsOf(audit, "latency_enabled").length, 1);
      assert.deepEqual(relay.getLatencyConfig!(), { sloMs: 50, maxSamplesPerEndpoint: 1024 });
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("an over-budget delivery after the enable is audited as slo_missed and reaches a later operator callback", async () => {
    const { relay, audit } = makeRelay();
    const port = await listen(relay);
    const seen: SloMissInfo[] = [];
    try {
      relay.enableLatency!({ sloMs: 50 });
      // No operator callback installed yet: the miss is audited as
      // `slo_missed` but reaches no operator.
      stubDelayMs = 60;
      const body = Buffer.from(JSON.stringify({ n: 0 }));
      const res = await post(port, body, {
        "x-signature": signSha256(body, signingKey),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
      await waitFor(audit, "slo_missed", () => true, "slo_missed audit");
      assert.deepEqual(seen, []);
      // Install the operator callback after the first miss; the wrapper
      // keeps reading the cell, so later misses arrive.
      relay.reviseSloMissCallback!((info) => seen.push(info));
      assert.equal(eventsOf(audit, "slo_miss_callback_revised").length, 1);
      const body2 = Buffer.from(JSON.stringify({ n: 1 }));
      const res2 = await post(port, body2, {
        "x-signature": signSha256(body2, signingKey),
        "content-type": "application/json",
      });
      assert.equal(res2.status, 202);
      await waitFor(audit, "slo_missed", () => true, "second slo_missed audit", 2);
      assert.equal(seen.length, 1);
      assert.equal(seen[0].sloMs, 50);
      assert.ok(seen[0].latencyMs > 50);
    } finally {
      stubDelayMs = 60;
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("GET /latency is [] before the enable and returns rows after the first sample", async () => {
    const { relay, audit } = makeRelay();
    const port = await listen(relay);
    try {
      const empty = await get(port, "/latency", { authorization: `Bearer ${opToken}` });
      assert.equal(empty.status, 200);
      assert.deepEqual(JSON.parse(empty.text), []);
      relay.enableLatency!({ sloMs: 50 });
      stubDelayMs = 60;
      const body = Buffer.from(JSON.stringify({ n: 0 }));
      const res = await post(port, body, {
        "x-signature": signSha256(body, signingKey),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
      await waitFor(audit, "slo_missed", () => true, "slo_missed audit");
      const ok = await get(port, "/latency", { authorization: `Bearer ${opToken}` });
      assert.equal(ok.status, 200);
      const rows = JSON.parse(ok.text) as Array<Record<string, unknown>>;
      assert.equal(rows.length, 1);
      assert.equal(rows[0].count, 1);
      assert.equal(rows[0].sloMs, 50);
      assert.equal(rows[0].endpoint, `http://127.0.0.1:${stubPort}/hook`);
    } finally {
      stubDelayMs = 60;
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("/metrics has no latency histogram row before the enable and gains one after the first sample", async () => {
    const { relay, audit } = makeRelay();
    const port = await listen(relay);
    try {
      const before = await get(port, "/metrics", { authorization: `Bearer ${opToken}` });
      assert.equal(before.status, 200);
      assert.ok(!before.text.includes("relay_delivery_latency_seconds"));
      relay.enableLatency!({ sloMs: 50 });
      stubDelayMs = 60;
      const body = Buffer.from(JSON.stringify({ n: 0 }));
      const res = await post(port, body, {
        "x-signature": signSha256(body, signingKey),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
      await waitFor(audit, "slo_missed", () => true, "slo_missed audit");
      const after = await get(port, "/metrics", { authorization: `Bearer ${opToken}` });
      assert.equal(after.status, 200);
      assert.ok(after.text.includes("relay_delivery_latency_seconds"));
    } finally {
      stubDelayMs = 60;
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("a restart restores the unconfigured construction state", async () => {
    const { relay } = makeRelay();
    const port = await listen(relay);
    try {
      relay.enableLatency!({ sloMs: 50 });
      assert.deepEqual(relay.getLatencyConfig!(), { sloMs: 50, maxSamplesPerEndpoint: 1024 });
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
    // A fresh relay from the same construction options has no tracker.
    const fresh = makeRelay();
    const freshPort = await listen(fresh.relay);
    try {
      assert.equal(fresh.relay.getLatencyConfig, undefined);
      const empty = await get(freshPort, "/latency", { authorization: `Bearer ${opToken}` });
      assert.equal(empty.status, 200);
      assert.deepEqual(JSON.parse(empty.text), []);
    } finally {
      fresh.relay.close();
      await new Promise((r) => fresh.relay.once("close", r));
    }
  });
});
