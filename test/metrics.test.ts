import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const URL = "http://localhost:9999/hook";
const SECRET = "relay-secret";
const BODY = Buffer.from(JSON.stringify({ event: "payment.succeeded" }));

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

const ITEM = {
  id: "m-1",
  payload: Buffer.from("hello"),
  targetUrl: URL,
  headers: {},
};

function metricLine(out: string, name: string, labels: string): string | undefined {
  const prefix = `${name}{${labels}} `;
  return out.split("\n").find((l) => l.startsWith(prefix));
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function get(port: number, path: string, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; headers: Record<string, string | string[] | undefined>; text: string }>(
    (resolve, reject) => {
      const r = httpRequest({ host: "127.0.0.1", port, path, method: "GET", headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers,
            text: Buffer.concat(chunks).toString(),
          })
        );
      });
      r.on("error", reject);
      r.end();
    }
  );
}

function post(port: number, path: string, method: string, headers: Record<string, string> = {}) {
  return new Promise<{ status: number }>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method, headers }, (res) => {
      res.resume();
      res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
    });
    r.on("error", reject);
    r.end();
  });
}

describe("Prometheus delivery counters", () => {
  it("counters reflect one failure + one retry + one success", async () => {
    const timer = manualTimer();
    let attempts = 0;
    const flaky: Sender = async () => {
      attempts += 1;
      if (attempts === 1) throw new Error("boom");
    };
    const q = new RetryQueue({
      sender: flaky,
      baseDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 3,
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();
    const out = q.renderMetrics();
    assert.ok(out.startsWith("# HELP relay_deliveries_total"));
    assert.ok(out.includes("# TYPE relay_deliveries_total counter"));
    const ep = `endpoint="${URL}"`;
    assert.equal(metricLine(out, "relay_deliveries_total", `${ep},status="delivered"`), `relay_deliveries_total{${ep},status="delivered"} 1`);
    assert.equal(metricLine(out, "relay_deliveries_total", `${ep},status="failed"`), `relay_deliveries_total{${ep},status="failed"} 1`);
    assert.equal(metricLine(out, "relay_deliveries_total", `${ep},status="retried"`), `relay_deliveries_total{${ep},status="retried"} 1`);
    assert.equal(metricLine(out, "relay_deliveries_total", `${ep},status="dead_letter"`), `relay_deliveries_total{${ep},status="dead_letter"} 0`);
    assert.ok(out.endsWith("\n"));
  });

  it("counts a budget-exhausting delivery as failed + dead_letter, not retried", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({
      sender: async () => {
        throw new Error("always down");
      },
      baseDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 2,
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();
    const out = q.renderMetrics();
    const ep = `endpoint="${URL}"`;
    assert.equal(metricLine(out, "relay_deliveries_total", `${ep},status="delivered"`), `relay_deliveries_total{${ep},status="delivered"} 0`);
    assert.equal(metricLine(out, "relay_deliveries_total", `${ep},status="failed"`), `relay_deliveries_total{${ep},status="failed"} 2`);
    assert.equal(metricLine(out, "relay_deliveries_total", `${ep},status="retried"`), `relay_deliveries_total{${ep},status="retried"} 1`);
    assert.equal(metricLine(out, "relay_deliveries_total", `${ep},status="dead_letter"`), `relay_deliveries_total{${ep},status="dead_letter"} 1`);
  });

  it("separates counters per endpoint and escapes label values", async () => {
    const timer = manualTimer();
    const weird = 'http://downstream/"quoted"\nslash';
    const q = new RetryQueue({ sender: async () => {}, setTimer: timer.setTimer });
    q.start();
    q.enqueue({ ...ITEM, id: "w-1", targetUrl: weird });
    await timer.run();
    const out = q.renderMetrics();
    const line = metricLine(out, "relay_deliveries_total", `endpoint="http://downstream/\\"quoted\\"\\nslash",status="delivered"`);
    assert.equal(line, `relay_deliveries_total{endpoint="http://downstream/\\"quoted\\"\\nslash",status="delivered"} 1`);
  });
});

describe("circuit breaker gauge", () => {
  it("tracks open (2) then closed (0) through the gauge", async () => {
    const timer = manualTimer();
    let breakerNow = 1_000_000;
    let fail = true;
    const q = new RetryQueue({
      sender: async () => {
        if (fail) throw new Error("down");
      },
      baseDelayMs: 10,
      jitterMs: 0,
      maxAttempts: 1,
      circuitBreaker: { failureThreshold: 1, cooldownMs: 60_000, nowMs: () => breakerNow },
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue({ ...ITEM, id: "c-1" });
    await timer.run();
    let out = q.renderMetrics();
    assert.equal(
      metricLine(out, "relay_endpoint_circuit_state", `endpoint="${URL}"`),
      `relay_endpoint_circuit_state{endpoint="${URL}"} 2`
    );
    // Past the cooldown a successful probe closes the circuit again.
    breakerNow += 61_000;
    fail = false;
    q.enqueue({ ...ITEM, id: "c-2" });
    await timer.run();
    out = q.renderMetrics();
    assert.equal(
      metricLine(out, "relay_endpoint_circuit_state", `endpoint="${URL}"`),
      `relay_endpoint_circuit_state{endpoint="${URL}"} 0`
    );
  });

  it("omits the gauge when the breaker is disabled", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({ sender: async () => {}, setTimer: timer.setTimer });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();
    assert.ok(!q.renderMetrics().includes("relay_endpoint_circuit_state"));
  });
});

describe("latency histogram", () => {
  it("buckets accepted→delivered latency cumulatively, sum and count included", async () => {
    const timer = manualTimer();
    let now = 0;
    const q = new RetryQueue({
      sender: async () => {},
      jitterMs: 0,
      latency: { sloMs: 60_000, now: () => now },
      metrics: { histogramBucketsMs: [100, 500] },
      setTimer: timer.setTimer,
    });
    q.start();
    now = 0;
    q.enqueue({ ...ITEM, id: "h-1" });
    now = 50;
    await timer.run();
    now = 1000;
    q.enqueue({ ...ITEM, id: "h-2" });
    now = 1300;
    await timer.run();
    now = 2000;
    q.enqueue({ ...ITEM, id: "h-3" });
    now = 4000; // 2000ms: beyond the last bucket → +Inf only
    await timer.run();
    const out = q.renderMetrics();
    const ep = `endpoint="${URL}"`;
    assert.equal(
      metricLine(out, "relay_delivery_latency_seconds_bucket", `${ep},le="0.1"`),
      `relay_delivery_latency_seconds_bucket{${ep},le="0.1"} 1`
    );
    assert.equal(
      metricLine(out, "relay_delivery_latency_seconds_bucket", `${ep},le="0.5"`),
      `relay_delivery_latency_seconds_bucket{${ep},le="0.5"} 2`
    );
    assert.equal(
      metricLine(out, "relay_delivery_latency_seconds_bucket", `${ep},le="+Inf"`),
      `relay_delivery_latency_seconds_bucket{${ep},le="+Inf"} 3`
    );
    assert.equal(
      metricLine(out, "relay_delivery_latency_seconds_sum", ep),
      `relay_delivery_latency_seconds_sum{${ep}} 2.35`
    );
    assert.equal(
      metricLine(out, "relay_delivery_latency_seconds_count", ep),
      `relay_delivery_latency_seconds_count{${ep}} 3`
    );
  });

  it("omits the histogram when latency tracking is disabled", async () => {
    const timer = manualTimer();
    const q = new RetryQueue({ sender: async () => {}, setTimer: timer.setTimer });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();
    assert.ok(!q.renderMetrics().includes("relay_delivery_latency_seconds"));
  });

  it("rejects invalid bucket configuration", () => {
    for (const buckets of [[], [100, 50], [100, 100], [0], [-5], [NaN], [Infinity]]) {
      assert.throws(
        () => new RetryQueue({ metrics: { histogramBucketsMs: buckets } }),
        RangeError,
        `buckets ${JSON.stringify(buckets)}`
      );
    }
  });
});

describe("GET /metrics operator endpoint", () => {
  function relay(opts: { operatorToken?: string; sender?: Sender }) {
    const dir = mkdtempSync(join(tmpdir(), "metrics-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const server = createRelayServer({
      secret: SECRET,
      forwardUrl: URL,
      auditLog: audit,
      operatorToken: opts.operatorToken,
      sender: opts.sender ?? (async () => {}),
    });
    return { server, audit };
  }

  function postHook(port: number) {
    return new Promise<number>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/",
          method: "POST",
          headers: { "x-signature": signSha256(BODY, SECRET) },
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve(res.statusCode ?? 0));
        }
      );
      r.on("error", reject);
      r.end(BODY);
    });
  }

  async function waitForDelivered(port: number) {
    // The first attempt is scheduled with delay 0 on real timers; poll
    // /metrics until the delivered counter lands.
    const deadline = Date.now() + 5000;
    for (;;) {
      const res = await get(port, "/metrics", { authorization: "Bearer op-token" });
      if (
        res.text.includes(
          'relay_deliveries_total{endpoint="http://localhost:9999/hook",status="delivered"} 1'
        )
      ) {
        return res;
      }
      if (Date.now() > deadline) throw new Error("delivery timed out");
      await new Promise((r) => setTimeout(r, 25));
    }
  }

  it("serves exposition text behind the bearer token", async () => {
    const { server } = relay({ operatorToken: "op-token" });
    const port = await listen(server);
    try {
      assert.equal(await postHook(port), 202);
      const res = await waitForDelivered(port);
      assert.equal(res.status, 200);
      assert.match(String(res.headers["content-type"] ?? ""), /^text\/plain/);
      // Wrong token is forbidden; POST is not allowed.
      assert.equal((await get(port, "/metrics", { authorization: "Bearer wrong" })).status, 403);
      assert.equal((await post(port, "/metrics", "POST", { authorization: "Bearer op-token" })).status, 405);
    } finally {
      server.close();
    }
  });

  it("answers 404 when operator endpoints are disabled", async () => {
    const { server } = relay({});
    const port = await listen(server);
    try {
      assert.equal((await get(port, "/metrics")).status, 404);
    } finally {
      server.close();
    }
  });
});
