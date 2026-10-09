import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";
import type { ConfigChange, EndpointConfigPatch } from "../src/hotreload.ts";

const URL = "http://localhost:9999/hook";
const TOKEN = "op-token";

/** Timer that records each scheduled delay and lets the test step them. */
function delayRecordingTimer() {
  const pending: Array<{ fn: () => void; ms: number }> = [];
  const delays: number[] = [];
  return {
    delays,
    setTimer: (fn: () => void, ms: number) => {
      delays.push(ms);
      pending.push({ fn, ms });
      return {
        clear: () => {
          const i = pending.findIndex((p) => p.fn === fn);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    async step() {
      const fns = pending.splice(0);
      for (const { fn } of fns) fn();
      await new Promise((r) => setImmediate(r));
    },
  };
}

function failingSender() {
  let calls = 0;
  const sender: Sender = async () => {
    calls += 1;
    throw new Error("downstream down");
  };
  return { sender, calls: () => calls };
}

function blockingSender() {
  let calls = 0;
  const gates: Array<() => void> = [];
  const sender: Sender = () =>
    new Promise<void>((resolve) => {
      calls += 1;
      gates.push(resolve);
    });
  return {
    sender,
    calls: () => calls,
    releaseOne: () => gates.shift()?.(),
    releaseAll: () => {
      while (gates.length > 0) gates.shift()!();
    },
  };
}

function enqueue(queue: RetryQueue, id: string, targetUrl: string = URL): void {
  queue.enqueue({
    id,
    targetUrl,
    payload: Buffer.from(JSON.stringify({ id })),
    headers: {},
  });
}

describe("updateEndpointConfig: backoff hot reload", () => {
  it("retunes future scheduled retries; already-scheduled timers keep their old delay", async () => {
    const t = delayRecordingTimer();
    const { sender } = failingSender();
    const changes: Array<{ endpoint: string; changes: ConfigChange[] }> = [];
    const q = new RetryQueue({
      sender,
      baseDelayMs: 1000,
      maxDelayMs: 60_000,
      maxAttempts: 5,
      jitterMs: 0,
      random: () => 0,
      setTimer: t.setTimer,
      onConfigChange: (endpoint, ch) => changes.push({ endpoint, changes: ch }),
    });
    enqueue(q, "a");
    q.start();
    await t.step(); // attempt 0 fails -> schedules retry with the OLD base
    assert.equal(t.delays.length, 2); // initial immediate (0) + backoff
    assert.equal(t.delays[1], 2000); // base 1000 * 2^1 (attempt counts from 0)

    const diff = q.updateEndpointConfig(URL, { retry: { baseDelayMs: 4000 } });
    assert.deepEqual(diff, [{ field: "retry.baseDelayMs", from: 1000, to: 4000 }]);
    assert.deepEqual(q.retryConfig().baseDelayMs, 4000);
    assert.deepEqual(changes, [{ endpoint: URL, changes: diff }]);

    await t.step(); // attempt 1 fails -> schedules retry with the NEW base
    assert.equal(t.delays[2], 16000); // 4000 * 2^2, jitter 0
  });

  it("rejects illegal backoff values with RangeError and leaves config untouched", () => {
    const q = new RetryQueue({ baseDelayMs: 1000, maxAttempts: 5, jitterMs: 0 });
    const before = q.retryConfig();
    const bad: EndpointConfigPatch[] = [
      { retry: { baseDelayMs: 0 } },
      { retry: { baseDelayMs: -3 } },
      { retry: { maxDelayMs: Number.NaN } },
      { retry: { maxAttempts: 0 } },
      { retry: { maxAttempts: 2.5 } },
      { retry: { jitterMs: -1 } },
      { retry: { jitterStrategy: "sometimes" as never } },
      { retry: "fast" as never },
    ];
    for (const patch of bad) {
      assert.throws(() => q.updateEndpointConfig(URL, patch), RangeError);
    }
    assert.deepEqual(q.retryConfig(), before);
  });
});

describe("updateEndpointConfig: concurrency hot reload", () => {
  it("raising the limit immediately grants slots to queued waiters", async () => {
    const t = delayRecordingTimer();
    const b = blockingSender();
    const q = new RetryQueue({
      sender: b.sender,
      maxConcurrentPerEndpoint: 1,
      setTimer: t.setTimer,
    });
    enqueue(q, "a");
    enqueue(q, "b");
    q.start();
    await t.step();
    assert.equal(b.calls(), 1); // "a" in flight, "b" queued
    assert.deepEqual(q.getConcurrencyStats(), [{ endpoint: URL, inFlight: 1, queued: 1 }]);

    const diff = q.updateEndpointConfig(URL, { maxConcurrentPerEndpoint: 3 });
    assert.deepEqual(diff, [{ field: "maxConcurrentPerEndpoint", from: 1, to: 3 }]);
    await new Promise((r) => setImmediate(r)); // let the grant propagate
    assert.equal(b.calls(), 2); // "b" picked up its slot without any release
    assert.deepEqual(q.getConcurrencyStats(), [{ endpoint: URL, inFlight: 2, queued: 0 }]);
    b.releaseAll();
  });

  it("lowering the limit never revokes in-flight deliveries", async () => {
    const t = delayRecordingTimer();
    const b = blockingSender();
    const q = new RetryQueue({
      sender: b.sender,
      maxConcurrentPerEndpoint: 2,
      setTimer: t.setTimer,
    });
    enqueue(q, "a");
    enqueue(q, "b");
    q.start();
    await t.step();
    assert.equal(b.calls(), 2);
    q.updateEndpointConfig(URL, { maxConcurrentPerEndpoint: 1 });
    assert.equal(b.calls(), 2); // in-flight untouched
    enqueue(q, "c");
    await t.step();
    assert.equal(b.calls(), 2); // new acquisition queues behind the new limit
    assert.deepEqual(q.getConcurrencyStats(), [{ endpoint: URL, inFlight: 2, queued: 1 }]);
    b.releaseAll();
  });

  it("rejects illegal concurrency values", () => {
    const q = new RetryQueue({});
    for (const v of [0, -1, 1.5, Number.NaN, "2" as never]) {
      assert.throws(() => q.updateEndpointConfig(URL, { maxConcurrentPerEndpoint: v as number }), RangeError);
    }
  });
});

describe("updateEndpointConfig: circuit-breaker hot reload", () => {
  function queueWithBreaker(now: { value: number }) {
    const transitions: string[] = [];
    const q = new RetryQueue({
      sender: async () => {
        throw new Error("down");
      },
      circuitBreaker: {
        failureThreshold: 5,
        cooldownMs: 60_000,
        nowMs: () => now.value,
      },
      onCircuitStateChange: (e, from, to) => transitions.push(`${from}->${to}`),
    });
    return { q, transitions };
  }

  it("raising failureThreshold stops a near-trip; lowering trips sooner", () => {
    const now = { value: 0 };
    const { q } = queueWithBreaker(now);
    // Reach 4 consecutive failures (below the original threshold of 5).
    const breaker = (q as unknown as { breaker: { recordFailure(e: string): void; state(e: string): string } }).breaker;
    for (let i = 0; i < 4; i++) breaker.recordFailure(URL);
    assert.equal(breaker.state(URL), "closed");

    const diff = q.updateEndpointConfig(URL, { circuitBreaker: { failureThreshold: 10 } });
    assert.deepEqual(diff, [{ field: "circuitBreaker.failureThreshold", from: 5, to: 10 }]);
    breaker.recordFailure(URL); // 5th failure: no longer trips at the new threshold
    assert.equal(breaker.state(URL), "closed");

    q.updateEndpointConfig(URL, { circuitBreaker: { failureThreshold: 2 } });
    breaker.recordFailure(URL); // 6th: exceeds the lowered threshold
    assert.equal(breaker.state(URL), "open");
  });

  it("shrinking cooldownMs makes an open circuit probe-eligible sooner", () => {
    const now = { value: 0 };
    const { q, transitions } = queueWithBreaker(now);
    const breaker = (q as unknown as { breaker: { recordFailure(e: string): void; state(e: string): string; shouldAllow(e: string): { allowed: boolean } } }).breaker;
    for (let i = 0; i < 5; i++) breaker.recordFailure(URL);
    assert.equal(breaker.state(URL), "open");
    assert.equal(transitions.at(-1), "closed->open");

    q.updateEndpointConfig(URL, { circuitBreaker: { cooldownMs: 1000 } });
    now.value += 999;
    assert.equal(breaker.shouldAllow(URL).allowed, false); // still cooling
    now.value += 1;
    assert.equal(breaker.shouldAllow(URL).allowed, true); // half-open probe
  });

  it("rejects illegal circuit values and patching a disabled breaker", () => {
    const now = { value: 0 };
    const { q } = queueWithBreaker(now);
    assert.throws(() => q.updateEndpointConfig(URL, { circuitBreaker: { failureThreshold: 0 } }), RangeError);
    assert.throws(() => q.updateEndpointConfig(URL, { circuitBreaker: { cooldownMs: -1 } }), RangeError);

    const noBreaker = new RetryQueue({});
    assert.throws(
      () => noBreaker.updateEndpointConfig(URL, { circuitBreaker: { failureThreshold: 3 } }),
      /not enabled/
    );
  });
});

describe("updateEndpointConfig: quota hot reload", () => {
  it("raises the per-endpoint budget immediately", () => {
    let now = 0;
    const q = new RetryQueue({ quota: { deliveriesPerMinute: 60, now: () => now } });
    const quota = (q as unknown as { quota: { limit(e: string): number; take(e: string): boolean } }).quota;
    assert.equal(quota.limit(URL), 60);
    const diff = q.updateEndpointConfig(URL, { quota: { deliveriesPerMinute: 120 } });
    assert.deepEqual(diff, [{ field: "quota.deliveriesPerMinute", from: 60, to: 120 }]);
    assert.equal(quota.limit(URL), 120);
    // Other endpoints keep the default budget.
    assert.equal(quota.limit("http://other/hook"), 60);
  });

  it("rejects illegal quota values and patching a disabled quota", () => {
    const q = new RetryQueue({ quota: { deliveriesPerMinute: 60 } });
    assert.throws(() => q.updateEndpointConfig(URL, { quota: { deliveriesPerMinute: 0 } }), RangeError);
    assert.throws(() => q.updateEndpointConfig(URL, { quota: { deliveriesPerMinute: -5 } }), RangeError);
    const noQuota = new RetryQueue({});
    assert.throws(() => noQuota.updateEndpointConfig(URL, { quota: { deliveriesPerMinute: 30 } }), /not enabled/);
  });
});

describe("updateEndpointConfig: validation and atomicity", () => {
  it("validates everything before mutating anything", () => {
    const q = new RetryQueue({
      maxConcurrentPerEndpoint: 2,
      baseDelayMs: 1000,
      circuitBreaker: { failureThreshold: 5 },
      quota: { deliveriesPerMinute: 60 },
    });
    const beforeRetry = q.retryConfig();
    // Valid concurrency + invalid backoff: nothing may be applied.
    assert.throws(
      () => q.updateEndpointConfig(URL, { maxConcurrentPerEndpoint: 5, retry: { baseDelayMs: 0 } }),
      RangeError
    );
    assert.deepEqual(q.retryConfig(), beforeRetry);
    assert.equal(
      (q as unknown as { limiter: { maxFor(e: string): number } }).limiter.maxFor(URL),
      2
    );
  });

  it("rejects an empty endpoint and non-object patches", () => {
    const q = new RetryQueue({});
    assert.throws(() => q.updateEndpointConfig("", { retry: { baseDelayMs: 5 } }), RangeError);
    assert.throws(() => q.updateEndpointConfig(URL, "nope" as never), RangeError);
    // An empty patch is a no-op that still reports through the hook.
    const seen: ConfigChange[][] = [];
    const q2 = new RetryQueue({ onConfigChange: (_e, c) => seen.push(c) });
    assert.deepEqual(q2.updateEndpointConfig(URL, {}), []);
    assert.deepEqual(seen, [[]]);
  });
});

describe("POST /config/endpoint operator route", () => {
  let servers: Server[] = [];
  afterEach(async () => {
    for (const s of servers) {
      s.close();
      await new Promise((r) => s.once("close", r));
    }
    servers = [];
  });

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  function postJson(port: number, path: string, body: unknown, token?: string) {
    return new Promise<{ status: number; json: unknown }>((resolve, reject) => {
      const headers: Record<string, string> = { "content-type": "application/json" };
      if (token !== undefined) headers["authorization"] = `Bearer ${token}`;
      const r = httpRequest({ host: "127.0.0.1", port, path, method: "POST", headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            json: JSON.parse(Buffer.concat(chunks).toString() || "{}"),
          })
        );
      });
      r.on("error", reject);
      r.end(JSON.stringify(body));
    });
  }

  async function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "hotreload-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: "test-secret",
      forwardUrl: URL,
      auditLog: audit,
      operatorToken: TOKEN,
      retry: { maxConcurrentPerEndpoint: 4, circuitBreaker: { failureThreshold: 5 }, quota: { deliveriesPerMinute: 60 } },
      ...extra,
    });
    servers.push(relay);
    return { port: await listen(relay), audit };
  }

  it("applies a patch with auth and audits endpoint_config_updated", async () => {
    const { port, audit } = await makeRelay();
    const res = await postJson(
      port,
      "/config/endpoint",
      { endpoint: URL, maxConcurrentPerEndpoint: 8, retry: { baseDelayMs: 250 } },
      TOKEN
    );
    assert.equal(res.status, 200);
    const body = res.json as { endpoint: string; changes: ConfigChange[] };
    assert.equal(body.endpoint, URL);
    assert.deepEqual(
      body.changes.map((c) => c.field),
      ["maxConcurrentPerEndpoint", "retry.baseDelayMs"]
    );
    const events = audit.query({ event: "endpoint_config_updated" });
    assert.equal(events.length, 1);
    assert.equal((events[0] as { endpoint: string }).endpoint, URL);
  });

  it("rejects illegal values with 400 and audits nothing", async () => {
    const { port, audit } = await makeRelay();
    const res = await postJson(port, "/config/endpoint", { endpoint: URL, retry: { baseDelayMs: 0 } }, TOKEN);
    assert.equal(res.status, 400);
    assert.equal(audit.query({ event: "endpoint_config_updated" }).length, 0);
    // Patching a disabled subsystem is a 400 too.
    const { port: port2 } = await makeRelay({ retry: {} });
    const res2 = await postJson(port2, "/config/endpoint", { endpoint: URL, circuitBreaker: { failureThreshold: 2 } }, TOKEN);
    assert.equal(res2.status, 400);
  });

  it("requires the operator token and fails closed without one", async () => {
    const { port } = await makeRelay();
    const noToken = await postJson(port, "/config/endpoint", { endpoint: URL, retry: { baseDelayMs: 5 } });
    assert.equal(noToken.status, 403);
    const wrongToken = await postJson(port, "/config/endpoint", { endpoint: URL }, "wrong");
    assert.equal(wrongToken.status, 403);

    const dir = mkdtempSync(join(tmpdir(), "hotreload-notoken-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({ secret: "test-secret", forwardUrl: URL, auditLog: audit });
    servers.push(relay);
    const p2 = await listen(relay);
    const disabled = await postJson(p2, "/config/endpoint", { endpoint: URL }, TOKEN);
    assert.equal(disabled.status, 404);
  });

  it("rejects malformed bodies", async () => {
    const { port } = await makeRelay();
    const missing = await postJson(port, "/config/endpoint", { retry: { baseDelayMs: 5 } }, TOKEN);
    assert.equal(missing.status, 400);
    const empty = await postJson(port, "/config/endpoint", { endpoint: "" }, TOKEN);
    assert.equal(empty.status, 400);
  });
});
