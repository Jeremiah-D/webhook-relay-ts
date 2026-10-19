import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { EndpointAutoDisable } from "../src/endpoint-disable.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const URL = "http://localhost:9999/hook";
const hookSecret = "relay-secret";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));
const TOKEN = "op-token";

/**
 * Manual timer with single-step control, mirroring test/circuit.test.ts:
 * each step drains the currently-armed timers exactly once.
 */
function manualTimer() {
  const pending: Array<() => void> = [];
  return {
    pendingCount: () => pending.length,
    setTimer: (fn: () => void, _ms: number) => {
      pending.push(fn);
      return {
        clear: () => {
          const i = pending.indexOf(fn);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    async step() {
      const fns = pending.splice(0);
      for (const f of fns) f();
      await new Promise((r) => setImmediate(r));
    },
  };
}

function failingSender() {
  let calls = 0;
  let fail = true;
  const sender: Sender = async () => {
    calls += 1;
    if (fail) throw new Error("downstream down");
  };
  return { sender, calls: () => calls, setFail: (v: boolean) => (fail = v) };
}

describe("EndpointAutoDisable", () => {
  it("trips after failureThreshold consecutive failures, edge-triggered", () => {
    let now = 0;
    const t = new EndpointAutoDisable({ failureThreshold: 3, nowMs: () => now });
    assert.equal(t.isDisabled(URL), false);
    assert.deepEqual(t.recordFailure(URL), { disabled: false, consecutiveFailures: 1, failureThreshold: 3 });
    assert.deepEqual(t.recordFailure(URL), { disabled: false, consecutiveFailures: 2, failureThreshold: 3 });
    assert.equal(t.isDisabled(URL), false);
    assert.deepEqual(t.recordFailure(URL), { disabled: true, consecutiveFailures: 3, failureThreshold: 3 });
    assert.equal(t.isDisabled(URL), true);
    // Edge-triggered: further failures do not re-fire.
    assert.deepEqual(t.recordFailure(URL), { disabled: false, consecutiveFailures: 4, failureThreshold: 3 });
    assert.equal(t.isDisabled(URL), true);
    const row = t.getStats().find((s) => s.endpoint === URL)!;
    assert.equal(row.disabled, true);
    assert.equal(row.autoDisables, 1);
    assert.equal(row.disabledAtMs, 0);
    assert.equal(row.lastFailureAtMs, 0);
  });

  it("a success resets the streak", () => {
    const t = new EndpointAutoDisable({ failureThreshold: 3 });
    t.recordFailure(URL);
    t.recordFailure(URL);
    t.recordSuccess(URL);
    assert.equal(t.consecutiveFailures(URL), 0);
    t.recordFailure(URL);
    t.recordFailure(URL);
    assert.equal(t.isDisabled(URL), false);
    assert.deepEqual(t.recordFailure(URL), { disabled: true, consecutiveFailures: 3, failureThreshold: 3 });
  });

  it("a finite window prunes old failures so a slow drip never trips", () => {
    let now = 0;
    const t = new EndpointAutoDisable({ failureThreshold: 3, windowMs: 1000, nowMs: () => now });
    t.recordFailure(URL);
    t.recordFailure(URL);
    now = 1500; // both failures aged out of the window
    assert.equal(t.consecutiveFailures(URL), 0);
    assert.deepEqual(t.recordFailure(URL), { disabled: false, consecutiveFailures: 1, failureThreshold: 3 });
    // Three failures inside the window still trip.
    now = 1600;
    t.recordFailure(URL);
    now = 1700;
    assert.deepEqual(t.recordFailure(URL), { disabled: true, consecutiveFailures: 3, failureThreshold: 3 });
  });

  it("enable clears the gate and resets the streak; idempotent", () => {
    const t = new EndpointAutoDisable({ failureThreshold: 2 });
    t.recordFailure(URL);
    t.recordFailure(URL);
    assert.equal(t.isDisabled(URL), true);
    assert.equal(t.enable(URL), true);
    assert.equal(t.isDisabled(URL), false);
    assert.equal(t.consecutiveFailures(URL), 0);
    assert.equal(t.enable(URL), false); // idempotent no-op
    // A fresh streak starts after the re-enable.
    t.recordFailure(URL);
    assert.equal(t.isDisabled(URL), false);
  });

  it("tracks endpoints independently", () => {
    const t = new EndpointAutoDisable({ failureThreshold: 2 });
    const other = "http://localhost:9999/other";
    t.recordFailure(URL);
    t.recordFailure(URL);
    assert.equal(t.isDisabled(URL), true);
    assert.equal(t.isDisabled(other), false);
    assert.equal(t.getStats().length, 1);
  });

  it("rejects illegal config with RangeError", () => {
    for (const opts of [
      { failureThreshold: 0 },
      { failureThreshold: -2 },
      { failureThreshold: 1.5 },
      { failureThreshold: "3" },
      { windowMs: 0 },
      { windowMs: -100 },
      { windowMs: NaN },
      { nowMs: "now" },
    ]) {
      assert.throws(() => new EndpointAutoDisable(opts as never), RangeError, JSON.stringify(opts));
    }
    // Legal shapes pass.
    new EndpointAutoDisable({});
    new EndpointAutoDisable({ failureThreshold: 1, windowMs: 1 });
    new EndpointAutoDisable({ windowMs: Infinity });
  });

  it("rejects empty endpoints with RangeError", () => {
    const t = new EndpointAutoDisable({});
    for (const m of ["recordFailure", "recordSuccess", "isDisabled", "enable", "consecutiveFailures"] as const) {
      assert.throws(() => (t[m] as (e: string) => unknown)(""), RangeError, m);
    }
  });
});

describe("retry queue endpoint auto-disable", () => {
  function makeQueue(extra: Record<string, unknown> = {}) {
    const timer = manualTimer();
    const f = failingSender();
    const disabled: Array<{ endpoint: string; consecutiveFailures: number; failureThreshold: number }> = [];
    const enabled: string[] = [];
    const q = new RetryQueue({
      sender: f.sender,
      baseDelayMs: 10,
      maxAttempts: 1,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      endpointAutoDisable: { failureThreshold: 3 },
      onEndpointAutoDisabled: (info) => disabled.push(info),
      onEndpointEnabled: (info) => enabled.push(info.endpoint),
      ...extra,
    });
    q.start();
    return { q, timer, f, disabled, enabled };
  }

  const ITEM = (id: string) => ({ id, payload: Buffer.from("x"), targetUrl: URL, headers: {} });

  it("dead-letters new deliveries immediately once disabled — no attempt, no retry", async () => {
    const { q, timer, f, disabled } = makeQueue();
    q.enqueue(ITEM("d-1"));
    await timer.step(); // failure 1
    q.enqueue(ITEM("d-2"));
    await timer.step(); // failure 2
    q.enqueue(ITEM("d-3"));
    await timer.step(); // failure 3 -> disabled
    assert.equal(f.calls(), 3);
    assert.equal(q.isEndpointDisabled(URL), true);
    assert.deepEqual(disabled, [{ endpoint: URL, consecutiveFailures: 3, failureThreshold: 3 }]);

    // The next delivery never touches the sender: straight to DLQ.
    q.enqueue(ITEM("d-4"));
    await timer.step();
    assert.equal(f.calls(), 3);
    const dl = q.getDeadLetter();
    assert.equal(dl.length, 4);
    const gated = dl.find((e) => e.id === "d-4")!;
    assert.equal(gated.failureClass, "endpoint_disabled");
    assert.equal(gated.attempts, 0);
    assert.match(gated.lastError, /auto-disabled after 3 consecutive delivery failures/);
    assert.equal(q.pendingCount(), 0);
  });

  it("a success resets the streak", async () => {
    const { q, timer, f } = makeQueue();
    q.enqueue(ITEM("d-1"));
    await timer.step(); // failure 1
    q.enqueue(ITEM("d-2"));
    await timer.step(); // failure 2
    f.setFail(false);
    q.enqueue(ITEM("d-3"));
    await timer.step(); // success -> streak reset
    assert.equal(q.isEndpointDisabled(URL), false);
    f.setFail(true);
    q.enqueue(ITEM("d-4"));
    await timer.step(); // failure 1 of a fresh streak
    q.enqueue(ITEM("d-5"));
    await timer.step(); // failure 2
    assert.equal(q.isEndpointDisabled(URL), false);
    assert.equal(q.pendingCount(), 0);
  });

  it("a non-retryable downstream answer resets the streak (endpoint is alive)", async () => {
    const timer = manualTimer();
    let calls = 0;
    let mode: "fail" | "reject" = "fail";
    const sender: Sender = async () => {
      calls += 1;
      if (mode === "reject") {
        // A 400 from the downstream classifies as non_retryable: the
        // endpoint answered, it just said no — not a sick endpoint.
        const err = new Error("bad request") as Error & { statusCode?: number };
        err.statusCode = 400;
        throw err;
      }
      throw new Error("downstream down");
    };
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxAttempts: 1,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      endpointAutoDisable: { failureThreshold: 3 },
    });
    q.start();
    q.enqueue(ITEM("d-1"));
    await timer.step();
    q.enqueue(ITEM("d-2"));
    await timer.step();
    assert.equal(q.getEndpointDisableStats()[0]?.consecutiveFailures, 2);
    mode = "reject";
    q.enqueue(ITEM("d-3"));
    await timer.step();
    assert.equal(calls, 3);
    assert.equal(q.isEndpointDisabled(URL), false);
    assert.equal(q.getEndpointDisableStats()[0]?.consecutiveFailures, 0);
    assert.equal(q.getDeadLetter().find((e) => e.id === "d-3")?.failureClass, "non_retryable");
    q.stop();
  });

  it("enableEndpoint re-enables: deliveries flow again and the streak restarts", async () => {
    const { q, timer, f, enabled } = makeQueue();
    for (const id of ["d-1", "d-2", "d-3"]) {
      q.enqueue(ITEM(id));
      await timer.step();
    }
    assert.equal(q.isEndpointDisabled(URL), true);
    assert.equal(q.enableEndpoint(URL), true);
    assert.deepEqual(enabled, [URL]);
    assert.equal(q.isEndpointDisabled(URL), false);
    assert.equal(q.enableEndpoint(URL), false); // idempotent

    f.setFail(false);
    q.enqueue(ITEM("d-4"));
    await timer.step();
    assert.equal(f.calls(), 4); // attempted again
    assert.equal(q.pendingCount(), 0);
    assert.equal(q.getDeadLetter().length, 3);

    // A fresh streak starts after the re-enable: 3 more failures disable again.
    f.setFail(true);
    for (const id of ["d-5", "d-6", "d-7"]) {
      q.enqueue(ITEM(id));
      await timer.step();
    }
    assert.equal(q.isEndpointDisabled(URL), true);
    const rows = q.getEndpointDisableStats();
    assert.equal(rows.find((r) => r.endpoint === URL)?.autoDisables, 2);
  });

  it("is orthogonal to the circuit breaker: separate streaks, separate gates", async () => {
    const { q, timer, f } = makeQueue({
      circuitBreaker: { failureThreshold: 10, cooldownMs: 60_000 },
    });
    for (const id of ["d-1", "d-2", "d-3"]) {
      q.enqueue(ITEM(id));
      await timer.step();
    }
    assert.equal(q.isEndpointDisabled(URL), true);
    assert.equal(q.getCircuitStats()[0].state, "closed"); // breaker untouched at 3 < 10
    // And the breaker tripping does not disable the endpoint on its own:
    // (breaker-only queue tested implicitly — the streaks are separate maps.)
  });

  it("a pause still parks: the explicit operator hold wins over the automatic gate", async () => {
    const { q, timer, f } = makeQueue();
    for (const id of ["d-1", "d-2", "d-3"]) {
      q.enqueue(ITEM(id));
      await timer.step();
    }
    assert.equal(q.isEndpointDisabled(URL), true);
    q.pauseEndpoint(URL);
    q.enqueue(ITEM("d-4"));
    await timer.step();
    assert.equal(f.calls(), 3); // parked, not dead-lettered
    assert.equal(q.pendingCount(), 1);
    assert.equal(q.getDeadLetter().length, 3);
    q.resumeEndpoint(URL);
    await timer.step();
    assert.equal(f.calls(), 3); // resumed into the disabled gate: dead-lettered
    assert.equal(q.getDeadLetter().length, 4);
    assert.equal(q.getDeadLetter().find((e) => e.id === "d-4")?.failureClass, "endpoint_disabled");
  });

  it("is disabled by default: no tracker, no series, no behavior change", async () => {
    const timer = manualTimer();
    const f = failingSender();
    const q = new RetryQueue({
      sender: f.sender,
      baseDelayMs: 10,
      maxAttempts: 1,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue(ITEM("d-1"));
    await timer.step();
    assert.equal(q.isEndpointDisabled(URL), false);
    assert.deepEqual(q.getEndpointDisableStats(), []);
    const exposition = q.renderMetrics();
    assert.ok(!exposition.includes("relay_endpoint_auto_disable"));
    assert.ok(!exposition.includes("relay_endpoint_disabled"));
    // Failures still dead-letter normally with the retryable class.
    assert.equal(q.getDeadLetter()[0]?.failureClass, "retryable");
  });

  it("exposes the counter and gauge in Prometheus exposition, activity-gated", async () => {
    const { q, timer } = makeQueue();
    // No series before the first disable.
    assert.ok(!q.renderMetrics().includes("relay_endpoint_auto_disable"));
    for (const id of ["d-1", "d-2", "d-3"]) {
      q.enqueue(ITEM(id));
      await timer.step();
    }
    const exposition = q.renderMetrics();
    assert.match(
      exposition,
      /relay_endpoint_auto_disables_total\{endpoint="http:\/\/localhost:9999\/hook"\} 1/
    );
    assert.match(
      exposition,
      /relay_endpoint_disabled\{endpoint="http:\/\/localhost:9999\/hook"\} 1/
    );
    // Re-enable drops the gauge but keeps the counter.
    q.enableEndpoint(URL);
    const after = q.renderMetrics();
    assert.ok(!after.includes("relay_endpoint_disabled{"));
    assert.match(after, /relay_endpoint_auto_disables_total\{[^}]*\} 1/);
  });

  it("rejects an illegal endpointAutoDisable option at construction", () => {
    assert.throws(
      () =>
        new RetryQueue({
          sender: async () => {},
          endpointAutoDisable: { failureThreshold: 0 },
        }),
      RangeError
    );
  });
});

describe("POST /endpoints/enable operator route", () => {
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

  function postJson(port: number, path: string, body: unknown, token?: string, method = "POST") {
    return new Promise<{ status: number; json: unknown }>((resolve, reject) => {
      const headers: Record<string, string> = { "content-type": "application/json" };
      if (token !== undefined) headers["authorization"] = `Bearer ${token}`;
      const r = httpRequest({ host: "127.0.0.1", port, path, method, headers }, (res) => {
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

  function postWebhook(port: number) {
    return new Promise<number>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/hook",
          method: "POST",
          headers: {
            "x-signature": signSha256(BODY, hookSecret),
            "content-type": "application/json",
            "content-length": String(BODY.length),
          },
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

  function getMetrics(port: number, token?: string) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const headers: Record<string, string> = {};
      if (token !== undefined) headers["authorization"] = `Bearer ${token}`;
      const r = httpRequest({ host: "127.0.0.1", port, path: "/metrics", method: "GET", headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
        );
      });
      r.on("error", reject);
      r.end();
    });
  }

  async function makeRelay() {
    const dir = mkdtempSync(join(tmpdir(), "autodisable-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    let calls = 0;
    const relay = createRelayServer({
      secret: hookSecret,
      forwardUrl: URL,
      auditLog: audit,
      operatorToken: TOKEN,
      sender: async () => {
        calls += 1;
        throw new Error("downstream down");
      },
      retry: {
        baseDelayMs: 10,
        maxAttempts: 1,
        jitterMs: 0,
        endpointAutoDisable: { failureThreshold: 2 },
      },
    });
    servers.push(relay);
    return { port: await listen(relay), audit, calls: () => calls };
  }

  it("auto-disables after consecutive failures, dead-letters without attempt, re-enables via the operator route", async () => {
    const { port, audit, calls } = await makeRelay();
    assert.equal(await postWebhook(port), 202);
    assert.equal(await postWebhook(port), 202);
    const deadline = Date.now() + 5000;
    while (calls() < 2 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(calls(), 2);

    // Two consecutive failures tripped the gate (recorded synchronously).
    const disabledEvents = audit.query({ event: "endpoint_auto_disabled" }) as Array<{
      endpoint: string;
      consecutiveFailures: number;
      failureThreshold: number;
    }>;
    assert.equal(disabledEvents.length, 1);
    assert.equal(disabledEvents[0].endpoint, URL);
    assert.equal(disabledEvents[0].consecutiveFailures, 2);
    assert.equal(disabledEvents[0].failureThreshold, 2);

    // The next webhook is accepted but never attempted: straight to DLQ.
    assert.equal(await postWebhook(port), 202);
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(calls(), 2);

    const metrics = await getMetrics(port, TOKEN);
    assert.equal(metrics.status, 200);
    assert.match(metrics.text, /relay_endpoint_auto_disables_total\{[^}]*\} 1/);
    assert.match(metrics.text, /relay_endpoint_disabled\{[^}]*\} 1/);

    // Operator re-enable: audited, deliveries flow again.
    const enable = await postJson(port, "/endpoints/enable", { endpoint: URL }, TOKEN);
    assert.equal(enable.status, 200);
    assert.deepEqual(enable.json, { endpoint: URL, disabled: false, wasDisabled: true });
    const enabledEvents = audit.query({ event: "endpoint_enabled" }) as Array<{ endpoint: string }>;
    assert.equal(enabledEvents.length, 1);
    assert.equal(enabledEvents[0].endpoint, URL);

    // Re-enabling an already-enabled endpoint is a no-op 200.
    const again = await postJson(port, "/endpoints/enable", { endpoint: URL }, TOKEN);
    assert.equal(again.status, 200);
    assert.deepEqual(again.json, { endpoint: URL, disabled: false, wasDisabled: false });

    // Unknown endpoints are a fail-closed 404.
    assert.equal(
      (await postJson(port, "/endpoints/enable", { endpoint: "http://unknown/hook" }, TOKEN)).status,
      404
    );
    // No token: 403.
    assert.equal((await postJson(port, "/endpoints/enable", { endpoint: URL })).status, 403);
  });
});
