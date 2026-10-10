import { describe, it, afterEach } from "node:test";
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
const TOKEN = "op-token";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));

/**
 * Manual timer with single-step control: parking re-arms timers, so the
 * tests advance one wave at a time instead of draining everything.
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
    clearTimer: (h: { clear(): void }) => h.clear(),
    async step() {
      const fns = pending.splice(0);
      for (const f of fns) f();
      await flush();
    },
  };
}

/** Let the deliver() promise chain (turn -> limiter -> sender) settle. */
async function flush(ticks = 10) {
  for (let i = 0; i < ticks; i++) {
    await new Promise((r) => setImmediate(r));
  }
}

function item(id: string, targetUrl: string = URL) {
  return { id, payload: BODY, targetUrl, headers: {} };
}

describe("RetryQueue.pauseEndpoint / resumeEndpoint", () => {
  it("parks queued deliveries while paused and resumes them on resume", async () => {
    const timer = manualTimer();
    let calls = 0;
    const q = new RetryQueue({
      sender: async () => {
        calls += 1;
      },
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      jitterMs: 0,
    });
    assert.equal(q.pauseEndpoint(URL), true);
    assert.deepEqual(q.getPausedEndpoints(), [URL]);

    q.enqueue(item("a"));
    q.start();
    await timer.step();
    assert.equal(calls, 0); // parked: no delivery attempt fired
    assert.equal(q.pendingCount(), 1);
    assert.equal(q.getDeadLetter().length, 0);

    assert.equal(q.resumeEndpoint(URL), true);
    assert.deepEqual(q.getPausedEndpoints(), []);
    await timer.step();
    assert.equal(calls, 1);
    assert.equal(q.pendingCount(), 0);
  });

  it("parks newly accepted events for a paused endpoint, including urgent ones", async () => {
    const timer = manualTimer();
    let calls = 0;
    const q = new RetryQueue({
      sender: async () => {
        calls += 1;
      },
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      jitterMs: 0,
    });
    q.start();
    q.pauseEndpoint(URL);
    q.enqueue(item("n1"));
    q.enqueue({ ...item("u1"), priority: "urgent" });
    await timer.step();
    assert.equal(calls, 0);
    assert.equal(q.pendingCount(), 2);
    q.resumeEndpoint(URL);
    await timer.step();
    await timer.step();
    assert.equal(calls, 2);
  });

  it("disarms an armed backoff timer on pause; resume continues the backoff without resetting attempts", async () => {
    const timer = manualTimer();
    const seenAttempts: number[] = [];
    let fail = true;
    const q = new RetryQueue({
      sender: async (it) => {
        seenAttempts.push(it.attempt ?? -1);
        if (fail) throw new Error("boom");
      },
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      baseDelayMs: 1000,
      maxAttempts: 5,
      jitterMs: 0,
    });
    q.enqueue(item("a"));
    q.start();
    await timer.step(); // attempt 1 fails -> retry scheduled
    assert.deepEqual(seenAttempts, [0]);
    assert.equal(timer.pendingCount(), 1);

    q.pauseEndpoint(URL);
    assert.equal(timer.pendingCount(), 0); // disarmed, not fired
    assert.equal(q.pendingCount(), 1);
    assert.equal(q.getDeadLetter().length, 0); // nothing dead-lettered while parked

    fail = false;
    q.resumeEndpoint(URL);
    assert.equal(timer.pendingCount(), 1); // re-armed with the remaining delay
    await timer.step();
    assert.deepEqual(seenAttempts, [0, 1]); // attempt count preserved, not reset
    assert.equal(q.pendingCount(), 0);
  });

  it("does not consume the global retry budget while parked", async () => {
    const timer = manualTimer();
    let depleted = 0;
    const q = new RetryQueue({
      sender: async () => {
        throw new Error("down");
      },
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      baseDelayMs: 10,
      maxAttempts: 5,
      jitterMs: 0,
      retryBudget: { retriesPerMinute: 2 },
      onRetryBudgetDepleted: () => {
        depleted += 1;
      },
    });
    q.enqueue(item("a"));
    q.start();
    await timer.step(); // attempt 1 fails -> budget take #1 -> retry scheduled
    q.pauseEndpoint(URL); // disarm + park
    q.resumeEndpoint(URL); // re-arm; parking must not have cost a token
    await timer.step(); // attempt 2 fails -> budget take #2 succeeds
    assert.equal(depleted, 0); // a consumed-on-park token would have parked this retry
    assert.equal(timer.pendingCount(), 1); // retry scheduled normally, not budget-parked
  });

  it("leaves the circuit breaker untouched and breaker transitions never unpause", async () => {
    const timer = manualTimer();
    const transitions: string[] = [];
    let calls = 0;
    const q = new RetryQueue({
      sender: async () => {
        calls += 1;
        throw new Error("down");
      },
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      baseDelayMs: 10,
      maxAttempts: 10,
      jitterMs: 0,
      circuitBreaker: { failureThreshold: 2, cooldownMs: 60_000 },
      onCircuitStateChange: (_e, from, to) => transitions.push(`${from}->${to}`),
    });
    q.enqueue(item("a"));
    q.start();
    await timer.step(); // fail 1
    await timer.step(); // fail 2 -> circuit opens
    assert.deepEqual(transitions, ["closed->open"]);
    assert.equal(q.getCircuitStats()[0].state, "open");
    assert.equal(calls, 2);

    q.pauseEndpoint(URL);
    assert.deepEqual(q.getPausedEndpoints(), [URL]);
    assert.equal(timer.pendingCount(), 0);
    await timer.step();
    assert.equal(calls, 2); // no attempt while paused
    // Pause added no transitions and did not change breaker state.
    assert.deepEqual(transitions, ["closed->open"]);
    assert.equal(q.getCircuitStats()[0].state, "open");

    q.resumeEndpoint(URL);
    assert.deepEqual(q.getPausedEndpoints(), []);
    await timer.step(); // retry due, but circuit still open -> parked by circuit
    assert.equal(calls, 2); // still no attempt: the park, not the pause
    assert.ok(q.circuitBlockedCount() >= 1);
    assert.deepEqual(transitions, ["closed->open"]); // pause/resume touched nothing
  });

  it("is idempotent and validates its input", () => {
    const q = new RetryQueue({});
    assert.equal(q.pauseEndpoint(URL), true);
    assert.equal(q.pauseEndpoint(URL), false);
    assert.deepEqual(q.getPausedEndpoints(), [URL]);
    assert.equal(q.resumeEndpoint(URL), true);
    assert.equal(q.resumeEndpoint(URL), false);
    assert.deepEqual(q.getPausedEndpoints(), []);
    assert.throws(() => q.pauseEndpoint(""), RangeError);
    assert.throws(() => q.resumeEndpoint(""), RangeError);
    assert.throws(() => q.pauseEndpoint(undefined as unknown as string), RangeError);
    assert.throws(() => q.resumeEndpoint(42 as unknown as string), RangeError);
  });

  it("allows pausing a never-seen endpoint (pre-emptive hold)", async () => {
    const timer = manualTimer();
    let calls = 0;
    const q = new RetryQueue({
      sender: async () => {
        calls += 1;
      },
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      jitterMs: 0,
    });
    const unknown = "http://never/seen";
    assert.equal(q.pauseEndpoint(unknown), true);
    q.enqueue(item("x", unknown));
    q.start();
    await timer.step();
    assert.equal(calls, 0); // parked immediately, even though never seen before
    q.resumeEndpoint(unknown);
    await timer.step();
    assert.equal(calls, 1);
  });

  it("fires the pause/resume hooks edge-triggered", () => {
    const paused: string[] = [];
    const resumed: string[] = [];
    const q = new RetryQueue({
      onEndpointPaused: (i) => paused.push(i.endpoint),
      onEndpointResumed: (i) => resumed.push(i.endpoint),
    });
    q.pauseEndpoint(URL);
    q.pauseEndpoint(URL); // no-op: no second event
    q.resumeEndpoint(URL);
    q.resumeEndpoint(URL); // no-op: no second event
    assert.deepEqual(paused, [URL]);
    assert.deepEqual(resumed, [URL]);
  });

  it("does not cancel an in-flight delivery when the pause lands", async () => {
    const timer = manualTimer();
    let releaseSender!: () => void;
    let delivered = 0;
    const sender: Sender = async () => {
      await new Promise<void>((r) => {
        releaseSender = r;
      });
    };
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      jitterMs: 0,
      onDelivered: () => {
        delivered += 1;
      },
    });
    q.enqueue(item("a"));
    q.start();
    await timer.step(); // sender invoked, promise pending
    q.pauseEndpoint(URL); // lands mid-flight: must not cancel it
    assert.deepEqual(q.getPausedEndpoints(), [URL]);
    releaseSender();
    await flush();
    assert.equal(delivered, 1); // settled normally
    assert.equal(q.pendingCount(), 0);
  });

  it("parks a delivery whose pause lands while it waits for a limiter slot", async () => {
    const timer = manualTimer();
    const order: string[] = [];
    let releaseA!: () => void;
    const sender: Sender = async (it) => {
      order.push(it.id);
      if (it.id === "a") {
        await new Promise<void>((r) => {
          releaseA = r;
        });
      }
    };
    const q = new RetryQueue({
      sender,
      setTimer: timer.setTimer,
      clearTimer: timer.clearTimer,
      maxConcurrentPerEndpoint: 1,
      jitterMs: 0,
    });
    q.enqueue(item("a"));
    q.enqueue(item("b"));
    q.start();
    await timer.step(); // a in flight (holds the slot), b waits on the limiter
    await flush();
    assert.deepEqual(order, ["a"]);
    q.pauseEndpoint(URL); // lands while b waits: b must park, not dispatch
    releaseA();
    await flush();
    assert.deepEqual(order, ["a"]); // b never attempted while paused
    assert.equal(q.pendingCount(), 1);
    q.resumeEndpoint(URL);
    await timer.step();
    await flush();
    assert.deepEqual(order, ["a", "b"]);
  });
});

describe("POST /endpoints/pause + /endpoints/resume operator routes", () => {
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
            "x-signature": signSha256(BODY, SECRET),
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

  async function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "pause-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    let calls = 0;
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: URL,
      auditLog: audit,
      operatorToken: TOKEN,
      sender: async () => {
        calls += 1;
      },
      retry: { baseDelayMs: 10, maxAttempts: 3, jitterMs: 0 },
      ...extra,
    });
    servers.push(relay);
    return { port: await listen(relay), audit, calls: () => calls };
  }

  it("pauses and resumes with audit events", async () => {
    const { port, audit } = await makeRelay();
    const paused = await postJson(port, "/endpoints/pause", { endpoint: URL }, TOKEN);
    assert.equal(paused.status, 200);
    assert.deepEqual(paused.json, { endpoint: URL, paused: true });
    const pauseEvents = audit.query({ event: "endpoint_paused" }) as Array<{ endpoint: string }>;
    assert.equal(pauseEvents.length, 1);
    assert.equal(pauseEvents[0].endpoint, URL);

    const resumed = await postJson(port, "/endpoints/resume", { endpoint: URL }, TOKEN);
    assert.equal(resumed.status, 200);
    assert.deepEqual(resumed.json, { endpoint: URL, paused: false });
    assert.equal(audit.query({ event: "endpoint_resumed" }).length, 1);
  });

  it("is idempotent over HTTP without duplicate audit events", async () => {
    const { port, audit } = await makeRelay();
    assert.equal((await postJson(port, "/endpoints/pause", { endpoint: URL }, TOKEN)).status, 200);
    assert.equal((await postJson(port, "/endpoints/pause", { endpoint: URL }, TOKEN)).status, 200);
    assert.equal(audit.query({ event: "endpoint_paused" }).length, 1);
    assert.equal((await postJson(port, "/endpoints/resume", { endpoint: URL }, TOKEN)).status, 200);
    assert.equal((await postJson(port, "/endpoints/resume", { endpoint: URL }, TOKEN)).status, 200);
    assert.equal(audit.query({ event: "endpoint_resumed" }).length, 1);
  });

  it("requires the operator token and fails closed without one", async () => {
    const { port } = await makeRelay();
    assert.equal((await postJson(port, "/endpoints/pause", { endpoint: URL })).status, 403);
    assert.equal((await postJson(port, "/endpoints/resume", { endpoint: URL }, "wrong")).status, 403);

    const dir = mkdtempSync(join(tmpdir(), "pause-notoken-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({ secret: SECRET, forwardUrl: URL, auditLog: audit });
    servers.push(relay);
    const p2 = await listen(relay);
    assert.equal((await postJson(p2, "/endpoints/pause", { endpoint: URL }, TOKEN)).status, 404);
    assert.equal((await postJson(p2, "/endpoints/resume", { endpoint: URL }, TOKEN)).status, 404);
  });

  it("rejects malformed bodies with 400 and unknown endpoints with 404", async () => {
    const { port, audit } = await makeRelay();
    assert.equal((await postJson(port, "/endpoints/pause", {}, TOKEN)).status, 400);
    assert.equal((await postJson(port, "/endpoints/pause", { endpoint: "" }, TOKEN)).status, 400);
    assert.equal((await postJson(port, "/endpoints/pause", { endpoint: 42 }, TOKEN)).status, 400);
    assert.equal(
      (await postJson(port, "/endpoints/pause", { endpoint: "http://unknown/hook" }, TOKEN)).status,
      404
    );
    assert.equal(
      (await postJson(port, "/endpoints/resume", { endpoint: "http://unknown/hook" }, TOKEN)).status,
      404
    );
    assert.equal(audit.query({ event: "endpoint_paused" }).length, 0);
    assert.equal((await postJson(port, "/endpoints/pause", { endpoint: URL }, TOKEN, "GET")).status, 405);
  });

  it("parks inbound deliveries end to end until resumed", async () => {
    const { port, calls } = await makeRelay();
    assert.equal((await postJson(port, "/endpoints/pause", { endpoint: URL }, TOKEN)).status, 200);
    assert.equal(await postWebhook(port), 202); // accepted, not delivered
    await new Promise((r) => setTimeout(r, 150));
    assert.equal(calls(), 0); // parked: no delivery attempt
    assert.equal((await postJson(port, "/endpoints/resume", { endpoint: URL }, TOKEN)).status, 200);
    const deadline = Date.now() + 5000;
    while (calls() === 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(calls(), 1);
  });
});
