import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type Sender, type CircuitState } from "../src/retry.ts";
import { EndpointCircuitBreaker } from "../src/circuit.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const URL = "http://localhost:9999/hook";
const SECRET = "relay-secret";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));

/**
 * Manual timer with single-step control: breaker parking re-arms timers, so
 * the tests advance one wave at a time instead of draining everything.
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

describe("EndpointCircuitBreaker", () => {
  it("trips open after failureThreshold consecutive failures", () => {
    let now = 0;
    const transitions: string[] = [];
    const b = new EndpointCircuitBreaker({
      failureThreshold: 3,
      cooldownMs: 5000,
      nowMs: () => now,
      onStateChange: (e, from, to) => transitions.push(`${from}->${to}`),
    });
    assert.equal(b.state(URL), "closed");
    assert.deepEqual(b.shouldAllow(URL), { allowed: true, probe: false });
    b.recordFailure(URL);
    b.recordFailure(URL);
    assert.equal(b.state(URL), "closed"); // below threshold
    b.recordFailure(URL);
    assert.equal(b.state(URL), "open");
    assert.deepEqual(b.shouldAllow(URL), { allowed: false, probe: false });
    assert.deepEqual(transitions, ["closed->open"]);
    const s = b.stats().find((x) => x.endpoint === URL)!;
    assert.equal(s.trips, 1);
    assert.equal(s.consecutiveFailures, 3);
    assert.equal(s.openedAtMs, 0);
  });

  it("allows a single half-open probe after the cooldown; success closes", () => {
    let now = 0;
    const b = new EndpointCircuitBreaker({
      failureThreshold: 2,
      cooldownMs: 5000,
      nowMs: () => now,
    });
    b.recordFailure(URL);
    b.recordFailure(URL);
    assert.equal(b.state(URL), "open");
    now += 4999;
    assert.equal(b.shouldAllow(URL).allowed, false); // still cooling
    now += 1;
    assert.deepEqual(b.shouldAllow(URL), { allowed: true, probe: true });
    assert.equal(b.state(URL), "half_open");
    assert.equal(b.shouldAllow(URL).allowed, false); // probe slot busy
    b.recordSuccess(URL);
    assert.equal(b.state(URL), "closed");
    assert.deepEqual(b.shouldAllow(URL), { allowed: true, probe: false });
    assert.equal(b.stats()[0].consecutiveFailures, 0);
  });

  it("re-opens when the half-open probe fails and restarts the cooldown", () => {
    let now = 0;
    const transitions: string[] = [];
    const b = new EndpointCircuitBreaker({
      failureThreshold: 1,
      cooldownMs: 1000,
      nowMs: () => now,
      onStateChange: (e, from, to) => transitions.push(`${from}->${to}`),
    });
    b.recordFailure(URL);
    assert.equal(b.state(URL), "open");
    now += 1000;
    assert.ok(b.shouldAllow(URL).probe);
    b.recordFailure(URL);
    assert.equal(b.state(URL), "open");
    assert.deepEqual(transitions, ["closed->open", "open->half_open", "half_open->open"]);
    assert.equal(b.stats()[0].trips, 2);
    now += 999;
    assert.equal(b.shouldAllow(URL).allowed, false); // cooldown restarted
    now += 1;
    assert.ok(b.shouldAllow(URL).probe);
  });

  it("a success resets the consecutive failure count", () => {
    const b = new EndpointCircuitBreaker({ failureThreshold: 3 });
    b.recordFailure(URL);
    b.recordFailure(URL);
    b.recordSuccess(URL);
    b.recordFailure(URL);
    b.recordFailure(URL);
    assert.equal(b.state(URL), "closed");
    assert.equal(b.stats()[0].consecutiveFailures, 2);
    assert.equal(b.stats()[0].trips, 0);
  });

  it("cancelProbe frees the half-open slot without changing state", () => {
    let now = 0;
    const b = new EndpointCircuitBreaker({
      failureThreshold: 1,
      cooldownMs: 1000,
      nowMs: () => now,
    });
    b.recordFailure(URL);
    now += 1000;
    assert.ok(b.shouldAllow(URL).probe);
    b.cancelProbe(URL);
    assert.equal(b.state(URL), "half_open");
    assert.ok(b.shouldAllow(URL).probe); // slot freed for the next attempt
  });

  it("retryInMs reports the remaining cooldown", () => {
    let now = 0;
    const b = new EndpointCircuitBreaker({
      failureThreshold: 1,
      cooldownMs: 5000,
      nowMs: () => now,
    });
    assert.equal(b.retryInMs(URL), 0); // closed
    b.recordFailure(URL);
    now += 2000;
    assert.equal(b.retryInMs(URL), 3000);
  });

  it("tracks endpoints independently", () => {
    const b = new EndpointCircuitBreaker({ failureThreshold: 1 });
    b.recordFailure("http://a/hook");
    assert.equal(b.state("http://a/hook"), "open");
    assert.equal(b.state("http://b/hook"), "closed");
    assert.equal(b.stats().length, 1); // unseen endpoints leave no record
  });

  it("rejects invalid configuration", () => {
    assert.throws(() => new EndpointCircuitBreaker({ failureThreshold: 0 }), RangeError);
    assert.throws(() => new EndpointCircuitBreaker({ failureThreshold: 1.5 }), RangeError);
    assert.throws(() => new EndpointCircuitBreaker({ cooldownMs: 0 }), RangeError);
    assert.throws(() => new EndpointCircuitBreaker({ cooldownMs: -5 }), RangeError);
    assert.throws(() => new EndpointCircuitBreaker({ halfOpenMaxInFlight: 0 }), RangeError);
    assert.throws(() => new EndpointCircuitBreaker({ halfOpenRetryMs: 0 }), RangeError);
    new EndpointCircuitBreaker({});
  });
});

describe("retry queue circuit breaker", () => {
  function makeQueue() {
    const timer = manualTimer();
    let now = 0;
    const f = failingSender();
    const transitions: Array<{ endpoint: string; from: CircuitState; to: CircuitState }> = [];
    const q = new RetryQueue({
      sender: f.sender,
      baseDelayMs: 10,
      maxAttempts: 5,
      jitterMs: 0,
      random: () => 0, // deterministic parking delay
      setTimer: timer.setTimer,
      circuitBreaker: { failureThreshold: 3, cooldownMs: 5000, nowMs: () => now },
      onCircuitStateChange: (endpoint, from, to) => transitions.push({ endpoint, from, to }),
    });
    return { q, timer, f, transitions, advance: (ms: number) => (now += ms) };
  }

  const ITEM = { id: "cb-1", payload: Buffer.from("x"), targetUrl: URL, headers: {} };

  it("parks attempts while open without consuming the retry budget", async () => {
    const { q, timer, f, transitions, advance } = makeQueue();
    q.start();
    q.enqueue({ ...ITEM });

    await timer.step(); // attempt 1 fails
    await timer.step(); // attempt 2 fails
    await timer.step(); // attempt 3 fails -> trips open
    assert.equal(f.calls(), 3);
    assert.equal(q.getCircuitStats()[0].state, "open");

    await timer.step(); // attempt 4 would fire: parked instead
    assert.equal(f.calls(), 3); // no sender call while open
    assert.equal(q.pendingCount(), 1); // item kept, not dead-lettered
    assert.equal(q.getDeadLetter().length, 0);
    assert.ok(q.circuitBlockedCount() >= 1);

    // Still cooling: another wave parks again, still no sender call.
    await timer.step();
    assert.equal(f.calls(), 3);

    // Cooldown elapses -> half-open probe runs and fails -> re-opens.
    advance(5000);
    await timer.step();
    assert.equal(f.calls(), 4);
    assert.equal(q.getCircuitStats()[0].state, "open");
    assert.equal(q.getCircuitStats()[0].trips, 2);

    // Next cooldown: probe succeeds -> circuit closes, item delivered.
    f.setFail(false);
    advance(5000);
    await timer.step();
    assert.equal(f.calls(), 5);
    assert.equal(q.getCircuitStats()[0].state, "closed");
    assert.equal(q.pendingCount(), 0);

    const seq = transitions.map((t) => `${t.from}->${t.to}`);
    assert.deepEqual(seq, [
      "closed->open",
      "open->half_open",
      "half_open->open",
      "open->half_open",
      "half_open->closed",
    ]);
  });

  it("is disabled by default: failures go straight to dead-letter", async () => {
    const timer = manualTimer();
    const f = failingSender();
    const q = new RetryQueue({
      sender: f.sender,
      baseDelayMs: 10,
      maxAttempts: 3,
      jitterMs: 0,
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue({ ...ITEM });
    while (timer.pendingCount() > 0) await timer.step();
    assert.equal(f.calls(), 3);
    assert.equal(q.getDeadLetter().length, 1);
    assert.deepEqual(q.getCircuitStats(), []);
    assert.equal(q.circuitBlockedCount(), 0);
  });
});

describe("server circuit breaker audit", () => {
  function listen(server: Server): Promise<number> {
    return new Promise((resolve) => {
      server.listen(0, "127.0.0.1", () => {
        const addr = server.address();
        assert.ok(addr && typeof addr === "object");
        resolve(addr.port);
      });
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

  it("audits circuit_open with the endpoint when the breaker trips", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const forwardUrl = "http://127.0.0.1:1/unreachable";
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl,
      auditLog: audit,
      sender: async () => {
        throw new Error("down");
      },
      retry: {
        baseDelayMs: 10,
        maxDelayMs: 50,
        maxAttempts: 2,
        jitterMs: 0,
        circuitBreaker: { failureThreshold: 2, cooldownMs: 60_000 },
      },
    });
    const port = await listen(relay);
    try {
      const res = await post(port, BODY, { "x-signature": signSha256(BODY, SECRET) });
      assert.equal(res.status, 202);
      const deadline = Date.now() + 5000;
      let events: Array<Record<string, unknown>> = [];
      while (Date.now() < deadline) {
        events = audit.readAll() as Array<Record<string, unknown>>;
        if (events.some((e) => e.event === "circuit_open")) break;
        await new Promise((r) => setTimeout(r, 25));
      }
      const open = events.find((e) => e.event === "circuit_open");
      assert.ok(open, "expected a circuit_open audit event");
      assert.equal(open.endpoint, forwardUrl);
      assert.equal(open.from, "closed");
      assert.equal(open.to, "open");
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });
});
