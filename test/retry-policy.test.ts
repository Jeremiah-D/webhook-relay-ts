import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  RetryPolicyRegistry,
  assertValidRetryPolicy,
  type Sender,
} from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

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

const ENDPOINT_A = "http://localhost:9999/policy-endpoint";
const ENDPOINT_B = "http://localhost:9999/plain-endpoint";

function policyQueue(extra: Record<string, unknown> = {}) {
  return new RetryQueue({
    sender: (async () => { throw new Error("boom"); }) as Sender,
    baseDelayMs: 1000,
    maxDelayMs: 60000,
    maxAttempts: 5,
    jitterMs: 0,
    random: () => 0,
    retryPolicies: [
      { name: "fast", maxAttempts: 2, baseDelayMs: 100, maxDelayMs: 10000 },
    ],
    endpointRetryPolicies: { [ENDPOINT_A]: "fast" },
    ...extra,
  });
}

describe("retry-policy registry", () => {
  it("rejects invalid registrations", () => {
    assert.throws(() => assertValidRetryPolicy("", { maxAttempts: 3, baseDelayMs: 100, maxDelayMs: 1000 }), RangeError);
    assert.throws(() => assertValidRetryPolicy("x", null), RangeError);
    assert.throws(() => assertValidRetryPolicy("x", { maxAttempts: 0, baseDelayMs: 100, maxDelayMs: 1000 }), RangeError);
    assert.throws(() => assertValidRetryPolicy("x", { maxAttempts: 1.5, baseDelayMs: 100, maxDelayMs: 1000 }), RangeError);
    assert.throws(() => assertValidRetryPolicy("x", { maxAttempts: 3, baseDelayMs: 0, maxDelayMs: 1000 }), RangeError);
    assert.throws(() => assertValidRetryPolicy("x", { maxAttempts: 3, baseDelayMs: 100, maxDelayMs: Infinity }), RangeError);
    assert.throws(() => assertValidRetryPolicy("x", { maxAttempts: 3, baseDelayMs: 100, maxDelayMs: 1000, jitterMs: -1 }), RangeError);
    assert.throws(() => assertValidRetryPolicy("x", { maxAttempts: 3, baseDelayMs: 100, maxDelayMs: 1000, jitterStrategy: "random" }), RangeError);
    // Valid minimal and full configs pass.
    assertValidRetryPolicy("ok", { maxAttempts: 1, baseDelayMs: 1, maxDelayMs: 1 });
    assertValidRetryPolicy("ok2", { maxAttempts: 3, baseDelayMs: 100, maxDelayMs: 1000, jitterMs: 50, jitterStrategy: "full" });
  });

  it("re-registration updates in place and preserves snapshot order", () => {
    const reg = new RetryPolicyRegistry();
    reg.register("a", { maxAttempts: 3, baseDelayMs: 100, maxDelayMs: 1000 });
    reg.register("b", { maxAttempts: 4, baseDelayMs: 200, maxDelayMs: 2000 });
    reg.register("a", { maxAttempts: 9, baseDelayMs: 900, maxDelayMs: 9000 });
    assert.deepEqual(reg.names(), ["a", "b"]);
    assert.equal(reg.get("a")?.maxAttempts, 9);
    assert.equal(reg.has("zzz"), false);
    assert.equal(reg.get("zzz"), undefined);
  });

  it("snapshot returns copies in registration order", () => {
    const reg = new RetryPolicyRegistry();
    reg.register("a", { maxAttempts: 3, baseDelayMs: 100, maxDelayMs: 1000 });
    const snap = reg.snapshot();
    snap[0].maxAttempts = 999;
    assert.equal(reg.get("a")?.maxAttempts, 3);
    assert.deepEqual(reg.snapshot(), [
      { name: "a", maxAttempts: 3, baseDelayMs: 100, maxDelayMs: 1000 },
    ]);
  });
});

describe("RetryQueue named retry policies", () => {
  it("rejects unknown policy names at construction", () => {
    assert.throws(
      () => new RetryQueue({ endpointRetryPolicies: { "http://x/": "nope" } }),
      RangeError
    );
    assert.throws(
      () => new RetryQueue({ retryPolicies: [{ name: "bad", maxAttempts: 0, baseDelayMs: 100, maxDelayMs: 1000 }] as never }),
      RangeError
    );
  });

  it("resolves per-endpoint backoff from the assigned policy", () => {
    const q = policyQueue();
    // Policy "fast": base 100, jitter 0 -> attempt 0: 100, attempt 1: 200.
    assert.equal(q.delayForAttempt(0, ENDPOINT_A), 100);
    assert.equal(q.delayForAttempt(1, ENDPOINT_A), 200);
    // Unassigned endpoint keeps the global schedule: base 1000.
    assert.equal(q.delayForAttempt(0, ENDPOINT_B), 1000);
    assert.equal(q.retryPolicyFor(ENDPOINT_A), "fast");
    assert.equal(q.retryPolicyFor(ENDPOINT_B), undefined);
  });

  it("policy jitter overrides and inherits the queue's jitter", () => {
    const q = new RetryQueue({
      sender: (async () => {}) as Sender,
      baseDelayMs: 1000,
      maxDelayMs: 60000,
      jitterMs: 100,
      random: () => 1, // jitter draws its maximum
      retryPolicies: [
        { name: "inherit", maxAttempts: 3, baseDelayMs: 100, maxDelayMs: 10000 },
        { name: "override", maxAttempts: 3, baseDelayMs: 100, maxDelayMs: 10000, jitterMs: 50 },
        { name: "full", maxAttempts: 3, baseDelayMs: 100, maxDelayMs: 10000, jitterStrategy: "full" },
      ],
      endpointRetryPolicies: {
        "http://x/inherit": "inherit",
        "http://x/override": "override",
        "http://x/full": "full",
      },
    });
    // Inherit: 100 + queue jitter 100 = 200.
    assert.equal(q.delayForAttempt(0, "http://x/inherit"), 200);
    // Override: 100 + policy jitter 50 = 150.
    assert.equal(q.delayForAttempt(0, "http://x/override"), 150);
    // Full jitter strategy from the policy: 1 * min(cap, base) = 100.
    assert.equal(q.delayForAttempt(0, "http://x/full"), 100);
  });

  it("set/clear endpoint policy at runtime", () => {
    const q = policyQueue();
    assert.throws(() => q.setEndpointRetryPolicy(ENDPOINT_B, "nope"), RangeError);
    assert.throws(() => q.setEndpointRetryPolicy("", "fast"), RangeError);
    q.setEndpointRetryPolicy(ENDPOINT_B, "fast");
    assert.equal(q.retryPolicyFor(ENDPOINT_B), "fast");
    assert.equal(q.delayForAttempt(0, ENDPOINT_B), 100);
    assert.equal(q.clearEndpointRetryPolicy(ENDPOINT_B), true);
    assert.equal(q.retryPolicyFor(ENDPOINT_B), undefined);
    assert.equal(q.delayForAttempt(0, ENDPOINT_B), 1000);
    assert.equal(q.clearEndpointRetryPolicy(ENDPOINT_B), false);
  });

  it("re-registering a policy takes effect immediately", () => {
    const q = policyQueue();
    assert.equal(q.delayForAttempt(0, ENDPOINT_A), 100);
    q.registerRetryPolicy("fast", { maxAttempts: 4, baseDelayMs: 500, maxDelayMs: 10000 });
    assert.equal(q.delayForAttempt(0, ENDPOINT_A), 500);
    assert.equal(q.effectiveRetryConfig(ENDPOINT_A).maxAttempts, 4);
    // Bad re-registration throws and leaves the old policy intact.
    assert.throws(
      () => q.registerRetryPolicy("fast", { maxAttempts: 0, baseDelayMs: 500, maxDelayMs: 10000 }),
      RangeError
    );
    assert.equal(q.delayForAttempt(0, ENDPOINT_A), 500);
  });

  it("getRetryPolicies returns an ordered, detached snapshot", () => {
    const q = policyQueue();
    const snap = q.getRetryPolicies();
    assert.deepEqual(snap.map((p) => p.name), ["fast"]);
    snap[0].baseDelayMs = 12345;
    assert.equal(q.effectiveRetryConfig(ENDPOINT_A).baseDelayMs, 100);
  });

  it("effectiveRetryConfig falls back to the global config", () => {
    const q = policyQueue();
    assert.deepEqual(q.effectiveRetryConfig(ENDPOINT_B), {
      baseDelayMs: 1000,
      maxDelayMs: 60000,
      maxAttempts: 5,
      jitterMs: 0,
      jitterStrategy: "additive",
    });
    assert.deepEqual(q.effectiveRetryConfig(ENDPOINT_A), {
      baseDelayMs: 100,
      maxDelayMs: 10000,
      maxAttempts: 2,
      jitterMs: 0,
      jitterStrategy: "additive",
    });
  });

  it("policy maxAttempts governs dead-lettering per endpoint", async () => {
    const timer = manualTimer();
    const attempts: Record<string, number> = { a: 0, b: 0 };
    const q = new RetryQueue({
      sender: (async (item) => {
        attempts[item.targetUrl === ENDPOINT_A ? "a" : "b"] += 1;
        throw new Error("boom");
      }) as Sender,
      baseDelayMs: 10,
      maxDelayMs: 100,
      maxAttempts: 5,
      jitterMs: 0,
      setTimer: timer.setTimer,
      retryPolicies: [{ name: "once", maxAttempts: 1, baseDelayMs: 10, maxDelayMs: 100 }],
      endpointRetryPolicies: { [ENDPOINT_A]: "once" },
    });
    q.start();
    q.enqueue({ id: "p1", payload: Buffer.from("x"), targetUrl: ENDPOINT_A, headers: {} });
    q.enqueue({ id: "p2", payload: Buffer.from("x"), targetUrl: ENDPOINT_B, headers: {} });
    await timer.run();
    // Policy endpoint: a single attempt, then dead-lettered.
    assert.equal(attempts.a, 1);
    // Global endpoint: all five attempts spent.
    assert.equal(attempts.b, 5);
    assert.equal(q.getDeadLetter().length, 2);
    assert.equal(q.pendingCount(), 0);
    q.stop();
  });

  it("updateEndpointConfig re-points and detaches policies (WR-32 combo)", () => {
    const q = policyQueue();
    q.registerRetryPolicy("slow", { maxAttempts: 7, baseDelayMs: 2000, maxDelayMs: 120000 });
    const changes = q.updateEndpointConfig(ENDPOINT_A, { retryPolicyName: "slow" });
    assert.ok(changes.some((c) => c.field === "retryPolicyName" && c.from === "fast" && c.to === "slow"));
    assert.equal(q.retryPolicyFor(ENDPOINT_A), "slow");
    assert.equal(q.delayForAttempt(0, ENDPOINT_A), 2000);
    // Unknown name: throws, assignment untouched.
    assert.throws(() => q.updateEndpointConfig(ENDPOINT_A, { retryPolicyName: "nope" }), RangeError);
    assert.equal(q.retryPolicyFor(ENDPOINT_A), "slow");
    // null detaches back to the global config.
    const cleared = q.updateEndpointConfig(ENDPOINT_A, { retryPolicyName: null });
    assert.ok(cleared.some((c) => c.field === "retryPolicyName" && c.from === "slow" && c.to === null));
    assert.equal(q.retryPolicyFor(ENDPOINT_A), undefined);
    assert.equal(q.delayForAttempt(0, ENDPOINT_A), 1000);
    // Malformed patches are rejected by the validator.
    assert.throws(() => q.updateEndpointConfig(ENDPOINT_A, { retryPolicyName: "" }), RangeError);
  });

  it("adaptive backoff is skipped for policy-assigned endpoints", () => {
    const q = new RetryQueue({
      sender: (async () => {}) as Sender,
      baseDelayMs: 1000,
      maxDelayMs: 60000,
      jitterMs: 0,
      random: () => 0,
      adaptiveBackoff: { minBaseMs: 100, maxBaseMs: 8000 },
      retryPolicies: [{ name: "fixed", maxAttempts: 3, baseDelayMs: 300, maxDelayMs: 30000 }],
      endpointRetryPolicies: { [ENDPOINT_A]: "fixed" },
    });
    // The policy base is used as-is even with adaptive backoff enabled.
    assert.equal(q.delayForAttempt(0, ENDPOINT_A), 300);
    // The global path still routes through the adaptive controller (resting base 1000).
    assert.equal(q.delayForAttempt(0, ENDPOINT_B), 1000);
  });
});

describe("server stamps the selected policy on accepted audit events", () => {
  it("accepted event carries retryPolicy when the endpoint has one", async () => {
    const stub: Server = createServer((_req, res) => res.writeHead(200).end("ok"));
    await new Promise<void>((r) => stub.listen(0, "127.0.0.1", r));
    const stubPort = (stub.address() as { port: number }).port;
    const forwardUrl = `http://127.0.0.1:${stubPort}/hook`;
    const dir = mkdtempSync(join(tmpdir(), "audit-policy-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: "relay-secret",
      forwardUrl,
      auditLog: audit,
      retry: {
        baseDelayMs: 10,
        jitterMs: 0,
        maxAttempts: 2,
        retryPolicies: [{ name: "patient", maxAttempts: 4, baseDelayMs: 50, maxDelayMs: 5000 }],
        endpointRetryPolicies: { [forwardUrl]: "patient" },
      },
    });
    await new Promise<void>((r) => relay.listen(0, "127.0.0.1", r));
    const port = (relay.address() as { port: number }).port;
    try {
      const body = Buffer.from(JSON.stringify({ n: 1 }));
      const res = await new Promise<{ status: number }>((resolve, reject) => {
        const r = httpRequest(
          {
            host: "127.0.0.1",
            port,
            path: "/",
            method: "POST",
            headers: {
              "x-signature": signSha256(body, "relay-secret"),
              "content-type": "application/json",
            },
          },
          (resp) => {
            resp.resume();
            resp.on("end", () => resolve({ status: resp.statusCode ?? 0 }));
          }
        );
        r.on("error", reject);
        r.end(body);
      });
      assert.equal(res.status, 202);
      const events = audit.readAll() as Array<Record<string, unknown>>;
      const accepted = events.find((e) => e.event === "accepted");
      assert.ok(accepted);
      assert.equal(accepted.retryPolicy, "patient");
      assert.equal(accepted.targetUrl, forwardUrl);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
      stub.close();
      await new Promise((r) => stub.once("close", r));
    }
  });

  it("accepted event omits retryPolicy without an assigned policy", async () => {
    const stub: Server = createServer((_req, res) => res.writeHead(200).end("ok"));
    await new Promise<void>((r) => stub.listen(0, "127.0.0.1", r));
    const stubPort = (stub.address() as { port: number }).port;
    const dir = mkdtempSync(join(tmpdir(), "audit-policy-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: "relay-secret",
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
    });
    await new Promise<void>((r) => relay.listen(0, "127.0.0.1", r));
    const port = (relay.address() as { port: number }).port;
    try {
      const body = Buffer.from(JSON.stringify({ n: 2 }));
      const res = await new Promise<{ status: number }>((resolve, reject) => {
        const r = httpRequest(
          {
            host: "127.0.0.1",
            port,
            path: "/",
            method: "POST",
            headers: {
              "x-signature": signSha256(body, "relay-secret"),
              "content-type": "application/json",
            },
          },
          (resp) => {
            resp.resume();
            resp.on("end", () => resolve({ status: resp.statusCode ?? 0 }));
          }
        );
        r.on("error", reject);
        r.end(body);
      });
      assert.equal(res.status, 202);
      const events = audit.readAll() as Array<Record<string, unknown>>;
      const accepted = events.find((e) => e.event === "accepted");
      assert.ok(accepted);
      assert.ok(!("retryPolicy" in accepted));
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
      stub.close();
      await new Promise((r) => stub.once("close", r));
    }
  });
});
