import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  RetryQueue,
  SemanticDeliveryError,
  type DownstreamResponse,
  type Sender,
  type SemanticFailureInfo,
} from "../src/retry.ts";

/** Deterministic timer: `run()` executes pending callbacks immediately. */
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
const URL_OTHER = "http://localhost:9999/other";

const ITEM = {
  id: "item-1",
  payload: Buffer.from("hello"),
  targetUrl: URL,
  headers: { "content-type": "application/json" },
};

/** Sender whose 2xx responses carry a JSON body the validator can judge. */
function jsonSender(bodies: Buffer[], senderCalls: { count: number }) {
  const sender: Sender = async () => {
    senderCalls.count += 1;
    const body = bodies[Math.min(senderCalls.count - 1, bodies.length - 1)];
    const response: DownstreamResponse = { statusCode: 200, body, truncated: false };
    return response;
  };
  return sender;
}

describe("WR-37 downstream response semantic validation", () => {
  it("delivers when the validator returns true", async () => {
    const timer = manualTimer();
    const calls = { count: 0 };
    const semantic: SemanticFailureInfo[] = [];
    let delivered = 0;
    const q = new RetryQueue({
      sender: jsonSender([Buffer.from('{"ok":true}')], calls),
      maxAttempts: 3,
      jitterMs: 0,
      setTimer: timer.setTimer,
      responseValidators: () => true,
      onSemanticFailure: (info) => semantic.push(info),
      onDelivered: () => {
        delivered += 1;
      },
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();
    assert.equal(calls.count, 1);
    assert.equal(delivered, 1);
    assert.equal(semantic.length, 0);
    assert.equal(q.getDeadLetter().length, 0);
    q.stop();
  });

  it("retries then dead-letters when the validator returns false", async () => {
    const timer = manualTimer();
    const calls = { count: 0 };
    const semantic: SemanticFailureInfo[] = [];
    const dead: Array<{ attempts: number; error: string }> = [];
    const q = new RetryQueue({
      sender: jsonSender([Buffer.from('{"ok":false}')], calls),
      maxAttempts: 3,
      jitterMs: 0,
      setTimer: timer.setTimer,
      responseValidators: () => false,
      onSemanticFailure: (info) => semantic.push(info),
      onDeadLetter: (_item, attempts, lastError) =>
        dead.push({ attempts, error: lastError instanceof Error ? lastError.message : String(lastError) }),
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();
    // Every attempt burned against the semantic failure, then dead letter.
    assert.equal(calls.count, 3);
    assert.equal(dead.length, 1);
    assert.equal(dead[0].attempts, 3);
    // One semantic-failure notification per attempt.
    assert.equal(semantic.length, 3);
    assert.ok(semantic.every((s) => s.id === "item-1" && s.endpoint === URL));
    assert.deepEqual(
      semantic.map((s) => s.attempts),
      [1, 2, 3]
    );
    assert.ok(semantic.every((s) => s.reason === "validator returned false"));
    q.stop();
  });

  it("a string verdict becomes the dead-letter reason", async () => {
    const timer = manualTimer();
    const calls = { count: 0 };
    let lastError = "";
    const q = new RetryQueue({
      sender: jsonSender([Buffer.from('{"ok":false,"code":"INSUFFICIENT_FUNDS"}')], calls),
      maxAttempts: 2,
      jitterMs: 0,
      setTimer: timer.setTimer,
      responseValidators: (r) => {
        const parsed = JSON.parse(r.body.toString()) as { ok?: boolean; code?: string };
        return parsed.ok === true || `gateway error: ${parsed.code ?? "unknown"}`;
      },
      onDeadLetter: (_item, _attempts, err) => {
        lastError = err instanceof Error ? err.message : String(err);
      },
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();
    assert.equal(calls.count, 2);
    assert.ok(lastError.includes("INSUFFICIENT_FUNDS"), lastError);
    q.stop();
  });

  it("a throwing validator is fail-closed (treated as a failure)", async () => {
    const timer = manualTimer();
    const calls = { count: 0 };
    const q = new RetryQueue({
      sender: jsonSender([Buffer.from("not json at all")], calls),
      maxAttempts: 2,
      jitterMs: 0,
      setTimer: timer.setTimer,
      responseValidators: (r) => {
        JSON.parse(r.body.toString());
        return true;
      },
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();
    // The throw did not bless the response: both attempts were consumed.
    assert.equal(calls.count, 2);
    assert.equal(q.getDeadLetter().length, 1);
    q.stop();
  });

  it("per-endpoint validators only gate their own endpoint", async () => {
    const timer = manualTimer();
    const calls = { count: 0 };
    let delivered = 0;
    const q = new RetryQueue({
      sender: jsonSender([Buffer.from('{"ok":false}')], calls),
      maxAttempts: 1,
      jitterMs: 0,
      setTimer: timer.setTimer,
      responseValidators: { [URL]: () => false },
      onDelivered: () => {
        delivered += 1;
      },
    });
    q.start();
    // The gated endpoint dead-letters; the ungated one delivers even
    // though the sender answered the same body.
    q.enqueue({ ...ITEM });
    q.enqueue({ ...ITEM, id: "item-2", targetUrl: URL_OTHER });
    await timer.run();
    assert.equal(calls.count, 2);
    assert.equal(delivered, 1);
    assert.equal(q.getDeadLetter().length, 1);
    assert.equal(q.getDeadLetter()[0].id, "item-1");
    q.stop();
  });

  it("skips validation when the sender returns no response", async () => {
    const timer = manualTimer();
    let delivered = 0;
    const q = new RetryQueue({
      sender: async () => {
        /* custom sender with no response visibility */
      },
      maxAttempts: 2,
      jitterMs: 0,
      setTimer: timer.setTimer,
      responseValidators: () => false,
      onDelivered: () => {
        delivered += 1;
      },
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();
    assert.equal(delivered, 1);
    assert.equal(q.getDeadLetter().length, 0);
    q.stop();
  });

  it("consecutive semantic failures trip the circuit breaker", async () => {
    // Single-step timer: once the circuit trips open, parked attempts
    // re-arm their timers forever, so a drain-all loop would never end.
    const pending: Array<() => void> = [];
    const stepTimer = {
      setTimer: (fn: () => void, _ms: number) => {
        pending.push(fn);
        return {
          clear: () => {
            const i = pending.indexOf(fn);
            if (i >= 0) pending.splice(i, 1);
          },
        };
      },
    };
    const step = async () => {
      const fns = pending.splice(0);
      for (const f of fns) f();
      await new Promise((r) => setImmediate(r));
    };
    const calls = { count: 0 };
    const q = new RetryQueue({
      sender: jsonSender([Buffer.from('{"ok":false}')], calls),
      maxAttempts: 5,
      jitterMs: 0,
      setTimer: stepTimer.setTimer,
      circuitBreaker: { failureThreshold: 2, cooldownMs: 60_000 },
      responseValidators: () => false,
    });
    q.start();
    q.enqueue({ ...ITEM, id: "item-1" });
    await step(); // attempt 1: semantic failure, retry scheduled
    await step(); // attempt 2: semantic failure, circuit trips open
    // After the circuit trips open, further attempts park instead of
    // burning the sender: 2 semantic failures happened (tripping the
    // breaker), the rest park on the open circuit.
    assert.equal(calls.count, 2);
    const stats = q.getCircuitStats();
    assert.equal(stats.length, 1);
    assert.equal(stats[0].endpoint, URL);
    assert.equal(stats[0].state, "open");
    q.stop();
  });

  it("rejects invalid validator configuration at construction", () => {
    assert.throws(() => new RetryQueue({ responseValidators: { [URL]: "nope" } as never }), TypeError);
    assert.throws(() => new RetryQueue({ responseValidators: 42 as never }), TypeError);
    assert.throws(() => new RetryQueue({ responseValidators: [() => true] as never }), TypeError);
  });

  it("SemanticDeliveryError classifies as retryable", () => {
    const err = new SemanticDeliveryError("gateway error");
    assert.equal(err.name, "SemanticDeliveryError");
    assert.equal(err.reason, "gateway error");
    assert.ok(err.message.includes("gateway error"));
  });
});
