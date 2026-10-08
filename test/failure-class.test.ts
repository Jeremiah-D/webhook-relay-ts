import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  type DeliveryEvent,
  type FailureClass,
  type Sender,
} from "../src/retry.ts";
import {
  HttpDeliveryError,
  classifyFailure,
  parseRetryAfterMs,
} from "../src/failure.ts";
import { createDefaultSender, createRelayServer } from "../src/server.ts";
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

const SECRET = "relay-secret";

const ITEM = {
  id: "item-1",
  payload: Buffer.from("hello"),
  targetUrl: "http://localhost:9999/hook",
  headers: { "content-type": "application/json" },
};

describe("classifyFailure", () => {
  it("treats 4xx (except 408/429) as non-retryable", () => {
    for (const status of [400, 401, 403, 404, 409, 413, 422, 499]) {
      const c = classifyFailure(new HttpDeliveryError(status));
      assert.equal(c.failureClass, "non_retryable", `status ${status}`);
      assert.equal(c.statusCode, status);
    }
  });

  it("treats 408, 429, 5xx and transport errors as retryable", () => {
    for (const status of [408, 429, 500, 502, 503, 504]) {
      const c = classifyFailure(new HttpDeliveryError(status));
      assert.equal(c.failureClass, "retryable", `status ${status}`);
    }
    assert.equal(classifyFailure(new Error("socket hang up")).failureClass, "retryable");
    assert.equal(classifyFailure(new Error("getaddrinfo ENOTFOUND x")).failureClass, "retryable");
    assert.equal(classifyFailure("a bare string").failureClass, "retryable");
    assert.equal(classifyFailure(undefined).failureClass, "retryable");
  });

  it("duck-types statusCode so custom senders need no import", () => {
    const err = new Error("custom 400") as Error & { statusCode: number };
    err.statusCode = 400;
    assert.equal(classifyFailure(err).failureClass, "non_retryable");
  });

  it("carries retryAfterMs through for retryable failures", () => {
    const c = classifyFailure(new HttpDeliveryError(429, 5000));
    assert.equal(c.failureClass, "retryable");
    assert.equal(c.retryAfterMs, 5000);
  });
});

describe("parseRetryAfterMs", () => {
  it("parses delay-seconds", () => {
    assert.equal(parseRetryAfterMs("120"), 120_000);
    assert.equal(parseRetryAfterMs("0"), 0);
    assert.equal(parseRetryAfterMs(["45"]), 45_000);
  });

  it("parses HTTP-dates relative to the clock", () => {
    const now = Date.now();
    const future = new Date(now + 30_000).toUTCString();
    const ms = parseRetryAfterMs(future, () => now);
    assert.ok(ms !== undefined && Math.abs(ms - 30_000) < 1500, `got ${ms}`);
  });

  it("returns undefined for missing, past, or garbage values", () => {
    assert.equal(parseRetryAfterMs(undefined), undefined);
    assert.equal(parseRetryAfterMs(""), undefined);
    assert.equal(parseRetryAfterMs("soon"), undefined);
    assert.equal(parseRetryAfterMs("1.5"), undefined);
    const past = new Date(Date.now() - 60_000).toUTCString();
    assert.equal(parseRetryAfterMs(past), undefined);
  });
});

describe("failure classification in the retry queue", () => {
  it("dead-letters a 400 immediately without burning the retry budget", async () => {
    const timer = manualTimer();
    const delays: number[] = [];
    const realSetTimer = timer.setTimer;
    let attempts = 0;
    const events: DeliveryEvent[] = [];
    const deadClasses: Array<FailureClass | undefined> = [];
    const q = new RetryQueue({
      sender: async () => {
        attempts += 1;
        throw new HttpDeliveryError(400);
      },
      baseDelayMs: 10,
      maxDelayMs: 100,
      maxAttempts: 5,
      jitterMs: 0,
      circuitBreaker: { failureThreshold: 2 },
      setTimer: (fn, ms) => {
        delays.push(ms);
        return realSetTimer(fn, ms);
      },
      onDeadLetter: (_item, _n, _err, failureClass) => deadClasses.push(failureClass),
    });
    q.subscribeDeliveryEvents((e) => events.push(e));
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();
    // One attempt, then straight to dead letter — no backoff waits.
    assert.equal(attempts, 1);
    assert.deepEqual(delays, [0]);
    assert.equal(events.filter((e) => e.type === "retrying").length, 0);
    assert.equal(events.filter((e) => e.type === "dead_letter").length, 1);
    const dead = q.getDeadLetter();
    assert.equal(dead.length, 1);
    assert.equal(dead[0].failureClass, "non_retryable");
    assert.equal(dead[0].attempts, 1);
    assert.deepEqual(deadClasses, ["non_retryable"]);
    // The endpoint answered (it just said no): the circuit must not trip
    // on a poison payload.
    const stats = q.getCircuitStats();
    assert.equal(stats.length, 1);
    assert.equal(stats[0].consecutiveFailures, 0);
    assert.equal(stats[0].state, "closed");
    q.stop();
  });

  it("classifies a duck-typed 422 as non-retryable too", async () => {
    const timer = manualTimer();
    let attempts = 0;
    const q = new RetryQueue({
      sender: async () => {
        attempts += 1;
        const err = new Error("custom 422") as Error & { statusCode: number };
        err.statusCode = 422;
        throw err;
      },
      maxAttempts: 5,
      jitterMs: 0,
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();
    assert.equal(attempts, 1);
    assert.equal(q.getDeadLetter()[0].failureClass, "non_retryable");
    q.stop();
  });

  it("honors a 429 Retry-After instead of the backoff", async () => {
    const timer = manualTimer();
    const delays: number[] = [];
    const realSetTimer = timer.setTimer;
    let attempts = 0;
    const q = new RetryQueue({
      sender: async () => {
        attempts += 1;
        if (attempts === 1) throw new HttpDeliveryError(429, 250);
      },
      baseDelayMs: 10,
      maxDelayMs: 1000,
      maxAttempts: 3,
      jitterMs: 0,
      setTimer: (fn, ms) => {
        delays.push(ms);
        return realSetTimer(fn, ms);
      },
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();
    assert.equal(attempts, 2);
    assert.deepEqual(delays, [0, 250]);
    assert.equal(q.getDeadLetter().length, 0);
    q.stop();
  });

  it("honors Retry-After on the urgent lane too", async () => {
    const timer = manualTimer();
    const delays: number[] = [];
    const realSetTimer = timer.setTimer;
    let attempts = 0;
    const q = new RetryQueue({
      sender: async () => {
        attempts += 1;
        if (attempts === 1) throw new HttpDeliveryError(429, 250);
      },
      maxAttempts: 3,
      jitterMs: 0,
      urgent: { retryDelayMs: 5, maxUrgentPerSecond: 1000 },
      setTimer: (fn, ms) => {
        delays.push(ms);
        return realSetTimer(fn, ms);
      },
    });
    q.start();
    q.enqueue({ ...ITEM, priority: "urgent" as const });
    await timer.run();
    assert.equal(attempts, 2);
    // The downstream's explicit wait wins over the 5ms fast-lane delay.
    assert.deepEqual(delays, [0, 250]);
    q.stop();
  });

  it("dead-letters exhausted transient failures as retryable", async () => {
    const timer = manualTimer();
    let attempts = 0;
    const q = new RetryQueue({
      sender: async () => {
        attempts += 1;
        throw new HttpDeliveryError(503);
      },
      baseDelayMs: 10,
      maxAttempts: 3,
      jitterMs: 0,
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();
    assert.equal(attempts, 3);
    const dead = q.getDeadLetter();
    assert.equal(dead.length, 1);
    assert.equal(dead[0].failureClass, "retryable");
    assert.equal(dead[0].attempts, 3);
    q.stop();
  });

  it("keeps retrying plain transport errors with backoff", async () => {
    const timer = manualTimer();
    let attempts = 0;
    const flaky: Sender = async () => {
      attempts += 1;
      if (attempts < 3) throw new Error("socket hang up");
    };
    const q = new RetryQueue({
      sender: flaky,
      baseDelayMs: 10,
      maxAttempts: 5,
      jitterMs: 0,
      setTimer: timer.setTimer,
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();
    assert.equal(attempts, 3);
    assert.equal(q.getDeadLetter().length, 0);
    q.stop();
  });
});

describe("default sender failure structure", () => {
  async function withStub(
    handler: (req: IncomingMessage, res: ServerResponse) => void,
    fn: (port: number) => Promise<void>
  ) {
    const stub: Server = createServer(handler);
    await new Promise<void>((r) => stub.listen(0, "127.0.0.1", r));
    const port = (stub.address() as AddressInfo).port;
    try {
      await fn(port);
    } finally {
      stub.close();
      await new Promise((r) => stub.once("close", r));
    }
  }

  it("rejects a 400 with HttpDeliveryError carrying the status", async () => {
    await withStub(
      (_req, res) => {
        res.statusCode = 400;
        res.end("bad payload");
      },
      async (port) => {
        const sender = createDefaultSender();
        try {
          await sender({
            id: "x",
            payload: Buffer.from("x"),
            targetUrl: `http://127.0.0.1:${port}/hook`,
            headers: {},
          });
          assert.fail("expected the sender to reject");
        } catch (err) {
          assert.ok(err instanceof HttpDeliveryError);
          assert.equal(err.statusCode, 400);
          assert.equal(err.message, "Forward failed with status 400");
          assert.equal(err.retryAfterMs, undefined);
          assert.equal(classifyFailure(err).failureClass, "non_retryable");
        } finally {
          sender.destroy();
        }
      }
    );
  });

  it("parses Retry-After on a 429 into retryAfterMs", async () => {
    await withStub(
      (_req, res) => {
        res.statusCode = 429;
        res.setHeader("retry-after", "2");
        res.end("slow down");
      },
      async (port) => {
        const sender = createDefaultSender();
        try {
          await sender({
            id: "x",
            payload: Buffer.from("x"),
            targetUrl: `http://127.0.0.1:${port}/hook`,
            headers: {},
          });
          assert.fail("expected the sender to reject");
        } catch (err) {
          assert.ok(err instanceof HttpDeliveryError);
          assert.equal(err.statusCode, 429);
          assert.equal(err.retryAfterMs, 2000);
          assert.equal(classifyFailure(err).failureClass, "retryable");
        } finally {
          sender.destroy();
        }
      }
    );
  });
});

describe("dead-letter audit carries failure_class", () => {
  it("audits a poison 400 as failure_class=non_retryable", async () => {
    const stub: Server = createServer((_req, res) => {
      res.statusCode = 400;
      res.end("bad payload");
    });
    await new Promise<void>((r) => stub.listen(0, "127.0.0.1", r));
    const stubPort = (stub.address() as AddressInfo).port;
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 5 },
      operatorToken: "op-secret",
    });
    await new Promise<void>((r) => relay.listen(0, "127.0.0.1", r));
    const port = (relay.address() as AddressInfo).port;
    try {
      const body = Buffer.from(JSON.stringify({ order: "ord_1" }));
      const res = await new Promise<number>((resolve, reject) => {
        const r = httpRequest(
          {
            host: "127.0.0.1",
            port,
            path: "/",
            method: "POST",
            headers: { "x-signature": signSha256(body, SECRET) },
          },
          (resp) => {
            resp.resume();
            resp.on("end", () => resolve(resp.statusCode ?? 0));
          }
        );
        r.on("error", reject);
        r.end(body);
      });
      assert.equal(res, 202);
      const deadline = Date.now() + 5000;
      let found: Record<string, unknown> | undefined;
      while (Date.now() < deadline) {
        const events = audit.readAll() as Array<Record<string, unknown>>;
        found = events.find((e) => e.event === "dead_letter");
        if (found) break;
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.ok(found, "expected a dead_letter audit event");
      assert.equal(found.failure_class, "non_retryable");
      assert.equal(found.attempts, 1);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
      stub.close();
      await new Promise((r) => stub.once("close", r));
    }
  });
});
