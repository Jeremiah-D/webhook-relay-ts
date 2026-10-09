import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  RetryBudget,
  DEFAULT_RETRY_BUDGET_PER_MINUTE,
  type RetryBudgetDepletedInfo,
  type Sender,
} from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

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

const ITEM = {
  id: "item-1",
  payload: Buffer.from("hello"),
  targetUrl: URL,
  headers: { "content-type": "application/json" },
};

describe("WR-38 RetryBudget (unit)", () => {
  it("allows takes within budget and reports time until the next token", () => {
    let now = 0;
    const b = new RetryBudget(2, () => now);
    assert.equal(b.limit(), 2);
    assert.ok(b.take());
    assert.ok(b.take());
    assert.equal(b.take(), false);
    // 2 tokens per 60s: a fresh token accrues every 30s.
    assert.equal(b.msUntilToken(), 30000);
    now = 30_000;
    assert.equal(b.msUntilToken(), 0);
    assert.ok(b.take());
    assert.equal(b.take(), false);
    // Clock regression never manufactures tokens.
    now = 0;
    assert.equal(b.msUntilToken(), 30000);
  });

  it("rejects illegal budgets", () => {
    for (const bad of [0, -1, NaN, Infinity, -Infinity]) {
      assert.throws(() => new RetryBudget(bad), RangeError, `budget ${bad}`);
    }
  });

  it("has a generous default budget", () => {
    assert.ok(DEFAULT_RETRY_BUDGET_PER_MINUTE >= 1000);
    const b = new RetryBudget();
    assert.equal(b.limit(), DEFAULT_RETRY_BUDGET_PER_MINUTE);
  });
});

describe("WR-38 global retry budget (queue)", () => {
  it("parks a retry when the budget is exhausted and resumes on refill", async () => {
    const timer = manualTimer();
    const now = { ms: 0 };
    const scheduledDelays: number[] = [];
    const depleted: RetryBudgetDepletedInfo[] = [];
    let senderCalls = 0;
    // Fail 3 times, then succeed: the 3rd failure's retry scheduling finds
    // the 2/min budget exhausted and parks instead of hammering on.
    const flaky: Sender = async () => {
      senderCalls += 1;
      if (senderCalls <= 3) throw new Error("downstream down");
    };
    let deliveredAttempts = 0;
    const q = new RetryQueue({
      sender: flaky,
      baseDelayMs: 100,
      maxDelayMs: 5000,
      maxAttempts: 5,
      jitterMs: 0,
      random: () => 0,
      setTimer: (fn, ms) => {
        scheduledDelays.push(ms);
        return timer.setTimer(fn, ms);
      },
      retryBudget: { retriesPerMinute: 2, now: () => now.ms },
      onRetryBudgetDepleted: (info) => depleted.push(info),
      onDelivered: (_item, attempts) => {
        deliveredAttempts = attempts;
      },
    });
    q.start();
    q.enqueue({ ...ITEM });
    // The manual clock stays at 0 (no refill mid-test), so the 3rd retry
    // scheduling parks; the parked timer then fires and attempt 4
    // succeeds, ending the run — no infinite loop.
    await timer.run();
    // 4 genuine attempts: 3 failures + 1 success. Parking consumed no
    // extra attempt.
    assert.equal(senderCalls, 4);
    assert.equal(deliveredAttempts, 4);
    assert.equal(depleted.length, 1);
    assert.equal(depleted[0].id, "item-1");
    assert.equal(depleted[0].endpoint, URL);
    assert.equal(depleted[0].attempts, 3);
    assert.equal(depleted[0].waitMs, 30000);
    // Scheduled delays: 0 (initial), 200, 400 (backoff), 30000 (parked).
    assert.deepEqual(scheduledDelays, [0, 200, 400, 30000]);
    assert.deepEqual(q.getRetryBudgetStats(), { retriesPerMinute: 2, depleted: 1 });
    // The depletion counter reaches the Prometheus exposition.
    assert.ok(q.renderMetrics().includes("relay_retry_budget_depleted_total 1"));
    q.stop();
  });

  it("parking neither consumes attempts nor touches the circuit breaker", async () => {
    const timer = manualTimer();
    let senderCalls = 0;
    const alwaysFail: Sender = async () => {
      senderCalls += 1;
      throw new Error("downstream down");
    };
    const q = new RetryQueue({
      sender: alwaysFail,
      baseDelayMs: 100,
      maxDelayMs: 5000,
      maxAttempts: 4,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      circuitBreaker: { failureThreshold: 100, cooldownMs: 60_000 },
      retryBudget: { retriesPerMinute: 2 },
    });
    q.start();
    q.enqueue({ ...ITEM });
    await timer.run();
    // Attempts: 3 genuine failures (2 budgeted retries + 1 parked retry),
    // then the 4th attempt exhausts maxAttempts → dead letter.
    assert.equal(senderCalls, 4);
    const dead = q.getDeadLetter();
    assert.equal(dead.length, 1);
    assert.equal(dead[0].attempts, 4);
    // The circuit saw exactly the 4 genuine failures: the parking itself
    // recorded nothing.
    const stats = q.getCircuitStats();
    assert.equal(stats.length, 1);
    assert.equal(stats[0].consecutiveFailures, 4);
    assert.equal(q.getRetryBudgetStats()?.depleted, 1);
    q.stop();
  });

  it("disabled by default: no budget, no metric, no parking", () => {
    const q = new RetryQueue({});
    assert.equal(q.getRetryBudgetStats(), undefined);
    assert.ok(!q.renderMetrics().includes("relay_retry_budget_depleted_total"));
    q.stop();
  });

  it("rejects an illegal budget at construction", () => {
    assert.throws(() => new RetryQueue({ retryBudget: { retriesPerMinute: 0 } }), RangeError);
    assert.throws(() => new RetryQueue({ retryBudget: { retriesPerMinute: -5 } }), RangeError);
  });
});

const SECRET = "budget-secret";
const BODY = Buffer.from(JSON.stringify({ order: "ord_9", amount: 100 }));

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

async function close(server: Server): Promise<void> {
  server.close();
  await new Promise((r) => server.once("close", r));
}

function post(port: number, body: Buffer, headers: Record<string, string> = {}) {
  return new Promise<{ status: number }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path: "/", method: "POST", headers },
      (res) => {
        res.resume();
        res.on("end", () => resolve({ status: res.statusCode ?? 0 }));
      }
    );
    r.on("error", reject);
    r.end(body);
  });
}

async function waitFor(cond: () => boolean, timeoutMs: number, what: string): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond() && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.ok(cond(), `timed out waiting for: ${what}`);
}

/** Downstream stub answering 200 with a body that carries a semantic error marker. */
function semanticErrorStub() {
  const hits: number[] = [];
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      hits.push(Date.now());
      res.writeHead(200, { "content-type": "application/json" }).end('{"ok":false,"code":"E_DECLINED"}');
    });
  });
  return { server, hits };
}

/** Downstream stub that always 500s. */
function alwaysFailingStub() {
  const hits: number[] = [];
  const server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      hits.push(Date.now());
      res.writeHead(500).end("boom");
    });
  });
  return { server, hits };
}

describe("WR-37/WR-38 server audit integration", () => {
  it("audits semantic failures as failed/semantic_failed end to end", async () => {
    const { server: stub, hits } = semanticErrorStub();
    const stubPort = await listen(stub);
    const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "wr37-")), "audit.jsonl"));
    // Real HTTP sender: proves the default sender captures the body for
    // the validator.
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: {
        baseDelayMs: 50,
        maxDelayMs: 500,
        maxAttempts: 2,
        jitterMs: 0,
        responseValidators: (r) => {
          const parsed = JSON.parse(r.body.toString()) as { ok?: boolean };
          return parsed.ok === true || "gateway said no";
        },
      },
    });
    const relayPort = await listen(relay);
    try {
      const res = await post(relayPort, BODY, {
        "x-signature": signSha256(BODY, SECRET),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
      await waitFor(() => hits.length >= 2, 15000, "2 downstream attempts");
      await waitFor(
        () =>
          audit.query({ event: "failed" }).filter((e) => (e as { reason?: string }).reason === "semantic_failed")
            .length >= 2,
        5000,
        "semantic_failed audit entries"
      );
      const failed = audit.query({ event: "failed" }) as Array<{
        reason: string;
        semanticReason: string;
        attempts: number;
      }>;
      assert.equal(failed.length, 2);
      assert.ok(failed.every((f) => f.reason === "semantic_failed"));
      assert.ok(failed.every((f) => f.semanticReason === "gateway said no"));
      // Both attempts failed semantically → dead letter, never "delivered".
      await waitFor(() => audit.query({ event: "dead_letter" }).length > 0, 5000, "dead_letter audit entry");
      assert.equal(audit.query({ event: "delivered" }).length, 0);
    } finally {
      await close(relay);
      await close(stub);
    }
  });

  it("audits retry_budget_depleted when the global budget is exhausted", async () => {
    const { server: stub, hits } = alwaysFailingStub();
    const stubPort = await listen(stub);
    const audit = new AuditLog(join(mkdtempSync(join(tmpdir(), "wr38-")), "audit.jsonl"));
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: {
        baseDelayMs: 50,
        maxDelayMs: 500,
        maxAttempts: 5,
        jitterMs: 0,
        retryBudget: { retriesPerMinute: 1 },
      },
    });
    const relayPort = await listen(relay);
    try {
      const res = await post(relayPort, BODY, {
        "x-signature": signSha256(BODY, SECRET),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
      // Attempt 1 fails → retry scheduled (budget take OK). Attempt 2
      // fails → budget exhausted → parked, audited as retry_budget_depleted.
      await waitFor(() => hits.length >= 2, 15000, "2 downstream attempts");
      await waitFor(
        () => audit.query({ event: "retry_budget_depleted" }).length > 0,
        5000,
        "retry_budget_depleted audit entry"
      );
      const events = audit.query({ event: "retry_budget_depleted" }) as Array<{
        targetUrl: string;
        attempts: number;
        waitMs: number;
      }>;
      assert.equal(events.length, 1);
      assert.ok(events[0].targetUrl.includes("127.0.0.1"));
      assert.equal(events[0].attempts, 2);
      assert.ok(events[0].waitMs >= 59000, `parked wait too short: ${events[0].waitMs}`);
      // The item was parked, not dropped or dead-lettered: nothing settled yet.
      assert.equal(audit.query({ event: "dead_letter" }).length, 0);
      assert.equal(audit.query({ event: "delivered" }).length, 0);
    } finally {
      await close(relay);
      await close(stub);
    }
  });
});
