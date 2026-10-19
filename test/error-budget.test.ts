import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  ErrorBudgetMonitor,
  errorBudgetBurnAuditEvent,
  resolveErrorBudgetOptions,
  type BurnRateAlertInfo,
} from "../src/error-budget.ts";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";
import { signSha256 } from "../src/verify.ts";
import { request as httpRequest } from "node:http";

const URL = "http://127.0.0.1:9999/hook";

/** Steppable clock for deterministic windows. */
function clock() {
  let now = 0;
  return { now: () => now, advance: (ms: number) => (now += ms) };
}

function monitor(alerts: BurnRateAlertInfo[], c = clock(), extra = {}) {
  return {
    m: new ErrorBudgetMonitor({
      fastWindowMs: 3_600_000,
      slowWindowMs: 6 * 3_600_000,
      budgetErrorRate: 0.01,
      alertThreshold: 2,
      minEvents: 5,
      onBurnRateAlert: (info) => alerts.push(info),
      now: c.now,
      ...extra,
    }),
    c,
  };
}

describe("error-budget burn-rate alerting (WR-147)", () => {
  it("validation: RangeError on invalid options", () => {
    assert.throws(() => resolveErrorBudgetOptions({ fastWindowMs: 0 }), RangeError);
    assert.throws(() => resolveErrorBudgetOptions({ fastWindowMs: 1.5 }), RangeError);
    assert.throws(
      () => resolveErrorBudgetOptions({ fastWindowMs: 3_600_000, slowWindowMs: 3_600_000 }),
      RangeError
    );
    assert.throws(() => resolveErrorBudgetOptions({ budgetErrorRate: 0 }), RangeError);
    assert.throws(() => resolveErrorBudgetOptions({ budgetErrorRate: 1 }), RangeError);
    assert.throws(() => resolveErrorBudgetOptions({ alertThreshold: 0 }), RangeError);
    assert.throws(() => resolveErrorBudgetOptions({ minEvents: 0 }), RangeError);
    assert.doesNotThrow(() => resolveErrorBudgetOptions({}));
  });

  it("fast-window burn fires the alert, edge-triggered (sustained breach alerts once)", () => {
    const alerts: BurnRateAlertInfo[] = [];
    const { m } = monitor(alerts);
    for (let i = 0; i < 5; i++) m.recordOutcome(URL, false);
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0].endpoint, URL);
    // 5 failures / 5 outcomes = 100% error rate against a 1% budget.
    assert.equal(alerts[0].burnRate, 100);
    assert.equal(alerts[0].fastErrorRate, 1);
    assert.equal(alerts[0].budgetErrorRate, 0.01);
    assert.equal(m.isAlerting(URL), true);
    // Sustained breach: ten more failures, still exactly one alert.
    for (let i = 0; i < 10; i++) m.recordOutcome(URL, false);
    assert.equal(alerts.length, 1);
    assert.equal(m.isAlerting(URL), true);
  });

  it("slow window not burned: no alert", () => {
    const alerts: BurnRateAlertInfo[] = [];
    const { m, c } = monitor(alerts);
    // Slow window: 990 successes + 10 failures = 1% error rate = exactly
    // at budget (burn 1 <= threshold 2).
    for (let i = 0; i < 990; i++) m.recordOutcome(URL, true);
    for (let i = 0; i < 10; i++) m.recordOutcome(URL, false);
    c.advance(5 * 3_600_000 + 59 * 60_000); // still inside the 6h slow window
    // Fast window: 10 failures out of 10 = 100% (burn 100) — but the slow
    // window does not confirm: 20/1010 = 1.98% -> burn 1.98 <= 2.
    for (let i = 0; i < 10; i++) m.recordOutcome(URL, false);
    assert.equal(alerts.length, 0);
    assert.equal(m.isAlerting(URL), false);
  });

  it("minEvents gate: a lone failure is not a catastrophe", () => {
    const alerts: BurnRateAlertInfo[] = [];
    const { m } = monitor(alerts);
    m.recordOutcome(URL, true);
    m.recordOutcome(URL, false); // 50% error rate but only 2 outcomes < minEvents 5
    assert.equal(alerts.length, 0);
  });

  it("recovery re-arms: a new episode alerts again", () => {
    const alerts: BurnRateAlertInfo[] = [];
    const { m } = monitor(alerts);
    for (let i = 0; i < 5; i++) m.recordOutcome(URL, false);
    assert.equal(alerts.length, 1);
    // Recover: enough successes to drag both windows under the threshold
    // (5/255 = 1.96% -> burn 1.96 < 2).
    for (let i = 0; i < 250; i++) m.recordOutcome(URL, true);
    assert.equal(m.isAlerting(URL), false);
    // A fresh episode alerts again.
    for (let i = 0; i < 5; i++) m.recordOutcome(URL, false);
    assert.equal(alerts.length, 2);
    assert.equal(m.isAlerting(URL), true);
  });

  it("a throwing onBurnRateAlert never breaks the delivery path", () => {
    const c = clock();
    const m = new ErrorBudgetMonitor({
      fastWindowMs: 3_600_000,
      slowWindowMs: 6 * 3_600_000,
      budgetErrorRate: 0.01,
      alertThreshold: 2,
      minEvents: 5,
      now: c.now,
      onBurnRateAlert: () => {
        throw new Error("pager exploded");
      },
    });
    assert.doesNotThrow(() => {
      for (let i = 0; i < 5; i++) m.recordOutcome(URL, false);
    });
    // The monitor is still fully functional after the throw.
    assert.equal(m.isAlerting(URL), true);
    assert.doesNotThrow(() => m.recordOutcome(URL, true));
    assert.ok((m.burnRate(URL) ?? 0) > 0);
  });

  it("metrics gauge: activity-gated, tracks the fast-window burn rate", () => {
    const alerts: BurnRateAlertInfo[] = [];
    const { m, c } = monitor(alerts);
    assert.equal(m.render(), "");
    m.recordOutcome(URL, true);
    m.recordOutcome(URL, false); // 50% -> burn 50
    assert.match(
      m.render(),
      /relay_error_budget_burn_ratio\{endpoint="http:\/\/127\.0\.0\.1:9999\/hook"\} 50/
    );
    // Recovery drags the gauge back down.
    for (let i = 0; i < 198; i++) m.recordOutcome(URL, true); // 1/200 = 0.5% -> burn 0.5
    assert.match(m.render(), /relay_error_budget_burn_ratio\{endpoint="[^"]+"\} 0\.5/);
    // Fully-aged endpoints drop out of the gauge.
    c.advance(7 * 3_600_000);
    assert.equal(m.render(), "");
    assert.deepEqual(m.endpoints(), []);
  });

  it("errorBudgetBurnAuditEvent carries the full alert context", () => {
    const ev = errorBudgetBurnAuditEvent({
      endpoint: URL,
      burnRate: 100,
      fastErrorRate: 1,
      slowErrorRate: 0.5,
      slowBurnRate: 50,
      budgetErrorRate: 0.01,
      alertThreshold: 2,
      fastWindowMs: 3_600_000,
      slowWindowMs: 21_600_000,
    });
    assert.equal(ev.event, "error_budget_burn");
    assert.equal(ev.endpoint, URL);
    assert.equal(ev.burnRate, 100);
    assert.equal(ev.fastWindowMs, 3_600_000);
  });

  it("queue integration: failed attempts feed the monitor; delivery still proceeds", async () => {
    const alerts: BurnRateAlertInfo[] = [];
    let calls = 0;
    const sender: Sender = async () => {
      calls++;
      throw new Error("downstream down");
    };
    const pending: Array<() => void> = [];
    const timer = {
      setTimer: (fn: () => void, _ms: number) => {
        pending.push(fn);
        return { clear: () => {} };
      },
      async step() {
        const fns = pending.splice(0);
        for (const f of fns) f();
        await new Promise((r) => setImmediate(r));
      },
    };
    const q = new RetryQueue({
      sender,
      baseDelayMs: 10,
      maxAttempts: 5,
      maxDelayMs: 20,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
      errorBudget: {
        budgetErrorRate: 0.01,
        alertThreshold: 2,
        minEvents: 3,
        onBurnRateAlert: (info) => alerts.push(info),
      },
    });
    q.start();
    const item = (id: string) => ({
      id,
      targetUrl: URL,
      payload: Buffer.from("{}"),
      headers: {},
    });
    q.enqueue(item("a"));
    q.enqueue(item("b"));
    q.enqueue(item("c"));
    await timer.step(); // attempt 1 of each fails
    await timer.step(); // retries fire
    // Three+ failed attempts -> 100% error rate -> the alert fired, and
    // the queue kept working (retries were scheduled, not dropped).
    assert.ok(calls >= 3, `calls=${calls}`);
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0].endpoint, URL);
    assert.ok(pending.length > 0 || calls > 3);
    // Metrics gauge is live on the queue's monitor.
    assert.match(q.getErrorBudgetMonitor()?.render() ?? "", /relay_error_budget_burn_ratio/);
    await q.shutdown();
  });

  it("queue without errorBudget: no monitor, byte-identical behavior", async () => {
    const q = new RetryQueue({ sender: async () => {} });
    assert.equal(q.getErrorBudgetMonitor(), undefined);
    await q.shutdown();
  });

  it("invalid errorBudget config throws at queue construction", () => {
    assert.throws(
      () =>
        new RetryQueue({
          sender: async () => {},
          errorBudget: { alertThreshold: 0 },
        }),
      RangeError
    );
  });

  it("server wiring: alert audits error_budget_burn and forwards the hook", async () => {
    const dir = mkdtempSync(join(tmpdir(), "eb-audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const alerts: BurnRateAlertInfo[] = [];
    const secret = "relay-secret";
    const relay = createRelayServer({
      secret,
      forwardUrl: URL,
      auditLog: audit,
      sender: async () => {
        throw new Error("down");
      },
      retry: {
        baseDelayMs: 5,
        maxDelayMs: 10,
        maxAttempts: 2,
        jitterMs: 0,
        errorBudget: {
          budgetErrorRate: 0.01,
          alertThreshold: 2,
          minEvents: 2,
          onBurnRateAlert: (info) => alerts.push(info),
        },
      },
    });
    const port = await new Promise<number>((resolve) => {
      relay.listen(0, "127.0.0.1", () => {
        const addr = relay.address();
        assert.ok(addr && typeof addr === "object");
        resolve(addr.port);
      });
    });
    const post = (body: Buffer) =>
      new Promise<number>((resolve, reject) => {
        const r = httpRequest(
          {
            host: "127.0.0.1",
            port,
            path: "/",
            method: "POST",
            headers: { "x-signature": signSha256(body, secret), "content-type": "application/json" },
          },
          (res) => {
            res.resume();
            res.on("end", () => resolve(res.statusCode ?? 0));
          }
        );
        r.on("error", reject);
        r.end(body);
      });
    try {
      // Two failing deliveries -> the burn-rate alert fires.
      for (const id of ["w1", "w2"]) {
        const status = await post(Buffer.from(JSON.stringify({ id })));
        assert.equal(status, 202);
      }
      const deadline = Date.now() + 5000;
      let burns: Array<Record<string, unknown>> = [];
      while (Date.now() < deadline) {
        burns = (audit.readAll() as Array<Record<string, unknown>>).filter(
          (e) => e.event === "error_budget_burn"
        );
        if (burns.length > 0) break;
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(alerts.length, 1);
      assert.ok(alerts[0].burnRate > 2);
      assert.equal(burns.length, 1);
      assert.equal(burns[0].endpoint, URL);
      assert.ok((burns[0].burnRate as number) > 2);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });
});
