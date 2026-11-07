import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import type { Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ErrorBudgetMonitor, type BurnRateAlertInfo } from "../src/error-budget.ts";
import { RetryQueue } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "error-budget-revision-test-key";
const opToken = "error-budget-revision-op-token";
const URL_A = "http://localhost:9999/a";
const EP_A = "http://a.example/hook";

const MUST_RESTART =
  "reviseErrorBudget: error budget is not configured — enabling it requires a restart";

/** Steppable clock for deterministic windows. */
function clock() {
  let now = 1_000_000;
  return { now: () => now, advance: (ms: number) => (now += ms) };
}

const HOUR = 3_600_000;

function monitor(
  alerts: BurnRateAlertInfo[],
  c = clock(),
  extra: Record<string, unknown> = {}
) {
  return {
    m: new ErrorBudgetMonitor({
      fastWindowMs: HOUR,
      slowWindowMs: 6 * HOUR,
      budgetErrorRate: 0.01,
      alertThreshold: 2,
      minEvents: 2,
      onBurnRateAlert: (info) => alerts.push(info),
      now: c.now,
      ...extra,
    }),
    c,
  };
}

describe("ErrorBudgetMonitor.retune (WR-346)", () => {
  it("fastWindowMs shrink slides old samples out of the fast window sooner", () => {
    const alerts: BurnRateAlertInfo[] = [];
    const { m, c } = monitor(alerts);
    for (let i = 0; i < 9; i++) m.recordOutcome(EP_A, true);
    m.recordOutcome(EP_A, false); // 10% error -> burn 10 (seed successes first: a lone early failure would trip the alert mid-seed)
    assert.equal(m.burnRate(EP_A), 10);
    c.advance(30 * 60_000);
    assert.equal(m.burnRate(EP_A), 10, "still inside the 1h fast window");
    assert.deepEqual(m.retune({ fastWindowMs: 10 * 60_000 }), {
      fastWindowMs: 10 * 60_000,
      slowWindowMs: 6 * HOUR,
      budgetErrorRate: 0.01,
      alertThreshold: 2,
      minEvents: 2,
    });
    // The t=0 outcomes are 30 minutes old — outside the tightened
    // 10-minute fast window, so there is no fast-window rate at all.
    assert.equal(m.burnRate(EP_A), undefined);
    assert.equal(m.config().fastWindowMs, 10 * 60_000);
  });

  it("slowWindowMs tighten prunes older samples on the next record", () => {
    const alerts: BurnRateAlertInfo[] = [];
    const { m, c } = monitor(alerts);
    // Seed successes first: a lone early failure would trip the alert
    // mid-seed (50% error on two outcomes burns at 50).
    for (let i = 0; i < 99; i++) m.recordOutcome(EP_A, true);
    m.recordOutcome(EP_A, false); // 1% error
    c.advance(5 * HOUR);
    // One more failure: fast window burns at 100, but the slow window
    // still holds the 99 old successes (2/101 = 1.98% -> burn 1.98),
    // so no alert yet.
    m.recordOutcome(EP_A, false);
    assert.equal(alerts.length, 0);
    // Tighten the slow window to 2h: the retune itself evaluates
    // nothing — no alert fires here.
    m.retune({ slowWindowMs: 2 * HOUR });
    assert.equal(alerts.length, 0, "retune must not open an episode early");
    // The next record prunes to the new cutoff (now - 2h): the t=0
    // outcomes are gone, so the slow window is 100% errors.
    m.recordOutcome(EP_A, false);
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0].slowErrorRate, 1, "old successes were pruned");
    assert.equal(alerts[0].fastErrorRate, 1);
  });

  it("slowWindowMs widen never resurrects pruned samples", () => {
    const alerts: BurnRateAlertInfo[] = [];
    const { m, c } = monitor(alerts, clock(), { slowWindowMs: 2 * HOUR });
    // Seed successes first (see the test above for why).
    for (let i = 0; i < 99; i++) m.recordOutcome(EP_A, true);
    m.recordOutcome(EP_A, false); // 1% error
    c.advance(3 * HOUR);
    // This record prunes the t=0 outcomes (past the 2h slow window).
    m.recordOutcome(EP_A, true);
    assert.equal(alerts.length, 0);
    // Widen the slow window to 6h — the pruned outcomes stay pruned.
    m.retune({ slowWindowMs: 6 * HOUR });
    m.recordOutcome(EP_A, false);
    // Only the two 3h outcomes remain: 50% error in both windows.
    assert.equal(alerts.length, 1, "resurrected samples would keep the slow burn under 2");
    assert.equal(alerts[0].slowErrorRate, 0.5);
  });

  it("budgetErrorRate tighten is followed by the gauge and triggers sooner at the same error rate", () => {
    const alerts: BurnRateAlertInfo[] = [];
    const { m } = monitor(alerts);
    // Seed successes first (see the slow-tighten test for why).
    for (let i = 0; i < 99; i++) m.recordOutcome(EP_A, true);
    m.recordOutcome(EP_A, false); // 1% error
    assert.equal(m.burnRate(EP_A), 1);
    assert.match(m.render(), /relay_error_budget_burn_ratio\{endpoint="[^"]+"\} 1\n?$/);
    assert.deepEqual(m.retune({ budgetErrorRate: 0.005 }), {
      fastWindowMs: HOUR,
      slowWindowMs: 6 * HOUR,
      budgetErrorRate: 0.005,
      alertThreshold: 2,
      minEvents: 2,
    });
    // Same outcomes, halved budget: the gauge doubles on next render.
    assert.equal(m.burnRate(EP_A), 2);
    assert.match(m.render(), /relay_error_budget_burn_ratio\{endpoint="[^"]+"\} 2\n?$/);
    // One more failure (1.98% error) now burns at ~3.96 — past the
    // threshold; under the old 1% budget it would burn at 1.98 and
    // stay silent.
    m.recordOutcome(EP_A, false);
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0].budgetErrorRate, 0.005);
    assert.ok(alerts[0].burnRate > 2);
  });

  it("alertThreshold lowered opens an episode on the next outcome, not at retune time", () => {
    const alerts: BurnRateAlertInfo[] = [];
    const { m } = monitor(alerts, clock(), { alertThreshold: 10 });
    // Seed successes first (see the slow-tighten test for why).
    for (let i = 0; i < 19; i++) m.recordOutcome(EP_A, true);
    m.recordOutcome(EP_A, false); // 5% error -> burn 5 < 10
    assert.equal(alerts.length, 0);
    m.retune({ alertThreshold: 2 });
    assert.equal(alerts.length, 0, "retune must not open an episode early");
    m.recordOutcome(EP_A, true); // 1/21 = 4.76% -> burn 4.76 > 2
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0].alertThreshold, 2);
    assert.equal(m.isAlerting(EP_A), true);
  });

  it("rejects illegal values and leaves the live config untouched", () => {
    const alerts: BurnRateAlertInfo[] = [];
    const { m } = monitor(alerts, clock(), { minEvents: 10 });
    const live = {
      fastWindowMs: HOUR,
      slowWindowMs: 6 * HOUR,
      budgetErrorRate: 0.01,
      alertThreshold: 2,
      minEvents: 10,
    };
    const bad: Array<Record<string, unknown>> = [
      { fastWindowMs: 0 },
      { fastWindowMs: -1 },
      { fastWindowMs: 1.5 },
      { slowWindowMs: HOUR }, // == fastWindowMs: cross-gate
      { slowWindowMs: 1000 }, // < fastWindowMs: cross-gate
      { fastWindowMs: 7 * HOUR }, // > slowWindowMs: cross-gate
      { budgetErrorRate: 0 },
      { budgetErrorRate: 1 },
      { alertThreshold: 0 },
      { minEvents: 0 },
      { minEvents: 1.5 },
    ];
    for (const patch of bad) {
      assert.throws(() => m.retune(patch as never), RangeError);
    }
    assert.deepEqual(m.config(), live);
    // The live monitor still runs on the old values: 1% error burns 1.
    // (Seed successes first: a lone early failure would trip the alert
    // mid-seed.)
    for (let i = 0; i < 99; i++) m.recordOutcome(EP_A, true);
    m.recordOutcome(EP_A, false);
    assert.equal(m.burnRate(EP_A), 1);
    assert.equal(alerts.length, 0);
  });

  it("rejects an empty patch and non-object patches", () => {
    const alerts: BurnRateAlertInfo[] = [];
    const { m } = monitor(alerts);
    assert.throws(() => m.retune({}), RangeError);
    for (const bad of [null, [], "2", 2, undefined]) {
      assert.throws(() => m.retune(bad as never), RangeError);
    }
    assert.deepEqual(m.config(), {
      fastWindowMs: HOUR,
      slowWindowMs: 6 * HOUR,
      budgetErrorRate: 0.01,
      alertThreshold: 2,
      minEvents: 2,
    });
  });

  it("same-value patch is a no-op; config() is a snapshot", () => {
    const alerts: BurnRateAlertInfo[] = [];
    const { m } = monitor(alerts);
    assert.deepEqual(m.retune({ alertThreshold: 2 }), {
      fastWindowMs: HOUR,
      slowWindowMs: 6 * HOUR,
      budgetErrorRate: 0.01,
      alertThreshold: 2,
      minEvents: 2,
    });
    const snap = m.config();
    snap.minEvents = 999;
    snap.budgetErrorRate = 0.5;
    assert.deepEqual(m.config(), {
      fastWindowMs: HOUR,
      slowWindowMs: 6 * HOUR,
      budgetErrorRate: 0.01,
      alertThreshold: 2,
      minEvents: 2,
    });
    assert.deepEqual(m.retune({ fastWindowMs: HOUR, minEvents: 2 }), {
      fastWindowMs: HOUR,
      slowWindowMs: 6 * HOUR,
      budgetErrorRate: 0.01,
      alertThreshold: 2,
      minEvents: 2,
    });
  });

  it("an open episode's latch is untouched by retune and re-evaluates on the next outcome", () => {
    const alerts: BurnRateAlertInfo[] = [];
    const { m } = monitor(alerts);
    m.recordOutcome(EP_A, false);
    m.recordOutcome(EP_A, false);
    assert.equal(alerts.length, 1);
    assert.equal(m.isAlerting(EP_A), true);
    // Raising the threshold must not close the open episode early.
    m.retune({ alertThreshold: 100 });
    assert.equal(m.isAlerting(EP_A), true, "latch untouched by retune");
    assert.equal(alerts.length, 1);
    // The next outcome re-evaluates under the new threshold: 2/3
    // errors burn at ~66.7, under 100, so the episode closes.
    m.recordOutcome(EP_A, true);
    assert.equal(m.isAlerting(EP_A), false);
    assert.equal(alerts.length, 1);
    // Lowering the threshold again re-opens on the next outcome.
    m.retune({ alertThreshold: 2 });
    assert.equal(alerts.length, 1, "retune alone opens nothing");
    m.recordOutcome(EP_A, false);
    assert.equal(alerts.length, 2);
    assert.equal(m.isAlerting(EP_A), true);
  });

  it("onBurnRateAlert and now survive a retune unchanged", () => {
    const alerts: BurnRateAlertInfo[] = [];
    const { m, c } = monitor(alerts);
    // Seed successes first: a lone early failure would trip the alert
    // mid-seed.
    for (let i = 0; i < 99; i++) m.recordOutcome(EP_A, true);
    m.recordOutcome(EP_A, false); // 1% error -> burn 1
    assert.equal(m.burnRate(EP_A), 1);
    m.retune({ budgetErrorRate: 0.02 });
    assert.equal(m.burnRate(EP_A), 0.5);
    // The injected clock still drives the windows: 30 minutes later
    // the outcomes are still inside the 1h fast window. (With the
    // default Date.now clock the epoch-0 outcomes would be long gone.)
    c.advance(30 * 60_000);
    assert.equal(m.burnRate(EP_A), 0.5, "the injected clock must survive the retune");
    // The original callback still receives the alert: five more
    // failures push the error rate to ~5.8%, burning at ~2.9.
    for (let i = 0; i < 5; i++) m.recordOutcome(EP_A, false);
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0].budgetErrorRate, 0.02);
    assert.equal(alerts[0].endpoint, EP_A);
  });
});

describe("RetryQueue.reviseErrorBudget (WR-346)", () => {
  it("revision follows the live monitor", async () => {
    const c = clock();
    const q = new RetryQueue({
      sender: async () => {},
      errorBudget: {
        fastWindowMs: HOUR,
        slowWindowMs: 6 * HOUR,
        budgetErrorRate: 0.01,
        alertThreshold: 2,
        minEvents: 2,
        now: c.now,
      },
    });
    try {
      assert.deepEqual(q.getErrorBudgetConfig(), {
        fastWindowMs: HOUR,
        slowWindowMs: 6 * HOUR,
        budgetErrorRate: 0.01,
        alertThreshold: 2,
        minEvents: 2,
      });
      const mon = q.getErrorBudgetMonitor()!;
      // Seed successes first: a lone early failure would trip the alert
      // mid-seed.
      for (let i = 0; i < 99; i++) mon.recordOutcome(EP_A, true);
      mon.recordOutcome(EP_A, false);
      assert.equal(mon.burnRate(EP_A), 1);
      assert.deepEqual(q.reviseErrorBudget({ budgetErrorRate: 0.005 }), {
        fastWindowMs: HOUR,
        slowWindowMs: 6 * HOUR,
        budgetErrorRate: 0.005,
        alertThreshold: 2,
        minEvents: 2,
      });
      assert.equal(mon.burnRate(EP_A), 2, "queue revision moves the live monitor");
      assert.deepEqual(q.getErrorBudgetConfig(), {
        fastWindowMs: HOUR,
        slowWindowMs: 6 * HOUR,
        budgetErrorRate: 0.005,
        alertThreshold: 2,
        minEvents: 2,
      });
      assert.throws(() => q.reviseErrorBudget({ slowWindowMs: HOUR }), RangeError);
      assert.equal(q.getErrorBudgetConfig()?.slowWindowMs, 6 * HOUR);
    } finally {
      await q.shutdown();
    }
  });

  it("unconfigured queue throws must-restart and the getter returns undefined", async () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      assert.equal(q.getErrorBudgetConfig(), undefined);
      assert.throws(() => q.reviseErrorBudget({ alertThreshold: 1.5 }), {
        name: "Error",
        message: MUST_RESTART,
      });
    } finally {
      await q.shutdown();
    }
  });
});

describe("RelayServer error-budget revision (WR-346)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function listen(server: Server): Promise<number> {
    return new Promise<number>((resolve) => {
      server.listen(0, "127.0.0.1", () => {
        const addr = server.address();
        assert.ok(addr && typeof addr === "object");
        resolve(addr.port);
      });
    });
  }

  function makeRelay(errorBudget?: Record<string, unknown>) {
    const dir = mkdtempSync(join(tmpdir(), "error-budget-revision-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: signingKey,
      forwardUrl: URL_A,
      auditLog: audit,
      operatorToken: opToken,
      sender: async () => ({ statusCode: 200, body: Buffer.from("ok") }),
      retry: {
        baseDelayMs: 5,
        jitterMs: 0,
        maxAttempts: 2,
        ...(errorBudget === undefined ? {} : { errorBudget }),
      },
    });
    servers.push(relay);
    return { relay, audit };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  it("revision audits previous/current exactly; same-value is a silent no-op", async () => {
    const construction = {
      fastWindowMs: HOUR,
      slowWindowMs: 6 * HOUR,
      budgetErrorRate: 0.01,
      alertThreshold: 2,
      minEvents: 10,
    };
    const { relay, audit } = makeRelay(construction);
    await listen(relay);
    // First `previous` is the construction config.
    assert.deepEqual(relay.getErrorBudgetConfig!(), construction);
    assert.deepEqual(relay.reviseErrorBudget!({ alertThreshold: 1.5 }), {
      ...construction,
      alertThreshold: 1.5,
    });
    const revised = eventsOf(audit, "error_budget_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, construction);
    assert.deepEqual(revised[0].current, { ...construction, alertThreshold: 1.5 });
    // Landing exactly on the live values audits nothing.
    relay.reviseErrorBudget!({ alertThreshold: 1.5 });
    assert.equal(eventsOf(audit, "error_budget_revised").length, 1);
    assert.deepEqual(relay.getErrorBudgetConfig!(), { ...construction, alertThreshold: 1.5 });
    // A second real revision chains previous from the revised values.
    relay.reviseErrorBudget!({ budgetErrorRate: 0.005, minEvents: 5 });
    const revised2 = eventsOf(audit, "error_budget_revised");
    assert.equal(revised2.length, 2);
    assert.deepEqual(revised2[1].previous, { ...construction, alertThreshold: 1.5 });
    assert.deepEqual(revised2[1].current, {
      ...construction,
      alertThreshold: 1.5,
      budgetErrorRate: 0.005,
      minEvents: 5,
    });
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseErrorBudget!({ slowWindowMs: HOUR }), RangeError);
    assert.throws(() => relay.reviseErrorBudget!({}), RangeError);
    assert.throws(() => relay.reviseErrorBudget!(null as never), RangeError);
    assert.equal(eventsOf(audit, "error_budget_revised").length, 2);
    assert.deepEqual(relay.getErrorBudgetConfig!(), {
      ...construction,
      alertThreshold: 1.5,
      budgetErrorRate: 0.005,
      minEvents: 5,
    });
    // The getter returns a snapshot, not a live reference.
    const snap = relay.getErrorBudgetConfig!();
    snap.minEvents = 999;
    assert.deepEqual(relay.getErrorBudgetConfig!(), {
      ...construction,
      alertThreshold: 1.5,
      budgetErrorRate: 0.005,
      minEvents: 5,
    });
  });

  it("first previous is the defaults when configured with an empty object", async () => {
    const defaults = {
      fastWindowMs: HOUR,
      slowWindowMs: 6 * HOUR,
      budgetErrorRate: 0.01,
      alertThreshold: 2,
      minEvents: 10,
    };
    const { relay, audit } = makeRelay({});
    await listen(relay);
    assert.deepEqual(relay.getErrorBudgetConfig!(), defaults);
    assert.deepEqual(relay.reviseErrorBudget!({ alertThreshold: 1.5 }), {
      ...defaults,
      alertThreshold: 1.5,
    });
    const revised = eventsOf(audit, "error_budget_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, defaults);
    assert.deepEqual(revised[0].current, { ...defaults, alertThreshold: 1.5 });
  });

  it("unconfigured server throws must-restart and mounts no getter", async () => {
    const { relay } = makeRelay(undefined);
    await listen(relay);
    assert.equal(relay.getErrorBudgetConfig, undefined);
    assert.equal(typeof relay.reviseErrorBudget, "function", "revise is always set");
    assert.throws(() => relay.reviseErrorBudget!({ alertThreshold: 1.5 }), {
      name: "Error",
      message: MUST_RESTART,
    });
  });
});
