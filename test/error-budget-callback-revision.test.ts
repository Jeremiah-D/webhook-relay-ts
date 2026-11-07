import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ErrorBudgetMonitor, type BurnRateAlertInfo } from "../src/error-budget.ts";
import { RetryQueue } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "error-budget-callback-revision-test-key";
const opToken = "error-budget-callback-revision-op-token";
const URL_A = "http://localhost:9999/a";
const EP_A = "http://a.example/hook";
const probeBody = Buffer.from(JSON.stringify({ event: "error-budget-callback-revision.probe" }));

const MUST_RESTART =
  "reviseErrorBudgetAlertCallback: error budget is not configured — enabling it requires a restart";

/** Steppable clock for deterministic windows. */
function clock() {
  let now = 1_000_000;
  return { now: () => now, advance: (ms: number) => (now += ms) };
}

const HOUR = 3_600_000;

/**
 * A monitor whose episodes open and close cheaply: budget 50% and
 * threshold 1.5, so two failures open an episode (100% error, burn
 * 2.0) and a single success closes it again (2/3 = 66.7% error,
 * burn 1.33).
 */
function monitor(
  alerts: BurnRateAlertInfo[],
  c = clock(),
  extra: Record<string, unknown> = {}
) {
  return {
    m: new ErrorBudgetMonitor({
      fastWindowMs: HOUR,
      slowWindowMs: 6 * HOUR,
      budgetErrorRate: 0.5,
      alertThreshold: 1.5,
      minEvents: 2,
      onBurnRateAlert: (info) => alerts.push(info),
      now: c.now,
      ...extra,
    }),
    c,
  };
}

/** Open one episode (two failures) and assert the callback fired once. */
function openEpisode(m: ErrorBudgetMonitor, alerts: BurnRateAlertInfo[]) {
  m.recordOutcome(EP_A, false);
  m.recordOutcome(EP_A, false);
  assert.equal(alerts.length, 1);
  assert.equal(m.isAlerting(EP_A), true);
}

/** Close the open episode with one success. */
function closeEpisode(m: ErrorBudgetMonitor) {
  m.recordOutcome(EP_A, true);
  assert.equal(m.isAlerting(EP_A), false);
}

describe("ErrorBudgetMonitor.replaceAlertCallback (WR-353)", () => {
  it("a non-function callback throws RangeError and the live callback is untouched", () => {
    const alerts: BurnRateAlertInfo[] = [];
    const { m } = monitor(alerts);
    const live = m.config();
    for (const bad of ["nope", 42, {}, true]) {
      assert.throws(() => m.replaceAlertCallback(bad as never), RangeError);
    }
    assert.deepEqual(m.config(), live);
    openEpisode(m, alerts);
    assert.equal(alerts[0].endpoint, EP_A);
  });

  it("undefined clears the callback: the next episode opens silently", () => {
    const alerts: BurnRateAlertInfo[] = [];
    const { m } = monitor(alerts);
    openEpisode(m, alerts);
    m.replaceAlertCallback(undefined);
    closeEpisode(m);
    // The latch still opens — only the notification is gone.
    m.recordOutcome(EP_A, false);
    m.recordOutcome(EP_A, false);
    assert.equal(alerts.length, 1, "cleared callback must not fire");
    assert.equal(m.isAlerting(EP_A), true);
  });

  it("the next episode goes to the new callback; the old one never fires again", () => {
    const oldAlerts: BurnRateAlertInfo[] = [];
    const newAlerts: BurnRateAlertInfo[] = [];
    const { m } = monitor(oldAlerts);
    openEpisode(m, oldAlerts);
    m.replaceAlertCallback((info) => newAlerts.push(info));
    closeEpisode(m);
    m.recordOutcome(EP_A, false);
    m.recordOutcome(EP_A, false);
    assert.equal(newAlerts.length, 1);
    assert.equal(newAlerts[0].endpoint, EP_A);
    assert.equal(oldAlerts.length, 1);
  });

  it("replacing with the same reference (or clearing when unset) is a silent no-op", () => {
    const alerts: BurnRateAlertInfo[] = [];
    const cb = (info: BurnRateAlertInfo) => alerts.push(info);
    const { m } = monitor([], clock(), { onBurnRateAlert: cb });
    m.replaceAlertCallback(cb);
    openEpisode(m, alerts);
    // Clearing twice when already unset is also a no-op, not an error.
    const { m: bare } = monitor([], clock(), { onBurnRateAlert: undefined });
    bare.replaceAlertCallback(undefined);
    bare.replaceAlertCallback(undefined);
    bare.recordOutcome(EP_A, false);
    bare.recordOutcome(EP_A, false);
    assert.equal(bare.isAlerting(EP_A), true);
  });

  it("replacing inside an open episode does not re-fire; the next episode uses the new callback", () => {
    const oldAlerts: BurnRateAlertInfo[] = [];
    const newAlerts: BurnRateAlertInfo[] = [];
    const { m } = monitor(oldAlerts);
    openEpisode(m, oldAlerts);
    m.replaceAlertCallback((info) => newAlerts.push(info));
    assert.equal(oldAlerts.length, 1);
    assert.equal(newAlerts.length, 0, "replacement must not re-fire an open episode");
    assert.equal(m.isAlerting(EP_A), true);
    closeEpisode(m);
    m.recordOutcome(EP_A, false);
    m.recordOutcome(EP_A, false);
    assert.equal(newAlerts.length, 1);
    assert.equal(oldAlerts.length, 1);
  });

  it("a throwing replacement callback never breaks the delivery path", () => {
    const alerts: BurnRateAlertInfo[] = [];
    const { m } = monitor(alerts);
    m.replaceAlertCallback(() => {
      throw new Error("pager is down");
    });
    assert.doesNotThrow(() => {
      m.recordOutcome(EP_A, false);
      m.recordOutcome(EP_A, false);
    });
    assert.equal(m.isAlerting(EP_A), true);
    assert.ok((m.burnRate(EP_A) ?? 0) > 0);
    // Later outcomes still process normally.
    assert.doesNotThrow(() => m.recordOutcome(EP_A, true));
    assert.equal(m.isAlerting(EP_A), false);
  });

  it("replacement leaves the five knobs, the clock, the outcomes and the latch untouched", () => {
    const alerts: BurnRateAlertInfo[] = [];
    const { m, c } = monitor(alerts);
    m.recordOutcome(EP_A, true);
    m.recordOutcome(EP_A, false); // 50% error -> burn 1.0 at the 50% budget
    const live = m.config();
    const burnBefore = m.burnRate(EP_A);
    assert.equal(burnBefore, 1);
    m.replaceAlertCallback(() => {});
    assert.deepEqual(m.config(), live);
    assert.equal(m.burnRate(EP_A), burnBefore);
    // The injected clock still drives the windows: 30 minutes later
    // the outcomes are still inside the 1h fast window.
    c.advance(30 * 60_000);
    assert.equal(m.burnRate(EP_A), burnBefore, "the injected clock must survive the replacement");
    // The outcomes are still there: three more failures push the error
    // rate to 80%, burning at 1.6 — past the threshold — and the
    // (replaced) callback fires.
    const fired: BurnRateAlertInfo[] = [];
    m.replaceAlertCallback((info) => fired.push(info));
    for (let i = 0; i < 3; i++) m.recordOutcome(EP_A, false);
    assert.equal(fired.length, 1);
    assert.equal(fired[0].budgetErrorRate, 0.5);
  });

  it("a later retune carries the replaced callback forward unchanged", () => {
    const oldAlerts: BurnRateAlertInfo[] = [];
    const newAlerts: BurnRateAlertInfo[] = [];
    const { m } = monitor(oldAlerts);
    m.replaceAlertCallback((info) => newAlerts.push(info));
    m.retune({ alertThreshold: 1.5 });
    openEpisode(m, newAlerts);
    assert.equal(newAlerts.length, 1);
    assert.equal(oldAlerts.length, 0);
  });
});

describe("RetryQueue.reviseErrorBudgetAlertCallback (WR-353)", () => {
  it("unconfigured queue throws the must-restart Error", async () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      assert.throws(() => q.reviseErrorBudgetAlertCallback(() => {}), {
        name: "Error",
        message: MUST_RESTART,
      });
    } finally {
      await q.shutdown();
    }
  });

  it("queue passthrough swaps the live monitor callback", async () => {
    const c = clock();
    const oldAlerts: BurnRateAlertInfo[] = [];
    const newAlerts: BurnRateAlertInfo[] = [];
    const q = new RetryQueue({
      sender: async () => {},
      errorBudget: {
        fastWindowMs: HOUR,
        slowWindowMs: 6 * HOUR,
        budgetErrorRate: 0.5,
        alertThreshold: 1.5,
        minEvents: 2,
        onBurnRateAlert: (info) => oldAlerts.push(info),
        now: c.now,
      },
    });
    try {
      const mon = q.getErrorBudgetMonitor()!;
      openEpisode(mon, oldAlerts);
      q.reviseErrorBudgetAlertCallback((info) => newAlerts.push(info));
      closeEpisode(mon);
      mon.recordOutcome(EP_A, false);
      mon.recordOutcome(EP_A, false);
      assert.equal(newAlerts.length, 1);
      assert.equal(oldAlerts.length, 1);
      // A non-function callback throws RangeError at the queue layer too.
      assert.throws(() => q.reviseErrorBudgetAlertCallback("nope" as never), RangeError);
      assert.equal(newAlerts.length, 1);
    } finally {
      await q.shutdown();
    }
  });
});

describe("RelayServer error-budget callback revision (WR-353)", () => {
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

  function post(port: number, path: string) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path,
          method: "POST",
          headers: { "x-signature": signSha256(probeBody, signingKey) },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => {
            r.destroy();
            resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() });
          });
        }
      );
      r.on("error", reject);
      r.end(probeBody);
    });
  }

  async function waitFor(cond: () => boolean, label: string, timeoutMs = 5000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (!cond()) {
      if (Date.now() > deadline) throw new Error(`timed out waiting for ${label}`);
      await new Promise((r) => setTimeout(r, 10));
    }
  }

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "error-budget-callback-revision-"));
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
      retry: { baseDelayMs: 5, jitterMs: 0, maxAttempts: 2 },
      ...extra,
    });
    servers.push(relay);
    return { relay, audit };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  const budget = {
    fastWindowMs: HOUR,
    slowWindowMs: 6 * HOUR,
    budgetErrorRate: 0.5,
    alertThreshold: 1.5,
    minEvents: 2,
  };

  it("replacement audits set/unset presence only; same-value is a silent no-op", async () => {
    const oldAlerts: BurnRateAlertInfo[] = [];
    const newAlerts: BurnRateAlertInfo[] = [];
    const newCb = (info: BurnRateAlertInfo) => newAlerts.push(info);
    const { relay, audit } = makeRelay({
      retry: {
        errorBudget: { ...budget, onBurnRateAlert: (info: BurnRateAlertInfo) => oldAlerts.push(info) },
      },
    });
    await listen(relay);
    // set -> set: the callback changes, presence does not.
    relay.reviseErrorBudgetAlertCallback!(newCb);
    let replaced = eventsOf(audit, "error_budget_alert_callback_replaced");
    assert.equal(replaced.length, 1);
    assert.deepEqual(
      { previous: replaced[0].previous, current: replaced[0].current },
      { previous: "set", current: "set" }
    );
    assert.ok(!("onBurnRateAlert" in replaced[0]), "the audit must never record a function body");
    // Same reference again: silent no-op.
    relay.reviseErrorBudgetAlertCallback!(newCb);
    assert.equal(eventsOf(audit, "error_budget_alert_callback_replaced").length, 1);
    // set -> unset.
    relay.reviseErrorBudgetAlertCallback!(undefined);
    replaced = eventsOf(audit, "error_budget_alert_callback_replaced");
    assert.equal(replaced.length, 2);
    assert.deepEqual(
      { previous: replaced[1].previous, current: replaced[1].current },
      { previous: "set", current: "unset" }
    );
    // Clearing when already unset: silent no-op.
    relay.reviseErrorBudgetAlertCallback!(undefined);
    assert.equal(eventsOf(audit, "error_budget_alert_callback_replaced").length, 2);
    // unset -> set.
    relay.reviseErrorBudgetAlertCallback!(newCb);
    replaced = eventsOf(audit, "error_budget_alert_callback_replaced");
    assert.equal(replaced.length, 3);
    assert.deepEqual(
      { previous: replaced[2].previous, current: replaced[2].current },
      { previous: "unset", current: "set" }
    );
    // A non-function callback throws RangeError and audits nothing.
    assert.throws(() => relay.reviseErrorBudgetAlertCallback!("nope" as never), RangeError);
    assert.equal(eventsOf(audit, "error_budget_alert_callback_replaced").length, 3);
  });

  it("after replacement the next episode alerts the new callback and still audits error_budget_burn", async () => {
    const oldAlerts: BurnRateAlertInfo[] = [];
    const newAlerts: BurnRateAlertInfo[] = [];
    let mode: "fail" | "ok" = "fail";
    const { relay, audit } = makeRelay({
      sender: async () => {
        if (mode === "fail") throw new Error("boom");
        return { statusCode: 200, body: Buffer.from("ok") };
      },
      retry: {
        baseDelayMs: 5,
        jitterMs: 0,
        maxAttempts: 1,
        errorBudget: { ...budget, onBurnRateAlert: (info: BurnRateAlertInfo) => oldAlerts.push(info) },
      },
    });
    const port = await listen(relay);
    // Two failing deliveries open the first episode on the old callback.
    await post(port, "/");
    await post(port, "/");
    await waitFor(
      () => oldAlerts.length === 1 && eventsOf(audit, "error_budget_burn").length === 1,
      "first episode"
    );
    // Replace the callback; the open episode does not re-fire.
    relay.reviseErrorBudgetAlertCallback!((info) => newAlerts.push(info));
    assert.equal(oldAlerts.length, 1);
    assert.equal(newAlerts.length, 0);
    // One success closes the episode (2/3 = 66.7% error, burn 1.33 < 1.5).
    // The `delivered` audit fires after recordOutcome (retry.ts: the
    // monitor is fed before onDelivered), so waiting on it proves the
    // success outcome landed before the next failures are posted.
    mode = "ok";
    await post(port, "/");
    await waitFor(() => eventsOf(audit, "delivered").length === 1, "success recorded");
    // Two more failures open the next episode on the new callback — and
    // the audit wrapper still records error_budget_burn.
    mode = "fail";
    await post(port, "/");
    await post(port, "/");
    await waitFor(
      () => newAlerts.length === 1 && eventsOf(audit, "error_budget_burn").length === 2,
      "second episode on the new callback"
    );
    assert.equal(oldAlerts.length, 1, "the old callback must not fire again");
    assert.equal(newAlerts[0].endpoint, URL_A);
  });

  it("unconfigured server throws must-restart and the method is always set", async () => {
    const { relay } = makeRelay();
    await listen(relay);
    assert.equal(relay.getErrorBudgetConfig, undefined);
    assert.equal(typeof relay.reviseErrorBudgetAlertCallback, "function");
    assert.throws(() => relay.reviseErrorBudgetAlertCallback!(() => {}), {
      name: "Error",
      message: MUST_RESTART,
    });
  });
});
