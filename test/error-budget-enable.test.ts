import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { BurnRateAlertInfo } from "../src/error-budget.ts";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "error-budget-enable-test-key";
const opToken = "error-budget-enable-op-token";
const URL_A = "http://localhost:9999/a";
const EP_A = "http://a.example/hook";
const probeBody = Buffer.from(JSON.stringify({ event: "error-budget-enable.probe" }));

const HOUR = 3_600_000;

/** The construction defaults a bare enable resolves against. */
const defaults = {
  fastWindowMs: HOUR,
  slowWindowMs: 6 * HOUR,
  budgetErrorRate: 0.01,
  alertThreshold: 2,
  minEvents: 10,
};

/** A patch that opens an episode on two failures (100% error, burn 2.0). */
const tripPatch = {
  budgetErrorRate: 0.5,
  alertThreshold: 1.5,
  minEvents: 2,
};

describe("RetryQueue.reviseErrorBudget enable (WR-443)", () => {
  it("enabling on an unconfigured queue resolves missing fields to the defaults", async () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      assert.equal(q.getErrorBudgetConfig(), undefined);
      assert.equal(q.getErrorBudgetMonitor(), undefined);
      assert.deepEqual(q.reviseErrorBudget({ alertThreshold: 1.5 }), {
        ...defaults,
        alertThreshold: 1.5,
      });
      assert.deepEqual(q.getErrorBudgetConfig(), { ...defaults, alertThreshold: 1.5 });
      assert.ok(q.getErrorBudgetMonitor() !== undefined);
    } finally {
      await q.shutdown();
    }
  });

  it("the next outcome after enable is evaluated under the new window", async () => {
    const alerts: BurnRateAlertInfo[] = [];
    const q = new RetryQueue({ sender: async () => {} });
    try {
      q.reviseErrorBudget(tripPatch);
      // The callback gate opens with the monitor (WR-353 follows).
      q.reviseErrorBudgetAlertCallback((info) => alerts.push(info));
      const mon = q.getErrorBudgetMonitor()!;
      assert.equal(mon.burnRate(EP_A), undefined, "empty table: no rate yet");
      assert.equal(mon.render(), "", "gauge is activity-gated before the first outcome");
      mon.recordOutcome(EP_A, false);
      assert.equal(alerts.length, 0, "minEvents 2: one failure cannot trip");
      mon.recordOutcome(EP_A, false);
      assert.equal(alerts.length, 1);
      assert.equal(alerts[0].endpoint, EP_A);
      assert.equal(alerts[0].burnRate, 2);
      assert.match(mon.render(), /relay_error_budget_burn_ratio/);
    } finally {
      await q.shutdown();
    }
  });

  it("an illegal enable patch throws RangeError and the queue stays unconfigured", async () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      for (const bad of [
        { slowWindowMs: HOUR }, // slow must exceed fast (default 1h)
        { fastWindowMs: 2 * HOUR, slowWindowMs: HOUR }, // slow <= fast
        { budgetErrorRate: 1 }, // must be in (0, 1)
        { budgetErrorRate: 0 },
        { alertThreshold: 0 },
        { minEvents: 0 },
        { fastWindowMs: -5 },
      ]) {
        assert.throws(() => q.reviseErrorBudget(bad), RangeError);
        assert.equal(q.getErrorBudgetConfig(), undefined, JSON.stringify(bad));
        assert.equal(q.getErrorBudgetMonitor(), undefined, JSON.stringify(bad));
      }
    } finally {
      await q.shutdown();
    }
  });

  it("an empty or non-object patch throws RangeError and enables nothing", async () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      for (const bad of [{}, null, "fast", 42, []]) {
        assert.throws(() => q.reviseErrorBudget(bad as never), RangeError);
      }
      assert.equal(q.getErrorBudgetConfig(), undefined);
      assert.equal(q.getErrorBudgetMonitor(), undefined);
    } finally {
      await q.shutdown();
    }
  });

  it("outcomes recorded before the enable are never evaluated", async () => {
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
      maxAttempts: 1,
      maxDelayMs: 20,
      jitterMs: 0,
      random: () => 0,
      setTimer: timer.setTimer,
    });
    q.start();
    const item = (id: string) => ({
      id,
      targetUrl: URL_A,
      payload: Buffer.from("{}"),
      headers: {},
    });
    try {
      // Three failed attempts while the budget is off — nothing records
      // them anywhere.
      q.enqueue(item("pre-1"));
      q.enqueue(item("pre-2"));
      q.enqueue(item("pre-3"));
      await timer.step();
      assert.ok(calls >= 3, `calls=${calls}`);
      // Enable: the monitor starts with an empty table.
      q.reviseErrorBudget(tripPatch);
      const mon = q.getErrorBudgetMonitor()!;
      assert.equal(mon.burnRate(URL_A), undefined, "pre-enable failures must not count");
      assert.equal(mon.render(), "", "no gauge until a post-enable outcome");
      q.reviseErrorBudgetAlertCallback((info) => alerts.push(info));
      // Two post-enable failures open the first episode on their own.
      q.enqueue(item("post-1"));
      q.enqueue(item("post-2"));
      await timer.step();
      assert.ok(calls >= 5, `calls=${calls}`);
      assert.equal(alerts.length, 1);
      assert.equal(alerts[0].endpoint, URL_A);
    } finally {
      await q.shutdown();
    }
  });

  it("a partial revision after enable still merges the live values", async () => {
    const q = new RetryQueue({ sender: async () => {} });
    try {
      q.reviseErrorBudget({ alertThreshold: 1.5 });
      assert.deepEqual(q.reviseErrorBudget({ minEvents: 5 }), {
        ...defaults,
        alertThreshold: 1.5,
        minEvents: 5,
      });
      assert.deepEqual(q.reviseErrorBudget({ alertThreshold: 1.5, minEvents: 5 }), {
        ...defaults,
        alertThreshold: 1.5,
        minEvents: 5,
      });
    } finally {
      await q.shutdown();
    }
  });

  it("a fresh queue built from the same options is unconfigured again (no persistence)", async () => {
    const q1 = new RetryQueue({ sender: async () => {} });
    try {
      q1.reviseErrorBudget({ alertThreshold: 1.5 });
      assert.ok(q1.getErrorBudgetConfig() !== undefined);
    } finally {
      await q1.shutdown();
    }
    const q2 = new RetryQueue({ sender: async () => {} });
    try {
      assert.equal(q2.getErrorBudgetConfig(), undefined);
      assert.equal(q2.getErrorBudgetMonitor(), undefined);
    } finally {
      await q2.shutdown();
    }
  });
});

describe("RelayServer error-budget enable (WR-443)", () => {
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

  function makeRelay() {
    const dir = mkdtempSync(join(tmpdir(), "error-budget-enable-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: signingKey,
      forwardUrl: URL_A,
      auditLog: audit,
      operatorToken: opToken,
      sender: async () => {
        throw new Error("downstream down");
      },
      retry: { baseDelayMs: 5, jitterMs: 0, maxAttempts: 1 },
    });
    servers.push(relay);
    return { relay, audit };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  it("enable audits previous null and the full current config, and mounts the getter", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.equal(relay.getErrorBudgetConfig, undefined);
    assert.equal(typeof relay.reviseErrorBudget, "function", "revise is always set");
    assert.deepEqual(relay.reviseErrorBudget!({ alertThreshold: 1.5 }), {
      ...defaults,
      alertThreshold: 1.5,
    });
    assert.deepEqual(relay.getErrorBudgetConfig!(), { ...defaults, alertThreshold: 1.5 });
    const revised = eventsOf(audit, "error_budget_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.deepEqual(revised[0].current, { ...defaults, alertThreshold: 1.5 });
    // A same-value revision after the enable is a silent no-op.
    relay.reviseErrorBudget!({ alertThreshold: 1.5 });
    assert.equal(eventsOf(audit, "error_budget_revised").length, 1);
  });

  it("an illegal or empty enable patch throws RangeError and leaves the server unconfigured", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    for (const bad of [{ budgetErrorRate: 0 }, { minEvents: 0 }, {}]) {
      assert.throws(() => relay.reviseErrorBudget!(bad), RangeError);
    }
    assert.equal(relay.getErrorBudgetConfig, undefined);
    assert.equal(eventsOf(audit, "error_budget_revised").length, 0);
  });

  it("enabling unlocks the callback gate: the next episode alerts the new callback and audits error_budget_burn", async () => {
    const alerts: BurnRateAlertInfo[] = [];
    const { relay, audit } = makeRelay();
    const port = await listen(relay);
    // The callback gate is still fail-closed before the enable.
    assert.throws(() => relay.reviseErrorBudgetAlertCallback!(() => {}), {
      name: "Error",
      message:
        "reviseErrorBudgetAlertCallback: error budget is not configured — enabling it requires a restart",
    });
    relay.reviseErrorBudget!(tripPatch);
    relay.reviseErrorBudgetAlertCallback!((info) => alerts.push(info));
    const replaced = eventsOf(audit, "error_budget_alert_callback_replaced");
    assert.equal(replaced.length, 1);
    assert.equal(replaced[0].previous, "unset");
    assert.equal(replaced[0].current, "set");
    // Two failing deliveries open the first episode on the new callback —
    // and the audit wrapper installed by the enable still records the burn.
    await post(port, "/");
    await post(port, "/");
    await waitFor(
      () => alerts.length === 1 && eventsOf(audit, "error_budget_burn").length === 1,
      "first episode after enable"
    );
    assert.equal(alerts[0].endpoint, URL_A);
    assert.equal(eventsOf(audit, "error_budget_burn")[0].endpoint, URL_A);
  });

  it("a fresh server built from the same options is unconfigured again (no persistence)", async () => {
    const first = makeRelay();
    await listen(first.relay);
    first.relay.reviseErrorBudget!({ alertThreshold: 1.5 });
    assert.ok(first.relay.getErrorBudgetConfig !== undefined);
    const second = makeRelay();
    await listen(second.relay);
    assert.equal(second.relay.getErrorBudgetConfig, undefined);
  });
});
