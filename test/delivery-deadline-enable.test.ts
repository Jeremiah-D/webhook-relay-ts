import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RetryQueue,
  type DeliveryDeadlineConfig,
  type RetryItem,
  type Sender,
} from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "delivery-deadline-enable-test-key";
const opToken = "delivery-deadline-enable-op-token";
const URL = "http://localhost:9999/hook";
const OTHER = "http://localhost:9999/other";
const URL_A = "http://localhost:9999/a";

/** Steppable timer: each `step()` runs the currently pending callbacks once. */
function stepTimer() {
  const pending: Array<() => void> = [];
  return {
    pending,
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
      for (const fn of fns) fn();
      // One macrotask flushes the whole deliver() microtask chain
      // (lane turn, limiter, global gate, sender, catch, reschedule).
      await new Promise((r) => setImmediate(r));
    },
  };
}

// Queue options for an *unconfigured* queue whose deadline clock is
// still controllable: `deliveryDeadline` carries only `now` (no
// deadlines), so the map stays undefined while the clock is
// deterministic. The enable keeps this construction clock.
const enableOpts = (t: ReturnType<typeof stepTimer>, now: () => number, sender: Sender) => ({
  sender,
  baseDelayMs: 100,
  maxDelayMs: 10_000,
  maxAttempts: 5,
  jitterMs: 0,
  setTimer: t.setTimer,
  clearTimer: t.clearTimer,
  deliveryDeadline: { now },
});

const ITEM = {
  id: "item-1",
  payload: Buffer.from("hello"),
  targetUrl: URL,
  headers: { "content-type": "application/json" },
};

describe("RetryQueue.reviseDeliveryDeadline enable (WR-444)", () => {
  it("enabling with a long deadline lets the next dispatch through", async () => {
    const t = stepTimer();
    let nowMs = 0;
    let attempts = 0;
    const q = new RetryQueue({
      ...enableOpts(t, () => nowMs, async () => {
        attempts += 1;
        throw new Error("boom");
      }),
    });
    assert.equal(q.getDeliveryDeadlineConfig(), undefined);
    q.start();
    q.enqueue({ ...ITEM });
    await t.step(); // attempt 1 at t=0 fails, retry scheduled
    assert.equal(attempts, 1);
    nowMs = 200;
    assert.deepEqual(q.reviseDeliveryDeadline({ deadlines: { [URL]: 5000 } }), {
      deadlines: { [URL]: 5000 },
      propagateBudget: true,
      minAttemptBudgetMs: 0,
    });
    nowMs = 300; // inside the new deadline
    await t.step(); // the next dispatch uses the new deadline
    assert.equal(attempts, 2);
    assert.equal(q.getDeadLetter().length, 0);
  });

  it("an item admitted before the enable keeps its elapsed from admission — the enable never resets it", async () => {
    const t = stepTimer();
    let nowMs = 0;
    let attempts = 0;
    const q = new RetryQueue({
      ...enableOpts(t, () => nowMs, async () => {
        attempts += 1;
        throw new Error("boom");
      }),
    });
    q.start();
    q.enqueue({ ...ITEM });
    await t.step(); // attempt 1 at t=0 fails, retry scheduled
    assert.equal(attempts, 1);
    nowMs = 200;
    q.reviseDeliveryDeadline({ deadlines: { [URL]: 250 } });
    nowMs = 300; // 300ms since admission, only 100ms since the enable
    await t.step();
    // Past the 250ms deadline measured from admission: no second
    // attempt — had the enable reset the clock, 100ms would be inside.
    assert.equal(attempts, 1);
    assert.equal(q.getDeadLetter().length, 1);
    assert.equal(q.getDeadLetter()[0].targetUrl, URL);
  });

  it("a knobs-only patch cannot enable", () => {
    const q = new RetryQueue({});
    assert.equal(q.getDeliveryDeadlineConfig(), undefined);
    for (const patch of [
      { propagateBudget: false },
      { minAttemptBudgetMs: 50 },
      { deadlines: {} },
      { propagateBudget: false, minAttemptBudgetMs: 50 },
    ]) {
      assert.throws(
        () => q.reviseDeliveryDeadline(patch as never),
        /must set at least one deadline to enable delivery deadlines/,
        JSON.stringify(patch)
      );
      assert.equal(q.getDeliveryDeadlineConfig(), undefined, JSON.stringify(patch));
    }
  });

  it("an illegal deadline patch throws RangeError and leaves the queue unconfigured", () => {
    const q = new RetryQueue({});
    const bad: Array<unknown> = [
      { deadlines: { [URL]: 0 } },
      { deadlines: { [URL]: -5 } },
      { deadlines: { [URL]: Number.NaN } },
      { deadlines: { [URL]: Number.POSITIVE_INFINITY } },
      { deadlines: { [URL]: "250" } },
      { deadlines: { "": 100 } },
      { deadlines: { [URL]: null } },
      { deadlines: null },
      { deadlines: [] },
      { deadlines: { [URL]: undefined } },
      // A valid deadline paired with an invalid knob must not
      // partially apply: validate-then-apply leaves everything intact.
      { deadlines: { [URL]: 999 }, minAttemptBudgetMs: -1 },
      { deadlines: { [URL]: 999 }, propagateBudget: "yes" },
    ];
    for (const patch of bad) {
      assert.throws(
        () => q.reviseDeliveryDeadline(patch as never),
        RangeError,
        JSON.stringify(patch)
      );
      assert.equal(q.getDeliveryDeadlineConfig(), undefined, JSON.stringify(patch));
    }
  });

  it("an empty or non-object patch throws RangeError", () => {
    const q = new RetryQueue({});
    for (const patch of [{}, null, "deadline", []]) {
      assert.throws(
        () => q.reviseDeliveryDeadline(patch as never),
        RangeError,
        JSON.stringify(patch)
      );
      assert.equal(q.getDeliveryDeadlineConfig(), undefined, JSON.stringify(patch));
    }
  });

  it("enabling with knobs takes them; omitted knobs take the construction defaults", () => {
    const q = new RetryQueue({});
    assert.deepEqual(
      q.reviseDeliveryDeadline({
        deadlines: { [URL]: 250 },
        propagateBudget: false,
        minAttemptBudgetMs: 50,
      }),
      {
        deadlines: { [URL]: 250 },
        propagateBudget: false,
        minAttemptBudgetMs: 50,
      }
    );
    const q2 = new RetryQueue({});
    assert.deepEqual(q2.reviseDeliveryDeadline({ deadlines: { [URL]: 250 } }), {
      deadlines: { [URL]: 250 },
      propagateBudget: true,
      minAttemptBudgetMs: 0,
    });
  });

  it("deleting endpoints after an enable works; deleting the last keeps the feature configured", () => {
    const q = new RetryQueue({});
    q.reviseDeliveryDeadline({ deadlines: { [URL]: 250, [OTHER]: 500 } });
    assert.deepEqual(q.reviseDeliveryDeadline({ deadlines: { [OTHER]: null } }), {
      deadlines: { [URL]: 250 },
      propagateBudget: true,
      minAttemptBudgetMs: 0,
    });
    // Deleting the last endpoint audits the empty map, not a switch-off.
    assert.deepEqual(q.reviseDeliveryDeadline({ deadlines: { [URL]: null } }), {
      deadlines: {},
      propagateBudget: true,
      minAttemptBudgetMs: 0,
    });
    assert.deepEqual(q.getDeliveryDeadlineConfig(), {
      deadlines: {},
      propagateBudget: true,
      minAttemptBudgetMs: 0,
    });
  });

  it("a partial revision after an enable still merges", () => {
    const q = new RetryQueue({});
    q.reviseDeliveryDeadline({ deadlines: { [URL]: 250 } });
    assert.deepEqual(
      q.reviseDeliveryDeadline({ deadlines: { [OTHER]: 500 }, propagateBudget: false }),
      {
        deadlines: { [URL]: 250, [OTHER]: 500 },
        propagateBudget: false,
        minAttemptBudgetMs: 0,
      }
    );
    // Landing exactly on the live values is a no-op.
    assert.deepEqual(q.reviseDeliveryDeadline({ deadlines: { [URL]: 250, [OTHER]: 500 } }), {
      deadlines: { [URL]: 250, [OTHER]: 500 },
      propagateBudget: false,
      minAttemptBudgetMs: 0,
    });
  });

  it("a restart returns to unconfigured — the enable is live-only", () => {
    const t = stepTimer();
    const opts = enableOpts(t, () => 0, async () => {
      throw new Error("boom");
    });
    const q = new RetryQueue({ ...opts });
    q.reviseDeliveryDeadline({ deadlines: { [URL]: 250 } });
    assert.notEqual(q.getDeliveryDeadlineConfig(), undefined);
    // A fresh queue from the same construction options has no deadlines.
    const restarted = new RetryQueue({ ...opts });
    assert.equal(restarted.getDeliveryDeadlineConfig(), undefined);
  });
});

describe("RelayServer delivery-deadline enable (WR-444)", () => {
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

  function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "delivery-deadline-enable-"));
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

  it("enabling audits previous null and mounts the getter; a same-value revision after the enable is a silent no-op", async () => {
    const { relay, audit } = makeRelay();
    await listen(relay);
    assert.equal(relay.getDeliveryDeadlineConfig, undefined);
    assert.deepEqual(relay.reviseDeliveryDeadline!({ deadlines: { [URL_A]: 250 } }), {
      deadlines: { [URL_A]: 250 },
      propagateBudget: true,
      minAttemptBudgetMs: 0,
    });
    assert.deepEqual(relay.getDeliveryDeadlineConfig!(), {
      deadlines: { [URL_A]: 250 },
      propagateBudget: true,
      minAttemptBudgetMs: 0,
    });
    const revised = eventsOf(audit, "delivery_deadline_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, null);
    assert.deepEqual(revised[0].current, {
      deadlines: { [URL_A]: 250 },
      propagateBudget: true,
      minAttemptBudgetMs: 0,
    });
    // Landing exactly on the live values audits nothing.
    relay.reviseDeliveryDeadline!({ deadlines: { [URL_A]: 250 } });
    assert.equal(eventsOf(audit, "delivery_deadline_revised").length, 1);
    // Deleting the last endpoint audits the empty map, not a switch-off.
    relay.reviseDeliveryDeadline!({ deadlines: { [URL_A]: null } });
    const revised2 = eventsOf(audit, "delivery_deadline_revised");
    assert.equal(revised2.length, 2);
    assert.deepEqual(revised2[1].previous, {
      deadlines: { [URL_A]: 250 },
      propagateBudget: true,
      minAttemptBudgetMs: 0,
    });
    assert.deepEqual(revised2[1].current, {
      deadlines: {},
      propagateBudget: true,
      minAttemptBudgetMs: 0,
    });
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseDeliveryDeadline!({ deadlines: { [URL_A]: 0 } }), RangeError);
    assert.throws(() => relay.reviseDeliveryDeadline!({}), RangeError);
    assert.equal(eventsOf(audit, "delivery_deadline_revised").length, 2);
    assert.deepEqual(relay.getDeliveryDeadlineConfig!(), {
      deadlines: {},
      propagateBudget: true,
      minAttemptBudgetMs: 0,
    });
  });

  it("a fresh relay from the same options is unconfigured again — the enable is live-only", async () => {
    const { relay } = makeRelay();
    await listen(relay);
    relay.reviseDeliveryDeadline!({ deadlines: { [URL_A]: 250 } });
    assert.notEqual(relay.getDeliveryDeadlineConfig, undefined);
    const second = makeRelay();
    await listen(second.relay);
    assert.equal(second.relay.getDeliveryDeadlineConfig, undefined);
  });
});
