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
const signingKey = "delivery-deadline-revision-test-key";
const opToken = "delivery-deadline-revision-op-token";
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

const baseOpts = (t: ReturnType<typeof stepTimer>, now: () => number, sender: Sender) => ({
  sender,
  baseDelayMs: 100,
  maxDelayMs: 10_000,
  maxAttempts: 5,
  jitterMs: 0,
  setTimer: t.setTimer,
  clearTimer: t.clearTimer,
  deliveryDeadline: { deadlines: { [URL]: 250 }, now },
});

const ITEM = {
  id: "item-1",
  payload: Buffer.from("hello"),
  targetUrl: URL,
  headers: { "content-type": "application/json" },
};

const flush = () => new Promise((r) => setImmediate(r));

describe("RetryQueue.reviseDeliveryDeadline (WR-341)", () => {
  it("lengthening a deadline revives a delivery about to expire at the next dispatch", async () => {
    const t = stepTimer();
    let nowMs = 0;
    let attempts = 0;
    const q = new RetryQueue({
      ...baseOpts(t, () => nowMs, async () => {
        attempts += 1;
        throw new Error("boom");
      }),
    });
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
    nowMs = 300; // past the old 250ms deadline, inside the new one
    await t.step(); // the next dispatch uses the new deadline
    assert.equal(attempts, 2);
    assert.equal(q.getDeadLetter().length, 0);
    assert.deepEqual(q.getDeliveryDeadlineConfig(), {
      deadlines: { [URL]: 5000 },
      propagateBudget: true,
      minAttemptBudgetMs: 0,
    });
  });

  it("shortening a deadline expires the delivery at the next dispatch", async () => {
    const t = stepTimer();
    let nowMs = 0;
    let attempts = 0;
    const q = new RetryQueue({
      ...baseOpts(t, () => nowMs, async () => {
        attempts += 1;
        throw new Error("boom");
      }),
      deliveryDeadline: { deadlines: { [URL]: 5000 }, now: () => nowMs },
    });
    q.start();
    q.enqueue({ ...ITEM });
    await t.step(); // attempt 1 at t=0 fails
    assert.equal(attempts, 1);
    nowMs = 200;
    q.reviseDeliveryDeadline({ deadlines: { [URL]: 250 } });
    nowMs = 300; // inside the old deadline, past the new one
    await t.step();
    assert.equal(attempts, 1); // no second attempt was dispatched
    assert.equal(q.pendingCount(), 0);
    assert.equal(q.getDeadLetter().length, 1);
    assert.equal(q.getDeadLetter()[0].id, "item-1");
  });

  it("deleting an endpoint's deadline restores no-deadline delivery for it", async () => {
    const t = stepTimer();
    let nowMs = 0;
    let attempts = 0;
    const q = new RetryQueue({
      ...baseOpts(t, () => nowMs, async () => {
        attempts += 1;
        throw new Error("boom");
      }),
    });
    q.start();
    q.enqueue({ ...ITEM });
    await t.step(); // attempt 1 at t=0 fails
    assert.equal(attempts, 1);
    assert.deepEqual(q.reviseDeliveryDeadline({ deadlines: { [URL]: null } }), {
      deadlines: {},
      propagateBudget: true,
      minAttemptBudgetMs: 0,
    });
    nowMs = 100_000; // far past the old deadline
    await t.step(); // the next dispatch has no deadline to enforce
    assert.equal(attempts, 2);
    assert.equal(q.getDeadLetter().length, 0);
  });

  it("null-deleting the last endpoint leaves an empty map and revision stays usable", async () => {
    const t = stepTimer();
    let nowMs = 0;
    let attempts = 0;
    const q = new RetryQueue({
      ...baseOpts(t, () => nowMs, async () => {
        attempts += 1;
        throw new Error("boom");
      }),
    });
    // Deleting the last endpoint does not switch the feature off.
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
    // A deadline can be added back afterwards, and it governs delivery.
    q.reviseDeliveryDeadline({ deadlines: { [URL]: 1000 } });
    q.start();
    q.enqueue({ ...ITEM });
    await t.step(); // attempt 1 at t=0 fails
    assert.equal(attempts, 1);
    nowMs = 1500; // past the re-added deadline
    await t.step();
    assert.equal(attempts, 1);
    assert.equal(q.getDeadLetter().length, 1);
  });

  it("turning propagateBudget off stops stamping the budget on the next dispatch", async () => {
    const t = stepTimer();
    let nowMs = 0;
    const stamped: Array<number | undefined> = [];
    const q = new RetryQueue({
      ...baseOpts(t, () => nowMs, async (item: RetryItem) => {
        stamped.push(item.deadlineBudgetMs);
        throw new Error("boom");
      }),
    });
    q.start();
    q.enqueue({ ...ITEM });
    await t.step(); // attempt 1 at t=0: remaining budget 250 is stamped
    assert.deepEqual(stamped, [250]);
    q.reviseDeliveryDeadline({ propagateBudget: false });
    nowMs = 50;
    await t.step(); // attempt 2: no budget stamped, the sender is uncapped
    assert.deepEqual(stamped, [250, undefined]);
    assert.equal(q.getDeadLetter().length, 0);
  });

  it("raising minAttemptBudgetMs expires a low-remaining delivery with no outbound call", async () => {
    const t = stepTimer();
    let nowMs = 0;
    let attempts = 0;
    const q = new RetryQueue({
      ...baseOpts(t, () => nowMs, async () => {
        attempts += 1;
        throw new Error("boom");
      }),
    });
    q.start();
    q.enqueue({ ...ITEM });
    await t.step(); // attempt 1 at t=0 fails
    assert.equal(attempts, 1);
    nowMs = 200; // remaining budget is 50ms
    q.reviseDeliveryDeadline({ minAttemptBudgetMs: 100 });
    await t.step(); // 50ms remaining is at/below the new floor: expire, no call
    assert.equal(attempts, 1);
    assert.equal(q.pendingCount(), 0);
    assert.equal(q.getDeadLetter().length, 1);
  });

  it("illegal patches throw RangeError and leave the live config untouched", () => {
    const t = stepTimer();
    const q = new RetryQueue({
      ...baseOpts(t, () => 0, async () => {
        throw new Error("boom");
      }),
      deliveryDeadline: {
        deadlines: { [URL]: 250, [OTHER]: 500 },
        propagateBudget: true,
        minAttemptBudgetMs: 10,
        now: () => 0,
      },
    });
    const live: DeliveryDeadlineConfig = {
      deadlines: { [URL]: 250, [OTHER]: 500 },
      propagateBudget: true,
      minAttemptBudgetMs: 10,
    };
    assert.deepEqual(q.getDeliveryDeadlineConfig(), live);
    const bad: Array<unknown> = [
      { deadlines: { [URL]: 0 } },
      { deadlines: { [URL]: -5 } },
      { deadlines: { [URL]: Number.NaN } },
      { deadlines: { [URL]: Number.POSITIVE_INFINITY } },
      { deadlines: { [URL]: "250" } },
      { deadlines: { "": 100 } },
      { deadlines: null },
      { deadlines: [] },
      { deadlines: { [URL]: undefined } },
      { propagateBudget: "yes" },
      { propagateBudget: 1 },
      { minAttemptBudgetMs: -1 },
      { minAttemptBudgetMs: Number.NaN },
      { minAttemptBudgetMs: Number.POSITIVE_INFINITY },
      {}, // empty patch
      { deadlines: {} }, // names no endpoint at all
      null, // non-object patch
      "deadline",
      [],
      // A valid deadline change paired with an invalid knob must not
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
      assert.deepEqual(q.getDeliveryDeadlineConfig(), live, JSON.stringify(patch));
    }
  });

  it("an unconfigured queue throws the must-restart Error and the getter returns undefined", () => {
    const q = new RetryQueue({});
    assert.equal(q.getDeliveryDeadlineConfig(), undefined);
    assert.throws(
      () => q.reviseDeliveryDeadline({ propagateBudget: false }),
      /not configured — enabling it requires a restart/
    );
    assert.throws(
      () => q.reviseDeliveryDeadline({ deadlines: { [URL]: 100 } }),
      /not configured — enabling it requires a restart/
    );
    assert.equal(q.getDeliveryDeadlineConfig(), undefined);
  });

  it("getDeliveryDeadlineConfig returns a snapshot, not the live map", () => {
    const t = stepTimer();
    const q = new RetryQueue({
      ...baseOpts(t, () => 0, async () => {
        throw new Error("boom");
      }),
    });
    const snap = q.getDeliveryDeadlineConfig()!;
    snap.deadlines[URL] = 1;
    snap.deadlines[OTHER] = 1;
    snap.propagateBudget = false;
    snap.minAttemptBudgetMs = 999;
    assert.deepEqual(q.getDeliveryDeadlineConfig(), {
      deadlines: { [URL]: 250 },
      propagateBudget: true,
      minAttemptBudgetMs: 0,
    });
  });

  it("a same-value revision is a silent no-op", () => {
    const t = stepTimer();
    const q = new RetryQueue({
      ...baseOpts(t, () => 0, async () => {
        throw new Error("boom");
      }),
      deliveryDeadline: {
        deadlines: { [URL]: 250 },
        propagateBudget: true,
        minAttemptBudgetMs: 10,
        now: () => 0,
      },
    });
    // Landing exactly on the live values changes nothing...
    assert.deepEqual(q.reviseDeliveryDeadline({ deadlines: { [URL]: 250 } }), {
      deadlines: { [URL]: 250 },
      propagateBudget: true,
      minAttemptBudgetMs: 10,
    });
    // ...and neither does deleting an endpoint that has no deadline.
    assert.deepEqual(q.reviseDeliveryDeadline({ deadlines: { [OTHER]: null } }), {
      deadlines: { [URL]: 250 },
      propagateBudget: true,
      minAttemptBudgetMs: 10,
    });
    assert.deepEqual(q.getDeliveryDeadlineConfig(), {
      deadlines: { [URL]: 250 },
      propagateBudget: true,
      minAttemptBudgetMs: 10,
    });
  });

  it("a budget already stamped on an in-flight wire copy is unaffected by revision", async () => {
    const t = stepTimer();
    let nowMs = 0;
    const stamped: Array<number | undefined> = [];
    let releaseAttempt: (() => void) | null = null;
    const q = new RetryQueue({
      ...baseOpts(t, () => nowMs, async (item: RetryItem) => {
        stamped.push(item.deadlineBudgetMs);
        await new Promise<void>((resolve) => {
          releaseAttempt = resolve;
        });
        throw new Error("boom");
      }),
    });
    q.start();
    q.enqueue({ ...ITEM });
    await t.step(); // attempt 1 dispatched at t=0; the sender is still in flight
    assert.deepEqual(stamped, [250]);
    // Revise while the attempt is in flight: the stamped budget (250)
    // is the wire copy's own value and must not move.
    q.reviseDeliveryDeadline({ deadlines: { [URL]: 5000 } });
    releaseAttempt!();
    await flush(); // let the failure propagate and the retry get scheduled
    assert.deepEqual(stamped, [250]);
    nowMs = 100;
    await t.step(); // attempt 2 dispatches under the revised deadline
    assert.deepEqual(stamped, [250, 4900]);
    releaseAttempt!();
    await flush();
  });

  it("a dead-letter replay opens a fresh cycle under the revised deadline", async () => {
    const t = stepTimer();
    let nowMs = 0;
    let attempts = 0;
    let fail = true;
    const q = new RetryQueue({
      ...baseOpts(t, () => nowMs, async () => {
        attempts += 1;
        if (fail) throw new Error("boom");
      }),
    });
    q.start();
    q.enqueue({ ...ITEM });
    await t.step(); // attempt 1 at t=0 fails
    nowMs = 600;
    await t.step(); // expired under the 250ms deadline → dead letter
    assert.equal(q.getDeadLetter().length, 1);
    // Lengthen the deadline, then replay: the replayed delivery gets a
    // fresh admission instant and the new deadline — 300ms in, it is
    // inside the new 5000ms deadline (and past the old 250ms one).
    q.reviseDeliveryDeadline({ deadlines: { [URL]: 5000 } });
    nowMs = 1000;
    fail = false;
    assert.equal(q.replayDeadLetter("item-1"), true);
    nowMs = 1300;
    await t.step();
    assert.equal(attempts, 2);
    assert.equal(q.pendingCount(), 0);
    assert.equal(q.getDeadLetter().length, 0);
  });
});

describe("RelayServer delivery-deadline revision (WR-341)", () => {
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
    const dir = mkdtempSync(join(tmpdir(), "delivery-deadline-revision-"));
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

  const construction: DeliveryDeadlineConfig = {
    deadlines: { [URL_A]: 250 },
    propagateBudget: true,
    minAttemptBudgetMs: 0,
  };

  it("revision audits previous/current with the three fields exactly; same-value is a silent no-op", async () => {
    const { relay, audit } = makeRelay({
      retry: {
        baseDelayMs: 5,
        jitterMs: 0,
        maxAttempts: 2,
        deliveryDeadline: { deadlines: { [URL_A]: 250 } },
      },
    });
    await listen(relay);
    assert.deepEqual(relay.getDeliveryDeadlineConfig!(), construction);
    assert.deepEqual(
      relay.reviseDeliveryDeadline!({
        deadlines: { [URL_A]: 5000 },
        minAttemptBudgetMs: 50,
      }),
      {
        deadlines: { [URL_A]: 5000 },
        propagateBudget: true,
        minAttemptBudgetMs: 50,
      }
    );
    const revised = eventsOf(audit, "delivery_deadline_revised");
    assert.equal(revised.length, 1);
    assert.deepEqual(revised[0].previous, construction);
    assert.deepEqual(revised[0].current, {
      deadlines: { [URL_A]: 5000 },
      propagateBudget: true,
      minAttemptBudgetMs: 50,
    });
    // Landing exactly on the live values audits nothing.
    relay.reviseDeliveryDeadline!({ deadlines: { [URL_A]: 5000 }, minAttemptBudgetMs: 50 });
    assert.equal(eventsOf(audit, "delivery_deadline_revised").length, 1);
    assert.deepEqual(relay.getDeliveryDeadlineConfig!(), {
      deadlines: { [URL_A]: 5000 },
      propagateBudget: true,
      minAttemptBudgetMs: 50,
    });
    // Deleting the last endpoint audits the empty map, not a switch-off.
    relay.reviseDeliveryDeadline!({ deadlines: { [URL_A]: null } });
    const revised2 = eventsOf(audit, "delivery_deadline_revised");
    assert.equal(revised2.length, 2);
    assert.deepEqual(revised2[1].previous, {
      deadlines: { [URL_A]: 5000 },
      propagateBudget: true,
      minAttemptBudgetMs: 50,
    });
    assert.deepEqual(revised2[1].current, {
      deadlines: {},
      propagateBudget: true,
      minAttemptBudgetMs: 50,
    });
    // An illegal patch throws and leaves live values and audit untouched.
    assert.throws(() => relay.reviseDeliveryDeadline!({ deadlines: { [URL_A]: 0 } }), RangeError);
    assert.throws(() => relay.reviseDeliveryDeadline!({}), RangeError);
    assert.equal(eventsOf(audit, "delivery_deadline_revised").length, 2);
    assert.deepEqual(relay.getDeliveryDeadlineConfig!(), {
      deadlines: {},
      propagateBudget: true,
      minAttemptBudgetMs: 50,
    });
  });

  it("unconfigured relay: revise throws the must-restart Error and the getter is not mounted", async () => {
    const { relay } = makeRelay();
    await listen(relay);
    assert.equal(relay.getDeliveryDeadlineConfig, undefined);
    assert.throws(
      () => relay.reviseDeliveryDeadline!({ propagateBudget: false }),
      /not configured — enabling it requires a restart/
    );
  });
});
