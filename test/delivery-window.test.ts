import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { EndpointDeliveryWindow, parseDeliveryWindowSpec } from "../src/delivery-window.ts";

const URL_A = "http://localhost:9999/a";
const URL_B = "http://localhost:9999/b";

/** A fixed Monday: 2026-01-05. */
const at = (h: number, m = 0, s = 0) => Date.UTC(2026, 0, 5, h, m, s);

/** Manual timer that also records the scheduled delays. */
function manualTimer() {
  const pending: Array<{ fn: () => void; ms: number }> = [];
  return {
    pendingCount: () => pending.length,
    lastDelay: () => pending[pending.length - 1]?.ms,
    setTimer: (fn: () => void, ms: number) => {
      const rec = { fn, ms };
      pending.push(rec);
      return {
        clear: () => {
          const i = pending.indexOf(rec);
          if (i >= 0) pending.splice(i, 1);
        },
      };
    },
    async step() {
      const fns = pending.splice(0);
      for (const f of fns) f.fn();
      await new Promise((r) => setImmediate(r));
    },
  };
}

function item(id: string, targetUrl: string, tenantId?: string) {
  return { id, payload: Buffer.from("x"), targetUrl, headers: {}, tenantId };
}

describe("parseDeliveryWindowSpec", () => {
  it("parses a plain window and keeps the raw spec", () => {
    const spec = parseDeliveryWindowSpec("01:00-09:00");
    assert.equal(spec.openMinutes, 60);
    assert.equal(spec.closeMinutes, 540);
    assert.equal(spec.raw, "01:00-09:00");
  });

  it("accepts midnight-crossing windows", () => {
    const spec = parseDeliveryWindowSpec("22:00-06:00");
    assert.equal(spec.openMinutes, 22 * 60);
    assert.equal(spec.closeMinutes, 6 * 60);
  });

  it("treats open === close as the full day", () => {
    const spec = parseDeliveryWindowSpec("00:00-00:00");
    assert.equal(spec.openMinutes, 0);
    assert.equal(spec.closeMinutes, 0);
  });

  it("rejects malformed specs with RangeError", () => {
    for (const bad of [
      "09:00",
      "9-17",
      "09:00-17",
      "25:00-09:00",
      "09:60-09:00",
      "09:00-24:00",
      "09:0-17:00",
      "",
      "midnight-dawn",
      "09:00 - 17:00", // inner spaces
    ]) {
      assert.throws(() => parseDeliveryWindowSpec(bad), RangeError, `spec ${bad}`);
    }
    assert.throws(() => parseDeliveryWindowSpec(undefined as never), RangeError);
  });
});

describe("EndpointDeliveryWindow", () => {
  it("honors the open edge (inclusive) and the close edge (exclusive)", () => {
    let now = at(0);
    const w = new EndpointDeliveryWindow({ windows: { [URL_A]: "01:00-09:00" }, now: () => now });
    now = at(0, 59);
    assert.equal(w.isOpen(URL_A), false);
    now = at(1, 0);
    assert.equal(w.isOpen(URL_A), true); // open edge inclusive: "flush at window open"
    now = at(8, 59);
    assert.equal(w.isOpen(URL_A), true);
    now = at(9, 0);
    assert.equal(w.isOpen(URL_A), false); // close edge exclusive
    now = at(23, 59);
    assert.equal(w.isOpen(URL_A), false);
  });

  it("handles midnight-crossing windows", () => {
    let now = at(0);
    const w = new EndpointDeliveryWindow({ windows: { [URL_A]: "22:00-06:00" }, now: () => now });
    now = at(5, 59);
    assert.equal(w.isOpen(URL_A), true);
    now = at(6, 0);
    assert.equal(w.isOpen(URL_A), false);
    now = at(12, 0);
    assert.equal(w.isOpen(URL_A), false);
    now = at(22, 0);
    assert.equal(w.isOpen(URL_A), true);
    now = at(23, 30);
    assert.equal(w.isOpen(URL_A), true);
  });

  it("full-day windows are always open; unconfigured endpoints are always deliverable", () => {
    let now = at(3);
    const w = new EndpointDeliveryWindow(
      { windows: { [URL_A]: "00:00-00:00" }, now: () => now },
      );
    assert.equal(w.isOpen(URL_A), true);
    assert.equal(w.isOpen(URL_B), true);
    now = at(15);
    assert.equal(w.isOpen(URL_A), true);
    assert.equal(w.isOpen(URL_B), true);
  });

  it("computes the wait until the window opens", () => {
    let now = at(2, 0);
    const w = new EndpointDeliveryWindow({ windows: { [URL_A]: "09:00-18:00" }, now: () => now });
    assert.equal(w.isOpen(URL_A), false);
    assert.equal(w.msUntilOpen(URL_A), 7 * 3_600_000); // 02:00 -> 09:00
    now = at(9, 0);
    assert.equal(w.msUntilOpen(URL_A), 0); // open now
    now = at(19, 0);
    assert.equal(w.msUntilOpen(URL_A), 14 * 3_600_000); // 19:00 -> next day 09:00
    assert.equal(w.msUntilOpen(URL_B), 0); // unconfigured
  });

  it("computes the wait for midnight-crossing windows", () => {
    let now = at(12, 0);
    const w = new EndpointDeliveryWindow({ windows: { [URL_A]: "22:00-06:00" }, now: () => now });
    assert.equal(w.msUntilOpen(URL_A), 10 * 3_600_000); // 12:00 -> 22:00
    now = at(23, 0);
    assert.equal(w.msUntilOpen(URL_A), 0); // inside the crossing window
  });

  it("sets, replaces, and deletes endpoint windows at runtime", () => {
    let now = at(12, 0);
    const w = new EndpointDeliveryWindow({ now: () => now });
    assert.equal(w.isOpen(URL_A), true);
    w.setEndpointWindow(URL_A, "22:00-06:00");
    assert.equal(w.isOpen(URL_A), false);
    assert.equal(w.specFor(URL_A)?.raw, "22:00-06:00");
    w.setEndpointWindow(URL_A, "00:00-23:59");
    assert.equal(w.isOpen(URL_A), true);
    // Invalid spec throws and leaves the current window intact.
    assert.throws(() => w.setEndpointWindow(URL_A, "nope"), RangeError);
    assert.equal(w.isOpen(URL_A), true);
    assert.throws(() => w.setEndpointWindow("", "09:00-18:00"), RangeError);
    assert.equal(w.deleteEndpointWindow(URL_A), true);
    assert.equal(w.isOpen(URL_A), true);
    assert.equal(w.deleteEndpointWindow(URL_A), false);
  });

  it("counts window-outside parks per endpoint", () => {
    const w = new EndpointDeliveryWindow({ windows: { [URL_A]: "09:00-18:00" } });
    assert.equal(w.delayedCount(URL_A), 0);
    w.noteDelayed(URL_A);
    w.noteDelayed(URL_A);
    w.noteDelayed(URL_B);
    assert.equal(w.delayedCount(URL_A), 2);
    assert.equal(w.delayedCount(URL_B), 1);
  });
});

describe("RetryQueue delivery windows (WR-52)", () => {
  it("parks out-of-window deliveries until the window opens without consuming attempts", async () => {
    let now = at(2, 0); // 02:00 UTC, before the daytime window
    const t = manualTimer();
    let senderCalls = 0;
    let deadLetters = 0;
    const sender: Sender = async () => {
      senderCalls += 1;
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      maxAttempts: 3,
      deliveryWindow: { windows: { [URL_A]: "09:00-18:00" }, now: () => now },
      onDeadLetter: () => {
        deadLetters += 1;
      },
    });
    q.start();
    q.enqueue(item("w1", URL_A));
    await t.step(); // first attempt: 02:00, window closed -> parked, no send
    assert.equal(senderCalls, 0);
    assert.equal(deadLetters, 0);
    // The item is re-scheduled for the window's opening instant, not a backoff.
    assert.equal(t.lastDelay(), 7 * 3_600_000);
    // The retry budget is untouched: nothing failed, so nothing retries.
    now = at(6, 0);
    await t.step(); // still closed -> parked again
    assert.equal(senderCalls, 0);
    assert.equal(deadLetters, 0);
    // "Flush at window open": the boundary is inclusive, so a delivery
    // landing exactly on 09:00 goes out.
    now = at(9, 0);
    await t.step();
    assert.equal(senderCalls, 1);
    assert.equal(deadLetters, 0);
    q.stop();
  });

  it("delivery exactly on the opening edge goes out immediately (boundary race)", async () => {
    let now = at(8, 59, 59);
    const t = manualTimer();
    let senderCalls = 0;
    const sender: Sender = async () => {
      senderCalls += 1;
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      deliveryWindow: { windows: { [URL_A]: "09:00-18:00" }, now: () => now },
    });
    q.start();
    q.enqueue(item("w2", URL_A));
    await t.step();
    assert.equal(senderCalls, 0); // 08:59:59 -> parked for ~1s
    now = at(9, 0, 0); // window opens exactly now
    await t.step();
    assert.equal(senderCalls, 1);
    q.stop();
  });

  it("endpoints without a window are unaffected (opt-in, backward compatible)", async () => {
    let now = at(2, 0);
    const t = manualTimer();
    let senderCalls = 0;
    const sender: Sender = async () => {
      senderCalls += 1;
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      deliveryWindow: { windows: { [URL_A]: "09:00-18:00" }, now: () => now },
    });
    q.start();
    q.enqueue(item("w3", URL_B)); // no window for URL_B
    await t.step();
    assert.equal(senderCalls, 1);
    q.stop();
  });

  it("reports per-endpoint window stats with spec, delay counts, and open flag", async () => {
    let now = at(2, 0);
    const t = manualTimer();
    const sender: Sender = async () => {};
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      deliveryWindow: { windows: { [URL_A]: "09:00-18:00" }, now: () => now },
    });
    q.start();
    assert.deepEqual(q.getDeliveryWindowStats(), []);
    q.enqueue(item("w4", URL_A));
    q.enqueue(item("w5", URL_A, "tenant-x"));
    await t.step();
    const stats = q.getDeliveryWindowStats();
    assert.equal(stats.length, 2);
    const byTenant = (tn?: string) => stats.find((s) => s.tenant === tn);
    const def = byTenant(undefined)!;
    assert.equal(def.endpoint, URL_A);
    assert.equal(def.window, "09:00-18:00");
    assert.equal(def.delayed, 1);
    assert.equal(def.open, false);
    const ten = byTenant("tenant-x")!;
    assert.equal(ten.endpoint, URL_A);
    assert.equal(ten.window, "09:00-18:00");
    assert.equal(ten.delayed, 1);
    now = at(12, 0);
    await t.step(); // 12:00, window open -> both delivered
    assert.equal(q.getDeliveryWindowStats().find((s) => s.tenant === undefined)?.open, true);
    q.stop();
  });

  it("supports runtime window overrides and leaves disabled queues alone", async () => {
    let now = at(2, 0);
    const t = manualTimer();
    let senderCalls = 0;
    const sender: Sender = async () => {
      senderCalls += 1;
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      deliveryWindow: { now: () => now }, // feature on, no windows yet
    });
    q.start();
    assert.equal(q.setEndpointDeliveryWindow(URL_A, "09:00-18:00"), true);
    q.enqueue(item("w6", URL_A));
    await t.step();
    assert.equal(senderCalls, 0); // parked by the runtime window
    assert.equal(q.getDeliveryWindowStats()[0].window, "09:00-18:00");
    assert.throws(() => q.setEndpointDeliveryWindow(URL_A, "bogus"), RangeError);
    assert.equal(q.deleteEndpointDeliveryWindow(URL_A), true);
    now = at(3, 0);
    await t.step(); // no window anymore -> goes out
    assert.equal(senderCalls, 1);
    q.stop();

    // Feature fully disabled: the runtime surface is a no-op.
    const q2 = new RetryQueue({ sender, setTimer: t.setTimer });
    q2.start();
    assert.equal(q2.setEndpointDeliveryWindow(URL_A, "09:00-18:00"), false);
    assert.equal(q2.deleteEndpointDeliveryWindow(URL_A), false);
    assert.deepEqual(q2.getDeliveryWindowStats(), []);
    q2.enqueue(item("w7", URL_A));
    await t.step();
    assert.equal(senderCalls, 2); // delivered immediately
    q2.stop();
  });

  it("rejects invalid window specs at construction", () => {
    assert.throws(
      () =>
        new RetryQueue({
          deliveryWindow: { windows: { [URL_A]: "not-a-window" } },
        }),
      RangeError
    );
  });

  it("payment-ops scenario: repayment reminders only go out in daytime", async () => {
    // The fintech ops use case: a repayment-reminder endpoint may only be
    // hit 09:00-18:00 UTC. Reminders generated overnight queue up and
    // flush exactly at 09:00 — none dropped, none dead-lettered, no retry
    // budget spent on a hold that was never a failure.
    let now = at(23, 30);
    const t = manualTimer();
    const delivered: string[] = [];
    const sender: Sender = async (it) => {
      delivered.push(it.id);
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      deliveryWindow: { windows: { [URL_A]: "09:00-18:00" }, now: () => now },
    });
    q.start();
    q.enqueue(item("reminder-1", URL_A));
    q.enqueue(item("reminder-2", URL_A));
    await t.step(); // 23:30: both parked
    assert.deepEqual(delivered, []);
    now = at(9, 0, 0); // next morning: "flush at window open"
    await t.step();
    assert.deepEqual(delivered, ["reminder-1", "reminder-2"]);
    q.stop();
  });
});
