import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { EndpointDeliveryWindow } from "../src/delivery-window.ts";

const URL_A = "http://localhost:9999/a";
const URL_B = "http://localhost:9999/b";

/** 2026-01-05 is a Monday. */
const atUTC = (y: number, mo: number, d: number, h: number, m = 0) => Date.UTC(y, mo, d, h, m, 0);

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

function item(id: string, targetUrl: string) {
  return { id, payload: Buffer.from("x"), targetUrl, headers: {} };
}

describe("WR-208 holiday calendars", () => {
  it("skip closes the whole holiday day and jumps to the next non-holiday opening", () => {
    let now = atUTC(2026, 0, 5, 10, 0); // Monday 10:00 UTC, inside 09:00-18:00
    const w = new EndpointDeliveryWindow({
      windows: { [URL_A]: "09:00-18:00" },
      holidays: { [URL_A]: { dates: ["2026-01-05"], region: "CN", strategy: "skip" } },
      now: () => now,
    });
    assert.equal(w.isOpen(URL_A), false);
    assert.equal(w.isHoliday(URL_A), true);
    assert.deepEqual(w.holidayInfo(URL_A), {
      region: "CN",
      strategy: "skip",
      dates: ["2026-01-05"],
    });
    // Monday 10:00 -> Tuesday 09:00 = 23h.
    assert.equal(w.msUntilOpen(URL_A), 23 * 3_600_000);
    assert.equal(w.isOpen(URL_A, now + 23 * 3_600_000), true);
    // Before the holiday window opens, skip still jumps past the day.
    now = atUTC(2026, 0, 5, 8, 0);
    assert.equal(w.msUntilOpen(URL_A), 25 * 3_600_000); // Monday 08:00 -> Tuesday 09:00
    // A non-holiday day is untouched.
    assert.equal(w.isOpen(URL_A, atUTC(2026, 0, 6, 10, 0)), true);
    assert.equal(w.isHoliday(URL_A, atUTC(2026, 0, 6, 10, 0)), false);
  });

  it("skip jumps over a multi-day holiday stretch", () => {
    const w = new EndpointDeliveryWindow({
      windows: { [URL_A]: "09:00-18:00" },
      holidays: { [URL_A]: { dates: ["2026-01-05", "2026-01-06"] } },
      now: () => atUTC(2026, 0, 5, 8, 0),
    });
    // Monday 08:00 -> Wednesday 09:00 = 49h.
    assert.equal(w.msUntilOpen(URL_A), 49 * 3_600_000);
    assert.equal(w.isOpen(URL_A, atUTC(2026, 0, 5, 8, 0) + 49 * 3_600_000), true);
  });

  it("defer parks only to the next window opening and re-evaluates there", () => {
    const w = new EndpointDeliveryWindow({
      windows: { [URL_A]: "09:00-18:00" },
      holidays: { [URL_A]: { dates: ["2026-01-05", "2026-01-06"], strategy: "defer" } },
      now: () => atUTC(2026, 0, 5, 8, 0),
    });
    assert.equal(w.isOpen(URL_A), false);
    // Before today's opening: defer goes to today's opening (then re-parks).
    assert.equal(w.msUntilOpen(URL_A), 3_600_000);
    // Inside the holiday window: the next opening is Tuesday's (also a
    // holiday — defer does not jump over it, the gate re-evaluates).
    assert.equal(w.msUntilOpen(URL_A, atUTC(2026, 0, 5, 10, 0)), 23 * 3_600_000);
    assert.equal(w.isOpen(URL_A, atUTC(2026, 0, 6, 9, 0)), false);
  });

  it("shrink without holidayWindow halves the window from its open edge", () => {
    let now = atUTC(2026, 0, 5, 12, 0); // Monday 12:00 UTC
    const w = new EndpointDeliveryWindow({
      windows: { [URL_A]: "09:00-18:00" },
      holidays: { [URL_A]: { dates: ["2026-01-05"], strategy: "shrink" } },
      now: () => now,
    });
    // Halved 09:00-18:00 is 09:00-13:30.
    assert.equal(w.isOpen(URL_A), true);
    now = atUTC(2026, 0, 5, 14, 0);
    assert.equal(w.isOpen(URL_A), false);
    // After the shrunken close: next opening is Tuesday 09:00 = 19h.
    assert.equal(w.msUntilOpen(URL_A), 19 * 3_600_000);
    // Before the shrunken opening: today's 09:00.
    assert.equal(w.msUntilOpen(URL_A, atUTC(2026, 0, 5, 8, 0)), 3_600_000);
  });

  it("shrink with an explicit holidayWindow replaces the window on holidays", () => {
    const w = new EndpointDeliveryWindow({
      windows: { [URL_A]: "09:00-18:00" },
      holidays: {
        [URL_A]: { dates: ["2026-01-05"], strategy: "shrink", holidayWindow: "10:00-12:00" },
      },
      now: () => atUTC(2026, 0, 5, 9, 30),
    });
    assert.equal(w.isOpen(URL_A), false); // before the holiday window
    assert.equal(w.isOpen(URL_A, atUTC(2026, 0, 5, 11, 0)), true);
    assert.equal(w.isOpen(URL_A, atUTC(2026, 0, 5, 13, 0)), false);
    // A non-holiday day keeps the normal window.
    assert.equal(w.isOpen(URL_A, atUTC(2026, 0, 6, 9, 30)), true);
  });

  it("uses the zone's local date for timezone windows", () => {
    // 2026-01-05 is a Shanghai holiday; 2026-01-05 10:00 Shanghai =
    // 2026-01-05 02:00 UTC (inside 09:00-18:00 local).
    let now = atUTC(2026, 0, 5, 2, 0);
    const w = new EndpointDeliveryWindow({
      tzWindows: { [URL_A]: { window: "09:00-18:00", timezone: "Asia/Shanghai" } },
      holidays: { [URL_A]: { dates: ["2026-01-05"] } },
      now: () => now,
    });
    assert.equal(w.isHoliday(URL_A), true);
    assert.equal(w.isOpen(URL_A), false);
    // Skip jumps to the next non-holiday local opening: Jan 6 09:00
    // Shanghai = Jan 6 01:00 UTC = 23h later.
    assert.equal(w.msUntilOpen(URL_A), 23 * 3_600_000);
    assert.equal(w.isOpen(URL_A, now + 23 * 3_600_000), true);
    // The same UTC instant on a non-holiday local date is open.
    now = atUTC(2026, 0, 6, 2, 0); // Jan 6 10:00 Shanghai
    assert.equal(w.isHoliday(URL_A), false);
    assert.equal(w.isOpen(URL_A), true);
  });

  it("rejects malformed calendars at construction", () => {
    const base = { windows: { [URL_A]: "09:00-18:00" } };
    assert.throws(
      () =>
        new EndpointDeliveryWindow({
          ...base,
          holidays: { [URL_A]: { dates: ["2026-02-30"] } },
        }),
      RangeError
    );
    assert.throws(
      () =>
        new EndpointDeliveryWindow({
          ...base,
          holidays: { [URL_A]: { dates: ["2026-1-5"] } },
        }),
      RangeError
    );
    assert.throws(
      () =>
        new EndpointDeliveryWindow({
          ...base,
          holidays: { [URL_A]: { dates: ["2026-01-05"], strategy: "drop" as never } },
        }),
      RangeError
    );
    assert.throws(
      () =>
        new EndpointDeliveryWindow({
          ...base,
          holidays: {
            [URL_A]: { dates: ["2026-01-05"], strategy: "skip", holidayWindow: "10:00-12:00" },
          },
        }),
      RangeError
    );
    // A calendar without a window is a silent no-op — so it throws.
    assert.throws(
      () =>
        new EndpointDeliveryWindow({
          holidays: { [URL_A]: { dates: ["2026-01-05"] } },
        }),
      RangeError
    );
    // A calendar on a different endpoint than the window also throws.
    assert.throws(
      () =>
        new EndpointDeliveryWindow({
          ...base,
          holidays: { [URL_B]: { dates: ["2026-01-05"] } },
        }),
      RangeError
    );
  });

  it("supports runtime calendars with the same hot-reload convention", () => {
    let now = atUTC(2026, 0, 5, 10, 0);
    const w = new EndpointDeliveryWindow({
      windows: { [URL_A]: "09:00-18:00" },
      now: () => now,
    });
    assert.equal(w.isOpen(URL_A), true);
    w.setEndpointHolidays(URL_A, { dates: ["2026-01-05"], region: "CN" });
    assert.equal(w.isOpen(URL_A), false); // skip holiday
    // An invalid calendar leaves the current one intact.
    assert.throws(() => w.setEndpointHolidays(URL_A, { dates: ["2026-02-30"] }), RangeError);
    assert.equal(w.isOpen(URL_A), false);
    assert.throws(() => w.setEndpointHolidays(URL_B, { dates: ["2026-01-05"] }), RangeError);
    assert.equal(w.deleteEndpointHolidays(URL_A), true);
    assert.equal(w.isOpen(URL_A), true);
    assert.equal(w.deleteEndpointHolidays(URL_A), false);
    // Deleting the window also deletes its calendar.
    w.setEndpointHolidays(URL_A, { dates: ["2026-01-05"] });
    assert.equal(w.deleteEndpointWindow(URL_A), true);
    assert.equal(w.holidayInfo(URL_A), undefined);
    assert.equal(w.isOpen(URL_A), true);
  });

  it("parks a queue delivery on a holiday until the next non-holiday opening", async () => {
    let now = atUTC(2026, 0, 5, 10, 0); // Monday 10:00 UTC, holiday
    const t = manualTimer();
    const delivered: string[] = [];
    const sender: Sender = async (it) => {
      delivered.push(it.id);
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      deliveryWindow: {
        windows: { [URL_A]: "09:00-18:00" },
        holidays: { [URL_A]: { dates: ["2026-01-05"] } },
        now: () => now,
      },
    });
    q.start();
    q.enqueue(item("hol-1", URL_A));
    await t.step(); // holiday: parked, no send
    assert.deepEqual(delivered, []);
    assert.equal(t.lastDelay(), 23 * 3_600_000); // re-scheduled for Tuesday 09:00
    now = atUTC(2026, 0, 6, 9, 0); // Tuesday 09:00: "flush at window open"
    await t.step();
    assert.deepEqual(delivered, ["hol-1"]);
    // Stats surface the calendar.
    const stats = q.getDeliveryWindowStats();
    assert.equal(stats[0]?.holidayStrategy, "skip");
    assert.equal(stats[0]?.open, true);
  });
});
