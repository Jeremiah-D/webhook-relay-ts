import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { EndpointDeliveryWindow } from "../src/delivery-window.ts";

const URL_A = "http://localhost:9999/a";
const URL_B = "http://localhost:9999/b";

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

/** 2026-01-05 00:00 UTC = 2026-01-05 08:00 Asia/Shanghai (+8, no DST). */
const SH = { window: "09:00-18:00", timezone: "Asia/Shanghai" };
const atUTC = (y: number, mo: number, d: number, h: number, m = 0) => Date.UTC(y, mo, d, h, m, 0);

describe("WR-126 timezone-aware delivery windows", () => {
  it("evaluates the window against the zone's local wall clock, not UTC", () => {
    let now = atUTC(2026, 0, 5, 0, 0); // 08:00 Shanghai
    const w = new EndpointDeliveryWindow({ tzWindows: { [URL_A]: SH }, now: () => now });
    assert.equal(w.isOpen(URL_A), false); // 08:00 local, before open
    now = atUTC(2026, 0, 5, 1, 0); // 09:00 Shanghai: open edge inclusive
    assert.equal(w.isOpen(URL_A), true);
    now = atUTC(2026, 0, 5, 9, 59); // 17:59 Shanghai
    assert.equal(w.isOpen(URL_A), true);
    now = atUTC(2026, 0, 5, 10, 0); // 18:00 Shanghai: close edge exclusive
    assert.equal(w.isOpen(URL_A), false);
    // Contrast: the same spec in UTC is closed at 02:00 UTC.
    const utc = new EndpointDeliveryWindow({ windows: { [URL_B]: "09:00-18:00" }, now: () => now });
    now = atUTC(2026, 0, 5, 2, 0);
    assert.equal(utc.isOpen(URL_B), false);
    assert.equal(w.isOpen(URL_A), true); // 10:00 Shanghai
  });

  it("handles midnight-crossing timezone windows", () => {
    let now = atUTC(2026, 0, 5, 13, 0); // 21:00 Shanghai
    const w = new EndpointDeliveryWindow({
      tzWindows: { [URL_A]: { window: "22:00-06:00", timezone: "Asia/Shanghai" } },
      now: () => now,
    });
    assert.equal(w.isOpen(URL_A), false);
    now = atUTC(2026, 0, 5, 14, 0); // 22:00 Shanghai
    assert.equal(w.isOpen(URL_A), true);
    now = atUTC(2026, 0, 5, 21, 0); // 2026-01-06 05:00 Shanghai
    assert.equal(w.isOpen(URL_A), true);
    now = atUTC(2026, 0, 5, 22, 0); // 06:00 Shanghai: close edge exclusive
    assert.equal(w.isOpen(URL_A), false);
  });

  it("computes the wait until the window opens in the zone", () => {
    let now = atUTC(2026, 0, 5, 0, 0); // 08:00 Shanghai
    const w = new EndpointDeliveryWindow({ tzWindows: { [URL_A]: SH }, now: () => now });
    assert.equal(w.msUntilOpen(URL_A), 3_600_000); // 08:00 -> 09:00 local
    // The fired instant is inside the window (open edge inclusive).
    assert.equal(w.isOpen(URL_A, now + 3_600_000), true);
    now = atUTC(2026, 0, 5, 10, 0); // 18:00 Shanghai: past close -> next day 09:00
    assert.equal(w.msUntilOpen(URL_A), 15 * 3_600_000);
    assert.equal(w.isOpen(URL_A, now + 15 * 3_600_000), true);
  });

  it("spring-forward gap hours never match; the wait skips to the next day", () => {
    // America/New_York springs forward on 2026-03-08: 02:00 -> 03:00 local.
    // A window inside the gap can never open that day.
    let now = atUTC(2026, 2, 8, 6, 30); // 01:30 EST
    const w = new EndpointDeliveryWindow({
      tzWindows: { [URL_A]: { window: "02:00-03:00", timezone: "America/New_York" } },
      now: () => now,
    });
    assert.equal(w.isOpen(URL_A), false); // 01:30 local
    now = atUTC(2026, 2, 8, 7, 30); // 03:30 EDT: the gap is skipped
    assert.equal(w.isOpen(URL_A), false);
    now = atUTC(2026, 2, 8, 6, 30);
    // Next real opening: 2026-03-09 02:00 local = 06:00 UTC (EDT) -> 23.5h.
    assert.equal(w.msUntilOpen(URL_A), 84_600_000);
    assert.equal(w.isOpen(URL_A, now + 84_600_000), true);
  });

  it("a window spanning the spring-forward gap stays honest", () => {
    let now = atUTC(2026, 2, 8, 6, 30); // 01:30 EST
    const w = new EndpointDeliveryWindow({
      tzWindows: { [URL_A]: { window: "01:00-04:00", timezone: "America/New_York" } },
      now: () => now,
    });
    assert.equal(w.isOpen(URL_A), true); // 01:30 EST, inside
    now = atUTC(2026, 2, 8, 7, 30); // 03:30 EDT, inside (the gap is just skipped)
    assert.equal(w.isOpen(URL_A), true);
    now = atUTC(2026, 2, 8, 8, 0); // 04:00 EDT: close edge exclusive
    assert.equal(w.isOpen(URL_A), false);
  });

  it("fall-back repeated hours are indistinguishable (first occurrence opens)", () => {
    // America/New_York falls back on 2026-11-01: 02:00 EDT -> 01:00 EST.
    // The wall clock reads 01:30 twice; both map to the same minutes.
    const w = new EndpointDeliveryWindow({
      tzWindows: { [URL_A]: { window: "01:00-03:00", timezone: "America/New_York" } },
      now: () => atUTC(2026, 10, 1, 5, 30), // 01:30 EDT
    });
    assert.equal(w.isOpen(URL_A), true);
    assert.equal(w.isOpen(URL_A, atUTC(2026, 10, 1, 6, 30)), true); // 01:30 EST, repeated
  });

  it("rejects unknown IANA timezones at construction", () => {
    assert.throws(
      () =>
        new EndpointDeliveryWindow({
          tzWindows: { [URL_A]: { window: "09:00-18:00", timezone: "Mars/Olympus" } },
        }),
      RangeError
    );
    assert.throws(
      () =>
        new EndpointDeliveryWindow({
          tzWindows: { [URL_A]: { window: "09:00-18:00", timezone: "" } },
        }),
      RangeError
    );
  });

  it("a UTC window and a timezone window are mutually exclusive per endpoint", () => {
    assert.throws(
      () =>
        new EndpointDeliveryWindow({
          windows: { [URL_A]: "09:00-18:00" },
          tzWindows: { [URL_A]: SH },
        }),
      RangeError
    );
  });

  it("rejects malformed timezone window configs", () => {
    assert.throws(
      () =>
        new EndpointDeliveryWindow({
          tzWindows: { [URL_A]: { window: "bogus", timezone: "Asia/Shanghai" } },
        }),
      RangeError
    );
    assert.throws(
      () =>
        new EndpointDeliveryWindow({
          tzWindows: { [URL_A]: { timezone: "Asia/Shanghai" } as never },
        }),
      RangeError
    );
    assert.throws(
      () =>
        new EndpointDeliveryWindow({
          tzWindows: { [URL_A]: "09:00-18:00" as never },
        }),
      RangeError
    );
  });

  it("supports runtime timezone windows with the same hot-reload convention", () => {
    let now = atUTC(2026, 0, 5, 0, 0);
    const w = new EndpointDeliveryWindow({ now: () => now });
    assert.equal(w.isOpen(URL_A), true);
    w.setEndpointTzWindow(URL_A, "09:00-18:00", "Asia/Shanghai");
    assert.equal(w.isOpen(URL_A), false); // 08:00 Shanghai
    assert.equal(w.timezoneFor(URL_A), "Asia/Shanghai");
    // A UTC window cannot be set on a timezone-windowed endpoint (and vice versa).
    assert.throws(() => w.setEndpointWindow(URL_A, "09:00-18:00"), RangeError);
    assert.equal(w.isOpen(URL_A), false); // current window intact
    assert.throws(() => w.setEndpointTzWindow(URL_A, "bogus", "Asia/Shanghai"), RangeError);
    assert.throws(() => w.setEndpointTzWindow(URL_A, "09:00-18:00", "Mars/Olympus"), RangeError);
    assert.equal(w.deleteEndpointWindow(URL_A), true);
    assert.equal(w.isOpen(URL_A), true);
    assert.equal(w.timezoneFor(URL_A), undefined);
    // After deletion a UTC window may be set.
    w.setEndpointWindow(URL_A, "09:00-18:00");
    assert.throws(() => w.setEndpointTzWindow(URL_A, "09:00-18:00", "Asia/Shanghai"), RangeError);
    assert.equal(w.deleteEndpointWindow(URL_A), true);
    assert.equal(w.deleteEndpointWindow(URL_A), false);
  });
});

describe("RetryQueue timezone delivery windows (WR-126)", () => {
  it("parks until the timezone window opens, then flushes at the open edge", async () => {
    // 2026-01-05 00:00 UTC = 08:00 Shanghai; the window opens 09:00 local = 01:00 UTC.
    let now = atUTC(2026, 0, 5, 0, 0);
    const t = manualTimer();
    const delivered: string[] = [];
    const sender: Sender = async (it) => {
      delivered.push(it.id);
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      deliveryWindow: { tzWindows: { [URL_A]: SH }, now: () => now },
    });
    q.start();
    q.enqueue(item("tz-1", URL_A));
    await t.step(); // 08:00 Shanghai: parked, no send
    assert.deepEqual(delivered, []);
    assert.equal(t.lastDelay(), 3_600_000); // re-scheduled for the local opening instant
    now = atUTC(2026, 0, 5, 1, 0); // 09:00 Shanghai: "flush at window open"
    await t.step();
    assert.deepEqual(delivered, ["tz-1"]);
    q.stop();
  });

  it("payment-ops scenario: repayment reminders go out 09:00-18:00 borrower-local", async () => {
    // The cross-border ops use case: reminders must reach borrowers in
    // daytime *their* time. A UTC window cannot express this.
    let now = atUTC(2026, 0, 5, 15, 0); // 23:00 Shanghai
    const t = manualTimer();
    const delivered: string[] = [];
    const sender: Sender = async (it) => {
      delivered.push(it.id);
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      deliveryWindow: { tzWindows: { [URL_A]: SH }, now: () => now },
    });
    q.start();
    q.enqueue(item("reminder-1", URL_A));
    await t.step(); // 23:00 Shanghai: parked
    assert.deepEqual(delivered, []);
    // 02:00 UTC next day is 10:00 Shanghai — inside the window.
    now = atUTC(2026, 0, 6, 1, 0); // 09:00 Shanghai next day: flush
    await t.step();
    assert.deepEqual(delivered, ["reminder-1"]);
    // Stats rows carry the effective timezone.
    const stats = q.getDeliveryWindowStats();
    assert.equal(stats.length, 1);
    assert.equal(stats[0].endpoint, URL_A);
    assert.equal(stats[0].window, "09:00-18:00");
    assert.equal(stats[0].timezone, "Asia/Shanghai");
    assert.equal(stats[0].delayed, 1);
    q.stop();
  });

  it("UTC-windowed and unwindowed endpoints are unaffected", async () => {
    let now = atUTC(2026, 0, 5, 0, 0);
    const t = manualTimer();
    let senderCalls = 0;
    const sender: Sender = async () => {
      senderCalls += 1;
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      deliveryWindow: {
        windows: { [URL_A]: "00:00-23:59" }, // UTC, always open here
        tzWindows: { [URL_B]: SH }, // 08:00 Shanghai: closed
        now: () => now,
      },
    });
    q.start();
    q.enqueue(item("u1", URL_A));
    q.enqueue(item("t1", URL_B));
    await t.step();
    assert.equal(senderCalls, 1); // only the UTC-windowed item went out
    const stats = q.getDeliveryWindowStats();
    // URL_A's UTC window was open: it never parked, so it has no row.
    assert.equal(stats.find((s) => s.endpoint === URL_A), undefined);
    const rowB = stats.find((s) => s.endpoint === URL_B)!;
    assert.equal(rowB.timezone, "Asia/Shanghai");
    assert.equal(rowB.delayed, 1);
    q.stop();
  });

  it("queue-level timezone hot-reload follows the UTC convention", async () => {
    let now = atUTC(2026, 0, 5, 0, 0);
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
    assert.equal(q.setEndpointTzDeliveryWindow(URL_A, "09:00-18:00", "Asia/Shanghai"), true);
    q.enqueue(item("tz-2", URL_A));
    await t.step();
    assert.equal(senderCalls, 0); // parked by the runtime timezone window
    assert.equal(q.getDeliveryWindowStats()[0].timezone, "Asia/Shanghai");
    assert.equal(q.deleteEndpointDeliveryWindow(URL_A), true);
    await t.step();
    assert.equal(senderCalls, 1);
    q.stop();

    // Feature fully disabled: the runtime surface is a no-op.
    const q2 = new RetryQueue({ sender, setTimer: t.setTimer });
    q2.start();
    assert.equal(q2.setEndpointTzDeliveryWindow(URL_A, "09:00-18:00", "Asia/Shanghai"), false);
    q2.enqueue(item("tz-3", URL_A));
    await t.step();
    assert.equal(senderCalls, 2);
    q2.stop();
  });

  it("rejects timezone windows at queue construction", () => {
    assert.throws(
      () =>
        new RetryQueue({
          deliveryWindow: {
            tzWindows: { [URL_A]: { window: "09:00-18:00", timezone: "Mars/Olympus" } },
          },
        }),
      RangeError
    );
    assert.throws(
      () =>
        new RetryQueue({
          deliveryWindow: {
            windows: { [URL_A]: "09:00-18:00" },
            tzWindows: { [URL_A]: SH },
          },
        }),
      RangeError
    );
  });
});
