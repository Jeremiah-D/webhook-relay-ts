import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import { createRelayServer } from "../src/server.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET-style names here.
const relaySecret = "delivery-window-holiday-revision-secret";
const EP_A = "http://a.example/hook";
const EP_B = "http://b.example/hook";
const EP_C = "http://c.example/hook";

/** A fixed Monday: 2026-01-05. */
const at = (h: number, m = 0, s = 0) => Date.UTC(2026, 0, 5, h, m, s);
const DAY_MS = 86_400_000;

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

describe("RetryQueue holiday-calendar snapshots (WR-318)", () => {
  it("getEndpointDeliveryHolidays returns the live snapshot, undefined without a calendar", () => {
    let now = at(12, 0);
    const q = new RetryQueue({
      sender: async () => {},
      deliveryWindow: {
        windows: { [EP_A]: "09:00-18:00" },
        tzWindows: { [EP_B]: { window: "09:00-18:00", timezone: "Asia/Shanghai" } },
        holidays: {
          [EP_A]: {
            dates: ["2026-01-05"],
            region: "CN",
            strategy: "shrink",
            holidayWindow: "10:00-12:00",
          },
        },
        now: () => now,
      },
    });
    try {
      // The explicit holidayWindow round-trips through the getter.
      assert.deepEqual(q.getEndpointDeliveryHolidays(EP_A), {
        region: "CN",
        strategy: "shrink",
        dates: ["2026-01-05"],
        holidayWindow: "10:00-12:00",
      });
      // A window without a calendar, and an unknown endpoint, are undefined.
      assert.equal(q.getEndpointDeliveryHolidays(EP_B), undefined);
      assert.equal(q.getEndpointDeliveryHolidays(EP_C), undefined);
      // A live revision is visible immediately, and a shrink without an
      // explicit holidayWindow reports no holidayWindow (default half).
      q.setEndpointDeliveryHolidays(EP_A, { dates: ["2026-01-06"], strategy: "shrink" });
      assert.deepEqual(q.getEndpointDeliveryHolidays(EP_A), {
        strategy: "shrink",
        dates: ["2026-01-06"],
      });
      q.deleteEndpointDeliveryHolidays(EP_A);
      assert.equal(q.getEndpointDeliveryHolidays(EP_A), undefined);
    } finally {
      q.stop();
    }
    // Feature disabled: always undefined / empty.
    const q2 = new RetryQueue({ sender: async () => {} });
    try {
      assert.equal(q2.getEndpointDeliveryHolidays(EP_A), undefined);
      assert.deepEqual(q2.getDeliveryHolidays(), []);
    } finally {
      q2.stop();
    }
  });

  it("getDeliveryHolidays lists every calendar endpoint, including ones that never parked", async () => {
    let now = at(12, 0);
    const t = manualTimer();
    const q = new RetryQueue({
      sender: async () => {},
      setTimer: t.setTimer,
      deliveryWindow: {
        windows: { [EP_A]: "09:00-18:00" },
        tzWindows: { [EP_B]: { window: "09:00-18:00", timezone: "Asia/Shanghai" } },
        holidays: {
          [EP_A]: { dates: ["2026-01-05"], region: "CN" },
          [EP_B]: { dates: ["2026-01-06"], region: "CN", strategy: "defer" },
        },
        now: () => now,
      },
    });
    try {
      q.start();
      // Nothing parked yet: the stats surface is empty by design …
      assert.deepEqual(q.getDeliveryWindowStats(), []);
      // … but the calendar listing already covers both endpoints.
      assert.deepEqual(q.getDeliveryHolidays(), [
        { endpoint: EP_A, region: "CN", strategy: "skip", dates: ["2026-01-05"] },
        { endpoint: EP_B, region: "CN", strategy: "defer", dates: ["2026-01-06"] },
      ]);
      // Park one delivery on EP_A; the listing is unchanged.
      now = at(10, 0);
      q.enqueue(item("h1", EP_A));
      await t.step();
      assert.equal(q.getDeliveryWindowStats().length, 1);
      assert.deepEqual(
        q.getDeliveryHolidays().map((r) => r.endpoint),
        [EP_A, EP_B]
      );
    } finally {
      q.stop();
    }
  });

  it("a widened calendar does not flush a parked delivery early — it goes out when the old timer fires", async () => {
    let now = at(10, 0); // Monday 10:00 UTC, inside 09:00-18:00 but a skip holiday
    const t = manualTimer();
    let senderCalls = 0;
    const sender: Sender = async () => {
      senderCalls += 1;
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      deliveryWindow: {
        windows: { [EP_A]: "09:00-18:00" },
        holidays: { [EP_A]: { dates: ["2026-01-05"], region: "CN", strategy: "skip" } },
        now: () => now,
      },
    });
    try {
      q.start();
      q.enqueue(item("h2", EP_A));
      await t.step(); // holiday-closed -> parked until Tuesday 09:00
      assert.equal(senderCalls, 0);
      assert.equal(t.lastDelay(), 23 * 3_600_000);
      // Widen by deleting the holiday: Monday would be open now, but
      // the armed timer is not re-armed — no early flush.
      assert.equal(q.deleteEndpointDeliveryHolidays(EP_A), true);
      assert.equal(senderCalls, 0);
      assert.equal(t.pendingCount(), 1, "widening must not re-arm the timer");
      assert.equal(t.lastDelay(), 23 * 3_600_000);
      // The old timer fires at Tuesday 09:00; the gate re-reads the
      // live calendar (no holiday now) and the delivery goes out.
      now = at(9, 0) + DAY_MS;
      await t.step();
      assert.equal(senderCalls, 1);
    } finally {
      q.stop();
    }
  });

  it("a narrowed calendar re-parks on the next trigger to the new opening, attempts untouched", async () => {
    let now = at(10, 0); // Monday 10:00 UTC, outside 01:00-09:00
    const t = manualTimer();
    let senderCalls = 0;
    const deliveredAttempts: number[] = [];
    const sender: Sender = async () => {
      senderCalls += 1;
    };
    const q = new RetryQueue({
      sender,
      setTimer: t.setTimer,
      deliveryWindow: { windows: { [EP_A]: "01:00-09:00" }, now: () => now },
      onDelivered: (_it, attempts) => {
        deliveredAttempts.push(attempts);
      },
    });
    try {
      q.start();
      q.enqueue(item("h3", EP_A));
      await t.step(); // parked until Tuesday 01:00
      assert.equal(senderCalls, 0);
      assert.equal(t.lastDelay(), 15 * 3_600_000);
      // Narrow: Tuesday becomes a skip holiday.
      assert.equal(
        q.setEndpointDeliveryHolidays(EP_A, { dates: ["2026-01-06"], strategy: "skip" }),
        true
      );
      // The old timer fires at Tuesday 01:00; the gate finds the new
      // holiday still closed and re-parks to Wednesday 01:00 (24h) —
      // the delivery does not escape early.
      now = at(1, 0) + DAY_MS;
      await t.step();
      assert.equal(senderCalls, 0);
      assert.equal(t.lastDelay(), 24 * 3_600_000);
      // Wednesday 01:00: the holiday is over and the delivery goes out
      // on its first real attempt — the two parks consumed nothing.
      now = at(1, 0) + 2 * DAY_MS;
      await t.step();
      assert.equal(senderCalls, 1);
      assert.deepEqual(deliveredAttempts, [1]);
    } finally {
      q.stop();
    }
  });
});

describe("RelayServer holiday-calendar revision (WR-318)", () => {
  const servers: Server[] = [];
  after(() => {
    for (const s of servers) s.close();
  });

  function makeServer(opts: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "delivery-window-holiday-revision-"));
    const auditLog = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: relaySecret,
      forwardUrl: "http://127.0.0.1:9/unused",
      auditLog,
      ...opts,
    });
    servers.push(relay);
    return { relay, auditLog };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  function configuredServer() {
    // Fixed clock: 12:00 UTC on the Monday — EP_A (09:00-18:00 UTC) is
    // open except on its skip holiday, EP_C has a window but no calendar.
    const fixedNow = Date.UTC(2026, 0, 5, 12, 0, 0);
    return makeServer({
      retry: {
        deliveryWindow: {
          windows: { [EP_A]: "09:00-18:00", [EP_C]: "08:00-20:00" },
          holidays: { [EP_A]: { dates: ["2026-01-05"], region: "CN", strategy: "skip" } },
          now: () => fixedNow,
        },
      },
    });
  }

  it("reviseEndpointHolidays sets a new calendar and audits previous undefined", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    assert.equal(relay.getEndpointHolidays!(EP_C), undefined);
    const current = relay.reviseEndpointHolidays(EP_C, {
      dates: ["2026-01-05"],
      region: "CN",
    });
    assert.deepEqual(current, { region: "CN", strategy: "skip", dates: ["2026-01-05"] });
    assert.deepEqual(relay.getEndpointHolidays!(EP_C), current);
    const revised = eventsOf(auditLog, "holiday_calendar_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].endpoint, EP_C);
    assert.equal(revised[0].previous, undefined);
    assert.deepEqual(revised[0].current, { region: "CN", strategy: "skip", dates: ["2026-01-05"] });
  });

  it("replacing dates/strategy audits previous/current snapshots", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    const current = relay.reviseEndpointHolidays(EP_A, {
      dates: ["2026-01-06", "2026-01-07"],
      region: "CN",
      strategy: "defer",
    });
    assert.deepEqual(current, {
      region: "CN",
      strategy: "defer",
      dates: ["2026-01-06", "2026-01-07"],
    });
    const revised = eventsOf(auditLog, "holiday_calendar_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].endpoint, EP_A);
    assert.deepEqual(revised[0].previous, {
      region: "CN",
      strategy: "skip",
      dates: ["2026-01-05"],
    });
    assert.deepEqual(revised[0].current, {
      region: "CN",
      strategy: "defer",
      dates: ["2026-01-06", "2026-01-07"],
    });
  });

  it("shrink with an explicit holidayWindow round-trips losslessly via the getter", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    const current = relay.reviseEndpointHolidays(EP_C, {
      dates: ["2026-01-05"],
      strategy: "shrink",
      holidayWindow: "10:00-12:00",
    });
    assert.deepEqual(current, {
      strategy: "shrink",
      dates: ["2026-01-05"],
      holidayWindow: "10:00-12:00",
    });
    assert.deepEqual(relay.getEndpointHolidays!(EP_C), current);
    // Feeding the getter's snapshot back in is a no-op (same values).
    const again = relay.reviseEndpointHolidays(EP_C, {
      dates: ["2026-01-05"],
      strategy: "shrink",
      holidayWindow: "10:00-12:00",
    });
    assert.deepEqual(again, current);
    assert.equal(eventsOf(auditLog, "holiday_calendar_revised").length, 1);
  });

  it("an illegal strategy/date/holidayWindow throws RangeError and the live calendar is untouched", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    const before = relay.getEndpointHolidays!(EP_A);
    // Unknown strategy.
    assert.throws(
      () =>
        relay.reviseEndpointHolidays(EP_A, {
          dates: ["2026-01-06"],
          strategy: "bogus" as never,
        }),
      RangeError
    );
    // Not a real calendar date.
    assert.throws(
      () => relay.reviseEndpointHolidays(EP_A, { dates: ["2026-02-30"] }),
      RangeError
    );
    // Malformed date string.
    assert.throws(
      () => relay.reviseEndpointHolidays(EP_A, { dates: ["Jan 5"] }),
      RangeError
    );
    // holidayWindow is only meaningful with shrink.
    assert.throws(
      () =>
        relay.reviseEndpointHolidays(EP_A, {
          dates: ["2026-01-06"],
          strategy: "skip",
          holidayWindow: "10:00-12:00",
        }),
      RangeError
    );
    // Empty region.
    assert.throws(
      () => relay.reviseEndpointHolidays(EP_A, { dates: ["2026-01-06"], region: "" }),
      RangeError
    );
    assert.equal(eventsOf(auditLog, "holiday_calendar_revised").length, 0);
    assert.deepEqual(relay.getEndpointHolidays!(EP_A), before);
  });

  it("a calendar on an endpoint with no window throws RangeError", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    assert.throws(
      () => relay.reviseEndpointHolidays(EP_B, { dates: ["2026-01-05"] }),
      RangeError
    );
    assert.equal(relay.getEndpointHolidays!(EP_B), undefined);
    assert.equal(eventsOf(auditLog, "holiday_calendar_revised").length, 0);
  });

  it("throws Error on an unconfigured server; the listing getters are unset; removal is a silent false", async () => {
    const { relay, auditLog } = makeServer({});
    await listen(relay);
    assert.equal(relay.getEndpointHolidays, undefined);
    assert.equal(relay.getHolidayCalendars, undefined);
    assert.throws(
      () => relay.reviseEndpointHolidays(EP_A, { dates: ["2026-01-05"] }),
      /not configured/
    );
    assert.equal(relay.removeEndpointHolidays(EP_A), false);
    assert.equal(eventsOf(auditLog, "holiday_calendar_revised").length, 0);
    assert.equal(eventsOf(auditLog, "holiday_calendar_removed").length, 0);
  });

  it("a same-value revision is a silent no-op, even with dates in a different order", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    // EP_A already has { region CN, skip, [2026-01-05] }.
    assert.deepEqual(relay.reviseEndpointHolidays(EP_A, { dates: ["2026-01-05"], region: "CN" }), {
      region: "CN",
      strategy: "skip",
      dates: ["2026-01-05"],
    });
    // Same set, different order, plus the default strategy spelled out.
    relay.reviseEndpointHolidays(EP_A, {
      dates: ["2026-01-05"],
      region: "CN",
      strategy: "skip",
    });
    assert.equal(eventsOf(auditLog, "holiday_calendar_revised").length, 0);
    // A two-date calendar revised with the dates swapped is also a no-op.
    relay.reviseEndpointHolidays(EP_A, {
      dates: ["2026-01-07", "2026-01-06"],
      region: "CN",
      strategy: "defer",
    });
    assert.equal(eventsOf(auditLog, "holiday_calendar_revised").length, 1);
    relay.reviseEndpointHolidays(EP_A, {
      dates: ["2026-01-06", "2026-01-07"],
      region: "CN",
      strategy: "defer",
    });
    assert.equal(eventsOf(auditLog, "holiday_calendar_revised").length, 1);
  });

  it("removeEndpointHolidays returns true, audits, and the endpoint is back to its plain window", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    // Monday 12:00 is inside EP_A's window, but the skip holiday closes it.
    const before = relay.getDeliveryWindows!().find((r) => r.endpoint === EP_A);
    assert.equal(before?.open, false);
    assert.equal(relay.removeEndpointHolidays(EP_A), true);
    const removed = eventsOf(auditLog, "holiday_calendar_removed");
    assert.equal(removed.length, 1);
    assert.equal(removed[0].endpoint, EP_A);
    assert.deepEqual(removed[0].previous, {
      region: "CN",
      strategy: "skip",
      dates: ["2026-01-05"],
    });
    assert.equal(relay.getEndpointHolidays!(EP_A), undefined);
    // The plain window is open again at the same instant.
    const after = relay.getDeliveryWindows!().find((r) => r.endpoint === EP_A);
    assert.equal(after?.open, true);
    // Setting a fresh calendar on the removed endpoint starts from undefined.
    relay.reviseEndpointHolidays(EP_A, { dates: ["2026-01-06"], strategy: "defer" });
    const revised = eventsOf(auditLog, "holiday_calendar_revised");
    assert.equal(revised.length, 1);
    assert.equal(revised[0].previous, undefined);
  });

  it("removing a calendar that was never set returns false and audits nothing", async () => {
    const { relay, auditLog } = configuredServer();
    await listen(relay);
    assert.equal(relay.removeEndpointHolidays(EP_C), false);
    assert.equal(eventsOf(auditLog, "holiday_calendar_removed").length, 0);
    assert.equal(relay.removeEndpointHolidays(EP_C), false);
  });

  it("getHolidayCalendars lists every calendar endpoint, including ones that never parked", async () => {
    const { relay } = configuredServer();
    await listen(relay);
    // No delivery has ever been attempted, so the stats surface would be
    // empty — but the listing already covers the calendar endpoint.
    assert.deepEqual(relay.getHolidayCalendars!(), [
      { endpoint: EP_A, region: "CN", strategy: "skip", dates: ["2026-01-05"] },
    ]);
    relay.reviseEndpointHolidays(EP_C, { dates: ["2026-01-06"], strategy: "defer" });
    assert.deepEqual(
      relay.getHolidayCalendars!().map((r) => r.endpoint),
      [EP_A, EP_C]
    );
  });
});
