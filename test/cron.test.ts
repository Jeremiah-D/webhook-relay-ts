import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  CRON_HEADER,
  parseCronExpression,
  nextCronOccurrence,
  type CronExpression,
} from "../src/cron.ts";

const utc = (y: number, mo: number, d: number, h = 0, mi = 0, s = 0) =>
  Date.UTC(y, mo - 1, d, h, mi, s);

describe("WR-80 cron parser", () => {
  it("exposes the x-schedule-cron header name", () => {
    assert.equal(CRON_HEADER, "x-schedule-cron");
  });

  it("parses the all-wildcard expression", () => {
    const e = parseCronExpression("* * * * *");
    assert.deepEqual(e.minute, [...Array(60).keys()]);
    assert.deepEqual(e.hour, [...Array(24).keys()]);
    assert.equal(e.dayOfMonth.length, 31);
    assert.equal(e.month.length, 12);
    assert.deepEqual(e.dayOfWeek, [0, 1, 2, 3, 4, 5, 6]);
    assert.equal(e.dayOfMonthRestricted, false);
    assert.equal(e.dayOfWeekRestricted, false);
    assert.equal(e.source, "* * * * *");
  });

  it("parses steps, lists, and ranges", () => {
    const e = parseCronExpression("*/15 9-17 * * 1-5");
    assert.deepEqual(e.minute, [0, 15, 30, 45]);
    assert.deepEqual(e.hour, [9, 10, 11, 12, 13, 14, 15, 16, 17]);
    assert.deepEqual(e.dayOfWeek, [1, 2, 3, 4, 5]);
    assert.equal(e.dayOfWeekRestricted, true);
  });

  it("parses comma lists and ranged steps", () => {
    const e = parseCronExpression("0,30 8 1,15 1-6/2 0,6");
    assert.deepEqual(e.minute, [0, 30]);
    assert.deepEqual(e.hour, [8]);
    assert.deepEqual(e.dayOfMonth, [1, 15]);
    assert.deepEqual(e.month, [1, 3, 5]);
    assert.deepEqual(e.dayOfWeek, [0, 6]);
  });

  it("normalizes day-of-week 7 to Sunday 0", () => {
    const e = parseCronExpression("0 0 * * 7");
    assert.deepEqual(e.dayOfWeek, [0]);
  });

  it("tolerates extra whitespace", () => {
    const e = parseCronExpression("  0   9  *  *   *  ");
    assert.deepEqual(e.minute, [0]);
    assert.deepEqual(e.hour, [9]);
    // source keeps the verbatim (trimmed) input — audit shows what was sent.
    assert.equal(e.source, "0   9  *  *   *");
  });

  it("accepts an array header value (first wins)", () => {
    const e = parseCronExpression(["0 12 * * *", "0 13 * * *"]);
    assert.deepEqual(e.hour, [12]);
  });

  it("rejects wrong field counts", () => {
    assert.throws(() => parseCronExpression("* * * *"), RangeError);
    assert.throws(() => parseCronExpression("* * * * * *"), RangeError);
    assert.throws(() => parseCronExpression(""), RangeError);
    assert.throws(() => parseCronExpression(undefined), RangeError);
  });

  it("rejects out-of-range values", () => {
    assert.throws(() => parseCronExpression("60 * * * *"), RangeError);
    assert.throws(() => parseCronExpression("* 24 * * *"), RangeError);
    assert.throws(() => parseCronExpression("* * 0 * *"), RangeError);
    assert.throws(() => parseCronExpression("* * 32 * *"), RangeError);
    assert.throws(() => parseCronExpression("* * * 0 *"), RangeError);
    assert.throws(() => parseCronExpression("* * * 13 *"), RangeError);
    assert.throws(() => parseCronExpression("* * * * 8"), RangeError);
    assert.throws(() => parseCronExpression("1-70 * * * *"), RangeError);
  });

  it("rejects zero steps, reversed ranges, and garbage", () => {
    assert.throws(() => parseCronExpression("*/0 * * * *"), RangeError);
    assert.throws(() => parseCronExpression("*/* * * * *"), RangeError);
    assert.throws(() => parseCronExpression("5-1 * * * *"), RangeError);
    assert.throws(() => parseCronExpression("abc * * * *"), RangeError);
    assert.throws(() => parseCronExpression("* * * * mon"), RangeError);
    assert.throws(() => parseCronExpression("1.5 * * * *"), RangeError);
    assert.throws(() => parseCronExpression("*, * * * *"), RangeError);
    assert.throws(() => parseCronExpression("-1 * * * *"), RangeError);
  });

  it("rejects a non-string step and double slashes", () => {
    assert.throws(() => parseCronExpression("0//5 * * * *"), RangeError);
    assert.throws(() => parseCronExpression("*/x * * * *"), RangeError);
  });
});

describe("WR-80 nextCronOccurrence", () => {
  const expr = (s: string): CronExpression => parseCronExpression(s);

  it("finds the next fire strictly after the instant", () => {
    // Monday 2026-10-12 08:00:00 UTC.
    const from = utc(2026, 10, 12, 8, 0, 0);
    assert.equal(nextCronOccurrence(expr("0 9 * * *"), from), utc(2026, 10, 12, 9, 0, 0));
    // Exactly on a fire instant: strictly after, so next day.
    assert.equal(
      nextCronOccurrence(expr("0 9 * * *"), utc(2026, 10, 12, 9, 0, 0)),
      utc(2026, 10, 13, 9, 0, 0)
    );
    // Mid-minute: the current minute is already past.
    assert.equal(
      nextCronOccurrence(expr("0 9 * * *"), utc(2026, 10, 12, 9, 0, 30)),
      utc(2026, 10, 13, 9, 0, 0)
    );
  });

  it("handles steps within the hour", () => {
    assert.equal(
      nextCronOccurrence(expr("*/15 * * * *"), utc(2026, 10, 12, 10, 7, 0)),
      utc(2026, 10, 12, 10, 15, 0)
    );
    assert.equal(
      nextCronOccurrence(expr("*/15 * * * *"), utc(2026, 10, 12, 10, 45, 0)),
      utc(2026, 10, 12, 11, 0, 0)
    );
  });

  it("applies the classic day-of-month OR day-of-week rule", () => {
    // 2026-10-12 is a Monday. Next Sunday is 10-18, next 1st is 11-01.
    assert.equal(
      nextCronOccurrence(expr("0 0 1 * 0"), utc(2026, 10, 12, 0, 0, 0)),
      utc(2026, 10, 18, 0, 0, 0)
    );
    // Only day-of-week restricted: next Sunday.
    assert.equal(
      nextCronOccurrence(expr("30 6 * * 0"), utc(2026, 10, 12, 0, 0, 0)),
      utc(2026, 10, 18, 6, 30, 0)
    );
    // Only day-of-month restricted: the 1st.
    assert.equal(
      nextCronOccurrence(expr("0 0 1 * *"), utc(2026, 10, 12, 0, 0, 0)),
      utc(2026, 11, 1, 0, 0, 0)
    );
  });

  it("treats day-of-week 7 as Sunday", () => {
    assert.equal(
      nextCronOccurrence(expr("0 0 * * 7"), utc(2026, 10, 12, 0, 0, 0)),
      utc(2026, 10, 18, 0, 0, 0)
    );
  });

  it("finds February 29th across non-leap years", () => {
    assert.equal(
      nextCronOccurrence(expr("0 0 29 2 *"), utc(2026, 1, 1)),
      utc(2028, 2, 29, 0, 0, 0)
    );
  });

  it("throws on impossible dates and non-finite instants", () => {
    assert.throws(() => nextCronOccurrence(expr("0 0 30 2 *"), utc(2026, 1, 1)), Error);
    assert.throws(() => nextCronOccurrence(expr("* * * * *"), NaN), RangeError);
    assert.throws(() => nextCronOccurrence(expr("* * * * *"), Infinity), RangeError);
  });

  it("is deterministic for the same inputs", () => {
    const e = expr("7 3 * * 2,4");
    const from = utc(2026, 10, 12, 12, 0, 0);
    assert.equal(nextCronOccurrence(e, from), nextCronOccurrence(e, from));
  });
});
