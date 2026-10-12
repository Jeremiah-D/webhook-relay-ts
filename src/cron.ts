/**
 * WR-80: recurring scheduled delivery — a zero-dependency 5-field cron
 * parser (minute hour day-of-month month day-of-week) plus next-occurrence
 * computation.
 *
 * Supported field shapes: `*`, `*\/n`, `n`, `n-m`, `n-m/s`, and comma
 * lists of those atoms. Everything is numeric — month/day names are not
 * accepted, so a typo like `mon` fails loudly instead of misfiring.
 * Anything invalid throws `RangeError` (fail-fast at intake, never
 * mid-schedule).
 *
 * Bounds: minute 0-59, hour 0-23, day-of-month 1-31, month 1-12,
 * day-of-week 0-7 (both 0 and 7 mean Sunday; 7 is normalized to 0).
 * Steps must be >= 1, ranges must satisfy n <= m, and every value must sit
 * inside its field's bounds.
 *
 * Occurrence semantics are classic cron: the minute and hour must match,
 * and for the day either the day-of-month matches OR the day-of-week
 * matches (when only one of them is restricted, that one decides; when
 * neither is restricted, every day matches). All evaluation is in UTC and
 * `nextCronOccurrence` returns the first fire instant *strictly after*
 * the given instant, at second 0 of the minute.
 */

/** Inbound header registering a recurring cron schedule (WR-80). */
export const CRON_HEADER = "x-schedule-cron";

/** Field bounds in field order: minute, hour, day-of-month, month, day-of-week. */
const FIELD_BOUNDS: Array<{ name: string; min: number; max: number }> = [
  { name: "minute", min: 0, max: 59 },
  { name: "hour", min: 0, max: 23 },
  { name: "day-of-month", min: 1, max: 31 },
  { name: "month", min: 1, max: 12 },
  { name: "day-of-week", min: 0, max: 7 },
];

/** A parsed cron expression: sorted allowed values per field, in UTC. */
export interface CronExpression {
  minute: number[];
  hour: number[];
  dayOfMonth: number[];
  month: number[];
  dayOfWeek: number[];
  /** True when the field is restricted (not the full range). Drives the classic dom/dow OR. */
  dayOfMonthRestricted: boolean;
  dayOfWeekRestricted: boolean;
  /** The original expression text (for operator display / audit). */
  source: string;
}

function fail(expr: string, why: string): never {
  throw new RangeError(`invalid cron expression ${JSON.stringify(expr)}: ${why}`);
}

/** Parse one atom (`*`, `*\/n`, `n`, `n-m`, `n-m/s`) into its value set. */
function parseAtom(atom: string, bound: { name: string; min: number; max: number }, expr: string): Set<number> {
  const out = new Set<number>();
  const addRange = (from: number, to: number, step: number) => {
    if (!Number.isInteger(step) || step < 1) {
      fail(expr, `${bound.name}: step must be a positive integer, got ${JSON.stringify(atom)}`);
    }
    if (from > to) {
      fail(expr, `${bound.name}: reversed range in ${JSON.stringify(atom)}`);
    }
    for (let v = from; v <= to; v += step) out.add(v);
  };
  if (atom === "*") {
    addRange(bound.min, bound.max, 1);
    return out;
  }
  const stepSplit = atom.split("/");
  if (stepSplit.length > 2) fail(expr, `${bound.name}: too many '/' in ${JSON.stringify(atom)}`);
  const base = stepSplit[0];
  const step = stepSplit.length === 2 ? Number(stepSplit[1]) : 1;
  if (stepSplit.length === 2 && (!/^\d+$/.test(stepSplit[1]) || step < 1)) {
    fail(expr, `${bound.name}: step must be a positive integer, got ${JSON.stringify(atom)}`);
  }
  if (base === "*") {
    addRange(bound.min, bound.max, step);
    return out;
  }
  const rangeSplit = base.split("-");
  if (rangeSplit.length > 2 || !/^\d+$/.test(rangeSplit[0]) || (rangeSplit[1] !== undefined && !/^\d+$/.test(rangeSplit[1]))) {
    fail(expr, `${bound.name}: expected a number or n-m range, got ${JSON.stringify(atom)}`);
  }
  const from = Number(rangeSplit[0]);
  const to = rangeSplit[1] === undefined ? from : Number(rangeSplit[1]);
  if (from < bound.min || to > bound.max) {
    fail(expr, `${bound.name}: value out of range ${bound.min}-${bound.max} in ${JSON.stringify(atom)}`);
  }
  addRange(from, to, step);
  return out;
}

/** Parse one comma-separated field into its sorted allowed values. */
function parseField(field: string, bound: { name: string; min: number; max: number }, expr: string): number[] {
  if (field.length === 0) fail(expr, `${bound.name}: empty field`);
  const values = new Set<number>();
  for (const atom of field.split(",")) {
    if (atom.length === 0) fail(expr, `${bound.name}: empty list element`);
    for (const v of parseAtom(atom, bound, expr)) values.add(v);
  }
  const sorted = [...values].sort((a, b) => a - b);
  // day-of-week: normalize 7 (Sunday) to 0.
  if (bound.name === "day-of-week" && sorted.includes(7)) {
    return [...new Set(sorted.map((v) => (v === 7 ? 0 : v)))].sort((a, b) => a - b);
  }
  return sorted;
}

/**
 * Parse a 5-field cron expression (`minute hour day-of-month month
 * day-of-week`). Returns the structured expression; throws `RangeError`
 * on anything invalid — wrong field count, bad atoms, out-of-range
 * values, zero steps, or reversed ranges.
 */
export function parseCronExpression(value: string | string[] | undefined): CronExpression {
  const raw = Array.isArray(value) ? value[0] : value;
  if (raw === undefined || raw.trim().length === 0) {
    fail(String(value), "expression must not be empty");
  }
  const source = raw.trim();
  const fields = source.split(/\s+/);
  if (fields.length !== 5) {
    fail(source, `expected 5 fields (minute hour day-of-month month day-of-week), got ${fields.length}`);
  }
  const [minute, hour, dayOfMonth, month, dayOfWeek] = fields.map((f, i) =>
    parseField(f, FIELD_BOUNDS[i], source)
  );
  // Full-range test on the *normalized* values: day-of-week 7 is folded to
  // 0, so a wildcard dow holds 7 values (0-6), not 8.
  const full = (vals: number[], size: number) => vals.length === size;
  return {
    minute,
    hour,
    dayOfMonth,
    month,
    dayOfWeek,
    dayOfMonthRestricted: !full(dayOfMonth, 31),
    dayOfWeekRestricted: !full(dayOfWeek, 7),
    source,
  };
}

/**
 * The first cron fire instant *strictly after* `fromMs` (epoch ms), at
 * second 0 of the matching minute, evaluated in UTC. Pure and
 * deterministic — no clock reads. Throws `RangeError` on a non-finite
 * `fromMs`, and `Error` when no occurrence exists within 5 years (e.g.
 * `0 0 30 2 *` — February 30th never comes; the parse stays permissive
 * like classic cron, the schedule just never fires).
 */
export function nextCronOccurrence(expr: CronExpression, fromMs: number): number {
  if (!Number.isFinite(fromMs)) {
    throw new RangeError(`nextCronOccurrence: fromMs must be finite, got ${String(fromMs)}`);
  }
  const minutes = new Set(expr.minute);
  const hours = new Set(expr.hour);
  const months = new Set(expr.month);
  const doms = new Set(expr.dayOfMonth);
  const dows = new Set(expr.dayOfWeek);
  // First whole minute strictly after fromMs.
  let t = (Math.floor(fromMs / 60000) + 1) * 60000;
  const cap = 366 * 5 * 24 * 60; // 5 years of minutes
  for (let i = 0; i < cap; i++, t += 60000) {
    const d = new Date(t);
    if (!minutes.has(d.getUTCMinutes())) continue;
    if (!hours.has(d.getUTCHours())) continue;
    if (!months.has(d.getUTCMonth() + 1)) continue;
    const dom = d.getUTCDate();
    const dow = d.getUTCDay();
    // Classic cron day rule: restricted fields decide, both restricted
    // means either may match, neither restricted means every day.
    const dayOk =
      !expr.dayOfMonthRestricted && !expr.dayOfWeekRestricted
        ? true
        : expr.dayOfMonthRestricted && !expr.dayOfWeekRestricted
          ? doms.has(dom)
          : !expr.dayOfMonthRestricted && expr.dayOfWeekRestricted
            ? dows.has(dow)
            : doms.has(dom) || dows.has(dow);
    if (!dayOk) continue;
    return t;
  }
  throw new Error(`cron: no occurrence of ${JSON.stringify(expr.source)} within 5 years`);
}
