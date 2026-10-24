/**
 * WR-52: per-endpoint delivery time windows ("quiet hours").
 *
 * Some deliveries must only reach a downstream inside a daily UTC window —
 * the payment-ops scenario is repayment reminders that go out in daytime
 * only. An endpoint's window is a single daily interval written
 * cron-style, e.g. `"01:00-09:00"` (UTC): the open edge is inclusive, the
 * close edge is exclusive, and the interval may cross midnight
 * (`"22:00-06:00"`). An endpoint without a configured window is always
 * deliverable — the feature is opt-in per endpoint, so an unset
 * `deliveryWindow` (or one with no matching endpoint) behaves exactly like
 * the pre-WR-52 relay.
 *
 * Holding a delivery outside its window is a *park*, not a failure: the
 * item stays queued with its attempt count intact, consumes no quota
 * token, no circuit-breaker verdict, and no retry-budget token, and it is
 * never dead-lettered for being out of window. The queue re-schedules it
 * for the window's opening instant, so the boundary semantics are "flush
 * at window open" — parked deliveries race for their gates exactly like
 * any due delivery.
 *
 * WR-126 adds opt-in per-endpoint IANA time zones: a window can be
 * evaluated against the zone's local wall clock (e.g. a repayment
 * reminder that must go out 09:00–18:00 in the *borrower's* zone) instead
 * of UTC. A UTC window and a timezone window are mutually exclusive per
 * endpoint. DST transitions are handled honestly against wall-clock
 * minutes: a spring-forward gap hour never matches any minute (the
 * window stays closed through the gap and the next opening is found on
 * the following day), while a fall-back repeated hour is
 * indistinguishable from its first occurrence. All of this uses
 * `Intl.DateTimeFormat` — zero new dependencies.
 *
 * WR-208 adds opt-in per-endpoint holiday calendars: a set of calendar
 * dates (plus a `region` label, e.g. `"CN"`) on which the day's window
 * behaves differently. The date is the window's own calendar date — the
 * zone's local date for a timezone window, the UTC date for a UTC window
 * — so a Shanghai holiday is not shifted by UTC. Three strategies:
 * `skip` closes the whole holiday day and `msUntilOpen` jumps straight
 * to the next non-holiday window opening; `defer` also closes the day
 * but parks only to the next window opening, re-evaluating there (so a
 * multi-day holiday re-parks day by day); `shrink` narrows the holiday
 * window to its first half by default, or to an explicit `holidayWindow`
 * spec when one is given (the open edge is shared with the normal
 * window unless `holidayWindow` says otherwise). Holidays are opt-in
 * per endpoint and require a window — a calendar on an endpoint with no
 * window throws `RangeError` at construction instead of silently doing
 * nothing. Endpoints without a calendar keep the exact pre-WR-208
 * behavior.
 *
 * Like `quota.ts` (WR-15) and the WR-50 pause switch, the clock is
 * injectable so tests pin wall-clock time deterministically.
 */

const MINUTES_PER_DAY = 24 * 60;
const WINDOW_SPEC_RE = /^(\d{1,2}):(\d{2})-(\d{1,2}):(\d{2})$/;

/** A parsed daily UTC delivery window. */
export interface DeliveryWindowSpec {
  /** Window open edge in minutes after UTC midnight (inclusive). */
  openMinutes: number;
  /** Window close edge in minutes after UTC midnight (exclusive). */
  closeMinutes: number;
  /** The original spec string (kept for observability). */
  raw: string;
}

function parseTimePart(hour: string, minute: string, raw: string): number {
  const h = Number(hour);
  const m = Number(minute);
  if (!Number.isInteger(h) || h < 0 || h > 23 || !Number.isInteger(m) || m < 0 || m > 59) {
    throw new RangeError(
      `invalid delivery window time in "${raw}": hours must be 00-23 and minutes 00-59`
    );
  }
  return h * 60 + m;
}

/**
 * Parse a window spec like `"01:00-09:00"` (UTC). The open edge is
 * inclusive, the close edge is exclusive; the interval may cross midnight
 * (`"22:00-06:00"`), and `open === close` means the full day (always
 * open). Anything malformed throws `RangeError`.
 */
export function parseDeliveryWindowSpec(spec: string): DeliveryWindowSpec {
  if (typeof spec !== "string") {
    throw new RangeError(`delivery window spec must be a string, got ${typeof spec}`);
  }
  const m = WINDOW_SPEC_RE.exec(spec.trim());
  if (m === null) {
    throw new RangeError(
      `invalid delivery window spec "${spec}": expected "HH:MM-HH:MM" in UTC, e.g. "01:00-09:00"`
    );
  }
  const openMinutes = parseTimePart(m[1], m[2], spec);
  const closeMinutes = parseTimePart(m[3], m[4], spec);
  return { openMinutes, closeMinutes, raw: spec.trim() };
}

/** Options for {@link EndpointDeliveryWindow} (WR-52). */
export interface DeliveryWindowOptions {
  /**
   * Per-endpoint delivery windows: exact `targetUrl` → window spec
   * (`"HH:MM-HH:MM"` in UTC, e.g. `"09:00-18:00"` for daytime-only
   * deliveries). Endpoints absent from the record are always
   * deliverable — windows are opt-in per endpoint, unset means off.
   * Invalid specs throw `RangeError` at construction.
   */
  windows?: Record<string, string>;
  /**
   * Per-endpoint timezone-aware delivery windows (WR-126): exact
   * `targetUrl` → `{ window, timezone }`. The window spec has the same
   * `"HH:MM-HH:MM"` syntax, but it is evaluated against the IANA time
   * zone's local wall clock instead of UTC — e.g. a repayment-reminder
   * endpoint can be daytime-only in the *borrower's* zone
   * (`{ window: "09:00-18:00", timezone: "Asia/Shanghai" }`). An endpoint
   * may have either a UTC window or a timezone window, never both
   * (mutual exclusion throws `RangeError` at construction); an invalid
   * IANA zone throws `RangeError` at construction. Opt-in per endpoint;
   * absent means off (zero behavior change).
   */
  tzWindows?: Record<string, TimezoneWindowConfig>;
  /**
   * Per-endpoint holiday calendars (WR-208): exact `targetUrl` →
   * `{ dates, region?, strategy?, holidayWindow? }`. An endpoint with a
   * calendar must also have a UTC or timezone window (a calendar alone
   * throws `RangeError` at construction). Opt-in per endpoint; absent
   * means off (zero behavior change).
   */
  holidays?: Record<string, HolidayCalendarConfig>;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
}

/**
 * How a holiday day treats its endpoint's delivery window (WR-208):
 * `skip` closes the whole day and jumps to the next non-holiday window
 * opening; `defer` closes the day but parks only to the next window
 * opening, re-evaluating there; `shrink` narrows the day's window (first
 * half of the normal window by default, or `holidayWindow` when given).
 */
export type HolidayStrategy = "skip" | "defer" | "shrink";

/** A per-endpoint holiday calendar (WR-208). */
export interface HolidayCalendarConfig {
  /**
   * Holiday dates as `"YYYY-MM-DD"` in the window's calendar (the zone's
   * local date for a timezone window, the UTC date for a UTC window).
   * Each date must be a real calendar date; malformed dates throw
   * `RangeError` at construction. Duplicates are ignored.
   */
  dates: string[];
  /** Region label for the calendar, e.g. `"CN"` — observability only. */
  region?: string;
  /** Holiday strategy; defaults to `"skip"`. */
  strategy?: HolidayStrategy;
  /**
   * Only meaningful with `strategy: "shrink"`: the window spec that
   * replaces the normal window on holidays (`"HH:MM-HH:MM"`, same syntax
   * as the window itself). Setting it with `skip`/`defer` throws
   * `RangeError`. When `shrink` has no `holidayWindow`, the holiday
   * window is the first half of the normal window, starting at its open
   * edge (a 1-minute window shrinks to nothing — closed all day).
   */
  holidayWindow?: string;
}

/**
 * A timezone-aware per-endpoint delivery window (WR-126): the window
 * spec plus the IANA time zone it is evaluated in.
 */
export interface TimezoneWindowConfig {
  /**
   * Window spec `"HH:MM-HH:MM"` (open edge inclusive, close edge
   * exclusive, may cross midnight). Evaluated against the zone's local
   * wall clock.
   */
  window: string;
  /**
   * IANA time zone, e.g. `"Asia/Shanghai"`. DST transitions are handled
   * honestly against wall-clock minutes: a spring-forward gap hour never
   * matches any minute (the window is simply closed through the gap),
   * and a fall-back repeated hour matches the same wall-clock minutes
   * twice (indistinguishable — the first occurrence opens the window).
   */
  timezone: string;
}

/** A parsed timezone-aware per-endpoint window with its cached formatter. */
interface TimezoneWindowEntry {
  spec: DeliveryWindowSpec;
  timezone: string;
  dtf: Intl.DateTimeFormat;
}

/**
 * Per-endpoint delivery time windows: `true` from {@link isOpen} means the
 * delivery may be attempted now; otherwise the caller parks the item and
 * re-schedules it for {@link msUntilOpen}.
 *
 * Delays are counted via {@link noteDelayed} (the queue calls it when it
 * parks) and surfaced by the queue's `getDeliveryWindowStats`. The clock
 * is the same injectable `now` everywhere, so a single frozen clock pins
 * both the gate and the schedule math in tests.
 */
/** A parsed per-endpoint holiday calendar (WR-208). */
interface HolidayEntry {
  dates: Set<string>;
  region?: string;
  strategy: HolidayStrategy;
  holidayWindowSpec?: DeliveryWindowSpec;
}

export class EndpointDeliveryWindow {
  private readonly specs = new Map<string, DeliveryWindowSpec>();
  /** WR-126: timezone-aware windows, keyed by exact `targetUrl`. */
  private readonly tzSpecs = new Map<string, TimezoneWindowEntry>();
  /** WR-208: holiday calendars, keyed by exact `targetUrl`. */
  private readonly holidays = new Map<string, HolidayEntry>();
  private readonly delayed = new Map<string, number>();
  private readonly now: () => number;

  constructor(opts: DeliveryWindowOptions = {}) {
    this.now = opts.now ?? Date.now;
    for (const [endpoint, spec] of Object.entries(opts.windows ?? {})) {
      this.assertValidEndpoint(endpoint, "constructor");
      this.specs.set(endpoint, parseDeliveryWindowSpec(spec));
    }
    // WR-126: timezone windows are staged before any is installed, so
    // an illegal entry throws with zero partial application.
    const staged = new Map<string, TimezoneWindowEntry>();
    for (const [endpoint, cfg] of Object.entries(opts.tzWindows ?? {})) {
      this.assertValidEndpoint(endpoint, "constructor");
      if (this.specs.has(endpoint)) {
        throw new RangeError(
          `constructor: endpoint ${JSON.stringify(endpoint)} has both a UTC window and a timezone window — they are mutually exclusive`
        );
      }
      staged.set(endpoint, this.parseTimezoneWindowConfig(endpoint, cfg, "constructor"));
    }
    for (const [endpoint, entry] of staged) this.tzSpecs.set(endpoint, entry);
    // WR-208: holiday calendars are staged before any is installed, so
    // an illegal entry throws with zero partial application — and a
    // calendar on an endpoint with no window throws instead of silently
    // doing nothing.
    const stagedHolidays = new Map<string, HolidayEntry>();
    for (const [endpoint, cfg] of Object.entries(opts.holidays ?? {})) {
      this.assertValidEndpoint(endpoint, "constructor");
      if (!this.specs.has(endpoint) && !this.tzSpecs.has(endpoint)) {
        throw new RangeError(
          `constructor: endpoint ${JSON.stringify(endpoint)} has a holiday calendar but no delivery window — calendars require a window`
        );
      }
      stagedHolidays.set(endpoint, this.parseHolidayCalendarConfig(endpoint, cfg, "constructor"));
    }
    for (const [endpoint, entry] of stagedHolidays) this.holidays.set(endpoint, entry);
  }

  /**
   * Validate one holiday calendar config and build its entry.
   * Throws `RangeError` on a malformed config, an unknown strategy, a
   * `holidayWindow` on a non-`shrink` strategy, or a non-calendar date.
   * Parsing happens before any install, so a throw leaves the current
   * calendar intact (constructor and runtime setters alike).
   */
  private parseHolidayCalendarConfig(
    endpoint: string,
    cfg: HolidayCalendarConfig,
    where: string
  ): HolidayEntry {
    if (typeof cfg !== "object" || cfg === null || Array.isArray(cfg)) {
      throw new RangeError(
        `${where}: holiday calendar for ${JSON.stringify(endpoint)} must be { dates, region?, strategy?, holidayWindow? }`
      );
    }
    const dates = (cfg as { dates?: unknown }).dates;
    if (!Array.isArray(dates)) {
      throw new RangeError(
        `${where}: holiday calendar for ${JSON.stringify(endpoint)} needs a dates array`
      );
    }
    const strategy = (cfg as { strategy?: unknown }).strategy ?? "skip";
    if (strategy !== "skip" && strategy !== "defer" && strategy !== "shrink") {
      throw new RangeError(
        `${where}: holiday strategy for ${JSON.stringify(endpoint)} must be "skip", "defer", or "shrink", got ${JSON.stringify(strategy)}`
      );
    }
    const holidayWindow = (cfg as { holidayWindow?: unknown }).holidayWindow;
    if (holidayWindow !== undefined && strategy !== "shrink") {
      throw new RangeError(
        `${where}: holidayWindow for ${JSON.stringify(endpoint)} is only meaningful with strategy "shrink", got ${JSON.stringify(strategy)}`
      );
    }
    const parsedDates = new Set<string>();
    for (const d of dates) {
      parsedDates.add(this.parseHolidayDate(endpoint, d, where));
    }
    const region = (cfg as { region?: unknown }).region;
    if (region !== undefined && (typeof region !== "string" || region.length === 0)) {
      throw new RangeError(
        `${where}: holiday region for ${JSON.stringify(endpoint)} must be a non-empty string`
      );
    }
    const entry: HolidayEntry = {
      dates: parsedDates,
      ...(region === undefined ? {} : { region: region as string }),
      strategy,
    };
    if (holidayWindow !== undefined) {
      entry.holidayWindowSpec = parseDeliveryWindowSpec(holidayWindow as string);
    }
    return entry;
  }

  /** Validate one `"YYYY-MM-DD"` holiday date (a real calendar date). */
  private parseHolidayDate(endpoint: string, date: unknown, where: string): string {
    if (typeof date !== "string") {
      throw new RangeError(
        `${where}: holiday date for ${JSON.stringify(endpoint)} must be a "YYYY-MM-DD" string, got ${typeof date}`
      );
    }
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date);
    if (m === null) {
      throw new RangeError(
        `${where}: invalid holiday date ${JSON.stringify(date)} for ${JSON.stringify(endpoint)}: expected "YYYY-MM-DD"`
      );
    }
    const probe = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])));
    if (
      probe.getUTCFullYear() !== Number(m[1]) ||
      probe.getUTCMonth() !== Number(m[2]) - 1 ||
      probe.getUTCDate() !== Number(m[3])
    ) {
      throw new RangeError(
        `${where}: invalid holiday date ${JSON.stringify(date)} for ${JSON.stringify(endpoint)}: not a real calendar date`
      );
    }
    return date;
  }

  /**
   * Validate one `{ window, timezone }` config and build its entry.
   * Throws `RangeError` on a malformed config, an unknown IANA zone, or
   * an invalid window spec.
   */
  private parseTimezoneWindowConfig(
    endpoint: string,
    cfg: TimezoneWindowConfig,
    where: string
  ): TimezoneWindowEntry {
    if (typeof cfg !== "object" || cfg === null || Array.isArray(cfg)) {
      throw new RangeError(
        `${where}: timezone window for ${JSON.stringify(endpoint)} must be { window, timezone }`
      );
    }
    const timezone = (cfg as { timezone?: unknown }).timezone;
    if (typeof timezone !== "string" || timezone.length === 0) {
      throw new RangeError(
        `${where}: timezone window for ${JSON.stringify(endpoint)} needs a non-empty IANA timezone string`
      );
    }
    let dtf: Intl.DateTimeFormat;
    try {
      dtf = new Intl.DateTimeFormat("en-US", {
        timeZone: timezone,
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hourCycle: "h23",
      });
    } catch (err) {
      throw new RangeError(
        `${where}: invalid IANA timezone ${JSON.stringify(timezone)} for ${JSON.stringify(endpoint)}: ${(err as Error).message}`
      );
    }
    const spec = parseDeliveryWindowSpec((cfg as { window?: unknown }).window as string);
    return { spec, timezone, dtf };
  }

  private assertValidEndpoint(endpoint: string, where: string): void {
    if (typeof endpoint !== "string" || endpoint.length === 0) {
      throw new RangeError(`${where}: endpoint must be a non-empty string`);
    }
  }

  /** Endpoints with a configured window (UTC or timezone), in first-configured order. */
  endpoints(): string[] {
    return [...this.specs.keys(), ...this.tzSpecs.keys()];
  }

  /** The parsed window spec for `endpoint`, or `undefined` when unconfigured. */
  specFor(endpoint: string): DeliveryWindowSpec | undefined {
    return this.tzSpecs.get(endpoint)?.spec ?? this.specs.get(endpoint);
  }

  /**
   * WR-126: the IANA time zone for `endpoint`'s window, or `undefined`
   * when the endpoint uses a UTC window (or has no window).
   */
  timezoneFor(endpoint: string): string | undefined {
    return this.tzSpecs.get(endpoint)?.timezone;
  }

  /**
   * WR-208: the holiday calendar for `endpoint`, or `undefined` when
   * none is configured. Dates are returned sorted, in `"YYYY-MM-DD"` form.
   */
  holidayInfo(endpoint: string):
    | { region?: string; strategy: HolidayStrategy; dates: string[] }
    | undefined {
    const entry = this.holidays.get(endpoint);
    if (entry === undefined) return undefined;
    return {
      ...(entry.region === undefined ? {} : { region: entry.region }),
      strategy: entry.strategy,
      dates: [...entry.dates].sort(),
    };
  }

  /** WR-208: true when `endpoint`'s calendar marks `nowMs`'s date a holiday. */
  isHoliday(endpoint: string, nowMs?: number): boolean {
    const entry = this.holidays.get(endpoint);
    if (entry === undefined) return false;
    return entry.dates.has(this.dateKeyFor(endpoint, nowMs ?? this.now()));
  }

  /** WR-208: the calendar date key (`"YYYY-MM-DD"`) for `nowMs` in the window's calendar. */
  private dateKeyFor(endpoint: string, nowMs: number): string {
    const tz = this.tzSpecs.get(endpoint);
    if (tz !== undefined) {
      const parts = this.tzDateParts(tz, nowMs);
      return this.padDate(parts.year, parts.month, parts.day);
    }
    const d = new Date(nowMs);
    return this.padDate(d.getUTCFullYear(), d.getUTCMonth() + 1, d.getUTCDate());
  }

  private padDate(year: number, month: number, day: number): string {
    return `${String(year).padStart(4, "0")}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
  }

  /** WR-208: the zone's local calendar date parts for `nowMs`. */
  private tzDateParts(entry: TimezoneWindowEntry, nowMs: number): { year: number; month: number; day: number } {
    let year = 0;
    let month = 0;
    let day = 0;
    for (const part of entry.dtf.formatToParts(new Date(nowMs))) {
      if (part.type === "year") year = Number(part.value);
      else if (part.type === "month") month = Number(part.value);
      else if (part.type === "day") day = Number(part.value);
    }
    return { year, month, day };
  }

  /**
   * WR-208: the window spec in force on `dateKey` for an endpoint whose
   * normal spec is `baseSpec`: the base spec on ordinary days, the
   * shrink spec on a `shrink` holiday, and `null` (closed all day) on a
   * `skip`/`defer` holiday. A shrink without an explicit `holidayWindow`
   * keeps the normal open edge and halves the window length (a
   * midnight-crossing window halves across midnight via `contains`).
   */
  private effectiveSpecForDate(
    endpoint: string,
    baseSpec: DeliveryWindowSpec,
    dateKey: string
  ): DeliveryWindowSpec | null {
    const entry = this.holidays.get(endpoint);
    if (entry === undefined || !entry.dates.has(dateKey)) return baseSpec;
    if (entry.strategy !== "shrink") return null;
    if (entry.holidayWindowSpec !== undefined) return entry.holidayWindowSpec;
    const length =
      baseSpec.openMinutes === baseSpec.closeMinutes
        ? MINUTES_PER_DAY
        : (baseSpec.closeMinutes - baseSpec.openMinutes + MINUTES_PER_DAY) % MINUTES_PER_DAY;
    const half = Math.floor(length / 2);
    if (half <= 0) return null;
    return {
      openMinutes: baseSpec.openMinutes,
      closeMinutes: (baseSpec.openMinutes + half) % MINUTES_PER_DAY,
      raw: `shrink:${baseSpec.raw}`,
    };
  }

  /** WR-208: the window spec in force at `nowMs` (see `effectiveSpecForDate`). */
  private effectiveSpecAt(
    endpoint: string,
    baseSpec: DeliveryWindowSpec,
    nowMs: number
  ): DeliveryWindowSpec | null {
    return this.effectiveSpecForDate(endpoint, baseSpec, this.dateKeyFor(endpoint, nowMs));
  }

  /**
   * WR-208: the epoch instant of the window's opening on the day
   * `dayOffset` days after `nowMs`'s calendar date, or `null` when that
   * opening falls in a spring-forward gap (timezone windows) or the
   * endpoint has no window. With `useEffective` (the default), a
   * `shrink` holiday contributes its shrink opening; a `skip`/`defer`
   * holiday contributes its normal opening (the caller filters it out
   * via `isOpen`). With `useEffective: false` the normal opening is
   * used regardless of holidays (the `defer` schedule).
   */
  private dayWindowOpenInstant(
    endpoint: string,
    nowMs: number,
    dayOffset: number,
    useEffective = true
  ): number | null {
    const tz = this.tzSpecs.get(endpoint);
    if (tz !== undefined) {
      const parts = this.tzDateParts(tz, nowMs);
      const base = Date.UTC(parts.year, parts.month - 1, parts.day) + dayOffset * 86_400_000;
      const bd = new Date(base);
      const ly = bd.getUTCFullYear();
      const lm = bd.getUTCMonth() + 1;
      const ld = bd.getUTCDate();
      const key = this.padDate(ly, lm, ld);
      const eff = useEffective ? this.effectiveSpecForDate(endpoint, tz.spec, key) : tz.spec;
      const open = (eff ?? tz.spec).openMinutes;
      const targetLocal = Date.UTC(ly, lm - 1, ld) + open * 60_000;
      const g = this.tzLocalToEpoch(tz, targetLocal, this.tzOffsetMinutes(tz, nowMs));
      if (this.tzMinutesOfDay(tz, g) !== open) return null; // spring-forward gap day
      return g;
    }
    const spec = this.specs.get(endpoint);
    if (spec === undefined) return null;
    const d = new Date(nowMs);
    const base = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()) + dayOffset * 86_400_000;
    const bd = new Date(base);
    const ly = bd.getUTCFullYear();
    const lm = bd.getUTCMonth() + 1;
    const ld = bd.getUTCDate();
    const key = this.padDate(ly, lm, ld);
    const eff = useEffective ? this.effectiveSpecForDate(endpoint, spec, key) : spec;
    const open = (eff ?? spec).openMinutes;
    return Date.UTC(ly, lm - 1, ld) + open * 60_000;
  }

  /**
   * WR-208: milliseconds until the next opening that is actually open
   * (a `skip` holiday's opening fails the `isOpen` check and is passed
   * over; a `shrink` holiday's shrink opening passes). The scan is
   * bounded at 400 days — a calendar longer than that still re-parks
   * after a day, so the queue re-evaluates instead of busy-looping.
   */
  private msUntilHolidayAwareOpen(endpoint: string, nowMs: number): number {
    for (let d = 0; d < 400; d++) {
      const g = this.dayWindowOpenInstant(endpoint, nowMs, d);
      if (g === null || g < nowMs) continue;
      if (this.isOpen(endpoint, g)) return Math.max(1, g - nowMs);
    }
    return 86_400_000;
  }

  /**
   * WR-208: milliseconds until the next window opening after `nowMs`,
   * ignoring holidays (the `defer` schedule: strictly after now, so a
   * holiday instant that is already passing never returns 0).
   */
  private msUntilNextWindowOpen(endpoint: string, nowMs: number): number {
    for (let d = 0; d < 400; d++) {
      const g = this.dayWindowOpenInstant(endpoint, nowMs, d, false);
      if (g === null || g <= nowMs) continue;
      return Math.max(1, g - nowMs);
    }
    return 86_400_000;
  }

  /**
   * True when `endpoint` may be delivered at `nowMs` (defaults to the
   * injected clock): either it has no configured window, or the time is
   * inside the window (open edge inclusive, close edge exclusive). The
   * inclusive open edge is what makes "flush at window open" race-free: a
   * delivery rescheduled for the opening instant always lands inside.
   * WR-126: timezone windows evaluate against the zone's local wall
   * clock; UTC windows keep the exact pre-WR-126 semantics.
   */
  isOpen(endpoint: string, nowMs?: number): boolean {
    const at = nowMs ?? this.now();
    const tz = this.tzSpecs.get(endpoint);
    if (tz !== undefined) {
      const eff = this.effectiveSpecAt(endpoint, tz.spec, at);
      if (eff === null) return false; // WR-208: skip/defer holiday
      return this.contains(eff, this.tzMinutesOfDay(tz, at));
    }
    const spec = this.specs.get(endpoint);
    if (spec === undefined) return true;
    const eff = this.effectiveSpecAt(endpoint, spec, at);
    if (eff === null) return false; // WR-208: skip/defer holiday
    return this.contains(eff, this.minutesOfDay(at));
  }

  private contains(spec: DeliveryWindowSpec, minutesOfDay: number): boolean {
    if (spec.openMinutes === spec.closeMinutes) return true; // full day
    if (spec.openMinutes < spec.closeMinutes) {
      return minutesOfDay >= spec.openMinutes && minutesOfDay < spec.closeMinutes;
    }
    // Crosses midnight: open past midnight through `closeMinutes`.
    return minutesOfDay >= spec.openMinutes || minutesOfDay < spec.closeMinutes;
  }

  private minutesOfDay(nowMs: number): number {
    const d = new Date(nowMs);
    return d.getUTCHours() * 60 + d.getUTCMinutes();
  }

  /**
   * WR-126: the zone's UTC offset in whole minutes at `nowMs`, derived
   * from the cached `Intl.DateTimeFormat` (second-granularity parts;
   * windows are minute-granular). DST is inherent: the offset is sampled
   * at the instant being converted.
   */
  private tzOffsetMinutes(entry: TimezoneWindowEntry, nowMs: number): number {
    const at = Math.floor(nowMs / 1000) * 1000;
    let year = 0;
    let month = 0;
    let day = 0;
    let hour = 0;
    let minute = 0;
    let second = 0;
    for (const part of entry.dtf.formatToParts(new Date(at))) {
      switch (part.type) {
        case "year":
          year = Number(part.value);
          break;
        case "month":
          month = Number(part.value);
          break;
        case "day":
          day = Number(part.value);
          break;
        case "hour":
          hour = Number(part.value);
          break;
        case "minute":
          minute = Number(part.value);
          break;
        case "second":
          second = Number(part.value);
          break;
      }
    }
    const asUTC = Date.UTC(year, month - 1, day, hour, minute, second);
    return Math.round((asUTC - at) / 60_000);
  }

  /** WR-126: local wall-clock minutes after midnight for `nowMs` in the zone. */
  private tzMinutesOfDay(entry: TimezoneWindowEntry, nowMs: number): number {
    const localMs = nowMs + this.tzOffsetMinutes(entry, nowMs) * 60_000;
    const m = Math.floor(localMs / 60_000) % MINUTES_PER_DAY;
    return m < 0 ? m + MINUTES_PER_DAY : m;
  }

  /**
   * WR-126: invert one local wall-clock instant back to epoch
   * milliseconds by iterative refinement. The offset is piecewise
   * constant, so this converges in 1–3 iterations; it is bounded (10
   * iterations) for the pathological case where the local instant does
   * not exist (spring-forward gap) — the caller verifies `isOpen` on
   * the result and advances a day when the instant is not real. The
   * offset math is exact to the millisecond (both sides of the
   * comparison are second-aligned), so a hit lands on the first instant
   * of the opening minute and the inclusive open edge holds.
   */
  private tzLocalToEpoch(entry: TimezoneWindowEntry, targetLocal: number, offsetHint: number): number {
    let g = targetLocal - offsetHint * 60_000;
    for (let i = 0; i < 10; i++) {
      const localG = g + this.tzOffsetMinutes(entry, g) * 60_000;
      const err = targetLocal - localG;
      if (err >= 0 && err < 60_000) return g + err;
      g += err;
    }
    return g;
  }

  /**
   * WR-126: milliseconds until the timezone window next opens. The
   * next opening is located in local wall-clock minutes (the same
   * delta-minutes math as the UTC path), converted back to epoch; the
   * result is verified open (a spring-forward gap hour never matches,
   * so the search advances to the next day's window) and the open edge
   * stays inclusive, preserving "flush at window open".
   */
  private msUntilTzOpen(entry: TimezoneWindowEntry, nowMs: number): number {
    const spec = entry.spec;
    const localMin = this.tzMinutesOfDay(entry, nowMs);
    if (this.contains(spec, localMin)) return 0;
    // Next opening in local minutes: before today's open -> today;
    // at/after close (or inside a crossing window's gap) -> tomorrow.
    const dayOffset =
      spec.openMinutes < spec.closeMinutes && localMin >= spec.closeMinutes ? 1 : 0;
    const offsetNow = this.tzOffsetMinutes(entry, nowMs);
    const localDayStart = Math.floor((nowMs + offsetNow * 60_000) / 86_400_000) * 86_400_000;
    for (let d = 0; d < 3; d++) {
      const targetLocal = localDayStart + (dayOffset + d) * 86_400_000 + spec.openMinutes * 60_000;
      const g = this.tzLocalToEpoch(entry, targetLocal, offsetNow);
      if (g >= nowMs && this.tzMinutesOfDay(entry, g) === spec.openMinutes) {
        return Math.max(1, g - nowMs);
      }
    }
    // Defensive fallback: windows are daily-periodic, so one of the
    // next three days must open. Unreachable in practice.
    return 86_400_000;
  }

  /**
   * Milliseconds from `nowMs` (default: the injected clock) until the
   * window opens for `endpoint`. Returns 0 when the endpoint is open now
   * or has no configured window — so callers that only schedule on a
   * closed window never busy-loop. WR-126: timezone windows convert the
   * next opening from the zone's local wall clock back to epoch
   * milliseconds; the "flush at window open" semantics are unchanged.
   */
  msUntilOpen(endpoint: string, nowMs?: number): number {
    const at = nowMs ?? this.now();
    const tz = this.tzSpecs.get(endpoint);
    if (tz !== undefined) {
      if (this.isOpen(endpoint, at)) return 0;
      const hol = this.holidays.get(endpoint);
      if (hol?.strategy === "defer") return this.msUntilNextWindowOpen(endpoint, at);
      if (hol !== undefined) return this.msUntilHolidayAwareOpen(endpoint, at);
      return this.msUntilTzOpen(tz, at);
    }
    const spec = this.specs.get(endpoint);
    if (spec === undefined) return 0;
    if (this.isOpen(endpoint, at)) return 0;
    const hol = this.holidays.get(endpoint);
    if (hol?.strategy === "defer") return this.msUntilNextWindowOpen(endpoint, at);
    if (hol !== undefined) return this.msUntilHolidayAwareOpen(endpoint, at);
    const minutes = this.minutesOfDay(at);
    if (this.contains(spec, minutes)) return 0;
    let deltaMinutes: number;
    if (spec.openMinutes === spec.closeMinutes) {
      deltaMinutes = 0; // full day — cannot happen (contains() is true), kept for clarity
    } else if (spec.openMinutes < spec.closeMinutes) {
      // Closed window: the next opening is today's open, or tomorrow's if
      // already past close today. (If we were before open, delta < a day;
      // if after close, we roll to tomorrow.)
      deltaMinutes =
        minutes < spec.openMinutes
          ? spec.openMinutes - minutes
          : MINUTES_PER_DAY - minutes + spec.openMinutes;
    } else {
      // Midnight-crossing window closed now means we are in the gap
      // [closeMinutes, openMinutes): the next opening is today's open.
      deltaMinutes = spec.openMinutes - minutes;
    }
    // Fire at the first millisecond of the opening minute so the open
    // edge (inclusive) is honored.
    const seconds = new Date(at).getUTCSeconds() * 1000 + new Date(at).getUTCMilliseconds();
    return Math.max(1, deltaMinutes * 60_000 - seconds);
  }

  /**
   * Set (or replace) the UTC delivery window for one endpoint at runtime.
   * An invalid spec throws `RangeError` and leaves the current window
   * intact. WR-126: an endpoint with a timezone window cannot take a UTC
   * window — use `setEndpointTzWindow` instead (mutual exclusion).
   * Follows the WR-32/WR-50 per-endpoint runtime-override convention.
   */
  setEndpointWindow(endpoint: string, spec: string): void {
    this.assertValidEndpoint(endpoint, "setEndpointWindow");
    if (this.tzSpecs.has(endpoint)) {
      throw new RangeError(
        `setEndpointWindow: endpoint ${JSON.stringify(endpoint)} has a timezone window — use setEndpointTzWindow (UTC and timezone windows are mutually exclusive)`
      );
    }
    this.specs.set(endpoint, parseDeliveryWindowSpec(spec));
  }

  /**
   * WR-126: set (or replace) the timezone-aware delivery window for one
   * endpoint at runtime. An invalid window/timezone throws `RangeError`
   * and leaves the current window intact. An endpoint with a UTC window
   * cannot take a timezone window — delete it first (mutual exclusion).
   */
  setEndpointTzWindow(endpoint: string, window: string, timezone: string): void {
    this.assertValidEndpoint(endpoint, "setEndpointTzWindow");
    if (this.specs.has(endpoint)) {
      throw new RangeError(
        `setEndpointTzWindow: endpoint ${JSON.stringify(endpoint)} has a UTC window — delete it first (UTC and timezone windows are mutually exclusive)`
      );
    }
    this.tzSpecs.set(endpoint, this.parseTimezoneWindowConfig(endpoint, { window, timezone }, "setEndpointTzWindow"));
  }

  /**
   * WR-208: set (or replace) the holiday calendar for one endpoint at
   * runtime. An invalid config throws `RangeError` and leaves the
   * current calendar intact; an endpoint with no window cannot take a
   * calendar (delete the window first is not the fix — set a window
   * first). Follows the WR-32/WR-50 per-endpoint runtime-override
   * convention.
   */
  setEndpointHolidays(endpoint: string, cfg: HolidayCalendarConfig): void {
    this.assertValidEndpoint(endpoint, "setEndpointHolidays");
    if (!this.specs.has(endpoint) && !this.tzSpecs.has(endpoint)) {
      throw new RangeError(
        `setEndpointHolidays: endpoint ${JSON.stringify(endpoint)} has no delivery window — calendars require a window`
      );
    }
    this.holidays.set(endpoint, this.parseHolidayCalendarConfig(endpoint, cfg, "setEndpointHolidays"));
  }

  /** WR-208: remove the holiday calendar for one endpoint at runtime. Returns `false` when none was set. */
  deleteEndpointHolidays(endpoint: string): boolean {
    this.assertValidEndpoint(endpoint, "deleteEndpointHolidays");
    return this.holidays.delete(endpoint);
  }

  /**
   * Remove the delivery window for one endpoint at runtime: the endpoint
   * becomes always deliverable. Removes a UTC or a timezone window alike,
   * plus any holiday calendar on it (a calendar without a window cannot
   * take effect). Returns `false` when no window was set.
   */
  deleteEndpointWindow(endpoint: string): boolean {
    this.assertValidEndpoint(endpoint, "deleteEndpointWindow");
    const utc = this.specs.delete(endpoint);
    const tz = this.tzSpecs.delete(endpoint);
    this.holidays.delete(endpoint);
    return utc || tz;
  }

  /** Record one window-outside park for `endpoint` (called by the queue). */
  noteDelayed(endpoint: string): void {
    this.delayed.set(endpoint, (this.delayed.get(endpoint) ?? 0) + 1);
  }

  /** Window-outside parks recorded for `endpoint`. */
  delayedCount(endpoint: string): number {
    return this.delayed.get(endpoint) ?? 0;
  }
}

/** Per-(tenant, endpoint) delivery-window observability. */
export interface DeliveryWindowStats {
  endpoint: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  /** Configured window spec, e.g. `"09:00-18:00"` (UTC). */
  window: string;
  /**
   * WR-126: the IANA time zone the window is evaluated in. Absent for
   * UTC windows (the pre-WR-126 shape is unchanged).
   */
  timezone?: string;
  /**
   * WR-208: the holiday calendar's region label, when one is configured.
   * Absent when no calendar is set (the pre-WR-208 shape is unchanged).
   */
  holidayRegion?: string;
  /** WR-208: the holiday strategy, when a calendar is configured. */
  holidayStrategy?: HolidayStrategy;
  /** Deliveries parked outside the window until it opened. */
  delayed: number;
  /** Whether the window is open at the injected clock's current time. */
  open: boolean;
}
