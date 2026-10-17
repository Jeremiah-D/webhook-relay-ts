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
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
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
export class EndpointDeliveryWindow {
  private readonly specs = new Map<string, DeliveryWindowSpec>();
  /** WR-126: timezone-aware windows, keyed by exact `targetUrl`. */
  private readonly tzSpecs = new Map<string, TimezoneWindowEntry>();
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
   * True when `endpoint` may be delivered at `nowMs` (defaults to the
   * injected clock): either it has no configured window, or the time is
   * inside the window (open edge inclusive, close edge exclusive). The
   * inclusive open edge is what makes "flush at window open" race-free: a
   * delivery rescheduled for the opening instant always lands inside.
   * WR-126: timezone windows evaluate against the zone's local wall
   * clock; UTC windows keep the exact pre-WR-126 semantics.
   */
  isOpen(endpoint: string, nowMs?: number): boolean {
    const tz = this.tzSpecs.get(endpoint);
    if (tz !== undefined) {
      const at = this.tzMinutesOfDay(tz, nowMs ?? this.now());
      return this.contains(tz.spec, at);
    }
    const spec = this.specs.get(endpoint);
    if (spec === undefined) return true;
    const at = this.minutesOfDay(nowMs ?? this.now());
    return this.contains(spec, at);
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
    if (tz !== undefined) return this.msUntilTzOpen(tz, at);
    const spec = this.specs.get(endpoint);
    if (spec === undefined) return 0;
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
   * Remove the delivery window for one endpoint at runtime: the endpoint
   * becomes always deliverable. Removes a UTC or a timezone window alike.
   * Returns `false` when no window was set.
   */
  deleteEndpointWindow(endpoint: string): boolean {
    this.assertValidEndpoint(endpoint, "deleteEndpointWindow");
    const utc = this.specs.delete(endpoint);
    const tz = this.tzSpecs.delete(endpoint);
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
  /** Deliveries parked outside the window until it opened. */
  delayed: number;
  /** Whether the window is open at the injected clock's current time. */
  open: boolean;
}
