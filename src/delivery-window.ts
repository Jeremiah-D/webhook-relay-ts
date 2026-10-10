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
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
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
  private readonly delayed = new Map<string, number>();
  private readonly now: () => number;

  constructor(opts: DeliveryWindowOptions = {}) {
    this.now = opts.now ?? Date.now;
    for (const [endpoint, spec] of Object.entries(opts.windows ?? {})) {
      this.assertValidEndpoint(endpoint, "constructor");
      this.specs.set(endpoint, parseDeliveryWindowSpec(spec));
    }
  }

  private assertValidEndpoint(endpoint: string, where: string): void {
    if (typeof endpoint !== "string" || endpoint.length === 0) {
      throw new RangeError(`${where}: endpoint must be a non-empty string`);
    }
  }

  /** Endpoints with a configured window, in first-configured order. */
  endpoints(): string[] {
    return [...this.specs.keys()];
  }

  /** The parsed window spec for `endpoint`, or `undefined` when unconfigured. */
  specFor(endpoint: string): DeliveryWindowSpec | undefined {
    return this.specs.get(endpoint);
  }

  /**
   * True when `endpoint` may be delivered at `nowMs` (defaults to the
   * injected clock): either it has no configured window, or the time is
   * inside the window (open edge inclusive, close edge exclusive). The
   * inclusive open edge is what makes "flush at window open" race-free: a
   * delivery rescheduled for the opening instant always lands inside.
   */
  isOpen(endpoint: string, nowMs?: number): boolean {
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
   * Milliseconds from `nowMs` (default: the injected clock) until the
   * window opens for `endpoint`. Returns 0 when the endpoint is open now
   * or has no configured window — so callers that only schedule on a
   * closed window never busy-loop.
   */
  msUntilOpen(endpoint: string, nowMs?: number): number {
    const spec = this.specs.get(endpoint);
    if (spec === undefined) return 0;
    const at = nowMs ?? this.now();
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
   * Set (or replace) the delivery window for one endpoint at runtime.
   * An invalid spec throws `RangeError` and leaves the current window
   * intact. Follows the WR-32/WR-50 per-endpoint runtime-override
   * convention.
   */
  setEndpointWindow(endpoint: string, spec: string): void {
    this.assertValidEndpoint(endpoint, "setEndpointWindow");
    this.specs.set(endpoint, parseDeliveryWindowSpec(spec));
  }

  /**
   * Remove the delivery window for one endpoint at runtime: the endpoint
   * becomes always deliverable. Returns `false` when no window was set.
   */
  deleteEndpointWindow(endpoint: string): boolean {
    this.assertValidEndpoint(endpoint, "deleteEndpointWindow");
    return this.specs.delete(endpoint);
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
  /** Deliveries parked outside the window until it opened. */
  delayed: number;
  /** Whether the window is open at the injected clock's current time. */
  open: boolean;
}
