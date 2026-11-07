/**
 * WR-147: downstream error-budget burn-rate alerting (Google SRE style).
 *
 * An error *budget* says how many failed deliveries an endpoint may have
 * (e.g. 1% of attempts may fail); the *burn rate* says how fast the
 * endpoint is spending that budget right now. Alerting on the burn rate
 * — rather than on a raw error count — catches a sudden outage in
 * minutes while ignoring the slow background trickle a budget is meant
 * to absorb.
 *
 * The monitor keeps a per-endpoint sliding event window and evaluates
 * two windows on every recorded outcome (the classic SRE multi-window
 * alert):
 *
 * - fast window (default 1h): catches a sudden spike quickly;
 * - slow window (default 6h): confirms the spike is real and not a
 *   one-minute fluke.
 *
 * An alert fires when *both* windows' burn rates exceed `alertThreshold`
 * (burn rate = observed error rate / budgeted error rate). The alert is
 * edge-triggered: a sustained breach alerts exactly once, and the
 * monitor re-arms only after both windows recover below the threshold —
 * so a flapping endpoint alerts once per episode, not once per
 * outcome.
 *
 * Composition:
 *
 * - The alert only *notifies* — it never blocks, delays, or reroutes a
 *   delivery. It is orthogonal to the WR-10 circuit breaker (which
 *   *does* gate dispatches) and the WR-34 active prober: a burning
 *   endpoint keeps receiving deliveries until the breaker trips on its
 *   own terms.
 * - The queue feeds the monitor one outcome per delivery attempt
 *   (`recordOutcome(endpoint, succeeded)`) from its existing
 *   `recordDelivery` funnel, so every attempt is accounted exactly
 *   once — the same outcomes that render `relay_deliveries_total`.
 * - A throwing `onBurnRateAlert` callback can never break the delivery
 *   path: the monitor swallows alert-dispatch errors (the alert is
 *   lost, the delivery is not).
 * - `relay_error_budget_burn_ratio{endpoint}` gauges the current
 *   fast-window burn rate (activity-gated — absent until the first
 *   outcome), and every fired alert is auditable as
 *   `error_budget_burn`.
 *
 * Zero dependencies. The clock is injectable (`now`) so tests drive
 * the windows deterministically.
 */

/** Default fast window: 1 hour (SRE fast-burn detection). */
export const DEFAULT_FAST_WINDOW_MS = 60 * 60 * 1000;
/** Default slow window: 6 hours (SRE slow-burn confirmation). */
export const DEFAULT_SLOW_WINDOW_MS = 6 * 60 * 60 * 1000;
/** Default budgeted error rate: 1% of attempts may fail. */
export const DEFAULT_BUDGET_ERROR_RATE = 0.01;
/** Default burn-rate alert threshold: 2x the budgeted rate. */
export const DEFAULT_ALERT_THRESHOLD = 2;
/**
 * Default minimum outcomes in the fast window before an alert can
 * fire: with fewer samples a single failure would look like a
 * 100%-error catastrophe.
 */
export const DEFAULT_MIN_EVENTS = 10;

/**
 * The alert payload delivered to `onBurnRateAlert` and recorded on the
 * `error_budget_burn` audit event.
 */
export interface BurnRateAlertInfo {
  /** The endpoint whose budget is burning. */
  endpoint: string;
  /** Fast-window burn rate that tripped the alert (observed/budgeted). */
  burnRate: number;
  /** Fast-window observed error rate in [0, 1]. */
  fastErrorRate: number;
  /** Slow-window observed error rate in [0, 1]. */
  slowErrorRate: number;
  /** Slow-window burn rate (the confirming window). */
  slowBurnRate: number;
  /** The configured budgeted error rate. */
  budgetErrorRate: number;
  /** The configured alert threshold. */
  alertThreshold: number;
  /** Fast/slow window sizes in ms. */
  fastWindowMs: number;
  slowWindowMs: number;
}

/** Audit event fired once per burn-rate alert episode. */
export interface ErrorBudgetBurnAuditEvent {
  event: "error_budget_burn";
  endpoint: string;
  burnRate: number;
  fastErrorRate: number;
  slowErrorRate: number;
  slowBurnRate: number;
  budgetErrorRate: number;
  alertThreshold: number;
  fastWindowMs: number;
  slowWindowMs: number;
}

/**
 * Options for {@link ErrorBudgetMonitor}.
 */
export interface ErrorBudgetOptions {
  /**
   * Master switch. `false`/absent = the monitor is never constructed
   * (the queue then behaves exactly as before).
   */
  enabled?: boolean;
  /** Fast window in ms (default 1h). Must be a positive integer. */
  fastWindowMs?: number;
  /** Slow window in ms (default 6h). Must be a positive integer > fastWindowMs. */
  slowWindowMs?: number;
  /**
   * Budgeted error rate in (0, 1) — the fraction of failed attempts the
   * endpoint is allowed (default 0.01 = 1%).
   */
  budgetErrorRate?: number;
  /**
   * Burn-rate alert threshold > 0 (default 2): alert when both windows
   * burn faster than this multiple of the budgeted rate.
   */
  alertThreshold?: number;
  /**
   * Minimum outcomes in the fast window before an alert can fire
   * (default 10). Positive integer.
   */
  minEvents?: number;
  /**
   * Called once per alert episode with a {@link BurnRateAlertInfo}.
   * Throwing is safe: the monitor catches it so alerting can never
   * break the delivery path.
   */
  onBurnRateAlert?: (info: BurnRateAlertInfo) => void;
  /** Injectable clock (epoch ms); defaults to `Date.now`. */
  now?: () => number;
}

/** Resolved (validated) error-budget configuration. */
export interface ResolvedErrorBudgetOptions {
  fastWindowMs: number;
  slowWindowMs: number;
  budgetErrorRate: number;
  alertThreshold: number;
  minEvents: number;
  onBurnRateAlert?: (info: BurnRateAlertInfo) => void;
  now: () => number;
}

/**
 * WR-346: a partial live revision of the five error-budget knobs —
 * omitted fields keep their live values. `now` is never revisable: a
 * retune carries the construction clock forward untouched. WR-353:
 * `onBurnRateAlert` is revisable after all — via the dedicated
 * `replaceAlertCallback()`, not through `retune()` — so the WR-346
 * "never revisable" exclusion no longer holds for the callback.
 */
export type ErrorBudgetRevision = Partial<
  Pick<
    ResolvedErrorBudgetOptions,
    "fastWindowMs" | "slowWindowMs" | "budgetErrorRate" | "alertThreshold" | "minEvents"
  >
>;

/** WR-346: the five live error-budget knobs, all required. */
export interface ErrorBudgetConfig {
  fastWindowMs: number;
  slowWindowMs: number;
  budgetErrorRate: number;
  alertThreshold: number;
  minEvents: number;
}

/**
 * Validate an {@link ErrorBudgetOptions} and fill in defaults. Throws
 * `RangeError` on any invalid value — fail fast at startup, never
 * mis-alert at runtime.
 */
export function resolveErrorBudgetOptions(options: ErrorBudgetOptions): ResolvedErrorBudgetOptions {
  const fastWindowMs = options.fastWindowMs ?? DEFAULT_FAST_WINDOW_MS;
  const slowWindowMs = options.slowWindowMs ?? DEFAULT_SLOW_WINDOW_MS;
  const budgetErrorRate = options.budgetErrorRate ?? DEFAULT_BUDGET_ERROR_RATE;
  const alertThreshold = options.alertThreshold ?? DEFAULT_ALERT_THRESHOLD;
  const minEvents = options.minEvents ?? DEFAULT_MIN_EVENTS;
  const fail = (msg: string): never => {
    throw new RangeError(`errorBudget: ${msg}`);
  };
  if (!Number.isInteger(fastWindowMs) || fastWindowMs <= 0) fail(`fastWindowMs must be a positive integer of ms, got ${String(options.fastWindowMs)}`);
  if (!Number.isInteger(slowWindowMs) || slowWindowMs <= 0) fail(`slowWindowMs must be a positive integer of ms, got ${String(options.slowWindowMs)}`);
  if (slowWindowMs <= fastWindowMs) fail(`slowWindowMs (${slowWindowMs}) must exceed fastWindowMs (${fastWindowMs})`);
  if (typeof budgetErrorRate !== "number" || !(budgetErrorRate > 0) || budgetErrorRate >= 1) {
    fail(`budgetErrorRate must be in (0, 1), got ${String(options.budgetErrorRate)}`);
  }
  if (typeof alertThreshold !== "number" || !(alertThreshold > 0)) {
    fail(`alertThreshold must be a positive number, got ${String(options.alertThreshold)}`);
  }
  if (!Number.isInteger(minEvents) || minEvents <= 0) fail(`minEvents must be a positive integer, got ${String(options.minEvents)}`);
  if (options.onBurnRateAlert !== undefined && typeof options.onBurnRateAlert !== "function") {
    fail("onBurnRateAlert must be a function");
  }
  return {
    fastWindowMs,
    slowWindowMs,
    budgetErrorRate,
    alertThreshold,
    minEvents,
    onBurnRateAlert: options.onBurnRateAlert,
    now: options.now ?? Date.now,
  };
}

interface OutcomeEvent {
  t: number;
  ok: boolean;
}

interface EndpointState {
  /** Sliding outcomes, pruned to the slow window on every record. */
  events: OutcomeEvent[];
  /** Edge-trigger latch: true while an alert episode is open. */
  alerting: boolean;
}

/**
 * Per-endpoint error-budget burn-rate monitor. Feed it one outcome per
 * delivery attempt with {@link recordOutcome}; it evaluates the
 * SRE-style fast/slow burn-rate windows and fires `onBurnRateAlert`
 * edge-triggered. `render()` exposes the current fast-window burn rate
 * per endpoint as `relay_error_budget_burn_ratio` (activity-gated).
 *
 * The monitor never touches the delivery path — it only observes.
 *
 * WR-346: the five knobs are live-revisable with `retune()` — no
 * restart. A retune takes effect on the next `recordOutcome`;
 * widening a window never resurrects samples already pruned, and an
 * open alert episode is untouched until the next outcome
 * re-evaluates it.
 */
export class ErrorBudgetMonitor {
  // WR-346: not readonly — `retune()` replaces the resolved config in
  // place so the five knobs are live-revisable. `now` is carried over
  // unchanged by every retune, never revised. WR-353: the callback is
  // live-replaceable via `replaceAlertCallback()`; a retune carries
  // the live callback forward untouched.
  private opts: ResolvedErrorBudgetOptions;
  private readonly states = new Map<string, EndpointState>();

  constructor(options: ErrorBudgetOptions = {}) {
    this.opts = resolveErrorBudgetOptions(options);
  }

  /**
   * WR-346: revise the five burn-rate knobs at runtime — no restart.
   * The patch must be a non-empty object; the merged config is
   * re-validated with the same five gates (and the same error text)
   * as construction, including the `slowWindowMs > fastWindowMs`
   * cross-gate, so an illegal patch throws `RangeError` and the live
   * values are left completely intact. Revising to the live values is
   * a silent no-op. Takes effect on the next `recordOutcome`: the
   * prune cutoff and the fast/slow window evaluation read the live
   * values, so tightening the slow window prunes older samples on the
   * next record while widening it never resurrects samples already
   * pruned — already-accumulated outcomes are never recomputed. An
   * open alert episode is neither opened nor closed early by a
   * retune; the next outcome re-evaluates the latch under the new
   * threshold. Returns the live config.
   */
  retune(patch: ErrorBudgetRevision): ErrorBudgetConfig {
    if (patch === null || typeof patch !== "object" || Array.isArray(patch)) {
      throw new RangeError(`errorBudget revision must be an object, got ${JSON.stringify(patch)}`);
    }
    if (Object.keys(patch).length === 0) {
      throw new RangeError("errorBudget revision must not be empty");
    }
    // Validate-then-apply: the merged config must pass the
    // construction gates before the live values move.
    const resolved = resolveErrorBudgetOptions({
      fastWindowMs: patch.fastWindowMs ?? this.opts.fastWindowMs,
      slowWindowMs: patch.slowWindowMs ?? this.opts.slowWindowMs,
      budgetErrorRate: patch.budgetErrorRate ?? this.opts.budgetErrorRate,
      alertThreshold: patch.alertThreshold ?? this.opts.alertThreshold,
      minEvents: patch.minEvents ?? this.opts.minEvents,
      onBurnRateAlert: this.opts.onBurnRateAlert,
      now: this.opts.now,
    });
    this.opts = resolved;
    return this.config();
  }

  /**
   * WR-353: replace the burn-rate alert callback at runtime — no
   * restart. A non-function callback throws `RangeError` (the same
   * gate as construction) and the live callback is left completely
   * untouched; `undefined` clears the callback back to unset.
   * Replacing with the same reference (or clearing when already
   * unset) is a silent no-op. Only the callback moves: the five
   * knobs, the clock, the accumulated outcomes, and the open-episode
   * latches are untouched — the new callback takes effect from the
   * next episode open, an open episode never re-fires, and a throwing
   * callback is still swallowed by `recordOutcome`, so alerting can
   * never break the delivery path. A later `retune()` carries the
   * replaced callback forward unchanged.
   */
  replaceAlertCallback(cb?: (info: BurnRateAlertInfo) => void): void {
    if (cb !== undefined && typeof cb !== "function") {
      throw new RangeError("errorBudget: onBurnRateAlert must be a function");
    }
    if (cb === this.opts.onBurnRateAlert) return;
    this.opts = { ...this.opts, onBurnRateAlert: cb };
  }

  /**
   * WR-346: the live five-knob config. A snapshot — mutating the
   * returned object never moves the monitor.
   */
  config(): ErrorBudgetConfig {
    return {
      fastWindowMs: this.opts.fastWindowMs,
      slowWindowMs: this.opts.slowWindowMs,
      budgetErrorRate: this.opts.budgetErrorRate,
      alertThreshold: this.opts.alertThreshold,
      minEvents: this.opts.minEvents,
    };
  }

  /**
   * Record one delivery attempt outcome for an endpoint. `succeeded`
   * mirrors the queue's `recordDelivery` funnel: `true` on `delivered`,
   * `false` on `failed` — exactly one call per attempt.
   */
  recordOutcome(endpoint: string, succeeded: boolean): void {
    const now = this.opts.now();
    let st = this.states.get(endpoint);
    if (st === undefined) {
      st = { events: [], alerting: false };
      this.states.set(endpoint, st);
    }
    st.events.push({ t: now, ok: succeeded });
    // Prune to the slow window: memory stays bounded by the slow
    // window's event count, and stale outcomes never inflate a rate.
    const cutoff = now - this.opts.slowWindowMs;
    while (st.events.length > 0 && st.events[0].t < cutoff) st.events.shift();

    const fast = this.windowStats(st.events, now - this.opts.fastWindowMs);
    const slow = this.windowStats(st.events, cutoff);
    const burnRate = fast.errorRate / this.opts.budgetErrorRate;
    const slowBurnRate = slow.errorRate / this.opts.budgetErrorRate;
    const burning =
      fast.total >= this.opts.minEvents &&
      burnRate > this.opts.alertThreshold &&
      slowBurnRate > this.opts.alertThreshold;

    if (burning && !st.alerting) {
      // Edge: the episode opens — alert exactly once.
      st.alerting = true;
      const info: BurnRateAlertInfo = {
        endpoint,
        burnRate,
        fastErrorRate: fast.errorRate,
        slowErrorRate: slow.errorRate,
        slowBurnRate,
        budgetErrorRate: this.opts.budgetErrorRate,
        alertThreshold: this.opts.alertThreshold,
        fastWindowMs: this.opts.fastWindowMs,
        slowWindowMs: this.opts.slowWindowMs,
      };
      try {
        this.opts.onBurnRateAlert?.(info);
      } catch {
        // Alerting must never break the delivery path: the alert is
        // lost, the delivery is not.
      }
    } else if (!burning && st.alerting) {
      // Recovered — re-arm for the next episode.
      st.alerting = false;
    }
  }

  /** Whether the endpoint currently has an open alert episode. */
  isAlerting(endpoint: string): boolean {
    return this.states.get(endpoint)?.alerting ?? false;
  }

  /**
   * Current fast-window burn rate for an endpoint (`undefined` when the
   * endpoint has no outcomes in the window).
   */
  burnRate(endpoint: string): number | undefined {
    const st = this.states.get(endpoint);
    if (st === undefined || st.events.length === 0) return undefined;
    const now = this.opts.now();
    const fast = this.windowStats(st.events, now - this.opts.fastWindowMs);
    if (fast.total === 0) return undefined;
    return fast.errorRate / this.opts.budgetErrorRate;
  }

  /** Endpoints with outcomes in the slow window, in first-seen order. */
  endpoints(): string[] {
    const out: string[] = [];
    const now = this.opts.now();
    for (const [endpoint, st] of this.states) {
      // Drop fully-aged endpoints so the gauge does not linger forever.
      while (st.events.length > 0 && st.events[0].t < now - this.opts.slowWindowMs) st.events.shift();
      if (st.events.length > 0) out.push(endpoint);
      else this.states.delete(endpoint);
    }
    return out;
  }

  /**
   * Prometheus exposition for `GET /metrics`:
   * `relay_error_budget_burn_ratio{endpoint}` — the current fast-window
   * burn rate (1.0 = exactly at budget). `""` when no endpoint has
   * outcomes: activity-gated, so relays that never enable the monitor
   * see byte-identical output.
   */
  render(): string {
    const endpoints = this.endpoints();
    if (endpoints.length === 0) return "";
    const lines = [
      "# HELP relay_error_budget_burn_ratio Per-endpoint error-budget burn rate (WR-147; 1.0 = exactly at budget).",
      "# TYPE relay_error_budget_burn_ratio gauge",
    ];
    for (const endpoint of endpoints) {
      const ratio = this.burnRate(endpoint) ?? 0;
      lines.push(`relay_error_budget_burn_ratio{endpoint="${escapeLabelValue(endpoint)}"} ${ratio}`);
    }
    return lines.join("\n") + "\n";
  }

  private windowStats(events: OutcomeEvent[], since: number): { total: number; errorRate: number } {
    let total = 0;
    let errors = 0;
    for (const e of events) {
      if (e.t < since) continue;
      total++;
      if (!e.ok) errors++;
    }
    return { total, errorRate: total === 0 ? 0 : errors / total };
  }
}

/** Minimal Prometheus label escaping (mirrors `src/metrics.ts`). */
function escapeLabelValue(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
}

/**
 * Build the `error_budget_burn` audit event for a fired alert.
 */
export function errorBudgetBurnAuditEvent(info: BurnRateAlertInfo): ErrorBudgetBurnAuditEvent {
  return {
    event: "error_budget_burn",
    endpoint: info.endpoint,
    burnRate: info.burnRate,
    fastErrorRate: info.fastErrorRate,
    slowErrorRate: info.slowErrorRate,
    slowBurnRate: info.slowBurnRate,
    budgetErrorRate: info.budgetErrorRate,
    alertThreshold: info.alertThreshold,
    fastWindowMs: info.fastWindowMs,
    slowWindowMs: info.slowWindowMs,
  };
}
