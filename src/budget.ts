/**
 * Tenant-level monthly delivery budget enforcement (WR-137).
 *
 * On top of the WR-78 usage metering, this module adds a *budget*
 * enforcement layer for usage-based billing (backend engineering /
 * payments-fintech SaaS billing): an operator sets a per-tenant monthly
 * delivery allowance with {@link TenantBudgetEnforcer.setTenantBudget},
 * and deliveries past the allowance are *delayed* — parked until the
 * next UTC calendar month — never dropped, never charged to the retry
 * budget, and never shown to the circuit breaker (the WR-15 quota
 * pattern, tenant-scoped).
 *
 * What counts as a delivery is the WR-78 billing vocabulary: the
 * `delivered` count. Since WR-78 guarantees `failed === retried +
 * dead_letter`, `delivered` is the only terminal-success counter, and it
 * is orthogonal to the WR-15 quota counts. The enforcer keeps its own
 * monthly buckets (the UsageMeter's window is rolling, so it cannot
 * serve a calendar-month budget) fed from the same `delivered` events.
 *
 * Tenants come from the inbound `x-tenant-id` header (see `src/tenant.ts`);
 * requests without the header are billed to the `default` tenant, like
 * everywhere else in the relay. A tenant without a configured budget is
 * **unlimited** — the default relay is byte-identical to the pre-WR-137
 * one.
 *
 * Zero dependencies (node builtins plus sibling modules only).
 */

import { assertValidTenantId } from "./tenant.ts";
import { DEFAULT_TENANT } from "./usage.ts";

/** One month in the UTC calendar, `YYYY-MM`. */
export type BudgetMonth = string;

/** Options for {@link TenantBudgetEnforcer.setTenantBudget}. */
export interface TenantBudgetConfig {
  /**
   * Maximum terminal deliveries (`delivered`) the tenant may consume
   * per UTC calendar month. Must be a positive integer — anything else
   * throws `RangeError`.
   */
  deliveriesPerMonth: number;
}

/** Options for {@link TenantBudgetEnforcer}. */
export interface TenantBudgetOptions {
  /**
   * Clock in ms; defaults to `Date.now`. Injectable for deterministic
   * tests (month-boundary behavior is fully clock-driven).
   */
  now?: () => number;
  /**
   * Initial budgets (`tenant -> deliveriesPerMonth`). Convenience for
   * construction-time config; validated exactly like
   * {@link TenantBudgetEnforcer.setTenantBudget}.
   */
  budgets?: Record<string, number>;
  /**
   * Maximum tenants with configured budgets; the least-recently-active
   * row is evicted past the cap. Default: 10000. Must be an integer >= 1.
   * Budgets are operator-set, so the cap is a safety rail, not a sizing
   * knob — evicting a row drops its budget (the row falls back to
   * unlimited).
   */
  maxTenants?: number;
}

/**
 * Fired on the first dispatch found over budget for a tenant in a UTC
 * calendar month — once per tenant per month, never an audit flood. The
 * month rollover re-arms it.
 */
export interface TenantBudgetAuditEvent {
  event: "budget_exceeded";
  /** Tenant id, or `"default"` for the default tenant. */
  tenant: string;
  /** The tenant's configured monthly allowance. */
  deliveriesPerMonth: number;
  /** Deliveries counted this month when the exceedance was found. */
  used: number;
  /** The UTC month (`YYYY-MM`) the exceedance belongs to. */
  month: BudgetMonth;
  /** ISO-8601 timestamp when the exceedance was detected. */
  at: string;
}

/**
 * One dispatch-time budget verdict (see
 * {@link TenantBudgetEnforcer.checkOver}).
 */
export interface TenantBudgetVerdict {
  /** True when the tenant is over its monthly delivery budget. */
  over: boolean;
  /** Tenant id, or `"default"` for the default tenant. */
  tenant: string;
  /** The UTC month (`YYYY-MM`) this verdict was computed for. */
  month: BudgetMonth;
  /** Deliveries counted this month. */
  used: number;
  /** Configured budget; `undefined` when the tenant is unlimited. */
  budget?: number;
  /** ms until the next UTC month boundary (0 when not over). */
  retryAfterMs: number;
  /**
   * True when the `budget_exceeded` audit event is due — the first
   * over-budget verdict for this tenant this month. The caller emits
   * the {@link TenantBudgetAuditEvent}; this flag exists so the caller
   * (the queue) can wrap the event into the audit log like every other
   * queue audit hook.
   */
  auditDue: boolean;
  /** ISO-8601 timestamp of the verdict, from the enforcer's clock. */
  at: string;
}

/** One row of {@link TenantBudgetEnforcer.snapshot}. */
export interface TenantBudgetStatsRow {
  /** Tenant id, or `"default"` for the default tenant. */
  tenant: string;
  /** The UTC month (`YYYY-MM`) the counters belong to. */
  month: BudgetMonth;
  /** Deliveries counted this month. */
  used: number;
  /** Configured monthly budget. */
  budget: number;
  /** Whether the tenant is currently over budget. */
  over: boolean;
}

/** Default cap on tenants with configured budgets. */
export const DEFAULT_MAX_BUDGET_TENANTS = 10_000;

interface TenantBudgetState {
  budget: number;
  /** UTC month (`YYYY-MM`) `used` was counted in. */
  month: BudgetMonth;
  /** Deliveries counted in `month`. */
  used: number;
  /** UTC month the `budget_exceeded` audit already fired for. */
  auditedMonth?: BudgetMonth;
  lastActive: number;
}

/** Escape a label value per the Prometheus exposition format. */
function escapeLabelValue(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, '\\"');
}

/** UTC calendar month (`YYYY-MM`) containing `at`. */
export function budgetMonthOf(at: number): BudgetMonth {
  const d = new Date(at);
  const y = d.getUTCFullYear();
  const m = d.getUTCMonth() + 1;
  return `${y}-${m < 10 ? "0" : ""}${m}`;
}

/** Milliseconds from `at` to the next UTC month boundary. */
export function msUntilBudgetReset(at: number): number {
  const d = new Date(at);
  const next = Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1);
  return Math.max(0, next - at);
}

function assertValidBudget(deliveriesPerMonth: number): void {
  if (!Number.isInteger(deliveriesPerMonth) || deliveriesPerMonth <= 0) {
    throw new RangeError(
      `deliveriesPerMonth must be a positive integer, got ${deliveriesPerMonth}`
    );
  }
}

export class TenantBudgetEnforcer {
  private readonly now: () => number;
  private readonly maxTenants: number;
  private readonly tenants = new Map<string, TenantBudgetState>();

  constructor(opts: TenantBudgetOptions = {}) {
    this.now = opts.now ?? Date.now;
    this.maxTenants = opts.maxTenants ?? DEFAULT_MAX_BUDGET_TENANTS;
    if (!Number.isInteger(this.maxTenants) || this.maxTenants < 1) {
      throw new RangeError(`maxTenants must be an integer >= 1, got ${opts.maxTenants}`);
    }
    if (opts.budgets !== undefined) {
      for (const [tenant, budget] of Object.entries(opts.budgets)) {
        this.setTenantBudget(tenant, { deliveriesPerMonth: budget });
      }
    }
  }

  private tenantKey(tenant: string | undefined): string {
    return tenant ?? DEFAULT_TENANT;
  }

  /**
   * Set (or replace) a tenant's monthly delivery budget. Takes effect
   * immediately: a tenant already past the new allowance parks its next
   * dispatch. `RangeError` for a non-positive (or non-integer) budget,
   * `TypeError`/`RangeError` for an invalid tenant id — and the current
   * budget is left intact.
   */
  setTenantBudget(tenantId: string, config: TenantBudgetConfig): void {
    assertValidTenantId(tenantId);
    assertValidBudget(config.deliveriesPerMonth);
    const at = this.now();
    const month = budgetMonthOf(at);
    let s = this.tenants.get(tenantId);
    if (s === undefined) {
      s = { budget: config.deliveriesPerMonth, month, used: 0, lastActive: at };
      this.tenants.set(tenantId, s);
      // Safety rail only: budgets are operator-set, so the population is
      // small; past the cap evict the least-recently-active *other* row
      // (the row being set is never its own eviction victim).
      while (this.tenants.size > this.maxTenants) {
        let oldestKey: string | undefined;
        let oldestAt = Infinity;
        for (const [k, st] of this.tenants) {
          if (k !== tenantId && st.lastActive < oldestAt) {
            oldestKey = k;
            oldestAt = st.lastActive;
          }
        }
        if (oldestKey === undefined) break;
        this.tenants.delete(oldestKey);
      }
    } else {
      s.budget = config.deliveriesPerMonth;
      s.lastActive = at;
      this.rollMonth(s, month);
    }
  }

  /**
   * Drop a tenant's budget — the tenant falls back to unlimited. Never
   * throws for unknown tenants.
   */
  clearTenantBudget(tenantId: string): void {
    this.tenants.delete(tenantId);
  }

  /** Configured monthly budget for `tenantId`, or `undefined` when unlimited. */
  budgetFor(tenantId?: string): number | undefined {
    return this.tenants.get(this.tenantKey(tenantId))?.budget;
  }

  /** Whether at least one tenant carries a configured budget. */
  hasBudgets(): boolean {
    return this.tenants.size > 0;
  }

  /** Roll a row into the current month, zeroing the counter. */
  private rollMonth(s: TenantBudgetState, month: BudgetMonth): void {
    if (s.month !== month) {
      s.month = month;
      s.used = 0;
      // The audit re-arms with the month: a fresh month's first
      // exceedance fires a fresh `budget_exceeded`.
      s.auditedMonth = undefined;
    }
  }

  /**
   * Count one terminal delivery against the tenant's current-month
   * budget. Feed the same `delivered` events that WR-78 meters — dead
   * letters and retries never count (per WR-78, `failed === retried +
   * dead_letter`, so `delivered` alone is the terminal-success counter).
   * No-op for tenants without a configured budget.
   */
  recordDelivered(tenantId?: string): void {
    const at = this.now();
    const s = this.tenants.get(this.tenantKey(tenantId));
    if (s === undefined) return;
    s.lastActive = at;
    this.rollMonth(s, budgetMonthOf(at));
    s.used += 1;
  }

  /**
   * Dispatch-time verdict for `tenantId`. Unlimited tenants and tenants
   * inside their budget get `{ over: false }`. Over-budget tenants get
   * `{ over: true, retryAfterMs }` — the caller parks the delivery for
   * `retryAfterMs` (the next UTC month boundary) plus a little jitter,
   * never dropping it. `auditDue` is true exactly on the first
   * over-budget verdict per tenant per month — the caller emits the
   * {@link TenantBudgetAuditEvent} then.
   */
  checkOver(tenantId?: string): TenantBudgetVerdict {
    const at = this.now();
    const key = this.tenantKey(tenantId);
    const month = budgetMonthOf(at);
    const s = this.tenants.get(key);
    const atIso = new Date(at).toISOString();
    if (s === undefined) {
      return {
        over: false,
        tenant: key,
        month,
        used: 0,
        retryAfterMs: 0,
        auditDue: false,
        at: atIso,
      };
    }
    s.lastActive = at;
    this.rollMonth(s, month);
    if (s.used < s.budget) {
      return {
        over: false,
        tenant: key,
        month: s.month,
        used: s.used,
        budget: s.budget,
        retryAfterMs: 0,
        auditDue: false,
        at: atIso,
      };
    }
    const auditDue = s.auditedMonth !== s.month;
    if (auditDue) s.auditedMonth = s.month;
    return {
      over: true,
      tenant: key,
      month: s.month,
      used: s.used,
      budget: s.budget,
      retryAfterMs: msUntilBudgetReset(at),
      auditDue,
      at: atIso,
    };
  }

  /**
   * One row per tenant with a configured budget, sorted by tenant. The
   * `over` flag is computed against the current month (rolling the
   * counter first), so a stale row never reports a stale verdict.
   */
  snapshot(): TenantBudgetStatsRow[] {
    const at = this.now();
    const month = budgetMonthOf(at);
    const rows: TenantBudgetStatsRow[] = [];
    for (const [tenant, s] of this.tenants) {
      this.rollMonth(s, month);
      rows.push({
        tenant,
        month: s.month,
        used: s.used,
        budget: s.budget,
        over: s.used >= s.budget,
      });
    }
    rows.sort((a, b) => (a.tenant < b.tenant ? -1 : a.tenant > b.tenant ? 1 : 0));
    return rows;
  }

  /**
   * Prometheus text exposition (0.0.4):
   * `relay_tenant_budget_deliveries_total{tenant}` (gauge: this month's
   * counted deliveries) and `relay_tenant_budget_deliveries_limit{tenant}`
   * (gauge: the configured monthly allowance). Returns `""` when no
   * tenant carries a budget, so the series stay absent exactly like the
   * other opt-in modules.
   */
  render(): string {
    const rows = this.snapshot();
    if (rows.length === 0) return "";
    const lines: string[] = [
      "# HELP relay_tenant_budget_deliveries_total Monthly delivered deliveries counted against the tenant delivery budget (WR-137).",
      "# TYPE relay_tenant_budget_deliveries_total gauge",
    ];
    for (const row of rows) {
      lines.push(
        `relay_tenant_budget_deliveries_total{tenant="${escapeLabelValue(row.tenant)}"} ${row.used}`
      );
    }
    lines.push(
      "# HELP relay_tenant_budget_deliveries_limit Configured monthly delivery budget, in deliveries per UTC month (WR-137).",
      "# TYPE relay_tenant_budget_deliveries_limit gauge"
    );
    for (const row of rows) {
      lines.push(
        `relay_tenant_budget_deliveries_limit{tenant="${escapeLabelValue(row.tenant)}"} ${row.budget}`
      );
    }
    return lines.join("\n") + "\n";
  }
}
