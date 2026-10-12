/**
 * Tenant-level usage metering for usage-based billing (WR-78).
 *
 * A {@link UsageMeter} counts, per tenant, inside a rolling window
 * (default 1 hour):
 *
 * - `delivered` — deliveries the downstream accepted (terminal success),
 * - `failed` — delivery attempts the downstream did not accept,
 * - `retried` — retries scheduled after a failed attempt (a subset of
 *   `failed`: every `retrying` delivery event is one failed attempt),
 * - `dead_letter` — deliveries that exhausted the retry budget (each one
 *   is also one `failed` attempt: its final one),
 * - `bytes_in` — inbound payload bytes accepted at intake,
 * - `bytes_out` — outbound payload bytes on successful deliveries,
 * - `urgent` — accepted events marked `x-priority: urgent` (fast-lane
 *   admissions).
 *
 * Invariant: `failed === retried + dead_letter` — a failed attempt either
 * schedules a retry or lands in the dead-letter queue, never both, never
 * neither.
 *
 * The meter is orthogonal to the delivery quota (WR-15): the quota is a
 * protective gate that *delays* attempts, the meter is a billing counter
 * that never gates, delays, or drops anything. Recording is O(1) on the
 * hot path; window expiry is lazy (on record and on read).
 *
 * Tenants come from the inbound `x-tenant-id` header (see `src/tenant.ts`).
 * Requests without the header are billed to the `default` tenant — the
 * same tenant the rest of the relay treats as unscoped.
 *
 * Memory is bounded: per-tenant samples are capped (`maxEventsPerTenant`,
 * oldest dropped first) and the tenant population is capped
 * (`maxTenants`, least-recently-active tenant evicted).
 *
 * Zero dependencies.
 */

/** Tenant label used when the request carried no `x-tenant-id`. */
export const DEFAULT_TENANT = "default";

/** One hour in ms — the default metering window. */
export const DEFAULT_USAGE_WINDOW_MS = 3_600_000;

/** Default cap on tracked tenants (least-recently-active evicted past it). */
export const DEFAULT_MAX_TENANTS = 10_000;

/** Default cap on samples per tenant (oldest dropped first past it). */
export const DEFAULT_MAX_EVENTS_PER_TENANT = 100_000;

export interface UsageOptions {
  /**
   * Rolling window (ms) counters are summed over. Default: 3600000 (1h).
   * Must be a finite number > 0.
   */
  windowMs?: number;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
  /**
   * Maximum tracked tenants; the least-recently-active tenant is evicted
   * past the cap. Default: 10000. Must be an integer >= 1.
   */
  maxTenants?: number;
  /**
   * Maximum samples kept per tenant (inbound + delivery samples share the
   * budget); the oldest samples are dropped first. Default: 100000. Must
   * be an integer >= 1.
   */
  maxEventsPerTenant?: number;
}

/** Delivery outcomes the meter tracks (billing vocabulary). */
export type UsageOutcome = "delivered" | "failed" | "retried" | "dead_letter";

/**
 * Minimal delivery-event shape the meter consumes — a structural subset
 * of `retry.ts`'s `DeliveryEvent`, so the queue's events are assignable
 * without importing the queue module.
 */
export interface UsageDeliveryEvent {
  type: "delivered" | "retrying" | "dead_letter";
  tenant?: string;
  /** Outbound payload bytes for this delivery; 0 when unknown. */
  bytesOut?: number;
}

/** One accepted inbound webhook, for `bytes_in` / `urgent` accounting. */
export interface UsageInboundRecord {
  tenant?: string;
  /** Accepted payload bytes. Must be a non-negative integer. */
  bytesIn: number;
  /** The event rode the urgent fast lane (`x-priority: urgent`). */
  urgent?: boolean;
}

/** One delivery outcome sample, for the terminal/retry counters. */
export interface UsageDeliveryRecord {
  tenant?: string;
  type: UsageOutcome;
  /** Outbound payload bytes; counted for `delivered` only. */
  bytesOut?: number;
}

/** Rolling-window aggregates for one tenant. */
export interface TenantUsage {
  /** Tenant id, or `"default"` when the request carried no `x-tenant-id`. */
  tenant: string;
  /** The window these counters were summed over (ms). */
  windowMs: number;
  delivered: number;
  failed: number;
  retried: number;
  deadLetter: number;
  bytesIn: number;
  bytesOut: number;
  urgent: number;
}

interface InboundSample {
  at: number;
  bytes: number;
  urgent: boolean;
}

interface DeliverySample {
  at: number;
  type: UsageOutcome;
  bytesOut: number;
}

interface TenantState {
  inbound: InboundSample[];
  deliveries: DeliverySample[];
  lastActive: number;
}

/** Escape a label value per the Prometheus exposition format. */
function escapeLabelValue(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, '\\"');
}

export class UsageMeter {
  private readonly windowMs: number;
  private readonly maxTenants: number;
  private readonly maxEventsPerTenant: number;
  private readonly now: () => number;
  private readonly tenants = new Map<string, TenantState>();

  constructor(opts: UsageOptions = {}) {
    this.windowMs = opts.windowMs ?? DEFAULT_USAGE_WINDOW_MS;
    this.maxTenants = opts.maxTenants ?? DEFAULT_MAX_TENANTS;
    this.maxEventsPerTenant = opts.maxEventsPerTenant ?? DEFAULT_MAX_EVENTS_PER_TENANT;
    this.now = opts.now ?? Date.now;
    if (!Number.isFinite(this.windowMs) || this.windowMs <= 0) {
      throw new RangeError(`windowMs must be a finite number > 0, got ${opts.windowMs}`);
    }
    if (!Number.isInteger(this.maxTenants) || this.maxTenants < 1) {
      throw new RangeError(`maxTenants must be an integer >= 1, got ${opts.maxTenants}`);
    }
    if (!Number.isInteger(this.maxEventsPerTenant) || this.maxEventsPerTenant < 1) {
      throw new RangeError(
        `maxEventsPerTenant must be an integer >= 1, got ${opts.maxEventsPerTenant}`
      );
    }
  }

  private tenantKey(tenant: string | undefined): string {
    return tenant ?? DEFAULT_TENANT;
  }

  private stateFor(key: string, at: number): TenantState {
    let s = this.tenants.get(key);
    if (s === undefined) {
      s = { inbound: [], deliveries: [], lastActive: at };
      this.tenants.set(key, s);
      // Evict the least-recently-active *other* tenant past the cap, so a
      // flood of distinct tenant ids cannot grow memory unboundedly. The
      // tenant being recorded is never its own eviction victim.
      while (this.tenants.size > this.maxTenants) {
        let oldestKey: string | undefined;
        let oldestAt = Infinity;
        for (const [k, st] of this.tenants) {
          if (k !== key && st.lastActive < oldestAt) {
            oldestKey = k;
            oldestAt = st.lastActive;
          }
        }
        if (oldestKey === undefined) break;
        this.tenants.delete(oldestKey);
      }
    }
    s.lastActive = at;
    return s;
  }

  /** Drop samples outside the window. Insertion-ordered, so stop at the first live one. */
  private evictExpired(s: TenantState, at: number): void {
    while (s.inbound.length > 0 && at - s.inbound[0].at >= this.windowMs) s.inbound.shift();
    while (s.deliveries.length > 0 && at - s.deliveries[0].at >= this.windowMs) s.deliveries.shift();
  }

  /** Enforce the per-tenant sample cap, oldest first. */
  private enforceCap(s: TenantState): void {
    while (s.inbound.length + s.deliveries.length > this.maxEventsPerTenant) {
      const inOldest = s.inbound.length > 0 ? s.inbound[0].at : Infinity;
      const delOldest = s.deliveries.length > 0 ? s.deliveries[0].at : Infinity;
      if (inOldest <= delOldest) s.inbound.shift();
      else s.deliveries.shift();
    }
  }

  /**
   * Record one accepted inbound webhook. Call at intake, after the event
   * is enqueued — rejections, schema failures, and dedup-suppressed
   * duplicates are acknowledged-but-not-processed and never bill.
   */
  recordInbound(record: UsageInboundRecord): void {
    if (!Number.isInteger(record.bytesIn) || record.bytesIn < 0) {
      throw new RangeError(`bytesIn must be a non-negative integer, got ${record.bytesIn}`);
    }
    const at = this.now();
    const s = this.stateFor(this.tenantKey(record.tenant), at);
    this.evictExpired(s, at);
    s.inbound.push({ at, bytes: record.bytesIn, urgent: record.urgent === true });
    this.enforceCap(s);
  }

  /** Record one delivery outcome sample (see {@link UsageDeliveryRecord}). */
  recordDelivery(record: UsageDeliveryRecord): void {
    const bytesOut = record.bytesOut ?? 0;
    if (!Number.isInteger(bytesOut) || bytesOut < 0) {
      throw new RangeError(`bytesOut must be a non-negative integer, got ${record.bytesOut}`);
    }
    const at = this.now();
    const s = this.stateFor(this.tenantKey(record.tenant), at);
    this.evictExpired(s, at);
    s.deliveries.push({ at, type: record.type, bytesOut });
    this.enforceCap(s);
  }

  /**
   * Record one queue delivery event, translating the queue's vocabulary
   * (`delivered` / `retrying` / `dead_letter`) into billing outcomes:
   * `delivered` → `delivered`; `retrying` → `retried` + `failed` (the
   * attempt that just failed); `dead_letter` → `dead_letter` + `failed`
   * (its final attempt). Preserves `failed === retried + dead_letter`.
   */
  recordDeliveryEvent(event: UsageDeliveryEvent): void {
    const tenant = event.tenant;
    if (event.type === "delivered") {
      this.recordDelivery({ tenant, type: "delivered", bytesOut: event.bytesOut ?? 0 });
    } else if (event.type === "retrying") {
      this.recordDelivery({ tenant, type: "retried" });
      this.recordDelivery({ tenant, type: "failed" });
    } else {
      this.recordDelivery({ tenant, type: "dead_letter" });
      this.recordDelivery({ tenant, type: "failed" });
    }
  }

  private aggregate(key: string, s: TenantState, at: number): TenantUsage {
    this.evictExpired(s, at);
    let delivered = 0;
    let failed = 0;
    let retried = 0;
    let deadLetter = 0;
    let bytesOut = 0;
    for (const d of s.deliveries) {
      if (d.type === "delivered") {
        delivered += 1;
        bytesOut += d.bytesOut;
      } else if (d.type === "failed") {
        failed += 1;
      } else if (d.type === "retried") {
        retried += 1;
      } else {
        deadLetter += 1;
      }
    }
    let bytesIn = 0;
    let urgent = 0;
    for (const i of s.inbound) {
      bytesIn += i.bytes;
      if (i.urgent) urgent += 1;
    }
    return {
      tenant: key,
      windowMs: this.windowMs,
      delivered,
      failed,
      retried,
      deadLetter,
      bytesIn,
      bytesOut,
      urgent,
    };
  }

  /**
   * Rolling-window aggregates. With `tenant`, returns at most one row
   * (empty when the tenant has no samples inside the window); without it,
   * one row per tenant with live samples, sorted by tenant name.
   */
  snapshot(tenant?: string): TenantUsage[] {
    const at = this.now();
    const rows: TenantUsage[] = [];
    if (tenant !== undefined) {
      const key = this.tenantKey(tenant);
      const s = this.tenants.get(key);
      if (s !== undefined) {
        const row = this.aggregate(key, s, at);
        if (this.hasSamples(row)) rows.push(row);
      }
      return rows;
    }
    for (const [key, s] of this.tenants) {
      const row = this.aggregate(key, s, at);
      if (this.hasSamples(row)) rows.push(row);
    }
    rows.sort((a, b) => (a.tenant < b.tenant ? -1 : a.tenant > b.tenant ? 1 : 0));
    return rows;
  }

  private hasSamples(row: TenantUsage): boolean {
    return (
      row.delivered + row.failed + row.retried + row.deadLetter + row.urgent > 0 ||
      row.bytesIn > 0 ||
      row.bytesOut > 0
    );
  }

  /**
   * Prometheus text exposition (0.0.4) for the current window:
   * `relay_tenant_deliveries_total{tenant,outcome}`,
   * `relay_tenant_bytes_in_total{tenant}`,
   * `relay_tenant_bytes_out_total{tenant}`,
   * `relay_tenant_urgent_total{tenant}`. Returns `""` when no tenant has
   * samples inside the window, so the series stay absent exactly like the
   * other opt-in modules.
   */
  render(): string {
    const rows = this.snapshot();
    if (rows.length === 0) return "";
    const lines: string[] = [
      "# HELP relay_tenant_deliveries_total Deliveries inside the usage window, per tenant and outcome.",
      "# TYPE relay_tenant_deliveries_total counter",
    ];
    const outcomes: Array<[UsageOutcome, keyof TenantUsage]> = [
      ["delivered", "delivered"],
      ["failed", "failed"],
      ["retried", "retried"],
      ["dead_letter", "deadLetter"],
    ];
    for (const row of rows) {
      const t = escapeLabelValue(row.tenant);
      for (const [outcome, field] of outcomes) {
        lines.push(`relay_tenant_deliveries_total{tenant="${t}",outcome="${outcome}"} ${row[field]}`);
      }
    }
    lines.push(
      "# HELP relay_tenant_bytes_in_total Inbound payload bytes accepted inside the usage window, per tenant.",
      "# TYPE relay_tenant_bytes_in_total counter"
    );
    for (const row of rows) {
      lines.push(`relay_tenant_bytes_in_total{tenant="${escapeLabelValue(row.tenant)}"} ${row.bytesIn}`);
    }
    lines.push(
      "# HELP relay_tenant_bytes_out_total Outbound payload bytes delivered inside the usage window, per tenant.",
      "# TYPE relay_tenant_bytes_out_total counter"
    );
    for (const row of rows) {
      lines.push(
        `relay_tenant_bytes_out_total{tenant="${escapeLabelValue(row.tenant)}"} ${row.bytesOut}`
      );
    }
    lines.push(
      "# HELP relay_tenant_urgent_total Accepted urgent (fast-lane) events inside the usage window, per tenant.",
      "# TYPE relay_tenant_urgent_total counter"
    );
    for (const row of rows) {
      lines.push(`relay_tenant_urgent_total{tenant="${escapeLabelValue(row.tenant)}"} ${row.urgent}`);
    }
    return lines.join("\n") + "\n";
  }
}
