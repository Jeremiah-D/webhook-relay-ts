/**
 * Per-endpoint ordered delivery (head-of-line blocking).
 *
 * When enabled for an endpoint, its deliveries leave the relay in the
 * order they were received: the head of the line must reach a terminal
 * state (`delivered` or `dead_letter`) before the next item is
 * dispatched. A head that is retrying, backing off, or parked behind the
 * circuit breaker / quota / rate limiter holds every follower behind it
 * — followers consume no attempt, no retry budget, no quota token, and
 * no circuit verdict while held.
 *
 * A head that never settles is the classic poison-message hazard, so the
 * hold is bounded by an opt-in timeout: `maxHeadOfLineHoldMs`. When the
 * head has been head longer than the timeout, it is parked into the
 * dead-letter list (never silently dropped) with failure class
 * `"head_of_line_timeout"` and the next head is released. The default is
 * `Infinity` — strict ordering, the head is held until it settles — which
 * is the honest default for a feature whose whole contract is "in
 * order": silently dead-lettering a never-attempted head on a timer
 * would break that contract, so the timeout is opt-in, not default.
 *
 * The urgent lane (WR-12) bypasses the ordered gate by design —
 * low-latency semantics win over ordering — and every bypass is audited
 * as `ordered_bypassed`. Batch-flushed items (WR-17) are single
 * `RetryItem`s: the ordered gate applies at item level, and a flushed
 * batch takes its ordered position at flush time.
 *
 * Zero dependencies. The clock is injectable for deterministic tests.
 */

/** Per-endpoint ordered-delivery options. Disabled unless enabled. */
export interface OrderedModeOptions {
  /**
   * Master switch for this scope. `false` (or absent) disables ordered
   * delivery; `true` enables it with the defaults below.
   */
  enabled?: boolean;
  /**
   * Poison-message bound: how long (ms) the head of the line may stay
   * unsettled before it is parked into the dead-letter list (failure
   * class `"head_of_line_timeout"`) and the next head is released.
   * Default: `Infinity` — the head is held indefinitely; its retries
   * keep running against it until `maxAttempts` exhausts, and only then
   * does the line advance. Set a finite value to bound the hold. Must
   * be a finite number > 0, or `Infinity`.
   */
  maxHeadOfLineHoldMs?: number;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
}

/** An ordered-delivery scope after validation and defaulting. */
export interface ResolvedOrderedEndpointConfig {
  /** Always `true` here — a resolved config is an enabled one. */
  enabled: true;
  /** Effective `maxHeadOfLineHoldMs`; `Infinity` when unset. */
  maxHeadOfLineHoldMs: number;
}

/** The normalized form of the `ordered` queue option. */
export interface ResolvedOrderedConfig {
  /**
   * Global scope (the `boolean | OrderedModeOptions` form): applies to
   * every endpoint. Absent when only per-endpoint records are used.
   */
  global?: ResolvedOrderedEndpointConfig;
  /** Exact-`targetUrl` → config, for the record form. */
  endpoints: Map<string, ResolvedOrderedEndpointConfig>;
}

/**
 * Validate the `ordered` option; throws `RangeError` at construction on
 * anything illegal — never mid-delivery. Accepts:
 *
 * - `undefined` (disabled)
 * - `boolean` — `true` orders every endpoint with defaults
 * - `OrderedModeOptions` — `{ enabled?, maxHeadOfLineHoldMs?, now? }`
 *   applying to every endpoint
 * - `Record<string, boolean | OrderedModeOptions>` — exact-`targetUrl`
 *   → config, the same exact-match convention as `tlsPins` /
 *   `responseValidators`
 */
export function assertValidOrderedConfig(value: unknown): void {
  if (value === undefined || typeof value === "boolean") return;
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new RangeError(
      `ordered must be a boolean, an OrderedModeOptions object, or a record of exact targetUrl to config, got ${describeValue(value)}`
    );
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj);
  const optionKeys = new Set(["enabled", "maxHeadOfLineHoldMs", "now"]);
  const looksLikeOptions = keys.length > 0 && keys.every((k) => optionKeys.has(k));
  if (looksLikeOptions || keys.length === 0) {
    assertValidOrderedModeOptions(obj, "ordered");
    return;
  }
  for (const [endpoint, v] of Object.entries(obj)) {
    if (endpoint.length === 0) {
      throw new RangeError("ordered endpoint keys must be non-empty target URLs");
    }
    if (typeof v === "boolean") continue;
    if (v === null || typeof v !== "object" || Array.isArray(v)) {
      throw new RangeError(
        `ordered[${JSON.stringify(endpoint)}] must be a boolean or an OrderedModeOptions object, got ${describeValue(v)}`
      );
    }
    assertValidOrderedModeOptions(v as Record<string, unknown>, `ordered[${JSON.stringify(endpoint)}]`);
  }
}

function assertValidOrderedModeOptions(obj: Record<string, unknown>, where: string): void {
  const { enabled, maxHeadOfLineHoldMs, now } = obj;
  if (enabled !== undefined && typeof enabled !== "boolean") {
    throw new RangeError(`${where}.enabled must be a boolean, got ${describeValue(enabled)}`);
  }
  if (maxHeadOfLineHoldMs !== undefined) {
    const v = maxHeadOfLineHoldMs as number;
    const ok =
      typeof v === "number" &&
      !Number.isNaN(v) &&
      (v === Infinity || (Number.isFinite(v) && v > 0));
    if (!ok) {
      throw new RangeError(
        `${where}.maxHeadOfLineHoldMs must be a finite number > 0 or Infinity, got ${describeValue(maxHeadOfLineHoldMs)}`
      );
    }
  }
  if (now !== undefined && typeof now !== "function") {
    throw new RangeError(`${where}.now must be a function, got ${describeValue(now)}`);
  }
}

function describeValue(value: unknown): string {
  if (typeof value === "string") return JSON.stringify(value);
  if (value === null) return "null";
  if (Array.isArray(value)) return "an array";
  return typeof value;
}

/**
 * Normalize a validated `ordered` option into the resolved form the
 * queue consults per dispatch. Returns `undefined` when ordered
 * delivery is entirely disabled (absent, `false`, `{ enabled: false }`,
 * or a record with no enabled endpoint).
 */
export function resolveOrderedConfig(
  value: boolean | OrderedModeOptions | Record<string, boolean | OrderedModeOptions> | undefined
): ResolvedOrderedConfig | undefined {
  if (value === undefined || value === false) return undefined;
  if (value === true) {
    return { global: { enabled: true, maxHeadOfLineHoldMs: Infinity }, endpoints: new Map() };
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj);
  const optionKeys = new Set(["enabled", "maxHeadOfLineHoldMs", "now"]);
  const looksLikeOptions = keys.length > 0 && keys.every((k) => optionKeys.has(k));
  if (looksLikeOptions || keys.length === 0) {
    const o = obj as unknown as OrderedModeOptions;
    if (o.enabled === false) return undefined;
    return {
      global: { enabled: true, maxHeadOfLineHoldMs: o.maxHeadOfLineHoldMs ?? Infinity },
      endpoints: new Map(),
    };
  }
  const endpoints = new Map<string, ResolvedOrderedEndpointConfig>();
  for (const [endpoint, v] of Object.entries(obj as Record<string, boolean | OrderedModeOptions>)) {
    if (v === false) continue;
    if (v === true) {
      endpoints.set(endpoint, { enabled: true, maxHeadOfLineHoldMs: Infinity });
      continue;
    }
    if (v.enabled === false) continue;
    endpoints.set(endpoint, { enabled: true, maxHeadOfLineHoldMs: v.maxHeadOfLineHoldMs ?? Infinity });
  }
  if (endpoints.size === 0) return undefined;
  return { endpoints };
}

/**
 * Resolve the clock for the ordered tracker. The `now` is read from the
 * global options form, or — for the per-endpoint record form — from the
 * first endpoint config that provides one (a test-only injection; in
 * practice every endpoint shares the wall clock).
 */
export function resolveOrderedClock(
  value: boolean | OrderedModeOptions | Record<string, boolean | OrderedModeOptions> | undefined
): () => number {
  if (value !== undefined && value !== null && typeof value === "object" && !Array.isArray(value)) {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj);
    const optionKeys = new Set(["enabled", "maxHeadOfLineHoldMs", "now"]);
    if ((keys.length > 0 && keys.every((k) => optionKeys.has(k))) || keys.length === 0) {
      const now = (obj as unknown as OrderedModeOptions).now;
      if (now !== undefined) return now;
      return Date.now;
    }
    for (const v of Object.values(obj as Record<string, boolean | OrderedModeOptions>)) {
      if (v !== null && typeof v === "object" && !Array.isArray(v)) {
        const now = (v as OrderedModeOptions).now;
        if (now !== undefined) return now;
      }
    }
  }
  return Date.now;
}

/**
 * Per-endpoint FIFO line state for ordered delivery. One instance per
 * queue; keyed by logical endpoint (`targetUrl`). The head is
 * `order[0]`; `headSinceMs` stamps when the current head took the head
 * position, which is what `maxHeadOfLineHoldMs` is measured against.
 */
export class OrderedTracker {
  private readonly now: () => number;
  private readonly lines = new Map<string, { order: string[]; headSinceMs?: number }>();

  constructor(now: () => number = Date.now) {
    this.now = now;
  }

  /** Append `id` to the endpoint's line; a first item becomes head immediately. */
  track(endpoint: string, id: string): void {
    let line = this.lines.get(endpoint);
    if (line === undefined) {
      line = { order: [], headSinceMs: undefined };
      this.lines.set(endpoint, line);
    }
    if (line.order.includes(id)) return;
    line.order.push(id);
    if (line.order.length === 1) line.headSinceMs = this.now();
  }

  /**
   * Remove `id` from the endpoint's line (delivery settled). When the
   * head settles, the next item becomes head and its hold clock starts
   * now — the hold measures head time, not queue time.
   */
  settle(endpoint: string, id: string): void {
    const line = this.lines.get(endpoint);
    if (line === undefined) return;
    const idx = line.order.indexOf(id);
    if (idx < 0) return;
    line.order.splice(idx, 1);
    if (idx === 0) {
      line.headSinceMs = line.order.length > 0 ? this.now() : undefined;
    }
  }

  /** The current head item id, or `undefined` when the line is empty. */
  head(endpoint: string): string | undefined {
    return this.lines.get(endpoint)?.order[0];
  }

  /** Whether `id` is currently tracked on the endpoint's line. */
  isTracked(endpoint: string, id: string): boolean {
    return this.lines.get(endpoint)?.order.includes(id) ?? false;
  }

  /**
   * How long (ms) the current head has held the head position, or
   * `undefined` when the line is empty.
   */
  headBlockedMs(endpoint: string): number | undefined {
    const line = this.lines.get(endpoint);
    if (line === undefined || line.headSinceMs === undefined) return undefined;
    return Math.max(0, this.now() - line.headSinceMs);
  }

  /** Live items currently on the endpoint's line. */
  depth(endpoint: string): number {
    return this.lines.get(endpoint)?.order.length ?? 0;
  }

  /** Endpoints with line state, in first-seen order. */
  endpoints(): string[] {
    return [...this.lines.keys()];
  }
}

/** Audit event for ordered-delivery transitions (the server writes these to the audit log). */
export interface OrderedAuditEvent {
  /** `ordered_bypassed`: an urgent item skipped the ordered gate. `head_of_line_parked`: a stuck head was dead-lettered. */
  kind: "ordered_bypassed" | "head_of_line_parked";
  /** Delivery id. */
  id: string;
  /** End-to-end trace id. */
  traceId: string;
  /** Logical endpoint (`targetUrl`). */
  endpoint: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  /**
   * `head_of_line_parked` only: how long the head had held the line
   * when it was parked.
   */
  blockedMs?: number;
  /** `head_of_line_parked` only: the configured hold bound that fired. */
  maxHeadOfLineHoldMs?: number;
}

/** Per-endpoint ordered-delivery stats (`RetryQueue.getOrderedStats()`). */
export interface OrderedEndpointStats {
  /** Logical endpoint (`targetUrl`). */
  endpoint: string;
  /** Live items currently on the endpoint's ordered line. */
  queued: number;
  /** The item id currently holding the head of the line, if any. */
  headId?: string;
  /** Cumulative follower dispatches held behind the head. */
  headBlockedCount: number;
  /** Cumulative heads poison-parked into the dead-letter list. */
  headOfLineParked: number;
  /** Cumulative urgent items that bypassed the ordered gate. */
  urgentBypassed: number;
}

/** Prometheus input for the ordered-delivery series (see `src/metrics.ts`). */
export interface OrderedMetricsInput {
  endpoint: string;
  headBlocked: number;
  headOfLineParked: number;
  urgentBypassed: number;
}
