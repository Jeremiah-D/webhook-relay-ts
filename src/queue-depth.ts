/**
 * Per-endpoint queue-depth breach alerting (WR-153).
 *
 * The auto-disable gate (WR-150) is the human-intervention gate: it *stops*
 * deliveries to a sick endpoint. Queue-depth alerting is the one level
 * below it — pure observation. When an endpoint's backlog (queued +
 * in-flight + backoff-waiting deliveries, the WR-71 pending counter) reaches
 * a configured per-endpoint threshold, the relay *notifies* — it never
 * pauses, never gates, never touches the breaker or the auto-disable
 * streak:
 *
 * - The alert is edge-triggered: reaching the threshold fires exactly
 *   once; staying above it fires nothing more. The gate re-arms only
 *   after the depth drops back below the threshold, so the next episode
 *   fires again.
 * - Orthogonality with WR-150 is structural, not just documented: this
 *   tracker keeps no failure streak, records no verdict, and the
 *   dispatch path never consults it. An alerted endpoint keeps
 *   delivering at full speed; a disabled endpoint's alert state is
 *   untouched by the disable.
 * - Off by default: without `queueDepthAlert` the tracker is never
 *   constructed — zero behavior change, zero hot-path cost beyond one
 *   undefined check.
 *
 * Zero dependencies (pure data + validation).
 */

/** Options for {@link QueueDepthAlert}. */
export interface QueueDepthAlertOptions {
  /**
   * Per-endpoint backlog depth thresholds, keyed by logical `targetUrl`.
   * An endpoint alerts only when it has an entry — there is no global
   * default, so the feature is opt-in per endpoint. Each threshold must
   * be an integer >= 1; anything else throws `RangeError` at
   * construction. An absent `thresholds` (or an empty record) alerts
   * nothing.
   */
  thresholds?: Record<string, number>;
}

/** Payload of one queue-depth breach episode (WR-153). */
export interface QueueDepthBreachInfo {
  /** The endpoint whose depth reached the threshold (logical `targetUrl`). */
  endpoint: string;
  /** Backlog depth at the moment of the breach (queued + in-flight + backoff-waiting). */
  depth: number;
  /** The configured threshold that was reached. */
  threshold: number;
}

/** Observable snapshot of one endpoint's queue-depth state. */
export interface QueueDepthStatsRow {
  /** The endpoint (logical `targetUrl`). */
  endpoint: string;
  /** Current depth: queued + in-flight + backoff-waiting deliveries. */
  depth: number;
  /** Configured alert threshold; absent when the endpoint has no alert. */
  threshold?: number;
  /** Whether the depth is currently at/above the configured threshold. */
  breached: boolean;
}

function describeValue(value: unknown): string {
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" || typeof value === "boolean" || value === null) {
    return String(value);
  }
  return typeof value;
}

function assertValidEndpoint(endpoint: unknown, method: string): asserts endpoint is string {
  if (typeof endpoint !== "string" || endpoint.length === 0) {
    throw new RangeError(`${method}: endpoint must be a non-empty string`);
  }
}

/**
 * Edge-triggered per-endpoint depth tracker.
 *
 * Feed it the endpoint's current depth after every backlog mutation
 * (`evaluate`); it returns a {@link QueueDepthBreachInfo} exactly once
 * per breach episode and re-arms when the depth falls back below the
 * threshold.
 */
export class QueueDepthAlert {
  private readonly thresholds = new Map<string, number>();
  private readonly breached = new Set<string>();

  constructor(opts: QueueDepthAlertOptions = {}) {
    const raw = opts.thresholds;
    if (raw !== undefined) {
      if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
        throw new RangeError(
          `queue depth alert: \`thresholds\` must be a record of targetUrl -> threshold, got ${describeValue(raw)}`
        );
      }
      for (const [endpoint, threshold] of Object.entries(raw)) {
        if (endpoint.length === 0) {
          throw new RangeError("queue depth alert: thresholds keys must be non-empty endpoint URLs");
        }
        if (typeof threshold !== "number" || !Number.isInteger(threshold) || threshold < 1) {
          throw new RangeError(
            `queue depth alert: thresholds[${JSON.stringify(endpoint)}] must be an integer >= 1, got ${describeValue(threshold)}`
          );
        }
        this.thresholds.set(endpoint, threshold);
      }
    }
  }

  /** Configured threshold for the endpoint, or `undefined` when it never alerts. */
  thresholdFor(endpoint: string): number | undefined {
    assertValidEndpoint(endpoint, "thresholdFor");
    return this.thresholds.get(endpoint);
  }

  /**
   * Evaluate the endpoint's current depth. Returns the breach info on
   * the transition that reaches the threshold (edge-triggered —
   * further calls at/above the threshold return `undefined`), and
   * re-arms the gate once the depth drops back below it. Endpoints
   * with no configured threshold never breach.
   */
  evaluate(endpoint: string, depth: number): QueueDepthBreachInfo | undefined {
    assertValidEndpoint(endpoint, "evaluate");
    const threshold = this.thresholds.get(endpoint);
    if (threshold === undefined) return undefined;
    if (depth >= threshold) {
      if (this.breached.has(endpoint)) return undefined;
      this.breached.add(endpoint);
      return { endpoint, depth, threshold };
    }
    // Below the threshold: re-arm for the next episode.
    this.breached.delete(endpoint);
    return undefined;
  }

  /** True while the endpoint sits in an open breach episode. */
  isBreached(endpoint: string): boolean {
    assertValidEndpoint(endpoint, "isBreached");
    return this.breached.has(endpoint);
  }
}
