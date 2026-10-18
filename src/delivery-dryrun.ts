/**
 * Outbound delivery dry-run drill mode (WR-145).
 *
 * Before a new downstream contract goes live — or after an incident —
 * operators want to rehearse the *whole* delivery pipeline without
 * touching the real downstream: intake (signature verification, routing),
 * retry scheduling, audit, and metrics. Per-endpoint opt-in dry-run
 * mode does exactly that: dispatches still walk `RetryQueue.deliver()`,
 * but instead of a physical outbound request the queue "sends" a
 * configurable canned response (`status`/`body`/`delayMs`) and records
 * the outcome in an isolated metrics dimension
 * (`relay_dry_run_deliveries_total{endpoint,outcome}`).
 *
 * Control-plane isolation is the point of the feature, not a side
 * effect: dry-run attempts NEVER write the circuit breaker, the
 * dead-letter queue, the retry budget, quotas, tenant rate limits, or
 * the urgent lane. They read nothing from them either at dispatch —
 * the dry-run branch sits before the quota gate, so a drill cannot be
 * throttled by, or throttle, real traffic. (Operational parking —
 * endpoint pause, delivery windows, maintenance windows, the WR-76
 * delivery deadline — still applies: a drill for a paused endpoint
 * parks like a real delivery.)
 *
 * Outcome model (mirrors the real path's vocabulary):
 * - canned 2xx → `delivered` (audited `delivered` with `dry_run: true`)
 * - canned retryable failure (408/429/5xx, the WR-30 classification)
 *   → `retrying` while attempts remain (audited `retrying` with
 *   `dry_run: true`, normal backoff, no retry-budget gate), then
 *   `exhausted` (audited `dry_run_exhausted` — never the dead-letter
 *   queue; drills must not pollute the dead-letter operator views)
 * - canned non-retryable failure (other 4xx, the WR-30 classification)
 *   → `failed` (audited `failed` with `reason: "dry_run_failed"` and
 *   `dry_run: true`)
 *
 * Every outcome is reported through the `onDryRunDelivery` hook with
 * `dry_run: true` baked into the audit shape by the server; the hook
 * itself never fires for real deliveries.
 *
 * Zero dependencies.
 */

/** The canned downstream answer a drill attempt receives. */
export interface DryRunCannedResponse {
  /**
   * HTTP status the drill pretends the downstream returned. 2xx =
   * delivered; 408/429/5xx = retryable (WR-30 classification); other
   * 4xx = terminal failure. Defaults to 200.
   */
  status?: number;
  /** Canned response body (unused for classification, audited nowhere). */
  body?: string;
  /**
   * Simulated network latency before the canned response arrives, in
   * ms. Defaults to 0. Operator-controlled — keep it small; it holds
   * the delivery in-flight for the duration.
   */
  delayMs?: number;
}

/** One endpoint's drill configuration. */
export interface EndpointDryRunConfig {
  /**
   * Master switch. Defaults to `true` when the endpoint has an entry —
   * an entry *is* the opt-in.
   */
  enabled?: boolean;
  /** The canned response; defaults to `{ status: 200 }`. */
  canned?: DryRunCannedResponse;
}

/** `RetryQueueOptions.deliveryDryRun`: exact `targetUrl` → drill config. */
export type DeliveryDryRunOptions = Record<string, EndpointDryRunConfig>;

/** Normalized drill config (all defaults applied). */
export interface NormalizedDryRunConfig {
  enabled: boolean;
  canned: { status: number; body: string; delayMs: number };
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** Validate one canned response; throws `RangeError` on anything illegal. */
export function assertValidDryRunCannedResponse(
  canned: unknown,
  where: string
): void {
  if (!isRecord(canned)) {
    throw new RangeError(`${where}: canned must be an object`);
  }
  const { status, body, delayMs } = canned;
  if (status !== undefined && (!Number.isInteger(status) || status < 100 || status > 599)) {
    throw new RangeError(
      `${where}: canned.status must be an integer 100-599, got ${String(status)}`
    );
  }
  if (body !== undefined && typeof body !== "string") {
    throw new RangeError(`${where}: canned.body must be a string, got ${typeof body}`);
  }
  if (
    delayMs !== undefined &&
    (typeof delayMs !== "number" || !Number.isFinite(delayMs) || delayMs < 0)
  ) {
    throw new RangeError(
      `${where}: canned.delayMs must be a finite number >= 0, got ${String(delayMs)}`
    );
  }
}

/** Validate one endpoint drill config; throws `RangeError` on anything illegal. */
export function assertValidEndpointDryRunConfig(
  endpoint: string,
  config: unknown
): void {
  if (!isRecord(config)) {
    throw new RangeError(`deliveryDryRun[${endpoint}]: config must be an object`);
  }
  const { enabled, canned } = config;
  if (enabled !== undefined && typeof enabled !== "boolean") {
    throw new RangeError(
      `deliveryDryRun[${endpoint}]: enabled must be a boolean, got ${typeof enabled}`
    );
  }
  if (canned !== undefined) {
    assertValidDryRunCannedResponse(canned, `deliveryDryRun[${endpoint}].canned`);
  }
}

/**
 * Validate the whole `deliveryDryRun` option map. Throws `RangeError` at
 * startup so a bad drill config can never fail a delivery mid-flight.
 */
export function assertValidDeliveryDryRunOptions(options: unknown): void {
  if (!isRecord(options)) {
    throw new RangeError("deliveryDryRun must be a record of targetUrl -> drill config");
  }
  for (const [endpoint, config] of Object.entries(options)) {
    if (endpoint.length === 0) {
      throw new RangeError("deliveryDryRun keys must be non-empty target URLs");
    }
    assertValidEndpointDryRunConfig(endpoint, config);
  }
}

/** Apply defaults to a validated drill config. */
export function normalizeEndpointDryRunConfig(
  config: EndpointDryRunConfig
): NormalizedDryRunConfig {
  return {
    enabled: config.enabled ?? true,
    canned: {
      status: config.canned?.status ?? 200,
      body: config.canned?.body ?? "",
      delayMs: config.canned?.delayMs ?? 0,
    },
  };
}

/**
 * Drill outcome classification for a canned status, following the WR-30
 * failure taxonomy the real path uses: 2xx succeeds, 408/429/5xx are
 * retryable, every other 4xx is a terminal (poison) failure.
 */
export type DryRunOutcome = "delivered" | "retrying" | "exhausted" | "failed";

export function classifyDryRunStatus(status: number): "delivered" | "retryable" | "failed" {
  if (status >= 200 && status < 300) return "delivered";
  if (status === 408 || status === 429 || status >= 500) return "retryable";
  return "failed";
}

/** One drill attempt's outcome, reported to the `onDryRunDelivery` hook. */
export interface DryRunDeliveryEvent {
  id: string;
  traceId: string;
  tenant?: string;
  /** The logical endpoint (the configured primary). */
  endpoint: string;
  /** The physical target the drill pretended to hit. */
  targetUrl: string;
  attempts: number;
  outcome: DryRunOutcome;
  /** The canned status that drove the outcome. */
  statusCode: number;
  /** Simulated round-trip latency (canned delay), in ms. */
  latencyMs: number;
  error?: string;
  /** Scheduled retry delay, for `retrying` outcomes. */
  nextDelayMs?: number;
}
