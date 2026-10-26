/**
 * Bulk endpoint enable/disable (WR-230).
 *
 * The single-endpoint operator switches — `POST /endpoints/pause`
 * (WR-50), `POST /endpoints/resume` (WR-50), `POST /endpoints/enable`
 * (WR-150) — each move one endpoint and fail closed on an unknown
 * one (404). An operator bringing a fleet back after an outage, or
 * stopping a set of endpoints for maintenance, needs the same moves
 * in bulk: one request, one row per endpoint, no silent skips.
 *
 * This module is the pure, server-independent half of that surface:
 * list normalization and per-endpoint application. The HTTP layer
 * (`src/server.ts`) owns authentication (the WR-82 operator gate,
 * same as the single routes), the known-endpoint set, the audit
 * hooks, and the operator ledger — it calls into here so the
 * bulk semantics are testable without a server.
 *
 * Operation mapping — bulk-enable and bulk-disable are the batch
 * forms of the two existing manual moves, not a new gate:
 *
 * - bulk-enable applies `RetryQueue.enableEndpoint` per endpoint:
 *   it clears the WR-150 auto-disable gate and resets the failure
 *   streak. It does not touch the pause set — an endpoint that is
 *   both paused and auto-disabled needs its pause resumed
 *   separately (the WR-50/WR-150 orthogonality, preserved here).
 * - bulk-disable applies `RetryQueue.pauseEndpoint` per endpoint:
 *   it parks the endpoint's deliveries (queued items stay queued,
 *   new events park, nothing is attempted) — the manual "stop"
 *   the WR-50 pause already provides. It is orthogonal to the
 *   WR-150 auto-disable (a consecutive-failure trip) and to the
 *   WR-100 stale-endpoint sweep (an automatic pause): both of
 *   those fire on their own, never through here, and neither is
 *   cleared by a bulk operation except through its own route.
 *
 * Per-endpoint outcome — one row per deduplicated endpoint, in
 * request order:
 *
 * - `{ endpoint, ok: true }` when the operation was applied (or
 *   was already in effect — enable of a non-disabled endpoint
 *   and pause of an already-paused endpoint are idempotent
 *   no-ops, exactly like the single routes' 200s);
 * - `{ endpoint, ok: false, error: "unknown endpoint" }` when
 *   the endpoint is not registered: reported, never silently
 *   skipped, and never aborting the remaining endpoints;
 * - `{ endpoint, ok: false, error: <message> }` when the
 *   operation itself throws: the failure is contained to that
 *   row, the other endpoints still run.
 *
 * List validation is fail-closed and all-or-nothing, before any
 * endpoint moves: the body must be a non-empty array of
 * non-empty strings. An empty list, a non-array, or an illegal
 * name throws `RangeError` (the server answers 400, "nothing
 * changed" — the same contract as the single routes' 400 on a
 * bad endpoint name, and as the WR-114 registry's "a 400 always
 * means nothing changed"). Duplicates collapse to the first
 * occurrence: processing the same endpoint twice in one request
 * would double-count audit events and confuse the row list.
 *
 * Auditing — the server records one operator-ledger entry per
 * successfully processed endpoint (`endpoints.bulk-enable` /
 * `endpoints.bulk-disable`, with the same before/after shape as
 * the single routes' `endpoints.enable` / `endpoints.pause`
 * entries) and the queue hooks emit the same audit events as
 * the single routes (`endpoint_enabled` / `endpoint_paused`)
 * on real transitions. An unknown endpoint earns no ledger
 * entry and no audit event: it never moved.
 *
 * Zero dependencies (pure data + validation).
 */

/** One endpoint's row in a bulk response. */
export interface BulkEndpointResultRow {
  /** The endpoint (physical `targetUrl`), as deduplicated from the request. */
  endpoint: string;
  /** True when the operation was applied (or was already in effect). */
  ok: boolean;
  /** Why this endpoint did not move; absent on success rows. */
  error?: string;
}

/**
 * Normalize a bulk request's endpoint list: the body must be a
 * non-empty array of non-empty strings, deduplicated with the
 * first occurrence winning. Throws `RangeError` on any
 * violation — the caller answers 400 with zero side effects.
 */
export function normalizeBulkEndpoints(endpoints: unknown): string[] {
  if (!Array.isArray(endpoints)) {
    throw new RangeError(
      `bulk endpoints: \`endpoints\` must be a non-empty array of endpoint names`
    );
  }
  if (endpoints.length === 0) {
    throw new RangeError(`bulk endpoints: \`endpoints\` must not be empty`);
  }
  const seen = new Set<string>();
  const normalized: string[] = [];
  for (const endpoint of endpoints) {
    if (typeof endpoint !== "string" || endpoint.length === 0) {
      throw new RangeError(
        `bulk endpoints: every endpoint must be a non-empty string`
      );
    }
    if (seen.has(endpoint)) continue;
    seen.add(endpoint);
    normalized.push(endpoint);
  }
  return normalized;
}

/** The two operations the bulk routes can apply. */
export interface BulkEndpointOperation {
  /** True when the endpoint is registered (known to the relay). */
  isKnown: (endpoint: string) => boolean;
  /**
   * Apply the operation to a known endpoint. Returns true on a
   * real transition, false on an idempotent no-op; both are
   * success rows. A throw becomes that row's error, not an
   * abort of the batch.
   */
  apply: (endpoint: string) => boolean;
}

/**
 * Apply one bulk operation across deduplicated endpoints, in
 * order, one row per endpoint. Unknown endpoints are reported,
 * not skipped; a throwing operation is contained to its row;
 * neither stops the remaining endpoints.
 */
export function applyBulkEndpointOperation(
  endpoints: string[],
  operation: BulkEndpointOperation
): BulkEndpointResultRow[] {
  const rows: BulkEndpointResultRow[] = [];
  for (const endpoint of endpoints) {
    if (!operation.isKnown(endpoint)) {
      rows.push({ endpoint, ok: false, error: "unknown endpoint" });
      continue;
    }
    try {
      operation.apply(endpoint);
      rows.push({ endpoint, ok: true });
    } catch (err) {
      rows.push({
        endpoint,
        ok: false,
        error: err instanceof Error && err.message !== "" ? err.message : "operation failed",
      });
    }
  }
  return rows;
}
