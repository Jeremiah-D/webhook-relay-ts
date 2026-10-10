/**
 * Delivery lifecycle snapshot (WR-43): aggregate the audit trail of one
 * trace ID into a single lifecycle view served by the operator
 * `GET /deliveries/:traceId` endpoint.
 *
 * The builder reads through {@link AuditLog.query} with a `traceId`
 * filter — the WR-04 line-offset index means only matching lines are ever
 * read back from disk, never the whole file. Dead-letter *replay* records
 * (`dead_letter_replayed`) carry no trace ID (they are operator actions,
 * not delivery events), so they are matched by delivery `id` via an
 * event-filtered index query instead.
 */

import type { AuditLog } from "./audit.ts";

/** One step of the delivery state machine. */
export interface DeliveryTimelineEntry {
  state:
    | "accepted"
    | "retrying"
    | "delivered"
    | "dead_letter"
    | "rejected"
    | "duplicate_suppressed";
  /** ISO-8601 audit timestamp of the step. */
  at: string;
  /** Attempts consumed so far (present on `retrying`/`delivered`/`dead_letter`). */
  attempts?: number;
  /** Last failure message (present on `retrying`/`dead_letter`). */
  lastError?: string;
  /** accepted→delivered wall time, audit-timestamp based (on `delivered`). */
  latencyMs?: number;
  /** Machine-readable rejection reason (on `rejected`). */
  reason?: string;
  /** Scheduled delay before the next attempt (on `retrying`). */
  nextDelayMs?: number;
  /** `"non_retryable" | "retryable"` (on `dead_letter`). */
  failureClass?: string;
}

/**
 * A contextual signal that is not part of the delivery state machine but
 * is worth keeping next to the trajectory (semantic validation failures,
 * budget-parked retries, SLO misses, batched deliveries).
 */
export interface DeliverySignal {
  event: string;
  at: string;
  attempts?: number;
  detail?: string;
  waitMs?: number;
  latencyMs?: number;
}

/** One dead-letter replay record matched by delivery id. */
export interface DeliveryReplayRecord {
  at: string;
  id: string;
}

export interface DeliverySnapshot {
  traceId: string;
  /** Delivery id from the `accepted` line, when the event was accepted. */
  id?: string;
  /** Downstream endpoint from the `accepted` line, when present. */
  endpoint?: string;
  /**
   * Current lifecycle state: the latest terminal event wins
   * (`delivered` / `dead_letter` / `rejected` / `duplicate_suppressed`);
   * a trace with no terminal event is still `delivering`.
   */
  state: "delivering" | "delivered" | "dead_letter" | "rejected" | "duplicate_suppressed";
  acceptedAt?: string;
  timeline: DeliveryTimelineEntry[];
  /** Maximum attempts observed across the trajectory. */
  attempts: number;
  /** Number of `retrying` steps. */
  retryCount: number;
  /** Latest failure message, when the trajectory saw a failure. */
  lastError?: string;
  /** accepted→delivered wall time, audit-timestamp based. */
  latencyMs?: number;
  signals: DeliverySignal[];
  replayed: DeliveryReplayRecord[];
}

type Rec = Record<string, unknown>;

function str(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function num(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}

/**
 * Build the lifecycle snapshot for one trace ID. Returns `null` when the
 * audit log holds no line for the trace ID.
 */
export function buildDeliverySnapshot(auditLog: AuditLog, traceId: string): DeliverySnapshot | null {
  const raw = auditLog.query({ traceId }) as Rec[];
  if (raw.length === 0) return null;
  // Chronological by audit timestamp; the query already returns index
  // order, but sorting makes rotated/merged logs behave the same.
  const events = [...raw].sort((a, b) => {
    const ta = Date.parse(str(a.ts) ?? "");
    const tb = Date.parse(str(b.ts) ?? "");
    if (Number.isNaN(ta) || Number.isNaN(tb)) return 0;
    return ta - tb;
  });

  const snapshot: DeliverySnapshot = {
    traceId,
    state: "delivering",
    timeline: [],
    attempts: 0,
    retryCount: 0,
    signals: [],
    replayed: [],
  };
  let acceptedAtMs: number | undefined;

  for (const e of events) {
    const event = str(e.event);
    const at = str(e.ts) ?? "";
    if (event === "accepted") {
      const acceptedId = str(e.id);
      if (acceptedId !== undefined) snapshot.id = acceptedId;
      const target = str(e.targetUrl);
      if (target !== undefined) snapshot.endpoint = target;
      snapshot.acceptedAt = at;
      acceptedAtMs = Date.parse(at);
      if (Number.isNaN(acceptedAtMs)) acceptedAtMs = undefined;
      snapshot.timeline.push({ state: "accepted", at });
    } else if (event === "rejected") {
      const entry: DeliveryTimelineEntry = { state: "rejected", at };
      const reason = str(e.reason);
      if (reason !== undefined) entry.reason = reason;
      snapshot.timeline.push(entry);
      snapshot.state = "rejected";
    } else if (event === "duplicate_suppressed") {
      snapshot.timeline.push({ state: "duplicate_suppressed", at });
      snapshot.state = "duplicate_suppressed";
    } else if (event === "retrying") {
      const entry: DeliveryTimelineEntry = { state: "retrying", at };
      const attempts = num(e.attempts);
      if (attempts !== undefined) {
        entry.attempts = attempts;
        snapshot.attempts = Math.max(snapshot.attempts, attempts);
      }
      const error = str(e.error);
      if (error !== undefined) {
        entry.lastError = error;
        snapshot.lastError = error;
      }
      const nextDelayMs = num(e.nextDelayMs);
      if (nextDelayMs !== undefined) entry.nextDelayMs = nextDelayMs;
      snapshot.timeline.push(entry);
      snapshot.retryCount += 1;
      snapshot.state = "delivering";
    } else if (event === "delivered") {
      const entry: DeliveryTimelineEntry = { state: "delivered", at };
      const attempts = num(e.attempts);
      if (attempts !== undefined) {
        entry.attempts = attempts;
        snapshot.attempts = Math.max(snapshot.attempts, attempts);
      }
      if (acceptedAtMs !== undefined) {
        const deliveredMs = Date.parse(at);
        if (!Number.isNaN(deliveredMs)) {
          entry.latencyMs = Math.max(0, deliveredMs - acceptedAtMs);
          snapshot.latencyMs = entry.latencyMs;
        }
      }
      snapshot.timeline.push(entry);
      snapshot.state = "delivered";
    } else if (event === "dead_letter") {
      const entry: DeliveryTimelineEntry = { state: "dead_letter", at };
      const attempts = num(e.attempts);
      if (attempts !== undefined) {
        entry.attempts = attempts;
        snapshot.attempts = Math.max(snapshot.attempts, attempts);
      }
      const error = str(e.error);
      if (error !== undefined) {
        entry.lastError = error;
        snapshot.lastError = error;
      }
      const failureClass = str(e.failure_class);
      if (failureClass !== undefined) entry.failureClass = failureClass;
      snapshot.timeline.push(entry);
      snapshot.state = "dead_letter";
    } else if (event === "failed" || event === "retry_budget_depleted" || event === "slo_missed" || event === "batch_flushed") {
      const signal: DeliverySignal = { event, at };
      const attempts = num(e.attempts);
      if (attempts !== undefined) signal.attempts = attempts;
      const detail = str(e.reason) ?? str(e.semanticReason);
      if (detail !== undefined) signal.detail = detail;
      const waitMs = num(e.waitMs);
      if (waitMs !== undefined) signal.waitMs = waitMs;
      const latencyMs = num(e.latencyMs);
      if (latencyMs !== undefined) signal.latencyMs = latencyMs;
      snapshot.signals.push(signal);
    }
    // All other events (circuit_*, failover_switched, *_replayed, probe_*)
    // carry no trace ID or are not part of one delivery's lifecycle.
  }

  // Dead-letter replays are operator actions keyed by delivery id, not by
  // trace ID: match them through an event-filtered index query.
  if (snapshot.id !== undefined) {
    const replays = auditLog.query({ event: "dead_letter_replayed" }) as Rec[];
    for (const r of replays) {
      if (str(r.id) === snapshot.id) {
        snapshot.replayed.push({ at: str(r.ts) ?? "", id: snapshot.id });
      }
    }
  }

  return snapshot;
}
