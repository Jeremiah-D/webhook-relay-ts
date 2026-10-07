import { randomUUID } from "node:crypto";

/**
 * End-to-end trace IDs: one identifier threads an event through the whole
 * relay lifecycle — inbound accept → delivery → retries → dead-letter —
 * and appears in every audit event, delivery event (SSE), and the
 * downstream `x-trace-id` header, so an operator can correlate the three
 * observability surfaces (audit log, metrics, live stream) for one event.
 *
 * The inbound client may supply a trace ID via the `x-trace-id` header
 * (e.g. propagated from an upstream service's own trace context); a
 * missing or malformed header gets a fresh generated ID, so tracing never
 * breaks on legacy senders.
 */

/** Inbound header carrying a client-supplied trace ID. */
export const TRACE_ID_HEADER = "x-trace-id";

/** Client trace IDs: 1–64 chars of alnum, dash, underscore. Rejects header-injection junk. */
const VALID_TRACE_ID = /^[A-Za-z0-9_-]{1,64}$/;

/** Fresh 32-hex-char trace ID (a UUID with the dashes stripped). */
export function newTraceId(): string {
  return randomUUID().replace(/-/g, "");
}

/** Whether `value` is safe to keep as a trace ID. */
export function isValidTraceId(value: string): boolean {
  return VALID_TRACE_ID.test(value);
}

/**
 * Resolve the trace ID for an inbound request: keep a valid
 * `x-trace-id` header, otherwise mint a new one. Accepts the raw header
 * value (first of an array when repeated).
 */
export function resolveTraceId(header: string | string[] | undefined): string {
  const raw = Array.isArray(header) ? header[0] : header;
  const value = raw?.trim();
  return value !== undefined && value.length > 0 && isValidTraceId(value)
    ? value
    : newTraceId();
}
