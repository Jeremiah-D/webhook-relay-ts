import { createHash, randomBytes } from "node:crypto";
import { mapOtlpTraceId } from "./otlp.ts";

/**
 * W3C Trace Context propagation (WR-98).
 *
 * Opt-in distributed-tracing glue between the relay's own end-to-end
 * trace IDs (`src/trace.ts`: the `x-trace-id` header, always minted at
 * intake) and the W3C `traceparent` / `tracestate` headers the
 * downstream ecosystem speaks. When the `traceContext` server/queue
 * option is set:
 *
 * - Inbound: a valid `traceparent` is parsed and its trace-id becomes
 *   the event's trace ID (so the relay's OTLP span, audit trail, and
 *   the downstream trace share one trace id); the sampled flag and
 *   `tracestate` ride along for propagation. An invalid `traceparent`
 *   is ignored — never a 400, never a behavior change beyond skipping
 *   propagation.
 * - Outbound: every HTTP delivery stamps `traceparent` (forced, after
 *   the passthrough headers — like `x-trace-id`, a stale inbound value
 *   is overridden) with a fresh child span id per attempt, plus the
 *   verbatim `tracestate` when the caller supplied one. A
 *   caller-supplied context keeps its sampled flag; a relay-generated
 *   one uses the configured `sampled` default.
 * - Span correlation: the span id injected on the wire is derived
 *   deterministically from (trace id, 1-based attempt), so the OTLP
 *   export can name the same span (`trace.span_id`) without plumbing
 *   per-attempt wire state through the queue's event subscription —
 *   and `trace.trace_id` on the record always equals the injected
 *   traceparent's trace id.
 *
 * When the option is unset: zero behavior change — no inbound parsing,
 * no outbound stamping, no extra allocations on the delivery path.
 * Zero dependencies beyond `node:crypto` (already used by `trace.ts`
 * and `otlp.ts`).
 */

/** Outbound/inbound W3C traceparent header name. */
export const TRACEPARENT_HEADER = "traceparent";
/** Outbound/inbound W3C tracestate header name. */
export const TRACESTATE_HEADER = "tracestate";

/**
 * A caller-propagated W3C trace context, as parsed from the inbound
 * `traceparent` / `tracestate` headers. Carried on `RetryItem.traceContext`
 * so every delivery attempt of the event propagates the same trace.
 */
export interface TraceContext {
  /** 32-hex W3C trace id (lowercased). */
  traceId: string;
  /**
   * 16-hex parent span id from the inbound `traceparent`. Outbound
   * deliveries stamp a fresh child span id per attempt (see
   * {@link traceAttemptSpanId}) — this value is never re-emitted.
   */
  spanId: string;
  /** The inbound sampled flag (the `01` bit), propagated untouched. */
  sampled: boolean;
  /** Verbatim inbound `tracestate`, when present and well-formed. */
  traceState?: string;
}

/** The resolved context an outbound delivery actually stamps. */
export interface ResolvedOutboundTraceContext {
  /** 32-hex trace id for the outbound `traceparent`. */
  traceId: string;
  /** Sampled flag for the outbound `traceparent`. */
  sampled: boolean;
  /** Verbatim `tracestate` to forward, when the caller supplied one. */
  traceState?: string;
}

const HEX2 = /^[0-9a-fA-F]{2}$/;
const HEX16 = /^[0-9a-fA-F]{16}$/;
const HEX32 = /^[0-9a-fA-F]{32}$/;
const ZERO32 = "0".repeat(32);
const ZERO16 = "0".repeat(16);
/** W3C caps `tracestate` at 512 bytes; anything longer is not propagated. */
const TRACESTATE_MAX_LENGTH = 512;

function firstHeader(value: string | string[] | undefined): string | undefined {
  const raw = Array.isArray(value) ? value[0] : value;
  const trimmed = raw?.trim();
  return trimmed !== undefined && trimmed.length > 0 ? trimmed : undefined;
}

/**
 * Parse a `traceparent` header value per W3C Trace Context
 * (`version-traceid-parentid-flags`). Returns `undefined` for anything
 * malformed — never throws. Validation rules:
 *
 * - `version` is 2 hex chars and not `"ff"` (reserved);
 * - `trace-id` is 32 hex chars and not all zeros;
 * - `parent-id` is 16 hex chars and not all zeros;
 * - `flags` is 2 hex chars (the sampled bit is `flags & 1`);
 * - version `"00"`: exactly the four fields (55 chars); a future version
 *   (`"01"`–`"fe"`): the four fields plus ignored trailing fields.
 */
export function parseTraceparent(value: string | string[] | undefined): TraceContext | undefined {
  const header = firstHeader(value);
  if (header === undefined) return undefined;
  const parts = header.split("-");
  if (parts.length < 4) return undefined;
  const [version, traceId, parentId, flags] = parts;
  if (!HEX2.test(version) || version.toLowerCase() === "ff") return undefined;
  if (version === "00" && parts.length !== 4) return undefined;
  if (!HEX32.test(traceId) || traceId.toLowerCase() === ZERO32) return undefined;
  if (!HEX16.test(parentId) || parentId.toLowerCase() === ZERO16) return undefined;
  if (!HEX2.test(flags)) return undefined;
  return {
    traceId: traceId.toLowerCase(),
    spanId: parentId.toLowerCase(),
    sampled: (parseInt(flags, 16) & 1) === 1,
  };
}

/**
 * Validate a `tracestate` header value. Returns the verbatim value when
 * it is a plausible W3C list (non-empty, within the 512-byte limit,
 * comma-separated `key=value` members), `undefined` otherwise — a bad
 * `tracestate` is dropped while a valid `traceparent` still propagates.
 */
export function parseTraceState(value: string | string[] | undefined): string | undefined {
  const header = firstHeader(value);
  if (header === undefined || header.length > TRACESTATE_MAX_LENGTH) return undefined;
  const members = header.split(",");
  for (const member of members) {
    const trimmed = member.trim();
    // Each list-member is `key=value`; empty members or members without
    // a value assignment are not a W3C tracestate.
    if (trimmed.length === 0 || !trimmed.includes("=")) return undefined;
  }
  return header;
}

/**
 * Parse the inbound W3C trace context from the request headers. Returns
 * `undefined` when there is no (valid) `traceparent` — an invalid
 * `traceparent` is ignored outright, never an error. A valid
 * `traceparent` with an invalid `tracestate` still propagates; only the
 * `tracestate` is dropped.
 */
export function parseInboundTraceContext(
  traceparent: string | string[] | undefined,
  tracestate: string | string[] | undefined
): TraceContext | undefined {
  const parsed = parseTraceparent(traceparent);
  if (parsed === undefined) return undefined;
  const state = parseTraceState(tracestate);
  if (state !== undefined) parsed.traceState = state;
  return parsed;
}

/** Render an outbound `traceparent` value (`00-<trace-id>-<span-id>-<flags>`). */
export function formatTraceparent(traceId: string, spanId: string, sampled: boolean): string {
  return `00-${traceId}-${spanId}-${sampled ? "01" : "00"}`;
}

/** Fresh 16-hex-char span id (a random 8-byte value). */
export function newSpanId(): string {
  return randomBytes(8).toString("hex");
}

/**
 * The span id the relay stamps as the `traceparent` parent-id for one
 * delivery attempt. Derived deterministically from the (32-hex) trace id
 * and the 1-based attempt number — unique per attempt (trace ids are
 * unique per event), and reproducible by the OTLP export path, which
 * names the same span in `trace.span_id` without any per-attempt wire
 * state being plumbed through the queue's event subscription.
 */
export function traceAttemptSpanId(traceId32: string, attempt1Based: number): string {
  return createHash("sha256").update(`${traceId32}:${attempt1Based}`, "utf8").digest("hex").slice(0, 16);
}

/** Opt-in W3C trace-context propagation, embedded in `RetryQueueOptions` / `RelayServerOptions`. */
export interface TraceContextOptions {
  /**
   * The sampled flag stamped on *relay-generated* traceparents (when no
   * caller context was propagated). Default `true`: enabling trace
   * context means the operator wants traces. A caller-supplied context
   * always keeps its own sampled flag, untouched.
   */
  sampled?: boolean;
}

/** `TraceContextOptions` with defaults applied (what the delivery path reads). */
export interface ResolvedTraceContextOptions {
  sampled: boolean;
}

/**
 * Validate and resolve the trace-context option. `undefined` stays
 * `undefined` (feature off); anything else resolves with defaults.
 * Throws `RangeError` on invalid values at startup, never mid-delivery.
 */
export function resolveTraceContextOptions(
  opts: TraceContextOptions | undefined
): ResolvedTraceContextOptions | undefined {
  if (opts === undefined) return undefined;
  if (opts === null || typeof opts !== "object" || Array.isArray(opts)) {
    throw new RangeError(`traceContext options must be an object, got ${Array.isArray(opts) ? "array" : typeof opts}`);
  }
  if (opts.sampled !== undefined && typeof opts.sampled !== "boolean") {
    throw new RangeError(`traceContext.sampled must be a boolean, got ${JSON.stringify(opts.sampled)}`);
  }
  return { sampled: opts.sampled ?? true };
}

/**
 * Resolve the outbound W3C context for one delivery. Returns `undefined`
 * — the zero-overhead skip — when the feature is off or the item has no
 * trace identity at all (no generation, no injection).
 *
 * - Caller-propagated context (`item.traceContext`, from the inbound
 *   `traceparent` or set by hand): the trace id and sampled flag pass
 *   through untouched.
 * - Otherwise: the trace id is derived from the relay's own trace id —
 *   32-hex values pass through, anything else is mapped deterministically
 *   (the same SHA-256 mapping the OTLP export applies, so the injected
 *   `traceparent` trace id always equals the relay span's OTLP
 *   `trace_id`) — with the configured sampled flag.
 */
export function resolveOutboundTraceContext(
  item: { traceId?: string; traceContext?: TraceContext },
  opts: ResolvedTraceContextOptions | undefined
): ResolvedOutboundTraceContext | undefined {
  if (opts === undefined) return undefined;
  const carried = item.traceContext;
  if (carried !== undefined) {
    return {
      traceId: mapOtlpTraceId(carried.traceId),
      sampled: carried.sampled,
      ...(carried.traceState !== undefined ? { traceState: carried.traceState } : {}),
    };
  }
  const traceId = item.traceId;
  if (traceId === undefined || traceId.length === 0) return undefined;
  return { traceId: mapOtlpTraceId(traceId), sampled: opts.sampled };
}
