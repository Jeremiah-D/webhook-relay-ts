/**
 * OpenTelemetry span export (WR-151).
 *
 * Opt-in distributed-tracing export for the relay's delivery lifecycle.
 * When enabled, each delivery gets one trace with the intake → dispatch
 * → delivery span chain:
 *
 * - `relay.intake` (root): from `enqueue()` to the first dispatch
 *   attempt (or to the terminal state when the delivery never attempts
 *   — e.g. the WR-150 auto-disable gate). Measures admission/queueing
 *   delay.
 * - `relay.dispatch` (child of intake): from the first attempt to the
 *   terminal state (`delivered` / `dead_letter`). Groups the attempts.
 * - `relay.delivery` (child of dispatch, one per attempt): each
 *   delivery attempt. Attributes carry endpoint/tenant/attempt/status,
 *   and the start/end timestamps give the duration.
 *
 * W3C trace-context reuse (WR-98): the trace id comes from the delivery's
 * caller-propagated W3C context (`RetryItem.traceContext`, carried by the
 * durable queue) when present, else from the relay's own trace id mapped
 * to 32-hex (the same `mapOtlpTraceId` the OTLP log export uses). The
 * per-attempt `relay.delivery` span id is `traceAttemptSpanId(traceId,
 * attempt)` — the exact parent-id the relay stamps on that attempt's
 * outbound `traceparent` — so the OTel span and the downstream trace's
 * span correlate without any extra plumbing.
 *
 * Sampling is head-based: the decision is made once at intake
 * (`random() < sampleRate`), so a sampled trace always exports whole.
 * Unsampled traces cost one random draw and nothing else.
 *
 * Export is OTLP/HTTP JSON (`Content-Type: application/json`) POSTed to
 * `<endpoint>/v1/traces`, with the same transport contract as the WR-83
 * log exporter: `record()` is synchronous buffer work and never throws,
 * the background flush timer is unref'd, failures stay in a bounded
 * in-memory buffer (drop-oldest) and retry with exponential backoff.
 *
 * Disabled by default: the queue constructs the tracer only when the
 * `otelTracing` option is set. When unset, every hook is a single
 * `undefined` check on the dispatch path — zero behavior change.
 *
 * Zero dependencies beyond `node:crypto` (trace-id mapping) and
 * `node:http`/`node:https` (transport).
 */

import { createHash } from "node:crypto";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { mapOtlpTraceId } from "./otlp.ts";
import { traceAttemptSpanId } from "./trace-context.ts";

/** Opt-in OTel span export, embedded in `RetryQueueOptions`. */
export interface OtelTracingOptions {
  /**
   * Collector base URL (http or https). Spans are POSTed to
   * `<endpoint>/v1/traces`. Required when the option is set.
   */
  endpoint: string;
  /**
   * Fraction of delivery traces exported, in [0, 1]. Head-based: the
   * decision is made once at intake. Default 1.0 (everything).
   */
  sampleRate?: number;
  /**
   * `service.name` resource attribute on every payload.
   * Default `"webhook-relay-ts"`.
   */
  serviceName?: string;
  /**
   * Extra HTTP headers on the export POST (e.g. an auth token).
   * Header names/values must be non-empty strings.
   */
  headers?: Record<string, string>;
  /**
   * Maximum finished traces held in the export buffer. Drop-oldest on
   * overflow. Default 1000. Must be >= 1.
   */
  maxBuffered?: number;
  /**
   * Maximum live (unterminated) traces tracked. Drop-oldest on
   * overflow — a delivery that never terminates (queue stopped
   * mid-flight) must not leak memory. Default 10000. Must be >= 1.
   */
  maxTraces?: number;
  /**
   * Sampling random source in [0, 1); defaults to `Math.random`.
   * Injectable so tests can verify sampling deterministically.
   */
  random?: () => number;
  /**
   * Clock in ms epoch; defaults to `Date.now`. Injectable so tests can
   * verify span timestamps deterministically.
   */
  now?: () => number;
}

/** Snapshot returned by `OtelTracer.stats()`. */
export interface OtelTracingStats {
  /** Always true for a constructed tracer; false when unset. */
  enabled: boolean;
  /** Live (unterminated) traces currently tracked. */
  liveTraces: number;
  /** Finished traces sitting in the export buffer. */
  buffered: number;
  /** Cumulative traces dropped by buffer overflow (drop-oldest). */
  dropped: number;
  /** Cumulative spans acknowledged by the collector (2xx). */
  exportedSpans: number;
  /** Last export failure message, if any; cleared on success. */
  lastError?: string;
}

/** Terminal outcome of a delivery, for the trace. */
export type OtelTerminalOutcome = "delivered" | "dead_letter";

/** Span names in the intake → dispatch → delivery chain. */
export const OTEL_SPAN_INTAKE = "relay.intake";
export const OTEL_SPAN_DISPATCH = "relay.dispatch";
export const OTEL_SPAN_DELIVERY = "relay.delivery";

interface OtelAttribute {
  key: string;
  value: { stringValue: string } | { intValue: string };
}

function stringValue(value: string): { stringValue: string } {
  return { stringValue: value };
}

function intValue(value: number): { intValue: string } {
  return { intValue: String(Math.round(value)) };
}

function attr(key: string, value: string): OtelAttribute {
  return { key, value: stringValue(value) };
}

function intAttr(key: string, value: number): OtelAttribute {
  return { key, value: intValue(value) };
}

/** One finished span, ready for OTLP rendering. */
interface FinishedSpan {
  traceId: string;
  spanId: string;
  parentSpanId?: string;
  name: string;
  startTimeUnixNano: string;
  endTimeUnixNano: string;
  attributes: OtelAttribute[];
  /** OTel status code: 1 = ok, 2 = error. */
  statusCode: number;
}

/** Mutable state of one live trace. */
interface LiveTrace {
  traceId: string;
  eventId: string;
  endpoint: string;
  tenant?: string;
  intakeStartMs: number;
  intakeSpanId: string;
  dispatchSpanId: string;
  /** Intake span end (first attempt start, or terminal). */
  intakeEndMs?: number;
  /** Dispatch span start (first attempt start). */
  dispatchStartMs?: number;
  /** Per-attempt span starts, keyed by 1-based attempt. */
  attemptStarts: Map<number, number>;
  /** Finished spans, in start order. */
  spans: FinishedSpan[];
  /** Highest 1-based attempt started (for the attempts attribute). */
  maxAttempt: number;
}

function describeValue(value: unknown): string {
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" || typeof value === "boolean" || value === null) {
    return String(value);
  }
  return typeof value;
}

/** Deterministic 16-hex span id for the intake/dispatch spans. */
function derivedSpanId(traceId32: string, kind: string): string {
  return createHash("sha256").update(`${traceId32}:${kind}`, "utf8").digest("hex").slice(0, 16);
}

function toNano(ms: number): string {
  return (BigInt(Math.max(0, Math.round(ms))) * 1_000_000n).toString();
}

/** Per-POST request timeout — a hung collector must not pin the flush. */
const REQUEST_TIMEOUT_MS = 5_000;
/** Coalescing delay after `record()` before the background flush fires. */
const FLUSH_DELAY_MS = 50;
/** Base backoff after a failed export; doubles per consecutive failure. */
const RETRY_BASE_MS = 250;
/** Cap for the export retry backoff. */
const RETRY_MAX_MS = 30_000;

/**
 * Background OTLP/HTTP JSON trace exporter. Mirrors the WR-83
 * `OtlpExporter` transport contract: synchronous non-throwing record,
 * unref'd flush timer, bounded drop-oldest buffer, exponential backoff.
 */
export class OtelTraceExporter {
  private readonly tracesUrl: string;
  private readonly isHttps: boolean;
  private readonly serviceName: string;
  private readonly headers: Record<string, string>;
  private readonly maxBuffered: number;
  private readonly now: () => number;

  private readonly buffer: FinishedSpan[][] = [];
  private droppedExports = 0;
  private exportedSpans = 0;
  private lastError: string | undefined;
  private consecutiveFailures = 0;
  private flushTimer: ReturnType<typeof setTimeout> | undefined;

  constructor(opts: OtelTracingOptions) {
    if (opts === null || typeof opts !== "object" || Array.isArray(opts)) {
      throw new RangeError(`otelTracing options must be an object, got ${describeValue(opts)}`);
    }
    if (typeof opts.endpoint !== "string" || opts.endpoint.length === 0) {
      throw new RangeError("otelTracing.endpoint must be a non-empty URL string");
    }
    let parsed: URL;
    try {
      parsed = new URL(opts.endpoint);
    } catch {
      throw new RangeError(`otelTracing.endpoint must be a valid URL, got ${JSON.stringify(opts.endpoint)}`);
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new RangeError(
        `otelTracing.endpoint must use http(s), got protocol ${JSON.stringify(parsed.protocol)}`
      );
    }
    const sampleRate = opts.sampleRate ?? 1.0;
    if (
      typeof sampleRate !== "number" ||
      !Number.isFinite(sampleRate) ||
      sampleRate < 0 ||
      sampleRate > 1
    ) {
      throw new RangeError(`otelTracing.sampleRate must be a finite number in [0, 1], got ${sampleRate}`);
    }
    const maxBuffered = opts.maxBuffered ?? 1000;
    if (typeof maxBuffered !== "number" || !Number.isInteger(maxBuffered) || maxBuffered < 1) {
      throw new RangeError(`otelTracing.maxBuffered must be an integer >= 1, got ${maxBuffered}`);
    }
    if (opts.serviceName !== undefined && (typeof opts.serviceName !== "string" || opts.serviceName.length === 0)) {
      throw new RangeError("otelTracing.serviceName must be a non-empty string when set");
    }
    if (opts.headers !== undefined) {
      if (opts.headers === null || typeof opts.headers !== "object" || Array.isArray(opts.headers)) {
        throw new RangeError("otelTracing.headers must be an object when set");
      }
      for (const [k, v] of Object.entries(opts.headers)) {
        if (typeof k !== "string" || k.length === 0 || typeof v !== "string" || v.length === 0) {
          throw new RangeError("otelTracing.headers must map non-empty strings to non-empty strings");
        }
      }
    }
    const tracesUrl = new URL("v1/traces", opts.endpoint.endsWith("/") ? opts.endpoint : `${opts.endpoint}/`);
    this.tracesUrl = tracesUrl.toString();
    this.isHttps = tracesUrl.protocol === "https:";
    this.serviceName = opts.serviceName ?? "webhook-relay-ts";
    this.headers = { ...(opts.headers ?? {}) };
    this.maxBuffered = maxBuffered;
    this.now = opts.now ?? Date.now;
  }

  /**
   * Record one finished trace for export. Synchronous buffer work only —
   * never blocks, never throws. Buffer overflow drops the oldest traces
   * first.
   */
  record(spans: FinishedSpan[]): void {
    try {
      if (spans.length === 0) return;
      this.buffer.push(spans);
      if (this.buffer.length > this.maxBuffered) {
        const overflow = this.buffer.length - this.maxBuffered;
        this.buffer.splice(0, overflow);
        this.droppedExports += overflow;
      }
      this.scheduleFlush(FLUSH_DELAY_MS);
    } catch {
      // Unreachable by contract — but the delivery path must never see
      // an export throw.
    }
  }

  /** POST the buffered traces to the collector. Never rejects. */
  async flush(): Promise<void> {
    const batch = this.buffer.splice(0, this.buffer.length);
    if (batch.length === 0) return;
    let body: string;
    try {
      body = buildOtlpTracesPayload(batch, this.serviceName);
    } catch (err) {
      this.buffer.unshift(...batch);
      this.noteFailure(err);
      this.scheduleFlush(this.backoffMs());
      return;
    }
    try {
      await this.post(body);
    } catch (err) {
      this.buffer.unshift(...batch);
      this.noteFailure(err);
      this.scheduleFlush(this.backoffMs());
      return;
    }
    this.exportedSpans += batch.reduce((n, spans) => n + spans.length, 0);
    this.lastError = undefined;
    this.consecutiveFailures = 0;
  }

  /** Stop the background timer. Buffered traces are dropped with the process. */
  stop(): void {
    this.clearFlushTimer();
  }

  /**
   * Re-arm a pending export retry timer (cleared by `stop()`) when
   * traces are still buffered.
   */
  resume(): void {
    if (this.buffer.length > 0) this.scheduleFlush(FLUSH_DELAY_MS);
  }

  /**
   * Best-effort final flush, bounded so a dead collector can never pin
   * shutdown. Resolves once the flush settles or the timeout fires.
   */
  async shutdown(timeoutMs = 1_000): Promise<void> {
    this.clearFlushTimer();
    await Promise.race([
      this.flush(),
      new Promise((resolve) => setTimeout(resolve, Math.max(0, timeoutMs))),
    ]);
  }

  /** Export stats for `OtelTracer.stats()`. */
  exportStats(): { buffered: number; dropped: number; exportedSpans: number; lastError?: string } {
    return {
      buffered: this.buffer.length,
      dropped: this.droppedExports,
      exportedSpans: this.exportedSpans,
      ...(this.lastError !== undefined ? { lastError: this.lastError } : {}),
    };
  }

  private noteFailure(err: unknown): void {
    this.lastError = err instanceof Error ? err.message : String(err);
    this.consecutiveFailures += 1;
  }

  private backoffMs(): number {
    return Math.min(RETRY_BASE_MS * 2 ** Math.min(this.consecutiveFailures, 10), RETRY_MAX_MS);
  }

  private scheduleFlush(delayMs: number): void {
    if (this.flushTimer !== undefined) return;
    this.flushTimer = setTimeout(() => {
      this.flushTimer = undefined;
      void this.flush();
    }, Math.max(0, delayMs));
    this.flushTimer.unref?.();
  }

  private clearFlushTimer(): void {
    if (this.flushTimer !== undefined) {
      clearTimeout(this.flushTimer);
      this.flushTimer = undefined;
    }
  }

  private post(body: string): Promise<void> {
    return new Promise((resolve, reject) => {
      const requestFn = this.isHttps ? httpsRequest : httpRequest;
      const req = requestFn(
        this.tracesUrl,
        {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "content-length": Buffer.byteLength(body),
            ...this.headers,
          },
          timeout: REQUEST_TIMEOUT_MS,
        },
        (res) => {
          res.resume();
          res.on("end", () => {
            const status = res.statusCode ?? 0;
            if (status >= 200 && status < 300) resolve();
            else reject(new Error(`OTLP traces export failed with status ${status}`));
          });
        }
      );
      req.on("timeout", () => req.destroy(new Error("OTLP traces export timed out")));
      req.on("error", reject);
      req.end(body);
    });
  }
}

/**
 * Build the OTLP/HTTP JSON traces payload for finished traces. Exported
 * for tests — the queue never calls it directly.
 */
export function buildOtlpTracesPayload(traces: FinishedSpan[][], serviceName: string): string {
  return JSON.stringify({
    resourceSpans: traces.map((spans) => ({
      resource: {
        attributes: [attr("service.name", serviceName)],
      },
      scopeSpans: [
        {
          scope: { name: "webhook-relay-ts" },
          spans: spans.map((s) => ({
            traceId: s.traceId,
            spanId: s.spanId,
            ...(s.parentSpanId !== undefined ? { parentSpanId: s.parentSpanId } : {}),
            name: s.name,
            kind: 1,
            startTimeUnixNano: s.startTimeUnixNano,
            endTimeUnixNano: s.endTimeUnixNano,
            attributes: s.attributes,
            status: { code: s.statusCode },
          })),
        },
      ],
    })),
  });
}

/**
 * Per-delivery trace lifecycle: intake → dispatch → delivery spans.
 * Constructed (and validated) by `RetryQueue` when
 * `RetryQueueOptions.otelTracing` is set; never constructed otherwise.
 *
 * All methods are safe to call for deliveries the tracer never saw
 * (unsampled or pre-feature): they no-op. Methods never throw — a
 * tracing bug must not reach the delivery path.
 */
export class OtelTracer {
  private readonly exporter: OtelTraceExporter;
  private readonly sampleRate: number;
  private readonly random: () => number;
  private readonly now: () => number;
  private readonly maxTraces: number;
  private readonly traces = new Map<string, LiveTrace>();

  constructor(opts: OtelTracingOptions) {
    if (opts === null || typeof opts !== "object" || Array.isArray(opts)) {
      throw new RangeError(`otelTracing options must be an object, got ${describeValue(opts)}`);
    }
    const sampleRate = opts.sampleRate ?? 1.0;
    if (
      typeof sampleRate !== "number" ||
      !Number.isFinite(sampleRate) ||
      sampleRate < 0 ||
      sampleRate > 1
    ) {
      throw new RangeError(`otelTracing.sampleRate must be a finite number in [0, 1], got ${sampleRate}`);
    }
    const maxTraces = opts.maxTraces ?? 10000;
    if (typeof maxTraces !== "number" || !Number.isInteger(maxTraces) || maxTraces < 1) {
      throw new RangeError(`otelTracing.maxTraces must be an integer >= 1, got ${maxTraces}`);
    }
    this.exporter = new OtelTraceExporter(opts);
    this.sampleRate = sampleRate;
    this.random = opts.random ?? Math.random;
    this.now = opts.now ?? Date.now;
    this.maxTraces = maxTraces;
  }

  /**
   * Trace identity for a delivery: the caller-propagated W3C trace id
   * when the item carries one (durable-queue passthrough), else the
   * relay's own trace id mapped to 32-hex. Matches the trace id the
   * outbound `traceparent` carries, so the OTel trace joins the
   * downstream trace.
   */
  static traceIdFor(item: { traceId?: string; traceContext?: { traceId: string } }): string {
    const carried = item.traceContext?.traceId;
    if (typeof carried === "string" && carried.length > 0) return mapOtlpTraceId(carried);
    return mapOtlpTraceId(item.traceId ?? "");
  }

  /**
   * Intake: start the trace and the root `relay.intake` span. Called
   * from `enqueueNow()` — when the item becomes a live delivery — and
   * from `requeueDeadLetter()` for replays. Batch-window and deliver_at
   * parking end before this point (like the latency clock), so a
   * batch-buffered member never starts a trace: the flushed batch item
   * gets its own. Head-based sampling: an unsampled delivery is not
   * tracked at all.
   */
  intake(item: { id: string; traceId?: string; traceContext?: { traceId: string }; targetUrl: string; tenantId?: string }): void {
    try {
      if (this.traces.has(item.id)) return;
      if (this.random() >= this.sampleRate) return;
      const traceId = OtelTracer.traceIdFor(item);
      const nowMs = this.now();
      const live: LiveTrace = {
        traceId,
        eventId: item.id,
        endpoint: item.targetUrl,
        ...(item.tenantId !== undefined ? { tenant: item.tenantId } : {}),
        intakeStartMs: nowMs,
        intakeSpanId: derivedSpanId(traceId, "intake"),
        dispatchSpanId: derivedSpanId(traceId, "dispatch"),
        attemptStarts: new Map(),
        spans: [],
        maxAttempt: 0,
      };
      this.traces.set(item.id, live);
      if (this.traces.size > this.maxTraces) {
        const oldest = this.traces.keys().next();
        if (!oldest.done) this.traces.delete(oldest.value);
      }
    } catch {
      // Tracing never breaks intake.
    }
  }

  /**
   * Start one `relay.delivery` attempt span (and the `relay.dispatch`
   * span on the first attempt). Called on the dispatch path just before
   * the sender is invoked. Returns the 1-based attempt number, or
   * `undefined` when the delivery is not traced.
   */
  startAttempt(item: { id: string; traceId?: string; traceContext?: { traceId: string }; targetUrl: string; tenantId?: string }, attempt1Based: number): number | undefined {
    try {
      const live = this.traces.get(item.id);
      if (live === undefined) return undefined;
      const nowMs = this.now();
      if (live.dispatchStartMs === undefined) {
        // First dispatch: the intake span ends here, the dispatch span
        // begins. Intake measures admission → first dispatch.
        live.intakeEndMs = nowMs;
        live.dispatchStartMs = nowMs;
        live.spans.push({
          traceId: live.traceId,
          spanId: live.intakeSpanId,
          name: OTEL_SPAN_INTAKE,
          startTimeUnixNano: toNano(live.intakeStartMs),
          endTimeUnixNano: toNano(nowMs),
          attributes: this.baseAttributes(live),
          statusCode: 1,
        });
      }
      live.attemptStarts.set(attempt1Based, nowMs);
      if (attempt1Based > live.maxAttempt) live.maxAttempt = attempt1Based;
      return attempt1Based;
    } catch {
      return undefined;
    }
  }

  /**
   * End one `relay.delivery` attempt span. Called when the attempt
   * settles (success, failure, or dead-letter). A no-op for untracked
   * deliveries.
   */
  endAttempt(
    item: { id: string },
    attempt1Based: number | undefined,
    ok: boolean,
    error?: string
  ): void {
    try {
      if (attempt1Based === undefined) return;
      const live = this.traces.get(item.id);
      if (live === undefined) return;
      const startMs = live.attemptStarts.get(attempt1Based);
      if (startMs === undefined) return;
      live.attemptStarts.delete(attempt1Based);
      const nowMs = this.now();
      const attributes = this.baseAttributes(live);
      attributes.push(intAttr("relay.attempt", attempt1Based));
      attributes.push(attr("relay.status", ok ? "ok" : "error"));
      if (error !== undefined && error.length > 0) {
        attributes.push(attr("relay.error", error.slice(0, 512)));
      }
      live.spans.push({
        traceId: live.traceId,
        // WR-98 reuse: the attempt span id is the exact parent-id the
        // relay stamps on this attempt's outbound `traceparent`.
        spanId: traceAttemptSpanId(live.traceId, attempt1Based),
        parentSpanId: live.dispatchSpanId,
        name: OTEL_SPAN_DELIVERY,
        startTimeUnixNano: toNano(startMs),
        endTimeUnixNano: toNano(nowMs),
        attributes,
        statusCode: ok ? 1 : 2,
      });
    } catch {
      // Tracing never breaks the delivery path.
    }
  }

  /**
   * Terminal: end any open attempt spans, then the intake span (when the
   * delivery never attempted) and the dispatch span, then hand the
   * finished trace to the exporter. A no-op for untracked deliveries.
   * Idempotent with `endAttempt`: open attempts end here with the given
   * error message (a later `endAttempt` for them is a no-op).
   */
  terminal(item: { id: string }, outcome: OtelTerminalOutcome, error?: string): void {
    try {
      const live = this.traces.get(item.id);
      if (live === undefined) return;
      this.traces.delete(item.id);
      const nowMs = this.now();
      // Any attempt still open settled with this terminal outcome — it
      // just ran, so end it here rather than leaving it dangling for
      // the (now pointless) `endAttempt` call.
      for (const [attempt1Based, startMs] of live.attemptStarts) {
        live.attemptStarts.delete(attempt1Based);
        const attributes = this.baseAttributes(live);
        attributes.push(intAttr("relay.attempt", attempt1Based));
        attributes.push(attr("relay.status", outcome === "delivered" ? "ok" : "error"));
        if (error !== undefined && error.length > 0) {
          attributes.push(attr("relay.error", error.slice(0, 512)));
        }
        live.spans.push({
          traceId: live.traceId,
          spanId: traceAttemptSpanId(live.traceId, attempt1Based),
          parentSpanId: live.dispatchSpanId,
          name: OTEL_SPAN_DELIVERY,
          startTimeUnixNano: toNano(startMs),
          endTimeUnixNano: toNano(nowMs),
          attributes,
          statusCode: outcome === "delivered" ? 1 : 2,
        });
        if (attempt1Based > live.maxAttempt) live.maxAttempt = attempt1Based;
      }
      if (live.dispatchStartMs === undefined) {
        // Never attempted: the intake span runs to the terminal state.
        live.spans.push({
          traceId: live.traceId,
          spanId: live.intakeSpanId,
          name: OTEL_SPAN_INTAKE,
          startTimeUnixNano: toNano(live.intakeStartMs),
          endTimeUnixNano: toNano(nowMs),
          attributes: this.baseAttributes(live),
          statusCode: outcome === "delivered" ? 1 : 2,
        });
      } else {
        // Dispatch span: first attempt → terminal.
        const attributes = this.baseAttributes(live);
        attributes.push(intAttr("relay.attempts", live.maxAttempt));
        attributes.push(attr("relay.status", outcome === "delivered" ? "ok" : "error"));
        live.spans.push({
          traceId: live.traceId,
          spanId: live.dispatchSpanId,
          parentSpanId: live.intakeSpanId,
          name: OTEL_SPAN_DISPATCH,
          startTimeUnixNano: toNano(live.dispatchStartMs),
          endTimeUnixNano: toNano(nowMs),
          attributes,
          statusCode: outcome === "delivered" ? 1 : 2,
        });
      }
      this.exporter.record(live.spans);
    } catch {
      // Tracing never breaks the delivery path.
    }
  }

  /** Current snapshot. */
  stats(): OtelTracingStats {
    const exp = this.exporter.exportStats();
    return {
      enabled: true,
      liveTraces: this.traces.size,
      buffered: exp.buffered,
      dropped: exp.dropped,
      exportedSpans: exp.exportedSpans,
      ...(exp.lastError !== undefined ? { lastError: exp.lastError } : {}),
    };
  }

  /** Stop the background export timer. */
  stop(): void {
    this.exporter.stop();
  }

  /** Re-arm a pending export retry timer (cleared by `stop()`). */
  resume(): void {
    this.exporter.resume();
  }

  /** Best-effort final export flush. */
  shutdown(timeoutMs?: number): Promise<void> {
    return this.exporter.shutdown(timeoutMs);
  }

  /** Flush buffered traces now. Never rejects. */
  flush(): Promise<void> {
    return this.exporter.flush();
  }

  private baseAttributes(live: LiveTrace): OtelAttribute[] {
    const attributes: OtelAttribute[] = [
      attr("relay.event_id", live.eventId),
      attr("relay.endpoint", live.endpoint),
    ];
    if (live.tenant !== undefined) attributes.push(attr("relay.tenant", live.tenant));
    return attributes;
  }
}
