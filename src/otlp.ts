import { createHash } from "node:crypto";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";

/**
 * OTLP/HTTP JSON delivery-event export (WR-83).
 *
 * Opt-in observability sink for the relay's delivery lifecycle: the
 * `delivered` / `retrying` / `dead_letter` delivery events (WR-16,
 * emitted via `RetryQueue.subscribeDeliveryEvents`) plus `slo_missed`
 * latency events (WR-13 `SloMissInfo`, via the wrapped
 * `LatencyOptions.onSloMiss`) are exported to a configurable collector
 * endpoint as OTLP logs JSON (`Content-Type: application/json`).
 *
 * Design rules:
 * - Disabled by default: no `otlp` option means zero behavior change —
 *   the queue never constructs an exporter.
 * - Export never blocks or breaks the delivery path: `record()` is
 *   synchronous buffer work and never throws; the background flush
 *   timer is unref'd; failures are retained in a bounded in-memory
 *   buffer (`maxBuffered`, drop-oldest) and retried with exponential
 *   backoff.
 * - Invalid configs fail fast with `RangeError` at construction, never
 *   mid-delivery.
 * - Zero dependencies: `node:crypto` for trace-ID mapping, `node:http` /
 *   `node:https` for transport.
 */

/** Event types exported to the collector. */
export type OtlpEventType = "delivered" | "retrying" | "dead_letter" | "slo_missed";

/** Export outcome for one (event_type, status) counter pair. */
export type OtlpExportStatus = "success" | "failure";

/** A single event waiting to be exported. */
export interface OtlpRecordInput {
  /** The relay event this log record describes. */
  eventType: OtlpEventType;
  /** Relay event id (`relay.event_id` attribute). */
  eventId: string;
  /** End-to-end trace ID; mapped to a valid 32-hex OTLP `trace_id`. */
  traceId: string;
  /** Delivery `targetUrl` (`relay.endpoint` attribute). */
  endpoint: string;
  /** Attempts consumed so far (delivery events only). */
  attempts?: number;
  /** Failure message (`retrying` / `dead_letter` only). */
  error?: string;
  /** Tenant id (WR-48); rendered only when present. */
  tenant?: string;
  /** SLO budget in ms (`slo_missed` only). */
  sloMs?: number;
  /** Observed accepted→delivered latency in ms (`slo_missed` only). */
  latencyMs?: number;
  /**
   * WR-95: the phase that dominated the delivery's latency
   * (`slo_missed` only). Set only when phase tracking is enabled and a
   * phase was measurable.
   */
  dominantPhase?: string;
}

/** Opt-in OTLP export, embedded in `RetryQueueOptions`. */
export interface OtlpExporterOptions {
  /**
   * Collector endpoint: the full URL (http or https) the OTLP logs JSON
   * payload is POSTed to. Required when the option is set.
   */
  endpoint: string;
  /**
   * Fraction of events exported, in [0, 1]. Default 1.0 (everything).
   * 0 drops every event before it reaches the buffer.
   */
  sampleRate?: number;
  /**
   * Maximum records held in the local in-memory buffer. When a new
   * record arrives and the buffer is full, the oldest records are
   * dropped (`otlpDroppedExports`). Default 1000. Must be >= 1.
   */
  maxBuffered?: number;
  /**
   * `service.name` resource attribute on every payload.
   * Default `"webhook-relay-ts"`.
   */
  serviceName?: string;
  /**
   * Sampling random source in [0, 1); defaults to `Math.random`.
   * Injectable so tests can verify sampling deterministically.
   */
  random?: () => number;
  /**
   * Clock in ms epoch; defaults to `Date.now`. Injectable so tests can
   * verify record timestamps deterministically.
   */
  now?: () => number;
}

/** Snapshot returned by `OtlpExporter.stats()` / `RetryQueue.getOtlpStats()`. */
export interface OtlpStats {
  /** Always true for a constructed exporter; false when unset. */
  enabled: boolean;
  /** Records currently sitting in the local buffer. */
  buffered: number;
  /** Cumulative records dropped by drop-oldest buffer overflow. */
  dropped: number;
  /** Cumulative records acknowledged by the collector (2xx). */
  exported: number;
  /** Last export failure message, if any; cleared on success. */
  lastError?: string;
}

/** One (event_type, status) cumulative export counter, for metrics. */
export interface OtlpExportCount {
  eventType: OtlpEventType;
  status: OtlpExportStatus;
  count: number;
}

/** Fresh 32-hex trace IDs pass through (lowercased); anything else is mapped. */
const HEX32 = /^[0-9a-fA-F]{32}$/;

/**
 * Map a relay trace ID (WR-18: fresh 32-hex UUIDs or 1–64 char
 * alnum/`_`/`-` client values) to a valid 32-hex OTLP `trace_id`.
 * 32-hex values pass through (lowercased); everything else is hashed
 * with SHA-256 and truncated to 32 hex chars — deterministic, so the
 * same client trace ID always maps to the same OTLP trace ID.
 */
export function mapOtlpTraceId(traceId: string): string {
  if (HEX32.test(traceId)) return traceId.toLowerCase();
  return createHash("sha256").update(traceId, "utf8").digest("hex").slice(0, 32);
}

/** One OTLP `AnyValue` carrying a string. */
function stringValue(value: string): { stringValue: string } {
  return { stringValue: value };
}

/** One OTLP `AnyValue` carrying an integer (OTLP int64s are JSON strings). */
function intValue(value: number): { intValue: string } {
  return { intValue: String(Math.round(value)) };
}

interface OtlpAttribute {
  key: string;
  value: { stringValue: string } | { intValue: string };
}

function attr(key: string, value: string): OtlpAttribute {
  return { key, value: stringValue(value) };
}

function intAttr(key: string, value: number): OtlpAttribute {
  return { key, value: intValue(value) };
}

/**
 * Render the buffered records as one OTLP logs JSON payload
 * (`ExportLogsServiceRequest` in JSON form). Pure — exported for tests.
 */
export function buildOtlpPayload(
  records: OtlpRecordInput[],
  serviceName: string,
  nowMs: number
): string {
  const nowNano = (BigInt(Math.round(nowMs)) * 1_000_000n).toString();
  const logRecords = records.map((r) => {
    const isWarn = r.eventType === "dead_letter";
    const attributes: OtlpAttribute[] = [
      attr("relay.event_id", r.eventId),
      attr("relay.event_type", r.eventType),
      attr("relay.endpoint", r.endpoint),
    ];
    if (r.tenant !== undefined) attributes.push(attr("relay.tenant", r.tenant));
    if (r.attempts !== undefined) attributes.push(intAttr("relay.attempts", r.attempts));
    if (r.error !== undefined) attributes.push(attr("relay.error", r.error));
    if (r.sloMs !== undefined) attributes.push(intAttr("relay.slo_ms", r.sloMs));
    if (r.latencyMs !== undefined) attributes.push(intAttr("relay.latency_ms", r.latencyMs));
    if (r.dominantPhase !== undefined) attributes.push(attr("relay.dominant_phase", r.dominantPhase));
    return {
      timeUnixNano: nowNano,
      observedTimeUnixNano: nowNano,
      severityNumber: isWarn ? 13 : 9,
      severityText: isWarn ? "WARN" : "INFO",
      traceId: mapOtlpTraceId(r.traceId),
      body: stringValue(r.eventType),
      attributes,
    };
  });
  return JSON.stringify({
    resourceLogs: [
      {
        resource: {
          attributes: [attr("service.name", serviceName)],
        },
        scopeLogs: [
          {
            scope: { name: "webhook-relay-ts" },
            logRecords,
          },
        ],
      },
    ],
  });
}

/** Per-POST request timeout — a hung collector must not pin the flush. */
const REQUEST_TIMEOUT_MS = 5_000;
/** Coalescing delay after `record()` before the background flush fires. */
const FLUSH_DELAY_MS = 50;
/** Base backoff after a failed export; doubles per consecutive failure. */
const RETRY_BASE_MS = 250;
/** Cap for the export retry backoff. */
const RETRY_MAX_MS = 30_000;
/** Default bound for `shutdown()`'s best-effort final flush. */
const SHUTDOWN_TIMEOUT_MS = 1_000;

/** Fixed render order for per-(event_type, status) export counters. */
const EXPORT_COUNTER_ORDER: Array<[OtlpEventType, OtlpExportStatus]> = [
  ["delivered", "success"],
  ["delivered", "failure"],
  ["retrying", "success"],
  ["retrying", "failure"],
  ["dead_letter", "success"],
  ["dead_letter", "failure"],
  ["slo_missed", "success"],
  ["slo_missed", "failure"],
];

/**
 * Background OTLP/HTTP JSON exporter. Constructed (and validated) by
 * `RetryQueue` when `RetryQueueOptions.otlp` is set; never constructed
 * otherwise, so the default relay keeps zero OTLP behavior.
 */
export class OtlpExporter {
  private readonly endpoint: URL;
  private readonly endpointString: string;
  private readonly sampleRate: number;
  private readonly maxBuffered: number;
  private readonly serviceName: string;
  private readonly random: () => number;
  private readonly now: () => number;

  private readonly buffer: OtlpRecordInput[] = [];
  private droppedExports = 0;
  private exportedCount = 0;
  private lastError: string | undefined;
  private consecutiveFailures = 0;
  private readonly exportCountMap = new Map<string, number>();
  private flushTimer: ReturnType<typeof setTimeout> | undefined;

  constructor(opts: OtlpExporterOptions) {
    if (opts === null || typeof opts !== "object" || Array.isArray(opts)) {
      throw new RangeError(`otlp options must be an object, got ${JSON.stringify(opts)}`);
    }
    if (typeof opts.endpoint !== "string" || opts.endpoint.length === 0) {
      throw new RangeError(`otlp.endpoint must be a non-empty URL string`);
    }
    let parsed: URL;
    try {
      parsed = new URL(opts.endpoint);
    } catch {
      throw new RangeError(`otlp.endpoint must be a valid URL, got ${JSON.stringify(opts.endpoint)}`);
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new RangeError(
        `otlp.endpoint must use http(s), got protocol ${JSON.stringify(parsed.protocol)}`
      );
    }
    const sampleRate = opts.sampleRate ?? 1.0;
    if (
      typeof sampleRate !== "number" ||
      !Number.isFinite(sampleRate) ||
      sampleRate < 0 ||
      sampleRate > 1
    ) {
      throw new RangeError(`otlp.sampleRate must be a finite number in [0, 1], got ${sampleRate}`);
    }
    const maxBuffered = opts.maxBuffered ?? 1000;
    if (typeof maxBuffered !== "number" || !Number.isInteger(maxBuffered) || maxBuffered < 1) {
      throw new RangeError(`otlp.maxBuffered must be an integer >= 1, got ${maxBuffered}`);
    }
    if (opts.serviceName !== undefined && (typeof opts.serviceName !== "string" || opts.serviceName.length === 0)) {
      throw new RangeError(`otlp.serviceName must be a non-empty string when set`);
    }
    this.endpoint = parsed;
    this.endpointString = opts.endpoint;
    this.sampleRate = sampleRate;
    this.maxBuffered = maxBuffered;
    this.serviceName = opts.serviceName ?? "webhook-relay-ts";
    this.random = opts.random ?? Math.random;
    this.now = opts.now ?? Date.now;
  }

  /**
   * Record one event for export. Synchronous buffer work only — never
   * blocks, never throws (a mapping bug must not reach the delivery
   * path). Sampling drops happen before the buffer; buffer overflow
   * drops the oldest records first.
   */
  record(input: OtlpRecordInput): void {
    try {
      if (this.random() >= this.sampleRate) return;
      this.buffer.push({ ...input });
      if (this.buffer.length > this.maxBuffered) {
        const overflow = this.buffer.length - this.maxBuffered;
        this.buffer.splice(0, overflow);
        this.droppedExports += overflow;
      }
      this.scheduleFlush(FLUSH_DELAY_MS);
    } catch {
      // Unreachable by contract — sampling, push, and splice are total —
      // but the delivery path must never see an export throw.
    }
  }

  /** Current snapshot; `enabled` is always true for a live exporter. */
  stats(): OtlpStats {
    const out: OtlpStats = {
      enabled: true,
      buffered: this.buffer.length,
      dropped: this.droppedExports,
      exported: this.exportedCount,
    };
    if (this.lastError !== undefined) out.lastError = this.lastError;
    return out;
  }

  /**
   * Cumulative per-(event_type, status) export counters in fixed order,
   * for the `relay_otlp_exports_total` series. Only pairs with a
   * non-zero count are returned.
   */
  exportCounts(): OtlpExportCount[] {
    const out: OtlpExportCount[] = [];
    for (const [eventType, status] of EXPORT_COUNTER_ORDER) {
      const count = this.exportCountMap.get(`${eventType}/${status}`) ?? 0;
      if (count > 0) out.push({ eventType, status, count });
    }
    return out;
  }

  /**
   * POST the buffered records to the collector. Never rejects: a failed
   * batch stays in the buffer and a retry is scheduled with exponential
   * backoff (capped). Safe to call concurrently — the first call drains
   * the buffer, later ones see it empty.
   */
  async flush(): Promise<void> {
    const batch = this.buffer.splice(0, this.buffer.length);
    if (batch.length === 0) return;
    let body: string;
    try {
      body = buildOtlpPayload(batch, this.serviceName, this.now());
    } catch (err) {
      // A payload-building bug must not lose the batch silently: keep it
      // buffered and surface the error for the next flush attempt.
      this.buffer.unshift(...batch);
      for (const r of batch) this.bumpCount(r.eventType, "failure");
      this.noteFailure(err);
      this.scheduleFlush(this.backoffMs());
      return;
    }
    try {
      await this.post(body);
    } catch (err) {
      this.buffer.unshift(...batch);
      for (const r of batch) this.bumpCount(r.eventType, "failure");
      this.noteFailure(err);
      this.scheduleFlush(this.backoffMs());
      return;
    }
    this.exportedCount += batch.length;
    this.lastError = undefined;
    this.consecutiveFailures = 0;
    for (const r of batch) this.bumpCount(r.eventType, "success");
  }

  /**
   * Stop the background retry timer and kick off one best-effort flush
   * (fire-and-forget — `stop()` is synchronous). Buffered records stay
   * in the buffer for the next `start()` via `resume()`.
   */
  stop(): void {
    this.clearFlushTimer();
    void this.flush();
  }

  /**
   * Clear timers and flush best-effort within `timeoutMs` (default 1s).
   * Never rejects and never hangs: the flush races the timeout, and the
   * timeout timer is unref'd.
   */
  async shutdown(timeoutMs = SHUTDOWN_TIMEOUT_MS): Promise<void> {
    this.clearFlushTimer();
    const bound = Math.max(0, timeoutMs);
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        this.flush(),
        new Promise<void>((resolve) => {
          timer = setTimeout(resolve, bound);
          timer.unref();
        }),
      ]);
    } catch {
      // `flush()` never rejects by contract; this is the final backstop.
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }

  /**
   * Re-arm a flush when the buffer is non-empty and no timer is armed
   * (e.g. after `stop()` cleared a pending retry timer). Called from
   * `RetryQueue.start()`.
   */
  resume(): void {
    if (this.buffer.length > 0) this.scheduleFlush(FLUSH_DELAY_MS);
  }

  private noteFailure(err: unknown): void {
    this.lastError = err instanceof Error ? err.message : String(err);
    this.consecutiveFailures += 1;
  }

  private bumpCount(eventType: OtlpEventType, status: OtlpExportStatus): void {
    const key = `${eventType}/${status}`;
    this.exportCountMap.set(key, (this.exportCountMap.get(key) ?? 0) + 1);
  }

  private backoffMs(): number {
    const exp = Math.min(this.consecutiveFailures, 10);
    return Math.min(RETRY_BASE_MS * 2 ** exp, RETRY_MAX_MS);
  }

  private scheduleFlush(delayMs: number): void {
    if (this.flushTimer !== undefined) return;
    this.flushTimer = setTimeout(() => {
      this.flushTimer = undefined;
      void this.flush();
    }, delayMs);
    this.flushTimer.unref();
  }

  private clearFlushTimer(): void {
    if (this.flushTimer !== undefined) {
      clearTimeout(this.flushTimer);
      this.flushTimer = undefined;
    }
  }

  /** One POST of the payload; resolves on 2xx, rejects otherwise. */
  private post(body: string): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const useHttps = this.endpoint.protocol === "https:";
      const lib = useHttps ? httpsRequest : httpRequest;
      let req: ReturnType<typeof httpRequest> | undefined;
      const timer = setTimeout(() => {
        req?.destroy(new Error(`OTLP export to ${this.endpointString} timed out after ${REQUEST_TIMEOUT_MS}ms`));
      }, REQUEST_TIMEOUT_MS);
      // Never pin the process on a slow collector; cleared on settle.
      timer.unref();
      const onSettled = (): void => clearTimeout(timer);
      try {
        req = lib(this.endpoint, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Content-Length": String(Buffer.byteLength(body)),
          },
        });
      } catch (err) {
        onSettled();
        reject(err);
        return;
      }
      req.on("error", (err) => {
        onSettled();
        reject(err);
      });
      req.on("response", (res) => {
        res.resume();
        res.on("error", (err) => {
          onSettled();
          reject(err);
        });
        res.on("end", () => {
          onSettled();
          const status = res.statusCode ?? 0;
          if (status >= 200 && status < 300) resolve();
          else reject(new Error(`OTLP collector responded with status ${status}`));
        });
      });
      req.end(body);
    });
  }
}
