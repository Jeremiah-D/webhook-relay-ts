import { createHmac } from "node:crypto";
import { readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { dirname, join } from "node:path";
import type { AuditLog } from "./audit.ts";
import { assertValidTenantId } from "./tenant.ts";

/**
 * Audit-event webhook sink (WR-90): opt-in forwarding of audit-log events
 * to an external webhook endpoint, following the LG-67 convention from
 * ledger-api-go.
 *
 * Delivery contract, stated honestly:
 *
 * - The sink never touches the delivery path: it tails the audit-log
 *   file on its own background worker, so a slow or dead webhook cannot
 *   stall intake or retries. A crash or restart resumes from the
 *   persisted cursor file.
 * - At-least-once and in order: an event is delivered (HTTP 2xx), then
 *   the cursor advances. A crash between delivery and the cursor write
 *   replays the event after restart — downstream must dedupe on the
 *   event's content, like any other outbox consumer. A stop mid-retry
 *   abandons the event (no dead letter) so the next start redelivers it.
 * - Gaps are possible by design: when an event exhausts `maxAttempts` it
 *   is dead-lettered — recorded as an `audit_sink_dead_letter` audit
 *   event, counted, and skipped — and the cursor moves past it. The
 *   stream then has a hole at that event; the dead-letter audit event is
 *   the record of it. Alert on the dead-letter counter. Dead-letter
 *   lines are never re-forwarded (that would loop forever), so a sink
 *   outage is visible exactly once per lost event.
 * - First start begins at the current log tail: history is NOT replayed.
 *   The sink forwards new audit facts; it is not a backfill tool.
 * - Head-of-line blocking: events are forwarded strictly in log order,
 *   so one poison tenant URL delays every event behind it (including
 *   other tenants') until it dead-letters. Route noisy tenants to a
 *   reliable sink, or accept the delay as the price of an ordered
 *   audit trail.
 * - Do not point the sink at this relay's own intake: the forwarded
 *   events would be rejected (no valid webhook signature), each
 *   rejection would audit a new line, and the sink would chase its own
 *   tail.
 *
 * Every delivery is signed: HMAC-SHA256(secret, body), hex-encoded, sent
 * as `x-relay-audit-signature: sha256=<hex>` (the WR-26 signing
 * convention), alongside `x-relay-audit-event` (the audit event name)
 * and `x-relay-audit-tenant` (only when the event carries a tenant,
 * WR-48). The body is the exact JSONL log line — byte-identical to the
 * audit record, hash-chain fields included — so a downstream can verify
 * both authenticity and chain continuity. Payloads sealed by the WR-11
 * encryptor stay sealed in transit; the sink never decrypts.
 *
 * The secret is mandatory: an unsigned webhook can be forged, so the
 * sink refuses to start without one. The whole sink is off by default —
 * constructing it is opt-in, and `createRelayServer` only builds one
 * when `auditSink` is set.
 */

/** Header carrying the HMAC-SHA256 signature of the forwarded log line. */
export const AUDIT_SINK_SIGNATURE_HEADER = "x-relay-audit-signature";
/** Header carrying the audit event name (e.g. `delivered`). */
export const AUDIT_SINK_EVENT_HEADER = "x-relay-audit-event";
/** Header carrying the tenant id, present only on tenant-scoped events. */
export const AUDIT_SINK_TENANT_HEADER = "x-relay-audit-tenant";
/**
 * Audit event name the sink writes when an event exhausts its retries.
 * These lines are bookkeeping, never forwarded (forwarding them would
 * loop: a dead sink would dead-letter its own dead letters forever).
 */
export const AUDIT_SINK_DEAD_LETTER_EVENT = "audit_sink_dead_letter";

/** Per-tenant sink override: this tenant's audit events go here instead. */
export interface AuditSinkTenantConfig {
  /**
   * Webhook endpoint receiving this tenant's audit events as JSON POSTs.
   * Required; must be an absolute http(s) URL.
   */
  url: string;
  /**
   * HMAC secret signing this tenant's deliveries. Defaults to the
   * sink-wide `secret` — set it only when the tenant's receiver needs
   * its own key.
   */
  secret?: string | Buffer;
}

/** Options for {@link AuditSink}. */
export interface AuditSinkOptions {
  /**
   * Webhook endpoint receiving every audit event as a JSON POST.
   * Required; must be an absolute http(s) URL.
   */
  url: string;
  /**
   * Signs every delivery: HMAC-SHA256(secret, body), sent as
   * `x-relay-audit-signature: sha256=<hex>`. Required — an unsigned
   * webhook can be forged, so the sink refuses to start without one.
   */
  secret: string | Buffer;
  /**
   * Per-tenant sink URL overrides (the LG-67 per-tenant convention):
   * events carrying a `tenant` (WR-48) are routed to the matching
   * entry, everything else goes to the default `url`/`secret`. Tenant
   * ids are validated with the WR-48 charset.
   */
  tenantSinks?: Record<string, AuditSinkTenantConfig>;
  /**
   * Bounds the POST attempts per event, including the first try.
   * Default 10.
   */
  maxAttempts?: number;
  /**
   * Wait before the first retry; doubles per retry up to
   * `maxBackoffMs`. Default 1000.
   */
  initialBackoffMs?: number;
  /** Backoff ceiling. Default 60_000. */
  maxBackoffMs?: number;
  /**
   * Idle wait between log polls when no new events are waiting.
   * Default 1000.
   */
  pollIntervalMs?: number;
  /** Bounds a single POST attempt. Default 10_000. */
  httpTimeoutMs?: number;
  /**
   * Persists the last forwarded byte offset across restarts (atomic
   * tmp+rename write). Default `<audit-log-dir>/audit-sink.cursor`.
   */
  cursorFile?: string;
}

/** Delivery counters; see {@link AuditSink.stats}. */
export interface AuditSinkStats {
  /** Events delivered (HTTP 2xx). */
  sent: number;
  /**
   * Failed POST attempts (network errors and non-2xx responses,
   * including the final attempts of dead-lettered events).
   */
  failedAttempts: number;
  /** Events dead-lettered after exhausting retries. */
  deadLetters: number;
}

const DEFAULT_MAX_ATTEMPTS = 10;
const DEFAULT_INITIAL_BACKOFF_MS = 1_000;
const DEFAULT_MAX_BACKOFF_MS = 60_000;
const DEFAULT_POLL_INTERVAL_MS = 1_000;
const DEFAULT_HTTP_TIMEOUT_MS = 10_000;

interface ResolvedTenantSink {
  url: URL;
  secret: string | Buffer;
}

interface ResolvedAuditSinkConfig {
  defaultUrl: URL;
  defaultSecret: string | Buffer;
  tenantSinks: Map<string, ResolvedTenantSink>;
  maxAttempts: number;
  initialBackoffMs: number;
  maxBackoffMs: number;
  pollIntervalMs: number;
  httpTimeoutMs: number;
  cursorFile: string;
}

function assertValidSinkUrl(raw: unknown, what: string): URL {
  if (typeof raw !== "string" || raw.length === 0) {
    throw new RangeError(`audit sink: ${what} url must be a non-empty string`);
  }
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new RangeError(`audit sink: ${what} url ${JSON.stringify(raw)} is not a valid absolute URL`);
  }
  if ((u.protocol !== "http:" && u.protocol !== "https:") || u.host === "") {
    throw new RangeError(
      `audit sink: ${what} url must be an absolute http(s) URL, got ${JSON.stringify(raw)}`
    );
  }
  return u;
}

function assertValidSinkSecret(secret: unknown, what: string): asserts secret is string | Buffer {
  const ok =
    (typeof secret === "string" && secret.length > 0) ||
    (Buffer.isBuffer(secret) && secret.length > 0);
  if (!ok) {
    throw new RangeError(
      `audit sink: ${what} secret must be a non-empty string or Buffer (unsigned webhooks can be forged)`
    );
  }
}

function assertNonNegativeInt(value: unknown, name: string): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new RangeError(`audit sink: ${name} must be a non-negative integer, got ${String(value)}`);
  }
  return value;
}

/** Validate the options and resolve zero values to the documented defaults. */
function resolveConfig(opts: AuditSinkOptions, auditLogPath: string): ResolvedAuditSinkConfig {
  if (opts === null || typeof opts !== "object" || Array.isArray(opts)) {
    throw new TypeError("audit sink: options must be an object");
  }
  const defaultUrl = assertValidSinkUrl(opts.url, "default");
  assertValidSinkSecret(opts.secret, "default");
  const defaultSecret: string | Buffer = opts.secret;

  const tenantSinks = new Map<string, ResolvedTenantSink>();
  if (opts.tenantSinks !== undefined) {
    if (opts.tenantSinks === null || typeof opts.tenantSinks !== "object" || Array.isArray(opts.tenantSinks)) {
      throw new TypeError("audit sink: tenantSinks must be a record of tenant id -> sink config");
    }
    for (const [tenant, cfg] of Object.entries(opts.tenantSinks)) {
      assertValidTenantId(tenant);
      if (cfg === null || typeof cfg !== "object" || Array.isArray(cfg)) {
        throw new TypeError(`audit sink: tenantSinks[${JSON.stringify(tenant)}] must be an object`);
      }
      const url = assertValidSinkUrl(cfg.url, `tenant ${JSON.stringify(tenant)}`);
      let secret: string | Buffer = defaultSecret;
      if (cfg.secret !== undefined) {
        assertValidSinkSecret(cfg.secret, `tenant ${JSON.stringify(tenant)}`);
        secret = cfg.secret;
      }
      tenantSinks.set(tenant, { url, secret });
    }
  }

  const maxAttempts = opts.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
  if (!Number.isInteger(maxAttempts) || maxAttempts < 1) {
    throw new RangeError(`audit sink: maxAttempts must be an integer >= 1, got ${String(opts.maxAttempts)}`);
  }
  // Zero selects the default (a zero poll interval would busy-loop); a
  // negative value is a configuration bug, fail fast.
  const initialBackoffMs = assertNonNegativeInt(opts.initialBackoffMs, "initialBackoffMs") || DEFAULT_INITIAL_BACKOFF_MS;
  const maxBackoffMs = assertNonNegativeInt(opts.maxBackoffMs, "maxBackoffMs") || DEFAULT_MAX_BACKOFF_MS;
  const pollIntervalMs = assertNonNegativeInt(opts.pollIntervalMs, "pollIntervalMs") || DEFAULT_POLL_INTERVAL_MS;
  const httpTimeoutMs = assertNonNegativeInt(opts.httpTimeoutMs, "httpTimeoutMs") || DEFAULT_HTTP_TIMEOUT_MS;

  let cursorFile = opts.cursorFile;
  if (cursorFile !== undefined && (typeof cursorFile !== "string" || cursorFile.length === 0)) {
    throw new RangeError("audit sink: cursorFile must be a non-empty string");
  }
  cursorFile ??= join(dirname(auditLogPath), "audit-sink.cursor");

  return {
    defaultUrl,
    defaultSecret,
    tenantSinks,
    maxAttempts,
    initialBackoffMs: Math.min(initialBackoffMs, maxBackoffMs),
    maxBackoffMs,
    pollIntervalMs,
    httpTimeoutMs,
    cursorFile,
  };
}

function fileSize(path: string): number {
  try {
    return statSync(path).size;
  } catch {
    return 0;
  }
}

/**
 * Load the persisted cursor: a byte offset, or null when the file is
 * absent (first start). A corrupt cursor fails the start loudly rather
 * than silently replaying or skipping the stream.
 */
function readCursorFile(path: string): number | null {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
  const n = Number(raw.trim());
  if (!Number.isInteger(n) || n < 0) {
    throw new RangeError(`audit sink: corrupt cursor file ${JSON.stringify(path)}: want a non-negative integer`);
  }
  return n;
}

/**
 * Persist the cursor with an atomic tmp+rename, so a crash can never
 * leave a torn cursor behind. (A lost cursor only costs redelivery —
 * the sink is at-least-once either way.)
 */
function writeCursorFile(path: string, offset: number): void {
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, `${offset}\n`, "utf8");
  renameSync(tmp, path);
}

/**
 * Forwards audit-log events to a webhook endpoint on a background
 * worker. Build one per audit log; `start()` begins forwarding,
 * `stop()` halts it. The zero value is unusable.
 */
export class AuditSink {
  private readonly auditLog: AuditLog;
  private readonly cfg: ResolvedAuditSinkConfig;
  private started = false;
  private stopRequested = false;
  private pollTimer: NodeJS.Timeout | undefined;
  private readonly sleepers = new Set<(ok: boolean) => void>();
  private readonly aborter = new AbortController();
  /** Last forwarded byte offset in the audit log; only the worker touches it. */
  private offset = 0;
  private sent = 0;
  private failedAttempts = 0;
  private deadLetters = 0;

  constructor(auditLog: AuditLog, opts: AuditSinkOptions) {
    if (
      auditLog === null ||
      typeof auditLog !== "object" ||
      typeof (auditLog as AuditLog).append !== "function" ||
      typeof (auditLog as AuditLog).filePath !== "string"
    ) {
      throw new TypeError("audit sink: auditLog must be an AuditLog instance");
    }
    this.auditLog = auditLog;
    this.cfg = resolveConfig(opts, auditLog.filePath);
  }

  /**
   * Start the background forwarder. Idempotent. The first start (no
   * cursor file) begins at the current log tail — history is not
   * replayed.
   */
  start(): void {
    if (this.started && !this.stopRequested) return;
    this.started = true;
    this.stopRequested = false;
    const saved = readCursorFile(this.cfg.cursorFile);
    if (saved === null) {
      this.offset = fileSize(this.auditLog.filePath);
      writeCursorFile(this.cfg.cursorFile, this.offset);
    } else {
      this.offset = saved;
    }
    this.loop();
  }

  /**
   * Halt the forwarder: no new polls, in-flight POSTs and backoff
   * sleeps are abandoned (the cursor does not advance, so the next
   * start redelivers them — at-least-once). Idempotent.
   */
  stop(): void {
    this.stopRequested = true;
    if (this.pollTimer !== undefined) {
      clearTimeout(this.pollTimer);
      this.pollTimer = undefined;
    }
    for (const wake of [...this.sleepers]) wake(false);
    this.aborter.abort();
  }

  /** Delivery counters: sent, failed attempts, dead-lettered events. */
  stats(): AuditSinkStats {
    return { sent: this.sent, failedAttempts: this.failedAttempts, deadLetters: this.deadLetters };
  }

  /** Last forwarded byte offset in the audit log. */
  cursorOffset(): number {
    return this.offset;
  }

  private loop(): void {
    if (this.stopRequested) return;
    this.forwardAvailable()
      .catch((err) => {
        // The forwarder is best-effort: a transient read error must not
        // kill it — the next poll retries. (Delivery failures never
        // reach here; deliver() dead-letters after maxAttempts.)
        process.stderr.write(`audit sink: poll failed: ${(err as Error).message}\n`);
      })
      .finally(() => {
        if (this.stopRequested) return;
        const t = setTimeout(() => {
          this.pollTimer = undefined;
          this.loop();
        }, this.cfg.pollIntervalMs);
        // The worker must never pin process exit.
        t.unref();
        this.pollTimer = t;
      });
  }

  /**
   * Forward every complete line appended since the cursor, in order.
   * The cursor advances only past delivered or dead-lettered lines —
   * never past a poison line — and is persisted as it goes.
   */
  private async forwardAvailable(): Promise<void> {
    const path = this.auditLog.filePath;
    let size = fileSize(path);
    if (size < this.offset) {
      // Truncated or rotated underneath us: restart from the beginning
      // rather than forwarding a torn stream. (The relay never rotates
      // the audit log itself; this covers external rotation.)
      this.offset = 0;
      size = fileSize(path);
    }
    if (size === this.offset) return;

    let raw: Buffer;
    try {
      raw = readFileSync(path);
    } catch (err) {
      throw new Error(`read audit log: ${(err as Error).message}`);
    }
    const tail = raw.subarray(this.offset, size);
    // Hold back a trailing partial line (no newline yet): a later poll
    // sees it complete. append() always writes whole lines, so this is
    // only crash-safety, never the common case.
    let completeEnd = tail.length;
    if (tail.length > 0 && tail[tail.length - 1] !== 0x0a) {
      const lastNl = tail.lastIndexOf(0x0a);
      completeEnd = lastNl < 0 ? 0 : lastNl + 1;
    }

    let consumed = 0;
    let lineStart = 0;
    for (let i = 0; i < completeEnd; i++) {
      if (tail[i] !== 0x0a) continue;
      const line = tail.subarray(lineStart, i); // without the newline
      lineStart = i + 1;
      const event = parseAuditLine(line);
      if (event !== undefined && event.name !== AUDIT_SINK_DEAD_LETTER_EVENT) {
        const delivered = await this.deliver(line, event.name, event.tenant);
        if (!delivered) break; // stopping: leave the cursor; restart redelivers
      }
      // Corrupt lines, pre-chain lines, and the sink's own dead-letter
      // bookkeeping are skipped but still advance the cursor — the
      // cursor must never stick on a line nobody can deliver.
      consumed = lineStart;
    }
    if (consumed > 0) {
      this.offset += consumed;
      writeCursorFile(this.cfg.cursorFile, this.offset);
    }
  }

  /**
   * POST one log line with its HMAC signature, retrying with
   * exponential backoff up to maxAttempts. Returns false only when the
   * sink is stopping mid-delivery; a delivered event and a
   * dead-lettered one both advance the cursor.
   */
  private async deliver(line: Buffer, eventName: string, tenant: string | undefined): Promise<boolean> {
    const target =
      tenant !== undefined ? this.cfg.tenantSinks.get(tenant) : undefined;
    const url = target?.url ?? this.cfg.defaultUrl;
    const secret = target?.secret ?? this.cfg.defaultSecret;
    const signature = `sha256=${createHmac("sha256", secret).update(line).digest("hex")}`;
    const headers: Record<string, string> = {
      "content-type": "application/json",
      [AUDIT_SINK_SIGNATURE_HEADER]: signature,
      [AUDIT_SINK_EVENT_HEADER]: eventName,
      ...(tenant !== undefined ? { [AUDIT_SINK_TENANT_HEADER]: tenant } : {}),
    };
    let backoff = this.cfg.initialBackoffMs;
    for (let attempt = 1; ; attempt++) {
      if (this.stopRequested) return false;
      const res = await this.post(url, line, headers);
      if (res.ok) {
        this.sent++;
        return true;
      }
      this.failedAttempts++;
      if (attempt >= this.cfg.maxAttempts) {
        this.deadLetter(eventName, tenant, url, attempt, res.status, res.error);
        return true;
      }
      if (!(await this.sleepInterruptible(backoff))) return false;
      backoff = Math.min(backoff * 2, this.cfg.maxBackoffMs);
    }
  }

  /** One signed delivery attempt. Never throws: the outcome is the return value. */
  private post(
    url: URL,
    body: Buffer,
    headers: Record<string, string>
  ): Promise<{ ok: boolean; status: number; error?: string }> {
    return new Promise((resolve) => {
      const request = url.protocol === "https:" ? httpsRequest : httpRequest;
      const req = request(
        url,
        {
          method: "POST",
          headers: { ...headers, "content-length": String(body.length) },
          timeout: this.cfg.httpTimeoutMs,
          signal: this.aborter.signal,
        },
        (res) => {
          res.resume(); // discard the response body
          res.on("end", () => {
            const status = res.statusCode ?? 0;
            resolve({ ok: status >= 200 && status < 300, status });
          });
        }
      );
      req.on("timeout", () => {
        req.destroy(new Error(`audit sink: POST timed out after ${this.cfg.httpTimeoutMs}ms`));
      });
      req.on("error", (err) => {
        resolve({ ok: false, status: 0, error: (err as Error).message });
      });
      req.end(body);
    });
  }

  /**
   * Record an undeliverable event as an `audit_sink_dead_letter` audit
   * event (the compliance record of the gap), count it, and let the
   * cursor move past it. The line itself is never forwarded.
   */
  private deadLetter(
    eventName: string,
    tenant: string | undefined,
    url: URL,
    attempts: number,
    lastStatus: number,
    lastError: string | undefined
  ): void {
    this.deadLetters++;
    const entry: Record<string, unknown> = {
      event: AUDIT_SINK_DEAD_LETTER_EVENT,
      eventName,
      sinkUrl: url.toString(),
      attempts,
      lastStatus,
      ...(tenant !== undefined ? { tenant } : {}),
      ...(lastError !== undefined ? { lastError } : {}),
    };
    try {
      this.auditLog.append(entry);
    } catch (err) {
      // Losing the dead-letter record is bad, but spinning on a broken
      // log is worse: the counter still reports the loss.
      process.stderr.write(`audit sink: dead-letter append failed: ${(err as Error).message}\n`);
    }
  }

  /** Sleep that resolves false when the sink stops mid-wait. Unref'd: never pins exit. */
  private sleepInterruptible(ms: number): Promise<boolean> {
    if (this.stopRequested) return Promise.resolve(false);
    if (ms <= 0) return Promise.resolve(true);
    return new Promise<boolean>((resolve) => {
      const wake = (ok: boolean): void => {
        this.sleepers.delete(wake);
        clearTimeout(t);
        resolve(ok && !this.stopRequested);
      };
      const t = setTimeout(() => wake(true), ms);
      t.unref();
      this.sleepers.add(wake);
    });
  }
}

/** Parse one JSONL line into its routable fields; undefined when not a usable event object. */
function parseAuditLine(line: Buffer): { name: string; tenant?: string } | undefined {
  let obj: unknown;
  try {
    obj = JSON.parse(line.toString("utf8"));
  } catch {
    return undefined;
  }
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) return undefined;
  const rec = obj as Record<string, unknown>;
  const name = typeof rec.event === "string" ? rec.event : "";
  const tenant = typeof rec.tenant === "string" ? rec.tenant : undefined;
  return { name, tenant };
}
