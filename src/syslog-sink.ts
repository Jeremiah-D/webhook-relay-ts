import { createSocket, type Socket as UdpSocket } from "node:dgram";
import { readFileSync } from "node:fs";
import { hostname } from "node:os";
import { createConnection, type Socket as TcpSocket } from "node:net";
import type { AuditLog } from "./audit.ts";
import {
  AUDIT_SINK_DEAD_LETTER_EVENT,
  fileSize,
  readCursorFile,
  writeCursorFile,
  type AuditSinkStats,
} from "./audit-sink.ts";

/**
 * Audit-event syslog sink (WR-157): opt-in forwarding of audit-log
 * events to a syslog collector (SIEM) over UDP or TCP, in RFC 5424 or
 * CEF format. Follows the WR-90 outbox contract:
 *
 * Delivery contract, stated honestly:
 *
 * - The sink never touches the delivery path: it tails the audit-log
 *   file on its own background worker, so a slow or dead collector
 *   cannot stall intake or retries. A crash or restart resumes from
 *   the persisted cursor file.
 * - At-least-once and in order: a message is sent, then the cursor
 *   advances. A crash between send and the cursor write replays the
 *   message after restart — downstream must dedupe like any other
 *   outbox consumer. A stop mid-retry abandons the event (no dead
 *   letter) so the next start redelivers it.
 * - Gaps are possible by design: when an event exhausts `maxAttempts`
 *   it is dead-lettered — recorded as an `audit_sink_dead_letter`
 *   audit event (the same event name the webhook sink uses, so both
 *   forwarders skip each other's bookkeeping), counted, and skipped.
 *   Dead-letter lines are never re-forwarded.
 * - First start begins at the current log tail: history is NOT
 *   replayed. The sink forwards new audit facts; it is not a backfill
 *   tool.
 * - Head-of-line blocking: events forward strictly in log order, so
 *   one poison event delays everything behind it until it
 *   dead-letters.
 * - UDP is at-most-once per datagram: the retry loop re-sends on send
 *   errors and timeouts, but a silently dropped datagram is never
 *   detected. Use TCP when the SIEM must see every event. A TCP write
 *   completing means the kernel accepted the frame, not that the SIEM
 *   processed it.
 * - TCP uses RFC 5425 octet counting (`<len> <frame>`). Any send
 *   failure drops the connection before the retry: a partial write
 *   would desynchronize the octet-counted stream, so the next attempt
 *   always starts on a fresh connection.
 *
 * Formats:
 *
 * - `rfc5424` (default): `<PRI>1 <ts> <host> <app> <pid> <event> - <json>`.
 *   PRI = facility*8 + severity; the MSG is the exact audit JSONL line
 *   (hash-chain fields included), so a downstream can verify chain
 *   continuity. Payloads sealed by the WR-11 encryptor stay sealed;
 *   the sink never decrypts.
 * - `cef`: the same RFC 5424 envelope, but the MSG is a CEF record
 *   `CEF:0|Jeremiah-D|webhook-relay|<version>|<event>|<event>|<sev>|<ext>`
 *   with mapped extensions (tenant, traceId, keyId, reason, request
 *   URL, attempt count). CEF severity is derived from the syslog
 *   severity tier.
 *
 * The whole sink is off by default — constructing it is opt-in, and
 * `createRelayServer` only builds one when `syslogSink` is set.
 */

/** Default syslog port. */
export const SYSLOG_DEFAULT_PORT = 514;
/** Largest syslog/UDP frame: 65507 (max UDP payload) - 28 (IP+UDP headers). */
export const SYSLOG_MAX_UDP_FRAME_BYTES = 65479;

/** Syslog facility numbers by name (RFC 5424 §6.2.1). */
const SYSLOG_FACILITIES: Record<string, number> = {
  kern: 0,
  user: 1,
  mail: 2,
  daemon: 3,
  auth: 4,
  syslog: 5,
  lpr: 6,
  news: 7,
  uucp: 8,
  cron: 9,
  authpriv: 10,
  ftp: 11,
  ntp: 12,
  logaudit: 13,
  logalert: 14,
  clock: 15,
  local0: 16,
  local1: 17,
  local2: 18,
  local3: 19,
  local4: 20,
  local5: 21,
  local6: 22,
  local7: 23,
};

export type SyslogTransport = "udp" | "tcp";
export type SyslogFormat = "rfc5424" | "cef";

/** Options for {@link SyslogAuditSink}. */
export interface SyslogAuditSinkOptions {
  /**
   * Syslog collector hostname or IP. Required.
   */
  host: string;
  /**
   * Collector port. Default 514.
   */
  port?: number;
  /**
   * `udp` (default) or `tcp` (RFC 5425 octet counting). UDP is
   * at-most-once per datagram; TCP retries on a fresh connection per
   * attempt.
   */
  transport?: SyslogTransport;
  /**
   * Syslog facility as a number (0-23) or name (`local0` … `local7`,
   * `daemon`, …). Default `local0`.
   */
  facility?: number | string;
  /**
   * Message format: `rfc5424` (default, JSON MSG) or `cef` (CEF record
   * in the MSG). Both ride the same RFC 5424 envelope.
   */
  format?: SyslogFormat;
  /**
   * APP-NAME in the envelope. Default `webhook-relay`.
   */
  appName?: string;
  /**
   * HOSTNAME in the envelope. Default `os.hostname()`.
   */
  hostname?: string;
  /**
   * CEF device version (`|Jeremiah-D|webhook-relay|<here>|…`). Default
   * `0.1.0`; keep it tracking package.json on release.
   */
  productVersion?: string;
  /**
   * Bounds the send attempts per event, including the first try.
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
  /**
   * Bounds a single send attempt (UDP send or TCP write).
   * Default 10_000.
   */
  sendTimeoutMs?: number;
  /**
   * Bounds the TCP connect per attempt. Default 5_000.
   */
  connectTimeoutMs?: number;
  /**
   * Persists the last forwarded byte offset across restarts (atomic
   * tmp+rename write). Default `<audit-log-dir>/syslog-sink.cursor`.
   */
  cursorFile?: string;
  /**
   * Clock for the RFC 5424 TIMESTAMP. Default `Date.now` — inject a
   * fixed clock in tests.
   */
  now?: () => number;
}

interface ResolvedSyslogSinkConfig {
  host: string;
  port: number;
  transport: SyslogTransport;
  facility: number;
  format: SyslogFormat;
  appName: string;
  hostname: string;
  productVersion: string;
  maxAttempts: number;
  initialBackoffMs: number;
  maxBackoffMs: number;
  pollIntervalMs: number;
  sendTimeoutMs: number;
  connectTimeoutMs: number;
  cursorFile: string;
  now: () => number;
}

const DEFAULT_MAX_ATTEMPTS = 10;
const DEFAULT_INITIAL_BACKOFF_MS = 1_000;
const DEFAULT_MAX_BACKOFF_MS = 60_000;
const DEFAULT_POLL_INTERVAL_MS = 1_000;
const DEFAULT_SEND_TIMEOUT_MS = 10_000;
const DEFAULT_CONNECT_TIMEOUT_MS = 5_000;

/**
 * Resolve a facility number or name to its number. Exported so
 * embedders can validate config the same way the sink does.
 */
export function resolveSyslogFacility(facility: number | string): number {
  if (typeof facility === "number") {
    if (Number.isInteger(facility) && facility >= 0 && facility <= 23) return facility;
  } else if (typeof facility === "string") {
    const n = SYSLOG_FACILITIES[facility.toLowerCase()];
    if (n !== undefined) return n;
  }
  throw new RangeError(
    `syslog sink: facility must be an integer 0-23 or a name (${Object.keys(SYSLOG_FACILITIES).join(", ")}), got ${JSON.stringify(facility)}`
  );
}

// Syslog severity tiers for the relay's audit event names. Unknown
// events are Informational(6): a new event name must never crash the
// sink, and info is the honest default for an unclassified audit fact.
const SEVERITY_CRITICAL = new Set(["ocsp_revoked"]);
const SEVERITY_ERROR = new Set([
  "dead_letter",
  "audit_sink_dead_letter",
  "delivery_deadline_exceeded",
  "quorum_failed",
  "quorum_target_dead_lettered",
  "endpoint_auto_disabled",
  "callback_failed",
  "dry_run_exhausted",
  "dead_letter_escalation_failed",
]);
const SEVERITY_WARNING = new Set([
  "rejected",
  "budget_exceeded",
  "retry_budget_depleted",
  "error_budget_burn",
  "queue_depth_breached",
  "endpoint_auto_paused",
  "cert_expiring",
  "ocsp_alert",
  "failover_switched",
  "gzip_fallback_plaintext",
  "probe_failed",
]);
const SEVERITY_NOTICE = new Set([
  "api_key_revoked",
  "operator_key_revoked",
  "e2ee_key_rotated",
  "config_applied",
  "config_rolled_back",
  "endpoint_paused",
  "endpoint_resumed",
  "endpoint_enabled",
  "endpoint_config_updated",
  "replay_approved",
  "replay_forced",
  "replay_approval_expired",
  "dead_letter_replayed",
  "dead_letter_purged",
  "dead_letter_escalated",
  "dead_letter_escalation",
  "inbound_mtls_config_updated",
  "routing_rules_updated",
]);

/**
 * Syslog severity (0-7) for an audit event name. Exported so SIEM
 * integrations can reuse the exact tier the sink applies.
 */
export function syslogSeverity(eventName: string): number {
  if (SEVERITY_CRITICAL.has(eventName)) return 2;
  if (SEVERITY_ERROR.has(eventName)) return 3;
  if (SEVERITY_WARNING.has(eventName)) return 4;
  if (SEVERITY_NOTICE.has(eventName)) return 5;
  return 6;
}

/** CEF severity (0-10) derived from the syslog severity tier. */
function cefSeverity(eventName: string): number {
  return 10 - Math.round((syslogSeverity(eventName) * 10) / 7);
}

function assertNonNegativeInt(value: unknown, name: string): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
    throw new RangeError(`syslog sink: ${name} must be a non-negative integer, got ${String(value)}`);
  }
  return value;
}

/** Validate the options and resolve zero values to the documented defaults. */
function resolveConfig(opts: SyslogAuditSinkOptions, auditLogPath: string): ResolvedSyslogSinkConfig {
  if (opts === null || typeof opts !== "object" || Array.isArray(opts)) {
    throw new TypeError("syslog sink: options must be an object");
  }
  if (typeof opts.host !== "string" || opts.host.length === 0) {
    throw new RangeError("syslog sink: host must be a non-empty string");
  }
  const port = opts.port ?? SYSLOG_DEFAULT_PORT;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new RangeError(`syslog sink: port must be an integer 1-65535, got ${String(opts.port)}`);
  }
  const transport = opts.transport ?? "udp";
  if (transport !== "udp" && transport !== "tcp") {
    throw new RangeError(`syslog sink: transport must be "udp" or "tcp", got ${JSON.stringify(opts.transport)}`);
  }
  const facility = opts.facility === undefined ? 16 : resolveSyslogFacility(opts.facility);
  const format = opts.format ?? "rfc5424";
  if (format !== "rfc5424" && format !== "cef") {
    throw new RangeError(`syslog sink: format must be "rfc5424" or "cef", got ${JSON.stringify(opts.format)}`);
  }
  const appName = sanitizeToken(opts.appName ?? "webhook-relay", "appName", 48);
  const hostName = sanitizeToken(opts.hostname ?? hostname(), "hostname", 255);
  const productVersion =
    opts.productVersion === undefined ? "0.1.0" : sanitizeToken(opts.productVersion, "productVersion", 32);

  const maxAttempts = opts.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
  if (!Number.isInteger(maxAttempts) || maxAttempts < 1) {
    throw new RangeError(`syslog sink: maxAttempts must be an integer >= 1, got ${String(opts.maxAttempts)}`);
  }
  // Zero selects the default (a zero poll interval would busy-loop); a
  // negative value is a configuration bug, fail fast.
  const initialBackoffMs = assertNonNegativeInt(opts.initialBackoffMs, "initialBackoffMs") || DEFAULT_INITIAL_BACKOFF_MS;
  const maxBackoffMs = assertNonNegativeInt(opts.maxBackoffMs, "maxBackoffMs") || DEFAULT_MAX_BACKOFF_MS;
  const pollIntervalMs = assertNonNegativeInt(opts.pollIntervalMs, "pollIntervalMs") || DEFAULT_POLL_INTERVAL_MS;
  const sendTimeoutMs = assertNonNegativeInt(opts.sendTimeoutMs, "sendTimeoutMs") || DEFAULT_SEND_TIMEOUT_MS;
  const connectTimeoutMs = assertNonNegativeInt(opts.connectTimeoutMs, "connectTimeoutMs") || DEFAULT_CONNECT_TIMEOUT_MS;

  let cursorFile = opts.cursorFile;
  if (cursorFile !== undefined && (typeof cursorFile !== "string" || cursorFile.length === 0)) {
    throw new RangeError("syslog sink: cursorFile must be a non-empty string");
  }
  cursorFile ??= joinDirname(auditLogPath, "syslog-sink.cursor");

  const now = opts.now ?? Date.now;
  if (typeof now !== "function") {
    throw new TypeError("syslog sink: now must be a function");
  }

  return {
    host: opts.host,
    port,
    transport,
    facility,
    format,
    appName,
    hostname: hostName,
    productVersion,
    maxAttempts,
    initialBackoffMs: Math.min(initialBackoffMs, maxBackoffMs),
    maxBackoffMs,
    pollIntervalMs,
    sendTimeoutMs,
    connectTimeoutMs,
    cursorFile,
    now,
  };
}

function joinDirname(path: string, file: string): string {
  const i = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  return (i < 0 ? "." : path.slice(0, i)) + "/" + file;
}

/**
 * Envelope tokens (HOSTNAME, APP-NAME, …) must be printable ASCII
 * without spaces (RFC 5424 §6). Anything else is replaced with `-`
 * rather than failing the send: a weird hostname must never break
 * the audit trail.
 */
function sanitizeToken(raw: string, what: string, maxLen: number): string {
  if (typeof raw !== "string" || raw.length === 0) {
    throw new RangeError(`syslog sink: ${what} must be a non-empty string`);
  }
  const clean = raw.replace(/[^\x21-\x7e]/g, "-").slice(0, maxLen);
  if (clean.length === 0) {
    throw new RangeError(`syslog sink: ${what} has no usable characters`);
  }
  return clean;
}

/** MSGID is the audit event name, capped at 32 printable chars. */
function sanitizeMsgId(eventName: string): string {
  const clean = eventName.replace(/[^\x21-\x7e]/g, "-").slice(0, 32);
  return clean.length === 0 ? "-" : clean;
}

function pad2(n: number): string {
  return String(n).padStart(2, "0");
}

/** RFC 5424 TIMESTAMP: `YYYY-MM-DDTHH:mm:ss.sss±HH:MM` in local time. */
function rfc5424Timestamp(ms: number): string {
  const d = new Date(ms);
  const tzMin = -d.getTimezoneOffset();
  const sign = tzMin >= 0 ? "+" : "-";
  const abs = Math.abs(tzMin);
  return (
    `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}` +
    `T${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}` +
    `.${String(d.getMilliseconds()).padStart(3, "0")}` +
    `${sign}${pad2(Math.floor(abs / 60))}:${pad2(abs % 60)}`
  );
}

/** CEF header fields escape `\` and `|`. */
function cefEscapeHeader(v: string): string {
  return v.replace(/\\/g, "\\\\").replace(/\|/g, "\\|");
}

/** CEF extension values escape `\`, `=`, CR, LF. */
function cefEscapeExt(v: string): string {
  return v
    .replace(/\\/g, "\\\\")
    .replace(/=/g, "\\=")
    .replace(/\r/g, "\\r")
    .replace(/\n/g, "\\n");
}

function extString(v: unknown): string | undefined {
  return typeof v === "string" && v !== "" ? v : undefined;
}

/**
 * Map the audit record's routable fields to CEF extensions:
 *
 *   tenant  -> cs1 / cs1Label=tenant
 *   traceId -> cs2 / cs2Label=traceId
 *   keyId   -> cs3 / cs3Label=keyId
 *   reason  -> reason
 *   endpoint|url|targetUrl -> request
 *   attempt|attempts -> cnt
 *
 * Everything else stays in the JSON form — pick `rfc5424` when the
 * SIEM needs the full record.
 */
function cefExtensions(rec: Record<string, unknown> | undefined): string {
  const parts: string[] = [];
  const tenant = rec && extString(rec.tenant);
  if (tenant !== undefined) parts.push(`cs1=${cefEscapeExt(tenant)} cs1Label=tenant`);
  const traceId = rec && extString(rec.traceId);
  if (traceId !== undefined) parts.push(`cs2=${cefEscapeExt(traceId)} cs2Label=traceId`);
  const keyId = rec && extString(rec.keyId);
  if (keyId !== undefined) parts.push(`cs3=${cefEscapeExt(keyId)} cs3Label=keyId`);
  const reason = rec && extString(rec.reason);
  if (reason !== undefined) parts.push(`reason=${cefEscapeExt(reason)}`);
  const url = rec && (extString(rec.endpoint) ?? extString(rec.url) ?? extString(rec.targetUrl));
  if (url !== undefined) parts.push(`request=${cefEscapeExt(url)}`);
  const attempt =
    rec && (typeof rec.attempt === "number" ? rec.attempt : typeof rec.attempts === "number" ? rec.attempts : undefined);
  if (attempt !== undefined && Number.isInteger(attempt)) parts.push(`cnt=${attempt}`);
  return parts.join(" ");
}

/** Parse one JSONL line into the full audit record; undefined when unusable. */
function parseAuditRecord(line: Buffer): Record<string, unknown> | undefined {
  let obj: unknown;
  try {
    obj = JSON.parse(line.toString("utf8"));
  } catch {
    return undefined;
  }
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) return undefined;
  return obj as Record<string, unknown>;
}

function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  if (ms <= 0) return p;
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${what} timed out after ${ms}ms`)), ms);
    timer.unref();
  });
  return Promise.race([p, timeout]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  });
}

/**
 * Options for {@link buildSyslogFrame}: the envelope parameters.
 * Exported so operators can preview exactly what the sink will send.
 */
export interface SyslogFrameOptions {
  facility: number;
  format: SyslogFormat;
  appName: string;
  hostname: string;
  productVersion: string;
  now: () => number;
  transport: SyslogTransport;
}

/**
 * Build one framed syslog message: `<PRI>1 <ts> <host> <app> <pid>
 * <event> - <msg>`, where MSG is the audit JSONL line (rfc5424) or a
 * CEF record (cef). Pure function — no I/O — so the exact bytes are
 * unit-testable without a collector. UDP frames are truncated to fit
 * one datagram (`SYSLOG_MAX_UDP_FRAME_BYTES`).
 */
export function buildSyslogFrame(
  opts: SyslogFrameOptions,
  eventName: string,
  line: Buffer,
  rec: Record<string, unknown>
): Buffer {
  const pri = opts.facility * 8 + syslogSeverity(eventName);
  const header =
    `<${pri}>1 ${rfc5424Timestamp(opts.now())} ${opts.hostname} ${opts.appName} ` +
    `${process.pid} ${sanitizeMsgId(eventName)} - `;
  const headerBuf = Buffer.from(header, "utf8");
  const msgBuf =
    opts.format === "cef" ? Buffer.from(cefLine(eventName, rec, opts.productVersion), "utf8") : line;
  if (opts.transport === "udp" && headerBuf.length + msgBuf.length > SYSLOG_MAX_UDP_FRAME_BYTES) {
    return Buffer.concat([headerBuf, msgBuf.subarray(0, SYSLOG_MAX_UDP_FRAME_BYTES - headerBuf.length)]);
  }
  return Buffer.concat([headerBuf, msgBuf]);
}

/** CEF record for an audit event. Exported for the same preview reason. */
export function cefLine(eventName: string, rec: Record<string, unknown>, productVersion: string): string {
  const id = cefEscapeHeader(eventName === "" ? "-" : eventName);
  return (
    `CEF:0|Jeremiah-D|webhook-relay|${cefEscapeHeader(productVersion)}` +
    `|${id}|${id}|${cefSeverity(eventName)}|${cefExtensions(rec)}`
  );
}

/**
 * Forwards audit-log events to a syslog collector on a background
 * worker. Build one per audit log; `start()` begins forwarding,
 * `stop()` halts it. The zero value is unusable.
 */
export class SyslogAuditSink {
  private readonly auditLog: AuditLog;
  private readonly cfg: ResolvedSyslogSinkConfig;
  private started = false;
  private stopRequested = false;
  private pollTimer: NodeJS.Timeout | undefined;
  private readonly sleepers = new Set<(ok: boolean) => void>();
  /** Last forwarded byte offset in the audit log; only the worker touches it. */
  private offset = 0;
  private sent = 0;
  private failedAttempts = 0;
  private deadLetters = 0;
  private udp: UdpSocket | null = null;
  private tcp: TcpSocket | null = null;
  private tcpConnect: Promise<TcpSocket> | null = null;

  constructor(auditLog: AuditLog, opts: SyslogAuditSinkOptions) {
    if (
      auditLog === null ||
      typeof auditLog !== "object" ||
      typeof (auditLog as AuditLog).append !== "function" ||
      typeof (auditLog as AuditLog).filePath !== "string"
    ) {
      throw new TypeError("syslog sink: auditLog must be an AuditLog instance");
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
   * Halt the forwarder: no new polls, in-flight sends and backoff
   * sleeps are abandoned (the cursor does not advance, so the next
   * start redelivers them — at-least-once). Sockets are destroyed.
   * Idempotent.
   */
  stop(): void {
    this.stopRequested = true;
    if (this.pollTimer !== undefined) {
      clearTimeout(this.pollTimer);
      this.pollTimer = undefined;
    }
    for (const wake of [...this.sleepers]) wake(false);
    if (this.udp !== null) {
      try {
        this.udp.close();
      } catch {
        // Already closed — nothing to do.
      }
      this.udp = null;
    }
    this.dropTcp();
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
        // kill it — the next poll retries. (Send failures never reach
        // here; deliver() dead-letters after maxAttempts.)
        process.stderr.write(`syslog sink: poll failed: ${(err as Error).message}\n`);
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
   * The cursor advances only past sent or dead-lettered lines — never
   * past a poison line — and is persisted as it goes.
   */
  private async forwardAvailable(): Promise<void> {
    const path = this.auditLog.filePath;
    let size = fileSize(path);
    if (size < this.offset) {
      // Truncated or rotated underneath us: restart from the beginning
      // rather than forwarding a torn stream.
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
      const rec = parseAuditRecord(line);
      const name = rec !== undefined && typeof rec.event === "string" ? rec.event : "";
      if (rec !== undefined && name !== AUDIT_SINK_DEAD_LETTER_EVENT) {
        const delivered = await this.deliver(line, name, rec);
        if (!delivered) break; // stopping: leave the cursor; restart redelivers
      }
      // Corrupt lines and the sink's own dead-letter bookkeeping are
      // skipped but still advance the cursor — the cursor must never
      // stick on a line nobody can deliver.
      consumed = lineStart;
    }
    if (consumed > 0) {
      this.offset += consumed;
      writeCursorFile(this.cfg.cursorFile, this.offset);
    }
  }

  /**
   * Send one framed message, retrying with exponential backoff up to
   * maxAttempts. Returns false only when the sink is stopping
   * mid-delivery; a sent event and a dead-lettered one both advance
   * the cursor.
   */
  private async deliver(line: Buffer, eventName: string, rec: Record<string, unknown>): Promise<boolean> {
    const frame = this.formatFrame(eventName, line, rec);
    let backoff = this.cfg.initialBackoffMs;
    for (let attempt = 1; ; attempt++) {
      if (this.stopRequested) return false;
      try {
        if (this.cfg.transport === "udp") {
          await this.sendUdp(frame);
        } else {
          await this.sendTcp(frame);
        }
        this.sent++;
        return true;
      } catch (err) {
        this.failedAttempts++;
        // A failed TCP write may have desynchronized the octet-counted
        // stream — the next attempt always starts on a fresh
        // connection.
        if (this.cfg.transport === "tcp") this.dropTcp();
        if (attempt >= this.cfg.maxAttempts) {
          this.deadLetter(eventName, attempt, (err as Error).message);
          return true;
        }
        if (!(await this.sleepInterruptible(backoff))) return false;
        backoff = Math.min(backoff * 2, this.cfg.maxBackoffMs);
      }
    }
  }

  /**
   * Build the framed syslog message via the exported pure
   * {@link buildSyslogFrame} — the class only supplies its resolved
   * envelope parameters.
   */
  private formatFrame(eventName: string, line: Buffer, rec: Record<string, unknown>): Buffer {
    return buildSyslogFrame(
      {
        facility: this.cfg.facility,
        format: this.cfg.format,
        appName: this.cfg.appName,
        hostname: this.cfg.hostname,
        productVersion: this.cfg.productVersion,
        now: this.cfg.now,
        transport: this.cfg.transport,
      },
      eventName,
      line,
      rec
    );
  }

  private udpSocket(): UdpSocket {
    if (this.udp === null) {
      const sock = createSocket("udp4");
      sock.on("error", () => {
        // Send-path errors surface per-attempt via the send callback;
        // a socket-level error just means this socket is done.
        try {
          sock.close();
        } catch {
          // Already closed — nothing to do.
        }
        if (this.udp === sock) this.udp = null;
      });
      sock.unref();
      this.udp = sock;
    }
    return this.udp;
  }

  /** One UDP datagram. Rejects on send error or timeout. */
  private sendUdp(frame: Buffer): Promise<void> {
    const sock = this.udpSocket();
    return withTimeout(
      new Promise<void>((resolve, reject) => {
        sock.send(frame, 0, frame.length, this.cfg.port, this.cfg.host, (err) => {
          if (err) reject(err);
          else resolve();
        });
      }),
      this.cfg.sendTimeoutMs,
      `syslog sink: UDP send to ${this.cfg.host}:${this.cfg.port}`
    );
  }

  private dropTcp(): void {
    const sock = this.tcp;
    this.tcp = null;
    if (sock !== null) {
      sock.removeAllListeners();
      try {
        sock.destroy();
      } catch {
        // Already destroyed — nothing to do.
      }
    }
  }

  /** A connected TCP socket, establishing one when needed. Never throws spuriously: rejects on failure. */
  private tcpSocket(): Promise<TcpSocket> {
    const live = this.tcp;
    if (live !== null && !live.destroyed && !live.pending) return Promise.resolve(live);
    if (this.tcpConnect === null) {
      this.tcpConnect = this.connectTcp().then(
        (sock) => {
          this.tcpConnect = null;
          return sock;
        },
        (err) => {
          this.tcpConnect = null;
          throw err;
        }
      );
    }
    return this.tcpConnect;
  }

  /** Establish the TCP connection with a bounded connect timeout. */
  private connectTcp(): Promise<TcpSocket> {
    return new Promise<TcpSocket>((resolve, reject) => {
      const sock = createConnection({ host: this.cfg.host, port: this.cfg.port });
      const timer = setTimeout(() => {
        cleanup();
        try {
          sock.destroy();
        } catch {
          // Destroy is best-effort here.
        }
        reject(new Error(`syslog sink: TCP connect to ${this.cfg.host}:${this.cfg.port} timed out after ${this.cfg.connectTimeoutMs}ms`));
      }, this.cfg.connectTimeoutMs);
      timer.unref();
      const cleanup = (): void => {
        clearTimeout(timer);
        sock.removeListener("error", onError);
        sock.removeListener("connect", onConnect);
      };
      const onError = (err: Error): void => {
        cleanup();
        reject(err);
      };
      const onConnect = (): void => {
        cleanup();
        // Any later socket error drops the connection: the next send
        // reconnects. (Octet counting needs an intact stream.)
        sock.on("error", () => this.dropTcp());
        sock.on("close", () => {
          if (this.tcp === sock) this.tcp = null;
        });
        this.tcp = sock;
        if (this.stopRequested) {
          // Connected while stopping: tear it down at once, never leak.
          this.dropTcp();
          reject(new Error("syslog sink: stopping"));
          return;
        }
        resolve(sock);
      };
      sock.once("error", onError);
      sock.once("connect", onConnect);
    });
  }

  /** One RFC 5425 octet-counted frame. Rejects on write error or timeout. */
  private sendTcp(frame: Buffer): Promise<void> {
    return withTimeout(
      (async () => {
        const sock = await this.tcpSocket();
        if (this.stopRequested) throw new Error("syslog sink: stopping");
        const payload = Buffer.concat([Buffer.from(`${frame.length} `, "utf8"), frame]);
        await new Promise<void>((resolve, reject) => {
          const onErr = (err: Error): void => {
            sock.removeListener("error", onErr);
            reject(err);
          };
          sock.once("error", onErr);
          sock.write(payload, (werr) => {
            sock.removeListener("error", onErr);
            if (werr) reject(werr);
            else resolve();
          });
        });
      })(),
      this.cfg.sendTimeoutMs,
      `syslog sink: TCP send to ${this.cfg.host}:${this.cfg.port}`
    );
  }

  /**
   * Record an undeliverable event as an `audit_sink_dead_letter` audit
   * event (the compliance record of the gap), count it, and let the
   * cursor move past it. The line itself is never forwarded — by this
   * sink or the webhook one, which skips the same event name.
   */
  private deadLetter(eventName: string, attempts: number, lastError: string): void {
    this.deadLetters++;
    const entry: Record<string, unknown> = {
      event: AUDIT_SINK_DEAD_LETTER_EVENT,
      eventName,
      sink: "syslog",
      sinkHost: this.cfg.host,
      sinkPort: this.cfg.port,
      transport: this.cfg.transport,
      format: this.cfg.format,
      attempts,
      lastError,
    };
    try {
      this.auditLog.append(entry);
    } catch (err) {
      // Losing the dead-letter record is bad, but spinning on a broken
      // log is worse: the counter still reports the loss.
      process.stderr.write(`syslog sink: dead-letter append failed: ${(err as Error).message}\n`);
    }
  }

  /** Sleep that resolves false when the sink stops mid-wait. Unref'd: never pins exit. */
  private sleepInterruptible(ms: number): Promise<boolean> {    if (this.stopRequested) return Promise.resolve(false);
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
