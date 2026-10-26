/**
 * Email notification delivery sink (WR-233).
 *
 * Some downstreams are not queues, streams, or topics at all:
 * they are a human's mailbox. Where the SQS sink (WR-210)
 * delivers to an unordered queue, the Kinesis sink (WR-213)
 * delivers to an AWS SigV4 stream, the Kafka sink (WR-215)
 * delivers to a partitioned log, the MQTT sink (WR-216)
 * delivers to a pub/sub topic tree, the AMQP sink (WR-217)
 * delivers to an exchange, the JetStream sink (WR-218) delivers
 * to a durable stream over the native JetStream publish
 * protocol, the Redis sink (WR-219) delivers to a Redis stream
 * with XADD, the Pub/Sub sink (WR-220) delivers to a Google
 * Cloud topic with pass-through attributes, the Service Bus
 * sink (WR-221) delivers to an Azure queue or topic with
 * pass-through properties, the EventBridge sink (WR-222)
 * delivers to an AWS event bus with a resolved DetailType, the
 * Pulsar sink (WR-223) delivers to an Apache Pulsar topic, the
 * SNS sink (WR-224) delivers to an AWS SNS topic, the Event
 * Hubs sink (WR-225) delivers to an Azure event hub, the Slack
 * sink (WR-226) delivers to a Slack channel, the DingTalk sink
 * (WR-228) delivers to a DingTalk group, the Feishu sink
 * (WR-229) delivers to a Feishu group, the Telegram sink
 * (WR-231) delivers to a Telegram chat, and the Discord sink
 * (WR-232) delivers to a Discord channel, this sink delivers
 * to a mailbox: one event is sent as one email to a configured
 * recipient, and the mail server — not the relay — owns the
 * mailbox, the message id, and the retention of the
 * notification. The sinks are orthogonal — queue delivery for
 * unordered work, stream delivery for AWS-ordered work, log
 * delivery for broker-native ordered work, topic-tree delivery
 * for broker-mediated fan-out, exchange delivery for
 * broker-mediated routing, durable-stream delivery for
 * replayable work, Redis-stream delivery for in-memory ordered
 * work, Pub/Sub delivery for cloud-managed fan-out, Service Bus
 * delivery for Azure-managed fan-out, EventBridge delivery for
 * rule-routed cloud events, Pulsar delivery for geo-replicated
 * partitioned topics, SNS delivery for cloud-managed fan-out to
 * many protocols at once, Event Hubs delivery for Azure-managed
 * streaming ingest, Slack delivery for human notification on
 * Slack, DingTalk delivery for human notification on DingTalk,
 * Feishu delivery for human notification on Feishu, Telegram
 * delivery for human notification on Telegram, Discord delivery
 * for human notification on Discord, email delivery for human
 * notification by mail — and an email delivery can still be
 * archived by the S3 offloaders like any other delivery.
 *
 * No real SMTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever SMTP
 * the operator runs — a library, a sidecar), so the module has
 * zero new dependencies and tests never need a mailbox. The
 * sink owns the relay-side concerns — recipient targeting,
 * subject and body derivation, payload-inclusion policy,
 * per-message failure mapping — and the injected client owns
 * the wire protocol, including the SMTP conversation and the
 * reply code it reports.
 *
 * Wire shape — one send per message, carried to the injected
 * client as:
 *
 *   { to: "<configured recipient>",
 *     subject: "<event subject>",
 *     text: "<derived message body>" }
 *
 * The client wraps this into a MIME message and runs the SMTP
 * conversation (including authentication, which it holds —
 * credentials never appear in the sink's request objects, the
 * message text, or the sink's config, so rotating them is a
 * client-side change and a credential that never crosses the
 * sink boundary cannot leak through a sink log, a dry run, or
 * a failed-record report). The sender address, if any, is
 * likewise the client's: the sink addresses only the
 * recipient.
 *
 * Recipient targeting — one sink targets one recipient:
 * every message goes there. A missing recipient is a config
 * error, not a resolution fallback: unlike the broker sinks,
 * there is no per-record channel to resolve to, so a sink with
 * no recipient has nowhere to deliver and fails closed with
 * `EmailSinkConfigError` at send time (dry runs excepted —
 * they need no recipient at all, mirroring the sibling sinks'
 * dry-run exemption for the client).
 *
 * Subject and body — unlike the chat sinks, which carry one
 * line of text, an email has two fields, and the event's
 * values split across them: the subject is the event's
 * `subject` (falling back to the generic `webhook event` when
 * the event carries none — an email with an empty subject
 * hides in an inbox, and a notification sink must not hide
 * deliveries), and the body is a one-line summary derived
 * from the event's own values, first non-empty wins: `key`,
 * then `traceId` — the same source chain the chat sinks use
 * for their message text, minus the subject, which already
 * occupies the subject line. An event with neither key nor
 * trace id still notifies, with the generic summary `webhook
 * event` as its body: a notification sink that silently
 * dropped sourceless events would hide exactly the deliveries
 * an operator most needs to see, and the recipient — not the
 * body — is the delivery contract here, so no invented
 * recipient is at stake.
 *
 * Payload inclusion — by default the body carries the summary
 * only, never the full payload: event bodies routinely carry
 * PII, secrets, or customer data, and a mailbox is a far wider
 * audience than a queue or a stream. Opting into
 * `includePayload` appends the body verbatim inside a fenced
 * code block, truncated to `payloadMaxChars` characters
 * (default 2000) with a truncation marker — the opt-in is
 * explicit, and the truncation is unconditional, so even an
 * opted-in body cannot flood a mailbox.
 *
 * Failure handling — SMTP reply codes, not HTTP statuses,
 * decide the retry lane, because an SMTP conversation has no
 * HTTP status to map. The shape mirrors the WR-210 SQS
 * sink's classification (`src/failure.ts`), applied per
 * message over the reply code the client reports:
 *
 * - a non-2xx reply throws `EmailSinkError` carrying every
 *   failed message with its retry lane already mapped, so the
 *   caller retries exactly the failed messages;
 * - retryable replies are the transient SMTP states — every
 *   4xx code (mailbox full, greylisting, temporary server
 *   failure): a transient refusal says the server could not
 *   accept the message right now, not that the message is
 *   poison;
 * - non-retryable replies are the fail-closed messages —
 *   every 5xx code, including authentication failures (530,
 *   535) and unknown recipients (550, 553): retrying them
 *   burns the retry budget for nothing, and rerouting them
 *   elsewhere would notify a recipient the operator never
 *   chose;
 * - a codeless transport failure (the client threw with no
 *   SMTP code) is retryable, like an SQS transport error with
 *   no status: it says nothing about the message — but a
 *   throw that does carry an SMTP code is classified by that
 *   code, so an authentication failure raised as a throw
 *   (535) is still fail-closed, not silently retried;
 * - a missing client or a missing recipient throws
 *   `EmailSinkConfigError`, which `classifyFailure` maps to
 *   `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no subject, key, or trace id. */
export const EMAIL_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const EMAIL_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/**
 * One send request as handed to the injected client. The
 * client owns the wire protocol (including the SMTP
 * conversation, authentication, the sender address, and the
 * reply code it reports); this shape is the relay-side
 * contract it must honour. Credentials deliberately appear
 * nowhere here: the client holds them, so they cannot leak
 * through a sink log or a dry run.
 */
export interface EmailSendRequest {
  /** Target recipient, exactly as configured. */
  to: string;
  /** The derived subject (the event's subject, or the generic fallback). */
  subject: string;
  /** The derived message body (summary, plus an opted-in payload snippet). */
  text: string;
}

/**
 * The result of one send, as reported by the injected client.
 * Only the SMTP reply code matters to the sink's retry
 * mapping; the client need not parse the server's reply text.
 */
export interface EmailSendResponse {
  /** The SMTP reply code of the send (e.g. 250, 450, 550). */
  status: number;
}

/**
 * The injected SMTP client. Any client adapter implements
 * this one method; it returns the send's SMTP reply code (a
 * throw with no SMTP code is a codeless transport failure,
 * retryable; a throw carrying an SMTP code is classified by
 * that code). The client is expected to send one message per
 * call, wrapping `to`/`subject`/`text` into a MIME message
 * and running the SMTP conversation with the credentials it
 * holds.
 */
export interface EmailSmtpClient {
  send(request: EmailSendRequest): Promise<EmailSendResponse>;
}

/**
 * Configuration for one email sink. The client is injected:
 * without one, `send()` throws `EmailSinkConfigError` (dry
 * runs excepted — they need no client at all). A missing
 * recipient is likewise a config error at send time (dry runs
 * excepted): there is no per-record channel to fall back to.
 */
export interface EmailSinkConfig {
  /**
   * Target recipient, e.g. `"ops@example.com"`. Must be a
   * non-empty string, free of NUL and whitespace, when set;
   * a missing recipient throws `EmailSinkConfigError` at
   * send time, never a silent no-op. The sink does not
   * validate the address shape beyond that: the SMTP client
   * owns address validation, like the chat sinks' clients
   * own their channel formats.
   */
  to?: string;
  /**
   * The SMTP client to deliver through. Injected, never
   * bundled: the operator's client adapter implements
   * `EmailSmtpClient` and holds the SMTP credentials.
   * Required for real sends; a missing client is a config
   * error, not a silent no-op.
   */
  client?: EmailSmtpClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no send call, no stat changes. Messages are
   * still validated (including subject/body derivation), so a
   * dry run catches a malformed record before it reaches
   * production. Mirrors the `dryRun` convention of the S3
   * offloaders. The recipient and client are not required in
   * dry-run mode, mirroring the sibling sinks' dry-run
   * exemption.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the message body appends the
   * event body verbatim inside a fenced code block, truncated
   * to `payloadMaxChars` characters (see below). When `false`
   * or absent, the body carries the summary only — the
   * default, so event bodies (which routinely carry PII) never
   * leak into a mailbox unless the operator explicitly asks
   * for them.
   */
  includePayload?: boolean;
  /**
   * Truncation limit for an opted-in payload snippet, in
   * characters (default 2000). Only meaningful with
   * `includePayload`; the truncation is unconditional when
   * the opt-in is set, so an opted-in body cannot flood a
   * mailbox. Must be a positive integer when set.
   */
  payloadMaxChars?: number;
}

/** One event to notify about. */
export interface EmailRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Subject-derivation source: the event's subject, when set
   * and non-empty. Falls back to the generic summary when
   * absent — an email subject must never be empty.
   */
  subject?: string;
  /**
   * Body-derivation source, first priority: the event's key
   * (e.g. aggregate id).
   */
  key?: string;
  /**
   * Body-derivation source, last priority: the trace id.
   */
  traceId?: string;
}

/** One record as it goes to the client (subject and body derived). */
export interface EmailResolvedRecord {
  /** Target recipient, exactly as configured. */
  to: string;
  /** The derived subject. */
  subject: string;
  /** The derived message body (summary, plus an opted-in payload snippet). */
  text: string;
  /** Index into the caller's original `records` array. */
  index: number;
}

/** One failed message, with its retry lane already mapped. */
export interface EmailFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /** Failure code: `SMTP_<code>` for a non-2xx reply, or `TRANSPORT_ERROR` for a codeless failure. */
  errorCode: string;
  /** Downstream SMTP reply code, when the failure carried one. */
  statusCode?: number;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the SMTP mapping: 4xx (plus codeless
   * transport failures) are retryable, every 5xx — including
   * authentication failures — is a fail-closed message.
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface EmailSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-233). */
export interface EmailSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for email send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already in their mailbox and are *not* in
 * `failedRecords`.
 */
export class EmailSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: EmailFailedRecord[];
  constructor(message: string, failedRecords: EmailFailedRecord[]) {
    super(message);
    this.name = "EmailSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, or the recipient is missing. A config
 * problem, not a downstream verdict, so the retry queue must
 * not burn attempts on it (`classifyFailure` maps it to
 * `non_retryable`).
 */
export class EmailSinkConfigError extends EmailSinkError {
  constructor(reason: string) {
    super(`email-sink: ${reason}`, []);
    this.name = "EmailSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing recipient is *not* a shape error: it is a config
 * error raised at send time (`EmailSinkConfigError`), so a
 * sink built before its recipient is known still fails closed
 * at send time rather than crashing at construction. A present
 * recipient must be a non-empty string, free of NUL and
 * whitespace; the `client`, when present, must expose `send`.
 */
export function assertValidEmailSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is EmailSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  if (c.to !== undefined) {
    if (
      typeof c.to !== "string" ||
      c.to === "" ||
      (c.to as string).includes("\0") ||
      /\s/.test(c.to as string)
    ) {
      throw new RangeError(
        at("`to` must be a non-empty string, free of NUL and whitespace when set")
      );
    }
  }
  if (
    c.client !== undefined &&
    (c.client === null ||
      typeof c.client !== "object" ||
      typeof (c.client as { send?: unknown }).send !== "function")
  ) {
    throw new RangeError(at("`client` must expose a `send` function when set"));
  }
  if (
    c.payloadMaxChars !== undefined &&
    (typeof c.payloadMaxChars !== "number" ||
      !Number.isInteger(c.payloadMaxChars) ||
      c.payloadMaxChars <= 0)
  ) {
    throw new RangeError(at("`payloadMaxChars` must be a positive integer when set"));
  }
}

/**
 * Derive one record's subject: the event's subject when set
 * and non-empty, else the generic `webhook event` summary —
 * an email subject must never be empty, and a notification
 * sink must not hide deliveries behind a blank subject line.
 */
export function resolveEmailSubject(record: EmailRecord): string {
  if (record.subject !== undefined && record.subject !== "") {
    return record.subject;
  }
  return EMAIL_FALLBACK_SUMMARY;
}

/**
 * Derive one record's body summary: the first non-empty value
 * among `key` and `traceId`, in that order — the subject
 * already occupies the subject line, so it does not repeat
 * here. Falls back to the generic `webhook event` summary
 * when the record carries neither — a notification sink must
 * not silently drop sourceless events, and the recipient (not
 * the body) is the delivery contract.
 */
export function resolveEmailSummary(record: EmailRecord): string {
  for (const value of [record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return EMAIL_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a mailbox.
 */
export function truncateEmailPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's message body: the summary, plus — only
 * under the `includePayload` opt-in — the body verbatim
 * inside a fenced code block, truncated to `payloadMaxChars`
 * (default 2000). Without the opt-in, the body is the summary
 * alone: event bodies routinely carry PII and must never leak
 * into a mailbox by default.
 */
export function resolveEmailText(
  record: EmailRecord,
  config: Pick<EmailSinkConfig, "includePayload" | "payloadMaxChars">
): string {
  const summary = resolveEmailSummary(record);
  if (config.includePayload !== true) {
    return summary;
  }
  const limit = config.payloadMaxChars ?? EMAIL_DEFAULT_PAYLOAD_MAX_CHARS;
  return `${summary}\n\`\`\`\n${truncateEmailPayload(record.body, limit)}\n\`\`\``;
}

/**
 * Validate one record's body and resolve its send form: the
 * subject derives from the record's subject, the body from
 * its key or trace id (plus an opted-in payload snippet).
 * Throws `RangeError` on an empty body string — even without
 * the opt-in, the body is the record's payload, and an empty
 * record is a caller bug that must fail closed, never notify
 * as an empty message.
 */
export function resolveEmailRecord(
  record: EmailRecord,
  index: number,
  config: Pick<EmailSinkConfig, "includePayload" | "payloadMaxChars">
): { subject: string; text: string; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`email-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { subject: resolveEmailSubject(record), text: resolveEmailText(record, config), index };
}

/**
 * Map one SMTP reply `statusCode` onto its retry lane: every
 * 4xx code is transient and so retryable — a temporary
 * refusal says the server could not accept the message right
 * now, not that the message is poison. Every 5xx code is a
 * fail-closed message: authentication failures, unknown
 * recipients, and other verdicts retrying cannot change.
 * Callers only pass non-2xx codes here; a 2xx code is a
 * success, not a failure.
 */
export function classifyEmailRecordFailure(statusCode: number): boolean {
  return statusCode >= 400 && statusCode < 500;
}

/**
 * Extract an SMTP reply code from a client throw, when the
 * throw carries one: a numeric `code` or `status` property,
 * or a numeric string in either. Returns `undefined` for a
 * codeless throw — the SQS no-status rule, retryable.
 */
export function extractSmtpCodeFromError(err: unknown): number | undefined {
  if (err === null || typeof err !== "object") {
    return undefined;
  }
  for (const field of ["code", "status"] as const) {
    const value = (err as Record<string, unknown>)[field];
    const code = typeof value === "number" ? value : typeof value === "string" ? Number(value) : NaN;
    if (Number.isInteger(code) && code >= 100 && code <= 999) {
      return code;
    }
  }
  return undefined;
}

/**
 * Email sink (WR-233). One instance targets one recipient;
 * the caller owns retry/dead-letter policy around `send()` —
 * this class performs one send attempt per message through
 * the injected client and reports its outcome. Failures throw
 * `EmailSinkError` carrying exactly the failed messages with
 * their retry lanes.
 */
export class EmailSink {
  private readonly cfg: EmailSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: EmailSinkConfig) {
    assertValidEmailSinkConfig(config, "EmailSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): EmailSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages to the configured recipient, in input
   * order. Throws `EmailSinkConfigError` when no client was
   * injected or the recipient is missing, and
   * `EmailSinkError` when any message fails (carrying
   * exactly the failed messages with their retry lanes; both
   * counted in stats before throwing, so the counters stay
   * honest even for callers that only inspect stats).
   */
  async send(records: EmailRecord[]): Promise<EmailSendResult> {
    const resolved = records.map((r, i) => resolveEmailRecord(r, i, this.cfg));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The
      // recipient and client are not required here, mirroring
      // the sibling sinks' dry-run exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new EmailSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const to = this.cfg.to;
    if (to === undefined) {
      throw new EmailSinkConfigError("no recipient configured (set `to` to the target mailbox)");
    }
    const failedRecords: EmailFailedRecord[] = [];
    let sent = 0;
    for (const record of resolved) {
      try {
        const response = await client.send({ to, subject: record.subject, text: record.text });
        if (response.status >= 200 && response.status < 300) {
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `SMTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyEmailRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toEmailFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new EmailSinkError(
        `email-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent };
  }
}

/**
 * Convert a client throw into a failed message: a throw
 * carrying an SMTP code is classified by that code (so an
 * authentication failure raised as a 535 throw is
 * fail-closed); a codeless transport failure is
 * `TRANSPORT_ERROR`, retryable — the SQS no-status rule.
 */
function toEmailFailedRecord(err: unknown, index: number): EmailFailedRecord {
  const code = extractSmtpCodeFromError(err);
  if (code !== undefined) {
    const failed: EmailFailedRecord = {
      index,
      errorCode: `SMTP_${code}`,
      statusCode: code,
      retryable: classifyEmailRecordFailure(code),
    };
    if (err instanceof Error && err.message !== "") {
      failed.errorMessage = err.message;
    }
    return failed;
  }
  const failed: EmailFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
