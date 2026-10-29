/**
 * Mailjet email notification delivery sink (WR-261).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's inbox. Where the generic email
 * sink (WR-233) delivers through an injected SMTP client
 * and the Postmark sink (WR-258) delivers through the
 * Postmark Email HTTP API, this sink delivers through
 * the Mailjet Send API: one event is sent as one
 * email, and Mailjet — not the relay — owns the mailbox,
 * the delivery, and the retention of the message.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Mailjet
 * server. The sink owns the relay-side concerns — message
 * targeting, subject and body derivation, payload-inclusion
 * policy, per-message failure mapping — and the injected
 * client owns the wire protocol, including the POST call,
 * the authentication, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://api.mailjet.com/v3.1/send",
 *     body: "{\"Messages\":[{\"From\":{\"Email\":\"<from>\"},\"To\":[{\"Email\":\"<to>\"}],\"Subject\":\"<subject>\",\"TextPart\":\"<text>\"}]}" }
 *
 * The client POSTs to that fixed URL, sending `body`
 * verbatim as the request body (a JSON object) and
 * authenticating with HTTP Basic auth over its own API
 * key and secret, which it alone holds. Two things about
 * this shape are deliberate, and both follow the sibling
 * sinks:
 *
 * - The credentials are held by the client alone. The sink
 *   never receives them, never places them in the request,
 *   and never logs them: like the Postmark sink (WR-258),
 *   whose server token the client alone holds, this sink's
 *   request carries no credential at all — the client adds
 *   the Basic `Authorization` header from the key and secret
 *   it alone holds, so there is nothing in the request for a
 *   log line or a retry queue to leak. This is the opposite
 *   of the Vonage sink (WR-252), whose credentials ride
 *   inside the request body: Mailjet authenticates by
 *   header, so the body carries only routing and content.
 * - The host is fixed, not configurable: Mailjet is a
 *   single hosted service, so there is no self-hosted
 *   deployment to point at — unlike the generic email
 *   sink, whose SMTP client varies, a configurable URL
 *   here could only misroute a message to a server that
 *   is not Mailjet.
 *
 * This sink is orthogonal to the Mailgun sink (WR-256):
 * Mailgun posts a form body to a domain-scoped path with
 * Basic auth, while Mailjet posts a JSON `Messages` array
 * to one fixed endpoint. It is likewise distinct from
 * WR-253/WR-254/WR-258/WR-259: SendGrid and Resend use
 * Bearer tokens, Postmark a server-token header, and
 * SparkPost a bare-key header, each with its own envelope;
 * Mailjet uses Basic auth and the `Messages` array envelope.
 *
 * The sender and the recipient are configured, not
 * derived from the event. One sink targets one sender
 * address and one recipient address. A missing sender or
 * recipient is a config error, not a resolution fallback:
 * unlike the broker sinks, there is no per-record target
 * to resolve to, so a sink with no recipient has nowhere
 * to deliver and fails closed with
 * `MailjetSinkConfigError` at send time (dry runs
 * excepted — they need no addresses at all, mirroring the
 * sibling sinks' dry-run exemption for the client).
 *
 * Message text — derived from the event's own values,
 * split across the envelope's two text fields. The
 * subject takes the first non-empty value among `subject`
 * and `key`, in that order: the subject is what the event
 * is about, the key (e.g. aggregate id) is the next most
 * identifying value. The text takes the first non-empty
 * value among `subject`, `key`, and `traceId`, in that
 * order — the trace id names the trace that produced the
 * event, and it belongs in the body even though it is too
 * opaque for a subject line. An event with none of the
 * values still notifies, with the generic summary
 * `webhook event` in both fields: a notification sink
 * that silently dropped sourceless events would hide
 * exactly the deliveries an operator most needs to see,
 * and the recipient address — not the text — is the
 * delivery contract here, so no invented target is at
 * stake.
 *
 * Payload inclusion — by default the message carries the
 * summary only, never the full payload: event bodies
 * routinely carry PII, secrets, or customer data, and an
 * inbox is a far wider audience than a queue or a stream.
 * Opting into `includePayload` appends the body verbatim
 * after a blank line, truncated to `payloadMaxChars`
 * characters (default 2000) with a truncation marker —
 * the opt-in is explicit, and the truncation is
 * unconditional, so even an opted-in body cannot flood an
 * inbox. The body is appended as plain text inside the
 * `TextPart` field, not a fenced code block: the field is
 * already plain text, and a fence around an already-JSON
 * body would be noise in an inbox.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over HTTP status:
 *
 * - a non-2xx POST throws `MailjetSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Mailjet could
 *   not accept the message right now, not that the
 *   payload is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (unknown address, invalid body, bad API
 *   key): retrying them burns the retry budget for
 *   nothing, and rerouting them elsewhere would email an
 *   address the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client, sender, or recipient
 *   throws `MailjetSinkConfigError`, which
 *   `classifyFailure` maps to `non_retryable` (the WR-116
 *   rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for a text field. */
export const MAILJET_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const MAILJET_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Fixed Mailjet Send API endpoint for every message. */
export const MAILJET_SEND_URL = "https://api.mailjet.com/v3.1/send";

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (a JSON object with a `Messages`
 * array) to the fixed Send endpoint, and authenticates
 * with HTTP Basic auth over an API key and secret it alone
 * holds. The sink never sees those credentials, so the
 * request carries no credential: nothing here can leak
 * into a log line.
 */
export interface MailjetMessagePostRequest {
  /** Always the fixed Mailjet Send endpoint. */
  url: string;
  /** The JSON message object, serialized: `Messages` with `From`, `To`, `Subject`, `TextPart`. */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse Mailjet's response body.
 */
export interface MailjetMessagePostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
}

/**
 * The injected Mailjet message client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one message per call, sending
 * `body` verbatim as the request body (the JSON object
 * with the `Messages` array), setting the
 * `application/json` content type, and authenticating with
 * HTTP Basic auth over its own API key and secret — which
 * the sink never sees.
 */
export interface MailjetMessageClient {
  post(request: MailjetMessagePostRequest): Promise<MailjetMessagePostResponse>;
}

/**
 * Configuration for one Mailjet sink. The client is
 * injected: without one, `send()` throws
 * `MailjetSinkConfigError` (dry runs excepted — they need
 * no client at all). A missing sender or recipient is
 * likewise a config error at send time (dry runs
 * excepted): there is no per-record target to fall back
 * to. The API key and secret are deliberately absent from
 * this config: the client alone holds them and sends them
 * as the Basic `Authorization` header.
 */
export interface MailjetSinkConfig {
  /**
   * The sender address (`from`): the address every
   * message appears to come from. Must be a non-empty
   * string, free of NUL and whitespace, when set; a missing
   * sender throws `MailjetSinkConfigError` at send time.
   */
  from?: string;
  /**
   * The recipient address (the single entry of `to`): the
   * recipient of every message from this sink. Must be a
   * non-empty string, free of NUL and whitespace, when set;
   * a missing recipient throws `MailjetSinkConfigError` at
   * send time.
   */
  to?: string;
  /**
   * The Mailjet message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `MailjetMessageClient` and alone holds the
   * API key and secret. Required for real sends; a missing
   * client is a config error, not a silent no-op.
   */
  client?: MailjetMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including text derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The sender, recipient, and client are not required in
   * dry-run mode, mirroring the sibling sinks' dry-run
   * exemption.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the text appends
   * the event body verbatim after a blank line, truncated to
   * `payloadMaxChars` characters (see below). When `false`
   * or absent, the message carries the summary only — the
   * default, so event bodies (which routinely carry PII)
   * never leak into a notification unless the operator
   * explicitly asks for them.
   */
  includePayload?: boolean;
  /**
   * Truncation limit for an opted-in payload snippet, in
   * characters (default 2000). Only meaningful with
   * `includePayload`; the truncation is unconditional when
   * the opt-in is set, so an opted-in body cannot flood an
   * inbox. Must be a positive integer when set.
   */
  payloadMaxChars?: number;
}

/** One event to notify about. */
export interface MailjetRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Text-derivation source, first priority: the event's
   * subject, when set and non-empty. Falls through to `key`
   * for the subject, and to `key`, then `traceId`, for the
   * text.
   */
  subject?: string;
  /**
   * Text-derivation source, second priority: the event's key
   * (e.g. aggregate id).
   */
  key?: string;
  /**
   * Text-derivation source, last priority for the text:
   * the trace id. Never used for the subject — too
   * opaque for a subject line.
   */
  traceId?: string;
}

/** One failed message, with its retry lane already mapped. */
export interface MailjetFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /** Failure code: `HTTP_<status>` for a non-2xx POST, or `TRANSPORT_ERROR` for a codeless failure. */
  errorCode: string;
  /** Downstream HTTP status, when the failure was a non-2xx POST. */
  statusCode?: number;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: 429 and 5xx (plus
   * codeless transport failures) are retryable, every other
   * non-2xx status is a fail-closed message (unknown address,
   * invalid body, bad API key).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface MailjetSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-261). */
export interface MailjetSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Mailjet send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on Mailjet's server and are *not* in
 * `failedRecords`.
 */
export class MailjetSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: MailjetFailedRecord[];
  constructor(message: string, failedRecords: MailjetFailedRecord[]) {
    super(message);
    this.name = "MailjetSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, or the sender or recipient is
 * missing. A config problem, not a downstream verdict, so
 * the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class MailjetSinkConfigError extends MailjetSinkError {
  constructor(reason: string) {
    super(`mailjet-sink: ${reason}`, []);
    this.name = "MailjetSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing sender or recipient is *not* a shape error: it is a
 * config error raised at send time
 * (`MailjetSinkConfigError`), so a sink built before its
 * addresses are known still fails closed at send time rather
 * than crashing at construction. A present address must be a
 * non-empty string, free of NUL and whitespace.
 */
export function assertValidMailjetSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is MailjetSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  for (const field of ["from", "to"] as const) {
    const value = c[field];
    if (value !== undefined) {
      if (
        typeof value !== "string" ||
        value === "" ||
        (value as string).includes("\0") ||
        /\s/.test(value as string)
      ) {
        throw new RangeError(
          at(`\`${field}\` must be a non-empty string, free of NUL and whitespace when set`)
        );
      }
    }
  }
  if (
    c.client !== undefined &&
    (c.client === null ||
      typeof c.client !== "object" ||
      typeof (c.client as { post?: unknown }).post !== "function")
  ) {
    throw new RangeError(at("`client` must expose a `post` function when set"));
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
 * Derive one record's subject: the first non-empty value
 * among `subject` and `key`, in that order. Falls back to
 * the generic `webhook event` summary when the record
 * carries neither — the envelope always needs a subject,
 * and a notification sink must not silently drop sourceless
 * events. The trace id is deliberately not a subject
 * source: it is too opaque for a subject line, and belongs
 * in the text instead.
 */
export function resolveMailjetSubject(record: MailjetRecord): string {
  for (const value of [record.subject, record.key]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return MAILJET_FALLBACK_SUMMARY;
}

/**
 * Derive one record's text: the first non-empty
 * value among `subject`, `key`, and `traceId`, in that
 * order. Falls back to the generic `webhook event` summary
 * when the record carries none — a notification sink must
 * not silently drop sourceless events, and the recipient
 * address (not the text) is the delivery contract.
 */
export function resolveMailjetText(record: MailjetRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return MAILJET_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood an inbox.
 */
export function truncateMailjetPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's notification: its subject and its
 * text. Only under the `includePayload` opt-in
 * does the text append the event body verbatim after a
 * blank line, truncated to `payloadMaxChars` (default
 * 2000). Without the opt-in, the text is the summary
 * alone: event bodies routinely carry PII and must never
 * leak into a notification by default. The body is
 * appended as plain text inside the `TextPart` field, not a
 * fenced code block.
 */
export function resolveMailjetNotification(
  record: MailjetRecord,
  config: Pick<MailjetSinkConfig, "includePayload" | "payloadMaxChars">
): { subject: string; text: string } {
  const subject = resolveMailjetSubject(record);
  let text = resolveMailjetText(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? MAILJET_DEFAULT_PAYLOAD_MAX_CHARS;
    text = `${text}\n\n${truncateMailjetPayload(record.body, limit)}`;
  }
  return { subject, text };
}

/**
 * Build one record's serialized request body: the JSON
 * object with a `Messages` array holding one message with
 * `From: { Email }`, `To: [{ Email }]`, `Subject`, and
 * `TextPart`, in that order. Neither the API key nor the
 * secret ever appears here — both are held by the client
 * alone and travel as the Basic `Authorization` header.
 */
export function buildMailjetMessageBody(from: string, to: string, subject: string, text: string): string {
  return JSON.stringify({
    Messages: [{ From: { Email: from }, To: [{ Email: to }], Subject: subject, TextPart: text }],
  });
}

/**
 * Validate one record's body and resolve its send form: the
 * notification subject and text. Throws `RangeError` on an
 * empty body string — even without the opt-in, the body is
 * the record's payload, and an empty record is a caller bug
 * that must fail closed, never notify as an empty message.
 */
export function resolveMailjetRecord(
  record: MailjetRecord,
  index: number,
  config: Pick<MailjetSinkConfig, "includePayload" | "payloadMaxChars">
): { notification: { subject: string; text: string }; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`mailjet-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { notification: resolveMailjetNotification(record, config), index };
}

/**
 * Map one Mailjet POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says Mailjet could not
 * accept the message right now, not that the payload is
 * poison. Every other non-2xx status (400, 401, 403, 404,
 * and the rest) is a fail-closed message: unknown address,
 * invalid body, bad API key, or another verdict retrying
 * cannot change. Callers only pass non-2xx statuses here;
 * a 2xx status is a success, not a failure.
 */
export function classifyMailjetRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Mailjet sink (WR-261). One instance targets one sender
 * address and one recipient address; the caller owns
 * retry/dead-letter policy around `send()` — this class
 * performs one POST attempt per message through the
 * injected client and reports its outcome. Failures
 * throw `MailjetSinkError` carrying exactly the failed
 * messages with their retry lanes.
 */
export class MailjetSink {
  private readonly cfg: MailjetSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: MailjetSinkConfig) {
    assertValidMailjetSinkConfig(config, "MailjetSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): MailjetSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages by email, in input order. Throws
   * `MailjetSinkConfigError` when no client was injected or
   * the sender or recipient is missing, and
   * `MailjetSinkError` when any message fails (carrying
   * exactly the failed messages with their retry lanes; both
   * counted in stats before throwing, so the counters stay
   * honest even for callers that only inspect stats).
   */
  async send(records: MailjetRecord[]): Promise<MailjetSendResult> {
    const resolved = records.map((r, i) => resolveMailjetRecord(r, i, this.cfg));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The
      // sender, recipient, and client are not required here,
      // mirroring the sibling sinks' dry-run exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new MailjetSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const from = this.cfg.from;
    if (from === undefined) {
      throw new MailjetSinkConfigError("no sender configured (set `from` in the sink config)");
    }
    const to = this.cfg.to;
    if (to === undefined) {
      throw new MailjetSinkConfigError("no recipient configured (set `to` in the sink config)");
    }
    const failedRecords: MailjetFailedRecord[] = [];
    let sent = 0;
    for (const record of resolved) {
      try {
        const response = await client.post({
          url: MAILJET_SEND_URL,
          body: buildMailjetMessageBody(from, to, record.notification.subject, record.notification.text),
        });
        if (response.status >= 200 && response.status < 300) {
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyMailjetRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toMailjetFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new MailjetSinkError(
        `mailjet-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent };
  }
}

/**
 * Convert a client throw into a failed message: a codeless
 * transport failure (`TRANSPORT_ERROR`, retryable — the SQS
 * no-status rule).
 */
function toMailjetFailedRecord(err: unknown, index: number): MailjetFailedRecord {
  const failed: MailjetFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
