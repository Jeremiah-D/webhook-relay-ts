/**
 * Elastic Email notification delivery sink (WR-266).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's inbox. Where the generic email
 * sink (WR-233) delivers through an injected SMTP client
 * and the Postmark sink (WR-258) delivers through the
 * Postmark Email HTTP API, the Mailjet sink (WR-261)
 * through Mailjet's Messages array API, the Brevo sink
 * (WR-262) through Brevo's Send API, and the Mandrill
 * sink (WR-265) through Mandrill's Messages API, this
 * sink delivers through the Elastic Email transactional
 * email API: one event email, and Elastic Email — not
 * the relay — owns the mailbox, the delivery, and the
 * retention of the message.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need an Elastic
 * Email server. The sink owns the relay-side concerns —
 * message targeting, subject and body derivation,
 * payload-inclusion policy, per-message failure mapping —
 * and the injected client owns the wire protocol,
 * including the POST call, the authentication, and the
 * status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://api.elasticemail.com/v4/emails/transactional",
 *     body: "{\"Recipients\":{\"To\":[\"<to>\"]},\"Content\":{\"From\":\"<from>\",\"Subject\":\"<subject>\",\"Body\":[{\"ContentType\":\"PlainText\",\"Content\":\"<text>\"}]}}" }
 *
 * The client POSTs to that fixed URL, sending `body`
 * verbatim as the request body (a JSON object) and
 * authenticating with an `X-ElasticEmail-ApiKey` header
 * carrying an API key it alone holds. Two things about
 * this shape are deliberate, and both follow the sibling
 * sinks:
 *
 * - The credentials are held by the client alone. The sink
 *   never receives them, never places them in the request,
 *   and never logs them: like the Brevo sink (WR-262),
 *   whose `api-key` header the client alone holds, this
 *   sink's request carries no credential at all — the
 *   client adds the `X-ElasticEmail-ApiKey` header from
 *   the key it alone holds, so there is nothing in the
 *   request for a log line or a retry queue to leak. This
 *   is the opposite of the Mandrill sink (WR-265), whose
 *   key rides inside the wire body: Elastic Email
 *   authenticates by header, so the body carries only
 *   routing and content.
 * - The host is fixed, not configurable: Elastic Email is
 *   a single hosted service, so there is no self-hosted
 *   deployment to point at — unlike the generic email
 *   sink, whose SMTP client varies, a configurable URL
 *   here could only misroute a message to a server that
 *   is not Elastic Email.
 *
 * This sink is orthogonal to the Brevo sink (WR-262):
 * Brevo posts a flat `sender`/`to` envelope with an
 * `api-key` header, while Elastic Email posts a
 * `Recipients`/`Content`/`Body` array envelope with an
 * `X-ElasticEmail-ApiKey` header. It is likewise distinct
 * from WR-261 (Mailjet): Mailjet posts a JSON `Messages`
 * array with Basic auth, while Elastic Email posts to a
 * dedicated transactional endpoint with a dedicated key
 * header.
 *
 * The sender and the recipient are configured, not
 * derived from the event. One sink targets one sender
 * address and one recipient address. A missing sender or
 * recipient is a config error, not a resolution fallback:
 * unlike the broker sinks, there is no per-record target
 * to resolve to, so a sink with no recipient has nowhere
 * to deliver and fails closed with
 * `ElasticEmailSinkConfigError` at send time (dry runs
 * excepted — they need no addresses at all, mirroring the
 * sibling sinks' dry-run exemption for the client).
 *
 * Message text — derived from the event's own values,
 * split across the envelope's two text fields. The
 * subject takes the first non-empty value among `subject`
 * and `key`, in that order: the subject is what the event
 * is about, the key (e.g. aggregate id) is the next most
 * identifying value. The content takes the first
 * non-empty value among `subject`, `key`, and `traceId`,
 * in that order — the trace id names the trace that
 * produced the event, and it belongs in the body even
 * though it is too opaque for a subject line. An event
 * with none of the values still notifies, with the
 * generic summary `webhook event` in both fields: a
 * notification sink that silently dropped sourceless
 * events would hide exactly the deliveries an operator
 * most needs to see, and the recipient address — not the
 * text — is the delivery contract here, so no invented
 * target is at stake.
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
 * `Content` field, not a fenced code block: the field is
 * already plain text, and a fence around an already-JSON
 * body would be noise in an inbox.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over HTTP status:
 *
 * - a non-2xx POST throws `ElasticEmailSinkError`
 *   carrying every failed message with its retry lane
 *   already mapped, so the caller retries exactly the
 *   failed messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Elastic Email
 *   could not accept the message right now, not that the
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
 *   throws `ElasticEmailSinkConfigError`, which
 *   `classifyFailure` maps to `non_retryable` (the WR-116
 *   rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for a text field. */
export const ELASTICEMAIL_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const ELASTICEMAIL_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Fixed Elastic Email transactional email endpoint for every message. */
export const ELASTICEMAIL_SEND_URL = "https://api.elasticemail.com/v4/emails/transactional";

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (a JSON object with `Recipients`
 * and `Content`) to the fixed transactional endpoint, and
 * authenticates with an `X-ElasticEmail-ApiKey` header
 * carrying an API key it alone holds. The sink never sees
 * that key, so the handed request carries no credential:
 * nothing here can leak into a log line.
 */
export interface ElasticEmailMessagePostRequest {
  /** Always the fixed Elastic Email transactional endpoint. */
  url: string;
  /** The JSON message object, serialized: `Recipients`, `Content` with `From`, `Subject`, `Body`. */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse Elastic Email's response body.
 */
export interface ElasticEmailMessagePostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
}

/**
 * The injected Elastic Email message client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one message per call, sending
 * `body` verbatim as the request body (the JSON object
 * with `Recipients` and `Content`), setting the
 * `application/json` content type, and authenticating with
 * an `X-ElasticEmail-ApiKey` header carrying its own API
 * key — which the sink never sees.
 */
export interface ElasticEmailMessageClient {
  post(request: ElasticEmailMessagePostRequest): Promise<ElasticEmailMessagePostResponse>;
}

/**
 * Configuration for one Elastic Email sink. The client is
 * injected: without one, `send()` throws
 * `ElasticEmailSinkConfigError` (dry runs excepted — they need
 * no client at all). A missing sender or recipient is
 * likewise a config error at send time (dry runs
 * excepted): there is no per-record target to fall back
 * to. The API key is deliberately absent from this config:
 * the client alone holds it and sends it as the
 * `X-ElasticEmail-ApiKey` header.
 */
export interface ElasticEmailSinkConfig {
  /**
   * The sender address (`from`): the address every
   * message appears to come from. Must be a non-empty
   * string, free of NUL and whitespace, when set; a missing
   * sender throws `ElasticEmailSinkConfigError` at send time.
   */
  from?: string;
  /**
   * The recipient address (the single entry of `To`): the
   * recipient of every message from this sink. Must be a
   * non-empty string, free of NUL and whitespace, when set;
   * a missing recipient throws `ElasticEmailSinkConfigError` at send time.
   */
  to?: string;
  /**
   * The Elastic Email message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `ElasticEmailMessageClient` and alone holds the
   * API key. Required for real sends; a missing
   * client is a config error, not a silent no-op.
   */
  client?: ElasticEmailMessageClient;
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
   * Payload opt-in: when `true`, the content appends
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
export interface ElasticEmailRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Text-derivation source, first priority: the event's
   * subject, when set and non-empty. Falls through to `key`
   * for the subject, and to `key`, then `traceId`, for the
   * content.
   */
  subject?: string;
  /**
   * Text-derivation source, second priority: the event's key
   * (e.g. aggregate id).
   */
  key?: string;
  /**
   * Text-derivation source, last priority for the content:
   * the trace id. Never used for the subject — too
   * opaque for a subject line.
   */
  traceId?: string;
}

/** One failed message, with its retry lane already mapped. */
export interface ElasticEmailFailedRecord {
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
export interface ElasticEmailSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-266). */
export interface ElasticEmailSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Elastic Email send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on Elastic Email's server and are *not* in
 * `failedRecords`.
 */
export class ElasticEmailSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: ElasticEmailFailedRecord[];
  constructor(message: string, failedRecords: ElasticEmailFailedRecord[]) {
    super(message);
    this.name = "ElasticEmailSinkError";
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
export class ElasticEmailSinkConfigError extends ElasticEmailSinkError {
  constructor(reason: string) {
    super(`elasticemail-sink: ${reason}`, []);
    this.name = "ElasticEmailSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing sender or recipient is *not* a shape error: it is a
 * config error raised at send time
 * (`ElasticEmailSinkConfigError`), so a sink built before its
 * addresses are known still fails closed at send time rather
 * than crashing at construction. A present address must be a
 * non-empty string, free of NUL and whitespace.
 */
export function assertValidElasticEmailSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is ElasticEmailSinkConfig {
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
 * in the content instead.
 */
export function resolveElasticEmailSubject(record: ElasticEmailRecord): string {
  for (const value of [record.subject, record.key]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return ELASTICEMAIL_FALLBACK_SUMMARY;
}

/**
 * Derive one record's content: the first non-empty
 * value among `subject`, `key`, and `traceId`, in that
 * order. Falls back to the generic `webhook event` summary
 * when the record carries none — a notification sink must
 * not silently drop sourceless events, and the recipient
 * address (not the content) is the delivery contract.
 */
export function resolveElasticEmailContent(record: ElasticEmailRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return ELASTICEMAIL_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood an inbox.
 */
export function truncateElasticEmailPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's notification: its subject and its
 * content. Only under the `includePayload` opt-in
 * does the content append the event body verbatim after a
 * blank line, truncated to `payloadMaxChars` (default
 * 2000). Without the opt-in, the content is the summary
 * alone: event bodies routinely carry PII and must never
 * leak into a notification by default. The body is
 * appended as plain text inside the `Content` field, not a
 * fenced code block.
 */
export function resolveElasticEmailNotification(
  record: ElasticEmailRecord,
  config: Pick<ElasticEmailSinkConfig, "includePayload" | "payloadMaxChars">
): { subject: string; content: string } {
  const subject = resolveElasticEmailSubject(record);
  let content = resolveElasticEmailContent(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? ELASTICEMAIL_DEFAULT_PAYLOAD_MAX_CHARS;
    content = `${content}\n\n${truncateElasticEmailPayload(record.body, limit)}`;
  }
  return { subject, content };
}

/**
 * Build one record's serialized request body: the JSON
 * object with `Recipients: { To: [email] }` and
 * `Content: { From, Subject, Body: [{ ContentType:
 * "PlainText", Content }] }`, in that order. The API key
 * never appears here — the client alone holds it and
 * sends it as the `X-ElasticEmail-ApiKey` header.
 */
export function buildElasticEmailMessageBody(from: string, to: string, subject: string, content: string): string {
  return JSON.stringify({
    Recipients: { To: [to] },
    Content: {
      From: from,
      Subject: subject,
      Body: [{ ContentType: "PlainText", Content: content }],
    },
  });
}

/**
 * Validate one record's body and resolve its send form: the
 * notification subject and content. Throws `RangeError` on an
 * empty body string — even without the opt-in, the body is
 * the record's payload, and an empty record is a caller bug
 * that must fail closed, never notify as an empty message.
 */
export function resolveElasticEmailRecord(
  record: ElasticEmailRecord,
  index: number,
  config: Pick<ElasticEmailSinkConfig, "includePayload" | "payloadMaxChars">
): { notification: { subject: string; content: string }; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`elasticemail-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { notification: resolveElasticEmailNotification(record, config), index };
}

/**
 * Map one Elastic Email POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says Elastic Email could
 * not accept the message right now, not that the payload is
 * poison. Every other non-2xx status (400, 401, 403, 404,
 * and the rest) is a fail-closed message: unknown address,
 * invalid body, bad API key, or another verdict retrying
 * cannot change. Callers only pass non-2xx statuses here;
 * a 2xx status is a success, not a failure.
 */
export function classifyElasticEmailRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Elastic Email sink (WR-266). One instance targets one sender
 * address and one recipient address; the caller owns
 * retry/dead-letter policy around `send()` — this class
 * performs one POST attempt per message through the
 * injected client and reports its outcome. Failures
 * throw `ElasticEmailSinkError` carrying exactly the failed
 * messages with their retry lanes.
 */
export class ElasticEmailSink {
  private readonly cfg: ElasticEmailSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: ElasticEmailSinkConfig) {
    assertValidElasticEmailSinkConfig(config, "ElasticEmailSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): ElasticEmailSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages by email, in input order. Throws
   * `ElasticEmailSinkConfigError` when no client was injected or
   * the sender or recipient is missing, and
   * `ElasticEmailSinkError` when any message fails (carrying
   * exactly the failed messages with their retry lanes; both
   * counted in stats before throwing, so the counters stay
   * honest even for callers that only inspect stats).
   */
  async send(records: ElasticEmailRecord[]): Promise<ElasticEmailSendResult> {
    const resolved = records.map((r, i) => resolveElasticEmailRecord(r, i, this.cfg));
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
      throw new ElasticEmailSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const from = this.cfg.from;
    if (from === undefined) {
      throw new ElasticEmailSinkConfigError("no sender configured (set `from` in the sink config)");
    }
    const to = this.cfg.to;
    if (to === undefined) {
      throw new ElasticEmailSinkConfigError("no recipient configured (set `to` in the sink config)");
    }
    const failedRecords: ElasticEmailFailedRecord[] = [];
    let sent = 0;
    for (const record of resolved) {
      try {
        const response = await client.post({
          url: ELASTICEMAIL_SEND_URL,
          body: buildElasticEmailMessageBody(from, to, record.notification.subject, record.notification.content),
        });
        if (response.status >= 200 && response.status < 300) {
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyElasticEmailRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toElasticEmailFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new ElasticEmailSinkError(
        `elasticemail-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toElasticEmailFailedRecord(err: unknown, index: number): ElasticEmailFailedRecord {
  const failed: ElasticEmailFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
