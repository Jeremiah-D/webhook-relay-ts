/**
 * MessageBird SMS notification delivery sink (WR-257).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's phone. Where the Twilio sink
 * (WR-247) delivers SMS through Twilio's form-encoded
 * Messages API, the Vonage sink (WR-252) delivers through
 * Vonage's key-in-body SMS API, and the Plivo sink
 * (WR-255) delivers through Plivo's account-pathed JSON
 * API, this sink delivers through MessageBird's Messages
 * HTTP API: one event is sent as one SMS, and
 * MessageBird — not the relay — owns the carrier routing,
 * the delivery, and the retention of the message.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a MessageBird
 * server. The sink owns the relay-side concerns — message
 * targeting, body derivation, payload-inclusion policy,
 * per-message failure mapping — and the injected client
 * owns the wire protocol, including the POST call, the
 * authentication, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://rest.messagebird.com/messages",
 *     body: "{\"originator\":\"<originator>\",\"recipients\":[\"<msisdn>\"],\"body\":\"<body>\"}" }
 *
 * The client POSTs to that fixed URL, sending `body`
 * verbatim as the request body (a JSON object) and
 * authenticating with an `Authorization: AccessKey`
 * header carrying an API key it alone holds. Two things
 * about this shape are deliberate, and both follow the
 * sibling sinks:
 *
 * - The API key is held by the client alone. The sink
 *   never receives it, never places it in the request,
 *   and never logs it: like the Plivo sink (WR-255),
 *   whose token the client alone holds, this sink's
 *   request carries no credential at all — the client adds
 *   the `Authorization: AccessKey` header from the key it
 *   alone holds, so there is nothing in the request for a
 *   log line or a retry queue to leak. This is the
 *   opposite of the Vonage sink (WR-252), whose
 *   credentials ride inside the request body: MessageBird
 *   authenticates by header, so the body carries only
 *   routing and content.
 * - The host is fixed, not configurable: MessageBird is a
 *   single hosted service, so there is no self-hosted
 *   deployment to point at — a configurable URL here
 *   could only misroute a message to a server that is
 *   not MessageBird. The recipients field is a
 *   single-element array holding this sink's one
 *   configured recipient: MessageBird's envelope takes an
 *   array, but one sink still targets one recipient, like
 *   every sibling SMS sink.
 *
 * The originator and the recipient are configured, not
 * derived from the event. One sink targets one originator
 * and one recipient number. A missing originator or
 * recipient is a config error, not a resolution fallback:
 * unlike the broker sinks, there is no per-record target
 * to resolve to, so a sink with no recipient has nowhere
 * to deliver and fails closed with
 * `MessageBirdSinkConfigError` at send time (dry runs
 * excepted — they need no numbers at all, mirroring the
 * sibling sinks' dry-run exemption for the client).
 *
 * Message body — derived from the event's own values:
 * the first non-empty value among `subject`, `key`, and
 * `traceId`, in that order. An SMS carries a single body
 * field, so there is no subject/value split like the
 * email sinks: the subject is what the event is about,
 * the key (e.g. aggregate id) is the next most
 * identifying value, and the trace id names the trace
 * that produced the event. An event with none of the
 * values still notifies, with the generic summary
 * `webhook event`: a notification sink that silently
 * dropped sourceless events would hide exactly the
 * deliveries an operator most needs to see, and the
 * recipient number — not the body — is the delivery
 * contract here, so no invented target is at stake.
 *
 * Payload inclusion — by default the message carries the
 * summary only, never the full payload: event bodies
 * routinely carry PII, secrets, or customer data, and a
 * phone is a far wider audience than a queue or a stream.
 * Opting into `includePayload` appends the body verbatim
 * after a blank line, truncated to `payloadMaxChars`
 * characters (default 2000) with a truncation marker —
 * the opt-in is explicit, and the truncation is
 * unconditional, so even an opted-in body cannot flood a
 * phone. The body is appended as plain text inside the
 * `body` field, not a fenced code block: an SMS renders
 * as-is, and a fence would be noise on a phone screen.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over HTTP status:
 *
 * - a non-2xx POST throws `MessageBirdSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says MessageBird
 *   could not accept the message right now, not that the
 *   payload is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (unknown number, invalid body, bad
 *   credentials): retrying them burns the retry budget
 *   for nothing, and rerouting them elsewhere would text
 *   a number the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client, originator, or recipient
 *   throws `MessageBirdSinkConfigError`, which
 *   `classifyFailure` maps to `non_retryable` (the WR-116
 *   rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for the body field. */
export const MESSAGEBIRD_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const MESSAGEBIRD_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Fixed MessageBird Messages API endpoint for every message. */
export const MESSAGEBIRD_MESSAGES_URL = "https://rest.messagebird.com/messages";

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (a JSON object with `originator`,
 * `recipients`, and `body`) to the fixed Messages
 * endpoint, and authenticates with an `Authorization:
 * AccessKey` header carrying an API key it alone holds.
 * The sink never sees the key, so the request carries no
 * credential: nothing here can leak into a log line.
 */
export interface MessageBirdMessagePostRequest {
  /** Always the fixed MessageBird Messages endpoint. */
  url: string;
  /** The JSON message object, serialized: `originator`, `recipients`, `body`. */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse MessageBird's response body.
 */
export interface MessageBirdMessagePostResponse {
  /** The HTTP status of the POST (e.g. 201, 429, 503). */
  status: number;
}

/**
 * The injected MessageBird message client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one message per call, sending
 * `body` verbatim as the request body (the JSON object
 * with `originator`, `recipients`, and `body`), setting the
 * `application/json` content type, and authenticating with
 * its own API key — which the sink never sees.
 */
export interface MessageBirdMessageClient {
  post(request: MessageBirdMessagePostRequest): Promise<MessageBirdMessagePostResponse>;
}

/**
 * Configuration for one MessageBird sink. The client is
 * injected: without one, `send()` throws
 * `MessageBirdSinkConfigError` (dry runs excepted — they need
 * no client at all). A missing originator or recipient is
 * likewise a config error at send time (dry runs
 * excepted): there is no per-record target to fall back
 * to. The API key is deliberately absent from this config:
 * the client alone holds it and sends it as the
 * `Authorization: AccessKey` header.
 */
export interface MessageBirdSinkConfig {
  /**
   * The originator: the sender id every message appears
   * to come from. Must be a non-empty string, free of NUL
   * and whitespace, when set; a missing originator throws
   * `MessageBirdSinkConfigError` at send time.
   */
  originator?: string;
  /**
   * The recipient number: the recipient of every message
   * from this sink, carried as the single entry of the
   * `recipients` array. Must be a non-empty string, free
   * of NUL and whitespace, when set; a missing recipient
   * throws `MessageBirdSinkConfigError` at send time.
   */
  recipient?: string;
  /**
   * The MessageBird message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `MessageBirdMessageClient` and alone holds
   * the API key. Required for real sends; a missing client
   * is a config error, not a silent no-op.
   */
  client?: MessageBirdMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including body derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The originator, recipient, and client are not
   * required in dry-run mode, mirroring the sibling sinks'
   * dry-run exemption.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the body appends
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
   * the opt-in is set, so an opted-in body cannot flood a
   * phone. Must be a positive integer when set.
   */
  payloadMaxChars?: number;
}

/** One event to notify about. */
export interface MessageBirdRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Body-derivation source, first priority: the event's
   * subject, when set and non-empty. Falls through to `key`,
   * then `traceId`.
   */
  subject?: string;
  /**
   * Body-derivation source, second priority: the event's key
   * (e.g. aggregate id).
   */
  key?: string;
  /**
   * Body-derivation source, last priority: the trace id.
   */
  traceId?: string;
}

/** One failed message, with its retry lane already mapped. */
export interface MessageBirdFailedRecord {
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
   * non-2xx status is a fail-closed message (unknown number,
   * invalid body, bad credentials).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface MessageBirdSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-257). */
export interface MessageBirdSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for MessageBird send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on MessageBird's server and are *not* in
 * `failedRecords`.
 */
export class MessageBirdSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: MessageBirdFailedRecord[];
  constructor(message: string, failedRecords: MessageBirdFailedRecord[]) {
    super(message);
    this.name = "MessageBirdSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, or the originator or recipient is
 * missing. A config problem, not a downstream verdict, so
 * the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class MessageBirdSinkConfigError extends MessageBirdSinkError {
  constructor(reason: string) {
    super(`messagebird-sink: ${reason}`, []);
    this.name = "MessageBirdSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing originator or recipient is *not* a shape error:
 * it is a config error raised at send time
 * (`MessageBirdSinkConfigError`), so a sink built before its
 * numbers are known still fails closed at send time rather
 * than crashing at construction. A present value must be a
 * non-empty string, free of NUL and whitespace.
 */
export function assertValidMessageBirdSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is MessageBirdSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  for (const field of ["originator", "recipient"] as const) {
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
 * Derive one record's message body: the first non-empty
 * value among `subject`, `key`, and `traceId`, in that
 * order. Falls back to the generic `webhook event` summary
 * when the record carries none — a notification sink must
 * not silently drop sourceless events, and the recipient
 * number (not the body) is the delivery contract.
 */
export function resolveMessageBirdBody(record: MessageBirdRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return MESSAGEBIRD_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a phone.
 */
export function truncateMessageBirdPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's notification body. Only under the
 * `includePayload` opt-in does the body append the event
 * body verbatim after a blank line, truncated to
 * `payloadMaxChars` (default 2000). Without the opt-in, the
 * body is the summary alone: event bodies routinely carry
 * PII and must never leak into a notification by default.
 * The body is appended as plain text inside the `body`
 * field, not a fenced code block: an SMS renders as-is,
 * and a fence would be noise on a phone screen.
 */
export function resolveMessageBirdNotification(
  record: MessageBirdRecord,
  config: Pick<MessageBirdSinkConfig, "includePayload" | "payloadMaxChars">
): { body: string } {
  let body = resolveMessageBirdBody(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? MESSAGEBIRD_DEFAULT_PAYLOAD_MAX_CHARS;
    body = `${body}\n\n${truncateMessageBirdPayload(record.body, limit)}`;
  }
  return { body };
}

/**
 * Build one record's serialized request body: the JSON
 * object with `originator`, `recipients` (a single-element
 * array with the recipient number), and `body`, in that
 * order. Neither the API key nor any credential ever
 * appears here — the key is held by the client alone and
 * travels as the `Authorization: AccessKey` header.
 */
export function buildMessageBirdMessageBody(originator: string, recipient: string, body: string): string {
  return JSON.stringify({ originator, recipients: [recipient], body });
}

/**
 * Validate one record's body and resolve its send form: the
 * notification body. Throws `RangeError` on an
 * empty body string — even without the opt-in, the body is
 * the record's payload, and an empty record is a caller bug
 * that must fail closed, never notify as an empty message.
 */
export function resolveMessageBirdRecord(
  record: MessageBirdRecord,
  index: number,
  config: Pick<MessageBirdSinkConfig, "includePayload" | "payloadMaxChars">
): { notification: { body: string }; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`messagebird-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { notification: resolveMessageBirdNotification(record, config), index };
}

/**
 * Map one MessageBird POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says MessageBird could
 * not accept the message right now, not that the payload
 * is poison. Every other non-2xx status (400, 401, 403,
 * 404, and the rest) is a fail-closed message: unknown
 * number, invalid body, bad credentials, or another verdict
 * retrying cannot change. Callers only pass non-2xx
 * statuses here; a 2xx status is a success, not a failure.
 */
export function classifyMessageBirdRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * MessageBird sink (WR-257). One instance targets one
 * originator and one recipient number; the caller owns
 * retry/dead-letter policy around `send()` — this class
 * performs one POST attempt per message through the
 * injected client and reports its outcome. Failures
 * throw `MessageBirdSinkError` carrying exactly the failed
 * messages with their retry lanes.
 */
export class MessageBirdSink {
  private readonly cfg: MessageBirdSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: MessageBirdSinkConfig) {
    assertValidMessageBirdSinkConfig(config, "MessageBirdSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): MessageBirdSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages by SMS, in input order. Throws
   * `MessageBirdSinkConfigError` when no client was injected or
   * the originator or recipient is missing, and
   * `MessageBirdSinkError` when any message fails (carrying
   * exactly the failed messages with their retry lanes; both
   * counted in stats before throwing, so the counters stay
   * honest even for callers that only inspect stats).
   */
  async send(records: MessageBirdRecord[]): Promise<MessageBirdSendResult> {
    const resolved = records.map((r, i) => resolveMessageBirdRecord(r, i, this.cfg));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The
      // originator, recipient, and client are not required
      // here, mirroring the sibling sinks' dry-run
      // exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new MessageBirdSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const originator = this.cfg.originator;
    if (originator === undefined) {
      throw new MessageBirdSinkConfigError("no originator configured (set `originator` in the sink config)");
    }
    const recipient = this.cfg.recipient;
    if (recipient === undefined) {
      throw new MessageBirdSinkConfigError("no recipient configured (set `recipient` in the sink config)");
    }
    const failedRecords: MessageBirdFailedRecord[] = [];
    let sent = 0;
    for (const record of resolved) {
      try {
        const response = await client.post({
          url: MESSAGEBIRD_MESSAGES_URL,
          body: buildMessageBirdMessageBody(originator, recipient, record.notification.body),
        });
        if (response.status >= 200 && response.status < 300) {
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyMessageBirdRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toMessageBirdFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new MessageBirdSinkError(
        `messagebird-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toMessageBirdFailedRecord(err: unknown, index: number): MessageBirdFailedRecord {
  const failed: MessageBirdFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
