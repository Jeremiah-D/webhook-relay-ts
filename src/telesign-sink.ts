/**
 * Telesign SMS notification delivery sink (WR-283).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's phone. Where the 46elks sink
 * (WR-277) delivers SMS through 46elks' SMS API with a
 * form-encoded `from`/`to`/`message` body and a Basic
 * auth header the client alone holds, and the ClickSend
 * sink (WR-268) delivers through ClickSend's API with a
 * JSON `messages`/`body` envelope and Basic auth, this
 * sink delivers through Telesign's Messaging API: one
 * event is sent as one POST, and Telesign — not the relay
 * — owns the carrier routing, the delivery, and the
 * retention of the message.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Telesign
 * server. The sink owns the relay-side concerns — message
 * targeting, content derivation, payload-inclusion policy,
 * per-message failure mapping — and the injected client
 * owns the wire protocol, including the POST call, the
 * authentication, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://rest-ww.telesign.com/v1/messaging",
 *     body: "phone_number=<number>&message=<message>&message_type=ARN" }
 *
 * The client POSTs to that URL, sending `body` verbatim
 * as the request body (an `application/x-www-form-urlencoded`
 * form with the `phone_number`, `message`, and
 * `message_type` fields) and authenticating with an
 * `Authorization: Basic` header carrying the base64 of
 * `customer_id:api_key` — the customer id and API key it
 * alone holds. Three things about this shape are
 * deliberate, and all follow the sibling sinks:
 *
 * - The credentials are held by the client alone. The sink
 *   never receives them, never places them in the request,
 *   and never logs them: like the 46elks sink (WR-277),
 *   whose API username and password the client alone
 *   holds, this sink's handed request carries no
 *   credential at all — the client adds the
 *   `Authorization: Basic` header from the customer id
 *   and API key it alone holds, so there is nothing in
 *   the handed request for a log line or a retry queue to
 *   leak. The backlog item's "配置持有" is the client's
 *   configuration, not the sink's: no credential ever
 *   enters the sink config. This is the opposite of the
 *   Vonage sink (WR-252), whose credentials ride inside
 *   the request body: Telesign authenticates by header, so
 *   the body carries only routing and content.
 * - The host is fixed, not configurable: Telesign is a
 *   single hosted service, so there is no self-hosted
 *   deployment to point at — unlike the Infobip sink
 *   (WR-267), whose host varies per account, a
 *   configurable URL here could only misroute a message
 *   to a server that is not Telesign. The endpoint and
 *   the form fields match the current Telesign
 *   documentation (checked this round, 2026-10-31):
 *   `POST https://rest-ww.telesign.com/v1/messaging`
 *   with `phone_number`, `message`, and `message_type`
 *   (ARN for alerts, reminders, and notifications).
 * - The response carries a reference id, not just a
 *   status: a 2xx returns the transaction's
 *   `reference_id`, and the id is an acceptance receipt
 *   only, not a delivery result (delivery confirmation
 *   lives in Telesign's Transaction Callback Service,
 *   keyed by that reference id). The client surfaces the
 *   id on the response, and the sink reads it — a 2xx
 *   with no reference id surfaced is retryable, because
 *   without the id the sink cannot claim the message was
 *   accepted.
 *
 * This sink is orthogonal to the 46elks sink (WR-277):
 * 46elks posts a form-encoded `from`/`to`/`message` body
 * with a sender identity and no acceptance id, while
 * Telesign posts a form-encoded
 * `phone_number`/`message`/`message_type=ARN` body with
 * no sender field and a `reference_id` acceptance
 * receipt. It is likewise distinct from the ClickSend
 * sink (WR-268): ClickSend posts a JSON
 * `messages`/`body` envelope with a single `to` string,
 * while Telesign posts a form-encoded body with a fixed
 * `message_type` field. And from the WonderPush sink
 * (WR-282): WonderPush posts a form-encoded delivery to
 * a segment audience and answers with a delivery id,
 * while Telesign posts a form-encoded SMS to one E.164
 * number and answers with a reference id.
 *
 * The recipient is configured, not derived from the
 * event. One sink targets one recipient number. A missing
 * recipient is a config error, not a resolution fallback:
 * unlike the broker sinks, there is no per-record target
 * to resolve to, so a sink with no number has nowhere to
 * deliver and fails closed with
 * `TelesignSinkConfigError` at send time (dry runs
 * excepted — they need no number at all, mirroring the
 * sibling sinks' dry-run exemption for the client). The
 * `phone_number` is an E.164 string: the docs require
 * the end user's number with the country code included,
 * digits without spaces or special characters.
 *
 * Message content — derived from the event's own values:
 * the first non-empty value among `subject`, `key`, and
 * `traceId`, in that order. An SMS carries a single
 * content field, so there is no subject/value split like
 * the email sinks: the subject is what the event is
 * about, the key (e.g. aggregate id) is the next most
 * identifying value, and the trace id names the trace
 * that produced the event. An event with none of the
 * values still notifies, with the generic summary
 * `webhook event`: a notification sink that silently
 * dropped sourceless events would hide exactly the
 * deliveries an operator most needs to see, and the
 * recipient number — not the content — is the delivery
 * contract here, so no invented target is at stake.
 * The `message_type` is fixed to `ARN` (alerts,
 * reminders, and notifications): this sink sends
 * notifications, never one-time passcodes — the OTP
 * channel is out of scope, per the backlog item.
 *
 * Payload inclusion — by default the message carries the
 * summary only, never the full payload: event bodies
 * routinely carry PII, secrets, or customer data, and a
 * phone is a far wider audience than a queue or a
 * stream. Opting into `includePayload` appends the body
 * verbatim after a blank line, truncated to
 * `payloadMaxChars` characters (default 2000) with a
 * truncation marker — the opt-in is explicit, and the
 * truncation is unconditional, so even an opted-in body
 * cannot flood a phone. The payload is appended as plain
 * text inside the `message` field, not a fenced code
 * block: an SMS renders as-is, and a fence would be
 * noise on a phone screen. Telesign splits a message
 * longer than its per-part limit into separate parts, so
 * a long opted-in body still sends — the truncation
 * keeps it to at most a couple of parts.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over the HTTP status and, on a 2xx, over the reference
 * id:
 *
 * - a non-2xx POST throws `TelesignSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Telesign could
 *   not accept the message right now, not that the
 *   payload is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (unknown number, invalid body, bad
 *   credentials): retrying them burns the retry budget
 *   for nothing, and rerouting them elsewhere would text
 *   numbers the operator never chose;
 * - on a 2xx, the reference id decides: a surfaced id
 *   means Telesign accepted the message; a 2xx with no
 *   id surfaced is retryable — the id is the acceptance
 *   result, and a missing id means the sink cannot claim
 *   the message was accepted;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client or recipient throws
 *   `TelesignSinkConfigError`, which `classifyFailure`
 *   maps to `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for the message field. */
export const TELESIGN_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const TELESIGN_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Fixed Telesign Messaging API endpoint for every message. */
export const TELESIGN_SEND_URL = "https://rest-ww.telesign.com/v1/messaging";

/** Fixed message type for this sink: alerts, reminders, and notifications — never OTP. */
export const TELESIGN_MESSAGE_TYPE = "ARN";

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (an `application/x-www-form-urlencoded`
 * form with the `phone_number`, `message`, and
 * `message_type` fields) to the fixed Messaging endpoint,
 * and authenticates with an `Authorization: Basic` header
 * carrying the base64 of its own `customer_id:api_key` —
 * which the sink never sees.
 */
export interface TelesignMessagePostRequest {
  /** Always the fixed Telesign Messaging endpoint. */
  url: string;
  /** The form-encoded message, serialized: `phone_number=<number>&message=<message>&message_type=ARN`. */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * The HTTP status drives the HTTP retry mapping; on a 2xx
 * the client surfaces the transaction's `reference_id`,
 * and the id — not the status alone — decides whether the
 * message was accepted. A client that reports a 2xx
 * without an id leaves the sink unable to claim
 * acceptance, so the message is treated as a retryable
 * delivery failure.
 */
export interface TelesignMessagePostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
  /**
   * The transaction's `reference_id`, on a 2xx: an
   * acceptance receipt only, not a delivery result
   * (delivery confirmation lives in Telesign's
   * Transaction Callback Service, keyed by this id).
   */
  referenceId?: string;
}

/**
 * The injected Telesign message client. Any client adapter
 * implements this one method; it returns the POST's status
 * and, on a 2xx, the transaction's `reference_id` (a throw
 * is a codeless transport failure, retryable). The client
 * is expected to POST one message per call, sending `body`
 * verbatim as the request body (the form-encoded
 * `phone_number`/`message`/`message_type` fields), setting
 * the `application/x-www-form-urlencoded` content type, and
 * authenticating with an `Authorization: Basic` header
 * carrying the base64 of its own `customer_id:api_key` —
 * which the sink never sees.
 */
export interface TelesignMessageClient {
  post(request: TelesignMessagePostRequest): Promise<TelesignMessagePostResponse>;
}

/**
 * Configuration for one Telesign sink. The client is
 * injected: without one, `send()` throws
 * `TelesignSinkConfigError` (dry runs excepted — they need
 * no client at all). A missing recipient is likewise a
 * config error at send time (dry runs excepted): there is
 * no per-record target to fall back to. The customer id
 * and API key are deliberately absent from this config:
 * the client alone holds them and sends them as the
 * `Authorization: Basic` header.
 */
export interface TelesignSinkConfig {
  /**
   * The recipient number (`phone_number`): an E.164 string
   * with the country code included, digits without spaces
   * or special characters. Must be a non-empty string,
   * free of NUL and whitespace, when set; a missing
   * recipient throws `TelesignSinkConfigError` at send
   * time.
   */
  phoneNumber?: string;
  /**
   * The Telesign message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `TelesignMessageClient` and alone holds the
   * customer id and API key. Required for real sends; a
   * missing client is a config error, not a silent no-op.
   */
  client?: TelesignMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including content derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The recipient and client are
   * not required in dry-run mode, mirroring the sibling
   * sinks' dry-run exemption.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the message content appends
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
export interface TelesignRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Content-derivation source, first priority: the event's
   * subject, when set and non-empty. Falls through to `key`,
   * then `traceId`.
   */
  subject?: string;
  /**
   * Content-derivation source, second priority: the event's key
   * (e.g. aggregate id).
   */
  key?: string;
  /**
   * Content-derivation source, last priority: the trace id.
   */
  traceId?: string;
}

/** One failed message, with its retry lane already mapped. */
export interface TelesignFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /**
   * Failure code: `HTTP_<status>` for a non-2xx POST,
   * `REFERENCE_ID_MISSING` for a 2xx with no reference id
   * surfaced, or `TRANSPORT_ERROR` for a codeless
   * failure.
   */
  errorCode: string;
  /** Downstream HTTP status, when the failure was a non-2xx POST. */
  statusCode?: number;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: 429 and 5xx (plus
   * codeless transport failures and missing reference ids)
   * are retryable, every other non-2xx status is a
   * fail-closed message (unknown number, invalid body, bad
   * credentials).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface TelesignSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-283). */
export interface TelesignSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Telesign send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on Telesign's server and are *not* in
 * `failedRecords`.
 */
export class TelesignSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: TelesignFailedRecord[];
  constructor(message: string, failedRecords: TelesignFailedRecord[]) {
    super(message);
    this.name = "TelesignSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, or the recipient is missing. A
 * config problem, not a downstream verdict, so the retry
 * queue must not burn attempts on it (`classifyFailure`
 * maps it to `non_retryable`).
 */
export class TelesignSinkConfigError extends TelesignSinkError {
  constructor(reason: string) {
    super(`telesign-sink: ${reason}`, []);
    this.name = "TelesignSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing recipient is *not* a shape error: it is a config
 * error raised at send time (`TelesignSinkConfigError`), so a
 * sink built before its number is known still fails closed at
 * send time rather than crashing at construction. A present
 * `phoneNumber` value must be a non-empty E.164 string, free
 * of NUL and whitespace.
 */
export function assertValidTelesignSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is TelesignSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  const phoneNumber = c.phoneNumber;
  if (phoneNumber !== undefined) {
    if (
      typeof phoneNumber !== "string" ||
      phoneNumber === "" ||
      phoneNumber.includes("\0") ||
      /\s/.test(phoneNumber)
    ) {
      throw new RangeError(
        at("`phoneNumber` must be a non-empty string, free of NUL and whitespace, when set")
      );
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
 * Derive one record's message content: the first non-empty
 * value among `subject`, `key`, and `traceId`, in that
 * order. Falls back to the generic `webhook event` summary
 * when the record carries none — a notification sink must
 * not silently drop sourceless events, and the recipient
 * number (not the content) is the delivery contract.
 */
export function resolveTelesignContent(record: TelesignRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return TELESIGN_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a phone.
 */
export function truncateTelesignPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's message content. Only under the
 * `includePayload` opt-in does the content append the event
 * body verbatim after a blank line, truncated to
 * `payloadMaxChars` (default 2000). Without the opt-in, the
 * content is the summary alone: event bodies routinely carry
 * PII and must never leak into a notification by default.
 * The payload is appended as plain text inside the `message`
 * field, not a fenced code block: an SMS renders as-is,
 * and a fence would be noise on a phone screen.
 */
export function resolveTelesignMessage(
  record: TelesignRecord,
  config: Pick<TelesignSinkConfig, "includePayload" | "payloadMaxChars">
): { message: string } {
  let message = resolveTelesignContent(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? TELESIGN_DEFAULT_PAYLOAD_MAX_CHARS;
    message = `${message}\n\n${truncateTelesignPayload(record.body, limit)}`;
  }
  return { message };
}

/**
 * Build one record's serialized request body: the
 * form-encoded `phone_number`/`message`/`message_type`
 * fields, in that order, each value percent-encoded, with
 * `message_type` fixed to `ARN`. The customer id and API
 * key never appear here — the client alone holds them and
 * sends them as the `Authorization: Basic` header.
 */
export function buildTelesignMessageBody(
  phoneNumber: string,
  message: string
): string {
  return `phone_number=${encodeURIComponent(phoneNumber)}&message=${encodeURIComponent(message)}&message_type=${TELESIGN_MESSAGE_TYPE}`;
}

/**
 * Validate one record's body and resolve its send form: the
 * message content. Throws `RangeError` on an empty body
 * string — even without the opt-in, the body is the record's
 * payload, and an empty record is a caller bug that must
 * fail closed, never notify as an empty message.
 */
export function resolveTelesignRecord(
  record: TelesignRecord,
  index: number,
  config: Pick<TelesignSinkConfig, "includePayload" | "payloadMaxChars">
): { message: string; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`telesign-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { message: resolveTelesignMessage(record, config).message, index };
}

/**
 * Map one Telesign POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says Telesign could not
 * accept the message right now, not that the payload is
 * poison. Every other non-2xx status (400, 401, 403,
 * 404, and the rest) is a fail-closed message: unknown
 * number, invalid body, bad credentials, or another verdict
 * retrying cannot change. Callers only pass non-2xx
 * statuses here; a 2xx status is decided by the reference
 * id, not by this function.
 */
export function classifyTelesignRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Map one Telesign POST response onto its failed record,
 * or `null` when the response accepted the message (a 2xx
 * with a surfaced reference id). A 2xx with no id is
 * retryable — the id is the acceptance result, and without
 * it the sink cannot claim the message was accepted.
 */
export function telesignResponseToFailedRecord(
  response: TelesignMessagePostResponse,
  index: number
): TelesignFailedRecord | null {
  if (
    response.referenceId !== undefined &&
    response.referenceId !== ""
  ) {
    return null;
  }
  return {
    index,
    errorCode: "REFERENCE_ID_MISSING",
    errorMessage: "Telesign answered 2xx but surfaced no reference_id",
    retryable: true,
  };
}

/**
 * Telesign sink (WR-283). One instance targets one
 * Telesign account and one recipient number; the caller owns
 * retry / dead-letter policy around `send()` — this class
 * performs one POST attempt per message through the injected
 * client and reports its outcome. Failures throw
 * `TelesignSinkError` carrying exactly the failed messages
 * with their retry lanes.
 */
export class TelesignSink {
  private readonly cfg: TelesignSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: TelesignSinkConfig) {
    assertValidTelesignSinkConfig(config, "TelesignSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): TelesignSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages by SMS, in input order. Throws
   * `TelesignSinkConfigError` when no client was injected
   * or the recipient is missing, and `TelesignSinkError`
   * when any message fails (carrying exactly the failed
   * messages with their retry lanes; both counted in stats
   * before throwing, so the counters stay honest even for
   * callers that only inspect stats).
   */
  async send(records: TelesignRecord[]): Promise<TelesignSendResult> {
    const resolved = records.map((r, i) => resolveTelesignRecord(r, i, this.cfg));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The
      // recipient and client are
      // not required here, mirroring the sibling sinks'
      // dry-run exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new TelesignSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const phoneNumber = this.cfg.phoneNumber;
    if (phoneNumber === undefined) {
      throw new TelesignSinkConfigError("no recipient configured (set `phoneNumber` in the sink config)");
    }
    const url = TELESIGN_SEND_URL;
    const failedRecords: TelesignFailedRecord[] = [];
    let sent = 0;
    for (const record of resolved) {
      try {
        const response = await client.post({
          url,
          body: buildTelesignMessageBody(phoneNumber, record.message),
        });
        if (response.status >= 200 && response.status < 300) {
          const idFailure = telesignResponseToFailedRecord(response, record.index);
          if (idFailure === null) {
            sent += 1;
            continue;
          }
          failedRecords.push(idFailure);
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyTelesignRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toTelesignFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new TelesignSinkError(
        `telesign-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toTelesignFailedRecord(err: unknown, index: number): TelesignFailedRecord {
  const failed: TelesignFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
