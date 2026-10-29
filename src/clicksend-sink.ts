/**
 * ClickSend SMS notification delivery sink (WR-268).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's phone. Where the Telnyx sink
 * (WR-264) delivers SMS through Telnyx's flat
 * `from`/`to`/`text` Messages API and the Bandwidth sink
 * (WR-263) delivers through Bandwidth's account-pathed
 * JSON API with `to` as a single-element array, this
 * sink delivers through ClickSend's SMS API: one event
 * is sent as one SMS, and ClickSend — not the relay —
 * owns the carrier routing, the delivery, and the
 * retention of the message.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a ClickSend
 * server. The sink owns the relay-side concerns — message
 * targeting, body derivation, payload-inclusion policy,
 * per-message failure mapping — and the injected client
 * owns the wire protocol, including the POST call, the
 * authentication, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://rest.clicksend.com/v3/sms/send",
 *     body: "{\"messages\":[{\"source\":\"<source>\",\"from\":\"<from>\",\"to\":\"<msisdn>\",\"body\":\"<text>\"}]}" }
 *
 * The client POSTs to that URL, sending `body` verbatim
 * as the request body (a JSON object) and authenticating
 * with an `Authorization: Basic` header carrying the
 * username + API key pair it alone holds — the official
 * SDK's Basic-auth shape; OAuth token flows are out of
 * scope here. Three things about this shape are
 * deliberate, and all follow the sibling sinks:
 *
 * - The Basic credentials are held by the client alone.
 *   The sink never receives them, never places them in
 *   the request, and never logs them: like the Telnyx
 *   sink (WR-264), whose API key the client alone
 *   holds, this sink's request carries no credential at
 *   all — the client adds the `Authorization: Basic`
 *   header from the pair it alone holds, so there is
 *   nothing in the request for a log line or a retry
 *   queue to leak. This is the opposite of the Vonage
 *   sink (WR-252), whose credentials ride inside the
 *   request body: ClickSend authenticates by header, so
 *   the body carries only routing and content.
 * - The `to` field is a single number string, not an
 *   array: that is ClickSend's fixed message shape —
 *   unlike the Bandwidth sink (WR-263), whose `to` is a
 *   single-element array, ClickSend takes one recipient
 *   number as a bare string inside the `messages` entry,
 *   so a sink that wrapped it in an array would be
 *   rejected.
 * - The host is fixed, not configurable: ClickSend is a
 *   single hosted service, so there is no self-hosted
 *   deployment to point at — unlike the Infobip sink
 *   (WR-267), whose host varies per account, a
 *   configurable URL here could only misroute a message
 *   to a server that is not ClickSend.
 *
 * The sender and the recipient are configured, not
 * derived from the event. One sink targets one sender
 * number and one recipient number. A missing sender or
 * recipient is a config error, not a resolution fallback:
 * unlike the broker sinks, there is no per-record target
 * to resolve to, so a sink with no recipient has nowhere
 * to deliver and fails closed with
 * `ClickSendSinkConfigError` at send time (dry runs
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
 * phone. The payload is appended as plain text inside
 * the `body` field, not a fenced code block: an SMS
 * renders as-is, and a fence would be noise on a phone
 * screen.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over HTTP status:
 *
 * - a non-2xx POST throws `ClickSendSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says ClickSend could
 *   not accept the message right now, not that the payload
 *   is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (unknown number, invalid body, bad
 *   credentials): retrying them burns the retry budget
 *   for nothing, and rerouting them elsewhere would text
 *   a number the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client, sender, or recipient throws
 *   `ClickSendSinkConfigError`, which
 *   `classifyFailure` maps to `non_retryable` (the WR-116
 *   rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for the text field. */
export const CLICKSEND_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const CLICKSEND_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Fixed ClickSend SMS API endpoint for every message. */
export const CLICKSEND_SEND_URL = "https://rest.clicksend.com/v3/sms/send";

/** Default ClickSend message `source`, identifying the sending application. */
export const CLICKSEND_DEFAULT_SOURCE = "webhook-relay";

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (a JSON object with a
 * `messages` array) to the fixed SMS endpoint, and
 * authenticates with an `Authorization: Basic` header
 * carrying the username + API key pair it alone holds.
 * The sink never sees that pair, so the request
 * carries no credential: nothing here can leak into a
 * log line.
 */
export interface ClickSendMessagePostRequest {
  /** Always the fixed ClickSend SMS endpoint. */
  url: string;
  /** The JSON message object, serialized: `messages` with `source`, `from`, `to`, and `body`. */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse ClickSend's response body.
 */
export interface ClickSendMessagePostResponse {
  /** The HTTP status of the POST (e.g. 201, 429, 503). */
  status: number;
}

/**
 * The injected ClickSend message client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one message per call, sending
 * `body` verbatim as the request body (the JSON object
 * with a `messages` array),
 * setting the `application/json` content type, and
 * authenticating with an `Authorization: Basic` header
 * carrying its own username + API key pair — which the
 * sink never sees.
 */
export interface ClickSendMessageClient {
  post(request: ClickSendMessagePostRequest): Promise<ClickSendMessagePostResponse>;
}

/**
 * Configuration for one ClickSend sink. The client is
 * injected: without one, `send()` throws
 * `ClickSendSinkConfigError` (dry runs excepted — they need
 * no client at all). A missing sender or recipient is
 * likewise a config error at send
 * time (dry runs excepted): there is no per-record target
 * to fall back to. The username + API key pair is deliberately
 * absent from this config: the client alone holds it
 * and sends it as the `Authorization: Basic` header.
 */
export interface ClickSendSinkConfig {
  /**
   * The sender number (`from`): the number every message
   * appears to come from. Must be a non-empty string, free
   * of NUL and whitespace, when set; a missing sender
   * throws `ClickSendSinkConfigError` at send time.
   */
  from?: string;
  /**
   * The recipient number (`to`): the recipient of every
 * message from this sink, carried as the bare `to` string
 * (ClickSend v2 takes a single number, not an array). Must be a
 * non-empty string, free of NUL and whitespace, when set; a missing
 * recipient throws `ClickSendSinkConfigError` at send time.
   */
  to?: string;
  /**
   * The message `source`: ClickSend's field identifying
   * the sending application. Defaults to
   * `webhook-relay` when unset — the relay identifying
   * itself, not a credential and not a routing address.
   * Must be a non-empty string, free of NUL and
   * whitespace, when set. OAuth token flows are out of
   * scope: authentication is the client's Basic pair.
   */
  source?: string;
  /**
   * The ClickSend message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `ClickSendMessageClient` and alone holds the
 * username + API key pair. Required for real sends; a missing
   * client is a config error, not a silent no-op.
   */
  client?: ClickSendMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including text derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
 * The numbers and client are
   * not required in dry-run mode, mirroring the sibling
   * sinks' dry-run exemption.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the message text appends
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
export interface ClickSendRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Text-derivation source, first priority: the event's
   * subject, when set and non-empty. Falls through to `key`,
   * then `traceId`.
   */
  subject?: string;
  /**
   * Text-derivation source, second priority: the event's key
   * (e.g. aggregate id).
   */
  key?: string;
  /**
   * Text-derivation source, last priority: the trace id.
   */
  traceId?: string;
}

/** One failed message, with its retry lane already mapped. */
export interface ClickSendFailedRecord {
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
export interface ClickSendSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-264). */
export interface ClickSendSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for ClickSend send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on ClickSend's server and are *not* in
 * `failedRecords`.
 */
export class ClickSendSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: ClickSendFailedRecord[];
  constructor(message: string, failedRecords: ClickSendFailedRecord[]) {
    super(message);
    this.name = "ClickSendSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, or the sender or recipient is
 * missing. A config problem, not a
 * downstream verdict, so the retry queue must not burn
 * attempts on it (`classifyFailure` maps it to
 * `non_retryable`).
 */
export class ClickSendSinkConfigError extends ClickSendSinkError {
  constructor(reason: string) {
    super(`clicksend-sink: ${reason}`, []);
    this.name = "ClickSendSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing sender or recipient is
 * *not* a shape error: it is a config error raised at send time
 * (`ClickSendSinkConfigError`), so a sink built before its
 * numbers are known still fails closed at send time rather
 * than crashing at construction. A present value must be a
 * non-empty string, free of NUL and whitespace.
 */
export function assertValidClickSendSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is ClickSendSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  for (const field of ["from", "to", "source"] as const) {
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
 * Derive one record's message text: the first non-empty
 * value among `subject`, `key`, and `traceId`, in that
 * order. Falls back to the generic `webhook event` summary
 * when the record carries none — a notification sink must
 * not silently drop sourceless events, and the recipient
 * number (not the text) is the delivery contract.
 */
export function resolveClickSendText(record: ClickSendRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return CLICKSEND_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a phone.
 */
export function truncateClickSendPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's notification body. Only under the
 * `includePayload` opt-in does the body append the event
 * payload verbatim after a blank line, truncated to
 * `payloadMaxChars` (default 2000). Without the opt-in, the
 * body is the summary alone: event bodies routinely carry
 * PII and must never leak into a notification by default.
 * The payload is appended as plain text inside the
 * `body` field, not a fenced code block: an SMS renders
 * as-is, and a fence would be noise on a phone screen.
 */
export function resolveClickSendNotification(
  record: ClickSendRecord,
  config: Pick<ClickSendSinkConfig, "includePayload" | "payloadMaxChars">
): { body: string } {
  let body = resolveClickSendText(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? CLICKSEND_DEFAULT_PAYLOAD_MAX_CHARS;
    body = `${body}\n\n${truncateClickSendPayload(record.body, limit)}`;
  }
  return { body };
}

/**
 * Build one record's serialized request body: the JSON
 * object with a `messages` array holding one entry with
 * `source`, `from`, `to` (a single number string, not
 * an array), and `body`, in that order. The username + API key pair
 * never appears here — the client alone holds it and
 * sends it as the `Authorization: Basic` header.
 */
export function buildClickSendMessageBody(
  from: string,
  to: string,
  body: string,
  source: string
): string {
  return JSON.stringify({ messages: [{ source, from, to, body }] });
}

/**
 * Validate one record's body and resolve its send form: the
 * notification body. Throws `RangeError` on an empty body
 * string — even without the opt-in, the body is the record's
 * payload, and an empty record is a caller bug that must
 * fail closed, never notify as an empty message.
 */
export function resolveClickSendRecord(
  record: ClickSendRecord,
  index: number,
  config: Pick<ClickSendSinkConfig, "includePayload" | "payloadMaxChars">
): { notification: { text: string }; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`clicksend-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { notification: resolveClickSendNotification(record, config), index };
}

/**
 * Map one ClickSend POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says ClickSend could not
 * accept the message right now, not that the payload is
 * poison. Every other non-2xx status (400, 401, 403,
 * 404, and the rest) is a fail-closed message: unknown
 * number, invalid body, bad credentials, or another verdict
 * retrying cannot change. Callers only pass non-2xx
 * statuses here; a 2xx status is a success, not a failure.
 */
export function classifyClickSendRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * ClickSend sink (WR-268). One instance targets one
 * ClickSend account, one sender number,
 * and one recipient number; the caller owns retry /
 * dead-letter policy around `send()` — this class
 * performs one POST attempt per message through the
 * injected client and reports its outcome. Failures
 * throw `ClickSendSinkError` carrying exactly the failed
 * messages with their retry lanes.
 */
export class ClickSendSink {
  private readonly cfg: ClickSendSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: ClickSendSinkConfig) {
    assertValidClickSendSinkConfig(config, "ClickSendSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): ClickSendSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages by SMS, in input order. Throws
   * `ClickSendSinkConfigError` when no client was injected
 * or the sender or recipient is missing, and
 * `ClickSendSinkError` when any message
   * fails (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: ClickSendRecord[]): Promise<ClickSendSendResult> {
    const resolved = records.map((r, i) => resolveClickSendRecord(r, i, this.cfg));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The
      // numbers and client are
      // not required here, mirroring the sibling sinks'
      // dry-run exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new ClickSendSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const from = this.cfg.from;
    if (from === undefined) {
      throw new ClickSendSinkConfigError("no sender configured (set `from` in the sink config)");
    }
    const to = this.cfg.to;
    if (to === undefined) {
      throw new ClickSendSinkConfigError("no recipient configured (set `to` in the sink config)");
    }
    const url = CLICKSEND_SEND_URL;
    const failedRecords: ClickSendFailedRecord[] = [];
    let sent = 0;
    for (const record of resolved) {
      try {
        const response = await client.post({
          url,
          body: buildClickSendMessageBody(
            from,
            to,
            record.notification.body,
            this.cfg.source ?? CLICKSEND_DEFAULT_SOURCE
          ),
        });
        if (response.status >= 200 && response.status < 300) {
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyClickSendRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toClickSendFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new ClickSendSinkError(
        `clicksend-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toClickSendFailedRecord(err: unknown, index: number): ClickSendFailedRecord {
  const failed: ClickSendFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
