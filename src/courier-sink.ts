/**
 * Courier notification delivery sink (WR-279).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's inbox. Where the Braze sink
 * (WR-278) delivers through Braze's `/messages/send` API
 * with an `external_user_ids` + `messages.email` envelope,
 * this sink delivers through Courier's `/send` API: one
 * event notification, and Courier — not the relay — owns
 * the channels, the routing, and the delivery of the
 * message.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Courier
 * server. The sink owns the relay-side concerns — message
 * targeting, title and body derivation, payload-inclusion
 * policy, per-message failure mapping — and the injected
 * client owns the wire protocol, including the POST call,
 * the authentication, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://api.courier.com/send",
 *     body: "{\"message\":{\"to\":{\"email\":\"<email>\"},\"content\":{\"title\":\"<title>\",\"body\":\"<body>\"}}}" }
 *
 * The client POSTs to that fixed URL, sending `body`
 * verbatim as the request body (a JSON object) and
 * authenticating with an `Authorization: Bearer <API key>`
 * header carrying an API key it alone holds — Courier's
 * header-auth shape, not a body-carried key. Three things
 * about this shape are deliberate, and all follow the
 * sibling sinks:
 *
 * - The API key is held by the client alone. The sink
 *   never receives it, never places it in the request,
 *   and never logs it: like the Braze sink (WR-278),
 *   whose Bearer key the client alone holds, this sink's
 *   handed request carries no credential at all — the
 *   client adds the `Authorization: Bearer` header from
 *   the key it alone holds, so there is nothing in the
 *   handed request for a log line or a retry queue to
 *   leak. This is the opposite of the SMTP2GO sink
 *   (WR-271), whose key rides inside the wire body at
 *   wire time: Courier authenticates by header, so the
 *   body carries only routing and content.
 * - The host is fixed, not configurable: the endpoint
 *   above is Courier's send API. Courier's EU data
 *   center uses its own host (`api.eu.courier.com`),
 *   and an operator on that data center points their
 *   client adapter at that host — the sink itself never
 *   takes a URL, because a configurable URL here could
 *   only misroute a message to a server that is not
 *   Courier. The fixed host is the documented default;
 *   the client adapter owns the data center.
 * - The response's `requestId` is only an acceptance
 *   receipt, not a delivery result: a 2xx with a
 *   `requestId` means Courier accepted the message for
 *   routing, not that any channel delivered it.
 *   Delivery confirmation lives in Courier's logs, not
 *   in this sink — the sink's retry mapping reads the
 *   HTTP status only, and the client need not surface
 *   the `requestId` at all (it is accepted as an
 *   optional field on the response, documented as a
 *   receipt). Treating acceptance as delivery would
 *   overstate what the relay knows.
 *
 * This sink is orthogonal to the Braze sink (WR-278):
 * Braze posts an `external_user_ids` array plus a
 * `messages.email` envelope addressed to users it already
 * knows, while Courier posts a `message` envelope with
 * `to.email` and inline `content` addressed to one
 * configured email — two vendors whose envelopes share
 * nothing but the header-auth shape, because Courier
 * routes by channel and recipient, not by a profile id.
 * It is likewise distinct from the Mailtrap sink (WR-273):
 * Mailtrap posts a `from` object / `to` object-array
 * envelope with a Bearer key, while Courier posts a
 * single-recipient `message/to/content` envelope with a
 * Bearer key — one channel's email send versus a
 * multi-channel notification API.
 *
 * The recipient is configured, not derived from the event.
 * One sink targets one recipient email. A missing
 * recipient is a config error, not a resolution fallback:
 * unlike the broker sinks, there is no per-record target
 * to resolve to, so a sink with no recipient has nowhere
 * to deliver and fails closed with
 * `CourierSinkConfigError` at send time (dry runs excepted
 * — they need no recipient at all, mirroring the sibling
 * sinks' dry-run exemption for the client).
 *
 * Message text — derived from the event's own values,
 * split across the envelope's two text fields. The title
 * takes the first non-empty value among `subject` and
 * `key`, in that order: the subject is what the event is
 * about, the key (e.g. aggregate id) is the next most
 * identifying value. The body takes the first non-empty
 * value among `subject`, `key`, and `traceId`, in that
 * order — the trace id names the trace that produced the
 * event, and it belongs in the body even though it is too
 * opaque for a title. An event with none of the values
 * still notifies, with the generic summary
 * `webhook event` in both fields: a notification sink
 * that silently dropped sourceless events would hide
 * exactly the deliveries an operator most needs to see,
 * and the recipient — not the text — is the delivery
 * contract here, so no invented target is at stake.
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
 * `body` field, not a fenced code block: the field is
 * already plain text, and a fence around an already-JSON
 * body would be noise in an inbox. No template is used:
 * this sink sends inline `content` only, with no template
 * dependency.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over HTTP status:
 *
 * - a non-2xx POST throws `CourierSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Courier could
 *   not accept the message right now, not that the
 *   payload is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (unknown recipient, invalid body, bad
 *   API key): retrying them burns the retry budget for
 *   nothing, and rerouting them elsewhere would notify
 *   a recipient the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client or recipient throws
 *   `CourierSinkConfigError`, which `classifyFailure`
 *   maps to `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for a text field. */
export const COURIER_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const COURIER_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Fixed Courier send endpoint for every message. */
export const COURIER_SEND_URL = "https://api.courier.com/send";

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (a JSON object with `message`) to
 * the fixed send endpoint, and authenticates with an
 * `Authorization: Bearer <API key>` header carrying an
 * API key it alone holds. The sink never sees that key, so
 * the request carries no credential: nothing here can leak
 * into a log line.
 */
export interface CourierMessagePostRequest {
  /** Always the fixed Courier send endpoint. */
  url: string;
  /** The JSON message object, serialized: `message` with `to` and `content`. */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse Courier's response body. A 2xx
 * response carries Courier's `requestId` — an acceptance
 * receipt only, not a delivery result (delivery
 * confirmation lives in Courier's logs) — so it is
 * accepted here as an optional field and never read by
 * the sink.
 */
export interface CourierMessagePostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
  /**
   * Courier's acceptance receipt for the message, when
   * the client surfaces it. Not a delivery result: a
   * 2xx with a `requestId` means Courier accepted the
   * message for routing, not that any channel
   * delivered it.
   */
  requestId?: string;
}

/**
 * The injected Courier message client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one message per call, sending
 * `body` verbatim as the request body (the JSON object
 * with `message`), setting the `application/json` content
 * type, and authenticating with an `Authorization: Bearer
 * <API key>` header carrying its own API key — which the
 * sink never sees. An operator on Courier's EU data
 * center points the client at that data center's host
 * (`api.eu.courier.com`).
 */
export interface CourierMessageClient {
  post(request: CourierMessagePostRequest): Promise<CourierMessagePostResponse>;
}

/**
 * Configuration for one Courier sink. The client is
 * injected: without one, `send()` throws
 * `CourierSinkConfigError` (dry runs excepted — they need
 * no client at all). A missing recipient is likewise a
 * config error at send time (dry runs excepted): there is
 * no per-record target to fall back to. The API key is
 * deliberately absent from this config: the client alone
 * holds it and sends it as the `Authorization: Bearer`
 * header. No template is configured here: this sink sends
 * inline `content` only.
 */
export interface CourierSinkConfig {
  /**
   * The recipient email (the `email` of `message.to`):
   * the address every message is sent to. Must be a
   * non-empty string, free of NUL and whitespace, when
   * set; a missing recipient throws
   * `CourierSinkConfigError` at send time.
   */
  to?: string;
  /**
   * The Courier message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `CourierMessageClient` and alone holds the
   * API key. Required for real sends; a missing client is
   * a config error, not a silent no-op.
   */
  client?: CourierMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including text derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The recipient and client are not required in dry-run
   * mode, mirroring the sibling sinks' dry-run exemption.
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
   * the opt-in is set, so an opted-in body cannot flood an
   * inbox. Must be a positive integer when set.
   */
  payloadMaxChars?: number;
}

/** One event to notify about. */
export interface CourierRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Text-derivation source, first priority: the event's
   * subject, when set and non-empty. Falls through to `key`
   * for the title, and to `key`, then `traceId`, for the
   * body.
   */
  subject?: string;
  /**
   * Text-derivation source, second priority: the event's key
   * (e.g. aggregate id).
   */
  key?: string;
  /**
   * Text-derivation source, last priority for the body:
   * the trace id. Never used for the title — too
   * opaque for a title line.
   */
  traceId?: string;
}

/** One failed message, with its retry lane already mapped. */
export interface CourierFailedRecord {
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
   * non-2xx status is a fail-closed message (unknown
   * recipient, invalid body, bad API key).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface CourierSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-279). */
export interface CourierSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Courier send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on Courier's server and are *not* in
 * `failedRecords`.
 */
export class CourierSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: CourierFailedRecord[];
  constructor(message: string, failedRecords: CourierFailedRecord[]) {
    super(message);
    this.name = "CourierSinkError";
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
export class CourierSinkConfigError extends CourierSinkError {
  constructor(reason: string) {
    super(`courier-sink: ${reason}`, []);
    this.name = "CourierSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing recipient is *not* a shape error: it is a config error
 * raised at send time (`CourierSinkConfigError`), so a sink built
 * before its recipient is known still fails closed at send time
 * rather than crashing at construction. A present recipient must
 * be a non-empty string, free of NUL and whitespace.
 */
export function assertValidCourierSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is CourierSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  const to = c.to;
  if (to !== undefined) {
    if (
      typeof to !== "string" ||
      to === "" ||
      (to as string).includes("\0") ||
      /\s/.test(to as string)
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
 * Derive one record's title: the first non-empty value
 * among `subject` and `key`, in that order. Falls back to
 * the generic `webhook event` summary when the record
 * carries neither — the envelope always needs a title,
 * and a notification sink must not silently drop sourceless
 * events. The trace id is deliberately not a title
 * source: it is too opaque for a title, and belongs in
 * the body instead.
 */
export function resolveCourierTitle(record: CourierRecord): string {
  for (const value of [record.subject, record.key]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return COURIER_FALLBACK_SUMMARY;
}

/**
 * Derive one record's body: the first non-empty
 * value among `subject`, `key`, and `traceId`, in that
 * order. Falls back to the generic `webhook event` summary
 * when the record carries none — a notification sink must
 * not silently drop sourceless events, and the recipient
 * (not the text) is the delivery contract.
 */
export function resolveCourierBody(record: CourierRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return COURIER_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood an inbox.
 */
export function truncateCourierPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's notification: its title and its
 * body. Only under the `includePayload` opt-in
 * does the body append the event body verbatim after a
 * blank line, truncated to `payloadMaxChars` (default
 * 2000). Without the opt-in, the body is the summary
 * alone: event bodies routinely carry PII and must never
 * leak into a notification by default. The body is
 * appended as plain text inside the `body` field, not a
 * fenced code block.
 */
export function resolveCourierNotification(
  record: CourierRecord,
  config: Pick<CourierSinkConfig, "includePayload" | "payloadMaxChars">
): { title: string; body: string } {
  const title = resolveCourierTitle(record);
  let body = resolveCourierBody(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? COURIER_DEFAULT_PAYLOAD_MAX_CHARS;
    body = `${body}\n\n${truncateCourierPayload(record.body, limit)}`;
  }
  return { title, body };
}

/**
 * Build one record's serialized request body: the JSON
 * object with `message` holding `to.email` (the configured
 * recipient) and `content` holding `title` and `body`
 * (inline content — no template), in that order. The API
 * key never appears here — the client alone holds it and
 * sends it as the `Authorization: Bearer` header.
 */
export function buildCourierMessageBody(
  to: string,
  title: string,
  body: string
): string {
  return JSON.stringify({
    message: {
      to: { email: to },
      content: { title, body },
    },
  });
}

/**
 * Validate one record's body and resolve its send form: the
 * notification title and body. Throws `RangeError` on an
 * empty body string — even without the opt-in, the body is
 * the record's payload, and an empty record is a caller bug
 * that must fail closed, never notify as an empty message.
 */
export function resolveCourierRecord(
  record: CourierRecord,
  index: number,
  config: Pick<CourierSinkConfig, "includePayload" | "payloadMaxChars">
): { notification: { title: string; body: string }; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`courier-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { notification: resolveCourierNotification(record, config), index };
}

/**
 * Map one Courier POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says Courier could not
 * accept the message right now, not that the payload is
 * poison. Every other non-2xx status (400, 401, 403,
 * 404, and the rest) is a fail-closed message: unknown
 * recipient, invalid body, bad API key, or another
 * verdict retrying cannot change. Callers only pass
 * non-2xx statuses here; a 2xx status is a success, not
 * a failure.
 */
export function classifyCourierRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Courier sink (WR-279). One instance targets one
 * recipient email; the caller owns retry/dead-letter
 * policy around `send()` — this class performs one POST
 * attempt per message through the injected client and
 * reports its outcome. Failures throw `CourierSinkError`
 * carrying exactly the failed messages with their retry
 * lanes.
 */
export class CourierSink {
  private readonly cfg: CourierSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: CourierSinkConfig) {
    assertValidCourierSinkConfig(config, "CourierSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): CourierSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages by notification, in input order. Throws
   * `CourierSinkConfigError` when no client was injected or
   * the recipient is missing, and `CourierSinkError` when
   * any message fails (carrying exactly the failed messages
   * with their retry lanes; both counted in stats before
   * throwing, so the counters stay honest even for callers
   * that only inspect stats).
   */
  async send(records: CourierRecord[]): Promise<CourierSendResult> {
    const resolved = records.map((r, i) => resolveCourierRecord(r, i, this.cfg));
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
      throw new CourierSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const to = this.cfg.to;
    if (to === undefined) {
      throw new CourierSinkConfigError("no recipient configured (set `to` in the sink config)");
    }
    const failedRecords: CourierFailedRecord[] = [];
    let sent = 0;
    for (const record of resolved) {
      try {
        const response = await client.post({
          url: COURIER_SEND_URL,
          body: buildCourierMessageBody(
            to,
            record.notification.title,
            record.notification.body
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
          retryable: classifyCourierRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toCourierFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new CourierSinkError(
        `courier-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toCourierFailedRecord(err: unknown, index: number): CourierFailedRecord {
  const failed: CourierFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
