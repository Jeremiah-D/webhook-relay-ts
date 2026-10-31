/**
 * Pushwoosh push notification delivery sink (WR-281).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's device. Where the Expo sink
 * (WR-280) delivers push notifications through Expo's push
 * API with no authentication by default and a flat
 * `{to, title, body}` envelope plus a per-message ticket,
 * this sink delivers push notifications through
 * Pushwoosh's Remote API: one event is sent as one POST
 * to Pushwoosh's `/createMessage` endpoint, and
 * Pushwoosh — not the relay — owns the device routing,
 * the delivery, and the retention of the notification.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Pushwoosh
 * server. The sink owns the relay-side concerns — message
 * targeting, notification derivation, payload-inclusion
 * policy, per-message failure mapping — and the injected
 * client owns the wire protocol, including the POST call,
 * the authentication, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://api.pushwoosh.com/json/1.3/createMessage",
 *     headers: {},
 *     body: "{\"request\":{\"application\":\"<application code>\",\"auth\":\"<API access token>\",\"notifications\":[{\"send_date\":\"now\",\"content\":\"<content>\"}]}}" }
 *
 * The client POSTs to that fixed URL, sending `body`
 * verbatim as the request body (a JSON object) and
 * `headers` verbatim as the request headers. Four things
 * about this shape are deliberate, and all follow the
 * sibling sinks:
 *
 * - The API access token rides in the request body, not
 *   in a header: Pushwoosh's Remote API authenticates
 *   with the `auth` field inside `request` (the
 *   Mandrill/SMTP2GO sinks' WR-247 key-in-body precedent),
 *   so the token is configured on the sink and handed to
 *   the client inside the serialized body — the client
 *   alone sends it at wire time, and it is never logged.
 *   Nothing about the token ever appears in the URL.
 * - The host is fixed, not configurable: the endpoint
 *   above is Pushwoosh's Remote API. A configurable URL
 *   here could only misroute a message to a server that
 *   is not Pushwoosh. The fixed host is the documented
 *   default; the client adapter owns nothing about the
 *   host.
 * - The response carries an API-level verdict, not just
 *   an HTTP status: a 200 returns `{"status_code": 200,
 *   "status_message": "OK", "response": {"Messages":
 *   ["<message id>", ...]}}`, and the message ids are
 *   acceptance receipts only, not delivery results
 *   (delivery confirmation lives in Pushwoosh's logs).
 *   The client surfaces the parsed `status_code` /
 *   `status_message` on the response, and the sink reads
 *   them — a 200 whose `status_code` is not 200 or whose
 *   `status_message` is not `"OK"` is a refused message,
 *   not an accepted one. A missing verdict on a 2xx is
 *   retryable too: without it the sink cannot claim the
 *   message was accepted.
 * - `createMessage` is marked Deprecated in Pushwoosh's
 *   current documentation (the unified Messaging API v2
 *   is its successor), but it remains fully operational.
 *   This sink pins `createMessage` per the backlog item,
 *   which was written against the current docs; a future
 *   item can add the v2 endpoint as a separate sink
 *   rather than silently changing this one's wire shape.
 *
 * This sink is orthogonal to the OneSignal sink (WR-275):
 * OneSignal posts with a Basic header and an `app_id`
 * plus player-id targeting and a `headings`/`contents`
 * envelope, while Pushwoosh posts with the token in the
 * body and an `application`/`auth` pair plus a
 * `request`/`notifications` envelope. It is likewise
 * distinct from the FCM sink (WR-276): FCM posts a
 * project-level endpoint with an OAuth Bearer token the
 * client alone holds and a `{message: {token,
 * notification}}` envelope, while Pushwoosh posts a
 * single fixed endpoint with a body-carried token and a
 * `notifications` array whose entries carry `send_date`
 * and `content`.
 *
 * The application code and the API access token are
 * configured, not derived from the event. One sink
 * targets one Pushwoosh application. A missing
 * application code or token is a config error, not a
 * resolution fallback: unlike the broker sinks, there is
 * no per-record target to resolve to, so a sink with no
 * application or token has nowhere to deliver and fails
 * closed with `PushwooshSinkConfigError` at send time
 * (dry runs excepted — they need neither, mirroring the
 * sibling sinks' dry-run exemption for the client).
 *
 * Targeting — by default a notification goes to the
 * whole application audience (a broadcast): the sink
 * sends no `devices` and no `conditions` unless the
 * operator configured them. `devices` (up to 1000 tokens
 * or hwids) and `conditions` (Pushwoosh's
 * `[field, operator, value]` condition triples) are
 * held by the sink config and passed through into the
 * notification object verbatim; the sink does not invent
 * a targeting rule, and targeting by user id, segment,
 * or filter is out of this item's default scope.
 *
 * Message content — a push notification carries one
 * text field here, so the event's values collapse into
 * it: `content` takes the first non-empty value among
 * `subject`, `key`, and `traceId`, in that order — the
 * subject is what the event is about, the key (e.g.
 * aggregate id) is the next most identifying value, and
 * the trace id names the trace that produced the event.
 * An event with none of the values still notifies, with
 * the generic summary `webhook event` as its content: a
 * notification sink that silently dropped sourceless
 * events would hide exactly the deliveries an operator
 * most needs to see, and the application — not the
 * content — is the delivery contract here, so no
 * invented target is at stake. `send_date` is always
 * `"now"`: the relay delivers immediately; scheduled
 * delivery is out of scope for this sink.
 *
 * Payload inclusion — by default the notification carries
 * the summary only, never the full payload: event bodies
 * routinely carry PII, secrets, or customer data, and a
 * device is a far wider audience than a queue or a
 * stream. Opting into `includePayload` appends the body
 * verbatim after a blank line, truncated to
 * `payloadMaxChars` characters (default 2000) with a
 * truncation marker — the opt-in is explicit, and the
 * truncation is unconditional, so even an opted-in body
 * cannot flood a device. The body is appended as plain
 * text inside the `content` field, not a fenced code block:
 * the field is already plain text, and a fence around an
 * already-JSON body would be noise on a device.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over the HTTP status and, on a 2xx, over the API-level
 * verdict:
 *
 * - a non-2xx POST throws `PushwooshSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Pushwoosh could
 *   not accept the message right now, not that the payload
 *   is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (unknown application, invalid body, bad
 *   API token): retrying them burns the retry budget
 *   for nothing, and rerouting them elsewhere would
 *   notify devices the operator never chose;
 * - on a 2xx, the API verdict decides: `status_code`
 *   200 with `status_message` `"OK"` means Pushwoosh
 *   accepted the message (the `Messages` ids are
 *   acceptance receipts); any other `status_code` is a
 *   refusal mapped by the same rule — 429 and 5xx-range
 *   codes are retryable, everything else (e.g. 210
 *   access denied, 400 bad request) is fail-closed;
 *   a 2xx with no verdict surfaced at all is retryable
 *   too — the verdict is the acceptance result, and a
 *   missing verdict means the sink cannot claim the
 *   message was accepted;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client, application code, or API token
 *   throws `PushwooshSinkConfigError`, which
 *   `classifyFailure` maps to `non_retryable` (the
 *   WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for the content field. */
export const PUSHWOOSH_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const PUSHWOOSH_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Fixed Pushwoosh Remote API createMessage endpoint for every message. */
export const PUSHWOOSH_CREATE_MESSAGE_URL =
  "https://api.pushwoosh.com/json/1.3/createMessage";

/**
 * One notification entry inside the `request.notifications`
 * array: `send_date` is always `"now"` (the relay delivers
 * immediately), `content` is the notification text, and
 * `devices` / `conditions` are passed through verbatim
 * only when the sink config holds them — targeting is the
 * operator's choice, never invented by the sink.
 */
export interface PushwooshNotification {
  /** Always `"now"`: the relay delivers immediately; scheduled delivery is out of scope. */
  send_date: string;
  /** The notification text, derived from subject → key → traceId, falling back to `webhook event`. */
  content: string;
  /**
   * Optional device targeting (up to 1000 tokens or hwids):
   * when set, the message goes only to these devices.
   */
  devices?: string[];
  /**
   * Optional audience conditions (Pushwoosh `[field, operator,
   * value]` triples): when set, the message goes only to
   * matching devices.
   */
  conditions?: unknown[];
}

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (a JSON object with `request`:
 * `{application, auth, notifications}`) to the fixed
 * createMessage endpoint, sending `headers` verbatim as
 * the request headers. `headers` is empty — Pushwoosh
 * authenticates with the `auth` field inside the body,
 * never with a header — and the client is expected to set
 * the `application/json` content type. The API access
 * token never enters the URL and is never logged: the
 * client alone sends it, inside the body, at wire time.
 */
export interface PushwooshMessagePostRequest {
  /** Always the fixed Pushwoosh createMessage endpoint. */
  url: string;
  /**
   * Request headers, sent verbatim: `{}` — Pushwoosh
   * authenticates in the body, so no auth header exists.
   */
  headers: Record<string, string>;
  /** The JSON message object, serialized: `request` with `application`, `auth`, `notifications`. */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * The HTTP status drives the HTTP retry mapping; on a 2xx
 * the client surfaces the API-level verdict parsed from the
 * response body — `statusCode` (`status_code`) and
 * `statusMessage` (`status_message`) — and the verdict,
 * not the status alone, decides whether the message was
 * accepted. `messageIds` carries the `response.Messages`
 * array: acceptance receipts only, not delivery results.
 * A client that reports a 2xx without a verdict leaves the
 * sink unable to claim acceptance, so the message is
 * treated as a retryable verdict failure.
 */
export interface PushwooshMessagePostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
  /**
   * The API-level status code parsed from the response
   * body (`status_code`), on a 2xx: 200 with
   * `status_message` `"OK"` means Pushwoosh accepted the
   * message.
   */
  statusCode?: number;
  /**
   * The API-level status message parsed from the response
   * body (`status_message`), on a 2xx.
   */
  statusMessage?: string;
  /**
   * The message ids parsed from `response.Messages`, on an
   * accepted POST: acceptance receipts only, not delivery
   * results.
   */
  messageIds?: string[];
}

/**
 * The injected Pushwoosh message client. Any client adapter
 * implements this one method; it returns the POST's status
 * and, on a 2xx, the API-level verdict parsed from the
 * response body (a throw is a codeless transport failure,
 * retryable). The client is expected to POST one message
 * per call, sending `body` verbatim as the request body
 * (the JSON object with `request`), sending `headers`
 * verbatim as the request headers, and setting the
 * `application/json` content type. The client never
 * invents an `Authorization` header: Pushwoosh
 * authenticates with the `auth` field inside the body.
 */
export interface PushwooshMessageClient {
  post(request: PushwooshMessagePostRequest): Promise<PushwooshMessagePostResponse>;
}

/**
 * Configuration for one Pushwoosh sink. The client is
 * injected: without one, `send()` throws
 * `PushwooshSinkConfigError` (dry runs excepted — they need
 * no client at all). A missing application code or API
 * token is likewise a config error at send time (dry runs
 * excepted): there is no per-record target to fall back
 * to. The API token is configured here only so the sink
 * can hand it to the client inside the request body —
 * Pushwoosh's documented auth shape — never in a header,
 * never in the URL, never logged.
 */
export interface PushwooshSinkConfig {
  /**
   * The Pushwoosh application code (`application`): every
   * message is delivered to this one application. Must be
   * a non-empty string, free of NUL and whitespace, when
   * set; a missing code throws `PushwooshSinkConfigError`
   * at send time.
   */
  application?: string;
  /**
   * The Pushwoosh API access token (`auth`, from the
   * Control Panel → Settings → API Access). The sink hands
   * it to the client inside the request body at send time
   * — never in a header, never in the URL, never logged.
   * Must be a non-empty string, free of NUL and
   * whitespace, when set; a missing token throws
   * `PushwooshSinkConfigError` at send time.
   */
  auth?: string;
  /**
   * Optional device targeting: up to 1000 tokens or hwids.
   * When set, the message goes only to these devices;
   * when absent, the notification goes to the whole
   * application audience (a broadcast).
   */
  devices?: string[];
  /**
   * Optional audience conditions (Pushwoosh `[field,
   * operator, value]` triples, passed through verbatim).
   * When set, the message goes only to matching devices;
   * when absent, no condition filters the audience.
   */
  conditions?: unknown[];
  /**
   * The Pushwoosh message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `PushwooshMessageClient`. Required for real sends;
   * a missing client is a config error, not a silent no-op.
   */
  client?: PushwooshMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including notification derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The application code, API token, and client are
   * not required in dry-run mode, mirroring the sibling
   * sinks' dry-run exemption.
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
   * the opt-in is set, so an opted-in body cannot flood a
   * device. Must be a positive integer when set.
   */
  payloadMaxChars?: number;
}

/** One event to notify about. */
export interface PushwooshRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Content-derivation source, first priority: the event's
   * subject, when set and non-empty.
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
export interface PushwooshFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /**
   * Failure code: `HTTP_<status>` for a non-2xx POST,
   * `PUSHWOOSH_<status_code>` for a 2xx whose API verdict
   * refused the message, `PUSHWOOSH_STATUS_MESSAGE` for a
   * 2xx with `status_code` 200 but a non-`"OK"`
   * `status_message`, `RESPONSE_MISSING` for a 2xx with no
   * verdict surfaced, or `TRANSPORT_ERROR` for a codeless
   * failure.
   */
  errorCode: string;
  /** Downstream HTTP status, when the failure was a non-2xx POST. */
  statusCode?: number;
  /** API-level status message, when the failure was a refused verdict. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping, extended by the
   * API verdict: 429 and 5xx (plus codeless transport
   * failures and missing verdicts) are retryable; every
   * other non-2xx status — and every non-transient API
   * verdict (e.g. 210 access denied, 400 bad request) —
   * is a fail-closed message.
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface PushwooshSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-281). */
export interface PushwooshSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Pushwoosh send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on Pushwoosh's server and are *not* in
 * `failedRecords`.
 */
export class PushwooshSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: PushwooshFailedRecord[];
  constructor(message: string, failedRecords: PushwooshFailedRecord[]) {
    super(message);
    this.name = "PushwooshSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, or the application code or API token
 * is missing. A config problem, not a downstream verdict, so the retry
 * queue must not burn attempts on it (`classifyFailure`
 * maps it to `non_retryable`).
 */
export class PushwooshSinkConfigError extends PushwooshSinkError {
  constructor(reason: string) {
    super(`pushwoosh-sink: ${reason}`, []);
    this.name = "PushwooshSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing application code or API token is *not* a shape error: it is
 * a config error raised at send time (`PushwooshSinkConfigError`), so a
 * sink built before its credentials are known still fails closed at
 * send time rather than crashing at construction. A present
 * `application` or `auth` value must be a non-empty string, free of
 * NUL and whitespace.
 */
export function assertValidPushwooshSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is PushwooshSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  for (const field of ["application", "auth"] as const) {
    const value = c[field];
    if (value !== undefined) {
      if (
        typeof value !== "string" ||
        value === "" ||
        value.includes("\0") ||
        /\s/.test(value)
      ) {
        throw new RangeError(
          at(`\`${field}\` must be a non-empty string, free of NUL and whitespace when set`)
        );
      }
    }
  }
  const devices = c.devices;
  if (devices !== undefined) {
    if (
      !Array.isArray(devices) ||
      devices.some(
        (d) =>
          typeof d !== "string" || d === "" || d.includes("\0") || /\s/.test(d)
      )
    ) {
      throw new RangeError(
        at("`devices` must be an array of non-empty strings, free of NUL and whitespace, when set")
      );
    }
  }
  const conditions = c.conditions;
  if (conditions !== undefined && !Array.isArray(conditions)) {
    throw new RangeError(at("`conditions` must be an array when set"));
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
 * Derive one record's notification content: the first non-empty
 * value among `subject`, `key`, and `traceId`, in that
 * order. Falls back to the generic `webhook event` summary
 * when the record carries none — a notification sink must
 * not silently drop sourceless events, and the application
 * (not the content) is the delivery contract.
 */
export function resolvePushwooshContent(record: PushwooshRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return PUSHWOOSH_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a device.
 */
export function truncatePushwooshPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Build one record's notification entry: `send_date`
 * `"now"` and `content` from the first non-empty among
 * `subject`, `key`, and `traceId` (falling back to
 * `webhook event`), then the event body appended after a
 * blank line only under the `includePayload` opt-in
 * (truncated to `payloadMaxChars`, default 2000).
 * `devices` / `conditions` are passed through verbatim
 * only when the sink config holds them.
 */
export function buildPushwooshNotification(
  record: PushwooshRecord,
  config: Pick<
    PushwooshSinkConfig,
    "devices" | "conditions" | "includePayload" | "payloadMaxChars"
  >
): PushwooshNotification {
  let content = resolvePushwooshContent(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? PUSHWOOSH_DEFAULT_PAYLOAD_MAX_CHARS;
    content = `${content}\n\n${truncatePushwooshPayload(record.body, limit)}`;
  }
  const notification: PushwooshNotification = { send_date: "now", content };
  if (config.devices !== undefined) {
    notification.devices = [...config.devices];
  }
  if (config.conditions !== undefined) {
    notification.conditions = [...config.conditions];
  }
  return notification;
}

/**
 * Build one record's serialized request body: the JSON
 * object with `request` carrying `application`, `auth`,
 * and a single-entry `notifications` array. The API access
 * token appears here — Pushwoosh's documented auth shape
 * — never in a header, never in the URL, never logged.
 */
export function buildPushwooshMessageBody(
  application: string,
  auth: string,
  notification: PushwooshNotification
): string {
  return JSON.stringify({
    request: { application, auth, notifications: [notification] },
  });
}

/**
 * Validate one record's body. Throws `RangeError` on an
 * empty body string — even without the opt-in, the body is
 * the record's payload, and an empty record is a caller
 * bug that must fail closed, never notify as an empty
 * message.
 */
export function resolvePushwooshRecord(
  record: PushwooshRecord,
  index: number
): { index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`pushwoosh-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { index };
}

/**
 * Map one Pushwoosh POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says Pushwoosh could not
 * accept the message right now, not that the payload is
 * poison. Every other non-2xx status (400, 401, 403,
 * 404, and the rest) is a fail-closed message: unknown
 * application, invalid body, bad API token, or another
 * verdict retrying cannot change. Callers only pass
 * non-2xx statuses here; a 2xx status is decided by the
 * API verdict, not by this function.
 */
export function classifyPushwooshRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Map one Pushwoosh API verdict onto its failed record, or
 * `null` when the verdict accepted the message
 * (`status_code` 200 with `status_message` `"OK"`). A
 * non-200 `status_code` is refused with
 * `PUSHWOOSH_<status_code>`; the retry lane follows the
 * same rule as the HTTP mapping — 429 and 5xx-range codes
 * are transient and retryable, everything else (e.g. 210
 * access denied, 400 bad request) is fail-closed. A 200
 * with a non-`"OK"` message is a verdict the sink cannot
 * treat as acceptance (fail-closed). A missing verdict (a
 * 2xx with nothing surfaced) is retryable — the verdict is
 * the acceptance result, and without it the sink cannot
 * claim the message was accepted.
 */
export function pushwooshVerdictToFailedRecord(
  response: PushwooshMessagePostResponse,
  index: number
): PushwooshFailedRecord | null {
  const statusCode = response.statusCode;
  const statusMessage = response.statusMessage;
  if (statusCode === undefined) {
    return {
      index,
      errorCode: "RESPONSE_MISSING",
      errorMessage: "Pushwoosh answered 2xx but surfaced no API verdict",
      retryable: true,
    };
  }
  if (statusCode === 200 && statusMessage === "OK") {
    return null;
  }
  if (statusCode === 200) {
    return {
      index,
      errorCode: "PUSHWOOSH_STATUS_MESSAGE",
      errorMessage: `Pushwoosh answered status_code 200 with status_message ${JSON.stringify(statusMessage)}`,
      retryable: false,
    };
  }
  const failed: PushwooshFailedRecord = {
    index,
    errorCode: `PUSHWOOSH_${statusCode}`,
    statusCode,
    retryable: statusCode === 429 || statusCode >= 500,
  };
  if (statusMessage !== undefined && statusMessage !== "") {
    failed.errorMessage = statusMessage;
  }
  return failed;
}

/**
 * Pushwoosh sink (WR-281). One instance targets one
 * Pushwoosh application; the caller owns retry / dead-letter
 * policy around `send()` — this class performs one POST
 * attempt per message through the injected client and
 * reports its outcome. Failures throw `PushwooshSinkError`
 * carrying exactly the failed messages with their retry
 * lanes.
 */
export class PushwooshSink {
  private readonly cfg: PushwooshSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: PushwooshSinkConfig) {
    assertValidPushwooshSinkConfig(config, "PushwooshSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): PushwooshSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send push notifications, in input order. Throws
   * `PushwooshSinkConfigError` when no client was injected
   * or the application code or API token is missing, and
   * `PushwooshSinkError` when any message fails (carrying
   * exactly the failed messages with their retry lanes;
   * both counted in stats before throwing, so the counters
   * stay honest even for callers that only inspect stats).
   */
  async send(records: PushwooshRecord[]): Promise<PushwooshSendResult> {
    const resolved = records.map((r, i) => resolvePushwooshRecord(r, i));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The
      // application code, API token, and client are
      // not required here, mirroring the sibling sinks'
      // dry-run exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new PushwooshSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const application = this.cfg.application;
    if (application === undefined) {
      throw new PushwooshSinkConfigError(
        "no application code configured (set `application` in the sink config)"
      );
    }
    const auth = this.cfg.auth;
    if (auth === undefined) {
      throw new PushwooshSinkConfigError(
        "no API access token configured (set `auth` in the sink config)"
      );
    }
    const failedRecords: PushwooshFailedRecord[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          url: PUSHWOOSH_CREATE_MESSAGE_URL,
          headers: {},
          body: buildPushwooshMessageBody(
            application,
            auth,
            buildPushwooshNotification(records[i], this.cfg)
          ),
        });
        if (response.status >= 200 && response.status < 300) {
          const verdictFailure = pushwooshVerdictToFailedRecord(response, record.index);
          if (verdictFailure === null) {
            sent += 1;
            continue;
          }
          failedRecords.push(verdictFailure);
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyPushwooshRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toPushwooshFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new PushwooshSinkError(
        `pushwoosh-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toPushwooshFailedRecord(err: unknown, index: number): PushwooshFailedRecord {
  const failed: PushwooshFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
