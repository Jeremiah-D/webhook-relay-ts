/**
 * Pushy push notification delivery sink (WR-296).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a phone in someone's pocket, reached
 * through a push gateway. Where the WonderPush sink
 * (WR-282) sends through WonderPush's management API
 * with an event notification, and the MagicBell sink
 * (WR-294) triggers a MagicBell workflow with a `Bearer`
 * Project JWT and a `key`/`input` envelope, this sink
 * pushes directly through Pushy's Send Notifications API:
 * one event is sent as one POST that Pushy accepts as one
 * push to one device token, and Pushy — not the relay —
 * owns the push, the delivery to the device, and the
 * delivery status (checked later through the
 * Notification Status API, out of scope here).
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Pushy
 * server. The sink owns the relay-side concerns — the
 * device token, the message derivation, the display
 * layer, the payload-inclusion policy, the per-message
 * failure mapping — and the injected client owns the wire
 * protocol, including the POST call, the authentication,
 * and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://api.pushy.me/push",
 *     headers: { "Content-Type": "application/json" },
 *     body: "{\"to\":\"<device token>\",\"data\":{\"message\":\"<summary>\"},\"notification\":{\"title\":\"<title>\",\"body\":\"<summary>\"}}" }
 *
 * The client POSTs to that URL, sending `body`
 * verbatim as the request body (JSON), sending `headers`
 * verbatim as the request headers, and appending the
 * `?api_key=<SECRET_API_KEY>` query parameter carrying
 * the Secret API Key — which it alone holds. Five things
 * about this shape are deliberate, and all follow the
 * sibling sinks or the backlog pins:
 *
 * - The Secret API Key is held by the client alone. The
 *   sink never receives the key, never places it in the
 *   request, and never logs it: the handed request
 *   therefore carries no credential at all, so there is
 *   nothing in it for a log line or a retry queue to leak
 *   — and the key is never persisted by the sink. The key
 *   rides in the URL as a query parameter (unlike the
 *   `Authorization: Bearer` headers of the MagicBell and
 *   Intercom sinks), so the sink hands the client the bare
 *   endpoint URL and the client appends the parameter:
 *   the sink's URL never contains a key, a placeholder,
 *   or anything that looks like one. This is the Pushy
 *   form of the MagicBell rule (whose Project JWT the
 *   client alone holds as an `Authorization: Bearer`
 *   header), with Pushy's own credential source: the
 *   Secret API Key, taken from the Dashboard -> API
 *   Authentication tab, verified against the current
 *   docs (pushy.me/docs/api/send-notifications and
 *   pushy.me/docs/api#errors, re-checked 2026-11-01 —
 *   "All requests must include an ?api_key=<SECRET_API_KEY>
 *   query parameter", "Never expose your application's
 *   Secret API Key in your client code. All Pushy APIs
 *   are backend APIs.").
 * - The endpoint is the Send Notifications API the
 *   backlog pins: `POST https://api.pushy.me/push`. The
 *   reference describes it as instantly sending push
 *   notifications to your users.
 * - `to` is the config-held device token, a single token,
 *   never a default to an audience. A `/topics/<name>`
 *   topic value is rejected at construction: topic
 *   broadcast is out of scope for this item (the sink
 *   pushes to one device, not to a topic's subscribers),
 *   so a topic string can never silently turn a
 *   single-device push into a broadcast. The token must
 *   already be registered for the app under the Secret
 *   API Key used to authenticate: the reference's
 *   `info.failed` lists tokens "which could not be found
 *   in our database registered under the app with the
 *   Secret API Key used to authenticate this request",
 *   and a `to` that resolves to no recipients at all
 *   surfaces as the endpoint error `NO_RECIPIENTS`
 *   (400). The sink never registers a device.
 * - `data` is the delivery payload, an object the device
 *   receives in its notification listener, limited to
 *   **4kb** in stringified JSON character length
 *   (`PAYLOAD_LIMIT_EXCEEDED`, 400, when exceeded). It
 *   carries `message` — the derived summary — and,
 *   only under the `includePayload` opt-in, `eventBody`
 *   (see below). The 2000-character default truncation
 *   keeps an opted-in body well under the 4kb limit.
 * - `notification` is the display layer, an object with
 *   `title`, `body`, `sound`, and `badge`. Two things
 *   about it are deliberate. First, it is an iOS object:
 *   the reference's schema marks `notification` as
 *   "Object (iOS)", and the docs' Android guidance is
 *   that the app builds its notification from `data` —
 *   so on Android the `notification` object is ignored
 *   and the device-side listener renders from `data`
 *   instead; the sink sends the same body either way and
 *   does not branch per platform. Second, `sound` and
 *   `badge` are config-held and optional, not invented:
 *   `sound` is a filename in the app bundle (the
 *   reference's example is `"ping.aiff"`), and `badge`
 *   is the app-icon badge count, so the sink sends
 *   neither unless the operator configured one — a
 *   fabricated sound filename or badge count would be
 *   worse than none.
 *
 * Acceptance is decided by the HTTP status together with
 * the response body's push acceptance credential: a 200
 * whose body carries an `id` means Pushy accepted the
 * push, and the id is the receipt the operator uses to
 * check delivery status later (`GET /pushes/PUSH_ID`).
 * `send()` returns the collected push ids in send order,
 * so a caller that only inspects the result still has
 * the receipts. A successful response is only an
 * acceptance receipt, not a delivery result: the
 * reference returns `{ success: true, id, info:
 * { devices } }`, and delivery surfaces later through
 * the Notification Status API. A 200 without a push id
 * is a failure (`PUSHY_NO_PUSH_ID`, fail-closed): the
 * reference promises no other receipt, so a 200 with
 * nothing to trace must not turn an untraceable push
 * into an acceptance. Any non-200 status is a failure.
 * The exact HTTP success status is pinned to 200 here,
 * unlike the MagicBell sink: the fetched API reference
 * states "The Pushy API returns a `200 OK` status code
 * with `JSON` response" and "If the request fails, a
 * non-`200 OK` status code is returned", so a 201 is not
 * a documented success for this endpoint and is treated
 * as a failure (`HTTP_201`, fail-closed). The reference's
 * error shape is a body carrying `{ code, error }` — a
 * constant error code plus a helpful description string;
 * when the client surfaces those, they ride on the
 * failure record. `info.failed` (invalid device tokens,
 * "for debugging purposes") plays no part in the
 * verdict: a wholly-invalid single token surfaces as
 * the 400 `NO_RECIPIENTS` error, not as a success with
 * a failed list.
 *
 * Message content — a push carries a message and a
 * display layer, both derived from the event's own
 * values: the first non-empty value among `subject`,
 * `key`, and `traceId`, in that order, is the summary.
 * `data.message` takes that summary, so an event with
 * none of the values still notifies, with the generic
 * summary `webhook event`: a notification sink that
 * silently dropped sourceless events would hide exactly
 * the deliveries an operator most needs to see.
 * `notification.body` takes the same summary, and
 * `notification.title` takes the `subject` alone, when
 * one exists, and is omitted otherwise: a subjectless
 * event pushes with a body and no title rather than a
 * title invented from a key or a trace id.
 *
 * Payload inclusion — by default the push carries the
 * summary only, never the full payload: event bodies
 * routinely carry PII, secrets, or customer data, and a
 * phone's lock screen is a far wider audience than a
 * queue or a stream. Opting into `includePayload` appends
 * the event body as `data.eventBody` — a JSON string
 * carrying the body verbatim, truncated to
 * `payloadMaxChars` characters (default 2000) with a
 * truncation marker — the opt-in is explicit, and the
 * truncation is unconditional, so even an opted-in body
 * cannot flood a device (and stays well under Pushy's
 * 4kb `data` limit). The payload rides in its own field
 * inside `data`, not inside the display body: `data` is
 * the payload the device's listener receives, while
 * `notification.body` is text for the screen.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over the HTTP status:
 *
 * - a non-200 POST, or a 200 whose body carries no push
 *   id, throws `PushySinkError` carrying every failed
 *   message with its retry lane already mapped, so the
 *   caller retries exactly the failed messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Pushy could not
 *   accept the push right now, not that the payload is
 *   poison. The docs pin the limit at 800 requests per
 *   minute for Pro accounts and 60 per minute for Trial
 *   accounts (`RATE_LIMIT_EXCEEDED`, 429); the global
 *   error table pins `INTERNAL_SERVER_ERROR` to 500;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-200 status, including 400 and 403
 *   (bad input or token, bad Secret API Key, suspended
 *   account, no recipients, missing APNs auth, payload
 *   over the 4kb limit), and a 200 whose body carries no
 *   push id: retrying them burns the retry budget for
 *   nothing, and rerouting them elsewhere would notify a
 *   device the operator never chose. Note `403
 *   AUTH_LIMIT_EXCEEDED` (too many auth attempts with an
 *   invalid key in the past hour) is fail-closed too: the
 *   key is wrong, and retrying with the same key only
 *   extends the block;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload (a retry after a
 *   transport failure may send the push a second time —
 *   the reference documents no idempotency key for this
 *   endpoint, so the sink sends none and callers that
 *   need exactly-once behavior should reconcile through
 *   the returned push id whenever one was observed,
 *   rather than blindly replaying a transport failure);
 * - a missing client throws `PushySinkConfigError`,
 *   which `classifyFailure` maps to `non_retryable`
 *   (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only. (No
 * `node:crypto` import either: with no idempotency key to
 * derive, there is nothing to hash.)
 */

/** Generic summary used when an event carries no value for the message body. */
export const PUSHY_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const PUSHY_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Content type the client sends with the JSON body. */
export const PUSHY_JSON_CONTENT_TYPE = "application/json";

/** Pushy API base URL. */
export const PUSHY_API_BASE_URL = "https://api.pushy.me";

/**
 * Send Notifications endpoint, without any credential:
 * the client appends `?api_key=<SECRET_API_KEY>` (the key
 * it alone holds). The sink's URL never contains a key.
 */
export const PUSHY_PUSH_URL = `${PUSHY_API_BASE_URL}/push`;

/** Rate limit the docs pin: API requests per minute, Pro accounts. */
export const PUSHY_RATE_LIMIT_PER_MINUTE_PRO = 800;

/** Rate limit the docs pin: API requests per minute, Trial accounts. */
export const PUSHY_RATE_LIMIT_PER_MINUTE_TRIAL = 60;

/** Pushy `data` payload limit, in stringified JSON characters (per the reference). */
export const PUSHY_DATA_LIMIT_CHARS = 4096;

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (JSON), sends `headers` verbatim
 * as the request headers, and appends the
 * `?api_key=<SECRET_API_KEY>` query parameter carrying
 * the Secret API Key — which the sink never sees. No
 * `Idempotency-Key` header is sent: the docs do not verify
 * it for this endpoint (see the module header).
 */
export interface PushyPushPostRequest {
  /**
   * Always `https://api.pushy.me/push` — the Send
   * Notifications API, without any credential. The client
   * appends `?api_key=<SECRET_API_KEY>`; the device token
   * rides in the body, not the path.
   */
  url: string;
  /**
   * Request headers, sent verbatim:
   * `{ "Content-Type": "application/json" }`. The
   * `api_key` query parameter is added by the client,
   * never by the sink, and there is deliberately no
   * `Idempotency-Key` header.
   */
  headers: Record<string, string>;
  /**
   * The JSON request body, serialized:
   * `{"to":"<device token>","data":{"message":"<summary>"},"notification":{"title":"<title>","body":"<summary>"}}`
   * (`title` is omitted when the event carries no
   * subject; `sound`/`badge` ride in `notification`
   * only when configured; `eventBody` is appended
   * inside `data` only under the `includePayload`
   * opt-in). There is exactly one recipient — the
   * config-held device token — and no topic: the sink
   * never pushes to an audience it was not configured
   * for. No credential ever enters the body.
   */
  body: string;
}

/**
 * The result of one POST, as reported by the injected
 * client. The HTTP status decides acceptance together
 * with the response body's push id: a 200 carrying an
 * `id` means Pushy accepted the push, and the id is the
 * receipt for checking delivery status later
 * (`GET /pushes/PUSH_ID`). A 200 without an id is a
 * failure, not an acceptance. The docs' error shape is
 * a body carrying `{ code, error }`; when the client
 * surfaces those, they ride on the failure record.
 * `info.failed` (invalid device tokens, debug-only)
 * plays no part in the verdict.
 */
export interface PushyPushPostResponse {
  /** The HTTP status of the POST (e.g. 200, 400, 403, 429, 500). */
  status: number;
  /** The push id from the success body, when the client surfaced one. */
  pushId?: string;
  /** The error `code` from the error body, when the client surfaced one (e.g. `INVALID_API_KEY`). */
  code?: string;
  /** The error description from the error body, when the client surfaced one. */
  error?: string;
}

/**
 * The injected Pushy push client. Any client adapter
 * implements this one method; it returns the POST's status
 * and the push id when present — a throw is a codeless
 * transport failure, retryable. The client is expected to
 * POST one push per call, sending `body` verbatim as
 * the request body (JSON), sending `headers` verbatim as
 * the request headers, and appending the
 * `?api_key=<SECRET_API_KEY>` query parameter carrying
 * the Secret API Key — which the sink never sees.
 */
export interface PushyPushClient {
  post(request: PushyPushPostRequest): Promise<PushyPushPostResponse>;
}

/**
 * Configuration for one Pushy sink. The client is
 * injected: without one, `send()` throws
 * `PushySinkConfigError` (dry runs excepted — they need
 * no client at all). The Secret API Key is deliberately
 * absent from this config: the client alone holds it
 * (appended as the `api_key` query parameter), and it is
 * never persisted by the sink.
 */
export interface PushySinkConfig {
  /**
   * The device token: the single device the push is sent
   * to (`to`). Required — a single token, never a default
   * to the whole audience. Must be a non-empty string,
   * and must not be a `/topics/<name>` topic: topic
   * broadcast is out of scope for this item. The token
   * must already be registered for the app under the
   * Secret API Key used to authenticate; the sink never
   * registers a device.
   */
  deviceToken: string;
  /**
   * The Pushy push client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `PushyPushClient` and alone holds the
   * Secret API Key. Required for real sends; a missing
   * client is a config error, not a silent no-op.
   */
  client?: PushyPushClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, pushIds: [], dryRun: true }`
   * and performs zero client I/O — no POST call, no stat
   * changes. Messages are still validated (including
   * message derivation), so a dry run catches a
   * malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The client is not required in dry-run mode, mirroring
   * the sibling sinks' dry-run exemption; the rest of the
   * config must still be valid — a dry run against a sink
   * with no device token would rehearse a request that
   * could never send.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the request body's
   * `data` appends `eventBody` carrying the event body
   * verbatim as a JSON string, truncated to
   * `payloadMaxChars` characters (see below). When
   * `false` or absent, `data` carries the summary only
   * — the default, so event bodies (which routinely
   * carry PII) never leak onto a lock screen unless the
   * operator explicitly asks for them.
   */
  includePayload?: boolean;
  /**
   * Truncation limit for an opted-in payload snippet, in
   * characters (default 2000). Only meaningful with
   * `includePayload`; the truncation is unconditional when
   * the opt-in is set, so an opted-in body cannot flood a
   * device — and stays well under Pushy's 4kb `data`
   * limit. Must be a positive integer when set.
   */
  payloadMaxChars?: number;
  /**
   * Display-layer sound: the filename of a sound in the
   * app bundle (the reference's example is `"ping.aiff"`),
   * sent as `notification.sound` when set. Optional and
   * never invented: omitted unless configured. Must be a
   * non-empty string when set.
   */
  sound?: string;
  /**
   * Display-layer badge: the number to display as the
   * badge of the app icon, sent as `notification.badge`
   * when set. Optional and never invented: omitted unless
   * configured. Must be a non-negative integer when set.
   */
  badge?: number;
}

/** One event to push about. */
export interface PushyRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Content-derivation source, first priority: the event's
   * subject, when set and non-empty. Also the sole source
   * of `notification.title`, when present.
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
export interface PushyFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /**
   * Failure code: `HTTP_<status>` for a non-200 POST,
   * `PUSHY_NO_PUSH_ID` for a 200 whose body carries no
   * push id, or `TRANSPORT_ERROR` for a codeless failure.
   */
  errorCode: string;
  /** Downstream HTTP status, when the failure was a non-200 POST. */
  statusCode?: number;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: 429 and 5xx
   * (plus codeless transport failures) are retryable;
   * every other non-200 status, and a 200 whose body
   * carries no push id, is a fail-closed message (bad
   * input or token, bad Secret API Key, suspended
   * account, no recipients, missing APNs auth, payload
   * over the 4kb limit, or a push Pushy received but
   * gave no id for).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface PushySendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /**
   * Push ids in send order — the id of each accepted
   * message that reported one. Empty in dry-run mode. A
   * 200 without a push id is a failure, so every accepted
   * message contributes exactly one entry here.
   */
  pushIds: string[];
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-296). */
export interface PushySinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Pushy send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already received on Pushy's server and are *not* in
 * `failedRecords`.
 */
export class PushySinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: PushyFailedRecord[];
  constructor(message: string, failedRecords: PushyFailedRecord[]) {
    super(message);
    this.name = "PushySinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class PushySinkConfigError extends PushySinkError {
  constructor(reason: string) {
    super(`pushy-sink: ${reason}`, []);
    this.name = "PushySinkConfigError";
  }
}

/**
 * Validate one configured device token: a non-empty
 * string, and never a `/topics/<name>` topic — topic
 * broadcast is out of scope for this item, so a topic
 * value can never silently turn a single-device push
 * into a broadcast. Throws `RangeError` otherwise.
 */
export function resolvePushyDeviceToken(token: unknown, label: string): string {
  if (typeof token !== "string" || token === "") {
    throw new RangeError(`${label}: must be a non-empty string`);
  }
  if (token.startsWith("/topics/")) {
    throw new RangeError(`${label}: must be a single device token, not a /topics/<name> topic (topic broadcast is out of scope)`);
  }
  return token;
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. The
 * device token is required and enforced here, not at send time:
 * it must be a non-empty string and must not be a topic.
 */
export function assertValidPushySinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is PushySinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  resolvePushyDeviceToken(c.deviceToken, at("`deviceToken`"));
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
  if (
    c.sound !== undefined &&
    (typeof c.sound !== "string" || c.sound === "")
  ) {
    throw new RangeError(at("`sound` must be a non-empty string when set"));
  }
  if (
    c.badge !== undefined &&
    (typeof c.badge !== "number" ||
      !Number.isInteger(c.badge) ||
      c.badge < 0)
  ) {
    throw new RangeError(at("`badge` must be a non-negative integer when set"));
  }
}

/**
 * Derive one record's content summary: the first
 * non-empty value among `subject`, `key`, and `traceId`,
 * in that order. Falls back to the generic `webhook
 * event` summary when the record carries none — a
 * notification sink must not silently drop sourceless
 * events.
 */
export function resolvePushySummary(record: PushyRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return PUSHY_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a device — and stays well
 * under Pushy's 4kb `data` limit.
 */
export function truncatePushyPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's `data` payload: `message` takes the
 * derived summary (the first non-empty among `subject`,
 * `key`, and `traceId`, falling back to `webhook event`)
 * — the payload the device's notification listener
 * receives, so it always has a value. Under the
 * `includePayload` opt-in `eventBody` carries the event
 * body verbatim as a JSON string, truncated to
 * `payloadMaxChars` (default 2000); without the opt-in
 * there is no `eventBody` key at all.
 */
export function resolvePushyData(
  record: PushyRecord,
  config: Pick<PushySinkConfig, "includePayload" | "payloadMaxChars">
): { message: string; eventBody?: string } {
  const data: { message: string; eventBody?: string } = {
    message: resolvePushySummary(record),
  };
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? PUSHY_DEFAULT_PAYLOAD_MAX_CHARS;
    data.eventBody = truncatePushyPayload(record.body, limit);
  }
  return data;
}

/**
 * Derive one record's display layer: `body` takes the
 * derived summary (the same value as `data.message`),
 * `title` takes the `subject` alone when one exists and
 * is omitted otherwise — a subjectless event pushes with
 * a body and no title rather than a title invented from a
 * key or a trace id. `sound` and `badge` ride along only
 * when configured: neither is ever invented. The
 * `notification` object is iOS-only per the reference —
 * on Android the app builds its notification from `data`
 * instead — so the same body is sent either way and the
 * sink does not branch per platform.
 */
export function resolvePushyNotification(
  record: PushyRecord,
  config: Pick<PushySinkConfig, "sound" | "badge">
): { title?: string; body: string; sound?: string; badge?: number } {
  const notification: { title?: string; body: string; sound?: string; badge?: number } = {
    body: resolvePushySummary(record),
  };
  if (record.subject !== undefined && record.subject !== "") {
    notification.title = record.subject;
  }
  if (config.sound !== undefined) {
    notification.sound = config.sound;
  }
  if (config.badge !== undefined) {
    notification.badge = config.badge;
  }
  return notification;
}

/**
 * Build one record's serialized JSON body: the push
 * object with `to` (the single config-held device token),
 * `data` (`message` always, `eventBody` only under the
 * `includePayload` opt-in), and `notification` (`body`
 * always, `title` only when the event carries a subject,
 * `sound`/`badge` only when configured). There is no
 * topic: the sink pushes to one device, never to a
 * `/topics/<name>` audience. No idempotency key: the
 * docs do not verify `Idempotency-Key` for this endpoint.
 * The Secret API Key never appears here — the client
 * alone holds it (appended as the `api_key` query
 * parameter).
 */
export function buildPushyPushBody(
  deviceToken: string,
  data: { message: string; eventBody?: string },
  notification: { title?: string; body: string; sound?: string; badge?: number }
): string {
  return JSON.stringify({ to: deviceToken, data, notification });
}

/**
 * Validate one record's body. Throws `RangeError` on an
 * empty body string — even without the opt-in, the body is
 * the record's payload, and an empty record is a caller
 * bug that must fail closed, never push as an empty
 * message.
 */
export function resolvePushyRecord(
  record: PushyRecord,
  index: number
): { index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`pushy-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { index };
}

/**
 * Map one Pushy POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says Pushy could not
 * accept the push right now, not that the payload is
 * poison (the docs pin 800 requests per minute for Pro
 * accounts and 60 per minute for Trial accounts, with
 * `RATE_LIMIT_EXCEEDED` at 429, and
 * `INTERNAL_SERVER_ERROR` at 500). Every other non-200
 * status (400, 403, and the rest) is a fail-closed
 * message: bad input or token, bad Secret API Key,
 * suspended account, no recipients, missing APNs auth,
 * or a payload over the 4kb limit — including 403
 * `AUTH_LIMIT_EXCEEDED`, too many auth attempts with an
 * invalid key, where retrying with the same key only
 * extends the block. Callers only pass non-200 statuses
 * here; a 200 is acceptance on its own only together
 * with a push id (see `classifyPushyPushResponse`).
 */
export function classifyPushyRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * The verdict on one push POST: either an acceptance,
 * or a failure with its error code and retry lane.
 */
export type PushyPushVerdict =
  | { accepted: true }
  | { accepted: false; errorCode: string; retryable: boolean; errorMessage?: string };

/**
 * Decide one push POST's verdict from the response the
 * client reported. A 200 carrying a push `id` is
 * acceptance — the id is the push acceptance credential,
 * and delivery status is checked later through
 * `GET /pushes/PUSH_ID`. A 200 without a push id is a
 * failure (`PUSHY_NO_PUSH_ID`, fail-closed: the reference
 * promises no other receipt, so a 200 with nothing to
 * trace must not become an acceptance). Any non-200
 * status is a failure with an `HTTP_<status>` code and
 * the WR-210 lane. The success status is pinned to 200
 * here, unlike the MagicBell sink: the fetched API
 * reference states "The Pushy API returns a `200 OK`
 * status code with `JSON` response" and "If the request
 * fails, a non-`200 OK` status code is returned", so a
 * 201 is not a documented success. The docs' error shape
 * is a body carrying `{ code, error }`; when the client
 * surfaces those, they ride on the failure record as
 * `CODE: description`. `info.failed` plays no part in
 * the verdict: a wholly-invalid single token surfaces
 * as the 400 `NO_RECIPIENTS` error, not as a success
 * with a failed list.
 */
export function classifyPushyPushResponse(
  response: PushyPushPostResponse
): PushyPushVerdict {
  if (response.status !== 200) {
    const verdict: PushyPushVerdict = {
      accepted: false,
      errorCode: `HTTP_${response.status}`,
      retryable: classifyPushyRecordFailure(response.status),
    };
    const messages = [
      ...(response.code !== undefined && response.code !== "" ? [response.code] : []),
      ...(response.error !== undefined && response.error !== "" ? [response.error] : []),
    ];
    if (messages.length > 0) {
      verdict.errorMessage = messages.join(": ");
    }
    return verdict;
  }
  if (typeof response.pushId !== "string" || response.pushId === "") {
    return { accepted: false, errorCode: "PUSHY_NO_PUSH_ID", retryable: false };
  }
  return { accepted: true };
}

/**
 * Pushy sink (WR-296). One push is sent per record; the
 * caller owns retry / dead-letter policy around `send()`
 * — this class performs one POST attempt per message
 * through the injected client and reports its outcome.
 * Failures throw `PushySinkError` carrying exactly the
 * failed messages with their retry lanes.
 */
export class PushySink {
  private readonly cfg: PushySinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: PushySinkConfig) {
    assertValidPushySinkConfig(config, "PushySink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): PushySinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send the pushes, in input order. Throws
   * `PushySinkConfigError` when no client was injected,
   * and `PushySinkError` when any message fails
   * (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: PushyRecord[]): Promise<PushySendResult> {
    const resolved = records.map((r, i) => resolvePushyRecord(r, i));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The client
      // is not required here, mirroring the sibling sinks'
      // dry-run exemption; the rest of the config was already
      // validated at construction.
      return { ok: true, sent: 0, pushIds: [], dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new PushySinkConfigError("no client injected (set `client` in the sink config)");
    }
    const deviceToken = resolvePushyDeviceToken(this.cfg.deviceToken, "PushySink: `deviceToken`");
    const failedRecords: PushyFailedRecord[] = [];
    const pushIds: string[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          url: PUSHY_PUSH_URL,
          headers: {
            "Content-Type": PUSHY_JSON_CONTENT_TYPE,
          },
          body: buildPushyPushBody(
            deviceToken,
            resolvePushyData(records[i], this.cfg),
            resolvePushyNotification(records[i], this.cfg)
          ),
        });
        const verdict = classifyPushyPushResponse(response);
        if (verdict.accepted) {
          // A 200 carrying a push id is acceptance on its
          // own: the id is the receipt, and delivery status
          // is checked later through GET /pushes/PUSH_ID —
          // the response is an acceptance receipt, not a
          // delivery result.
          sent += 1;
          if (typeof response.pushId === "string" && response.pushId !== "") {
            pushIds.push(response.pushId);
          }
          continue;
        }
        const failed: PushyFailedRecord = {
          index: record.index,
          errorCode: verdict.errorCode,
          retryable: verdict.retryable,
        };
        if (verdict.errorCode.startsWith("HTTP_")) {
          failed.statusCode = response.status;
        }
        if (verdict.errorMessage !== undefined) {
          failed.errorMessage = verdict.errorMessage;
        }
        failedRecords.push(failed);
      } catch (err) {
        failedRecords.push(toPushyFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new PushySinkError(
        `pushy-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent, pushIds };
  }
}

/**
 * Convert a client throw into a failed message: a codeless
 * transport failure (`TRANSPORT_ERROR`, retryable — the SQS
 * no-status rule).
 */
function toPushyFailedRecord(err: unknown, index: number): PushyFailedRecord {
  const failed: PushyFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
