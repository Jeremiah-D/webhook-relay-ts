/**
 * WonderPush push notification delivery sink (WR-282).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's device. Where the Pushwoosh sink
 * (WR-281) delivers push notifications through Pushwoosh's
 * Remote API with the token in a JSON `request` body and a
 * `notifications` array, this sink delivers push
 * notifications through WonderPush's Management API: one
 * event is sent as one POST to WonderPush's `/deliveries`
 * endpoint, and WonderPush — not the relay — owns the
 * device routing, the delivery, and the retention of the
 * notification.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a WonderPush
 * server. The sink owns the relay-side concerns — message
 * targeting, notification derivation, payload-inclusion
 * policy, per-message failure mapping — and the injected
 * client owns the wire protocol, including the POST call,
 * the authentication, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://management-api.wonderpush.com/v1/deliveries",
 *     headers: { "Content-Type": "application/x-www-form-urlencoded" },
 *     body: "accessToken=<token>&targetSegmentIds=<segments>&notification=%7B%22alert%22%3A%7B%22title%22%3A%22<title>%22%2C%22text%22%3A%22<text>%22%7D%7D" }
 *
 * The client POSTs to that fixed URL, sending `body`
 * verbatim as the request body (form-encoded) and `headers`
 * verbatim as the request headers. Four things about this
 * shape are deliberate, and all follow the sibling sinks —
 * with one deliberate deviation from the backlog item's
 * prescribed envelope, documented below:
 *
 * - The Management API is form-encoded, not JSON: the
 *   current WonderPush documentation (checked this round,
 *   2026-10-31) sends every `/deliveries` call as
 *   `application/x-www-form-urlencoded`, with `notification`
 *   carried as a JSON string inside the form. The sink
 *   therefore hands the client a URL-encoded form body,
 *   not a JSON body — the client sends it verbatim.
 * - Authentication is the documented `accessToken` form
 *   field, not a Bearer header: the current docs
 *   authenticate every Management API call with
 *   `accessToken` as a query or form parameter (the
 *   application access token from the API Credentials
 *   page). The backlog item prescribed `Authorization:
 *   Bearer <access token>` with the token never in the
 *   body, but no Bearer-header auth appears in the
 *   current WonderPush documentation, and the item
 *   itself says the implementation round takes the
 *   current docs as authoritative ("实现轮以现行文档为准").
 *   So the sink puts the token in the form body — the
 *   API's documented auth mechanism — where only the
 *   client sends it at wire time, and it is never logged.
 *   Nothing about the token ever appears in the URL the
 *   sink builds (the client may move it to the query
 *   string, which the docs also accept, but the sink
 *   does not).
 * - The host is fixed, not configurable: the endpoint
 *   above is WonderPush's Management API. A configurable
 *   URL here could only misroute a message to a server
 *   that is not WonderPush. The fixed host is the
 *   documented default; the client adapter owns nothing
 *   about the host.
 * - The response carries a delivery id, not just a
 *   status: a 201 returns the created delivery's id,
 *   and the id is an acceptance receipt only, not a
 *   delivery result (delivery confirmation lives in
 *   WonderPush's logs). The client surfaces the id on
 *   the response, and the sink reads it — a 2xx with no
 *   delivery id surfaced is retryable, because without
 *   the id the sink cannot claim the delivery was
 *   created.
 *
 * Targeting — the `targeting` config holds the
 * Management API's target parameters verbatim:
 * `targetSegmentIds`, `targetUserIds`, `targetTags`,
 * `targetInstallationIds`, and `targetDeviceIds` (each a
 * string or a string array, joined with commas on the
 * wire, per the docs). At least one targeting field must
 * be set: the API refuses a delivery with no target and
 * no campaign, so a sink with no targeting fails closed
 * with `WonderPushSinkConfigError` at send time. The
 * sink invents no default audience — in particular it
 * never defaults to the `@ALL` segment, which the docs
 * warn against using on a production app. A `campaignId`
 * is out of scope: this sink always specifies the
 * notification content and the target audience directly
 * in the call, so its deliveries are not included in the
 * dashboard metrics (the docs' own caveat, noted here
 * so the operator is not surprised).
 *
 * This sink is orthogonal to the Pushwoosh sink (WR-281):
 * Pushwoosh posts a JSON body with the token in a
 * `request`/`auth` field and a `notifications` array
 * carrying `send_date`/`content`, while WonderPush posts
 * a form-encoded body with the token as the `accessToken`
 * field and a `notification` JSON string carrying an
 * `alert` object. It is likewise distinct from the Expo
 * sink (WR-280): Expo posts a flat `{to, title, body}`
 * JSON envelope to a single push token and answers with
 * a per-message ticket, while WonderPush posts a
 * form-encoded delivery to a segment/user/tag audience
 * and answers with a delivery id. And from the FCM sink
 * (WR-276): FCM posts a project-level endpoint with an
 * OAuth Bearer token the client alone holds and a
 * `{message: {token, notification}}` envelope, while
 * WonderPush posts the Management API with a form-field
 * access token and a `notification`/`alert` envelope.
 *
 * The access token and the targeting are configured, not
 * derived from the event. One sink targets one WonderPush
 * application audience. A missing access token or
 * targeting is a config error, not a resolution fallback:
 * unlike the broker sinks, there is no per-record target
 * to resolve to, so a sink with no token or no targeting
 * has nowhere to deliver and fails closed with
 * `WonderPushSinkConfigError` at send time (dry runs
 * excepted — they need neither, mirroring the sibling
 * sinks' dry-run exemption for the client).
 *
 * Message content — a push notification carries two
 * fields, so the event's values split across them:
 * `title` takes the event's `subject` and is omitted
 * entirely when the event has no subject (a title is a
 * subject line, and neither the key nor the trace id is
 * one), while `text` takes the first non-empty value
 * among `subject`, `key`, and `traceId`, in that order —
 * the subject is what the event is about, the key (e.g.
 * aggregate id) is the next most identifying value, and
 * the trace id names the trace that produced the event.
 * An event with none of the values still notifies, with
 * the generic summary `webhook event` as its text: a
 * notification sink that silently dropped sourceless
 * events would hide exactly the deliveries an operator
 * most needs to see, and the audience — not the content
 * — is the delivery contract here, so no invented target
 * is at stake.
 *
 * Payload inclusion — by default the notification carries
 * the summary only, never the full payload: event bodies
 * routinely carry PII, secrets, or customer data, and a
 * device is a far wider audience than a queue or a
 * stream. Opting into `includePayload` appends the body
 * verbatim after a blank line inside `text`, truncated to
 * `payloadMaxChars` characters (default 2000) with a
 * truncation marker — the opt-in is explicit, and the
 * truncation is unconditional, so even an opted-in body
 * cannot flood a device. The body is appended as plain
 * text inside the `text` field, not a fenced code block:
 * the field is already plain text, and a fence around an
 * already-JSON body would be noise on a device.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over the HTTP status and, on a 2xx, over the delivery
 * id:
 *
 * - a non-2xx POST throws `WonderPushSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says WonderPush could
 *   not accept the message right now, not that the payload
 *   is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (unknown segment, invalid body, bad
 *   access token): retrying them burns the retry budget
 *   for nothing, and rerouting them elsewhere would
 *   notify devices the operator never chose;
 * - on a 2xx, the delivery id decides: a surfaced id
 *   means WonderPush accepted the delivery; a 2xx with
 *   no id surfaced is retryable — the id is the
 *   acceptance result, and a missing id means the sink
 *   cannot claim the delivery was created;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client, access token, or targeting throws
 *   `WonderPushSinkConfigError`, which `classifyFailure`
 *   maps to `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for the text field. */
export const WONDERPUSH_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const WONDERPUSH_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Fixed WonderPush Management API deliveries endpoint for every message. */
export const WONDERPUSH_DELIVERIES_URL =
  "https://management-api.wonderpush.com/v1/deliveries";

/** Content type the client sends with the form-encoded body. */
export const WONDERPUSH_FORM_CONTENT_TYPE = "application/x-www-form-urlencoded";

/**
 * The notification object, serialized as a JSON string
 * inside the form's `notification` field: an `alert`
 * with `title` (from the subject, omitted when absent)
 * and `text` (subject → key → traceId, falling back to
 * `webhook event`).
 */
export interface WonderPushAlert {
  /** The notification title, from the event's subject; omitted when the event has no subject. */
  title?: string;
  /** The notification text: subject → key → traceId, falling back to `webhook event`. */
  text: string;
}

/**
 * Targeting for one WonderPush sink, held by the sink
 * config and passed through verbatim into the form body.
 * Each field is a string or a string array (arrays are
 * joined with commas on the wire, per the docs). At
 * least one field must be set — the API refuses a
 * delivery with no target and no campaign. No default
 * audience is invented: in particular the sink never
 * defaults to the `@ALL` segment.
 */
export interface WonderPushTargeting {
  /** Target segment ids (e.g. a dashboard segment id, or `@ALL` for the entire audience — not a production default). */
  targetSegmentIds?: string | string[];
  /** Target user ids (as registered with WonderPush). */
  targetUserIds?: string | string[];
  /** Target tags: installations carrying at least one of these tags. */
  targetTags?: string | string[];
  /** Target installation ids. */
  targetInstallationIds?: string | string[];
  /** Target device ids, optionally prefixed by platform and a colon. */
  targetDeviceIds?: string | string[];
}

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (form-encoded) to the fixed
 * deliveries endpoint, sending `headers` verbatim as the
 * request headers. The access token rides in the form
 * body as the `accessToken` field — the Management API's
 * documented auth mechanism — never in a header, never
 * in the URL the sink builds, never logged.
 */
export interface WonderPushMessagePostRequest {
  /** Always the fixed WonderPush deliveries endpoint. */
  url: string;
  /**
   * Request headers, sent verbatim:
   * `{ "Content-Type": "application/x-www-form-urlencoded" }`.
   */
  headers: Record<string, string>;
  /**
   * The form-encoded request body, serialized:
   * `accessToken=<token>&<targeting fields>&notification=<JSON string>`.
   */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * The HTTP status drives the HTTP retry mapping; on a 2xx
 * the client surfaces the created delivery's id, and the
 * id — not the status alone — decides whether the delivery
 * was created. A client that reports a 2xx without an id
 * leaves the sink unable to claim acceptance, so the
 * message is treated as a retryable delivery failure.
 */
export interface WonderPushMessagePostResponse {
  /** The HTTP status of the POST (e.g. 201, 429, 503). */
  status: number;
  /**
   * The created delivery's id, on a 2xx: an acceptance
   * receipt only, not a delivery result (delivery
   * confirmation lives in WonderPush's logs).
   */
  deliveryId?: string;
}

/**
 * The injected WonderPush message client. Any client adapter
 * implements this one method; it returns the POST's status
 * and, on a 2xx, the created delivery's id (a throw is a
 * codeless transport failure, retryable). The client is
 * expected to POST one message per call, sending `body`
 * verbatim as the request body (form-encoded), sending
 * `headers` verbatim as the request headers. The client
 * never invents an `Authorization` header: the Management
 * API authenticates with the `accessToken` form field.
 */
export interface WonderPushMessageClient {
  post(request: WonderPushMessagePostRequest): Promise<WonderPushMessagePostResponse>;
}

/**
 * Configuration for one WonderPush sink. The client is
 * injected: without one, `send()` throws
 * `WonderPushSinkConfigError` (dry runs excepted — they need
 * no client at all). A missing access token or targeting
 * is likewise a config error at send time (dry runs
 * excepted): there is no per-record target to fall back
 * to. The access token is configured here only so the
 * sink can hand it to the client inside the form body —
 * the Management API's documented auth shape — never in
 * a header, never logged.
 */
export interface WonderPushSinkConfig {
  /**
   * The WonderPush application access token (from the API
   * Credentials page). The sink hands it to the client
   * inside the form body at send time — never in a header,
   * never logged. Must be a non-empty string, free of NUL
   * and whitespace, when set; a missing token throws
   * `WonderPushSinkConfigError` at send time.
   */
  accessToken?: string;
  /**
   * The delivery's targeting (at least one field must be
   * set). Held by the sink config and passed through
   * verbatim; the sink invents no default audience.
   */
  targeting?: WonderPushTargeting;
  /**
   * The WonderPush message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `WonderPushMessageClient`. Required for real sends;
   * a missing client is a config error, not a silent no-op.
   */
  client?: WonderPushMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including notification derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The access token, targeting, and client are
   * not required in dry-run mode, mirroring the sibling
   * sinks' dry-run exemption.
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
   * the opt-in is set, so an opted-in body cannot flood a
   * device. Must be a positive integer when set.
   */
  payloadMaxChars?: number;
}

/** One event to notify about. */
export interface WonderPushRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Title source and text-derivation source, first
   * priority: the event's subject, when set and non-empty.
   * The title takes it directly (omitted when absent);
   * the text falls through to `key`, then `traceId`.
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
export interface WonderPushFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /**
   * Failure code: `HTTP_<status>` for a non-2xx POST,
   * `DELIVERY_ID_MISSING` for a 2xx with no delivery id
   * surfaced, or `TRANSPORT_ERROR` for a codeless
   * failure.
   */
  errorCode: string;
  /** Downstream HTTP status, when the failure was a non-2xx POST. */
  statusCode?: number;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: 429 and 5xx
   * (plus codeless transport failures and missing delivery
   * ids) are retryable; every other non-2xx status is a
   * fail-closed message (unknown segment, invalid body, bad
   * access token).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface WonderPushSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-282). */
export interface WonderPushSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for WonderPush send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on WonderPush's server and are *not* in
 * `failedRecords`.
 */
export class WonderPushSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: WonderPushFailedRecord[];
  constructor(message: string, failedRecords: WonderPushFailedRecord[]) {
    super(message);
    this.name = "WonderPushSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, or the access token or targeting
 * is missing. A config problem, not a downstream verdict, so the retry
 * queue must not burn attempts on it (`classifyFailure`
 * maps it to `non_retryable`).
 */
export class WonderPushSinkConfigError extends WonderPushSinkError {
  constructor(reason: string) {
    super(`wonderpush-sink: ${reason}`, []);
    this.name = "WonderPushSinkConfigError";
  }
}

/** Targeting fields, in the fixed wire order of the form body. */
const TARGETING_FIELDS = [
  "targetSegmentIds",
  "targetUserIds",
  "targetTags",
  "targetInstallationIds",
  "targetDeviceIds",
] as const;

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing access token or targeting is *not* a shape error: it is
 * a config error raised at send time (`WonderPushSinkConfigError`),
 * so a sink built before its credentials are known still fails
 * closed at send time rather than crashing at construction. A
 * present `accessToken` value must be a non-empty string, free of
 * NUL and whitespace; a present targeting field must be a
 * non-empty string or an array of non-empty strings.
 */
export function assertValidWonderPushSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is WonderPushSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  const accessToken = c.accessToken;
  if (accessToken !== undefined) {
    if (
      typeof accessToken !== "string" ||
      accessToken === "" ||
      accessToken.includes("\0") ||
      /\s/.test(accessToken)
    ) {
      throw new RangeError(
        at("`accessToken` must be a non-empty string, free of NUL and whitespace when set")
      );
    }
  }
  const targeting = c.targeting;
  if (targeting !== undefined) {
    if (targeting === null || typeof targeting !== "object" || Array.isArray(targeting)) {
      throw new RangeError(at("`targeting` must be an object when set"));
    }
    const t = targeting as Record<string, unknown>;
    for (const field of TARGETING_FIELDS) {
      const value = t[field];
      if (value === undefined) continue;
      const values = Array.isArray(value) ? value : [value];
      if (
        values.length === 0 ||
        values.some(
          (v) =>
            typeof v !== "string" || v === "" || v.includes("\0") || /\s/.test(v)
        )
      ) {
        throw new RangeError(
          at(`\`targeting.${field}\` must be a non-empty string or an array of non-empty strings, free of NUL and whitespace, when set`)
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
 * Derive one record's notification text: the first non-empty
 * value among `subject`, `key`, and `traceId`, in that
 * order. Falls back to the generic `webhook event` summary
 * when the record carries none — a notification sink must
 * not silently drop sourceless events, and the audience
 * (not the content) is the delivery contract.
 */
export function resolveWonderPushText(record: WonderPushRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return WONDERPUSH_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a device.
 */
export function truncateWonderPushPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's notification alert: `title` from the
 * subject (omitted when absent — neither the key nor the
 * trace id is a title) and `text` from the first
 * non-empty among `subject`, `key`, and `traceId`
 * (falling back to `webhook event`), then the event body
 * appended after a blank line only under the
 * `includePayload` opt-in (truncated to `payloadMaxChars`,
 * default 2000).
 */
export function resolveWonderPushNotification(
  record: WonderPushRecord,
  config: Pick<WonderPushSinkConfig, "includePayload" | "payloadMaxChars">
): WonderPushAlert {
  let text = resolveWonderPushText(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? WONDERPUSH_DEFAULT_PAYLOAD_MAX_CHARS;
    text = `${text}\n\n${truncateWonderPushPayload(record.body, limit)}`;
  }
  if (record.subject !== undefined && record.subject !== "") {
    return { title: record.subject, text };
  }
  return { text };
}

/**
 * Serialize one targeting value for the form body: a
 * string passes through, an array joins with commas (the
 * docs' list shape, e.g. `targetSegmentIds=a,b`).
 */
export function serializeWonderPushTargetValue(value: string | string[]): string {
  return Array.isArray(value) ? value.join(",") : value;
}

/**
 * Build one record's serialized form body: the
 * `accessToken` field first, then the targeting fields in
 * fixed order (only the set ones), then `notification` as
 * a JSON string carrying the `alert` object. Field order
 * is fixed so the wire shape is deterministic.
 */
export function buildWonderPushFormBody(
  accessToken: string,
  targeting: WonderPushTargeting,
  notification: WonderPushAlert
): string {
  const params = new URLSearchParams();
  params.set("accessToken", accessToken);
  for (const field of TARGETING_FIELDS) {
    const value = targeting[field];
    if (value !== undefined) {
      params.set(field, serializeWonderPushTargetValue(value));
    }
  }
  params.set("notification", JSON.stringify({ alert: notification }));
  return params.toString();
}

/**
 * Whether the targeting config names at least one audience:
 * at least one field set to a non-empty string or a
 * non-empty array. A delivery with no target and no
 * campaign is refused by the API, so an empty targeting
 * fails closed at send time instead.
 */
export function hasWonderPushTargeting(targeting: WonderPushTargeting | undefined): boolean {
  if (targeting === undefined) return false;
  for (const field of TARGETING_FIELDS) {
    const value = targeting[field];
    if (value === undefined) continue;
    if (Array.isArray(value) ? value.length > 0 : value !== "") return true;
  }
  return false;
}

/**
 * Validate one record's body. Throws `RangeError` on an
 * empty body string — even without the opt-in, the body is
 * the record's payload, and an empty record is a caller
 * bug that must fail closed, never notify as an empty
 * message.
 */
export function resolveWonderPushRecord(
  record: WonderPushRecord,
  index: number
): { index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`wonderpush-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { index };
}

/**
 * Map one WonderPush POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says WonderPush could not
 * accept the message right now, not that the payload is
 * poison. Every other non-2xx status (400, 401, 403,
 * 404, and the rest) is a fail-closed message: unknown
 * segment, invalid body, bad access token, or another
 * verdict retrying cannot change. Callers only pass
 * non-2xx statuses here; a 2xx status is decided by the
 * delivery id, not by this function.
 */
export function classifyWonderPushRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Map one WonderPush POST response onto its failed record,
 * or `null` when the response accepted the message (a 2xx
 * with a surfaced delivery id). A 2xx with no id is
 * retryable — the id is the acceptance result, and without
 * it the sink cannot claim the delivery was created.
 */
export function wonderPushResponseToFailedRecord(
  response: WonderPushMessagePostResponse,
  index: number
): WonderPushFailedRecord | null {
  if (
    response.deliveryId !== undefined &&
    response.deliveryId !== ""
  ) {
    return null;
  }
  return {
    index,
    errorCode: "DELIVERY_ID_MISSING",
    errorMessage: "WonderPush answered 2xx but surfaced no delivery id",
    retryable: true,
  };
}

/**
 * WonderPush sink (WR-282). One instance targets one
 * WonderPush application audience; the caller owns retry /
 * dead-letter policy around `send()` — this class performs
 * one POST attempt per message through the injected client
 * and reports its outcome. Failures throw
 * `WonderPushSinkError` carrying exactly the failed
 * messages with their retry lanes.
 */
export class WonderPushSink {
  private readonly cfg: WonderPushSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: WonderPushSinkConfig) {
    assertValidWonderPushSinkConfig(config, "WonderPushSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): WonderPushSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send push notifications, in input order. Throws
   * `WonderPushSinkConfigError` when no client was injected
   * or the access token or targeting is missing, and
   * `WonderPushSinkError` when any message fails (carrying
   * exactly the failed messages with their retry lanes;
   * both counted in stats before throwing, so the counters
   * stay honest even for callers that only inspect stats).
   */
  async send(records: WonderPushRecord[]): Promise<WonderPushSendResult> {
    const resolved = records.map((r, i) => resolveWonderPushRecord(r, i));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The
      // access token, targeting, and client are
      // not required here, mirroring the sibling sinks'
      // dry-run exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new WonderPushSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const accessToken = this.cfg.accessToken;
    if (accessToken === undefined) {
      throw new WonderPushSinkConfigError(
        "no access token configured (set `accessToken` in the sink config)"
      );
    }
    const targeting = this.cfg.targeting;
    if (!hasWonderPushTargeting(targeting)) {
      throw new WonderPushSinkConfigError(
        "no targeting configured (set at least one `targeting` field in the sink config)"
      );
    }
    const failedRecords: WonderPushFailedRecord[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          url: WONDERPUSH_DELIVERIES_URL,
          headers: { "Content-Type": WONDERPUSH_FORM_CONTENT_TYPE },
          body: buildWonderPushFormBody(
            accessToken,
            targeting as WonderPushTargeting,
            resolveWonderPushNotification(records[i], this.cfg)
          ),
        });
        if (response.status >= 200 && response.status < 300) {
          const idFailure = wonderPushResponseToFailedRecord(response, record.index);
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
          retryable: classifyWonderPushRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toWonderPushFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new WonderPushSinkError(
        `wonderpush-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toWonderPushFailedRecord(err: unknown, index: number): WonderPushFailedRecord {
  const failed: WonderPushFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
