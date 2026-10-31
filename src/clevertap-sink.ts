/**
 * CleverTap push notification delivery sink (WR-285).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's device. Where the Airship sink
 * (WR-284) delivers push notifications through Airship's
 * Push API with a Basic-auth header the client alone
 * holds and an `audience`/`notification`/`device_types`
 * envelope, and the WonderPush sink (WR-282) delivers
 * through WonderPush's Management API with a form-encoded
 * body and an `accessToken` form field, this sink
 * delivers push notifications through CleverTap's Create
 * Campaign API: one event is sent as one POST that
 * creates a push campaign, and CleverTap — not the relay
 * — owns the audience targeting, the delivery, and the
 * retention of the notification.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a CleverTap
 * server. The sink owns the relay-side concerns — campaign
 * naming, notification derivation, payload-inclusion
 * policy, per-message failure mapping — and the injected
 * client owns the wire protocol, including the POST call,
 * the authentication, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://api.clevertap.com/1/targets/create.json",
 *     headers: { "Content-Type": "application/json" },
 *     body: "{\"name\":\"<name>\",\"target_mode\":\"Push\",\"where\":{...},\"content\":{\"title\":\"<title>\",\"body\":\"<body>\"}}" }
 *
 * The client POSTs to that URL, sending `body`
 * verbatim as the request body (JSON) and `headers`
 * verbatim as the request headers, and authenticating
 * with `X-CleverTap-Account-Id` and
 * `X-CleverTap-Passcode` headers carrying the account id
 * and passcode — which it alone holds. Five things about
 * this shape are deliberate, and all follow the sibling
 * sinks:
 *
 * - The credentials are held by the client alone. The sink
 *   never receives them, never places them in the request,
 *   and never logs them: like the Airship sink (WR-284),
 *   whose app key and master secret the client alone holds,
 *   this sink's handed request carries no credential at
 *   all — the client adds the `X-CleverTap-Account-Id`
 *   and `X-CleverTap-Passcode` headers from the account
 *   id and passcode it alone holds, so there is nothing
 *   in the handed request for a log line or a retry queue
 *   to leak. The backlog item's "配置持有" is the client's
 *   configuration, not the sink's: no credential ever
 *   enters the sink config. This is the opposite of the
 *   WonderPush sink (WR-282), whose access token rides in
 *   the form body because that API authenticates that way:
 *   CleverTap authenticates by header, so the body
 *   carries only routing and content.
 * - The host is config-held, not fixed: CleverTap serves
 *   the same API from one host per region — the default
 *   `api.clevertap.com` is the Europe region, `in1`
 *   serves India, `us1` serves the US — so the sink
 *   config holds the full host (default
 *   `api.clevertap.com`) and the sink builds
 *   `https://<host>/1/targets/create.json` from it. A
 *   fixed host here could only misroute a message to the
 *   wrong region's account. The endpoint, the JSON
 *   envelope, and the headers match the current
 *   CleverTap documentation (checked this round,
 *   2026-10-31): `POST /1/targets/create.json` with
 *   `name`, `target_mode`, `where`, and `content`,
 *   answering HTTP 200 with a JSON body whose `status`
 *   field is `"success"` or `"fail"`. The endpoint is
 *   limited to 3 requests per second — the relay's retry
 *   budget and the 429 lane below absorb bursts; the
 *   sink itself adds no limiter.
 * - The response's `status` field — not the HTTP status
 *   alone — decides acceptance: a 200 answers
 *   `{"status": "success", "message": "Added to queue
 *   for processing"}` (the docs: "A successful response
 *   implies payload validity and addition to the
 *   processing queue"), while a failure answers
 *   `{"status": "fail", "error": "<message>", "code":
 *   <code>}`. The client surfaces the `status` field
 *   (and, on a fail, the `code`/`error`) on the
 *   response, and the sink reads them — a 2xx with no
 *   `status` surfaced is retryable, because without it
 *   the sink cannot claim the campaign was created.
 *   A successful response is only an acceptance receipt,
 *   not a delivery result: delivery is handled by the
 *   provider and depends on valid recipient ids.
 * - The `where` targeting is config-held and passed
 *   through verbatim: the `where` object filters the
 *   target base on user events and profile properties
 *   (per the docs, an empty object targets the entire
 *   user base). One sink targets one CleverTap audience,
 *   and a missing `where` sends `{}` — the API's own
 *   documented entire-base targeting — so operators who
 *   want a narrower audience must set it; the sink never
 *   invents a filter.
 * - The campaign `name` comes from the sink config when
 *   set, and otherwise derives from the event's `key`
 *   (`webhook-<key>`), falling back to the generic
 *   summary `webhook event` for keyless events: the
 *   name is what the campaign is shown as in the
 *   CleverTap dashboard, and a relay-created campaign
 *   should be identifiable there.
 *
 * This sink is orthogonal to the Airship sink (WR-284):
 * Airship posts a fixed-host JSON body with Basic auth
 * held by the client and an `audience`/`notification`/
 * `device_types` envelope whose acceptance is decided by
 * surfaced `push_ids`, while CleverTap posts a
 * region-host JSON body with two `X-CleverTap-*`
 * headers held by the client and a `name`/
 * `target_mode`/`where`/`content` envelope whose
 * acceptance is decided by the response body's `status`
 * field. It is likewise distinct from the WonderPush
 * sink (WR-282): WonderPush posts a form-encoded body
 * with the token as the `accessToken` field and a
 * `notification` JSON string carrying a `title`/`text`
 * split, while CleverTap posts a JSON body with dual
 * header auth and a `content` object carrying a
 * `title`/`body` pair. And from the OneSignal sink
 * (WR-275): OneSignal posts an `app_id`/
 * `included_segments` envelope with a bare-key header,
 * while CleverTap posts a campaign-creation envelope
 * with dual header auth and a `where` targeting object.
 *
 * Message content — a push notification carries a title
 * and a body, both derived from the event's own values:
 * the first non-empty value among `subject`, `key`, and
 * `traceId`, in that order. The title takes that derived
 * summary — the backlog pins the title to `subject`,
 * and `subject` is the first link of the chain, so when
 * a subject exists the title is exactly the subject; when
 * it does not, the chain's next value keeps the title
 * valid, because the docs require `content.title` for
 * push. The body takes the same summary, so an event
 * with none of the values still notifies, with the
 * generic summary `webhook event`: a notification sink
 * that silently dropped sourceless events would hide
 * exactly the deliveries an operator most needs to see,
 * and the audience — not the content — is the delivery
 * contract here, so no invented target is at stake.
 *
 * Payload inclusion — by default the notification
 * carries the summary only, never the full payload:
 * event bodies routinely carry PII, secrets, or
 * customer data, and a device is a far wider audience
 * than a queue or a stream. Opting into `includePayload`
 * appends the body verbatim after a blank line inside
 * `content.body`, truncated to `payloadMaxChars`
 * characters (default 2000) with a truncation marker —
 * the opt-in is explicit, and the truncation is
 * unconditional, so even an opted-in body cannot flood a
 * device. The body is appended as plain text inside the
 * `body` field, not a fenced code block: the field is
 * already plain text, and a fence around an already-JSON
 * body would be noise on a device.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over the HTTP status and, on a 2xx, over the response
 * body's `status` field:
 *
 * - a non-2xx POST throws `CleverTapSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says CleverTap could
 *   not accept the message right now, not that the
 *   payload is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (unknown targeting, invalid body, bad
 *   account id or passcode): retrying them burns the
 *   retry budget for nothing, and rerouting them
 *   elsewhere would notify devices the operator never
 *   chose;
 * - on a 2xx, the `status` field decides: `"success"`
 *   means CleverTap accepted the campaign; `"fail"` is
 *   a failure — retryable only for error code 89
 *   ("Unexpected error, please try again", per the
 *   docs), non-retryable for every other code (21
 *   missing `to`, 78 invalid payload, 84 invalid
 *   recipients, and the rest are validation verdicts
 *   retrying cannot change); a 2xx with no `status`
 *   field surfaced is retryable — the field is the
 *   acceptance result, and a missing field means the
 *   sink cannot claim the campaign was created;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client throws `CleverTapSinkConfigError`,
 *   which `classifyFailure` maps to `non_retryable`
 *   (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for the title/body. */
export const CLEVERTAP_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const CLEVERTAP_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Default CleverTap API host (the Europe region) when the config sets none. */
export const CLEVERTAP_DEFAULT_HOST = "api.clevertap.com";

/** Content type the client sends with the JSON body. */
export const CLEVERTAP_JSON_CONTENT_TYPE = "application/json";

/** Fixed campaign type for every message this sink creates. */
export const CLEVERTAP_TARGET_MODE = "Push";

/**
 * CleverTap error code whose documented troubleshooting step is
 * "Unexpected error, please try again" — the only `status: "fail"`
 * code that is retryable. Every other fail code is a validation
 * verdict (missing `to`, invalid payload, invalid recipients, …)
 * that retrying cannot change.
 */
export const CLEVERTAP_RETRYABLE_FAIL_CODE = 89;

/**
 * The push targeting for one CleverTap sink: the `where` object
 * filters the target base on user events and profile properties,
 * passed through verbatim into the JSON body. An empty object
 * targets the entire user base, per the docs. Held by the sink
 * config; defaults to `{}` when the config sets none — so a sink
 * with no targeting configured still has somewhere to deliver,
 * and the operator who wants a narrower audience must set it
 * (the sink never invents a filter).
 */
export type CleverTapWhere = Record<string, unknown>;

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (JSON) to the region endpoint,
 * sending `headers` verbatim as the request headers, and
 * authenticating with `X-CleverTap-Account-Id` and
 * `X-CleverTap-Passcode` headers carrying the account id
 * and passcode — which the sink never sees.
 */
export interface CleverTapMessagePostRequest {
  /** Always `https://<region host>/1/targets/create.json`. */
  url: string;
  /**
   * Request headers, sent verbatim:
   * `{ "Content-Type": "application/json" }`. The
   * `X-CleverTap-Account-Id` and `X-CleverTap-Passcode`
   * headers are added by the client, never by the sink.
   */
  headers: Record<string, string>;
  /**
   * The JSON request body, serialized:
   * `{"name":"<name>","target_mode":"Push","where":{...},"content":{"title":"<title>","body":"<body>"}}`.
   */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * The HTTP status drives the HTTP retry mapping; on a 2xx
 * the client surfaces the response body's `status` field
 * (`"success"` / `"fail"`) and, on a fail, the `code` and
 * `error` fields — and the `status` field, not the HTTP
 * status alone, decides whether the campaign was created.
 * A client that reports a 2xx without a `status` field
 * leaves the sink unable to claim acceptance, so the
 * message is treated as a retryable delivery failure.
 */
export interface CleverTapMessagePostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
  /**
   * The `status` field of the CleverTap JSON body, on a
   * 2xx: `"success"` means the campaign was accepted
   * (an acceptance receipt only, not a delivery result);
   * `"fail"` means the campaign was not created.
   */
  statusField?: string;
  /**
   * The `code` field of a fail body (e.g. 21, 78, 84,
   * 89), surfaced by the client when present. Only code
   * 89 ("Unexpected error, please try again") is
   * retryable; every other fail code is a validation
   * verdict.
   */
  errorCode?: number;
  /** The `error` message of a fail body, when the client surfaces one. */
  errorMessage?: string;
}

/**
 * The injected CleverTap message client. Any client adapter
 * implements this one method; it returns the POST's status
 * and, on a 2xx, the response body's `status` field (and,
 * on a fail, the `code`/`error` fields) — a throw is a
 * codeless transport failure, retryable. The client is
 * expected to POST one message per call, sending `body`
 * verbatim as the request body (JSON), sending `headers`
 * verbatim as the request headers, and authenticating with
 * `X-CleverTap-Account-Id` and `X-CleverTap-Passcode`
 * headers carrying the account id and passcode — which
 * the sink never sees.
 */
export interface CleverTapMessageClient {
  post(request: CleverTapMessagePostRequest): Promise<CleverTapMessagePostResponse>;
}

/**
 * Configuration for one CleverTap sink. The client is
 * injected: without one, `send()` throws
 * `CleverTapSinkConfigError` (dry runs excepted — they need
 * no client at all). The region host defaults to
 * `api.clevertap.com` (Europe) when unset; the targeting
 * defaults to `{}` (the entire user base, per the docs)
 * when unset. The account id and passcode are deliberately
 * absent from this config: the client alone holds them and
 * sends them as the `X-CleverTap-Account-Id` and
 * `X-CleverTap-Passcode` headers.
 */
export interface CleverTapSinkConfig {
  /**
   * The CleverTap API host for the account's region, as a
   * bare hostname with no scheme or path: `in1` serves
   * India (`in1.api.clevertap.com`), `us1` serves the US
   * (`us1.api.clevertap.com`), and the default
   * `api.clevertap.com` is the Europe region. Defaults to
   * `api.clevertap.com` when unset. Must be a non-empty
   * hostname when set.
   */
  regionHost?: string;
  /**
   * The campaign name shown in the CleverTap dashboard.
   * When set, every message creates a campaign under
   * this name; when unset, the name derives per message
   * from the event's `key` (`webhook-<key>`), falling
   * back to `webhook event` for keyless events. Must be
   * a non-empty string when set.
   */
  campaignName?: string;
  /**
   * The push targeting: the `where` object, held
   * verbatim and passed through into the JSON body.
   * Filters the target base on user events and profile
   * properties; an empty object targets the entire user
   * base, per the docs. Defaults to `{}` when unset.
   * Must be a non-array object when set.
   */
  where?: CleverTapWhere;
  /**
   * The CleverTap message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `CleverTapMessageClient` and alone holds
   * the account id and passcode. Required for real sends; a
   * missing client is a config error, not a silent no-op.
   */
  client?: CleverTapMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including notification derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The region host, targeting, and client are
   * not required in dry-run mode, mirroring the sibling
   * sinks' dry-run exemption.
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
   * device. Must be a positive integer when set.
   */
  payloadMaxChars?: number;
}

/** One event to notify about. */
export interface CleverTapRecord {
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
   * (e.g. aggregate id). Also the campaign-name derivation
   * source when no `campaignName` is configured.
   */
  key?: string;
  /**
   * Content-derivation source, last priority: the trace id.
   */
  traceId?: string;
}

/** One failed message, with its retry lane already mapped. */
export interface CleverTapFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /**
   * Failure code: `HTTP_<status>` for a non-2xx POST,
   * `CLEVERTAP_<code>` for a 2xx with `status: "fail"`
   * and a surfaced code, `STATUS_FAIL` for a 2xx with
   * `status: "fail"` and no code surfaced,
   * `STATUS_MISSING` for a 2xx with no `status` field
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
   * (plus codeless transport failures, missing `status`
   * fields, and fail code 89) are retryable; every other
   * non-2xx status and every other fail code is a
   * fail-closed message (unknown targeting, invalid body,
   * bad account id or passcode, invalid recipients).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface CleverTapSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-285). */
export interface CleverTapSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for CleverTap send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on CleverTap's server and are *not* in
 * `failedRecords`.
 */
export class CleverTapSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: CleverTapFailedRecord[];
  constructor(message: string, failedRecords: CleverTapFailedRecord[]) {
    super(message);
    this.name = "CleverTapSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class CleverTapSinkConfigError extends CleverTapSinkError {
  constructor(reason: string) {
    super(`clevertap-sink: ${reason}`, []);
    this.name = "CleverTapSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing region host, campaign name, or targeting is *not* a shape
 * error: they default at send time (Europe host, derived name, `{}`),
 * so a sink built before its targeting is known still sends rather
 * than crashing at construction. A present `regionHost` must be a
 * bare hostname (no scheme, no path); a present `campaignName` must
 * be a non-empty string; a present `where` must be a non-array
 * object (an empty object is valid — it targets the entire user
 * base, per the docs).
 */
export function assertValidCleverTapSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is CleverTapSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  const regionHost = c.regionHost;
  if (regionHost !== undefined) {
    if (
      typeof regionHost !== "string" ||
      regionHost === "" ||
      regionHost.includes("://") ||
      regionHost.includes("/")
    ) {
      throw new RangeError(at("`regionHost` must be a bare hostname (no scheme or path) when set"));
    }
  }
  if (
    c.campaignName !== undefined &&
    (typeof c.campaignName !== "string" || c.campaignName === "")
  ) {
    throw new RangeError(at("`campaignName` must be a non-empty string when set"));
  }
  const where = c.where;
  if (
    where !== undefined &&
    (where === null || typeof where !== "object" || Array.isArray(where))
  ) {
    throw new RangeError(at("`where` must be a non-array object when set"));
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
 * Resolve the effective region host: the configured host,
 * or `api.clevertap.com` (the Europe region) when the
 * config sets none.
 */
export function resolveCleverTapHost(
  config: Pick<CleverTapSinkConfig, "regionHost">
): string {
  return config.regionHost ?? CLEVERTAP_DEFAULT_HOST;
}

/**
 * Resolve the effective targeting: the configured `where`
 * object, or `{}` when the config sets none — an empty
 * object targets the entire user base, per the docs.
 */
export function resolveCleverTapWhere(
  config: Pick<CleverTapSinkConfig, "where">
): CleverTapWhere {
  return config.where ?? {};
}

/**
 * Build the Create Campaign endpoint URL for a region host:
 * `https://<host>/1/targets/create.json`.
 */
export function buildCleverTapCreateUrl(regionHost: string): string {
  return `https://${regionHost}/1/targets/create.json`;
}

/**
 * Derive one record's content summary: the first
 * non-empty value among `subject`, `key`, and `traceId`,
 * in that order. Falls back to the generic `webhook
 * event` summary when the record carries none — a
 * notification sink must not silently drop sourceless
 * events, and the audience (not the content) is the
 * delivery contract.
 */
export function resolveCleverTapSummary(record: CleverTapRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return CLEVERTAP_FALLBACK_SUMMARY;
}

/**
 * Derive one record's campaign name: the configured
 * `campaignName` when set, otherwise `webhook-<key>`
 * from the event's key, falling back to the generic
 * `webhook event` summary for keyless events.
 */
export function resolveCleverTapCampaignName(
  record: CleverTapRecord,
  config: Pick<CleverTapSinkConfig, "campaignName">
): string {
  if (config.campaignName !== undefined) return config.campaignName;
  if (record.key !== undefined && record.key !== "") return `webhook-${record.key}`;
  return CLEVERTAP_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a device.
 */
export function truncateCleverTapPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's notification content: `title` and
 * `body` both take the derived summary (the first
 * non-empty among `subject`, `key`, and `traceId`,
 * falling back to `webhook event`) — the title because
 * the docs require `content.title` for push and the
 * backlog pins it to `subject`, the first link of the
 * chain — then the event body is appended after a blank
 * line only under the `includePayload` opt-in (truncated
 * to `payloadMaxChars`, default 2000).
 */
export function resolveCleverTapContent(
  record: CleverTapRecord,
  config: Pick<CleverTapSinkConfig, "includePayload" | "payloadMaxChars">
): { title: string; body: string } {
  const summary = resolveCleverTapSummary(record);
  let body = summary;
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? CLEVERTAP_DEFAULT_PAYLOAD_MAX_CHARS;
    body = `${summary}\n\n${truncateCleverTapPayload(record.body, limit)}`;
  }
  return { title: summary, body };
}

/**
 * Build one record's serialized JSON body: the campaign
 * creation object with `name`, `target_mode` fixed to
 * `"Push"`, `where`, and `content` carrying `title` and
 * `body`. The account id and passcode never appear here —
 * the client alone holds them and sends them as the
 * `X-CleverTap-Account-Id` and `X-CleverTap-Passcode`
 * headers.
 */
export function buildCleverTapCreateBody(
  name: string,
  where: CleverTapWhere,
  content: { title: string; body: string }
): string {
  return JSON.stringify({
    name,
    target_mode: CLEVERTAP_TARGET_MODE,
    where,
    content,
  });
}

/**
 * Validate one record's body. Throws `RangeError` on an
 * empty body string — even without the opt-in, the body is
 * the record's payload, and an empty record is a caller
 * bug that must fail closed, never notify as an empty
 * message.
 */
export function resolveCleverTapRecord(
  record: CleverTapRecord,
  index: number
): { index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`clevertap-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { index };
}

/**
 * Map one CleverTap POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says CleverTap could not
 * accept the message right now, not that the payload is
 * poison. Every other non-2xx status (400, 401, 403,
 * 404, and the rest) is a fail-closed message: unknown
 * targeting, invalid body, bad account id or passcode, or
 * another verdict retrying cannot change. Callers only pass
 * non-2xx statuses here; a 2xx status is decided by the
 * response body's `status` field, not by this function.
 */
export function classifyCleverTapRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Map one CleverTap POST response onto its failed record,
 * or `null` when the response accepted the message (a 2xx
 * with the `status` field `"success"`). A 2xx with
 * `status: "fail"` is a failure — retryable only for
 * error code 89 ("Unexpected error, please try again",
 * per the docs), non-retryable for every other code
 * (validation verdicts retrying cannot change). A 2xx
 * with no `status` field surfaced is retryable — the
 * field is the acceptance result, and without it the
 * sink cannot claim the campaign was created.
 */
export function cleverTapResponseToFailedRecord(
  response: CleverTapMessagePostResponse,
  index: number
): CleverTapFailedRecord | null {
  if (response.statusField === "success") {
    return null;
  }
  if (response.statusField === "fail") {
    const retryable = response.errorCode === CLEVERTAP_RETRYABLE_FAIL_CODE;
    return {
      index,
      errorCode:
        response.errorCode !== undefined
          ? `CLEVERTAP_${response.errorCode}`
          : "STATUS_FAIL",
      errorMessage: response.errorMessage,
      retryable,
    };
  }
  return {
    index,
    errorCode: "STATUS_MISSING",
    errorMessage: "CleverTap answered 2xx but surfaced no status field",
    retryable: true,
  };
}

/**
 * CleverTap sink (WR-285). One instance targets one
 * CleverTap region account audience; the caller owns retry /
 * dead-letter policy around `send()` — this class performs
 * one POST attempt per message through the injected client
 * and reports its outcome. Failures throw
 * `CleverTapSinkError` carrying exactly the failed messages
 * with their retry lanes.
 */
export class CleverTapSink {
  private readonly cfg: CleverTapSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: CleverTapSinkConfig) {
    assertValidCleverTapSinkConfig(config, "CleverTapSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): CleverTapSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send push notifications, in input order. Throws
   * `CleverTapSinkConfigError` when no client was injected,
   * and `CleverTapSinkError` when any message fails
   * (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: CleverTapRecord[]): Promise<CleverTapSendResult> {
    const resolved = records.map((r, i) => resolveCleverTapRecord(r, i));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The
      // region host, targeting, and client are
      // not required here, mirroring the sibling sinks'
      // dry-run exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new CleverTapSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const url = buildCleverTapCreateUrl(resolveCleverTapHost(this.cfg));
    const where = resolveCleverTapWhere(this.cfg);
    const failedRecords: CleverTapFailedRecord[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          url,
          headers: {
            "Content-Type": CLEVERTAP_JSON_CONTENT_TYPE,
          },
          body: buildCleverTapCreateBody(
            resolveCleverTapCampaignName(records[i], this.cfg),
            where,
            resolveCleverTapContent(records[i], this.cfg)
          ),
        });
        if (response.status >= 200 && response.status < 300) {
          const statusFailure = cleverTapResponseToFailedRecord(response, record.index);
          if (statusFailure === null) {
            sent += 1;
            continue;
          }
          failedRecords.push(statusFailure);
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyCleverTapRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toCleverTapFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new CleverTapSinkError(
        `clevertap-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toCleverTapFailedRecord(err: unknown, index: number): CleverTapFailedRecord {
  const failed: CleverTapFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
