/**
 * MoEngage push notification delivery sink (WR-286).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's device. Where the CleverTap sink
 * (WR-285) delivers push notifications through CleverTap's
 * Create Campaign API with two `X-CleverTap-*` headers the
 * client alone holds and a `name`/`target_mode`/`where`/
 * `content` envelope, and the Airship sink (WR-284)
 * delivers through Airship's Push API with a Basic-auth
 * header the client alone holds and an `audience`/
 * `notification`/`device_types` envelope, this sink
 * delivers push notifications through MoEngage's Push API
 * (V5): one event is sent as one POST that creates a push
 * campaign, and MoEngage — not the relay — owns the
 * audience targeting, the delivery, and the retention of
 * the notification.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a MoEngage
 * server. The sink owns the relay-side concerns — region
 * host, audience and query-type matching, campaign naming,
 * platform payload derivation, payload-inclusion policy,
 * per-message failure mapping — and the injected client
 * owns the wire protocol, including the POST call, the
 * Basic authentication, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://api-01.moengage.com/v5/push/notifications",
 *     headers: { "Content-Type": "application/json",
 *                "X-MOE-Query-Type": "user" },
 *     body: "{\"campaignName\":\"<name>\",\"targetPlatform\":[\"ANDROID\",\"IOS\",\"WEB\"],\"targetAudience\":\"User\",\"payload\":{\"ANDROID\":{\"title\":\"<title>\",\"message\":\"<body>\"},\"IOS\":{...},\"WEB\":{...}},\"requestType\":\"push\",\"targetUserAttributes\":{...}}" }
 *
 * The client POSTs to that URL, sending `body`
 * verbatim as the request body (JSON) and `headers`
 * verbatim as the request headers, and authenticating
 * with a Basic `Authorization` header carrying
 * `workspace_id:api_key` — which it alone holds. Five
 * things about this shape are deliberate, and all follow
 * the sibling sinks:
 *
 * - The credentials are held by the client alone. The sink
 *   never receives them, never places them in the request,
 *   and never logs them: like the CleverTap sink (WR-285),
 *   whose account id and passcode the client alone holds,
 *   this sink's handed request carries no credential at
 *   all — the client adds the `Authorization: Basic ...`
 *   header from the workspace id and API key it alone
 *   holds, so there is nothing in the handed request for
 *   a log line or a retry queue to leak. The backlog
 *   item's "只由 client 持有" is the client's
 *   configuration, not the sink's: no credential ever
 *   enters the sink config. This is the opposite of the
 *   WonderPush sink (WR-282), whose access token rides in
 *   the form body because that API authenticates that way:
 *   MoEngage authenticates by header, so the body
 *   carries only routing and content.
 * - The host is config-held, not fixed: MoEngage serves
 *   the same API from one host per data center — the
 *   default `api-01.moengage.com` is DC-01, `api-02`
 *   serves DC-02, and so on — so the sink config holds
 *   the full host (default `api-01.moengage.com`) and
 *   the sink builds `https://<host>/v5/push/notifications`
 *   from it. A fixed host here could only misroute a
 *   message to the wrong data center's workspace. The
 *   endpoint, the JSON envelope, and the headers match the
 *   current MoEngage documentation (checked this round,
 *   2026-10-31): `POST /v5/push/notifications` with
 *   camelCase fields, answering with a `{response_id,
 *   type, data}` envelope; the v2.1/v2 legacy endpoints
 *   stop working after 30 November 2026, so this sink
 *   pins the supported V5 endpoint and nothing older.
 * - The `X-MOE-Query-Type` header is sink-owned, not
 *   client-owned: it is derived from the config's
 *   `targetAudience` (and `bulkUserRequest`), not from a
 *   secret, so the sink sends it in the handed request
 *   headers — `User` maps to `user` (or `bulk users`
 *   when `bulkUserRequest` is true), `Custom Segment` to
 *   `custom segment`, `All Users` to `all users`. The
 *   docs require the header to match `targetAudience`,
 *   case-insensitive; a missing or mismatched value
 *   returns 400. The sink computes the header from the
 *   same resolved audience it puts in the body, so the
 *   two can never disagree.
 * - The `payload` object carries one block per listed
 *   `targetPlatform` (ANDROID, IOS, WEB), each block
 *   carrying the notification content as `title` and
 *   `message` derived from the event (see below). The
 *   V5 reference pins `payload` as the per-platform
 *   content object — "Include one block for each platform
 *   listed in `targetPlatform`" — and the `title`/
 *   `message` pair is the notification content each
 *   block carries. `requestType` is sent explicitly as
 *   `"push"` (the doc default, and the only supported
 *   value), mirroring how the CleverTap sink sends its
 *   `target_mode` explicitly.
 * - The `targetAudience` rules are enforced at
 *   construction, not discovered at send time: `User`
 *   requires `targetUserAttributes` (held by the sink
 *   config, passed through verbatim — one sink targets
 *   one MoEngage user set), `Custom Segment` requires
 *   `customSegmentName`, and `bulkUserRequest` requires
 *   `requestId` (the doc: `requestId` is required when
 *   `bulkUserRequest` is true). Targeting for another
 *   audience is rejected rather than silently dropped:
 *   sending a User-targeted body to All Users would
 *   notify devices the operator never chose. And the
 *   `campaignName` rules are documented, not enforced by
 *   invention: `campaignName` must be at least 5
 *   characters; for `User` audiences the same name is
 *   reused across calls (one campaign per name); for
 *   `Custom Segment` and `All Users` a new campaign is
 *   created on every call, so the name must be unique —
 *   a repeated name returns 409. The sink derives the
 *   name from the event key when no config name is set
 *   (`webhook-<key>`), so callers targeting those
 *   audiences must pass a distinct key per message; the
 *   sink never invents a suffix to force uniqueness.
 *
 * The response's `type` field — not the HTTP status
 * alone — decides acceptance: a 2xx answers
 * `{"response_id": "<id>", "type":
 * "push_notification", "data": {...}}` (the docs: "A
 * successful response implies payload validity and
 * addition to the processing queue" is CleverTap's
 * wording; MoEngage's is the same shape of promise —
 * "Notification accepted for sending"). The client
 * surfaces the `type` field (and the `response_id`) on
 * the response, and the sink reads them — a 2xx with no
 * `type` surfaced is retryable, because without it the
 * sink cannot claim the campaign was created. A
 * successful response is only an acceptance receipt,
 * not a delivery result: delivery is handled by the
 * provider and depends on valid recipient attributes.
 *
 * Message content — a push notification carries a title
 * and a body, both derived from the event's own values:
 * the first non-empty value among `subject`, `key`, and
 * `traceId`, in that order. The title takes that derived
 * summary — the backlog pins the message to the event,
 * and `subject` is the first link of the chain, so when
 * a subject exists the title is exactly the subject; when
 * it does not, the chain's next value keeps the title
 * valid, because every platform block needs a `title`.
 * The body takes the same summary, so an event with none
 * of the values still notifies, with the generic summary
 * `webhook event`: a notification sink that silently
 * dropped sourceless events would hide exactly the
 * deliveries an operator most needs to see, and the
 * audience — not the content — is the delivery contract
 * here, so no invented target is at stake.
 *
 * Payload inclusion — by default the notification
 * carries the summary only, never the full payload:
 * event bodies routinely carry PII, secrets, or
 * customer data, and a device is a far wider audience
 * than a queue or a stream. Opting into `includePayload`
 * appends the body verbatim after a blank line inside
 * `message`, truncated to `payloadMaxChars`
 * characters (default 2000) with a truncation marker —
 * the opt-in is explicit, and the truncation is
 * unconditional, so even an opted-in body cannot flood a
 * device. The body is appended as plain text inside the
 * `message` field, not a fenced code block: the field is
 * already plain text, and a fence around an already-JSON
 * body would be noise on a device.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over the HTTP status and, on a 2xx, over the response
 * body's `type` field:
 *
 * - a non-2xx POST throws `MoEngageSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says MoEngage could
 *   not accept the message right now, not that the
 *   payload is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, 404, and 409 (mismatched query type, invalid
 *   body, bad workspace id or API key, duplicate
 *   campaign name): retrying them burns the retry budget
 *   for nothing, and rerouting them elsewhere would
 *   notify devices the operator never chose;
 * - on a 2xx, the `type` field decides: `"push_notification"`
 *   means MoEngage accepted the campaign; any other
 *   surfaced `type` is a failure — non-retryable, because
 *   the server answered a different resource than the one
 *   requested and retrying cannot change that; a 2xx
 *   with no `type` field surfaced is retryable — the
 *   field is the acceptance result, and a missing field
 *   means the sink cannot claim the campaign was created;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client throws `MoEngageSinkConfigError`,
 *   which `classifyFailure` maps to `non_retryable`
 *   (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for the title/body. */
export const MOENGAGE_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const MOENGAGE_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Default MoEngage API host (DC-01) when the config sets none. */
export const MOENGAGE_DEFAULT_HOST = "api-01.moengage.com";

/** Content type the client sends with the JSON body. */
export const MOENGAGE_JSON_CONTENT_TYPE = "application/json";

/** The only supported `requestType` value (also the doc default). */
export const MOENGAGE_REQUEST_TYPE = "push";

/** Minimum `campaignName` length, per the V5 docs. */
export const MOENGAGE_MIN_CAMPAIGN_NAME_LENGTH = 5;

/** Default target platforms when the config sets none. */
export const MOENGAGE_DEFAULT_TARGET_PLATFORMS: readonly MoEngageTargetPlatform[] = [
  "ANDROID",
  "IOS",
  "WEB",
];

/** Target platforms the V5 API accepts. */
export const MOENGAGE_TARGET_PLATFORMS = ["ANDROID", "IOS", "WEB"] as const;

/** One target platform in a V5 request. */
export type MoEngageTargetPlatform = (typeof MOENGAGE_TARGET_PLATFORMS)[number];

/** Target audiences the V5 API accepts. */
export const MOENGAGE_TARGET_AUDIENCES = ["User", "Custom Segment", "All Users"] as const;

/** One target audience in a V5 request (canonical spelling). */
export type MoEngageTargetAudience = (typeof MOENGAGE_TARGET_AUDIENCES)[number];

/**
 * The `X-MOE-Query-Type` header value for an audience:
 * `User` maps to `user` (or `bulk users` when
 * `bulkUserRequest` is true), `Custom Segment` to
 * `custom segment`, `All Users` to `all users` — matching
 * `targetAudience`, case-insensitive, per the docs.
 */
export function resolveMoEngageQueryType(
  audience: MoEngageTargetAudience,
  bulkUserRequest: boolean
): string {
  switch (audience) {
    case "User":
      return bulkUserRequest ? "bulk users" : "user";
    case "Custom Segment":
      return "custom segment";
    case "All Users":
      return "all users";
  }
}

/**
 * The user attributes identifying the target users, for a
 * `User` audience: passed through verbatim into the JSON
 * body. Held by the sink config; required when the
 * audience is `User` (the docs: `targetUserAttributes`
 * is required for `User`), and rejected for any other
 * audience — targeting for the wrong audience must fail
 * fast, never silently route to the wrong devices.
 */
export type MoEngageTargetUserAttributes = Record<string, unknown>;

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (JSON) to the data-center endpoint,
 * sending `headers` verbatim as the request headers, and
 * authenticating with a Basic `Authorization` header
 * carrying `workspace_id:api_key` — which the sink never
 * sees.
 */
export interface MoEngageMessagePostRequest {
  /** Always `https://<data-center host>/v5/push/notifications`. */
  url: string;
  /**
   * Request headers, sent verbatim:
   * `{ "Content-Type": "application/json",
   *    "X-MOE-Query-Type": "<query type>" }`. The Basic
   * `Authorization` header is added by the client, never
   * by the sink.
   */
  headers: Record<string, string>;
  /**
   * The JSON request body, serialized:
   * `{"campaignName":"<name>","targetPlatform":["ANDROID","IOS","WEB"],"targetAudience":"User","payload":{"ANDROID":{"title":"<title>","message":"<body>"},"IOS":{...},"WEB":{...}},"requestType":"push","targetUserAttributes":{...}}`
   * (plus `customSegmentName` for a `Custom Segment`
   * audience, or `bulkUserRequest`/`requestId` for bulk
   * user requests).
   */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * The HTTP status drives the HTTP retry mapping; on a 2xx
 * the client surfaces the response body's `type` field
 * (`"push_notification"` on acceptance) and the
 * `response_id` — and the `type` field, not the HTTP
 * status alone, decides whether the campaign was created.
 * A client that reports a 2xx without a `type` field
 * leaves the sink unable to claim acceptance, so the
 * message is treated as a retryable delivery failure.
 */
export interface MoEngageMessagePostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
  /**
   * The `type` field of the MoEngage JSON body, on a
   * 2xx: `"push_notification"` means the campaign was
   * accepted (an acceptance receipt only, not a delivery
   * result); any other surfaced value means the server
   * answered a different resource.
   */
  type?: string;
  /**
   * The `response_id` field of the MoEngage JSON body,
   * when the client surfaces it: the unique ID of the
   * response, quoted when contacting MoEngage Support.
   */
  responseId?: string;
}

/**
 * The injected MoEngage message client. Any client adapter
 * implements this one method; it returns the POST's status
 * and, on a 2xx, the response body's `type` field (and the
 * `response_id` when surfaced) — a throw is a codeless
 * transport failure, retryable. The client is expected to
 * POST one message per call, sending `body` verbatim as
 * the request body (JSON), sending `headers` verbatim as
 * the request headers, and authenticating with a Basic
 * `Authorization` header carrying `workspace_id:api_key`
 * — which the sink never sees.
 */
export interface MoEngageMessageClient {
  post(request: MoEngageMessagePostRequest): Promise<MoEngageMessagePostResponse>;
}

/**
 * Configuration for one MoEngage sink. The client is
 * injected: without one, `send()` throws
 * `MoEngageSinkConfigError` (dry runs excepted — they need
 * no client at all). The data-center host defaults to
 * `api-01.moengage.com` (DC-01) when unset; the audience
 * defaults to `User` when unset; the platforms default to
 * `["ANDROID", "IOS", "WEB"]` when unset. The workspace
 * id and API key are deliberately absent from this config:
 * the client alone holds them and sends them as the Basic
 * `Authorization` header.
 */
export interface MoEngageSinkConfig {
  /**
   * The MoEngage API host for the account's data center,
   * as a bare hostname with no scheme or path:
   * `api-01.moengage.com` is DC-01, `api-02` serves
   * DC-02, and so on. Defaults to `api-01.moengage.com`
   * when unset. Must be a non-empty hostname when set.
   */
  regionHost?: string;
  /**
   * The target audience for the campaign: `"User"`,
   * `"Custom Segment"`, or `"All Users"` (case-insensitive
   * at construction, normalized to the canonical
   * spelling). Defaults to `"User"` when unset. The
   * matching `X-MOE-Query-Type` header is derived from
   * this value at send time.
   */
  targetAudience?: string;
  /**
   * The campaign name shown in the MoEngage dashboard.
   * When set, every message creates a campaign under
   * this name; when unset, the name derives per message
   * from the event's `key` (`webhook-<key>`), falling
   * back to `webhook event` for keyless events. Must be
   * at least 5 characters when set. Note the audience
   * rule: for `User` the name is reused across calls
   * (one campaign per name); for `Custom Segment` and
   * `All Users` a new campaign is created on every call,
   * so the name must be unique — callers targeting those
   * audiences must pass a distinct key per message, or
   * a repeated name returns 409.
   */
  campaignName?: string;
  /**
   * The platforms targeted by the campaign: a non-empty
   * subset of `["ANDROID", "IOS", "WEB"]`. Defaults to
   * all three when unset. Each listed platform gets a
   * matching block in `payload`.
   */
  targetPlatform?: MoEngageTargetPlatform[];
  /**
   * The user attributes identifying the target users,
   * passed through verbatim into the JSON body. Required
   * when the audience is `User`; rejected for any other
   * audience. Must be a non-array object when set.
   */
  targetUserAttributes?: MoEngageTargetUserAttributes;
  /**
   * The name of the custom segment to target. Required
   * when the audience is `Custom Segment` (the segment
   * must exist and must not be archived); rejected for
   * any other audience. Must be a non-empty string when
   * set.
   */
  customSegmentName?: string;
  /**
   * Whether to process a `User` request asynchronously,
   * in bulk mode. Only meaningful for the `User`
   * audience; when `true`, the `X-MOE-Query-Type`
   * header is `bulk users` and `requestId` is required.
   * Rejected for any other audience.
   */
  bulkUserRequest?: boolean;
  /**
   * A client-side trace ID for the request. MoEngage
   * returns it in `data.request_id` in the response.
   * Required when `bulkUserRequest` is `true`. Must be a
   * non-empty string when set.
   */
  requestId?: string;
  /**
   * The MoEngage message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `MoEngageMessageClient` and alone holds
   * the workspace id and API key. Required for real sends; a
   * missing client is a config error, not a silent no-op.
   */
  client?: MoEngageMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including notification derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The client is not required in dry-run mode, mirroring
   * the sibling sinks' dry-run exemption; the rest of the
   * config must still be valid — a dry run against an
   * audience with no targeting would rehearse a request
   * that could never send.
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
export interface MoEngageRecord {
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
export interface MoEngageFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /**
   * Failure code: `HTTP_<status>` for a non-2xx POST,
   * `TYPE_MISMATCH` for a 2xx whose surfaced `type` is
   * not `"push_notification"`, `TYPE_MISSING` for a 2xx
   * with no `type` field surfaced, or
   * `TRANSPORT_ERROR` for a codeless failure.
   */
  errorCode: string;
  /** Downstream HTTP status, when the failure was a non-2xx POST. */
  statusCode?: number;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: 429 and 5xx
   * (plus codeless transport failures and missing `type`
   * fields) are retryable; every other non-2xx status
   * and a mismatched `type` are fail-closed messages
   * (mismatched query type, invalid body, bad workspace
   * id or API key, duplicate campaign name).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface MoEngageSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-286). */
export interface MoEngageSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for MoEngage send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on MoEngage's server and are *not* in
 * `failedRecords`.
 */
export class MoEngageSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: MoEngageFailedRecord[];
  constructor(message: string, failedRecords: MoEngageFailedRecord[]) {
    super(message);
    this.name = "MoEngageSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class MoEngageSinkConfigError extends MoEngageSinkError {
  constructor(reason: string) {
    super(`moengage-sink: ${reason}`, []);
    this.name = "MoEngageSinkConfigError";
  }
}

/**
 * Resolve a configured audience to its canonical spelling,
 * case-insensitively. Throws `RangeError` on any other
 * value — the docs accept only `User`, `Custom Segment`,
 * and `All Users`.
 */
export function resolveMoEngageTargetAudience(
  audience: string | undefined
): MoEngageTargetAudience {
  if (audience === undefined) return "User";
  const lower = audience.toLowerCase();
  for (const canonical of MOENGAGE_TARGET_AUDIENCES) {
    if (canonical.toLowerCase() === lower) return canonical;
  }
  throw new RangeError(
    `moengage-sink: \`targetAudience\` must be one of "User", "Custom Segment", "All Users" when set`
  );
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing region host, campaign name, or platform list is *not* a
 * shape error: they default at send time (DC-01 host, derived
 * name, all three platforms), so a sink built before its targeting
 * is known still sends rather than crashing at construction. A
 * present `regionHost` must be a bare hostname (no scheme, no
 * path); a present `campaignName` must be a non-empty string of at
 * least 5 characters; a present `targetPlatform` must be a
 * non-empty array of `ANDROID`/`IOS`/`WEB`. The audience rules
 * are enforced here, not at send time: `User` requires
 * `targetUserAttributes`, `Custom Segment` requires
 * `customSegmentName`, `bulkUserRequest` requires the `User`
 * audience and a `requestId`, and targeting for another
 * audience is rejected rather than silently dropped.
 */
export function assertValidMoEngageSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is MoEngageSinkConfig {
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
  let audience: MoEngageTargetAudience;
  try {
    audience = resolveMoEngageTargetAudience(c.targetAudience as string | undefined);
  } catch {
    throw new RangeError(
      at('`targetAudience` must be one of "User", "Custom Segment", "All Users" when set')
    );
  }
  if (
    c.campaignName !== undefined &&
    (typeof c.campaignName !== "string" ||
      c.campaignName === "" ||
      c.campaignName.length < MOENGAGE_MIN_CAMPAIGN_NAME_LENGTH)
  ) {
    throw new RangeError(
      at(`\`campaignName\` must be a non-empty string of at least ${MOENGAGE_MIN_CAMPAIGN_NAME_LENGTH} characters when set`)
    );
  }
  const targetPlatform = c.targetPlatform;
  if (targetPlatform !== undefined) {
    if (
      !Array.isArray(targetPlatform) ||
      targetPlatform.length === 0 ||
      targetPlatform.some(
        (p) => typeof p !== "string" || !(MOENGAGE_TARGET_PLATFORMS as readonly string[]).includes(p)
      )
    ) {
      throw new RangeError(at("`targetPlatform` must be a non-empty array of \"ANDROID\" / \"IOS\" / \"WEB\" when set"));
    }
  }
  const targetUserAttributes = c.targetUserAttributes;
  if (
    targetUserAttributes !== undefined &&
    (targetUserAttributes === null ||
      typeof targetUserAttributes !== "object" ||
      Array.isArray(targetUserAttributes))
  ) {
    throw new RangeError(at("`targetUserAttributes` must be a non-array object when set"));
  }
  if (audience === "User" && targetUserAttributes === undefined) {
    throw new RangeError(at("`targetUserAttributes` is required when `targetAudience` is \"User\""));
  }
  if (audience !== "User" && targetUserAttributes !== undefined) {
    throw new RangeError(at("`targetUserAttributes` is only valid when `targetAudience` is \"User\""));
  }
  if (
    c.customSegmentName !== undefined &&
    (typeof c.customSegmentName !== "string" || c.customSegmentName === "")
  ) {
    throw new RangeError(at("`customSegmentName` must be a non-empty string when set"));
  }
  if (audience === "Custom Segment" && c.customSegmentName === undefined) {
    throw new RangeError(at("`customSegmentName` is required when `targetAudience` is \"Custom Segment\""));
  }
  if (audience !== "Custom Segment" && c.customSegmentName !== undefined) {
    throw new RangeError(at("`customSegmentName` is only valid when `targetAudience` is \"Custom Segment\""));
  }
  if (c.bulkUserRequest !== undefined && typeof c.bulkUserRequest !== "boolean") {
    throw new RangeError(at("`bulkUserRequest` must be a boolean when set"));
  }
  if (c.bulkUserRequest === true && audience !== "User") {
    throw new RangeError(at("`bulkUserRequest` is only valid when `targetAudience` is \"User\""));
  }
  if (
    c.requestId !== undefined &&
    (typeof c.requestId !== "string" || c.requestId === "")
  ) {
    throw new RangeError(at("`requestId` must be a non-empty string when set"));
  }
  if (c.bulkUserRequest === true && c.requestId === undefined) {
    throw new RangeError(at("`requestId` is required when `bulkUserRequest` is true"));
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
 * or `api-01.moengage.com` (DC-01) when the config sets
 * none.
 */
export function resolveMoEngageHost(
  config: Pick<MoEngageSinkConfig, "regionHost">
): string {
  return config.regionHost ?? MOENGAGE_DEFAULT_HOST;
}

/**
 * Resolve the effective target platforms: the configured
 * list, or all three platforms when the config sets none.
 */
export function resolveMoEngageTargetPlatform(
  config: Pick<MoEngageSinkConfig, "targetPlatform">
): MoEngageTargetPlatform[] {
  return config.targetPlatform ?? [...MOENGAGE_DEFAULT_TARGET_PLATFORMS];
}

/**
 * Build the Push API (V5) endpoint URL for a region host:
 * `https://<host>/v5/push/notifications`.
 */
export function buildMoEngageNotificationsUrl(regionHost: string): string {
  return `https://${regionHost}/v5/push/notifications`;
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
export function resolveMoEngageSummary(record: MoEngageRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return MOENGAGE_FALLBACK_SUMMARY;
}

/**
 * Derive one record's campaign name: the configured
 * `campaignName` when set, otherwise `webhook-<key>`
 * from the event's key, falling back to the generic
 * `webhook event` summary for keyless events. Every
 * derived name is at least 5 characters (the doc minimum):
 * the `webhook-` prefix alone is 8.
 */
export function resolveMoEngageCampaignName(
  record: MoEngageRecord,
  config: Pick<MoEngageSinkConfig, "campaignName">
): string {
  if (config.campaignName !== undefined) return config.campaignName;
  if (record.key !== undefined && record.key !== "") return `webhook-${record.key}`;
  return MOENGAGE_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a device.
 */
export function truncateMoEngagePayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's notification content: `title` and
 * `message` both take the derived summary (the first
 * non-empty among `subject`, `key`, and `traceId`,
 * falling back to `webhook event`) — the title because
 * every platform block needs a `title` and the backlog
 * pins the message to the event's subject, the first link
 * of the chain — then the event body is appended after a
 * blank line only under the `includePayload` opt-in
 * (truncated to `payloadMaxChars`, default 2000).
 */
export function resolveMoEngageContent(
  record: MoEngageRecord,
  config: Pick<MoEngageSinkConfig, "includePayload" | "payloadMaxChars">
): { title: string; message: string } {
  const summary = resolveMoEngageSummary(record);
  let message = summary;
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? MOENGAGE_DEFAULT_PAYLOAD_MAX_CHARS;
    message = `${summary}\n\n${truncateMoEngagePayload(record.body, limit)}`;
  }
  return { title: summary, message };
}

/**
 * Build the per-platform `payload` object: one block per
 * listed platform, each carrying the notification content
 * as `title`/`message`. The V5 docs require one block for
 * each platform listed in `targetPlatform`.
 */
export function buildMoEngagePayload(
  platforms: readonly MoEngageTargetPlatform[],
  content: { title: string; message: string }
): Record<string, { title: string; message: string }> {
  const payload: Record<string, { title: string; message: string }> = {};
  for (const platform of platforms) {
    payload[platform] = { title: content.title, message: content.message };
  }
  return payload;
}

/**
 * Build one record's serialized JSON body: the V5 request
 * object with `campaignName`, `targetPlatform`,
 * `targetAudience`, `payload`, and `requestType` fixed to
 * `"push"`, plus the audience's targeting — `targetUserAttributes`
 * for `User`, `customSegmentName` for `Custom Segment` —
 * and `bulkUserRequest`/`requestId` for bulk user
 * requests. The workspace id and API key never appear here —
 * the client alone holds them and sends them as the Basic
 * `Authorization` header.
 */
export function buildMoEngageNotificationsBody(
  name: string,
  platforms: readonly MoEngageTargetPlatform[],
  audience: MoEngageTargetAudience,
  content: { title: string; message: string },
  config: Pick<
    MoEngageSinkConfig,
    "targetUserAttributes" | "customSegmentName" | "bulkUserRequest" | "requestId"
  >
): string {
  const body: Record<string, unknown> = {
    campaignName: name,
    targetPlatform: [...platforms],
    targetAudience: audience,
    payload: buildMoEngagePayload(platforms, content),
    requestType: MOENGAGE_REQUEST_TYPE,
  };
  if (audience === "User" && config.targetUserAttributes !== undefined) {
    body.targetUserAttributes = config.targetUserAttributes;
  }
  if (audience === "Custom Segment" && config.customSegmentName !== undefined) {
    body.customSegmentName = config.customSegmentName;
  }
  if (config.bulkUserRequest === true) {
    body.bulkUserRequest = true;
  }
  if (config.requestId !== undefined) {
    body.requestId = config.requestId;
  }
  return JSON.stringify(body);
}

/**
 * Validate one record's body. Throws `RangeError` on an
 * empty body string — even without the opt-in, the body is
 * the record's payload, and an empty record is a caller
 * bug that must fail closed, never notify as an empty
 * message.
 */
export function resolveMoEngageRecord(
  record: MoEngageRecord,
  index: number
): { index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`moengage-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { index };
}

/**
 * Map one MoEngage POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says MoEngage could not
 * accept the message right now, not that the payload is
 * poison. Every other non-2xx status (400, 401, 403,
 * 404, 409, and the rest) is a fail-closed message:
 * mismatched query type, invalid body, bad workspace id
 * or API key, duplicate campaign name, or another verdict
 * retrying cannot change. Callers only pass non-2xx
 * statuses here; a 2xx status is decided by the response
 * body's `type` field, not by this function.
 */
export function classifyMoEngageRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Map one MoEngage POST response onto its failed record,
 * or `null` when the response accepted the message (a 2xx
 * with the `type` field `"push_notification"`). A 2xx
 * with any other surfaced `type` is a failure —
 * non-retryable, because the server answered a different
 * resource than the one requested and retrying cannot
 * change that. A 2xx with no `type` field surfaced is
 * retryable — the field is the acceptance result, and
 * without it the sink cannot claim the campaign was
 * created.
 */
export function moEngageResponseToFailedRecord(
  response: MoEngageMessagePostResponse,
  index: number
): MoEngageFailedRecord | null {
  if (response.type === "push_notification") {
    return null;
  }
  if (response.type !== undefined) {
    return {
      index,
      errorCode: "TYPE_MISMATCH",
      errorMessage: `MoEngage answered 2xx with type "${response.type}", not "push_notification"`,
      retryable: false,
    };
  }
  return {
    index,
    errorCode: "TYPE_MISSING",
    errorMessage: "MoEngage answered 2xx but surfaced no type field",
    retryable: true,
  };
}

/**
 * MoEngage sink (WR-286). One instance targets one
 * MoEngage data-center account audience; the caller owns retry /
 * dead-letter policy around `send()` — this class performs
 * one POST attempt per message through the injected client
 * and reports its outcome. Failures throw
 * `MoEngageSinkError` carrying exactly the failed messages
 * with their retry lanes.
 */
export class MoEngageSink {
  private readonly cfg: MoEngageSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: MoEngageSinkConfig) {
    assertValidMoEngageSinkConfig(config, "MoEngageSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): MoEngageSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send push notifications, in input order. Throws
   * `MoEngageSinkConfigError` when no client was injected,
   * and `MoEngageSinkError` when any message fails
   * (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: MoEngageRecord[]): Promise<MoEngageSendResult> {
    const resolved = records.map((r, i) => resolveMoEngageRecord(r, i));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The client
      // is not required here, mirroring the sibling sinks'
      // dry-run exemption; the rest of the config was already
      // validated at construction.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new MoEngageSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const audience = resolveMoEngageTargetAudience(this.cfg.targetAudience);
    const bulkUserRequest = this.cfg.bulkUserRequest === true;
    const url = buildMoEngageNotificationsUrl(resolveMoEngageHost(this.cfg));
    const platforms = resolveMoEngageTargetPlatform(this.cfg);
    const failedRecords: MoEngageFailedRecord[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          url,
          headers: {
            "Content-Type": MOENGAGE_JSON_CONTENT_TYPE,
            "X-MOE-Query-Type": resolveMoEngageQueryType(audience, bulkUserRequest),
          },
          body: buildMoEngageNotificationsBody(
            resolveMoEngageCampaignName(records[i], this.cfg),
            platforms,
            audience,
            resolveMoEngageContent(records[i], this.cfg),
            this.cfg
          ),
        });
        if (response.status >= 200 && response.status < 300) {
          const typeFailure = moEngageResponseToFailedRecord(response, record.index);
          if (typeFailure === null) {
            sent += 1;
            continue;
          }
          failedRecords.push(typeFailure);
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyMoEngageRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toMoEngageFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new MoEngageSinkError(
        `moengage-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toMoEngageFailedRecord(err: unknown, index: number): MoEngageFailedRecord {
  const failed: MoEngageFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
