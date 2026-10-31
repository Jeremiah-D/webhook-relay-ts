/**
 * Pusher Beams push notification delivery sink (WR-289).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's device. Where the Iterable sink
 * (WR-288) delivers push notifications through Iterable's
 * push/target API with an `Api-Key` header the client alone
 * holds and a `campaignId`/`recipientEmail`/`dataFields`
 * envelope decided by the HTTP status alone, this sink
 * delivers push notifications through Pusher Beams'
 * Publish API: one event is sent as one POST that publishes
 * to one or more interests, and Beams — not the relay —
 * owns the audience targeting, the delivery, and the
 * retention of the notification.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Beams
 * server. The sink owns the relay-side concerns — instance
 * identity, interest targeting, platform payload derivation,
 * payload-inclusion policy, per-message failure mapping —
 * and the injected client owns the wire protocol, including
 * the POST call, the `Authorization: Bearer <secret key>`
 * authentication, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://<instanceId>.pushnotifications.pusher.com/publish_api/v1/instances/<instanceId>/publishes",
 *     headers: { "Content-Type": "application/json" },
 *     body: "{\"interests\":[\"hello\"],\"fcm\":{\"notification\":{\"title\":\"<title>\",\"body\":\"<body>\"}},\"apns\":{\"aps\":{\"alert\":{\"title\":\"<title>\",\"body\":\"<body>\"}}},\"web\":{\"notification\":{\"title\":\"<title>\",\"body\":\"<body>\"}}}" }
 *
 * The client POSTs to that URL, sending `body`
 * verbatim as the request body (JSON) and `headers`
 * verbatim as the request headers, and authenticating
 * with an `Authorization: Bearer <secret key>` header
 * carrying the instance secret key — which it alone holds.
 * Five things about this shape are deliberate, and all
 * follow the sibling sinks:
 *
 * - The credentials are held by the client alone. The sink
 *   never receives them, never places them in the request,
 *   and never logs them: like the Iterable sink (WR-288),
 *   whose server-side API key the client alone holds, this
 *   sink's handed request carries no credential at all — the
 *   client adds the `Authorization` header from the instance
 *   secret key it alone holds, so there is nothing in the
 *   handed request for a log line or a retry queue to leak.
 *   This is the opposite of the WonderPush sink (WR-282),
 *   whose access token rides in the form body because that
 *   API authenticates that way: Beams authenticates by
 *   header, so the body carries only routing and content.
 * - The endpoint is the classic `/publishes` path the
 *   backlog pins, with the interests in the request body:
 *   `POST https://<instanceId>.pushnotifications.pusher.com
 *   /publish_api/v1/instances/<instanceId>/publishes`. The
 *   current Publish API reference page also documents the
 *   split `/publishes/interests` and `/publishes/users`
 *   paths; the `/publishes` form with `interests` in the
 *   body is the form the Beams quickstart tutorials still
 *   use, and the backlog pins it, so the sink uses it and
 *   does not guess at the split paths. The host is built
 *   from the config-held `instanceId` — the instance is the
 *   routing identity, and a sink built for the wrong
 *   instance would notify the wrong audience.
 * - The `interests` list is config-held and required: 1–100
 *   interests per publish request, each at most 164
 *   characters drawn from ASCII letters, digits, and
 *   `_-=@,.;` (the docs' limits, enforced at construction).
 *   One sink targets one fixed interest set; the sink never
 *   invents an interest, and a publish against an interest
 *   no device subscribes to is still accepted by Beams —
 *   the audience is the devices' subscriptions, not the
 *   sink's. Multiple interests mean delivery to devices
 *   subscribed to any of them.
 * - The platform payloads are derived, not passed through:
 *   the sink builds `fcm.notification`, `apns.aps.alert`,
 *   and `web.notification` from the same derived title and
 *   body, for exactly the platforms the config enables
 *   (default: all three). An operator who needs a
 *   platform-specific payload shape beyond title/body uses
 *   that platform's own API; this sink's contract is one
 *   notification, every enabled platform, same content.
 * - The `webhookUrl` field is never sent: the docs list it
 *   as an optional publish webhook, but the backlog pins
 *   only the interests and the three platform payloads, so
 *   the sink does not invent a webhook destination. An
 *   operator who wants publish webhooks configures them in
 *   the Beams dashboard.
 *
 * Acceptance is decided by the HTTP status plus the
 * response body's `publishId`: a 2xx means Beams received
 * the publish, and the success body carries `publishId`
 * (a string), the receipt the operator correlates with
 * Beams' publish webhooks (`v1.PublishToInterestsAttempt`
 * carries the same `publish_id`). The client surfaces the
 * status and the `publishId` when present; `send()` returns
 * the collected publish IDs in send order, so a caller
 * that only inspects the result still has the receipts.
 * A successful response is only an acceptance receipt, not
 * a delivery result: delivery is handled by Beams and the
 * platform gateways, and surfaces later through Beams'
 * webhooks. A 2xx without a `publishId` is still an
 * acceptance — the docs promise the field on success, but
 * the status is the verdict and a missing field must not
 * turn an accepted publish into a failure.
 *
 * Message content — a push notification carries a title
 * and a body, both derived from the event's own values:
 * the first non-empty value among `subject`, `key`, and
 * `traceId`, in that order. The title takes that derived
 * summary — the backlog pins the message to the event,
 * and `subject` is the first link of the chain, so when
 * a subject exists the title is exactly the subject; when
 * it does not, the chain's next value keeps the title
 * valid, because every platform's notification slot needs
 * a value. The body takes the same summary, so an event
 * with none of the values still notifies, with the
 * generic summary `webhook event`: a notification sink
 * that silently dropped sourceless events would hide
 * exactly the deliveries an operator most needs to see,
 * and the interests — not the content — are the delivery
 * contract here, so no invented target is at stake.
 * Both go into each enabled platform payload as its
 * `title`/`body` (FCM and web) or `alert.title`/
 * `alert.body` (APNs).
 *
 * Payload inclusion — by default the notification
 * carries the summary only, never the full payload:
 * event bodies routinely carry PII, secrets, or
 * customer data, and a device is a far wider audience
 * than a queue or a stream. Opting into `includePayload`
 * appends the body verbatim after a blank line inside
 * the notification body, truncated to `payloadMaxChars`
 * characters (default 2000) with a truncation marker —
 * the opt-in is explicit, and the truncation is
 * unconditional, so even an opted-in body cannot flood a
 * device. The body is appended as plain text inside the
 * notification body, not a fenced code block: the field
 * is already plain text, and a fence around an already-JSON
 * body would be noise on a device. The docs cap a publish
 * request body at 10KiB; the 2000-character default keeps
 * a notification far under it, and the truncation is
 * unconditional under the opt-in.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over the HTTP status:
 *
 * - a non-2xx POST throws `PusherBeamsSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Beams could not
 *   accept the message right now, not that the payload
 *   is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   402, and 404 (bad interests or payload, bad instance
 *   secret key, publishing blocked for being over plan
 *   limits, unknown instance): retrying them burns the
 *   retry budget for nothing, and rerouting them
 *   elsewhere would notify people the operator never
 *   chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client throws `PusherBeamsSinkConfigError`,
 *   which `classifyFailure` maps to `non_retryable`
 *   (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for the title/body. */
export const PUSHER_BEAMS_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const PUSHER_BEAMS_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Maximum interests per publish request, per the Beams docs. */
export const PUSHER_BEAMS_MAX_INTERESTS = 100;

/** Maximum interest name length, in characters, per the Beams docs. */
export const PUSHER_BEAMS_MAX_INTEREST_LENGTH = 164;

/**
 * Interest name characters, per the Beams docs: ASCII
 * upper- or lower-case letters, numbers, or one of
 * `_-=@,.;`.
 */
export const PUSHER_BEAMS_INTEREST_PATTERN = /^[A-Za-z0-9_\-=@,.;]+$/;

/** Content type the client sends with the JSON body. */
export const PUSHER_BEAMS_JSON_CONTENT_TYPE = "application/json";

/** Publish API path, relative to the instance host. */
export const PUSHER_BEAMS_PUBLISH_PATH = "/publish_api/v1/instances";

/** Platforms a publish can target. */
export type PusherBeamsPlatform = "fcm" | "apns" | "web";

/** All three platforms, the default when the config sets none. */
export const PUSHER_BEAMS_ALL_PLATFORMS: readonly PusherBeamsPlatform[] = ["fcm", "apns", "web"];

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (JSON) to the instance endpoint,
 * sending `headers` verbatim as the request headers, and
 * authenticating with an `Authorization: Bearer <secret
 * key>` header carrying the instance secret key — which
 * the sink never sees.
 */
export interface PusherBeamsMessagePostRequest {
  /** Always `https://<instanceId>.pushnotifications.pusher.com/publish_api/v1/instances/<instanceId>/publishes`. */
  url: string;
  /**
   * Request headers, sent verbatim:
   * `{ "Content-Type": "application/json" }`. The
   * `Authorization` header is added by the client, never by
   * the sink.
   */
  headers: Record<string, string>;
  /**
   * The JSON request body, serialized:
   * `{"interests":["hello"],"fcm":{"notification":{"title":"<title>","body":"<body>"}},"apns":{"aps":{"alert":{"title":"<title>","body":"<body>"}}},"web":{"notification":{"title":"<title>","body":"<body>"}}}`
   * (only the configured platforms are present).
   */
  body: string;
}

/**
 * The result of one POST, as reported by the injected
 * client. The HTTP status decides acceptance: any 2xx
 * means Beams received the publish. The success body
 * carries `publishId`, the receipt the operator correlates
 * with Beams' publish webhooks — the client surfaces it
 * when present, and `send()` returns the collected IDs.
 * A 2xx without a `publishId` is still an acceptance.
 */
export interface PusherBeamsMessagePostResponse {
  /** The HTTP status of the POST (e.g. 200, 400, 401, 402, 429, 503). */
  status: number;
  /** The publish receipt from the success body, when the client surfaced one. */
  publishId?: string;
}

/**
 * The injected Pusher Beams message client. Any client adapter
 * implements this one method; it returns the POST's status
 * and the publish receipt when present — a throw is a
 * codeless transport failure, retryable. The client is
 * expected to POST one message per call, sending `body`
 * verbatim as the request body (JSON), sending `headers`
 * verbatim as the request headers, and authenticating with
 * an `Authorization: Bearer <secret key>` header carrying
 * the instance secret key — which the sink never sees.
 */
export interface PusherBeamsMessageClient {
  post(request: PusherBeamsMessagePostRequest): Promise<PusherBeamsMessagePostResponse>;
}

/**
 * Configuration for one Pusher Beams sink. The client is
 * injected: without one, `send()` throws
 * `PusherBeamsSinkConfigError` (dry runs excepted — they need
 * no client at all). The instance secret key is deliberately
 * absent from this config: the client alone holds it and
 * sends it as the `Authorization` header.
 */
export interface PusherBeamsSinkConfig {
  /**
   * The Beams instance ID: the routing identity of the
   * instance, used in both the host and the path
   * (`https://<instanceId>.pushnotifications.pusher.com/
   * publish_api/v1/instances/<instanceId>/publishes`).
   * Required — the sink never invents an instance, and a
   * sink built for the wrong instance would notify the
   * wrong audience. Must be a non-empty bare identifier
   * (no scheme, no slash) when set.
   */
  instanceId: string;
  /**
   * The interests to publish to: devices subscribed to
   * any of them receive the notification. Required, 1–100
   * interests; each at most 164 characters drawn from
   * ASCII letters, digits, and `_-=@,.;` (the docs'
   * limits, enforced at construction so a bad interest
   * fails fast instead of answering 400 at send time).
   */
  interests: string[];
  /**
   * The platforms to build payloads for, in send order:
   * any subset of `"fcm"`, `"apns"`, `"web"`. Defaults to
   * all three when unset. Must be non-empty, with no
   * duplicates and no unknown platform, when set.
   */
  platforms?: PusherBeamsPlatform[];
  /**
   * The Pusher Beams message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `PusherBeamsMessageClient` and alone holds
   * the instance secret key. Required for real sends; a
   * missing client is a config error, not a silent no-op.
   */
  client?: PusherBeamsMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, publishIds: [], dryRun: true }`
   * and performs zero client I/O — no POST call, no stat
   * changes. Messages are still validated (including
   * notification derivation), so a dry run catches a
   * malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The client is not required in dry-run mode, mirroring
   * the sibling sinks' dry-run exemption; the rest of the
   * config must still be valid — a dry run against an
   * instance with no interests would rehearse a request
   * that could never send.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the notification body
   * appends the event body verbatim after a blank line,
   * truncated to `payloadMaxChars` characters (see below).
   * When `false` or absent, the message carries the
   * summary only — the default, so event bodies (which
   * routinely carry PII) never leak into a notification
   * unless the operator explicitly asks for them.
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
export interface PusherBeamsRecord {
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
export interface PusherBeamsFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /**
   * Failure code: `HTTP_<status>` for a non-2xx POST, or
   * `TRANSPORT_ERROR` for a codeless failure.
   */
  errorCode: string;
  /** Downstream HTTP status, when the failure was a non-2xx POST. */
  statusCode?: number;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: 429 and 5xx
   * (plus codeless transport failures) are retryable;
   * every other non-2xx status is a fail-closed message
   * (bad interests or payload, bad instance secret key,
   * over plan limits, unknown instance).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface PusherBeamsSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /**
   * Publish receipts in send order — the `publishId` of
   * each accepted message that reported one. Empty in
   * dry-run mode. A 2xx without a `publishId` still counts
   * as accepted but contributes no entry here.
   */
  publishIds: string[];
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-289). */
export interface PusherBeamsSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Pusher Beams send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already received on Beams' server and are *not* in
 * `failedRecords`.
 */
export class PusherBeamsSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: PusherBeamsFailedRecord[];
  constructor(message: string, failedRecords: PusherBeamsFailedRecord[]) {
    super(message);
    this.name = "PusherBeamsSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class PusherBeamsSinkConfigError extends PusherBeamsSinkError {
  constructor(reason: string) {
    super(`pusher-beams-sink: ${reason}`, []);
    this.name = "PusherBeamsSinkConfigError";
  }
}

/**
 * Validate one interest name: non-empty, at most 164
 * characters, drawn from ASCII letters, digits, and
 * `_-=@,.;` — the docs' limits, enforced here so a bad
 * interest fails fast at construction instead of answering
 * 400 at send time. Throws `RangeError` otherwise.
 */
export function resolvePusherBeamsInterest(
  interest: unknown,
  index: number,
  label: string
): string {
  const at = (what: string) => `${label}: ${what}`;
  if (typeof interest !== "string" || interest === "") {
    throw new RangeError(at(`\`interests[${index}]\` must be a non-empty string`));
  }
  if (interest.length > PUSHER_BEAMS_MAX_INTEREST_LENGTH) {
    throw new RangeError(
      at(`\`interests[${index}]\` must be at most ${PUSHER_BEAMS_MAX_INTEREST_LENGTH} characters`)
    );
  }
  if (!PUSHER_BEAMS_INTEREST_PATTERN.test(interest)) {
    throw new RangeError(
      at(`\`interests[${index}]\` may only contain ASCII letters, digits, and _-=@,.;`)
    );
  }
  return interest;
}

/**
 * Validate the interests list: an array of 1–100 interest
 * names (the docs' per-request cap), each passing
 * `resolvePusherBeamsInterest`. Throws `RangeError`
 * otherwise.
 */
export function resolvePusherBeamsInterests(
  interests: unknown,
  label: string
): string[] {
  const at = (what: string) => `${label}: ${what}`;
  if (!Array.isArray(interests)) {
    throw new RangeError(at("`interests` must be an array of 1–100 interest names"));
  }
  if (interests.length < 1 || interests.length > PUSHER_BEAMS_MAX_INTERESTS) {
    throw new RangeError(
      at(`\`interests\` must carry 1–${PUSHER_BEAMS_MAX_INTERESTS} interests`)
    );
  }
  return interests.map((interest, i) => resolvePusherBeamsInterest(interest, i, label));
}

/**
 * Validate the platforms list: a non-empty array with no
 * duplicates and no unknown platform. An unset list is
 * *not* a shape error: it defaults at send time (all three
 * platforms), so a sink built before its platform mix is
 * known still sends rather than crashing at construction.
 * Throws `RangeError` otherwise.
 */
export function resolvePusherBeamsPlatforms(
  platforms: unknown,
  label: string
): PusherBeamsPlatform[] {
  const at = (what: string) => `${label}: ${what}`;
  if (!Array.isArray(platforms)) {
    throw new RangeError(at("`platforms` must be an array of `fcm`, `apns`, `web`"));
  }
  if (platforms.length === 0) {
    throw new RangeError(at("`platforms` must not be empty when set"));
  }
  const seen = new Set<string>();
  for (let i = 0; i < platforms.length; i += 1) {
    const platform = platforms[i];
    if (platform !== "fcm" && platform !== "apns" && platform !== "web") {
      throw new RangeError(
        at(`\`platforms[${i}]\` must be one of \`fcm\`, \`apns\`, \`web\``)
      );
    }
    if (seen.has(platform)) {
      throw new RangeError(at(`\`platforms\` must not repeat \`${platform}\``));
    }
    seen.add(platform);
  }
  return [...platforms] as PusherBeamsPlatform[];
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. The
 * instance ID and the interests are required and enforced here,
 * not at send time: `instanceId` must be a non-empty bare
 * identifier (no scheme, no slash — it is used in both the host
 * and the path), and `interests` must be 1–100 valid names.
 */
export function assertValidPusherBeamsSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is PusherBeamsSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  const instanceId = c.instanceId;
  if (
    typeof instanceId !== "string" ||
    instanceId === "" ||
    instanceId.includes("://") ||
    instanceId.includes("/")
  ) {
    throw new RangeError(at("`instanceId` is required and must be a bare identifier (no scheme or slash)"));
  }
  resolvePusherBeamsInterests(c.interests, label);
  if (c.platforms !== undefined) {
    resolvePusherBeamsPlatforms(c.platforms, label);
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
 * Build the publish endpoint URL for an instance ID:
 * `https://<instanceId>.pushnotifications.pusher.com
 * /publish_api/v1/instances/<instanceId>/publishes`.
 */
export function buildPusherBeamsPublishUrl(instanceId: string): string {
  return `https://${instanceId}.pushnotifications.pusher.com${PUSHER_BEAMS_PUBLISH_PATH}/${instanceId}/publishes`;
}

/**
 * Derive one record's content summary: the first
 * non-empty value among `subject`, `key`, and `traceId`,
 * in that order. Falls back to the generic `webhook
 * event` summary when the record carries none — a
 * notification sink must not silently drop sourceless
 * events, and the interests (not the content) are the
 * delivery contract.
 */
export function resolvePusherBeamsSummary(record: PusherBeamsRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return PUSHER_BEAMS_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a device.
 */
export function truncatePusherBeamsPayload(body: string, limit: number): string {
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
 * every platform's notification slot needs a value and
 * the backlog pins it to `subject`, the first link of the
 * chain — then the event body is appended after a blank
 * line inside `body` only under the `includePayload`
 * opt-in (truncated to `payloadMaxChars`, default 2000).
 */
export function resolvePusherBeamsContent(
  record: PusherBeamsRecord,
  config: Pick<PusherBeamsSinkConfig, "includePayload" | "payloadMaxChars">
): { title: string; body: string } {
  const summary = resolvePusherBeamsSummary(record);
  let body = summary;
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? PUSHER_BEAMS_DEFAULT_PAYLOAD_MAX_CHARS;
    body = `${summary}\n\n${truncatePusherBeamsPayload(record.body, limit)}`;
  }
  return { title: summary, body };
}

/**
 * Build one platform's payload object from the derived
 * content: FCM and web take `{ notification: { title,
 * body } }`; APNs takes `{ aps: { alert: { title, body }
 * } }`, the Apple payload shape the docs point at.
 */
export function buildPusherBeamsPlatformPayload(
  platform: PusherBeamsPlatform,
  content: { title: string; body: string }
): Record<string, unknown> {
  if (platform === "apns") {
    return { aps: { alert: { title: content.title, body: content.body } } };
  }
  return { notification: { title: content.title, body: content.body } };
}

/**
 * Build one record's serialized JSON body: the publish
 * object with `interests` and one payload per enabled
 * platform, in the config's platform order. The instance
 * secret key never appears here — the client alone holds
 * it and sends it as the `Authorization` header. No
 * `webhookUrl` is ever sent: the backlog pins only the
 * interests and the three platform payloads.
 */
export function buildPusherBeamsPublishBody(
  interests: string[],
  platforms: readonly PusherBeamsPlatform[],
  content: { title: string; body: string }
): string {
  const body: Record<string, unknown> = { interests: [...interests] };
  for (const platform of platforms) {
    body[platform] = buildPusherBeamsPlatformPayload(platform, content);
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
export function resolvePusherBeamsRecord(
  record: PusherBeamsRecord,
  index: number
): { index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`pusher-beams-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { index };
}

/**
 * Map one Beams POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says Beams could not
 * accept the message right now, not that the payload is
 * poison. Every other non-2xx status (400, 401, 402, 404,
 * and the rest) is a fail-closed message: bad interests or
 * payload, bad instance secret key, publishing blocked
 * for being over plan limits, unknown instance, or
 * another verdict retrying cannot change. Callers only
 * pass non-2xx statuses here; a 2xx status is acceptance
 * on its own — the response body's `publishId` is a
 * receipt to surface, not a second verdict.
 */
export function classifyPusherBeamsRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Pusher Beams sink (WR-289). One instance publishes one
 * notification per message to a fixed interest set; the
 * caller owns retry / dead-letter policy around `send()` —
 * this class performs one POST attempt per message through
 * the injected client and reports its outcome. Failures
 * throw `PusherBeamsSinkError` carrying exactly the failed
 * messages with their retry lanes.
 */
export class PusherBeamsSink {
  private readonly cfg: PusherBeamsSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: PusherBeamsSinkConfig) {
    assertValidPusherBeamsSinkConfig(config, "PusherBeamsSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): PusherBeamsSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send push notifications, in input order. Throws
   * `PusherBeamsSinkConfigError` when no client was injected,
   * and `PusherBeamsSinkError` when any message fails
   * (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: PusherBeamsRecord[]): Promise<PusherBeamsSendResult> {
    const resolved = records.map((r, i) => resolvePusherBeamsRecord(r, i));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The client
      // is not required here, mirroring the sibling sinks'
      // dry-run exemption; the rest of the config was already
      // validated at construction.
      return { ok: true, sent: 0, publishIds: [], dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new PusherBeamsSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const url = buildPusherBeamsPublishUrl(this.cfg.instanceId);
    const interests = resolvePusherBeamsInterests(this.cfg.interests, "PusherBeamsSink");
    const platforms =
      this.cfg.platforms !== undefined
        ? resolvePusherBeamsPlatforms(this.cfg.platforms, "PusherBeamsSink")
        : [...PUSHER_BEAMS_ALL_PLATFORMS];
    const failedRecords: PusherBeamsFailedRecord[] = [];
    const publishIds: string[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          url,
          headers: {
            "Content-Type": PUSHER_BEAMS_JSON_CONTENT_TYPE,
          },
          body: buildPusherBeamsPublishBody(
            interests,
            platforms,
            resolvePusherBeamsContent(records[i], this.cfg)
          ),
        });
        if (response.status >= 200 && response.status < 300) {
          // A 2xx is acceptance on its own: the docs'
          // promise is that a 200 carries a `publishId`
          // receipt, and delivery surfaces later through
          // Beams' publish webhooks — the receipt is a
          // correlation handle, not a second verdict, so a
          // 2xx without one still counts as accepted.
          sent += 1;
          if (typeof response.publishId === "string" && response.publishId !== "") {
            publishIds.push(response.publishId);
          }
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyPusherBeamsRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toPusherBeamsFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new PusherBeamsSinkError(
        `pusher-beams-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent, publishIds };
  }
}

/**
 * Convert a client throw into a failed message: a codeless
 * transport failure (`TRANSPORT_ERROR`, retryable — the SQS
 * no-status rule).
 */
function toPusherBeamsFailedRecord(err: unknown, index: number): PusherBeamsFailedRecord {
  const failed: PusherBeamsFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
