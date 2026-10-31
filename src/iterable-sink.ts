/**
 * Iterable push notification delivery sink (WR-288).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's device. Where the Customer.io
 * sink (WR-287) delivers push notifications through
 * Customer.io's Transactional API with a Bearer header
 * the client alone holds and a `transactional_message_id`/
 * `identifiers`/`message_data` envelope decided by the
 * response body's `delivery_id` field, and the MoEngage
 * sink (WR-286) delivers through MoEngage's Push API
 * (V5) with a Basic-auth header the client alone holds
 * and a `campaignName`/`targetPlatform`/`targetAudience`/
 * `payload` envelope decided by the response body's
 * `type` field, this sink delivers push notifications
 * through Iterable's push/target API: one event is sent
 * as one POST that triggers a pre-built, activated
 * API-triggered push campaign for one user, and Iterable
 * — not the relay — owns the audience targeting, the
 * delivery, and the retention of the notification.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need an Iterable
 * server. The sink owns the relay-side concerns — region
 * host, campaign reference, recipient selection,
 * notification derivation, payload-inclusion policy,
 * per-message failure mapping — and the injected client
 * owns the wire protocol, including the POST call, the
 * `Api-Key` authentication, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://api.iterable.com/api/push/target",
 *     headers: { "Content-Type": "application/json" },
 *     body: "{\"campaignId\":123,\"recipientEmail\":\"person@example.com\",\"dataFields\":{\"title\":\"<title>\",\"message\":\"<body>\"}}" }
 *
 * The client POSTs to that URL, sending `body`
 * verbatim as the request body (JSON) and `headers`
 * verbatim as the request headers, and authenticating
 * with an `Api-Key` header carrying the server-side API
 * key — which it alone holds. Five things about this
 * shape are deliberate, and all follow the sibling sinks:
 *
 * - The credentials are held by the client alone. The sink
 *   never receives them, never places them in the request,
 *   and never logs them: like the Customer.io sink
 *   (WR-287), whose App API private key the client alone
 *   holds, this sink's handed request carries no credential
 *   at all — the client adds the `Api-Key` header from the
 *   server-side API key it alone holds, so there is nothing
 *   in the handed request for a log line or a retry queue to
 *   leak. The backlog item's "Api-Key 头只由 client 持有"
 *   is the client's configuration, not the sink's: no
 *   credential ever enters the sink config. This is the
 *   opposite of the WonderPush sink (WR-282), whose access
 *   token rides in the form body because that API
 *   authenticates that way: Iterable authenticates by
 *   header, so the body carries only routing and content.
 * - The host is config-held, not fixed: Iterable serves
 *   the same API from one host per data center — the
 *   default `api.iterable.com` is the USDC data center,
 *   `api.eu.iterable.com` serves the EDC data center — so
 *   the sink config holds the full host (default
 *   `api.iterable.com`) and the sink builds
 *   `https://<host>/api/push/target` from it. A fixed host
 *   here could only misroute a message to the wrong data
 *   center's project. The endpoint, the JSON envelope, and
 *   the headers match the current Iterable documentation
 *   (checked this round, 2026-10-31): `POST
 *   /api/push/target` sends a triggered push notification
 *   to a specific user; the campaign must be set up in
 *   Iterable beforehand, and when the `sendAt` field is not
 *   included the message is sent immediately.
 * - The `campaignId` is config-held and required: the
 *   numeric ID of the API-triggered push campaign that
 *   the operator built beforehand in Iterable and
 *   activated (a triggered campaign must be in the
 *   Running state before it can send). One sink triggers
 *   one campaign; the sink never invents a campaign, and
 *   a message sent against a campaign that does not exist
 *   or is not running answers 4xx. The campaign's own
 *   title and body are template-driven: the sink passes
 *   `title` and `message` inside `dataFields`, so the
 *   template renders them as Handlebars fields — the
 *   campaign is the message's skin, the event is its
 *   content.
 * - The recipient is config-held and required: exactly
 *   one of `recipientEmail` or `recipientUserId`, naming
 *   the user the message is sent to. One sink targets one
 *   Iterable user, and the choice is enforced at
 *   construction — exactly one key, a non-empty string —
 *   because the docs require one of the two and not both
 *   (the sibling `/api/rcs/target` section states it
 *   outright: "Include a `recipientUserId` or
 *   `recipientEmail`, but not both"), and a missing or
 *   doubled recipient answers 400. The sink never invents
 *   a recipient.
 * - The `sendAt` field is omitted, always: the backlog
 *   pins immediate sending — when `sendAt` is not
 *   included the message is sent immediately, per the
 *   docs — so the sink never schedules. An operator who
 *   wants a scheduled send uses Iterable's own scheduling
 *   or a different sink; this sink's contract is
 *   trigger-now.
 *
 * The HTTP status alone decides acceptance: a 200 means
 * the request has been received (the docs' wording for
 * the sibling `/api/email/target`: "a 200 response means
 * that the request has been received, not that the email
 * has been sent"; the sibling `/api/rcs/target` adds that
 * success "creates an `rcsSend` event on the specified
 * user's Iterable profile"). There is no response-body
 * acceptance field to read — unlike Customer.io's
 * `delivery_id` or MoEngage's `type` — so any 2xx is an
 * acceptance receipt, and the client surfaces only the
 * status. A successful response is only an acceptance
 * receipt, not a delivery result: delivery is handled by
 * the provider and surfaces as a `pushSend` event on the
 * user's Iterable profile.
 *
 * Message content — a push notification carries a title
 * and a body, both derived from the event's own values:
 * the first non-empty value among `subject`, `key`, and
 * `traceId`, in that order. The title takes that derived
 * summary — the backlog pins the message to the event,
 * and `subject` is the first link of the chain, so when
 * a subject exists the title is exactly the subject; when
 * it does not, the chain's next value keeps the title
 * valid, because the campaign's title slot needs a
 * value. The body takes the same summary, so an event
 * with none of the values still notifies, with the
 * generic summary `webhook event`: a notification sink
 * that silently dropped sourceless events would hide
 * exactly the deliveries an operator most needs to see,
 * and the recipient — not the content — is the delivery
 * contract here, so no invented target is at stake.
 * Both go into `dataFields` as `title` and `message`
 * (the backlog pins the chain into `dataFields`, not
 * into top-level fields, which would be a different
 * request shape).
 *
 * Payload inclusion — by default the notification
 * carries the summary only, never the full payload:
 * event bodies routinely carry PII, secrets, or
 * customer data, and a device is a far wider audience
 * than a queue or a stream. Opting into `includePayload`
 * appends the body verbatim after a blank line inside
 * `dataFields.message`, truncated to `payloadMaxChars`
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
 * over the HTTP status:
 *
 * - a non-2xx POST throws `IterableSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Iterable
 *   could not accept the message right now, not that
 *   the payload is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (unknown campaign, missing or doubled
 *   recipient, bad server-side API key, campaign not
 *   activated): retrying them burns the retry budget
 *   for nothing, and rerouting them elsewhere would
 *   notify a person the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client throws `IterableSinkConfigError`,
 *   which `classifyFailure` maps to `non_retryable`
 *   (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for the title/body. */
export const ITERABLE_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const ITERABLE_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Default Iterable API host (the USDC data center) when the config sets none. */
export const ITERABLE_DEFAULT_HOST = "api.iterable.com";

/** EDC-region Iterable API host, for a config-held `regionHost`. */
export const ITERABLE_EDC_HOST = "api.eu.iterable.com";

/** Content type the client sends with the JSON body. */
export const ITERABLE_JSON_CONTENT_TYPE = "application/json";

/** Push/target API path for triggered push sends. */
export const ITERABLE_PUSH_TARGET_PATH = "/api/push/target";

/**
 * The recipient for one Iterable sink: exactly one of
 * `email` or `userId`, per the docs ("Include a
 * `recipientUserId` or `recipientEmail`, but not both").
 * Held by the sink config and passed through verbatim
 * into the JSON body as `recipientEmail` /
 * `recipientUserId`. One sink targets one Iterable user.
 */
export interface IterableRecipient {
  /** The user's email address. */
  email?: string;
  /** The user's Iterable userId. */
  userId?: string;
}

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (JSON) to the data-center endpoint,
 * sending `headers` verbatim as the request headers, and
 * authenticating with an `Api-Key` header carrying the
 * server-side API key — which the sink never sees.
 */
export interface IterableMessagePostRequest {
  /** Always `https://<data-center host>/api/push/target`. */
  url: string;
  /**
   * Request headers, sent verbatim:
   * `{ "Content-Type": "application/json" }`. The
   * `Api-Key` header is added by the client, never by
   * the sink.
   */
  headers: Record<string, string>;
  /**
   * The JSON request body, serialized:
   * `{"campaignId":123,"recipientEmail":"person@example.com","dataFields":{"title":"<title>","message":"<body>"}}`
   * (with `recipientUserId` in place of `recipientEmail`
   * when the recipient is identified by userId).
   */
  body: string;
}

/**
 * The result of one POST, as reported by the injected
 * client. The HTTP status alone decides acceptance: any
 * 2xx means Iterable received the request (an acceptance
 * receipt only — delivery surfaces later as a `pushSend`
 * event on the user's profile). There is no response-body
 * acceptance field to surface, so the client reports only
 * the status.
 */
export interface IterableMessagePostResponse {
  /** The HTTP status of the POST (e.g. 200, 400, 429, 503). */
  status: number;
}

/**
 * The injected Iterable message client. Any client adapter
 * implements this one method; it returns the POST's status
 * — a throw is a codeless transport failure, retryable.
 * The client is expected to POST one message per call,
 * sending `body` verbatim as the request body (JSON),
 * sending `headers` verbatim as the request headers, and
 * authenticating with an `Api-Key` header carrying the
 * server-side API key — which the sink never sees.
 */
export interface IterableMessageClient {
  post(request: IterableMessagePostRequest): Promise<IterableMessagePostResponse>;
}

/**
 * Configuration for one Iterable sink. The client is
 * injected: without one, `send()` throws
 * `IterableSinkConfigError` (dry runs excepted — they need
 * no client at all). The region host defaults to
 * `api.iterable.com` (USDC) when unset. The server-side
 * API key is deliberately absent from this config: the
 * client alone holds it and sends it as the `Api-Key`
 * header.
 */
export interface IterableSinkConfig {
  /**
   * The Iterable API host for the account's data center,
   * as a bare hostname with no scheme or path:
   * `api.iterable.com` is the USDC data center,
   * `api.eu.iterable.com` serves the EDC data center.
   * Defaults to `api.iterable.com` when unset. Must be
   * a non-empty hostname when set.
   */
  regionHost?: string;
  /**
   * The API-triggered push campaign to trigger: the
   * numeric ID of the campaign built beforehand in
   * Iterable and activated (Running). Required — the
   * sink never invents a campaign, and a message sent
   * against a campaign that does not exist or is not
   * running answers 4xx. Must be an integer when set.
   */
  campaignId: number;
  /**
   * The recipient: exactly one of `email` or `userId`,
   * naming the user the message is sent to. Required —
   * the docs require one of the two and not both, and a
   * missing or doubled recipient answers 400. Passed
   * through verbatim into the JSON body as
   * `recipientEmail` / `recipientUserId`.
   */
  recipient: IterableRecipient;
  /**
   * The Iterable message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `IterableMessageClient` and alone holds
   * the server-side API key. Required for real sends; a
   * missing client is a config error, not a silent no-op.
   */
  client?: IterableMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including notification derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The client is not required in dry-run mode, mirroring
   * the sibling sinks' dry-run exemption; the rest of the
   * config must still be valid — a dry run against a
   * campaign with no recipient would rehearse a request
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
export interface IterableRecord {
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
export interface IterableFailedRecord {
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
   * (unknown campaign, missing or doubled recipient, bad
   * server-side API key, campaign not activated).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface IterableSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-288). */
export interface IterableSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Iterable send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already received on Iterable's server and are *not* in
 * `failedRecords`.
 */
export class IterableSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: IterableFailedRecord[];
  constructor(message: string, failedRecords: IterableFailedRecord[]) {
    super(message);
    this.name = "IterableSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class IterableSinkConfigError extends IterableSinkError {
  constructor(reason: string) {
    super(`iterable-sink: ${reason}`, []);
    this.name = "IterableSinkConfigError";
  }
}

/**
 * Validate one recipient object: exactly one of `email`
 * or `userId`, a non-empty string. Throws `RangeError`
 * otherwise — the docs require one of the two and not
 * both, and a missing or doubled recipient answers 400,
 * so the sink fails fast at construction instead of
 * discovering it at send time.
 */
export function resolveIterableRecipient(
  recipient: unknown,
  label: string
): IterableRecipient {
  const at = (what: string) => `${label}: ${what}`;
  if (recipient === null || typeof recipient !== "object" || Array.isArray(recipient)) {
    throw new RangeError(at("`recipient` must be an object with exactly one of `email`, `userId`"));
  }
  const r = recipient as Record<string, unknown>;
  const present = (["email", "userId"] as const).filter((key) => r[key] !== undefined);
  if (present.length !== 1) {
    throw new RangeError(at("`recipient` must carry exactly one of `email`, `userId`"));
  }
  const key = present[0];
  if (typeof r[key] !== "string" || (r[key] as string) === "") {
    throw new RangeError(at(`\`recipient.${key}\` must be a non-empty string when set`));
  }
  return { [key]: r[key] } as IterableRecipient;
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing region host is *not* a shape error: it defaults at send
 * time (USDC host), so a sink built before its data center is known
 * still sends rather than crashing at construction. A present
 * `regionHost` must be a bare hostname (no scheme, no path). The
 * campaign reference and the recipient are required and enforced
 * here, not at send time: `campaignId` must be an integer, and
 * `recipient` must carry exactly one of `email`, `userId`.
 */
export function assertValidIterableSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is IterableSinkConfig {
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
  const campaignId = c.campaignId;
  if (
    campaignId === undefined ||
    typeof campaignId !== "number" ||
    !Number.isInteger(campaignId)
  ) {
    throw new RangeError(at("`campaignId` is required and must be an integer (campaign id)"));
  }
  resolveIterableRecipient(c.recipient, label);
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
 * or `api.iterable.com` (the USDC data center) when the
 * config sets none.
 */
export function resolveIterableHost(
  config: Pick<IterableSinkConfig, "regionHost">
): string {
  return config.regionHost ?? ITERABLE_DEFAULT_HOST;
}

/**
 * Build the push/target endpoint URL for a region host:
 * `https://<host>/api/push/target`.
 */
export function buildIterablePushTargetUrl(regionHost: string): string {
  return `https://${regionHost}${ITERABLE_PUSH_TARGET_PATH}`;
}

/**
 * Derive one record's content summary: the first
 * non-empty value among `subject`, `key`, and `traceId`,
 * in that order. Falls back to the generic `webhook
 * event` summary when the record carries none — a
 * notification sink must not silently drop sourceless
 * events, and the recipient (not the content) is the
 * delivery contract.
 */
export function resolveIterableSummary(record: IterableRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return ITERABLE_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a device.
 */
export function truncateIterablePayload(body: string, limit: number): string {
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
 * the campaign's title slot needs a value and the backlog
 * pins it to `subject`, the first link of the chain —
 * then the event body is appended after a blank line
 * inside `message` only under the `includePayload`
 * opt-in (truncated to `payloadMaxChars`, default 2000).
 */
export function resolveIterableContent(
  record: IterableRecord,
  config: Pick<IterableSinkConfig, "includePayload" | "payloadMaxChars">
): { title: string; message: string } {
  const summary = resolveIterableSummary(record);
  let message = summary;
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? ITERABLE_DEFAULT_PAYLOAD_MAX_CHARS;
    message = `${summary}\n\n${truncateIterablePayload(record.body, limit)}`;
  }
  return { title: summary, message };
}

/**
 * Build one record's `dataFields` object: the template
 * fields the campaign renders as `{{title}}` /
 * `{{message}}`. The campaign is the message's skin; the
 * event is its content.
 */
export function buildIterableDataFields(content: {
  title: string;
  message: string;
}): Record<string, string> {
  return { title: content.title, message: content.message };
}

/**
 * Build one record's serialized JSON body: the push/target
 * object with `campaignId`, exactly one of
 * `recipientEmail` / `recipientUserId`, and `dataFields`
 * carrying the derived `title`/`message`. `sendAt` is
 * never sent — omitting it means the message is sent
 * immediately, per the docs. The server-side API key
 * never appears here — the client alone holds it and
 * sends it as the `Api-Key` header.
 */
export function buildIterablePushTargetBody(
  campaignId: number,
  recipient: IterableRecipient,
  content: { title: string; message: string }
): string {
  const body: Record<string, unknown> = {
    campaignId,
    dataFields: buildIterableDataFields(content),
  };
  if (recipient.email !== undefined) {
    body.recipientEmail = recipient.email;
  }
  if (recipient.userId !== undefined) {
    body.recipientUserId = recipient.userId;
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
export function resolveIterableRecord(
  record: IterableRecord,
  index: number
): { index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`iterable-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { index };
}

/**
 * Map one Iterable POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says Iterable could
 * not accept the message right now, not that the payload
 * is poison. Every other non-2xx status (400, 401, 403,
 * 404, and the rest) is a fail-closed message: unknown
 * campaign, missing or doubled recipient, bad server-side
 * API key, campaign not activated, or another verdict
 * retrying cannot change. Callers only pass non-2xx
 * statuses here; a 2xx status is acceptance on its own —
 * the response carries no acceptance field to read.
 */
export function classifyIterableRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Iterable sink (WR-288). One instance triggers one
 * API-triggered push campaign for one Iterable user;
 * the caller owns retry / dead-letter policy around
 * `send()` — this class performs one POST attempt per
 * message through the injected client and reports its
 * outcome. Failures throw `IterableSinkError` carrying
 * exactly the failed messages with their retry lanes.
 */
export class IterableSink {
  private readonly cfg: IterableSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: IterableSinkConfig) {
    assertValidIterableSinkConfig(config, "IterableSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): IterableSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send push notifications, in input order. Throws
   * `IterableSinkConfigError` when no client was injected,
   * and `IterableSinkError` when any message fails
   * (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: IterableRecord[]): Promise<IterableSendResult> {
    const resolved = records.map((r, i) => resolveIterableRecord(r, i));
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
      throw new IterableSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const url = buildIterablePushTargetUrl(resolveIterableHost(this.cfg));
    const recipient = resolveIterableRecipient(this.cfg.recipient, "IterableSink");
    const failedRecords: IterableFailedRecord[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          url,
          headers: {
            "Content-Type": ITERABLE_JSON_CONTENT_TYPE,
          },
          body: buildIterablePushTargetBody(
            this.cfg.campaignId,
            recipient,
            resolveIterableContent(records[i], this.cfg)
          ),
        });
        if (response.status >= 200 && response.status < 300) {
          // A 2xx is acceptance on its own: the docs'
          // promise is that a 200 means the request has been
          // received, and delivery surfaces later as a
          // `pushSend` event — there is no response-body
          // acceptance field to read, unlike Customer.io's
          // `delivery_id` or MoEngage's `type`.
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyIterableRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toIterableFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new IterableSinkError(
        `iterable-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toIterableFailedRecord(err: unknown, index: number): IterableFailedRecord {
  const failed: IterableFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
