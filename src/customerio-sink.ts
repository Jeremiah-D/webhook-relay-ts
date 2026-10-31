/**
 * Customer.io push notification delivery sink (WR-287).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's device. Where the MoEngage sink
 * (WR-286) delivers push notifications through MoEngage's
 * Push API (V5) with a Basic-auth header the client alone
 * holds and a `campaignName`/`targetPlatform`/
 * `targetAudience`/`payload` envelope decided by the
 * response body's `type` field, and the CleverTap sink
 * (WR-285) delivers through CleverTap's Create Campaign
 * API with two `X-CleverTap-*` headers the client alone
 * holds and a `name`/`target_mode`/`where`/`content`
 * envelope decided by the response body's `status` field,
 * this sink delivers push notifications through
 * Customer.io's Transactional API: one event is sent as
 * one POST that triggers a pre-built transactional push
 * message, and Customer.io — not the relay — owns the
 * audience targeting, the delivery, and the retention of
 * the notification.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Customer.io
 * server. The sink owns the relay-side concerns — region
 * host, template reference, recipient identifiers, device
 * selection, notification derivation, payload-inclusion
 * policy, per-message failure mapping — and the injected
 * client owns the wire protocol, including the POST call,
 * the Bearer authentication, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://api.customer.io/v1/send/push",
 *     headers: { "Content-Type": "application/json" },
 *     body: "{\"transactional_message_id\":44,\"identifiers\":{\"email\":\"person@example.com\"},\"message_data\":{\"title\":\"<title>\",\"message\":\"<body>\"}}" }
 *
 * The client POSTs to that URL, sending `body`
 * verbatim as the request body (JSON) and `headers`
 * verbatim as the request headers, and authenticating
 * with an `Authorization: Bearer <key>` header carrying
 * the App API private key (`sk_…`) — which it alone
 * holds. Five things about this shape are deliberate,
 * and all follow the sibling sinks:
 *
 * - The credentials are held by the client alone. The sink
 *   never receives them, never places them in the request,
 *   and never logs them: like the CleverTap sink (WR-285),
 *   whose account id and passcode the client alone holds,
 *   this sink's handed request carries no credential at
 *   all — the client adds the `Authorization: Bearer
 *   <key>` header from the App API private key it alone
 *   holds, so there is nothing in the handed request for
 *   a log line or a retry queue to leak. The backlog
 *   item's "App API Bearer 认证" is the client's
 *   configuration, not the sink's: no credential ever
 *   enters the sink config. This is the opposite of the
 *   WonderPush sink (WR-282), whose access token rides in
 *   the form body because that API authenticates that way:
 *   Customer.io authenticates by header, so the body
 *   carries only routing and content.
 * - The host is config-held, not fixed: Customer.io serves
 *   the same API from one host per region — the default
 *   `api.customer.io` is the US region, `api-eu.customer.io`
 *   serves the EU region — so the sink config holds the
 *   full host (default `api.customer.io`) and the sink
 *   builds `https://<host>/v1/send/push` from it. A
 *   fixed host here could only misroute a message to the
 *   wrong region's workspace. The endpoint, the JSON
 *   envelope, and the headers match the current
 *   Customer.io documentation (checked this round,
 *   2026-10-31): `POST /v1/send/push` with
 *   `transactional_message_id`, `identifiers`, and
 *   `message_data`, answering 200 with a JSON body whose
 *   `delivery_id` field is the acceptance receipt. The
 *   general App API limit is 10 requests per second, but
 *   the current docs exempt transactional messages from
 *   it ("Transactional messages aren't rate limited"), so
 *   the sink adds no limiter — the relay's retry budget
 *   and the 429 lane below absorb bursts either way.
 * - The `transactional_message_id` is config-held and
 *   required: the numeric ID of the transactional push
 *   message (or its trigger name, case-insensitive) that
 *   the operator built beforehand in Customer.io. One
 *   sink triggers one template; the sink never invents a
 *   template, and a message sent against a template that
 *   does not exist in the workspace answers 400. The
 *   template's own title and body are liquid: the sink
 *   passes `title` and `message` inside `message_data`,
 *   so the template renders them as
 *   `{{trigger.title}}` / `{{trigger.message}}` — the
 *   template is the message's skin, the event is its
 *   content.
 * - The `identifiers` object is config-held and required:
 *   exactly one of `id`, `email`, or `cio_id`, naming the
 *   person the message is attributed to. One sink targets
 *   one Customer.io person, and the identifier is
 *   enforced at construction — exactly one key, a
 *   non-empty string — because the docs require exactly
 *   one of the three, and a missing or doubled identifier
 *   answers 400. The sink never invents a recipient.
 * - The `to` device selection is config-held and optional:
 *   `all`, `last_used`, or a specific device token
 *   belonging to the identified person. When omitted the
 *   request carries no `to` field and Customer.io
 *   defaults to `all` of the identified profile's devices
 *   (per the docs), so a sink with no device selection
 *   configured still has somewhere to deliver — the
 *   operator who wants a narrower target must set it.
 *
 * The response's `delivery_id` field — not the HTTP
 * status alone — decides acceptance: a 200 answers
 * `{"delivery_id": "<id>", "queued_at": <unix>}` (the
 * docs: "A successful transactional API request returns
 * a 200 OK"). The client surfaces the `delivery_id`
 * field (and the `queued_at` when surfaced) on the
 * response, and the sink reads them — a 2xx with no
 * `delivery_id` surfaced is retryable, because without
 * it the sink cannot claim the message was queued. A
 * successful response is only an acceptance receipt,
 * not a delivery result: delivery is handled by the
 * provider and depends on valid recipient identifiers
 * and a reachable device.
 *
 * Message content — a push notification carries a title
 * and a body, both derived from the event's own values:
 * the first non-empty value among `subject`, `key`, and
 * `traceId`, in that order. The title takes that derived
 * summary — the backlog pins the message to the event,
 * and `subject` is the first link of the chain, so when
 * a subject exists the title is exactly the subject; when
 * it does not, the chain's next value keeps the title
 * valid, because the template's title slot needs a
 * value. The body takes the same summary, so an event
 * with none of the values still notifies, with the
 * generic summary `webhook event`: a notification sink
 * that silently dropped sourceless events would hide
 * exactly the deliveries an operator most needs to see,
 * and the recipient — not the content — is the delivery
 * contract here, so no invented target is at stake.
 * Both go into `message_data` as `title` and `message`
 * (the backlog pins the chain into `message_data`, not
 * into the top-level `title`/`message` override fields,
 * which would replace the template's own title and body
 * outright).
 *
 * Payload inclusion — by default the notification
 * carries the summary only, never the full payload:
 * event bodies routinely carry PII, secrets, or
 * customer data, and a device is a far wider audience
 * than a queue or a stream. Opting into `includePayload`
 * appends the body verbatim after a blank line inside
 * `message_data.message`, truncated to `payloadMaxChars`
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
 * body's `delivery_id` field:
 *
 * - a non-2xx POST throws `CustomerIoSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Customer.io
 *   could not accept the message right now, not that
 *   the payload is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, 404, and 405 (unknown template, missing
 *   identifiers, bad App API key, workspace set to "Do
 *   Not Send", misspelled URI): retrying them burns the
 *   retry budget for nothing, and rerouting them
 *   elsewhere would notify a person the operator never
 *   chose;
 * - on a 2xx, the `delivery_id` field decides: a
 *   surfaced `delivery_id` means Customer.io queued the
 *   message; a 2xx with no `delivery_id` field surfaced
 *   is retryable — the field is the acceptance result,
 *   and a missing field means the sink cannot claim the
 *   message was queued;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client throws `CustomerIoSinkConfigError`,
 *   which `classifyFailure` maps to `non_retryable`
 *   (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for the title/body. */
export const CUSTOMERIO_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const CUSTOMERIO_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Default Customer.io API host (the US region) when the config sets none. */
export const CUSTOMERIO_DEFAULT_HOST = "api.customer.io";

/** EU-region Customer.io API host, for a config-held `regionHost`. */
export const CUSTOMERIO_EU_HOST = "api-eu.customer.io";

/** Content type the client sends with the JSON body. */
export const CUSTOMERIO_JSON_CONTENT_TYPE = "application/json";

/** Transactional API path for push sends. */
export const CUSTOMERIO_SEND_PUSH_PATH = "/v1/send/push";

/** Device-selection value that targets all of the identified person's devices. */
export const CUSTOMERIO_TO_ALL = "all";

/** Device-selection value that targets the identified person's last used device. */
export const CUSTOMERIO_TO_LAST_USED = "last_used";

/**
 * The recipient identifiers for one Customer.io sink:
 * exactly one of `id`, `email`, or `cio_id`, per the
 * docs ("one of, and only one of"). Held by the sink
 * config and passed through verbatim into the JSON body.
 * One sink targets one Customer.io person.
 */
export interface CustomerIoIdentifiers {
  /** The identifier for the person (use `email` instead when the workspace identifies people by email). */
  id?: string;
  /** The person's email address. */
  email?: string;
  /** The Customer.io internal id for the person. */
  cio_id?: string;
}

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (JSON) to the region endpoint,
 * sending `headers` verbatim as the request headers, and
 * authenticating with an `Authorization: Bearer <key>`
 * header carrying the App API private key — which the
 * sink never sees.
 */
export interface CustomerIoMessagePostRequest {
  /** Always `https://<region host>/v1/send/push`. */
  url: string;
  /**
   * Request headers, sent verbatim:
   * `{ "Content-Type": "application/json" }`. The
   * `Authorization: Bearer <key>` header is added by the
   * client, never by the sink.
   */
  headers: Record<string, string>;
  /**
   * The JSON request body, serialized:
   * `{"transactional_message_id":44,"identifiers":{"email":"person@example.com"},"message_data":{"title":"<title>","message":"<body>"}}`
   * (plus `to` when a device selection is configured).
   */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * The HTTP status drives the HTTP retry mapping; on a 2xx
 * the client surfaces the response body's `delivery_id`
 * field (and the `queued_at` when surfaced) — and the
 * `delivery_id` field, not the HTTP status alone, decides
 * whether the message was queued. A client that reports a
 * 2xx without a `delivery_id` field leaves the sink unable
 * to claim acceptance, so the message is treated as a
 * retryable delivery failure.
 */
export interface CustomerIoMessagePostResponse {
  /** The HTTP status of the POST (e.g. 200, 400, 429, 503). */
  status: number;
  /**
   * The `delivery_id` field of the Customer.io JSON body,
   * on a 2xx: the acceptance receipt for the queued
   * message. A 2xx with no `delivery_id` surfaced cannot
   * be claimed as queued.
   */
  deliveryId?: string;
  /**
   * The `queued_at` field of the Customer.io JSON body
   * (unix timestamp), when the client surfaces it.
   */
  queuedAt?: number;
}

/**
 * The injected Customer.io message client. Any client adapter
 * implements this one method; it returns the POST's status
 * and, on a 2xx, the response body's `delivery_id` field
 * (and the `queued_at` when surfaced) — a throw is a
 * codeless transport failure, retryable. The client is
 * expected to POST one message per call, sending `body`
 * verbatim as the request body (JSON), sending `headers`
 * verbatim as the request headers, and authenticating
 * with an `Authorization: Bearer <key>` header carrying
 * the App API private key — which the sink never sees.
 */
export interface CustomerIoMessageClient {
  post(request: CustomerIoMessagePostRequest): Promise<CustomerIoMessagePostResponse>;
}

/**
 * Configuration for one Customer.io sink. The client is
 * injected: without one, `send()` throws
 * `CustomerIoSinkConfigError` (dry runs excepted — they need
 * no client at all). The region host defaults to
 * `api.customer.io` (US) when unset; the device selection
 * defaults to the API's own `all` (by omitting `to`) when
 * unset. The App API private key is deliberately absent
 * from this config: the client alone holds it and sends
 * it as the `Authorization: Bearer <key>` header.
 */
export interface CustomerIoSinkConfig {
  /**
   * The Customer.io API host for the account's region, as a
   * bare hostname with no scheme or path: `api.customer.io`
   * is the US region, `api-eu.customer.io` serves the EU
   * region. Defaults to `api.customer.io` when unset.
   * Must be a non-empty hostname when set.
   */
  regionHost?: string;
  /**
   * The transactional push message to trigger: the numeric
   * ID of the message built beforehand in Customer.io, or
   * its trigger name (case-insensitive). Required — the
   * sink never invents a template, and a message sent
   * against a template that does not exist in the
   * workspace answers 400. Must be a non-empty string or
   * an integer when set.
   */
  transactionalMessageId: number | string;
  /**
   * The recipient identifiers: exactly one of `id`,
   * `email`, or `cio_id`, naming the person the message
   * is attributed to. Required — the docs require exactly
   * one of the three, and a missing or doubled identifier
   * answers 400. Passed through verbatim into the JSON
   * body.
   */
  identifiers: CustomerIoIdentifiers;
  /**
   * The devices to send this push to: `all`, `last_used`,
   * or a specific device token belonging to the identified
   * person. When unset the request carries no `to` field
   * and Customer.io defaults to `all` of the identified
   * profile's devices, per the docs. Must be a non-empty
   * string when set.
   */
  to?: string;
  /**
   * The Customer.io message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `CustomerIoMessageClient` and alone holds
   * the App API private key. Required for real sends; a
   * missing client is a config error, not a silent no-op.
   */
  client?: CustomerIoMessageClient;
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
   * template with no recipient would rehearse a request
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
export interface CustomerIoRecord {
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
export interface CustomerIoFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /**
   * Failure code: `HTTP_<status>` for a non-2xx POST,
   * `DELIVERY_ID_MISSING` for a 2xx with no `delivery_id`
   * field surfaced, or `TRANSPORT_ERROR` for a codeless
   * failure.
   */
  errorCode: string;
  /** Downstream HTTP status, when the failure was a non-2xx POST. */
  statusCode?: number;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: 429 and 5xx
   * (plus codeless transport failures and missing
   * `delivery_id` fields) are retryable; every other
   * non-2xx status is a fail-closed message (unknown
   * template, missing identifiers, bad App API key,
   * workspace set to "Do Not Send", misspelled URI).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface CustomerIoSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-287). */
export interface CustomerIoSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Customer.io send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already queued on Customer.io's server and are *not* in
 * `failedRecords`.
 */
export class CustomerIoSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: CustomerIoFailedRecord[];
  constructor(message: string, failedRecords: CustomerIoFailedRecord[]) {
    super(message);
    this.name = "CustomerIoSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class CustomerIoSinkConfigError extends CustomerIoSinkError {
  constructor(reason: string) {
    super(`customerio-sink: ${reason}`, []);
    this.name = "CustomerIoSinkConfigError";
  }
}

/**
 * Validate one recipient-identifiers object: exactly one
 * of `id`, `email`, or `cio_id`, a non-empty string. Throws
 * `RangeError` otherwise — the docs require exactly one of
 * the three, and a missing or doubled identifier answers
 * 400, so the sink fails fast at construction instead of
 * discovering it at send time.
 */
export function resolveCustomerIoIdentifiers(
  identifiers: unknown,
  label: string
): CustomerIoIdentifiers {
  const at = (what: string) => `${label}: ${what}`;
  if (identifiers === null || typeof identifiers !== "object" || Array.isArray(identifiers)) {
    throw new RangeError(at("`identifiers` must be an object with exactly one of `id`, `email`, `cio_id`"));
  }
  const ids = identifiers as Record<string, unknown>;
  const present = (["id", "email", "cio_id"] as const).filter(
    (key) => ids[key] !== undefined
  );
  if (present.length !== 1) {
    throw new RangeError(at("`identifiers` must carry exactly one of `id`, `email`, `cio_id`"));
  }
  const key = present[0];
  if (typeof ids[key] !== "string" || (ids[key] as string) === "") {
    throw new RangeError(at(`\`identifiers.${key}\` must be a non-empty string when set`));
  }
  return { [key]: ids[key] } as CustomerIoIdentifiers;
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing region host or device selection is *not* a shape error:
 * they default at send time (US host, the API's own `all` by
 * omitting `to`), so a sink built before its targeting is known
 * still sends rather than crashing at construction. A present
 * `regionHost` must be a bare hostname (no scheme, no path); a
 * present `to` must be a non-empty string. The template
 * reference and the recipient identifiers are required and
 * enforced here, not at send time: `transactionalMessageId`
 * must be a non-empty string (trigger name) or an integer
 * (template id), and `identifiers` must carry exactly one of
 * `id`, `email`, or `cio_id`.
 */
export function assertValidCustomerIoSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is CustomerIoSinkConfig {
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
  const transactionalMessageId = c.transactionalMessageId;
  if (
    transactionalMessageId === undefined ||
    (typeof transactionalMessageId !== "string" &&
      typeof transactionalMessageId !== "number") ||
    (typeof transactionalMessageId === "string" && transactionalMessageId === "") ||
    (typeof transactionalMessageId === "number" && !Number.isInteger(transactionalMessageId))
  ) {
    throw new RangeError(
      at("`transactionalMessageId` is required and must be a non-empty string (trigger name) or an integer (template id)")
    );
  }
  resolveCustomerIoIdentifiers(c.identifiers, label);
  if (c.to !== undefined && (typeof c.to !== "string" || c.to === "")) {
    throw new RangeError(at("`to` must be a non-empty string when set"));
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
 * or `api.customer.io` (the US region) when the config sets
 * none.
 */
export function resolveCustomerIoHost(
  config: Pick<CustomerIoSinkConfig, "regionHost">
): string {
  return config.regionHost ?? CUSTOMERIO_DEFAULT_HOST;
}

/**
 * Build the Transactional API push endpoint URL for a region host:
 * `https://<host>/v1/send/push`.
 */
export function buildCustomerIoSendPushUrl(regionHost: string): string {
  return `https://${regionHost}${CUSTOMERIO_SEND_PUSH_PATH}`;
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
export function resolveCustomerIoSummary(record: CustomerIoRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return CUSTOMERIO_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a device.
 */
export function truncateCustomerIoPayload(body: string, limit: number): string {
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
 * the template's title slot needs a value and the backlog
 * pins it to `subject`, the first link of the chain —
 * then the event body is appended after a blank line
 * inside `message` only under the `includePayload`
 * opt-in (truncated to `payloadMaxChars`, default 2000).
 */
export function resolveCustomerIoContent(
  record: CustomerIoRecord,
  config: Pick<CustomerIoSinkConfig, "includePayload" | "payloadMaxChars">
): { title: string; message: string } {
  const summary = resolveCustomerIoSummary(record);
  let message = summary;
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? CUSTOMERIO_DEFAULT_PAYLOAD_MAX_CHARS;
    message = `${summary}\n\n${truncateCustomerIoPayload(record.body, limit)}`;
  }
  return { title: summary, message };
}

/**
 * Build one record's `message_data` object: the liquid
 * trigger data the template renders as
 * `{{trigger.title}}` / `{{trigger.message}}`. The
 * template is the message's skin; the event is its
 * content.
 */
export function buildCustomerIoMessageData(content: {
  title: string;
  message: string;
}): Record<string, string> {
  return { title: content.title, message: content.message };
}

/**
 * Build one record's serialized JSON body: the
 * transactional push object with `transactional_message_id`,
 * `identifiers`, and `message_data` carrying the derived
 * `title`/`message`, plus `to` when a device selection is
 * configured (omitted otherwise — the API defaults to
 * `all`). The App API private key never appears here —
 * the client alone holds it and sends it as the
 * `Authorization: Bearer <key>` header.
 */
export function buildCustomerIoSendPushBody(
  transactionalMessageId: number | string,
  identifiers: CustomerIoIdentifiers,
  content: { title: string; message: string },
  config: Pick<CustomerIoSinkConfig, "to">
): string {
  const body: Record<string, unknown> = {
    transactional_message_id: transactionalMessageId,
    identifiers: { ...identifiers },
    message_data: buildCustomerIoMessageData(content),
  };
  if (config.to !== undefined) {
    body.to = config.to;
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
export function resolveCustomerIoRecord(
  record: CustomerIoRecord,
  index: number
): { index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`customerio-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { index };
}

/**
 * Map one Customer.io POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says Customer.io could
 * not accept the message right now, not that the payload
 * is poison. Every other non-2xx status (400, 401, 403,
 * 404, 405, and the rest) is a fail-closed message:
 * unknown template, missing identifiers, bad App API key,
 * workspace set to "Do Not Send", misspelled URI, or
 * another verdict retrying cannot change. Callers only pass
 * non-2xx statuses here; a 2xx status is decided by the
 * response body's `delivery_id` field, not by this function.
 */
export function classifyCustomerIoRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Map one Customer.io POST response onto its failed record,
 * or `null` when the response accepted the message (a 2xx
 * with a surfaced `delivery_id` field). A 2xx with no
 * `delivery_id` field surfaced is retryable — the field is
 * the acceptance result, and without it the sink cannot
 * claim the message was queued.
 */
export function customerIoResponseToFailedRecord(
  response: CustomerIoMessagePostResponse,
  index: number
): CustomerIoFailedRecord | null {
  if (response.deliveryId !== undefined && response.deliveryId !== "") {
    return null;
  }
  return {
    index,
    errorCode: "DELIVERY_ID_MISSING",
    errorMessage: "Customer.io answered 2xx but surfaced no delivery_id field",
    retryable: true,
  };
}

/**
 * Customer.io sink (WR-287). One instance triggers one
 * transactional push template for one Customer.io person;
 * the caller owns retry / dead-letter policy around
 * `send()` — this class performs one POST attempt per
 * message through the injected client and reports its
 * outcome. Failures throw `CustomerIoSinkError` carrying
 * exactly the failed messages with their retry lanes.
 */
export class CustomerIoSink {
  private readonly cfg: CustomerIoSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: CustomerIoSinkConfig) {
    assertValidCustomerIoSinkConfig(config, "CustomerIoSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): CustomerIoSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send push notifications, in input order. Throws
   * `CustomerIoSinkConfigError` when no client was injected,
   * and `CustomerIoSinkError` when any message fails
   * (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: CustomerIoRecord[]): Promise<CustomerIoSendResult> {
    const resolved = records.map((r, i) => resolveCustomerIoRecord(r, i));
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
      throw new CustomerIoSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const url = buildCustomerIoSendPushUrl(resolveCustomerIoHost(this.cfg));
    const identifiers = resolveCustomerIoIdentifiers(this.cfg.identifiers, "CustomerIoSink");
    const failedRecords: CustomerIoFailedRecord[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          url,
          headers: {
            "Content-Type": CUSTOMERIO_JSON_CONTENT_TYPE,
          },
          body: buildCustomerIoSendPushBody(
            this.cfg.transactionalMessageId,
            identifiers,
            resolveCustomerIoContent(records[i], this.cfg),
            this.cfg
          ),
        });
        if (response.status >= 200 && response.status < 300) {
          const deliveryFailure = customerIoResponseToFailedRecord(response, record.index);
          if (deliveryFailure === null) {
            sent += 1;
            continue;
          }
          failedRecords.push(deliveryFailure);
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyCustomerIoRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toCustomerIoFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new CustomerIoSinkError(
        `customerio-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toCustomerIoFailedRecord(err: unknown, index: number): CustomerIoFailedRecord {
  const failed: CustomerIoFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
