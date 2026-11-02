/**
 * Zenduty on-call alert delivery sink (WR-299).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are the on-call engineer's phone, reached
 * through an alerting API. Where the PagerDuty sink
 * (WR-248) posts an Events API v2 event with a
 * `routing_key` carried inside the body and an
 * `event_action`/`dedup_key` envelope, the Opsgenie sink
 * (WR-297) creates an alert through the Alert API v2
 * with a `GenieKey` header the client alone holds and a
 * `message`/`alias`/`description`/`priority` envelope,
 * and the ilert sink (WR-298) posts an event to an ilert
 * alert source through the Events API v1 with the key in
 * the URL path and an `eventType`/`summary`/`details`/
 * `alertKey`/`priority` envelope, this sink posts an
 * alert to a Zenduty Generic Integration webhook URL:
 * one event is sent as one POST that Zenduty routes into
 * that integration's escalation policy, and Zenduty —
 * not the relay — owns the alert, the escalation, the
 * notification, and the alert lifecycle.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Zenduty
 * server. The sink owns the relay-side concerns — the
 * alert type, the message derivation, the summary, the
 * entity id, the payload, the payload-inclusion policy,
 * the per-message failure mapping — and the injected client
 * owns the wire protocol, including the POST call, the
 * Generic Integration webhook URL, and the status it
 * returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { headers: { "Content-Type": "application/json" },
 *     body: "{\"alert_type\":\"critical\",\"message\":\"<summary>\",\"summary\":\"<key>\",\"entity_id\":\"<key>\",\"payload\":{\"key\":\"<key>\",\"traceId\":\"<traceId>\"}}" }
 *
 * The client POSTs to the Generic Integration webhook URL
 * it alone holds — `https://events.zenduty.com/
 * integration/<integration>/generic/<uuid>/` — sending
 * `body` verbatim as the request body (JSON) and sending
 * `headers` verbatim as the request headers. Six things
 * about this shape are deliberate, and all follow the
 * sibling sinks or the backlog pins:
 *
 * - The webhook URL — integration segment and UUID alike
 *   — is held by the client alone. The sink never
 *   receives the key, never places it in the request, and
 *   never logs it: the sink config has no `apiKey` field
 *   at all, and the handed request carries no URL at all
 *   (like the ilert sink, unlike the Opsgenie sink,
 *   whose handed request carries the bare endpoint URL),
 *   so there is nothing in it for a log line or a retry
 *   queue to leak — and the key is never persisted by
 *   the sink. The key rides in the URL path (like the
 *   ilert sink's alert-source URL, unlike the Opsgenie
 *   sink's `Authorization: GenieKey <key>` header and
 *   the PagerDuty sink's `routing_key` inside the body),
 *   so the sink hands the client the bare `Content-Type`
 *   header and the body and the client posts to the
 *   webhook URL it was configured with: the sink's
 *   request never contains a key, a placeholder, or
 *   anything that looks like one. This is the Zenduty
 *   form of the MagicBell rule (whose Project JWT the
 *   client alone holds as an `Authorization: Bearer`
 *   header), with Zenduty's own credential source: the
 *   integration key of a Generic Integration, verified
 *   against the current docs (zenduty.com/docs/
 *   generic-integration/, re-checked 2026-11-01 — the
 *   sample Python script posts to
 *   `https://events.zenduty.com/integration/sdsds/
 *   generic/7e44896b-36c3-4fa2-b145-c292f543d8dc/`).
 * - The endpoint is the Generic Integration webhook the
 *   backlog pins: `POST https://events.zenduty.com/
 *   integration/<integration>/generic/<uuid>/`. The old
 *   API Integration endpoint (`POST https://
 *   events.zenduty.com/api/events/<integration-key>/`)
 *   is not used: the backlog pins it as deprecated and
 *   non-functional since 2025-05-15, so this sink only
 *   ever walks the Generic Integration webhook URL.
 *   (Honesty note: the Generic Integration page
 *   re-checked for this item does not itself mention the
 *   old endpoint or its deprecation date — the
 *   deprecation is the backlog pin, stated here as such,
 *   not as a claim from that page. The page now carries
 *   the Xurrent IMR brand, but the
 *   `events.zenduty.com` webhook URL, the body fields,
 *   and the status codes below are the ones that page
 *   pins.)
 * - `alert_type` is one of `critical`, `error`,
 *   `warning`, `info`, `acknowledged`, and `resolved`
 *   (the six values the backlog pins). It is config-held
 *   with a per-record override, defaulting to
 *   `critical`: the relay does not invent a severity it
 *   was not told. The fetched page's examples confirm
 *   `critical`, `error`, and `resolved` in use; the
 *   full six-value set is the backlog pin, stated here
 *   as such.
 * - `message` is mandatory, so it is derived as the
 *   first non-empty value among `subject`, `key`, and
 *   `traceId`, in that order, falling back to the generic
 *   `webhook event`: an alert sink that silently dropped
 *   sourceless events would hide exactly the deliveries
 *   an operator most needs to see. No truncation is
 *   applied: the re-checked documentation states no
 *   message length limit for this endpoint, and inventing
 *   one would silently cut an operator's alert text.
 * - `summary` is the incident summary, derived as the
 *   first non-empty value among `key` and `traceId`, in
 *   that order, and omitted entirely when the event
 *   carries neither: a summaryless alert still alerts,
 *   it just carries no incident summary. It is never
 *   truncated: the re-checked documentation states no
 *   summary length limit for this endpoint.
 * - `entity_id` is the event's `key`, sent when one
 *   exists and omitted entirely when the event carries
 *   none: a keyless event still alerts, it just carries
 *   no grouping key. The entity id is the official
 *   de-duplication key: the reference states "The alerts
 *   are bound into incidents by their `entity_id`
 *   parameter, i.e `entity_id` is the deduplication key
 *   for all incidents", so a second alert with the same
 *   entity id while the first is still open is appended
 *   to the same incident instead of creating a new one,
 *   and sending `alert_type` `resolved` with the same
 *   entity id resolves that incident. The entity id is
 *   sent verbatim, never truncated: truncating a dedup
 *   key would silently merge distinct incidents. The
 *   same entity id also makes a transport-failure retry
 *   safe: replaying the same record reuses the same
 *   entity id, so the retry lands on the open incident
 *   instead of paging the on-call engineer twice. The
 *   reference's sample shows `entity_id` as a number
 *   (`12345`) and its cURL example as a string
 *   (`"some_entity_id"`), so both forms are accepted by
 *   the endpoint; the sink sends the event key verbatim
 *   as a string, never coerced to a number.
 * - `payload` carries only the event's own identifiers
 *   by default — `key` and `traceId` when present,
 *   nothing else — so the alert's payload stays
 *   identifiers, never event body. Under the
 *   `includePayload` opt-in the event body is appended
 *   as a `body` field inside `payload`, truncated to
 *   `payloadMaxChars` characters (default 2000). When
 *   the event carries no identifiers and the opt-in is
 *   off, `payload` is omitted entirely rather than sent
 *   as an empty object.
 *
 * `urls`, `sla`, `escalation_policy`, `priority`,
 * `stakeholders`, and `tags` are out of scope: the
 * reference shows them as fields the Zenduty-side
 * integration configuration owns, and the sink never
 * invents a routing, SLA, priority, or stakeholder
 * decision. No `Idempotency-Key` header is sent: the
 * reference documents no idempotency key for this
 * endpoint, and the entity id already gives a retry its
 * de-duplication key (see above).
 *
 * Acceptance is decided by the HTTP status alone, and
 * the success status is pinned to exactly `200 OK`: the
 * reference's status table lists only 200, 400, and 404,
 * and states "200 OK: Message has passed the basic check
 * and sent for further processing", so a 201 or 202 from
 * a proxy or a future revision is not a documented
 * success and is treated as an `HTTP_<status>` failure,
 * fail-closed (the Pushy sink's pinned-200 rule). A 200
 * is only an acceptance receipt, not an incident: the
 * reference states the message has only "passed the basic
 * check" and been "sent for further processing", and the
 * success body is only `{ message: "success", trace_id }`
 * — no incident id, no incident state. The `trace_id`
 * is the receipt for tracking the alert later (`GET
 * https://events.zenduty.com/api/alert/status/
 * <trace_id>/`, valid within 60 minutes, states
 * `queued`/`failed`/`completed` — out of scope here),
 * so `send()` returns the collected trace ids in send
 * order; a 200 that carries no trace id is still an
 * acceptance (the status is the acceptance credential
 * here, unlike the Pushy sink, where a 200 without a
 * push id is a failure), just one with no later tracking.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over the HTTP status:
 *
 * - a non-200 POST throws `ZendutySinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Zenduty could
 *   not accept the alert right now, not that the payload
 *   is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-200 status, including the two the
 *   reference pins, 400 (incorrect payload) and 404
 *   (invalid integration key or integration disabled):
 *   retrying them burns the retry budget for nothing, and
 *   rerouting them elsewhere would page an on-call
 *   engineer the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload (a retry after a
 *   transport failure reuses the same entity id, so it
 *   lands on the open incident rather than creating a
 *   second one — see entity_id above);
 * - a missing client throws `ZendutySinkConfigError`,
 *   which `classifyFailure` maps to `non_retryable`
 *   (the WR-116 rule).
 *
 * One honesty note on the failure mapping: the Generic
 * Integration page re-checked for this item
 * (zenduty.com/docs/generic-integration/, 2026-11-01)
 * pins the endpoint, the webhook URL form, the
 * `alert_type`/`message`/`summary`/`entity_id`/`payload`
 * body, the entity-id de-duplication and resolution, the
 * 200 acceptance with its `{ message: "success",
 * trace_id }` body, the 60-minute trace-id status window,
 * and the 400/404 error meanings — but it publishes no
 * 429 or 5xx mention at all. The 429/5xx-retryable,
 * other-4xx-fail-closed mapping above is therefore the
 * slot convention for the unlisted statuses, not a
 * per-status claim from that page, and no per-status
 * error code is invented here: the failure record
 * carries `HTTP_<status>` plus whatever free-form error
 * text the client surfaced, and nothing more. The 400
 * and 404 meanings, by contrast, are the page's own
 * words, quoted above.
 *
 * Zero new dependencies: the injected client only. (No
 * `node:crypto` import either: with no idempotency key to
 * derive, there is nothing to hash.)
 */

/** Generic message used when an event carries no value for the message body. */
export const ZENDUTY_FALLBACK_MESSAGE = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const ZENDUTY_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Content type the client sends with the JSON body. */
export const ZENDUTY_JSON_CONTENT_TYPE = "application/json";

/** Zenduty events base URL. */
export const ZENDUTY_API_BASE_URL = "https://events.zenduty.com";

/**
 * Generic Integration webhook URL template, with the two
 * segments the client alone holds: `{integration}` is
 * the integration segment and `{uuid}` is the integration
 * UUID. The client substitutes both from the webhook URL
 * it was configured with; the sink never builds this URL,
 * so no key — real or placeholder — ever passes through
 * the sink. Exported so the URL shape is pinned in
 * tests, not so the sink can construct a request URL.
 */
export const ZENDUTY_GENERIC_WEBHOOK_URL_TEMPLATE =
  "https://events.zenduty.com/integration/{integration}/generic/{uuid}/";

/**
 * Alert-status tracking endpoint template, with the
 * `{trace_id}` the 200 response returns. Tracking is out
 * of scope for this item (the status is only retrievable
 * within 60 minutes of the alert creation request, with
 * states `queued`/`failed`/`completed`); the template is
 * exported so the receipt shape is pinned in tests, not
 * so the sink can poll it.
 */
export const ZENDUTY_ALERT_STATUS_URL_TEMPLATE =
  "https://events.zenduty.com/api/alert/status/{trace_id}/";

/** Default `alert_type`. */
export const ZENDUTY_DEFAULT_ALERT_TYPE = "critical";

/** The alert types the backlog pins. */
export const ZENDUTY_ALERT_TYPES = [
  "critical",
  "error",
  "warning",
  "info",
  "acknowledged",
  "resolved",
] as const;

/** One of the alert types the backlog pins. */
export type ZendutyAlertType = (typeof ZENDUTY_ALERT_TYPES)[number];

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (JSON) to the Generic Integration
 * webhook URL it alone holds (`https://events.zenduty.com/
 * integration/{integration}/generic/{uuid}/`), sending
 * `headers` verbatim as the request headers. There is
 * deliberately no `url` field here: the webhook URL
 * carries the integration key in its path, so the sink
 * must never see, build, or hand over a URL — the client
 * posts to the URL it was configured with. No
 * `Idempotency-Key` header is sent: the docs do not
 * verify it for this endpoint, and the entity id already
 * gives a retry its de-duplication key (see the module
 * header).
 */
export interface ZendutyAlertPostRequest {
  /**
   * Request headers, sent verbatim:
   * `{ "Content-Type": "application/json" }`. There is
   * deliberately no `url` field: the Generic Integration
   * webhook URL (integration segment and UUID in the
   * path) is held by the client alone, never by the sink,
   * and there is no `Authorization` header and no
   * `Idempotency-Key` header.
   */
  headers: Record<string, string>;
  /**
   * The JSON request body, serialized:
   * `{"alert_type":"critical","message":"<summary>","summary":"<key>","entity_id":"<key>","payload":{"key":"<key>","traceId":"<traceId>"}}`
   * (`summary` is omitted when the event carries neither
   * a key nor a trace id; `entity_id` is omitted when the
   * event carries no key; `payload` is omitted when the
   * event carries no identifiers and the payload opt-in
   * is off, and gains a truncated `body` field only under
   * the `includePayload` opt-in). No credential ever
   * enters the body.
   */
  body: string;
}

/**
 * The result of one POST, as reported by the injected
 * client. The HTTP status decides acceptance: exactly
 * 200 means Zenduty accepted the alert, and the
 * `traceId` — when the client surfaced one — is the
 * receipt for tracking the alert later through the alert
 * status endpoint (`GET /api/alert/status/<trace_id>/`,
 * valid within 60 minutes). A 200 without a trace id is
 * still an acceptance (the status is the acceptance
 * credential here), just one with no later tracking. The
 * success body is only `{ message: "success", trace_id }`:
 * no incident id, no incident state — a 200 is an
 * acceptance receipt, not an incident. The error text,
 * when the client surfaced one, rides on the failure
 * record; no per-status error code is claimed from the
 * reference beyond the documented 400/404 meanings (see
 * the module header).
 */
export interface ZendutyAlertPostResponse {
  /** The HTTP status of the POST (e.g. 200, 400, 404, 429, 500). */
  status: number;
  /** The trace id from the success body, when the client surfaced one. */
  traceId?: string;
  /** Free-form error text from the error body, when the client surfaced one. */
  errorMessage?: string;
}

/**
 * The injected Zenduty alert client. Any client adapter
 * implements this one method; it returns the POST's status
 * and the trace id when present — a throw is a codeless
 * transport failure, retryable. The client is expected to
 * POST one alert per call, sending `body` verbatim as
 * the request body (JSON), sending `headers` verbatim
 * as the request headers, and posting to the Generic
 * Integration webhook URL it alone holds
 * (`https://events.zenduty.com/integration/{integration}/
 * generic/{uuid}/`) — the sink never sees that URL.
 */
export interface ZendutyAlertClient {
  post(request: ZendutyAlertPostRequest): Promise<ZendutyAlertPostResponse>;
}

/**
 * Configuration for one Zenduty sink. The client is
 * injected: without one, `send()` throws
 * `ZendutySinkConfigError` (dry runs excepted — they need
 * no client at all). The API key is deliberately absent
 * from this config: the client alone holds the Generic
 * Integration webhook URL (integration segment and UUID
 * in the path), and the key is never persisted by the
 * sink.
 */
export interface ZendutySinkConfig {
  /**
   * The Zenduty alert client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `ZendutyAlertClient` and alone holds the
   * Generic Integration webhook URL. Required for real sends; a missing
   * client is a config error, not a silent no-op.
   */
  client?: ZendutyAlertClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, traceIds: [], dryRun: true }`
   * and performs zero client I/O — no POST call, no stat
   * changes. Messages are still validated (including
   * alert-type derivation), so a dry run catches a
   * malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The client is not required in dry-run mode, mirroring
   * the sibling sinks' dry-run exemption; the rest of the
   * config must still be valid — a dry run against a sink
   * with a bad alert type would rehearse a request that
   * could never send.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the request body's
   * `payload` gains a `body` field carrying the event
   * body verbatim as a JSON string, truncated to
   * `payloadMaxChars` characters (see below), alongside
   * the identifiers. When `false` or absent, `payload`
   * carries the identifiers only — the default, so event
   * bodies (which routinely carry PII) never leak into an
   * alert unless the operator explicitly asks for them.
   */
  includePayload?: boolean;
  /**
   * Truncation limit for an opted-in payload snippet, in
   * characters (default 2000). Only meaningful with
   * `includePayload`; the truncation is unconditional when
   * the opt-in is set, so an opted-in body cannot flood
   * an alert. Must be a positive integer when set.
   */
  payloadMaxChars?: number;
  /**
   * Default alert type: one of critical/error/warning/
   * info/acknowledged/resolved, default critical.
   * Config-held, overridable per record (see
   * `ZendutyRecord.alertType`): the relay does not invent
   * a severity it was not told. Must be one of the six
   * values when set.
   */
  alertType?: ZendutyAlertType;
}

/** One event to alert about. */
export interface ZendutyRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Content-derivation source, first priority: the event's
   * subject, when set and non-empty. The incident title
   * (`message`).
   */
  subject?: string;
  /**
   * Content-derivation source, second priority: the event's key
   * (e.g. aggregate id). Also the incident summary
   * (`summary`, first priority there), the alert's
   * `entity_id` (the official de-duplication key), and a
   * `payload` identifier, when set.
   */
  key?: string;
  /**
   * Content-derivation source, last priority: the trace id.
   * Also the incident summary (`summary`, second
   * priority there) and a `payload` identifier, when set.
   */
  traceId?: string;
  /**
   * Per-record alert type override: one of
   * critical/error/warning/info/acknowledged/resolved.
   * When absent, the config's `alertType` applies,
   * defaulting to critical. A `resolved` override with
   * the same `key` as an earlier alert resolves that
   * alert's incident — the sink sends it exactly like
   * any other alert and lets Zenduty resolve the
   * incident; there is no sink-side lifecycle tracking.
   */
  alertType?: ZendutyAlertType;
}

/** One failed message, with its retry lane already mapped. */
export interface ZendutyFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /**
   * Failure code: `HTTP_<status>` for a non-200 POST,
   * or `TRANSPORT_ERROR` for a codeless failure.
   */
  errorCode: string;
  /** Downstream HTTP status, when the failure was a non-200 POST. */
  statusCode?: number;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: 429 and 5xx
   * (plus codeless transport failures) are retryable;
   * every other non-200 status is a fail-closed message
   * (400 incorrect payload, 404 invalid integration key
   * or disabled integration — the reference's own words
   * — and the rest). No per-status error code is claimed
   * from the reference beyond the documented 400/404
   * meanings (see the module header).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface ZendutySendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /**
   * Trace ids in send order — the id of each accepted
   * message that reported one, the receipt for tracking
   * the alert later through the alert status endpoint
   * (`GET /api/alert/status/<trace_id>/`, valid within
   * 60 minutes). Empty in dry-run mode, and an accepted
   * message that reported no trace id contributes no
   * entry here: it is still accepted (the 200 status is
   * the acceptance credential), it just has no later
   * tracking.
   */
  traceIds: string[];
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-299). */
export interface ZendutySinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Zenduty send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already received on Zenduty's server and are *not* in
 * `failedRecords`.
 */
export class ZendutySinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: ZendutyFailedRecord[];
  constructor(message: string, failedRecords: ZendutyFailedRecord[]) {
    super(message);
    this.name = "ZendutySinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class ZendutySinkConfigError extends ZendutySinkError {
  constructor(reason: string) {
    super(`zenduty-sink: ${reason}`, []);
    this.name = "ZendutySinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery.
 * The alert type, when set, must be one of critical/error/
 * warning/info/acknowledged/resolved. There is deliberately
 * no `apiKey` field to validate: the client alone holds the
 * Generic Integration webhook URL.
 */
export function assertValidZendutySinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is ZendutySinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
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
    c.alertType !== undefined &&
    (typeof c.alertType !== "string" ||
      !(ZENDUTY_ALERT_TYPES as readonly string[]).includes(c.alertType))
  ) {
    throw new RangeError(
      at("`alertType` must be one of critical, error, warning, info, acknowledged, resolved when set")
    );
  }
}

/**
 * Derive one record's message (the incident title): the
 * first non-empty value among `subject`, `key`, and
 * `traceId`, in that order. Falls back to the generic
 * `webhook event` message when the record carries none —
 * an alert sink must not silently drop sourceless events.
 */
export function resolveZendutyMessage(record: ZendutyRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return ZENDUTY_FALLBACK_MESSAGE;
}

/**
 * Derive one record's summary (the incident summary):
 * the first non-empty value among `key` and `traceId`,
 * in that order. Returns `undefined` when the record
 * carries neither, so the field is omitted entirely
 * rather than sent empty.
 */
export function resolveZendutySummary(record: ZendutyRecord): string | undefined {
  for (const value of [record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return undefined;
}

/**
 * Resolve the alert type: the record's override when set,
 * else the config-held value, else `critical`.
 */
export function resolveZendutyAlertType(
  record: ZendutyRecord,
  config: Pick<ZendutySinkConfig, "alertType">
): ZendutyAlertType {
  return record.alertType ?? config.alertType ?? ZENDUTY_DEFAULT_ALERT_TYPE;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood an alert.
 */
export function truncateZendutyPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's `payload` object: only the event's
 * own identifiers — `key` and `traceId` when present,
 * nothing else. Under the `includePayload` opt-in the
 * event body is appended as a `body` field, truncated to
 * `payloadMaxChars` (default 2000). Returns `undefined`
 * when the event carries no identifiers and the opt-in
 * is off, so the field is omitted entirely rather than
 * sent as an empty object.
 */
export function resolveZendutyPayload(
  record: ZendutyRecord,
  config: Pick<ZendutySinkConfig, "includePayload" | "payloadMaxChars">
): Record<string, string> | undefined {
  const payload: Record<string, string> = {};
  if (record.key !== undefined && record.key !== "") {
    payload.key = record.key;
  }
  if (record.traceId !== undefined && record.traceId !== "") {
    payload.traceId = record.traceId;
  }
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? ZENDUTY_DEFAULT_PAYLOAD_MAX_CHARS;
    payload.body = truncateZendutyPayload(record.body, limit);
  }
  return Object.keys(payload).length === 0 ? undefined : payload;
}

/**
 * Build one record's serialized JSON body: `alert_type`
 * (the record override, else the config default, else
 * critical), `message` (the derived message, never
 * truncated — the re-checked docs state no message
 * length limit), `summary` (the incident summary, from
 * `key` then `traceId`, omitted when the event carries
 * neither), `entity_id` (the event key, omitted when the
 * event carries none — the official de-duplication key),
 * and `payload` (only the `key`/`traceId` identifiers,
 * with the event body appended as a `body` field only
 * under the `includePayload` opt-in; omitted when
 * empty). No `urls`, `sla`, `escalation_policy`,
 * `priority`, `stakeholders`, or `tags`: the
 * Zenduty-side integration configuration owns those.
 * No credential ever enters the body — the client alone
 * holds the Generic Integration webhook URL (integration
 * segment and UUID in the path).
 */
export function buildZendutyAlertBody(
  record: ZendutyRecord,
  config: Pick<ZendutySinkConfig, "includePayload" | "payloadMaxChars" | "alertType">
): string {
  const alert: {
    alert_type: ZendutyAlertType;
    message: string;
    summary?: string;
    entity_id?: string;
    payload?: Record<string, string>;
  } = {
    alert_type: resolveZendutyAlertType(record, config),
    message: resolveZendutyMessage(record),
  };
  const summary = resolveZendutySummary(record);
  if (summary !== undefined) {
    alert.summary = summary;
  }
  if (record.key !== undefined && record.key !== "") {
    alert.entity_id = record.key;
  }
  const payload = resolveZendutyPayload(record, config);
  if (payload !== undefined) {
    alert.payload = payload;
  }
  return JSON.stringify(alert);
}

/**
 * Validate one record. Throws `RangeError` on an empty
 * body string — even without the opt-in, the body is the
 * record's payload, and an empty record is a caller bug
 * that must fail closed, never alert as an empty message.
 * A bad per-record `alertType` value fails here too (the
 * config-level check in `assertValidZendutySinkConfig`
 * only covers the config default). A `resolved` alert
 * type without a key is not rejected here: the reference
 * does not pin it as an error, so the sink sends it
 * exactly like any other alert and lets Zenduty decide.
 */
export function resolveZendutyRecord(
  record: ZendutyRecord,
  index: number
): { index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`zenduty-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  if (
    record.alertType !== undefined &&
    !(ZENDUTY_ALERT_TYPES as readonly string[]).includes(record.alertType)
  ) {
    throw new RangeError(
      `zenduty-sink: record ${index} \`alertType\` must be one of critical, error, warning, info, acknowledged, resolved when set`
    );
  }
  return { index };
}

/**
 * Map one Zenduty POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says Zenduty could not
 * accept the alert right now, not that the payload is
 * poison. Every other non-200 status (400 incorrect
 * payload, 404 invalid integration key or disabled
 * integration — the reference's own words — and the rest)
 * is a fail-closed message. Honesty note: the Generic
 * Integration page re-checked for this item publishes no
 * 429 or 5xx mention at all, so this mapping is the slot
 * convention for the unlisted statuses, not a per-status
 * claim from that page — and no per-status error code is
 * invented here. Callers only pass non-200 statuses here;
 * exactly 200 is acceptance on its own (see
 * `classifyZendutyAlertResponse`).
 */
export function classifyZendutyRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * The verdict on one alert POST: either an acceptance,
 * or a failure with its error code and retry lane.
 */
export type ZendutyAlertVerdict =
  | { accepted: true }
  | { accepted: false; errorCode: string; retryable: boolean; errorMessage?: string };

/**
 * Decide one alert POST's verdict from the response the
 * client reported. Exactly 200 is acceptance — the
 * reference's status table lists only 200, 400, and 404,
 * and states "200 OK: Message has passed the basic check
 * and sent for further processing", so a 201 or 202 from
 * a proxy or a future revision is not a documented
 * success and is treated as an `HTTP_<status>` failure,
 * fail-closed (the Pushy sink's pinned-200 rule). A 200
 * is only an acceptance receipt, not an incident: the
 * success body is only `{ message: "success", trace_id }`
 * — no incident id, no incident state — and the alert
 * itself is processed further by Zenduty, tracked later
 * through the alert status endpoint with the `trace_id`
 * (valid within 60 minutes; out of scope here). A 200
 * that carries no trace id is still an acceptance (the
 * status is the acceptance credential here, unlike the
 * Pushy sink's 200-without-a-push-id failure), just one
 * with no later tracking. Any non-200 status is a
 * failure with an `HTTP_<status>` code and the WR-210
 * lane; the error text rides on the failure record when
 * the client surfaced one. No per-status error code is
 * claimed from the reference beyond the documented
 * 400/404 meanings (see the module header).
 */
export function classifyZendutyAlertResponse(
  response: ZendutyAlertPostResponse
): ZendutyAlertVerdict {
  if (response.status === 200) {
    return { accepted: true };
  }
  const verdict: ZendutyAlertVerdict = {
    accepted: false,
    errorCode: `HTTP_${response.status}`,
    retryable: classifyZendutyRecordFailure(response.status),
  };
  if (response.errorMessage !== undefined && response.errorMessage !== "") {
    verdict.errorMessage = response.errorMessage;
  }
  return verdict;
}

/**
 * Zenduty sink (WR-299). One alert is sent per record; the
 * caller owns retry / dead-letter policy around `send()`
 * — this class performs one POST attempt per message
 * through the injected client and reports its outcome.
 * Failures throw `ZendutySinkError` carrying exactly the
 * failed messages with their retry lanes. The sink keeps
 * no per-alert state: a later `resolved` alert carrying
 * the same `entity_id` is sent exactly like any other
 * alert, and Zenduty resolves the incident — the sink
 * does not try to track that.
 */
export class ZendutySink {
  private readonly cfg: ZendutySinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: ZendutySinkConfig) {
    assertValidZendutySinkConfig(config, "ZendutySink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): ZendutySinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send the alerts, in input order. Throws
   * `ZendutySinkConfigError` when no client was injected,
   * and `ZendutySinkError` when any message fails
   * (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: ZendutyRecord[]): Promise<ZendutySendResult> {
    const resolved = records.map((r, i) => resolveZendutyRecord(r, i));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The client
      // is not required here, mirroring the sibling sinks'
      // dry-run exemption; the rest of the config was already
      // validated at construction.
      return { ok: true, sent: 0, traceIds: [], dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new ZendutySinkConfigError("no client injected (set `client` in the sink config)");
    }
    const failedRecords: ZendutyFailedRecord[] = [];
    const traceIds: string[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          headers: {
            "Content-Type": ZENDUTY_JSON_CONTENT_TYPE,
          },
          body: buildZendutyAlertBody(records[i], this.cfg),
        });
        const verdict = classifyZendutyAlertResponse(response);
        if (verdict.accepted) {
          // Exactly 200 is acceptance on its own: the status
          // is the acceptance receipt, and the alert itself
          // is processed further by Zenduty — the response is
          // an acceptance receipt, not an incident. The trace
          // id, when the client surfaced one, is the receipt
          // for tracking the alert later through the alert
          // status endpoint; a 200 without one is still
          // accepted.
          sent += 1;
          if (typeof response.traceId === "string" && response.traceId !== "") {
            traceIds.push(response.traceId);
          }
          continue;
        }
        const failed: ZendutyFailedRecord = {
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
        failedRecords.push(toZendutyFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new ZendutySinkError(
        `zenduty-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent, traceIds };
  }
}

/**
 * Convert a client throw into a failed message: a codeless
 * transport failure (`TRANSPORT_ERROR`, retryable — the SQS
 * no-status rule). A retry reuses the same entity id, so it
 * lands on the open incident rather than creating a second
 * one (see the module header).
 */
function toZendutyFailedRecord(err: unknown, index: number): ZendutyFailedRecord {
  const failed: ZendutyFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
