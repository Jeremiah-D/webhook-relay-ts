/**
 * Squadcast on-call alert delivery sink (WR-300).
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
 * the ilert sink (WR-298) posts an event to an ilert
 * alert source through the Events API v1 with the key in
 * the URL path and an `eventType`/`summary`/`details`/
 * `alertKey`/`priority` envelope, and the Zenduty sink
 * (WR-299) posts an alert to a Zenduty Generic
 * Integration webhook URL with an `alert_type`/`message`/
 * `summary`/`entity_id`/`payload` envelope, this sink
 * posts an incident to a Squadcast Incident Webhook: one
 * event is sent as one POST that Squadcast routes into
 * that service's escalation policy, and Squadcast —
 * not the relay — owns the incident, the escalation, the
 * notification, and the incident lifecycle.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Squadcast
 * server. The sink owns the relay-side concerns — the
 * status, the message derivation, the description, the
 * event id, the payload-inclusion policy, the per-message
 * failure mapping — and the injected client owns the wire
 * protocol, including the POST call, the Incident Webhook
 * URL, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { headers: { "Content-Type": "application/json" },
 *     body: "{\"message\":\"<message>\",\"description\":\"key=<key>; traceId=<traceId>\",\"status\":\"trigger\",\"event_id\":\"<key>\"}" }
 *
 * The client POSTs to the Incident Webhook URL it alone
 * holds — copied in Squadcast from Services → Alert
 * Sources → Incident Webhook for the applicable service —
 * sending `body` verbatim as the request body (JSON) and
 * sending `headers` verbatim as the request headers.
 * Seven things about this shape are deliberate, and all
 * follow the sibling sinks or the backlog pins:
 *
 * - The Incident Webhook URL — per-service webhook URL,
 *   key/UUID in the URL path alike — is held by the
 *   client alone. The sink never receives the key, never
 *   places it in the request, and never logs it: the sink
 *   config has no `apiKey` field at all, and the handed
 *   request carries no URL at all (like the ilert and
 *   Zenduty sinks, unlike the Opsgenie sink, whose handed
 *   request carries the bare endpoint URL), so there is
 *   nothing in it for a log line or a retry queue to leak
 *   — and the key is never persisted by the sink. The key
 *   rides in the URL path (like the ilert sink's
 *   alert-source URL and the Zenduty sink's Generic
 *   Integration webhook URL, unlike the Opsgenie sink's
 *   `Authorization: GenieKey <key>` header and the
 *   PagerDuty sink's `routing_key` inside the body), so
 *   the sink hands the client the bare `Content-Type`
 *   header and the body and the client posts to the
 *   webhook URL it was configured with: the sink's
 *   request never contains a key, a placeholder, or
 *   anything that looks like one. This is the Squadcast
 *   form of the MagicBell rule (whose Project JWT the
 *   client alone holds as an `Authorization: Bearer`
 *   header), with Squadcast's own credential source: the
 *   per-service Incident Webhook URL, verified against
 *   the current docs (squadcasthub.github.io/docs/apiv2,
 *   re-checked 2026-11-02 — "Search for **Incident
 *   Webhook** from the Alert Source drop-down and copy
 *   the Webhook URL. Use this Webhook URL endpoint to
 *   send `HTTP POST` requests").
 * - The endpoint is the Incident Webhook the backlog
 *   pins: a generic incoming webhook per service,
 *   reached through the URL copied from Services →
 *   Alert Sources → Incident Webhook. No URL template
 *   constant is exported here, unlike the Zenduty sink:
 *   the re-checked page states the copy path but
 *   publishes no literal webhook URL form, and inventing
 *   one would be worse than exporting none — the client
 *   alone holds the URL it was configured with, and the
 *   sink never builds, sees, or hands over a URL.
 * - `message` is mandatory, so it is derived as the
 *   first non-empty value among `subject`, `key`, and
 *   `traceId`, in that order, falling back to the generic
 *   `webhook event`: an alert sink that silently dropped
 *   sourceless events would hide exactly the deliveries
 *   an operator most needs to see. No truncation is
 *   applied: the re-checked documentation states no
 *   message length limit for this endpoint, and inventing
 *   one would silently cut an operator's alert text.
 * - `description` is mandatory, so it is derived from
 *   the event's own identifiers — `key=<key>;
 *   traceId=<traceId>` when present (the ilert `details`
 *   form) — and falls back to the derived message text
 *   when the event carries no identifiers, so it is never
 *   empty: a descriptionless incident would hide exactly
 *   the context an operator most needs to see. No
 *   truncation is applied to the identifiers or the
 *   fallback text: the re-checked documentation states no
 *   description length limit for this endpoint.
 * - `status` is one of `trigger` and `resolve` (the two
 *   values the reference pins). It is config-held with a
 *   per-record override, defaulting to `trigger`: the
 *   relay does not invent a lifecycle transition it was
 *   not told. `resolve` must carry an `event_id` —
 *   without one Squadcast cannot associate the call with
 *   an open incident — so a record (or a config default)
 *   that asks for `resolve` without a key fails closed
 *   with a `RangeError` before any POST is made, never
 *   sent as a keyless resolution (the ilert
 *   ACCEPT/RESOLVE rule). Note the reference says a
 *   resolve call does not *require* `message` and
 *   `description` — it does not forbid them — so the
 *   sink still sends the derived values on a resolve,
 *   keeping one uniform envelope instead of a second,
 *   resolve-only shape; the description is never empty
 *   either way (see above).
 * - `event_id` is the event's `key`, sent when one
 *   exists and omitted entirely when the event carries
 *   none: a keyless event still triggers, it just carries
 *   no grouping key. The event id is the official
 *   de-duplication/association key: the reference states
 *   a trigger "associates the incident with the
 *   `event_id` value as specified" and that the same
 *   `event_id` "can be used to resolve the above created
 *   incident with an API call", so a second trigger with
 *   the same event id while the first is still open is
 *   associated with the same incident instead of creating
 *   a new one, and sending `status` `resolve` with the
 *   same event id resolves that incident. The event id is
 *   sent verbatim, never truncated: truncating a dedup
 *   key would silently merge distinct incidents. The
 *   same event id also makes a transport-failure retry
 *   safe: replaying the same record reuses the same event
 *   id, so the retry lands on the open incident instead
 *   of paging the on-call engineer twice. The reference's
 *   examples show `event_id` as a string (`"6"`); the
 *   sink sends the event key verbatim as a string, never
 *   coerced to a number.
 * - `payload` carries only the event's own identifiers
 *   by default — `key` and `traceId` when present,
 *   nothing else — so the alert's payload stays
 *   identifiers, never event body: here that means the
 *   `description` carries the identifiers only (see
 *   above). Under the `includePayload` opt-in the event
 *   body is appended to the `description` after the
 *   identifiers, truncated to `payloadMaxChars`
 *   characters (default 2000). `tags` is out of scope:
 *   the reference shows tags as an optional enrichment
 *   (`"tags": { "tagname1": "Tag value#1", ... }`, with
 *   an optional per-tag colour), and the sink never
 *   invents a routing, severity, or priority decision.
 *   No `Idempotency-Key` header is sent: the reference
 *   documents no idempotency key for this endpoint, and
 *   the event id already gives a retry its
 *   de-duplication key (see above).
 *
 * Acceptance is decided by the HTTP status alone: any
 * 2xx status means Squadcast accepted the incident, and
 * `send()` returns the count of accepted messages, so a
 * caller that only inspects the result still has the
 * receipt. A 2xx is only an acceptance receipt, not an
 * incident: the incident is routed into the service's
 * escalation policy, and the incident itself is created
 * asynchronously by Squadcast. No receipt id is claimed
 * here: the re-checked documentation states no response
 * id for this endpoint, so `send()` returns no ids —
 * inventing one would be worse than returning none.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over the HTTP status:
 *
 * - a non-2xx POST throws `SquadcastSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Squadcast could
 *   not accept the incident right now, not that the
 *   payload is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 413 (the one
 *   status the reference pins: "The payload size is
 *   limited to 30KB. Any payload that crosses this limit
 *   will not be processed. You will receive HTTP Status
 *   Code 413 to notify you of this"): a payload over
 *   30KB will never shrink on retry, so retrying it
 *   burns the retry budget for nothing, and rerouting it
 *   elsewhere would page an on-call engineer the
 *   operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload (a retry after a
 *   transport failure reuses the same event id, so it
 *   lands on the open incident rather than creating a
 *   second one — see event_id above);
 * - a missing client throws `SquadcastSinkConfigError`,
 *   which `classifyFailure` maps to `non_retryable`
 *   (the WR-116 rule).
 *
 * One honesty note on the failure mapping: the Incident
 * Webhook page re-checked for this item
 * (squadcasthub.github.io/docs/apiv2, 2026-11-02) pins
 * the endpoint, the webhook URL copy path, the
 * `message`/`description`/`status`/`event_id` body, the
 * message/description-mandatory rule, the event-id
 * association and resolution, the optional `tags`, and
 * the 30KB payload limit with its 413 — but it publishes
 * no success status code and no per-status error-code
 * table beyond 413. The 2xx-acceptance and 429/5xx-
 * retryable, other-4xx-fail-closed mapping above is
 * therefore the slot convention for the unlisted
 * statuses, not a per-status claim from that page, and no
 * per-status error code is invented here: the failure
 * record carries `HTTP_<status>` plus whatever free-form
 * error text the client surfaced, and nothing more. If
 * the reference later pins a different success status,
 * only `classifySquadcastIncidentResponse` needs to
 * change.
 *
 * Zero new dependencies: the injected client only. (No
 * `node:crypto` import either: with no idempotency key to
 * derive, there is nothing to hash.)
 */

/** Generic message used when an event carries no value for the message body. */
export const SQUADCAST_FALLBACK_MESSAGE = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const SQUADCAST_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Content type the client sends with the JSON body. */
export const SQUADCAST_JSON_CONTENT_TYPE = "application/json";

/**
 * Squadcast API base host. The Incident Webhook URL is
 * per-service and copied from Services → Alert Sources →
 * Incident Webhook; the re-checked page publishes no
 * literal webhook URL form, so no URL template constant
 * is exported (see the module header) — this host is
 * exported only to pin the product's API host in tests,
 * not so the sink can construct a request URL.
 */
export const SQUADCAST_API_BASE_URL = "https://api.squadcast.com";

/** Default `status`. */
export const SQUADCAST_DEFAULT_STATUS = "trigger";

/** The incident statuses the reference pins. */
export const SQUADCAST_STATUSES = ["trigger", "resolve"] as const;

/** One of the incident statuses the reference pins (trigger/resolve). */
export type SquadcastIncidentStatus = (typeof SQUADCAST_STATUSES)[number];

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (JSON) to the Incident Webhook URL
 * it alone holds (copied from Services → Alert Sources →
 * Incident Webhook for the applicable service), sending
 * `headers` verbatim as the request headers. There is
 * deliberately no `url` field here: the URL carries the
 * per-service webhook key/UUID in its path, so the sink
 * must never see, build, or hand over a URL — the client
 * posts to the URL it was configured with. No
 * `Idempotency-Key` header is sent: the docs do not
 * verify it for this endpoint, and the event id already
 * gives a retry its de-duplication key (see the module
 * header).
 */
export interface SquadcastIncidentPostRequest {
  /**
   * Request headers, sent verbatim:
   * `{ "Content-Type": "application/json" }`. There is
   * deliberately no `url` field: the Incident Webhook
   * URL (per-service key/UUID in the path) is held by
   * the client alone, never by the sink, and there is no
   * `Authorization` header and no `Idempotency-Key`
   * header.
   */
  headers: Record<string, string>;
  /**
   * The JSON request body, serialized:
   * `{"message":"<message>","description":"key=<key>; traceId=<traceId>","status":"trigger","event_id":"<key>"}`
   * (`description` falls back to the message text when
   * the event carries no identifiers, so it is never
   * empty; the event body is appended to it only under
   * the `includePayload` opt-in; `event_id` is omitted
   * when the event carries no key; `tags` is never
   * sent). No credential ever enters the body.
   */
  body: string;
}

/**
 * The result of one POST, as reported by the injected
 * client. The HTTP status decides acceptance: any 2xx
 * means Squadcast accepted the incident. No receipt id
 * is claimed: the re-checked documentation states no
 * response id for this endpoint, so the client surfaces
 * none and `send()` returns no ids. The error text, when
 * the client surfaced one, rides on the failure record;
 * no per-status error code is claimed from the reference
 * beyond the documented 413 (see the module header).
 */
export interface SquadcastIncidentPostResponse {
  /** The HTTP status of the POST (e.g. 200, 201, 413, 429, 500). */
  status: number;
  /** Free-form error text from the error body, when the client surfaced one. */
  errorMessage?: string;
}

/**
 * The injected Squadcast incident client. Any client adapter
 * implements this one method; it returns the POST's status
 * — a throw is a codeless transport failure, retryable.
 * The client is expected to POST one incident per call,
 * sending `body` verbatim as the request body (JSON),
 * sending `headers` verbatim as the request headers, and
 * posting to the Incident Webhook URL it alone holds
 * (copied from Services → Alert Sources → Incident
 * Webhook for the applicable service) — the sink never
 * sees that URL.
 */
export interface SquadcastIncidentClient {
  post(request: SquadcastIncidentPostRequest): Promise<SquadcastIncidentPostResponse>;
}

/**
 * Configuration for one Squadcast sink. The client is
 * injected: without one, `send()` throws
 * `SquadcastSinkConfigError` (dry runs excepted — they need
 * no client at all). The API key is deliberately absent
 * from this config: the client alone holds the Incident
 * Webhook URL (per-service key/UUID in the path), and
 * the key is never persisted by the sink.
 */
export interface SquadcastSinkConfig {
  /**
   * The Squadcast incident client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `SquadcastIncidentClient` and alone holds
   * the Incident Webhook URL. Required for real sends; a missing
   * client is a config error, not a silent no-op.
   */
  client?: SquadcastIncidentClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }`
   * and performs zero client I/O — no POST call, no stat
   * changes. Messages are still validated (including
   * status derivation and the resolve event-id rule), so
   * a dry run catches a malformed record before it
   * reaches production. Mirrors the `dryRun` convention
   * of the S3 offloaders. The client is not required in
   * dry-run mode, mirroring the sibling sinks' dry-run
   * exemption; the rest of the config must still be
   * valid — a dry run against a sink with a bad status
   * would rehearse a request that could never send.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the request body's
   * `description` appends the event body verbatim as a
   * JSON string, truncated to `payloadMaxChars`
   * characters (see below), after the identifiers (or
   * after the message-text fallback, when the event
   * carries no identifiers). When `false` or absent,
   * `description` carries the identifiers only — the
   * default, so event bodies (which routinely carry PII)
   * never leak into an incident unless the operator
   * explicitly asks for them.
   */
  includePayload?: boolean;
  /**
   * Truncation limit for an opted-in payload snippet, in
   * characters (default 2000). Only meaningful with
   * `includePayload`; the truncation is unconditional when
   * the opt-in is set, so an opted-in body cannot flood
   * an incident. Must be a positive integer when set.
   */
  payloadMaxChars?: number;
  /**
   * Default incident status: one of trigger/resolve,
   * default trigger. Config-held, overridable per record
   * (see `SquadcastRecord.status`): the relay does not
   * invent a lifecycle transition it was not told. Must
   * be one of the two values when set. A configured
   * `resolve` default still needs an event id on every
   * record — see `resolveSquadcastRecord`.
   */
  status?: SquadcastIncidentStatus;
}

/** One event to alert about. */
export interface SquadcastRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Content-derivation source, first priority: the event's
   * subject, when set and non-empty. The incident message.
   */
  subject?: string;
  /**
   * Content-derivation source, second priority: the event's key
   * (e.g. aggregate id). Also the incident's `event_id`
   * (the official de-duplication/association key) and a
   * `description` identifier, when set. Required when the
   * effective status is resolve — without one Squadcast
   * cannot associate the call with an open incident.
   */
  key?: string;
  /**
   * Content-derivation source, last priority: the trace id.
   * Also a `description` identifier, when set.
   */
  traceId?: string;
  /**
   * Per-record incident status override: one of
   * trigger/resolve. When absent, the config's `status`
   * applies, defaulting to trigger. A `resolve` override
   * still needs an event id on this record — see
   * `resolveSquadcastRecord`.
   */
  status?: SquadcastIncidentStatus;
}

/** One failed message, with its retry lane already mapped. */
export interface SquadcastFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /**
   * Failure code: `HTTP_<status>` for a non-2xx POST,
   * or `TRANSPORT_ERROR` for a codeless failure.
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
   * (413 payload over the documented 30KB limit, bad
   * input, bad webhook key, and the rest). No per-status
   * error code is claimed from the reference beyond the
   * documented 413 (see the module header).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface SquadcastSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-300). */
export interface SquadcastSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Squadcast send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already received on Squadcast's server and are *not* in
 * `failedRecords`.
 */
export class SquadcastSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: SquadcastFailedRecord[];
  constructor(message: string, failedRecords: SquadcastFailedRecord[]) {
    super(message);
    this.name = "SquadcastSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class SquadcastSinkConfigError extends SquadcastSinkError {
  constructor(reason: string) {
    super(`squadcast-sink: ${reason}`, []);
    this.name = "SquadcastSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery.
 * The status, when set, must be one of trigger/resolve.
 * There is deliberately no `apiKey` field to validate: the
 * client alone holds the Incident Webhook URL.
 */
export function assertValidSquadcastSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is SquadcastSinkConfig {
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
    c.status !== undefined &&
    (typeof c.status !== "string" ||
      !(SQUADCAST_STATUSES as readonly string[]).includes(c.status))
  ) {
    throw new RangeError(at("`status` must be one of trigger, resolve when set"));
  }
}

/**
 * Derive one record's incident message: the first
 * non-empty value among `subject`, `key`, and `traceId`,
 * in that order. Falls back to the generic `webhook
 * event` message when the record carries none — an alert
 * sink must not silently drop sourceless events.
 */
export function resolveSquadcastMessage(record: SquadcastRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return SQUADCAST_FALLBACK_MESSAGE;
}

/**
 * Resolve the incident status: the record's override when set,
 * else the config-held value, else `trigger`.
 */
export function resolveSquadcastStatus(
  record: SquadcastRecord,
  config: Pick<SquadcastSinkConfig, "status">
): SquadcastIncidentStatus {
  return record.status ?? config.status ?? SQUADCAST_DEFAULT_STATUS;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood an incident.
 */
export function truncateSquadcastPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's `description`: only the event's own
 * identifiers — `key=<key>` and `traceId=<traceId>`
 * when present, joined with `"; "` — and, when the event
 * carries no identifiers, the derived message text, so
 * the description is never empty. Under the
 * `includePayload` opt-in the event body is appended
 * after the identifiers (or after the message-text
 * fallback), truncated to `payloadMaxChars` (default
 * 2000). The description is never truncated itself: the
 * re-checked docs state no description length limit.
 */
export function resolveSquadcastDescription(
  record: SquadcastRecord,
  config: Pick<SquadcastSinkConfig, "includePayload" | "payloadMaxChars">
): string {
  const parts: string[] = [];
  if (record.key !== undefined && record.key !== "") {
    parts.push(`key=${record.key}`);
  }
  if (record.traceId !== undefined && record.traceId !== "") {
    parts.push(`traceId=${record.traceId}`);
  }
  const base = parts.length > 0 ? parts.join("; ") : resolveSquadcastMessage(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? SQUADCAST_DEFAULT_PAYLOAD_MAX_CHARS;
    const payload = truncateSquadcastPayload(record.body, limit);
    return `${base}\n\n${payload}`;
  }
  return base;
}

/**
 * Build one record's serialized JSON body: `message`
 * (the derived message, never truncated — the re-checked
 * docs state no message length limit), `description`
 * (only the `key`/`traceId` identifiers, falling back to
 * the message text when the event carries neither, so
 * never empty; the event body appended only under the
 * `includePayload` opt-in), `status` (the record
 * override, else the config default, else trigger), and
 * `event_id` (the event key, omitted when the event
 * carries none — the official de-duplication/association
 * key). No `tags`: the record carries no tag values, and
 * the sink never invents any. No credential ever enters
 * the body — the client alone holds the Incident Webhook
 * URL (per-service key/UUID in the path).
 */
export function buildSquadcastIncidentBody(
  record: SquadcastRecord,
  config: Pick<SquadcastSinkConfig, "includePayload" | "payloadMaxChars" | "status">
): string {
  const incident: {
    message: string;
    description: string;
    status: SquadcastIncidentStatus;
    event_id?: string;
  } = {
    message: resolveSquadcastMessage(record),
    description: resolveSquadcastDescription(record, config),
    status: resolveSquadcastStatus(record, config),
  };
  if (record.key !== undefined && record.key !== "") {
    incident.event_id = record.key;
  }
  return JSON.stringify(incident);
}

/**
 * Validate one record. Throws `RangeError` on an empty
 * body string — even without the opt-in, the body is the
 * record's payload, and an empty record is a caller bug
 * that must fail closed, never alert as an empty message.
 * Also throws `RangeError` when the effective status is
 * `resolve` and the record carries no key: without an
 * `event_id` Squadcast cannot associate the call with an
 * open incident, so the call must never be sent keyless.
 * A bad per-record `status` value fails here too (the
 * config-level check in `assertValidSquadcastSinkConfig`
 * only covers the config default).
 */
export function resolveSquadcastRecord(
  record: SquadcastRecord,
  index: number,
  config: Pick<SquadcastSinkConfig, "status">
): { index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`squadcast-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  if (
    record.status !== undefined &&
    !(SQUADCAST_STATUSES as readonly string[]).includes(record.status)
  ) {
    throw new RangeError(`squadcast-sink: record ${index} \`status\` must be one of trigger, resolve when set`);
  }
  const status = resolveSquadcastStatus(record, config);
  if (
    status === "resolve" &&
    (record.key === undefined || record.key === "")
  ) {
    throw new RangeError(
      `squadcast-sink: record ${index} \`status\` resolve requires an event key (\`key\`), otherwise Squadcast cannot associate the call with an open incident`
    );
  }
  return { index };
}

/**
 * Map one Squadcast POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says Squadcast could
 * not accept the incident right now, not that the payload
 * is poison. Every other non-2xx status (413 payload over
 * the documented 30KB limit — the reference's own words —
 * and the rest) is a fail-closed message: a payload over
 * 30KB will never shrink on retry. Honesty note: the
 * Incident Webhook page re-checked for this item
 * publishes no 429 or 5xx mention at all, so this mapping
 * is the slot convention for the unlisted statuses, not a
 * per-status claim from that page — and no per-status
 * error code is invented here. Callers only pass non-2xx
 * statuses here; any 2xx is acceptance on its own (see
 * `classifySquadcastIncidentResponse`).
 */
export function classifySquadcastRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * The verdict on one incident POST: either an acceptance,
 * or a failure with its error code and retry lane.
 */
export type SquadcastIncidentVerdict =
  | { accepted: true }
  | { accepted: false; errorCode: string; retryable: boolean; errorMessage?: string };

/**
 * Decide one incident POST's verdict from the response the
 * client reported. Any 2xx status is acceptance — the
 * reference pins no per-status success code for this
 * endpoint (see the module header), so the whole 2xx
 * range is accepted, matching the ilert sink: a 200 or
 * 201 from a proxy or a future revision is still an
 * acceptance receipt, not a delivery result. No receipt
 * id is required or collected: the re-checked docs state
 * no response id for this endpoint, so a 2xx is
 * acceptance on its own, with nothing to track later.
 * Any non-2xx status is a failure with an `HTTP_<status>`
 * code and the WR-210 lane; the error text rides on the
 * failure record when the client surfaced one. No
 * per-status error code is claimed from the reference
 * beyond the documented 413 (see the module header).
 */
export function classifySquadcastIncidentResponse(
  response: SquadcastIncidentPostResponse
): SquadcastIncidentVerdict {
  if (response.status >= 200 && response.status < 300) {
    return { accepted: true };
  }
  const verdict: SquadcastIncidentVerdict = {
    accepted: false,
    errorCode: `HTTP_${response.status}`,
    retryable: classifySquadcastRecordFailure(response.status),
  };
  if (response.errorMessage !== undefined && response.errorMessage !== "") {
    verdict.errorMessage = response.errorMessage;
  }
  return verdict;
}

/**
 * Squadcast sink (WR-300). One incident is sent per record; the
 * caller owns retry / dead-letter policy around `send()`
 * — this class performs one POST attempt per message
 * through the injected client and reports its outcome.
 * Failures throw `SquadcastSinkError` carrying exactly the
 * failed messages with their retry lanes. The sink keeps
 * no per-incident state: a later `resolve` carrying the
 * same `event_id` is sent exactly like any other
 * incident, and Squadcast resolves the incident — the
 * sink does not try to track that.
 */
export class SquadcastSink {
  private readonly cfg: SquadcastSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: SquadcastSinkConfig) {
    assertValidSquadcastSinkConfig(config, "SquadcastSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): SquadcastSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send the incidents, in input order. Throws
   * `SquadcastSinkConfigError` when no client was injected,
   * and `SquadcastSinkError` when any message fails
   * (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: SquadcastRecord[]): Promise<SquadcastSendResult> {
    const resolved = records.map((r, i) => resolveSquadcastRecord(r, i, this.cfg));
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
      throw new SquadcastSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const failedRecords: SquadcastFailedRecord[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          headers: {
            "Content-Type": SQUADCAST_JSON_CONTENT_TYPE,
          },
          body: buildSquadcastIncidentBody(records[i], this.cfg),
        });
        const verdict = classifySquadcastIncidentResponse(response);
        if (verdict.accepted) {
          // Any 2xx is acceptance on its own: the status is
          // the acceptance receipt, and the incident itself
          // is created asynchronously by Squadcast — the
          // response is an acceptance receipt, not an
          // incident. No receipt id is documented for this
          // endpoint, so none is collected.
          sent += 1;
          continue;
        }
        const failed: SquadcastFailedRecord = {
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
        failedRecords.push(toSquadcastFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new SquadcastSinkError(
        `squadcast-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent };
  }
}

/**
 * Convert a client throw into a failed message: a codeless
 * transport failure (`TRANSPORT_ERROR`, retryable — the SQS
 * no-status rule). A retry reuses the same event id, so it
 * lands on the open incident rather than creating a second
 * one (see the module header).
 */
function toSquadcastFailedRecord(err: unknown, index: number): SquadcastFailedRecord {
  const failed: SquadcastFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
