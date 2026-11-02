/**
 * PagerTree on-call alert delivery sink (WR-305).
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
 * `alertKey`/`priority` envelope, the Zenduty sink
 * (WR-299) posts an alert to a Zenduty Generic
 * Integration webhook URL with an `alert_type`/`message`/
 * `summary`/`entity_id`/`payload` envelope, the
 * Squadcast sink (WR-300) posts an incident to a
 * Squadcast Incident Webhook with a `message`/
 * `description`/`status`/`event_id` envelope, the
 * SIGNL4 sink (WR-301) posts an alert to a SIGNL4 team
 * webhook with a `Title`/`Message`/`X-S4-ExternalID`/
 * `X-S4-Status`/`X-S4-SourceSystem` envelope, the
 * Grafana OnCall sink (WR-302) posts an alert to a
 * Grafana OnCall webhook integration with a `title`/
 * `message`/`state`/`ruleId` envelope, the Spike.sh
 * sink (WR-303) posts an incident to a Spike.sh webhook
 * integration with a `title`/`body`/`severity`/`priority`/
 * `status` envelope, and the Splunk On-Call sink
 * (WR-304) posts an alert to a Splunk On-Call REST
 * Generic integration with a `message_type`/`entity_id`/
 * `entity_display_name`/`state_message`/`monitoring_tool`
 * envelope, this sink posts an alert to a PagerTree
 * webhook integration: one event is sent as one POST
 * that PagerTree's webhook adapter turns into an alert,
 * and PagerTree — not the relay — owns the incident, the
 * escalation, the notification, and the incident
 * lifecycle.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a PagerTree
 * server. The sink owns the relay-side concerns — the
 * event type, the id, the title, the description, the
 * urgency, the resolve signal, the payload-inclusion
 * policy, the per-message failure mapping — and the
 * injected client owns the wire protocol, including
 * the POST call, the webhook integration URL, and the
 * status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { headers: { "Content-Type": "application/json" },
 *     body: "{\"event_type\":\"create\",\"id\":\"<key>\",\"title\":\"<subject>\",\"description\":\"key=<key>; traceId=<traceId>\",\"urgency\":\"critical\"}" }
 *
 * The client POSTs to the webhook integration URL it
 * alone holds — `https://api.pagertree.com/integration/
 * <integration_id>` — sending `body` verbatim as the
 * request body (JSON) and sending `headers` verbatim as
 * the request headers. Ten things about this shape are
 * deliberate, and all follow the sibling sinks or the
 * backlog pins:
 *
 * - The webhook integration URL — integration_id in the
 *   URL path — is held by the client alone. The sink
 *   never receives the integration id, never places it
 *   in the request, and never logs it: the sink config
 *   has no `apiKey` field at all, and the handed request
 *   carries no URL at all (like the ilert, Zenduty,
 *   Squadcast, SIGNL4, Grafana OnCall, Spike.sh, and
 *   Splunk On-Call sinks, unlike the Opsgenie sink,
 *   whose handed request carries the bare endpoint URL),
 *   so there is nothing in it for a log line or a retry
 *   queue to leak — and the id is never persisted by the
 *   sink. The id rides in the URL path (like the ilert
 *   sink's alert-source URL and the Splunk On-Call
 *   sink's api_key/routing_key path segments, unlike the
 *   Opsgenie sink's `Authorization: GenieKey <key>`
 *   header and the PagerDuty sink's `routing_key` inside
 *   the body), so the sink hands the client the bare
 *   `Content-Type` header and the body and the client
 *   posts to the integration URL it was configured
 *   with: the sink's request never contains a key, a
 *   placeholder, or anything that looks like one, and
 *   there is no `Authorization` header. This is the
 *   PagerTree form of the MagicBell rule (whose Project
 *   JWT the client alone holds as an `Authorization:
 *   Bearer` header), with PagerTree's own credential
 *   source: the integration id of a webhook integration,
 *   verified against the current docs (pagertree.com/
 *   docs/integrations, re-checked 2026-11-02 — the
 *   webhook example log shows the request URL
 *   `https://api.pagertree.com/integration/int_xxxx`,
 *   and the webhook example payload shows
 *   `{"event_type": "create", "Id": "example-id-123",
 *   "Title": "Example Incident Title", "Description":
 *   "Example Incident Description"}`).
 * - The endpoint is the webhook integration the backlog
 *   pins: `POST https://api.pagertree.com/integration/
 *   <integration_id>`. The client substitutes the path
 *   segment from the integration URL it holds; the sink
 *   never builds the URL, so the sink cannot leak, log,
 *   or misroute the id.
 * - `event_type` is mandatory, so it is config-held
 *   with a per-record override, defaulting to
 *   `create`. It is one of `create`, `update`,
 *   `acknowledge`, and `resolve` — the four actions the
 *   webhook adapter's `adapter_action` pins
 *   (PagerTree/pager_tree-integrations,
 *   `app/models/pager_tree/integrations/webhook/v3.rb`,
 *   re-checked 2026-11-02: `case
 *   _adapter_incoming_request_params.dig("event_type")
 *   .to_s.downcase.strip` with `when "create", :create`,
 *   `when "update", :update`, `when "acknowledge",
 *   :acknowledge`, `when "resolve", :resolve`, `else,
 *   :other`). Any other value maps to `:other` on the
 *   adapter side and creates no alert — so an illegal
 *   value fails at construction (config) or at record
 *   validation (per-record) with a `RangeError`: a typo
 *   must fail fast, never reach PagerTree as an event
 *   type that silently creates nothing. Unlike the
 *   Splunk On-Call sink's case-sensitive `message_type`,
 *   the adapter lowercases and strips the value before
 *   matching, so the sink normalizes the value to
 *   lowercase (and trims it) instead of rejecting mixed
 *   case — `"Create"` and `"CREATE"` both send
 *   `"create"`, mirroring the downstream's own
 *   tolerance rather than inventing a stricter rule.
 * - `id` is the event's key, sent when one exists and
 *   omitted entirely when the event carries none: the
 *   adapter uses it as the alert's `thirdparty_id`
 *   (`adapter_thirdparty_id` is `params.dig("id") ||
 *   SecureRandom.uuid`), and a later create with the
 *   same thirdparty_id only increments the dedup count
 *   on the open alert instead of creating a new one
 *   (the official Alert Aggregation rule, re-checked
 *   2026-11-02 on pagertree.com/docs/integrations: a
 *   create with the same thirdparty_id while the alert
 *   is queued, open, acknowledged, or dropped
 *   increments `dedup_count`). It is sent verbatim,
 *   never truncated: truncating a grouping key would
 *   silently merge distinct incidents.
 * - `title` is mandatory, so it is derived as the first
 *   non-empty value among `subject`, `key`, and
 *   `traceId`, in that order, falling back to the
 *   generic `webhook event`: an alert sink that
 *   silently dropped sourceless events would hide
 *   exactly the deliveries an operator most needs to
 *   see. No truncation is applied: the re-checked
 *   documentation states no title length limit for this
 *   endpoint, and inventing one would silently cut an
 *   operator's alert text.
 * - `description` is mandatory, so it is derived from
 *   the event's own identifiers — `key=<key>;
 *   traceId=<traceId>` when present (the ilert `details`
 *   form, following the SIGNL4 `Message` shape) — and
 *   falls back to the derived title text when the event
 *   carries no identifiers, so it is never empty: a
 *   stateless incident would hide exactly the context
 *   an operator most needs to see. No truncation is
 *   applied to the identifiers or the fallback text: the
 *   re-checked documentation states no description
 *   length limit for this endpoint.
 * - `urgency` is one of `low`, `medium`, `high`, and
 *   `critical` — the four values the re-checked docs pin
 *   (pagertree.com/docs/alerts: "low|medium|high|
 *   critical"). It is config-held with a per-record
 *   override, defaulting to `critical` for a firing
 *   alert. The adapter matches it with the regex
 *   `/(?<urgency>low|medium|high|critical)/` against the
 *   downcased, stripped value and returns nil when
 *   nothing matches, in which case PagerTree falls back
 *   to the integration's default urgency — urgency is a
 *   required option when the integration is created, so
 *   the fallback always exists. The sink mirrors the
 *   adapter's case-insensitivity by normalizing the
 *   value to lowercase (and trimming it) instead of
 *   rejecting mixed case, but an illegal value still
 *   fails at construction (config) or at record
 *   validation (per-record) with a `RangeError`: a typo
 *   must fail fast, never reach PagerTree as an urgency
 *   the adapter silently drops in favour of the
 *   integration default. The sink always sends a valid
 *   urgency, so the adapter-side fallback is never
 *   exercised by this sink — it is documented here
 *   because the adapter source pins it, not because the
 *   sink relies on it.
 * - `status` is the resolve signal, carried by
 *   `event_type` itself rather than by a second field.
 *   There is no separate status knob: the event type
 *   is the lifecycle. A firing alert sends `event_type`
 *   exactly as derived (`create` / `update` /
 *   `acknowledge`). A resolved record sends
 *   `event_type` exactly `"resolve"` with the same `id`
 *   the incident was created with (the adapter maps
 *   `"resolve"` to `:resolve`, and the docs' Alert
 *   Aggregation examples show the resolve carrying the
 *   same thirdparty_id as the create). The sink still
 *   sends the derived title, description, and urgency
 *   on a resolve, keeping one uniform envelope instead
 *   of a second, resolve-only shape; the description is
 *   never empty either way (see above). A resolve
 *   requires an `id`: a keyless resolve fails closed
 *   with a `RangeError` before any POST is made (the
 *   ilert ACCEPT/RESOLVE and Squadcast rules) — without
 *   an id the adapter mints a fresh UUID as the
 *   thirdparty_id, so the resolve would silently land
 *   on no open alert.
 * - `tags`, `meta`, and `dedup_keys` are out of scope
 *   for this sink: the adapter reads all three
 *   (`_tags`, `_meta`, `_dedup_keys` in v3.rb — and
 *   `meta` carries `incident`, `incident_message`, and
 *   `incident_severity`, which the adapter strips out
 *   of `meta` before storing it), but the backlog pins
 *   none of them, and the relay's record carries no tag
 *   list, no meta map, and no dedup-key list — so the
 *   sink never sends any of them, and never sends
 *   `meta`'s `incident` / `incident_message` /
 *   `incident_severity` either. The adapter's
 *   `capture_additional_data` option is likewise not
 *   modelled: extra body keys are not sent, so nothing
 *   else can leak into the alert as additional data.
 * - `payload` carries only the event's own identifiers
 *   by default — `key` and `traceId` when present,
 *   nothing else — so the incident's description stays
 *   identifiers, never event body: here that means the
 *   `description` carries the identifiers only (see
 *   above). Under the `includePayload` opt-in the event
 *   body is appended to the `description` after the
 *   identifiers (or after the title fallback, when the
 *   event carries no identifiers), truncated to
 *   `payloadMaxChars` characters (default 2000). No
 *   `Idempotency-Key` header is sent: the reference
 *   documents no idempotency key for this endpoint, and
 *   the id already gives a retry its grouping key (see
 *   above) — a retry after a transport failure reuses
 *   the same id, so it lands on the open alert rather
 *   than creating a second one.
 *
 * Acceptance is decided by the HTTP status alone, and
 * the success rule is tentatively any 2xx: the
 * re-checked references pin the endpoint, the URL form,
 * the `event_type`/`id`/`title`/`description`/`urgency`
 * body, the four event_type values, the same-
 * thirdparty_id dedup rule, the resolve-with-same-id
 * rule, and the urgency regex — but none of them states
 * a success status code or a response body, and the
 * webhook adapter source states no HTTP status at all
 * (it transforms the request, it does not answer it), so
 * no per-status success claim can be made from a live
 * page. Any 2xx is therefore treated as acceptance (the
 * slot convention, marked tentative in the code and the
 * README — if the reference later pins a single success
 * status, only `classifyPagerTreeAlertResponse` needs to
 * change). A 2xx is only an acceptance receipt, not an
 * incident: the incident itself is created by PagerTree.
 * No receipt id is collected: the re-checked
 * documentation states no response id for this endpoint,
 * so `send()` returns no ids (inventing one would be
 * worse than returning none).
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over the HTTP status:
 *
 * - a non-2xx POST throws `PagerTreeSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says PagerTree
 *   could not accept the alert right now, not that the
 *   payload is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400 (the
 *   submitted body is invalid) and 404 (the integration
 *   URL is wrong): retrying them burns the retry budget
 *   for nothing, and rerouting them elsewhere would page
 *   an on-call engineer the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload (a retry after a
 *   transport failure reuses the same id, so it lands on
 *   the open alert rather than creating a second one —
 *   see `id` above);
 * - a missing client throws `PagerTreeSinkConfigError`,
 *   which `classifyFailure` maps to `non_retryable`
 *   (the WR-116 rule).
 *
 * One honesty note on the failure mapping: the
 * re-checked references pin the endpoint, the URL form,
 * the body fields, the event_type values, the
 * same-thirdparty_id dedup rule, the resolve rule, and
 * the urgency values, but they publish no 429 or
 * per-status 4xx mention at all. The 429/5xx-retryable,
 * other-4xx-fail-closed mapping above is therefore the
 * slot convention for the unlisted statuses, not a
 * per-status claim from those pages, and no per-status
 * error code is invented here: the failure record carries
 * `HTTP_<status>` plus whatever free-form error text the
 * client surfaced, and nothing more. A second honesty
 * note, on the success status: no 2xx status is
 * documented for this endpoint by any re-checked source;
 * any 2xx is accepted under the task's tentative 2xx
 * rule, not because any reference pins it — if the
 * reference later pins a single success status, only
 * `classifyPagerTreeAlertResponse` needs to change.
 *
 * Zero new dependencies: the injected client only. (No
 * `node:crypto` import either: with no idempotency key to
 * derive, there is nothing to hash.)
 */

/** Generic title used when an event carries no value for it. */
export const PAGERTREE_FALLBACK_TITLE = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const PAGERTREE_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Content type the client sends with the JSON body. */
export const PAGERTREE_JSON_CONTENT_TYPE = "application/json";

/**
 * Webhook integration URL template, with the segment
 * the client alone holds: `{integration_id}` is the
 * integration's id in the URL path. The client
 * substitutes it from the integration URL it was
 * configured with; the sink never builds this URL, so
 * no id — real or placeholder — ever passes through the
 * sink. Exported so the URL shape is pinned in tests, not
 * so the sink can construct a request URL.
 */
export const PAGERTREE_INTEGRATION_URL_TEMPLATE =
  "https://api.pagertree.com/integration/{integration_id}";

/** Default event type for a firing alert. */
export const PAGERTREE_DEFAULT_EVENT_TYPE = "create";

/** The event types the re-checked adapter pins. */
export const PAGERTREE_EVENT_TYPES = ["create", "update", "acknowledge", "resolve"] as const;

/** One of the event types the re-checked adapter pins. */
export type PagerTreeEventType = (typeof PAGERTREE_EVENT_TYPES)[number];

/** Wire `event_type` sent for a resolved alert (the adapter's `resolve` action). */
export const PAGERTREE_RESOLVED_EVENT_TYPE = "resolve";

/** Default urgency for a firing alert. */
export const PAGERTREE_DEFAULT_URGENCY = "critical";

/** The urgencies the re-checked docs pin. */
export const PAGERTREE_URGENCIES = ["low", "medium", "high", "critical"] as const;

/** One of the urgencies the re-checked docs pin. */
export type PagerTreeUrgency = (typeof PAGERTREE_URGENCIES)[number];

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (JSON) to the webhook integration
 * URL it alone holds
 * (`https://api.pagertree.com/integration/<integration_id>`),
 * sending `headers` verbatim as the request headers.
 * There is deliberately no `url` field here: the URL
 * carries the integration's id in its path, so the sink
 * must never see, build, or hand over a URL — the client
 * posts to the URL it was configured with. No
 * `Authorization` header is sent: the id rides in the
 * URL path, never in a header. No `Idempotency-Key`
 * header is sent: the docs do not verify it for this
 * endpoint, and the id already gives a retry its
 * grouping key (see the module header).
 */
export interface PagerTreeAlertPostRequest {
  /**
   * Request headers, sent verbatim:
   * `{ "Content-Type": "application/json" }`. There is
   * deliberately no `url` field: the webhook integration
   * URL (integration_id in the path) is held by the
   * client alone, never by the sink, and there is no
   * `Authorization` header and no `Idempotency-Key`
   * header.
   */
  headers: Record<string, string>;
  /**
   * The JSON request body, serialized:
   * `{"event_type":"create","id":"<key>","title":"<subject>","description":"key=<key>; traceId=<traceId>","urgency":"critical"}`
   * (`id` is omitted when the event carries no key;
   * `description` falls back to the title text when the
   * event carries no identifiers, so it is never empty;
   * the event body is appended to it only under the
   * `includePayload` opt-in; a resolved alert sends
   * `event_type` exactly `"resolve"`). No credential ever
   * enters the body.
   */
  body: string;
}

/**
 * The result of one POST, as reported by the injected
 * client. The HTTP status decides acceptance: any 2xx
 * means PagerTree accepted the alert (tentative —
 * see the module header: no re-checked source states a
 * success status code). The error text, when the client
 * surfaced one, rides on the failure record; no
 * per-status error code is claimed from the reference.
 * No receipt id is collected: the re-checked
 * documentation states no response id for this endpoint.
 */
export interface PagerTreeAlertPostResponse {
  /** The HTTP status of the POST (e.g. 200, 400, 404, 429, 500). */
  status: number;
  /** Free-form error text from the error body, when the client surfaced one. */
  errorMessage?: string;
}

/**
 * The injected PagerTree alert client. Any client adapter
 * implements this one method; it returns the POST's status —
 * a throw is a codeless transport failure, retryable. The
 * client is expected to POST one alert per call, sending
 * `body` verbatim as the request body (JSON), sending
 * `headers` verbatim as the request headers, and posting
 * to the webhook integration URL it alone holds
 * (`https://api.pagertree.com/integration/<integration_id>`)
 * — the sink never sees that URL.
 */
export interface PagerTreeAlertClient {
  post(request: PagerTreeAlertPostRequest): Promise<PagerTreeAlertPostResponse>;
}

/**
 * Configuration for one PagerTree sink. The client is
 * injected: without one, `send()` throws
 * `PagerTreeSinkConfigError` (dry runs excepted — they need
 * no client at all). The integration's id is deliberately
 * absent from this config: the client alone holds the
 * webhook integration URL (id in the path), and it is never
 * persisted by the sink.
 */
export interface PagerTreeSinkConfig {
  /**
   * The PagerTree alert client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `PagerTreeAlertClient` and alone holds the
   * webhook integration URL. Required for real sends; a missing
   * client is a config error, not a silent no-op.
   */
  client?: PagerTreeAlertClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }`
   * and performs zero client I/O — no POST call, no stat
   * changes. Messages are still validated (including
   * event type, urgency derivation, and the keyless-
   * resolve rule), so a dry run catches a malformed
   * record before it reaches production. Mirrors the
   * `dryRun` convention of the S3 offloaders. The client
   * is not required in dry-run mode, mirroring the
   * sibling sinks' dry-run exemption; the rest of the
   * config must still be valid — a dry run against a sink
   * with a bad event type would rehearse a request that
   * could never send.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the request body's
   * `description` appends the event body verbatim as a
   * JSON string, truncated to `payloadMaxChars`
   * characters (see below), after the identifiers (or
   * after the title fallback, when the event carries no
   * identifiers). When `false` or absent,
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
   * Default event type: one of create/update/acknowledge/
   * resolve, default create. Config-held, overridable per
   * record (see `PagerTreeRecord.eventType`). A resolved
   * alert is simply an alert whose effective event type
   * is `"resolve"`, sent with the same id the incident
   * was created with — and a keyless resolve fails closed
   * before any POST is made. Must be one of the four
   * values when set (case-insensitive — the value is
   * normalized to lowercase, mirroring the adapter).
   */
  eventType?: PagerTreeEventType;
  /**
   * Default urgency: one of low/medium/high/critical,
   * default critical. Config-held, overridable per record
   * (see `PagerTreeRecord.urgency`). Must be one of the
   * four values when set (case-insensitive — the value is
   * normalized to lowercase, mirroring the adapter's
   * case-insensitive regex match).
   */
  urgency?: PagerTreeUrgency;
}

/** One event to alert about. */
export interface PagerTreeRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Content-derivation source, first priority: the event's
   * subject, when set and non-empty. The alert's title.
   */
  subject?: string;
  /**
   * Content-derivation source, second priority: the event's key
   * (e.g. aggregate id). The alert's id — the adapter's
   * thirdparty_id, the official dedup key — and a
   * `description` identifier, when set. A resolve
   * without a key fails closed before any POST is made:
   * without an id the adapter mints a fresh UUID, so the
   * resolve would silently land on no open alert.
   */
  key?: string;
  /**
   * Content-derivation source, last priority: the trace id.
   * Also a `description` identifier, when set. It is
   * never an id: only the event key is.
   */
  traceId?: string;
  /**
   * Per-record event type override: one of
   * create/update/acknowledge/resolve. When absent, the
   * config's `eventType` applies, defaulting to create.
   * A `"resolve"` alert is sent with the same id the
   * incident was created with. A keyless resolve fails
   * closed with a `RangeError` before any POST is made
   * (see the module header).
   */
  eventType?: PagerTreeEventType;
  /**
   * Per-record urgency override: one of
   * low/medium/high/critical. When absent, the config's
   * `urgency` applies, defaulting to critical. An illegal
   * value fails record validation with a `RangeError`.
   */
  urgency?: PagerTreeUrgency;
}

/** One failed message, with its retry lane already mapped. */
export interface PagerTreeFailedRecord {
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
   * (400 invalid body, 404 wrong integration URL, and the
   * rest). No per-status error code is claimed from the
   * reference (see the module header).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface PagerTreeSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-305). */
export interface PagerTreeSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for PagerTree send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already received on PagerTree's server and are *not* in
 * `failedRecords`.
 */
export class PagerTreeSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: PagerTreeFailedRecord[];
  constructor(message: string, failedRecords: PagerTreeFailedRecord[]) {
    super(message);
    this.name = "PagerTreeSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class PagerTreeSinkConfigError extends PagerTreeSinkError {
  constructor(reason: string) {
    super(`pagertree-sink: ${reason}`, []);
    this.name = "PagerTreeSinkConfigError";
  }
}

/**
 * Normalize one event-type value to the lowercase form the
 * adapter matches (the adapter lowercases and strips before
 * matching, so mixed case and surrounding whitespace are
 * tolerated here too). Throws `RangeError` on a value that
 * is not one of create/update/acknowledge/resolve — the
 * adapter would map it to `:other` and create no alert, so
 * a typo must fail fast, never reach PagerTree.
 */
function normalizePagerTreeEventType(value: unknown, label: string): PagerTreeEventType {
  if (typeof value !== "string") {
    throw new RangeError(`${label} must be one of create, update, acknowledge, resolve`);
  }
  const normalized = value.toLowerCase().trim();
  if (!(PAGERTREE_EVENT_TYPES as readonly string[]).includes(normalized)) {
    throw new RangeError(`${label} must be one of create, update, acknowledge, resolve`);
  }
  return normalized as PagerTreeEventType;
}

/**
 * Normalize one urgency value to the lowercase form the
 * adapter's regex matches (the adapter matches
 * case-insensitively, so mixed case and surrounding
 * whitespace are tolerated here too). Throws `RangeError`
 * on a value that is not one of low/medium/high/critical
 * — the adapter would return nil and fall back to the
 * integration default, so a typo must fail fast, never
 * reach PagerTree as an urgency the adapter silently
 * drops.
 */
function normalizePagerTreeUrgency(value: unknown, label: string): PagerTreeUrgency {
  if (typeof value !== "string") {
    throw new RangeError(`${label} must be one of low, medium, high, critical`);
  }
  const normalized = value.toLowerCase().trim();
  if (!(PAGERTREE_URGENCIES as readonly string[]).includes(normalized)) {
    throw new RangeError(`${label} must be one of low, medium, high, critical`);
  }
  return normalized as PagerTreeUrgency;
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery.
 * The event type, when set, must be one of
 * create/update/acknowledge/resolve; the urgency, when set,
 * must be one of low/medium/high/critical (both
 * case-insensitive — the values are normalized to
 * lowercase, mirroring the adapter). There is deliberately
 * no `apiKey` field to validate: the client alone holds the
 * webhook integration URL.
 */
export function assertValidPagerTreeSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is PagerTreeSinkConfig {
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
  if (c.eventType !== undefined) {
    normalizePagerTreeEventType(c.eventType, at("`eventType`"));
  }
  if (c.urgency !== undefined) {
    normalizePagerTreeUrgency(c.urgency, at("`urgency`"));
  }
}

/**
 * Derive one record's title: the first non-empty value
 * among `subject`, `key`, and `traceId`, in that order.
 * Falls back to the generic `webhook event` title when the
 * record carries none — an alert sink must not silently
 * drop sourceless events. No truncation is applied: the
 * re-checked documentation states no title length limit
 * for this endpoint.
 */
export function resolvePagerTreeTitle(record: PagerTreeRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return PAGERTREE_FALLBACK_TITLE;
}

/**
 * Resolve the event type: the record's override when set,
 * else the config-held value, else `create`. The value is
 * normalized to lowercase (the adapter lowercases before
 * matching), and an illegal value throws `RangeError` —
 * the adapter would map it to `:other` and create no
 * alert.
 */
export function resolvePagerTreeEventType(
  record: PagerTreeRecord,
  config: Pick<PagerTreeSinkConfig, "eventType">
): PagerTreeEventType {
  return normalizePagerTreeEventType(
    record.eventType ?? config.eventType ?? PAGERTREE_DEFAULT_EVENT_TYPE,
    "PagerTree eventType"
  );
}

/**
 * Resolve the urgency: the record's override when set,
 * else the config-held value, else `critical`. The value
 * is normalized to lowercase (the adapter matches its
 * urgency regex case-insensitively), and an illegal value
 * throws `RangeError` — the adapter would return nil and
 * fall back to the integration default.
 */
export function resolvePagerTreeUrgency(
  record: PagerTreeRecord,
  config: Pick<PagerTreeSinkConfig, "urgency">
): PagerTreeUrgency {
  return normalizePagerTreeUrgency(
    record.urgency ?? config.urgency ?? PAGERTREE_DEFAULT_URGENCY,
    "PagerTree urgency"
  );
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood an incident.
 */
export function truncatePagerTreePayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's `description`: only the event's own
 * identifiers — `key=<key>` and `traceId=<traceId>`
 * when present, joined with `"; "` — and, when the event
 * carries no identifiers, the derived title text, so the
 * description is never empty. Under the `includePayload`
 * opt-in the event body is appended after the identifiers
 * (or after the title fallback), truncated to
 * `payloadMaxChars` (default 2000). The description itself
 * is never truncated: the re-checked docs state no
 * description length limit.
 */
export function resolvePagerTreeDescription(
  record: PagerTreeRecord,
  config: Pick<PagerTreeSinkConfig, "includePayload" | "payloadMaxChars">
): string {
  const parts: string[] = [];
  if (record.key !== undefined && record.key !== "") {
    parts.push(`key=${record.key}`);
  }
  if (record.traceId !== undefined && record.traceId !== "") {
    parts.push(`traceId=${record.traceId}`);
  }
  const base = parts.length > 0 ? parts.join("; ") : resolvePagerTreeTitle(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? PAGERTREE_DEFAULT_PAYLOAD_MAX_CHARS;
    const payload = truncatePagerTreePayload(record.body, limit);
    return `${base}\n\n${payload}`;
  }
  return base;
}

/**
 * Build one record's serialized JSON body: `event_type`
 * (the derived event type — create/update/acknowledge, or
 * exactly `"resolve"` for a resolved alert), `id` (the
 * event's key, sent only when one exists — the adapter's
 * thirdparty_id, the official dedup key, sent verbatim,
 * never truncated), `title` (the derived title, never
 * truncated — the re-checked docs state no length limit),
 * `description` (only the `key`/`traceId` identifiers,
 * falling back to the title text when the event carries
 * neither, so never empty; the event body appended only
 * under the `includePayload` opt-in), and `urgency` (the
 * derived urgency, always a valid lowercase value — the
 * adapter falls back to the integration default when the
 * field is absent or invalid, a path this sink never
 * takes). No `tags`, `meta`, or `dedup_keys` are sent:
 * they are out of scope for this sink (see the module
 * header). No credential ever enters the body — the client
 * alone holds the webhook integration URL (integration_id
 * in the path).
 */
export function buildPagerTreeAlertBody(
  record: PagerTreeRecord,
  config: Pick<PagerTreeSinkConfig, "includePayload" | "payloadMaxChars" | "eventType" | "urgency">
): string {
  const alert: {
    event_type: string;
    id?: string;
    title: string;
    description: string;
    urgency: string;
  } = {
    event_type: resolvePagerTreeEventType(record, config),
    title: resolvePagerTreeTitle(record),
    description: resolvePagerTreeDescription(record, config),
    urgency: resolvePagerTreeUrgency(record, config),
  };
  if (record.key !== undefined && record.key !== "") {
    alert.id = record.key;
  }
  return JSON.stringify(alert);
}

/**
 * Validate one record. Throws `RangeError` on an empty
 * body string — even without the opt-in, the body is the
 * record's payload, and an empty record is a caller bug
 * that must fail closed, never alert as an empty message.
 * A bad per-record `eventType` or `urgency` value fails
 * here too (the config-level check in
 * `assertValidPagerTreeSinkConfig` only covers the config
 * defaults). A keyless resolve fails closed here: without
 * an id the adapter mints a fresh UUID as the
 * thirdparty_id, so the resolve would silently land on no
 * open alert (the ilert ACCEPT/RESOLVE and Squadcast
 * rules) — the effective event type is the record's
 * override else the config-held value, defaulting to
 * create.
 */
export function resolvePagerTreeRecord(
  record: PagerTreeRecord,
  index: number,
  config: Pick<PagerTreeSinkConfig, "eventType" | "urgency">
): { index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`pagertree-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  // Validate the per-record event type and urgency (each
  // throws `RangeError` on an illegal value).
  resolvePagerTreeEventType(record, config);
  resolvePagerTreeUrgency(record, config);
  if (
    resolvePagerTreeEventType(record, config) === PAGERTREE_RESOLVED_EVENT_TYPE &&
    (record.key === undefined || record.key === "")
  ) {
    throw new RangeError(`pagertree-sink: record ${index} a resolved alert requires \`key\` (id)`);
  }
  return { index };
}

/**
 * Map one PagerTree POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says PagerTree could not
 * accept the alert right now, not that the payload is
 * poison. Every other non-2xx status (400 invalid body,
 * 404 wrong integration URL, and the rest) is a fail-closed
 * message: an invalid body will never become valid on
 * retry. Honesty note: the re-checked references publish
 * no 429 or per-status 4xx mention at all, so this mapping
 * is the slot convention for the unlisted statuses, not a
 * per-status claim from those pages — and no per-status
 * error code is invented here. Callers only pass non-2xx
 * statuses here; any 2xx is acceptance on its own (see
 * `classifyPagerTreeAlertResponse`).
 */
export function classifyPagerTreeRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * The verdict on one alert POST: either an acceptance,
 * or a failure with its error code and retry lane.
 */
export type PagerTreeAlertVerdict =
  | { accepted: true }
  | { accepted: false; errorCode: string; retryable: boolean; errorMessage?: string };

/**
 * Decide one alert POST's verdict from the response the
 * client reported. Any 2xx is acceptance — the tentative
 * rule (see the module header: no re-checked source states
 * a success status code, and the webhook adapter source
 * states no HTTP status at all). A 2xx is only an
 * acceptance receipt, not an incident: the incident itself
 * is created by PagerTree. No receipt id is required or
 * collected as an acceptance condition: the re-checked
 * documentation states no response id for this endpoint,
 * so `send()` returns no ids. Any non-2xx status is a
 * failure with an `HTTP_<status>` code and the WR-210
 * lane; the error text rides on the failure record when
 * the client surfaced one. No per-status error code is
 * claimed from the reference. If the reference later pins
 * a single success status, only this function needs to
 * change.
 */
export function classifyPagerTreeAlertResponse(
  response: PagerTreeAlertPostResponse
): PagerTreeAlertVerdict {
  if (response.status >= 200 && response.status < 300) {
    return { accepted: true };
  }
  const verdict: PagerTreeAlertVerdict = {
    accepted: false,
    errorCode: `HTTP_${response.status}`,
    retryable: classifyPagerTreeRecordFailure(response.status),
  };
  if (response.errorMessage !== undefined && response.errorMessage !== "") {
    verdict.errorMessage = response.errorMessage;
  }
  return verdict;
}

/**
 * PagerTree sink (WR-305). One alert is sent per record; the
 * caller owns retry / dead-letter policy around `send()`
 * — this class performs one POST attempt per message
 * through the injected client and reports its outcome.
 * Failures throw `PagerTreeSinkError` carrying exactly the
 * failed messages with their retry lanes. The sink keeps
 * no per-incident state: a later `resolve` carrying the
 * same key is sent exactly like any other alert, and
 * PagerTree resolves the open alert by thirdparty_id —
 * the sink does not try to track that.
 */
export class PagerTreeSink {
  private readonly cfg: PagerTreeSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: PagerTreeSinkConfig) {
    assertValidPagerTreeSinkConfig(config, "PagerTreeSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): PagerTreeSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send the alerts, in input order. Throws
   * `PagerTreeSinkConfigError` when no client was injected,
   * and `PagerTreeSinkError` when any message fails
   * (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: PagerTreeRecord[]): Promise<PagerTreeSendResult> {
    const resolved = records.map((r, i) => resolvePagerTreeRecord(r, i, this.cfg));
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
      throw new PagerTreeSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const failedRecords: PagerTreeFailedRecord[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          headers: {
            "Content-Type": PAGERTREE_JSON_CONTENT_TYPE,
          },
          body: buildPagerTreeAlertBody(records[i], this.cfg),
        });
        const verdict = classifyPagerTreeAlertResponse(response);
        if (verdict.accepted) {
          // Any 2xx is acceptance on its own (tentative —
          // see the module header): the status is the
          // acceptance receipt, and the incident itself is
          // created by PagerTree — the response is an
          // acceptance receipt, not an incident. No receipt id
          // is claimed: the re-checked documentation states
          // no response id for this endpoint.
          sent += 1;
          continue;
        }
        const failed: PagerTreeFailedRecord = {
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
        failedRecords.push(toPagerTreeFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new PagerTreeSinkError(
        `pagertree-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent };
  }
}

/**
 * Convert a client throw into a failed message: a codeless
 * transport failure (`TRANSPORT_ERROR`, retryable — the SQS
 * no-status rule). A retry reuses the same id, so it lands
 * on the open alert rather than creating a second one (see
 * the module header).
 */
function toPagerTreeFailedRecord(err: unknown, index: number): PagerTreeFailedRecord {
  const failed: PagerTreeFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
