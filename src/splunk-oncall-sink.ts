/**
 * Splunk On-Call (VictorOps) on-call alert delivery sink (WR-304).
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
 * `message`/`state`/`ruleId` envelope, and the Spike.sh
 * sink (WR-303) posts an incident to a Spike.sh webhook
 * integration with a `title`/`body`/`severity`/`priority`/
 * `status` envelope, this sink posts an alert to a Splunk
 * On-Call (formerly VictorOps) REST Generic integration:
 * one event is sent as one POST that Splunk On-Call
 * routes into the team behind the integration's routing
 * key, and Splunk On-Call — not the relay — owns the
 * incident, the escalation, the notification, and the
 * incident lifecycle.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Splunk
 * On-Call server. The sink owns the relay-side concerns — the
 * message type, the entity id, the display name, the state
 * message, the monitoring tool, the resolve signal, the
 * payload-inclusion policy, the per-message failure mapping —
 * and the injected client owns the wire protocol, including
 * the POST call, the REST Generic integration URL, and the
 * status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { headers: { "Content-Type": "application/json" },
 *     body: "{\"message_type\":\"CRITICAL\",\"entity_id\":\"<key>\",\"entity_display_name\":\"<subject>\",\"state_message\":\"key=<key>; traceId=<traceId>\",\"monitoring_tool\":\"webhook-relay\"}" }
 *
 * The client POSTs to the REST Generic integration URL it
 * alone holds — `https://alert.victorops.com/integrations/
 * generic/20131114/alert/<api_key>/<routing_key>` — sending
 * `body` verbatim as the request body (JSON) and sending
 * `headers` verbatim as the request headers. Nine things
 * about this shape are deliberate, and all follow the
 * sibling sinks or the backlog pins:
 *
 * - The REST Generic integration URL — api_key and
 *   routing_key both in the URL path — is held by the
 *   client alone. The sink never receives either key,
 *   never places either in the request, and never logs
 *   either: the sink config has no `apiKey` or
 *   `routingKey` field at all, and the handed request
 *   carries no URL at all (like the ilert, Zenduty,
 *   Squadcast, SIGNL4, Grafana OnCall, and Spike.sh
 *   sinks, unlike the Opsgenie sink, whose handed
 *   request carries the bare endpoint URL), so there is
 *   nothing in it for a log line or a retry queue to
 *   leak — and neither key is ever persisted by the
 *   sink. Both keys ride in the URL path (like the
 *   ilert sink's alert-source URL and the Zenduty sink's
 *   Generic Integration webhook URL, unlike the Opsgenie
 *   sink's `Authorization: GenieKey <key>` header and the
 *   PagerDuty sink's `routing_key` inside the body), so
 *   the sink hands the client the bare `Content-Type`
 *   header and the body and the client posts to the
 *   integration URL it was configured with: the sink's
 *   request never contains a key, a placeholder, or
 *   anything that looks like one, and there is no
 *   `Authorization` header. This is the Splunk On-Call
 *   form of the MagicBell rule (whose Project JWT the
 *   client alone holds as an `Authorization: Bearer`
 *   header), with Splunk On-Call's own credential source:
 *   the api_key and routing_key of a REST Generic
 *   integration, verified against the current docs (the
 *   Cisco Splunk Enterprise integration doc, the
 *   Logz.io VictorOps integration guides, and the
 *   Backstage splunk-on-call plugin docs, re-checked
 *   2026-11-02 — request URL
 *   `https://alert.victorops.com/integrations/generic/
 *   20131114/alert/<api_key>/<routing_key>`, where
 *   `20131114` is a fixed version segment of the
 *   endpoint, not a date the caller supplies).
 * - The endpoint is the REST Generic integration the
 *   backlog pins: `POST https://alert.victorops.com/
 *   integrations/generic/20131114/alert/<api_key>/
 *   <routing_key>`. The integration is enabled inside
 *   the Splunk On-Call portal at Integrations > 3rd
 *   Party Integrations > REST – Generic, which is where
 *   the URL is copied from; the routing_key decides
 *   which team / on-call group the incident routes to.
 *   The client substitutes both path segments from the
 *   integration URL it holds; the sink never builds the
 *   URL, so the sink cannot leak, log, or misroute
 *   either key.
 * - `message_type` is mandatory, so it is config-held
 *   with a per-record override, defaulting to
 *   `CRITICAL`. It is one of `CRITICAL`, `WARNING`,
 *   and `INFO` (the three firing values the re-checked
 *   docs pin — the Pulumi VictorOpsAlertNotifier values
 *   and the Cisco integration doc agree). An illegal
 *   value fails at construction (config) or at record
 *   validation (per-record) with a `RangeError` — a typo
 *   must fail fast, never reach Splunk On-Call as an
 *   invented message type.
 * - `entity_id` is the event's key, sent when one
 *   exists and omitted entirely when the event carries
 *   none: it is the official dedup / correlation key —
 *   a later event with the same entity_id is folded
 *   into the same incident rather than opening a new
 *   one (the Logz.io integration guide states every
 *   field but `message_type` is optional, and names
 *   entity_id the de-duplication key). It is sent
 *   verbatim, never truncated: truncating a grouping
 *   key would silently merge distinct incidents.
 * - `entity_display_name` is mandatory, so it is
 *   derived as the first non-empty value among
 *   `subject`, `key`, and `traceId`, in that order,
 *   falling back to the generic `webhook event`: an
 *   alert sink that silently dropped sourceless events
 *   would hide exactly the deliveries an operator most
 *   needs to see. No truncation is applied: the
 *   re-checked documentation states no display-name
 *   length limit for this endpoint, and inventing one
 *   would silently cut an operator's alert text.
 * - `state_message` is mandatory, so it is derived from
 *   the event's own identifiers — `key=<key>;
 *   traceId=<traceId>` when present (the ilert `details`
 *   form, following the SIGNL4 `Message` shape) — and
 *   falls back to the derived display-name text when the
 *   event carries no identifiers, so it is never empty:
 *   a stateless incident would hide exactly the context
 *   an operator most needs to see. No truncation is
 *   applied to the identifiers or the fallback text: the
 *   re-checked documentation states no state-message
 *   length limit for this endpoint.
 * - `monitoring_tool` is fixed to `"webhook-relay"`,
 *   following the Opsgenie `source` and SIGNL4
 *   `X-S4-SourceSystem` precedents: the field names the
 *   system that raised the alert, and the relay is that
 *   system. It is not configurable — a caller that could
 *   rename the monitoring tool could impersonate another
 *   integration's alerts.
 * - `status` is the resolve signal, carried by
 *   `message_type` itself rather than by a second
 *   field. It is config-held with a per-record override,
 *   defaulting to firing — and a firing alert sends
 *   `message_type` exactly as derived (`CRITICAL` /
 *   `WARNING` / `INFO`). A resolved record sends
 *   `message_type` exactly `"RECOVERY"` (the one value
 *   the re-checked docs pin for the reset: the SolarWinds
 *   integration doc — "CRITICAL is Used for the Trigger,
 *   RECOVERY for the Reset" — and the Wavefront official
 *   template's `endedTime` → recovery mapping agree,
 *   and the Splunk Alert Rules Engine doc lists
 *   `CRITICAL/INFO/RECOVERY/WARNING/ACKNOWLEDGE` as the
 *   message_type values). The sink still sends the
 *   derived entity_display_name and state_message on a
 *   resolve, keeping one uniform envelope instead of a
 *   second, resolve-only shape; the state_message is
 *   never empty either way (see above). A resolve
 *   requires an `entity_id`: a keyless resolve fails
 *   closed with a `RangeError` before any POST is made
 *   (the ilert ACCEPT/RESOLVE and Squadcast rules) —
 *   without an entity_id Splunk On-Call cannot associate
 *   the call with an open incident, so the resolve
 *   would silently land nowhere. `ACKNOWLEDGE` /
 *   `ACKNOWLEDGEMENT` is out of scope for this sink:
 *   the re-checked docs list it as a message_type
 *   value, but the backlog pins only the three firing
 *   values plus RECOVERY, and no acknowledgement
 *   lifecycle is modelled here — an acknowledgement
 *   value is a `RangeError` at construction or record
 *   validation, like any other illegal message type.
 * - `payload` carries only the event's own identifiers
 *   by default — `key` and `traceId` when present,
 *   nothing else — so the incident's state_message
 *   stays identifiers, never event body: here that means
 *   the `state_message` carries the identifiers only
 *   (see above). Under the `includePayload` opt-in the
 *   event body is appended to the `state_message` after
 *   the identifiers (or after the display-name fallback,
 *   when the event carries no identifiers), truncated to
 *   `payloadMaxChars` characters (default 2000). No
 *   `Idempotency-Key` header is sent: the reference
 *   documents no idempotency key for this endpoint, and
 *   the entity_id already gives a retry its grouping key
 *   (see above) — a retry after a transport failure
 *   reuses the same entity_id, so it lands on the open
 *   incident rather than creating a second one.
 *
 * Acceptance is decided by the HTTP status alone, and
 * the success rule is tentatively any 2xx: the
 * re-checked references pin the endpoint, the URL form,
 * the `message_type`/`entity_id`/`entity_display_name`/
 * `state_message`/`monitoring_tool` body, the
 * CRITICAL/WARNING/INFO/RECOVERY values, the
 * same-entity_id dedup rule, and the RECOVERY resolve
 * rule — but none of them states a success status code
 * or a response body, and the official Alert Ingestion
 * API reference page (the victorops.force.com knowledge
 * base) is down, so no per-status success claim can be
 * made from a live page. Any 2xx is therefore treated as
 * acceptance (the slot convention, marked tentative in
 * the code and the README — if the reference later pins
 * a single success status, only
 * `classifySplunkOnCallIncidentResponse` needs to
 * change). A 2xx is only an acceptance receipt, not an
 * incident: the incident itself is created by Splunk
 * On-Call. No receipt id is collected: the re-checked
 * documentation states no response id for this endpoint,
 * so `send()` returns no ids (inventing one would be
 * worse than returning none).
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over the HTTP status:
 *
 * - a non-2xx POST throws `SplunkOnCallSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Splunk On-Call
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
 *   transport failure reuses the same entity_id, so it
 *   lands on the open incident rather than creating a
 *   second one — see `entity_id` above);
 * - a missing client throws `SplunkOnCallSinkConfigError`,
 *   which `classifyFailure` maps to `non_retryable`
 *   (the WR-116 rule).
 *
 * One honesty note on the failure mapping: the
 * re-checked references pin the endpoint, the URL form,
 * the body fields, the message_type values, the
 * same-entity_id dedup rule, and the RECOVERY resolve
 * rule, but they publish no 429 or per-status 4xx
 * mention at all. The 429/5xx-retryable, other-4xx-
 * fail-closed mapping above is therefore the slot
 * convention for the unlisted statuses, not a per-status
 * claim from those pages, and no per-status error code is
 * invented here: the failure record carries `HTTP_<status>`
 * plus whatever free-form error text the client surfaced,
 * and nothing more. A second honesty note, on the
 * success status: no 2xx status is documented for this
 * endpoint by any re-checked source; any 2xx is accepted
 * under the task's tentative 2xx rule, not because any
 * reference pins it — if the reference later pins a
 * single success status, only
 * `classifySplunkOnCallIncidentResponse` needs to change.
 *
 * Zero new dependencies: the injected client only. (No
 * `node:crypto` import either: with no idempotency key to
 * derive, there is nothing to hash.)
 */

/** Generic display name used when an event carries no value for it. */
export const SPLUNK_ONCALL_FALLBACK_DISPLAY_NAME = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const SPLUNK_ONCALL_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Content type the client sends with the JSON body. */
export const SPLUNK_ONCALL_JSON_CONTENT_TYPE = "application/json";

/** Monitoring tool name the sink always reports. */
export const SPLUNK_ONCALL_MONITORING_TOOL = "webhook-relay";

/**
 * REST Generic integration URL template, with the segments
 * the client alone holds: `{api_key}` is the integration's
 * REST API key and `{routing_key}` is the routing key that
 * decides which team / on-call group the incident routes
 * to. `20131114` is a fixed version segment of the
 * endpoint, not a date the caller supplies. The client
 * substitutes both segments from the integration URL it
 * was configured with; the sink never builds this URL, so
 * no key — real or placeholder — ever passes through the
 * sink. Exported so the URL shape is pinned in tests, not
 * so the sink can construct a request URL.
 */
export const SPLUNK_ONCALL_REST_GENERIC_URL_TEMPLATE =
  "https://alert.victorops.com/integrations/generic/20131114/alert/{api_key}/{routing_key}";

/** Default message type for a firing alert. */
export const SPLUNK_ONCALL_DEFAULT_MESSAGE_TYPE = "CRITICAL";

/** The firing message types the re-checked docs pin. */
export const SPLUNK_ONCALL_MESSAGE_TYPES = ["CRITICAL", "WARNING", "INFO"] as const;

/** One of the firing message types the re-checked docs pin. */
export type SplunkOnCallMessageType = (typeof SPLUNK_ONCALL_MESSAGE_TYPES)[number];

/** Wire `message_type` sent for a resolved alert (the docs' `RECOVERY` value). */
export const SPLUNK_ONCALL_RESOLVED_MESSAGE_TYPE = "RECOVERY";

/** Default alert status. */
export const SPLUNK_ONCALL_DEFAULT_STATUS = "firing";

/** The alert statuses the sink accepts (firing/resolved). */
export const SPLUNK_ONCALL_STATUSES = ["firing", "resolved"] as const;

/** One of the alert statuses the sink accepts (firing/resolved). */
export type SplunkOnCallAlertStatus = (typeof SPLUNK_ONCALL_STATUSES)[number];

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (JSON) to the REST Generic
 * integration URL it alone holds
 * (`https://alert.victorops.com/integrations/generic/
 * 20131114/alert/<api_key>/<routing_key>`), sending
 * `headers` verbatim as the request headers. There is
 * deliberately no `url` field here: the URL carries the
 * integration's api_key and routing_key in its path, so
 * the sink must never see, build, or hand over a URL —
 * the client posts to the URL it was configured with. No
 * `Authorization` header is sent: both keys ride in the
 * URL path, never in a header. No `Idempotency-Key`
 * header is sent: the docs do not verify it for this
 * endpoint, and the entity_id already gives a retry its
 * grouping key (see the module header).
 */
export interface SplunkOnCallAlertPostRequest {
  /**
   * Request headers, sent verbatim:
   * `{ "Content-Type": "application/json" }`. There is
   * deliberately no `url` field: the REST Generic
   * integration URL (api_key and routing_key in the
   * path) is held by the client alone, never by the
   * sink, and there is no `Authorization` header and no
   * `Idempotency-Key` header.
   */
  headers: Record<string, string>;
  /**
   * The JSON request body, serialized:
   * `{"message_type":"CRITICAL","entity_id":"<key>","entity_display_name":"<subject>","state_message":"key=<key>; traceId=<traceId>","monitoring_tool":"webhook-relay"}`
   * (`entity_id` is omitted when the event carries no
   * key; `state_message` falls back to the display-name
   * text when the event carries no identifiers, so it is
   * never empty; the event body is appended to it only
   * under the `includePayload` opt-in; a resolved alert
   * sends `message_type` exactly `"RECOVERY"`). No
   * credential ever enters the body.
   */
  body: string;
}

/**
 * The result of one POST, as reported by the injected
 * client. The HTTP status decides acceptance: any 2xx
 * means Splunk On-Call accepted the alert (tentative —
 * see the module header: no re-checked source states a
 * success status code). The error text, when the client
 * surfaced one, rides on the failure record; no
 * per-status error code is claimed from the reference.
 * No receipt id is collected: the re-checked
 * documentation states no response id for this endpoint.
 */
export interface SplunkOnCallAlertPostResponse {
  /** The HTTP status of the POST (e.g. 200, 400, 404, 429, 500). */
  status: number;
  /** Free-form error text from the error body, when the client surfaced one. */
  errorMessage?: string;
}

/**
 * The injected Splunk On-Call alert client. Any client adapter
 * implements this one method; it returns the POST's status —
 * a throw is a codeless transport failure, retryable. The
 * client is expected to POST one alert per call, sending
 * `body` verbatim as the request body (JSON), sending
 * `headers` verbatim as the request headers, and posting
 * to the REST Generic integration URL it alone holds
 * (`https://alert.victorops.com/integrations/generic/
 * 20131114/alert/<api_key>/<routing_key>`) — the sink
 * never sees that URL.
 */
export interface SplunkOnCallAlertClient {
  post(request: SplunkOnCallAlertPostRequest): Promise<SplunkOnCallAlertPostResponse>;
}

/**
 * Configuration for one Splunk On-Call sink. The client is
 * injected: without one, `send()` throws
 * `SplunkOnCallSinkConfigError` (dry runs excepted — they need
 * no client at all). The integration's api_key and
 * routing_key are deliberately absent from this config: the
 * client alone holds the REST Generic integration URL (both
 * keys in the path), and neither key is ever persisted by
 * the sink.
 */
export interface SplunkOnCallSinkConfig {
  /**
   * The Splunk On-Call alert client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `SplunkOnCallAlertClient` and alone holds
   * the REST Generic integration URL. Required for real sends; a missing
   * client is a config error, not a silent no-op.
   */
  client?: SplunkOnCallAlertClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }`
   * and performs zero client I/O — no POST call, no stat
   * changes. Messages are still validated (including
   * message type, status derivation, and the keyless-
   * resolve rule), so a dry run catches a malformed
   * record before it reaches production. Mirrors the
   * `dryRun` convention of the S3 offloaders. The client
   * is not required in dry-run mode, mirroring the
   * sibling sinks' dry-run exemption; the rest of the
   * config must still be valid — a dry run against a sink
   * with a bad message type would rehearse a request that
   * could never send.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the request body's
   * `state_message` appends the event body verbatim as a
   * JSON string, truncated to `payloadMaxChars`
   * characters (see below), after the identifiers (or
   * after the display-name fallback, when the event
   * carries no identifiers). When `false` or absent,
   * `state_message` carries the identifiers only — the
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
   * Default alert status: one of firing/resolved, default
   * firing. Config-held, overridable per record (see
   * `SplunkOnCallRecord.status`): the relay does not invent a
   * lifecycle transition it was not told. Must be one of
   * the two values when set. A firing alert sends
   * `message_type` as derived (CRITICAL/WARNING/INFO);
   * a resolved alert sends `message_type` exactly
   * `"RECOVERY"` with the same entity_id the incident was
   * created with — and a keyless resolve fails closed
   * before any POST is made.
   */
  status?: SplunkOnCallAlertStatus;
  /**
   * Default message type: one of CRITICAL/WARNING/INFO,
   * default CRITICAL. Config-held, overridable per record
   * (see `SplunkOnCallRecord.messageType`). A resolved
   * alert ignores this value and sends `message_type`
   * exactly `"RECOVERY"`. Must be one of the three values
   * when set.
   */
  messageType?: SplunkOnCallMessageType;
}

/** One event to alert about. */
export interface SplunkOnCallRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Content-derivation source, first priority: the event's
   * subject, when set and non-empty. The incident's
   * entity_display_name.
   */
  subject?: string;
  /**
   * Content-derivation source, second priority: the event's key
   * (e.g. aggregate id). The incident's entity_id — the
   * official dedup / correlation key — and a
   * `state_message` identifier, when set. A resolve
   * without a key fails closed before any POST is made:
   * without an entity_id Splunk On-Call cannot associate
   * the call with an open incident.
   */
  key?: string;
  /**
   * Content-derivation source, last priority: the trace id.
   * Also a `state_message` identifier, when set. It is
   * never an entity_id: only the event key is.
   */
  traceId?: string;
  /**
   * Per-record alert status override: one of
   * firing/resolved. When absent, the config's `status`
   * applies, defaulting to firing. A firing alert sends
   * `message_type` as derived; a resolved alert sends
   * `message_type` exactly `"RECOVERY"` with the same
   * entity_id the incident was created with. A keyless
   * resolve fails closed with a `RangeError` before any
   * POST is made (see the module header).
   */
  status?: SplunkOnCallAlertStatus;
  /**
   * Per-record message type override: one of
   * CRITICAL/WARNING/INFO. When absent, the config's
   * `messageType` applies, defaulting to CRITICAL. A
   * resolved alert ignores this value and sends
   * `"RECOVERY"`. An illegal value fails record
   * validation with a `RangeError` — `ACKNOWLEDGE` /
   * `ACKNOWLEDGEMENT` is out of scope for this sink
   * (see the module header).
   */
  messageType?: SplunkOnCallMessageType;
}

/** One failed message, with its retry lane already mapped. */
export interface SplunkOnCallFailedRecord {
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
export interface SplunkOnCallSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-304). */
export interface SplunkOnCallSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Splunk On-Call send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already received on Splunk On-Call's server and are *not* in
 * `failedRecords`.
 */
export class SplunkOnCallSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: SplunkOnCallFailedRecord[];
  constructor(message: string, failedRecords: SplunkOnCallFailedRecord[]) {
    super(message);
    this.name = "SplunkOnCallSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class SplunkOnCallSinkConfigError extends SplunkOnCallSinkError {
  constructor(reason: string) {
    super(`splunk-oncall-sink: ${reason}`, []);
    this.name = "SplunkOnCallSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery.
 * The status, when set, must be one of firing/resolved; the
 * message type, when set, must be one of CRITICAL/WARNING/INFO
 * (`ACKNOWLEDGE` / `ACKNOWLEDGEMENT` is out of scope — see the
 * module header). There is deliberately no `apiKey` or
 * `routingKey` field to validate: the client alone holds the
 * REST Generic integration URL.
 */
export function assertValidSplunkOnCallSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is SplunkOnCallSinkConfig {
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
      !(SPLUNK_ONCALL_STATUSES as readonly string[]).includes(c.status))
  ) {
    throw new RangeError(at("`status` must be one of firing, resolved when set"));
  }
  if (
    c.messageType !== undefined &&
    (typeof c.messageType !== "string" ||
      !(SPLUNK_ONCALL_MESSAGE_TYPES as readonly string[]).includes(c.messageType))
  ) {
    throw new RangeError(at("`messageType` must be one of CRITICAL, WARNING, INFO when set"));
  }
}

/**
 * Derive one record's entity_display_name: the first
 * non-empty value among `subject`, `key`, and `traceId`,
 * in that order. Falls back to the generic `webhook event`
 * title when the record carries none — an alert sink must
 * not silently drop sourceless events. No truncation is
 * applied: the re-checked documentation states no
 * display-name length limit for this endpoint.
 */
export function resolveSplunkOnCallDisplayName(record: SplunkOnCallRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return SPLUNK_ONCALL_FALLBACK_DISPLAY_NAME;
}

/**
 * Resolve the alert status: the record's override when set,
 * else the config-held value, else `firing`.
 */
export function resolveSplunkOnCallStatus(
  record: SplunkOnCallRecord,
  config: Pick<SplunkOnCallSinkConfig, "status">
): SplunkOnCallAlertStatus {
  return record.status ?? config.status ?? SPLUNK_ONCALL_DEFAULT_STATUS;
}

/**
 * Resolve the message type: the record's override when set,
 * else the config-held value, else `CRITICAL`. A resolved
 * alert ignores this value: it sends `message_type`
 * exactly `"RECOVERY"` (see `buildSplunkOnCallAlertBody`).
 */
export function resolveSplunkOnCallMessageType(
  record: SplunkOnCallRecord,
  config: Pick<SplunkOnCallSinkConfig, "messageType">
): SplunkOnCallMessageType {
  return record.messageType ?? config.messageType ?? SPLUNK_ONCALL_DEFAULT_MESSAGE_TYPE;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood an incident.
 */
export function truncateSplunkOnCallPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's `state_message`: only the event's own
 * identifiers — `key=<key>` and `traceId=<traceId>`
 * when present, joined with `"; "` — and, when the event
 * carries no identifiers, the derived display-name text,
 * so the state_message is never empty. Under the
 * `includePayload` opt-in the event body is appended after
 * the identifiers (or after the display-name fallback),
 * truncated to `payloadMaxChars` (default 2000). The
 * state_message itself is never truncated: the re-checked
 * docs state no state-message length limit.
 */
export function resolveSplunkOnCallStateMessage(
  record: SplunkOnCallRecord,
  config: Pick<SplunkOnCallSinkConfig, "includePayload" | "payloadMaxChars">
): string {
  const parts: string[] = [];
  if (record.key !== undefined && record.key !== "") {
    parts.push(`key=${record.key}`);
  }
  if (record.traceId !== undefined && record.traceId !== "") {
    parts.push(`traceId=${record.traceId}`);
  }
  const base = parts.length > 0 ? parts.join("; ") : resolveSplunkOnCallDisplayName(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? SPLUNK_ONCALL_DEFAULT_PAYLOAD_MAX_CHARS;
    const payload = truncateSplunkOnCallPayload(record.body, limit);
    return `${base}\n\n${payload}`;
  }
  return base;
}

/**
 * Build one record's serialized JSON body: `message_type`
 * (the derived firing type — CRITICAL/WARNING/INFO — or
 * exactly `"RECOVERY"` for a resolved alert), `entity_id`
 * (the event's key, sent only when one exists — the
 * official dedup / correlation key, sent verbatim, never
 * truncated), `entity_display_name` (the derived display
 * name, never truncated — the re-checked docs state no
 * length limit), `state_message` (only the `key`/`traceId`
 * identifiers, falling back to the display-name text when
 * the event carries neither, so never empty; the event
 * body appended only under the `includePayload` opt-in),
 * and `monitoring_tool` (fixed `"webhook-relay"` — the
 * field names the system that raised the alert, and the
 * relay is that system). No credential ever enters the
 * body — the client alone holds the REST Generic
 * integration URL (api_key and routing_key in the path).
 */
export function buildSplunkOnCallAlertBody(
  record: SplunkOnCallRecord,
  config: Pick<SplunkOnCallSinkConfig, "includePayload" | "payloadMaxChars" | "status" | "messageType">
): string {
  const alert: {
    message_type: string;
    entity_id?: string;
    entity_display_name: string;
    state_message: string;
    monitoring_tool: string;
  } = {
    message_type:
      resolveSplunkOnCallStatus(record, config) === "resolved"
        ? SPLUNK_ONCALL_RESOLVED_MESSAGE_TYPE
        : resolveSplunkOnCallMessageType(record, config),
    entity_display_name: resolveSplunkOnCallDisplayName(record),
    state_message: resolveSplunkOnCallStateMessage(record, config),
    monitoring_tool: SPLUNK_ONCALL_MONITORING_TOOL,
  };
  if (record.key !== undefined && record.key !== "") {
    alert.entity_id = record.key;
  }
  return JSON.stringify(alert);
}

/**
 * Validate one record. Throws `RangeError` on an empty
 * body string — even without the opt-in, the body is the
 * record's payload, and an empty record is a caller bug
 * that must fail closed, never alert as an empty message.
 * A bad per-record `status` or `messageType` value fails
 * here too (the config-level check in
 * `assertValidSplunkOnCallSinkConfig` only covers the
 * config defaults). A keyless resolve fails closed here:
 * without an entity_id Splunk On-Call cannot associate
 * the call with an open incident, so the resolve would
 * silently land nowhere (the ilert ACCEPT/RESOLVE and
 * Squadcast rules) — the effective status is the record's
 * override else the config-held value, defaulting to
 * firing.
 */
export function resolveSplunkOnCallRecord(
  record: SplunkOnCallRecord,
  index: number,
  config: Pick<SplunkOnCallSinkConfig, "status">
): { index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`splunk-oncall-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  if (
    record.status !== undefined &&
    !(SPLUNK_ONCALL_STATUSES as readonly string[]).includes(record.status)
  ) {
    throw new RangeError(`splunk-oncall-sink: record ${index} \`status\` must be one of firing, resolved when set`);
  }
  if (
    record.messageType !== undefined &&
    (typeof record.messageType !== "string" ||
      !(SPLUNK_ONCALL_MESSAGE_TYPES as readonly string[]).includes(record.messageType))
  ) {
    throw new RangeError(`splunk-oncall-sink: record ${index} \`messageType\` must be one of CRITICAL, WARNING, INFO when set`);
  }
  if (
    resolveSplunkOnCallStatus(record, config) === "resolved" &&
    (record.key === undefined || record.key === "")
  ) {
    throw new RangeError(`splunk-oncall-sink: record ${index} a resolved alert requires \`key\` (entity_id)`);
  }
  return { index };
}

/**
 * Map one Splunk On-Call POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says Splunk On-Call could
 * not accept the alert right now, not that the payload is
 * poison. Every other non-2xx status (400 invalid body,
 * 404 wrong integration URL, and the rest) is a fail-closed
 * message: an invalid body will never become valid on
 * retry. Honesty note: the re-checked references publish
 * no 429 or per-status 4xx mention at all, so this mapping
 * is the slot convention for the unlisted statuses, not a
 * per-status claim from those pages — and no per-status
 * error code is invented here. Callers only pass non-2xx
 * statuses here; any 2xx is acceptance on its own (see
 * `classifySplunkOnCallIncidentResponse`).
 */
export function classifySplunkOnCallRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * The verdict on one alert POST: either an acceptance,
 * or a failure with its error code and retry lane.
 */
export type SplunkOnCallIncidentVerdict =
  | { accepted: true }
  | { accepted: false; errorCode: string; retryable: boolean; errorMessage?: string };

/**
 * Decide one alert POST's verdict from the response the
 * client reported. Any 2xx is acceptance — the tentative
 * rule (see the module header: no re-checked source states
 * a success status code, and the official Alert Ingestion
 * API reference page is down). A 2xx is only an acceptance
 * receipt, not an incident: the incident itself is created
 * by Splunk On-Call. No receipt id is required or
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
export function classifySplunkOnCallIncidentResponse(
  response: SplunkOnCallAlertPostResponse
): SplunkOnCallIncidentVerdict {
  if (response.status >= 200 && response.status < 300) {
    return { accepted: true };
  }
  const verdict: SplunkOnCallIncidentVerdict = {
    accepted: false,
    errorCode: `HTTP_${response.status}`,
    retryable: classifySplunkOnCallRecordFailure(response.status),
  };
  if (response.errorMessage !== undefined && response.errorMessage !== "") {
    verdict.errorMessage = response.errorMessage;
  }
  return verdict;
}

/**
 * Splunk On-Call sink (WR-304). One alert is sent per record; the
 * caller owns retry / dead-letter policy around `send()`
 * — this class performs one POST attempt per message
 * through the injected client and reports its outcome.
 * Failures throw `SplunkOnCallSinkError` carrying exactly the
 * failed messages with their retry lanes. The sink keeps
 * no per-incident state: a later `resolved` carrying the
 * same key is sent exactly like any other alert, and
 * Splunk On-Call resolves the open incident by entity_id —
 * the sink does not try to track that.
 */
export class SplunkOnCallSink {
  private readonly cfg: SplunkOnCallSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: SplunkOnCallSinkConfig) {
    assertValidSplunkOnCallSinkConfig(config, "SplunkOnCallSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): SplunkOnCallSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send the alerts, in input order. Throws
   * `SplunkOnCallSinkConfigError` when no client was injected,
   * and `SplunkOnCallSinkError` when any message fails
   * (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: SplunkOnCallRecord[]): Promise<SplunkOnCallSendResult> {
    const resolved = records.map((r, i) => resolveSplunkOnCallRecord(r, i, this.cfg));
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
      throw new SplunkOnCallSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const failedRecords: SplunkOnCallFailedRecord[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          headers: {
            "Content-Type": SPLUNK_ONCALL_JSON_CONTENT_TYPE,
          },
          body: buildSplunkOnCallAlertBody(records[i], this.cfg),
        });
        const verdict = classifySplunkOnCallIncidentResponse(response);
        if (verdict.accepted) {
          // Any 2xx is acceptance on its own (tentative —
          // see the module header): the status is the
          // acceptance receipt, and the incident itself is
          // created by Splunk On-Call — the response is an
          // acceptance receipt, not an incident. No receipt id
          // is claimed: the re-checked documentation states
          // no response id for this endpoint.
          sent += 1;
          continue;
        }
        const failed: SplunkOnCallFailedRecord = {
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
        failedRecords.push(toSplunkOnCallFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new SplunkOnCallSinkError(
        `splunk-oncall-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent };
  }
}

/**
 * Convert a client throw into a failed message: a codeless
 * transport failure (`TRANSPORT_ERROR`, retryable — the SQS
 * no-status rule). A retry reuses the same entity_id, so it
 * lands on the open incident rather than creating a second
 * one (see the module header).
 */
function toSplunkOnCallFailedRecord(err: unknown, index: number): SplunkOnCallFailedRecord {
  const failed: SplunkOnCallFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
