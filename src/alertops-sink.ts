/**
 * AlertOps on-call alert delivery sink (WR-307).
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
 * `status` envelope, the Splunk On-Call sink (WR-304)
 * posts an alert to a Splunk On-Call REST Generic
 * integration with a `message_type`/`entity_id`/
 * `entity_display_name`/`state_message`/`monitoring_tool`
 * envelope, the PagerTree sink (WR-305) posts an alert
 * to a PagerTree webhook integration with an
 * `event_type`/`id`/`title`/`description`/`urgency`
 * envelope, and the xMatters sink (WR-306) posts an
 * alert to an xMatters "Trigger Alerts by Webhook"
 * workflow with a `summary`/`message`/`recipients`/
 * `priority` envelope, this sink posts an alert to an
 * AlertOps Inbound API integration: one event is sent as
 * one POST to the integration endpoint URL the client
 * alone holds, and AlertOps — not the relay — owns the
 * alert, the escalation, the notification, and the alert
 * lifecycle.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need an AlertOps
 * server. The sink owns the relay-side concerns — the
 * subject, the description, the source id, the firing-only
 * rule, the payload-inclusion policy, the per-message
 * failure mapping — and the injected client owns the wire
 * protocol, including the POST call, the integration
 * endpoint URL, the authentication, and the status it
 * returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { headers: { "Content-Type": "application/json" },
 *     body: "{\"source_id\":\"<key>\",\"source_status\":\"open\",\"subject\":\"<subject>\",\"description\":\"key=<key>; traceId=<traceId>\"}" }
 *
 * The client POSTs to the integration endpoint URL it alone
 * holds, sending `body` verbatim as the request body
 * (JSON) and sending `headers` verbatim as the request
 * headers. Nine things about this shape are deliberate,
 * and all follow the sibling sinks or the backlog pins:
 *
 * - The integration endpoint URL is held by the client
 *   alone. The sink never receives the endpoint URL,
 *   never places it in the request, and never logs it:
 *   the sink config has no `apiKey` field at all, and
 *   the handed request carries no URL at all (like the
 *   ilert, Zenduty, Squadcast, SIGNL4, Grafana OnCall,
 *   Spike.sh, Splunk On-Call, PagerTree, and xMatters
 *   sinks, unlike the Opsgenie sink, whose handed request
 *   carries the bare endpoint URL), so there is nothing
 *   in it for a log line or a retry queue to leak — and
 *   the URL is never persisted by the sink. The URL
 *   itself is the credential: creating an API integration
 *   generates a unique URL of the form
 *   `https://notify.alertops.com/POSTAlert/<uuid-token>/
 *   <source-value>`, with the token in the URL path and
 *   no query parameters (help.alertops.com, "Configuring
 *   API Integration" and "Custom API Integration",
 *   re-checked 2026-11-02). The integration page also
 *   offers an Authorization Header toggle below the URL;
 *   an operator who enables it configures that header in
 *   the client alone — the sink sends no `Authorization`
 *   header either way. This is the AlertOps form of the
 *   MagicBell rule (whose Project JWT the client alone
 *   holds as an `Authorization: Bearer` header), with
 *   AlertOps' own credential source: the integration
 *   endpoint URL, verified against the current docs.
 * - The endpoint is the integration endpoint URL the
 *   backlog pins: the Inbound API integration's endpoint,
 *   `https://notify.alertops.com/POSTAlert/<uuid-token>/
 *   <source-value>`. The client substitutes nothing and
 *   the sink never builds the URL, so the sink cannot
 *   leak, log, or misroute the credential. The trailing
 *   path segment is the integration's Source value (not
 *   the Integration Name) — the client alone holds the
 *   full URL, so no URL template constant is pinned here
 *   beyond the documented pattern in this comment: the
 *   sink never constructs a URL at all.
 * - `source_id` is the event's key, sent when one exists
 *   and omitted entirely when the event carries none.
 *   It is the integration's Source Id — the documented
 *   dedup/correlation key: the Advanced Field Mapping
 *   page calls Source Id "a unique identifier
 *   (deduplication key/alias)" and the Alerta
 *   integration guide's mapping table says the Alert
 *   Source ID "uniquely identifies the Alerta alert for
 *   deduplication and correlation of repeated alerts",
 *   and the API Integration Advanced Settings page says
 *   Alert Grouping merges "alerts that share Source,
 *   Source Name, and Source Id into one" (all re-checked
 *   2026-11-02). A later event with the same source id
 *   therefore folds into the same alert instead of
 *   opening a new one. It is sent verbatim, never
 *   truncated: truncating a grouping key would silently
 *   merge distinct incidents. (Contrast the xMatters
 *   sink, whose workflow accepts no id field and so
 *   sends none.)
 * - `source_status` is mandatory: it is the integration's
 *   Source Status, which "determines whether to open or
 *   close the corresponding AlertOps alert" (Alerta
 *   guide's mapping table). A firing record sends the
 *   configured firing value (default `"open"`); a
 *   resolved record sends the configured resolved value
 *   (default `"close"`). The defaults are the Advanced
 *   Field Mapping page's own values — its Grafana
 *   example opens when the SourceStatus is 'Open' and
 *   closes when it "contains the value of 'close'", and
 *   the Alerta plugin's published payload sends
 *   `"source_status": "open"` (both re-checked
 *   2026-11-02). The values are the integration's
 *   agreement, so they are configurable per sink through
 *   `statusValues` (an integration that agreed on the
 *   Segment pair, for example, configures
 *   `{ firing: "triggered", resolved: "ok" }` — the
 *   Segment guide's values) — but they are never
 *   normalized or re-cased by the sink: the
 *   integration's Open/Close rules match on the
 *   configured values, and re-casing them would silently
 *   break the match. An empty configured value fails at
 *   construction with a `RangeError`.
 * - `subject` is mandatory, so it is derived as the first
 *   non-empty value among `subject`, `key`, and
 *   `traceId`, in that order, falling back to the
 *   generic `webhook event`: an alert sink that
 *   silently dropped sourceless events would hide
 *   exactly the deliveries an operator most needs to
 *   see. No truncation is applied: the re-checked
 *   documentation states no subject length limit for
 *   this endpoint, and inventing one would silently cut
 *   an operator's alert text. The field name is the
 *   AlertOps alert field's own: the Alerta guide's
 *   mapping table lists Subject ("Identifies the event
 *   that triggered the alert") among the AlertOps alert
 *   fields, and the integration maps it from a top-level
 *   incoming JSON key (the Advanced Field Mapping page:
 *   a basic top-level field is mapped "simply
 *   referencing the Key from the Key-Value pair").
 * - `description` is mandatory, so it is derived from the
 *   event's own identifiers — `key=<key>;
 *   traceId=<traceId>` when present (the ilert `details`
 *   form, following the SIGNL4 `Message` shape) — and
 *   falls back to the derived subject text when the event
 *   carries no identifiers, so it is never empty: a
 *   stateless incident would hide exactly the context
 *   an operator most needs to see. No truncation is
 *   applied to the identifiers or the fallback text: the
 *   re-checked documentation states no description length
 *   limit for this endpoint. The field name is the
 *   AlertOps alert field's own: the Alerta guide's
 *   mapping table lists the notification text field as
 *   fed by `<description>` ("Provides the alert summary
 *   in responder notifications"), and the Alerta plugin's
 *   published payload carries a top-level `description`.
 * - A resolved record sends `source_status` with the
 *   configured resolved value and the same `source_id`
 *   the alert was created with — the close matches the
 *   open alert by Source, Source Name, and Source Id
 *   (the Advanced Field Mapping page: "To close an
 *   alert, AlertOps looks to see if an alert exists in
 *   the system with a matching combination of Source and
 *   Source Name. If the SourceStatus of the signal
 *   contains the value of 'close', the alert will be
 *   closed"). A keyless resolve therefore fails closed
 *   at record validation with a `RangeError` before any
 *   POST is made (the ilert ACCEPT/RESOLVE and Squadcast
 *   rules): without a source id there is no open alert
 *   to match, and the close would silently land on
 *   nothing — or worse, on another alert from the same
 *   source. The default is firing-only: a record with
 *   no status sends the firing value.
 * - `source` is deliberately NOT sent. Source is a static
 *   field configured on the integration itself (it "is a
 *   static field in AlertOps", per the Advanced Field
 *   Mapping page), and its value is already the trailing
 *   segment of the endpoint URL the client alone holds —
 *   sending it again would duplicate a value the
 *   integration already owns, and the sink never sees
 *   the URL. Likewise no `source_url` is sent: the relay
 *   holds no dashboard or runbook URL for the event, and
 *   inventing one would be worse than sending none.
 * - `payload` carries only the event's own identifiers
 *   by default — `key` and `traceId` when present,
 *   nothing else — so the alert's description stays
 *   identifiers, never event body: here that means the
 *   `description` carries the identifiers only (see
 *   above). Under the `includePayload` opt-in the event
 *   body is appended to the `description` after the
 *   identifiers (or after the subject fallback, when the
 *   event carries no identifiers), truncated to
 *   `payloadMaxChars` characters (default 2000). No
 *   `Idempotency-Key` header is sent: the reference
 *   documents no idempotency key for this endpoint, and
 *   the source id already gives a retry its grouping
 *   key — a retry after a transport failure reuses the
 *   same source id, so it lands on the open alert
 *   instead of paging the on-call engineer twice.
 *
 * Acceptance is decided by the HTTP status alone, and
 * the success rule is tentatively any 2xx: the
 * re-checked references pin the endpoint URL, the POST
 * method, the JSON content, the Source Id dedup rule, the
 * Source Status open/close rule, and the Subject and
 * description alert fields — but none of them states a
 * success status code or a response body (the Custom API
 * Integration page's TEST button reports only an inline
 * "Success" string, not an HTTP status), so no per-status
 * success claim can be made from a live page. Any 2xx is
 * therefore treated as acceptance (the slot convention,
 * marked tentative in the code and the README — if the
 * reference later pins a single success status, only
 * `classifyAlertOpsAlertResponse` needs to change). A 2xx
 * is only an acceptance receipt, not an alert: the alert
 * itself is created by AlertOps.
 * No receipt id is collected: the re-checked
 * documentation states no response id for this endpoint,
 * so `send()` returns no ids (inventing one would be
 * worse than returning none).
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over the HTTP status:
 *
 * - a non-2xx POST throws `AlertOpsSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: no re-checked reference pins a
 *   per-status error for this endpoint, so the 429 lane
 *   is the slot convention here, not a live citation (a
 *   rate limit says AlertOps could not accept the alert
 *   right now, not that the payload is poison);
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400 (the
 *   submitted body is invalid) and 401/403 (the
 *   integration URL or its token is wrong): retrying them
 *   burns the retry budget for nothing, and rerouting
 *   them elsewhere would page an on-call engineer the
 *   operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client throws `AlertOpsSinkConfigError`,
 *   which `classifyFailure` maps to `non_retryable`
 *   (the WR-116 rule).
 *
 * One honesty note on the failure mapping: the
 * re-checked references publish no per-status error
 * mention at all for this endpoint, so the 429/5xx
 * retryable, other-4xx-fail-closed mapping is the slot
 * convention for the unlisted statuses, not a per-status
 * claim from those pages, and no per-status error code is
 * invented here: the failure record carries `HTTP_<status>`
 * plus whatever free-form error text the client surfaced,
 * and nothing more. A second honesty note, on the success
 * status: no 2xx status is documented for this endpoint
 * by any re-checked source; any 2xx is accepted under the
 * task's tentative 2xx rule, not because any reference
 * pins it — if the reference later pins a single success
 * status, only `classifyAlertOpsAlertResponse` needs to
 * change. A third honesty note, on the status values:
 * the docs publish more than one agreed pair — 'Open' /
 * 'close' (Advanced Field Mapping), "open" (Alerta
 * plugin), 'triggered' / 'ok' (Segment) — so the
 * defaults are the Advanced Field Mapping pair and the
 * pair is configurable; the sink asserts no pair beyond
 * the one the operator configures.
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic title used when an event carries no value for it. */
export const ALERTOPS_FALLBACK_TITLE = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const ALERTOPS_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Content type the client sends with the JSON body. */
export const ALERTOPS_JSON_CONTENT_TYPE = "application/json";

/**
 * Default Source Status value sent for a firing alert.
 * The Advanced Field Mapping page's own value: its
 * Grafana example opens when the SourceStatus is 'Open',
 * and the Alerta plugin's published payload sends
 * `"source_status": "open"`.
 */
export const ALERTOPS_DEFAULT_FIRING_STATUS = "open";

/**
 * Default Source Status value sent for a resolved alert.
 * The Advanced Field Mapping page's own value: "If the
 * SourceStatus of the signal contains the value of
 * 'close', the alert will be closed."
 */
export const ALERTOPS_DEFAULT_RESOLVED_STATUS = "close";

/** Default alert status: this sink sends firing alerts unless told otherwise. */
export const ALERTOPS_DEFAULT_STATUS = "firing";

/** The alert statuses this sink recognizes. */
export const ALERTOPS_STATUSES = ["firing", "resolved"] as const;

/** One of the alert statuses this sink recognizes. */
export type AlertOpsStatus = (typeof ALERTOPS_STATUSES)[number];

/**
 * The Source Status values the integration agreed on,
 * one per alert status. Both default to the Advanced
 * Field Mapping page's pair (`"open"` / `"close"`); an
 * integration that agreed on a different pair (the
 * Segment guide's `'triggered'` / `'ok'`, for example)
 * configures it here. Values are sent verbatim, never
 * normalized or re-cased: the integration's Open/Close
 * rules match on the configured values.
 */
export interface AlertOpsStatusValues {
  /** Source Status value sent for a firing alert (default `"open"`). */
  firing?: string;
  /** Source Status value sent for a resolved alert (default `"close"`). */
  resolved?: string;
}

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (JSON) to the integration endpoint
 * URL it alone holds, sending `headers` verbatim as the
 * request headers. There is deliberately no `url` field
 * here: the integration endpoint URL is the credential,
 * so the sink must never see, build, or hand over a URL —
 * the client posts to the URL it was configured with. No
 * `Authorization` header is sent: the client alone holds
 * whichever authentication the integration was configured
 * with (the URL itself, or the integration's optional
 * Authorization Header toggle). No `Idempotency-Key`
 * header is sent: the docs do not verify it for this
 * endpoint, and the source id already gives a retry its
 * grouping key.
 */
export interface AlertOpsAlertPostRequest {
  /**
   * Request headers, sent verbatim:
   * `{ "Content-Type": "application/json" }`. There is
   * deliberately no `url` field: the integration endpoint
   * URL is held by the client alone, never by the sink,
   * and there is no `Authorization` header and no
   * `Idempotency-Key` header.
   */
  headers: Record<string, string>;
  /**
   * The JSON request body, serialized:
   * `{"source_id":"<key>","source_status":"open","subject":"<subject>","description":"key=<key>; traceId=<traceId>"}`
   * (`source_id` is sent only when the event carries a
   * key — it is the integration's Source Id dedup key;
   * the event body is appended to `description` only
   * under the `includePayload` opt-in). No credential
   * ever enters the body.
   */
  body: string;
}

/**
 * The result of one POST, as reported by the injected
 * client. The HTTP status decides acceptance: any 2xx
 * means AlertOps accepted the alert (tentative —
 * see the module header: no re-checked source states a
 * success status code). The error text, when the client
 * surfaced one, rides on the failure record; no
 * per-status error code is claimed from the reference.
 * No receipt id is collected: the re-checked
 * documentation states no response id for this endpoint.
 */
export interface AlertOpsAlertPostResponse {
  /** The HTTP status of the POST (e.g. 200, 400, 401, 429, 500). */
  status: number;
  /** Free-form error text from the error body, when the client surfaced one. */
  errorMessage?: string;
}

/**
 * The injected AlertOps alert client. Any client adapter
 * implements this one method; it returns the POST's status —
 * a throw is a codeless transport failure, retryable. The
 * client is expected to POST one alert per call, sending
 * `body` verbatim as the request body (JSON), sending
 * `headers` verbatim as the request headers, and posting
 * to the integration endpoint URL it alone holds — the sink
 * never sees that URL.
 */
export interface AlertOpsAlertClient {
  post(request: AlertOpsAlertPostRequest): Promise<AlertOpsAlertPostResponse>;
}

/**
 * Configuration for one AlertOps sink. The client is
 * injected: without one, `send()` throws
 * `AlertOpsSinkConfigError` (dry runs excepted — they need
 * no client at all). The integration endpoint URL is
 * deliberately absent from this config: the client alone
 * holds it, and it is never persisted by the sink.
 */
export interface AlertOpsSinkConfig {
  /**
   * The AlertOps alert client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `AlertOpsAlertClient` and alone holds the
   * integration endpoint URL. Required for real sends; a missing
   * client is a config error, not a silent no-op.
   */
  client?: AlertOpsAlertClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }`
   * and performs zero client I/O — no POST call, no stat
   * changes. Messages are still validated (including
   * status derivation and the keyless-resolve rule), so
   * a dry run catches a malformed record before it
   * reaches production. Mirrors the `dryRun` convention
   * of the S3 offloaders. The client is not required in
   * dry-run mode, mirroring the sibling sinks' dry-run
   * exemption; the rest of the config must still be valid
   * — a dry run against a sink with a bad status value
   * would rehearse a request that could never send.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the request body's
   * `description` appends the event body verbatim as a
   * JSON string, truncated to `payloadMaxChars`
   * characters (see below), after the identifiers (or
   * after the subject fallback, when the event carries no
   * identifiers). When `false` or absent,
   * `description` carries the identifiers only — the
   * default, so event bodies (which routinely carry PII)
   * never leak into an alert unless the operator
   * explicitly asks for them.
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
   * The Source Status values the integration agreed on,
   * one per alert status (see `AlertOpsStatusValues`).
   * Both default to the Advanced Field Mapping page's
   * pair (`"open"` for firing, `"close"` for resolved).
   * Each value, when set, must be a non-empty string and
   * is sent verbatim, never normalized or re-cased: the
   * integration's Open/Close rules match on the
   * configured values.
   */
  statusValues?: AlertOpsStatusValues;
}

/** One event to alert about. */
export interface AlertOpsRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Content-derivation source, first priority: the event's
   * subject, when set and non-empty. The alert's subject.
   */
  subject?: string;
  /**
   * Content-derivation source, second priority: the event's key
   * (e.g. aggregate id). The integration's Source Id when set
   * — the documented dedup/correlation key — and a `subject`
   * fallback when no subject exists. It is sent verbatim,
   * never truncated.
   */
  key?: string;
  /**
   * Content-derivation source, last priority: the trace id.
   * Also a `description` identifier, when set. It is never
   * an id: only the event key is the Source Id.
   */
  traceId?: string;
  /**
   * Alert status: `"firing"` (the default) or
   * `"resolved"`. A resolved record sends the configured
   * resolved Source Status value with the same `source_id`
   * the alert was created with — and a keyless resolve
   * fails closed with a `RangeError` before any POST is
   * made (without a source id there is no open alert to
   * match).
   */
  status?: AlertOpsStatus;
}

/** One failed message, with its retry lane already mapped. */
export interface AlertOpsFailedRecord {
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
   * (400 invalid body, 401/403 wrong integration URL or
   * token, and the rest). The 429 lane is the slot
   * convention here, not a live citation (see the module
   * header). No per-status error code is claimed from
   * the reference.
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface AlertOpsSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-307). */
export interface AlertOpsSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for AlertOps send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already received on AlertOps' server and are *not* in
 * `failedRecords`.
 */
export class AlertOpsSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: AlertOpsFailedRecord[];
  constructor(message: string, failedRecords: AlertOpsFailedRecord[]) {
    super(message);
    this.name = "AlertOpsSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class AlertOpsSinkConfigError extends AlertOpsSinkError {
  constructor(reason: string) {
    super(`alertops-sink: ${reason}`, []);
    this.name = "AlertOpsSinkConfigError";
  }
}

/**
 * Normalize one status value to the lowercase form this
 * sink matches. Throws `RangeError` on a value that is
 * not firing or resolved — an unknown status has no
 * meaning through this integration.
 */
function normalizeAlertOpsStatus(value: unknown, label: string): AlertOpsStatus {
  if (typeof value !== "string") {
    throw new RangeError(`${label} must be one of firing, resolved`);
  }
  const normalized = value.toLowerCase().trim();
  if (!(ALERTOPS_STATUSES as readonly string[]).includes(normalized)) {
    throw new RangeError(`${label} must be one of firing, resolved`);
  }
  return normalized as AlertOpsStatus;
}

/**
 * Resolve one configured Source Status value: the
 * configured value when set, else the documented default.
 * A set value must be a non-empty string and is returned
 * verbatim, never normalized or re-cased: the
 * integration's Open/Close rules match on the configured
 * values.
 */
function resolveAlertOpsStatusValue(
  values: AlertOpsStatusValues | undefined,
  which: "firing" | "resolved",
  label: string
): string {
  const configured = values?.[which];
  if (configured === undefined) {
    return which === "firing" ? ALERTOPS_DEFAULT_FIRING_STATUS : ALERTOPS_DEFAULT_RESOLVED_STATUS;
  }
  if (typeof configured !== "string" || configured === "") {
    throw new RangeError(`${label} must be a non-empty string when set`);
  }
  return configured;
}

/**
 * Resolve the Source Status value for one record's alert
 * status: the configured value for that status (see
 * `resolveAlertOpsStatusValue`). The record's status
 * defaults to firing.
 */
export function resolveAlertOpsSourceStatus(
  record: AlertOpsRecord,
  config: Pick<AlertOpsSinkConfig, "statusValues">
): string {
  const status = normalizeAlertOpsStatus(record.status ?? ALERTOPS_DEFAULT_STATUS, "AlertOps status");
  return resolveAlertOpsStatusValue(config.statusValues, status, `AlertOps statusValues.${status}`);
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery.
 * Each configured Source Status value, when set, must be a
 * non-empty string. There is deliberately no `apiKey` field
 * to validate: the client alone holds the integration
 * endpoint URL.
 */
export function assertValidAlertOpsSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is AlertOpsSinkConfig {
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
  if (c.statusValues !== undefined) {
    if (c.statusValues === null || typeof c.statusValues !== "object") {
      throw new RangeError(at("`statusValues` must be an object when set"));
    }
    const values = c.statusValues as Record<string, unknown>;
    for (const which of ["firing", "resolved"] as const) {
      if (values[which] !== undefined) {
        resolveAlertOpsStatusValue(values as AlertOpsStatusValues, which, at(`\`statusValues.${which}\``));
      }
    }
  }
}

/**
 * Derive one record's subject: the first non-empty value
 * among `subject`, `key`, and `traceId`, in that order.
 * Falls back to the generic `webhook event` subject when the
 * record carries none — an alert sink must not silently
 * drop sourceless events. No truncation is applied: the
 * re-checked documentation states no subject length limit
 * for this endpoint.
 */
export function resolveAlertOpsSubject(record: AlertOpsRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return ALERTOPS_FALLBACK_TITLE;
}

/**
 * Resolve the status: the record's value when set, else
 * `firing`. The value is normalized to lowercase, and an
 * illegal value throws `RangeError`.
 */
export function resolveAlertOpsStatus(record: AlertOpsRecord): AlertOpsStatus {
  return normalizeAlertOpsStatus(record.status ?? ALERTOPS_DEFAULT_STATUS, "AlertOps status");
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood an alert.
 */
export function truncateAlertOpsPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's `description`: only the event's own
 * identifiers — `key=<key>` and `traceId=<traceId>`
 * when present, joined with `"; "` — and, when the event
 * carries no identifiers, the derived subject text, so the
 * description is never empty. Under the `includePayload`
 * opt-in the event body is appended after the identifiers
 * (or after the subject fallback), truncated to
 * `payloadMaxChars` (default 2000). The description itself
 * is never truncated: the re-checked docs state no
 * description length limit.
 */
export function resolveAlertOpsDescription(
  record: AlertOpsRecord,
  config: Pick<AlertOpsSinkConfig, "includePayload" | "payloadMaxChars">
): string {
  const parts: string[] = [];
  if (record.key !== undefined && record.key !== "") {
    parts.push(`key=${record.key}`);
  }
  if (record.traceId !== undefined && record.traceId !== "") {
    parts.push(`traceId=${record.traceId}`);
  }
  const base = parts.length > 0 ? parts.join("; ") : resolveAlertOpsSubject(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? ALERTOPS_DEFAULT_PAYLOAD_MAX_CHARS;
    const payload = truncateAlertOpsPayload(record.body, limit);
    return `${base}\n\n${payload}`;
  }
  return base;
}

/**
 * Build one record's serialized JSON body: `source_id`
 * (the event key, sent only when one exists — the
 * integration's Source Id dedup/correlation key, sent
 * verbatim, never truncated), `source_status` (the
 * configured Source Status value for the record's alert
 * status — `"open"` by default for firing, `"close"` for
 * resolved), `subject` (the derived subject, never
 * truncated — the re-checked docs state no length limit),
 * and `description` (only the `key`/`traceId`
 * identifiers, falling back to the subject text when the
 * event carries neither, so never empty; the event body
 * appended only under the `includePayload` opt-in). No
 * credential ever enters the body — the client alone
 * holds the integration endpoint URL.
 */
export function buildAlertOpsAlertBody(
  record: AlertOpsRecord,
  config: Pick<AlertOpsSinkConfig, "includePayload" | "payloadMaxChars" | "statusValues">
): string {
  const alert: {
    source_id?: string;
    source_status: string;
    subject: string;
    description: string;
  } = {
    source_status: resolveAlertOpsSourceStatus(record, config),
    subject: resolveAlertOpsSubject(record),
    description: resolveAlertOpsDescription(record, config),
  };
  if (record.key !== undefined && record.key !== "") {
    alert.source_id = record.key;
  }
  return JSON.stringify(alert);
}

/**
 * Validate one record. Throws `RangeError` on an empty
 * body string — even without the opt-in, the body is the
 * record's payload, and an empty record is a caller bug
 * that must fail closed, never alert as an empty message.
 * A bad per-record status value fails here too (the
 * config-level check in `assertValidAlertOpsSinkConfig`
 * only covers the config defaults). A keyless resolve
 * fails closed here: the close matches the open alert by
 * Source, Source Name, and Source Id, so without a key
 * there is no open alert to match — sending it would
 * page people for an incident that is already over, or
 * close nothing at all (see the module header).
 */
export function resolveAlertOpsRecord(
  record: AlertOpsRecord,
  index: number,
  config: Pick<AlertOpsSinkConfig, "statusValues">
): { index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`alertops-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  // Validate the status value (throws `RangeError` on an
  // illegal value) and derive the Source Status value.
  const status = resolveAlertOpsStatus(record);
  resolveAlertOpsSourceStatus(record, config);
  if (status === "resolved" && (record.key === undefined || record.key === "")) {
    throw new RangeError(
      `alertops-sink: record ${index} a resolved alert without a key has no source id to match an open alert`
    );
  }
  return { index };
}

/**
 * Map one AlertOps POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable. Every other non-2xx status (400
 * invalid body, 401/403 wrong integration URL or token,
 * and the rest) is a fail-closed message: an invalid body
 * will never become valid on retry. Honesty note: the
 * re-checked references publish no per-status error
 * mention at all for this endpoint, so the 429 lane is the
 * slot convention, not a live citation — and no per-status
 * error code is invented here. Callers only pass non-2xx
 * statuses here; any 2xx is acceptance on its own (see
 * `classifyAlertOpsAlertResponse`).
 */
export function classifyAlertOpsRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * The verdict on one alert POST: either an acceptance,
 * or a failure with its error code and retry lane.
 */
export type AlertOpsAlertVerdict =
  | { accepted: true }
  | { accepted: false; errorCode: string; retryable: boolean; errorMessage?: string };

/**
 * Decide one alert POST's verdict from the response the
 * client reported. Any 2xx is acceptance — the tentative
 * rule (see the module header: no re-checked source states
 * a success status code). A 2xx is only an acceptance
 * receipt, not an alert: the alert itself is created by
 * AlertOps. No receipt id is required or collected as an
 * acceptance condition: the re-checked documentation
 * states no response id for this endpoint, so `send()`
 * returns no ids. Any non-2xx status is a failure with an
 * `HTTP_<status>` code and the WR-210 lane; the error text
 * rides on the failure record when the client surfaced
 * one. No per-status error code is claimed from the
 * reference. If the reference later pins a single success
 * status, only this function needs to change.
 */
export function classifyAlertOpsAlertResponse(
  response: AlertOpsAlertPostResponse
): AlertOpsAlertVerdict {
  if (response.status >= 200 && response.status < 300) {
    return { accepted: true };
  }
  const verdict: AlertOpsAlertVerdict = {
    accepted: false,
    errorCode: `HTTP_${response.status}`,
    retryable: classifyAlertOpsRecordFailure(response.status),
  };
  if (response.errorMessage !== undefined && response.errorMessage !== "") {
    verdict.errorMessage = response.errorMessage;
  }
  return verdict;
}

/**
 * AlertOps sink (WR-307). One alert is sent per record; the
 * caller owns retry / dead-letter policy around `send()`
 * — this class performs one POST attempt per message
 * through the injected client and reports its outcome.
 * Failures throw `AlertOpsSinkError` carrying exactly the
 * failed messages with their retry lanes. The sink keeps
 * no per-alert state: a retry re-POSTs the same source id,
 * source status, subject, and description, and the same
 * source id groups the retry onto the open alert instead
 * of paging the on-call engineer twice (see the module
 * header).
 */
export class AlertOpsSink {
  private readonly cfg: AlertOpsSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: AlertOpsSinkConfig) {
    assertValidAlertOpsSinkConfig(config, "AlertOpsSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): AlertOpsSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send the alerts, in input order. Throws
   * `AlertOpsSinkConfigError` when no client was injected,
   * and `AlertOpsSinkError` when any message fails
   * (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: AlertOpsRecord[]): Promise<AlertOpsSendResult> {
    const resolved = records.map((r, i) => resolveAlertOpsRecord(r, i, this.cfg));
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
      throw new AlertOpsSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const failedRecords: AlertOpsFailedRecord[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          headers: {
            "Content-Type": ALERTOPS_JSON_CONTENT_TYPE,
          },
          body: buildAlertOpsAlertBody(records[i], this.cfg),
        });
        const verdict = classifyAlertOpsAlertResponse(response);
        if (verdict.accepted) {
          // Any 2xx is acceptance on its own (tentative —
          // see the module header): the status is the
          // acceptance receipt, and the alert itself is
          // created by AlertOps — the response is an
          // acceptance receipt, not an alert. No receipt id
          // is claimed: the re-checked documentation states
          // no response id for this endpoint.
          sent += 1;
          continue;
        }
        const failed: AlertOpsFailedRecord = {
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
        failedRecords.push(toAlertOpsFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new AlertOpsSinkError(
        `alertops-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent };
  }
}

/**
 * Convert a client throw into a failed message: a codeless
 * transport failure (`TRANSPORT_ERROR`, retryable — the SQS
 * no-status rule). A retry re-POSTs the same source id,
 * source status, subject, and description; the same source
 * id groups the retry onto the open alert (see the module
 * header).
 */
function toAlertOpsFailedRecord(err: unknown, index: number): AlertOpsFailedRecord {
  const failed: AlertOpsFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
