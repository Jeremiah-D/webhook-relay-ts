/**
 * xMatters on-call alert delivery sink (WR-306).
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
 * envelope, and the PagerTree sink (WR-305) posts an
 * alert to a PagerTree webhook integration with an
 * `event_type`/`id`/`title`/`description`/`urgency`
 * envelope, this sink posts an alert to an xMatters
 * "Trigger Alerts by Webhook" workflow: one event is
 * sent as one POST that the workflow's HTTP trigger
 * parses into an alert, and xMatters — not the relay —
 * owns the alert, the escalation, the notification, and
 * the alert lifecycle.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need an xMatters
 * server. The sink owns the relay-side concerns — the
 * summary, the message, the recipients, the priority, the
 * firing-only rule, the payload-inclusion policy, the
 * per-message failure mapping — and the injected client
 * owns the wire protocol, including the POST call, the
 * workflow trigger URL, the authentication, and the
 * status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { headers: { "Content-Type": "application/json" },
 *     body: "{\"summary\":\"<subject>\",\"message\":\"key=<key>; traceId=<traceId>\",\"recipients\":\"teamrigel, mmcbride\"}" }
 *
 * The client POSTs to the workflow trigger URL it alone
 * holds, sending `body` verbatim as the request body
 * (JSON) and sending `headers` verbatim as the request
 * headers. Nine things about this shape are deliberate,
 * and all follow the sibling sinks or the backlog pins:
 *
 * - The workflow trigger URL is held by the client alone.
 *   The sink never receives the trigger URL, never places
 *   it in the request, and never logs it: the sink config
 *   has no `apiKey` field at all, and the handed request
 *   carries no URL at all (like the ilert, Zenduty,
 *   Squadcast, SIGNL4, Grafana OnCall, Spike.sh, Splunk
 *   On-Call, and PagerTree sinks, unlike the Opsgenie
 *   sink, whose handed request carries the bare endpoint
 *   URL), so there is nothing in it for a log line or a
 *   retry queue to leak — and the URL is never persisted
 *   by the sink. The URL itself is the credential under
 *   URL authentication (the docs' own example shows the
 *   authenticating user's API key appended to the trigger
 *   URL; Basic authentication instead sends the
 *   trigger URL with an xMatters username and password,
 *   API Key authentication sends the key as the username
 *   and the secret as the password, and OAuth sends an
 *   access token in a header — whichever method the
 *   trigger was configured with, the client alone holds
 *   it). The sink hands the client the bare
 *   `Content-Type` header and the body and the client
 *   posts to the trigger URL it was configured with: the
 *   sink's request never contains a key, a placeholder,
 *   or anything that looks like one, and there is no
 *   `Authorization` header. This is the xMatters form of
 *   the MagicBell rule (whose Project JWT the client
 *   alone holds as an `Authorization: Bearer` header),
 *   with xMatters' own credential source: the workflow
 *   trigger URL, verified against the current docs
 *   (help.xmatters.com, re-checked 2026-11-02 — the
 *   "Trigger Alerts by Webhook" workflow page: "Copy the
 *   trigger URL — you'll use this to configure the
 *   webhook that will initiate your flow"; the Flow
 *   triggers page: URL Authentication "generates an API
 *   key unique to the authenticating user ... and appends
 *   that API key to the trigger URL").
 * - The endpoint is the workflow trigger URL the backlog
 *   pins: the "Trigger Alerts by Webhook" workflow's
 *   Initiate by HTTP (Webhook) trigger. The client
 *   substitutes nothing and the sink never builds the
 *   URL, so the sink cannot leak, log, or misroute the
 *   credential. The docs elide the middle path segments
 *   of the trigger URL in their examples
 *   (`https://<company>.xmatters.com/api/..../triggers`),
 *   so no URL template constant is pinned here — pinning
 *   one would invent path segments the reference does
 *   not publish.
 * - `summary` is mandatory, so it is derived as the first
 *   non-empty value among `subject`, `key`, and
 *   `traceId`, in that order, falling back to the
 *   generic `webhook event`: an alert sink that
 *   silently dropped sourceless events would hide
 *   exactly the deliveries an operator most needs to
 *   see. No truncation is applied: the re-checked
 *   documentation states no summary length limit for
 *   this endpoint, and inventing one would silently cut
 *   an operator's alert text. The field name is the
 *   workflow page's own: its sample JSON request body is
 *   `{"recipients": "teamrigel, mmcbride", "summary":
 *   "...", "message": "..."}` (re-checked 2026-11-02).
 * - `message` is mandatory, so it is derived from the
 *   event's own identifiers — `key=<key>;
 *   traceId=<traceId>` when present (the ilert `details`
 *   form, following the SIGNL4 `Message` shape) — and
 *   falls back to the derived summary text when the event
 *   carries no identifiers, so it is never empty: a
 *   stateless incident would hide exactly the context
 *   an operator most needs to see. No truncation is
 *   applied to the identifiers or the fallback text: the
 *   re-checked documentation states no message length
 *   limit for this endpoint. The field name is the
 *   workflow page's own (`message`, which the Simple
 *   Webhook - Alerts trigger maps to its Description
 *   output).
 * - `recipients` is the workflow page's own third body
 *   field: the target names of the xMatters users,
 *   groups, or dynamic teams to notify, comma-separated
 *   (the workflow page's sample body shows
 *   `"recipients": "teamrigel, mmcbride"`). It is
 *   config-held with a per-record override, and omitted
 *   entirely when neither is set — the trigger URL
 *   itself carries a `recipients` parameter (by default
 *   the installing user; `&recipients=` under URL
 *   authentication, `?recipients=` under the other
 *   methods, URL-encoded), so a sink with no recipients
 *   configured still pages whoever the trigger URL
 *   names. When the sink does send `recipients`, the
 *   value is sent verbatim, never re-encoded or split:
 *   re-encoding target names would silently rename the
 *   people paged.
 * - `priority` is the Simple Webhook - Alerts trigger's
 *   documented output (HIGH, MEDIUM, or LOW), sent only
 *   when the operator sets it — config-held with a
 *   per-record override, omitted when neither is set.
 *   The "Trigger Alerts by Webhook" workflow page's own
 *   sample payload carries no priority field, so an
 *   unset priority means the workflow's own default
 *   governs; the field exists for workflows whose
 *   trigger maps a Priority output. The value is
 *   normalized to uppercase (the docs pin uppercase),
 *   and an illegal value fails at construction (config)
 *   or at record validation (per-record) with a
 *   `RangeError`: a typo must fail fast, never reach
 *   xMatters as a priority the trigger silently drops.
 * - This sink sends firing alerts only. The workflow's
 *   published configuration payload carries no status
 *   or signal field — its sample body is
 *   summary/message/recipients and nothing else, and
 *   the Simple Webhook - Alerts trigger's outputs are
 *   Recipients/Summary/Description/Priority, with no
 *   status among them (the Firing/Resolved Status
 *   output belongs to the Prometheus Alertmanager
 *   trigger's own payload, not to this workflow) — so
 *   a resolved record has no faithful mapping through
 *   this workflow: sending it as a firing alert would
 *   page people for an incident that is already over,
 *   and inventing a status field would send a key the
 *   trigger never reads. A resolved record therefore
 *   fails closed at record validation with a
 *   `RangeError`, before any POST is made (the PagerTree
 *   keyless-resolve rule, applied to a missing status
 *   channel instead of a missing id). Operators whose
 *   workflow adds a status output need a different sink
 *   configuration, not a silent reinterpretation here.
 * - No id or dedup key is sent. The workflow's published
 *   payload accepts no id field — its sample body is
 *   summary/message/recipients only, and neither the
 *   workflow page nor the Simple Webhook - Alerts
 *   trigger outputs list an id or dedup key (the
 *   Incident ID lookup belongs to the Simple Webhook -
 *   Incidents trigger, a different trigger for a
 *   different flow). The event's key is therefore NOT
 *   mapped to any id field: it appears only inside the
 *   `message` identifiers, where it aids triage without
 *   pretending to dedupe. A retry re-POSTs the same
 *   summary and message, and whether xMatters treats it
 *   as a second alert is governed by the workflow's own
 *   flood-control settings, which the sink does not
 *   claim to control — no dedup behaviour is asserted
 *   here. (Contrast the PagerTree sink, whose adapter
 *   documents a same-thirdparty_id dedup rule and so
 *   sends the key as `id`.)
 * - `payload` carries only the event's own identifiers
 *   by default — `key` and `traceId` when present,
 *   nothing else — so the incident's message stays
 *   identifiers, never event body: here that means the
 *   `message` carries the identifiers only (see
 *   above). Under the `includePayload` opt-in the event
 *   body is appended to the `message` after the
 *   identifiers (or after the summary fallback, when the
 *   event carries no identifiers), truncated to
 *   `payloadMaxChars` characters (default 2000). No
 *   `Idempotency-Key` header is sent: the reference
 *   documents no idempotency key for this endpoint, and
 *   there is no id field to key one on (see above).
 *
 * Acceptance is decided by the HTTP status alone, and
 * the success rule is tentatively any 2xx: the
 * re-checked references pin the trigger URL, the
 * recipients parameter, the summary/message/recipients
 * body, and the 429 rate-limit rejection — but none of
 * them states a success status code or a response body,
 * so no per-status success claim can be made from a live
 * page. Any 2xx is therefore treated as acceptance (the
 * slot convention, marked tentative in the code and the
 * README — if the reference later pins a single success
 * status, only `classifyXMattersAlertResponse` needs to
 * change). A 2xx is only an acceptance receipt, not an
 * alert: the alert itself is created by xMatters.
 * No receipt id is collected: the re-checked
 * documentation states no response id for this endpoint,
 * so `send()` returns no ids (inventing one would be
 * worse than returning none).
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over the HTTP status:
 *
 * - a non-2xx POST throws `XMattersSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: the Flow triggers page pins the
 *   429 itself ("The maximum number of requests you can
 *   submit within a one-minute period to xMatters is
 *   limited by your pricing plan. If you exceed this
 *   limit, your request will be rejected with a 429
 *   error and will not be queued for processing",
 *   re-checked 2026-11-02), so the 429 lane is a live
 *   citation, not a convention — a rate limit says
 *   xMatters could not accept the alert right now, not
 *   that the payload is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400 (the
 *   submitted body is invalid) and 401/403 (the trigger
 *   URL or its credentials are wrong): retrying them
 *   burns the retry budget for nothing, and rerouting
 *   them elsewhere would page an on-call engineer the
 *   operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client throws `XMattersSinkConfigError`,
 *   which `classifyFailure` maps to `non_retryable`
 *   (the WR-116 rule).
 *
 * One honesty note on the failure mapping: the
 * re-checked references pin the 429 rate-limit rejection
 * but publish no per-status 4xx mention beyond it, so
 * the other-4xx-fail-closed lane is the slot convention
 * for the unlisted statuses, not a per-status claim from
 * those pages, and no per-status error code is invented
 * here: the failure record carries `HTTP_<status>` plus
 * whatever free-form error text the client surfaced, and
 * nothing more. A second honesty note, on the success
 * status: no 2xx status is documented for this endpoint
 * by any re-checked source; any 2xx is accepted under
 * the task's tentative 2xx rule, not because any
 * reference pins it — if the reference later pins a
 * single success status, only
 * `classifyXMattersAlertResponse` needs to change.
 *
 * The legacy fallback the backlog names is NOT built
 * here: `POST https://<company>.<deployment>.xmatters.com/
 * reapi/2015-04-01/forms/<form-id>/triggers` with HTTP
 * Basic authentication and a `{"properties": {...}}` body
 * (the Integration Builder outbound example, re-checked
 * 2026-11-02) is the form-trigger path for workflows
 * that do not expose a trigger URL, and the backlog
 * directs the two paths not to coexist — the trigger-URL
 * workflow is the current template path, so it is the
 * one implemented. If the workflow path is ever
 * unavailable, that endpoint is the documented fallback
 * to build instead, not alongside.
 *
 * Zero new dependencies: the injected client only. (No
 * `node:crypto` import either: with no idempotency key to
 * derive, there is nothing to hash.)
 */

/** Generic title used when an event carries no value for it. */
export const XMATTERS_FALLBACK_TITLE = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const XMATTERS_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Content type the client sends with the JSON body. */
export const XMATTERS_JSON_CONTENT_TYPE = "application/json";

/**
 * Query parameter the trigger URL carries for its
 * recipients (`&recipients=` under URL authentication,
 * `?recipients=` under the other methods). Exported so
 * the parameter name is pinned in tests, not so the sink
 * can build a URL — the sink never sees, builds, or
 * hands over a trigger URL; the client alone holds it.
 */
export const XMATTERS_RECIPIENTS_PARAM = "recipients";

/** Default alert status: this sink sends firing alerts only. */
export const XMATTERS_DEFAULT_STATUS = "firing";

/** The priorities the Simple Webhook - Alerts trigger documents. */
export const XMATTERS_PRIORITIES = ["HIGH", "MEDIUM", "LOW"] as const;

/** One of the priorities the Simple Webhook - Alerts trigger documents. */
export type XMattersPriority = (typeof XMATTERS_PRIORITIES)[number];

/** The alert statuses this sink recognizes. Only `firing` sends. */
export const XMATTERS_STATUSES = ["firing", "resolved"] as const;

/** One of the alert statuses this sink recognizes. */
export type XMattersStatus = (typeof XMATTERS_STATUSES)[number];

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (JSON) to the workflow trigger URL
 * it alone holds, sending `headers` verbatim as the
 * request headers. There is deliberately no `url` field
 * here: the trigger URL is the credential under URL
 * authentication, so the sink must never see, build, or
 * hand over a URL — the client posts to the URL it was
 * configured with. No `Authorization` header is sent:
 * the client alone holds whichever authentication the
 * trigger was configured with (URL, Basic, API key, or
 * OAuth). No `Idempotency-Key` header is sent: the docs
 * do not verify it for this endpoint, and there is no id
 * field to key one on.
 */
export interface XMattersAlertPostRequest {
  /**
   * Request headers, sent verbatim:
   * `{ "Content-Type": "application/json" }`. There is
   * deliberately no `url` field: the workflow trigger
   * URL is held by the client alone, never by the sink,
   * and there is no `Authorization` header and no
   * `Idempotency-Key` header.
   */
  headers: Record<string, string>;
  /**
   * The JSON request body, serialized:
   * `{"summary":"<subject>","message":"key=<key>; traceId=<traceId>","recipients":"teamrigel, mmcbride","priority":"HIGH"}`
   * (`recipients` is sent only when the config or the
   * record names recipients — otherwise the trigger URL
   * itself carries them; `priority` is sent only when
   * the config or the record sets one; the event body is
   * appended to `message` only under the `includePayload`
   * opt-in). No credential ever enters the body.
   */
  body: string;
}

/**
 * The result of one POST, as reported by the injected
 * client. The HTTP status decides acceptance: any 2xx
 * means xMatters accepted the alert (tentative —
 * see the module header: no re-checked source states a
 * success status code). The error text, when the client
 * surfaced one, rides on the failure record; no
 * per-status error code is claimed from the reference.
 * No receipt id is collected: the re-checked
 * documentation states no response id for this endpoint.
 */
export interface XMattersAlertPostResponse {
  /** The HTTP status of the POST (e.g. 200, 400, 401, 429, 500). */
  status: number;
  /** Free-form error text from the error body, when the client surfaced one. */
  errorMessage?: string;
}

/**
 * The injected xMatters alert client. Any client adapter
 * implements this one method; it returns the POST's status —
 * a throw is a codeless transport failure, retryable. The
 * client is expected to POST one alert per call, sending
 * `body` verbatim as the request body (JSON), sending
 * `headers` verbatim as the request headers, and posting
 * to the workflow trigger URL it alone holds — the sink
 * never sees that URL.
 */
export interface XMattersAlertClient {
  post(request: XMattersAlertPostRequest): Promise<XMattersAlertPostResponse>;
}

/**
 * Configuration for one xMatters sink. The client is
 * injected: without one, `send()` throws
 * `XMattersSinkConfigError` (dry runs excepted — they need
 * no client at all). The workflow trigger URL is
 * deliberately absent from this config: the client alone
 * holds it, and it is never persisted by the sink.
 */
export interface XMattersSinkConfig {
  /**
   * The xMatters alert client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `XMattersAlertClient` and alone holds the
   * workflow trigger URL. Required for real sends; a missing
   * client is a config error, not a silent no-op.
   */
  client?: XMattersAlertClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }`
   * and performs zero client I/O — no POST call, no stat
   * changes. Messages are still validated (including
   * priority derivation and the resolved-record rule), so
   * a dry run catches a malformed record before it
   * reaches production. Mirrors the `dryRun` convention
   * of the S3 offloaders. The client is not required in
   * dry-run mode, mirroring the sibling sinks' dry-run
   * exemption; the rest of the config must still be valid
   * — a dry run against a sink with a bad priority would
   * rehearse a request that could never send.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the request body's
   * `message` appends the event body verbatim as a
   * JSON string, truncated to `payloadMaxChars`
   * characters (see below), after the identifiers (or
   * after the summary fallback, when the event carries no
   * identifiers). When `false` or absent,
   * `message` carries the identifiers only — the
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
   * Default recipients: the target names of the xMatters
   * users, groups, or dynamic teams to notify,
   * comma-separated (e.g. `"teamrigel, mmcbride"`).
   * Config-held, overridable per record (see
   * `XMattersRecord.recipients`). Omitted from the body
   * when neither the config nor the record names any —
   * the trigger URL itself carries a `recipients`
   * parameter, so a sink with no recipients configured
   * still pages whoever the trigger URL names. Must be a
   * non-empty string when set; sent verbatim, never
   * re-encoded.
   */
  recipients?: string;
  /**
   * Default priority: one of HIGH, MEDIUM, LOW (the
   * Simple Webhook - Alerts trigger's documented
   * values). Config-held, overridable per record (see
   * `XMattersRecord.priority`). Omitted from the body
   * when neither the config nor the record sets one —
   * the workflow page's own sample payload carries no
   * priority field, so an unset priority means the
   * workflow's own default governs. Must be one of the
   * three values when set (case-insensitive — the value
   * is normalized to uppercase, mirroring the docs'
   * uppercase form).
   */
  priority?: XMattersPriority;
}

/** One event to alert about. */
export interface XMattersRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Content-derivation source, first priority: the event's
   * subject, when set and non-empty. The alert's summary.
   */
  subject?: string;
  /**
   * Content-derivation source, second priority: the event's key
   * (e.g. aggregate id). A `message` identifier, when set —
   * and a `summary` fallback when no subject exists. It is
   * never sent as an id field: the workflow's published
   * payload accepts no id or dedup key (see the module
   * header).
   */
  key?: string;
  /**
   * Content-derivation source, last priority: the trace id.
   * Also a `message` identifier, when set. It is never an
   * id: only the event key would be, and this workflow
   * accepts none.
   */
  traceId?: string;
  /**
   * Per-record recipients override: the target names of
   * the xMatters users, groups, or dynamic teams to
   * notify, comma-separated. When absent, the config's
   * `recipients` applies; when neither is set, the field
   * is omitted and the trigger URL's own `recipients`
   * parameter governs. Must be a non-empty string when
   * set; sent verbatim, never re-encoded.
   */
  recipients?: string;
  /**
   * Per-record priority override: one of HIGH, MEDIUM,
   * LOW. When absent, the config's `priority` applies;
   * when neither is set, the field is omitted. An illegal
   * value fails record validation with a `RangeError`.
   */
  priority?: XMattersPriority;
  /**
   * Alert status: `"firing"` (the default) or
   * `"resolved"`. A resolved record fails closed with a
   * `RangeError` before any POST is made: the workflow's
   * published configuration payload carries no status or
   * signal field, so a resolve has no faithful mapping
   * through this workflow — sending it as a firing alert
   * would page people for an incident that is already
   * over, and inventing a status field would send a key
   * the trigger never reads.
   */
  status?: XMattersStatus;
}

/** One failed message, with its retry lane already mapped. */
export interface XMattersFailedRecord {
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
   * (400 invalid body, 401/403 wrong trigger URL or
   * credentials, and the rest). The 429 lane is a live
   * citation (the Flow triggers page pins the 429
   * rate-limit rejection); the other-4xx lane is the slot
   * convention (see the module header). No per-status
   * error code is claimed from the reference.
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface XMattersSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-306). */
export interface XMattersSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for xMatters send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already received on xMatters' server and are *not* in
 * `failedRecords`.
 */
export class XMattersSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: XMattersFailedRecord[];
  constructor(message: string, failedRecords: XMattersFailedRecord[]) {
    super(message);
    this.name = "XMattersSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class XMattersSinkConfigError extends XMattersSinkError {
  constructor(reason: string) {
    super(`xmatters-sink: ${reason}`, []);
    this.name = "XMattersSinkConfigError";
  }
}

/**
 * Normalize one priority value to the uppercase form the
 * docs pin (HIGH, MEDIUM, LOW). Throws `RangeError` on a
 * value that is not one of the three — the trigger would
 * silently drop an unknown priority, so a typo must fail
 * fast, never reach xMatters.
 */
function normalizeXMattersPriority(value: unknown, label: string): XMattersPriority {
  if (typeof value !== "string") {
    throw new RangeError(`${label} must be one of HIGH, MEDIUM, LOW`);
  }
  const normalized = value.toUpperCase().trim();
  if (!(XMATTERS_PRIORITIES as readonly string[]).includes(normalized)) {
    throw new RangeError(`${label} must be one of HIGH, MEDIUM, LOW`);
  }
  return normalized as XMattersPriority;
}

/**
 * Normalize one status value to the lowercase form this
 * sink matches. Throws `RangeError` on a value that is
 * not firing or resolved — an unknown status has no
 * meaning through this workflow.
 */
function normalizeXMattersStatus(value: unknown, label: string): XMattersStatus {
  if (typeof value !== "string") {
    throw new RangeError(`${label} must be one of firing, resolved`);
  }
  const normalized = value.toLowerCase().trim();
  if (!(XMATTERS_STATUSES as readonly string[]).includes(normalized)) {
    throw new RangeError(`${label} must be one of firing, resolved`);
  }
  return normalized as XMattersStatus;
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery.
 * The recipients, when set, must be a non-empty string; the
 * priority, when set, must be one of HIGH, MEDIUM, LOW
 * (case-insensitive — the value is normalized to uppercase,
 * mirroring the docs' uppercase form). There is deliberately
 * no `apiKey` field to validate: the client alone holds the
 * workflow trigger URL.
 */
export function assertValidXMattersSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is XMattersSinkConfig {
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
  if (c.recipients !== undefined && (typeof c.recipients !== "string" || c.recipients === "")) {
    throw new RangeError(at("`recipients` must be a non-empty string when set"));
  }
  if (c.priority !== undefined) {
    normalizeXMattersPriority(c.priority, at("`priority`"));
  }
}

/**
 * Derive one record's summary: the first non-empty value
 * among `subject`, `key`, and `traceId`, in that order.
 * Falls back to the generic `webhook event` summary when the
 * record carries none — an alert sink must not silently
 * drop sourceless events. No truncation is applied: the
 * re-checked documentation states no summary length limit
 * for this endpoint.
 */
export function resolveXMattersSummary(record: XMattersRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return XMATTERS_FALLBACK_TITLE;
}

/**
 * Resolve the recipients: the record's override when set,
 * else the config-held value, else `undefined` (omitted
 * from the body — the trigger URL itself carries a
 * `recipients` parameter). A set value must be a
 * non-empty string, sent verbatim, never re-encoded.
 */
export function resolveXMattersRecipients(
  record: XMattersRecord,
  config: Pick<XMattersSinkConfig, "recipients">
): string | undefined {
  const recipients = record.recipients ?? config.recipients;
  if (recipients === undefined) {
    return undefined;
  }
  if (typeof recipients !== "string" || recipients === "") {
    throw new RangeError("xMatters recipients must be a non-empty string when set");
  }
  return recipients;
}

/**
 * Resolve the priority: the record's override when set,
 * else the config-held value, else `undefined` (omitted
 * from the body — the workflow page's own sample payload
 * carries no priority field, so an unset priority means
 * the workflow's own default governs). The value is
 * normalized to uppercase (the docs pin uppercase), and
 * an illegal value throws `RangeError` — the trigger
 * would silently drop an unknown priority.
 */
export function resolveXMattersPriority(
  record: XMattersRecord,
  config: Pick<XMattersSinkConfig, "priority">
): XMattersPriority | undefined {
  const priority = record.priority ?? config.priority;
  if (priority === undefined) {
    return undefined;
  }
  return normalizeXMattersPriority(priority, "xMatters priority");
}

/**
 * Resolve the status: the record's value when set, else
 * `firing`. The value is normalized to lowercase, and an
 * illegal value throws `RangeError`.
 */
export function resolveXMattersStatus(record: XMattersRecord): XMattersStatus {
  return normalizeXMattersStatus(record.status ?? XMATTERS_DEFAULT_STATUS, "xMatters status");
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood an alert.
 */
export function truncateXMattersPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's `message`: only the event's own
 * identifiers — `key=<key>` and `traceId=<traceId>`
 * when present, joined with `"; "` — and, when the event
 * carries no identifiers, the derived summary text, so the
 * message is never empty. Under the `includePayload`
 * opt-in the event body is appended after the identifiers
 * (or after the summary fallback), truncated to
 * `payloadMaxChars` (default 2000). The message itself
 * is never truncated: the re-checked docs state no
 * message length limit.
 */
export function resolveXMattersMessage(
  record: XMattersRecord,
  config: Pick<XMattersSinkConfig, "includePayload" | "payloadMaxChars">
): string {
  const parts: string[] = [];
  if (record.key !== undefined && record.key !== "") {
    parts.push(`key=${record.key}`);
  }
  if (record.traceId !== undefined && record.traceId !== "") {
    parts.push(`traceId=${record.traceId}`);
  }
  const base = parts.length > 0 ? parts.join("; ") : resolveXMattersSummary(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? XMATTERS_DEFAULT_PAYLOAD_MAX_CHARS;
    const payload = truncateXMattersPayload(record.body, limit);
    return `${base}\n\n${payload}`;
  }
  return base;
}

/**
 * Build one record's serialized JSON body: `summary`
 * (the derived summary, never truncated — the re-checked
 * docs state no length limit), `message` (only the
 * `key`/`traceId` identifiers, falling back to the summary
 * text when the event carries neither, so never empty; the
 * event body appended only under the `includePayload`
 * opt-in), `recipients` (the derived recipients, sent only
 * when the config or the record names any — otherwise the
 * trigger URL's own `recipients` parameter governs), and
 * `priority` (the derived priority, sent only when the
 * config or the record sets one — the workflow page's own
 * sample payload carries no priority field). No id field
 * is sent: the workflow's published payload accepts no id
 * or dedup key — the event key appears only inside the
 * `message` identifiers. No credential ever enters the
 * body — the client alone holds the workflow trigger URL.
 */
export function buildXMattersAlertBody(
  record: XMattersRecord,
  config: Pick<XMattersSinkConfig, "includePayload" | "payloadMaxChars" | "recipients" | "priority">
): string {
  const alert: {
    summary: string;
    message: string;
    recipients?: string;
    priority?: string;
  } = {
    summary: resolveXMattersSummary(record),
    message: resolveXMattersMessage(record, config),
  };
  const recipients = resolveXMattersRecipients(record, config);
  if (recipients !== undefined) {
    alert.recipients = recipients;
  }
  const priority = resolveXMattersPriority(record, config);
  if (priority !== undefined) {
    alert.priority = priority;
  }
  return JSON.stringify(alert);
}

/**
 * Validate one record. Throws `RangeError` on an empty
 * body string — even without the opt-in, the body is the
 * record's payload, and an empty record is a caller bug
 * that must fail closed, never alert as an empty message.
 * A bad per-record `recipients` or `priority` value fails
 * here too (the config-level check in
 * `assertValidXMattersSinkConfig` only covers the config
 * defaults). A resolved record fails closed here: the
 * workflow's published configuration payload carries no
 * status or signal field, so a resolve has no faithful
 * mapping through this workflow — sending it as a firing
 * alert would page people for an incident that is already
 * over, and inventing a status field would send a key the
 * trigger never reads (see the module header).
 */
export function resolveXMattersRecord(
  record: XMattersRecord,
  index: number,
  config: Pick<XMattersSinkConfig, "recipients" | "priority">
): { index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`xmatters-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  // Validate the per-record recipients and priority (each
  // throws `RangeError` on an illegal value).
  resolveXMattersRecipients(record, config);
  resolveXMattersPriority(record, config);
  if (resolveXMattersStatus(record) === "resolved") {
    throw new RangeError(
      `xmatters-sink: record ${index} a resolved alert has no mapping through the Trigger Alerts by Webhook workflow (its published payload carries no status field)`
    );
  }
  return { index };
}

/**
 * Map one xMatters POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — the Flow triggers page pins the 429
 * itself (a per-minute plan limit, "rejected with a 429
 * error and will not be queued for processing"), so the
 * 429 lane is a live citation. Every other non-2xx status
 * (400 invalid body, 401/403 wrong trigger URL or
 * credentials, and the rest) is a fail-closed message: an
 * invalid body will never become valid on retry. Honesty
 * note: the re-checked references pin the 429 but publish
 * no other per-status 4xx mention, so the other-4xx lane
 * is the slot convention for the unlisted statuses, not a
 * per-status claim from those pages — and no per-status
 * error code is invented here. Callers only pass non-2xx
 * statuses here; any 2xx is acceptance on its own (see
 * `classifyXMattersAlertResponse`).
 */
export function classifyXMattersRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * The verdict on one alert POST: either an acceptance,
 * or a failure with its error code and retry lane.
 */
export type XMattersAlertVerdict =
  | { accepted: true }
  | { accepted: false; errorCode: string; retryable: boolean; errorMessage?: string };

/**
 * Decide one alert POST's verdict from the response the
 * client reported. Any 2xx is acceptance — the tentative
 * rule (see the module header: no re-checked source states
 * a success status code). A 2xx is only an acceptance
 * receipt, not an alert: the alert itself is created by
 * xMatters. No receipt id is required or collected as an
 * acceptance condition: the re-checked documentation
 * states no response id for this endpoint, so `send()`
 * returns no ids. Any non-2xx status is a failure with an
 * `HTTP_<status>` code and the WR-210 lane; the error text
 * rides on the failure record when the client surfaced
 * one. No per-status error code is claimed from the
 * reference. If the reference later pins a single success
 * status, only this function needs to change.
 */
export function classifyXMattersAlertResponse(
  response: XMattersAlertPostResponse
): XMattersAlertVerdict {
  if (response.status >= 200 && response.status < 300) {
    return { accepted: true };
  }
  const verdict: XMattersAlertVerdict = {
    accepted: false,
    errorCode: `HTTP_${response.status}`,
    retryable: classifyXMattersRecordFailure(response.status),
  };
  if (response.errorMessage !== undefined && response.errorMessage !== "") {
    verdict.errorMessage = response.errorMessage;
  }
  return verdict;
}

/**
 * xMatters sink (WR-306). One alert is sent per record; the
 * caller owns retry / dead-letter policy around `send()`
 * — this class performs one POST attempt per message
 * through the injected client and reports its outcome.
 * Failures throw `XMattersSinkError` carrying exactly the
 * failed messages with their retry lanes. The sink keeps
 * no per-alert state: a retry re-POSTs the same summary
 * and message, and whether xMatters treats it as a second
 * alert is governed by the workflow's own flood-control
 * settings — the sink claims no dedup behaviour (see the
 * module header).
 */
export class XMattersSink {
  private readonly cfg: XMattersSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: XMattersSinkConfig) {
    assertValidXMattersSinkConfig(config, "XMattersSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): XMattersSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send the alerts, in input order. Throws
   * `XMattersSinkConfigError` when no client was injected,
   * and `XMattersSinkError` when any message fails
   * (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: XMattersRecord[]): Promise<XMattersSendResult> {
    const resolved = records.map((r, i) => resolveXMattersRecord(r, i, this.cfg));
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
      throw new XMattersSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const failedRecords: XMattersFailedRecord[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          headers: {
            "Content-Type": XMATTERS_JSON_CONTENT_TYPE,
          },
          body: buildXMattersAlertBody(records[i], this.cfg),
        });
        const verdict = classifyXMattersAlertResponse(response);
        if (verdict.accepted) {
          // Any 2xx is acceptance on its own (tentative —
          // see the module header): the status is the
          // acceptance receipt, and the alert itself is
          // created by xMatters — the response is an
          // acceptance receipt, not an alert. No receipt id
          // is claimed: the re-checked documentation states
          // no response id for this endpoint.
          sent += 1;
          continue;
        }
        const failed: XMattersFailedRecord = {
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
        failedRecords.push(toXMattersFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new XMattersSinkError(
        `xmatters-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent };
  }
}

/**
 * Convert a client throw into a failed message: a codeless
 * transport failure (`TRANSPORT_ERROR`, retryable — the SQS
 * no-status rule). A retry re-POSTs the same summary and
 * message; whether xMatters treats it as a second alert is
 * governed by the workflow's own flood-control settings
 * (see the module header).
 */
function toXMattersFailedRecord(err: unknown, index: number): XMattersFailedRecord {
  const failed: XMattersFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
