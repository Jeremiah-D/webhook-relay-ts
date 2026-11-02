/**
 * Grafana OnCall on-call alert delivery sink (WR-302).
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
 * `description`/`status`/`event_id` envelope, and the
 * SIGNL4 sink (WR-301) posts an alert to a SIGNL4 team
 * webhook with a `Title`/`Message`/`X-S4-ExternalID`/
 * `X-S4-Status`/`X-S4-SourceSystem` envelope, this sink
 * posts an alert to a Grafana OnCall webhook
 * integration: one event is sent as one POST that
 * Grafana OnCall routes into that integration's alert
 * groups, and Grafana OnCall — not the relay — owns the
 * alert, the escalation, the notification, and the alert
 * lifecycle.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Grafana
 * OnCall server. The sink owns the relay-side concerns — the
 * status, the title derivation, the message, the grouping
 * id, the payload-inclusion policy, the per-message
 * failure mapping — and the injected client owns the wire
 * protocol, including the POST call, the integration
 * webhook URL, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { headers: { "Content-Type": "application/json" },
 *     body: "{\"title\":\"<title>\",\"message\":\"key=<key>; traceId=<traceId>\",\"state\":\"alerting\",\"ruleId\":\"<key>\"}" }
 *
 * The client POSTs to the integration webhook URL it alone
 * holds — `https://<host>/integrations/v1/webhook/
 * <token>/` — sending `body` verbatim as the
 * request body (JSON) and sending `headers` verbatim as
 * the request headers. Seven things about this shape are
 * deliberate, and all follow the sibling sinks or the
 * backlog pins:
 *
 * - The integration webhook URL — token in the URL path
 *   — is held by the client alone. The sink never
 *   receives the token, never places it in the request,
 *   and never logs it: the sink config has no `apiKey`
 *   field at all, and the handed request carries no URL
 *   at all (like the ilert, Zenduty, Squadcast, and
 *   SIGNL4 sinks, unlike the Opsgenie sink, whose handed
 *   request carries the bare endpoint URL), so there is
 *   nothing in it for a log line or a retry queue to leak
 *   — and the token is never persisted by the sink. The
 *   token rides in the URL path (like the ilert sink's
 *   alert-source URL and the Zenduty sink's Generic
 *   Integration webhook URL, unlike the Opsgenie sink's
 *   `Authorization: GenieKey <key>` header and the
 *   PagerDuty sink's `routing_key` inside the body), so
 *   the sink hands the client the bare `Content-Type`
 *   header and the body and the client posts to the
 *   webhook URL it was configured with: the sink's
 *   request never contains a token, a placeholder, or
 *   anything that looks like one, and there is no
 *   `Authorization` header. This is the Grafana OnCall
 *   form of the MagicBell rule (whose Project JWT the
 *   client alone holds as an `Authorization: Bearer`
 *   header), with Grafana OnCall's own credential source:
 *   the token of a Grafana OnCall webhook integration,
 *   verified against the current docs (Grafana OnCall
 *   webhook integration, re-checked 2026-11-02 — request
 *   URL `https://<host>/integrations/v1/webhook/
 *   <token>/`, e.g. `https://a-prod-us-central-0.
 *   grafana.net/integrations/v1/webhook/<token>/`).
 * - The endpoint is the webhook integration the backlog
 *   pins: `POST https://<host>/integrations/v1/webhook/
 *   <token>/`. The client substitutes the host and token
 *   from the webhook URL it holds; the sink never builds
 *   the URL, so the sink cannot leak, log, or misroute
 *   the token. The `formatted_webhook` variant —
 *   `https://<host>/integrations/v1/formatted_webhook/
 *   <token>/` — is the same endpoint shape with the
 *   same payload: the LibreNMS Grafana OnCall transport
 *   docs state the difference between the two is small
 *   and the formatted webhook only gives a clearer
 *   default view, i.e. the variant is a server-side
 *   integration-type choice (which URL the client
 *   holds), not a second sink shape, so this sink sends
 *   the identical `{title, message, state, ...}` body to
 *   either URL and never selects between them.
 * - `title` is mandatory, so it is derived as the first
 *   non-empty value among `subject`, `key`, and
 *   `traceId`, in that order, falling back to the generic
 *   `webhook event`: an alert sink that silently dropped
 *   sourceless events would hide exactly the deliveries
 *   an operator most needs to see. No truncation is
 *   applied: the re-checked documentation states no
 *   title length limit for this endpoint, and inventing
 *   one would silently cut an operator's alert text.
 * - `message` is mandatory, so it is derived from the
 *   event's own identifiers — `key=<key>;
 *   traceId=<traceId>` when present (the ilert `details`
 *   form) — and falls back to the derived title text
 *   when the event carries no identifiers, so it is never
 *   empty: a messageless alert would hide exactly the
 *   context an operator most needs to see. No truncation
 *   is applied to the identifiers or the fallback text:
 *   the re-checked documentation states no message
 *   length limit for this endpoint.
 * - `state` is one of `alerting` and `OK` (the two
 *   values the re-checked docs pin for the webhook
 *   integration's default templates). It is config-held
 *   with a per-record override, defaulting to firing
 *   (`alerting`): the relay does not invent a lifecycle
 *   transition it was not told. The resolve signal is
 *   the documented default-template rule `{{ 1 if
 *   payload.state == 'OK' else 0 }}` → Resolve Signal
 *   (Grafana OnCall Jinja2 templating docs), corroborated
 *   by the LibreNMS transport's autoresolution template
 *   `{{ payload.get("raw_state", "") != 2 and
 *   payload.get("state", "").upper() == "OK" }}` — so a
 *   `resolved` record sends `state` exactly `"OK"` (the
 *   casing the default template compares against, not a
 *   lowercase guess) and a firing record sends
 *   `"alerting"`. A `resolved` without a key fails closed
 *   with a `RangeError` before any POST is made: without
 *   a `ruleId` Grafana OnCall cannot associate the call
 *   with an open alert group, so the call must never be
 *   sent keyless (the ilert ACCEPT/RESOLVE rule). The
 *   sink still sends the derived title and message on a
 *   resolve, keeping one uniform envelope instead of a
 *   second, resolve-only shape; the message is never
 *   empty either way (see above).
 * - `ruleId` is the event's `key`, sent when one exists
 *   and omitted entirely when the event carries none: the
 *   docs map `{{ payload.ruleId }}` → Grouping Id, so a
 *   second alert carrying the same rule id while the
 *   first is still open is grouped into the same alert
 *   group instead of creating a new one, and sending
 *   `state` `"OK"` with the same rule id resolves that
 *   group. Feeding the event key into `ruleId` is the
 *   slot convention — the docs pin the field-to-grouping
 *   mapping, not which caller value fills it — and the
 *   rule id is sent verbatim, never truncated:
 *   truncating a grouping key would silently merge
 *   distinct alerts. The same rule id also makes a
 *   transport-failure retry safe: replaying the same
 *   record reuses the same rule id, so the retry lands
 *   on the open alert group instead of paging the
 *   on-call engineer twice.
 * - `severity` is an unvalidated verbatim passthrough,
 *   sent only when the record supplies one and omitted
 *   entirely otherwise: a published webhook example for
 *   this exact endpoint posts `"severity": "critical"`
 *   in the body, but the re-checked Grafana docs pin no
 *   severity field, no severity enum, and no severity
 *   mapping for the webhook integration — so the sink
 *   validates no values, invents no default, and never
 *   sends a severity it was not given. `imageUrl` and
 *   `link_to_upstream_details` are out of scope: the
 *   docs map `{{ payload.imageUrl }}` → Image Url and
 *   the LibreNMS template shows `link_to_upstream_
 *   details`, but the relay's record carries no image URL
 *   and no upstream URL, and the sink never invents
 *   either. No `Idempotency-Key` header is sent: the
 *   reference documents no idempotency key for this
 *   endpoint, and the rule id already gives a retry its
 *   grouping key (see above).
 * - `payload` carries only the event's own identifiers
 *   by default — `key` and `traceId` when present,
 *   nothing else — so the alert's message stays
 *   identifiers, never event body: here that means the
 *   `message` carries the identifiers only (see above).
 *   Under the `includePayload` opt-in the event body is
 *   appended to the `message` after the identifiers (or
 *   after the title-text fallback, when the event
 *   carries no identifiers), truncated to
 *   `payloadMaxChars` characters (default 2000).
 *
 * Acceptance is decided by the HTTP status alone, and
 * any 2xx status is acceptance: the OnCall engine's own
 * access log for a live webhook POST shows `status=200
 * method=POST path=/integrations/v1/webhook/<token>/`,
 * and the task pins 2xx as acceptance — so 200 is the
 * documented success and the rest of 2xx is accepted
 * under that rule, not as individually documented
 * statuses (see the honesty note below). A 2xx is only
 * an acceptance receipt, not an alert: the alert itself
 * is created by Grafana OnCall. No receipt id is
 * collected: the re-checked documentation states no
 * response id for this endpoint, so `send()` returns no
 * ids (inventing one would be worse than returning
 * none).
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over the HTTP status:
 *
 * - a non-2xx POST throws `GrafanaOnCallSinkError`
 *   carrying every failed message with its retry lane
 *   already mapped, so the caller retries exactly the
 *   failed messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Grafana OnCall
 *   could not accept the alert right now, not that the
 *   payload is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400 (the
 *   submitted body is invalid) and 404 (the webhook URL
 *   is wrong): retrying them burns the retry budget for
 *   nothing, and rerouting them elsewhere would page an
 *   on-call engineer the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload (a retry after a
 *   transport failure reuses the same rule id, so it
 *   lands on the open alert group rather than creating
 *   a second one — see `ruleId` above);
 * - a missing client throws `GrafanaOnCallSinkConfigError`,
 *   which `classifyFailure` maps to `non_retryable`
 *   (the WR-116 rule).
 *
 * One honesty note on the failure mapping: the
 * re-checked references pin the endpoint, the webhook
 * URL form, the `title`/`message`/`state`/`ruleId`
 * body, the `state == 'OK'` resolve rule, the 200
 * success, and the `formatted_webhook` variant — but
 * they publish no 429 or 5xx mention at all. The
 * 429/5xx-retryable, other-4xx-fail-closed mapping above
 * is therefore the slot convention for the unlisted
 * statuses, not a per-status claim from those pages, and
 * no per-status error code is invented here: the failure
 * record carries `HTTP_<status>` plus whatever free-form
 * error text the client surfaced, and nothing more. A
 * second honesty note, on the success status: only 200
 * is documented for this endpoint (the engine log line
 * above); 201 and the rest of 2xx are accepted under
 * the task's 2xx rule, not because any reference pins
 * them — if the reference later pins a single success
 * status, only `classifyGrafanaOnCallAlertResponse`
 * needs to change. A third honesty note, on the
 * archive: as of 2026-03-24 the Grafana OnCall OSS
 * project is archived; the endpoint form above is the
 * Grafana Cloud IRM form, verified against the current
 * docs on 2026-11-02.
 *
 * Zero new dependencies: the injected client only. (No
 * `node:crypto` import either: with no idempotency key to
 * derive, there is nothing to hash.)
 */

/** Generic title used when an event carries no value for the title. */
export const GRAFANA_ONCALL_FALLBACK_TITLE = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const GRAFANA_ONCALL_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Content type the client sends with the JSON body. */
export const GRAFANA_ONCALL_JSON_CONTENT_TYPE = "application/json";

/**
 * Webhook integration URL template, with the segments the
 * client alone holds: `<host>` is the Grafana Cloud stack
 * host (or the self-hosted OnCall host) and `<token>` is
 * the integration token. The client substitutes both from
 * the webhook URL it was configured with; the sink never
 * builds this URL, so no token — real or placeholder —
 * ever passes through the sink. Exported so the URL shape
 * is pinned in tests, not so the sink can construct a
 * request URL.
 */
export const GRAFANA_ONCALL_WEBHOOK_URL_TEMPLATE =
  "https://<host>/integrations/v1/webhook/{token}/";

/**
 * Formatted-webhook integration URL template: the same
 * endpoint shape with the same payload — the variant is a
 * server-side integration-type choice (which URL the
 * client holds), not a second sink shape. See the module
 * header.
 */
export const GRAFANA_ONCALL_FORMATTED_WEBHOOK_URL_TEMPLATE =
  "https://<host>/integrations/v1/formatted_webhook/{token}/";

/** Default alert status. */
export const GRAFANA_ONCALL_DEFAULT_STATUS = "firing";

/** The alert statuses the sink accepts (firing/resolved). */
export const GRAFANA_ONCALL_STATUSES = ["firing", "resolved"] as const;

/** One of the alert statuses the sink accepts (firing/resolved). */
export type GrafanaOnCallAlertStatus = (typeof GRAFANA_ONCALL_STATUSES)[number];

/** Wire `state` sent for a firing alert (the docs' `alerting` value). */
export const GRAFANA_ONCALL_FIRING_STATE = "alerting";

/** Wire `state` sent for a resolved alert (the docs' `OK` value). */
export const GRAFANA_ONCALL_RESOLVED_STATE = "OK";

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (JSON) to the integration webhook
 * URL it alone holds (`https://<host>/integrations/v1/
 * webhook/<token>/`, or the `formatted_webhook` variant),
 * sending `headers` verbatim as the request headers.
 * There is deliberately no `url` field here: the URL
 * carries the integration token in its path, so the sink
 * must never see, build, or hand over a URL — the client
 * posts to the URL it was configured with. No
 * `Authorization` header is sent: the token rides in the
 * URL path, never in a header. No `Idempotency-Key`
 * header is sent: the docs do not verify it for this
 * endpoint, and the rule id already gives a retry its
 * grouping key (see the module header).
 */
export interface GrafanaOnCallAlertPostRequest {
  /**
   * Request headers, sent verbatim:
   * `{ "Content-Type": "application/json" }`. There is
   * deliberately no `url` field: the integration webhook
   * URL (token in the path) is held by the client
   * alone, never by the sink, and there is no
   * `Authorization` header and no `Idempotency-Key`
   * header.
   */
  headers: Record<string, string>;
  /**
   * The JSON request body, serialized:
   * `{"title":"<title>","message":"key=<key>; traceId=<traceId>","state":"alerting","ruleId":"<key>"}`
   * (`message` falls back to the title text when the
   * event carries no identifiers, so it is never empty;
   * the event body is appended to it only under the
   * `includePayload` opt-in; `ruleId` is omitted when
   * the event carries no key; `severity` is sent only
   * when the record supplies one, verbatim).
   * No credential ever enters the body.
   */
  body: string;
}

/**
 * The result of one POST, as reported by the injected
 * client. The HTTP status decides acceptance: any 2xx
 * means Grafana OnCall accepted the alert. The error
 * text, when the client surfaced one, rides on the
 * failure record; no per-status error code is claimed
 * from the reference beyond the documented 200 success
 * (see the module header). No receipt id is collected:
 * the re-checked documentation states no response id
 * for this endpoint.
 */
export interface GrafanaOnCallAlertPostResponse {
  /** The HTTP status of the POST (e.g. 200, 400, 404, 429, 500). */
  status: number;
  /** Free-form error text from the error body, when the client surfaced one. */
  errorMessage?: string;
}

/**
 * The injected Grafana OnCall alert client. Any client adapter
 * implements this one method; it returns the POST's status —
 * a throw is a codeless transport failure, retryable. The
 * client is expected to POST one alert per call, sending
 * `body` verbatim as the request body (JSON), sending
 * `headers` verbatim as the request headers, and posting
 * to the integration webhook URL it alone holds
 * (`https://<host>/integrations/v1/webhook/<token>/`, or
 * the `formatted_webhook` variant) — the sink never sees
 * that URL.
 */
export interface GrafanaOnCallAlertClient {
  post(request: GrafanaOnCallAlertPostRequest): Promise<GrafanaOnCallAlertPostResponse>;
}

/**
 * Configuration for one Grafana OnCall sink. The client is
 * injected: without one, `send()` throws
 * `GrafanaOnCallSinkConfigError` (dry runs excepted — they need
 * no client at all). The integration token is deliberately
 * absent from this config: the client alone holds the
 * integration webhook URL (token in the path), and the
 * token is never persisted by the sink.
 */
export interface GrafanaOnCallSinkConfig {
  /**
   * The Grafana OnCall alert client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `GrafanaOnCallAlertClient` and alone holds
   * the integration webhook URL. Required for real sends; a missing
   * client is a config error, not a silent no-op.
   */
  client?: GrafanaOnCallAlertClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }`
   * and performs zero client I/O — no POST call, no stat
   * changes. Messages are still validated (including
   * status derivation and the resolve rule-id rule),
   * so a dry run catches a malformed record before it
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
   * `message` appends the event body verbatim as a
   * JSON string, truncated to `payloadMaxChars`
   * characters (see below), after the identifiers (or
   * after the title-text fallback, when the event
   * carries no identifiers). When `false` or absent,
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
   * Default alert status: one of firing/resolved, default
   * firing. Config-held, overridable per record (see
   * `GrafanaOnCallRecord.status`): the relay does not invent a
   * lifecycle transition it was not told. Must be one of
   * the two values when set. A configured `resolved`
   * default still needs a rule id on every record
   * — see `resolveGrafanaOnCallRecord`.
   */
  status?: GrafanaOnCallAlertStatus;
}

/** One event to alert about. */
export interface GrafanaOnCallRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Content-derivation source, first priority: the event's
   * subject, when set and non-empty. The alert title.
   */
  subject?: string;
  /**
   * Content-derivation source, second priority: the event's key
   * (e.g. aggregate id). Also the alert's `ruleId` (the
   * documented Grouping Id) and a `message` identifier,
   * when set. Required when the effective status is
   * resolved — without one Grafana OnCall cannot
   * associate the call with an open alert group.
   */
  key?: string;
  /**
   * Content-derivation source, last priority: the trace id.
   * Also a `message` identifier, when set.
   */
  traceId?: string;
  /**
   * Per-record alert status override: one of
   * firing/resolved. When absent, the config's `status`
   * applies, defaulting to firing. A `resolved` override
   * still needs a rule id on this record — see
   * `resolveGrafanaOnCallRecord`.
   */
  status?: GrafanaOnCallAlertStatus;
  /**
   * Optional severity, passed through verbatim when set
   * and omitted entirely when absent: a published webhook
   * example for this endpoint posts `"severity":
   * "critical"`, but the re-checked Grafana docs pin no
   * severity field, enum, or mapping for the webhook
   * integration — so the sink validates no values,
   * invents no default, and never sends a severity it
   * was not given. Must be a non-empty string when set.
   */
  severity?: string;
}

/** One failed message, with its retry lane already mapped. */
export interface GrafanaOnCallFailedRecord {
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
   * (400 invalid body, 404 wrong webhook URL, and the
   * rest). No per-status error code is claimed from the
   * reference beyond the documented 200 success (see the
   * module header).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface GrafanaOnCallSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-302). */
export interface GrafanaOnCallSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Grafana OnCall send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already received on Grafana OnCall's server and are *not* in
 * `failedRecords`.
 */
export class GrafanaOnCallSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: GrafanaOnCallFailedRecord[];
  constructor(message: string, failedRecords: GrafanaOnCallFailedRecord[]) {
    super(message);
    this.name = "GrafanaOnCallSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class GrafanaOnCallSinkConfigError extends GrafanaOnCallSinkError {
  constructor(reason: string) {
    super(`grafana-oncall-sink: ${reason}`, []);
    this.name = "GrafanaOnCallSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery.
 * The status, when set, must be one of firing/resolved.
 * There is deliberately no `apiKey` field to validate: the
 * client alone holds the integration webhook URL.
 */
export function assertValidGrafanaOnCallSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is GrafanaOnCallSinkConfig {
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
      !(GRAFANA_ONCALL_STATUSES as readonly string[]).includes(c.status))
  ) {
    throw new RangeError(at("`status` must be one of firing, resolved when set"));
  }
}

/**
 * Derive one record's alert title: the first non-empty
 * value among `subject`, `key`, and `traceId`, in that
 * order. Falls back to the generic `webhook event` title
 * when the record carries none — an alert sink must not
 * silently drop sourceless events.
 */
export function resolveGrafanaOnCallTitle(record: GrafanaOnCallRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return GRAFANA_ONCALL_FALLBACK_TITLE;
}

/**
 * Resolve the alert status: the record's override when set,
 * else the config-held value, else `firing`.
 */
export function resolveGrafanaOnCallStatus(
  record: GrafanaOnCallRecord,
  config: Pick<GrafanaOnCallSinkConfig, "status">
): GrafanaOnCallAlertStatus {
  return record.status ?? config.status ?? GRAFANA_ONCALL_DEFAULT_STATUS;
}

/**
 * Map one record's resolved status onto the wire `state`:
 * firing → `alerting`, resolved → `OK`. The `OK` casing
 * is the one the documented default-template resolve rule
 * compares against (`{{ 1 if payload.state == 'OK' else 0
 * }}` → Resolve Signal), not a lowercase guess.
 */
export function resolveGrafanaOnCallState(
  record: GrafanaOnCallRecord,
  config: Pick<GrafanaOnCallSinkConfig, "status">
): string {
  return resolveGrafanaOnCallStatus(record, config) === "resolved"
    ? GRAFANA_ONCALL_RESOLVED_STATE
    : GRAFANA_ONCALL_FIRING_STATE;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood an alert.
 */
export function truncateGrafanaOnCallPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's `message`: only the event's own
 * identifiers — `key=<key>` and `traceId=<traceId>`
 * when present, joined with `"; "` — and, when the event
 * carries no identifiers, the derived title text, so the
 * message is never empty. Under the `includePayload`
 * opt-in the event body is appended after the identifiers
 * (or after the title-text fallback), truncated to
 * `payloadMaxChars` (default 2000). The message is never
 * truncated itself: the re-checked docs state no message
 * length limit.
 */
export function resolveGrafanaOnCallMessage(
  record: GrafanaOnCallRecord,
  config: Pick<GrafanaOnCallSinkConfig, "includePayload" | "payloadMaxChars">
): string {
  const parts: string[] = [];
  if (record.key !== undefined && record.key !== "") {
    parts.push(`key=${record.key}`);
  }
  if (record.traceId !== undefined && record.traceId !== "") {
    parts.push(`traceId=${record.traceId}`);
  }
  const base = parts.length > 0 ? parts.join("; ") : resolveGrafanaOnCallTitle(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? GRAFANA_ONCALL_DEFAULT_PAYLOAD_MAX_CHARS;
    const payload = truncateGrafanaOnCallPayload(record.body, limit);
    return `${base}\n\n${payload}`;
  }
  return base;
}

/**
 * Build one record's serialized JSON body: `title` (the
 * derived title, never truncated — the re-checked docs
 * state no title length limit), `message` (only the
 * `key`/`traceId` identifiers, falling back to the title
 * text when the event carries neither, so never empty;
 * the event body appended only under the
 * `includePayload` opt-in), `state` (`alerting` for a
 * firing alert, `OK` for a resolved one — the casing the
 * documented default-template resolve rule compares
 * against), `ruleId` (the event key, omitted when the
 * event carries none — the documented Grouping Id), and
 * `severity` (the record's value verbatim, omitted when
 * the record supplies none — an unvalidated passthrough,
 * since the re-checked docs pin no severity enum). No
 * credential ever enters the body — the client alone
 * holds the integration webhook URL (token in the path).
 */
export function buildGrafanaOnCallAlertBody(
  record: GrafanaOnCallRecord,
  config: Pick<GrafanaOnCallSinkConfig, "includePayload" | "payloadMaxChars" | "status">
): string {
  const alert: {
    title: string;
    message: string;
    state: string;
    ruleId?: string;
    severity?: string;
  } = {
    title: resolveGrafanaOnCallTitle(record),
    message: resolveGrafanaOnCallMessage(record, config),
    state: resolveGrafanaOnCallState(record, config),
  };
  if (record.key !== undefined && record.key !== "") {
    alert.ruleId = record.key;
  }
  if (record.severity !== undefined && record.severity !== "") {
    alert.severity = record.severity;
  }
  return JSON.stringify(alert);
}

/**
 * Validate one record. Throws `RangeError` on an empty
 * body string — even without the opt-in, the body is the
 * record's payload, and an empty record is a caller bug
 * that must fail closed, never alert as an empty message.
 * Also throws `RangeError` when the effective status is
 * `resolved` and the record carries no key: without a
 * `ruleId` Grafana OnCall cannot associate the call with
 * an open alert group, so the call must never be sent
 * keyless. A bad per-record `status` value fails here too
 * (the config-level check in
 * `assertValidGrafanaOnCallSinkConfig` only covers the
 * config default). A `severity` that is set but not a
 * non-empty string fails here too — the sink passes it
 * through verbatim, so a non-string value is a caller bug.
 */
export function resolveGrafanaOnCallRecord(
  record: GrafanaOnCallRecord,
  index: number,
  config: Pick<GrafanaOnCallSinkConfig, "status">
): { index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`grafana-oncall-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  if (
    record.status !== undefined &&
    !(GRAFANA_ONCALL_STATUSES as readonly string[]).includes(record.status)
  ) {
    throw new RangeError(`grafana-oncall-sink: record ${index} \`status\` must be one of firing, resolved when set`);
  }
  if (
    record.severity !== undefined &&
    (typeof record.severity !== "string" || record.severity === "")
  ) {
    throw new RangeError(`grafana-oncall-sink: record ${index} \`severity\` must be a non-empty string when set`);
  }
  const status = resolveGrafanaOnCallStatus(record, config);
  if (
    status === "resolved" &&
    (record.key === undefined || record.key === "")
  ) {
    throw new RangeError(
      `grafana-oncall-sink: record ${index} \`status\` resolved requires an event key (\`key\`), otherwise Grafana OnCall cannot associate the call with an open alert group`
    );
  }
  return { index };
}

/**
 * Map one Grafana OnCall POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says Grafana OnCall could
 * not accept the alert right now, not that the payload is
 * poison. Every other non-2xx status (400 invalid body, 404
 * wrong webhook URL, and the rest) is a fail-closed message:
 * an invalid body will never become valid on retry. Honesty
 * note: the re-checked references publish no 429 or 5xx
 * mention at all, so this mapping is the slot convention
 * for the unlisted statuses, not a per-status claim from
 * those pages — and no per-status error code is invented
 * here. Callers only pass non-2xx statuses here; 2xx is
 * acceptance on its own (see
 * `classifyGrafanaOnCallAlertResponse`).
 */
export function classifyGrafanaOnCallRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * The verdict on one alert POST: either an acceptance,
 * or a failure with its error code and retry lane.
 */
export type GrafanaOnCallAlertVerdict =
  | { accepted: true }
  | { accepted: false; errorCode: string; retryable: boolean; errorMessage?: string };

/**
 * Decide one alert POST's verdict from the response the
 * client reported. Any 2xx status is acceptance — 200 is
 * the documented success (the OnCall engine's access log
 * for a live webhook POST shows `status=200`), and the
 * rest of 2xx is accepted under the task's 2xx rule, not
 * as individually documented statuses. A 2xx is only an
 * acceptance receipt, not an alert: the alert itself is
 * created by Grafana OnCall. No receipt id is required or
 * collected as an acceptance condition: the re-checked
 * documentation states no response id for this endpoint,
 * so `send()` returns no ids. Any non-2xx status is a
 * failure with an `HTTP_<status>` code and the WR-210
 * lane; the error text rides on the failure record when
 * the client surfaced one. No per-status error code is
 * claimed from the reference beyond the documented 200
 * success (see the module header).
 */
export function classifyGrafanaOnCallAlertResponse(
  response: GrafanaOnCallAlertPostResponse
): GrafanaOnCallAlertVerdict {
  if (response.status >= 200 && response.status < 300) {
    return { accepted: true };
  }
  const verdict: GrafanaOnCallAlertVerdict = {
    accepted: false,
    errorCode: `HTTP_${response.status}`,
    retryable: classifyGrafanaOnCallRecordFailure(response.status),
  };
  if (response.errorMessage !== undefined && response.errorMessage !== "") {
    verdict.errorMessage = response.errorMessage;
  }
  return verdict;
}

/**
 * Grafana OnCall sink (WR-302). One alert is sent per record; the
 * caller owns retry / dead-letter policy around `send()`
 * — this class performs one POST attempt per message
 * through the injected client and reports its outcome.
 * Failures throw `GrafanaOnCallSinkError` carrying exactly the
 * failed messages with their retry lanes. The sink keeps
 * no per-alert state: a later `resolved` carrying the
 * same `ruleId` is sent exactly like any other alert, and
 * Grafana OnCall resolves the alert group — the sink
 * does not try to track that.
 */
export class GrafanaOnCallSink {
  private readonly cfg: GrafanaOnCallSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: GrafanaOnCallSinkConfig) {
    assertValidGrafanaOnCallSinkConfig(config, "GrafanaOnCallSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): GrafanaOnCallSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send the alerts, in input order. Throws
   * `GrafanaOnCallSinkConfigError` when no client was injected,
   * and `GrafanaOnCallSinkError` when any message fails
   * (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: GrafanaOnCallRecord[]): Promise<GrafanaOnCallSendResult> {
    const resolved = records.map((r, i) => resolveGrafanaOnCallRecord(r, i, this.cfg));
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
      throw new GrafanaOnCallSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const failedRecords: GrafanaOnCallFailedRecord[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          headers: {
            "Content-Type": GRAFANA_ONCALL_JSON_CONTENT_TYPE,
          },
          body: buildGrafanaOnCallAlertBody(records[i], this.cfg),
        });
        const verdict = classifyGrafanaOnCallAlertResponse(response);
        if (verdict.accepted) {
          // Any 2xx is acceptance on its own: the status
          // is the acceptance receipt, and the alert itself
          // is created by Grafana OnCall — the response is an
          // acceptance receipt, not an alert. No receipt id
          // is claimed: the re-checked documentation states
          // no response id for this endpoint.
          sent += 1;
          continue;
        }
        const failed: GrafanaOnCallFailedRecord = {
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
        failedRecords.push(toGrafanaOnCallFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new GrafanaOnCallSinkError(
        `grafana-oncall-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent };
  }
}

/**
 * Convert a client throw into a failed message: a codeless
 * transport failure (`TRANSPORT_ERROR`, retryable — the SQS
 * no-status rule). A retry reuses the same rule id, so it
 * lands on the open alert group rather than creating a
 * second one (see the module header).
 */
function toGrafanaOnCallFailedRecord(err: unknown, index: number): GrafanaOnCallFailedRecord {
  const failed: GrafanaOnCallFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
