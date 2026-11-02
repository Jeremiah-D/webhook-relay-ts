/**
 * Spike.sh on-call alert delivery sink (WR-303).
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
 * `X-S4-Status`/`X-S4-SourceSystem` envelope, and the
 * Grafana OnCall sink (WR-302) posts an alert to a
 * Grafana OnCall webhook integration with a `title`/
 * `message`/`state`/`ruleId` envelope, this sink posts
 * an incident to a Spike.sh webhook integration: one
 * event is sent as one POST that Spike.sh routes into
 * that service's escalation policy, and Spike.sh — not
 * the relay — owns the incident, the escalation, the
 * notification, and the incident lifecycle.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Spike.sh
 * server. The sink owns the relay-side concerns — the
 * status, the title derivation, the body, the severity,
 * the priority, the resolve signal, the payload-inclusion
 * policy, the per-message failure mapping — and the
 * injected client owns the wire protocol, including the
 * POST call, the webhook integration URL, and the status
 * it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { headers: { "Content-Type": "application/json" },
 *     body: "{\"title\":\"<title>\",\"body\":\"key=<key>; traceId=<traceId>\",\"severity\":\"sev1\",\"priority\":\"p1\"}" }
 *
 * The client POSTs to the webhook integration URL it
 * alone holds — `https://hooks.spike.sh/:token/
 * push-events` — sending `body` verbatim as the
 * request body (JSON) and sending `headers` verbatim as
 * the request headers. Eight things about this shape are
 * deliberate, and all follow the sibling sinks or the
 * backlog pins:
 *
 * - The webhook integration URL — token in the URL path
 *   — is held by the client alone. The sink never
 *   receives the token, never places it in the request,
 *   and never logs it: the sink config has no `apiKey`
 *   field at all, and the handed request carries no URL
 *   at all (like the ilert, Zenduty, Squadcast, SIGNL4,
 *   and Grafana OnCall sinks, unlike the Opsgenie sink,
 *   whose handed request carries the bare endpoint URL),
 *   so there is nothing in it for a log line or a retry
 *   queue to leak — and the token is never persisted by
 *   the sink. The token rides in the URL path (like the
 *   ilert sink's alert-source URL and the Zenduty sink's
 *   Generic Integration webhook URL, unlike the Opsgenie
 *   sink's `Authorization: GenieKey <key>` header and the
 *   PagerDuty sink's `routing_key` inside the body), so
 *   the sink hands the client the bare `Content-Type`
 *   header and the body and the client posts to the
 *   webhook URL it was configured with: the sink's
 *   request never contains a token, a placeholder, or
 *   anything that looks like one, and there is no
 *   `Authorization` header. This is the Spike.sh form of
 *   the MagicBell rule (whose Project JWT the client
 *   alone holds as an `Authorization: Bearer` header),
 *   with Spike.sh's own credential source: the token of
 *   a Spike.sh webhook integration, verified against the
 *   current docs (docs.spike.sh "Integrating with
 *   Webhooks", re-checked 2026-11-02 — request URL
 *   `https://hooks.spike.sh/:token/push-events`).
 * - The endpoint is the webhook integration the backlog
 *   pins: `POST https://hooks.spike.sh/:token/
 *   push-events`. The client substitutes the token from
 *   the webhook URL it holds; the sink never builds the
 *   URL, so the sink cannot leak, log, or misroute the
 *   token.
 * - `title` is mandatory, so it is derived as the first
 *   non-empty value among `subject`, `key`, and
 *   `traceId`, in that order, falling back to the generic
 *   `webhook event`: an alert sink that silently dropped
 *   sourceless events would hide exactly the deliveries
 *   an operator most needs to see. No truncation is
 *   applied: the re-checked documentation states no
 *   title length limit for this endpoint, and inventing
 *   one would silently cut an operator's alert text.
 *   The docs warn that failing to add a title creates an
 *   empty incident that will not group, suppress, or
 *   auto-resolve — which is exactly why the sink never
 *   sends a missing title: the derived title is always
 *   non-empty (see above), so every incident the sink
 *   creates carries a title that can group, suppress,
 *   and auto-resolve.
 * - `body` is mandatory, so it is derived from the
 *   event's own identifiers — `key=<key>;
 *   traceId=<traceId>` when present (the ilert `details`
 *   form) — and falls back to the derived title text
 *   when the event carries no identifiers, so it is never
 *   empty: a bodyless incident would hide exactly the
 *   context an operator most needs to see. No truncation
 *   is applied to the identifiers or the fallback text:
 *   the re-checked documentation states no body length
 *   limit for this endpoint. The docs say the body
 *   accepts objects and strings; the sink sends a
 *   string, which is one of the two documented forms.
 * - `severity` is one of `sev1`, `sev2`, and `sev3`
 *   (the three values the re-checked docs pin). It is
 *   config-held with a per-record override, and omitted
 *   entirely when neither supplies one: the docs state
 *   no default severity, and inventing one would
 *   silently escalate (or de-escalate) an operator's
 *   incident. An illegal value fails at construction
 *   (config) or at record validation (per-record) with a
 *   `RangeError` — a typo must fail fast, never reach
 *   Spike.sh as an invented severity.
 * - `priority` is one of `p1`, `p2`, `p3`, `p4`, and
 *   `p5` (the five values the re-checked docs pin). It
 *   follows the same rule as `severity`: config-held
 *   with a per-record override, omitted entirely when
 *   neither supplies one (the docs state no default
 *   priority), and an illegal value fails with a
 *   `RangeError` at construction or at record
 *   validation.
 * - `status` is the resolve signal. It is config-held
 *   with a per-record override, defaulting to firing —
 *   and a firing alert sends no `status` field at all
 *   (creation is the absence of a status: the docs show
 *   the create-incident body with no `status` field).
 *   A resolved record sends `status` exactly
 *   `"resolve"` (the one value the re-checked docs pin
 *   for auto-resolve) with the same title the incident
 *   was created with: the docs resolve open incidents by
 *   title plus token, and warn that resolving with a
 *   different title will not work. The sink still sends
 *   the derived title and body on a resolve, keeping one
 *   uniform envelope instead of a second, resolve-only
 *   shape; the body is never empty either way (see
 *   above). Unlike the Squadcast and ilert sinks, a
 *   keyless resolve does NOT fail closed here: the title
 *   is always non-empty (the subject/key/traceId chain
 *   plus the `webhook event` fallback), so a keyless
 *   resolve is still a well-formed resolve call — but it
 *   resolves by the fallback title, which almost
 *   certainly matches no open incident, so the README
 *   warns the operator to resolve with the same key (and
 *   therefore the same title) as the firing alert. The
 *   title itself is the grouping, suppression, and
 *   auto-resolve key: the docs state that an open
 *   incident with the same title suppresses a second
 *   create, so the title is sent verbatim, never
 *   truncated — truncating a grouping key would silently
 *   merge distinct incidents. The same title also makes
 *   a transport-failure retry safe: replaying the same
 *   record reuses the same title, so the retry lands on
 *   the open incident instead of paging the on-call
 *   engineer twice.
 * - `payload` carries only the event's own identifiers
 *   by default — `key` and `traceId` when present,
 *   nothing else — so the incident's body stays
 *   identifiers, never event body: here that means the
 *   `body` carries the identifiers only (see above).
 *   Under the `includePayload` opt-in the event body is
 *   appended to the `body` after the identifiers (or
 *   after the title-text fallback, when the event
 *   carries no identifiers), truncated to
 *   `payloadMaxChars` characters (default 2000). No
 *   `Idempotency-Key` header is sent: the reference
 *   documents no idempotency key for this endpoint, and
 *   the title already gives a retry its grouping key
 *   (see above).
 *
 * Acceptance is decided by the HTTP status alone, and
 * the success status is pinned to exactly `200`: the
 * re-checked docs show a successful request returning
 * `200` with the body `{ Ok: true }`, and state "A
 * successful request will get you 200 HTTP response
 * status code" — so 200 is acceptance and any other
 * status is a failure (see the honesty note below). A
 * 200 is only an acceptance receipt, not an incident:
 *   the incident itself is created by Spike.sh. No
 * receipt id is collected: the re-checked documentation
 * states no response id for this endpoint, so `send()`
 * returns no ids (inventing one would be worse than
 * returning none).
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over the HTTP status:
 *
 * - a non-200 POST throws `SpikeSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Spike.sh could
 *   not accept the incident right now, not that the
 *   payload is poison (the docs show a 500 example
 *   response, `{}` — "Could not process your request");
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-200 status, including 400 (the
 *   submitted body is invalid) and 404 (the webhook URL
 *   is wrong): retrying them burns the retry budget for
 *   nothing, and rerouting them elsewhere would page an
 *   on-call engineer the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload (a retry after a
 *   transport failure reuses the same title, so it lands
 *   on the open incident rather than creating a second
 *   one — see `status` above);
 * - a missing client throws `SpikeSinkConfigError`,
 *   which `classifyFailure` maps to `non_retryable`
 *   (the WR-116 rule).
 *
 * One honesty note on the failure mapping: the
 * re-checked reference pins the endpoint, the webhook
 * URL form, the `title`/`body`/`severity`/`priority`/
 * `status` body, the sev1–sev3 and p1–p5 enums, the
 * same-title grouping/suppression/auto-resolve rules,
 * the `status: "resolve"` auto-resolve rule, the 200
 * success with its `{ Ok: true }` body, and a 500
 * example error — but it publishes no 429 or per-status
 * 4xx mention at all. The 429/5xx-retryable, other-4xx-
 * fail-closed mapping above is therefore the slot
 * convention for the unlisted statuses, not a per-status
 * claim from that page, and no per-status error code is
 * invented here: the failure record carries `HTTP_<status>`
 * plus whatever free-form error text the client surfaced,
 * and nothing more. A second honesty note, on the
 * success status: only 200 is documented for this
 * endpoint; a 201 from a proxy or a future revision is
 * not a documented success and is treated as an
 * `HTTP_201` failure, fail-closed — if the reference
 * later pins a second success status, only
 * `classifySpikeIncidentResponse` needs to change.
 *
 * Zero new dependencies: the injected client only. (No
 * `node:crypto` import either: with no idempotency key to
 * derive, there is nothing to hash.)
 */

/** Generic title used when an event carries no value for the title. */
export const SPIKE_FALLBACK_TITLE = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const SPIKE_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Content type the client sends with the JSON body. */
export const SPIKE_JSON_CONTENT_TYPE = "application/json";

/**
 * Webhook integration URL template, with the segment the
 * client alone holds: `{token}` is the webhook
 * integration token. The client substitutes it from the
 * webhook URL it was configured with; the sink never
 * builds this URL, so no token — real or placeholder —
 * ever passes through the sink. Exported so the URL shape
 * is pinned in tests, not so the sink can construct a
 * request URL.
 */
export const SPIKE_WEBHOOK_URL_TEMPLATE =
  "https://hooks.spike.sh/{token}/push-events";

/** Default alert status. */
export const SPIKE_DEFAULT_STATUS = "firing";

/** The alert statuses the sink accepts (firing/resolved). */
export const SPIKE_STATUSES = ["firing", "resolved"] as const;

/** One of the alert statuses the sink accepts (firing/resolved). */
export type SpikeAlertStatus = (typeof SPIKE_STATUSES)[number];

/** Wire `status` sent for a resolved alert (the docs' `resolve` value). */
export const SPIKE_RESOLVED_STATUS = "resolve";

/** The severities the re-checked docs pin. */
export const SPIKE_SEVERITIES = ["sev1", "sev2", "sev3"] as const;

/** One of the severities the re-checked docs pin. */
export type SpikeSeverity = (typeof SPIKE_SEVERITIES)[number];

/** The priorities the re-checked docs pin. */
export const SPIKE_PRIORITIES = ["p1", "p2", "p3", "p4", "p5"] as const;

/** One of the priorities the re-checked docs pin. */
export type SpikePriority = (typeof SPIKE_PRIORITIES)[number];

/** The documented success status. */
export const SPIKE_SUCCESS_STATUS = 200;

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (JSON) to the webhook integration
 * URL it alone holds (`https://hooks.spike.sh/:token/
 * push-events`), sending `headers` verbatim as the
 * request headers. There is deliberately no `url` field
 * here: the URL carries the integration token in its path,
 * so the sink must never see, build, or hand over a URL —
 * the client posts to the URL it was configured with. No
 * `Authorization` header is sent: the token rides in the
 * URL path, never in a header. No `Idempotency-Key`
 * header is sent: the docs do not verify it for this
 * endpoint, and the title already gives a retry its
 * grouping key (see the module header).
 */
export interface SpikeIncidentPostRequest {
  /**
   * Request headers, sent verbatim:
   * `{ "Content-Type": "application/json" }`. There is
   * deliberately no `url` field: the webhook integration
   * URL (token in the path) is held by the client
   * alone, never by the sink, and there is no
   * `Authorization` header and no `Idempotency-Key`
   * header.
   */
  headers: Record<string, string>;
  /**
   * The JSON request body, serialized:
   * `{"title":"<title>","body":"key=<key>; traceId=<traceId>","severity":"sev1","priority":"p1"}`
   * (`body` falls back to the title text when the
   * event carries no identifiers, so it is never empty;
   * the event body is appended to it only under the
   * `includePayload` opt-in; `severity` and `priority`
   * are omitted when neither the record nor the config
   * supplies them; `status` is omitted for a firing
   * alert and is exactly `"resolve"` for a resolved
   * one). No credential ever enters the body.
   */
  body: string;
}

/**
 * The result of one POST, as reported by the injected
 * client. The HTTP status decides acceptance: exactly 200
 * means Spike.sh accepted the incident (`{ Ok: true }`
 * in the docs). The error text, when the client surfaced
 * one, rides on the failure record; no per-status error
 * code is claimed from the reference beyond the
 * documented 500 example (see the module header). No
 * receipt id is collected: the re-checked documentation
 * states no response id for this endpoint.
 */
export interface SpikeIncidentPostResponse {
  /** The HTTP status of the POST (e.g. 200, 400, 404, 429, 500). */
  status: number;
  /** Free-form error text from the error body, when the client surfaced one. */
  errorMessage?: string;
}

/**
 * The injected Spike.sh incident client. Any client adapter
 * implements this one method; it returns the POST's status —
 * a throw is a codeless transport failure, retryable. The
 * client is expected to POST one incident per call, sending
 * `body` verbatim as the request body (JSON), sending
 * `headers` verbatim as the request headers, and posting
 * to the webhook integration URL it alone holds
 * (`https://hooks.spike.sh/:token/push-events`) — the sink
 * never sees that URL.
 */
export interface SpikeIncidentClient {
  post(request: SpikeIncidentPostRequest): Promise<SpikeIncidentPostResponse>;
}

/**
 * Configuration for one Spike.sh sink. The client is
 * injected: without one, `send()` throws
 * `SpikeSinkConfigError` (dry runs excepted — they need
 * no client at all). The integration token is deliberately
 * absent from this config: the client alone holds the
 * webhook integration URL (token in the path), and the
 * token is never persisted by the sink.
 */
export interface SpikeSinkConfig {
  /**
   * The Spike.sh incident client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `SpikeIncidentClient` and alone holds the
   * webhook integration URL. Required for real sends; a missing
   * client is a config error, not a silent no-op.
   */
  client?: SpikeIncidentClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }`
   * and performs zero client I/O — no POST call, no stat
   * changes. Messages are still validated (including
   * status, severity, and priority derivation), so a dry
   * run catches a malformed record before it reaches
   * production. Mirrors the `dryRun` convention of the
   * S3 offloaders. The client is not required in
   * dry-run mode, mirroring the sibling sinks' dry-run
   * exemption; the rest of the config must still be
   * valid — a dry run against a sink with a bad severity
   * would rehearse a request that could never send.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the request body's
   * `body` appends the event body verbatim as a
   * JSON string, truncated to `payloadMaxChars`
   * characters (see below), after the identifiers (or
   * after the title-text fallback, when the event
   * carries no identifiers). When `false` or absent,
   * `body` carries the identifiers only — the
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
   * `SpikeRecord.status`): the relay does not invent a
   * lifecycle transition it was not told. Must be one of
   * the two values when set. A firing alert sends no
   * `status` field at all; a resolved alert sends
   * `status` exactly `"resolve"` with the same title the
   * incident was created with.
   */
  status?: SpikeAlertStatus;
  /**
   * Default severity: one of sev1/sev2/sev3. Config-held,
   * overridable per record (see `SpikeRecord.severity`).
   * Omitted entirely when neither the config nor the
   * record supplies one: the docs state no default
   * severity, so the sink invents none. Must be one of
   * the three values when set.
   */
  severity?: SpikeSeverity;
  /**
   * Default priority: one of p1/p2/p3/p4/p5. Config-held,
   * overridable per record (see `SpikeRecord.priority`).
   * Omitted entirely when neither the config nor the
   * record supplies one: the docs state no default
   * priority, so the sink invents none. Must be one of
   * the five values when set.
   */
  priority?: SpikePriority;
}

/** One event to alert about. */
export interface SpikeRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Content-derivation source, first priority: the event's
   * subject, when set and non-empty. The incident title.
   */
  subject?: string;
  /**
   * Content-derivation source, second priority: the event's key
   * (e.g. aggregate id). Also a `body` identifier, when set.
   * The title — not the key — is Spike.sh's grouping,
   * suppression, and auto-resolve key, so the key is
   * never sent as a separate field.
   */
  key?: string;
  /**
   * Content-derivation source, last priority: the trace id.
   * Also a `body` identifier, when set.
   */
  traceId?: string;
  /**
   * Per-record alert status override: one of
   * firing/resolved. When absent, the config's `status`
   * applies, defaulting to firing. A firing alert sends
   * no `status` field; a resolved alert sends `status`
   * exactly `"resolve"` with the same title the incident
   * was created with. A keyless resolve is NOT
   * fail-closed (see the module header): the title is
   * always non-empty, so the call is well-formed — but it
   * resolves by the fallback title, so the operator
   * should resolve with the same key as the firing alert.
   */
  status?: SpikeAlertStatus;
  /**
   * Per-record severity override: one of sev1/sev2/sev3.
   * When absent, the config's `severity` applies; when
   * neither supplies one, the field is omitted entirely.
   * An illegal value fails record validation with a
   * `RangeError`.
   */
  severity?: SpikeSeverity;
  /**
   * Per-record priority override: one of
   * p1/p2/p3/p4/p5. When absent, the config's `priority`
   * applies; when neither supplies one, the field is
   * omitted entirely. An illegal value fails record
   * validation with a `RangeError`.
   */
  priority?: SpikePriority;
}

/** One failed message, with its retry lane already mapped. */
export interface SpikeFailedRecord {
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
   * (400 invalid body, 404 wrong webhook URL, and the
   * rest). No per-status error code is claimed from the
   * reference beyond the documented 500 example (see the
   * module header).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface SpikeSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-303). */
export interface SpikeSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Spike.sh send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already received on Spike.sh's server and are *not* in
 * `failedRecords`.
 */
export class SpikeSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: SpikeFailedRecord[];
  constructor(message: string, failedRecords: SpikeFailedRecord[]) {
    super(message);
    this.name = "SpikeSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class SpikeSinkConfigError extends SpikeSinkError {
  constructor(reason: string) {
    super(`spike-sink: ${reason}`, []);
    this.name = "SpikeSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery.
 * The status, when set, must be one of firing/resolved; the
 * severity, when set, must be one of sev1/sev2/sev3; the
 * priority, when set, must be one of p1/p2/p3/p4/p5.
 * There is deliberately no `apiKey` field to validate: the
 * client alone holds the webhook integration URL.
 */
export function assertValidSpikeSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is SpikeSinkConfig {
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
      !(SPIKE_STATUSES as readonly string[]).includes(c.status))
  ) {
    throw new RangeError(at("`status` must be one of firing, resolved when set"));
  }
  if (
    c.severity !== undefined &&
    (typeof c.severity !== "string" ||
      !(SPIKE_SEVERITIES as readonly string[]).includes(c.severity))
  ) {
    throw new RangeError(at("`severity` must be one of sev1, sev2, sev3 when set"));
  }
  if (
    c.priority !== undefined &&
    (typeof c.priority !== "string" ||
      !(SPIKE_PRIORITIES as readonly string[]).includes(c.priority))
  ) {
    throw new RangeError(at("`priority` must be one of p1, p2, p3, p4, p5 when set"));
  }
}

/**
 * Derive one record's incident title: the first non-empty
 * value among `subject`, `key`, and `traceId`, in that
 * order. Falls back to the generic `webhook event` title
 * when the record carries none — an alert sink must not
 * silently drop sourceless events, and the docs warn that
 * a missing title creates an empty incident that will not
 * group, suppress, or auto-resolve.
 */
export function resolveSpikeTitle(record: SpikeRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return SPIKE_FALLBACK_TITLE;
}

/**
 * Resolve the alert status: the record's override when set,
 * else the config-held value, else `firing`.
 */
export function resolveSpikeStatus(
  record: SpikeRecord,
  config: Pick<SpikeSinkConfig, "status">
): SpikeAlertStatus {
  return record.status ?? config.status ?? SPIKE_DEFAULT_STATUS;
}

/**
 * Resolve the severity: the record's override when set,
 * else the config-held value, else `undefined` (omitted
 * from the wire body — the docs state no default
 * severity, so the sink invents none).
 */
export function resolveSpikeSeverity(
  record: SpikeRecord,
  config: Pick<SpikeSinkConfig, "severity">
): SpikeSeverity | undefined {
  return record.severity ?? config.severity;
}

/**
 * Resolve the priority: the record's override when set,
 * else the config-held value, else `undefined` (omitted
 * from the wire body — the docs state no default
 * priority, so the sink invents none).
 */
export function resolveSpikePriority(
  record: SpikeRecord,
  config: Pick<SpikeSinkConfig, "priority">
): SpikePriority | undefined {
  return record.priority ?? config.priority;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood an incident.
 */
export function truncateSpikePayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's `body`: only the event's own
 * identifiers — `key=<key>` and `traceId=<traceId>`
 * when present, joined with `"; "` — and, when the event
 * carries no identifiers, the derived title text, so the
 * body is never empty. Under the `includePayload`
 * opt-in the event body is appended after the identifiers
 * (or after the title-text fallback), truncated to
 * `payloadMaxChars` (default 2000). The body is never
 * truncated itself: the re-checked docs state no body
 * length limit.
 */
export function resolveSpikeBody(
  record: SpikeRecord,
  config: Pick<SpikeSinkConfig, "includePayload" | "payloadMaxChars">
): string {
  const parts: string[] = [];
  if (record.key !== undefined && record.key !== "") {
    parts.push(`key=${record.key}`);
  }
  if (record.traceId !== undefined && record.traceId !== "") {
    parts.push(`traceId=${record.traceId}`);
  }
  const base = parts.length > 0 ? parts.join("; ") : resolveSpikeTitle(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? SPIKE_DEFAULT_PAYLOAD_MAX_CHARS;
    const payload = truncateSpikePayload(record.body, limit);
    return `${base}\n\n${payload}`;
  }
  return base;
}

/**
 * Build one record's serialized JSON body: `title` (the
 * derived title, never truncated — the re-checked docs
 * state no title length limit, and the title is the
 * grouping/suppression/auto-resolve key), `body` (only the
 * `key`/`traceId` identifiers, falling back to the title
 * text when the event carries neither, so never empty;
 * the event body appended only under the
 * `includePayload` opt-in), `severity` (one of
 * sev1/sev2/sev3, the record override else the config
 * default, omitted when neither supplies one — the docs
 * state no default), `priority` (one of p1/p2/p3/p4/p5,
 * same rule — the docs state no default), and `status`
 * (omitted for a firing alert; exactly `"resolve"` for a
 * resolved one — the one value the docs pin for
 * auto-resolve, sent with the same title the incident was
 * created with). No credential ever enters the body —
 * the client alone holds the webhook integration URL
 * (token in the path).
 */
export function buildSpikeIncidentBody(
  record: SpikeRecord,
  config: Pick<SpikeSinkConfig, "includePayload" | "payloadMaxChars" | "status" | "severity" | "priority">
): string {
  const incident: {
    title: string;
    body: string;
    severity?: SpikeSeverity;
    priority?: SpikePriority;
    status?: typeof SPIKE_RESOLVED_STATUS;
  } = {
    title: resolveSpikeTitle(record),
    body: resolveSpikeBody(record, config),
  };
  const severity = resolveSpikeSeverity(record, config);
  if (severity !== undefined) {
    incident.severity = severity;
  }
  const priority = resolveSpikePriority(record, config);
  if (priority !== undefined) {
    incident.priority = priority;
  }
  if (resolveSpikeStatus(record, config) === "resolved") {
    incident.status = SPIKE_RESOLVED_STATUS;
  }
  return JSON.stringify(incident);
}

/**
 * Validate one record. Throws `RangeError` on an empty
 * body string — even without the opt-in, the body is the
 * record's payload, and an empty record is a caller bug
 * that must fail closed, never alert as an empty message.
 * A bad per-record `status`, `severity`, or `priority`
 * value fails here too (the config-level check in
 * `assertValidSpikeSinkConfig` only covers the config
 * defaults). A keyless resolve is NOT rejected here: the
 * title is always non-empty, so the call is well-formed
 * — but it resolves by the fallback title (see the module
 * header and the README warning), so the operator should
 * resolve with the same key as the firing alert.
 */
export function resolveSpikeRecord(
  record: SpikeRecord,
  index: number,
  config: Pick<SpikeSinkConfig, "status">
): { index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`spike-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  if (
    record.status !== undefined &&
    !(SPIKE_STATUSES as readonly string[]).includes(record.status)
  ) {
    throw new RangeError(`spike-sink: record ${index} \`status\` must be one of firing, resolved when set`);
  }
  if (
    record.severity !== undefined &&
    (typeof record.severity !== "string" ||
      !(SPIKE_SEVERITIES as readonly string[]).includes(record.severity))
  ) {
    throw new RangeError(`spike-sink: record ${index} \`severity\` must be one of sev1, sev2, sev3 when set`);
  }
  if (
    record.priority !== undefined &&
    (typeof record.priority !== "string" ||
      !(SPIKE_PRIORITIES as readonly string[]).includes(record.priority))
  ) {
    throw new RangeError(`spike-sink: record ${index} \`priority\` must be one of p1, p2, p3, p4, p5 when set`);
  }
  return { index };
}

/**
 * Map one Spike.sh POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says Spike.sh could not
 * accept the incident right now, not that the payload is
 * poison. Every other non-200 status (400 invalid body,
 * 404 wrong webhook URL, and the rest) is a fail-closed
 * message: an invalid body will never become valid on
 * retry. Honesty note: the re-checked reference publishes
 * no 429 or per-status 4xx mention at all (it shows only
 * a 200 success and a 500 example error), so this mapping
 * is the slot convention for the unlisted statuses, not a
 * per-status claim from that page — and no per-status
 * error code is invented here. Callers only pass non-200
 * statuses here; 200 is acceptance on its own (see
 * `classifySpikeIncidentResponse`).
 */
export function classifySpikeRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * The verdict on one incident POST: either an acceptance,
 * or a failure with its error code and retry lane.
 */
export type SpikeIncidentVerdict =
  | { accepted: true }
  | { accepted: false; errorCode: string; retryable: boolean; errorMessage?: string };

/**
 * Decide one incident POST's verdict from the response the
 * client reported. Exactly 200 is acceptance — the one
 * documented success status (the docs show a successful
 * request returning `200` with the body `{ Ok: true }`
 * and state "A successful request will get you 200 HTTP
 * response status code"). A 201 from a proxy or a future
 * revision is not a documented success and is treated as
 * an `HTTP_201` failure, fail-closed. A 200 is only an
 * acceptance receipt, not an incident: the incident itself
 * is created by Spike.sh. No receipt id is required or
 * collected as an acceptance condition: the re-checked
 * documentation states no response id for this endpoint,
 * so `send()` returns no ids. Any non-200 status is a
 * failure with an `HTTP_<status>` code and the WR-210
 * lane; the error text rides on the failure record when
 * the client surfaced one. No per-status error code is
 * claimed from the reference beyond the documented 500
 * example (see the module header).
 */
export function classifySpikeIncidentResponse(
  response: SpikeIncidentPostResponse
): SpikeIncidentVerdict {
  if (response.status === SPIKE_SUCCESS_STATUS) {
    return { accepted: true };
  }
  const verdict: SpikeIncidentVerdict = {
    accepted: false,
    errorCode: `HTTP_${response.status}`,
    retryable: classifySpikeRecordFailure(response.status),
  };
  if (response.errorMessage !== undefined && response.errorMessage !== "") {
    verdict.errorMessage = response.errorMessage;
  }
  return verdict;
}

/**
 * Spike.sh sink (WR-303). One incident is sent per record; the
 * caller owns retry / dead-letter policy around `send()`
 * — this class performs one POST attempt per message
 * through the injected client and reports its outcome.
 * Failures throw `SpikeSinkError` carrying exactly the
 * failed messages with their retry lanes. The sink keeps
 * no per-incident state: a later `resolved` carrying the
 * same title is sent exactly like any other incident, and
 * Spike.sh resolves the open incident — the sink does not
 * try to track that.
 */
export class SpikeSink {
  private readonly cfg: SpikeSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: SpikeSinkConfig) {
    assertValidSpikeSinkConfig(config, "SpikeSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): SpikeSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send the incidents, in input order. Throws
   * `SpikeSinkConfigError` when no client was injected,
   * and `SpikeSinkError` when any message fails
   * (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: SpikeRecord[]): Promise<SpikeSendResult> {
    const resolved = records.map((r, i) => resolveSpikeRecord(r, i, this.cfg));
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
      throw new SpikeSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const failedRecords: SpikeFailedRecord[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          headers: {
            "Content-Type": SPIKE_JSON_CONTENT_TYPE,
          },
          body: buildSpikeIncidentBody(records[i], this.cfg),
        });
        const verdict = classifySpikeIncidentResponse(response);
        if (verdict.accepted) {
          // 200 is acceptance on its own: the status is the
          // acceptance receipt, and the incident itself is
          // created by Spike.sh — the response is an
          // acceptance receipt, not an incident. No receipt id
          // is claimed: the re-checked documentation states
          // no response id for this endpoint.
          sent += 1;
          continue;
        }
        const failed: SpikeFailedRecord = {
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
        failedRecords.push(toSpikeFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new SpikeSinkError(
        `spike-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent };
  }
}

/**
 * Convert a client throw into a failed message: a codeless
 * transport failure (`TRANSPORT_ERROR`, retryable — the SQS
 * no-status rule). A retry reuses the same title, so it
 * lands on the open incident rather than creating a second
 * one (see the module header).
 */
function toSpikeFailedRecord(err: unknown, index: number): SpikeFailedRecord {
  const failed: SpikeFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
