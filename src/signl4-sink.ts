/**
 * SIGNL4 on-call alert delivery sink (WR-301).
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
 * `summary`/`entity_id`/`payload` envelope, and the
 * Squadcast sink (WR-300) posts an incident to a
 * Squadcast Incident Webhook with a `message`/
 * `description`/`status`/`event_id` envelope, this sink
 * posts an alert to a SIGNL4 team webhook: one event is
 * sent as one POST that SIGNL4 routes into that team's
 * on-call schedule, and SIGNL4 — not the relay — owns
 * the alert, the escalation, the notification, and the
 * alert lifecycle.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a SIGNL4
 * server. The sink owns the relay-side concerns — the
 * status, the title derivation, the message, the external
 * id, the payload-inclusion policy, the per-message
 * failure mapping — and the injected client owns the wire
 * protocol, including the POST call, the team webhook URL,
 * and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { headers: { "Content-Type": "application/json" },
 *     body: "{\"Title\":\"<title>\",\"Message\":\"key=<key>; traceId=<traceId>\",\"X-S4-ExternalID\":\"<key>\",\"X-S4-Status\":\"new\",\"X-S4-SourceSystem\":\"webhook-relay\"}" }
 *
 * The client POSTs to the team webhook URL it alone
 * holds — `https://connect.signl4.com/webhook/
 * {team-secret}` — sending `body` verbatim as the
 * request body (JSON) and sending `headers` verbatim as
 * the request headers. Seven things about this shape are
 * deliberate, and all follow the sibling sinks or the
 * backlog pins:
 *
 * - The team webhook URL — team secret in the URL path
 *   — is held by the client alone. The sink never
 *   receives the secret, never places it in the request,
 *   and never logs it: the sink config has no `apiKey`
 *   field at all, and the handed request carries no URL
 *   at all (like the ilert, Zenduty, and Squadcast sinks,
 *   unlike the Opsgenie sink, whose handed request
 *   carries the bare endpoint URL), so there is nothing
 *   in it for a log line or a retry queue to leak — and
 *   the secret is never persisted by the sink. The secret
 *   rides in the URL path (like the ilert sink's
 *   alert-source URL and the Zenduty sink's Generic
 *   Integration webhook URL, unlike the Opsgenie sink's
 *   `Authorization: GenieKey <key>` header and the
 *   PagerDuty sink's `routing_key` inside the body), so
 *   the sink hands the client the bare `Content-Type`
 *   header and the body and the client posts to the
 *   webhook URL it was configured with: the sink's
 *   request never contains a secret, a placeholder, or
 *   anything that looks like one, and there is no
 *   `Authorization` header. This is the SIGNL4 form of
 *   the MagicBell rule (whose Project JWT the client
 *   alone holds as an `Authorization: Bearer` header),
 *   with SIGNL4's own credential source: the team secret
 *   of a SIGNL4 team webhook, verified against the
 *   current docs (support.signl4.com "HTTP details",
 *   re-checked 2026-11-02 — request URL
 *   `https://connect.signl4.com/webhook/{Secret}`).
 * - The endpoint is the team webhook the backlog pins:
 *   `POST https://connect.signl4.com/webhook/
 *   {team-secret}`. The client substitutes the secret
 *   from the webhook URL it holds; the sink never builds
 *   the URL, so the sink cannot leak, log, or misroute
 *   the secret.
 * - `Title` is mandatory, so it is derived as the first
 *   non-empty value among `subject`, `key`, and
 *   `traceId`, in that order, falling back to the generic
 *   `webhook event`: an alert sink that silently dropped
 *   sourceless events would hide exactly the deliveries
 *   an operator most needs to see. No truncation is
 *   applied: the re-checked documentation states no
 *   title length limit for this endpoint, and inventing
 *   one would silently cut an operator's alert text.
 * - `Message` is mandatory, so it is derived from the
 *   event's own identifiers — `key=<key>;
 *   traceId=<traceId>` when present (the ilert `details`
 *   form) — and falls back to the derived title text
 *   when the event carries no identifiers, so it is never
 *   empty: a messageless alert would hide exactly the
 *   context an operator most needs to see. No truncation
 *   is applied to the identifiers or the fallback text:
 *   the re-checked documentation states no message
 *   length limit for this endpoint.
 * - `X-S4-ExternalID` is the event's `key`, sent when
 *   one exists and omitted entirely when the event
 *   carries none: a keyless event still alerts, it just
 *   carries no grouping key. The external id is the
 *   official de-duplication/association key: the
 *   reference states the same value must be used to
 *   close the alert as was used to trigger it, so a
 *   second alert with the same external id while the
 *   first is still open is grouped into the same SIGNL4
 *   alert instead of creating a new one, and sending
 *   `X-S4-Status` `resolved` with the same external id
 *   resolves that alert. The external id is sent
 *   verbatim, never truncated: truncating a dedup key
 *   would silently merge distinct alerts. The same
 *   external id also makes a transport-failure retry
 *   safe: replaying the same record reuses the same
 *   external id, so the retry lands on the open alert
 *   instead of paging the on-call engineer twice.
 * - `X-S4-Status` is one of `new` and `resolved` (the
 *   two values the reference pins — "If the parameter
 *   `X-S4-Status` is present and neither `new` nor
 *   `resolved` the event gets discarded"). It is
 *   config-held with a per-record override, defaulting
 *   to `new`: the relay does not invent a lifecycle
 *   transition it was not told. `resolved` must carry an
 *   `X-S4-ExternalID` — without one SIGNL4 cannot
 *   associate the call with an open alert — so a record
 *   (or a config default) that asks for `resolved`
 *   without a key fails closed with a `RangeError`
 *   before any POST is made, never sent as a keyless
 *   resolution (the ilert ACCEPT/RESOLVE rule). The sink
 *   still sends the derived title and message on a
 *   resolve, keeping one uniform envelope instead of a
 *   second, resolve-only shape; the message is never
 *   empty either way (see above).
 * - `X-S4-SourceSystem` is fixed to `"webhook-relay"`
 *   (the Opsgenie `source` precedent — the Sumo Logic
 *   integration sends `"SumoLogic"` here, the Datadog
 *   integration `"Datadog"`): it names the relay as the
 *   sending system, and the sink never lets a record
 *   override it. `Severity`, `Service`, and `Location`
 *   are out of scope: they are SIGNL4-side integration
 *   configuration, and the sink never invents a routing,
 *   severity, or priority decision. No `Idempotency-Key`
 *   header is sent: the reference documents no
 *   idempotency key for this endpoint, and the external
 *   id already gives a retry its de-duplication key (see
 *   above).
 * - `payload` carries only the event's own identifiers
 *   by default — `key` and `traceId` when present,
 *   nothing else — so the alert's message stays
 *   identifiers, never event body: here that means the
 *   `Message` carries the identifiers only (see above).
 *   Under the `includePayload` opt-in the event body is
 *   appended to the `Message` after the identifiers (or
 *   after the title-text fallback, when the event
 *   carries no identifiers), truncated to
 *   `payloadMaxChars` characters (default 2000).
 *
 * Acceptance is decided by the HTTP status alone, and
 * the success statuses are pinned to exactly `200` and
 * `201`: the Sumo Logic integration doc states a
 * successful test returns `200 OK`, and SIGNL4's own
 * support page ("HTTP details") states the success
 * response code is `201` with a body containing an
 * `eventId` — so both documented success statuses are
 * accepted, and any other status is a failure (see the
 * honesty note below). A 200 or 201 is only an
 * acceptance receipt, not an alert: the alert itself is
 * created by SIGNL4. The `eventId` — when the client
 * surfaced one — is the receipt for querying further
 * details via the SIGNL4 REST API, so `send()` returns
 * the collected event ids in send order; a success that
 * carries no event id is still an acceptance (the status
 * is the acceptance credential here), just one with no
 * later tracking.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over the HTTP status:
 *
 * - a non-200/201 POST throws `Signl4SinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says SIGNL4 could
 *   not accept the alert right now, not that the payload
 *   is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-200/201 status, including the two
 *   the reference pins, 400 (the submitted body is
 *   invalid) and 404 (the webhook URL is wrong):
 *   retrying them burns the retry budget for nothing, and
 *   rerouting them elsewhere would page an on-call
 *   engineer the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload (a retry after a
 *   transport failure reuses the same external id, so it
 *   lands on the open alert rather than creating a second
 *   one — see X-S4-ExternalID above);
 * - a missing client throws `Signl4SinkConfigError`,
 *   which `classifyFailure` maps to `non_retryable`
 *   (the WR-116 rule).
 *
 * One honesty note on the failure mapping: the
 * re-checked references pin the endpoint, the webhook
 * URL form, the `Title`/`Message`/`X-S4-ExternalID`/
 * `X-S4-Status`/`X-S4-SourceSystem` body, the
 * new/resolved-only status rule with its discard
 * behaviour, the same-external-id resolution rule, the
 * 201 success with its `eventId` body, and the 400/404
 * error meanings — but they publish no 429 or 5xx
 * mention at all. The 429/5xx-retryable, other-4xx-
 * fail-closed mapping above is therefore the slot
 * convention for the unlisted statuses, not a per-status
 * claim from those pages, and no per-status error code
 * is invented here: the failure record carries
 * `HTTP_<status>` plus whatever free-form error text the
 * client surfaced, and nothing more. A second honesty
 * note, on the success status: the backlog pins exactly
 * `200 OK` (from the Sumo Logic integration doc's test
 * flow), while SIGNL4's own support page pins `201
 * Created` with an `eventId` body as the success
 * response. This sink accepts both — the two documented
 * success statuses — rather than treating a live 201
 * as a failure; if the reference later pins a single
 * success status, only `classifySignl4AlertResponse`
 * needs to change.
 *
 * Zero new dependencies: the injected client only. (No
 * `node:crypto` import either: with no idempotency key to
 * derive, there is nothing to hash.)
 */

/** Generic title used when an event carries no value for the title. */
export const SIGNL4_FALLBACK_TITLE = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const SIGNL4_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Content type the client sends with the JSON body. */
export const SIGNL4_JSON_CONTENT_TYPE = "application/json";

/** SIGNL4 connect base host. */
export const SIGNL4_API_BASE_URL = "https://connect.signl4.com";

/**
 * Team webhook URL template, with the segment the client
 * alone holds: `{team-secret}` is the team's webhook
 * secret. The client substitutes it from the webhook URL
 * it was configured with; the sink never builds this URL,
 * so no secret — real or placeholder — ever passes
 * through the sink. Exported so the URL shape is pinned
 * in tests, not so the sink can construct a request URL.
 */
export const SIGNL4_WEBHOOK_URL_TEMPLATE =
  "https://connect.signl4.com/webhook/{team-secret}";

/** Fixed source system naming the relay as the sending system. */
export const SIGNL4_SOURCE_SYSTEM = "webhook-relay";

/** Default `X-S4-Status`. */
export const SIGNL4_DEFAULT_STATUS = "new";

/** The alert statuses the reference pins. */
export const SIGNL4_STATUSES = ["new", "resolved"] as const;

/** One of the alert statuses the reference pins (new/resolved). */
export type Signl4AlertStatus = (typeof SIGNL4_STATUSES)[number];

/** The two documented success statuses. */
export const SIGNL4_SUCCESS_STATUSES = [200, 201] as const;

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (JSON) to the team webhook URL it
 * alone holds (`https://connect.signl4.com/webhook/
 * {team-secret}`), sending `headers` verbatim as the
 * request headers. There is deliberately no `url` field
 * here: the URL carries the team secret in its path, so
 * the sink must never see, build, or hand over a URL —
 * the client posts to the URL it was configured with. No
 * `Authorization` header is sent: the secret rides in the
 * URL path, never in a header. No `Idempotency-Key`
 * header is sent: the docs do not verify it for this
 * endpoint, and the external id already gives a retry its
 * de-duplication key (see the module header).
 */
export interface Signl4AlertPostRequest {
  /**
   * Request headers, sent verbatim:
   * `{ "Content-Type": "application/json" }`. There is
   * deliberately no `url` field: the team webhook URL
   * (team secret in the path) is held by the client
   * alone, never by the sink, and there is no
   * `Authorization` header and no `Idempotency-Key`
   * header.
   */
  headers: Record<string, string>;
  /**
   * The JSON request body, serialized:
   * `{"Title":"<title>","Message":"key=<key>; traceId=<traceId>","X-S4-ExternalID":"<key>","X-S4-Status":"new","X-S4-SourceSystem":"webhook-relay"}`
   * (`Message` falls back to the title text when the
   * event carries no identifiers, so it is never empty;
   * the event body is appended to it only under the
   * `includePayload` opt-in; `X-S4-ExternalID` is
   * omitted when the event carries no key;
   * `X-S4-SourceSystem` is fixed to `"webhook-relay"`).
   * No credential ever enters the body.
   */
  body: string;
}

/**
 * The result of one POST, as reported by the injected
 * client. The HTTP status decides acceptance: 200 or 201
 * means SIGNL4 accepted the alert, and the `eventId` —
 * when the client surfaced one — is the receipt for
 * querying further details via the SIGNL4 REST API. The
 * error text, when the client surfaced one, rides on the
 * failure record; no per-status error code is claimed
 * from the reference beyond the documented 400/404
 * meanings (see the module header).
 */
export interface Signl4AlertPostResponse {
  /** The HTTP status of the POST (e.g. 200, 201, 400, 404, 429, 500). */
  status: number;
  /** The event id from the success body, when the client surfaced one. */
  eventId?: string;
  /** Free-form error text from the error body, when the client surfaced one. */
  errorMessage?: string;
}

/**
 * The injected SIGNL4 alert client. Any client adapter
 * implements this one method; it returns the POST's status
 * and the event id when present — a throw is a codeless
 * transport failure, retryable. The client is expected to
 * POST one alert per call, sending `body` verbatim as
 * the request body (JSON), sending `headers` verbatim
 * as the request headers, and posting to the team webhook
 * URL it alone holds (`https://connect.signl4.com/
 * webhook/{team-secret}`) — the sink never sees that URL.
 */
export interface Signl4AlertClient {
  post(request: Signl4AlertPostRequest): Promise<Signl4AlertPostResponse>;
}

/**
 * Configuration for one SIGNL4 sink. The client is
 * injected: without one, `send()` throws
 * `Signl4SinkConfigError` (dry runs excepted — they need
 * no client at all). The team secret is deliberately
 * absent from this config: the client alone holds the
 * team webhook URL (team secret in the path), and the
 * secret is never persisted by the sink.
 */
export interface Signl4SinkConfig {
  /**
   * The SIGNL4 alert client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `Signl4AlertClient` and alone holds the
   * team webhook URL. Required for real sends; a missing
   * client is a config error, not a silent no-op.
   */
  client?: Signl4AlertClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, eventIds: [], dryRun: true }`
   * and performs zero client I/O — no POST call, no stat
   * changes. Messages are still validated (including
   * status derivation and the resolve external-id rule),
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
   * `Message` appends the event body verbatim as a
   * JSON string, truncated to `payloadMaxChars`
   * characters (see below), after the identifiers (or
   * after the title-text fallback, when the event
   * carries no identifiers). When `false` or absent,
   * `Message` carries the identifiers only — the
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
   * Default alert status: one of new/resolved, default
   * new. Config-held, overridable per record (see
   * `Signl4Record.status`): the relay does not invent a
   * lifecycle transition it was not told. Must be one of
   * the two values when set. A configured `resolved`
   * default still needs an external id on every record
   * — see `resolveSignl4Record`.
   */
  status?: Signl4AlertStatus;
}

/** One event to alert about. */
export interface Signl4Record {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Content-derivation source, first priority: the event's
   * subject, when set and non-empty. The alert title.
   */
  subject?: string;
  /**
   * Content-derivation source, second priority: the event's key
   * (e.g. aggregate id). Also the alert's `X-S4-ExternalID`
   * (the official de-duplication/association key) and a
   * `Message` identifier, when set. Required when the
   * effective status is resolved — without one SIGNL4
   * cannot associate the call with an open alert.
   */
  key?: string;
  /**
   * Content-derivation source, last priority: the trace id.
   * Also a `Message` identifier, when set.
   */
  traceId?: string;
  /**
   * Per-record alert status override: one of
   * new/resolved. When absent, the config's `status`
   * applies, defaulting to new. A `resolved` override
   * still needs an external id on this record — see
   * `resolveSignl4Record`.
   */
  status?: Signl4AlertStatus;
}

/** One failed message, with its retry lane already mapped. */
export interface Signl4FailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /**
   * Failure code: `HTTP_<status>` for a non-200/201 POST,
   * or `TRANSPORT_ERROR` for a codeless failure.
   */
  errorCode: string;
  /** Downstream HTTP status, when the failure was a non-200/201 POST. */
  statusCode?: number;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: 429 and 5xx
   * (plus codeless transport failures) are retryable;
   * every other non-200/201 status is a fail-closed message
   * (400 invalid body, 404 wrong webhook URL — the
   * reference's own words — and the rest). No per-status
   * error code is claimed from the reference beyond the
   * documented 400/404 meanings (see the module header).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface Signl4SendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /**
   * Event ids in send order — the id of each accepted
   * message that reported one, the receipt for querying
   * further details via the SIGNL4 REST API. Empty in
   * dry-run mode, and an accepted message that reported
   * no event id contributes no entry here: it is still
   * accepted (the 200/201 status is the acceptance
   * credential), it just has no later tracking.
   */
  eventIds: string[];
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-301). */
export interface Signl4SinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for SIGNL4 send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already received on SIGNL4's server and are *not* in
 * `failedRecords`.
 */
export class Signl4SinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: Signl4FailedRecord[];
  constructor(message: string, failedRecords: Signl4FailedRecord[]) {
    super(message);
    this.name = "Signl4SinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class Signl4SinkConfigError extends Signl4SinkError {
  constructor(reason: string) {
    super(`signl4-sink: ${reason}`, []);
    this.name = "Signl4SinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery.
 * The status, when set, must be one of new/resolved.
 * There is deliberately no `apiKey` field to validate: the
 * client alone holds the team webhook URL.
 */
export function assertValidSignl4SinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is Signl4SinkConfig {
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
      !(SIGNL4_STATUSES as readonly string[]).includes(c.status))
  ) {
    throw new RangeError(at("`status` must be one of new, resolved when set"));
  }
}

/**
 * Derive one record's alert title: the first non-empty
 * value among `subject`, `key`, and `traceId`, in that
 * order. Falls back to the generic `webhook event` title
 * when the record carries none — an alert sink must not
 * silently drop sourceless events.
 */
export function resolveSignl4Title(record: Signl4Record): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return SIGNL4_FALLBACK_TITLE;
}

/**
 * Resolve the alert status: the record's override when set,
 * else the config-held value, else `new`.
 */
export function resolveSignl4Status(
  record: Signl4Record,
  config: Pick<Signl4SinkConfig, "status">
): Signl4AlertStatus {
  return record.status ?? config.status ?? SIGNL4_DEFAULT_STATUS;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood an alert.
 */
export function truncateSignl4Payload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's `Message`: only the event's own
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
export function resolveSignl4Message(
  record: Signl4Record,
  config: Pick<Signl4SinkConfig, "includePayload" | "payloadMaxChars">
): string {
  const parts: string[] = [];
  if (record.key !== undefined && record.key !== "") {
    parts.push(`key=${record.key}`);
  }
  if (record.traceId !== undefined && record.traceId !== "") {
    parts.push(`traceId=${record.traceId}`);
  }
  const base = parts.length > 0 ? parts.join("; ") : resolveSignl4Title(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? SIGNL4_DEFAULT_PAYLOAD_MAX_CHARS;
    const payload = truncateSignl4Payload(record.body, limit);
    return `${base}\n\n${payload}`;
  }
  return base;
}

/**
 * Build one record's serialized JSON body: `Title` (the
 * derived title, never truncated — the re-checked docs
 * state no title length limit), `Message` (only the
 * `key`/`traceId` identifiers, falling back to the title
 * text when the event carries neither, so never empty;
 * the event body appended only under the
 * `includePayload` opt-in), `X-S4-ExternalID` (the event
 * key, omitted when the event carries none — the official
 * de-duplication/association key), `X-S4-Status` (the
 * record override, else the config default, else new),
 * and `X-S4-SourceSystem` (fixed to `"webhook-relay"`).
 * No `Severity`, `Service`, or `Location`: those are
 * SIGNL4-side integration configuration, and the sink
 * never invents a routing, severity, or priority
 * decision. No credential ever enters the body — the
 * client alone holds the team webhook URL (team secret
 * in the path).
 */
export function buildSignl4AlertBody(
  record: Signl4Record,
  config: Pick<Signl4SinkConfig, "includePayload" | "payloadMaxChars" | "status">
): string {
  const alert: {
    Title: string;
    Message: string;
    "X-S4-ExternalID"?: string;
    "X-S4-Status": Signl4AlertStatus;
    "X-S4-SourceSystem": string;
  } = {
    Title: resolveSignl4Title(record),
    Message: resolveSignl4Message(record, config),
    "X-S4-Status": resolveSignl4Status(record, config),
    "X-S4-SourceSystem": SIGNL4_SOURCE_SYSTEM,
  };
  if (record.key !== undefined && record.key !== "") {
    alert["X-S4-ExternalID"] = record.key;
  }
  return JSON.stringify(alert);
}

/**
 * Validate one record. Throws `RangeError` on an empty
 * body string — even without the opt-in, the body is the
 * record's payload, and an empty record is a caller bug
 * that must fail closed, never alert as an empty message.
 * Also throws `RangeError` when the effective status is
 * `resolved` and the record carries no key: without an
 * `X-S4-ExternalID` SIGNL4 cannot associate the call
 * with an open alert, so the call must never be sent
 * keyless. A bad per-record `status` value fails here too
 * (the config-level check in `assertValidSignl4SinkConfig`
 * only covers the config default).
 */
export function resolveSignl4Record(
  record: Signl4Record,
  index: number,
  config: Pick<Signl4SinkConfig, "status">
): { index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`signl4-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  if (
    record.status !== undefined &&
    !(SIGNL4_STATUSES as readonly string[]).includes(record.status)
  ) {
    throw new RangeError(`signl4-sink: record ${index} \`status\` must be one of new, resolved when set`);
  }
  const status = resolveSignl4Status(record, config);
  if (
    status === "resolved" &&
    (record.key === undefined || record.key === "")
  ) {
    throw new RangeError(
      `signl4-sink: record ${index} \`status\` resolved requires an event key (\`key\`), otherwise SIGNL4 cannot associate the call with an open alert`
    );
  }
  return { index };
}

/**
 * Map one SIGNL4 POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says SIGNL4 could not
 * accept the alert right now, not that the payload is
 * poison. Every other non-200/201 status (400 invalid
 * body, 404 wrong webhook URL — the reference's own
 * words — and the rest) is a fail-closed message: an
 * invalid body will never become valid on retry. Honesty
 * note: the re-checked references publish no 429 or 5xx
 * mention at all, so this mapping is the slot convention
 * for the unlisted statuses, not a per-status claim from
 * those pages — and no per-status error code is invented
 * here. Callers only pass non-200/201 statuses here; 200
 * and 201 are acceptance on their own (see
 * `classifySignl4AlertResponse`).
 */
export function classifySignl4RecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * The verdict on one alert POST: either an acceptance,
 * or a failure with its error code and retry lane.
 */
export type Signl4AlertVerdict =
  | { accepted: true }
  | { accepted: false; errorCode: string; retryable: boolean; errorMessage?: string };

/**
 * Decide one alert POST's verdict from the response the
 * client reported. Exactly 200 or 201 is acceptance —
 * the two documented success statuses (see the module
 * header): the Sumo Logic integration doc states a
 * successful test returns `200 OK`, and SIGNL4's own
 * support page states the success response code is `201`
 * with a body containing an `eventId`. A 202 or 204 from
 * a proxy or a future revision is not a documented
 * success and is treated as an `HTTP_<status>` failure,
 * fail-closed. A 200 or 201 is only an acceptance receipt,
 * not an alert: the alert itself is created by SIGNL4.
 * No receipt id is required or collected as an acceptance
 * condition: a success that carries no event id is still
 * an acceptance, just one with no later tracking. Any
 * non-200/201 status is a failure with an `HTTP_<status>`
 * code and the WR-210 lane; the error text rides on the
 * failure record when the client surfaced one. No
 * per-status error code is claimed from the reference
 * beyond the documented 400/404 meanings (see the module
 * header).
 */
export function classifySignl4AlertResponse(
  response: Signl4AlertPostResponse
): Signl4AlertVerdict {
  if (response.status === 200 || response.status === 201) {
    return { accepted: true };
  }
  const verdict: Signl4AlertVerdict = {
    accepted: false,
    errorCode: `HTTP_${response.status}`,
    retryable: classifySignl4RecordFailure(response.status),
  };
  if (response.errorMessage !== undefined && response.errorMessage !== "") {
    verdict.errorMessage = response.errorMessage;
  }
  return verdict;
}

/**
 * SIGNL4 sink (WR-301). One alert is sent per record; the
 * caller owns retry / dead-letter policy around `send()`
 * — this class performs one POST attempt per message
 * through the injected client and reports its outcome.
 * Failures throw `Signl4SinkError` carrying exactly the
 * failed messages with their retry lanes. The sink keeps
 * no per-alert state: a later `resolved` carrying the
 * same `X-S4-ExternalID` is sent exactly like any other
 * alert, and SIGNL4 resolves the alert — the sink does
 * not try to track that.
 */
export class Signl4Sink {
  private readonly cfg: Signl4SinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: Signl4SinkConfig) {
    assertValidSignl4SinkConfig(config, "Signl4Sink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): Signl4SinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send the alerts, in input order. Throws
   * `Signl4SinkConfigError` when no client was injected,
   * and `Signl4SinkError` when any message fails
   * (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: Signl4Record[]): Promise<Signl4SendResult> {
    const resolved = records.map((r, i) => resolveSignl4Record(r, i, this.cfg));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The client
      // is not required here, mirroring the sibling sinks'
      // dry-run exemption; the rest of the config was already
      // validated at construction.
      return { ok: true, sent: 0, eventIds: [], dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new Signl4SinkConfigError("no client injected (set `client` in the sink config)");
    }
    const failedRecords: Signl4FailedRecord[] = [];
    const eventIds: string[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          headers: {
            "Content-Type": SIGNL4_JSON_CONTENT_TYPE,
          },
          body: buildSignl4AlertBody(records[i], this.cfg),
        });
        const verdict = classifySignl4AlertResponse(response);
        if (verdict.accepted) {
          // 200 or 201 is acceptance on its own: the status
          // is the acceptance receipt, and the alert itself
          // is created by SIGNL4 — the response is an
          // acceptance receipt, not an alert. The event id,
          // when the client surfaced one, is the receipt for
          // querying further details via the SIGNL4 REST API;
          // a success without one is still accepted.
          sent += 1;
          if (typeof response.eventId === "string" && response.eventId !== "") {
            eventIds.push(response.eventId);
          }
          continue;
        }
        const failed: Signl4FailedRecord = {
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
        failedRecords.push(toSignl4FailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new Signl4SinkError(
        `signl4-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent, eventIds };
  }
}

/**
 * Convert a client throw into a failed message: a codeless
 * transport failure (`TRANSPORT_ERROR`, retryable — the SQS
 * no-status rule). A retry reuses the same external id, so it
 * lands on the open alert rather than creating a second
 * one (see the module header).
 */
function toSignl4FailedRecord(err: unknown, index: number): Signl4FailedRecord {
  const failed: Signl4FailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
