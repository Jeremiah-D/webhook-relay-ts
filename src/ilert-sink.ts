/**
 * ilert on-call alert delivery sink (WR-298).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are the on-call engineer's phone, reached
 * through an alerting API. Where the PagerDuty sink
 * (WR-248) posts an Events API v2 event with a
 * `routing_key` carried inside the body and an
 * `event_action`/`dedup_key` envelope, and the Opsgenie
 * sink (WR-297) creates an alert through the Alert API
 * v2 with a `GenieKey` header the client alone holds and
 * a `message`/`alias`/`description`/`priority` envelope,
 * this sink posts an event to an ilert alert source
 * through the ilert Events API v1: one event is sent as
 * one POST that ilert routes into that alert source's
 * escalation policy, and ilert — not the relay — owns
 * the alert, the escalation, the notification, and the
 * alert lifecycle.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need an ilert
 * server. The sink owns the relay-side concerns — the
 * event type, the summary derivation, the alert key, the
 * details, the priority, the payload-inclusion policy, the
 * per-message failure mapping — and the injected client
 * owns the wire protocol, including the POST call, the
 * alert-source URL, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { headers: { "Content-Type": "application/json" },
 *     body: "{\"eventType\":\"ALERT\",\"summary\":\"<summary>\",\"details\":\"key=<key>; traceId=<traceId>\",\"alertKey\":\"<key>\",\"priority\":\"LOW\"}" }
 *
 * The client POSTs to the alert-source URL it alone
 * holds — `https://api.ilert.com/api/v1/events/
 * {integration}/{apiKey}` — sending `body` verbatim as
 * the request body (JSON) and sending `headers` verbatim
 * as the request headers. Six things about this shape
 * are deliberate, and all follow the sibling sinks or
 * the backlog pins:
 *
 * - The alert-source URL — integration segment and API
 *   key alike — is held by the client alone. The sink
 *   never receives the key, never places it in the
 *   request, and never logs it: the sink config has no
 *   `apiKey` field at all, and the handed request
 *   carries no URL at all (unlike the Opsgenie sink,
 *   whose handed request carries the bare endpoint URL),
 *   so there is nothing in it for a log line or a retry
 *   queue to leak — and the key is never persisted by
 *   the sink. The key rides in the URL path (unlike the
 *   Opsgenie sink's `Authorization: GenieKey <key>`
 *   header and the PagerDuty sink's `routing_key` inside
 *   the body), so the sink hands the client the bare
 *   `Content-Type` header and the body and the client
 *   posts to the alert-source URL it was configured
 *   with: the sink's request never contains a key, a
 *   placeholder, or anything that looks like one. This
 *   is the ilert form of the MagicBell rule (whose
 *   Project JWT the client alone holds as an
 *   `Authorization: Bearer` header), with ilert's own
 *   credential source: the API key of an alert source,
 *   verified against the current docs
 *   (docs.keephq.dev/providers/documentation/
 *   ilert-provider, netdata.cloud ilert integration,
 *   and docs.librenms.org ilert transport, re-checked
 *   2026-11-01 — the Keep provider posts to
 *   `https://api.ilert.com/api/v1/events/keep/
 *   {ALERT-SOURCE-API-KEY}`, Netdata to
 *   `https://api.ilert.com/api/v1/events/netdata/
 *   {API-KEY}`).
 * - The endpoint is the Events API the backlog pins:
 *   `POST https://api.ilert.com/api/v1/events/
 *   {integration}/{apiKey}`, where `{integration}` is
 *   the alert source's integration name (e.g. `keep`,
 *   `netdata`) and `{apiKey}` is that alert source's
 *   API key. The client substitutes both from the URL
 *   it holds; the sink never builds the URL, so the
 *   sink cannot leak, log, or misroute the key.
 * - `eventType` is one of `ALERT`, `ACCEPT`, and
 *   `RESOLVE` (the values the Keep provider and the
 *   LibreNMS transport both pin). It is config-held
 *   with a per-record override, defaulting to `ALERT`:
 *   the relay does not invent a lifecycle transition it
 *   was not told. `ACCEPT` and `RESOLVE` must carry an
 *   `alertKey` — without one ilert cannot associate the
 *   event with an open alert — so a record (or a
 *   config default) that asks for `ACCEPT`/`RESOLVE`
 *   without a key fails closed with a `RangeError`
 *   before any POST is made, never sent as a keyless
 *   acknowledgement or resolution.
 * - `summary` is mandatory, so it is derived as the
 *   first non-empty value among `subject`, `key`, and
 *   `traceId`, in that order, falling back to the generic
 *   `webhook event`: an alert sink that silently dropped
 *   sourceless events would hide exactly the deliveries
 *   an operator most needs to see. No truncation is
 *   applied: the re-checked documentation states no
 *   summary length limit for this endpoint, and inventing
 *   one would silently cut an operator's alert text.
 * - `alertKey` is the event's `key`, sent when one
 *   exists and omitted entirely when the event carries
 *   none: a keyless event still alerts, it just carries
 *   no grouping key. The alert key is the official
 *   grouping/deduplication key: events carrying the same
 *   `alertKey` are grouped into the same open alert, so
 *   the same key also makes a transport-failure retry
 *   safe — replaying the same record reuses the same
 *   alert key, so the retry lands on the open alert
 *   instead of paging the on-call engineer twice. The
 *   alert key is sent verbatim, never truncated:
 *   truncating a grouping key would silently merge
 *   distinct alerts.
 * - `details` carries only the event's own identifiers
 *   — `key` and `traceId` when present, nothing else —
 *   so the alert's details stay identifiers, never
 *   payload; `priority` is config-held and defaults to
 *   `LOW` (the two values are `HIGH` and `LOW`, per the Keep
 *   provider and the LibreNMS transport — `HIGH` is
 *   critical, `LOW` is warning or OK). `customDetails`
 *   is not sent: the record carries no custom key-value
 *   pairs, and the sink never invents any. `images` is
 *   out of scope: the record carries no image URLs.
 *
 * A resolved alert cannot be reopened: ilert treats a
 * later event carrying the same `alertKey` as a new
 * alert, not as a resurrection of the resolved one.
 * The sink does nothing special here — it sends the
 * later event exactly like any other event, with the
 * same `alertKey`, and lets ilert create the new alert.
 * There is deliberately no sink-side suppression, no
 * state, and no "already resolved" bookkeeping: the
 * sink is stateless per send, and ilert owns the alert
 * lifecycle.
 *
 * Acceptance is decided by the HTTP status alone: any
 * 2xx status means ilert accepted the event, and
 * `send()` returns the count of accepted messages, so a
 * caller that only inspects the result still has the
 * receipt. A 2xx is only an acceptance receipt, not an
 * alert: the event is routed into the alert source's
 * escalation policy, and the alert itself is created
 * asynchronously by ilert. No receipt id is claimed
 * here: the re-checked documentation states no response
 * id for this endpoint, so `send()` returns no ids —
 * inventing one would be worse than returning none.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over the HTTP status:
 *
 * - a non-2xx POST throws `IlertSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says ilert could
 *   not accept the event right now, not that the payload
 *   is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   and 403 (bad input, bad API key, disabled
 *   integration, no permission): retrying them burns
 *   the retry budget for nothing, and rerouting them
 *   elsewhere would page an on-call engineer the
 *   operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload (a retry after a
 *   transport failure reuses the same alert key, so it
 *   lands on the open alert rather than creating a
 *   second one — see alertKey above);
 * - a missing client throws `IlertSinkConfigError`,
 *   which `classifyFailure` maps to `non_retryable`
 *   (the WR-116 rule).
 *
 * One honesty note on the failure mapping: the ilert
 * API reference the backlog pins for this item
 * (https://api.ilert.com/api-docs/#tag/Events/paths/
 * ~1events/post) could not be fetched at implementation
 * time — the page returned 404 on 2026-11-01 — and the
 * re-checked integration docs (Keep, LibreNMS, Netdata)
 * pin the endpoint, the `{integration}/{apiKey}` URL
 * form, the `eventType` values, the `alertKey`
 * grouping, and the `HIGH`/`LOW` priority range, but
 * publish no per-status success code or error-code
 * table for the Events endpoint. The 2xx-acceptance and
 * 429/5xx-retryable, other-4xx-fail-closed mapping above
 * is therefore the slot convention, not a per-status
 * claim from the reference, and no per-status error code
 * is invented here: the failure record carries
 * `HTTP_<status>` plus whatever free-form error text the
 * client surfaced, and nothing more. If the reference
 * later pins a different success status, only
 * `classifyIlertEventResponse` needs to change.
 *
 * Zero new dependencies: the injected client only. (No
 * `node:crypto` import either: with no idempotency key to
 * derive, there is nothing to hash.)
 */

/** Generic summary used when an event carries no value for the message body. */
export const ILERT_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const ILERT_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Content type the client sends with the JSON body. */
export const ILERT_JSON_CONTENT_TYPE = "application/json";

/** ilert API base URL. */
export const ILERT_API_BASE_URL = "https://api.ilert.com";

/**
 * Events API path template, with the two segments the
 * client alone holds: `{integration}` is the alert
 * source's integration name (e.g. `keep`, `netdata`)
 * and `{apiKey}` is that alert source's API key. The
 * client substitutes both from the alert-source URL it
 * was configured with; the sink never builds this URL,
 * so no key — real or placeholder — ever passes through
 * the sink. Exported so the path shape is pinned in
 * tests, not so the sink can construct a request URL.
 */
export const ILERT_EVENTS_PATH_TEMPLATE = "/api/v1/events/{integration}/{apiKey}";

/** Default `priority` (also the documented low end). */
export const ILERT_DEFAULT_PRIORITY = "LOW";

/** The priorities the re-checked docs allow. */
export const ILERT_PRIORITIES = ["HIGH", "LOW"] as const;

/** One of the priorities the re-checked docs allow (HIGH/LOW). */
export type IlertPriority = (typeof ILERT_PRIORITIES)[number];

/** Default `eventType`. */
export const ILERT_DEFAULT_EVENT_TYPE = "ALERT";

/** The event types the re-checked docs allow. */
export const ILERT_EVENT_TYPES = ["ALERT", "ACCEPT", "RESOLVE"] as const;

/** One of the event types the re-checked docs allow (ALERT/ACCEPT/RESOLVE). */
export type IlertEventType = (typeof ILERT_EVENT_TYPES)[number];

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (JSON) to the alert-source URL it
 * alone holds (`https://api.ilert.com/api/v1/events/
 * {integration}/{apiKey}`), sending `headers` verbatim
 * as the request headers. There is deliberately no `url`
 * field here: the URL carries the alert source's API key
 * in its path, so the sink must never see, build, or hand
 * over a URL — the client posts to the URL it was
 * configured with. No `Idempotency-Key` header is sent:
 * the docs do not verify it for this endpoint, and the
 * alert key already gives a retry its grouping key (see
 * the module header).
 */
export interface IlertEventPostRequest {
  /**
   * Request headers, sent verbatim:
   * `{ "Content-Type": "application/json" }`. There is
   * deliberately no `url` field: the alert-source URL
   * (integration segment and API key in the path) is
   * held by the client alone, never by the sink, and
   * there is no `Authorization` header and no
   * `Idempotency-Key` header.
   */
  headers: Record<string, string>;
  /**
   * The JSON request body, serialized:
   * `{"eventType":"ALERT","summary":"<summary>","details":"key=<key>; traceId=<traceId>","alertKey":"<key>","priority":"LOW"}`
   * (`details` is omitted when the event carries no
   * identifiers and the payload opt-in is off; `alertKey`
   * is omitted when the event carries no key; the payload
   * is appended to `details` only under the
   * `includePayload` opt-in). No credential ever enters
   * the body.
   */
  body: string;
}

/**
 * The result of one POST, as reported by the injected
 * client. The HTTP status decides acceptance: any 2xx
 * means ilert accepted the event. No receipt id is
 * claimed: the re-checked documentation states no
 * response id for this endpoint, so the client surfaces
 * none and `send()` returns no ids. The error text, when
 * the client surfaced one, rides on the failure record;
 * no per-status error code is claimed from the reference
 * (see the module header).
 */
export interface IlertEventPostResponse {
  /** The HTTP status of the POST (e.g. 200, 400, 401, 429, 500). */
  status: number;
  /** Free-form error text from the error body, when the client surfaced one. */
  errorMessage?: string;
}

/**
 * The injected ilert event client. Any client adapter
 * implements this one method; it returns the POST's status
 * — a throw is a codeless transport failure, retryable.
 * The client is expected to POST one event per call,
 * sending `body` verbatim as the request body (JSON),
 * sending `headers` verbatim as the request headers, and
 * posting to the alert-source URL it alone holds
 * (`https://api.ilert.com/api/v1/events/{integration}/
 * {apiKey}`) — the sink never sees that URL.
 */
export interface IlertEventClient {
  post(request: IlertEventPostRequest): Promise<IlertEventPostResponse>;
}

/**
 * Configuration for one ilert sink. The client is
 * injected: without one, `send()` throws
 * `IlertSinkConfigError` (dry runs excepted — they need
 * no client at all). The API key is deliberately absent
 * from this config: the client alone holds the
 * alert-source URL (integration segment and key in the
 * path), and the key is never persisted by the sink.
 */
export interface IlertSinkConfig {
  /**
   * The ilert event client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `IlertEventClient` and alone holds the
   * alert-source URL. Required for real sends; a missing
   * client is a config error, not a silent no-op.
   */
  client?: IlertEventClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }`
   * and performs zero client I/O — no POST call, no stat
   * changes. Messages are still validated (including
   * event-type derivation and the ACCEPT/RESOLVE
   * alert-key rule), so a dry run catches a
   * malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The client is not required in dry-run mode, mirroring
   * the sibling sinks' dry-run exemption; the rest of the
   * config must still be valid — a dry run against a sink
   * with a bad priority would rehearse a request that
   * could never send.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the request body's
   * `details` appends the event body verbatim as a
   * JSON string, truncated to `payloadMaxChars`
   * characters (see below), after the identifiers. When
   * `false` or absent, `details` carries the identifiers
   * only — the default, so event bodies (which routinely
   * carry PII) never leak into an alert unless the
   * operator explicitly asks for them.
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
   * Alert priority: one of HIGH/LOW, default LOW (also
   * the documented low end). Config-held, never derived
   * from the event: the relay does not invent an urgency
   * it was not told. Must be one of the two values when
   * set.
   */
  priority?: IlertPriority;
  /**
   * Default event type: one of ALERT/ACCEPT/RESOLVE,
   * default ALERT. Config-held, overridable per record
   * (see `IlertRecord.eventType`): the relay does not
   * invent a lifecycle transition it was not told. Must
   * be one of the three values when set. A configured
   * `ACCEPT` or `RESOLVE` default still needs an alert
   * key on every record — see `resolveIlertRecord`.
   */
  eventType?: IlertEventType;
}

/** One event to alert about. */
export interface IlertRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Content-derivation source, first priority: the event's
   * subject, when set and non-empty. Also the base of
   * `details` only through the `key`/`traceId`
   * identifiers — the subject itself is not repeated in
   * `details`.
   */
  subject?: string;
  /**
   * Content-derivation source, second priority: the event's key
   * (e.g. aggregate id). Also the alert's `alertKey` (the
   * official grouping key) and a `details` entry, when set.
   * Required when the effective event type is ACCEPT or
   * RESOLVE — without one ilert cannot associate the
   * event with an open alert.
   */
  key?: string;
  /**
   * Content-derivation source, last priority: the trace id.
   * Also a `details` entry, when set.
   */
  traceId?: string;
  /**
   * Per-record event type override: one of
   * ALERT/ACCEPT/RESOLVE. When absent, the config's
   * `eventType` applies, defaulting to ALERT. An
   * ACCEPT or RESOLVE override still needs an alert key
   * on this record — see `resolveIlertRecord`.
   */
  eventType?: IlertEventType;
}

/** One failed message, with its retry lane already mapped. */
export interface IlertFailedRecord {
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
   * (bad input, bad API key, disabled integration, no
   * permission). No per-status error code is claimed
   * from the reference (see the module header).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface IlertSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-298). */
export interface IlertSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for ilert send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already received on ilert's server and are *not* in
 * `failedRecords`.
 */
export class IlertSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: IlertFailedRecord[];
  constructor(message: string, failedRecords: IlertFailedRecord[]) {
    super(message);
    this.name = "IlertSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class IlertSinkConfigError extends IlertSinkError {
  constructor(reason: string) {
    super(`ilert-sink: ${reason}`, []);
    this.name = "IlertSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery.
 * The priority, when set, must be one of HIGH/LOW; the
 * event type, when set, must be one of ALERT/ACCEPT/
 * RESOLVE. There is deliberately no `apiKey` field to
 * validate: the client alone holds the alert-source URL.
 */
export function assertValidIlertSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is IlertSinkConfig {
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
    c.priority !== undefined &&
    (typeof c.priority !== "string" ||
      !(ILERT_PRIORITIES as readonly string[]).includes(c.priority))
  ) {
    throw new RangeError(at("`priority` must be one of HIGH, LOW when set"));
  }
  if (
    c.eventType !== undefined &&
    (typeof c.eventType !== "string" ||
      !(ILERT_EVENT_TYPES as readonly string[]).includes(c.eventType))
  ) {
    throw new RangeError(at("`eventType` must be one of ALERT, ACCEPT, RESOLVE when set"));
  }
}

/**
 * Derive one record's content summary: the first
 * non-empty value among `subject`, `key`, and `traceId`,
 * in that order. Falls back to the generic `webhook
 * event` summary when the record carries none — an alert
 * sink must not silently drop sourceless events.
 */
export function resolveIlertSummary(record: IlertRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return ILERT_FALLBACK_SUMMARY;
}

/**
 * Resolve the event type: the record's override when set,
 * else the config-held value, else `ALERT`.
 */
export function resolveIlertEventType(
  record: IlertRecord,
  config: Pick<IlertSinkConfig, "eventType">
): IlertEventType {
  return record.eventType ?? config.eventType ?? ILERT_DEFAULT_EVENT_TYPE;
}

/**
 * Resolve the alert priority: the config-held value, or
 * `LOW` when none is configured.
 */
export function resolveIlertPriority(
  config: Pick<IlertSinkConfig, "priority">
): IlertPriority {
  return config.priority ?? ILERT_DEFAULT_PRIORITY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood an alert.
 */
export function truncateIlertPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's `details` string: only the event's
 * own identifiers — `key=<key>` and `traceId=<traceId>`
 * when present, joined with `"; "`. Under the
 * `includePayload` opt-in the event body is appended
 * after the identifiers (or alone, when the event carries
 * no identifiers), truncated to `payloadMaxChars`
 * (default 2000). Returns `undefined` when the event
 * carries no identifiers and the opt-in is off, so the
 * field is omitted entirely rather than sent empty.
 */
export function resolveIlertDetails(
  record: IlertRecord,
  config: Pick<IlertSinkConfig, "includePayload" | "payloadMaxChars">
): string | undefined {
  const parts: string[] = [];
  if (record.key !== undefined && record.key !== "") {
    parts.push(`key=${record.key}`);
  }
  if (record.traceId !== undefined && record.traceId !== "") {
    parts.push(`traceId=${record.traceId}`);
  }
  const identifiers = parts.join("; ");
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? ILERT_DEFAULT_PAYLOAD_MAX_CHARS;
    const payload = truncateIlertPayload(record.body, limit);
    return identifiers === "" ? payload : `${identifiers}\n\n${payload}`;
  }
  return identifiers === "" ? undefined : identifiers;
}

/**
 * Build one record's serialized JSON body: `eventType`
 * (the record override, else the config default, else
 * ALERT), `summary` (the derived summary, never
 * truncated — the re-checked docs state no summary
 * length limit), `details` (only the `key`/`traceId`
 * identifiers, with the payload appended only under the
 * `includePayload` opt-in; omitted when empty),
 * `alertKey` (the event key, omitted when the event
 * carries none — the official grouping key), and
 * `priority` (config-held, default LOW). No
 * `customDetails`: the record carries no custom
 * key-value pairs, and the sink never invents any. No
 * `images`: the record carries no image URLs. No
 * credential ever enters the body — the client alone
 * holds the alert-source URL (integration segment and
 * API key in the path).
 */
export function buildIlertEventBody(
  record: IlertRecord,
  config: Pick<IlertSinkConfig, "includePayload" | "payloadMaxChars" | "priority" | "eventType">
): string {
  const event: {
    eventType: IlertEventType;
    summary: string;
    details?: string;
    alertKey?: string;
    priority: IlertPriority;
  } = {
    eventType: resolveIlertEventType(record, config),
    summary: resolveIlertSummary(record),
    priority: resolveIlertPriority(config),
  };
  const details = resolveIlertDetails(record, config);
  if (details !== undefined) {
    event.details = details;
  }
  if (record.key !== undefined && record.key !== "") {
    event.alertKey = record.key;
  }
  return JSON.stringify(event);
}

/**
 * Validate one record. Throws `RangeError` on an empty
 * body string — even without the opt-in, the body is the
 * record's payload, and an empty record is a caller bug
 * that must fail closed, never alert as an empty message.
 * Also throws `RangeError` when the effective event type
 * is ACCEPT or RESOLVE and the record carries no key:
 * without an `alertKey` ilert cannot associate the event
 * with an open alert, so the event must never be sent
 * keyless. A bad per-record `eventType` value fails here
 * too (the config-level check in
 * `assertValidIlertSinkConfig` only covers the config
 * default).
 */
export function resolveIlertRecord(
  record: IlertRecord,
  index: number,
  config: Pick<IlertSinkConfig, "eventType">
): { index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`ilert-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  if (
    record.eventType !== undefined &&
    !(ILERT_EVENT_TYPES as readonly string[]).includes(record.eventType)
  ) {
    throw new RangeError(`ilert-sink: record ${index} \`eventType\` must be one of ALERT, ACCEPT, RESOLVE when set`);
  }
  const eventType = resolveIlertEventType(record, config);
  if (
    (eventType === "ACCEPT" || eventType === "RESOLVE") &&
    (record.key === undefined || record.key === "")
  ) {
    throw new RangeError(
      `ilert-sink: record ${index} \`eventType\` ${eventType} requires an alert key (\`key\`), otherwise ilert cannot associate the event with an open alert`
    );
  }
  return { index };
}

/**
 * Map one ilert POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says ilert could not
 * accept the event right now, not that the payload is
 * poison. Every other non-2xx status (400, 401, 403, and
 * the rest) is a fail-closed message: bad input, bad API
 * key, disabled integration, no permission. Honesty note:
 * the ilert API reference pinned for this item returned
 * 404 when re-checked for this item (2026-11-01), and
 * the re-checked integration docs publish no per-status
 * error-code table for the Events endpoint, so this
 * mapping is the slot convention, not a per-status claim
 * from the reference — and no per-status error code is
 * invented here. Callers only pass non-2xx statuses here;
 * any 2xx is acceptance on its own (see
 * `classifyIlertEventResponse`).
 */
export function classifyIlertRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * The verdict on one event POST: either an acceptance,
 * or a failure with its error code and retry lane.
 */
export type IlertEventVerdict =
  | { accepted: true }
  | { accepted: false; errorCode: string; retryable: boolean; errorMessage?: string };

/**
 * Decide one event POST's verdict from the response the
 * client reported. Any 2xx status is acceptance — the
 * reference pins no per-status success code for this
 * endpoint (see the module header), so the whole 2xx
 * range is accepted, matching the Opsgenie sink: a 200
 * or 201 from a proxy or a future revision is still an
 * acceptance receipt, not a delivery result. No receipt
 * id is required or collected: the re-checked docs state
 * no response id for this endpoint, so a 2xx is
 * acceptance on its own, with nothing to track later.
 * Any non-2xx status is a failure with an `HTTP_<status>`
 * code and the WR-210 lane; the error text rides on the
 * failure record when the client surfaced one. No
 * per-status error code is claimed from the reference
 * (see the module header).
 */
export function classifyIlertEventResponse(
  response: IlertEventPostResponse
): IlertEventVerdict {
  if (response.status >= 200 && response.status < 300) {
    return { accepted: true };
  }
  const verdict: IlertEventVerdict = {
    accepted: false,
    errorCode: `HTTP_${response.status}`,
    retryable: classifyIlertRecordFailure(response.status),
  };
  if (response.errorMessage !== undefined && response.errorMessage !== "") {
    verdict.errorMessage = response.errorMessage;
  }
  return verdict;
}

/**
 * ilert sink (WR-298). One event is sent per record; the
 * caller owns retry / dead-letter policy around `send()`
 * — this class performs one POST attempt per message
 * through the injected client and reports its outcome.
 * Failures throw `IlertSinkError` carrying exactly the
 * failed messages with their retry lanes. The sink keeps
 * no per-alert state: a later event carrying the same
 * `alertKey` after a RESOLVE is sent exactly like any
 * other event, and ilert creates a new alert for it — a
 * resolved alert is never reopened, and the sink does
 * not try to track that.
 */
export class IlertSink {
  private readonly cfg: IlertSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: IlertSinkConfig) {
    assertValidIlertSinkConfig(config, "IlertSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): IlertSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send the events, in input order. Throws
   * `IlertSinkConfigError` when no client was injected,
   * and `IlertSinkError` when any message fails
   * (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: IlertRecord[]): Promise<IlertSendResult> {
    const resolved = records.map((r, i) => resolveIlertRecord(r, i, this.cfg));
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
      throw new IlertSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const failedRecords: IlertFailedRecord[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          headers: {
            "Content-Type": ILERT_JSON_CONTENT_TYPE,
          },
          body: buildIlertEventBody(records[i], this.cfg),
        });
        const verdict = classifyIlertEventResponse(response);
        if (verdict.accepted) {
          // Any 2xx is acceptance on its own: the status is
          // the acceptance receipt, and the alert itself is
          // created asynchronously by ilert — the response is
          // an acceptance receipt, not an alert. No receipt
          // id is documented for this endpoint, so none is
          // collected.
          sent += 1;
          continue;
        }
        const failed: IlertFailedRecord = {
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
        failedRecords.push(toIlertFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new IlertSinkError(
        `ilert-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent };
  }
}

/**
 * Convert a client throw into a failed message: a codeless
 * transport failure (`TRANSPORT_ERROR`, retryable — the SQS
 * no-status rule). A retry reuses the same alert key, so it
 * lands on the open alert rather than creating a second
 * one (see the module header).
 */
function toIlertFailedRecord(err: unknown, index: number): IlertFailedRecord {
  const failed: IlertFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
