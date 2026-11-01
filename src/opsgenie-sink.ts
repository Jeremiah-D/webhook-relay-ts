/**
 * Opsgenie on-call alert delivery sink (WR-297).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are the on-call engineer's phone, reached
 * through an alerting API. Where the PagerDuty sink
 * (WR-248) posts an Events API v2 event with a
 * `routing_key` carried inside the body and an
 * `event_action`/`dedup_key` envelope, this sink creates
 * an alert through Opsgenie's Alert API v2: one event is
 * sent as one POST that Opsgenie accepts as one alert
 * (or, when an open alert already carries the same alias,
 * as a count increment on that alert — see alias below),
 * and Opsgenie — not the relay — owns the alert, the
 * escalation, the notification, and the alert lifecycle
 * (checked later through the Get Request Status endpoint,
 * out of scope here).
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need an Opsgenie
 * server. The sink owns the relay-side concerns — the
 * message derivation, the alias, the description, the
 * priority, the payload-inclusion policy, the per-message
 * failure mapping — and the injected client owns the wire
 * protocol, including the POST call, the authentication,
 * and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://api.opsgenie.com/v2/alerts",
 *     headers: { "Content-Type": "application/json" },
 *     body: "{\"message\":\"<summary>\",\"alias\":\"<key>\",\"description\":\"<summary>\",\"details\":{\"key\":\"<key>\",\"traceId\":\"<traceId>\"},\"priority\":\"P3\",\"source\":\"webhook-relay\"}" }
 *
 * The client POSTs to that URL, sending `body`
 * verbatim as the request body (JSON), sending `headers`
 * verbatim as the request headers, and sending the
 * `Authorization: GenieKey <key>` header carrying the API
 * key — which it alone holds. Five things about this
 * shape are deliberate, and all follow the sibling sinks
 * or the backlog pins:
 *
 * - The API key is held by the client alone. The sink
 *   never receives the key, never places it in the
 *   request, and never logs it: the sink config has no
 *   `apiKey` field at all, and the handed request
 *   therefore carries no credential, so there is nothing
 *   in it for a log line or a retry queue to leak — and
 *   the key is never persisted by the sink. The key rides
 *   in the `Authorization: GenieKey <key>` header (unlike
 *   the Pushy sink's `?api_key=` query parameter and the
 *   PagerDuty sink's `routing_key` inside the body), so
 *   the sink hands the client the bare endpoint URL and
 *   the bare `Content-Type` header and the client adds
 *   the authorization header itself: the sink's URL and
 *   body never contain a key, a placeholder, or anything
 *   that looks like one. This is the Opsgenie form of the
 *   MagicBell rule (whose Project JWT the client alone
 *   holds as an `Authorization: Bearer` header), with
 *   Opsgenie's own credential source: the API key of an
 *   API integration, verified against the current docs
 *   (docs.opsgenie.com/docs/alert-api, re-checked
 *   2026-11-01 — the sample request sends `-H
 *   "Authorization: GenieKey
 *   eb243592-faa2-4ba2-a551q-1afdf565c889"`, and the
 *   migration guide states "API Key is moved to
 *   Authentication header instead of request payloads").
 * - The endpoint is the Create Alert API the backlog
 *   pins: `POST https://api.opsgenie.com/v2/alerts`,
 *   the fixed US host. The EU instance
 *   (`https://api.eu.opsgenie.com`) is out of scope for
 *   this item: an EU operator's client points at the EU
 *   host, but the sink itself always hands the US URL,
 *   and the sink never switches hosts on its own.
 * - `message` is mandatory and limited to 130 characters
 *   by the reference, so the sink truncates the derived
 *   summary to exactly 130 characters, with no truncation
 *   marker — a marker would itself push the message over
 *   the official limit. The summary is the first
 *   non-empty value among `subject`, `key`, and
 *   `traceId`, in that order, falling back to the generic
 *   `webhook event`: an alert sink that silently dropped
 *   sourceless events would hide exactly the deliveries
 *   an operator most needs to see.
 * - `alias` is the event's `key`, sent when one exists
 *   and omitted entirely when the event carries none: a
 *   keyless event still alerts, it just carries no
 *   dedup key. The alias is the official de-duplication
 *   key: the reference calls it "the key element of Alert
 *   De-Duplication", so a second alert with the same
 *   alias while the first is still open increments that
 *   alert's count instead of creating a new alert. The
 *   alias is sent verbatim, never truncated: truncating
 *   a dedup key would silently merge distinct alerts,
 *   and the reference's 512-character limit is the
 *   operator's to respect. The same alias also makes a
 *   transport-failure retry safe: replaying the same
 *   record reuses the same alias, so the retry bumps the
 *   open alert's count instead of paging the on-call
 *   engineer twice.
 * - `description` carries the derived summary (the full
 *   value, not the 130-character message truncation —
 *   the reference allows 15000 characters here), and,
 *   only under the `includePayload` opt-in, the event
 *   body appended after it, truncated to
 *   `payloadMaxChars` characters (default 2000) with a
 *   truncation marker. `details` carries only the event's
 *   own identifiers — `key` and `traceId` when present,
 *   nothing else — so the alert's custom properties stay
 *   identifiers, never payload. `priority` is config-held
 *   and defaults to `P3` (the API default; P1–P5).
 *   `source` is fixed to `"webhook-relay"`: the reference
 *   defaults it to the incoming request's IP address,
 *   which would say nothing about where the alert came
 *   from, so the sink pins the relay's name instead.
 *   `responders`, `visibleTo`, `actions`, and `tags` are
 *   out of scope: the API key belongs to a team
 *   integration, and that integration owns the routing —
 *   the reference notes a `responders` field "will be
 *   overwritten with the owner team" when the API key
 *   belongs to a team integration, so the sink sends
 *   none and never invents a routing decision.
 *
 * Acceptance is decided by the HTTP status alone: any
 * 2xx status means Opsgenie accepted the request, and
 * `send()` returns the collected request ids in send
 * order, so a caller that only inspects the result still
 * has the receipts for the Get Request Status endpoint.
 * A 2xx is only an acceptance receipt, not an alert:
 * the reference states that create requests "are
 * processed asynchronously to provide higher availability
 * and scalability, therefore valid requests for those
 * endpoints are responded to with HTTP status `202 -
 * Accepted`", and the sample response is only
 * `{ result: "Request will be processed", took,
 * requestId }` — no alert id, no alert state. The
 * request id is the receipt for tracking the request
 * later (`GET /v2/alerts/requests/:requestId`); a 2xx
 * that carries no request id is still an acceptance —
 * the status itself is the acceptance credential here,
 * unlike the Pushy sink, where a 200 without a push id
 * is a failure — but no request id means no later
 * tracking for that alert, so the collected id is
 * recorded only when the client surfaced one. The sink
 * accepts the whole 2xx range, not just 202: the
 * reference pins 202 for valid requests, and a 200 or
 * 201 from a proxy or a future revision is still an
 * acceptance receipt, not a delivery result.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over the HTTP status:
 *
 * - a non-2xx POST throws `OpsgenieSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Opsgenie could
 *   not accept the alert right now, not that the payload
 *   is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   and 403 (bad input, bad API key, wrong region, no
 *   permission): retrying them burns the retry budget
 *   for nothing, and rerouting them elsewhere would page
 *   an on-call engineer the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload (a retry after a
 *   transport failure reuses the same alias, so it bumps
 *   the open alert's count rather than creating a second
 *   alert — see alias above);
 * - a missing client throws `OpsgenieSinkConfigError`,
 *   which `classifyFailure` maps to `non_retryable`
 *   (the WR-116 rule).
 *
 * One honesty note on the failure mapping: the Alert API
 * reference page re-checked for this item
 * (docs.opsgenie.com/docs/alert-api, 2026-11-01) pins the
 * endpoint, the `GenieKey` header, the 130-character
 * message limit, the P1–P5 priority range with a P3
 * default, the alias de-duplication, and the 202
 * asynchronous-acceptance semantics — but it does not
 * publish a per-status error-code table for the create
 * endpoint (no 429 or 422 mention on the page at all).
 * The 429/5xx-retryable, other-4xx-fail-closed mapping
 * above is therefore the slot convention, not a
 * per-status claim from that page, and no per-status
 * error code is invented here: the failure record
 * carries `HTTP_<status>` plus whatever free-form error
 * text the client surfaced, and nothing more.
 *
 * Zero new dependencies: the injected client only. (No
 * `node:crypto` import either: with no idempotency key to
 * derive, there is nothing to hash.)
 */

/** Generic summary used when an event carries no value for the message body. */
export const OPSGENIE_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const OPSGENIE_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Content type the client sends with the JSON body. */
export const OPSGENIE_JSON_CONTENT_TYPE = "application/json";

/** Opsgenie API base URL (US instance; the EU host is out of scope for this item). */
export const OPSGENIE_API_BASE_URL = "https://api.opsgenie.com";

/**
 * Create Alert endpoint, without any credential:
 * the client adds the `Authorization: GenieKey <key>`
 * header (the key it alone holds). The sink's URL never
 * contains a key.
 */
export const OPSGENIE_ALERTS_URL = `${OPSGENIE_API_BASE_URL}/v2/alerts`;

/** Official `message` limit, in characters (per the reference). */
export const OPSGENIE_MESSAGE_MAX_CHARS = 130;

/** Official `alias` limit, in characters (per the reference; the alias is sent verbatim). */
export const OPSGENIE_ALIAS_MAX_CHARS = 512;

/** Fixed `source` value: the relay's name, not the request's IP address. */
export const OPSGENIE_SOURCE = "webhook-relay";

/** Default `priority` (also the API default). */
export const OPSGENIE_DEFAULT_PRIORITY = "P3";

/** The priorities the reference allows. */
export const OPSGENIE_PRIORITIES = ["P1", "P2", "P3", "P4", "P5"] as const;

/** One of the priorities the reference allows (P1–P5). */
export type OpsgeniePriority = (typeof OPSGENIE_PRIORITIES)[number];

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (JSON), sends `headers` verbatim
 * as the request headers, and sends the `Authorization:
 * GenieKey <key>` header carrying the API key — which the
 * sink never sees. No `Idempotency-Key` header is sent:
 * the docs do not verify it for this endpoint, and the
 * alias already gives a retry its de-duplication key
 * (see the module header).
 */
export interface OpsgenieAlertPostRequest {
  /**
   * Always `https://api.opsgenie.com/v2/alerts` — the
   * Create Alert API, without any credential. The client
   * adds the `Authorization: GenieKey <key>` header; the
   * EU host (`https://api.eu.opsgenie.com`) is out of
   * scope for this item.
   */
  url: string;
  /**
   * Request headers, sent verbatim:
   * `{ "Content-Type": "application/json" }`. The
   * `Authorization: GenieKey <key>` header is added by
   * the client, never by the sink, and there is
   * deliberately no `Idempotency-Key` header.
   */
  headers: Record<string, string>;
  /**
   * The JSON request body, serialized:
   * `{"message":"<summary, truncated to 130 chars>","alias":"<key>","description":"<summary>[\\n\\n<payload>]","details":{"key":"<key>","traceId":"<traceId>"},"priority":"P3","source":"webhook-relay"}`
   * (`alias` is omitted when the event carries no key;
   * `details` carries only the identifiers that exist;
   * the payload is appended to `description` only under
   * the `includePayload` opt-in). No credential ever
   * enters the body.
   */
  body: string;
}

/**
 * The result of one POST, as reported by the injected
 * client. The HTTP status decides acceptance: any 2xx
 * means Opsgenie accepted the request, and the
 * `requestId` — when the client surfaced one — is the
 * receipt for tracking the request later through Get
 * Request Status (`GET /v2/alerts/requests/:requestId`).
 * A 2xx without a request id is still an acceptance (the
 * status is the acceptance credential here), just one
 * with no later tracking. The reference's success body is
 * only `{ result: "Request will be processed", took,
 * requestId }`: no alert id, no alert state — a 202 is an
 * acceptance receipt, not an alert. The error text, when
 * the client surfaced one, rides on the failure record;
 * no per-status error code is claimed from the reference
 * (see the module header).
 */
export interface OpsgenieAlertPostResponse {
  /** The HTTP status of the POST (e.g. 202, 400, 401, 429, 500). */
  status: number;
  /** The request id from the success body, when the client surfaced one. */
  requestId?: string;
  /** Free-form error text from the error body, when the client surfaced one. */
  errorMessage?: string;
}

/**
 * The injected Opsgenie alert client. Any client adapter
 * implements this one method; it returns the POST's status
 * and the request id when present — a throw is a codeless
 * transport failure, retryable. The client is expected to
 * POST one alert per call, sending `body` verbatim as
 * the request body (JSON), sending `headers` verbatim as
 * the request headers, and sending the `Authorization:
 * GenieKey <key>` header carrying the API key — which the
 * sink never sees.
 */
export interface OpsgenieAlertClient {
  post(request: OpsgenieAlertPostRequest): Promise<OpsgenieAlertPostResponse>;
}

/**
 * Configuration for one Opsgenie sink. The client is
 * injected: without one, `send()` throws
 * `OpsgenieSinkConfigError` (dry runs excepted — they need
 * no client at all). The API key is deliberately absent
 * from this config: the client alone holds it (sent as
 * the `Authorization: GenieKey <key>` header), and it is
 * never persisted by the sink.
 */
export interface OpsgenieSinkConfig {
  /**
   * The Opsgenie alert client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `OpsgenieAlertClient` and alone holds the
   * API key. Required for real sends; a missing client is
   * a config error, not a silent no-op.
   */
  client?: OpsgenieAlertClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, requestIds: [], dryRun: true }`
   * and performs zero client I/O — no POST call, no stat
   * changes. Messages are still validated (including
   * message derivation), so a dry run catches a
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
   * `description` appends the event body verbatim as a
   * JSON string, truncated to `payloadMaxChars`
   * characters (see below), after the summary. When
   * `false` or absent, `description` carries the summary
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
   * an alert — and stays well under the reference's
   * 15000-character `description` limit. Must be a
   * positive integer when set.
   */
  payloadMaxChars?: number;
  /**
   * Alert priority: one of P1–P5, default P3 (also the
   * API default). Config-held, never derived from the
   * event: the relay does not invent an urgency it was
   * not told. Must be one of the five values when set.
   */
  priority?: OpsgeniePriority;
}

/** One event to alert about. */
export interface OpsgenieRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Content-derivation source, first priority: the event's
   * subject, when set and non-empty. Also the base of
   * `description`.
   */
  subject?: string;
  /**
   * Content-derivation source, second priority: the event's key
   * (e.g. aggregate id). Also the alert's `alias` (the
   * official de-duplication key) and a `details` entry,
   * when set.
   */
  key?: string;
  /**
   * Content-derivation source, last priority: the trace id.
   * Also a `details` entry, when set.
   */
  traceId?: string;
}

/** One failed message, with its retry lane already mapped. */
export interface OpsgenieFailedRecord {
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
   * (bad input, bad API key, wrong region, no
   * permission). No per-status error code is claimed
   * from the reference page (see the module header).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface OpsgenieSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /**
   * Request ids in send order — the id of each accepted
   * message that reported one. Empty in dry-run mode, and
   * an accepted message that reported no request id
   * contributes no entry here: it is still accepted (the
   * 2xx status is the acceptance credential), it just has
   * no later tracking.
   */
  requestIds: string[];
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-297). */
export interface OpsgenieSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Opsgenie send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already received on Opsgenie's server and are *not* in
 * `failedRecords`.
 */
export class OpsgenieSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: OpsgenieFailedRecord[];
  constructor(message: string, failedRecords: OpsgenieFailedRecord[]) {
    super(message);
    this.name = "OpsgenieSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class OpsgenieSinkConfigError extends OpsgenieSinkError {
  constructor(reason: string) {
    super(`opsgenie-sink: ${reason}`, []);
    this.name = "OpsgenieSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery.
 * The priority, when set, must be one of P1–P5. There is
 * deliberately no `apiKey` field to validate: the client
 * alone holds the key.
 */
export function assertValidOpsgenieSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is OpsgenieSinkConfig {
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
      !(OPSGENIE_PRIORITIES as readonly string[]).includes(c.priority))
  ) {
    throw new RangeError(at("`priority` must be one of P1, P2, P3, P4, P5 when set"));
  }
}

/**
 * Derive one record's content summary: the first
 * non-empty value among `subject`, `key`, and `traceId`,
 * in that order. Falls back to the generic `webhook
 * event` summary when the record carries none — an alert
 * sink must not silently drop sourceless events.
 */
export function resolveOpsgenieSummary(record: OpsgenieRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return OPSGENIE_FALLBACK_SUMMARY;
}

/**
 * Truncate the alert message to the reference's
 * 130-character limit, with no truncation marker — a
 * marker would itself push the message over the official
 * limit.
 */
export function truncateOpsgenieMessage(summary: string): string {
  if (summary.length <= OPSGENIE_MESSAGE_MAX_CHARS) {
    return summary;
  }
  return summary.slice(0, OPSGENIE_MESSAGE_MAX_CHARS);
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood an alert — and stays well
 * under the reference's 15000-character `description`
 * limit.
 */
export function truncateOpsgeniePayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's `description`: the derived summary
 * in full (not the 130-character message truncation —
 * the reference allows 15000 characters here). Under the
 * `includePayload` opt-in the event body is appended
 * after the summary, truncated to `payloadMaxChars`
 * (default 2000); without the opt-in the description
 * carries the summary only.
 */
export function resolveOpsgenieDescription(
  record: OpsgenieRecord,
  config: Pick<OpsgenieSinkConfig, "includePayload" | "payloadMaxChars">
): string {
  const summary = resolveOpsgenieSummary(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? OPSGENIE_DEFAULT_PAYLOAD_MAX_CHARS;
    return `${summary}\n\n${truncateOpsgeniePayload(record.body, limit)}`;
  }
  return summary;
}

/**
 * Derive one record's `details`: only the event's own
 * identifiers — `key` and `traceId` when present, nothing
 * else. An event with neither identifier gets an empty
 * `details` object: the alert's custom properties stay
 * identifiers, never payload.
 */
export function resolveOpsgenieDetails(
  record: OpsgenieRecord
): Record<string, string> {
  const details: Record<string, string> = {};
  if (record.key !== undefined && record.key !== "") {
    details.key = record.key;
  }
  if (record.traceId !== undefined && record.traceId !== "") {
    details.traceId = record.traceId;
  }
  return details;
}

/**
 * Resolve the alert priority: the config-held value, or
 * `P3` — also the API default — when none is configured.
 */
export function resolveOpsgeniePriority(
  config: Pick<OpsgenieSinkConfig, "priority">
): OpsgeniePriority {
  return config.priority ?? OPSGENIE_DEFAULT_PRIORITY;
}

/**
 * Build one record's serialized JSON body: `message`
 * (the derived summary, truncated to the official 130
 * characters), `alias` (the event key, omitted when the
 * event carries none — the official de-duplication key),
 * `description` (the summary in full, with the payload
 * appended only under the `includePayload` opt-in),
 * `details` (only the `key`/`traceId` identifiers),
 * `priority` (config-held, default P3), and `source`
 * (fixed `"webhook-relay"`). No `responders`,
 * `visibleTo`, `actions`, or `tags`: the API key's team
 * integration owns the routing. No credential ever
 * enters the body — the client alone holds the API key
 * (sent as the `Authorization: GenieKey <key>` header).
 */
export function buildOpsgenieAlertBody(
  record: OpsgenieRecord,
  config: Pick<OpsgenieSinkConfig, "includePayload" | "payloadMaxChars" | "priority">
): string {
  const alert: {
    message: string;
    alias?: string;
    description: string;
    details: Record<string, string>;
    priority: OpsgeniePriority;
    source: string;
  } = {
    message: truncateOpsgenieMessage(resolveOpsgenieSummary(record)),
    description: resolveOpsgenieDescription(record, config),
    details: resolveOpsgenieDetails(record),
    priority: resolveOpsgeniePriority(config),
    source: OPSGENIE_SOURCE,
  };
  if (record.key !== undefined && record.key !== "") {
    alert.alias = record.key;
  }
  return JSON.stringify(alert);
}

/**
 * Validate one record's body. Throws `RangeError` on an
 * empty body string — even without the opt-in, the body is
 * the record's payload, and an empty record is a caller
 * bug that must fail closed, never alert as an empty
 * message.
 */
export function resolveOpsgenieRecord(
  record: OpsgenieRecord,
  index: number
): { index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`opsgenie-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { index };
}

/**
 * Map one Opsgenie POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says Opsgenie could not
 * accept the alert right now, not that the payload is
 * poison. Every other non-2xx status (400, 401, 403, and
 * the rest) is a fail-closed message: bad input, bad API
 * key, wrong region, no permission. Honesty note: the
 * Alert API reference page re-checked for this item does
 * not publish a per-status error-code table for the create
 * endpoint (no 429 or 422 mention on the page at all), so
 * this mapping is the slot convention, not a per-status
 * claim from that page — and no per-status error code is
 * invented here. Callers only pass non-2xx statuses here;
 * any 2xx is acceptance on its own (see
 * `classifyOpsgenieAlertResponse`).
 */
export function classifyOpsgenieRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * The verdict on one alert POST: either an acceptance,
 * or a failure with its error code and retry lane.
 */
export type OpsgenieAlertVerdict =
  | { accepted: true }
  | { accepted: false; errorCode: string; retryable: boolean; errorMessage?: string };

/**
 * Decide one alert POST's verdict from the response the
 * client reported. Any 2xx status is acceptance — the
 * reference pins 202 for valid requests ("valid requests
 * for those endpoints are responded to with HTTP status
 * `202 - Accepted`"), and a 200 or 201 from a proxy or a
 * future revision is still an acceptance receipt, not a
 * delivery result. The acceptance is only a receipt: the
 * reference's success body is `{ result: "Request will be
 * processed", took, requestId }` — no alert id, no alert
 * state — and the alert itself is created asynchronously,
 * tracked later through Get Request Status. A 2xx that
 * carries no request id is still an acceptance (the status
 * is the acceptance credential here, unlike the Pushy
 * sink's 200-without-a-push-id failure), just one with no
 * later tracking. Any non-2xx status is a failure with an
 * `HTTP_<status>` code and the WR-210 lane; the error
 * text rides on the failure record when the client
 * surfaced one. No per-status error code is claimed from
 * the reference (see the module header).
 */
export function classifyOpsgenieAlertResponse(
  response: OpsgenieAlertPostResponse
): OpsgenieAlertVerdict {
  if (response.status >= 200 && response.status < 300) {
    return { accepted: true };
  }
  const verdict: OpsgenieAlertVerdict = {
    accepted: false,
    errorCode: `HTTP_${response.status}`,
    retryable: classifyOpsgenieRecordFailure(response.status),
  };
  if (response.errorMessage !== undefined && response.errorMessage !== "") {
    verdict.errorMessage = response.errorMessage;
  }
  return verdict;
}

/**
 * Opsgenie sink (WR-297). One alert is sent per record; the
 * caller owns retry / dead-letter policy around `send()`
 * — this class performs one POST attempt per message
 * through the injected client and reports its outcome.
 * Failures throw `OpsgenieSinkError` carrying exactly the
 * failed messages with their retry lanes.
 */
export class OpsgenieSink {
  private readonly cfg: OpsgenieSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: OpsgenieSinkConfig) {
    assertValidOpsgenieSinkConfig(config, "OpsgenieSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): OpsgenieSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send the alerts, in input order. Throws
   * `OpsgenieSinkConfigError` when no client was injected,
   * and `OpsgenieSinkError` when any message fails
   * (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: OpsgenieRecord[]): Promise<OpsgenieSendResult> {
    const resolved = records.map((r, i) => resolveOpsgenieRecord(r, i));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The client
      // is not required here, mirroring the sibling sinks'
      // dry-run exemption; the rest of the config was already
      // validated at construction.
      return { ok: true, sent: 0, requestIds: [], dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new OpsgenieSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const failedRecords: OpsgenieFailedRecord[] = [];
    const requestIds: string[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          url: OPSGENIE_ALERTS_URL,
          headers: {
            "Content-Type": OPSGENIE_JSON_CONTENT_TYPE,
          },
          body: buildOpsgenieAlertBody(records[i], this.cfg),
        });
        const verdict = classifyOpsgenieAlertResponse(response);
        if (verdict.accepted) {
          // Any 2xx is acceptance on its own: the status is
          // the acceptance receipt, and the alert itself is
          // created asynchronously — the response is an
          // acceptance receipt, not an alert. The request id,
          // when the client surfaced one, is the receipt for
          // tracking the request later through Get Request
          // Status; a 2xx without one is still accepted.
          sent += 1;
          if (typeof response.requestId === "string" && response.requestId !== "") {
            requestIds.push(response.requestId);
          }
          continue;
        }
        const failed: OpsgenieFailedRecord = {
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
        failedRecords.push(toOpsgenieFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new OpsgenieSinkError(
        `opsgenie-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent, requestIds };
  }
}

/**
 * Convert a client throw into a failed message: a codeless
 * transport failure (`TRANSPORT_ERROR`, retryable — the SQS
 * no-status rule). A retry reuses the same alias, so it
 * bumps the open alert's count rather than creating a
 * second alert (see the module header).
 */
function toOpsgenieFailedRecord(err: unknown, index: number): OpsgenieFailedRecord {
  const failed: OpsgenieFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
