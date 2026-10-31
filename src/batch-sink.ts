/**
 * Batch push notification delivery sink (WR-290).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's device. Where the Iterable sink
 * (WR-288) delivers push notifications through Iterable's
 * push/target API with an `Api-Key` header the client alone
 * holds and a `campaignId`/`recipientEmail`/`dataFields`
 * envelope, and the Pusher Beams sink (WR-289) publishes to
 * a fixed interest set with a `Bearer` instance secret key,
 * this sink delivers push notifications through Batch's
 * Transactional API: one event is sent as one POST that
 * Batch accepts for one recipient set, and Batch — not the
 * relay — owns the audience targeting, the delivery, and
 * the retention of the notification.
 *
 * This module is `batch-sink.ts`, not `batch.ts`: `src/
 * batch.ts` (WR-17) is the relay's own batch delivery
 * merging — holding same-endpoint items and flushing them
 * as one merged HTTP delivery. The two share a word and
 * nothing else; do not confuse them.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Batch
 * server. The sink owns the relay-side concerns — the
 * analysis group, the recipient selection, the message
 * derivation, the payload-inclusion policy, the per-message
 * failure mapping — and the injected client owns the wire
 * protocol, including the POST call, both authentications,
 * and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://api.batch.com/1.1/{apiKey}/transactional/send",
 *     headers: { "Content-Type": "application/json" },
 *     body: "{\"group_id\":\"webhook-relay\",\"recipients\":{\"custom_ids\":[\"user-1\"]},\"message\":{\"title\":\"<title>\",\"body\":\"<body>\"}}" }
 *
 * The client POSTs to that URL, sending `body`
 * verbatim as the request body (JSON) and `headers`
 * verbatim as the request headers, and authenticating
 * with an `X-Authorization: <REST API key>` header
 * carrying the company REST API key — which it alone
 * holds. Six things about this shape are deliberate, and
 * all follow the sibling sinks or the backlog pins:
 *
 * - Both keys are held by the client alone. The sink
 *   never receives either key, never places either in the
 *   request, and never logs either: the app API key rides
 *   in the URL path, so the sink hands the client the URL
 *   as a template — `https://api.batch.com/1.1/{apiKey}/
 *   transactional/send` — and the client substitutes the
 *   `{apiKey}` placeholder with the app API key it alone
 *   holds before sending; the company REST API key rides
 *   in the `X-Authorization` header, which the client adds
 *   from the key it alone holds. The handed request
 *   therefore carries no credential at all, so there is
 *   nothing in it for a log line or a retry queue to leak
 *   — and neither key is ever persisted by the sink. This
 *   is the Batch form of the Pusher Beams rule (whose
 *   instance secret key the client alone holds as a
 *   `Bearer` header), extended to the URL path because
 *   Batch authenticates that way: the app key in the path
 *   identifies the app, the REST key in the header
 *   authorizes the call.
 * - The endpoint is the Transactional API the backlog
 *   pins: `POST https://api.batch.com/1.1/{apiKey}/
 *   transactional/send`. The docs (doc.batch.com,
 *   re-checked 2026-10-31) describe it as the call that
 *   sends an action-oriented, time-sensitive push to a
 *   specific user ID or a group of IDs — a device token,
 *   an install ID, or a custom user ID.
 * - The `group_id` is config-held and required: it is
 *   only an analysis grouping (Batch uses it to group the
 *   send in the dashboard), never a routing or audience
 *   decision. One sink carries one fixed group; when the
 *   config sets none, the sink uses `"webhook-relay"`, so
 *   a send never fails for want of a grouping label — the
 *   default is a relay-chosen label, not a Batch value,
 *   and it is documented as such.
 * - The `recipients` are config-held and required: one of
 *   `tokens` (device push tokens), `custom_ids` (custom
 *   user IDs), or `install_ids` (Batch installation IDs),
 *   at least one of the three, each a non-empty list of
 *   non-empty strings when present. One sink targets one
 *   fixed recipient set; the sink never invents a
 *   recipient, and it never defaults to the whole audience
 *   — there is no "all" here, and a send with no
 *   recipient anywhere would notify nobody Batch can
 *   name. A recipient list that is present but empty is a
 *   config error at construction, not a silent no-op at
 *   send time.
 * - The platforms and the environment are not selected
 *   by the sink. Batch serves iOS, Android, and Web from
 *   the same call, routing each recipient by how that
 *   recipient registered; and Dev and Live are separate
 *   publications because the app and REST keys are
 *   per-environment — the client holds the Dev keys or
 *   the Live keys, and the sink sends one message either
 *   way. An operator who needs a Dev send and a Live
 *   send builds two sinks with two clients.
 * - The `custom_payload` is never rendered by Batch. Per
 *   the docs, the CEP version of the API does not render
 *   template tags inside `custom_payload`: a `{{...}}`
 *   sequence in the event body arrives literally, so the
 *   sink never relies on Batch-side rendering and never
 *   pre-renders tags itself — the payload is the event
 *   body verbatim, truncated, as a JSON string.
 *
 * Acceptance is decided by the HTTP status plus the
 * response body's transactional token: a 201 means Batch
 * received the send, and the success body carries a
 * transactional response token — the receipt the operator
 * uses in the dashboard (Settings > Debug) to check the
 * effective sending time against the API call time. The
 * client surfaces the status and the token when present;
 * `send()` returns the collected tokens in send order, so
 * a caller that only inspects the result still has the
 * receipts. A successful response is only an acceptance
 * receipt, not a delivery result: delivery is handled by
 * Batch and the platform gateways, and surfaces later
 * through Batch's Transactional Stats API. A 201 without
 * a token is still an acceptance — the docs promise the
 * token on success, but the status is the verdict and a
 * missing token must not turn an accepted send into a
 * failure. Any status other than 201 is a failure,
 * including any other 2xx: the docs promise 201 for this
 * endpoint, so an unexpected 2xx is not an acceptance the
 * sink can trust.
 *
 * Message content — a push notification carries a title
 * and a body, both derived from the event's own values:
 * the first non-empty value among `subject`, `key`, and
 * `traceId`, in that order, is the summary. The body takes
 * that summary, so an event with none of the values still
 * notifies, with the generic summary `webhook event`: a
 * notification sink that silently dropped sourceless
 * events would hide exactly the deliveries an operator
 * most needs to see, and the recipients — not the content
 * — are the delivery contract here, so no invented target
 * is at stake. The title takes the `subject` alone, when
 * one exists, and is omitted otherwise: the docs make
 * `message.title` optional and `message.body` required,
 * so a subjectless event notifies with a body and no
 * title rather than a title invented from a key or a
 * trace id. Both go into `message` as `title` (when
 * present) and `body` (always).
 *
 * Payload inclusion — by default the notification
 * carries the summary only, never the full payload:
 * event bodies routinely carry PII, secrets, or
 * customer data, and a device is a far wider audience
 * than a queue or a stream. Opting into `includePayload`
 * appends the event body as `custom_payload` — a JSON
 * string carrying the body verbatim, truncated to
 * `payloadMaxChars` characters (default 2000) with a
 * truncation marker — the opt-in is explicit, and the
 * truncation is unconditional, so even an opted-in body
 * cannot flood a device. The payload rides in its own
 * field, not inside the notification body: Batch's
 * `custom_payload` is data for the app, not text for the
 * screen.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over the HTTP status:
 *
 * - a non-201 POST throws `BatchSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Batch could not
 *   accept the message right now, not that the payload
 *   is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-201 status, including 400, 401,
 *   402, and 404 (bad recipients or payload, bad REST API
 *   key, unknown app API key): retrying them burns the
 *   retry budget for nothing, and rerouting them
 *   elsewhere would notify people the operator never
 *   chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client throws `BatchSinkConfigError`,
 *   which `classifyFailure` maps to `non_retryable`
 *   (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for the message body. */
export const BATCH_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const BATCH_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Default analysis group when the config sets no `groupId`. */
export const BATCH_DEFAULT_GROUP_ID = "webhook-relay";

/** Content type the client sends with the JSON body. */
export const BATCH_JSON_CONTENT_TYPE = "application/json";

/**
 * Transactional send endpoint, as a URL template: the
 * `{apiKey}` placeholder is the app API key, which the
 * client alone holds and substitutes before sending. The
 * sink never sees the key and never builds a URL with a
 * real one in it.
 */
export const BATCH_TRANSACTIONAL_SEND_URL_TEMPLATE =
  "https://api.batch.com/1.1/{apiKey}/transactional/send";

/** Recipient identifier kinds, named exactly as the Batch API spells them. */
export type BatchRecipientKind = "tokens" | "custom_ids" | "install_ids";

/**
 * The fixed recipient set of one sink, held by the config.
 * At least one of the three kinds must be present, each a
 * non-empty list of non-empty strings when present. There
 * is no "all" — the sink never defaults to the whole
 * audience, and a present-but-empty list is a config
 * error, not a silent no-op.
 */
export interface BatchRecipients {
  /** Device push tokens. */
  tokens?: string[];
  /** Custom user IDs. */
  custom_ids?: string[];
  /** Batch installation IDs. */
  install_ids?: string[];
}

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it substitutes the
 * `{apiKey}` placeholder in `url` with the app API key it
 * alone holds, POSTs `body` verbatim as the request body
 * (JSON), sends `headers` verbatim as the request headers,
 * and authenticates with an `X-Authorization: <REST API
 * key>` header carrying the company REST API key — which
 * the sink never sees.
 */
export interface BatchMessagePostRequest {
  /**
   * Always the template
   * `https://api.batch.com/1.1/{apiKey}/transactional/send`
   * — the client replaces `{apiKey}` with the app API key
   * it alone holds before sending.
   */
  url: string;
  /**
   * Request headers, sent verbatim:
   * `{ "Content-Type": "application/json" }`. The
   * `X-Authorization` header is added by the client, never
   * by the sink.
   */
  headers: Record<string, string>;
  /**
   * The JSON request body, serialized:
   * `{"group_id":"webhook-relay","recipients":{"custom_ids":["user-1"]},"message":{"title":"<title>","body":"<body>"}}`
   * (`custom_payload` is appended only under the
   * `includePayload` opt-in; `title` is omitted when the
   * event carries no subject).
   */
  body: string;
}

/**
 * The result of one POST, as reported by the injected
 * client. The HTTP status decides acceptance: 201 means
 * Batch received the send. The success body carries a
 * transactional response token, the receipt the operator
 * uses in the dashboard to check the effective sending
 * time — the client surfaces it when present, and
 * `send()` returns the collected tokens. A 201 without a
 * token is still an acceptance.
 */
export interface BatchMessagePostResponse {
  /** The HTTP status of the POST (e.g. 201, 400, 401, 429, 503). */
  status: number;
  /** The transactional response token from the success body, when the client surfaced one. */
  token?: string;
}

/**
 * The injected Batch message client. Any client adapter
 * implements this one method; it returns the POST's status
 * and the transactional token when present — a throw is a
 * codeless transport failure, retryable. The client is
 * expected to POST one message per call, replacing the
 * `{apiKey}` placeholder in the request URL with the app
 * API key it alone holds, sending `body` verbatim as the
 * request body (JSON), sending `headers` verbatim as the
 * request headers, and authenticating with an
 * `X-Authorization: <REST API key>` header carrying the
 * company REST API key — which the sink never sees.
 */
export interface BatchMessageClient {
  post(request: BatchMessagePostRequest): Promise<BatchMessagePostResponse>;
}

/**
 * Configuration for one Batch sink. The client is
 * injected: without one, `send()` throws
 * `BatchSinkConfigError` (dry runs excepted — they need
 * no client at all). Both Batch keys are deliberately
 * absent from this config: the client alone holds the app
 * API key (URL path) and the company REST API key
 * (`X-Authorization` header), and neither is ever
 * persisted by the sink.
 */
export interface BatchSinkConfig {
  /**
   * The analysis group for the send: Batch groups the send
   * under this id in the dashboard; it is not a routing or
   * audience decision. Required by the API, so when the
   * config sets none the sink uses `"webhook-relay"`.
   * Must be a non-empty string when set.
   */
  groupId?: string;
  /**
   * The recipients to send to: at least one of `tokens`,
   * `custom_ids`, or `install_ids`, each a non-empty list
   * of non-empty strings when present. Required — the sink
   * never invents a recipient and never defaults to the
   * whole audience. A present-but-empty list fails at
   * construction.
   */
  recipients: BatchRecipients;
  /**
   * The Batch message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `BatchMessageClient` and alone holds both
   * Batch keys. Required for real sends; a missing client
   * is a config error, not a silent no-op.
   */
  client?: BatchMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, tokens: [], dryRun: true }`
   * and performs zero client I/O — no POST call, no stat
   * changes. Messages are still validated (including
   * message derivation), so a dry run catches a
   * malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The client is not required in dry-run mode, mirroring
   * the sibling sinks' dry-run exemption; the rest of the
   * config must still be valid — a dry run against a sink
   * with no recipients would rehearse a request that
   * could never send.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the request body appends
   * `custom_payload` carrying the event body verbatim as
   * a JSON string, truncated to `payloadMaxChars`
   * characters (see below). When `false` or absent, the
   * message carries the summary only — the default, so
   * event bodies (which routinely carry PII) never leak
   * into a notification unless the operator explicitly
   * asks for them.
   */
  includePayload?: boolean;
  /**
   * Truncation limit for an opted-in payload snippet, in
   * characters (default 2000). Only meaningful with
   * `includePayload`; the truncation is unconditional when
   * the opt-in is set, so an opted-in body cannot flood a
   * device. Must be a positive integer when set.
   */
  payloadMaxChars?: number;
}

/** One event to notify about. */
export interface BatchRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Content-derivation source, first priority: the event's
   * subject, when set and non-empty. Also the sole source
   * of `message.title`, when present.
   */
  subject?: string;
  /**
   * Content-derivation source, second priority: the event's key
   * (e.g. aggregate id).
   */
  key?: string;
  /**
   * Content-derivation source, last priority: the trace id.
   */
  traceId?: string;
}

/** One failed message, with its retry lane already mapped. */
export interface BatchFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /**
   * Failure code: `HTTP_<status>` for a non-201 POST, or
   * `TRANSPORT_ERROR` for a codeless failure.
   */
  errorCode: string;
  /** Downstream HTTP status, when the failure was a non-201 POST. */
  statusCode?: number;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: 429 and 5xx
   * (plus codeless transport failures) are retryable;
   * every other non-201 status is a fail-closed message
   * (bad recipients or payload, bad REST API key, unknown
   * app API key).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface BatchSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /**
   * Transactional response tokens in send order — the
   * token of each accepted message that reported one.
   * Empty in dry-run mode. A 201 without a token still
   * counts as accepted but contributes no entry here.
   */
  tokens: string[];
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-290). */
export interface BatchSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Batch send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already received on Batch's server and are *not* in
 * `failedRecords`.
 */
export class BatchSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: BatchFailedRecord[];
  constructor(message: string, failedRecords: BatchFailedRecord[]) {
    super(message);
    this.name = "BatchSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class BatchSinkConfigError extends BatchSinkError {
  constructor(reason: string) {
    super(`batch-sink: ${reason}`, []);
    this.name = "BatchSinkConfigError";
  }
}

/**
 * Validate one recipient list: when present, a non-empty
 * array of non-empty strings. An empty list is a config
 * bug that fails fast at construction instead of sending
 * a request Batch would reject. Throws `RangeError`
 * otherwise.
 */
export function resolveBatchRecipientList(
  list: unknown,
  kind: BatchRecipientKind,
  label: string
): string[] {
  const at = (what: string) => `${label}: ${what}`;
  if (!Array.isArray(list)) {
    throw new RangeError(at(`\`recipients.${kind}\` must be an array of non-empty strings when set`));
  }
  if (list.length === 0) {
    throw new RangeError(at(`\`recipients.${kind}\` must not be empty when set`));
  }
  for (let i = 0; i < list.length; i += 1) {
    if (typeof list[i] !== "string" || list[i] === "") {
      throw new RangeError(at(`\`recipients.${kind}[${i}]\` must be a non-empty string`));
    }
  }
  return [...list] as string[];
}

/**
 * Validate the recipients: an object carrying at least one
 * of `tokens`, `custom_ids`, or `install_ids`, each passing
 * `resolveBatchRecipientList`. The sink never defaults to
 * the whole audience: a config with no recipient kind at
 * all fails here. Throws `RangeError` otherwise. Returns a
 * copy carrying only the kinds the config set.
 */
export function resolveBatchRecipients(recipients: unknown, label: string): BatchRecipients {
  const at = (what: string) => `${label}: ${what}`;
  if (recipients === null || typeof recipients !== "object" || Array.isArray(recipients)) {
    throw new RangeError(at("`recipients` must be an object with at least one of `tokens`, `custom_ids`, `install_ids`"));
  }
  const r = recipients as Record<string, unknown>;
  const resolved: BatchRecipients = {};
  let kinds = 0;
  for (const kind of ["tokens", "custom_ids", "install_ids"] as const) {
    if (r[kind] !== undefined) {
      resolved[kind] = resolveBatchRecipientList(r[kind], kind, label);
      kinds += 1;
    }
  }
  if (kinds === 0) {
    throw new RangeError(
      at("`recipients` must carry at least one of `tokens`, `custom_ids`, `install_ids` — the sink never defaults to the whole audience")
    );
  }
  return resolved;
}

/**
 * Validate the analysis group: unset means the default
 * `"webhook-relay"`; when set it must be a non-empty
 * string. Throws `RangeError` otherwise.
 */
export function resolveBatchGroupId(groupId: unknown, label: string): string {
  if (groupId === undefined) {
    return BATCH_DEFAULT_GROUP_ID;
  }
  if (typeof groupId !== "string" || groupId === "") {
    throw new RangeError(`${label}: \`groupId\` must be a non-empty string when set`);
  }
  return groupId;
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. The
 * recipients are required and enforced here, not at send time:
 * at least one of `tokens`, `custom_ids`, or `install_ids`
 * must be a non-empty list. The group id defaults at send
 * time and is only shape-checked here when set.
 */
export function assertValidBatchSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is BatchSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  if (c.groupId !== undefined) {
    resolveBatchGroupId(c.groupId, label);
  }
  resolveBatchRecipients(c.recipients, label);
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
}

/**
 * Derive one record's content summary: the first
 * non-empty value among `subject`, `key`, and `traceId`,
 * in that order. Falls back to the generic `webhook
 * event` summary when the record carries none — a
 * notification sink must not silently drop sourceless
 * events, and the recipients (not the content) are the
 * delivery contract.
 */
export function resolveBatchSummary(record: BatchRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return BATCH_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a device.
 */
export function truncateBatchPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's message: `body` takes the derived
 * summary (the first non-empty among `subject`, `key`,
 * and `traceId`, falling back to `webhook event`) — the
 * body is required by the API, so it always has a value —
 * and `title` takes the `subject` alone when one exists,
 * omitted otherwise: the docs make `message.title`
 * optional, so a subjectless event notifies with a body
 * and no title rather than a title invented from a key or
 * a trace id. Under the `includePayload` opt-in the
 * `custom_payload` carries the event body verbatim as a
 * JSON string, truncated to `payloadMaxChars` (default
 * 2000); without the opt-in there is no `custom_payload`
 * key at all.
 */
export function resolveBatchMessage(
  record: BatchRecord,
  config: Pick<BatchSinkConfig, "includePayload" | "payloadMaxChars">
): { title?: string; body: string; customPayload?: string } {
  const summary = resolveBatchSummary(record);
  const message: { title?: string; body: string; customPayload?: string } = { body: summary };
  if (record.subject !== undefined && record.subject !== "") {
    message.title = record.subject;
  }
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? BATCH_DEFAULT_PAYLOAD_MAX_CHARS;
    message.customPayload = truncateBatchPayload(record.body, limit);
  }
  return message;
}

/**
 * Build one record's serialized JSON body: the
 * transactional send object with `group_id`, `recipients`,
 * and `message` (`title` only when the event carries a
 * subject), plus `custom_payload` only under the
 * `includePayload` opt-in. Neither Batch key ever appears
 * here — the client alone holds the app API key (URL
 * path) and the REST API key (`X-Authorization` header).
 */
export function buildBatchTransactionalBody(
  groupId: string,
  recipients: BatchRecipients,
  message: { title?: string; body: string; customPayload?: string }
): string {
  const body: Record<string, unknown> = {
    group_id: groupId,
    recipients: { ...recipients },
    message: message.title !== undefined ? { title: message.title, body: message.body } : { body: message.body },
  };
  if (message.customPayload !== undefined) {
    body.custom_payload = message.customPayload;
  }
  return JSON.stringify(body);
}

/**
 * Validate one record's body. Throws `RangeError` on an
 * empty body string — even without the opt-in, the body is
 * the record's payload, and an empty record is a caller
 * bug that must fail closed, never notify as an empty
 * message.
 */
export function resolveBatchRecord(
  record: BatchRecord,
  index: number
): { index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`batch-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { index };
}

/**
 * Map one Batch POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says Batch could not
 * accept the message right now, not that the payload is
 * poison. Every other non-201 status (400, 401, 402, 404,
 * and the rest — including any unexpected 2xx, since the
 * docs promise 201 for this endpoint) is a fail-closed
 * message: bad recipients or payload, bad REST API key,
 * unknown app API key, or another verdict retrying cannot
 * change. Callers only pass non-201 statuses here; a 201
 * is acceptance on its own — the response body's
 * transactional token is a receipt to surface, not a
 * second verdict.
 */
export function classifyBatchRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Batch sink (WR-290). One recipient set receives one
 * notification per message; the caller owns retry /
 * dead-letter policy around `send()` — this class performs
 * one POST attempt per message through the injected client
 * and reports its outcome. Failures throw `BatchSinkError`
 * carrying exactly the failed messages with their retry
 * lanes.
 */
export class BatchSink {
  private readonly cfg: BatchSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: BatchSinkConfig) {
    assertValidBatchSinkConfig(config, "BatchSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): BatchSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send push notifications, in input order. Throws
   * `BatchSinkConfigError` when no client was injected,
   * and `BatchSinkError` when any message fails
   * (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: BatchRecord[]): Promise<BatchSendResult> {
    const resolved = records.map((r, i) => resolveBatchRecord(r, i));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The client
      // is not required here, mirroring the sibling sinks'
      // dry-run exemption; the rest of the config was already
      // validated at construction.
      return { ok: true, sent: 0, tokens: [], dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new BatchSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const groupId = resolveBatchGroupId(this.cfg.groupId, "BatchSink");
    const recipients = resolveBatchRecipients(this.cfg.recipients, "BatchSink");
    const failedRecords: BatchFailedRecord[] = [];
    const tokens: string[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          url: BATCH_TRANSACTIONAL_SEND_URL_TEMPLATE,
          headers: {
            "Content-Type": BATCH_JSON_CONTENT_TYPE,
          },
          body: buildBatchTransactionalBody(
            groupId,
            recipients,
            resolveBatchMessage(records[i], this.cfg)
          ),
        });
        if (response.status === 201) {
          // A 201 is acceptance on its own: the docs'
          // promise is that a 201 carries a transactional
          // response token, and delivery surfaces later
          // through Batch's Transactional Stats API — the
          // token is a correlation handle, not a second
          // verdict, so a 201 without one still counts as
          // accepted.
          sent += 1;
          if (typeof response.token === "string" && response.token !== "") {
            tokens.push(response.token);
          }
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyBatchRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toBatchFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new BatchSinkError(
        `batch-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent, tokens };
  }
}

/**
 * Convert a client throw into a failed message: a codeless
 * transport failure (`TRANSPORT_ERROR`, retryable — the SQS
 * no-status rule).
 */
function toBatchFailedRecord(err: unknown, index: number): BatchFailedRecord {
  const failed: BatchFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
