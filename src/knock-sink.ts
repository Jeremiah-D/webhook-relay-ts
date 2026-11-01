/**
 * Knock workflow trigger delivery sink (WR-292).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's inbox, phone, or push token,
 * reached through a multi-channel workflow. Where the
 * Novu sink (WR-291) triggers a Novu workflow through
 * Novu's Events trigger API with an `Authorization: ApiKey`
 * header and a `name`/`to`/`payload` envelope, this sink
 * triggers a Knock workflow: one event is sent as one
 * POST that Knock accepts for one recipient set, and
 * Knock — not the relay — owns the workflow execution,
 * the channel fan-out, the delivery, and the retention of
 * the notification.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Knock
 * server. The sink owns the relay-side concerns — the
 * workflow key, the recipient selection, the message
 * derivation, the payload-inclusion policy, the per-message
 * failure mapping — and the injected client owns the wire
 * protocol, including the POST call, the authentication,
 * and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://api.knock.app/v1/workflows/<key>/trigger",
 *     headers: { "Content-Type": "application/json",
 *                "Idempotency-Key": "<derived>" },
 *     body: "{\"key\":\"<workflow>\",\"recipients\":[<recipient>],\"data\":{\"title\":\"<title>\",\"body\":\"<body>\"}}" }
 *
 * The client POSTs to that URL, sending `body`
 * verbatim as the request body (JSON) and `headers`
 * verbatim as the request headers, and authenticating
 * with an `Authorization: Bearer <secret key>` header
 * carrying the environment secret key — which it alone
 * holds. Five things about this shape are deliberate, and
 * all follow the sibling sinks or the backlog pins:
 *
 * - The secret key is held by the client alone. The sink
 *   never receives the key, never places it in the
 *   request, and never logs it: the handed request
 *   therefore carries no credential at all, so there is
 *   nothing in it for a log line or a retry queue to leak
 *   — and the key is never persisted by the sink. This
 *   is the Knock form of the Novu rule (whose secret key
 *   the client alone holds as an `Authorization: ApiKey`
 *   header), with Knock's own header scheme:
 *   `Authorization: Bearer <secret key>`, verified
 *   against the current docs (docs.knock.app, re-checked
 *   2026-11-01, including the live OpenAPI document).
 * - The endpoint is the workflow trigger API the backlog
 *   pins: `POST https://api.knock.app/v1/workflows/{key}/trigger`.
 *   The docs describe it as the main way to send
 *   notifications to recipients: Knock runs the given
 *   recipients and `data` through the workflow, and all
 *   workflow runs are executed asynchronously.
 * - The `key` is config-held and required: the workflow
 *   key, the human-readable key of the workflow from the
 *   Knock dashboard. One sink triggers one fixed
 *   workflow; the workflow must already exist before a
 *   trigger can run it — the sink never creates a
 *   workflow, and a missing key is a config error at
 *   construction, not a silent no-op at send time.
 * - The `recipients` are config-held and required: an
 *   array of recipient identifiers — a user-id string, or
 *   an object reference (`{ id, collection? }`, or a full
 *   recipient entity identified inline, which Knock
 *   identifies before triggering for that recipient).
 *   One sink targets one fixed recipient set; the sink
 *   never invents a recipient, and it never defaults to
 *   the whole audience — there is no broadcast form here,
 *   and a send with no recipient anywhere would notify
 *   nobody Knock can name. A recipient that is present
 *   but empty is a config error at construction, not a
 *   silent no-op at send time. The docs cap a trigger at
 *   1,000 recipients.
 * - The `Idempotency-Key` header is derived by the sink,
 *   deterministically per record, so a retry of the same
 *   record replays the same key: once the first request
 *   completes, Knock returns the same response and the
 *   retry counts as one workflow run, never a duplicate.
 *   The key is a SHA-256 over the workflow key, the
 *   serialized recipients, and the record's identity and
 *   body, so distinct records — and the same event sent
 *   to a different workflow or recipient set — always
 *   carry distinct keys, while a content-identical
 *   replay of the same record shares one. The docs cap
 *   keys at 255 characters; the derived key is 78. The
 *   docs support the header only on this endpoint
 *   (`POST /workflows/:key/trigger`); sending it anywhere
 *   else has no effect. Knock only caches successful
 *   (2xx) responses, so a retry after a 4xx or 5xx
 *   re-executes the request rather than replaying the
 *   failure.
 *
 * Acceptance is decided by the HTTP status: a 200 means
 * Knock received the trigger, and the success body
 * carries `workflow_run_id` — the receipt the operator
 * uses in the dashboard (Observability > Logs) to trace
 * the run. The client surfaces the run id when present;
 * `send()` returns the collected run ids in send order,
 * so a caller that only inspects the result still has
 * the receipts. A successful response is only an
 * acceptance receipt, not a delivery result: the workflow
 * runs asynchronously, delivery is handled by Knock and
 * the channel providers, and surfaces later through
 * Knock's dashboard. A 200 without a workflow run id is
 * still an acceptance — the docs promise the id on
 * success, but the status is the verdict and a missing
 * id must not turn an accepted trigger into a failure.
 * Any status other than 200 is a failure, including any
 * other 2xx: the docs promise 200 for this endpoint, so
 * an unexpected 2xx is not an acceptance the sink can
 * trust. Unlike Novu, Knock's trigger response carries
 * no body verdict of its own (`acknowledged`/`status`),
 * so the HTTP status alone decides.
 *
 * Message content — a notification carries a title and a
 * body, both derived from the event's own values: the
 * first non-empty value among `subject`, `key`, and
 * `traceId`, in that order, is the summary. The body takes
 * that summary, so an event with none of the values still
 * notifies, with the generic summary `webhook event`: a
 * notification sink that silently dropped sourceless
 * events would hide exactly the deliveries an operator
 * most needs to see, and the recipients — not the content
 * — are the delivery contract here, so no invented target
 * is at stake. The title takes the `subject` alone, when
 * one exists, and is omitted otherwise: the data is for
 * the workflow's templates, so a subjectless event
 * triggers with a body and no title rather than a title
 * invented from a key or a trace id. Both go into `data`
 * as `title` (when present) and `body` (always).
 *
 * Payload inclusion — by default the notification
 * carries the summary only, never the full payload:
 * event bodies routinely carry PII, secrets, or
 * customer data, and a workflow's channels are a far
 * wider audience than a queue or a stream. Opting into
 * `includePayload` appends the event body as
 * `data.eventBody` — a JSON string carrying the body
 * verbatim, truncated to `payloadMaxChars` characters
 * (default 2000) with a truncation marker — the opt-in
 * is explicit, and the truncation is unconditional, so
 * even an opted-in body cannot flood a workflow. The
 * payload rides in its own field, not inside the
 * notification body: Knock's `data` is a map for the
 * workflow's templates, not text for the screen.
 *
 * Optional trigger fields — `actor` (a recipient
 * identifier naming who or what performed the action)
 * and `cancellation_key` (a unique identifier that
 * enables a later cancellation of this workflow run,
 * for delayed or batch steps) are both config-held and
 * passed through verbatim when set; neither is required,
 * and neither is ever defaulted.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over the HTTP status:
 *
 * - a non-200 POST throws `KnockSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Knock could not
 *   accept the message right now, not that the payload
 *   is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-200 status, including 400, 401,
 *   403, and 404 (bad recipients or payload, bad secret
 *   key, insufficient permissions, unknown workflow):
 *   retrying them burns the retry budget for nothing,
 *   and rerouting them elsewhere would notify people the
 *   operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client throws `KnockSinkConfigError`,
 *   which `classifyFailure` maps to `non_retryable`
 *   (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only, plus
 * `node:crypto` for the idempotency-key hash.
 */

import { createHash } from "node:crypto";

/** Generic summary used when an event carries no value for the message body. */
export const KNOCK_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const KNOCK_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Maximum recipients per trigger, per the Knock docs. */
export const KNOCK_MAX_RECIPIENTS = 1000;

/** Content type the client sends with the JSON body. */
export const KNOCK_JSON_CONTENT_TYPE = "application/json";

/** Knock API base URL; the client owns any regional host. */
export const KNOCK_API_BASE_URL = "https://api.knock.app/v1";

/**
 * Trigger endpoint for one workflow key (the key is
 * URL-encoded into the path). The secret key never
 * appears in the URL.
 */
export function knockTriggerUrl(key: string): string {
  return `${KNOCK_API_BASE_URL}/workflows/${encodeURIComponent(key)}/trigger`;
}

/**
 * One recipient as a user-id string: references a user
 * the operator has previously identified to Knock.
 */
export type KnockUserId = string;

/**
 * One recipient as an object reference: identifies a
 * user or an object in Knock by `id`, optionally scoped
 * to a `collection` (for objects). A full recipient
 * entity may also be passed inline (`id` plus profile
 * fields such as `name` or `email`); Knock identifies
 * the recipient before triggering for them, so the extra
 * fields are passed through verbatim.
 */
export interface KnockRecipientObject {
  /** The recipient's id in Knock (required). */
  id: string;
  /** The collection the recipient object belongs to, for object recipients. */
  collection?: string;
  /** Extra recipient fields (name, email, channel_data, ...), passed through verbatim. */
  [field: string]: unknown;
}

/**
 * One recipient of a trigger: a user-id string, or a
 * recipient object (identified inline on trigger).
 * There is deliberately no broadcast form: the sink
 * never triggers a workflow for every recipient in the
 * environment.
 */
export type KnockRecipient = KnockUserId | KnockRecipientObject;

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (JSON), sends `headers` verbatim
 * as the request headers, and authenticates with an
 * `Authorization: Bearer <secret key>` header carrying
 * the environment secret key — which the sink never sees.
 */
export interface KnockTriggerPostRequest {
  /**
   * Always `https://api.knock.app/v1/workflows/<key>/trigger`
   * — the workflow trigger API. No credential ever appears
   * in the URL.
   */
  url: string;
  /**
   * Request headers, sent verbatim:
   * `{ "Content-Type": "application/json",
   *    "Idempotency-Key": "<derived>" }`. The
   * `Authorization` header is added by the client, never
   * by the sink.
   */
  headers: Record<string, string>;
  /**
   * The JSON request body, serialized:
   * `{"key":"<workflow>","recipients":[<recipient>],"data":{"title":"<title>","body":"<body>"}}`
   * (`eventBody` is appended inside `data` only under
   * the `includePayload` opt-in; `title` is omitted when
   * the event carries no subject; `actor` and
   * `cancellation_key` are appended only when the config
   * sets them).
   */
  body: string;
}

/**
 * The result of one POST, as reported by the injected
 * client. The HTTP status decides acceptance: 200 means
 * Knock received the trigger. The success body carries a
 * workflow run id, the receipt the operator uses in the
 * dashboard to trace the run — the client surfaces it
 * when present, and `send()` returns the collected ids.
 * A 200 without a workflow run id is still an
 * acceptance. When the client surfaces the body's error
 * messages, they ride on the failure record.
 */
export interface KnockTriggerPostResponse {
  /** The HTTP status of the POST (e.g. 200, 400, 401, 403, 404, 429, 503). */
  status: number;
  /** The workflow run id from the success body, when the client surfaced one. */
  workflowRunId?: string;
  /** The error messages from the response body, when the client surfaced them. */
  errors?: string[];
}

/**
 * The injected Knock trigger client. Any client adapter
 * implements this one method; it returns the POST's status
 * and the workflow run id when present — a throw is a
 * codeless transport failure, retryable. The client is
 * expected to POST one trigger per call, sending `body`
 * verbatim as the request body (JSON), sending `headers`
 * verbatim as the request headers, and authenticating
 * with an `Authorization: Bearer <secret key>` header
 * carrying the environment secret key — which the sink
 * never sees.
 */
export interface KnockTriggerClient {
  post(request: KnockTriggerPostRequest): Promise<KnockTriggerPostResponse>;
}

/**
 * Configuration for one Knock sink. The client is
 * injected: without one, `send()` throws
 * `KnockSinkConfigError` (dry runs excepted — they need
 * no client at all). The secret key is deliberately
 * absent from this config: the client alone holds it
 * (`Authorization: Bearer` header), and it is never
 * persisted by the sink.
 */
export interface KnockSinkConfig {
  /**
   * The workflow key: the human-readable key of the
   * workflow from the Knock dashboard. Required — the
   * workflow must already exist before a trigger can run
   * it. Must be a non-empty string.
   */
  key: string;
  /**
   * The recipients to trigger for: an array of 1–1000
   * recipient identifiers (a user-id string, or a
   * recipient object). Required — the sink never invents
   * a recipient and never defaults to the whole audience.
   * A present-but-empty recipient fails at construction.
   */
  recipients: KnockRecipient[];
  /**
   * The trigger actor: a recipient identifier naming who
   * or what performed the action. Optional; passed
   * through verbatim when set.
   */
  actor?: KnockRecipient;
  /**
   * The cancellation key: a unique identifier that
   * enables a later cancellation of this workflow run
   * (for delayed or batch steps). Optional; passed
   * through verbatim when set. Must be a non-empty
   * string when set.
   */
  cancellationKey?: string;
  /**
   * The Knock trigger client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `KnockTriggerClient` and alone holds the
   * environment secret key. Required for real sends; a
   * missing client is a config error, not a silent no-op.
   */
  client?: KnockTriggerClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, workflowRunIds: [], dryRun: true }`
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
   * Payload opt-in: when `true`, the request body's
   * `data` appends `eventBody` carrying the event body
   * verbatim as a JSON string, truncated to
   * `payloadMaxChars` characters (see below). When
   * `false` or absent, the data carries the summary
   * only — the default, so event bodies (which routinely
   * carry PII) never leak into a notification unless the
   * operator explicitly asks for them.
   */
  includePayload?: boolean;
  /**
   * Truncation limit for an opted-in payload snippet, in
   * characters (default 2000). Only meaningful with
   * `includePayload`; the truncation is unconditional when
   * the opt-in is set, so an opted-in body cannot flood a
   * workflow. Must be a positive integer when set.
   */
  payloadMaxChars?: number;
}

/** One event to notify about. */
export interface KnockRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Content-derivation source, first priority: the event's
   * subject, when set and non-empty. Also the sole source
   * of `data.title`, when present.
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
export interface KnockFailedRecord {
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
   * (bad recipients or payload, bad secret key,
   * insufficient permissions, unknown workflow).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface KnockSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /**
   * Workflow run ids in send order — the id of each accepted
   * message that reported one. Empty in dry-run mode. A 200
   * without a workflow run id still counts as accepted but
   * contributes no entry here.
   */
  workflowRunIds: string[];
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-292). */
export interface KnockSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Knock send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already received on Knock's server and are *not* in
 * `failedRecords`.
 */
export class KnockSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: KnockFailedRecord[];
  constructor(message: string, failedRecords: KnockFailedRecord[]) {
    super(message);
    this.name = "KnockSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class KnockSinkConfigError extends KnockSinkError {
  constructor(reason: string) {
    super(`knock-sink: ${reason}`, []);
    this.name = "KnockSinkConfigError";
  }
}

/**
 * Validate the workflow key: a non-empty string. Throws
 * `RangeError` otherwise.
 */
export function resolveKnockWorkflowKey(key: unknown, label: string): string {
  if (typeof key !== "string" || key === "") {
    throw new RangeError(`${label}: \`key\` must be a non-empty workflow key string`);
  }
  return key;
}

/**
 * Validate one recipient: a non-empty user-id string, or
 * a recipient object with a non-empty `id` (Knock
 * identifies the recipient inline on trigger when new).
 * Extra object fields are passed through verbatim; a
 * `collection` field, when present, must be a non-empty
 * string. There is deliberately no broadcast form — an
 * object without an `id` fails here. Throws `RangeError`
 * otherwise. Returns a copy carrying only the fields the
 * config set.
 */
export function resolveKnockRecipient(recipient: unknown, label: string): KnockRecipient {
  const at = (what: string) => `${label}: ${what}`;
  if (typeof recipient === "string") {
    if (recipient === "") {
      throw new RangeError(at("`recipients` user id must be a non-empty string"));
    }
    return recipient;
  }
  if (recipient === null || typeof recipient !== "object" || Array.isArray(recipient)) {
    throw new RangeError(
      at("`recipients` must be a user-id string or a recipient object `{ id, ... }`")
    );
  }
  const r = recipient as Record<string, unknown>;
  if (typeof r.id !== "string" || r.id === "") {
    throw new RangeError(at("a recipient object must carry a non-empty `id`"));
  }
  if (r.collection !== undefined && (typeof r.collection !== "string" || r.collection === "")) {
    throw new RangeError(at("`recipients[].collection` must be a non-empty string when set"));
  }
  return { ...r } as KnockRecipientObject;
}

/**
 * Validate the recipients: an array of 1–1000 recipients
 * (the docs' per-trigger cap), each passing
 * `resolveKnockRecipient`. The sink never defaults to the
 * whole audience: a config with no recipient at all fails
 * here. Throws `RangeError` otherwise. Returns a new array
 * of validated copies.
 */
export function resolveKnockRecipients(
  recipients: unknown,
  label: string
): KnockRecipient[] {
  const at = (what: string) => `${label}: ${what}`;
  if (!Array.isArray(recipients)) {
    throw new RangeError(at("`recipients` must be an array of recipient identifiers"));
  }
  if (recipients.length === 0) {
    throw new RangeError(at("`recipients` must not be empty — the sink never defaults to the whole audience"));
  }
  if (recipients.length > KNOCK_MAX_RECIPIENTS) {
    throw new RangeError(at(`\`recipients\` must carry at most ${KNOCK_MAX_RECIPIENTS} recipients per trigger`));
  }
  return recipients.map((entry) => resolveKnockRecipient(entry, label));
}

/**
 * Validate the optional cancellation key: when present it
 * must be a non-empty string. Throws `RangeError`
 * otherwise. Returns the value, or `undefined` when absent.
 */
export function resolveKnockCancellationKey(
  value: unknown,
  label: string
): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string" || value === "") {
    throw new RangeError(`${label}: \`cancellationKey\` must be a non-empty string when set`);
  }
  return value;
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. The
 * workflow key and the recipients are required and enforced here,
 * not at send time: `key` must be a non-empty string, and
 * `recipients` must carry at least one valid recipient.
 */
export function assertValidKnockSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is KnockSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  resolveKnockWorkflowKey(c.key, label);
  resolveKnockRecipients(c.recipients, label);
  if (c.actor !== undefined) {
    resolveKnockRecipient(c.actor, label);
  }
  resolveKnockCancellationKey(c.cancellationKey, label);
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
export function resolveKnockSummary(record: KnockRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return KNOCK_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a workflow.
 */
export function truncateKnockPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's data map: `body` takes the derived
 * summary (the first non-empty among `subject`, `key`,
 * and `traceId`, falling back to `webhook event`) — the
 * body is the data the workflow's templates render, so it
 * always has a value — and `title` takes the `subject`
 * alone when one exists, omitted otherwise: a subjectless
 * event triggers with a body and no title rather than a
 * title invented from a key or a trace id. Under the
 * `includePayload` opt-in the `eventBody` carries the
 * event body verbatim as a JSON string, truncated to
 * `payloadMaxChars` (default 2000); without the opt-in
 * there is no `eventBody` key at all.
 */
export function resolveKnockData(
  record: KnockRecord,
  config: Pick<KnockSinkConfig, "includePayload" | "payloadMaxChars">
): { title?: string; body: string; eventBody?: string } {
  const summary = resolveKnockSummary(record);
  const data: { title?: string; body: string; eventBody?: string } = { body: summary };
  if (record.subject !== undefined && record.subject !== "") {
    data.title = record.subject;
  }
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? KNOCK_DEFAULT_PAYLOAD_MAX_CHARS;
    data.eventBody = truncateKnockPayload(record.body, limit);
  }
  return data;
}

/**
 * Build one record's serialized JSON body: the trigger
 * object with `key`, `recipients`, and `data` (`title`
 * only when the event carries a subject), plus `eventBody`
 * inside `data` only under the `includePayload` opt-in,
 * plus `actor` and `cancellation_key` only when the
 * config sets them. The secret key never appears here —
 * the client alone holds it (`Authorization: Bearer`
 * header).
 */
export function buildKnockTriggerBody(
  key: string,
  recipients: KnockRecipient[],
  data: { title?: string; body: string; eventBody?: string },
  actor?: KnockRecipient,
  cancellationKey?: string
): string {
  const body: Record<string, unknown> = { key, recipients, data };
  if (actor !== undefined) {
    body.actor = actor;
  }
  if (cancellationKey !== undefined) {
    body.cancellation_key = cancellationKey;
  }
  return JSON.stringify(body);
}

/**
 * Derive one record's idempotency key: a SHA-256 over the
 * workflow key, the serialized recipients, and the
 * record's identity and body, prefixed `knock-trigger-`.
 * Deterministic per record, so a retry of the same record
 * replays the same key and Knock returns the same response
 * instead of running the workflow twice — while distinct
 * records, and the same event sent to a different workflow
 * or recipient set, always carry distinct keys. A
 * content-identical replay of the same record shares one
 * key by design: that is the replay the key exists to
 * catch. The docs cap keys at 255 characters; the derived
 * key is 78.
 */
export function resolveKnockIdempotencyKey(
  key: string,
  recipients: KnockRecipient[],
  record: KnockRecord
): string {
  const digest = createHash("sha256")
    .update(`${key}\n${JSON.stringify(recipients)}\n${record.traceId ?? ""}\n${record.key ?? ""}\n${record.body}`, "utf8")
    .digest("hex");
  return `knock-trigger-${digest}`;
}

/**
 * Validate one record's body. Throws `RangeError` on an
 * empty body string — even without the opt-in, the body is
 * the record's payload, and an empty record is a caller
 * bug that must fail closed, never trigger as an empty
 * message.
 */
export function resolveKnockRecord(
  record: KnockRecord,
  index: number
): { index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`knock-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { index };
}

/**
 * Map one Knock POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says Knock could not
 * accept the message right now, not that the payload
 * is poison. Every other non-200 status (400, 401, 403,
 * 404, and the rest — including any unexpected 2xx, since
 * the docs promise 200 for this endpoint) is a fail-closed
 * message: bad recipients or payload, bad secret key,
 * insufficient permissions, or an unknown workflow.
 * Callers only pass non-200 statuses here; a 200 is
 * acceptance on its own (see `classifyKnockTriggerResponse`).
 */
export function classifyKnockRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * The verdict on one trigger POST: either an acceptance,
 * or a failure with its error code and retry lane.
 */
export type KnockTriggerVerdict =
  | { accepted: true }
  | { accepted: false; errorCode: string; retryable: boolean; errorMessage?: string };

/**
 * Decide one trigger POST's verdict from the response the
 * client reported. A 200 is acceptance — Knock's trigger
 * response carries no body verdict of its own, so the
 * HTTP status alone decides (a 200 without a workflow run
 * id is still an acceptance; the id is a correlation
 * handle, not a second verdict). Any non-200 status is a
 * failure with an `HTTP_<status>` code and the WR-210 lane.
 */
export function classifyKnockTriggerResponse(
  response: KnockTriggerPostResponse
): KnockTriggerVerdict {
  if (response.status !== 200) {
    const verdict: KnockTriggerVerdict = {
      accepted: false,
      errorCode: `HTTP_${response.status}`,
      retryable: classifyKnockRecordFailure(response.status),
    };
    if (response.errors !== undefined && response.errors.length > 0) {
      verdict.errorMessage = response.errors.join("; ");
    }
    return verdict;
  }
  return { accepted: true };
}

/**
 * Knock sink (WR-292). One recipient set receives one
 * workflow trigger per message; the caller owns retry /
 * dead-letter policy around `send()` — this class performs
 * one POST attempt per message through the injected client
 * and reports its outcome. Failures throw `KnockSinkError`
 * carrying exactly the failed messages with their retry
 * lanes.
 */
export class KnockSink {
  private readonly cfg: KnockSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: KnockSinkConfig) {
    assertValidKnockSinkConfig(config, "KnockSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): KnockSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Trigger the workflow, in input order. Throws
   * `KnockSinkConfigError` when no client was injected,
   * and `KnockSinkError` when any message fails
   * (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: KnockRecord[]): Promise<KnockSendResult> {
    const resolved = records.map((r, i) => resolveKnockRecord(r, i));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The client
      // is not required here, mirroring the sibling sinks'
      // dry-run exemption; the rest of the config was already
      // validated at construction.
      return { ok: true, sent: 0, workflowRunIds: [], dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new KnockSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const key = resolveKnockWorkflowKey(this.cfg.key, "KnockSink");
    const recipients = resolveKnockRecipients(this.cfg.recipients, "KnockSink");
    const actor =
      this.cfg.actor !== undefined
        ? resolveKnockRecipient(this.cfg.actor, "KnockSink")
        : undefined;
    const cancellationKey = resolveKnockCancellationKey(this.cfg.cancellationKey, "KnockSink");
    const failedRecords: KnockFailedRecord[] = [];
    const workflowRunIds: string[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          url: knockTriggerUrl(key),
          headers: {
            "Content-Type": KNOCK_JSON_CONTENT_TYPE,
            "Idempotency-Key": resolveKnockIdempotencyKey(key, recipients, records[i]),
          },
          body: buildKnockTriggerBody(
            key,
            recipients,
            resolveKnockData(records[i], this.cfg),
            actor,
            cancellationKey
          ),
        });
        const verdict = classifyKnockTriggerResponse(response);
        if (verdict.accepted) {
          // A 200 is acceptance on its own: the docs'
          // promise is that a 200 carries a workflow run id,
          // and delivery surfaces later through Knock's
          // dashboard — the id is a correlation handle,
          // not a second verdict, so a 200 without one still
          // counts as accepted.
          sent += 1;
          if (typeof response.workflowRunId === "string" && response.workflowRunId !== "") {
            workflowRunIds.push(response.workflowRunId);
          }
          continue;
        }
        const failed: KnockFailedRecord = {
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
        failedRecords.push(toKnockFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new KnockSinkError(
        `knock-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent, workflowRunIds };
  }
}

/**
 * Convert a client throw into a failed message: a codeless
 * transport failure (`TRANSPORT_ERROR`, retryable — the SQS
 * no-status rule).
 */
function toKnockFailedRecord(err: unknown, index: number): KnockFailedRecord {
  const failed: KnockFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
