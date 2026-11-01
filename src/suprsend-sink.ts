/**
 * SuprSend workflow trigger delivery sink (WR-293).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's inbox, phone, or push token,
 * reached through a multi-channel workflow. Where the
 * Novu sink (WR-291) triggers a Novu workflow through
 * Novu's Events trigger API with an `Authorization: ApiKey`
 * header and a `name`/`to`/`payload` envelope, and the
 * Knock sink (WR-292) triggers a Knock workflow through
 * Knock's workflow trigger API with a `Bearer` secret key
 * and a `key`/`recipients`/`data` envelope, this sink
 * triggers a SuprSend workflow: one event is sent as one
 * POST that SuprSend accepts for one recipient set, and
 * SuprSend — not the relay — owns the workflow execution,
 * the channel fan-out, the delivery, and the retention of
 * the notification.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a SuprSend
 * server. The sink owns the relay-side concerns — the
 * workflow slug, the recipient selection, the message
 * derivation, the payload-inclusion policy, the per-message
 * failure mapping — and the injected client owns the wire
 * protocol, including the POST call, the authentication,
 * and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://hub.suprsend.com/trigger/",
 *     headers: { "Content-Type": "application/json" },
 *     body: "{\"workflow\":\"<slug>\",\"recipients\":[<recipient>],\"data\":{\"title\":\"<title>\",\"body\":\"<body>\"},\"idempotency_key\":\"<derived>\"}" }
 *
 * The client POSTs to that URL, sending `body`
 * verbatim as the request body (JSON) and `headers`
 * verbatim as the request headers, and authenticating
 * with an `Authorization: Bearer <API key>` header
 * carrying the workspace API key — which it alone
 * holds. Five things about this shape are deliberate, and
 * all follow the sibling sinks or the backlog pins:
 *
 * - The API key is held by the client alone. The sink
 *   never receives the key, never places it in the
 *   request, and never logs it: the handed request
 *   therefore carries no credential at all, so there is
 *   nothing in it for a log line or a retry queue to leak
 *   — and the key is never persisted by the sink. This
 *   is the SuprSend form of the Knock rule (whose secret
 *   key the client alone holds as an `Authorization:
 *   Bearer` header), with SuprSend's own key source:
 *   the workspace API key from the SuprSend dashboard
 *   (Developers → API Keys), verified against the
 *   current docs (docs.suprsend.com, re-checked
 *   2026-11-01, including the API reference).
 * - The endpoint is the workflow trigger API the backlog
 *   pins: `POST https://hub.suprsend.com/trigger/`.
 *   The docs describe it as the unified API to trigger a
 *   workflow, which does not require user creation
 *   beforehand: SuprSend runs the given recipients and
 *   `data` through the workflow, and all workflow runs
 *   are executed asynchronously. The sibling event API
 *   (`POST https://hub.suprsend.com/event/`) is a
 *   different trigger path and is deliberately not used
 *   here — this sink only triggers workflows directly.
 * - The `workflow` is config-held and required: the
 *   workflow slug from the SuprSend dashboard workflow
 *   settings. One sink triggers one fixed workflow; the
 *   workflow must already exist and be published before
 *   a trigger can run it — the sink never creates a
 *   workflow, and a missing slug is a config error at
 *   construction, not a silent no-op at send time.
 * - The `recipients` are config-held and required: an
 *   array of recipient identifiers — a `distinct_id`
 *   string, or an inline recipient object (`{
 *   distinct_id, $email?, $sms?, ... }`, which SuprSend
 *   identifies inline before triggering for that
 *   recipient, creating the profile in the background).
 *   One sink targets one fixed recipient set; the sink
 *   never invents a recipient, and it never defaults to
 *   the whole audience — there is no broadcast form here,
 *   and a send with no recipient anywhere would notify
 *   nobody SuprSend can name. A recipient that is present
 *   but empty is a config error at construction, not a
 *   silent no-op at send time. The docs cap a trigger at
 *   100 recipients.
 * - The `idempotency_key` is derived by the sink,
 *   deterministically per record, and carried in the
 *   request body (not a header — SuprSend's key is a
 *   body field, unlike Knock's `Idempotency-Key`
 *   header): once SuprSend receives and processes a
 *   request with a key, it skips processing requests
 *   with the same key for the next 24 hours, so a retry
 *   of the same record replays the same key and never
 *   runs the workflow twice. The key is a SHA-256 over
 *   the workflow slug, the serialized recipients, and
 *   the record's identity and body, so distinct records
 *   — and the same event sent to a different workflow or
 *   recipient set — always carry distinct keys, while a
 *   content-identical replay of the same record shares
 *   one. The docs cap keys at 255 characters; the
 *   derived key is 82. The docs trim leading and
 *   trailing spaces from keys; the derived key carries
 *   none.
 *
 * Acceptance is decided by the HTTP status together with
 * the response body's own verdict: a 2xx whose body says
 * `success: true` (the SDK documents the trigger
 * response as `{ success, status: "success"/"fail",
 * status_code, message }`) means SuprSend accepted the
 * trigger, and the success body carries no workflow run
 * id — the receipt is the acceptance itself, and the
 * request's status is followed later in SuprSend Logs.
 * A successful response is only an acceptance receipt,
 * not a delivery result: the workflow runs asynchronously,
 * delivery is handled by SuprSend and the channel
 * providers, and surfaces later through SuprSend's logs.
 * A 2xx whose body does not say `success: true` is a
 * failure (`SUPRSEND_NOT_SUCCESS`): the body verdict is
 * the authority SuprSend itself defines, and a 2xx
 * without it must not turn a rejected trigger into an
 * acceptance — the same body-verdict rule the Novu sink
 * applies to its `acknowledged`/`status` verdict. Any
 * non-2xx status is a failure, including any other 2xx
 * outside the acceptance rule above. The exact HTTP
 * success status (200 vs 201) is deliberately not
 * pinned: the fetched API reference documents the body
 * verdict but shows no response-status section, so the
 * sink trusts the documented body verdict on any 2xx
 * rather than inventing a status number.
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
 * notification body: SuprSend's `data` is a map for the
 * workflow's templates, not text for the screen.
 *
 * Optional trigger fields — `actor` (a recipient
 * identifier naming who or what performed the action),
 * `tenant_id` (a brand/tenant identifier for
 * multi-tenant notifications), and `cancellation_key`
 * (a unique identifier that enables a later cancellation
 * of this workflow run, while it waits in a delay or
 * digest step) are all config-held and passed through
 * verbatim when set; none is required, and none is ever
 * defaulted.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over the HTTP status:
 *
 * - a non-2xx POST, or a 2xx whose body does not say
 *   `success: true`, throws `SuprSendSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says SuprSend could
 *   not accept the message right now, not that the payload
 *   is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (bad recipients or payload, bad API key,
 *   insufficient permissions, unknown workflow), and a
 *   2xx whose body verdict is not success: retrying them
 *   burns the retry budget for nothing, and rerouting
 *   them elsewhere would notify people the operator never
 *   chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client throws `SuprSendSinkConfigError`,
 *   which `classifyFailure` maps to `non_retryable`
 *   (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only, plus
 * `node:crypto` for the idempotency-key hash.
 */

import { createHash } from "node:crypto";

/** Generic summary used when an event carries no value for the message body. */
export const SUPRSEND_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const SUPRSEND_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Maximum recipients per trigger, per the SuprSend docs. */
export const SUPRSEND_MAX_RECIPIENTS = 100;

/** Content type the client sends with the JSON body. */
export const SUPRSEND_JSON_CONTENT_TYPE = "application/json";

/** SuprSend API base URL; the client owns any regional host. */
export const SUPRSEND_API_BASE_URL = "https://hub.suprsend.com";

/** Trigger endpoint for one workflow (the workflow slug rides in the body, not the path). */
export const SUPRSEND_TRIGGER_URL = `${SUPRSEND_API_BASE_URL}/trigger/`;

/**
 * One recipient as a `distinct_id` string: references a
 * user the operator has previously synced to SuprSend.
 */
export type SuprSendUserId = string;

/**
 * One recipient as an inline object: SuprSend identifies
 * the recipient before triggering for them and creates
 * the profile in the background when new. `distinct_id`
 * is required; channel information (`$email`, `$sms`,
 * `$whatsapp`, `$channels`, ...) and any other user
 * properties are passed through verbatim and may be
 * referenced in templates as `$recipient.<property>`.
 */
export interface SuprSendRecipientObject {
  /** The recipient's distinct id in SuprSend (required). */
  distinct_id: string;
  /** Extra recipient fields (name, $email, $channels, ...), passed through verbatim. */
  [field: string]: unknown;
}

/**
 * One recipient of a trigger: a `distinct_id` string, or
 * an inline recipient object. There is deliberately no
 * broadcast form: the sink never triggers a workflow for
 * every recipient in the environment.
 */
export type SuprSendRecipient = SuprSendUserId | SuprSendRecipientObject;

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (JSON), sends `headers` verbatim
 * as the request headers, and authenticates with an
 * `Authorization: Bearer <API key>` header carrying the
 * workspace API key — which the sink never sees.
 */
export interface SuprSendTriggerPostRequest {
  /**
   * Always `https://hub.suprsend.com/trigger/` — the
   * workflow trigger API. No credential ever appears
   * in the URL, and the workflow slug rides in the body,
   * not the path.
   */
  url: string;
  /**
   * Request headers, sent verbatim:
   * `{ "Content-Type": "application/json" }`. The
   * `Authorization` header is added by the client, never
   * by the sink.
   */
  headers: Record<string, string>;
  /**
   * The JSON request body, serialized:
   * `{"workflow":"<slug>","recipients":[<recipient>],"data":{"title":"<title>","body":"<body>"},"idempotency_key":"<derived>"}`
   * (`eventBody` is appended inside `data` only under
   * the `includePayload` opt-in; `title` is omitted when
   * the event carries no subject; `actor`, `tenant_id`,
   * and `cancellation_key` are appended only when the
   * config sets them).
   */
  body: string;
}

/**
 * The result of one POST, as reported by the injected
 * client. The HTTP status decides acceptance together
 * with the response body's own verdict: a 2xx whose body
 * says `success: true` means SuprSend accepted the
 * trigger. The client surfaces the body's verdict fields
 * (`success`, `status`, `message`) when present — they
 * are the authority the SDK documents for this endpoint
 * (`{ success, status: "success"/"fail", status_code,
 * message }`), and a 2xx without `success: true` is a
 * failure, not an acceptance. When the client surfaces
 * the body's message, it rides on the failure record.
 * The documented success body carries no workflow run
 * id, so there is no receipt to collect.
 */
export interface SuprSendTriggerPostResponse {
  /** The HTTP status of the POST (e.g. 200, 201, 400, 401, 403, 404, 429, 503). */
  status: number;
  /** The body's `success` verdict, when the client surfaced one. */
  success?: boolean;
  /** The body's `status` verdict (`"success"` / `"fail"`), when the client surfaced one. */
  bodyStatus?: string;
  /** The body's `message`, when the client surfaced one. */
  message?: string;
}

/**
 * The injected SuprSend trigger client. Any client adapter
 * implements this one method; it returns the POST's status
 * and the response body's verdict fields when present — a
 * throw is a codeless transport failure, retryable. The
 * client is expected to POST one trigger per call, sending
 * `body` verbatim as the request body (JSON), sending
 * `headers` verbatim as the request headers, and
 * authenticating with an `Authorization: Bearer <API key>`
 * header carrying the workspace API key — which the sink
 * never sees.
 */
export interface SuprSendTriggerClient {
  post(request: SuprSendTriggerPostRequest): Promise<SuprSendTriggerPostResponse>;
}

/**
 * Configuration for one SuprSend sink. The client is
 * injected: without one, `send()` throws
 * `SuprSendSinkConfigError` (dry runs excepted — they need
 * no client at all). The API key is deliberately
 * absent from this config: the client alone holds it
 * (`Authorization: Bearer` header), and it is never
 * persisted by the sink.
 */
export interface SuprSendSinkConfig {
  /**
   * The workflow slug: the slug of the workflow from the
   * SuprSend dashboard workflow settings. Required — the
   * workflow must already exist and be published before
   * a trigger can run it. Must be a non-empty string.
   */
  workflow: string;
  /**
   * The recipients to trigger for: an array of 1–100
   * recipient identifiers (a `distinct_id` string, or an
   * inline recipient object). Required — the sink never
   * invents a recipient and never defaults to the whole
   * audience. A present-but-empty recipient fails at
   * construction.
   */
  recipients: SuprSendRecipient[];
  /**
   * The trigger actor: a recipient identifier naming who
   * or what performed the action. Optional; passed
   * through verbatim when set.
   */
  actor?: SuprSendRecipient;
  /**
   * The tenant/brand identifier for multi-tenant
   * notifications. Optional; passed through verbatim
   * when set. Must be a non-empty string when set.
   */
  tenantId?: string;
  /**
   * The cancellation key: a unique identifier that
   * enables a later cancellation of this workflow run
   * (while it waits in a delay or digest step). Optional;
   * passed through verbatim when set. Must be a
   * non-empty string when set.
   */
  cancellationKey?: string;
  /**
   * The SuprSend trigger client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `SuprSendTriggerClient` and alone holds
   * the workspace API key. Required for real sends; a
   * missing client is a config error, not a silent no-op.
   */
  client?: SuprSendTriggerClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }`
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
export interface SuprSendRecord {
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
export interface SuprSendFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /**
   * Failure code: `HTTP_<status>` for a non-2xx POST,
   * `SUPRSEND_NOT_SUCCESS` for a 2xx whose body does not
   * say `success: true`, or `TRANSPORT_ERROR` for a
   * codeless failure.
   */
  errorCode: string;
  /** Downstream HTTP status, when the failure was a non-2xx POST. */
  statusCode?: number;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: 429 and 5xx
   * (plus codeless transport failures) are retryable;
   * every other non-2xx status, and a 2xx whose body
   * verdict is not success, is a fail-closed message
   * (bad recipients or payload, bad API key,
   * insufficient permissions, unknown workflow, or a
   * trigger SuprSend received but refused).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface SuprSendSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-293). */
export interface SuprSendSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for SuprSend send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already received on SuprSend's server and are *not* in
 * `failedRecords`.
 */
export class SuprSendSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: SuprSendFailedRecord[];
  constructor(message: string, failedRecords: SuprSendFailedRecord[]) {
    super(message);
    this.name = "SuprSendSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class SuprSendSinkConfigError extends SuprSendSinkError {
  constructor(reason: string) {
    super(`suprsend-sink: ${reason}`, []);
    this.name = "SuprSendSinkConfigError";
  }
}

/**
 * Validate the workflow slug: a non-empty string. Throws
 * `RangeError` otherwise.
 */
export function resolveSuprSendWorkflow(workflow: unknown, label: string): string {
  if (typeof workflow !== "string" || workflow === "") {
    throw new RangeError(`${label}: \`workflow\` must be a non-empty workflow slug string`);
  }
  return workflow;
}

/**
 * Validate one recipient: a non-empty `distinct_id`
 * string, or an inline recipient object with a non-empty
 * `distinct_id` (SuprSend identifies the recipient inline
 * on trigger when new, creating the profile in the
 * background). Extra object fields — channel information
 * (`$email`, `$sms`, `$channels`, ...) and user
 * properties — are passed through verbatim. There is
 * deliberately no broadcast form — an object without a
 * `distinct_id` fails here. Throws `RangeError`
 * otherwise. Returns a copy carrying only the fields the
 * config set.
 */
export function resolveSuprSendRecipient(recipient: unknown, label: string): SuprSendRecipient {
  const at = (what: string) => `${label}: ${what}`;
  if (typeof recipient === "string") {
    if (recipient === "") {
      throw new RangeError(at("`recipients` distinct id must be a non-empty string"));
    }
    return recipient;
  }
  if (recipient === null || typeof recipient !== "object" || Array.isArray(recipient)) {
    throw new RangeError(
      at("`recipients` must be a distinct-id string or a recipient object `{ distinct_id, ... }`")
    );
  }
  const r = recipient as Record<string, unknown>;
  if (typeof r.distinct_id !== "string" || r.distinct_id === "") {
    throw new RangeError(at("a recipient object must carry a non-empty `distinct_id`"));
  }
  return { ...r } as SuprSendRecipientObject;
}

/**
 * Validate the recipients: an array of 1–100 recipients
 * (the docs' per-trigger cap), each passing
 * `resolveSuprSendRecipient`. The sink never defaults to
 * the whole audience: a config with no recipient at all fails
 * here. Throws `RangeError` otherwise. Returns a new array
 * of validated copies.
 */
export function resolveSuprSendRecipients(
  recipients: unknown,
  label: string
): SuprSendRecipient[] {
  const at = (what: string) => `${label}: ${what}`;
  if (!Array.isArray(recipients)) {
    throw new RangeError(at("`recipients` must be an array of recipient identifiers"));
  }
  if (recipients.length === 0) {
    throw new RangeError(at("`recipients` must not be empty — the sink never defaults to the whole audience"));
  }
  if (recipients.length > SUPRSEND_MAX_RECIPIENTS) {
    throw new RangeError(at(`\`recipients\` must carry at most ${SUPRSEND_MAX_RECIPIENTS} recipients per trigger`));
  }
  return recipients.map((entry) => resolveSuprSendRecipient(entry, label));
}

/**
 * Validate the optional tenant id: when present it must
 * be a non-empty string. Throws `RangeError` otherwise.
 * Returns the value, or `undefined` when absent.
 */
export function resolveSuprSendTenantId(value: unknown, label: string): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string" || value === "") {
    throw new RangeError(`${label}: \`tenantId\` must be a non-empty string when set`);
  }
  return value;
}

/**
 * Validate the optional cancellation key: when present it
 * must be a non-empty string. Throws `RangeError`
 * otherwise. Returns the value, or `undefined` when absent.
 */
export function resolveSuprSendCancellationKey(
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
 * workflow slug and the recipients are required and enforced here,
 * not at send time: `workflow` must be a non-empty string, and
 * `recipients` must carry at least one valid recipient.
 */
export function assertValidSuprSendSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is SuprSendSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  resolveSuprSendWorkflow(c.workflow, label);
  resolveSuprSendRecipients(c.recipients, label);
  if (c.actor !== undefined) {
    resolveSuprSendRecipient(c.actor, label);
  }
  resolveSuprSendTenantId(c.tenantId, label);
  resolveSuprSendCancellationKey(c.cancellationKey, label);
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
export function resolveSuprSendSummary(record: SuprSendRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return SUPRSEND_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a workflow.
 */
export function truncateSuprSendPayload(body: string, limit: number): string {
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
export function resolveSuprSendData(
  record: SuprSendRecord,
  config: Pick<SuprSendSinkConfig, "includePayload" | "payloadMaxChars">
): { title?: string; body: string; eventBody?: string } {
  const summary = resolveSuprSendSummary(record);
  const data: { title?: string; body: string; eventBody?: string } = { body: summary };
  if (record.subject !== undefined && record.subject !== "") {
    data.title = record.subject;
  }
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? SUPRSEND_DEFAULT_PAYLOAD_MAX_CHARS;
    data.eventBody = truncateSuprSendPayload(record.body, limit);
  }
  return data;
}

/**
 * Build one record's serialized JSON body: the trigger
 * object with `workflow`, `recipients`, and `data`
 * (`title` only when the event carries a subject), plus
 * `eventBody` inside `data` only under the
 * `includePayload` opt-in, plus `idempotency_key` (always
 * — derived deterministically per record), plus `actor`,
 * `tenant_id`, and `cancellation_key` only when the
 * config sets them. The API key never appears here —
 * the client alone holds it (`Authorization: Bearer`
 * header).
 */
export function buildSuprSendTriggerBody(
  workflow: string,
  recipients: SuprSendRecipient[],
  data: { title?: string; body: string; eventBody?: string },
  idempotencyKey: string,
  actor?: SuprSendRecipient,
  tenantId?: string,
  cancellationKey?: string
): string {
  const body: Record<string, unknown> = { workflow, recipients, data, idempotency_key: idempotencyKey };
  if (actor !== undefined) {
    body.actor = actor;
  }
  if (tenantId !== undefined) {
    body.tenant_id = tenantId;
  }
  if (cancellationKey !== undefined) {
    body.cancellation_key = cancellationKey;
  }
  return JSON.stringify(body);
}

/**
 * Derive one record's idempotency key: a SHA-256 over the
 * workflow slug, the serialized recipients, and the
 * record's identity and body, prefixed `suprsend-trigger-`.
 * Deterministic per record, so a retry of the same record
 * replays the same key and SuprSend skips reprocessing
 * it for the next 24 hours instead of running the
 * workflow twice — while distinct records, and the same
 * event sent to a different workflow or recipient set,
 * always carry distinct keys. A content-identical replay
 * of the same record shares one key by design: that is
 * the replay the key exists to catch. The docs cap keys
 * at 255 characters and trim leading/trailing spaces;
 * the derived key is 82 characters with no spaces.
 */
export function resolveSuprSendIdempotencyKey(
  workflow: string,
  recipients: SuprSendRecipient[],
  record: SuprSendRecord
): string {
  const digest = createHash("sha256")
    .update(`${workflow}\n${JSON.stringify(recipients)}\n${record.traceId ?? ""}\n${record.key ?? ""}\n${record.body}`, "utf8")
    .digest("hex");
  return `suprsend-trigger-${digest}`;
}

/**
 * Validate one record's body. Throws `RangeError` on an
 * empty body string — even without the opt-in, the body is
 * the record's payload, and an empty record is a caller
 * bug that must fail closed, never trigger as an empty
 * message.
 */
export function resolveSuprSendRecord(
  record: SuprSendRecord,
  index: number
): { index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`suprsend-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { index };
}

/**
 * Map one SuprSend POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says SuprSend could not
 * accept the message right now, not that the payload
 * is poison. Every other non-2xx status (400, 401, 403,
 * 404, and the rest) is a fail-closed message: bad
 * recipients or payload, bad API key, insufficient
 * permissions, or an unknown workflow. Callers only pass
 * non-2xx statuses here; a 2xx is acceptance on its own
 * only together with the body's `success: true` verdict
 * (see `classifySuprSendTriggerResponse`).
 */
export function classifySuprSendRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * The verdict on one trigger POST: either an acceptance,
 * or a failure with its error code and retry lane.
 */
export type SuprSendTriggerVerdict =
  | { accepted: true }
  | { accepted: false; errorCode: string; retryable: boolean; errorMessage?: string };

/**
 * Decide one trigger POST's verdict from the response the
 * client reported. A 2xx whose body says `success: true`
 * is acceptance — the SDK documents the trigger response
 * as `{ success, status, status_code, message }`, so the
 * body's verdict is the authority, and a 2xx without
 * `success: true` is a failure (`SUPRSEND_NOT_SUCCESS`,
 * fail-closed: SuprSend received the request but refused
 * the trigger). Any non-2xx status is a failure with an
 * `HTTP_<status>` code and the WR-210 lane. The exact
 * HTTP success status is deliberately not pinned (see
 * the module header): the fetched API reference documents
 * the body verdict but no response-status section.
 */
export function classifySuprSendTriggerResponse(
  response: SuprSendTriggerPostResponse
): SuprSendTriggerVerdict {
  if (response.status < 200 || response.status >= 300) {
    const verdict: SuprSendTriggerVerdict = {
      accepted: false,
      errorCode: `HTTP_${response.status}`,
      retryable: classifySuprSendRecordFailure(response.status),
    };
    if (response.message !== undefined && response.message !== "") {
      verdict.errorMessage = response.message;
    }
    return verdict;
  }
  if (response.success !== true) {
    const verdict: SuprSendTriggerVerdict = {
      accepted: false,
      errorCode: "SUPRSEND_NOT_SUCCESS",
      retryable: false,
    };
    if (response.message !== undefined && response.message !== "") {
      verdict.errorMessage = response.message;
    }
    return verdict;
  }
  return { accepted: true };
}

/**
 * SuprSend sink (WR-293). One recipient set receives one
 * workflow trigger per message; the caller owns retry /
 * dead-letter policy around `send()` — this class performs
 * one POST attempt per message through the injected client
 * and reports its outcome. Failures throw `SuprSendSinkError`
 * carrying exactly the failed messages with their retry
 * lanes.
 */
export class SuprSendSink {
  private readonly cfg: SuprSendSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: SuprSendSinkConfig) {
    assertValidSuprSendSinkConfig(config, "SuprSendSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): SuprSendSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Trigger the workflow, in input order. Throws
   * `SuprSendSinkConfigError` when no client was injected,
   * and `SuprSendSinkError` when any message fails
   * (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: SuprSendRecord[]): Promise<SuprSendSendResult> {
    const resolved = records.map((r, i) => resolveSuprSendRecord(r, i));
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
      throw new SuprSendSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const workflow = resolveSuprSendWorkflow(this.cfg.workflow, "SuprSendSink");
    const recipients = resolveSuprSendRecipients(this.cfg.recipients, "SuprSendSink");
    const actor =
      this.cfg.actor !== undefined
        ? resolveSuprSendRecipient(this.cfg.actor, "SuprSendSink")
        : undefined;
    const tenantId = resolveSuprSendTenantId(this.cfg.tenantId, "SuprSendSink");
    const cancellationKey = resolveSuprSendCancellationKey(this.cfg.cancellationKey, "SuprSendSink");
    const failedRecords: SuprSendFailedRecord[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          url: SUPRSEND_TRIGGER_URL,
          headers: {
            "Content-Type": SUPRSEND_JSON_CONTENT_TYPE,
          },
          body: buildSuprSendTriggerBody(
            workflow,
            recipients,
            resolveSuprSendData(records[i], this.cfg),
            resolveSuprSendIdempotencyKey(workflow, recipients, records[i]),
            actor,
            tenantId,
            cancellationKey
          ),
        });
        const verdict = classifySuprSendTriggerResponse(response);
        if (verdict.accepted) {
          // A 2xx with `success: true` is acceptance on
          // its own: the documented success body carries
          // no workflow run id, so there is no receipt to
          // collect — the acceptance itself is the receipt,
          // and the request's status is followed later in
          // SuprSend Logs.
          sent += 1;
          continue;
        }
        const failed: SuprSendFailedRecord = {
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
        failedRecords.push(toSuprSendFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new SuprSendSinkError(
        `suprsend-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent };
  }
}

/**
 * Convert a client throw into a failed message: a codeless
 * transport failure (`TRANSPORT_ERROR`, retryable — the SQS
 * no-status rule).
 */
function toSuprSendFailedRecord(err: unknown, index: number): SuprSendFailedRecord {
  const failed: SuprSendFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
