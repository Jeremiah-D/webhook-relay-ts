/**
 * Novu workflow trigger delivery sink (WR-291).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's inbox, phone, or push token,
 * reached through a multi-channel workflow. Where the
 * Batch sink (WR-290) delivers push notifications through
 * Batch's Transactional API with an `X-Authorization` REST
 * key and a `group_id`/`recipients`/`message` envelope,
 * and the Customer.io sink (WR-287) delivers transactional
 * push through Customer.io's API, this sink triggers a
 * Novu workflow: one event is sent as one POST that Novu
 * accepts for one recipient set, and Novu — not the relay
 * — owns the workflow execution, the channel fan-out, the
 * delivery, and the retention of the notification.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Novu
 * server. The sink owns the relay-side concerns — the
 * workflow name, the recipient selection, the message
 * derivation, the payload-inclusion policy, the per-message
 * failure mapping — and the injected client owns the wire
 * protocol, including the POST call, the authentication,
 * and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://api.novu.co/v1/events/trigger",
 *     headers: { "Content-Type": "application/json",
 *                "Idempotency-Key": "<derived>" },
 *     body: "{\"name\":\"<workflow>\",\"to\":<recipient>,\"payload\":{\"title\":\"<title>\",\"body\":\"<body>\"}}" }
 *
 * The client POSTs to that URL, sending `body`
 * verbatim as the request body (JSON) and `headers`
 * verbatim as the request headers, and authenticating
 * with an `Authorization: ApiKey <secret key>` header
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
 *   is the Novu form of the Batch rule (whose REST key
 *   the client alone holds as an `X-Authorization`
 *   header), with Novu's own header scheme:
 *   `Authorization: ApiKey <secret key>`, verified
 *   against the current docs (docs.novu.co, re-checked
 *   2026-10-31).
 * - The endpoint is the Events trigger API the backlog
 *   pins: `POST https://api.novu.co/v1/events/trigger`.
 *   The docs describe it as the main (and only) way to
 *   send notifications to subscribers: the trigger
 *   identifier matches the workflow, Novu resolves the
 *   target subscribers, evaluates the workflow logic,
 *   and executes each configured step across the selected
 *   channels.
 * - The `name` is config-held and required: the workflow
 *   trigger identifier, found on the workflow page. One
 *   sink triggers one fixed workflow; the workflow must
 *   already exist and be published before a Production
 *   trigger can run it — the sink never creates a
 *   workflow, and a missing name is a config error at
 *   construction, not a silent no-op at send time.
 * - The `to` recipients are config-held and required:
 *   one of a subscriber-id string, a subscriber object
 *   (`{ subscriberId, ...profile }` — Novu creates the
 *   subscriber on that trigger when they do not exist
 *   yet), a topic (`{ type: "Topic", topicKey }` — Novu
 *   fans the workflow out to every subscriber in the
 *   topic), or an array of those (at most 100 recipients
 *   per the docs). One sink targets one fixed recipient
 *   set; the sink never invents a recipient, and it never
 *   defaults to the whole audience — there is no
 *   broadcast form here, and a send with no recipient
 *   anywhere would notify nobody Novu can name. A
 *   recipient that is present but empty is a config error
 *   at construction, not a silent no-op at send time.
 * - The `Idempotency-Key` header is derived by the sink,
 *   deterministically per record, so a retry of the same
 *   record replays the same key: once the first request
 *   completes, Novu returns the cached response and the
 *   retry counts as one workflow run, never a duplicate.
 *   The key is a SHA-256 over the workflow name, the
 *   serialized recipients, and the record's identity and
 *   body, so distinct records — and the same event sent
 *   to a different workflow or recipient set — always
 *   carry distinct keys, while a content-identical
 *   replay of the same record shares one. The docs cap
 *   keys at 255 characters; the derived key is 77.
 *   While the first request is still in progress, a
 *   duplicate key returns 409 Conflict and is not queued
 *   — that 409 is a fail-closed, non-retryable verdict
 *   for the duplicate copy (the original run is already
 *   in flight and owns the notification), never a reason
 *   to trigger the workflow a second time.
 *
 * Acceptance is decided by the HTTP status plus, when the
 * client surfaces it, the response body's own verdict: a
 * 201 means Novu received the trigger, and the success
 * body carries `acknowledged` (whether the trigger was
 * acknowledged), `status` (one of `processed`, `error`,
 * `trigger_not_active`, `no_workflow_active_steps_defined`,
 * `no_workflow_steps_defined`, `no_tenant_found`,
 * `invalid_recipients`), and a `transactionId` — the
 * receipt the operator uses in the Activity Feed to trace
 * the run, cancel the event, or look up related messages.
 * The client surfaces the status and the transaction id
 * when present; `send()` returns the collected
 * transaction ids in send order, so a caller that only
 * inspects the result still has the receipts. A
 * successful response is only an acceptance receipt, not
 * a delivery result: delivery is handled by Novu and the
 * channel providers, and surfaces later through Novu's
 * Activity Feed. A 201 without a transaction id is still
 * an acceptance — the docs promise the id on success,
 * but the status is the verdict and a missing id must not
 * turn an accepted trigger into a failure. A 201 whose
 * body says the trigger was not processed
 * (`acknowledged: false`, or a `status` other than
 * `processed` — an unpublished workflow, an unknown
 * recipient, a workflow with no steps) is a failure, not
 * an acceptance: the workflow did not run, and the
 * verdict is a config-side problem the relay cannot fix
 * by retrying. Any status other than 201 is a failure,
 * including any other 2xx: the docs promise 201 for this
 * endpoint, so an unexpected 2xx is not an acceptance the
 * sink can trust.
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
 * one exists, and is omitted otherwise: the payload is
 * data for the workflow's templates, so a subjectless
 * event triggers with a body and no title rather than a
 * title invented from a key or a trace id. Both go into
 * `payload` as `title` (when present) and `body` (always).
 *
 * Payload inclusion — by default the notification
 * carries the summary only, never the full payload:
 * event bodies routinely carry PII, secrets, or
 * customer data, and a workflow's channels are a far
 * wider audience than a queue or a stream. Opting into
 * `includePayload` appends the event body as
 * `payload.eventBody` — a JSON string carrying the body
 * verbatim, truncated to `payloadMaxChars` characters
 * (default 2000) with a truncation marker — the opt-in
 * is explicit, and the truncation is unconditional, so
 * even an opted-in body cannot flood a workflow. The
 * payload rides in its own field, not inside the
 * notification body: Novu's `payload` is data for the
 * workflow, not text for the screen.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over the HTTP status and, for 201s, the body's verdict:
 *
 * - a non-201 POST, or a 201 whose body says the trigger
 *   was not processed, throws `NovuSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Novu could not
 *   accept the message right now, not that the payload
 *   is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-201 status, including 400, 401,
 *   404, and 409 (bad recipients or payload, bad secret
 *   key, unknown workflow, an in-progress duplicate
 *   under the same idempotency key): retrying them burns
 *   the retry budget for nothing, and rerouting them
 *   elsewhere would notify people the operator never
 *   chose;
 * - a 201 whose body verdict is not `processed` is
 *   non-retryable with a `NOVU_<status>` code (an
 *   unpublished workflow, an invalid recipient, a
 *   workflow with no steps — all config-side problems);
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client throws `NovuSinkConfigError`,
 *   which `classifyFailure` maps to `non_retryable`
 *   (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only, plus
 * `node:crypto` for the idempotency-key hash.
 */

import { createHash } from "node:crypto";

/** Generic summary used when an event carries no value for the message body. */
export const NOVU_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const NOVU_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Maximum recipients per trigger, per the Novu docs. */
export const NOVU_MAX_RECIPIENTS = 100;

/** Content type the client sends with the JSON body. */
export const NOVU_JSON_CONTENT_TYPE = "application/json";

/** Events trigger endpoint (US base URL; the client owns any regional host). */
export const NOVU_TRIGGER_URL = "https://api.novu.co/v1/events/trigger";

/** Trigger statuses the docs report as a processed workflow run. */
export const NOVU_PROCESSED_STATUS = "processed";

/**
 * One recipient as a subscriber-id string: references an
 * existing subscriber in the environment.
 */
export type NovuSubscriberId = string;

/**
 * One recipient as a subscriber object: Novu creates the
 * subscriber on this trigger when they do not exist yet,
 * storing the profile fields the workflow needs (such as
 * `email`). Only `subscriberId` is required; the rest
 * are passed through verbatim.
 */
export interface NovuSubscriberObject {
  /** The subscriber's id in the environment (required). */
  subscriberId: string;
  /** Subscriber's first name, when the workflow needs it. */
  firstName?: string;
  /** Subscriber's last name, when the workflow needs it. */
  lastName?: string;
  /** Subscriber's email address, when the workflow needs it. */
  email?: string;
  /** Subscriber's phone number, when the workflow needs it. */
  phone?: string;
  /** Subscriber's avatar URL, when the workflow needs it. */
  avatar?: string;
  /** Subscriber's locale, when the workflow needs it. */
  locale?: string;
  /** Extra subscriber data, passed through verbatim. */
  data?: Record<string, unknown>;
}

/**
 * One recipient as a topic: Novu fans the workflow out
 * to every subscriber in the topic, one run each. The
 * `topicKey` is the topic's permanent, internal reference.
 */
export interface NovuTopicRecipient {
  /** Always `"Topic"` for a topic recipient. */
  type: "Topic";
  /** The topic's key (required, non-empty). */
  topicKey: string;
}

/**
 * One recipient of a trigger: a subscriber-id string, a
 * subscriber object (created on trigger when new), or a
 * topic (fan-out). There is deliberately no broadcast
 * form: the sink never triggers a workflow for every
 * subscriber in the environment.
 */
export type NovuRecipient = NovuSubscriberId | NovuSubscriberObject | NovuTopicRecipient;

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (JSON), sends `headers` verbatim as
 * the request headers, and authenticates with an
 * `Authorization: ApiKey <secret key>` header carrying
 * the environment secret key — which the sink never sees.
 */
export interface NovuTriggerPostRequest {
  /**
   * Always `https://api.novu.co/v1/events/trigger` —
   * the Events trigger API. No credential ever appears
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
   * `{"name":"<workflow>","to":<recipient>,"payload":{"title":"<title>","body":"<body>"}}`
   * (`eventBody` is appended inside `payload` only under
   * the `includePayload` opt-in; `title` is omitted when
   * the event carries no subject).
   */
  body: string;
}

/**
 * The result of one POST, as reported by the injected
 * client. The HTTP status decides acceptance: 201 means
 * Novu received the trigger. The success body carries a
 * transaction id, the receipt the operator uses in the
 * Activity Feed to trace the run — the client surfaces
 * it when present, and `send()` returns the collected
 * ids. A 201 without a transaction id is still an
 * acceptance. When the client surfaces the body's own
 * verdict (`acknowledged` and `triggerStatus`), a 201
 * whose body says the trigger was not processed is a
 * failure, not an acceptance; when the client does not
 * surface them, the HTTP status alone decides.
 */
export interface NovuTriggerPostResponse {
  /** The HTTP status of the POST (e.g. 201, 400, 401, 409, 429, 503). */
  status: number;
  /** The transaction id from the success body, when the client surfaced one. */
  transactionId?: string;
  /** Whether Novu acknowledged the trigger, when the client surfaced it. */
  acknowledged?: boolean;
  /**
   * The trigger `status` from the success body (`processed`,
   * `error`, `trigger_not_active`, `invalid_recipients`,
   * ...), when the client surfaced it.
   */
  triggerStatus?: string;
  /** The error messages from the response body, when the client surfaced them. */
  errors?: string[];
}

/**
 * The injected Novu trigger client. Any client adapter
 * implements this one method; it returns the POST's status
 * and the transaction id when present — a throw is a
 * codeless transport failure, retryable. The client is
 * expected to POST one trigger per call, sending `body`
 * verbatim as the request body (JSON), sending `headers`
 * verbatim as the request headers, and authenticating
 * with an `Authorization: ApiKey <secret key>` header
 * carrying the environment secret key — which the sink
 * never sees.
 */
export interface NovuTriggerClient {
  post(request: NovuTriggerPostRequest): Promise<NovuTriggerPostResponse>;
}

/**
 * Configuration for one Novu sink. The client is
 * injected: without one, `send()` throws
 * `NovuSinkConfigError` (dry runs excepted — they need
 * no client at all). The secret key is deliberately
 * absent from this config: the client alone holds it
 * (`Authorization: ApiKey` header), and it is never
 * persisted by the sink.
 */
export interface NovuSinkConfig {
  /**
   * The workflow trigger identifier: the `name` Novu
   * matches to the workflow. Required — the workflow
   * must already exist and be published before a
   * Production trigger can run it. Must be a non-empty
   * string.
   */
  name: string;
  /**
   * The recipients to trigger for: a subscriber-id
   * string, a subscriber object, a topic, or an array of
   * those (at most 100, per the docs). Required — the
   * sink never invents a recipient and never defaults to
   * the whole audience. A present-but-empty recipient
   * fails at construction.
   */
  to: NovuRecipient | NovuRecipient[];
  /**
   * The Novu trigger client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `NovuTriggerClient` and alone holds the
   * environment secret key. Required for real sends; a
   * missing client is a config error, not a silent no-op.
   */
  client?: NovuTriggerClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, transactionIds: [], dryRun: true }`
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
   * `payload` appends `eventBody` carrying the event body
   * verbatim as a JSON string, truncated to
   * `payloadMaxChars` characters (see below). When
   * `false` or absent, the payload carries the summary
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
export interface NovuRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Content-derivation source, first priority: the event's
   * subject, when set and non-empty. Also the sole source
   * of `payload.title`, when present.
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
export interface NovuFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /**
   * Failure code: `HTTP_<status>` for a non-201 POST,
   * `NOVU_<status>` for a 201 whose body says the trigger
   * was not processed, `NOVU_NOT_ACKNOWLEDGED` for a 201
   * the body did not acknowledge, or `TRANSPORT_ERROR`
   * for a codeless failure.
   */
  errorCode: string;
  /** Downstream HTTP status, when the failure was a non-201 POST. */
  statusCode?: number;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: 429 and 5xx
   * (plus codeless transport failures) are retryable;
   * every other non-201 status — and every 201 whose
   * body verdict is not `processed` — is a fail-closed
   * message (bad recipients or payload, bad secret key,
   * unknown or unpublished workflow, an in-progress
   * duplicate under the same idempotency key).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface NovuSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /**
   * Transaction ids in send order — the id of each accepted
   * message that reported one. Empty in dry-run mode. A 201
   * without a transaction id still counts as accepted but
   * contributes no entry here.
   */
  transactionIds: string[];
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-291). */
export interface NovuSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Novu send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already received on Novu's server and are *not* in
 * `failedRecords`.
 */
export class NovuSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: NovuFailedRecord[];
  constructor(message: string, failedRecords: NovuFailedRecord[]) {
    super(message);
    this.name = "NovuSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class NovuSinkConfigError extends NovuSinkError {
  constructor(reason: string) {
    super(`novu-sink: ${reason}`, []);
    this.name = "NovuSinkConfigError";
  }
}

/**
 * Validate the workflow trigger identifier: a non-empty
 * string. Throws `RangeError` otherwise.
 */
export function resolveNovuWorkflowName(name: unknown, label: string): string {
  if (typeof name !== "string" || name === "") {
    throw new RangeError(`${label}: \`name\` must be a non-empty workflow trigger identifier string`);
  }
  return name;
}

/**
 * Validate one optional subscriber-profile string field:
 * when present it must be a non-empty string. Throws
 * `RangeError` otherwise. Returns the value, or
 * `undefined` when absent.
 */
function resolveNovuProfileString(
  value: unknown,
  field: string,
  label: string
): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== "string" || value === "") {
    throw new RangeError(`${label}: \`to.${field}\` must be a non-empty string when set`);
  }
  return value;
}

/**
 * Validate one recipient: a non-empty subscriber-id string,
 * a subscriber object with a non-empty `subscriberId`
 * (Novu creates the subscriber on trigger when new), or a
 * topic `{ type: "Topic", topicKey }`. There is deliberately
 * no broadcast form — an object whose `type` is anything
 * other than `"Topic"`, or that carries neither a
 * `subscriberId` nor a topic key, fails here. Throws
 * `RangeError` otherwise. Returns a copy carrying only the
 * fields the config set.
 */
export function resolveNovuRecipient(recipient: unknown, label: string): NovuRecipient {
  const at = (what: string) => `${label}: ${what}`;
  if (typeof recipient === "string") {
    if (recipient === "") {
      throw new RangeError(at("`to` subscriber id must be a non-empty string"));
    }
    return recipient;
  }
  if (recipient === null || typeof recipient !== "object" || Array.isArray(recipient)) {
    throw new RangeError(
      at("`to` must be a subscriber-id string, a subscriber object, a topic `{ type: \"Topic\", topicKey }`, or an array of those")
    );
  }
  const r = recipient as Record<string, unknown>;
  if (r.type !== undefined) {
    if (r.type !== "Topic" || typeof r.topicKey !== "string" || r.topicKey === "") {
      throw new RangeError(
        at("a topic recipient must be `{ type: \"Topic\", topicKey }` with a non-empty `topicKey` — there is no broadcast form")
      );
    }
    return { type: "Topic", topicKey: r.topicKey };
  }
  if (typeof r.subscriberId !== "string" || r.subscriberId === "") {
    throw new RangeError(at("a subscriber-object recipient must carry a non-empty `subscriberId`"));
  }
  const resolved: NovuSubscriberObject = { subscriberId: r.subscriberId };
  for (const field of ["firstName", "lastName", "email", "phone", "avatar", "locale"] as const) {
    const value = resolveNovuProfileString(r[field], field, label);
    if (value !== undefined) {
      resolved[field] = value;
    }
  }
  if (r.data !== undefined) {
    if (r.data === null || typeof r.data !== "object" || Array.isArray(r.data)) {
      throw new RangeError(at("`to.data` must be an object when set"));
    }
    resolved.data = { ...(r.data as Record<string, unknown>) };
  }
  return resolved;
}

/**
 * Validate the recipients: a single recipient or an array
 * of 1–100 recipients (the docs' per-trigger cap), each
 * passing `resolveNovuRecipient`. The sink never defaults
 * to the whole audience: a config with no recipient at
 * all fails here. Throws `RangeError` otherwise. Returns a
 * copy: a single recipient as given, an array as a new
 * array of validated copies.
 */
export function resolveNovuRecipients(
  to: unknown,
  label: string
): NovuRecipient | NovuRecipient[] {
  const at = (what: string) => `${label}: ${what}`;
  if (Array.isArray(to)) {
    if (to.length === 0) {
      throw new RangeError(at("`to` must not be an empty array — the sink never defaults to the whole audience"));
    }
    if (to.length > NOVU_MAX_RECIPIENTS) {
      throw new RangeError(at(`\`to\` must carry at most ${NOVU_MAX_RECIPIENTS} recipients per trigger`));
    }
    return to.map((entry) => resolveNovuRecipient(entry, label));
  }
  return resolveNovuRecipient(to, label);
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. The
 * workflow name and the recipients are required and enforced here,
 * not at send time: `name` must be a non-empty string, and `to`
 * must carry at least one valid recipient.
 */
export function assertValidNovuSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is NovuSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  resolveNovuWorkflowName(c.name, label);
  resolveNovuRecipients(c.to, label);
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
export function resolveNovuSummary(record: NovuRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return NOVU_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a workflow.
 */
export function truncateNovuPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's payload: `body` takes the derived
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
export function resolveNovuPayload(
  record: NovuRecord,
  config: Pick<NovuSinkConfig, "includePayload" | "payloadMaxChars">
): { title?: string; body: string; eventBody?: string } {
  const summary = resolveNovuSummary(record);
  const payload: { title?: string; body: string; eventBody?: string } = { body: summary };
  if (record.subject !== undefined && record.subject !== "") {
    payload.title = record.subject;
  }
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? NOVU_DEFAULT_PAYLOAD_MAX_CHARS;
    payload.eventBody = truncateNovuPayload(record.body, limit);
  }
  return payload;
}

/**
 * Build one record's serialized JSON body: the trigger
 * object with `name`, `to`, and `payload` (`title` only
 * when the event carries a subject), plus `eventBody`
 * inside `payload` only under the `includePayload`
 * opt-in. The secret key never appears here — the client
 * alone holds it (`Authorization: ApiKey` header).
 */
export function buildNovuTriggerBody(
  name: string,
  to: NovuRecipient | NovuRecipient[],
  payload: { title?: string; body: string; eventBody?: string }
): string {
  return JSON.stringify({ name, to, payload });
}

/**
 * Derive one record's idempotency key: a SHA-256 over the
 * workflow name, the serialized recipients, and the
 * record's identity and body, prefixed `novu-trigger-`.
 * Deterministic per record, so a retry of the same record
 * replays the same key and Novu returns the cached
 * response instead of running the workflow twice — while
 * distinct records, and the same event sent to a
 * different workflow or recipient set, always carry
 * distinct keys. A content-identical replay of the same
 * record shares one key by design: that is the replay
 * the key exists to catch. The docs cap keys at 255
 * characters; the derived key is 77.
 */
export function resolveNovuIdempotencyKey(
  name: string,
  to: NovuRecipient | NovuRecipient[],
  record: NovuRecord
): string {
  const digest = createHash("sha256")
    .update(`${name}\n${JSON.stringify(to)}\n${record.traceId ?? ""}\n${record.key ?? ""}\n${record.body}`, "utf8")
    .digest("hex");
  return `novu-trigger-${digest}`;
}

/**
 * Validate one record's body. Throws `RangeError` on an
 * empty body string — even without the opt-in, the body is
 * the record's payload, and an empty record is a caller
 * bug that must fail closed, never trigger as an empty
 * message.
 */
export function resolveNovuRecord(
  record: NovuRecord,
  index: number
): { index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`novu-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { index };
}

/**
 * Map one Novu POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says Novu could not
 * accept the message right now, not that the payload
 * is poison. Every other non-201 status (400, 401, 404,
 * 409, and the rest — including any unexpected 2xx, since
 * the docs promise 201 for this endpoint) is a fail-closed
 * message: bad recipients or payload, bad secret key,
 * unknown workflow, or an in-progress duplicate under
 * the same idempotency key. Callers only pass non-201
 * statuses here; a 201 is acceptance on its own unless
 * the body's verdict says otherwise (see
 * `classifyNovuTriggerResponse`).
 */
export function classifyNovuRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * The verdict on one trigger POST: either an acceptance,
 * or a failure with its error code and retry lane.
 */
export type NovuTriggerVerdict =
  | { accepted: true }
  | { accepted: false; errorCode: string; retryable: boolean; errorMessage?: string };

/**
 * Decide one trigger POST's verdict from the response the
 * client reported. A 201 is acceptance — unless the client
 * surfaced the body's own verdict and it says the trigger
 * was not processed: `acknowledged: false` means Novu did
 * not take the trigger, and a `triggerStatus` other than
 * `processed` means the workflow did not run (an
 * unpublished workflow, an invalid recipient, a workflow
 * with no steps) — both are config-side problems, so both
 * are non-retryable with a `NOVU_*` code. When the client
 * does not surface the body's verdict, the HTTP status
 * alone decides, so a minimal client still works. Any
 * non-201 status is a failure with an `HTTP_<status>` code
 * and the WR-210 lane.
 */
export function classifyNovuTriggerResponse(
  response: NovuTriggerPostResponse
): NovuTriggerVerdict {
  if (response.status !== 201) {
    return {
      accepted: false,
      errorCode: `HTTP_${response.status}`,
      retryable: classifyNovuRecordFailure(response.status),
    };
  }
  if (response.acknowledged === false) {
    return { accepted: false, errorCode: "NOVU_NOT_ACKNOWLEDGED", retryable: false };
  }
  if (response.triggerStatus !== undefined && response.triggerStatus !== NOVU_PROCESSED_STATUS) {
    const verdict: NovuTriggerVerdict = {
      accepted: false,
      errorCode: `NOVU_${response.triggerStatus.toUpperCase()}`,
      retryable: false,
    };
    if (response.errors !== undefined && response.errors.length > 0) {
      verdict.errorMessage = response.errors.join("; ");
    }
    return verdict;
  }
  return { accepted: true };
}

/**
 * Novu sink (WR-291). One recipient set receives one
 * workflow trigger per message; the caller owns retry /
 * dead-letter policy around `send()` — this class performs
 * one POST attempt per message through the injected client
 * and reports its outcome. Failures throw `NovuSinkError`
 * carrying exactly the failed messages with their retry
 * lanes.
 */
export class NovuSink {
  private readonly cfg: NovuSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: NovuSinkConfig) {
    assertValidNovuSinkConfig(config, "NovuSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): NovuSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Trigger the workflow, in input order. Throws
   * `NovuSinkConfigError` when no client was injected,
   * and `NovuSinkError` when any message fails
   * (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: NovuRecord[]): Promise<NovuSendResult> {
    const resolved = records.map((r, i) => resolveNovuRecord(r, i));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The client
      // is not required here, mirroring the sibling sinks'
      // dry-run exemption; the rest of the config was already
      // validated at construction.
      return { ok: true, sent: 0, transactionIds: [], dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new NovuSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const name = resolveNovuWorkflowName(this.cfg.name, "NovuSink");
    const to = resolveNovuRecipients(this.cfg.to, "NovuSink");
    const failedRecords: NovuFailedRecord[] = [];
    const transactionIds: string[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          url: NOVU_TRIGGER_URL,
          headers: {
            "Content-Type": NOVU_JSON_CONTENT_TYPE,
            "Idempotency-Key": resolveNovuIdempotencyKey(name, to, records[i]),
          },
          body: buildNovuTriggerBody(
            name,
            to,
            resolveNovuPayload(records[i], this.cfg)
          ),
        });
        const verdict = classifyNovuTriggerResponse(response);
        if (verdict.accepted) {
          // A 201 is acceptance on its own: the docs'
          // promise is that a 201 carries a transaction id,
          // and delivery surfaces later through Novu's
          // Activity Feed — the id is a correlation handle,
          // not a second verdict, so a 201 without one still
          // counts as accepted.
          sent += 1;
          if (typeof response.transactionId === "string" && response.transactionId !== "") {
            transactionIds.push(response.transactionId);
          }
          continue;
        }
        const failed: NovuFailedRecord = {
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
        failedRecords.push(toNovuFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new NovuSinkError(
        `novu-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent, transactionIds };
  }
}

/**
 * Convert a client throw into a failed message: a codeless
 * transport failure (`TRANSPORT_ERROR`, retryable — the SQS
 * no-status rule).
 */
function toNovuFailedRecord(err: unknown, index: number): NovuFailedRecord {
  const failed: NovuFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
