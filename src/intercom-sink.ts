/**
 * Intercom in-app message delivery sink (WR-295).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's inbox — a support conversation
 * with one contact, reached through a customer-messaging
 * API. Where the MagicBell sink (WR-294) triggers a
 * MagicBell workflow through MagicBell's workflow trigger
 * API with a `Bearer` Project JWT and a `key`/`input`
 * envelope carrying no recipients at all, this sink
 * creates an Intercom message directly: one event is sent
 * as one POST that Intercom accepts as one message from
 * an admin to one contact, and Intercom — not the relay —
 * owns the message, the conversation it may grow into,
 * the delivery, and the read state.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need an Intercom
 * server. The sink owns the relay-side concerns — the
 * admin and contact identities, the message derivation, the
 * payload-inclusion policy, the per-message failure
 * mapping — and the injected client owns the wire
 * protocol, including the POST call, the authentication,
 * and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://api.intercom.io/messages",
 *     headers: { "Content-Type": "application/json",
 *                "Intercom-Version": "2.17" },
 *     body: "{\"message_type\":\"in_app\",\"body\":\"<body>\",\"template\":\"plain\",\"from\":{\"type\":\"admin\",\"id\":\"<admin>\"},\"to\":{\"type\":\"user\",\"id\":\"<contact>\"}}" }
 *
 * The client POSTs to that URL, sending `body`
 * verbatim as the request body (JSON), sending `headers`
 * verbatim as the request headers, and authenticating
 * with an `Authorization: Bearer <access token>` header
 * carrying the access token — which it alone holds. Five
 * things about this shape are deliberate, and all follow
 * the sibling sinks or the backlog pins:
 *
 * - The access token is held by the client alone. The sink
 *   never receives the token, never places it in the
 *   request, and never logs it: the handed request
 *   therefore carries no credential at all, so there is
 *   nothing in it for a log line or a retry queue to leak
 *   — and the token is never persisted by the sink. This
 *   is the Intercom form of the MagicBell rule (whose
 *   Project JWT the client alone holds as an
 *   `Authorization: Bearer` header), with Intercom's own
 *   credential source: the access token, generated in the
 *   Intercom Developer Hub, verified against the current
 *   docs (developers.intercom.com, re-checked 2026-11-01,
 *   including the Create a message reference — whose
 *   example confirms the expected authorization header
 *   format, `Bearer <token>`).
 * - The endpoint is the message creation API the backlog
 *   pins: `POST https://api.intercom.io/messages`. The
 *   reference describes it as creating a message that has
 *   been initiated by an admin; the conversation can be an
 *   in-app message, an email, or whatsapp. This sink sends
 *   in-app messages only: `message_type` is fixed to
 *   `"in_app"`, and the email/whatsapp variants are out of
 *   scope for this item.
 * - The pinned `Intercom-Version: 2.17` header rides in
 *   the handed request (unlike the `Authorization` header,
 *   which the client adds): it is a pinned API version,
 *   not a credential, and the sink pins it so the wire
 *   shape does not drift with the workspace's app-package
 *   default. The value was re-checked against the current
 *   reference on 2026-11-01 (the reference's own example
 *   sends `Intercom-Version: 2.17`).
 * - `from` is always `{ type: "admin", id: <admin id> }`
 *   and `to` is always `{ type: "user", id: <contact id> }`,
 *   both config-held and required. The reference says
 *   `from` should be an admin: a request with a user or
 *   lead as `from` is not rejected — it creates a
 *   conversation initiated by that contact, as the Create a
 *   conversation endpoint does, and the `to`, `cc`, and
 *   `bcc` fields are ignored. The sink therefore validates
 *   at construction that an admin id was configured and
 *   hardcodes `type: "admin"`, so a misconfigured sender
 *   can never silently turn an admin message into a
 *   contact-initiated conversation that drops its
 *   recipient. There is exactly one recipient: the sink
 *   never invents a contact and never defaults to an
 *   audience — who is messaged is the operator's
 *   decision, not the relay's. The contact must already
 *   exist before the message can be sent: the reference
 *   warns there can be a short delay between when a
 *   contact is created and when it becomes available to
 *   be messaged through the API, and a 404 is returned in
 *   that case. The operator must confirm the contact
 *   exists before wiring the sink; the sink never creates
 *   a contact.
 * - No `Idempotency-Key` header is sent — deliberately.
 *   The official reference entry for `POST /messages`
 *   documents no `Idempotency-Key` header parameter, so
 *   applicability to this endpoint is unverified and the
 *   sink does not send a header it cannot verify the
 *   server honors (re-checked 2026-11-01). The
 *   consequence is honest and worth stating: a retry
 *   after a codeless transport failure (no response was
 *   received, so no message id exists to reconcile
 *   against) may send the message a second time. Callers
 *   that need exactly-once behavior should reconcile
 *   through the returned message id whenever one was
 *   observed, rather than blindly replaying a transport
 *   failure.
 *
 * Acceptance is decided by the HTTP status together with
 * the response body's message acceptance credential: a
 * 200 whose body carries a Message model `id` means
 * Intercom accepted the message, and the id is the
 * receipt the operator uses to find the message (and,
 * once the contact responds, the conversation) later.
 * `send()` returns the collected message ids in send
 * order, so a caller that only inspects the result still
 * has the receipts. A successful response is only an
 * acceptance receipt, not a delivery or read result: the
 * reference returns the created Message model, and there
 * is no conversation present until the contact responds —
 * `conversation_id` may be absent from the response, and
 * its absence says nothing about acceptance. A 200
 * without a message id is a failure
 * (`INTERCOM_NO_MESSAGE_ID`, fail-closed): the reference
 * promises no other receipt, so a 200 with nothing to
 * trace must not turn an untraceable message into an
 * acceptance. Any non-200 status is a failure. The exact
 * HTTP success status is pinned to 200 here, unlike the
 * MagicBell sink: the fetched reference documents the
 * response as "Response 200 fields", so a 201 is not a
 * documented success for this endpoint and is treated as
 * a failure (`HTTP_201`, fail-closed). The reference's
 * error shape is an `error.list` body carrying an
 * `errors` array of `{ code, message }`; when the client
 * surfaces those messages, they ride on the failure
 * record.
 *
 * Message content — a message carries a body, derived
 * from the event's own values: the first non-empty value
 * among `subject`, `key`, and `traceId`, in that order,
 * is the summary. The body takes that summary, so an
 * event with none of the values still notifies, with the
 * generic summary `webhook event`: a message sink that
 * silently dropped sourceless events would hide exactly
 * the deliveries an operator most needs to see. There is
 * no `subject` field on the request: the reference says
 * the subject is only present when `message_type` is
 * email, and this sink sends in-app messages only, so
 * the subject contributes to the body derivation and
 * nothing else. `template` is fixed to `"plain"`.
 *
 * Payload inclusion — by default the message carries the
 * summary only, never the full payload: event bodies
 * routinely carry PII, secrets, or customer data, and a
 * support conversation is a far wider audience than a
 * queue or a stream. Opting into `includePayload` appends
 * the event body to the message body, after a blank line,
 * as a JSON string carrying the body verbatim, truncated
 * to `payloadMaxChars` characters (default 2000) with a
 * truncation marker — the opt-in is explicit, and the
 * truncation is unconditional, so even an opted-in body
 * cannot flood a conversation. The payload rides inside
 * the message body itself, not in a separate field: the
 * reference's message body has no payload field, so
 * appending to `body` is the only honest shape.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over the HTTP status:
 *
 * - a non-200 POST, or a 200 whose body carries no
 *   message id, throws `IntercomSinkError` carrying every
 *   failed message with its retry lane already mapped, so
 *   the caller retries exactly the failed messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Intercom could
 *   not accept the message right now, not that the payload
 *   is poison. The docs pin the limit at 10,000 API calls
 *   per minute per app and 25,000 per minute per
 *   workspace, enforced in 10-second windows (about
 *   1,667 calls per window per app);
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-200 status, including 400, 401,
 *   403, and 404 (bad input or identities, bad access
 *   token, insufficient permissions, unknown contact —
 *   including a contact that was only just created and is
 *   not yet messageable, which the reference says also
 *   surfaces as a 404), and a 200 whose body carries no
 *   message id: retrying them burns the retry budget for
 *   nothing, and rerouting them elsewhere would message
 *   people the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload (see the
 *   idempotency note above for what a retried transport
 *   failure can still do);
 * - a missing client throws `IntercomSinkConfigError`,
 *   which `classifyFailure` maps to `non_retryable`
 *   (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only. (No
 * `node:crypto` import either: with no idempotency key to
 * derive, there is nothing to hash.)
 */

/** Generic summary used when an event carries no value for the message body. */
export const INTERCOM_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const INTERCOM_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Content type the client sends with the JSON body. */
export const INTERCOM_JSON_CONTENT_TYPE = "application/json";

/** Pinned Intercom API version, re-checked against the current reference on 2026-11-01. */
export const INTERCOM_API_VERSION = "2.17";

/** Intercom API base URL. */
export const INTERCOM_API_BASE_URL = "https://api.intercom.io";

/** Message creation endpoint. */
export const INTERCOM_MESSAGES_URL = `${INTERCOM_API_BASE_URL}/messages`;

/** Rate limit the docs pin: API calls per minute, per app. */
export const INTERCOM_RATE_LIMIT_PER_MINUTE_PER_APP = 10000;

/** Rate limit the docs pin: API calls per minute, per workspace. */
export const INTERCOM_RATE_LIMIT_PER_MINUTE_PER_WORKSPACE = 25000;

/** Seconds in one rate-limit enforcement window (the per-minute limit is split evenly). */
export const INTERCOM_RATE_LIMIT_WINDOW_SECONDS = 10;

/** Approximate calls one app may burst per 10-second window (10,000 / 6). */
export const INTERCOM_RATE_LIMIT_PER_WINDOW_PER_APP = 1667;

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (JSON), sends `headers` verbatim
 * as the request headers, and authenticates with an
 * `Authorization: Bearer <access token>` header carrying
 * the access token — which the sink never sees. No
 * `Idempotency-Key` header is sent: the docs do not verify
 * it for this endpoint (see the module header).
 */
export interface IntercomMessagePostRequest {
  /**
   * Always `https://api.intercom.io/messages` — the
   * message creation API. No credential ever appears in
   * the URL, and the admin and contact ids ride in the
   * body, not the path.
   */
  url: string;
  /**
   * Request headers, sent verbatim:
   * `{ "Content-Type": "application/json", "Intercom-Version": "2.17" }`.
   * The `Authorization` header is added by the client, never
   * by the sink, and there is deliberately no
   * `Idempotency-Key` header.
   */
  headers: Record<string, string>;
  /**
   * The JSON request body, serialized:
   * `{"message_type":"in_app","body":"<body>","template":"plain","from":{"type":"admin","id":"<admin>"},"to":{"type":"user","id":"<contact>"}}`
   * (`body` appends the truncated event JSON after a blank
   * line only under the `includePayload` opt-in). There is
   * exactly one recipient — the config-held contact — and
   * no `cc`/`bcc`: the sink never messages an audience it
   * was not configured for. No credential ever enters the
   * body.
   */
  body: string;
}

/**
 * The result of one POST, as reported by the injected
 * client. The HTTP status decides acceptance together
 * with the response body's Message model id: a 200
 * carrying an `id` means Intercom accepted the message,
 * and the id is the receipt for finding the message
 * later. A 200 without an id is a failure, not an
 * acceptance. `conversation_id` may be absent — there is
 * no conversation until the contact responds — so it is
 * informational only and never part of the acceptance
 * verdict. The docs' error shape is an `error.list` body
 * carrying an `errors` array of `{ code, message }`; when
 * the client surfaces those messages, they ride on the
 * failure record.
 */
export interface IntercomMessagePostResponse {
  /** The HTTP status of the POST (e.g. 200, 400, 401, 403, 404, 429, 503). */
  status: number;
  /** The message id from the success body, when the client surfaced one. */
  messageId?: string;
  /** The associated `conversation_id`, when the client surfaced one (absent until the contact responds). */
  conversationId?: string;
  /** The error messages from the response body's `errors` array, when the client surfaced them. */
  errors?: string[];
  /** The body's `message`, when the client surfaced one. */
  message?: string;
}

/**
 * The injected Intercom message client. Any client adapter
 * implements this one method; it returns the POST's status
 * and the message id when present — a throw is a codeless
 * transport failure, retryable. The client is expected to
 * POST one message per call, sending `body` verbatim as
 * the request body (JSON), sending `headers` verbatim as
 * the request headers, and authenticating with an
 * `Authorization: Bearer <access token>` header carrying
 * the access token — which the sink never sees.
 */
export interface IntercomMessageClient {
  post(request: IntercomMessagePostRequest): Promise<IntercomMessagePostResponse>;
}

/**
 * Configuration for one Intercom sink. The client is
 * injected: without one, `send()` throws
 * `IntercomSinkConfigError` (dry runs excepted — they need
 * no client at all). The access token is deliberately
 * absent from this config: the client alone holds it
 * (`Authorization: Bearer` header), and it is never
 * persisted by the sink.
 */
export interface IntercomSinkConfig {
  /**
   * The admin id: the Intercom admin the message is sent
   * from (`from: { type: "admin", id }`). Required — the
   * reference says `from` should be an admin, and a user
   * or lead as `from` would silently rebuild the request
   * as a contact-initiated conversation and ignore `to`,
   * so the sink hardcodes `type: "admin"` and validates
   * only that an id was configured. Must be a non-empty
   * string.
   */
  adminId: string;
  /**
   * The contact id: the Intercom contact the message is
   * sent to (`to: { type: "user", id }`). Required — a
   * single contact, never a default to the whole audience.
   * The contact must already exist (and be messageable)
   * before a message can be sent; the sink never creates
   * a contact. Must be a non-empty string.
   */
  contactId: string;
  /**
   * The Intercom message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `IntercomMessageClient` and alone holds
   * the access token. Required for real sends; a missing
   * client is a config error, not a silent no-op.
   */
  client?: IntercomMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, messageIds: [], dryRun: true }`
   * and performs zero client I/O — no POST call, no stat
   * changes. Messages are still validated (including
   * message derivation), so a dry run catches a
   * malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The client is not required in dry-run mode, mirroring
   * the sibling sinks' dry-run exemption; the rest of the
   * config must still be valid — a dry run against a sink
   * with no admin or contact id would rehearse a request
   * that could never send.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the request body's
   * `body` appends the event body after a blank line,
   * carrying the event body verbatim as a JSON string,
   * truncated to `payloadMaxChars` characters (see
   * below). When `false` or absent, the body carries the
   * summary only — the default, so event bodies (which
   * routinely carry PII) never leak into a support
   * conversation unless the operator explicitly asks for
   * them.
   */
  includePayload?: boolean;
  /**
   * Truncation limit for an opted-in payload snippet, in
   * characters (default 2000). Only meaningful with
   * `includePayload`; the truncation is unconditional when
   * the opt-in is set, so an opted-in body cannot flood a
   * conversation. Must be a positive integer when set.
   */
  payloadMaxChars?: number;
}

/** One event to message about. */
export interface IntercomRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Content-derivation source, first priority: the event's
   * subject, when set and non-empty. There is no `subject`
   * field on the request (the reference says the subject
   * is only present when `message_type` is email), so the
   * subject contributes to the body derivation only.
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
export interface IntercomFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /**
   * Failure code: `HTTP_<status>` for a non-200 POST,
   * `INTERCOM_NO_MESSAGE_ID` for a 200 whose body carries
   * no message id, or `TRANSPORT_ERROR` for a codeless
   * failure.
   */
  errorCode: string;
  /** Downstream HTTP status, when the failure was a non-200 POST. */
  statusCode?: number;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: 429 and 5xx
   * (plus codeless transport failures) are retryable;
   * every other non-200 status, and a 200 whose body
   * carries no message id, is a fail-closed message (bad
   * input or identities, bad access token, insufficient
   * permissions, unknown or not-yet-messageable contact,
   * or a message Intercom received but gave no id for).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface IntercomSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /**
   * Message ids in send order — the id of each accepted
   * message that reported one. Empty in dry-run mode. A
   * 200 without a message id is a failure, so every
   * accepted message contributes exactly one entry here.
   */
  messageIds: string[];
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-295). */
export interface IntercomSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Intercom send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already received on Intercom's server and are *not* in
 * `failedRecords`.
 */
export class IntercomSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: IntercomFailedRecord[];
  constructor(message: string, failedRecords: IntercomFailedRecord[]) {
    super(message);
    this.name = "IntercomSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class IntercomSinkConfigError extends IntercomSinkError {
  constructor(reason: string) {
    super(`intercom-sink: ${reason}`, []);
    this.name = "IntercomSinkConfigError";
  }
}

/**
 * Validate one configured identity: a non-empty string.
 * Throws `RangeError` otherwise.
 */
export function resolveIntercomIdentity(id: unknown, label: string): string {
  if (typeof id !== "string" || id === "") {
    throw new RangeError(`${label}: must be a non-empty string`);
  }
  return id;
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. The
 * admin id and the contact id are required and enforced here, not
 * at send time: both must be non-empty strings. The `from` type is
 * hardcoded to `"admin"` by the sink itself, so a misconfigured
 * sender can never rebuild the request as a contact-initiated
 * conversation.
 */
export function assertValidIntercomSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is IntercomSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  resolveIntercomIdentity(c.adminId, at("`adminId`"));
  resolveIntercomIdentity(c.contactId, at("`contactId`"));
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
 * message sink must not silently drop sourceless
 * events.
 */
export function resolveIntercomSummary(record: IntercomRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return INTERCOM_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a conversation.
 */
export function truncateIntercomPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's message body: the derived summary
 * (the first non-empty among `subject`, `key`, and
 * `traceId`, falling back to `webhook event`). Under the
 * `includePayload` opt-in the event body is appended
 * after a blank line, truncated to `payloadMaxChars`
 * (default 2000); without the opt-in the body is the
 * summary alone. The payload rides inside the message
 * body itself: the reference's message body has no
 * separate payload field, so appending to `body` is the
 * only honest shape.
 */
export function resolveIntercomBody(
  record: IntercomRecord,
  config: Pick<IntercomSinkConfig, "includePayload" | "payloadMaxChars">
): string {
  const summary = resolveIntercomSummary(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? INTERCOM_DEFAULT_PAYLOAD_MAX_CHARS;
    return `${summary}\n\n${truncateIntercomPayload(record.body, limit)}`;
  }
  return summary;
}

/**
 * Build one record's serialized JSON body: the message
 * object with fixed `message_type: "in_app"` and
 * `template: "plain"`, the derived `body`, and the
 * config-held `from: { type: "admin", id }` and
 * `to: { type: "user", id }`. There is no `subject` field
 * (the reference says the subject is only present when
 * `message_type` is email), no `cc`/`bcc`, and no
 * idempotency key: the docs do not verify
 * `Idempotency-Key` for this endpoint. The access token
 * never appears here — the client alone holds it
 * (`Authorization: Bearer` header).
 */
export function buildIntercomMessageBody(
  adminId: string,
  contactId: string,
  body: string
): string {
  return JSON.stringify({
    message_type: "in_app",
    body,
    template: "plain",
    from: { type: "admin", id: adminId },
    to: { type: "user", id: contactId },
  });
}

/**
 * Validate one record's body. Throws `RangeError` on an
 * empty body string — even without the opt-in, the body is
 * the record's payload, and an empty record is a caller
 * bug that must fail closed, never send as an empty
 * message.
 */
export function resolveIntercomRecord(
  record: IntercomRecord,
  index: number
): { index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`intercom-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { index };
}

/**
 * Map one Intercom POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says Intercom could not
 * accept the message right now, not that the payload
 * is poison (the docs pin 10,000 API calls per minute per
 * app and 25,000 per minute per workspace, enforced in
 * 10-second windows of about 1,667 calls). Every other
 * non-200 status (400, 401, 403, 404, and the rest) is a
 * fail-closed message: bad input or identities, bad access
 * token, insufficient permissions, or an unknown or
 * not-yet-messageable contact (a 404 the reference says a
 * just-created contact also surfaces). Callers only pass
 * non-200 statuses here; a 200 is acceptance on its own
 * only together with a message id (see
 * `classifyIntercomMessageResponse`).
 */
export function classifyIntercomRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * The verdict on one message POST: either an acceptance,
 * or a failure with its error code and retry lane.
 */
export type IntercomMessageVerdict =
  | { accepted: true }
  | { accepted: false; errorCode: string; retryable: boolean; errorMessage?: string };

/**
 * Decide one message POST's verdict from the response the
 * client reported. A 200 carrying a Message model `id` is
 * acceptance — the id is the message acceptance
 * credential, and the message (and, once the contact
 * responds, the conversation) is found later through it.
 * A 200 without a message id is a failure
 * (`INTERCOM_NO_MESSAGE_ID`, fail-closed: the reference
 * promises no other receipt, so a 200 with nothing to
 * trace must not become an acceptance). Any non-200
 * status is a failure with an `HTTP_<status>` code and
 * the WR-210 lane. The success status is pinned to 200
 * here, unlike the MagicBell sink: the fetched reference
 * documents the response as "Response 200 fields", so a
 * 201 is not a documented success for this endpoint.
 * `conversation_id` plays no part in the verdict: there
 * is no conversation until the contact responds, so it
 * may be absent on an accepted message. The docs' error
 * shape is an `error.list` body carrying an `errors`
 * array of `{ code, message }`; when the client surfaces
 * those messages (or a `message`), they ride on the
 * failure record.
 */
export function classifyIntercomMessageResponse(
  response: IntercomMessagePostResponse
): IntercomMessageVerdict {
  if (response.status !== 200) {
    const verdict: IntercomMessageVerdict = {
      accepted: false,
      errorCode: `HTTP_${response.status}`,
      retryable: classifyIntercomRecordFailure(response.status),
    };
    const messages = [
      ...(response.errors ?? []).filter((m) => m !== ""),
      ...(response.message !== undefined && response.message !== "" ? [response.message] : []),
    ];
    if (messages.length > 0) {
      verdict.errorMessage = messages.join("; ");
    }
    return verdict;
  }
  if (typeof response.messageId !== "string" || response.messageId === "") {
    return { accepted: false, errorCode: "INTERCOM_NO_MESSAGE_ID", retryable: false };
  }
  return { accepted: true };
}

/**
 * Intercom sink (WR-295). One message is created per
 * record; the caller owns retry / dead-letter policy
 * around `send()` — this class performs one POST attempt
 * per message through the injected client and reports its
 * outcome. Failures throw `IntercomSinkError` carrying
 * exactly the failed messages with their retry lanes.
 */
export class IntercomSink {
  private readonly cfg: IntercomSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: IntercomSinkConfig) {
    assertValidIntercomSinkConfig(config, "IntercomSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): IntercomSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Create the messages, in input order. Throws
   * `IntercomSinkConfigError` when no client was injected,
   * and `IntercomSinkError` when any message fails
   * (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: IntercomRecord[]): Promise<IntercomSendResult> {
    const resolved = records.map((r, i) => resolveIntercomRecord(r, i));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The client
      // is not required here, mirroring the sibling sinks'
      // dry-run exemption; the rest of the config was already
      // validated at construction.
      return { ok: true, sent: 0, messageIds: [], dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new IntercomSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const adminId = resolveIntercomIdentity(this.cfg.adminId, "IntercomSink: `adminId`");
    const contactId = resolveIntercomIdentity(this.cfg.contactId, "IntercomSink: `contactId`");
    const failedRecords: IntercomFailedRecord[] = [];
    const messageIds: string[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          url: INTERCOM_MESSAGES_URL,
          headers: {
            "Content-Type": INTERCOM_JSON_CONTENT_TYPE,
            "Intercom-Version": INTERCOM_API_VERSION,
          },
          body: buildIntercomMessageBody(
            adminId,
            contactId,
            resolveIntercomBody(records[i], this.cfg)
          ),
        });
        const verdict = classifyIntercomMessageResponse(response);
        if (verdict.accepted) {
          // A 200 carrying a Message model id is acceptance
          // on its own: the id is the receipt, and the
          // message is found later through it — the response
          // is an acceptance receipt, not a delivery or read
          // result, and there is no conversation until the
          // contact responds.
          sent += 1;
          if (typeof response.messageId === "string" && response.messageId !== "") {
            messageIds.push(response.messageId);
          }
          continue;
        }
        const failed: IntercomFailedRecord = {
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
        failedRecords.push(toIntercomFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new IntercomSinkError(
        `intercom-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent, messageIds };
  }
}

/**
 * Convert a client throw into a failed message: a codeless
 * transport failure (`TRANSPORT_ERROR`, retryable — the SQS
 * no-status rule).
 */
function toIntercomFailedRecord(err: unknown, index: number): IntercomFailedRecord {
  const failed: IntercomFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
