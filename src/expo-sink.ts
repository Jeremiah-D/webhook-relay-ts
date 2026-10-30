/**
 * Expo push notification delivery sink (WR-280).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's device. Where the FCM sink
 * (WR-276) delivers push notifications through Firebase
 * Cloud Messaging's HTTP v1 API with an OAuth Bearer
 * token and a `{message: {token, notification}}` envelope,
 * this sink delivers push notifications through Expo's
 * push API: one event is sent as one POST to Expo's push
 * service, and Expo — not the relay — owns the device
 * routing, the delivery, and the retention of the
 * notification.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need an Expo
 * server. The sink owns the relay-side concerns — message
 * targeting, notification derivation, payload-inclusion
 * policy, per-message failure mapping — and the injected
 * client owns the wire protocol, including the POST call,
 * the authentication, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://exp.host/--/api/v2/push/send",
 *     headers: {},
 *     body: "{\"to\":\"<ExponentPushToken>\",\"title\":\"<subject>\",\"body\":\"<content>\"}" }
 *
 * The client POSTs to that fixed URL, sending `body`
 * verbatim as the request body (a JSON object) and
 * `headers` verbatim as the request headers. Three things
 * about this shape are deliberate, and all follow the
 * sibling sinks:
 *
 * - Expo requires no authentication by default — the
 *   Expo documentation says so outright — so `headers`
 *   is empty unless the project opted into enhanced
 *   push security. Only then does the sink config carry
 *   an `accessToken`, and the sink hands it to the client
 *   as the `Authorization: Bearer <Expo access token>`
 *   header (the Pushbullet sink's WR-245 pattern: the
 *   token rides in the headers, never in the URL and
 *   never in the body). The token never enters the JSON
 *   body and is never logged: the client alone sends it
 *   as the header at wire time. A sink with no
 *   `accessToken` sends no `Authorization` header at
 *   all — an operator whose project never enabled
 *   enhanced push security must not have a header
 *   invented for them.
 * - The host is fixed, not configurable: the endpoint
 *   above is Expo's push API. A configurable URL here
 *   could only misroute a message to a server that is
 *   not Expo. The fixed host is the documented default;
 *   the client adapter owns nothing about the host.
 * - The response carries a push ticket, not just a
 *   status: an HTTP 200 returns `{data: {status}}`,
 *   one ticket per message, and the ticket is the
 *   per-message acceptance result. A ticket with
 *   `status: "ok"` means Expo accepted the message for
 *   delivery; a ticket with `status: "error"` means
 *   Expo refused it, and the `details.error` name says
 *   why. The client surfaces the ticket (parsed from
 *   the response `data` object) on the response, and the
 *   sink reads it — the ticket, not the HTTP status
 *   alone, decides the retry lane of an accepted POST.
 *   `sound` is out of scope for this sink: the envelope
 *   carries `to`, `title`, and `body` only.
 *
 * This sink is orthogonal to the FCM sink (WR-276):
 * FCM posts a project-level endpoint with an OAuth
 * Bearer token the client alone holds and a `{message:
 * {token, notification}}` envelope, while Expo posts a
 * single fixed endpoint with no authentication by
 * default (an opt-in Bearer token only under enhanced
 * push security) and a flat `{to, title, body}` envelope
 * with a ticket model — one token sent straight to the
 * push service versus one device token routed through a
 * project-scoped API. It is likewise distinct from the
 * OneSignal sink (WR-275): OneSignal posts with a Basic
 * header and an `app_id` plus player-id targeting and a
 * `headings`/`contents` envelope, while Expo posts with
 * no authentication by default and a single
 * ExponentPushToken target.
 *
 * The ExponentPushToken is configured, not derived from
 * the event. One sink targets one push token. A missing
 * token is a config error, not a resolution fallback:
 * unlike the broker sinks, there is no per-record target
 * to resolve to, so a sink with no token has nowhere to
 * deliver and fails closed with `ExpoSinkConfigError`
 * at send time (dry runs excepted — they need no token
 * at all, mirroring the sibling sinks' dry-run exemption
 * for the client).
 *
 * Message content — a push notification carries two
 * fields, not one, so the event's values split across
 * them: `title` takes the event's `subject` and is
 * omitted entirely when the event has no subject (the
 * FCM sink's WR-276 shape — a title is a subject line,
 * and neither the key nor the trace id is one), while
 * `body` takes the first non-empty value among
 * `subject`, `key`, and `traceId`, in that order — the
 * subject is what the event is about, the key (e.g.
 * aggregate id) is the next most identifying value, and
 * the trace id names the trace that produced the event.
 * An event with none of the values still notifies, with
 * the generic summary `webhook event` as its body: a
 * notification sink that silently dropped sourceless
 * events would hide exactly the deliveries an operator
 * most needs to see, and the push token — not the
 * content — is the delivery contract here, so no
 * invented target is at stake.
 *
 * Payload inclusion — by default the notification carries
 * the summary only, never the full payload: event bodies
 * routinely carry PII, secrets, or customer data, and a
 * device is a far wider audience than a queue or a
 * stream. Opting into `includePayload` appends the body
 * verbatim after a blank line, truncated to
 * `payloadMaxChars` characters (default 2000) with a
 * truncation marker — the opt-in is explicit, and the
 * truncation is unconditional, so even an opted-in body
 * cannot flood a device. The body is appended as plain
 * text inside the `body` field, not a fenced code block:
 * the field is already plain text, and a fence around an
 * already-JSON body would be noise on a device.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over the HTTP status and, on a 200, over the push
 * ticket:
 *
 * - a non-2xx POST throws `ExpoSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Expo could not
 *   accept the message right now, not that the payload
 *   is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (unknown token, invalid body, bad
 *   access token): retrying them burns the retry budget
 *   for nothing, and rerouting them elsewhere would
 *   notify devices the operator never chose;
 * - on a 200, the ticket decides: `status: "error"`
 *   with `details.error` of `DeviceNotRegistered` is
 *   non-retryable — the token is dead (the device
 *   uninstalled the app or the token expired), so the
 *   message is dead-lettered without retry and the
 *   operator must stop targeting that token; any other
 *   ticket error is retryable (a transient Expo-side
 *   refusal says nothing durable about the token or
 *   the payload); a 200 with no ticket surfaced at all
 *   is retryable too — the ticket is the acceptance
 *   result, and a missing ticket means the sink cannot
 *   claim the message was accepted;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client or push token throws
 *   `ExpoSinkConfigError`, which `classifyFailure`
 *   maps to `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for the body field. */
export const EXPO_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const EXPO_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Fixed Expo push send endpoint for every message. */
export const EXPO_SEND_URL = "https://exp.host/--/api/v2/push/send";

/** Ticket error name for a push token Expo no longer recognizes. */
export const EXPO_DEVICE_NOT_REGISTERED = "DeviceNotRegistered";

/**
 * One push ticket, as returned by Expo inside the
 * response `data` object for a single message: `status`
 * is `"ok"` (accepted for delivery) or `"error"`
 * (refused). On `"ok"` the ticket carries an `id` — an
 * acceptance receipt only, not a delivery result
 * (delivery confirmation lives in Expo's logs). On
 * `"error"` the ticket carries a human-readable
 * `message` and a machine-readable `details.error`
 * name (e.g. `DeviceNotRegistered`).
 */
export interface ExpoPushTicket {
  /** `"ok"` when Expo accepted the message, `"error"` when it refused it. */
  status: string;
  /** Acceptance receipt for an `"ok"` ticket. Not a delivery result. */
  id?: string;
  /** Human-readable refusal reason, on an `"error"` ticket. */
  message?: string;
  /** Machine-readable refusal detail, on an `"error"` ticket. */
  details?: {
    /** The Expo error name, e.g. `DeviceNotRegistered`. */
    error?: string;
  };
}

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (a JSON object with `to`, `title`,
 * and `body`) to the fixed send endpoint, sending
 * `headers` verbatim as the request headers. `headers`
 * is empty by default — Expo requires no authentication
 * — and carries `Authorization: Bearer <Expo access
 * token>` only when the sink config opted into an
 * `accessToken` (the project enabled enhanced push
 * security). The token never enters the JSON body and
 * is never logged: the client alone sends it as the
 * header at wire time.
 */
export interface ExpoMessagePostRequest {
  /** Always the fixed Expo push send endpoint. */
  url: string;
  /**
   * Request headers, sent verbatim: `{}` by default, or
   * `{ Authorization: "Bearer <Expo access token>" }`
   * when the sink config opted into an `accessToken`.
   */
  headers: Record<string, string>;
  /** The JSON message object, serialized: `to`, `title` (when the event has a subject), `body`. */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * The status drives the HTTP retry mapping; on a 2xx the
 * client surfaces the push ticket parsed from the response
 * `data` object, and the ticket — not the status alone —
 * decides whether the message was accepted. A client that
 * reports a 2xx without a ticket leaves the sink unable
 * to claim acceptance, so the message is treated as a
 * retryable ticket failure.
 */
export interface ExpoMessagePostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
  /**
   * The push ticket parsed from the response `data`
   * object, on a 2xx. `status: "ok"` means Expo accepted
   * the message; `status: "error"` means Expo refused
   * it, with the reason in `details.error`.
   */
  ticket?: ExpoPushTicket;
}

/**
 * The injected Expo message client. Any client adapter
 * implements this one method; it returns the POST's status
 * and, on a 2xx, the push ticket (a throw is a codeless
 * transport failure, retryable). The client is expected
 * to POST one message per call, sending `body` verbatim
 * as the request body (the JSON object with `to`,
 * `title`, and `body`), sending `headers` verbatim as
 * the request headers, and setting the
 * `application/json` content type. The client never
 * invents an `Authorization` header: it sends the one
 * the sink handed it, which is present only when the
 * sink config opted into an `accessToken`.
 */
export interface ExpoMessageClient {
  post(request: ExpoMessagePostRequest): Promise<ExpoMessagePostResponse>;
}

/**
 * Configuration for one Expo sink. The client is
 * injected: without one, `send()` throws
 * `ExpoSinkConfigError` (dry runs excepted — they need
 * no client at all). A missing push token is likewise a
 * config error at send time (dry runs excepted): there is
 * no per-record target to fall back to. The access token
 * is opt-in only: Expo requires no authentication by
 * default, and the token is configured here only when
 * the project enabled enhanced push security — the sink
 * then hands it to the client as the `Authorization:
 * Bearer` header, never in the request body.
 */
export interface ExpoSinkConfig {
  /**
   * The target ExponentPushToken (`to`): every message
   * is delivered to this one device. Must be a
   * non-empty string, free of NUL and whitespace, when
   * set; a missing token throws `ExpoSinkConfigError`
   * at send time.
   */
  to?: string;
  /**
   * The Expo access token, opt-in only: set it only when
   * the project enabled enhanced push security. The sink
   * hands it to the client as the `Authorization: Bearer`
   * header at send time — never in the request body, never
   * logged. Must be a non-empty string, free of NUL and
   * whitespace, when set; absent by default, in which case
   * no `Authorization` header is sent at all.
   */
  accessToken?: string;
  /**
   * The Expo message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `ExpoMessageClient`. Required for real sends;
   * a missing client is a config error, not a silent no-op.
   */
  client?: ExpoMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including notification derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The push token, access token, and client are
   * not required in dry-run mode, mirroring the sibling
   * sinks' dry-run exemption.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the body appends
   * the event body verbatim after a blank line, truncated to
   * `payloadMaxChars` characters (see below). When `false`
   * or absent, the message carries the summary only — the
   * default, so event bodies (which routinely carry PII)
   * never leak into a notification unless the operator
   * explicitly asks for them.
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
export interface ExpoRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Title source and body-derivation source, first
   * priority: the event's subject, when set and non-empty.
   * The title takes it directly (omitted when absent);
   * the body falls through to `key`, then `traceId`.
   */
  subject?: string;
  /**
   * Body-derivation source, second priority: the event's key
   * (e.g. aggregate id).
   */
  key?: string;
  /**
   * Body-derivation source, last priority: the trace id.
   */
  traceId?: string;
}

/** One failed message, with its retry lane already mapped. */
export interface ExpoFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /**
   * Failure code: `HTTP_<status>` for a non-2xx POST,
   * `DEVICE_NOT_REGISTERED` for a ticket refusing a dead
   * token, `TICKET_ERROR` for any other ticket refusal,
   * `TICKET_MISSING` for a 2xx with no ticket surfaced,
   * or `TRANSPORT_ERROR` for a codeless failure.
   */
  errorCode: string;
  /** Downstream HTTP status, when the failure was a non-2xx POST. */
  statusCode?: number;
  /** Client error message, when the failure carried one; for a ticket refusal, the ticket's message. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping, extended by the
   * ticket model: 429 and 5xx (plus codeless transport
   * failures, other ticket errors, and missing tickets)
   * are retryable; every other non-2xx status — and a
   * `DeviceNotRegistered` ticket — is a fail-closed
   * message (unknown token, invalid body, bad access
   * token, or a token Expo no longer recognizes).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface ExpoSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-280). */
export interface ExpoSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Expo send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on Expo's server and are *not* in
 * `failedRecords`.
 */
export class ExpoSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: ExpoFailedRecord[];
  constructor(message: string, failedRecords: ExpoFailedRecord[]) {
    super(message);
    this.name = "ExpoSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, or the push token is missing. A
 * config problem, not a downstream verdict, so the retry
 * queue must not burn attempts on it (`classifyFailure`
 * maps it to `non_retryable`).
 */
export class ExpoSinkConfigError extends ExpoSinkError {
  constructor(reason: string) {
    super(`expo-sink: ${reason}`, []);
    this.name = "ExpoSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing push token is *not* a shape error: it is a config error
 * raised at send time (`ExpoSinkConfigError`), so a sink built
 * before its token is known still fails closed at send time
 * rather than crashing at construction. A present `to` or
 * `accessToken` value must be a non-empty string, free of NUL
 * and whitespace.
 */
export function assertValidExpoSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is ExpoSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  const to = c.to;
  if (to !== undefined) {
    if (
      typeof to !== "string" ||
      to === "" ||
      to.includes("\0") ||
      /\s/.test(to)
    ) {
      throw new RangeError(
        at("`to` must be a non-empty string, free of NUL and whitespace when set")
      );
    }
  }
  const accessToken = c.accessToken;
  if (accessToken !== undefined) {
    if (
      typeof accessToken !== "string" ||
      accessToken === "" ||
      accessToken.includes("\0") ||
      /\s/.test(accessToken)
    ) {
      throw new RangeError(
        at("`accessToken` must be a non-empty string, free of NUL and whitespace when set")
      );
    }
  }
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
 * Derive one record's notification body: the first non-empty
 * value among `subject`, `key`, and `traceId`, in that
 * order. Falls back to the generic `webhook event` summary
 * when the record carries none — a notification sink must
 * not silently drop sourceless events, and the push token
 * (not the content) is the delivery contract.
 */
export function resolveExpoBody(record: ExpoRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return EXPO_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a device.
 */
export function truncateExpoPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's notification: `title` from the
 * subject (omitted when absent — neither the key nor the
 * trace id is a title) and `body` from the first
 * non-empty among `subject`, `key`, and `traceId`
 * (falling back to `webhook event`).
 */
export function resolveExpoNotification(
  record: ExpoRecord
): { title?: string; body: string } {
  const body = resolveExpoBody(record);
  if (record.subject !== undefined && record.subject !== "") {
    return { title: record.subject, body };
  }
  return { body };
}

/**
 * Build one record's serialized request body: the JSON
 * object with `to` (the configured ExponentPushToken),
 * `title` when the event has a subject, and `body` — then
 * the event body appended after a blank line only under
 * the `includePayload` opt-in (truncated to
 * `payloadMaxChars`, default 2000). The access token
 * never appears here — the client sends it as the
 * `Authorization: Bearer` header, from the `headers`
 * of the handed request.
 */
export function buildExpoMessageBody(
  to: string,
  notification: { title?: string; body: string },
  config: Pick<ExpoSinkConfig, "includePayload" | "payloadMaxChars">,
  recordBody?: string
): string {
  const message: Record<string, string> = { to };
  if (notification.title !== undefined) {
    message.title = notification.title;
  }
  let body = notification.body;
  if (config.includePayload === true && recordBody !== undefined) {
    const limit = config.payloadMaxChars ?? EXPO_DEFAULT_PAYLOAD_MAX_CHARS;
    body = `${body}\n\n${truncateExpoPayload(recordBody, limit)}`;
  }
  message.body = body;
  return JSON.stringify(message);
}

/**
 * Build the request headers for one POST: empty by
 * default — Expo requires no authentication — and
 * carrying `Authorization: Bearer <Expo access token>`
 * only when the sink config opted into an `accessToken`
 * (the project enabled enhanced push security). The
 * client sends these headers verbatim at wire time.
 */
export function buildExpoRequestHeaders(
  config: Pick<ExpoSinkConfig, "accessToken">
): Record<string, string> {
  if (config.accessToken === undefined) {
    return {};
  }
  return { Authorization: `Bearer ${config.accessToken}` };
}

/**
 * Validate one record's body and resolve its send form: the
 * notification title and body. Throws `RangeError`
 * on an empty body string — even without the opt-in, the
 * body is the record's payload, and an empty record is a
 * caller bug that must fail closed, never notify as an
 * empty message.
 */
export function resolveExpoRecord(
  record: ExpoRecord,
  index: number
): { notification: { title?: string; body: string }; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`expo-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { notification: resolveExpoNotification(record), index };
}

/**
 * Map one Expo POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says Expo could not
 * accept the message right now, not that the payload is
 * poison. Every other non-2xx status (400, 401, 403,
 * 404, and the rest) is a fail-closed message: unknown
 * token, invalid body, bad access token, or another
 * verdict retrying cannot change. Callers only pass
 * non-2xx statuses here; a 2xx status is decided by the
 * ticket, not by this function.
 */
export function classifyExpoRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Map one Expo push ticket onto its failed record, or
 * `null` when the ticket accepted the message
 * (`status: "ok"`). A `DeviceNotRegistered` ticket error
 * is non-retryable — the token is dead, so retrying
 * cannot deliver and the message is dead-lettered
 * without retry. Any other ticket error is retryable: a
 * transient Expo-side refusal says nothing durable about
 * the token or the payload. A missing ticket (a 2xx with
 * nothing surfaced) is retryable too — the ticket is the
 * acceptance result, and without it the sink cannot claim
 * the message was accepted.
 */
export function ticketToExpoFailedRecord(
  ticket: ExpoPushTicket | undefined,
  index: number
): ExpoFailedRecord | null {
  if (ticket === undefined) {
    return {
      index,
      errorCode: "TICKET_MISSING",
      errorMessage: "Expo answered 2xx but surfaced no push ticket",
      retryable: true,
    };
  }
  if (ticket.status === "ok") {
    return null;
  }
  if (ticket.status === "error") {
    const errorName = ticket.details?.error;
    const failed: ExpoFailedRecord = {
      index,
      errorCode:
        errorName === EXPO_DEVICE_NOT_REGISTERED
          ? "DEVICE_NOT_REGISTERED"
          : "TICKET_ERROR",
      retryable: errorName !== EXPO_DEVICE_NOT_REGISTERED,
    };
    if (ticket.message !== undefined && ticket.message !== "") {
      failed.errorMessage = ticket.message;
    } else if (errorName !== undefined && errorName !== "") {
      failed.errorMessage = errorName;
    }
    return failed;
  }
  return {
    index,
    errorCode: "TICKET_ERROR",
    errorMessage: `Expo returned an unknown ticket status: ${ticket.status}`,
    retryable: true,
  };
}

/**
 * Expo sink (WR-280). One instance targets one
 * ExponentPushToken; the caller owns retry / dead-letter
 * policy around `send()` — this class performs one POST
 * attempt per message through the injected client and
 * reports its outcome. Failures throw `ExpoSinkError`
 * carrying exactly the failed messages with their retry
 * lanes.
 */
export class ExpoSink {
  private readonly cfg: ExpoSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: ExpoSinkConfig) {
    assertValidExpoSinkConfig(config, "ExpoSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): ExpoSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send push notifications, in input order. Throws
   * `ExpoSinkConfigError` when no client was injected
   * or the push token is missing, and `ExpoSinkError`
   * when any message fails (carrying exactly the failed
   * messages with their retry lanes; both counted in
   * stats before throwing, so the counters stay honest
   * even for callers that only inspect stats).
   */
  async send(records: ExpoRecord[]): Promise<ExpoSendResult> {
    const resolved = records.map((r, i) => resolveExpoRecord(r, i));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The
      // push token, access token, and client are
      // not required here, mirroring the sibling sinks'
      // dry-run exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new ExpoSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const to = this.cfg.to;
    if (to === undefined) {
      throw new ExpoSinkConfigError("no push token configured (set `to` in the sink config)");
    }
    const headers = buildExpoRequestHeaders(this.cfg);
    const failedRecords: ExpoFailedRecord[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          url: EXPO_SEND_URL,
          headers,
          body: buildExpoMessageBody(to, record.notification, this.cfg, records[i].body),
        });
        if (response.status >= 200 && response.status < 300) {
          const ticketFailure = ticketToExpoFailedRecord(response.ticket, record.index);
          if (ticketFailure === null) {
            sent += 1;
            continue;
          }
          failedRecords.push(ticketFailure);
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyExpoRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toExpoFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new ExpoSinkError(
        `expo-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toExpoFailedRecord(err: unknown, index: number): ExpoFailedRecord {
  const failed: ExpoFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
