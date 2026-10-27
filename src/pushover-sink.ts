/**
 * Pushover notification delivery sink (WR-244).
 *
 * Some downstreams are not queues, streams, or topics at all:
 * they are a human's phone or desktop. Where the Bark sink
 * (WR-243) delivers to a Bark server, this sink delivers to
 * Pushover: one event is posted as one notification to the
 * Pushover messages endpoint, and Pushover — not the relay
 * — owns the subscription, the delivery, and the retention
 * of the notification.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Pushover
 * server. The sink owns the relay-side concerns — message
 * targeting, title/message derivation, payload-inclusion
 * policy, per-message failure mapping — and the injected
 * client owns the wire protocol, including the POST call
 * and the status it returns.
 *
 * Wire shape — one POST per notification, carried to the
 * injected client as:
 *
 *   { url: "https://api.pushover.net/1/messages.json",
 *     body: "{\"token\":\"<app-token>\",\"user\":\"<user-key>\",\"title\":\"<title>\",\"message\":\"<message>\",\"priority\":0}" }
 *
 * The client POSTs `body` verbatim as the request body
 * (a JSON object, not plain text): Pushover's messages
 * endpoint takes a JSON object with `token`, `user`,
 * `title`, `message`, and `priority` fields. The host is
 * fixed, not configurable: Pushover is a single hosted
 * service, so there is no self-hosted deployment to point
 * at — unlike the Bark and Gotify sinks, whose hosts vary,
 * a configurable URL here could only misroute a
 * notification to a server that is not Pushover.
 *
 * Authentication — carried in the body, not the URL:
 * Pushover authenticates by the `token` (application token)
 * and `user` (user key) fields inside the request body.
 * This differs from the Gotify and Bark sinks, whose
 * credentials ride in the URL itself, and from the
 * Pushbullet sink (WR-245), whose token rides in an
 * `Access-Token` request header. The sink takes both
 * values from its config (the email sink's precedent for
 * credential-style config, rather than a URL-embedded
 * credential): the values are placed into the body at send
 * time and are never logged, extracted into a separate
 * field, or carried anywhere else. Nothing about either
 * credential is ever logged by this module.
 *
 * Priority — fixed at 0, the ordinary Pushover priority:
 * the relay does not re-rank an operator's notifications,
 * and a sink that let the caller pick a priority per event
 * could silently escalate routine deliveries into alarms
 * (or demote urgent ones into silence). This mirrors the
 * Gotify sink's fixed priority 5.
 *
 * Message targeting — one sink targets one Pushover user:
 * every message goes to the configured user key. A missing
 * app token or user key is a config error, not a
 * resolution fallback: unlike the broker sinks, there is
 * no per-record target to resolve to, so a sink with no
 * credentials has nowhere to deliver and fails closed
 * with `PushoverSinkConfigError` at send time (dry runs
 * excepted — they need no credentials at all, mirroring
 * the sibling sinks' dry-run exemption for the client).
 *
 * Title and message — derived from the event's own values.
 * The title takes `subject` first, falling back to `key`
 * when the event carries no subject: the subject is what
 * the event is about, the key (e.g. aggregate id) is the
 * next most identifying value. The message takes `key`
 * first, falling back to `traceId`: the message line names
 * the entity and the trace that produced the event. An
 * event with none of the values a field needs still
 * notifies, with the generic summary `webhook event`: a
 * notification sink that silently dropped sourceless events
 * would hide exactly the deliveries an operator most needs
 * to see, and the user key — not the text — is the
 * delivery contract here, so no invented target is at
 * stake.
 *
 * Payload inclusion — by default the message carries the
 * summary only, never the full payload: event bodies
 * routinely carry PII, secrets, or customer data, and a
 * push notification is a far wider audience than a queue
 * or a stream. Opting into `includePayload` appends the
 * body verbatim after a blank line, truncated to
 * `payloadMaxChars` characters (default 2000) with a
 * truncation marker — the opt-in is explicit, and the
 * truncation is unconditional, so even an opted-in body
 * cannot flood a device or blow past Pushover's message
 * limits. The body is appended as plain text inside the
 * `message` field, not a fenced code block: Pushover
 * renders the message as-is, and a fence would be noise
 * on a phone screen.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over HTTP status:
 *
 * - a non-2xx POST throws `PushoverSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Pushover could
 *   not accept the message right now, not that the
 *   payload is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (unknown app token or user key, invalid
 *   body): retrying them burns the retry budget for
 *   nothing, and rerouting them elsewhere would notify a
 *   user the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client or missing credentials throws
 *   `PushoverSinkConfigError`, which `classifyFailure`
 *   maps to `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for a text field. */
export const PUSHOVER_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const PUSHOVER_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Fixed Pushover priority for every notification (0 is ordinary). */
export const PUSHOVER_PRIORITY = 0;

/**
 * The single Pushover messages endpoint. Fixed, not
 * configurable: Pushover is one hosted service, so a
 * configurable URL could only misroute a notification to
 * a server that is not Pushover.
 */
export const PUSHOVER_MESSAGES_URL = "https://api.pushover.net/1/messages.json";

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol (including the status it
 * returns and the request headers); this shape is the
 * relay-side contract it must honour. The URL is always
 * the fixed Pushover messages endpoint, and the body is
 * the JSON object `{"token","user","title","message",
 * "priority":0}` serialized as a string, posted verbatim.
 * The credentials ride inside the body, never in the URL
 * and never as a separate field.
 */
export interface PushoverMessagePostRequest {
  /** Always the fixed Pushover messages endpoint. */
  url: string;
  /** The JSON notification object, serialized: token, user, title, message, priority 0. */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse Pushover's response body.
 */
export interface PushoverMessagePostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
}

/**
 * The injected Pushover message client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one message per call, sending
 * `body` verbatim as the request body (the JSON object with
 * `token`, `user`, `title`, `message`, and `priority`).
 */
export interface PushoverMessageClient {
  post(request: PushoverMessagePostRequest): Promise<PushoverMessagePostResponse>;
}

/**
 * Configuration for one Pushover sink. The client is
 * injected: without one, `send()` throws
 * `PushoverSinkConfigError` (dry runs excepted — they need
 * no client at all). Missing credentials are likewise a
 * config error at send time (dry runs excepted): there is
 * no per-record target to fall back to.
 */
export interface PushoverSinkConfig {
  /**
   * Pushover application token. Placed into the `token`
   * field of the request body at send time, never into
   * the URL and never logged. Must be a non-empty string,
   * free of NUL and whitespace, when set; a missing token
   * throws `PushoverSinkConfigError` at send time, never a
   * silent no-op.
   */
  appToken?: string;
  /**
   * Pushover user key: the recipient of every message
   * from this sink. Placed into the `user` field of the
   * request body at send time, never into the URL and
   * never logged. Must be a non-empty string, free of NUL
   * and whitespace, when set; a missing user key throws
   * `PushoverSinkConfigError` at send time.
   */
  userKey?: string;
  /**
   * The Pushover message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `PushoverMessageClient`. Required for real
   * sends; a missing client is a config error, not a
   * silent no-op.
   */
  client?: PushoverMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including text derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The credentials and client are not required in dry-run
   * mode, mirroring the sibling sinks' dry-run exemption.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the message text appends
   * the event body verbatim after a blank line, truncated
   * to `payloadMaxChars` characters (see below). When
   * `false` or absent, the message carries the summary
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
   * device. Must be a positive integer when set.
   */
  payloadMaxChars?: number;
}

/** One event to notify about. */
export interface PushoverRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Title-derivation source, first priority: the event's
   * subject, when set and non-empty. Falls through to `key`.
   */
  subject?: string;
  /**
   * Title-derivation source, second priority, and
   * message-derivation source, first priority: the event's key
   * (e.g. aggregate id).
   */
  key?: string;
  /**
   * Message-derivation source, last priority: the trace id.
   */
  traceId?: string;
}

/** One failed message, with its retry lane already mapped. */
export interface PushoverFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /** Failure code: `HTTP_<status>` for a non-2xx POST, or `TRANSPORT_ERROR` for a codeless failure. */
  errorCode: string;
  /** Downstream HTTP status, when the failure was a non-2xx POST. */
  statusCode?: number;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: 429 and 5xx (plus
   * codeless transport failures) are retryable, every other
   * non-2xx status is a fail-closed message (unknown app
   * token or user key, invalid body).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface PushoverSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-244). */
export interface PushoverSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Pushover send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on Pushover's server and are *not* in
 * `failedRecords`.
 */
export class PushoverSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: PushoverFailedRecord[];
  constructor(message: string, failedRecords: PushoverFailedRecord[]) {
    super(message);
    this.name = "PushoverSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, or the app token or user key is
 * missing. A config problem, not a downstream verdict, so
 * the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class PushoverSinkConfigError extends PushoverSinkError {
  constructor(reason: string) {
    super(`pushover-sink: ${reason}`, []);
    this.name = "PushoverSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing app token or user key is *not* a shape error: it is
 * a config error raised at send time
 * (`PushoverSinkConfigError`), so a sink built before its
 * credentials are known still fails closed at send time rather
 * than crashing at construction. A present credential must be
 * a non-empty string, free of NUL and whitespace.
 */
export function assertValidPushoverSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is PushoverSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  for (const field of ["appToken", "userKey"] as const) {
    const value = c[field];
    if (value !== undefined) {
      if (
        typeof value !== "string" ||
        value === "" ||
        (value as string).includes("\0") ||
        /\s/.test(value as string)
      ) {
        throw new RangeError(
          at(`\`${field}\` must be a non-empty string, free of NUL and whitespace when set`)
        );
      }
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
 * Derive one record's title: the first non-empty value
 * among `subject` and `key`, in that order. Falls back to
 * the generic `webhook event` summary when the record
 * carries neither — a notification sink must not silently
 * drop sourceless events, and the user key (not the
 * text) is the delivery contract.
 */
export function resolvePushoverTitle(record: PushoverRecord): string {
  for (const value of [record.subject, record.key]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return PUSHOVER_FALLBACK_SUMMARY;
}

/**
 * Derive one record's message summary: the first non-empty
 * value among `key` and `traceId`, in that order. Falls back
 * to the generic `webhook event` summary when the record
 * carries neither.
 */
export function resolvePushoverMessageSummary(record: PushoverRecord): string {
  for (const value of [record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return PUSHOVER_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a device.
 */
export function truncatePushoverPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's notification text: the title and the
 * message summary. Only under the `includePayload` opt-in
 * does the message append the body verbatim after a blank
 * line, truncated to `payloadMaxChars` (default 2000).
 * Without the opt-in, the message is the summary alone:
 * event bodies routinely carry PII and must never leak into
 * a notification by default. The body is appended as plain
 * text inside the `message` field, not a fenced code block:
 * Pushover renders the message as-is, and a fence would be
 * noise on a phone screen.
 */
export function resolvePushoverNotification(
  record: PushoverRecord,
  config: Pick<PushoverSinkConfig, "includePayload" | "payloadMaxChars">
): { title: string; message: string } {
  const title = resolvePushoverTitle(record);
  let message = resolvePushoverMessageSummary(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? PUSHOVER_DEFAULT_PAYLOAD_MAX_CHARS;
    message = `${message}\n\n${truncatePushoverPayload(record.body, limit)}`;
  }
  return { title, message };
}

/**
 * Validate one record's body and resolve its notification
 * text. Throws `RangeError` on an empty body string — even
 * without the opt-in, the body is the record's payload, and
 * an empty record is a caller bug that must fail closed,
 * never notify as an empty message.
 */
export function resolvePushoverRecord(
  record: PushoverRecord,
  index: number,
  config: Pick<PushoverSinkConfig, "includePayload" | "payloadMaxChars">
): { notification: { title: string; message: string }; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`pushover-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { notification: resolvePushoverNotification(record, config), index };
}

/**
 * Build one record's serialized request body: the
 * notification text plus the body-carried credentials and
 * the fixed priority 0. Kept separate from text
 * derivation because the credentials are only known to be
 * present after `send()` has passed its config checks —
 * deriving text first, then assembling the body, keeps a
 * missing credential a config error rather than a body
 * with silently dropped fields.
 */
export function buildPushoverMessageBody(
  notification: { title: string; message: string },
  appToken: string,
  userKey: string
): string {
  return JSON.stringify({
    token: appToken,
    user: userKey,
    title: notification.title,
    message: notification.message,
    priority: PUSHOVER_PRIORITY,
  });
}

/**
 * Map one Pushover POST `statusCode` onto its retry lane under
 * the WR-210 rules: 429 and every 5xx are transient and so
 * retryable — a rate limit says Pushover could not accept
 * the message right now, not that the payload is poison.
 * Every other non-2xx status (400, 401, 403, 404, and the
 * rest) is a fail-closed message: unknown app token or user
 * key, invalid body, or another verdict retrying cannot
 * change. Callers only pass non-2xx statuses here; a 2xx
 * status is a success, not a failure.
 */
export function classifyPushoverRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Pushover sink (WR-244). One instance targets one Pushover
 * user; the caller owns retry/dead-letter policy around
 * `send()` — this class performs one POST attempt per
 * message through the injected client and reports its
 * outcome. Failures throw `PushoverSinkError` carrying
 * exactly the failed messages with their retry lanes.
 */
export class PushoverSink {
  private readonly cfg: PushoverSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: PushoverSinkConfig) {
    assertValidPushoverSinkConfig(config, "PushoverSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): PushoverSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages to Pushover, in input order. Throws
   * `PushoverSinkConfigError` when no client was injected
   * or the app token or user key is missing, and
   * `PushoverSinkError` when any message fails (carrying
   * exactly the failed messages with their retry lanes; both
   * counted in stats before throwing, so the counters stay
   * honest even for callers that only inspect stats).
   */
  async send(records: PushoverRecord[]): Promise<PushoverSendResult> {
    const resolved = records.map((r, i) => resolvePushoverRecord(r, i, this.cfg));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The
      // credentials and client are not required here,
      // mirroring the sibling sinks' dry-run exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new PushoverSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const appToken = this.cfg.appToken;
    if (appToken === undefined) {
      throw new PushoverSinkConfigError("no app token configured (set `appToken` in the sink config)");
    }
    const userKey = this.cfg.userKey;
    if (userKey === undefined) {
      throw new PushoverSinkConfigError("no user key configured (set `userKey` in the sink config)");
    }
    const failedRecords: PushoverFailedRecord[] = [];
    let sent = 0;
    for (const record of resolved) {
      try {
        const response = await client.post({
          url: PUSHOVER_MESSAGES_URL,
          body: buildPushoverMessageBody(record.notification, appToken, userKey),
        });
        if (response.status >= 200 && response.status < 300) {
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyPushoverRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toPushoverFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new PushoverSinkError(
        `pushover-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toPushoverFailedRecord(err: unknown, index: number): PushoverFailedRecord {
  const failed: PushoverFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
