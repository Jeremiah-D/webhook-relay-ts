/**
 * Firebase Cloud Messaging (FCM) push notification delivery sink (WR-276).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's device. Where the OneSignal sink
 * (WR-275) delivers push notifications through OneSignal's
 * notifications API with a Basic-auth header and an
 * `app_id` plus `include_player_ids` envelope, this sink
 * delivers push notifications through Firebase Cloud
 * Messaging's HTTP v1 API: one event is sent as one POST,
 * and FCM — not the relay — owns the device routing, the
 * delivery, and the retention of the notification.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need an FCM server.
 * The sink owns the relay-side concerns — message
 * targeting, notification derivation, payload-inclusion
 * policy, per-message failure mapping — and the injected
 * client owns the wire protocol, including the POST call,
 * the authentication, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://fcm.googleapis.com/v1/projects/<project>/messages:send",
 *     body: "{\"message\":{\"token\":\"<device token>\",\"notification\":{\"title\":\"<subject>\",\"body\":\"<content>\"}}}" }
 *
 * The client POSTs to that URL, sending `body` verbatim
 * as the request body (a JSON object) and authenticating
 * with an `Authorization: Bearer <OAuth 2.0 access token>`
 * header carrying a short-lived token minted from the
 * operator's Firebase service account (scope
 * `https://www.googleapis.com/auth/firebase.messaging`).
 * Three things about this shape are deliberate, and all
 * follow the sibling sinks:
 *
 * - The OAuth token is held by the client alone. The sink
 *   never receives it, never places it in the request,
 *   and never logs it: like the OneSignal sink (WR-275),
 *   whose REST API key the client alone holds, this sink's
 *   handed request carries no credential at all — the
 *   client adds the `Authorization: Bearer` header from
 *   the token it alone holds, so there is nothing in the
 *   handed request for a log line or a retry queue to
 *   leak. Minting and refreshing the token live outside
 *   this sink: the config holds an already-minted token
 *   only through the client, never through the sink.
 * - The host is fixed, not configurable, and the project
 *   is a path segment, not a host: FCM is a single hosted
 *   service, so there is no self-hosted deployment to
 *   point at — unlike the Infobip sink (WR-267), whose
 *   host varies per account, a configurable URL here
 *   could only misroute a message to a server that is
 *   not FCM. The project id is configured (one sink
 *   targets one Firebase project), and the URL is built
 *   from it at send time.
 * - Only the HTTP v1 API is used: the legacy server-key
 *   interface was retired in July 2024, so no legacy
 *   `key=` header or `to` field is accepted anywhere in
 *   this module — the `message` envelope with a
 *   per-device `token` is the only shape.
 *
 * The project id and device token are configured, not
 * derived from the event. One sink targets one project
 * and one device registration token. A missing project id
 * or device token is a config error, not a resolution
 * fallback: unlike the broker sinks, there is no
 * per-record target to resolve to, so a sink with neither
 * has nowhere to deliver and fails closed with
 * `FcmSinkConfigError` at send time (dry runs excepted —
 * they need no project or token at all, mirroring the
 * sibling sinks' dry-run exemption for the client).
 *
 * Message content — a push notification carries two
 * fields, not one, so the event's values split across
 * them: `notification.title` takes the event's `subject`
 * and is omitted entirely when the event has no subject,
 * while `notification.body` takes the first non-empty
 * value among `subject`, `key`, and `traceId`, in that
 * order — the subject is what the event is about, the key
 * (e.g. aggregate id) is the next most identifying value,
 * and the trace id names the trace that produced the
 * event. An event with none of the values still notifies,
 * with the generic summary `webhook event` as its body: a
 * notification sink that silently dropped sourceless
 * events would hide exactly the deliveries an operator
 * most needs to see, and the device token — not the
 * content — is the delivery contract here, so no invented
 * target is at stake.
 *
 * Payload inclusion — by default the notification carries
 * the summary only, never the full payload: event bodies
 * routinely carry PII, secrets, or customer data, and a
 * device is a far wider audience than a queue or a
 * stream. Opting into `includePayload` appends the body
 * as the `data.payload` field of the `message` object,
 * truncated to `payloadMaxChars` characters (default
 * 2000) with a truncation marker — the opt-in is
 * explicit, and the truncation is unconditional, so even
 * an opted-in body cannot flood a device. The payload
 * rides in `data`, not inside the notification text: FCM
 * `data` is the machine-readable channel (string-to-
 * string map), while `notification` stays the human-
 * readable summary, so an opted-in body never changes
 * what the device renders.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over HTTP status:
 *
 * - a non-2xx POST throws `FcmSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says FCM could not
 *   accept the message right now, not that the
 *   payload is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (unknown token, invalid body, bad
 *   credentials): retrying them burns the retry budget
 *   for nothing, and rerouting them elsewhere would
 *   notify devices the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client, project id, or device token throws
 *   `FcmSinkConfigError`, which `classifyFailure`
 *   maps to `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for the body field. */
export const FCM_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const FCM_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Fixed FCM HTTP v1 API host and path prefix; the project id fills the middle segment. */
export const FCM_SEND_URL_PREFIX = "https://fcm.googleapis.com/v1/projects/";
export const FCM_SEND_URL_SUFFIX = "/messages:send";

/**
 * Build the fixed FCM HTTP v1 send URL for one project:
 * `https://fcm.googleapis.com/v1/projects/<project>/messages:send`.
 * The host is fixed; only the project segment varies, and it
 * comes from the sink config, never from the event.
 */
export function buildFcmSendUrl(project: string): string {
  return `${FCM_SEND_URL_PREFIX}${project}${FCM_SEND_URL_SUFFIX}`;
}

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (a JSON object with the `message`
 * envelope) to the fixed per-project send endpoint, and
 * authenticates with an `Authorization: Bearer` header
 * carrying its own short-lived OAuth 2.0 access token —
 * which the sink never sees. The legacy server-key
 * interface is not used: no `key=` header, no `to` field.
 */
export interface FcmMessagePostRequest {
  /** Always the fixed FCM HTTP v1 send endpoint for the configured project. */
  url: string;
  /** The JSON message object, serialized: `message` with `token`, `notification`, and optional `data`. */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse FCM's response body.
 */
export interface FcmMessagePostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
}

/**
 * The injected FCM message client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one message per call, sending
 * `body` verbatim as the request body (the JSON object
 * with the `message` envelope), setting the
 * `application/json` content type, and authenticating with
 * an `Authorization: Bearer` header carrying its own
 * OAuth 2.0 access token (minted from the operator's
 * Firebase service account, scope
 * `https://www.googleapis.com/auth/firebase.messaging`)
 * — which the sink never sees.
 */
export interface FcmMessageClient {
  post(request: FcmMessagePostRequest): Promise<FcmMessagePostResponse>;
}

/**
 * Configuration for one FCM sink. The client is
 * injected: without one, `send()` throws
 * `FcmSinkConfigError` (dry runs excepted — they need
 * no client at all). A missing project id or device token
 * is likewise a config error at send time (dry runs
 * excepted): there is no per-record target to fall back
 * to. The OAuth access token is deliberately absent from
 * this config: the client alone holds it (minted from the
 * service account) and sends it as the `Authorization:
 * Bearer` header; minting and refreshing live outside
 * this sink.
 */
export interface FcmSinkConfig {
  /**
   * The Firebase project id: every message is addressed
   * to this project, as the middle segment of the send
   * URL. Must be a non-empty string, free of NUL and
   * whitespace, when set; a missing project id throws
   * `FcmSinkConfigError` at send time.
   */
  project?: string;
  /**
   * The target device registration token (`message.token`):
   * every message is delivered to this one device. Must
   * be a non-empty string, free of NUL and whitespace,
   * when set; a missing token throws `FcmSinkConfigError`
   * at send time.
   */
  token?: string;
  /**
   * The FCM message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `FcmMessageClient` and alone holds the
   * OAuth 2.0 access token. Required for real sends; a
   * missing client is a config error, not a silent no-op.
   */
  client?: FcmMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including notification derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The project id, device token, and client are
   * not required in dry-run mode, mirroring the sibling
   * sinks' dry-run exemption.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the message appends the
   * event body verbatim as the `data.payload` field of the
   * `message` object, truncated to `payloadMaxChars`
   * characters (see below). When `false` or absent, the
   * message carries the notification summary only — the
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
export interface FcmRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Title source and body-derivation source, first
   * priority: the event's subject, when set and non-empty.
   * `notification.title` takes it directly (omitted when
   * absent); `notification.body` falls through to `key`,
   * then `traceId`.
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
export interface FcmFailedRecord {
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
   * non-2xx status is a fail-closed message (unknown token,
   * invalid body, bad credentials).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface FcmSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-276). */
export interface FcmSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for FCM send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on FCM's server and are *not* in
 * `failedRecords`.
 */
export class FcmSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: FcmFailedRecord[];
  constructor(message: string, failedRecords: FcmFailedRecord[]) {
    super(message);
    this.name = "FcmSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, or the project id or device token
 * is missing. A config problem, not a downstream verdict,
 * so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class FcmSinkConfigError extends FcmSinkError {
  constructor(reason: string) {
    super(`fcm-sink: ${reason}`, []);
    this.name = "FcmSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing project id or device token is *not* a shape error: it
 * is a config error raised at send time
 * (`FcmSinkConfigError`), so a sink built before its project
 * or token is known still fails closed at send time rather
 * than crashing at construction. A present `project` or
 * `token` value must be a non-empty string, free of NUL and
 * whitespace.
 */
export function assertValidFcmSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is FcmSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  const project = c.project;
  if (project !== undefined) {
    if (
      typeof project !== "string" ||
      project === "" ||
      project.includes("\0") ||
      /\s/.test(project)
    ) {
      throw new RangeError(
        at("`project` must be a non-empty string, free of NUL and whitespace, when set")
      );
    }
  }
  const token = c.token;
  if (token !== undefined) {
    if (
      typeof token !== "string" ||
      token === "" ||
      token.includes("\0") ||
      /\s/.test(token)
    ) {
      throw new RangeError(
        at("`token` must be a non-empty string, free of NUL and whitespace, when set")
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
 * not silently drop sourceless events, and the device
 * token (not the content) is the delivery contract.
 */
export function resolveFcmBody(record: FcmRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return FCM_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a device.
 */
export function truncateFcmPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's notification: `title` from the
 * subject (omitted when absent) and `body` from the first
 * non-empty among `subject`, `key`, and `traceId`
 * (falling back to `webhook event`).
 */
export function resolveFcmNotification(
  record: FcmRecord
): { title?: string; body: string } {
  const body = resolveFcmBody(record);
  if (record.subject !== undefined && record.subject !== "") {
    return { title: record.subject, body };
  }
  return { body };
}

/**
 * Build one record's serialized request body: the JSON
 * object with the `message` envelope — `token`, then the
 * `notification` (`title` when present, `body`), then
 * `data.payload` only under the `includePayload` opt-in
 * (truncated to `payloadMaxChars`, default 2000). The
 * OAuth token never appears here — the client alone holds
 * it and sends it as the `Authorization: Bearer` header.
 */
export function buildFcmMessageBody(
  token: string,
  notification: { title?: string; body: string },
  config: Pick<FcmSinkConfig, "includePayload" | "payloadMaxChars">,
  recordBody?: string
): string {
  const notificationBody: Record<string, string> = {};
  if (notification.title !== undefined) {
    notificationBody.title = notification.title;
  }
  notificationBody.body = notification.body;
  const message: Record<string, unknown> = {
    token,
    notification: notificationBody,
  };
  if (config.includePayload === true && recordBody !== undefined) {
    const limit = config.payloadMaxChars ?? FCM_DEFAULT_PAYLOAD_MAX_CHARS;
    message.data = { payload: truncateFcmPayload(recordBody, limit) };
  }
  return JSON.stringify({ message });
}

/**
 * Validate one record's body and resolve its send form: the
 * notification title and body. Throws `RangeError`
 * on an empty body string — even without the opt-in, the
 * body is the record's payload, and an empty record is a
 * caller bug that must fail closed, never notify as an
 * empty message.
 */
export function resolveFcmRecord(
  record: FcmRecord,
  index: number
): { notification: { title?: string; body: string }; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`fcm-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { notification: resolveFcmNotification(record), index };
}

/**
 * Map one FCM POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says FCM could not
 * accept the message right now, not that the payload is
 * poison. Every other non-2xx status (400, 401, 403,
 * 404, and the rest) is a fail-closed message: unknown
 * token, invalid body, bad credentials, or another verdict
 * retrying cannot change. Callers only pass non-2xx
 * statuses here; a 2xx status is a success, not a failure.
 */
export function classifyFcmRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * FCM sink (WR-276). One instance targets one Firebase
 * project and one device registration token; the caller
 * owns retry / dead-letter policy around `send()` — this
 * class performs one POST attempt per message through the
 * injected client and reports its outcome. Failures throw
 * `FcmSinkError` carrying exactly the failed messages
 * with their retry lanes.
 */
export class FcmSink {
  private readonly cfg: FcmSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: FcmSinkConfig) {
    assertValidFcmSinkConfig(config, "FcmSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): FcmSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send push notifications, in input order. Throws
   * `FcmSinkConfigError` when no client was injected
   * or the project id or device token is missing, and
   * `FcmSinkError` when any message
   * fails (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: FcmRecord[]): Promise<FcmSendResult> {
    const resolved = records.map((r, i) => resolveFcmRecord(r, i));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The
      // project id, device token, and client are
      // not required here, mirroring the sibling sinks'
      // dry-run exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new FcmSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const project = this.cfg.project;
    if (project === undefined) {
      throw new FcmSinkConfigError("no project configured (set `project` in the sink config)");
    }
    const token = this.cfg.token;
    if (token === undefined) {
      throw new FcmSinkConfigError("no device token configured (set `token` in the sink config)");
    }
    const url = buildFcmSendUrl(project);
    const failedRecords: FcmFailedRecord[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          url,
          body: buildFcmMessageBody(token, record.notification, this.cfg, records[i].body),
        });
        if (response.status >= 200 && response.status < 300) {
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyFcmRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toFcmFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new FcmSinkError(
        `fcm-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toFcmFailedRecord(err: unknown, index: number): FcmFailedRecord {
  const failed: FcmFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
