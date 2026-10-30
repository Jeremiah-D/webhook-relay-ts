/**
 * OneSignal push notification delivery sink (WR-275).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's device. Where the Clickatell sink
 * (WR-274) delivers SMS through Clickatell's platform API
 * with a bare-key `Authorization` header and the TextMagic
 * sink (WR-272) delivers SMS through TextMagic's SMS API
 * with the `X-TM-Username` and `X-TM-Key` header pair,
 * this sink delivers push notifications through OneSignal's
 * notifications API: one event is sent as one POST, and
 * OneSignal — not the relay — owns the device routing, the
 * delivery, and the retention of the notification.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a OneSignal
 * server. The sink owns the relay-side concerns — message
 * targeting, headings/contents derivation, payload-inclusion
 * policy, per-message failure mapping — and the injected
 * client owns the wire protocol, including the POST call,
 * the authentication, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://api.onesignal.com/notifications",
 *     body: "{\"app_id\":\"<app id>\",\"include_player_ids\":[\"<player id>\", ...],\"headings\":{\"en\":\"<subject>\"},\"contents\":{\"en\":\"<content>\"}}" }
 *
 * The client POSTs to that URL, sending `body` verbatim
 * as the request body (a JSON object) and authenticating
 * with an `Authorization: Basic <REST API key>` header
 * carrying the REST API key it alone holds — OneSignal's
 * header-auth shape. Three things about this shape are
 * deliberate, and all follow the sibling sinks:
 *
 * - The REST API key is held by the client alone. The sink
 *   never receives it, never places it in the request,
 *   and never logs it: like the TextMagic sink (WR-272),
 *   whose header pair the client alone holds, this sink's
 *   handed request carries no credential at all — the
 *   client adds the `Authorization: Basic` header from the
 *   key it alone holds, so there is nothing in the handed
 *   request for a log line or a retry queue to leak. This
 *   is the opposite of the Vonage sink (WR-252), whose
 *   credentials ride inside the request body: OneSignal
 *   authenticates by header, so the body carries only
 *   routing and content.
 * - The targeting rides in `app_id` plus
 *   `include_player_ids`: the app id names the OneSignal
 *   app and the player ids name the devices, so one POST
 *   fans the notification out to every listed device.
 *   Segment targeting is out of scope for this item: no
 *   `included_segments` field is accepted.
 * - The host is fixed, not configurable: OneSignal is a
 *   single hosted service, so there is no self-hosted
 *   deployment to point at — unlike the Infobip sink
 *   (WR-267), whose host varies per account, a
 *   configurable URL here could only misroute a message
 *   to a server that is not OneSignal.
 *
 * The app id and player ids are configured, not derived
 * from the event. One sink targets one app and one set of
 * player ids. A missing app id or player set is a config
 * error, not a resolution fallback: unlike the broker
 * sinks, there is no per-record target to resolve to, so a
 * sink with neither has nowhere to deliver and fails
 * closed with `OneSignalSinkConfigError` at send time
 * (dry runs excepted — they need no app or players at
 * all, mirroring the sibling sinks' dry-run exemption for
 * the client).
 *
 * Message content — a push notification carries two
 * fields, not one, so the event's values split across
 * them: `headings.en` takes the event's `subject` and is
 * omitted entirely when the event has no subject, while
 * `contents.en` takes the first non-empty value among
 * `subject`, `key`, and `traceId`, in that order — the
 * subject is what the event is about, the key (e.g.
 * aggregate id) is the next most identifying value, and
 * the trace id names the trace that produced the event.
 * An event with none of the values still notifies, with
 * the generic summary `webhook event` as its contents: a
 * notification sink that silently dropped sourceless
 * events would hide exactly the deliveries an operator
 * most needs to see, and the player ids — not the
 * content — are the delivery contract here, so no
 * invented target is at stake.
 *
 * Payload inclusion — by default the notification carries
 * the summary only, never the full payload: event bodies
 * routinely carry PII, secrets, or customer data, and a
 * device is a far wider audience than a queue or a
 * stream. Opting into `includePayload` appends the body
 * verbatim after a blank line inside `contents.en`,
 * truncated to `payloadMaxChars` characters (default
 * 2000) with a truncation marker — the opt-in is
 * explicit, and the truncation is unconditional, so even
 * an opted-in body cannot flood a device. The payload is
 * appended as plain text inside the `contents` field, not
 * a fenced code block: a push notification renders as-is,
 * and a fence would be noise on a device screen.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over HTTP status:
 *
 * - a non-2xx POST throws `OneSignalSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says OneSignal could
 *   not accept the message right now, not that the
 *   payload is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (unknown player, invalid body, bad
 *   credentials): retrying them burns the retry budget
 *   for nothing, and rerouting them elsewhere would
 *   notify players the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client, app id, or player set throws
 *   `OneSignalSinkConfigError`, which `classifyFailure`
 *   maps to `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for the content field. */
export const ONESIGNAL_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const ONESIGNAL_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Fixed OneSignal platform API endpoint for every message. */
export const ONESIGNAL_SEND_URL = "https://api.onesignal.com/notifications";

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (a JSON object with `app_id`,
 * `include_player_ids`, and the `headings`/`contents`
 * fields) to the fixed notifications endpoint, and
 * authenticates with an `Authorization: Basic` header
 * carrying the REST API key it alone holds. The sink
 * never sees that key, so the request carries no
 * credential: nothing here can leak into a log line.
 */
export interface OneSignalMessagePostRequest {
  /** Always the fixed OneSignal notifications endpoint. */
  url: string;
  /** The JSON message object, serialized: `app_id`, `include_player_ids`, plus `headings`/`contents`. */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse OneSignal's response body.
 */
export interface OneSignalMessagePostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
}

/**
 * The injected OneSignal message client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one message per call, sending
 * `body` verbatim as the request body (the JSON object
 * with `app_id`, `include_player_ids`, and the
 * `headings`/`contents` fields), setting the
 * `application/json` content type, and authenticating with
 * an `Authorization: Basic` header carrying its own REST
 * API key — which the sink never sees.
 */
export interface OneSignalMessageClient {
  post(request: OneSignalMessagePostRequest): Promise<OneSignalMessagePostResponse>;
}

/**
 * Configuration for one OneSignal sink. The client is
 * injected: without one, `send()` throws
 * `OneSignalSinkConfigError` (dry runs excepted — they need
 * no client at all). A missing app id or player set is
 * likewise a config error at send time (dry runs
 * excepted): there is no per-record target to fall back
 * to. The REST API key is deliberately absent from this
 * config: the client alone holds it and sends it as the
 * `Authorization: Basic` header. Segment targeting is out
 * of scope for this item: no `included_segments` field is
 * configured.
 */
export interface OneSignalSinkConfig {
  /**
   * The OneSignal app id (`app_id`): every message is
   * addressed to this app. Must be a non-empty string,
   * free of NUL and whitespace, when set; a missing app
   * id throws `OneSignalSinkConfigError` at send time.
   */
  appId?: string;
  /**
   * The target player ids (`include_player_ids`): every
   * message is fanned out to each device in this array,
   * carried as the flat `include_player_ids` array. Each
   * entry must be a non-empty string, free of NUL and
   * whitespace, when set; a missing player set throws
   * `OneSignalSinkConfigError` at send time.
   */
  includePlayerIds?: string[];
  /**
   * The OneSignal message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `OneSignalMessageClient` and alone holds the
   * REST API key. Required for real sends; a missing client
   * is a config error, not a silent no-op.
   */
  client?: OneSignalMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including content derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The app id, player set, and client are
   * not required in dry-run mode, mirroring the sibling
   * sinks' dry-run exemption.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the message content appends
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
   * phone. Must be a positive integer when set.
   */
  payloadMaxChars?: number;
}

/** One event to notify about. */
export interface OneSignalRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Headings source and contents-derivation source, first
   * priority: the event's subject, when set and non-empty.
   * `headings.en` takes it directly (omitted when absent);
   * `contents.en` falls through to `key`, then `traceId`.
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
export interface OneSignalFailedRecord {
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
   * non-2xx status is a fail-closed message (unknown player,
   * invalid body, bad credentials).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface OneSignalSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-275). */
export interface OneSignalSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for OneSignal send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on OneSignal's server and are *not* in
 * `failedRecords`.
 */
export class OneSignalSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: OneSignalFailedRecord[];
  constructor(message: string, failedRecords: OneSignalFailedRecord[]) {
    super(message);
    this.name = "OneSignalSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, or the app id or player set is
 * missing. A config problem, not a downstream verdict, so
 * the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class OneSignalSinkConfigError extends OneSignalSinkError {
  constructor(reason: string) {
    super(`onesignal-sink: ${reason}`, []);
    this.name = "OneSignalSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing app id or player set is *not* a shape error: it
 * is a config error raised at send time
 * (`OneSignalSinkConfigError`), so a sink built before its
 * app or players are known still fails closed at send time
 * rather than crashing at construction. A present `appId`
 * value must be a non-empty string, and a present
 * `includePlayerIds` value a non-empty array of non-empty
 * strings, each free of NUL and whitespace.
 */
export function assertValidOneSignalSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is OneSignalSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  const appId = c.appId;
  if (appId !== undefined) {
    if (
      typeof appId !== "string" ||
      appId === "" ||
      appId.includes("\0") ||
      /\s/.test(appId)
    ) {
      throw new RangeError(
        at("`appId` must be a non-empty string, free of NUL and whitespace, when set")
      );
    }
  }
  const includePlayerIds = c.includePlayerIds;
  if (includePlayerIds !== undefined) {
    if (
      !Array.isArray(includePlayerIds) ||
      includePlayerIds.length === 0 ||
      includePlayerIds.some(
        (p) =>
          typeof p !== "string" || p === "" || p.includes("\0") || /\s/.test(p)
      )
    ) {
      throw new RangeError(
        at("`includePlayerIds` must be a non-empty array of non-empty strings, free of NUL and whitespace, when set")
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
 * Derive one record's contents text: the first non-empty
 * value among `subject`, `key`, and `traceId`, in that
 * order. Falls back to the generic `webhook event` summary
 * when the record carries none — a notification sink must
 * not silently drop sourceless events, and the player ids
 * (not the content) are the delivery contract.
 */
export function resolveOneSignalContent(record: OneSignalRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return ONESIGNAL_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a device.
 */
export function truncateOneSignalPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's headings: the event's `subject`
 * when set and non-empty, otherwise absent — `headings`
 * is omitted from the request entirely when the event has
 * no subject, rather than sent as an empty object, so a
 * subject-less notification carries contents alone.
 */
export function resolveOneSignalHeadings(
  record: OneSignalRecord
): { en: string } | undefined {
  if (record.subject !== undefined && record.subject !== "") {
    return { en: record.subject };
  }
  return undefined;
}

/**
 * Derive one record's notification: `headings` from the
 * subject (omitted when absent) and `contents` from the
 * first non-empty among `subject`, `key`, and `traceId`
 * (falling back to `webhook event`). Only under the
 * `includePayload` opt-in does the contents append the
 * event body verbatim after a blank line, truncated to
 * `payloadMaxChars` (default 2000). Without the opt-in,
 * the contents are the summary alone: event bodies
 * routinely carry PII and must never leak into a
 * notification by default. The payload is appended as
 * plain text inside the `contents` field, not a fenced
 * code block: a push notification renders as-is, and a
 * fence would be noise on a device screen.
 */
export function resolveOneSignalNotification(
  record: OneSignalRecord,
  config: Pick<OneSignalSinkConfig, "includePayload" | "payloadMaxChars">
): { headings?: { en: string }; contents: { en: string } } {
  let contents = resolveOneSignalContent(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? ONESIGNAL_DEFAULT_PAYLOAD_MAX_CHARS;
    contents = `${contents}\n\n${truncateOneSignalPayload(record.body, limit)}`;
  }
  const headings = resolveOneSignalHeadings(record);
  return headings === undefined
    ? { contents: { en: contents } }
    : { headings, contents: { en: contents } };
}

/**
 * Build one record's serialized request body: the JSON
 * object with `app_id`, `include_player_ids`, then the
 * notification's `headings` (when present) and `contents`,
 * in that order. The REST API key never appears here —
 * the client alone holds it and sends it as the
 * `Authorization: Basic` header.
 */
export function buildOneSignalMessageBody(
  appId: string,
  includePlayerIds: string[],
  notification: { headings?: { en: string }; contents: { en: string } }
): string {
  const body: Record<string, unknown> = {
    app_id: appId,
    include_player_ids: includePlayerIds,
  };
  if (notification.headings !== undefined) {
    body.headings = notification.headings;
  }
  body.contents = notification.contents;
  return JSON.stringify(body);
}

/**
 * Validate one record's body and resolve its send form: the
 * notification headings and contents. Throws `RangeError`
 * on an empty body string — even without the opt-in, the
 * body is the record's payload, and an empty record is a
 * caller bug that must fail closed, never notify as an
 * empty message.
 */
export function resolveOneSignalRecord(
  record: OneSignalRecord,
  index: number,
  config: Pick<OneSignalSinkConfig, "includePayload" | "payloadMaxChars">
): { notification: { content: string }; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`onesignal-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { notification: resolveOneSignalNotification(record, config), index };
}

/**
 * Map one OneSignal POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says OneSignal could not
 * accept the message right now, not that the payload is
 * poison. Every other non-2xx status (400, 401, 403,
 * 404, and the rest) is a fail-closed message: unknown
 * player, invalid body, bad credentials, or another verdict
 * retrying cannot change. Callers only pass non-2xx
 * statuses here; a 2xx status is a success, not a failure.
 */
export function classifyOneSignalRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * OneSignal sink (WR-275). One instance targets one
 * OneSignal app and one set of player ids; the
 * caller owns retry / dead-letter policy around `send()` —
 * this class performs one POST attempt per message
 * through the injected client and reports its outcome.
 * Failures throw `OneSignalSinkError` carrying exactly the
 * failed messages with their retry lanes.
 */
export class OneSignalSink {
  private readonly cfg: OneSignalSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: OneSignalSinkConfig) {
    assertValidOneSignalSinkConfig(config, "OneSignalSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): OneSignalSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send push notifications, in input order. Throws
   * `OneSignalSinkConfigError` when no client was injected
   * or the app id or player set is missing, and
   * `OneSignalSinkError` when any message
   * fails (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: OneSignalRecord[]): Promise<OneSignalSendResult> {
    const resolved = records.map((r, i) => resolveOneSignalRecord(r, i, this.cfg));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The
      // app id, player set, and client are
      // not required here, mirroring the sibling sinks'
      // dry-run exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new OneSignalSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const appId = this.cfg.appId;
    if (appId === undefined) {
      throw new OneSignalSinkConfigError("no app id configured (set `appId` in the sink config)");
    }
    const includePlayerIds = this.cfg.includePlayerIds;
    if (includePlayerIds === undefined) {
      throw new OneSignalSinkConfigError("no player ids configured (set `includePlayerIds` in the sink config)");
    }
    const url = ONESIGNAL_SEND_URL;
    const failedRecords: OneSignalFailedRecord[] = [];
    let sent = 0;
    for (const record of resolved) {
      try {
        const response = await client.post({
          url,
          body: buildOneSignalMessageBody(appId, includePlayerIds, record.notification),
        });
        if (response.status >= 200 && response.status < 300) {
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyOneSignalRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toOneSignalFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new OneSignalSinkError(
        `onesignal-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toOneSignalFailedRecord(err: unknown, index: number): OneSignalFailedRecord {
  const failed: OneSignalFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
