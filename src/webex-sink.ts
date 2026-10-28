/**
 * Webex notification delivery sink (WR-250).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a team's chat room. Where the Zulip sink
 * (WR-249) posts to a stream topic, this sink posts a
 * message to a Webex room: one event is posted as one
 * room message, and Webex — not the relay — owns the
 * room, the delivery, and the retention of the message.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Webex
 * server. The sink owns the relay-side concerns — room
 * targeting, message-text derivation, payload-inclusion
 * policy, per-message failure mapping — and the injected
 * client owns the wire protocol, including the POST call,
 * the authentication, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { roomId: "<room-id>",
 *     body: "{\"roomId\":\"<room-id>\",\"text\":\"<text>\"}" }
 *
 * The client POSTs to `https://webexapis.com/v1/messages`,
 * sending `body` verbatim as the request body (a JSON
 * object with `roomId` and `text`) and authenticating with
 * an `Authorization: Bearer` header carrying a bot token
 * it alone holds. Two things about this shape are
 * deliberate, and both follow the sibling sinks:
 *
 * - The bot token is held by the client alone. The sink
 *   never receives the token, never places it in the
 *   request, and never logs it: like the Twilio sink
 *   (WR-247), whose auth token the client alone holds,
 *   this sink's request carries no credential at all — the
 *   client adds the `Authorization: Bearer` header from
 *   the bot token it alone holds, so there is nothing in
 *   the request for a log line or a retry queue to leak.
 * - The room is configured, not derived from the event.
 *   One sink targets one room: `roomId` names it. A
 *   missing room is a config error, not a resolution
 *   fallback: unlike the broker sinks, there is no
 *   per-record target to resolve to, so a sink with no
 *   room has nowhere to deliver and fails closed with
 *   `WebexSinkConfigError` at send time (dry runs
 *   excepted — they need no room at all, mirroring the
 *   sibling sinks' dry-run exemption for the client).
 *
 * A room id is an opaque identifier, not a human name:
 * unlike the Zulip sink's stream and topic names, which
 * may contain spaces, a Webex room id must be free of
 * whitespace as well as NUL — the Twilio sink's phone
 * number rule, applied to an identifier.
 *
 * Message text — derived from the event's own values.
 * A room message carries a single text field, so where
 * the sibling sinks split text into title and body, this
 * sink folds the derivation chain into one: the first
 * non-empty value among the record's `subject`, `key`,
 * and `traceId`, in that order. The subject is what the
 * event is about, the key (e.g. aggregate id) is the next
 * most identifying value, and the trace id names the trace
 * that produced the event. An event with none of the
 * values still notifies, with the generic summary
 * `webhook event`: a notification sink that silently
 * dropped sourceless events would hide exactly the
 * deliveries an operator most needs to see, and the room
 * — not the text — is the delivery contract here, so no
 * invented target is at stake.
 *
 * Payload inclusion — by default the message carries the
 * summary only, never the full payload: event bodies
 * routinely carry PII, secrets, or customer data, and a
 * team room is a far wider audience than a queue or a
 * stream. Opting into `includePayload` appends the body
 * verbatim after a blank line, truncated to
 * `payloadMaxChars` characters (default 2000) with a
 * truncation marker — the opt-in is explicit, and the
 * truncation is unconditional, so even an opted-in body
 * cannot flood a room. The body is appended as plain
 * text inside the `text` field, not a fenced code block:
 * Webex renders `text` as plain text, and a fence around
 * an already-JSON body would be noise in a room.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over HTTP status:
 *
 * - a non-2xx POST throws `WebexSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Webex could
 *   not accept the message right now, not that the
 *   payload is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (unknown room, invalid body): retrying
 *   them burns the retry budget for nothing, and
 *   rerouting them elsewhere would notify a room the
 *   operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client or room throws
 *   `WebexSinkConfigError`, which `classifyFailure`
 *   maps to `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for the text field. */
export const WEBEX_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const WEBEX_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Fixed Webex Messages API endpoint. Webex is not self-hostable, so no site is configured. */
export const WEBEX_MESSAGES_URL = "https://webexapis.com/v1/messages";

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (a JSON object with `roomId` and
 * `text`) to `https://webexapis.com/v1/messages`, and
 * authenticates with an `Authorization: Bearer` header
 * carrying a bot token it alone holds. The sink never sees
 * that token, so the request carries no credential:
 * nothing here can leak into a log line.
 */
export interface WebexMessagePostRequest {
  /** The target room id. */
  roomId: string;
  /** The JSON message object, serialized: `roomId`, `text`. */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse Webex's response body.
 */
export interface WebexMessagePostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
}

/**
 * The injected Webex message client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one message per call, sending
 * `body` verbatim as the request body (the JSON object
 * with `roomId` and `text`), and authenticating with its
 * own bot token — which the sink never sees.
 */
export interface WebexMessageClient {
  post(request: WebexMessagePostRequest): Promise<WebexMessagePostResponse>;
}

/**
 * Configuration for one Webex sink. The client is
 * injected: without one, `send()` throws
 * `WebexSinkConfigError` (dry runs excepted — they need
 * no client at all). A missing room is likewise a config
 * error at send time (dry runs excepted): there is no
 * per-record target to fall back to.
 */
export interface WebexSinkConfig {
  /**
   * The target room id: the room every message from this
   * sink lands in. An opaque identifier, so it must be a
   * non-empty string, free of NUL and whitespace, when
   * set; a missing room throws `WebexSinkConfigError` at
   * send time, never a silent no-op.
   */
  roomId?: string;
  /**
   * The Webex message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `WebexMessageClient` and alone holds the
   * bot token. Required for real sends; a missing client
   * is a config error, not a silent no-op.
   */
  client?: WebexMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including text derivation), so a dry
   * run catches a malformed record before it reaches
   * production. Mirrors the `dryRun` convention of the S3
   * offloaders. The room and client are not required in
   * dry-run mode, mirroring the sibling sinks' dry-run
   * exemption.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the message text appends
   * the event body verbatim after a blank line, truncated to
   * `payloadMaxChars` characters (see below). When `false`
   * or absent, the message carries the summary only — the
   * default, so event bodies (which routinely carry PII)
   * never leak into a room unless the operator explicitly
   * asks for them.
   */
  includePayload?: boolean;
  /**
   * Truncation limit for an opted-in payload snippet, in
   * characters (default 2000). Only meaningful with
   * `includePayload`; the truncation is unconditional when
   * the opt-in is set, so an opted-in body cannot flood a
   * room. Must be a positive integer when set.
   */
  payloadMaxChars?: number;
}

/** One event to notify about. */
export interface WebexRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Text-derivation source, first priority: the event's
   * subject, when set and non-empty. Falls through to `key`,
   * then `traceId`.
   */
  subject?: string;
  /**
   * Text-derivation source, second priority: the event's
   * key (e.g. aggregate id).
   */
  key?: string;
  /**
   * Text-derivation source, last priority: the trace id.
   */
  traceId?: string;
}

/** One failed message, with its retry lane already mapped. */
export interface WebexFailedRecord {
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
   * non-2xx status is a fail-closed message (unknown room,
   * invalid body).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface WebexSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-250). */
export interface WebexSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Webex send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on the Webex server and are *not* in
 * `failedRecords`.
 */
export class WebexSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: WebexFailedRecord[];
  constructor(message: string, failedRecords: WebexFailedRecord[]) {
    super(message);
    this.name = "WebexSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, or the room is missing. A config
 * problem, not a downstream verdict, so the retry queue must
 * not burn attempts on it (`classifyFailure` maps it to
 * `non_retryable`).
 */
export class WebexSinkConfigError extends WebexSinkError {
  constructor(reason: string) {
    super(`webex-sink: ${reason}`, []);
    this.name = "WebexSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing room is *not* a shape error: it is a config error
 * raised at send time (`WebexSinkConfigError`), so a sink built
 * before its room is known still fails closed at send time
 * rather than crashing at construction. A present room id must
 * be a non-empty string, free of NUL and whitespace: it is an
 * opaque identifier, not a human name.
 */
export function assertValidWebexSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is WebexSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  const roomId = c.roomId;
  if (roomId !== undefined) {
    if (
      typeof roomId !== "string" ||
      roomId === "" ||
      (roomId as string).includes("\0") ||
      /\s/.test(roomId as string)
    ) {
      throw new RangeError(
        at("`roomId` must be a non-empty string, free of NUL and whitespace when set")
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
 * Derive one record's message text: the first non-empty
 * value among the record's `subject`, `key`, and `traceId`,
 * in that order. Falls back to the generic `webhook event`
 * summary when the record carries none — a notification sink
 * must not silently drop sourceless events, and the room
 * (not the text) is the delivery contract.
 */
export function resolveWebexContent(record: WebexRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return WEBEX_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a room.
 */
export function truncateWebexPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's notification text. Only under the
 * `includePayload` opt-in does the text append the event
 * body verbatim after a blank line, truncated to
 * `payloadMaxChars` (default 2000). Without the opt-in, the
 * text is the summary alone: event bodies routinely carry
 * PII and must never leak into a room by default. The body
 * is appended as plain text inside the `text` field, not
 * a fenced code block: Webex renders `text` as plain text,
 * and a fence around an already-JSON body would be noise
 * in a room.
 */
export function resolveWebexNotification(
  record: WebexRecord,
  config: Pick<WebexSinkConfig, "includePayload" | "payloadMaxChars">
): { text: string } {
  let text = resolveWebexContent(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? WEBEX_DEFAULT_PAYLOAD_MAX_CHARS;
    text = `${text}\n\n${truncateWebexPayload(record.body, limit)}`;
  }
  return { text };
}

/**
 * Build one record's serialized request body: the JSON
 * object with `roomId` and `text`, in that order. Neither
 * the bot token nor any other credential ever appears
 * here — the client alone holds it.
 */
export function buildWebexMessageBody(roomId: string, text: string): string {
  return JSON.stringify({ roomId, text });
}

/**
 * Validate one record's body and resolve its send form: the
 * notification text. Throws `RangeError` on an empty body
 * string — even without the opt-in, the body is the record's
 * payload, and an empty record is a caller bug that must
 * fail closed, never notify as an empty message.
 */
export function resolveWebexRecord(
  record: WebexRecord,
  index: number,
  config: Pick<WebexSinkConfig, "includePayload" | "payloadMaxChars">
): { notification: { text: string }; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`webex-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { notification: resolveWebexNotification(record, config), index };
}

/**
 * Map one Webex POST `statusCode` onto its retry lane under
 * the WR-210 rules: 429 and every 5xx are transient and so
 * retryable — a rate limit says Webex could not accept the
 * message right now, not that the payload is poison.
 * Every other non-2xx status (400, 401, 403, 404, and the
 * rest) is a fail-closed message: unknown room, invalid
 * body, or another verdict retrying cannot change. Callers
 * only pass non-2xx statuses here; a 2xx status is a
 * success, not a failure.
 */
export function classifyWebexRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Webex sink (WR-250). One instance targets one Webex
 * room; the caller owns retry/dead-letter policy around
 * `send()` — this class performs one POST attempt per
 * message through the injected client and reports its
 * outcome. Failures throw `WebexSinkError` carrying
 * exactly the failed messages with their retry lanes.
 */
export class WebexSink {
  private readonly cfg: WebexSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: WebexSinkConfig) {
    assertValidWebexSinkConfig(config, "WebexSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): WebexSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages to the Webex room, in input order.
   * Throws `WebexSinkConfigError` when no client was
   * injected or the room is missing, and `WebexSinkError`
   * when any message fails (carrying exactly the failed
   * messages with their retry lanes; both counted in stats
   * before throwing, so the counters stay honest even for
   * callers that only inspect stats).
   */
  async send(records: WebexRecord[]): Promise<WebexSendResult> {
    const resolved = records.map((r, i) => resolveWebexRecord(r, i, this.cfg));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The room
      // and client are not required here, mirroring the
      // sibling sinks' dry-run exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new WebexSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const roomId = this.cfg.roomId;
    if (roomId === undefined) {
      throw new WebexSinkConfigError("no room configured (set `roomId` in the sink config)");
    }
    const failedRecords: WebexFailedRecord[] = [];
    let sent = 0;
    for (const record of resolved) {
      try {
        const response = await client.post({
          roomId,
          body: buildWebexMessageBody(roomId, record.notification.text),
        });
        if (response.status >= 200 && response.status < 300) {
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyWebexRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toWebexFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new WebexSinkError(
        `webex-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toWebexFailedRecord(err: unknown, index: number): WebexFailedRecord {
  const failed: WebexFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
