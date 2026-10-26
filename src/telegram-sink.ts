/**
 * Telegram notification delivery sink (WR-231).
 *
 * Some downstreams are not queues, streams, or topics at all:
 * they are a human's chat channel. Where the SQS sink (WR-210)
 * delivers to an unordered queue, the Kinesis sink (WR-213)
 * delivers to an AWS SigV4 stream, the Kafka sink (WR-215)
 * delivers to a partitioned log, the MQTT sink (WR-216)
 * delivers to a pub/sub topic tree, the AMQP sink (WR-217)
 * delivers to an exchange, the JetStream sink (WR-218) delivers
 * to a durable stream over the native JetStream publish
 * protocol, the Redis sink (WR-219) delivers to a Redis stream
 * with XADD, the Pub/Sub sink (WR-220) delivers to a Google
 * Cloud topic with pass-through attributes, the Service Bus
 * sink (WR-221) delivers to an Azure queue or topic with
 * pass-through properties, the EventBridge sink (WR-222)
 * delivers to an AWS event bus with a resolved DetailType, the
 * Pulsar sink (WR-223) delivers to an Apache Pulsar topic, the
 * SNS sink (WR-224) delivers to an AWS SNS topic, the Event
 * Hubs sink (WR-225) delivers to an Azure event hub, the Slack
 * sink (WR-226) delivers to a Slack channel, the DingTalk sink
 * (WR-228) delivers to a DingTalk group, and the Feishu sink
 * (WR-229) delivers to a Feishu group, this sink delivers to a
 * Telegram chat: one event is posted as one text message to a
 * configured chat, and Telegram — not the relay — owns the
 * chat, the message id, and the retention of the notification.
 * The sinks are orthogonal — queue delivery for unordered work,
 * stream delivery for AWS-ordered work, log delivery for
 * broker-native ordered work, topic-tree delivery for
 * broker-mediated fan-out, exchange delivery for broker-mediated
 * routing, durable-stream delivery for replayable work,
 * Redis-stream delivery for in-memory ordered work, Pub/Sub
 * delivery for cloud-managed fan-out, Service Bus delivery for
 * Azure-managed fan-out, EventBridge delivery for rule-routed
 * cloud events, Pulsar delivery for geo-replicated partitioned
 * topics, SNS delivery for cloud-managed fan-out to many
 * protocols at once, Event Hubs delivery for Azure-managed
 * streaming ingest, Slack delivery for human notification on
 * Slack, DingTalk delivery for human notification on DingTalk,
 * Feishu delivery for human notification on Feishu, Telegram
 * delivery for human notification on Telegram — and a Telegram
 * delivery can still be archived by the S3 offloaders like any
 * other delivery.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Telegram chat.
 * The sink owns the relay-side concerns — chat targeting,
 * message-text derivation, payload-inclusion policy,
 * per-message failure mapping — and the injected client owns
 * the wire protocol, including the POST call and the status it
 * returns.
 *
 * Wire shape — one POST per message, carried to the injected
 * client as:
 *
 *   { chatId: "<configured chat id>", text: "<derived message text>" }
 *
 * The client wraps this into Telegram's Bot API `sendMessage`
 * call (`POST https://api.telegram.org/bot<token>/sendMessage`
 * with `{ chat_id, text }`). The bot token is held by the
 * client alone: it never appears in the sink's request
 * objects, never in the message text, and never in the sink's
 * config — rotating the token is a client-side change, and a
 * token that never crosses the sink boundary cannot leak
 * through a sink log, a dry run, or a failed-record report.
 * The client sends the text verbatim (no parse mode is set by
 * the sink), so message text is never reinterpreted as
 * markup.
 *
 * Chat targeting — one sink targets one chat: every message
 * goes there. The chat id is configured as a string (group
 * and channel ids are negative integers in Telegram's API,
 * and a string preserves the exact value with no float
 * rounding; `@channel` usernames are likewise strings). A
 * missing chat id is a config error, not a resolution
 * fallback: unlike the broker sinks, there is no per-record
 * channel to resolve to, so a sink with no chat id has
 * nowhere to deliver and fails closed with
 * `TelegramSinkConfigError` at send time (dry runs excepted —
 * they need no chat id at all, mirroring the sibling sinks'
 * dry-run exemption for the client).
 *
 * Message text — one line of summary, derived from the
 * event's own values, first non-empty wins: `subject`, then
 * `key`, then `traceId` — the same source chain the
 * EventBridge sink uses for its DetailType, the SNS sink
 * uses for its topic, and the Slack, DingTalk, and Feishu
 * sinks use for their message text. An event with none of the
 * three still notifies, with the generic summary
 * `webhook event`: a notification sink that silently dropped
 * sourceless events would hide exactly the deliveries an
 * operator most needs to see, and the channel — not the
 * text — is the delivery contract here, so no invented
 * channel is at stake.
 *
 * Payload inclusion — by default the message carries the
 * summary only, never the full payload: event bodies routinely
 * carry PII, secrets, or customer data, and a chat is a far
 * wider audience than a queue or a stream. Opting into
 * `includePayload` appends the body verbatim inside a fenced
 * code block, truncated to `payloadMaxChars` characters
 * (default 2000) with a truncation marker — the opt-in is
 * explicit, and the truncation is unconditional, so even an
 * opted-in body cannot flood a chat or blow past Telegram's
 * message limits.
 *
 * Failure handling mirrors the WR-210 SQS sink's classification
 * (`src/failure.ts`), applied per message over HTTP status:
 *
 * - a non-2xx POST throws `TelegramSinkError` carrying every
 *   failed message with its retry lane already mapped, so the
 *   caller retries exactly the failed messages;
 * - retryable statuses are the transient HTTP states — 429
 *   and every 5xx: a rate limit says Telegram could not
 *   accept the message right now, not that the payload is
 *   poison;
 * - non-retryable statuses are the fail-closed messages —
 *   every other non-2xx status, including 400, 401, 403, and
 *   404 (unknown chat, bot blocked, invalid body): retrying
 *   them burns the retry budget for nothing, and rerouting
 *   them elsewhere would notify a chat the operator never
 *   chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status: it
 *   says nothing about the payload;
 * - a missing client or a missing chat id throws
 *   `TelegramSinkConfigError`, which `classifyFailure` maps to
 *   `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no subject, key, or trace id. */
export const TELEGRAM_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const TELEGRAM_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol (including the Bot API URL,
 * the bot token in that URL, and the status it returns);
 * this shape is the relay-side contract it must honour. The
 * token deliberately appears nowhere here: the client holds
 * it, so it cannot leak through a sink log or a dry run.
 */
export interface TelegramPostRequest {
  /** Target chat id, exactly as configured. */
  chatId: string;
  /** The derived message text (summary, plus an opted-in payload snippet). */
  text: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse Telegram's response body.
 */
export interface TelegramPostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
}

/**
 * The injected Telegram Bot API client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one message per call, wrapping
 * `chatId`/`text` into a Bot API `sendMessage` call with the
 * bot token it holds.
 */
export interface TelegramClient {
  post(request: TelegramPostRequest): Promise<TelegramPostResponse>;
}

/**
 * Configuration for one Telegram sink. The client is injected:
 * without one, `send()` throws `TelegramSinkConfigError` (dry
 * runs excepted — they need no client at all). A missing chat
 * id is likewise a config error at send time (dry runs
 * excepted): there is no per-record channel to fall back to.
 */
export interface TelegramSinkConfig {
  /**
   * Target chat id, e.g. `"-1001234567890"` for a group or
   * `"@channel"` for a channel username. Kept as a string so
   * negative group ids survive exactly. Must be a non-empty
   * string, free of NUL and whitespace, when set; a missing
   * chat id throws `TelegramSinkConfigError` at send time,
   * never a silent no-op.
   */
  chatId?: string;
  /**
   * The Telegram Bot API client to deliver through. Injected,
   * never bundled: the operator's client adapter implements
   * `TelegramClient` and holds the bot token. Required for
   * real sends; a missing client is a config error, not a
   * silent no-op.
   */
  client?: TelegramClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including text derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The chat id and client are not required in dry-run mode,
   * mirroring the sibling sinks' dry-run exemption.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the message text appends the
   * event body verbatim inside a fenced code block, truncated
   * to `payloadMaxChars` characters (see below). When `false`
   * or absent, the message carries the summary only — the
   * default, so event bodies (which routinely carry PII) never
   * leak into a chat unless the operator explicitly asks for
   * them.
   */
  includePayload?: boolean;
  /**
   * Truncation limit for an opted-in payload snippet, in
   * characters (default 2000). Only meaningful with
   * `includePayload`; the truncation is unconditional when
   * the opt-in is set, so an opted-in body cannot flood a
   * chat. Must be a positive integer when set.
   */
  payloadMaxChars?: number;
}

/** One event to notify about. */
export interface TelegramRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Text-derivation source, first priority: the event's
   * subject, when set and non-empty. Falls through to `key`,
   * then `traceId`.
   */
  subject?: string;
  /**
   * Text-derivation source, second priority: the event's key
   * (e.g. aggregate id).
   */
  key?: string;
  /**
   * Text-derivation source, last priority: the trace id.
   */
  traceId?: string;
}

/** One record as it goes to the client (text derived). */
export interface TelegramResolvedRecord {
  /** Target chat id, exactly as configured. */
  chatId: string;
  /** The derived message text (summary, plus an opted-in payload snippet). */
  text: string;
  /** Index into the caller's original `records` array. */
  index: number;
}

/** One failed message, with its retry lane already mapped. */
export interface TelegramFailedRecord {
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
   * non-2xx status is a fail-closed message (unknown chat,
   * bot blocked, invalid body).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface TelegramSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-231). */
export interface TelegramSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Telegram send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already in their chat and are *not* in
 * `failedRecords`.
 */
export class TelegramSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: TelegramFailedRecord[];
  constructor(message: string, failedRecords: TelegramFailedRecord[]) {
    super(message);
    this.name = "TelegramSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, or the chat id is missing. A config
 * problem, not a downstream verdict, so the retry queue must
 * not burn attempts on it (`classifyFailure` maps it to
 * `non_retryable`).
 */
export class TelegramSinkConfigError extends TelegramSinkError {
  constructor(reason: string) {
    super(`telegram-sink: ${reason}`, []);
    this.name = "TelegramSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing chat id is *not* a shape error: it is a config
 * error raised at send time (`TelegramSinkConfigError`), so a
 * sink built before its chat id is known still fails closed at
 * send time rather than crashing at construction. A present
 * chat id must be a non-empty string, free of NUL and
 * whitespace; the `client`, when present, must expose `post`.
 */
export function assertValidTelegramSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is TelegramSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  if (c.chatId !== undefined) {
    if (
      typeof c.chatId !== "string" ||
      c.chatId === "" ||
      (c.chatId as string).includes("\0") ||
      /\s/.test(c.chatId as string)
    ) {
      throw new RangeError(
        at("`chatId` must be a non-empty string, free of NUL and whitespace when set")
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
 * Derive one record's summary: the first non-empty value
 * among `subject`, `key`, and `traceId`, in that order. Falls
 * back to the generic `webhook event` summary when the record
 * carries none of the three — a notification sink must not
 * silently drop sourceless events, and the channel (not the
 * text) is the delivery contract.
 */
export function resolveTelegramSummary(record: TelegramRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return TELEGRAM_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a chat.
 */
export function truncateTelegramPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's message text: the summary, plus — only
 * under the `includePayload` opt-in — the body verbatim
 * inside a fenced code block, truncated to `payloadMaxChars`
 * (default 2000). Without the opt-in, the text is the summary
 * alone: event bodies routinely carry PII and must never leak
 * into a chat by default.
 */
export function resolveTelegramText(
  record: TelegramRecord,
  config: Pick<TelegramSinkConfig, "includePayload" | "payloadMaxChars">
): string {
  const summary = resolveTelegramSummary(record);
  if (config.includePayload !== true) {
    return summary;
  }
  const limit = config.payloadMaxChars ?? TELEGRAM_DEFAULT_PAYLOAD_MAX_CHARS;
  return `${summary}\n\`\`\`\n${truncateTelegramPayload(record.body, limit)}\n\`\`\``;
}

/**
 * Validate one record's body and resolve its send form: the
 * text derives from the record's own subject, key, or trace
 * id (plus an opted-in payload snippet). Throws `RangeError`
 * on an empty body string — even without the opt-in, the body
 * is the record's payload, and an empty record is a caller bug
 * that must fail closed, never notify as an empty message.
 */
export function resolveTelegramRecord(
  record: TelegramRecord,
  index: number,
  config: Pick<TelegramSinkConfig, "includePayload" | "payloadMaxChars">
): { text: string; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`telegram-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { text: resolveTelegramText(record, config), index };
}

/**
 * Map one Telegram POST `statusCode` onto its retry lane under
 * the WR-210 rules: 429 and every 5xx are transient and so
 * retryable — a rate limit says Telegram could not accept the
 * message right now, not that the payload is poison. Every
 * other non-2xx status (400, 401, 403, 404, and the rest) is
 * a fail-closed message: unknown chat, bot blocked, invalid
 * body, or another verdict retrying cannot change. Callers
 * only pass non-2xx statuses here; a 2xx status is a success,
 * not a failure.
 */
export function classifyTelegramRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Telegram sink (WR-231). One instance targets one chat; the
 * caller owns retry/dead-letter policy around `send()` — this
 * class performs one POST attempt per message through the
 * injected client and reports its outcome. Failures throw
 * `TelegramSinkError` carrying exactly the failed messages
 * with their retry lanes.
 */
export class TelegramSink {
  private readonly cfg: TelegramSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: TelegramSinkConfig) {
    assertValidTelegramSinkConfig(config, "TelegramSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): TelegramSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages to the configured chat, in input order.
   * Throws `TelegramSinkConfigError` when no client was
   * injected or the chat id is missing, and
   * `TelegramSinkError` when any message fails (carrying
   * exactly the failed messages with their retry lanes; both
   * counted in stats before throwing, so the counters stay
   * honest even for callers that only inspect stats).
   */
  async send(records: TelegramRecord[]): Promise<TelegramSendResult> {
    const resolved = records.map((r, i) => resolveTelegramRecord(r, i, this.cfg));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The chat
      // id and client are not required here, mirroring the
      // sibling sinks' dry-run exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new TelegramSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const chatId = this.cfg.chatId;
    if (chatId === undefined) {
      throw new TelegramSinkConfigError("no chat id configured (set `chatId` to the target chat)");
    }
    const failedRecords: TelegramFailedRecord[] = [];
    let sent = 0;
    for (const record of resolved) {
      try {
        const response = await client.post({ chatId, text: record.text });
        if (response.status >= 200 && response.status < 300) {
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyTelegramRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toTelegramFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new TelegramSinkError(
        `telegram-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toTelegramFailedRecord(err: unknown, index: number): TelegramFailedRecord {
  const failed: TelegramFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
