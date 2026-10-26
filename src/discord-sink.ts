/**
 * Discord notification delivery sink (WR-232).
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
 * (WR-228) delivers to a DingTalk group, the Feishu sink
 * (WR-229) delivers to a Feishu group, and the Telegram sink
 * (WR-231) delivers to a Telegram chat, this sink delivers to
 * a Discord channel: one event is posted as one message to a
 * configured webhook URL, and Discord — not the relay — owns
 * the channel, the message id, and the retention of the
 * notification. The sinks are orthogonal — queue delivery for
 * unordered work, stream delivery for AWS-ordered work, log
 * delivery for broker-native ordered work, topic-tree delivery
 * for broker-mediated fan-out, exchange delivery for
 * broker-mediated routing, durable-stream delivery for
 * replayable work, Redis-stream delivery for in-memory ordered
 * work, Pub/Sub delivery for cloud-managed fan-out, Service Bus
 * delivery for Azure-managed fan-out, EventBridge delivery for
 * rule-routed cloud events, Pulsar delivery for geo-replicated
 * partitioned topics, SNS delivery for cloud-managed fan-out to
 * many protocols at once, Event Hubs delivery for Azure-managed
 * streaming ingest, Slack delivery for human notification on
 * Slack, DingTalk delivery for human notification on DingTalk,
 * Feishu delivery for human notification on Feishu, Telegram
 * delivery for human notification on Telegram, Discord
 * delivery for human notification on Discord — and a Discord
 * delivery can still be archived by the S3 offloaders like any
 * other delivery.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Discord
 * channel. The sink owns the relay-side concerns — webhook
 * targeting, message-text derivation, payload-inclusion
 * policy, per-message failure mapping — and the injected
 * client owns the wire protocol, including the POST call and
 * the status it returns.
 *
 * Wire shape — one POST per message, carried to the injected
 * client as:
 *
 *   { url: "<configured webhook URL>",
 *     content: "<derived message text>" }
 *
 * The client wraps `content` into Discord's webhook message
 * body (`{"content": content}`) before posting. Discord
 * authenticates webhooks by the webhook id and token in the
 * URL path (`.../webhooks/<id>/<token>`), so — like Feishu
 * and unlike DingTalk — no token is appended at send time:
 * the configured URL is posted to verbatim. Nothing about
 * the webhook token is ever extracted, logged, or carried
 * separately from the URL: the URL is the credential, and
 * treating it as one opaque value means rotating the webhook
 * never means changing sink code.
 *
 * Webhook targeting — one sink targets one webhook URL:
 * every message goes there. A missing webhook URL is a config
 * error, not a resolution fallback: unlike the broker sinks,
 * there is no per-record channel to resolve to, so a sink with
 * no URL has nowhere to deliver and fails closed with
 * `DiscordSinkConfigError` at send time (dry runs excepted —
 * they need no URL at all, mirroring the sibling sinks'
 * dry-run exemption for the client). An invalid URL —
 * unparseable, or not `https:` — is the same config error: a
 * notification URL must never travel over plaintext, and a
 * URL the operator cannot have meant must not be posted to.
 * The host is not pinned to discord.com: an operator may
 * front the webhook with a proxy or sidecar, and the sink
 * must not second-guess that deployment.
 *
 * Message text — one line of summary, derived from the
 * event's own values, first non-empty wins: `subject`, then
 * `key`, then `traceId` — the same source chain the
 * EventBridge sink uses for its DetailType, the SNS sink
 * uses for its topic, and the Slack, DingTalk, Feishu, and
 * Telegram sinks use for their message text. An event with
 * none of the three still notifies, with the generic summary
 * `webhook event`: a notification sink that silently dropped
 * sourceless events would hide exactly the deliveries an
 * operator most needs to see, and the channel — not the
 * text — is the delivery contract here, so no invented
 * channel is at stake.
 *
 * Payload inclusion — by default the message carries the
 * summary only, never the full payload: event bodies routinely
 * carry PII, secrets, or customer data, and a chat channel is
 * a far wider audience than a queue or a stream. Opting into
 * `includePayload` appends the body verbatim inside a fenced
 * code block, truncated to `payloadMaxChars` characters
 * (default 2000) with a truncation marker — the opt-in is
 * explicit, and the truncation is unconditional, so even an
 * opted-in body cannot flood a channel or blow past Discord's
 * message limits.
 *
 * Failure handling mirrors the WR-210 SQS sink's classification
 * (`src/failure.ts`), applied per message over HTTP status:
 *
 * - a non-2xx POST throws `DiscordSinkError` carrying every
 *   failed message with its retry lane already mapped, so the
 *   caller retries exactly the failed messages;
 * - retryable statuses are the transient HTTP states — 429
 *   and every 5xx: a rate limit says Discord could not
 *   accept the message right now, not that the payload is
 *   poison;
 * - non-retryable statuses are the fail-closed messages —
 *   every other non-2xx status, including 400, 401, 403, and
 *   404 (unknown webhook, invalid body): retrying them burns
 *   the retry budget for nothing, and rerouting them
 *   elsewhere would notify a channel the operator never
 *   chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status: it
 *   says nothing about the payload;
 * - a missing client or a missing/invalid webhook URL throws
 *   `DiscordSinkConfigError`, which `classifyFailure` maps to
 *   `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no subject, key, or trace id. */
export const DISCORD_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const DISCORD_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol (including the status it
 * returns and the Discord message envelope); this shape is
 * the relay-side contract it must honour. The webhook URL is
 * posted verbatim: Discord authenticates by the id/token in
 * its path, so no token is ever appended or extracted.
 */
export interface DiscordWebhookPostRequest {
  /** Target webhook URL, exactly as configured. */
  url: string;
  /** The derived message text (summary, plus an opted-in payload snippet). */
  content: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse Discord's response body.
 */
export interface DiscordWebhookPostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
}

/**
 * The injected Discord webhook client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one message per call, wrapping
 * `content` into Discord's `{"content": ...}` message body.
 */
export interface DiscordWebhookClient {
  post(request: DiscordWebhookPostRequest): Promise<DiscordWebhookPostResponse>;
}

/**
 * Configuration for one Discord sink. The client is injected:
 * without one, `send()` throws `DiscordSinkConfigError` (dry
 * runs excepted — they need no client at all). A missing or
 * invalid webhook URL is likewise a config error at send
 * time (dry runs excepted): there is no per-record channel to
 * fall back to.
 */
export interface DiscordSinkConfig {
  /**
   * Target webhook URL, e.g.
   * `https://discord.com/api/webhooks/<id>/<token>`.
   * Posted to verbatim: Discord authenticates webhooks by
   * the id/token in the path, so no token is appended at
   * send time. Must be a parseable `https:` URL at send
   * time; a missing or invalid URL throws
   * `DiscordSinkConfigError`, never a silent no-op.
   */
  webhookUrl?: string;
  /**
   * The Discord webhook client to deliver through. Injected,
   * never bundled: the operator's client adapter implements
   * `DiscordWebhookClient`. Required for real sends; a
   * missing client is a config error, not a silent no-op.
   */
  client?: DiscordWebhookClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including text derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The webhook URL and client are not required in dry-run
   * mode, mirroring the sibling sinks' dry-run exemption.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the message text appends the
   * event body verbatim inside a fenced code block, truncated
   * to `payloadMaxChars` characters (see below). When `false`
   * or absent, the message carries the summary only — the
   * default, so event bodies (which routinely carry PII) never
   * leak into a channel unless the operator explicitly asks
   * for them.
   */
  includePayload?: boolean;
  /**
   * Truncation limit for an opted-in payload snippet, in
   * characters (default 2000). Only meaningful with
   * `includePayload`; the truncation is unconditional when
   * the opt-in is set, so an opted-in body cannot flood a
   * channel. Must be a positive integer when set.
   */
  payloadMaxChars?: number;
}

/** One event to notify about. */
export interface DiscordRecord {
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
export interface DiscordResolvedRecord {
  /** Target webhook URL, exactly as configured. */
  url: string;
  /** The derived message text (summary, plus an opted-in payload snippet). */
  content: string;
  /** Index into the caller's original `records` array. */
  index: number;
}

/** One failed message, with its retry lane already mapped. */
export interface DiscordFailedRecord {
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
   * non-2xx status is a fail-closed message (unknown webhook,
   * invalid body).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface DiscordSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-232). */
export interface DiscordSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Discord send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already in their channel and are *not* in
 * `failedRecords`.
 */
export class DiscordSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: DiscordFailedRecord[];
  constructor(message: string, failedRecords: DiscordFailedRecord[]) {
    super(message);
    this.name = "DiscordSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, or the webhook URL is missing or
 * invalid. A config problem, not a downstream verdict, so the
 * retry queue must not burn attempts on it (`classifyFailure`
 * maps it to `non_retryable`).
 */
export class DiscordSinkConfigError extends DiscordSinkError {
  constructor(reason: string) {
    super(`discord-sink: ${reason}`, []);
    this.name = "DiscordSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing webhook URL is *not* a shape error: it is a config
 * error raised at send time (`DiscordSinkConfigError`), so a
 * sink built before its URL is known still fails closed at
 * send time rather than crashing at construction. A present
 * webhook URL must be a non-empty string, free of NUL and
 * whitespace; the `https:` parse check happens at send time,
 * so an invalid URL surfaces as the same config error.
 */
export function assertValidDiscordSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is DiscordSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  if (c.webhookUrl !== undefined) {
    if (
      typeof c.webhookUrl !== "string" ||
      c.webhookUrl === "" ||
      (c.webhookUrl as string).includes("\0") ||
      /\s/.test(c.webhookUrl as string)
    ) {
      throw new RangeError(
        at("`webhookUrl` must be a non-empty string, free of NUL and whitespace when set")
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
 * True when a webhook URL is usable: parseable, and `https:`.
 * A notification URL must never travel over plaintext, and a
 * URL the operator cannot have meant must not be posted to.
 * The host is deliberately not pinned: an operator may front
 * the webhook with a proxy or sidecar.
 */
export function isValidDiscordWebhookUrl(url: string): boolean {
  try {
    return new URL(url).protocol === "https:";
  } catch {
    return false;
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
export function resolveDiscordSummary(record: DiscordRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return DISCORD_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a channel.
 */
export function truncateDiscordPayload(body: string, limit: number): string {
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
 * into a channel by default.
 */
export function resolveDiscordText(
  record: DiscordRecord,
  config: Pick<DiscordSinkConfig, "includePayload" | "payloadMaxChars">
): string {
  const summary = resolveDiscordSummary(record);
  if (config.includePayload !== true) {
    return summary;
  }
  const limit = config.payloadMaxChars ?? DISCORD_DEFAULT_PAYLOAD_MAX_CHARS;
  return `${summary}\n\`\`\`\n${truncateDiscordPayload(record.body, limit)}\n\`\`\``;
}

/**
 * Validate one record's body and resolve its send form: the
 * text derives from the record's own subject, key, or trace
 * id (plus an opted-in payload snippet). Throws `RangeError`
 * on an empty body string — even without the opt-in, the body
 * is the record's payload, and an empty record is a caller bug
 * that must fail closed, never notify as an empty message.
 */
export function resolveDiscordRecord(
  record: DiscordRecord,
  index: number,
  config: Pick<DiscordSinkConfig, "includePayload" | "payloadMaxChars">
): { content: string; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`discord-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { content: resolveDiscordText(record, config), index };
}

/**
 * Map one Discord POST `statusCode` onto its retry lane under
 * the WR-210 rules: 429 and every 5xx are transient and so
 * retryable — a rate limit says Discord could not accept the
 * message right now, not that the payload is poison. Every
 * other non-2xx status (400, 401, 403, 404, and the rest) is
 * a fail-closed message: unknown webhook, invalid body, or
 * another verdict retrying cannot change. Callers only pass
 * non-2xx statuses here; a 2xx status is a success, not a
 * failure.
 */
export function classifyDiscordRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Discord sink (WR-232). One instance targets one webhook
 * URL; the caller owns retry/dead-letter policy around
 * `send()` — this class performs one POST attempt per
 * message through the injected client and reports its
 * outcome. Failures throw `DiscordSinkError` carrying exactly
 * the failed messages with their retry lanes.
 */
export class DiscordSink {
  private readonly cfg: DiscordSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: DiscordSinkConfig) {
    assertValidDiscordSinkConfig(config, "DiscordSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): DiscordSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages to the configured webhook URL, in input
   * order. Throws `DiscordSinkConfigError` when no client was
   * injected or the webhook URL is missing or invalid, and
   * `DiscordSinkError` when any message fails (carrying
   * exactly the failed messages with their retry lanes; both
   * counted in stats before throwing, so the counters stay
   * honest even for callers that only inspect stats).
   */
  async send(records: DiscordRecord[]): Promise<DiscordSendResult> {
    const resolved = records.map((r, i) => resolveDiscordRecord(r, i, this.cfg));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The URL
      // and client are not required here, mirroring the
      // sibling sinks' dry-run exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new DiscordSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const url = this.cfg.webhookUrl;
    if (url === undefined || !isValidDiscordWebhookUrl(url)) {
      throw new DiscordSinkConfigError(
        "no valid webhook URL configured (set `webhookUrl` to a parseable `https:` URL)"
      );
    }
    const failedRecords: DiscordFailedRecord[] = [];
    let sent = 0;
    for (const record of resolved) {
      try {
        const response = await client.post({ url, content: record.content });
        if (response.status >= 200 && response.status < 300) {
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyDiscordRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toDiscordFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new DiscordSinkError(
        `discord-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toDiscordFailedRecord(err: unknown, index: number): DiscordFailedRecord {
  const failed: DiscordFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
