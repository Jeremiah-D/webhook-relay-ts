/**
 * Rocket.Chat notification delivery sink (WR-238).
 *
 * Some downstreams are not queues, streams, or topics at all:
 * they are a human's chat channel. Where the Mattermost sink
 * (WR-237) delivers to a Mattermost channel, this sink delivers
 * to a Rocket.Chat channel: one event is posted as one message
 * to a configured incoming webhook URL, and Rocket.Chat — not
 * the relay — owns the channel, the message id, and the
 * retention of the notification.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Rocket.Chat
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
 *     text: "<derived message text>" }
 *
 * The client wraps `text` into Rocket.Chat's webhook message
 * body (`{"text": text}`) before posting. Rocket.Chat
 * authenticates an incoming webhook by the URL itself (the
 * id and token are embedded in its path, e.g.
 * `https://chat.example.com/hooks/<id>/<token>`), so — like
 * Mattermost, Teams, Feishu, WeCom, and Google Chat, and
 * unlike DingTalk — no token is appended at send time: the
 * configured URL is posted to verbatim. Nothing about the
 * token is ever extracted, logged, or carried separately from
 * the URL: the URL is the credential, and treating it as one
 * opaque value means rotating the webhook never means
 * changing sink code.
 *
 * No channel or username override is ever set: the target
 * channel is bound to the webhook on the Rocket.Chat server,
 * and the URL is the target. A sink that overrode the channel
 * could notify a channel the operator never chose; the
 * relay-side request carries only the URL and the text, and
 * the server-side binding decides where the message lands.
 *
 * Webhook targeting — one sink targets one webhook URL:
 * every message goes there. A missing webhook URL is a config
 * error, not a resolution fallback: unlike the broker sinks,
 * there is no per-record channel to resolve to, so a sink with
 * no URL has nowhere to deliver and fails closed with
 * `RocketChatSinkConfigError` at send time (dry runs excepted —
 * they need no URL at all, mirroring the sibling sinks'
 * dry-run exemption for the client). An invalid URL —
 * unparseable, or not `https:` — is the same config error: a
 * notification URL must never travel over plaintext, and a
 * URL the operator cannot have meant must not be posted to.
 * The host is not pinned to any Rocket.Chat deployment: an
 * operator may self-host Rocket.Chat or front the webhook
 * with a proxy or sidecar, and the sink must not
 * second-guess that deployment.
 *
 * Message text — one line of summary, derived from the
 * event's own values, first non-empty wins: `subject`, then
 * `key`, then `traceId` — the same source chain the
 * EventBridge sink uses for its DetailType, the SNS sink
 * uses for its topic, and the Slack, DingTalk, Feishu,
 * Telegram, Teams, WeCom, Google Chat, and Mattermost sinks
 * use for their message text. An event with none of the three
 * still notifies, with the generic summary `webhook event`: a
 * notification sink that silently dropped sourceless events
 * would hide exactly the deliveries an operator most needs to
 * see, and the channel — not the text — is the delivery
 * contract here, so no invented channel is at stake.
 *
 * Payload inclusion — by default the message carries the
 * summary only, never the full payload: event bodies routinely
 * carry PII, secrets, or customer data, and a chat channel is
 * a far wider audience than a queue or a stream. Opting into
 * `includePayload` appends the body verbatim inside a fenced
 * code block, truncated to `payloadMaxChars` characters
 * (default 2000) with a truncation marker — the opt-in is
 * explicit, and the truncation is unconditional, so even an
 * opted-in body cannot flood a channel or blow past
 * Rocket.Chat's message limits.
 *
 * Failure handling mirrors the WR-210 SQS sink's classification
 * (`src/failure.ts`), applied per message over HTTP status:
 *
 * - a non-2xx POST throws `RocketChatSinkError` carrying every
 *   failed message with its retry lane already mapped, so the
 *   caller retries exactly the failed messages;
 * - retryable statuses are the transient HTTP states — 429
 *   and every 5xx: a rate limit says Rocket.Chat could not
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
 *   `RocketChatSinkConfigError`, which `classifyFailure` maps to
 *   `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no subject, key, or trace id. */
export const ROCKETCHAT_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const ROCKETCHAT_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol (including the status it
 * returns and the RocketChat message envelope); this shape is
 * the relay-side contract it must honour. The webhook URL is
 * posted verbatim: RocketChat authenticates by the token in
 * its path, so no token is ever appended or extracted, and no
 * channel or username override is ever set — the channel is
 * bound to the webhook on the server.
 */
export interface RocketChatWebhookPostRequest {
  /** Target webhook URL, exactly as configured. */
  url: string;
  /** The derived message text (summary, plus an opted-in payload snippet). */
  text: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse RocketChat's response body.
 */
export interface RocketChatWebhookPostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
}

/**
 * The injected RocketChat webhook client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one message per call, wrapping
 * `text` into RocketChat's `{"text": ...}` message body, with
 * no channel or username override.
 */
export interface RocketChatWebhookClient {
  post(request: RocketChatWebhookPostRequest): Promise<RocketChatWebhookPostResponse>;
}

/**
 * Configuration for one RocketChat sink. The client is injected:
 * without one, `send()` throws `RocketChatSinkConfigError` (dry
 * runs excepted — they need no client at all). A missing or
 * invalid webhook URL is likewise a config error at send
 * time (dry runs excepted): there is no per-record channel to
 * fall back to.
 */
export interface RocketChatSinkConfig {
  /**
   * Target webhook URL, e.g.
   * `https://chat.example.com/hooks/<id>/<token>`.
   * Posted to verbatim: RocketChat authenticates webhooks by
   * the token in the path, so no token is appended at
   * send time. Must be a parseable `https:` URL at send
   * time; a missing or invalid URL throws
   * `RocketChatSinkConfigError`, never a silent no-op.
   */
  webhookUrl?: string;
  /**
   * The RocketChat webhook client to deliver through. Injected,
   * never bundled: the operator's client adapter implements
   * `RocketChatWebhookClient`. Required for real sends; a
   * missing client is a config error, not a silent no-op.
   */
  client?: RocketChatWebhookClient;
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
export interface RocketChatRecord {
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
export interface RocketChatResolvedRecord {
  /** Target webhook URL, exactly as configured. */
  url: string;
  /** The derived message text (summary, plus an opted-in payload snippet). */
  text: string;
  /** Index into the caller's original `records` array. */
  index: number;
}

/** One failed message, with its retry lane already mapped. */
export interface RocketChatFailedRecord {
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
export interface RocketChatSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-238). */
export interface RocketChatSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for RocketChat send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already in their channel and are *not* in
 * `failedRecords`.
 */
export class RocketChatSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: RocketChatFailedRecord[];
  constructor(message: string, failedRecords: RocketChatFailedRecord[]) {
    super(message);
    this.name = "RocketChatSinkError";
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
export class RocketChatSinkConfigError extends RocketChatSinkError {
  constructor(reason: string) {
    super(`rocketchat-sink: ${reason}`, []);
    this.name = "RocketChatSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing webhook URL is *not* a shape error: it is a config
 * error raised at send time (`RocketChatSinkConfigError`), so a
 * sink built before its URL is known still fails closed at
 * send time rather than crashing at construction. A present
 * webhook URL must be a non-empty string, free of NUL and
 * whitespace; the `https:` parse check happens at send time,
 * so an invalid URL surfaces as the same config error.
 */
export function assertValidRocketChatSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is RocketChatSinkConfig {
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
 * The host is deliberately not pinned: an operator may
 * self-host RocketChat or front the webhook with a proxy.
 */
export function isValidRocketChatWebhookUrl(url: string): boolean {
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
export function resolveRocketChatSummary(record: RocketChatRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return ROCKETCHAT_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a channel.
 */
export function truncateRocketChatPayload(body: string, limit: number): string {
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
export function resolveRocketChatText(
  record: RocketChatRecord,
  config: Pick<RocketChatSinkConfig, "includePayload" | "payloadMaxChars">
): string {
  const summary = resolveRocketChatSummary(record);
  if (config.includePayload !== true) {
    return summary;
  }
  const limit = config.payloadMaxChars ?? ROCKETCHAT_DEFAULT_PAYLOAD_MAX_CHARS;
  return `${summary}\n\`\`\`\n${truncateRocketChatPayload(record.body, limit)}\n\`\`\``;
}

/**
 * Validate one record's body and resolve its send form: the
 * text derives from the record's own subject, key, or trace
 * id (plus an opted-in payload snippet). Throws `RangeError`
 * on an empty body string — even without the opt-in, the body
 * is the record's payload, and an empty record is a caller bug
 * that must fail closed, never notify as an empty message.
 */
export function resolveRocketChatRecord(
  record: RocketChatRecord,
  index: number,
  config: Pick<RocketChatSinkConfig, "includePayload" | "payloadMaxChars">
): { text: string; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`rocketchat-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { text: resolveRocketChatText(record, config), index };
}

/**
 * Map one RocketChat POST `statusCode` onto its retry lane under
 * the WR-210 rules: 429 and every 5xx are transient and so
 * retryable — a rate limit says RocketChat could not accept the
 * message right now, not that the payload is poison. Every
 * other non-2xx status (400, 401, 403, 404, and the rest) is
 * a fail-closed message: unknown webhook, invalid body, or
 * another verdict retrying cannot change. Callers only pass
 * non-2xx statuses here; a 2xx status is a success, not a
 * failure.
 */
export function classifyRocketChatRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * RocketChat sink (WR-238). One instance targets one webhook
 * URL; the caller owns retry/dead-letter policy around
 * `send()` — this class performs one POST attempt per
 * message through the injected client and reports its
 * outcome. Failures throw `RocketChatSinkError` carrying exactly
 * the failed messages with their retry lanes.
 */
export class RocketChatSink {
  private readonly cfg: RocketChatSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: RocketChatSinkConfig) {
    assertValidRocketChatSinkConfig(config, "RocketChatSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): RocketChatSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages to the configured webhook URL, in input
   * order. Throws `RocketChatSinkConfigError` when no client was
   * injected or the webhook URL is missing or invalid, and
   * `RocketChatSinkError` when any message fails (carrying
   * exactly the failed messages with their retry lanes; both
   * counted in stats before throwing, so the counters stay
   * honest even for callers that only inspect stats).
   */
  async send(records: RocketChatRecord[]): Promise<RocketChatSendResult> {
    const resolved = records.map((r, i) => resolveRocketChatRecord(r, i, this.cfg));
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
      throw new RocketChatSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const url = this.cfg.webhookUrl;
    if (url === undefined || !isValidRocketChatWebhookUrl(url)) {
      throw new RocketChatSinkConfigError(
        "no valid webhook URL configured (set `webhookUrl` to a parseable `https:` URL)"
      );
    }
    const failedRecords: RocketChatFailedRecord[] = [];
    let sent = 0;
    for (const record of resolved) {
      try {
        const response = await client.post({ url, text: record.text });
        if (response.status >= 200 && response.status < 300) {
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyRocketChatRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toRocketChatFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new RocketChatSinkError(
        `rocketchat-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toRocketChatFailedRecord(err: unknown, index: number): RocketChatFailedRecord {
  const failed: RocketChatFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
