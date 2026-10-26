/**
 * Feishu (Lark) notification delivery sink (WR-229).
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
 * sink (WR-226) delivers to a Slack channel, and the DingTalk
 * sink (WR-228) delivers to a DingTalk group, this sink
 * delivers to a Feishu (Lark) group: one event is posted as one
 * text message to a configured robot webhook URL, and Feishu —
 * not the relay — owns the group, the message id, and the
 * retention of the notification. The sinks are orthogonal —
 * queue delivery for unordered work, stream delivery for
 * AWS-ordered work, log delivery for broker-native ordered work,
 * topic-tree delivery for broker-mediated fan-out, exchange
 * delivery for broker-mediated routing, durable-stream delivery
 * for replayable work, Redis-stream delivery for in-memory
 * ordered work, Pub/Sub delivery for cloud-managed fan-out,
 * Service Bus delivery for Azure-managed fan-out, EventBridge
 * delivery for rule-routed cloud events, Pulsar delivery for
 * geo-replicated partitioned topics, SNS delivery for
 * cloud-managed fan-out to many protocols at once, Event Hubs
 * delivery for Azure-managed streaming ingest, Slack delivery
 * for human notification on Slack, DingTalk delivery for
 * human notification on DingTalk, Feishu delivery for human
 * notification on Feishu — and a Feishu delivery can still be
 * archived by the S3 offloaders like any other delivery.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Feishu
 * group. The sink owns the relay-side concerns — webhook
 * targeting, robot authentication, message-text derivation,
 * payload-inclusion policy, per-message failure mapping — and
 * the injected client owns the wire protocol, including the
 * POST call and the status it returns.
 *
 * Wire shape — one POST per message, carried to the injected
 * client as:
 *
 *   { url: "<configured webhook URL>",
 *     text: "<derived message text>",
 *     timestamp?: "<epoch seconds, signed robots only>",
 *     sign?: "<base64 HMAC-SHA256 signature, signed robots only>" }
 *
 * The client wraps `text` into Feishu's text-message envelope
 * (`{"msg_type":"text","content":{"text": text}}`) before
 * posting, and — for a signed robot — adds `timestamp` and
 * `sign` to the same JSON body: the envelope and the signature
 * placement are wire detail, not relay state, so they live
 * with the client like DingTalk's `{"msgtype":"text",...}`
 * envelope does.
 *
 * Webhook targeting and robot authentication — one sink
 * targets one robot webhook URL: every message goes there.
 * Feishu authenticates robots by the webhook id in the URL
 * path (`.../bot/v2/hook/<id>`), so unlike DingTalk there is
 * no access token to append at send time: the configured URL
 * is posted to verbatim. A missing webhook URL is a config
 * error, not a resolution fallback: unlike the broker sinks,
 * there is no per-record channel to resolve to, so a sink with
 * no URL has nowhere to deliver and fails closed with
 * `FeishuSinkConfigError` at send time (dry runs excepted —
 * they need no URL at all, mirroring the sibling sinks'
 * dry-run exemption for the client). An invalid URL —
 * unparseable, or not `https:` — is the same config error: a
 * notification URL must never travel over plaintext, and a
 * URL the operator cannot have meant must not be posted to.
 * The host is not pinned to open.feishu.cn: an operator may
 * front the webhook with a proxy or sidecar, and the sink
 * must not second-guess that deployment.
 *
 * Signed robots — when `signSecret` is configured, the sink
 * additionally computes `timestamp` (the current epoch
 * *seconds*, not milliseconds — Feishu's documented scheme
 * counts seconds, and a millisecond timestamp fails its
 * signature check) and `sign` for every message, following
 * Feishu's documented robot-signing scheme: `sign` is the
 * base64 of HMAC-SHA256 over `"<timestamp>\n<secret>"`,
 * keyed by the secret. The secret is configured separately
 * from the webhook URL, so rotating the signing secret never
 * means re-issuing the robot. An unsigned robot (no
 * `signSecret`) simply omits both fields. The signature is
 * computed with Node's built-in `node:crypto` — zero new
 * dependencies. Unlike DingTalk, the signature rides in the
 * JSON body, not the URL: putting it in the query string
 * would not authenticate a Feishu robot at all.
 *
 * Message text — one line of summary, derived from the
 * event's own values, first non-empty wins: `subject`, then
 * `key`, then `traceId` — the same source chain the
 * EventBridge sink uses for its DetailType, the SNS sink
 * uses for its topic, and the Slack and DingTalk sinks use
 * for their message text. An event with none of the three
 * still notifies, with the generic summary `webhook event`: a
 * notification sink that silently dropped sourceless events
 * would hide exactly the deliveries an operator most needs to
 * see, and the channel — not the text — is the delivery
 * contract here, so no invented channel is at stake.
 *
 * Payload inclusion — by default the message carries the
 * summary only, never the full payload: event bodies routinely
 * carry PII, secrets, or customer data, and a chat group is
 * a far wider audience than a queue or a stream. Opting into
 * `includePayload` appends the body verbatim inside a fenced
 * code block, truncated to `payloadMaxChars` characters
 * (default 2000) with a truncation marker — the opt-in is
 * explicit, and the truncation is unconditional, so even an
 * opted-in body cannot flood a group or blow past Feishu's
 * message limits.
 *
 * Failure handling mirrors the WR-210 SQS sink's classification
 * (`src/failure.ts`), applied per message over HTTP status:
 *
 * - a non-2xx POST throws `FeishuSinkError` carrying every
 *   failed message with its retry lane already mapped, so the
 *   caller retries exactly the failed messages;
 * - retryable statuses are the transient HTTP states — 429
 *   and every 5xx: a rate limit says Feishu could not
 *   accept the message right now, not that the payload is
 *   poison;
 * - non-retryable statuses are the fail-closed messages —
 *   every other non-2xx status, including 400, 401, 403, and
 *   404 (unknown robot, invalid body): retrying them burns
 *   the retry budget for nothing, and rerouting them
 *   elsewhere would notify a group the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status: it
 *   says nothing about the payload;
 * - a missing client or a missing/invalid webhook URL throws
 *   `FeishuSinkConfigError`, which `classifyFailure` maps to
 *   `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only, plus
 * Node's built-in `node:crypto` for the signature.
 */

import { createHmac } from "node:crypto";

/** Generic summary used when an event carries no subject, key, or trace id. */
export const FEISHU_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const FEISHU_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol (including the status it
 * returns and the Feishu text-message envelope); this shape
 * is the relay-side contract it must honour. For a signed
 * robot the client adds `timestamp` and `sign` to the JSON
 * body alongside the envelope; for an unsigned robot both
 * are absent.
 */
export interface FeishuWebhookPostRequest {
  /** Target robot webhook URL, exactly as configured. */
  url: string;
  /** The derived message text (summary, plus an opted-in payload snippet). */
  text: string;
  /**
   * Epoch seconds at send time, signed robots only: the
   * client puts this in the JSON body as `timestamp`.
   * Absent for unsigned robots.
   */
  timestamp?: string;
  /**
   * Base64 HMAC-SHA256 signature over
   * `"<timestamp>\n<signSecret>"`, signed robots only: the
   * client puts this in the JSON body as `sign`. Absent for
   * unsigned robots.
   */
  sign?: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse Feishu's response body.
 */
export interface FeishuWebhookPostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
}

/**
 * The injected Feishu webhook client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one message per call, wrapping
 * `text` into Feishu's text-message envelope and — for a
 * signed robot — adding `timestamp` and `sign` to the body.
 */
export interface FeishuWebhookClient {
  post(request: FeishuWebhookPostRequest): Promise<FeishuWebhookPostResponse>;
}

/**
 * Configuration for one Feishu sink. The client is injected:
 * without one, `send()` throws `FeishuSinkConfigError` (dry
 * runs excepted — they need no client at all). A missing or
 * invalid webhook URL is likewise a config error at send
 * time (dry runs excepted): there is no per-record channel to
 * fall back to.
 */
export interface FeishuSinkConfig {
  /**
   * Target robot webhook URL, e.g.
   * `https://open.feishu.cn/open-apis/bot/v2/hook/<id>`.
   * Posted to verbatim: Feishu authenticates robots by the
   * webhook id in the path, so no token is appended at send
   * time. Must be a parseable `https:` URL at send time; a
   * missing or invalid URL throws `FeishuSinkConfigError`,
   * never a silent no-op.
   */
  webhookUrl?: string;
  /**
   * The robot's signing secret, when the robot is a signed
   * robot. When set, `timestamp` and `sign` are computed per
   * message (see `computeFeishuSign`) and handed to the
   * client for the JSON body. Configured separately from
   * the webhook URL, so rotating the secret never means
   * re-issuing the robot. Unset for unsigned robots.
   */
  signSecret?: string;
  /**
   * The Feishu webhook client to deliver through. Injected,
   * never bundled: the operator's client adapter implements
   * `FeishuWebhookClient`. Required for real sends; a
   * missing client is a config error, not a silent no-op.
   */
  client?: FeishuWebhookClient;
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
   * leak into a chat group unless the operator explicitly
   * asks for them.
   */
  includePayload?: boolean;
  /**
   * Truncation limit for an opted-in payload snippet, in
   * characters (default 2000). Only meaningful with
   * `includePayload`; the truncation is unconditional when
   * the opt-in is set, so an opted-in body cannot flood a
   * group. Must be a positive integer when set.
   */
  payloadMaxChars?: number;
}

/** One event to notify about. */
export interface FeishuRecord {
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

/** One record as it goes to the client (text derived, signature attached when signed). */
export interface FeishuResolvedRecord {
  /** Target robot webhook URL, exactly as configured. */
  url: string;
  /** The derived message text (summary, plus an opted-in payload snippet). */
  text: string;
  /** Epoch seconds at send time, signed robots only. */
  timestamp?: string;
  /** Base64 signature, signed robots only. */
  sign?: string;
  /** Index into the caller's original `records` array. */
  index: number;
}

/** One failed message, with its retry lane already mapped. */
export interface FeishuFailedRecord {
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
   * non-2xx status is a fail-closed message (unknown robot,
   * invalid body).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface FeishuSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-229). */
export interface FeishuSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Feishu send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already in their group and are *not* in
 * `failedRecords`.
 */
export class FeishuSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: FeishuFailedRecord[];
  constructor(message: string, failedRecords: FeishuFailedRecord[]) {
    super(message);
    this.name = "FeishuSinkError";
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
export class FeishuSinkConfigError extends FeishuSinkError {
  constructor(reason: string) {
    super(`feishu-sink: ${reason}`, []);
    this.name = "FeishuSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing webhook URL is *not* a shape error: it is a config
 * error raised at send time (`FeishuSinkConfigError`), so a
 * sink built before its URL is known still fails closed at
 * send time rather than crashing at construction. A present
 * webhook URL or signing secret must be a non-empty string,
 * free of NUL and whitespace; the `https:` parse check happens
 * at send time, so an invalid URL surfaces as the same config
 * error.
 */
export function assertValidFeishuSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is FeishuSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  for (const field of ["webhookUrl", "signSecret"] as const) {
    if (c[field] !== undefined) {
      if (
        typeof c[field] !== "string" ||
        c[field] === "" ||
        (c[field] as string).includes("\0") ||
        /\s/.test(c[field] as string)
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
 * True when a webhook URL is usable: parseable, and `https:`.
 * A notification URL must never travel over plaintext, and a
 * URL the operator cannot have meant must not be posted to.
 * The host is deliberately not pinned: an operator may front
 * the webhook with a proxy or sidecar.
 */
export function isValidFeishuWebhookUrl(url: string): boolean {
  try {
    return new URL(url).protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * Compute a signed robot's `sign` for a given epoch-seconds
 * `timestamp`: the base64 of HMAC-SHA256 over
 * `"<timestamp>\n<secret>"`, keyed by the secret — Feishu's
 * documented robot-signing scheme. Pure, so tests pin the
 * exact bytes without a clock. Note the seconds unit: the
 * same scheme as DingTalk's, but Feishu counts seconds where
 * DingTalk counts milliseconds — passing a millisecond value
 * here fails Feishu's signature check.
 */
export function computeFeishuSign(signSecret: string, timestampSeconds: number): string {
  return createHmac("sha256", signSecret)
    .update(`${timestampSeconds}\n${signSecret}`, "utf8")
    .digest("base64");
}

/**
 * Derive one record's summary: the first non-empty value
 * among `subject`, `key`, and `traceId`, in that order. Falls
 * back to the generic `webhook event` summary when the record
 * carries none of the three — a notification sink must not
 * silently drop sourceless events, and the channel (not the
 * text) is the delivery contract.
 */
export function resolveFeishuSummary(record: FeishuRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return FEISHU_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a group.
 */
export function truncateFeishuPayload(body: string, limit: number): string {
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
 * into a chat group by default.
 */
export function resolveFeishuText(
  record: FeishuRecord,
  config: Pick<FeishuSinkConfig, "includePayload" | "payloadMaxChars">
): string {
  const summary = resolveFeishuSummary(record);
  if (config.includePayload !== true) {
    return summary;
  }
  const limit = config.payloadMaxChars ?? FEISHU_DEFAULT_PAYLOAD_MAX_CHARS;
  return `${summary}\n\`\`\`\n${truncateFeishuPayload(record.body, limit)}\n\`\`\``;
}

/**
 * Validate one record's body and resolve its send form: the
 * text derives from the record's own subject, key, or trace
 * id (plus an opted-in payload snippet). Throws `RangeError`
 * on an empty body string — even without the opt-in, the body
 * is the record's payload, and an empty record is a caller bug
 * that must fail closed, never notify as an empty message.
 */
export function resolveFeishuRecord(
  record: FeishuRecord,
  index: number,
  config: Pick<FeishuSinkConfig, "includePayload" | "payloadMaxChars">
): { text: string; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`feishu-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { text: resolveFeishuText(record, config), index };
}

/**
 * Map one Feishu POST `statusCode` onto its retry lane under
 * the WR-210 rules: 429 and every 5xx are transient and so
 * retryable — a rate limit says Feishu could not accept the
 * message right now, not that the payload is poison. Every
 * other non-2xx status (400, 401, 403, 404, and the rest) is
 * a fail-closed message: unknown robot, invalid body, or
 * another verdict retrying cannot change. Callers only pass
 * non-2xx statuses here; a 2xx status is a success, not a
 * failure.
 */
export function classifyFeishuRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Feishu sink (WR-229). One instance targets one robot
 * webhook URL; the caller owns retry/dead-letter policy
 * around `send()` — this class performs one POST attempt per
 * message through the injected client and reports its
 * outcome. Failures throw `FeishuSinkError` carrying exactly
 * the failed messages with their retry lanes.
 */
export class FeishuSink {
  private readonly cfg: FeishuSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: FeishuSinkConfig) {
    assertValidFeishuSinkConfig(config, "FeishuSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): FeishuSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages to the configured robot webhook URL, in
   * input order. Throws `FeishuSinkConfigError` when no
   * client was injected or the webhook URL is missing or
   * invalid, and `FeishuSinkError` when any message fails
   * (carrying exactly the failed messages with their retry
   * lanes; both counted in stats before throwing, so the
   * counters stay honest even for callers that only inspect
   * stats). For a signed robot every request carries the
   * same send-time `timestamp` (epoch seconds) and `sign`,
   * computed once per `send()` call.
   */
  async send(records: FeishuRecord[]): Promise<FeishuSendResult> {
    const resolved = records.map((r, i) => resolveFeishuRecord(r, i, this.cfg));
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
      throw new FeishuSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const url = this.cfg.webhookUrl;
    if (url === undefined || !isValidFeishuWebhookUrl(url)) {
      throw new FeishuSinkConfigError(
        "no valid webhook URL configured (set `webhookUrl` to a parseable `https:` URL)"
      );
    }
    const signSecret = this.cfg.signSecret;
    const timestamp =
      signSecret === undefined ? undefined : String(Math.floor(Date.now() / 1000));
    const sign =
      signSecret === undefined || timestamp === undefined
        ? undefined
        : computeFeishuSign(signSecret, Number(timestamp));
    const failedRecords: FeishuFailedRecord[] = [];
    let sent = 0;
    for (const record of resolved) {
      try {
        const response = await client.post({ url, text: record.text, timestamp, sign });
        if (response.status >= 200 && response.status < 300) {
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyFeishuRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toFeishuFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new FeishuSinkError(
        `feishu-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toFeishuFailedRecord(err: unknown, index: number): FeishuFailedRecord {
  const failed: FeishuFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
