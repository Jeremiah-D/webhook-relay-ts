/**
 * DingTalk notification delivery sink (WR-228).
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
 * Hubs sink (WR-225) delivers to an Azure event hub, and the
 * Slack sink (WR-226) delivers to a Slack channel, this sink
 * delivers to a DingTalk group: one event is posted as one
 * text message to a configured robot webhook URL, and
 * DingTalk — not the relay — owns the group, the message id,
 * and the retention of the notification. The sinks are
 * orthogonal — queue delivery for unordered work, stream
 * delivery for AWS-ordered work, log delivery for
 * broker-native ordered work, topic-tree delivery for
 * broker-mediated fan-out, exchange delivery for
 * broker-mediated routing, durable-stream delivery for
 * replayable work, Redis-stream delivery for in-memory
 * ordered work, Pub/Sub delivery for cloud-managed fan-out,
 * Service Bus delivery for Azure-managed fan-out, EventBridge
 * delivery for rule-routed cloud events, Pulsar delivery for
 * geo-replicated partitioned topics, SNS delivery for
 * cloud-managed fan-out to many protocols at once, Event Hubs
 * delivery for Azure-managed streaming ingest, Slack delivery
 * for human notification on Slack, DingTalk delivery for
 * human notification on DingTalk — and a DingTalk delivery
 * can still be archived by the S3 offloaders like any other
 * delivery.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a DingTalk
 * group. The sink owns the relay-side concerns — webhook
 * targeting, robot authentication, message-text derivation,
 * payload-inclusion policy, per-message failure mapping — and
 * the injected client owns the wire protocol, including the
 * POST call and the status it returns.
 *
 * Wire shape — one POST per message, carried to the injected
 * client as:
 *
 *   { url: "<webhook URL with access_token (and timestamp + sign when signed)>",
 *     text: "<derived message text>" }
 *
 * The client wraps `text` into DingTalk's text-message
 * envelope (`{"msgtype":"text","text":{"content": text}}`)
 * before posting: the envelope is wire detail, not relay
 * state, so it lives with the client like Slack's
 * `{"text": ...}` envelope does.
 *
 * Webhook targeting and robot authentication — one sink
 * targets one robot webhook URL: every message goes there.
 * The access token rides the URL, not a header: DingTalk
 * authenticates robots by the `access_token` query parameter
 * (`.../robot/send?access_token=<token>`), so the sink
 * appends it to the configured base URL at send time (with
 * `&` when the base URL already carries a query string). A
 * missing access token is a config error, not a resolution
 * fallback: unlike the broker sinks, there is no per-record
 * channel to resolve to, so a sink with no token has nowhere
 * to deliver and fails closed with `DingTalkSinkConfigError`
 * at send time (dry runs excepted — they need no token at
 * all, mirroring the sibling sinks' dry-run exemption for the
 * client). A missing webhook URL is the same config error,
 * and an invalid URL — unparseable, or not `https:` — is
 * too: a notification URL must never travel over plaintext,
 * and a URL the operator cannot have meant must not be
 * posted to. The host is not pinned to oapi.dingtalk.com:
 * an operator may front the webhook with a proxy or sidecar,
 * and the sink must not second-guess that deployment.
 *
 * Signed robots — when `signSecret` is configured, the sink
 * additionally appends `timestamp` (the current epoch
 * milliseconds) and `sign` to the URL, following DingTalk's
 * documented robot-signing scheme: `sign` is the
 * URL-encoded base64 of HMAC-SHA256 over
 * `"<timestamp>\n<secret>"`, keyed by the secret. The secret
 * is configured separately from the webhook URL and the
 * access token, so rotating the signing secret never means
 * re-issuing the robot. An unsigned robot (no `signSecret`)
 * simply omits both parameters. The signature is computed
 * with Node's built-in `node:crypto` — zero new
 * dependencies.
 *
 * Message text — one line of summary, derived from the
 * event's own values, first non-empty wins: `subject`, then
 * `key`, then `traceId` — the same source chain the
 * EventBridge sink uses for its DetailType, the SNS sink
 * uses for its topic, and the Slack sink uses for its
 * message text. An event with none of the three still
 * notifies, with the generic summary `webhook event`: a
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
 * opted-in body cannot flood a group or blow past DingTalk's
 * message limits.
 *
 * Failure handling mirrors the WR-210 SQS sink's classification
 * (`src/failure.ts`), applied per message over HTTP status:
 *
 * - a non-2xx POST throws `DingTalkSinkError` carrying every
 *   failed message with its retry lane already mapped, so the
 *   caller retries exactly the failed messages;
 * - retryable statuses are the transient HTTP states — 429
 *   and every 5xx: a rate limit says DingTalk could not
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
 * - a missing client, a missing/invalid webhook URL, or a
 *   missing access token throws `DingTalkSinkConfigError`,
 *   which `classifyFailure` maps to `non_retryable` (the
 *   WR-116 rule).
 *
 * Zero new dependencies: the injected client only, plus
 * Node's built-in `node:crypto` for the signature.
 */

import { createHmac } from "node:crypto";

/** Generic summary used when an event carries no subject, key, or trace id. */
export const DINGTALK_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const DINGTALK_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol (including the status it
 * returns and the DingTalk text-message envelope); this shape
 * is the relay-side contract it must honour.
 */
export interface DingTalkWebhookPostRequest {
  /** Target robot webhook URL (base URL plus access_token, plus timestamp + sign when signed). */
  url: string;
  /** The derived message text (summary, plus an opted-in payload snippet). */
  text: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse DingTalk's response body.
 */
export interface DingTalkWebhookPostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
}

/**
 * The injected DingTalk webhook client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one message per call, wrapping
 * `text` into DingTalk's text-message envelope.
 */
export interface DingTalkWebhookClient {
  post(request: DingTalkWebhookPostRequest): Promise<DingTalkWebhookPostResponse>;
}

/**
 * Configuration for one DingTalk sink. The client is injected:
 * without one, `send()` throws `DingTalkSinkConfigError` (dry
 * runs excepted — they need no client at all). A missing or
 * invalid webhook URL, or a missing access token, is likewise
 * a config error at send time (dry runs excepted): there is
 * no per-record channel to fall back to.
 */
export interface DingTalkSinkConfig {
  /**
   * Target robot webhook base URL, e.g.
   * `https://oapi.dingtalk.com/robot/send`. The access token
   * is appended as a query parameter at send time, never
   * baked into this URL: the token and the endpoint rotate
   * independently. Must be a parseable `https:` URL at send
   * time; a missing or invalid URL throws
   * `DingTalkSinkConfigError`, never a silent no-op.
   */
  webhookUrl?: string;
  /**
   * The robot's access token, appended to the webhook URL as
   * `access_token` at send time. Required for real sends; a
   * missing token is a config error, not a silent no-op.
   */
  accessToken?: string;
  /**
   * The robot's signing secret, when the robot is a signed
   * robot. When set, `timestamp` and `sign` query parameters
   * are appended alongside `access_token` at send time (see
   * `computeDingTalkSign`). Configured separately from the
   * webhook URL and the access token, so rotating the secret
   * never means re-issuing the robot. Unset for unsigned
   * robots.
   */
  signSecret?: string;
  /**
   * The DingTalk webhook client to deliver through. Injected,
   * never bundled: the operator's client adapter implements
   * `DingTalkWebhookClient`. Required for real sends; a
   * missing client is a config error, not a silent no-op.
   */
  client?: DingTalkWebhookClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including text derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The webhook URL, access token, and client are not
   * required in dry-run mode, mirroring the sibling sinks'
   * dry-run exemption.
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
export interface DingTalkRecord {
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

/** One record as it goes to the client (text derived, URL attached). */
export interface DingTalkResolvedRecord {
  /** Target robot webhook URL (base URL plus access_token, plus timestamp + sign when signed). */
  url: string;
  /** The derived message text (summary, plus an opted-in payload snippet). */
  text: string;
  /** Index into the caller's original `records` array. */
  index: number;
}

/** One failed message, with its retry lane already mapped. */
export interface DingTalkFailedRecord {
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
export interface DingTalkSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-228). */
export interface DingTalkSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for DingTalk send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already in their group and are *not* in
 * `failedRecords`.
 */
export class DingTalkSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: DingTalkFailedRecord[];
  constructor(message: string, failedRecords: DingTalkFailedRecord[]) {
    super(message);
    this.name = "DingTalkSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, the webhook URL is missing or
 * invalid, or the access token is missing. A config problem,
 * not a downstream verdict, so the retry queue must not burn
 * attempts on it (`classifyFailure` maps it to
 * `non_retryable`).
 */
export class DingTalkSinkConfigError extends DingTalkSinkError {
  constructor(reason: string) {
    super(`dingtalk-sink: ${reason}`, []);
    this.name = "DingTalkSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing webhook URL or access token is *not* a shape error:
 * it is a config error raised at send time
 * (`DingTalkSinkConfigError`), so a sink built before its
 * robot credentials are known still fails closed at send time
 * rather than crashing at construction. A present webhook URL,
 * access token, or signing secret must be a non-empty string,
 * free of NUL and whitespace; the `https:` parse check happens
 * at send time, so an invalid URL surfaces as the same config
 * error.
 */
export function assertValidDingTalkSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is DingTalkSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  for (const field of ["webhookUrl", "accessToken", "signSecret"] as const) {
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
export function isValidDingTalkWebhookUrl(url: string): boolean {
  try {
    return new URL(url).protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * Compute a signed robot's `sign` parameter for a given
 * millisecond `timestamp`: the base64 of HMAC-SHA256 over
 * `"<timestamp>\n<secret>"`, keyed by the secret — DingTalk's
 * documented robot-signing scheme. Pure, so tests pin the
 * exact bytes without a clock. The caller URL-encodes the
 * result when appending it to the webhook URL (base64 can
 * contain `+`, `/`, and `=`).
 */
export function computeDingTalkSign(signSecret: string, timestamp: number): string {
  return createHmac("sha256", signSecret)
    .update(`${timestamp}\n${signSecret}`, "utf8")
    .digest("base64");
}

/**
 * Build the POST URL for one send: the base webhook URL plus
 * `access_token`, plus `timestamp` and `sign` when the robot
 * is signed. Appends with `&` when the base URL already
 * carries a query string, `?` otherwise. The caller supplies
 * `nowMs` (the current epoch milliseconds) so the timestamp
 * is the send's own moment; `send()` passes `Date.now()`.
 */
export function buildDingTalkWebhookUrl(
  webhookUrl: string,
  accessToken: string,
  signSecret: string | undefined,
  nowMs: number
): string {
  const separator = webhookUrl.includes("?") ? "&" : "?";
  let url = `${webhookUrl}${separator}access_token=${encodeURIComponent(accessToken)}`;
  if (signSecret !== undefined) {
    const sign = computeDingTalkSign(signSecret, nowMs);
    url += `&timestamp=${nowMs}&sign=${encodeURIComponent(sign)}`;
  }
  return url;
}

/**
 * Derive one record's summary: the first non-empty value
 * among `subject`, `key`, and `traceId`, in that order. Falls
 * back to the generic `webhook event` summary when the record
 * carries none of the three — a notification sink must not
 * silently drop sourceless events, and the channel (not the
 * text) is the delivery contract.
 */
export function resolveDingTalkSummary(record: DingTalkRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return DINGTALK_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a group.
 */
export function truncateDingTalkPayload(body: string, limit: number): string {
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
export function resolveDingTalkText(
  record: DingTalkRecord,
  config: Pick<DingTalkSinkConfig, "includePayload" | "payloadMaxChars">
): string {
  const summary = resolveDingTalkSummary(record);
  if (config.includePayload !== true) {
    return summary;
  }
  const limit = config.payloadMaxChars ?? DINGTALK_DEFAULT_PAYLOAD_MAX_CHARS;
  return `${summary}\n\`\`\`\n${truncateDingTalkPayload(record.body, limit)}\n\`\`\``;
}

/**
 * Validate one record's body and resolve its send form: the
 * text derives from the record's own subject, key, or trace
 * id (plus an opted-in payload snippet). Throws `RangeError`
 * on an empty body string — even without the opt-in, the body
 * is the record's payload, and an empty record is a caller bug
 * that must fail closed, never notify as an empty message.
 */
export function resolveDingTalkRecord(
  record: DingTalkRecord,
  index: number,
  config: Pick<DingTalkSinkConfig, "includePayload" | "payloadMaxChars">
): { text: string; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`dingtalk-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { text: resolveDingTalkText(record, config), index };
}

/**
 * Map one DingTalk POST `statusCode` onto its retry lane under
 * the WR-210 rules: 429 and every 5xx are transient and so
 * retryable — a rate limit says DingTalk could not accept the
 * message right now, not that the payload is poison. Every
 * other non-2xx status (400, 401, 403, 404, and the rest) is
 * a fail-closed message: unknown robot, invalid body, or
 * another verdict retrying cannot change. Callers only pass
 * non-2xx statuses here; a 2xx status is a success, not a
 * failure.
 */
export function classifyDingTalkRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * DingTalk sink (WR-228). One instance targets one robot
 * webhook URL; the caller owns retry/dead-letter policy
 * around `send()` — this class performs one POST attempt per
 * message through the injected client and reports its
 * outcome. Failures throw `DingTalkSinkError` carrying exactly
 * the failed messages with their retry lanes.
 */
export class DingTalkSink {
  private readonly cfg: DingTalkSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: DingTalkSinkConfig) {
    assertValidDingTalkSinkConfig(config, "DingTalkSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): DingTalkSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages to the configured robot webhook URL, in
   * input order. Throws `DingTalkSinkConfigError` when no
   * client was injected, the webhook URL is missing or
   * invalid, or the access token is missing, and
   * `DingTalkSinkError` when any message fails (carrying
   * exactly the failed messages with their retry lanes; both
   * counted in stats before throwing, so the counters stay
   * honest even for callers that only inspect stats).
   */
  async send(records: DingTalkRecord[]): Promise<DingTalkSendResult> {
    const resolved = records.map((r, i) => resolveDingTalkRecord(r, i, this.cfg));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The URL,
      // token, and client are not required here, mirroring the
      // sibling sinks' dry-run exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new DingTalkSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const url = this.cfg.webhookUrl;
    if (url === undefined || !isValidDingTalkWebhookUrl(url)) {
      throw new DingTalkSinkConfigError(
        "no valid webhook URL configured (set `webhookUrl` to a parseable `https:` URL)"
      );
    }
    const accessToken = this.cfg.accessToken;
    if (accessToken === undefined) {
      throw new DingTalkSinkConfigError("no access token configured (set `accessToken` in the sink config)");
    }
    const postUrl = buildDingTalkWebhookUrl(url, accessToken, this.cfg.signSecret, Date.now());
    const failedRecords: DingTalkFailedRecord[] = [];
    let sent = 0;
    for (const record of resolved) {
      try {
        const response = await client.post({ url: postUrl, text: record.text });
        if (response.status >= 200 && response.status < 300) {
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyDingTalkRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toDingTalkFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new DingTalkSinkError(
        `dingtalk-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toDingTalkFailedRecord(err: unknown, index: number): DingTalkFailedRecord {
  const failed: DingTalkFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
