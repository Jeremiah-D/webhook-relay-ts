/**
 * ntfy notification delivery sink (WR-241).
 *
 * Some downstreams are not queues, streams, or topics at all:
 * they are a human's phone or desktop. Where the Rocket.Chat
 * sink (WR-238) delivers to a chat channel, this sink delivers
 * to an ntfy topic: one event is posted as one notification
 * to a configured topic URL, and ntfy — not the relay — owns
 * the subscription, the delivery, and the retention of the
 * notification.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need an ntfy server.
 * The sink owns the relay-side concerns — topic targeting,
 * message-text derivation, payload-inclusion policy,
 * per-message failure mapping — and the injected client owns
 * the wire protocol, including the POST call and the status
 * it returns.
 *
 * Wire shape — one POST per notification, carried to the
 * injected client as:
 *
 *   { url: "<configured topic URL>",
 *     body: "<derived message text>" }
 *
 * The client POSTs `body` verbatim as the request body
 * (plain text, not a JSON envelope): ntfy takes the raw
 * message body as the notification text, so no envelope,
 * channel, or title header is ever set from the relay side.
 * The topic URL is posted to verbatim: ntfy authenticates
 * and routes by the URL itself (e.g.
 * `https://ntfy.sh/<topic>` or a self-hosted
 * `https://ntfy.example.com/<topic>`), so — like the
 * webhook-URL chat sinks, and unlike DingTalk — no token is
 * appended at send time: the configured URL is posted to
 * verbatim. Nothing about any credential is ever extracted,
 * logged, or carried separately from the URL: the URL is the
 * target, and treating it as one opaque value means moving
 * a topic never means changing sink code.
 *
 * No title, tag, priority, or action header is ever set:
 * the topic is the target, and the body is the message. A
 * sink that set headers the operator never chose could
 * re-prioritize or re-route a notification the operator
 * meant to be plain; the relay-side request carries only
 * the URL and the body, and the server-side subscription
 * decides how the notification is presented.
 *
 * Topic targeting — one sink targets one topic URL: every
 * message goes there. A missing topic URL is a config
 * error, not a resolution fallback: unlike the broker sinks,
 * there is no per-record topic to resolve to, so a sink with
 * no URL has nowhere to deliver and fails closed with
 * `NtfySinkConfigError` at send time (dry runs excepted —
 * they need no URL at all, mirroring the sibling sinks'
 * dry-run exemption for the client). An invalid URL —
 * unparseable, or not `https:` — is the same config error: a
 * notification URL must never travel over plaintext, and a
 * URL the operator cannot have meant must not be posted to.
 * The host is not pinned to any ntfy deployment: an
 * operator may use ntfy.sh, self-host ntfy, or front the
 * topic with a proxy or sidecar, and the sink must not
 * second-guess that deployment.
 *
 * Message text — one line of summary, derived from the
 * event's own values, first non-empty wins: `subject`, then
 * `key`, then `traceId` — the same source chain the
 * EventBridge sink uses for its DetailType, the SNS sink
 * uses for its topic, and the Slack, DingTalk, Feishu,
 * Telegram, Teams, WeCom, Google Chat, Mattermost, and
 * Rocket.Chat sinks use for their message text. An event
 * with none of the three still notifies, with the generic
 * summary `webhook event`: a notification sink that silently
 * dropped sourceless events would hide exactly the
 * deliveries an operator most needs to see, and the topic —
 * not the text — is the delivery contract here, so no
 * invented topic is at stake.
 *
 * Payload inclusion — by default the message carries the
 * summary only, never the full payload: event bodies routinely
 * carry PII, secrets, or customer data, and a push
 * notification is a far wider audience than a queue or a
 * stream. Opting into `includePayload` appends the body
 * verbatim after a blank line, truncated to
 * `payloadMaxChars` characters (default 2000) with a
 * truncation marker — the opt-in is explicit, and the
 * truncation is unconditional, so even an opted-in body
 * cannot flood a device or blow past ntfy's message limits.
 * The body is appended as plain text, not a fenced code
 * block: ntfy renders the body as-is, and a fence would be
 * noise on a phone screen.
 *
 * Failure handling mirrors the WR-210 SQS sink's classification
 * (`src/failure.ts`), applied per message over HTTP status:
 *
 * - a non-2xx POST throws `NtfySinkError` carrying every
 *   failed message with its retry lane already mapped, so the
 *   caller retries exactly the failed messages;
 * - retryable statuses are the transient HTTP states — 429
 *   and every 5xx: a rate limit says ntfy could not accept
 *   the message right now, not that the payload is poison;
 * - non-retryable statuses are the fail-closed messages —
 *   every other non-2xx status, including 400, 401, 403, and
 *   404 (unknown topic, invalid body): retrying them burns
 *   the retry budget for nothing, and rerouting them
 *   elsewhere would notify a topic the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status: it
 *   says nothing about the payload;
 * - a missing client or a missing/invalid topic URL throws
 *   `NtfySinkConfigError`, which `classifyFailure` maps to
 *   `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no subject, key, or trace id. */
export const NTFY_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const NTFY_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol (including the status it
 * returns and the request headers); this shape is the
 * relay-side contract it must honour. The topic URL is
 * posted verbatim: ntfy authenticates and routes by the URL
 * itself, so no token is ever appended or extracted, and no
 * title, tag, or priority header is ever set — the body is
 * the message, plain text, not a JSON envelope.
 */
export interface NtfyTopicPostRequest {
  /** Target topic URL, exactly as configured. */
  url: string;
  /** The derived message text (summary, plus an opted-in payload snippet). */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse ntfy's response body.
 */
export interface NtfyTopicPostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
}

/**
 * The injected ntfy topic client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one message per call, sending
 * `body` verbatim as the request body with no JSON envelope
 * and no title, tag, or priority header.
 */
export interface NtfyTopicClient {
  post(request: NtfyTopicPostRequest): Promise<NtfyTopicPostResponse>;
}

/**
 * Configuration for one ntfy sink. The client is injected:
 * without one, `send()` throws `NtfySinkConfigError` (dry
 * runs excepted — they need no client at all). A missing or
 * invalid topic URL is likewise a config error at send
 * time (dry runs excepted): there is no per-record topic to
 * fall back to.
 */
export interface NtfySinkConfig {
  /**
   * Target topic URL, e.g. `https://ntfy.sh/<topic>` or a
   * self-hosted `https://ntfy.example.com/<topic>`.
   * Posted to verbatim: ntfy authenticates and routes by
   * the URL itself, so no token is appended at send time.
   * Must be a parseable `https:` URL at send time; a
   * missing or invalid URL throws `NtfySinkConfigError`,
   * never a silent no-op.
   */
  topicUrl?: string;
  /**
   * The ntfy topic client to deliver through. Injected,
   * never bundled: the operator's client adapter implements
   * `NtfyTopicClient`. Required for real sends; a missing
   * client is a config error, not a silent no-op.
   */
  client?: NtfyTopicClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including text derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The topic URL and client are not required in dry-run
   * mode, mirroring the sibling sinks' dry-run exemption.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the message text appends the
   * event body verbatim after a blank line, truncated to
   * `payloadMaxChars` characters (see below). When `false`
   * or absent, the message carries the summary only — the
   * default, so event bodies (which routinely carry PII) never
   * leak into a notification unless the operator explicitly
   * asks for them.
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
export interface NtfyRecord {
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
export interface NtfyResolvedRecord {
  /** Target topic URL, exactly as configured. */
  url: string;
  /** The derived message text (summary, plus an opted-in payload snippet). */
  body: string;
  /** Index into the caller's original `records` array. */
  index: number;
}

/** One failed message, with its retry lane already mapped. */
export interface NtfyFailedRecord {
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
   * non-2xx status is a fail-closed message (unknown topic,
   * invalid body).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface NtfySendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-241). */
export interface NtfySinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for ntfy send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already in their topic and are *not* in
 * `failedRecords`.
 */
export class NtfySinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: NtfyFailedRecord[];
  constructor(message: string, failedRecords: NtfyFailedRecord[]) {
    super(message);
    this.name = "NtfySinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, or the topic URL is missing or
 * invalid. A config problem, not a downstream verdict, so the
 * retry queue must not burn attempts on it (`classifyFailure`
 * maps it to `non_retryable`).
 */
export class NtfySinkConfigError extends NtfySinkError {
  constructor(reason: string) {
    super(`ntfy-sink: ${reason}`, []);
    this.name = "NtfySinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing topic URL is *not* a shape error: it is a config
 * error raised at send time (`NtfySinkConfigError`), so a sink
 * built before its URL is known still fails closed at send
 * time rather than crashing at construction. A present topic
 * URL must be a non-empty string, free of NUL and whitespace;
 * the `https:` parse check happens at send time, so an invalid
 * URL surfaces as the same config error.
 */
export function assertValidNtfySinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is NtfySinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  if (c.topicUrl !== undefined) {
    if (
      typeof c.topicUrl !== "string" ||
      c.topicUrl === "" ||
      (c.topicUrl as string).includes("\0") ||
      /\s/.test(c.topicUrl as string)
    ) {
      throw new RangeError(
        at("`topicUrl` must be a non-empty string, free of NUL and whitespace when set")
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
 * True when a topic URL is usable: parseable, and `https:`.
 * A notification URL must never travel over plaintext, and a
 * URL the operator cannot have meant must not be posted to.
 * The host is deliberately not pinned: an operator may use
 * ntfy.sh, self-host ntfy, or front the topic with a proxy.
 */
export function isValidNtfyTopicUrl(url: string): boolean {
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
 * silently drop sourceless events, and the topic (not the
 * text) is the delivery contract.
 */
export function resolveNtfySummary(record: NtfyRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return NTFY_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a device.
 */
export function truncateNtfyPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's message text: the summary, plus — only
 * under the `includePayload` opt-in — the body verbatim
 * after a blank line, truncated to `payloadMaxChars`
 * (default 2000). Without the opt-in, the text is the summary
 * alone: event bodies routinely carry PII and must never leak
 * into a notification by default. The body is appended as
 * plain text, not a fenced code block: ntfy renders the body
 * as-is, and a fence would be noise on a phone screen.
 */
export function resolveNtfyText(
  record: NtfyRecord,
  config: Pick<NtfySinkConfig, "includePayload" | "payloadMaxChars">
): string {
  const summary = resolveNtfySummary(record);
  if (config.includePayload !== true) {
    return summary;
  }
  const limit = config.payloadMaxChars ?? NTFY_DEFAULT_PAYLOAD_MAX_CHARS;
  return `${summary}\n\n${truncateNtfyPayload(record.body, limit)}`;
}

/**
 * Validate one record's body and resolve its send form: the
 * text derives from the record's own subject, key, or trace
 * id (plus an opted-in payload snippet). Throws `RangeError`
 * on an empty body string — even without the opt-in, the body
 * is the record's payload, and an empty record is a caller bug
 * that must fail closed, never notify as an empty message.
 */
export function resolveNtfyRecord(
  record: NtfyRecord,
  index: number,
  config: Pick<NtfySinkConfig, "includePayload" | "payloadMaxChars">
): { body: string; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`ntfy-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { body: resolveNtfyText(record, config), index };
}

/**
 * Map one ntfy POST `statusCode` onto its retry lane under
 * the WR-210 rules: 429 and every 5xx are transient and so
 * retryable — a rate limit says ntfy could not accept the
 * message right now, not that the payload is poison. Every
 * other non-2xx status (400, 401, 403, 404, and the rest) is
 * a fail-closed message: unknown topic, invalid body, or
 * another verdict retrying cannot change. Callers only pass
 * non-2xx statuses here; a 2xx status is a success, not a
 * failure.
 */
export function classifyNtfyRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * ntfy sink (WR-241). One instance targets one topic URL;
 * the caller owns retry/dead-letter policy around `send()` —
 * this class performs one POST attempt per message through
 * the injected client and reports its outcome. Failures throw
 * `NtfySinkError` carrying exactly the failed messages with
 * their retry lanes.
 */
export class NtfySink {
  private readonly cfg: NtfySinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: NtfySinkConfig) {
    assertValidNtfySinkConfig(config, "NtfySink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): NtfySinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages to the configured topic URL, in input
   * order. Throws `NtfySinkConfigError` when no client was
   * injected or the topic URL is missing or invalid, and
   * `NtfySinkError` when any message fails (carrying
   * exactly the failed messages with their retry lanes; both
   * counted in stats before throwing, so the counters stay
   * honest even for callers that only inspect stats).
   */
  async send(records: NtfyRecord[]): Promise<NtfySendResult> {
    const resolved = records.map((r, i) => resolveNtfyRecord(r, i, this.cfg));
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
      throw new NtfySinkConfigError("no client injected (set `client` in the sink config)");
    }
    const url = this.cfg.topicUrl;
    if (url === undefined || !isValidNtfyTopicUrl(url)) {
      throw new NtfySinkConfigError(
        "no valid topic URL configured (set `topicUrl` to a parseable `https:` URL)"
      );
    }
    const failedRecords: NtfyFailedRecord[] = [];
    let sent = 0;
    for (const record of resolved) {
      try {
        const response = await client.post({ url, body: record.body });
        if (response.status >= 200 && response.status < 300) {
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyNtfyRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toNtfyFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new NtfySinkError(
        `ntfy-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toNtfyFailedRecord(err: unknown, index: number): NtfyFailedRecord {
  const failed: NtfyFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
