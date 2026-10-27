/**
 * Gotify notification delivery sink (WR-242).
 *
 * Some downstreams are not queues, streams, or topics at all:
 * they are a human's phone or desktop. Where the ntfy sink
 * (WR-241) delivers to an ntfy topic, this sink delivers to a
 * Gotify server: one event is posted as one notification to
 * a configured message URL, and Gotify — not the relay —
 * owns the subscription, the delivery, and the retention of
 * the notification.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Gotify server.
 * The sink owns the relay-side concerns — message targeting,
 * title/message derivation, payload-inclusion policy,
 * per-message failure mapping — and the injected client owns
 * the wire protocol, including the POST call and the status
 * it returns.
 *
 * Wire shape — one POST per notification, carried to the
 * injected client as:
 *
 *   { url: "<configured message URL>",
 *     body: "{\"title\":\"<title>\",\"message\":\"<message>\",\"priority\":5}" }
 *
 * The client POSTs `body` verbatim as the request body
 * (a JSON object, not plain text): Gotify's `/message`
 * endpoint takes a JSON object with `title`, `message`, and
 * `priority` fields. The priority is fixed at 5 — the
 * middle of Gotify's 0–10 scale, an ordinary notification,
 * neither silent nor alarming: the relay does not re-rank
 * an operator's notifications, and a sink that let the
 * caller pick a priority per event could silently escalate
 * routine deliveries into alarms.
 *
 * The message URL is posted to verbatim: Gotify
 * authenticates by the URL itself (e.g.
 * `https://gotify.example.com/message?token=<app-token>`),
 * so — like the ntfy sink, and unlike DingTalk — no token is
 * appended at send time: the configured URL, query string
 * included, is posted to verbatim. Nothing about any
 * credential is ever extracted, logged, or carried
 * separately from the URL: the URL is the target, and
 * treating it as one opaque value means rotating an app
 * token never means changing sink code.
 *
 * Message targeting — one sink targets one message URL:
 * every message goes there. A missing message URL is a
 * config error, not a resolution fallback: unlike the broker
 * sinks, there is no per-record target to resolve to, so a
 * sink with no URL has nowhere to deliver and fails closed
 * with `GotifySinkConfigError` at send time (dry runs
 * excepted — they need no URL at all, mirroring the sibling
 * sinks' dry-run exemption for the client). An invalid URL —
 * unparseable, or not `https:` — is the same config error: a
 * notification URL must never travel over plaintext, and a
 * URL the operator cannot have meant must not be posted to.
 * The host is not pinned to any Gotify deployment: an
 * operator may self-host Gotify or front the server with a
 * proxy or sidecar, and the sink must not second-guess that
 * deployment. The query string is part of the URL: a
 * validator that stripped it would silently drop the app
 * token and break authentication, so the URL is validated
 * whole and posted whole.
 *
 * Title and message — derived from the event's own values.
 * The title takes `subject` first, falling back to `key`
 * when the event carries no subject: the subject is what
 * the event is about, the key (e.g. aggregate id) is the
 * next most identifying value. The message takes `key`
 * first, falling back to `traceId`: the message line names
 * the entity and the trace that produced the event. An event
 * with none of the values a field needs still notifies,
 * with the generic summary `webhook event`: a notification
 * sink that silently dropped sourceless events would hide
 * exactly the deliveries an operator most needs to see, and
 * the message URL — not the text — is the delivery contract
 * here, so no invented target is at stake.
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
 * cannot flood a device or blow past Gotify's message
 * limits. The body is appended as plain text inside the
 * `message` field, not a fenced code block: Gotify renders
 * the message as-is, and a fence would be noise on a phone
 * screen.
 *
 * Failure handling mirrors the WR-210 SQS sink's classification
 * (`src/failure.ts`), applied per message over HTTP status:
 *
 * - a non-2xx POST throws `GotifySinkError` carrying every
 *   failed message with its retry lane already mapped, so the
 *   caller retries exactly the failed messages;
 * - retryable statuses are the transient HTTP states — 429
 *   and every 5xx: a rate limit says Gotify could not accept
 *   the message right now, not that the payload is poison;
 * - non-retryable statuses are the fail-closed messages —
 *   every other non-2xx status, including 400, 401, 403, and
 *   404 (unknown app token, invalid body): retrying them burns
 *   the retry budget for nothing, and rerouting them
 *   elsewhere would notify a server the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status: it
 *   says nothing about the payload;
 * - a missing client or a missing/invalid message URL throws
 *   `GotifySinkConfigError`, which `classifyFailure` maps to
 *   `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for a text field. */
export const GOTIFY_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const GOTIFY_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Fixed Gotify priority for every notification (0–10 scale, 5 is ordinary). */
export const GOTIFY_PRIORITY = 5;

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol (including the status it
 * returns and the request headers); this shape is the
 * relay-side contract it must honour. The message URL is
 * posted verbatim, query string included: Gotify
 * authenticates by the URL itself, so no token is ever
 * appended or extracted. The body is the JSON object
 * `{"title","message","priority":5}` serialized as a string,
 * posted verbatim.
 */
export interface GotifyMessagePostRequest {
  /** Target message URL, exactly as configured (query string included). */
  url: string;
  /** The JSON notification object, serialized: title, message, priority 5. */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse Gotify's response body.
 */
export interface GotifyMessagePostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
}

/**
 * The injected Gotify message client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one message per call, sending
 * `body` verbatim as the request body (the JSON object with
 * `title`, `message`, and `priority`).
 */
export interface GotifyMessageClient {
  post(request: GotifyMessagePostRequest): Promise<GotifyMessagePostResponse>;
}

/**
 * Configuration for one Gotify sink. The client is injected:
 * without one, `send()` throws `GotifySinkConfigError` (dry
 * runs excepted — they need no client at all). A missing or
 * invalid message URL is likewise a config error at send
 * time (dry runs excepted): there is no per-record target to
 * fall back to.
 */
export interface GotifySinkConfig {
  /**
   * Target message URL, e.g.
   * `https://gotify.example.com/message?token=<app-token>`.
   * Posted to verbatim, query string included: Gotify
   * authenticates by the URL itself, so no token is appended
   * at send time. Must be a parseable `https:` URL at send
   * time; a missing or invalid URL throws
   * `GotifySinkConfigError`, never a silent no-op.
   */
  messageUrl?: string;
  /**
   * The Gotify message client to deliver through. Injected,
   * never bundled: the operator's client adapter implements
   * `GotifyMessageClient`. Required for real sends; a missing
   * client is a config error, not a silent no-op.
   */
  client?: GotifyMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including text derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The message URL and client are not required in dry-run
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
export interface GotifyRecord {
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
export interface GotifyFailedRecord {
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
   * token, invalid body).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface GotifySendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-242). */
export interface GotifySinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Gotify send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on their server and are *not* in
 * `failedRecords`.
 */
export class GotifySinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: GotifyFailedRecord[];
  constructor(message: string, failedRecords: GotifyFailedRecord[]) {
    super(message);
    this.name = "GotifySinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, or the message URL is missing or
 * invalid. A config problem, not a downstream verdict, so the
 * retry queue must not burn attempts on it (`classifyFailure`
 * maps it to `non_retryable`).
 */
export class GotifySinkConfigError extends GotifySinkError {
  constructor(reason: string) {
    super(`gotify-sink: ${reason}`, []);
    this.name = "GotifySinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing message URL is *not* a shape error: it is a config
 * error raised at send time (`GotifySinkConfigError`), so a sink
 * built before its URL is known still fails closed at send
 * time rather than crashing at construction. A present message
 * URL must be a non-empty string, free of NUL and whitespace;
 * the `https:` parse check happens at send time, so an invalid
 * URL surfaces as the same config error.
 */
export function assertValidGotifySinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is GotifySinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  if (c.messageUrl !== undefined) {
    if (
      typeof c.messageUrl !== "string" ||
      c.messageUrl === "" ||
      (c.messageUrl as string).includes("\0") ||
      /\s/.test(c.messageUrl as string)
    ) {
      throw new RangeError(
        at("`messageUrl` must be a non-empty string, free of NUL and whitespace when set")
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
 * True when a message URL is usable: parseable, and `https:`.
 * A notification URL must never travel over plaintext, and a
 * URL the operator cannot have meant must not be posted to.
 * The host is deliberately not pinned: an operator may
 * self-host Gotify or front the server with a proxy. The
 * query string is part of the URL and is validated whole:
 * stripping it would silently drop the app token.
 */
export function isValidGotifyMessageUrl(url: string): boolean {
  try {
    return new URL(url).protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * Derive one record's title: the first non-empty value
 * among `subject` and `key`, in that order. Falls back to
 * the generic `webhook event` summary when the record
 * carries neither — a notification sink must not silently
 * drop sourceless events, and the message URL (not the
 * text) is the delivery contract.
 */
export function resolveGotifyTitle(record: GotifyRecord): string {
  for (const value of [record.subject, record.key]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return GOTIFY_FALLBACK_SUMMARY;
}

/**
 * Derive one record's message summary: the first non-empty
 * value among `key` and `traceId`, in that order. Falls back
 * to the generic `webhook event` summary when the record
 * carries neither.
 */
export function resolveGotifyMessageSummary(record: GotifyRecord): string {
  for (const value of [record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return GOTIFY_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a device.
 */
export function truncateGotifyPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's notification object: the title, the
 * message summary, and the fixed priority 5. Only under the
 * `includePayload` opt-in does the message append the body
 * verbatim after a blank line, truncated to `payloadMaxChars`
 * (default 2000). Without the opt-in, the message is the
 * summary alone: event bodies routinely carry PII and must
 * never leak into a notification by default. The body is
 * appended as plain text inside the `message` field, not a
 * fenced code block: Gotify renders the message as-is, and a
 * fence would be noise on a phone screen.
 */
export function resolveGotifyNotification(
  record: GotifyRecord,
  config: Pick<GotifySinkConfig, "includePayload" | "payloadMaxChars">
): { title: string; message: string; priority: number } {
  const title = resolveGotifyTitle(record);
  let message = resolveGotifyMessageSummary(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? GOTIFY_DEFAULT_PAYLOAD_MAX_CHARS;
    message = `${message}\n\n${truncateGotifyPayload(record.body, limit)}`;
  }
  return { title, message, priority: GOTIFY_PRIORITY };
}

/**
 * Validate one record's body and resolve its send form: the
 * JSON notification object, serialized. Throws `RangeError`
 * on an empty body string — even without the opt-in, the body
 * is the record's payload, and an empty record is a caller bug
 * that must fail closed, never notify as an empty message.
 */
export function resolveGotifyRecord(
  record: GotifyRecord,
  index: number,
  config: Pick<GotifySinkConfig, "includePayload" | "payloadMaxChars">
): { body: string; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`gotify-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { body: JSON.stringify(resolveGotifyNotification(record, config)), index };
}

/**
 * Map one Gotify POST `statusCode` onto its retry lane under
 * the WR-210 rules: 429 and every 5xx are transient and so
 * retryable — a rate limit says Gotify could not accept the
 * message right now, not that the payload is poison. Every
 * other non-2xx status (400, 401, 403, 404, and the rest) is
 * a fail-closed message: unknown app token, invalid body, or
 * another verdict retrying cannot change. Callers only pass
 * non-2xx statuses here; a 2xx status is a success, not a
 * failure.
 */
export function classifyGotifyRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Gotify sink (WR-242). One instance targets one message URL;
 * the caller owns retry/dead-letter policy around `send()` —
 * this class performs one POST attempt per message through
 * the injected client and reports its outcome. Failures throw
 * `GotifySinkError` carrying exactly the failed messages with
 * their retry lanes.
 */
export class GotifySink {
  private readonly cfg: GotifySinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: GotifySinkConfig) {
    assertValidGotifySinkConfig(config, "GotifySink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): GotifySinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages to the configured message URL, in input
   * order. Throws `GotifySinkConfigError` when no client was
   * injected or the message URL is missing or invalid, and
   * `GotifySinkError` when any message fails (carrying
   * exactly the failed messages with their retry lanes; both
   * counted in stats before throwing, so the counters stay
   * honest even for callers that only inspect stats).
   */
  async send(records: GotifyRecord[]): Promise<GotifySendResult> {
    const resolved = records.map((r, i) => resolveGotifyRecord(r, i, this.cfg));
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
      throw new GotifySinkConfigError("no client injected (set `client` in the sink config)");
    }
    const url = this.cfg.messageUrl;
    if (url === undefined || !isValidGotifyMessageUrl(url)) {
      throw new GotifySinkConfigError(
        "no valid message URL configured (set `messageUrl` to a parseable `https:` URL)"
      );
    }
    const failedRecords: GotifyFailedRecord[] = [];
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
          retryable: classifyGotifyRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toGotifyFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new GotifySinkError(
        `gotify-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toGotifyFailedRecord(err: unknown, index: number): GotifyFailedRecord {
  const failed: GotifyFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
