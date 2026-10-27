/**
 * Pushbullet notification delivery sink (WR-245).
 *
 * Some downstreams are not queues, streams, or topics at all:
 * they are a human's phone or desktop. Where the Pushover
 * sink (WR-244) delivers to Pushover, this sink delivers to
 * Pushbullet: one event is posted as one push to the
 * Pushbullet pushes endpoint, and Pushbullet — not the relay
 * — owns the subscription, the delivery, and the retention
 * of the push.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Pushbullet
 * server. The sink owns the relay-side concerns — push
 * targeting, title/body derivation, payload-inclusion
 * policy, per-message failure mapping — and the injected
 * client owns the wire protocol, including the POST call,
 * the headers it sends, and the status it returns.
 *
 * Wire shape — one POST per push, carried to the injected
 * client as:
 *
 *   { url: "https://api.pushbullet.com/v2/pushes",
 *     headers: { "Access-Token": "<access-token>" },
 *     body: "{\"type\":\"note\",\"title\":\"<title>\",\"body\":\"<body>\"}" }
 *
 * The client POSTs `body` verbatim as the request body
 * (a JSON object, not plain text) and sends `headers`
 * verbatim as the request headers: Pushbullet's pushes
 * endpoint takes a JSON object with `type`, `title`, and
 * `body` fields, where `type: "note"` is the plain-text
 * push kind — the relay sends notes, not links or files,
 * and a sink that picked another type per event could
 * silently change what lands on a device. The host is
 * fixed, not configurable: Pushbullet is a single hosted
 * service, so there is no self-hosted deployment to point
 * at — unlike the Bark and Gotify sinks, whose hosts vary,
 * a configurable URL here could only misroute a push to a
 * server that is not Pushbullet.
 *
 * Authentication — carried in a request header, not the
 * URL and not the body: Pushbullet authenticates by the
 * `Access-Token` request header. This differs from the
 * Gotify and Bark sinks, whose credentials ride in the URL
 * itself, and from the Pushover sink (WR-244), whose token
 * and user key ride inside the request body. The sink takes
 * the token from its config (the email sink's precedent for
 * credential-style config, rather than a URL-embedded
 * credential): the token is placed into the `headers` of
 * the request object at send time, the client sends those
 * headers verbatim, and nothing about the token is ever
 * logged by this module. The header name is exact —
 * `Access-Token`, not `Authorization: Bearer` — because
 * that is the scheme Pushbullet's API takes, and a client
 * that rewrote it would silently break authentication.
 *
 * Push targeting — one sink targets one Pushbullet
 * account: every push goes to the configured access token's
 * account. A missing access token is a config error, not a
 * resolution fallback: unlike the broker sinks, there is
 * no per-record target to resolve to, so a sink with no
 * token has nowhere to deliver and fails closed with
 * `PushbulletSinkConfigError` at send time (dry runs
 * excepted — they need no token at all, mirroring the
 * sibling sinks' dry-run exemption for the client).
 *
 * Title and body — derived from the event's own values.
 * The title takes `subject` first, falling back to `key`
 * when the event carries no subject: the subject is what
 * the event is about, the key (e.g. aggregate id) is the
 * next most identifying value. The body takes `key`
 * first, falling back to `traceId`: the body line names
 * the entity and the trace that produced the event. An
 * event with none of the values a field needs still
 * notifies, with the generic summary `webhook event`: a
 * notification sink that silently dropped sourceless events
 * would hide exactly the deliveries an operator most needs
 * to see, and the access token — not the text — is the
 * delivery contract here, so no invented target is at
 * stake.
 *
 * Payload inclusion — by default the body carries the
 * summary only, never the full payload: event bodies
 * routinely carry PII, secrets, or customer data, and a
 * push notification is a far wider audience than a queue
 * or a stream. Opting into `includePayload` appends the
 * body verbatim after a blank line, truncated to
 * `payloadMaxChars` characters (default 2000) with a
 * truncation marker — the opt-in is explicit, and the
 * truncation is unconditional, so even an opted-in body
 * cannot flood a device or blow past Pushbullet's message
 * limits. The body is appended as plain text inside the
 * `body` field, not a fenced code block: Pushbullet
 * renders the note body as-is, and a fence would be noise
 * on a phone screen.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over HTTP status:
 *
 * - a non-2xx POST throws `PushbulletSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Pushbullet could
 *   not accept the message right now, not that the
 *   payload is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (unknown access token, invalid body):
 *   retrying them burns the retry budget for nothing, and
 *   rerouting them elsewhere would notify an account the
 *   operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client or a missing access token throws
 *   `PushbulletSinkConfigError`, which `classifyFailure`
 *   maps to `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for a text field. */
export const PUSHBULLET_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const PUSHBULLET_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Fixed Pushbullet push type for every notification (a plain-text note). */
export const PUSHBULLET_PUSH_TYPE = "note";

/** Exact Pushbullet authentication header name (not `Authorization: Bearer`). */
export const PUSHBULLET_ACCESS_TOKEN_HEADER = "Access-Token";

/**
 * The single Pushbullet pushes endpoint. Fixed, not
 * configurable: Pushbullet is one hosted service, so a
 * configurable URL could only misroute a push to a server
 * that is not Pushbullet.
 */
export const PUSHBULLET_PUSHES_URL = "https://api.pushbullet.com/v2/pushes";

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol (including the status it
 * returns); this shape is the relay-side contract it must
 * honour. The URL is always the fixed Pushbullet pushes
 * endpoint, the headers carry the `Access-Token` exactly
 * (the client sends them verbatim, never rewrites or logs
 * them), and the body is the JSON object `{"type":"note",
 * "title","body"}` serialized as a string, posted verbatim.
 * The token rides in the headers, never in the URL and
 * never in the body.
 */
export interface PushbulletPushPostRequest {
  /** Always the fixed Pushbullet pushes endpoint. */
  url: string;
  /** Request headers, sent verbatim: exactly `{ "Access-Token": "<access-token>" }`. */
  headers: Record<string, string>;
  /** The JSON push object, serialized: type "note", title, body. */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse Pushbullet's response body.
 */
export interface PushbulletPushPostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
}

/**
 * The injected Pushbullet push client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one push per call, sending
 * `body` verbatim as the request body (the JSON object with
 * `type`, `title`, and `body`) and `headers` verbatim as
 * the request headers (the `Access-Token`).
 */
export interface PushbulletPushClient {
  post(request: PushbulletPushPostRequest): Promise<PushbulletPushPostResponse>;
}

/**
 * Configuration for one Pushbullet sink. The client is
 * injected: without one, `send()` throws
 * `PushbulletSinkConfigError` (dry runs excepted — they need
 * no client at all). A missing access token is likewise a
 * config error at send time (dry runs excepted): there is
 * no per-record target to fall back to.
 */
export interface PushbulletSinkConfig {
  /**
   * Pushbullet access token. Placed into the `Access-Token`
   * request header at send time, never into the URL or the
   * body, and never logged. Must be a non-empty string,
   * free of NUL and whitespace, when set; a missing token
   * throws `PushbulletSinkConfigError` at send time, never
   * a silent no-op.
   */
  accessToken?: string;
  /**
   * The Pushbullet push client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `PushbulletPushClient`. Required for real
   * sends; a missing client is a config error, not a
   * silent no-op.
   */
  client?: PushbulletPushClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including text derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The access token and client are not required in dry-run
   * mode, mirroring the sibling sinks' dry-run exemption.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the body text appends the
   * event body verbatim after a blank line, truncated to
   * `payloadMaxChars` characters (see below). When `false`
   * or absent, the body carries the summary only — the
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
export interface PushbulletRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Title-derivation source, first priority: the event's
   * subject, when set and non-empty. Falls through to `key`.
   */
  subject?: string;
  /**
   * Title-derivation source, second priority, and
   * body-derivation source, first priority: the event's key
   * (e.g. aggregate id).
   */
  key?: string;
  /**
   * Body-derivation source, last priority: the trace id.
   */
  traceId?: string;
}

/** One failed message, with its retry lane already mapped. */
export interface PushbulletFailedRecord {
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
   * non-2xx status is a fail-closed message (unknown access
   * token, invalid body).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface PushbulletSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-245). */
export interface PushbulletSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Pushbullet send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on Pushbullet's server and are *not* in
 * `failedRecords`.
 */
export class PushbulletSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: PushbulletFailedRecord[];
  constructor(message: string, failedRecords: PushbulletFailedRecord[]) {
    super(message);
    this.name = "PushbulletSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, or the access token is missing. A
 * config problem, not a downstream verdict, so the retry
 * queue must not burn attempts on it (`classifyFailure`
 * maps it to `non_retryable`).
 */
export class PushbulletSinkConfigError extends PushbulletSinkError {
  constructor(reason: string) {
    super(`pushbullet-sink: ${reason}`, []);
    this.name = "PushbulletSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing access token is *not* a shape error: it is a config
 * error raised at send time (`PushbulletSinkConfigError`), so
 * a sink built before its token is known still fails closed
 * at send time rather than crashing at construction. A present
 * token must be a non-empty string, free of NUL and
 * whitespace.
 */
export function assertValidPushbulletSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is PushbulletSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  if (c.accessToken !== undefined) {
    if (
      typeof c.accessToken !== "string" ||
      c.accessToken === "" ||
      (c.accessToken as string).includes("\0") ||
      /\s/.test(c.accessToken as string)
    ) {
      throw new RangeError(
        at("`accessToken` must be a non-empty string, free of NUL and whitespace when set")
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
 * Derive one record's title: the first non-empty value
 * among `subject` and `key`, in that order. Falls back to
 * the generic `webhook event` summary when the record
 * carries neither — a notification sink must not silently
 * drop sourceless events, and the access token (not the
 * text) is the delivery contract.
 */
export function resolvePushbulletTitle(record: PushbulletRecord): string {
  for (const value of [record.subject, record.key]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return PUSHBULLET_FALLBACK_SUMMARY;
}

/**
 * Derive one record's body summary: the first non-empty
 * value among `key` and `traceId`, in that order. Falls back
 * to the generic `webhook event` summary when the record
 * carries neither.
 */
export function resolvePushbulletBodySummary(record: PushbulletRecord): string {
  for (const value of [record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return PUSHBULLET_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a device.
 */
export function truncatePushbulletPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's notification text: the title and the
 * body. Only under the `includePayload` opt-in does the
 * body append the event body verbatim after a blank line,
 * truncated to `payloadMaxChars` (default 2000). Without
 * the opt-in, the body is the summary alone: event bodies
 * routinely carry PII and must never leak into a
 * notification by default. The body is appended as plain
 * text inside the `body` field, not a fenced code block:
 * Pushbullet renders the note body as-is, and a fence
 * would be noise on a phone screen.
 */
export function resolvePushbulletNotification(
  record: PushbulletRecord,
  config: Pick<PushbulletSinkConfig, "includePayload" | "payloadMaxChars">
): { title: string; body: string } {
  const title = resolvePushbulletTitle(record);
  let body = resolvePushbulletBodySummary(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? PUSHBULLET_DEFAULT_PAYLOAD_MAX_CHARS;
    body = `${body}\n\n${truncatePushbulletPayload(record.body, limit)}`;
  }
  return { title, body };
}

/**
 * Validate one record's body and resolve its send form: the
 * JSON push object, serialized. Throws `RangeError` on an
 * empty body string — even without the opt-in, the body is
 * the record's payload, and an empty record is a caller bug
 * that must fail closed, never notify as an empty push.
 * The serialized form carries no credential: the access
 * token rides in the request headers, added by `send()`.
 */
export function resolvePushbulletRecord(
  record: PushbulletRecord,
  index: number,
  config: Pick<PushbulletSinkConfig, "includePayload" | "payloadMaxChars">
): { body: string; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`pushbullet-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  const notification = resolvePushbulletNotification(record, config);
  return {
    body: JSON.stringify({
      type: PUSHBULLET_PUSH_TYPE,
      title: notification.title,
      body: notification.body,
    }),
    index,
  };
}

/**
 * Map one Pushbullet POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says Pushbullet could not
 * accept the message right now, not that the payload is
 * poison. Every other non-2xx status (400, 401, 403, 404,
 * and the rest) is a fail-closed message: unknown access
 * token, invalid body, or another verdict retrying cannot
 * change. Callers only pass non-2xx statuses here; a 2xx
 * status is a success, not a failure.
 */
export function classifyPushbulletRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Pushbullet sink (WR-245). One instance targets one
 * Pushbullet account; the caller owns retry/dead-letter
 * policy around `send()` — this class performs one POST
 * attempt per message through the injected client and
 * reports its outcome. Failures throw `PushbulletSinkError`
 * carrying exactly the failed messages with their retry
 * lanes.
 */
export class PushbulletSink {
  private readonly cfg: PushbulletSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: PushbulletSinkConfig) {
    assertValidPushbulletSinkConfig(config, "PushbulletSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): PushbulletSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages to Pushbullet, in input order. Throws
   * `PushbulletSinkConfigError` when no client was injected
   * or the access token is missing, and `PushbulletSinkError`
   * when any message fails (carrying exactly the failed
   * messages with their retry lanes; both counted in stats
   * before throwing, so the counters stay honest even for
   * callers that only inspect stats).
   */
  async send(records: PushbulletRecord[]): Promise<PushbulletSendResult> {
    const resolved = records.map((r, i) => resolvePushbulletRecord(r, i, this.cfg));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The
      // access token and client are not required here,
      // mirroring the sibling sinks' dry-run exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new PushbulletSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const accessToken = this.cfg.accessToken;
    if (accessToken === undefined) {
      throw new PushbulletSinkConfigError("no access token configured (set `accessToken` in the sink config)");
    }
    const failedRecords: PushbulletFailedRecord[] = [];
    let sent = 0;
    for (const record of resolved) {
      try {
        const response = await client.post({
          url: PUSHBULLET_PUSHES_URL,
          headers: { [PUSHBULLET_ACCESS_TOKEN_HEADER]: accessToken },
          body: record.body,
        });
        if (response.status >= 200 && response.status < 300) {
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyPushbulletRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toPushbulletFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new PushbulletSinkError(
        `pushbullet-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toPushbulletFailedRecord(err: unknown, index: number): PushbulletFailedRecord {
  const failed: PushbulletFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
