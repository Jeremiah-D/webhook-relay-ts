/**
 * 46elks SMS notification delivery sink (WR-277).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's phone. Where the Clickatell sink
 * (WR-274) delivers SMS through Clickatell's platform API
 * with a bare-key `Authorization` header and a flat JSON
 * `content`/`to` envelope, and the TextMagic sink (WR-272)
 * delivers through TextMagic's SMS API with the
 * `X-TM-Username` and `X-TM-Key` header pair and a flat
 * JSON `text`/`phones` envelope, this sink delivers
 * through 46elks' SMS API: one event is sent as one POST,
 * and 46elks — not the relay — owns the carrier routing,
 * the delivery, and the retention of the message.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a 46elks
 * server. The sink owns the relay-side concerns — message
 * targeting, content derivation, payload-inclusion policy,
 * per-message failure mapping — and the injected client
 * owns the wire protocol, including the POST call, the
 * authentication, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://api.46elks.com/a1/sms",
 *     body: "from=<from>&to=<to>&message=<message>" }
 *
 * The client POSTs to that URL, sending `body` verbatim
 * as the request body (an `application/x-www-form-urlencoded`
 * form with the `from`, `to`, and `message` fields) and
 * authenticating with an `Authorization: Basic` header
 * carrying the base64 of `API username:password` — the
 * API username and password it alone holds. Two things
 * about this shape are deliberate, and both follow the
 * sibling sinks:
 *
 * - The credentials are held by the client alone. The sink
 *   never receives them, never places them in the request,
 *   and never logs them: like the Clickatell sink (WR-274),
 *   whose bare key the client alone holds, this sink's
 *   handed request carries no credential at all — the
 *   client adds the `Authorization: Basic` header from the
 *   username and password it alone holds, so there is
 *   nothing in the handed request for a log line or a
 *   retry queue to leak. This is the opposite of the
 *   Vonage sink (WR-252), whose credentials ride inside
 *   the request body: 46elks authenticates by header, so
 *   the body carries only routing and content.
 * - The host is fixed, not configurable: 46elks is a
 *   single hosted service, so there is no self-hosted
 *   deployment to point at — unlike the Infobip sink
 *   (WR-267), whose host varies per account, a
 *   configurable URL here could only misroute a message
 *   to a server that is not 46elks.
 *
 * This sink is orthogonal to the Clickatell sink (WR-274):
 * Clickatell posts a flat JSON `content`/`to` envelope
 * with a bare-key `Authorization` header, while 46elks
 * posts a form-encoded `from`/`to`/`message` body with
 * Basic auth. It is likewise distinct from the ClickSend
 * sink (WR-268): ClickSend posts a JSON `messages`/`body`
 * envelope with Basic auth and a single `to` string, while
 * 46elks posts a form-encoded body with an explicit `from`
 * sender field.
 *
 * The sender and recipient are configured, not derived
 * from the event. One sink targets one sender identity and
 * one recipient number. A missing sender or recipient is a
 * config error, not a resolution fallback: unlike the
 * broker sinks, there is no per-record target to resolve
 * to, so a sink with neither has nowhere to deliver and
 * fails closed with `ElksSinkConfigError` at send time
 * (dry runs excepted — they need no sender or number at
 * all, mirroring the sibling sinks' dry-run exemption for
 * the client). The `from` value is either a 46elks number
 * or an alphanumeric sender id of at most 11 characters:
 * a longer alphanumeric sender is rejected at config
 * validation, because 46elks caps alphanumeric sender ids
 * at 11 characters and a longer value could never send.
 *
 * Message content — derived from the event's own values:
 * the first non-empty value among `subject`, `key`, and
 * `traceId`, in that order. An SMS carries a single
 * content field, so there is no subject/value split like
 * the email sinks: the subject is what the event is
 * about, the key (e.g. aggregate id) is the next most
 * identifying value, and the trace id names the trace
 * that produced the event. An event with none of the
 * values still notifies, with the generic summary
 * `webhook event`: a notification sink that silently
 * dropped sourceless events would hide exactly the
 * deliveries an operator most needs to see, and the
 * recipient number — not the content — is the delivery
 * contract here, so no invented target is at stake.
 *
 * Payload inclusion — by default the message carries the
 * summary only, never the full payload: event bodies
 * routinely carry PII, secrets, or customer data, and a
 * phone is a far wider audience than a queue or a stream.
 * Opting into `includePayload` appends the body verbatim
 * after a blank line, truncated to `payloadMaxChars`
 * characters (default 2000) with a truncation marker —
 * the opt-in is explicit, and the truncation is
 * unconditional, so even an opted-in body cannot flood a
 * phone. The payload is appended as plain text inside
 * the `message` field, not a fenced code block: an SMS
 * renders as-is, and a fence would be noise on a phone
 * screen.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over HTTP status:
 *
 * - a non-2xx POST throws `ElksSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says 46elks could
 *   not accept the message right now, not that the
 *   payload is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (unknown number, invalid body, bad
 *   credentials): retrying them burns the retry budget
 *   for nothing, and rerouting them elsewhere would text
 *   numbers the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client, sender, or recipient throws
 *   `ElksSinkConfigError`, which `classifyFailure`
 *   maps to `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for the message field. */
export const ELKS_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const ELKS_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Fixed 46elks SMS API endpoint for every message. */
export const ELKS_SEND_URL = "https://api.46elks.com/a1/sms";

/** Maximum length of an alphanumeric sender id, per 46elks. */
export const ELKS_MAX_ALPHANUMERIC_SENDER_LENGTH = 11;

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (an `application/x-www-form-urlencoded`
 * form with the `from`, `to`, and `message` fields) to the
 * fixed SMS endpoint, and authenticates with an
 * `Authorization: Basic` header carrying the base64 of
 * `API username:password` — which the sink never sees.
 */
export interface ElksMessagePostRequest {
  /** Always the fixed 46elks SMS endpoint. */
  url: string;
  /** The form-encoded message, serialized: `from=<from>&to=<to>&message=<message>`. */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse 46elks' response body.
 */
export interface ElksMessagePostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
}

/**
 * The injected 46elks message client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one message per call, sending
 * `body` verbatim as the request body (the form-encoded
 * `from`/`to`/`message` fields), setting the
 * `application/x-www-form-urlencoded` content type, and
 * authenticating with an `Authorization: Basic` header
 * carrying the base64 of its own API username and
 * password — which the sink never sees.
 */
export interface ElksMessageClient {
  post(request: ElksMessagePostRequest): Promise<ElksMessagePostResponse>;
}

/**
 * Configuration for one 46elks sink. The client is
 * injected: without one, `send()` throws
 * `ElksSinkConfigError` (dry runs excepted — they need
 * no client at all). A missing sender or recipient is
 * likewise a config error at send time (dry runs
 * excepted): there is no per-record target to fall back
 * to. The API username and password are deliberately
 * absent from this config: the client alone holds them
 * and sends them as the `Authorization: Basic` header.
 */
export interface ElksSinkConfig {
  /**
   * The sender identity (`from`): either a 46elks number
   * or an alphanumeric sender id of at most 11
   * characters. Must be a non-empty string, free of NUL
   * and whitespace, when set; a longer alphanumeric sender
   * is rejected at config validation. A missing sender
   * throws `ElksSinkConfigError` at send time.
   */
  from?: string;
  /**
   * The recipient number (`to`): an E.164 string. Must
   * be a non-empty string, free of NUL and whitespace,
   * when set; a missing recipient throws
   * `ElksSinkConfigError` at send time.
   */
  to?: string;
  /**
   * The 46elks message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `ElksMessageClient` and alone holds the
   * API username and password. Required for real sends; a
   * missing client is a config error, not a silent no-op.
   */
  client?: ElksMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including content derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The sender, recipient, and client are
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
export interface ElksRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Content-derivation source, first priority: the event's
   * subject, when set and non-empty. Falls through to `key`,
   * then `traceId`.
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
export interface ElksFailedRecord {
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
   * non-2xx status is a fail-closed message (unknown number,
   * invalid body, bad credentials).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface ElksSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-277). */
export interface ElksSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for 46elks send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on 46elks' server and are *not* in
 * `failedRecords`.
 */
export class ElksSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: ElksFailedRecord[];
  constructor(message: string, failedRecords: ElksFailedRecord[]) {
    super(message);
    this.name = "ElksSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, or the sender or recipient is
 * missing. A config problem, not a downstream verdict, so
 * the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class ElksSinkConfigError extends ElksSinkError {
  constructor(reason: string) {
    super(`46elks-sink: ${reason}`, []);
    this.name = "ElksSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing sender or recipient is *not* a shape error: it
 * is a config error raised at send time
 * (`ElksSinkConfigError`), so a sink built before its sender
 * or number is known still fails closed at send time rather
 * than crashing at construction. A present `from` value
 * must be a non-empty string, free of NUL and whitespace,
 * and — when it is an alphanumeric sender id — at most 11
 * characters. A present `to` value must be a non-empty
 * string, free of NUL and whitespace.
 */
export function assertValidElksSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is ElksSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  const from = c.from;
  if (from !== undefined) {
    if (
      typeof from !== "string" ||
      from === "" ||
      from.includes("\0") ||
      /\s/.test(from)
    ) {
      throw new RangeError(
        at("`from` must be a non-empty string, free of NUL and whitespace, when set")
      );
    }
    if (
      /^[A-Za-z0-9]+$/.test(from) &&
      from.length > ELKS_MAX_ALPHANUMERIC_SENDER_LENGTH
    ) {
      throw new RangeError(
        at(
          "`from` as an alphanumeric sender id must be at most 11 characters (46elks cap)"
        )
      );
    }
  }
  const to = c.to;
  if (to !== undefined) {
    if (
      typeof to !== "string" ||
      to === "" ||
      to.includes("\0") ||
      /\s/.test(to)
    ) {
      throw new RangeError(
        at("`to` must be a non-empty string, free of NUL and whitespace, when set")
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
 * Derive one record's message content: the first non-empty
 * value among `subject`, `key`, and `traceId`, in that
 * order. Falls back to the generic `webhook event` summary
 * when the record carries none — a notification sink must
 * not silently drop sourceless events, and the recipient
 * number (not the content) is the delivery contract.
 */
export function resolveElksContent(record: ElksRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return ELKS_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a phone.
 */
export function truncateElksPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's message content. Only under the
 * `includePayload` opt-in does the content append the event
 * body verbatim after a blank line, truncated to
 * `payloadMaxChars` (default 2000). Without the opt-in, the
 * content is the summary alone: event bodies routinely carry
 * PII and must never leak into a notification by default.
 * The payload is appended as plain text inside the `message`
 * field, not a fenced code block: an SMS renders as-is,
 * and a fence would be noise on a phone screen.
 */
export function resolveElksMessage(
  record: ElksRecord,
  config: Pick<ElksSinkConfig, "includePayload" | "payloadMaxChars">
): { message: string } {
  let message = resolveElksContent(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? ELKS_DEFAULT_PAYLOAD_MAX_CHARS;
    message = `${message}\n\n${truncateElksPayload(record.body, limit)}`;
  }
  return { message };
}

/**
 * Build one record's serialized request body: the
 * form-encoded `from`/`to`/`message` fields, in that order,
 * each value percent-encoded. The API username and password
 * never appear here — the client alone holds them and sends
 * them as the `Authorization: Basic` header.
 */
export function buildElksMessageBody(from: string, to: string, message: string): string {
  return `from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}&message=${encodeURIComponent(message)}`;
}

/**
 * Validate one record's body and resolve its send form: the
 * message content. Throws `RangeError` on an empty body
 * string — even without the opt-in, the body is the record's
 * payload, and an empty record is a caller bug that must
 * fail closed, never notify as an empty message.
 */
export function resolveElksRecord(
  record: ElksRecord,
  index: number,
  config: Pick<ElksSinkConfig, "includePayload" | "payloadMaxChars">
): { message: string; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`46elks-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { message: resolveElksMessage(record, config).message, index };
}

/**
 * Map one 46elks POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says 46elks could not
 * accept the message right now, not that the payload is
 * poison. Every other non-2xx status (400, 401, 403,
 * 404, and the rest) is a fail-closed message: unknown
 * number, invalid body, bad credentials, or another verdict
 * retrying cannot change. Callers only pass non-2xx
 * statuses here; a 2xx status is a success, not a failure.
 */
export function classifyElksRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * 46elks sink (WR-277). One instance targets one
 * 46elks account, one sender identity, and one recipient
 * number; the caller owns retry / dead-letter policy
 * around `send()` — this class performs one POST attempt
 * per message through the injected client and reports its
 * outcome. Failures throw `ElksSinkError` carrying exactly
 * the failed messages with their retry lanes.
 */
export class ElksSink {
  private readonly cfg: ElksSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: ElksSinkConfig) {
    assertValidElksSinkConfig(config, "ElksSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): ElksSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages by SMS, in input order. Throws
   * `ElksSinkConfigError` when no client was injected
   * or the sender or recipient is missing, and
   * `ElksSinkError` when any message
   * fails (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: ElksRecord[]): Promise<ElksSendResult> {
    const resolved = records.map((r, i) => resolveElksRecord(r, i, this.cfg));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The
      // sender, recipient, and client are
      // not required here, mirroring the sibling sinks'
      // dry-run exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new ElksSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const from = this.cfg.from;
    if (from === undefined) {
      throw new ElksSinkConfigError("no sender configured (set `from` in the sink config)");
    }
    const to = this.cfg.to;
    if (to === undefined) {
      throw new ElksSinkConfigError("no recipient configured (set `to` in the sink config)");
    }
    const url = ELKS_SEND_URL;
    const failedRecords: ElksFailedRecord[] = [];
    let sent = 0;
    for (const record of resolved) {
      try {
        const response = await client.post({
          url,
          body: buildElksMessageBody(from, to, record.message),
        });
        if (response.status >= 200 && response.status < 300) {
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyElksRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toElksFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new ElksSinkError(
        `46elks-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toElksFailedRecord(err: unknown, index: number): ElksFailedRecord {
  const failed: ElksFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
