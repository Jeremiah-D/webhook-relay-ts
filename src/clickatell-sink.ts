/**
 * Clickatell SMS notification delivery sink (WR-274).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's phone. Where the ClickSend sink
 * (WR-268) delivers SMS through ClickSend's `messages`
 * envelope with a Basic-auth header and the TextMagic sink
 * (WR-272) delivers through TextMagic's SMS API with
 * `X-TM-Username` and `X-TM-Key` headers, this sink
 * delivers through Clickatell's platform API: one event
 * is sent as one POST, and Clickatell — not the relay —
 * owns the carrier routing, the delivery, and the
 * retention of the message.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Clickatell
 * server. The sink owns the relay-side concerns — message
 * targeting, content derivation, payload-inclusion policy,
 * per-message failure mapping — and the injected client
 * owns the wire protocol, including the POST call, the
 * authentication, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://platform.clickatell.com/messages",
 *     body: "{\"content\":\"<content>\",\"to\":[\"<msisdn>\", ...]}" }
 *
 * The client POSTs to that URL, sending `body` verbatim
 * as the request body (a JSON object) and authenticating
 * with an `Authorization` header carrying the bare API key
 * — no Bearer or Basic scheme prefix, which is Clickatell's
 * header-auth shape. Two things about this shape are
 * deliberate, and both follow the sibling sinks:
 *
 * - The API key is held by the client alone. The sink
 *   never receives it, never places it in the request,
 *   and never logs it: like the TextMagic sink (WR-272),
 *   whose header pair the client alone holds, this sink's
 *   handed request carries no credential at all — the
 *   client adds the bare-key `Authorization` header from
 *   the key it alone holds, so there is nothing in the
 *   handed request for a log line or a retry queue to
 *   leak. This is the opposite of the Vonage sink
 *   (WR-252), whose credentials ride inside the request
 *   body: Clickatell authenticates by header, so the body
 *   carries only routing and content.
 * - The host is fixed, not configurable: Clickatell is a
 *   single hosted service, so there is no self-hosted
 *   deployment to point at — unlike the Infobip sink
 *   (WR-267), whose host varies per account, a
 *   configurable URL here could only misroute a message
 *   to a server that is not Clickatell.
 *
 * This sink is orthogonal to the TextMagic sink (WR-272):
 * TextMagic posts a `text`/`phones` envelope with the
 * `X-TM-Username` and `X-TM-Key` header pair, while
 * Clickatell posts a flat `content`/`to` envelope with a
 * single bare-key `Authorization` header. It is likewise
 * distinct from the ClickSend sink (WR-268): ClickSend
 * posts a `messages`/`body` envelope with Basic auth and
 * a single `to` string, while Clickatell posts a flat
 * envelope with a `to` array of E.164 strings and a bare
 * key header.
 *
 * The recipients are configured, not derived from the
 * event. One sink targets one set of recipient numbers.
 * A missing recipient set is a config error, not a
 * resolution fallback: unlike the broker sinks, there is
 * no per-record target to resolve to, so a sink with no
 * recipients has nowhere to deliver and fails closed with
 * `ClickatellSinkConfigError` at send time (dry runs
 * excepted — they need no numbers at all, mirroring the
 * sibling sinks' dry-run exemption for the client). A
 * sender ID (`from`) is out of scope for this item:
 * Clickatell's sender identification is not configured
 * here, and no `from` field is accepted.
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
 * recipient numbers — not the content — are the delivery
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
 * the `content` field, not a fenced code block: an SMS
 * renders as-is, and a fence would be noise on a phone
 * screen.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over HTTP status:
 *
 * - a non-2xx POST throws `ClickatellSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Clickatell could
 *   not accept the message right now, not that the payload
 *   is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (unknown number, invalid body, bad
 *   credentials): retrying them burns the retry budget
 *   for nothing, and rerouting them elsewhere would text
 *   numbers the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client or recipient set throws
 *   `ClickatellSinkConfigError`, which `classifyFailure`
 *   maps to `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for the content field. */
export const CLICKATELL_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const CLICKATELL_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Fixed Clickatell platform API endpoint for every message. */
export const CLICKATELL_SEND_URL = "https://platform.clickatell.com/messages";

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (a JSON object with `content` and a
 * `to` array) to the fixed messages endpoint, and
 * authenticates with an `Authorization` header carrying
 * the bare API key it alone holds — no Bearer or Basic
 * scheme prefix. The sink never sees that key, so the
 * request carries no credential: nothing here can leak
 * into a log line.
 */
export interface ClickatellMessagePostRequest {
  /** Always the fixed Clickatell messages endpoint. */
  url: string;
  /** The JSON message object, serialized: `content` plus `to` (an array of E.164 strings). */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse Clickatell's response body.
 */
export interface ClickatellMessagePostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
}

/**
 * The injected Clickatell message client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one message per call, sending
 * `body` verbatim as the request body (the JSON object
 * with `content` and `to`), setting the `application/json`
 * content type, and authenticating with an `Authorization`
 * header carrying its own bare API key — which the sink
 * never sees.
 */
export interface ClickatellMessageClient {
  post(request: ClickatellMessagePostRequest): Promise<ClickatellMessagePostResponse>;
}

/**
 * Configuration for one Clickatell sink. The client is
 * injected: without one, `send()` throws
 * `ClickatellSinkConfigError` (dry runs excepted — they need
 * no client at all). A missing recipient set is likewise
 * a config error at send time (dry runs excepted): there
 * is no per-record target to fall back to. The API key is
 * deliberately absent from this config: the client alone
 * holds it and sends it as the bare-key `Authorization`
 * header. No sender ID is configured here: `from` is out
 * of scope for this item.
 */
export interface ClickatellSinkConfig {
  /**
   * The recipient numbers (`to`): every message is
   * fanned out to each number in this array, carried as
   * the flat `to` array (Clickatell takes an array of
   * E.164 strings, not a bare string). Each entry must
   * be a non-empty string, free of NUL and whitespace,
   * when set; a missing recipient set throws
   * `ClickatellSinkConfigError` at send time.
   */
  to?: string[];
  /**
   * The Clickatell message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `ClickatellMessageClient` and alone holds the
   * API key. Required for real sends; a missing client is a
   * config error, not a silent no-op.
   */
  client?: ClickatellMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including content derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The recipient set and client are
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
export interface ClickatellRecord {
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
export interface ClickatellFailedRecord {
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
export interface ClickatellSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-274). */
export interface ClickatellSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Clickatell send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on Clickatell's server and are *not* in
 * `failedRecords`.
 */
export class ClickatellSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: ClickatellFailedRecord[];
  constructor(message: string, failedRecords: ClickatellFailedRecord[]) {
    super(message);
    this.name = "ClickatellSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, or the recipient set is missing.
 * A config problem, not a downstream verdict, so the
 * retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class ClickatellSinkConfigError extends ClickatellSinkError {
  constructor(reason: string) {
    super(`clickatell-sink: ${reason}`, []);
    this.name = "ClickatellSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing recipient set is *not* a shape error: it is a
 * config error raised at send time
 * (`ClickatellSinkConfigError`), so a sink built before its
 * numbers are known still fails closed at send time rather
 * than crashing at construction. A present `to` value
 * must be a non-empty array of non-empty strings, each free
 * of NUL and whitespace.
 */
export function assertValidClickatellSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is ClickatellSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  const to = c.to;
  if (to !== undefined) {
    if (
      !Array.isArray(to) ||
      to.length === 0 ||
      to.some(
        (p) =>
          typeof p !== "string" || p === "" || p.includes("\0") || /\s/.test(p)
      )
    ) {
      throw new RangeError(
        at("`to` must be a non-empty array of non-empty strings, free of NUL and whitespace, when set")
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
 * numbers (not the content) are the delivery contract.
 */
export function resolveClickatellContent(record: ClickatellRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return CLICKATELL_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a phone.
 */
export function truncateClickatellPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's notification content. Only under the
 * `includePayload` opt-in does the content append the event
 * body verbatim after a blank line, truncated to
 * `payloadMaxChars` (default 2000). Without the opt-in, the
 * content is the summary alone: event bodies routinely carry
 * PII and must never leak into a notification by default.
 * The payload is appended as plain text inside the `content`
 * field, not a fenced code block: an SMS renders as-is,
 * and a fence would be noise on a phone screen.
 */
export function resolveClickatellNotification(
  record: ClickatellRecord,
  config: Pick<ClickatellSinkConfig, "includePayload" | "payloadMaxChars">
): { content: string } {
  let content = resolveClickatellContent(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? CLICKATELL_DEFAULT_PAYLOAD_MAX_CHARS;
    content = `${content}\n\n${truncateClickatellPayload(record.body, limit)}`;
  }
  return { content };
}

/**
 * Build one record's serialized request body: the JSON
 * object with `content` and `to` (an array of E.164
 * strings), in that order. The API key never appears here —
 * the client alone holds it and sends it as the bare-key
 * `Authorization` header.
 */
export function buildClickatellMessageBody(content: string, to: string[]): string {
  return JSON.stringify({ content, to });
}

/**
 * Validate one record's body and resolve its send form: the
 * notification content. Throws `RangeError` on an empty body
 * string — even without the opt-in, the body is the record's
 * payload, and an empty record is a caller bug that must
 * fail closed, never notify as an empty message.
 */
export function resolveClickatellRecord(
  record: ClickatellRecord,
  index: number,
  config: Pick<ClickatellSinkConfig, "includePayload" | "payloadMaxChars">
): { notification: { content: string }; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`clickatell-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { notification: resolveClickatellNotification(record, config), index };
}

/**
 * Map one Clickatell POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says Clickatell could not
 * accept the message right now, not that the payload is
 * poison. Every other non-2xx status (400, 401, 403,
 * 404, and the rest) is a fail-closed message: unknown
 * number, invalid body, bad credentials, or another verdict
 * retrying cannot change. Callers only pass non-2xx
 * statuses here; a 2xx status is a success, not a failure.
 */
export function classifyClickatellRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Clickatell sink (WR-274). One instance targets one
 * Clickatell account and one set of recipient numbers; the
 * caller owns retry / dead-letter policy around `send()` —
 * this class performs one POST attempt per message
 * through the injected client and reports its outcome.
 * Failures throw `ClickatellSinkError` carrying exactly the
 * failed messages with their retry lanes.
 */
export class ClickatellSink {
  private readonly cfg: ClickatellSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: ClickatellSinkConfig) {
    assertValidClickatellSinkConfig(config, "ClickatellSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): ClickatellSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages by SMS, in input order. Throws
   * `ClickatellSinkConfigError` when no client was injected
   * or the recipient set is missing, and
   * `ClickatellSinkError` when any message
   * fails (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: ClickatellRecord[]): Promise<ClickatellSendResult> {
    const resolved = records.map((r, i) => resolveClickatellRecord(r, i, this.cfg));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The
      // recipient set and client are
      // not required here, mirroring the sibling sinks'
      // dry-run exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new ClickatellSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const to = this.cfg.to;
    if (to === undefined) {
      throw new ClickatellSinkConfigError("no recipients configured (set `to` in the sink config)");
    }
    const url = CLICKATELL_SEND_URL;
    const failedRecords: ClickatellFailedRecord[] = [];
    let sent = 0;
    for (const record of resolved) {
      try {
        const response = await client.post({
          url,
          body: buildClickatellMessageBody(record.notification.content, to),
        });
        if (response.status >= 200 && response.status < 300) {
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyClickatellRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toClickatellFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new ClickatellSinkError(
        `clickatell-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toClickatellFailedRecord(err: unknown, index: number): ClickatellFailedRecord {
  const failed: ClickatellFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
