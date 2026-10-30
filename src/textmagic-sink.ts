/**
 * TextMagic SMS notification delivery sink (WR-272).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's phone. Where the ClickSend sink
 * (WR-268) delivers SMS through ClickSend's `messages`
 * envelope with a Basic-auth header and the Infobip sink
 * (WR-267) delivers through Infobip's account-subdomain
 * API with an `Authorization: App` header, this sink
 * delivers through TextMagic's SMS API: one event is
 * sent as one POST, and TextMagic — not the relay —
 * owns the carrier routing, the delivery, and the
 * retention of the message.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a TextMagic
 * server. The sink owns the relay-side concerns — message
 * targeting, text derivation, payload-inclusion policy,
 * per-message failure mapping — and the injected client
 * owns the wire protocol, including the POST call, the
 * authentication, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://rest.textmagic.com/api/v2/messages",
 *     body: "{\"text\":\"<text>\",\"phones\":[\"<msisdn>\", ...]}" }
 *
 * The client POSTs to that URL, sending `body` verbatim
 * as the request body (a JSON object) and authenticating
 * with the `X-TM-Username` and `X-TM-Key` headers
 * carrying the username + API key pair it alone holds —
 * TextMagic v2's header-auth shape, not Basic or Bearer.
 * Three things about this shape are deliberate, and all
 * follow the sibling sinks:
 *
 * - The username + API key pair is held by the client
 *   alone. The sink never receives it, never places it
 *   in the request, and never logs it: like the ClickSend
 *   sink (WR-268), whose Basic pair the client alone
 *   holds, this sink's request carries no credential at
 *   all — the client adds the `X-TM-Username` and
 *   `X-TM-Key` headers from the pair it alone holds, so
 *   there is nothing in the request for a log line or a
 *   retry queue to leak. This is the opposite of the
 *   Vonage sink (WR-252), whose credentials ride inside
 *   the request body: TextMagic authenticates by header,
 *   so the body carries only routing and content.
 * - The recipients ride in `phones` as an array of E.164
 *   strings: that is TextMagic's fixed message shape —
 *   unlike the ClickSend sink (WR-268), whose `to` is a
 *   single number string, TextMagic takes the recipient
 *   set as a flat array, so a sink that sent a bare
 *   string would be rejected. One POST fans the text out
 *   to every number in the array.
 * - The host is fixed, not configurable: TextMagic is a
 *   single hosted service, so there is no self-hosted
 *   deployment to point at — unlike the Infobip sink
 *   (WR-267), whose host varies per account, a
 *   configurable URL here could only misroute a message
 *   to a server that is not TextMagic.
 *
 * The recipients are configured, not derived from the
 * event. One sink targets one set of recipient numbers.
 * A missing recipient set is a config error, not a
 * resolution fallback: unlike the broker sinks, there is
 * no per-record target to resolve to, so a sink with no
 * recipients has nowhere to deliver and fails closed with
 * `TextMagicSinkConfigError` at send time (dry runs
 * excepted — they need no numbers at all, mirroring the
 * sibling sinks' dry-run exemption for the client). A
 * sender ID (`from`) is out of scope for this item:
 * TextMagic's sender identification is not configured
 * here, and no `from` field is accepted.
 *
 * Message text — derived from the event's own values:
 * the first non-empty value among `subject`, `key`, and
 * `traceId`, in that order. An SMS carries a single text
 * field, so there is no subject/value split like the
 * email sinks: the subject is what the event is about,
 * the key (e.g. aggregate id) is the next most
 * identifying value, and the trace id names the trace
 * that produced the event. An event with none of the
 * values still notifies, with the generic summary
 * `webhook event`: a notification sink that silently
 * dropped sourceless events would hide exactly the
 * deliveries an operator most needs to see, and the
 * recipient numbers — not the text — are the delivery
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
 * the `text` field, not a fenced code block: an SMS
 * renders as-is, and a fence would be noise on a phone
 * screen.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over HTTP status:
 *
 * - a non-2xx POST throws `TextMagicSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says TextMagic could
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
 *   `TextMagicSinkConfigError`, which
 *   `classifyFailure` maps to `non_retryable` (the WR-116
 *   rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for the text field. */
export const TEXTMAGIC_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const TEXTMAGIC_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Fixed TextMagic SMS API endpoint for every message. */
export const TEXTMAGIC_SEND_URL = "https://rest.textmagic.com/api/v2/messages";

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (a JSON object with `text` and a
 * `phones` array) to the fixed SMS endpoint, and
 * authenticates with the `X-TM-Username` and `X-TM-Key`
 * headers carrying the username + API key pair it alone
 * holds. The sink never sees that pair, so the request
 * carries no credential: nothing here can leak into a
 * log line.
 */
export interface TextMagicMessagePostRequest {
  /** Always the fixed TextMagic SMS endpoint. */
  url: string;
  /** The JSON message object, serialized: `text` plus `phones` (an array of E.164 strings). */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse TextMagic's response body.
 */
export interface TextMagicMessagePostResponse {
  /** The HTTP status of the POST (e.g. 201, 429, 503). */
  status: number;
}

/**
 * The injected TextMagic message client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one message per call, sending
 * `body` verbatim as the request body (the JSON object
 * with `text` and `phones`),
 * setting the `application/json` content type, and
 * authenticating with the `X-TM-Username` and `X-TM-Key`
 * headers carrying its own username + API key pair — which
 * the sink never sees.
 */
export interface TextMagicMessageClient {
  post(request: TextMagicMessagePostRequest): Promise<TextMagicMessagePostResponse>;
}

/**
 * Configuration for one TextMagic sink. The client is
 * injected: without one, `send()` throws
 * `TextMagicSinkConfigError` (dry runs excepted — they need
 * no client at all). A missing recipient set is likewise
 * a config error at send time (dry runs excepted): there
 * is no per-record target to fall back to. The username +
 * API key pair is deliberately absent from this config:
 * the client alone holds it and sends it as the
 * `X-TM-Username` and `X-TM-Key` headers. No sender ID is
 * configured here: `from` is out of scope for this item.
 */
export interface TextMagicSinkConfig {
  /**
   * The recipient numbers (`phones`): every message is
   * fanned out to each number in this array, carried as
   * the flat `phones` array (TextMagic v2 takes an array
   * of E.164 strings, not a bare string). Each entry must
   * be a non-empty string, free of NUL and whitespace,
   * when set; a missing recipient set throws
   * `TextMagicSinkConfigError` at send time.
   */
  phones?: string[];
  /**
   * The TextMagic message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `TextMagicMessageClient` and alone holds the
   * username + API key pair. Required for real sends; a missing
   * client is a config error, not a silent no-op.
   */
  client?: TextMagicMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including text derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The recipient set and client are
   * not required in dry-run mode, mirroring the sibling
   * sinks' dry-run exemption.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the message text appends
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
export interface TextMagicRecord {
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

/** One failed message, with its retry lane already mapped. */
export interface TextMagicFailedRecord {
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
export interface TextMagicSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-264). */
export interface TextMagicSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for TextMagic send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on TextMagic's server and are *not* in
 * `failedRecords`.
 */
export class TextMagicSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: TextMagicFailedRecord[];
  constructor(message: string, failedRecords: TextMagicFailedRecord[]) {
    super(message);
    this.name = "TextMagicSinkError";
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
export class TextMagicSinkConfigError extends TextMagicSinkError {
  constructor(reason: string) {
    super(`textmagic-sink: ${reason}`, []);
    this.name = "TextMagicSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing recipient set is *not* a shape error: it is a
 * config error raised at send time
 * (`TextMagicSinkConfigError`), so a sink built before its
 * numbers are known still fails closed at send time rather
 * than crashing at construction. A present `phones` value
 * must be a non-empty array of non-empty strings, each free
 * of NUL and whitespace.
 */
export function assertValidTextMagicSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is TextMagicSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  const phones = c.phones;
  if (phones !== undefined) {
    if (
      !Array.isArray(phones) ||
      phones.length === 0 ||
      phones.some(
        (p) =>
          typeof p !== "string" || p === "" || p.includes("\0") || /\s/.test(p)
      )
    ) {
      throw new RangeError(
        at("`phones` must be a non-empty array of non-empty strings, free of NUL and whitespace, when set")
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
 * Derive one record's message text: the first non-empty
 * value among `subject`, `key`, and `traceId`, in that
 * order. Falls back to the generic `webhook event` summary
 * when the record carries none — a notification sink must
 * not silently drop sourceless events, and the recipient
 * numbers (not the text) are the delivery contract.
 */
export function resolveTextMagicText(record: TextMagicRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return TEXTMAGIC_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a phone.
 */
export function truncateTextMagicPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's notification text. Only under the
 * `includePayload` opt-in does the text append the event
 * body verbatim after a blank line, truncated to
 * `payloadMaxChars` (default 2000). Without the opt-in, the
 * text is the summary alone: event bodies routinely carry
 * PII and must never leak into a notification by default.
 * The payload is appended as plain text inside the `text`
 * field, not a fenced code block: an SMS renders as-is,
 * and a fence would be noise on a phone screen.
 */
export function resolveTextMagicNotification(
  record: TextMagicRecord,
  config: Pick<TextMagicSinkConfig, "includePayload" | "payloadMaxChars">
): { text: string } {
  let text = resolveTextMagicText(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? TEXTMAGIC_DEFAULT_PAYLOAD_MAX_CHARS;
    text = `${text}\n\n${truncateTextMagicPayload(record.body, limit)}`;
  }
  return { text };
}

/**
 * Build one record's serialized request body: the JSON
 * object with `text` and `phones` (an array of E.164
 * strings), in that order. The username + API key pair
 * never appears here — the client alone holds it and
 * sends it as the `X-TM-Username` and `X-TM-Key` headers.
 */
export function buildTextMagicMessageBody(text: string, phones: string[]): string {
  return JSON.stringify({ text, phones });
}

/**
 * Validate one record's body and resolve its send form: the
 * notification text. Throws `RangeError` on an empty body
 * string — even without the opt-in, the body is the record's
 * payload, and an empty record is a caller bug that must
 * fail closed, never notify as an empty message.
 */
export function resolveTextMagicRecord(
  record: TextMagicRecord,
  index: number,
  config: Pick<TextMagicSinkConfig, "includePayload" | "payloadMaxChars">
): { notification: { text: string }; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`textmagic-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { notification: resolveTextMagicNotification(record, config), index };
}

/**
 * Map one TextMagic POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says TextMagic could not
 * accept the message right now, not that the payload is
 * poison. Every other non-2xx status (400, 401, 403,
 * 404, and the rest) is a fail-closed message: unknown
 * number, invalid body, bad credentials, or another verdict
 * retrying cannot change. Callers only pass non-2xx
 * statuses here; a 2xx status is a success, not a failure.
 */
export function classifyTextMagicRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * TextMagic sink (WR-272). One instance targets one
 * TextMagic account and one set of recipient numbers; the
 * caller owns retry / dead-letter policy around `send()` —
 * this class performs one POST attempt per message
 * through the injected client and reports its outcome.
 * Failures throw `TextMagicSinkError` carrying exactly the
 * failed messages with their retry lanes.
 */
export class TextMagicSink {
  private readonly cfg: TextMagicSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: TextMagicSinkConfig) {
    assertValidTextMagicSinkConfig(config, "TextMagicSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): TextMagicSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages by SMS, in input order. Throws
   * `TextMagicSinkConfigError` when no client was injected
   * or the recipient set is missing, and
   * `TextMagicSinkError` when any message
   * fails (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: TextMagicRecord[]): Promise<TextMagicSendResult> {
    const resolved = records.map((r, i) => resolveTextMagicRecord(r, i, this.cfg));
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
      throw new TextMagicSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const phones = this.cfg.phones;
    if (phones === undefined) {
      throw new TextMagicSinkConfigError("no recipients configured (set `phones` in the sink config)");
    }
    const url = TEXTMAGIC_SEND_URL;
    const failedRecords: TextMagicFailedRecord[] = [];
    let sent = 0;
    for (const record of resolved) {
      try {
        const response = await client.post({
          url,
          body: buildTextMagicMessageBody(record.notification.text, phones),
        });
        if (response.status >= 200 && response.status < 300) {
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyTextMagicRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toTextMagicFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new TextMagicSinkError(
        `textmagic-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toTextMagicFailedRecord(err: unknown, index: number): TextMagicFailedRecord {
  const failed: TextMagicFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
