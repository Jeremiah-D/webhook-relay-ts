/**
 * Twilio SMS notification delivery sink (WR-247).
 *
 * Some downstreams are not queues, streams, or topics at all:
 * they are a human's phone. Where the Matrix sink (WR-246)
 * delivers to a Matrix room, this sink delivers to a phone
 * number by SMS: one event is posted as one message to the
 * Twilio Messages API, and Twilio — not the relay — owns
 * the number, the delivery, and the retention of the
 * message.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Twilio
 * server. The sink owns the relay-side concerns — message
 * targeting, text derivation, payload-inclusion policy,
 * per-message failure mapping — and the injected client
 * owns the wire protocol, including the POST call, the
 * authentication, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://api.twilio.com/2010-04-01/Accounts/{AccountSid}/Messages.json",
 *     body: "To=<to>&From=<from>&Body=<body>" }
 *
 * The client POSTs `body` verbatim as the request body
 * (an `application/x-www-form-urlencoded` object, not
 * JSON) and authenticates with HTTP Basic auth. Two
 * things about this shape differ from the JSON sinks, and
 * both are deliberate:
 *
 * - The Account SID appears in the URL path only, never
 *   in the body: Twilio routes by the path, and a SID in
 *   the body would be a second, redundant copy of an
 *   account identifier in a field Twilio does not read
 *   for routing.
 * - The auth token is held by the client alone. The sink
 *   never receives it, never places it in the request, and
 *   never logs it: unlike the Pushover sink, whose
 *   credentials ride inside the request body, the Twilio
 *   sink's request carries no credential at all — the
 *   client adds the `Authorization: Basic` header from
 *   the token it alone holds, so there is nothing in the
 *   request for a log line or a retry queue to leak.
 *
 * The host is fixed, not configurable: Twilio is a single
 * hosted service, so there is no self-hosted deployment to
 * point at — unlike the Matrix sink, whose homeserver
 * varies, a configurable URL here could only misroute a
 * message to a server that is not Twilio. The account,
 * the sender, and the recipient are configured: one sink
 * targets one Twilio account, one sender number, and one
 * recipient number. A missing account SID, sender, or
 * recipient is a config error, not a resolution fallback:
 * unlike the broker sinks, there is no per-record target
 * to resolve to, so a sink with no recipient has nowhere
 * to deliver and fails closed with `TwilioSinkConfigError`
 * at send time (dry runs excepted — they need no numbers
 * at all, mirroring the sibling sinks' dry-run exemption
 * for the client).
 *
 * Message text — derived from the event's own values.
 * Twilio's message carries a single text field, so where
 * the Pushover and Pushbullet sinks split the text into a
 * title and a body, this sink folds the derivation chain
 * into one: the first non-empty value among `subject`,
 * `key`, and `traceId`, in that order. The subject is what
 * the event is about, the key (e.g. aggregate id) is the
 * next most identifying value, and the trace id names the
 * trace that produced the event. An event with none of the
 * values still notifies, with the generic summary `webhook
 * event`: a notification sink that silently dropped
 * sourceless events would hide exactly the deliveries an
 * operator most needs to see, and the recipient number —
 * not the text — is the delivery contract here, so no
 * invented target is at stake.
 *
 * Payload inclusion — by default the message carries the
 * summary only, never the full payload: event bodies
 * routinely carry PII, secrets, or customer data, and an
 * SMS is a far wider audience than a queue or a stream.
 * Opting into `includePayload` appends the body verbatim
 * after a blank line, truncated to `payloadMaxChars`
 * characters (default 2000) with a truncation marker —
 * the opt-in is explicit, and the truncation is
 * unconditional, so even an opted-in body cannot flood a
 * phone or blow past Twilio's message limits. The body is
 * appended as plain text inside the `Body` field, not a
 * fenced code block: an SMS renders as-is, and a fence
 * would be noise on a phone screen.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over HTTP status:
 *
 * - a non-2xx POST throws `TwilioSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Twilio could
 *   not accept the message right now, not that the
 *   payload is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (unknown account SID or number, invalid
 *   body): retrying them burns the retry budget for
 *   nothing, and rerouting them elsewhere would text a
 *   number the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client, account SID, sender, or recipient
 *   throws `TwilioSinkConfigError`, which
 *   `classifyFailure` maps to `non_retryable` (the WR-116
 *   rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for the text field. */
export const TWILIO_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const TWILIO_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Fixed Twilio API host for every message. */
export const TWILIO_API_HOST = "https://api.twilio.com";

/**
 * Build the single Twilio Messages endpoint for an
 * account. Fixed host, account-scoped path: the Account
 * SID rides in the URL path only, never in the request
 * body, and is percent-encoded so a SID with reserved
 * characters cannot break the path.
 */
export function twilioMessagesUrl(accountSid: string): string {
  return `${TWILIO_API_HOST}/2010-04-01/Accounts/${encodeURIComponent(accountSid)}/Messages.json`;
}

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (an `application/x-www-form-urlencoded`
 * object with `To`, `From`, and `Body` fields) to `url`,
 * and authenticates with an `Authorization: Basic` header
 * carrying an auth token it alone holds. The sink never
 * sees that token, so the request carries no credential:
 * nothing here can leak into a log line. The Account SID
 * appears in the URL path only, never in the body.
 */
export interface TwilioMessagePostRequest {
  /** Always the fixed Twilio Messages endpoint for the configured account. */
  url: string;
  /** The urlencoded message object, serialized: `To`, `From`, `Body`. */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse Twilio's response body.
 */
export interface TwilioMessagePostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
}

/**
 * The injected Twilio message client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one message per call, sending
 * `body` verbatim as the request body (the urlencoded
 * object with `To`, `From`, and `Body`), setting the
 * `application/x-www-form-urlencoded` content type, and
 * authenticating with its own auth token — which the sink
 * never sees.
 */
export interface TwilioMessageClient {
  post(request: TwilioMessagePostRequest): Promise<TwilioMessagePostResponse>;
}

/**
 * Configuration for one Twilio sink. The client is
 * injected: without one, `send()` throws
 * `TwilioSinkConfigError` (dry runs excepted — they need
 * no client at all). A missing account SID, sender, or
 * recipient is likewise a config error at send time (dry
 * runs excepted): there is no per-record target to fall
 * back to.
 */
export interface TwilioSinkConfig {
  /**
   * Twilio Account SID: the account every message is sent
   * from. Placed into the URL path at send time, never
   * into the body and never logged. Must be a non-empty
   * string, free of NUL and whitespace, when set; a
   * missing SID throws `TwilioSinkConfigError` at send
   * time, never a silent no-op.
   */
  accountSid?: string;
  /**
   * The sender number (`From`): the number every message
   * appears to come from. Must be a non-empty string, free
   * of NUL and whitespace, when set; a missing sender
   * throws `TwilioSinkConfigError` at send time.
   */
  from?: string;
  /**
   * The recipient number (`To`): the recipient of every
   * message from this sink. Must be a non-empty string,
   * free of NUL and whitespace, when set; a missing
   * recipient throws `TwilioSinkConfigError` at send time.
   */
  to?: string;
  /**
   * The Twilio message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `TwilioMessageClient` and alone holds the
   * auth token. Required for real sends; a missing client
   * is a config error, not a silent no-op.
   */
  client?: TwilioMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including text derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The account SID, numbers, and client are not required in
   * dry-run mode, mirroring the sibling sinks' dry-run
   * exemption.
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
export interface TwilioRecord {
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
export interface TwilioFailedRecord {
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
   * non-2xx status is a fail-closed message (unknown account
   * SID or number, invalid body).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface TwilioSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-247). */
export interface TwilioSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Twilio send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on Twilio's server and are *not* in
 * `failedRecords`.
 */
export class TwilioSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: TwilioFailedRecord[];
  constructor(message: string, failedRecords: TwilioFailedRecord[]) {
    super(message);
    this.name = "TwilioSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, or the account SID, sender, or
 * recipient is missing. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class TwilioSinkConfigError extends TwilioSinkError {
  constructor(reason: string) {
    super(`twilio-sink: ${reason}`, []);
    this.name = "TwilioSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing account SID, sender, or recipient is *not* a shape
 * error: it is a config error raised at send time
 * (`TwilioSinkConfigError`), so a sink built before its
 * numbers are known still fails closed at send time rather
 * than crashing at construction. A present SID or number must
 * be a non-empty string, free of NUL and whitespace.
 */
export function assertValidTwilioSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is TwilioSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  for (const field of ["accountSid", "from", "to"] as const) {
    const value = c[field];
    if (value !== undefined) {
      if (
        typeof value !== "string" ||
        value === "" ||
        (value as string).includes("\0") ||
        /\s/.test(value as string)
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
 * Derive one record's message text: the first non-empty
 * value among `subject`, `key`, and `traceId`, in that
 * order. Falls back to the generic `webhook event` summary
 * when the record carries none — a notification sink must
 * not silently drop sourceless events, and the recipient
 * number (not the text) is the delivery contract.
 */
export function resolveTwilioText(record: TwilioRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return TWILIO_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a phone.
 */
export function truncateTwilioPayload(body: string, limit: number): string {
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
 * The body is appended as plain text inside the `Body`
 * field, not a fenced code block: an SMS renders as-is,
 * and a fence would be noise on a phone screen.
 */
export function resolveTwilioNotification(
  record: TwilioRecord,
  config: Pick<TwilioSinkConfig, "includePayload" | "payloadMaxChars">
): { text: string } {
  let text = resolveTwilioText(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? TWILIO_DEFAULT_PAYLOAD_MAX_CHARS;
    text = `${text}\n\n${truncateTwilioPayload(record.body, limit)}`;
  }
  return { text };
}

/**
 * Build one record's serialized request body: the
 * urlencoded object with `To`, `From`, and `Body` fields,
 * in that order. Values are percent-encoded, so a text
 * with `&`, `=`, or newlines cannot break the form. The
 * Account SID never appears here — it rides in the URL
 * path only — and neither does the auth token, which the
 * client alone holds.
 */
export function buildTwilioFormBody(to: string, from: string, text: string): string {
  const encode = (value: string) => encodeURIComponent(value);
  return `To=${encode(to)}&From=${encode(from)}&Body=${encode(text)}`;
}

/**
 * Validate one record's body and resolve its send form: the
 * notification text. Throws `RangeError` on an empty body
 * string — even without the opt-in, the body is the record's
 * payload, and an empty record is a caller bug that must
 * fail closed, never notify as an empty message.
 */
export function resolveTwilioRecord(
  record: TwilioRecord,
  index: number,
  config: Pick<TwilioSinkConfig, "includePayload" | "payloadMaxChars">
): { notification: { text: string }; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`twilio-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { notification: resolveTwilioNotification(record, config), index };
}

/**
 * Map one Twilio POST `statusCode` onto its retry lane under
 * the WR-210 rules: 429 and every 5xx are transient and so
 * retryable — a rate limit says Twilio could not accept
 * the message right now, not that the payload is poison.
 * Every other non-2xx status (400, 401, 403, 404, and the
 * rest) is a fail-closed message: unknown account SID or
 * number, invalid body, or another verdict retrying cannot
 * change. Callers only pass non-2xx statuses here; a 2xx
 * status is a success, not a failure.
 */
export function classifyTwilioRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Twilio sink (WR-247). One instance targets one Twilio
 * account, one sender number, and one recipient number; the
 * caller owns retry/dead-letter policy around `send()` —
 * this class performs one POST attempt per message through
 * the injected client and reports its outcome. Failures
 * throw `TwilioSinkError` carrying exactly the failed
 * messages with their retry lanes.
 */
export class TwilioSink {
  private readonly cfg: TwilioSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: TwilioSinkConfig) {
    assertValidTwilioSinkConfig(config, "TwilioSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): TwilioSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages by SMS, in input order. Throws
   * `TwilioSinkConfigError` when no client was injected or
   * the account SID, sender, or recipient is missing, and
   * `TwilioSinkError` when any message fails (carrying
   * exactly the failed messages with their retry lanes; both
   * counted in stats before throwing, so the counters stay
   * honest even for callers that only inspect stats).
   */
  async send(records: TwilioRecord[]): Promise<TwilioSendResult> {
    const resolved = records.map((r, i) => resolveTwilioRecord(r, i, this.cfg));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The
      // account SID, numbers, and client are not required here,
      // mirroring the sibling sinks' dry-run exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new TwilioSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const accountSid = this.cfg.accountSid;
    if (accountSid === undefined) {
      throw new TwilioSinkConfigError("no account SID configured (set `accountSid` in the sink config)");
    }
    const from = this.cfg.from;
    if (from === undefined) {
      throw new TwilioSinkConfigError("no sender configured (set `from` in the sink config)");
    }
    const to = this.cfg.to;
    if (to === undefined) {
      throw new TwilioSinkConfigError("no recipient configured (set `to` in the sink config)");
    }
    const failedRecords: TwilioFailedRecord[] = [];
    let sent = 0;
    for (const record of resolved) {
      try {
        const response = await client.post({
          url: twilioMessagesUrl(accountSid),
          body: buildTwilioFormBody(to, from, record.notification.text),
        });
        if (response.status >= 200 && response.status < 300) {
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyTwilioRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toTwilioFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new TwilioSinkError(
        `twilio-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toTwilioFailedRecord(err: unknown, index: number): TwilioFailedRecord {
  const failed: TwilioFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
