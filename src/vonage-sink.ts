/**
 * Vonage SMS notification delivery sink (WR-252).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's phone. Where the Twilio sink
 * (WR-247) delivers to a phone number by SMS through the
 * Twilio Messages API, this sink delivers to a phone
 * number by SMS through the Vonage SMS API — a second
 * SMS vendor, and a second SMS authentication shape.
 * Vonage — not the relay — owns the number, the
 * delivery, and the retention of the message.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Vonage
 * server. The sink owns the relay-side concerns — message
 * targeting, text derivation, payload-inclusion policy,
 * per-message failure mapping — and the injected client
 * owns the wire protocol, including the POST call, the
 * authentication, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://rest.nexmo.com/sms/json",
 *     body: "from=<from>&to=<to>&text=<text>" }
 *
 * The client POSTs to that fixed URL, sending the form
 * body as `application/x-www-form-urlencoded`. On the
 * wire the form is `api_key`, `api_secret`, `from`, `to`,
 * `text`, in that order — and that is where the Vonage
 * shape differs from the Twilio shape, deliberately:
 *
 * - Twilio authenticates with an `Authorization: Basic`
 *   header and routes by an Account SID in the URL path;
 *   Vonage authenticates with a key and a secret carried
 *   inside the request body itself, and routes by the
 *   `from`/`to` form fields — there is no account id in
 *   the path and no header credential.
 * - The key and secret are held by the client alone. The
 *   sink never receives them, never places them in the
 *   request it hands the client, and never logs them: the
 *   client inserts `api_key` and `api_secret` into the
 *   form before POSTing, from the credentials it alone
 *   holds. So the request the sink produces carries no
 *   credential at all — unlike the Pushover sink, whose
 *   credentials ride in the request body the sink itself
 *   builds — and there is nothing in the sink's request
 *   for a log line or a retry queue to leak. The sink's
 *   body contributes only the trailing three fields
 *   (`from`, `to`, `text`); the leading two are the
 *   client's alone.
 *
 * The host is fixed, not configurable: Vonage is a single
 * hosted service, so there is no self-hosted deployment to
 * point at — a configurable URL here could only misroute
 * a message to a server that is not Vonage. The sender
 * and the recipient are configured: one sink targets one
 * sender number and one recipient number. A missing
 * sender or recipient is a config error, not a resolution
 * fallback: unlike the broker sinks, there is no
 * per-record target to resolve to, so a sink with no
 * recipient has nowhere to deliver and fails closed with
 * `VonageSinkConfigError` at send time (dry runs
 * excepted — they need no numbers at all, mirroring the
 * sibling sinks' dry-run exemption for the client).
 *
 * Message text — derived from the event's own values.
 * Vonage's message carries a single text field, so where
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
 * phone or blow past Vonage's message limits. The body is
 * appended as plain text inside the `text` field, not a
 * fenced code block: an SMS renders as-is, and a fence
 * would be noise on a phone screen.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over HTTP status:
 *
 * - a non-2xx POST throws `VonageSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Vonage could
 *   not accept the message right now, not that the
 *   payload is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (unknown number, invalid body, bad
 *   credentials): retrying them burns the retry budget
 *   for nothing, and rerouting them elsewhere would text
 *   a number the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client, sender, or recipient
 *   throws `VonageSinkConfigError`, which
 *   `classifyFailure` maps to `non_retryable` (the WR-116
 *   rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for the text field. */
export const VONAGE_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const VONAGE_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Fixed Vonage SMS API endpoint for every message. */
export const VONAGE_SMS_URL = "https://rest.nexmo.com/sms/json";

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs to `url`,
 * sending `body` plus the `api_key` and `api_secret`
 * fields it alone holds as the request body (an
 * `application/x-www-form-urlencoded` object with
 * `api_key`, `api_secret`, `from`, `to`, and `text`, in
 * that order). The sink never sees the key or the secret,
 * so the request carries no credential: nothing here can
 * leak into a log line.
 */
export interface VonageMessagePostRequest {
  /** Always the fixed Vonage SMS endpoint. */
  url: string;
  /** The urlencoded message object, serialized: `from`, `to`, `text` (the client prepends `api_key` and `api_secret`). */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse Vonage's response body.
 */
export interface VonageMessagePostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
}

/**
 * The injected Vonage message client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one message per call, sending
 * the urlencoded object (with `api_key` and `api_secret`
 * from the credentials it alone holds, plus the sink's
 * `from`, `to`, and `text` fields) to the fixed SMS
 * endpoint, with the `application/x-www-form-urlencoded`
 * content type.
 */
export interface VonageMessageClient {
  post(request: VonageMessagePostRequest): Promise<VonageMessagePostResponse>;
}

/**
 * Configuration for one Vonage sink. The client is
 * injected: without one, `send()` throws
 * `VonageSinkConfigError` (dry runs excepted — they need
 * no client at all). A missing sender or recipient is
 * likewise a config error at send time (dry runs
 * excepted): there is no per-record target to fall back
 * to. The API key and secret are deliberately absent from
 * this config: the client alone holds them and inserts
 * them into the form body.
 */
export interface VonageSinkConfig {
  /**
   * The sender number (`from`): the number every message
   * appears to come from. Must be a non-empty string, free
   * of NUL and whitespace, when set; a missing sender
   * throws `VonageSinkConfigError` at send time.
   */
  from?: string;
  /**
   * The recipient number (`to`): the recipient of every
   * message from this sink. Must be a non-empty string,
   * free of NUL and whitespace, when set; a missing
   * recipient throws `VonageSinkConfigError` at send time.
   */
  to?: string;
  /**
   * The Vonage message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `VonageMessageClient` and alone holds the
   * API key and secret. Required for real sends; a missing
   * client is a config error, not a silent no-op.
   */
  client?: VonageMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including text derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The sender, recipient, and client are not required in
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
export interface VonageRecord {
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
export interface VonageFailedRecord {
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
export interface VonageSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-252). */
export interface VonageSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Vonage send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on Vonage's server and are *not* in
 * `failedRecords`.
 */
export class VonageSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: VonageFailedRecord[];
  constructor(message: string, failedRecords: VonageFailedRecord[]) {
    super(message);
    this.name = "VonageSinkError";
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
export class VonageSinkConfigError extends VonageSinkError {
  constructor(reason: string) {
    super(`vonage-sink: ${reason}`, []);
    this.name = "VonageSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing sender or recipient is *not* a shape error: it is a
 * config error raised at send time
 * (`VonageSinkConfigError`), so a sink built before its
 * numbers are known still fails closed at send time rather
 * than crashing at construction. A present number must be a
 * non-empty string, free of NUL and whitespace.
 */
export function assertValidVonageSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is VonageSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  for (const field of ["from", "to"] as const) {
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
export function resolveVonageText(record: VonageRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return VONAGE_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a phone.
 */
export function truncateVonagePayload(body: string, limit: number): string {
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
 * The body is appended as plain text inside the `text`
 * field, not a fenced code block: an SMS renders as-is,
 * and a fence would be noise on a phone screen.
 */
export function resolveVonageNotification(
  record: VonageRecord,
  config: Pick<VonageSinkConfig, "includePayload" | "payloadMaxChars">
): { text: string } {
  let text = resolveVonageText(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? VONAGE_DEFAULT_PAYLOAD_MAX_CHARS;
    text = `${text}\n\n${truncateVonagePayload(record.body, limit)}`;
  }
  return { text };
}

/**
 * Build one record's serialized request body: the
 * urlencoded object with `from`, `to`, and `text` fields,
 * in that order. Values are percent-encoded, so a text
 * with `&`, `=`, or newlines cannot break the form. The
 * API key and secret never appear here — the client alone
 * holds them and prepends `api_key` and `api_secret` to
 * the form before POSTing, so the wire form reads
 * `api_key`, `api_secret`, `from`, `to`, `text`.
 */
export function buildVonageFormBody(from: string, to: string, text: string): string {
  const encode = (value: string) => encodeURIComponent(value);
  return `from=${encode(from)}&to=${encode(to)}&text=${encode(text)}`;
}

/**
 * Validate one record's body and resolve its send form: the
 * notification text. Throws `RangeError` on an empty body
 * string — even without the opt-in, the body is the record's
 * payload, and an empty record is a caller bug that must
 * fail closed, never notify as an empty message.
 */
export function resolveVonageRecord(
  record: VonageRecord,
  index: number,
  config: Pick<VonageSinkConfig, "includePayload" | "payloadMaxChars">
): { notification: { text: string }; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`vonage-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { notification: resolveVonageNotification(record, config), index };
}

/**
 * Map one Vonage POST `statusCode` onto its retry lane under
 * the WR-210 rules: 429 and every 5xx are transient and so
 * retryable — a rate limit says Vonage could not accept
 * the message right now, not that the payload is poison.
 * Every other non-2xx status (400, 401, 403, 404, and the
 * rest) is a fail-closed message: unknown number, invalid
 * body, bad credentials, or another verdict retrying cannot
 * change. Callers only pass non-2xx statuses here; a 2xx
 * status is a success, not a failure.
 */
export function classifyVonageRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Vonage sink (WR-252). One instance targets one sender
 * number and one recipient number; the caller owns
 * retry/dead-letter policy around `send()` — this class
 * performs one POST attempt per message through the
 * injected client and reports its outcome. Failures
 * throw `VonageSinkError` carrying exactly the failed
 * messages with their retry lanes.
 */
export class VonageSink {
  private readonly cfg: VonageSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: VonageSinkConfig) {
    assertValidVonageSinkConfig(config, "VonageSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): VonageSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages by SMS, in input order. Throws
   * `VonageSinkConfigError` when no client was injected or
   * the sender or recipient is missing, and
   * `VonageSinkError` when any message fails (carrying
   * exactly the failed messages with their retry lanes; both
   * counted in stats before throwing, so the counters stay
   * honest even for callers that only inspect stats).
   */
  async send(records: VonageRecord[]): Promise<VonageSendResult> {
    const resolved = records.map((r, i) => resolveVonageRecord(r, i, this.cfg));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The
      // sender, recipient, and client are not required here,
      // mirroring the sibling sinks' dry-run exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new VonageSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const from = this.cfg.from;
    if (from === undefined) {
      throw new VonageSinkConfigError("no sender configured (set `from` in the sink config)");
    }
    const to = this.cfg.to;
    if (to === undefined) {
      throw new VonageSinkConfigError("no recipient configured (set `to` in the sink config)");
    }
    const failedRecords: VonageFailedRecord[] = [];
    let sent = 0;
    for (const record of resolved) {
      try {
        const response = await client.post({
          url: VONAGE_SMS_URL,
          body: buildVonageFormBody(from, to, record.notification.text),
        });
        if (response.status >= 200 && response.status < 300) {
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyVonageRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toVonageFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new VonageSinkError(
        `vonage-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toVonageFailedRecord(err: unknown, index: number): VonageFailedRecord {
  const failed: VonageFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
