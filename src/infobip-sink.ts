/**
 * Infobip SMS notification delivery sink (WR-267).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's phone. Where the Telnyx sink
 * (WR-264) delivers SMS through Telnyx's flat
 * `from`/`to`/`text` Messages API and the Bandwidth sink
 * (WR-263) delivers through Bandwidth's account-pathed
 * JSON API, this sink delivers through Infobip's SMS
 * API: one event is sent as one SMS, and Infobip — not
 * the relay — owns the carrier routing, the delivery,
 * and the retention of the message.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need an Infobip
 * server. The sink owns the relay-side concerns — message
 * targeting, text derivation, payload-inclusion policy,
 * per-message failure mapping — and the injected client
 * owns the wire protocol, including the POST call, the
 * authentication, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "{baseUrl}/sms/2/text/advanced",
 *     body: "{\"messages\":[{\"from\":\"<from>\",\"destinations\":[{\"to\":\"<msisdn>\"}],\"text\":\"<text>\"}]}" }
 *
 * The client POSTs to that URL, sending `body` verbatim
 * as the request body (a JSON object) and authenticating
 * with an `Authorization: App` header carrying the API key
 * it alone holds. Three things about this shape are
 * deliberate, and all follow the sibling sinks:
 *
 * - The API key is held by the client alone.
 *   The sink never receives it, never places it in
 *   the request, and never logs it: like the Telnyx
 *   sink (WR-264), whose API key the client alone
 *   holds, this sink's request carries no credential at
 *   all — the client adds the `Authorization: App`
 *   header from the key it alone holds, so there is
 *   nothing in the request for a log line or a retry
 *   queue to leak. This is the opposite of the Vonage
 *   sink (WR-252), whose credentials ride inside the
 *   request body: Infobip authenticates by header, so
 *   the body carries only routing and content.
 * - The recipient rides inside `destinations` as a
 *   single-element array: that is Infobip's fixed
 *   message shape — unlike the Telnyx sink (WR-264),
 *   whose `to` is a bare string, Infobip wraps the
 *   number in `destinations`, so a sink that sent a
 *   bare `to` would be rejected.
 * - The host is account-configurable, not fixed:
 *   Infobip accounts live on per-account subdomains
 *   (e.g. `xxx.api.infobip.com`), so the base URL
 *   comes from the sink config — unlike the Telnyx
 *   sink, whose host is one fixed endpoint, a fixed
 *   host here could only misroute a message to an
 *   account that is not the operator's. The sink uses
 *   the base URL as given and never prepends a
 *   protocol prefix: the operator supplies the full
 *   account URL, including its scheme.
 *
 * The sender and the recipient are configured, not
 * derived from the event. One sink targets one sender
 * number and one recipient number. A missing sender,
 * recipient, or base URL is a config error, not a
 * resolution fallback: unlike the broker sinks, there
 * is no per-record target to resolve to, so a sink
 * with no recipient has nowhere to deliver and fails
 * closed with `InfobipSinkConfigError` at send time
 * (dry runs excepted — they need no numbers at all,
 * mirroring the sibling sinks' dry-run exemption for the
 * client).
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
 * recipient number — not the text — is the delivery
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
 * phone. The body is appended as plain text inside the
 * `text` field, not a fenced code block: an SMS renders
 * as-is, and a fence would be noise on a phone screen.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over HTTP status:
 *
 * - a non-2xx POST throws `InfobipSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Infobip could
 *   not accept the message right now, not that the payload
 *   is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (unknown number, invalid body, bad
 *   credentials): retrying them burns the retry budget
 *   for nothing, and rerouting them elsewhere would text
 *   a number the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client, sender, recipient, or base URL
 *   throws `InfobipSinkConfigError`, which
 *   `classifyFailure` maps to `non_retryable` (the WR-116
 *   rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for the text field. */
export const INFOBIP_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const INFOBIP_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Infobip SMS API path, appended to the account base URL. */
export const INFOBIP_SEND_PATH = "/sms/2/text/advanced";

/**
 * Build the Infobip SMS endpoint for an account base URL.
 * The base URL is used as given — the sink never prepends
 * a protocol prefix, so the operator supplies the full
 * account URL (e.g. `https://xxx.api.infobip.com`).
 * Trailing slashes are stripped so the path joins cleanly.
 */
export function buildInfobipSendUrl(baseUrl: string): string {
  return `${baseUrl.replace(/\/+$/, "")}${INFOBIP_SEND_PATH}`;
}

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (a JSON object with a
 * `messages` array) to the account endpoint, and
 * authenticates with an
 * `Authorization: App` header carrying the API key
 * it alone holds. The sink never sees that key, so the
 * request carries no credential: nothing here can leak
 * into a log line.
 */
export interface InfobipMessagePostRequest {
  /** Always the account Infobip SMS endpoint (`{baseUrl}/sms/2/text/advanced`). */
  url: string;
  /** The JSON message object, serialized: `messages` array with `from`, `destinations` (a single-element array holding `to`), and `text`. */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse Infobip's response body.
 */
export interface InfobipMessagePostResponse {
  /** The HTTP status of the POST (e.g. 201, 429, 503). */
  status: number;
}

/**
 * The injected Infobip message client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one message per call, sending
 * `body` verbatim as the request body (the JSON object
 * with a `messages` array),
 * setting the `application/json` content type, and
 * authenticating with an `Authorization: App` header
 * carrying its own API key — which the sink never sees.
 */
export interface InfobipMessageClient {
  post(request: InfobipMessagePostRequest): Promise<InfobipMessagePostResponse>;
}

/**
 * Configuration for one Infobip sink. The client is
 * injected: without one, `send()` throws
 * `InfobipSinkConfigError` (dry runs excepted — they need
 * no client at all). A missing sender or recipient is
 * likewise a config error at send
 * time (dry runs excepted): there is no per-record target
 * to fall back to. The API key is deliberately
 * absent from this config: the client alone holds it
 * and sends it as the `Authorization: App` header.
 */
export interface InfobipSinkConfig {
  /**
   * The sender number (`from`): the number every message
   * appears to come from. Must be a non-empty string, free
   * of NUL and whitespace, when set; a missing sender
   * throws `InfobipSinkConfigError` at send time.
   */
  from?: string;
  /**
   * The recipient number (`to`): the recipient of every
 * message from this sink, carried as the bare `to` string
 * (Infobip v2 takes a single number, not an array). Must be a
 * non-empty string, free of NUL and whitespace, when set; a missing
 * recipient throws `InfobipSinkConfigError` at send time.
   */
  to?: string;
  /**
   * The account base URL (e.g. `https://xxx.api.infobip.com`):
   * Infobip accounts live on per-account subdomains, so the
   * host is configurable, not fixed — unlike the Telnyx
   * sink, whose host is one fixed endpoint. Must be a
   * non-empty string, free of NUL and whitespace, when set;
   * a missing base URL throws `InfobipSinkConfigError` at
   * send time. The sink uses it as given and never
   * prepends a protocol prefix.
   */
  baseUrl?: string;
  /**
   * The Infobip message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `InfobipMessageClient` and alone holds the
 * API key. Required for real sends; a missing
   * client is a config error, not a silent no-op.
   */
  client?: InfobipMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including text derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
 * The numbers and client are
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
export interface InfobipRecord {
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
export interface InfobipFailedRecord {
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
export interface InfobipSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-264). */
export interface InfobipSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Infobip send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on Infobip's server and are *not* in
 * `failedRecords`.
 */
export class InfobipSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: InfobipFailedRecord[];
  constructor(message: string, failedRecords: InfobipFailedRecord[]) {
    super(message);
    this.name = "InfobipSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, or the sender, recipient, or base
 * URL is missing. A config problem, not a
 * downstream verdict, so the retry queue must not burn
 * attempts on it (`classifyFailure` maps it to
 * `non_retryable`).
 */
export class InfobipSinkConfigError extends InfobipSinkError {
  constructor(reason: string) {
    super(`infobip-sink: ${reason}`, []);
    this.name = "InfobipSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing sender or recipient is
 * *not* a shape error: it is a config error raised at send time
 * (`InfobipSinkConfigError`), so a sink built before its
 * numbers are known still fails closed at send time rather
 * than crashing at construction. A present value must be a
 * non-empty string, free of NUL and whitespace.
 */
export function assertValidInfobipSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is InfobipSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  for (const field of ["from", "to", "baseUrl"] as const) {
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
export function resolveInfobipText(record: InfobipRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return INFOBIP_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a phone.
 */
export function truncateInfobipPayload(body: string, limit: number): string {
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
export function resolveInfobipNotification(
  record: InfobipRecord,
  config: Pick<InfobipSinkConfig, "includePayload" | "payloadMaxChars">
): { text: string } {
  let text = resolveInfobipText(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? INFOBIP_DEFAULT_PAYLOAD_MAX_CHARS;
    text = `${text}\n\n${truncateInfobipPayload(record.body, limit)}`;
  }
  return { text };
}

/**
 * Build one record's serialized request body: the JSON
 * object with a `messages` array holding one entry with
 * `from`, `destinations` (a single-element array holding
 * the recipient as `to`), and `text`, in that order. The
 * API key never appears here — the client alone holds it
 * and sends it as the `Authorization: App` header.
 */
export function buildInfobipMessageBody(from: string, to: string, text: string): string {
  return JSON.stringify({
    messages: [{ from, destinations: [{ to }], text }],
  });
}

/**
 * Validate one record's body and resolve its send form: the
 * notification text. Throws `RangeError` on an empty body
 * string — even without the opt-in, the body is the record's
 * payload, and an empty record is a caller bug that must
 * fail closed, never notify as an empty message.
 */
export function resolveInfobipRecord(
  record: InfobipRecord,
  index: number,
  config: Pick<InfobipSinkConfig, "includePayload" | "payloadMaxChars">
): { notification: { text: string }; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`infobip-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { notification: resolveInfobipNotification(record, config), index };
}

/**
 * Map one Infobip POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says Infobip could not
 * accept the message right now, not that the payload is
 * poison. Every other non-2xx status (400, 401, 403,
 * 404, and the rest) is a fail-closed message: unknown
 * number, invalid body, bad credentials, or another verdict
 * retrying cannot change. Callers only pass non-2xx
 * statuses here; a 2xx status is a success, not a failure.
 */
export function classifyInfobipRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Infobip sink (WR-267). One instance targets one
 * Infobip account, one sender number,
 * and one recipient number; the caller owns retry /
 * dead-letter policy around `send()` — this class
 * performs one POST attempt per message through the
 * injected client and reports its outcome. Failures
 * throw `InfobipSinkError` carrying exactly the failed
 * messages with their retry lanes.
 */
export class InfobipSink {
  private readonly cfg: InfobipSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: InfobipSinkConfig) {
    assertValidInfobipSinkConfig(config, "InfobipSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): InfobipSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages by SMS, in input order. Throws
   * `InfobipSinkConfigError` when no client was injected
 * or the sender or recipient is missing, and
 * `InfobipSinkError` when any message
   * fails (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: InfobipRecord[]): Promise<InfobipSendResult> {
    const resolved = records.map((r, i) => resolveInfobipRecord(r, i, this.cfg));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The
      // numbers and client are
      // not required here, mirroring the sibling sinks'
      // dry-run exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new InfobipSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const from = this.cfg.from;
    if (from === undefined) {
      throw new InfobipSinkConfigError("no sender configured (set `from` in the sink config)");
    }
    const to = this.cfg.to;
    if (to === undefined) {
      throw new InfobipSinkConfigError("no recipient configured (set `to` in the sink config)");
    }
    const baseUrl = this.cfg.baseUrl;
    if (baseUrl === undefined) {
      throw new InfobipSinkConfigError("no base URL configured (set `baseUrl` in the sink config)");
    }
    const url = buildInfobipSendUrl(baseUrl);
    const failedRecords: InfobipFailedRecord[] = [];
    let sent = 0;
    for (const record of resolved) {
      try {
        const response = await client.post({
          url,
          body: buildInfobipMessageBody(from, to, record.notification.text),
        });
        if (response.status >= 200 && response.status < 300) {
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyInfobipRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toInfobipFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new InfobipSinkError(
        `infobip-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toInfobipFailedRecord(err: unknown, index: number): InfobipFailedRecord {
  const failed: InfobipFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
