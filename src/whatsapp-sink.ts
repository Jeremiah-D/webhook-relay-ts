/**
 * WhatsApp Business notification delivery sink (WR-251).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a customer's chat app. Where the Webex
 * sink (WR-250) posts to a team room, this sink sends a
 * WhatsApp text message to one recipient: one event is
 * sent as one text message, and WhatsApp — not the relay
 * — owns the delivery and the retention of the message.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a WhatsApp
 * server. The sink owns the relay-side concerns — recipient
 * targeting, message-text derivation, payload-inclusion
 * policy, per-message failure mapping — and the injected
 * client owns the wire protocol, including the POST call,
 * the authentication, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { phoneNumberId: "<phone-number-id>",
 *     to: "<recipient>",
 *     body: "{\"messaging_product\":\"whatsapp\",\"recipient_type\":\"individual\",\"to\":\"<recipient>\",\"type\":\"text\",\"text\":{\"body\":\"<text>\",\"preview_url\":false}}" }
 *
 * The client POSTs to
 * `https://graph.facebook.com/v26.0/{phone-number-id}/messages`,
 * sending `body` verbatim as the request body (a JSON
 * object) and authenticating with an `Authorization: Bearer`
 * header carrying an access token it alone holds. Three
 * things about this shape are deliberate, and all follow
 * the sibling sinks:
 *
 * - The access token is held by the client alone. The
 *   sink never receives the token, never places it in
 *   the request, and never logs it: like the Twilio sink
 *   (WR-247) and the Webex sink (WR-250), whose tokens
 *   the client alone holds, this sink's request carries
 *   no credential at all — the client adds the
 *   `Authorization: Bearer` header from the access token
 *   it alone holds, so there is nothing in the request
 *   for a log line or a retry queue to leak.
 * - The phone-number id appears only in the URL path,
 *   never in the message body: the id identifies the
 *   sender's number to Meta's routing, not to the
 *   recipient, so it belongs in the path the client
 *   builds from the `phoneNumberId` field — exactly the
 *   Matrix sink's rule (WR-246), where the room id
 *   travels in the path, not the body. The message body
 *   carries only what the recipient sees plus the
 *   routing fields the API requires (`messaging_product`,
 *   `recipient_type`, `to`, `type`).
 * - The Graph API version is pinned in one constant
 *   (`WHATSAPP_GRAPH_API_VERSION`), not scattered
 *   through code: Meta versions the API, and a pinned
 *   version is what keeps the endpoint stable across
 *   upgrades. The version pinned here is the latest
 *   verified at implementation time (v26.0, released
 *   July 2026); the backlog draft's v21.0 example was
 *   superseded by that check, per the item's own
 *   instruction to verify the latest version at
 *   implementation time.
 *
 * The recipient is configured, not derived from the
 * event. One sink targets one recipient: `to` names it.
 * A missing phone-number id or recipient is a config
 * error, not a resolution fallback: unlike the broker
 * sinks, there is no per-record target to resolve to, so
 * a sink with no recipient has nowhere to deliver and
 * fails closed with `WhatsAppSinkConfigError` at send
 * time (dry runs excepted — they need no recipient at
 * all, mirroring the sibling sinks' dry-run exemption
 * for the client).
 *
 * Both the phone-number id and the recipient are opaque
 * identifiers, not human names: unlike the Zulip sink's
 * stream and topic names, which may contain spaces, both
 * must be free of whitespace as well as NUL — the Twilio
 * sink's phone number rule, applied to both identifiers.
 * (A recipient is a number with country code and no
 * leading `+`, per the Cloud API's format.)
 *
 * Message text — derived from the event's own values.
 * A text message carries a single body field, so where
 * the sibling sinks split text into title and body, this
 * sink folds the derivation chain into one: the first
 * non-empty value among the record's `subject`, `key`,
 * and `traceId`, in that order. The subject is what the
 * event is about, the key (e.g. aggregate id) is the next
 * most identifying value, and the trace id names the trace
 * that produced the event. An event with none of the
 * values still notifies, with the generic summary
 * `webhook event`: a notification sink that silently
 * dropped sourceless events would hide exactly the
 * deliveries an operator most needs to see, and the
 * recipient — not the text — is the delivery contract
 * here, so no invented target is at stake.
 *
 * Text messages, not templates: this sink sends only
 * `type: "text"` messages with `preview_url: false` (no
 * link preview is generated for URLs in the text — a
 * notification body is not a marketing link). Text
 * messages require an open 24-hour customer-service
 * window with the recipient; template messages, which
 * are what opens a window, are out of scope for this
 * item. An operator whose window has lapsed gets a
 * fail-closed non-2xx from the API, not a silently
 * reworded template.
 *
 * Payload inclusion — by default the message carries the
 * summary only, never the full payload: event bodies
 * routinely carry PII, secrets, or customer data, and a
 * customer's chat app is a far wider audience than a
 * queue or a stream. Opting into `includePayload`
 * appends the body verbatim after a blank line, truncated
 * to `payloadMaxChars` characters (default 2000) with a
 * truncation marker — the opt-in is explicit, and the
 * truncation is unconditional, so even an opted-in body
 * cannot flood a chat. The body is appended as plain
 * text inside the `text.body` field, not a fenced code
 * block: WhatsApp renders `text.body` as plain text, and
 * a fence around an already-JSON body would be noise in
 * a chat.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over HTTP status:
 *
 * - a non-2xx POST throws `WhatsAppSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Meta could
 *   not accept the message right now, not that the
 *   payload is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (unknown number, invalid body, lapsed
 *   24-hour window): retrying them burns the retry
 *   budget for nothing, and rerouting them elsewhere
 *   would message a recipient the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client, phone-number id, or recipient
 *   throws `WhatsAppSinkConfigError`, which
 *   `classifyFailure` maps to `non_retryable` (the
 *   WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for the text field. */
export const WHATSAPP_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const WHATSAPP_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Fixed Graph API host for the WhatsApp Cloud API. */
export const WHATSAPP_GRAPH_API_HOST = "graph.facebook.com";

/**
 * Pinned Graph API version for the messages endpoint.
 * Verified latest at implementation time (v26.0, released
 * July 2026). Pinned in one place so a version bump is a
 * one-line change, not a hunt through call sites.
 */
export const WHATSAPP_GRAPH_API_VERSION = "v26.0";

/**
 * Build the WhatsApp messages endpoint for a phone-number
 * id. The id appears only here, in the URL path — never
 * in the message body.
 */
export function whatsappMessagesUrl(phoneNumberId: string): string {
  return `https://${WHATSAPP_GRAPH_API_HOST}/${WHATSAPP_GRAPH_API_VERSION}/${phoneNumberId}/messages`;
}

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (a JSON object with
 * `messaging_product`, `recipient_type`, `to`, `type`,
 * and `text`) to
 * `https://graph.facebook.com/v26.0/{phone-number-id}/messages`,
 * and authenticates with an `Authorization: Bearer`
 * header carrying an access token it alone holds. The sink
 * never sees that token, so the request carries no
 * credential: nothing here can leak into a log line.
 */
export interface WhatsAppMessagePostRequest {
  /** The sender's phone-number id — used only in the URL path, never in the body. */
  phoneNumberId: string;
  /** The recipient number (country code, no leading `+`). */
  to: string;
  /** The JSON message object, serialized: `messaging_product`, `recipient_type`, `to`, `type`, `text`. */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse Meta's response body.
 */
export interface WhatsAppMessagePostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
}

/**
 * The injected WhatsApp message client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one message per call, sending
 * `body` verbatim as the request body (the JSON object
 * with `messaging_product`, `recipient_type`, `to`,
 * `type`, and `text`), and authenticating with its own
 * access token — which the sink never sees.
 */
export interface WhatsAppMessageClient {
  post(request: WhatsAppMessagePostRequest): Promise<WhatsAppMessagePostResponse>;
}

/**
 * Configuration for one WhatsApp sink. The client is
 * injected: without one, `send()` throws
 * `WhatsAppSinkConfigError` (dry runs excepted — they need
 * no client at all). A missing phone-number id or recipient
 * is likewise a config error at send time (dry runs
 * excepted): there is no per-record target to fall back
 * to.
 */
export interface WhatsAppSinkConfig {
  /**
   * The sender's phone-number id: the number the message
   * is sent from, as registered in WhatsApp Manager. Used
   * only in the URL path. An opaque identifier, so it must
   * be a non-empty string, free of NUL and whitespace,
   * when set; a missing id throws `WhatsAppSinkConfigError`
   * at send time, never a silent no-op.
   */
  phoneNumberId?: string;
  /**
   * The recipient number (country code, no leading `+`):
   * the number every message from this sink is sent to.
   * An opaque identifier, so it must be a non-empty
   * string, free of NUL and whitespace, when set; a
   * missing recipient throws `WhatsAppSinkConfigError` at
   * send time, never a silent no-op.
   */
  to?: string;
  /**
   * The WhatsApp message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `WhatsAppMessageClient` and alone holds the
   * access token. Required for real sends; a missing client
   * is a config error, not a silent no-op.
   */
  client?: WhatsAppMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including text derivation), so a dry
   * run catches a malformed record before it reaches
   * production. Mirrors the `dryRun` convention of the S3
   * offloaders. The phone-number id, recipient, and client
   * are not required in dry-run mode, mirroring the sibling
   * sinks' dry-run exemption.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the message text appends
   * the event body verbatim after a blank line, truncated to
   * `payloadMaxChars` characters (see below). When `false`
   * or absent, the message carries the summary only — the
   * default, so event bodies (which routinely carry PII)
   * never leak into a customer's chat unless the operator
   * explicitly asks for them.
   */
  includePayload?: boolean;
  /**
   * Truncation limit for an opted-in payload snippet, in
   * characters (default 2000). Only meaningful with
   * `includePayload`; the truncation is unconditional when
   * the opt-in is set, so an opted-in body cannot flood a
   * chat. Must be a positive integer when set.
   */
  payloadMaxChars?: number;
}

/** One event to notify about. */
export interface WhatsAppRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Text-derivation source, first priority: the event's
   * subject, when set and non-empty. Falls through to `key`,
   * then `traceId`.
   */
  subject?: string;
  /**
   * Text-derivation source, second priority: the event's
   * key (e.g. aggregate id).
   */
  key?: string;
  /**
   * Text-derivation source, last priority: the trace id.
   */
  traceId?: string;
}

/** One failed message, with its retry lane already mapped. */
export interface WhatsAppFailedRecord {
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
   * non-2xx status is a fail-closed message (unknown
   * number, invalid body, lapsed 24-hour window).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface WhatsAppSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-251). */
export interface WhatsAppSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for WhatsApp send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on Meta's server and are *not* in
 * `failedRecords`.
 */
export class WhatsAppSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: WhatsAppFailedRecord[];
  constructor(message: string, failedRecords: WhatsAppFailedRecord[]) {
    super(message);
    this.name = "WhatsAppSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, or the phone-number id or recipient
 * is missing. A config problem, not a downstream verdict,
 * so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class WhatsAppSinkConfigError extends WhatsAppSinkError {
  constructor(reason: string) {
    super(`whatsapp-sink: ${reason}`, []);
    this.name = "WhatsAppSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing phone-number id or recipient is *not* a shape error:
 * it is a config error raised at send time
 * (`WhatsAppSinkConfigError`), so a sink built before its
 * recipient is known still fails closed at send time rather
 * than crashing at construction. A present id or recipient
 * must be a non-empty string, free of NUL and whitespace:
 * both are opaque identifiers, not human names.
 */
export function assertValidWhatsAppSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is WhatsAppSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  for (const field of ["phoneNumberId", "to"] as const) {
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
 * value among the record's `subject`, `key`, and `traceId`,
 * in that order. Falls back to the generic `webhook event`
 * summary when the record carries none — a notification sink
 * must not silently drop sourceless events, and the
 * recipient (not the text) is the delivery contract.
 */
export function resolveWhatsAppContent(record: WhatsAppRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return WHATSAPP_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a chat.
 */
export function truncateWhatsAppPayload(body: string, limit: number): string {
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
 * PII and must never leak into a customer's chat by
 * default. The body is appended as plain text inside the
 * `text.body` field, not a fenced code block: WhatsApp
 * renders `text.body` as plain text, and a fence around an
 * already-JSON body would be noise in a chat.
 */
export function resolveWhatsAppNotification(
  record: WhatsAppRecord,
  config: Pick<WhatsAppSinkConfig, "includePayload" | "payloadMaxChars">
): { text: string } {
  let text = resolveWhatsAppContent(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? WHATSAPP_DEFAULT_PAYLOAD_MAX_CHARS;
    text = `${text}\n\n${truncateWhatsAppPayload(record.body, limit)}`;
  }
  return { text };
}

/**
 * Build one record's serialized request body: the JSON
 * object with `messaging_product`, `recipient_type`, `to`,
 * `type`, and `text` (with `body` and `preview_url:
 * false`), in that order. Neither the access token nor
 * the phone-number id ever appears here — the token is
 * held by the client alone, and the id travels only in
 * the URL path.
 */
export function buildWhatsAppMessageBody(to: string, text: string): string {
  return JSON.stringify({
    messaging_product: "whatsapp",
    recipient_type: "individual",
    to,
    type: "text",
    text: { body: text, preview_url: false },
  });
}

/**
 * Validate one record's body and resolve its send form: the
 * notification text. Throws `RangeError` on an empty body
 * string — even without the opt-in, the body is the record's
 * payload, and an empty record is a caller bug that must
 * fail closed, never notify as an empty message.
 */
export function resolveWhatsAppRecord(
  record: WhatsAppRecord,
  index: number,
  config: Pick<WhatsAppSinkConfig, "includePayload" | "payloadMaxChars">
): { notification: { text: string }; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`whatsapp-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { notification: resolveWhatsAppNotification(record, config), index };
}

/**
 * Map one WhatsApp POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says Meta could not
 * accept the message right now, not that the payload is
 * poison. Every other non-2xx status (400, 401, 403, 404,
 * and the rest) is a fail-closed message: unknown number,
 * invalid body, lapsed 24-hour window, or another verdict
 * retrying cannot change. Callers only pass non-2xx
 * statuses here; a 2xx status is a success, not a failure.
 */
export function classifyWhatsAppRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * WhatsApp sink (WR-251). One instance targets one
 * recipient; the caller owns retry/dead-letter policy
 * around `send()` — this class performs one POST attempt
 * per message through the injected client and reports its
 * outcome. Failures throw `WhatsAppSinkError` carrying
 * exactly the failed messages with their retry lanes.
 */
export class WhatsAppSink {
  private readonly cfg: WhatsAppSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: WhatsAppSinkConfig) {
    assertValidWhatsAppSinkConfig(config, "WhatsAppSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): WhatsAppSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages to the WhatsApp recipient, in input
   * order. Throws `WhatsAppSinkConfigError` when no client
   * was injected or the phone-number id or recipient is
   * missing, and `WhatsAppSinkError` when any message fails
   * (carrying exactly the failed messages with their retry
   * lanes; both counted in stats before throwing, so the
   * counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: WhatsAppRecord[]): Promise<WhatsAppSendResult> {
    const resolved = records.map((r, i) => resolveWhatsAppRecord(r, i, this.cfg));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The
      // phone-number id, recipient, and client are not
      // required here, mirroring the sibling sinks' dry-run
      // exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new WhatsAppSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const phoneNumberId = this.cfg.phoneNumberId;
    if (phoneNumberId === undefined) {
      throw new WhatsAppSinkConfigError("no phone-number id configured (set `phoneNumberId` in the sink config)");
    }
    const to = this.cfg.to;
    if (to === undefined) {
      throw new WhatsAppSinkConfigError("no recipient configured (set `to` in the sink config)");
    }
    const failedRecords: WhatsAppFailedRecord[] = [];
    let sent = 0;
    for (const record of resolved) {
      try {
        const response = await client.post({
          phoneNumberId,
          to,
          body: buildWhatsAppMessageBody(to, record.notification.text),
        });
        if (response.status >= 200 && response.status < 300) {
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyWhatsAppRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toWhatsAppFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new WhatsAppSinkError(
        `whatsapp-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toWhatsAppFailedRecord(err: unknown, index: number): WhatsAppFailedRecord {
  const failed: WhatsAppFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
