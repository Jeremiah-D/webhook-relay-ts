/**
 * Braze email notification delivery sink (WR-278).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's inbox. Where the Mailtrap sink
 * (WR-273) delivers through Mailtrap's send API with a
 * `from` object / `to` object-array envelope, this sink
 * delivers through Braze's `/messages/send` API: one event
 * email, and Braze — not the relay — owns the user
 * profiles, the delivery, and the retention of the
 * message.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Braze
 * server. The sink owns the relay-side concerns — message
 * targeting, subject and body derivation, payload-inclusion
 * policy, per-message failure mapping — and the injected
 * client owns the wire protocol, including the POST call,
 * the authentication, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://rest.iad-01.braze.com/messages/send",
 *     body: "{\"external_user_ids\":[\"<external_id>\"],\"messages\":{\"email\":{\"app_id\":\"<app_id>\",\"subject\":\"<subject>\",\"body\":\"<body>\",\"from\":\"<from>\"}}}" }
 *
 * The client POSTs to that fixed URL, sending `body`
 * verbatim as the request body (a JSON object) and
 * authenticating with an `Authorization: Bearer <REST API
 * key>` header carrying a REST API key it alone holds —
 * Braze's header-auth shape, not a body-carried key. The
 * key needs the `messages.send` permission. Three things
 * about this shape are deliberate, and all follow the
 * sibling sinks:
 *
 * - The REST API key is held by the client alone. The sink
 *   never receives it, never places it in the request,
 *   and never logs it: like the Mailtrap sink (WR-273),
 *   whose Bearer key the client alone holds, this sink's
 *   handed request carries no credential at all — the
 *   client adds the `Authorization: Bearer` header from
 *   the key it alone holds, so there is nothing in the
 *   handed request for a log line or a retry queue to
 *   leak. This is the opposite of the SMTP2GO sink
 *   (WR-271), whose key rides inside the wire body at
 *   wire time: Braze authenticates by header, so the
 *   body carries only routing and content.
 * - The host is fixed, not configurable: the endpoint
 *   above is Braze's US-01 instance. Other Braze
 *   instances use their own REST endpoints (for example
 *   `rest.iad-03.braze.com` for US-03, or the EU
 *   instances' `rest.fra-01.braze.com`), and an operator
 *   on another instance points their client adapter at
 *   that instance's endpoint — the sink itself never
 *   takes a URL, because a configurable URL here could
 *   only misroute a message to a server that is not
 *   Braze. The fixed host is the documented US-01
 *   default; the client adapter owns the instance.
 * - The recipients are Braze external ids, not email
 *   addresses: Braze sends to users it already knows.
 *   The API-only `/messages/send` endpoint does not
 *   create users — a recipient that does not exist in
 *   Braze yet fails with a 400, fail-closed, not with a
 *   silently created profile. The operator provisions
 *   the users in Braze first; this sink only addresses
 *   them.
 *
 * This sink is orthogonal to the Mailtrap sink (WR-273):
 * Mailtrap posts a `from` object / `to` object-array
 * envelope with a Bearer header, while Braze posts an
 * `external_user_ids` array plus a `messages.email`
 * envelope with a Bearer header — two vendors whose
 * envelopes share nothing but the header-auth shape,
 * because Braze addresses users by external id, not by
 * email address. It is likewise distinct from the FCM
 * sink (WR-276): FCM posts a per-device `token` envelope
 * with a Bearer OAuth token, while Braze posts a per-user
 * external-id envelope with a Bearer REST API key.
 *
 * The app id, sender, and recipients are configured, not
 * derived from the event. One sink targets one Braze app,
 * one sender address, and one set of external ids. A
 * missing app id, sender, or recipient set is a config
 * error, not a resolution fallback: unlike the broker
 * sinks, there is no per-record target to resolve to, so
 * a sink with no recipient has nowhere to deliver and
 * fails closed with `BrazeSinkConfigError` at send time
 * (dry runs excepted — they need no app, sender, or
 * recipients at all, mirroring the sibling sinks'
 * dry-run exemption for the client).
 *
 * Message text — derived from the event's own values,
 * split across the envelope's two text fields. The
 * subject takes the first non-empty value among `subject`
 * and `key`, in that order: the subject is what the event
 * is about, the key (e.g. aggregate id) is the next most
 * identifying value. The body takes the first non-empty
 * value among `subject`, `key`, and `traceId`, in that
 * order — the trace id names the trace that produced the
 * event, and it belongs in the body even though it is too
 * opaque for a subject line. An event with none of the
 * values still notifies, with the generic summary
 * `webhook event` in both fields: a notification sink
 * that silently dropped sourceless events would hide
 * exactly the deliveries an operator most needs to see,
 * and the external ids — not the text — are the delivery
 * contract here, so no invented target is at stake.
 *
 * Payload inclusion — by default the message carries the
 * summary only, never the full payload: event bodies
 * routinely carry PII, secrets, or customer data, and an
 * inbox is a far wider audience than a queue or a stream.
 * Opting into `includePayload` appends the body verbatim
 * after a blank line, truncated to `payloadMaxChars`
 * characters (default 2000) with a truncation marker —
 * the opt-in is explicit, and the truncation is
 * unconditional, so even an opted-in body cannot flood an
 * inbox. The body is appended as plain text inside the
 * `body` field, not a fenced code block: the field is
 * already plain text, and a fence around an already-JSON
 * body would be noise in an inbox. No `html` field is
 * configured here: this sink sends plain text only.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over HTTP status:
 *
 * - a non-2xx POST throws `BrazeSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Braze could
 *   not accept the message right now, not that the
 *   payload is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (unknown external id — the recipient
 *   does not exist in Braze yet — invalid body, bad API
 *   key): retrying them burns the retry budget for
 *   nothing, and rerouting them elsewhere would email
 *   users the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client, app id, sender, or recipient set
 *   throws `BrazeSinkConfigError`, which `classifyFailure`
 *   maps to `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for a text field. */
export const BRAZE_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const BRAZE_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Fixed Braze send endpoint for every message (US-01 instance). */
export const BRAZE_SEND_URL = "https://rest.iad-01.braze.com/messages/send";

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (a JSON object with
 * `external_user_ids` and `messages.email`) to the fixed
 * send endpoint, and authenticates with an
 * `Authorization: Bearer <REST API key>` header carrying a
 * REST API key it alone holds (with the `messages.send`
 * permission). The sink never sees that key, so the
 * request carries no credential: nothing here can leak
 * into a log line.
 */
export interface BrazeMessagePostRequest {
  /** Always the fixed Braze send endpoint (US-01). */
  url: string;
  /** The JSON message object, serialized: `external_user_ids`, `messages.email`. */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse Braze's response body.
 */
export interface BrazeMessagePostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
}

/**
 * The injected Braze message client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one message per call, sending
 * `body` verbatim as the request body (the JSON object
 * with `external_user_ids` and `messages.email`), setting
 * the `application/json` content type, and authenticating
 * with an `Authorization: Bearer <REST API key>` header
 * carrying its own REST API key — which the sink never
 * sees. An operator on a non-US-01 Braze instance points
 * the client at that instance's own REST endpoint.
 */
export interface BrazeMessageClient {
  post(request: BrazeMessagePostRequest): Promise<BrazeMessagePostResponse>;
}

/**
 * Configuration for one Braze sink. The client is
 * injected: without one, `send()` throws
 * `BrazeSinkConfigError` (dry runs excepted — they need
 * no client at all). A missing app id, sender, or
 * recipient set is likewise a config error at send time
 * (dry runs excepted): there is no per-record target to
 * fall back to. The REST API key is deliberately absent
 * from this config: the client alone holds it and sends
 * it as the `Authorization: Bearer` header. No `html`
 * field is configured here: this sink sends plain text
 * only.
 */
export interface BrazeSinkConfig {
  /**
   * The Braze app id (the `app_id` of `messages.email`):
   * the Braze app the message is sent from. Must be a
   * non-empty string, free of NUL and whitespace, when
   * set; a missing app id throws `BrazeSinkConfigError`
   * at send time.
   */
  appId?: string;
  /**
   * The sender address (the `from` of `messages.email`):
   * the address every message appears to come from. Must
   * be a non-empty string, free of NUL and whitespace,
   * when set; a missing sender throws
   * `BrazeSinkConfigError` at send time.
   */
  from?: string;
  /**
   * The recipient external ids (the `external_user_ids`
   * array): the Braze users every message is sent to.
   * Each entry must be a non-empty string, free of NUL
   * and whitespace; the array must be non-empty when set.
   * A missing or empty recipient set throws
   * `BrazeSinkConfigError` at send time. Recipients must
   * already exist in Braze: the API-only send does not
   * create users, and an unknown external id fails with
   * a 400.
   */
  externalUserIds?: string[];
  /**
   * The Braze message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `BrazeMessageClient` and alone holds the
   * REST API key (with the `messages.send` permission).
   * Required for real sends; a missing client is a
   * config error, not a silent no-op.
   */
  client?: BrazeMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including text derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The app id, sender, recipients, and client are not
   * required in dry-run mode, mirroring the sibling
   * sinks' dry-run exemption.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the body appends
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
   * the opt-in is set, so an opted-in body cannot flood an
   * inbox. Must be a positive integer when set.
   */
  payloadMaxChars?: number;
}

/** One event to notify about. */
export interface BrazeRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Text-derivation source, first priority: the event's
   * subject, when set and non-empty. Falls through to `key`
   * for the subject, and to `key`, then `traceId`, for the
   * body.
   */
  subject?: string;
  /**
   * Text-derivation source, second priority: the event's key
   * (e.g. aggregate id).
   */
  key?: string;
  /**
   * Text-derivation source, last priority for the body:
   * the trace id. Never used for the subject — too
   * opaque for a subject line.
   */
  traceId?: string;
}

/** One failed message, with its retry lane already mapped. */
export interface BrazeFailedRecord {
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
   * non-2xx status is a fail-closed message (unknown external
   * id, invalid body, bad API key).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface BrazeSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-278). */
export interface BrazeSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Braze send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on Braze's server and are *not* in
 * `failedRecords`.
 */
export class BrazeSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: BrazeFailedRecord[];
  constructor(message: string, failedRecords: BrazeFailedRecord[]) {
    super(message);
    this.name = "BrazeSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, or the app id, sender, or recipient
 * set is missing. A config problem, not a downstream verdict, so
 * the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class BrazeSinkConfigError extends BrazeSinkError {
  constructor(reason: string) {
    super(`braze-sink: ${reason}`, []);
    this.name = "BrazeSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing app id, sender, or recipient set is *not* a shape error: it
 * is a config error raised at send time
 * (`BrazeSinkConfigError`), so a sink built before its app and
 * recipients are known still fails closed at send time rather
 * than crashing at construction. A present app id or sender must be
 * a non-empty string, free of NUL and whitespace; a present
 * recipient set must be a non-empty array of non-empty strings,
 * each free of NUL and whitespace.
 */
export function assertValidBrazeSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is BrazeSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  for (const field of ["appId", "from"] as const) {
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
  const externalUserIds = c.externalUserIds;
  if (externalUserIds !== undefined) {
    if (!Array.isArray(externalUserIds) || externalUserIds.length === 0) {
      throw new RangeError(at("`externalUserIds` must be a non-empty array when set"));
    }
    for (const id of externalUserIds as unknown[]) {
      if (
        typeof id !== "string" ||
        id === "" ||
        id.includes("\0") ||
        /\s/.test(id)
      ) {
        throw new RangeError(
          at("each `externalUserIds` entry must be a non-empty string, free of NUL and whitespace")
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
 * Derive one record's subject: the first non-empty value
 * among `subject` and `key`, in that order. Falls back to
 * the generic `webhook event` summary when the record
 * carries neither — the envelope always needs a subject,
 * and a notification sink must not silently drop sourceless
 * events. The trace id is deliberately not a subject
 * source: it is too opaque for a subject line, and belongs
 * in the body instead.
 */
export function resolveBrazeSubject(record: BrazeRecord): string {
  for (const value of [record.subject, record.key]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return BRAZE_FALLBACK_SUMMARY;
}

/**
 * Derive one record's body: the first non-empty
 * value among `subject`, `key`, and `traceId`, in that
 * order. Falls back to the generic `webhook event` summary
 * when the record carries none — a notification sink must
 * not silently drop sourceless events, and the external
 * ids (not the text) are the delivery contract.
 */
export function resolveBrazeBody(record: BrazeRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return BRAZE_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood an inbox.
 */
export function truncateBrazePayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's notification: its subject and its
 * body. Only under the `includePayload` opt-in
 * does the body append the event body verbatim after a
 * blank line, truncated to `payloadMaxChars` (default
 * 2000). Without the opt-in, the body is the summary
 * alone: event bodies routinely carry PII and must never
 * leak into a notification by default. The body is
 * appended as plain text inside the `body` field, not a
 * fenced code block.
 */
export function resolveBrazeNotification(
  record: BrazeRecord,
  config: Pick<BrazeSinkConfig, "includePayload" | "payloadMaxChars">
): { subject: string; body: string } {
  const subject = resolveBrazeSubject(record);
  let body = resolveBrazeBody(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? BRAZE_DEFAULT_PAYLOAD_MAX_CHARS;
    body = `${body}\n\n${truncateBrazePayload(record.body, limit)}`;
  }
  return { subject, body };
}

/**
 * Build one record's serialized request body: the JSON
 * object with `external_user_ids` (the configured external
 * ids), and `messages.email` holding `app_id`, `subject`,
 * `body`, and `from` (plain text only — Braze's `html`
 * field is out of scope for this sink), in that order.
 * The REST API key never appears here — the client alone
 * holds it and sends it as the `Authorization: Bearer`
 * header.
 */
export function buildBrazeMessageBody(
  appId: string,
  from: string,
  externalUserIds: string[],
  subject: string,
  body: string
): string {
  return JSON.stringify({
    external_user_ids: externalUserIds,
    messages: {
      email: {
        app_id: appId,
        subject,
        body,
        from,
      },
    },
  });
}

/**
 * Validate one record's body and resolve its send form: the
 * notification subject and body. Throws `RangeError` on an
 * empty body string — even without the opt-in, the body is
 * the record's payload, and an empty record is a caller bug
 * that must fail closed, never notify as an empty message.
 */
export function resolveBrazeRecord(
  record: BrazeRecord,
  index: number,
  config: Pick<BrazeSinkConfig, "includePayload" | "payloadMaxChars">
): { notification: { subject: string; body: string }; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`braze-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { notification: resolveBrazeNotification(record, config), index };
}

/**
 * Map one Braze POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says Braze could not
 * accept the message right now, not that the payload is
 * poison. Every other non-2xx status (400, 401, 403,
 * 404, and the rest) is a fail-closed message: unknown
 * external id, invalid body, bad API key, or another
 * verdict retrying cannot change. Callers only pass
 * non-2xx statuses here; a 2xx status is a success, not
 * a failure.
 */
export function classifyBrazeRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Braze sink (WR-278). One instance targets one Braze app,
 * one sender address, and one set of external ids; the
 * caller owns retry/dead-letter policy around `send()` —
 * this class performs one POST attempt per message through
 * the injected client and reports its outcome. Failures
 * throw `BrazeSinkError` carrying exactly the failed
 * messages with their retry lanes.
 */
export class BrazeSink {
  private readonly cfg: BrazeSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: BrazeSinkConfig) {
    assertValidBrazeSinkConfig(config, "BrazeSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): BrazeSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages by email, in input order. Throws
   * `BrazeSinkConfigError` when no client was injected or
   * the app id, sender, or recipient set is missing, and
   * `BrazeSinkError` when any message fails (carrying
   * exactly the failed messages with their retry lanes; both
   * counted in stats before throwing, so the counters stay
   * honest even for callers that only inspect stats).
   */
  async send(records: BrazeRecord[]): Promise<BrazeSendResult> {
    const resolved = records.map((r, i) => resolveBrazeRecord(r, i, this.cfg));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The
      // app id, sender, recipients, and client are not
      // required here, mirroring the sibling sinks'
      // dry-run exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new BrazeSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const appId = this.cfg.appId;
    if (appId === undefined) {
      throw new BrazeSinkConfigError("no app id configured (set `appId` in the sink config)");
    }
    const from = this.cfg.from;
    if (from === undefined) {
      throw new BrazeSinkConfigError("no sender configured (set `from` in the sink config)");
    }
    const externalUserIds = this.cfg.externalUserIds;
    if (externalUserIds === undefined) {
      throw new BrazeSinkConfigError(
        "no recipients configured (set `externalUserIds` in the sink config)"
      );
    }
    const failedRecords: BrazeFailedRecord[] = [];
    let sent = 0;
    for (const record of resolved) {
      try {
        const response = await client.post({
          url: BRAZE_SEND_URL,
          body: buildBrazeMessageBody(
            appId,
            from,
            externalUserIds,
            record.notification.subject,
            record.notification.body
          ),
        });
        if (response.status >= 200 && response.status < 300) {
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyBrazeRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toBrazeFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new BrazeSinkError(
        `braze-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toBrazeFailedRecord(err: unknown, index: number): BrazeFailedRecord {
  const failed: BrazeFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
