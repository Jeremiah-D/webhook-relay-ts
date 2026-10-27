/**
 * Bark notification delivery sink (WR-243).
 *
 * Some downstreams are not queues, streams, or topics at all:
 * they are a human's phone or desktop. Where the Gotify sink
 * (WR-242) delivers to a Gotify server, this sink delivers to
 * a Bark server: one event is posted as one notification to
 * a configured push URL, and Bark — not the relay — owns
 * the subscription, the delivery, and the retention of the
 * notification.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Bark server.
 * The sink owns the relay-side concerns — push targeting,
 * title/body derivation, payload-inclusion policy,
 * per-message failure mapping — and the injected client owns
 * the wire protocol, including the POST call and the status
 * it returns.
 *
 * Wire shape — one POST per notification, carried to the
 * injected client as:
 *
 *   { url: "<configured push URL>",
 *     body: "{\"title\":\"<title>\",\"body\":\"<body>\"}" }
 *
 * The client POSTs `body` verbatim as the request body
 * (a JSON object, not plain text): Bark's push endpoint
 * takes a JSON object with `title` and `body` fields. No
 * other field is ever set: no badge, sound, icon, or
 * grouping key — the relay does not restyle an operator's
 * notifications, and a sink that set fields the operator
 * never chose could re-prioritize or re-route a
 * notification the operator meant to be plain.
 *
 * The push URL is posted to verbatim: Bark routes and
 * authenticates by the URL itself (e.g.
 * `https://api.day.app/<device-key>/` or a self-hosted
 * `https://bark.example.com/<device-key>/`), so — like the
 * Gotify and ntfy sinks, and unlike DingTalk — no token is
 * appended at send time: the configured URL, device key
 * included, is posted to verbatim. Nothing about any
 * credential is ever extracted, logged, or carried
 * separately from the URL: the URL is the target, and
 * treating it as one opaque value means rotating a device
 * key never means changing sink code.
 *
 * Push targeting — one sink targets one push URL: every
 * message goes there. A missing push URL is a config
 * error, not a resolution fallback: unlike the broker
 * sinks, there is no per-record target to resolve to, so a
 * sink with no URL has nowhere to deliver and fails closed
 * with `BarkSinkConfigError` at send time (dry runs
 * excepted — they need no URL at all, mirroring the sibling
 * sinks' dry-run exemption for the client). An invalid URL —
 * unparseable, or not `https:` — is the same config error: a
 * notification URL must never travel over plaintext, and a
 * URL the operator cannot have meant must not be posted to.
 * The host is not pinned to any Bark deployment: an
 * operator may use api.day.app, self-host Bark, or front
 * the server with a proxy or sidecar, and the sink must not
 * second-guess that deployment.
 *
 * Title and body — derived from the event's own values.
 * The title takes `subject` first, falling back to `key`
 * when the event carries no subject: the subject is what
 * the event is about, the key (e.g. aggregate id) is the
 * next most identifying value. The body takes `key` first,
 * falling back to `traceId`: the body line names the entity
 * and the trace that produced the event. An event with none
 * of the values a field needs still notifies, with the
 * generic summary `webhook event`: a notification sink that
 * silently dropped sourceless events would hide exactly the
 * deliveries an operator most needs to see, and the push URL
 * — not the text — is the delivery contract here, so no
 * invented target is at stake.
 *
 * Payload inclusion — by default the body carries the
 * summary only, never the full payload: event bodies routinely
 * carry PII, secrets, or customer data, and a push
 * notification is a far wider audience than a queue or a
 * stream. Opting into `includePayload` appends the body
 * verbatim after a blank line, truncated to
 * `payloadMaxChars` characters (default 2000) with a
 * truncation marker — the opt-in is explicit, and the
 * truncation is unconditional, so even an opted-in body
 * cannot flood a device or blow past Bark's message
 * limits. The body is appended as plain text inside the
 * `body` field, not a fenced code block: Bark renders the
 * body as-is, and a fence would be noise on a phone screen.
 *
 * Failure handling mirrors the WR-210 SQS sink's classification
 * (`src/failure.ts`), applied per message over HTTP status:
 *
 * - a non-2xx POST throws `BarkSinkError` carrying every
 *   failed message with its retry lane already mapped, so the
 *   caller retries exactly the failed messages;
 * - retryable statuses are the transient HTTP states — 429
 *   and every 5xx: a rate limit says Bark could not accept
 *   the message right now, not that the payload is poison;
 * - non-retryable statuses are the fail-closed messages —
 *   every other non-2xx status, including 400, 401, 403, and
 *   404 (unknown device key, invalid body): retrying them burns
 *   the retry budget for nothing, and rerouting them
 *   elsewhere would notify a device the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status: it
 *   says nothing about the payload;
 * - a missing client or a missing/invalid push URL throws
 *   `BarkSinkConfigError`, which `classifyFailure` maps to
 *   `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for a text field. */
export const BARK_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const BARK_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol (including the status it
 * returns and the request headers); this shape is the
 * relay-side contract it must honour. The push URL is
 * posted verbatim, device key included: Bark routes and
 * authenticates by the URL itself, so no token is ever
 * appended or extracted. The body is the JSON object
 * `{"title","body"}` serialized as a string, posted
 * verbatim.
 */
export interface BarkPushPostRequest {
  /** Target push URL, exactly as configured (device key included). */
  url: string;
  /** The JSON notification object, serialized: title and body. */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse Bark's response body.
 */
export interface BarkPushPostResponse {
  /** The HTTP status of the POST (e.g. 200, 429, 503). */
  status: number;
}

/**
 * The injected Bark push client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one message per call, sending
 * `body` verbatim as the request body (the JSON object with
 * `title` and `body`).
 */
export interface BarkPushClient {
  post(request: BarkPushPostRequest): Promise<BarkPushPostResponse>;
}

/**
 * Configuration for one Bark sink. The client is injected:
 * without one, `send()` throws `BarkSinkConfigError` (dry
 * runs excepted — they need no client at all). A missing or
 * invalid push URL is likewise a config error at send
 * time (dry runs excepted): there is no per-record target to
 * fall back to.
 */
export interface BarkSinkConfig {
  /**
   * Target push URL, e.g.
   * `https://api.day.app/<device-key>/` or a self-hosted
   * `https://bark.example.com/<device-key>/`.
   * Posted to verbatim, device key included: Bark routes and
   * authenticates by the URL itself, so no token is appended
   * at send time. Must be a parseable `https:` URL at send
   * time; a missing or invalid URL throws
   * `BarkSinkConfigError`, never a silent no-op.
   */
  pushUrl?: string;
  /**
   * The Bark push client to deliver through. Injected,
   * never bundled: the operator's client adapter implements
   * `BarkPushClient`. Required for real sends; a missing
   * client is a config error, not a silent no-op.
   */
  client?: BarkPushClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including text derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The push URL and client are not required in dry-run
   * mode, mirroring the sibling sinks' dry-run exemption.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the body text appends the
   * event body verbatim after a blank line, truncated to
   * `payloadMaxChars` characters (see below). When `false`
   * or absent, the body carries the summary only — the
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
export interface BarkRecord {
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
export interface BarkFailedRecord {
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
   * non-2xx status is a fail-closed message (unknown device
   * key, invalid body).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface BarkSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-243). */
export interface BarkSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Bark send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on their server and are *not* in
 * `failedRecords`.
 */
export class BarkSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: BarkFailedRecord[];
  constructor(message: string, failedRecords: BarkFailedRecord[]) {
    super(message);
    this.name = "BarkSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, or the push URL is missing or
 * invalid. A config problem, not a downstream verdict, so the
 * retry queue must not burn attempts on it (`classifyFailure`
 * maps it to `non_retryable`).
 */
export class BarkSinkConfigError extends BarkSinkError {
  constructor(reason: string) {
    super(`bark-sink: ${reason}`, []);
    this.name = "BarkSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing push URL is *not* a shape error: it is a config
 * error raised at send time (`BarkSinkConfigError`), so a sink
 * built before its URL is known still fails closed at send
 * time rather than crashing at construction. A present push
 * URL must be a non-empty string, free of NUL and whitespace;
 * the `https:` parse check happens at send time, so an invalid
 * URL surfaces as the same config error.
 */
export function assertValidBarkSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is BarkSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  if (c.pushUrl !== undefined) {
    if (
      typeof c.pushUrl !== "string" ||
      c.pushUrl === "" ||
      (c.pushUrl as string).includes("\0") ||
      /\s/.test(c.pushUrl as string)
    ) {
      throw new RangeError(
        at("`pushUrl` must be a non-empty string, free of NUL and whitespace when set")
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
 * True when a push URL is usable: parseable, and `https:`.
 * A notification URL must never travel over plaintext, and a
 * URL the operator cannot have meant must not be posted to.
 * The host is deliberately not pinned: an operator may use
 * api.day.app, self-host Bark, or front the server with a
 * proxy.
 */
export function isValidBarkPushUrl(url: string): boolean {
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
 * drop sourceless events, and the push URL (not the
 * text) is the delivery contract.
 */
export function resolveBarkTitle(record: BarkRecord): string {
  for (const value of [record.subject, record.key]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return BARK_FALLBACK_SUMMARY;
}

/**
 * Derive one record's body summary: the first non-empty
 * value among `key` and `traceId`, in that order. Falls back
 * to the generic `webhook event` summary when the record
 * carries neither.
 */
export function resolveBarkBodySummary(record: BarkRecord): string {
  for (const value of [record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return BARK_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a device.
 */
export function truncateBarkPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's notification object: the title and
 * the body. Only under the `includePayload` opt-in does the
 * body append the event body verbatim after a blank line,
 * truncated to `payloadMaxChars` (default 2000). Without the
 * opt-in, the body is the summary alone: event bodies
 * routinely carry PII and must never leak into a
 * notification by default. The body is appended as plain
 * text inside the `body` field, not a fenced code block:
 * Bark renders the body as-is, and a fence would be noise
 * on a phone screen.
 */
export function resolveBarkNotification(
  record: BarkRecord,
  config: Pick<BarkSinkConfig, "includePayload" | "payloadMaxChars">
): { title: string; body: string } {
  const title = resolveBarkTitle(record);
  let body = resolveBarkBodySummary(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? BARK_DEFAULT_PAYLOAD_MAX_CHARS;
    body = `${body}\n\n${truncateBarkPayload(record.body, limit)}`;
  }
  return { title, body };
}

/**
 * Validate one record's body and resolve its send form: the
 * JSON notification object, serialized. Throws `RangeError`
 * on an empty body string — even without the opt-in, the body
 * is the record's payload, and an empty record is a caller bug
 * that must fail closed, never notify as an empty message.
 */
export function resolveBarkRecord(
  record: BarkRecord,
  index: number,
  config: Pick<BarkSinkConfig, "includePayload" | "payloadMaxChars">
): { body: string; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`bark-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { body: JSON.stringify(resolveBarkNotification(record, config)), index };
}

/**
 * Map one Bark POST `statusCode` onto its retry lane under
 * the WR-210 rules: 429 and every 5xx are transient and so
 * retryable — a rate limit says Bark could not accept the
 * message right now, not that the payload is poison. Every
 * other non-2xx status (400, 401, 403, 404, and the rest) is
 * a fail-closed message: unknown device key, invalid body, or
 * another verdict retrying cannot change. Callers only pass
 * non-2xx statuses here; a 2xx status is a success, not a
 * failure.
 */
export function classifyBarkRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Bark sink (WR-243). One instance targets one push URL;
 * the caller owns retry/dead-letter policy around `send()` —
 * this class performs one POST attempt per message through
 * the injected client and reports its outcome. Failures throw
 * `BarkSinkError` carrying exactly the failed messages with
 * their retry lanes.
 */
export class BarkSink {
  private readonly cfg: BarkSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: BarkSinkConfig) {
    assertValidBarkSinkConfig(config, "BarkSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): BarkSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages to the configured push URL, in input
   * order. Throws `BarkSinkConfigError` when no client was
   * injected or the push URL is missing or invalid, and
   * `BarkSinkError` when any message fails (carrying
   * exactly the failed messages with their retry lanes; both
   * counted in stats before throwing, so the counters stay
   * honest even for callers that only inspect stats).
   */
  async send(records: BarkRecord[]): Promise<BarkSendResult> {
    const resolved = records.map((r, i) => resolveBarkRecord(r, i, this.cfg));
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
      throw new BarkSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const url = this.cfg.pushUrl;
    if (url === undefined || !isValidBarkPushUrl(url)) {
      throw new BarkSinkConfigError(
        "no valid push URL configured (set `pushUrl` to a parseable `https:` URL)"
      );
    }
    const failedRecords: BarkFailedRecord[] = [];
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
          retryable: classifyBarkRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toBarkFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new BarkSinkError(
        `bark-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toBarkFailedRecord(err: unknown, index: number): BarkFailedRecord {
  const failed: BarkFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
