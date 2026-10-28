/**
 * Zulip notification delivery sink (WR-249).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a team's chat stream. Where the PagerDuty
 * sink (WR-248) opens an incident, this sink posts a
 * message to a Zulip stream: one event is posted as one
 * stream message, and Zulip — not the relay — owns the
 * stream, the delivery, and the retention of the message.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a Zulip
 * server. The sink owns the relay-side concerns — stream
 * targeting, message-text derivation, payload-inclusion
 * policy, per-message failure mapping — and the injected
 * client owns the wire protocol, including the POST call,
 * the authentication, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { site: "<zulip-site>",
 *     to: "<stream>",
 *     subject: "<topic>",
 *     body: "type=stream&to=<stream>&subject=<topic>&content=<content>" }
 *
 * The client POSTs to `{site}/api/v1/messages`, sending
 * `body` verbatim as the request body (an
 * `application/x-www-form-urlencoded` object, not JSON)
 * and authenticating with HTTP Basic auth. Two things
 * about this shape differ from the sibling sinks, and
 * both are deliberate:
 *
 * - The credentials are held by the client alone. The sink
 *   never receives the bot email or the API key, never
 *   places either in the request, and never logs them:
 *   like the Twilio sink (WR-247), whose auth token the
 *   client alone holds, this sink's request carries no
 *   credential at all — the client adds the
 *   `Authorization: Basic` header from the bot email and
 *   API key it alone holds, so there is nothing in the
 *   request for a log line or a retry queue to leak.
 * - The stream and the topic are configured, not derived
 *   from the event. One sink targets one stream and one
 *   topic: `to` names the stream, `subject` names the
 *   topic (Zulip's API field name for a topic — the
 *   legacy name, still the wire name). Do not confuse the
 *   configured `subject` (the topic every message lands
 *   under) with the record's `subject` field (the first
 *   link of the content-derivation chain, below): they
 *   share a name because the Zulip API and the relay's
 *   record shape both call their field `subject`, but
 *   they are different values, and the code keeps them in
 *   different variables for exactly that reason.
 *
 * The site is configurable, like the Matrix sink's
 * homeserver (WR-246): Zulip is self-hostable, so the
 * operator's server varies (zulip.com cloud, a company
 * server, a self-hosted one). The stream and the topic
 * are likewise configured: one sink targets one stream
 * topic. A missing site, stream, or topic is a config
 * error, not a resolution fallback: unlike the broker
 * sinks, there is no per-record target to resolve to, so
 * a sink with no stream has nowhere to deliver and fails
 * closed with `ZulipSinkConfigError` at send time (dry
 * runs excepted — they need no stream at all, mirroring
 * the sibling sinks' dry-run exemption for the client).
 *
 * Stream and topic names are human names, not
 * identifiers: unlike the Twilio sink's phone numbers,
 * which must be free of whitespace, a Zulip stream may
 * legitimately be called e.g. `general chat` and a topic
 * may contain spaces. Config validation therefore
 * requires stream and topic only to be non-empty and free
 * of NUL — whitespace is legal, and the form encoding
 * percent-encodes it. The site, being a URL, keeps the
 * stricter no-whitespace rule.
 *
 * Message text — derived from the event's own values.
 * A stream message carries a single content field, so
 * where the sibling sinks split text into title and body,
 * this sink folds the derivation chain into one: the
 * first non-empty value among the record's `subject`,
 * `key`, and `traceId`, in that order. The subject is
 * what the event is about, the key (e.g. aggregate id)
 * is the next most identifying value, and the trace id
 * names the trace that produced the event. An event with
 * none of the values still notifies, with the generic
 * summary `webhook event`: a notification sink that
 * silently dropped sourceless events would hide exactly
 * the deliveries an operator most needs to see, and the
 * stream — not the text — is the delivery contract here,
 * so no invented target is at stake.
 *
 * Payload inclusion — by default the message carries the
 * summary only, never the full payload: event bodies
 * routinely carry PII, secrets, or customer data, and a
 * team stream is a far wider audience than a queue or a
 * stream. Opting into `includePayload` appends the body
 * verbatim after a blank line, truncated to
 * `payloadMaxChars` characters (default 2000) with a
 * truncation marker — the opt-in is explicit, and the
 * truncation is unconditional, so even an opted-in body
 * cannot flood a stream. The body is appended as plain
 * text inside the `content` field, not a fenced code
 * block: Zulip renders `content` as Markdown, and a fence
 * around an already-JSON body would be noise in a stream.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over HTTP status:
 *
 * - a non-2xx POST throws `ZulipSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Zulip could
 *   not accept the message right now, not that the
 *   payload is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (unknown stream, invalid body): retrying
 *   them burns the retry budget for nothing, and
 *   rerouting them elsewhere would notify a stream the
 *   operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client, site, stream, or topic throws
 *   `ZulipSinkConfigError`, which `classifyFailure`
 *   maps to `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for the content field. */
export const ZULIP_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const ZULIP_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Zulip API path segment for sending a message. */
export const ZULIP_MESSAGES_PATH = "/api/v1/messages";

/**
 * Build the Zulip messages endpoint for a site. The site
 * is passed with trailing slashes stripped, so the path
 * concatenation cannot double a slash.
 */
export function zulipMessagesUrl(site: string): string {
  return `${normalizeZulipSite(site)}${ZULIP_MESSAGES_PATH}`;
}

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (an
 * `application/x-www-form-urlencoded` object with `type`,
 * `to`, `subject`, and `content` fields) to
 * `{site}/api/v1/messages`, and authenticates with an
 * `Authorization: Basic` header carrying a bot email and
 * API key it alone holds. The sink never sees those
 * credentials, so the request carries no credential:
 * nothing here can leak into a log line.
 */
export interface ZulipMessagePostRequest {
  /** The operator's Zulip site base URL, trailing slashes stripped. */
  site: string;
  /** The target stream name. */
  to: string;
  /** The target topic (Zulip's API field name for a topic). */
  subject: string;
  /** The urlencoded message object, serialized: `type`, `to`, `subject`, `content`. */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse Zulip's response body.
 */
export interface ZulipMessagePostResponse {
  /** The HTTP status of the POST (e.g. 201, 429, 503). */
  status: number;
}

/**
 * The injected Zulip message client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one message per call, sending
 * `body` verbatim as the request body (the urlencoded
 * object with `type`, `to`, `subject`, and `content`),
 * and authenticating with its own bot email and API key —
 * neither of which the sink ever sees.
 */
export interface ZulipMessageClient {
  post(request: ZulipMessagePostRequest): Promise<ZulipMessagePostResponse>;
}

/**
 * Configuration for one Zulip sink. The client is
 * injected: without one, `send()` throws
 * `ZulipSinkConfigError` (dry runs excepted — they need
 * no client at all). A missing site, stream, or topic is
 * likewise a config error at send time (dry runs
 * excepted): there is no per-record target to fall back
 * to.
 */
export interface ZulipSinkConfig {
  /**
   * The operator's Zulip site base URL (e.g.
   * `https://zulip.example.com`). Zulip is self-hostable,
   * so this varies per deployment — unlike the fixed hosts
   * of the PagerDuty and Twilio sinks. Must be a non-empty
   * string, free of NUL and whitespace, when set; a missing
   * site throws `ZulipSinkConfigError` at send time, never
   * a silent no-op.
   */
  site?: string;
  /**
   * The target stream name (`to` in the Zulip API): the
   * stream every message from this sink lands in. A human
   * name, so whitespace is legal — it must only be a
   * non-empty string, free of NUL, when set; a missing
   * stream throws `ZulipSinkConfigError` at send time.
   */
  to?: string;
  /**
   * The target topic (`subject` in the Zulip API): the
   * topic every message from this sink lands under. Not
   * the record's `subject` field — that is the first link
   * of the content-derivation chain. A human name, so
   * whitespace is legal — it must only be a non-empty
   * string, free of NUL, when set; a missing topic throws
   * `ZulipSinkConfigError` at send time.
   */
  subject?: string;
  /**
   * The Zulip message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `ZulipMessageClient` and alone holds the bot
   * email and API key. Required for real sends; a missing
   * client is a config error, not a silent no-op.
   */
  client?: ZulipMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including content derivation), so a dry
   * run catches a malformed record before it reaches
   * production. Mirrors the `dryRun` convention of the S3
   * offloaders. The site, stream, topic, and client are not
   * required in dry-run mode, mirroring the sibling sinks'
   * dry-run exemption.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the message content appends
   * the event body verbatim after a blank line, truncated to
   * `payloadMaxChars` characters (see below). When `false`
   * or absent, the message carries the summary only — the
   * default, so event bodies (which routinely carry PII)
   * never leak into a stream unless the operator explicitly
   * asks for them.
   */
  includePayload?: boolean;
  /**
   * Truncation limit for an opted-in payload snippet, in
   * characters (default 2000). Only meaningful with
   * `includePayload`; the truncation is unconditional when
   * the opt-in is set, so an opted-in body cannot flood a
   * stream. Must be a positive integer when set.
   */
  payloadMaxChars?: number;
}

/** One event to notify about. */
export interface ZulipRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Content-derivation source, first priority: the event's
   * subject, when set and non-empty. Falls through to `key`,
   * then `traceId`. Not the configured topic — that is
   * `ZulipSinkConfig.subject`.
   */
  subject?: string;
  /**
   * Content-derivation source, second priority: the event's
   * key (e.g. aggregate id).
   */
  key?: string;
  /**
   * Content-derivation source, last priority: the trace id.
   */
  traceId?: string;
}

/** One failed message, with its retry lane already mapped. */
export interface ZulipFailedRecord {
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
   * non-2xx status is a fail-closed message (unknown stream,
   * invalid body).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface ZulipSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-249). */
export interface ZulipSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Zulip send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on the Zulip server and are *not* in
 * `failedRecords`.
 */
export class ZulipSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: ZulipFailedRecord[];
  constructor(message: string, failedRecords: ZulipFailedRecord[]) {
    super(message);
    this.name = "ZulipSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, or the site, stream, or topic is
 * missing. A config problem, not a downstream verdict, so
 * the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class ZulipSinkConfigError extends ZulipSinkError {
  constructor(reason: string) {
    super(`zulip-sink: ${reason}`, []);
    this.name = "ZulipSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing site, stream, or topic is *not* a shape error: it is a
 * config error raised at send time (`ZulipSinkConfigError`),
 * so a sink built before its stream is known still fails closed
 * at send time rather than crashing at construction. A present
 * site must be a non-empty string, free of NUL and whitespace;
 * a present stream or topic must be a non-empty string, free of
 * NUL — whitespace is legal in human stream and topic names,
 * and the form encoding percent-encodes it.
 */
export function assertValidZulipSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is ZulipSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  const site = c.site;
  if (site !== undefined) {
    if (
      typeof site !== "string" ||
      site === "" ||
      (site as string).includes("\0") ||
      /\s/.test(site as string)
    ) {
      throw new RangeError(
        at("`site` must be a non-empty string, free of NUL and whitespace when set")
      );
    }
  }
  for (const field of ["to", "subject"] as const) {
    const value = c[field];
    if (value !== undefined) {
      if (
        typeof value !== "string" ||
        value === "" ||
        (value as string).includes("\0")
      ) {
        throw new RangeError(
          at(`\`${field}\` must be a non-empty string, free of NUL when set`)
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
 * Strip trailing slashes from a Zulip site base URL, so the
 * client's path concatenation cannot double a slash. The
 * root `/` alone is not a usable site and is left to the
 * client's URL handling — this helper only trims.
 */
export function normalizeZulipSite(site: string): string {
  return site.replace(/\/+$/, "");
}

/**
 * Derive one record's message content: the first non-empty
 * value among the record's `subject`, `key`, and `traceId`,
 * in that order. Falls back to the generic `webhook event`
 * summary when the record carries none — a notification sink
 * must not silently drop sourceless events, and the stream
 * (not the content) is the delivery contract.
 */
export function resolveZulipContent(record: ZulipRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return ZULIP_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a stream.
 */
export function truncateZulipPayload(body: string, limit: number): string {
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
 * PII and must never leak into a stream by default. The body
 * is appended as plain text inside the `content` field, not
 * a fenced code block: Zulip renders `content` as Markdown,
 * and a fence around an already-JSON body would be noise in
 * a stream.
 */
export function resolveZulipNotification(
  record: ZulipRecord,
  config: Pick<ZulipSinkConfig, "includePayload" | "payloadMaxChars">
): { content: string } {
  let content = resolveZulipContent(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? ZULIP_DEFAULT_PAYLOAD_MAX_CHARS;
    content = `${content}\n\n${truncateZulipPayload(record.body, limit)}`;
  }
  return { content };
}

/**
 * Build one record's serialized request body: the
 * urlencoded object with `type`, `to`, `subject`, and
 * `content` fields, in that order. Values are
 * percent-encoded, so a stream or topic name with spaces,
 * or a content with `&`, `=`, or newlines, cannot break
 * the form. Neither the bot email nor the API key ever
 * appears here — the client alone holds them.
 */
export function buildZulipFormBody(
  to: string,
  subject: string,
  content: string
): string {
  const encode = (value: string) => encodeURIComponent(value);
  return `type=stream&to=${encode(to)}&subject=${encode(subject)}&content=${encode(content)}`;
}

/**
 * Validate one record's body and resolve its send form: the
 * notification content. Throws `RangeError` on an empty body
 * string — even without the opt-in, the body is the record's
 * payload, and an empty record is a caller bug that must
 * fail closed, never notify as an empty message.
 */
export function resolveZulipRecord(
  record: ZulipRecord,
  index: number,
  config: Pick<ZulipSinkConfig, "includePayload" | "payloadMaxChars">
): { notification: { content: string }; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`zulip-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { notification: resolveZulipNotification(record, config), index };
}

/**
 * Map one Zulip POST `statusCode` onto its retry lane under
 * the WR-210 rules: 429 and every 5xx are transient and so
 * retryable — a rate limit says Zulip could not accept the
 * message right now, not that the payload is poison.
 * Every other non-2xx status (400, 401, 403, 404, and the
 * rest) is a fail-closed message: unknown stream, invalid
 * body, or another verdict retrying cannot change. Callers
 * only pass non-2xx statuses here; a 2xx status is a
 * success, not a failure.
 */
export function classifyZulipRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Zulip sink (WR-249). One instance targets one Zulip
 * stream topic; the caller owns retry/dead-letter policy
 * around `send()` — this class performs one POST attempt
 * per message through the injected client and reports its
 * outcome. Failures throw `ZulipSinkError` carrying
 * exactly the failed messages with their retry lanes.
 */
export class ZulipSink {
  private readonly cfg: ZulipSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: ZulipSinkConfig) {
    assertValidZulipSinkConfig(config, "ZulipSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): ZulipSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages to the Zulip stream topic, in input
   * order. Throws `ZulipSinkConfigError` when no client was
   * injected or the site, stream, or topic is missing, and
   * `ZulipSinkError` when any message fails (carrying
   * exactly the failed messages with their retry lanes; both
   * counted in stats before throwing, so the counters stay
   * honest even for callers that only inspect stats).
   */
  async send(records: ZulipRecord[]): Promise<ZulipSendResult> {
    const resolved = records.map((r, i) => resolveZulipRecord(r, i, this.cfg));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The site,
      // stream, topic, and client are not required here,
      // mirroring the sibling sinks' dry-run exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new ZulipSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const site = this.cfg.site;
    if (site === undefined) {
      throw new ZulipSinkConfigError("no site configured (set `site` in the sink config)");
    }
    const to = this.cfg.to;
    if (to === undefined) {
      throw new ZulipSinkConfigError("no stream configured (set `to` in the sink config)");
    }
    const subject = this.cfg.subject;
    if (subject === undefined) {
      throw new ZulipSinkConfigError("no topic configured (set `subject` in the sink config)");
    }
    const failedRecords: ZulipFailedRecord[] = [];
    let sent = 0;
    for (const record of resolved) {
      try {
        const response = await client.post({
          site: normalizeZulipSite(site),
          to,
          subject,
          body: buildZulipFormBody(to, subject, record.notification.content),
        });
        if (response.status >= 200 && response.status < 300) {
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyZulipRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toZulipFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new ZulipSinkError(
        `zulip-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
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
function toZulipFailedRecord(err: unknown, index: number): ZulipFailedRecord {
  const failed: ZulipFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
