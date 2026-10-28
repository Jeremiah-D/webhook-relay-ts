/**
 * PagerDuty notification delivery sink (WR-248).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are an on-call rotation. Where the Twilio sink
 * (WR-247) texts a phone number, this sink triggers a
 * PagerDuty incident: one event is posted as one Events
 * API v2 event, and PagerDuty — not the relay — owns the
 * incident, the escalation, and the acknowledgement.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a PagerDuty
 * server. The sink owns the relay-side concerns — event
 * targeting, summary derivation, severity policy,
 * payload-inclusion policy, per-event failure mapping —
 * and the injected client owns the wire protocol,
 * including the POST call and the status it returns.
 *
 * Wire shape — one POST per event, carried to the
 * injected client as:
 *
 *   { url: "https://events.pagerduty.com/v2/enqueue",
 *     body: "{\"routing_key\":\"<key>\",\"event_action\":\"trigger\",
 *       \"dedup_key\":\"<key>\",
 *       \"payload\":{\"summary\":\"<summary>\",\"source\":\"webhook-relay\",
 *       \"severity\":\"error\",
 *       \"custom_details\":{\"key\":\"<key>\",\"traceId\":\"<trace>\"}}}" }
 *
 * The client POSTs `body` verbatim as the request body
 * (a JSON object, not plain text). Three things about
 * this shape differ from the sibling sinks, and all three
 * are forced by the Events API v2 envelope:
 *
 * - The routing key rides inside the request body. Unlike
 *   the Twilio sink, whose auth token is held by the client
 *   alone, PagerDuty authenticates an event by the
 *   `routing_key` in the envelope itself — there is no
 *   header or path alternative. The key is therefore held
 *   by the sink config and emitted with every event,
 *   along the Slack webhook URL precedent (WR-93's
 *   operator-signed URL channel, where the credential is
 *   likewise part of the request the sink builds). Treat
 *   the sink config as sensitive for exactly this reason:
 *   a log line that captures a request body captures the
 *   routing key with it.
 * - `event_action` is always `"trigger"`. This sink only
 *   opens incidents; it never acknowledges or resolves
 *   them, so no other action value is ever emitted.
 * - `dedup_key` is the event's key, when the event has
 *   one. PagerDuty deduplicates natively on `dedup_key`:
 *   a redelivered event with the same key updates the
 *   open incident instead of opening a second one. An
 *   event with no key carries no `dedup_key` at all, and
 *   PagerDuty generates one — inventing a dedup key for a
 *   keyless event would collapse unrelated incidents into
 *   one.
 *
 * The host is fixed, not configurable: PagerDuty Events
 * API v2 lives at one endpoint, so a configurable URL
 * could only misroute an incident to a server that is
 * not PagerDuty — the Twilio fixed-host rule, applied
 * here. The routing key is configured: one sink targets
 * one PagerDuty service integration. A missing routing
 * key is a config error, not a resolution fallback:
 * unlike the broker sinks, there is no per-record target
 * to resolve to, so a sink with no routing key has
 * nowhere to deliver and fails closed with
 * `PagerDutySinkConfigError` at send time (dry runs
 * excepted — they need no key at all, mirroring the
 * sibling sinks' dry-run exemption for the client).
 *
 * Summary — derived from the event's own values. The
 * payload carries a single summary field, so where the
 * sibling sinks split text into title and body, this sink
 * folds the derivation chain into one: the first
 * non-empty value among `subject`, `key`, and `traceId`,
 * in that order. An event with none of the values still
 * triggers, with the generic summary `webhook event`: a
 * notification sink that silently dropped sourceless
 * events would hide exactly the deliveries an operator
 * most needs to see, and the routing key — not the
 * summary — is the delivery contract here, so no
 * invented target is at stake.
 *
 * Severity — configurable, defaulting to `error`.
 * PagerDuty severities are `critical`, `error`,
 * `warning`, and `info`. The default is `error`, not
 * `critical`: a relayed webhook event is a failure worth
 * an incident, but paging the on-call rotation as
 * `critical` for every relayed event would train the
 * rotation to ignore pages. An operator who wants a
 * page sets `severity: "critical"` explicitly; an
 * operator who wants noise-level delivery sets
 * `"warning"` or `"info"`. The configured severity
 * applies to every event from the sink — severity is a
 * property of the sink's integration, not of any one
 * event, so there is no per-record severity override to
 * misconfigure.
 *
 * Payload inclusion — by default the incident carries
 * the summary only, never the full payload: event bodies
 * routinely carry PII, secrets, or customer data, and an
 * incident timeline is a far wider audience than a queue
 * or a stream. `custom_details` by default carries only
 * the event's identifiers (`key`, `traceId`, when set) —
 * identifiers, not the body. Opting into `includePayload`
 * appends the body verbatim under `custom_details.body`,
 * truncated to `payloadMaxChars` characters (default
 * 2000) with a truncation marker — the opt-in is
 * explicit, and the truncation is unconditional, so even
 * an opted-in body cannot flood an incident timeline.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per event
 * over HTTP status:
 *
 * - a non-2xx POST throws `PagerDutySinkError` carrying
 *   every failed event with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   events;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says PagerDuty could
 *   not accept the event right now, not that the
 *   payload is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (unknown routing key, invalid envelope):
 *   retrying them burns the retry budget for nothing,
 *   and rerouting them elsewhere would page a rotation
 *   the operator never chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client or routing key throws
 *   `PagerDutySinkConfigError`, which `classifyFailure`
 *   maps to `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for the summary field. */
export const PAGERDUTY_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const PAGERDUTY_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Fixed PagerDuty Events API v2 endpoint for every event. */
export const PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue";

/** Fixed payload source identifying the relay as the event origin. */
export const PAGERDUTY_SOURCE = "webhook-relay";

/** Default severity: an incident, but not a page. */
export const PAGERDUTY_DEFAULT_SEVERITY = "error";

/** PagerDuty severity tiers, in the API's own vocabulary. */
export type PagerDutySeverity = "critical" | "error" | "warning" | "info";

/** All PagerDuty severity tiers, for validation. */
export const PAGERDUTY_SEVERITIES: readonly PagerDutySeverity[] = [
  "critical",
  "error",
  "warning",
  "info",
];

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (a JSON object) to the fixed Events
 * API v2 endpoint. The routing key is inside `body` by
 * API design — the Events API authenticates by the
 * envelope's `routing_key`, so unlike the Twilio sink
 * there is no client-held-token alternative, and the
 * request body must be treated as sensitive.
 */
export interface PagerDutyEventPostRequest {
  /** Always the fixed Events API v2 endpoint. */
  url: string;
  /** The serialized Events API v2 envelope (see module docs). */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * Only the status matters to the sink's retry mapping; the
 * client need not parse PagerDuty's response body.
 */
export interface PagerDutyEventPostResponse {
  /** The HTTP status of the POST (e.g. 202, 429, 503). */
  status: number;
}

/**
 * The injected PagerDuty event client. Any client adapter
 * implements this one method; it returns the POST's status
 * (a throw is a codeless transport failure, retryable). The
 * client is expected to POST one event per call, sending
 * `body` verbatim as the request body (the JSON envelope).
 */
export interface PagerDutyEventClient {
  post(request: PagerDutyEventPostRequest): Promise<PagerDutyEventPostResponse>;
}

/**
 * Configuration for one PagerDuty sink. The client is
 * injected: without one, `send()` throws
 * `PagerDutySinkConfigError` (dry runs excepted — they need
 * no client at all). A missing routing key is likewise a
 * config error at send time (dry runs excepted): there is
 * no per-record target to fall back to.
 */
export interface PagerDutySinkConfig {
  /**
   * PagerDuty service integration key: the integration
   * every event is routed to. Placed into the request body
   * at send time — the Events API v2 envelope authenticates
   * by `routing_key`, so there is no header alternative —
   * and never logged. Must be a non-empty string, free of
   * NUL and whitespace, when set; a missing key throws
   * `PagerDutySinkConfigError` at send time, never a silent
   * no-op.
   */
  routingKey?: string;
  /**
   * The PagerDuty event client to deliver through.
   * Injected, never bundled. Required for real sends; a
   * missing client is a config error, not a silent no-op.
   */
  client?: PagerDutyEventClient;
  /**
   * Severity for every event from this sink: one of
   * `critical`, `error`, `warning`, `info`. Defaults to
   * `error` — an incident without paging the rotation as
   * `critical` for every relayed event. Set `critical`
   * explicitly to page.
   */
  severity?: PagerDutySeverity;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Events are
   * still validated (including summary derivation), so a dry
   * run catches a malformed record before it reaches
   * production. Mirrors the `dryRun` convention of the S3
   * offloaders. The routing key and client are not required
   * in dry-run mode, mirroring the sibling sinks' dry-run
   * exemption.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the payload's
   * `custom_details` gains a `body` field holding the event
   * body verbatim, truncated to `payloadMaxChars`
   * characters (see below). When `false` or absent, the
   * incident carries the summary plus identifiers only —
   * the default, so event bodies (which routinely carry PII)
   * never leak into an incident timeline unless the operator
   * explicitly asks for them.
   */
  includePayload?: boolean;
  /**
   * Truncation limit for an opted-in payload snippet, in
   * characters (default 2000). Only meaningful with
   * `includePayload`; the truncation is unconditional when
   * the opt-in is set, so an opted-in body cannot flood an
   * incident timeline. Must be a positive integer when set.
   */
  payloadMaxChars?: number;
}

/** One event to notify about. */
export interface PagerDutyRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Summary-derivation source, first priority: the event's
   * subject, when set and non-empty. Falls through to `key`,
   * then `traceId`.
   */
  subject?: string;
  /**
   * Summary-derivation source, second priority, and the
   * PagerDuty dedup key when set: the event's key (e.g.
   * aggregate id). A redelivery with the same key updates
   * the open incident instead of opening a second one.
   */
  key?: string;
  /**
   * Summary-derivation source, last priority: the trace id.
   * Also carried in `custom_details` when set.
   */
  traceId?: string;
}

/** One failed event, with its retry lane already mapped. */
export interface PagerDutyFailedRecord {
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
   * non-2xx status is a fail-closed message (unknown routing
   * key, invalid envelope).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface PagerDutySendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Events the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-248). */
export interface PagerDutySinkStats {
  /** Events accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Events reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for PagerDuty send failures. Carries every failed
 * event with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those events. A send call that
 * throws has partial success behind it — the accepted events
 * are already incidents on PagerDuty's server and are *not*
 * in `failedRecords`.
 */
export class PagerDutySinkError extends Error {
  /** Per-event failures, in input order, each with their retry lane. */
  readonly failedRecords: PagerDutyFailedRecord[];
  constructor(message: string, failedRecords: PagerDutyFailedRecord[]) {
    super(message);
    this.name = "PagerDutySinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected, or the routing key is missing. A
 * config problem, not a downstream verdict, so the retry
 * queue must not burn attempts on it (`classifyFailure`
 * maps it to `non_retryable`).
 */
export class PagerDutySinkConfigError extends PagerDutySinkError {
  constructor(reason: string) {
    super(`pagerduty-sink: ${reason}`, []);
    this.name = "PagerDutySinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing routing key is *not* a shape error: it is a config
 * error raised at send time (`PagerDutySinkConfigError`), so a
 * sink built before its key is known still fails closed at send
 * time rather than crashing at construction. A present routing
 * key must be a non-empty string, free of NUL and whitespace;
 * a present severity must be one of the four API tiers.
 */
export function assertValidPagerDutySinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is PagerDutySinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  const routingKey = c.routingKey;
  if (routingKey !== undefined) {
    if (
      typeof routingKey !== "string" ||
      routingKey === "" ||
      (routingKey as string).includes("\0") ||
      /\s/.test(routingKey as string)
    ) {
      throw new RangeError(
        at("`routingKey` must be a non-empty string, free of NUL and whitespace when set")
      );
    }
  }
  if (
    c.severity !== undefined &&
    (typeof c.severity !== "string" ||
      !(PAGERDUTY_SEVERITIES as readonly string[]).includes(c.severity))
  ) {
    throw new RangeError(
      at("`severity` must be one of `critical`, `error`, `warning`, `info` when set")
    );
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
 * Derive one record's summary: the first non-empty value
 * among `subject`, `key`, and `traceId`, in that order.
 * Falls back to the generic `webhook event` summary when
 * the record carries none — a notification sink must not
 * silently drop sourceless events, and the routing key
 * (not the summary) is the delivery contract.
 */
export function resolvePagerDutySummary(record: PagerDutyRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return PAGERDUTY_FALLBACK_SUMMARY;
}

/**
 * Resolve the severity for a sink: the configured tier, or
 * the `error` default. The default is `error`, not
 * `critical`: paging the rotation for every relayed event
 * would train it to ignore pages; `critical` is an
 * explicit operator choice.
 */
export function resolvePagerDutySeverity(
  config: Pick<PagerDutySinkConfig, "severity">
): PagerDutySeverity {
  return config.severity ?? PAGERDUTY_DEFAULT_SEVERITY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood an incident timeline.
 */
export function truncatePagerDutyPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Build one record's `custom_details`: the event's
 * identifiers (`key`, `traceId`, when set) always, plus
 * the body verbatim under `body` only under the
 * `includePayload` opt-in, truncated to `payloadMaxChars`
 * (default 2000). Without the opt-in, no body ever
 * reaches the incident timeline.
 */
export function resolvePagerDutyCustomDetails(
  record: PagerDutyRecord,
  config: Pick<PagerDutySinkConfig, "includePayload" | "payloadMaxChars">
): Record<string, string> {
  const details: Record<string, string> = {};
  if (record.key !== undefined && record.key !== "") {
    details.key = record.key;
  }
  if (record.traceId !== undefined && record.traceId !== "") {
    details.traceId = record.traceId;
  }
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? PAGERDUTY_DEFAULT_PAYLOAD_MAX_CHARS;
    details.body = truncatePagerDutyPayload(record.body, limit);
  }
  return details;
}

/** The serialized Events API v2 envelope for one record, as an object. */
export interface PagerDutyEnvelope {
  routing_key: string;
  event_action: "trigger";
  dedup_key?: string;
  payload: {
    summary: string;
    source: string;
    severity: PagerDutySeverity;
    custom_details: Record<string, string>;
  };
}

/**
 * Build one record's Events API v2 envelope: the routing
 * key, the fixed `trigger` action, the event key as
 * `dedup_key` when set (omitted otherwise — PagerDuty
 * generates one, and an invented key would collapse
 * unrelated incidents), and the payload with its summary,
 * fixed source, resolved severity, and custom details.
 */
export function buildPagerDutyEnvelope(
  routingKey: string,
  record: PagerDutyRecord,
  config: Pick<PagerDutySinkConfig, "severity" | "includePayload" | "payloadMaxChars">
): PagerDutyEnvelope {
  const envelope: PagerDutyEnvelope = {
    routing_key: routingKey,
    event_action: "trigger",
    payload: {
      summary: resolvePagerDutySummary(record),
      source: PAGERDUTY_SOURCE,
      severity: resolvePagerDutySeverity(config),
      custom_details: resolvePagerDutyCustomDetails(record, config),
    },
  };
  if (record.key !== undefined && record.key !== "") {
    envelope.dedup_key = record.key;
  }
  return envelope;
}

/**
 * Validate one record's body and resolve its send form:
 * the serialized Events API v2 envelope. Throws
 * `RangeError` on an empty body string — even without the
 * opt-in, the body is the record's payload, and an empty
 * record is a caller bug that must fail closed, never
 * trigger as an empty incident.
 */
export function resolvePagerDutyRecord(
  record: PagerDutyRecord,
  index: number,
  routingKey: string,
  config: Pick<PagerDutySinkConfig, "severity" | "includePayload" | "payloadMaxChars">
): { body: string; index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`pagerduty-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { body: JSON.stringify(buildPagerDutyEnvelope(routingKey, record, config)), index };
}

/**
 * Map one PagerDuty POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says PagerDuty could not
 * accept the event right now, not that the payload is
 * poison. Every other non-2xx status (400, 401, 403, 404,
 * and the rest) is a fail-closed message: unknown routing
 * key, invalid envelope, or another verdict retrying
 * cannot change. Callers only pass non-2xx statuses here;
 * a 2xx status is a success, not a failure.
 */
export function classifyPagerDutyRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * PagerDuty sink (WR-248). One instance targets one
 * PagerDuty service integration; the caller owns
 * retry/dead-letter policy around `send()` — this class
 * performs one POST attempt per event through the injected
 * client and reports its outcome. Failures throw
 * `PagerDutySinkError` carrying exactly the failed events
 * with their retry lanes.
 */
export class PagerDutySink {
  private readonly cfg: PagerDutySinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: PagerDutySinkConfig) {
    assertValidPagerDutySinkConfig(config, "PagerDutySink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): PagerDutySinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send events as PagerDuty incidents, in input order.
   * Throws `PagerDutySinkConfigError` when no client was
   * injected or the routing key is missing, and
   * `PagerDutySinkError` when any event fails (carrying
   * exactly the failed events with their retry lanes; both
   * counted in stats before throwing, so the counters stay
   * honest even for callers that only inspect stats).
   */
  async send(records: PagerDutyRecord[]): Promise<PagerDutySendResult> {
    const resolved = records.map((r, i) => {
      if (typeof r.body !== "string" || r.body === "") {
        throw new RangeError(`pagerduty-sink: record ${i} \`body\` must be a non-empty event JSON string`);
      }
      return { record: r, index: i };
    });
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The routing
      // key and client are not required here, mirroring the
      // sibling sinks' dry-run exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new PagerDutySinkConfigError("no client injected (set `client` in the sink config)");
    }
    const routingKey = this.cfg.routingKey;
    if (routingKey === undefined) {
      throw new PagerDutySinkConfigError("no routing key configured (set `routingKey` in the sink config)");
    }
    const prepared = resolved.map(({ record, index }) =>
      resolvePagerDutyRecord(record, index, routingKey, this.cfg)
    );
    const failedRecords: PagerDutyFailedRecord[] = [];
    let sent = 0;
    for (const record of prepared) {
      try {
        const response = await client.post({
          url: PAGERDUTY_EVENTS_URL,
          body: record.body,
        });
        if (response.status >= 200 && response.status < 300) {
          sent += 1;
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyPagerDutyRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toPagerDutyFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new PagerDutySinkError(
        `pagerduty-sink: send failed for ${failedRecords.length} of ${prepared.length} events`,
        failedRecords
      );
    }
    return { ok: true, sent };
  }
}

/**
 * Convert a client throw into a failed event: a codeless
 * transport failure (`TRANSPORT_ERROR`, retryable — the SQS
 * no-status rule).
 */
function toPagerDutyFailedRecord(err: unknown, index: number): PagerDutyFailedRecord {
  const failed: PagerDutyFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
