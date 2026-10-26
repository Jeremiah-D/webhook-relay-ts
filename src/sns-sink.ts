/**
 * AWS SNS delivery sink (WR-224).
 *
 * Some downstreams are not HTTP endpoints at all: they are SNS
 * topics. Where the SQS sink (WR-210) delivers to an unordered
 * queue, the Kinesis sink (WR-213) delivers to an AWS SigV4
 * stream, the Kafka sink (WR-215) delivers to a partitioned log,
 * the MQTT sink (WR-216) delivers to a pub/sub topic tree, the
 * AMQP sink (WR-217) delivers to an exchange, the JetStream sink
 * (WR-218) delivers to a durable stream over the native JetStream
 * publish protocol, the Redis sink (WR-219) delivers to a Redis
 * stream with XADD, the Pub/Sub sink (WR-220) delivers to a Google
 * Cloud topic with pass-through attributes, the Service Bus sink
 * (WR-221) delivers to an Azure queue or topic with pass-through
 * properties, the EventBridge sink (WR-222) delivers to an AWS
 * event bus with a resolved DetailType, and the Pulsar sink
 * (WR-223) delivers to an Apache Pulsar topic, this sink delivers
 * to an AWS SNS topic: one event is published as one message,
 * and SNS — not the relay — owns the message id, the topic's
 * retention, and fan-out to subscriptions. The sinks are
 * orthogonal — queue delivery for unordered work, stream delivery
 * for AWS-ordered work, log delivery for broker-native ordered
 * work, topic-tree delivery for broker-mediated fan-out, exchange
 * delivery for broker-mediated routing, durable-stream delivery
 * for replayable work, Redis-stream delivery for in-memory
 * ordered work, Pub/Sub delivery for cloud-managed fan-out,
 * Service Bus delivery for Azure-managed fan-out, EventBridge
 * delivery for rule-routed cloud events, Pulsar delivery for
 * geo-replicated partitioned topics, SNS delivery for
 * cloud-managed fan-out to many protocols at once — and an SNS
 * delivery can still be archived by the S3 offloaders like any
 * other delivery.
 *
 * No real SNS client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever client
 * the operator runs — the AWS SDK, a sidecar), so the module
 * has zero new dependencies and tests never need an AWS
 * account. The sink owns the relay-side concerns — topic
 * targeting, attribute pass-through, FIFO field opt-ins,
 * per-message failure mapping — and the injected client owns
 * the wire protocol, including the Publish call and the message
 * id it returns.
 *
 * Wire shape — one Publish request per message, carried to the
 * injected client as:
 *
 *   { topicArn: "<topic ARN>",
 *     message: "<event JSON>",
 *     messageAttributes: { tenant: "<tenant>", endpoint: "<endpoint>",
 *       trace: "<traceId>" },
 *     messageGroupId: "<event key>",          // FIFO topics only, opt-in
 *     messageDeduplicationId: "<event id>" }  // FIFO topics only
 *
 * Topic targeting — one sink targets one topic ARN when
 * `topicArn` is configured: every message goes there. When no
 * topic ARN is configured, the topic resolves per record from
 * the event's own values, first non-empty wins: `subject`, then
 * `key`, then `traceId` — the same source chain the EventBridge
 * sink uses for its DetailType and the Pulsar sink uses for its
 * topic. A record with none of the three has no topic source
 * and fails closed with a `RangeError` at resolve time:
 * inventing a topic would deliver the event to subscribers that
 * never asked for it.
 *
 * Message attributes — a message's attributes pass through the
 * record's own tenant, endpoint, and trace id, never invented:
 * an attribute is present only when the record carries that
 * value, so a subscriber can filter or correlate without
 * opening the body. The trace id rides as `trace`, the short
 * name the sibling sinks use for the same value. A record with
 * none of the three carries an empty attributes object — the
 * sink never invents a tenant, an endpoint, or a trace id.
 *
 * FIFO fields — only a topic whose name ends in `.fifo` is a
 * FIFO topic, and only on FIFO topics do the two extra fields
 * ever appear (SNS rejects them on standard topics, so
 * attaching them elsewhere would fail every publish):
 *
 * - `messageGroupId` is opt-in, and only effective when the
 *   sink opted in (`messageGroupId`). When set, a record's
 *   event `key` becomes the message's group id, so messages
 *   sharing a key stay ordered within the group. When the flag
 *   is absent, or the record has no key, or the topic is not
 *   FIFO, no group id is attached: the key is ignored, not
 *   defaulted, because a group id the operator never asked for
 *   would silently serialize unrelated events behind each
 *   other.
 * - `messageDeduplicationId` needs no opt-in: on a FIFO topic
 *   a record's event `id` becomes the deduplication id, so a
 *   retried publish of the same event is deduplicated by SNS
 *   itself. When the record has no id, or the topic is not
 *   FIFO, no deduplication id is attached — the sink never
 *   invents one, because an invented id would deduplicate
 *   unrelated events against each other.
 *
 * Failure handling mirrors the WR-210 SQS sink's classification
 * (`src/failure.ts`), applied per message:
 *
 * - a per-message Publish failure throws `SnsSinkError`
 *   carrying every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed messages;
 * - retryable codes are the transient SNS states —
 *   throttling, internal errors, service unavailability, and
 *   codeless transport failures: a throttling failure says SNS
 *   could not accept the message right now, not that the
 *   payload is poison;
 * - non-retryable codes are the fail-closed messages —
 *   permission denied, unknown topic, malformed message:
 *   retrying them burns the retry budget for nothing, and
 *   rerouting them elsewhere would break the fan-out contract
 *   the subscribers depend on;
 * - a missing client throws `SnsSinkConfigError`, which
 *   `classifyFailure` maps to `non_retryable` (the WR-116
 *   rule). A missing topic ARN is not a config error: it
 *   selects per-record topic resolution instead.
 *
 * Zero new dependencies: the injected client only.
 */

/** Message attribute carrying the record's tenant, verbatim. */
export const SNS_TENANT_ATTRIBUTE = "tenant";

/** Message attribute carrying the record's endpoint, verbatim. */
export const SNS_ENDPOINT_ATTRIBUTE = "endpoint";

/** Message attribute carrying the record's trace id, verbatim. */
export const SNS_TRACE_ATTRIBUTE = "trace";

/**
 * One Publish request as handed to the injected client. The
 * client owns the wire protocol (including the message id it
 * returns); this shape is the relay-side contract it must
 * honour.
 */
export interface SnsPublishRequest {
  /** Target topic ARN (the sink's configured ARN, or the record's resolved topic). */
  topicArn: string;
  /** The event JSON, verbatim. */
  message: string;
  /**
   * Pass-through message attributes: `tenant`, `endpoint`, and
   * `trace`, each present only when the record carried that
   * value — the sink never invents an attribute.
   */
  messageAttributes: Record<string, string>;
  /**
   * FIFO group id, present only on FIFO topics when the sink
   * opted into group ids and the record has a key.
   */
  messageGroupId?: string;
  /**
   * FIFO deduplication id, present only on FIFO topics when the
   * record has an event id.
   */
  messageDeduplicationId?: string;
}

/**
 * The injected SNS client. Any client adapter implements this
 * one method; per-message failures throw `SnsPublishError`
 * (or any error, which the sink treats as a transport failure).
 * The client is expected to publish one message per call, so
 * the returned id is the message SNS stored.
 */
export interface SnsClient {
  publish(request: SnsPublishRequest): Promise<string>;
}

/**
 * Configuration for one SNS sink. The client is injected:
 * without one, `publish()` throws `SnsSinkConfigError` (dry
 * runs excepted — they need no client at all). A missing topic
 * ARN is not a config error: it selects per-record topic
 * resolution (subject, then key, then trace id).
 */
export interface SnsSinkConfig {
  /**
   * Target topic ARN, e.g.
   * `arn:aws:sns:us-east-1:123456789012:events`. When set,
   * every message goes there; when absent, the topic resolves
   * per record (see `resolveSnsTopic`). When set, it must be
   * a non-empty string, free of NUL and whitespace.
   */
  topicArn?: string;
  /**
   * The SNS client to deliver through. Injected, never
   * bundled: the operator's client adapter implements
   * `SnsClient`. Required for real sends; a missing client
   * is a config error, not a silent no-op.
   */
  client?: SnsClient;
  /**
   * Rehearsal mode: `publish()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no Publish call, no stat changes. Records are
   * still validated (including per-record topic resolution),
   * so a dry run catches a topic-less record before it reaches
   * production. Mirrors the `dryRun` convention of the S3
   * offloaders.
   */
  dryRun?: boolean;
  /**
   * Message-group-id opt-in: when `true`, a record's event
   * `key` becomes the message's group id — but only on FIFO
   * topics (see `resolveSnsMessageGroupId`). When `false` or
   * absent, no group id is ever attached.
   */
  messageGroupId?: boolean;
}

/** One event to publish to the topic. */
export interface SnsRecord {
  /** The event JSON, already serialized by the caller — stored verbatim. */
  body: string;
  /**
   * Topic-resolution source, first priority (only when the sink
   * has no configured topic ARN): the event's subject, when set
   * and non-empty. Falls through to `key`, then `traceId`.
   */
  subject?: string;
  /**
   * Topic-resolution source, second priority (only when the sink
   * has no configured topic ARN): the event's key (e.g.
   * aggregate id). Also the message-group-id source when the
   * sink opted into group ids on a FIFO topic.
   */
  key?: string;
  /**
   * Topic-resolution source, last priority (only when the sink
   * has no configured topic ARN): the trace id. Also passed
   * through verbatim as the `trace` message attribute when set,
   * absent otherwise — the sink never invents a trace id.
   */
  traceId?: string;
  /**
   * Tenant attribute source: passed through verbatim as the
   * `tenant` message attribute when set, absent otherwise — the
   * sink never invents a tenant.
   */
  tenant?: string;
  /**
   * Endpoint attribute source: passed through verbatim as the
   * `endpoint` message attribute when set, absent otherwise.
   */
  endpoint?: string;
  /**
   * Event id: the message-deduplication-id source on FIFO
   * topics (see `resolveSnsMessageDeduplicationId`). Absent
   * otherwise — the sink never invents a deduplication id.
   */
  id?: string;
}

/** One record as it goes to the client (topic resolved, attributes built, FIFO fields resolved). */
export interface SnsResolvedRecord {
  /** Target topic ARN (configured, or resolved per record). */
  topicArn: string;
  /** The event JSON, verbatim. */
  message: string;
  /** Pass-through message attributes (only the record's own values). */
  messageAttributes: Record<string, string>;
  /** FIFO group id, present only under the group-id opt-in on FIFO topics (see above). */
  messageGroupId?: string;
  /** FIFO deduplication id, present only on FIFO topics when the record has an event id. */
  messageDeduplicationId?: string;
}

/** One failed message, with its retry lane already mapped. */
export interface SnsFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /** SNS error code, or `TRANSPORT_ERROR` for a codeless failure. */
  errorCode: string;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: transient SNS states
   * (including throttling and internal errors) are retryable,
   * fail-closed messages (permission, unknown topic, malformed
   * message) are not.
   */
  retryable: boolean;
}

/** Outcome of one `publish()` call (failures throw, see above). */
export interface SnsPublishResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-224). */
export interface SnsSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** Publish calls that threw (counted before the error is thrown). */
  publishFailures: number;
}

/**
 * Thrown when a Publish throws per message: an SNS-side or
 * transport failure mapped onto the SNS error code. Carries
 * the codeless transport case as `TRANSPORT_ERROR`, and every
 * failed message with its retry lane, so the caller retries
 * exactly the failed messages without parsing message strings.
 */
export class SnsPublishError extends Error {
  /** SNS error code (e.g. `ThrottlingException`). */
  readonly errorCode: string;
  constructor(errorCode: string, message?: string) {
    super(message ?? `sns-sink: publish failed (${errorCode})`);
    this.name = "SnsPublishError";
    this.errorCode = errorCode;
  }
}

/**
 * Thrown for SNS publish failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A publish call that
 * throws has partial success behind it — the accepted messages
 * are already in their topic and are *not* in `failedRecords`.
 */
export class SnsSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: SnsFailedRecord[];
  constructor(message: string, failedRecords: SnsFailedRecord[]) {
    super(message);
    this.name = "SnsSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even publish — currently: no
 * client was injected. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`). A missing
 * topic ARN is not a config error: it selects per-record topic
 * resolution instead.
 */
export class SnsSinkConfigError extends SnsSinkError {
  constructor(reason: string) {
    super(`sns-sink: ${reason}`, []);
    this.name = "SnsSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing topic ARN is *not* a shape error: it selects
 * per-record topic resolution, so a sink built before its topic
 * is known still fails closed on a topic-less record rather
 * than crashing at construction.
 */
export function assertValidSnsSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is SnsSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  if (c.topicArn !== undefined) {
    if (
      typeof c.topicArn !== "string" ||
      c.topicArn === "" ||
      c.topicArn.includes("\0") ||
      /\s/.test(c.topicArn)
    ) {
      throw new RangeError(
        at("`topicArn` must be a non-empty string, free of NUL and whitespace when set")
      );
    }
  }
  if (
    c.client !== undefined &&
    (c.client === null ||
      typeof c.client !== "object" ||
      typeof (c.client as { publish?: unknown }).publish !== "function")
  ) {
    throw new RangeError(at("`client` must expose a `publish` function when set"));
  }
}

/**
 * Build one record's pass-through message attributes: `tenant`,
 * `endpoint`, and `trace`, each present only when the record
 * carries a non-empty value for it — the sink never invents an
 * attribute.
 */
export function resolveSnsMessageAttributes(record: SnsRecord): Record<string, string> {
  const attributes: Record<string, string> = {};
  if (record.tenant !== undefined && record.tenant !== "") {
    attributes[SNS_TENANT_ATTRIBUTE] = record.tenant;
  }
  if (record.endpoint !== undefined && record.endpoint !== "") {
    attributes[SNS_ENDPOINT_ATTRIBUTE] = record.endpoint;
  }
  if (record.traceId !== undefined && record.traceId !== "") {
    attributes[SNS_TRACE_ATTRIBUTE] = record.traceId;
  }
  return attributes;
}

/**
 * Resolve one record's topic: the sink's configured topic ARN
 * wins; otherwise the first non-empty value among `subject`,
 * `key`, and `traceId`, in that order. Returns `undefined` when
 * the sink has no configured topic ARN and the record carries
 * none of the three — the caller fails closed rather than
 * inventing a topic.
 */
export function resolveSnsTopic(
  record: SnsRecord,
  config: Pick<SnsSinkConfig, "topicArn">
): string | undefined {
  if (config.topicArn !== undefined) {
    return config.topicArn;
  }
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return undefined;
}

/**
 * True when a topic is an SNS FIFO topic: its name ends in
 * `.fifo`. Only FIFO topics ever carry the two extra Publish
 * fields — SNS rejects them on standard topics.
 */
export function isSnsFifoTopic(topicArn: string): boolean {
  return topicArn.endsWith(".fifo");
}

/**
 * Resolve one record's message group id: the record's event
 * `key`, but only when the sink opted into group ids
 * (`messageGroupId`) and the topic is a FIFO topic. Any other
 * combination — including a key with the opt-in absent, or a
 * FIFO-opted sink publishing to a standard topic — yields no
 * group id: the key is ignored, not defaulted, because a group
 * id the operator never asked for would silently serialize
 * unrelated events behind each other, and a group id on a
 * standard topic would fail every publish.
 */
export function resolveSnsMessageGroupId(
  record: SnsRecord,
  config: Pick<SnsSinkConfig, "messageGroupId">,
  topicArn: string
): string | undefined {
  if (config.messageGroupId !== true) {
    return undefined;
  }
  if (!isSnsFifoTopic(topicArn)) {
    return undefined;
  }
  if (record.key === undefined || record.key === "") {
    return undefined;
  }
  return record.key;
}

/**
 * Resolve one record's message deduplication id: the record's
 * event `id`, but only on FIFO topics. On a standard topic,
 * or when the record has no id, no deduplication id is
 * attached: the sink never invents one, because an invented
 * id would deduplicate unrelated events against each other.
 */
export function resolveSnsMessageDeduplicationId(
  record: SnsRecord,
  topicArn: string
): string | undefined {
  if (!isSnsFifoTopic(topicArn)) {
    return undefined;
  }
  if (record.id === undefined || record.id === "") {
    return undefined;
  }
  return record.id;
}

/**
 * Validate one record's body and resolve its publish form: the
 * topic resolves from the sink config or the record's own
 * subject, key, or trace id; the attributes pass through
 * verbatim; and the FIFO fields resolve under their rules.
 * Throws `RangeError` on an empty body string, and on a record
 * with no topic source when the sink has no configured topic
 * ARN — a topic-less record fails closed, never with an
 * invented topic.
 */
export function resolveSnsRecord(
  record: SnsRecord,
  index: number,
  config: Pick<SnsSinkConfig, "topicArn" | "messageGroupId">
): SnsResolvedRecord {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`sns-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  const topicArn = resolveSnsTopic(record, config);
  if (topicArn === undefined) {
    throw new RangeError(
      `sns-sink: record ${index} has no topic source (configure \`topicArn\` or set \`subject\`, \`key\`, or \`traceId\`)`
    );
  }
  const resolved: SnsResolvedRecord = {
    topicArn,
    message: record.body,
    messageAttributes: resolveSnsMessageAttributes(record),
  };
  const messageGroupId = resolveSnsMessageGroupId(record, config, topicArn);
  if (messageGroupId !== undefined) {
    resolved.messageGroupId = messageGroupId;
  }
  const messageDeduplicationId = resolveSnsMessageDeduplicationId(record, topicArn);
  if (messageDeduplicationId !== undefined) {
    resolved.messageDeduplicationId = messageDeduplicationId;
  }
  return resolved;
}

/**
 * SNS error codes that are transient — throttling, internal
 * errors, service unavailability — and so retryable under the
 * WR-210 mapping. A throttling failure is retryable: it says
 * SNS could not accept the message right now, not that the
 * payload is poison. A codeless transport failure is carried as
 * `TRANSPORT_ERROR` and is retryable too: like an SQS transport
 * error with no status, it says nothing about the payload. Any
 * code not listed here is a fail-closed message (permission
 * denied, unknown topic, malformed message) and is
 * non-retryable: retrying it burns the retry budget for
 * nothing, and rerouting it elsewhere would break the fan-out
 * contract.
 */
const SNS_RETRYABLE_ERROR_CODES = new Set([
  "TRANSPORT_ERROR",
  "ThrottlingException",
  "Throttling",
  "TooManyRequestsException",
  "InternalError",
  "InternalErrorException",
  "ServiceUnavailable",
  "ServiceUnavailableException",
]);

/**
 * Map one SNS Publish `errorCode` onto its retry lane under
 * the WR-210 rules: transient SNS states (including throttling
 * and internal errors) are retryable, any other code is a
 * fail-closed message, like any other 4xx.
 */
export function classifySnsRecordFailure(errorCode: string): boolean {
  return SNS_RETRYABLE_ERROR_CODES.has(errorCode);
}

/**
 * SNS sink (WR-224). One instance targets one topic ARN (or
 * resolves topics per record when none is configured); the
 * caller owns retry/dead-letter policy around `publish()` —
 * this class performs one Publish attempt per message through
 * the injected client and reports its outcome. Failures throw
 * `SnsSinkError` carrying exactly the failed messages with
 * their retry lanes.
 */
export class SnsSink {
  private readonly cfg: SnsSinkConfig;
  private sent = 0;
  private failed = 0;
  private publishFailures = 0;

  constructor(config: SnsSinkConfig) {
    assertValidSnsSinkConfig(config, "SnsSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): SnsSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      publishFailures: this.publishFailures,
    };
  }

  /**
   * Publish messages to the configured topic ARN (or each
   * record's resolved topic), in input order. Throws
   * `SnsSinkConfigError` when no client was injected, and
   * `SnsSinkError` when any message fails (carrying exactly
   * the failed messages with their retry lanes; both counted in
   * stats before throwing, so the counters stay honest even for
   * callers that only inspect stats).
   */
  async publish(records: SnsRecord[]): Promise<SnsPublishResult> {
    const resolved = records.map((r, i) => resolveSnsRecord(r, i, this.cfg));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches a
      // topic-less record before it reaches production — but
      // perform zero client I/O and touch no stats.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new SnsSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const failedRecords: SnsFailedRecord[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i] as SnsResolvedRecord;
      try {
        await client.publish({
          topicArn: record.topicArn,
          message: record.message,
          messageAttributes: record.messageAttributes,
          ...(record.messageGroupId !== undefined ? { messageGroupId: record.messageGroupId } : {}),
          ...(record.messageDeduplicationId !== undefined
            ? { messageDeduplicationId: record.messageDeduplicationId }
            : {}),
        });
      } catch (err) {
        failedRecords.push(toSnsFailedRecord(err, i));
        continue;
      }
      sent += 1;
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.publishFailures += 1;
      throw new SnsSinkError(
        `sns-sink: publish failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent };
  }
}

/**
 * Convert a client throw into a failed message: a
 * `SnsPublishError` maps by its code, any other error is a
 * codeless transport failure (`TRANSPORT_ERROR`, retryable — the
 * SQS no-status rule).
 */
function toSnsFailedRecord(err: unknown, index: number): SnsFailedRecord {
  if (err instanceof SnsPublishError) {
    const failed: SnsFailedRecord = {
      index,
      errorCode: err.errorCode,
      retryable: classifySnsRecordFailure(err.errorCode),
    };
    if (err.message !== "") failed.errorMessage = err.message;
    return failed;
  }
  const failed: SnsFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
