/**
 * Google Cloud Pub/Sub delivery sink (WR-220).
 *
 * Some downstreams are not HTTP endpoints at all: they are Pub/Sub
 * topics. Where the SQS sink (WR-210) delivers to an unordered
 * queue, the Kinesis sink (WR-213) delivers to an AWS SigV4 stream,
 * the Kafka sink (WR-215) delivers to a partitioned log, the MQTT
 * sink (WR-216) delivers to a pub/sub topic tree, the AMQP sink
 * (WR-217) delivers to an exchange, the JetStream sink (WR-218)
 * delivers to a durable stream over the native JetStream publish
 * protocol, and the Redis sink (WR-219) delivers to a Redis stream
 * with XADD, this sink delivers to a Google Cloud Pub/Sub topic:
 * one event is published as one message, and Pub/Sub — not the
 * relay — owns the message id, the topic's retention, and fan-out
 * to subscriptions. The sinks are orthogonal — queue delivery for
 * unordered work, stream delivery for AWS-ordered work, log
 * delivery for broker-native ordered work, topic-tree delivery for
 * broker-mediated fan-out, exchange delivery for broker-mediated
 * routing, durable-stream delivery for replayable work,
 * Redis-stream delivery for in-memory ordered work, Pub/Sub
 * delivery for cloud-managed fan-out — and a Pub/Sub delivery can
 * still be archived by the S3 offloaders like any other delivery.
 *
 * No real Pub/Sub client is bundled: the client is injected through
 * `config.client` (a thin adapter over whatever client the
 * operator runs — @google-cloud/pubsub, a sidecar), so the module
 * has zero new dependencies and tests never need a GCP project.
 * The sink owns the relay-side concerns — topic targeting,
 * attribute pass-through, ordering-key opt-in, per-message failure
 * mapping — and the injected client owns the wire protocol,
 * including the publish call and the message id it returns.
 *
 * Wire shape — one publish request per message, carried to the
 * injected client as:
 *
 *   { topic: "<topic>", data: "<event JSON>",
 *     attributes: { tenant: "<tenant>", endpoint: "<endpoint>",
 *       "trace-id": "<traceId>" },
 *     orderingKey: "<event key>" }
 *
 * Attributes — a message's attributes pass through the record's
 * own tenant, endpoint, and trace id, never invented: an attribute
 * is present only when the record carries that value, so a
 * subscriber can filter or correlate without opening the body.
 * The trace id rides as `trace-id`, the same attribute name the
 * Redis sink uses for its entry field, so a consumer reading both
 * sinks sees one correlation key. A record with none of the three
 * carries an empty attributes object — the sink never invents a
 * tenant, an endpoint, or a trace id.
 *
 * Ordering keys — opt-in, and only effective when the topic has
 * ordering enabled. When `orderingKey` is set and the topic is
 * declared ordering-enabled (`orderingEnabled`), a record's event
 * `key` becomes the message's ordering key, so messages sharing a
 * key are delivered in publish order. When either flag is absent,
 * or the record has no key, no ordering key is attached: the
 * ordering key is ignored, not defaulted, because ordering on a
 * topic that never enabled it is a publish error
 * (`FAILED_PRECONDITION`), and inventing a key would silently
 * serialize unrelated events. The operator enables both flags
 * together only for topics created with message ordering.
 *
 * Failure handling mirrors the WR-210 SQS sink's classification
 * (`src/failure.ts`), applied per message:
 *
 * - a per-message publish failure throws `PubSubSinkError`
 *   carrying every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed messages;
 * - retryable codes are the transient Pub/Sub states — quota
 *   exhaustion, unavailability, deadline overruns, internal
 *   errors, and codeless transport failures: a quota failure says
 *   Pub/Sub could not accept the message right now, not that the
 *   payload is poison;
 * - non-retryable codes are the fail-closed messages — permission
 *   denied, unknown topic, malformed message, ordering on a
 *   non-ordering topic: retrying them burns the retry budget for
 *   nothing, and rerouting them elsewhere would break the fan-out
 *   contract the subscribers depend on;
 * - a missing client or a missing topic throws
 *   `PubSubSinkConfigError`, which `classifyFailure` maps to
 *   `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Topic-name cap: Pub/Sub topic names are short operator strings. */
export const PUBSUB_TOPIC_MAX = 255;

/** Message attribute carrying the record's tenant, verbatim. */
export const PUBSUB_TENANT_ATTRIBUTE = "tenant";

/** Message attribute carrying the record's endpoint, verbatim. */
export const PUBSUB_ENDPOINT_ATTRIBUTE = "endpoint";

/** Message attribute carrying the record's trace id, verbatim. */
export const PUBSUB_TRACE_ID_ATTRIBUTE = "trace-id";

/**
 * One publish request as handed to the injected client. The client
 * owns the wire protocol (including the message id it returns);
 * this shape is the relay-side contract it must honour.
 */
export interface PubSubPublishRequest {
  /** Target topic (the sink's configured topic). */
  topic: string;
  /** The event JSON, verbatim. */
  data: string;
  /**
   * Pass-through attributes: `tenant`, `endpoint`, and
   * `trace-id`, each present only when the record carried that
   * value — the sink never invents an attribute.
   */
  attributes: Record<string, string>;
  /**
   * Ordering key, present only when the sink opted into ordering,
   * the topic is ordering-enabled, and the record has a key.
   */
  orderingKey?: string;
}

/**
 * The injected Pub/Sub client. Any client adapter implements this
 * one method; per-message failures throw `PubSubPublishError` (or
 * any error, which the sink treats as a transport failure). The
 * client is expected to publish one message per call, so the
 * returned id is the message Pub/Sub stored.
 */
export interface PubSubClient {
  publish(request: PubSubPublishRequest): Promise<string>;
}

/**
 * Configuration for one Pub/Sub sink. The client is injected:
 * without one, `publish()` throws `PubSubSinkConfigError` (dry
 * runs excepted — they need no client at all). Without a topic,
 * `publish()` likewise throws `PubSubSinkConfigError`: a missing
 * topic is a config problem, not a silent no-op.
 */
export interface PubSubSinkConfig {
  /**
   * Target topic, e.g. `projects/p/topics/events`. Required for
   * real sends; a missing topic is a config error at publish
   * time. When set, it must be 1–255 characters, free of NUL and
   * whitespace. One sink targets one topic only.
   */
  topic?: string;
  /**
   * The Pub/Sub client to deliver through. Injected, never
   * bundled: the operator's client adapter (@google-cloud/pubsub,
   * sidecar) implements `PubSubClient`. Required for real sends;
   * a missing client is a config error, not a silent no-op.
   */
  client?: PubSubClient;
  /**
   * Rehearsal mode: `publish()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero client
   * I/O — no publish call, no stat changes. Records are still
   * validated, so a dry run catches a malformed record before it
   * reaches production. Mirrors the `dryRun` convention of the S3
   * offloaders.
   */
  dryRun?: boolean;
  /**
   * Ordering-key opt-in: when `true` and the topic is
   * ordering-enabled (see `orderingEnabled`), a record's event
   * `key` becomes the message's ordering key. When `false` or
   * absent, no ordering key is ever attached.
   */
  orderingKey?: boolean;
  /**
   * Declares that the configured topic was created with message
   * ordering enabled. The ordering key is attached only when both
   * this and `orderingKey` are set: ordering on a topic that
   * never enabled it is a publish error, so the sink ignores the
   * key rather than failing the message.
   */
  orderingEnabled?: boolean;
}

/** One event to publish to the topic. */
export interface PubSubRecord {
  /** The event JSON, already serialized by the caller — stored verbatim. */
  body: string;
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
   * Trace id: passed through verbatim as the `trace-id` message
   * attribute when set, absent otherwise — the sink never invents
   * a trace id.
   */
  traceId?: string;
  /**
   * Event key (e.g. aggregate id): the ordering-key source when
   * the sink opted into ordering and the topic is
   * ordering-enabled. Events sharing a key are delivered in
   * publish order.
   */
  key?: string;
}

/** One record as it goes to the client (attributes built, ordering key resolved). */
export interface PubSubResolvedRecord {
  /** The event JSON, verbatim. */
  data: string;
  /** Pass-through attributes (only the record's own values). */
  attributes: Record<string, string>;
  /** Ordering key, present only under the ordering opt-in (see above). */
  orderingKey?: string;
}

/** One failed message, with its retry lane already mapped. */
export interface PubSubFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /** Pub/Sub error code, or `TRANSPORT_ERROR` for a codeless failure. */
  errorCode: string;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: transient Pub/Sub states
   * (including quota exhaustion and unavailability) are retryable,
   * fail-closed messages (permission, unknown topic, malformed
   * message, ordering on a non-ordering topic) are not.
   */
  retryable: boolean;
}

/** Outcome of one `publish()` call (failures throw, see above). */
export interface PubSubPublishResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-220). */
export interface PubSubSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** Publish calls that threw (counted before the error is thrown). */
  publishFailures: number;
}

/**
 * Thrown when a publish throws per message: a Pub/Sub-side or
 * transport failure mapped onto the Pub/Sub error code. Carries the
 * codeless transport case as `TRANSPORT_ERROR`, and every failed
 * message with its retry lane, so the caller retries exactly the
 * failed messages without parsing message strings.
 */
export class PubSubPublishError extends Error {
  /** Pub/Sub error code (e.g. `UNAVAILABLE`). */
  readonly errorCode: string;
  constructor(errorCode: string, message?: string) {
    super(message ?? `pubsub-sink: publish failed (${errorCode})`);
    this.name = "PubSubPublishError";
    this.errorCode = errorCode;
  }
}

/**
 * Thrown for Pub/Sub publish failures. Carries every failed message
 * with its retry lane (`failedRecords`), so the retry queue can
 * requeue exactly those messages. A publish call that throws has
 * partial success behind it — the accepted messages are already in
 * their topic and are *not* in `failedRecords`.
 */
export class PubSubSinkError extends Error {
  /** Per-message failures, in input order, each with its retry lane. */
  readonly failedRecords: PubSubFailedRecord[];
  constructor(message: string, failedRecords: PubSubFailedRecord[]) {
    super(message);
    this.name = "PubSubSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even publish — currently: no client
 * was injected, or no topic was configured. A config problem, not
 * a downstream verdict, so the retry queue must not burn attempts
 * on it (`classifyFailure` maps it to `non_retryable`).
 */
export class PubSubSinkConfigError extends PubSubSinkError {
  constructor(reason: string) {
    super(`pubsub-sink: ${reason}`, []);
    this.name = "PubSubSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing topic is *not* a shape error: it is a config error at
 * publish time (`PubSubSinkConfigError`), so a sink built before
 * its topic is known still fails closed rather than crashing at
 * construction.
 */
export function assertValidPubSubSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is PubSubSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  if (c.topic !== undefined) {
    if (
      typeof c.topic !== "string" ||
      c.topic === "" ||
      c.topic.length > PUBSUB_TOPIC_MAX ||
      c.topic.includes("\0") ||
      /\s/.test(c.topic)
    ) {
      throw new RangeError(
        at("`topic` must be 1–255 characters, free of NUL and whitespace when set")
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
 * Build one record's pass-through attributes: `tenant`,
 * `endpoint`, and `trace-id`, each present only when the record
 * carries a non-empty value for it — the sink never invents an
 * attribute.
 */
export function resolvePubSubAttributes(record: PubSubRecord): Record<string, string> {
  const attributes: Record<string, string> = {};
  if (record.tenant !== undefined && record.tenant !== "") {
    attributes[PUBSUB_TENANT_ATTRIBUTE] = record.tenant;
  }
  if (record.endpoint !== undefined && record.endpoint !== "") {
    attributes[PUBSUB_ENDPOINT_ATTRIBUTE] = record.endpoint;
  }
  if (record.traceId !== undefined && record.traceId !== "") {
    attributes[PUBSUB_TRACE_ID_ATTRIBUTE] = record.traceId;
  }
  return attributes;
}

/**
 * Resolve one record's ordering key: the record's event `key`,
 * but only when the sink opted into ordering (`orderingKey`) and
 * the topic is ordering-enabled (`orderingEnabled`). Any other
 * combination — including a key on a non-ordering topic — yields
 * no ordering key: the key is ignored, not defaulted, because
 * ordering on a topic that never enabled it is a publish error.
 */
export function resolvePubSubOrderingKey(
  record: PubSubRecord,
  config: Pick<PubSubSinkConfig, "orderingKey" | "orderingEnabled">
): string | undefined {
  if (config.orderingKey !== true || config.orderingEnabled !== true) {
    return undefined;
  }
  if (record.key === undefined || record.key === "") {
    return undefined;
  }
  return record.key;
}

/**
 * Validate one record's body and resolve its publish form: the
 * attributes pass through verbatim, and the ordering key resolves
 * under the ordering opt-in. Throws `RangeError` on an empty body
 * string.
 */
export function resolvePubSubRecord(
  record: PubSubRecord,
  index: number,
  config: Pick<PubSubSinkConfig, "orderingKey" | "orderingEnabled">
): PubSubResolvedRecord {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`pubsub-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  const resolved: PubSubResolvedRecord = {
    data: record.body,
    attributes: resolvePubSubAttributes(record),
  };
  const orderingKey = resolvePubSubOrderingKey(record, config);
  if (orderingKey !== undefined) {
    resolved.orderingKey = orderingKey;
  }
  return resolved;
}

/**
 * Pub/Sub error codes that are transient — quota exhaustion,
 * unavailability, deadline overruns, internal errors — and so
 * retryable under the WR-210 mapping. A quota failure is
 * retryable: it says Pub/Sub could not accept the message right
 * now, not that the payload is poison. A codeless transport
 * failure is carried as `TRANSPORT_ERROR` and is retryable too:
 * like an SQS transport error with no status, it says nothing
 * about the payload. Any code not listed here is a fail-closed
 * message (permission denied, unknown topic, malformed message,
 * ordering on a non-ordering topic) and is non-retryable:
 * retrying it burns the retry budget for nothing, and rerouting it
 * elsewhere would break the fan-out contract.
 */
const PUBSUB_RETRYABLE_ERROR_CODES = new Set([
  "TRANSPORT_ERROR",
  "RESOURCE_EXHAUSTED",
  "UNAVAILABLE",
  "DEADLINE_EXCEEDED",
  "INTERNAL",
  "ABORTED",
]);

/**
 * Map one Pub/Sub publish `errorCode` onto its retry lane under
 * the WR-210 rules: transient Pub/Sub states (including quota
 * exhaustion and unavailability) are retryable, any other code is
 * a fail-closed message, like any other 4xx.
 */
export function classifyPubSubRecordFailure(errorCode: string): boolean {
  return PUBSUB_RETRYABLE_ERROR_CODES.has(errorCode);
}

/**
 * Pub/Sub sink (WR-220). One instance targets one topic; the
 * caller owns retry/dead-letter policy around `publish()` — this
 * class performs one publish attempt per message through the
 * injected client and reports its outcome. Failures throw
 * `PubSubSinkError` carrying exactly the failed messages with
 * their retry lanes.
 */
export class PubSubSink {
  private readonly cfg: PubSubSinkConfig;
  private sent = 0;
  private failed = 0;
  private publishFailures = 0;

  constructor(config: PubSubSinkConfig) {
    assertValidPubSubSinkConfig(config, "PubSubSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): PubSubSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      publishFailures: this.publishFailures,
    };
  }

  /**
   * Publish messages to the configured topic, in input order.
   * Throws `PubSubSinkConfigError` when no client was injected or
   * no topic was configured, and `PubSubSinkError` when any
   * message fails (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so the
   * counters stay honest even for callers that only inspect
   * stats).
   */
  async publish(records: PubSubRecord[]): Promise<PubSubPublishResult> {
    const resolved = records.map((r, i) => resolvePubSubRecord(r, i, this.cfg));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches a
      // malformed record before it reaches production — but perform
      // zero client I/O and touch no stats.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new PubSubSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const topic = this.cfg.topic;
    if (topic === undefined) {
      throw new PubSubSinkConfigError("no topic configured (set `topic` in the sink config)");
    }
    const failedRecords: PubSubFailedRecord[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i] as PubSubResolvedRecord;
      try {
        await client.publish({
          topic,
          data: record.data,
          attributes: record.attributes,
          ...(record.orderingKey !== undefined ? { orderingKey: record.orderingKey } : {}),
        });
      } catch (err) {
        failedRecords.push(toPubSubFailedRecord(err, i));
        continue;
      }
      sent += 1;
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.publishFailures += 1;
      throw new PubSubSinkError(
        `pubsub-sink: publish ${topic} failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent };
  }
}

/**
 * Convert a client throw into a failed message: a
 * `PubSubPublishError` maps by its code, any other error is a
 * codeless transport failure (`TRANSPORT_ERROR`, retryable — the
 * SQS no-status rule).
 */
function toPubSubFailedRecord(err: unknown, index: number): PubSubFailedRecord {
  if (err instanceof PubSubPublishError) {
    const failed: PubSubFailedRecord = {
      index,
      errorCode: err.errorCode,
      retryable: classifyPubSubRecordFailure(err.errorCode),
    };
    if (err.message !== "") failed.errorMessage = err.message;
    return failed;
  }
  const failed: PubSubFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
