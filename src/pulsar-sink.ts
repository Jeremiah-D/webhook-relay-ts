/**
 * Apache Pulsar delivery sink (WR-223).
 *
 * Some downstreams are not HTTP endpoints at all: they are
 * Pulsar topics. Where the SQS sink (WR-210) delivers to an
 * unordered queue, the Kinesis sink (WR-213) delivers to an AWS
 * SigV4 stream, the Kafka sink (WR-215) delivers to a
 * partitioned log, the MQTT sink (WR-216) delivers to a pub/sub
 * topic tree, the AMQP sink (WR-217) delivers to an exchange,
 * the JetStream sink (WR-218) delivers to a durable stream over
 * the native JetStream publish protocol, the Redis sink (WR-219)
 * delivers to a Redis stream with XADD, the Pub/Sub sink
 * (WR-220) delivers to a Google Cloud topic with pass-through
 * attributes, the Service Bus sink (WR-221) delivers to an Azure
 * queue or topic with pass-through properties, and the
 * EventBridge sink (WR-222) delivers to an AWS event bus with a
 * resolved DetailType, this sink delivers to an Apache Pulsar
 * topic: one event is produced as one message, and Pulsar — not
 * the relay — owns the message id, the topic's retention, and
 * fan-out to subscriptions. The sinks are orthogonal — queue
 * delivery for unordered work, stream delivery for AWS-ordered
 * work, log delivery for broker-native ordered work, topic-tree
 * delivery for broker-mediated fan-out, exchange delivery for
 * broker-mediated routing, durable-stream delivery for
 * replayable work, Redis-stream delivery for in-memory ordered
 * work, Pub/Sub delivery for cloud-managed fan-out, Service Bus
 * delivery for Azure-managed fan-out, EventBridge delivery for
 * rule-routed cloud events, Pulsar delivery for
 * geo-replicated partitioned topics — and a Pulsar delivery can
 * still be archived by the S3 offloaders like any other
 * delivery.
 *
 * No real Pulsar client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever client
 * the operator runs — a Pulsar client library, a sidecar), so
 * the module has zero new dependencies and tests never need a
 * Pulsar cluster. The sink owns the relay-side concerns — topic
 * targeting, property pass-through, partition-key opt-in,
 * per-message failure mapping — and the injected client owns
 * the wire protocol, including the produce call and the message
 * id it returns.
 *
 * Wire shape — one produce request per message, carried to the
 * injected client as:
 *
 *   { topic: "<topic>", data: "<event JSON>",
 *     properties: { tenant: "<tenant>", endpoint: "<endpoint>",
 *       trace: "<traceId>" },
 *     partitionKey: "<event key>" }
 *
 * Topic targeting — one sink targets one topic when `topic` is
 * configured: every message goes there. When no topic is
 * configured, the topic resolves per record from the event's own
 * values, first non-empty wins: `subject`, then `key`, then
 * `traceId` — the same source chain the EventBridge sink uses
 * for its DetailType. A record with none of the three has no
 * topic source and fails closed with a `RangeError` at resolve
 * time: inventing a topic would deliver the event to
 * subscribers that never asked for it.
 *
 * Properties — a message's properties pass through the record's
 * own tenant, endpoint, and trace id, never invented: a
 * property is present only when the record carries that value,
 * so a subscriber can filter or correlate without opening the
 * body. The trace id rides as `trace`, the Pulsar-idiomatic
 * short name, because Pulsar properties are operator-chosen
 * strings and the sibling sinks' `trace-id` spelling is a
 * header convention Pulsar does not share. A record with none
 * of the three carries an empty properties object — the sink
 * never invents a tenant, an endpoint, or a trace id.
 *
 * Partition keys — opt-in, and only effective when the sink
 * opted in (`partitionKey`). When set, a record's event `key`
 * becomes the message's partition key, so messages sharing a
 * key land on one partition in produce order. When the flag is
 * absent, or the record has no key, no partition key is
 * attached: the key is ignored, not defaulted, because a
 * partition key the operator never asked for would silently
 * serialize unrelated events onto one partition.
 *
 * Failure handling mirrors the WR-210 SQS sink's classification
 * (`src/failure.ts`), applied per message:
 *
 * - a per-message produce failure throws `PulsarSinkError`
 *   carrying every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed messages;
 * - retryable codes are the transient Pulsar states —
 *   connection failures, produce failures, timeouts, and
 *   codeless transport failures: a connection failure says
 *   Pulsar could not accept the message right now, not that
 *   the payload is poison;
 * - non-retryable codes are the fail-closed messages —
 *   permission denied, unknown topic, malformed message:
 *   retrying them burns the retry budget for nothing, and
 *   rerouting them elsewhere would break the fan-out contract
 *   the subscribers depend on;
 * - a missing client throws `PulsarSinkConfigError`, which
 *   `classifyFailure` maps to `non_retryable` (the WR-116
 *   rule). A missing topic is not a config error: it selects
 *   per-record topic resolution instead.
 *
 * Zero new dependencies: the injected client only.
 */

/** Topic-name cap: Pulsar topic names are short operator strings. */
export const PULSAR_TOPIC_MAX = 255;

/** Message property carrying the record's tenant, verbatim. */
export const PULSAR_TENANT_PROPERTY = "tenant";

/** Message property carrying the record's endpoint, verbatim. */
export const PULSAR_ENDPOINT_PROPERTY = "endpoint";

/** Message property carrying the record's trace id, verbatim. */
export const PULSAR_TRACE_PROPERTY = "trace";

/**
 * One produce request as handed to the injected client. The
 * client owns the wire protocol (including the message id it
 * returns); this shape is the relay-side contract it must
 * honour.
 */
export interface PulsarProduceRequest {
  /** Target topic (the sink's configured topic, or the record's resolved topic). */
  topic: string;
  /** The event JSON, verbatim. */
  data: string;
  /**
   * Pass-through properties: `tenant`, `endpoint`, and `trace`,
   * each present only when the record carried that value — the
   * sink never invents a property.
   */
  properties: Record<string, string>;
  /**
   * Partition key, present only when the sink opted into
   * partition keys and the record has a key.
   */
  partitionKey?: string;
}

/**
 * The injected Pulsar client. Any client adapter implements this
 * one method; per-message failures throw `PulsarProduceError`
 * (or any error, which the sink treats as a transport failure).
 * The client is expected to produce one message per call, so the
 * returned id is the message Pulsar stored.
 */
export interface PulsarClient {
  produce(request: PulsarProduceRequest): Promise<string>;
}

/**
 * Configuration for one Pulsar sink. The client is injected:
 * without one, `produce()` throws `PulsarSinkConfigError` (dry
 * runs excepted — they need no client at all). A missing topic
 * is not a config error: it selects per-record topic resolution
 * (subject, then key, then trace id).
 */
export interface PulsarSinkConfig {
  /**
   * Target topic, e.g. `persistent://public/default/events`.
   * When set, every message goes there; when absent, the topic
   * resolves per record (see `resolvePulsarTopic`). When set,
   * it must be 1–255 characters, free of NUL and whitespace.
   */
  topic?: string;
  /**
   * The Pulsar client to deliver through. Injected, never
   * bundled: the operator's client adapter implements
   * `PulsarClient`. Required for real sends; a missing client
   * is a config error, not a silent no-op.
   */
  client?: PulsarClient;
  /**
   * Rehearsal mode: `produce()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no produce call, no stat changes. Records are
   * still validated (including per-record topic resolution), so
   * a dry run catches a topic-less record before it reaches
   * production. Mirrors the `dryRun` convention of the S3
   * offloaders.
   */
  dryRun?: boolean;
  /**
   * Partition-key opt-in: when `true`, a record's event `key`
   * becomes the message's partition key. When `false` or
   * absent, no partition key is ever attached.
   */
  partitionKey?: boolean;
}

/** One event to produce to the topic. */
export interface PulsarRecord {
  /** The event JSON, already serialized by the caller — stored verbatim. */
  body: string;
  /**
   * Topic-resolution source, first priority (only when the sink
   * has no configured topic): the event's subject, when set and
   * non-empty. Falls through to `key`, then `traceId`.
   */
  subject?: string;
  /**
   * Topic-resolution source, second priority (only when the
   * sink has no configured topic): the event's key (e.g.
   * aggregate id). Also the partition-key source when the sink
   * opted into partition keys.
   */
  key?: string;
  /**
   * Topic-resolution source, last priority (only when the sink
   * has no configured topic): the trace id. Also passed through
   * verbatim as the `trace` message property when set, absent
   * otherwise — the sink never invents a trace id.
   */
  traceId?: string;
  /**
   * Tenant property source: passed through verbatim as the
   * `tenant` message property when set, absent otherwise — the
   * sink never invents a tenant.
   */
  tenant?: string;
  /**
   * Endpoint property source: passed through verbatim as the
   * `endpoint` message property when set, absent otherwise.
   */
  endpoint?: string;
}

/** One record as it goes to the client (topic resolved, properties built, partition key resolved). */
export interface PulsarResolvedRecord {
  /** Target topic (configured, or resolved per record). */
  topic: string;
  /** The event JSON, verbatim. */
  data: string;
  /** Pass-through properties (only the record's own values). */
  properties: Record<string, string>;
  /** Partition key, present only under the partition-key opt-in (see above). */
  partitionKey?: string;
}

/** One failed message, with its retry lane already mapped. */
export interface PulsarFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /** Pulsar error code, or `TRANSPORT_ERROR` for a codeless failure. */
  errorCode: string;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: transient Pulsar states
   * (including connection and produce failures) are retryable,
   * fail-closed messages (permission, unknown topic, malformed
   * message) are not.
   */
  retryable: boolean;
}

/** Outcome of one `produce()` call (failures throw, see above). */
export interface PulsarProduceResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-223). */
export interface PulsarSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** Produce calls that threw (counted before the error is thrown). */
  produceFailures: number;
}

/**
 * Thrown when a produce throws per message: a Pulsar-side or
 * transport failure mapped onto the Pulsar error code. Carries
 * the codeless transport case as `TRANSPORT_ERROR`, and every
 * failed message with its retry lane, so the caller retries
 * exactly the failed messages without parsing message strings.
 */
export class PulsarProduceError extends Error {
  /** Pulsar error code (e.g. `ConnectionFailed`). */
  readonly errorCode: string;
  constructor(errorCode: string, message?: string) {
    super(message ?? `pulsar-sink: produce failed (${errorCode})`);
    this.name = "PulsarProduceError";
    this.errorCode = errorCode;
  }
}

/**
 * Thrown for Pulsar produce failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A produce call that
 * throws has partial success behind it — the accepted messages
 * are already in their topic and are *not* in `failedRecords`.
 */
export class PulsarSinkError extends Error {
  /** Per-message failures, in input order, each with its retry lane. */
  readonly failedRecords: PulsarFailedRecord[];
  constructor(message: string, failedRecords: PulsarFailedRecord[]) {
    super(message);
    this.name = "PulsarSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even produce — currently: no
 * client was injected. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`). A missing
 * topic is not a config error: it selects per-record topic
 * resolution instead.
 */
export class PulsarSinkConfigError extends PulsarSinkError {
  constructor(reason: string) {
    super(`pulsar-sink: ${reason}`, []);
    this.name = "PulsarSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing topic is *not* a shape error: it selects per-record
 * topic resolution, so a sink built before its topic is known
 * still fails closed on a topic-less record rather than
 * crashing at construction.
 */
export function assertValidPulsarSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is PulsarSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  if (c.topic !== undefined) {
    if (
      typeof c.topic !== "string" ||
      c.topic === "" ||
      c.topic.length > PULSAR_TOPIC_MAX ||
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
      typeof (c.client as { produce?: unknown }).produce !== "function")
  ) {
    throw new RangeError(at("`client` must expose a `produce` function when set"));
  }
}

/**
 * Build one record's pass-through properties: `tenant`,
 * `endpoint`, and `trace`, each present only when the record
 * carries a non-empty value for it — the sink never invents a
 * property.
 */
export function resolvePulsarProperties(record: PulsarRecord): Record<string, string> {
  const properties: Record<string, string> = {};
  if (record.tenant !== undefined && record.tenant !== "") {
    properties[PULSAR_TENANT_PROPERTY] = record.tenant;
  }
  if (record.endpoint !== undefined && record.endpoint !== "") {
    properties[PULSAR_ENDPOINT_PROPERTY] = record.endpoint;
  }
  if (record.traceId !== undefined && record.traceId !== "") {
    properties[PULSAR_TRACE_PROPERTY] = record.traceId;
  }
  return properties;
}

/**
 * Resolve one record's topic: the sink's configured topic wins;
 * otherwise the first non-empty value among `subject`, `key`,
 * and `traceId`, in that order. Returns `undefined` when the
 * sink has no configured topic and the record carries none of
 * the three — the caller fails closed rather than inventing a
 * topic.
 */
export function resolvePulsarTopic(
  record: PulsarRecord,
  config: Pick<PulsarSinkConfig, "topic">
): string | undefined {
  if (config.topic !== undefined) {
    return config.topic;
  }
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return undefined;
}

/**
 * Resolve one record's partition key: the record's event `key`,
 * but only when the sink opted into partition keys
 * (`partitionKey`). Any other combination — including a key
 * with the opt-in absent — yields no partition key: the key is
 * ignored, not defaulted, because a partition key the operator
 * never asked for would silently serialize unrelated events.
 */
export function resolvePulsarPartitionKey(
  record: PulsarRecord,
  config: Pick<PulsarSinkConfig, "partitionKey">
): string | undefined {
  if (config.partitionKey !== true) {
    return undefined;
  }
  if (record.key === undefined || record.key === "") {
    return undefined;
  }
  return record.key;
}

/**
 * Validate one record's body and resolve its produce form: the
 * topic resolves from the sink config or the record's own
 * subject, key, or trace id; the properties pass through
 * verbatim; and the partition key resolves under the opt-in.
 * Throws `RangeError` on an empty body string, and on a record
 * with no topic source when the sink has no configured topic —
 * a topic-less record fails closed, never with an invented
 * topic.
 */
export function resolvePulsarRecord(
  record: PulsarRecord,
  index: number,
  config: Pick<PulsarSinkConfig, "topic" | "partitionKey">
): PulsarResolvedRecord {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`pulsar-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  const topic = resolvePulsarTopic(record, config);
  if (topic === undefined) {
    throw new RangeError(
      `pulsar-sink: record ${index} has no topic source (configure \`topic\` or set \`subject\`, \`key\`, or \`traceId\`)`
    );
  }
  const resolved: PulsarResolvedRecord = {
    topic,
    data: record.body,
    properties: resolvePulsarProperties(record),
  };
  const partitionKey = resolvePulsarPartitionKey(record, config);
  if (partitionKey !== undefined) {
    resolved.partitionKey = partitionKey;
  }
  return resolved;
}

/**
 * Pulsar error codes that are transient — connection failures,
 * produce failures, timeouts — and so retryable under the WR-210
 * mapping. A connection failure is retryable: it says Pulsar
 * could not accept the message right now, not that the payload
 * is poison. A codeless transport failure is carried as
 * `TRANSPORT_ERROR` and is retryable too: like an SQS transport
 * error with no status, it says nothing about the payload. Any
 * code not listed here is a fail-closed message (permission
 * denied, unknown topic, malformed message) and is
 * non-retryable: retrying it burns the retry budget for
 * nothing, and rerouting it elsewhere would break the fan-out
 * contract.
 */
const PULSAR_RETRYABLE_ERROR_CODES = new Set([
  "TRANSPORT_ERROR",
  "ConnectionFailed",
  "ProduceFailed",
  "TimeoutError",
  "ServiceNotReady",
]);

/**
 * Map one Pulsar produce `errorCode` onto its retry lane under
 * the WR-210 rules: transient Pulsar states (including
 * connection and produce failures) are retryable, any other
 * code is a fail-closed message, like any other 4xx.
 */
export function classifyPulsarRecordFailure(errorCode: string): boolean {
  return PULSAR_RETRYABLE_ERROR_CODES.has(errorCode);
}

/**
 * Pulsar sink (WR-223). One instance targets one topic (or
 * resolves topics per record when none is configured); the
 * caller owns retry/dead-letter policy around `produce()` —
 * this class performs one produce attempt per message through
 * the injected client and reports its outcome. Failures throw
 * `PulsarSinkError` carrying exactly the failed messages with
 * their retry lanes.
 */
export class PulsarSink {
  private readonly cfg: PulsarSinkConfig;
  private sent = 0;
  private failed = 0;
  private produceFailures = 0;

  constructor(config: PulsarSinkConfig) {
    assertValidPulsarSinkConfig(config, "PulsarSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): PulsarSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      produceFailures: this.produceFailures,
    };
  }

  /**
   * Produce messages to the configured topic (or each record's
   * resolved topic), in input order. Throws
   * `PulsarSinkConfigError` when no client was injected, and
   * `PulsarSinkError` when any message fails (carrying exactly
   * the failed messages with their retry lanes; both counted in
   * stats before throwing, so the counters stay honest even for
   * callers that only inspect stats).
   */
  async produce(records: PulsarRecord[]): Promise<PulsarProduceResult> {
    const resolved = records.map((r, i) => resolvePulsarRecord(r, i, this.cfg));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches a
      // topic-less record before it reaches production — but
      // perform zero client I/O and touch no stats.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new PulsarSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const failedRecords: PulsarFailedRecord[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i] as PulsarResolvedRecord;
      try {
        await client.produce({
          topic: record.topic,
          data: record.data,
          properties: record.properties,
          ...(record.partitionKey !== undefined ? { partitionKey: record.partitionKey } : {}),
        });
      } catch (err) {
        failedRecords.push(toPulsarFailedRecord(err, i));
        continue;
      }
      sent += 1;
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.produceFailures += 1;
      throw new PulsarSinkError(
        `pulsar-sink: produce failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent };
  }
}

/**
 * Convert a client throw into a failed message: a
 * `PulsarProduceError` maps by its code, any other error is a
 * codeless transport failure (`TRANSPORT_ERROR`, retryable — the
 * SQS no-status rule).
 */
function toPulsarFailedRecord(err: unknown, index: number): PulsarFailedRecord {
  if (err instanceof PulsarProduceError) {
    const failed: PulsarFailedRecord = {
      index,
      errorCode: err.errorCode,
      retryable: classifyPulsarRecordFailure(err.errorCode),
    };
    if (err.message !== "") failed.errorMessage = err.message;
    return failed;
  }
  const failed: PulsarFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
