/**
 * Kafka delivery sink (WR-215).
 *
 * Some downstreams are not HTTP endpoints at all: they are Apache
 * Kafka topics. Where the SQS sink (WR-210) delivers to an unordered
 * queue and the Kinesis sink (WR-213) delivers to an AWS SigV4
 * stream, this sink delivers to a *partitioned log* over the native
 * Kafka produce protocol: records sharing a partition key land on
 * the same partition in order, so a consumer can replay one key's
 * events exactly. The three sinks are orthogonal — queue delivery
 * for unordered work, stream delivery for AWS-ordered work, log
 * delivery for broker-native ordered work — and a Kafka delivery can
 * still be archived by the S3 offloaders like any other delivery.
 *
 * No real Kafka client is bundled: the producer is injected through
 * `config.producer` (a thin adapter over whatever client the
 * operator runs — kafkajs, a native binding, a sidecar), so the
 * module has zero new dependencies and tests never need a broker.
 * The sink owns the relay-side concerns — partition-key resolution,
 * acks configuration, per-key dedup, per-record failure mapping —
 * and the injected producer owns the wire protocol.
 *
 * Wire shape — one produce request per record, carried to the
 * injected producer as:
 *
 *   { topic: "<topic>", key: "<partition key>",
 *     value: "<event JSON>", acks: "<all|1|0>",
 *     headers?: { ... } }
 *
 * Partition keys come from the event, never invented: an explicit
 * `partitionKey` wins, then the event `key`, then the `traceId`. A
 * record with none of the three is rejected at build time
 * (fail-closed) — inventing a key would silently serialize unrelated
 * events behind each other on one partition, the same reason the
 * SQS sink refuses to invent a FIFO `MessageGroupId` and the
 * Kinesis sink refuses to invent a partition key. Unlike Kinesis
 * (256-char cap), Kafka keys have no protocol length cap, so the
 * sink only rejects an empty key.
 *
 * Acks are configurable per sink: `"all"` (the default — wait for
 * all in-sync replicas, strongest durability), `"1"` (leader only),
 * `"0"` (fire and forget, no acknowledgement). The configured value
 * is carried on every produce request so the injected producer can
 * apply it; a client that fixes acks at construction time applies
 * the same value there instead.
 *
 * Dedup window — when `dedupWindowMs` is set, a record whose
 * partition key was already produced within the window is skipped
 * (reported in `result.duplicates` by original index) instead of
 * being produced twice. The window is per key, not per payload: a
 * retried delivery of the same key inside the window is exactly the
 * duplicate this guard exists for. A key produced again after the
 * window expires is a fresh produce. The guard is in-memory only —
 * it does not survive a restart, and it is not a substitute for an
 * idempotent consumer.
 *
 * Failure handling mirrors the WR-210 SQS sink's classification
 * (`src/failure.ts`), applied per record:
 *
 * - a per-record produce failure throws `KafkaSinkError` carrying
 *   every failed record with its retry lane already mapped, so the
 *   caller retries exactly the failed records. (Kafka produce is
 *   per message, not per batch, so unlike the Kinesis sink's
 *   partial-success result, a failed record here is a throw — but
 *   the throw still carries the full failed set, never just a
 *   message string.)
 * - retryable codes are the transient broker states — leader /
 *   replica churn, request timeouts, metadata propagation, and
 *   transport failures with no code at all (the no-status analog of
 *   the SQS transport rule, carried as `TRANSPORT_ERROR`);
 * - non-retryable codes are the poison records — oversize messages
 *   and invalid topics/records — the 4xx analog: retrying them
 *   burns the retry budget for nothing;
 * - a missing producer throws `KafkaSinkConfigError`, which
 *   `classifyFailure` maps to `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected producer only.
 */

/** Default acks when `acks` is unset: wait for all in-sync replicas. */
export const KAFKA_SINK_DEFAULT_ACKS = "all";

/** Kafka topic name shape: 1–249 `[A-Za-z0-9._-]` characters. */
export const KAFKA_TOPIC_NAME_RE = /^[A-Za-z0-9._-]{1,249}$/;

/**
 * Produce acknowledgement level. `"all"` waits for every in-sync
 * replica, `"1"` for the leader only, `"0"` for no acknowledgement.
 */
export type KafkaAcks = "all" | "1" | "0";

/**
 * One produce request as handed to the injected producer. The
 * producer owns the wire protocol; this shape is the relay-side
 * contract it must honour.
 */
export interface KafkaProduceRequest {
  /** Target topic (the sink's configured topic). */
  topic: string;
  /** Resolved partition key — never invented, see above. */
  key: string;
  /** The event JSON, verbatim. */
  value: string;
  /** Configured acknowledgement level for this produce. */
  acks: KafkaAcks;
  /** Caller-supplied record headers, when any. */
  headers?: Record<string, string>;
}

/** Outcome of one producer `send()` call. */
export interface KafkaProducerSendResult {
  /** Partition the record landed on, when the producer reports one. */
  partition?: number;
  /** Offset the record landed at, when the producer reports one. */
  offset?: number;
}

/**
 * The injected Kafka producer. Any client adapter implements this
 * one method; per-record failures throw `KafkaProduceError` (or any
 * error, which the sink treats as a transport failure).
 */
export interface KafkaProducer {
  send(request: KafkaProduceRequest): Promise<KafkaProducerSendResult>;
}

/**
 * Configuration for one Kafka topic sink. The producer is injected:
 * without one, `produce()` throws `KafkaSinkConfigError` (dry runs
 * excepted — they need no producer at all).
 */
export interface KafkaSinkConfig {
  /** Target topic, 1–249 `[A-Za-z0-9._-]` characters. */
  topic: string;
  /**
   * Acknowledgement level; default {@link KAFKA_SINK_DEFAULT_ACKS}.
   * Carried on every produce request to the injected producer.
   */
  acks?: KafkaAcks;
  /**
   * The Kafka producer to deliver through. Injected, never bundled:
   * the operator's client adapter (kafkajs, native binding, sidecar)
   * implements `KafkaProducer`. Required for real sends; a missing
   * producer is a config error, not a silent no-op.
   */
  producer?: KafkaProducer;
  /**
   * Per-key dedup window in ms. When set (> 0), a record whose
   * partition key was produced within the window is skipped and
   * reported in `result.duplicates`. Unset or 0 disables dedup.
   */
  dedupWindowMs?: number;
  /**
   * Clock source for the dedup window. Defaults to `Date.now`;
   * injectable so tests can move time without sleeping.
   */
  now?: () => number;
  /**
   * Rehearsal mode: `produce()` returns
   * `{ ok: true, sent: 0, duplicates: [], dryRun: true }` and
   * performs zero producer I/O — no producer call, no stat changes,
   * no dedup state changes. Records are still validated, so a dry
   * run catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   */
  dryRun?: boolean;
}

/** One event to produce to the topic. */
export interface KafkaRecord {
  /** The event JSON, already serialized by the caller — produced verbatim. */
  value: string;
  /**
   * Explicit partition key. Wins over `key`/`traceId` when set.
   * Must be non-empty when resolved.
   */
  partitionKey?: string;
  /**
   * Event key (e.g. aggregate id): the partition-key source when no
   * explicit `partitionKey` is set. Events sharing a key land on the
   * same partition, in order.
   */
  key?: string;
  /**
   * Trace id: the partition-key fallback when neither `partitionKey`
   * nor `key` is set. Lets the consumer correlate the topic record
   * with the relay's audit trail without opening the value.
   */
  traceId?: string;
  /** Caller-supplied record headers, carried verbatim. */
  headers?: Record<string, string>;
}

/** One record as it goes to the producer (partition key resolved). */
export interface KafkaResolvedRecord {
  /** The event JSON, verbatim. */
  value: string;
  /** Resolved partition key (non-empty). */
  partitionKey: string;
  /** Caller-supplied record headers, when any. */
  headers?: Record<string, string>;
}

/** One failed record, with its retry lane already mapped. */
export interface KafkaFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /** Broker error code, or `TRANSPORT_ERROR` for a codeless failure. */
  errorCode: string;
  /** Producer error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: transient broker states
   * are retryable, poison records are not.
   */
  retryable: boolean;
}

/** Outcome of one `produce()` call (failures throw, see above). */
export interface KafkaProduceResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Records the producer accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /**
   * Original indices skipped by the dedup window, in input order.
   * Empty when dedup is disabled or nothing was skipped.
   */
  duplicates: number[];
  /** `true` only in dry-run mode: no producer I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-215). */
export interface KafkaSinkStats {
  /** Records accepted by the producer (real sends, not dry runs). */
  sent: number;
  /** Records reported failed by the producer. */
  failed: number;
  /** Records skipped by the dedup window. */
  duplicates: number;
  /** Produce calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown when a producer throws per record: a broker-side or
 * transport failure mapped onto the Kafka error code. Carries the
 * codeless transport case as `TRANSPORT_ERROR`, and every failed
 * record with its retry lane, so the caller retries exactly the
 * failed records without parsing message strings.
 */
export class KafkaProduceError extends Error {
  /** Broker error code (e.g. `NOT_LEADER_OR_FOLLOWER`). */
  readonly errorCode: string;
  constructor(errorCode: string, message?: string) {
    super(message ?? `kafka-sink: produce failed (${errorCode})`);
    this.name = "KafkaProduceError";
    this.errorCode = errorCode;
  }
}

/**
 * Thrown for Kafka produce failures. Carries every failed record
 * with its retry lane (`failedRecords`), so the retry queue can
 * requeue exactly those records. A produce call that throws has
 * partial success behind it — the accepted records are already in
 * the topic and are *not* in `failedRecords`.
 */
export class KafkaSinkError extends Error {
  /** Per-record failures, in input order, each with its retry lane. */
  readonly failedRecords: KafkaFailedRecord[];
  constructor(message: string, failedRecords: KafkaFailedRecord[]) {
    super(message);
    this.name = "KafkaSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even produce — currently: no producer
 * was injected. A config problem, not a downstream verdict, so the
 * retry queue must not burn attempts on it (`classifyFailure` maps
 * it to `non_retryable`).
 */
export class KafkaSinkConfigError extends KafkaSinkError {
  constructor() {
    super("kafka-sink: no producer injected (set `producer` in the sink config)", []);
    this.name = "KafkaSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery.
 */
export function assertValidKafkaSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is KafkaSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  if (typeof c.topic !== "string" || !KAFKA_TOPIC_NAME_RE.test(c.topic)) {
    throw new RangeError(at("`topic` must be 1–249 `[A-Za-z0-9._-]` characters"));
  }
  if (
    c.acks !== undefined &&
    c.acks !== "all" &&
    c.acks !== "1" &&
    c.acks !== "0"
  ) {
    throw new RangeError(at("`acks` must be one of `all`, `1`, `0` when set"));
  }
  if (
    c.producer !== undefined &&
    (c.producer === null ||
      typeof c.producer !== "object" ||
      typeof (c.producer as { send?: unknown }).send !== "function")
  ) {
    throw new RangeError(at("`producer` must expose a `send` function when set"));
  }
  if (
    c.dedupWindowMs !== undefined &&
    (!Number.isFinite(c.dedupWindowMs) || c.dedupWindowMs < 0)
  ) {
    throw new RangeError(at("`dedupWindowMs` must be a non-negative finite number"));
  }
  if (c.now !== undefined && typeof c.now !== "function") {
    throw new RangeError(at("`now` must be a function when set"));
  }
}

/**
 * Resolve one record's partition key: explicit `partitionKey`, then
 * `key`, then `traceId`. Throws `RangeError` when none is set or
 * the resolved key is empty — the sink never invents a key.
 */
export function resolveKafkaPartitionKey(
  record: KafkaRecord,
  index: number
): string {
  const key = record.partitionKey ?? record.key ?? record.traceId;
  if (typeof key !== "string" || key === "") {
    throw new RangeError(
      `kafka-sink: record ${index} has no partition key (set partitionKey, key, or traceId)`
    );
  }
  return key;
}

/**
 * Validate one record's value and resolve its producer form. Throws
 * `RangeError` on an empty value string or a non-string header value.
 */
export function resolveKafkaRecord(
  record: KafkaRecord,
  index: number
): KafkaResolvedRecord {
  if (typeof record.value !== "string" || record.value === "") {
    throw new RangeError(`kafka-sink: record ${index} \`value\` must be a non-empty event JSON string`);
  }
  const resolved: KafkaResolvedRecord = {
    value: record.value,
    partitionKey: resolveKafkaPartitionKey(record, index),
  };
  if (record.headers !== undefined) {
    for (const [name, value] of Object.entries(record.headers)) {
      if (typeof value !== "string") {
        throw new RangeError(`kafka-sink: record ${index} header "${name}" must be a string value`);
      }
    }
    resolved.headers = record.headers;
  }
  return resolved;
}

/**
 * Broker error codes that are transient — leader/replica churn,
 * request timeouts, metadata propagation, coordinator load — and so
 * retryable under the WR-210 mapping. A codeless transport failure
 * is carried as `TRANSPORT_ERROR` and is retryable too: like an SQS
 * transport error with no status, it says nothing about the payload.
 * Any code not listed here is a poison record (oversize message,
 * invalid topic/record) and is non-retryable.
 */
const KAFKA_RETRYABLE_ERROR_CODES = new Set([
  "TRANSPORT_ERROR",
  "NOT_LEADER_OR_FOLLOWER",
  "LEADER_NOT_AVAILABLE",
  "REPLICA_NOT_AVAILABLE",
  "REQUEST_TIMED_OUT",
  "NETWORK_EXCEPTION",
  "UNKNOWN_SERVER_ERROR",
  "OFFSET_NOT_AVAILABLE",
  "KAFKA_STORAGE_ERROR",
  "NOT_ENOUGH_REPLICAS",
  "NOT_ENOUGH_REPLICAS_AFTER_APPEND",
  "UNKNOWN_TOPIC_OR_PARTITION",
  "COORDINATOR_LOAD_IN_PROGRESS",
  "REBALANCE_IN_PROGRESS",
]);

/**
 * Map one Kafka produce `errorCode` onto its retry lane under the
 * WR-210 rules: transient broker states are retryable, any other
 * code is a poison record, like any other 4xx.
 */
export function classifyKafkaRecordFailure(errorCode: string): boolean {
  return KAFKA_RETRYABLE_ERROR_CODES.has(errorCode);
}

/**
 * Kafka topic sink (WR-215). One instance targets one topic; the
 * caller owns retry/dead-letter policy around `produce()` — this
 * class performs one produce attempt per record through the injected
 * producer and reports its outcome. Failures throw `KafkaSinkError`
 * carrying exactly the failed records with their retry lanes.
 */
export class KafkaSink {
  private readonly cfg: KafkaSinkConfig;
  private readonly acks: KafkaAcks;
  private readonly dedupWindowMs: number;
  private readonly now: () => number;
  /** Partition key → ms of its last accepted produce. */
  private readonly lastProducedByKey = new Map<string, number>();
  private sent = 0;
  private failed = 0;
  private duplicates = 0;
  private sendFailures = 0;

  constructor(config: KafkaSinkConfig) {
    assertValidKafkaSinkConfig(config, "KafkaSink");
    this.cfg = config;
    this.acks = config.acks ?? KAFKA_SINK_DEFAULT_ACKS;
    this.dedupWindowMs = config.dedupWindowMs ?? 0;
    this.now = config.now ?? Date.now;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): KafkaSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      duplicates: this.duplicates,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Produce records to the topic, in input order. Throws
   * `KafkaSinkConfigError` when no producer was injected and
   * `KafkaSinkError` when any record fails (carrying exactly the
   * failed records with their retry lanes; both counted in stats
   * before throwing, so the counters stay honest even for callers
   * that only inspect stats). Dedup-skipped records are reported in
   * `result.duplicates`, never thrown.
   */
  async produce(records: KafkaRecord[]): Promise<KafkaProduceResult> {
    const resolved = records.map((r, i) => resolveKafkaRecord(r, i));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches a
      // malformed record before it reaches production — but perform
      // zero producer I/O and touch no stats or dedup state.
      return { ok: true, sent: 0, duplicates: [], dryRun: true };
    }
    const producer = this.cfg.producer;
    if (producer === undefined) {
      throw new KafkaSinkConfigError();
    }
    const at = this.now();
    // Drop dedup entries older than the window, so the map tracks
    // only keys that can still suppress a produce.
    if (this.dedupWindowMs > 0) {
      for (const [key, last] of this.lastProducedByKey) {
        if (at - last >= this.dedupWindowMs) this.lastProducedByKey.delete(key);
      }
    }
    const failedRecords: KafkaFailedRecord[] = [];
    const duplicates: number[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i] as KafkaResolvedRecord;
      if (
        this.dedupWindowMs > 0 &&
        this.lastProducedByKey.has(record.partitionKey)
      ) {
        duplicates.push(i);
        continue;
      }
      try {
        await producer.send({
          topic: this.cfg.topic,
          key: record.partitionKey,
          value: record.value,
          acks: this.acks,
          ...(record.headers !== undefined ? { headers: record.headers } : {}),
        });
      } catch (err) {
        const failed = toKafkaFailedRecord(err, i);
        failedRecords.push(failed);
        continue;
      }
      sent += 1;
      if (this.dedupWindowMs > 0) {
        this.lastProducedByKey.set(record.partitionKey, at);
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    this.duplicates += duplicates.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new KafkaSinkError(
        `kafka-sink: produce ${this.cfg.topic} failed for ${failedRecords.length} of ${resolved.length} records`,
        failedRecords
      );
    }
    return { ok: true, sent, duplicates };
  }
}

/**
 * Convert a producer throw into a failed record: a
 * `KafkaProduceError` maps by its code, any other error is a
 * codeless transport failure (`TRANSPORT_ERROR`, retryable — the
 * SQS no-status rule).
 */
function toKafkaFailedRecord(err: unknown, index: number): KafkaFailedRecord {
  if (err instanceof KafkaProduceError) {
    const failed: KafkaFailedRecord = {
      index,
      errorCode: err.errorCode,
      retryable: classifyKafkaRecordFailure(err.errorCode),
    };
    if (err.message !== "") failed.errorMessage = err.message;
    return failed;
  }
  const failed: KafkaFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
