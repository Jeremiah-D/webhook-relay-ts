/**
 * Redis Streams delivery sink (WR-219).
 *
 * Some downstreams are not HTTP endpoints at all: they are Redis
 * streams. Where the SQS sink (WR-210) delivers to an unordered
 * queue, the Kinesis sink (WR-213) delivers to an AWS SigV4 stream,
 * the Kafka sink (WR-215) delivers to a partitioned log, the MQTT
 * sink (WR-216) delivers to a pub/sub topic tree, the AMQP sink
 * (WR-217) delivers to an exchange, and the JetStream sink (WR-218)
 * delivers to a durable stream over the native JetStream publish
 * protocol, this sink delivers to a Redis stream with XADD: one
 * event is appended as one stream entry, and Redis — not the relay
 * — owns the entry id, the stream's length, and trimming per the
 * operator's MAXLEN policy. The sinks are orthogonal — queue
 * delivery for unordered work, stream delivery for AWS-ordered
 * work, log delivery for broker-native ordered work, topic
 * delivery for broker-mediated fan-out, exchange delivery for
 * broker-mediated routing, durable-stream delivery for replayable
 * work, Redis-stream delivery for in-memory ordered work — and a
 * Redis-stream delivery can still be archived by the S3 offloaders
 * like any other delivery.
 *
 * No real Redis client is bundled: the client is injected through
 * `config.client` (a thin adapter over whatever client the
 * operator runs — node-redis, ioredis, a sidecar), so the module
 * has zero new dependencies and tests never need a Redis server.
 * The sink owns the relay-side concerns — stream-key resolution,
 * trace-id field pass-through, per-record failure mapping — and the
 * injected client owns the wire protocol, including the XADD call
 * and the entry id it returns.
 *
 * Wire shape — one XADD request per record, carried to the injected
 * client as:
 *
 *   { stream: "<stream key>", fields: { body: "<event JSON>",
 *     "trace-id": "<traceId>" } }
 *
 * Stream keys — a record's stream key resolves from the event,
 * never invented: an explicit `subject` wins, then the event
 * `key`, then the `traceId`, exactly the JetStream sink's subject
 * resolution applied to the one routing value Redis has. A record
 * with none of the three is rejected at build time (fail-closed) —
 * inventing a stream key would silently append unrelated events to
 * a stream the consumer replays, the same reason the JetStream
 * sink refuses to invent a subject, the Kafka sink refuses to
 * invent a partition key, the MQTT sink refuses to invent a topic
 * segment, and the AMQP sink refuses to invent a routing key.
 * When the sink is configured with a fixed `stream`, that stream
 * is the XADD target for every record and per-record resolution is
 * skipped: the configured stream is the operator's explicit
 * routing decision, so it wins over the event's own key material.
 *
 * Trace-id fields — when the record carries a `traceId`, it is
 * passed through verbatim as the `trace-id` entry field, so a
 * consumer can correlate the stream entry with the relay's audit
 * trail without opening the body. The field is a copy, never a
 * substitute: a record whose stream key resolved from `traceId`
 * still carries the same value as a field, and a record with no
 * `traceId` carries no `trace-id` field — the sink never invents
 * one. Redis entries have no headers, so the trace id rides as a
 * field where JetStream carries it as a header.
 *
 * Auto-created streams — a stream that does not exist yet is
 * created by Redis on the first XADD, so there is no "unknown
 * stream" failure lane here. That is the deliberate difference
 * from the JetStream sink, where an unknown stream is a fail-closed
 * record: a Redis consumer never has to pre-create a stream for a
 * new subject, but a key that already exists with a non-stream
 * type (`WRONGTYPE`) is still fail-closed — retrying it cannot
 * turn a string into a stream, and rerouting it elsewhere would
 * break the replay contract the consumer depends on.
 *
 * Failure handling mirrors the WR-210 SQS sink's classification
 * (`src/failure.ts`), applied per record:
 *
 * - a per-record XADD failure throws `RedisSinkError` carrying
 *   every failed record with its retry lane already mapped, so the
 *   caller retries exactly the failed records;
 * - retryable codes are the transient Redis states — XADD
 *   failures, connection loss, timeouts, and codeless transport
 *   failures: an XADD failure says Redis could not accept the
 *   entry right now, not that the payload is poison;
 * - non-retryable codes are the fail-closed records — a key of
 *   the wrong type, an oversize message: retrying them burns the
 *   retry budget for nothing, and rerouting them elsewhere would
 *   break the replay contract;
 * - a missing client throws `RedisSinkConfigError`, which
 *   `classifyFailure` maps to `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Redis stream-key cap: stream keys are 1–255 characters. */
export const REDIS_STREAM_KEY_MAX = 255;

/** Entry field carrying the event JSON, verbatim. */
export const REDIS_BODY_FIELD = "body";

/** Entry field carrying the record's trace id, verbatim. */
export const REDIS_TRACE_ID_FIELD = "trace-id";

/**
 * One XADD request as handed to the injected client. The client
 * owns the wire protocol (including the entry id it returns);
 * this shape is the relay-side contract it must honour.
 */
export interface RedisXAddRequest {
  /** Target stream key (configured stream, or resolved per record). */
  stream: string;
  /**
   * Entry fields. Always carries `body`; carries `trace-id` when
   * the record has a `traceId`, and is otherwise body-only — the
   * sink never invents a trace id.
   */
  fields: Record<string, string>;
}

/**
 * The injected Redis Streams client. Any client adapter implements
 * this one method; per-record failures throw `RedisXAddError` (or
 * any error, which the sink treats as a transport failure). The
 * client is expected to issue XADD with an auto-generated entry id
 * (`*`), so the returned id is the entry Redis stored.
 */
export interface RedisStreamsClient {
  xadd(request: RedisXAddRequest): Promise<string>;
}

/**
 * Configuration for one Redis Streams sink. The client is
 * injected: without one, `publish()` throws
 * `RedisSinkConfigError` (dry runs excepted — they need no client
 * at all).
 */
export interface RedisSinkConfig {
  /**
   * Fixed target stream, 1–255 characters, no NUL, no whitespace.
   * When set, every record is XADDed to this stream and per-record
   * stream-key resolution is skipped; when absent, each record's
   * stream key resolves from its subject, key, or traceId (see
   * `resolveRedisStreamKey`). One sink targets one stream only in
   * the fixed case — the per-record case targets one stream per
   * subject, like the JetStream sink's per-record subjects.
   */
  stream?: string;
  /**
   * The Redis client to deliver through. Injected, never bundled:
   * the operator's client adapter (node-redis, ioredis, sidecar)
   * implements `RedisStreamsClient`. Required for real sends; a
   * missing client is a config error, not a silent no-op.
   */
  client?: RedisStreamsClient;
  /**
   * Rehearsal mode: `publish()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero client
   * I/O — no XADD call, no stat changes. Records are still
   * validated, so a dry run catches a malformed record before it
   * reaches production. Mirrors the `dryRun` convention of the S3
   * offloaders.
   */
  dryRun?: boolean;
}

/** One event to append to a stream. */
export interface RedisRecord {
  /** The event JSON, already serialized by the caller — stored verbatim. */
  body: string;
  /**
   * Explicit stream-key source. Wins over `key`/`traceId` when
   * set (and when no fixed `stream` is configured). Must be
   * non-empty and at most 255 characters when resolved, free of
   * NUL and whitespace.
   */
  subject?: string;
  /**
   * Event key (e.g. aggregate id): the stream-key source when no
   * explicit `subject` is set. Events sharing a key land in the
   * same stream and replay in order.
   */
  key?: string;
  /**
   * Trace id: the stream-key fallback when neither `subject` nor
   * `key` is set, and — when set — the value passed through as
   * the `trace-id` entry field. Lets the consumer correlate the
   * stream entry with the relay's audit trail without opening the
   * body.
   */
  traceId?: string;
}

/** One record as it goes to the client (stream key resolved, fields built). */
export interface RedisResolvedRecord {
  /** The event JSON, verbatim. */
  data: string;
  /** Resolved stream key (non-empty, at most 255 characters). */
  stream: string;
  /** Entry fields (`body`, plus `trace-id` when the record has a `traceId`). */
  fields: Record<string, string>;
}

/** One failed record, with its retry lane already mapped. */
export interface RedisFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /** Redis error code, or `TRANSPORT_ERROR` for a codeless failure. */
  errorCode: string;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: transient Redis states
   * (including XADD failures and connection loss) are retryable,
   * fail-closed records (wrong key type, oversize message) are not.
   */
  retryable: boolean;
}

/** Outcome of one `publish()` call (failures throw, see above). */
export interface RedisPublishResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Records the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-219). */
export interface RedisSinkStats {
  /** Records accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Records reported failed by the client. */
  failed: number;
  /** Publish calls that threw (counted before the error is thrown). */
  publishFailures: number;
}

/**
 * Thrown when an XADD throws per record: a Redis-side or transport
 * failure mapped onto the Redis error code. Carries the codeless
 * transport case as `TRANSPORT_ERROR`, and every failed record with
 * its retry lane, so the caller retries exactly the failed records
 * without parsing message strings.
 */
export class RedisXAddError extends Error {
  /** Redis error code (e.g. `CONNECTION_LOST`). */
  readonly errorCode: string;
  constructor(errorCode: string, message?: string) {
    super(message ?? `redis-sink: xadd failed (${errorCode})`);
    this.name = "RedisXAddError";
    this.errorCode = errorCode;
  }
}

/**
 * Thrown for Redis XADD failures. Carries every failed record with
 * its retry lane (`failedRecords`), so the retry queue can requeue
 * exactly those records. An XADD call that throws has partial
 * success behind it — the accepted records are already in their
 * streams and are *not* in `failedRecords`.
 */
export class RedisSinkError extends Error {
  /** Per-record failures, in input order, each with its retry lane. */
  readonly failedRecords: RedisFailedRecord[];
  constructor(message: string, failedRecords: RedisFailedRecord[]) {
    super(message);
    this.name = "RedisSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even publish — currently: no client
 * was injected. A config problem, not a downstream verdict, so the
 * retry queue must not burn attempts on it (`classifyFailure`
 * maps it to `non_retryable`).
 */
export class RedisSinkConfigError extends RedisSinkError {
  constructor() {
    super("redis-sink: no client injected (set `client` in the sink config)", []);
    this.name = "RedisSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery.
 */
export function assertValidRedisSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is RedisSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  if (c.stream !== undefined) {
    if (
      typeof c.stream !== "string" ||
      c.stream === "" ||
      c.stream.length > REDIS_STREAM_KEY_MAX ||
      c.stream.includes("\0") ||
      /\s/.test(c.stream)
    ) {
      throw new RangeError(
        at("`stream` must be 1–255 characters, free of NUL and whitespace when set")
      );
    }
  }
  if (
    c.client !== undefined &&
    (c.client === null ||
      typeof c.client !== "object" ||
      typeof (c.client as { xadd?: unknown }).xadd !== "function")
  ) {
    throw new RangeError(at("`client` must expose an `xadd` function when set"));
  }
}

/**
 * Resolve one record's stream key: explicit `subject`, then `key`,
 * then `traceId`. Throws `RangeError` when none is set or the
 * resolved key is empty, over 255 characters, or contains NUL or
 * whitespace — the sink never invents a stream key and never
 * appends to a key the consumer cannot match.
 */
export function resolveRedisStreamKey(record: RedisRecord, index: number): string {
  const stream = record.subject ?? record.key ?? record.traceId;
  if (typeof stream !== "string" || stream === "") {
    throw new RangeError(
      `redis-sink: record ${index} has no stream key (set subject, key, or traceId, or configure a fixed stream)`
    );
  }
  if (
    stream.length > REDIS_STREAM_KEY_MAX ||
    stream.includes("\0") ||
    /\s/.test(stream)
  ) {
    throw new RangeError(
      `redis-sink: record ${index} stream key must be 1–255 characters, free of NUL and whitespace`
    );
  }
  return stream;
}

/**
 * Build one record's entry fields: `body` carries the event JSON
 * verbatim, and `trace-id` carries the record's `traceId` verbatim
 * when set, absent otherwise — the sink never invents a trace id.
 */
export function resolveRedisFields(record: RedisRecord): Record<string, string> {
  if (record.traceId === undefined || record.traceId === "") {
    return { [REDIS_BODY_FIELD]: record.body };
  }
  return { [REDIS_BODY_FIELD]: record.body, [REDIS_TRACE_ID_FIELD]: record.traceId };
}

/**
 * Validate one record's body and resolve its XADD form against the
 * sink's configured stream: a fixed stream wins, otherwise the
 * stream key resolves per record. Throws `RangeError` on an empty
 * body string or an unresolvable stream key.
 */
export function resolveRedisRecord(
  record: RedisRecord,
  index: number,
  configuredStream?: string
): RedisResolvedRecord {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`redis-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return {
    data: record.body,
    stream: configuredStream ?? resolveRedisStreamKey(record, index),
    fields: resolveRedisFields(record),
  };
}

/**
 * Redis error codes that are transient — XADD failures, connection
 * loss, timeouts — and so retryable under the WR-210 mapping. An
 * XADD failure is retryable: it says Redis could not accept the
 * entry right now, not that the payload is poison. A codeless
 * transport failure is carried as `TRANSPORT_ERROR` and is
 * retryable too: like an SQS transport error with no status, it
 * says nothing about the payload. Any code not listed here is a
 * fail-closed record (wrong key type, oversize message) and is
 * non-retryable: retrying it burns the retry budget for nothing,
 * and rerouting it elsewhere would break the replay contract.
 */
const REDIS_RETRYABLE_ERROR_CODES = new Set([
  "TRANSPORT_ERROR",
  "CONNECTION_LOST",
  "NOT_CONNECTED",
  "XADD_FAILED",
  "TIMEOUT",
  "STREAM_UNAVAILABLE",
]);

/**
 * Map one Redis XADD `errorCode` onto its retry lane under the
 * WR-210 rules: transient Redis states (including XADD failures
 * and connection loss) are retryable, any other code is a
 * fail-closed record, like any other 4xx.
 */
export function classifyRedisRecordFailure(errorCode: string): boolean {
  return REDIS_RETRYABLE_ERROR_CODES.has(errorCode);
}

/**
 * Redis Streams sink (WR-219). One instance targets one stream in
 * the fixed case, or one stream per record subject in the resolved
 * case; the caller owns retry/dead-letter policy around
 * `publish()` — this class performs one XADD attempt per record
 * through the injected client and reports its outcome. Failures
 * throw `RedisSinkError` carrying exactly the failed records with
 * their retry lanes.
 */
export class RedisSink {
  private readonly cfg: RedisSinkConfig;
  private sent = 0;
  private failed = 0;
  private publishFailures = 0;

  constructor(config: RedisSinkConfig) {
    assertValidRedisSinkConfig(config, "RedisSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): RedisSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      publishFailures: this.publishFailures,
    };
  }

  /**
   * Append records to their streams, in input order. Throws
   * `RedisSinkConfigError` when no client was injected and
   * `RedisSinkError` when any record fails (carrying exactly the
   * failed records with their retry lanes; both counted in stats
   * before throwing, so the counters stay honest even for
   * callers that only inspect stats).
   */
  async publish(records: RedisRecord[]): Promise<RedisPublishResult> {
    const resolved = records.map((r, i) => resolveRedisRecord(r, i, this.cfg.stream));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches a
      // malformed record before it reaches production — but perform
      // zero client I/O and touch no stats.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new RedisSinkConfigError();
    }
    const failedRecords: RedisFailedRecord[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i] as RedisResolvedRecord;
      try {
        await client.xadd({ stream: record.stream, fields: record.fields });
      } catch (err) {
        failedRecords.push(toRedisFailedRecord(err, i));
        continue;
      }
      sent += 1;
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.publishFailures += 1;
      const target = this.cfg.stream ?? "resolved streams";
      throw new RedisSinkError(
        `redis-sink: xadd ${target} failed for ${failedRecords.length} of ${resolved.length} records`,
        failedRecords
      );
    }
    return { ok: true, sent };
  }
}

/**
 * Convert a client throw into a failed record: a `RedisXAddError`
 * maps by its code, any other error is a codeless transport failure
 * (`TRANSPORT_ERROR`, retryable — the SQS no-status rule).
 */
function toRedisFailedRecord(err: unknown, index: number): RedisFailedRecord {
  if (err instanceof RedisXAddError) {
    const failed: RedisFailedRecord = {
      index,
      errorCode: err.errorCode,
      retryable: classifyRedisRecordFailure(err.errorCode),
    };
    if (err.message !== "") failed.errorMessage = err.message;
    return failed;
  }
  const failed: RedisFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
