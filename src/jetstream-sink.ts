/**
 * NATS JetStream delivery sink (WR-218).
 *
 * Some downstreams are not HTTP endpoints at all: they are NATS
 * JetStream streams. Where the SQS sink (WR-210) delivers to an
 * unordered queue, the Kinesis sink (WR-213) delivers to an AWS
 * SigV4 stream, the Kafka sink (WR-215) delivers to a partitioned
 * log, the MQTT sink (WR-216) delivers to a pub/sub topic tree,
 * and the AMQP sink (WR-217) delivers to an exchange, this sink
 * delivers to a *durable stream* over the native JetStream publish
 * protocol: one event is published to a named stream under a
 * subject, and the stream — not the relay — owns persisting it,
 * replaying it to later consumers, and expiring it per its
 * retention policy. The five sinks are orthogonal — queue
 * delivery for unordered work, stream delivery for AWS-ordered
 * work, log delivery for broker-native ordered work, topic
 * delivery for broker-mediated fan-out, exchange delivery for
 * broker-mediated routing, stream delivery for durable,
 * replayable work — and a JetStream delivery can still be
 * archived by the S3 offloaders like any other delivery.
 *
 * No real NATS client is bundled: the client is injected through
 * `config.client` (a thin adapter over whatever client the
 * operator runs — nats.js, a native binding, a sidecar), so the
 * module has zero new dependencies and tests never need a broker.
 * The sink owns the relay-side concerns — stream and subject
 * resolution, trace-id header pass-through, per-record failure
 * mapping — and the injected client owns the wire protocol,
 * including publish acknowledgements.
 *
 * Wire shape — one publish request per record, carried to the
 * injected client as:
 *
 *   { stream: "<stream>", subject: "<subject>",
 *     data: "<event JSON>", headers: { "trace-id": "<traceId>" } }
 *
 * Subjects come from the event, never invented: an explicit
 * `subject` wins, then the event `key`, then the `traceId`. A
 * record with none of the three is rejected at build time
 * (fail-closed) — inventing a subject would silently append
 * unrelated events to a stream the consumer replays, the same
 * reason the Kafka sink refuses to invent a partition key, the
 * MQTT sink refuses to invent a topic segment, and the AMQP sink
 * refuses to invent a routing key. The stream is
 * sink-configured (one sink targets one stream), like the Kafka
 * sink's topic, the MQTT sink's topic prefix, and the AMQP sink's
 * exchange.
 *
 * Trace-id headers — when the record carries a `traceId`, it is
 * passed through verbatim as the `trace-id` message header, so a
 * consumer can correlate the stream message with the relay's
 * audit trail without opening the body. The header is a copy,
 * never a substitute: a record whose subject resolved from
 * `traceId` still carries the same value as a header, and a
 * record with no `traceId` carries no `trace-id` header — the
 * sink never invents one.
 *
 * Durable-stream semantics — persistence is a property of the
 * stream, not of the message: unlike the AMQP sink's per-message
 * `persistent` flag, there is no per-publish durability switch
 * here, because a JetStream stream either persists what it
 * accepts or it is not a JetStream stream. The injected client
 * is expected to publish with acknowledgement enabled, so a
 * publish the stream did not acknowledge surfaces as a failure
 * rather than a silent drop: an unacknowledged publish was never
 * durably stored, so it must be retried, not assumed delivered.
 *
 * Failure handling mirrors the WR-210 SQS sink's classification
 * (`src/failure.ts`), applied per record:
 *
 * - a per-record publish failure throws `JetStreamSinkError`
 *   carrying every failed record with its retry lane already
 *   mapped, so the caller retries exactly the failed records;
 * - retryable codes are the transient stream states — publish
 *   failures, publish acknowledgement timeouts, stream
 *   unavailability, connection loss, and codeless transport
 *   failures: a publish failure says the stream could not accept
 *   the message right now, not that the payload is poison;
 * - non-retryable codes are the fail-closed records — a subject
 *   or stream that does not exist, an invalid subject, an
 *   oversize message: retrying them burns the retry budget for
 *   nothing, and rerouting them elsewhere would break the
 *   replay contract the consumer depends on;
 * - a missing client throws `JetStreamSinkConfigError`, which
 *   `classifyFailure` maps to `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** NATS stream-name cap: stream names are 1–128 characters. */
export const JETSTREAM_STREAM_NAME_MAX = 128;

/** NATS subject cap: subjects are 1–255 characters. */
export const JETSTREAM_SUBJECT_MAX = 255;

/** Header carrying the record's trace id, verbatim. */
export const JETSTREAM_TRACE_ID_HEADER = "trace-id";

/**
 * One publish request as handed to the injected client. The client
 * owns the wire protocol (including publish acknowledgements);
 * this shape is the relay-side contract it must honour.
 */
export interface JetStreamPublishRequest {
  /** Target stream (the sink's configured stream). */
  stream: string;
  /** Resolved subject — never invented, see above. */
  subject: string;
  /** The event JSON, verbatim. */
  data: string;
  /**
   * Message headers. Carries `trace-id` when the record has a
   * `traceId`, and is empty otherwise — the sink never invents a
   * trace id.
   */
  headers: Record<string, string>;
}

/**
 * The injected JetStream client. Any client adapter implements
 * this one method; per-record failures throw
 * `JetStreamPublishError` (or any error, which the sink treats as
 * a transport failure). The client is expected to publish with
 * acknowledgement enabled, so a publish the stream did not
 * acknowledge surfaces as a throw.
 */
export interface JetStreamClient {
  publish(request: JetStreamPublishRequest): Promise<void>;
}

/**
 * Configuration for one JetStream stream sink. The client is
 * injected: without one, `publish()` throws
 * `JetStreamSinkConfigError` (dry runs excepted — they need no
 * client at all).
 */
export interface JetStreamSinkConfig {
  /**
   * Target stream, 1–128 characters, no NUL, no whitespace. One
   * sink targets one stream; the subject varies per record.
   * Persistence is a property of the stream itself (its
   * retention/storage config), not a per-message flag.
   */
  stream: string;
  /**
   * The JetStream client to deliver through. Injected, never
   * bundled: the operator's client adapter (nats.js, native
   * binding, sidecar) implements `JetStreamClient`. Required for
   * real sends; a missing client is a config error, not a
   * silent no-op.
   */
  client?: JetStreamClient;
  /**
   * Rehearsal mode: `publish()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero client
   * I/O — no publish call, no stat changes. Records are still
   * validated, so a dry run catches a malformed record before it
   * reaches production. Mirrors the `dryRun` convention of the S3
   * offloaders.
   */
  dryRun?: boolean;
}

/** One event to publish to the stream. */
export interface JetStreamRecord {
  /** The event JSON, already serialized by the caller — published verbatim. */
  body: string;
  /**
   * Explicit subject. Wins over `key`/`traceId` when set.
   * Must be non-empty and at most 255 characters when resolved,
   * free of NUL and whitespace.
   */
  subject?: string;
  /**
   * Event key (e.g. aggregate id): the subject source when no
   * explicit `subject` is set. Events sharing a key land under
   * the same subject and replay in order.
   */
  key?: string;
  /**
   * Trace id: the subject fallback when neither `subject` nor
   * `key` is set, and — when set — the value passed through as
   * the `trace-id` message header. Lets the consumer correlate
   * the stream message with the relay's audit trail without
   * opening the body.
   */
  traceId?: string;
}

/** One record as it goes to the client (subject resolved, headers built). */
export interface JetStreamResolvedRecord {
  /** The event JSON, verbatim. */
  data: string;
  /** Resolved subject (non-empty, at most 255 characters). */
  subject: string;
  /** Message headers (`trace-id` when the record has a `traceId`). */
  headers: Record<string, string>;
}

/** One failed record, with its retry lane already mapped. */
export interface JetStreamFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /** Stream error code, or `TRANSPORT_ERROR` for a codeless failure. */
  errorCode: string;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: transient stream states
   * (including publish failures and stream unavailability) are
   * retryable, fail-closed records (unknown stream/subject,
   * invalid subject, oversize message) are not.
   */
  retryable: boolean;
}

/** Outcome of one `publish()` call (failures throw, see above). */
export interface JetStreamPublishResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Records the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-218). */
export interface JetStreamSinkStats {
  /** Records accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Records reported failed by the client. */
  failed: number;
  /** Publish calls that threw (counted before the error is thrown). */
  publishFailures: number;
}

/**
 * Thrown when a publish throws per record: a stream-side or
 * transport failure mapped onto the JetStream error code. Carries
 * the codeless transport case as `TRANSPORT_ERROR`, and every
 * failed record with its retry lane, so the caller retries
 * exactly the failed records without parsing message strings.
 */
export class JetStreamPublishError extends Error {
  /** Stream error code (e.g. `STREAM_UNAVAILABLE`). */
  readonly errorCode: string;
  constructor(errorCode: string, message?: string) {
    super(message ?? `jetstream-sink: publish failed (${errorCode})`);
    this.name = "JetStreamPublishError";
    this.errorCode = errorCode;
  }
}

/**
 * Thrown for JetStream publish failures. Carries every failed
 * record with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those records. A publish call that
 * throws has partial success behind it — the accepted records
 * are already in the stream and are *not* in `failedRecords`.
 */
export class JetStreamSinkError extends Error {
  /** Per-record failures, in input order, each with its retry lane. */
  readonly failedRecords: JetStreamFailedRecord[];
  constructor(message: string, failedRecords: JetStreamFailedRecord[]) {
    super(message);
    this.name = "JetStreamSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even publish — currently: no client
 * was injected. A config problem, not a downstream verdict, so
 * the retry queue must not burn attempts on it (`classifyFailure`
 * maps it to `non_retryable`).
 */
export class JetStreamSinkConfigError extends JetStreamSinkError {
  constructor() {
    super("jetstream-sink: no client injected (set `client` in the sink config)", []);
    this.name = "JetStreamSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery.
 */
export function assertValidJetStreamSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is JetStreamSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  if (
    typeof c.stream !== "string" ||
    c.stream === "" ||
    c.stream.length > JETSTREAM_STREAM_NAME_MAX ||
    c.stream.includes("\0") ||
    /\s/.test(c.stream)
  ) {
    throw new RangeError(
      at("`stream` must be 1–128 characters, free of NUL and whitespace")
    );
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
 * Resolve one record's subject: explicit `subject`, then `key`,
 * then `traceId`. Throws `RangeError` when none is set or the
 * resolved subject is empty, over 255 characters, or contains
 * NUL or whitespace — the sink never invents a subject and never
 * publishes a subject the stream cannot match.
 */
export function resolveJetStreamSubject(
  record: JetStreamRecord,
  index: number
): string {
  const subject = record.subject ?? record.key ?? record.traceId;
  if (typeof subject !== "string" || subject === "") {
    throw new RangeError(
      `jetstream-sink: record ${index} has no subject (set subject, key, or traceId)`
    );
  }
  if (
    subject.length > JETSTREAM_SUBJECT_MAX ||
    subject.includes("\0") ||
    /\s/.test(subject)
  ) {
    throw new RangeError(
      `jetstream-sink: record ${index} subject must be 1–255 characters, free of NUL and whitespace`
    );
  }
  return subject;
}

/**
 * Build one record's headers: the `trace-id` header carries the
 * record's `traceId` verbatim when set, and is absent otherwise —
 * the sink never invents a trace id.
 */
export function resolveJetStreamHeaders(
  record: JetStreamRecord
): Record<string, string> {
  if (record.traceId === undefined || record.traceId === "") {
    return {};
  }
  return { [JETSTREAM_TRACE_ID_HEADER]: record.traceId };
}

/**
 * Validate one record's body and resolve its publish form. Throws
 * `RangeError` on an empty body string.
 */
export function resolveJetStreamRecord(
  record: JetStreamRecord,
  index: number
): JetStreamResolvedRecord {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`jetstream-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return {
    data: record.body,
    subject: resolveJetStreamSubject(record, index),
    headers: resolveJetStreamHeaders(record),
  };
}

/**
 * Stream error codes that are transient — publish failures,
 * publish acknowledgement timeouts, stream unavailability,
 * connection loss — and so retryable under the WR-210 mapping.
 * A publish failure is retryable: it says the stream could not
 * accept the message right now, not that the payload is poison.
 * A codeless transport failure is carried as `TRANSPORT_ERROR`
 * and is retryable too: like an SQS transport error with no
 * status, it says nothing about the payload. Any code not listed
 * here is a fail-closed record (unknown stream/subject, invalid
 * subject, oversize message) and is non-retryable: rerouting it
 * elsewhere would break the replay contract, and retrying it
 * burns the retry budget for nothing.
 */
const JETSTREAM_RETRYABLE_ERROR_CODES = new Set([
  "TRANSPORT_ERROR",
  "CONNECTION_LOST",
  "NOT_CONNECTED",
  "STREAM_UNAVAILABLE",
  "PUBLISH_FAILED",
  "PUBLISH_TIMEOUT",
  "NO_ACK",
]);

/**
 * Map one JetStream publish `errorCode` onto its retry lane under
 * the WR-210 rules: transient stream states (including publish
 * failures and stream unavailability) are retryable, any other
 * code is a fail-closed record, like any other 4xx.
 */
export function classifyJetStreamRecordFailure(errorCode: string): boolean {
  return JETSTREAM_RETRYABLE_ERROR_CODES.has(errorCode);
}

/**
 * JetStream stream sink (WR-218). One instance targets one
 * stream; the caller owns retry/dead-letter policy around
 * `publish()` — this class performs one publish attempt per
 * record through the injected client and reports its outcome.
 * Failures throw `JetStreamSinkError` carrying exactly the failed
 * records with their retry lanes.
 */
export class JetStreamSink {
  private readonly cfg: JetStreamSinkConfig;
  private sent = 0;
  private failed = 0;
  private publishFailures = 0;

  constructor(config: JetStreamSinkConfig) {
    assertValidJetStreamSinkConfig(config, "JetStreamSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): JetStreamSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      publishFailures: this.publishFailures,
    };
  }

  /**
   * Publish records to the stream, in input order. Throws
   * `JetStreamSinkConfigError` when no client was injected and
   * `JetStreamSinkError` when any record fails (carrying exactly
   * the failed records with their retry lanes; both counted in
   * stats before throwing, so the counters stay honest even for
   * callers that only inspect stats).
   */
  async publish(records: JetStreamRecord[]): Promise<JetStreamPublishResult> {
    const resolved = records.map((r, i) => resolveJetStreamRecord(r, i));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches a
      // malformed record before it reaches production — but perform
      // zero client I/O and touch no stats.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new JetStreamSinkConfigError();
    }
    const failedRecords: JetStreamFailedRecord[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i] as JetStreamResolvedRecord;
      try {
        await client.publish({
          stream: this.cfg.stream,
          subject: record.subject,
          data: record.data,
          headers: record.headers,
        });
      } catch (err) {
        failedRecords.push(toJetStreamFailedRecord(err, i));
        continue;
      }
      sent += 1;
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.publishFailures += 1;
      throw new JetStreamSinkError(
        `jetstream-sink: publish ${this.cfg.stream} failed for ${failedRecords.length} of ${resolved.length} records`,
        failedRecords
      );
    }
    return { ok: true, sent };
  }
}

/**
 * Convert a client throw into a failed record: a
 * `JetStreamPublishError` maps by its code, any other error is a
 * codeless transport failure (`TRANSPORT_ERROR`, retryable — the
 * SQS no-status rule).
 */
function toJetStreamFailedRecord(err: unknown, index: number): JetStreamFailedRecord {
  if (err instanceof JetStreamPublishError) {
    const failed: JetStreamFailedRecord = {
      index,
      errorCode: err.errorCode,
      retryable: classifyJetStreamRecordFailure(err.errorCode),
    };
    if (err.message !== "") failed.errorMessage = err.message;
    return failed;
  }
  const failed: JetStreamFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
