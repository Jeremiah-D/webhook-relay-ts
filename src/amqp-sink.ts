/**
 * AMQP delivery sink (WR-217).
 *
 * Some downstreams are not HTTP endpoints at all: they are AMQP
 * brokers (RabbitMQ and kin). Where the SQS sink (WR-210) delivers
 * to an unordered queue, the Kinesis sink (WR-213) delivers to an
 * AWS SigV4 stream, the Kafka sink (WR-215) delivers to a
 * partitioned log, and the MQTT sink (WR-216) delivers to a pub/sub
 * topic tree, this sink delivers to an *exchange* over the native
 * AMQP publish protocol: one event is published to a named
 * exchange under a routing key, and the broker — not the relay —
 * owns routing it to the bound queues. The five sinks are
 * orthogonal — queue delivery for unordered work, stream delivery
 * for AWS-ordered work, log delivery for broker-native ordered
 * work, topic delivery for broker-mediated fan-out, exchange
 * delivery for broker-mediated routing — and an AMQP delivery can
 * still be archived by the S3 offloaders like any other delivery.
 *
 * No real AMQP client is bundled: the client is injected through
 * `config.client` (a thin adapter over whatever client the
 * operator runs — amqplib, a native binding, a sidecar), so the
 * module has zero new dependencies and tests never need a broker.
 * The sink owns the relay-side concerns — exchange and routing-key
 * resolution, persistent delivery mode, per-record failure mapping
 * — and the injected client owns the wire protocol, including
 * publisher confirms.
 *
 * Wire shape — one publish request per record, carried to the
 * injected client as:
 *
 *   { exchange: "<exchange>", routingKey: "<routing key>",
 *     body: "<event JSON>", persistent: <boolean> }
 *
 * Routing keys come from the event, never invented: an explicit
 * `routingKey` wins, then the event `key`, then the `traceId`. A
 * record with none of the three is rejected at build time
 * (fail-closed) — inventing a key would silently route unrelated
 * events to the same queue, the same reason the Kafka sink refuses
 * to invent a partition key and the MQTT sink refuses to invent a
 * topic segment. The exchange is sink-configured (one sink targets
 * one exchange), like the Kafka sink's topic and the MQTT sink's
 * topic prefix.
 *
 * Persistent delivery is opt-in (`persistent: true`): a persistent
 * message is written to disk by the broker and survives a broker
 * restart, at the cost of a disk write per publish. It defaults to
 * off, because most relay events are transient notifications whose
 * retry queue — not the broker's disk — is the durability story.
 * The flag is carried on every publish request so the injected
 * client can apply it (delivery mode 2 in AMQP terms); a client
 * that fixes persistence at construction time applies the same
 * value there instead.
 *
 * Publisher confirms — the injected client is expected to publish
 * with confirms enabled, so a publish that the broker did not
 * acknowledge surfaces as a failure rather than a silent drop. A
 * confirm failure (`PUBLISH_NACKED`, `CONFIRM_TIMEOUT`) maps to
 * the retryable lane: a nack says the broker could not accept the
 * message right now, not that the payload is poison, so the
 * caller's retry queue replays exactly those records. The same
 * lane covers connection and channel loss and codeless transport
 * failures.
 *
 * Failure handling mirrors the WR-210 SQS sink's classification
 * (`src/failure.ts`), applied per record:
 *
 * - a per-record publish failure throws `AmqpSinkError` carrying
 *   every failed record with its retry lane already mapped, so the
 *   caller retries exactly the failed records;
 * - retryable codes are the transient broker states — connection /
 *   channel loss, confirm failures, and transport failures with no
 *   code at all (the no-status analog of the SQS transport rule,
 *   carried as `TRANSPORT_ERROR`);
 * - non-retryable codes are the poison records — oversize bodies
 *   and invalid exchanges / routing keys / payloads — the 4xx
 *   analog: retrying them burns the retry budget for nothing;
 * - a missing client throws `AmqpSinkConfigError`, which
 *   `classifyFailure` maps to `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** AMQP short-string cap: exchange names are 1–127 characters. */
export const AMQP_EXCHANGE_NAME_MAX = 127;

/** AMQP short-string cap: routing keys are 1–255 characters. */
export const AMQP_ROUTING_KEY_MAX = 255;

/**
 * One publish request as handed to the injected client. The client
 * owns the wire protocol (including publisher confirms); this
 * shape is the relay-side contract it must honour.
 */
export interface AmqpPublishRequest {
  /** Target exchange (the sink's configured exchange). */
  exchange: string;
  /** Resolved routing key — never invented, see above. */
  routingKey: string;
  /** The event JSON, verbatim. */
  body: string;
  /**
   * Persistent delivery flag for this publish: when `true` the
   * client must mark the message persistent (AMQP delivery mode
   * 2) so it survives a broker restart.
   */
  persistent: boolean;
}

/**
 * The injected AMQP client. Any client adapter implements this
 * one method; per-record failures throw `AmqpPublishError` (or any
 * error, which the sink treats as a transport failure). The client
 * is expected to publish with publisher confirms enabled, so a
 * broker nack or a confirm timeout surfaces as a throw.
 */
export interface AmqpClient {
  publish(request: AmqpPublishRequest): Promise<void>;
}

/**
 * Configuration for one AMQP exchange sink. The client is injected:
 * without one, `publish()` throws `AmqpSinkConfigError` (dry runs
 * excepted — they need no client at all).
 */
export interface AmqpSinkConfig {
  /**
   * Target exchange, 1–127 characters, no NUL. One sink targets
   * one exchange; the routing key varies per record.
   */
  exchange: string;
  /**
   * Persistent delivery flag, carried on every publish request.
   * Default `false`: persistent messages cost a broker disk write
   * each, and the relay's retry queue — not the broker's disk —
   * is the durability story for most events.
   */
  persistent?: boolean;
  /**
   * The AMQP client to deliver through. Injected, never bundled:
   * the operator's client adapter (amqplib, native binding,
   * sidecar) implements `AmqpClient`. Required for real sends; a
   * missing client is a config error, not a silent no-op.
   */
  client?: AmqpClient;
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

/** One event to publish to the exchange. */
export interface AmqpRecord {
  /** The event JSON, already serialized by the caller — published verbatim. */
  body: string;
  /**
   * Explicit routing key. Wins over `key`/`traceId` when set.
   * Must be non-empty and at most 255 characters when resolved.
   */
  routingKey?: string;
  /**
   * Event key (e.g. aggregate id): the routing-key source when no
   * explicit `routingKey` is set. Events sharing a key route to
   * the same queues.
   */
  key?: string;
  /**
   * Trace id: the routing-key fallback when neither `routingKey`
   * nor `key` is set. Lets the consumer correlate the exchange
   * message with the relay's audit trail without opening the body.
   */
  traceId?: string;
}

/** One record as it goes to the client (routing key resolved). */
export interface AmqpResolvedRecord {
  /** The event JSON, verbatim. */
  body: string;
  /** Resolved routing key (non-empty, at most 255 characters). */
  routingKey: string;
}

/** One failed record, with its retry lane already mapped. */
export interface AmqpFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /** Broker error code, or `TRANSPORT_ERROR` for a codeless failure. */
  errorCode: string;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: transient broker states
   * (including confirm failures) are retryable, poison records
   * are not.
   */
  retryable: boolean;
}

/** Outcome of one `publish()` call (failures throw, see above). */
export interface AmqpPublishResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Records the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-217). */
export interface AmqpSinkStats {
  /** Records accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Records reported failed by the client. */
  failed: number;
  /** Publish calls that threw (counted before the error is thrown). */
  publishFailures: number;
}

/**
 * Thrown when a publish throws per record: a broker-side or
 * transport failure mapped onto the AMQP error code. Carries the
 * codeless transport case as `TRANSPORT_ERROR`, and every failed
 * record with its retry lane, so the caller retries exactly the
 * failed records without parsing message strings.
 */
export class AmqpPublishError extends Error {
  /** Broker error code (e.g. `CONNECTION_LOST`). */
  readonly errorCode: string;
  constructor(errorCode: string, message?: string) {
    super(message ?? `amqp-sink: publish failed (${errorCode})`);
    this.name = "AmqpPublishError";
    this.errorCode = errorCode;
  }
}

/**
 * Thrown for AMQP publish failures. Carries every failed record
 * with its retry lane (`failedRecords`), so the retry queue can
 * requeue exactly those records. A publish call that throws has
 * partial success behind it — the accepted records are already at
 * the broker and are *not* in `failedRecords`.
 */
export class AmqpSinkError extends Error {
  /** Per-record failures, in input order, each with its retry lane. */
  readonly failedRecords: AmqpFailedRecord[];
  constructor(message: string, failedRecords: AmqpFailedRecord[]) {
    super(message);
    this.name = "AmqpSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even publish — currently: no client
 * was injected. A config problem, not a downstream verdict, so the
 * retry queue must not burn attempts on it (`classifyFailure` maps
 * it to `non_retryable`).
 */
export class AmqpSinkConfigError extends AmqpSinkError {
  constructor() {
    super("amqp-sink: no client injected (set `client` in the sink config)", []);
    this.name = "AmqpSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery.
 */
export function assertValidAmqpSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is AmqpSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  if (
    typeof c.exchange !== "string" ||
    c.exchange === "" ||
    c.exchange.length > AMQP_EXCHANGE_NAME_MAX ||
    c.exchange.includes("\0")
  ) {
    throw new RangeError(
      at("`exchange` must be 1–127 characters, free of NUL")
    );
  }
  if (c.persistent !== undefined && typeof c.persistent !== "boolean") {
    throw new RangeError(at("`persistent` must be a boolean when set"));
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
 * Resolve one record's routing key: explicit `routingKey`, then
 * `key`, then `traceId`. Throws `RangeError` when none is set or
 * the resolved key is empty, over 255 characters, or contains
 * NUL — the sink never invents a key and never publishes a key
 * the broker cannot route.
 */
export function resolveAmqpRoutingKey(
  record: AmqpRecord,
  index: number
): string {
  const key = record.routingKey ?? record.key ?? record.traceId;
  if (typeof key !== "string" || key === "") {
    throw new RangeError(
      `amqp-sink: record ${index} has no routing key (set routingKey, key, or traceId)`
    );
  }
  if (key.length > AMQP_ROUTING_KEY_MAX || key.includes("\0")) {
    throw new RangeError(
      `amqp-sink: record ${index} routing key must be 1–255 characters, free of NUL`
    );
  }
  return key;
}

/**
 * Validate one record's body and resolve its publish form. Throws
 * `RangeError` on an empty body string.
 */
export function resolveAmqpRecord(
  record: AmqpRecord,
  index: number
): AmqpResolvedRecord {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`amqp-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return {
    body: record.body,
    routingKey: resolveAmqpRoutingKey(record, index),
  };
}

/**
 * Broker error codes that are transient — connection / channel
 * loss, publisher-confirm failures, broker unavailability — and so
 * retryable under the WR-210 mapping. A confirm failure is
 * retryable: a nack or a confirm timeout says the broker could not
 * accept the message right now, not that the payload is poison. A
 * codeless transport failure is carried as `TRANSPORT_ERROR` and
 * is retryable too: like an SQS transport error with no status, it
 * says nothing about the payload. Any code not listed here is a
 * poison record (oversize body, invalid exchange / routing key)
 * and is non-retryable.
 */
const AMQP_RETRYABLE_ERROR_CODES = new Set([
  "TRANSPORT_ERROR",
  "CONNECTION_LOST",
  "NOT_CONNECTED",
  "CHANNEL_CLOSED",
  "SERVER_UNAVAILABLE",
  "PUBLISH_NACKED",
  "CONFIRM_TIMEOUT",
]);

/**
 * Map one AMQP publish `errorCode` onto its retry lane under the
 * WR-210 rules: transient broker states (including confirm
 * failures) are retryable, any other code is a poison record, like
 * any other 4xx.
 */
export function classifyAmqpRecordFailure(errorCode: string): boolean {
  return AMQP_RETRYABLE_ERROR_CODES.has(errorCode);
}

/**
 * AMQP exchange sink (WR-217). One instance targets one exchange;
 * the caller owns retry/dead-letter policy around `publish()` —
 * this class performs one publish attempt per record through the
 * injected client and reports its outcome. Failures throw
 * `AmqpSinkError` carrying exactly the failed records with their
 * retry lanes.
 */
export class AmqpSink {
  private readonly cfg: AmqpSinkConfig;
  private readonly persistent: boolean;
  private sent = 0;
  private failed = 0;
  private publishFailures = 0;

  constructor(config: AmqpSinkConfig) {
    assertValidAmqpSinkConfig(config, "AmqpSink");
    this.cfg = config;
    this.persistent = config.persistent ?? false;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): AmqpSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      publishFailures: this.publishFailures,
    };
  }

  /**
   * Publish records to the exchange, in input order. Throws
   * `AmqpSinkConfigError` when no client was injected and
   * `AmqpSinkError` when any record fails (carrying exactly the
   * failed records with their retry lanes; both counted in stats
   * before throwing, so the counters stay honest even for callers
   * that only inspect stats).
   */
  async publish(records: AmqpRecord[]): Promise<AmqpPublishResult> {
    const resolved = records.map((r, i) => resolveAmqpRecord(r, i));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches a
      // malformed record before it reaches production — but perform
      // zero client I/O and touch no stats.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new AmqpSinkConfigError();
    }
    const failedRecords: AmqpFailedRecord[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i] as AmqpResolvedRecord;
      try {
        await client.publish({
          exchange: this.cfg.exchange,
          routingKey: record.routingKey,
          body: record.body,
          persistent: this.persistent,
        });
      } catch (err) {
        failedRecords.push(toAmqpFailedRecord(err, i));
        continue;
      }
      sent += 1;
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.publishFailures += 1;
      throw new AmqpSinkError(
        `amqp-sink: publish ${this.cfg.exchange} failed for ${failedRecords.length} of ${resolved.length} records`,
        failedRecords
      );
    }
    return { ok: true, sent };
  }
}

/**
 * Convert a client throw into a failed record: an
 * `AmqpPublishError` maps by its code, any other error is a
 * codeless transport failure (`TRANSPORT_ERROR`, retryable — the
 * SQS no-status rule).
 */
function toAmqpFailedRecord(err: unknown, index: number): AmqpFailedRecord {
  if (err instanceof AmqpPublishError) {
    const failed: AmqpFailedRecord = {
      index,
      errorCode: err.errorCode,
      retryable: classifyAmqpRecordFailure(err.errorCode),
    };
    if (err.message !== "") failed.errorMessage = err.message;
    return failed;
  }
  const failed: AmqpFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
