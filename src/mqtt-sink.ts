/**
 * MQTT delivery sink (WR-216).
 *
 * Some downstreams are not HTTP endpoints at all: they are MQTT
 * brokers. Where the SQS sink (WR-210) delivers to an unordered
 * queue, the Kinesis sink (WR-213) delivers to an AWS SigV4 stream,
 * and the Kafka sink (WR-215) delivers to a partitioned log, this
 * sink delivers to a *pub/sub topic tree* over the native MQTT
 * publish protocol: one event fans out to every subscriber of its
 * topic, and the broker — not the relay — owns fan-out. The four
 * sinks are orthogonal — queue delivery for unordered work, stream
 * delivery for AWS-ordered work, log delivery for broker-native
 * ordered work, topic delivery for broker-mediated fan-out — and an
 * MQTT delivery can still be archived by the S3 offloaders like any
 * other delivery. It is orthogonal to the WebSocket downstream
 * (WR-45) too: that is a direct relay-to-client connection, this is
 * broker-mediated delivery.
 *
 * No real MQTT client is bundled: the client is injected through
 * `config.client` (a thin adapter over whatever client the operator
 * runs — mqtt.js, a native binding, a sidecar), so the module has
 * zero new dependencies and tests never need a broker. The sink owns
 * the relay-side concerns — topic resolution, QoS configuration and
 * downgrade, retain flag, per-record failure mapping, connection
 * state — and the injected client owns the wire protocol.
 *
 * Wire shape — one publish request per record, carried to the
 * injected client as:
 *
 *   { topic: "<topic>", payload: "<event JSON>",
 *     qos: <0|1|2>, retain: <boolean> }
 *
 * Topics come from the event, never invented: an explicit
 * `topicKey` wins, then the event `key`, then the `traceId`. The
 * resolved segment is appended to the configured `topicPrefix`
 * (when set) as one topic level, so one event maps to exactly one
 * topic: `<prefix>/<segment>`, or just `<segment>` with no prefix.
 * A record with none of the three is rejected at build time
 * (fail-closed) — inventing a segment would silently publish
 * unrelated events under one topic, the same reason the Kafka sink
 * refuses to invent a partition key. A segment containing a `/`
 * would silently fan out into sub-levels, so it is rejected too;
 * `+`, `#`, and NUL are rejected for the same reason they are
 * illegal in an MQTT topic.
 *
 * QoS is configurable per sink: `1` (the default — at-least-once,
 * the relay's normal delivery guarantee), `2` (exactly-once, when
 * the broker and the consumer both honour it), `0` (fire and
 * forget, no acknowledgement). The configured value is carried on
 * every publish request so the injected client can apply it; a
 * client that fixes QoS at construction time applies the same value
 * there instead.
 *
 * QoS downgrade — a broker may cap the QoS it accepts (e.g. a
 * constrained IoT broker that only honours QoS 0/1). When a publish
 * fails with `QOS_NOT_SUPPORTED`, the sink retries the same record
 * at the next lower QoS, down to 0, inside the same produce call:
 * a downgrade is a broker capability negotiation, not a delivery
 * failure, so it must not burn the retry budget. A record that
 * lands at a lower QoS is counted as sent and reported in
 * `result.downgrades` (by original index, with the requested and
 * delivered levels), so the caller can see the guarantee it
 * actually got. QoS 0 rejected with `QOS_NOT_SUPPORTED` has nowhere
 * lower to go and is a poison record (non-retryable).
 *
 * Disconnect and resend — a publish that fails with a connection
 * error (`CONNECTION_LOST`, `NOT_CONNECTED`, or a codeless transport
 * failure carried as `TRANSPORT_ERROR`) marks the sink
 * disconnected and maps to the retryable lane under the WR-210
 * rules, so the caller's retry queue replays exactly those records
 * after the connection is restored — that replay *is* the resend,
 * not a second mechanism. `reconnect()` re-arms the sink once the
 * operator has restored the client (delegating to the client's
 * `connect` when it provides one); the `connected` flag is the last
 * observed connection outcome, nothing more — a publish is still
 * attempted while disconnected, and fails fast if the broker is
 * still unreachable.
 *
 * Retain is opt-in (`retain: true`): a retained message becomes the
 * topic's last-known-good value for late subscribers. It defaults
 * to off, because retaining relay events by accident would hand
 * every new subscriber a stale event as if it were fresh.
 *
 * Failure handling mirrors the WR-210 SQS sink's classification
 * (`src/failure.ts`), applied per record:
 *
 * - a per-record publish failure throws `MqttSinkError` carrying
 *   every failed record with its retry lane already mapped, so the
 *   caller retries exactly the failed records;
 * - retryable codes are the transient broker states — connection
 *   loss, broker unavailability, and transport failures with no
 *   code at all (the no-status analog of the SQS transport rule,
 *   carried as `TRANSPORT_ERROR`);
 * - non-retryable codes are the poison records — oversize
 *   payloads, invalid topics, unauthorized publishes, and a QoS
 *   floor rejection — the 4xx analog: retrying them burns the
 *   retry budget for nothing;
 * - a missing client throws `MqttSinkConfigError`, which
 *   `classifyFailure` maps to `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Default QoS when `qos` is unset: at-least-once. */
export const MQTT_SINK_DEFAULT_QOS = 1;

/**
 * MQTT quality-of-service level. `0` is fire and forget, `1` is
 * at-least-once, `2` is exactly-once (when broker and consumer both
 * honour it).
 */
export type MqttQos = 0 | 1 | 2;

/**
 * One publish request as handed to the injected client. The client
 * owns the wire protocol; this shape is the relay-side contract it
 * must honour.
 */
export interface MqttPublishRequest {
  /** Target topic (prefix + resolved segment, see above). */
  topic: string;
  /** The event JSON, verbatim. */
  payload: string;
  /** QoS level for this publish (after any downgrade). */
  qos: MqttQos;
  /** Retain flag for this publish. */
  retain: boolean;
}

/**
 * The injected MQTT client. Any client adapter implements
 * `publish`; `connect` is optional and is only used by
 * `MqttSink.reconnect()` to re-establish the broker connection.
 */
export interface MqttClient {
  publish(request: MqttPublishRequest): Promise<void>;
  /** Re-establish the broker connection, when the client manages one. */
  connect?(): Promise<void>;
}

/**
 * Configuration for one MQTT topic sink. The client is injected:
 * without one, `publish()` throws `MqttSinkConfigError` (dry runs
 * excepted — they need no client at all).
 */
export interface MqttSinkConfig {
  /**
   * Topic prefix prepended to every resolved segment as
   * `<prefix>/<segment>`. When unset, the segment alone is the
   * topic. Must not contain `+`, `#`, NUL, or empty levels.
   */
  topicPrefix?: string;
  /**
   * Quality-of-service level; default {@link MQTT_SINK_DEFAULT_QOS}.
   * Carried on every publish request to the injected client, before
   * any downgrade.
   */
  qos?: MqttQos;
  /**
   * Retain flag, carried on every publish request. Default `false`:
   * retained relay events would otherwise greet every late
   * subscriber as if fresh.
   */
  retain?: boolean;
  /**
   * The MQTT client to deliver through. Injected, never bundled:
   * the operator's client adapter (mqtt.js, native binding,
   * sidecar) implements `MqttClient`. Required for real sends; a
   * missing client is a config error, not a silent no-op.
   */
  client?: MqttClient;
  /**
   * Rehearsal mode: `publish()` returns
   * `{ ok: true, sent: 0, downgrades: [], dryRun: true }` and
   * performs zero client I/O — no publish call, no stat changes.
   * Records are still validated, so a dry run catches a malformed
   * record before it reaches production. Mirrors the `dryRun`
   * convention of the S3 offloaders.
   */
  dryRun?: boolean;
}

/** One event to publish to the broker. */
export interface MqttRecord {
  /** The event JSON, already serialized by the caller — published verbatim. */
  payload: string;
  /**
   * Explicit topic segment. Wins over `key`/`traceId` when set.
   * Must be non-empty and free of `/`, `+`, `#`, NUL when resolved.
   */
  topicKey?: string;
  /**
   * Event key (e.g. aggregate id): the topic-segment source when no
   * explicit `topicKey` is set. Events sharing a key land on the
   * same topic.
   */
  key?: string;
  /**
   * Trace id: the topic-segment fallback when neither `topicKey`
   * nor `key` is set. Lets the subscriber correlate the topic
   * message with the relay's audit trail without opening the
   * payload.
   */
  traceId?: string;
}

/** One record as it goes to the client (topic resolved). */
export interface MqttResolvedRecord {
  /** The event JSON, verbatim. */
  payload: string;
  /** Resolved topic (prefix + segment, or segment alone). */
  topic: string;
}

/** One failed record, with its retry lane already mapped. */
export interface MqttFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /** Broker error code, or `TRANSPORT_ERROR` for a codeless failure. */
  errorCode: string;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: transient broker states
   * are retryable, poison records are not.
   */
  retryable: boolean;
}

/** One record that landed at a lower QoS than requested. */
export interface MqttDowngrade {
  /** Index into the caller's original `records` array. */
  index: number;
  /** QoS the sink was configured to use. */
  requested: MqttQos;
  /** QoS the broker actually accepted. */
  delivered: MqttQos;
}

/** Outcome of one `publish()` call (failures throw, see above). */
export interface MqttPublishResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Records the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /**
   * Records delivered at a lower QoS than configured, in input
   * order. Empty when nothing was downgraded.
   */
  downgrades: MqttDowngrade[];
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-216). */
export interface MqttSinkStats {
  /** Records accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Records reported failed by the client. */
  failed: number;
  /** Records delivered at a downgraded QoS. */
  downgrades: number;
  /** Publish calls that threw (counted before the error is thrown). */
  publishFailures: number;
}

/**
 * Thrown when a publish throws per record: a broker-side or
 * transport failure mapped onto the MQTT error code. Carries the
 * codeless transport case as `TRANSPORT_ERROR`, and every failed
 * record with its retry lane, so the caller retries exactly the
 * failed records without parsing message strings.
 */
export class MqttPublishError extends Error {
  /** Broker error code (e.g. `CONNECTION_LOST`). */
  readonly errorCode: string;
  constructor(errorCode: string, message?: string) {
    super(message ?? `mqtt-sink: publish failed (${errorCode})`);
    this.name = "MqttPublishError";
    this.errorCode = errorCode;
  }
}

/**
 * Thrown for MQTT publish failures. Carries every failed record
 * with its retry lane (`failedRecords`), so the retry queue can
 * requeue exactly those records. A publish call that throws has
 * partial success behind it — the accepted records are already at
 * the broker and are *not* in `failedRecords`.
 */
export class MqttSinkError extends Error {
  /** Per-record failures, in input order, each with its retry lane. */
  readonly failedRecords: MqttFailedRecord[];
  constructor(message: string, failedRecords: MqttFailedRecord[]) {
    super(message);
    this.name = "MqttSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even publish — currently: no client
 * was injected. A config problem, not a downstream verdict, so the
 * retry queue must not burn attempts on it (`classifyFailure` maps
 * it to `non_retryable`).
 */
export class MqttSinkConfigError extends MqttSinkError {
  constructor() {
    super("mqtt-sink: no client injected (set `client` in the sink config)", []);
    this.name = "MqttSinkConfigError";
  }
}

/**
 * A topic level is illegal when it is empty or contains an MQTT
 * wildcard (`+`, `#`) or NUL. A resolved segment additionally
 * rejects `/`, which would silently fan out into sub-levels.
 */
function assertValidTopicPart(part: string, what: string, label: string): void {
  if (
    part === "" ||
    part.includes("+") ||
    part.includes("#") ||
    part.includes("\0")
  ) {
    throw new RangeError(
      `${label}: ${what} must be non-empty and free of \`+\`, \`#\`, NUL`
    );
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery.
 */
export function assertValidMqttSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is MqttSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  if (c.topicPrefix !== undefined) {
    if (typeof c.topicPrefix !== "string") {
      throw new RangeError(at("`topicPrefix` must be a string when set"));
    }
    assertValidTopicPart(c.topicPrefix, "`topicPrefix`", label);
    for (const level of c.topicPrefix.split("/")) {
      assertValidTopicPart(level, "`topicPrefix` level", label);
    }
  }
  if (
    c.qos !== undefined &&
    c.qos !== 0 &&
    c.qos !== 1 &&
    c.qos !== 2
  ) {
    throw new RangeError(at("`qos` must be one of `0`, `1`, `2` when set"));
  }
  if (c.retain !== undefined && typeof c.retain !== "boolean") {
    throw new RangeError(at("`retain` must be a boolean when set"));
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
 * Resolve one record's topic segment: explicit `topicKey`, then
 * `key`, then `traceId`. Throws `RangeError` when none is set or
 * the resolved segment is empty or contains `/`, `+`, `#`, NUL —
 * the sink never invents a segment and never fans one record out
 * into sub-levels.
 */
export function resolveMqttTopicSegment(
  record: MqttRecord,
  index: number
): string {
  const segment = record.topicKey ?? record.key ?? record.traceId;
  if (typeof segment !== "string" || segment === "") {
    throw new RangeError(
      `mqtt-sink: record ${index} has no topic segment (set topicKey, key, or traceId)`
    );
  }
  assertValidTopicPart(segment, "topic segment", "mqtt-sink");
  if (segment.includes("/")) {
    throw new RangeError(
      `mqtt-sink: record ${index} topic segment must not contain \`/\` (one event maps to one topic level)`
    );
  }
  return segment;
}

/**
 * Validate one record's payload and resolve its publish form.
 * Throws `RangeError` on an empty payload string.
 */
export function resolveMqttRecord(
  record: MqttRecord,
  index: number,
  topicPrefix?: string
): MqttResolvedRecord {
  if (typeof record.payload !== "string" || record.payload === "") {
    throw new RangeError(`mqtt-sink: record ${index} \`payload\` must be a non-empty event JSON string`);
  }
  const segment = resolveMqttTopicSegment(record, index);
  return {
    payload: record.payload,
    topic: topicPrefix !== undefined ? `${topicPrefix}/${segment}` : segment,
  };
}

/**
 * Broker error codes that are transient — connection loss, broker
 * unavailability — and so retryable under the WR-210 mapping. A
 * codeless transport failure is carried as `TRANSPORT_ERROR` and is
 * retryable too: like an SQS transport error with no status, it
 * says nothing about the payload. Any code not listed here is a
 * poison record (oversize payload, invalid topic, unauthorized
 * publish, QoS floor rejection) and is non-retryable.
 */
const MQTT_RETRYABLE_ERROR_CODES = new Set([
  "TRANSPORT_ERROR",
  "CONNECTION_LOST",
  "NOT_CONNECTED",
  "SERVER_UNAVAILABLE",
]);

/** Broker error codes that mark the sink disconnected. */
const MQTT_CONNECTION_ERROR_CODES = new Set([
  "TRANSPORT_ERROR",
  "CONNECTION_LOST",
  "NOT_CONNECTED",
  "SERVER_UNAVAILABLE",
]);

/**
 * Map one MQTT publish `errorCode` onto its retry lane under the
 * WR-210 rules: transient broker states are retryable, any other
 * code is a poison record, like any other 4xx.
 */
export function classifyMqttRecordFailure(errorCode: string): boolean {
  return MQTT_RETRYABLE_ERROR_CODES.has(errorCode);
}

/**
 * MQTT topic sink (WR-216). One instance targets one topic prefix;
 * the caller owns retry/dead-letter policy around `publish()` —
 * this class performs one publish attempt per record through the
 * injected client (plus QoS-downgrade retries inside the same call)
 * and reports its outcome. Failures throw `MqttSinkError`
 * carrying exactly the failed records with their retry lanes.
 */
export class MqttSink {
  private readonly cfg: MqttSinkConfig;
  private readonly qos: MqttQos;
  private readonly retain: boolean;
  private connected = true;
  private sent = 0;
  private failed = 0;
  private downgrades = 0;
  private publishFailures = 0;

  constructor(config: MqttSinkConfig) {
    assertValidMqttSinkConfig(config, "MqttSink");
    this.cfg = config;
    this.qos = config.qos ?? MQTT_SINK_DEFAULT_QOS;
    this.retain = config.retain ?? false;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): MqttSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      downgrades: this.downgrades,
      publishFailures: this.publishFailures,
    };
  }

  /**
   * Last observed connection outcome: `false` after a publish
   * failed with a connection error, `true` otherwise. Advisory
   * only — a publish is still attempted while disconnected, and
   * fails fast if the broker is still unreachable.
   */
  get isConnected(): boolean {
    return this.connected;
  }

  /**
   * Re-arm the sink after the operator has restored the client:
   * delegates to the client's `connect` when it provides one, then
   * marks the sink connected. The caller replays the records the
   * failed publish threw — that replay is the resend.
   */
  async reconnect(): Promise<void> {
    const connect = this.cfg.client?.connect;
    if (connect !== undefined) {
      await connect.call(this.cfg.client);
    }
    this.connected = true;
  }

  /**
   * Publish records to the broker, in input order. Throws
   * `MqttSinkConfigError` when no client was injected and
   * `MqttSinkError` when any record fails (carrying exactly the
   * failed records with their retry lanes; both counted in stats
   * before throwing, so the counters stay honest even for callers
   * that only inspect stats). Records delivered at a downgraded
   * QoS are counted as sent and reported in
   * `result.downgrades`, never thrown.
   */
  async publish(records: MqttRecord[]): Promise<MqttPublishResult> {
    const resolved = records.map((r, i) =>
      resolveMqttRecord(r, i, this.cfg.topicPrefix)
    );
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches a
      // malformed record before it reaches production — but perform
      // zero client I/O and touch no stats.
      return { ok: true, sent: 0, downgrades: [], dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new MqttSinkConfigError();
    }
    const failedRecords: MqttFailedRecord[] = [];
    const downgrades: MqttDowngrade[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i] as MqttResolvedRecord;
      let level = this.qos;
      for (;;) {
        try {
          await client.publish({
            topic: record.topic,
            payload: record.payload,
            qos: level,
            retain: this.retain,
          });
        } catch (err) {
          const failed = toMqttFailedRecord(err, i);
          if (
            failed.errorCode === "QOS_NOT_SUPPORTED" &&
            level > 0
          ) {
            // Broker capability negotiation, not a delivery
            // failure: step down one level and try again in the
            // same call, without burning the retry budget.
            level = (level - 1) as MqttQos;
            continue;
          }
          if (MQTT_CONNECTION_ERROR_CODES.has(failed.errorCode)) {
            this.connected = false;
          }
          failedRecords.push(failed);
          break;
        }
        sent += 1;
        if (level !== this.qos) {
          downgrades.push({ index: i, requested: this.qos, delivered: level });
        }
        break;
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    this.downgrades += downgrades.length;
    if (failedRecords.length > 0) {
      this.publishFailures += 1;
      throw new MqttSinkError(
        `mqtt-sink: publish failed for ${failedRecords.length} of ${resolved.length} records`,
        failedRecords
      );
    }
    return { ok: true, sent, downgrades };
  }
}

/**
 * Convert a client throw into a failed record: a
 * `MqttPublishError` maps by its code, any other error is a
 * codeless transport failure (`TRANSPORT_ERROR`, retryable — the
 * SQS no-status rule).
 */
function toMqttFailedRecord(err: unknown, index: number): MqttFailedRecord {
  if (err instanceof MqttPublishError) {
    const failed: MqttFailedRecord = {
      index,
      errorCode: err.errorCode,
      retryable: classifyMqttRecordFailure(err.errorCode),
    };
    if (err.message !== "") failed.errorMessage = err.message;
    return failed;
  }
  const failed: MqttFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
