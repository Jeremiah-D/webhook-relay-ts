/**
 * Azure Event Hubs delivery sink (WR-225).
 *
 * Some downstreams are not HTTP endpoints at all: they are Event
 * Hubs event hubs. Where the SQS sink (WR-210) delivers to an
 * unordered queue, the Kinesis sink (WR-213) delivers to an AWS
 * SigV4 stream, the Kafka sink (WR-215) delivers to a partitioned
 * log, the MQTT sink (WR-216) delivers to a pub/sub topic tree,
 * the AMQP sink (WR-217) delivers to an exchange, the JetStream
 * sink (WR-218) delivers to a durable stream over the native
 * JetStream publish protocol, the Redis sink (WR-219) delivers
 * to a Redis stream with XADD, the Pub/Sub sink (WR-220)
 * delivers to a Google Cloud topic with pass-through attributes,
 * the Service Bus sink (WR-221) delivers to an Azure queue or
 * topic with pass-through properties, the EventBridge sink
 * (WR-222) delivers to an AWS event bus with a resolved
 * DetailType, the Pulsar sink (WR-223) delivers to an Apache
 * Pulsar topic, and the SNS sink (WR-224) delivers to an AWS
 * SNS topic, this sink delivers to an Azure Event Hubs event
 * hub: a batch of events is sent as one `sendBatch` call, and
 * Event Hubs — not the relay — owns the event hub's retention,
 * partitioning, and fan-out to consumer groups. The sinks are
 * orthogonal — queue delivery for unordered work, stream
 * delivery for AWS-ordered work, log delivery for broker-native
 * ordered work, topic-tree delivery for broker-mediated fan-out,
 * exchange delivery for broker-mediated routing, durable-stream
 * delivery for replayable work, Redis-stream delivery for
 * in-memory ordered work, Pub/Sub delivery for cloud-managed
 * fan-out, Service Bus delivery for Azure-managed fan-out,
 * EventBridge delivery for rule-routed cloud events, Pulsar
 * delivery for geo-replicated partitioned topics, SNS delivery
 * for cloud-managed fan-out to many protocols at once, Event
 * Hubs delivery for Azure-managed streaming ingest — and an
 * Event Hubs delivery can still be archived by the S3 offloaders
 * like any other delivery.
 *
 * No real Event Hubs client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever client
 * the operator runs — @azure/event-hubs, a sidecar), so the
 * module has zero new dependencies and tests never need an
 * Azure namespace. The sink owns the relay-side concerns — event
 * hub targeting, property pass-through, partition-key opt-in,
 * per-event failure mapping — and the injected client owns the
 * wire protocol, including the sendBatch call.
 *
 * Wire shape — one sendBatch request per event hub, carried to
 * the injected client as:
 *
 *   { eventHubName: "<event hub>",
 *     events: [{ body: "<event JSON>",
 *       properties: { tenant: "<tenant>", endpoint: "<endpoint>",
 *         trace: "<traceId>" },
 *       partitionKey: "<event key>" }] }  // opt-in only
 *
 * Event hub targeting — one sink targets one event hub when
 * `eventHubName` is configured: every event goes there in a
 * single batch. When no event hub is configured, the hub
 * resolves per event from the event's own values, first
 * non-empty wins: `subject`, then `key`, then `traceId` — the
 * same source chain the EventBridge sink uses for its DetailType
 * and the SNS sink uses for its topic. Events are then batched
 * per resolved hub, one sendBatch call per hub, in
 * first-appearance order. An event with none of the three has
 * no hub source and fails closed with a `RangeError` at resolve
 * time: inventing a hub would deliver the event to consumers
 * that never asked for it.
 *
 * Event body — a message's body is the event JSON, fixed and
 * verbatim: the sink never templates, wraps, or rewrites it.
 *
 * Properties — a message's properties pass through the event's
 * own tenant, endpoint, and trace id, never invented: a
 * property is present only when the event carries that value,
 * so a consumer can filter or correlate without opening the
 * body. The trace id rides as `trace`, the short name the
 * sibling sinks use for the same value. An event with none of
 * the three carries an empty properties object — the sink never
 * invents a tenant, an endpoint, or a trace id.
 *
 * Partition keys — opt-in: when `partitionKey` is set, an
 * event's `key` becomes the event's partition key, so events
 * sharing a key land on the same partition. When the flag is
 * absent, or the event has no key, no partition key is
 * attached: the key is ignored, not defaulted, because a
 * partition key the operator never asked for would silently
 * serialize unrelated events behind each other, and Event Hubs
 * partitions unkeyed events itself.
 *
 * Failure handling mirrors the WR-210 SQS sink's classification
 * (`src/failure.ts`), applied per event (a failed batch fails
 * every event in it, since the client reports no per-event
 * outcome):
 *
 * - a failed sendBatch throws `EventHubsSinkError` carrying
 *   every failed event with its retry lane already mapped, so
 *   the caller retries exactly the failed events;
 * - retryable codes are the transient Event Hubs states —
 *   throttling, server busy, service unavailability, operation
 *   timeouts, internal errors, and codeless transport failures:
 *   a throttling failure says Event Hubs could not accept the
 *   batch right now, not that the payload is poison;
 * - non-retryable codes are the fail-closed messages —
 *   permission denied, unknown event hub, malformed event: any
 *   code outside the retryable set is fail-closed, so retrying
 *   it burns the retry budget for nothing, and rerouting it
 *   elsewhere would break the streaming contract the consumers
 *   depend on;
 * - a missing client throws `EventHubsSinkConfigError`, which
 *   `classifyFailure` maps to `non_retryable` (the WR-116
 *   rule). A missing event hub name is not a config error: it
 *   selects per-event hub resolution instead.
 *
 * Zero new dependencies: the injected client only.
 */

/** Event property carrying the event's tenant, verbatim. */
export const EVENTHUBS_TENANT_PROPERTY = "tenant";

/** Event property carrying the event's endpoint, verbatim. */
export const EVENTHUBS_ENDPOINT_PROPERTY = "endpoint";

/** Event property carrying the event's trace id, verbatim. */
export const EVENTHUBS_TRACE_PROPERTY = "trace";

/**
 * One event as handed to the injected client inside a batch.
 * The client owns the wire protocol; this shape is the
 * relay-side contract it must honour.
 */
export interface EventHubsEventData {
  /** The event JSON, verbatim. */
  body: string;
  /**
   * Pass-through event properties: `tenant`, `endpoint`, and
   * `trace`, each present only when the event carried that
   * value — the sink never invents a property.
   */
  properties: Record<string, string>;
  /**
   * Partition key, present only when the sink opted into
   * partition keys and the event has a key.
   */
  partitionKey?: string;
}

/**
 * One sendBatch request as handed to the injected client: all
 * events for one event hub, in input order.
 */
export interface EventHubsSendBatchRequest {
  /** Target event hub (the sink's configured hub, or the events' resolved hub). */
  eventHubName: string;
  /** The events for this hub, in input order. */
  events: EventHubsEventData[];
}

/**
 * The injected Event Hubs client. Any client adapter implements
 * this one method; batch failures throw `EventHubsSendError`
 * (or any error, which the sink treats as a transport failure).
 * The client sends a whole batch per call and reports no
 * per-event outcome, so a failed call fails every event in
 * that batch.
 */
export interface EventHubsClient {
  sendBatch(batch: EventHubsSendBatchRequest): Promise<void>;
}

/**
 * Configuration for one Event Hubs sink. The client is
 * injected: without one, `sendBatch()` throws
 * `EventHubsSinkConfigError` (dry runs excepted — they need no
 * client at all). A missing event hub name is not a config
 * error: it selects per-event hub resolution (subject, then
 * key, then trace id).
 */
export interface EventHubsSinkConfig {
  /**
   * Target event hub, e.g. `events`. When set, every event
   * goes there in a single batch; when absent, the hub
   * resolves per event (see `resolveEventHubsHub`). When set,
   * it must be a non-empty string, free of NUL and whitespace.
   */
  eventHubName?: string;
  /**
   * The Event Hubs client to deliver through. Injected, never
   * bundled: the operator's client adapter implements
   * `EventHubsClient`. Required for real sends; a missing
   * client is a config error, not a silent no-op.
   */
  client?: EventHubsClient;
  /**
   * Rehearsal mode: `sendBatch()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no sendBatch call, no stat changes. Events
   * are still validated (including per-event hub resolution),
   * so a dry run catches a hub-less event before it reaches
   * production. Mirrors the `dryRun` convention of the S3
   * offloaders.
   */
  dryRun?: boolean;
  /**
   * Partition-key opt-in: when `true`, an event's `key`
   * becomes the event's partition key (see
   * `resolveEventHubsPartitionKey`). When `false` or absent,
   * no partition key is ever attached.
   */
  partitionKey?: boolean;
}

/** One event to send to the event hub. */
export interface EventHubsRecord {
  /** The event JSON, already serialized by the caller — stored verbatim. */
  body: string;
  /**
   * Hub-resolution source, first priority (only when the sink
   * has no configured event hub name): the event's subject,
   * when set and non-empty. Falls through to `key`, then
   * `traceId`.
   */
  subject?: string;
  /**
   * Hub-resolution source, second priority (only when the sink
   * has no configured event hub name): the event's key (e.g.
   * aggregate id). Also the partition-key source when the sink
   * opted into partition keys.
   */
  key?: string;
  /**
   * Hub-resolution source, last priority (only when the sink
   * has no configured event hub name): the trace id. Also
   * passed through verbatim as the `trace` event property when
   * set, absent otherwise — the sink never invents a trace id.
   */
  traceId?: string;
  /**
   * Tenant property source: passed through verbatim as the
   * `tenant` event property when set, absent otherwise — the
   * sink never invents a tenant.
   */
  tenant?: string;
  /**
   * Endpoint property source: passed through verbatim as the
   * `endpoint` event property when set, absent otherwise.
   */
  endpoint?: string;
}

/** One event as it goes to the client (hub resolved, properties built, partition key resolved). */
export interface EventHubsResolvedRecord {
  /** Target event hub (configured, or resolved per event). */
  eventHubName: string;
  /** The event JSON, verbatim. */
  body: string;
  /** Pass-through event properties (only the event's own values). */
  properties: Record<string, string>;
  /** Partition key, present only under the partition-key opt-in with a key (see above). */
  partitionKey?: string;
  /** Index into the caller's original `records` array. */
  index: number;
}

/** One failed event, with its retry lane already mapped. */
export interface EventHubsFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /** Event Hubs error code, or `TRANSPORT_ERROR` for a codeless failure. */
  errorCode: string;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: transient Event Hubs
   * states (including throttling and server busy) are
   * retryable, fail-closed messages (permission, unknown hub,
   * malformed event) are not.
   */
  retryable: boolean;
}

/** Outcome of one `sendBatch()` call (failures throw, see above). */
export interface EventHubsSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Events the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-225). */
export interface EventHubsSinkStats {
  /** Events accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Events reported failed by the client. */
  failed: number;
  /** sendBatch calls that threw (counted before the error is thrown). */
  sendBatchFailures: number;
}

/**
 * Thrown when a sendBatch throws: an Event Hubs-side or
 * transport failure mapped onto the Event Hubs error code.
 * Carries the codeless transport case as `TRANSPORT_ERROR`.
 */
export class EventHubsSendError extends Error {
  /** Event Hubs error code (e.g. `ThrottlingError`). */
  readonly errorCode: string;
  constructor(errorCode: string, message?: string) {
    super(message ?? `eventhubs-sink: sendBatch failed (${errorCode})`);
    this.name = "EventHubsSendError";
    this.errorCode = errorCode;
  }
}

/**
 * Thrown for Event Hubs send failures. Carries every failed
 * event with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those events. A sendBatch call
 * that throws has partial success behind it only across
 * batches — the accepted batches are already in their hubs and
 * are *not* in `failedRecords`.
 */
export class EventHubsSinkError extends Error {
  /** Per-event failures, in input order, each with their retry lane. */
  readonly failedRecords: EventHubsFailedRecord[];
  constructor(message: string, failedRecords: EventHubsFailedRecord[]) {
    super(message);
    this.name = "EventHubsSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no client
 * was injected. A config problem, not a downstream verdict, so
 * the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`). A missing
 * event hub name is not a config error: it selects per-event
 * hub resolution instead.
 */
export class EventHubsSinkConfigError extends EventHubsSinkError {
  constructor(reason: string) {
    super(`eventhubs-sink: ${reason}`, []);
    this.name = "EventHubsSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing event hub name is *not* a shape error: it selects
 * per-event hub resolution, so a sink built before its hub is
 * known still fails closed on a hub-less event rather than
 * crashing at construction.
 */
export function assertValidEventHubsSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is EventHubsSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  if (c.eventHubName !== undefined) {
    if (
      typeof c.eventHubName !== "string" ||
      c.eventHubName === "" ||
      c.eventHubName.includes("\0") ||
      /\s/.test(c.eventHubName)
    ) {
      throw new RangeError(
        at("`eventHubName` must be a non-empty string, free of NUL and whitespace when set")
      );
    }
  }
  if (
    c.client !== undefined &&
    (c.client === null ||
      typeof c.client !== "object" ||
      typeof (c.client as { sendBatch?: unknown }).sendBatch !== "function")
  ) {
    throw new RangeError(at("`client` must expose a `sendBatch` function when set"));
  }
}

/**
 * Build one event's pass-through properties: `tenant`,
 * `endpoint`, and `trace`, each present only when the event
 * carries a non-empty value for it — the sink never invents a
 * property.
 */
export function resolveEventHubsProperties(record: EventHubsRecord): Record<string, string> {
  const properties: Record<string, string> = {};
  if (record.tenant !== undefined && record.tenant !== "") {
    properties[EVENTHUBS_TENANT_PROPERTY] = record.tenant;
  }
  if (record.endpoint !== undefined && record.endpoint !== "") {
    properties[EVENTHUBS_ENDPOINT_PROPERTY] = record.endpoint;
  }
  if (record.traceId !== undefined && record.traceId !== "") {
    properties[EVENTHUBS_TRACE_PROPERTY] = record.traceId;
  }
  return properties;
}

/**
 * Resolve one event's hub: the sink's configured event hub name
 * wins; otherwise the first non-empty value among `subject`,
 * `key`, and `traceId`, in that order. Returns `undefined`
 * when the sink has no configured event hub name and the event
 * carries none of the three — the caller fails closed rather
 * than inventing a hub.
 */
export function resolveEventHubsHub(
  record: EventHubsRecord,
  config: Pick<EventHubsSinkConfig, "eventHubName">
): string | undefined {
  if (config.eventHubName !== undefined) {
    return config.eventHubName;
  }
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return undefined;
}

/**
 * Resolve one event's partition key: the event's `key`, but
 * only when the sink opted into partition keys
 * (`partitionKey`). Any other combination — including a key
 * with the opt-in absent, or an event with no key — yields no
 * partition key: the key is ignored, not defaulted, because a
 * partition key the operator never asked for would silently
 * serialize unrelated events behind each other, and Event Hubs
 * partitions unkeyed events itself.
 */
export function resolveEventHubsPartitionKey(
  record: EventHubsRecord,
  config: Pick<EventHubsSinkConfig, "partitionKey">
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
 * Validate one event's body and resolve its send form: the hub
 * resolves from the sink config or the event's own subject,
 * key, or trace id; the properties pass through verbatim; and
 * the partition key resolves under its opt-in rule. Throws
 * `RangeError` on an empty body string, and on an event with
 * no hub source when the sink has no configured event hub name
 * — a hub-less event fails closed, never with an invented hub.
 */
export function resolveEventHubsRecord(
  record: EventHubsRecord,
  index: number,
  config: Pick<EventHubsSinkConfig, "eventHubName" | "partitionKey">
): EventHubsResolvedRecord {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`eventhubs-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  const eventHubName = resolveEventHubsHub(record, config);
  if (eventHubName === undefined) {
    throw new RangeError(
      `eventhubs-sink: record ${index} has no hub source (configure \`eventHubName\` or set \`subject\`, \`key\`, or \`traceId\`)`
    );
  }
  const resolved: EventHubsResolvedRecord = {
    eventHubName,
    body: record.body,
    properties: resolveEventHubsProperties(record),
    index,
  };
  const partitionKey = resolveEventHubsPartitionKey(record, config);
  if (partitionKey !== undefined) {
    resolved.partitionKey = partitionKey;
  }
  return resolved;
}

/**
 * Event Hubs error codes that are transient — throttling,
 * server busy, service unavailability, operation timeouts,
 * internal errors — and so retryable under the WR-210 mapping.
 * A throttling failure is retryable: it says Event Hubs could
 * not accept the batch right now, not that the payload is
 * poison. A codeless transport failure is carried as
 * `TRANSPORT_ERROR` and is retryable too: like an SQS transport
 * error with no status, it says nothing about the payload. Any
 * code not listed here is a fail-closed message (permission
 * denied, unknown hub, malformed event) and is non-retryable:
 * retrying it burns the retry budget for nothing, and rerouting
 * it elsewhere would break the streaming contract.
 */
const EVENTHUBS_RETRYABLE_ERROR_CODES = new Set([
  "TRANSPORT_ERROR",
  "ThrottlingError",
  "Throttling",
  "TooManyRequests",
  "ServerBusyError",
  "ServerBusy",
  "ServiceBusy",
  "ServiceUnavailable",
  "ServiceUnavailableError",
  "OperationTimeout",
  "TimeoutError",
  "Timeout",
  "InternalError",
  "InternalServerError",
]);

/**
 * Map one Event Hubs sendBatch `errorCode` onto its retry lane
 * under the WR-210 rules: transient Event Hubs states
 * (including throttling and server busy) are retryable, any
 * other code is a fail-closed message, like any other 4xx.
 */
export function classifyEventHubsRecordFailure(errorCode: string): boolean {
  return EVENTHUBS_RETRYABLE_ERROR_CODES.has(errorCode);
}

/**
 * Event Hubs sink (WR-225). One instance targets one event hub
 * (or resolves hubs per event when none is configured); the
 * caller owns retry/dead-letter policy around `sendBatch()` —
 * this class performs one sendBatch attempt per hub through the
 * injected client and reports its outcome. Failures throw
 * `EventHubsSinkError` carrying exactly the failed events with
 * their retry lanes.
 */
export class EventHubsSink {
  private readonly cfg: EventHubsSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendBatchFailures = 0;

  constructor(config: EventHubsSinkConfig) {
    assertValidEventHubsSinkConfig(config, "EventHubsSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): EventHubsSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendBatchFailures: this.sendBatchFailures,
    };
  }

  /**
   * Send events to the configured event hub in a single batch
   * (or one batch per resolved hub when none is configured),
   * preserving input order within each batch. Throws
   * `EventHubsSinkConfigError` when no client was injected, and
   * `EventHubsSinkError` when any batch fails (carrying exactly
   * the failed events with their retry lanes; both counted in
   * stats before throwing, so the counters stay honest even for
   * callers that only inspect stats).
   */
  async sendBatch(records: EventHubsRecord[]): Promise<EventHubsSendResult> {
    const resolved = records.map((r, i) => resolveEventHubsRecord(r, i, this.cfg));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a hub-less event before it reaches production — but
      // perform zero client I/O and touch no stats.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new EventHubsSinkConfigError("no client injected (set `client` in the sink config)");
    }
    // Group by hub, preserving first-appearance order of hubs
    // and input order within each hub. A configured sink always
    // yields exactly one group.
    const groups = new Map<string, EventHubsResolvedRecord[]>();
    for (const record of resolved) {
      const group = groups.get(record.eventHubName);
      if (group === undefined) {
        groups.set(record.eventHubName, [record]);
      } else {
        group.push(record);
      }
    }
    const failedRecords: EventHubsFailedRecord[] = [];
    let sent = 0;
    for (const [eventHubName, group] of groups) {
      try {
        await client.sendBatch({
          eventHubName,
          events: group.map((record) => ({
            body: record.body,
            properties: record.properties,
            ...(record.partitionKey !== undefined ? { partitionKey: record.partitionKey } : {}),
          })),
        });
      } catch (err) {
        for (const record of group) {
          failedRecords.push(toEventHubsFailedRecord(err, record.index));
        }
        continue;
      }
      sent += group.length;
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendBatchFailures += 1;
      // Report in input order, not batch order, so the caller
      // retries exactly the failed events in their original
      // sequence.
      failedRecords.sort((a, b) => a.index - b.index);
      throw new EventHubsSinkError(
        `eventhubs-sink: sendBatch failed for ${failedRecords.length} of ${resolved.length} events`,
        failedRecords
      );
    }
    return { ok: true, sent };
  }
}

/**
 * Convert a client throw into a failed event: an
 * `EventHubsSendError` maps by its code, any other error is a
 * codeless transport failure (`TRANSPORT_ERROR`, retryable —
 * the SQS no-status rule).
 */
function toEventHubsFailedRecord(err: unknown, index: number): EventHubsFailedRecord {
  if (err instanceof EventHubsSendError) {
    const failed: EventHubsFailedRecord = {
      index,
      errorCode: err.errorCode,
      retryable: classifyEventHubsRecordFailure(err.errorCode),
    };
    if (err.message !== "") failed.errorMessage = err.message;
    return failed;
  }
  const failed: EventHubsFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
