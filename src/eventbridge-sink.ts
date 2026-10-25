/**
 * AWS EventBridge delivery sink (WR-222).
 *
 * Some downstreams are not HTTP endpoints at all: they are
 * EventBridge event buses. Where the SQS sink (WR-210) delivers
 * to an unordered queue, the Kinesis sink (WR-213) delivers to an
 * AWS SigV4 stream, the Kafka sink (WR-215) delivers to a
 * partitioned log, the MQTT sink (WR-216) delivers to a pub/sub
 * topic tree, the AMQP sink (WR-217) delivers to an exchange,
 * the JetStream sink (WR-218) delivers to a durable stream over
 * the native JetStream publish protocol, the Redis sink (WR-219)
 * delivers to a Redis stream with XADD, the Pub/Sub sink
 * (WR-220) delivers to a Google Cloud topic with pass-through
 * attributes, and the Service Bus sink (WR-221) delivers to an
 * Azure queue or topic with pass-through properties, this sink
 * delivers to an AWS EventBridge event bus: one event is sent as
 * one PutEvents entry, and EventBridge — not the relay — owns
 * routing to rules, retries to targets, and archiving. The sinks
 * are orthogonal — queue delivery for unordered work, stream
 * delivery for AWS-ordered work, log delivery for broker-native
 * ordered work, topic-tree delivery for broker-mediated fan-out,
 * exchange delivery for broker-mediated routing, durable-stream
 * delivery for replayable work, Redis-stream delivery for
 * in-memory ordered work, Pub/Sub delivery for cloud-managed
 * fan-out, Service Bus delivery for Azure-managed fan-out,
 * EventBridge delivery for rule-routed cloud events — and an
 * EventBridge delivery can still be archived by the S3 offloaders
 * like any other delivery.
 *
 * No real EventBridge client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever client
 * the operator runs — the AWS SDK, a sidecar), so the module has
 * zero new dependencies and tests never need an AWS account. The
 * sink owns the relay-side concerns — bus targeting, DetailType
 * resolution, trace-id pass-through, per-message failure mapping
 * — and the injected client owns the wire protocol, including
 * the PutEvents call. The client adapter also owns the entry's
 * `Source`: EventBridge requires one, but the relay invents no
 * source value — the operator's adapter supplies the source its
 * rules match on, and a relay that invented a source would route
 * events to rules nobody configured.
 *
 * Wire shape — one PutEvents entry per message, carried to the
 * injected client as:
 *
 *   { eventBusName: "<bus>", detailType: "<DetailType>",
 *     detail: "<event JSON>", traceId: "<traceId>" }
 *
 * Detail — the event JSON, fixed and verbatim: the sink never
 * templates, wraps, or rewrites it. Rules match on DetailType and
 * on the detail's own content, so any relay-side reshaping would
 * break the consumer's match. The trace id rides as an entry
 * field alongside Detail (the same pass-through role properties
 * play in the Service Bus sink), present only when the record
 * carries one — the sink never invents a trace id, and Detail
 * itself stays untouched.
 *
 * DetailType — resolved per record from the event's own values,
 * first non-empty wins: `subject`, then `key`, then `traceId`.
 * A record with none of the three has no DetailType source and
 * fails closed with a `RangeError` at resolve time: inventing a
 * DetailType would route the event to rules that never asked for
 * it, and silently dropping it would lose the event. The same
 * value may serve twice — a trace id used as the DetailType is
 * still passed through as the entry's trace id, because both
 * fields carry the record's own value, not an invention.
 *
 * Failure handling mirrors the WR-210 SQS sink's classification
 * (`src/failure.ts`), applied per message:
 *
 * - a per-message PutEvents failure throws
 *   `EventBridgeSinkError` carrying every failed message with
 *   its retry lane already mapped, so the caller retries exactly
 *   the failed messages;
 * - retryable codes are the transient EventBridge states —
 *   throttling, quota exhaustion, and internal errors, plus
 *   codeless transport failures: a throttling failure says
 *   EventBridge could not accept the entry right now, not that
 *   the payload is poison;
 * - non-retryable codes are the fail-closed messages —
 *   permission denied, unknown bus, malformed detail: retrying
 *   them burns the retry budget for nothing, and rerouting them
 *   elsewhere would break the rule-routing contract the
 *   consumers depend on;
 * - a missing client or a missing event bus throws
 *   `EventBridgeSinkConfigError`, which `classifyFailure` maps
 *   to `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Event-bus-name cap: EventBridge bus names are short operator strings. */
export const EVENTBRIDGE_BUS_MAX = 256;

/**
 * One PutEvents entry as handed to the injected client. The client
 * owns the wire protocol (including the `Source` the operator's
 * rules match on, which the relay never invents); this shape is
 * the relay-side contract it must honour.
 */
export interface EventBridgePutEventsEntry {
  /** Target event bus (the sink's configured bus). */
  eventBusName: string;
  /** DetailType, resolved from the record's subject, key, or trace id. */
  detailType: string;
  /** The event JSON, verbatim. */
  detail: string;
  /**
   * Trace id, present only when the record carried one — the sink
   * never invents a trace id, and Detail itself stays untouched.
   */
  traceId?: string;
}

/**
 * The injected EventBridge client. Any client adapter implements
 * this one method; per-message failures throw
 * `EventBridgePutError` (or any error, which the sink treats as a
 * transport failure). The client is expected to send one entry
 * per call. It returns nothing: the relay reports acceptance
 * itself and invents no PutEvents result id.
 */
export interface EventBridgeClient {
  putEvents(entry: EventBridgePutEventsEntry): Promise<void>;
}

/**
 * Configuration for one EventBridge sink. The client is injected:
 * without one, `putEvents()` throws `EventBridgeSinkConfigError`
 * (dry runs excepted — they need no client at all). Without an
 * event bus, `putEvents()` likewise throws
 * `EventBridgeSinkConfigError`: a missing bus is a config
 * problem, not a silent no-op.
 */
export interface EventBridgeSinkConfig {
  /**
   * Target event bus, e.g. `events`. Required for real sends; a
   * missing bus is a config error at send time. When set, it
   * must be 1–256 characters, free of NUL and whitespace. One
   * sink targets one bus only.
   */
  eventBusName?: string;
  /**
   * The EventBridge client to deliver through. Injected, never
   * bundled: the operator's client adapter (AWS SDK, sidecar)
   * implements `EventBridgeClient`. Required for real sends; a
   * missing client is a config error, not a silent no-op.
   */
  client?: EventBridgeClient;
  /**
   * Rehearsal mode: `putEvents()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no PutEvents call, no stat changes. Records
   * are still validated (including DetailType resolution), so a
   * dry run catches a sourceless record before it reaches
   * production. Mirrors the `dryRun` convention of the S3
   * offloaders.
   */
  dryRun?: boolean;
}

/** One event to send to the bus. */
export interface EventBridgeRecord {
  /** The event JSON, already serialized by the caller — stored verbatim as Detail. */
  body: string;
  /**
   * DetailType source, first priority: the event's subject, when
   * set and non-empty. Falls through to `key`, then `traceId`
   * when absent — never invented.
   */
  subject?: string;
  /**
   * DetailType source, second priority: the event's key (e.g.
   * aggregate id), when no subject is set. Also the trace id's
   * fallback is not this field — see `traceId`.
   */
  key?: string;
  /**
   * DetailType source, last priority: the trace id, when neither
   * subject nor key is set. Also passed through verbatim as the
   * entry's trace id when set, absent otherwise — the sink never
   * invents a trace id.
   */
  traceId?: string;
}

/** One record as it goes to the client (DetailType resolved, trace id passed through). */
export interface EventBridgeResolvedRecord {
  /** The event JSON, verbatim. */
  detail: string;
  /** DetailType, resolved from subject, key, or trace id. */
  detailType: string;
  /** Trace id, present only when the record carried one. */
  traceId?: string;
}

/** One failed message, with its retry lane already mapped. */
export interface EventBridgeFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /** EventBridge error code, or `TRANSPORT_ERROR` for a codeless failure. */
  errorCode: string;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: transient EventBridge
   * states (including throttling and quota exhaustion) are
   * retryable, fail-closed messages (permission, unknown bus,
   * malformed detail) are not.
   */
  retryable: boolean;
}

/** Outcome of one `putEvents()` call (failures throw, see above). */
export interface EventBridgePutEventsResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-222). */
export interface EventBridgeSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** Send calls that threw (counted before the error is thrown). */
  putFailures: number;
}

/**
 * Thrown when a send throws per message: an EventBridge-side or
 * transport failure mapped onto the EventBridge error code.
 * Carries the codeless transport case as `TRANSPORT_ERROR`, and
 * every failed message with its retry lane, so the caller retries
 * exactly the failed messages without parsing message strings.
 */
export class EventBridgePutError extends Error {
  /** EventBridge error code (e.g. `ThrottlingException`). */
  readonly errorCode: string;
  constructor(errorCode: string, message?: string) {
    super(message ?? `eventbridge-sink: putEvents failed (${errorCode})`);
    this.name = "EventBridgePutError";
    this.errorCode = errorCode;
  }
}

/**
 * Thrown for EventBridge send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already in their bus and are *not* in `failedRecords`.
 */
export class EventBridgeSinkError extends Error {
  /** Per-message failures, in input order, each with its retry lane. */
  readonly failedRecords: EventBridgeFailedRecord[];
  constructor(message: string, failedRecords: EventBridgeFailedRecord[]) {
    super(message);
    this.name = "EventBridgeSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no client
 * was injected, or no event bus was configured. A config
 * problem, not a downstream verdict, so the retry queue must not
 * burn attempts on it (`classifyFailure` maps it to
 * `non_retryable`).
 */
export class EventBridgeSinkConfigError extends EventBridgeSinkError {
  constructor(reason: string) {
    super(`eventbridge-sink: ${reason}`, []);
    this.name = "EventBridgeSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing event bus is *not* a shape error: it is a config error
 * at send time (`EventBridgeSinkConfigError`), so a sink built
 * before its bus is known still fails closed rather than
 * crashing at construction.
 */
export function assertValidEventBridgeSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is EventBridgeSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  if (c.eventBusName !== undefined) {
    if (
      typeof c.eventBusName !== "string" ||
      c.eventBusName === "" ||
      c.eventBusName.length > EVENTBRIDGE_BUS_MAX ||
      c.eventBusName.includes("\0") ||
      /\s/.test(c.eventBusName)
    ) {
      throw new RangeError(
        at("`eventBusName` must be 1–256 characters, free of NUL and whitespace when set")
      );
    }
  }
  if (
    c.client !== undefined &&
    (c.client === null ||
      typeof c.client !== "object" ||
      typeof (c.client as { putEvents?: unknown }).putEvents !== "function")
  ) {
    throw new RangeError(at("`client` must expose a `putEvents` function when set"));
  }
}

/**
 * Resolve one record's DetailType: the first non-empty value
 * among `subject`, `key`, and `traceId`, in that order. Returns
 * `undefined` when the record carries none of the three — the
 * caller fails closed rather than inventing a DetailType.
 */
export function resolveEventBridgeDetailType(
  record: EventBridgeRecord
): string | undefined {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return undefined;
}

/**
 * Validate one record's body and resolve its send form: Detail
 * is the body verbatim, DetailType resolves from subject, key,
 * or trace id, and the trace id passes through when present.
 * Throws `RangeError` on an empty body string, and on a record
 * with no DetailType source — a sourceless record fails closed,
 * never with an invented DetailType.
 */
export function resolveEventBridgeRecord(
  record: EventBridgeRecord,
  index: number
): EventBridgeResolvedRecord {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`eventbridge-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  const detailType = resolveEventBridgeDetailType(record);
  if (detailType === undefined) {
    throw new RangeError(
      `eventbridge-sink: record ${index} has no DetailType source (set \`subject\`, \`key\`, or \`traceId\`)`
    );
  }
  const resolved: EventBridgeResolvedRecord = {
    detail: record.body,
    detailType,
  };
  if (record.traceId !== undefined && record.traceId !== "") {
    resolved.traceId = record.traceId;
  }
  return resolved;
}

/**
 * EventBridge error codes that are transient — throttling, quota
 * exhaustion, internal errors — and so retryable under the
 * WR-210 mapping. A throttling failure is retryable: it says
 * EventBridge could not accept the entry right now, not that the
 * payload is poison. A codeless transport failure is carried as
 * `TRANSPORT_ERROR` and is retryable too: like an SQS transport
 * error with no status, it says nothing about the payload. Any
 * code not listed here is a fail-closed message (permission
 * denied, unknown bus, malformed detail) and is non-retryable:
 * retrying it burns the retry budget for nothing, and rerouting
 * it elsewhere would break the rule-routing contract.
 */
const EVENTBRIDGE_RETRYABLE_ERROR_CODES = new Set([
  "TRANSPORT_ERROR",
  "ThrottlingException",
  "TooManyRequestsException",
  "LimitExceededException",
  "InternalError",
]);

/**
 * Map one EventBridge PutEvents `errorCode` onto its retry lane
 * under the WR-210 rules: transient EventBridge states
 * (including throttling and quota exhaustion) are retryable,
 * any other code is a fail-closed message, like any other 4xx.
 */
export function classifyEventBridgeRecordFailure(errorCode: string): boolean {
  return EVENTBRIDGE_RETRYABLE_ERROR_CODES.has(errorCode);
}

/**
 * EventBridge sink (WR-222). One instance targets one bus; the
 * caller owns retry/dead-letter policy around `putEvents()` —
 * this class performs one send attempt per message through the
 * injected client and reports its outcome. Failures throw
 * `EventBridgeSinkError` carrying exactly the failed messages
 * with their retry lanes.
 */
export class EventBridgeSink {
  private readonly cfg: EventBridgeSinkConfig;
  private sent = 0;
  private failed = 0;
  private putFailures = 0;

  constructor(config: EventBridgeSinkConfig) {
    assertValidEventBridgeSinkConfig(config, "EventBridgeSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): EventBridgeSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      putFailures: this.putFailures,
    };
  }

  /**
   * Send messages to the configured bus, in input order. Throws
   * `EventBridgeSinkConfigError` when no client was injected or
   * no bus was configured, and `EventBridgeSinkError` when any
   * message fails (carrying exactly the failed messages with
   * their retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only inspect
   * stats).
   */
  async putEvents(records: EventBridgeRecord[]): Promise<EventBridgePutEventsResult> {
    const resolved = records.map((r, i) => resolveEventBridgeRecord(r, i));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches a
      // sourceless record before it reaches production — but
      // perform zero client I/O and touch no stats.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new EventBridgeSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const eventBusName = this.cfg.eventBusName;
    if (eventBusName === undefined) {
      throw new EventBridgeSinkConfigError("no event bus configured (set `eventBusName` in the sink config)");
    }
    const failedRecords: EventBridgeFailedRecord[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i] as EventBridgeResolvedRecord;
      try {
        await client.putEvents({
          eventBusName,
          detailType: record.detailType,
          detail: record.detail,
          ...(record.traceId !== undefined ? { traceId: record.traceId } : {}),
        });
      } catch (err) {
        failedRecords.push(toEventBridgeFailedRecord(err, i));
        continue;
      }
      sent += 1;
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.putFailures += 1;
      throw new EventBridgeSinkError(
        `eventbridge-sink: putEvents ${eventBusName} failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent };
  }
}

/**
 * Convert a client throw into a failed message: an
 * `EventBridgePutError` maps by its code, any other error is a
 * codeless transport failure (`TRANSPORT_ERROR`, retryable — the
 * SQS no-status rule).
 */
function toEventBridgeFailedRecord(err: unknown, index: number): EventBridgeFailedRecord {
  if (err instanceof EventBridgePutError) {
    const failed: EventBridgeFailedRecord = {
      index,
      errorCode: err.errorCode,
      retryable: classifyEventBridgeRecordFailure(err.errorCode),
    };
    if (err.message !== "") failed.errorMessage = err.message;
    return failed;
  }
  const failed: EventBridgeFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
