/**
 * Azure Service Bus delivery sink (WR-221).
 *
 * Some downstreams are not HTTP endpoints at all: they are Service
 * Bus entities. Where the SQS sink (WR-210) delivers to an unordered
 * queue, the Kinesis sink (WR-213) delivers to an AWS SigV4 stream,
 * the Kafka sink (WR-215) delivers to a partitioned log, the MQTT
 * sink (WR-216) delivers to a pub/sub topic tree, the AMQP sink
 * (WR-217) delivers to an exchange, the JetStream sink (WR-218)
 * delivers to a durable stream over the native JetStream publish
 * protocol, the Redis sink (WR-219) delivers to a Redis stream
 * with XADD, and the Pub/Sub sink (WR-220) delivers to a Google
 * Cloud topic with pass-through attributes, this sink delivers to
 * an Azure Service Bus queue or topic: one event is sent as one
 * message, and Service Bus — not the relay — owns the message id,
 * the entity's retention, and fan-out to subscriptions. The sinks
 * are orthogonal — queue delivery for unordered work, stream
 * delivery for AWS-ordered work, log delivery for broker-native
 * ordered work, topic-tree delivery for broker-mediated fan-out,
 * exchange delivery for broker-mediated routing, durable-stream
 * delivery for replayable work, Redis-stream delivery for
 * in-memory ordered work, Pub/Sub delivery for cloud-managed
 * fan-out, Service Bus delivery for Azure-managed fan-out — and a
 * Service Bus delivery can still be archived by the S3 offloaders
 * like any other delivery.
 *
 * No real Service Bus client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever client the
 * operator runs — @azure/service-bus, a sidecar), so the module
 * has zero new dependencies and tests never need an Azure
 * namespace. The sink owns the relay-side concerns — entity
 * targeting, property pass-through, session-id opt-in, per-message
 * failure mapping — and the injected client owns the wire
 * protocol, including the send call. Service Bus send does not
 * return a message id (the id is client-set, never relay-set), so
 * the injected client's `send` returns nothing and the relay
 * invents no id.
 *
 * Wire shape — one send request per message, carried to the
 * injected client as:
 *
 *   { entity: "<queue-or-topic>", body: "<event JSON>",
 *     properties: { tenant: "<tenant>", endpoint: "<endpoint>",
 *       "trace-id": "<traceId>" },
 *     sessionId: "<event key>" }
 *
 * Entity targeting — one sink targets one entity: either a queue
 * (`queue`) or a topic (`topic`), never both (both set is a
 * shape error at construction). When the target is a topic, the
 * relay only publishes to it: subscriptions are built and owned
 * downstream, never created by the relay — a publish-only sink
 * must not invent subscriber state.
 *
 * Properties — a message's application properties pass through the
 * record's own tenant, endpoint, and trace id, never invented: a
 * property is present only when the record carries that value, so
 * a subscriber can filter or correlate without opening the body.
 * The trace id rides as `trace-id`, the same property name the
 * Pub/Sub sink uses for its attribute, so a consumer reading both
 * sinks sees one correlation key. A record with none of the three
 * carries an empty properties object — the sink never invents a
 * tenant, an endpoint, or a trace id.
 *
 * Session ids — opt-in, and only effective when the entity has
 * sessions enabled. When `sessionId` is set and the entity is
 * declared session-enabled (`sessionEnabled`), a record's event
 * `key` becomes the message's session id, so messages sharing a
 * key are delivered in send order to one session receiver. When
 * either flag is absent, or the record has no key, no session id
 * is attached: the session id is ignored, not defaulted, because
 * sending a session id to an entity without sessions enabled is
 * a send error, and inventing a session would silently serialize
 * unrelated events. The operator enables both flags together only
 * for entities created with sessions enabled.
 *
 * Failure handling mirrors the WR-210 SQS sink's classification
 * (`src/failure.ts`), applied per message:
 *
 * - a per-message send failure throws `ServiceBusSinkError`
 *   carrying every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed messages;
 * - retryable codes are the transient Service Bus states — quota
 *   exhaustion, server busy, operation timeouts, and codeless
 *   transport failures: a quota failure says Service Bus could
 *   not accept the message right now, not that the payload is
 *   poison;
 * - non-retryable codes are the fail-closed messages — permission
 *   denied, unknown entity, disabled entity, malformed message:
 *   retrying them burns the retry budget for nothing, and
 *   rerouting them elsewhere would break the fan-out contract
 *   the subscribers depend on;
 * - a missing client or a missing entity throws
 *   `ServiceBusSinkConfigError`, which `classifyFailure` maps to
 *   `non_retryable` (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Entity-name cap: Service Bus queue/topic names are short operator strings. */
export const SERVICEBUS_ENTITY_MAX = 260;

/** Message property carrying the record's tenant, verbatim. */
export const SERVICEBUS_TENANT_PROPERTY = "tenant";

/** Message property carrying the record's endpoint, verbatim. */
export const SERVICEBUS_ENDPOINT_PROPERTY = "endpoint";

/** Message property carrying the record's trace id, verbatim. */
export const SERVICEBUS_TRACE_ID_PROPERTY = "trace-id";

/**
 * One send request as handed to the injected client. The client
 * owns the wire protocol; this shape is the relay-side contract it
 * must honour. The send returns no id: Service Bus send does not
 * return one, and the relay never invents a message id.
 */
export interface ServiceBusSendRequest {
  /** Target entity (the sink's configured queue or topic). */
  entity: string;
  /** The event JSON, verbatim. */
  body: string;
  /**
   * Pass-through application properties: `tenant`, `endpoint`,
   * and `trace-id`, each present only when the record carried that
   * value — the sink never invents a property.
   */
  properties: Record<string, string>;
  /**
   * Session id, present only when the sink opted into sessions,
   * the entity is session-enabled, and the record has a key.
   */
  sessionId?: string;
}

/**
 * The injected Service Bus client. Any client adapter implements
 * this one method; per-message failures throw `ServiceBusSendError`
 * (or any error, which the sink treats as a transport failure).
 * The client is expected to send one message per call. It returns
 * nothing: Service Bus send carries no return id to report.
 */
export interface ServiceBusClient {
  send(request: ServiceBusSendRequest): Promise<void>;
}

/**
 * Configuration for one Service Bus sink. The client is injected:
 * without one, `send()` throws `ServiceBusSinkConfigError` (dry
 * runs excepted — they need no client at all). Without an entity,
 * `send()` likewise throws `ServiceBusSinkConfigError`: a missing
 * entity is a config problem, not a silent no-op.
 */
export interface ServiceBusSinkConfig {
  /**
   * Target queue, e.g. `events`. Required for real sends unless
   * `topic` is set; a missing entity is a config error at send
   * time. When set, it must be 1–260 characters, free of NUL and
   * whitespace, and mutually exclusive with `topic`. One sink
   * targets one entity only.
   */
  queue?: string;
  /**
   * Target topic, e.g. `events`. Required for real sends unless
   * `queue` is set; a missing entity is a config error at send
   * time. When set, it must be 1–260 characters, free of NUL and
   * whitespace, and mutually exclusive with `queue`. The relay
   * only publishes to the topic: subscriptions are built and
   * owned downstream, never created by the relay.
   */
  topic?: string;
  /**
   * The Service Bus client to deliver through. Injected, never
   * bundled: the operator's client adapter (@azure/service-bus,
   * sidecar) implements `ServiceBusClient`. Required for real
   * sends; a missing client is a config error, not a silent no-op.
   */
  client?: ServiceBusClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero client
   * I/O — no send call, no stat changes. Records are still
   * validated, so a dry run catches a malformed record before it
   * reaches production. Mirrors the `dryRun` convention of the S3
   * offloaders.
   */
  dryRun?: boolean;
  /**
   * Session-id opt-in: when `true` and the entity is
   * session-enabled (see `sessionEnabled`), a record's event
   * `key` becomes the message's session id. When `false` or
   * absent, no session id is ever attached.
   */
  sessionId?: boolean;
  /**
   * Declares that the configured entity was created with sessions
   * enabled. The session id is attached only when both this and
   * `sessionId` are set: sending a session id to an entity
   * without sessions enabled is a send error, so the sink ignores
   * the key rather than failing the message.
   */
  sessionEnabled?: boolean;
}

/** One event to send to the entity. */
export interface ServiceBusRecord {
  /** The event JSON, already serialized by the caller — stored verbatim. */
  body: string;
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
  /**
   * Trace id: passed through verbatim as the `trace-id` message
   * property when set, absent otherwise — the sink never invents
   * a trace id.
   */
  traceId?: string;
  /**
   * Event key (e.g. aggregate id): the session-id source when the
   * sink opted into sessions and the entity is session-enabled.
   * Events sharing a key are delivered in send order to one
   * session receiver.
   */
  key?: string;
}

/** One record as it goes to the client (properties built, session id resolved). */
export interface ServiceBusResolvedRecord {
  /** The event JSON, verbatim. */
  body: string;
  /** Pass-through properties (only the record's own values). */
  properties: Record<string, string>;
  /** Session id, present only under the session opt-in (see above). */
  sessionId?: string;
}

/** One failed message, with its retry lane already mapped. */
export interface ServiceBusFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /** Service Bus error code, or `TRANSPORT_ERROR` for a codeless failure. */
  errorCode: string;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: transient Service Bus
   * states (including quota exhaustion and server busy) are
   * retryable, fail-closed messages (permission, unknown entity,
   * malformed message) are not.
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface ServiceBusSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-221). */
export interface ServiceBusSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** Send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown when a send throws per message: a Service Bus-side or
 * transport failure mapped onto the Service Bus error code.
 * Carries the codeless transport case as `TRANSPORT_ERROR`, and
 * every failed message with its retry lane, so the caller retries
 * exactly the failed messages without parsing message strings.
 */
export class ServiceBusSendError extends Error {
  /** Service Bus error code (e.g. `ServiceBusy`). */
  readonly errorCode: string;
  constructor(errorCode: string, message?: string) {
    super(message ?? `servicebus-sink: send failed (${errorCode})`);
    this.name = "ServiceBusSendError";
    this.errorCode = errorCode;
  }
}

/**
 * Thrown for Service Bus send failures. Carries every failed message
 * with its retry lane (`failedRecords`), so the retry queue can
 * requeue exactly those messages. A send call that throws has
 * partial success behind it — the accepted messages are already in
 * their entity and are *not* in `failedRecords`.
 */
export class ServiceBusSinkError extends Error {
  /** Per-message failures, in input order, each with its retry lane. */
  readonly failedRecords: ServiceBusFailedRecord[];
  constructor(message: string, failedRecords: ServiceBusFailedRecord[]) {
    super(message);
    this.name = "ServiceBusSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no client
 * was injected, no entity was configured, or both a queue and a
 * topic were configured (the last is a shape error at
 * construction; the first two fail at send time). A config
 * problem, not a downstream verdict, so the retry queue must not
 * burn attempts on it (`classifyFailure` maps it to
 * `non_retryable`).
 */
export class ServiceBusSinkConfigError extends ServiceBusSinkError {
  constructor(reason: string) {
    super(`servicebus-sink: ${reason}`, []);
    this.name = "ServiceBusSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing entity is *not* a shape error: it is a config error at
 * send time (`ServiceBusSinkConfigError`), so a sink built before
 * its entity is known still fails closed rather than crashing at
 * construction. Setting both a queue and a topic *is* a shape
 * error: one sink targets one entity, and two targets would make
 * every send ambiguous.
 */
export function assertValidServiceBusSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is ServiceBusSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  for (const field of ["queue", "topic"] as const) {
    const value = c[field];
    if (value !== undefined) {
      if (
        typeof value !== "string" ||
        value === "" ||
        value.length > SERVICEBUS_ENTITY_MAX ||
        value.includes("\0") ||
        /\s/.test(value)
      ) {
        throw new RangeError(
          at(
            `\`${field}\` must be 1–260 characters, free of NUL and whitespace when set`
          )
        );
      }
    }
  }
  if (c.queue !== undefined && c.topic !== undefined) {
    throw new RangeError(at("at most one of `queue` and `topic` may be set"));
  }
  if (
    c.client !== undefined &&
    (c.client === null ||
      typeof c.client !== "object" ||
      typeof (c.client as { send?: unknown }).send !== "function")
  ) {
    throw new RangeError(at("`client` must expose a `send` function when set"));
  }
}

/**
 * Build one record's pass-through properties: `tenant`,
 * `endpoint`, and `trace-id`, each present only when the record
 * carries a non-empty value for it — the sink never invents a
 * property.
 */
export function resolveServiceBusProperties(
  record: ServiceBusRecord
): Record<string, string> {
  const properties: Record<string, string> = {};
  if (record.tenant !== undefined && record.tenant !== "") {
    properties[SERVICEBUS_TENANT_PROPERTY] = record.tenant;
  }
  if (record.endpoint !== undefined && record.endpoint !== "") {
    properties[SERVICEBUS_ENDPOINT_PROPERTY] = record.endpoint;
  }
  if (record.traceId !== undefined && record.traceId !== "") {
    properties[SERVICEBUS_TRACE_ID_PROPERTY] = record.traceId;
  }
  return properties;
}

/**
 * Resolve one record's session id: the record's event `key`,
 * but only when the sink opted into sessions (`sessionId`) and
 * the entity is session-enabled (`sessionEnabled`). Any other
 * combination — including a key on a non-session entity — yields
 * no session id: the key is ignored, not defaulted, because
 * sending a session id to an entity without sessions enabled is
 * a send error.
 */
export function resolveServiceBusSessionId(
  record: ServiceBusRecord,
  config: Pick<ServiceBusSinkConfig, "sessionId" | "sessionEnabled">
): string | undefined {
  if (config.sessionId !== true || config.sessionEnabled !== true) {
    return undefined;
  }
  if (record.key === undefined || record.key === "") {
    return undefined;
  }
  return record.key;
}

/**
 * Validate one record's body and resolve its send form: the
 * properties pass through verbatim, and the session id resolves
 * under the session opt-in. Throws `RangeError` on an empty body
 * string.
 */
export function resolveServiceBusRecord(
  record: ServiceBusRecord,
  index: number,
  config: Pick<ServiceBusSinkConfig, "sessionId" | "sessionEnabled">
): ServiceBusResolvedRecord {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`servicebus-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  const resolved: ServiceBusResolvedRecord = {
    body: record.body,
    properties: resolveServiceBusProperties(record),
  };
  const sessionId = resolveServiceBusSessionId(record, config);
  if (sessionId !== undefined) {
    resolved.sessionId = sessionId;
  }
  return resolved;
}

/**
 * Service Bus error codes that are transient — quota exhaustion,
 * server busy, operation timeouts — and so retryable under the
 * WR-210 mapping. A quota failure is retryable: it says Service
 * Bus could not accept the message right now, not that the
 * payload is poison. A codeless transport failure is carried as
 * `TRANSPORT_ERROR` and is retryable too: like an SQS transport
 * error with no status, it says nothing about the payload. Any
 * code not listed here is a fail-closed message (permission
 * denied, unknown entity, disabled entity, malformed message)
 * and is non-retryable: retrying it burns the retry budget for
 * nothing, and rerouting it elsewhere would break the fan-out
 * contract.
 */
const SERVICEBUS_RETRYABLE_ERROR_CODES = new Set([
  "TRANSPORT_ERROR",
  "QuotaExceeded",
  "ServiceBusy",
  "OperationTimeout",
]);

/**
 * Map one Service Bus send `errorCode` onto its retry lane under
 * the WR-210 rules: transient Service Bus states (including
 * quota exhaustion and server busy) are retryable, any other code
 * is a fail-closed message, like any other 4xx.
 */
export function classifyServiceBusRecordFailure(errorCode: string): boolean {
  return SERVICEBUS_RETRYABLE_ERROR_CODES.has(errorCode);
}

/**
 * Service Bus sink (WR-221). One instance targets one entity; the
 * caller owns retry/dead-letter policy around `send()` — this
 * class performs one send attempt per message through the
 * injected client and reports its outcome. Failures throw
 * `ServiceBusSinkError` carrying exactly the failed messages with
 * their retry lanes.
 */
export class ServiceBusSink {
  private readonly cfg: ServiceBusSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: ServiceBusSinkConfig) {
    assertValidServiceBusSinkConfig(config, "ServiceBusSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): ServiceBusSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send messages to the configured entity, in input order.
   * Throws `ServiceBusSinkConfigError` when no client was
   * injected or no entity was configured, and
   * `ServiceBusSinkError` when any message fails (carrying
   * exactly the failed messages with their retry lanes; both
   * counted in stats before throwing, so the counters stay
   * honest even for callers that only inspect stats).
   */
  async send(records: ServiceBusRecord[]): Promise<ServiceBusSendResult> {
    const resolved = records.map((r, i) => resolveServiceBusRecord(r, i, this.cfg));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches a
      // malformed record before it reaches production — but perform
      // zero client I/O and touch no stats.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new ServiceBusSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const entity = this.cfg.queue ?? this.cfg.topic;
    if (entity === undefined) {
      throw new ServiceBusSinkConfigError("no entity configured (set `queue` or `topic` in the sink config)");
    }
    const failedRecords: ServiceBusFailedRecord[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i] as ServiceBusResolvedRecord;
      try {
        await client.send({
          entity,
          body: record.body,
          properties: record.properties,
          ...(record.sessionId !== undefined ? { sessionId: record.sessionId } : {}),
        });
      } catch (err) {
        failedRecords.push(toServiceBusFailedRecord(err, i));
        continue;
      }
      sent += 1;
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new ServiceBusSinkError(
        `servicebus-sink: send ${entity} failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent };
  }
}

/**
 * Convert a client throw into a failed message: a
 * `ServiceBusSendError` maps by its code, any other error is a
 * codeless transport failure (`TRANSPORT_ERROR`, retryable — the
 * SQS no-status rule).
 */
function toServiceBusFailedRecord(err: unknown, index: number): ServiceBusFailedRecord {
  if (err instanceof ServiceBusSendError) {
    const failed: ServiceBusFailedRecord = {
      index,
      errorCode: err.errorCode,
      retryable: classifyServiceBusRecordFailure(err.errorCode),
    };
    if (err.message !== "") failed.errorMessage = err.message;
    return failed;
  }
  const failed: ServiceBusFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
