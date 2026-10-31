/**
 * Airship push notification delivery sink (WR-284).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's device. Where the WonderPush
 * sink (WR-282) delivers push notifications through
 * WonderPush's Management API with a form-encoded body
 * and an `accessToken` form field, and the FCM sink
 * (WR-276) delivers through Firebase with an OAuth
 * Bearer token and a `{message: {token, notification}}`
 * envelope, this sink delivers push notifications
 * through Airship's Push API: one event is sent as one
 * POST, and Airship — not the relay — owns the device
 * routing, the delivery, and the retention of the
 * notification.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need an Airship
 * server. The sink owns the relay-side concerns — message
 * targeting, notification derivation, payload-inclusion
 * policy, per-message failure mapping — and the injected
 * client owns the wire protocol, including the POST call,
 * the authentication, and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://go.urbanairship.com/api/push",
 *     headers: { "Content-Type": "application/json",
 *                "Accept": "application/vnd.urbanairship+json; version=3" },
 *     body: "{\"audience\":\"all\",\"notification\":{\"alert\":\"<alert>\"},\"device_types\":\"all\"}" }
 *
 * The client POSTs to that fixed URL, sending `body`
 * verbatim as the request body (JSON) and `headers`
 * verbatim as the request headers, and authenticating
 * with an `Authorization: Basic` header carrying the
 * base64 of `app key:app secret` — the app key and master
 * secret it alone holds. Four things about this shape
 * are deliberate, and all follow the sibling sinks:
 *
 * - The credentials are held by the client alone. The sink
 *   never receives them, never places them in the request,
 *   and never logs them: like the ClickSend sink (WR-268),
 *   whose username + API key pair the client alone holds,
 *   this sink's handed request carries no credential at
 *   all — the client adds the `Authorization: Basic`
 *   header from the app key and master secret it alone
 *   holds, so there is nothing in the handed request for
 *   a log line or a retry queue to leak. The backlog
 *   item's "配置持有" is the client's configuration, not
 *   the sink's: no credential ever enters the sink
 *   config. This is the opposite of the WonderPush sink
 *   (WR-282), whose access token rides in the form body
 *   because that API authenticates that way: Airship
 *   authenticates by header, so the body carries only
 *   routing and content.
 * - The host is fixed, not configurable: the endpoint
 *   above is Airship's Push API (v3, the current and only
 *   supported version). A configurable URL here could
 *   only misroute a message to a server that is not
 *   Airship. The fixed host is the documented default;
 *   the client adapter owns nothing about the host.
 *   The endpoint, the JSON envelope, and the `Accept`
 *   header match the current Airship documentation
 *   (checked this round, 2026-10-31): `POST
 *   /api/push` with a push object carrying `audience`,
 *   `notification`, and `device_types`, answering `202
 *   Accepted`.
 * - The response carries push ids, not just a status: a
 *   202 returns the created push's `push_ids`, and the
 *   ids are an acceptance receipt only, not a delivery
 *   result (delivery confirmation lives in Airship's
 *   reports, keyed by the `operation_id` the response
 *   also carries). The client surfaces the ids on the
 *   response, and the sink reads them — a 2xx with no
 *   push ids surfaced is retryable, because without the
 *   ids the sink cannot claim the push was created.
 * - The `Accept` header pins API v3: Airship answers
 *   push calls with `application/vnd.urbanairship+json;
 *   version=3`, and the docs send that `Accept` value on
 *   every push call. The sink hands it to the client
 *   verbatim so the wire shape stays exactly the
 *   documented one.
 *
 * Targeting — the `audience` config holds the Push API's
 * audience selector verbatim: either the string `"all"`
 * (a broadcast to the whole audience) or an object with
 * audience selectors (`ios_channel`, `android_channel`,
 * `named_user`, `tag`, `segment`, `channel`, and the
 * rest, combined with `and`/`or`/`not` per the docs).
 * The audience defaults to `"all"`: unlike the
 * WonderPush sink, which invents no default audience
 * because the API refuses a delivery with no target,
 * Airship accepts a broadcast audience, and the backlog
 * item prescribes `"all"` as the default — so a sink
 * with no audience configured still has somewhere to
 * deliver, and never fails closed for a missing audience.
 * The audience is config-held, never derived from the
 * event: one sink targets one Airship audience.
 *
 * This sink is orthogonal to the WonderPush sink
 * (WR-282): WonderPush posts a form-encoded body with
 * the token as the `accessToken` field and a
 * `notification` JSON string carrying an `alert` object
 * with a `title`/`text` split, while Airship posts a
 * JSON body with Basic auth held by the client and a
 * `notification` object carrying a single `alert`
 * string. It is likewise distinct from the FCM sink
 * (WR-276): FCM posts a project-level endpoint with an
 * OAuth Bearer token the client alone holds and a
 * `{message: {token, notification}}` envelope to one
 * device token, while Airship posts the Push API with a
 * Basic header and an `audience`/`notification`/
 * `device_types` envelope to a whole audience. And from
 * the OneSignal sink (WR-275): OneSignal posts an
 * `app_id`/`included_segments` envelope with a bare-key
 * header, while Airship posts an `audience` envelope
 * with Basic auth and a `device_types` field.
 *
 * Message content — a push notification carries one
 * alert string, derived from the event's own values:
 * the first non-empty value among `subject`, `key`, and
 * `traceId`, in that order. There is no title/alert
 * split like the WonderPush sink: the Airship push
 * object carries a single `alert` string, so the subject
 * is what the event is about, the key (e.g. aggregate
 * id) is the next most identifying value, and the trace
 * id names the trace that produced the event. An event
 * with none of the values still notifies, with the
 * generic summary `webhook event`: a notification sink
 * that silently dropped sourceless events would hide
 * exactly the deliveries an operator most needs to see,
 * and the audience — not the content — is the delivery
 * contract here, so no invented target is at stake.
 * `device_types` is fixed to `"all"`: the sink notifies
 * every device type in the audience, per the backlog
 * item — narrowing to `ios`/`android`/`web` is a
 * per-sink deployment choice the item does not ask for,
 * and a fixed `"all"` keeps one sink's contract
 * unambiguous.
 *
 * Payload inclusion — by default the notification
 * carries the summary only, never the full payload:
 * event bodies routinely carry PII, secrets, or
 * customer data, and a device is a far wider audience
 * than a queue or a stream. Opting into `includePayload`
 * appends the body verbatim after a blank line inside
 * `alert`, truncated to `payloadMaxChars` characters
 * (default 2000) with a truncation marker — the opt-in
 * is explicit, and the truncation is unconditional, so
 * even an opted-in body cannot flood a device. The body
 * is appended as plain text inside the `alert` field,
 * not a fenced code block: the field is already plain
 * text, and a fence around an already-JSON body would be
 * noise on a device.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over the HTTP status and, on a 2xx, over the push ids:
 *
 * - a non-2xx POST throws `AirshipSinkError` carrying
 *   every failed message with its retry lane already
 *   mapped, so the caller retries exactly the failed
 *   messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says Airship could
 *   not accept the message right now, not that the
 *   payload is poison;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (unknown audience selector, invalid
 *   body, bad app key): retrying them burns the retry
 *   budget for nothing, and rerouting them elsewhere
 *   would notify devices the operator never chose;
 * - on a 2xx, the push ids decide: surfaced ids mean
 *   Airship accepted the push; a 2xx with no ids
 *   surfaced is retryable — the ids are the acceptance
 *   result, and a missing id means the sink cannot claim
 *   the push was created;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload;
 * - a missing client throws `AirshipSinkConfigError`,
 *   which `classifyFailure` maps to `non_retryable`
 *   (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only.
 */

/** Generic summary used when an event carries no value for the alert field. */
export const AIRSHIP_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const AIRSHIP_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Fixed Airship Push API endpoint for every message. */
export const AIRSHIP_PUSH_URL = "https://go.urbanairship.com/api/push";

/** Content type the client sends with the JSON body. */
export const AIRSHIP_JSON_CONTENT_TYPE = "application/json";

/** Accept header pinning Airship API v3, per the current docs. */
export const AIRSHIP_ACCEPT_HEADER = "application/vnd.urbanairship+json; version=3";

/** Fixed device types for every push: all device types in the audience. */
export const AIRSHIP_DEVICE_TYPES = "all";

/**
 * The push audience for one Airship sink: either the
 * string `"all"` (a broadcast to the whole audience) or
 * an object with audience selectors (`ios_channel`,
 * `android_channel`, `named_user`, `tag`, `segment`,
 * `channel`, combined with `and`/`or`/`not` per the
 * docs). Held by the sink config and passed through
 * verbatim into the JSON body; defaults to `"all"` when
 * the config sets no audience.
 */
export type AirshipAudience = "all" | Record<string, unknown>;

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (JSON) to the fixed Push endpoint,
 * sending `headers` verbatim as the request headers, and
 * authenticating with an `Authorization: Basic` header
 * carrying the base64 of its own `app key:app secret` —
 * which the sink never sees.
 */
export interface AirshipMessagePostRequest {
  /** Always the fixed Airship Push endpoint. */
  url: string;
  /**
   * Request headers, sent verbatim:
   * `{ "Content-Type": "application/json", "Accept": "application/vnd.urbanairship+json; version=3" }`.
   */
  headers: Record<string, string>;
  /**
   * The JSON request body, serialized:
   * `{"audience":<audience>,"notification":{"alert":"<alert>"},"device_types":"all"}`.
   */
  body: string;
}

/**
 * The result of one POST, as reported by the injected client.
 * The HTTP status drives the HTTP retry mapping; on a 2xx
 * the client surfaces the created push's `push_ids`, and
 * the ids — not the status alone — decide whether the push
 * was created. A client that reports a 2xx without ids
 * leaves the sink unable to claim acceptance, so the
 * message is treated as a retryable delivery failure.
 */
export interface AirshipMessagePostResponse {
  /** The HTTP status of the POST (e.g. 202, 429, 503). */
  status: number;
  /**
   * The created push's ids, on a 2xx: an acceptance
   * receipt only, not a delivery result (delivery
   * confirmation lives in Airship's reports, keyed by
   * the response's `operation_id`).
   */
  pushIds?: string[];
}

/**
 * The injected Airship message client. Any client adapter
 * implements this one method; it returns the POST's status
 * and, on a 2xx, the created push's `push_ids` (a throw is
 * a codeless transport failure, retryable). The client is
 * expected to POST one message per call, sending `body`
 * verbatim as the request body (JSON), sending `headers`
 * verbatim as the request headers, and authenticating with
 * an `Authorization: Basic` header carrying the base64 of
 * its own `app key:app secret` — which the sink never
 * sees.
 */
export interface AirshipMessageClient {
  post(request: AirshipMessagePostRequest): Promise<AirshipMessagePostResponse>;
}

/**
 * Configuration for one Airship sink. The client is
 * injected: without one, `send()` throws
 * `AirshipSinkConfigError` (dry runs excepted — they need
 * no client at all). The audience defaults to `"all"`
 * when unset, so a missing audience is never a config
 * error: Airship accepts a broadcast audience. The app
 * key and master secret are deliberately absent from this
 * config: the client alone holds them and sends them as
 * the `Authorization: Basic` header.
 */
export interface AirshipSinkConfig {
  /**
   * The push audience: either the string `"all"` (a
   * broadcast to the whole audience) or an object with
   * audience selectors, held verbatim. Defaults to
   * `"all"` when unset. Must be `"all"` or a non-empty
   * object when set; any other string is rejected at
   * config validation.
   */
  audience?: AirshipAudience;
  /**
   * The Airship message client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `AirshipMessageClient` and alone holds the
   * app key and master secret. Required for real sends; a
   * missing client is a config error, not a silent no-op.
   */
  client?: AirshipMessageClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, dryRun: true }` and performs zero
   * client I/O — no POST call, no stat changes. Messages are
   * still validated (including notification derivation), so a dry run
   * catches a malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The audience and client are
   * not required in dry-run mode, mirroring the sibling
   * sinks' dry-run exemption.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the alert appends
   * the event body verbatim after a blank line, truncated to
   * `payloadMaxChars` characters (see below). When `false`
   * or absent, the message carries the summary only — the
   * default, so event bodies (which routinely carry PII)
   * never leak into a notification unless the operator
   * explicitly asks for them.
   */
  includePayload?: boolean;
  /**
   * Truncation limit for an opted-in payload snippet, in
   * characters (default 2000). Only meaningful with
   * `includePayload`; the truncation is unconditional when
   * the opt-in is set, so an opted-in body cannot flood a
   * device. Must be a positive integer when set.
   */
  payloadMaxChars?: number;
}

/** One event to notify about. */
export interface AirshipRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Alert-derivation source, first priority: the event's
   * subject, when set and non-empty. Falls through to `key`,
   * then `traceId`.
   */
  subject?: string;
  /**
   * Alert-derivation source, second priority: the event's key
   * (e.g. aggregate id).
   */
  key?: string;
  /**
   * Alert-derivation source, last priority: the trace id.
   */
  traceId?: string;
}

/** One failed message, with its retry lane already mapped. */
export interface AirshipFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /**
   * Failure code: `HTTP_<status>` for a non-2xx POST,
   * `PUSH_IDS_MISSING` for a 2xx with no push ids
   * surfaced, or `TRANSPORT_ERROR` for a codeless
   * failure.
   */
  errorCode: string;
  /** Downstream HTTP status, when the failure was a non-2xx POST. */
  statusCode?: number;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: 429 and 5xx
   * (plus codeless transport failures and missing push
   * ids) are retryable; every other non-2xx status is a
   * fail-closed message (unknown audience selector,
   * invalid body, bad app key).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface AirshipSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-284). */
export interface AirshipSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for Airship send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already on Airship's server and are *not* in
 * `failedRecords`.
 */
export class AirshipSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: AirshipFailedRecord[];
  constructor(message: string, failedRecords: AirshipFailedRecord[]) {
    super(message);
    this.name = "AirshipSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class AirshipSinkConfigError extends AirshipSinkError {
  constructor(reason: string) {
    super(`airship-sink: ${reason}`, []);
    this.name = "AirshipSinkConfigError";
  }
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. A
 * missing audience is *not* a shape error: it defaults to
 * `"all"` at send time, so a sink built before its audience
 * is known still sends a broadcast rather than crashing at
 * construction. A present `audience` value must be the
 * string `"all"` or a non-empty object; any other string
 * (or an array, or an empty object) is rejected.
 */
export function assertValidAirshipSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is AirshipSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  const audience = c.audience;
  if (audience !== undefined) {
    if (typeof audience === "string") {
      if (audience !== "all") {
        throw new RangeError(at("`audience` as a string must be `\"all\"` when set"));
      }
    } else if (
      audience === null ||
      typeof audience !== "object" ||
      Array.isArray(audience) ||
      Object.keys(audience as Record<string, unknown>).length === 0
    ) {
      throw new RangeError(at("`audience` must be `\"all\"` or a non-empty object when set"));
    }
  }
  if (
    c.client !== undefined &&
    (c.client === null ||
      typeof c.client !== "object" ||
      typeof (c.client as { post?: unknown }).post !== "function")
  ) {
    throw new RangeError(at("`client` must expose a `post` function when set"));
  }
  if (
    c.payloadMaxChars !== undefined &&
    (typeof c.payloadMaxChars !== "number" ||
      !Number.isInteger(c.payloadMaxChars) ||
      c.payloadMaxChars <= 0)
  ) {
    throw new RangeError(at("`payloadMaxChars` must be a positive integer when set"));
  }
}

/**
 * Resolve the effective audience: the configured audience,
 * or `"all"` when the config sets none. A broadcast is
 * always a valid audience, so a missing audience never
 * fails closed.
 */
export function resolveAirshipAudience(
  config: Pick<AirshipSinkConfig, "audience">
): AirshipAudience {
  return config.audience ?? "all";
}

/**
 * Derive one record's notification alert: the first
 * non-empty value among `subject`, `key`, and `traceId`,
 * in that order. Falls back to the generic `webhook
 * event` summary when the record carries none — a
 * notification sink must not silently drop sourceless
 * events, and the audience (not the content) is the
 * delivery contract.
 */
export function resolveAirshipAlert(record: AirshipRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return AIRSHIP_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a device.
 */
export function truncateAirshipPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's notification: the `alert` string
 * from the first non-empty among `subject`, `key`, and
 * `traceId` (falling back to `webhook event`), then the
 * event body appended after a blank line only under the
 * `includePayload` opt-in (truncated to `payloadMaxChars`,
 * default 2000).
 */
export function resolveAirshipNotification(
  record: AirshipRecord,
  config: Pick<AirshipSinkConfig, "includePayload" | "payloadMaxChars">
): { alert: string } {
  let alert = resolveAirshipAlert(record);
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? AIRSHIP_DEFAULT_PAYLOAD_MAX_CHARS;
    alert = `${alert}\n\n${truncateAirshipPayload(record.body, limit)}`;
  }
  return { alert };
}

/**
 * Build one record's serialized JSON body: the push
 * object with `audience`, `notification` carrying the
 * `alert`, and `device_types` fixed to `"all"`. The app
 * key and master secret never appear here — the client
 * alone holds them and sends them as the `Authorization:
 * Basic` header.
 */
export function buildAirshipPushBody(
  audience: AirshipAudience,
  notification: { alert: string }
): string {
  return JSON.stringify({
    audience,
    notification,
    device_types: AIRSHIP_DEVICE_TYPES,
  });
}

/**
 * Validate one record's body. Throws `RangeError` on an
 * empty body string — even without the opt-in, the body is
 * the record's payload, and an empty record is a caller
 * bug that must fail closed, never notify as an empty
 * message.
 */
export function resolveAirshipRecord(
  record: AirshipRecord,
  index: number
): { index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`airship-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { index };
}

/**
 * Map one Airship POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says Airship could not
 * accept the message right now, not that the payload is
 * poison. Every other non-2xx status (400, 401, 403,
 * 404, and the rest) is a fail-closed message: unknown
 * audience selector, invalid body, bad app key, or another
 * verdict retrying cannot change. Callers only pass
 * non-2xx statuses here; a 2xx status is decided by the
 * push ids, not by this function.
 */
export function classifyAirshipRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * Map one Airship POST response onto its failed record,
 * or `null` when the response accepted the message (a 2xx
 * with at least one surfaced push id). A 2xx with no ids
 * is retryable — the ids are the acceptance result, and
 * without them the sink cannot claim the push was created.
 */
export function airshipResponseToFailedRecord(
  response: AirshipMessagePostResponse,
  index: number
): AirshipFailedRecord | null {
  if (
    response.pushIds !== undefined &&
    response.pushIds.length > 0 &&
    response.pushIds.every((id) => id !== "")
  ) {
    return null;
  }
  return {
    index,
    errorCode: "PUSH_IDS_MISSING",
    errorMessage: "Airship answered 2xx but surfaced no push_ids",
    retryable: true,
  };
}

/**
 * Airship sink (WR-284). One instance targets one
 * Airship application audience; the caller owns retry /
 * dead-letter policy around `send()` — this class performs
 * one POST attempt per message through the injected client
 * and reports its outcome. Failures throw
 * `AirshipSinkError` carrying exactly the failed messages
 * with their retry lanes.
 */
export class AirshipSink {
  private readonly cfg: AirshipSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: AirshipSinkConfig) {
    assertValidAirshipSinkConfig(config, "AirshipSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): AirshipSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Send push notifications, in input order. Throws
   * `AirshipSinkConfigError` when no client was injected,
   * and `AirshipSinkError` when any message fails
   * (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: AirshipRecord[]): Promise<AirshipSendResult> {
    const resolved = records.map((r, i) => resolveAirshipRecord(r, i));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The
      // audience and client are
      // not required here, mirroring the sibling sinks'
      // dry-run exemption.
      return { ok: true, sent: 0, dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new AirshipSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const audience = resolveAirshipAudience(this.cfg);
    const failedRecords: AirshipFailedRecord[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          url: AIRSHIP_PUSH_URL,
          headers: {
            "Content-Type": AIRSHIP_JSON_CONTENT_TYPE,
            Accept: AIRSHIP_ACCEPT_HEADER,
          },
          body: buildAirshipPushBody(
            audience,
            resolveAirshipNotification(records[i], this.cfg)
          ),
        });
        if (response.status >= 200 && response.status < 300) {
          const idFailure = airshipResponseToFailedRecord(response, record.index);
          if (idFailure === null) {
            sent += 1;
            continue;
          }
          failedRecords.push(idFailure);
          continue;
        }
        failedRecords.push({
          index: record.index,
          errorCode: `HTTP_${response.status}`,
          statusCode: response.status,
          retryable: classifyAirshipRecordFailure(response.status),
        });
      } catch (err) {
        failedRecords.push(toAirshipFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new AirshipSinkError(
        `airship-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent };
  }
}

/**
 * Convert a client throw into a failed message: a codeless
 * transport failure (`TRANSPORT_ERROR`, retryable — the SQS
 * no-status rule).
 */
function toAirshipFailedRecord(err: unknown, index: number): AirshipFailedRecord {
  const failed: AirshipFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
