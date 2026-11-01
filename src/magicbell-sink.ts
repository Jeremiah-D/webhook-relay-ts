/**
 * MagicBell workflow trigger delivery sink (WR-294).
 *
 * Some downstreams are not queues, streams, or topics at
 * all: they are a human's inbox, phone, or push token,
 * reached through a multi-channel workflow. Where the
 * SuprSend sink (WR-293) triggers a SuprSend workflow
 * through SuprSend's workflow trigger API with a `Bearer`
 * workspace API key and a `workflow`/`recipients`/`data`
 * envelope carrying a body `idempotency_key`, and the
 * Knock sink (WR-292) triggers a Knock workflow with a
 * `Bearer` secret key and a `key`/`recipients`/`data`
 * envelope carrying an `Idempotency-Key` header, this sink
 * triggers a MagicBell workflow: one event is sent as one
 * POST that MagicBell accepts for one workflow run, and
 * MagicBell — not the relay — owns the workflow execution,
 * the channel fan-out, the delivery, and the retention of
 * the notification.
 *
 * No real HTTP client is bundled: the client is injected
 * through `config.client` (a thin adapter over whatever HTTP
 * the operator runs — `fetch`, a sidecar), so the module has
 * zero new dependencies and tests never need a MagicBell
 * server. The sink owns the relay-side concerns — the
 * workflow key, the message derivation, the
 * payload-inclusion policy, the per-message failure
 * mapping — and the injected client owns the wire
 * protocol, including the POST call, the authentication,
 * and the status it returns.
 *
 * Wire shape — one POST per message, carried to the
 * injected client as:
 *
 *   { url: "https://api.magicbell.com/v2/workflows/runs",
 *     headers: { "Content-Type": "application/json" },
 *     body: "{\"key\":\"<workflow>\",\"input\":{\"title\":\"<title>\",\"body\":\"<body>\"}}" }
 *
 * The client POSTs to that URL, sending `body`
 * verbatim as the request body (JSON) and `headers`
 * verbatim as the request headers, and authenticating
 * with an `Authorization: Bearer <PROJECT_JWT>` header
 * carrying the Project JWT — which it alone holds. Five
 * things about this shape are deliberate, and all follow
 * the sibling sinks or the backlog pins:
 *
 * - The Project JWT is held by the client alone. The sink
 *   never receives the token, never places it in the
 *   request, and never logs it: the handed request
 *   therefore carries no credential at all, so there is
 *   nothing in it for a log line or a retry queue to leak
 *   — and the token is never persisted by the sink. This
 *   is the MagicBell form of the SuprSend rule (whose
 *   workspace API key the client alone holds as an
 *   `Authorization: Bearer` header), with MagicBell's own
 *   credential source: the Project JWT, generated in the
 *   MagicBell dashboard, verified against the current
 *   docs (magicbell.com, re-checked 2026-11-01,
 *   including the API (v2) reference and the REST API
 *   (v2) page — whose error example confirms the
 *   expected authorization header format,
 *   `Bearer <token>`).
 * - The endpoint is the workflow trigger API the backlog
 *   pins: `POST https://api.magicbell.com/v2/workflows/runs`.
 *   The reference describes it as executing a workflow
 *   with the provided input parameters, under Project JWT
 *   authentication. The workflow runs asynchronously.
 * - The `key` is config-held and required: the workflow
 *   identifier, the unique key of the workflow from the
 *   MagicBell dashboard. One sink triggers one fixed
 *   workflow; the workflow must already exist — the sink
 *   never creates a workflow (a workflow definition is
 *   created separately, in the dashboard or the CLI, or
 *   through `PUT /workflows`), and a missing key is a
 *   config error at construction, not a silent no-op at
 *   send time. The reference pins the key pattern
 *   `^[A-Za-z0-9_.\\-:]+$` with a minimum length of 3;
 *   the sink validates only that the key is a non-empty
 *   string, matching the sibling sinks' validation, and
 *   leaves the pattern to MagicBell's own verdict.
 * - There is no recipients envelope. Recipients are
 *   defined inside the workflow's steps (a broadcast step
 *   carries its own recipients), so the trigger call
 *   carries only `key` and `input` — this is the whole
 *   point of the slot, and what makes it orthogonal to
 *   WR-293 (SuprSend's `workflow`/`recipients`/`data`
 *   envelope) and WR-292 (Knock's
 *   `key`/`recipients`/`data` envelope). The sink never
 *   invents a recipient and never defaults to an audience:
 *   who is notified is the workflow's decision, not the
 *   relay's.
 * - No `Idempotency-Key` header is sent — deliberately,
 *   and unlike the Knock and Novu sinks. The REST API
 *   (v2) docs say idempotent requests are supported "for
 *   some endpoints" without enumerating which, and the
 *   only example given is notification creation; the
 *   API (v2) reference entry for `POST /workflows/runs`
 *   documents no `Idempotency-Key` header parameter, so
 *   applicability to this endpoint is unverified and the
 *   sink does not send a header it cannot verify the
 *   server honors. The consequence is honest and worth
 *   stating: a retry after a codeless transport failure
 *   (no response was received, so no run id exists to
 *   reconcile against) may execute the workflow a second
 *   time. Callers that need exactly-once behavior should
 *   reconcile through `GET /workflows/runs/{run_id}`
 *   whenever a run id was observed, rather than blindly
 *   replaying a transport failure.
 *
 * Acceptance is decided by the HTTP status together with
 * the response body's run acceptance credential: a 2xx
 * whose body carries a `run_id` means MagicBell accepted
 * the trigger, and the run id is the receipt the operator
 * uses to check the run's status later
 * (`GET /workflows/runs/{run_id}`). The client surfaces
 * the run id when present; `send()` returns the collected
 * run ids in send order, so a caller that only inspects
 * the result still has the receipts. A successful response
 * is only an acceptance receipt, not a delivery result:
 * the workflow runs asynchronously, delivery is handled
 * by MagicBell and the channel providers, and surfaces
 * later through MagicBell's run status. A 2xx without a
 * run id is a failure (`MAGICBELL_NO_RUN_ID`, fail-closed):
 * the reference promises no other receipt, so a 2xx with
 * nothing to trace must not turn an untraceable trigger
 * into an acceptance. Any non-2xx status is a failure. The
 * exact HTTP success status is deliberately not pinned:
 * the fetched API reference documents the endpoint and its
 * request body but shows no response-status section, so
 * the sink trusts any 2xx carrying a run id rather than
 * inventing a status number. The reference documents the
 * run id as the acceptance credential; the docs' error
 * shape (a 4xx body carrying an `errors` array of
 * `{ code, message }`) is what the client surfaces on
 * failure records.
 *
 * Message content — a notification carries a title and a
 * body, both derived from the event's own values: the
 * first non-empty value among `subject`, `key`, and
 * `traceId`, in that order, is the summary. The body takes
 * that summary, so an event with none of the values still
 * notifies, with the generic summary `webhook event`: a
 * notification sink that silently dropped sourceless
 * events would hide exactly the deliveries an operator
 * most needs to see. The title takes the `subject` alone,
 * when one exists, and is omitted otherwise: the input is
 * for the workflow's templates (referenced as liquid
 * variables), so a subjectless event triggers with a body
 * and no title rather than a title invented from a key or
 * a trace id. Both go into `input` as `title` (when
 * present) and `body` (always).
 *
 * Payload inclusion — by default the notification
 * carries the summary only, never the full payload:
 * event bodies routinely carry PII, secrets, or
 * customer data, and a workflow's channels are a far
 * wider audience than a queue or a stream. Opting into
 * `includePayload` appends the event body as
 * `input.eventBody` — a JSON string carrying the body
 * verbatim, truncated to `payloadMaxChars` characters
 * (default 2000) with a truncation marker — the opt-in
 * is explicit, and the truncation is unconditional, so
 * even an opted-in body cannot flood a workflow. The
 * payload rides in its own field, not inside the
 * notification body: MagicBell's `input` is a map for the
 * workflow's templates, not text for the screen.
 *
 * Failure handling mirrors the WR-210 SQS sink's
 * classification (`src/failure.ts`), applied per message
 * over the HTTP status:
 *
 * - a non-2xx POST, or a 2xx whose body carries no run
 *   id, throws `MagicBellSinkError` carrying every failed
 *   message with its retry lane already mapped, so the
 *   caller retries exactly the failed messages;
 * - retryable statuses are the transient HTTP states —
 *   429 and every 5xx: a rate limit says MagicBell could
 *   not accept the message right now, not that the payload
 *   is poison. The docs pin the limit at 500 requests per
 *   minute per IP address, with a 429 block removed after
 *   60 seconds;
 * - non-retryable statuses are the fail-closed messages
 *   — every other non-2xx status, including 400, 401,
 *   403, and 404 (bad input or key, bad Project JWT,
 *   insufficient permissions, unknown workflow), and a
 *   2xx whose body carries no run id: retrying them burns
 *   the retry budget for nothing, and rerouting them
 *   elsewhere would notify people the operator never
 *   chose;
 * - a codeless transport failure (the client threw) is
 *   retryable, like an SQS transport error with no status:
 *   it says nothing about the payload (see the
 *   idempotency note above for what a retried transport
 *   failure can still do);
 * - a missing client throws `MagicBellSinkConfigError`,
 *   which `classifyFailure` maps to `non_retryable`
 *   (the WR-116 rule).
 *
 * Zero new dependencies: the injected client only. (No
 * `node:crypto` import either: with no idempotency key to
 * derive, there is nothing to hash.)
 */

/** Generic summary used when an event carries no value for the message body. */
export const MAGICBELL_FALLBACK_SUMMARY = "webhook event";

/** Default truncation limit for an opted-in payload snippet, in characters. */
export const MAGICBELL_DEFAULT_PAYLOAD_MAX_CHARS = 2000;

/** Content type the client sends with the JSON body. */
export const MAGICBELL_JSON_CONTENT_TYPE = "application/json";

/** MagicBell API base URL (v2). */
export const MAGICBELL_API_BASE_URL = "https://api.magicbell.com/v2";

/** Trigger endpoint for one workflow run (the workflow key rides in the body, not the path). */
export const MAGICBELL_TRIGGER_URL = `${MAGICBELL_API_BASE_URL}/workflows/runs`;

/** Rate limit the docs pin for the REST API: requests per minute, counted per IP address. */
export const MAGICBELL_RATE_LIMIT_PER_MINUTE_PER_IP = 500;

/** Seconds a 429 block lasts before the API removes it, per the docs. */
export const MAGICBELL_RATE_LIMIT_BLOCK_SECONDS = 60;

/**
 * One POST request as handed to the injected client. The
 * client owns the wire protocol: it POSTs `body` verbatim
 * as the request body (JSON), sends `headers` verbatim
 * as the request headers, and authenticates with an
 * `Authorization: Bearer <PROJECT_JWT>` header carrying
 * the Project JWT — which the sink never sees. No
 * `Idempotency-Key` header is sent: the docs do not verify
 * it for this endpoint (see the module header).
 */
export interface MagicBellTriggerPostRequest {
  /**
   * Always `https://api.magicbell.com/v2/workflows/runs`
   * — the workflow trigger API. No credential ever appears
   * in the URL, and the workflow key rides in the body,
   * not the path.
   */
  url: string;
  /**
   * Request headers, sent verbatim:
   * `{ "Content-Type": "application/json" }`. The
   * `Authorization` header is added by the client, never
   * by the sink, and there is deliberately no
   * `Idempotency-Key` header.
   */
  headers: Record<string, string>;
  /**
   * The JSON request body, serialized:
   * `{"key":"<workflow>","input":{"title":"<title>","body":"<body>"}}`
   * (`eventBody` is appended inside `input` only under
   * the `includePayload` opt-in; `title` is omitted when
   * the event carries no subject). There is no
   * recipients envelope: recipients live inside the
   * workflow's steps.
   */
  body: string;
}

/**
 * The result of one POST, as reported by the injected
 * client. The HTTP status decides acceptance together
 * with the response body's run id: a 2xx carrying a
 * `run_id` means MagicBell accepted the trigger, and the
 * run id is the receipt for checking the run's status
 * later (`GET /workflows/runs/{run_id}`). A 2xx without a
 * run id is a failure, not an acceptance. The docs'
 * error shape is a 4xx body carrying an `errors` array of
 * `{ code, message }`; when the client surfaces those
 * messages, they ride on the failure record.
 */
export interface MagicBellTriggerPostResponse {
  /** The HTTP status of the POST (e.g. 200, 201, 400, 401, 403, 404, 429, 503). */
  status: number;
  /** The run id from the success body, when the client surfaced one. */
  runId?: string;
  /** The error messages from the response body's `errors` array, when the client surfaced them. */
  errors?: string[];
  /** The body's `message`, when the client surfaced one. */
  message?: string;
}

/**
 * The injected MagicBell trigger client. Any client adapter
 * implements this one method; it returns the POST's status
 * and the run id when present — a throw is a codeless
 * transport failure, retryable. The client is expected to
 * POST one trigger per call, sending `body` verbatim as
 * the request body (JSON), sending `headers` verbatim as
 * the request headers, and authenticating with an
 * `Authorization: Bearer <PROJECT_JWT>` header carrying
 * the Project JWT — which the sink never sees.
 */
export interface MagicBellTriggerClient {
  post(request: MagicBellTriggerPostRequest): Promise<MagicBellTriggerPostResponse>;
}

/**
 * Configuration for one MagicBell sink. The client is
 * injected: without one, `send()` throws
 * `MagicBellSinkConfigError` (dry runs excepted — they need
 * no client at all). The Project JWT is deliberately
 * absent from this config: the client alone holds it
 * (`Authorization: Bearer` header), and it is never
 * persisted by the sink.
 */
export interface MagicBellSinkConfig {
  /**
   * The workflow key: the unique key of the workflow from
   * the MagicBell dashboard. Required — the workflow must
   * already exist before a trigger can run it (the sink
   * never creates a workflow; a definition is created in
   * the dashboard or the CLI, or through `PUT /workflows`).
   * Must be a non-empty string. The reference pins the key
   * pattern `^[A-Za-z0-9_.\\-:]+$` with a minimum length
   * of 3; the sink validates only non-emptiness, matching
   * the sibling sinks, and leaves the pattern to
   * MagicBell's own verdict.
   */
  key: string;
  /**
   * The MagicBell trigger client to deliver through.
   * Injected, never bundled: the operator's client adapter
   * implements `MagicBellTriggerClient` and alone holds
   * the Project JWT. Required for real sends; a missing
   * client is a config error, not a silent no-op.
   */
  client?: MagicBellTriggerClient;
  /**
   * Rehearsal mode: `send()` returns
   * `{ ok: true, sent: 0, runIds: [], dryRun: true }`
   * and performs zero client I/O — no POST call, no stat
   * changes. Messages are still validated (including
   * message derivation), so a dry run catches a
   * malformed record before it reaches production.
   * Mirrors the `dryRun` convention of the S3 offloaders.
   * The client is not required in dry-run mode, mirroring
   * the sibling sinks' dry-run exemption; the rest of the
   * config must still be valid — a dry run against a sink
   * with no workflow key would rehearse a request that
   * could never send.
   */
  dryRun?: boolean;
  /**
   * Payload opt-in: when `true`, the request body's
   * `input` appends `eventBody` carrying the event body
   * verbatim as a JSON string, truncated to
   * `payloadMaxChars` characters (see below). When
   * `false` or absent, the input carries the summary
   * only — the default, so event bodies (which routinely
   * carry PII) never leak into a notification unless the
   * operator explicitly asks for them.
   */
  includePayload?: boolean;
  /**
   * Truncation limit for an opted-in payload snippet, in
   * characters (default 2000). Only meaningful with
   * `includePayload`; the truncation is unconditional when
   * the opt-in is set, so an opted-in body cannot flood a
   * workflow. Must be a positive integer when set.
   */
  payloadMaxChars?: number;
}

/** One event to notify about. */
export interface MagicBellRecord {
  /** The event JSON, already serialized by the caller — used only under the `includePayload` opt-in. */
  body: string;
  /**
   * Content-derivation source, first priority: the event's
   * subject, when set and non-empty. Also the sole source
   * of `input.title`, when present.
   */
  subject?: string;
  /**
   * Content-derivation source, second priority: the event's key
   * (e.g. aggregate id).
   */
  key?: string;
  /**
   * Content-derivation source, last priority: the trace id.
   */
  traceId?: string;
}

/** One failed message, with its retry lane already mapped. */
export interface MagicBellFailedRecord {
  /** Index into the caller's original `records` array. */
  index: number;
  /**
   * Failure code: `HTTP_<status>` for a non-2xx POST,
   * `MAGICBELL_NO_RUN_ID` for a 2xx whose body carries no
   * run id, or `TRANSPORT_ERROR` for a codeless failure.
   */
  errorCode: string;
  /** Downstream HTTP status, when the failure was a non-2xx POST. */
  statusCode?: number;
  /** Client error message, when the failure carried one. */
  errorMessage?: string;
  /**
   * Retry lane under the WR-210 mapping: 429 and 5xx
   * (plus codeless transport failures) are retryable;
   * every other non-2xx status, and a 2xx whose body
   * carries no run id, is a fail-closed message (bad input
   * or key, bad Project JWT, insufficient permissions,
   * unknown workflow, or a trigger MagicBell received but
   * gave no run id for).
   */
  retryable: boolean;
}

/** Outcome of one `send()` call (failures throw, see above). */
export interface MagicBellSendResult {
  /** Always `true` for a returned result — failures throw. */
  ok: true;
  /** Messages the client accepted (real sends only; 0 in dry-run mode). */
  sent: number;
  /**
   * Run ids in send order — the id of each accepted
   * message that reported one. Empty in dry-run mode. A
   * 2xx without a run id is a failure, so every accepted
   * message contributes exactly one entry here.
   */
  runIds: string[];
  /** `true` only in dry-run mode: no client I/O happened. */
  dryRun?: boolean;
}

/** Introspection counters (WR-294). */
export interface MagicBellSinkStats {
  /** Messages accepted by the client (real sends, not dry runs). */
  sent: number;
  /** Messages reported failed by the client. */
  failed: number;
  /** send calls that threw (counted before the error is thrown). */
  sendFailures: number;
}

/**
 * Thrown for MagicBell send failures. Carries every failed
 * message with its retry lane (`failedRecords`), so the retry
 * queue can requeue exactly those messages. A send call that
 * throws has partial success behind it — the accepted messages
 * are already received on MagicBell's server and are *not* in
 * `failedRecords`.
 */
export class MagicBellSinkError extends Error {
  /** Per-message failures, in input order, each with their retry lane. */
  readonly failedRecords: MagicBellFailedRecord[];
  constructor(message: string, failedRecords: MagicBellFailedRecord[]) {
    super(message);
    this.name = "MagicBellSinkError";
    this.failedRecords = failedRecords;
  }
}

/**
 * Thrown when the sink cannot even send — currently: no
 * client was injected. A config problem, not a downstream
 * verdict, so the retry queue must not burn attempts on it
 * (`classifyFailure` maps it to `non_retryable`).
 */
export class MagicBellSinkConfigError extends MagicBellSinkError {
  constructor(reason: string) {
    super(`magicbell-sink: ${reason}`, []);
    this.name = "MagicBellSinkConfigError";
  }
}

/**
 * Validate the workflow key: a non-empty string. Throws
 * `RangeError` otherwise.
 */
export function resolveMagicBellWorkflowKey(key: unknown, label: string): string {
  if (typeof key !== "string" || key === "") {
    throw new RangeError(`${label}: \`key\` must be a non-empty workflow key string`);
  }
  return key;
}

/**
 * Validate a sink config. Throws `RangeError` on any bad shape —
 * called at startup so a typo fails fast, never mid-delivery. The
 * workflow key is required and enforced here, not at send time:
 * `key` must be a non-empty string.
 */
export function assertValidMagicBellSinkConfig(
  cfg: unknown,
  label: string
): asserts cfg is MagicBellSinkConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  resolveMagicBellWorkflowKey(c.key, label);
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
 * Derive one record's content summary: the first
 * non-empty value among `subject`, `key`, and `traceId`,
 * in that order. Falls back to the generic `webhook
 * event` summary when the record carries none — a
 * notification sink must not silently drop sourceless
 * events.
 */
export function resolveMagicBellSummary(record: MagicBellRecord): string {
  for (const value of [record.subject, record.key, record.traceId]) {
    if (value !== undefined && value !== "") {
      return value;
    }
  }
  return MAGICBELL_FALLBACK_SUMMARY;
}

/**
 * Truncate an opted-in payload snippet to `limit`
 * characters, appending a truncation marker when cut. The
 * truncation is unconditional under the opt-in, so an
 * opted-in body cannot flood a workflow.
 */
export function truncateMagicBellPayload(body: string, limit: number): string {
  if (body.length <= limit) {
    return body;
  }
  return `${body.slice(0, limit)}… (truncated)`;
}

/**
 * Derive one record's input map: `body` takes the derived
 * summary (the first non-empty among `subject`, `key`,
 * and `traceId`, falling back to `webhook event`) — the
 * body is the data the workflow's templates render, so it
 * always has a value — and `title` takes the `subject`
 * alone when one exists, omitted otherwise: a subjectless
 * event triggers with a body and no title rather than a
 * title invented from a key or a trace id. Under the
 * `includePayload` opt-in the `eventBody` carries the
 * event body verbatim as a JSON string, truncated to
 * `payloadMaxChars` (default 2000); without the opt-in
 * there is no `eventBody` key at all.
 */
export function resolveMagicBellInput(
  record: MagicBellRecord,
  config: Pick<MagicBellSinkConfig, "includePayload" | "payloadMaxChars">
): { title?: string; body: string; eventBody?: string } {
  const summary = resolveMagicBellSummary(record);
  const input: { title?: string; body: string; eventBody?: string } = { body: summary };
  if (record.subject !== undefined && record.subject !== "") {
    input.title = record.subject;
  }
  if (config.includePayload === true) {
    const limit = config.payloadMaxChars ?? MAGICBELL_DEFAULT_PAYLOAD_MAX_CHARS;
    input.eventBody = truncateMagicBellPayload(record.body, limit);
  }
  return input;
}

/**
 * Build one record's serialized JSON body: the trigger
 * object with `key` and `input` (`title` only when the
 * event carries a subject), plus `eventBody` inside
 * `input` only under the `includePayload` opt-in. There
 * is no recipients envelope — recipients live inside the
 * workflow's steps — and no idempotency key: the docs do
 * not verify `Idempotency-Key` for this endpoint. The
 * Project JWT never appears here — the client alone holds
 * it (`Authorization: Bearer` header).
 */
export function buildMagicBellTriggerBody(
  key: string,
  input: { title?: string; body: string; eventBody?: string }
): string {
  return JSON.stringify({ key, input });
}

/**
 * Validate one record's body. Throws `RangeError` on an
 * empty body string — even without the opt-in, the body is
 * the record's payload, and an empty record is a caller
 * bug that must fail closed, never trigger as an empty
 * message.
 */
export function resolveMagicBellRecord(
  record: MagicBellRecord,
  index: number
): { index: number } {
  if (typeof record.body !== "string" || record.body === "") {
    throw new RangeError(`magicbell-sink: record ${index} \`body\` must be a non-empty event JSON string`);
  }
  return { index };
}

/**
 * Map one MagicBell POST `statusCode` onto its retry lane
 * under the WR-210 rules: 429 and every 5xx are transient
 * and so retryable — a rate limit says MagicBell could not
 * accept the message right now, not that the payload
 * is poison (the docs pin 500 requests per minute per IP,
 * with a 429 block removed after 60 seconds). Every other
 * non-2xx status (400, 401, 403, 404, and the rest) is a
 * fail-closed message: bad input or key, bad Project JWT,
 * insufficient permissions, or an unknown workflow.
 * Callers only pass non-2xx statuses here; a 2xx is
 * acceptance on its own only together with a run id (see
 * `classifyMagicBellTriggerResponse`).
 */
export function classifyMagicBellRecordFailure(statusCode: number): boolean {
  return statusCode === 429 || statusCode >= 500;
}

/**
 * The verdict on one trigger POST: either an acceptance,
 * or a failure with its error code and retry lane.
 */
export type MagicBellTriggerVerdict =
  | { accepted: true }
  | { accepted: false; errorCode: string; retryable: boolean; errorMessage?: string };

/**
 * Decide one trigger POST's verdict from the response the
 * client reported. A 2xx carrying a `run_id` is acceptance
 * — the run id is the run acceptance credential, and the
 * run's status is checked later through
 * `GET /workflows/runs/{run_id}`. A 2xx without a run id
 * is a failure (`MAGICBELL_NO_RUN_ID`, fail-closed: the
 * reference promises no other receipt, so a 2xx with
 * nothing to trace must not become an acceptance). Any
 * non-2xx status is a failure with an `HTTP_<status>` code
 * and the WR-210 lane. The exact HTTP success status is
 * deliberately not pinned: the fetched API reference
 * documents the endpoint and its request body but no
 * response-status section. The docs' error shape is a 4xx
 * body carrying an `errors` array of `{ code, message }`;
 * when the client surfaces those messages (or a `message`),
 * they ride on the failure record.
 */
export function classifyMagicBellTriggerResponse(
  response: MagicBellTriggerPostResponse
): MagicBellTriggerVerdict {
  if (response.status < 200 || response.status >= 300) {
    const verdict: MagicBellTriggerVerdict = {
      accepted: false,
      errorCode: `HTTP_${response.status}`,
      retryable: classifyMagicBellRecordFailure(response.status),
    };
    const messages = [
      ...(response.errors ?? []).filter((m) => m !== ""),
      ...(response.message !== undefined && response.message !== "" ? [response.message] : []),
    ];
    if (messages.length > 0) {
      verdict.errorMessage = messages.join("; ");
    }
    return verdict;
  }
  if (typeof response.runId !== "string" || response.runId === "") {
    return { accepted: false, errorCode: "MAGICBELL_NO_RUN_ID", retryable: false };
  }
  return { accepted: true };
}

/**
 * MagicBell sink (WR-294). One workflow run is triggered
 * per message; the caller owns retry / dead-letter policy
 * around `send()` — this class performs one POST attempt
 * per message through the injected client and reports its
 * outcome. Failures throw `MagicBellSinkError` carrying
 * exactly the failed messages with their retry lanes.
 */
export class MagicBellSink {
  private readonly cfg: MagicBellSinkConfig;
  private sent = 0;
  private failed = 0;
  private sendFailures = 0;

  constructor(config: MagicBellSinkConfig) {
    assertValidMagicBellSinkConfig(config, "MagicBellSink");
    this.cfg = config;
  }

  /** Current counters; dry runs change none of them. */
  get stats(): MagicBellSinkStats {
    return {
      sent: this.sent,
      failed: this.failed,
      sendFailures: this.sendFailures,
    };
  }

  /**
   * Trigger the workflow, in input order. Throws
   * `MagicBellSinkConfigError` when no client was injected,
   * and `MagicBellSinkError` when any message fails
   * (carrying exactly the failed messages with their
   * retry lanes; both counted in stats before throwing, so
   * the counters stay honest even for callers that only
   * inspect stats).
   */
  async send(records: MagicBellRecord[]): Promise<MagicBellSendResult> {
    const resolved = records.map((r, i) => resolveMagicBellRecord(r, i));
    if (this.cfg.dryRun === true) {
      // Validate even in rehearsal, so a dry run still catches
      // a malformed record before it reaches production — but
      // perform zero client I/O and touch no stats. The client
      // is not required here, mirroring the sibling sinks'
      // dry-run exemption; the rest of the config was already
      // validated at construction.
      return { ok: true, sent: 0, runIds: [], dryRun: true };
    }
    const client = this.cfg.client;
    if (client === undefined) {
      throw new MagicBellSinkConfigError("no client injected (set `client` in the sink config)");
    }
    const key = resolveMagicBellWorkflowKey(this.cfg.key, "MagicBellSink");
    const failedRecords: MagicBellFailedRecord[] = [];
    const runIds: string[] = [];
    let sent = 0;
    for (let i = 0; i < resolved.length; i += 1) {
      const record = resolved[i];
      try {
        const response = await client.post({
          url: MAGICBELL_TRIGGER_URL,
          headers: {
            "Content-Type": MAGICBELL_JSON_CONTENT_TYPE,
          },
          body: buildMagicBellTriggerBody(
            key,
            resolveMagicBellInput(records[i], this.cfg)
          ),
        });
        const verdict = classifyMagicBellTriggerResponse(response);
        if (verdict.accepted) {
          // A 2xx carrying a run id is acceptance on its
          // own: the run id is the receipt, and the run's
          // status is checked later through
          // GET /workflows/runs/{run_id} — the response is
          // an acceptance receipt, not a delivery result.
          sent += 1;
          if (typeof response.runId === "string" && response.runId !== "") {
            runIds.push(response.runId);
          }
          continue;
        }
        const failed: MagicBellFailedRecord = {
          index: record.index,
          errorCode: verdict.errorCode,
          retryable: verdict.retryable,
        };
        if (verdict.errorCode.startsWith("HTTP_")) {
          failed.statusCode = response.status;
        }
        if (verdict.errorMessage !== undefined) {
          failed.errorMessage = verdict.errorMessage;
        }
        failedRecords.push(failed);
      } catch (err) {
        failedRecords.push(toMagicBellFailedRecord(err, record.index));
      }
    }
    this.sent += sent;
    this.failed += failedRecords.length;
    if (failedRecords.length > 0) {
      this.sendFailures += 1;
      throw new MagicBellSinkError(
        `magicbell-sink: send failed for ${failedRecords.length} of ${resolved.length} messages`,
        failedRecords
      );
    }
    return { ok: true, sent, runIds };
  }
}

/**
 * Convert a client throw into a failed message: a codeless
 * transport failure (`TRANSPORT_ERROR`, retryable — the SQS
 * no-status rule).
 */
function toMagicBellFailedRecord(err: unknown, index: number): MagicBellFailedRecord {
  const failed: MagicBellFailedRecord = {
    index,
    errorCode: "TRANSPORT_ERROR",
    retryable: true,
  };
  if (err instanceof Error && err.message !== "") {
    failed.errorMessage = err.message;
  }
  return failed;
}
