/**
 * WR-111: operator API route registry + OpenAPI 3.1 document generation.
 *
 * The operator surface (`handleOperator` in `src/server.ts`) used to list
 * its routes in three separate places — the split-plane gate
 * (`isOperatorPath`), the "not found" recognition check, and the
 * "method not allowed" check — with no single source of truth. This
 * module is that source: every operator route is declared once, with its
 * OpenAPI path template, its runtime matcher, its allowed methods, and
 * the parameters it accepts. `src/server.ts` derives both the 404
 * recognition check and the 405 method check from the registry, and
 * `GET /openapi.json` serves the generated document — so the spec can
 * only drift from the server if the registry itself is wrong, and the
 * snapshot test (`test/openapi.test.ts`) pins the registry's route
 * inventory to catch exactly that.
 *
 * Conventions (mirroring the server):
 * - Every route is behind the operator bearer token (`operatorToken` or
 *   an `operatorKeys` ring entry): 404 when no operator credential is
 *   configured (fail-closed), 403 on a bad bearer.
 * - WR-82 scopes: GET routes need the `read` scope, POST routes need
 *   `admin`. The spec records this as the `x-required-scope` vendor
 *   extension on each operation.
 *
 * Zero dependencies (pure data + string building).
 */

export type OperatorHttpMethod = "GET" | "POST";

/** One query parameter accepted by a route. All operator query params are optional. */
export interface OperatorRouteQueryParam {
  name: string;
  type: "string" | "integer" | "boolean";
  description: string;
  /** Allowed values, when the server validates against an enum. */
  enum?: string[];
  /** Notes on repeated/edge behavior the server implements. */
  note?: string;
}

/** One `{param}` segment of an OpenAPI path template. Always required. */
export interface OperatorRoutePathParam {
  name: string;
  description: string;
  enum?: string[];
}

/** The JSON request body a POST route accepts. */
export interface OperatorRouteBody {
  description: string;
  required: string[];
  properties: Record<
    string,
    { type: string; description: string; items?: { type: string }; enum?: string[] }
  >;
}

export interface OperatorRoute {
  /**
   * OpenAPI path template, e.g. `/dead-letter/{id}/replay`.
   */
  path: string;
  /**
   * Runtime matcher. Must accept exactly the pathnames the server
   * dispatches for this route — anchored, no partial matches.
   */
  pattern: RegExp;
  methods: OperatorHttpMethod[];
  summary: string;
  description: string;
  /** What a 200 response carries (shape summary, not a full schema). */
  okDescription: string;
  queryParams?: OperatorRouteQueryParam[];
  pathParams?: OperatorRoutePathParam[];
  requestBody?: OperatorRouteBody;
}

const exact = (path: string): RegExp =>
  new RegExp(`^${path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`);

/**
 * The full operator route inventory. Order is documentation order
 * (dead letters, audit, observability, replay control, config, misc);
 * runtime matching is order-independent — no two patterns overlap.
 */
export const OPERATOR_ROUTES: readonly OperatorRoute[] = [
  {
    path: "/dead-letter",
    pattern: exact("/dead-letter"),
    methods: ["GET"],
    summary: "List dead-letter entries (metadata only)",
    description:
      "Live dead-letter queue entries. Payloads are never exposed here — only metadata (id, targetUrl, attempts, lastError, deadLetteredAt, payloadBytes, encrypted flag).",
    okDescription: "JSON array of dead-letter entry metadata objects.",
    queryParams: [
      {
        name: "tenant",
        type: "string",
        description: "Restrict the list to one tenant's entries.",
      },
    ],
  },
  {
    path: "/dead-letter/stats",
    pattern: exact("/dead-letter/stats"),
    methods: ["GET"],
    summary: "Dead-letter queue statistics",
    description:
      "WR-64 observability: live entry count, retention purges so far, and live entries per logical endpoint.",
    okDescription: "JSON object with live/retention/per-endpoint counters.",
  },
  {
    path: "/dead-letter/replay",
    pattern: exact("/dead-letter/replay"),
    methods: ["POST"],
    summary: "Batch-replay dead letters",
    description:
      "WR-23: replay dead letters back into the delivery queue with a fresh retry budget, grouped per endpoint. `dryRun: true` returns the would-be-replayed metadata with zero side effects (nothing re-queued, nothing audited, payloads never touched).",
    okDescription:
      "`{ replayed, failed }`, or `{ dryRun: true, entries: [...] }` for a dry run.",
    requestBody: {
      description: "Replay filter; all fields optional.",
      required: [],
      properties: {
        endpoint: { type: "string", description: "Only replay entries for this target URL." },
        tenant: { type: "string", description: "Only replay this tenant's entries." },
        ids: {
          type: "array",
          items: { type: "string" },
          description: "Only replay these dead-letter ids; unknown ids are an explicit error.",
        },
        dryRun: { type: "boolean", description: "Preview only: return metadata, change nothing." },
      },
    },
  },
  {
    path: "/dead-letter/{id}/replay",
    pattern: /^\/dead-letter\/([^/]+)\/replay$/,
    methods: ["POST"],
    summary: "Replay one dead letter",
    description:
      "Re-queue a single dead-letter entry with a fresh retry budget. Audited as `dead_letter_replayed`.",
    okDescription: "`{ id, replayed: true }`, or 404 for an unknown id.",
    pathParams: [{ name: "id", description: "The dead-letter entry id." }],
  },
  {
    path: "/dead-letter/auto-replay/status",
    pattern: exact("/dead-letter/auto-replay/status"),
    methods: ["GET"],
    summary: "Dead-letter auto-replay status",
    description:
      "WR-31: status of the opt-in scheduled dead-letter replayer. Readable even when never configured (`enabled: false` explains the empty control surface).",
    okDescription:
      "`{ enabled, paused, stopped, consecutiveEmptyRounds, totalReplayed, lastRunAt, nextRunAt }`.",
  },
  {
    path: "/dead-letter/auto-replay/pause",
    pattern: exact("/dead-letter/auto-replay/pause"),
    methods: ["POST"],
    summary: "Pause dead-letter auto-replay",
    description:
      "Freeze the auto-replay schedule with state retained: a pending round is cancelled, but the rounds counter and totals survive for resume.",
    okDescription: "`{ paused: true }`, or 404 when auto-replay is not configured.",
  },
  {
    path: "/dead-letter/auto-replay/resume",
    pattern: exact("/dead-letter/auto-replay/resume"),
    methods: ["POST"],
    summary: "Resume dead-letter auto-replay",
    description:
      "Resume a paused scheduler. Resuming a rounds-exhausted scheduler is the operator's explicit “try again”: the counter resets to 0 and the schedule restarts.",
    okDescription: "`{ paused: false, restarted }`, or 404 when auto-replay is not configured.",
  },
  {
    path: "/dead-letter/auto-replay/trigger",
    pattern: exact("/dead-letter/auto-replay/trigger"),
    methods: ["POST"],
    summary: "Trigger one auto-replay round now",
    description:
      "Run one replay round immediately, outside the schedule, through the same accounting as a scheduled round (it can itself trigger the rounds-exhausted stop).",
    okDescription: "`{ replayed, failed, consecutiveEmptyRounds, stopped }`.",
  },
  {
    path: "/audit",
    pattern: exact("/audit"),
    methods: ["GET"],
    summary: "Query the delivery audit log",
    description:
      "WR-04: read the append-only audit trail (accepted / delivered / retrying / dead_letter / rejected / operator actions …) filtered by event, endpoint, tenant, trace id, and time range.",
    okDescription: "JSON array of audit events, oldest first.",
    queryParams: [
      {
        name: "event",
        type: "string",
        description: "Filter to these audit event kinds.",
        note: "Repeatable: ?event=delivered&event=dead_letter.",
      },
      { name: "endpoint", type: "string", description: "Filter to one target URL." },
      { name: "tenant", type: "string", description: "Filter to one tenant." },
      { name: "traceId", type: "string", description: "Filter to one end-to-end trace." },
      { name: "since", type: "string", description: "ISO-8601 lower bound (inclusive)." },
      { name: "until", type: "string", description: "ISO-8601 upper bound (inclusive)." },
      { name: "limit", type: "integer", description: "Max events to return (positive integer)." },
    ],
  },
  {
    path: "/audit/verify",
    pattern: exact("/audit/verify"),
    methods: ["GET"],
    summary: "Verify the audit log hash chain",
    description:
      "WR-77: tamper-evidence report for the audit log's hash chain — recomputes every link and reports the first break, if any.",
    okDescription: "JSON tamper-evidence report (`{ ok, ... }`).",
  },
  {
    path: "/latency",
    pattern: exact("/latency"),
    methods: ["GET"],
    summary: "Delivery latency distributions",
    description:
      "WR-13: per-endpoint accepted→delivered latency distributions (p50/p95/p99, min/max/mean) and SLO attainment, sampled into a bounded rolling window.",
    okDescription: "JSON object keyed by endpoint with latency summaries.",
    queryParams: [
      { name: "endpoint", type: "string", description: "Restrict to one target URL." },
      { name: "tenant", type: "string", description: "Restrict to one tenant." },
    ],
  },
  {
    path: "/slo-risk",
    pattern: exact("/slo-risk"),
    methods: ["GET"],
    summary: "SLO-breach early-warning snapshot",
    description:
      "WR-71: one row per endpoint with at least one risk evaluation — the early-warning view over latency SLO burn.",
    okDescription: "JSON array of per-endpoint risk rows.",
    queryParams: [{ name: "tenant", type: "string", description: "Restrict to one tenant." }],
  },
  {
    path: "/quorum",
    pattern: exact("/quorum"),
    methods: ["GET"],
    summary: "Fan-out acknowledgement progress",
    description:
      "WR-106: per-fanout acknowledgement progress (`fanoutId`, `endpoint`, `targets`, `acked`, `status`, lost targets), in dispatch order.",
    okDescription: "JSON array of per-fanout progress objects.",
  },
  {
    path: "/quorum/stats",
    pattern: exact("/quorum/stats"),
    methods: ["GET"],
    summary: "Fan-out acknowledgement progress with retention stats",
    description:
      "WR-109: object-shaped companion to the array-shaped `GET /quorum` (whose array response is pinned by clients): the same per-fanout progress plus the cumulative retention-eviction count.",
    okDescription: "`{ fanouts: [...], evicted }`.",
  },
  {
    path: "/usage",
    pattern: exact("/usage"),
    methods: ["GET"],
    summary: "Tenant usage metering snapshot",
    description:
      "WR-78: rolling-window per-tenant counters (delivered/failed/retried/dead_letter, bytes_in/bytes_out, urgent) for usage-based billing. 404 when the usage meter is not configured.",
    okDescription: "JSON object keyed by tenant with usage counters.",
    queryParams: [{ name: "tenant", type: "string", description: "Restrict to one tenant." }],
  },
  {
    path: "/health/summary",
    pattern: exact("/health/summary"),
    methods: ["GET"],
    summary: "Operator health dashboard",
    description:
      "WR-87: one human-readable aggregate over the relay's health signals — per-endpoint circuit state and consecutive-failure streaks, quota exhaustion, downstream probe state, global retry-budget headroom, and the top-N tenants by delivery volume. Pure read aggregation with zero write impact.",
    okDescription: "JSON health summary object.",
  },
  {
    path: "/events",
    pattern: exact("/events"),
    methods: ["GET"],
    summary: "Live delivery-event stream (SSE)",
    description:
      "WR-16: `text/event-stream` of delivery lifecycle events (`delivered` / `retrying` / `dead_letter`) as they happen, with periodic `: ping` heartbeats. Slow consumers (buffer > 1MiB) are disconnected.",
    okDescription: "Server-sent event stream; each event is a JSON delivery event.",
  },
  {
    path: "/events/archive",
    pattern: exact("/events/archive"),
    methods: ["GET"],
    summary: "Query the persistent delivery-event archive",
    description:
      "WR-55: queryable history of past delivery events. 404 when the archive is not configured (without leaking its existence to unauthenticated callers — the operator guard runs first).",
    okDescription: "JSON array of archived delivery events.",
    queryParams: [
      {
        name: "event",
        type: "string",
        description: "Filter to one event kind.",
        enum: ["delivered", "retrying", "dead_letter"],
      },
      { name: "since", type: "string", description: "ISO-8601 lower bound (inclusive)." },
      { name: "until", type: "string", description: "ISO-8601 upper bound (inclusive)." },
      {
        name: "endpoint",
        type: "string",
        description: "Exact match on the event's target URL (no substring matching).",
      },
    ],
  },
  {
    path: "/metrics",
    pattern: exact("/metrics"),
    methods: ["GET"],
    summary: "Prometheus metrics exposition",
    description:
      "Hand-rolled Prometheus 0.0.4 exposition (zero dependencies): per-endpoint delivered/failed/retried/dead_letter counters, circuit state, latency histograms, mesh counters, and every other subsystem's series. Served as `text/plain; version=0.0.4`.",
    okDescription: "Prometheus text exposition.",
  },
  {
    path: "/config/endpoint",
    pattern: exact("/config/endpoint"),
    methods: ["POST"],
    summary: "Hot-reload one endpoint's runtime config",
    description:
      "WR-32: update concurrency caps, breaker thresholds, quotas, and backoff parameters for one endpoint at runtime. The patch is validated before anything is applied — a 400 always means “nothing changed”. Applied changes are audited as `endpoint_config_updated`.",
    okDescription: "`{ endpoint, tenant?, changes }`.",
    requestBody: {
      description: "`endpoint` selects the target; every other field is a config patch.",
      required: ["endpoint"],
      properties: {
        endpoint: { type: "string", description: "Target URL of the endpoint to reconfigure." },
        tenant: { type: "string", description: "Scope the patch to this tenant's instance." },
      },
    },
  },
  {
    path: "/config/snapshot",
    pattern: exact("/config/snapshot"),
    methods: ["GET", "POST"],
    summary: "Declarative config snapshot export/apply",
    description:
      "WR-88: `GET` exports the current declarative config (`{ snapshot }`, read scope); `POST` applies a snapshot (`{ snapshot, dryRun? }`, admin scope) item by item through the imperative setter, rolling back to the pre-apply state on any mid-apply failure. Secret-bearing inventory refuses the whole apply fail-closed when it diverged; snapshots carry identifiers only, never key bytes.",
    okDescription:
      "GET: `{ snapshot }`. POST: the apply result, or `{ dryRun: true, plan }` for a dry run.",
    requestBody: {
      description: "POST body. `snapshot` is required; `dryRun` previews without mutating.",
      required: ["snapshot"],
      properties: {
        snapshot: { type: "object", description: "Declarative config snapshot (see GET shape)." },
        dryRun: { type: "boolean", description: "Return the apply plan without mutating anything." },
      },
    },
  },
  {
    path: "/routing/rules",
    pattern: exact("/routing/rules"),
    methods: ["GET", "POST"],
    summary: "Content-based routing rules",
    description:
      "WR-84: `GET` lists the live content-routing table (`{ rules, defaultTargetUrl }`, read scope); `POST` replaces it wholesale (`{ rules: [...], defaultTargetUrl? }`, admin scope). A 400 always means “nothing changed”; a successful replacement is audited as `routing_rules_updated`.",
    okDescription: "`{ rules, defaultTargetUrl? }`.",
    requestBody: {
      description: "POST body: the replacement rule table.",
      required: ["rules"],
      properties: {
        rules: {
          type: "array",
          items: { type: "object" },
          description: "Content-route rules (validated before the swap).",
        },
        defaultTargetUrl: { type: "string", description: "Fallback target when no rule matches." },
      },
    },
  },
  {
    path: "/endpoints/pause",
    pattern: exact("/endpoints/pause"),
    methods: ["POST"],
    summary: "Pause an endpoint",
    description:
      "WR-50: park an endpoint's deliveries — queued items stay queued, new events park, nothing is attempted, budgeted, or dead-lettered. Unknown endpoints are a fail-closed 404 (pausing a typo must be loud). Audited as `endpoint_paused`.",
    okDescription: "`{ endpoint, paused: true }`.",
    requestBody: {
      description: "Names the endpoint to pause.",
      required: ["endpoint"],
      properties: {
        endpoint: { type: "string", description: "Target URL of the endpoint to pause." },
      },
    },
  },
  {
    path: "/endpoints/resume",
    pattern: exact("/endpoints/resume"),
    methods: ["POST"],
    summary: "Resume an endpoint",
    description:
      "WR-50: re-arm a paused endpoint's deliveries with their remaining delays. Audited as `endpoint_resumed`.",
    okDescription: "`{ endpoint, paused: false }`.",
    requestBody: {
      description: "Names the endpoint to resume.",
      required: ["endpoint"],
      properties: {
        endpoint: { type: "string", description: "Target URL of the endpoint to resume." },
      },
    },
  },
  {
    path: "/scheduled",
    pattern: exact("/scheduled"),
    methods: ["GET"],
    summary: "List pending scheduled deliveries",
    description:
      "WR-57: pending scheduled deliveries — operator metadata only (id, targetUrl, deliverAt, traceId, tenant, priority). Payloads are never exposed. Recurring cron schedules are included with `recurring: true` plus `cron` / `nextAt` / `paused`.",
    okDescription: "JSON array of scheduled-delivery metadata objects.",
  },
  {
    path: "/scheduled/{id}/{action}",
    pattern: /^\/scheduled\/([^/]+)\/(pause|resume)$/,
    methods: ["POST"],
    summary: "Pause or resume a recurring schedule",
    description:
      "WR-80: pause/resume a recurring cron schedule. Pausing stops occurrence generation (already-generated deliveries are unaffected); resuming computes the next occurrence from now — missed cycles are skipped, never backfilled. Unknown schedule ids are a fail-closed 404; transitions are audited.",
    okDescription: "`{ id, paused }`.",
    pathParams: [
      { name: "id", description: "The schedule id." },
      { name: "action", description: "The transition to apply.", enum: ["pause", "resume"] },
    ],
  },
  {
    path: "/deliveries/{traceId}",
    pattern: /^\/deliveries\/([^/]+)$/,
    methods: ["GET"],
    summary: "Per-trace delivery lifecycle snapshot",
    description:
      "WR-43: aggregate the audit trail for one trace id into `{ state, timeline, attempts, lastError, latencyMs, retry trajectory, replay records }`. 404 for an unknown trace id.",
    okDescription: "JSON delivery-lifecycle snapshot.",
    pathParams: [{ name: "traceId", description: "The end-to-end trace id." }],
  },
  {
    path: "/openapi.json",
    pattern: exact("/openapi.json"),
    methods: ["GET"],
    summary: "OpenAPI 3.1 document for this operator API",
    description:
      "WR-111: the machine-readable operator API surface, generated from the route registry — the same registry the server's 404/405 dispatch reads, so the document cannot drift from the live routes. Same operator authentication as every other operator endpoint (fail-closed 404 without an operator credential).",
    okDescription: "The OpenAPI 3.1.0 document as JSON.",
  },
];

/** The route whose pattern accepts this pathname, regardless of method. */
export function findOperatorRoute(pathname: string): OperatorRoute | undefined {
  return OPERATOR_ROUTES.find((route) => route.pattern.test(pathname));
}

/** The route for this (pathname, method) pair — `undefined` means 404 or 405. */
export function matchOperatorRoute(
  pathname: string,
  method: string
): OperatorRoute | undefined {
  const route = findOperatorRoute(pathname);
  if (route === undefined) return undefined;
  return (route.methods as string[]).includes(method) ? route : undefined;
}

/** The operator scope a method needs: GET is read-only, POST is mutating (WR-82). */
export function requiredScopeForMethod(method: OperatorHttpMethod): "read" | "admin" {
  return method === "GET" ? "read" : "admin";
}

function schemaForParam(param: OperatorRouteQueryParam): Record<string, unknown> {
  const schema: Record<string, unknown> = { type: param.type };
  if (param.enum !== undefined) schema.enum = param.enum;
  return schema;
}

/**
 * Generate the OpenAPI 3.1.0 document for the operator API from the
 * registry. Deterministic: the same registry always renders the same
 * document (field order follows declaration order).
 */
export function buildOpenApiDocument(): Record<string, unknown> {
  const paths: Record<string, unknown> = {};
  for (const route of OPERATOR_ROUTES) {
    const pathItem: Record<string, unknown> = {};
    for (const method of route.methods) {
      const scope = requiredScopeForMethod(method);
      const parameters: Record<string, unknown>[] = [];
      for (const p of route.pathParams ?? []) {
        parameters.push({
          name: p.name,
          in: "path",
          required: true,
          description: p.description,
          ...(p.enum !== undefined ? { schema: { type: "string", enum: p.enum } } : { schema: { type: "string" } }),
        });
      }
      for (const q of route.queryParams ?? []) {
        const description =
          q.note !== undefined ? `${q.description} ${q.note}` : q.description;
        parameters.push({
          name: q.name,
          in: "query",
          required: false,
          description,
          schema: schemaForParam(q),
        });
      }
      const operation: Record<string, unknown> = {
        summary: route.summary,
        description: `${route.description}\n\nRequired operator scope: \`${scope}\`.`,
        "x-required-scope": scope,
        ...(parameters.length > 0 ? { parameters } : {}),
        ...(route.requestBody !== undefined
          ? {
              requestBody: {
                required: true,
                description: route.requestBody.description,
                content: {
                  "application/json": {
                    schema: {
                      type: "object",
                      required: route.requestBody.required,
                      properties: Object.fromEntries(
                        Object.entries(route.requestBody.properties).map(([name, prop]) => [
                          name,
                          {
                            type: prop.type,
                            description: prop.description,
                            ...(prop.items !== undefined ? { items: prop.items } : {}),
                            ...(prop.enum !== undefined ? { enum: prop.enum } : {}),
                          },
                        ])
                      ),
                    },
                  },
                },
              },
            }
          : {}),
        responses: {
          "200": { description: route.okDescription },
          "400": { description: "Malformed request (bad query params or JSON body)." },
          "401": { description: "Missing bearer token where the route needs one (mTLS gates)." },
          "403": { description: "Bad bearer token, or the key's scopes do not cover this operation." },
          "404": {
            description:
              "No operator credential is configured (fail-closed); unknown path or id.",
          },
          "405": { description: "Method not allowed for this path." },
        },
        security: [{ operatorToken: [] as string[] }],
      };
      pathItem[method.toLowerCase()] = operation;
    }
    paths[route.path] = pathItem;
  }
  return {
    openapi: "3.1.0",
    info: {
      title: "webhook-relay-ts operator API",
      // Matches package.json; bump together with the package version.
      version: "0.1.0",
      description:
        "Operator control plane for webhook-relay-ts: dead letters, audit, observability, replay control, and runtime configuration. " +
        "Every route requires the operator bearer token (`operatorToken` or an `operatorKeys` ring entry); " +
        "the plane answers 404 when no operator credential is configured. " +
        "Generated from the server's own route registry (WR-111), so this document cannot drift from the live dispatch.",
    },
    paths,
    components: {
      securitySchemes: {
        operatorToken: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "opaque",
          description:
            "The configured `operatorToken`, or any `operatorKeys` ring entry's key, as an HTTP Bearer token. " +
            "GET operations need the `read` scope, POST operations need `admin` (WR-82); the legacy single token carries full `admin` semantics.",
        },
      },
    },
    security: [{ operatorToken: [] as string[] }],
  };
}
