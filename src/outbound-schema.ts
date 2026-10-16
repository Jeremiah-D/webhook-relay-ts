/**
 * Outbound payload JSON schema registry (WR-117).
 *
 * The mirror image of `src/schema.ts` (WR-41 inbound): a relay that fans
 * out to many downstreams cannot trust every producer (or every relay
 * stage) to emit the shape a downstream expects. The WR-115 payload
 * transform rewrites payloads on the way out — a misconfigured rename
 * can silently drop a field the downstream requires — and a poisoned
 * payload retried five times burns retry budget, backoff slots, and
 * dead-letter capacity on a delivery that could never succeed. The
 * outbound schema registry is a per-endpoint, pluggable, opt-in
 * admission gate on the payload shape *after* transformation:
 *
 * - Rules are keyed by EXACT `targetUrl` (no prefix matching) — the
 *   outbound config convention in this relay (WR-60 `tlsSniOverrides`,
 *   WR-42 H2 pool keys). Endpoints without a rule keep byte-exact
 *   current behavior; enabling the registry changes nothing for
 *   unlisted endpoints (default: off, zero behavior change).
 * - Pipeline order: transform (WR-115) -> schema (this module) -> gzip
 *   (WR-40/WR-75) -> E2EE sealing (WR-58) -> sign (WR-26). Validation
 *   runs on the post-transform JSON payload: compression and sealing
 *   produce non-JSON wire bytes, so the schema must precede them, and
 *   `x-relay-signature` covers the validated bytes — exactly what the
 *   downstream receives and verifies.
 * - A payload that fails validation is dead-lettered on the first
 *   attempt (`"non_retryable"` — see `src/failure.ts`) and audited as
 *   `schema_violation` on top of the usual `dead_letter` audit event.
 *   It burns no retry budget, trips no breaker, and the downstream is
 *   never contacted — never silently dropped.
 *
 * Schemas validate JSON: the post-transform payload bytes are parsed
 * before validation, and a non-JSON payload under a configured rule
 * fails with a schema violation (a JSON schema validator has nothing
 * to say about opaque bytes — the WR-41 convention). A throwing
 * validator is fail-closed — the delivery is dead-lettered, never
 * sent.
 *
 * Invalid rules throw `RangeError` at registry construction (startup)
 * — zero partial application: a bad record registers nothing and the
 * relay refuses to boot rather than running with a half-wired gate.
 *
 * The `PayloadSchema` shape is reused from `src/schema.ts` (`{ name,
 * version, validate }`) so one schema implementation can guard both
 * directions; the built-in `createRequiredFieldsSchema` there works
 * here unchanged.
 *
 * Zero dependencies (`node:` builtins only).
 */

/** Outcome of one schema validation (re-exported shape from WR-41). */
export type { SchemaCheck } from "./schema.ts";
/** A pluggable payload shape validator (re-exported from WR-41). */
export type { PayloadSchema } from "./schema.ts";
import type { PayloadSchema } from "./schema.ts";

/**
 * Structured delivery failure for an outbound schema violation. Thrown
 * by `OutboundSchemaRegistry.validatePayload` (invoked from
 * `buildWireRequest` in `src/server.ts`) so the retry queue can classify
 * without parsing error message strings — `classifyFailure` maps it to
 * `"non_retryable"` (see `src/failure.ts`), the WR-115
 * `PayloadTransformError` precedent.
 */
export class OutboundSchemaViolationError extends Error {
  /** The `targetUrl` whose payload failed validation. */
  readonly endpoint: string;
  /** `schema.name` of the rule that rejected the payload. */
  readonly schemaName: string;
  /** `schema.version` of the rule that rejected the payload. */
  readonly schemaVersion: string;

  constructor(endpoint: string, schema: PayloadSchema, message: string, options?: { cause?: unknown }) {
    super(
      `outbound schema validation failed for ${endpoint} (schema "${schema.name}" v${schema.version}): ${message}`,
      options
    );
    this.name = "OutboundSchemaViolationError";
    this.endpoint = endpoint;
    this.schemaName = schema.name;
    this.schemaVersion = schema.version;
  }
}

/**
 * Validate an outbound schema record (`{ "<exact targetUrl>":
 * PayloadSchema }`) at startup. Throws `RangeError` on anything that is
 * not a plain object, on empty or non-string keys, or on a schema
 * without a usable name/version/validate — fail fast, never
 * mid-delivery. `undefined` (feature off) is valid.
 */
export function assertValidOutboundSchemas(
  rules: Record<string, PayloadSchema> | undefined
): void {
  if (rules === undefined) return;
  if (typeof rules !== "object" || rules === null || Array.isArray(rules)) {
    throw new RangeError("outboundSchemas: expected a Record<exact targetUrl, PayloadSchema>");
  }
  for (const [targetUrl, schema] of Object.entries(rules)) {
    const where = `outboundSchemas[${JSON.stringify(targetUrl)}]`;
    if (targetUrl === "") {
      throw new RangeError(`${where}: targetUrl must be a non-empty exact target URL`);
    }
    if (!schema || typeof schema.name !== "string" || schema.name === "") {
      throw new RangeError(`${where}: schema needs a non-empty name`);
    }
    if (typeof schema.version !== "string" || schema.version === "") {
      throw new RangeError(`${where}: schema needs a non-empty version`);
    }
    if (typeof schema.validate !== "function") {
      throw new RangeError(`${where}: schema needs a validate method`);
    }
  }
}

/**
 * Per-endpoint outbound schema counters: validations that passed vs.
 * validations that failed (any failure mode — shape violation,
 * non-JSON payload, throwing validator — counts as `"invalid"`).
 */
export interface OutboundSchemaCounters {
  valid: number;
  invalid: number;
}

/**
 * Outbound schema counters by schema name/version and endpoint.
 * Renders to Prometheus exposition text; renders `""` when nothing was
 * recorded, keeping `GET /metrics` byte-identical for relays that never
 * enable outbound schema validation.
 */
export class OutboundSchemaMetrics {
  private readonly counters = new Map<string, { schema: PayloadSchema; endpoint: string } & OutboundSchemaCounters>();

  /**
   * Record one validation for `schema` on `endpoint`. `outcome` is
   * `"valid"` when the payload passed, `"invalid"` otherwise.
   */
  record(schema: PayloadSchema, endpoint: string, outcome: "valid" | "invalid"): void {
    const key = `${schema.name}\0${schema.version}\0${endpoint}`;
    let c = this.counters.get(key);
    if (!c) {
      c = { schema, endpoint, valid: 0, invalid: 0 };
      this.counters.set(key, c);
    }
    c[outcome] += 1;
  }

  /** Per-schema/per-endpoint snapshot (insertion order). */
  getStats(): Array<{ schemaName: string; schemaVersion: string; endpoint: string } & OutboundSchemaCounters> {
    return [...this.counters.values()].map((c) => ({
      schemaName: c.schema.name,
      schemaVersion: c.schema.version,
      endpoint: c.endpoint,
      valid: c.valid,
      invalid: c.invalid,
    }));
  }

  /** Prometheus text exposition (0.0.4) of the counters; `""` when empty. */
  render(): string {
    if (this.counters.size === 0) return "";
    const esc = (v: string): string => v.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, '\\"');
    const lines: string[] = [
      "# HELP relay_outbound_schema_total Outbound payload schema validations by schema, endpoint, and outcome.",
      "# TYPE relay_outbound_schema_total counter",
    ];
    for (const c of this.counters.values()) {
      const schema = esc(c.schema.name);
      const version = esc(c.schema.version);
      const endpoint = esc(c.endpoint);
      lines.push(
        `relay_outbound_schema_total{schema="${schema}",version="${version}",endpoint="${endpoint}",status="valid"} ${c.valid}`
      );
      lines.push(
        `relay_outbound_schema_total{schema="${schema}",version="${version}",endpoint="${endpoint}",status="invalid"} ${c.invalid}`
      );
    }
    return lines.join("\n") + "\n";
  }
}

/**
 * Stateful outbound schema registry (WR-117).
 *
 * Owns the lifecycle behind the `outboundSchemas` option: construction
 * validates every rule (`RangeError` fail-fast — a bad record registers
 * nothing), then request-time selection is an exact-`targetUrl` map
 * lookup, never throwing. The registry also owns the per-endpoint
 * counters (`metrics`), so one object carries the whole feature.
 */
export class OutboundSchemaRegistry {
  private readonly rules = new Map<string, PayloadSchema>();
  /** Per-schema/per-endpoint validation counters. */
  readonly metrics = new OutboundSchemaMetrics();

  constructor(rules?: Record<string, PayloadSchema>) {
    assertValidOutboundSchemas(rules);
    if (rules !== undefined) {
      for (const [targetUrl, schema] of Object.entries(rules)) {
        this.rules.set(targetUrl, schema);
      }
    }
  }

  /**
   * Whether `targetUrl` has a schema rule (exact match). The opt-in
   * gate: endpoints without rules keep the exact current behavior.
   * Never throws.
   */
  hasRules(targetUrl: string): boolean {
    return this.rules.has(targetUrl);
  }

  /**
   * The schema rule for an exact `targetUrl`, or `undefined` when none
   * is configured. Never throws.
   */
  select(targetUrl: string): PayloadSchema | undefined {
    return this.rules.get(targetUrl);
  }

  /**
   * Validate the post-transform payload bytes for `targetUrl` against
   * its rule. No-op (no metrics, no throw) when the endpoint has no
   * rule — the caller is expected to gate with `hasRules`, but the
   * no-rule path is safe by construction.
   *
   * The bytes are parsed as JSON first: a non-JSON payload under a
   * configured rule fails validation (WR-41 convention — a JSON schema
   * has nothing to say about opaque bytes). A validator that returns
   * `{ ok: false }` or throws fails the delivery, fail-closed. Every
   * validated payload records one counter (`"valid"` / `"invalid"`);
   * any failure throws `OutboundSchemaViolationError`, which
   * `classifyFailure` maps to `"non_retryable"`.
   */
  validatePayload(targetUrl: string, body: Buffer): void {
    const schema = this.rules.get(targetUrl);
    if (schema === undefined) return;
    const fail = (message: string, cause?: unknown): never => {
      this.metrics.record(schema, targetUrl, "invalid");
      throw new OutboundSchemaViolationError(targetUrl, schema, message, cause === undefined ? undefined : { cause });
    };
    let parsed: unknown;
    try {
      parsed = JSON.parse(body.toString("utf8"));
    } catch (err) {
      fail("payload is not JSON", err);
    }
    let check;
    try {
      check = schema.validate(parsed);
    } catch (err) {
      fail("validator threw (fail-closed)", err);
    }
    if (!check.ok) {
      const errors = Array.isArray(check.errors) ? check.errors : [];
      const detail = errors.length > 0 ? errors.slice(0, 10).join("; ") : "schema rejected the payload";
      fail(detail);
    }
    this.metrics.record(schema, targetUrl, "valid");
  }
}
