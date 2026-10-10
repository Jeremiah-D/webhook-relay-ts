/**
 * Inbound payload JSON schema registry (WR-41).
 *
 * A relay that fronts many upstreams cannot trust every sender to speak
 * the current payload shape: a payment provider's callback with a missing
 * `amount_cents` field is a sender bug, and letting it through burns
 * retry budget, breaker trips, and dead-letter slots on a message that
 * could never succeed downstream. The schema registry is a per-endpoint,
 * pluggable, opt-in admission gate on payload *shape*:
 *
 * - Rules match the inbound request path — exact (`/hooks/stripe`) or
 *   prefix (`/hooks/*`, which also matches `/hooks` itself) — and the
 *   first matching rule's schema validates the payload. Paths with no
 *   matching rule skip validation entirely, so enabling the registry
 *   changes nothing for unlisted endpoints (default: off, zero behavior
 *   change).
 * - Validation runs on the *verified, adapted* payload: signature
 *   verification (on the raw wire bytes the sender signed) and WR-33
 *   version adaptation (so a v1 payload reshaped into the current schema
 *   validates against the *current* schema) both happen first, and dedup
 *   / the retry queue only ever see payloads that passed. The ordering is
 *   verify -> version-adapt -> schema -> replay guard -> dedup -> enqueue.
 *   When a WR-33 version route matched, the schema rule is first tried
 *   against the endpoint path with the version prefix stripped — one
 *   `/hooks/*` rule covers `/v1/hooks/...` and `/v2/hooks/...` alike —
 *   then against the full inbound path, so per-version rules
 *   (`/v1/admin/*`) still work.
 * - A payload that fails validation is rejected with 400 and audited as
 *   `rejected` with reason `schema_failed` — it never enters the queue,
 *   so it consumes no retry budget, no breaker trips, and no dedup slots.
 * - The schema's name and version ride on both `accepted`
 *   (`schema`/`schemaVersion`) and `rejected` audit events, so a schema
 *   version change is visible in the audit trail without diffing config.
 *
 * Schemas validate JSON: the request body is parsed before validation,
 * and a non-JSON body fails with `schema_failed` (a JSON schema validator
 * has nothing to say about opaque bytes). A validator that throws is
 * fail-closed — the request is rejected, never admitted.
 */

/** Outcome of one schema validation. */
export interface SchemaCheck {
  /** Whether the payload satisfied the schema. */
  ok: boolean;
  /**
   * Human-readable violations, recorded in the audit event (bounded to
   * the first 10 by the server). Absent or empty when `ok` is true.
   */
  errors?: string[];
}

/**
 * A pluggable payload shape validator. `validate` receives the parsed
 * JSON of the verified (and, when WR-33 version routing matched, adapted)
 * request body, and must return `{ ok: true }` to admit the request. It
 * may throw to reject — a throwing validator is fail-closed, the request
 * is rejected with 400, never admitted. Validators must be synchronous:
 * they run on the request path.
 */
export interface PayloadSchema {
  /** Schema name recorded in audit events and metrics, e.g. `"payment-callback"`. */
  name: string;
  /**
   * Schema version recorded in audit events, e.g. `"3"`. Bump it when the
   * accepted shape changes — the version rides on every intake audit
   * event, so version changes are visible in the audit trail.
   */
  version: string;
  validate(payload: unknown): SchemaCheck;
}

/** One inbound path pattern and the schema that owns it. */
export interface EndpointSchemaRule {
  /** Request path pattern: exact (`/hooks/stripe`) or prefix (`/hooks/*`). */
  pattern: string;
  /** The schema trusted payloads for this endpoint must satisfy. */
  schema: PayloadSchema;
}

/**
 * Validate endpoint schema rules at startup. Throws RangeError on a
 * non-array, a pattern that is not a `/`-rooted path, or a schema without
 * a usable name/version/validate — fail fast, never mid-request.
 */
export function assertValidEndpointSchemaRules(rules: EndpointSchemaRule[] | undefined): void {
  if (rules === undefined) return;
  if (!Array.isArray(rules)) {
    throw new RangeError("payloadSchemas: expected an array of { pattern, schema } rules");
  }
  rules.forEach((rule, i) => {
    const where = `payloadSchemas[${i}]`;
    if (!rule || typeof rule.pattern !== "string" || rule.pattern === "" || !rule.pattern.startsWith("/")) {
      throw new RangeError(
        `${where}: pattern must be a path starting with "/" (exact) or ending with "/*" (prefix)`
      );
    }
    const s = rule.schema;
    if (!s || typeof s.name !== "string" || s.name === "") {
      throw new RangeError(`${where}: schema needs a non-empty name`);
    }
    if (typeof s.version !== "string" || s.version === "") {
      throw new RangeError(`${where}: schema needs a non-empty version`);
    }
    if (typeof s.validate !== "function") {
      throw new RangeError(`${where}: schema needs a validate method`);
    }
  });
}

/**
 * Select the schema rule for an inbound request path: the first matching
 * rule in config order, or `undefined` when nothing matches (the caller
 * skips validation). Never throws.
 */
export function selectEndpointSchema(
  pathname: string,
  rules: EndpointSchemaRule[] | undefined
): EndpointSchemaRule | undefined {
  if (rules === undefined) return undefined;
  for (const rule of rules) {
    if (rule.pattern.endsWith("/*")) {
      const prefix = rule.pattern.slice(0, -2);
      if (pathname === prefix || pathname.startsWith(prefix + "/")) {
        return rule;
      }
    } else if (pathname === rule.pattern) {
      return rule;
    }
  }
  return undefined;
}

/** One endpoint's schema intake counters. */
export interface SchemaCounters {
  accepted: number;
  rejected: number;
}

/**
 * Inbound intake counters by schema name. Renders to Prometheus exposition
 * text; renders `""` when nothing was recorded, keeping `GET /metrics`
 * byte-identical for relays that never enable the schema registry.
 */
export class SchemaMetrics {
  private readonly counters = new Map<string, SchemaCounters>();

  /** Record one intake for `schema` (`schema.name` of the matched rule). */
  record(schema: string, outcome: "accepted" | "rejected"): void {
    let c = this.counters.get(schema);
    if (!c) {
      c = { accepted: 0, rejected: 0 };
      this.counters.set(schema, c);
    }
    c[outcome] += 1;
  }

  /** Prometheus text exposition (0.0.4) of the counters; `""` when empty. */
  render(): string {
    if (this.counters.size === 0) return "";
    const esc = (v: string): string => v.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, '\\"');
    const lines: string[] = [
      "# HELP relay_inbound_schema_total Inbound webhook intakes by payload schema and admission outcome.",
      "# TYPE relay_inbound_schema_total counter",
    ];
    for (const [schema, c] of this.counters) {
      const s = esc(schema);
      lines.push(`relay_inbound_schema_total{schema="${s}",status="accepted"} ${c.accepted}`);
      lines.push(`relay_inbound_schema_total{schema="${s}",status="rejected"} ${c.rejected}`);
    }
    return lines.join("\n") + "\n";
  }
}

/**
 * A minimal built-in schema: the payload must be a JSON object carrying
 * every listed field (presence only — a field set to `null` or `0` still
 * counts as present). Enough for the common "required webhook fields"
 * gate; bring your own `PayloadSchema` for types, enums, or ranges.
 */
export function createRequiredFieldsSchema(
  name: string,
  version: string,
  requiredFields: string[]
): PayloadSchema {
  if (typeof name !== "string" || name === "") {
    throw new RangeError("createRequiredFieldsSchema: name must be a non-empty string");
  }
  if (typeof version !== "string" || version === "") {
    throw new RangeError("createRequiredFieldsSchema: version must be a non-empty string");
  }
  if (!Array.isArray(requiredFields) || requiredFields.some((f) => typeof f !== "string" || f === "")) {
    throw new RangeError("createRequiredFieldsSchema: requiredFields must be an array of non-empty strings");
  }
  const required = [...requiredFields];
  return {
    name,
    version,
    validate(payload: unknown): SchemaCheck {
      if (typeof payload !== "object" || payload === null || Array.isArray(payload)) {
        return { ok: false, errors: ["payload must be a JSON object"] };
      }
      const missing = required.filter((f) => !(f in payload));
      if (missing.length > 0) {
        return { ok: false, errors: missing.map((f) => `missing required field: ${f}`) };
      }
      return { ok: true };
    },
  };
}
