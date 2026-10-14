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
 *
 * Evolving a schema without breaking senders is the operator's job, and
 * the registry helps with an opt-in compatibility gate (WR-96): a rule
 * may declare `compatibilityCorpus` — the sample set of payloads the
 * endpoint historically accepted, either manually registered or
 * auto-accumulated from accepted payloads (bounded, oldest-first
 * eviction) — and at registration time the new validator is run against
 * every sample. Any rejected or throwing sample fails registration with
 * `RangeError` and registers nothing: the currently serving schema keeps
 * handling the pattern untouched (EB-95 convention). Registering a newer
 * schema version for the same pattern is gated the same way, against the
 * full corpus including samples accumulated while older versions served.
 * `InboundSchemaRegistry.getStats()` exposes the per-registration gate
 * result (`'passed'` / `'not-tested'`) and corpus size, and
 * `renderMetrics()` exposes them to Prometheus.
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
  /**
   * Opt-in compatibility corpus (WR-96): the sample set of payloads this
   * endpoint historically accepted. Either a plain array (manual
   * registration) or {@link CompatibilityCorpusOptions} (manual samples
   * plus optional auto-accumulation of accepted payloads). At registration
   * time the schema's validator is run against every sample; any rejected
   * or throwing sample fails registration with `RangeError` and registers
   * nothing — the previous schema for the pattern keeps serving
   * untouched (EB-95 convention). Omitted → the gate is skipped and
   * stats report `'not-tested'`.
   */
  compatibilityCorpus?: unknown[] | CompatibilityCorpusOptions;
}

/** Default bound on compatibility-corpus samples per endpoint pattern. */
export const DEFAULT_COMPAT_CORPUS_MAX_SAMPLES = 100;

/**
 * Opt-in compatibility-corpus configuration (WR-96), the object form of
 * `EndpointSchemaRule.compatibilityCorpus`.
 */
export interface CompatibilityCorpusOptions {
  /**
   * Manually registered sample payloads this endpoint previously
   * accepted (captured from production traffic or a shared fixture).
   * Bounded by `maxSamples`: more samples than the bound throw
   * `RangeError` at registration.
   */
  samples?: unknown[];
  /**
   * When true, every payload accepted for this rule's schema is recorded
   * into the corpus (deep-copied, oldest-first eviction past
   * `maxSamples`), so a *later* schema registration for the same pattern
   * is gated against real traffic the current schema accepted. Default
   * false. Accepted (never rejected) payloads only — a rejected payload
   * is not evidence of an accepted shape.
   */
  accumulate?: boolean;
  /**
   * Corpus bound: manual samples plus accumulated samples together may
   * not exceed this. Positive integer, default
   * {@link DEFAULT_COMPAT_CORPUS_MAX_SAMPLES}.
   */
  maxSamples?: number;
}

/** A compatibility corpus after validation and normalization. */
export interface NormalizedCompatibilityCorpus {
  /** Defensive copy of the manually registered samples. */
  manualSamples: unknown[];
  /** Whether accepted payloads accumulate into the corpus. */
  accumulate: boolean;
  /** Corpus bound (manual + accumulated). */
  maxSamples: number;
}

/**
 * Normalize and validate an opt-in compatibility corpus. Throws
 * `RangeError` when the value is neither an array nor a valid options
 * object, when `samples` is not an array, when `accumulate` is not a
 * boolean, when `maxSamples` is not a positive integer, or when the
 * manual samples exceed the bound — fail fast at registration, never
 * mid-request.
 */
export function assertValidCompatibilityCorpus(
  corpus: unknown[] | CompatibilityCorpusOptions | undefined,
  where: string
): NormalizedCompatibilityCorpus {
  if (corpus === undefined) {
    return { manualSamples: [], accumulate: false, maxSamples: DEFAULT_COMPAT_CORPUS_MAX_SAMPLES };
  }
  if (Array.isArray(corpus)) {
    if (corpus.length > DEFAULT_COMPAT_CORPUS_MAX_SAMPLES) {
      throw new RangeError(
        `${where}: compatibilityCorpus has ${corpus.length} samples, exceeding the bound of ${DEFAULT_COMPAT_CORPUS_MAX_SAMPLES} (set maxSamples explicitly to raise it)`
      );
    }
    return { manualSamples: [...corpus], accumulate: false, maxSamples: DEFAULT_COMPAT_CORPUS_MAX_SAMPLES };
  }
  if (typeof corpus !== "object" || corpus === null) {
    throw new RangeError(
      `${where}: compatibilityCorpus must be an array of payloads or an options object`
    );
  }
  const opts = corpus as CompatibilityCorpusOptions;
  const maxSamples = opts.maxSamples ?? DEFAULT_COMPAT_CORPUS_MAX_SAMPLES;
  if (!Number.isInteger(maxSamples) || maxSamples < 1) {
    throw new RangeError(`${where}: compatibilityCorpus.maxSamples must be a positive integer`);
  }
  if (opts.accumulate !== undefined && typeof opts.accumulate !== "boolean") {
    throw new RangeError(`${where}: compatibilityCorpus.accumulate must be a boolean`);
  }
  const samples = opts.samples ?? [];
  if (!Array.isArray(samples)) {
    throw new RangeError(`${where}: compatibilityCorpus.samples must be an array of payloads`);
  }
  if (samples.length > maxSamples) {
    throw new RangeError(
      `${where}: compatibilityCorpus has ${samples.length} samples, exceeding maxSamples=${maxSamples}`
    );
  }
  return {
    manualSamples: [...samples],
    accumulate: opts.accumulate ?? false,
    maxSamples,
  };
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
 * Gate result of one schema registration (WR-96): `'passed'` when the
 * registration ran the validator against a non-empty compatibility
 * corpus and every sample was accepted, `'not-tested'` when no corpus
 * was supplied. A failed gate never registers, so no persisted row ever
 * carries a failed result.
 */
export type CompatGateResult = "passed" | "not-tested";

/** One schema registration held by {@link InboundSchemaRegistry}. */
export interface SchemaRegistration {
  /** The endpoint pattern this schema owns. */
  pattern: string;
  /** The registered schema. */
  schema: PayloadSchema;
  /** Normalized corpus config of this registration. */
  corpus: NormalizedCompatibilityCorpus;
  /** Gate result recorded at registration time. */
  compatGate: CompatGateResult;
  /** Corpus samples the gate ran (0 when `compatGate` is `'not-tested'`). */
  compatCorpusSize: number;
  /** Epoch ms when a newer schema version superseded this registration. */
  supersededAt?: number;
}

/** Per-registration stats row from {@link InboundSchemaRegistry.getStats}. */
export interface SchemaRegistryStats {
  pattern: string;
  schemaName: string;
  schemaVersion: string;
  compatGate: CompatGateResult;
  /** Samples the registration-time gate ran. */
  compatCorpusSize: number;
  /** Current corpus size: manual samples + accumulated accepted payloads. */
  corpusSize: number;
  /** Whether a newer schema version superseded this registration. */
  superseded: boolean;
}

/**
 * Stateful inbound schema registry (WR-96).
 *
 * The registry owns the lifecycle behind `payloadSchemas`: registering a
 * rule validates it (pattern shape, schema shape, corpus shape — the same
 * `RangeError` fail-fast as `assertValidEndpointSchemaRules`), then runs
 * the opt-in compatibility gate *before* any registry state is touched,
 * so a failing gate registers nothing and leaves the currently serving
 * schema for the pattern completely untouched.
 *
 * The compatibility corpus belongs to the *endpoint pattern*: manual
 * samples registered per rule plus auto-accumulated accepted payloads
 * (bounded, oldest-first eviction). Registering a *new* schema version
 * for a pattern (a later rule with the same pattern but a different
 * schema name/version) is gated against the full corpus — including
 * samples accumulated while the older version served — and on success
 * supersedes the older registration (`supersededAt` is stamped; it stays
 * in stats for the audit trail but no longer matches requests).
 *
 * Request-time selection keeps the WR-41 semantics: first matching rule
 * in registration order wins, exact or prefix patterns, only active
 * (non-superseded) registrations match. WR-33 composition is the caller's
 * job — try the version-stripped path first, then the full path — exactly
 * as before; the registry itself matches plain patterns.
 */
export class InboundSchemaRegistry {
  private readonly registrations: SchemaRegistration[] = [];
  /** Auto-accumulated accepted payloads, keyed by endpoint pattern. */
  private readonly accumulated = new Map<string, unknown[]>();

  constructor(rules?: EndpointSchemaRule[]) {
    if (rules !== undefined) {
      for (const rule of rules) this.registerSchema(rule);
    }
  }

  /**
   * Register one `{ pattern, schema }` rule. Throws `RangeError` on an
   * invalid pattern/schema/corpus, on an exact duplicate (same pattern,
   * schema name, and schema version — registering the same thing twice is
   * a config bug, not a no-op), or when the compatibility gate rejects or
   * throws on any corpus sample. The gate runs before any registry
   * mutation: a failing registration is a zero-side-effect no-op — the
   * previously serving schema for the pattern is never stamped
   * superseded and never disturbed.
   */
  registerSchema(rule: EndpointSchemaRule): void {
    if (!rule || typeof rule.pattern !== "string" || rule.pattern === "" || !rule.pattern.startsWith("/")) {
      throw new RangeError(
        `schema registry: pattern must be a path starting with "/" (exact) or ending with "/*" (prefix)`
      );
    }
    const s = rule.schema;
    if (!s || typeof s.name !== "string" || s.name === "") {
      throw new RangeError(`schema registry: schema for ${rule.pattern} needs a non-empty name`);
    }
    if (typeof s.version !== "string" || s.version === "") {
      throw new RangeError(`schema registry: schema for ${rule.pattern} needs a non-empty version`);
    }
    if (typeof s.validate !== "function") {
      throw new RangeError(`schema registry: schema for ${rule.pattern} needs a validate method`);
    }
    const corpus = assertValidCompatibilityCorpus(rule.compatibilityCorpus, `pattern ${rule.pattern}`);
    const active = this.activeRegistration(rule.pattern);
    if (active !== undefined && active.schema.name === s.name && active.schema.version === s.version) {
      throw new RangeError(
        `schema registry: schema "${s.name}" version "${s.version}" is already registered for ${rule.pattern}`
      );
    }
    // Compatibility gate (WR-96, opt-in, EB-95 convention): run the new
    // validator against the endpoint's full corpus — the rule's manual
    // samples plus payloads auto-accumulated while older versions served.
    // Pure: touches no registry state, so a failure leaves everything as
    // it was. Any rejection or throw fails registration with RangeError.
    const gateCorpus = [...corpus.manualSamples, ...(this.accumulated.get(rule.pattern) ?? [])];
    const gate = this.checkCompatibility(rule.pattern, s, gateCorpus);
    // Gate passed (or skipped): mutate. A newer schema version for the
    // pattern supersedes the currently active registration — the
    // migration declares the window, so the newest operator intent wins.
    if (active !== undefined) {
      active.supersededAt = Date.now();
    }
    this.registrations.push({
      pattern: rule.pattern,
      schema: s,
      corpus,
      compatGate: gate.gate,
      compatCorpusSize: gate.samples,
    });
  }

  /**
   * Select the active schema registration for an inbound request path:
   * the first matching registration in registration order (exact or
   * prefix, segment-boundary, same as `selectEndpointSchema`), or
   * `undefined` when nothing matches (the caller skips validation).
   * Superseded registrations never match. Never throws.
   */
  select(pathname: string): SchemaRegistration | undefined {
    for (const reg of this.registrations) {
      if (reg.supersededAt !== undefined) continue;
      if (reg.pattern.endsWith("/*")) {
        const prefix = reg.pattern.slice(0, -2);
        if (pathname === prefix || pathname.startsWith(prefix + "/")) {
          return reg;
        }
      } else if (pathname === reg.pattern) {
        return reg;
      }
    }
    return undefined;
  }

  /**
   * Record one accepted payload for a registration's corpus. Only
   * registrations with `accumulate: true` keep samples; the rest are a
   * no-op. Payloads are deep-copied so later mutation of the request
   * object cannot corrupt the corpus, and oldest samples are evicted
   * past `maxSamples` (bounded by construction).
   */
  noteAcceptedPayload(reg: SchemaRegistration, payload: unknown): void {
    if (!reg.corpus.accumulate) return;
    const store = this.accumulated.get(reg.pattern) ?? [];
    store.push(structuredClone(payload));
    while (store.length > reg.corpus.maxSamples) store.shift();
    this.accumulated.set(reg.pattern, store);
  }

  /**
   * Per-registration stats: schema identity, the registration-time
   * compatibility gate result (`'passed'` when the gate ran against a
   * non-empty corpus, `'not-tested'` when no corpus was supplied), the
   * sample count the gate ran, the current corpus size (manual samples +
   * accumulated), and whether a newer version superseded the row.
   */
  getStats(): SchemaRegistryStats[] {
    return this.registrations.map((reg) => ({
      pattern: reg.pattern,
      schemaName: reg.schema.name,
      schemaVersion: reg.schema.version,
      compatGate: reg.compatGate,
      compatCorpusSize: reg.compatCorpusSize,
      corpusSize:
        reg.corpus.manualSamples.length + (this.accumulated.get(reg.pattern) ?? []).length,
      superseded: reg.supersededAt !== undefined,
    }));
  }

  /**
   * Prometheus exposition of the compatibility gate: one
   * `relay_inbound_schema_compat_gate{pattern,schema,version,gate}`
   * gauge (1) and one `relay_inbound_schema_corpus_size{pattern,schema,version}`
   * gauge per *active* registration with a corpus configured. Renders `""`
   * when no registration opted into a corpus, keeping `GET /metrics`
   * byte-identical for relays that never enable the gate.
   */
  renderMetrics(): string {
    const active = this.registrations.filter(
      (reg) =>
        reg.supersededAt === undefined &&
        (reg.corpus.manualSamples.length > 0 || reg.corpus.accumulate)
    );
    if (active.length === 0) return "";
    const esc = (v: string): string => v.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, '\\"');
    const lines: string[] = [
      "# HELP relay_inbound_schema_compat_gate Compatibility-gate result of the active inbound schema registration (1 when the gate passed at registration, labeled by outcome).",
      "# TYPE relay_inbound_schema_compat_gate gauge",
      "# HELP relay_inbound_schema_corpus_size Current compatibility-corpus sample count for the active inbound schema registration.",
      "# TYPE relay_inbound_schema_corpus_size gauge",
    ];
    for (const reg of active) {
      const pattern = esc(reg.pattern);
      const schema = esc(reg.schema.name);
      const version = esc(reg.schema.version);
      lines.push(
        `relay_inbound_schema_compat_gate{pattern="${pattern}",schema="${schema}",version="${version}",gate="${reg.compatGate}"} 1`
      );
      lines.push(
        `relay_inbound_schema_corpus_size{pattern="${pattern}",schema="${schema}",version="${version}"} ${
          reg.corpus.manualSamples.length + (this.accumulated.get(reg.pattern) ?? []).length
        }`
      );
    }
    return lines.join("\n") + "\n";
  }

  /** The active (non-superseded) registration for `pattern`, if any. */
  private activeRegistration(pattern: string): SchemaRegistration | undefined {
    for (const reg of this.registrations) {
      if (reg.pattern === pattern && reg.supersededAt === undefined) return reg;
    }
    return undefined;
  }

  /**
   * The compatibility gate itself (EB-95 convention): run `schema`'s
   * validator over every corpus sample. Any rejected sample or any
   * throwing sample throws `RangeError` naming the failing sample index.
   * An empty corpus skips the gate (`'not-tested'`). Pure — no registry
   * state is touched, so the caller can run it before mutating anything.
   */
  private checkCompatibility(
    pattern: string,
    schema: PayloadSchema,
    corpus: unknown[]
  ): { gate: CompatGateResult; samples: number } {
    if (corpus.length === 0) return { gate: "not-tested", samples: 0 };
    for (let i = 0; i < corpus.length; i++) {
      let check: SchemaCheck;
      try {
        check = schema.validate(corpus[i]);
      } catch {
        throw new RangeError(
          `schema registry: compatibility gate failed for ${pattern}: validator of "${schema.name}" version "${schema.version}" threw on corpus sample ${i} — nothing was registered`
        );
      }
      if (!check.ok) {
        throw new RangeError(
          `schema registry: compatibility gate failed for ${pattern}: validator of "${schema.name}" version "${schema.version}" rejected corpus sample ${i} — nothing was registered`
        );
      }
    }
    return { gate: "passed", samples: corpus.length };
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
