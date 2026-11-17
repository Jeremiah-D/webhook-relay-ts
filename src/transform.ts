/**
 * WR-115: per-endpoint payload transform, applied before delivery.
 *
 * Some downstreams speak a different dialect than the producer: a payment
 * gateway that wants `amount_cents` instead of `amount`, a ledger hook
 * that requires a static `x-tenant` header, an event bus that needs the
 * relay's delivery id echoed back as a header. `PayloadTransformer` holds
 * opt-in, per-endpoint transform rules keyed by the delivery `targetUrl`
 * and rewrites the JSON payload (and the outbound header set) just
 * before the wire request is built.
 *
 * Where it runs: at the top of `buildWireRequest` in `src/server.ts` —
 * after the payload is final (including WR-09 batch envelopes, which are
 * transformed as one merged JSON document) and *before* compression
 * (WR-40/WR-75), E2EE sealing (WR-58), and signing (WR-26). The signature
 * therefore always covers the transformed bytes — exactly what the
 * downstream receives. Endpoints without rules keep the exact current
 * behavior (opt-in; the input buffer is returned untouched).
 *
 * Capabilities:
 *
 * - `fieldRenames`: `{ "a.b": "c.d" }` — move the value at `from` to
 *   `to` (dot-separated paths, numeric segments address array elements,
 *   e.g. `items.0.sku`; intermediate objects/arrays on the `to` side are
 *   created). Missing `from` paths are no-ops.
 * - `fieldDeletes`: `["card_number"]` — drop fields. Missing paths are
 *   no-ops.
 * - `fieldMaps`: `{ "dest": "src" }` — copy the value at `src` to `dest`,
 *   keeping the source (rename moves, map copies).
 * - `constants`: `{ "source": "relay", "meta.v": 1 }` — set a path to a
 *   constant JSON value, creating intermediates as needed.
 * - `headerInjections`: `{ "x-event-id": "evt-{{event_id}}" }` — stamp
 *   outbound headers. Values are static strings or templates using the
 *   `{{variable}}` syntax (see below). Injected headers are
 *   downstream-only: any inbound header with the same name is stripped
 *   before stamping (the WR-26 anti-forgery pattern), and reserved
 *   relay/transport names are rejected at construction.
 *
 * Template variables (rendered per attempt):
 *
 * - `{{event_id}}` — the delivery id (`RetryItem.id`).
 * - `{{endpoint}}` — the delivery `targetUrl`.
 * - `{{attempt}}` — the 1-based attempt number about to be dispatched.
 * - `{{timestamp}}` — ISO-8601 render time (UTC).
 *
 * Failure semantics: templates are compiled at construction — an
 * unclosed `{{`, a stray `}}`, or an unknown variable throws
 * `TemplateError` at startup, never mid-delivery. A payload that is not
 * JSON, or any other runtime failure, throws `PayloadTransformError`,
 * which `classifyFailure` (see `src/failure.ts`) maps to
 * `"non_retryable"`: the item is dead-lettered on the first attempt
 * without burning the retry budget, and the server audits
 * `transform_failed` (event id, error, endpoint). Nothing is silently
 * dropped. Invalid rule shapes/values throw `RangeError` at
 * construction — never mid-request.
 *
 * The input value is never mutated — the transform works on a deep
 * clone. A transformed payload is serialized as canonical JSON
 * (`JSON.stringify`, no whitespace): when rules exist for an endpoint,
 * the wire body is the canonical form, not the producer's original
 * whitespace.
 */

/** Thrown for an illegal template (unclosed braces / unknown variable). */
export class TemplateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TemplateError";
  }
}

/**
 * Thrown when a configured transform cannot run for a delivery —
 * typically a non-JSON payload. Classified `"non_retryable"` by
 * `classifyFailure`, so the queue dead-letters the item immediately
 * and the server audits `transform_failed`.
 */
export class PayloadTransformError extends Error {
  /** The `targetUrl` whose transform failed. */
  readonly endpoint: string;
  constructor(endpoint: string, message: string, options?: { cause?: unknown }) {
    super(`payload transform failed for ${endpoint}: ${message}`, options);
    this.name = "PayloadTransformError";
    this.endpoint = endpoint;
  }
}

/** Template render context — one attempt of one delivery. */
export interface TransformContext {
  /** Delivery id (`RetryItem.id`). */
  eventId: string;
  /** Delivery `targetUrl`. */
  endpoint: string;
  /** 1-based attempt number about to be dispatched. */
  attempt: number;
  /** ISO-8601 render time (UTC). */
  timestamp: string;
}

/** Transform rules for one endpoint. Every field is optional. */
export interface PayloadTransformRules {
  /**
   * Field renames (move): `{ "from.path": "to.path" }`. The value is
   * moved — the source is deleted. Missing sources are no-ops;
   * intermediates on the target side are created.
   */
  fieldRenames?: Record<string, string>;
  /** Field deletions: dot paths to drop. Missing paths are no-ops. */
  fieldDeletes?: string[];
  /**
   * Field maps (copy): `{ "to.path": "from.path" }` — like renames, but
   * the source is kept. Missing sources are no-ops.
   */
  fieldMaps?: Record<string, string>;
  /**
   * Constant injection: `{ "path": value }` — set the path to a JSON
   * literal, creating intermediates as needed. Values must be
   * JSON-shaped (finite numbers, strings, booleans, null, arrays,
   * plain objects).
   */
  constants?: Record<string, unknown>;
  /**
   * Outbound header injection: `{ "x-name": "static or {{template}}" }`.
   * Rendered per attempt with the delivery's {@link TransformContext}.
   * Names should carry an `x-` prefix by convention; relay-owned and
   * transport headers are rejected at construction.
   */
  headerInjections?: Record<string, string>;
}

/**
 * A live payload-transform patch (WR-432): exact `targetUrl` → new
 * transform rules, or `null` to clear that endpoint's rules. Endpoints
 * omitted from the patch keep their live rules.
 */
export type PayloadTransformsRevision = Record<string, PayloadTransformRules | null>;

/** One endpoint's rule change, as returned by `PayloadTransformer.revise`. */
export interface PayloadTransformsRevisionChange {
  /** The endpoint whose rules changed. */
  endpoint: string;
  /** The live raw rules before the revision (`null` = no rules were live). */
  previous: PayloadTransformRules | null;
  /** The live raw rules after the revision (`null` = rules cleared). */
  current: PayloadTransformRules | null;
}

/** The four template variables WR-115 supports. */
const TEMPLATE_VARS = new Set(["event_id", "endpoint", "attempt", "timestamp"]);

/** Segments that would allow prototype pollution — never valid in a path. */
const FORBIDDEN_SEGMENTS = new Set(["__proto__", "constructor", "prototype"]);

/**
 * Relay-owned or transport headers a transform may never inject —
 * stamping these would collide with (or forge) the relay's own wire
 * accounting. Compared case-insensitively.
 */
const RESERVED_HEADERS = new Set([
  "x-relay-signature",
  "x-relay-key-id",
  "x-trace-id",
  "traceparent",
  "tracestate",
  "x-relay-idempotency-key",
  "x-relay-hops",
  "x-relay-encryption",
  "x-tenant-id",
  "content-length",
  "content-encoding",
  "transfer-encoding",
  "host",
  "connection",
]);

function checkPath(path: unknown, what: string): string[] {
  if (typeof path !== "string" || path.length === 0) {
    throw new RangeError(`${what} must be a non-empty string, got ${JSON.stringify(path)}`);
  }
  const segments = path.split(".");
  for (const seg of segments) {
    if (seg.length === 0) {
      throw new RangeError(`${what} ${JSON.stringify(path)}: empty segment`);
    }
    if (FORBIDDEN_SEGMENTS.has(seg)) {
      throw new RangeError(`${what} ${JSON.stringify(path)}: forbidden segment ${JSON.stringify(seg)}`);
    }
  }
  return segments;
}

function checkHeaderName(name: unknown): string {
  if (typeof name !== "string" || !/^[A-Za-z0-9][A-Za-z0-9-]*$/.test(name) || name.length > 200) {
    throw new RangeError(
      `header-injection name must be a valid HTTP token (<=200 chars), got ${JSON.stringify(name)}`
    );
  }
  if (RESERVED_HEADERS.has(name.toLowerCase())) {
    throw new RangeError(`header-injection name ${JSON.stringify(name)} is reserved by the relay`);
  }
  return name;
}

function checkJsonValue(value: unknown, what: string): void {
  if (value === null) return;
  const t = typeof value;
  if (t === "string" || t === "boolean") return;
  if (t === "number") {
    if (!Number.isFinite(value)) {
      throw new RangeError(`${what}: non-finite number ${JSON.stringify(value)}`);
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const v of value) checkJsonValue(v, what);
    return;
  }
  if (t === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (typeof k !== "string" || k.length === 0) {
        throw new RangeError(`${what}: invalid object key ${JSON.stringify(k)}`);
      }
      checkJsonValue(v, what);
    }
    return;
  }
  throw new RangeError(`${what}: not a JSON value, got ${JSON.stringify(value)}`);
}

/** Compile-check a template: unclosed `{{`, stray `}}`, unknown variable. */
function compileTemplate(tpl: string, what: string): void {
  let i = 0;
  for (;;) {
    const open = tpl.indexOf("{{", i);
    if (open === -1) {
      if (tpl.indexOf("}}", i) !== -1) {
        throw new TemplateError(`${what}: stray "}}" without opening "{{" in ${JSON.stringify(tpl)}`);
      }
      return;
    }
    const close = tpl.indexOf("}}", open + 2);
    if (close === -1) {
      throw new TemplateError(`${what}: unclosed "{{" in ${JSON.stringify(tpl)}`);
    }
    const name = tpl.slice(open + 2, close).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
      throw new TemplateError(`${what}: invalid template variable ${JSON.stringify(name)} in ${JSON.stringify(tpl)}`);
    }
    if (!TEMPLATE_VARS.has(name)) {
      throw new TemplateError(
        `${what}: unknown template variable ${JSON.stringify(name)} in ${JSON.stringify(tpl)} ` +
          `(known: event_id, endpoint, attempt, timestamp)`
      );
    }
    i = close + 2;
  }
}

/** Render a pre-validated template against the attempt context. */
function renderTemplate(tpl: string, ctx: TransformContext): string {
  return tpl.replace(/\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}/g, (_m, name: string) => {
    switch (name) {
      case "event_id":
        return ctx.eventId;
      case "endpoint":
        return ctx.endpoint;
      case "attempt":
        return String(ctx.attempt);
      case "timestamp":
        return ctx.timestamp;
      default:
        // Unreachable: compileTemplate rejected unknown names at
        // construction. Fail closed rather than leak the raw braces.
        throw new TemplateError(`unknown template variable ${JSON.stringify(name)}`);
    }
  });
}

interface CompiledRules {
  renames: Array<{ from: string[]; to: string[] }>;
  deletes: string[][];
  maps: Array<{ from: string[]; to: string[] }>;
  constants: Array<{ path: string[]; value: unknown }>;
  headers: Array<{ name: string; template: string }>;
}

function isArrayIndex(seg: string): boolean {
  return /^(0|[1-9][0-9]*)$/.test(seg);
}

/** Resolve `segments` against `root`; undefined when the path is absent. */
function getPath(root: unknown, segments: string[]): unknown {
  let node: unknown = root;
  for (const seg of segments) {
    if (node === null || typeof node !== "object") return undefined;
    node = (node as Record<string, unknown>)[seg];
  }
  return node;
}

/**
 * Set `segments` to `value`, creating intermediate objects (or arrays
 * when the *next* segment is a numeric index). Returns false when an
 * intermediate is a primitive that cannot be traversed — the set is
 * then a no-op rather than a crash.
 */
function setPath(root: unknown, segments: string[], value: unknown): boolean {
  let node: unknown = root;
  for (let i = 0; i < segments.length - 1; i++) {
    if (node === null || typeof node !== "object") return false;
    const rec = node as Record<string, unknown>;
    let next = rec[segments[i]];
    if (next === null || typeof next !== "object") {
      next = isArrayIndex(segments[i + 1]) ? [] : {};
      rec[segments[i]] = next;
    }
    node = next;
  }
  if (node === null || typeof node !== "object") return false;
  (node as Record<string, unknown>)[segments[segments.length - 1]] = value;
  return true;
}

/** Delete the leaf at `segments`; missing paths are no-ops. */
function deletePath(root: unknown, segments: string[]): void {
  let node: unknown = root;
  for (let i = 0; i < segments.length - 1; i++) {
    if (node === null || typeof node !== "object") return;
    node = (node as Record<string, unknown>)[segments[i]];
  }
  if (node === null || typeof node !== "object") return;
  const rec = node as Record<string, unknown>;
  const leaf = segments[segments.length - 1];
  if (Array.isArray(rec) && isArrayIndex(leaf)) {
    rec.splice(Number(leaf), 1);
  } else {
    delete rec[leaf];
  }
}

/**
 * Compile one endpoint's rules through the construction-time path:
 * every class validated (`RangeError`/`TemplateError` on illegal
 * shapes, paths, header names, constants, or templates) and lowered
 * to segment arrays. Shared by the constructor and by
 * `PayloadTransformer.revise`, so a live revision is checked by the
 * exact same gates as a startup config — never mid-delivery.
 */
function compileEndpointRules(endpoint: string, rules: PayloadTransformRules): CompiledRules {
  const r = rules;
  const compiled: CompiledRules = { renames: [], deletes: [], maps: [], constants: [], headers: [] };
  if (r.fieldRenames !== undefined) {
    if (r.fieldRenames === null || typeof r.fieldRenames !== "object" || Array.isArray(r.fieldRenames)) {
      throw new RangeError(`fieldRenames for ${JSON.stringify(endpoint)} must be an object, got ${JSON.stringify(r.fieldRenames)}`);
    }
    for (const [from, to] of Object.entries(r.fieldRenames)) {
      compiled.renames.push({
        from: checkPath(from, `fieldRenames source for ${JSON.stringify(endpoint)}`),
        to: checkPath(to, `fieldRenames target for ${JSON.stringify(endpoint)}`),
      });
    }
  }
  if (r.fieldDeletes !== undefined) {
    if (!Array.isArray(r.fieldDeletes)) {
      throw new RangeError(`fieldDeletes for ${JSON.stringify(endpoint)} must be an array, got ${JSON.stringify(r.fieldDeletes)}`);
    }
    for (const p of r.fieldDeletes) {
      compiled.deletes.push(checkPath(p, `fieldDeletes path for ${JSON.stringify(endpoint)}`));
    }
  }
  if (r.fieldMaps !== undefined) {
    if (r.fieldMaps === null || typeof r.fieldMaps !== "object" || Array.isArray(r.fieldMaps)) {
      throw new RangeError(`fieldMaps for ${JSON.stringify(endpoint)} must be an object, got ${JSON.stringify(r.fieldMaps)}`);
    }
    for (const [to, from] of Object.entries(r.fieldMaps)) {
      compiled.maps.push({
        from: checkPath(from, `fieldMaps source for ${JSON.stringify(endpoint)}`),
        to: checkPath(to, `fieldMaps target for ${JSON.stringify(endpoint)}`),
      });
    }
  }
  if (r.constants !== undefined) {
    if (r.constants === null || typeof r.constants !== "object" || Array.isArray(r.constants)) {
      throw new RangeError(`constants for ${JSON.stringify(endpoint)} must be an object, got ${JSON.stringify(r.constants)}`);
    }
    for (const [path, value] of Object.entries(r.constants)) {
      checkJsonValue(value, `constants value at ${JSON.stringify(path)} for ${JSON.stringify(endpoint)}`);
      compiled.constants.push({
        path: checkPath(path, `constants path for ${JSON.stringify(endpoint)}`),
        value,
      });
    }
  }
  if (r.headerInjections !== undefined) {
    if (
      r.headerInjections === null ||
      typeof r.headerInjections !== "object" ||
      Array.isArray(r.headerInjections)
    ) {
      throw new RangeError(
        `headerInjections for ${JSON.stringify(endpoint)} must be an object, got ${JSON.stringify(r.headerInjections)}`
      );
    }
    for (const [name, tpl] of Object.entries(r.headerInjections)) {
      checkHeaderName(name);
      if (typeof tpl !== "string") {
        throw new RangeError(
          `headerInjections value for ${JSON.stringify(name)} must be a string, got ${JSON.stringify(tpl)}`
        );
      }
      compileTemplate(tpl, `headerInjections ${JSON.stringify(name)} for ${JSON.stringify(endpoint)}`);
      compiled.headers.push({ name, template: tpl });
    }
  }
  return compiled;
}

/** Order-insensitive deep equality for JSON-shaped values. */
function jsonDeepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (a === null || b === null) return false;
  if (typeof a !== "object" || typeof b !== "object") return false;
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b) || a.length !== b.length) return false;
    return a.every((v, i) => jsonDeepEqual(v, b[i]));
  }
  const ra = a as Record<string, unknown>;
  const rb = b as Record<string, unknown>;
  const ka = Object.keys(ra);
  const kb = Object.keys(rb);
  if (ka.length !== kb.length) return false;
  return ka.every(
    (k) => Object.prototype.hasOwnProperty.call(rb, k) && jsonDeepEqual(ra[k], rb[k])
  );
}

/** Same-value test for two raw rule records (absent class = empty class). */
function sameRules(a: PayloadTransformRules, b: PayloadTransformRules): boolean {
  return (
    jsonDeepEqual(a.fieldRenames ?? {}, b.fieldRenames ?? {}) &&
    jsonDeepEqual(a.fieldDeletes ?? [], b.fieldDeletes ?? []) &&
    jsonDeepEqual(a.fieldMaps ?? {}, b.fieldMaps ?? {}) &&
    jsonDeepEqual(a.constants ?? {}, b.constants ?? {}) &&
    jsonDeepEqual(a.headerInjections ?? {}, b.headerInjections ?? {})
  );
}

/**
 * Per-endpoint payload transforms. Construct once at startup from the
 * `payloadTransforms` server option; the same instance backs every
 * delivery. Invalid shapes, paths, header names, or templates throw
 * `RangeError`/`TemplateError` at construction — never mid-delivery.
 */
export class PayloadTransformer {
  private readonly rules = new Map<string, CompiledRules>();
  /**
   * WR-432: the raw (uncompiled) rules per endpoint, kept alongside
   * the compiled form for same-value comparison in `revise` and for
   * the defensive deep copy `getRawRules` returns. Mutated in place
   * by `revise`, never replaced.
   */
  private readonly rawRules = new Map<string, PayloadTransformRules>();

  /**
   * `rulesByEndpoint` maps an endpoint (the delivery `targetUrl`) to its
   * transform rules. Endpoints without an entry are never transformed.
   */
  constructor(rulesByEndpoint: Record<string, PayloadTransformRules>) {
    if (
      rulesByEndpoint === null ||
      typeof rulesByEndpoint !== "object" ||
      Array.isArray(rulesByEndpoint)
    ) {
      throw new RangeError(
        `payload-transform rules must be an object mapping endpoint to rules, got ${JSON.stringify(rulesByEndpoint)}`
      );
    }
    for (const [endpoint, rules] of Object.entries(rulesByEndpoint)) {
      if (rules === null || typeof rules !== "object" || Array.isArray(rules)) {
        throw new RangeError(
          `payload-transform rules for ${JSON.stringify(endpoint)} must be an object, got ${JSON.stringify(rules)}`
        );
      }
      // Compile first: an illegal endpoint binds nothing, and the raw
      // copy stored below is already known to be JSON-shaped.
      this.rules.set(endpoint, compileEndpointRules(endpoint, rules));
      this.rawRules.set(endpoint, structuredClone(rules));
    }
  }

  /**
   * Revise the live transform rules in place (WR-432): validate the
   * whole patch first — every non-null entry goes through the same
   * gates `compileEndpointRules` applies at construction, compiled
   * into temporary tables — then apply it entry by entry, mutating
   * the Maps in place (never replacing the transformer object, so a
   * send whose `apply()` already read its compiled rules keeps them,
   * while the next send reads the revised ones). Returns the
   * per-endpoint changes; an empty array means the patch was a
   * same-value no-op (clearing an endpoint with no rules, or setting
   * rules identical to the live ones).
   *
   * Throws `RangeError` on a non-object or empty patch, or on any
   * invalid rule, and `TemplateError` on an unclosed template — with
   * the live rules left completely intact (zero partial application).
   */
  revise(patch: PayloadTransformsRevision): PayloadTransformsRevisionChange[] {
    if (patch === null || typeof patch !== "object" || Array.isArray(patch)) {
      throw new RangeError(
        "revisePayloadTransforms: patch must be a Record<targetUrl, PayloadTransformRules | null>"
      );
    }
    const entries = Object.entries(patch);
    if (entries.length === 0) {
      throw new RangeError("revisePayloadTransforms: patch must contain at least one endpoint");
    }
    for (const [endpoint] of entries) {
      if (endpoint === "") {
        throw new RangeError("revisePayloadTransforms: patch keys must be non-empty endpoint strings");
      }
    }
    // Validate-then-apply: compile the non-null entries through the
    // construction-time path into temp tables, so a bad rule binds
    // nothing. The raw copies are cloned here, so later caller-side
    // mutation of the patch object can never move the live rules.
    const compiled = new Map<string, CompiledRules>();
    const raw = new Map<string, PayloadTransformRules>();
    for (const [endpoint, rules] of entries) {
      if (rules === null) continue;
      if (rules === undefined || typeof rules !== "object" || Array.isArray(rules)) {
        throw new RangeError(
          `revisePayloadTransforms: rules for ${JSON.stringify(endpoint)} must be an object, got ${JSON.stringify(rules)}`
        );
      }
      compiled.set(endpoint, compileEndpointRules(endpoint, rules));
      raw.set(endpoint, structuredClone(rules));
    }
    const changes: PayloadTransformsRevisionChange[] = [];
    for (const [endpoint, rules] of entries) {
      const prevRaw = this.rawRules.get(endpoint) ?? null;
      if (rules === null) {
        if (prevRaw === null) continue; // Clearing an endpoint with no rules: no-op.
        this.rawRules.delete(endpoint);
        this.rules.delete(endpoint);
        changes.push({ endpoint, previous: structuredClone(prevRaw), current: null });
      } else {
        const nextRaw = raw.get(endpoint)!;
        if (prevRaw !== null && sameRules(prevRaw, nextRaw)) continue; // Same-value: no-op.
        this.rawRules.set(endpoint, nextRaw);
        this.rules.set(endpoint, compiled.get(endpoint)!);
        changes.push({
          endpoint,
          previous: prevRaw === null ? null : structuredClone(prevRaw),
          current: structuredClone(nextRaw),
        });
      }
    }
    return changes;
  }

  /**
   * The live raw rules — a defensive deep copy, so callers can
   * neither mutate the live rules nor observe a half-applied
   * revision.
   */
  getRawRules(): Record<string, PayloadTransformRules> {
    return Object.fromEntries(
      [...this.rawRules.entries()].map(([endpoint, rules]) => [endpoint, structuredClone(rules)])
    );
  }

  /** Whether `endpoint` has at least one transform rule. */
  hasRules(endpoint: string): boolean {
    const r = this.rules.get(endpoint);
    return (
      r !== undefined &&
      (r.renames.length > 0 ||
        r.deletes.length > 0 ||
        r.maps.length > 0 ||
        r.constants.length > 0 ||
        r.headers.length > 0)
    );
  }

  /**
   * Transform `body` for `endpoint` under `ctx`. Returns the transformed
   * wire bytes plus the outbound headers to inject. When the endpoint
   * has no rules the input buffer is returned untouched with no
   * headers. Throws `PayloadTransformError` when the payload is not
   * JSON (or rendering otherwise fails) — never returns a silently
   * untransformed body for a configured endpoint. The parsed value is
   * deep-cloned before mutation; the caller's buffer is never touched.
   */
  apply(
    endpoint: string,
    body: Buffer,
    ctx: TransformContext
  ): { body: Buffer; headers: Record<string, string> } {
    const rules = this.rules.get(endpoint);
    if (rules === undefined || !this.hasRules(endpoint)) return { body, headers: {} };
    let parsed: unknown;
    try {
      parsed = JSON.parse(body.toString("utf8"));
    } catch (err) {
      throw new PayloadTransformError(endpoint, "payload is not JSON", { cause: err });
    }
    try {
      const clone = structuredClone(parsed);
      // Order is documented and fixed: deletes, renames (move), maps
      // (copy), constants. A rename whose source is missing is a no-op;
      // sets create intermediate objects/arrays as needed.
      for (const segs of rules.deletes) deletePath(clone, segs);
      for (const { from, to } of rules.renames) {
        const value = getPath(clone, from);
        if (value === undefined) continue;
        if (setPath(clone, to, structuredClone(value))) deletePath(clone, from);
      }
      for (const { from, to } of rules.maps) {
        const value = getPath(clone, from);
        if (value === undefined) continue;
        setPath(clone, to, structuredClone(value));
      }
      for (const { path, value } of rules.constants) {
        setPath(clone, path, structuredClone(value));
      }
      const headers: Record<string, string> = {};
      for (const { name, template } of rules.headers) {
        headers[name] = renderTemplate(template, ctx);
      }
      return { body: Buffer.from(JSON.stringify(clone)), headers };
    } catch (err) {
      if (err instanceof PayloadTransformError) throw err;
      throw new PayloadTransformError(endpoint, err instanceof Error ? err.message : String(err), {
        cause: err,
      });
    }
  }
}
