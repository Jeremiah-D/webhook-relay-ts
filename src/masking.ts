/**
 * WR-72: field-level masking for audit payloads (PII/PAN hygiene).
 * WR-191: JSONPath subset expressions as an alternative to dot-paths.
 *
 * Some webhook payloads carry fields that must never reach the audit
 * trail in the clear — card numbers, national IDs, tokens. `FieldMask`
 * holds opt-in, per-endpoint masking rules keyed by dot-separated field
 * paths (e.g. `card_number`, `payment.card.number`; numeric segments
 * address array elements, e.g. `items.0.sku`).
 *
 * WR-191 adds a JSONPath *subset* expression language for rules that
 * need to reach into arrays of objects or whose shape is awkward for
 * dot-paths. Examples:
 *
 * - `$.payment.card.number` — nested field
 * - `$['a']['b']` / `$["a"]["b"]` — bracket-quoted names (literal keys,
 *   may contain dots or spaces)
 * - `$.items[*].pan` — every element's `pan` in an array
 * - `$.users.*.token` — every value's `token` in an object
 * - `$.items[0].sku` — positional array index
 * - `$` — the whole payload (masks the entire payload for the endpoint)
 *
 * Supported: `.name`, `.*`, `['name']`, `["name"]`, `[<non-negative int>]`,
 * `[*]`. Deliberately *not* supported (all rejected with `RangeError`
 * at construction): `..` recursive descent, negative indices, slices,
 * filters `?()`, script expressions, unclosed brackets/quotes, and empty
 * segments. The parser is hand-written and dependency-free.
 *
 * Masking is *irreversible*: `"full"` replaces the value with `"****"`,
 * `"last4"` keeps only the last four characters of a string
 * (`"4111111111111111"` → `"****1111"`). There is no unmask operation —
 * a masked value cannot be turned back into the original.
 *
 * Where it runs (always *before* the WR-11 payload encryptor seals
 * anything, so the raw values never reach the ciphertext either):
 *
 * - `AuditLog.append` — the `payload` field of any audit event whose
 *   `targetUrl`/`endpoint` has rules, when the payload is JSON-shaped;
 * - `RetryQueue` — the opt-in WR-54 `responseBodyCapture` body, when it
 *   parses as JSON, before it is sealed into `capturedBody`.
 *
 * Honest scoping note: the delivery-event archive (`EventArchive`)
 * persists payload-free metadata lines (per WR-188), so there is no
 * payload there for field masking to act on. JSONPath masking applies at
 * the existing WR-72 integration points above, not to the archive.
 *
 * Non-JSON payloads cannot take field paths and pass through untouched
 * (a documented limitation, not a silent drop). Missing paths and
 * non-object intermediates are no-ops. The input value is never mutated
 * — masking works on a deep clone.
 */

/** How the matched value is replaced. `"full"` by default. */
export type MaskStrategy = "full" | "last4";

/** One field path to mask for an endpoint. */
export interface FieldMaskRule {
  /**
   * Dot-separated path from the payload root, e.g. `"card_number"` or
   * `"payment.card.number"`. Numeric segments address array elements
   * (`"items.0.sku"`). Empty segments and the prototype-pollution
   * segments `__proto__` / `constructor` / `prototype` are rejected with
   * `RangeError` at construction. Mutually exclusive with `jsonpath`:
   * exactly one of the two must be set.
   */
  path?: string;
  /**
   * JSONPath subset expression (WR-191) from the payload root, e.g.
   * `"$.payment.card.number"` or `"$.items[*].pan"`. See the module doc
   * for the supported grammar. Mutually exclusive with `path`: exactly
   * one of the two must be set. Invalid expressions are rejected with
   * `RangeError` at construction.
   */
  jsonpath?: string;
  /** Replacement strategy. Default: `"full"`. */
  strategy?: MaskStrategy;
}

/** One compiled JSONPath segment (WR-191 subset). */
type JsonPathSegment =
  | { type: "field"; name: string }
  | { type: "index"; index: number }
  | { type: "wildcard" };

interface CompiledRule {
  strategy: MaskStrategy;
  /** Set for dot-path rules (WR-72). */
  dotSegments?: string[];
  /** Set for JSONPath rules (WR-191). */
  jsonSegments?: JsonPathSegment[];
}

/** Segments that would allow prototype pollution — never valid in a path. */
const FORBIDDEN_SEGMENTS = new Set(["__proto__", "constructor", "prototype"]);

function checkPath(path: unknown): string[] {
  if (typeof path !== "string" || path.length === 0) {
    throw new RangeError(`field-mask path must be a non-empty string, got ${JSON.stringify(path)}`);
  }
  const segments = path.split(".");
  for (const seg of segments) {
    if (seg.length === 0) {
      throw new RangeError(
        `invalid field-mask path ${JSON.stringify(path)}: empty segment`
      );
    }
    if (FORBIDDEN_SEGMENTS.has(seg)) {
      throw new RangeError(
        `invalid field-mask path ${JSON.stringify(path)}: forbidden segment ${JSON.stringify(seg)}`
      );
    }
  }
  return segments;
}

function checkForbiddenJsonSegment(name: string, expr: string): void {
  if (FORBIDDEN_SEGMENTS.has(name)) {
    throw new RangeError(
      `invalid field-mask jsonpath ${JSON.stringify(expr)}: forbidden segment ${JSON.stringify(name)}`
    );
  }
}

/**
 * Hand-written parser for the WR-191 JSONPath subset. Zero dependencies.
 * Returns the compiled segment list; `$` alone yields an empty list
 * (mask the whole payload). Every invalid expression throws `RangeError`
 * — validation always happens at construction, never mid-request.
 */
function parseJsonPath(expr: unknown): JsonPathSegment[] {
  if (typeof expr !== "string" || expr.length === 0) {
    throw new RangeError(`field-mask jsonpath must be a non-empty string, got ${JSON.stringify(expr)}`);
  }
  if (expr[0] !== "$") {
    throw new RangeError(`field-mask jsonpath must start with "$", got ${JSON.stringify(expr)}`);
  }
  const segments: JsonPathSegment[] = [];
  let i = 1;
  const n = expr.length;
  const fail = (why: string): never => {
    throw new RangeError(`invalid field-mask jsonpath ${JSON.stringify(expr)}: ${why}`);
  };
  const isDigit = (ch: string): boolean => ch >= "0" && ch <= "9";
  while (i < n) {
    const ch = expr[i];
    if (ch === ".") {
      i++;
      if (expr[i] === ".") fail(`recursive descent ".." is not supported`);
      if (expr[i] === "*") {
        segments.push({ type: "wildcard" });
        i++;
        continue;
      }
      const start = i;
      while (i < n && expr[i] !== "." && expr[i] !== "[" && expr[i] !== "]") i++;
      const name = expr.slice(start, i);
      if (name.length === 0) fail("empty segment");
      checkForbiddenJsonSegment(name, expr);
      segments.push({ type: "field", name });
      continue;
    }
    if (ch === "[") {
      i++;
      if (i >= n) fail("unclosed bracket");
      const q = expr[i];
      if (q === "'" || q === '"') {
        // ['name'] or ["name"] — literal key, may contain dots or spaces.
        i++;
        const start = i;
        while (i < n && expr[i] !== q) i++;
        if (i >= n) fail("unclosed quote");
        const name = expr.slice(start, i);
        if (name.length === 0) fail("empty segment");
        checkForbiddenJsonSegment(name, expr);
        i++; // past the closing quote
        if (expr[i] !== "]") fail(`expected "]" after quoted name`);
        i++;
        segments.push({ type: "field", name });
        continue;
      }
      if (expr[i] === "*") {
        i++;
        if (expr[i] !== "]") fail(`expected "]" after "*"`);
        i++;
        segments.push({ type: "wildcard" });
        continue;
      }
      const start = i;
      while (i < n && isDigit(expr[i])) i++;
      const digits = expr.slice(start, i);
      if (digits.length === 0) {
        fail("unsupported bracket expression (slices, filters, and negative indices are not supported)");
      }
      if (expr[i] !== "]") fail(`expected "]" after array index`);
      i++;
      segments.push({ type: "index", index: Number(digits) });
      continue;
    }
    fail(`unexpected character ${JSON.stringify(ch)} (expected "." or "[")`);
  }
  return segments;
}

function checkStrategy(strategy: unknown): MaskStrategy {
  const s = strategy ?? "full";
  if (s !== "full" && s !== "last4") {
    throw new RangeError(`field-mask strategy must be "full" or "last4", got ${JSON.stringify(strategy)}`);
  }
  return s;
}

/**
 * Replace one leaf value. Short strings and non-strings under `"last4"`
 * fall back to `"****"` — a 3-character secret has no safe "last 4".
 * Non-primitive values (objects/arrays) are always fully masked: a
 * subtree cannot be partially redacted safely.
 */
function maskLeaf(value: unknown, strategy: MaskStrategy): unknown {
  if (strategy === "last4" && typeof value === "string" && value.length > 4) {
    return `****${value.slice(-4)}`;
  }
  return "****";
}

function applyRule(root: unknown, rule: CompiledRule): void {
  const segs = rule.dotSegments;
  if (segs === undefined) return;
  let node: unknown = root;
  for (let i = 0; i < segs.length - 1; i++) {
    if (node === null || typeof node !== "object") return;
    node = (node as Record<string, unknown>)[segs[i]];
  }
  if (node === null || typeof node !== "object") return;
  const leaf = segs[segs.length - 1];
  const rec = node as Record<string, unknown>;
  if (!Object.prototype.hasOwnProperty.call(rec, leaf)) return; // missing path: no-op
  rec[leaf] = maskLeaf(rec[leaf], rule.strategy);
}

interface JsonSlot {
  parent: Record<string | number, unknown>;
  key: string | number;
}

/**
 * Evaluate a compiled JSONPath against the cloned root, masking every
 * matched leaf. `$` alone (empty segments) masks the whole payload.
 * Wildcards expand over both array elements and object own-enumerable
 * values (forbidden segments are skipped during expansion). Missing
 * paths and non-object intermediates are no-ops, like dot-path rules.
 */
function applyJsonPathRule(
  root: unknown,
  segments: JsonPathSegment[],
  strategy: MaskStrategy
): unknown {
  if (segments.length === 0) return maskLeaf(root, strategy);
  const box: { v: unknown } = { v: root };
  let slots: JsonSlot[] = [
    { parent: box as unknown as Record<string | number, unknown>, key: "v" },
  ];
  for (const seg of segments) {
    const next: JsonSlot[] = [];
    for (const slot of slots) {
      const holder = slot.parent[slot.key];
      if (holder === null || typeof holder !== "object") continue;
      const obj = holder as Record<string | number, unknown>;
      if (seg.type === "field") {
        next.push({ parent: obj, key: seg.name });
      } else if (seg.type === "index") {
        next.push({ parent: obj, key: seg.index });
      } else {
        for (const k of Object.keys(obj)) {
          if (FORBIDDEN_SEGMENTS.has(k)) continue;
          next.push({ parent: obj, key: k });
        }
      }
    }
    slots = next;
    if (slots.length === 0) break;
  }
  for (const slot of slots) {
    const parent = slot.parent;
    if (!Object.prototype.hasOwnProperty.call(parent, slot.key)) continue; // missing path: no-op
    parent[slot.key] = maskLeaf(parent[slot.key], strategy);
  }
  return root;
}

/**
 * Per-endpoint field-masking rules. Construct once, share between the
 * `AuditLog` and the `RetryQueue` — the same instance may back both.
 */
export class FieldMask {
  private readonly rules = new Map<string, CompiledRule[]>();

  /**
   * `rulesByEndpoint` maps an endpoint (the delivery `targetUrl`) to its
   * masking rules. Endpoints without an entry are never masked. Each
   * rule sets exactly one of `path` (WR-72 dot-path) or `jsonpath`
   * (WR-191 JSONPath subset); setting both or neither throws
   * `RangeError`. Invalid paths, expressions, strategies, or shapes
   * throw `RangeError` at construction — never mid-request.
   */
  constructor(rulesByEndpoint: Record<string, FieldMaskRule[]>) {
    if (
      rulesByEndpoint === null ||
      typeof rulesByEndpoint !== "object" ||
      Array.isArray(rulesByEndpoint)
    ) {
      throw new RangeError(
        `field-mask rules must be an object mapping endpoint to rules, got ${JSON.stringify(rulesByEndpoint)}`
      );
    }
    for (const [endpoint, rules] of Object.entries(rulesByEndpoint)) {
      if (!Array.isArray(rules)) {
        throw new RangeError(
          `field-mask rules for ${JSON.stringify(endpoint)} must be an array, got ${JSON.stringify(rules)}`
        );
      }
      this.rules.set(
        endpoint,
        rules.map((rule) => {
          if (rule === null || typeof rule !== "object" || Array.isArray(rule)) {
            throw new RangeError(
              `field-mask rule must be an object, got ${JSON.stringify(rule)}`
            );
          }
          const r = rule as FieldMaskRule;
          const hasPath = r.path !== undefined;
          const hasJsonPath = r.jsonpath !== undefined;
          if (hasPath === hasJsonPath) {
            throw new RangeError(
              `field-mask rule must set exactly one of "path" or "jsonpath", got ${JSON.stringify(rule)}`
            );
          }
          const strategy = checkStrategy(r.strategy);
          if (hasJsonPath) {
            return { strategy, jsonSegments: parseJsonPath(r.jsonpath) };
          }
          return { strategy, dotSegments: checkPath(r.path) };
        })
      );
    }
  }

  /** Whether `endpoint` has at least one masking rule. */
  hasRules(endpoint: string): boolean {
    const r = this.rules.get(endpoint);
    return r !== undefined && r.length > 0;
  }

  /**
   * Deep-clone `value` with every rule for `endpoint` applied. Returns
   * `value` itself (uncloned, untouched) when the endpoint has no rules.
   * The clone is JSON-shaped when the input is; `structuredClone` keeps
   * Buffers and other natives intact.
   */
  maskJson(endpoint: string, value: unknown): unknown {
    const rules = this.rules.get(endpoint);
    if (rules === undefined || rules.length === 0) return value;
    let clone: unknown = structuredClone(value);
    for (const rule of rules) {
      if (rule.jsonSegments !== undefined) {
        clone = applyJsonPathRule(clone, rule.jsonSegments, rule.strategy);
      } else {
        applyRule(clone, rule);
      }
    }
    return clone;
  }
}
