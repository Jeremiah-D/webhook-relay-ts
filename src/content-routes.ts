/**
 * Content-based routing rule engine (WR-84).
 *
 * Routes an inbound webhook to a target endpoint by matching rules against
 * payload JSON fields. A rule carries dot-path matchers
 * (`"order.type"`), an op per matcher, and a target URL; rules are tried
 * in `priority` order (ascending, stable, default 100) and the first
 * fully-matching rule wins. When no rule matches, the optional
 * `defaultTargetUrl` applies; the caller substitutes its own fallback
 * (the relay's `forwardUrl`) when neither a rule nor the default matched.
 *
 * Design rules:
 * - Routing never rejects an event: `resolve()` never throws at runtime.
 *   A non-JSON payload, a missing field, or a throwing regex engine all
 *   mean "no match" and fall through to the default / caller fallback.
 * - Invalid rules fail fast with `RangeError` at construction /
 *   `setRules`, never mid-request. `setRules` is validate-then-apply:
 *   the swap is atomic, so a rejected update leaves the live table
 *   untouched.
 * - Zero dependencies: node built-ins only (none needed here, in fact).
 */

/** Matcher operators supported by `ContentMatcher`. */
export type ContentMatcherOp = "equals" | "contains" | "regex" | "exists" | "range";

/** The default rule priority when `priority` is omitted. */
export const CONTENT_ROUTE_DEFAULT_PRIORITY = 100;

/**
 * One field predicate inside a rule. `field` is a dot-path into the
 * parsed JSON payload (e.g. `"order.type"`). Semantics per `op`:
 * - `equals`: JSON-compare of the field against `value` (deep-ish
 *   equality for primitives and arrays).
 * - `contains`: substring match when the field is a string and `value`
 *   is a string; `includes`-style element compare when the field is an
 *   array.
 * - `regex`: the field must be a string; the pattern (`value`, compiled
 *   once at validation) is tested against it. Non-string fields never
 *   match.
 * - `exists`: the field is present and not null/undefined.
 * - `range`: the field must be numeric and lie in `[min, max]`; both
 *   bounds are optional but at least one must be set.
 */
export interface ContentMatcher {
  field: string;
  op: ContentMatcherOp;
  value?: unknown;
  min?: number;
  max?: number;
}

/**
 * A content route: when every matcher matches, the event is delivered to
 * `targetUrl`. Lower `priority` wins (ties keep config order).
 */
export interface ContentRouteRule {
  id: string;
  matchers: ContentMatcher[];
  targetUrl: string;
  priority?: number;
}

const KNOWN_OPS: ReadonlySet<string> = new Set([
  "equals",
  "contains",
  "regex",
  "exists",
  "range",
]);

/** Validate one matcher; throws RangeError on the first violation. */
function assertValidMatcher(matcher: unknown, ruleId: string): asserts matcher is ContentMatcher {
  if (matcher === null || typeof matcher !== "object" || Array.isArray(matcher)) {
    throw new RangeError(`contentRoutes: rule "${ruleId}" has a matcher that is not an object`);
  }
  const m = matcher as Record<string, unknown>;
  if (typeof m.field !== "string" || m.field.length === 0) {
    throw new RangeError(`contentRoutes: rule "${ruleId}" has a matcher with an empty field path`);
  }
  if (typeof m.op !== "string" || !KNOWN_OPS.has(m.op)) {
    throw new RangeError(`contentRoutes: rule "${ruleId}" has an unknown matcher op "${String(m.op)}"`);
  }
  const op = m.op as ContentMatcherOp;
  if (op === "equals" || op === "contains") {
    if (m.value === undefined) {
      throw new RangeError(`contentRoutes: rule "${ruleId}" matcher "${m.field}" op "${op}" requires a value`);
    }
  }
  if (op === "regex") {
    // The pattern is compiled once here, fail-fast, so a bad regex can
    // never reach request time.
    if (typeof m.value !== "string") {
      throw new RangeError(`contentRoutes: rule "${ruleId}" matcher "${m.field}" regex requires a string pattern`);
    }
    try {
      // eslint-disable-next-line no-new
      new RegExp(m.value);
    } catch (err) {
      throw new RangeError(
        `contentRoutes: rule "${ruleId}" matcher "${m.field}" has an invalid regex: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }
  if (op === "range") {
    const { min, max } = m;
    if (min === undefined && max === undefined) {
      throw new RangeError(`contentRoutes: rule "${ruleId}" matcher "${m.field}" range requires at least one bound`);
    }
    if (min !== undefined && (typeof min !== "number" || Number.isNaN(min))) {
      throw new RangeError(`contentRoutes: rule "${ruleId}" matcher "${m.field}" range min must be a number`);
    }
    if (max !== undefined && (typeof max !== "number" || Number.isNaN(max))) {
      throw new RangeError(`contentRoutes: rule "${ruleId}" matcher "${m.field}" range max must be a number`);
    }
  }
}

/**
 * Fail-fast validation of a content-route rule list. Returns the rules
 * sorted by priority ascending (default 100), stable. Throws `RangeError`
 * on: a non-array, an empty/duplicate rule id, a non-object rule,
 * `targetUrl` not a non-empty string, `matchers` not a non-empty array,
 * any matcher violation, or a non-numeric `priority`.
 */
export function assertValidContentRouteRules(rules: unknown): asserts rules is ContentRouteRule[] {
  if (!Array.isArray(rules)) {
    throw new RangeError("contentRoutes: rules must be an array");
  }
  const seen = new Set<string>();
  for (const rule of rules) {
    if (rule === null || typeof rule !== "object" || Array.isArray(rule)) {
      throw new RangeError("contentRoutes: every rule must be an object");
    }
    const r = rule as Record<string, unknown>;
    if (typeof r.id !== "string" || r.id.length === 0) {
      throw new RangeError("contentRoutes: every rule needs a non-empty string id");
    }
    if (seen.has(r.id)) {
      throw new RangeError(`contentRoutes: duplicate rule id "${r.id}"`);
    }
    seen.add(r.id);
    if (typeof r.targetUrl !== "string" || r.targetUrl.length === 0) {
      throw new RangeError(`contentRoutes: rule "${r.id}" targetUrl must be a non-empty string`);
    }
    if (!Array.isArray(r.matchers) || r.matchers.length === 0) {
      throw new RangeError(`contentRoutes: rule "${r.id}" matchers must be a non-empty array`);
    }
    if (r.priority !== undefined && (typeof r.priority !== "number" || Number.isNaN(r.priority))) {
      throw new RangeError(`contentRoutes: rule "${r.id}" priority must be a number`);
    }
    for (const matcher of r.matchers) {
      assertValidMatcher(matcher, r.id);
    }
  }
}

/**
 * Fail-fast validation of the content-route default target. Throws
 * `RangeError` when it is present but not a non-empty string.
 */
export function assertValidContentRouteDefault(defaultTargetUrl: unknown): void {
  if (defaultTargetUrl === undefined) return;
  if (typeof defaultTargetUrl !== "string" || defaultTargetUrl.length === 0) {
    throw new RangeError("contentRouteDefault: must be a non-empty string when set");
  }
}

/** Walk a dot-path into parsed JSON; `found` is false on any miss. */
function lookupField(root: unknown, path: string): { found: boolean; value: unknown } {
  let current: unknown = root;
  for (const segment of path.split(".")) {
    if (current === null || typeof current !== "object") {
      return { found: false, value: undefined };
    }
    if (!Object.prototype.hasOwnProperty.call(current, segment)) {
      return { found: false, value: undefined };
    }
    current = (current as Record<string, unknown>)[segment];
  }
  return { found: true, value: current };
}

/** Deep-ish equality via JSON compare (covers primitives and arrays). */
function jsonEquals(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

function matchMatcher(matcher: ContentMatcher, payload: unknown): boolean {
  const { found, value: fieldValue } = lookupField(payload, matcher.field);
  switch (matcher.op) {
    case "exists":
      return found && fieldValue !== null && fieldValue !== undefined;
    case "equals":
      return found && jsonEquals(fieldValue, matcher.value);
    case "contains":
      if (!found) return false;
      if (typeof fieldValue === "string" && typeof matcher.value === "string") {
        return fieldValue.includes(matcher.value);
      }
      if (Array.isArray(fieldValue)) {
        return fieldValue.some((element) => jsonEquals(element, matcher.value));
      }
      return false;
    case "regex":
      // Regex applies to strings only; anything else is no match.
      if (!found || typeof fieldValue !== "string") return false;
      return new RegExp(matcher.value as string).test(fieldValue);
    case "range": {
      if (!found || typeof fieldValue !== "number" || Number.isNaN(fieldValue)) return false;
      if (matcher.min !== undefined && fieldValue < matcher.min) return false;
      if (matcher.max !== undefined && fieldValue > matcher.max) return false;
      return true;
    }
    default:
      // Unreachable after validation, but fail-closed at runtime.
      return false;
  }
}

/** The outcome of `ContentRouteTable.resolve`. */
export interface ContentRouteDecision {
  /** The id of the first matching rule, if any matched. */
  ruleId?: string;
  /**
   * The winning rule's target, or the default target when no rule
   * matched. `undefined` when neither applies — the caller substitutes
   * its own fallback (the relay's `forwardUrl`) in that case.
   */
  targetUrl?: string;
}

/**
 * An immutable-ish, atomically-swappable content-route table. The table
 * never throws from `resolve`: routing only picks a target, it never
 * rejects an event.
 */
export class ContentRouteTable {
  private rules: ContentRouteRule[];
  private defaultTargetUrl: string | undefined;

  constructor(initial: ContentRouteRule[], defaultTargetUrl?: string) {
    assertValidContentRouteRules(initial);
    assertValidContentRouteDefault(defaultTargetUrl);
    this.rules = sortRules(initial);
    this.defaultTargetUrl = defaultTargetUrl;
  }

  /**
   * Validate-then-apply full replacement. Both arguments are validated
   * before anything is swapped, so a `RangeError` leaves the live table
   * untouched (zero partial application).
   */
  setRules(rules: ContentRouteRule[], defaultTargetUrl?: string): void {
    assertValidContentRouteRules(rules);
    assertValidContentRouteDefault(defaultTargetUrl);
    this.rules = sortRules(rules);
    this.defaultTargetUrl = defaultTargetUrl;
  }

  /** A deep copy of the live rules, in match order (priority ascending). */
  getRules(): ContentRouteRule[] {
    return this.rules.map((rule) => ({
      ...rule,
      matchers: rule.matchers.map((matcher) => ({ ...matcher })),
    }));
  }

  getDefaultTargetUrl(): string | undefined {
    return this.defaultTargetUrl;
  }

  /**
   * Resolve the target for one inbound payload. `payload` may be a
   * Buffer, a JSON string, or an already-parsed value. Never throws: a
   * non-JSON payload, missing fields, or a throwing regex engine all mean
   * "no rule matched" and fall through to the default / undefined.
   */
  resolve(payload: unknown): ContentRouteDecision {
    let parsed: unknown;
    try {
      parsed = parsePayload(payload);
    } catch {
      return this.fallthrough();
    }
    if (parsed === undefined) return this.fallthrough();
    try {
      for (const rule of this.rules) {
        let matched = true;
        for (const matcher of rule.matchers) {
          let ok: boolean;
          try {
            ok = matchMatcher(matcher, parsed);
          } catch {
            // A throwing matcher (e.g. a pathological regex at
            // runtime) must never reject an event: treat as no match.
            ok = false;
          }
          if (!ok) {
            matched = false;
            break;
          }
        }
        if (matched) return { ruleId: rule.id, targetUrl: rule.targetUrl };
      }
    } catch {
      return this.fallthrough();
    }
    return this.fallthrough();
  }

  private fallthrough(): ContentRouteDecision {
    if (this.defaultTargetUrl !== undefined) {
      return { targetUrl: this.defaultTargetUrl };
    }
    return {};
  }
}

/** Stable priority-ascending sort; input is not mutated. */
function sortRules(rules: ContentRouteRule[]): ContentRouteRule[] {
  return [...rules]
    .map((rule, index) => ({ rule, index }))
    .sort(
      (a, b) =>
        (a.rule.priority ?? CONTENT_ROUTE_DEFAULT_PRIORITY) -
          (b.rule.priority ?? CONTENT_ROUTE_DEFAULT_PRIORITY) || a.index - b.index
    )
    .map(({ rule }) => rule);
}

/** Coerce Buffer/string/object into a parsed JSON value; throws on garbage. */
function parsePayload(payload: unknown): unknown {
  if (Buffer.isBuffer(payload)) {
    return JSON.parse(payload.toString("utf8"));
  }
  if (typeof payload === "string") {
    return JSON.parse(payload);
  }
  if (payload !== null && typeof payload === "object") {
    return payload;
  }
  throw new Error("contentRoutes: payload is not JSON-shaped");
}
