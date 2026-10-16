/**
 * Per-endpoint declarative response assertions (WR-118).
 *
 * The programmatic sibling is WR-37 (`ResponseValidator` functions in
 * `src/retry.ts`): a hand-written predicate that sees the decoded
 * `DownstreamResponse`. Assertions cover the same need — a downstream
 * that answers `200 OK` with a body that still means failure —
 * declaratively, for operators who would rather write config than code:
 *
 * ```ts
 * new RetryQueue({
 *   responseAssertions: [
 *     {
 *       targetUrl: "https://downstream.example/hook",
 *       expectedStatuses: [200, 201], // default: every 2xx
 *       assertions: [
 *         { path: "$.status", op: "eq", value: "ok" },
 *         { path: "$.data.latencyMs", op: "lt", value: 5000 },
 *         { path: "$.error", op: "ne", value: "rate_limited" },
 *         { path: "$.traceId", op: "exists" },
 *         { path: "$.code", op: "matches", value: "^PAY-[0-9]+$" },
 *       ],
 *     },
 *   ],
 * });
 * ```
 *
 * The expression language is deliberately tiny — a path plus one
 * operator, no general expression evaluator, no `eval()`. Paths are
 * strict: `$` for the whole document, then any number of `.name` /
 * `[index]` segments (`$.data.items[0].code`). Anything else is a
 * config error, rejected at construction.
 *
 * Failure semantics (see the WR-118 hook in `RetryQueue`'s `deliver()`):
 *
 * - assertions run on responses that would otherwise be delivered —
 *   i.e. whose status is inside the rule's whitelist (default: all
 *   2xx). A non-whitelisted status keeps the WR-30 classification
 *   (it never reaches the assertions).
 * - a failing assertion is a *retryable* delivery failure with
 *   `failure_class: "assertion_failed"` (see `src/failure.ts`): it
 *   goes through the normal backoff lane, trips the WR-10 breaker
 *   like any retryable failure, and honors the retry budget.
 * - a body that is not JSON, a path that resolves to nothing, or an
 *   evaluation error fails *closed* — counted as an assertion failure,
 *   never silently blessed.
 * - illegal rules (bad path syntax, unknown operator, missing `value`,
 *   empty status whitelist, duplicate `targetUrl`) throw `RangeError`
 *   at construction — fail-fast, with zero partial application.
 *
 * Zero dependencies (`node:` builtins only).
 */

/**
 * The assertion operators. `eq`/`ne` are strict equality
 * (`===`/`!==` — no type coercion); `gt`/`gte`/`lt`/`lte` compare
 * finite numbers only (a non-numeric operand fails the assertion
 * closed); `exists` passes when the path resolves to a present value;
 * `matches` tests a string operand against a regular expression.
 */
export type AssertionOperator =
  | "eq"
  | "ne"
  | "gt"
  | "gte"
  | "lt"
  | "lte"
  | "exists"
  | "matches";

/** One declarative assertion on the decoded downstream response body. */
export interface ResponseAssertion {
  /**
   * Strict JSON path: `$` for the whole document, then `.name` /
   * `[index]` segments (e.g. `$.status`, `$.data.items[0].code`).
   * Anything else is a construction-time `RangeError`.
   */
  path: string;
  /** The comparison to apply to the value at `path`. */
  op: AssertionOperator;
  /**
   * The expected value. Required for every operator except `exists`
   * (supplying one for `exists` is a construction-time `RangeError`);
   * must be a string holding a valid regex for `matches` and a finite
   * number for the numeric comparisons.
   */
  value?: unknown;
}

/**
 * One endpoint's declarative response expectations. Matched by exact
 * `targetUrl` (the same exact-match convention as WR-37's
 * `responseValidators` record).
 */
export interface ResponseAssertionRule {
  /** Exact `targetUrl` this rule applies to. */
  targetUrl: string;
  /**
   * Statuses the rule considers deliverable. Default: every 2xx
   * (`200`–`299`). A response outside the whitelist never reaches
   * the assertions — it keeps the WR-30 failure classification. Must
   * be a non-empty list of integer codes 100–599 when present.
   */
  expectedStatuses?: number[];
  /**
   * The assertions that must all pass on the decoded JSON body.
   * May be omitted or empty — a rule may exist just to pin the
   * status whitelist.
   */
  assertions?: ResponseAssertion[];
}

/**
 * Structured delivery failure: a whitelisted downstream response
 * failed one or more response assertions. Classified
 * `"assertion_failed"` by `classifyFailure` (see `src/failure.ts`) —
 * retryable, so it follows the normal backoff / circuit / budget path.
 */
export class AssertionFailedError extends Error {
  /** The endpoint whose response failed the assertions. */
  readonly targetUrl: string;
  /** Human-readable reason (the first failing assertion's detail). */
  readonly reason: string;
  /**
   * The downstream HTTP status (duck-typed by the WR-54 response
   * summary, so the audit trail still shows the status code).
   */
  readonly statusCode?: number;

  constructor(targetUrl: string, reason: string, statusCode?: number) {
    super(`Downstream response failed assertion for ${targetUrl}: ${reason}`);
    this.name = "AssertionFailedError";
    this.targetUrl = targetUrl;
    this.reason = reason;
    if (statusCode !== undefined) {
      this.statusCode = statusCode;
    }
  }
}

/** Fired when a delivery attempt fails a response assertion (WR-118). */
export interface AssertionFailureInfo {
  /** Delivery id. */
  id: string;
  /** End-to-end trace ID. */
  traceId: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  /** Downstream endpoint (`targetUrl`) whose response failed. */
  endpoint: string;
  /** Attempts consumed so far, including this one. */
  attempts: number;
  /** The first failing assertion's detail. */
  reason: string;
}

const ASSERTION_OPERATORS: ReadonlySet<string> = new Set([
  "eq",
  "ne",
  "gt",
  "gte",
  "lt",
  "lte",
  "exists",
  "matches",
]);

const IDENT_START = /[A-Za-z_$]/;
const IDENT_PART = /[A-Za-z0-9_$]/;

/**
 * Parse a strict assertion path into segments (`string` for `.name`,
 * `number` for `[index]`). `$` alone addresses the whole document.
 * Throws `RangeError` on anything outside the grammar — this is the
 * fail-fast half of the illegal-expression contract (the other half
 * is `assertValidResponseAssertion`, which labels the error).
 */
export function parseAssertionPath(path: string): Array<string | number> {
  if (path === "$") return [];
  if (!path.startsWith("$")) {
    throw new RangeError(`assertion path must start with "$", got ${JSON.stringify(path)}`);
  }
  const segments: Array<string | number> = [];
  let i = 1;
  while (i < path.length) {
    const ch = path[i] as string;
    if (ch === ".") {
      i += 1;
      const name = readIdentifier(path, i);
      if (name.length === 0) {
        throw new RangeError(`assertion path ${JSON.stringify(path)}: expected a name after "."`);
      }
      segments.push(name);
      i += name.length;
    } else if (ch === "[") {
      const close = path.indexOf("]", i + 1);
      if (close === -1) {
        throw new RangeError(`assertion path ${JSON.stringify(path)}: unterminated "["`);
      }
      const index = path.slice(i + 1, close);
      if (!/^\d+$/.test(index)) {
        throw new RangeError(
          `assertion path ${JSON.stringify(path)}: [${index}] is not a numeric index`
        );
      }
      segments.push(Number(index));
      i = close + 1;
    } else {
      throw new RangeError(
        `assertion path ${JSON.stringify(path)}: unexpected ${JSON.stringify(ch)} at offset ${i} — only ".name" and "[index]" segments are supported`
      );
    }
  }
  if (segments.length === 0) {
    // "$." or "$[" left nothing behind — a dangling operator.
    throw new RangeError(`assertion path ${JSON.stringify(path)}: no segments after "$"`);
  }
  return segments;
}

function readIdentifier(path: string, from: number): string {
  if (from >= path.length || !IDENT_START.test(path[from] as string)) {
    return "";
  }
  let i = from + 1;
  while (i < path.length && IDENT_PART.test(path[i] as string)) {
    i += 1;
  }
  return path.slice(from, i);
}

/**
 * Resolve parsed path segments against a decoded JSON value.
 * Missing keys, null hops, and out-of-range indexes resolve to
 * `undefined` — never throw. (A missing value fails the assertion
 * closed at evaluation time, except for the `exists` operator.)
 */
export function resolveAssertionPath(
  document: unknown,
  segments: Array<string | number>
): unknown {
  let current = document;
  for (const segment of segments) {
    if (current === null || current === undefined) return undefined;
    if (typeof segment === "string") {
      if (typeof current !== "object") return undefined;
      current = (current as Record<string, unknown>)[segment];
    } else {
      if (!Array.isArray(current)) return undefined;
      current = current[segment];
    }
  }
  return current;
}

/** Validate one rule; throws `RangeError` on the first illegal value. */
export function assertValidResponseAssertionRule(rule: unknown, label: string): void {
  if (rule === null || typeof rule !== "object" || Array.isArray(rule)) {
    throw new RangeError(`${label} must be an object`);
  }
  const r = rule as Record<string, unknown>;
  if (typeof r.targetUrl !== "string" || r.targetUrl.length === 0) {
    throw new RangeError(`${label}.targetUrl must be a non-empty string`);
  }
  if (r.expectedStatuses !== undefined) {
    const statuses = r.expectedStatuses;
    if (!Array.isArray(statuses) || statuses.length === 0) {
      throw new RangeError(`${label}.expectedStatuses must be a non-empty array of HTTP status codes`);
    }
    for (const code of statuses) {
      if (!Number.isInteger(code) || (code as number) < 100 || (code as number) > 599) {
        throw new RangeError(
          `${label}.expectedStatuses must contain only integer status codes 100-599, got ${JSON.stringify(code)}`
        );
      }
    }
  }
  if (r.assertions !== undefined) {
    const assertions = r.assertions;
    if (!Array.isArray(assertions)) {
      throw new RangeError(`${label}.assertions must be an array`);
    }
    assertions.forEach((assertion, index) => {
      assertValidResponseAssertion(assertion, `${label}.assertions[${index}]`);
    });
  }
}

/** Validate one assertion; throws `RangeError` on the first illegal value. */
export function assertValidResponseAssertion(assertion: unknown, label: string): void {
  if (assertion === null || typeof assertion !== "object" || Array.isArray(assertion)) {
    throw new RangeError(`${label} must be an object`);
  }
  const a = assertion as Record<string, unknown>;
  if (typeof a.path !== "string" || a.path.length === 0) {
    throw new RangeError(`${label}.path must be a non-empty string`);
  }
  try {
    parseAssertionPath(a.path);
  } catch (err) {
    // Re-label the grammar error so the operator can find the
    // offending assertion in a long rule list.
    throw new RangeError(`${label}.path: ${(err as Error).message}`);
  }
  if (typeof a.op !== "string" || !ASSERTION_OPERATORS.has(a.op)) {
    throw new RangeError(
      `${label}.op must be one of ${[...ASSERTION_OPERATORS].join(" | ")}, got ${JSON.stringify(a.op)}`
    );
  }
  const op = a.op as AssertionOperator;
  if (op === "exists") {
    if (a.value !== undefined) {
      throw new RangeError(`${label}: op "exists" takes no value`);
    }
    return;
  }
  if (a.value === undefined) {
    throw new RangeError(`${label}: op "${op}" requires a value`);
  }
  if (op === "matches") {
    if (typeof a.value !== "string") {
      throw new RangeError(`${label}.value must be a string holding a regular expression for op "matches"`);
    }
    try {
      new RegExp(a.value);
    } catch {
      throw new RangeError(`${label}.value is not a valid regular expression: ${JSON.stringify(a.value)}`);
    }
  }
  if (op === "gt" || op === "gte" || op === "lt" || op === "lte") {
    if (typeof a.value !== "number" || !Number.isFinite(a.value)) {
      throw new RangeError(`${label}.value must be a finite number for op "${op}"`);
    }
  }
}

/**
 * Whether a status code may carry assertions under this rule —
 * the rule's whitelist, or every 2xx when the rule sets none.
 */
export function isResponseStatusWhitelisted(statusCode: number, rule: ResponseAssertionRule): boolean {
  const whitelist = rule.expectedStatuses;
  if (whitelist === undefined) {
    return statusCode >= 200 && statusCode <= 299;
  }
  return whitelist.includes(statusCode);
}

/** The outcome of evaluating a rule against one response body. */
export interface ResponseAssertionVerdict {
  passed: boolean;
  /** The first failing assertion's detail; present when `passed` is false. */
  reason?: string;
}

/**
 * Evaluate a rule's assertions against a raw response body.
 *
 * Fail-closed by design: a body that is not JSON, a path that
 * resolves to nothing, a type mismatch on a numeric comparison, or
 * any evaluation error fails the verdict — it never silently
 * blesses a response the evaluator could not understand. Rules with
 * no assertions always pass (the whitelist check is the caller's).
 */
export function evaluateResponseAssertionRule(
  rule: ResponseAssertionRule,
  body: Buffer
): ResponseAssertionVerdict {
  const assertions = rule.assertions ?? [];
  if (assertions.length === 0) {
    return { passed: true };
  }
  let document: unknown;
  try {
    document = JSON.parse(body.toString("utf8"));
  } catch {
    // Not JSON — the assertions cannot be evaluated, so the response
    // cannot be trusted. Fail closed.
    return { passed: false, reason: "response body is not JSON" };
  }
  for (const assertion of assertions) {
    const reason = evaluateOneAssertion(document, assertion);
    if (reason !== undefined) {
      return { passed: false, reason };
    }
  }
  return { passed: true };
}

/**
 * Evaluate one assertion; returns `undefined` when it passes, else a
 * human-readable failure detail. Evaluation never throws — the
 * construction-time validation guarantees well-formed assertions, and
 * anything unexpected (a regex that no longer compiles, a hostile
 * value) fails closed here.
 */
function evaluateOneAssertion(document: unknown, assertion: ResponseAssertion): string | undefined {
  let actual: unknown;
  try {
    actual = resolveAssertionPath(document, parseAssertionPath(assertion.path));
  } catch {
    return `path ${JSON.stringify(assertion.path)} could not be evaluated`;
  }
  const at = JSON.stringify(assertion.path);
  switch (assertion.op) {
    case "exists":
      return actual === undefined ? `expected ${at} to exist` : undefined;
    case "eq":
      return actual === assertion.value
        ? undefined
        : `expected ${at} === ${JSON.stringify(assertion.value)}, got ${JSON.stringify(actual)}`;
    case "ne":
      return actual !== assertion.value
        ? undefined
        : `expected ${at} !== ${JSON.stringify(assertion.value)}`;
    case "gt":
    case "gte":
    case "lt":
    case "lte": {
      const expected = assertion.value as number;
      if (typeof actual !== "number" || !Number.isFinite(actual)) {
        return `expected ${at} to be a finite number for "${assertion.op}", got ${JSON.stringify(actual)}`;
      }
      const ok =
        assertion.op === "gt"
          ? actual > expected
          : assertion.op === "gte"
            ? actual >= expected
            : assertion.op === "lt"
              ? actual < expected
              : actual <= expected;
      return ok ? undefined : `expected ${at} ${assertion.op} ${expected}, got ${actual}`;
    }
    case "matches": {
      if (typeof actual !== "string") {
        return `expected ${at} to be a string for "matches", got ${JSON.stringify(actual)}`;
      }
      let pattern: RegExp;
      try {
        pattern = new RegExp(assertion.value as string);
      } catch {
        // Cannot happen for validated rules (the pattern is compiled
        // at construction), but fail closed anyway.
        return `invalid regular expression for ${at}`;
      }
      return pattern.test(actual)
        ? undefined
        : `expected ${at} to match ${JSON.stringify(assertion.value)}, got ${JSON.stringify(actual)}`;
    }
  }
}
