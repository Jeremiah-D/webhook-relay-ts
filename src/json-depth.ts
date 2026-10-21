/**
 * WR-173: inbound JSON nesting-depth guard.
 *
 * A webhook body nested thousands of levels deep (`[[[[...`) is a
 * cheap denial-of-service against whatever parses it next: V8's
 * `JSON.parse` itself throws `RangeError` past its own stack budget,
 * and a downstream JSON parser with a deeper budget can still be
 * stack-smashed by a payload the relay happily forwarded. The body-size
 * cap (WR-25) bounds *volume*; this module bounds *shape* — the two are
 * orthogonal.
 *
 * Depth counts nested containers (arrays and objects) identically: a
 * scalar has depth 0, `[]` has depth 1, `[[]]` has depth 2. Only a JSON
 * array or object at the root can have depth > 0, so bodies whose first
 * non-whitespace byte is not `{` or `[` skip parsing entirely — the
 * verdict is `skipped`, never a false rejection.
 *
 * The walk is iterative (an explicit stack): a recursive walk would
 * reintroduce exactly the stack exhaustion this guard exists to
 * prevent. `JSON.parse` output is acyclic, so no visited-set is needed.
 */

/** Default maximum JSON nesting depth when the option is unset. */
export const DEFAULT_MAX_JSON_DEPTH = 32;

/**
 * Validate the `maxJsonDepth` option. Returns the value when valid;
 * throws `RangeError` otherwise — at startup, never mid-request.
 */
export function assertValidMaxJsonDepth(value: unknown): number {
  if (!Number.isInteger(value) || (value as number) < 1) {
    throw new RangeError(
      `createRelayServer: \`maxJsonDepth\` must be a positive integer, got ${JSON.stringify(value)}`
    );
  }
  return value as number;
}

/**
 * Nesting depth of a parsed JSON value: the number of nested array /
 * object levels. Scalars are 0. Iterative — safe on adversarial input.
 */
export function jsonDepth(value: unknown): number {
  let max = 0;
  const stack: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }];
  let frame = stack.pop();
  while (frame !== undefined) {
    const v = frame.value;
    if (Array.isArray(v)) {
      const d = frame.depth + 1;
      if (d > max) max = d;
      for (let i = 0; i < v.length; i++) stack.push({ value: v[i], depth: d });
    } else if (typeof v === "object" && v !== null) {
      const d = frame.depth + 1;
      if (d > max) max = d;
      for (const key of Object.keys(v)) {
        stack.push({ value: (v as Record<string, unknown>)[key], depth: d });
      }
    }
    frame = stack.pop();
  }
  return max;
}

/** Outcome of {@link checkJsonDepth}. */
export interface JsonDepthVerdict {
  /**
   * `true` when the body is not a JSON container (not JSON at all, or a
   * scalar / empty) — nothing to check, the body passes through.
   */
  skipped: boolean;
  /**
   * Nesting depth of arrays/objects (`Infinity` when `JSON.parse`
   * itself stack-overflowed — proof of excessive depth). 0 when
   * skipped.
   */
  depth: number;
  /** `true` when the body is within the depth limit. */
  ok: boolean;
}

/**
 * Check an inbound body against the depth limit. Never throws: a body
 * that is not JSON is `skipped`; a `JSON.parse` stack overflow
 * (`RangeError`) is reported as over-limit rather than crashing the
 * intake — the overflow *is* the evidence.
 */
export function checkJsonDepth(body: Buffer, maxDepth: number): JsonDepthVerdict {
  const text = body.toString("utf8");
  const trimmed = text.trimStart();
  if (trimmed.length === 0) return { skipped: true, depth: 0, ok: true };
  const first = trimmed[0];
  // Only a JSON array or object at the root can have depth > 0 — a
  // scalar (`123`, `"s"`, `true`, `null`) is depth 0 by construction,
  // so anything else skips without paying for a parse.
  if (first !== "{" && first !== "[") return { skipped: true, depth: 0, ok: true };
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    if (err instanceof RangeError) {
      // V8 ran out of stack parsing it — the body is deeper than any
      // parser should have to survive. Reject as over-limit.
      return { skipped: false, depth: Infinity, ok: false };
    }
    // Not valid JSON — not a JSON depth problem; leave it alone.
    return { skipped: true, depth: 0, ok: true };
  }
  const depth = jsonDepth(parsed);
  return { skipped: false, depth, ok: depth <= maxDepth };
}
