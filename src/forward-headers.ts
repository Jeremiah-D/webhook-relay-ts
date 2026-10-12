/**
 * Outbound request header forwarding allowlist (WR-69).
 *
 * By default the relay forwards the inbound request's headers to the
 * downstream (minus the relay-owned strips the intake applies: `host`,
 * `content-length`, stale `content-encoding`, `x-relay-*`,
 * `x-tenant-id`, `x-api-key`). That default is convenient — trace
 * correlation and content hints flow through — but it also means a
 * caller's `authorization` or `cookie` header reaches a downstream that
 * never asked for it. This module adds a per-endpoint allow/deny gate on
 * the *passthrough* headers, evaluated in `buildWireRequest`
 * (`src/server.ts`) after the intake strips and before the relay stamps
 * its own forced headers.
 *
 * Semantics:
 * - Rules are per endpoint (exact `targetUrl` match, the same convention
 *   as `tlsPins` / `compressOutbound`). Endpoints without a rule keep
 *   the exact current behavior.
 * - `allow` (absent = allow everything) and `deny` (absent = deny
 *   nothing) are lists of header-name patterns; `deny` wins over `allow`
 *   — an explicit deny can never be overridden.
 * - `authorization` and `cookie` are in the *default* deny set: with a
 *   rule configured for an endpoint they are never forwarded unless the
 *   operator explicitly allowlists them (the explicit allow wins over
 *   the default deny, never over an explicit deny). Without a rule the
 *   current pass-through behavior is preserved byte-for-byte.
 * - Relay-forced headers are stamped *after* the gate and are always
 *   present: `x-trace-id`, `x-relay-signature` / `x-relay-key-id`
 *   (WR-26), the WR-44 idempotency key, and `content-encoding` /
 *   `accept-encoding` (WR-40/WR-62). The rule can neither drop them nor
 *   be confused by them — they are not in the passthrough set.
 *
 * Matching is case-insensitive against the lowercased header name.
 * Patterns are strings compiled as regexes (a plain name like
 * `"x-custom-id"` is a regex that matches exactly, `"x-.*"` a prefix
 * family) or `RegExp` objects. Invalid patterns throw `RangeError` at
 * startup — never mid-delivery.
 *
 * Composes with WR-26 (signing stamps after the gate, always retained)
 * and WR-36 (mTLS is transport-level, orthogonal); WR-65's `x-api-key`
 * never reaches the gate at all (stripped at intake).
 */

/** One endpoint's header forwarding rule, as configured. */
export interface ForwardHeadersRuleConfig {
  /**
   * Patterns for headers to forward. Absent = forward everything the
   * default/explicit deny does not block. An explicit empty list forwards
   * nothing (except the relay-forced headers, which always survive).
   */
  allow?: Array<string | RegExp>;
  /**
   * Patterns for headers to drop. Evaluated first: an explicit deny
   * always wins over any allow, including an explicit one.
   */
  deny?: Array<string | RegExp>;
}

/** A rule with its patterns compiled and normalized at startup. */
export interface CompiledForwardHeadersRule {
  /** `undefined` when the config had no `allow` — "allow everything". */
  allow: RegExp[] | undefined;
  deny: RegExp[];
}

/**
 * Headers that are never forwarded *by default* when a rule is configured
 * for an endpoint (see module doc for the override semantics).
 */
export const FORWARD_HEADERS_DEFAULT_DENY = ["authorization", "cookie"] as const;

function compilePattern(pattern: string | RegExp, what: string): RegExp {
  if (typeof pattern === "string") {
    try {
      return new RegExp(pattern, "i");
    } catch (err) {
      throw new RangeError(`${what}: invalid header pattern ${JSON.stringify(pattern)}: ${(err as Error).message}`);
    }
  }
  if (pattern instanceof RegExp) {
    // Rebuild without the stateful flags: `test()` on a /g/y regex is
    // lastIndex-sensitive, which would make forwarding nondeterministic.
    const flags = pattern.flags.replace(/[gy]/g, "");
    return new RegExp(pattern.source, flags.includes("i") ? flags : flags + "i");
  }
  throw new RangeError(`${what}: header patterns must be strings or RegExp, got ${typeof pattern}`);
}

function compileList(list: Array<string | RegExp> | undefined, what: string): RegExp[] | undefined {
  if (list === undefined) return undefined;
  if (!Array.isArray(list)) {
    throw new RangeError(`${what}: must be an array of header patterns, got ${typeof list}`);
  }
  return list.map((p, i) => compilePattern(p, `${what}[${i}]`));
}

/**
 * Validate and compile the per-endpoint forwarding rules. Throws
 * `RangeError` on any invalid config (callers wrap with their endpoint
 * context).
 */
export function resolveForwardHeadersConfig(
  record: Record<string, ForwardHeadersRuleConfig>
): Map<string, CompiledForwardHeadersRule> {
  if (record === null || typeof record !== "object" || Array.isArray(record)) {
    throw new RangeError(`forwardHeaders must be a record of targetUrl -> rule, got ${Array.isArray(record) ? "array" : typeof record}`);
  }
  const out = new Map<string, CompiledForwardHeadersRule>();
  for (const [endpoint, cfg] of Object.entries(record)) {
    const what = `forwardHeaders[${JSON.stringify(endpoint)}]`;
    if (cfg === null || typeof cfg !== "object" || Array.isArray(cfg)) {
      throw new RangeError(`${what}: rule must be an object, got ${Array.isArray(cfg) ? "array" : typeof cfg}`);
    }
    out.set(endpoint, {
      allow: compileList(cfg.allow, `${what}.allow`),
      deny: compileList(cfg.deny, `${what}.deny`) ?? [],
    });
  }
  return out;
}

/**
 * Whether the passthrough header `name` survives the gate. The name is
 * matched case-insensitively. Precedence: explicit deny > explicit allow
 * > default deny (`authorization`/`cookie`) > absent allow (= forward).
 */
export function shouldForwardHeader(rule: CompiledForwardHeadersRule, name: string): boolean {
  const lower = name.toLowerCase();
  if (rule.deny.some((re) => re.test(lower))) return false;
  if (rule.allow !== undefined) {
    // An explicit allow overrides the *default* deny (the operator asked
    // for the header by name), but never an explicit deny (checked above).
    return rule.allow.some((re) => re.test(lower));
  }
  return !(FORWARD_HEADERS_DEFAULT_DENY as readonly string[]).some((d) => d === lower);
}
