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

/**
 * A live forward-headers patch (WR-433): exact `targetUrl` → new
 * forwarding rule, or `null` to clear that endpoint's rule. Endpoints
 * omitted from the patch keep their live rule.
 */
export type ForwardHeadersRevision = Record<string, ForwardHeadersRuleConfig | null>;

/** One endpoint's rule change, as returned by `reviseForwardHeadersMap`. */
export interface ForwardHeadersChange {
  /** The endpoint whose rule changed. */
  endpoint: string;
  /** The live rule before the revision (`null` = no rule was live). */
  previous: CompiledForwardHeadersRule | null;
  /** The live rule after the revision (`null` = rule cleared). */
  current: CompiledForwardHeadersRule | null;
}

/** Same-value test for two compiled rules (pattern source + flags, order-insensitive). */
function sameCompiledRule(a: CompiledForwardHeadersRule, b: CompiledForwardHeadersRule): boolean {
  const key = (list: RegExp[] | undefined): string | null =>
    list === undefined
      ? null
      : JSON.stringify(
          list.map((re) => [re.source, re.flags]).sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0))
        );
  return key(a.allow) === key(b.allow) && key(a.deny) === key(b.deny);
}

/**
 * Revise the live forward-headers rules in place (WR-433): validate the
 * whole patch first — the non-null entries go through the same gates
 * `resolveForwardHeadersConfig` applies at construction — then apply it
 * entry by entry, mutating `live` in place (never replacing the Map
 * object, so the sender, which reads the Map on every send, picks a
 * revision up from the next send, while a send already in flight keeps
 * the compiled rule object it read). Returns the per-endpoint changes;
 * an empty array means the patch was a same-value no-op (clearing an
 * endpoint with no rule, or setting a rule identical to the live one).
 *
 * Throws `RangeError` on a non-object or empty patch, or on any
 * invalid rule — with the live rules left completely intact (zero
 * partial application).
 */
export function reviseForwardHeadersMap(
  live: Map<string, CompiledForwardHeadersRule>,
  patch: ForwardHeadersRevision
): ForwardHeadersChange[] {
  if (patch === null || typeof patch !== "object" || Array.isArray(patch)) {
    throw new RangeError(
      "reviseForwardHeaders: patch must be a Record<targetUrl, ForwardHeadersRuleConfig | null>"
    );
  }
  const entries = Object.entries(patch);
  if (entries.length === 0) {
    throw new RangeError("reviseForwardHeaders: patch must contain at least one endpoint");
  }
  for (const [endpoint] of entries) {
    if (endpoint === "") {
      throw new RangeError("reviseForwardHeaders: patch keys must be non-empty endpoint strings");
    }
  }
  // Validate-then-apply: resolve the non-null entries through the
  // construction-time gates, so a bad rule binds nothing.
  // `Object.fromEntries` (not `obj[key] = …`) so an endpoint key like
  // `"__proto__"` lands as an own property instead of mutating a prototype.
  const newRules: Record<string, ForwardHeadersRuleConfig> = Object.fromEntries(
    entries.filter(([, rule]) => rule !== null) as Array<[string, ForwardHeadersRuleConfig]>
  );
  const resolved = resolveForwardHeadersConfig(newRules);
  const changes: ForwardHeadersChange[] = [];
  for (const [endpoint, rule] of entries) {
    const prev = live.get(endpoint) ?? null;
    if (rule === null) {
      if (prev === null) continue; // Clearing an endpoint with no rule: no-op.
      live.delete(endpoint);
      changes.push({ endpoint, previous: prev, current: null });
    } else {
      const next = resolved.get(endpoint)!;
      if (prev !== null && sameCompiledRule(prev, next)) continue; // Same-value: no-op.
      live.set(endpoint, next);
      changes.push({ endpoint, previous: prev, current: next });
    }
  }
  return changes;
}

/**
 * The live compiled rule as a user-facing config — patterns rebuilt
 * without the stateful `g`/`y` flags, so callers get a defensive copy
 * that can neither mutate the live rule nor share a stateful regex
 * with it. Only the fields the rule actually sets are present
 * (`allow` omitted when absent, `deny` omitted when empty), matching
 * the construction-time shape.
 */
export function forwardHeadersRuleToConfig(rule: CompiledForwardHeadersRule): ForwardHeadersRuleConfig {
  const clone = (re: RegExp): RegExp => {
    const flags = re.flags.replace(/[gy]/g, "");
    return new RegExp(re.source, flags.includes("i") ? flags : flags + "i");
  };
  const cfg: ForwardHeadersRuleConfig = {};
  if (rule.allow !== undefined) cfg.allow = rule.allow.map(clone);
  if (rule.deny.length > 0) cfg.deny = rule.deny.map(clone);
  return cfg;
}
