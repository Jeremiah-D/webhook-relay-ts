/**
 * Inbound per-endpoint API key authentication (WR-65).
 *
 * Not every sender can do HMAC: a legacy PSP, a tiny IoT device, or an
 * internal cron job may only be able to attach a static bearer secret to
 * a request. The API key gate gives those endpoints a real authenticator
 * without weakening anyone else: per-endpoint rules map an inbound path
 * to a set of `{ id, key }` entries, and the `x-api-key` header is
 * compared in constant time (`crypto.timingSafeEqual`) against every
 * entry in the set.
 *
 * - Rules match the inbound request path — exact (`/hooks/legacy`) or
 *   prefix (`/hooks/*`, which also matches `/hooks` itself) — the first
 *   matching rule in config order wins, mirroring WR-29 endpoint
 *   verifiers, WR-41 schema rules, and the WR-53 IP ACL. Paths with no
 *   matching rule skip the gate entirely, so enabling the feature changes
 *   nothing for unlisted endpoints (off by default, zero behavior
 *   change).
 * - Several keys coexist per rule so rotation is overlap-safe: deploy
 *   the new key alongside the old one (both verify), cut the sender
 *   over, then remove the old entry. Each entry's `id` is the stable key
 *   identifier that rides on `accepted` audit events (`keyId`); a
 *   rejection (no key matched) audits `keyId: "unknown"`, following the
 *   WR-20 rotation convention.
 * - The gate runs in the intake gates *before* the body is read (right
 *   after the WR-53 IP ACL, like it), so an unauthenticated caller costs
 *   zero bandwidth and zero downstream state: a missing or non-matching
 *   key is answered 401 (`connection: close`) and audited as `rejected`
 *   with reason `api_key_missing` / `api_key_invalid` — it never
 *   enqueues, burns no retry budget, and never trips the breaker.
 * - Orthogonal to signature verification: by default
 *   (`requireSignature` unset/false) the API key alone authenticates the
 *   endpoint — the signature check is skipped for requests that passed
 *   the gate. Set `requireSignature: true` to demand BOTH the key and a
 *   valid signature (the normal global/per-endpoint verifier check still
 *   runs in the admission pipeline). When both factors are in play, the
 *   accepted audit's `keyId` names the API key (the admission
 *   credential); a signature rejection after a passed gate carries the
 *   matched API key id, since possession was already proven.
 * - `x-api-key` is the caller's inbound credential, not part of the
 *   event: the server strips it from the headers forwarded downstream.
 *
 * Zero dependencies: the only import is `node:crypto`'s
 * `timingSafeEqual`.
 */

import { timingSafeEqual } from "node:crypto";

/** One API key in an endpoint's rotation set. */
export interface ApiKeyEntry {
  /**
   * Stable key identifier, surfaced in audit events as `keyId`.
   * Survives rotation: keep the id stable while the key value changes.
   */
  id: string;
  /**
   * The key value itself, compared in constant time against the
   * `x-api-key` header. Never empty.
   */
  key: string;
}

/** One per-endpoint API key rule (WR-65). */
export interface EndpointApiKeyRule {
  /** Request path pattern: exact (`/hooks/legacy`) or prefix (`/hooks/*`). */
  pattern: string;
  /**
   * The key set: at least one entry, ids unique, keys non-empty.
   * Several keys coexist so rotation is overlap-safe.
   */
  keys: ApiKeyEntry[];
  /**
   * When true, the endpoint additionally requires a valid signature —
   * the normal global/per-endpoint verifier check runs in the admission
   * pipeline after the key gate. Default false: the API key alone
   * authenticates the endpoint and the signature check is skipped for
   * requests that passed the gate.
   */
  requireSignature?: boolean;
}

/** Options for {@link InboundApiKeyAuth}. */
export interface ApiKeyOptions {
  /**
   * Per-endpoint rules in config order; the first matching rule wins.
   * Unset (or empty) means no endpoint is guarded — the feature is off.
   */
  rules?: EndpointApiKeyRule[];
}

/** Fail with a RangeError naming the offending input. */
function invalid(where: string, detail: string): never {
  throw new RangeError(`apiKeys: ${where}: ${detail}`);
}

/**
 * Validate endpoint API key rules. Throws RangeError on a non-array, a
 * pattern that is not a `/`-rooted path, an empty `keys` list, an entry
 * with an empty `id` or `key`, duplicate key ids within a rule, or a
 * non-boolean `requireSignature` — fail fast at startup, never
 * mid-request.
 */
export function assertValidEndpointApiKeyRules(rules: EndpointApiKeyRule[] | undefined): void {
  if (rules === undefined) return;
  if (!Array.isArray(rules)) {
    throw new RangeError("apiKeys.rules: expected an array of { pattern, keys, requireSignature? } rules");
  }
  rules.forEach((rule, i) => {
    const where = `apiKeys.rules[${i}]`;
    if (!rule || typeof rule.pattern !== "string" || rule.pattern === "" || !rule.pattern.startsWith("/")) {
      throw new RangeError(
        `${where}: pattern must be a path starting with "/" (exact) or ending with "/*" (prefix)`
      );
    }
    if (!Array.isArray(rule.keys) || rule.keys.length === 0) {
      throw new RangeError(`${where}: keys must be a non-empty array of { id, key } entries`);
    }
    const seen = new Set<string>();
    rule.keys.forEach((entry, j) => {
      const ewhere = `${where}.keys[${j}]`;
      if (!entry || typeof entry.id !== "string" || entry.id === "") {
        throw new RangeError(`${ewhere}: id must be a non-empty string`);
      }
      if (typeof entry.key !== "string" || entry.key === "") {
        throw new RangeError(`${ewhere}: key must be a non-empty string`);
      }
      if (seen.has(entry.id)) {
        throw new RangeError(`${ewhere}: duplicate key id "${entry.id}"`);
      }
      seen.add(entry.id);
    });
    if (rule.requireSignature !== undefined && typeof rule.requireSignature !== "boolean") {
      throw new RangeError(`${where}: requireSignature must be a boolean when set`);
    }
  });
}

/**
 * Select the API key rule for an inbound request path: the first
 * matching rule in config order (exact or prefix, same semantics as
 * WR-29/WR-41/WR-53), or `undefined` when nothing matches. Never throws.
 */
export function selectEndpointApiKeyRule<T extends { pattern: string }>(
  pathname: string,
  rules: readonly T[] | undefined
): T | undefined {
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

/**
 * The inbound API key gate: per-endpoint key sets plus constant-time
 * verification. Construct once at server startup (invalid config throws
 * RangeError there); `ruleFor` + `verifyKey` are then safe to call on
 * every request — they never throw on hostile input.
 */
export class InboundApiKeyAuth {
  private readonly rules: EndpointApiKeyRule[];

  constructor(opts: ApiKeyOptions = {}) {
    assertValidEndpointApiKeyRules(opts.rules);
    this.rules = opts.rules ?? [];
  }

  /**
   * The rule guarding `pathname` (first match wins), or `undefined`
   * when no rule matches — the request skips the gate entirely.
   */
  ruleFor(pathname: string): EndpointApiKeyRule | undefined {
    return selectEndpointApiKeyRule(pathname, this.rules);
  }

  /**
   * Verify the presented key against the rule's key set in constant
   * time: every entry is compared with `timingSafeEqual` (no early exit
   * on a match), so the comparison timing reveals neither the key nor
   * which entry matched. Returns the matched entry's `id`, or `null`.
   * A length mismatch is an instant non-match — the key length is not
   * the protected secret. Never throws.
   */
  verifyKey(rule: EndpointApiKeyRule, presented: string): string | null {
    try {
      if (typeof presented !== "string") return null;
      const candidate = Buffer.from(presented, "utf8");
      let matchedId: string | null = null;
      for (const entry of rule.keys) {
        const expected = Buffer.from(entry.key, "utf8");
        if (expected.length !== candidate.length) continue;
        // No early exit: compare every key so timing does not reveal
        // which entry matched; keep the first matching id so the audit
        // trail is deterministic even if two entries shared a value.
        if (timingSafeEqual(expected, candidate) && matchedId === null) {
          matchedId = entry.id;
        }
      }
      return matchedId;
    } catch {
      return null;
    }
  }
}
