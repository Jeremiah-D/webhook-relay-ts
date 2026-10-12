/**
 * Scoped operator API keys (WR-82).
 *
 * The operator plane (`handleOperator` in `src/server.ts`) used to be
 * guarded by one shared bearer secret (`operatorToken`): anyone holding
 * it could read metrics/audit trails AND replay dead letters or hot-patch
 * endpoint config. That all-or-nothing trust shape is a poor fit for a
 * backend engineering workflow where a monitoring agent only needs the
 * read-only endpoints. `operatorKeys` upgrades the plane to a key ring:
 * each entry has a stable `id` plus an optional `scopes` list drawn from
 * exactly two case-sensitive scopes —
 *
 * - `read`: every read-only operator path (`GET /metrics`, `GET /audit`,
 *   `GET /audit/verify`, `GET /latency`, `GET /slo-risk`, `GET /usage`,
 *   `GET /events`, `GET /events/archive`, `GET /deliveries/:traceId`,
 *   `GET /dead-letter`, `GET /dead-letter/stats`,
 *   `GET /dead-letter/auto-replay/status`, `GET /scheduled`).
 * - `admin`: everything `read` covers plus every mutating operator path
 *   (dead-letter replays, auto-replay pause/resume/trigger,
 *   `POST /config/endpoint`, endpoint pause/resume, schedule
 *   pause/resume).
 *
 * Semantics, deliberately conservative:
 * - The legacy single `operatorToken` keeps working with full `admin`
 *   semantics (its key id audits as `"legacy"`). When both are
 *   configured, either authenticates; when neither is, the operator
 *   plane stays 404 fail-closed, exactly the legacy behavior.
 * - A key entry with no `scopes` (or an empty array) is fail-closed: it
 *   authenticates, but every operator path answers 403 — the operator
 *   can see nothing and change nothing.
 * - Every operator call's audit event carries the key's `keyId`, so an
 *   incident review can tell the monitoring key apart from the
 *   human operator.
 *
 * Zero dependencies: the only import is `node:crypto`'s
 * `timingSafeEqual`, reused in the same no-early-exit style as
 * `src/api-key.ts`'s `InboundApiKeyAuth.verifyKey`.
 */

import { timingSafeEqual } from "node:crypto";

/** The two operator scopes. Case-sensitive; anything else is a RangeError. */
export type OperatorScope = "read" | "admin";

/** The scope strings, as a tuple for validation and error messages. */
export const OPERATOR_SCOPES: readonly OperatorScope[] = ["read", "admin"];

/** One operator key in the `operatorKeys` ring. */
export interface OperatorKeyEntry {
  /**
   * Stable key identifier, surfaced in every operator audit event as
   * `keyId`. Survives rotation: keep the id stable while the key value
   * changes.
   */
  id: string;
  /**
   * The key value itself, compared in constant time against the bearer
   * token. Never empty.
   */
  key: string;
  /**
   * Scopes granted to this key. Unset (or an empty array) is fail-closed:
   * the key authenticates but is authorized for nothing. An entry that
   * grants `admin` implicitly includes `read`.
   */
  scopes?: OperatorScope[];
}

/** An authenticated operator identity: the matched key's id and scopes. */
export interface OperatorIdentity {
  /** The matched key's `id` (`"legacy"` for the old `operatorToken`). */
  id: string;
  /** The scopes this identity may exercise. */
  scopes: OperatorScope[];
}

/** Fail with a RangeError naming the offending input. */
function invalid(where: string, detail: string): never {
  throw new RangeError(`operatorKeys: ${where}: ${detail}`);
}

/**
 * Validate the `operatorKeys` ring. Throws RangeError on a non-array, an
 * entry with an empty `id` or `key`, duplicate key ids, duplicate key
 * values, a non-array `scopes`, or a scope string other than `"read"` /
 * `"admin"` (exact, case-sensitive) — fail fast at startup, never
 * mid-request. An unset or empty `scopes` is legal: that key is
 * fail-closed (authenticates, authorizes nothing).
 */
export function assertValidOperatorKeys(keys: OperatorKeyEntry[] | undefined): void {
  if (keys === undefined) return;
  if (!Array.isArray(keys)) {
    throw new RangeError("operatorKeys: expected an array of { id, key, scopes? } entries");
  }
  const seenIds = new Set<string>();
  const seenKeys = new Set<string>();
  keys.forEach((entry, i) => {
    const where = `operatorKeys[${i}]`;
    if (!entry || typeof entry.id !== "string" || entry.id === "") {
      invalid(where, "id must be a non-empty string");
    }
    if (typeof entry.key !== "string" || entry.key === "") {
      invalid(where, "key must be a non-empty string");
    }
    if (seenIds.has(entry.id)) {
      invalid(where, `duplicate key id "${entry.id}"`);
    }
    seenIds.add(entry.id);
    // Duplicate key *values* are rejected: two entries that both match
    // would make the audit `keyId` ambiguous, and they signal a copy
    // error in the config, not a legitimate rotation (rotation changes
    // the value while keeping the id).
    if (seenKeys.has(entry.key)) {
      invalid(where, "duplicate key value (each entry must have a distinct key)");
    }
    seenKeys.add(entry.key);
    if (entry.scopes !== undefined) {
      if (!Array.isArray(entry.scopes)) {
        invalid(where, 'scopes must be an array of "read" | "admin"');
      }
      for (const scope of entry.scopes) {
        if (scope !== "read" && scope !== "admin") {
          invalid(
            where,
            `unknown operator scope ${JSON.stringify(String(scope))} — expected "read" or "admin" (case-sensitive)`
          );
        }
      }
    }
  });
}

/**
 * Extract the bearer token from an `Authorization` header, or `null` when
 * the header is absent or not a `Bearer` credential.
 */
export function bearerToken(header: unknown): string | null {
  const raw = Array.isArray(header) ? header[0] : header;
  if (typeof raw !== "string") return null;
  const prefix = "Bearer ";
  if (!raw.startsWith(prefix) || raw.length === prefix.length) return null;
  return raw.slice(prefix.length);
}

/**
 * Compare two strings in constant time (never throws on length
 * mismatch): the key values are the protected secret, not the lengths.
 */
function keysEqual(expected: string, candidate: string): boolean {
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(candidate, "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/**
 * Match a presented bearer token against the legacy `operatorToken` and
 * the `operatorKeys` ring. The legacy token, when set, authenticates with
 * full `admin` semantics (`keyId: "legacy"`); every ring entry is
 * compared with `timingSafeEqual` (no early exit on a match) so the
 * comparison timing reveals neither the key nor which entry matched.
 * Returns the operator identity, or `null` when nothing matched. Never
 * throws on hostile input.
 */
export function matchOperatorKey(
  presented: string | null,
  legacyToken: string | undefined,
  keys: readonly OperatorKeyEntry[]
): OperatorIdentity | null {
  try {
    if (presented === null) return null;
    if (
      legacyToken !== undefined &&
      legacyToken !== "" &&
      keysEqual(legacyToken, presented)
    ) {
      return { id: "legacy", scopes: ["admin"] };
    }
    let matched: OperatorIdentity | null = null;
    for (const entry of keys) {
      // No early exit: compare every key so timing does not reveal which
      // entry matched; keep the first matching id so the audit trail is
      // deterministic.
      if (keysEqual(entry.key, presented) && matched === null) {
        matched = { id: entry.id, scopes: entry.scopes ?? [] };
      }
    }
    return matched;
  } catch {
    return null;
  }
}

/**
 * Whether `identity` may call a recognized operator path with `method`.
 * Every recognized `GET` operator path is read-only (`read` suffices);
 * every recognized `POST` operator path is mutating (needs `admin`).
 * Call only after the path is known to be an operator path and the
 * method is one the path allows — unknown paths and method mismatches
 * keep their 404/405 answers ahead of this check.
 */
export function operatorMay(identity: OperatorIdentity, method: string): boolean {
  if (method !== "POST") return identity.scopes.includes("read") || identity.scopes.includes("admin");
  return identity.scopes.includes("admin");
}
