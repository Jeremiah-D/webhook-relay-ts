/**
 * WR-197: centralized operator action audit log.
 *
 * Operator API write operations (endpoint pause/resume/enable, key
 * revocation, config reloads) already emit scattered delivery-stream
 * audit events (`endpoint_paused`, `operator_key_revoked`,
 * `endpoint_config_updated`, ...). This module is the orthogonal,
 * centralized operator ledger: one entry per executed operator mutation
 * carrying the acting operator's key id, the action name, the target
 * resource, and the before/after diff — stored separately from the
 * delivery audit stream and queryable by key id.
 *
 * Entries never carry secret material: key ids and config-field diffs
 * only, never key bytes. The log is an in-memory bounded deque —
 * oldest entries are evicted past `maxEntries`, so it never grows
 * without bound under sustained operator activity.
 *
 * Zero dependencies.
 */

/** Outcome of the recorded operator mutation. */
export type OperatorAuditResult = "ok" | "error";

/** One operator mutation, as recorded by {@link OperatorAuditLog}. All JSON-serializable. */
export interface OperatorAuditEntry {
  /** Monotonic sequence number, 1-based. */
  seq: number;
  /** ISO-8601 timestamp of the mutation. */
  at: string;
  /**
   * The acting operator's key id (`"legacy"` for the legacy
   * `operatorToken`). This is the *actor*, never the revoked key —
   * revoked key ids land in `target`.
   */
  keyId: string;
  /** Machine-readable action name, e.g. `"endpoints.pause"`. */
  action: string;
  /** The resource acted on (endpoint URL, key id, config prefix...). */
  target?: string;
  /** Before-state of the mutated fields (JSON-serializable). */
  before?: unknown;
  /** After-state of the mutated fields (JSON-serializable). */
  after?: unknown;
  /** Whether the mutation executed (`"ok"`) or was attempted and failed (`"error"`). */
  result: OperatorAuditResult;
}

/** Options for {@link OperatorAuditLog}. */
export interface OperatorAuditLogOptions {
  /**
   * Maximum entries retained: the oldest entries are evicted past this
   * bound. Default: 10000. Must be an integer >= 1.
   */
  maxEntries?: number;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
}

/** Input for {@link OperatorAuditLog.record}: `seq`/`at` are assigned by the log. */
export interface OperatorAuditRecordInput {
  keyId: string;
  action: string;
  target?: string;
  before?: unknown;
  after?: unknown;
  result?: OperatorAuditResult;
}

/** Filter for {@link OperatorAuditLog.query}. */
export interface OperatorAuditQuery {
  /** Only entries recorded by this operator key id. */
  keyId?: string;
  /** Only entries with this action name. */
  action?: string;
  /** Maximum entries returned (newest first). Default: 100. */
  limit?: number;
}

/** Default bound for {@link OperatorAuditLogOptions.maxEntries}. */
export const DEFAULT_OPERATOR_AUDIT_MAX_ENTRIES = 10_000;
/** Default bound for {@link OperatorAuditQuery.limit}. */
export const DEFAULT_OPERATOR_AUDIT_QUERY_LIMIT = 100;

/** Validate an {@link OperatorAuditLogOptions}. Throws `RangeError` on anything invalid. */
export function assertValidOperatorAuditLogOptions(opts: unknown): void {
  if (opts === null || typeof opts !== "object" || Array.isArray(opts)) {
    throw new RangeError(`operatorAuditLog must be an options object, got ${String(opts)}`);
  }
  const o = opts as Record<string, unknown>;
  const maxEntries = o.maxEntries ?? DEFAULT_OPERATOR_AUDIT_MAX_ENTRIES;
  if (!Number.isInteger(maxEntries) || (maxEntries as number) < 1) {
    throw new RangeError(
      `operatorAuditLog.maxEntries must be an integer >= 1, got ${String(o.maxEntries)}`
    );
  }
  if (o.now !== undefined && typeof o.now !== "function") {
    throw new RangeError(`operatorAuditLog.now must be a function, got ${String(o.now)}`);
  }
}

/**
 * Bounded in-memory ledger of operator mutations (WR-197).
 *
 * `record()` appends one entry per executed operator mutation;
 * `query()` reads it back filtered by acting key id and/or action.
 * The delivery audit stream (`AuditLog`) is untouched — this ledger is
 * the centralized operator view, not a second copy of delivery events.
 */
export class OperatorAuditLog {
  private readonly maxEntries: number;
  private readonly now: () => number;
  private seq = 0;
  /** Oldest first; evicted from the front past `maxEntries`. */
  private readonly entries: OperatorAuditEntry[] = [];

  constructor(opts: OperatorAuditLogOptions = {}) {
    assertValidOperatorAuditLogOptions(opts);
    this.maxEntries = opts.maxEntries ?? DEFAULT_OPERATOR_AUDIT_MAX_ENTRIES;
    this.now = opts.now ?? Date.now;
  }

  /**
   * Append one operator mutation. `keyId` and `action` must be
   * non-empty strings; `before`/`after` must be JSON-serializable and
   * must never carry secret material (key ids only, never key bytes).
   * Returns the stored entry.
   */
  record(input: OperatorAuditRecordInput): OperatorAuditEntry {
    if (typeof input.keyId !== "string" || input.keyId.length === 0) {
      throw new RangeError(`operator audit record: keyId must be a non-empty string`);
    }
    if (typeof input.action !== "string" || input.action.length === 0) {
      throw new RangeError(`operator audit record: action must be a non-empty string`);
    }
    const entry: OperatorAuditEntry = {
      seq: ++this.seq,
      at: new Date(this.now()).toISOString(),
      keyId: input.keyId,
      action: input.action,
      ...(input.target !== undefined ? { target: input.target } : {}),
      ...(input.before !== undefined ? { before: input.before } : {}),
      ...(input.after !== undefined ? { after: input.after } : {}),
      result: input.result ?? "ok",
    };
    this.entries.push(entry);
    if (this.entries.length > this.maxEntries) {
      this.entries.splice(0, this.entries.length - this.maxEntries);
    }
    return entry;
  }

  /**
   * Read back entries, newest first, filtered by `keyId` and/or
   * `action`. `limit` caps the result (default 100); a non-positive
   * limit yields an empty list.
   */
  query(filter: OperatorAuditQuery = {}): OperatorAuditEntry[] {
    const limit = filter.limit ?? DEFAULT_OPERATOR_AUDIT_QUERY_LIMIT;
    if (!Number.isInteger(limit) || limit <= 0) return [];
    const out: OperatorAuditEntry[] = [];
    for (let i = this.entries.length - 1; i >= 0 && out.length < limit; i--) {
      const e = this.entries[i];
      if (filter.keyId !== undefined && e.keyId !== filter.keyId) continue;
      if (filter.action !== undefined && e.action !== filter.action) continue;
      out.push(e);
    }
    return out;
  }

  /** Ledger size and bound. */
  stats(): { entries: number; maxEntries: number } {
    return { entries: this.entries.length, maxEntries: this.maxEntries };
  }
}
