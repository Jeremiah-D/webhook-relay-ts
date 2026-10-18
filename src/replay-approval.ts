import { randomBytes } from "node:crypto";

/**
 * Two-phase approval for dead-letter replays (WR-135).
 *
 * A dead-letter replay is a real funds-moving action in a payments
 * pipeline: re-queueing a webhook re-fires the downstream charge/refund
 * handler. This module adds an opt-in second pair of eyes — one operator
 * reviews the blast radius (`POST /dead-letter/replay/approve-request`
 * issues a one-shot token scoped to endpoint/tenant/ids), and execution
 * (`POST /dead-letter/replay` or `POST /dead-letter/{id}/replay`,
 * non-dry-run) consumes it. Dry runs never need approval: they have zero
 * side effects.
 *
 * The store is deliberately dumb: it issues random tokens
 * (`node:crypto` `randomBytes`), binds each to a scope and an expiry, and
 * enforces one-shot consumption. Enforcement lives in
 * `RetryQueue.replayDeadLetters`/`replayDeadLetter` (the token travels in
 * the call options); the HTTP layer in `src/server.ts` maps denials to
 * 403 and writes the `replay_approved` / `replay_approval_expired` audit
 * lines. Expired tokens are swept lazily — on issue and on consume —
 * never by a background timer, so an idle relay holds no timers.
 *
 * Zero dependencies, injectable clock for deterministic tests.
 */

/** Scope a replay approval token covers: every field is a ceiling. */
export interface ReplayApprovalScope {
  /** Only entries dead-lettered for this exact `targetUrl`. Unset: any endpoint. */
  endpoint?: string;
  /** Only this tenant's entries. Unset: any tenant. */
  tenant?: string;
  /** Only these dead-letter ids. Unset: any ids within the other fields. */
  ids?: string[];
}

/** Opt-in two-phase replay approval, embedded in `RetryQueueOptions`. */
export interface ReplayApprovalOptions {
  /**
   * Token TTL in ms. Default: 300_000 (5 minutes). Must be a finite
   * number > 0 — invalid values throw `RangeError` at construction.
   */
  ttlMs?: number;
  /** Clock in ms; defaults to `Date.now`. Injectable for tests. */
  now?: () => number;
}

/** A freshly issued approval token and its expiry (unix ms). */
export interface ReplayApprovalGrant {
  approvalToken: string;
  expiresAt: number;
}

/**
 * Why a token was rejected at execution time:
 * - `missing` — no token supplied, or the token was never issued;
 * - `expired` — the token outlived its TTL;
 * - `reused` — a one-shot token spent by an earlier execution;
 * - `scope_mismatch` — the execution is wider than the token's scope.
 */
export type ReplayApprovalDenyReason = "missing" | "expired" | "reused" | "scope_mismatch";

/** Thrown by the replay methods when the approval gate denies a replay. */
export class ReplayApprovalError extends Error {
  /** Stable machine-readable code; `reason` carries the verdict. */
  readonly code = "replay_approval_denied";
  readonly reason: ReplayApprovalDenyReason;
  constructor(reason: ReplayApprovalDenyReason) {
    super(`replay approval denied: ${reason}`);
    this.name = "ReplayApprovalError";
    this.reason = reason;
  }
}

/** Default token TTL: 5 minutes — long enough for a human to eyeball the preview. */
export const DEFAULT_REPLAY_APPROVAL_TTL_MS = 5 * 60 * 1000;

interface ApprovalTokenRecord {
  scope: ReplayApprovalScope;
  expiresAt: number;
  used: boolean;
}

/**
 * True when the approved scope covers the requested execution: every
 * scope field the token binds must match, and named ids must be a
 * subset. An unbound field on the token imposes no constraint — a
 * broad token executes narrow, never the reverse.
 */
export function approvalScopeCovers(
  approved: ReplayApprovalScope,
  requested: ReplayApprovalScope
): boolean {
  if (approved.endpoint !== undefined && requested.endpoint !== approved.endpoint) return false;
  if (approved.tenant !== undefined && requested.tenant !== approved.tenant) return false;
  if (approved.ids !== undefined) {
    if (requested.ids === undefined) return false;
    const allowed = new Set(approved.ids);
    for (const id of requested.ids) {
      if (!allowed.has(id)) return false;
    }
  }
  return true;
}

/**
 * One-shot replay approval tokens: issue with a scope, consume once at
 * execution. Expired tokens are swept lazily on issue/consume.
 */
export class ReplayApprovalStore {
  private readonly tokens = new Map<string, ApprovalTokenRecord>();
  private readonly ttlMs: number;
  private readonly now: () => number;

  constructor(opts: ReplayApprovalOptions = {}) {
    const ttlMs = opts.ttlMs ?? DEFAULT_REPLAY_APPROVAL_TTL_MS;
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
      throw new RangeError(`replayApproval.ttlMs must be a finite number > 0, got ${ttlMs}`);
    }
    this.ttlMs = ttlMs;
    this.now = opts.now ?? Date.now;
  }

  /** Configured token TTL in ms. */
  tokenTtlMs(): number {
    return this.ttlMs;
  }

  /**
   * Issue a one-shot token bound to `scope`. The returned grant carries
   * the token and its expiry; only the token leaves this process.
   */
  issue(scope: ReplayApprovalScope): ReplayApprovalGrant {
    this.sweepExpired();
    let approvalToken = randomBytes(24).toString("hex");
    while (this.tokens.has(approvalToken)) {
      approvalToken = randomBytes(24).toString("hex");
    }
    this.tokens.set(approvalToken, {
      scope: {
        ...(scope.endpoint !== undefined ? { endpoint: scope.endpoint } : {}),
        ...(scope.tenant !== undefined ? { tenant: scope.tenant } : {}),
        ...(scope.ids !== undefined ? { ids: [...scope.ids] } : {}),
      },
      expiresAt: this.now() + this.ttlMs,
      used: false,
    });
    return { approvalToken, expiresAt: this.now() + this.ttlMs };
  }

  /**
   * Spend a token on a replay with this execution scope. A denial does
   * not consume the token (except expiry, which sweeps it) — the caller
   * maps the reason to its own error surface. The record is inspected
   * before the lazy sweep so an expired token reports `expired` on the
   * attempt that outlives it, not `missing`.
   */
  consume(
    approvalToken: string | undefined,
    scope: ReplayApprovalScope
  ): { ok: true } | { ok: false; reason: ReplayApprovalDenyReason } {
    if (approvalToken === undefined || approvalToken === "") {
      return { ok: false, reason: "missing" };
    }
    const record = this.tokens.get(approvalToken);
    if (record === undefined) {
      this.sweepExpired();
      return { ok: false, reason: "missing" };
    }
    if (record.used) return { ok: false, reason: "reused" };
    if (this.now() >= record.expiresAt) {
      this.tokens.delete(approvalToken);
      this.sweepExpired();
      return { ok: false, reason: "expired" };
    }
    if (!approvalScopeCovers(record.scope, scope)) {
      return { ok: false, reason: "scope_mismatch" };
    }
    record.used = true;
    return { ok: true };
  }

  /** Drop every token whose TTL has elapsed. */
  private sweepExpired(): void {
    const now = this.now();
    for (const [token, record] of this.tokens) {
      if (now >= record.expiresAt) this.tokens.delete(token);
    }
  }
}
