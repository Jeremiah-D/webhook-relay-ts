import type { ReplayTimerHandle } from "./autoreplay.ts";
import type { DeadLetterEntry } from "./retry.ts";

/** Opt-in dead-letter retention tuning, embedded in {@link RetryQueueOptions}. */
export interface DeadLetterRetentionOptions {
  /**
   * Per-endpoint dead-letter retention TTL in milliseconds (opt-in).
   * Entries dead-lettered longer ago than their endpoint's TTL are
   * automatically purged by the background sweep. A plain number applies
   * the same TTL to every endpoint; a record maps exact `targetUrl` to
   * its TTL and opts in only the listed endpoints (the same exact-match
   * convention as `responseValidators` and `tlsPins`). Unset (or an
   * absent `deadLetterRetention` object) disables automatic purging:
   * entries live until replayed manually, exactly the legacy behavior.
   * Every TTL must be a finite number > 0; anything else throws
   * `RangeError` at construction.
   */
  retentionMs?: number | Record<string, number>;
  /**
   * Interval in ms between retention sweeps; default 60_000. The sweep
   * timer is unref'd, so a configured sweeper never pins the process
   * open. Must be a finite number > 0; anything else throws `RangeError`
   * at construction.
   */
  sweepIntervalMs?: number;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
  /**
   * Scheduler factory; defaults to an unref'd real `setTimeout` so an
   * armed sweep never pins the process open. Injectable so tests can
   * drive sweeps deterministically.
   */
  setTimer?: (fn: () => void, ms: number) => ReplayTimerHandle;
  clearTimer?: (handle: ReplayTimerHandle) => void;
}

/** Payload of the `dead_letter_purged` audit event. */
export interface DeadLetterPurgedEvent {
  event: "dead_letter_purged";
  /** Id of the purged dead-letter entry. */
  id: string;
  /**
   * The logical endpoint the entry was dead-lettered for (`targetUrl`;
   * the configured primary when the entry died on a failover standby —
   * see `failoverEndpoint` on `DeadLetterEntry`). Matches the endpoint
   * the operator configured, not the physical target that happened to
   * serve the final attempt.
   */
  endpoint: string;
  /** Attempts consumed before the entry was dead-lettered. */
  attempts: number;
  /** ISO-8601 timestamp when the entry entered the dead-letter list. */
  deadLetteredAt: string;
  /**
   * End-to-end trace ID (see `src/trace.ts`): correlates the purge back
   * to the entry's `accepted` / `dead_letter` audit lines. Always
   * populated.
   */
  traceId: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
}

/** One purged entry's operator metadata (no payload, ever). */
export interface DeadLetterPurgeInfo {
  id: string;
  /** Logical endpoint (see {@link DeadLetterPurgedEvent.endpoint}). */
  endpoint: string;
  attempts: number;
  deadLetteredAt: string;
}

/** Outcome of {@link DeadLetterRetentionSweeper.sweepNow}. */
export interface DeadLetterPurgeResult {
  /** Entries purged this sweep, in dead-letter order. */
  purged: DeadLetterPurgeInfo[];
  /**
   * Ids whose TTL had expired but were skipped because a replay
   * operation (WR-23 batch replay or the WR-31 auto-replay, which runs
   * through the same batch replay) currently claims them. A replay
   * claims its entries for its whole synchronous run, so the sweep
   * never deletes an entry out from under an in-progress replay; the
   * next sweep picks the entry up if it is still expired.
   */
  skipped: string[];
}

/** Per-endpoint TTL lookup after validation. */
export type RetentionTtlFor = (logicalEndpoint: string) => number | undefined;

function assertTtl(value: unknown, where: string): asserts value is number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    throw new RangeError(`${where} must be a finite number > 0, got ${String(value)}`);
  }
}

/**
 * Validate `retentionMs` and build the TTL lookup. Throws `RangeError`
 * on any illegal value. Returns `undefined` when retention is not
 * configured (no TTL at all) — the caller then disables the sweep.
 */
export function resolveRetentionTtl(
  retentionMs: DeadLetterRetentionOptions["retentionMs"]
): RetentionTtlFor | undefined {
  if (retentionMs === undefined) return undefined;
  if (typeof retentionMs === "number") {
    assertTtl(retentionMs, "deadLetterRetention.retentionMs");
    return () => retentionMs;
  }
  if (retentionMs === null || Array.isArray(retentionMs) || typeof retentionMs !== "object") {
    throw new RangeError(
      `deadLetterRetention.retentionMs must be a number or a Record<string, number>, got ${String(retentionMs)}`
    );
  }
  const perEndpoint = new Map<string, number>();
  for (const [endpoint, ttl] of Object.entries(retentionMs)) {
    if (endpoint.length === 0) {
      throw new RangeError("deadLetterRetention.retentionMs keys must be non-empty endpoint URLs");
    }
    assertTtl(ttl, `deadLetterRetention.retentionMs[${JSON.stringify(endpoint)}]`);
    perEndpoint.set(endpoint, ttl);
  }
  return (logicalEndpoint) => perEndpoint.get(logicalEndpoint);
}

/**
 * The queue-side contract the sweeper needs. All state mutations stay in
 * the owning {@link RetryQueue}; the sweeper only decides *which* entries
 * are expired and calls back to remove/audit them.
 */
export interface DeadLetterRetentionOwner {
  /** Live dead-letter entries, in dead-letter order. */
  listEntries(): DeadLetterEntry[];
  /**
   * Remove the entry from the dead-letter list, journal the purge
   * (WR-49), and count it. Returns the removed entry, or `undefined`
   * when the id is already gone (a replay won the race).
   */
  removeEntry(id: string): DeadLetterEntry | undefined;
  /** Whether a replay operation currently claims the id (skip purges). */
  isClaimedByReplay(id: string): boolean;
  /** Called once per purged entry; the owner audits it. */
  onPurged(event: DeadLetterPurgedEvent): void;
}

/**
 * Dead-letter retention sweeper (WR-64).
 *
 * Opt-in TTL-based cleanup of the dead-letter list: every
 * `sweepIntervalMs` the sweeper purges entries whose
 * `deadLetteredAt + TTL` has passed. TTLs are per endpoint (exact
 * `targetUrl` match on the *logical* endpoint, so an entry
 * dead-lettered on a failover standby is governed by its configured
 * primary's TTL); endpoints without a configured TTL never expire.
 *
 * Each purge is audited as `dead_letter_purged` with the entry's
 * operator metadata (`id`, `endpoint`, `attempts`, `deadLetteredAt`)
 * plus the standard correlation fields (`traceId`, `tenant`) — the
 * payload is never exposed, not even as metadata, and sealed
 * (encrypted) entries are purged sealed.
 *
 * The sweep is purely additive to the existing dead-letter contract:
 * replay paths are untouched, and entries claimed by an in-progress
 * replay are skipped, never deleted from under it.
 */
export class DeadLetterRetentionSweeper {
  /**
   * `undefined` when no TTL is configured: the sweeper is validated but
   * inert — `start()` arms nothing and `sweepNow()` purges nothing, so a
   * `deadLetterRetention` object without `retentionMs` keeps the legacy
   * no-purge behavior instead of failing startup.
   */
  private readonly ttlFor: RetentionTtlFor | undefined;
  private readonly sweepIntervalMs: number;
  private readonly now: () => number;
  private readonly setTimer: (fn: () => void, ms: number) => ReplayTimerHandle;
  private readonly clearTimer: (handle: ReplayTimerHandle) => void;
  private readonly owner: DeadLetterRetentionOwner;

  private started = false;
  private timer?: ReplayTimerHandle;

  constructor(opts: DeadLetterRetentionOptions & { owner: DeadLetterRetentionOwner }) {
    this.ttlFor = resolveRetentionTtl(opts.retentionMs);
    this.sweepIntervalMs = opts.sweepIntervalMs ?? 60_000;
    if (!Number.isFinite(this.sweepIntervalMs) || this.sweepIntervalMs <= 0) {
      throw new RangeError(
        `deadLetterRetention.sweepIntervalMs must be a finite number > 0, got ${String(opts.sweepIntervalMs)}`
      );
    }
    this.now = opts.now ?? Date.now;
    this.setTimer =
      opts.setTimer ??
      ((fn, ms) => {
        // Unref'd: an armed sweep must never pin the process open just
        // because a retention TTL is configured.
        const t = setTimeout(fn, ms);
        t.unref?.();
        return { clear: () => clearTimeout(t) };
      });
    this.clearTimer = opts.clearTimer ?? ((h) => h.clear());
    this.owner = opts.owner;
  }

  /** Whether the sweep schedule is currently armed. */
  isRunning(): boolean {
    return this.started && this.timer !== undefined;
  }

  /** Whether any TTL is configured (the sweep can actually purge). */
  isEnabled(): boolean {
    return this.ttlFor !== undefined;
  }

  /** Arm the sweep schedule. Idempotent; a no-op when no TTL is configured. */
  start(): void {
    if (this.started || this.ttlFor === undefined) return;
    this.started = true;
    this.arm();
  }

  /** Disarm the sweep schedule. Idempotent. */
  stop(): void {
    this.started = false;
    this.clearPending();
  }

  /**
   * Run one sweep immediately, outside the schedule: purge every entry
   * whose TTL has expired, skipping entries claimed by an in-progress
   * replay. Safe to call directly (tests, operator tooling) — it does
   * not disturb the armed schedule.
   */
  sweepNow(): DeadLetterPurgeResult {
    const ttlFor = this.ttlFor;
    const purged: DeadLetterPurgeInfo[] = [];
    const skipped: string[] = [];
    if (ttlFor === undefined) return { purged, skipped };
    const nowMs = this.now();
    // Snapshot: removeEntry mutates the live list while we iterate.
    for (const entry of [...this.owner.listEntries()]) {
      if (this.owner.isClaimedByReplay(entry.id)) {
        skipped.push(entry.id);
        continue;
      }
      // WR-39: the TTL is keyed by the logical endpoint the operator
      // configured, not the physical target that served the final
      // attempt — the same convention as the batch-replay filter.
      const logicalEndpoint = entry.failoverEndpoint ?? entry.targetUrl;
      const ttl = ttlFor(logicalEndpoint);
      if (ttl === undefined) continue;
      const deadLetteredAtMs = Date.parse(entry.deadLetteredAt);
      if (!Number.isFinite(deadLetteredAtMs)) continue; // corrupt timestamp: keep, never purge blind
      if (nowMs - deadLetteredAtMs < ttl) continue;
      const removed = this.owner.removeEntry(entry.id);
      if (removed === undefined) continue; // a replay won the race after the snapshot
      const info: DeadLetterPurgeInfo = {
        id: removed.id,
        endpoint: logicalEndpoint,
        attempts: removed.attempts,
        deadLetteredAt: removed.deadLetteredAt,
      };
      purged.push(info);
      this.owner.onPurged({
        event: "dead_letter_purged",
        ...info,
        traceId: removed.traceId ?? "",
        ...(removed.tenantId !== undefined ? { tenant: removed.tenantId } : {}),
      });
    }
    return { purged, skipped };
  }

  private arm(): void {
    this.clearPending();
    if (!this.started) return;
    this.timer = this.setTimer(() => {
      this.timer = undefined;
      this.sweepNow();
      this.arm();
    }, this.sweepIntervalMs);
  }

  private clearPending(): void {
    if (this.timer) {
      this.clearTimer(this.timer);
      this.timer = undefined;
    }
  }
}
