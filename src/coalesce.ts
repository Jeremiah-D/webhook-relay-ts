import { createHash } from "node:crypto";
import type { DownstreamResponse, RetryItem, Sender } from "./retry.ts";

/**
 * In-flight outbound request coalescing (WR-91).
 *
 * When many deliveries carry the identical logical request — the same
 * tenant, the same physical `targetUrl`, the same payload bytes — and
 * their attempts overlap in time, only the first one performs the real
 * outbound attempt. The rest *attach* to it: their delivery promises
 * settle with the shared attempt's outcome (response or error), while
 * every member still runs its own full delivery bookkeeping — its own
 * audit events, its own delivery counters, its own latency sample, its
 * own attempt counter and retry schedule. The downstream is hit once;
 * the relay's books still show N deliveries. This is the retry-storm
 * case the feature exists for: a burst of identical deliveries (a fan-out
 * retry wave, a replayed dead-letter batch) must not bombard the
 * downstream N times for one logical request.
 *
 * Ownership and cancellation: the physical attempt is owned by the
 * in-flight entry, never by a member. A member that never reaches the
 * sender never joins; a member that joined always rides the attempt to
 * settlement. Cancelling one delivery (removing it from the queue, a
 * pause landing mid-wait — anything that keeps it from calling the
 * sender) cannot cancel, truncate, or poison the merged attempt for the
 * others, because members hold no handle on it at all. Conversely a
 * member's failure-path handling is strictly its own: one member's
 * exception can never leak into another member's `catch`.
 *
 * Leader/follower accounting: the downstream-facing control plane
 * reflects physical reality, so only the *leader* — the member that
 * started the physical attempt — records the breaker verdict, the
 * failover / weighted routing outcome, and the adaptive-backoff outcome.
 * Recording N failures for one real failure would trip the circuit N×
 * faster than the downstream actually failed; recording per-member would
 * also double-count a half-open probe. Followers record everything
 * logical (audit, `relay_deliveries_total`, latency, SLO) exactly as if
 * their attempt had gone out on its own wire.
 *
 * Combination semantics:
 * - WR-24 keepalive: coalescing wraps the *fully composed* sender, so
 *   the merged physical attempt is the one that checks out a pooled
 *   connection — N logical deliveries ride one socket, and
 *   `created`/`reused` count the physical attempt only.
 * - WR-21 pinning: the pin check runs on the physical attempt's TLS
 *   handshake, before a single payload byte is written. Followers never
 *   open their own connection, so their bytes can only ever travel over
 *   a pin-verified socket — pinning is strictly preserved, not bypassed.
 * - WR-10 circuit breaker: see leader/follower accounting above. A
 *   follower that was granted a half-open probe permit releases it via
 *   `cancelProbe` the moment it learns it is a follower — the permit is
 *   settled exactly once, as the breaker contract requires.
 *
 * Zero dependencies (`node:crypto` only).
 */

/** Tuning for {@link OutboundCoalescer}. All values are validated up front. */
export interface CoalescingOptions {
  /**
   * Maximum deliveries that may ride one physical attempt as followers.
   * Default: `Infinity` (bounded in practice by queue depth). Must be a
   * positive integer or `Infinity`. When the bound is exceeded the extra
   * delivery starts its own physical attempt instead of joining — it is
   * never dropped and never waits behind the merged body.
   */
  maxFollowers?: number;
}

/** Snapshot from {@link OutboundCoalescer.getStats}. */
export interface CoalesceStats {
  /** Physical outbound attempts started (leaders). */
  physicalAttempts: number;
  /** Deliveries that rode another delivery's attempt instead of sending. */
  mergedDeliveries: number;
  /** Coalescing keys with an attempt currently in flight. */
  inFlightKeys: number;
}

interface InFlightAttempt {
  promise: Promise<DownstreamResponse | void>;
  followers: number;
}

/**
 * The coalescing key: tenant (the WR-48 isolation boundary — one
 * tenant's deliveries never ride another tenant's attempt, so breaker
 * attribution stays inside the tenant), the physical `targetUrl` the
 * attempt actually goes to (failover/weighted resolution already
 * applied by the caller), and SHA-256 over the logical payload bytes.
 * Wire-level transforms (compression, signatures, headers) do not
 * participate: two deliveries with the same logical request are the
 * same request.
 */
export function coalesceKey(
  tenantId: string | undefined,
  targetUrl: string,
  payload: Buffer
): string {
  const payloadHash = createHash("sha256").update(payload).digest("hex");
  // NUL separators keep the three components unambiguous as a flat key.
  return `${tenantId ?? ""}\0${payloadHash}\0${targetUrl}`;
}

function assertMaxFollowers(value: number): void {
  if (value !== Infinity && (!Number.isInteger(value) || value <= 0)) {
    throw new RangeError(
      `OutboundCoalescer: maxFollowers must be a positive integer or Infinity, got ${value}`
    );
  }
}

export class OutboundCoalescer {
  private readonly maxFollowers: number;
  private readonly inFlight = new Map<string, InFlightAttempt>();
  /**
   * Whether the wrapped sender's last call for this item led the
   * physical attempt. Set synchronously inside the wrapper, before the
   * returned promise is handed back, so the caller can read it
   * immediately after invoking the sender.
   */
  private readonly leaderOf = new WeakMap<RetryItem, boolean>();
  private physicalAttempts = 0;
  private mergedDeliveries = 0;

  constructor(opts: CoalescingOptions = {}) {
    this.maxFollowers = opts.maxFollowers ?? Infinity;
    assertMaxFollowers(this.maxFollowers);
  }

  /**
   * Wrap a sender with coalescing. The returned sender has the same
   * contract: it resolves with the downstream response, or rejects with
   * the attempt's error. Followers receive the *same* outcome object the
   * leader's attempt produced — they must treat it as read-only, exactly
   * like the leader does.
   *
   * The wrapper returns a plain `Sender`: extra properties a custom
   * sender object may carry (e.g. `PooledSender.pool`) are not forwarded.
   * The queue's own sender reference is what gets wrapped; the server's
   * `PooledSender` handle keeps its properties.
   */
  wrap(sender: Sender): Sender {
    const coalescer = this;
    return function coalescedSender(item: RetryItem): Promise<DownstreamResponse | void> {
      const key = coalesceKey(item.tenantId, item.targetUrl, item.payload);
      const existing = coalescer.inFlight.get(key);
      if (existing !== undefined && existing.followers < coalescer.maxFollowers) {
        existing.followers += 1;
        coalescer.mergedDeliveries += 1;
        coalescer.leaderOf.set(item, false);
        // Attach to the shared attempt. The derived promise settles with
        // the identical outcome — every attached member's delivery logic
        // then runs independently on it.
        return existing.promise.then(
          (response) => response,
          (err) => {
            throw err;
          }
        );
      }
      coalescer.leaderOf.set(item, true);
      let physical: Promise<DownstreamResponse | void>;
      try {
        physical = sender(item);
      } catch (err) {
        // The sender threw before returning a promise: nothing is in
        // flight, so there is nothing to register or count. Re-throw
        // unchanged — error semantics stay the sender's.
        throw err;
      }
      coalescer.physicalAttempts += 1;
      // Registered synchronously, before any await in the caller: a
      // delivery dispatched in the same tick attaches instead of
      // starting a second physical attempt.
      coalescer.inFlight.set(key, { promise: physical, followers: 0 });
      const settle = (): void => {
        const current = coalescer.inFlight.get(key);
        if (current !== undefined && current.promise === physical) {
          coalescer.inFlight.delete(key);
        }
      };
      // `settle` never throws, so the derived promise always resolves —
      // this never creates an unhandled rejection. Every member awaits
      // either `physical` (the leader) or its own attached chain.
      physical.then(settle, settle);
      return physical;
    };
  }

  /**
   * Whether `item` led the physical attempt on its last wrapped-sender
   * call. Items that never went through the wrapper (coalescing
   * disabled, or the item hasn't been sent yet) report `true` — the
   * pre-WR-91 behavior where every delivery is its own attempt.
   */
  wasLeader(item: RetryItem): boolean {
    return this.leaderOf.get(item) ?? true;
  }

  getStats(): CoalesceStats {
    return {
      physicalAttempts: this.physicalAttempts,
      mergedDeliveries: this.mergedDeliveries,
      inFlightKeys: this.inFlight.size,
    };
  }
}
