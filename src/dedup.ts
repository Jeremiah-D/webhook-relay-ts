import { createHash } from "node:crypto";

export interface DedupOptions {
  /**
   * How long (ms) a seen (endpoint, payload-hash) pair suppresses
   * duplicates. Default: 300000 (5 minutes). Must be > 0.
   */
  windowMs?: number;
  /**
   * Maximum tracked pairs; the oldest entries are evicted first when the
   * cap is exceeded, so memory stays bounded under a flood of distinct
   * payloads. Default: 10000. Must be an integer >= 1.
   */
  maxEntries?: number;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
}

/**
 * Idempotent delivery deduplicator: within `windowMs`, a payload hash
 * already accepted for an endpoint is a duplicate — the repeat webhook is
 * acknowledged but never delivered, so an upstream retry (e.g. a repeated
 * payment callback) cannot cause a duplicate business action.
 *
 * The key is `(targetUrl, sha256(payload))`: the same payload forwarded to
 * a different endpoint is a different delivery, and headers do not affect
 * the identity of the event. Entries expire lazily out of the window, and
 * the oldest entries are evicted past `maxEntries`, so a flood of distinct
 * payloads cannot grow memory unboundedly.
 *
 * This is inbound-side dedup (the server checks before enqueueing), not a
 * replacement for the nonce/timestamp replay guard (`src/replay.ts`):
 * the guard rejects exact replays by header, the deduplicator suppresses
 * the same business event arriving under a new id.
 */
export class DeliveryDeduplicator {
  private readonly windowMs: number;
  private readonly maxEntries: number;
  private readonly now: () => number;
  /** Insertion-ordered: key -> ms timestamp when first seen. */
  private readonly seen = new Map<string, number>();
  private checked = 0;
  private suppressed = 0;

  constructor(opts: DedupOptions = {}) {
    this.windowMs = opts.windowMs ?? 300_000;
    this.maxEntries = opts.maxEntries ?? 10_000;
    this.now = opts.now ?? Date.now;
    if (!Number.isFinite(this.windowMs) || this.windowMs <= 0) {
      throw new RangeError(`windowMs must be > 0, got ${opts.windowMs}`);
    }
    if (!Number.isInteger(this.maxEntries) || this.maxEntries < 1) {
      throw new RangeError(`maxEntries must be an integer >= 1, got ${opts.maxEntries}`);
    }
  }

  /** SHA-256 hex digest of a payload (the stable half of the dedup key). */
  static hashPayload(payload: Buffer): string {
    return createHash("sha256").update(payload).digest("hex");
  }

  /**
   * Record `(endpoint, payloadHash)`. Returns `true` when the pair was
   * already seen inside the window — the delivery must be suppressed —
   * `false` on first sight (deliver it). A pair seen again *after* its
   * window expired counts as new and restarts the window.
   */
  check(endpoint: string, payloadHash: string): boolean {
    const at = this.now();
    this.evictExpired(at);
    this.checked += 1;
    const key = `${endpoint}\n${payloadHash}`;
    const firstSeen = this.seen.get(key);
    if (firstSeen !== undefined && at - firstSeen < this.windowMs) {
      this.suppressed += 1;
      return true;
    }
    // Re-seen after expiry: delete + set keeps the insertion order fresh so
    // oldest-eviction drops the truly oldest pairs.
    if (firstSeen !== undefined) this.seen.delete(key);
    this.seen.set(key, at);
    while (this.seen.size > this.maxEntries) {
      const oldest = this.seen.keys().next();
      if (oldest.done) break;
      this.seen.delete(oldest.value);
    }
    return false;
  }

  private evictExpired(at: number): void {
    // Insertion-ordered: once a pair is still inside its window, every
    // later pair is newer and also inside its window.
    for (const [key, ts] of this.seen) {
      if (at - ts >= this.windowMs) this.seen.delete(key);
      else break;
    }
  }

  /** Observability: pairs checked, duplicates suppressed, pairs tracked. */
  stats(): { checked: number; suppressed: number; tracked: number } {
    return { checked: this.checked, suppressed: this.suppressed, tracked: this.seen.size };
  }
}
