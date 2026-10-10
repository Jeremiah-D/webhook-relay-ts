/**
 * Delivery-latency SLO tracking: measures accepted→delivered latency per
 * endpoint and exposes the delay distribution (p50/p95/p99) together with
 * the SLO attainment rate. Samples live in a bounded rolling window per
 * endpoint, so the tracker never grows without bound under sustained load.
 *
 * The queue records acceptance in `enqueue()` and delivery in the success
 * path of `deliver()`; items that die in the dead-letter list are
 * `discard()`ed without sampling (they were never delivered, so they have
 * no delivery latency).
 */

/** Options for {@link LatencyTracker}. */
export interface LatencyTrackerOptions {
  /**
   * SLO budget in ms for accepted→delivered latency. Samples slower than
   * this count as misses in `sloAttainment`. Default: 5000. Must be > 0.
   */
  sloMs?: number;
  /**
   * Rolling sample window per endpoint: only the newest N latencies are
   * kept. Default: 1024. Must be an integer >= 1.
   */
  maxSamplesPerEndpoint?: number;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
}

/** Per-endpoint latency distribution plus SLO attainment. All JSON-serializable. */
export interface EndpointLatencyStats {
  endpoint: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  /** Samples currently in the rolling window. */
  count: number;
  min: number;
  max: number;
  mean: number;
  /** Nearest-rank percentiles over the window's samples. */
  p50: number;
  p95: number;
  p99: number;
  /** The SLO budget this attainment was computed against. */
  sloMs: number;
  /** Samples with latency <= `sloMs`. */
  withinSlo: number;
  /** `withinSlo / count`, in [0, 1]. */
  sloAttainment: number;
}

/** Nearest-rank percentile over a pre-sorted sample array. */
function percentile(sorted: number[], p: number): number {
  const rank = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.min(sorted.length - 1, Math.max(0, rank))];
}

export class LatencyTracker {
  /** The SLO budget in ms samples are judged against. */
  readonly sloMs: number;
  private readonly maxSamples: number;
  private readonly now: () => number;
  /** Delivery ids accepted but not yet delivered or discarded. */
  private readonly acceptedAt = new Map<string, number>();
  /** Rolling latency window per endpoint, newest last. */
  private readonly samples = new Map<string, number[]>();

  constructor(opts: LatencyTrackerOptions = {}) {
    const sloMs = opts.sloMs ?? 5000;
    if (!Number.isFinite(sloMs) || sloMs <= 0) {
      throw new RangeError(`sloMs must be > 0, got ${opts.sloMs}`);
    }
    const maxSamples = opts.maxSamplesPerEndpoint ?? 1024;
    if (!Number.isInteger(maxSamples) || maxSamples < 1) {
      throw new RangeError(
        `maxSamplesPerEndpoint must be an integer >= 1, got ${opts.maxSamplesPerEndpoint}`
      );
    }
    this.sloMs = sloMs;
    this.maxSamples = maxSamples;
    this.now = opts.now ?? Date.now;
  }

  /**
   * Mark a delivery accepted: starts its latency clock. A repeated accept
   * for the same id (e.g. a dead-letter replay re-queued under the same id)
   * restarts the clock — the sample then measures the newest delivery cycle.
   */
  recordAccepted(id: string): void {
    this.acceptedAt.set(id, this.now());
  }

  /**
   * Mark a delivery delivered: appends its accepted→delivered latency to
   * the endpoint's rolling window (evicting the oldest sample past the
   * window). Returns the latency in ms, or `undefined` when no accepted
   * record exists (unknown id, or already delivered/discarded).
   */
  recordDelivered(id: string, endpoint: string): number | undefined {
    const at = this.acceptedAt.get(id);
    if (at === undefined) return undefined;
    this.acceptedAt.delete(id);
    const latencyMs = Math.max(0, this.now() - at);
    let arr = this.samples.get(endpoint);
    if (!arr) {
      arr = [];
      this.samples.set(endpoint, arr);
    }
    arr.push(latencyMs);
    if (arr.length > this.maxSamples) arr.shift();
    return latencyMs;
  }

  /** Drop a pending accepted record without sampling (e.g. dead-lettered). */
  discard(id: string): void {
    this.acceptedAt.delete(id);
  }

  /** Deliveries accepted but not yet delivered or discarded. */
  pendingCount(): number {
    return this.acceptedAt.size;
  }

  /**
   * Per-endpoint latency stats. With `endpoint` set, only that endpoint's
   * stats are returned. Endpoints with no samples are omitted.
   */
  stats(endpoint?: string): EndpointLatencyStats[] {
    const out: EndpointLatencyStats[] = [];
    for (const [ep, arr] of this.samples) {
      if (endpoint !== undefined && ep !== endpoint) continue;
      if (arr.length === 0) continue;
      const sorted = [...arr].sort((a, b) => a - b);
      const withinSlo = arr.reduce((n, v) => n + (v <= this.sloMs ? 1 : 0), 0);
      out.push({
        endpoint: ep,
        count: arr.length,
        min: sorted[0],
        max: sorted[sorted.length - 1],
        mean: arr.reduce((a, b) => a + b, 0) / arr.length,
        p50: percentile(sorted, 50),
        p95: percentile(sorted, 95),
        p99: percentile(sorted, 99),
        sloMs: this.sloMs,
        withinSlo,
        sloAttainment: withinSlo / arr.length,
      });
    }
    return out;
  }
}
