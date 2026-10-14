/**
 * WR-95: delivery-latency phase breakdown.
 *
 * WR-13 measures accepted→delivered latency end to end, but a single
 * number cannot say *where* the time went — a 4s delivery could be a slow
 * DNS lookup, a struggling TLS handshake, or a downstream that took 3.9s
 * to think. The {@link LatencyPhasesTracker} keeps, per endpoint, a
 * bounded rolling window of per-phase samples measured by the sender:
 *
 * - `dns`: DNS resolution. The sender does not perform attribution-safe
 *   per-request DNS timing (resolution happens inside the connection
 *   machinery, often served from the WR-92 cache), so this phase is
 *   reported as *unavailable* — never fabricated.
 * - `connect`: request-issued → TCP established. Includes DNS + agent
 *   queueing on the sender's clock; measured only for fresh direct
 *   sockets (pooled reuse and proxied tunnels report unavailable).
 * - `tls`: TCP established → TLS handshake complete (https, fresh
 *   sockets only; plain-http and reused sockets report unavailable).
 * - `firstByte`: request-issued → first response bytes — the existing
 *   WR-54 TTFB. On a fresh connection it overlaps `connect`/`tls` by
 *   construction; the overlap is documented, not hidden.
 * - `body`: first response bytes → response end (downstream think time
 *   after headers + body transfer).
 *
 * Aggregation mirrors the WR-13 `LatencyTracker` convention: bounded
 * rolling windows per endpoint, nearest-rank p50/p95, injectable clock
 * for the (purely operational) `lastSampleAt` staleness marker. The
 * durations themselves are measured by the sender and handed in — the
 * tracker is pure aggregation, so its math is deterministic.
 *
 * Disabled by default (backward compatible): the queue only records
 * phases when `latencyPhases` is configured, and the sender only measures
 * them when told to (zero overhead otherwise).
 */

/** The delivery phases the sender can decompose. */
export type LatencyPhaseName = "dns" | "connect" | "tls" | "firstByte" | "body";

/** All phase names, in wire order. */
export const LATENCY_PHASES: readonly LatencyPhaseName[] = [
  "dns",
  "connect",
  "tls",
  "firstByte",
  "body",
];

/**
 * Per-delivery phase durations in ms. Every field is optional: a phase
 * the sender could not measure is *absent* ("unavailable"), never
 * fabricated — see the module doc for the exact measurability rules.
 */
export interface PhaseDurationsMs {
  dnsMs?: number;
  connectMs?: number;
  tlsMs?: number;
  firstByteMs?: number;
  bodyMs?: number;
}

/** Pick the phase with the largest measured duration (ties → earliest phase). */
export function dominantPhaseOf(phases: PhaseDurationsMs | undefined): LatencyPhaseName | undefined {
  if (phases === undefined) return undefined;
  let best: LatencyPhaseName | undefined;
  let bestMs = -Infinity;
  for (const name of LATENCY_PHASES) {
    const ms = phases[`${name}Ms` as keyof PhaseDurationsMs];
    if (typeof ms !== "number" || !Number.isFinite(ms)) continue;
    if (ms > bestMs) {
      bestMs = ms;
      best = name;
    }
  }
  return best;
}

/** Options for {@link LatencyPhasesTracker}. */
export interface LatencyPhaseOptions {
  /**
   * Rolling sample window per (endpoint, phase): only the newest N
   * samples are kept. Default: 1024. Must be an integer >= 1.
   */
  maxSamplesPerEndpoint?: number;
  /**
   * Clock in ms; defaults to `Date.now`. Used only for the operational
   * `lastSampleAt` staleness marker — phase durations are measured by the
   * sender and handed in. Injectable for deterministic tests.
   */
  now?: () => number;
}

/** Per-phase distribution for one endpoint. All JSON-serializable. */
export interface EndpointLatencyPhaseStats {
  endpoint: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  /** Per-phase samples currently in the rolling window. */
  phases: {
    [K in LatencyPhaseName]?: {
      /** Samples in the window. */
      count: number;
      /** Nearest-rank percentiles over the window's samples. */
      p50: number;
      p95: number;
      /** Newest sample. */
      latest: number;
    };
  };
  /** Wall-clock ms of the newest recorded sample (staleness marker). */
  lastSampleAt: number;
}

/** Nearest-rank percentile over a pre-sorted sample array. */
function percentile(sorted: number[], p: number): number {
  const rank = Math.ceil((p / 100) * sorted.length) - 1;
  return sorted[Math.min(sorted.length - 1, Math.max(0, rank))];
}

export class LatencyPhasesTracker {
  private readonly maxSamples: number;
  private readonly now: () => number;
  /** Per endpoint → per phase → rolling sample window, newest last. */
  private readonly windows = new Map<string, Map<LatencyPhaseName, number[]>>();
  private readonly lastSampleAt = new Map<string, number>();

  constructor(opts: LatencyPhaseOptions = {}) {
    const maxSamples = opts.maxSamplesPerEndpoint ?? 1024;
    if (!Number.isInteger(maxSamples) || maxSamples < 1) {
      throw new RangeError(
        `maxSamplesPerEndpoint must be an integer >= 1, got ${opts.maxSamplesPerEndpoint}`
      );
    }
    this.maxSamples = maxSamples;
    this.now = opts.now ?? Date.now;
  }

  /**
   * Record one delivery's measured phases for `endpoint`. Only defined
   * phases are sampled; unavailable phases leave their window untouched.
   * Non-finite or negative values are ignored (a misbehaving sender must
   * not corrupt the distribution).
   */
  recordPhases(endpoint: string, phases: PhaseDurationsMs): void {
    let per = this.windows.get(endpoint);
    if (per === undefined) {
      per = new Map();
      this.windows.set(endpoint, per);
    }
    let recorded = false;
    for (const name of LATENCY_PHASES) {
      const ms = phases[`${name}Ms` as keyof PhaseDurationsMs];
      if (typeof ms !== "number" || !Number.isFinite(ms) || ms < 0) continue;
      let arr = per.get(name);
      if (arr === undefined) {
        arr = [];
        per.set(name, arr);
      }
      arr.push(ms);
      if (arr.length > this.maxSamples) arr.shift();
      recorded = true;
    }
    if (recorded) this.lastSampleAt.set(endpoint, this.now());
  }

  /**
   * The endpoint's dominant phase by p50 (the phase whose median
   * dominates the delivery time), or `undefined` when no phase has any
   * sample.
   */
  dominantPhase(endpoint: string): LatencyPhaseName | undefined {
    const per = this.windows.get(endpoint);
    if (per === undefined) return undefined;
    let best: LatencyPhaseName | undefined;
    let bestP50 = -Infinity;
    for (const name of LATENCY_PHASES) {
      const arr = per.get(name);
      if (arr === undefined || arr.length === 0) continue;
      const p50 = percentile([...arr].sort((a, b) => a - b), 50);
      if (p50 > bestP50) {
        bestP50 = p50;
        best = name;
      }
    }
    return best;
  }

  /**
   * Per-endpoint phase stats. With `endpoint` set, only that endpoint's
   * stats are returned. Endpoints with no samples are omitted.
   */
  stats(endpoint?: string): EndpointLatencyPhaseStats[] {
    const out: EndpointLatencyPhaseStats[] = [];
    for (const [ep, per] of this.windows) {
      if (endpoint !== undefined && ep !== endpoint) continue;
      const phases: EndpointLatencyPhaseStats["phases"] = {};
      let any = false;
      for (const name of LATENCY_PHASES) {
        const arr = per.get(name);
        if (arr === undefined || arr.length === 0) continue;
        const sorted = [...arr].sort((a, b) => a - b);
        phases[name] = {
          count: arr.length,
          p50: percentile(sorted, 50),
          p95: percentile(sorted, 95),
          latest: arr[arr.length - 1],
        };
        any = true;
      }
      if (!any) continue;
      out.push({ endpoint: ep, phases, lastSampleAt: this.lastSampleAt.get(ep) ?? 0 });
    }
    return out;
  }
}
