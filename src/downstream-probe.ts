import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import type { LookupFunction } from "node:net";

/**
 * Active downstream health probing (WR-34).
 *
 * The circuit breaker (WR-10) only learns an endpoint is sick *after*
 * real deliveries fail against it. The prober flips that around: opt-in
 * timed HEAD (or GET) requests go straight at the endpoint on a
 * lightweight path — no retry queue, no retry budget, no latency
 * tracker, no quota, no batching, no keep-alive pool, no proxy, no TLS
 * pins — so a probe measures raw endpoint reachability and can never
 * disturb a delivery.
 *
 * Each probe outcome is reported to the circuit breaker exactly like a
 * delivery outcome (`recordFailure` / `recordSuccess` on the queue's
 * breaker): `failureThreshold` consecutive probe failures trip the
 * circuit open *before* the next delivery has to fail, and a successful
 * probe resets the counter like any success. When the breaker is
 * disabled, probes are still useful observability: outcomes are counted
 * in the Prometheus exposition (`relay_probe_*`) and audited as
 * `probe_failed` (every failure, with the current streak) /
 * `probe_recovered` (once, when a failing endpoint answers again).
 *
 * Probes never close an open circuit early: a success reported while the
 * breaker is open is ignored by the breaker itself, so recovery still
 * flows through the normal cooldown → half-open probe → close path —
 * the next real delivery is the half-open probe that proves recovery.
 */

/** Timer handle matching the retry queue's injectable scheduler shape. */
export interface ProbeTimerHandle {
  clear(): void;
}

/** Opt-in downstream health probing, embedded in `RetryQueueOptions`. */
export interface ProbeOptions {
  /**
   * Endpoints to probe — exact target URLs. Required, non-empty,
   * no duplicates. Each endpoint gets its own schedule.
   */
  endpoints: string[];
  /**
   * Interval in ms between probe rounds per endpoint; default 30_000.
   * The first round runs one interval after `start()` — no burst at
   * startup. Must be a finite number > 0.
   */
  intervalMs?: number;
  /**
   * Probe method; default `"HEAD"`. `"GET"` is for endpoints whose
   * health route rejects HEAD. The (small) GET body is drained and
   * discarded.
   */
  method?: "HEAD" | "GET";
  /**
   * Per-round request timeout in ms; default 5_000. A timeout counts as
   * a failure. Must be a finite number > 0.
   */
  timeoutMs?: number;
  /**
   * Scheduler factory; defaults to an unref'd real `setTimeout` so a
   * configured prober never pins the process open. Injectable so tests
   * can observe scheduling deterministically.
   */
  setTimer?: (fn: () => void, ms: number) => ProbeTimerHandle;
  clearTimer?: (handle: ProbeTimerHandle) => void;
  /**
   * The actual probe. Defaults to a one-off `HEAD`/`GET` over
   * `node:http(s)` with `timeoutMs`; 2xx answers are healthy, anything
   * else (non-2xx, timeout, DNS error, refused connection) is a
   * failure. Injectable so tests (and exotic transports) can fake the
   * network; it must never throw — a throw is counted as a failure.
   */
  probeRequest?: (endpoint: string, method: "HEAD" | "GET") => Promise<boolean>;
  /**
   * WR-92: DNS lookup override for the default probe request (e.g. a
   * shared `DnsCache#lookup`) — probes resolve through it instead of the
   * OS resolver, so a probe for a hostname mid-DNS-flap gets the same
   * stale-while-revalidate treatment as deliveries. Ignored when a
   * custom `probeRequest` is injected. Must be a function when provided.
   */
  lookup?: LookupFunction;
}

/**
 * WR-355: a partial revision of the downstream probe cadence
 * (`intervalMs` / `timeoutMs` / `method`, at least one field set).
 * Omitted fields keep their live values; an empty patch is a
 * `RangeError`. The probed endpoint list stays fixed at construction
 * — only the rhythm moves.
 */
export type ProbeRevision = Partial<Pick<ProbeOptions, "intervalMs" | "timeoutMs" | "method">>;

/** WR-355: live downstream probe config — the three cadence knobs, after any revision. */
export interface ProbeConfig {
  intervalMs: number;
  timeoutMs: number;
  method: "HEAD" | "GET";
}

/** Payload of the `probe_failed` audit event. */
export interface ProbeFailedAuditEvent {
  event: "probe_failed";
  endpoint: string;
  /** Consecutive probe failures including this one. */
  consecutiveFailures: number;
}

/** Payload of the `probe_recovered` audit event. */
export interface ProbeRecoveredAuditEvent {
  event: "probe_recovered";
  endpoint: string;
}

/** Every probe outcome the prober audits. */
export type ProbeAuditEvent = ProbeFailedAuditEvent | ProbeRecoveredAuditEvent;

/** Observable snapshot of one endpoint's probe history. */
export interface ProbeEndpointStats {
  endpoint: string;
  success: number;
  failure: number;
  /** Consecutive failures since the last success (0 once healthy). */
  consecutiveFailures: number;
  /** ms epoch of the last completed round; absent before the first round. */
  lastProbeAtMs?: number;
}

function defaultSetTimer(fn: () => void, ms: number): ProbeTimerHandle {
  const t = setTimeout(fn, ms);
  // A configured prober must never pin process exit.
  (t as unknown as { unref?: () => unknown }).unref?.();
  return { clear: () => clearTimeout(t) };
}

/**
 * Default probe: one fresh HEAD/GET request, no pooling, no proxy, no
 * pins — raw reachability. Never throws: every failure mode resolves
 * `false`.
 */
function defaultProbeRequest(
  endpoint: string,
  method: "HEAD" | "GET",
  timeoutMs: number,
  lookup?: LookupFunction
): Promise<boolean> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (ok: boolean): void => {
      if (!settled) {
        settled = true;
        resolve(ok);
      }
    };
    let url: URL;
    try {
      url = new URL(endpoint);
    } catch {
      done(false);
      return;
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      done(false);
      return;
    }
    const req = (url.protocol === "https:" ? httpsRequest : httpRequest)(
      url,
      {
        method,
        timeout: timeoutMs,
        // WR-92: probe through the shared DNS cache when one is
        // configured — same stale-while-revalidate as deliveries.
        ...(lookup !== undefined ? { lookup } : {}),
      },
      (res) => {
        res.resume(); // drain a GET body; we only care about the status
        res.on("end", () =>
          done(res.statusCode !== undefined && res.statusCode >= 200 && res.statusCode < 300)
        );
        res.on("error", () => done(false));
      }
    );
    req.on("error", () => done(false));
    req.on("timeout", () => {
      req.destroy();
      done(false);
    });
    req.end();
  });
}

/**
 * Shared gates for the three probe cadence knobs, used by the
 * constructor and by `retune()` (WR-355): merge-then-validate means a
 * revision is judged against the same rules as construction, so an
 * illegal patch throws `RangeError` before any live value moves.
 */
function assertValidProbeCadence(
  intervalMs: number,
  timeoutMs: number,
  method: "HEAD" | "GET"
): void {
  if (!Number.isFinite(intervalMs) || intervalMs <= 0) {
    throw new RangeError(`probe.intervalMs must be a finite number > 0, got ${intervalMs}`);
  }
  if (method !== "HEAD" && method !== "GET") {
    throw new RangeError(`probe.method must be "HEAD" or "GET", got ${JSON.stringify(method)}`);
  }
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new RangeError(`probe.timeoutMs must be a finite number > 0, got ${timeoutMs}`);
  }
}

interface ProbeRecord {
  success: number;
  failure: number;
  consecutiveFailures: number;
  lastProbeAtMs?: number;
  timer?: ProbeTimerHandle;
  inFlight: boolean;
}

/**
 * Timed health prober for downstream endpoints. Constructed by
 * `RetryQueue` when `RetryQueueOptions.probe` is set; `recordOutcome`
 * wires probe results into the queue's circuit breaker, `onAudit` carries
 * `probe_failed` / `probe_recovered` to the audit log.
 */
export class DownstreamProber {
  private readonly endpoints: string[];
  // WR-355: live-revisable via `retune()` (the constructor still
  // validates every value through the same gates), so these are
  // deliberately not `readonly`. The probed endpoint list stays fixed.
  private intervalMs: number;
  private method: "HEAD" | "GET";
  private timeoutMs: number;
  private readonly setTimer: (fn: () => void, ms: number) => ProbeTimerHandle;
  private readonly clearTimer: (handle: ProbeTimerHandle) => void;
  private readonly probeRequest: (endpoint: string, method: "HEAD" | "GET") => Promise<boolean>;
  private readonly recordOutcome: (endpoint: string, ok: boolean) => void;
  private readonly onAudit?: (event: ProbeAuditEvent) => void;
  private readonly records = new Map<string, ProbeRecord>();
  private running = false;

  constructor(
    opts: ProbeOptions & {
      recordOutcome: (endpoint: string, ok: boolean) => void;
      onAudit?: (event: ProbeAuditEvent) => void;
    }
  ) {
    const { endpoints, recordOutcome, onAudit, ...rest } = opts;
    if (!Array.isArray(endpoints) || endpoints.length === 0) {
      throw new RangeError("`probe.endpoints` must be a non-empty array of target URLs");
    }
    const seen = new Set<string>();
    for (const ep of endpoints) {
      if (typeof ep !== "string" || ep === "") {
        throw new RangeError("`probe.endpoints` entries must be non-empty strings");
      }
      if (seen.has(ep)) {
        throw new RangeError(`duplicate probe endpoint ${JSON.stringify(ep)}`);
      }
      seen.add(ep);
    }
    this.endpoints = [...endpoints];
    this.intervalMs = rest.intervalMs ?? 30_000;
    this.method = rest.method ?? "HEAD";
    this.timeoutMs = rest.timeoutMs ?? 5_000;
    assertValidProbeCadence(this.intervalMs, this.timeoutMs, this.method);
    this.setTimer = rest.setTimer ?? defaultSetTimer;
    this.clearTimer = rest.clearTimer ?? ((h) => h.clear());
    if (rest.lookup !== undefined && typeof rest.lookup !== "function") {
      throw new RangeError("probe.lookup must be a function");
    }
    // WR-355: the default probe reads `this.timeoutMs` live at call
    // time instead of capturing the construction value, so a
    // `timeoutMs` revision takes effect on the next round without
    // rebinding — and an injected custom `probeRequest` is untouched
    // by `timeoutMs` revisions, exactly as before.
    this.probeRequest =
      rest.probeRequest ??
      ((endpoint, method) => defaultProbeRequest(endpoint, method, this.timeoutMs, rest.lookup));
    this.recordOutcome = recordOutcome;
    this.onAudit = onAudit;
    for (const ep of this.endpoints) {
      this.records.set(ep, { success: 0, failure: 0, consecutiveFailures: 0, inFlight: false });
    }
  }

  /** Start the per-endpoint schedules. Idempotent. */
  start(): void {
    if (this.running) return;
    this.running = true;
    for (const ep of this.endpoints) {
      this.schedule(ep);
    }
  }

  /** Stop all schedules. In-flight rounds settle on their own. Idempotent. */
  stop(): void {
    this.running = false;
    for (const rec of this.records.values()) {
      if (rec.timer !== undefined) {
        this.clearTimer(rec.timer);
        rec.timer = undefined;
      }
    }
  }

  /**
   * WR-355: revise the live probe cadence (partial — omitted fields
   * keep their live values). Merge-then-validate reusing the
   * construction gates (`assertValidProbeCadence`): an illegal patch
   * throws `RangeError` and the live values are left completely
   * untouched, and an empty patch is a `RangeError`. A patch equal to
   * the live values is a silent no-op. A real revision updates the
   * three knobs in place: when the prober is running and `intervalMs`
   * changed, every pending timer is re-armed at the new interval
   * (clear + reschedule — no extra round, and the `running` /
   * `success` / `failure` / `consecutiveFailures` counts are
   * untouched); an unstarted prober picks the new values up on the
   * next `start()`. `method` / `timeoutMs` changes take effect from
   * the next round — the default probe request reads the live
   * `timeoutMs` at call time, while an injected custom `probeRequest`
   * is unaffected by `timeoutMs`. In-flight rounds settle on their
   * original flow (not cancelled, not re-sent). The probed endpoint
   * list never moves. Returns the live config after the revision.
   */
  retune(patch: ProbeRevision): ProbeConfig {
    if (patch === null || typeof patch !== "object" || Array.isArray(patch)) {
      throw new RangeError(`probe revision must be an object, got ${JSON.stringify(patch)}`);
    }
    if (
      patch.intervalMs === undefined &&
      patch.timeoutMs === undefined &&
      patch.method === undefined
    ) {
      throw new RangeError(
        "probe revision must set at least one of intervalMs, timeoutMs, method"
      );
    }
    const next: ProbeConfig = {
      intervalMs: patch.intervalMs ?? this.intervalMs,
      timeoutMs: patch.timeoutMs ?? this.timeoutMs,
      method: patch.method ?? this.method,
    };
    // Validate-then-apply: the merged values must pass the
    // construction gates before any live value moves.
    assertValidProbeCadence(next.intervalMs, next.timeoutMs, next.method);
    if (
      next.intervalMs === this.intervalMs &&
      next.timeoutMs === this.timeoutMs &&
      next.method === this.method
    ) {
      return this.snapshot();
    }
    const intervalChanged = next.intervalMs !== this.intervalMs;
    this.intervalMs = next.intervalMs;
    this.timeoutMs = next.timeoutMs;
    this.method = next.method;
    // A running prober re-arms every pending timer at the new
    // interval. `schedule()` clears the old timer first, so no round
    // is duplicated; an in-flight round keeps settling on its own and
    // its `tick()` re-arms afterwards as usual. Unchanged intervals
    // leave the pending countdowns alone.
    if (this.running && intervalChanged) {
      for (const ep of this.endpoints) this.schedule(ep);
    }
    return this.snapshot();
  }

  /** WR-355: live probe config snapshot (the three cadence knobs). */
  snapshot(): ProbeConfig {
    return {
      intervalMs: this.intervalMs,
      timeoutMs: this.timeoutMs,
      method: this.method,
    };
  }

  /**
   * Probe one endpoint (or every endpoint) immediately, outside the
   * schedule. Returns per-endpoint outcomes. The schedule is unaffected.
   */
  async runRound(endpoint?: string): Promise<{ endpoint: string; ok: boolean }[]> {
    const targets = endpoint !== undefined ? [endpoint] : this.endpoints;
    const results: { endpoint: string; ok: boolean }[] = [];
    for (const ep of targets) {
      const rec = this.records.get(ep);
      if (!rec) throw new RangeError(`unknown probe endpoint ${JSON.stringify(ep)}`);
      results.push({ endpoint: ep, ok: await this.probeOnce(ep, rec) });
    }
    return results;
  }

  /** Snapshot of every probed endpoint. */
  stats(): ProbeEndpointStats[] {
    return this.endpoints.map((endpoint) => {
      const rec = this.records.get(endpoint)!;
      return {
        endpoint,
        success: rec.success,
        failure: rec.failure,
        consecutiveFailures: rec.consecutiveFailures,
        ...(rec.lastProbeAtMs !== undefined ? { lastProbeAtMs: rec.lastProbeAtMs } : {}),
      };
    });
  }

  private schedule(endpoint: string): void {
    const rec = this.records.get(endpoint)!;
    if (rec.timer !== undefined) this.clearTimer(rec.timer);
    rec.timer = this.setTimer(() => this.tick(endpoint), this.intervalMs);
  }

  private async tick(endpoint: string): Promise<void> {
    const rec = this.records.get(endpoint);
    if (!rec || !this.running) return;
    rec.timer = undefined;
    // A round slower than the interval must not stack: skip, don't pile up.
    if (!rec.inFlight) {
      await this.probeOnce(endpoint, rec);
    }
    if (this.running) this.schedule(endpoint);
  }

  private async probeOnce(endpoint: string, rec: ProbeRecord): Promise<boolean> {
    rec.inFlight = true;
    let ok = false;
    try {
      // The injected probe must never throw, but a defensive catch keeps
      // one bad probe implementation from killing the schedule — a throw
      // is a failure, not a crash.
      ok = await this.probeRequest(endpoint, this.method);
    } catch {
      ok = false;
    } finally {
      rec.inFlight = false;
    }
    rec.lastProbeAtMs = Date.now();
    if (ok) {
      rec.success += 1;
      const wasFailing = rec.consecutiveFailures > 0;
      rec.consecutiveFailures = 0;
      this.recordOutcome(endpoint, true);
      // Recovery is a transition worth auditing; steady-state healthy
      // probes are noise and stay out of the audit log.
      if (wasFailing) this.onAudit?.({ event: "probe_recovered", endpoint });
    } else {
      rec.failure += 1;
      rec.consecutiveFailures += 1;
      this.recordOutcome(endpoint, false);
      this.onAudit?.({ event: "probe_failed", endpoint, consecutiveFailures: rec.consecutiveFailures });
    }
    return ok;
  }
}
