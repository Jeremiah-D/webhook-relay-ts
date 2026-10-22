import type { Socket } from "node:net";
import { assertValidProxyUrl, connectViaProxy } from "./proxy.ts";
import { isSocks5ProxyUrl } from "./socks5.ts";

/**
 * Outbound proxy health probing + failover (WR-181).
 *
 * `resolveProxyUrl` (WR-27) picks a proxy per delivery, but it has no
 * opinion on whether that proxy is *alive*: a dead proxy turns every
 * delivery into CONNECT timeouts until an operator notices. The
 * `ProxyHealthMonitor` closes that loop:
 *
 * - each tracked proxy URL gets a timed CONNECT probe (the same
 *   `connectViaProxy` handshake the sender uses, against a configurable
 *   probe target — the tunnel is torn down the moment the proxy answers
 *   `200`, so zero payload bytes ever reach the probe target);
 * - `failureThreshold` consecutive probe failures mark the proxy
 *   unhealthy (`proxy_unhealthy` audit); the first successful probe
 *   re-admits it (`proxy_recovered` audit) — traffic only returns after
 *   a *scheduled probe* proves the proxy, never on a delivery outcome,
 *   which is the WR-39 failback-canary shape: probes are the canary,
 *   deliveries are the traffic;
 * - at dispatch time `resolveProxy` routes around an unhealthy proxy:
 *   a healthy backup proxy from the known-proxy list first (still
 *   proxied, egress policy preserved), then direct (when
 *   `directFallback` allows), and — when every proxy is sick and
 *   direct is disallowed — the sick proxy anyway, so the delivery
 *   flows through the normal retry/dead-letter path and is never
 *   silently dropped.
 *
 * Probes are deliberately outside the delivery path: they consume no
 * retry budget, no quota token, no concurrency slot, and never touch
 * the latency tracker or the circuit breaker (WR-34 `DownstreamProber`
 * convention). Only plain-HTTP CONNECT proxies (`http:` scheme) are
 * tracked — `socks5://` entries are skipped, not failed.
 *
 * Proxy credentials never leave this module's redaction boundary:
 * metrics labels, audit fields, and stats all use the userinfo-stripped
 * form (`http://user:pass@proxy:8080` → `http://proxy:8080`).
 *
 * Zero dependencies (`node:net` + the existing `proxy.ts` only).
 */

/** Strip userinfo from a proxy URL so credentials never reach logs. */
export function redactProxyUrl(proxyUrl: string): string {
  // String surgery instead of URL re-serialization: the rest of the URL
  // (including a trailing-slash-less host) is preserved byte-for-byte so
  // redacted forms still match the configured strings exactly.
  return proxyUrl.replace(/^([a-zA-Z][a-zA-Z0-9+.-]*:\/\/)[^@/]*@/, "$1");
}

/** Timer handle matching the retry queue's injectable scheduler shape. */
export interface ProxyHealthTimerHandle {
  clear(): void;
}

/** Why a delivery's proxy differs from the configured one. */
export type ProxyDegradeReason = "backup_proxy" | "direct" | "no_healthy_proxy";

export interface ProxyDegradedAuditEvent {
  event: "proxy_degraded";
  /** The delivery's target URL. */
  targetUrl: string;
  /** The configured (unhealthy) proxy, userinfo-stripped. */
  proxyUrl: string;
  /** What the delivery actually used: a backup proxy (redacted) or "direct". */
  usedProxyUrl: string;
  reason: ProxyDegradeReason;
}

export interface ProxyUnhealthyAuditEvent {
  event: "proxy_unhealthy";
  /** The sick proxy, userinfo-stripped. */
  proxyUrl: string;
  consecutiveFailures: number;
}

export interface ProxyRecoveredAuditEvent {
  event: "proxy_recovered";
  /** The re-admitted proxy, userinfo-stripped. */
  proxyUrl: string;
}

/** Every audit event this module emits. */
export type ProxyHealthAuditEvent =
  | ProxyDegradedAuditEvent
  | ProxyUnhealthyAuditEvent
  | ProxyRecoveredAuditEvent;

export interface ProxyHealthOptions {
  /**
   * Proxy URLs to track from the start. Extra proxies are tracked
   * lazily on first sight at dispatch (`ensureTracked`), so
   * environment-resolved or registry-provided proxies join the health
   * picture without a restart. `socks5://` entries are skipped.
   */
  proxies?: string[];
  /**
   * ms between probe rounds per proxy; default 30_000. The first round
   * runs one interval after `start()` — no burst at startup. Must be a
   * finite number > 0.
   */
  intervalMs?: number;
  /**
   * CONNECT timeout per probe in ms; default 10_000. Must be a finite
   * number > 0.
   */
  probeTimeoutMs?: number;
  /**
   * Consecutive probe failures that mark a proxy unhealthy; default 3.
   * Must be an integer >= 1.
   */
  failureThreshold?: number;
  /**
   * CONNECT target for probes. Default `{ host: "1.1.1.1", port: 443 }`
   * — a stable public HTTPS endpoint; the tunnel is destroyed
   * immediately after the proxy's `200`, so no bytes reach the target.
   * Override for closed egress (e.g. an internal host the proxy can
   * always reach).
   */
  probeTarget?: { host: string; port: number };
  /**
   * The actual CONNECT probe. Defaults to `connectViaProxy` (the exact
   * handshake the sender uses). Injectable so tests can fake the
   * network; it must never throw — a throw is counted as a failure.
   */
  connect?: (
    proxyUrl: string,
    host: string,
    port: number,
    opts: { connectTimeoutMs: number }
  ) => Promise<Socket>;
  /**
   * Scheduler factory; defaults to an unref'd real `setTimeout` so a
   * configured monitor never pins process exit. Injectable so tests
   * can observe scheduling deterministically.
   */
  setTimer?: (fn: () => void, ms: number) => ProxyHealthTimerHandle;
  clearTimer?: (handle: ProxyHealthTimerHandle) => void;
  /** Receives `proxy_unhealthy` / `proxy_recovered` / `proxy_degraded`. */
  onAudit?: (event: ProxyHealthAuditEvent) => void;
  /**
   * When the preferred proxy is unhealthy and no healthy backup
   * exists, fall back to a direct connection. Default `true`.
   * Set `false` when egress policy forbids ever bypassing the proxy —
   * then a sick proxy keeps its deliveries on the normal
   * retry/dead-letter path.
   */
  directFallback?: boolean;
}

/** Observable snapshot of one tracked proxy. */
export interface ProxyHealthStats {
  /** Redacted (userinfo-stripped) proxy URL. */
  proxyUrl: string;
  healthy: boolean;
  success: number;
  failure: number;
  consecutiveFailures: number;
  /** ms epoch of the last completed probe round; absent before the first. */
  lastProbeAtMs?: number;
}

/** Result of a dispatch-time proxy health decision. */
export interface ProxyResolveDecision {
  /** The proxy to use for this delivery, or `undefined` for direct. */
  proxyUrl: string | undefined;
  /** Whether the decision differs from the configured proxy. */
  degraded: boolean;
  /** Set when `degraded`; why the traffic moved. */
  reason?: ProxyDegradeReason;
  /** The configured (unhealthy) proxy; set when `degraded`. */
  from?: string;
}

interface ProxyHealthRecord {
  success: number;
  failure: number;
  consecutiveFailures: number;
  healthy: boolean;
  lastProbeAtMs?: number;
  timer?: ProxyHealthTimerHandle;
  inFlight: boolean;
}

function defaultSetTimer(fn: () => void, ms: number): ProxyHealthTimerHandle {
  const t = setTimeout(fn, ms);
  // A configured monitor must never pin process exit.
  (t as unknown as { unref?: () => unknown }).unref?.();
  return { clear: () => clearTimeout(t) };
}

function escapeLabelValue(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, '\\"');
}

/**
 * Timed CONNECT health prober + dispatch-time failover for outbound
 * proxies. Constructed by `createRelayServer` when the `proxyHealth`
 * server option is set; `resolveProxy` is consulted by the default
 * sender on every proxied delivery attempt.
 */
export class ProxyHealthMonitor {
  private readonly intervalMs: number;
  private readonly probeTimeoutMs: number;
  private readonly failureThreshold: number;
  private readonly probeTarget: { host: string; port: number };
  private readonly connect: (
    proxyUrl: string,
    host: string,
    port: number,
    opts: { connectTimeoutMs: number }
  ) => Promise<Socket>;
  private readonly setTimer: (fn: () => void, ms: number) => ProxyHealthTimerHandle;
  private readonly clearTimer: (handle: ProxyHealthTimerHandle) => void;
  private readonly onAudit?: (event: ProxyHealthAuditEvent) => void;
  private readonly directFallback: boolean;
  private readonly records = new Map<string, ProxyHealthRecord>();
  private running = false;

  constructor(opts: ProxyHealthOptions = {}) {
    this.intervalMs = opts.intervalMs ?? 30_000;
    if (!Number.isFinite(this.intervalMs) || this.intervalMs <= 0) {
      throw new RangeError(
        `proxyHealth.intervalMs must be a finite number > 0, got ${opts.intervalMs}`
      );
    }
    this.probeTimeoutMs = opts.probeTimeoutMs ?? 10_000;
    if (!Number.isFinite(this.probeTimeoutMs) || this.probeTimeoutMs <= 0) {
      throw new RangeError(
        `proxyHealth.probeTimeoutMs must be a finite number > 0, got ${opts.probeTimeoutMs}`
      );
    }
    this.failureThreshold = opts.failureThreshold ?? 3;
    if (!Number.isInteger(this.failureThreshold) || this.failureThreshold < 1) {
      throw new RangeError(
        `proxyHealth.failureThreshold must be an integer >= 1, got ${opts.failureThreshold}`
      );
    }
    const target = opts.probeTarget ?? { host: "1.1.1.1", port: 443 };
    if (
      typeof target.host !== "string" ||
      target.host === "" ||
      !Number.isInteger(target.port) ||
      target.port <= 0 ||
      target.port > 65535
    ) {
      throw new RangeError(
        `proxyHealth.probeTarget must be { host: string, port: 1..65535 }, got ${JSON.stringify(opts.probeTarget)}`
      );
    }
    this.probeTarget = { host: target.host, port: target.port };
    this.connect =
      opts.connect ??
      ((proxyUrl, host, port, cOpts) => connectViaProxy(proxyUrl, host, port, cOpts));
    this.setTimer = opts.setTimer ?? defaultSetTimer;
    this.clearTimer = opts.clearTimer ?? ((h) => h.clear());
    this.onAudit = opts.onAudit;
    this.directFallback = opts.directFallback ?? true;
    for (const proxyUrl of opts.proxies ?? []) {
      this.track(proxyUrl);
    }
  }

  /**
   * Start tracking a proxy URL found outside the constructor list
   * (environment-resolved or registry-provided). Validates it; returns
   * `false` — without throwing — for values this module cannot probe
   * (`socks5://`, unparsable), so a dispatch never breaks on a proxy
   * the monitor does not understand. Invalid *constructor* values
   * throw `RangeError` at startup instead (fail fast, not per delivery).
   */
  ensureTracked(proxyUrl: string): boolean {
    if (this.records.has(proxyUrl)) return true;
    if (typeof proxyUrl !== "string" || proxyUrl === "" || isSocks5ProxyUrl(proxyUrl)) {
      return false;
    }
    try {
      assertValidProxyUrl(proxyUrl);
    } catch {
      return false;
    }
    this.records.set(proxyUrl, this.freshRecord());
    if (this.running) this.schedule(proxyUrl);
    return true;
  }

  /** Start the per-proxy probe schedules. Idempotent. */
  start(): void {
    if (this.running) return;
    this.running = true;
    for (const proxyUrl of this.records.keys()) this.schedule(proxyUrl);
  }

  /** Stop all probe schedules. In-flight rounds settle on their own. Idempotent. */
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
   * Whether `proxyUrl` may be used for a delivery. Unknown or
   * never-probed proxies are healthy by default — degradation only
   * ever follows *observed* sickness, never suspicion.
   */
  isHealthy(proxyUrl: string): boolean {
    const rec = this.records.get(proxyUrl);
    return rec === undefined || rec.healthy;
  }

  /**
   * Dispatch-time failover decision for one delivery attempt.
   *
   * - `preferred` healthy (or unknown/untracked) → use it, not degraded.
   * - `preferred` unhealthy → first healthy tracked proxy wins
   *   (`backup_proxy`); else direct (`direct`) when allowed; else the
   *   sick proxy itself (`no_healthy_proxy`) so the attempt still runs
   *   through the normal retry/dead-letter path and is never silently
   *   dropped.
   *
   * `targetUrl` feeds the `proxy_degraded` audit event emitted on every
   * degraded decision. `directFallback` overrides the constructor
   * default for this call.
   */
  resolveProxy(
    preferred: string | undefined,
    opts: { targetUrl: string; directFallback?: boolean } = { targetUrl: "" }
  ): ProxyResolveDecision {
    if (preferred === undefined || this.isHealthy(preferred)) {
      return { proxyUrl: preferred, degraded: false };
    }
    const directFallback = opts.directFallback ?? this.directFallback;
    for (const candidate of this.records.keys()) {
      if (candidate !== preferred && this.isHealthy(candidate)) {
        const decision: ProxyResolveDecision = {
          proxyUrl: candidate,
          degraded: true,
          reason: "backup_proxy",
          from: preferred,
        };
        this.auditDegraded(decision, opts.targetUrl);
        return decision;
      }
    }
    if (directFallback) {
      const decision: ProxyResolveDecision = {
        proxyUrl: undefined,
        degraded: true,
        reason: "direct",
        from: preferred,
      };
      this.auditDegraded(decision, opts.targetUrl);
      return decision;
    }
    const decision: ProxyResolveDecision = {
      proxyUrl: preferred,
      degraded: true,
      reason: "no_healthy_proxy",
      from: preferred,
    };
    this.auditDegraded(decision, opts.targetUrl);
    return decision;
  }

  /**
   * Probe one proxy (or every tracked proxy) immediately, outside the
   * schedule. Returns per-proxy outcomes. The schedule is unaffected.
   */
  async runRound(proxyUrl?: string): Promise<{ proxyUrl: string; ok: boolean }[]> {
    const targets = proxyUrl !== undefined ? [proxyUrl] : [...this.records.keys()];
    const results: { proxyUrl: string; ok: boolean }[] = [];
    for (const url of targets) {
      const rec = this.records.get(url);
      if (!rec) throw new RangeError(`unknown tracked proxy ${JSON.stringify(url)}`);
      results.push({ proxyUrl: url, ok: await this.probeOnce(url, rec) });
    }
    return results;
  }

  /** Snapshot of every tracked proxy, in first-tracked order. */
  stats(): ProxyHealthStats[] {
    return [...this.records.keys()].map((proxyUrl) => {
      const rec = this.records.get(proxyUrl)!;
      return {
        proxyUrl: redactProxyUrl(proxyUrl),
        healthy: rec.healthy,
        success: rec.success,
        failure: rec.failure,
        consecutiveFailures: rec.consecutiveFailures,
        ...(rec.lastProbeAtMs !== undefined ? { lastProbeAtMs: rec.lastProbeAtMs } : {}),
      };
    });
  }

  /**
   * Prometheus exposition: one `relay_proxy_unhealthy` gauge (1/0) per
   * tracked proxy. Emits nothing when no proxy is tracked.
   */
  renderMetrics(): string {
    const lines: string[] = [];
    const stats = this.stats();
    if (stats.length === 0) return "";
    lines.push("# HELP relay_proxy_unhealthy 1 when the outbound proxy is marked unhealthy by CONNECT health probes, else 0.");
    lines.push("# TYPE relay_proxy_unhealthy gauge");
    for (const s of stats) {
      lines.push(`relay_proxy_unhealthy{proxy_url="${escapeLabelValue(s.proxyUrl)}"} ${s.healthy ? 0 : 1}`);
    }
    return lines.join("\n") + "\n";
  }

  private track(proxyUrl: string): void {
    if (typeof proxyUrl !== "string" || proxyUrl === "") {
      throw new RangeError("proxyHealth.proxies entries must be non-empty strings");
    }
    if (isSocks5ProxyUrl(proxyUrl)) return; // out of scope: CONNECT probing only
    try {
      assertValidProxyUrl(proxyUrl);
    } catch (err) {
      throw new RangeError(
        `proxyHealth.proxies: invalid proxy URL ${JSON.stringify(proxyUrl)}: ${(err as Error).message}`
      );
    }
    if (!this.records.has(proxyUrl)) this.records.set(proxyUrl, this.freshRecord());
  }

  private freshRecord(): ProxyHealthRecord {
    return { success: 0, failure: 0, consecutiveFailures: 0, healthy: true, inFlight: false };
  }

  private schedule(proxyUrl: string): void {
    const rec = this.records.get(proxyUrl);
    if (!rec) return;
    if (rec.timer !== undefined) this.clearTimer(rec.timer);
    rec.timer = this.setTimer(() => this.tick(proxyUrl), this.intervalMs);
  }

  private async tick(proxyUrl: string): Promise<void> {
    const rec = this.records.get(proxyUrl);
    if (!rec || !this.running) return;
    rec.timer = undefined;
    // A round slower than the interval must not stack: skip, don't pile up.
    if (!rec.inFlight) {
      await this.probeOnce(proxyUrl, rec);
    }
    if (this.running) this.schedule(proxyUrl);
  }

  private async probeOnce(proxyUrl: string, rec: ProxyHealthRecord): Promise<boolean> {
    rec.inFlight = true;
    let ok = false;
    try {
      // The injected probe must never throw, but a defensive catch keeps
      // one bad probe implementation from killing the schedule — a throw
      // is a failure, not a crash.
      const sock = await this.connect(proxyUrl, this.probeTarget.host, this.probeTarget.port, {
        connectTimeoutMs: this.probeTimeoutMs,
      });
      // The proxy answered 200: the tunnel is proven. Tear it down
      // immediately — the target sees zero bytes from us.
      sock.destroy();
      ok = true;
    } catch {
      ok = false;
    } finally {
      rec.inFlight = false;
    }
    rec.lastProbeAtMs = Date.now();
    if (ok) {
      rec.success += 1;
      const wasUnhealthy = !rec.healthy;
      rec.consecutiveFailures = 0;
      rec.healthy = true;
      // Recovery is a transition worth auditing; steady-state healthy
      // probes are noise and stay out of the audit log.
      if (wasUnhealthy) {
        this.onAudit?.({ event: "proxy_recovered", proxyUrl: redactProxyUrl(proxyUrl) });
      }
    } else {
      rec.failure += 1;
      rec.consecutiveFailures += 1;
      if (rec.healthy && rec.consecutiveFailures >= this.failureThreshold) {
        rec.healthy = false;
        this.onAudit?.({
          event: "proxy_unhealthy",
          proxyUrl: redactProxyUrl(proxyUrl),
          consecutiveFailures: rec.consecutiveFailures,
        });
      }
    }
    return ok;
  }

  private auditDegraded(decision: ProxyResolveDecision, targetUrl: string): void {
    if (decision.reason === undefined || decision.from === undefined) return;
    this.onAudit?.({
      event: "proxy_degraded",
      targetUrl,
      proxyUrl: redactProxyUrl(decision.from),
      usedProxyUrl: decision.proxyUrl === undefined ? "direct" : redactProxyUrl(decision.proxyUrl),
      reason: decision.reason,
    });
  }
}
