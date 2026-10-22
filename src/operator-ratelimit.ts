import { createHash } from "node:crypto";

/**
 * Operator-plane API rate limiting (WR-180).
 *
 * The webhook intake has its own gates (WR-22 per-IP/per-endpoint, WR-141
 * per-tenant, WR-56 plane separation), but the operator surface (`/metrics`,
 * `/audit`, `/deliveries/*`, `/config/endpoint`, … — everything
 * `isOperatorPath` recognizes) had no pacing at all: one chatty poller or
 * a brute-forcing scanner could hammer it at line rate. This module paces
 * operator requests with a per-client sliding window, so the operator
 * plane degrades gracefully instead of failing open under load.
 *
 * Enforcement point: after the operatorToken/operatorKeys authentication
 * inside `handleOperator`, before any business handling — a rejected
 * request never touches a handler, never burns handler-side resources,
 * and is audited as `rejected` with reason `operator_rate_limited`.
 * Authentication failures keep their existing behavior (403 fail-closed);
 * this limiter is orthogonal to the WR-22 intake limiter (that one guards
 * the webhook intake, this one guards the operator plane).
 *
 * Mechanics: a 60-second sliding window of admission timestamps per
 * client, pruned lazily on every `take` — no background timers, no
 * cross-window bursts, and a backward clock can never grant extra budget
 * (elapsed time is clamped at zero). The clock is injectable for
 * deterministic tests. Invalid budgets throw `RangeError` at
 * construction. Unset (`operatorRateLimit` not passed) = unlimited: the
 * operator path is byte-identical.
 *
 * Split-plane note (WR-56): both planes share one limiter instance; the
 * `plane` dimension is part of the accounting key, so an operator-plane
 * flood can never eat the budget of the other plane's operator traffic
 * (and vice versa) — per-plane counters, one shared instance.
 *
 * Zero dependencies. The client key never contains a credential: when
 * `keyBy` is `"token"` the key is the SHA-256 hex digest of the presented
 * bearer value (computed, never logged, never stored raw); `"ip"` keys by
 * the request's source IP (WR-53 trusted-proxy aware when `ipAcl` is
 * configured, matching the intake path).
 */

/** Which listener plane the operator request arrived on. */
export type OperatorRateLimitPlane = "single" | "operator";

/** How a request is attributed to one rate-limit client. */
export type OperatorRateLimitKeyBy = "token" | "ip";

export interface OperatorRateLimitOptions {
  /**
   * Requests per minute admitted for one client on one plane. Default 60.
   * Must be a finite number > 0; fractional values are floored
   * (60.9 → 60) with a minimum effective budget of 1.
   */
  requestsPerMinute?: number;
  /**
   * Client attribution: `"token"` keys by the SHA-256 digest of the
   * presented bearer credential (one operator, one budget, across IPs),
   * `"ip"` keys by source IP. Default `"ip"`.
   */
  keyBy?: OperatorRateLimitKeyBy;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
}

export type OperatorRateLimitVerdict =
  | { ok: true }
  | {
      ok: false;
      /**
       * Milliseconds until the client's window has budget again — the
       * honest `Retry-After` value (the oldest admission's expiry).
       */
      retryAfterMs: number;
    };

/** The sliding window length in ms (one minute). */
export const OPERATOR_RATE_LIMIT_WINDOW_MS = 60_000;

/** Default budget: 60 requests per minute per client per plane. */
export const DEFAULT_OPERATOR_REQUESTS_PER_MINUTE = 60;

/**
 * SHA-256 hex digest of a presented operator credential. The digest is
 * the rate-limit key — the raw credential is never stored, never logged,
 * and never leaves the request handler.
 */
export function digestOperatorCredential(credential: string): string {
  return createHash("sha256").update(credential, "utf8").digest("hex");
}

interface ClientWindow {
  /** Admission timestamps (ms), ascending; pruned on every `take`. */
  admissions: number[];
}

export class OperatorRateLimiter {
  private readonly budget: number;
  private readonly keyBy: OperatorRateLimitKeyBy;
  private readonly now: () => number;
  private readonly windows = new Map<OperatorRateLimitPlane, Map<string, ClientWindow>>();

  constructor(opts: OperatorRateLimitOptions = {}) {
    const { requestsPerMinute = DEFAULT_OPERATOR_REQUESTS_PER_MINUTE, keyBy = "ip" } = opts;
    if (!Number.isFinite(requestsPerMinute) || requestsPerMinute <= 0) {
      throw new RangeError(
        `requestsPerMinute must be a finite number > 0, got ${requestsPerMinute}`
      );
    }
    if (keyBy !== "token" && keyBy !== "ip") {
      throw new RangeError(`keyBy must be "token" or "ip", got ${keyBy}`);
    }
    this.budget = Math.max(1, Math.floor(requestsPerMinute));
    this.keyBy = keyBy;
    this.now = opts.now ?? Date.now;
  }

  /** The effective per-client, per-plane budget (requests/minute). */
  budgetPerMinute(): number {
    return this.budget;
  }

  /** The configured client-attribution mode. */
  keyByMode(): OperatorRateLimitKeyBy {
    return this.keyBy;
  }

  private windowFor(clientKey: string, plane: OperatorRateLimitPlane): ClientWindow {
    // The plane is part of the accounting key: one shared instance,
    // per-plane counters (WR-56), so planes can never starve each other.
    let byClient = this.windows.get(plane);
    if (byClient === undefined) {
      byClient = new Map<string, ClientWindow>();
      this.windows.set(plane, byClient);
    }
    let w = byClient.get(clientKey);
    if (w === undefined) {
      w = { admissions: [] };
      byClient.set(clientKey, w);
    }
    return w;
  }

  /** Drop admissions that slid out of the 60s window; returns the live list. */
  private prune(w: ClientWindow, at: number): number[] {
    const cutoff = at - OPERATOR_RATE_LIMIT_WINDOW_MS;
    // Clamp clock skew at zero: a backward clock never grants extra budget.
    while (w.admissions.length > 0 && w.admissions[0] <= cutoff) w.admissions.shift();
    return w.admissions;
  }

  /**
   * Try to admit one operator request for `clientKey` on `plane`.
   * Sliding window: at most `budget` admissions in the trailing 60s.
   * A rejection never consumes budget — the window is only appended on
   * admission.
   */
  take(clientKey: string, plane: OperatorRateLimitPlane): OperatorRateLimitVerdict {
    const at = this.now();
    const w = this.windowFor(clientKey, plane);
    const live = this.prune(w, at);
    if (live.length < this.budget) {
      live.push(at);
      return { ok: true };
    }
    // The honest retry-after: when the oldest live admission expires.
    const retryAfterMs = Math.max(0, live[0] + OPERATOR_RATE_LIMIT_WINDOW_MS - at);
    return { ok: false, retryAfterMs };
  }

  /** Distinct (client, plane) pairs ever seen. */
  trackedClients(): number {
    let n = 0;
    for (const byClient of this.windows.values()) n += byClient.size;
    return n;
  }

  /** Snapshot for operator observability (`getOperatorRateLimitStats`). */
  stats(): OperatorRateLimitStats {
    const at = this.now();
    const clients: OperatorRateLimitClientStats[] = [];
    for (const [plane, byClient] of this.windows) {
      for (const [clientKey, w] of byClient) {
        const live = this.prune(w, at);
        clients.push({
          clientKey,
          plane,
          admittedInWindow: live.length,
          budgetPerMinute: this.budget,
          windowResetsInMs: live.length === 0 ? 0 : Math.max(0, live[0] + OPERATOR_RATE_LIMIT_WINDOW_MS - at),
        });
      }
    }
    // Deterministic order: plane, then client key.
    clients.sort((a, b) =>
      a.plane === b.plane ? (a.clientKey < b.clientKey ? -1 : a.clientKey > b.clientKey ? 1 : 0) : a.plane < b.plane ? -1 : 1
    );
    return {
      enabled: true,
      budgetPerMinute: this.budget,
      keyBy: this.keyBy,
      clients,
    };
  }
}

export interface OperatorRateLimitClientStats {
  /** The client key: bearer digest (`token` mode) or source IP (`ip` mode). */
  clientKey: string;
  plane: OperatorRateLimitPlane;
  /** Admissions inside the current trailing 60s window. */
  admittedInWindow: number;
  budgetPerMinute: number;
  /** Ms until the current window fully resets (0 when empty). */
  windowResetsInMs: number;
}

export interface OperatorRateLimitStats {
  enabled: true;
  budgetPerMinute: number;
  keyBy: OperatorRateLimitKeyBy;
  clients: OperatorRateLimitClientStats[];
}

/**
 * Denial counters by plane. Renders to Prometheus exposition text;
 * renders `""` when nothing was denied, keeping `GET /metrics`
 * byte-identical for relays that never enable the limiter (the
 * `IpAclMetrics` pattern for admission metrics).
 */
export class OperatorRateLimitMetrics {
  private readonly denied = new Map<OperatorRateLimitPlane, number>();

  /** Record one 429 denial on `plane`. */
  record(plane: OperatorRateLimitPlane): void {
    this.denied.set(plane, (this.denied.get(plane) ?? 0) + 1);
  }

  /** Prometheus text exposition (0.0.4) of the counters; `""` when empty. */
  render(): string {
    if (this.denied.size === 0) return "";
    const lines = [
      "# HELP relay_operator_ratelimited_total Operator-plane requests rejected by the per-client sliding-window rate limiter (WR-180), by plane.",
      "# TYPE relay_operator_ratelimited_total counter",
    ];
    for (const plane of ["single", "operator"] as const) {
      const n = this.denied.get(plane);
      if (n !== undefined && n > 0) {
        lines.push(`relay_operator_ratelimited_total{plane="${plane}"} ${n}`);
      }
    }
    return lines.join("\n") + "\n";
  }
}
