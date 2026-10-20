import { HttpDeliveryError } from "./failure.ts";
import type { RetryItem, Sender, SenderCallOptions, DownstreamResponse } from "./retry.ts";

/**
 * Outbound delivery fault injection (WR-165).
 *
 * Chaos drills for the retry / backoff / breaker / dead-letter path:
 * operators inject controlled faults at the *sender* layer — decoupled
 * from any real downstream, so the drill runs in CI — and watch the
 * relay's resilience machinery react to them exactly as it would to
 * real failures.
 *
 * Three fault kinds, per endpoint (exact `targetUrl` keys, the repo's
 * sender-side convention):
 *
 * - `latencyMs`: hold the attempt back this long before it runs (delay
 *   jitter / slow-downstream drill);
 * - `resetConnection`: fail the attempt with a simulated `ECONNRESET`
 *   transport reset — no request is written, so there is nothing to
 *   duplicate on retry;
 * - `statusCode`: answer with a synthetic HTTP status *without touching
 *   the network* — the attempt throws `HttpDeliveryError`, which the
 *   queue classifies exactly like a real downstream verdict (5xx → the
 *   normal backoff lane, breaker counting, and eventual dead-letter;
 *   429 → `Retry-After`-less backoff; 4xx → immediate dead-letter per
 *   WR-30).
 *
 * Every injection is observable twice: the `chaos_injected` audit event
 * (endpoint, kind, and the fault detail) and the
 * `relay_chaos_injected_total{endpoint,kind}` counter — injected faults
 * are always counted separately from real ones, so a drill never
 * pollutes the production failure statistics.
 *
 * Opt-in via `createDefaultSender(..., chaos)` / `createRelayServer({
 * chaos })`. Unset = the sender is returned unwrapped: zero behavior
 * change, zero overhead.
 *
 * Zero dependencies.
 */

/** What kind of fault was injected into an attempt. */
export type ChaosFaultKind = "latency" | "reset" | "status";

/** One endpoint's fault rule. At least one fault must be set. */
export interface ChaosFaultRule {
  /**
   * Hold the attempt back this long (ms) before it runs. Must be a
   * finite number >= 0.
   */
  latencyMs?: number;
  /**
   * Fail the attempt with a simulated `ECONNRESET` transport reset.
   * Mutually exclusive with `statusCode`.
   */
  resetConnection?: boolean;
  /**
   * Answer with this synthetic HTTP status without touching the network
   * (the attempt throws `HttpDeliveryError`, classified like a real
   * downstream verdict). Integer 100–599. Mutually exclusive with
   * `resetConnection`.
   */
  statusCode?: number;
}

/** Chaos drill configuration: exact `targetUrl` → fault rule. */
export interface ChaosConfig {
  rules: Record<string, ChaosFaultRule>;
}

/** A validated fault rule (what the injector reads). */
export interface ResolvedChaosFaultRule {
  latencyMs: number | undefined;
  resetConnection: boolean;
  statusCode: number | undefined;
}

/** `ChaosConfig` validated up front (`RangeError` on invalid values). */
export interface ResolvedChaosConfig {
  rules: Map<string, ResolvedChaosFaultRule>;
}

/** One injected fault, for the audit hook. */
export interface ChaosInjectionInfo {
  /** The endpoint the fault was injected for. */
  endpoint: string;
  /** Which fault fired. */
  kind: ChaosFaultKind;
  /** The delivery the fault hit. */
  id: string;
  /** Trace id when the item carries one. */
  traceId?: string;
  /** Fault detail: the injected latency, or the synthetic status. */
  detailMs?: number;
  detailStatus?: number;
}

/** Hooks for the chaos injector. */
export interface ChaosHooks {
  /** Called once per injected fault (the server audits `chaos_injected`). */
  onInjected?: (info: ChaosInjectionInfo) => void;
}

/**
 * Validate a chaos drill config the way a constructor would; returns
 * the resolved config, or `undefined` when the feature is off.
 * `what` prefixes `RangeError` messages (e.g. `"createDefaultSender"`).
 */
export function resolveChaosConfig(
  cfg: ChaosConfig | undefined,
  what: string
): ResolvedChaosConfig | undefined {
  if (cfg === undefined) return undefined;
  if (cfg === null || typeof cfg !== "object" || Array.isArray(cfg)) {
    throw new RangeError(`${what}: \`chaos\` must be an object, got ${cfg === null ? "null" : typeof cfg}`);
  }
  const rules = cfg.rules;
  if (rules === undefined || rules === null || typeof rules !== "object" || Array.isArray(rules)) {
    throw new RangeError(`${what}: \`chaos.rules\` must be a Record<targetUrl, ChaosFaultRule>`);
  }
  const resolved = new Map<string, ResolvedChaosFaultRule>();
  for (const [endpoint, rule] of Object.entries(rules)) {
    if (endpoint === "") {
      throw new RangeError(`${what}: \`chaos.rules\` keys must be non-empty endpoint strings`);
    }
    if (rule === null || typeof rule !== "object" || Array.isArray(rule)) {
      throw new RangeError(`${what}: \`chaos.rules["${endpoint}"]\` must be an object`);
    }
    const latencyMs = rule.latencyMs;
    if (latencyMs !== undefined && (!Number.isFinite(latencyMs) || latencyMs < 0)) {
      throw new RangeError(
        `${what}: \`chaos.rules["${endpoint}"].latencyMs\` must be a finite number >= 0, got ${rule.latencyMs}`
      );
    }
    const resetConnection = rule.resetConnection ?? false;
    if (typeof resetConnection !== "boolean") {
      throw new RangeError(
        `${what}: \`chaos.rules["${endpoint}"].resetConnection\` must be a boolean`
      );
    }
    const statusCode = rule.statusCode;
    if (
      statusCode !== undefined &&
      (!Number.isInteger(statusCode) || statusCode < 100 || statusCode > 599)
    ) {
      throw new RangeError(
        `${what}: \`chaos.rules["${endpoint}"].statusCode\` must be an integer 100–599, got ${rule.statusCode}`
      );
    }
    if (resetConnection && statusCode !== undefined) {
      throw new RangeError(
        `${what}: \`chaos.rules["${endpoint}"]\` sets both resetConnection and statusCode — pick one fault per rule`
      );
    }
    if (latencyMs === undefined && !resetConnection && statusCode === undefined) {
      throw new RangeError(
        `${what}: \`chaos.rules["${endpoint}"]\` sets no fault (latencyMs/resetConnection/statusCode)`
      );
    }
    resolved.set(endpoint, { latencyMs, resetConnection, statusCode });
  }
  return { rules: resolved };
}

/** Per-endpoint injection counters, shared by the wrapper. */
export class ChaosMetrics {
  private readonly counts = new Map<string, Map<ChaosFaultKind, number>>();

  /** Record one injected fault. */
  inject(endpoint: string, kind: ChaosFaultKind): void {
    let byKind = this.counts.get(endpoint);
    if (byKind === undefined) {
      byKind = new Map();
      this.counts.set(endpoint, byKind);
    }
    byKind.set(kind, (byKind.get(kind) ?? 0) + 1);
  }

  /** Snapshot for tests/operators: endpoint → kind → count. */
  getStats(): Record<string, Record<ChaosFaultKind, number>> {
    const out: Record<string, Record<ChaosFaultKind, number>> = {};
    for (const [endpoint, byKind] of this.counts) {
      out[endpoint] = Object.fromEntries(byKind) as Record<ChaosFaultKind, number>;
    }
    return out;
  }

  /**
   * Prometheus exposition (`relay_chaos_injected_total{endpoint,kind}`).
   * Empty string until the first injection — the activity-gated
   * convention, so a relay with chaos configured but never injected
   * exposes no new series.
   */
  render(): string {
    if (this.counts.size === 0) return "";
    const lines = [
      "# HELP relay_chaos_injected_total Faults injected by the WR-165 chaos drill, by endpoint and fault kind. Injected faults are counted separately from real downstream failures.",
      "# TYPE relay_chaos_injected_total counter",
    ];
    for (const [endpoint, byKind] of this.counts) {
      for (const [kind, n] of byKind) {
        lines.push(
          `relay_chaos_injected_total{endpoint="${escapeLabel(endpoint)}",kind="${kind}"} ${n}`
        );
      }
    }
    return lines.join("\n") + "\n";
  }
}

function escapeLabel(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * A simulated transport reset: the shape a real `ECONNRESET` takes on
 * the wire path (code + "socket hang up" message, which is what
 * `classifyFailure` keys on). The attempt fails *before* any request
 * byte is written, so a retry can never duplicate a side effect.
 */
export function chaosResetError(): NodeJS.ErrnoException {
  const err = new Error("socket hang up (chaos-injected)") as NodeJS.ErrnoException;
  err.code = "ECONNRESET";
  return err;
}

/**
 * Wrap a `Sender` with the chaos drill: for endpoints with a configured
 * rule, inject the fault(s) on every attempt, then delegate to the
 * wrapped sender. Endpoints without a rule delegate untouched — zero
 * behavior change, zero overhead.
 *
 * Fault order within an attempt: latency first (the hold applies even
 * when the attempt is about to fail), then exactly one of
 * status/reset. A latency-only rule still delegates after the hold.
 */
export function wrapSenderWithChaos(
  sender: Sender,
  chaos: ResolvedChaosConfig,
  metrics: ChaosMetrics,
  hooks: ChaosHooks = {}
): Sender {
  const wrapped = async (
    item: RetryItem,
    opts?: SenderCallOptions
  ): Promise<DownstreamResponse | void> => {
    const rule = chaos.rules.get(item.targetUrl);
    if (rule === undefined) return sender(item, opts);
    const base = {
      endpoint: item.targetUrl,
      id: item.id,
      ...(item.traceId !== undefined ? { traceId: item.traceId } : {}),
    };
    if (rule.latencyMs !== undefined && rule.latencyMs > 0) {
      metrics.inject(item.targetUrl, "latency");
      hooks.onInjected?.({ ...base, kind: "latency", detailMs: rule.latencyMs });
      await sleep(rule.latencyMs);
    }
    if (rule.statusCode !== undefined) {
      metrics.inject(item.targetUrl, "status");
      hooks.onInjected?.({ ...base, kind: "status", detailStatus: rule.statusCode });
      // Synthetic verdict, no network: the queue classifies it exactly
      // like a real downstream status (5xx → backoff lane + breaker +
      // dead-letter; 4xx → immediate dead-letter per WR-30).
      throw new HttpDeliveryError(rule.statusCode);
    }
    if (rule.resetConnection) {
      metrics.inject(item.targetUrl, "reset");
      hooks.onInjected?.({ ...base, kind: "reset" });
      throw chaosResetError();
    }
    return sender(item, opts);
  };
  return wrapped;
}
