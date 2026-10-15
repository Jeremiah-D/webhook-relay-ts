import type { RetryItem } from "./retry.ts";
import type { FailureClass } from "./failure.ts";
import type { QuorumMetricsInput } from "./metrics.ts";
import { newTraceId } from "./trace.ts";

/**
 * Quorum fan-out: M-of-N downstream acknowledgements (WR-106).
 *
 * Payment / multi-channel notification scenario: one admitted event must
 * reach *several* downstream targets (multiple settlement channels,
 * redundant notification endpoints), and M successful confirmations out of
 * N targets count as delivered. The fan-out is one admission — the event
 * is accepted once, audited once — and each target gets its own queue
 * item, so every target keeps the relay's normal per-endpoint machinery:
 * exponential backoff, the WR-12 urgent fast lane, the circuit breaker,
 * quota, the global retry budget, and the dead-letter list. The quorum
 * layer never schedules its own retries: an unacknowledged target is
 * retried by the queue exactly like any other delivery, and a target that
 * exhausts its budget (or fails non-retryable per WR-30) dead-letters
 * individually. The fan-out itself never becomes a single dead-letter
 * entry — the "overall dead letter" is the `failed` fan-out state, with
 * each lost target still visible in the dead-letter list on its own.
 *
 * Terminal semantics, documented so operators are not surprised:
 *
 * - `satisfied`: M targets acknowledged. Members still in flight keep
 *   their own lifecycle — a late ack is recorded (the `acked` count can
 *   exceed M) but never changes the settled state.
 * - `failed`: M became unreachable (`acked + live < M`). Remaining live
 *   members still finish their own lifecycle (at-least-once delivery is
 *   not revoked by the quorum verdict); their late acks are recorded but
 *   the fan-out stays failed.
 * - `partial` is not terminal: at least one target dead-lettered while M
 *   is still reachable — degraded, still working.
 *
 * Zero dependencies (`node:test`-free; pure logic + the queue's types).
 */

/** One fan-out target list for a logical endpoint. */
export interface QuorumFanoutConfig {
  /**
   * The downstream URLs that each receive a copy of the event. Must be a
   * non-empty list of distinct absolute `http:`/`https:` URLs, none of
   * them the logical endpoint itself (fanning out to self would
   * double-deliver under two ids; rejected as a config bug).
   */
  targets: string[];
  /**
   * How many target acknowledgements count the fan-out as delivered.
   * Integer in `[1, targets.length]`.
   */
  quorum: number;
}

/**
 * Per-endpoint opt-in quorum fan-out: exact logical `targetUrl` ->
 * fan-out config. Endpoints absent from the record behave exactly as
 * before — zero behavior change when the feature is off.
 */
export type QuorumConfig = Record<string, QuorumFanoutConfig>;

/** Lifecycle state of one fan-out (see the module doc for the semantics). */
export type QuorumFanoutStatus = "in_progress" | "satisfied" | "partial" | "failed";

/** One target that exhausted its own retry lifecycle inside a fan-out. */
export interface QuorumDeadTarget {
  /** The downstream URL that never acknowledged. */
  targetUrl: string;
  /** WR-30 classification of the final failure. */
  failureClass: FailureClass;
  /** Last delivery error message. */
  lastError: string;
}

/** One row of {@link QuorumFanoutSet.stats}: operator metadata only. */
export interface QuorumFanoutStats {
  /** The admitted event's delivery id — also the fan-out id. */
  fanoutId: string;
  /** The logical endpoint the event was admitted for. */
  endpoint: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  /** Total fan-out targets (N). */
  targets: number;
  /** Targets that acknowledged so far. */
  acked: number;
  /** Current lifecycle state. */
  status: QuorumFanoutStatus;
  /** Targets that exhausted their own retry lifecycle, in loss order. */
  deadLettered: QuorumDeadTarget[];
  /** ISO-8601 when the fan-out was dispatched. */
  dispatchedAt: string;
  /**
   * ISO-8601 when the fan-out settled (`satisfied` / `failed`); absent
   * while the fan-out is still working.
   */
  settledAt?: string;
}

/** One endpoint's cumulative quorum counters — the Prometheus row shape (see `src/metrics.ts`). */
export type { QuorumMetricsInput };

/** Fired when a fan-out is dispatched (one admission -> N target items). */
export interface QuorumDispatchedInfo {
  event: "quorum_dispatched";
  fanoutId: string;
  traceId: string;
  tenant?: string;
  /** The logical endpoint the event was admitted for. */
  endpoint: string;
  /** The N downstream URLs, in dispatch order. */
  targets: string[];
  /** The configured quorum M. */
  quorum: number;
  at: string;
}

/** Fired when one target acknowledges (transport success, post-validation). */
export interface QuorumAcknowledgedInfo {
  event: "quorum_acknowledged";
  fanoutId: string;
  traceId: string;
  tenant?: string;
  endpoint: string;
  /** The downstream URL that acknowledged. */
  targetUrl: string;
  /** Acknowledgements so far, including this one. */
  acked: number;
  /** Total fan-out targets (N). */
  targets: number;
  at: string;
}

/** Fired once when a fan-out reaches its quorum. */
export interface QuorumSatisfiedInfo {
  event: "quorum_satisfied";
  fanoutId: string;
  traceId: string;
  tenant?: string;
  endpoint: string;
  /** Acknowledgements at satisfaction (>= M). */
  acked: number;
  /** Total fan-out targets (N). */
  targets: number;
  at: string;
}

/** Fired once when a fan-out's quorum becomes unreachable. */
export interface QuorumFailedInfo {
  event: "quorum_failed";
  fanoutId: string;
  traceId: string;
  tenant?: string;
  endpoint: string;
  /** Acknowledgements banked when the quorum died. */
  acked: number;
  /** Total fan-out targets (N). */
  targets: number;
  /** Why the quorum died (e.g. how many targets were lost). */
  reason: string;
  at: string;
}

/** Fired when one target exhausts its own retry lifecycle. */
export interface QuorumTargetDeadLetteredInfo {
  event: "quorum_target_dead_lettered";
  fanoutId: string;
  traceId: string;
  tenant?: string;
  endpoint: string;
  /** The downstream URL that never acknowledged. */
  targetUrl: string;
  /** WR-30 classification of the final failure — drives the audit trail. */
  failureClass: FailureClass;
  lastError: string;
  /** Acknowledgements so far (the lost target is not one of them). */
  acked: number;
  /** Total fan-out targets (N). */
  targets: number;
  at: string;
}

/** Hooks for {@link QuorumFanoutSet}. */
export interface QuorumFanoutSetOptions {
  onDispatched?: (info: QuorumDispatchedInfo) => void;
  onAcknowledged?: (info: QuorumAcknowledgedInfo) => void;
  onSatisfied?: (info: QuorumSatisfiedInfo) => void;
  onFailed?: (info: QuorumFailedInfo) => void;
  onTargetDeadLettered?: (info: QuorumTargetDeadLetteredInfo) => void;
}

/**
 * Validate a quorum config the way a constructor would. Throws
 * `RangeError` on the first problem so a bad config fails at startup,
 * never mid-delivery. `undefined` (feature off) is valid.
 */
export function assertValidQuorumConfig(config: QuorumConfig | undefined): void {
  if (config === undefined) return;
  if (config === null || typeof config !== "object" || Array.isArray(config)) {
    throw new RangeError("quorum must be a record of targetUrl -> fan-out config");
  }
  for (const [endpoint, fanout] of Object.entries(config)) {
    if (endpoint.length === 0) {
      throw new RangeError("quorum keys must be non-empty endpoint URLs");
    }
    assertValidQuorumFanout(endpoint, fanout);
  }
}

function assertValidQuorumFanout(endpoint: string, fanout: QuorumFanoutConfig): void {
  const label = `quorum[${JSON.stringify(endpoint)}]`;
  if (fanout === null || typeof fanout !== "object" || Array.isArray(fanout)) {
    throw new RangeError(`${label} must be an object with targets and quorum`);
  }
  if (!Array.isArray(fanout.targets) || fanout.targets.length === 0) {
    throw new RangeError(`${label}.targets must be a non-empty array of downstream URLs`);
  }
  const seen = new Set<string>();
  for (const target of fanout.targets) {
    if (typeof target !== "string" || target.length === 0) {
      throw new RangeError(`${label}.targets entries must be non-empty strings`);
    }
    let protocol: string;
    try {
      protocol = new URL(target).protocol;
    } catch {
      throw new RangeError(`${label}.targets: ${JSON.stringify(target)} is not a valid absolute URL`);
    }
    if (protocol !== "http:" && protocol !== "https:") {
      throw new RangeError(
        `${label}.targets: ${JSON.stringify(target)} must be an http(s) URL (got ${protocol})`
      );
    }
    if (target === endpoint) {
      throw new RangeError(
        `${label}.targets: fanning out to the logical endpoint itself (${JSON.stringify(endpoint)}) would double-deliver`
      );
    }
    if (seen.has(target)) {
      throw new RangeError(
        `${label}.targets lists ${JSON.stringify(target)} twice: a target must appear at most once per fan-out`
      );
    }
    seen.add(target);
  }
  if (
    !Number.isInteger(fanout.quorum) ||
    fanout.quorum < 1 ||
    fanout.quorum > fanout.targets.length
  ) {
    throw new RangeError(
      `${label}.quorum must be an integer in [1, ${fanout.targets.length}], got ${String(fanout.quorum)}`
    );
  }
}

interface FanoutMember {
  fanoutId: string;
  targetIndex: number;
  targetUrl: string;
}

interface FanoutState {
  fanoutId: string;
  endpoint: string;
  tenant?: string;
  traceId: string;
  targets: string[];
  quorum: number;
  /** Target indexes that acknowledged. */
  acked: Set<number>;
  /** Target index -> loss record, in loss order. */
  dead: Map<number, QuorumDeadTarget>;
  dispatchedAt: string;
  settledAt?: string;
  satisfiedFired: boolean;
  failedFired: boolean;
}

/**
 * Owns the per-endpoint quorum fan-out configs and tracks every live
 * fan-out's acknowledgement progress. The queue calls `dispatch()` once
 * per admitted event (instead of a plain `enqueue`), then reports each
 * member item's terminal outcome via `recordDelivered` /
 * `recordDeadLetter`. Non-member ids are ignored silently, so the set is
 * safe to consult on every delivery.
 */
export class QuorumFanoutSet {
  private readonly configs = new Map<string, QuorumFanoutConfig>();
  private readonly fanouts = new Map<string, FanoutState>();
  /** Member item id -> membership. The queue consults this to skip batching. */
  private readonly members = new Map<string, FanoutMember>();
  private readonly opts: QuorumFanoutSetOptions;
  /**
   * Cumulative counters, keyed by JSON of [tenant, endpoint]
   * (`""` tenant = the default tenant). Activity-gated: a row is created
   * on the first recorded outcome, so `metricsRows()` is empty until a
   * target actually acknowledges or dies.
   */
  private readonly counters = new Map<
    string,
    { endpoint: string; tenant?: string; satisfied: number; failed: number; acknowledged: number; targetDeadLetters: number }
  >();

  constructor(config: QuorumConfig, opts: QuorumFanoutSetOptions = {}) {
    // Fail-fast: an invalid quorum config is a misconfiguration, never a
    // mid-delivery surprise.
    assertValidQuorumConfig(config);
    for (const [endpoint, fanout] of Object.entries(config)) {
      this.configs.set(endpoint, { targets: [...fanout.targets], quorum: fanout.quorum });
    }
    this.opts = opts;
  }

  /** Whether `endpoint` has a quorum fan-out configured. */
  hasConfig(endpoint: string): boolean {
    return this.configs.has(endpoint);
  }

  /** Whether `id` is a fan-out member item (the queue uses this to skip batching). */
  isMemberId(id: string): boolean {
    return this.members.has(id);
  }

  /**
   * Dispatch one admitted event to every configured target of its
   * endpoint. Registers the fan-out, then hands `enqueueMember` one item
   * per target — the same payload/headers/priority (WR-12: an urgent
   * admission puts every member on the fast lane), the shared trace id,
   * and a member-scoped id (`<id>:quorum:<i>`). Returns the fan-out id
   * (the admitted item's id). Throws when the endpoint has no quorum
   * config or the fan-out id is already live.
   */
  dispatch(item: RetryItem, enqueueMember: (member: RetryItem) => void): string {
    const cfg = this.configs.get(item.targetUrl);
    if (cfg === undefined) {
      throw new Error(`no quorum fan-out configured for ${item.targetUrl}`);
    }
    const fanoutId = item.id;
    if (this.fanouts.has(fanoutId)) {
      throw new Error(`Duplicate fan-out id: ${fanoutId}`);
    }
    const traceId = item.traceId ?? newTraceId();
    const tenant = item.tenantId;
    const dispatchedAt = new Date().toISOString();
    this.fanouts.set(fanoutId, {
      fanoutId,
      endpoint: item.targetUrl,
      ...(tenant === undefined ? {} : { tenant }),
      traceId,
      targets: [...cfg.targets],
      quorum: cfg.quorum,
      acked: new Set(),
      dead: new Map(),
      dispatchedAt,
      satisfiedFired: false,
      failedFired: false,
    });
    cfg.targets.forEach((targetUrl, i) => {
      const memberId = `${fanoutId}:quorum:${i}`;
      this.members.set(memberId, { fanoutId, targetIndex: i, targetUrl });
      // Same wire shape as the admitted event, only the targetUrl and
      // the id change — the member rides the queue's normal machinery
      // (backoff / urgent lane / circuit / quota / dead-letter) as its
      // own delivery.
      enqueueMember({ ...item, id: memberId, targetUrl, traceId });
    });
    this.opts.onDispatched?.({
      event: "quorum_dispatched",
      fanoutId,
      traceId,
      ...(tenant === undefined ? {} : { tenant }),
      endpoint: item.targetUrl,
      targets: [...cfg.targets],
      quorum: cfg.quorum,
      at: dispatchedAt,
    });
    return fanoutId;
  }

  /**
   * Record one member item's successful delivery (the queue calls this
   * from its `delivered` path). Unknown ids and duplicate acks are
   * ignored — the same item is never counted twice.
   */
  recordDelivered(
    itemId: string,
    info: { targetUrl: string; traceId?: string; tenant?: string }
  ): void {
    const member = this.members.get(itemId);
    if (member === undefined) return;
    const fanout = this.fanouts.get(member.fanoutId);
    if (fanout === undefined || fanout.acked.has(member.targetIndex)) return;
    fanout.acked.add(member.targetIndex);
    this.bumpCounter(fanout, "acknowledged");
    const at = new Date().toISOString();
    this.opts.onAcknowledged?.({
      event: "quorum_acknowledged",
      fanoutId: fanout.fanoutId,
      traceId: info.traceId ?? fanout.traceId,
      ...(fanout.tenant === undefined ? {} : { tenant: fanout.tenant }),
      endpoint: fanout.endpoint,
      targetUrl: member.targetUrl,
      acked: fanout.acked.size,
      targets: fanout.targets.length,
      at,
    });
    if (fanout.acked.size >= fanout.quorum && !fanout.satisfiedFired) {
      fanout.satisfiedFired = true;
      fanout.settledAt = at;
      this.bumpCounter(fanout, "satisfied");
      this.opts.onSatisfied?.({
        event: "quorum_satisfied",
        fanoutId: fanout.fanoutId,
        traceId: info.traceId ?? fanout.traceId,
        ...(fanout.tenant === undefined ? {} : { tenant: fanout.tenant }),
        endpoint: fanout.endpoint,
        acked: fanout.acked.size,
        targets: fanout.targets.length,
        at,
      });
    }
  }

  /**
   * Record one member item's terminal failure (the queue calls this from
   * its `dead_letter` path, with the WR-30 classification of the final
   * failure). Members the queue already retried to exhaustion — or
   * refused to retry as poison — land here exactly once each. When the
   * loss makes the quorum unreachable, the fan-out fails.
   */
  recordDeadLetter(itemId: string, failureClass: FailureClass, lastError: string): void {
    const member = this.members.get(itemId);
    if (member === undefined) return;
    const fanout = this.fanouts.get(member.fanoutId);
    if (
      fanout === undefined ||
      fanout.acked.has(member.targetIndex) ||
      fanout.dead.has(member.targetIndex)
    ) {
      return;
    }
    fanout.dead.set(member.targetIndex, {
      targetUrl: member.targetUrl,
      failureClass,
      lastError,
    });
    this.bumpCounter(fanout, "targetDeadLetters");
    const at = new Date().toISOString();
    this.opts.onTargetDeadLettered?.({
      event: "quorum_target_dead_lettered",
      fanoutId: fanout.fanoutId,
      traceId: fanout.traceId,
      ...(fanout.tenant === undefined ? {} : { tenant: fanout.tenant }),
      endpoint: fanout.endpoint,
      targetUrl: member.targetUrl,
      failureClass,
      lastError,
      acked: fanout.acked.size,
      targets: fanout.targets.length,
      at,
    });
    const live = fanout.targets.length - fanout.acked.size - fanout.dead.size;
    if (
      !fanout.satisfiedFired &&
      !fanout.failedFired &&
      fanout.acked.size + live < fanout.quorum
    ) {
      fanout.failedFired = true;
      fanout.settledAt = at;
      this.bumpCounter(fanout, "failed");
      this.opts.onFailed?.({
        event: "quorum_failed",
        fanoutId: fanout.fanoutId,
        traceId: fanout.traceId,
        ...(fanout.tenant === undefined ? {} : { tenant: fanout.tenant }),
        endpoint: fanout.endpoint,
        acked: fanout.acked.size,
        targets: fanout.targets.length,
        reason: `quorum unreachable: ${fanout.dead.size} of ${fanout.targets.length} targets dead-lettered, ${fanout.acked.size} acknowledged, need ${fanout.quorum}`,
        at,
      });
    }
  }

  private bumpCounter(
    fanout: FanoutState,
    field: "satisfied" | "failed" | "acknowledged" | "targetDeadLetters"
  ): void {
    const key = JSON.stringify([fanout.tenant ?? "", fanout.endpoint]);
    let c = this.counters.get(key);
    if (c === undefined) {
      c = {
        endpoint: fanout.endpoint,
        ...(fanout.tenant === undefined ? {} : { tenant: fanout.tenant }),
        satisfied: 0,
        failed: 0,
        acknowledged: 0,
        targetDeadLetters: 0,
      };
      this.counters.set(key, c);
    }
    c[field] += 1;
  }

  private statusOf(fanout: FanoutState): QuorumFanoutStatus {
    if (fanout.acked.size >= fanout.quorum) return "satisfied";
    const live = fanout.targets.length - fanout.acked.size - fanout.dead.size;
    if (fanout.acked.size + live < fanout.quorum) return "failed";
    if (fanout.dead.size > 0) return "partial";
    return "in_progress";
  }

  /**
   * Per-fanout acknowledgement progress (`acked` / `targets` /
   * `status`), in dispatch order. Operator metadata only — no payloads.
   */
  stats(): QuorumFanoutStats[] {
    return [...this.fanouts.values()].map((f) => ({
      fanoutId: f.fanoutId,
      endpoint: f.endpoint,
      ...(f.tenant === undefined ? {} : { tenant: f.tenant }),
      targets: f.targets.length,
      acked: f.acked.size,
      status: this.statusOf(f),
      deadLettered: [...f.dead.values()],
      dispatchedAt: f.dispatchedAt,
      ...(f.settledAt === undefined ? {} : { settledAt: f.settledAt }),
    }));
  }

  /**
   * Cumulative quorum counters per (tenant, endpoint), in first-seen
   * order. Activity-gated: endpoints with no recorded outcome produce no
   * row, so the metrics exposition stays byte-identical until the first
   * ack or loss.
   */
  metricsRows(): QuorumMetricsInput[] {
    return [...this.counters.values()];
  }
}
