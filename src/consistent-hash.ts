import { createHash } from "node:crypto";
import type { CircuitState } from "./circuit.ts";

/**
 * Consistent-hash sticky routing (WR-202).
 *
 * WR-39 failover (active/standby) answers "which target is *up*"; WR-66
 * weighted (smooth round-robin) answers "how is traffic *shared*";
 * consistent-hash answers "which target owns this *sticky key*" — for
 * stateful downstreams (session affinity, sharded consumers) where the
 * same tenant / endpoint / event must keep landing on the same physical
 * target. The sticky key is configurable per endpoint
 * (`tenant` / `endpoint` / `event` parts, default `["tenant",
 * "endpoint"]`); deliveries carrying the same key always resolve to the
 * same target while the ring is stable, and adding or removing a target
 * only remigrates the keys whose ring position fell on the changed
 * arcs — the minimal-migration property the hash ring exists for.
 *
 * The ring is a hand-written ketama-style construction (zero
 * dependencies): every target owns `virtualNodes` points (default 128),
 * each point placed by SHA-256 (`node:crypto`), sorted ascending; a key
 * walks clockwise to the first point at or past its own hash. Deterministic
 * given the target set — no randomness anywhere.
 *
 * Health filtering reuses the codebase's own signals, never a parallel
 * health universe (same convention as WR-66):
 * - the circuit breaker's state for the target (`open` = excluded;
 *   `half_open` = included, so the breaker's probe delivery can settle).
 * - the dispatcher's own per-target consecutive-failure counter, so
 *   exclusion works with the breaker disabled too (mirrors
 *   `FailoverManager`). A downstream that *answers* — even with a 4xx —
 *   counts as a success: it is up, it just refused this payload.
 *
 * All-unhealthy fallback: when every target is unhealthy the dispatcher
 * pins to the *first* configured target instead of dropping the delivery
 * (the failover equivalent of "钉死最后一个走正常重试/死信") — the
 * queue's normal retry / dead-letter machinery owns the outcome from
 * there.
 *
 * Mutual exclusion with WR-66 weighted, WR-39 failover, and WR-201
 * weight-tuning is fail-fast at construction in the retry queue:
 * consistent-hash ("own this key"), weighted ("share traffic"), and
 * failover ("ordered standby") routing must never all claim the same
 * endpoint.
 */

/** Default virtual nodes per target on the ring. */
export const DEFAULT_VIRTUAL_NODES = 128;
/** Upper bound for virtual nodes per target (bounds ring memory). */
export const MAX_VIRTUAL_NODES = 4096;
/** Default consecutive retryable failures before a target leaves the ring. */
export const DEFAULT_CONSISTENT_HASH_FAILURE_THRESHOLD = 5;
/** Default quiet period after a target's last failure before it rejoins (ms). */
export const DEFAULT_CONSISTENT_HASH_RECOVERY_INTERVAL_MS = 30_000;

/** One dimension of the sticky key a delivery is routed on. */
export type StickyKeyPart = "tenant" | "endpoint" | "event";

/** One physical target on the ring. */
export interface ConsistentHashTargetConfig {
  /** Physical `targetUrl` this target's deliveries go to. */
  targetUrl: string;
}

/** Consistent-hash routing config for one logical endpoint. */
export interface ConsistentHashEndpointConfig {
  /** The physical targets sharing this endpoint's deliveries. Required, non-empty. */
  targets: ConsistentHashTargetConfig[];
  /**
   * Virtual nodes per target on the ring. Default: 128. Must be an
   * integer in [1, 4096].
   */
  virtualNodes?: number;
  /**
   * Which sticky-key parts compose the routing key. Default:
   * `["tenant", "endpoint"]`. Non-empty, no duplicates.
   */
  stickyKey?: StickyKeyPart[];
  /**
   * Consecutive retryable failures that exclude the target from the
   * ring. Default: 5. Must be an integer >= 1.
   */
  failureThreshold?: number;
  /**
   * Quiet period in ms after a target's last failure before it becomes
   * eligible again (recovery canary). Default: 30_000. Must be > 0.
   */
  recoveryIntervalMs?: number;
}

/** Consistent-hash routing config: logical endpoint -> its ring config. */
export type ConsistentHashConfig = Record<string, ConsistentHashEndpointConfig>;

/** The sticky-key dimensions the queue extracts from a queued delivery. */
export interface ConsistentHashKey {
  /** Tenant id (WR-48); undefined = the default tenant. */
  tenant?: string;
  /** Event/delivery id — the WR-44 idempotency anchor per delivery. */
  eventId: string;
}

/** Observable snapshot of one physical target's ring state. */
export interface ConsistentHashTargetStats {
  /** Physical target URL. */
  targetUrl: string;
  /** Virtual nodes this target owns on the ring. */
  virtualNodes: number;
  /** Cumulative dispatches routed to this target since construction. */
  dispatched: number;
  /** Consecutive retryable failures since the last success (0 once healthy). */
  consecutiveFailures: number;
  /** Whether the target currently joins the ring. */
  healthy: boolean;
}

/** Observable snapshot of one endpoint's ring. */
export interface ConsistentHashEndpointStats {
  /** Logical endpoint. */
  endpoint: string;
  /**
   * Ring generation — bumped on every target-list change (`setTargets`),
   * so an operator can see whether a stickiness complaint predates the
   * latest membership change.
   */
  ringVersion: number;
  /**
   * Cumulative ring-membership changes (a target added or removed).
   * Each change may migrate the keys that fell on the changed arcs —
   * this counts the events, not the keys, which the ring cannot
   * enumerate without keeping every key in memory.
   */
  migrations: number;
  /** Targets in config order. */
  targets: ConsistentHashTargetStats[];
}

export interface ConsistentHashDispatcherOptions {
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
  /**
   * Current breaker state for a target. The queue wires its own breaker
   * here (OR-ed across tenants, like failover); without a breaker every
   * target reads `"closed"` and only the failure-count trigger applies.
   */
  circuitState?: (target: string) => CircuitState;
}

const VALID_STICKY_PARTS: ReadonlySet<string> = new Set(["tenant", "endpoint", "event"]);

/**
 * Validate one endpoint's target list (shape + uniqueness). Throws
 * `RangeError` on anything illegal — at construction / before apply,
 * never mid-delivery.
 */
export function assertValidConsistentHashTargets(targets: unknown): void {
  if (!Array.isArray(targets) || targets.length === 0) {
    throw new RangeError(
      `consistent-hash targets must be a non-empty array, got ${JSON.stringify(targets)}`
    );
  }
  const seen = new Set<string>();
  for (const t of targets) {
    const where = "consistent-hash target";
    if (t === null || typeof t !== "object" || Array.isArray(t)) {
      throw new RangeError(`${where} must be an object, got ${JSON.stringify(t)}`);
    }
    const { targetUrl } = t as { targetUrl: unknown };
    if (typeof targetUrl !== "string" || targetUrl.length === 0) {
      throw new RangeError(`${where}.targetUrl must be a non-empty string, got ${JSON.stringify(targetUrl)}`);
    }
    if (seen.has(targetUrl)) {
      throw new RangeError(`${where}: duplicate targetUrl ${JSON.stringify(targetUrl)}`);
    }
    seen.add(targetUrl);
  }
}

function assertValidStickyKey(stickyKey: unknown, where: string): asserts stickyKey is StickyKeyPart[] {
  if (!Array.isArray(stickyKey) || stickyKey.length === 0) {
    throw new RangeError(`${where}.stickyKey must be a non-empty array, got ${JSON.stringify(stickyKey)}`);
  }
  const seen = new Set<string>();
  for (const part of stickyKey) {
    if (typeof part !== "string" || !VALID_STICKY_PARTS.has(part)) {
      throw new RangeError(
        `${where}.stickyKey entries must be one of "tenant" | "endpoint" | "event", got ${JSON.stringify(part)}`
      );
    }
    if (seen.has(part)) {
      throw new RangeError(`${where}.stickyKey: duplicate part ${JSON.stringify(part)}`);
    }
    seen.add(part);
  }
}

/**
 * Validate a consistent-hash routing config. Throws `RangeError` on
 * anything illegal — at construction, never mid-delivery.
 */
export function assertValidConsistentHashConfig(config: ConsistentHashConfig): void {
  if (config === null || typeof config !== "object" || Array.isArray(config)) {
    throw new RangeError(
      `consistent-hash must be a record of endpoint -> ring config, got ${JSON.stringify(config)}`
    );
  }
  for (const [endpoint, cfg] of Object.entries(config)) {
    const where = `consistent-hash[${JSON.stringify(endpoint)}]`;
    if (endpoint.length === 0) {
      throw new RangeError("consistent-hash endpoint must be a non-empty string");
    }
    if (cfg === null || typeof cfg !== "object" || Array.isArray(cfg)) {
      throw new RangeError(`${where} must be an object, got ${JSON.stringify(cfg)}`);
    }
    assertValidConsistentHashTargets(cfg.targets);
    const { virtualNodes, stickyKey, failureThreshold, recoveryIntervalMs } = cfg;
    if (
      virtualNodes !== undefined &&
      (!Number.isInteger(virtualNodes) || virtualNodes < 1 || virtualNodes > MAX_VIRTUAL_NODES)
    ) {
      throw new RangeError(
        `${where}.virtualNodes must be an integer in [1, ${MAX_VIRTUAL_NODES}], got ${JSON.stringify(virtualNodes)}`
      );
    }
    if (stickyKey !== undefined) {
      assertValidStickyKey(stickyKey, where);
    }
    if (
      failureThreshold !== undefined &&
      (!Number.isInteger(failureThreshold) || failureThreshold < 1)
    ) {
      throw new RangeError(
        `${where}.failureThreshold must be an integer >= 1, got ${JSON.stringify(failureThreshold)}`
      );
    }
    if (
      recoveryIntervalMs !== undefined &&
      (!Number.isFinite(recoveryIntervalMs) || recoveryIntervalMs <= 0)
    ) {
      throw new RangeError(
        `${where}.recoveryIntervalMs must be > 0, got ${JSON.stringify(recoveryIntervalMs)}`
      );
    }
  }
}

/** One ring point: a 53-bit-safe position owned by a target. */
interface RingPoint {
  /** Position on the ring, in [0, 2^53). */
  position: number;
  /** Physical target owning this point. */
  targetUrl: string;
}

/** Hash an arbitrary string to a 53-bit-safe number via SHA-256. */
function hashToPosition(input: string): number {
  const digest = createHash("sha256").update(input, "utf8").digest();
  // First 8 bytes big-endian as a 53-bit-safe integer (2^32 * hi + lo).
  return digest.readUInt32BE(0) * 0x1_0000_0000 + digest.readUInt32BE(4);
}

interface EndpointRingState {
  /** Physical targets in config order; replaced atomically on updates. */
  targets: ConsistentHashTargetConfig[];
  virtualNodes: number;
  stickyKey: StickyKeyPart[];
  failureThreshold: number;
  recoveryIntervalMs: number;
  /** Sorted ring points; rebuilt atomically whenever targets change. */
  ring: RingPoint[];
  /** Ring generation; bumped on every target-list change. */
  ringVersion: number;
  /** Cumulative membership changes (add/remove). */
  migrations: number;
  /** Own consecutive-failure counter per target (works breaker-less). */
  consecutiveFailures: Map<string, number>;
  /** ms epoch of each target's last recorded failure. */
  lastFailureAtMs: Map<string, number>;
  /** Cumulative dispatches per target. */
  dispatched: Map<string, number>;
}

/**
 * Consistent-hash sticky routing per logical endpoint. Pure routing
 * state — it never sends anything itself; the retry queue asks
 * `resolveTarget()` on every dispatch and reports outcomes via
 * `recordOutcome()`.
 */
export class ConsistentHashDispatcher {
  private readonly states = new Map<string, EndpointRingState>();
  private readonly now: () => number;
  private readonly circuitState: (target: string) => CircuitState;

  constructor(config: ConsistentHashConfig, opts: ConsistentHashDispatcherOptions = {}) {
    assertValidConsistentHashConfig(config);
    this.now = opts.now ?? Date.now;
    this.circuitState = opts.circuitState ?? (() => "closed");
    for (const [endpoint, cfg] of Object.entries(config)) {
      this.states.set(endpoint, this.freshState(cfg));
    }
  }

  /** Whether `endpoint` has consistent-hash routing configured. */
  hasEndpoint(endpoint: string): boolean {
    return this.states.has(endpoint);
  }

  /**
   * The physical target the delivery's sticky key owns. Returns
   * `undefined` when the endpoint has no consistent-hash config (the
   * caller falls through to weighted / failover / the endpoint itself —
   * zero behavior change when the mode is not configured).
   *
   * The sticky key is composed from the configured parts
   * (`tenant`/`endpoint`/`event`) and walked clockwise to the first
   * *healthy* target's ring point; targets already tried are skipped so
   * one sick target's many virtual nodes cannot absorb the whole walk.
   * When every target is unhealthy the first configured target is
   * pinned (documented fallback — the queue's retry / dead-letter
   * machinery owns the outcome).
   */
  resolveTarget(endpoint: string, key: ConsistentHashKey): string | undefined {
    const st = this.states.get(endpoint);
    if (!st) return undefined;
    const position = hashToPosition(this.composeKey(st, endpoint, key));
    const start = lowerBound(st.ring, position);
    const tried = new Set<string>();
    // Walk the ring clockwise over distinct targets; at most one full
    // lap — with >= 1 target a lap always terminates.
    for (let i = 0; i < st.ring.length; i++) {
      const point = st.ring[(start + i) % st.ring.length];
      if (tried.has(point.targetUrl)) continue;
      tried.add(point.targetUrl);
      if (this.isHealthy(st, point.targetUrl)) {
        this.countDispatch(st, point.targetUrl);
        return point.targetUrl;
      }
      if (tried.size >= st.targets.length) break;
    }
    // All-unhealthy fallback: pin to the first configured target.
    const fallback = st.targets[0].targetUrl;
    this.countDispatch(st, fallback);
    return fallback;
  }

  /**
   * Report a delivery outcome for `target` (the physical target the
   * attempt went to). A target that *answered* — even with a 4xx —
   * counts as a success: it is up, it just refused this payload.
   * Outcomes for unknown endpoints or targets no longer configured are
   * ignored (stale, e.g. recorded after a target update removed them).
   */
  recordOutcome(endpoint: string, target: string, ok: boolean): void {
    const st = this.states.get(endpoint);
    if (!st || !st.targets.some((t) => t.targetUrl === target)) return;
    if (ok) {
      st.consecutiveFailures.set(target, 0);
    } else {
      st.consecutiveFailures.set(target, (st.consecutiveFailures.get(target) ?? 0) + 1);
      st.lastFailureAtMs.set(target, this.now());
    }
  }

  /**
   * Replace the target list for `endpoint` at runtime (WR-32). Validated
   * *before* anything mutates: an illegal list throws `RangeError` and
   * the running ring is left completely intact — zero partial
   * application. The ring is rebuilt atomically and `ringVersion` is
   * bumped; when the membership actually changed (a target added or
   * removed), `migrations` is incremented — only the keys on the changed
   * arcs remigrate, the rest keep their sticky target. Per-target health
   * counters and cumulative dispatch counts survive for targets still
   * present.
   */
  setTargets(endpoint: string, targets: ConsistentHashTargetConfig[]): void {
    const st = this.states.get(endpoint);
    if (!st) {
      throw new RangeError(
        `consistent-hash routing is not configured for endpoint ${JSON.stringify(endpoint)}`
      );
    }
    assertValidConsistentHashTargets(targets);
    const before = new Set(st.targets.map((t) => t.targetUrl));
    const after = new Set(targets.map((t) => t.targetUrl));
    const membershipChanged =
      before.size !== after.size || [...before].some((t) => !after.has(t));
    st.targets = targets.map((t) => ({ targetUrl: t.targetUrl }));
    st.ring = buildRing(st.targets, st.virtualNodes);
    st.ringVersion += 1;
    if (membershipChanged) {
      st.migrations += 1;
    }
  }

  /**
   * Snapshot of every endpoint with consistent-hash routing configured —
   * ring version and migration counts included (WR-202).
   */
  getConsistentHashStats(): ConsistentHashEndpointStats[] {
    return [...this.states.entries()].map(([endpoint, st]) => ({
      endpoint,
      ringVersion: st.ringVersion,
      migrations: st.migrations,
      targets: st.targets.map((t) => ({
        targetUrl: t.targetUrl,
        virtualNodes: st.virtualNodes,
        dispatched: st.dispatched.get(t.targetUrl) ?? 0,
        consecutiveFailures: st.consecutiveFailures.get(t.targetUrl) ?? 0,
        healthy: this.isHealthy(st, t.targetUrl),
      })),
    }));
  }

  private freshState(cfg: ConsistentHashEndpointConfig): EndpointRingState {
    const targets = cfg.targets.map((t) => ({ targetUrl: t.targetUrl }));
    const virtualNodes = cfg.virtualNodes ?? DEFAULT_VIRTUAL_NODES;
    const st: EndpointRingState = {
      targets,
      virtualNodes,
      stickyKey: cfg.stickyKey !== undefined ? [...cfg.stickyKey] : ["tenant", "endpoint"],
      failureThreshold: cfg.failureThreshold ?? DEFAULT_CONSISTENT_HASH_FAILURE_THRESHOLD,
      recoveryIntervalMs:
        cfg.recoveryIntervalMs ?? DEFAULT_CONSISTENT_HASH_RECOVERY_INTERVAL_MS,
      ring: buildRing(targets, virtualNodes),
      ringVersion: 1,
      migrations: 0,
      consecutiveFailures: new Map(),
      lastFailureAtMs: new Map(),
      dispatched: new Map(),
    };
    for (const t of targets) {
      st.consecutiveFailures.set(t.targetUrl, 0);
    }
    return st;
  }

  /**
   * Compose the routing key from the configured sticky parts. Each part
   * is namespaced (`tenant=…`) so `tenant="a", endpoint="b/c"` can never
   * collide with `tenant="a/b", endpoint="c"`; the default tenant hashes
   * as the empty string and is stable across restarts.
   */
  private composeKey(st: EndpointRingState, endpoint: string, key: ConsistentHashKey): string {
    const parts: string[] = [];
    for (const part of st.stickyKey) {
      if (part === "tenant") parts.push(`tenant=${key.tenant ?? ""}`);
      else if (part === "endpoint") parts.push(`endpoint=${endpoint}`);
      else parts.push(`event=${key.eventId}`);
    }
    return parts.join("");
  }

  private countDispatch(st: EndpointRingState, target: string): void {
    st.dispatched.set(target, (st.dispatched.get(target) ?? 0) + 1);
  }

  /**
   * Whether `target` joins the ring. The breaker's `open` state always
   * excludes; `half_open` always includes (the breaker's probe delivery
   * must run so its outcome can re-admit or re-exclude). Otherwise the
   * dispatcher's own consecutive-failure counter applies — after
   * `failureThreshold` failures the target is out until
   * `recoveryIntervalMs` has passed since its last failure (the recovery
   * canary), so exclusion works with the breaker disabled too.
   */
  private isHealthy(st: EndpointRingState, target: string): boolean {
    const circuit = this.circuitState(target);
    if (circuit === "open") return false;
    if (circuit === "half_open") return true;
    const failures = st.consecutiveFailures.get(target) ?? 0;
    if (failures < st.failureThreshold) return true;
    const lastFailure = st.lastFailureAtMs.get(target) ?? 0;
    return this.now() - lastFailure >= st.recoveryIntervalMs;
  }
}

/** Build the sorted ring: `virtualNodes` SHA-256 points per target. */
function buildRing(targets: ConsistentHashTargetConfig[], virtualNodes: number): RingPoint[] {
  const ring: RingPoint[] = [];
  for (const t of targets) {
    for (let i = 0; i < virtualNodes; i++) {
      ring.push({ position: hashToPosition(`${t.targetUrl} ${i}`), targetUrl: t.targetUrl });
    }
  }
  ring.sort((a, b) => a.position - b.position);
  return ring;
}

/** First index in `ring` with `position >= target` (binary search); wraps to 0. */
function lowerBound(ring: RingPoint[], target: number): number {
  let lo = 0;
  let hi = ring.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (ring[mid].position < target) lo = mid + 1;
    else hi = mid;
  }
  return lo % ring.length;
}
