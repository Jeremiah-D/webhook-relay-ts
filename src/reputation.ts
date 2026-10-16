/**
 * Inbound sender reputation scoring (WR-119).
 *
 * Per-sender (inbound API key id, or `"anonymous"` when no key guards the
 * endpoint) behavior scoring: verify failures, rate-limit hits, and schema
 * violations each carry a weighted penalty that accumulates against the
 * sender; the accumulated demerit decays exponentially (configurable
 * half-life), so a sender that stops misbehaving recovers on its own.
 *
 * Score is 100 minus decayed demerit, clamped to [0, 100]; a pristine
 * sender sits at 100. Thresholds use hysteresis: the score must fall
 * *below* `lowThreshold` to downgrade and climb *above* `highThreshold`
 * to upgrade again — a sender oscillating around one line cannot flap.
 * Threshold crossings are surfaced as `ReputationTransition`s so the
 * caller can audit `reputation_downgraded` / `reputation_upgraded`.
 *
 * While a sender is degraded, the intake tightens around them:
 *   (a) an extra per-sender rate-limit budget (the caller's halved
 *       inbound budget — `takeTightenedBudget`) gates admission;
 *   (b) signature verification is forced even where an API key alone
 *       would authenticate (the caller applies this to the WR-65 gate);
 *   (c) the dedup window is lengthened (the caller admits through a
 *       second `DeliveryDeduplicator` with a wider window).
 * Forcing verification is only meaningful where a verifier is
 * configured — the relay always configures one (the default HMAC
 * verifier over `secret`), so the forced check always takes effect.
 *
 * Opt-in: the server only constructs the tracker when
 * `senderReputation` is set. Unset = zero behavior change.
 *
 * Zero dependencies. The clock is injectable for deterministic tests.
 */

/** The three penalty event kinds, in the WR-119 spec order. */
export type ReputationPenaltyKind = "verify_failure" | "rate_limit" | "schema_violation";

/** Options for {@link SenderReputationTracker}. */
export interface ReputationOptions {
  /**
   * Exponential half-life (ms) of accumulated demerit: after one
   * half-life of quiet, a sender's demerit halves and the score climbs
   * halfway back to 100. Default: 600000 (10 minutes). Must be a finite
   * number > 0.
   */
  halfLifeMs?: number;
  /**
   * A sender whose score falls strictly below this is downgraded
   * (tightened). Default: 40. Must be a finite number in [0, 100] and
   * strictly below `highThreshold`.
   */
  lowThreshold?: number;
  /**
   * A degraded sender whose score climbs strictly above this is upgraded
   * back (relaxed). Default: 70. Must be a finite number in [0, 100] and
   * strictly above `lowThreshold` — the gap is the hysteresis that
   * prevents flapping.
   */
  highThreshold?: number;
  /** Demerit points added per signature verification failure. Default: 25. Must be finite and >= 0. */
  verifyFailurePenalty?: number;
  /** Demerit points added per inbound rate-limit hit. Default: 5. Must be finite and >= 0. */
  rateLimitPenalty?: number;
  /** Demerit points added per inbound schema validation failure. Default: 10. Must be finite and >= 0. */
  schemaViolationPenalty?: number;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
}

/** Fail with a RangeError naming the offending input. */
function invalid(where: string, detail: string): never {
  throw new RangeError(`senderReputation: ${where}: ${detail}`);
}

function assertFiniteNumber(name: string, value: number | undefined, min: number): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "number" || !Number.isFinite(value) || value < min) {
    invalid(name, `expected a finite number >= ${min}, got ${value}`);
  }
  return value;
}

/**
 * Validate sender reputation options. Throws RangeError on a bad
 * half-life, thresholds outside [0, 100], thresholds without a strict
 * low < high gap, or negative/non-finite penalties — fail fast at
 * startup, never mid-request.
 */
export function assertValidReputationOptions(opts: ReputationOptions | undefined): void {
  if (opts === undefined) return;
  if (opts === null || typeof opts !== "object") {
    throw new RangeError("senderReputation: expected an options object");
  }
  const halfLife = assertFiniteNumber("halfLifeMs", opts.halfLifeMs, 0);
  if (halfLife !== undefined && halfLife <= 0) {
    invalid("halfLifeMs", `expected a finite number > 0, got ${opts.halfLifeMs}`);
  }
  const low = assertFiniteNumber("lowThreshold", opts.lowThreshold, 0);
  if (low !== undefined && low > 100) {
    invalid("lowThreshold", `expected a number in [0, 100], got ${opts.lowThreshold}`);
  }
  const high = assertFiniteNumber("highThreshold", opts.highThreshold, 0);
  if (high !== undefined && high > 100) {
    invalid("highThreshold", `expected a number in [0, 100], got ${opts.highThreshold}`);
  }
  if (low !== undefined && high !== undefined && low >= high) {
    invalid("lowThreshold/highThreshold", `lowThreshold (${low}) must be strictly below highThreshold (${high})`);
  }
  assertFiniteNumber("verifyFailurePenalty", opts.verifyFailurePenalty, 0);
  assertFiniteNumber("rateLimitPenalty", opts.rateLimitPenalty, 0);
  assertFiniteNumber("schemaViolationPenalty", opts.schemaViolationPenalty, 0);
  if (opts.now !== undefined && typeof opts.now !== "function") {
    invalid("now", "expected a function returning ms");
  }
}

/** A threshold crossing: the caller audits it and (un)tightens the sender. */
export interface ReputationTransition {
  /** The sender key that crossed (API key id, or `"anonymous"`). */
  key: string;
  /** Which way the hysteresis line was crossed. */
  kind: "downgraded" | "upgraded";
  /** The decayed score at the crossing instant, in [0, 100]. */
  score: number;
  /** The ms timestamp of the crossing (the tracker's clock). */
  at: number;
}

/** Current view of one sender: decayed score plus tightening state. */
export interface ReputationView {
  /** Decayed score in [0, 100]; 100 = pristine. */
  score: number;
  /** Whether the sender is currently degraded (tightening applies). */
  degraded: boolean;
  /**
   * A threshold crossing caused by the decay/hysteresis check behind
   * this view (e.g. a quiet degraded sender climbing past
   * `highThreshold`); the caller audits it exactly like a
   * `recordPenalty` transition.
   */
  transition?: ReputationTransition;
}

interface SenderState {
  /** Accumulated demerit at `updatedMs` (decays exponentially toward 0). */
  demerit: number;
  /** Ms timestamp the demerit was last decayed to. */
  updatedMs: number;
  /** Whether the sender is currently degraded (tightening applies). */
  degraded: boolean;
  /** Cumulative downgrade transitions (the degraded counter metric). */
  downgrades: number;
}

interface TightenBucket {
  tokens: number;
  updatedMs: number;
}

/** Pristine score: no demerit, no penalties recorded yet. */
const PRISTINE_SCORE = 100;
/** Demerit is a soft accumulator; capping keeps the math bounded on a flood. */
const MAX_DEMERIT = 1000;

/**
 * Per-sender reputation tracker: weighted penalties with exponential
 * half-life recovery and hysteresis thresholding. Construct once at
 * server startup (invalid config throws RangeError there); `recordPenalty`
 * / `observe` / `score` / `isDegraded` are then safe to call per request —
 * they never throw on hostile input (a sender key is an opaque string).
 */
export class SenderReputationTracker {
  private readonly halfLifeMs: number;
  private readonly lowThreshold: number;
  private readonly highThreshold: number;
  private readonly penalties: Record<ReputationPenaltyKind, number>;
  private readonly now: () => number;
  private readonly senders = new Map<string, SenderState>();
  private readonly tightenBuckets = new Map<string, TightenBucket>();

  constructor(opts: ReputationOptions = {}) {
    assertValidReputationOptions(opts);
    this.halfLifeMs = opts.halfLifeMs ?? 600_000;
    this.lowThreshold = opts.lowThreshold ?? 40;
    this.highThreshold = opts.highThreshold ?? 70;
    this.penalties = {
      verify_failure: opts.verifyFailurePenalty ?? 25,
      rate_limit: opts.rateLimitPenalty ?? 5,
      schema_violation: opts.schemaViolationPenalty ?? 10,
    };
    this.now = opts.now ?? Date.now;
  }

  private stateFor(key: string, at: number): SenderState {
    let s = this.senders.get(key);
    if (!s) {
      s = { demerit: 0, updatedMs: at, degraded: false, downgrades: 0 };
      this.senders.set(key, s);
    }
    return s;
  }

  /** Demerit decayed from `s.updatedMs` to `at` (never negative elapsed). */
  private decayedDemerit(s: SenderState, at: number): number {
    const elapsedMs = Math.max(0, at - s.updatedMs);
    if (elapsedMs === 0) return s.demerit;
    return s.demerit * Math.pow(0.5, elapsedMs / this.halfLifeMs);
  }

  private scoreOf(demerit: number): number {
    return Math.max(0, Math.min(PRISTINE_SCORE, PRISTINE_SCORE - demerit));
  }

  /**
   * Decay `s` to `at`, apply the hysteresis thresholds, and report a
   * crossing when one happened. State is updated in place; the returned
   * transition (if any) is the caller's cue to audit.
   */
  private checkThresholds(key: string, s: SenderState, at: number): ReputationTransition | undefined {
    s.demerit = this.decayedDemerit(s, at);
    s.updatedMs = at;
    const score = this.scoreOf(s.demerit);
    if (!s.degraded && score < this.lowThreshold) {
      s.degraded = true;
      s.downgrades += 1;
      return { key, kind: "downgraded", score, at };
    }
    if (s.degraded && score > this.highThreshold) {
      s.degraded = false;
      return { key, kind: "upgraded", score, at };
    }
    return undefined;
  }

  /**
   * Record one penalty event for `key`: decay the existing demerit to
   * now, add the kind's weight, then check the hysteresis thresholds.
   * Returns the threshold crossing (if any) for the caller to audit as
   * `reputation_downgraded` / `reputation_upgraded`. Never throws.
   */
  recordPenalty(key: string, kind: ReputationPenaltyKind): ReputationTransition | undefined {
    const at = this.now();
    const s = this.stateFor(String(key), at);
    s.demerit = this.decayedDemerit(s, at);
    s.updatedMs = at;
    s.demerit = Math.min(MAX_DEMERIT, s.demerit + (this.penalties[kind] ?? 0));
    return this.checkThresholds(String(key), s, at);
  }

  /**
   * Observe `key` without adding a penalty: decay to now and check the
   * hysteresis thresholds. This is how a quiet degraded sender recovers —
   * the decay alone can carry the score back above `highThreshold` and
   * emit the `upgraded` transition. The caller audits `transition` when
   * present and applies tightening when `degraded` is true.
   */
  observe(key: string): ReputationView {
    const k = String(key);
    const at = this.now();
    const s = this.stateFor(k, at);
    const transition = this.checkThresholds(k, s, at);
    return { score: this.scoreOf(s.demerit), degraded: s.degraded, transition };
  }

  /** Current decayed score for `key` in [0, 100]; 100 when never seen. */
  score(key: string): number {
    const s = this.senders.get(String(key));
    if (!s) return PRISTINE_SCORE;
    return this.scoreOf(this.decayedDemerit(s, this.now()));
  }

  /**
   * Whether `key` is currently degraded (tightening applies). Decays
   * first, so a sender quiet long enough can come back un-degraded —
   * but the upgrade *transition* (the audit cue) is only reported by
   * `observe` / `recordPenalty`, so it is emitted exactly once.
   */
  isDegraded(key: string): boolean {
    return this.observe(key).degraded;
  }

  /**
   * The tightening rate-limit budget (WR-119 action (a)): a per-sender
   * token bucket the caller sizes at half the configured inbound budget.
   * A degraded sender must hold a token here in *addition* to the normal
   * inbound limiter to be admitted. The bucket refills lazily with the
   * tracker's injectable clock; a backward clock never grants extra
   * budget. Returns `true` when admitted (a token was consumed).
   */
  takeTightenedBudget(key: string, perSecond: number): boolean {
    const k = String(key);
    const at = this.now();
    let b = this.tightenBuckets.get(k);
    if (!b) {
      b = { tokens: perSecond, updatedMs: at };
      this.tightenBuckets.set(k, b);
    } else {
      const elapsedMs = Math.max(0, at - b.updatedMs);
      b.tokens = Math.min(perSecond, b.tokens + (elapsedMs * perSecond) / 1000);
      b.updatedMs = at;
    }
    if (b.tokens < 1) return false;
    b.tokens -= 1;
    return true;
  }

  /** Senders currently tracked. */
  trackedSenders(): number {
    return this.senders.size;
  }

  /**
   * Metric rows for every tracked sender: the score gauge for all of
   * them, plus a downgrade counter only for senders that actually
   * downgraded (activity-gated, like the other metric blocks).
   */
  metricsSnapshot(): SenderReputationMetricsInput[] {
    const at = this.now();
    const rows: SenderReputationMetricsInput[] = [];
    for (const [key, s] of this.senders) {
      rows.push({
        key,
        score: this.scoreOf(this.decayedDemerit(s, at)),
        degraded: s.degraded,
        downgrades: s.downgrades,
      });
    }
    return rows;
  }

  /**
   * Prometheus text exposition (0.0.4) of the reputation state; `""`
   * when no sender has been seen yet, so a relay with the feature
   * enabled but no intake traffic exposes no new series — and a relay
   * with the feature off never renders this at all.
   */
  renderMetrics(): string {
    return renderSenderReputationBlock(this.metricsSnapshot());
  }
}

/** One sender's metric row, in Prometheus label order. */
export interface SenderReputationMetricsInput {
  /** The sender key (API key id, or `"anonymous"`). */
  key: string;
  /** Current decayed score in [0, 100]. */
  score: number;
  /** Whether the sender is currently degraded. */
  degraded: boolean;
  /** Cumulative downgrade transitions for this sender. */
  downgrades: number;
}

/**
 * Render just the sender-reputation block (WR-119) as exposition lines;
 * `[]` when the series is empty, so callers keep their output
 * byte-identical until the first sender is actually tracked.
 */
export function renderSenderReputationBlock(series: SenderReputationMetricsInput[]): string {
  if (series.length === 0) return "";
  const esc = (v: string): string => v.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, '\\"');
  const lines = [
    "# HELP relay_sender_reputation_score Inbound sender reputation score (0-100, 100 = pristine) by sender key (WR-119).",
    "# TYPE relay_sender_reputation_score gauge",
  ];
  for (const s of series) {
    lines.push(`relay_sender_reputation_score{key="${esc(s.key)}"} ${s.score}`);
  }
  const withDowngrades = series.filter((s) => s.downgrades > 0);
  if (withDowngrades.length > 0) {
    lines.push(
      "# HELP relay_sender_reputation_degraded_total Cumulative reputation downgrade transitions by sender key (WR-119)."
    );
    lines.push("# TYPE relay_sender_reputation_degraded_total counter");
    for (const s of withDowngrades) {
      lines.push(`relay_sender_reputation_degraded_total{key="${esc(s.key)}"} ${s.downgrades}`);
    }
  }
  return lines.join("\n") + "\n";
}
