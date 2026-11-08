/**
 * Inbound auth-failure IP banning (WR-182): fail2ban for the webhook intake.
 *
 * A webhook relay's intake is a magnet for credential-stuffing botnets and
 * misconfigured senders alike: the same IP hammering the endpoint with bad
 * signatures, bad API keys, or flood traffic costs verifier CPU and intake
 * budget on every attempt, even when every attempt is rejected. The WR-53
 * IP ACL is the static answer (an operator-curated allow/denylist), and the
 * WR-22 rate limiter is the volumetric answer — fail2ban is the behavioral
 * answer: per-sender-IP consecutive auth-failure counting with automatic,
 * time-boxed bans.
 *
 * How it plugs into the intake (see `runIntakeGates` in `src/server.ts`):
 * - Ban check: immediately after the WR-53 IP ACL, before the body is
 *   read, before rate limiting, before signature verification — a banned
 *   IP costs zero bandwidth and zero CPU. A banned request is answered
 *   403 (`connection: close`) and audited as `ip_blocked`; it never
 *   enqueues, burns no retry budget, and never trips the breaker.
 * - Failure counting: each inbound 401 (API-key missing/invalid at the
 *   intake gate, signature verification failure in admission) and each
 *   inbound 429 (WR-22 / reputation-tightened / WR-141 tenant limiters)
 *   increments the sender IP's consecutive-failure counter. Operator-plane
 *   401s (mTLS / mesh gates), the WR-53/GeoIP policy 403s, and the
 *   WR-97 outbound-pacing 429 are deliberately NOT counted — they are
 *   different trust layers, and counting them would ban callers for
 *   being unauthenticated at a layer the ban cannot even enforce
 *   (the mTLS gate 401s before the intake gates ever run).
 * - Success reset: any accepted (202) inbound request zeroes the IP's
 *   counter immediately. A ban is per-IP state with its own expiry; the
 *   counter is separate — after a ban expires with no intervening
 *   success, one more failure re-bans at once (repeat-offender
 *   semantics), while a single success clears the slate.
 * - Static-allow exemption: an IP that hits a WR-53 static `allow` rule
 *   for the request's path is never banned for that path (exemption
 *   wins, checked both at ban time and at check time). The exemption is
 *   per (path, IP): an allow-listed partner that abuses a *different*,
 *   non-allow-listed path is still counted and can still be banned —
 *   the exemption only ever protects the path the allow rule covers.
 *
 * Memory is bounded: at most `maxEntries` IPs are tracked (failures and
 * bans alike). When the table is full, expired bans are swept first,
 * then the least-recently-active non-banned entry is evicted; a live ban
 * is never evicted to make room (evicting it would silently lift the
 * ban). The clock is injectable for deterministic tests.
 *
 * Off by default: the server only constructs a `Fail2Ban` when the
 * `fail2ban` option is set. Invalid config throws `RangeError` at
 * startup — fail fast, never mid-request.
 *
 * Zero dependencies. Only Node type-stripping-erasable syntax.
 */

/** Options for {@link Fail2Ban}. */
export interface Fail2BanOptions {
  /**
   * Consecutive inbound auth failures (401/403/429 on the webhook
   * intake plane) from one sender IP before the IP is banned. Must be
   * an integer >= 1 (`1` bans on the first failure — the operator's
   * choice for a zero-tolerance endpoint).
   */
  maxConsecutiveFailures: number;
  /**
   * How long a ban lasts, in milliseconds. Must be a finite number > 0.
   */
  banDurationMs: number;
  /**
   * Upper bound on tracked sender IPs (failure counters and bans
   * alike). Must be an integer >= 1. Default 10000. When the table is
   * full the least-recently-active entry is evicted (live bans are
   * protected — see the module doc).
   */
  maxEntries?: number;
  /** Clock in ms; defaults to `Date.now`. Injectable for deterministic tests. */
  now?: () => number;
  /**
   * Exemption hook: `(pathname, ip) => true` means the IP is statically
   * allow-listed for this path and must never be banned (the server
   * wires this to the WR-53 `InboundIpAcl` static-allow check).
   * Unset means nothing is exempt.
   */
  isExempt?: (pathname: string, ip: string) => boolean;
}

/** The default bound on tracked sender IPs when `maxEntries` is unset. */
export const DEFAULT_FAIL2BAN_MAX_ENTRIES = 10000;

/**
 * WR-357: a partial revision of the fail2ban thresholds
 * (`maxConsecutiveFailures` / `banDurationMs` / `maxEntries`, at
 * least one field set). Omitted fields keep their live values; an
 * empty patch is a `RangeError`. The merged values are judged against
 * the same gates as construction, so an illegal patch throws
 * `RangeError` and the live values are left completely untouched.
 */
export type Fail2BanRevision = Partial<
  Pick<Fail2BanOptions, "maxConsecutiveFailures" | "banDurationMs" | "maxEntries">
>;

/** WR-357: live fail2ban config — the three thresholds, after any revision. */
export interface Fail2BanConfig {
  maxConsecutiveFailures: number;
  banDurationMs: number;
  maxEntries: number;
}

/** One active ban, as exposed to operators (`GET /bans`). */
export interface BanInfo {
  /** The banned sender IP. */
  ip: string;
  /** When the ban started (epoch ms). */
  bannedAt: number;
  /** When the ban lifts (epoch ms). */
  expiresAt: number;
  /** Consecutive failures that armed the ban. */
  consecutiveFailures: number;
}

/** The outcome of recording one inbound auth failure. */
export interface FailureRecord {
  /** Whether the IP is banned after this failure. */
  banned: boolean;
  /** Whether this failure newly triggered the ban (ban activation). */
  justBanned: boolean;
  /** The IP's consecutive-failure count after this failure. */
  consecutiveFailures: number;
}

/** Fail with a RangeError naming the offending input. */
function invalid(where: string, detail: string): never {
  throw new RangeError(`fail2ban: ${where}: ${detail}`);
}

/**
 * Validate fail2ban options. Throws RangeError on a non-object, a
 * `maxConsecutiveFailures` that is not an integer >= 1, a
 * `banDurationMs` that is not finite and > 0, a `maxEntries` that is
 * not an integer >= 1, or a `now`/`isExempt` of the wrong type —
 * fail fast at startup, never mid-request.
 */
export function assertValidFail2BanOptions(opts: Fail2BanOptions): void {
  if (opts === undefined || opts === null || typeof opts !== "object") {
    throw new RangeError("fail2ban: expected an options object");
  }
  const { maxConsecutiveFailures, banDurationMs, maxEntries, now, isExempt } = opts;
  if (!Number.isInteger(maxConsecutiveFailures) || maxConsecutiveFailures < 1) {
    throw new RangeError(
      `fail2ban: maxConsecutiveFailures must be an integer >= 1, got ${String(maxConsecutiveFailures)}`
    );
  }
  if (typeof banDurationMs !== "number" || !Number.isFinite(banDurationMs) || banDurationMs <= 0) {
    throw new RangeError(
      `fail2ban: banDurationMs must be a finite number > 0, got ${String(banDurationMs)}`
    );
  }
  if (maxEntries !== undefined && (!Number.isInteger(maxEntries) || maxEntries < 1)) {
    throw new RangeError(
      `fail2ban: maxEntries must be an integer >= 1, got ${String(maxEntries)}`
    );
  }
  if (now !== undefined && typeof now !== "function") {
    throw new RangeError("fail2ban: now must be a () => number function");
  }
  if (isExempt !== undefined && typeof isExempt !== "function") {
    throw new RangeError("fail2ban: isExempt must be a (pathname, ip) => boolean function");
  }
}

interface TrackedIp {
  /** Consecutive inbound auth failures (reset by any success). */
  failures: number;
  /** Epoch ms the ban lifts; 0 means not banned. */
  bannedUntil: number;
  /**
   * WR-357: epoch ms the current ban started, stored at activation.
   * `bans()` used to derive this as `bannedUntil - banDurationMs`,
   * which drifted when `banDurationMs` was revised mid-ban — the
   * stored value keeps `GET /bans` stable across revisions. 0 means
   * never banned; kept across ban extensions, refreshed on re-ban.
   */
  bannedAt: number;
  /** Epoch ms of the last failure or success (eviction order). */
  lastSeen: number;
}

/**
 * Per-sender-IP consecutive auth-failure tracking with automatic
 * time-boxed bans. Construct once at server startup (invalid config
 * throws RangeError there); the per-request methods never throw on
 * hostile input — an unparseable IP is just another map key. The
 * three thresholds are live-revisable at runtime via `retune()`
 * (WR-357): `recordFailure` reads them live, so a revision takes
 * effect from the next failure assessment — already-counted failures
 * and already-armed bans are untouched (lowering the threshold never
 * retroactively bans, raising it never unbans, and an in-flight ban
 * keeps the expiry it was armed with).
 */
export class Fail2Ban {
  // WR-357: live-revisable via `retune()` (the constructor still
  // validates every value through the same gates), so these are
  // deliberately not `readonly`.
  private maxConsecutiveFailures: number;
  private banDurationMs: number;
  private maxEntries: number;
  private readonly now: () => number;
  private readonly isExempt: ((pathname: string, ip: string) => boolean) | undefined;
  private readonly entries = new Map<string, TrackedIp>();

  constructor(opts: Fail2BanOptions) {
    assertValidFail2BanOptions(opts);
    this.maxConsecutiveFailures = opts.maxConsecutiveFailures;
    this.banDurationMs = opts.banDurationMs;
    this.maxEntries = opts.maxEntries ?? DEFAULT_FAIL2BAN_MAX_ENTRIES;
    this.now = opts.now ?? Date.now;
    this.isExempt = opts.isExempt;
  }

  /**
   * WR-357: revise the live fail2ban thresholds (partial — omitted
   * fields keep their live values). Merge-then-validate reusing the
   * construction gates (`assertValidFail2BanOptions`): an illegal
   * patch throws `RangeError` and the live values are left completely
   * untouched, and an empty patch is a `RangeError`. A patch equal to
   * the live values is a silent no-op. A real revision updates the
   * three knobs in place: `recordFailure` reads them live, so the new
   * values govern the next failure assessment — already-counted
   * failures and already-armed bans are untouched (lowering the
   * threshold never retroactively bans, raising it never unbans, and
   * an in-flight ban keeps the expiry it was armed with). Shrinking
   * `maxEntries` trims the table at once, sweeping expired bans
   * first and then evicting the least-recently-active non-banned
   * entries — a live ban is never evicted to make room, so when the
   * table holds more live bans than the new bound the trim stops at
   * the live bans and the table temporarily exceeds the bound until
   * bans expire (the next admission re-applies the bound through
   * `evictIfNeeded`). Returns the live config after the revision.
   */
  retune(patch: Fail2BanRevision): Fail2BanConfig {
    if (patch === null || typeof patch !== "object" || Array.isArray(patch)) {
      throw new RangeError(`fail2ban revision must be an object, got ${JSON.stringify(patch)}`);
    }
    if (
      patch.maxConsecutiveFailures === undefined &&
      patch.banDurationMs === undefined &&
      patch.maxEntries === undefined
    ) {
      throw new RangeError(
        "fail2ban revision must set at least one of maxConsecutiveFailures, banDurationMs, maxEntries"
      );
    }
    const next: Fail2BanConfig = {
      maxConsecutiveFailures: patch.maxConsecutiveFailures ?? this.maxConsecutiveFailures,
      banDurationMs: patch.banDurationMs ?? this.banDurationMs,
      maxEntries: patch.maxEntries ?? this.maxEntries,
    };
    // Validate-then-apply: the merged values must pass the
    // construction gates before any live value moves. `now` /
    // `isExempt` are carried over untouched — a revision never
    // rebinds the clock or the exemption hook.
    assertValidFail2BanOptions({ ...next, now: this.now, isExempt: this.isExempt });
    if (
      next.maxConsecutiveFailures === this.maxConsecutiveFailures &&
      next.banDurationMs === this.banDurationMs &&
      next.maxEntries === this.maxEntries
    ) {
      return this.snapshot();
    }
    const maxEntriesShrank = next.maxEntries < this.maxEntries;
    this.maxConsecutiveFailures = next.maxConsecutiveFailures;
    this.banDurationMs = next.banDurationMs;
    this.maxEntries = next.maxEntries;
    if (maxEntriesShrank) this.trimToMaxEntries(this.now());
    return this.snapshot();
  }

  /** WR-357: live fail2ban config snapshot (the three thresholds). */
  snapshot(): Fail2BanConfig {
    return {
      maxConsecutiveFailures: this.maxConsecutiveFailures,
      banDurationMs: this.banDurationMs,
      maxEntries: this.maxEntries,
    };
  }

  /** Number of IPs currently tracked (counters and bans alike). */
  get size(): number {
    return this.entries.size;
  }

  /**
   * Whether `ip` is currently banned for `pathname`. A statically
   * allow-listed (exempt) IP is never reported banned — the WR-53
   * exemption wins even when a ban record exists (e.g. armed via a
   * different, non-exempt path). Never throws.
   */
  isBanned(pathname: string, ip: string): boolean {
    if (this.isExempt?.(pathname, ip) === true) return false;
    const e = this.entries.get(ip);
    return e !== undefined && e.bannedUntil > this.now();
  }

  /**
   * Record one inbound auth failure (401/403/429 on the webhook intake
   * plane) for `ip` on `pathname`. When the consecutive count reaches
   * `maxConsecutiveFailures` and the IP is not exempt for this path,
   * the IP is banned for `banDurationMs` (`justBanned` is true only on
   * the failure that newly triggers the ban — an already-banned IP's
   * ban is extended, not re-audited). Exempt-path failures still count
   * (the counter is per-IP) but can never arm the ban. Never throws.
   */
  recordFailure(pathname: string, ip: string): FailureRecord {
    const now = this.now();
    let e = this.entries.get(ip);
    if (e === undefined) {
      this.evictIfNeeded(now);
      e = { failures: 0, bannedUntil: 0, bannedAt: 0, lastSeen: now };
      this.entries.set(ip, e);
    }
    e.failures += 1;
    e.lastSeen = now;
    let justBanned = false;
    if (
      e.failures >= this.maxConsecutiveFailures &&
      this.isExempt?.(pathname, ip) !== true
    ) {
      justBanned = e.bannedUntil <= now;
      // WR-357: only a fresh activation (re-)stamps the start — an
      // extension keeps the original bannedAt, so `bans()` never
      // drifts when `banDurationMs` is revised mid-ban.
      if (justBanned) e.bannedAt = now;
      e.bannedUntil = now + this.banDurationMs;
    }
    return { banned: e.bannedUntil > now, justBanned, consecutiveFailures: e.failures };
  }

  /**
   * Record one successful (2xx) inbound request for `ip`: the
   * consecutive-failure counter is zeroed immediately. Ban state is
   * untouched — a success never shortens a ban, it only clears the
   * repeat-offender memory so the next failure starts counting from
   * zero. (A banned IP cannot reach this except through an exempt
   * path, which bypasses the ban check.) Never throws.
   */
  recordSuccess(ip: string): void {
    const e = this.entries.get(ip);
    if (e === undefined) return;
    const now = this.now();
    if (e.bannedUntil > now) {
      // Live ban: keep the ban, zero the counter.
      e.failures = 0;
      e.lastSeen = now;
      return;
    }
    // Not banned: a zeroed counter carries no information — drop the
    // entry so idle IPs do not pin memory.
    this.entries.delete(ip);
  }

  /**
   * Lift `ip`'s ban early (the operator `POST /bans/:ip/unban` plane).
   * The failure counter is reset too — an operator unban is an explicit
   * judgment that the ban was wrong or the sender fixed itself, so the
   * IP starts from a clean slate. Returns true when a live ban was
   * lifted, false when the IP was not banned. Never throws.
   */
  unban(ip: string): boolean {
    const e = this.entries.get(ip);
    if (e === undefined || e.bannedUntil <= this.now()) return false;
    this.entries.delete(ip);
    return true;
  }

  /**
   * All currently active bans, oldest first (the operator `GET /bans`
   * plane). Never throws.
   */
  bans(): BanInfo[] {
    const now = this.now();
    const out: BanInfo[] = [];
    for (const [ip, e] of this.entries) {
      if (e.bannedUntil > now) {
        out.push({
          ip,
          // WR-357: stored at activation, never derived from the live
          // `banDurationMs` — a duration revision mid-ban leaves both
          // timestamps exactly as armed.
          bannedAt: e.bannedAt,
          expiresAt: e.bannedUntil,
          consecutiveFailures: e.failures,
        });
      }
    }
    out.sort((a, b) => a.bannedAt - b.bannedAt);
    return out;
  }

  /**
   * WR-357: trim the table down to the live `maxEntries` bound after
   * a shrink — the `evictIfNeeded` victim order (expired bans swept
   * first, then least-recently-active non-banned entries), except a
   * live ban is never evicted to make room: when every remaining
   * entry is a live ban the trim stops and the table temporarily
   * exceeds the bound (there is no new entry to admit here, unlike
   * `evictIfNeeded`'s soonest-expiring fallback).
   */
  private trimToMaxEntries(now: number): void {
    for (const [ip, e] of this.entries) {
      if (e.bannedUntil !== 0 && e.bannedUntil <= now) this.entries.delete(ip);
    }
    while (this.entries.size > this.maxEntries) {
      let victim: string | undefined;
      let victimScore = Infinity;
      for (const [ip, e] of this.entries) {
        if (e.bannedUntil > now) continue; // live ban: protected
        if (e.lastSeen < victimScore) {
          victim = ip;
          victimScore = e.lastSeen;
        }
      }
      if (victim === undefined) return; // only live bans remain
      this.entries.delete(victim);
    }
  }

  /**
   * Make room for one more tracked IP. Expired bans are swept first
   * (dead weight, not protection); then the least-recently-active
   * non-banned entry is evicted. A live ban is never evicted to make
   * room — evicting it would silently lift the ban. Only when every
   * entry is a live ban does the one expiring soonest give way.
   */
  private evictIfNeeded(now: number): void {
    if (this.entries.size < this.maxEntries) return;
    for (const [ip, e] of this.entries) {
      if (e.bannedUntil !== 0 && e.bannedUntil <= now) this.entries.delete(ip);
    }
    while (this.entries.size >= this.maxEntries) {
      let victim: string | undefined;
      let victimScore = Infinity;
      for (const [ip, e] of this.entries) {
        if (e.bannedUntil > now) continue; // live ban: protected
        if (e.lastSeen < victimScore) {
          victim = ip;
          victimScore = e.lastSeen;
        }
      }
      if (victim === undefined) {
        // Every entry is a live ban: evict the one expiring soonest.
        for (const [ip, e] of this.entries) {
          if (e.bannedUntil < victimScore) {
            victim = ip;
            victimScore = e.bannedUntil;
          }
        }
      }
      if (victim === undefined) return; // unreachable: size >= maxEntries >= 1
      this.entries.delete(victim);
    }
  }
}

/**
 * Fail2ban counters. Renders to Prometheus exposition text; renders
 * `""` when nothing was ever banned, keeping `GET /metrics`
 * byte-identical for relays that never enable fail2ban.
 */
export class Fail2BanMetrics {
  private blockedByEndpoint = new Map<string, number>();
  private banActivations = 0;

  /** Record one inbound request rejected 403 because its IP is banned. */
  recordBlocked(endpoint: string): void {
    this.blockedByEndpoint.set(endpoint, (this.blockedByEndpoint.get(endpoint) ?? 0) + 1);
  }

  /** Record one ban activation (the failure that newly triggered a ban). */
  recordBan(): void {
    this.banActivations += 1;
  }

  /** Prometheus text exposition (0.0.4) of the counters; `""` when empty. */
  render(): string {
    if (this.blockedByEndpoint.size === 0 && this.banActivations === 0) return "";
    const esc = (v: string): string =>
      v.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, '\\"');
    const lines: string[] = [
      "# HELP relay_inbound_ip_banned_total Inbound webhook requests rejected because the sender IP is fail2ban-banned, by endpoint path.",
      "# TYPE relay_inbound_ip_banned_total counter",
    ];
    for (const [endpoint, n] of this.blockedByEndpoint) {
      lines.push(`relay_inbound_ip_banned_total{endpoint="${esc(endpoint)}"} ${n}`);
    }
    lines.push(
      "# HELP relay_inbound_ip_ban_activations_total Sender-IP bans activated by consecutive inbound auth failures."
    );
    lines.push("# TYPE relay_inbound_ip_ban_activations_total counter");
    lines.push(`relay_inbound_ip_ban_activations_total ${this.banActivations}`);
    return lines.join("\n") + "\n";
  }
}
