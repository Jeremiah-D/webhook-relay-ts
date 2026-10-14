/**
 * Dead-letter storm escalation alerts (WR-93).
 *
 * Not to be confused with the delivery completion callbacks
 * (`src/callback.ts`, WR-47): those are *per-delivery* receipts — one
 * signed POST per terminal delivery (`delivered` / `dead_letter`) to the
 * *caller's* URL. This module is *aggregate* storm telemetry: when dead
 * letters for one (tenant, endpoint) pile up inside a sliding window, the
 * relay POSTs one signed alert to the *operator's* URL. The operator
 * learns "endpoint X is dying faster than usual" without reading every
 * per-delivery receipt or tailing the dead-letter list.
 *
 * Edge-triggered with a cooldown, so one storm produces one alert:
 *
 * - a scope's dead-letter count inside `windowMs` reaches `threshold` →
 *   one alert is dispatched and the scope is marked `alerted`;
 * - while `alerted`, further dead letters do not re-alert (edge, not
 *   level);
 * - the scope returns to quiet when the operator acknowledges
 *   (`acknowledge`) or when the sliding-window count falls back below
 *   `threshold` (auto-reset) — either rearms the next episode;
 * - `cooldownMs` is the anti-flap guard between *episodes*: an episode
 *   that starts inside the cooldown of the previous alert stays silent.
 *
 * The alert body is a signed JSON document POSTed to the operator URL
 * (WR-26 signing style: `x-relay-signature: sha256=<hex>` HMAC-SHA256 of
 * the raw body, `x-relay-key-id` when `keyId` is set), so the operator
 * side can verify the alert really came from this relay with
 * {@link HmacSha256Verifier}.
 *
 * State transitions are reported through hooks — the server audits them
 * as `dead_letter_escalated` (alert dispatched) and
 * `dead_letter_escalation_failed` (the alert POST gave up). A failing
 * alert never enters the retry queue or the dead-letter list: alert
 * delivery must not recurse into the delivery machinery it observes.
 *
 * Loop protection: an operator URL that resolves to this relay's own
 * inbound listener would re-enter intake on every storm and amplify it.
 * The target is checked at configuration time against declared
 * `selfOrigins`, and the server installs a runtime check derived from the
 * actually bound address via {@link setSelfCheck}.
 */

import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { tenantScopeKey, splitTenantScopeKey } from "./tenant.ts";
import { signSha256, HmacSha256Verifier } from "./verify.ts";

/** Re-exported so operator-side verifiers can import from one place. */
export { HmacSha256Verifier };

/** Default sliding-window length for storm detection: 10 minutes. */
export const DEFAULT_ESCALATION_WINDOW_MS = 600_000;
/** Default dead-letter count inside the window that fires an alert. */
export const DEFAULT_ESCALATION_THRESHOLD = 20;
/** Default quiet period between alerts for the same scope: 1 hour. */
export const DEFAULT_ESCALATION_COOLDOWN_MS = 3_600_000;
/** Default alert POST attempts per escalation (capped at 3). */
export const DEFAULT_ESCALATION_MAX_ATTEMPTS = 2;
/** Default backoff between alert POST retries (`backoffMs * attempt`). */
export const DEFAULT_ESCALATION_BACKOFF_MS = 1000;
/** Default per-attempt socket timeout for the alert POST. */
export const DEFAULT_ESCALATION_TIMEOUT_MS = 5000;

/**
 * The JSON body POSTed to the operator URL when a scope's dead-letter
 * count inside the sliding window reaches the threshold.
 */
export interface DeadLetterEscalationAlert {
  /** Discriminator, so the operator side can route on event name. */
  event: "dead_letter_escalation";
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  /** Downstream endpoint whose dead letters piled up. */
  endpoint: string;
  /** Dead letters counted inside the window at trigger time. */
  deadLetters: number;
  /** The configured threshold that was crossed. */
  threshold: number;
  /** The configured sliding-window length in ms. */
  windowMs: number;
  /** ISO-8601 timestamp when the alert was dispatched. */
  alertedAt: string;
}

/** Info passed to the escalation hook when an alert is dispatched. */
export interface DeadLetterEscalatedInfo extends DeadLetterEscalationAlert {}

/** Info passed to the failure hook when an alert POST exhausts its attempts. */
export interface DeadLetterEscalationFailedInfo {
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  endpoint: string;
  /** Alert POST attempts made. */
  attempts: number;
  error: string;
}

/** Transport result for one alert POST attempt. */
export interface EscalationPostResult {
  statusCode: number;
}

/**
 * Minimal alert transport: POST bytes, report the status. The default
 * implementation uses `node:http`/`node:https` directly with a timeout;
 * tests inject a stub.
 */
export type EscalationPostFn = (
  url: string,
  body: Buffer,
  headers: Record<string, string>
) => Promise<EscalationPostResult>;

/** Operator-facing options for dead-letter storm escalation. */
export interface DeadLetterEscalationOptions {
  /**
   * The operator's alert endpoint. Required; must be `http:` or `https:`.
   * A URL whose origin matches this relay's own inbound origin is
   * rejected — the alert would re-enter intake and amplify the storm it
   * reports.
   */
  url: string;
  /**
   * Origins (`scheme://host:port`) of this relay's own inbound listener,
   * for the configuration-time loop check. The runtime check installed
   * by the server (from the actual bound address) runs before every POST
   * regardless; declaring them here additionally fails fast at startup.
   */
  selfOrigins?: string[];
  /**
   * HMAC-SHA256 secret for the `x-relay-signature` alert header
   * (WR-26 style). Required and non-empty: an unsigned operator alert
   * is a misconfiguration — the operator side must be able to verify
   * the alert really came from this relay. Keep it out of logs.
   */
  signingSecret: string;
  /** Stable key identifier surfaced in `x-relay-key-id`. Optional. */
  keyId?: string;
  /**
   * Sliding-window length in ms over which dead letters are counted per
   * (tenant, endpoint). Default 600_000 (10 minutes). Must be > 0.
   */
  windowMs?: number;
  /**
   * Dead-letter count inside the window that fires one alert for the
   * scope. Default 20. Must be a positive integer.
   */
  threshold?: number;
  /**
   * Quiet period in ms between alerts for the same scope: an episode
   * that starts inside the cooldown of the previous alert stays silent.
   * Default 3_600_000 (1 hour). Must be >= 0.
   */
  cooldownMs?: number;
  /**
   * Alert POST attempts per escalation, including the first. Default 2,
   * capped at 3 — an alert that will not land in a few tries is
   * reported via `onFailed`, not chased. A failing alert never enters
   * the retry queue or the dead-letter list.
   */
  maxAttempts?: number;
  /** Backoff between alert retries in ms (`backoffMs * attempt`). Default 1000. */
  backoffMs?: number;
  /** Per-attempt socket timeout in ms. Default 5000. */
  timeoutMs?: number;
  /** Injectable transport for tests; defaults to a real HTTP(S) POST. */
  post?: EscalationPostFn;
  /** Injectable clock for tests; defaults to `Date.now`. */
  now?: () => number;
  /** Injectable timers for tests. */
  setTimer?: (fn: () => void, ms: number) => { clear(): void };
  /** Injectable timers for tests. */
  clearTimer?: (handle: { clear(): void }) => void;
}

/** Validated, ready-to-use dead-letter escalation configuration. */
export interface ResolvedDeadLetterEscalationConfig {
  url: string;
  signingSecret: string;
  keyId?: string;
  windowMs: number;
  threshold: number;
  cooldownMs: number;
  maxAttempts: number;
  backoffMs: number;
  timeoutMs: number;
  post: EscalationPostFn;
  now: () => number;
  setTimer: (fn: () => void, ms: number) => { clear(): void };
  clearTimer: (handle: { clear(): void }) => void;
}

function originOf(raw: string): string {
  return new URL(raw).origin;
}

/**
 * True when `url` targets one of `selfOrigins` (origin comparison:
 * scheme + host + port). Same rule as the WR-47 completion callbacks —
 * a storm alert POSTed back into this relay's own intake would re-enter
 * the delivery machinery and amplify the storm it reports.
 */
export function isSelfEscalationTarget(url: string, selfOrigins: string[]): boolean {
  let origin: string;
  try {
    origin = originOf(url);
  } catch {
    return false;
  }
  return selfOrigins.some((s) => {
    try {
      return originOf(s) === origin;
    } catch {
      return false;
    }
  });
}

/**
 * Validate `DeadLetterEscalationOptions` at startup. Returns `undefined`
 * when the feature is off (`opts` unset) — the default — so callers can
 * branch on "configured" with a single check. Throws `RangeError` on
 * invalid values; never mid-delivery.
 */
export function resolveDeadLetterEscalationConfig(
  opts?: DeadLetterEscalationOptions
): ResolvedDeadLetterEscalationConfig | undefined {
  if (opts === undefined) return undefined;
  if (typeof opts.url !== "string" || opts.url === "") {
    throw new RangeError("escalation: `url` must be a non-empty string");
  }
  let parsed: URL;
  try {
    parsed = new URL(opts.url);
  } catch {
    throw new RangeError(`escalation: \`url\` is not a valid URL: ${opts.url}`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new RangeError(`escalation: \`url\` must be http(s), got ${parsed.protocol}//`);
  }
  if (opts.selfOrigins !== undefined) {
    if (!Array.isArray(opts.selfOrigins) || opts.selfOrigins.some((s) => typeof s !== "string")) {
      throw new RangeError("escalation: `selfOrigins` must be an array of strings");
    }
    if (isSelfEscalationTarget(opts.url, opts.selfOrigins)) {
      throw new RangeError(
        "escalation: `url` targets this relay's own inbound origin — the alert would re-enter intake and amplify the storm it reports"
      );
    }
  }
  if (typeof opts.signingSecret !== "string" || opts.signingSecret === "") {
    throw new RangeError("escalation: `signingSecret` is required and must be non-empty");
  }
  if (opts.keyId !== undefined && opts.keyId === "") {
    throw new RangeError("escalation: `keyId` must be non-empty when set");
  }
  const windowMs = opts.windowMs ?? DEFAULT_ESCALATION_WINDOW_MS;
  if (!Number.isFinite(windowMs) || windowMs <= 0) {
    throw new RangeError(`escalation: \`windowMs\` must be > 0, got ${opts.windowMs}`);
  }
  const threshold = opts.threshold ?? DEFAULT_ESCALATION_THRESHOLD;
  if (!Number.isInteger(threshold) || threshold < 1) {
    throw new RangeError(`escalation: \`threshold\` must be a positive integer, got ${opts.threshold}`);
  }
  const cooldownMs = opts.cooldownMs ?? DEFAULT_ESCALATION_COOLDOWN_MS;
  if (!Number.isFinite(cooldownMs) || cooldownMs < 0) {
    throw new RangeError(`escalation: \`cooldownMs\` must be >= 0, got ${opts.cooldownMs}`);
  }
  const maxAttempts = opts.maxAttempts ?? DEFAULT_ESCALATION_MAX_ATTEMPTS;
  if (!Number.isInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 3) {
    throw new RangeError(
      `escalation: \`maxAttempts\` must be an integer in [1, 3], got ${opts.maxAttempts}`
    );
  }
  const backoffMs = opts.backoffMs ?? DEFAULT_ESCALATION_BACKOFF_MS;
  if (!Number.isFinite(backoffMs) || backoffMs < 0) {
    throw new RangeError(`escalation: \`backoffMs\` must be >= 0, got ${opts.backoffMs}`);
  }
  const timeoutMs = opts.timeoutMs ?? DEFAULT_ESCALATION_TIMEOUT_MS;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new RangeError(`escalation: \`timeoutMs\` must be > 0, got ${opts.timeoutMs}`);
  }
  if (opts.post !== undefined && typeof opts.post !== "function") {
    throw new TypeError("escalation: `post` must be a function when set");
  }
  return {
    url: opts.url,
    signingSecret: opts.signingSecret,
    keyId: opts.keyId,
    windowMs,
    threshold,
    cooldownMs,
    maxAttempts,
    backoffMs,
    timeoutMs,
    // The default transport gets the configured socket timeout; a custom
    // `post` is trusted to enforce its own.
    post: opts.post ?? ((url, body, headers) => defaultEscalationPost(url, body, headers, timeoutMs)),
    now: opts.now ?? Date.now,
    setTimer:
      opts.setTimer ??
      ((fn, ms) => {
        const t = setTimeout(fn, ms);
        return { clear: () => clearTimeout(t) };
      }),
    clearTimer: opts.clearTimer ?? ((h) => h.clear()),
  };
}

/** Default alert transport: one HTTP(S) POST with a socket timeout. */
export function defaultEscalationPost(
  url: string,
  body: Buffer,
  headers: Record<string, string>,
  timeoutMs = DEFAULT_ESCALATION_TIMEOUT_MS
): Promise<EscalationPostResult> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = (u.protocol === "https:" ? httpsRequest : httpRequest)(
      {
        method: "POST",
        hostname: u.hostname,
        port: u.port === "" ? undefined : Number(u.port),
        path: `${u.pathname}${u.search}`,
        headers: { ...headers, "content-length": String(body.length) },
        // Fail fast instead of hanging a shutdown on a dead operator.
        timeout: timeoutMs,
      },
      (res) => {
        res.resume();
        res.on("end", () => resolve({ statusCode: res.statusCode ?? 0 }));
      }
    );
    req.on("timeout", () => {
      req.destroy(new Error(`dead-letter escalation timed out after ${timeoutMs}ms`));
    });
    req.on("error", reject);
    req.end(body);
  });
}

export interface DeadLetterEscalatorHooks {
  /** Called once when an alert is dispatched for a scope (audited as `dead_letter_escalated`). */
  onEscalated: (info: DeadLetterEscalatedInfo) => void;
  /** Called once when an alert exhausts its POST attempts (audited as `dead_letter_escalation_failed`). */
  onFailed: (info: DeadLetterEscalationFailedInfo) => void;
}

/** Per-scope observation row (see {@link DeadLetterStormEscalator.stats}). All JSON-serializable. */
export interface DeadLetterEscalationStatsRow {
  /** Downstream endpoint this scope watches. */
  endpoint: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  /** Dead letters currently inside the sliding window. */
  windowDeadLetters: number;
  /** The configured threshold that fires an alert. */
  threshold: number;
  /** True while the scope is in the alerted edge state (quiet until reset). */
  alerted: boolean;
  /** ISO-8601 timestamp of the last dispatched alert; absent when never. */
  lastAlertAt?: string;
  /**
   * Cumulative escalation episodes triggered for this scope (the
   * Prometheus counter's source). An alert refused by the loop check
   * still consumes the edge and is counted here — the refusal is
   * reported through `onFailed`, never hidden.
   */
  escalations: number;
}

interface ScopeState {
  /** Dead-letter timestamps inside the window, ascending. */
  timestamps: number[];
  /** Edge state: an alert fired for the current episode. */
  alerted: boolean;
  /** Epoch ms of the last dispatched alert; the cooldown anchor. */
  lastAlertAt?: number;
  /** Cumulative dispatched alerts. */
  escalations: number;
}

/**
 * Dead-letter storm escalator: one instance per relay (or per queue),
 * watching per-(tenant, endpoint) scopes — keyed with
 * {@link tenantScopeKey}, so the default tenant keys plain endpoints
 * exactly like the pre-tenant relay.
 *
 * Feed it from the queue's dead-letter landing point via
 * {@link recordDeadLetter}; the server exposes manual acknowledgement
 * through the queue's `acknowledgeDeadLetterEscalation`.
 */
export class DeadLetterStormEscalator {
  private readonly config: ResolvedDeadLetterEscalationConfig;
  private readonly hooks: DeadLetterEscalatorHooks;
  private readonly scopes = new Map<string, ScopeState>();
  private selfCheck?: (url: string) => boolean;
  private readonly timers = new Set<{ clear(): void }>();
  private stopped = false;

  constructor(config: ResolvedDeadLetterEscalationConfig, hooks: DeadLetterEscalatorHooks) {
    this.config = config;
    this.hooks = hooks;
  }

  /**
   * Install (or replace) the runtime loop check. The server derives it
   * from the actually bound address, so an operator URL that resolves to
   * this relay — even one that was not declared in `selfOrigins` — is
   * refused before every POST.
   */
  setSelfCheck(fn: (url: string) => boolean): void {
    this.selfCheck = fn;
  }

  /** Stop retrying in-flight alerts; pending timers are cancelled. */
  stop(): void {
    this.stopped = true;
    for (const t of this.timers) t.clear();
    this.timers.clear();
  }

  /**
   * Record one dead letter for a scope and evaluate the storm rule.
   * Edge-triggered: the first crossing of `threshold` inside the window
   * dispatches exactly one alert; later dead letters in the same
   * episode are silent until a reset (manual `acknowledge` or the
   * window count falling below `threshold`) rearms the scope. An
   * episode that starts inside `cooldownMs` of the previous alert is
   * suppressed instead of dispatched.
   */
  recordDeadLetter(info: { tenant?: string; endpoint: string }): void {
    if (this.stopped) return;
    const key = tenantScopeKey(info.tenant, info.endpoint);
    let scope = this.scopes.get(key);
    if (scope === undefined) {
      scope = { timestamps: [], alerted: false, escalations: 0 };
      this.scopes.set(key, scope);
    }
    const now = this.config.now();
    const floor = now - this.config.windowMs;
    // Prune expired timestamps (ascending, so drop the stale head), then
    // append — the count below is always the in-window count.
    while (scope.timestamps.length > 0 && scope.timestamps[0] <= floor) {
      scope.timestamps.shift();
    }
    scope.timestamps.push(now);
    const count = scope.timestamps.length;
    if (count >= this.config.threshold) {
      if (scope.alerted) return; // Same episode: edge already fired.
      if (
        scope.lastAlertAt !== undefined &&
        now - scope.lastAlertAt < this.config.cooldownMs
      ) {
        return; // Previous episode still in cooldown: stay silent.
      }
      this.dispatch(info.tenant, info.endpoint, scope, count, now);
    } else if (scope.alerted) {
      // The window drained below the threshold on its own — the storm
      // is over, rearm for the next episode.
      scope.alerted = false;
    }
  }

  /**
   * Manually acknowledge a scope's storm: the scope returns to quiet and
   * the next threshold crossing dispatches a fresh alert (subject to the
   * cooldown). No-op for unknown scopes. The acknowledgement itself is
   * not an escalation — this method only rearms the edge; callers audit
   * it as their own event if they want one.
   */
  acknowledge(tenant: string | undefined, endpoint: string): void {
    const scope = this.scopes.get(tenantScopeKey(tenant, endpoint));
    if (scope !== undefined) {
      scope.alerted = false;
    }
  }

  /**
   * Per-scope observation snapshot. Scopes appear once they have seen at
   * least one dead letter; `windowDeadLetters` is pruned to the current
   * window at read time. Rows carry `tenant` only when set.
   */
  stats(): DeadLetterEscalationStatsRow[] {
    const now = this.config.now();
    const floor = now - this.config.windowMs;
    const out: DeadLetterEscalationStatsRow[] = [];
    for (const [key, scope] of this.scopes) {
      while (scope.timestamps.length > 0 && scope.timestamps[0] <= floor) {
        scope.timestamps.shift();
      }
      const { tenant, endpoint } = splitTenantScopeKey(key);
      out.push({
        endpoint,
        ...(tenant === undefined ? {} : { tenant }),
        windowDeadLetters: scope.timestamps.length,
        threshold: this.config.threshold,
        alerted: scope.alerted,
        ...(scope.lastAlertAt === undefined
          ? {}
          : { lastAlertAt: new Date(scope.lastAlertAt).toISOString() }),
        escalations: scope.escalations,
      });
    }
    return out;
  }

  private dispatch(
    tenant: string | undefined,
    endpoint: string,
    scope: ScopeState,
    count: number,
    now: number
  ): void {
    scope.alerted = true;
    scope.lastAlertAt = now;
    scope.escalations += 1;
    const alert: DeadLetterEscalationAlert = {
      event: "dead_letter_escalation",
      ...(tenant === undefined ? {} : { tenant }),
      endpoint,
      deadLetters: count,
      threshold: this.config.threshold,
      windowMs: this.config.windowMs,
      alertedAt: new Date(now).toISOString(),
    };
    // Runtime loop check (the configuration-time check ran at startup):
    // refuse to POST a storm alert back into this relay's own intake.
    if (this.selfCheck?.(this.config.url)) {
      this.hooks.onFailed({
        ...(tenant === undefined ? {} : { tenant }),
        endpoint,
        attempts: 0,
        error: "escalation target is this relay's own inbound origin (loop detected)",
      });
      return;
    }
    void this.attempt(alert, tenant, endpoint, 1);
  }

  private async attempt(
    alert: DeadLetterEscalationAlert,
    tenant: string | undefined,
    endpoint: string,
    attempt: number
  ): Promise<void> {
    if (this.stopped) return;
    const body = Buffer.from(JSON.stringify(alert), "utf8");
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "x-relay-signature": signSha256(body, this.config.signingSecret),
    };
    if (this.config.keyId !== undefined) {
      headers["x-relay-key-id"] = this.config.keyId;
    }
    let failure: string | undefined;
    try {
      const result = await this.raceTimeout(this.config.post(this.config.url, body, headers));
      if (result.statusCode < 200 || result.statusCode >= 300) {
        failure = `unexpected status ${result.statusCode}`;
      }
    } catch (err) {
      failure = err instanceof Error ? err.message : String(err);
    }
    if (failure === undefined) {
      this.hooks.onEscalated({ ...alert });
      return;
    }
    if (attempt < this.config.maxAttempts && !this.stopped) {
      const waitMs = this.config.backoffMs * attempt;
      const timer = this.config.setTimer(() => {
        this.timers.delete(timer);
        void this.attempt(alert, tenant, endpoint, attempt + 1);
      }, waitMs);
      this.timers.add(timer);
      return;
    }
    this.hooks.onFailed({
      ...(tenant === undefined ? {} : { tenant }),
      endpoint,
      attempts: attempt,
      error: failure,
    });
  }

  /** The transport gets its own timeout even when a custom `post` hangs. */
  private raceTimeout(p: Promise<EscalationPostResult>): Promise<EscalationPostResult> {
    const timeoutMs = this.config.timeoutMs;
    return new Promise((resolve, reject) => {
      const timer = this.config.setTimer(
        () => reject(new Error(`dead-letter escalation timed out after ${timeoutMs}ms`)),
        timeoutMs
      );
      this.timers.add(timer);
      p.then(
        (r) => {
          this.timers.delete(timer);
          timer.clear();
          resolve(r);
        },
        (e) => {
          this.timers.delete(timer);
          timer.clear();
          reject(e);
        }
      );
    });
  }
}
