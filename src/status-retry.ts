/**
 * WR-178: per-status retry policies.
 *
 * Downstream error semantics are not uniform: a `429` from a
 * rate-limited payment provider wants a patient, slow schedule; a
 * `503` from a flapping edge cache wants a quick, short one. The
 * queue-global backoff (WR-02) and even named retry policies (WR-172)
 * are endpoint-granular but status-blind — every failure on the
 * endpoint shares one schedule. A per-status policy lets an operator
 * tune the backoff and the attempt budget *by the status code the
 * downstream actually answered with*, per endpoint.
 *
 * A policy is a plain object keyed by status selector:
 *
 * ```ts
 * {
 *   "429":  { baseDelayMs: 5_000, maxAttempts: 12 },          // exact status code
 *   "5xx":  { baseDelayMs: 500,  maxAttempts: 6, multiplier: 3 }, // status class
 * }
 * ```
 *
 * Match order for a failure's status code: exact code (`"429"`) beats
 * class (`"4xx"`); when neither matches, the delivery falls back to
 * the endpoint's normal schedule — the WR-172 named policy when one is
 * assigned, else the WR-02 global backoff (base/cap/jitter untouched).
 *
 * The matched entry governs two things only:
 *
 * - `baseDelayMs` / `multiplier` — the retry delay for that status is
 *   `baseDelayMs * multiplier^attempt` (attempt = the 0-based index of
 *   the just-failed attempt, the same convention as the global
 *   `delayForAttempt`). `multiplier` defaults to 2. There is no jitter
 *   on this schedule: it is operator-authored, deterministic, and
 *   short.
 * - `maxAttempts` — the attempt budget for deliveries whose *current*
 *   failure matched this status. A `Retry-After` (429/503, WR-30) is
 *   never ignored: when a status schedule matches, the effective delay
 *   is `max(policy delay, retryAfterMs)` — the downstream's explicit
 *   backpressure request always wins.
 *
 * What the policy never touches (deliberately):
 *
 * - failure classification (`classifyFailure` in `src/failure.ts`).
 *   A `4xx` other than `408`/`429` is `"non_retryable"` (WR-30): the
 *   item is dead-lettered on the first attempt, before any policy
 *   lookup. A `"4xx"`/`"400"` policy entry is therefore inert — it can
 *   restate but never soften the instant dead-letter.
 * - attempt accounting. Each failed attempt consumes exactly one
 *   attempt; the WR-38 retry budget and the WR-10 circuit breaker see
 *   the same events they always did — the policy only reschedules,
 *   never mints or forgives attempts.
 *
 * Zero dependencies (`node:` only where a caller's clock is needed —
 * which is nowhere here; the module is pure).
 */

/** One status selector's schedule within a per-status retry policy. */
export interface StatusRetryPolicyEntry {
  /**
   * Base delay in ms for the exponential schedule
   * (`baseDelayMs * multiplier^attempt`). Must be a finite number > 0.
   */
  baseDelayMs: number;
  /**
   * Attempt budget for deliveries failing with the matched status.
   * Must be an integer >= 1.
   */
  maxAttempts: number;
  /**
   * Per-attempt growth factor. Optional; defaults to 2 (the WR-02
   * house convention). Must be a finite number > 0 when set.
   */
  multiplier?: number;
}

/**
 * A per-status retry policy: status selector → schedule. Selectors are
 * exact status codes (`"429"`, `"503"`) or status classes (`"2xx"`,
 * `"3xx"`, `"4xx"`, `"5xx"`). Exact beats class at match time.
 */
export type StatusRetryPolicyConfig = Record<string, StatusRetryPolicyEntry>;

/** The status classes a policy may key on. */
const STATUS_CLASSES = new Set(["2xx", "3xx", "4xx", "5xx"]);

/** Default growth factor when an entry omits `multiplier`. */
export const DEFAULT_STATUS_RETRY_MULTIPLIER = 2;

function isFinitePositive(n: unknown): n is number {
  return typeof n === "number" && Number.isFinite(n) && n > 0;
}

/** Whether `key` is a legal status selector: exact code or class. */
export function isValidStatusSelector(key: unknown): boolean {
  if (typeof key !== "string") return false;
  if (STATUS_CLASSES.has(key)) return true;
  if (/^\d{3}$/.test(key)) {
    const code = Number(key);
    return code >= 100 && code <= 599;
  }
  return false;
}

/**
 * Validate a per-status retry policy. Throws `RangeError` on the first
 * illegal value — at configuration time, never mid-delivery. The config
 * is never mutated.
 */
export function assertValidStatusRetryPolicy(config: unknown): void {
  if (typeof config !== "object" || config === null || Array.isArray(config)) {
    throw new RangeError("statusRetryPolicy: config must be an object mapping status selectors to schedules");
  }
  for (const [key, entry] of Object.entries(config)) {
    const where = `statusRetryPolicy[${JSON.stringify(key)}]`;
    if (!isValidStatusSelector(key)) {
      throw new RangeError(
        `${where}: key must be an exact 3-digit status code (100-599) or one of "2xx", "3xx", "4xx", "5xx", got ${JSON.stringify(key)}`
      );
    }
    if (typeof entry !== "object" || entry === null || Array.isArray(entry)) {
      throw new RangeError(`${where}: entry must be an object`);
    }
    const e = entry as Partial<Record<keyof StatusRetryPolicyEntry, unknown>>;
    if (!isFinitePositive(e.baseDelayMs)) {
      throw new RangeError(
        `${where}: baseDelayMs must be a finite number > 0, got ${JSON.stringify(e.baseDelayMs)}`
      );
    }
    if (!Number.isInteger(e.maxAttempts) || (e.maxAttempts as number) < 1) {
      throw new RangeError(
        `${where}: maxAttempts must be an integer >= 1, got ${JSON.stringify(e.maxAttempts)}`
      );
    }
    if (e.multiplier !== undefined && !isFinitePositive(e.multiplier)) {
      throw new RangeError(
        `${where}: multiplier must be a finite number > 0 when set, got ${JSON.stringify(e.multiplier)}`
      );
    }
  }
}

/**
 * Normalize a valid policy into a detached copy: every entry carries
 * its `multiplier` explicitly (defaulted to
 * {@link DEFAULT_STATUS_RETRY_MULTIPLIER}) and no entry shares a
 * reference with the caller's object. Validates first — an illegal
 * config throws `RangeError` and nothing is returned.
 */
export function normalizeStatusRetryPolicy(
  config: StatusRetryPolicyConfig
): StatusRetryPolicyConfig {
  assertValidStatusRetryPolicy(config);
  const out: StatusRetryPolicyConfig = {};
  for (const [key, entry] of Object.entries(config)) {
    out[key] = {
      baseDelayMs: entry.baseDelayMs,
      maxAttempts: entry.maxAttempts,
      multiplier: entry.multiplier ?? DEFAULT_STATUS_RETRY_MULTIPLIER,
    };
  }
  return out;
}

/**
 * Match a failure's status code against a policy: the exact-code entry
 * wins, then the class entry (`"5xx"` for a 503), then `undefined`
 * (the caller falls back to the WR-172 / WR-02 schedule). The
 * returned entry is the policy's own object — callers must not mutate
 * it.
 */
export function matchStatusRetryPolicy(
  config: StatusRetryPolicyConfig | undefined,
  statusCode: number | undefined
): StatusRetryPolicyEntry | undefined {
  if (config === undefined || statusCode === undefined || !Number.isFinite(statusCode)) {
    return undefined;
  }
  const code = Math.floor(statusCode);
  const exact = config[String(code)];
  if (exact !== undefined) return exact;
  return config[`${Math.floor(code / 100)}xx`];
}

/**
 * The retry delay a matched entry prescribes for the just-failed
 * attempt (0-based index of the completed attempt, the same convention
 * as `RetryQueue.delayForAttempt`): `baseDelayMs * multiplier^attempt`.
 * Deterministic — no jitter on this schedule.
 */
export function statusRetryDelayMs(entry: StatusRetryPolicyEntry, attempt: number): number {
  const multiplier = entry.multiplier ?? DEFAULT_STATUS_RETRY_MULTIPLIER;
  return entry.baseDelayMs * multiplier ** attempt;
}
