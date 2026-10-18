/**
 * WR-143: per-endpoint phase timeout budgets for outbound delivery attempts.
 *
 * WR-99 gave each attempt one shared budget (the remaining deadline
 * budget); this module splits the attempt into the WR-95 delivery phases
 * and budgets each one separately. An endpoint whose TLS handshake
 * habitually stalls can say "tls: 500ms" instead of watching the whole
 * attempt burn a 30s budget — and the failure attributes to the phase
 * that blew it, so the retry / dead-letter path and the `slo_missed`
 * audit channel can say "firstByte blew the budget" instead of just
 * "was slow".
 *
 * Layering (see the `phaseTimeouts` server option):
 *
 * - The phase budgets are per-attempt allocations *inside* one attempt;
 *   the WR-76 `deliveryDeadline` stays end-to-end (queue admission →
 *   delivery confirmation). Both may be configured: the deadline can
 *   expire a delivery whose attempts never hit a phase budget, and a
 *   phase budget can fail an attempt long before the deadline.
 * - A `PhaseTimeoutError` carries no `statusCode`, so
 *   `classifyFailure` (see `src/failure.ts`) routes it through the
 *   default fallthrough to `"retryable"` — the normal backoff lane,
 *   circuit breaker, retry budget, and dead-letter path. No new failure
 *   class was needed: a phase timeout is a transient downstream
 *   condition, exactly like any other timeout.
 * - `dns` is never budgeted: per-request DNS timing is not attributable
 *   (WR-95 convention — resolution happens inside the connection
 *   machinery, often served from the WR-92 cache).
 * - `connect` / `tls` are only measurable on a fresh direct socket
 *   (WR-95): on pooled reuse or behind a proxy they report unavailable,
 *   so their timers are never armed there — budgets fire against
 *   measured phases only.
 *
 * Zero dependencies. The sender arms the timers; this module only
 * defines the config shape, the validation, and the typed error.
 */

/**
 * The delivery phases a timeout budget can be attached to. `dns` is
 * deliberately absent — never attributable per-request (see above).
 */
export type PhaseTimeoutPhase = "connect" | "tls" | "firstByte" | "body";

/**
 * Per-endpoint phase timeout budgets in milliseconds. Every configured
 * value must be a positive integer; at least one phase is required.
 */
export interface PhaseTimeoutBudgets {
  /** Socket-assigned → TCP established (fresh direct sockets only). */
  connectMs?: number;
  /** TCP established → TLS handshake complete (https, fresh sockets only). */
  tlsMs?: number;
  /** Request-issued → first response bytes. */
  firstByteMs?: number;
  /** First response bytes → response end (2xx responses only). */
  bodyMs?: number;
}

/**
 * The error a phase-budget-enforcing sender rejects with when a phase's
 * budget expires before the sender observes that phase's completion.
 * Carries no `statusCode`, so `classifyFailure` routes it to
 * `"retryable"` via the default fallthrough — the normal backoff /
 * dead-letter path. The payload never rides along: the error carries
 * the phase name and the budget, never payload bytes.
 */
export class PhaseTimeoutError extends Error {
  /** Physical target the attempt was bound for. */
  readonly targetUrl: string;
  /** The phase whose budget fired. */
  readonly phase: PhaseTimeoutPhase;
  /** The budget (ms) the phase was held to. */
  readonly timeoutMs: number;
  constructor(targetUrl: string, phase: PhaseTimeoutPhase, timeoutMs: number) {
    super(
      `phase timeout: ${phase} phase of downstream call to ${targetUrl} ` +
        `exceeded ${Math.max(0, Math.round(timeoutMs))}ms budget`
    );
    this.name = "PhaseTimeoutError";
    this.targetUrl = targetUrl;
    this.phase = phase;
    this.timeoutMs = timeoutMs;
  }
}

/** The phase keys a `PhaseTimeoutBudgets` entry may carry. */
const PHASE_TIMEOUT_KEYS: readonly string[] = ["connectMs", "tlsMs", "firstByteMs", "bodyMs"];

/**
 * Validate one `phaseTimeouts` entry. Throws `RangeError` on anything
 * invalid — fail fast at construction, never mid-delivery.
 */
export function assertValidPhaseTimeoutBudgets(budgets: unknown): void {
  if (budgets === null || typeof budgets !== "object" || Array.isArray(budgets)) {
    throw new RangeError(
      `phaseTimeouts entry must be an object of phase -> positive integer ms, got ${String(budgets)}`
    );
  }
  let configured = 0;
  for (const [key, value] of Object.entries(budgets as Record<string, unknown>)) {
    if (!PHASE_TIMEOUT_KEYS.includes(key)) {
      throw new RangeError(
        `phaseTimeouts entry has unknown phase "${key}" — expected one of ${PHASE_TIMEOUT_KEYS.join(", ")}`
      );
    }
    if (typeof value !== "number" || !Number.isInteger(value) || value <= 0) {
      throw new RangeError(
        `phaseTimeouts.${key} must be a positive integer (ms), got ${String(value)}`
      );
    }
    configured += 1;
  }
  if (configured === 0) {
    throw new RangeError("phaseTimeouts entry must configure at least one phase budget");
  }
}

/**
 * Resolve the phase timeout budgets for one delivery target (exact
 * `targetUrl` match). Returns `undefined` when the record is absent or
 * the endpoint has no entry — the sender then keeps the current single
 * attempt-total-timeout behavior untouched.
 */
export function resolvePhaseTimeouts(
  targetUrl: string,
  record: Record<string, PhaseTimeoutBudgets> | undefined
): PhaseTimeoutBudgets | undefined {
  if (record === undefined) return undefined;
  return record[targetUrl];
}
