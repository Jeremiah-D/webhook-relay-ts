/**
 * WR-99: outbound deadline-budget propagation.
 *
 * WR-76 gave each endpoint an end-to-end delivery deadline (queue
 * admission → delivery confirmation) and expires the delivery at the
 * next dispatch once the deadline has passed. What it did *not* do was
 * propagate the *remaining* budget into the downstream call itself: a
 * delivery dispatched 1ms before its deadline could still run a
 * 30-second downstream attempt, overshooting the SLO it was supposed
 * to enforce.
 *
 * This module closes that gap:
 *
 * 1. **Budget stamping** — at dispatch, the queue computes
 *    `remainingMs = deadlineMs - elapsedMs` and stamps it on the wire
 *    copy as `RetryItem.deadlineBudgetMs`. The remaining budget is the
 *    single shared pool for "queue wait so far + this downstream call".
 * 2. **Short-circuit** — when the remaining budget is at or below
 *    `minAttemptBudgetMs` the dispatch is pointless (the call could not
 *    usefully complete inside the budget), so the delivery expires
 *    *without* issuing the outbound call — one wasted downstream hit
 *    saved.
 * 3. **Sender enforcement** — the default sender caps the per-attempt
 *    downstream call at the stamped budget: the HTTP/1.1 path destroys
 *    the in-flight request when the budget fires (that path has no
 *    other per-attempt timeout), and a uniform race in `defaultSender`
 *    bounds the H2/WS paths. The rejection is a typed
 *    {@link DeadlineBudgetTimeoutError} so the queue routes it to the
 *    deadline-expiry path (audit + dead letter, actual attempt count,
 *    no backoff) instead of the normal retry path.
 * 4. **SLO-miss attribution** — budget exhaustion (queued or mid-call)
 *    is attributed into the `slo_missed` channel with the dominant
 *    latency phase (WR-95), so operators see *why* the SLO burned, not
 *    just that a dead letter exists.
 *
 * Zero dependencies. Custom (injected) senders simply ignore
 * `deadlineBudgetMs` — the queue-side expiry still bounds the delivery,
 * only the per-attempt cap is lost; that limitation is documented on
 * the sender type.
 */

/** Default floor: a dispatch with no remaining budget is never useful. */
export const DEFAULT_MIN_ATTEMPT_BUDGET_MS = 0;

/**
 * The error a budget-enforcing sender rejects with when the remaining
 * deadline budget fires mid-call. The queue treats it like the
 * WR-76 queue-side expiry (dead letter, no backoff, actual attempt
 * count) — never like a generic timeout, which would schedule a retry
 * the deadline has already ruled out.
 */
export class DeadlineBudgetTimeoutError extends Error {
  /** Physical target the attempt was bound for. */
  readonly targetUrl: string;
  /** The remaining budget (ms) the attempt was capped at. */
  readonly budgetMs: number;
  constructor(targetUrl: string, budgetMs: number) {
    super(
      `deadline budget exhausted during downstream call to ${targetUrl}: ` +
        `attempt capped at ${Math.max(0, Math.round(budgetMs))}ms remaining`
    );
    this.name = "DeadlineBudgetTimeoutError";
    this.targetUrl = targetUrl;
    this.budgetMs = budgetMs;
  }
}

/**
 * Resolve the dispatch decision for one endpoint's deadline.
 *
 * @returns `expired` when the delivery must expire *without* calling the
 * downstream (the remaining budget is at or below the useful floor);
 * otherwise `expired: false` and the `remainingMs` to stamp on the wire
 * copy as this attempt's shared budget.
 */
export function resolveDeadlineBudget(
  deadlineMs: number,
  elapsedMs: number,
  minAttemptBudgetMs: number
): { expired: boolean; remainingMs: number } {
  const remainingMs = deadlineMs - elapsedMs;
  return {
    expired: remainingMs <= minAttemptBudgetMs,
    remainingMs: Math.max(0, remainingMs),
  };
}

/**
 * Validate the WR-99 additions to `DeliveryDeadlineOptions`.
 * Throws `RangeError` on anything invalid — fail fast at construction,
 * never mid-delivery.
 */
export function assertValidDeadlineBudgetOptions(opts: {
  propagateBudget?: unknown;
  minAttemptBudgetMs?: unknown;
}): void {
  const { propagateBudget, minAttemptBudgetMs } = opts;
  if (propagateBudget !== undefined && typeof propagateBudget !== "boolean") {
    throw new RangeError(
      `deliveryDeadline.propagateBudget must be a boolean, got ${String(propagateBudget)}`
    );
  }
  if (minAttemptBudgetMs !== undefined) {
    if (
      typeof minAttemptBudgetMs !== "number" ||
      !Number.isFinite(minAttemptBudgetMs) ||
      minAttemptBudgetMs < 0
    ) {
      throw new RangeError(
        `deliveryDeadline.minAttemptBudgetMs must be a finite number >= 0, got ${String(minAttemptBudgetMs)}`
      );
    }
  }
}

/**
 * Read a stamped budget off a wire item the way the sender does.
 * Returns `undefined` when no usable budget is present (absent, NaN,
 * non-positive) — the sender then behaves exactly as before.
 */
export function readDeadlineBudgetMs(item: { deadlineBudgetMs?: unknown }): number | undefined {
  const v = item.deadlineBudgetMs;
  return typeof v === "number" && Number.isFinite(v) && v > 0 ? v : undefined;
}
