/**
 * Downstream failure classification (see the `deliver()` failure path in
 * `src/retry.ts`).
 *
 * Not every failed delivery deserves a retry. A `400 Bad Request` means the
 * payload itself is poison — retrying it five times with exponential backoff
 * only burns the retry budget and delays the operator from seeing the real
 * problem in the dead-letter queue. A `503` or a DNS timeout is transient:
 * the normal backoff lane is exactly right for it.
 *
 * Classification rules (deliberately conservative — when in doubt, retry):
 *
 * - HTTP `4xx` **except** `408` and `429` → `"non_retryable"`: the item is
 *   dead-lettered immediately, without consuming further attempts. The
 *   endpoint's circuit breaker is *not* tripped — the downstream answered,
 *   it just said no — and a half-open probe is settled as a success.
 * - `408` (Request Timeout), `429` (Too Many Requests), every `5xx`, and
 *   anything that is not an HTTP response at all (DNS failures, timeouts,
 *   TLS errors, proxy failures) → `"retryable"`: the normal backoff lane.
 *   A `429` additionally honors the downstream's `Retry-After` header when
 *   present.
 *
 * Zero dependencies (`node:` only where the caller's clock is needed).
 */

/**
 * How a delivery failure should be treated by the retry queue.
 *
 * - `"retryable"`: schedule another attempt (backoff, or the downstream's
 *   `Retry-After` when one was supplied).
 * - `"non_retryable"`: the payload is poison — dead-letter immediately,
 *   without burning more of the retry budget.
 */
export type FailureClass = "retryable" | "non_retryable";

/**
 * Structured delivery failure for a non-2xx downstream HTTP response.
 * Thrown by the default sender (`createDefaultSender` in `src/server.ts`)
 * so the retry queue can classify without parsing error message strings.
 * Custom senders may throw it too (or any error with a numeric
 * `statusCode` field — `classifyFailure` duck-types it).
 */
export class HttpDeliveryError extends Error {
  /** The downstream HTTP status code (e.g. 400, 429, 503). */
  readonly statusCode: number;
  /**
   * Milliseconds the downstream asked us to wait before the next attempt,
   * parsed from its `Retry-After` header. Present only when the header was
   * present and parseable.
   */
  readonly retryAfterMs?: number;

  constructor(statusCode: number, retryAfterMs?: number) {
    // Keep the historical message shape so existing log greps and
    // message-matching tests keep working.
    super(`Forward failed with status ${statusCode}`);
    this.name = "HttpDeliveryError";
    this.statusCode = statusCode;
    if (retryAfterMs !== undefined) {
      this.retryAfterMs = retryAfterMs;
    }
  }
}

/**
 * Parse a `Retry-After` header value into milliseconds.
 *
 * Accepts both RFC 9110 forms: delay-seconds (`"120"` → 120000) and an
 * HTTP-date (`"Wed, 21 Oct 2026 07:28:00 GMT"` → ms until that instant,
 * clamped at 0). Returns `undefined` when the value is missing,
 * unparseable, or already in the past — in which case the normal backoff
 * applies instead of a bogus wait.
 */
export function parseRetryAfterMs(
  value: string | string[] | undefined,
  nowMs: () => number = Date.now
): number | undefined {
  const raw = Array.isArray(value) ? value[0] : value;
  if (raw === undefined) return undefined;
  const trimmed = raw.trim();
  if (trimmed === "") return undefined;
  // Delay-seconds: a non-negative integer. (Fractional values are not
  // valid per the RFC; parseInt would silently accept "1.5", so require
  // the whole token to be digits.)
  if (/^\d+$/.test(trimmed)) {
    const seconds = Number(trimmed);
    if (!Number.isSafeInteger(seconds)) return undefined;
    return seconds * 1000;
  }
  // HTTP-date.
  const at = Date.parse(trimmed);
  if (Number.isNaN(at)) return undefined;
  const wait = at - nowMs();
  return wait > 0 ? wait : undefined;
}

/** A classified delivery failure. */
export interface ClassifiedFailure {
  /** Whether the item may be retried (`"retryable"`) or is poison (`"non_retryable"`). */
  failureClass: FailureClass;
  /** Downstream HTTP status, when the failure was an HTTP response. */
  statusCode?: number;
  /**
   * Downstream-requested wait before the next attempt (ms), when a
   * parseable `Retry-After` was present. Only meaningful for
   * `"retryable"` failures (practically: 429/503).
   */
  retryAfterMs?: number;
}

/**
 * Classify a sender failure per the rules documented above.
 *
 * Reads `statusCode` / `retryAfterMs` structurally (duck-typed), so custom
 * senders do not need to import `HttpDeliveryError` — throwing any error
 * with a numeric `statusCode` field is enough.
 */
export function classifyFailure(err: unknown): ClassifiedFailure {
  let statusCode: number | undefined;
  let retryAfterMs: number | undefined;
  if (err !== null && typeof err === "object") {
    const sc = (err as { statusCode?: unknown }).statusCode;
    if (typeof sc === "number" && Number.isInteger(sc)) {
      statusCode = sc;
    }
    const ra = (err as { retryAfterMs?: unknown }).retryAfterMs;
    if (typeof ra === "number" && Number.isFinite(ra) && ra >= 0) {
      retryAfterMs = ra;
    }
  }
  if (
    statusCode !== undefined &&
    statusCode >= 400 &&
    statusCode <= 499 &&
    statusCode !== 408 &&
    statusCode !== 429
  ) {
    return { failureClass: "non_retryable", statusCode };
  }
  return { failureClass: "retryable", ...(statusCode !== undefined ? { statusCode } : {}), ...(retryAfterMs !== undefined ? { retryAfterMs } : {}) };
}
