/**
 * Downstream response guard configuration (WR-168 / WR-169).
 *
 * Two independent opt-ins, keyed per endpoint by exact `targetUrl` and
 * applied by the default sender on the HTTP/1.1 and HTTP/2 delivery
 * paths (WebSocket deliveries carry no HTTP response body, so the
 * guard does not apply there):
 *
 * - `maxResponseBytes` (WR-169): cap on the downstream response body.
 *   The sender reads the body in streaming chunks and truncates at the
 *   cap; a body that runs past it fails the attempt with
 *   `ResponseTooLargeError` — classified `"retryable"`, so it follows
 *   the normal backoff lane, trips the WR-10 breaker like any retryable
 *   failure, and is dead-lettered after the budget is spent. The memory
 *   bound is the point: one pathological downstream can no longer park
 *   gigabytes in the relay's heap. Mirrors the inbound WR-25
 *   `maxBodyBytes` contract on the outbound side.
 * - `verifyContentDigest` (WR-168): verify the downstream's
 *   `Content-Digest` response header (RFC 9530 subset: `sha-256` /
 *   `sha-512`) against the received body. A mismatch fails the attempt
 *   with `IntegrityMismatchError` — classified `"retryable"`, same
 *   lane as above. A response that carries no `Content-Digest` header
 *   resolves exactly as before (the guard has no opinion).
 *
 * When either opt-in is on for an endpoint, the sender's response read
 * cap becomes `maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES` (4 MiB)
 * instead of the plain 64 KiB capture cap — digest verification needs
 * the whole body to hash, and a verification read must be bounded too.
 * A digest-enabled endpoint whose body overruns the cap fails with
 * `ResponseTooLargeError` (a truncated body is unverifiable by
 * definition, so it fails closed rather than resolving half-checked).
 *
 * Both failures get their own audit line on top of the `dead_letter`
 * event (see the server's `onDeadLetter` hook): `response_too_large`
 * and `integrity_mismatch` — the operator sees *why* the item died,
 * not just that it died (the WR-115 / WR-117 precedent).
 *
 * Zero dependencies (`node:` only where the caller needs it).
 */

/**
 * Default response-body read bound applied when an endpoint opts into
 * the guard without naming its own `maxResponseBytes`. 4 MiB — large
 * enough for any sane webhook acknowledgment, small enough that a
 * pathological downstream cannot exhaust the relay's heap.
 */
export const DEFAULT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

/**
 * Per-endpoint downstream response guard. Both fields are opt-in:
 * an endpoint with no entry keeps the exact current behavior (64 KiB
 * truncated capture, no digest check).
 */
export interface ResponseGuardConfig {
  /**
   * Cap on the downstream response body in bytes (WR-169). Must be a
   * positive integer when present. A body that runs past it fails the
   * attempt with `ResponseTooLargeError` (retryable).
   */
  maxResponseBytes?: number;
  /**
   * Verify the downstream's `Content-Digest` header (RFC 9530 subset,
   * WR-168). Defaults to false. A mismatch fails the attempt with
   * `IntegrityMismatchError` (retryable); no header means no check.
   */
  verifyContentDigest?: boolean;
}

/**
 * Structured delivery failure: the downstream's response body ran past
 * the endpoint's `maxResponseBytes` (WR-169). Thrown by the default
 * sender after it truncated the read at the cap, so the relay never
 * holds more than the cap in memory for one response. Classified
 * `"retryable"` by `classifyFailure` — a downstream that recovers
 * deserves another attempt, and the WR-10 breaker sees it like any
 * retryable failure. The numeric `statusCode` rides along so the
 * dead-letter `response_summary` stays honest (the downstream did
 * answer 2xx).
 */
export class ResponseTooLargeError extends Error {
  /** The endpoint whose response overran the cap. */
  readonly targetUrl: string;
  /** The cap that was exceeded, in bytes. */
  readonly maxBytes: number;
  /** The downstream HTTP status (always 2xx on this path). */
  readonly statusCode: number;

  constructor(targetUrl: string, maxBytes: number, statusCode: number) {
    super(
      `response_too_large: downstream response body exceeded maxResponseBytes=${maxBytes} for ${targetUrl}`
    );
    this.name = "ResponseTooLargeError";
    this.targetUrl = targetUrl;
    this.maxBytes = maxBytes;
    this.statusCode = statusCode;
  }
}

/**
 * Validate one endpoint's guard config; throws `RangeError` on the
 * first illegal value. `maxResponseBytes` must be a positive integer —
 * a fractional, zero, negative, or non-numeric cap is a config error,
 * not something to clamp silently. `verifyContentDigest` must be a
 * boolean when present.
 */
export function assertValidResponseGuardConfigValue(
  config: unknown,
  label: string
): asserts config is ResponseGuardConfig {
  if (config === null || typeof config !== "object" || Array.isArray(config)) {
    throw new RangeError(`${label} must be an object`);
  }
  const c = config as Record<string, unknown>;
  if (c.maxResponseBytes !== undefined) {
    const v = c.maxResponseBytes;
    if (typeof v !== "number" || !Number.isInteger(v) || v <= 0) {
      throw new RangeError(
        `${label}.maxResponseBytes must be a positive integer number of bytes, got ${JSON.stringify(v)}`
      );
    }
  }
  if (c.verifyContentDigest !== undefined && typeof c.verifyContentDigest !== "boolean") {
    throw new RangeError(
      `${label}.verifyContentDigest must be a boolean, got ${JSON.stringify(c.verifyContentDigest)}`
    );
  }
}

/**
 * Validate the whole per-endpoint guard record; throws `RangeError` on
 * the first illegal entry. Keys must be non-empty endpoint strings —
 * the same exact-`targetUrl` convention as every other per-endpoint
 * record in the sender.
 */
export function assertValidResponseGuardConfig(
  record: unknown,
  label = "responseGuard"
): void {
  if (record === null || typeof record !== "object" || Array.isArray(record)) {
    throw new RangeError(`${label} must be an object keyed by endpoint URL`);
  }
  for (const [endpoint, config] of Object.entries(record as Record<string, unknown>)) {
    if (endpoint.length === 0) {
      throw new RangeError(`${label} keys must be non-empty endpoint strings`);
    }
    assertValidResponseGuardConfigValue(config, `${label}["${endpoint}"]`);
  }
}
