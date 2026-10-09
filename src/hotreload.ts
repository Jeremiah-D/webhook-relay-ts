/**
 * Runtime endpoint configuration hot-reload (WR-32).
 *
 * Long-lived relay operators need to tune per-endpoint delivery policy
 * without restarting the process: raising the concurrency limit when a
 * downstream scales up, tightening a circuit breaker's trip threshold
 * during an incident, or changing backoff parameters after a bad deploy.
 *
 * `RetryQueue.updateEndpointConfig(endpoint, patch)` applies such a patch
 * immediately:
 *
 * - Validation happens *before* anything mutates: an illegal value throws
 *   `RangeError` and the previous configuration is left completely intact.
 * - Already-scheduled retries keep the delay they were scheduled with;
 *   in-flight deliveries are never revoked — only future scheduling
 *   decisions see the new values. (Lowering a concurrency limit below the
 *   current in-flight count does not kill running deliveries; it only
 *   stops *new* acquisitions until the count drains below the new limit.)
 * - Every applied change is reported through the queue's `onConfigChange`
 *   hook (the server audits it as `endpoint_config_updated`), so tuning
 *   stays observable.
 *
 * Per-endpoint scope: `maxConcurrentPerEndpoint`, circuit-breaker
 * thresholds, and quota limits resolve per endpoint. Backoff parameters
 * are queue-global by design (one scheduling policy for the whole queue)
 * and are patched through the same call for operator convenience.
 */

import type { JitterStrategy } from "./retry.ts";

/** Patch for one endpoint's circuit-breaker trip/cooldown thresholds. */
export interface CircuitBreakerPatch {
  /** Consecutive failures that trip the circuit. Integer >= 1. */
  failureThreshold?: number;
  /** Cooldown in ms before a half-open probe. Finite > 0. */
  cooldownMs?: number;
}

/** Patch for one endpoint's per-minute delivery quota. */
export interface QuotaPatch {
  /** Maximum deliveries per minute. Finite > 0. */
  deliveriesPerMinute?: number;
}

/**
 * Patch for the queue's backoff parameters. These are queue-global: they
 * apply to every endpoint, effective for retries scheduled after the
 * update — already-scheduled timers keep their old delay.
 */
export interface RetryPatch {
  /** Base delay in ms for exponential backoff. Finite > 0. */
  baseDelayMs?: number;
  /** Maximum delay in ms between attempts. Finite > 0. */
  maxDelayMs?: number;
  /** Total attempts per item. Integer >= 1. */
  maxAttempts?: number;
  /** Jitter in ms (uniform 0..jitterMs). Finite >= 0. */
  jitterMs?: number;
  /** Jitter strategy: "additive" (default) or "full" (AWS-style). */
  jitterStrategy?: JitterStrategy;
}

/**
 * Partial endpoint configuration update accepted by
 * `RetryQueue.updateEndpointConfig`. Every field is optional; omitted
 * fields keep their current value.
 */
export interface EndpointConfigPatch {
  /**
   * Per-endpoint concurrency limit: positive integer, or `Infinity` for no
   * limit on this endpoint. Raising it immediately grants slots to queued
   * waiters; lowering it never revokes in-flight deliveries.
   */
  maxConcurrentPerEndpoint?: number;
  /** Per-endpoint circuit-breaker thresholds (requires the breaker enabled). */
  circuitBreaker?: CircuitBreakerPatch;
  /** Per-endpoint quota limit (requires quota enabled). */
  quota?: QuotaPatch;
  /** Queue-global backoff parameters. */
  retry?: RetryPatch;
}

/** One applied configuration change, for audit/observability. */
export interface ConfigChange {
  /** Dotted field name, e.g. `circuitBreaker.failureThreshold`. */
  field: string;
  /** Value before the update. */
  from: unknown;
  /** Value after the update. */
  to: unknown;
}

function assertNumberIn(
  value: unknown,
  field: string,
  predicate: (n: number) => boolean,
  constraint: string
): void {
  if (typeof value !== "number" || !predicate(value)) {
    throw new RangeError(
      `updateEndpointConfig: \`${field}\` must be ${constraint}, got ${JSON.stringify(value)}`
    );
  }
}

function assertConcurrencyLimit(value: unknown, field: string): void {
  if (
    !(
      value === Infinity ||
      (typeof value === "number" && Number.isInteger(value) && value >= 1)
    )
  ) {
    throw new RangeError(
      `updateEndpointConfig: \`${field}\` must be a positive integer or Infinity, got ${JSON.stringify(value)}`
    );
  }
}

function assertJitterStrategy(value: unknown): void {
  if (value !== "additive" && value !== "full") {
    throw new RangeError(
      `updateEndpointConfig: \`retry.jitterStrategy\` must be "additive" or "full", got ${JSON.stringify(value)}`
    );
  }
}

/**
 * Validate an endpoint config patch. Throws `RangeError` on the first
 * illegal value. Does not mutate anything — call this before applying.
 */
export function assertValidEndpointConfigPatch(patch: EndpointConfigPatch): void {
  if (typeof patch !== "object" || patch === null || Array.isArray(patch)) {
    throw new RangeError("updateEndpointConfig: patch must be an object");
  }
  const p = patch;
  if (p.maxConcurrentPerEndpoint !== undefined) {
    assertConcurrencyLimit(p.maxConcurrentPerEndpoint, "maxConcurrentPerEndpoint");
  }
  if (p.circuitBreaker !== undefined) {
    if (typeof p.circuitBreaker !== "object" || p.circuitBreaker === null || Array.isArray(p.circuitBreaker)) {
      throw new RangeError("updateEndpointConfig: `circuitBreaker` must be an object");
    }
    const cb = p.circuitBreaker;
    if (cb.failureThreshold !== undefined) {
      assertNumberIn(cb.failureThreshold, "circuitBreaker.failureThreshold", (n) => Number.isInteger(n) && n >= 1, "an integer >= 1");
    }
    if (cb.cooldownMs !== undefined) {
      assertNumberIn(cb.cooldownMs, "circuitBreaker.cooldownMs", (n) => Number.isFinite(n) && n > 0, "a finite number > 0");
    }
  }
  if (p.quota !== undefined) {
    if (typeof p.quota !== "object" || p.quota === null || Array.isArray(p.quota)) {
      throw new RangeError("updateEndpointConfig: `quota` must be an object");
    }
    if (p.quota.deliveriesPerMinute !== undefined) {
      assertNumberIn(p.quota.deliveriesPerMinute, "quota.deliveriesPerMinute", (n) => Number.isFinite(n) && n > 0, "a finite number > 0");
    }
  }
  if (p.retry !== undefined) {
    if (typeof p.retry !== "object" || p.retry === null || Array.isArray(p.retry)) {
      throw new RangeError("updateEndpointConfig: `retry` must be an object");
    }
    const r = p.retry;
    if (r.baseDelayMs !== undefined) {
      assertNumberIn(r.baseDelayMs, "retry.baseDelayMs", (n) => Number.isFinite(n) && n > 0, "a finite number > 0");
    }
    if (r.maxDelayMs !== undefined) {
      assertNumberIn(r.maxDelayMs, "retry.maxDelayMs", (n) => Number.isFinite(n) && n > 0, "a finite number > 0");
    }
    if (r.maxAttempts !== undefined) {
      assertNumberIn(r.maxAttempts, "retry.maxAttempts", (n) => Number.isInteger(n) && n >= 1, "an integer >= 1");
    }
    if (r.jitterMs !== undefined) {
      assertNumberIn(r.jitterMs, "retry.jitterMs", (n) => Number.isFinite(n) && n >= 0, "a finite number >= 0");
    }
    if (r.jitterStrategy !== undefined) {
      assertJitterStrategy(r.jitterStrategy);
    }
  }
}
