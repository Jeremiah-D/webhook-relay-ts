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
import { assertValidWeightedTargets, type WeightedTargetConfig } from "./weighted.ts";
import {
  assertValidConsistentHashTargets,
  type ConsistentHashTargetConfig,
} from "./consistent-hash.ts";
import type { CircuitTripMode } from "./circuit.ts";
import {
  assertValidStatusRetryPolicy,
  type StatusRetryPolicyConfig,
} from "./status-retry.ts";

/** Patch for one endpoint's circuit-breaker trip/cooldown thresholds. */
export interface CircuitBreakerPatch {
  /** Consecutive failures that trip the circuit. Integer >= 1. */
  failureThreshold?: number;
  /** Cooldown in ms before a half-open probe. Finite > 0. */
  cooldownMs?: number;
  /** Trip mode switch (WR-104): "consecutive-failures" or "error-rate". */
  tripMode?: CircuitTripMode;
  /** Rolling-window size for error-rate mode. Integer >= 2. */
  errorRateWindowSize?: number;
  /** Failure-rate threshold for error-rate mode. In (0, 1]. */
  errorRateThreshold?: number;
  /**
   * Minimum outcomes before error-rate mode may trip. Integer >= 2 and
   * <= the effective window size (validated against the merged
   * thresholds at apply time).
   */
  errorRateMinSamples?: number;
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
  /** Jitter strategy: "additive" (default), "full" (AWS-style) or "decorrelated" (AWS-style random walk). */
  jitterStrategy?: JitterStrategy;
}

/**
 * Patch for one endpoint's weighted multi-target dispatch (WR-66).
 * Replaces the endpoint's whole target list — weights included — so the
 * shape is always complete, never a partial merge. Requires weighted
 * dispatch to be enabled for the endpoint.
 */
export interface WeightedPatch {
  /** The endpoint's new target list (validated before apply). */
  targets: WeightedTargetConfig[];
}

/**
 * Patch for one endpoint's consistent-hash ring membership (WR-202).
 * Replaces the endpoint's whole target list atomically — the ring is
 * rebuilt, the ring version is bumped, and only the keys on the changed
 * arcs remigrate. Requires consistent-hash routing to be enabled for
 * the endpoint.
 */
export interface ConsistentHashPatch {
  /** The endpoint's new target list (validated before apply). */
  targets: ConsistentHashTargetConfig[];
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
  /**
   * Per-endpoint weighted target list (requires weighted dispatch
   * enabled for the endpoint). Replaces the whole list atomically; the
   * smooth-WRR accumulators reset, health counters and dispatch counts
   * survive.
   */
  weighted?: WeightedPatch;
  /**
   * Per-endpoint consistent-hash target list (requires consistent-hash
   * routing enabled for the endpoint). Replaces the whole list
   * atomically; the ring is rebuilt and the ring version bumped, health
   * counters and dispatch counts survive for targets still present.
   */
  consistentHash?: ConsistentHashPatch;
  /** Queue-global backoff parameters. */
  retry?: RetryPatch;
  /**
   * WR-172: named retry policy for the endpoint (exact `targetUrl`). The
   * name must be registered on the queue — an unknown name throws
   * `RangeError` when the patch is applied. `null` detaches the
   * endpoint's policy, falling back to the global retry config.
   */
  retryPolicyName?: string | null;
  /**
   * WR-178: per-status retry policy for the endpoint (see
   * `src/status-retry.ts`). Replaces the endpoint's whole policy —
   * the shape is always complete, never a partial merge. `null`
   * detaches the policy, falling back to the WR-172 policy / global
   * schedule. An illegal value throws `RangeError` and leaves the
   * running config untouched.
   */
  statusRetryPolicy?: StatusRetryPolicyConfig | null;
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
  if (value !== "additive" && value !== "full" && value !== "decorrelated") {
    throw new RangeError(
      `updateEndpointConfig: \`retry.jitterStrategy\` must be "additive", "full" or "decorrelated", got ${JSON.stringify(value)}`
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
    if (cb.tripMode !== undefined) {
      if (cb.tripMode !== "consecutive-failures" && cb.tripMode !== "error-rate") {
        throw new RangeError(
          `updateEndpointConfig: \`circuitBreaker.tripMode\` must be "consecutive-failures" or "error-rate", got ${JSON.stringify(cb.tripMode)}`
        );
      }
    }
    if (cb.errorRateWindowSize !== undefined) {
      assertNumberIn(cb.errorRateWindowSize, "circuitBreaker.errorRateWindowSize", (n) => Number.isInteger(n) && n >= 2, "an integer >= 2");
    }
    if (cb.errorRateThreshold !== undefined) {
      assertNumberIn(cb.errorRateThreshold, "circuitBreaker.errorRateThreshold", (n) => Number.isFinite(n) && n > 0 && n <= 1, "a finite number in (0, 1]");
    }
    if (cb.errorRateMinSamples !== undefined) {
      // The <= windowSize half is checked against the merged thresholds
      // at apply time (setEndpointThresholds); here we only fail-fast
      // the >= 2 floor that structurally prevents 1/1 flapping.
      assertNumberIn(cb.errorRateMinSamples, "circuitBreaker.errorRateMinSamples", (n) => Number.isInteger(n) && n >= 2, "an integer >= 2");
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
  if (p.weighted !== undefined) {
    if (typeof p.weighted !== "object" || p.weighted === null || Array.isArray(p.weighted)) {
      throw new RangeError("updateEndpointConfig: `weighted` must be an object");
    }
    try {
      assertValidWeightedTargets(p.weighted.targets);
    } catch (err) {
      throw new RangeError(
        `updateEndpointConfig: \`weighted.targets\` is invalid: ${(err as Error).message}`
      );
    }
  }
  if (p.consistentHash !== undefined) {
    if (
      typeof p.consistentHash !== "object" ||
      p.consistentHash === null ||
      Array.isArray(p.consistentHash)
    ) {
      throw new RangeError("updateEndpointConfig: `consistentHash` must be an object");
    }
    try {
      assertValidConsistentHashTargets(p.consistentHash.targets);
    } catch (err) {
      throw new RangeError(
        `updateEndpointConfig: \`consistentHash.targets\` is invalid: ${(err as Error).message}`
      );
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
  // WR-172: a policy name patch — `null` detaches, a string re-points.
  // Whether the name is registered is checked when the queue applies
  // the patch (the validator has no registry handle).
  if (p.retryPolicyName !== undefined && p.retryPolicyName !== null) {
    if (typeof p.retryPolicyName !== "string" || p.retryPolicyName.length === 0) {
      throw new RangeError(
        `updateEndpointConfig: \`retryPolicyName\` must be a non-empty string or null, got ${JSON.stringify(p.retryPolicyName)}`
      );
    }
  }
  // WR-178: a per-status retry policy patch — `null` detaches, an object
  // replaces the endpoint's whole policy. Validated with the same
  // fail-fast RangeError as the construction-time setter.
  if (p.statusRetryPolicy !== undefined && p.statusRetryPolicy !== null) {
    try {
      assertValidStatusRetryPolicy(p.statusRetryPolicy);
    } catch (err) {
      throw new RangeError(
        `updateEndpointConfig: \`statusRetryPolicy\` is invalid: ${(err as Error).message}`
      );
    }
  }
}
