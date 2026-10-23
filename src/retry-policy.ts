/**
 * WR-172: named retry-policy registry.
 *
 * A named retry policy pins the backoff schedule for one downstream
 * class: how many attempts a delivery gets (`maxAttempts`), the
 * exponential backoff's base and cap (`baseDelayMs` / `maxDelayMs`), and
 * the jitter (`jitterMs` / `jitterStrategy`). Operators register policies
 * once and reference them per endpoint by name — e.g. a payment
 * provider that answers slowly gets a patient policy, a flaky analytics
 * sink gets a fast-fail one — instead of one global schedule for every
 * downstream.
 *
 * An endpoint with no assigned policy falls back to the queue's global
 * retry config, exactly as before. Jitter fields are optional per
 * policy: when unset they inherit the queue's current jitter settings,
 * so a policy only needs to spell out what differs.
 *
 * Policies are read live: re-registering a name updates every endpoint
 * pointing at it immediately, which is the runtime-update story that
 * composes with WR-32 hot-reload (`RetryQueue.updateEndpointConfig`
 * accepts a `retryPolicyName` patch to re-point an endpoint).
 */
import type { JitterStrategy } from "./retry.ts";

/** The backoff parameters a named retry policy carries. */
export interface RetryPolicyConfig {
  /** Total attempts per delivery (initial try + retries). Must be an integer >= 1. */
  maxAttempts: number;
  /**
   * Base delay in ms for the exponential backoff (`base * 2^attempt`).
   * Must be a finite number > 0.
   */
  baseDelayMs: number;
  /** Maximum delay in ms between attempts. Must be a finite number > 0. */
  maxDelayMs: number;
  /**
   * Jitter added to each delay in ms (uniform 0..jitterMs) for the
   * `"additive"` strategy. Optional: inherits the queue's `jitterMs`
   * when unset. Must be a finite number >= 0.
   */
  jitterMs?: number;
  /**
   * Jitter strategy; see the `JitterStrategy` docs. Optional: inherits
   * the queue's `jitterStrategy` when unset.
   */
  jitterStrategy?: JitterStrategy;
}

/** A registered retry policy: its config plus the name it is filed under. */
export interface NamedRetryPolicy extends RetryPolicyConfig {
  /** Registry key. Must be a non-empty string. */
  name: string;
}

function isFinitePositive(n: unknown): n is number {
  return typeof n === "number" && Number.isFinite(n) && n > 0;
}

/**
 * Validate a policy registration. Throws `RangeError` on the first
 * illegal value — at registration time, never mid-delivery.
 */
export function assertValidRetryPolicy(name: unknown, config: unknown): void {
  if (typeof name !== "string" || name.length === 0) {
    throw new RangeError(
      `registerRetryPolicy: name must be a non-empty string, got ${JSON.stringify(name)}`
    );
  }
  if (typeof config !== "object" || config === null || Array.isArray(config)) {
    throw new RangeError(
      `registerRetryPolicy: config for "${name}" must be an object`
    );
  }
  const c = config as Partial<Record<keyof RetryPolicyConfig, unknown>>;
  if (!Number.isInteger(c.maxAttempts) || (c.maxAttempts as number) < 1) {
    throw new RangeError(
      `registerRetryPolicy: maxAttempts for "${name}" must be an integer >= 1, got ${JSON.stringify(c.maxAttempts)}`
    );
  }
  if (!isFinitePositive(c.baseDelayMs)) {
    throw new RangeError(
      `registerRetryPolicy: baseDelayMs for "${name}" must be a finite number > 0, got ${JSON.stringify(c.baseDelayMs)}`
    );
  }
  if (!isFinitePositive(c.maxDelayMs)) {
    throw new RangeError(
      `registerRetryPolicy: maxDelayMs for "${name}" must be a finite number > 0, got ${JSON.stringify(c.maxDelayMs)}`
    );
  }
  if (c.jitterMs !== undefined && !(typeof c.jitterMs === "number" && Number.isFinite(c.jitterMs) && c.jitterMs >= 0)) {
    throw new RangeError(
      `registerRetryPolicy: jitterMs for "${name}" must be a finite number >= 0, got ${JSON.stringify(c.jitterMs)}`
    );
  }
  if (
    c.jitterStrategy !== undefined &&
    c.jitterStrategy !== "additive" &&
    c.jitterStrategy !== "full" &&
    c.jitterStrategy !== "decorrelated"
  ) {
    throw new RangeError(
      `registerRetryPolicy: jitterStrategy for "${name}" must be "additive", "full" or "decorrelated", got ${JSON.stringify(c.jitterStrategy)}`
    );
  }
}

/**
 * Registry of named retry policies. Registration replaces any existing
 * policy under the same name (the runtime-update path); registration
 * order is preserved for observability snapshots.
 */
export class RetryPolicyRegistry {
  private readonly policies = new Map<string, NamedRetryPolicy>();

  /**
   * Register (or re-register) a policy. Validated eagerly — a bad
   * config throws `RangeError` and leaves the registry untouched.
   */
  register(name: string, config: RetryPolicyConfig): void {
    assertValidRetryPolicy(name, config);
    // Map.set on an existing key preserves its original insertion
    // slot, so a re-registration updates in place without moving in
    // the snapshot order.
    this.policies.set(name, {
      name,
      maxAttempts: config.maxAttempts,
      baseDelayMs: config.baseDelayMs,
      maxDelayMs: config.maxDelayMs,
      ...(config.jitterMs !== undefined ? { jitterMs: config.jitterMs } : {}),
      ...(config.jitterStrategy !== undefined ? { jitterStrategy: config.jitterStrategy } : {}),
    });
  }

  /** Whether a policy is registered under `name`. */
  has(name: string): boolean {
    return this.policies.has(name);
  }

  /**
   * Look up a policy. Returns a copy — callers can never mutate the
   * registry's live entries through it. `undefined` when unregistered.
   */
  get(name: string): NamedRetryPolicy | undefined {
    const found = this.policies.get(name);
    return found === undefined ? undefined : { ...found };
  }

  /** Registered names, in registration order. */
  names(): string[] {
    return [...this.policies.keys()];
  }

  /**
   * Observability snapshot: every registered policy, in registration
   * order, as copies.
   */
  snapshot(): NamedRetryPolicy[] {
    return [...this.policies.values()].map((p) => ({ ...p }));
  }
}
