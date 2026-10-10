/**
 * Outbound idempotency-key derivation (WR-44).
 *
 * When enabled, every delivery the default sender makes carries
 * `x-relay-idempotency-key`, derived deterministically from
 * `(event id, attempt)` under the relay's HMAC-SHA256 secret. The
 * downstream can feed the header straight into its own deduplicator:
 *
 * - The same attempt of the same event always yields the same key, so a
 *   transport-level redelivery of attempt N is recognizable downstream.
 * - A new attempt gets a fresh key, so the downstream can tell a genuine
 *   retry (new business intent window) apart from a duplicate send.
 * - A dead-letter replay restarts the attempt budget at attempt 1 with
 *   the same event id, so it reproduces the *original* keys — the
 *   downstream deduplicator sees the replay as the same attempt it may
 *   already hold, never as a new event.
 * - Batch deliveries derive from the `batch_id` (the batch item's id is
 *   the batch id), so one key covers the whole merged envelope.
 *
 * HMAC-SHA256 under the relay secret makes the key unforgeable and
 * unguessable to anyone without the secret: a sender that never saw the
 * relay cannot mint a colliding key for someone else's event.
 */

import { createHmac } from "node:crypto";

/** The outbound header carrying the derived idempotency key. */
export const IDEMPOTENCY_KEY_HEADER = "x-relay-idempotency-key";

/** Domain-separation prefix for the HMAC input (versioned). */
const HMAC_DOMAIN = "relay-idempotency-key/v1:";

/** Operator-facing options for outbound idempotency keys. */
export interface IdempotencyKeyOptions {
  /**
   * Stamp `x-relay-idempotency-key` on every delivery. Default `false`
   * (absent headers stay absent; inbound forgeries are stripped at
   * intake regardless).
   */
  enabled?: boolean;
  /**
   * Relay secret used as the HMAC key. Required (non-empty) when
   * `enabled` is true; a `RangeError` is thrown at startup otherwise.
   * Keep it out of logs and config dumps — anyone holding it can mint
   * keys for arbitrary event ids.
   */
  secret?: string;
  /**
   * Optional prefix prepended to the derived key, e.g. `"relay-"`.
   * Useful when the downstream shares one dedup namespace across
   * producers. Default `""`.
   */
  keyPrefix?: string;
}

/** Validated, ready-to-use idempotency-key configuration. */
export interface ResolvedIdempotencyKeyConfig {
  enabled: true;
  secret: string;
  keyPrefix: string;
}

/**
 * Validate `IdempotencyKeyOptions` at startup. Returns `undefined` when
 * the feature is off (unset or `enabled: false`) — the default — so
 * callers can branch on "configured" with a single check. Throws
 * `RangeError` on invalid values; never mid-delivery.
 */
export function resolveIdempotencyKeyConfig(
  opts?: IdempotencyKeyOptions
): ResolvedIdempotencyKeyConfig | undefined {
  if (opts === undefined || opts.enabled !== true) return undefined;
  if (typeof opts.secret !== "string" || opts.secret === "") {
    throw new RangeError("idempotencyKey: `secret` must be a non-empty string when `enabled` is true");
  }
  if (opts.keyPrefix !== undefined && typeof opts.keyPrefix !== "string") {
    throw new RangeError("idempotencyKey: `keyPrefix` must be a string when set");
  }
  return { enabled: true, secret: opts.secret, keyPrefix: opts.keyPrefix ?? "" };
}

/**
 * Derive the idempotency key for one delivery attempt.
 *
 * `attempt` is the 1-based attempt number (`RetryItem.attempt + 1` on the
 * sender-bound copy). The derivation is deterministic: identical
 * `(secret, eventId, attempt)` inputs always produce the identical key,
 * which is what makes dead-letter replays reproduce the original keys.
 */
export function deriveIdempotencyKey(
  secret: string,
  eventId: string,
  attempt: number,
  keyPrefix = ""
): string {
  const hmac = createHmac("sha256", secret);
  hmac.update(HMAC_DOMAIN);
  hmac.update(eventId);
  hmac.update(":");
  hmac.update(String(attempt));
  return `${keyPrefix}${hmac.digest("hex")}`;
}
