import type { RetryItem, Sender } from "./retry.ts";

/**
 * Shadow-target dry-run mirroring (WR-85).
 *
 * Downstream-migration / contract-verification scenario: after every main
 * delivery *attempt* completes (success or failure), the relay
 * asynchronously mirrors the identical wire request to one or more shadow
 * targets. The shadow copy is the exact item the main attempt sent —
 * same payload, same headers, same 0-based `attempt` index — with only
 * the `targetUrl` swapped, so an independent sender copy configured with
 * the same wire settings (signing secret, idempotency-key secret,
 * compression) rebuilds the byte-identical wire request: the same
 * `x-relay-signature` (it signs the body), the same
 * `x-relay-idempotency-key` (derived from id + 1-based attempt), and the
 * same `content-encoding` (deterministic in payload + content-type).
 *
 * Isolation guarantees (the whole point of the feature):
 *
 * - shadow outcomes are only *observed*: they feed the
 *   `onShadowDelivered` / `onShadowFailed` hooks (audited as
 *   `shadow_delivered` / `shadow_failed` by the server) and the
 *   `relay_shadow_total` metrics counter. They never touch the main
 *   delivery counters, the retry budget, the dead-letter list, the
 *   circuit breaker, or the quota — a failing shadow target is silent
 *   and cannot influence the main flow in any way;
 * - the dispatch is fire-and-forget on a fresh microtask: the main path
 *   never awaits it, and a shadow sender that throws synchronously
 *   becomes a recorded `shadow_failed`, never an unhandled rejection;
 * - each shadow target may carry its own `sender` — an independent copy
 *   (own keep-alive pools, own pinning/mTLS identity). When a target
 *   carries no dedicated sender, the mirrored copy is sent through the
 *   queue's main sender — still asynchronously and still outside every
 *   main-flow gate.
 *
 * Opt-in per endpoint (exact `targetUrl` match, the same convention as
 * `tlsPins`): endpoints without a configured list behave exactly as
 * before — zero behavior change when the feature is off. Invalid configs
 * throw `RangeError` at construction, never mid-delivery.
 *
 * Zero dependencies (`node:test`-free; pure logic + the `Sender` type).
 */

/**
 * One shadow downstream for a logical endpoint.
 */
export interface ShadowTargetConfig {
  /**
   * The shadow downstream URL — the mirrored copy goes here. Must be a
   * valid absolute `http:`/`https:` URL, and must differ from the logical
   * endpoint it shadows (mirroring an endpoint to itself would
   * double-deliver; rejected as a config bug).
   */
  targetUrl: string;
  /**
   * Dedicated sender for this shadow target: an independent copy of the
   * main sender (own pinning via `tlsPins`, own mTLS identity via
   * `tlsClientCerts` — independently configurable per target). When
   * unset, the mirrored copy is sent through the queue's main `sender`
   * (still asynchronous, still outside every main-flow gate).
   */
  sender?: Sender;
}

/**
 * Per-endpoint opt-in shadow targets: exact logical `targetUrl` ->
 * shadow target list. Endpoints absent from the record have no shadows.
 */
export type ShadowTargetsConfig = Record<string, ShadowTargetConfig[]>;

/**
 * Validate a shadow-target config the way a constructor would. Throws
 * `RangeError` on the first problem so a bad config fails at startup,
 * never mid-delivery. `undefined` (feature off) is valid.
 */
export function assertValidShadowTargets(config: ShadowTargetsConfig | undefined): void {
  if (config === undefined) return;
  if (config === null || typeof config !== "object" || Array.isArray(config)) {
    throw new RangeError("shadowTargets must be a record of targetUrl -> shadow target list");
  }
  for (const [endpoint, targets] of Object.entries(config)) {
    if (endpoint.length === 0) {
      throw new RangeError("shadowTargets keys must be non-empty endpoint URLs");
    }
    if (!Array.isArray(targets)) {
      throw new RangeError(
        `shadowTargets[${JSON.stringify(endpoint)}] must be an array of shadow targets`
      );
    }
    if (targets.length === 0) {
      throw new RangeError(
        `shadowTargets[${JSON.stringify(endpoint)}] must not be empty: refusing to configure an endpoint with zero shadow targets`
      );
    }
    const seen = new Set<string>();
    for (const target of targets) {
      assertValidShadowTarget(endpoint, target);
      if (seen.has(target.targetUrl)) {
        throw new RangeError(
          `shadowTargets[${JSON.stringify(endpoint)}] lists ${JSON.stringify(target.targetUrl)} twice: a shadow target must appear at most once per endpoint`
        );
      }
      seen.add(target.targetUrl);
    }
  }
}

function assertValidShadowTarget(endpoint: string, target: ShadowTargetConfig): void {
  const label = `shadowTargets[${JSON.stringify(endpoint)}]`;
  if (target === null || typeof target !== "object" || Array.isArray(target)) {
    throw new RangeError(`${label} entries must be objects with a targetUrl`);
  }
  if (typeof target.targetUrl !== "string" || target.targetUrl.length === 0) {
    throw new RangeError(`${label} entries need a non-empty string targetUrl`);
  }
  let protocol: string;
  try {
    protocol = new URL(target.targetUrl).protocol;
  } catch {
    throw new RangeError(`${label}: ${JSON.stringify(target.targetUrl)} is not a valid absolute URL`);
  }
  if (protocol !== "http:" && protocol !== "https:") {
    throw new RangeError(
      `${label}: shadow target ${JSON.stringify(target.targetUrl)} must be an http(s) URL (got ${protocol})`
    );
  }
  if (target.targetUrl === endpoint) {
    throw new RangeError(
      `${label}: shadow target must differ from the endpoint it shadows (${JSON.stringify(endpoint)}): mirroring an endpoint to itself would double-deliver`
    );
  }
  if (target.sender !== undefined && typeof target.sender !== "function") {
    throw new RangeError(`${label}: sender for ${JSON.stringify(target.targetUrl)} must be a function`);
  }
}

/** Fired when a mirrored copy reaches a shadow target (transport success). */
export interface ShadowDeliveredInfo {
  event: "shadow_delivered";
  /** The main delivery's id. */
  id: string;
  /** End-to-end trace ID of the main delivery. */
  traceId: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  /** The logical endpoint (the configured primary `targetUrl`). */
  endpoint: string;
  /** The shadow downstream URL that received the mirrored copy. */
  shadowTarget: string;
  /** Main attempts consumed so far, including the mirrored attempt (1-based, like `delivered`). */
  attempts: number;
}

/** Fired when a mirrored copy fails to reach a shadow target. Silent by design — never retried. */
export interface ShadowFailedInfo extends Omit<ShadowDeliveredInfo, "event"> {
  event: "shadow_failed";
  /** The shadow failure message. */
  error: string;
}

/** Per-(tenant, endpoint, shadow target) mirror counters. */
export interface ShadowTargetStats {
  /** The logical endpoint (the configured primary `targetUrl`). */
  endpoint: string;
  /** Tenant id (WR-48); absent for the default tenant. */
  tenant?: string;
  /** The shadow downstream URL. */
  shadowTarget: string;
  /** Cumulative mirrored copies the shadow target answered (transport success). */
  delivered: number;
  /** Cumulative mirrored copies that failed (any error — silent, never retried). */
  failed: number;
}

/** Hooks for {@link ShadowDispatcher}. */
export interface ShadowDispatcherOptions {
  /** Fallback sender for shadow targets without a dedicated `sender`. */
  sender: Sender;
  /** Called once per mirrored copy a shadow target answers. */
  onDelivered?: (info: ShadowDeliveredInfo) => void;
  /** Called once per mirrored copy a shadow target fails. Never retried. */
  onFailed?: (info: ShadowFailedInfo) => void;
}

/**
 * Owns the per-endpoint shadow target lists and performs the
 * fire-and-forget mirroring. The queue calls `mirror()` once per main
 * attempt, right after the attempt's sender promise settles (success or
 * failure); everything from there is detached from the main flow.
 */
export class ShadowDispatcher {
  private readonly targets = new Map<string, ShadowTargetConfig[]>();
  private readonly sender: Sender;
  private readonly onDelivered?: (info: ShadowDeliveredInfo) => void;
  private readonly onFailed?: (info: ShadowFailedInfo) => void;
  /**
   * Mirror counters, keyed by JSON of [tenant, endpoint, shadowTarget]
   * (`""` tenant = the default tenant). Rows are created on the first recorded
   * outcome, so `stats()` is empty until a shadow copy actually lands —
   * the same activity-gating convention as the other optional series.
   */
  private readonly counters = new Map<
    string,
    { endpoint: string; tenant?: string; shadowTarget: string; delivered: number; failed: number }
  >();

  constructor(config: ShadowTargetsConfig, opts: ShadowDispatcherOptions) {
    // Fail-fast: an invalid shadow config is a misconfiguration, never a
    // mid-delivery surprise.
    assertValidShadowTargets(config);
    for (const [endpoint, targets] of Object.entries(config)) {
      this.targets.set(endpoint, [...targets]);
    }
    this.sender = opts.sender;
    this.onDelivered = opts.onDelivered;
    this.onFailed = opts.onFailed;
  }

  /** Whether `endpoint` has any shadow targets configured. */
  hasTargets(endpoint: string): boolean {
    return this.targets.has(endpoint);
  }

  /**
   * Mirror one completed main attempt to every shadow target of
   * `endpoint`. Fire-and-forget: the returned promise is intentionally
   * not awaited by the caller, the dispatch runs on a fresh microtask so
   * the main path never waits, and every outcome — success or failure —
   * is recorded only in the shadow counters and hooks. Nothing here
   * touches the retry budget, the dead-letter list, the circuit breaker,
   * the quota, or the main delivery counters.
   *
   * `wire` is the exact item the main attempt sent (payload, headers,
   * 0-based `attempt` index); each shadow target gets a copy with only
   * `targetUrl` swapped, so an independent sender copy rebuilds the
   * identical wire request (signature, idempotency key, compression).
   */
  mirror(
    endpoint: string,
    wire: RetryItem,
    tenant: string | undefined,
    traceId: string,
    attempts: number
  ): void {
    const targets = this.targets.get(endpoint);
    if (targets === undefined) return;
    for (const target of targets) {
      const shadowItem: RetryItem = { ...wire, targetUrl: target.targetUrl };
      const send = target.sender ?? this.sender;
      // Detached microtask: the main path never waits for the shadow
      // copy, and a sender that throws synchronously becomes a recorded
      // `shadow_failed` instead of an unhandled rejection or a main-flow
      // throw.
      void Promise.resolve()
        .then(() => send(shadowItem))
        .then(
          () => this.record(endpoint, target.targetUrl, shadowItem, tenant, traceId, attempts, true),
          (err: unknown) =>
            this.record(endpoint, target.targetUrl, shadowItem, tenant, traceId, attempts, false, err)
        );
    }
  }

  private record(
    endpoint: string,
    shadowTarget: string,
    item: RetryItem,
    tenant: string | undefined,
    traceId: string,
    attempts: number,
    ok: boolean,
    err?: unknown
  ): void {
    const key = JSON.stringify([tenant ?? "", endpoint, shadowTarget]);
    let c = this.counters.get(key);
    if (c === undefined) {
      c = {
        endpoint,
        ...(tenant === undefined ? {} : { tenant }),
        shadowTarget,
        delivered: 0,
        failed: 0,
      };
      this.counters.set(key, c);
    }
    if (ok) {
      c.delivered += 1;
      this.onDelivered?.({
        event: "shadow_delivered",
        id: item.id,
        traceId,
        ...(tenant === undefined ? {} : { tenant }),
        endpoint,
        shadowTarget,
        attempts,
      });
    } else {
      c.failed += 1;
      this.onFailed?.({
        event: "shadow_failed",
        id: item.id,
        traceId,
        ...(tenant === undefined ? {} : { tenant }),
        endpoint,
        shadowTarget,
        attempts,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  /** Per-(tenant, endpoint, shadow target) mirror counters, in first-seen order. */
  stats(): ShadowTargetStats[] {
    return [...this.counters.values()];
  }
}
