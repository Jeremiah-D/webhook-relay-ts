/**
 * Dynamic endpoint registry (WR-114).
 *
 * Long-lived relay operators need to manage the *set* of downstream
 * endpoints — not just tune one endpoint's knobs (WR-32) — without
 * restarting the process: registering a new downstream with its full
 * delivery policy, rotating a proxy or TLS pins, or retiring an endpoint
 * once its in-flight deliveries have drained.
 *
 * `EndpointRegistry` is the in-memory store for those endpoint records:
 *
 * - `EndpointConfig` — one endpoint's full configuration: `targetUrl`
 *   plus per-endpoint overrides for the outbound signing identity
 *   (`verifier`, mirroring `OutboundSigningConfig`), circuit-breaker
 *   thresholds, quota, `maxConcurrentPerEndpoint`, outbound `proxy`,
 *   `tlsPins`, and `ordered` delivery.
 * - Startup validation is total: the constructor validates *every*
 *   record before inserting *any* of them — an illegal value throws
 *   `RangeError` and the registry stays empty (zero partial
 *   application). The server applies the same rule to the
 *   deliver-policy fields it pushes into the `RetryQueue`.
 * - Runtime CRUD (`create` / `update` / `remove`) validates before
 *   mutating, so a 400 from the operator API always means "nothing
 *   changed".
 * - The registry is a *config overlay*: it never owns deliveries. The
 *   delivery-policy fields (`maxConcurrentPerEndpoint`,
 *   `circuitBreaker`, `quota`) are applied through
 *   `RetryQueue.updateEndpointConfig`, which carries the WR-32
 *   hot-reload semantics — in-flight deliveries keep the config they
 *   started with; only future scheduling decisions see the new values.
 *   The sender-side fields (`verifier`, `proxy`, `tlsPins`) resolve per
 *   delivery attempt inside the default sender, so an attempt already
 *   on the wire is likewise unaffected by a mid-flight registry change.
 *   `ordered` is startup-only: the queue builds its ordered-delivery
 *   tracker once at construction, so enabling it at runtime cannot be
 *   done safely — the operator API rejects runtime `ordered` changes
 *   with a clear error.
 *
 * Secrets never leave the registry: `list()` and the change summaries
 * expose metadata only (a verifier renders as `{ keyId }`, never the
 * secret bytes).
 *
 * Zero dependencies (pure data + validation).
 */

import {
  assertValidEndpointConfigPatch,
  type CircuitBreakerPatch,
  type QuotaPatch,
} from "./hotreload.ts";
import { assertValidProxyUrl } from "./proxy.ts";
import { assertValidPins } from "./pinning.ts";
import { assertValidOrderedConfig } from "./ordered.ts";

/** Per-endpoint outbound signing identity (WR-114 `verifier`). */
export interface EndpointVerifierConfig {
  /**
   * HMAC secret used to sign outbound payloads to this endpoint —
   * replaces the server-global `outboundSigning` for this endpoint.
   * Non-empty. Never exposed through the registry's metadata views.
   */
  secret: string;
  /** Stable key identifier surfaced in the `x-relay-key-id` header. */
  keyId?: string;
}

/** Per-endpoint ordered-delivery configuration (WR-114 `ordered`). */
export interface EndpointOrderedConfig {
  /**
   * Master switch. `true` orders this endpoint's deliveries
   * (head-of-line blocking); `false` leaves it explicitly unordered.
   */
  enabled: boolean;
  /**
   * Poison-message bound in ms (see `src/ordered.ts`). Finite > 0, or
   * `Infinity` (default) for strict ordering with no timeout.
   */
  maxHeadOfLineHoldMs?: number;
}

/**
 * One endpoint's full configuration, as accepted by the registry and
 * the operator API. `id` is optional on input and defaults to
 * `targetUrl`.
 */
export interface EndpointConfig {
  /** Registry id. Defaults to `targetUrl` when omitted. */
  id?: string;
  /** Downstream URL (`http:`, `https:`, `ws:`, or `wss:`). */
  targetUrl: string;
  /** Per-endpoint outbound signing override (replaces global `outboundSigning`). */
  verifier?: EndpointVerifierConfig;
  /** Per-endpoint circuit-breaker thresholds (requires the breaker enabled). */
  circuitBreaker?: CircuitBreakerPatch;
  /** Per-endpoint quota limit (requires quota enabled). */
  quota?: QuotaPatch;
  /** Per-endpoint concurrency limit: positive integer, or `Infinity`. */
  maxConcurrentPerEndpoint?: number;
  /** Per-endpoint outbound proxy URL (plain-HTTP proxy; replaces static `proxies` entry). */
  proxy?: string;
  /** Per-endpoint SPKI TLS pin whitelist (replaces the static `tlsPins` entry). */
  tlsPins?: string[];
  /**
   * Per-endpoint ordered delivery. Startup-only: the operator API
   * rejects runtime changes to this field (the queue builds its
   * ordered-delivery tracker once at construction).
   */
  ordered?: EndpointOrderedConfig;
}

/** A stored endpoint record — `id` always resolved. */
export interface EndpointRecord extends Omit<EndpointConfig, "id"> {
  id: string;
}

/** Public metadata for one endpoint: everything except secrets. */
export interface EndpointSummary {
  id: string;
  targetUrl: string;
  /** Present when a verifier is configured; carries `keyId` only, never the secret. */
  verifier?: { keyId?: string };
  circuitBreaker?: CircuitBreakerPatch;
  quota?: QuotaPatch;
  maxConcurrentPerEndpoint?: number;
  proxy?: string;
  tlsPins?: string[];
  ordered?: EndpointOrderedConfig;
}

/** One field-level change, for audit/observability (no secrets). */
export interface EndpointConfigChange {
  /** Dotted field name, e.g. `circuitBreaker.failureThreshold`. */
  field: string;
  /** Value before the change (`null` on create). Secrets render as `"[redacted]"`. */
  from: unknown;
  /** Value after the change (`null` on delete). Secrets render as `"[redacted]"`. */
  to: unknown;
}

/** Schemes a registry endpoint may target. */
const ENDPOINT_SCHEMES = new Set(["http:", "https:", "ws:", "wss:"]);

function describeValue(value: unknown): string {
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number" || typeof value === "boolean" || value === null) {
    return String(value);
  }
  if (Array.isArray(value)) return `array[${value.length}]`;
  return typeof value;
}

/**
 * Validate a registry id: a non-empty string. Slashes are allowed (the
 * default id *is* the `targetUrl`, which contains them); the ids
 * `pause`, `resume`, and `enable` are reserved by the
 * `/endpoints/pause`, `/endpoints/resume`, and `/endpoints/enable`
 * operator routes and can never address a record.
 */
export function assertValidEndpointId(id: unknown): asserts id is string {
  if (typeof id !== "string" || id.length === 0) {
    throw new RangeError(
      `endpoint registry: \`id\` must be a non-empty string, got ${describeValue(id)}`
    );
  }
  if (id === "pause" || id === "resume" || id === "enable") {
    throw new RangeError(
      `endpoint registry: \`id\` ${JSON.stringify(id)} is reserved by the operator API`
    );
  }
}

/** Validate a registry target URL. */
export function assertValidEndpointTargetUrl(targetUrl: unknown): asserts targetUrl is string {
  if (typeof targetUrl !== "string" || targetUrl.length === 0) {
    throw new RangeError(
      `endpoint registry: \`targetUrl\` must be a non-empty string, got ${describeValue(targetUrl)}`
    );
  }
  let protocol: string;
  try {
    protocol = new URL(targetUrl).protocol;
  } catch {
    throw new RangeError(
      `endpoint registry: \`targetUrl\` is not a valid URL: ${JSON.stringify(targetUrl)}`
    );
  }
  if (!ENDPOINT_SCHEMES.has(protocol)) {
    throw new RangeError(
      `endpoint registry: \`targetUrl\` must use http:, https:, ws:, or wss: (got ${protocol})`
    );
  }
}

function assertValidVerifierConfig(value: unknown): void {
  if (value === undefined) return;
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new RangeError(
      `endpoint registry: \`verifier\` must be an object, got ${describeValue(value)}`
    );
  }
  const v = value as Record<string, unknown>;
  if (typeof v.secret !== "string" || v.secret === "") {
    throw new RangeError("endpoint registry: `verifier.secret` must be a non-empty string");
  }
  if (v.keyId !== undefined && (typeof v.keyId !== "string" || v.keyId === "")) {
    throw new RangeError("endpoint registry: `verifier.keyId` must be a non-empty string");
  }
}

function assertValidOrderedField(value: unknown): void {
  if (value === undefined) return;
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new RangeError(
      `endpoint registry: \`ordered\` must be an object, got ${describeValue(value)}`
    );
  }
  const o = value as Record<string, unknown>;
  if (typeof o.enabled !== "boolean") {
    throw new RangeError(
      `endpoint registry: \`ordered.enabled\` must be a boolean, got ${describeValue(o.enabled)}`
    );
  }
  if (o.maxHeadOfLineHoldMs !== undefined) {
    const ms = o.maxHeadOfLineHoldMs;
    if (!(typeof ms === "number" && (ms === Infinity || (Number.isFinite(ms) && ms > 0)))) {
      throw new RangeError(
        "endpoint registry: `ordered.maxHeadOfLineHoldMs` must be a finite number > 0 or Infinity"
      );
    }
  }
  // Reuse the module's own structural validation for the shared shape.
  assertValidOrderedConfig({ enabled: o.enabled, maxHeadOfLineHoldMs: o.maxHeadOfLineHoldMs });
}

/**
 * Validate a full endpoint config. Throws `RangeError` on the first
 * illegal value. Does not mutate anything — call this before applying.
 */
export function assertValidEndpointConfig(config: unknown): asserts config is EndpointConfig {
  if (typeof config !== "object" || config === null || Array.isArray(config)) {
    throw new RangeError(
      `endpoint registry: config must be an object, got ${describeValue(config)}`
    );
  }
  const c = config as Record<string, unknown>;
  if (c.id !== undefined) assertValidEndpointId(c.id);
  assertValidEndpointTargetUrl(c.targetUrl);
  assertValidVerifierConfig(c.verifier);
  // The deliver-policy fields share WR-32's validation verbatim, so the
  // registry and `updateEndpointConfig` can never disagree about what is
  // legal. Unknown top-level fields are rejected below, not here.
  assertValidEndpointConfigPatch({
    ...(c.maxConcurrentPerEndpoint !== undefined
      ? { maxConcurrentPerEndpoint: c.maxConcurrentPerEndpoint }
      : {}),
    ...(c.circuitBreaker !== undefined ? { circuitBreaker: c.circuitBreaker } : {}),
    ...(c.quota !== undefined ? { quota: c.quota } : {}),
  });
  if (c.proxy !== undefined) {
    if (typeof c.proxy !== "string") {
      throw new RangeError(
        `endpoint registry: \`proxy\` must be a string, got ${describeValue(c.proxy)}`
      );
    }
    try {
      assertValidProxyUrl(c.proxy);
    } catch (err) {
      throw new RangeError(
        `endpoint registry: invalid \`proxy\` URL: ${(err as Error).message}`
      );
    }
  }
  if (c.tlsPins !== undefined) {
    if (!Array.isArray(c.tlsPins)) {
      throw new RangeError(
        `endpoint registry: \`tlsPins\` must be an array of pins, got ${describeValue(c.tlsPins)}`
      );
    }
    try {
      assertValidPins(c.tlsPins as string[]);
    } catch (err) {
      throw new RangeError(
        `endpoint registry: invalid \`tlsPins\`: ${(err as Error).message}`
      );
    }
  }
  assertValidOrderedField(c.ordered);
  const known = new Set([
    "id",
    "targetUrl",
    "verifier",
    "circuitBreaker",
    "quota",
    "maxConcurrentPerEndpoint",
    "proxy",
    "tlsPins",
    "ordered",
  ]);
  for (const key of Object.keys(c)) {
    if (!known.has(key)) {
      throw new RangeError(
        `endpoint registry: unknown config field ${JSON.stringify(key)}`
      );
    }
  }
}

/** The deliver-policy subset that flows through `RetryQueue.updateEndpointConfig` (WR-32). */
export function deliverPolicyPatch(config: EndpointConfig): {
  maxConcurrentPerEndpoint?: number;
  circuitBreaker?: CircuitBreakerPatch;
  quota?: QuotaPatch;
} {
  return {
    ...(config.maxConcurrentPerEndpoint !== undefined
      ? { maxConcurrentPerEndpoint: config.maxConcurrentPerEndpoint }
      : {}),
    ...(config.circuitBreaker !== undefined ? { circuitBreaker: config.circuitBreaker } : {}),
    ...(config.quota !== undefined ? { quota: config.quota } : {}),
  };
}

/** True when the config carries any deliver-policy field. */
export function hasDeliverPolicy(config: EndpointConfig): boolean {
  return (
    config.maxConcurrentPerEndpoint !== undefined ||
    config.circuitBreaker !== undefined ||
    config.quota !== undefined
  );
}

const REDACTED = "[redacted]";

function redactSecrets(value: unknown, field: string): unknown {
  if (field === "verifier.secret") return REDACTED;
  return value;
}

function flattenConfig(config: EndpointConfig): Array<[string, unknown]> {
  const out: Array<[string, unknown]> = [];
  out.push(["targetUrl", config.targetUrl]);
  if (config.verifier !== undefined) {
    out.push(["verifier.secret", config.verifier.secret]);
    if (config.verifier.keyId !== undefined) out.push(["verifier.keyId", config.verifier.keyId]);
  }
  if (config.circuitBreaker !== undefined) {
    for (const [k, v] of Object.entries(config.circuitBreaker)) {
      if (v !== undefined) out.push([`circuitBreaker.${k}`, v]);
    }
  }
  if (config.quota !== undefined) {
    for (const [k, v] of Object.entries(config.quota)) {
      if (v !== undefined) out.push([`quota.${k}`, v]);
    }
  }
  if (config.maxConcurrentPerEndpoint !== undefined) {
    out.push(["maxConcurrentPerEndpoint", config.maxConcurrentPerEndpoint]);
  }
  if (config.proxy !== undefined) out.push(["proxy", config.proxy]);
  if (config.tlsPins !== undefined) out.push(["tlsPins", config.tlsPins]);
  if (config.ordered !== undefined) {
    out.push(["ordered.enabled", config.ordered.enabled]);
    if (config.ordered.maxHeadOfLineHoldMs !== undefined) {
      out.push(["ordered.maxHeadOfLineHoldMs", config.ordered.maxHeadOfLineHoldMs]);
    }
  }
  return out;
}

/**
 * Field-level diff between two configs, for the `endpoint_config_updated`
 * audit. Secrets render as `"[redacted]"` — the audit proves *that* the
 * secret changed, never *what* it changed to.
 */
export function diffEndpointConfigs(
  oldConfig: EndpointConfig | null,
  newConfig: EndpointConfig | null
): EndpointConfigChange[] {
  const oldFields = new Map(oldConfig === null ? [] : flattenConfig(oldConfig));
  const newFields = new Map(newConfig === null ? [] : flattenConfig(newConfig));
  const changes: EndpointConfigChange[] = [];
  for (const [field, from] of oldFields) {
    if (!newFields.has(field)) {
      changes.push({ field, from: redactSecrets(from, field), to: null });
    } else {
      const to = newFields.get(field);
      if (JSON.stringify(from) !== JSON.stringify(to)) {
        changes.push({ field, from: redactSecrets(from, field), to: redactSecrets(to, field) });
      }
    }
  }
  for (const [field, to] of newFields) {
    if (!oldFields.has(field)) {
      changes.push({ field, from: null, to: redactSecrets(to, field) });
    }
  }
  return changes;
}

/** Public metadata for one record: everything except secrets. */
export function summarizeEndpointConfig(record: EndpointRecord): EndpointSummary {
  return {
    id: record.id,
    targetUrl: record.targetUrl,
    ...(record.verifier !== undefined
      ? {
          verifier: {
            ...(record.verifier.keyId !== undefined ? { keyId: record.verifier.keyId } : {}),
          },
        }
      : {}),
    ...(record.circuitBreaker !== undefined ? { circuitBreaker: record.circuitBreaker } : {}),
    ...(record.quota !== undefined ? { quota: record.quota } : {}),
    ...(record.maxConcurrentPerEndpoint !== undefined
      ? { maxConcurrentPerEndpoint: record.maxConcurrentPerEndpoint }
      : {}),
    ...(record.proxy !== undefined ? { proxy: record.proxy } : {}),
    ...(record.tlsPins !== undefined ? { tlsPins: record.tlsPins } : {}),
    ...(record.ordered !== undefined ? { ordered: record.ordered } : {}),
  };
}

function toRecord(config: EndpointConfig): EndpointRecord {
  const { id, ...rest } = config;
  return { ...rest, id: id ?? config.targetUrl };
}

/**
 * In-memory dynamic endpoint registry (WR-114).
 *
 * Every mutating method validates *before* mutating: a `RangeError`
 * always means "nothing changed". The registry itself is queue-agnostic
 * — the server wires the deliver-policy fields into
 * `RetryQueue.updateEndpointConfig` and the sender-side fields into the
 * default sender's per-attempt resolution.
 */
export class EndpointRegistry {
  private readonly records = new Map<string, EndpointRecord>();
  private readonly byTargetUrl = new Map<string, string>();

  /**
   * Build a registry from static startup config. Validates *all* records
   * before inserting *any*: the first illegal value throws `RangeError`
   * and the registry stays empty.
   */
  constructor(endpoints: EndpointConfig[] = []) {
    if (!Array.isArray(endpoints)) {
      throw new RangeError("endpoint registry: endpoints must be an array");
    }
    for (const config of endpoints) {
      assertValidEndpointConfig(config);
    }
    for (const config of endpoints) {
      this.insert(toRecord(config));
    }
  }

  private insert(record: EndpointRecord): void {
    if (this.records.has(record.id)) {
      throw new RangeError(
        `endpoint registry: duplicate endpoint id ${JSON.stringify(record.id)}`
      );
    }
    this.records.set(record.id, record);
    this.byTargetUrl.set(record.targetUrl, record.id);
  }

  /** Register a new endpoint. `id` defaults to `targetUrl`. */
  create(config: EndpointConfig): EndpointRecord {
    assertValidEndpointConfig(config);
    const record = toRecord(config);
    this.insert(record);
    return record;
  }

  /**
   * Update an endpoint's config. The patch is merged over the stored
   * record and the *merged* config is validated before anything is
   * swapped in. `id` cannot be changed through the patch (it is the
   * record's identity); `targetUrl` can. Throws `RangeError` for an
   * unknown id.
   */
  update(id: string, patch: Partial<EndpointConfig>): { old: EndpointRecord; new: EndpointRecord } {
    const current = this.records.get(id);
    if (current === undefined) {
      throw new RangeError(`endpoint registry: unknown endpoint id ${JSON.stringify(id)}`);
    }
    if (patch.id !== undefined && patch.id !== id) {
      throw new RangeError("endpoint registry: `id` is immutable; create a new endpoint instead");
    }
    const merged: EndpointConfig = { ...current, ...patch, id };
    assertValidEndpointConfig(merged);
    const next = toRecord(merged);
    this.byTargetUrl.delete(current.targetUrl);
    this.records.set(id, next);
    this.byTargetUrl.set(next.targetUrl, id);
    return { old: current, new: next };
  }

  /** Remove an endpoint. Returns the removed record, or `undefined` for an unknown id. */
  remove(id: string): EndpointRecord | undefined {
    const record = this.records.get(id);
    if (record === undefined) return undefined;
    this.records.delete(id);
    if (this.byTargetUrl.get(record.targetUrl) === id) {
      this.byTargetUrl.delete(record.targetUrl);
    }
    return record;
  }

  /** Look up a record by registry id. */
  get(id: string): EndpointRecord | undefined {
    return this.records.get(id);
  }

  /** Look up a record by exact `targetUrl` — the sender's resolution path. */
  getByTargetUrl(targetUrl: string): EndpointRecord | undefined {
    const id = this.byTargetUrl.get(targetUrl);
    return id === undefined ? undefined : this.records.get(id);
  }

  /** Per-endpoint outbound signing override for the sender (secret included — sender-internal). */
  getSigning(targetUrl: string): EndpointVerifierConfig | undefined {
    return this.getByTargetUrl(targetUrl)?.verifier;
  }

  /** Per-endpoint proxy override for the sender. */
  getProxy(targetUrl: string): string | undefined {
    return this.getByTargetUrl(targetUrl)?.proxy;
  }

  /** Per-endpoint TLS pin override for the sender. */
  getTlsPins(targetUrl: string): string[] | undefined {
    return this.getByTargetUrl(targetUrl)?.tlsPins;
  }

  /** Metadata for every endpoint, in registration order. No secrets. */
  list(): EndpointSummary[] {
    return [...this.records.values()].map(summarizeEndpointConfig);
  }

  /** Number of registered endpoints. */
  size(): number {
    return this.records.size;
  }
}

/** Live concurrency counters per endpoint, for the drain check. */
export interface EndpointConcurrencyRow {
  endpoint: string;
  inFlight: number;
  queued: number;
}

export interface DrainOptions {
  /** How long to wait for the drain before giving up. Default: 30_000 ms. */
  timeoutMs?: number;
  /** Poll interval between checks. Default: 50 ms. */
  pollIntervalMs?: number;
  /** Sleep implementation; injectable for deterministic tests. */
  sleep?: (ms: number) => Promise<void>;
}

export interface DrainResult {
  /** True when the endpoint reached zero in-flight + queued deliveries. */
  drained: boolean;
  /** Deliveries still in flight or queued for a slot when the wait ended. */
  remaining: number;
  /** Milliseconds waited. */
  waitedMs: number;
}

const defaultSleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Wait until an endpoint has no in-flight or slot-queued deliveries.
 * Polls `readStats` (the queue's `getConcurrencyStats`) until the
 * endpoint's counters hit zero or `timeoutMs` elapses. Never rejects on
 * timeout — it reports `{ drained: false, remaining }` and lets the
 * caller decide (the operator API answers 409 suggesting `force`).
 */
export async function waitForEndpointDrain(
  readStats: () => EndpointConcurrencyRow[],
  targetUrl: string,
  opts: DrainOptions = {}
): Promise<DrainResult> {
  const timeoutMs = opts.timeoutMs ?? 30_000;
  const pollIntervalMs = opts.pollIntervalMs ?? 50;
  const sleep = opts.sleep ?? defaultSleep;
  if (!(timeoutMs > 0) || !Number.isFinite(timeoutMs)) {
    throw new RangeError("waitForEndpointDrain: `timeoutMs` must be a finite number > 0");
  }
  if (!(pollIntervalMs > 0) || !Number.isFinite(pollIntervalMs)) {
    throw new RangeError("waitForEndpointDrain: `pollIntervalMs` must be a finite number > 0");
  }
  const startedAt = Date.now();
  for (;;) {
    let remaining = 0;
    for (const row of readStats()) {
      if (row.endpoint === targetUrl) {
        remaining += row.inFlight + row.queued;
      }
    }
    if (remaining === 0) {
      return { drained: true, remaining: 0, waitedMs: Date.now() - startedAt };
    }
    if (Date.now() - startedAt >= timeoutMs) {
      return { drained: false, remaining, waitedMs: Date.now() - startedAt };
    }
    await sleep(Math.min(pollIntervalMs, timeoutMs - (Date.now() - startedAt)));
  }
}
