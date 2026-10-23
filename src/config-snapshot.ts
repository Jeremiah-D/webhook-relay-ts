/**
 * Declarative operator config snapshots: export / apply / rollback /
 * drift detection (WR-88).
 *
 * Long-lived relay operators tune delivery policy at runtime through
 * `RetryQueue.updateEndpointConfig` (WR-32, imperative, per-endpoint).
 * This module adds the declarative layer on top:
 *
 * - `exportConfig(queue, env)` captures a JSON-safe snapshot of the
 *   current hot-reloadable config (per-(tenant, endpoint) concurrency
 *   limit, circuit-breaker thresholds, quota budget, weighted targets,
 *   plus the queue-global backoff parameters) and a declarative
 *   *inventory* of the non-hot-reloadable wiring (content-routing rules,
 *   signing-key inventory, mTLS certificate identities, TLS pins, proxy
 *   presence, outbound compression, observed tenants).
 * - `applyConfig(queue, snapshot, { dryRun })` diffs a snapshot against
 *   the live config and converges the hot-reloadable subset item by
 *   item: value changes go through `updateEndpointConfig`, and overrides
 *   the snapshot no longer carries are removed again (falling back to
 *   the queue defaults). If any step throws mid-apply, every
 *   already-applied item is rolled back to its exact pre-apply state
 *   and a `ConfigApplyError` is thrown.
 * - `detectConfigDrift(queue, snapshot, env)` reports the live-vs-
 *   snapshot diff without touching anything.
 *
 * Fail-closed secret handling: snapshots carry an *inventory* of keys
 * and certificates — identifiers only, never key bytes. `applyConfig`
 * refuses (zero mutation) any snapshot that claims to carry secret
 * material, and refuses any apply whose live secret-bearing inventory
 * (signing keys, mTLS identities, proxies) diverged from the snapshot —
 * those dimensions need a restart or a key-rotation ceremony, never a
 * config restore.
 *
 * `Infinity` concurrency limits are encoded as the string `"Infinity"`
 * so snapshots stay valid JSON; `applyConfig` decodes them back.
 */

import type {
  RetryQueue,
  EndpointConfigState,
  JitterStrategy,
} from "./retry.ts";
import {
  assertValidEndpointConfigPatch,
  type EndpointConfigPatch,
} from "./hotreload.ts";
import { tenantScopeKey, splitTenantScopeKey } from "./tenant.ts";
import type { WeightedTargetConfig } from "./weighted.ts";

/** Snapshot envelope discriminator. */
export const CONFIG_SNAPSHOT_FORMAT = "webhook-relay/config-snapshot";
/** Current snapshot schema version. */
export const CONFIG_SNAPSHOT_VERSION = 1;

/** One endpoint's hot-reloadable config, JSON-safe. */
export interface EndpointConfigSnapshot {
  /** Effective limit; `"Infinity"` encodes an unlimited endpoint. */
  maxConcurrentPerEndpoint: number | "Infinity";
  /** Present only when the endpoint carries a threshold override. */
  circuitBreaker?: { failureThreshold: number; cooldownMs: number };
  /** Present only when the endpoint carries a quota override. */
  quota?: { deliveriesPerMinute: number };
  /** Present only when weighted dispatch is enabled for the endpoint. */
  weighted?: { targets: WeightedTargetConfig[] };
}

/** Queue-global backoff parameters, JSON-safe. */
export interface RetryConfigSnapshot {
  baseDelayMs: number;
  maxDelayMs: number;
  maxAttempts: number;
  jitterMs: number;
  jitterStrategy: JitterStrategy;
}

/**
 * Declarative inventory of the wiring `updateEndpointConfig` cannot
 * hot-reload. Identifiers only — never key bytes, PEM blocks, or proxy
 * credentials. Used for drift visibility; `applyConfig` never applies
 * these and refuses (fail-closed) when a secret-bearing dimension
 * diverged.
 */
export interface ConfigSnapshotInventory {
  /** Content-routing rules (WR-84), or null when routing is disabled. */
  routing: { rules: unknown[]; defaultTargetUrl?: string } | null;
  /** Signing-key inventory: key ids only, never the HMAC secrets (WR-20). */
  signingKeys: Array<{ id: string }>;
  /** Per-endpoint mTLS client-cert identity (sha256 fingerprint), no PEM. */
  mtls: Record<string, { certIdentity: string }>;
  /** Per-endpoint SPKI pin whitelist (public fingerprints, WR-21). */
  tlsPins: Record<string, string[]>;
  /** Per-endpoint proxy presence — never the proxy URL or credentials. */
  proxies: Record<string, { configured: boolean; hasCredentials: boolean }>;
  /** Per-endpoint outbound compression settings. */
  compression: Record<string, { thresholdBytes?: number }>;
  /** Tenant ids observed in the queue's configured keyspace (WR-48). */
  tenants: string[];
  /**
   * Revoked inbound API key ids (WR-156): id-only, never key bytes.
   * Grouped by the rule's exact `pattern`; sorted by (pattern, keyId).
   * Append-only: revocation never un-applies, so a snapshot can only
   * add revocations the live config lacks. Optional so pre-WR-156
   * inventory readers keep validating — absent means "no revocations".
   */
  revokedApiKeys?: Array<{ pattern: string; keyIds: string[] }>;
  /**
   * Revoked operator key ids (WR-156): id-only, never key bytes,
   * sorted. Append-only, same one-way rule; optional, same as above.
   */
  revokedOperatorKeys?: string[];
}

/** A declarative config snapshot. */
export interface ConfigSnapshot {
  format: typeof CONFIG_SNAPSHOT_FORMAT;
  version: 1;
  /** Wall-clock ms when the snapshot was taken. */
  takenAtMs: number;
  retry: RetryConfigSnapshot;
  /** Keyed by `tenantScopeKey(tenant, endpoint)`. */
  endpoints: Record<string, EndpointConfigSnapshot>;
  /** Null when no inventory provider was supplied. */
  inventory: ConfigSnapshotInventory | null;
}

/** Environment for snapshot operations (server-supplied). */
export interface ConfigSnapshotEnv {
  /** Declarative inventory reader. Omit for queue-only snapshots. */
  readInventory?: () => ConfigSnapshotInventory;
  /** Audit sink; receives `config_applied` / `config_rolled_back`. */
  audit?: (event: Record<string, unknown>) => void;
  /** Clock for `takenAtMs`; defaults to `Date.now`. */
  nowMs?: () => number;
  /**
   * Revoke an inbound API key at runtime (WR-156). Required to apply
   * `inventory.revokedApiKeys` diffs; a missing hook refuses the apply
   * (`unsupported`). Returns true when the key was newly revoked.
   */
  revokeApiKey?: (rulePattern: string, keyId: string) => boolean;
  /**
   * Revoke an operator key at runtime (WR-156). Required to apply
   * `inventory.revokedOperatorKeys` diffs. Returns true when newly
   * revoked.
   */
  revokeOperatorKey?: (id: string) => boolean;
}

/** One live-vs-snapshot difference. */
export interface ConfigDiffItem {
  /**
   * `"queue"` for queue-global retry fields, a `tenantScopeKey` for
   * endpoint fields, `"inventory"` for declarative inventory fields.
   */
  scope: string;
  /**
   * Dotted field path for value changes (e.g. `retry.baseDelayMs`,
   * `circuitBreaker.failureThreshold`); the section name for removals
   * (e.g. `circuitBreaker`, `quota`).
   */
  field: string;
  /** Live value. */
  from: unknown;
  /** Snapshot value (`null` for removals). */
  to: unknown;
  /** True when the item applies through the imperative setter path. */
  appliable: boolean;
  /** True when the item concerns secret/cert material (fail-closed). */
  secretBearing: boolean;
  /**
   * True when the snapshot carries no value for a live override: applying
   * removes the override so the endpoint falls back to the queue default.
   */
  removal?: boolean;
}

/** One item applied (or rolled back) through the imperative setter. */
export interface ConfigApplyItem {
  scope: string;
  field: string;
  from: unknown;
  to: unknown;
}

export type ConfigApplyErrorKind =
  | "invalid_snapshot"
  | "secret_material_refused"
  | "unsupported"
  | "apply_failed";

/**
 * Thrown by `applyConfig` when a snapshot cannot be applied. Nothing is
 * partially applied: `invalid_snapshot`, `secret_material_refused`, and
 * `unsupported` throw before any mutation; `apply_failed` throws after
 * rolling `applied` back to the pre-apply state (see `rolledBack`).
 */
export class ConfigApplyError extends Error {
  readonly kind: ConfigApplyErrorKind;
  /** Diff items relevant to the failure (the refused/offending ones). */
  readonly items: ConfigDiffItem[];
  /** Items that were applied before the failure (already rolled back). */
  readonly applied: ConfigApplyItem[];
  /** Items restored during rollback (subset of `applied`, best effort). */
  readonly rolledBack: ConfigApplyItem[];
  constructor(
    kind: ConfigApplyErrorKind,
    message: string,
    opts: {
      items?: ConfigDiffItem[];
      applied?: ConfigApplyItem[];
      rolledBack?: ConfigApplyItem[];
      cause?: unknown;
    } = {}
  ) {
    super(`config snapshot apply failed (${kind}): ${message}`);
    this.name = "ConfigApplyError";
    this.kind = kind;
    this.items = opts.items ?? [];
    this.applied = opts.applied ?? [];
    this.rolledBack = opts.rolledBack ?? [];
    if (opts.cause !== undefined) this.cause = opts.cause;
  }
}

/** Result of `applyConfig`. */
export interface ConfigApplyResult {
  dryRun: boolean;
  /** Items applied through the imperative setter (empty on dryRun). */
  applied: ConfigApplyItem[];
  /** The plan that would be applied (dryRun only; empty otherwise). */
  plan: ConfigDiffItem[];
  /** Declarative-only diffs needing out-of-band reconciliation. */
  pending: ConfigDiffItem[];
}

/** Key names that must never appear with secret material in a snapshot. */
const SECRET_FIELD_NAMES = new Set([
  "secret",
  "privateKey",
  "key",
  "cert",
  "passphrase",
]);

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function fail(kind: ConfigApplyErrorKind, message: string): never {
  throw new ConfigApplyError(kind, message);
}

/** Structural snapshot validation. Throws `ConfigApplyError`. */
function assertValidConfigSnapshot(snapshot: unknown): ConfigSnapshot {
  if (!isRecord(snapshot)) fail("invalid_snapshot", "snapshot must be a JSON object");
  const s = snapshot;
  const allowedTop = new Set([
    "format",
    "version",
    "takenAtMs",
    "retry",
    "endpoints",
    "inventory",
  ]);
  for (const k of Object.keys(s)) {
    if (!allowedTop.has(k)) fail("invalid_snapshot", `unknown top-level key ${JSON.stringify(k)}`);
  }
  if (s.format !== CONFIG_SNAPSHOT_FORMAT) {
    fail("invalid_snapshot", `bad format ${JSON.stringify(s.format)}`);
  }
  if (s.version !== CONFIG_SNAPSHOT_VERSION) {
    fail("invalid_snapshot", `unsupported version ${JSON.stringify(s.version)}`);
  }
  if (typeof s.takenAtMs !== "number" || !Number.isFinite(s.takenAtMs) || s.takenAtMs < 0) {
    fail("invalid_snapshot", "takenAtMs must be a finite number >= 0");
  }
  assertValidRetrySnapshot(s.retry);
  if (!isRecord(s.endpoints)) fail("invalid_snapshot", "endpoints must be an object");
  for (const [key, row] of Object.entries(s.endpoints as Record<string, unknown>)) {
    assertValidEndpointSnapshot(key, row);
  }
  if (s.inventory !== null) assertValidInventorySnapshot(s.inventory);
  return snapshot as ConfigSnapshot;
}

function assertValidRetrySnapshot(retry: unknown): void {
  if (!isRecord(retry)) fail("invalid_snapshot", "retry must be an object");
  const r = retry;
  const num = (field: string, pred: (n: number) => boolean, what: string): void => {
    if (typeof r[field] !== "number" || !pred(r[field] as number)) {
      fail("invalid_snapshot", `retry.${field} must be ${what}`);
    }
  };
  num("baseDelayMs", (n) => Number.isFinite(n) && n > 0, "a finite number > 0");
  num("maxDelayMs", (n) => Number.isFinite(n) && n > 0, "a finite number > 0");
  num("maxAttempts", (n) => Number.isInteger(n) && n >= 1, "an integer >= 1");
  num("jitterMs", (n) => Number.isFinite(n) && n >= 0, "a finite number >= 0");
  if (r.jitterStrategy !== "additive" && r.jitterStrategy !== "full" && r.jitterStrategy !== "decorrelated") {
    fail("invalid_snapshot", 'retry.jitterStrategy must be "additive", "full" or "decorrelated"');
  }
  for (const k of Object.keys(r)) {
    if (!["baseDelayMs", "maxDelayMs", "maxAttempts", "jitterMs", "jitterStrategy"].includes(k)) {
      fail("invalid_snapshot", `unknown retry key ${JSON.stringify(k)}`);
    }
  }
}

function assertValidEndpointSnapshot(key: string, row: unknown): void {
  if (!isRecord(row)) fail("invalid_snapshot", `endpoints[${JSON.stringify(key)}] must be an object`);
  const r = row;
  for (const k of Object.keys(r)) {
    if (!["maxConcurrentPerEndpoint", "circuitBreaker", "quota", "weighted"].includes(k)) {
      fail("invalid_snapshot", `endpoints[${JSON.stringify(key)}] has unknown key ${JSON.stringify(k)}`);
    }
  }
  const limit = r.maxConcurrentPerEndpoint;
  const limitOk =
    limit === "Infinity" ||
    (typeof limit === "number" && Number.isInteger(limit) && limit >= 1);
  if (!limitOk) {
    fail(
      "invalid_snapshot",
      `endpoints[${JSON.stringify(key)}].maxConcurrentPerEndpoint must be a positive integer or "Infinity"`
    );
  }
  if (r.circuitBreaker !== undefined) {
    if (!isRecord(r.circuitBreaker)) {
      fail("invalid_snapshot", `endpoints[${JSON.stringify(key)}].circuitBreaker must be an object`);
    }
    const cb = r.circuitBreaker;
    if (
      typeof cb.failureThreshold !== "number" ||
      !Number.isInteger(cb.failureThreshold) ||
      cb.failureThreshold < 1
    ) {
      fail("invalid_snapshot", `endpoints[${JSON.stringify(key)}].circuitBreaker.failureThreshold must be an integer >= 1`);
    }
    if (typeof cb.cooldownMs !== "number" || !Number.isFinite(cb.cooldownMs) || cb.cooldownMs <= 0) {
      fail("invalid_snapshot", `endpoints[${JSON.stringify(key)}].circuitBreaker.cooldownMs must be a finite number > 0`);
    }
  }
  if (r.quota !== undefined) {
    if (!isRecord(r.quota)) {
      fail("invalid_snapshot", `endpoints[${JSON.stringify(key)}].quota must be an object`);
    }
    const q = r.quota;
    if (
      typeof q.deliveriesPerMinute !== "number" ||
      !Number.isFinite(q.deliveriesPerMinute) ||
      q.deliveriesPerMinute <= 0
    ) {
      fail("invalid_snapshot", `endpoints[${JSON.stringify(key)}].quota.deliveriesPerMinute must be a finite number > 0`);
    }
  }
  if (r.weighted !== undefined) {
    if (!isRecord(r.weighted) || !Array.isArray(r.weighted.targets)) {
      fail("invalid_snapshot", `endpoints[${JSON.stringify(key)}].weighted.targets must be an array`);
    }
    for (const t of r.weighted.targets as unknown[]) {
      if (
        !isRecord(t) ||
        typeof t.targetUrl !== "string" ||
        t.targetUrl.length === 0 ||
        typeof t.weight !== "number" ||
        !Number.isFinite(t.weight) ||
        t.weight <= 0
      ) {
        fail("invalid_snapshot", `endpoints[${JSON.stringify(key)}].weighted.targets entries must be { targetUrl, weight>0 }`);
      }
    }
  }
}

/**
 * Inventory validation with the fail-closed secret scan: any entry that
 * *claims* to carry key/cert material (a poisoned or hand-edited
 * snapshot) is refused as `secret_material_refused` — key bytes are
 * never restored from a snapshot.
 */
function assertValidInventorySnapshot(inventory: unknown): void {
  if (!isRecord(inventory)) fail("invalid_snapshot", "inventory must be an object or null");
  const inv = inventory;
  for (const k of Object.keys(inv)) {
    if (!["routing", "signingKeys", "mtls", "tlsPins", "proxies", "compression", "tenants", "revokedApiKeys", "revokedOperatorKeys"].includes(k)) {
      fail("invalid_snapshot", `unknown inventory key ${JSON.stringify(k)}`);
    }
  }
  const refuseSecrets = (where: string, obj: Record<string, unknown>): void => {
    for (const k of Object.keys(obj)) {
      if (SECRET_FIELD_NAMES.has(k)) {
        throw new ConfigApplyError(
          "secret_material_refused",
          `${where}: snapshot carries secret material under ${JSON.stringify(k)} — snapshots are inventory-only, key bytes are never restored`
        );
      }
    }
  };
  if (inv.routing !== null && inv.routing !== undefined) {
    if (!isRecord(inv.routing) || !Array.isArray(inv.routing.rules)) {
      fail("invalid_snapshot", "inventory.routing must be { rules } or null");
    }
    if (
      inv.routing.defaultTargetUrl !== undefined &&
      typeof inv.routing.defaultTargetUrl !== "string"
    ) {
      fail("invalid_snapshot", "inventory.routing.defaultTargetUrl must be a string");
    }
  }
  if (!Array.isArray(inv.signingKeys)) fail("invalid_snapshot", "inventory.signingKeys must be an array");
  for (const entry of inv.signingKeys as unknown[]) {
    if (!isRecord(entry)) fail("invalid_snapshot", "inventory.signingKeys entries must be objects");
    refuseSecrets("inventory.signingKeys", entry);
    if (typeof entry.id !== "string" || Object.keys(entry).length !== 1) {
      fail("invalid_snapshot", "inventory.signingKeys entries must be exactly { id } — key inventory only, never key bytes");
    }
  }
  for (const [section, value] of Object.entries({
    mtls: inv.mtls,
    tlsPins: inv.tlsPins,
    proxies: inv.proxies,
    compression: inv.compression,
  })) {
    if (!isRecord(value)) fail("invalid_snapshot", `inventory.${section} must be an object`);
  }
  for (const [endpoint, entry] of Object.entries(inv.mtls as Record<string, unknown>)) {
    if (!isRecord(entry)) fail("invalid_snapshot", `inventory.mtls[${JSON.stringify(endpoint)}] must be an object`);
    refuseSecrets(`inventory.mtls[${JSON.stringify(endpoint)}]`, entry);
    if (typeof entry.certIdentity !== "string" || Object.keys(entry).length !== 1) {
      fail("invalid_snapshot", `inventory.mtls[${JSON.stringify(endpoint)}] must be exactly { certIdentity }`);
    }
  }
  for (const [endpoint, entry] of Object.entries(inv.tlsPins as Record<string, unknown>)) {
    if (!Array.isArray(entry) || !entry.every((p) => typeof p === "string")) {
      fail("invalid_snapshot", `inventory.tlsPins[${JSON.stringify(endpoint)}] must be an array of strings`);
    }
  }
  for (const [endpoint, entry] of Object.entries(inv.proxies as Record<string, unknown>)) {
    if (!isRecord(entry)) fail("invalid_snapshot", `inventory.proxies[${JSON.stringify(endpoint)}] must be an object`);
    refuseSecrets(`inventory.proxies[${JSON.stringify(endpoint)}]`, entry);
    for (const k of Object.keys(entry)) {
      if (!["configured", "hasCredentials"].includes(k) || typeof entry[k] !== "boolean") {
        fail("invalid_snapshot", `inventory.proxies[${JSON.stringify(endpoint)}] allows only boolean { configured, hasCredentials } — never the proxy URL`);
      }
    }
    for (const v of Object.values(entry)) {
      if (typeof v === "string" && (v.includes("://") || v.includes("@"))) {
        throw new ConfigApplyError(
          "secret_material_refused",
          `inventory.proxies[${JSON.stringify(endpoint)}]: snapshot carries a proxy URL — inventory only, never restored`
        );
      }
    }
  }
  for (const [endpoint, entry] of Object.entries(inv.compression as Record<string, unknown>)) {
    if (!isRecord(entry)) fail("invalid_snapshot", `inventory.compression[${JSON.stringify(endpoint)}] must be an object`);
    if (
      entry.thresholdBytes !== undefined &&
      (typeof entry.thresholdBytes !== "number" ||
        !Number.isInteger(entry.thresholdBytes) ||
        entry.thresholdBytes < 1)
    ) {
      fail("invalid_snapshot", `inventory.compression[${JSON.stringify(endpoint)}].thresholdBytes must be a positive integer`);
    }
  }
  if (!Array.isArray(inv.tenants) || !inv.tenants.every((t) => typeof t === "string")) {
    fail("invalid_snapshot", "inventory.tenants must be an array of strings");
  }
  // WR-156: revoked-key inventory is id-only by construction — no key
  // bytes can hide here, but validate the shape anyway (fail-fast, and
  // applyConfig's revocation path trusts these rows to name real keys).
  // The keys are optional for backward compatibility: a pre-WR-156
  // inventory reader that omits them validates fine (absent = none).
  if (inv.revokedApiKeys !== undefined) {
    if (!Array.isArray(inv.revokedApiKeys)) {
      fail("invalid_snapshot", "inventory.revokedApiKeys must be an array");
    }
    for (const row of inv.revokedApiKeys as unknown[]) {
      if (
        !isRecord(row) ||
        typeof row.pattern !== "string" ||
        row.pattern === "" ||
        !Array.isArray(row.keyIds) ||
        !(row.keyIds as unknown[]).every((k) => typeof k === "string" && k !== "") ||
        Object.keys(row).length !== 2
      ) {
        fail(
          "invalid_snapshot",
          "inventory.revokedApiKeys entries must be exactly { pattern, keyIds: string[] } — id inventory only, never key bytes"
        );
      }
      refuseSecrets("inventory.revokedApiKeys", row);
    }
  }
  if (inv.revokedOperatorKeys !== undefined) {
    if (
      !Array.isArray(inv.revokedOperatorKeys) ||
      !(inv.revokedOperatorKeys as unknown[]).every((k) => typeof k === "string" && k !== "")
    ) {
      fail("invalid_snapshot", "inventory.revokedOperatorKeys must be an array of non-empty strings");
    }
  }
}

/**
 * Capture the current declarative config as a JSON-safe snapshot.
 * Pure read — never mutates the queue.
 */
export function exportConfig(queue: RetryQueue, env: ConfigSnapshotEnv = {}): ConfigSnapshot {
  const retry = queue.retryConfig();
  const endpoints: Record<string, EndpointConfigSnapshot> = {};
  for (const { tenant, endpoint } of queue.configuredEndpoints()) {
    endpoints[tenantScopeKey(tenant, endpoint)] = endpointStateToSnapshot(
      queue.endpointConfig(tenant, endpoint)
    );
  }
  return {
    format: CONFIG_SNAPSHOT_FORMAT,
    version: CONFIG_SNAPSHOT_VERSION,
    takenAtMs: (env.nowMs ?? Date.now)(),
    retry: { ...retry },
    endpoints,
    inventory: env.readInventory !== undefined ? env.readInventory() : null,
  };
}

function encodeLimit(v: number): number | "Infinity" {
  return v === Infinity ? "Infinity" : v;
}

/** Convert a live endpoint state to its JSON-safe snapshot row. */
function endpointStateToSnapshot(state: EndpointConfigState): EndpointConfigSnapshot {
  const row: EndpointConfigSnapshot = {
    maxConcurrentPerEndpoint: encodeLimit(state.maxConcurrentPerEndpoint),
  };
  if (state.circuitBreaker !== undefined) row.circuitBreaker = { ...state.circuitBreaker };
  if (state.quota !== undefined) row.quota = { ...state.quota };
  if (state.weighted !== undefined) {
    row.weighted = {
      targets: state.weighted.targets.map((t) => ({ targetUrl: t.targetUrl, weight: t.weight })),
    };
  }
  return row;
}

function deepEqual(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

type RemovalSection = "maxConcurrentPerEndpoint" | "circuitBreaker" | "quota" | "weighted";

/**
 * Diff the live endpoint config (read from the queue, so override
 * presence is exact) against the snapshot's desired state. `from` is the
 * live effective value; `to` is the snapshot value (`null` for removals —
 * the snapshot carries no override where live has one).
 */
function planEndpointDiffs(queue: RetryQueue, snapshot: ConfigSnapshot): ConfigDiffItem[] {
  const items: ConfigDiffItem[] = [];
  const liveScopes = new Map<string, { tenant?: string; endpoint: string }>();
  for (const e of queue.configuredEndpoints()) {
    liveScopes.set(tenantScopeKey(e.tenant, e.endpoint), e);
  }
  const scopes = new Set([...liveScopes.keys(), ...Object.keys(snapshot.endpoints)]);
  const push = (item: ConfigDiffItem): void => {
    items.push(item);
  };
  for (const scope of [...scopes].sort()) {
    const liveEntry = liveScopes.get(scope);
    const { tenant, endpoint } = liveEntry ?? splitTenantScopeKey(scope);
    const state = queue.endpointConfig(tenant, endpoint);
    const overrides = queue.endpointConfigOverrides(tenant, endpoint);
    const row = snapshot.endpoints[scope];

    // Concurrency limit.
    if (row === undefined) {
      if (overrides.maxConcurrentPerEndpoint) {
        push({ scope, field: "maxConcurrentPerEndpoint", from: encodeLimit(state.maxConcurrentPerEndpoint), to: null, appliable: true, secretBearing: false, removal: true });
      }
    } else if (!deepEqual(encodeLimit(state.maxConcurrentPerEndpoint), row.maxConcurrentPerEndpoint)) {
      push({ scope, field: "maxConcurrentPerEndpoint", from: encodeLimit(state.maxConcurrentPerEndpoint), to: row.maxConcurrentPerEndpoint, appliable: true, secretBearing: false });
    }

    // Circuit-breaker thresholds.
    const liveCb = overrides.circuitBreaker ? state.circuitBreaker ?? null : null;
    const wantCb = row?.circuitBreaker ?? null;
    if (wantCb === null) {
      if (liveCb !== null) {
        push({ scope, field: "circuitBreaker", from: liveCb, to: null, appliable: true, secretBearing: false, removal: true });
      }
    } else {
      for (const f of ["failureThreshold", "cooldownMs"] as const) {
        const from = liveCb?.[f] ?? null;
        if (!deepEqual(from, wantCb[f])) {
          push({ scope, field: `circuitBreaker.${f}`, from, to: wantCb[f], appliable: true, secretBearing: false });
        }
      }
    }

    // Quota budget.
    const liveQuota = overrides.quota ? state.quota?.deliveriesPerMinute ?? null : null;
    const wantQuota = row?.quota?.deliveriesPerMinute ?? null;
    if (wantQuota === null) {
      if (liveQuota !== null) {
        push({ scope, field: "quota", from: { deliveriesPerMinute: liveQuota }, to: null, appliable: true, secretBearing: false, removal: true });
      }
    } else if (!deepEqual(liveQuota, wantQuota)) {
      push({ scope, field: "quota.deliveriesPerMinute", from: liveQuota, to: wantQuota, appliable: true, secretBearing: false });
    }

    // Weighted targets. Removal is fail-closed: weighted dispatch cannot
    // be un-configured at runtime, so a snapshot that drops it is
    // refused (unsupported) rather than half-applied.
    const liveTargets = state.weighted?.targets ?? null;
    const wantTargets = row?.weighted?.targets ?? null;
    if (wantTargets === null) {
      if (liveTargets !== null) {
        push({ scope, field: "weighted", from: liveTargets, to: null, appliable: true, secretBearing: false, removal: true });
      }
    } else if (!deepEqual(liveTargets, wantTargets)) {
      push({ scope, field: "weighted.targets", from: liveTargets, to: wantTargets, appliable: true, secretBearing: false });
    }
  }
  return items;
}

/**
 * Diff queue-global retry fields and declarative inventory. `from` is
 * live, `to` is the snapshot.
 */
function diffRetryAndInventory(live: ConfigSnapshot, snapshot: ConfigSnapshot): ConfigDiffItem[] {
  const items: ConfigDiffItem[] = [];
  const push = (
    scope: string,
    field: string,
    from: unknown,
    to: unknown,
    appliable: boolean,
    secretBearing: boolean
  ): void => {
    items.push({ scope, field, from, to, appliable, secretBearing });
  };
  for (const field of [
    "baseDelayMs",
    "maxDelayMs",
    "maxAttempts",
    "jitterMs",
    "jitterStrategy",
  ] as const) {
    const from = live.retry[field];
    const to = snapshot.retry[field];
    if (!deepEqual(from, to)) {
      push("queue", `retry.${field}`, from, to, true, false);
    }
  }
  const li = live.inventory;
  const si = snapshot.inventory;
  if (li !== null || si !== null) {
    const l = li ?? emptyInventory();
    const s = si ?? emptyInventory();
    if (!deepEqual(l.routing, s.routing)) {
      push("inventory", "routing", l.routing, s.routing, false, false);
    }
    if (!deepEqual(l.signingKeys, s.signingKeys)) {
      push("inventory", "signingKeys", l.signingKeys, s.signingKeys, false, true);
    }
    for (const endpoint of unionKeys(l.mtls, s.mtls).sort()) {
      if (!deepEqual(l.mtls[endpoint] ?? null, s.mtls[endpoint] ?? null)) {
        push("inventory", `mtls.${endpoint}`, l.mtls[endpoint] ?? null, s.mtls[endpoint] ?? null, false, true);
      }
    }
    for (const endpoint of unionKeys(l.tlsPins, s.tlsPins).sort()) {
      if (!deepEqual(l.tlsPins[endpoint] ?? null, s.tlsPins[endpoint] ?? null)) {
        push("inventory", `tlsPins.${endpoint}`, l.tlsPins[endpoint] ?? null, s.tlsPins[endpoint] ?? null, false, false);
      }
    }
    for (const endpoint of unionKeys(l.proxies, s.proxies).sort()) {
      if (!deepEqual(l.proxies[endpoint] ?? null, s.proxies[endpoint] ?? null)) {
        push("inventory", `proxies.${endpoint}`, l.proxies[endpoint] ?? null, s.proxies[endpoint] ?? null, false, true);
      }
    }
    for (const endpoint of unionKeys(l.compression, s.compression).sort()) {
      if (!deepEqual(l.compression[endpoint] ?? null, s.compression[endpoint] ?? null)) {
        push("inventory", `compression.${endpoint}`, l.compression[endpoint] ?? null, s.compression[endpoint] ?? null, false, false);
      }
    }
    if (!deepEqual([...l.tenants].sort(), [...s.tenants].sort())) {
      push("inventory", "tenants", l.tenants, s.tenants, false, false);
    }
    // WR-156: revocation diffs are append-only — a snapshot can only add
    // revocations the live config lacks; it can never un-revoke (that
    // would be a security hole, and revocation is one-way by design).
    // Revoked ids are identifiers, never key bytes, so these diffs are
    // appliable through the runtime revoke hooks (hot-reload path).
    // The revocation keys are optional on the inventory (pre-WR-156
    // readers omit them): absent means none.
    const addedApiKeyRevocations: Array<{ pattern: string; keyIds: string[] }> = [];
    const liveApiRevoked = new Map<string, Set<string>>(
      (l.revokedApiKeys ?? []).map((r) => [r.pattern, new Set(r.keyIds)])
    );
    for (const row of s.revokedApiKeys ?? []) {
      const liveIds = liveApiRevoked.get(row.pattern) ?? new Set<string>();
      const added = [...new Set(row.keyIds)].filter((id) => !liveIds.has(id)).sort();
      if (added.length > 0) addedApiKeyRevocations.push({ pattern: row.pattern, keyIds: added });
    }
    if (addedApiKeyRevocations.length > 0) {
      push("inventory", "revokedApiKeys", l.revokedApiKeys ?? [], addedApiKeyRevocations, true, false);
    }
    const addedOperatorRevocations = [...new Set(s.revokedOperatorKeys ?? [])]
      .filter((id) => !(l.revokedOperatorKeys ?? []).includes(id))
      .sort();
    if (addedOperatorRevocations.length > 0) {
      push("inventory", "revokedOperatorKeys", l.revokedOperatorKeys ?? [], addedOperatorRevocations, true, false);
    }
  }
  return items;
}

function unionKeys(a: Record<string, unknown>, b: Record<string, unknown>): string[] {
  return [...new Set([...Object.keys(a), ...Object.keys(b)])];
}

function emptyInventory(): ConfigSnapshotInventory {
  return {
    routing: null,
    signingKeys: [],
    mtls: {},
    tlsPins: {},
    proxies: {},
    compression: {},
    tenants: [],
    revokedApiKeys: [],
    revokedOperatorKeys: [],
  };
}

/**
 * Report how the live config drifted from a snapshot, without touching
 * anything. Returns the live-vs-snapshot diff items (retry fields,
 * endpoint fields, inventory) — empty when nothing drifted.
 */
export function detectConfigDrift(
  queue: RetryQueue,
  snapshot: unknown,
  env: ConfigSnapshotEnv = {}
): ConfigDiffItem[] {
  const target = assertValidConfigSnapshot(snapshot);
  const live = exportConfig(queue, env);
  return [...planEndpointDiffs(queue, target), ...diffRetryAndInventory(live, target)];
}

const decodeLimit = (v: number | "Infinity"): number =>
  v === "Infinity" ? Infinity : v;

/** Build one endpoint's `updateEndpointConfig` patch from value-change diff items. */
function buildEndpointPatch(items: ConfigDiffItem[]): EndpointConfigPatch {
  const patch: EndpointConfigPatch = {};
  for (const it of items) {
    if (it.removal === true) continue;
    switch (it.field) {
      case "maxConcurrentPerEndpoint":
        patch.maxConcurrentPerEndpoint = decodeLimit(it.to as number | "Infinity");
        break;
      case "circuitBreaker.failureThreshold":
        patch.circuitBreaker = patch.circuitBreaker ?? {};
        patch.circuitBreaker.failureThreshold = it.to as number;
        break;
      case "circuitBreaker.cooldownMs":
        patch.circuitBreaker = patch.circuitBreaker ?? {};
        patch.circuitBreaker.cooldownMs = it.to as number;
        break;
      case "quota.deliveriesPerMinute":
        patch.quota = { deliveriesPerMinute: it.to as number };
        break;
      case "weighted.targets":
        patch.weighted = { targets: (it.to as WeightedTargetConfig[]).map((t) => ({ ...t })) };
        break;
      default:
        fail("invalid_snapshot", `cannot build a patch for field ${JSON.stringify(it.field)}`);
    }
  }
  return patch;
}

interface PlannedCall {
  scope: string;
  tenant: string | undefined;
  endpoint: string;
  /** Value changes applied through `updateEndpointConfig` (may be empty). */
  patch: EndpointConfigPatch;
  /** Override sections the snapshot drops — removed via `clearEndpointConfigOverride`. */
  removals: RemovalSection[];
  /** Pre-apply state, for rollback. */
  before: EndpointConfigState;
  beforeOverrides: { maxConcurrentPerEndpoint: boolean; circuitBreaker: boolean; quota: boolean };
  /** Sections this call sets or removes (for exact rollback). */
  touched: { maxConcurrentPerEndpoint: boolean; circuitBreaker: boolean; quota: boolean; weighted: boolean };
  retryBefore?: RetryConfigSnapshot;
}

/** Restore-exact undo patch from a planned call's captured pre-apply state. */
function buildUndoPatch(call: PlannedCall): EndpointConfigPatch {
  const undo: EndpointConfigPatch = {};
  if (call.beforeOverrides.maxConcurrentPerEndpoint || call.touched.maxConcurrentPerEndpoint) {
    undo.maxConcurrentPerEndpoint = call.before.maxConcurrentPerEndpoint;
  }
  if (
    (call.beforeOverrides.circuitBreaker || call.touched.circuitBreaker) &&
    call.before.circuitBreaker !== undefined
  ) {
    undo.circuitBreaker = { ...call.before.circuitBreaker };
  }
  if ((call.beforeOverrides.quota || call.touched.quota) && call.before.quota !== undefined) {
    undo.quota = { ...call.before.quota };
  }
  if (call.touched.weighted && call.before.weighted !== undefined) {
    undo.weighted = {
      targets: call.before.weighted.targets.map((t) => ({ targetUrl: t.targetUrl, weight: t.weight })),
    };
  }
  if (call.retryBefore !== undefined) {
    undo.retry = { ...call.retryBefore };
  }
  return undo;
}

/**
 * Apply a snapshot's hot-reloadable subset through
 * `RetryQueue.updateEndpointConfig`, item by item.
 *
 * - `dryRun: true` returns the plan without mutating anything.
 * - Overrides the snapshot no longer carries are removed (queue
 *   defaults restored); removing weighted dispatch is fail-closed
 *   (`unsupported` — it cannot be un-configured at runtime).
 * - Inventory diffs are never applied: secret-bearing ones
 *   (signing keys, mTLS identities, proxies) refuse the whole apply
 *   fail-closed; the rest are reported as `pending` for out-of-band
 *   reconciliation.
 * - On a mid-apply setter failure, every applied item is rolled back to
 *   its exact pre-apply state and a `ConfigApplyError` (`apply_failed`)
 *   is thrown; `config_rolled_back` is audited. On success,
 *   `config_applied` is audited.
 */
export function applyConfig(
  queue: RetryQueue,
  snapshot: unknown,
  env: ConfigSnapshotEnv & { dryRun?: boolean } = {}
): ConfigApplyResult {
  const target = assertValidConfigSnapshot(snapshot);
  const live = exportConfig(queue, env);
  const diffs = [...planEndpointDiffs(queue, target), ...diffRetryAndInventory(live, target)];

  const secretDiffs = diffs.filter((d) => d.secretBearing);
  if (secretDiffs.length > 0) {
    throw new ConfigApplyError(
      "secret_material_refused",
      `live secret-bearing inventory diverged from the snapshot (${secretDiffs
        .map((d) => `${d.scope}:${d.field}`)
        .join(", ")}) — restore refused fail-closed; rotate/reconcile out-of-band and re-export`,
      { items: secretDiffs }
    );
  }

  const appliable = diffs.filter((d) => d.appliable);
  const pending = diffs.filter((d) => !d.appliable);
  if (env.dryRun === true) {
    return { dryRun: true, applied: [], plan: appliable, pending };
  }

  // WR-156: key-revocation diffs apply through the runtime revoke hooks
  // before anything else. Revocation is one-way (a CRL append): it is
  // never rolled back, even if a later endpoint item fails and rolls
  // back — un-revoking on a partial failure would resurrect a key the
  // operator just killed, which is the wrong failure mode for a
  // security action.
  const applied: ConfigApplyItem[] = [];
  const revocationDiffs = appliable.filter(
    (d) => d.scope === "inventory" && (d.field === "revokedApiKeys" || d.field === "revokedOperatorKeys")
  );
  if (revocationDiffs.length > 0) {
    for (const d of revocationDiffs) {
      if (d.field === "revokedApiKeys") {
        if (env.revokeApiKey === undefined) {
          throw new ConfigApplyError(
            "unsupported",
            "snapshot revokes inbound API keys but no revokeApiKey hook was supplied — nothing applied",
            { items: revocationDiffs }
          );
        }
        for (const row of d.to as Array<{ pattern: string; keyIds: string[] }>) {
          for (const keyId of row.keyIds) {
            env.revokeApiKey(row.pattern, keyId);
          }
        }
      } else {
        if (env.revokeOperatorKey === undefined) {
          throw new ConfigApplyError(
            "unsupported",
            "snapshot revokes operator keys but no revokeOperatorKey hook was supplied — nothing applied",
            { items: revocationDiffs }
          );
        }
        for (const id of d.to as string[]) {
          env.revokeOperatorKey(id);
        }
      }
      applied.push({ scope: d.scope, field: d.field, from: d.from, to: d.to });
    }
  }
  const endpointDiffs = appliable.filter(
    (d) => !(d.scope === "inventory" && (d.field === "revokedApiKeys" || d.field === "revokedOperatorKeys"))
  );

  // Group appliable items per (tenant, endpoint); retry.* is queue-global
  // and rides on the first endpoint call (WR-32 applies it through the
  // same imperative setter).
  const byScope = new Map<string, ConfigDiffItem[]>();
  for (const d of endpointDiffs) {
    const list = byScope.get(d.scope) ?? [];
    list.push(d);
    byScope.set(d.scope, list);
  }
  const retryItems = byScope.get("queue") ?? [];
  byScope.delete("queue");
  const endpointScopes = [...byScope.keys()].sort();
  if (retryItems.length > 0 && endpointScopes.length === 0) {
    const snapshotScopes = Object.keys(target.endpoints).sort();
    if (snapshotScopes.length === 0) {
      throw new ConfigApplyError(
        "unsupported",
        "the snapshot changes queue-global retry parameters but carries no endpoint to anchor the imperative patch — nothing applied"
      );
    }
    endpointScopes.push(snapshotScopes[0]);
    byScope.set(snapshotScopes[0], []);
  }

  const calls: PlannedCall[] = endpointScopes.map((scope) => {
    const { tenant, endpoint } = splitTenantScopeKey(scope);
    const items = byScope.get(scope) ?? [];
    const removals = items
      .filter((it) => it.removal === true)
      .map((it) => it.field as RemovalSection);
    const patch = buildEndpointPatch(items);
    if (scope === endpointScopes[0] && retryItems.length > 0) {
      patch.retry = {};
      for (const it of retryItems) {
        const field = it.field.slice("retry.".length) as keyof RetryConfigSnapshot;
        (patch.retry as Record<string, unknown>)[field] = it.to;
      }
    }
    const touched = {
      maxConcurrentPerEndpoint:
        patch.maxConcurrentPerEndpoint !== undefined || removals.includes("maxConcurrentPerEndpoint"),
      circuitBreaker: patch.circuitBreaker !== undefined || removals.includes("circuitBreaker"),
      quota: patch.quota !== undefined || removals.includes("quota"),
      weighted: patch.weighted !== undefined,
    };
    // Validate the assembled patch before anything mutates.
    try {
      assertValidEndpointConfigPatch(patch);
    } catch (err) {
      throw new ConfigApplyError("invalid_snapshot", (err as Error).message, { items });
    }
    // Fail-closed subsystem gates — before any mutation.
    const needsCircuit =
      items.some((it) => it.field === "circuitBreaker" || it.field.startsWith("circuitBreaker."));
    const needsQuota =
      items.some((it) => it.field === "quota" || it.field.startsWith("quota."));
    const needsWeighted = items.some((it) => it.field.startsWith("weighted"));
    if (needsCircuit && !queue.circuitBreakerConfigured()) {
      throw new ConfigApplyError(
        "unsupported",
        `snapshot touches ${scope}:circuitBreaker but the circuit breaker is not enabled — nothing applied`,
        { items: items.filter((it) => it.field.startsWith("circuitBreaker")) }
      );
    }
    if (needsQuota && !queue.quotaConfigured()) {
      throw new ConfigApplyError(
        "unsupported",
        `snapshot touches ${scope}:quota but per-endpoint quotas are not enabled — nothing applied`,
        { items: items.filter((it) => it.field.startsWith("quota")) }
      );
    }
    if (removals.includes("weighted")) {
      throw new ConfigApplyError(
        "unsupported",
        `snapshot drops ${scope}:weighted but weighted dispatch cannot be un-configured at runtime — nothing applied`,
        { items: items.filter((it) => it.field === "weighted") }
      );
    }
    if (needsWeighted && !queue.weightedHasEndpoint(endpoint)) {
      throw new ConfigApplyError(
        "unsupported",
        `snapshot touches ${scope}:weighted but weighted dispatch is not enabled for this endpoint — nothing applied`,
        { items: items.filter((it) => it.field.startsWith("weighted")) }
      );
    }
    return {
      scope,
      tenant,
      endpoint,
      patch,
      removals,
      before: queue.endpointConfig(tenant, endpoint),
      beforeOverrides: queue.endpointConfigOverrides(tenant, endpoint),
      touched,
      ...(scope === endpointScopes[0] && retryItems.length > 0
        ? { retryBefore: { ...live.retry } }
        : {}),
    };
  });

  const appliedCalls: PlannedCall[] = [];
  try {
    for (const call of calls) {
      let didAnything = false;
      if (Object.keys(call.patch).length > 0) {
        const changes = queue.updateEndpointConfig(call.endpoint, call.patch, call.tenant);
        didAnything = true;
        for (const c of changes) {
          // Queue-global retry fields ride on this endpoint's imperative
          // call; keep their "queue" scope in the applied record.
          const scope = c.field.startsWith("retry.") ? "queue" : call.scope;
          applied.push({ scope, field: c.field, from: c.from, to: c.to });
        }
      }
      for (const section of call.removals) {
        // Weighted removal never reaches here — refused as `unsupported`
        // in the pre-checks above.
        if (section === "weighted") continue;
        const from =
          section === "maxConcurrentPerEndpoint"
            ? encodeLimit(call.before.maxConcurrentPerEndpoint)
            : section === "circuitBreaker"
              ? call.before.circuitBreaker ?? null
              : call.before.quota ?? null;
        queue.clearEndpointConfigOverride(call.tenant, call.endpoint, section);
        didAnything = true;
        applied.push({ scope: call.scope, field: section, from, to: null });
      }
      if (didAnything) appliedCalls.push(call);
    }
  } catch (err) {
    // Roll back every applied item to its exact pre-apply state, in
    // reverse order. Overrides that did not exist pre-apply are removed
    // again rather than frozen to their effective value; removed
    // overrides are re-applied from the captured pre-apply state.
    const rolledBack: ConfigApplyItem[] = [];
    const rollbackErrors: unknown[] = [];
    for (const call of [...appliedCalls].reverse()) {
      try {
        const undo = buildUndoPatch(call);
        if (Object.keys(undo).length > 0) {
          const changes = queue.updateEndpointConfig(call.endpoint, undo, call.tenant);
          for (const c of changes) {
            rolledBack.push({ scope: call.scope, field: c.field, from: c.from, to: c.to });
          }
        }
        for (const section of ["maxConcurrentPerEndpoint", "circuitBreaker", "quota"] as const) {
          if (!call.beforeOverrides[section] && call.touched[section]) {
            queue.clearEndpointConfigOverride(call.tenant, call.endpoint, section);
          }
        }
      } catch (rbErr) {
        rollbackErrors.push(rbErr);
      }
    }
    env.audit?.({
      event: "config_rolled_back",
      reason: (err as Error)?.message ?? String(err),
      applied: applied.length,
      rolledBack: rolledBack.length,
      ...(rollbackErrors.length > 0 ? { rollbackErrors: rollbackErrors.length } : {}),
    });
    throw new ConfigApplyError("apply_failed", (err as Error)?.message ?? String(err), {
      applied,
      rolledBack,
      cause: err,
    });
  }

  env.audit?.({
    event: "config_applied",
    applied: applied.length,
    changes: applied,
    pending: pending.length,
  });
  return { dryRun: false, applied, plan: [], pending };
}
