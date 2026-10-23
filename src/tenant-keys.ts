/**
 * Per-tenant inbound HMAC keys (WR-195).
 *
 * The relay's global inbound signature verifier (WR-01/WR-20) trusts one
 * key set for every sender. Multi-tenant relays need finer trust: each
 * tenant's upstream signs with its own secret, so a leaked tenant secret
 * compromises exactly one tenant, and one tenant's key rotation never
 * forces every other tenant's senders to cut over at the same time.
 *
 * A `TenantKeyStore` manages one inbound HMAC key per tenant, keyed by
 * the WR-48 tenant namespace (`x-tenant-id`):
 *
 *   - `setTenantSecret(tenantId, secret)` registers the tenant's signing
 *     key. Setting a key twice is a `RangeError` — rotate or remove first,
 *     never silently overwrite a live trust anchor.
 *   - `rotateTenantSecret(tenantId, newSecret, graceMs?)` installs the new
 *     key as primary and retires the old one. Inside the grace window
 *     (default 24h, inclusive boundary, same convention as
 *     `RotatingHmacVerifier`) both keys verify in parallel, so in-flight
 *     webhooks signed with the old key do not 401-storm; once the window
 *     elapses the old key is dead weight.
 *
 * Each key gets a stable, non-secret identity
 * (`${tenantId}:${generation}`) that surfaces in audit events via the
 * existing rotating-verifier `keyId` attribution — the secret itself never
 * leaves the store. The server picks a tenant's key set per request from
 * the `x-tenant-id` claim (see `tenantKeys` in `RelayServerOptions`);
 * tenants with no configured key walk the exact legacy global path, so
 * the feature is off by default and fully backward compatible.
 *
 * Orthogonality (by design):
 *   - WR-48 (tenant isolation): reuses the same tenant namespace and
 *     `assertValidTenantId` charset; a value that cannot be a tenant id
 *     can never own a key.
 *   - WR-65 (endpoint API keys): a different credential type on a
 *     different axis — API keys authenticate *endpoints*, tenant keys
 *     authenticate *senders*. Both can be required at once.
 *   - WR-20/WR-67 (global/per-endpoint rotations): the tenant key set is
 *     a per-tenant sibling; a pinned per-endpoint verifier rule (WR-29)
 *     still wins on its path.
 */

import { assertValidTenantId } from "./tenant.ts";
import {
  DEFAULT_KEY_GRACE_MS,
  RotatingHmacVerifier,
  type VerifyDetail,
  type VerifyDetailOptions,
  type VerifyOptions,
} from "./verify.ts";

/** Default grace window for a retired tenant key: 24h (the WR-20 default). */
export const DEFAULT_TENANT_KEY_GRACE_MS = DEFAULT_KEY_GRACE_MS;

/** Options for {@link TenantKeyStore}. */
export interface TenantKeyStoreOptions {
  /** Clock source for rotation grace checks; defaults to Date.now. Injectable for tests. */
  nowMs?: () => number;
}

interface TenantKeyRecord {
  /** Key identity generation: 1 for the first set, incremented per rotation. */
  generation: number;
  /** The key currently used to sign new webhooks. */
  current: { id: string; secret: string };
  /** The retired key, still verifiable inside its grace window. */
  previous?: { id: string; secret: string; retiredAtMs: number; graceMs: number };
  /** Compiled verifier over current + (in-grace) previous. */
  verifier: RotatingHmacVerifier;
}

/**
 * Per-tenant inbound HMAC key management. Mutation calls fail fast with
 * `RangeError`; verification calls never throw. Secrets are held only in
 * memory and are never exposed — key identities (`${tenantId}:${n}`)
 * are the only thing that leaves the store.
 */
export class TenantKeyStore {
  private readonly records = new Map<string, TenantKeyRecord>();
  private readonly nowMs: () => number;

  constructor(options: TenantKeyStoreOptions = {}) {
    const nowMs = options?.nowMs ?? Date.now;
    if (typeof nowMs !== "function") {
      throw new RangeError("TenantKeyStore: `nowMs` must be a function");
    }
    this.nowMs = nowMs;
  }

  /** Validate a tenant id for key management; any failure is a RangeError. */
  private checkedTenantId(tenantId: string): string {
    try {
      assertValidTenantId(tenantId);
    } catch (err) {
      throw new RangeError(`TenantKeyStore: invalid tenant id: ${(err as Error).message}`);
    }
    return tenantId;
  }

  /** Key identity for a tenant generation: stable, non-secret, audit-safe. */
  static keyIdFor(tenantId: string, generation: number): string {
    return `${tenantId}:${generation}`;
  }

  private buildVerifier(record: Pick<TenantKeyRecord, "current" | "previous">): RotatingHmacVerifier {
    const keys = [
      { id: record.current.id, secret: record.current.secret, primary: true },
      ...(record.previous !== undefined
        ? [{ id: record.previous.id, secret: record.previous.secret, retiredAtMs: record.previous.retiredAtMs }]
        : []),
    ];
    // The grace lives on the rotation, not on the verifier config default:
    // each rotation stamps its own window (default 24h) at retire time.
    const graceMs = record.previous?.graceMs ?? DEFAULT_TENANT_KEY_GRACE_MS;
    return new RotatingHmacVerifier({ keys, graceMs, nowMs: this.nowMs });
  }

  /**
   * Register a tenant's inbound HMAC signing key. Returns the assigned
   * key id (`${tenantId}:1`). Throws `RangeError` on an invalid tenant
   * id, an empty/non-string secret, or when the tenant already has a key
   * — rotate or remove first; a live trust anchor is never overwritten
   * silently.
   */
  setTenantSecret(tenantId: string, secret: string): string {
    const id = this.checkedTenantId(tenantId);
    if (typeof secret !== "string" || secret === "") {
      throw new RangeError("TenantKeyStore: `secret` must be a non-empty string");
    }
    if (this.records.has(id)) {
      throw new RangeError(
        `TenantKeyStore: tenant "${id}" already has a key — use rotateTenantSecret or removeTenantSecret first`
      );
    }
    const generation = 1;
    const current = { id: TenantKeyStore.keyIdFor(id, generation), secret };
    const record: TenantKeyRecord = {
      generation,
      current,
      verifier: this.buildVerifier({ current }),
    };
    this.records.set(id, record);
    return current.id;
  }

  /**
   * Rotate a tenant's inbound key: `newSecret` becomes the primary signer
   * and the old key keeps verifying for `graceMs` (default 24h). Returns
   * the new key id (`${tenantId}:${generation}`). Throws `RangeError`
   * when the tenant has no key yet (use `setTenantSecret` first), on an
   * empty/non-string secret, or on a negative/non-finite `graceMs`.
   * Rotating again drops the older retired key — at most two keys ever
   * verify for one tenant.
   */
  rotateTenantSecret(tenantId: string, newSecret: string, graceMs: number = DEFAULT_TENANT_KEY_GRACE_MS): string {
    const id = this.checkedTenantId(tenantId);
    if (typeof newSecret !== "string" || newSecret === "") {
      throw new RangeError("TenantKeyStore: `newSecret` must be a non-empty string");
    }
    if (!Number.isFinite(graceMs) || graceMs < 0) {
      throw new RangeError("TenantKeyStore: `graceMs` must be a non-negative finite number");
    }
    const record = this.records.get(id);
    if (record === undefined) {
      throw new RangeError(`TenantKeyStore: tenant "${id}" has no key — use setTenantSecret first`);
    }
    const generation = record.generation + 1;
    const previous = {
      id: record.current.id,
      secret: record.current.secret,
      retiredAtMs: this.nowMs(),
      graceMs,
    };
    const current = { id: TenantKeyStore.keyIdFor(id, generation), secret: newSecret };
    record.generation = generation;
    record.current = current;
    record.previous = previous;
    record.verifier = this.buildVerifier({ current, previous });
    return current.id;
  }

  /**
   * Drop a tenant's key entirely (both current and any retired previous).
   * Returns true when a key existed. After removal the tenant walks the
   * legacy global verification path again.
   */
  removeTenantSecret(tenantId: string): boolean {
    const id = this.checkedTenantId(tenantId);
    return this.records.delete(id);
  }

  /** Whether the tenant has an inbound HMAC key configured. */
  hasTenantSecret(tenantId: string): boolean {
    const id = this.checkedTenantId(tenantId);
    return this.records.has(id);
  }

  /**
   * The tenant's rotating verifier, or `undefined` when the tenant has
   * no configured key (the caller falls back to the global verifier).
   * Never throws.
   */
  getVerifier(tenantId: string): RotatingHmacVerifier | undefined {
    try {
      return this.records.get(this.checkedTenantId(tenantId))?.verifier;
    } catch {
      return undefined;
    }
  }

  /** Key id of the tenant's current (primary) key; undefined when no key is set. */
  getCurrentKeyId(tenantId: string): string | undefined {
    const id = this.checkedTenantId(tenantId);
    return this.records.get(id)?.current.id;
  }

  /**
   * All key ids the tenant has ever had in this store (current +
   * retired previous, in service order). Audit/debug only — never
   * contains secrets.
   */
  getKeyIds(tenantId: string): string[] {
    const id = this.checkedTenantId(tenantId);
    const record = this.records.get(id);
    if (record === undefined) return [];
    const ids = [record.current.id];
    if (record.previous !== undefined) ids.unshift(record.previous.id);
    return ids;
  }

  /**
   * Whether the tenant's previous key is still inside its grace window.
   * False when there is no previous key.
   */
  previousInGrace(tenantId: string): boolean {
    const id = this.checkedTenantId(tenantId);
    const record = this.records.get(id);
    if (record?.previous === undefined) return false;
    return this.nowMs() - record.previous.retiredAtMs <= record.previous.graceMs;
  }

  /**
   * Whether the rotation is complete: a previous key is configured but
   * its grace window has fully elapsed — old-key signatures are now
   * rejected and the operator can treat the cutover as done.
   */
  rotationComplete(tenantId: string): boolean {
    const id = this.checkedTenantId(tenantId);
    const record = this.records.get(id);
    return record?.previous !== undefined && !this.previousInGrace(id);
  }

  /**
   * Verify a payload against the tenant's key set, reporting the key id
   * that verified. Unknown tenants and unparsable headers mean
   * `{ ok: false }` — never throws, so callers can treat "no key" as
   * "fall back to the global verifier".
   */
  verifyDetailed(
    tenantId: string,
    rawBody: Buffer,
    header: string,
    opts: VerifyDetailOptions = {}
  ): VerifyDetail {
    try {
      const verifier = this.records.get(this.checkedTenantId(tenantId))?.verifier;
      if (verifier === undefined) return { ok: false };
      return verifier.verifyDetailed(rawBody, header, opts);
    } catch {
      return { ok: false };
    }
  }

  /** Boolean form of {@link verifyDetailed}. Never throws. */
  verify(tenantId: string, rawBody: Buffer, header: string, opts: VerifyOptions = {}): boolean {
    return this.verifyDetailed(tenantId, rawBody, header, opts).ok;
  }

  /** Tenants with a configured key, for operator introspection. */
  tenantIds(): string[] {
    return [...this.records.keys()];
  }
}
