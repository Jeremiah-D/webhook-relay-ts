/**
 * Inbound HMAC secret dual-version zero-downtime rotation (WR-67).
 *
 * When a sender's signing secret must change, flipping it atomically
 * bricks every in-flight webhook still signed with the old key: the
 * rotation window — while the sender migrates from old to new — is
 * exactly when 401 storms happen. This module gives an inbound endpoint
 * two parallel secrets:
 *
 *   - `currentSecret` — the new key, always tried first;
 *   - `previousSecret` — the old key, still accepted inside a grace
 *     window measured from `previousRetiredAtMs`.
 *
 * Senders declare which key they used with the `x-signature-version`
 * header (`"current"` / `"previous"`); without the header the relay
 * tries `current` first and falls back to `previous` when it is still
 * inside its grace window. An unknown version value fails closed (401),
 * never falls back — a header that claims `"v3"` is a sender bug, not a
 * reason to try harder.
 *
 * The grace boundary is inclusive, matching the retired-key grace in
 * `RotatingHmacVerifier` (`src/verify.ts`): a signature that verifies
 * exactly at the deadline still verifies. Outside the window, `previous`
 * is dead weight — `isRotationComplete()` reports that, and the operator
 * then clears `previousSecret` from the endpoint's config to finish the
 * rotation. Every time the previous key verifies, the server records the
 * `secret_rotation_previous_used` audit event, so the operator sees how
 * much rotation traffic still runs on the old key.
 *
 * Orthogonal to WR-65 API-key authentication: when an endpoint requires
 * the API key alone, no secret is consulted; when it requires both
 * (`requireSignature: true`), the dual-secret check above is the
 * signature leg. Orthogonal to WR-20's global key set: that verifier
 * handles many keys across the whole relay, this one handles one
 * endpoint's two keys at a time.
 */

import { HmacSha256Verifier } from "./verify.ts";

/** Which side of the rotation verified a signature. */
export type SecretVersion = "current" | "previous";

/** Header a sender uses to declare which secret signed the payload. */
export const SIGNATURE_VERSION_HEADER = "x-signature-version";

/** Default grace window for the previous secret: one hour. */
export const DEFAULT_SECRET_GRACE_SECONDS = 3600;

export interface SecretRotationConfig {
  /** The new key: always tried first. Non-empty. */
  currentSecret: string;
  /**
   * The old key: tried only inside its grace window. Omit it (or clear
   * it after `isRotationComplete()`) once the rotation is done.
   */
  previousSecret?: string;
  /**
   * Grace window in seconds, measured from `previousRetiredAtMs`, during
   * which `previousSecret` still verifies. Default 3600 (one hour).
   */
  graceSeconds?: number;
  /**
   * Millisecond epoch at which `previousSecret` was retired. Defaults to
   * construction time: when the config is applied, the rotation is
   * assumed to have just begun. Operators who rotate across restarts
   * should pin this to the real retirement moment so the window does
   * not silently restart on every deploy.
   */
  previousRetiredAtMs?: number;
  /** Clock source for grace checks; defaults to Date.now. Injectable for tests. */
  nowMs?: () => number;
}

export interface SecretRotationVerifyOptions {
  /**
   * The sender's `x-signature-version` header value. `"current"` and
   * `"previous"` are honored; anything else fails closed.
   */
  version?: string;
}

/** Result of {@link RotatingEndpointSecret.verify}. Never throws. */
export interface SecretRotationVerifyResult {
  ok: boolean;
  /** Which secret verified; undefined when `ok` is false. */
  version?: SecretVersion;
}

/** One per-endpoint rotation rule (WR-67): inbound request paths that match `pattern` verify with `rotation`. */
export interface EndpointSecretRotationRule {
  /**
   * Request path pattern, following the WR-29 convention: exact
   * (`/hooks/stripe`) or prefix (`/hooks/*`, which also matches
   * `/hooks` itself). The first matching rule in config order wins.
   */
  pattern: string;
  /** The dual-secret rotation config for this endpoint. */
  rotation: SecretRotationConfig;
}

/**
 * One endpoint's two-secret HMAC rotation. Verification never throws:
 * unparsable headers, wrong secrets, expired grace windows, and unknown
 * version hints all mean `false`.
 */
export class RotatingEndpointSecret {
  readonly name = "hmac-sha256-dual-rotation";

  private readonly current: HmacSha256Verifier;
  private readonly previous?: HmacSha256Verifier;
  private readonly graceMs: number;
  private readonly retiredAtMs: number;
  private readonly nowMs: () => number;

  constructor(config: SecretRotationConfig) {
    if (!config || typeof config.currentSecret !== "string" || config.currentSecret === "") {
      throw new RangeError("SecretRotationConfig: `currentSecret` must be a non-empty string");
    }
    if (
      config.previousSecret !== undefined &&
      (typeof config.previousSecret !== "string" || config.previousSecret === "")
    ) {
      throw new RangeError("SecretRotationConfig: `previousSecret` must be a non-empty string when set");
    }
    const graceSeconds = config.graceSeconds ?? DEFAULT_SECRET_GRACE_SECONDS;
    if (!Number.isFinite(graceSeconds) || graceSeconds < 0) {
      throw new RangeError("SecretRotationConfig: `graceSeconds` must be a non-negative finite number");
    }
    const nowMs = config.nowMs ?? Date.now;
    const retiredAtMs = config.previousRetiredAtMs ?? nowMs();
    if (!Number.isFinite(retiredAtMs) || retiredAtMs < 0) {
      throw new RangeError("SecretRotationConfig: `previousRetiredAtMs` must be a non-negative epoch ms");
    }
    this.current = new HmacSha256Verifier(config.currentSecret);
    if (config.previousSecret !== undefined) {
      this.previous = new HmacSha256Verifier(config.previousSecret);
    }
    this.graceMs = graceSeconds * 1000;
    this.retiredAtMs = retiredAtMs;
    this.nowMs = nowMs;
  }

  /** Whether the previous secret is still inside its grace window. */
  previousInGrace(): boolean {
    if (this.previous === undefined) return false;
    return this.nowMs() - this.retiredAtMs <= this.graceMs;
  }

  /**
   * Whether the rotation is complete: a previous secret is configured
   * but its grace window has fully elapsed. The operator can then clear
   * `previousSecret` from this endpoint's config — the rotation is done,
   * and old-key signatures are rejected.
   */
  isRotationComplete(): boolean {
    return this.previous !== undefined && !this.previousInGrace();
  }

  verify(rawBody: Buffer, header: string, opts: SecretRotationVerifyOptions = {}): SecretRotationVerifyResult {
    try {
      const hint =
        typeof opts.version === "string" && opts.version.trim() !== ""
          ? opts.version.trim().toLowerCase()
          : undefined;
      if (hint !== undefined && hint !== "current" && hint !== "previous") {
        // An unknown version claim fails closed: never fall back across
        // a sender bug.
        return { ok: false };
      }
      if (hint === "current") {
        return this.current.verify(rawBody, header)
          ? { ok: true, version: "current" }
          : { ok: false };
      }
      if (hint === "previous") {
        if (!this.previousInGrace()) return { ok: false };
        return this.previous!.verify(rawBody, header) ? { ok: true, version: "previous" } : { ok: false };
      }
      // No hint: new key first, old key as fallback inside its grace.
      if (this.current.verify(rawBody, header)) {
        return { ok: true, version: "current" };
      }
      if (this.previousInGrace() && this.previous!.verify(rawBody, header)) {
        return { ok: true, version: "previous" };
      }
      return { ok: false };
    } catch {
      return { ok: false };
    }
  }
}

/**
 * Validate per-endpoint secret rotation rules at startup. Throws
 * RangeError on a non-array, a pattern that is not a `/`-rooted path, or
 * an invalid rotation config — fail fast, never mid-request.
 */
export function assertValidSecretRotationRules(rules: EndpointSecretRotationRule[] | undefined): void {
  if (rules === undefined) return;
  if (!Array.isArray(rules)) {
    throw new RangeError("secretRotation: expected an array of { pattern, rotation } rules");
  }
  rules.forEach((rule, i) => {
    const where = `secretRotation[${i}]`;
    if (!rule || typeof rule.pattern !== "string" || rule.pattern === "" || !rule.pattern.startsWith("/")) {
      throw new RangeError(
        `${where}: pattern must be a path starting with "/" (exact) or ending with "/*" (prefix)`
      );
    }
    try {
      new RotatingEndpointSecret(rule.rotation);
    } catch (e) {
      throw new RangeError(`${where}: invalid rotation config: ${(e as Error).message}`);
    }
  });
}

/**
 * One compiled rule: the path pattern paired with a single
 * `RotatingEndpointSecret` instance.
 */
export interface CompiledSecretRotationRule {
  pattern: string;
  secret: RotatingEndpointSecret;
}

/**
 * Compile per-endpoint rotation rules once at server startup, after
 * {@link assertValidSecretRotationRules} has validated them. Compiling
 * once matters: a rule without `previousRetiredAtMs` assumes the
 * rotation began when the config was applied — building a fresh
 * instance per request would silently restart the grace window on every
 * webhook.
 */
export function compileSecretRotationRules(
  rules: EndpointSecretRotationRule[] | undefined
): CompiledSecretRotationRule[] | undefined {
  if (rules === undefined) return undefined;
  return rules.map((rule) => ({
    pattern: rule.pattern,
    secret: new RotatingEndpointSecret(rule.rotation),
  }));
}

/**
 * Select the rotation config for an inbound request path: the first
 * matching compiled rule's `RotatingEndpointSecret`, or `undefined` when
 * nothing matches (the caller falls back to the global verifier). Never
 * throws.
 */
export function selectSecretRotation(
  pathname: string,
  rules: CompiledSecretRotationRule[] | undefined
): RotatingEndpointSecret | undefined {
  if (rules === undefined) return undefined;
  for (const rule of rules) {
    if (rule.pattern.endsWith("/*")) {
      const prefix = rule.pattern.slice(0, -2);
      if (pathname === prefix || pathname.startsWith(prefix + "/")) {
        return rule.secret;
      }
    } else if (pathname === rule.pattern) {
      return rule.secret;
    }
  }
  return undefined;
}
