/**
 * Outbound static credential injection (WR-192).
 *
 * Some downstreams gate webhooks on a static secret — an `x-api-key`
 * header, a shared `Authorization` token — rather than on anything the
 * relay computes per request. `OutboundCredentialConfig` names such a
 * credential per endpoint (exact `targetUrl` match, the same convention
 * as `tlsPins` / `compressOutbound` / `oauth2`); the relay injects the
 * credential *value* into the outbound request header, so the value
 * comes from relay configuration and never from the inbound request.
 *
 * Secret handling reuses the WR-116 / `archive-s3.ts` convention:
 * - the config carries `secretRef` — a *reference* (with the default
 *   resolver, an environment variable name), never the raw secret — so
 *   config snapshots, audit events, and stats can never leak key
 *   material;
 * - `secretResolver` resolves the reference per delivery attempt
 *   (rotation without restart) and is injectable for deterministic
 *   tests; the default is `defaultSecretResolver` (`process.env[ref]`);
 * - unlike WR-116 (which fails a single attempt), a reference that
 *   does not resolve *at startup* is a `RangeError` — the relay refuses
 *   to boot rather than accepting webhooks it could never deliver.
 *
 * Wire semantics (applied in `buildWireRequest` in `src/server.ts`):
 * - stamped *after* the WR-129 OAuth2 bearer token: when both configure
 *   the same header (e.g. `Authorization`), the explicit static
 *   credential wins deterministically — operators should avoid that
 *   overlap; the same "last stamp wins" rule applies against the WR-116
 *   SigV4 `Authorization` stamp;
 * - the relay-forged value always wins: any inbound header with the
 *   same name is stripped first (the WR-26 anti-forgery pattern), so a
 *   sender can never smuggle a forged credential downstream;
 * - stamped *after* the passthrough-forwarding gate (WR-69), like the
 *   other relay-owned headers (`x-trace-id`, `x-relay-signature`), so a
 *   forwarding rule can neither drop a credential stamp nor be confused
 *   by it. The WR-26 HMAC signs the body and SigV4 signs only its own
 *   headers, so stamping credential headers after those blocks does not
 *   interact with either signature.
 *
 * Orthogonal to:
 * - WR-69 (`forward-headers.ts`): the gate applies to *passthrough*
 *   headers; credential stamps are relay-forced and always survive it;
 * - WR-129 (`oauth-client.ts`): dynamic per-attempt bearer tokens vs
 *   static configured values — both may be enabled (same-header
 *   conflicts resolve to the static value, deterministically);
 * - WR-36 (`mtls.ts`): client certificates authenticate the TLS
 *   handshake (transport layer); credentials authenticate the HTTP
 *   request (application layer) — the two compose freely.
 *
 * Auditing: the relay never audits a credential *value*. `accepted`
 * events carry `credentialIds` — the configured credential ids for the
 * endpoint — so operators can see which credential a delivery will
 * stamp without the value ever entering the audit trail.
 */

import {
  defaultSecretResolver,
  type SecretResolver,
} from "./sigv4.ts";

/** One static outbound credential for an endpoint (WR-192). */
export interface OutboundCredentialConfig {
  /**
   * Operator-chosen credential id, e.g. `"partner-x-api-key"`. Audited
   * on `accepted` events (`credentialIds`) — the only credential
   * detail that ever enters the audit trail. Unique per endpoint.
   */
  id: string;
  /**
   * Outbound header to stamp, e.g. `"x-api-key"` or `"Authorization"`.
   * Matched case-insensitively; unique per endpoint.
   */
  header: string;
  /**
   * Secret-store reference naming where the credential value lives
   * (WR-116 convention: an environment variable name with the default
   * resolver). Never the raw secret — config snapshots, audit events,
   * and stats can never leak key material.
   */
  secretRef: string;
  /**
   * Resolves `secretRef` to the credential value per delivery attempt
   * (so a rotation takes effect without a restart). Defaults to
   * `defaultSecretResolver` (environment variable lookup).
   */
  secretResolver?: SecretResolver;
}

/** A credential validated at startup, ready for the delivery path. */
export interface CompiledOutboundCredential {
  readonly id: string;
  readonly header: string;
  /** Lowercased header name, for case-insensitive matching. */
  readonly headerLower: string;
  readonly secretRef: string;
  readonly secretResolver: SecretResolver;
}

/**
 * Thrown on the delivery path when a credential's `secretRef` stops
 * resolving (e.g. rotated away mid-run). Should not happen in a
 * correctly started relay — startup refuses to boot with an
 * unresolvable reference — so the queue classifies it
 * `non_retryable` (see `src/failure.ts`): a poisoned delivery
 * dead-letters on the first attempt instead of burning the retry
 * budget.
 */
export class CredentialSecretUnavailableError extends Error {
  readonly endpoint: string;
  readonly credentialId: string;
  readonly secretRef: string;
  constructor(endpoint: string, credentialId: string, secretRef: string) {
    super(
      `outbound-credentials[${endpoint}]: secret unavailable for credential ` +
        `"${credentialId}" (secretRef "${secretRef}" did not resolve)`
    );
    this.name = "CredentialSecretUnavailableError";
    this.endpoint = endpoint;
    this.credentialId = credentialId;
    this.secretRef = secretRef;
  }
}

/**
 * Validate one credential's shape and resolve its `secretRef`.
 * Throws `RangeError` on any bad shape *and* on an unresolvable
 * reference — called at startup so a typo or a missing secret fails
 * fast, never mid-delivery.
 */
export function assertValidOutboundCredential(
  cfg: unknown,
  label: string
): asserts cfg is OutboundCredentialConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object" || Array.isArray(cfg)) {
    throw new RangeError(at("credential must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  if (typeof c.id !== "string" || c.id === "") {
    throw new RangeError(at("`id` must be a non-empty string"));
  }
  if (typeof c.header !== "string" || c.header.trim() === "") {
    throw new RangeError(at("`header` must be a non-empty header name"));
  }
  if (typeof c.secretRef !== "string" || c.secretRef === "") {
    throw new RangeError(
      at("`secretRef` must be a non-empty string (a reference, never the raw secret)")
    );
  }
  if (c.secretResolver !== undefined && typeof c.secretResolver !== "function") {
    throw new RangeError(at("`secretResolver` must be a function when set"));
  }
  // Fail-fast secret presence: the reference must resolve *now*, not on
  // the first delivery. A relay that accepts webhooks it can never
  // deliver is worse than one that refuses to boot.
  const resolver = (c.secretResolver as SecretResolver | undefined) ?? defaultSecretResolver;
  const secret = resolver(c.secretRef);
  if (typeof secret !== "string" || secret === "") {
    throw new RangeError(
      at(
        `secretRef "${c.secretRef}" did not resolve (credential "${c.id}") — ` +
          "set the secret before boot"
      )
    );
  }
}

/**
 * Validate and compile the per-endpoint credential records. Throws
 * `RangeError` on any invalid config — shape, duplicate `id`s or
 * duplicate header names within one endpoint, or an unresolvable
 * `secretRef`. Callers wrap with their endpoint context.
 */
export function resolveOutboundCredentialsConfig(
  record: Record<string, OutboundCredentialConfig[]>
): Map<string, CompiledOutboundCredential[]> {
  if (record === null || typeof record !== "object" || Array.isArray(record)) {
    throw new RangeError(
      `outboundCredentials must be a record of targetUrl -> credentials, got ${Array.isArray(record) ? "array" : typeof record}`
    );
  }
  const out = new Map<string, CompiledOutboundCredential[]>();
  for (const [endpoint, list] of Object.entries(record)) {
    const what = `outboundCredentials[${JSON.stringify(endpoint)}]`;
    if (!Array.isArray(list)) {
      throw new RangeError(`${what}: credentials must be an array, got ${typeof list}`);
    }
    if (list.length === 0) {
      throw new RangeError(`${what}: credentials must be a non-empty array`);
    }
    const seenIds = new Set<string>();
    const seenHeaders = new Set<string>();
    const compiled: CompiledOutboundCredential[] = list.map((cfg, i) => {
      assertValidOutboundCredential(cfg, `${what}[${i}]`);
      const c = cfg as OutboundCredentialConfig;
      if (seenIds.has(c.id)) {
        throw new RangeError(`${what}: duplicate credential id ${JSON.stringify(c.id)}`);
      }
      seenIds.add(c.id);
      const headerLower = c.header.toLowerCase();
      if (seenHeaders.has(headerLower)) {
        throw new RangeError(
          `${what}: duplicate header ${JSON.stringify(c.header)} — two credentials stamping one header is ambiguous`
        );
      }
      seenHeaders.add(headerLower);
      return {
        id: c.id,
        header: c.header,
        headerLower,
        secretRef: c.secretRef,
        secretResolver: c.secretResolver ?? defaultSecretResolver,
      };
    });
    out.set(endpoint, compiled);
  }
  return out;
}

/**
 * Stamp an endpoint's static credentials onto the wire headers.
 *
 * For each credential: drop any passthrough header with the same name
 * first (the WR-26 anti-forgery pattern — a sender can never smuggle a
 * forged credential value downstream), then stamp the relay-resolved
 * value. The resolver runs per attempt, so a secret rotation takes
 * effect without a restart; an unresolvable reference throws
 * `CredentialSecretUnavailableError` (classified `non_retryable`).
 * Header values are never logged — only the credential *ids* ride the
 * audit trail (as `credentialIds` on `accepted` events).
 */
export function applyOutboundCredentials(
  headers: Record<string, string | string[]>,
  endpoint: string,
  creds: CompiledOutboundCredential[] | undefined
): void {
  if (creds === undefined) return;
  for (const cred of creds) {
    for (const k of Object.keys(headers)) {
      if (k.toLowerCase() === cred.headerLower) delete headers[k];
    }
    const secret = cred.secretResolver(cred.secretRef);
    if (typeof secret !== "string" || secret === "") {
      throw new CredentialSecretUnavailableError(endpoint, cred.id, cred.secretRef);
    }
    headers[cred.header] = secret;
  }
}
