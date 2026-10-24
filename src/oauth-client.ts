/**
 * Outbound OAuth2 `client_credentials` token management (WR-129).
 *
 * Some downstreams — a bank's API gateway, a partner's token-gated
 * webhook receiver — require OAuth2 bearer tokens instead of (or in
 * addition to) the relay's own request signatures (WR-26 HMAC, WR-124
 * Ed25519, WR-116 SigV4). This module lets the relay act as the OAuth2
 * client on the downstream's behalf:
 *
 * - `tokenFor(cfg)` fetches an access token from the configured
 *   `token_endpoint` (RFC 6749 §4.4 `client_credentials` grant, posted
 *   as `application/x-www-form-urlencoded` via `node:https` — zero new
 *   dependencies) and caches it;
 * - the cache is keyed per `(token_endpoint, scope)` — a token minted
 *   for one endpoint/scope is never sent to another — with the
 *   `client_id` as an extra key dimension so two identities sharing an
 *   endpoint/scope still get their own tokens;
 * - a cached token is treated as expired `OAUTH2_CLOCK_SKEW_MS` (30s)
 *   before its `expires_in` elapses, so a downstream whose clock runs
 *   ahead never receives a token it considers stale;
 * - concurrent callers share one in-flight fetch (single-flight): a
 *   thundering herd on an expired token still issues exactly one token
 *   request;
 * - `refreshFor(cfg)` drops the cached entry and fetches unconditionally
 *   — the sender calls it once after a downstream 401, then retries the
 *   delivery with the fresh token inside the same attempt;
 * - the `client_secret` lives only in memory: it is never logged, never
 *   audited, and `OAuth2TokenError` messages never carry it.
 *
 * Clocks and the token fetch itself are injectable
 * (`OAuth2TokenCacheOptions`), so tests stay deterministic without
 * touching the network. Invalid configuration throws `RangeError` at
 * startup — never mid-delivery.
 *
 * WR-189: `private_key_jwt` client authentication (RFC 7523) is an
 * alternative to `client_secret` — a self-signed JWT
 * (`client_assertion`) with Ed25519 (`EdDSA`) or RS256, built fresh per
 * token fetch. The assertion cache, single-flight, and 401-refresh
 * mechanics are the token cache's and are unchanged: they operate on
 * the access token, never the assertion.
 *
 * WR-205: DPoP sender-constrained access tokens (RFC 9449) — a second,
 * orthogonal proof. The WR-189 assertion (or the `client_secret`)
 * authenticates the *client* to the token endpoint; the DPoP proof
 * proves *possession of the DPoP key* on every token use: a fresh proof
 * JWT rides the `DPoP` header of the token request itself (no `ath`
 * yet), and each downstream delivery stamps `Authorization: DPoP
 * <token>` plus a per-request proof binding method, target URI, and
 * the token (`ath`). A leaked token cannot be replayed from another
 * machine. The endpoint must answer `token_type: "DPoP"` — anything
 * else fails closed (the client-side binding confirmation) — and an
 * RFC 9449 §4.3 `use_dpop_nonce` challenge is retried once with a
 * fresh proof carrying the server nonce. Proofs, like secrets and
 * assertions, are never logged or audited.
 */

import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  sign as cryptoSign,
  type KeyObject,
} from "node:crypto";
import { compileEd25519OutboundKey } from "./outbound-ed25519.ts";

/** `client_assertion_type` value for JWT bearer assertions (RFC 7523 §2.2). */
export const PRIVATE_KEY_JWT_ASSERTION_TYPE =
  "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/** How long a `private_key_jwt` assertion is valid (RFC 7523: keep it short). */
export const PRIVATE_KEY_JWT_EXPIRY_SECONDS = 300;

/** HTTP header carrying a DPoP proof JWT (RFC 9449 §4.2 / §7.1). */
export const DPOP_PROOF_HEADER = "DPoP";

/** HTTP header carrying the authorization server's DPoP nonce (RFC 9449 §4.3). */
export const DPOP_NONCE_HEADER = "DPoP-Nonce";

/** `token_type` a DPoP-capable token endpoint must return (RFC 9449 §6.1). */
export const DPOP_TOKEN_TYPE = "DPoP";

/** Safety margin: a token counts as expired this early (clock-skew reserve). */
export const OAUTH2_CLOCK_SKEW_MS = 30_000;

/** Fallback token TTL when the endpoint omits `expires_in`. */
export const OAUTH2_DEFAULT_EXPIRES_IN_MS = 300_000;

/** Default timeout for one token request. */
export const OAUTH2_TOKEN_REQUEST_TIMEOUT_MS = 10_000;

/**
 * WR-205: DPoP proof key configuration (RFC 9449). When set, the relay
 * proves possession of this key on every token use: a fresh DPoP proof
 * JWT rides the `DPoP` header of the token request itself, and every
 * downstream delivery stamps `Authorization: DPoP <token>` plus a
 * per-request proof binding the HTTP method, the target URI, and the
 * access token (`ath` — the token's SHA-256 thumbprint). A leaked
 * token is useless without the key: it cannot be replayed from another
 * machine.
 *
 * Orthogonal to the client-authentication method: `dpop` composes with
 * either `client_secret` or WR-189 `private_key_jwt`. The assertion
 * proves *who* asks the token endpoint; the DPoP proof proves *the
 * asker holds the key* on every use of the issued token.
 */
export interface DpopKeyConfig {
  /**
   * PEM-encoded private key: Ed25519 or P-256 EC (`alg` selects).
   * Parsed once at startup, fail-fast. Ed25519 keys reuse the
   * outbound-Ed25519 key management (`compileEd25519OutboundKey`).
   */
  privateKey: string;
  /**
   * Stable key id. DPoP identifies the key by its embedded JWK (not
   * `kid`), so this is bookkeeping only — used to isolate the token
   * cache between keys. Optional.
   */
  keyId?: string;
  /** Signing algorithm: Ed25519 (EdDSA) or ES256 (P-256). */
  alg: "Ed25519" | "ES256";
}

/**
 * Per-endpoint OAuth2 `client_credentials` configuration, as given in
 * the relay options (`oauth2: { "<exact targetUrl>": ... }`).
 */
export interface OAuth2ClientCredentialsConfig {
  /**
   * Token endpoint URL. Non-empty; `https:` in production (`http:` is
   * accepted for local test doubles — the secret travels in the POST
   * body, so plain HTTP leaks it on the wire).
   */
  token_endpoint: string;
  /** OAuth2 `client_id`. Non-empty. */
  client_id: string;
  /**
   * OAuth2 `client_secret`. Memory-only: never logged, never audited,
   * never rendered by any stats/introspection method. Exactly one of
   * `client_secret` / `private_key_jwt` must be set.
   */
  client_secret?: string;
  /**
   * WR-189: OAuth2 `private_key_jwt` client authentication (RFC 7523).
   * When set, the relay proves its identity with a self-signed JWT
   * (`client_assertion`) instead of `client_secret` — what FAPI /
   * bank-gateway token endpoints require. Exactly one of
   * `client_secret` / `private_key_jwt` must be set.
   */
  private_key_jwt?: {
    /**
     * PEM-encoded private key: Ed25519 or RS256 (`alg` selects).
     * Parsed once at startup, fail-fast. Ed25519 keys reuse the
     * outbound-Ed25519 key management (`compileEd25519OutboundKey`).
     */
    privateKey: string;
    /**
     * Stable key id, stamped as the JWT's `kid` so the token endpoint
     * can select the matching public key. Optional.
     */
    keyId?: string;
    /** Signing algorithm: Ed25519 (EdDSA) or RS256. */
    alg: "Ed25519" | "RS256";
  };
  /** Optional space-delimited `scope`. Non-empty when set. */
  scope?: string;
  /**
   * WR-205: DPoP sender-constrained access tokens (RFC 9449). Optional;
   * composes with either `client_secret` or `private_key_jwt`
   * authentication. The DPoP key is memory-only: never logged, never
   * audited, exactly like the secret and the assertion.
   */
  dpop?: DpopKeyConfig;
}

/**
 * WR-205: a validated DPoP key — the private key parsed once at
 * startup, the public JWK and its RFC 7638 thumbprint (`jkt`)
 * precomputed so proof construction never touches key parsing.
 */
export interface ResolvedDpopKey {
  privateKey: KeyObject;
  keyId?: string;
  alg: "Ed25519" | "ES256";
  /**
   * Public JWK embedded in every proof's header (`jwk`) — public
   * material only, never the private key.
   */
  jwk: { kty: string; crv: string; x: string; y?: string };
  /**
   * RFC 7638 JWK SHA-256 thumbprint — the `jkt` the authorization
   * server binds the access token to. Compare against the AS's token
   * introspection to confirm the binding out of band.
   */
  jkt: string;
}

/** A validated OAuth2 config: the endpoint parsed once at startup. */
export interface ResolvedOAuth2ClientConfig {
  tokenEndpoint: URL;
  clientId: string;
  clientSecret?: string;
  /**
   * WR-189: compiled `private_key_jwt` assertion key — the private key
   * parsed once at startup, the id stamped per assertion.
   */
  assertion?: {
    privateKey: KeyObject;
    keyId?: string;
    alg: "Ed25519" | "RS256";
  };
  /**
   * WR-205: compiled DPoP proof key — the private key parsed once at
   * startup, the public JWK and `jkt` precomputed.
   */
  dpop?: ResolvedDpopKey;
  scope?: string;
}

/**
 * Validate an OAuth2 client config. Throws `RangeError` on invalid
 * values — call at startup, never mid-delivery.
 */
export function resolveOAuth2ClientConfig(
  cfg: OAuth2ClientCredentialsConfig,
  where: string
): ResolvedOAuth2ClientConfig {
  if (cfg === null || typeof cfg !== "object" || Array.isArray(cfg)) {
    throw new RangeError(`${where} must be an object`);
  }
  if (typeof cfg.token_endpoint !== "string" || cfg.token_endpoint.trim() === "") {
    throw new RangeError(`${where}: \`token_endpoint\` must be a non-empty URL string`);
  }
  let tokenEndpoint: URL;
  try {
    tokenEndpoint = new URL(cfg.token_endpoint);
  } catch {
    throw new RangeError(`${where}: \`token_endpoint\` is not a valid URL`);
  }
  if (tokenEndpoint.protocol !== "https:" && tokenEndpoint.protocol !== "http:") {
    throw new RangeError(
      `${where}: \`token_endpoint\` must be an http(s) URL, got ${tokenEndpoint.protocol}`
    );
  }
  if (typeof cfg.client_id !== "string" || cfg.client_id === "") {
    throw new RangeError(`${where}: \`client_id\` must be a non-empty string`);
  }
  const hasSecret = typeof cfg.client_secret === "string" && cfg.client_secret !== "";
  const hasAssertion =
    cfg.private_key_jwt !== null && typeof cfg.private_key_jwt === "object";
  // WR-189: exactly one client-authentication method — the token
  // endpoint must never see a secret *and* an assertion, and it must
  // see one of them.
  if (hasSecret === hasAssertion) {
    throw new RangeError(
      `${where}: exactly one of \`client_secret\` / \`private_key_jwt\` must be set`
    );
  }
  let assertion: ResolvedOAuth2ClientConfig["assertion"];
  if (hasAssertion) {
    assertion = compilePrivateKeyJwtAssertion(
      cfg.private_key_jwt as NonNullable<OAuth2ClientCredentialsConfig["private_key_jwt"]>,
      `${where}: \`private_key_jwt\``
    );
  }
  if (cfg.scope !== undefined && (typeof cfg.scope !== "string" || cfg.scope.trim() === "")) {
    throw new RangeError(`${where}: \`scope\` must be a non-empty string when set`);
  }
  // WR-205: the DPoP proof key is validated and parsed once here, at
  // startup — a missing or malformed key refuses to boot, never
  // surfaces as a mid-delivery failure.
  let dpop: ResolvedDpopKey | undefined;
  if (cfg.dpop !== undefined) {
    dpop = compileDpopKey(cfg.dpop, `${where}: \`dpop\``);
  }
  return {
    tokenEndpoint,
    clientId: cfg.client_id,
    ...(hasSecret ? { clientSecret: cfg.client_secret as string } : {}),
    ...(assertion !== undefined ? { assertion } : {}),
    ...(dpop !== undefined ? { dpop } : {}),
    ...(cfg.scope !== undefined ? { scope: cfg.scope } : {}),
  };
}

/**
 * WR-189: validate a `private_key_jwt` config and parse the private key
 * once at startup. Ed25519 keys reuse the outbound-Ed25519 key
 * management (`compileEd25519OutboundKey` — WR-124); RS256 keys are
 * parsed here. Throws `RangeError` on any bad shape — call at startup,
 * never mid-delivery.
 */
function compilePrivateKeyJwtAssertion(
  cfg: NonNullable<OAuth2ClientCredentialsConfig["private_key_jwt"]>,
  where: string
): NonNullable<ResolvedOAuth2ClientConfig["assertion"]> {
  if (cfg.alg !== "Ed25519" && cfg.alg !== "RS256") {
    throw new RangeError(`${where}: \`alg\` must be "Ed25519" or "RS256"`);
  }
  if (cfg.keyId !== undefined && (typeof cfg.keyId !== "string" || cfg.keyId === "")) {
    throw new RangeError(`${where}: \`keyId\` must be a non-empty string when set`);
  }
  if (cfg.alg === "Ed25519") {
    const compiled = compileEd25519OutboundKey(
      { privateKey: cfg.privateKey, ...(cfg.keyId !== undefined ? { keyId: cfg.keyId } : {}) },
      where
    );
    return { privateKey: compiled.privateKey, keyId: compiled.keyId, alg: "Ed25519" };
  }
  if (typeof cfg.privateKey !== "string" || cfg.privateKey.trim() === "") {
    throw new RangeError(`${where}: \`privateKey\` must be a non-empty PEM string`);
  }
  let key: KeyObject;
  try {
    key = createPrivateKey(cfg.privateKey);
  } catch {
    throw new RangeError(`${where}: \`privateKey\` is not a valid PEM private key`);
  }
  if (key.asymmetricKeyType !== "rsa") {
    throw new RangeError(
      `${where}: \`privateKey\` must be an RSA private key for RS256, got ${key.asymmetricKeyType ?? "unknown"}`
    );
  }
  return { privateKey: key, keyId: cfg.keyId, alg: "RS256" };
}

function base64UrlEncode(data: Buffer | string): string {
  return Buffer.from(data).toString("base64url");
}

/** Input for {@link buildPrivateKeyJwtAssertion}. */
export interface PrivateKeyJwtAssertionInput {
  /** OAuth2 `client_id` — stamped as the JWT's `iss`/`sub`. */
  clientId: string;
  /** Token endpoint URL string — stamped as the JWT's `aud` (RFC 7523 §3). */
  tokenEndpoint: string;
  /** Compiled assertion key (from {@link resolveOAuth2ClientConfig}). */
  assertion: NonNullable<ResolvedOAuth2ClientConfig["assertion"]>;
  /** Signing instant; defaults to now. Inject for deterministic tests. */
  nowMs?: number;
  /** `jti` nonce; defaults to 16 random bytes (hex). */
  jti?: string;
}

/**
 * WR-189: build an OAuth2 `private_key_jwt` client assertion
 * (RFC 7523 §2.2 / §3): a self-signed JWT with `iss`/`sub` = the
 * `client_id`, `aud` = the token endpoint, a unique `jti`, and a short
 * expiry (`PRIVATE_KEY_JWT_EXPIRY_SECONDS`). Signed with Ed25519
 * (`EdDSA`) or RS256 per the configured `alg`, with `kid` stamped when
 * a `keyId` is configured. `node:crypto` only, zero new dependencies.
 *
 * The assertion carries no secret — only the signature proves
 * possession of the private key — but it is still a short-lived
 * credential: callers must never log it (the token fetcher names the
 * endpoint and status only, exactly like the `client_secret` path).
 */
export function buildPrivateKeyJwtAssertion(input: PrivateKeyJwtAssertionInput): string {
  const nowSec = Math.floor((input.nowMs ?? Date.now()) / 1000);
  const header: Record<string, string> = {
    alg: input.assertion.alg === "Ed25519" ? "EdDSA" : "RS256",
    typ: "JWT",
  };
  if (input.assertion.keyId !== undefined) {
    header["kid"] = input.assertion.keyId;
  }
  const payload = {
    iss: input.clientId,
    sub: input.clientId,
    aud: input.tokenEndpoint,
    jti: input.jti ?? randomBytes(16).toString("hex"),
    iat: nowSec,
    exp: nowSec + PRIVATE_KEY_JWT_EXPIRY_SECONDS,
  };
  const signingInput = `${base64UrlEncode(JSON.stringify(header))}.${base64UrlEncode(JSON.stringify(payload))}`;
  const data = Buffer.from(signingInput, "utf8");
  const signature =
    input.assertion.alg === "Ed25519"
      ? cryptoSign(null, data, input.assertion.privateKey)
      : cryptoSign("RSA-SHA256", data, input.assertion.privateKey);
  return `${signingInput}.${base64UrlEncode(signature)}`;
}

/** The token endpoint's JSON response (RFC 6749 §5.1). */
export interface OAuth2TokenResponse {
  access_token: string;
  expires_in?: number;
}

/**
 * WR-205: validate a DPoP key config and parse the private key once at
 * startup. Ed25519 keys reuse the outbound-Ed25519 key management
 * (`compileEd25519OutboundKey` — WR-124); ES256 keys must be P-256 EC
 * keys. The public JWK and its RFC 7638 thumbprint are precomputed
 * here, so proof construction never parses keys. Throws `RangeError`
 * on any bad shape — call at startup, never mid-delivery.
 */
function compileDpopKey(cfg: DpopKeyConfig, where: string): ResolvedDpopKey {
  if (cfg === null || typeof cfg !== "object" || Array.isArray(cfg)) {
    throw new RangeError(`${where} must be an object`);
  }
  if (cfg.alg !== "Ed25519" && cfg.alg !== "ES256") {
    throw new RangeError(`${where}: \`alg\` must be "Ed25519" or "ES256"`);
  }
  if (cfg.keyId !== undefined && (typeof cfg.keyId !== "string" || cfg.keyId === "")) {
    throw new RangeError(`${where}: \`keyId\` must be a non-empty string when set`);
  }
  let privateKey: KeyObject;
  if (cfg.alg === "Ed25519") {
    privateKey = compileEd25519OutboundKey(
      {
        privateKey: cfg.privateKey,
        ...(cfg.keyId !== undefined ? { keyId: cfg.keyId } : {}),
      },
      where
    ).privateKey;
  } else {
    if (typeof cfg.privateKey !== "string" || cfg.privateKey.trim() === "") {
      throw new RangeError(`${where}: \`privateKey\` must be a non-empty PEM string`);
    }
    try {
      privateKey = createPrivateKey(cfg.privateKey);
    } catch {
      throw new RangeError(`${where}: \`privateKey\` is not a valid PEM private key`);
    }
    const namedCurve = privateKey.asymmetricKeyDetails?.namedCurve;
    // Node reports the OpenSSL curve name (`prime256v1`); accept the
    // JWA name (`P-256`) too.
    if (
      privateKey.asymmetricKeyType !== "ec" ||
      (namedCurve !== "P-256" && namedCurve !== "prime256v1")
    ) {
      throw new RangeError(
        `${where}: \`privateKey\` must be a P-256 EC private key for ES256, got ` +
          `${privateKey.asymmetricKeyType ?? "unknown"}${namedCurve !== undefined ? `/${namedCurve}` : ""}`
      );
    }
  }
  const jwk = exportDpopPublicJwk(privateKey, where);
  return {
    privateKey,
    keyId: cfg.keyId,
    alg: cfg.alg,
    jwk,
    jkt: dpopJwkThumbprint(jwk),
  };
}

/**
 * Export the public half of a compiled DPoP key as a minimal JWK —
 * public material only. Throws `RangeError` when the key does not
 * export the expected shape (an internal invariant: the key was just
 * validated above).
 */
function exportDpopPublicJwk(
  privateKey: KeyObject,
  where: string
): ResolvedDpopKey["jwk"] {
  let exported: unknown;
  try {
    exported = createPublicKey(privateKey).export({ format: "jwk" });
  } catch {
    throw new RangeError(`${where}: cannot export the DPoP public key`);
  }
  const jwk = exported as Record<string, unknown>;
  if (jwk["kty"] === "OKP" && jwk["crv"] === "Ed25519" && typeof jwk["x"] === "string") {
    return { kty: "OKP", crv: "Ed25519", x: jwk["x"] };
  }
  if (
    jwk["kty"] === "EC" &&
    jwk["crv"] === "P-256" &&
    typeof jwk["x"] === "string" &&
    typeof jwk["y"] === "string"
  ) {
    return { kty: "EC", crv: "P-256", x: jwk["x"], y: jwk["y"] };
  }
  throw new RangeError(`${where}: the DPoP key exported an unexpected public JWK`);
}

/**
 * WR-205: RFC 7638 JWK SHA-256 thumbprint of a DPoP public key — the
 * `jkt` the authorization server binds the access token to. The
 * canonical member order is fixed by the RFC (lexicographic), so the
 * thumbprint is stable across implementations.
 */
export function dpopJwkThumbprint(jwk: ResolvedDpopKey["jwk"]): string {
  const canonical =
    jwk.kty === "OKP"
      ? `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}"}`
      : `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
  return createHash("sha256").update(canonical, "utf8").digest().toString("base64url");
}

/**
 * Convert a DER-encoded ECDSA signature (what `node:crypto` returns)
 * to the raw fixed-width `R || S` form JWS ES256 requires (RFC 7518
 * §3.4). `node:crypto` always emits valid DER for its own signatures,
 * so a malformed input here is an internal invariant violation.
 */
function derToRawEcdsaSignature(der: Buffer): Buffer {
  let off = 0;
  const fail = (): RangeError => new RangeError("DPoP: malformed DER ECDSA signature");
  if (der[off++] !== 0x30) throw fail();
  let len = der[off++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 2) throw fail();
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | (der[off++] ?? 0);
  }
  void len;
  const takeInt = (): Buffer => {
    if (der[off++] !== 0x02) throw fail();
    const intLen = der[off++] ?? 0;
    if (intLen === 0 || intLen > 33) throw fail();
    let v = der.subarray(off, off + intLen);
    off += intLen;
    while (v.length > 1 && v[0] === 0x00) v = v.subarray(1);
    if (v.length > 32) throw fail();
    const out = Buffer.alloc(32);
    v.copy(out, 32 - v.length);
    return out;
  };
  const r = takeInt();
  const s = takeInt();
  if (off !== der.length) throw fail();
  return Buffer.concat([r, s]);
}

/**
 * Normalize a DPoP `htu` claim per RFC 9449 §4.2: the HTTP URI
 * *without* query and fragment parts — the proof binds the endpoint,
 * not one request's parameters.
 */
function normalizeDpopHtu(raw: string): string {
  if (typeof raw !== "string" || raw === "") {
    throw new RangeError("DPoP proof: `htu` must be a non-empty URL string");
  }
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new RangeError("DPoP proof: `htu` is not a valid URL");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new RangeError(`DPoP proof: \`htu\` must be an http(s) URL, got ${url.protocol}`);
  }
  url.hash = "";
  url.search = "";
  return url.toString();
}

/** Input for {@link buildDpopProofJwt}. */
export interface DpopProofInput {
  /** Compiled DPoP key (from {@link resolveOAuth2ClientConfig}). */
  dpop: ResolvedDpopKey;
  /** HTTP method of the request the proof is attached to (e.g. `"POST"`). Non-empty. */
  htm: string;
  /**
   * HTTP URI of the request the proof is attached to — normalized
   * inside (query and fragment stripped, RFC 9449 §4.2).
   */
  htu: string;
  /**
   * Access token the proof is bound to: stamped as `ath`
   * (base64url(SHA-256(token)), RFC 9449 §4.2). Set for resource
   * requests; omitted for the token request itself, where no token
   * exists yet.
   */
  accessToken?: string;
  /**
   * Server `DPoP-Nonce` challenge value (RFC 9449 §4.3): set after a
   * `use_dpop_nonce` rejection. Non-empty when set.
   */
  nonce?: string;
  /** Signing instant; defaults to now. Inject for deterministic tests. */
  nowMs?: number;
  /** `jti` nonce; defaults to 16 random bytes (hex) — unique per proof. */
  jti?: string;
}

/**
 * WR-205: build a DPoP proof JWT (RFC 9449 §4.2): header
 * `{typ:"dpop+jwt", alg, jwk}` with the public key embedded, payload
 * `{htm, htu, iat, jti}` plus `ath` when the proof accompanies an
 * access token and `nonce` after a server challenge. Ed25519 signs
 * with EdDSA, P-256 with ES256 — `node:crypto` only, zero new
 * dependencies.
 *
 * The proof is a short-lived bearer of key possession: it
 * authenticates as the relay. Like the `client_secret` and the WR-189
 * assertion, it must never be logged or audited — the token fetcher
 * names the endpoint and status only.
 */
export function buildDpopProofJwt(input: DpopProofInput): string {
  if (input === null || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("DPoP proof input must be an object");
  }
  const dpop = input.dpop;
  // `KeyObject` is a type-only import (erased by type stripping), so
  // this is a structural check, not `instanceof`.
  if (
    dpop === null ||
    typeof dpop !== "object" ||
    (dpop.alg !== "Ed25519" && dpop.alg !== "ES256") ||
    dpop.privateKey === null ||
    typeof dpop.privateKey !== "object"
  ) {
    throw new TypeError("DPoP proof input: `dpop` must be a compiled DPoP key");
  }
  if (typeof input.htm !== "string" || input.htm.trim() === "") {
    throw new RangeError("DPoP proof: `htm` must be a non-empty HTTP method");
  }
  const htu = normalizeDpopHtu(input.htu);
  if (
    input.accessToken !== undefined &&
    (typeof input.accessToken !== "string" || input.accessToken === "")
  ) {
    throw new RangeError("DPoP proof: `accessToken` must be a non-empty string when set");
  }
  if (input.nonce !== undefined && (typeof input.nonce !== "string" || input.nonce === "")) {
    throw new RangeError("DPoP proof: `nonce` must be a non-empty string when set");
  }
  if (input.jti !== undefined && (typeof input.jti !== "string" || input.jti === "")) {
    throw new RangeError("DPoP proof: `jti` must be a non-empty string when set");
  }
  const nowSec = Math.floor((input.nowMs ?? Date.now()) / 1000);
  const header = {
    typ: "dpop+jwt",
    alg: dpop.alg === "Ed25519" ? "EdDSA" : "ES256",
    jwk:
      dpop.alg === "Ed25519"
        ? { kty: dpop.jwk.kty, crv: dpop.jwk.crv, x: dpop.jwk.x }
        : { kty: dpop.jwk.kty, crv: dpop.jwk.crv, x: dpop.jwk.x, y: dpop.jwk.y },
  };
  const payload: Record<string, unknown> = {
    htm: input.htm,
    htu,
    iat: nowSec,
    jti: input.jti ?? randomBytes(16).toString("hex"),
  };
  if (input.accessToken !== undefined) {
    payload["ath"] = createHash("sha256")
      .update(input.accessToken, "utf8")
      .digest()
      .toString("base64url");
  }
  if (input.nonce !== undefined) {
    payload["nonce"] = input.nonce;
  }
  const signingInput = `${base64UrlEncode(JSON.stringify(header))}.${base64UrlEncode(JSON.stringify(payload))}`;
  const data = Buffer.from(signingInput, "utf8");
  const signature =
    dpop.alg === "Ed25519"
      ? cryptoSign(null, data, dpop.privateKey)
      : derToRawEcdsaSignature(cryptoSign("SHA256", data, dpop.privateKey));
  return `${signingInput}.${base64UrlEncode(signature)}`;
}

/**
 * Thrown for token endpoint failures: unreachable endpoint, non-2xx
 * status, malformed JSON, missing `access_token`. The message never
 * carries the `client_secret`, the WR-189 assertion, or a WR-205 DPoP
 * proof — it names the endpoint and status only.
 */
export class OAuth2TokenError extends Error {
  /**
   * HTTP status of the token endpoint response, when a response was
   * received (`undefined` for transport failures).
   */
  readonly statusCode?: number;
  /**
   * WR-205: the authorization server's `DPoP-Nonce` challenge from a
   * `use_dpop_nonce` rejection (RFC 9449 §4.3). Not sensitive — a
   * server-issued challenge, safe to surface to the caller.
   */
  readonly dpopNonce?: string;
  constructor(message: string, opts?: { statusCode?: number; dpopNonce?: string }) {
    super(message);
    this.name = "OAuth2TokenError";
    if (opts?.statusCode !== undefined) this.statusCode = opts.statusCode;
    if (opts?.dpopNonce !== undefined) this.dpopNonce = opts.dpopNonce;
  }
}

/** Parameters for an {@link OAuth2TokenFetcher}. */
export interface OAuth2TokenFetchParams {
  tokenEndpoint: URL;
  clientId: string;
  /**
   * Memory-only: a fetcher must never log or persist this. Set only
   * for `client_secret` configs.
   */
  clientSecret?: string;
  /**
   * WR-189: a freshly built `private_key_jwt` client assertion
   * (RFC 7523) for this fetch. Set only for `private_key_jwt`
   * configs, mutually exclusive with `clientSecret`.
   */
  clientAssertionJwt?: string;
  /**
   * WR-205: a freshly built DPoP proof JWT for the token request
   * (RFC 9449 §4.2 — no `ath`, since no token exists yet). Sent as the
   * `DPoP` header. Like the assertion, it is never logged.
   */
  dpopProofJwt?: string;
  scope?: string;
  /** Per-request timeout in ms. */
  timeoutMs: number;
}

/**
 * Fetch one token from the token endpoint. Injectable so tests can
 * stub the endpoint without network access.
 */
export type OAuth2TokenFetcher = (
  params: OAuth2TokenFetchParams
) => Promise<OAuth2TokenResponse>;

function assertValidTokenResponse(
  parsed: unknown,
  endpoint: URL,
  dpopBound: boolean
): OAuth2TokenResponse {
  const where = `oauth2 token response from ${endpoint.host}${endpoint.pathname}`;
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new OAuth2TokenError(`${where}: not a JSON object`);
  }
  const p = parsed as Record<string, unknown>;
  if (typeof p.access_token !== "string" || p.access_token === "") {
    throw new OAuth2TokenError(`${where}: missing \`access_token\``);
  }
  if (dpopBound) {
    // WR-205: the client-side binding confirmation. A DPoP proof was
    // presented, so the issued token must be DPoP-bound (RFC 9449
    // §6.1) — the authorization server confirms the binding by
    // returning `token_type: "DPoP"`. A `Bearer` token here would not
    // be sender-constrained: fail closed instead of stamping a token
    // whose stolen copy could be replayed from anywhere.
    if (
      typeof p.token_type !== "string" ||
      p.token_type.toLowerCase() !== DPOP_TOKEN_TYPE.toLowerCase()
    ) {
      throw new OAuth2TokenError(
        `${where}: expected \`token_type\` "${DPOP_TOKEN_TYPE}" for a DPoP-bound token`
      );
    }
  } else if (
    // Only bearer tokens are supported: the sender stamps
    // `Authorization: Bearer <token>`, and stamping anything else under
    // a Bearer scheme would be a lie the downstream cannot verify.
    p.token_type !== undefined &&
    (typeof p.token_type !== "string" || p.token_type.toLowerCase() !== "bearer")
  ) {
    throw new OAuth2TokenError(
      `${where}: unsupported \`token_type\` (only Bearer is supported)`
    );
  }
  if (
    p.expires_in !== undefined &&
    (typeof p.expires_in !== "number" || !Number.isFinite(p.expires_in) || p.expires_in < 0)
  ) {
    throw new OAuth2TokenError(`${where}: invalid \`expires_in\``);
  }
  return {
    access_token: p.access_token,
    ...(typeof p.expires_in === "number" ? { expires_in: p.expires_in } : {}),
  };
}

/**
 * The default token fetcher: one `POST` with
 * `grant_type=client_credentials`, `node:http(s)` only.
 *
 * WR-189: for `private_key_jwt` configs the request carries
 * `client_assertion_type` + `client_assertion` (RFC 7523 §2.2) instead
 * of `client_secret`; `client_id` is sent in both cases (the assertion
 * already identifies the client via `iss`/`sub`, but some token
 * endpoints expect the field). The assertion — like the secret —
 * travels in the form body; it is never written to any log, and error
 * messages name the endpoint and status only.
 *
 * WR-205: for DPoP configs the request additionally carries the proof
 * in the `DPoP` header (RFC 9449 §4.2) — composed with either client
 * authentication method. An RFC 9449 §4.3 `use_dpop_nonce` rejection
 * surfaces the server's `DPoP-Nonce` challenge on the thrown
 * `OAuth2TokenError` (as `dpopNonce`, with `statusCode`), so the
 * caller can retry once with a fresh proof carrying it.
 */
export function defaultOAuth2TokenFetcher(
  params: OAuth2TokenFetchParams
): Promise<OAuth2TokenResponse> {
  return new Promise((resolve, reject) => {
    const form = new URLSearchParams({ grant_type: "client_credentials" });
    form.set("client_id", params.clientId);
    if (params.clientAssertionJwt !== undefined) {
      form.set("client_assertion_type", PRIVATE_KEY_JWT_ASSERTION_TYPE);
      form.set("client_assertion", params.clientAssertionJwt);
    } else if (params.clientSecret !== undefined) {
      form.set("client_secret", params.clientSecret);
    } else {
      reject(
        new OAuth2TokenError(
          `oauth2 token request failed: no client authentication configured for ${params.tokenEndpoint.host}${params.tokenEndpoint.pathname}`
        )
      );
      return;
    }
    if (params.scope !== undefined) {
      form.set("scope", params.scope);
    }
    const body = form.toString();
    const endpoint = params.tokenEndpoint;
    const requestFn = endpoint.protocol === "https:" ? httpsRequest : httpRequest;
    const fail = (message: string): void => {
      reject(new OAuth2TokenError(`oauth2 token request failed: ${message}`));
    };
    let req;
    try {
      req = requestFn(
        {
          protocol: endpoint.protocol,
          hostname: endpoint.hostname,
          port: endpoint.port === "" ? undefined : Number(endpoint.port),
          path: `${endpoint.pathname}${endpoint.search}`,
          method: "POST",
          headers: {
            "content-type": "application/x-www-form-urlencoded",
            "content-length": String(Buffer.byteLength(body)),
            accept: "application/json",
            // WR-205: the token-request proof rides the `DPoP` header.
            ...(params.dpopProofJwt !== undefined ? { [DPOP_PROOF_HEADER]: params.dpopProofJwt } : {}),
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          // Cap the response: a token response is tiny; a huge body is
          // either a misconfigured endpoint or a DoS attempt.
          let bytes = 0;
          res.on("data", (c: Buffer) => {
            bytes += c.length;
            if (bytes <= 64 * 1024) chunks.push(c);
          });
          res.on("end", () => {
            if (bytes > 64 * 1024) {
              fail(`${endpoint.host}${endpoint.pathname}: response too large`);
              return;
            }
            const status = res.statusCode ?? 0;
            if (status < 200 || status >= 300) {
              // WR-205: surface an RFC 9449 §4.3 nonce challenge so the
              // caller can retry once with a fresh proof carrying it.
              // The challenge is a server-issued nonce, not a secret —
              // safe to surface. The proof itself stays out of the
              // error, exactly like the secret and the assertion.
              let dpopNonce: string | undefined;
              if (status === 400 && params.dpopProofJwt !== undefined) {
                try {
                  const bodyText = Buffer.concat(chunks).toString("utf8");
                  const errCode = (JSON.parse(bodyText) as { error?: unknown }).error;
                  if (errCode === "use_dpop_nonce") {
                    const header = res.headers[DPOP_NONCE_HEADER.toLowerCase()];
                    if (typeof header === "string" && header !== "") dpopNonce = header;
                  }
                } catch {
                  // Not a JSON nonce challenge — a plain failure below.
                }
              }
              reject(
                new OAuth2TokenError(
                  `oauth2 token request failed: ${endpoint.host}${endpoint.pathname} -> HTTP ${status}`,
                  {
                    statusCode: status,
                    ...(dpopNonce !== undefined ? { dpopNonce } : {}),
                  }
                )
              );
              return;
            }
            let parsed: unknown;
            try {
              parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
            } catch {
              fail(`${endpoint.host}${endpoint.pathname}: response is not JSON`);
              return;
            }
            try {
              resolve(assertValidTokenResponse(parsed, endpoint, params.dpopProofJwt !== undefined));
            } catch (err) {
              reject(err);
            }
          });
        }
      );
    } catch (err) {
      fail((err as Error).message);
      return;
    }
    req.on("error", (err) => fail((err as Error).message));
    req.setTimeout(params.timeoutMs, () => {
      req.destroy();
      fail(`${endpoint.host}${endpoint.pathname}: timed out after ${params.timeoutMs}ms`);
    });
    req.end(body);
  });
}

/** Options for {@link OAuth2TokenCache}. */
export interface OAuth2TokenCacheOptions {
  /** Clock source; defaults to `Date.now`. Injectable for tests. */
  nowMs?: () => number;
  /** Token fetch implementation; defaults to {@link defaultOAuth2TokenFetcher}. */
  fetchToken?: OAuth2TokenFetcher;
  /** Per-request timeout handed to the fetcher; default {@link OAUTH2_TOKEN_REQUEST_TIMEOUT_MS}. */
  tokenRequestTimeoutMs?: number;
}

interface CachedOAuth2Token {
  token: string;
  /** `nowMs()` instant at which the token must be refetched (skew already applied). */
  expiresAtMs: number;
}

/**
 * In-memory OAuth2 access-token cache for `client_credentials` grants.
 *
 * Tokens are isolated per `(token_endpoint, scope)` — a token minted
 * for one endpoint/scope is never sent to another — with `client_id`
 * as an extra key dimension, so two identities sharing an endpoint and
 * scope still get their own tokens. Cached entries expire
 * {@link OAUTH2_CLOCK_SKEW_MS} early; endpoints that omit `expires_in`
 * get {@link OAUTH2_DEFAULT_EXPIRES_IN_MS}. Concurrent callers share a
 * single in-flight fetch per key. Holds `client_secret`s in memory
 * only — nothing here is ever logged, audited, or serialized.
 */
export class OAuth2TokenCache {
  private readonly nowMs: () => number;
  private readonly fetchToken: OAuth2TokenFetcher;
  private readonly tokenRequestTimeoutMs: number;
  private readonly entries = new Map<string, CachedOAuth2Token>();
  private readonly inflight = new Map<string, Promise<string>>();
  /**
   * WR-205: the authorization server's latest `DPoP-Nonce` per cache
   * key (RFC 9449 §4.3). A nonce learned from a `use_dpop_nonce`
   * rejection is sent proactively on the next fetch for the same key
   * instead of paying for another challenge round-trip. Nonces are not
   * secrets — server-issued challenges.
   */
  private readonly dpopNonces = new Map<string, string>();

  constructor(opts: OAuth2TokenCacheOptions = {}) {
    this.nowMs = opts.nowMs ?? Date.now;
    this.fetchToken = opts.fetchToken ?? defaultOAuth2TokenFetcher;
    const timeoutMs = opts.tokenRequestTimeoutMs ?? OAUTH2_TOKEN_REQUEST_TIMEOUT_MS;
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      throw new RangeError(
        `OAuth2TokenCache: \`tokenRequestTimeoutMs\` must be a positive finite number, got ${timeoutMs}`
      );
    }
    this.tokenRequestTimeoutMs = timeoutMs;
  }

  private keyFor(cfg: ResolvedOAuth2ClientConfig): string {
    const base = `${cfg.tokenEndpoint.href}\n${cfg.scope ?? ""}\n${cfg.clientId}`;
    // WR-189: the assertion key is part of the identity — two configs
    // with the same client_id but different signing keys must not
    // share a cached token. Secret-based keys are unchanged
    // (byte-identical to before).
    const assertionDim = cfg.assertion !== undefined ? `\n${cfg.assertion.keyId ?? ""}` : "";
    // WR-205: a DPoP-bound token is bound to the proof key — two
    // configs sharing a client_id but using different DPoP keys must
    // not share a cached token. Non-DPoP keys are unchanged
    // (byte-identical to before).
    const dpopDim = cfg.dpop !== undefined ? `\n${cfg.dpop.jkt}` : "";
    return `${base}${assertionDim}${dpopDim}`;
  }

  /**
   * A valid access token for `cfg`: the cached one when still fresh,
   * otherwise exactly one fetch (concurrent callers share it).
   * Throws `RangeError` for invalid config, `OAuth2TokenError` for
   * endpoint failures.
   */
  async tokenFor(cfg: OAuth2ClientCredentialsConfig): Promise<string> {
    const resolved = resolveOAuth2ClientConfig(cfg, "OAuth2TokenCache.tokenFor");
    const key = this.keyFor(resolved);
    const cached = this.entries.get(key);
    if (cached !== undefined && cached.expiresAtMs > this.nowMs()) {
      return cached.token;
    }
    return this.fetchOnce(key, resolved);
  }

  /**
   * Drop the cached token for `(token_endpoint, scope)` and fetch a
   * fresh one unconditionally — the sender's 401 recovery path.
   */
  async refreshFor(cfg: OAuth2ClientCredentialsConfig): Promise<string> {
    const resolved = resolveOAuth2ClientConfig(cfg, "OAuth2TokenCache.refreshFor");
    const key = this.keyFor(resolved);
    this.entries.delete(key);
    return this.fetchOnce(key, resolved);
  }

  /** Number of cached token entries (introspection for tests/ops; no secrets). */
  size(): number {
    return this.entries.size;
  }

  private fetchOnce(key: string, cfg: ResolvedOAuth2ClientConfig): Promise<string> {
    const ongoing = this.inflight.get(key);
    if (ongoing !== undefined) return ongoing;
    // WR-205: the token-request proof carries no `ath` — no token
    // exists yet — and picks up the server nonce learned from a
    // previous `use_dpop_nonce` challenge for this key.
    const attempt = (dpopNonce: string | undefined): Promise<OAuth2TokenResponse> => {
      // WR-189: the assertion is built fresh per token fetch — a new
      // `jti` and a fresh `iat`/`exp` every time, so a leaked or replayed
      // assertion cannot outlive its 5-minute window. Caching,
      // single-flight, and the 401 refresh path are unchanged: they
      // operate on the token, not the assertion.
      const clientAssertionJwt =
        cfg.assertion !== undefined
          ? buildPrivateKeyJwtAssertion({
              clientId: cfg.clientId,
              tokenEndpoint: cfg.tokenEndpoint.href,
              assertion: cfg.assertion,
              nowMs: this.nowMs(),
            })
          : undefined;
      const dpopProofJwt =
        cfg.dpop !== undefined
          ? buildDpopProofJwt({
              dpop: cfg.dpop,
              htm: "POST",
              htu: cfg.tokenEndpoint.href,
              ...(dpopNonce !== undefined ? { nonce: dpopNonce } : {}),
              nowMs: this.nowMs(),
            })
          : undefined;
      return this.fetchToken({
        tokenEndpoint: cfg.tokenEndpoint,
        clientId: cfg.clientId,
        ...(cfg.clientSecret !== undefined ? { clientSecret: cfg.clientSecret } : {}),
        ...(clientAssertionJwt !== undefined ? { clientAssertionJwt } : {}),
        ...(dpopProofJwt !== undefined ? { dpopProofJwt } : {}),
        ...(cfg.scope !== undefined ? { scope: cfg.scope } : {}),
        timeoutMs: this.tokenRequestTimeoutMs,
      });
    };
    const fetched = attempt(this.dpopNonces.get(key))
      .catch((err) => {
        // WR-205 / RFC 9449 §4.3: on a `use_dpop_nonce` rejection,
        // retry exactly once with a fresh proof carrying the server
        // nonce (a fresh `jti` too — proofs are never reused). The
        // nonce is remembered per key, so the next fetch leads with it
        // instead of paying for another challenge round-trip.
        if (
          cfg.dpop !== undefined &&
          err instanceof OAuth2TokenError &&
          err.statusCode === 400 &&
          typeof err.dpopNonce === "string" &&
          err.dpopNonce !== ""
        ) {
          this.dpopNonces.set(key, err.dpopNonce);
          return attempt(err.dpopNonce);
        }
        throw err;
      })
      .then(
        (resp) => {
          const ttlMs =
            resp.expires_in !== undefined
              ? resp.expires_in * 1000
              : OAUTH2_DEFAULT_EXPIRES_IN_MS;
          // Clock-skew reserve: a token that expires in less than the
          // skew margin is treated as already expired — the next call
          // refetches instead of sending a token the downstream may
          // already consider stale.
          const expiresAtMs = this.nowMs() + Math.max(0, ttlMs - OAUTH2_CLOCK_SKEW_MS);
          this.entries.set(key, { token: resp.access_token, expiresAtMs });
          this.inflight.delete(key);
          return resp.access_token;
        },
        (err) => {
          this.inflight.delete(key);
          throw err;
        }
      );
    this.inflight.set(key, fetched);
    return fetched;
  }
}
