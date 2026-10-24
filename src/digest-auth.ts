import { createHash, randomBytes } from "node:crypto";

import {
  defaultSecretResolver,
  type SecretResolver,
} from "./sigv4.ts";

/**
 * Outbound HTTP Digest authentication (WR-212, RFC 7616).
 *
 * Some legacy enterprise downstreams gate webhooks on Digest auth
 * rather than on a bearer token or a static header: the first request
 * goes out unauthenticated, the downstream answers `401` with a
 * `WWW-Authenticate: Digest ...` challenge, and the relay retries
 * with an `Authorization: Digest ...` header computed from the
 * challenge parameters. This module is that challenge/response
 * client — it is *not* a static credential and *not* a bearer-token
 * flow, which is why it is orthogonal to both of its neighbours:
 *
 * - WR-192 (`outbound-credentials.ts`): a static header value stamped
 *   on every attempt, never challenge-driven;
 * - WR-129 (`oauth-client.ts`): a dynamic bearer token minted from a
 *   token endpoint, never computed from a `401` challenge.
 *
 * Supported subset, deliberately narrow and fail-closed:
 *
 * - algorithms `MD5` and `SHA-256` only (case-insensitive; absent
 *   means `MD5`, the RFC 7616 default). `-sess` variants, `SHA-512`
 *   and anything else throw `DigestAuthError` — a downstream that
 *   demands an algorithm this client does not implement is a config
 *   problem, not a retryable delivery, and silently falling back to
 *   a weaker algorithm would be worse than refusing;
 * - `qop=auth` only. A challenge offering `auth` (alone or in a list
 *   such as `auth, auth-int`) uses `auth`; a challenge offering only
 *   `auth-int` throws — `auth-int` would bind the entity body, which
 *   this client does not hash, and guessing it would produce a
 *   response the downstream must reject. A challenge with no `qop`
 *   uses the RFC 2617 legacy form (no `nc` / `cnonce` / `qop` in
 *   either the hash or the header);
 * - `userhash=true` throws: the hashed-username form is out of scope
 *   for this client, and sending a plain username where the server
 *   expects a hash (or vice versa) only burns a delivery attempt.
 *
 * Secret handling reuses the WR-116 / WR-192 convention:
 *
 * - the config carries `passwordSecretRef` — a *reference* (with the
 *   default resolver, an environment variable name), never the raw
 *   password — so config snapshots, audit events, and stats can never
 *   leak credential material;
 * - `passwordResolver` resolves the reference per authorization
 *   attempt (rotation without restart) and is injectable for
 *   deterministic tests; the default is `defaultSecretResolver`;
 * - the constructor still resolves once up front (the WR-192
 *   fail-fast rule): a relay that boots with a credential it can
 *   never use is worse than one that refuses to boot. A reference
 *   that stops resolving mid-run throws `DigestAuthError` naming
 *   only the reference, never the value;
 * - this module never logs. No error message, header value, or return
 *   value in this file ever contains the password: the computed
 *   `response` hash is safe to log, the password is not, and the two
 *   are never concatenated into a single string anywhere here.
 *
 * Nonce-count discipline: `DigestAuthSession` keeps one counter per
 * `nonce` value, starting at 1 and formatted as eight lowercase hex
 * digits (`00000001`, ...). A `stale=true` challenge carries a *new*
 * nonce, so it gets a fresh counter — reusing the old nonce's count
 * against a new nonce is exactly the replay shape the counter
 * exists to prevent. The session is per endpoint: two endpoints
 * sharing a username must not share a counter, because a nonce is
 * only meaningful to the server that issued it.
 *
 * The `fetchWithDigestAuth` helper is transport-agnostic: the caller
 * injects a `fetch`-shaped function, so the helper stays testable
 * without a network and stays independent of the relay's own sender
 * (it does not import `src/server.ts` or `src/failure.ts` — the
 * dependency direction stays one-way, like the SQS sink). Its
 * attempt budget is fixed: the plain attempt, one authenticated
 * attempt, and — only when the second `401` carries
 * `stale=true` — one re-authenticated attempt against the fresh
 * nonce. Any other second `401` is returned as-is: the delivery
 * layer, not this helper, decides whether a `401` is retryable, and
 * looping forever against a server that keeps saying no would burn
 * the retry budget for nothing.
 *
 * Zero new dependencies: `node:crypto` + the WR-116 resolver only.
 */

/** Digest algorithms this client implements (RFC 7616). */
export type DigestAlgorithm = "MD5" | "SHA-256";

/** One parsed `WWW-Authenticate: Digest ...` challenge. */
export interface DigestChallenge {
  /** Authentication realm; echoed back verbatim in the response. */
  realm: string;
  /** Server nonce; echoed back verbatim in the response. */
  nonce: string;
  /** Opaque value, echoed back verbatim when present. */
  opaque?: string;
  /** Negotiated algorithm; absent in the challenge means `MD5`. */
  algorithm: DigestAlgorithm;
  /** Negotiated quality of protection, or `undefined` (legacy form). */
  qop?: "auth";
  /** True when the server says the nonce is stale (re-authenticate). */
  stale: boolean;
}

/**
 * Structured Digest failure: a malformed challenge, an unsupported
 * algorithm / qop, or a password reference that stopped resolving.
 * `classifyFailure` maps it to `non_retryable` (the WR-116 rule — a
 * config problem that retrying cannot fix). The message never
 * contains credential material: it names realms, nonces, and secret
 * references only.
 */
export class DigestAuthError extends Error {
  constructor(message: string) {
    super(`digest-auth: ${message}`);
    this.name = "DigestAuthError";
  }
}

/** Configuration for one Digest-authenticated endpoint. */
export interface DigestAuthConfig {
  /** HTTP username (not secret — safe to log/audit). */
  username: string;
  /**
   * Secret-store reference naming where the password lives
   * (WR-116 convention: an environment variable name with the
   * default resolver). Never the raw password.
   */
  passwordSecretRef: string;
  /**
   * Resolves `passwordSecretRef` to the password per authorization
   * attempt (so a rotation takes effect without a restart).
   * Defaults to `defaultSecretResolver`.
   */
  passwordResolver?: SecretResolver;
  /**
   * `cnonce` source, defaulting to 16 hex chars from
   * `crypto.randomBytes`. Injectable for deterministic tests; must
   * return a non-empty string.
   */
  cnonceGenerator?: () => string;
}

/**
 * Validate a Digest config's shape. Throws `RangeError` on any bad
 * shape — empty username, empty secret reference, or a non-function
 * resolver / generator. Does not resolve the secret; the session
 * constructor adds the fail-fast resolution check.
 */
export function assertValidDigestAuthConfig(
  cfg: unknown,
  label: string
): asserts cfg is DigestAuthConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object" || Array.isArray(cfg)) {
    throw new RangeError(at("digest auth config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  if (typeof c.username !== "string" || c.username === "") {
    throw new RangeError(at("`username` must be a non-empty string"));
  }
  if (typeof c.passwordSecretRef !== "string" || c.passwordSecretRef === "") {
    throw new RangeError(
      at("`passwordSecretRef` must be a non-empty string (a reference, never the raw password)")
    );
  }
  if (c.passwordResolver !== undefined && typeof c.passwordResolver !== "function") {
    throw new RangeError(at("`passwordResolver` must be a function when set"));
  }
  if (c.cnonceGenerator !== undefined && typeof c.cnonceGenerator !== "function") {
    throw new RangeError(at("`cnonceGenerator` must be a function when set"));
  }
}

/** Format a nonce count as eight lowercase hex digits (`00000001`). */
export function formatNonceCount(nc: number): string {
  if (!Number.isInteger(nc) || nc < 1) {
    throw new RangeError(`digest-auth: nonce count must be a positive integer, got ${nc}`);
  }
  return nc.toString(16).padStart(8, "0");
}

/**
 * Split a challenge parameter list on commas that are *not* inside
 * a quoted string, so a realm containing a comma (e.g.
 * `realm="a, b"`) survives parsing instead of splitting the realm.
 */
function splitChallengeParams(input: string): string[] {
  const parts: string[] = [];
  let current = "";
  let inQuotes = false;
  let escaped = false;
  for (const ch of input) {
    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }
    if (ch === "\\" && inQuotes) {
      current += ch;
      escaped = true;
      continue;
    }
    if (ch === '"') {
      inQuotes = !inQuotes;
      current += ch;
      continue;
    }
    if (ch === "," && !inQuotes) {
      parts.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  parts.push(current);
  return parts;
}

/** Unquote a challenge value, handling `\"` and `\\` escapes. */
function unquote(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed
      .slice(1, -1)
      .replace(/\\(.)/g, "$1");
  }
  return trimmed;
}

/**
 * Parse a `WWW-Authenticate` header value into a `DigestChallenge`.
 * Accepts the bare parameter list as well as a leading `Digest`
 * scheme token (case-insensitive); when several challenges share one
 * header, the first `Digest` challenge wins and the rest are ignored
 * (a downstream that also offers Basic does not change this
 * client's answer). Throws `DigestAuthError` on a missing realm or
 * nonce, an unsupported algorithm, an unsupported `qop`, or
 * `userhash=true` — all fail-closed, never a guessed response.
 */
export function parseDigestChallenge(header: string): DigestChallenge {
  if (typeof header !== "string" || header.trim() === "") {
    throw new DigestAuthError("empty WWW-Authenticate header");
  }
  let params = header.trim();
  // Strip a leading scheme token ("Digest" or, defensively, "digest").
  const schemeMatch = /^digest\s+/i.exec(params);
  if (schemeMatch) {
    params = params.slice(schemeMatch[0].length);
  } else {
    // A header carrying several challenges ("Basic ..., Digest ..."):
    // find the Digest challenge and parse from there.
    const digestAt = params.search(/digest\s+/i);
    if (digestAt === -1) {
      throw new DigestAuthError("no Digest challenge in WWW-Authenticate header");
    }
    params = params.slice(digestAt).replace(/^digest\s+/i, "");
  }
  const raw: Record<string, string> = {};
  for (const part of splitChallengeParams(params)) {
    const eq = part.indexOf("=");
    if (eq === -1) {
      continue;
    }
    const key = part.slice(0, eq).trim().toLowerCase();
    if (key === "") {
      continue;
    }
    raw[key] = unquote(part.slice(eq + 1));
  }
  if (!raw.realm) {
    throw new DigestAuthError("Digest challenge has no realm");
  }
  if (!raw.nonce) {
    throw new DigestAuthError("Digest challenge has no nonce");
  }
  if (raw.userhash === "true") {
    throw new DigestAuthError("Digest challenge requires userhash, which is out of scope");
  }
  let algorithm: DigestAlgorithm = "MD5";
  if (raw.algorithm !== undefined && raw.algorithm !== "") {
    const normalized = raw.algorithm.toUpperCase();
    if (normalized === "MD5" || normalized === "SHA-256") {
      algorithm = normalized;
    } else {
      throw new DigestAuthError(`unsupported Digest algorithm "${raw.algorithm}"`);
    }
  }
  let qop: "auth" | undefined;
  if (raw.qop !== undefined && raw.qop !== "") {
    const offered = raw.qop.split(",").map((q) => q.trim().toLowerCase());
    if (offered.includes("auth")) {
      qop = "auth";
    } else {
      throw new DigestAuthError(`unsupported Digest qop "${raw.qop}" (only auth is supported)`);
    }
  }
  return {
    realm: raw.realm,
    nonce: raw.nonce,
    ...(raw.opaque !== undefined ? { opaque: raw.opaque } : {}),
    algorithm,
    ...(qop !== undefined ? { qop } : {}),
    stale: raw.stale === "true",
  };
}

function hashHex(algorithm: DigestAlgorithm, input: string): string {
  return createHash(algorithm === "MD5" ? "md5" : "sha256")
    .update(input, "utf8")
    .digest("hex");
}

export interface ComputeDigestResponseInput {
  username: string;
  /** Resolved password value (never a reference — resolved by the caller). */
  password: string;
  /** HTTP method, e.g. `POST`. Uppercased before hashing. */
  method: string;
  /** Request-target (path + query), e.g. `/hook?tenant=1`. */
  uri: string;
  challenge: DigestChallenge;
  /** Nonce count; defaults to 1. Ignored for the legacy (no-qop) form. */
  nc?: number;
  /**
   * Client nonce; generated (16 hex chars) when absent and `qop`
   * is set. Ignored for the legacy (no-qop) form.
   */
  cnonce?: string;
}

export interface ComputedDigestResponse {
  /** Hex response hash — safe to log; it is not the password. */
  response: string;
  /** Effective nonce count (1 for the legacy form, which has none). */
  nc: number;
  /** Effective client nonce (empty string for the legacy form). */
  cnonce: string;
}

/**
 * Compute the RFC 7616 `response` hash for one challenge:
 * `H(H(username:realm:password):nonce:nc:cnonce:qop:H(method:uri))`
 * for `qop=auth`, or `H(H(username:realm:password):nonce:H(method:uri))`
 * for the legacy form. Pure function — no secret resolution, no
 * state — so the RFC test vectors pin it exactly.
 */
export function computeDigestResponse(input: ComputeDigestResponseInput): ComputedDigestResponse {
  const { username, password, challenge } = input;
  if (username === "" || password === "") {
    throw new DigestAuthError("username and password must be non-empty");
  }
  const method = input.method.toUpperCase();
  const ha1 = hashHex(challenge.algorithm, `${username}:${challenge.realm}:${password}`);
  const ha2 = hashHex(challenge.algorithm, `${method}:${input.uri}`);
  if (challenge.qop === undefined) {
    return {
      response: hashHex(challenge.algorithm, `${ha1}:${challenge.nonce}:${ha2}`),
      nc: 1,
      cnonce: "",
    };
  }
  const nc = input.nc ?? 1;
  const ncHex = formatNonceCount(nc);
  const cnonce = input.cnonce ?? randomBytes(8).toString("hex");
  if (cnonce === "") {
    throw new DigestAuthError("cnonce must be non-empty for qop=auth");
  }
  return {
    response: hashHex(
      challenge.algorithm,
      `${ha1}:${challenge.nonce}:${ncHex}:${cnonce}:${challenge.qop}:${ha2}`
    ),
    nc,
    cnonce,
  };
}

export interface BuildDigestAuthorizationInput extends ComputeDigestResponseInput {
  // Same shape: the header is built from the computed response.
}

/** Quote a header value, escaping backslash and double-quote. */
function quote(value: string): string {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/**
 * Build the full `Authorization: Digest ...` header value for one
 * challenge: `username`, `realm`, `nonce`, `uri`, `response`,
 * `algorithm`, plus `opaque` (when challenged), plus `qop`, `nc`
 * (eight hex digits), and `cnonce` for the `qop=auth` form. The
 * legacy form omits the last three, matching the hash inputs
 * exactly — a header field the hash did not cover (or vice versa)
 * is a response the downstream must reject.
 */
export function buildDigestAuthorization(input: BuildDigestAuthorizationInput): string {
  const computed = computeDigestResponse(input);
  const { challenge } = input;
  const parts = [
    `username=${quote(input.username)}`,
    `realm=${quote(challenge.realm)}`,
    `nonce=${quote(challenge.nonce)}`,
    `uri=${quote(input.uri)}`,
    `response=${quote(computed.response)}`,
    `algorithm=${challenge.algorithm}`,
  ];
  if (challenge.opaque !== undefined) {
    parts.push(`opaque=${quote(challenge.opaque)}`);
  }
  if (challenge.qop !== undefined) {
    parts.push(`qop=${challenge.qop}`);
    parts.push(`nc=${formatNonceCount(computed.nc)}`);
    parts.push(`cnonce=${quote(computed.cnonce)}`);
  }
  return `Digest ${parts.join(", ")}`;
}

/** Extract the request-target (path + query) from an absolute URL. */
export function digestUriFor(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.pathname}${parsed.search}`;
  } catch {
    throw new DigestAuthError(`cannot derive a Digest uri from "${url}"`);
  }
}

/** Minimal response shape the fetch helper reads. */
export interface DigestFetchResponse {
  status: number;
  headers: { get(name: string): string | null };
}

/** Minimal `fetch`-shaped function the helper drives. */
export type DigestFetch = (
  url: string,
  init: { method?: string; headers?: Record<string, string>; body?: unknown }
) => Promise<DigestFetchResponse>;

/**
 * A stateful Digest session for one endpoint: per-nonce counters,
 * per-attempt secret resolution, and the challenge/response loop.
 * One session per endpoint — counters are keyed by nonce, and a
 * nonce is only meaningful to the server that issued it.
 */
export class DigestAuthSession {
  private readonly username: string;
  private readonly passwordSecretRef: string;
  private readonly passwordResolver: SecretResolver;
  private readonly cnonceGenerator: () => string;
  private readonly nonceCounts = new Map<string, number>();

  constructor(config: DigestAuthConfig) {
    assertValidDigestAuthConfig(config, "digest-auth");
    this.username = config.username;
    this.passwordSecretRef = config.passwordSecretRef;
    this.passwordResolver = config.passwordResolver ?? defaultSecretResolver;
    this.cnonceGenerator = config.cnonceGenerator ?? (() => randomBytes(8).toString("hex"));
    // Fail-fast (WR-192 rule): refuse to boot with a credential
    // this session can never use. The check resolves once here;
    // every authorization re-resolves, so a rotation still lands.
    const initial = this.passwordResolver(this.passwordSecretRef);
    if (typeof initial !== "string" || initial === "") {
      throw new RangeError(
        `digest-auth: passwordSecretRef "${this.passwordSecretRef}" did not resolve (username "${this.username}") — set the secret before boot`
      );
    }
  }

  /** Next nonce count for `nonce` (first use is 1). */
  private nextNonceCount(nonce: string): number {
    const next = (this.nonceCounts.get(nonce) ?? 0) + 1;
    this.nonceCounts.set(nonce, next);
    return next;
  }

  /** Resolve the password for this attempt (rotation-aware). */
  private resolvePassword(): string {
    const password = this.passwordResolver(this.passwordSecretRef);
    if (typeof password !== "string" || password === "") {
      throw new DigestAuthError(
        `passwordSecretRef "${this.passwordSecretRef}" did not resolve`
      );
    }
    return password;
  }

  /**
   * Build an `Authorization` value for one challenge header:
   * parse, resolve the password for this attempt, advance this
   * nonce's counter, and compute the response. The counter advances
   * even if the downstream later rejects the response — a reused
   * `nc` is a replay, so a failed attempt must never rewind it.
   */
  authorizationFor(challengeHeader: string, method: string, uri: string): string {
    const challenge = parseDigestChallenge(challengeHeader);
    const password = this.resolvePassword();
    const cnonce = this.cnonceGenerator();
    if (typeof cnonce !== "string" || cnonce === "") {
      throw new DigestAuthError("cnonce generator returned an empty value");
    }
    return buildDigestAuthorization({
      username: this.username,
      password,
      method,
      uri,
      challenge,
      nc: this.nextNonceCount(challenge.nonce),
      cnonce,
    });
  }

  /**
   * Drive one delivery through the Digest handshake with an
   * injected fetch: plain attempt, authenticated attempt, and —
   * only on a second `401` with `stale=true` — one re-authenticated
   * attempt against the fresh nonce. Returns the last response in
   * every case (including a `401` the server will not negotiate
   * past): this helper authenticates, it does not classify — the
   * caller owns retry / dead-letter decisions for the final status.
   * A malformed Digest challenge on a retry step likewise returns
   * the `401` instead of throwing: the server answered, and its
   * answer is the delivery outcome.
   */
  async fetchWithDigestAuth(
    fetchFn: DigestFetch,
    url: string,
    init: { method?: string; headers?: Record<string, string>; body?: unknown } = {}
  ): Promise<DigestFetchResponse> {
    const method = init.method ?? "GET";
    const uri = digestUriFor(url);
    let authorization: string | undefined;
    let last: DigestFetchResponse | undefined;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const headers: Record<string, string> = { ...(init.headers ?? {}) };
      if (authorization !== undefined) {
        headers.Authorization = authorization;
      }
      const response = await fetchFn(url, { ...init, headers });
      last = response;
      if (response.status !== 401) {
        return response;
      }
      const challengeHeader =
        response.headers.get("www-authenticate") ??
        response.headers.get("WWW-Authenticate");
      if (challengeHeader === null || !/digest/i.test(challengeHeader)) {
        return response;
      }
      let challenge: DigestChallenge;
      try {
        challenge = parseDigestChallenge(challengeHeader);
      } catch {
        return response;
      }
      // Attempt 0 -> first auth; attempt 1 -> only a stale nonce
      // earns a second auth (a fresh nonce, a fresh counter).
      // Attempt 2 is the last word: return whatever it says.
      if (attempt === 0) {
        authorization = this.authorizationFor(challengeHeader, method, uri);
        continue;
      }
      if (attempt === 1 && challenge.stale) {
        authorization = this.authorizationFor(challengeHeader, method, uri);
        continue;
      }
      return response;
    }
    // Unreachable in practice (the loop always returns), but the
    // type system wants a value: the last response is the outcome.
    return last as DigestFetchResponse;
  }
}
