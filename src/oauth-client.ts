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
 */

import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";

/** Safety margin: a token counts as expired this early (clock-skew reserve). */
export const OAUTH2_CLOCK_SKEW_MS = 30_000;

/** Fallback token TTL when the endpoint omits `expires_in`. */
export const OAUTH2_DEFAULT_EXPIRES_IN_MS = 300_000;

/** Default timeout for one token request. */
export const OAUTH2_TOKEN_REQUEST_TIMEOUT_MS = 10_000;

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
   * OAuth2 `client_secret`. Non-empty. Memory-only: never logged, never
   * audited, never rendered by any stats/introspection method.
   */
  client_secret: string;
  /** Optional space-delimited `scope`. Non-empty when set. */
  scope?: string;
}

/** A validated OAuth2 config: the endpoint parsed once at startup. */
export interface ResolvedOAuth2ClientConfig {
  tokenEndpoint: URL;
  clientId: string;
  clientSecret: string;
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
  if (typeof cfg.client_secret !== "string" || cfg.client_secret === "") {
    throw new RangeError(`${where}: \`client_secret\` must be a non-empty string`);
  }
  if (cfg.scope !== undefined && (typeof cfg.scope !== "string" || cfg.scope.trim() === "")) {
    throw new RangeError(`${where}: \`scope\` must be a non-empty string when set`);
  }
  return {
    tokenEndpoint,
    clientId: cfg.client_id,
    clientSecret: cfg.client_secret,
    ...(cfg.scope !== undefined ? { scope: cfg.scope } : {}),
  };
}

/** The token endpoint's JSON response (RFC 6749 §5.1). */
export interface OAuth2TokenResponse {
  access_token: string;
  expires_in?: number;
}

/**
 * Thrown for token endpoint failures: unreachable endpoint, non-2xx
 * status, malformed JSON, missing `access_token`. The message never
 * carries the `client_secret`.
 */
export class OAuth2TokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OAuth2TokenError";
  }
}

/** Parameters for an {@link OAuth2TokenFetcher}. */
export interface OAuth2TokenFetchParams {
  tokenEndpoint: URL;
  clientId: string;
  /** Memory-only: a fetcher must never log or persist this. */
  clientSecret: string;
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
  endpoint: URL
): OAuth2TokenResponse {
  const where = `oauth2 token response from ${endpoint.host}${endpoint.pathname}`;
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new OAuth2TokenError(`${where}: not a JSON object`);
  }
  const p = parsed as Record<string, unknown>;
  if (typeof p.access_token !== "string" || p.access_token === "") {
    throw new OAuth2TokenError(`${where}: missing \`access_token\``);
  }
  // Only bearer tokens are supported: the sender stamps
  // `Authorization: Bearer <token>`, and stamping anything else under
  // a Bearer scheme would be a lie the downstream cannot verify.
  if (
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
 * `grant_type=client_credentials`, `node:http(s)` only. The
 * `client_secret` travels in the form body — it is never written to any
 * log, and error messages name the endpoint and status only.
 */
export function defaultOAuth2TokenFetcher(
  params: OAuth2TokenFetchParams
): Promise<OAuth2TokenResponse> {
  return new Promise((resolve, reject) => {
    const body = new URLSearchParams({
      grant_type: "client_credentials",
      client_id: params.clientId,
      client_secret: params.clientSecret,
      ...(params.scope !== undefined ? { scope: params.scope } : {}),
    }).toString();
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
              fail(`${endpoint.host}${endpoint.pathname} -> HTTP ${status}`);
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
              resolve(assertValidTokenResponse(parsed, endpoint));
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
    return `${cfg.tokenEndpoint.href}\n${cfg.scope ?? ""}\n${cfg.clientId}`;
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
    const fetched = this.fetchToken({
      tokenEndpoint: cfg.tokenEndpoint,
      clientId: cfg.clientId,
      clientSecret: cfg.clientSecret,
      ...(cfg.scope !== undefined ? { scope: cfg.scope } : {}),
      timeoutMs: this.tokenRequestTimeoutMs,
    }).then(
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
