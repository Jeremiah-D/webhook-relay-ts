/**
 * Outbound 3xx redirect following (WR-484).
 *
 * The default sender only recognizes 2xx as success: a downstream that
 * answers 301/302/307/308 fails the attempt with `HttpDeliveryError`,
 * which the retry queue classifies retryable — so a moved endpoint burns
 * the whole retry budget and then dead-letters, even though the
 * downstream told us exactly where it moved to. A per-endpoint opt-in
 * (`followRedirects`, keyed by exact delivery `targetUrl`) lets an
 * endpoint follow those redirects *inside the same attempt*: the hop
 * consumes no retry budget, recomputes no backoff, and records no
 * circuit verdict — the queue still sees a single attempt.
 *
 * Rules (all fail closed):
 *
 * - Only 301/302/307/308 with an `http:`/`https:` `Location` are
 *   followed. 303 is never followed (its method semantics change), and
 *   a missing, unparseable, or non-HTTP(S) `Location` is not followed —
 *   the original 3xx fails exactly as before.
 * - Method and body are preserved on every hop (301/302 keep POST +
 *   body here, by documented convention — unlike a browser, which
 *   converts them to GET).
 * - Every hop re-runs the per-hop gates against the *hop* URL: the
 *   SSRF guard (`bindingFor`, allowlist + proxy skip included), the
 *   DNS pin (the shared pin-checked lookup judges every hop's
 *   resolution), and the egress residency gate. A gate refusal fails
 *   the attempt under that gate's own classification (SSRF / egress
 *   refusals are `non_retryable` — dead-letter, no retry budget).
 *   Known boundary, inherited from the gates themselves (not
 *   introduced here): they judge hostnames through the lookup path,
 *   and Node dials literal IPs without resolving — so a hop target
 *   that is a literal private IP never reaches the guard or the pin,
 *   exactly like a direct delivery to a literal IP. Only hostname
 *   hop targets are gated.
 * - An `https:` → `http:` downgrade is refused by default and only
 *   allowed with explicit `allowDowngrade: true`.
 * - The relay signature covers body + timestamp and is host-independent,
 *   so it stays valid across hops with no re-signing; the `Host` header
 *   is set by Node from the hop URL. SigV4, when configured, is
 *   re-signed per hop URL. The OAuth2 bearer token is *not* forwarded
 *   across origins (a cross-origin hop drops it and its DPoP proof);
 *   a same-origin hop rebuilds the DPoP proof against the hop URL.
 * - TLS identity config (pins, SNI override, CA bundle, OCSP, client
 *   certificates) is the original endpoint's and travels with the
 *   delivery; a cross-host hop whose peer does not match it fails
 *   closed. Per-endpoint static credentials and forwarded headers are
 *   likewise the original endpoint's and are not re-gated per hop.
 * - Hops are capped by `maxRedirects` (default 5, hard ceiling 10).
 *   The response that exceeds the cap fails as the original 3xx
 *   (retryable → normal retry / dead-letter path).
 * - Each hop is audited as `redirect_followed` (`from`/`to` carry
 *   origin + path only — never the query, so a `Location` carrying a
 *   token cannot land in the audit trail).
 * - Applies to the HTTP/1.1 and HTTP/2 delivery paths. WebSocket
 *   deliveries have no HTTP redirect semantics and are untouched.
 */

/** Per-endpoint redirect-following opt-in (WR-484). */
export interface FollowRedirectsOptions {
  /**
   * Maximum redirects followed inside one attempt (default 5, ceiling
   * 10). Must be an integer in 1..10; anything else throws `RangeError`
   * at startup. The entry's presence is the opt-in — `{}` follows up
   * to the default 5 hops.
   */
  maxRedirects?: number;
  /**
   * Allow `https:` → `http:` downgrades (default `false` — a downgrade
   * hop is refused and the original 3xx fails as before). Upgrades
   * (`http:` → `https:`) and same-scheme hops are always allowed.
   */
  allowDowngrade?: boolean;
}

/** A validated `FollowRedirectsOptions` — every knob resolved. */
export interface ResolvedFollowRedirectsOptions {
  maxRedirects: number;
  allowDowngrade: boolean;
}

/** One followed hop, delivered to `onRedirectFollowed`. */
export interface RedirectFollowedInfo {
  /** Delivery id. */
  id: string;
  /** Trace id, when the delivery carries one. */
  traceId?: string;
  /** The original endpoint (`item.targetUrl`) — the config key. */
  endpoint: string;
  /** Hop source: origin + path only, never the query. */
  from: string;
  /** Hop target: origin + path only, never the query. */
  to: string;
  /** 1-based hop count within this attempt. */
  hops: number;
  /** The 3xx status that triggered this hop. */
  statusCode: number;
}

/** Default `maxRedirects` when the entry names none. */
export const DEFAULT_MAX_REDIRECTS = 5;
/** Hard ceiling for `maxRedirects` — a larger value is a `RangeError`. */
export const MAX_MAX_REDIRECTS = 10;

/** The redirect statuses the relay follows (303 is deliberately absent). */
export const REDIRECT_STATUS_CODES: readonly number[] = [301, 302, 307, 308];

/** True when `statusCode` is a followable redirect status. */
export function isRedirectStatus(statusCode: number): boolean {
  return REDIRECT_STATUS_CODES.includes(statusCode);
}

/**
 * Validate one endpoint's `followRedirects` entry and resolve its
 * defaults. Throws `RangeError` on a non-object entry, a non-integer
 * or out-of-range `maxRedirects`, or a non-boolean `allowDowngrade`.
 */
export function resolveFollowRedirectsOptions(
  opts: FollowRedirectsOptions
): ResolvedFollowRedirectsOptions {
  if (opts === null || typeof opts !== "object" || Array.isArray(opts)) {
    throw new RangeError("followRedirects entry must be an object");
  }
  const maxRedirects = opts.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
  if (
    typeof maxRedirects !== "number" ||
    !Number.isInteger(maxRedirects) ||
    maxRedirects < 1 ||
    maxRedirects > MAX_MAX_REDIRECTS
  ) {
    throw new RangeError(
      `followRedirects.maxRedirects must be an integer in 1..${MAX_MAX_REDIRECTS}`
    );
  }
  const allowDowngrade = opts.allowDowngrade ?? false;
  if (typeof allowDowngrade !== "boolean") {
    throw new RangeError("followRedirects.allowDowngrade must be a boolean");
  }
  return { maxRedirects, allowDowngrade };
}

/**
 * Validate a whole `followRedirects` record (endpoint → entry).
 * Throws `RangeError` naming the offending endpoint on the first bad
 * entry; the sender's live record is left untouched (validate before
 * assign, here and in `createDefaultSender`).
 */
export function assertValidFollowRedirectsConfig(
  record: Record<string, FollowRedirectsOptions>
): void {
  if (record === null || typeof record !== "object" || Array.isArray(record)) {
    throw new RangeError("followRedirects must be an object keyed by targetUrl");
  }
  for (const [endpoint, opts] of Object.entries(record)) {
    try {
      resolveFollowRedirectsOptions(opts);
    } catch (err) {
      throw new RangeError(
        `followRedirects["${endpoint}"]: ${(err as Error).message}`
      );
    }
  }
}

/** First value of a possibly multi-valued header (or `undefined`). */
export function firstHeaderValue(
  value: string | string[] | undefined
): string | undefined {
  if (value === undefined) return undefined;
  return Array.isArray(value) ? value[0] : value;
}

/**
 * Resolve a redirect target from a `Location` header value against the
 * URL that produced it. Returns `undefined` — do not follow — when
 * there is no `Location`, it is empty or unparseable, or it names a
 * non-HTTP(S) scheme (including `ws:`/`wss:`: the WebSocket path has
 * no redirect semantics). Relative locations resolve against the hop
 * source, per RFC 9110 §10.2.2.
 */
export function resolveRedirectUrl(
  from: URL,
  location: string | string[] | undefined
): URL | undefined {
  const raw = firstHeaderValue(location);
  if (raw === undefined || raw.trim() === "") return undefined;
  let next: URL;
  try {
    next = new URL(raw, from);
  } catch {
    return undefined;
  }
  if (next.protocol !== "http:" && next.protocol !== "https:") return undefined;
  return next;
}

/** True when the hop downgrades `https:` to `http:`. */
export function isDowngrade(from: URL, to: URL): boolean {
  return from.protocol === "https:" && to.protocol === "http:";
}

/**
 * Audit-safe label for a hop endpoint: origin + path only. The query
 * is dropped on purpose — a `Location` may carry a token.
 */
export function redirectTargetLabel(url: URL): string {
  return `${url.origin}${url.pathname}`;
}
