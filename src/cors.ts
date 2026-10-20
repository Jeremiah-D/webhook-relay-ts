/**
 * WR-159: CORS policy for the operator plane.
 *
 * Browser dashboards need to call the operator endpoints (`/metrics`,
 * `/audit`, `/dead-letter`, `/events` SSE, …) cross-origin. This module
 * implements an opt-in, allowlist-based CORS layer that only ever touches
 * operator paths — the webhook intake is untouched.
 *
 * Semantics:
 * - `allowedOrigins` is an exact-match allowlist. The default (empty or
 *   unset) disables CORS entirely: zero behavior change.
 * - A preflight (`OPTIONS`) to an operator path is answered here, before
 *   operator auth (browsers never send credentials or client certificates
 *   on preflights, so gating them on auth would break every dashboard).
 *   Only allowlisted origins are echoed; a non-allowlisted origin gets a
 *   bare 204 and the browser blocks the real request naturally.
 * - Actual (non-OPTIONS) operator responses to allowlisted origins carry
 *   `Access-Control-Allow-Origin` (+ `Vary: Origin`, and
 *   `Access-Control-Allow-Credentials` when configured).
 */

import type { IncomingMessage, ServerResponse } from "node:http";

export interface CorsPolicy {
  /** Exact-match origin allowlist. Empty/unset = CORS disabled. */
  allowedOrigins?: string[];
  /** Echoed as Access-Control-Allow-Methods on preflights. */
  allowedMethods?: string[];
  /** Echoed as Access-Control-Allow-Headers on preflights. */
  allowedHeaders?: string[];
  /** Adds Access-Control-Allow-Credentials: true. Default false. */
  allowCredentials?: boolean;
  /** Echoed as Access-Control-Max-Age (seconds) on preflights. Default 600. */
  maxAgeSeconds?: number;
}

export interface ResolvedCorsPolicy {
  allowedOrigins: string[];
  allowedMethods: string[];
  allowedHeaders: string[];
  allowCredentials: boolean;
  maxAgeSeconds: number;
}

const DEFAULT_ALLOWED_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];
const DEFAULT_ALLOWED_HEADERS = ["content-type", "authorization"];
const DEFAULT_MAX_AGE_SECONDS = 600;

function assertStringList(value: unknown, field: string): string[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value)) {
    throw new RangeError(`\`cors.${field}\` must be an array of strings`);
  }
  for (const entry of value) {
    if (typeof entry !== "string" || entry.length === 0) {
      throw new RangeError(`\`cors.${field}\` must contain only non-empty strings`);
    }
  }
  // De-duplicate, preserving first-seen order.
  return [...new Set(value as string[])];
}

/**
 * Validate once at startup. Returns `undefined` when CORS is disabled
 * (policy unset or empty allowlist) so call sites keep the exact
 * pre-WR-159 behavior. Throws `RangeError` on invalid config — never
 * mid-request.
 */
export function assertValidCorsPolicy(policy: CorsPolicy | undefined): ResolvedCorsPolicy | undefined {
  if (policy === undefined) return undefined;
  if (typeof policy !== "object" || policy === null) {
    throw new RangeError("`cors` must be an object");
  }
  const origins = assertStringList(policy.allowedOrigins, "allowedOrigins") ?? [];
  for (const origin of origins) {
    if (origin === "*") {
      throw new RangeError(
        '`cors.allowedOrigins` does not accept "*": origins are matched exactly; ' +
          "list each dashboard origin explicitly"
      );
    }
  }
  if (origins.length === 0) return undefined; // disabled: zero behavior change

  const methods = assertStringList(policy.allowedMethods, "allowedMethods") ?? DEFAULT_ALLOWED_METHODS;
  const headers = assertStringList(policy.allowedHeaders, "allowedHeaders") ?? DEFAULT_ALLOWED_HEADERS;
  if (methods.length === 0) {
    throw new RangeError("`cors.allowedMethods` must not be empty");
  }
  if (headers.length === 0) {
    throw new RangeError("`cors.allowedHeaders` must not be empty");
  }
  if (policy.allowCredentials !== undefined && typeof policy.allowCredentials !== "boolean") {
    throw new RangeError("`cors.allowCredentials` must be a boolean");
  }
  if (
    policy.maxAgeSeconds !== undefined &&
    (!Number.isInteger(policy.maxAgeSeconds) || policy.maxAgeSeconds < 0)
  ) {
    throw new RangeError("`cors.maxAgeSeconds` must be a non-negative integer");
  }
  return {
    allowedOrigins: origins,
    allowedMethods: methods,
    allowedHeaders: headers,
    allowCredentials: policy.allowCredentials ?? false,
    maxAgeSeconds: policy.maxAgeSeconds ?? DEFAULT_MAX_AGE_SECONDS,
  };
}

function readOrigin(req: IncomingMessage): string | undefined {
  const raw = req.headers.origin;
  const origin = Array.isArray(raw) ? raw[0] : raw;
  return typeof origin === "string" && origin.length > 0 ? origin : undefined;
}

/** The request's `Origin` when it is on the allowlist, else `undefined`. */
export function corsAllowedOrigin(
  req: IncomingMessage,
  policy: ResolvedCorsPolicy
): string | undefined {
  const origin = readOrigin(req);
  return origin !== undefined && policy.allowedOrigins.includes(origin) ? origin : undefined;
}

/**
 * Answer a CORS preflight for an operator path. Returns `true` when this
 * was an `OPTIONS` request and the response has been sent — the caller
 * must not continue dispatch. Non-OPTIONS requests return `false`.
 *
 * Non-allowlisted (or missing) origins get a bare 204: nothing is
 * echoed, and the browser blocks the real request on its own.
 */
export function answerCorsPreflight(
  req: IncomingMessage,
  res: ServerResponse,
  policy: ResolvedCorsPolicy
): boolean {
  if (req.method !== "OPTIONS") return false;
  const origin = corsAllowedOrigin(req, policy);
  if (origin === undefined) {
    res.writeHead(204).end();
    return true;
  }
  const headers: Record<string, string> = {
    "access-control-allow-origin": origin,
    vary: "Origin",
    "access-control-allow-methods": policy.allowedMethods.join(", "),
    "access-control-allow-headers": policy.allowedHeaders.join(", "),
    "access-control-max-age": String(policy.maxAgeSeconds),
  };
  if (policy.allowCredentials) {
    headers["access-control-allow-credentials"] = "true";
  }
  res.writeHead(204, headers).end();
  return true;
}

/**
 * Stamp CORS headers on an actual operator response. No-op unless the
 * request carries an allowlisted `Origin` — same-origin and
 * non-browser clients see byte-identical responses to pre-WR-159.
 * Safe to call before the response is written: `setHeader` merges with
 * the later `writeHead`.
 */
export function setCorsResponseHeaders(
  req: IncomingMessage,
  res: ServerResponse,
  policy: ResolvedCorsPolicy
): void {
  const origin = corsAllowedOrigin(req, policy);
  if (origin === undefined) return;
  res.setHeader("access-control-allow-origin", origin);
  res.setHeader("vary", "Origin");
  if (policy.allowCredentials) {
    res.setHeader("access-control-allow-credentials", "true");
  }
}
