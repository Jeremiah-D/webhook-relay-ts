/**
 * WR-116: per-endpoint AWS Signature Version 4 request signing (opt-in).
 *
 * Some downstreams (API Gateway with IAM auth, AWS-service webhook sinks,
 * …) require every request to carry a SigV4 signature instead of — or in
 * addition to — the relay's own `x-relay-signature` HMAC (WR-26). The two
 * are orthogonal: SigV4 stamps `Authorization` + `x-amz-date`, WR-26
 * stamps `x-relay-signature`; both may be enabled for the same endpoint.
 *
 * The signing follows the AWS "Signature Version 4 signing process"
 * exactly:
 *
 *   1. CanonicalRequest =
 *        HTTPRequestMethod + "\n" +
 *        CanonicalURI + "\n" +
 *        CanonicalQueryString + "\n" +
 *        CanonicalHeaders + "\n" +
 *        SignedHeaders + "\n" +
 *        HexEncode(Hash(payload))
 *   2. StringToSign =
 *        "AWS4-HMAC-SHA256" + "\n" +
 *        amzdate + "\n" +
 *        credentialScope + "\n" +
 *        HexEncode(Hash(CanonicalRequest))
 *   3. signing key: kDate    = HMAC("AWS4" + secret, yyyymmdd)
 *                   kRegion  = HMAC(kDate, region)
 *                   kService = HMAC(kRegion, service)
 *                   kSigning = HMAC(kService, "aws4_request")
 *      signature = HexEncode(HMAC(kSigning, StringToSign))
 *   4. Authorization: AWS4-HMAC-SHA256
 *        Credential=<akid>/<yyyymmdd>/<region>/<service>/aws4_request,
 *        SignedHeaders=<semicolon-list>, Signature=<hex>
 *
 * Signed headers are always `host` + `x-amz-date`; the operator may add
 * more (e.g. `content-type`) via `additionalSignedHeaders`. The payload
 * hash is the real SHA-256 of the exact wire bytes (never
 * `UNSIGNED-PAYLOAD`): the hash covers the final body — after
 * transform/compression/E2EE — so the signature authenticates exactly
 * what the downstream receives.
 *
 * Secret handling: the endpoint config carries `secretRef`, a *reference*
 * (by default the name of an environment variable), never the raw secret —
 * so config snapshots, audit logs and operator API responses can never
 * leak plaintext key material. The secret is resolved per delivery attempt
 * through an injected `SecretResolver`, which also makes rotation work
 * without a restart. Signing-time failures throw `SigV4SigningError`
 * (missing secret: `SigV4SecretUnavailableError`), classified
 * `non_retryable` — retrying a config problem burns the retry budget for
 * nothing.
 *
 * Zero new dependencies: `node:crypto` only.
 */

import { createHash, createHmac } from "node:crypto";

/** SigV4 algorithm designation, stamped in `Authorization` and StringToSign. */
export const SIGV4_ALGORITHM = "AWS4-HMAC-SHA256";

/** Header carrying the SigV4 request timestamp (`<yyyymmdd>T<hhmmss>Z`). */
export const AMZ_DATE_HEADER = "x-amz-date";

/** Header carrying the SigV4 `Authorization` value. */
export const AUTHORIZATION_HEADER = "authorization";

/** Terminal scope string in the credential scope. */
const AWS4_REQUEST = "aws4_request";

/** AWS access key pair used for one signature computation. */
export interface AwsSigV4Credentials {
  /** Public access key id — safe to log/audit. */
  accessKeyId: string;
  /** Secret access key — resolved per attempt, never stored in config. */
  secretAccessKey: string;
}

/**
 * Per-endpoint SigV4 config (WR-116). Keyed by exact `targetUrl` in the
 * sender, mirroring the other per-endpoint maps.
 */
export interface AwsSigV4EndpointConfig {
  /** AWS access key id. Not secret — may appear in snapshots/audit. */
  accessKeyId: string;
  /**
   * Secret-store reference naming where the secret access key lives.
   * With the default resolver this is an environment variable name;
   * a custom resolver may point at a vault/KMS-backed store. This is
   * never the raw key.
   */
  secretRef: string;
  /** AWS region, e.g. `us-east-1`. */
  region: string;
  /** AWS service name, e.g. `execute-api`. */
  service: string;
  /**
   * Extra headers to fold into `SignedHeaders` beyond `host`/`x-amz-date`
   * (e.g. `["content-type"]`). Read case-insensitively from the wire
   * headers at signing time; a listed header absent from the wire
   * request fails the attempt loudly instead of signing a lie.
   */
  additionalSignedHeaders?: string[];
}

/** Resolves a `secretRef` to key material (or `undefined` when unknown). */
export type SecretResolver = (ref: string) => string | undefined;

/**
 * Default resolver: the ref is an environment variable name. Keeps the
 * reference/plumbing split honest — operators can swap in a vault-backed
 * resolver without touching the signer.
 */
export const defaultSecretResolver: SecretResolver = (ref) => process.env[ref];

/**
 * Base class for per-attempt SigV4 signing failures (bad URL, missing
 * secret, absent signed header). Classified `non_retryable`: the item as
 * built cannot be signed under the configured policy, so burning the
 * retry budget cannot help.
 */
export class SigV4SigningError extends Error {
  readonly endpoint: string;
  constructor(endpoint: string, message: string) {
    super(`awsSigV4[${endpoint}]: ${message}`);
    this.name = "SigV4SigningError";
    this.endpoint = endpoint;
  }
}

/**
 * Thrown when the secret for an endpoint cannot be resolved at signing
 * time. Carries the endpoint and the *reference* — never key material.
 */
export class SigV4SecretUnavailableError extends SigV4SigningError {
  readonly secretRef: string;
  constructor(endpoint: string, secretRef: string) {
    super(endpoint, `secret unavailable (secretRef "${secretRef}" did not resolve)`);
    this.name = "SigV4SecretUnavailableError";
    this.secretRef = secretRef;
  }
}

const REGION_SERVICE_RE = /^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$/;
const HEADER_NAME_RE = /^[a-z0-9][a-z0-9-]*$/;

/**
 * Validate one endpoint's SigV4 config. Throws `RangeError` on any bad
 * shape — called at startup so a typo fails fast, never mid-delivery.
 */
export function assertValidAwsSigV4Config(cfg: unknown, label: string): asserts cfg is AwsSigV4EndpointConfig {
  const at = (what: string) => `${label}: ${what}`;
  if (cfg === null || typeof cfg !== "object") {
    throw new RangeError(at("config must be an object"));
  }
  const c = cfg as Record<string, unknown>;
  if (typeof c.accessKeyId !== "string" || c.accessKeyId === "") {
    throw new RangeError(at("`accessKeyId` must be a non-empty string"));
  }
  if (typeof c.secretRef !== "string" || c.secretRef === "") {
    throw new RangeError(at("`secretRef` must be a non-empty string (a reference, never the raw secret)"));
  }
  if (typeof c.region !== "string" || !REGION_SERVICE_RE.test(c.region)) {
    throw new RangeError(at("`region` must look like an AWS region (e.g. `us-east-1`)"));
  }
  if (typeof c.service !== "string" || !REGION_SERVICE_RE.test(c.service)) {
    throw new RangeError(at("`service` must look like an AWS service name (e.g. `execute-api`)"));
  }
  if (c.additionalSignedHeaders !== undefined) {
    if (!Array.isArray(c.additionalSignedHeaders)) {
      throw new RangeError(at("`additionalSignedHeaders` must be an array of header names"));
    }
    const seen = new Set<string>();
    for (const h of c.additionalSignedHeaders) {
      if (typeof h !== "string" || !HEADER_NAME_RE.test(h.toLowerCase())) {
        throw new RangeError(at("`additionalSignedHeaders` entries must be valid header names"));
      }
      const lower = h.toLowerCase();
      if (lower === "host" || lower === AMZ_DATE_HEADER || lower === AUTHORIZATION_HEADER) {
        throw new RangeError(at(`\`additionalSignedHeaders\` must not repeat the always-signed headers (host, ${AMZ_DATE_HEADER}, authorization)`));
      }
      if (seen.has(lower)) {
        throw new RangeError(at(`\`additionalSignedHeaders\` lists "${h}" twice`));
      }
      seen.add(lower);
    }
  }
}

/**
 * WR-437: a live revision patch for one endpoint's SigV4 signing
 * config (partial — omitted fields keep their live values). A
 * `null` field is rejected: the four required fields have no
 * "clear back to a default" semantics — clearing is whole-entry
 * deletion only (a `null` patch). `additionalSignedHeaders` clears
 * by passing an empty list, not `null`.
 */
export interface AwsSigV4Revision {
  /** New AWS access key id. */
  accessKeyId?: string;
  /** New secret-store reference (a name, never the raw secret). */
  secretRef?: string;
  /** New AWS region. */
  region?: string;
  /** New AWS service name. */
  service?: string;
  /** New extra signed headers (an empty list clears the list). */
  additionalSignedHeaders?: string[];
}

/**
 * WR-437: the outcome of merging an {@link AwsSigV4Revision} onto
 * the live entry for one endpoint.
 */
export interface AwsSigV4RevisionChange {
  /**
   * The entry to store for the endpoint, or `undefined` to delete it
   * (the patch was `null`). `undefined` with `changed: false` means
   * there was no entry and the patch changed nothing.
   */
  entry: AwsSigV4EndpointConfig | undefined;
  /** False when the patch leaves the live entry exactly as it was. */
  changed: boolean;
}

function sameStringList(a: readonly string[] | undefined, b: readonly string[] | undefined): boolean {
  if (a === undefined || b === undefined) return a === b;
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

function sameSigV4Config(
  a: AwsSigV4EndpointConfig,
  b: AwsSigV4EndpointConfig
): boolean {
  return (
    a.accessKeyId === b.accessKeyId &&
    a.secretRef === b.secretRef &&
    a.region === b.region &&
    a.service === b.service &&
    sameStringList(a.additionalSignedHeaders, b.additionalSignedHeaders)
  );
}

/**
 * WR-437: merge one live revision patch onto the stored entry for an
 * endpoint. Pure and unit-testable: the caller owns the live map and
 * only applies the returned `entry` when `changed` is true — the map
 * itself is never mutated here. Validate-first-then-apply — the
 * candidate entry is built and run through
 * {@link assertValidAwsSigV4Config} before anything is returned, so
 * an illegal patch (a missing required field on opt-in, a bad region,
 * a `null` field, an empty patch) throws `RangeError` and the live
 * record is untouched. A `null` patch deletes the entry (the endpoint
 * stops SigV4 signing); a same-value patch is a silent no-op.
 */
export function reviseAwsSigV4Map(
  map: ReadonlyMap<string, AwsSigV4EndpointConfig>,
  endpoint: string,
  patch: AwsSigV4Revision | null,
  label = `awsSigV4[${endpoint}]`
): AwsSigV4RevisionChange {
  const prev = map.get(endpoint);
  if (patch === null) {
    return { entry: undefined, changed: prev !== undefined };
  }
  if (typeof patch !== "object" || Array.isArray(patch)) {
    throw new RangeError(`${label}: patch must be an object`);
  }
  const p = patch as Record<string, unknown>;
  for (const field of ["accessKeyId", "secretRef", "region", "service", "additionalSignedHeaders"]) {
    if (p[field] === null) {
      throw new RangeError(`${label}: \`${field}\` must not be null (clearing is whole-entry deletion only)`);
    }
  }
  if (
    p.accessKeyId === undefined &&
    p.secretRef === undefined &&
    p.region === undefined &&
    p.service === undefined &&
    p.additionalSignedHeaders === undefined
  ) {
    throw new RangeError(`${label}: empty patch — nothing to revise`);
  }
  const candidate: AwsSigV4EndpointConfig = {
    ...(prev ?? {}),
    ...(p.accessKeyId !== undefined ? { accessKeyId: p.accessKeyId as string } : {}),
    ...(p.secretRef !== undefined ? { secretRef: p.secretRef as string } : {}),
    ...(p.region !== undefined ? { region: p.region as string } : {}),
    ...(p.service !== undefined ? { service: p.service as string } : {}),
    ...(p.additionalSignedHeaders !== undefined
      ? { additionalSignedHeaders: [...(p.additionalSignedHeaders as string[])] }
      : {}),
  } as AwsSigV4EndpointConfig;
  // Opt-in needs all four required fields at once; a partial patch
  // on an unconfigured endpoint fails here, before anything is
  // applied. The same call also rejects a bad region/service or a
  // malformed additionalSignedHeaders list on an existing entry.
  assertValidAwsSigV4Config(candidate, label);
  if (prev !== undefined && sameSigV4Config(prev, candidate)) {
    return { entry: prev, changed: false };
  }
  return { entry: candidate, changed: true };
}

/** Case-insensitive header lookup over a wire-headers map. */
export function headerValueIgnoreCase(
  headers: Record<string, string | string[] | undefined>,
  name: string
): string | undefined {
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) {
      if (v === undefined) return undefined;
      return Array.isArray(v) ? v.join(", ") : v;
    }
  }
  return undefined;
}

/** `yyyymmdd` credential-scope date for the given instant (UTC). */
export function sigV4DateStamp(nowMs: number): string {
  const d = new Date(nowMs);
  const p = (n: number, w: number) => String(n).padStart(w, "0");
  return `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1, 2)}${p(d.getUTCDate(), 2)}`;
}

/** `<yyyymmdd>T<hhmmss>Z` request timestamp for the given instant (UTC). */
export function formatAmzDate(nowMs: number): string {
  const d = new Date(nowMs);
  const p = (n: number, w: number) => String(n).padStart(w, "0");
  return (
    `${sigV4DateStamp(nowMs)}T` +
    `${p(d.getUTCHours(), 2)}${p(d.getUTCMinutes(), 2)}${p(d.getUTCSeconds(), 2)}Z`
  );
}

/** Percent-encode per RFC 3986 (AWS SigV4 flavor: `!'()*` are encoded). */
function awsEncode(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (c) =>
    `%${c.charCodeAt(0).toString(16).toUpperCase()}`
  );
}

/** Canonical URI: `/` for empty paths, each segment RFC 3986-encoded. */
function canonicalUri(url: URL): string {
  const path = url.pathname === "" ? "/" : url.pathname;
  return path
    .split("/")
    .map((seg) => awsEncode(decodeURIComponentSafe(seg)))
    .join("/");
}

/** Decode a path segment without throwing on stray `%` sequences. */
function decodeURIComponentSafe(seg: string): string {
  try {
    return decodeURIComponent(seg);
  } catch {
    return seg;
  }
}

/**
 * Canonical query string: params sorted by (name, value) byte order,
 * `name=value` (bare name when valueless), joined with `&`.
 */
function canonicalQueryString(url: URL): string {
  const params: Array<[string, string]> = [];
  // URLSearchParams already splits on `&`/`=` and percent-decodes; empty
  // values and valueless params both surface as `""`, which matches the
  // SigV4 `name=` rendering either way.
  url.searchParams.forEach((value, name) => {
    params.push([name, value]);
  });
  params.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
  return params.map(([n, v]) => `${awsEncode(n)}=${awsEncode(v)}`).join("&");
}

/** `host` for the canonical headers: hostname + port unless default. */
function canonicalHost(url: URL): string {
  const defaultPort = url.protocol === "https:" ? "443" : url.protocol === "http:" ? "80" : "";
  return url.port === "" || url.port === defaultPort ? url.hostname.toLowerCase() : `${url.hostname.toLowerCase()}:${url.port}`;
}

/** Collapse header value whitespace per the SigV4 spec. */
function canonicalHeaderValue(value: string): string {
  return value.trim().replace(/\s+/g, " ");
}

export interface SignAwsSigV4Input {
  /** HTTP method, e.g. `POST`. */
  method: string;
  /** Full request URL (query string participates in the signature). */
  url: string;
  /** Exact wire bytes — the real payload hash, never UNSIGNED-PAYLOAD. */
  body: Buffer;
  credentials: AwsSigV4Credentials;
  region: string;
  service: string;
  /**
   * Extra signed headers (already lowercased names) with their wire
   * values. `host`/`x-amz-date` are always included and need not be
   * listed here.
   */
  extraSignedHeaders?: Record<string, string>;
  /** Signing instant; defaults to now. Inject for deterministic tests. */
  nowMs?: number;
}

export interface SignAwsSigV4Output {
  /** Value for the `Authorization` header. */
  authorization: string;
  /** Value for the `x-amz-date` header. */
  amzDate: string;
  /** `;`-joined signed header names, in signature order. */
  signedHeaders: string;
  /** Hex SHA-256 of the canonical request (exposed for tests/audit). */
  canonicalRequestHash: string;
}

/** Derive the SigV4 signing key for (secret, dateStamp, region, service). */
export function deriveSigV4SigningKey(
  secretAccessKey: string,
  dateStamp: string,
  region: string,
  service: string
): Buffer {
  const kDate = createHmac("sha256", `AWS4${secretAccessKey}`).update(dateStamp).digest();
  const kRegion = createHmac("sha256", kDate).update(region).digest();
  const kService = createHmac("sha256", kRegion).update(service).digest();
  return createHmac("sha256", kService).update(AWS4_REQUEST).digest();
}

/** Build the canonical request string for the given inputs. */
export function buildCanonicalRequest(input: {
  method: string;
  url: string;
  body: Buffer;
  extraSignedHeaders?: Record<string, string>;
  amzDate: string;
}): { canonicalRequest: string; signedHeaders: string } {
  const url = new URL(input.url);
  const host = canonicalHost(url);
  const headerEntries: Array<[string, string]> = [
    ["host", host],
    [AMZ_DATE_HEADER, input.amzDate],
  ];
  for (const [name, value] of Object.entries(input.extraSignedHeaders ?? {})) {
    headerEntries.push([name.toLowerCase(), canonicalHeaderValue(value)]);
  }
  headerEntries.sort((a, b) => (a[0] < b[0] ? -1 : 1));
  const canonicalHeaders = headerEntries.map(([n, v]) => `${n}:${v}\n`).join("");
  const signedHeaders = headerEntries.map(([n]) => n).join(";");
  const payloadHash = createHash("sha256").update(input.body).digest("hex");
  const canonicalRequest = [
    input.method.toUpperCase(),
    canonicalUri(url),
    canonicalQueryString(url),
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");
  return { canonicalRequest, signedHeaders };
}

/**
 * Sign one request per AWS Signature Version 4. Pure function — no I/O,
 * no clock reads beyond `nowMs`.
 */
export function signAwsSigV4(input: SignAwsSigV4Input): SignAwsSigV4Output {
  const { accessKeyId, secretAccessKey } = input.credentials;
  if (typeof accessKeyId !== "string" || accessKeyId === "") {
    throw new RangeError("signAwsSigV4: `credentials.accessKeyId` must be a non-empty string");
  }
  if (typeof secretAccessKey !== "string" || secretAccessKey === "") {
    throw new RangeError("signAwsSigV4: `credentials.secretAccessKey` must be a non-empty string");
  }
  const nowMs = input.nowMs ?? Date.now();
  const amzDate = formatAmzDate(nowMs);
  const dateStamp = sigV4DateStamp(nowMs);
  const { canonicalRequest, signedHeaders } = buildCanonicalRequest({
    method: input.method,
    url: input.url,
    body: input.body,
    extraSignedHeaders: input.extraSignedHeaders,
    amzDate,
  });
  const canonicalRequestHash = createHash("sha256").update(canonicalRequest, "utf8").digest("hex");
  const credentialScope = `${dateStamp}/${input.region}/${input.service}/${AWS4_REQUEST}`;
  const stringToSign = [SIGV4_ALGORITHM, amzDate, credentialScope, canonicalRequestHash].join("\n");
  const signingKey = deriveSigV4SigningKey(secretAccessKey, dateStamp, input.region, input.service);
  const signature = createHmac("sha256", signingKey).update(stringToSign, "utf8").digest("hex");
  const authorization =
    `${SIGV4_ALGORITHM} Credential=${accessKeyId}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return { authorization, amzDate, signedHeaders, canonicalRequestHash };
}
