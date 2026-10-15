import { createHash, X509Certificate } from "node:crypto";
import { createSecureContext } from "node:tls";
import type { TLSSocket } from "node:tls";
import { assertValidPins, normalizePin } from "./pinning.ts";
import type { ConfigChange } from "./hotreload.ts";

/**
 * Inbound mTLS — client-certificate authentication for the relay's own
 * listeners (WR-103).
 *
 * The relay's listeners are plain HTTP by default. When `inboundMtls` is
 * configured, the listeners that can require a client certificate become
 * Node `https` servers with `requestCert: true` and
 * `rejectUnauthorized: false`: the handshake *requests* a certificate but
 * never aborts on a missing/invalid one, so enforcement happens at
 * request time and a rejected caller gets a proper HTTP 401 (with a
 * machine-readable `reason` and a `rejected` audit event) instead of a
 * bare TLS alert that carries no diagnostics.
 *
 * Which listeners terminate TLS:
 *
 * - `requireCert: true` (the default): every route on every listener
 *   requires a client certificate — both the intake plane and the
 *   operator plane (when split) become HTTPS.
 * - `requireCert: false` + `operatorMtls: true`: only operator routes
 *   require a certificate. With a split operator plane (WR-56
 *   `operatorPort`) the operator listener alone becomes HTTPS and the
 *   intake plane stays plain HTTP — webhook ingest is untouched, not
 *   even TLS-terminated. On the legacy single plane the shared listener
 *   must become HTTPS (operator paths live on it), but ingest routes
 *   still accept requests without a client certificate.
 *
 * Verified client identity (whole-certificate SHA-256 fingerprint plus
 * the certificate subject, e.g. `CN=relay-client`) is recorded on the
 * `accepted` / `rejected` audit events as `clientCertFingerprint` /
 * `clientCertSubject`.
 *
 * Hot-reload: the CA chain, the server key/certificate, the fingerprint
 * whitelist, and the `requireCert` / `operatorMtls` policy are all
 * hot-swappable via `RelayServer#updateInboundMtlsConfig` — the TLS
 * material is pushed into the live listeners with
 * `server.setSecureContext()`. Two genuine limitations, documented here
 * instead of faked:
 *
 * 1. `setSecureContext()` only affects *new* TLS handshakes. Connections
 *    already established (e.g. keep-alive clients) keep the previous
 *    secure context until they reconnect.
 * 2. *Enabling* or *disabling* inbound mTLS needs a restart: the
 *    listener is created as HTTPS or plain HTTP at startup, and a bound
 *    socket cannot change modes at runtime.
 *
 * Zero dependencies (`node:crypto` + `node:tls` only).
 */

/**
 * Inbound mTLS configuration (`createRelayServer({ inboundMtls })`).
 * PEM values are in-memory strings — no file paths, so rotating the CA
 * or the server certificate is a config change.
 */
export interface InboundMtlsConfig {
  /**
   * The relay's own TLS private key (PEM string). Required: a listener
   * that enforces mTLS must terminate TLS, and that needs a server
   * identity.
   */
  key: string;
  /** The relay's own TLS certificate (PEM string, leaf first). */
  cert: string;
  /**
   * Client CA chain (PEM string, or array of PEM strings) that client
   * certificates must chain to. This is the trust anchor for
   * `socket.authorized`.
   */
  ca: string | string[];
  /**
   * When `true` (default), every route requires a client certificate.
   * When `false`, a request without a certificate passes as anonymous —
   * combine with `operatorMtls: true` to lock down only the operator
   * routes while ingest stays open.
   */
  requireCert?: boolean;
  /**
   * Optional client-certificate fingerprint whitelist: SHA-256 over the
   * DER-encoded client certificate, base64 — the same
   * `"sha256/<base64>"` / `"sha256:<base64>"` / bare-base64 spellings the
   * WR-21 pinning module accepts (whole-certificate fingerprint, like
   * `X509Certificate#fingerprint256`, so a renewal with a new key needs
   * a whitelist update). A presented certificate whose fingerprint is
   * not listed is rejected with `client_cert_invalid`, even when its
   * chain verifies. Empty array throws `RangeError` (refusing to trust
   * nobody is a misconfiguration, not a policy).
   */
  clientFingerprints?: string[];
  /**
   * Operator routes (`/dead-letter`, `/metrics`, `/events`, …) require a
   * client certificate independently of ingest. Useful with
   * `requireCert: false`: admin endpoints are locked down without
   * forcing webhook senders to present certificates.
   */
  operatorMtls?: boolean;
}

/** `InboundMtlsConfig` with defaults applied and fingerprints normalized. */
export interface ResolvedInboundMtlsConfig {
  key: string;
  cert: string;
  ca: string[];
  requireCert: boolean;
  /** Bare-base64 SHA-256 digests (no `sha256/` prefix). */
  clientFingerprints: string[];
  operatorMtls: boolean;
}

/** Partial `inboundMtls` update accepted by `updateInboundMtlsConfig`. */
export interface InboundMtlsConfigPatch {
  key?: string;
  cert?: string;
  ca?: string | string[];
  requireCert?: boolean;
  clientFingerprints?: string[];
  operatorMtls?: boolean;
}

/** The verified identity of one mTLS-authenticated caller. */
export interface InboundMtlsIdentity {
  /** Base64 SHA-256 of the DER-encoded client certificate. */
  fingerprint: string;
  /** Certificate subject, e.g. `"CN=relay-client"`. */
  subject: string;
}

/** What the TLS layer observed about the peer certificate. */
export interface PeerCertInfo {
  presented: boolean;
  /** `socket.authorized` — the chain verified against the configured CA. */
  authorized: boolean;
  authorizationError?: string;
  fingerprint?: string;
  subject?: string;
}

/** SHA-256 (base64) of a DER-encoded certificate — the fingerprint dialect. */
export function peerCertFingerprint(certDer: Buffer): string {
  return createHash("sha256").update(certDer).digest("base64");
}

function assertPemString(value: unknown, field: string): asserts value is string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new RangeError(`inboundMtls: \`${field}\` must be a non-empty PEM string`);
  }
}

/**
 * Validate an inbound mTLS config the way a constructor would. Throws
 * `RangeError` on the first problem — an unusable server identity or CA
 * fails at startup, never on the first client handshake.
 */
export function assertValidInboundMtlsConfig(cfg: unknown): void {
  if (typeof cfg !== "object" || cfg === null || Array.isArray(cfg)) {
    throw new RangeError("inboundMtls: config must be an object");
  }
  const c = cfg as Record<string, unknown>;
  assertPemString(c.key, "key");
  assertPemString(c.cert, "cert");
  const ca = c.ca;
  const caList = typeof ca === "string" ? [ca] : ca;
  if (!Array.isArray(caList) || caList.length === 0) {
    throw new RangeError("inboundMtls: `ca` must be a non-empty PEM string or a non-empty array of PEM strings");
  }
  for (const entry of caList) assertPemString(entry, "ca");
  if (c.requireCert !== undefined && typeof c.requireCert !== "boolean") {
    throw new RangeError(
      `inboundMtls: \`requireCert\` must be a boolean, got ${JSON.stringify(c.requireCert)}`
    );
  }
  if (c.operatorMtls !== undefined && typeof c.operatorMtls !== "boolean") {
    throw new RangeError(
      `inboundMtls: \`operatorMtls\` must be a boolean, got ${JSON.stringify(c.operatorMtls)}`
    );
  }
  if (c.clientFingerprints !== undefined) {
    if (!Array.isArray(c.clientFingerprints)) {
      throw new RangeError("inboundMtls: `clientFingerprints` must be an array of fingerprint strings");
    }
    try {
      assertValidPins(c.clientFingerprints as string[]);
    } catch (err) {
      throw new RangeError(`inboundMtls: invalid \`clientFingerprints\`: ${(err as Error).message}`);
    }
  }
  try {
    // The cheapest real parse check: OpenSSL rejects a garbage or
    // mismatched key/cert pair here, at config time.
    createSecureContext({ key: c.key as string, cert: c.cert as string });
  } catch (err) {
    throw new RangeError(`inboundMtls: invalid server key/cert PEM: ${(err as Error).message}`);
  }
  try {
    new X509Certificate(c.cert as string);
  } catch (err) {
    throw new RangeError(`inboundMtls: unparseable server cert PEM: ${(err as Error).message}`);
  }
  for (const entry of caList as string[]) {
    try {
      new X509Certificate(entry);
    } catch (err) {
      throw new RangeError(`inboundMtls: unparseable \`ca\` PEM: ${(err as Error).message}`);
    }
  }
}

/**
 * Validate + normalize an inbound mTLS config. Throws `RangeError` on
 * invalid values; the returned object is what the request-time gate
 * reads.
 */
export function resolveInboundMtlsConfig(cfg: InboundMtlsConfig): ResolvedInboundMtlsConfig {
  assertValidInboundMtlsConfig(cfg);
  const ca = typeof cfg.ca === "string" ? [cfg.ca] : [...cfg.ca];
  return {
    key: cfg.key,
    cert: cfg.cert,
    ca,
    requireCert: cfg.requireCert ?? true,
    clientFingerprints: (cfg.clientFingerprints ?? []).map(normalizePin),
    operatorMtls: cfg.operatorMtls ?? false,
  };
}

/**
 * Extract what the TLS handshake observed about the peer certificate.
 * Never throws: an unreadable peer cert is reported as not presented.
 */
export function extractPeerCertInfo(socket: TLSSocket): PeerCertInfo {
  let raw: unknown;
  try {
    raw = (socket.getPeerCertificate() as { raw?: unknown } | undefined)?.raw;
  } catch {
    raw = undefined;
  }
  if (!(raw instanceof Buffer) || raw.length === 0) {
    return { presented: false, authorized: false };
  }
  let subject = "";
  try {
    subject = new X509Certificate(raw).subject;
  } catch {
    subject = "";
  }
  return {
    presented: true,
    authorized: socket.authorized === true,
    ...(typeof socket.authorizationError === "string" && socket.authorizationError !== ""
      ? { authorizationError: socket.authorizationError }
      : {}),
    fingerprint: peerCertFingerprint(raw),
    subject,
  };
}

/** The request-time verdict of the inbound mTLS gate. */
export type InboundMtlsDecision =
  | { allowed: true; identity?: InboundMtlsIdentity }
  | {
      allowed: false;
      reason: "client_cert_required" | "client_cert_invalid";
      fingerprint?: string;
      subject?: string;
    };

/**
 * Decide one request against the resolved config. `isOperatorRoute`
 * selects the independent operator-route policy (`operatorMtls`).
 *
 * - No certificate + route requires one → `client_cert_required`.
 * - Certificate presented but the chain does not verify against the
 *   configured CA, or its fingerprint is not whitelisted →
 *   `client_cert_invalid`.
 * - Route does not require mTLS → allowed; a *verified* presented
 *   certificate still yields its identity for the audit trail, an
 *   unverified one is ignored (ingest stays open).
 */
export function decideInboundMtls(
  cfg: ResolvedInboundMtlsConfig,
  peer: PeerCertInfo,
  isOperatorRoute: boolean
): InboundMtlsDecision {
  const required = cfg.requireCert || (isOperatorRoute && cfg.operatorMtls);
  if (!peer.presented) {
    return required ? { allowed: false, reason: "client_cert_required" } : { allowed: true };
  }
  const whitelisted =
    cfg.clientFingerprints.length === 0 ||
    (peer.fingerprint !== undefined && cfg.clientFingerprints.includes(peer.fingerprint));
  if (!peer.authorized || !whitelisted) {
    return {
      allowed: false,
      reason: "client_cert_invalid",
      ...(peer.fingerprint !== undefined ? { fingerprint: peer.fingerprint } : {}),
      ...(peer.subject !== undefined ? { subject: peer.subject } : {}),
    };
  }
  return {
    allowed: true,
    identity: {
      fingerprint: peer.fingerprint as string,
      subject: peer.subject ?? "",
    },
  };
}

/**
 * `https.createServer` options for an mTLS-enforcing listener:
 * request the client certificate, but never abort the handshake on it —
 * enforcement happens at request time (see `decideInboundMtls`).
 */
export function inboundMtlsServerOptions(cfg: ResolvedInboundMtlsConfig): {
  key: string;
  cert: string;
  ca: string[];
  requestCert: boolean;
  rejectUnauthorized: boolean;
} {
  return {
    key: cfg.key,
    cert: cfg.cert,
    ca: cfg.ca,
    requestCert: true,
    rejectUnauthorized: false,
  };
}

/**
 * The TLS secure-context slice of the config — what
 * `server.setSecureContext()` accepts for hot-swapping the key, cert,
 * and CA chain on live listeners (new handshakes only; established
 * connections keep the previous context).
 */
export function inboundMtlsSecureContext(cfg: ResolvedInboundMtlsConfig): {
  key: string;
  cert: string;
  ca: string[];
} {
  return { key: cfg.key, cert: cfg.cert, ca: cfg.ca };
}

const PATCH_FIELDS = ["key", "cert", "ca", "requireCert", "clientFingerprints", "operatorMtls"] as const;

/**
 * Validate an `updateInboundMtlsConfig` patch shape. Throws `RangeError`
 * on unknown fields or wrong types; full semantic validation happens
 * against the merged config in `applyInboundMtlsConfigPatch`.
 */
export function assertValidInboundMtlsConfigPatch(patch: unknown): void {
  if (typeof patch !== "object" || patch === null || Array.isArray(patch)) {
    throw new RangeError("updateInboundMtlsConfig: patch must be an object");
  }
  const p = patch as Record<string, unknown>;
  for (const field of Object.keys(p)) {
    if (!(PATCH_FIELDS as readonly string[]).includes(field)) {
      throw new RangeError(`updateInboundMtlsConfig: unknown field ${JSON.stringify(field)}`);
    }
  }
  if (p.key !== undefined && (typeof p.key !== "string" || p.key.trim() === "")) {
    throw new RangeError("updateInboundMtlsConfig: `key` must be a non-empty PEM string");
  }
  if (p.cert !== undefined && (typeof p.cert !== "string" || p.cert.trim() === "")) {
    throw new RangeError("updateInboundMtlsConfig: `cert` must be a non-empty PEM string");
  }
  if (p.ca !== undefined) {
    const caList = typeof p.ca === "string" ? [p.ca] : p.ca;
    if (
      !Array.isArray(caList) ||
      caList.length === 0 ||
      !caList.every((e) => typeof e === "string" && e.trim() !== "")
    ) {
      throw new RangeError(
        "updateInboundMtlsConfig: `ca` must be a non-empty PEM string or a non-empty array of PEM strings"
      );
    }
  }
  if (p.requireCert !== undefined && typeof p.requireCert !== "boolean") {
    throw new RangeError("updateInboundMtlsConfig: `requireCert` must be a boolean");
  }
  if (p.operatorMtls !== undefined && typeof p.operatorMtls !== "boolean") {
    throw new RangeError("updateInboundMtlsConfig: `operatorMtls` must be a boolean");
  }
  if (p.clientFingerprints !== undefined && !Array.isArray(p.clientFingerprints)) {
    throw new RangeError("updateInboundMtlsConfig: `clientFingerprints` must be an array of fingerprint strings");
  }
}

function pemIdentity(pem: string): string {
  return createHash("sha256").update(pem.trim()).digest("hex").slice(0, 16);
}

/**
 * Apply a patch to the live config. Validation runs against the *merged*
 * config before anything is returned: an illegal patch throws
 * `RangeError` and the caller's current config is untouched. PEM
 * material is compared by hash and reported as `<redacted>` — key
 * material never lands in the change list (or the audit log).
 */
export function applyInboundMtlsConfigPatch(
  current: ResolvedInboundMtlsConfig,
  patch: InboundMtlsConfigPatch
): { next: ResolvedInboundMtlsConfig; changes: ConfigChange[] } {
  assertValidInboundMtlsConfigPatch(patch);
  // An unset whitelist normalizes to `[]`; map it back to `undefined`
  // for the merged candidate so re-validation does not mistake "no
  // whitelist" for "an explicitly empty whitelist" (which is a
  // misconfiguration and throws).
  const mergedFingerprints = patch.clientFingerprints ?? current.clientFingerprints;
  const candidate: InboundMtlsConfig = {
    key: patch.key ?? current.key,
    cert: patch.cert ?? current.cert,
    ca: patch.ca ?? current.ca,
    requireCert: patch.requireCert ?? current.requireCert,
    clientFingerprints: mergedFingerprints.length === 0 ? undefined : mergedFingerprints,
    operatorMtls: patch.operatorMtls ?? current.operatorMtls,
  };
  // Full validation of the merged whole: a patch that breaks the
  // key/cert pair or empties the CA fails here, before apply.
  const next = resolveInboundMtlsConfig(candidate);
  const changes: ConfigChange[] = [];
  if (pemIdentity(current.key) !== pemIdentity(next.key)) {
    changes.push({ field: "inboundMtls.key", from: "<redacted>", to: "<redacted>" });
  }
  if (pemIdentity(current.cert) !== pemIdentity(next.cert)) {
    changes.push({ field: "inboundMtls.cert", from: "<redacted>", to: "<redacted>" });
  }
  if (current.ca.map(pemIdentity).join(",") !== next.ca.map(pemIdentity).join(",")) {
    changes.push({ field: "inboundMtls.ca", from: "<redacted>", to: "<redacted>" });
  }
  if (current.requireCert !== next.requireCert) {
    changes.push({ field: "inboundMtls.requireCert", from: current.requireCert, to: next.requireCert });
  }
  if (current.operatorMtls !== next.operatorMtls) {
    changes.push({ field: "inboundMtls.operatorMtls", from: current.operatorMtls, to: next.operatorMtls });
  }
  if (current.clientFingerprints.join(",") !== next.clientFingerprints.join(",")) {
    changes.push({
      field: "inboundMtls.clientFingerprints",
      from: current.clientFingerprints,
      to: next.clientFingerprints,
    });
  }
  return { next, changes };
}
