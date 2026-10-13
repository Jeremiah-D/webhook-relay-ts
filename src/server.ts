import { Agent as HttpAgent, createServer, request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import type { Server } from "node:http";
import { randomUUID } from "node:crypto";
import {
  assertValidEndpointVerifierRules,
  HmacSha256Verifier,
  RotatingHmacVerifier,
  selectEndpointVerifier,
  signSha256,
  type EndpointVerifierRule,
  type SigningKey,
  type Verifier,
} from "./verify.ts";
import { RetryQueue, type DeliveryPriority, type DownstreamResponse, type RetryItem, type Sender } from "./retry.ts";
import { parseDeliverAtHeader, DELIVER_AT_HEADER } from "./retry.ts";
import type { ShadowDeliveredInfo, ShadowFailedInfo, ShadowTargetConfig, ShadowTargetsConfig } from "./retry.ts";
import { parseCronExpression, CRON_HEADER } from "./cron.ts";
import type { CompletionCallbackOptions } from "./callback.ts";
import { createBoundAddressSelfCheck } from "./callback.ts";
import { TENANT_ID_HEADER, assertValidTenantId, tenantScopeKey } from "./tenant.ts";
import type { AutoReplayOptions } from "./autoreplay.ts";
import type { DeadLetterRetentionOptions } from "./deadletter-retention.ts";
import type { ReplayEgressOptions } from "./replay-egress.ts";
import { HttpDeliveryError, parseRetryAfterMs } from "./failure.ts";
import { installGracefulShutdown } from "./shutdown.ts";
import { SourceBaselineDetector, type SourceBaselineOptions } from "./source-baseline.ts";
import type { PayloadEncryptor } from "./encrypt.ts";
import type { FieldMask } from "./masking.ts";
import type { ReplayGuard } from "./replay.ts";
import { DeliveryDeduplicator, type DedupOptions } from "./dedup.ts";
import { UsageMeter, type UsageOptions } from "./usage.ts";
import { InboundRateLimiter, type InboundRateLimitOptions } from "./ratelimit.ts";
import { InboundIpAcl, IpAclMetrics, type IpAclOptions } from "./ip-acl.ts";
import { InboundApiKeyAuth, type ApiKeyOptions, type EndpointApiKeyRule } from "./api-key.ts";
import {
  assertValidOperatorKeys,
  bearerToken,
  matchOperatorKey,
  operatorMay,
  type OperatorKeyEntry,
} from "./operator-keys.ts";
import { resolveTraceId, TRACE_ID_HEADER } from "./trace.ts";
import { ContentRouteTable, type ContentRouteRule } from "./content-routes.ts";
import {
  deriveIdempotencyKey,
  IDEMPOTENCY_KEY_HEADER,
  resolveIdempotencyKeyConfig,
  type IdempotencyKeyOptions,
  type ResolvedIdempotencyKeyConfig,
} from "./idempotency-key.ts";
import type { TLSSocket } from "node:tls";
import { assertValidPins, normalizePin, spkiFingerprint, TlsPinMismatchError } from "./pinning.ts";
import {
  assertValidClientCert,
  clientCertIdentity,
  type TlsClientCert,
} from "./mtls.ts";
import {
  assertValidTlsSniOverride,
  resolveTlsSniOverride,
  type ResolvedTlsSniOverride,
  type TlsSniOverride,
} from "./tls-sni.ts";
import {
  assertTlsVersionMeetsFloor,
  assertValidMinTlsVersion,
  TlsVersionMonitor,
  TlsVersionRejectedError,
  type MinTlsVersion,
} from "./tls-version.ts";
import {
  assertValidSecretRotationRules,
  compileSecretRotationRules,
  selectSecretRotation,
  SIGNATURE_VERSION_HEADER,
  type EndpointSecretRotationRule,
} from "./secret-rotation.ts";
import {
  CertExpiryMonitor,
  resolveCertExpiryOptions,
  type CertExpiryOptions,
} from "./cert-expiry.ts";
import { OutboundConnectionPool, type KeepAlivePoolOptions } from "./keepalive.ts";
import { warmupOutboundPool, resolveWarmupOptions } from "./warmup.ts";
import {
  assertValidProxyUrl,
  createProxiedAgent,
  resolveProxyUrl,
} from "./proxy.ts";
import {
  Http2SessionPool,
  Http2UnavailableError,
  resolveHttp2PoolOptions,
  runHttp2Stream,
  type Http2PoolOptions,
} from "./http2.ts";
import { WebSocketPool, type WebSocketPoolOptions } from "./websocket.ts";
import {
  DEFAULT_E2EE_KEY_GRACE_MS,
  E2EE_ALGORITHM,
  E2EE_HEADER,
  RotatingE2eeSealer,
  parseX25519PublicKey,
  sealOutboundPayload,
  type E2eeRotationKey,
} from "./e2ee.ts";
import type { KeyObject } from "node:crypto";
import type { AuditLog } from "./audit.ts";
import { DeliveryEventArchiver } from "./event-archive.ts";
import { buildDeliverySnapshot } from "./delivery-status.ts";
import type { EndpointConfigPatch } from "./hotreload.ts";
import {
  ApiVersionRouter,
  VersionMetrics,
  type ApiVersionOptions,
  type ApiVersionRoute,
} from "./version.ts";
import {
  assertValidEndpointSchemaRules,
  SchemaMetrics,
  selectEndpointSchema,
  type EndpointSchemaRule,
  type PayloadSchema,
} from "./schema.ts";
import type { ProbeOptions } from "./downstream-probe.ts";
import type { OtlpExporterOptions } from "./otlp.ts";
import {
  assertValidCompressOutboundConfig,
  DecompressionFailedError,
  DecompressionTooLargeError,
  gunzipCapped,
  guardedCompressOutbound,
  isGzipContentEncoding,
  maybeCompressOutbound,
  outboundContentType,
  OutboundCompressionTracker,
  assertValidGuardedCompressConfig,
  type CompressOutboundOptions,
  type GuardedCompressOptions,
  type GzipFallbackInfo,
} from "./gzip.ts";
import {
  assertValidResponseCompressionConfig,
  decodeResponseBody,
  DEFAULT_OUTBOUND_ACCEPT_ENCODING,
  type ResponseCompressionOptions,
} from "./response-encoding.ts";
import {
  resolveForwardHeadersConfig,
  shouldForwardHeader,
  type CompiledForwardHeadersRule,
  type ForwardHeadersRuleConfig,
} from "./forward-headers.ts";

/**
 * Operator/intake plane split (WR-56). When set, the relay listens on two
 * ports: the intake plane (the returned server, bound by the caller with
 * `listen()`) accepts only webhooks, and the operator plane (bound by the
 * relay itself at creation, see `RelayServer.operatorServer`) serves only
 * the operator endpoints (`/dead-letter`, `/audit`, `/audit/verify`, `/metrics`, `/events`,
 * `/config/endpoint`, `/deliveries/:traceId`, ...). Operator paths hit on
 * the intake plane — and webhook posts hit on the operator plane — are
 * answered with a plain 404 that reveals nothing about the other plane.
 * Bind errors surface as `error` on `operatorServer`, the standard Server
 * contract.
 */
export interface OperatorPortOptions {
  /**
   * The operator plane's listen port. `0` binds an ephemeral port (useful
   * for tests; read the bound port from `server.operatorServer.address()`).
   * Integer 0-65535; anything else throws `RangeError` at startup.
   */
  port: number;
  /**
   * Bind host for the operator plane. Defaults to `127.0.0.1` — the
   * operator plane never binds `0.0.0.0` by default, so it is not
   * reachable from the network unless the operator explicitly opts in.
   */
  host?: string;
}

/**
 * One shadow downstream for a logical endpoint (WR-85; see `src/shadow.ts`
 * and the `shadowTargets` server option): the downstream-migration /
 * contract-verification scenario. After every main delivery attempt
 * completes, the relay mirrors the identical wire request to this URL.
 */
export interface ShadowTargetServerConfig {
  /**
   * The shadow downstream URL — the mirrored copy goes here. Must be a
   * valid absolute `http:`/`https:` URL, and must differ from the logical
   * endpoint it shadows.
   */
  targetUrl: string;
  /**
   * Independent TLS pin whitelist for this shadow target (WR-21),
   * verified against the shadow downstream's certificate — the shadow
   * sender is a separate copy, so its pins are configured here, not in
   * the top-level `tlsPins`. Malformed pins throw `RangeError` at
   * startup.
   */
  tlsPins?: string[];
  /**
   * Independent mTLS client identity for this shadow target (WR-36) —
   * the shadow sender presents this certificate during the TLS
   * handshake with the shadow downstream. Invalid values throw
   * `RangeError` at startup.
   */
  tlsClientCert?: TlsClientCert;
}

export interface RelayServerOptions {
  /** HMAC secret used to verify incoming webhooks. */
  secret: string;
  /** Where verified payloads are forwarded (POST). */
  forwardUrl: string;
  /** Audit log sink. */
  auditLog: AuditLog;
  /** Injectable delivery function; defaults to a node:http(s) POST. */
  sender?: Sender;
  /**
   * Signature verifier; defaults to HMAC-SHA256 with `secret`.
   * Inject e.g. `new Ed25519Verifier(pem)` to change schemes.
   * Cannot be combined with `signingKeys`.
   */
  verifier?: Verifier;
  /**
   * Signature key rotation (see `RotatingHmacVerifier` in `src/verify.ts`):
   * several HMAC keys coexist, one primary signs new webhooks, retired
   * keys stay verifiable inside `keyGraceMs`. Senders name the signing key
   * with the `x-key-id` header; without it the server tries the primary
   * key first, then every other still-active key. `accepted` / `rejected`
   * audit events carry the verifying `keyId` (or `"unknown"`). Cannot be
   * combined with `verifier`.
   */
  signingKeys?: SigningKey[];
  /**
   * Grace period in ms during which a retired signing key still verifies.
   * Default: 86_400_000 (24h). Only meaningful with `signingKeys`.
   */
  keyGraceMs?: number;
  /**
   * Clock source for signing-key retirement checks; defaults to
   * `Date.now`. Injectable for deterministic tests. Only meaningful with
   * `signingKeys`.
   */
  keyNowMs?: () => number;
  /** Retry queue tuning, passed through to RetryQueue. */
  retry?: ConstructorParameters<typeof RetryQueue>[0];
  /**
   * Per-endpoint signature verifier selection (WR-29): inbound request
   * paths can each trust a different verifier — e.g. Ed25519 for
   * `/hooks/solana-program` and HMAC-SHA256 everywhere else. Rules are
   * tried in config order and the first match wins; paths with no match
   * fall back to the global `verifier` (or `signingKeys` / `secret`
   * default). Patterns are exact (`/hooks/stripe`) or prefix
   * (`/hooks/*`). A signature mismatch on a per-endpoint verifier is
   * answered 401 and audited as `rejected` like any other bad signature —
   * it never enqueues, so it never touches the circuit breaker. Invalid
   * rules throw `RangeError` at startup.
   */
  endpointVerifiers?: EndpointVerifierRule[];
  /**
   * Inbound HMAC secret dual-version zero-downtime rotation (WR-67, see
   * `src/secret-rotation.ts`): per-endpoint `currentSecret` +
   * `previousSecret` in parallel — the old key stays verifiable inside
   * its grace window while the sender migrates, so no in-flight webhook
   * fails during the flip. Senders declare the signing side with the
   * `x-signature-version` header (`"current"` / `"previous"`); without
   * it the server tries `current` first and falls back to `previous`.
   * Every `previous`-verified webhook is audited as
   * `secret_rotation_previous_used`; once the grace window has elapsed
   * (`RotatingEndpointSecret#isRotationComplete()`), clearing
   * `previousSecret` completes the rotation. Applies only where the
   * default HMAC verifier is in force — a custom `verifier`,
   * `signingKeys`, or a matching `endpointVerifiers` rule takes
   * precedence and the rotation rule is ignored there. Invalid rules
   * throw `RangeError` at startup.
   */
  secretRotation?: EndpointSecretRotationRule[];
  /**
   * Inbound API version routing (WR-33, see `src/version.ts`): inbound
   * paths may carry a version prefix (`/v1/...`, `/v2/...`) whose payload
   * is reshaped into the current schema by a pluggable adapter *after*
   * signature verification (the signature covers the raw body the sender
   * signed) and *before* dedup/enqueue — so dedup hashes the adapted
   * payload and the same business event sent as `v1` and `v2` suppresses
   * to one delivery. An adapter that throws rejects the request with 400
   * (audited as `rejected` with reason `version_adapt_failed`). The
   * matched version is recorded on `accepted` audit events (`version`)
   * and in the Prometheus exposition
   * (`relay_inbound_version_total{version,status}`; unversioned requests
   * count under `version="none"`). Paths without a registered prefix are
   * untouched — no `version` field anywhere, exactly the legacy behavior.
   * Invalid routes throw `RangeError` at startup.
   */
  versions?: ApiVersionOptions;
  /**
   * Inbound payload JSON schema registry (WR-41, see `src/schema.ts`):
   * per-endpoint pluggable payload-shape validation. Rules are tried in
   * config order and the first matching rule's schema validates the
   * request — patterns are exact (`/hooks/stripe`) or prefix
   * (`/hooks/*`); paths with no match skip validation entirely, so
   * enabling the registry changes nothing for unlisted endpoints. The
   * check runs *after* signature verification and WR-33 version
   * adaptation (so a v1 payload reshaped into the current schema
   * validates against the current schema) and *before* the replay guard
   * and dedup. A payload that fails validation is answered 400 and
   * audited as `rejected` with reason `schema_failed` — it never enters
   * the queue, so it consumes no retry budget, no breaker trips, and no
   * dedup slots. The schema's name and version ride on `accepted`
   * (`schema` / `schemaVersion`) and `rejected` audit events, so a schema
   * version change is visible in the audit trail; intakes also render in
   * the Prometheus exposition (`relay_inbound_schema_total{schema,status}`).
   * Schemas validate JSON: a non-JSON body fails validation. Off by
   * default. Invalid rules throw `RangeError` at startup.
   *
   * Composes with `versions` (WR-33): when a version route matched, the
   * schema rule is first tried against the endpoint path with the version
   * prefix stripped — one `/hooks/*` rule covers `/v1/hooks/...` and
   * `/v2/hooks/...` alike, since every version adapts into the current
   * schema before validation — then against the full inbound path, so
   * per-version rules (`/v1/admin/*`) still work.
   */
  payloadSchemas?: EndpointSchemaRule[];
  /**
   * Content-based routing (WR-84, see `src/content-routes.ts`): route an
   * inbound webhook to a target endpoint by matching rules against payload
   * JSON fields (`equals` / `contains` / `regex` / `exists` / `range` on
   * dot-path fields, e.g. `"order.type"`). Rules are sorted by `priority`
   * ascending (default 100, stable); the first fully-matching rule wins
   * and its `targetUrl` is the delivery target. When no rule matches,
   * `contentRouteDefault` applies if set, otherwise `forwardUrl`. Routing
   * runs after signature verification and before dedup/enqueue on the
   * canonical payload (decompressed, version-adapted), and it never
   * rejects an event — a non-JSON body or an unmatchable payload just
   * takes the fallback. Rules are hot-swappable via operator
   * `POST /routing/rules` (admin scope). Invalid rules throw `RangeError`
   * at startup. Off by default.
   */
  contentRoutes?: ContentRouteRule[];
  /**
   * Fallback target for content-based routing when no rule matches.
   * Must be a non-empty string when present; `RangeError` at startup.
   */
  contentRouteDefault?: string;
  /**
   * Opt-in active health probing of downstream endpoints (see
   * `src/downstream-probe.ts` and the `probe` `RetryQueue` option): each listed
   * endpoint gets a timed HEAD (or GET) request every `intervalMs` on a
   * lightweight path — no retry queue, no retry budget, no latency
   * samples, no quota — so probes can never disturb a delivery. Each
   * probe outcome is reported to the circuit breaker exactly like a
   * delivery outcome: consecutive probe failures trip the circuit open
   * *early* (before real deliveries have to fail), a success resets the
   * counter. Outcomes are audited as `probe_failed` (every failure, with
   * the streak) / `probe_recovered` (when a failing endpoint answers
   * again) and counted in the Prometheus exposition (`relay_probe_*`).
   * Off by default.
   */
  probe?: ProbeOptions;
  /**
   * OTLP/HTTP JSON delivery-event export (WR-83; see `src/otlp.ts` and
   * the `otlp` `RetryQueue` option): exports the `delivered` /
   * `retrying` / `dead_letter` delivery events plus `slo_missed`
   * latency events to a configurable collector endpoint as OTLP logs
   * JSON. An explicit server-level `otlp` wins over the nested
   * `retry.otlp`. Off by default.
   */
  otlp?: OtlpExporterOptions;
  /**
   * WR-85: shadow-target dry-run mirroring (see `src/shadow.ts`): the
   * downstream-migration / contract-verification scenario. Per-endpoint
   * opt-in — exact `forwardUrl`/endpoint `targetUrl` -> shadow target
   * list. After every main delivery attempt completes (success or
   * failure), the relay asynchronously mirrors the identical wire
   * request (same payload, `x-relay-signature` / `x-relay-key-id`,
   * `x-relay-idempotency-key`, compression encoding) to each shadow
   * target. Each target is served by an independent sender copy built
   * with the same wire config as the main sender — same signing secret,
   * idempotency-key secret, and compression — but its own keep-alive
   * pools and its own pinning/mTLS identity (`tlsPins` /
   * `tlsClientCert` per target). Shadow outcomes are only *observed*:
   * audited as `shadow_delivered` / `shadow_failed` and counted in
   * `relay_shadow_total{endpoint,shadow_target,result}` — they never
   * trigger a main retry, never dead-letter, never trip the circuit
   * breaker, never consume a quota token, and never pollute the main
   * delivery counters; a shadow failure is silent (recorded, not
   * retried). An explicit server-level `shadowTargets` wins over the
   * nested `retry.shadowTargets` (which takes raw queue-level
   * `ShadowTargetConfig` entries with pre-built senders). Off by
   * default; invalid values throw `RangeError` at startup.
   */
  shadowTargets?: Record<string, ShadowTargetServerConfig[]>;
  /**
   * Outbound TLS certificate pinning (see `src/pinning.ts`): per-endpoint
   * SPKI fingerprint whitelist, keyed by exact delivery `targetUrl`.
   * When pins are configured for an endpoint, the pin check *replaces* the
   * default PKI chain verification for that endpoint — the pin is the trust
   * anchor, which is what stops a MITM holding a valid-but-unexpected
   * certificate. The peer certificate is verified on the socket's
   * `secureConnect` before a single payload byte is written, so a mismatch
   * cannot even observe the request body. A mismatch fails the delivery
   * attempt (`TlsPinMismatchError`); the attempt then follows the normal
   * retry / dead-letter path and the mismatch is visible in the audit
   * trail (`dead_letter` with the pin error). Endpoints without pins keep
   * the default Node TLS verification. Pin format: `"sha256/<base64>"`,
   * `"sha256:<base64>"`, or bare base64 of the 32-byte digest. Empty
   * whitelists and malformed pins throw `RangeError` at startup.
   */
  tlsPins?: Record<string, string[]>;
  /**
   * Outbound mTLS client certificates (see `src/mtls.ts`): per-endpoint
   * client identity, keyed by exact delivery `targetUrl`. Each entry is a
   * `{ cert, key, passphrase? }` triple of PEM *strings* held in memory —
   * no file paths, so rotation is a config change. During the TLS
   * handshake the relay presents this certificate, proving to the
   * downstream that the request comes from this relay (the downstream
   * verifies it, typically with `requestCert: true` and its own CA list).
   * Off by default: endpoints without an entry send no client certificate.
   * Composes with `tlsPins` (pins verify the server, the client cert
   * proves the relay) and with the keep-alive pool (agents are keyed per
   * `(origin, cert)`, so a connection authenticated as one identity never
   * serves an endpoint with a different one; a failed handshake's socket
   * is destroyed and never reused). Invalid values throw `RangeError` at
   * startup.
   */
  tlsClientCerts?: Record<string, TlsClientCert>;
  /**
   * Outbound per-endpoint TLS minimum version (WR-74, see
   * `src/tls-version.ts`): `{ "<exact targetUrl>": "1.2" | "1.3" }`,
   * keyed by exact delivery `targetUrl`. The floor is enforced
   * observationally: the handshake runs at whatever the downstream
   * negotiates and the negotiated version is compared against the floor
   * on the socket's `secureConnect`, *before* a single payload byte is
   * written. A negotiation below the floor destroys the request with
   * `TlsVersionRejectedError`; the attempt follows the normal retry /
   * dead-letter path and the rejection is audited (`tls_version_rejected`)
   * plus counted in `relay_tls_version_rejections_total{endpoint,version}`.
   * Endpoints without an entry keep the exact historical behavior (Node
   * defaults, minimum TLS 1.2) — `"1.2"` is the default floor and needs
   * no entry. Orthogonal to `tlsClientCerts` (WR-36, client identity)
   * and the WR-73 cert-expiry monitor (warns about expiry; this rejects
   * weak negotiation). The keep-alive pool and the HTTP/2 session pool
   * bind the floor into their keys, so a connection handshaked under one
   * floor can never serve an endpoint configured with another. `wss:`
   * targets are not covered in this round — the WebSocket pool owns its
   * own handshake (see README). Invalid values throw `RangeError` at
   * startup.
   */
  minTlsVersions?: Record<string, MinTlsVersion>;
  /**
   * Per-endpoint outbound TLS SNI/ALPN overrides (WR-60, see
   * `src/tls-sni.ts`): `{ "<exact targetUrl>": { servername?,
   * alpnProtocols? } }`. `servername` is the SNI name sent in the TLS
   * ClientHello and defaults to the target URL's host — set it explicitly
   * for CDN / multi-tenant-fronting setups, either to present the real
   * service name to the front or to keep the default SNI from leaking the
   * real backend host. `alpnProtocols` is the ALPN offer in preference
   * order and defaults to `["h2", "http/1.1"]`. Endpoints without an entry
   * keep the exact current behavior (no `servername`/`ALPNProtocols` set —
   * Node's defaults apply untouched). The override changes only the
   * SNI/ALPN wire values: certificate verification still anchors on the
   * target URL's host (or the `tlsPins` whitelist), and the keep-alive
   * pool plus the H2 session pool key connections by the effective TLS
   * identity, so a connection handshaked with one SNI can never serve an
   * endpoint configured with a different one. Composes with `tlsPins`
   * (the pin is verified on the overridden-SNI connection),
   * `tlsClientCerts` (the client certificate rides the same handshake),
   * the H2 pool, and proxied endpoints (the handshake runs over the
   * CONNECT tunnel). Applies to `https:` targets; entry keys for other
   * schemes, empty servernames, IP-literal servernames, and
   * empty/malformed `alpnProtocols` throw `RangeError` at startup.
   */
  tlsSniOverrides?: Record<string, TlsSniOverride>;
  /**
   * Downstream + own TLS certificate expiry warning (WR-73, see
   * `src/cert-expiry.ts`): `{ enabled: true, thresholdSeconds? }`. When
   * enabled, every `https:`/`wss:` handshake feeds the peer certificate's
   * `notAfter` into the monitor — reusing the `getPeerCertificate` read
   * the WR-21 pin check performs, across the keep-alive pool, proxied
   * CONNECT tunnels, the H2 session pool, and the WebSocket pool — and a
   * certificate expiring within `thresholdSeconds` (default 14 days)
   * fires one edge-triggered `cert_expiring` audit event per
   * certificate (not per handshake) plus a
   * `relay_cert_expiry_seconds{endpoint,kind}` gauge in `GET /metrics`
   * (`kind` = `downstream` for the peer, `client` for the relay's own
   * mTLS client certificates, which are checked at config load). Off by
   * default: an unconfigured relay behaves exactly as before. Invalid
   * values throw `RangeError` at startup.
   */
  tlsCertExpiry?: CertExpiryOptions;
  /**
   * Outbound gzip compression (see `src/gzip.ts`): per-endpoint opt-in,
   * keyed by exact delivery `targetUrl`. When the payload reaches
   * `thresholdBytes` (default 1024) it is gzipped, `Content-Encoding:
   * gzip` is stamped, and `Content-Length` reflects the compressed size;
   * payloads that do not shrink are sent as-is. The relay signature
   * (`x-relay-signature`) covers the compressed wire bytes. Inbound,
   * webhooks posted with `Content-Encoding: gzip` are transparently
   * decompressed after signature verification (which covers the raw wire
   * bytes the sender signed) — decompression is streaming and capped at
   * `maxBodyBytes`, so a gzip bomb is answered 413 like any oversized
   * body. Invalid values throw `RangeError` at startup.
   */
  compressOutbound?: Record<string, CompressOutboundOptions>;
  /**
   * Guarded outbound gzip compression (WR-75, see `src/gzip.ts`):
   * per-endpoint opt-in, keyed by exact delivery `targetUrl`. Beyond the
   * WR-40 threshold behavior this adds a content-type whitelist (default
   * `application/json` — batch envelopes and relay payloads are JSON by
   * contract) and a self-healing fallback: when a guarded-compressed
   * delivery is answered 415, the sender resends it once as plaintext
   * inside the same delivery attempt (no retry budget consumed, no
   * circuit event). Compressed bytes saved per endpoint are counted in
   * `relay_compressed_bytes_saved_total`. When both `compressOutbound`
   * and `compressThreshold` configure an endpoint, the guarded path
   * wins. Applies to the HTTP/1.1 and HTTP/2 delivery paths only —
   * WebSocket deliveries keep their RFC 7692 permessage-deflate story
   * (`src/deflate.ts`). Invalid values throw `RangeError` at startup.
   */
  compressThreshold?: Record<string, GuardedCompressOptions>;
  /**
   * Outbound response compression negotiation (WR-62, see
   * `src/response-encoding.ts`): per-endpoint opt-in, keyed by exact
   * delivery `targetUrl`. An opted-in endpoint advertises
   * `Accept-Encoding: gzip, deflate, br` (overridable per endpoint), and
   * a compressed downstream response is transparently decoded *before*
   * the WR-37 responseValidator and the audit summary see the body — a
   * validator written against the downstream's plain JSON keeps working
   * whether the downstream compressed or not. Every decode stage is
   * hard-capped at `maxDecompressedBytes` (default 64 KiB, the sender's
   * response capture cap), so a compression bomb fails the attempt
   * (retryable) instead of blowing up the process; a downstream that
   * ignores `Accept-Encoding` (or answers an unknown coding) is passed
   * through untouched — negotiation never loses a delivery. Applies to
   * the HTTP/1.1 and HTTP/2 delivery paths; endpoints without an entry
   * keep the exact current behavior. Invalid values throw `RangeError`
   * at startup.
   */
  responseCompression?: Record<string, ResponseCompressionOptions>;
  /**
   * Outbound request header forwarding allowlist (WR-69; see
   * `src/forward-headers.ts`): per-endpoint (exact `targetUrl`) gate on
   * the inbound passthrough headers forwarded downstream. Rules carry
   * `allow` / `deny` header-name pattern lists (strings compiled as
   * case-insensitive regexes, or `RegExp`); `deny` wins over `allow`, and
   * `authorization` / `cookie` are never forwarded by default — an
   * explicit allow can re-enable them for an endpoint, never an
   * explicit deny. The relay's own forced headers (`x-trace-id`,
   * `x-relay-signature` / `x-relay-key-id`, the WR-44 idempotency key,
   * encodings) are stamped after the gate and always survive. Endpoints
   * without a rule keep the exact current pass-through behavior.
   * Invalid rules throw `RangeError` at startup.
   */
  forwardHeaders?: Record<string, ForwardHeadersRuleConfig>;
  /**
   * Outbound keep-alive connection pool (see `src/keepalive.ts`): outbound
   * deliveries reuse TCP/TLS connections per `(scheme, host, port)` instead
   * of paying a handshake per attempt. Enabled by default with sane limits
   * (`maxSocketsPerHost: 64`, idle reaping after 30s); pass `false` to
   * disable pooling entirely (one fresh connection per delivery, the legacy
   * behavior), or tune with `KeepAlivePoolOptions`. Endpoints with a TLS pin
   * whitelist get a dedicated agent per pin set, so a connection pinned for
   * one whitelist can never serve an endpoint with a different one; the
   * pin is still verified on `secureConnect` for every new connection.
   * Endpoints with an mTLS client identity (`tlsClientCerts`) likewise get
   * a dedicated agent per `(origin, cert)`, so a connection authenticated
   * as one identity can never serve an endpoint configured with a
   * different one. Pooled connections are closed when the server closes
   * (`stop()`/`shutdown()` path), and idle sockets are unref'd so a
   * forgotten pool never pins process exit. Invalid option values throw
   * `RangeError` at startup.
   */
  outboundKeepAlive?: KeepAlivePoolOptions | false;
  /**
   * Outbound connection warm-up (WR-70, see `src/warmup.ts`): at startup,
   * pre-establish keep-alive connections for the listed endpoint URLs on
   * top of the WR-24 pool, so the first deliveries to those origins skip
   * the TCP/TLS handshake. The warm-up resolves the exact pool agent the
   * delivery path would use (per pin whitelist, proxy, mTLS identity, and
   * TLS SNI override), opens `socketsPerOrigin` sockets per origin
   * (default 1) through the agent's own connection funnel, and parks
   * them idle — no application bytes are ever sent. TLS pins are verified
   * against the endpoint's whitelist during warm-up (a mismatch fails
   * that endpoint's warm-up); the verified fingerprint is cached on the
   * pooled socket, which the pool's health probe requires before handing
   * a pinned socket to a delivery.
   *
   * Warm-up is fire-and-forget: it never blocks or fails startup. Each
   * endpoint failure is audited as `warmup_failed` (endpoint + error) and
   * a summary as `warmup_completed`; a failed warm-up only means the
   * first delivery pays the handshake it would have paid anyway. Applies
   * only when the server owns the default sender (an injected `sender`
   * or `outboundKeepAlive: false` means there is no pool to warm — the
   * option is then a silent no-op). `http:`/`https:` targets only;
   * anything else is reported as a per-endpoint failure. Invalid option
   * shapes throw `RangeError` at startup; invalid URLs inside the list do
   * not — they are per-endpoint `warmup_failed` audits.
   */
  warmup?: {
    endpoints: string[];
    timeoutMs?: number;
    concurrency?: number;
    socketsPerOrigin?: number;
  };
  /**
   * Outbound HTTP/2 session reuse (see `src/http2.ts`): on top of the
   * keep-alive pool, per-origin H2 sessions multiplex high-concurrency
   * deliveries over a single connection. Opt-in per host —
   * `{ enabled: true, hosts: ["relay.example.com"] }` — and off by default,
   * so existing deployments keep their exact current behavior. `http:`
   * targets use h2c; `https:` targets use TLS with the same WR-21 pinning
   * trust-anchor semantics and WR-36 client certificates as the HTTP/1.1
   * path (sessions are keyed per origin + pin set + client identity). A
   * failed or refused H2 session falls back to the HTTP/1.1 keep-alive
   * pool — a delivery is never lost because of H2 — and the origin sits
   * out H2 for `fallbackCooldownMs` (default 30s). H2 is bypassed for
   * proxied endpoints: proxy traffic rides the HTTP/1.1 CONNECT tunnel.
   * Invalid values throw `RangeError` at startup.
   */
  outboundHttp2?: Http2PoolOptions;
  /**
   * Outbound HTTP(S) proxy (see `src/proxy.ts`): per-endpoint proxy URLs,
   * keyed by exact delivery `targetUrl`. Deliveries to a configured
   * endpoint ride a `CONNECT` tunnel through the proxy — proxy basic-auth
   * credentials come from the proxy URL's userinfo
   * (`http://user:pass@proxy:8080`); only plain-HTTP proxies are
   * supported (proxy-over-TLS is rejected). Endpoints without an explicit
   * entry fall back to the environment (`HTTPS_PROXY` / `HTTP_PROXY` /
   * `ALL_PROXY`, lowercase variants honored, `NO_PROXY` bypasses), read
   * per delivery so proxy rotation needs no restart. Tunneled sockets join
   * the keep-alive pool keyed per (proxy, origin, pins), so one CONNECT
   * serves many deliveries; with pooling disabled each delivery opens its
   * own tunnel. For `https:` targets the TLS handshake runs over the
   * tunnel, so end-to-end encryption and `tlsPins` verification behave
   * exactly as without a proxy — the proxy sees only the CONNECT line,
   * never the payload. Invalid URLs throw `RangeError` at startup.
   */
  proxies?: Record<string, string>;
  /**
   * Inbound request body size limit (WR-25). A POST whose body exceeds this
   * is answered 413 and audited as `rejected` (reason `body_too_large`):
   * the declared `content-length` is checked before a single body byte is
   * read, and chunked or lying bodies are capped while streaming, so a
   * flood of giant payloads costs us almost nothing. Default: 1 MiB
   * (`DEFAULT_MAX_BODY_BYTES`). Invalid values throw `RangeError`.
   */
  maxBodyBytes?: number;
  /**
   * Outbound request signing (WR-26, see `OutboundSigningConfig`): when set,
   * every delivery made by the default sender carries
   * `x-relay-signature: sha256=<hex>` — the HMAC-SHA256 of the forwarded
   * body — plus `x-relay-key-id` when `keyId` is given, so the downstream
   * can prove the request really came from this relay (verify with
   * `verifySignature(body, header, secret)` from `src/verify.ts`). Off by
   * default; applies to the default sender only — an injected `sender`
   * signs (or doesn't) on its own. Inbound `x-relay-signature` /
   * `x-relay-key-id` headers are always stripped from the forwarded header
   * set, so a sender can never smuggle a forged relay signature
   * downstream. Invalid values throw `RangeError`.
   */
  outboundSigning?: OutboundSigningConfig;
  /**
   * Per-endpoint outbound end-to-end encryption (WR-58, see
   * `OutboundEncryptionConfig` and `src/e2ee.ts`): `{ "<exact targetUrl>":
   * { publicKey } }`, where `publicKey` is the downstream's base64 X25519
   * public key. Sealed deliveries carry
   * `x-relay-encryption: x25519-hkdf-sha256/aes-256-gcm` and the
   * `x-relay-signature` (WR-26) still covers the ciphertext wire bytes.
   * Off by default; applies to the default sender only. Invalid values
   * throw `RangeError`.
   */
  outboundEncryption?: Record<string, OutboundEncryptionConfig>;
  /**
   * Outbound idempotency-key stamping (WR-44, see `IdempotencyKeyOptions`
   * in `src/idempotency-key.ts`): when `enabled`, every delivery made by
   * the default sender carries `x-relay-idempotency-key` — the
   * HMAC-SHA256 of `(event id, attempt)` under the configured `secret`,
   * prefixed with `keyPrefix` — so the downstream can dedupe retries
   * and dead-letter replays on it (same attempt → same key; a replay
   * restarts at attempt 1 and reproduces the original keys; batch
   * deliveries key off the `batch_id`). Off by default; applies to the
   * default sender only — an injected `sender` stamps (or doesn't) on
   * its own. An inbound `x-relay-idempotency-key` is always stripped, so
   * a sender can never smuggle a forged relay-derived key downstream.
   * Invalid values throw `RangeError`.
   */
  outboundIdempotencyKey?: IdempotencyKeyOptions;
  /**
   * Bearer token guarding the operator endpoints (`GET /dead-letter`,
   * `GET /dead-letter/stats`, `POST /dead-letter/:id/replay`,
   * `POST /dead-letter/replay`, the `/dead-letter/auto-replay/*`
   * controls, `GET /audit`, `GET /latency`, `GET /events`,
   * `GET /metrics`, `GET /deliveries/:traceId`). When unset, those
   * endpoints are disabled and answer 404 (fail closed).
   */
  operatorToken?: string;
  /**
   * Scoped operator API keys (WR-82; see `src/operator-keys.ts`): upgrades
   * `operatorToken` to a key ring of `{ id, key, scopes? }` entries, where
   * `scopes` is drawn from exactly two case-sensitive scopes — `read`
   * (all read-only operator paths: `GET /metrics`, `GET /audit`,
   * `GET /audit/verify`, `GET /latency`, `GET /slo-risk`, `GET /usage`,
   * `GET /events`, `GET /events/archive`, `GET /deliveries/:traceId`,
   * `GET /dead-letter`, `GET /dead-letter/stats`,
   * `GET /dead-letter/auto-replay/status`, `GET /scheduled`) and `admin`
   * (everything `read` covers plus every mutating operator path:
   * dead-letter replays, auto-replay pause/resume/trigger,
   * `POST /config/endpoint`, endpoint pause/resume, schedule
   * pause/resume). The legacy `operatorToken` keeps working with full
   * `admin` semantics when set; when both are configured, either
   * authenticates. An entry with no `scopes` (or an empty array) is
   * fail-closed: it authenticates but every operator path answers 403.
   * Every operator call's audit event carries the key's `keyId` (the
   * legacy token audits as `"legacy"`). When neither `operatorToken` nor
   * `operatorKeys` is configured, the operator endpoints stay disabled
   * and answer 404 (fail closed). Invalid entries (bad scope, empty
   * id/key, duplicate id, duplicate key) throw `RangeError` at startup.
   */
  operatorKeys?: OperatorKeyEntry[];
  /**
   * Operator/intake plane split (WR-56, see `OperatorPortOptions`): serve
   * the operator endpoints on a second listener bound by the relay itself
   * (default host `127.0.0.1`) while the intake plane keeps accepting
   * webhooks on the caller-bound port. Cross-plane requests answer 404
   * without revealing the other plane. Unset by default: a single
   * listener serves both planes, exactly the legacy behavior. Invalid
   * values throw `RangeError` at startup.
   */
  operatorPort?: OperatorPortOptions;
  /**
   * Opt-in dead-letter auto-replay scheduler (see `src/autoreplay.ts` and
   * the `autoReplay` `RetryQueue` option): timed rounds that replay the
   * whole dead-letter list with the same fresh-budget semantics as the
   * manual `POST /dead-letter/replay`. Exponential backoff between
   * consecutive empty rounds (`intervalMs * 2^n`, capped by
   * `maxIntervalMs`); after `maxRounds` consecutive empty rounds the
   * scheduler stops permanently and audits `dead_letter_auto_replay`.
   * Controlled at runtime by `POST /dead-letter/auto-replay/pause`,
   * `/resume`, `/trigger` and observed via
   * `GET /dead-letter/auto-replay/status`. Off by default — manual replay
   * is the only behavior unless the operator opts in.
   */
  autoReplay?: AutoReplayOptions;
  /**
   * Dead-letter retention TTL (WR-64; see `src/deadletter-retention.ts`
   * and the `deadLetterRetention` `RetryQueue` option): per-endpoint
   * opt-in TTL in ms after which dead letters are auto-purged by a
   * background sweep, auditing each purge as `dead_letter_purged`
   * (`id`/`endpoint`/`attempts`/`deadLetteredAt` — never the payload).
   * Purges skip entries claimed by an in-progress WR-23 batch replay or
   * WR-31 auto-replay round, and are journaled when the durable queue is
   * on, so a purged entry never resurrects after a restart. Off by
   * default — dead letters live until replayed manually. Invalid values
   * throw `RangeError` at startup. Stats are served at
   * `GET /dead-letter/stats`.
   */
  deadLetterRetention?: DeadLetterRetentionOptions;
  /**
   * Dead-letter replay egress throttle (WR-68; see
   * `src/replay-egress.ts` and the `replayEgress` `RetryQueue` option):
   * opt-in per-endpoint RPS cap on the *re-queue* admission shared by
   * manual `replayDeadLetters`, operator `POST /dead-letter/replay`, and
   * WR-31 auto-replay rounds. Entries held back stay dead-lettered
   * (nothing dropped) and are reported in the batch result's `throttled`
   * field plus the cumulative `throttled` counter on
   * `GET /dead-letter/stats`. Off by default — replays admit
   * immediately. Invalid values throw `RangeError` at startup.
   */
  replayEgress?: ReplayEgressOptions;
  /**
   * Delivery completion callbacks (WR-47; see `src/callback.ts`). Opt-in:
   * when a delivery reaches a terminal state (`delivered` or
   * `dead_letter`), the relay POSTs a signed receipt (traceId,
   * `x-relay-idempotency-key`, `x-relay-signature`) to the caller's URL —
   * the active counterpart to the passive `GET /deliveries/:traceId`
   * query. Exhausted receipts are audited as `callback_failed` and never
   * enter the retry queue or the dead-letter list. Off by default.
   */
  completionCallback?: CompletionCallbackOptions;
  /**
   * Replay protection for inbound webhooks. When set, each accepted POST must
   * carry a unique `x-nonce` header: a nonce seen inside the guard's window is
   * rejected with 409 (`duplicate_nonce`), a missing nonce or an `x-timestamp`
   * (unix seconds) outside the window is rejected with 400. Rejections are
   * audited as `rejected` with the guard's reason. Off by default, so
   * unsigned-legacy senders keep working unless the operator opts in.
   */
  replay?: ReplayGuard;
  /**
   * Idempotent delivery dedup (see `src/dedup.ts`). When set, an inbound
   * POST whose (endpoint, payload-hash) pair was already accepted inside
   * `windowMs` is answered 202 with `duplicate: true` and never delivered —
   * the suppression is audited as `duplicate_suppressed`. This is the
   * payment-callback guard: an upstream retry of the same event cannot
   * trigger a duplicate business action. 202, not 409: upstream should
   * treat the event as handled. Off by default, so identical payloads keep
   * the legacy always-deliver behavior unless the operator opts in.
   */
  dedup?: DedupOptions;
  /**
   * Tenant-level usage metering for usage-based billing (WR-78, see
   * `src/usage.ts`). When set, every accepted webhook records `bytes_in`
   * (and the urgent fast-lane admission) per tenant at intake, and every
   * queue delivery event records `delivered` / `retried` / `failed` /
   * `dead_letter` plus `bytes_out` per tenant. Read back via the operator
   * `GET /usage` endpoint (`?tenant=` filter) and the Prometheus
   * exposition (`relay_tenant_deliveries_total{tenant,outcome}` and
   * friends). Requests without `x-tenant-id` bill to the `default`
   * tenant. The meter never gates, delays, or drops anything — it is
   * orthogonal to the delivery quota (WR-15), which is the protective
   * gate. Off by default; the `/usage` endpoint 404s when unconfigured.
   */
  usage?: UsageOptions;
  /**
   * Inbound IP allowlist/denylist (WR-53, see `src/ip-acl.ts`):
   * per-endpoint CIDR gates on the sender's IP — the outermost admission
   * check. Rules match the inbound request path (exact `/hooks/stripe` or
   * prefix `/hooks/*`, first match wins, same semantics as WR-29 endpoint
   * verifiers); each rule carries either an `allow` or a `deny` list of
   * IPv4/IPv6 CIDRs (never both — configuring both is a `RangeError` at
   * startup). A deny-list hit rejects; in allow mode an IP outside every
   * allow range rejects; paths with no matching rule skip the check
   * entirely. The check runs before the body is read, before WR-22 rate
   * limiting, and before signature verification, so a hostile IP costs
   * zero bandwidth and zero downstream state — a denial never enqueues,
   * so it burns no retry budget and never trips the breaker. Denials are
   * answered 403 (with `connection: close`, so the client cannot keep
   * streaming a flood into a dead request), audited as `rejected` with
   * reason `ip_denied`, and counted in the Prometheus exposition
   * (`relay_inbound_ip_denied_total{endpoint}`).
   *
   * Client IP resolution honors `x-forwarded-for` only through
   * `trustedProxies` (CIDR list of known reverse proxies): when the
   * direct socket peer is a trusted proxy, the chain is stripped from the
   * right and the leftmost untrusted hop becomes the client IP. The
   * default (no trusted proxies) trusts only the direct socket peer — a
   * spoofed `x-forwarded-for` from an untrusted client is ignored, never
   * honored. An unparseable peer IP on a guarded endpoint is denied (fail
   * closed). Off by default: with no `rules`, intake behavior is exactly
   * the legacy one. Invalid CIDRs throw `RangeError` at startup.
   */
  ipAcl?: IpAclOptions;
  /**
   * Inbound per-endpoint API key authentication (WR-65, see
   * `src/api-key.ts`): a bearer-key admission gate for senders that
   * cannot do HMAC — the shared secret travels in the `x-api-key`
   * header and is compared in constant time (`crypto.timingSafeEqual`)
   * against the endpoint's key set. Rules match the inbound request path
   * (exact `/hooks/legacy` or prefix `/hooks/*`, first match wins, same
   * semantics as WR-29 endpoint verifiers and the WR-53 IP ACL); each
   * rule lists one or more `{ id, key }` entries — several keys coexist
   * so rotation is overlap-safe (deploy the new key alongside the old,
   * cut the sender over, then remove the old entry). The check runs in
   * the intake gates before the body is read (right after the WR-53 IP
   * ACL, before the WR-63 baseline and WR-22 rate limiting), so an
   * unauthenticated caller costs zero bandwidth and zero downstream
   * state: a missing or non-matching key is answered 401
   * (`connection: close`) and audited as `rejected` with reason
   * `api_key_missing` / `api_key_invalid` (and `keyId: "unknown"`) — it
   * never enqueues, burns no retry budget, and never trips the breaker.
   * `accepted` audit events carry the matched `keyId`.
   *
   * Orthogonal to signature verification: by default
   * (`requireSignature` unset/false) the API key alone authenticates the
   * endpoint — the signature check is skipped for requests that passed
   * the key gate, so endpoints whose senders cannot sign keep working.
   * Set `requireSignature: true` on the rule to demand BOTH the key and
   * a valid signature (the normal global/per-endpoint verifier check
   * still runs in the admission pipeline); when both factors are in
   * play, the accepted audit's `keyId` names the API key (the admission
   * credential). Endpoints with no matching rule are untouched —
   * signature behavior there is exactly the legacy one. `x-api-key` is
   * the caller's inbound credential, not part of the event: it is
   * stripped from the headers forwarded downstream. Off by default: with
   * no `rules`, intake behavior is exactly the legacy one. Invalid rules
   * (empty key list, empty id/key, duplicate key ids, bad pattern) throw
   * `RangeError` at startup.
   */
  apiKeys?: ApiKeyOptions;
  /**
   * Inbound source baseline anomaly detection (WR-63; see
   * `src/source-baseline.ts`): opt-in per-endpoint learning of the sender
   * baseline — (source IP, approximate TLS fingerprint) triples, the
   * fingerprint being `"plain"` for the normal plain-HTTP listener or
   * `${tlsProtocol}:${cipherName}` when the socket looks like a
   * `tls.TLSSocket`. The first sighting of a triple learns the baseline
   * silently; a later new triple on a guarded endpoint is audited as
   * `source_anomaly` — alert-only, never blocks: the request continues
   * through the remaining gates and is delivered exactly as before, so
   * this is orthogonal to the WR-53 IP ACL (which *rejects*). The check
   * runs on headers alone, before the body is read, and after the IP ACL
   * — a denied IP returns before the check, so blocked senders never
   * teach the baseline. The source IP is the WR-53 `clientIp` when an IP
   * ACL is configured (honoring `x-forwarded-for` through trusted
   * proxies), otherwise the direct socket peer. Baselines live in memory
   * by default; set `dir` for append-only JSONL persistence across
   * restarts (best-effort: a full disk degrades to memory-only, never
   * fails intake). Off by default; invalid config throws `RangeError` at
   * startup.
   */
  sourceBaseline?: SourceBaselineOptions;
  /**
   * Inbound rate limiting (see `src/ratelimit.ts`): dual-dimension token
   * buckets — per-sender IP and per-endpoint — guarding the webhook intake.
   * A request exceeding either budget is answered 429 with a `retry-after`
   * header and audited as `rejected` with reason `rate_limited` (plus the
   * `dimension`: `"ip"` or `"endpoint"`). The check runs before signature
   * verification, so a flood of invalid requests still costs almost
   * nothing. Disabled by default.
   */
  rateLimit?: InboundRateLimitOptions;
  /** Inject queue hooks (e.g. to fail the server fast on dead letters). */
  /**
   * Seals dead-letter payloads at rest (see `RetryQueue` `payloadEncryptor`;
   * default AES-256-GCM via `node:crypto`, zero dependencies). Pair with
   * `new AuditLog(path, { payloadEncryptor })` to also seal payloads
   * written to the audit log.
   */
  payloadEncryptor?: PayloadEncryptor;
  /**
   * Attach the raw request body to `accepted` audit events. Off by default;
   * when enabled, construct the `AuditLog` with a `payloadEncryptor` unless
   * plaintext webhook bodies on disk are acceptable.
   */
  auditPayloads?: boolean;
  /**
   * WR-72: field-level masking for audit payloads (see `src/masking.ts`):
   * opt-in per-endpoint rules like `card_number → ****1234`. The one mask
   * backs both the audit log (`payload` fields, masked before the WR-11
   * encryptor seals them) and the retry queue (the WR-54
   * `responseBodyCapture` body, masked before sealing). Raw values never
   * reach disk — masked or not, `bodyFingerprintSha256` still covers the
   * original bytes. Unset by default: payloads are stored as received.
   */
  fieldMask?: FieldMask;
  /**
   * Durable delivery queue (WR-49; see `src/durable-queue.ts`). Opt-in:
   * pending and backoff-waiting deliveries plus the dead-letter list are
   * journaled to `<dir>/queue.jsonl` and restored on restart — retries
   * resume with their remaining backoff, consumed attempts are preserved,
   * and a `queue_restored` audit event records what came back. Payloads
   * are sealed with `payloadEncryptor` when one is configured. Wins over
   * `retry.durableQueueDir` when both are set.
   */
  durableQueueDir?: string;
  /**
   * Live delivery-event stream (`GET /events`, Server-Sent Events). Emits
   * `delivered` / `retrying` / `dead_letter` frames as JSON
   * (`event: delivery`) in real time, so an operator can watch the delivery
   * flow without polling. A `: ping` heartbeat comment goes out every
   * `heartbeatMs` (default 15_000) to keep idle connections alive; the
   * interval is unref'd so it never pins the process. A subscriber whose
   * kernel buffer exceeds 1 MiB is disconnected instead of buffering
   * without bound. The stream is live-only — no replay of past events; use
   * `GET /audit` for history. Like the other operator endpoints, it answers
   * 404 when no `operatorToken` is configured.
   */
  events?: { heartbeatMs?: number };
  /**
   * Persistent delivery-event archive (WR-55; see `src/event-archive.ts`).
   * Opt-in: subscribes to the queue's delivery events and appends every
   * `delivered` / `retrying` / `dead_letter` event as JSONL to
   * `<dir>/events.jsonl`, surviving process restarts and queryable via
   * `GET /events/archive` (same `operatorToken` bearer auth; 404
   * fail-closed when this option is unset, so an unconfigured archive
   * leaks no existence). `maxAgeMs` / `maxBytes` enable rolling retention
   * (oldest-first eviction, at-least-once crash semantics documented in
   * `src/event-archive.ts`). Complements the live `GET /events` SSE stream
   * (real-time, memory-only, no replay) and is decoupled from the audit
   * log: audit records operator actions, the archive records the delivery
   * event stream.
   */
  eventArchive?: { dir: string; maxAgeMs?: number; maxBytes?: number };
  /**
   * Opt-in graceful shutdown on SIGTERM/SIGINT: stop accepting new
   * connections, wait up to `timeoutMs` (default 30_000) for in-flight
   * deliveries to settle, then exit the process (0 = drained, 1 = drain
   * timeout). `exit` overrides `process.exit` — an escape hatch for
   * embedding the server or asserting the shutdown path in tests.
   * Off by default so the server stays a pure library component.
   */
  gracefulShutdown?: { timeoutMs?: number; exit?: (code: number) => void };
}

/**
 * The default delivery function: a `node:http(s)` POST of the item's
 * payload and headers. Exported so tests (and embedders) can exercise the
 * exact outbound path, including TLS pinning.
 *
 * `tlsPins` is the per-endpoint SPKI whitelist (see the `tlsPins` server
 * option); it is validated once, up front.
 *
 * `keepAlive` controls the outbound connection pool (see
 * `src/keepalive.ts` and the `outboundKeepAlive` server option): by default
 * deliveries reuse keep-alive connections per `(scheme, host, port)`;
 * pass `false` for one fresh connection per delivery (the legacy
 * behavior). The returned sender carries its pool as `.pool` and closes
 * it via `.destroy()` (a no-op when pooling is disabled).
 *
 * `outboundSigning` (see `OutboundSigningConfig`) makes every outbound
 * request carry `x-relay-signature: sha256=<hex>` (HMAC-SHA256 of the
 * forwarded body) plus `x-relay-key-id` when a `keyId` is given, so the
 * downstream can prove the request really came from this relay. Invalid
 * values throw `RangeError` at startup.
 *
 * `proxies` is the per-endpoint outbound proxy map (see `src/proxy.ts` and
 * the `proxies` server option): `{ "<exact targetUrl>": "<proxyUrl>" }`.
 * Deliveries to a configured endpoint ride a `CONNECT` tunnel through the
 * proxy; endpoints without an entry fall back to `HTTPS_PROXY` /
 * `HTTP_PROXY` / `ALL_PROXY` (lowercase honored, `NO_PROXY` bypasses the
 * env fallback only — an explicit entry always wins), read per delivery.
 * Invalid proxy URLs throw `RangeError` at startup.
 *
 * `tlsClientCerts` is the per-endpoint mTLS client identity (see
 * `src/mtls.ts` and the `tlsClientCerts` server option):
 * `{ "<exact targetUrl>": { cert, key, passphrase? } }`, PEM strings held
 * in memory. The relay presents the certificate during the TLS handshake
 * so the downstream can verify the request really comes from this relay.
 * Off by default; composes with `tlsPins` and the keep-alive pool (agents
 * are keyed per `(origin, cert)`). Invalid values throw `RangeError` at
 * startup.
 *
 * `http2` is the opt-in HTTP/2 session pool (see `src/http2.ts` and the
 * `outboundHttp2` server option): `{ enabled: true, hosts: [...] }`.
 * Disabled by default. Invalid values throw `RangeError` at startup. The
 * returned sender carries the pool as `.http2Pool` and closes it via
 * `.destroy()` alongside the keep-alive pool.
 *
 * `idempotencyKey` is the opt-in outbound idempotency key (WR-44, see
 * `src/idempotency-key.ts` and the `outboundIdempotencyKey` server
 * option): `{ enabled: true, secret, keyPrefix? }`. When enabled, every
 * outbound request carries `x-relay-idempotency-key` — the HMAC-SHA256
 * of `(event id, attempt)` under `secret`, prefixed with `keyPrefix` —
 * so the downstream can dedupe retries and dead-letter replays on it.
 * Off by default. Invalid values throw `RangeError` at startup.
 *
 * `websocket` tunes the WebSocket downstream path (WR-45, see
 * `src/websocket.ts`): `{ timeoutMs?, maxMessageBytes?, pingIntervalMs?,
 * idleTimeoutMs?, permessageDeflate? }`. The pool itself is always created
 * — a `ws:`/`wss:` target just works — the options only tune timeouts,
 * caps, and the opt-in permessage-deflate extension (WR-46, see
 * `src/deflate.ts`). Invalid values throw `RangeError` at startup. The
 * returned sender carries the pool as `.wsPool` and closes it via
 * `.destroy()` alongside the other pools.
 *
 * `outboundEncryption` is the per-endpoint end-to-end encryption map (WR-58,
 * see `OutboundEncryptionConfig` and `src/e2ee.ts`): `{ "<exact targetUrl>":
 * { publicKey } }`. Sealing happens after compression and before signing,
 * so `x-relay-signature` covers the ciphertext wire bytes. Off by default;
 * endpoints without an entry are sent exactly as before. Invalid values
 * throw `RangeError` at startup.
 *
 * `tlsSniOverrides` is the per-endpoint outbound TLS SNI/ALPN override map
 * (WR-60, see `src/tls-sni.ts` and the `tlsSniOverrides` server option):
 * `{ "<exact targetUrl>": { servername?, alpnProtocols? } }`. `servername`
 * defaults to the target URL's host, `alpnProtocols` to `["h2",
 * "http/1.1"]`; endpoints without an entry behave exactly as before.
 * Composes with `tlsPins`, `tlsClientCerts`, the keep-alive pool, the H2
 * pool, and proxied endpoints. Invalid values throw `RangeError` at
 * startup.
 *
 * `certExpiryMonitor` (WR-73, see `src/cert-expiry.ts`) hooks
 * certificate-expiry capture into the TLS handshake paths: every
 * `https:`/`wss:` handshake feeds the peer certificate's `notAfter` into
 * the monitor (the keep-alive pool, proxied CONNECT tunnels, the H2
 * session pool, and the WebSocket pool are all covered), and the relay's
 * own mTLS client certificates are checked at config load here. When
 * omitted — or when the monitor is disabled — the request path is
 * untouched. The monitor is owned by the caller (usually the relay
 * server, which audits `cert_expiring` and renders the
 * `relay_cert_expiry_seconds` gauge).
 */
export interface PooledSender extends Sender {
  /** The keep-alive pool, or `undefined` when pooling is disabled. */
  pool: OutboundConnectionPool | undefined;
  /** The HTTP/2 session pool, or `undefined` when H2 is not enabled. */
  http2Pool: Http2SessionPool | undefined;
  /** The WebSocket connection pool (always created). */
  wsPool: WebSocketPool;
  /**
   * WR-75: cumulative per-endpoint guarded-compression byte savings;
   * rendered into `GET /metrics` as `relay_compressed_bytes_saved_total`.
   */
  compressionStats: OutboundCompressionTracker;
  /** Close all pooled connections and stop the idle reaper. Idempotent. */
  destroy(): void;
}

export function createDefaultSender(
  tlsPins?: Record<string, string[]>,
  keepAlive?: KeepAlivePoolOptions | false,
  outboundSigning?: OutboundSigningConfig,
  proxies?: Record<string, string>,
  tlsClientCerts?: Record<string, TlsClientCert>,
  compressOutbound?: Record<string, CompressOutboundOptions>,
  http2?: Http2PoolOptions,
  idempotencyKey?: IdempotencyKeyOptions,
  websocket?: WebSocketPoolOptions,
  outboundEncryption?: Record<string, OutboundEncryptionConfig>,
  tlsSniOverrides?: Record<string, TlsSniOverride>,
  responseCompression?: Record<string, ResponseCompressionOptions>,
  forwardHeaders?: Record<string, ForwardHeadersRuleConfig>,
  certExpiryMonitor?: CertExpiryMonitor,
  minTlsVersions?: Record<string, MinTlsVersion>,
  tlsVersionMonitor?: TlsVersionMonitor,
  /**
   * WR-75: guarded outbound gzip compression (content-type whitelist +
   * 415→plaintext fallback + byte-savings accounting). Validated at
   * startup; `undefined` keeps the WR-40-only behavior.
   */
  compressThreshold?: Record<string, GuardedCompressOptions>,
  /**
   * WR-75: called once per 415-triggered plaintext fallback resend. The
   * server audits these as `gzip_fallback_plaintext`; library users get
   * the hook directly.
   */
  onGzipFallback?: (info: GzipFallbackInfo) => void,
  /**
   * WR-81: called once per endpoint at startup when E2EE key rotation is
   * configured (a `keyId`/`previousKeys` entry). The server audits these
   * as `e2ee_key_rotated`; library users get the hook directly.
   */
  onE2eeKeyRotated?: (info: E2eeKeyRotatedInfo) => void
): PooledSender {
  if (tlsPins !== undefined) {
    for (const [endpoint, pins] of Object.entries(tlsPins)) {
      try {
        assertValidPins(pins);
      } catch (err) {
        throw new RangeError(
          `createDefaultSender: invalid TLS pins for ${endpoint}: ${(err as Error).message}`
        );
      }
    }
  }
  // WR-74: fail fast on a misconfigured floor — a typo must not silently
  // leave an endpoint unprotected.
  if (minTlsVersions !== undefined) {
    for (const [endpoint, floor] of Object.entries(minTlsVersions)) {
      try {
        assertValidMinTlsVersion(floor);
      } catch (err) {
        throw new RangeError(
          `createDefaultSender: invalid minTlsVersion for ${endpoint}: ${(err as Error).message}`
        );
      }
    }
  }
  if (proxies !== undefined) {
    for (const [endpoint, proxyUrl] of Object.entries(proxies)) {
      try {
        assertValidProxyUrl(proxyUrl);
      } catch (err) {
        throw new RangeError(
          `createDefaultSender: invalid proxy URL for ${endpoint}: ${(err as Error).message}`
        );
      }
    }
  }
  if (tlsClientCerts !== undefined) {
    for (const [endpoint, cert] of Object.entries(tlsClientCerts)) {
      try {
        assertValidClientCert(cert, `tlsClientCerts[${endpoint}]`);
      } catch (err) {
        throw new RangeError(
          `createDefaultSender: invalid TLS client certificate for ${endpoint}: ${(err as Error).message}`
        );
      }
    }
    // WR-73: the relay's own mTLS client identities are checked for
    // expiry at config load (same audit + gauge treatment as downstream
    // certificates) — an expired client identity fails every handshake
    // and no retry ever fixes it. The monitor is inert unless enabled.
    if (certExpiryMonitor !== undefined) {
      for (const [endpoint, cert] of Object.entries(tlsClientCerts)) {
        certExpiryMonitor.checkClientCertificate(cert.cert, endpoint);
      }
    }
  }
  // WR-60: RangeError on invalid values, at startup — never mid-handshake.
  // `undefined` (feature off) is the common case. Entry keys must be
  // `https:` URLs: SNI/ALPN only exist on the TLS handshake.
  if (tlsSniOverrides !== undefined) {
    for (const [endpoint, override] of Object.entries(tlsSniOverrides)) {
      try {
        assertValidTlsSniOverride(override, `tlsSniOverrides[${endpoint}]`);
        let protocol: string;
        try {
          protocol = new URL(endpoint).protocol;
        } catch {
          throw new RangeError(`not a valid URL: ${endpoint}`);
        }
        if (protocol !== "https:") {
          throw new RangeError(
            `only https: targets support TLS SNI/ALPN overrides (got ${protocol})`
          );
        }
      } catch (err) {
        throw new RangeError(
          `createDefaultSender: invalid TLS SNI override for ${endpoint}: ${(err as Error).message}`
        );
      }
    }
  }
  // RangeError on invalid values, at startup — never mid-delivery.
  if (compressOutbound !== undefined) {
    try {
      assertValidCompressOutboundConfig(compressOutbound);
    } catch (err) {
      throw new RangeError(
        `createDefaultSender: invalid compressOutbound config: ${(err as Error).message}`
      );
    }
  }
  // WR-75: RangeError on invalid values, at startup — never mid-delivery.
  if (compressThreshold !== undefined) {
    try {
      assertValidGuardedCompressConfig(compressThreshold);
    } catch (err) {
      throw new RangeError(
        `createDefaultSender: invalid compressThreshold config: ${(err as Error).message}`
      );
    }
  }
  // WR-75: the byte-savings tracker is always created (cheap, empty) so
  // `sender.compressionStats` is available even with no guarded endpoint
  // configured; its exposition stays absent until the first byte saved.
  const compressionTracker = new OutboundCompressionTracker();
  // WR-62: RangeError on invalid values, at startup — never mid-delivery.
  if (responseCompression !== undefined) {
    try {
      assertValidResponseCompressionConfig(responseCompression);
    } catch (err) {
      throw new RangeError(
        `createDefaultSender: invalid responseCompression config: ${(err as Error).message}`
      );
    }
  }
  // WR-69: RangeError on invalid values, at startup — never mid-delivery.
  let forwardHeadersRules: Map<string, CompiledForwardHeadersRule> | undefined;
  if (forwardHeaders !== undefined) {
    try {
      forwardHeadersRules = resolveForwardHeadersConfig(forwardHeaders);
    } catch (err) {
      throw new RangeError(
        `createDefaultSender: invalid forwardHeaders config: ${(err as Error).message}`
      );
    }
  }
  // RangeError on invalid values, at startup — never mid-delivery.
  if (outboundSigning !== undefined) {
    if (typeof outboundSigning.secret !== "string" || outboundSigning.secret === "") {
      throw new RangeError("createDefaultSender: `outboundSigning.secret` must be a non-empty string");
    }
    if (
      outboundSigning.keyId !== undefined &&
      (typeof outboundSigning.keyId !== "string" || outboundSigning.keyId === "")
    ) {
      throw new RangeError("createDefaultSender: `outboundSigning.keyId` must be a non-empty string");
    }
  }
  // WR-58: RangeError on invalid values, at startup — never mid-delivery.
  // `undefined` (feature off) is the common case. Parsed keys are cached
  // so the per-delivery seal only does the ECDH + AEAD, never re-parse.
  // WR-81: endpoints with `keyId`/`previousKeys` get a RotatingE2eeSealer
  // (envelope `kid` + grace-windowed retired keys); plain `{ publicKey }`
  // endpoints keep the WR-58 single-key path exactly as before.
  let e2eeKeys: Map<string, KeyObject> | undefined;
  let e2eeSealers: Map<string, RotatingE2eeSealer> | undefined;
  if (outboundEncryption !== undefined) {
    e2eeKeys = new Map();
    e2eeSealers = new Map();
    for (const [endpoint, cfg] of Object.entries(outboundEncryption)) {
      try {
        if (cfg === null || typeof cfg !== "object" || typeof cfg.publicKey !== "string") {
          throw new RangeError(`outboundEncryption[${endpoint}].publicKey must be a base64 X25519 public key string`);
        }
        const rotating = cfg.keyId !== undefined || cfg.previousKeys !== undefined;
        if (!rotating) {
          e2eeKeys.set(endpoint, parseX25519PublicKey(cfg.publicKey, `outboundEncryption[${endpoint}].publicKey`));
          continue;
        }
        if (typeof cfg.keyId !== "string" || cfg.keyId === "") {
          throw new RangeError(`outboundEncryption[${endpoint}].keyId is required when previousKeys is set`);
        }
        const previous: E2eeRotationKey[] = (cfg.previousKeys ?? []).map((k, i) => {
          if (k === null || typeof k !== "object" || typeof k.id !== "string" || k.id === "") {
            throw new RangeError(`outboundEncryption[${endpoint}].previousKeys[${i}].id must be a non-empty string`);
          }
          if (typeof k.publicKey !== "string") {
            throw new RangeError(`outboundEncryption[${endpoint}].previousKeys[${i}].publicKey must be a base64 X25519 public key string`);
          }
          return {
            id: k.id,
            publicKey: k.publicKey,
            ...(k.primary === true ? { primary: true as const } : {}),
            retiredAtMs: k.retiredAtMs ?? Date.now(),
          };
        });
        const sealer = new RotatingE2eeSealer({
          keys: [{ id: cfg.keyId, publicKey: cfg.publicKey, primary: true }, ...previous],
          ...(cfg.graceMs !== undefined ? { graceMs: cfg.graceMs } : {}),
        });
        e2eeSealers.set(endpoint, sealer);
        // WR-81: a rotation is configured for this endpoint — the operator
        // needs one audit line saying which key is now primary and which
        // retired keys are still inside their grace window.
        onE2eeKeyRotated?.({
          endpoint,
          primaryKeyId: sealer.primaryKeyId,
          previousKeyIds: previous.map((k) => k.id),
          graceMs: cfg.graceMs ?? DEFAULT_E2EE_KEY_GRACE_MS,
          rotationInProgress: sealer.rotationInProgress,
        });
      } catch (err) {
        throw new RangeError(
          `createDefaultSender: invalid outboundEncryption for ${endpoint}: ${(err as Error).message}`
        );
      }
    }
  }
  // RangeError on invalid values, at startup — never mid-delivery.
  // `undefined` (feature off) is the common case.
  let idempotencyKeyCfg: ResolvedIdempotencyKeyConfig | undefined;
  try {
    idempotencyKeyCfg = resolveIdempotencyKeyConfig(idempotencyKey);
  } catch (err) {
    throw new RangeError(`createDefaultSender: invalid idempotencyKey config: ${(err as Error).message}`);
  }
  const pool = keepAlive === false ? undefined : new OutboundConnectionPool(keepAlive);
  // RangeError on invalid values, at startup — never mid-delivery.
  const http2Opts = http2 === undefined ? undefined : resolveHttp2PoolOptions(http2);
  // No pool when H2 is disabled or no host is eligible for it: `undefined`
  // is the "H2 inactive" signal, mirroring `keepAlive: false`.
  const h2pool =
    http2Opts !== undefined && http2Opts.enabled && http2Opts.hosts.length > 0
      ? new Http2SessionPool(http2Opts)
      : undefined;
  // WebSocket pool (WR-45): always created — a ws:/wss: target just
  // works. RangeError on invalid values, at startup — never mid-delivery.
  const wsPool = new WebSocketPool({
    ...websocket,
    // WR-73: downstream cert-expiry capture on the wss: handshake (the
    // pool's verifyPins path feeds the monitor). The monitor is inert
    // unless enabled, so the request path is untouched when off.
    ...(certExpiryMonitor !== undefined
      ? {
          onTlsPeerCertificate: (socket: TLSSocket, targetUrl: string) =>
            certExpiryMonitor.observePeerCertificate(socket, targetUrl),
        }
      : {}),
  });

  /**
   * Shared outbound request material: passthrough headers, trace id,
   * compression, the relay signature, and (WR-44) the idempotency key.
   * Both transports stamp the same wire bytes, so an H2 delivery is
   * indistinguishable downstream from an HTTP/1.1 one (a forged inbound
   * `x-relay-signature` was already stripped from the passthrough
   * headers at intake).
   */
  const buildWireRequest = (
    item: RetryItem,
    wireOpts?: { forcePlaintext?: boolean; httpTransport?: boolean }
  ): {
    headers: Record<string, string | string[]>;
    body: Buffer;
    /** WR-75: true when the guarded path compressed this request. */
    guardedCompressed: boolean;
    /** WR-75: payload bytes saved by the guarded compression (0 otherwise). */
    guardedBytesSaved: number;
  } => {
    const headers: Record<string, string | string[]> = {};
    // WR-69: per-endpoint header forwarding allowlist. Evaluated on the
    // inbound passthrough headers (already stripped of relay-owned
    // headers at intake); the relay-forced stamps below (trace id,
    // x-relay-signature, idempotency key, encodings) are unaffected — they
    // are always sent. Endpoints without a rule keep the exact current
    // behavior.
    const forwardRule = forwardHeadersRules?.get(item.targetUrl);
    for (const [k, v] of Object.entries(item.headers)) {
      if (v === undefined) continue;
      if (forwardRule !== undefined && !shouldForwardHeader(forwardRule, k)) continue;
      headers[k] = v;
    }
    // Propagate the trace ID downstream so the next hop can correlate the
    // delivery with this relay's audit trail (overrides a stale inbound
    // value, which is identical anyway after `resolveTraceId`).
    if (item.traceId) headers[TRACE_ID_HEADER] = item.traceId;
    // WR-75: the guarded path is decided first — when both records
    // configure an endpoint it wins outright (safer superset: whitelist +
    // 415 fallback), so the two compressions never stack or disagree. It
    // engages only on HTTP transports: WebSocket deliveries keep their
    // RFC 7692 permessage-deflate story (`src/deflate.ts`) and never pass
    // through here. The 415 fallback resend forces both compressions off.
    let wireBody = item.payload;
    let contentEncoding: "gzip" | undefined;
    let guardedCompressed = false;
    let guardedBytesSaved = 0;
    const forcePlaintext = wireOpts?.forcePlaintext === true;
    if (!forcePlaintext) {
      const guardedOpts =
        wireOpts?.httpTransport === false ? undefined : compressThreshold?.[item.targetUrl];
      if (guardedOpts !== undefined) {
        const decision = guardedCompressOutbound(
          item.payload,
          outboundContentType(item.headers),
          guardedOpts
        );
        wireBody = decision.body;
        contentEncoding = decision.contentEncoding;
        guardedCompressed = decision.contentEncoding === "gzip";
        guardedBytesSaved = decision.bytesSaved;
      } else {
        // WR-40: per-endpoint opt-in gzip (fire-and-forget: no whitelist,
        // no fallback). Compression happens before signing so
        // `x-relay-signature` covers the exact wire bytes the downstream
        // receives.
        const legacy = maybeCompressOutbound(item.payload, compressOutbound?.[item.targetUrl]);
        wireBody = legacy.body;
        contentEncoding = legacy.contentEncoding;
      }
    }
    // WR-58: per-endpoint end-to-end encryption. Seals the (possibly
    // compressed) wire body with the downstream's X25519 public key BEFORE
    // signing, so `x-relay-signature` covers the ciphertext wire bytes —
    // exactly what the downstream receives and verifies. The envelope
    // carries the pre-seal content encoding (WR-40), so the HTTP
    // `content-encoding` header is dropped when a body is sealed: the wire
    // bytes are the JSON envelope, not the gzip stream. Endpoints without
    // a configured key behave exactly as before.
    const e2eeKey = e2eeKeys?.get(item.targetUrl);
    const e2eeSealer = e2eeSealers?.get(item.targetUrl);
    let body = wireBody;
    if (e2eeSealer !== undefined) {
      // WR-81: rotation endpoint — the primary key seals and its id is
      // stamped as the envelope `kid`.
      body = e2eeSealer.seal(wireBody, contentEncoding);
      headers[E2EE_HEADER] = E2EE_ALGORITHM;
    } else if (e2eeKey !== undefined) {
      body = sealOutboundPayload(wireBody, e2eeKey, contentEncoding);
      headers[E2EE_HEADER] = E2EE_ALGORITHM;
    }
    if (outboundSigning !== undefined) {
      // Stamp AFTER the passthrough headers: this guarantees the relay's
      // own signature always wins.
      headers["x-relay-signature"] = signSha256(body, outboundSigning.secret);
      if (outboundSigning.keyId !== undefined) headers["x-relay-key-id"] = outboundSigning.keyId;
    }
    if (idempotencyKeyCfg !== undefined) {
      // WR-44: derive from (event id, 1-based attempt). The queue stamps
      // `attempt` (0-based, attempts consumed so far) on the sender-bound
      // copy; a missing value means a hand-built item, i.e. attempt 1.
      // Batch deliveries arrive with the batch id as the item id, so the
      // key covers the whole merged envelope. Deterministic per
      // (event, attempt): a dead-letter replay restarts at attempt 1 with
      // the same event id and reproduces the original keys.
      headers[IDEMPOTENCY_KEY_HEADER] = deriveIdempotencyKey(
        idempotencyKeyCfg.secret,
        item.id,
        (item.attempt ?? 0) + 1,
        idempotencyKeyCfg.keyPrefix
      );
    }
    // WR-58: a sealed body is the JSON envelope, not the gzip stream — the
    // pre-seal encoding travels inside the envelope instead.
    if (contentEncoding !== undefined && e2eeKey === undefined) headers["content-encoding"] = contentEncoding;
    // WR-62: per-endpoint opt-in — advertise compressed responses, so a
    // downstream that compresses saves us (and itself) bytes on the way
    // back. The response is decoded before the WR-37 validator sees it.
    const respCompress = responseCompression?.[item.targetUrl];
    if (respCompress !== undefined) {
      headers["accept-encoding"] = respCompress.acceptEncoding ?? DEFAULT_OUTBOUND_ACCEPT_ENCODING;
    }
    headers["content-length"] = String(body.length);
    return { headers, body, guardedCompressed, guardedBytesSaved };
  };

  /**
   * The HTTP/1.1 delivery path: pooled keep-alive agent (or a fresh
   * connection / one-off tunneled agent), with the WR-21 pinning and
   * WR-36 mTLS handshake handling.
   */
  const deliverViaHttp1 = (
    item: RetryItem,
    url: URL,
    pins: string[] | undefined,
    clientCert: TlsClientCert | undefined,
    proxyUrl: string | undefined,
    tlsSni: ResolvedTlsSniOverride | undefined,
    minTlsVersion: MinTlsVersion | undefined
  ): Promise<DownstreamResponse | void> => {
    // WR-75: the guarded 415→plaintext fallback needs the compression
    // decision outside the attempt promise. The decision is deterministic
    // in (payload, content-type, config), and the Promise executor runs
    // synchronously, so these are set before `attempt(false)` settles.
    let guardedApplied = false;
    let guardedBytesSaved = 0;
    const attempt = (forcePlaintext: boolean): Promise<DownstreamResponse | void> =>
      new Promise((resolve, reject) => {
        // The wire request is built once per attempt: the guarded decision
        // is deterministic, so building it here gives the fallback check
        // the same answer the wire builder used — without compressing
        // twice. The byte savings are noted per guarded-compressed
        // dispatch (the sender committed to sending it compressed).
        const wire = buildWireRequest(item, { forcePlaintext, httpTransport: true });
        if (!forcePlaintext && wire.guardedCompressed) {
          guardedApplied = true;
          guardedBytesSaved = wire.guardedBytesSaved;
          compressionTracker.noteSaved(item.targetUrl, wire.guardedBytesSaved);
        }
        // WR-54: time-to-first-byte — request-issued timestamp; the diff is
        // taken when the downstream's first response bytes arrive (the
        // 'response' handler below). A "首响应头到达耗时" approximation:
        // connection setup + request write + server think time. It does not
        // measure kernel-to-user dispatch, and the doc on
        // `DownstreamResponse.timeToFirstByteMs` says so.
        const requestIssuedMs = Date.now();
        // Pooled keep-alive agent for this origin (dedicated agent per pin
        // whitelist, per proxy, per client identity, and per effective TLS
        // identity, so a connection pinned, tunneled, authenticated, or
        // handshaked for one endpoint can never serve another's). With
        // pooling disabled but a proxy configured, each delivery gets a
        // one-off tunneled agent — fresh tunnel per delivery, destroyed when
        // the request settles.
        let oneOffAgent: HttpAgent | undefined;
        const agent =
          pool?.agentFor(
            url,
            pins,
            proxyUrl,
            clientCert !== undefined ? clientCertIdentity(clientCert) : undefined,
            tlsSni,
            minTlsVersion
          ) ??
          (proxyUrl !== undefined
            ? (oneOffAgent = createProxiedAgent(
                url.protocol === "https:" ? "https" : "http",
                proxyUrl,
                { keepAlive: false, maxSockets: 1, maxFreeSockets: 0 }
              ))
            : undefined);
        const onResponse = (res: Parameters<Parameters<typeof httpsRequest>[2]>[0]): void => {
          // WR-54: the downstream's first response bytes just arrived — this
          // is the TTFB instant measured against `requestIssuedMs` above.
          const timeToFirstByteMs = Date.now() - requestIssuedMs;
          // WR-37: capture the response body (capped) so a per-endpoint
          // responseValidator can check its semantics after a 2xx
          // transport success. Non-2xx responses still reject on the
          // status code alone — the validator never sees them.
          // WR-62: when the endpoint opted into response compression, the
          // wire cap is the decompressed-bytes cap (default: the same 64
          // KiB as the plain capture) — the wire form of a compressed
          // response is the smaller side, so one cap bounds both.
          const respCompress = responseCompression?.[item.targetUrl];
          const wireCap = respCompress?.maxDecompressedBytes ?? RESPONSE_CAPTURE_MAX_BYTES;
          const chunks: Buffer[] = [];
          let captured = 0;
          let truncated = false;
          res.on("data", (chunk: Buffer) => {
            if (captured < wireCap) {
              const room = wireCap - captured;
              if (chunk.length > room) {
                chunks.push(chunk.subarray(0, room));
                captured += room;
                truncated = true;
              } else {
                chunks.push(chunk);
                captured += chunk.length;
              }
            } else {
              truncated = true;
            }
          });
          res.on("end", () => {
            if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
              const statusCode: number = res.statusCode;
              // WR-62: decode a compressed downstream response before the
              // WR-37 validator (and the audit summary) see the body. The
              // decode runs async — a corrupt or over-budget body rejects
              // the attempt, which the retry layer classifies retryable.
              // A wire capture cut at the cap cannot be decoded (a
              // truncated compressed stream is corrupt by definition): the
              // raw bytes travel on with `truncated: true`, exactly like
              // the uncompressed path.
              (async () => {
                let body = Buffer.concat(chunks);
                let contentEncoding: string | undefined;
                if (respCompress !== undefined && !truncated) {
                  const decoded = await decodeResponseBody(
                    body,
                    res.headers["content-encoding"],
                    wireCap
                  );
                  body = decoded.body;
                  contentEncoding = decoded.contentEncoding;
                }
                resolve({
                  statusCode,
                  body,
                  truncated,
                  timeToFirstByteMs,
                  ...(contentEncoding !== undefined ? { contentEncoding } : {}),
                });
              })().catch(reject);
            } else {
              // Structured failure: the retry queue classifies on the status
              // code (4xx-except-408/429 → immediate dead letter, never
              // retried) and honors a 429's Retry-After header. The error
              // message keeps the historical shape.
              reject(
                new HttpDeliveryError(
                  res.statusCode ?? 0,
                  parseRetryAfterMs(res.headers["retry-after"])
                )
              );
            }
          });
          res.on("error", reject);
        };
        // `agent: false` opts out of Node's global agent (which pools
        // keep-alive connections by default since Node 19): each delivery
        // gets a one-off agent and therefore a fresh connection.
        const req =
          url.protocol === "https:"
            ? httpsRequest(
                url,
                {
                  method: "POST",
                  agent: agent ?? false,
                  ...(pins ? { rejectUnauthorized: false } : {}),
                  // WR-60: per-endpoint TLS SNI/ALPN override. `servername`
                  // and `ALPNProtocols` flow through the agent's
                  // `createConnection` into `tls.connect` — the pooled
                  // `https.Agent`, the one-off agent, and the proxied tunnel
                  // agent all honor them (verified against Node v24). Without
                  // an entry nothing is set: Node's defaults apply, exactly
                  // as before.
                  ...(tlsSni !== undefined
                    ? {
                        ...(tlsSni.servername !== undefined
                          ? { servername: tlsSni.servername }
                          : {}),
                        ALPNProtocols: [...tlsSni.alpnProtocols],
                      }
                    : {}),
                  // The client certificate rides the TLS handshake (per-request
                  // TLS options apply to connections the pooled agent opens;
                  // the pool key already binds this exact identity, so a
                  // reused socket was authenticated as this same identity).
                  ...(clientCert
                    ? {
                        cert: clientCert.cert,
                        key: clientCert.key,
                        ...(clientCert.passphrase !== undefined
                          ? { passphrase: clientCert.passphrase }
                          : {}),
                      }
                    : {}),
                },
                onResponse
              )
            : httpRequest(url, { method: "POST", agent: agent ?? false }, onResponse);
        req.on("error", reject);

        if (pool && agent) {
          req.on("socket", (socket) => pool.noteSocket(agent, socket));
          // Once the request settles the socket is back in the agent's free
          // list: stamp it idle and unref it, so a forgotten pool never pins
          // process exit. Deferred one tick — the agent frees the socket
          // just before 'close' fires.
          req.on("close", () => setImmediate(() => pool.markIdle(agent)));
        }
        if (oneOffAgent !== undefined) {
          // No pooling: the tunneled socket must not outlive the delivery.
          req.on("close", () => oneOffAgent?.destroy());
        }

        const writePayload = (): void => {
          for (const [k, v] of Object.entries(wire.headers)) req.setHeader(k, v);
          req.end(wire.body);
        };

        /**
         * WR-73: capture the peer certificate's expiry on the TLS handshake
         * for `https:` targets — the same `getPeerCertificate` read the
         * WR-21 pin check uses. Runs on the fresh-handshake path; a reused
         * pooled connection's certificate was already captured when its
         * handshake ran (the monitor edge-triggers per certificate, so a
         * re-observation would be a no-op anyway).
         */
        const observeTlsPeer = (socket: unknown, endpoint: string): void => {
          const tlsSocket = socket as TLSSocket;
          const already = tlsSocket.getPeerCertificate() as { raw?: unknown };
          if (already && already.raw) {
            certExpiryMonitor?.observePeerCertificate(tlsSocket, endpoint);
          } else {
            tlsSocket.once("secureConnect", () =>
              certExpiryMonitor?.observePeerCertificate(tlsSocket, endpoint)
            );
          }
        };

        if (pins === undefined) {
          // WR-73: hook cert-expiry capture for the unpinned https: path too.
          if (url.protocol === "https:" && certExpiryMonitor?.enabled) {
            req.on("socket", (socket) => observeTlsPeer(socket, item.targetUrl));
          }
          // WR-74: enforce the endpoint's TLS floor on the fresh handshake.
          // A reused pooled socket was handshaked under this same floor
          // (the pool key binds it), so its version trivially qualifies.
          if (minTlsVersion !== undefined && url.protocol === "https:") {
            req.on("socket", (socket) => {
              const tlsSocket = socket as TLSSocket;
              const already = tlsSocket.getPeerCertificate() as { raw?: unknown };
              if (already && already.raw) {
                enforceTlsFloor(tlsSocket);
              } else {
                tlsSocket.once("secureConnect", () => enforceTlsFloor(tlsSocket));
              }
            });
          }
          writePayload();
          return;
        }
        // Normalized once, up front, so the per-handshake path is a plain compare.
        // WR-60 consistency: this socket comes from a pool agent keyed by the
        // effective TLS identity, so the pin is always verified on the
        // connection that was handshaked with the (possibly overridden) SNI —
        // the check and the handshake cannot disagree about the peer.
        const allowed = pins.map(normalizePin);
        /**
         * WR-74: enforce the endpoint's TLS floor on a handshaked socket,
         * before any payload byte is written. Returns true when the
         * connection was destroyed — the caller must stop and not write.
         * The rejection is recorded on the monitor (audit
         * `tls_version_rejected` + `relay_tls_version_rejections_total`);
         * the destroyed request fails the delivery attempt, which then
         * follows the normal retry / dead-letter path.
         */
        const enforceTlsFloor = (tlsSocket: TLSSocket): boolean => {
          if (minTlsVersion === undefined) return false;
          try {
            assertTlsVersionMeetsFloor(item.targetUrl, tlsSocket.getProtocol(), minTlsVersion);
            return false;
          } catch (err) {
            const rejected = err as TlsVersionRejectedError;
            tlsVersionMonitor?.recordRejection(item.targetUrl, rejected.negotiated, minTlsVersion);
            req.destroy(rejected);
            return true;
          }
        };
        const verifyFreshPin = (tlsSocket: TLSSocket): void => {
          // WR-74: floor first — a below-floor peer is rejected before the
          // pin check runs (both fail the attempt; the floor's audit event
          // is the more actionable signal for a version regression).
          if (enforceTlsFloor(tlsSocket)) return;
          let presented: string;
          try {
            const raw = (tlsSocket.getPeerCertificate() as { raw?: unknown }).raw;
            // WR-73: reuse this handshake's certificate read for the
            // expiry monitor — no second getPeerCertificate call.
            certExpiryMonitor?.observePeerCertificateDer(Buffer.from(raw as Buffer), item.targetUrl);
            presented = spkiFingerprint(Buffer.from(raw as Buffer));
          } catch {
            presented = "<unreadable certificate>";
          }
          if (allowed.includes(presented)) {
            // Cache the handshake result on the pooled socket: pinning is
            // about server identity, and this connection already proved it.
            pool?.cachePresentedPin(tlsSocket, presented);
            writePayload();
          } else {
            // Fail the delivery attempt: it follows the normal retry /
            // dead-letter path and the mismatch lands in the audit trail.
            // The socket is destroyed with the request, so a mismatched
            // peer is never handed to another delivery from the pool.
            req.destroy(new TlsPinMismatchError(item.targetUrl, presented));
          }
        };
        req.on("socket", (socket) => {
          const tlsSocket = socket as TLSSocket;
          const cached = pool?.presentedPin(socket);
          if (cached !== undefined) {
            // Reused pooled connection: the peer was pinned at handshake
            // time, and the pool key already binds this exact pin whitelist —
            // a cached fingerprint outside the whitelist means a poisoned
            // socket, so fail loudly instead of delivering over it. The
            // pool key likewise binds the TLS floor (WR-74), so the reused
            // socket's version trivially qualifies — still checked, cheap
            // and loud, in case a socket ever drifts below the floor.
            if (enforceTlsFloor(tlsSocket)) return;
            if (allowed.includes(cached)) {
              writePayload();
            } else {
              socket.destroy();
              req.destroy(new TlsPinMismatchError(item.targetUrl, cached));
            }
            return;
          }
          let verified = false;
          const verifyPin = (): void => {
            if (verified) return;
            verified = true;
            verifyFreshPin(tlsSocket);
          };
          const already = tlsSocket.getPeerCertificate() as { raw?: unknown };
          if (already && already.raw) {
            // Defensive: a reused agent socket may already be secure.
            verifyPin();
          } else {
            tlsSocket.once("secureConnect", verifyPin);
          }
        });
      });
    // WR-75: the downstream answered 415 to a guarded-compressed request —
    // it does not speak gzip. Resend once as plaintext *inside the same
    // delivery attempt*: the queue sees a single attempt, so the fallback
    // consumes no retry budget and records no circuit verdict. A 415 on
    // the plaintext resend (or any other failure) follows the normal
    // classify → retry / dead-letter path instead.
    return attempt(false).catch((err) => {
      if (err instanceof HttpDeliveryError && err.statusCode === 415 && guardedApplied) {
        onGzipFallback?.({
          id: item.id,
          traceId: item.traceId,
          endpoint: item.targetUrl,
          bytesSaved: guardedBytesSaved,
        });
        return attempt(true);
      }
      throw err;
    });
  };

  /**
   * HTTP/2 delivery (WR-42): one multiplexed stream on the origin's
   * session, stamping the same wire bytes as the HTTP/1.1 path. Any
   * H2-level failure throws Http2UnavailableError, and the dispatcher
   * below retries the delivery over HTTP/1.1 — a delivery is never lost
   * because of H2.
   */
  const deliverViaHttp2 = (
    item: RetryItem,
    url: URL,
    pins: string[] | undefined,
    clientCert: TlsClientCert | undefined,
    tlsSni: ResolvedTlsSniOverride | undefined,
    minTlsVersion: MinTlsVersion | undefined
  ): Promise<DownstreamResponse> => {
    // WR-75: same guarded 415→plaintext fallback as the HTTP/1.1 path —
    // the resend rides a fresh H2 stream inside the same delivery
    // attempt, so the queue still sees a single attempt.
    let guardedApplied = false;
    let guardedBytesSaved = 0;
    const attempt = async (forcePlaintext: boolean): Promise<DownstreamResponse> => {
        const session = await h2pool!.sessionFor(url, pins, clientCert, tlsSni, minTlsVersion);
        h2pool!.acquireStream(session);
        // WR-73: the session's handshake is done by now (established or
        // reused — the monitor edge-triggers per certificate, so a
        // re-observation is a no-op), which is exactly when the peer
        // certificate is readable. A resumed session re-sends no
        // certificate; the monitor skips those silently.
        if (certExpiryMonitor?.enabled) {
          const sock = session.socket as TLSSocket | undefined;
          if (sock !== undefined) certExpiryMonitor.observePeerCertificate(sock, item.targetUrl);
        }
        try {
          const wire = buildWireRequest(item, { forcePlaintext, httpTransport: true });
          if (!forcePlaintext && wire.guardedCompressed) {
            guardedApplied = true;
            guardedBytesSaved = wire.guardedBytesSaved;
            compressionTracker.noteSaved(item.targetUrl, wire.guardedBytesSaved);
          }
          const res = await runHttp2Stream(session, {
            method: "POST",
            path: `${url.pathname}${url.search}`,
            headers: wire.headers,
            body: wire.body,
            captureMaxBytes: RESPONSE_CAPTURE_MAX_BYTES,
          });
        if (res.statusCode >= 200 && res.statusCode < 300) {
          // WR-62: decode a compressed downstream response before the WR-37
          // validator sees the body — same contract as the HTTP/1.1 path.
          // A capture cut at the cap cannot be decoded: the raw bytes
          // travel on with `truncated: true`.
          const respCompress = responseCompression?.[item.targetUrl];
          let body = res.body;
          let contentEncoding: string | undefined;
          if (respCompress !== undefined && !res.truncated) {
            const decoded = await decodeResponseBody(
              body,
              res.headers["content-encoding"],
              respCompress.maxDecompressedBytes ?? RESPONSE_CAPTURE_MAX_BYTES
            );
            body = decoded.body;
            contentEncoding = decoded.contentEncoding;
          }
          return {
            statusCode: res.statusCode,
            body,
            truncated: res.truncated,
            ...(contentEncoding !== undefined ? { contentEncoding } : {}),
          };
        }
        // Structured failure, same as the HTTP/1.1 path: the retry queue
        // classifies on the status code and honors a 429's Retry-After.
        throw new HttpDeliveryError(res.statusCode, parseRetryAfterMs(res.headers["retry-after"]));
      } finally {
        h2pool!.releaseStream(session);
      }
    };
    return attempt(false).catch((err) => {
      if (err instanceof HttpDeliveryError && err.statusCode === 415 && guardedApplied) {
        onGzipFallback?.({
          id: item.id,
          traceId: item.traceId,
          endpoint: item.targetUrl,
          bytesSaved: guardedBytesSaved,
        });
        return attempt(true);
      }
      throw err;
    });
  };

  /**
   * The WebSocket delivery path (WR-45): pooled RFC 6455 connections,
   * one masked text frame per delivery, `x-relay-*` headers as upgrade
   * request headers. Handshake failures surface as `HttpDeliveryError`
   * (non-101) or plain errors (transport), so they flow through the
   * normal retry / dead-letter path like the HTTP transports.
   */
  const deliverViaWebSocket = (
    item: RetryItem,
    url: URL,
    pins: string[] | undefined
  ): Promise<DownstreamResponse> => {
    // WR-75: the guarded HTTP gzip path never engages here — WebSocket
    // deliveries keep their RFC 7692 permessage-deflate story
    // (`src/deflate.ts`), so the two mechanisms cannot disagree about who
    // compressed what. WR-40 behavior on this path is unchanged.
    const { headers, body } = buildWireRequest(item, { httpTransport: false });
    const relayHeaders: Record<string, string> = {};
    for (const [name, value] of Object.entries(headers)) {
      if (typeof value === "string" && name.toLowerCase().startsWith("x-relay-")) {
        relayHeaders[name] = value;
      }
    }
    return wsPool.deliver(url, body, relayHeaders, pins, item.targetUrl);
  };

  const sender = function defaultSender(item: RetryItem): Promise<DownstreamResponse | void> {
    const url = new URL(item.targetUrl);
    // Pinning is per endpoint (exact targetUrl match). When pins are
    // configured for the endpoint, the whitelist is the trust anchor: it
    // replaces Node's PKI chain verification, and the peer certificate is
    // verified on `secureConnect` before a single payload byte is written
    // (a MITM must not even see the request body). See `src/pinning.ts`
    // for why `checkServerIdentity` cannot do this job. WR-45: the same
    // rule covers `wss:` targets — the WebSocket pool verifies the SPKI
    // fingerprint before the upgrade handshake is written.
    const pins =
      url.protocol === "https:" || url.protocol === "wss:" ? tlsPins?.[item.targetUrl] : undefined;
    // mTLS client identity for this endpoint (exact targetUrl match):
    // the certificate is presented during the TLS handshake so the
    // downstream can verify the relay. Off by default — endpoints without
    // an entry send no client certificate, exactly as before.
    const clientCert = url.protocol === "https:" ? tlsClientCerts?.[item.targetUrl] : undefined;
    // WR-60: per-endpoint TLS SNI/ALPN override (exact targetUrl match).
    // `undefined` for endpoints without an entry — and for non-`https:`
    // targets — keeps the exact current behavior.
    const tlsSni =
      url.protocol === "https:"
        ? resolveTlsSniOverride(item.targetUrl, url, tlsSniOverrides)
        : undefined;
    // WR-74: per-endpoint TLS minimum version (exact targetUrl match).
    // `undefined` for endpoints without an entry — and for non-`https:`
    // targets — keeps the exact current behavior.
    const minTlsVersion =
      url.protocol === "https:" ? minTlsVersions?.[item.targetUrl] : undefined;
    // Outbound proxy for this endpoint: explicit per-endpoint config
    // first, then the environment (read per delivery, so proxy rotation
    // needs no restart; `NO_PROXY` bypasses the env fallback only — an
    // explicit entry always wins). An invalid *environment* value throws
    // here and fails the delivery through the normal retry path; explicit
    // values were validated at startup.
    const proxyUrl = resolveProxyUrl(item.targetUrl, proxies);
    if (proxyUrl === undefined && proxies?.[item.targetUrl] !== undefined) {
      return Promise.reject(
        new Error(`outbound proxy: proxy configured for non-HTTP(S) target ${item.targetUrl}`)
      );
    }
    // WebSocket (WR-45): ws:/wss: targets ride the pooled RFC 6455 path.
    // Proxied ws: is rejected above (explicit proxy + non-HTTP(S)
    // target), same as any other non-HTTP scheme.
    if (url.protocol === "ws:" || url.protocol === "wss:") {
      return deliverViaWebSocket(item, url, pins);
    }
    // HTTP/2 (WR-42): opt-in per host, never under a proxy — proxied
    // traffic rides the HTTP/1.1 CONNECT tunnel (see `src/http2.ts`). Any
    // H2-level failure falls back to the HTTP/1.1 pool below: a delivery
    // is never lost because of H2.
    if (h2pool !== undefined && proxyUrl === undefined && h2pool.eligibleFor(url)) {
      return deliverViaHttp2(item, url, pins, clientCert, tlsSni, minTlsVersion).catch((err) => {
        if (err instanceof Http2UnavailableError) {
          h2pool!.noteFallback();
          return deliverViaHttp1(item, url, pins, clientCert, proxyUrl, tlsSni, minTlsVersion);
        }
        throw err;
      });
    }
    return deliverViaHttp1(item, url, pins, clientCert, proxyUrl, tlsSni, minTlsVersion);
  } as PooledSender;
  sender.pool = pool;
  sender.http2Pool = h2pool;
  sender.wsPool = wsPool;
  sender.compressionStats = compressionTracker;
  sender.destroy = () => {
    pool?.destroy();
    h2pool?.destroy();
    wsPool.destroy();
  };
  return sender;
}

/** Default inbound request body size limit: 1 MiB. */
export const DEFAULT_MAX_BODY_BYTES = 1_048_576;

/**
 * WR-37: cap on the downstream response body the default sender captures
 * for semantic validation (64 KiB). Semantic markers (`{"ok":false}`,
 * gateway error codes) live in the first bytes; beyond the cap the
 * response is truncated and `DownstreamResponse.truncated` is set, so a
 * validator can decide whether to trust a cut-off body.
 */
export const RESPONSE_CAPTURE_MAX_BYTES = 64 * 1024;

/** Thrown by `readRawBody` when the streamed body exceeds `maxBytes`. */
export class BodyTooLargeError extends Error {
  readonly maxBytes: number;
  constructor(maxBytes: number) {
    super(`Request body exceeds ${maxBytes} bytes`);
    this.name = "BodyTooLargeError";
    this.maxBytes = maxBytes;
  }
}

function readRawBody(
  req: Parameters<Parameters<typeof createServer>[0]>[0],
  maxBytes: number
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    let failed = false;
    const onData = (c: Buffer): void => {
      if (failed) return;
      total += c.length;
      if (total > maxBytes) {
        // Stop buffering immediately — the caller answers 413 and closes
        // the connection, so the remaining bytes must not pile up here.
        failed = true;
        req.removeListener("data", onData);
        reject(new BodyTooLargeError(maxBytes));
        return;
      }
      chunks.push(c);
    };
    req.on("data", onData);
    req.on("end", () => {
      if (!failed) resolve(Buffer.concat(chunks));
    });
    req.on("error", reject);
  });
}

/**
 * Signing material for outbound delivery requests (see the
 * `outboundSigning` server option). When set, every outbound request made
 * by the default sender carries `x-relay-signature: sha256=<hex>` — the
 * HMAC-SHA256 of the forwarded body — plus `x-relay-key-id` when `keyId`
 * is given, so the downstream can prove the request really came from this
 * relay (verify with `verifySignature(body, header, secret)` from
 * `src/verify.ts`). Disabled by default.
 */
export interface OutboundSigningConfig {
  /** HMAC secret used to sign forwarded payloads. Non-empty. */
  secret: string;
  /** Stable key identifier surfaced in the `x-relay-key-id` header. Optional. */
  keyId?: string;
}

/**
 * Per-endpoint outbound end-to-end encryption material (WR-58, see
 * `src/e2ee.ts`). When an endpoint has an entry, the default sender seals
 * the (possibly compressed) wire body with the downstream's X25519 public
 * key *before* signing, so `x-relay-signature` (WR-26) covers the
 * ciphertext wire bytes. The sealed request carries
 * `x-relay-encryption: x25519-hkdf-sha256/aes-256-gcm`; the downstream
 * opens it with its private key (`unsealOutboundPayload` in `src/e2ee.ts`).
 * Endpoints without an entry behave exactly as before. Disabled by
 * default. Invalid values throw `RangeError` at startup.
 */
export interface OutboundEncryptionConfig {
  /**
   * The downstream's X25519 public key: base64 of the raw 32-byte key.
   * Generate with `generateX25519KeyPair()` from `src/e2ee.ts` — the
   * private half stays with the downstream and is never given to the
   * relay.
   */
  publicKey: string;
  /**
   * WR-81: stable id for this key, stamped as the envelope `kid` and
   * surfaced in `e2ee_key_rotated` audit events. Required when
   * `previousKeys` is set; when unset the endpoint behaves exactly as
   * WR-58 (no `kid` in the envelope).
   */
  keyId?: string;
  /**
   * WR-81: rotated-out downstream public keys, newest first. Each entry
   * needs `id` and `publicKey`; `retiredAtMs` (ms epoch) defaults to
   * sender-construction time. Retired keys stay in-rotation inside
   * `graceMs` (default 24h, same as WR-20) — the rotation is reported
   * as in flight while any retired key is inside its window.
   */
  previousKeys?: E2eeRotationKey[];
  /**
   * WR-81: grace period in ms for retired keys. Must be a non-negative
   * number; defaults to 24h (`DEFAULT_E2EE_KEY_GRACE_MS`).
   */
  graceMs?: number;
}

/** Info passed to `onE2eeKeyRotated` (WR-81). */
export interface E2eeKeyRotatedInfo {
  /** The endpoint (`targetUrl`) whose rotation was configured. */
  endpoint: string;
  /** Id of the key now sealing new deliveries (the envelope `kid`). */
  primaryKeyId: string;
  /** Ids of the retired keys, newest first. */
  previousKeyIds: string[];
  /** Effective grace window in ms. */
  graceMs: number;
  /** True while any retired key is still inside its grace window. */
  rotationInProgress: boolean;
}

/**
 * The value `createRelayServer` returns: the intake plane's `http.Server`
 * (bound by the caller with `listen()`, like the legacy single-plane
 * return), plus — only when `operatorPort` is configured — the relay-bound
 * operator plane listener. Closing the returned server also closes the
 * operator plane.
 */
export interface RelayServer extends Server {
  /**
   * WR-56: the operator-plane listener. Set only when `operatorPort` is
   * configured; the relay binds it at creation (default host `127.0.0.1`,
   * ephemeral when `port: 0`). It answers 404 to anything that is not an
   * operator path, so it can never accept a webhook.
   */
  operatorServer?: Server;
}

/**
 * WR-56: the operator-plane path set. Shared by both planes in
 * split-plane mode — the intake plane 404s these paths without revealing
 * the operator plane exists, the operator plane 404s everything else —
 * and by the legacy single-plane dispatch, where it is unchanged.
 */
function isOperatorPath(pathname: string): boolean {
  return (
    pathname === "/dead-letter" ||
    pathname.startsWith("/dead-letter/") ||
    pathname === "/audit" ||
    pathname === "/audit/verify" ||
    pathname === "/latency" ||
    pathname === "/slo-risk" ||
    pathname === "/usage" ||
    pathname === "/events" ||
    pathname === "/events/archive" ||
    pathname === "/metrics" ||
    pathname === "/config/endpoint" ||
    pathname === "/routing/rules" ||
    pathname === "/endpoints/pause" ||
    pathname === "/endpoints/resume" ||
    pathname === "/scheduled" ||
    pathname.startsWith("/scheduled/") ||
    pathname.startsWith("/deliveries/")
  );
}

/**
 * WR-61: one event inside a `POST /ingest/batch` envelope. `payload` is
 * base64 of the exact event bytes the per-item `x-signature` covers, so
 * per-item trust semantics are identical to a single webhook POST;
 * `headers` carries the per-item headers (`x-signature`, `x-trace-id`,
 * `x-nonce`, `x-timestamp`, `x-priority`, `x-tenant-id`, `x-deliver-at`,
 * `content-encoding`, …).
 */
export interface IngestBatchItem {
  payload: string;
  headers?: Record<string, string | string[]>;
}

/** Strict base64 shape: canonical alphabet, correct padding, no whitespace. */
const BATCH_ITEM_BASE64_SHAPE = /^[A-Za-z0-9+/]*={0,2}$/;

/** Strict base64 decode — `undefined` on any shape violation. */
function decodeBatchItemPayload(payload: string): Buffer | undefined {
  if (
    payload.length === 0 ||
    payload.length % 4 !== 0 ||
    !BATCH_ITEM_BASE64_SHAPE.test(payload)
  ) {
    return undefined;
  }
  return Buffer.from(payload, "base64");
}

/**
 * WR-61: validate one batch item's shape. Returns the normalized item
 * plus the decoded event bytes, or a short machine-readable `problem`
 * string when the item is malformed (audited as `invalid_item` — it
 * fails in isolation and never aborts the batch).
 */
export function checkIngestBatchItem(
  raw: unknown
): { item: IngestBatchItem; body: Buffer } | { problem: string } {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    return { problem: "item_must_be_object" };
  }
  const { payload, headers } = raw as { payload?: unknown; headers?: unknown };
  if (typeof payload !== "string") {
    return { problem: "payload_must_be_base64" };
  }
  const body = decodeBatchItemPayload(payload);
  if (body === undefined) {
    return { problem: "payload_must_be_base64" };
  }
  let normalizedHeaders: Record<string, string | string[]> | undefined;
  if (headers !== undefined) {
    if (headers === null || typeof headers !== "object" || Array.isArray(headers)) {
      return { problem: "headers_must_be_object" };
    }
    normalizedHeaders = {};
    for (const [k, v] of Object.entries(headers as Record<string, unknown>)) {
      if (typeof v === "string") {
        normalizedHeaders[k] = v;
      } else if (Array.isArray(v) && v.every((e) => typeof e === "string")) {
        normalizedHeaders[k] = v as string[];
      } else {
        return { problem: "header_values_must_be_strings" };
      }
    }
  }
  return {
    item: {
      payload,
      ...(normalizedHeaders === undefined ? {} : { headers: normalizedHeaders }),
    },
    body,
  };
}

/**
 * Create a minimal webhook relay: verify the `x-signature` header, enqueue
 * the payload into a retry queue, and forward it to `forwardUrl`.
 * Both accepted deliveries and signature rejections are written to the audit log.
 */
export function createRelayServer(opts: RelayServerOptions): RelayServer {
  const latencyOpts = opts.retry?.latency;
  // RangeError on invalid values, at startup — never mid-request.
  const maxBodyBytes = opts.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  if (!Number.isInteger(maxBodyBytes) || maxBodyBytes <= 0) {
    throw new RangeError("createRelayServer: `maxBodyBytes` must be a positive integer");
  }
  // WR-56: split-plane config is validated once at startup, so a bad port
  // or host can never surface as a half-bound relay mid-flight.
  const operatorPlane = opts.operatorPort;
  if (operatorPlane !== undefined) {
    if (
      !Number.isInteger(operatorPlane.port) ||
      operatorPlane.port < 0 ||
      operatorPlane.port > 65535
    ) {
      throw new RangeError("createRelayServer: `operatorPort.port` must be an integer 0-65535");
    }
    if (
      operatorPlane.host !== undefined &&
      (typeof operatorPlane.host !== "string" || operatorPlane.host.length === 0)
    ) {
      throw new RangeError("createRelayServer: `operatorPort.host` must be a non-empty string");
    }
  }
  // WR-84: content-based routing rule engine — validated once at startup
  // (`RangeError` fail-fast on bad rules or a bad default), held by the
  // server closure, hot-swappable atomically via `POST /routing/rules`.
  // Unset entirely when neither option is configured, so intake is
  // byte-identical to the legacy single-target behavior.
  let contentRouteTable: ContentRouteTable | undefined;
  if (opts.contentRoutes !== undefined || opts.contentRouteDefault !== undefined) {
    contentRouteTable = new ContentRouteTable(opts.contentRoutes ?? [], opts.contentRouteDefault);
  }
  // When the caller does not inject a sender, the server owns the default
  // sender — and with it the keep-alive pool, which is closed on server
  // close so pooled outbound connections never outlive the server. The
  // outbound-signing config (validated by createDefaultSender) applies to
  // the default sender only; an injected sender signs on its own.
  // WR-73: the cert-expiry monitor is always constructed but inert
  // unless enabled; every edge-triggered `cert_expiring` event lands in
  // the audit log. Invalid values throw RangeError at startup.
  const certExpiryMonitor = new CertExpiryMonitor(resolveCertExpiryOptions(opts.tlsCertExpiry), {
    onCertExpiring: (event) => {
      opts.auditLog.append(event);
    },
  });
  // WR-74: the TLS floor monitor is always constructed but inert unless
  // an endpoint configures a floor; every `tls_version_rejected` event
  // lands in the audit log. Invalid floors throw RangeError at startup
  // (see createDefaultSender).
  const tlsVersionMonitor = new TlsVersionMonitor({
    onRejected: (rejection) => {
      opts.auditLog.append({
        event: "tls_version_rejected",
        endpoint: rejection.endpoint,
        negotiatedVersion: rejection.negotiatedVersion,
        requiredMinVersion: rejection.requiredMinVersion,
        at: rejection.at,
      });
    },
  });
  // WR-75: a guarded-compressed delivery was answered 415 and resent
  // as plaintext inside the same attempt — worth an audit line (the
  // downstream does not speak gzip; the operator may want to drop the
  // endpoint from `compressThreshold`), not just a counter. Shared by
  // the main sender and every WR-85 shadow sender copy below
  // (`targetUrl` is whichever downstream answered 415).
  const onGzipFallbackAudit = (info: GzipFallbackInfo) => {
    opts.auditLog.append({
      event: "gzip_fallback_plaintext",
      id: info.id,
      ...(info.traceId !== undefined ? { traceId: info.traceId } : {}),
      targetUrl: info.endpoint,
      bytesSaved: info.bytesSaved,
    });
  };
  // WR-81: an endpoint's E2EE key rotation was picked up at startup —
  // one audit line naming the new primary and the retired keys still
  // inside their grace window. Shared with the shadow sender copies.
  const onE2eeKeyRotatedAudit = (info: E2eeKeyRotatedInfo) => {
    opts.auditLog.append({
      event: "e2ee_key_rotated",
      targetUrl: info.endpoint,
      primaryKeyId: info.primaryKeyId,
      previousKeyIds: info.previousKeyIds,
      graceMs: info.graceMs,
      rotationInProgress: info.rotationInProgress,
    });
  };
  const defaultSender =
    opts.sender === undefined
      ? createDefaultSender(opts.tlsPins, opts.outboundKeepAlive, opts.outboundSigning, opts.proxies, opts.tlsClientCerts, opts.compressOutbound, opts.outboundHttp2, opts.outboundIdempotencyKey, undefined, opts.outboundEncryption, opts.tlsSniOverrides, opts.responseCompression, opts.forwardHeaders, certExpiryMonitor, opts.minTlsVersions, tlsVersionMonitor, opts.compressThreshold, onGzipFallbackAudit, onE2eeKeyRotatedAudit)
      : undefined;
  // WR-50: endpoints the operator may pause/resume over HTTP. The server
  // only ever delivers to these — the intake target plus every
  // per-endpoint-configured target — so anything else is a typo or a
  // probe, and pausing it would be a silent no-op. Fail closed with 404.
  // (Library users hit `queue.pauseEndpoint` directly, which allows any
  // endpoint, including never-seen ones, as a pre-emptive hold.)
  const knownEndpoints = new Set<string>([opts.forwardUrl]);
  {
    const failoverCfg = opts.retry?.failover;
    if (failoverCfg) {
      for (const [primary, cfg] of Object.entries(failoverCfg)) {
        knownEndpoints.add(primary);
        for (const standby of cfg.standbys ?? []) knownEndpoints.add(standby);
      }
    }
    // WR-66: weighted physical targets are real delivery destinations —
    // operators can pause them and the pause-404 validation covers them.
    const weightedCfg = opts.retry?.weighted;
    if (weightedCfg) {
      for (const [endpoint, cfg] of Object.entries(weightedCfg)) {
        knownEndpoints.add(endpoint);
        for (const target of cfg.targets ?? []) knownEndpoints.add(target.targetUrl);
      }
    }
    const validators = opts.retry?.responseValidators;
    if (validators !== undefined && typeof validators === "object") {
      for (const endpoint of Object.keys(validators)) knownEndpoints.add(endpoint);
    }
    for (const record of [opts.tlsPins, opts.tlsClientCerts, opts.compressOutbound, opts.compressThreshold, opts.proxies, opts.outboundEncryption, opts.responseCompression, opts.forwardHeaders, opts.minTlsVersions]) {
      if (record) for (const endpoint of Object.keys(record)) knownEndpoints.add(endpoint);
    }
    for (const endpoint of opts.retry?.probe?.endpoints ?? []) knownEndpoints.add(endpoint);
    for (const endpoint of opts.probe?.endpoints ?? []) knownEndpoints.add(endpoint);
  }
  // WR-72: one field mask backs both the audit log (payload fields) and
  // the queue (captured response bodies); masking always runs before the
  // WR-11 encryptor seals anything.
  if (opts.fieldMask !== undefined) {
    opts.auditLog.setFieldMask(opts.fieldMask);
  }
  // WR-82: the operator key id of the request currently running a
  // mutating operator call, or `undefined` when no operator call is
  // active. `onConfigChange` / `onEndpointPaused` / `onEndpointResumed`
  // fire synchronously inside the queue methods the operator branches
  // call, so setting this around those calls stamps the resulting
  // `endpoint_config_updated` / `endpoint_paused` / `endpoint_resumed`
  // audit events with the right `keyId`. Outside operator calls it is
  // `undefined` and the audit shape is exactly the legacy one (no
  // `keyId` field).
  let activeOperatorKeyId: string | undefined;
  /** Run `fn` as operator `keyId`, stamping any hook-fired audits. */
  const runAsOperator = <T>(keyId: string, fn: () => T): T => {
    const prev = activeOperatorKeyId;
    activeOperatorKeyId = keyId;
    try {
      return fn();
    } finally {
      activeOperatorKeyId = prev;
    }
  };
  // WR-85: translate the server-level `shadowTargets` into queue-level
  // config. Each shadow target gets an independent sender copy — built
  // with the same wire config as the main sender (signing, idempotency
  // key, compression, proxies, HTTP/2, E2EE, header forwarding) but its
  // own keep-alive pools and its own pinning/mTLS identity — so the
  // shadow downstream sees the identical wire request. Invalid values
  // throw `RangeError` here, at startup, never mid-delivery. Note: the
  // copies mirror the *default* sender; with a custom `opts.sender` use
  // the nested `retry.shadowTargets` with hand-built senders instead.
  // An explicit server-level `shadowTargets` wins over the nested
  // `retry.shadowTargets`.
  const shadowTargets: ShadowTargetsConfig | undefined =
    opts.shadowTargets !== undefined
      ? Object.fromEntries(
          Object.entries(opts.shadowTargets).map(([endpoint, targets]) => [
            endpoint,
            targets.map(
              (t): ShadowTargetConfig => ({
                targetUrl: t.targetUrl,
                sender: createDefaultSender(
                  t.tlsPins !== undefined ? { [t.targetUrl]: t.tlsPins } : undefined,
                  opts.outboundKeepAlive,
                  opts.outboundSigning,
                  opts.proxies,
                  t.tlsClientCert !== undefined ? { [t.targetUrl]: t.tlsClientCert } : undefined,
                  opts.compressOutbound,
                  opts.outboundHttp2,
                  opts.outboundIdempotencyKey,
                  undefined,
                  opts.outboundEncryption,
                  opts.tlsSniOverrides,
                  opts.responseCompression,
                  opts.forwardHeaders,
                  certExpiryMonitor,
                  opts.minTlsVersions,
                  tlsVersionMonitor,
                  opts.compressThreshold,
                  onGzipFallbackAudit,
                  onE2eeKeyRotatedAudit
                ),
              })
            ),
          ])
        )
      : opts.retry?.shadowTargets;
  const queue = new RetryQueue({
    sender: opts.sender ?? defaultSender,
    ...(opts.retry ?? {}),
    payloadEncryptor: opts.payloadEncryptor ?? opts.retry?.payloadEncryptor,
    fieldMask: opts.fieldMask ?? opts.retry?.fieldMask,
    // WR-49: an explicit server-level `durableQueueDir` wins over the
    // nested `retry.durableQueueDir`; either way the queue owns the
    // journal. Wrap the caller's hook so every recovery is audited as
    // `queue_restored`, not just observed.
    durableQueueDir: opts.durableQueueDir ?? opts.retry?.durableQueueDir,
    onQueueRestored: (info) => {
      opts.auditLog.append({
        event: "queue_restored",
        dir: info.dir,
        restoredItems: info.restoredItems,
        restoredDeadLetters: info.restoredDeadLetters,
        restoredRetries: info.restoredRetries,
        skippedLines: info.skippedLines,
      });
      opts.retry?.onQueueRestored?.(info);
    },
    // An explicit server-level `autoReplay` wins over the nested
    // `retry.autoReplay`; either way the queue owns the scheduler.
    autoReplay: opts.autoReplay ?? opts.retry?.autoReplay,
    // Wrap the caller's hook so every cron occurrence is audited as
    // `scheduled_fired`, not just observed.
    onScheduledFired: (event) => {
      opts.auditLog.append(event);
      opts.retry?.onScheduledFired?.(event);
    },
    // Wrap the caller's hook so rounds-exhaustion is always audited, not
    // just observed.
    onAutoReplayAudit: (event) => {
      opts.auditLog.append(event);
      opts.retry?.onAutoReplayAudit?.(event);
    },
    // An explicit server-level `deadLetterRetention` wins over the nested
    // `retry.deadLetterRetention`; either way the queue owns the sweeper.
    deadLetterRetention: opts.deadLetterRetention ?? opts.retry?.deadLetterRetention,
    // An explicit server-level `replayEgress` wins over the nested
    // `retry.replayEgress`; either way the queue owns the gate.
    replayEgress: opts.replayEgress ?? opts.retry?.replayEgress,
    // Wrap the caller's hook so every retention purge is audited as
    // `dead_letter_purged`, not just observed.
    onDeadLetterPurged: (event) => {
      opts.auditLog.append(event);
      opts.retry?.onDeadLetterPurged?.(event);
    },
    // Wrap the caller's hook so every deadline expiry is audited as
    // `delivery_deadline_exceeded`, not just observed.
    onDeliveryDeadlineExceeded: (info) => {
      opts.auditLog.append({
        event: "delivery_deadline_exceeded",
        id: info.id,
        traceId: info.traceId,
        ...(info.tenant !== undefined ? { tenant: info.tenant } : {}),
        targetUrl: info.endpoint,
        attempts: info.attempts,
        elapsedMs: info.elapsedMs,
        deadlineMs: info.deadlineMs,
      });
      opts.retry?.onDeliveryDeadlineExceeded?.(info);
    },
    // An explicit server-level `probe` wins over the nested `retry.probe`;
    // either way the queue owns the prober. Wrap the caller's hook so
    // every probe outcome worth auditing lands in the audit log.
    probe: opts.probe ?? opts.retry?.probe,
    // WR-83: an explicit server-level `otlp` wins over the nested
    // `retry.otlp`; either way the queue owns the exporter.
    otlp: opts.otlp ?? opts.retry?.otlp,
    // WR-85: shadow-target dry-run mirroring. `shadowTargets` (computed
    // above) wins over the nested `retry.shadowTargets`; either way the
    // queue owns the dispatcher. Wrap the caller's hooks so every
    // shadow outcome is audited as `shadow_delivered` / `shadow_failed`,
    // not just observed.
    shadowTargets,
    onShadowDelivered: (info) => {
      opts.auditLog.append({
        event: "shadow_delivered",
        id: info.id,
        traceId: info.traceId,
        ...(info.tenant !== undefined ? { tenant: info.tenant } : {}),
        targetUrl: info.endpoint,
        shadowTarget: info.shadowTarget,
        attempts: info.attempts,
      });
      opts.retry?.onShadowDelivered?.(info);
    },
    onShadowFailed: (info) => {
      opts.auditLog.append({
        event: "shadow_failed",
        id: info.id,
        traceId: info.traceId,
        ...(info.tenant !== undefined ? { tenant: info.tenant } : {}),
        targetUrl: info.endpoint,
        shadowTarget: info.shadowTarget,
        attempts: info.attempts,
        error: info.error,
      });
      opts.retry?.onShadowFailed?.(info);
    },
    onProbeAudit: (event) => {
      opts.auditLog.append(event);
      opts.retry?.onProbeAudit?.(event);
    },
    // Wrap the caller's hook so every starvation-guard activation is
    // audited, not just observed.
    onStarvationGuardAudit: (event) => {
      opts.auditLog.append(event);
      opts.retry?.onStarvationGuardAudit?.(event);
    },
    // Wrap the caller's hook so every failover switch is audited, not
    // just observed.
    onFailoverSwitch: (event) => {
      opts.auditLog.append({
        event: "failover_switched",
        endpoint: event.endpoint,
        from: event.from,
        to: event.to,
        reason: event.reason,
        at: event.at,
      });
      opts.retry?.onFailoverSwitch?.(event);
    },
    // An explicit server-level `completionCallback` wins over the nested
    // `retry.completionCallback`; either way the queue owns the sender.
    // Wrap the caller's hook so every exhausted receipt is audited as
    // `callback_failed`, not just observed. Receipts never enter the
    // retry queue or the dead-letter list — a failing callback cannot
    // recurse into the delivery machinery.
    completionCallback: opts.completionCallback ?? opts.retry?.completionCallback,
    onCompletionCallbackFailed: (info) => {
      opts.auditLog.append({
        event: "callback_failed",
        id: info.id,
        traceId: info.traceId,
        ...(info.tenant !== undefined ? { tenant: info.tenant } : {}),
        targetUrl: info.targetUrl,
        terminalState: info.terminalState,
        attempts: info.attempts,
        error: info.error,
      });
      opts.retry?.onCompletionCallbackFailed?.(info);
    },
    // Wrap the caller's onSloMiss so every SLO miss is audited, not just observed.
    // WR-71: same treatment for onSloRisk — every early-warning
    // transition is audited as `slo_risk` (state "elevated" / "cleared"),
    // not just observed.
    latency: latencyOpts
      ? {
          ...latencyOpts,
          onSloMiss: (info) => {
            opts.auditLog.append({ event: "slo_missed", ...info });
            latencyOpts.onSloMiss?.(info);
          },
          ...(latencyOpts.sloRisk
            ? {
                sloRisk: {
                  ...latencyOpts.sloRisk,
                  onSloRisk: (info) => {
                    opts.auditLog.append({ event: "slo_risk", ...info });
                    latencyOpts.sloRisk?.onSloRisk?.(info);
                  },
                },
              }
            : {}),
        }
      : undefined,
    onDelivered: (item, attempts, summary) => {
      opts.auditLog.append({
        event: "delivered",
        id: item.id,
        traceId: item.traceId,
        ...(item.tenantId !== undefined ? { tenant: item.tenantId } : {}),
        targetUrl: item.targetUrl,
        attempts,
        // WR-54: downstream response summary — statusCode, responseBytes,
        // timeToFirstByteMs, bodyFingerprintSha256. `capturedBody` (the
        // sealed full body) appears only with the
        // `retry.responseBodyCapture` opt-in plus a payloadEncryptor;
        // unmeasured fields are honestly "unavailable".
        response_summary: summary,
      });
    },
    // Wrap the caller's onSemanticFailure so every semantic failure is
    // audited as `failed` with reason `semantic_failed`, not just observed.
    onSemanticFailure: (info) => {
      opts.auditLog.append({
        event: "failed",
        id: info.id,
        traceId: info.traceId,
        ...(info.tenant !== undefined ? { tenant: info.tenant } : {}),
        targetUrl: info.endpoint,
        attempts: info.attempts,
        reason: "semantic_failed",
        semanticReason: info.reason,
      });
      opts.retry?.onSemanticFailure?.(info);
    },
    // Wrap the caller's onRetryBudgetDepleted so every budget-parked retry
    // is audited, not just observed.
    onRetryBudgetDepleted: (info) => {
      opts.auditLog.append({
        event: "retry_budget_depleted",
        id: info.id,
        traceId: info.traceId,
        ...(info.tenant !== undefined ? { tenant: info.tenant } : {}),
        targetUrl: info.endpoint,
        attempts: info.attempts,
        waitMs: info.waitMs,
      });
      opts.retry?.onRetryBudgetDepleted?.(info);
    },
    // Wrap the caller's onAttemptFailed so every failed attempt that
    // schedules a retry is audited as `retrying` with its error and the
    // scheduled delay — the retry trajectory behind
    // `GET /deliveries/:traceId` (WR-43).
    onAttemptFailed: (info) => {
      opts.auditLog.append({
        event: "retrying",
        id: info.id,
        traceId: info.traceId,
        ...(info.tenant !== undefined ? { tenant: info.tenant } : {}),
        targetUrl: info.endpoint,
        attempts: info.attempts,
        error: info.error,
        nextDelayMs: info.nextDelayMs,
      });
      opts.retry?.onAttemptFailed?.(info);
    },
    onDeadLetter: (item, attempts, lastError, failureClass, summary) => {
      opts.auditLog.append({
        event: "dead_letter",
        id: item.id,
        traceId: item.traceId,
        ...(item.tenantId !== undefined ? { tenant: item.tenantId } : {}),
        targetUrl: item.targetUrl,
        attempts,
        error: lastError instanceof Error ? lastError.message : String(lastError),
        // "non_retryable" = poison payload dead-lettered on the first
        // attempt (no retry budget burned); "retryable" = every attempt
        // spent against a transient failure.
        failure_class: failureClass ?? "retryable",
        // WR-54: last attempt's response summary — only statusCode is
        // known (from the failing HTTP response); the rest is honestly
        // "unavailable". Never carries a body.
        response_summary: summary,
      });
    },
    onCircuitStateChange: (endpoint, from, to, tenant) => {
      const event =
        to === "open" ? "circuit_open" : to === "half_open" ? "circuit_half_open" : "circuit_closed";
      opts.auditLog.append({
        event,
        endpoint,
        ...(tenant !== undefined ? { tenant } : {}),
        from,
        to,
      });
      opts.retry?.onCircuitStateChange?.(endpoint, from, to, tenant);
    },
    // Wrap the caller's onConfigChange so every runtime config change is
    // audited, not just observed.
    onConfigChange: (endpoint, changes) => {
      opts.auditLog.append({
        event: "endpoint_config_updated",
        endpoint,
        changes,
        ...(activeOperatorKeyId !== undefined ? { keyId: activeOperatorKeyId } : {}),
      });
      opts.retry?.onConfigChange?.(endpoint, changes);
    },
    // Wrap the caller's pause hooks so every pause/resume transition is
    // audited as `endpoint_paused` / `endpoint_resumed`, not just
    // observed. Edge-triggered in the queue — idempotent no-ops audit
    // nothing.
    onEndpointPaused: ({ endpoint }) => {
      opts.auditLog.append({
        event: "endpoint_paused",
        endpoint,
        ...(activeOperatorKeyId !== undefined ? { keyId: activeOperatorKeyId } : {}),
      });
      opts.retry?.onEndpointPaused?.({ endpoint });
    },
    onEndpointResumed: ({ endpoint }) => {
      opts.auditLog.append({
        event: "endpoint_resumed",
        endpoint,
        ...(activeOperatorKeyId !== undefined ? { keyId: activeOperatorKeyId } : {}),
      });
      opts.retry?.onEndpointResumed?.({ endpoint });
    },
    // Wrap the caller's onBatch so every flushed batch is audited, not just observed.
    onBatch: (info) => {
      opts.auditLog.append({
        event: "batch_flushed",
        batchId: info.batchId,
        traceId: info.traceIds.length === 1 ? info.traceIds[0] : undefined,
        traceIds: info.traceIds,
        targetUrl: info.endpoint,
        size: info.size,
      });
      opts.retry?.onBatch?.(info);
    },
  });
  queue.start();
  // WR-55: persistent delivery-event archive. Subscribes to the queue's
  // delivery events and appends every event to `<dir>/events.jsonl`
  // (survives restarts; served at `GET /events/archive`). Unset by
  // default — the endpoint then answers 404 fail-closed.
  const eventArchiver = opts.eventArchive
    ? new DeliveryEventArchiver({
        ...opts.eventArchive,
        source: { subscribeDeliveryEvents: (l) => queue.subscribeDeliveryEvents(l) },
      })
    : undefined;
  // WR-78: tenant usage metering for usage-based billing. One permanent
  // subscription feeds the meter from the queue's delivery events
  // (delivered / retrying / dead_letter per tenant); intake records
  // bytes_in via recordInbound in admitOneEvent. The meter never gates or
  // delays — it only counts. Validated once at startup (RangeError on bad
  // values), like every other module above.
  const usageMeter = opts.usage !== undefined ? new UsageMeter(opts.usage) : undefined;
  if (usageMeter !== undefined) {
    queue.subscribeDeliveryEvents((event) => usageMeter.recordDeliveryEvent(event));
  }

  const verifier: Verifier =
    opts.signingKeys !== undefined
      ? (() => {
          if (opts.verifier !== undefined) {
            throw new Error("createRelayServer: `verifier` and `signingKeys` cannot be combined");
          }
          return new RotatingHmacVerifier({
            keys: opts.signingKeys,
            graceMs: opts.keyGraceMs,
            nowMs: opts.keyNowMs,
          });
        })()
      : (opts.verifier ?? new HmacSha256Verifier(opts.secret));
  // Per-endpoint verifier rules are validated once at startup so a bad
  // pattern or verifier can never fail a request mid-flight.
  assertValidEndpointVerifierRules(opts.endpointVerifiers);
  // WR-67: dual-secret rotation rules are validated and compiled once at
  // startup for the same reason — and compiling once pins the
  // previous-secret grace window of rules without previousRetiredAtMs to
  // server start instead of restarting it per request.
  assertValidSecretRotationRules(opts.secretRotation);
  const secretRotations = compileSecretRotationRules(opts.secretRotation);
  // API version routes are validated once at startup for the same reason.
  const versionRouter =
    opts.versions !== undefined ? new ApiVersionRouter(opts.versions.routes) : undefined;
  const versionMetrics = new VersionMetrics();
  // Schema registry rules are validated once at startup for the same reason.
  assertValidEndpointSchemaRules(opts.payloadSchemas);
  const schemaMetrics = new SchemaMetrics();
  const deduplicator = opts.dedup ? new DeliveryDeduplicator(opts.dedup) : undefined;
  const rateLimiter = opts.rateLimit ? new InboundRateLimiter(opts.rateLimit) : undefined;
  // Inbound IP allowlist/denylist (WR-53): rules and trusted proxies are
  // validated (and every CIDR pre-parsed) once at startup, so a bad CIDR
  // can never fail a request mid-flight.
  const ipAcl = opts.ipAcl !== undefined ? new InboundIpAcl(opts.ipAcl) : undefined;
  const ipAclMetrics = new IpAclMetrics();
  // Inbound per-endpoint API key authentication (WR-65): rules are
  // validated (constant-time comparison needs no precomputation, so this
  // is pure validation) once at startup, so a bad pattern or key entry
  // can never fail a request mid-flight.
  const apiKeyAuth = opts.apiKeys !== undefined ? new InboundApiKeyAuth(opts.apiKeys) : undefined;
  // Scoped operator API keys (WR-82): validated once at startup so a bad
  // scope, empty id/key, or duplicate id/key can never fail a request
  // mid-flight.
  assertValidOperatorKeys(opts.operatorKeys);
  // Inbound source baseline anomaly detection (WR-63): validated once at
  // startup so bad config can never fail a request mid-flight. Alert-only
  // — it never rejects — so it is orthogonal to the WR-53 IP ACL above.
  const sourceBaseline =
    opts.sourceBaseline !== undefined ? new SourceBaselineDetector(opts.sourceBaseline) : undefined;

  const respondJson = (
    res: Parameters<Parameters<typeof createServer>[0]>[1],
    status: number,
    body: unknown
  ): void => {
    res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
  };

  /** SSE live stream of delivery lifecycle events for operators. */
  const streamDeliveryEvents = (
    req: Parameters<Parameters<typeof createServer>[0]>[0],
    res: Parameters<Parameters<typeof createServer>[0]>[1]
  ): void => {
    // WR-48: `?tenant=` subscribes to one tenant's stream only.
    const tenantFilter =
      new URL(req.url ?? "/events", "http://internal").searchParams.get("tenant") ?? undefined;
    res.writeHead(200, {
      "content-type": "text/event-stream",
      "cache-control": "no-cache",
      connection: "keep-alive",
      // Tell buffering proxies (e.g. nginx) not to hold frames back.
      "x-accel-buffering": "no",
    });
    // A comment frame right away: some clients only consider the stream
    // open once the first bytes arrive.
    res.write(": connected\n\n");
    let closed = false;
    const heartbeat = setInterval(() => {
      if (!closed) res.write(": ping\n\n");
    }, opts.events?.heartbeatMs ?? 15_000);
    // Never let an idle dashboard pin the process open.
    (heartbeat as unknown as { unref?: () => unknown }).unref?.();
    const cleanup = (): void => {
      if (closed) return;
      closed = true;
      clearInterval(heartbeat);
      unsubscribe();
    };
    const unsubscribe = queue.subscribeDeliveryEvents((event) => {
      if (closed) return;
      if (tenantFilter !== undefined && event.tenant !== tenantFilter) return;
      // Slow-consumer guard: a dashboard that cannot keep up gets
      // disconnected instead of buffering without bound.
      if (res.writableLength > 1_048_576) {
        cleanup();
        res.end();
        return;
      }
      res.write(`event: delivery\ndata: ${JSON.stringify(event)}\n\n`);
    });
    req.on("close", cleanup);
    res.on("close", cleanup);
  };

  /** Operator surface: dead-letter queue + audit-log queries + live event stream. */
  const handleOperator = async (
    req: Parameters<Parameters<typeof createServer>[0]>[0],
    res: Parameters<Parameters<typeof createServer>[0]>[1],
    pathname: string
  ): Promise<void> => {
    // Scoped operator authentication (WR-82): the legacy single
    // `operatorToken` authenticates with full `admin` semantics (key id
    // `"legacy"`), or any `operatorKeys` ring entry authenticates with
    // its own scopes. Neither configured → 404 fail-closed, exactly the
    // legacy behavior; a non-matching bearer → 403. Key comparison is
    // constant-time (see `src/operator-keys.ts`).
    const operatorKeys = opts.operatorKeys ?? [];
    const operatorEnabled =
      (opts.operatorToken !== undefined && opts.operatorToken !== "") ||
      operatorKeys.length > 0;
    if (!operatorEnabled) {
      respondJson(res, 404, { error: "operator endpoints disabled" });
      return;
    }
    const identity = matchOperatorKey(
      bearerToken(req.headers["authorization"]),
      opts.operatorToken,
      operatorKeys
    );
    if (identity === null) {
      respondJson(res, 403, { error: "forbidden" });
      return;
    }
    const operatorKeyId = identity.id;
    const isList = pathname === "/dead-letter";
    const isStats = pathname === "/dead-letter/stats";
    const isBatchReplay = pathname === "/dead-letter/replay";
    const isAudit = pathname === "/audit";
    const isAuditVerify = pathname === "/audit/verify";
    const isLatency = pathname === "/latency";
    const isSloRisk = pathname === "/slo-risk";
    const isUsage = pathname === "/usage";
    const isEvents = pathname === "/events";
    const isEventsArchive = pathname === "/events/archive";
    const isMetrics = pathname === "/metrics";
    const isAutoStatus = pathname === "/dead-letter/auto-replay/status";
    const isAutoPause = pathname === "/dead-letter/auto-replay/pause";
    const isAutoResume = pathname === "/dead-letter/auto-replay/resume";
    const isAutoTrigger = pathname === "/dead-letter/auto-replay/trigger";
    const isConfigEndpoint = pathname === "/config/endpoint";
    const isRoutingRules = pathname === "/routing/rules";
    const isEndpointsPause = pathname === "/endpoints/pause";
    const isEndpointsResume = pathname === "/endpoints/resume";
    const isScheduledList = pathname === "/scheduled";
    const scheduleActionMatch = /^\/scheduled\/([^/]+)\/(pause|resume)$/.exec(pathname);
    const deliveryMatch = /^\/deliveries\/([^/]+)$/.exec(pathname);
    const replayMatch = /^\/dead-letter\/([^/]+)\/replay$/.exec(pathname);
    if (
      !isList &&
      !isStats &&
      !isBatchReplay &&
      !isAudit &&
      !isAuditVerify &&
      !isLatency &&
      !isSloRisk &&
      !isUsage &&
      !isEvents &&
      !isEventsArchive &&
      !isMetrics &&
      !isAutoStatus &&
      !isAutoPause &&
      !isAutoResume &&
      !isAutoTrigger &&
      !isConfigEndpoint &&
      !isRoutingRules &&
      !isEndpointsPause &&
      !isEndpointsResume &&
      !isScheduledList &&
      !scheduleActionMatch &&
      !deliveryMatch &&
      !replayMatch
    ) {
      respondJson(res, 404, { error: "not found" });
      return;
    }
    if (
      !(
        (isList && req.method === "GET") ||
        (isStats && req.method === "GET") ||
        (isBatchReplay && req.method === "POST") ||
        (isAudit && req.method === "GET") ||
        (isAuditVerify && req.method === "GET") ||
        (isLatency && req.method === "GET") ||
        (isSloRisk && req.method === "GET") ||
        (isUsage && req.method === "GET") ||
        (isEvents && req.method === "GET") ||
        (isEventsArchive && req.method === "GET") ||
        (isMetrics && req.method === "GET") ||
        (isAutoStatus && req.method === "GET") ||
        (isAutoPause && req.method === "POST") ||
        (isAutoResume && req.method === "POST") ||
        (isAutoTrigger && req.method === "POST") ||
        (isConfigEndpoint && req.method === "POST") ||
        (isRoutingRules && (req.method === "GET" || req.method === "POST")) ||
        (isEndpointsPause && req.method === "POST") ||
        (isEndpointsResume && req.method === "POST") ||
        (isScheduledList && req.method === "GET") ||
        (scheduleActionMatch && req.method === "POST") ||
        (deliveryMatch && req.method === "GET") ||
        (replayMatch && req.method === "POST")
      )
    ) {
      respondJson(res, 405, { error: "method not allowed" });
      return;
    }
    // WR-82 scope check: every recognized GET operator path is read-only
    // (`read` suffices), every recognized POST operator path is mutating
    // (needs `admin`) — the method-allowed list above makes GET/POST
    // disjoint across operator paths. A scopeless key is fail-closed: it
    // authenticated above, but every operator path answers 403 here.
    if (!operatorMay(identity, req.method ?? "")) {
      respondJson(res, 403, { error: "forbidden" });
      return;
    }
    if (isBatchReplay) {
      let body: Record<string, unknown>;
      try {
        // The body limit applies here too: operator bodies are small, and
        // an unbounded read on an authenticated endpoint is a cheap DoS.
        const raw = (await readRawBody(req, maxBodyBytes)).toString("utf8");
        body = raw.trim() === "" ? {} : JSON.parse(raw);
      } catch (err) {
        if (err instanceof BodyTooLargeError) {
          respondJson(res, 413, { error: "request body too large" });
          return;
        }
        respondJson(res, 400, { error: "invalid JSON body" });
        return;
      }
      if (typeof body !== "object" || body === null || Array.isArray(body)) {
        respondJson(res, 400, { error: "body must be a JSON object" });
        return;
      }
      const { endpoint, ids, dryRun } = body;
      if (endpoint !== undefined && typeof endpoint !== "string") {
        respondJson(res, 400, { error: "endpoint must be a string" });
        return;
      }
      if (
        ids !== undefined &&
        (!Array.isArray(ids) || ids.some((i) => typeof i !== "string"))
      ) {
        respondJson(res, 400, { error: "ids must be an array of strings" });
        return;
      }
      if (dryRun !== undefined && typeof dryRun !== "boolean") {
        respondJson(res, 400, { error: "dryRun must be a boolean" });
        return;
      }
      const filter = {
        ...(endpoint !== undefined ? { endpoint } : {}),
        ...(ids !== undefined ? { ids: ids as string[] } : {}),
      };
      if (dryRun === true) {
        // Dry run: metadata-only preview, zero side effects — nothing is
        // re-queued, nothing is audited, payloads are never touched.
        respondJson(res, 200, {
          dryRun: true,
          entries: queue.replayDeadLetters(filter, { dryRun: true }),
        });
        return;
      }
      const result = queue.replayDeadLetters(filter);
      opts.auditLog.append({
        event: "dead_letter_batch_replayed",
        keyId: operatorKeyId,
        replayed: result.replayed,
        failed: result.failed,
        ...(endpoint !== undefined ? { endpoint } : {}),
      });
      respondJson(res, 200, { replayed: result.replayed, failed: result.failed });
      return;
    }
    if (isMetrics) {
      // Prometheus scrapes this; it sits behind the same bearer token as
      // the other operator endpoints (fail closed without operatorToken).
      // The version-routing counters render "" when versioning was never
      // configured, keeping the output byte-identical to the legacy shape.
      res
        .writeHead(200, { "content-type": "text/plain; version=0.0.4" })
        .end(queue.renderMetrics() + versionMetrics.render() + schemaMetrics.render() + ipAclMetrics.render() + certExpiryMonitor.render() + tlsVersionMonitor.render() + (usageMeter?.render() ?? "") + (defaultSender?.compressionStats.render() ?? ""));
      return;
    }
    if (isEvents) {
      streamDeliveryEvents(req, res);
      return;
    }
    if (isEventsArchive) {
      // WR-55: persistent delivery-event history. The shared operator-token
      // check above already ran (404 when no operatorToken is configured,
      // 403 on a bad bearer), so an unconfigured archive 404s here without
      // leaking its existence to unauthenticated callers.
      if (!eventArchiver) {
        respondJson(res, 404, { error: "event archive is not configured" });
        return;
      }
      const params = new URL(req.url ?? "/events/archive", "http://internal").searchParams;
      const eventRaw = params.get("event");
      if (
        eventRaw !== null &&
        eventRaw !== "delivered" &&
        eventRaw !== "retrying" &&
        eventRaw !== "dead_letter"
      ) {
        respondJson(res, 400, { error: "invalid event" });
        return;
      }
      let entries: object[];
      try {
        entries = eventArchiver.query({
          since: params.get("since") ?? undefined,
          until: params.get("until") ?? undefined,
          // Exact match on targetUrl (documented; no substring matching).
          endpoint: params.get("endpoint") ?? undefined,
          event: (eventRaw ?? undefined) as "delivered" | "retrying" | "dead_letter" | undefined,
        });
      } catch {
        respondJson(res, 400, { error: "invalid query parameters" });
        return;
      }
      respondJson(res, 200, entries);
      return;
    }
    if (isLatency) {
      const params = new URL(req.url ?? "/latency", "http://internal").searchParams;
      respondJson(
        res,
        200,
        queue.getLatencyStats(
          params.get("endpoint") ?? undefined,
          params.get("tenant") ?? undefined
        )
      );
      return;
    }
    if (isSloRisk) {
      // WR-71: SLO-breach early-warning snapshot — one row per endpoint
      // with at least one risk evaluation. Guarded by the same
      // operator-token check as the other operator endpoints
      // (fail-closed without operatorToken).
      const params = new URL(req.url ?? "/slo-risk", "http://internal").searchParams;
      respondJson(res, 200, queue.getSloRiskStats(params.get("tenant") ?? undefined));
      return;
    }
    if (isUsage) {
      // WR-78: tenant usage metering for usage-based billing — rolling
      // window per-tenant counters (delivered/failed/retried/dead_letter,
      // bytes_in/bytes_out, urgent). Same operator-token guard as the
      // other operator endpoints (404 when no operatorToken — fail
      // closed); when the meter itself is unconfigured the endpoint 404s
      // without leaking anything.
      if (usageMeter === undefined) {
        respondJson(res, 404, { error: "usage metering is not configured" });
        return;
      }
      const params = new URL(req.url ?? "/usage", "http://internal").searchParams;
      respondJson(res, 200, usageMeter.snapshot(params.get("tenant") ?? undefined));
      return;
    }
    if (isScheduledList) {
      // WR-57: pending scheduled deliveries — operator metadata only
      // (id, targetUrl, deliverAt, traceId, tenant, priority). The payload
      // is never exposed here. WR-80: recurring schedules are included
      // with `recurring: true` plus `cron` / `nextAt` / `paused`.
      respondJson(res, 200, queue.getScheduled());
      return;
    }
    if (scheduleActionMatch) {
      // WR-80: pause/resume a recurring cron schedule. Pausing stops
      // occurrence generation (already-generated deliveries are
      // unaffected); resuming computes the next occurrence from now —
      // missed cycles are skipped, never backfilled. Unknown schedule
      // ids are a fail-closed 404; transitions are audited.
      const scheduleId = decodeURIComponent(scheduleActionMatch[1]);
      const action = scheduleActionMatch[2];
      const ok =
        action === "pause" ? queue.pauseSchedule(scheduleId) : queue.resumeSchedule(scheduleId);
      if (!ok) {
        respondJson(res, 404, { error: "unknown schedule" });
        return;
      }
      opts.auditLog.append({
        event: action === "pause" ? "schedule_paused" : "schedule_resumed",
        keyId: operatorKeyId,
        id: scheduleId,
        ...(action === "resume"
          ? {
              nextAtMs: queue.nextScheduleFire(scheduleId),
              nextAt:
                queue.nextScheduleFire(scheduleId) !== undefined
                  ? new Date(queue.nextScheduleFire(scheduleId)!).toISOString()
                  : undefined,
            }
          : {}),
      });
      respondJson(res, 200, { id: scheduleId, paused: action === "pause" });
      return;
    }
    if (isAudit) {
      const params = new URL(req.url ?? "/audit", "http://internal").searchParams;
      const events = params.getAll("event");
      const limitRaw = params.get("limit");
      let limit: number | undefined;
      if (limitRaw !== null) {
        limit = Number(limitRaw);
        if (!Number.isInteger(limit) || limit < 1) {
          respondJson(res, 400, { error: "invalid limit" });
          return;
        }
      }
      let entries: object[];
      try {
        entries = opts.auditLog.query({
          endpoint: params.get("endpoint") ?? undefined,
          tenant: params.get("tenant") ?? undefined,
          traceId: params.get("traceId") ?? undefined,
          since: params.get("since") ?? undefined,
          until: params.get("until") ?? undefined,
          event: events.length > 0 ? events : undefined,
          limit,
        });
      } catch {
        respondJson(res, 400, { error: "invalid query parameters" });
        return;
      }
      respondJson(res, 200, entries);
      return;
    }
    if (isAuditVerify) {
      // WR-77: tamper-evidence report for the audit log's hash chain. Behind
      // the same operatorToken guard as the other operator endpoints (404
      // when no operatorToken is configured — fail closed).
      respondJson(res, 200, opts.auditLog.verifyChain());
      return;
    }
    if (deliveryMatch) {
      // Per-trace delivery lifecycle snapshot (WR-43): aggregates the
      // audit trail for one trace ID into {state, timeline, attempts,
      // lastError, latencyMs, retry trajectory, replay records}. The
      // aggregation reads through the WR-04 line-offset index — only
      // matching audit lines are read, never the whole file.
      const rawTraceId = deliveryMatch[1];
      let traceId: string;
      try {
        traceId = decodeURIComponent(rawTraceId);
      } catch {
        respondJson(res, 400, { error: "invalid traceId" });
        return;
      }
      if (traceId.length === 0) {
        respondJson(res, 404, { error: "not found" });
        return;
      }
      const snapshot = buildDeliverySnapshot(opts.auditLog, traceId);
      if (snapshot === null) {
        respondJson(res, 404, {
          error: "unknown traceId",
          hint: "query GET /audit?traceId=<id> for the raw audit trail, or check the x-trace-id echoed in the 202 response body",
        });
        return;
      }
      respondJson(res, 200, snapshot);
      return;
    }
    if (isList) {
      // WR-48: `?tenant=` filters the dead-letter list to one tenant.
      const dlTenant =
        new URL(req.url ?? "/dead-letter", "http://internal").searchParams.get("tenant") ?? undefined;
      respondJson(
        res,
        200,
        queue
          .getDeadLetter()
          .filter((e) => dlTenant === undefined || e.tenantId === dlTenant)
          .map((e) => ({
            id: e.id,
            targetUrl: e.targetUrl,
            ...(e.tenantId !== undefined ? { tenant: e.tenantId } : {}),
            attempts: e.attempts,
            lastError: e.lastError,
            deadLetteredAt: e.deadLetteredAt,
            payloadBytes: e.payloadBytes,
            encrypted: e.encryptedPayload !== undefined,
          }))
      );
      return;
    }
    if (isStats) {
      // WR-64: dead-letter observability — live entries, retention
      // purges so far, and live entries per logical endpoint.
      respondJson(res, 200, queue.getDeadLetterStats());
      return;
    }
    if (isAutoStatus || isAutoPause || isAutoResume || isAutoTrigger) {
      const replayer = queue.getAutoReplayer();
      if (isAutoStatus) {
        // Status is readable even when the scheduler was never configured:
        // `enabled: false` explains why there is nothing to control.
        respondJson(
          res,
          200,
          replayer
            ? replayer.status()
            : {
                enabled: false,
                paused: false,
                stopped: false,
                consecutiveEmptyRounds: 0,
                totalReplayed: 0,
                lastRunAt: null,
                nextRunAt: null,
              }
        );
        return;
      }
      if (!replayer) {
        respondJson(res, 404, { error: "dead-letter auto-replay is not configured" });
        return;
      }
      if (isAutoPause) {
        // Pause freezes the schedule with state retained: a pending round
        // is cancelled, but the rounds counter and totals survive for
        // resume.
        replayer.pause();
        respondJson(res, 200, { paused: true });
        return;
      }
      if (isAutoResume) {
        // Resuming a rounds-exhausted scheduler is the operator's explicit
        // "try again": the counter resets to 0 and the schedule restarts.
        const { restarted } = replayer.resume();
        respondJson(res, 200, { paused: false, restarted });
        return;
      }
      // isAutoTrigger: one round immediately, outside the schedule. It goes
      // through the same accounting as a scheduled round — an empty trigger
      // increments the empty-round counter, a successful one resets it, and
      // it can itself trigger the rounds-exhausted stop (audited as
      // `dead_letter_auto_replay`). A stopped scheduler ignores it.
      const round = replayer.triggerOnce();
      respondJson(res, 200, {
        replayed: round.replayed,
        failed: round.failed,
        consecutiveEmptyRounds: round.consecutiveEmptyRounds,
        stopped: round.stopped,
      });
      return;
    }
    if (isConfigEndpoint) {
      // Runtime endpoint config hot reload (WR-32): body is
      // `{ endpoint, ...patch }`. The body limit applies to operator
      // bodies too; a RangeError from updateEndpointConfig (illegal values
      // or a disabled subsystem) surfaces as a 400 — the queue guarantees
      // no partial application on validation failure, so a 400 always
      // means "nothing changed". Applied changes are audited as
      // `endpoint_config_updated` by the onConfigChange hook.
      // WR-48: an optional `tenant` scopes the patch to that tenant's
      // instance; without it the default tenant is patched.
      let body: Record<string, unknown>;
      try {
        const raw = (await readRawBody(req, maxBodyBytes)).toString("utf8");
        body = raw.trim() === "" ? {} : JSON.parse(raw);
      } catch (err) {
        if (err instanceof BodyTooLargeError) {
          respondJson(res, 413, { error: "request body too large" });
          return;
        }
        respondJson(res, 400, { error: "invalid JSON body" });
        return;
      }
      if (typeof body !== "object" || body === null || Array.isArray(body)) {
        respondJson(res, 400, { error: "body must be a JSON object" });
        return;
      }
      const { endpoint, tenant, ...patch } = body;
      if (typeof endpoint !== "string" || endpoint.length === 0) {
        respondJson(res, 400, { error: "endpoint must be a non-empty string" });
        return;
      }
      if (tenant !== undefined) {
        try {
          assertValidTenantId(tenant as string);
        } catch {
          respondJson(res, 400, { error: "invalid tenant" });
          return;
        }
      }
      try {
        // WR-82: the `onConfigChange` hook fires synchronously inside
        // `updateEndpointConfig`, so running it as this operator stamps
        // the `endpoint_config_updated` audit with the right `keyId`.
        const changes = runAsOperator(operatorKeyId, () =>
          queue.updateEndpointConfig(
            endpoint,
            patch as EndpointConfigPatch,
            tenant as string | undefined
          )
        );
        respondJson(res, 200, { endpoint, ...(tenant !== undefined ? { tenant } : {}), changes });
      } catch (err) {
        if (err instanceof RangeError) {
          respondJson(res, 400, { error: err.message });
          return;
        }
        throw err;
      }
      return;
    }
    if (isRoutingRules) {
      // Content-based routing rules (WR-84): `GET` lists the live table
      // (`{ rules, defaultTargetUrl }`, read scope); `POST` replaces it
      // wholesale (`{ rules: [...], defaultTargetUrl?: string }`, admin
      // scope). The body limit applies here too; a `RangeError` from
      // construction (illegal rules or default) surfaces as a 400 — the
      // constructor validates before anything is swapped, so a 400 always
      // means "nothing changed". A successful replacement is audited as
      // `routing_rules_updated` with the operator's `keyId`.
      if (req.method === "GET") {
        const snapshot = contentRouteTable;
        respondJson(res, 200, {
          rules: snapshot?.getRules() ?? [],
          ...(snapshot?.getDefaultTargetUrl() !== undefined
            ? { defaultTargetUrl: snapshot.getDefaultTargetUrl() }
            : {}),
        });
        return;
      }
      let body: Record<string, unknown>;
      try {
        const raw = (await readRawBody(req, maxBodyBytes)).toString("utf8");
        body = raw.trim() === "" ? {} : JSON.parse(raw);
      } catch (err) {
        if (err instanceof BodyTooLargeError) {
          respondJson(res, 413, { error: "request body too large" });
          return;
        }
        respondJson(res, 400, { error: "invalid JSON body" });
        return;
      }
      if (typeof body !== "object" || body === null || Array.isArray(body)) {
        respondJson(res, 400, { error: "body must be a JSON object" });
        return;
      }
      try {
        contentRouteTable = new ContentRouteTable(
          body.rules as ContentRouteRule[],
          body.defaultTargetUrl as string | undefined
        );
      } catch (err) {
        if (err instanceof RangeError) {
          respondJson(res, 400, { error: err.message });
          return;
        }
        throw err;
      }
      const applied = contentRouteTable;
      opts.auditLog.append({
        event: "routing_rules_updated",
        keyId: operatorKeyId,
        ruleCount: applied.getRules().length,
        ...(applied.getDefaultTargetUrl() !== undefined
          ? { defaultTargetUrl: applied.getDefaultTargetUrl() }
          : {}),
      });
      respondJson(res, 200, {
        rules: applied.getRules(),
        ...(applied.getDefaultTargetUrl() !== undefined
          ? { defaultTargetUrl: applied.getDefaultTargetUrl() }
          : {}),
      });
      return;
    }
    if (isEndpointsPause || isEndpointsResume) {
      // WR-50: operator pause/resume switch. Body is `{ endpoint }`.
      // Pausing parks the endpoint's deliveries (queued items stay
      // queued, new events park, nothing is attempted, budgeted, or
      // dead-lettered); resuming re-arms them with their remaining
      // delays. Transitions are audited as `endpoint_paused` /
      // `endpoint_resumed` by the queue hooks. Unknown endpoints are a
      // fail-closed 404 — pausing a typo must be loud, not a silent
      // no-op (the queue-level API still allows pre-emptive pauses of
      // never-seen endpoints for library users).
      let body: Record<string, unknown>;
      try {
        const raw = (await readRawBody(req, maxBodyBytes)).toString("utf8");
        body = raw.trim() === "" ? {} : JSON.parse(raw);
      } catch (err) {
        if (err instanceof BodyTooLargeError) {
          respondJson(res, 413, { error: "request body too large" });
          return;
        }
        respondJson(res, 400, { error: "invalid JSON body" });
        return;
      }
      if (typeof body !== "object" || body === null || Array.isArray(body)) {
        respondJson(res, 400, { error: "body must be a JSON object" });
        return;
      }
      const { endpoint } = body;
      if (typeof endpoint !== "string" || endpoint.length === 0) {
        respondJson(res, 400, { error: "endpoint must be a non-empty string" });
        return;
      }
      if (!knownEndpoints.has(endpoint)) {
        respondJson(res, 404, { error: "unknown endpoint" });
        return;
      }
      // WR-82: the pause/resume hooks fire synchronously inside the
      // queue calls, so `runAsOperator` stamps the `endpoint_paused` /
      // `endpoint_resumed` audit with this call's `keyId`.
      if (isEndpointsPause) {
        runAsOperator(operatorKeyId, () => queue.pauseEndpoint(endpoint));
        respondJson(res, 200, { endpoint, paused: true });
      } else {
        runAsOperator(operatorKeyId, () => queue.resumeEndpoint(endpoint));
        respondJson(res, 200, { endpoint, paused: false });
      }
      return;
    }
    const id = decodeURIComponent(replayMatch![1]);
    if (queue.replayDeadLetter(id)) {
      opts.auditLog.append({ event: "dead_letter_replayed", keyId: operatorKeyId, id });
      respondJson(res, 200, { id, replayed: true });
    } else {
      respondJson(res, 404, { error: "unknown dead-letter id" });
    }
  };

  /**
   * Intake pipeline: everything below the operator/intake plane split.
   * Shared by the legacy single-plane listener and the split-plane intake
   * listener, so both planes admit webhooks identically.
   */
  /**
   * WR-61: the intake gates shared by the single-webhook and batch
   * ingestion paths — IP allowlist (WR-53), inbound rate limiting
   * (WR-22), and the body-size cap (WR-25). Runs before any signature
   * verification, so a flood costs almost nothing. Writes its own
   * rejection responses; resolves to the raw body on success, or
   * `undefined` when the response was already written.
   */
  /**
   * WR-65: what the intake gates hand downstream — the (possibly capped)
   * body plus the API key auth context, when an API-key rule guarded the
   * endpoint and the request passed the gate.
   */
  interface IntakeGateResult {
    body: Buffer;
    /**
     * The matched API key id and the guarding rule. The rule travels
     * with it so the admission pipeline knows whether the signature
     * check still applies (`requireSignature`) and which `keyId` to
     * audit. Absent when no API-key rule matched this endpoint.
     */
    apiKey?: { keyId: string; rule: EndpointApiKeyRule };
  }

  const runIntakeGates = async (
    req: Parameters<Parameters<typeof createServer>[0]>[0],
    res: Parameters<Parameters<typeof createServer>[0]>[1],
    pathname: string,
    id: string,
    traceId: string
  ): Promise<IntakeGateResult | undefined> => {
    // Inbound IP allowlist/denylist (WR-53): the outermost admission
    // gate — before the body is even read, before rate limiting, before
    // signature verification — so a hostile IP costs us zero bandwidth
    // and zero downstream state. A denial never enqueues, so it burns no
    // retry budget and never trips the breaker.
    if (ipAcl) {
      const clientIp = ipAcl.clientIp(req.socket.remoteAddress, req.headers["x-forwarded-for"]);
      const aclVerdict = ipAcl.check(pathname, clientIp);
      if (!aclVerdict.ok) {
        ipAclMetrics.record(aclVerdict.pattern);
        opts.auditLog.append({
          event: "rejected",
          id,
          traceId,
          reason: "ip_denied",
          ip: clientIp,
          endpoint: aclVerdict.pattern,
        });
        // `connection: close` drops the socket after the 403, so the
        // client cannot keep streaming a flood into a dead request (same
        // rationale as the WR-25 413).
        res
          .writeHead(403, { "content-type": "text/plain", connection: "close" })
          .end("Forbidden");
        return undefined;
      }
    }

    // Inbound per-endpoint API key authentication (WR-65): the second
    // admission gate — on headers alone, before the body is read (like
    // the WR-53 IP ACL), so an unauthenticated caller costs zero
    // bandwidth and zero downstream state. A rejection never enqueues,
    // so it burns no retry budget and never trips the breaker.
    let apiKey: IntakeGateResult["apiKey"];
    if (apiKeyAuth !== undefined) {
      const rule = apiKeyAuth.ruleFor(pathname);
      if (rule !== undefined) {
        const presentedRaw = req.headers["x-api-key"];
        const presented = Array.isArray(presentedRaw) ? presentedRaw[0] : presentedRaw;
        if (typeof presented !== "string" || presented === "") {
          opts.auditLog.append({
            event: "rejected",
            id,
            traceId,
            reason: "api_key_missing",
            keyId: "unknown",
            endpoint: rule.pattern,
          });
          // `connection: close` like the other pre-body rejections: the
          // caller is unauthenticated, don't let it stream a body into a
          // dead request.
          res
            .writeHead(401, { "content-type": "text/plain", connection: "close" })
            .end("Unauthorized");
          return undefined;
        }
        const matchedId = apiKeyAuth.verifyKey(rule, presented);
        if (matchedId === null) {
          opts.auditLog.append({
            event: "rejected",
            id,
            traceId,
            reason: "api_key_invalid",
            keyId: "unknown",
            endpoint: rule.pattern,
          });
          res
            .writeHead(401, { "content-type": "text/plain", connection: "close" })
            .end("Unauthorized");
          return undefined;
        }
        apiKey = { keyId: matchedId, rule };
      }
    }

    // Inbound source baseline anomaly detection (WR-63): alert-only, never
    // a gate — it cannot reject, skip, or alter anything below. Runs on
    // headers alone, before the body is read. Placed after the WR-53 IP
    // ACL on purpose: a denied IP returns above, so blocked senders never
    // teach the baseline. The first sighting of an (endpoint, source IP,
    // TLS fingerprint) triple learns the baseline silently; a later new
    // triple on a guarded endpoint is audited as `source_anomaly` and the
    // request continues unchanged. The source IP reuses the WR-53 client
    // IP resolution when an IP ACL is configured (x-forwarded-for through
    // trusted proxies), otherwise it is the direct socket peer.
    if (sourceBaseline) {
      const baselineIp = ipAcl
        ? ipAcl.clientIp(req.socket.remoteAddress, req.headers["x-forwarded-for"])
        : (req.socket.remoteAddress ?? "unknown");
      const anomaly = sourceBaseline.observe(pathname, baselineIp, req.socket);
      if (anomaly !== null) {
        opts.auditLog.append({
          event: "source_anomaly",
          id,
          traceId,
          endpoint: anomaly.endpoint,
          path: anomaly.path,
          sourceIp: anomaly.sourceIp,
          fingerprint: anomaly.fingerprint,
          at: anomaly.at,
        });
      }
    }

    // Inbound rate limiting (WR-22): per-sender-IP + per-endpoint buckets.
    // Checked before the body is even read and before signature
    // verification, so a flood costs us almost nothing. Rejections are
    // audited like every other rejection, with the exhausted dimension.
    if (rateLimiter) {
      const ip = req.socket.remoteAddress ?? "unknown";
      const verdict = rateLimiter.take(ip, opts.forwardUrl);
      if (!verdict.ok) {
        opts.auditLog.append({
          event: "rejected",
          id,
          traceId,
          reason: "rate_limited",
          dimension: verdict.dimension,
          retryAfterMs: verdict.retryAfterMs,
        });
        res
          .writeHead(429, {
            "content-type": "text/plain",
            // Ceiling seconds, minimum 1: a Retry-After of 0 is meaningless.
            "retry-after": String(Math.max(1, Math.ceil(verdict.retryAfterMs / 1000))),
          })
          .end("Too many requests");
        return undefined;
      }
    }

    // Inbound body size limit (WR-25), first line of defense: the declared
    // Content-Length is checked before a single body byte is read, so a
    // giant payload is rejected without touching memory or the verifier. A
    // missing or unparseable header falls through to the streaming cap.
    const declaredLength = req.headers["content-length"];
    if (typeof declaredLength === "string") {
      const n = Number(declaredLength);
      if (Number.isInteger(n) && n > maxBodyBytes) {
        opts.auditLog.append({
          event: "rejected",
          id,
          traceId,
          reason: "body_too_large",
          maxBodyBytes,
        });
        // `connection: close` drops the socket after the 413, so the
        // client cannot keep streaming a flood into a dead request.
        res
          .writeHead(413, { "content-type": "text/plain", connection: "close" })
          .end("Request body too large");
        return undefined;
      }
    }

    let body: Buffer;
    try {
      // Second line of defense: chunked bodies and lying Content-Lengths
      // are capped while streaming; the body never exceeds the budget.
      body = await readRawBody(req, maxBodyBytes);
    } catch (err) {
      if (err instanceof BodyTooLargeError) {
        opts.auditLog.append({
          event: "rejected",
          id,
          traceId,
          reason: "body_too_large",
          maxBodyBytes,
        });
        res
          .writeHead(413, { "content-type": "text/plain", connection: "close" })
          .end("Request body too large");
        return undefined;
      }
      res.writeHead(400, { "content-type": "text/plain" }).end("Bad request");
      return undefined;
    }
    return { body, apiKey };
  };

  /**
   * WR-61: the outcome of admitting one event through the inbound
   * pipeline (signature → tenant → gzip → version → schema → replay →
   * dedup → enqueue). The single-webhook path and the batch ingestion
   * path share it; each caller translates it into its own HTTP response
   * shape.
   */
  interface AdmitOutcome {
    /** HTTP status the admission decided: 202 accepted, 400/401/409/413 rejected. */
    status: number;
    /** Per-event UUID minted before admission (audited even on rejection). */
    id: string;
    /** Per-event trace ID (client-supplied or fresh). */
    traceId: string;
    /** Machine-readable rejection reason (the audit `reason`); absent on 202. */
    reason?: string;
    /** Human-readable rejection detail for the response body. */
    detail?: string;
    /** WR-14: the event was a duplicate — 202 with `duplicate: true`. */
    duplicate?: boolean;
    /** WR-57: the delivery was parked for a future time (epoch ms). */
    scheduledAt?: number;
    /** WR-80: a recurring cron schedule was registered (the schedule id). */
    scheduleId?: string;
    /** WR-80: the registered cron expression text. */
    cron?: string;
    /** WR-80: next fire instant of the registered schedule (epoch ms). */
    nextAt?: number;
    /** Validated tenant, when the event claimed one. */
    tenantId?: string;
    /** The rejection must close the connection (413 flood protection). */
    closeConnection?: boolean;
  }

  /**
   * WR-61: admit one event through the full inbound pipeline — signature
   * verification → tenant validation → inbound gzip → version adaptation
   * → schema validation → replay guard → dedup → enqueue — auditing every
   * decision. `headers` is the event's header map (the HTTP headers for a
   * single webhook, the item's `headers` for a batch item); `correlation`
   * is spread into every audit event the admission emits (e.g.
   * `{ batchId }`, empty for single webhooks). Never writes the HTTP
   * response — the caller translates the outcome. `apiKey` carries the
   * WR-65 gate result for the HTTP-level request (matched key id +
   * rule); batch items pass none, so per-item signature verification
   * always runs for them.
   */
  const admitOneEvent = async (
    id: string,
    traceId: string,
    body: Buffer,
    headers: Record<string, string | string[] | undefined>,
    pathname: string,
    correlation: Record<string, unknown>,
    apiKey?: { keyId: string; rule: EndpointApiKeyRule }
  ): Promise<AdmitOutcome> => {
    const signatureHeader = headers["x-signature"];
    const keyIdHeader = headers["x-key-id"];
    const keyIdHint = Array.isArray(keyIdHeader) ? keyIdHeader[0] : keyIdHeader;

    // Per-endpoint verifier selection (WR-29): the request path picks the
    // trusted verifier; anything unmatched falls back to the global one.
    // A mismatch here is answered 401 below and never enqueues, so it can
    // never trip the downstream circuit breaker.
    const activeVerifier = selectEndpointVerifier(pathname, opts.endpointVerifiers) ?? verifier;
    const perEndpointVerifier = activeVerifier !== verifier;

    // With key rotation, learn which key id verified so it can go on the
    // audit trail; otherwise keep the legacy boolean contract.
    //
    // Inbound API key authentication (WR-65): when an API-key rule
    // guarded this endpoint and the request passed the pre-body key
    // gate, the key is the endpoint's authenticator — the signature
    // check is skipped UNLESS the rule demands both (`requireSignature:
    // true`). Endpoints with no API-key rule keep the exact legacy
    // behavior.
    let verified = false;
    let verifiedKeyId: string | undefined;
    const apiKeyAuthenticates = apiKey !== undefined && apiKey.rule.requireSignature !== true;
    const rotatingVerifier = activeVerifier instanceof RotatingHmacVerifier;
    // Rotation attribution only applies when the signature check ran;
    // in api-key-only mode the key gate already authenticated the
    // request, so no signing key id is reported.
    const rotating = !apiKeyAuthenticates && rotatingVerifier;
    // Dual-secret rotation (WR-67): an endpoint rotation rule applies
    // only where the default HMAC verifier is in force — a custom
    // `verifier`, `signingKeys` (WR-20), or a matching per-endpoint
    // verifier rule (WR-29) takes precedence and the rotation rule is
    // ignored there. Orthogonal to WR-65: in api-key-only mode the key
    // gate already authenticated the request; in requireSignature mode
    // the dual-secret check below is the signature leg.
    const dualSecret =
      !apiKeyAuthenticates && !rotatingVerifier && opts.verifier === undefined && !perEndpointVerifier
        ? selectSecretRotation(pathname, secretRotations)
        : undefined;
    const versionHintRaw = headers[SIGNATURE_VERSION_HEADER];
    const versionHint = Array.isArray(versionHintRaw) ? versionHintRaw[0] : versionHintRaw;
    let verifiedSecretVersion: "current" | "previous" | undefined;
    if (apiKeyAuthenticates) {
      verified = true;
    } else if (rotatingVerifier) {
      const detail = activeVerifier.verifyDetailed(body, signatureHeader ?? "", { keyId: keyIdHint });
      verified = detail.ok;
      verifiedKeyId = detail.keyId;
    } else if (dualSecret !== undefined) {
      const detail = dualSecret.verify(body, signatureHeader ?? "", { version: versionHint });
      verified = detail.ok;
      verifiedSecretVersion = detail.version;
    } else {
      verified = activeVerifier.verify(body, signatureHeader ?? "");
    }

    if (!verified) {
      const rejectedEvent: Record<string, unknown> = { ...correlation,
        event: "rejected",
        id,
        traceId,
        reason: "invalid_signature",
      };
      if (rotating) rejectedEvent.keyId = "unknown";
      // WR-65: the request proved possession of the API key at the
      // pre-body gate before failing the signature check (both-required
      // mode) — attribute the rejection to that key. "unknown" stays
      // reserved for gates where no key ever matched.
      if (apiKey !== undefined) rejectedEvent.keyId = apiKey.keyId;
      // Name the verifier that rejected, so a multi-scheme relay's audit
      // trail shows which trust rule fired.
      if (perEndpointVerifier) rejectedEvent.verifier = activeVerifier.name;
      opts.auditLog.append(rejectedEvent);
      return {
        status: 401,
        id,
        traceId,
        reason: "invalid_signature",
        detail: "Invalid signature",
      };
    }

    // Multi-tenant isolation (WR-48): the inbound `x-tenant-id` header
    // claims the tenant for this webhook. It is validated here — after
    // signature verification, so unauthenticated callers learn nothing —
    // and an invalid value is answered 400, never enqueued. Everything
    // below (dedup, the queue, audits) sees the validated tenant.
    const tenantHeader = headers[TENANT_ID_HEADER];
    const tenantRaw = Array.isArray(tenantHeader) ? tenantHeader[0] : tenantHeader;
    let tenantId: string | undefined;
    if (tenantRaw !== undefined) {
      try {
        assertValidTenantId(tenantRaw);
        tenantId = tenantRaw;
      } catch {
        opts.auditLog.append({ ...correlation, event: "rejected", id, traceId, reason: "invalid_tenant_id" });
        return { status: 400, id, traceId, reason: "invalid_tenant_id", detail: "Invalid x-tenant-id" };
      }
    }
    // Spread into audit events; empty when the request claimed no tenant.
    const tenantLabel = tenantId === undefined ? {} : { tenant: tenantId };

    // Inbound gzip (WR-40): a webhook posted with `Content-Encoding: gzip`
    // is transparently decompressed. Signature verification above ran on
    // the raw wire bytes the sender signed; everything below — version
    // routing, replay guard, dedup, the queue — sees the canonical plain
    // payload. Decompression is streaming and capped at `maxBodyBytes`
    // (WR-25 applies to the decompressed size too), so a gzip bomb is
    // answered 413 exactly like an oversized plain body.
    let inboundGzip = false;
    if (isGzipContentEncoding(headers["content-encoding"])) {
      try {
        body = await gunzipCapped(body, maxBodyBytes);
        inboundGzip = true;
      } catch (err) {
        if (err instanceof DecompressionTooLargeError) {
          opts.auditLog.append({ ...correlation,
            event: "rejected",
            id,
            traceId,
            reason: "body_too_large",
            maxBodyBytes,
          });
          return {
            status: 413,
            id,
            traceId,
            reason: "body_too_large",
            detail: "Request body too large",
            closeConnection: true,
          };
        }
        opts.auditLog.append({ ...correlation,
          event: "rejected",
          id,
          traceId,
          reason: "decompression_failed",
          error: err instanceof Error ? err.message : String(err),
        });
        return { status: 400, id, traceId, reason: "decompression_failed", detail: "Invalid gzip body" };
      }
    }

    // API version routing (WR-33): a version-prefixed path (e.g. /v1/...)
    // runs the *verified* payload through its adapter into the current
    // schema. Signature verification above ran on the raw body the sender
    // signed; everything below — replay guard, dedup, the queue — sees
    // the adapted body, so dedup hashes the canonical form and the same
    // event sent as v1 and v2 suppresses to one delivery. An adapter that
    // throws rejects the request with 400: an unadaptable payload is a
    // sender bug, never a delivery problem, so it never touches the queue.
    let version: string | undefined;
    let versionRoute: ApiVersionRoute | undefined;
    if (versionRouter !== undefined) {
      versionRoute = versionRouter.match(pathname);
      if (versionRoute !== undefined) {
        version = versionRoute.adapter.version;
        try {
          body = versionRoute.adapter.adapt(body, { version, path: pathname, traceId });
        } catch (err) {
          versionMetrics.record(version, "rejected");
          opts.auditLog.append({ ...correlation,
            event: "rejected",
            id,
            traceId,
            ...tenantLabel,
            reason: "version_adapt_failed",
            version,
            error: err instanceof Error ? err.message : String(err),
          });
          return { status: 400, id, traceId, reason: "version_adapt_failed", detail: "Invalid versioned payload" };
        }
      }
    }

    // Inbound JSON schema registry (WR-41): a per-endpoint pluggable
    // payload-shape gate. It runs on the *verified, adapted* body —
    // signature verification above ran on the raw bytes the sender
    // signed, and WR-33 version adaptation (when matched) already reshaped
    // the payload into the current schema — so the schema validates the
    // canonical form, exactly like dedup hashes it below. Everything
    // after this point (replay guard, dedup, the queue) only ever sees
    // schema-valid payloads. A failure is answered 400 and audited as
    // `rejected` with reason `schema_failed`: it never enters the queue,
    // so it consumes no retry budget and never trips the breaker. Schemas
    // validate JSON — a non-JSON body fails validation — and a throwing
    // validator is fail-closed (rejected, never admitted).
    let schema: PayloadSchema | undefined;
    if (opts.payloadSchemas !== undefined) {
      // Compose with WR-33 version routing (see `src/version.ts`): when a
      // version route matched, the schema rule is first tried against the
      // endpoint path with the version prefix stripped — one `/hooks/*`
      // rule covers `/v1/hooks/...` and `/v2/hooks/...` alike, because
      // every version adapts into the current schema before validation.
      // If nothing matches the stripped path, the full inbound path is
      // tried as a fallback, so per-version rules (`/v1/admin/*`) still
      // work. Unversioned requests match against the path as-is.
      const strippedPath =
        versionRoute === undefined ? pathname : pathname.slice(versionRoute.prefix.length) || "/";
      const rule =
        selectEndpointSchema(strippedPath, opts.payloadSchemas) ??
        (strippedPath === pathname
          ? undefined
          : selectEndpointSchema(pathname, opts.payloadSchemas));
      if (rule !== undefined) {
        schema = rule.schema;
        let payload: unknown;
        let parseError: string | undefined;
        try {
          payload = JSON.parse(body.toString("utf8"));
        } catch {
          parseError = "body is not valid JSON";
        }
        let errors: string[] | undefined;
        if (parseError !== undefined) {
          errors = [parseError];
        } else {
          try {
            const check = schema.validate(payload);
            if (!check.ok) errors = check.errors ?? ["schema validation failed"];
          } catch (err) {
            errors = [`schema validator threw: ${err instanceof Error ? err.message : String(err)}`];
          }
        }
        if (errors !== undefined) {
          schemaMetrics.record(schema.name, "rejected");
          opts.auditLog.append({ ...correlation,
            event: "rejected",
            id,
            traceId,
            ...tenantLabel,
            reason: "schema_failed",
            schema: schema.name,
            schemaVersion: schema.version,
            errors: errors.slice(0, 10),
          });
          return { status: 400, id, traceId, reason: "schema_failed", detail: "Schema validation failed" };
        }
      }
    }

    // Content-based routing (WR-84): pick the delivery target from the
    // verified, decompressed, version-adapted body — the canonical bytes
    // dedup hashes below. Routing only ever picks a target; it never
    // rejects an event, so a non-JSON body or an unmatchable payload falls
    // back to `opts.forwardUrl`. Unconfigured → `targetUrl` stays
    // `opts.forwardUrl` and everything below is byte-identical to before.
    let targetUrl = opts.forwardUrl;
    let routeRuleId: string | undefined;
    if (contentRouteTable !== undefined) {
      const decision = contentRouteTable.resolve(body);
      if (decision.targetUrl !== undefined) targetUrl = decision.targetUrl;
      routeRuleId = decision.ruleId ?? "default";
    }

    if (opts.replay) {
      const nonceHeader = headers["x-nonce"];
      const nonce = Array.isArray(nonceHeader) ? nonceHeader[0] : nonceHeader;
      const tsHeader = headers["x-timestamp"];
      const tsRaw = Array.isArray(tsHeader) ? tsHeader[0] : tsHeader;
      // x-timestamp is unix seconds (same unit as the `t=` signature field);
      // the guard works in ms. A non-numeric value fails the window check.
      const timestampMs = tsRaw === undefined ? undefined : Number(tsRaw) * 1000;
      const verdict = opts.replay.check(nonce, timestampMs);
      if (!verdict.ok) {
        const reason = verdict.reason as string;
        opts.auditLog.append({ ...correlation, event: "rejected", id, traceId, ...tenantLabel, reason });
        const status = reason === "duplicate_nonce" ? 409 : 400;
        return { status, id, traceId, reason, detail: `Rejected: ${reason}` };
      }
    }

    // Payload-hash dedup (WR-14): the same business event re-pushed inside
    // the window is acknowledged but never delivered — the duplicate
    // business action (e.g. a repeated payment callback charging twice) is
    // what we are protecting against. 202, not 409, so upstream treats the
    // event as handled instead of retrying again. WR-48: the dedup key is
    // tenant-scoped — one tenant's push must never suppress another
    // tenant's identical business event.
    if (deduplicator) {
      const payloadHash = DeliveryDeduplicator.hashPayload(body);
      if (deduplicator.check(tenantScopeKey(tenantId, targetUrl), payloadHash)) {
        opts.auditLog.append({ ...correlation,
          event: "duplicate_suppressed",
          id,
          traceId,
          ...tenantLabel,
          targetUrl,
        });
        return { status: 202, id, traceId, duplicate: true, tenantId };
      }
    }

    const passthrough: Record<string, string | string[] | undefined> = {};
    for (const [k, v] of Object.entries(headers)) {
      if (k === "host" || k === "content-length") continue;
      // WR-40: the payload was decompressed above, so a stale inbound
      // `content-encoding: gzip` must not travel with the plain bytes —
      // the downstream would try to gunzip JSON and fail.
      if (k === "content-encoding" && inboundGzip) continue;
      // `x-relay-signature` / `x-relay-key-id` / `x-relay-idempotency-key`
      // are this relay's own namespace: an inbound client asserting them
      // would impersonate the relay downstream. Strip them always; when
      // outbound signing / idempotency keys are enabled the sender stamps
      // fresh ones below. `x-tenant-id` is likewise relay-internal routing
      // state (WR-48): the tenant is already on the queued item, and the
      // downstream never asked for the caller's tenancy claim.
      if (k === "x-relay-signature" || k === "x-relay-key-id" || k === IDEMPOTENCY_KEY_HEADER) continue;
      if (k === TENANT_ID_HEADER) continue;
      // WR-65: `x-api-key` is the caller's inbound credential — it
      // authenticates the intake, it is not part of the event, and it
      // must never travel downstream to the forward target.
      if (k === "x-api-key") continue;
      passthrough[k] = v;
    }

    // `x-priority: urgent` opts the delivery into the fast lane: it skips
    // the exponential backoff and the per-endpoint concurrency limiter, and
    // is instead bounded by the per-endpoint urgent token bucket
    // (`retry.urgent`, defaults: immediate retries, 100/sec per endpoint).
    const priorityHeader = headers["x-priority"];
    const priorityValue = Array.isArray(priorityHeader) ? priorityHeader[0] : priorityHeader;
    const priority: DeliveryPriority | undefined =
      priorityValue?.toLowerCase() === "urgent" ? "urgent" : undefined;

    // Timed delivery (WR-57): `x-deliver-at` declares a future delivery
    // time as epoch ms or an HTTP-date. An invalid value is a sender bug —
    // answered 400 fail-fast, never enqueued (fail-fast placement: after
    // signature verification and tenant validation, so unauthenticated
    // callers learn nothing new). A past-due value takes the normal
    // delivery path; the queue decides the parking, the check below only
    // mirrors it for the 202 response and the audit event.
    const deliverAtHeader = headers[DELIVER_AT_HEADER];
    let deliverAt: number | undefined;
    if (deliverAtHeader !== undefined) {
      try {
        deliverAt = parseDeliverAtHeader(deliverAtHeader);
      } catch {
        opts.auditLog.append({ ...correlation, event: "rejected", id, traceId, ...tenantLabel, reason: "invalid_deliver_at" });
        return { status: 400, id, traceId, reason: "invalid_deliver_at", detail: "Invalid x-deliver-at" };
      }
    }

    // Recurring schedules (WR-80): `x-schedule-cron` registers a cron
    // schedule that emits one delivery per cycle, each with a fresh
    // traceId. An invalid expression is a sender bug — 400 fail-fast,
    // audited as `rejected` with reason `invalid_schedule_cron`.
    // `x-deliver-at` and `x-schedule-cron` are mutually exclusive (a
    // request declaring both is rejected as `conflicting_schedule`);
    // the one-shot semantics of `x-deliver-at` are unchanged.
    const cronHeader = headers[CRON_HEADER];
    let cronSource: string | undefined;
    if (cronHeader !== undefined) {
      const rawCron = Array.isArray(cronHeader) ? cronHeader[0] : cronHeader;
      try {
        parseCronExpression(rawCron);
      } catch {
        opts.auditLog.append({ ...correlation, event: "rejected", id, traceId, ...tenantLabel, reason: "invalid_schedule_cron" });
        return { status: 400, id, traceId, reason: "invalid_schedule_cron", detail: "Invalid x-schedule-cron" };
      }
      cronSource = rawCron;
    }
    if (deliverAt !== undefined && cronSource !== undefined) {
      opts.auditLog.append({ ...correlation, event: "rejected", id, traceId, ...tenantLabel, reason: "conflicting_schedule" });
      return { status: 400, id, traceId, reason: "conflicting_schedule", detail: "x-deliver-at and x-schedule-cron are mutually exclusive" };
    }

    let scheduleId: string | undefined;
    let nextAt: number | undefined;
    if (cronSource !== undefined) {
      // Recurring: register the schedule — the intake-time event is the
      // template, not a delivery. Each cycle mints a fresh delivery with
      // a fresh traceId into the normal path.
      scheduleId = queue.addRecurringDelivery({
        id,
        traceId,
        // WR-48: the validated tenant rides the template into the
        // per-tenant isolation scope, like any other delivery.
        ...(tenantId !== undefined ? { tenantId } : {}),
        payload: body,
        targetUrl,
        headers: passthrough,
        ...(priority ? { priority } : {}),
      }, cronSource);
      nextAt = queue.nextScheduleFire(scheduleId);
    } else {
      queue.enqueue({
        id,
        traceId,
        // WR-48: the validated tenant rides the item into the per-tenant
        // isolation scope (breaker/quota/limiter/latency instances).
        ...(tenantId !== undefined ? { tenantId } : {}),
        payload: body,
        targetUrl,
        headers: passthrough,
        ...(priority ? { priority } : {}),
        ...(deliverAt !== undefined ? { deliverAt } : {}),
      });
    }
    // WR-78: usage metering — accepted events only. Rejections, schema
    // failures, replay-guard hits, and dedup-suppressed duplicates are
    // acknowledged-but-not-processed and never bill.
    usageMeter?.recordInbound({
      tenant: tenantId,
      bytesIn: body.length,
      urgent: priority === "urgent",
    });
    // Version intake accounting (WR-33): unversioned requests count under
    // "none" so the version mix is fully visible in the exposition.
    if (versionRouter !== undefined) {
      versionMetrics.record(version ?? "none", "accepted");
    }
    // Schema intake accounting (WR-41): only schema-validated requests
    // were ever counted here — rejected payloads were recorded as
    // "rejected" at the gate above.
    if (schema !== undefined) {
      schemaMetrics.record(schema.name, "accepted");
    }
    const acceptedEvent: Record<string, unknown> = { ...correlation,
      event: "accepted",
      id,
      traceId,
      ...tenantLabel,
      targetUrl,
    };
    // WR-67: every webhook that verified with the previous secret is
    // audited on its own event, so the operator sees how much rotation
    // traffic still runs on the old key — the signal that the rotation
    // is (or is not) ready to complete.
    if (verifiedSecretVersion === "previous") {
      opts.auditLog.append({
        ...correlation,
        event: "secret_rotation_previous_used",
        id,
        traceId,
        ...tenantLabel,
        endpoint: pathname,
      });
    }
    if (version !== undefined) acceptedEvent.version = version;
    if (schema !== undefined) {
      acceptedEvent.schema = schema.name;
      acceptedEvent.schemaVersion = schema.version;
    }
    if (rotating) acceptedEvent.keyId = verifiedKeyId ?? "unknown";
    // WR-65: the API key admitted the request — its id is the admission
    // credential, so it wins over the signing key id when both factors
    // are in play.
    if (apiKey !== undefined) acceptedEvent.keyId = apiKey.keyId;
    if (perEndpointVerifier) acceptedEvent.verifier = activeVerifier.name;
    if (priority) acceptedEvent.priority = priority;
    if (inboundGzip) acceptedEvent.contentEncoding = "gzip";
    if (opts.auditPayloads) acceptedEvent.payload = body;
    opts.auditLog.append(acceptedEvent);
    // WR-84: the routing decision, audited as its own event so operators
    // can query `GET /audit?event=routed`. Only emitted when content
    // routing is configured; `routeRuleId` is the matched rule id, or
    // "default" when the default / legacy fallback applied.
    if (contentRouteTable !== undefined) {
      opts.auditLog.append({ ...correlation,
        event: "routed",
        id,
        traceId,
        ...tenantLabel,
        ruleId: routeRuleId ?? "default",
        targetUrl,
      });
    }
    // WR-57: the queue parked the delivery in the delay queue (a future
    // deliver_at) — audit it as its own event so operators can query
    // `GET /audit?event=scheduled`, and tell the sender when to expect it.
    const scheduledAt = deliverAt !== undefined && queue.isScheduled(id) ? deliverAt : undefined;
    if (scheduledAt !== undefined) {
      opts.auditLog.append({ ...correlation,
        event: "scheduled",
        id,
        traceId,
        ...tenantLabel,
        targetUrl,
        deliverAtMs: scheduledAt,
        deliverAt: new Date(scheduledAt).toISOString(),
      });
    }
    // WR-80: a recurring schedule was registered — audit the registration
    // (queryable via `GET /audit?event=schedule_registered`); each cycle
    // is audited separately as `scheduled_fired`.
    if (scheduleId !== undefined) {
      opts.auditLog.append({ ...correlation,
        event: "schedule_registered",
        id: scheduleId,
        traceId,
        ...tenantLabel,
        targetUrl,
        cron: cronSource,
        nextAtMs: nextAt,
        nextAt: nextAt !== undefined ? new Date(nextAt).toISOString() : undefined,
      });
    }
    return { status: 202, id, traceId, tenantId, scheduledAt, scheduleId, cron: cronSource, nextAt };
  };

  /**
   * Intake pipeline: everything below the operator/intake plane split.
   * Shared by the legacy single-plane listener and the split-plane intake
   * listener, so both planes admit webhooks identically.
   */
  const handleInbound = async (
    req: Parameters<Parameters<typeof createServer>[0]>[0],
    res: Parameters<Parameters<typeof createServer>[0]>[1],
    pathname: string
  ): Promise<void> => {
    if (req.method !== "POST") {
      res.writeHead(405, { "content-type": "text/plain" }).end("Method not allowed");
      return;
    }
    // WR-61: batch ingestion rides the intake plane like any webhook —
    // one envelope signature, then per-item admission.
    if (pathname === "/ingest/batch") {
      await handleIngestBatch(req, res);
      return;
    }
    const id = randomUUID();
    // Resolve the trace ID before any admission decision so even rejections
    // are traceable; a client-supplied x-trace-id is honored, otherwise fresh.
    const traceId = resolveTraceId(req.headers[TRACE_ID_HEADER]);
    const gates = await runIntakeGates(req, res, pathname, id, traceId);
    if (gates === undefined) return;
    const outcome = await admitOneEvent(id, traceId, gates.body, req.headers, pathname, {}, gates.apiKey);
    const tenantLabel = outcome.tenantId === undefined ? {} : { tenant: outcome.tenantId };
    if (outcome.status === 202) {
      res
        .writeHead(202, { "content-type": "application/json" })
        .end(
          JSON.stringify({
            id: outcome.id,
            traceId: outcome.traceId,
            status: "accepted",
            ...tenantLabel,
            ...(outcome.duplicate === true ? { duplicate: true } : {}),
            ...(outcome.scheduledAt !== undefined
              ? { scheduled: true, deliverAt: new Date(outcome.scheduledAt).toISOString() }
              : {}),
            ...(outcome.scheduleId !== undefined
              ? {
                  scheduled: true,
                  recurring: true,
                  scheduleId: outcome.scheduleId,
                  cron: outcome.cron,
                  ...(outcome.nextAt !== undefined
                    ? { nextAt: new Date(outcome.nextAt).toISOString() }
                    : {}),
                }
              : {}),
          })
        );
      return;
    }
    const rejHeaders: Record<string, string> = { "content-type": "text/plain" };
    if (outcome.closeConnection === true) rejHeaders["connection"] = "close";
    res.writeHead(outcome.status, rejHeaders).end(outcome.detail ?? "Rejected");
  };

  /**
   * Batch inbound ingestion (WR-61): `POST /ingest/batch` accepts one
   * JSON envelope carrying many events, so a producer — e.g. a payment
   * provider pushing a batch of callbacks — pays one HTTP round trip
   * instead of one per event.
   *
   * Trust model, in order:
   *  1. The intake gates (IP allowlist, rate limit, body cap) run first,
   *     exactly like a single webhook.
   *  2. The envelope's `x-signature` is verified over the whole raw
   *     batch body BEFORE the batch is split — a tampered or reordered
   *     batch never reaches per-item admission. Per-endpoint verifier
   *     rules apply to the batch path, with key-rotation support.
   *  3. Each item then walks the full per-item pipeline through
   *     `admitOneEvent` (per-item signature → tenant → gzip → version →
   *     schema → content routing → replay → dedup → enqueue) with its own id and its own
   *     trace ID. Item failures are isolated: one bad item never affects
   *     the rest of the batch.
   *
   * Envelope shape:
   * `{ "events": [{ "payload": "<base64>", "headers": { "x-signature":
   * "sha256=…", "x-trace-id": "…", … } }, …] }`
   * `payload` is base64 of the exact bytes the per-item signature
   * covers. Per-item `headers` are optional; an item without a verifiable
   * signature is rejected 401 exactly like an unsigned single webhook —
   * the batch envelope signature authenticates the batcher, the item
   * signature authenticates each event's origin.
   *
   * Responses: 202 when every item was accepted, 207 Multi-Status when
   * mixed, with per-item `{ index, status, id, traceId, … }` results. A
   * malformed envelope is 400 and never touches per-item admission. The
   * batch is audited once as `batch_ingested` (totals), plus the normal
   * per-item `accepted` / `rejected` / `duplicate_suppressed` events,
   * each carrying `batchId` for correlation.
   */
  const handleIngestBatch = async (
    req: Parameters<Parameters<typeof createServer>[0]>[0],
    res: Parameters<Parameters<typeof createServer>[0]>[1]
  ): Promise<void> => {
    const batchId = randomUUID();
    const batchTraceId = resolveTraceId(req.headers[TRACE_ID_HEADER]);
    const gates = await runIntakeGates(req, res, "/ingest/batch", batchId, batchTraceId);
    if (gates === undefined) return;
    const body = gates.body;

    // The envelope signature covers the whole raw batch body — verified
    // before splitting, so dropping, reordering, or tampering with items
    // invalidates the batch.
    const envelopeVerifier =
      selectEndpointVerifier("/ingest/batch", opts.endpointVerifiers) ?? verifier;
    const envelopeKeyIdHeader = req.headers["x-key-id"];
    const envelopeKeyIdHint = Array.isArray(envelopeKeyIdHeader)
      ? envelopeKeyIdHeader[0]
      : envelopeKeyIdHeader;
    const envelopeSignature = req.headers["x-signature"];
    const envelopeSigValue = Array.isArray(envelopeSignature)
      ? envelopeSignature[0]
      : (envelopeSignature ?? "");
    let envelopeVerified = false;
    if (envelopeVerifier instanceof RotatingHmacVerifier) {
      envelopeVerified = envelopeVerifier.verifyDetailed(body, envelopeSigValue, {
        keyId: envelopeKeyIdHint,
      }).ok;
    } else {
      envelopeVerified = envelopeVerifier.verify(body, envelopeSigValue);
    }
    if (!envelopeVerified) {
      opts.auditLog.append({
        event: "rejected",
        id: batchId,
        traceId: batchTraceId,
        path: "/ingest/batch",
        reason: "invalid_batch_signature",
      });
      res.writeHead(401, { "content-type": "text/plain" }).end("Invalid batch signature");
      return;
    }

    // A batch-level tenant is validated once here; a per-item
    // `x-tenant-id` overrides it for that item.
    const batchTenantHeader = req.headers[TENANT_ID_HEADER];
    const batchTenantRaw = Array.isArray(batchTenantHeader)
      ? batchTenantHeader[0]
      : batchTenantHeader;
    let batchTenantId: string | undefined;
    if (batchTenantRaw !== undefined) {
      try {
        assertValidTenantId(batchTenantRaw);
        batchTenantId = batchTenantRaw;
      } catch {
        opts.auditLog.append({
          event: "rejected",
          id: batchId,
          traceId: batchTraceId,
          path: "/ingest/batch",
          reason: "invalid_tenant_id",
        });
        res.writeHead(400, { "content-type": "text/plain" }).end("Invalid x-tenant-id");
        return;
      }
    }

    let envelope: unknown;
    try {
      envelope = JSON.parse(body.toString("utf8"));
    } catch {
      envelope = undefined;
    }
    const events =
      typeof envelope === "object" && envelope !== null
        ? (envelope as { events?: unknown }).events
        : undefined;
    if (!Array.isArray(events) || events.length === 0) {
      opts.auditLog.append({
        event: "rejected",
        id: batchId,
        traceId: batchTraceId,
        path: "/ingest/batch",
        reason: !Array.isArray(events) ? "invalid_batch_shape" : "empty_batch",
      });
      res.writeHead(400, { "content-type": "text/plain" }).end("Invalid batch envelope");
      return;
    }

    const correlation = { batchId };
    const results: Array<Record<string, unknown>> = [];
    let accepted = 0;
    for (let index = 0; index < events.length; index++) {
      const itemId = randomUUID();
      const checked = checkIngestBatchItem(events[index]);
      // Per-item trace IDs are independent: an item's own `x-trace-id`
      // is honored, otherwise a fresh one — never the batch's.
      const itemTraceId = resolveTraceId(
        "item" in checked && checked.item.headers !== undefined
          ? checked.item.headers[TRACE_ID_HEADER]
          : undefined
      );
      if (!("item" in checked)) {
        opts.auditLog.append({
          event: "rejected",
          ...correlation,
          id: itemId,
          traceId: itemTraceId,
          index,
          reason: "invalid_item",
          detail: checked.problem,
        });
        results.push({
          index,
          status: 400,
          id: itemId,
          traceId: itemTraceId,
          reason: "invalid_item",
          detail: checked.problem,
        });
        continue;
      }
      const itemHeaders: Record<string, string | string[] | undefined> = {
        ...(checked.item.headers ?? {}),
      };
      if (itemHeaders[TENANT_ID_HEADER] === undefined && batchTenantId !== undefined) {
        itemHeaders[TENANT_ID_HEADER] = batchTenantId;
      }
      const outcome = await admitOneEvent(
        itemId,
        itemTraceId,
        checked.body,
        itemHeaders,
        "/ingest/batch",
        correlation
      );
      const result: Record<string, unknown> = {
        index,
        status: outcome.status,
        id: outcome.id,
        traceId: outcome.traceId,
      };
      if (outcome.reason !== undefined) result.reason = outcome.reason;
      if (outcome.detail !== undefined) result.detail = outcome.detail;
      if (outcome.duplicate === true) result.duplicate = true;
      if (outcome.scheduledAt !== undefined) {
        result.scheduled = true;
        result.deliverAt = new Date(outcome.scheduledAt).toISOString();
      }
      if (outcome.scheduleId !== undefined) {
        result.scheduled = true;
        result.recurring = true;
        result.scheduleId = outcome.scheduleId;
        result.cron = outcome.cron;
        if (outcome.nextAt !== undefined) result.nextAt = new Date(outcome.nextAt).toISOString();
      }
      results.push(result);
      if (outcome.status === 202) accepted++;
    }

    opts.auditLog.append({
      event: "batch_ingested",
      id: batchId,
      traceId: batchTraceId,
      path: "/ingest/batch",
      total: events.length,
      accepted,
      rejected: events.length - accepted,
      ...(batchTenantId !== undefined ? { tenant: batchTenantId } : {}),
    });
    res
      .writeHead(accepted === events.length ? 202 : 207, {
        "content-type": "application/json",
      })
      .end(JSON.stringify({ batchId, traceId: batchTraceId, results }));
  };

  /**
   * Operator-plane call with the last-resort crash guard: never let an
   * operator-endpoint failure crash the process as an unhandled rejection;
   * the batch replay path rethrows per-item decrypt errors internally, so
   * this is only the final safety net.
   */
  const guardOperator = async (
    req: Parameters<Parameters<typeof createServer>[0]>[0],
    res: Parameters<Parameters<typeof createServer>[0]>[1],
    pathname: string
  ): Promise<void> => {
    try {
      await handleOperator(req, res, pathname);
    } catch {
      if (!res.headersSent) {
        respondJson(res, 500, { error: "internal server error" });
      }
    }
  };

  /** Plain 404 that reveals nothing about the other plane (WR-56). */
  const crossPlaneNotFound = (
    res: Parameters<Parameters<typeof createServer>[0]>[1]
  ): void => {
    res.writeHead(404, { "content-type": "text/plain" }).end("Not found");
  };

  let server: RelayServer;
  let operatorServer: Server | undefined;
  if (operatorPlane === undefined) {
    // Legacy single-plane behavior: one listener serves operator paths
    // and webhooks alike.
    server = createServer(async (req, res) => {
      const pathname = new URL(req.url ?? "/", "http://internal").pathname;
      if (isOperatorPath(pathname)) {
        await guardOperator(req, res, pathname);
        return;
      }
      await handleInbound(req, res, pathname);
    });
  } else {
    // Split plane (WR-56): operator paths hit on the intake listener are
    // indistinguishable from unknown paths — the operator plane's
    // existence is not revealed — and the operator listener 404s anything
    // that is not an operator path, so it can never accept a webhook.
    server = createServer(async (req, res) => {
      const pathname = new URL(req.url ?? "/", "http://internal").pathname;
      if (isOperatorPath(pathname)) {
        crossPlaneNotFound(res);
        return;
      }
      await handleInbound(req, res, pathname);
    });
    operatorServer = createServer(async (req, res) => {
      const pathname = new URL(req.url ?? "/", "http://internal").pathname;
      if (!isOperatorPath(pathname)) {
        crossPlaneNotFound(res);
        return;
      }
      await guardOperator(req, res, pathname);
    });
    server.operatorServer = operatorServer;
    // The operator port is fully specified in the options, so the relay
    // binds it itself at creation; the caller only ever binds the intake
    // plane with `listen()`.
    operatorServer.listen(operatorPlane.port, operatorPlane.host ?? "127.0.0.1");
  }

  server.on("close", () => {
    queue.stop();
    // Pooled outbound connections must not outlive the server: close them
    // (and stop the idle reaper) on the same close path that stops the
    // queue — this covers stop() and the graceful-shutdown drain alike.
    // Idle pool sockets are unref'd anyway, so even a missed close cannot
    // pin process exit.
    // WR-56: the returned (intake) server owns the operator plane's
    // lifecycle — closing it closes the operator listener too.
    if (operatorServer?.listening) operatorServer.close();
    defaultSender?.destroy();
  });

  // WR-47 runtime loop check: a callback URL that resolves to this relay's
  // own listener would re-enter intake on every terminal delivery and
  // ping-pong forever. The configuration-time check (declared
  // `selfOrigins`) ran at queue construction; this re-checks against the
  // actually bound address before every receipt POST, so even an
  // undeclared self-target (e.g. an ephemeral test port) is refused.
  // WR-56: the check only needs the intake listener — the operator plane
  // 404s webhooks, so a callback pointed at it can never re-enter intake.
  queue.setCompletionCallbackSelfCheck(
    createBoundAddressSelfCheck(() => {
      const addr = server.address();
      if (addr === null || typeof addr === "string") return addr;
      return { address: addr.address, port: addr.port };
    })
  );

  if (opts.gracefulShutdown) {
    const timeoutMs = opts.gracefulShutdown.timeoutMs ?? 30_000;
    const uninstall = installGracefulShutdown(
      server,
      async () => {
        // WR-56: stop the operator plane before draining, so no manual
        // replays or config changes can land while in-flight deliveries
        // settle. (The intake plane was already closed by
        // installGracefulShutdown, whose close handler also closes the
        // operator plane — the `listening` check makes this a no-op then.)
        const op = operatorServer;
        if (op?.listening) {
          await new Promise<void>((resolve) => op.close(() => resolve()));
        }
        return queue.shutdown(timeoutMs);
      },
      {
        exit: opts.gracefulShutdown.exit,
      }
    );
    // Remove the signal listeners once the server is gone so an embedded
    // server does not leave process-level handlers behind.
    server.on("close", () => uninstall());
  }

  // WR-70: outbound connection warm-up. When the server owns the default
  // sender (so there is a keep-alive pool) and warmup endpoints are
  // configured, pre-establish pooled connections for them — fire and
  // forget: warm-up must never block or fail startup. Per-endpoint
  // failures are audited as `warmup_failed` (a failed warm-up only means
  // the first delivery to that origin pays the handshake it would have
  // paid anyway); a summary lands as `warmup_completed`.
  if (opts.warmup !== undefined) {
    const warmupCfg = opts.warmup;
    if (
      warmupCfg === null ||
      typeof warmupCfg !== "object" ||
      !Array.isArray(warmupCfg.endpoints) ||
      !warmupCfg.endpoints.every((e) => typeof e === "string" && e.length > 0)
    ) {
      throw new RangeError("createRelayServer: `warmup.endpoints` must be a non-empty array of URL strings");
    }
    const warmupOpts = resolveWarmupOptions(warmupCfg);
    const pool = defaultSender?.pool;
    if (pool !== undefined && warmupCfg.endpoints.length > 0) {
      const endpointCfg = {
        tlsPins: opts.tlsPins,
        proxies: opts.proxies,
        tlsClientCerts: opts.tlsClientCerts,
        tlsSniOverrides: opts.tlsSniOverrides,
      };
      warmupOutboundPool(pool, warmupCfg.endpoints, endpointCfg, warmupOpts).then(
        (report) => {
          opts.auditLog.append({
            event: "warmup_completed",
            warmed: report.warmed,
            failed: report.failed,
            elapsedMs: report.elapsedMs,
            endpoints: report.results.map((r) => ({
              endpoint: r.endpoint,
              ok: r.ok,
              ...(r.error !== undefined ? { error: r.error } : {}),
              ...(r.connectMs !== undefined ? { connectMs: r.connectMs } : {}),
            })),
          });
          for (const r of report.results) {
            if (!r.ok) {
              opts.auditLog.append({ event: "warmup_failed", endpoint: r.endpoint, error: r.error });
            }
          }
        },
        (err) => {
          // Unreachable in practice: warmupOutboundPool reports endpoint
          // failures as data and never rejects for them — this is the
          // backstop for a bug in warm-up itself.
          opts.auditLog.append({
            event: "warmup_failed",
            endpoint: "<warmup>",
            error: String((err as Error)?.message ?? err),
          });
        }
      );
    }
  }

  return server;
}
