import { Agent as HttpAgent, createServer, request as httpRequest } from "node:http";
import { request as httpsRequest, createServer as createHttpsServer } from "node:https";
import type { IncomingMessage, Server } from "node:http";
import { randomUUID } from "node:crypto";
import {
  assertValidEndpointBodyLimitRules,
  assertValidEndpointVerifierRules,
  HmacSha256Verifier,
  RotatingHmacVerifier,
  RotatingRsaPssVerifier,
  selectEndpointBodyLimit,
  selectEndpointVerifier,
  signSha256,
  type EndpointBodyLimitRule,
  type EndpointVerifierRule,
  type SigningKey,
  type Verifier,
} from "./verify.ts";
import {
  SIGNATURE_ALG_HEADER,
  assertValidSignatureAlgorithmRules,
  normalizeSignatureAlg,
  selectSignatureAlgorithmVerifier,
  type SignatureAlgorithmRule,
} from "./signature-alg.ts";
import { RetryQueue, errorBudgetBurnAuditEvent, type BurnRateAlertInfo, type DeliveryEvent, type DeliveryEventType, type DeliveryPriority, type DownstreamResponse, type RetryItem, type Sender, type SenderCallOptions, type MaintenanceWindowTransition } from "./retry.ts";
import { parseDeliverAtHeader, DELIVER_AT_HEADER } from "./retry.ts";
import type { ShadowDeliveredInfo, ShadowFailedInfo, ShadowTargetConfig, ShadowTargetsConfig } from "./retry.ts";
import type {
  DeliveryDryRunOptions,
  DryRunDeliveryEvent,
  EndpointDryRunConfig,
} from "./delivery-dryrun.ts";
import type {
  QuorumAcknowledgedInfo,
  QuorumConfig,
  QuorumDispatchedInfo,
  QuorumEvictedInfo,
  QuorumFailedInfo,
  QuorumSatisfiedInfo,
  QuorumTargetDeadLetteredInfo,
} from "./retry.ts";
import type { PhaseDurationsMs } from "./retry.ts";
import type { StalePauseOptions } from "./retry.ts";
import {
  assertValidCorsPolicy,
  answerCorsPreflight,
  setCorsResponseHeaders,
  type CorsPolicy,
  type ResolvedCorsPolicy,
} from "./cors.ts";
import {
  assertValidHttpHardening,
  applyHttpHardening,
  type HttpHardeningOptions,
  type ResolvedHttpHardening,
} from "./http-hardening.ts";
import type { OrderedAuditEvent, OrderedModeOptions } from "./retry.ts";
import { parseCronExpression, CRON_HEADER } from "./cron.ts";
import type { CompletionCallbackOptions } from "./callback.ts";
import { createBoundAddressSelfCheck } from "./callback.ts";
import type {
  DeadLetterEscalatedInfo,
  DeadLetterEscalationFailedInfo,
  DeadLetterEscalationOptions,
} from "./escalation.ts";
import { TENANT_ID_HEADER, assertValidTenantId, tenantScopeKey } from "./tenant.ts";
import type { AutoReplayOptions } from "./autoreplay.ts";
import type { DeadLetterRetentionOptions } from "./deadletter-retention.ts";
import {
  DEAD_LETTER_EXPORT_ROW_LIMIT,
  InvalidExportCursorError,
  buildDeadLetterExportRow,
  parseDeadLetterExportTime,
  planDeadLetterExport,
  renderDeadLetterExportHeader,
  renderDeadLetterExportRow,
  type DeadLetterExportFilter,
  type DeadLetterExportFormat,
  type DeadLetterExportPlan,
} from "./deadletter-export.ts";
import {
  OAuth2TokenCache,
  resolveOAuth2ClientConfig,
  type OAuth2ClientCredentialsConfig,
} from "./oauth-client.ts";
import type { ReplayEgressOptions } from "./replay-egress.ts";
import { ReplayApprovalError, type ReplayApprovalDenyReason, type ReplayApprovalOptions } from "./replay-approval.ts";
import { HttpDeliveryError, parseRetryAfterMs } from "./failure.ts";
import {
  resolveChaosConfig,
  wrapSenderWithChaos,
  ChaosMetrics,
  type ChaosConfig,
  type ChaosInjectionInfo,
} from "./chaos.ts";
import {
  DeadlineBudgetTimeoutError,
  readDeadlineBudgetMs,
} from "./deadline-budget.ts";
import {
  AdaptiveTimeoutError,
  readAdaptiveTimeoutMs,
} from "./adaptive-timeout.ts";
import {
  PhaseTimeoutError,
  assertValidPhaseTimeoutBudgets,
  resolvePhaseTimeouts,
  type PhaseTimeoutBudgets,
  type PhaseTimeoutPhase,
} from "./phase-timeouts.ts";
import {
  createHedgedSender,
  HedgeCancelledError,
  HedgeMetrics,
  assertValidHedgedSenderOptions,
  type HedgeAuditEvent,
  type HedgedSender,
} from "./hedged.ts";
import { installGracefulShutdown } from "./shutdown.ts";
import { SourceBaselineDetector, type SourceBaselineOptions } from "./source-baseline.ts";
import type { PayloadEncryptor } from "./encrypt.ts";
import type { FieldMask } from "./masking.ts";
import {
  PayloadTransformer,
  PayloadTransformError,
  TemplateError,
  type PayloadTransformRules,
} from "./transform.ts";
export { PayloadTransformer, PayloadTransformError, TemplateError };
export type { PayloadTransformRules, TransformContext } from "./transform.ts";
import {
  AMZ_DATE_HEADER,
  AUTHORIZATION_HEADER,
  SigV4SecretUnavailableError,
  SigV4SigningError,
  assertValidAwsSigV4Config,
  defaultSecretResolver,
  headerValueIgnoreCase,
  signAwsSigV4,
  type AwsSigV4EndpointConfig,
  type SecretResolver,
} from "./sigv4.ts";
export {
  SigV4SecretUnavailableError,
  SigV4SigningError,
  assertValidAwsSigV4Config,
  defaultSecretResolver,
  headerValueIgnoreCase,
  signAwsSigV4,
};
export type { AwsSigV4EndpointConfig, SecretResolver };
export {
  createHedgedSender,
  HedgeCancelledError,
  HedgeMetrics,
  assertValidHedgedSenderOptions,
};
export type { HedgeAuditEvent, HedgedSender, HedgedSenderOptions } from "./hedged.ts";
export { errorBudgetBurnAuditEvent };
export type { BurnRateAlertInfo, ErrorBudgetBurnAuditEvent } from "./retry.ts";
import type { ReplayGuard } from "./replay.ts";
import { DeliveryDeduplicator, type DedupOptions } from "./dedup.ts";
import {
  RELAY_HOPS_HEADER,
  assertValidMeshOptions,
  parseRelayHops,
  nextRelayHops,
  MeshMetrics,
  type MeshOptions,
} from "./mesh.ts";
import { UsageMeter, type UsageOptions } from "./usage.ts";
import { buildHealthSummary } from "./health-summary.ts";
import {
  buildOpenApiDocument,
  findOperatorRoute,
  matchOperatorRoute,
} from "./operator-routes.ts";
import { InboundRateLimiter, type InboundRateLimitOptions } from "./ratelimit.ts";
import {
  InboundTenantRateLimiter,
  InboundTenantRateLimitMetrics,
  type InboundTenantRateLimitOptions,
} from "./tenant-inbound-ratelimit.ts";
import type { TenantRateLimitOptions } from "./tenant-ratelimit.ts";
import type { OutboundRateLimitOptions } from "./outbound-ratelimit.ts";
import type { DeliveryReceiptOptions } from "./delivery-receipt.ts";
import { InboundIpAcl, IpAclMetrics, type IpAclOptions } from "./ip-acl.ts";
import { GeoIpInboundPolicy, type GeoIpOptions } from "./geoip.ts";
import { InboundApiKeyAuth, type ApiKeyOptions, type EndpointApiKeyRule } from "./api-key.ts";
import {
  SenderReputationTracker,
  assertValidReputationOptions,
  type ReputationOptions,
  type ReputationPenaltyKind,
  type ReputationTransition,
} from "./reputation.ts";
import {
  bearerToken,
  operatorMay,
  OperatorKeyRing,
  type OperatorKeyEntry,
} from "./operator-keys.ts";
import { resolveTraceId, TRACE_ID_HEADER } from "./trace.ts";
import {
  formatTraceparent,
  parseInboundTraceContext,
  resolveOutboundTraceContext,
  resolveTraceContextOptions,
  traceAttemptSpanId,
  TRACEPARENT_HEADER,
  TRACESTATE_HEADER,
  type ResolvedTraceContextOptions,
  type TraceContext,
  type TraceContextOptions,
} from "./trace-context.ts";
import { ContentRouteTable, type ContentRouteRule } from "./content-routes.ts";
import {
  deriveIdempotencyKey,
  IDEMPOTENCY_KEY_HEADER,
  resolveIdempotencyKeyConfig,
  type IdempotencyKeyOptions,
  type ResolvedIdempotencyKeyConfig,
} from "./idempotency-key.ts";
import type { TLSSocket, Server as TlsServer } from "node:tls";
import type { Socket } from "node:net";
import {
  checkInboundWsHandshake,
  INBOUND_DEFLATE_ACCEPT,
  inboundWsAcceptKey,
  InboundWsParser,
  negotiateInboundPerMessageDeflate,
  resolveInboundWsOptions,
  wsCloseFrame,
  wsDeflatedTextFrame,
  wsPingFrame,
  wsPongFrame,
  WsProtocolError,
  type InboundWsMessage,
  type InboundWsOptions,
  type NegotiatedInboundDeflate,
  type ResolvedInboundWsOptions,
} from "./inbound-ws.ts";
import { decompressMessage, WsInflateBombError } from "./deflate.ts";
import { assertValidCaBundle, assertValidPins, normalizePin, spkiFingerprint, TlsPinMismatchError } from "./pinning.ts";
import {
  assertValidClientCert,
  clientCertIdentity,
  type TlsClientCert,
} from "./mtls.ts";
import {
  applyInboundMtlsConfigPatch,
  decideInboundMtls,
  extractPeerCertInfo,
  inboundMtlsSecureContext,
  inboundMtlsServerOptions,
  resolveInboundMtlsConfig,
  type InboundMtlsConfig,
  type InboundMtlsConfigPatch,
  type InboundMtlsIdentity,
  type ResolvedInboundMtlsConfig,
} from "./inbound-mtls.ts";
import type { ConfigChange } from "./hotreload.ts";
import {
  RotatingClientCertSet,
  type RotatingClientCertConfig,
} from "./mtls-rotation.ts";
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
  OcspMonitor,
  resolveOcspEndpointOptions,
  type OcspEndpointOptions,
  type ResolvedOcspEndpointOptions,
} from "./ocsp.ts";
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
import { DnsCache, type DnsCacheOptions } from "./dns-cache.ts";
import { warmupOutboundPool, resolveWarmupOptions } from "./warmup.ts";
import { AuditSink, type AuditSinkOptions } from "./audit-sink.ts";
import { SyslogAuditSink, type SyslogAuditSinkOptions } from "./syslog-sink.ts";
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
  type ClientHttp2Session,
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
import {
  compileEd25519OutboundKey,
  ED25519_KEY_ID_HEADER,
  ED25519_SIGNATURE_HEADER,
  signEd25519Outbound,
  type CompiledEd25519OutboundKey,
  type Ed25519OutboundKeyConfig,
} from "./outbound-ed25519.ts";
import type { KeyObject } from "node:crypto";
import type { AuditLog } from "./audit.ts";
import { DeliveryEventArchiver } from "./event-archive.ts";
import { resolveOrderedConfig } from "./ordered.ts";
import { buildDeliverySnapshot } from "./delivery-status.ts";
import type { EndpointConfigPatch } from "./hotreload.ts";
import {
  EndpointRegistry,
  deliverPolicyPatch,
  diffEndpointConfigs,
  hasDeliverPolicy,
  summarizeEndpointConfig,
  waitForEndpointDrain,
  type EndpointConfig,
  type EndpointRecord,
} from "./endpoints.ts";
import {
  exportConfig,
  applyConfig,
  ConfigApplyError,
  type ConfigSnapshotInventory,
} from "./config-snapshot.ts";
import {
  ApiVersionRouter,
  VersionMetrics,
  type ApiVersionOptions,
  type ApiVersionRoute,
} from "./version.ts";
import {
  assertValidEndpointSchemaRules,
  InboundSchemaRegistry,
  SchemaMetrics,
  type EndpointSchemaRule,
  type PayloadSchema,
  type SchemaRegistration,
} from "./schema.ts";
import {
  OutboundSchemaRegistry,
  OutboundSchemaViolationError,
  type OutboundSchemaMetrics,
} from "./outbound-schema.ts";
import type { ProbeOptions } from "./downstream-probe.ts";
import type { OtlpExporterOptions } from "./otlp.ts";
import {
  assertValidBrotliCompressConfig,
  maybeCompressBrotliOutbound,
  type BrotliCompressOptions,
} from "./brotli.ts";
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
 * WR-123: cap on how many archived events one `Last-Event-ID` reconnect
 * may pull. A larger gap is not replayed partially — the client gets
 * 210 Gone and rebuilds from `GET /events/archive` instead.
 */
const SSE_REPLAY_MAX_EVENTS = 10_000;

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
   * Independent private-CA trust bundle for this shadow target (WR-163)
   * — a PEM bundle string, verified against the shadow downstream's
   * chain. The shadow sender is a separate copy, so it is configured
   * here, not in the top-level `tlsCa`. Invalid bundles throw
   * `RangeError` at startup.
   */
  tlsCa?: string;
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
   * Inject e.g. `new Ed25519Verifier(pem)` or `new RsaPssVerifier(pem)` to
   * change schemes. Cannot be combined with `signingKeys`.
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
   * `/hooks/solana-program`, RSA-PSS for `/hooks/bank` (WR-110), and
   * HMAC-SHA256 everywhere else. Rules are
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
   * Inbound signature algorithm negotiation (WR-138, see
   * `src/signature-alg.ts`): upstreams name the algorithm they signed
   * with in the `x-signature-alg` header (`"hmac-sha256"` / `"ed25519"`)
   * and the relay verifies with the matching rule's verifier instead of
   * the global default. The rules array is the allowlist — a negotiated
   * name that is not listed is answered 400 and audited as `rejected`
   * with reason `unsupported_algorithm`, never enqueued. Unset means
   * negotiation is disabled: the header is ignored and the legacy
   * default verifier applies, fully backward compatible (effectively
   * "only hmac-sha256", the default). Negotiation never widens a
   * per-endpoint verifier rule (WR-29): a pinned path keeps its
   * verifier and the header is ignored there. Invalid rules throw
   * `RangeError` at startup.
   */
  signatureAlgorithms?: SignatureAlgorithmRule[];
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
   *
   * WR-144: each route accepts an opt-in `sunsetAt` (epoch-ms or an
   * ISO-8601 string). Once reached, intakes matching the version are
   * answered `410 Gone` with the RFC 8594 `Sunset` header and audited as
   * `rejected` with reason `version_sunset` — they never enter the retry
   * queue. Sunsets can be set/cleared at runtime (immediate effect, no
   * restart) via `POST /config/version-sunset` (operator, admin scope;
   * audited as `version_sunset_updated`) and inspected with
   * `GET /config/version-sunset` (operator, read scope).
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
   *
   * A rule may opt into the WR-96 compatibility corpus
   * (`compatibilityCorpus`): manually registered sample payloads the
   * endpoint accepted, and/or auto-accumulated accepted payloads
   * (bounded). At registration the schema's validator is run against
   * every corpus sample; a rejected or throwing sample fails the whole
   * server startup with `RangeError` — and registering a *newer* schema
   * version for the same pattern is gated the same way, leaving the
   * currently serving version untouched on failure.
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
   * W3C Trace Context propagation (WR-98; see `src/trace-context.ts` and
   * the `traceContext` `RetryQueue` option): opt-in `traceparent` /
   * `tracestate` handling. A valid inbound `traceparent` becomes the
   * event's trace ID (its sampled flag and `tracestate` ride along);
   * every outbound delivery stamps `traceparent` with a fresh child span
   * id per attempt — caller-propagated contexts keep their sampled flag,
   * relay-generated ones use the configured `sampled` (default `true`).
   * An invalid inbound `traceparent` is ignored (never a 400). An
   * explicit server-level `traceContext` wins over the nested
   * `retry.traceContext`. Off by default: unset means no parsing, no
   * stamping, zero behavior change.
   */
  traceContext?: TraceContextOptions;
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
   * WR-106: quorum fan-out — M-of-N downstream acknowledgement (see
   * `src/quorum.ts`): the multi-settlement-channel / redundant-notification
   * scenario. Per-endpoint opt-in — exact `forwardUrl`/endpoint
   * `targetUrl` -> `{ targets, quorum }`. An admitted event for a
   * configured endpoint is dispatched to every target (each through the
   * relay's main sender, with the full per-endpoint retry/backoff/circuit/
   * quota/dead-letter machinery); M acknowledgements settle the fan-out
   * as delivered. Progress is observable via `GET /quorum`, audited as
   * `quorum_dispatched` / `quorum_acknowledged` / `quorum_satisfied` /
   * `quorum_failed` / `quorum_target_dead_lettered`, and counted in
   * `relay_quorum_*`. Settled fan-outs are retained by a retention
   * window (WR-109): `quorumRetentionMs` after the verdict (default 1h)
   * and at most `quorumMaxFanouts` settled fan-outs (default 10_000,
   * oldest verdict evicted first); evictions are audited as
   * `quorum_evicted`, counted in `relay_quorum_evicted_total`, and
   * exposed via `GET /quorum/stats` (the object-shaped companion to the
   * array-shaped `GET /quorum`). An explicit server-level `quorum` wins
   * over the nested `retry.quorum`. Off by default; invalid values throw
   * `RangeError` at startup.
   */
  quorum?: QuorumConfig;
  /**
   * WR-109: retention window for settled quorum fan-outs — milliseconds
   * after the verdict, after which the fan-out is archived (audited as
   * `quorum_evicted`) and evicted from memory. In-progress fan-outs are
   * never evicted. An explicit server-level `quorumRetentionMs` wins over
   * the nested `retry.quorumRetentionMs`. Off by default (= 1h);
   * invalid values throw `RangeError` at startup.
   */
  quorumRetentionMs?: number;
  /**
   * WR-109: cap on retained settled quorum fan-outs (LRU by verdict
   * time; oldest verdict evicted first). In-progress fan-outs are
   * exempt. An explicit server-level `quorumMaxFanouts` wins over the
   * nested `retry.quorumMaxFanouts`. Off by default (= 10_000);
   * invalid values throw `RangeError` at startup.
   */
  quorumMaxFanouts?: number;
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
   * Outbound private-CA trust bundles (WR-163; see `src/pinning.ts`):
   * per-endpoint PEM CA bundle, keyed by exact delivery `targetUrl`. The
   * value is a PEM *string* (one or more `CERTIFICATE` blocks) held in
   * memory — no file paths, so rotation is a config change. When set for
   * an endpoint, Node verifies the downstream's chain against the bundle
   * instead of the public PKI: this is what makes private-PKI downstreams
   * (self-signed roots, enterprise CAs) reachable — without it, Node
   * rejects the chain before a single payload byte is written.
   * Orthogonal to `tlsPins` (WR-21): the bundle builds *chain trust*,
   * pins anchor *identity*; when both are set for an endpoint the chain
   * is verified against the bundle first and the SPKI pin check runs on
   * `secureConnect` after. The keep-alive pool keys connections by
   * (origin, proxy, pins, client-cert, ca), so a connection handshaked
   * against one trust store can never serve an endpoint using another.
   * Invalid bundles (no `CERTIFICATE` block, unparseable DER) throw
   * `RangeError` at startup. Endpoints without an entry keep the default
   * Node TLS verification. `https:` targets only — `wss:` targets keep
   * the WR-21/WR-45 pinning handshake, and a CA-configured endpoint
   * never rides the opt-in HTTP/2 pool (the WR-101 OCSP precedent: the
   * H2 session pool owns its own handshake and takes no `ca`, so the
   * endpoint falls back to HTTP/1.1 where the bundle rides the
   * handshake).
   */
  tlsCa?: Record<string, string>;
  /**
   * WR-165: outbound fault-injection drill (see `src/chaos.ts`):
   * `{ rules: { "<exact targetUrl>": { latencyMs?, resetConnection?,
   * statusCode? } } }`. Injected faults exercise the retry / backoff /
   * breaker / dead-letter path exactly like real failures, and are
   * audited as `chaos_injected` plus counted separately in
   * `relay_chaos_injected_total{endpoint,kind}`. Off by default: with no
   * `chaos` configured the sender is unwrapped — zero behavior change,
   * zero overhead. Invalid rules throw `RangeError` at startup.
   */
  chaos?: ChaosConfig;
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
   * Inbound mTLS — client-certificate authentication for the relay's own
   * listeners (WR-103, see `src/inbound-mtls.ts`). The relay's listeners
   * are plain HTTP by default; configuring this makes the listeners that
   * can require a client certificate terminate TLS themselves (Node
   * `https` with `requestCert: true`, `rejectUnauthorized: false`):
   *
   * - `key` / `cert`: the relay's own TLS identity (PEM strings held in
   *   memory — no file paths, so rotation is a config change). Required:
   *   a listener that enforces mTLS must terminate TLS.
   * - `ca`: the client CA chain (PEM string or array) that presented
   *   client certificates must chain to.
   * - `requireCert` (default `true`): every route requires a client
   *   certificate. Set `false` with `operatorMtls: true` to require
   *   certificates only on operator routes while webhook ingest stays
   *   open.
   * - `clientFingerprints`: optional whitelist of whole-certificate
   *   SHA-256 fingerprints (`"sha256/<base64>"`, `"sha256:<base64>"`, or
   *   bare base64 — the WR-21 spellings). A chain-valid certificate
   *   whose fingerprint is not listed is rejected.
   * - `operatorMtls` (default `false`): operator routes (`/dead-letter`,
   *   `/metrics`, `/events`, …) independently require a client
   *   certificate.
   *
   * The handshake never aborts on a missing/invalid certificate —
   * enforcement happens at request time, so a rejected caller gets a
   * proper HTTP 401 (`reason` `client_cert_required` /
   * `client_cert_invalid`, audited as `rejected` like the other intake
   * gates) instead of a bare TLS alert. A verified caller's
   * `clientCertFingerprint` / `clientCertSubject` ride the `accepted` /
   * `rejected` audit events.
   *
   * Hot-reload: `server.updateInboundMtlsConfig(patch)` swaps the CA,
   * key/cert, whitelist, and policy at runtime (new TLS handshakes only;
   * established connections keep the previous secure context).
   * *Enabling* or *disabling* inbound mTLS needs a restart — a bound
   * listener cannot change between plain HTTP and HTTPS at runtime.
   * Off by default: unset means plain-HTTP listeners and zero behavior
   * change. Invalid values throw `RangeError` at startup.
   */
  inboundMtls?: InboundMtlsConfig;
  /**
   * Outbound mTLS client certificate rotation (WR-89, see
   * `src/mtls-rotation.ts`): `{ "<exact targetUrl>": { certificates,
   * graceMs? } }`, keyed by exact delivery `targetUrl`. Several client
   * identities coexist per endpoint — the new certificate (declared
   * first) is presented on new handshakes, retired certificates stay
   * eligible as handshake fallbacks inside `graceMs` (default 24h,
   * boundary inclusive, same as WR-20/WR-81), and the id of the
   * certificate actually used is audited as `clientCertId` on the
   * `delivered` / `dead_letter` events (and inside `response_summary`).
   * Cannot be combined with `tlsClientCerts` on the same endpoint —
   * configuring both throws `RangeError` at startup. Composes with
   * `tlsPins` (a pin mismatch never falls back — it is not about the
   * client identity), the keep-alive pool (agents are keyed per
   * *actually used* certificate identity, so a connection authenticated
   * as one identity never serves another), the H2 session pool, and the
   * WR-73 cert-expiry monitor (retired certificates whose grace window
   * has fully elapsed are no longer warned about). Off by default.
   * Invalid values throw `RangeError` at startup.
   */
  tlsClientCertRotation?: Record<string, RotatingClientCertConfig>;
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
   * Outbound per-endpoint TLS OCSP revocation checking (WR-101, see
   * `src/ocsp.ts`): `{ "<exact targetUrl>": { mode?, useStapled?,
   * responderUrl?, responderFetcher?, responderTimeoutMs? } }`, keyed by
   * exact delivery `targetUrl`. After the handshake the relay checks
   * whether the peer's certificate was revoked — stapled OCSP response
   * first (`requestOCSP: true` on the handshake), responder fallback
   * second (explicit `responderUrl`, else the leaf's AIA extension, via
   * the pluggable `responderFetcher`). A `revoked` verdict destroys the
   * request with `OcspRevokedError` *before* a single payload byte is
   * written (the revoked peer never observes the body); the attempt
   * follows the normal retry / dead-letter path, an `ocsp_revoked` audit
   * event fires, the alert hook fires, and the outcome counts in
   * `relay_ocsp_total{endpoint,status}`.
   *
   * `mode` (default `"fail-open"`): what happens when the revocation
   * *status* cannot be determined (no stapled response, no/failing
   * responder, malformed response). `"fail-open"` lets the delivery
   * proceed after firing the alert; `"fail-closed"` fails the attempt
   * with `OcspError`. A `revoked` verdict rejects the delivery in both
   * modes. **Pinned endpoints should use `"fail-closed"`** — a pin
   * already says "I know exactly which key to expect", so failing
   * closed on revocation-telemetry loss is the consistent posture; an
   * unpinned endpoint typically stays `"fail-open"` so a dead OCSP
   * responder cannot take down deliveries.
   *
   * Orthogonal to `tlsPins` (WR-21): pinning anchors *identity* (stops a
   * compromised CA / MITM with a valid-but-unexpected certificate),
   * OCSP checks *revocation freshness* (stops a once-valid certificate
   * killed after issuance). The pin check runs first; OCSP runs on the
   * pinned (or PKI-verified) peer. An OCSP *query* failure explicitly
   * does NOT count as a circuit-breaker failure (it is a local
   * telemetry outage, not a sick endpoint); a revocation does.
   *
   * Off by default: endpoints without an entry behave exactly as
   * before, and `GET /metrics` exposes no `relay_ocsp_*` series until
   * the first check runs. The keep-alive pool binds OCSP endpoints to
   * their own agents (`|ocsp`): stapling is requested on every
   * handshake and TLS session resumption is disabled (a resumed
   * handshake carries no certificate to check). Applies to `https:`
   * targets on the HTTP/1.1 path; an OCSP-configured endpoint is kept
   * off the opt-in HTTP/2 path rather than silently skipping the
   * check, and `wss:` targets are not covered in this round (the
   * WebSocket pool owns its own handshake). Invalid values throw
   * `RangeError` at startup.
   */
  tlsOcsp?: Record<string, OcspEndpointOptions>;
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
   * Outbound per-endpoint phase timeout budgets (WR-143, see
   * `src/phase-timeouts.ts`): `{ "<exact targetUrl>": { connectMs?,
   * tlsMs?, firstByteMs?, bodyMs? } }`, keyed by exact delivery
   * `targetUrl`. Each entry budgets the WR-95 delivery phases of one
   * attempt separately: `connect` (socket-assigned → TCP established),
   * `tls` (TCP established → TLS handshake complete, https only),
   * `firstByte` (request-issued → first response bytes), `body`
   * (first response bytes → response end, 2xx only). When a phase's
   * budget expires before the sender observes that phase's completion,
   * the attempt fails with a typed `PhaseTimeoutError` — classified
   * `"retryable"` by the default fallthrough (see `src/failure.ts`),
   * so it takes the normal backoff / dead-letter path. A `connect`
   * or `tls` budget firing destroys the request before a single
   * payload byte is written (the pinning.ts/ocsp.ts zero-leak
   * standard).
   *
   * Off by default: endpoints without an entry keep the current
   * single attempt-total-timeout behavior untouched. `dns` is never
   * budgeted (not attributable per-request, WR-95 convention).
   * `connect`/`tls` are only measurable on a fresh direct socket
   * (WR-95): on pooled reuse or behind a proxy they report
   * unavailable, so their timers never arm there — budgets fire
   * against measured phases only. Applies to the HTTP/1.1 path;
   * phase-timeout endpoints are kept off the opt-in HTTP/2 path
   * (per-request phases don't exist on a multiplexed session — the
   * WR-101 OCSP precedent), and `wss:` targets are not covered.
   * Layering with WR-76 `deliveryDeadline` / WR-99: the phase budgets
   * are per-attempt allocations *inside* one attempt; the delivery
   * deadline stays end-to-end — both may be configured. All values
   * must be positive integers (ms) with at least one phase per
   * entry; invalid entries throw `RangeError` at startup.
   */
  phaseTimeouts?: Record<string, PhaseTimeoutBudgets>;
  /**
   * Outbound tail-latency hedging (WR-146, see `src/hedged.ts`): when a
   * delivery attempt to a hedgeable endpoint has not returned within
   * `hedgeDelayMs`, a second identical attempt is issued in parallel —
   * first to settle wins, the loser is cancelled. Opt-in (off by
   * default). Hedging duplicates a downstream hit on slow endpoints, so
   * only endpoints listed in `hedgeableEndpoints` (exact `targetUrl`
   * match) are ever hedged — conservative by construction; omit the
   * list (or the whole block) and nothing hedges. A `hedgeable(item)`
   * predicate may override the list for library-style dynamic routing.
   * A returned 429/5xx settles the attempt, so it never triggers a
   * hedge — it takes the normal classify → backoff path. Each hedge
   * attempt is an independent full attempt (own keep-alive checkout,
   * own WR-99 deadline budget, own WR-143 phase budgets). The losing
   * attempt is cancelled via `AbortSignal` on the HTTP/1.1 path
   * (`HedgeCancelledError`, swallowed by the wrapper); H2/WS attempts
   * ignore the signal (best effort). `hedgeDelayMs` must be a positive
   * integer; invalid configs throw `RangeError` at startup. Wraps
   * `opts.sender` when one is injected (a custom sender that ignores
   * the signal gets abandon-the-loser semantics).
   */
  hedgedRequests?: {
    /** Master switch; absent/`false` disables hedging entirely. */
    enabled?: boolean;
    /** Ms after issue with no response before the hedge fires. */
    hedgeDelayMs: number;
    /** Exact targetUrls eligible for hedging (default: none). */
    hedgeableEndpoints?: string[];
    /** Dynamic predicate override (wins over `hedgeableEndpoints`). */
    hedgeable?: (item: RetryItem) => boolean;
  };
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
   * Outbound brotli compression (WR-142, see `src/brotli.ts`):
   * per-endpoint opt-in, keyed by exact delivery `targetUrl`. Payloads at
   * or above `thresholdBytes` (default 1024) are brotli-compressed when
   * (and only when) the compressed form is actually smaller;
   * `Content-Encoding: br` is stamped and `Content-Length` reflects the
   * compressed size. The relay signature (`x-relay-signature`) covers the
   * compressed wire bytes — exactly what the downstream receives.
   * Precedence: when an endpoint is configured in `compressBrotli`, the
   * brotli path wins over both gzip paths (`compressOutbound`,
   * `compressThreshold`) for that endpoint — compression is never
   * stacked. Fire-and-forget like WR-40: no content-type whitelist, no
   * 415 fallback (an endpoint whose downstream may reject `br` should
   * use `compressThreshold` instead). Applies to the HTTP/1.1 and HTTP/2
   * delivery paths only — WebSocket deliveries keep their RFC 7692
   * permessage-deflate story (`src/deflate.ts`) and never pass through
   * here. Compressed bytes saved per endpoint are counted in
   * `relay_compressed_bytes_saved_total` (the same tracker as the gzip
   * paths). Invalid values throw `RangeError` at startup.
   */
  compressBrotli?: Record<string, BrotliCompressOptions>;
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
   * WR-92: outbound DNS resolution cache (see `src/dns-cache.ts`) — a
   * compiled `DnsCache` or options to build one. When set, the default
   * sender's pooled agents (WR-24) and one-off requests resolve
   * hostnames through it (stale-while-revalidate, 60s default TTL), and
   * the WR-34 downstream probes do too. One instance is shared by the
   * main and shadow senders: a single counter set, a single `/metrics`
   * block (`relay_dns_cache_*`). `undefined` keeps the OS-resolver
   * behavior. Invalid values throw `RangeError` at startup.
   */
  dnsCache?: DnsCache | DnsCacheOptions;
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
   * Per-endpoint inbound body size overrides (WR-102). Rules are
   * `{ pattern, maxBodyBytes }` — exact (`/hooks/payments`) or prefix
   * (`/hooks/*`) path patterns, first match wins, unmatched paths keep
   * the global `maxBodyBytes`. A rule may be tighter or looser than the
   * global budget, and it governs all three enforcement points for the
   * matched endpoint: the declared Content-Length pre-check, the
   * `readRawBody` streaming cap, and the `gunzipCapped` decompression
   * cap (a gzip bomb on the endpoint is answered 413 under the
   * endpoint's own budget). Over-limit bodies are answered 413 and
   * audited as `rejected` with reason `body_too_large` carrying the
   * *effective* `maxBodyBytes`. This is the transport layer — it runs
   * before signature verification and before WR-41 schema validation
   * (semantic validation); the two are orthogonal. The batch envelope
   * (`POST /ingest/batch`) is subject to the same gate, so per-item
   * payloads are bounded by the outer envelope. Unset means exact
   * current global behavior. Invalid rules throw `RangeError` at
   * startup.
   */
  endpointBodyLimits?: EndpointBodyLimitRule[];
  /**
   * Outbound request signing (WR-26, see `OutboundSigningConfig`): when set,
   * every delivery made by the default sender carries
   * `x-relay-signature: sha256=<hex>` — the HMAC-SHA256 of the forwarded
   * body — plus `x-relay-key-id` when `keyId` is given, so the downstream
   * can prove the request really came from this relay (verify with
   * `verifySignature(body, header, secret)` from `src/verify.ts`). The
   * opt-in `ed25519` sub-config (WR-124) additionally stamps
   * `x-relay-ed25519-signature: ed25519=<hex>` for downstreams that
   * verify with the public key alone — the delivery is accepted when
   * either signature verifies. Off by default; applies to the default
   * sender only — an injected `sender` signs (or doesn't) on its own.
   * Inbound `x-relay-signature` / `x-relay-key-id` /
   * `x-relay-ed25519-signature` / `x-relay-ed25519-key-id` headers are
   * always stripped from the forwarded header set, so a sender can never
   * smuggle a forged relay signature downstream. Invalid values throw
   * `RangeError`.
   */
  outboundSigning?: OutboundSigningConfig;
  /**
   * Dynamic endpoint registry (WR-114, see `src/endpoints.ts`): static
   * endpoint records applied at startup — `{ targetUrl, verifier?,
   * circuitBreaker?, quota?, maxConcurrentPerEndpoint?, proxy?,
   * tlsPins?, ordered? }`. Every record is fully validated before any
   * is applied (an illegal value throws `RangeError` at startup with
   * zero partial application). The registry stays live after startup:
   * the operator API (`POST /endpoints`, `PUT /endpoints/{id}`,
   * `GET /endpoints`, `DELETE /endpoints/{id}`) manages it at runtime
   * with WR-32 hot-reload semantics. Unset (default) keeps the exact
   * pre-WR-114 behavior — the registry resolves nothing and every
   * endpoint falls back to the static per-endpoint options above.
   */
  endpoints?: EndpointConfig[];
  /**
   * WR-114: how long `DELETE /endpoints/{id}` waits for in-flight
   * deliveries to drain before answering 409 (use `?force=true` to skip
   * the drain). Default: 30_000 ms. Must be a finite number > 0.
   * Invalid values throw `RangeError` at startup.
   */
  endpointDrainTimeoutMs?: number;
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
   * Per-endpoint payload transform (WR-115, see `src/transform.ts`):
   * `{ "<exact targetUrl>": PayloadTransformRules }` — field
   * renames/maps/deletes, constant injection, and outbound header
   * injection (static or `{{event_id}}` / `{{endpoint}}` / `{{attempt}}`
   * / `{{timestamp}}` templates), applied to the JSON payload just
   * before the wire request is built (after the payload is final,
   * before compression / E2EE sealing / signing, so `x-relay-signature`
   * always covers the transformed bytes). Useful when a downstream
   * speaks a different dialect than the producer — e.g. a payment
   * gateway that wants `amount_cents` instead of `amount`, or a ledger
   * hook that requires a static `x-tenant` header. Interaction order:
   * transform → brotli/gzip (WR-142/WR-40/WR-75) → E2EE (WR-58) → sign
   * (WR-26); for
   * WR-09 batched deliveries the merged envelope is transformed as one
   * JSON document. A non-JSON payload (or any runtime transform
   * failure) dead-letters the item on the first attempt and audits
   * `transform_failed` — never silently dropped. Opt-in; endpoints
   * without rules are untouched. Applies to the default sender only.
   * Invalid values throw `RangeError`/`TemplateError` at startup.
   */
  payloadTransforms?: Record<string, PayloadTransformRules>;
  /**
   * Per-endpoint outbound payload JSON schema validation (WR-117, see
   * `src/outbound-schema.ts`): `{ "<exact targetUrl>": PayloadSchema }`
   * — a pluggable shape gate on the *post-transform* payload, keyed by
   * exact `targetUrl` (no prefix matching — the outbound config
   * convention in this relay: WR-60 `tlsSniOverrides`, WR-42 H2 pool
   * keys). Pipeline order: transform (WR-115) → schema → brotli/gzip
   * (WR-142/WR-40/WR-75) → E2EE (WR-58) → sign (WR-26), so `x-relay-signature`
   * always covers the validated bytes — exactly what the downstream
   * receives and verifies. A violation throws
   * `OutboundSchemaViolationError`, classified `"non_retryable"`: the
   * item dead-letters on the first attempt without burning the retry
   * budget, the endpoint's breaker is untouched, and the audit log gets
   * a dedicated `schema_violation` event (delivery id, error, endpoint,
   * schema name/version) alongside the usual `dead_letter` — never
   * silently dropped. A non-JSON payload under a configured rule fails
   * validation (a JSON schema has nothing to say about opaque bytes —
   * the WR-41 convention); a throwing validator is fail-closed.
   * Opt-in; endpoints without rules keep byte-exact current behavior.
   * Applies to the default sender only. Invalid rules throw
   * `RangeError` at startup — never mid-delivery.
   */
  outboundSchemas?: Record<string, PayloadSchema>;
  /**
   * Per-endpoint AWS SigV4 request signing (WR-116, see `src/sigv4.ts`):
   * `{ "<exact targetUrl>": AwsSigV4EndpointConfig }` — access key id +
   * secret *reference* + region + service. Each delivery attempt to a
   * configured endpoint stamps `Authorization` + `x-amz-date` per the
   * AWS Signature Version 4 spec, over the final wire bytes (after
   * transform/compression/E2EE). The secret itself is never in this
   * config: `secretRef` is resolved per attempt through
   * `awsSecretResolver` (default: the ref names an environment
   * variable), so config snapshots and the operator API can never leak
   * plaintext key material, and rotation works without a restart.
   * Orthogonal to `outboundSigning` (WR-26 HMAC): both may be enabled
   * for one endpoint. A missing secret fails the attempt as
   * `SigV4SecretUnavailableError` (classified `non_retryable`).
   * Applies to the default sender only. Invalid values throw
   * `RangeError` at startup.
   */
  awsSigV4?: Record<string, AwsSigV4EndpointConfig>;
  /**
   * Per-endpoint OAuth2 `client_credentials` token management (WR-129,
   * see `src/oauth-client.ts`): `{ "<exact targetUrl>":
   * OAuth2ClientCredentialsConfig }` — when set, the default sender
   * fetches, caches, and refreshes an access token for the downstream
   * and stamps `Authorization: Bearer <token>` on every delivery to
   * that endpoint (http/https only). The token cache expires entries
   * 30s before `expires_in` (clock-skew reserve) and is isolated per
   * `(token_endpoint, scope)`; a downstream 401 triggers exactly one
   * forced refresh + redelivery inside the same attempt. The
   * `client_secret` lives in memory only — never logged, never audited.
   * Orthogonal to `outboundSigning` (WR-26 HMAC), the WR-124 Ed25519
   * stamp, and `awsSigV4`: any combination may be enabled for one
   * endpoint (downstream picks either or requires both). Applies to the
   * default sender only. Invalid values throw `RangeError` at startup.
   */
  oauth2?: Record<string, OAuth2ClientCredentialsConfig>;
  /**
   * WR-116: resolves `awsSigV4` `secretRef`s to key material per
   * delivery attempt. Defaults to `process.env[ref]`; inject a
   * vault/KMS-backed function to keep secrets out of the environment.
   */
  awsSecretResolver?: SecretResolver;
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
   * Per-endpoint delivery dry-run drill mode (WR-145; see
   * `src/delivery-dryrun.ts`): exact `targetUrl` → drill config. A
   * drill dispatch walks the intake-to-dispatch pipeline but answers
   * with a configurable canned response (`status`/`body`/`delayMs`)
   * instead of a physical outbound request — and never writes the
   * circuit breaker, the dead-letter queue, the retry budget, quotas,
   * or the urgent lane (control plane: read zero, write zero). Drill
   * outcomes are audited with `dry_run: true` and counted in the
   * isolated `relay_dry_run_deliveries_total{endpoint,outcome}`
   * dimension. Toggle at runtime via `POST /endpoints/dry-run`
   * (operator, admin scope; audited as
   * `endpoint_dry_run_enabled`/`endpoint_dry_run_disabled`). Off by
   * default — wins over the nested `retry.deliveryDryRun` when both
   * are set.
   */
  deliveryDryRun?: DeliveryDryRunOptions;
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
   * Stale-endpoint auto-pause (WR-100; see `src/stale-pause.ts` and the
   * `stalePause` `RetryQueue` option): opt-in configuration-rot
   * hygiene — a background sweep auto-pauses a logical endpoint with no
   * successful delivery for `staleAfterDays` (default 30) and nothing
   * pending, through the exact WR-50 parking mechanics (inbound events
   * still accepted and parked — never discarded). Each auto-pause is
   * audited as `endpoint_auto_paused` (endpoint/idleDays/
   * staleAfterDays/lastSuccessfulDeliveryAt — never the payload), which
   * is the operator alert channel for this feature (edge-triggered, one
   * event per transition), alongside the
   * `relay_endpoint_auto_pauses_total` Prometheus counter; resume with
   * the ordinary `POST /endpoints/resume`. This is not the WR-10
   * circuit breaker: the breaker is transient fault handling,
   * auto-pause is rot hygiene. Off by default. Invalid values throw
   * `RangeError` at startup.
   */
  stalePause?: StalePauseOptions;
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
   * Two-phase approval for dead-letter replays (WR-135; see
   * `src/replay-approval.ts` and the `replayApproval` `RetryQueue`
   * option). Opt-in: when set, the executing side of `POST
   * /dead-letter/replay` and `POST /dead-letter/{id}/replay`
   * (non-dry-run) consumes a one-shot `approvalToken` issued by `POST
   * /dead-letter/replay/approve-request` — missing, expired, reused, or
   * scope-mismatched tokens answer 403, and dry-run previews never need
   * approval (zero side effects). A replay re-fires the downstream
   * handler, so for payment webhooks this is the second pair of eyes
   * before real money moves again. Token consumption is audited as
   * `replay_approved`; executing with an expired token is audited as
   * `replay_approval_expired`. Off by default — replays run on the
   * operator token alone, exactly the pre-WR-135 behavior. Invalid values
   * throw `RangeError` at startup.
   */
  replayApproval?: ReplayApprovalOptions;
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
   * Dead-letter storm escalation alerts (WR-93; see `src/escalation.ts`
   * and the `escalation` `RetryQueue` option). Opt-in, off by default:
   * when the dead-letter count for one (tenant, endpoint) scope inside
   * the sliding window (`windowMs`, default 10 minutes) reaches
   * `threshold` (default 20), the relay POSTs one HMAC-SHA256-signed
   * JSON alert (`x-relay-signature`, WR-26 style) to the operator's
   * `url`.
   *
   * The aggregate counterpart to the per-delivery `completionCallback`
   * receipts above: completion callbacks notify the *caller* of every
   * terminal delivery; storm escalation notifies the *operator* once per
   * threshold crossing. Escalations are edge-triggered with a cooldown
   * (`cooldownMs`, default 1 hour) — one storm, one alert — and are
   * audited as `dead_letter_escalated` (dispatched) /
   * `dead_letter_escalation_failed` (alert POST gave up). The queue's
   * `getEscalationStats()` exposes the per-scope state, and the operator
   * can acknowledge a scope to rearm it.
   */
  deadLetterEscalation?: DeadLetterEscalationOptions;
  /**
   * Replay protection for inbound webhooks. When set, each accepted POST must
   * carry a unique `x-nonce` header: a nonce seen inside the guard's window is
   * rejected with 409 (`duplicate_nonce`), a missing nonce or an `x-timestamp`
   * (unix seconds) outside the window is rejected with 400. The nonce is
   * scoped by the resolved `targetUrl` (WR-122), so unrelated targets never
   * collide. Rejections are audited as `rejected` with the guard's reason.
   * Construct the guard with `journalDir` to survive restarts (see
   * `src/replay.ts`); call `await guard.flush()` before a planned shutdown
   * when the journal tail must be durable. Off by default, so
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
   * Relay mesh forwarding (WR-107, see `src/mesh.ts`): chain this relay
   * to other relays so an event can hop relay → relay before reaching
   * the final downstream. When set, inbound `x-relay-hops` is parsed
   * (absent = 0), rejected 400 past `maxHops` (the loop guard), carried
   * on the item through retries/dead-letter/replay, and stamped back
   * out as `x-relay-hops: meshHops + 1` on every outbound wire request.
   * Mutual trust between hops rides the existing mechanisms: sign with
   * WR-26 outbound signing on the sending relay, verify with a
   * registered verifier (WR-01/WR-20/WR-29) on the receiving one — or
   * upgrade the link to mutual TLS with `mesh.mtls` (WR-112: inbound
   * mesh-peer claims must present a client certificate verified through
   * the `inboundMtls` chain; outbound mesh hops only go over `https:`
   * with a WR-36 `tlsClientCerts` identity for the peer endpoint).
   * Off by default — when unset the header is stripped at intake and
   * never stamped, i.e. zero behavior change.
   */
  mesh?: MeshOptions;
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
   * Inbound GeoIP country policy (WR-158, see `src/geoip.ts`): a
   * config-only country gate — no MaxMind, no binary, no lookups, just a
   * `{ cidr, country }` table of IPv4/IPv6 CIDRs to ISO 3166-1 alpha-2
   * country codes plus a `policy` of `{ default: "allow" | "deny",
   * countries: { <CC>: "allow" | "deny" } }`. The first table match wins;
   * an unmapped IP follows the policy default; an unparseable client IP
   * fails closed to `deny`.
   *
   * The check runs in the intake gates after the WR-53 IP ACL and before
   * the body is read — the same header-only admission tier — so a blocked
   * country costs zero bandwidth and zero downstream state: the denial
   * never enqueues, burns no retry budget, and never trips the breaker.
   * Denials are answered 403 (with `connection: close`) and audited as
   * `rejected` with reason `geo_blocked` (plus `ip` and `country`).
   *
   * The client IP reuses the WR-53 `clientIp` resolution when an IP ACL
   * is configured (`x-forwarded-for` through `trustedProxies`), otherwise
   * the direct socket peer — identical trusted-proxy semantics either
   * way. Off by default: with no `geoIp`, intake behavior is exactly the
   * legacy one. Invalid tables/policies throw `RangeError` at startup.
   */
  geoIp?: GeoIpOptions;
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
   * Inbound sender reputation scoring (WR-119; see `src/reputation.ts`):
   * opt-in per-sender behavior scoring keyed by the inbound API key id
   * (or `"anonymous"` when no key guards the endpoint). Signature
   * verification failures, inbound rate-limit hits, and schema
   * violations accumulate weighted penalties; the demerit decays
   * exponentially (`halfLifeMs`, default 10 minutes), so quiet senders
   * recover on their own. Below `lowThreshold` (default 40) the sender
   * is downgraded and intake tightens automatically: (a) a halved
   * per-sender rate-limit budget on top of the configured inbound
   * limiter, (b) forced signature verification even where the API key
   * alone would authenticate (only meaningful where a verifier is
   * configured — the relay always configures one, default HMAC over
   * `secret`), (c) a doubled dedup window. Above `highThreshold`
   * (default 70) the sender upgrades back and relaxes. Crossings are
   * audited as `reputation_downgraded` / `reputation_upgraded` (key id +
   * score, no secrets) and exposed as `relay_sender_reputation_score`
   * / `relay_sender_reputation_degraded_total`. Off by default: unset =
   * zero behavior change. Invalid config throws `RangeError` at startup.
   */
  senderReputation?: ReputationOptions;
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
  /**
   * CORS policy for the operator plane (WR-159; see `src/cors.ts`):
   * `CorsPolicy` with an exact-match `allowedOrigins` allowlist plus
   * optional `allowedMethods` / `allowedHeaders` / `allowCredentials` /
   * `maxAgeSeconds`. A preflight (`OPTIONS`) to an operator path
   * (`/metrics`, `/audit`, `/dead-letter`, `/events` SSE, …) is answered
   * 204 here, before operator auth — browsers never send credentials or
   * client certificates on preflights, so gating them on auth would break
   * every dashboard. Only allowlisted origins are echoed; anything else
   * gets a bare 204 and the browser blocks the real request on its own.
   * Actual operator responses to allowlisted origins carry
   * `Access-Control-Allow-Origin` (+ `Vary: Origin`). The webhook intake
   * is untouched. Disabled by default (empty/unset allowlist): zero
   * behavior change. Invalid config throws `RangeError` at startup.
   */
  cors?: CorsPolicy;
  /**
   * Inbound HTTP server timeout hardening (WR-160; see
   * `src/http-hardening.ts`): `{ headersTimeoutMs, requestTimeoutMs,
   * maxHeaderSizeBytes }` applied to every listener the relay binds
   * (intake + operator, HTTP and HTTPS alike). Slow headers / slow body
   * are answered 408 and audited as `rejected` with reason
   * `http_timeout`; oversized headers are answered 431. The timeout is
   * enforced inbound-side: a timed-out request never reaches the intake
   * pipeline, so it burns no retry budget and never trips the breaker.
   * Unset fields keep Node's defaults (headers: min(requestTimeout,
   * 60000); request: 300000; max header size: 16384) — fully unconfigured
   * means zero behavior change. Invalid config throws `RangeError` at
   * startup.
   */
  httpHardening?: HttpHardeningOptions;
  /**
   * Per-tenant inbound rate limiting (see
   * `src/tenant-inbound-ratelimit.ts`): a token bucket per `x-tenant-id`
   * guarding the webhook intake. A request over its tenant's per-second
   * budget is answered 429 with a `retry-after` header and audited as
   * `rejected` with reason `tenant_rate_limited`. The check runs after
   * the WR-22 limiter and before signature verification, so one abusive
   * tenant's flood is rejected before it burns verifier CPU. Disabled by
   * default; requests without `x-tenant-id` are untouched (zero behavior
   * change). Orthogonal to `tenantRateLimit` (WR-97), which paces
   * *outbound* dispatch per (tenant, endpoint).
   */
  inboundTenantRateLimit?: InboundTenantRateLimitOptions;
  /**
   * Inbound WebSocket event intake (WR-130; see `src/inbound-ws.ts`): serve
   * a `ws(s)://` upgrade endpoint so producers can push events over one
   * long-lived connection instead of one HTTP POST per event.
   *
   * The endpoint reuses the HTTP intake semantics per event: HMAC/Ed25519
   * signature verification (`verifier`, `endpointVerifiers`), the
   * WR-22 inbound rate limiter, dedup (`dedup`), schema validation
   * (`payloadSchemas`), the `maxBodyBytes` / `endpointBodyLimits`
   * budget, per-endpoint API keys (`apiKeys`), and `x-trace-id` trace
   * propagation. Each text frame carries one JSON envelope shaped like a
   * WR-61 batch item (`{ "payload": "<base64>", "headers": { … } }`);
   * `x-relay-*` headers ride the upgrade request and apply to every
   * event on the connection. The server answers each event with a text
   * frame `{ "type": "event-ack", "status": "accepted" | "rejected", … }`
   * mirroring the HTTP 202 / 4xx outcome.
   *
   * Keep-alive: the server pings every `pingIntervalMs` (answering
   * client pings with pongs) and closes connections idle longer than
   * `idleTimeoutMs`; a client whose outbound buffer exceeds 1MiB is
   * disconnected like a slow SSE `/events` consumer. When the intake
   * listener terminates TLS the same listener serves `wss://` — no
   * second port. Disabled by default; invalid config throws `RangeError`
   * at startup.
   *
   * Opt-in permessage-deflate (WR-152): set
   * `inboundWs.permessageDeflate` (`true` or `{ thresholdBytes? }`) and
   * the endpoint negotiates RFC 7692 compression in the upgrade
   * handshake — strictly, the client's offer must carry both
   * no-context-takeover parameters or the upgrade fails with 400.
   */
  inboundWs?: InboundWsOptions;
  /**
   * Per-(tenant, endpoint) outbound rate limiting (WR-97; see
   * `src/tenant-ratelimit.ts` and `RetryQueueOptions.tenantRateLimit`).
   * An explicit server-level value wins over the nested
   * `retry.tenantRateLimit`; either way the queue owns the limiter. In
   * `queue` mode (default) the limit is enforced at dispatch (over-limit
   * attempts wait for the next token refill, never dropped); in
   * `reject-429` mode it is enforced here at intake — an over-limit
   * webhook is answered 429 with a `retry-after` header and audited as
   * `rejected` with reason `rate_limited`, before it ever enters the
   * queue. Disabled by default.
   */
  tenantRateLimit?: TenantRateLimitOptions;
  /**
   * Per-endpoint outbound token-bucket rate limiting (WR-154; see
   * `src/outbound-ratelimit.ts` and `RetryQueueOptions.outboundRateLimit`).
   * An explicit server-level value wins over the nested
   * `retry.outboundRateLimit`; either way the queue owns the limiter.
   * Over-limit attempts wait for the next token refill at dispatch
   * (never dropped). Disabled by default.
   */
  outboundRateLimit?: OutboundRateLimitOptions;
  /**
   * Structured delivery receipts (WR-155; see
   * `src/delivery-receipt.ts` and `RetryQueueOptions.deliveryReceipts`).
   * An explicit server-level value wins over the nested
   * `retry.deliveryReceipts`; either way the queue owns the store.
   * Every terminal delivery gets a receipt, the matching
   * `onDelivered`/`onFailed` callback fires, and the receipt lands in
   * a bounded log (optional JSONL journal). Disabled by default.
   */
  deliveryReceipts?: DeliveryReceiptOptions;
  /**
   * Per-endpoint ordered delivery (head-of-line blocking; see
   * `RetryQueueOptions.ordered` and `src/ordered.ts`). An explicit
   * server-level value wins over the nested `retry.ordered`; either way
   * the queue owns the line state. Disabled by default.
   */
  ordered?: boolean | OrderedModeOptions | Record<string, boolean | OrderedModeOptions>;
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
   * Durable scheduled deliveries (WR-133; see `src/scheduled-journal.ts`).
   * Opt-in: one-shot `deliver_at` parked deliveries are journaled to
   * `<dir>/scheduled.jsonl` and restored on restart — past-due items go
   * straight to the normal delivery path, the rest resume parked, and a
   * `scheduled_restored` audit event records what came back. Payloads are
   * sealed with `payloadEncryptor` when one is configured. Wins over
   * `retry.durableScheduledDir` when both are set.
   */
  durableScheduledDir?: string;
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
   *
   * WR-162: opt-in subscription filters — `?endpoint=` (exact match on the
   * event's `targetUrl`, same semantics as `GET /events/archive`) and
   * `?event=` (one of `delivered` / `retrying` / `dead_letter`; any other
   * value answers 400 `invalid event`, same as the archive). All filters
   * are ANDed with the WR-48 `?tenant=` filter and applied server-side
   * before emit, so a high-traffic operator connection only receives what
   * it asked for. The `Last-Event-ID` sseReplay path (below) applies the
   * same filters to the replayed events.
   *
   * WR-123: `sseReplay: true` (opt-in, default off) enables reconnect
   * resume via the standard SSE `Last-Event-ID` header. It requires the
   * `eventArchive` option: each frame carries an `id:` field with the
   * archiver-assigned monotonic `eventSeq`, and a reconnecting client that
   * sends `Last-Event-ID` gets the missed events replayed in order before
   * the live stream continues. When the cursor is older than the retained
   * archive, newer than anything produced, or the gap exceeds
   * `SSE_REPLAY_MAX_EVENTS`, the server answers `210 Gone` so the client
   * rebuilds from `GET /events/archive` instead of silently missing
   * events. Off by default: zero behavior change, `Last-Event-ID` ignored.
   */
  events?: { heartbeatMs?: number; sseReplay?: boolean };
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
  /**
   * WR-90: opt-in audit-event webhook sink (see `src/audit-sink.ts`).
   * Tails the audit log on a background worker and POSTs every new
   * audit event as signed JSON (`x-relay-audit-signature:
   * sha256=<hex>`, HMAC-SHA256 over the exact log line) to `url` — or
   * to a per-tenant URL from `tenantSinks` when the event carries a
   * tenant (WR-48). Retries with exponential backoff (`maxAttempts`,
   * default 10); an event that exhausts its retries is recorded as
   * `audit_sink_dead_letter` in the audit log (never re-forwarded) and
   * skipped. The worker never touches the delivery path — a slow or
   * dead sink only delays the cursor, never a webhook — and stops with
   * the server. Unset by default: no forwarding, byte-identical
   * behavior.
   */
  auditSink?: AuditSinkOptions;
  /**
   * Opt-in audit-event syslog sink (WR-157): forwards audit events to
   * a syslog collector (SIEM) over UDP or TCP, in RFC 5424 or CEF
   * format (`src/syslog-sink.ts`). Same outbox contract as
   * `auditSink` — background tail worker, cursor file, at-least-once
   * in order, dead-letter after `maxAttempts` — and the same
   * isolation: the worker never touches the delivery path, and stops
   * with the server. Unset by default: no forwarding, byte-identical
   * behavior. Note the UDP caveat: a silently dropped datagram is
   * never detected — use TCP when the SIEM must see every event.
   */
  syslogSink?: SyslogAuditSinkOptions;
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
 * downstream can prove the request really came from this relay. The
 * opt-in `ed25519` sub-config (WR-124) additionally stamps
 * `x-relay-ed25519-signature: ed25519=<hex>` for downstreams that verify
 * with the public key alone — accepted when either signature verifies.
 * Invalid values throw `RangeError` at startup.
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
 *
 * `tlsClientCertRotation` is the per-endpoint mTLS client certificate
 * rotation map (WR-89, see `src/mtls-rotation.ts`): a `Map` of exact
 * `targetUrl` → compiled `RotatingClientCertSet`. Compile each set once
 * at startup (`new RotatingClientCertSet(cfg)`) — the set pins the grace
 * window to its construction, so rebuilding per request would silently
 * restart it (the WR-67 lesson). New handshakes present the primary
 * certificate; when a handshake fails in a way attributable to
 * client-cert rejection (a fatal TLS alert, or a transport reset with no
 * response received — non-TLS errors never fall back), the same attempt
 * retries the handshake with each in-grace retired certificate, newest
 * first. `PooledSender#takeRotationClientCertId` reports the id used by
 * the latest handshake attempt of a delivery for audit stamping. An
 * endpoint configured in both this map and `tlsClientCerts` throws
 * `RangeError` at startup.
 */
export interface PooledSender extends Sender {
  /** The keep-alive pool, or `undefined` when pooling is disabled. */
  pool: OutboundConnectionPool | undefined;
  /** The HTTP/2 session pool, or `undefined` when H2 is not enabled. */
  http2Pool: Http2SessionPool | undefined;
  /** The WebSocket connection pool (always created). */
  wsPool: WebSocketPool;
  /**
   * WR-92: the outbound DNS resolution cache, when configured — shared
   * by the pooled and one-off request paths. `undefined` when the
   * feature is off. Counters render into `GET /metrics` as
   * `relay_dns_cache_*` via `render()`.
   */
  dnsCache: DnsCache | undefined;
  /**
   * WR-75/WR-142: cumulative per-endpoint byte savings from guarded gzip
   * (WR-75) and brotli (WR-142) compression; rendered into `GET /metrics`
   * as `relay_compressed_bytes_saved_total`.
   */
  compressionStats: OutboundCompressionTracker;
  /**
   * WR-117: per-schema/per-endpoint outbound payload schema validation
   * counters, when the feature is enabled — rendered into `GET /metrics`
   * as `relay_outbound_schema_total` via `render()`. `undefined` when
   * no `outboundSchemas` were configured; the metrics object itself
   * renders `""` until the first validated delivery, keeping
   * `GET /metrics` byte-identical for relays that never enable it.
   */
  outboundSchemaMetrics: OutboundSchemaMetrics | undefined;
  /**
   * WR-165: chaos-drill injection counters, when the feature is enabled —
   * rendered into `GET /metrics` as `relay_chaos_injected_total` via
   * `render()`. `undefined` when no `chaos` was configured; the metrics
   * object itself renders `""` until the first injected fault, keeping
   * `GET /metrics` byte-identical for relays that never run a drill.
   */
  chaosMetrics: ChaosMetrics | undefined;
  /**
   * WR-89: take-and-clear the id of the rotation client certificate most
   * recently used in a handshake attempt for the delivery `deliveryId`
   * (the queue's item id) — the primary's id, or a fallback's id when an
   * attempt rode a retired certificate. Returns `undefined` when the
   * endpoint has no rotation configured or when no handshake ran for this
   * delivery. Consuming on read keeps the bookkeeping bounded: each
   * delivery's entry is taken exactly once, by the terminal `delivered` /
   * `dead_letter` audit. Optional: custom senders simply don't implement
   * it.
   */
  takeRotationClientCertId?(deliveryId: string): string | undefined;
  /** Close all pooled connections and stop the idle reaper. Idempotent. */
  destroy(): void;
}

/**
 * WR-89: whether a failed delivery attempt's error is attributable to the
 * downstream rejecting the presented client certificate — the only
 * failure class that warrants retrying the same handshake with the next
 * rotation certificate.
 *
 * Two shapes, both observed against real downstreams:
 * - a fatal TLS alert (`ERR_SSL_TLSV1_ALERT_*`, "sslv3 alert …" text):
 *   the peer killed the handshake itself, so no application byte could
 *   have been processed;
 * - a transport reset (`ECONNRESET` / `EPROTO` / `EPIPE`, "socket hang
 *   up") with no response received: TLS 1.3 completes the client's
 *   handshake view before the server validates the client certificate,
 *   so a rejection commonly surfaces as a reset right after
 *   `secureConnect` (notably Node's own https server, which destroys the
 *   socket instead of sending an alert). The caller pairs this with its
 *   own "no response received" guard — the zero-payload-byte condition:
 *   a reset after the downstream started answering is a mid-delivery
 *   failure, never a cert rejection.
 *
 * Structured HTTP failures (`HttpDeliveryError`), pin mismatches, and
 * TLS-floor rejections are never cert rejections: they prove the
 * handshake completed and the failure is not about the client identity.
 * Anything else (DNS, timeouts, refusals) is not a TLS failure at all —
 * non-TLS errors never fall back.
 */
function isClientCertRejectedError(err: unknown): boolean {
  if (err instanceof HttpDeliveryError) return false;
  if (err instanceof TlsPinMismatchError) return false;
  if (err instanceof TlsVersionRejectedError) return false;
  const code = (err as NodeJS.ErrnoException | undefined)?.code;
  const message = err instanceof Error ? err.message : String(err);
  if (typeof code === "string") {
    if (code.startsWith("ERR_SSL_")) return true;
    if (code === "ECONNRESET" || code === "EPROTO" || code === "EPIPE") return true;
  }
  return /sslv?3 alert|tlsv?1 alert|certificate_unknown|handshake_failure|bad_certificate|socket hang up/i.test(
    message
  );
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
  onE2eeKeyRotated?: (info: E2eeKeyRotatedInfo) => void,
  /**
   * WR-89: per-endpoint mTLS client certificate rotation — a `Map` of
   * exact `targetUrl` → compiled `RotatingClientCertSet` (see the
   * `tlsClientCertRotation` doc above). Validated at startup;
   * `undefined` keeps the WR-36-only behavior.
   */
  tlsClientCertRotation?: Map<string, RotatingClientCertSet>,
  /**
   * WR-92: outbound DNS resolution cache — a compiled `DnsCache` or
   * options to build one. When set, pooled agents (WR-24) and one-off
   * requests resolve through the cache; the counters render into
   * `GET /metrics` via `PooledSender.dnsCache.render()`. `undefined`
   * keeps the OS-resolver behavior. Validated at startup.
   */
  dnsCache?: DnsCache | DnsCacheOptions,
  /**
   * WR-95: measure per-phase delivery timing (dns/connect/tls/firstByte/
   * body) on the HTTP/1.1 path and attach it as `phases` on the resolved
   * `DownstreamResponse`. Off by default — zero measurement overhead when
   * unset. `createRelayServer` enables it exactly when
   * `retry.latencyPhases` is configured.
   */
  measureLatencyPhases?: boolean,
  /**
   * WR-98: W3C Trace Context propagation (see `src/trace-context.ts`).
   * When set, every delivery built by this sender stamps `traceparent`
   * (fresh child span id per attempt; caller-propagated contexts keep
   * their sampled flag, generated ones use the configured `sampled`) and
   * forwards a caller-supplied `tracestate` verbatim. `undefined` keeps
   * the exact pre-WR-98 wire shape. Validated at startup.
   */
  traceContext?: TraceContextOptions,
  /**
   * WR-101: per-endpoint OCSP revocation checking (see `src/ocsp.ts`
   * and the `tlsOcsp` server option): `{ "<exact targetUrl>":
   * OcspEndpointOptions }`. Validated at startup; `undefined` keeps
   * the exact pre-WR-101 behavior.
   */
  tlsOcsp?: Record<string, OcspEndpointOptions>,
  /**
   * WR-101: the revocation monitor owning the verified-socket cache,
   * the `relay_ocsp_total` counters, and the revocation/alert hooks.
   * When `tlsOcsp` is set but no monitor is passed, an inert one (no
   * hooks) is created so the check still gates deliveries; the relay
   * server passes its hooked monitor here.
   */
  ocspMonitor?: OcspMonitor,
  /**
   * WR-107: relay mesh forwarding (see `src/mesh.ts`). When set, the
   * sender stamps `x-relay-hops: meshHops + 1` on every wire request
   * built for an item carrying a mesh hop count, and records each stamp
   * on `metrics` (the server's `MeshMetrics`, rendered into
   * `GET /metrics`). `undefined` keeps the exact pre-WR-107 wire shape.
   * Shadow-target sender copies (WR-85) intentionally pass `undefined`:
   * a shadow mirror is not a mesh traversal.
   * WR-112: `mtls: true` additionally refuses to forward a mesh hop
   * without mutual TLS — the peer endpoint must be `https:` with a
   * WR-36 client identity configured; anything else fails the delivery
   * locally instead of sending an unauthenticated hop.
   */
  mesh?: { metrics: MeshMetrics; mtls?: boolean },
  /**
   * WR-114: dynamic endpoint registry. When set, each delivery attempt
   * resolves its sender-side config (`verifier` signing override,
   * `proxy`, `tlsPins`) from the registry first, falling back to the
   * static per-endpoint options above. Resolution happens once per
   * attempt, before the wire request is built — a registry change
   * mid-flight never touches an attempt already on the wire (the WR-32
   * in-flight-preservation rule). `undefined` keeps the exact
   * pre-WR-114 resolution.
   */
  endpointRegistry?: EndpointRegistry,
  /**
   * WR-115: per-endpoint payload transform (see `src/transform.ts`):
   * `{ "<exact targetUrl>": PayloadTransformRules }` — field
   * renames/maps/deletes, constant injection, and outbound header
   * injection (static or `{{event_id}}` / `{{endpoint}}` / `{{attempt}}`
   * / `{{timestamp}}` templates), applied to the JSON payload just
   * before the wire request is built. The transform runs before
   * compression (WR-142/WR-40/WR-75) and E2EE sealing (WR-58) — which produce
   * non-JSON wire bytes — and before signing (WR-26), so
   * `x-relay-signature` always covers the transformed bytes. Opt-in:
   * endpoints without rules keep the exact current behavior. A
   * non-JSON payload (or any runtime transform failure) throws
   * `PayloadTransformError`, classified `"non_retryable"` — the item
   * dead-letters on the first attempt and is audited as
   * `transform_failed`, never silently dropped. Invalid rules throw
   * `RangeError`/`TemplateError` at startup. `undefined` keeps the
   * exact pre-WR-115 wire shape.
   */
  payloadTransformRules?: Record<string, PayloadTransformRules>,
  /**
   * WR-116: per-endpoint AWS SigV4 request signing (opt-in, see
   * `src/sigv4.ts`): `{ "<exact targetUrl>": AwsSigV4EndpointConfig }`
   * — access key id + secret *reference* + region + service. The secret
   * itself is never in this config: it resolves per attempt through
   * `awsSecretResolver` (default: the `secretRef` names an environment
   * variable). Each attempt stamps `Authorization` + `x-amz-date` over
   * the final wire bytes, after transform/compression/E2EE and
   * orthogonal to the WR-26 HMAC `x-relay-signature` (both may be
   * enabled; SigV4 never signs `x-relay-signature`, so the two never
   * order-depend). Entries are validated at startup (`RangeError`);
   * `undefined` keeps the exact pre-WR-116 wire shape.
   */
  awsSigV4?: Record<string, AwsSigV4EndpointConfig>,
  /**
   * WR-116: resolves `AwsSigV4EndpointConfig.secretRef` to key material
   * per delivery attempt (rotation without restart). Defaults to
   * reading `process.env[ref]`; a vault/KMS-backed function may be
   * injected. An unresolvable ref fails the attempt with
   * `SigV4SecretUnavailableError` (classified `non_retryable`).
   */
  awsSecretResolver?: SecretResolver,
  /**
   * WR-117: per-endpoint outbound payload JSON schema validation
   * (opt-in, see `src/outbound-schema.ts`): `{ "<exact targetUrl>":
   * PayloadSchema }`. Validated at startup (`RangeError`); `undefined`
   * keeps the exact pre-WR-117 wire shape.
   */
  outboundSchemas?: Record<string, PayloadSchema>,
  /**
   * WR-129: per-endpoint OAuth2 `client_credentials` token management
   * (opt-in, see `src/oauth-client.ts`): `{ "<exact targetUrl>":
   * OAuth2ClientCredentialsConfig }` — when set, the relay fetches,
   * caches, and refreshes a bearer token for the downstream and stamps
   * `Authorization: Bearer <token>` on every delivery to that endpoint.
   * Validated at startup (`RangeError`); `undefined` keeps the exact
   * pre-WR-129 wire shape. Orthogonal to the WR-26/WR-124/WR-116
   * request signatures: all stamps may coexist on one delivery.
   */
  oauth2?: Record<string, OAuth2ClientCredentialsConfig>,
  /**
   * WR-129: the token cache backing `oauth2` — injectable for tests.
   * When `oauth2` is set but no cache is passed, one is created
   * internally. Ignored when `oauth2` is unset.
   */
  oauth2TokenCache?: OAuth2TokenCache,
  /**
   * WR-142: per-endpoint outbound brotli compression (see `src/brotli.ts`):
   * `{ "<exact targetUrl>": BrotliCompressOptions }`. Validated at
   * startup (`RangeError`); `undefined` keeps the exact pre-WR-142 wire
   * shape.
   */
  compressBrotli?: Record<string, BrotliCompressOptions>,
  /**
   * WR-143: per-endpoint phase timeout budgets (see
   * `src/phase-timeouts.ts` and the `phaseTimeouts` server option):
   * `{ "<exact targetUrl>": PhaseTimeoutBudgets }`. Validated at
   * startup (`RangeError`); `undefined` keeps the exact pre-WR-143
   * behavior.
   */
  phaseTimeouts?: Record<string, PhaseTimeoutBudgets>,
  /**
   * WR-163: per-endpoint private CA bundle (see the `tlsCa` server
   * option): `{ "<exact targetUrl>": "<PEM bundle string>" }`. Validated
   * at startup (`RangeError`); `undefined` keeps the exact pre-WR-163
   * behavior.
   */
  tlsCa?: Record<string, string>,
  /**
   * WR-165: outbound fault-injection drill (see `src/chaos.ts`):
   * `{ rules: { "<exact targetUrl>": { latencyMs?, resetConnection?,
   * statusCode? } } }`. Validated at startup (`RangeError`); `undefined`
   * keeps the exact pre-WR-165 behavior (the sender is returned
   * unwrapped — zero overhead).
   */
  chaos?: ChaosConfig,
  /**
   * WR-165: called once per injected fault. The server audits these as
   * `chaos_injected`; library users get the hook directly.
   */
  onChaosInjected?: (info: ChaosInjectionInfo) => void
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
  // WR-163: fail fast on a bundle Node could never build a chain with —
  // a typo must not silently leave an endpoint unreachable.
  if (tlsCa !== undefined) {
    for (const [endpoint, pem] of Object.entries(tlsCa)) {
      try {
        assertValidCaBundle(pem);
      } catch (err) {
        throw new RangeError(
          `createDefaultSender: invalid TLS CA bundle for ${endpoint}: ${(err as Error).message}`
        );
      }
    }
  }
  // WR-165: fail fast on a misconfigured drill — a typo'd fault must
  // never silently run (or silently not run) mid-delivery.
  const resolvedChaos = resolveChaosConfig(chaos, "createDefaultSender");
  const chaosMetrics = resolvedChaos === undefined ? undefined : new ChaosMetrics();
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
  // WR-129: fail fast on a misconfigured OAuth2 entry — a bad token
  // endpoint or an empty credential must never surface as a mid-delivery
  // 401 storm. The secret is validated, never logged.
  if (oauth2 !== undefined) {
    if (oauth2 === null || typeof oauth2 !== "object" || Array.isArray(oauth2)) {
      throw new RangeError(
        "createDefaultSender: `oauth2` must be a Record<targetUrl, OAuth2ClientCredentialsConfig>"
      );
    }
    for (const [endpoint, cfg] of Object.entries(oauth2)) {
      if (endpoint === "") {
        throw new RangeError(
          "createDefaultSender: `oauth2` keys must be non-empty endpoint strings"
        );
      }
      resolveOAuth2ClientConfig(cfg, `createDefaultSender: \`oauth2["${endpoint}"]\``);
    }
  }
  const oauthTokenCache = oauth2 !== undefined ? (oauth2TokenCache ?? new OAuth2TokenCache()) : undefined;
  // WR-143: fail fast on a misconfigured phase budget — a typo'd phase
  // name or a non-positive budget must not silently leave an endpoint
  // unbudgeted (or budgeted against a phase that can never complete).
  if (phaseTimeouts !== undefined) {
    for (const [endpoint, budgets] of Object.entries(phaseTimeouts)) {
      try {
        assertValidPhaseTimeoutBudgets(budgets);
      } catch (err) {
        throw new RangeError(
          `createDefaultSender: invalid phaseTimeouts for ${endpoint}: ${(err as Error).message}`
        );
      }
    }
  }
  // WR-101: fail fast on a misconfigured OCSP entry — a bad mode or
  // responder URL must not silently leave an endpoint unprotected (or
  // unknowingly fail-closed). When entries exist but no monitor was
  // passed, create an inert one so the check still gates deliveries —
  // the security property must not depend on the caller remembering
  // the monitor argument.
  const resolvedOcsp = new Map<string, ResolvedOcspEndpointOptions>();
  if (tlsOcsp !== undefined) {
    for (const [endpoint, cfg] of Object.entries(tlsOcsp)) {
      try {
        resolvedOcsp.set(endpoint, resolveOcspEndpointOptions(cfg));
      } catch (err) {
        throw new RangeError(
          `createDefaultSender: invalid tlsOcsp for ${endpoint}: ${(err as Error).message}`
        );
      }
    }
    if (ocspMonitor === undefined) ocspMonitor = new OcspMonitor();
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
  // WR-89: per-endpoint client certificate rotation. The map holds sets
  // compiled once by the caller at startup — a set's grace window is
  // pinned to its construction, so rebuilding per request would silently
  // restart it (the WR-67 lesson). An endpoint with both a single
  // identity and a rotation set is a config error: fail fast, never let
  // the two disagree about which identity a handshake presents.
  if (tlsClientCertRotation !== undefined) {
    if (!(tlsClientCertRotation instanceof Map)) {
      throw new RangeError(
        "createDefaultSender: `tlsClientCertRotation` must be a Map<endpoint, RotatingClientCertSet>"
      );
    }
    for (const [endpoint, set] of tlsClientCertRotation) {
      if (typeof endpoint !== "string" || endpoint === "") {
        throw new RangeError(
          "createDefaultSender: `tlsClientCertRotation` keys must be non-empty endpoint strings"
        );
      }
      if (!(set instanceof RotatingClientCertSet)) {
        throw new RangeError(
          `createDefaultSender: invalid tlsClientCertRotation for ${endpoint}: expected a RotatingClientCertSet (compile with new RotatingClientCertSet(cfg))`
        );
      }
      if (tlsClientCerts !== undefined && tlsClientCerts[endpoint] !== undefined) {
        throw new RangeError(
          `createDefaultSender: endpoint ${endpoint} configures both tlsClientCerts and tlsClientCertRotation — use one`
        );
      }
    }
    // WR-73: the relay's own rotation client certificates are checked
    // for expiry at config load, like the WR-36 single identities — but
    // a retired certificate whose grace window has fully elapsed is
    // dead weight: it can never authenticate again, so warning about it
    // would be unactionable noise (the operator removes it once
    // isRotationComplete()). `certificatesForExpiryWatch` orders
    // fallback-first with the primary last, so the monitor's
    // per-endpoint gauge settles on the primary — the identity doing the
    // work — while each expiring certificate still gets its own
    // edge-triggered alert.
    if (certExpiryMonitor !== undefined) {
      for (const [endpoint, set] of tlsClientCertRotation) {
        for (const candidate of set.certificatesForExpiryWatch()) {
          certExpiryMonitor.checkClientCertificate(candidate.cert.cert, endpoint);
        }
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
  // `sender.compressionStats` is available even with no compression
  // endpoint configured; its exposition stays absent until the first
  // byte saved.
  const compressionTracker = new OutboundCompressionTracker();
  // WR-142: RangeError on invalid values, at startup — never mid-delivery.
  if (compressBrotli !== undefined) {
    try {
      assertValidBrotliCompressConfig(compressBrotli);
    } catch (err) {
      throw new RangeError(
        `createDefaultSender: invalid compressBrotli config: ${(err as Error).message}`
      );
    }
  }
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
  // WR-98: RangeError on invalid values, at startup — never mid-delivery.
  let senderTraceContextOpts: ResolvedTraceContextOptions | undefined;
  try {
    senderTraceContextOpts = resolveTraceContextOptions(traceContext);
  } catch (err) {
    throw new RangeError(
      `createDefaultSender: invalid traceContext config: ${(err as Error).message}`
    );
  }
  // WR-115: RangeError/TemplateError on invalid values, at startup —
  // never mid-delivery.
  let payloadTransforms: PayloadTransformer | undefined;
  if (payloadTransformRules !== undefined) {
    try {
      payloadTransforms = new PayloadTransformer(payloadTransformRules);
    } catch (err) {
      // Preserve TemplateError (illegal template) vs RangeError
      // (illegal shape/value) — callers distinguish the two.
      if (err instanceof TemplateError) {
        throw new TemplateError(
          `createDefaultSender: invalid payloadTransforms config: ${err.message}`
        );
      }
      throw new RangeError(
        `createDefaultSender: invalid payloadTransforms config: ${(err as Error).message}`
      );
    }
  }
  // WR-116: RangeError on invalid values, at startup — never
  // mid-delivery. Only the shape is validated here; the secret itself
  // resolves per attempt (rotation without restart), so a missing env
  // var fails attempts loudly instead of refusing to boot.
  const sigv4Configs = new Map<string, AwsSigV4EndpointConfig>();
  if (awsSigV4 !== undefined) {
    for (const [endpoint, cfg] of Object.entries(awsSigV4)) {
      try {
        assertValidAwsSigV4Config(cfg, `awsSigV4[${endpoint}]`);
      } catch (err) {
        throw new RangeError(
          `createDefaultSender: invalid awsSigV4 for ${endpoint}: ${(err as Error).message}`
        );
      }
      sigv4Configs.set(endpoint, cfg);
    }
  }
  // WR-117: RangeError on invalid values, at startup — never
  // mid-delivery. The registry validates the whole record before any
  // state is touched: zero partial application — a bad record refuses
  // to boot rather than running with a half-wired gate.
  let outboundSchemaRegistry: OutboundSchemaRegistry | undefined;
  if (outboundSchemas !== undefined) {
    try {
      outboundSchemaRegistry = new OutboundSchemaRegistry(outboundSchemas);
    } catch (err) {
      throw new RangeError(
        `createDefaultSender: invalid outboundSchemas config: ${(err as Error).message}`
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
  // WR-124: compile the opt-in Ed25519 asymmetric outbound signing key
  // once — RangeError on invalid values at startup, never mid-delivery.
  // `undefined` (feature off) keeps the WR-26-only behavior byte-identical.
  let compiledEd25519: CompiledEd25519OutboundKey | undefined;
  if (outboundSigning?.ed25519 !== undefined) {
    compiledEd25519 = compileEd25519OutboundKey(
      outboundSigning.ed25519,
      "createDefaultSender: `outboundSigning.ed25519`"
    );
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
  // WR-92: compile the DNS cache once — the instance is shared by the
  // pool and the one-off request path, so both observe the same entries
  // and counters.
  let resolvedDnsCache: DnsCache | undefined;
  if (dnsCache !== undefined) {
    try {
      resolvedDnsCache = dnsCache instanceof DnsCache ? dnsCache : new DnsCache(dnsCache);
    } catch (err) {
      throw new RangeError(`createDefaultSender: invalid dnsCache: ${(err as Error).message}`);
    }
  }
  // Bound arrow property — no `this` context needed downstream.
  const dnsLookup = resolvedDnsCache?.lookup;
  // WR-92: the pool's agents resolve through the DNS cache when one is
  // configured — connections are built against the resolved IP while the
  // pool key stays the logical (scheme, host, port).
  const pool =
    keepAlive === false
      ? undefined
      : new OutboundConnectionPool(
          dnsLookup === undefined ? keepAlive : { ...(keepAlive ?? {}), lookup: dnsLookup }
        );
  // WR-89: id of the rotation client certificate most recently used in a
  // handshake attempt, per delivery (queue item id). Written on every
  // rotation handshake attempt — primary or fallback — and taken
  // exactly once by the terminal `delivered` / `dead_letter` audit, so
  // the audit names the identity that actually authenticated the
  // delivery. Keyed per delivery, not per endpoint: concurrent
  // deliveries to the same endpoint must not overwrite each other's
  // attribution, and a delivery whose attempts never reached a
  // handshake (DNS failure, refusal) leaves no entry — honestly absent
  // instead of stale.
  const rotationClientCertUsed = new Map<string, string>();
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
    wireOpts?: { forcePlaintext?: boolean; httpTransport?: boolean; oauthToken?: string }
  ): {
    headers: Record<string, string | string[]>;
    body: Buffer;
    /** WR-75: true when the guarded path compressed this request. */
    guardedCompressed: boolean;
    /** WR-75: payload bytes saved by the guarded compression (0 otherwise). */
    guardedBytesSaved: number;
    /** WR-142: true when the brotli path compressed this request. */
    brotliCompressed: boolean;
    /** WR-142: payload bytes saved by the brotli compression (0 otherwise). */
    brotliBytesSaved: number;
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
    // WR-115: per-endpoint payload transform — runs on the raw inbound
    // payload *before* compression (WR-142/WR-40/WR-75) and E2EE sealing
    // (WR-58), which both produce non-JSON wire bytes, and before
    // signing (WR-26), so `x-relay-signature` covers the transformed
    // bytes — exactly what the downstream receives. Opt-in: endpoints
    // without rules keep the exact current behavior. A transform
    // failure (non-JSON payload, template render failure) throws
    // PayloadTransformError, which the queue classifies
    // "non_retryable": the item dead-letters on the first attempt and
    // is audited as `transform_failed` — never silently dropped.
    // Injected headers are relay-computed, so any inbound header with
    // the same name is stripped first (the WR-26 anti-forgery pattern).
    // The payload the wire body is derived from: the raw inbound bytes,
    // or the WR-115 transformed bytes when the endpoint has rules.
    let sourcePayload = item.payload;
    if (payloadTransforms !== undefined && payloadTransforms.hasRules(item.targetUrl)) {
      const transformed = payloadTransforms.apply(item.targetUrl, sourcePayload, {
        eventId: item.id,
        endpoint: item.targetUrl,
        attempt: (item.attempt ?? 0) + 1,
        timestamp: new Date().toISOString(),
      });
      sourcePayload = transformed.body;
      const injectedHeaders = transformed.headers;
      for (const name of Object.keys(injectedHeaders)) {
        const lower = name.toLowerCase();
        for (const k of Object.keys(headers)) {
          if (k.toLowerCase() === lower) delete headers[k];
        }
      }
      Object.assign(headers, injectedHeaders);
    }
    // WR-117: per-endpoint outbound payload schema validation — runs on
    // the post-transform JSON payload BEFORE compression
    // (WR-142/WR-40/WR-75)
    // and E2EE sealing (WR-58) — which produce non-JSON wire bytes — and
    // before signing (WR-26), so `x-relay-signature` covers exactly the
    // validated bytes the downstream receives. Opt-in: endpoints without
    // rules keep the exact current behavior. A violation throws
    // OutboundSchemaViolationError, classified "non_retryable": the item
    // dead-letters on the first attempt and is audited as
    // `schema_violation` — never silently dropped. A non-JSON payload
    // under a configured rule fails validation (the WR-41 convention); a
    // throwing validator is fail-closed.
    if (outboundSchemaRegistry !== undefined) {
      outboundSchemaRegistry.validatePayload(item.targetUrl, sourcePayload);
    }
    // Propagate the trace ID downstream so the next hop can correlate the
    // delivery with this relay's audit trail (overrides a stale inbound
    // value, which is identical anyway after `resolveTraceId`).
    if (item.traceId) headers[TRACE_ID_HEADER] = item.traceId;
    // WR-107: mesh forwarding — stamp the incremented hop count. The
    // inbound value was consumed into `item.meshHops` at admission (and
    // stripped from the passthrough set), so this is always the relay's
    // own accounting, never a verbatim forward of a peer's header. Only
    // when the mesh sender option is set; otherwise the wire shape is
    // untouched.
    if (mesh !== undefined && item.meshHops !== undefined) {
      headers[RELAY_HOPS_HEADER] = String(nextRelayHops(item.meshHops));
      mesh.metrics.recordForwarded(item.targetUrl);
    }
    // WR-98: W3C trace-context propagation — a forced stamp like
    // `x-trace-id`: a stale inbound `traceparent` in the passthrough set
    // is overridden with a fresh child span id per attempt, and a
    // caller-supplied `tracestate` rides along verbatim. When the option
    // is off this resolves `undefined` and the wire shape is untouched.
    const outboundTrace = resolveOutboundTraceContext(item, senderTraceContextOpts);
    if (outboundTrace !== undefined) {
      const spanId = traceAttemptSpanId(outboundTrace.traceId, (item.attempt ?? 0) + 1);
      headers[TRACEPARENT_HEADER] = formatTraceparent(outboundTrace.traceId, spanId, outboundTrace.sampled);
      if (outboundTrace.traceState !== undefined) headers[TRACESTATE_HEADER] = outboundTrace.traceState;
    }
    // WR-142: the brotli path is decided first — when it configures an
    // endpoint it wins outright over both gzip paths (WR-40 and WR-75),
    // so the compressions never stack or disagree. It engages only on
    // HTTP transports: WebSocket deliveries keep their RFC 7692
    // permessage-deflate story (`src/deflate.ts`) and never pass through
    // here. The 415 fallback resend forces all compressions off.
    let wireBody = sourcePayload;
    let contentEncoding: "gzip" | "br" | undefined;
    let guardedCompressed = false;
    let guardedBytesSaved = 0;
    let brotliCompressed = false;
    let brotliBytesSaved = 0;
    const forcePlaintext = wireOpts?.forcePlaintext === true;
    if (!forcePlaintext) {
      const brotliOpts =
        wireOpts?.httpTransport === false ? undefined : compressBrotli?.[item.targetUrl];
      if (brotliOpts !== undefined) {
        // WR-142: per-endpoint opt-in brotli (fire-and-forget: no
        // whitelist, no fallback). Compression happens before signing so
        // `x-relay-signature` covers the exact wire bytes the downstream
        // receives.
        const decision = maybeCompressBrotliOutbound(sourcePayload, brotliOpts);
        wireBody = decision.body;
        contentEncoding = decision.contentEncoding;
        brotliCompressed = decision.contentEncoding === "br";
        brotliBytesSaved = decision.bytesSaved;
      } else {
        // WR-75: the guarded path is decided before the legacy one — when
        // both records configure an endpoint it wins outright (safer
        // superset: whitelist + 415 fallback), so the two compressions
        // never stack or disagree.
        const guardedOpts =
          wireOpts?.httpTransport === false ? undefined : compressThreshold?.[item.targetUrl];
        if (guardedOpts !== undefined) {
          const decision = guardedCompressOutbound(
            sourcePayload,
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
          const legacy = maybeCompressOutbound(sourcePayload, compressOutbound?.[item.targetUrl]);
          wireBody = legacy.body;
          contentEncoding = legacy.contentEncoding;
        }
      }
    }
    // WR-58: per-endpoint end-to-end encryption. Seals the (possibly
    // compressed) wire body with the downstream's X25519 public key BEFORE
    // signing, so `x-relay-signature` covers the ciphertext wire bytes —
    // exactly what the downstream receives and verifies. The envelope
    // carries the pre-seal content encoding (WR-40/WR-75/WR-142), so the
    // HTTP `content-encoding` header is dropped when a body is sealed:
    // the wire bytes are the JSON envelope, not the compressed stream.
    // Endpoints without a configured key behave exactly as before.
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
    // WR-114: a registry `verifier` record replaces the global
    // `outboundSigning` for this endpoint. Resolved per attempt, like
    // pins and proxy above.
    const endpointSigning = endpointRegistry?.getSigning(item.targetUrl);
    const signing = endpointSigning ?? outboundSigning;
    if (signing !== undefined) {
      // Stamp AFTER the passthrough headers: this guarantees the relay's
      // own signature always wins.
      headers["x-relay-signature"] = signSha256(body, signing.secret);
      if (signing.keyId !== undefined) headers["x-relay-key-id"] = signing.keyId;
      // WR-124: opt-in Ed25519 asymmetric stamp — coexists with the HMAC
      // one above, and the downstream accepts the delivery when either
      // verifies. Only the global `outboundSigning` carries it: a WR-114
      // per-endpoint `verifier` replaces the whole signing identity, so it
      // disables the Ed25519 stamp for that endpoint too.
      if (endpointSigning === undefined && compiledEd25519 !== undefined) {
        headers[ED25519_SIGNATURE_HEADER] = signEd25519Outbound(body, compiledEd25519);
        if (compiledEd25519.keyId !== undefined) headers[ED25519_KEY_ID_HEADER] = compiledEd25519.keyId;
      }
    }
    // WR-116: per-endpoint AWS SigV4 request signing (opt-in). Applied to
    // the final wire body — after transform/compression/E2EE — so the
    // payload hash authenticates exactly the bytes the downstream
    // receives. Orthogonal to the WR-26 HMAC stamp above: both may be
    // enabled, and SigV4 signs only host + x-amz-date (+ configured
    // additional headers), never x-relay-signature, so the two never
    // order-depend on each other. Skipped for the WebSocket path
    // (SigV4 is an HTTP authorization scheme).
    const sigv4Cfg = sigv4Configs.get(item.targetUrl);
    if (sigv4Cfg !== undefined && wireOpts?.httpTransport !== false) {
      // Anti-forgery: inbound Authorization / x-amz-date passthrough
      // values are dropped first — the relay's own stamps always win.
      for (const k of Object.keys(headers)) {
        const lower = k.toLowerCase();
        if (lower === AUTHORIZATION_HEADER || lower === AMZ_DATE_HEADER) delete headers[k];
      }
      const secret = (awsSecretResolver ?? defaultSecretResolver)(sigv4Cfg.secretRef);
      if (typeof secret !== "string" || secret === "") {
        throw new SigV4SecretUnavailableError(item.targetUrl, sigv4Cfg.secretRef);
      }
      const extraSignedHeaders: Record<string, string> = {};
      for (const name of sigv4Cfg.additionalSignedHeaders ?? []) {
        const wireValue = headerValueIgnoreCase(headers, name);
        if (wireValue === undefined) {
          throw new SigV4SigningError(
            item.targetUrl,
            `signed header "${name}" is absent from the wire request`
          );
        }
        extraSignedHeaders[name] = wireValue;
      }
      const signed = signAwsSigV4({
        method: "POST",
        url: item.targetUrl,
        body,
        credentials: { accessKeyId: sigv4Cfg.accessKeyId, secretAccessKey: secret },
        region: sigv4Cfg.region,
        service: sigv4Cfg.service,
        ...(Object.keys(extraSignedHeaders).length > 0 ? { extraSignedHeaders } : {}),
      });
      headers[AMZ_DATE_HEADER] = signed.amzDate;
      headers[AUTHORIZATION_HEADER] = signed.authorization;
    }
    // WR-129: per-endpoint OAuth2 client_credentials bearer token
    // (opt-in). Stamped after signing (WR-26/WR-124/WR-116): the token
    // authenticates the relay to the downstream, orthogonal to the
    // relay's own request signatures — HMAC, Ed25519, SigV4, and the
    // bearer token may all coexist on one delivery. Inbound
    // `authorization` values are stripped first so a sender can never
    // smuggle a forged bearer token downstream (the same anti-forgery
    // rule as the SigV4 Authorization handling above).
    if (wireOpts?.oauthToken !== undefined) {
      for (const k of Object.keys(headers)) {
        if (k.toLowerCase() === AUTHORIZATION_HEADER) delete headers[k];
      }
      headers[AUTHORIZATION_HEADER] = `Bearer ${wireOpts.oauthToken}`;
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
    // WR-58: a sealed body is the JSON envelope, not the compressed stream
    // — the pre-seal encoding travels inside the envelope instead.
    if (contentEncoding !== undefined && e2eeKey === undefined) headers["content-encoding"] = contentEncoding;
    // WR-62: per-endpoint opt-in — advertise compressed responses, so a
    // downstream that compresses saves us (and itself) bytes on the way
    // back. The response is decoded before the WR-37 validator sees it.
    const respCompress = responseCompression?.[item.targetUrl];
    if (respCompress !== undefined) {
      headers["accept-encoding"] = respCompress.acceptEncoding ?? DEFAULT_OUTBOUND_ACCEPT_ENCODING;
    }
    headers["content-length"] = String(body.length);
    return { headers, body, guardedCompressed, guardedBytesSaved, brotliCompressed, brotliBytesSaved };
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
    minTlsVersion: MinTlsVersion | undefined,
    /**
     * WR-89: rotation set for this endpoint. When set, `clientCert`
     * (above) is undefined — mutual exclusion is enforced at sender
     * construction — and the handshake runs the primary → fallback
     * candidate loop below.
     */
    clientCertRotation?: RotatingClientCertSet,
    /**
     * WR-101: revocation checking for this endpoint (`undefined` when
     * the endpoint has no `tlsOcsp` entry): the resolved per-endpoint
     * config plus the monitor owning the verified-socket cache. The
     * pool key already binds this (see the `agentFor` call below), so a
     * connection handshaked without OCSP stapling can never silently
     * serve an OCSP endpoint.
     */
    ocsp?: { cfg: ResolvedOcspEndpointOptions; monitor: OcspMonitor },
    /**
     * WR-129: resolved OAuth2 bearer value for this delivery
     * (`undefined` when the endpoint has no `oauth2` entry). Resolved
     * once per attempt in `defaultSender`, before the wire request is
     * built.
     */
    oauthToken?: string,
    /**
     * WR-143: per-endpoint phase timeout budgets for this delivery
     * (`undefined` when the endpoint has no `phaseTimeouts` entry).
     * Enforced on the HTTP/1.1 path only — see the arming block in
     * `runWithClientCert` below.
     */
    phaseTimeout?: PhaseTimeoutBudgets,
    /**
     * WR-146: hedge-loser cancellation — forwarded to
     * `runWithClientCert`, which destroys the in-flight request when
     * the signal fires. H2/WS paths ignore it (best effort).
     */
    signal?: AbortSignal,
    /**
     * WR-163: per-endpoint private CA bundle for this delivery
     * (`undefined` when the endpoint has no `tlsCa` entry). Bound into
     * the keep-alive pool key and passed as the handshake's `ca`, so
     * every connection serving this endpoint chains to the same trust
     * store.
     */
    caBundle?: string
  ): Promise<DownstreamResponse | void> => {
    // WR-75: the guarded 415→plaintext fallback needs the compression
    // decision outside the attempt promise. The decision is deterministic
    // in (payload, content-type, config), and the Promise executor runs
    // synchronously, so these are set before `attempt(false)` settles.
    let guardedApplied = false;
    let guardedBytesSaved = 0;
    // WR-89: the handshake identity candidates for this delivery — the
    // rotation primary first, then in-grace retired certificates newest
    // first. A non-rotation endpoint has exactly one candidate (which may
    // be "no client certificate"), so the loop below is a no-op for it.
    const handshakeCandidates = (): { cert: TlsClientCert | undefined; kid: string | undefined }[] => {
      if (clientCertRotation === undefined) return [{ cert: clientCert, kid: undefined }];
      const primary = clientCertRotation.primary();
      return [
        { cert: primary.cert, kid: primary.id },
        ...clientCertRotation.fallbacks().map((f) => ({ cert: f.cert, kid: f.id })),
      ];
    };
    // WR-89: the rotation certificate id that completed a handshake for
    // this delivery (set by the candidate loop). The guarded 415→
    // plaintext resend reuses it directly instead of re-running the
    // primary→fallback gauntlet — the downstream already proved it
    // accepts this identity.
    let establishedKid: string | undefined;
    /**
     * One handshake with one client identity: the pre-WR-89 attempt body,
     * parameterized by the certificate to present. `kid` is the
     * rotation certificate id (undefined for non-rotation endpoints);
     * `state.responseReceived` is set the moment response bytes arrive,
     * backing the fallback classifier's zero-payload-byte condition;
     * `state.handshakeCompleted` is set when the client side of the TLS
     * handshake completes, backing the attribution-honesty rule (no
     * certificate was offered when the handshake never got that far).
     */
    const runWithClientCert = (
      certToUse: TlsClientCert | undefined,
      kid: string | undefined,
      state: { responseReceived: boolean; handshakeCompleted: boolean },
      forcePlaintext: boolean,
      /**
       * WR-146: hedge-loser cancellation. When the signal fires, the
       * in-flight request is destroyed with a typed
       * `HedgeCancelledError` (surfaces through `req.on("error",
       * reject)`; the hedged wrapper swallows the loser's rejection).
       * H2/WS paths do not take this parameter — best effort there.
       */
      signal?: AbortSignal
    ): Promise<DownstreamResponse | void> =>
      new Promise((resolve, reject) => {
        // The wire request is built once per attempt: the guarded decision
        // is deterministic, so building it here gives the fallback check
        // the same answer the wire builder used — without compressing
        // twice. The byte savings are noted per guarded-compressed
        // dispatch (the sender committed to sending it compressed).
        const wire = buildWireRequest(item, { forcePlaintext, httpTransport: true, oauthToken });
        if (!forcePlaintext && wire.guardedCompressed) {
          guardedApplied = true;
          guardedBytesSaved = wire.guardedBytesSaved;
          compressionTracker.noteSaved(item.targetUrl, wire.guardedBytesSaved);
        }
        // WR-142: brotli byte savings feed the same tracker (the same
        // `relay_compressed_bytes_saved_total` exposition as the gzip
        // paths); no 415 fallback for brotli — it is fire-and-forget
        // like WR-40.
        if (!forcePlaintext && wire.brotliCompressed) {
          compressionTracker.noteSaved(item.targetUrl, wire.brotliBytesSaved);
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
            // WR-89: the pool key binds the *actually used* certificate
            // identity — the primary's agent and each fallback's agent
            // are distinct, so a connection authenticated as one
            // identity can never serve a delivery using another.
            certToUse !== undefined ? clientCertIdentity(certToUse) : undefined,
            tlsSni,
            minTlsVersion,
            // WR-101: OCSP endpoints get their own agent (stapling
            // requested, resumption off) — a connection handshaked
            // without revocation telemetry can never silently serve
            // them.
            ocsp !== undefined,
            // WR-163: the CA bundle binds the pool key (see agentFor) —
            // a connection handshaked against the private bundle can
            // never serve an endpoint on the public PKI, or vice versa.
            caBundle
          ) ??
          (proxyUrl !== undefined
            ? (oneOffAgent = createProxiedAgent(
                url.protocol === "https:" ? "https" : "http",
                proxyUrl,
                { keepAlive: false, maxSockets: 1, maxFreeSockets: 0 }
              ))
            : undefined);
        // WR-143: phase-timeout response hook — assigned below when the
        // endpoint configures `phaseTimeouts`. `onResponse` invokes it so
        // the firstByte → body budget handoff observes exactly the
        // response the attempt processes.
        let phaseResponseHook:
          | ((res: Parameters<Parameters<typeof httpsRequest>[2]>[0]) => void)
          | undefined;
        const onResponse = (res: Parameters<Parameters<typeof httpsRequest>[2]>[0]): void => {
          // WR-143: first response bytes arrived — hand the body phase
          // its own budget (assigned below when the endpoint configures
          // phaseTimeouts; a no-op otherwise).
          phaseResponseHook?.(res);
          // WR-89: response bytes arrived — the handshake completed and
          // the downstream answered, so this attempt's failure (if any)
          // is never attributable to client-cert rejection.
          state.responseReceived = true;
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
                // WR-95: phase breakdown for this attempt. `firstByteMs` is
                // the WR-54 TTFB — on a fresh connection it overlaps
                // connectMs/tlsMs by construction (documented, not
                // hidden). `bodyMs` runs first-bytes → response end.
                // Phases that could not be measured are absent
                // ("unavailable"), never fabricated.
                const phases: PhaseDurationsMs | undefined =
                  measureLatencyPhases === true
                    ? {
                        ...(connectAtMs !== undefined
                          ? { connectMs: Math.max(0, connectAtMs - requestIssuedMs) }
                          : {}),
                        ...(tlsAtMs !== undefined && connectAtMs !== undefined
                          ? { tlsMs: Math.max(0, tlsAtMs - connectAtMs) }
                          : {}),
                        firstByteMs: timeToFirstByteMs,
                        bodyMs: Math.max(0, Date.now() - (requestIssuedMs + timeToFirstByteMs)),
                      }
                    : undefined;
                resolve({
                  statusCode,
                  body,
                  truncated,
                  timeToFirstByteMs,
                  ...(phases !== undefined ? { phases } : {}),
                  ...(contentEncoding !== undefined ? { contentEncoding } : {}),
                  // WR-89: the rotation certificate id that authenticated
                  // this delivery — copied into `response_summary` and
                  // stamped top-level on the delivery audits. Present
                  // only for rotation endpoints.
                  ...(kid !== undefined ? { clientCertId: kid } : {}),
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
                  // WR-92: one-off (unpooled) requests resolve through the
                  // DNS cache too — same stale-while-revalidate as pooled.
                  ...(dnsLookup !== undefined ? { lookup: dnsLookup } : {}),
                  // WR-163: per-endpoint private CA bundle — Node verifies
                  // the chain against it (`rejectUnauthorized` stays on),
                  // so with pins also configured this is chain-first: a
                  // chain failure kills the handshake before the pin
                  // check below runs. Pins alone keep the pre-WR-163
                  // behavior (`rejectUnauthorized: false`) where the pin
                  // whitelist replaces PKI verification entirely.
                  ...(caBundle !== undefined ? { ca: caBundle } : {}),
                  ...(pins !== undefined && caBundle === undefined
                    ? { rejectUnauthorized: false }
                    : {}),
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
                  // WR-101: ask the server to staple its OCSP response
                  // (RFC 6960 §4) when the endpoint wants the stapled
                  // fast path. Per-request TLS options apply to
                  // connections the pooled agent opens (like the WR-60
                  // SNI options above) and to one-off connections; the
                  // pool key additionally binds OCSP endpoints to their
                  // own agent, so the stapling request is present on
                  // every handshake serving them.
                  ...(ocsp !== undefined && ocsp.cfg.useStapled ? { requestOCSP: true } : {}),
                  // The client certificate rides the TLS handshake (per-request
                  // TLS options apply to connections the pooled agent opens;
                  // the pool key already binds this exact identity, so a
                  // reused socket was authenticated as this same identity).
                  // WR-89: `certToUse` is the rotation candidate for this
                  // handshake — primary or one in-grace fallback.
                  ...(certToUse
                    ? {
                        cert: certToUse.cert,
                        key: certToUse.key,
                        ...(certToUse.passphrase !== undefined
                          ? { passphrase: certToUse.passphrase }
                          : {}),
                      }
                    : {}),
                },
                onResponse
              )
            : httpRequest(
                url,
                {
                  method: "POST",
                  agent: agent ?? false,
                  // WR-92: one-off (unpooled) requests resolve through the
                  // DNS cache too — same stale-while-revalidate as pooled.
                  ...(dnsLookup !== undefined ? { lookup: dnsLookup } : {}),
                },
                onResponse
              );
        req.on("error", reject);

        // WR-146: hedge-loser cancellation — destroy the in-flight
        // request when the hedged sender fires the loser's controller.
        // The typed error surfaces through `req.on("error", reject)`
        // above; the hedged wrapper swallows the loser's rejection so
        // the queue never classifies it as a delivery failure. The
        // listener is removed on request close so settled attempts
        // leave no dangling subscription.
        if (signal !== undefined) {
          if (signal.aborted) {
            req.destroy(new HedgeCancelledError(item.targetUrl));
          } else {
            const onAbort = () => req.destroy(new HedgeCancelledError(item.targetUrl));
            signal.addEventListener("abort", onAbort, { once: true });
            req.on("close", () => signal.removeEventListener("abort", onAbort));
          }
        }

        // WR-99: enforce the propagated deadline budget on this attempt.
        // The HTTP/1.1 path has no other per-attempt timeout, so without
        // this a hung downstream would hold a pool slot past the
        // end-to-end SLO. Destroying the request surfaces the typed
        // error through the `req.on("error", reject)` above; the timer
        // is unref'd so it never pins process exit, and cleared on
        // request close so a settled attempt leaves no timer behind.
        const attemptBudgetMs = readDeadlineBudgetMs(item);
        if (attemptBudgetMs !== undefined) {
          const budgetTimer = setTimeout(() => {
            req.destroy(new DeadlineBudgetTimeoutError(item.targetUrl, attemptBudgetMs));
          }, attemptBudgetMs);
          budgetTimer.unref?.();
          req.on("close", () => clearTimeout(budgetTimer));
        }

        // WR-166: enforce the stamped adaptive outbound timeout. The
        // default sender does NOT reuse the WR-99 deadline budget: a
        // deadline-budget expiry is terminal (dead letter, no backoff),
        // while an adaptive timeout is a normal retryable timeout (it
        // feeds the breaker and the retry budget like any other timeout).
        // `AdaptiveTimeoutError` carries no statusCode so the failure
        // classifier treats it as retryable.
        const adaptiveTimeoutMs = readAdaptiveTimeoutMs(item);
        if (adaptiveTimeoutMs !== undefined) {
          const adaptiveTimer = setTimeout(() => {
            req.destroy(new AdaptiveTimeoutError(item.targetUrl, adaptiveTimeoutMs));
          }, adaptiveTimeoutMs);
          adaptiveTimer.unref?.();
          req.on("close", () => clearTimeout(adaptiveTimer));
        }

        // WR-143: per-endpoint phase timeout budgets (opt-in via the
        // `phaseTimeouts` record). One unref'd timer per configured
        // phase, armed per delivery attempt: when a phase's budget
        // expires before the sender observes that phase's completion,
        // the request is destroyed with a typed `PhaseTimeoutError`
        // (classified "retryable" by the default fallthrough — the
        // normal backoff / dead-letter path). A `connect` or `tls`
        // budget firing destroys the request before a single payload
        // byte is written (the pinning.ts/ocsp.ts zero-leak standard —
        // the plain-path write is deferred below when a pre-write
        // budget is configured). Timers are cleared when their phase
        // completes or the request settles, and never pin process
        // exit. Endpoints without a `phaseTimeouts` entry skip this
        // block entirely: the current single attempt-total-timeout
        // behavior is untouched.
        //
        // Budget origins mirror the WR-95 phase definitions, with one
        // deliberate difference: `connect` arms at socket assignment
        // (not request issue) so a reused pooled socket can never
        // spuriously trip it — `connect`/`tls` budgets fire against
        // measured phases only. A reused pooled socket or a proxied
        // tunnel reports `connect`/`tls` as unavailable (WR-95), so
        // their timers are never armed there; `tls` is meaningless on
        // plain http and never armed there either. `firstByte` runs
        // request-issued → first response bytes (overlapping
        // connect/tls on a fresh connection by construction —
        // documented, not hidden, same convention as WR-95's
        // overlapping firstByteMs); `body` runs first-bytes →
        // response end on 2xx responses only — a non-2xx attempt is
        // already doomed on its status code, so budgeting its body
        // would only convert a poison verdict into a retryable
        // timeout.
        let phaseConnectTimer: NodeJS.Timeout | undefined;
        let phaseTlsTimer: NodeJS.Timeout | undefined;
        let phaseFirstByteTimer: NodeJS.Timeout | undefined;
        let phaseBodyTimer: NodeJS.Timeout | undefined;
        const clearPhaseTimer = (phase: PhaseTimeoutPhase): void => {
          if (phase === "connect" && phaseConnectTimer !== undefined) {
            clearTimeout(phaseConnectTimer);
            phaseConnectTimer = undefined;
          } else if (phase === "tls" && phaseTlsTimer !== undefined) {
            clearTimeout(phaseTlsTimer);
            phaseTlsTimer = undefined;
          } else if (phase === "firstByte" && phaseFirstByteTimer !== undefined) {
            clearTimeout(phaseFirstByteTimer);
            phaseFirstByteTimer = undefined;
          } else if (phase === "body" && phaseBodyTimer !== undefined) {
            clearTimeout(phaseBodyTimer);
            phaseBodyTimer = undefined;
          }
        };
        if (phaseTimeout !== undefined) {
          const armPhaseTimer = (phase: PhaseTimeoutPhase, timeoutMs: number | undefined): void => {
            if (timeoutMs === undefined) return;
            const timer = setTimeout(() => {
              // The phase may have completed between arm and fire with
              // the completion hook not yet run — only fire while still
              // armed.
              const armed =
                phase === "connect"
                  ? phaseConnectTimer
                  : phase === "tls"
                    ? phaseTlsTimer
                    : phase === "firstByte"
                      ? phaseFirstByteTimer
                      : phaseBodyTimer;
              if (armed !== timer) return;
              req.destroy(new PhaseTimeoutError(item.targetUrl, phase, timeoutMs));
            }, timeoutMs);
            timer.unref?.();
            if (phase === "connect") phaseConnectTimer = timer;
            else if (phase === "tls") phaseTlsTimer = timer;
            else if (phase === "firstByte") phaseFirstByteTimer = timer;
            else phaseBodyTimer = timer;
          };
          // firstByte is measurable on every transport — arm at request
          // issue. connect/tls arm below, on socket assignment, and
          // only for fresh direct sockets (see above).
          armPhaseTimer("firstByte", phaseTimeout.firstByteMs);
          req.on("socket", (socket) => {
            if (!socket.connecting || proxyUrl !== undefined) return;
            socket.once("connect", () => {
              clearPhaseTimer("connect");
              // tls is budgeted TCP-established → handshake complete.
              if (url.protocol === "https:") armPhaseTimer("tls", phaseTimeout.tlsMs);
            });
            armPhaseTimer("connect", phaseTimeout.connectMs);
          });
          phaseResponseHook = (res) => {
            // firstByte completed: the downstream's first response bytes
            // arrived — hand the body phase its own budget.
            clearPhaseTimer("firstByte");
            if (
              phaseTimeout.bodyMs !== undefined &&
              res.statusCode !== undefined &&
              res.statusCode >= 200 &&
              res.statusCode < 300
            ) {
              armPhaseTimer("body", phaseTimeout.bodyMs);
              res.once("end", () => clearPhaseTimer("body"));
            }
          };
          req.on("close", () => {
            clearPhaseTimer("connect");
            clearPhaseTimer("tls");
            clearPhaseTimer("firstByte");
            clearPhaseTimer("body");
          });
        }

        // WR-95: per-phase delivery timing (opt-in via
        // `measureLatencyPhases`, which `createRelayServer` enables exactly
        // when `retry.latencyPhases` is configured). Only a fresh direct
        // socket can report connect/TLS: a reused pooled socket was
        // connected long ago, and a proxied tunnel's TCP/TLS belong to the
        // proxy leg — both report those phases as unavailable, never
        // fabricated. DNS is never attributable per-request (resolution
        // happens inside the connection machinery, often served from the
        // WR-92 cache), so `dnsMs` is unset by design.
        let connectAtMs: number | undefined;
        let tlsAtMs: number | undefined;
        if (measureLatencyPhases === true && proxyUrl === undefined) {
          req.on("socket", (socket) => {
            if (!socket.connecting) return;
            socket.once("connect", () => {
              connectAtMs = Date.now();
            });
            if (url.protocol === "https:") {
              socket.once("secureConnect", () => {
                tlsAtMs = Date.now();
              });
            }
          });
        }

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
         * WR-101: gate the payload on the endpoint's OCSP revocation
         * check. The check may need an async responder round-trip, so —
         * unlike the pin/floor checks — the payload waits for it instead
         * of firing inline on `secureConnect`. The revoked / fail-closed
         * paths destroy the request before a single payload byte is
         * written (the pinning.ts precedent: the revoked peer never
         * observes the body); the attempt then follows the normal retry
         * / dead-letter path. A no-op `writePayload()` when the endpoint
         * has no OCSP entry.
         */
        const gatePayloadOnOcsp = (tlsSocket: TLSSocket): void => {
          if (ocsp === undefined) {
            writePayload();
            return;
          }
          // A pooled socket already verified for this endpoint skips the
          // re-check: revocation is a property of the certificate
          // presented at session establishment, and the peer cannot
          // change underneath a live TLS session.
          if (ocsp.monitor.socketVerified(tlsSocket, item.targetUrl)) {
            writePayload();
            return;
          }
          void (async () => {
            try {
              await ocsp.monitor.checkPeer(tlsSocket, item.targetUrl, ocsp.cfg);
              writePayload();
            } catch (err) {
              req.destroy(err as Error);
            }
          })();
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
          // WR-101: OCSP gates the payload on the unpinned path too. The
          // check may need an async responder round-trip, so writePayload
          // waits for the check instead of firing immediately — the
          // revoked / fail-closed paths destroy the request first.
          if (ocsp !== undefined && url.protocol === "https:") {
            req.on("socket", (socket) => {
              const tlsSocket = socket as TLSSocket;
              const already = tlsSocket.getPeerCertificate() as { raw?: unknown };
              if (already && already.raw) {
                gatePayloadOnOcsp(tlsSocket);
              } else {
                tlsSocket.once("secureConnect", () => gatePayloadOnOcsp(tlsSocket));
              }
            });
            return;
          }
          // WR-143: when a pre-write phase budget is configured, the
          // payload write waits for the budgeted phase to complete — a
          // connect/tls budget firing destroys the request before a
          // single payload byte is written (the pinning.ts/ocsp.ts
          // zero-leak standard). The pinned and OCSP paths already gate
          // their writes on the handshake, so only this plain path
          // needs the deferral; proxied endpoints keep their existing
          // write point (the tunnel's TLS belongs to the proxy leg, and
          // connect/tls budgets never arm there).
          const deferWriteForPhaseBudget =
            phaseTimeout !== undefined &&
            proxyUrl === undefined &&
            (phaseTimeout.connectMs !== undefined || phaseTimeout.tlsMs !== undefined);
          if (deferWriteForPhaseBudget) {
            let phaseWriteDone = false;
            const writeOnBudgetedPhase = (): void => {
              if (phaseWriteDone) return;
              phaseWriteDone = true;
              writePayload();
            };
            // A tls budget holds the write until the handshake
            // completes; otherwise the TCP connect is the last
            // pre-write phase to wait for.
            const waitForTls =
              phaseTimeout !== undefined &&
              phaseTimeout.tlsMs !== undefined &&
              url.protocol === "https:";
            req.on("socket", (socket) => {
              if (!socket.connecting) {
                // Reused pooled socket: the budgeted phases are
                // unavailable (WR-95), so nothing is left to wait for.
                writeOnBudgetedPhase();
                return;
              }
              if (waitForTls) {
                const tlsSocket = socket as TLSSocket;
                const already = (tlsSocket.getPeerCertificate() as { raw?: unknown }).raw;
                if (already !== undefined) {
                  writeOnBudgetedPhase();
                } else {
                  socket.once("secureConnect", writeOnBudgetedPhase);
                }
              } else {
                socket.once("connect", writeOnBudgetedPhase);
              }
            });
          } else {
            writePayload();
          }
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
            // WR-101: OCSP after pinning — pinning anchors identity
            // (stops a compromised CA / MITM), OCSP checks revocation
            // freshness. The payload waits for the (possibly async)
            // check; the revoked / fail-closed paths destroy the request
            // before a single payload byte is written.
            gatePayloadOnOcsp(tlsSocket);
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
              // WR-101: a reused pooled connection proved its identity at
              // handshake time, but revocation is re-checked per endpoint
              // policy — the monitor skips sockets it already verified
              // for this endpoint (session-establishment semantics).
              gatePayloadOnOcsp(tlsSocket);
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
            // WR-89: the client side of the TLS handshake completed —
            // this identity's certificate was offered on the wire
            // (whenever the server requested one), so the rotation
            // attribution recorded for this delivery is honest from
            // here on. Also covers reused pooled sockets, whose
            // handshake completed when the connection was first made.
            state.handshakeCompleted = true;
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
    /**
     * WR-89: run one delivery attempt across the rotation candidates —
     * primary first, then in-grace retired certificates newest first.
     * A candidate is only tried after the previous one failed in a way
     * attributable to client-cert rejection (see
     * `isClientCertRejectedError`); any other failure — an HTTP
     * response, a pin or TLS-floor rejection, DNS, a timeout — ends the
     * loop immediately, because those are not about the client identity.
     * The used certificate id is recorded per delivery for audit
     * stamping; when `establishedKid` is set (the guarded 415 resend
     * below), that identity leads — the downstream already proved it
     * accepts it.
     */
    const attempt = (forcePlaintext: boolean): Promise<DownstreamResponse | void> => {
      const candidates = ((): { cert: TlsClientCert | undefined; kid: string | undefined }[] => {
        const all = handshakeCandidates();
        if (establishedKid === undefined) return all;
        const idx = all.findIndex((c) => c.kid === establishedKid);
        return idx <= 0 ? all : [all[idx], ...all.slice(0, idx), ...all.slice(idx + 1)];
      })();
      const runCandidates = async (): Promise<DownstreamResponse | void> => {
        let lastErr: unknown;
        // WR-89: whether any candidate completed the client side of the
        // TLS handshake. The attribution map is written optimistically
        // before each attempt; when the loop ends without any handshake
        // having completed, no certificate was actually offered, so the
        // entry is dropped instead of stamping a stale id on the audit.
        let handshakeCompletedAny = false;
        for (const candidate of candidates) {
          if (candidate.kid !== undefined) {
            rotationClientCertUsed.set(item.id, candidate.kid);
          }
          const state = { responseReceived: false, handshakeCompleted: false };
          try {
            const response = await runWithClientCert(candidate.cert, candidate.kid, state, forcePlaintext, signal);
            if (candidate.kid !== undefined) establishedKid = candidate.kid;
            return response;
          } catch (err) {
            lastErr = err;
            if (state.handshakeCompleted) handshakeCompletedAny = true;
            if (
              candidate.kid === undefined ||
              state.responseReceived ||
              !isClientCertRejectedError(err)
            ) {
              if (!handshakeCompletedAny) {
                rotationClientCertUsed.delete(item.id);
              }
              throw err;
            }
            // Client-cert rejection: the next candidate retries the same
            // handshake with a fresh socket on its own identity-keyed
            // agent. Zero payload bytes were sent (no response was ever
            // received), so the retry duplicates nothing.
          }
        }
        throw lastErr;
      };
      return runCandidates();
    };
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
    minTlsVersion: MinTlsVersion | undefined,
    /** WR-89: rotation set for this endpoint (mutually exclusive with `clientCert`). */
    clientCertRotation?: RotatingClientCertSet,
    /**
     * WR-129: resolved OAuth2 bearer value for this delivery
     * (`undefined` when the endpoint has no `oauth2` entry).
     */
    oauthToken?: string
  ): Promise<DownstreamResponse> => {
    // WR-75: same guarded 415→plaintext fallback as the HTTP/1.1 path —
    // the resend rides a fresh H2 stream inside the same delivery
    // attempt, so the queue still sees a single attempt.
    let guardedApplied = false;
    let guardedBytesSaved = 0;
    const attempt = async (forcePlaintext: boolean): Promise<DownstreamResponse> => {
        // WR-89: the rotation candidates — the session pool keys sessions
        // per certificate identity, so each candidate gets its own
        // session and a rejected primary never poisons a fallback's
        // session. A rejected handshake surfaces as
        // Http2UnavailableError wrapping the TLS failure; anything that
        // is not a client-cert rejection propagates to the HTTP/1.1
        // fallback below, exactly as before.
        const candidates: { cert: TlsClientCert | undefined; kid: string | undefined }[] =
          clientCertRotation !== undefined
            ? (() => {
                const primary = clientCertRotation.primary();
                return [
                  { cert: primary.cert, kid: primary.id },
                  ...clientCertRotation.fallbacks().map((f) => ({ cert: f.cert, kid: f.id })),
                ];
              })()
            : [{ cert: clientCert, kid: undefined }];
        let session: ClientHttp2Session | undefined;
        let usedKid: string | undefined;
        let lastErr: unknown;
        for (const candidate of candidates) {
          try {
            session = await h2pool!.sessionFor(url, pins, candidate.cert, tlsSni, minTlsVersion);
            usedKid = candidate.kid;
            break;
          } catch (err) {
            lastErr = err;
            // No response could have been received yet — no stream
            // exists — so the classifier's no-response condition holds
            // trivially here.
            if (candidate.kid === undefined || !isClientCertRejectedError(err)) throw err;
          }
        }
        if (session === undefined) throw lastErr;
        if (usedKid !== undefined) rotationClientCertUsed.set(item.id, usedKid);
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
          const wire = buildWireRequest(item, { forcePlaintext, httpTransport: true, oauthToken });
          if (!forcePlaintext && wire.guardedCompressed) {
            guardedApplied = true;
            guardedBytesSaved = wire.guardedBytesSaved;
            compressionTracker.noteSaved(item.targetUrl, wire.guardedBytesSaved);
          }
          // WR-142: brotli byte savings feed the same tracker (the same
          // `relay_compressed_bytes_saved_total` exposition as the gzip
          // paths).
          if (!forcePlaintext && wire.brotliCompressed) {
            compressionTracker.noteSaved(item.targetUrl, wire.brotliBytesSaved);
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
            // WR-89: the rotation certificate id that authenticated this
            // delivery — present only for rotation endpoints.
            ...(usedKid !== undefined ? { clientCertId: usedKid } : {}),
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

  const innerSender = function defaultSender(item: RetryItem, callOpts?: SenderCallOptions): Promise<DownstreamResponse | void> {
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
      url.protocol === "https:" || url.protocol === "wss:"
        ? // WR-114: the registry's per-endpoint pins win over the static
          // `tlsPins` record; an endpoint without a registry entry (or
          // without pins in its record) falls back to the static config.
          (endpointRegistry?.getTlsPins(item.targetUrl) ?? tlsPins?.[item.targetUrl])
        : undefined;
    // WR-163: per-endpoint private CA bundle (exact targetUrl match,
    // `https:` only — the wss: path keeps its pinning-only handshake and
    // the opt-in HTTP/2 pool does not take the bundle). `undefined` for
    // endpoints without an entry keeps the exact pre-WR-163 behavior.
    const caBundle = url.protocol === "https:" ? tlsCa?.[item.targetUrl] : undefined;
    // mTLS client identity for this endpoint (exact targetUrl match):
    // the certificate is presented during the TLS handshake so the
    // downstream can verify the relay. Off by default — endpoints without
    // an entry send no client certificate, exactly as before.
    const clientCert = url.protocol === "https:" ? tlsClientCerts?.[item.targetUrl] : undefined;
    // WR-89: rotation set for this endpoint (exact targetUrl match).
    // Mutual exclusion with `tlsClientCerts` is enforced at sender
    // construction, so at most one of the two is ever set here.
    const clientCertRotation =
      url.protocol === "https:" ? tlsClientCertRotation?.get(item.targetUrl) : undefined;
    // WR-112: mesh-link mTLS (opt-in) outbound pre-flight. A mesh hop is
    // an authenticated relay-to-relay link: when enabled it is only
    // forwarded over `https:` and only with a client identity configured
    // for the peer endpoint (WR-36 `tlsClientCerts`, exact targetUrl
    // match — a rotation set counts too). Refusing locally, instead of
    // sending a hop the peer would 401, keeps the misconfiguration loud:
    // the rejection flows through the normal delivery failure path
    // (retry budget, then dead-letter with this message as `lastError`),
    // never a silent unauthenticated send.
    if (
      mesh?.mtls === true &&
      item.meshHops !== undefined &&
      (url.protocol !== "https:" || (clientCert === undefined && clientCertRotation === undefined))
    ) {
      return Promise.reject(
        new Error(
          `mesh.mtls: refusing unauthenticated mesh forward to ${item.targetUrl} — ` +
            `mesh peers need https: with a TLS client certificate (tlsClientCerts)`
        )
      );
    }
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
    // WR-101: per-endpoint OCSP revocation checking (exact targetUrl
    // match). `undefined` for endpoints without an entry — and for
    // non-`https:` targets — keeps the exact current behavior. The
    // monitor is always present when entries exist (createDefaultSender
    // creates an inert one when the caller passes none), so the pair is
    // complete here.
    const ocspForEndpoint =
      url.protocol === "https:" ? resolvedOcsp.get(item.targetUrl) : undefined;
    const ocsp =
      ocspForEndpoint !== undefined && ocspMonitor !== undefined
        ? { cfg: ocspForEndpoint, monitor: ocspMonitor }
        : undefined;
    // WR-143: per-endpoint phase timeout budgets (exact targetUrl
    // match, http/https only — the WebSocket pool owns its own
    // handshake). `undefined` for endpoints without an entry keeps the
    // exact current behavior.
    const phaseTimeout =
      url.protocol === "http:" || url.protocol === "https:"
        ? resolvePhaseTimeouts(item.targetUrl, phaseTimeouts)
        : undefined;
    // Outbound proxy for this endpoint: the WR-114 registry override
    // first, then explicit per-endpoint config, then the environment
    // (read per delivery, so proxy rotation needs no restart;
    // `NO_PROXY` bypasses the env fallback only — an explicit entry
    // always wins). An invalid *environment* value throws here and
    // fails the delivery through the normal retry path; explicit values
    // were validated at startup (static) or at registry-write time.
    const registryProxy = endpointRegistry?.getProxy(item.targetUrl);
    const proxyUrl = registryProxy ?? resolveProxyUrl(item.targetUrl, proxies);
    if (proxyUrl === undefined && registryProxy === undefined && proxies?.[item.targetUrl] !== undefined) {
      return Promise.reject(
        new Error(`outbound proxy: proxy configured for non-HTTP(S) target ${item.targetUrl}`)
      );
    }
    if (registryProxy !== undefined && url.protocol !== "http:" && url.protocol !== "https:") {
      return Promise.reject(
        new Error(`outbound proxy: proxy configured for non-HTTP(S) target ${item.targetUrl}`)
      );
    }
    // WR-129: per-endpoint OAuth2 client_credentials (exact targetUrl
    // match, http/https only — the WS upgrade path keeps its
    // `x-relay-*` header contract). `undefined` for endpoints without
    // an entry keeps the exact pre-WR-129 wire shape.
    const oauthCfg =
      url.protocol === "http:" || url.protocol === "https:"
        ? oauth2?.[item.targetUrl]
        : undefined;
    // WR-99: the physical attempt dispatch, wrapped below with the
    // deadline-budget race when the queue stamped a remaining budget.
    const dispatch = (oauthToken: string | undefined): Promise<DownstreamResponse | void> => {
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
      // WR-101: an OCSP-configured endpoint never rides H2 — the H2
      // session pool owns its own handshake and has no revocation gate,
      // so H2 would silently skip the check. HTTP/1.1 instead, loudly.
      // WR-143: a phase-timeout endpoint is likewise kept off H2 — a
      // multiplexed session has no per-request connect/tls/firstByte
      // phases to budget, so H2 would silently skip the budgets.
      // WR-163: a CA-bundle endpoint is likewise kept off H2 — the H2
      // session pool owns its own handshake and takes no `ca`, so H2
      // would fail the chain it was configured to trust. HTTP/1.1
      // instead, where the bundle rides the handshake.
      if (h2pool !== undefined && proxyUrl === undefined && ocsp === undefined && phaseTimeout === undefined && caBundle === undefined && h2pool.eligibleFor(url)) {
        return deliverViaHttp2(item, url, pins, clientCert, tlsSni, minTlsVersion, clientCertRotation, oauthToken).catch((err) => {
          if (err instanceof Http2UnavailableError) {
            h2pool!.noteFallback();
            return deliverViaHttp1(item, url, pins, clientCert, proxyUrl, tlsSni, minTlsVersion, clientCertRotation, ocsp, oauthToken, phaseTimeout, callOpts?.signal, caBundle);
          }
          throw err;
        });
      }
      return deliverViaHttp1(item, url, pins, clientCert, proxyUrl, tlsSni, minTlsVersion, clientCertRotation, ocsp, oauthToken, phaseTimeout, callOpts?.signal, caBundle);
    };
    // WR-129: resolve the bearer value once per delivery attempt
    // (cached); a 401 forces exactly one refresh + redelivery inside the
    // same attempt — the queue still sees a single attempt, so the
    // refresh consumes no retry budget. A second 401 follows the normal
    // classify → retry / dead-letter path. A token-endpoint failure
    // (OAuth2TokenError) is not a 401 and fails the delivery directly.
    const attemptWithOAuth = (forceRefresh: boolean): Promise<DownstreamResponse | void> => {
      if (oauthCfg === undefined || oauthTokenCache === undefined) return dispatch(undefined);
      const tokenP = forceRefresh
        ? oauthTokenCache.refreshFor(oauthCfg)
        : oauthTokenCache.tokenFor(oauthCfg);
      return tokenP.then((token) => dispatch(token));
    };
    const dispatchWithOAuth = (): Promise<DownstreamResponse | void> =>
      attemptWithOAuth(false).catch((err) => {
        if (
          oauthCfg !== undefined &&
          err instanceof HttpDeliveryError &&
          err.statusCode === 401
        ) {
          return attemptWithOAuth(true);
        }
        throw err;
      });
    // WR-99: enforce the propagated deadline budget on the physical
    // attempt. The race bounds every transport (H1/H2/WS) at the
    // remaining budget — the HTTP/1.1 path additionally destroys its
    // in-flight request on budget fire (it has no other per-attempt
    // timeout; see above), while H2/WS rely on this race plus their own
    // timeouts. The rejection is typed so the queue routes it to the
    // deadline-expiry path, not the retry path. No budget stamped —
    // byte-identical behavior to before.
    //
    // WR-166: the uniform race is factored into `raceCap` so the stamped
    // adaptive outbound timeout applies here too — via
    // `AdaptiveTimeoutError` (no `statusCode`) so the queue routes it to
    // the normal retryable path, unlike the deadline-budget expiry.
    const raceCap = (
      raced: Promise<DownstreamResponse | void>,
      capMs: number,
      makeError: (ms: number) => Error
    ): Promise<DownstreamResponse | void> =>
      new Promise<DownstreamResponse | void>((resolve, reject) => {
        let settled = false;
        const timer = setTimeout(() => {
          if (settled) return;
          settled = true;
          reject(makeError(capMs));
        }, capMs);
        // An SLO timer must never pin process exit.
        timer.unref?.();
        raced.then(
          (res) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            resolve(res);
          },
          (err) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            reject(err);
          }
        );
      });
    const budgetMs = readDeadlineBudgetMs(item);
    let raced = dispatchWithOAuth();
    if (budgetMs !== undefined) {
      raced = raceCap(raced, budgetMs, (ms) => new DeadlineBudgetTimeoutError(item.targetUrl, ms));
    }
    // WR-166: enforce the stamped adaptive outbound timeout on every
    // transport via the race — `AdaptiveTimeoutError` carries no
    // `statusCode`, so the queue treats it as a regular retryable
    // timeout (backoff, breaker, dead letter), not a deadline expiry.
    const adaptiveMs = readAdaptiveTimeoutMs(item);
    if (adaptiveMs !== undefined) {
      raced = raceCap(raced, adaptiveMs, (ms) => new AdaptiveTimeoutError(item.targetUrl, ms));
    }
    return raced;
  } as PooledSender;
  // WR-165: wrap the built sender with the chaos drill when configured —
  // the wrapper delegates every attempt to the real sender and injects
  // faults only for endpoints with a rule. PooledSender props are
  // assigned to the wrapper below, so operators see one sender.
  const sender =
    resolvedChaos === undefined
      ? innerSender
      : (wrapSenderWithChaos(innerSender, resolvedChaos, chaosMetrics!, {
          onInjected: onChaosInjected,
        }) as PooledSender);
  sender.pool = pool;
  sender.http2Pool = h2pool;
  sender.wsPool = wsPool;
  sender.compressionStats = compressionTracker;
  // WR-117: outbound schema counters (undefined when the feature is off)
  // — operators read them via `sender.outboundSchemaMetrics.getStats()`;
  // they render into GET /metrics as `relay_outbound_schema_total`.
  sender.outboundSchemaMetrics = outboundSchemaRegistry?.metrics;
  // WR-165: chaos-drill injection counters (undefined when the feature
  // is off) — operators read them via `sender.chaosMetrics.getStats()`;
  // they render into GET /metrics as `relay_chaos_injected_total`.
  sender.chaosMetrics = chaosMetrics;
  // WR-92: the shared DNS cache instance (undefined when the feature is
  // off) — operators read counters via `sender.dnsCache.getStats()`.
  sender.dnsCache = resolvedDnsCache;
  // WR-89: take-and-clear the rotation certificate id used by a
  // delivery's latest handshake attempt, for audit stamping (see the
  // `rotationClientCertUsed` map above).
  sender.takeRotationClientCertId = (deliveryId: string): string | undefined => {
    const kid = rotationClientCertUsed.get(deliveryId);
    rotationClientCertUsed.delete(deliveryId);
    return kid;
  };
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

/**
 * WR-135: operator-facing message for a denied replay approval token.
 * The token itself is never echoed — it is bearer material.
 */
function approvalDenyMessage(reason: ReplayApprovalDenyReason): string {
  switch (reason) {
    case "missing":
      return "replay approval token required";
    case "expired":
      return "replay approval token expired";
    case "reused":
      return "replay approval token already used";
    case "scope_mismatch":
      return "replay approval token scope mismatch";
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
  /**
   * WR-124: opt-in Ed25519 asymmetric outbound signing. When set, every
   * delivery made by the default sender additionally carries
   * `x-relay-ed25519-signature: ed25519=<hex>` — the Ed25519 signature of
   * the forwarded body under this private key — plus
   * `x-relay-ed25519-key-id` when `keyId` is given. Downstreams that
   * cannot hold a shared secret (e.g. a bank's verification service)
   * verify with the public key alone (`Ed25519Verifier` /
   * `RotatingEd25519Verifier` from `src/outbound-ed25519.ts`); the HMAC
   * stamp is kept alongside, and the downstream accepts the delivery
   * when either signature verifies. Unset by default: existing behavior
   * is byte-identical. Invalid values throw `RangeError` at startup.
   */
  ed25519?: Ed25519OutboundKeyConfig;
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
  /**
   * WR-103: hot-swap the inbound mTLS configuration at runtime
   * (CA chain, server key/cert, fingerprint whitelist, `requireCert` /
   * `operatorMtls` policy). Validation runs against the merged config
   * before anything applies — an illegal patch throws `RangeError` and
   * the live config is untouched. TLS material is pushed into the live
   * listeners via `setSecureContext()`, so it takes effect on *new* TLS
   * handshakes; already-established connections keep the previous
   * secure context until they reconnect. Enabling or disabling inbound
   * mTLS is NOT hot-swappable and throws `Error`: the listener is
   * created as HTTPS or plain HTTP at startup and a bound socket cannot
   * change modes at runtime. Only set when `inboundMtls` was configured
   * at startup.
   */
  updateInboundMtlsConfig?: (patch: InboundMtlsConfigPatch) => ConfigChange[];
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
    pathname === "/quorum" ||
    pathname === "/quorum/stats" ||
    pathname === "/usage" ||
    pathname === "/health/summary" ||
    pathname === "/events" ||
    pathname === "/events/archive" ||
    pathname === "/metrics" ||
    pathname === "/openapi.json" ||
    pathname === "/config/endpoint" ||
    pathname === "/config/snapshot" ||
    // WR-144: per-version sunset inspection / hot updates.
    pathname === "/config/version-sunset" ||
    pathname === "/routing/rules" ||
    pathname === "/endpoints" ||
    pathname.startsWith("/endpoints/") ||
    pathname === "/scheduled" ||
    pathname.startsWith("/scheduled/") ||
    pathname.startsWith("/deliveries/") ||
    // WR-127: one-shot per-endpoint maintenance windows.
    pathname === "/maintenance/windows"
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
  // WR-159: CORS policy for the operator plane — validated once at
  // startup (`undefined` = disabled, zero behavior change).
  let corsPolicy: ResolvedCorsPolicy | undefined;
  try {
    corsPolicy = assertValidCorsPolicy(opts.cors);
  } catch (err) {
    throw new RangeError(`createRelayServer: invalid cors config: ${(err as Error).message}`);
  }
  // WR-160: inbound HTTP server timeout hardening — validated once at
  // startup (`undefined` = Node defaults, zero behavior change).
  let hardening: ResolvedHttpHardening | undefined;
  try {
    hardening = assertValidHttpHardening(opts.httpHardening);
  } catch (err) {
    throw new RangeError(`createRelayServer: invalid httpHardening config: ${(err as Error).message}`);
  }
  // WR-130: inbound WebSocket intake — validated once at startup so a bad
  // path or timer can never fail an upgrade mid-flight. The path must not
  // collide with the operator surface: an upgrade handler runs before the
  // HTTP dispatch, so it would shadow operator routes.
  let inboundWs: ResolvedInboundWsOptions | undefined;
  if (opts.inboundWs !== undefined) {
    try {
      inboundWs = resolveInboundWsOptions(opts.inboundWs);
    } catch (err) {
      throw new RangeError(`createRelayServer: invalid inboundWs config: ${(err as Error).message}`);
    }
    if (isOperatorPath(inboundWs.path)) {
      throw new RangeError(
        `createRelayServer: inboundWs.path must not be an operator path: ${inboundWs.path}`
      );
    }
  }
  // WR-107: relay mesh config + activity-gated metrics. `undefined` =
  // mesh disabled: the header is stripped at intake and never stamped.
  // Declared early: the default sender (built below) needs the sender
  // options in scope.
  const meshCfg = assertValidMeshOptions(opts.mesh);
  const meshMetrics = new MeshMetrics();
  // The default sender stamps mesh hops only when mesh is enabled;
  // `undefined` keeps the exact pre-WR-107 wire shape. WR-112: the
  // sender also learns whether mesh-link mTLS is on, so it can refuse
  // to forward a hop without mutual TLS.
  const meshSenderOpts =
    meshCfg !== undefined ? { metrics: meshMetrics, mtls: meshCfg.mtls === true } : undefined;
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
  // WR-103: inbound mTLS — validated once at startup (`RangeError`
  // fail-fast on a bad server identity, CA chain, or whitelist);
  // `undefined` keeps the exact pre-WR-103 behavior (plain HTTP
  // listeners, no certificate checks). `let` so
  // `updateInboundMtlsConfig` can hot-swap the resolved config.
  let inboundMtls: ResolvedInboundMtlsConfig | undefined;
  if (opts.inboundMtls !== undefined) {
    try {
      inboundMtls = resolveInboundMtlsConfig(opts.inboundMtls);
    } catch (err) {
      throw new RangeError(`createRelayServer: invalid inboundMtls config: ${(err as Error).message}`);
    }
  }
  // WR-112: mesh-link mTLS (opt-in) startup contract. A client
  // certificate can only be verified inside a TLS handshake, so
  // `mesh.mtls` requires `inboundMtls` with the intake listener
  // terminating TLS (`requireCert`, or `operatorMtls` on the legacy
  // single plane) — otherwise enabling it would silently verify
  // nothing, which is worse than refusing to start. Plain HTTP intake
  // + `mesh.mtls` is therefore a `RangeError`, never a quiet no-op.
  if (meshCfg?.mtls === true) {
    if (inboundMtls === undefined) {
      throw new RangeError(
        "createRelayServer: mesh.mtls requires inboundMtls — mesh peer certificates can only be verified when the intake listener terminates TLS"
      );
    }
    const intakeTerminatesTls =
      inboundMtls.requireCert || (operatorPlane === undefined && inboundMtls.operatorMtls);
    if (!intakeTerminatesTls) {
      throw new RangeError(
        "createRelayServer: mesh.mtls requires the intake listener to terminate TLS " +
          "(inboundMtls.requireCert, or inboundMtls.operatorMtls on the single-plane listener)"
      );
    }
  }
  // WR-112: the inbound-mtls chain the mesh gate reuses, with the
  // certificate forced required on the mesh path. `undefined` when mesh
  // mTLS is off — or when the global gate already requires a
  // certificate everywhere (`requireCert`), which makes the mesh gate
  // redundant: every request already carries a verified identity.
  const meshMtlsInbound: ResolvedInboundMtlsConfig | undefined =
    meshCfg?.mtls === true && inboundMtls !== undefined && !inboundMtls.requireCert
      ? { ...inboundMtls, requireCert: true }
      : undefined;
  // WR-84: content-based routing rule engine — validated once at startup
  // (`RangeError` fail-fast on bad rules or a bad default), held by the
  // server closure, hot-swappable atomically via `POST /routing/rules`.
  // Unset entirely when neither option is configured, so intake is
  // byte-identical to the legacy single-target behavior.
  let contentRouteTable: ContentRouteTable | undefined;
  if (opts.contentRoutes !== undefined || opts.contentRouteDefault !== undefined) {
    contentRouteTable = new ContentRouteTable(opts.contentRoutes ?? [], opts.contentRouteDefault);
  }
  // WR-98: W3C trace-context propagation — validated once at startup
  // (`RangeError` fail-fast on bad values), held by the server closure.
  // `undefined` keeps the exact pre-WR-98 behavior: the intake never
  // parses `traceparent` and the sender never stamps one.
  let traceContextOpts: ReturnType<typeof resolveTraceContextOptions>;
  try {
    traceContextOpts = resolveTraceContextOptions(opts.traceContext ?? opts.retry?.traceContext);
  } catch (err) {
    throw new RangeError(`createRelayServer: invalid traceContext config: ${(err as Error).message}`);
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
  // WR-101: the OCSP revocation monitor is only constructed when at
  // least one endpoint opts in via `tlsOcsp` — otherwise no
  // `relay_ocsp_*` series ever appears. Every `ocsp_revoked` event lands
  // in the audit log; revocations and fail-open continuations also fire
  // the alert hook (audited as `ocsp_alert`). Invalid values throw
  // RangeError at startup (see createDefaultSender).
  const ocspMonitor =
    opts.tlsOcsp !== undefined
      ? new OcspMonitor({
          onRevoked: (event) => {
            opts.auditLog.append(event);
          },
          onAlert: (alert) => {
            opts.auditLog.append({
              event: "ocsp_alert",
              kind: alert.kind,
              endpoint: alert.endpoint,
              mode: alert.mode,
              detail: alert.detail,
              outcome: alert.outcome,
              at: alert.at,
            });
          },
        })
      : undefined;
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
  // WR-165: a chaos-drill fault was injected — one audit line per fault
  // naming the endpoint, the fault kind, and the detail (latency or
  // synthetic status). Injected faults are always distinguishable from
  // real downstream failures in the audit trail.
  const onChaosInjectedAudit = (info: ChaosInjectionInfo) => {
    opts.auditLog.append({
      event: "chaos_injected",
      id: info.id,
      ...(info.traceId !== undefined ? { traceId: info.traceId } : {}),
      targetUrl: info.endpoint,
      kind: info.kind,
      ...(info.detailMs !== undefined ? { latencyMs: info.detailMs } : {}),
      ...(info.detailStatus !== undefined ? { statusCode: info.detailStatus } : {}),
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
  // WR-89: compile per-endpoint client-cert rotation sets once at
  // startup — the compiled set pins each rotation's grace window to
  // server start (same reasoning as WR-67's compileSecretRotationRules:
  // rebuilding per request would silently restart the grace window).
  // Invalid values throw RangeError here, never mid-handshake. The
  // compiled map is shared with the inventory below and passed to the
  // default sender.
  let clientCertRotations: Map<string, RotatingClientCertSet> | undefined;
  if (opts.tlsClientCertRotation !== undefined) {
    const raw = opts.tlsClientCertRotation;
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
      throw new RangeError(
        "createRelayServer: `tlsClientCertRotation` must be a record of endpoint -> rotation config"
      );
    }
    clientCertRotations = new Map();
    for (const [endpoint, cfg] of Object.entries(raw)) {
      try {
        clientCertRotations.set(endpoint, new RotatingClientCertSet(cfg));
      } catch (err) {
        throw new RangeError(
          `createRelayServer: invalid tlsClientCertRotation for ${endpoint}: ${(err as Error).message}`
        );
      }
    }
  }
  // WR-92: one shared DNS cache instance for the main and shadow
  // senders — a single counter set, a single `relay_dns_cache_*` block
  // in `GET /metrics`. Built once here (not per sender) so both observe
  // the same entries.
  let sharedDnsCache: DnsCache | undefined;
  if (opts.dnsCache !== undefined) {
    try {
      sharedDnsCache =
        opts.dnsCache instanceof DnsCache ? opts.dnsCache : new DnsCache(opts.dnsCache);
    } catch (err) {
      throw new RangeError(`createRelayServer: invalid dnsCache: ${(err as Error).message}`);
    }
  }
  // WR-114: the dynamic endpoint registry. Always constructed — empty
  // when `opts.endpoints` is unset — so the sender's per-attempt
  // resolution has a stable lookup target and an unused registry is
  // exactly the pre-WR-114 behavior (every lookup misses). The
  // constructor validates every record before inserting any of them:
  // an illegal value throws `RangeError` here, at startup.
  let endpointRegistry: EndpointRegistry;
  try {
    endpointRegistry = new EndpointRegistry(opts.endpoints ?? []);
  } catch (err) {
    throw new RangeError(
      `createRelayServer: invalid \`endpoints\`: ${(err as Error).message}`
    );
  }
  if (
    opts.endpointDrainTimeoutMs !== undefined &&
    !(typeof opts.endpointDrainTimeoutMs === "number" &&
      Number.isFinite(opts.endpointDrainTimeoutMs) &&
      opts.endpointDrainTimeoutMs > 0)
  ) {
    throw new RangeError(
      "createRelayServer: `endpointDrainTimeoutMs` must be a finite number > 0"
    );
  }
  // WR-114: registry `ordered` records fold into the queue's ordered
  // config before the queue is built (the queue constructs its
  // ordered-delivery tracker once, at construction — there is no safe
  // runtime enable). A static `ordered` config (server-level or nested)
  // that is already enabled conflicts with registry `ordered` records:
  // fail fast, never let the two disagree about who owns the line.
  let registryOrdered: Record<string, boolean | { enabled: boolean; maxHeadOfLineHoldMs?: number }> | undefined;
  for (const record of endpointRegistry.list()) {
    if (record.ordered !== undefined) {
      registryOrdered = registryOrdered ?? {};
      registryOrdered[record.targetUrl] = record.ordered.enabled
        ? { enabled: true, ...(record.ordered.maxHeadOfLineHoldMs !== undefined ? { maxHeadOfLineHoldMs: record.ordered.maxHeadOfLineHoldMs } : {}) }
        : false;
    }
  }
  if (registryOrdered !== undefined) {
    let staticOrderedEnabled = false;
    try {
      staticOrderedEnabled =
        resolveOrderedConfig(opts.ordered ?? opts.retry?.ordered) !== undefined;
    } catch {
      // Invalid static config: leave it for the queue constructor's own
      // validation to report — the conflict check must not mask it.
      staticOrderedEnabled = false;
    }
    if (staticOrderedEnabled) {
      throw new RangeError(
        "createRelayServer: `ordered` is configured both statically and via `endpoints` registry records — use one"
      );
    }
  }
  const defaultSender =
    opts.sender === undefined
      ? createDefaultSender(opts.tlsPins, opts.outboundKeepAlive, opts.outboundSigning, opts.proxies, opts.tlsClientCerts, opts.compressOutbound, opts.outboundHttp2, opts.outboundIdempotencyKey, undefined, opts.outboundEncryption, opts.tlsSniOverrides, opts.responseCompression, opts.forwardHeaders, certExpiryMonitor, opts.minTlsVersions, tlsVersionMonitor, opts.compressThreshold, onGzipFallbackAudit, onE2eeKeyRotatedAudit, clientCertRotations, sharedDnsCache, opts.retry?.latencyPhases !== undefined, opts.traceContext ?? opts.retry?.traceContext, opts.tlsOcsp, ocspMonitor, meshSenderOpts, endpointRegistry, opts.payloadTransforms, opts.awsSigV4, opts.awsSecretResolver, opts.outboundSchemas, opts.oauth2, undefined, opts.compressBrotli, opts.phaseTimeouts, opts.tlsCa, opts.chaos, onChaosInjectedAudit)
      : undefined;
  // WR-146: tail-latency hedging for outbound attempts (opt-in). The
  // wrapper sits around whichever sender the queue uses — the default
  // sender or an injected custom one — and is a pure pass-through when
  // disabled or when no endpoint is hedgeable. The server's own
  // `defaultSender` handle keeps its PooledSender properties (pool,
  // destroy, ...) untouched, exactly like the WR-85 coalescing wrap.
  const hedgeMetrics = new HedgeMetrics();
  const hedgedCfg = opts.hedgedRequests;
  if (hedgedCfg !== undefined && hedgedCfg.enabled === true) {
    if (hedgedCfg.hedgeable !== undefined && typeof hedgedCfg.hedgeable !== "function") {
      throw new RangeError("createRelayServer: hedgedRequests.hedgeable must be a function");
    }
  }
  const hedgeableEndpoints = hedgedCfg?.hedgeableEndpoints;
  const hedgedSender = (
    hedgedCfg !== undefined && hedgedCfg.enabled === true
      ? createHedgedSender(opts.sender ?? defaultSender!, {
          enabled: true,
          hedgeDelayMs: hedgedCfg.hedgeDelayMs,
          hedgeable:
            hedgedCfg.hedgeable ??
            (hedgeableEndpoints === undefined
              ? () => false
              : (item) => hedgeableEndpoints.includes(item.targetUrl)),
          metrics: hedgeMetrics,
          onHedge: (event: HedgeAuditEvent) => {
            opts.auditLog.append({
              event: event.event,
              id: event.id,
              ...(event.traceId !== undefined ? { traceId: event.traceId } : {}),
              targetUrl: event.endpoint,
              hedgeDelayMs: event.hedgeDelayMs,
            });
          },
        })
      : // Hedging off: the queue talks to the sender directly, byte-identical.
        (opts.sender ?? defaultSender!)
  ) as HedgedSender;
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
    for (const record of [opts.tlsPins, opts.tlsClientCerts, opts.tlsClientCertRotation, opts.compressOutbound, opts.compressThreshold, opts.compressBrotli, opts.proxies, opts.outboundEncryption, opts.responseCompression, opts.forwardHeaders, opts.minTlsVersions, opts.tlsOcsp, opts.payloadTransforms, opts.outboundSchemas]) {
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
                  onE2eeKeyRotatedAudit,
                  undefined,
                  // WR-92: shadow senders share the relay's DNS cache
                  // instance — one counter set for main + shadow traffic.
                  sharedDnsCache,
                  // WR-95: same phase-measurement gate as the main sender.
                  opts.retry?.latencyPhases !== undefined,
                  // WR-98: shadow deliveries mirror the identical wire
                  // request, so they propagate trace context like the main
                  // sender.
                  opts.traceContext ?? opts.retry?.traceContext,
                  // tlsOcsp / ocspMonitor / mesh / endpointRegistry stay
                  // off for shadow copies (pre-existing).
                  undefined,
                  undefined,
                  undefined,
                  undefined,
                  // WR-115: shadow deliveries mirror the identical wire
                  // request, so they apply the same payload transform.
                  opts.payloadTransforms,
                  // WR-116/WR-129: shadow copies are byte-identical
                  // mirrors — SigV4/OAuth2 stay off (pre-existing).
                  undefined,
                  undefined,
                  undefined,
                  undefined,
                  undefined,
                  // WR-142: like the gzip compressions, the brotli
                  // config mirrors onto shadow senders.
                  opts.compressBrotli,
                  // phaseTimeouts stay off for shadow copies (pre-existing);
                  // the trailing slot is the WR-163 tlsCa record.
                  undefined,
                  t.tlsCa !== undefined ? { [t.targetUrl]: t.tlsCa } : undefined
                ),
              })
            ),
          ])
        )
      : opts.retry?.shadowTargets;
  const queue = new RetryQueue({
    // WR-146: the queue talks to the hedged wrapper (a pure pass-through
    // when hedging is off) so the server's `defaultSender` handle keeps
    // its PooledSender properties for pool management.
    sender: hedgedSender,
    ...(opts.retry ?? {}),
    // WR-127: one-shot per-endpoint maintenance windows (see
    // `src/maintenance-window.ts`). Wrap the caller's `onTransition` so
    // every window transition is audited as `maintenance_window_opened` /
    // `maintenance_window_closed`, not just observed.
    ...(opts.retry?.maintenanceWindow === undefined
      ? {}
      : {
          maintenanceWindow: {
            ...opts.retry.maintenanceWindow,
            onTransition: (t: MaintenanceWindowTransition) => {
              opts.auditLog.append({
                event: t.kind === "opened" ? "maintenance_window_opened" : "maintenance_window_closed",
                endpoint: t.endpoint,
                start: t.window.start,
                end: t.window.end,
              });
              opts.retry?.maintenanceWindow?.onTransition?.(t);
            },
          },
        }),
    // WR-92: downstream health probes (WR-34) resolve through the shared
    // DNS cache when one is configured — the same stale-while-revalidate
    // treatment as the delivery path. An explicit `probe.lookup` still
    // wins (explicit beats ambient).
    ...(sharedDnsCache !== undefined && opts.retry?.probe !== undefined
      ? { probe: { lookup: sharedDnsCache.lookup, ...opts.retry.probe } }
      : {}),
    // WR-147: wrap the caller's onBurnRateAlert so every burn-rate alert
    // is audited as `error_budget_burn`, not just observed. The monitor
    // itself swallows a throwing callback, so alerting can never break
    // the delivery path.
    ...(opts.retry?.errorBudget === undefined
      ? {}
      : {
          errorBudget: {
            ...opts.retry.errorBudget,
            onBurnRateAlert: (info: BurnRateAlertInfo) => {
              opts.auditLog.append(errorBudgetBurnAuditEvent(info));
              opts.retry?.errorBudget?.onBurnRateAlert?.(info);
            },
          },
        }),
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
    // WR-133: an explicit server-level `durableScheduledDir` wins over the
    // nested `retry.durableScheduledDir`; either way the queue owns the
    // journal. Wrap the caller's hook so every recovery is audited as
    // `scheduled_restored`, not just observed.
    durableScheduledDir: opts.durableScheduledDir ?? opts.retry?.durableScheduledDir,
    onScheduledRestored: (info) => {
      opts.auditLog.append({
        event: "scheduled_restored",
        dir: info.dir,
        restoredParked: info.restoredParked,
        restoredPastDue: info.restoredPastDue,
        skippedLines: info.skippedLines,
      });
      opts.retry?.onScheduledRestored?.(info);
    },
    // An explicit server-level `autoReplay` wins over the nested
    // `retry.autoReplay`; either way the queue owns the scheduler.
    autoReplay: opts.autoReplay ?? opts.retry?.autoReplay,
    // WR-145: an explicit server-level `deliveryDryRun` wins over the
    // nested `retry.deliveryDryRun`; either way the queue owns the
    // drill configs. Wrap the caller's hook so every drill outcome is
    // audited with `dry_run: true`, not just observed.
    deliveryDryRun: opts.deliveryDryRun ?? opts.retry?.deliveryDryRun,
    onDryRunDelivery: (event: DryRunDeliveryEvent) => {
      const dryRunLabel = { dry_run: true } as const;
      if (event.outcome === "delivered") {
        opts.auditLog.append({
          event: "delivered",
          id: event.id,
          traceId: event.traceId,
          ...(event.tenant !== undefined ? { tenant: event.tenant } : {}),
          endpoint: event.endpoint,
          targetUrl: event.targetUrl,
          attempts: event.attempts,
          statusCode: event.statusCode,
          latencyMs: event.latencyMs,
          ...dryRunLabel,
        });
      } else if (event.outcome === "retrying") {
        opts.auditLog.append({
          event: "retrying",
          id: event.id,
          traceId: event.traceId,
          ...(event.tenant !== undefined ? { tenant: event.tenant } : {}),
          endpoint: event.endpoint,
          targetUrl: event.targetUrl,
          attempts: event.attempts,
          statusCode: event.statusCode,
          error: event.error,
          nextDelayMs: event.nextDelayMs,
          ...dryRunLabel,
        });
      } else if (event.outcome === "exhausted") {
        // A drill must never enter the dead-letter queue, so exhaustion
        // gets its own audit event name instead of `dead_letter` —
        // operator dead-letter views stay clean for real dead letters.
        opts.auditLog.append({
          event: "dry_run_exhausted",
          id: event.id,
          traceId: event.traceId,
          ...(event.tenant !== undefined ? { tenant: event.tenant } : {}),
          endpoint: event.endpoint,
          targetUrl: event.targetUrl,
          attempts: event.attempts,
          statusCode: event.statusCode,
          error: event.error,
          ...dryRunLabel,
        });
      } else {
        opts.auditLog.append({
          event: "failed",
          id: event.id,
          traceId: event.traceId,
          ...(event.tenant !== undefined ? { tenant: event.tenant } : {}),
          endpoint: event.endpoint,
          targetUrl: event.targetUrl,
          attempts: event.attempts,
          statusCode: event.statusCode,
          reason: "dry_run_failed",
          error: event.error,
          ...dryRunLabel,
        });
      }
      opts.retry?.onDryRunDelivery?.(event);
    },
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
    // WR-100: an explicit server-level `stalePause` wins over the nested
    // `retry.stalePause`; either way the queue owns the sweeper.
    stalePause: opts.stalePause ?? opts.retry?.stalePause,
    // An explicit server-level `replayEgress` wins over the nested
    // `retry.replayEgress`; either way the queue owns the gate.
    replayEgress: opts.replayEgress ?? opts.retry?.replayEgress,
    // WR-135: same precedence for two-phase replay approval — the queue
    // owns the token ledger, the operator endpoints issue from it.
    replayApproval: opts.replayApproval ?? opts.retry?.replayApproval,
    // Wrap the caller's hook so every retention purge is audited as
    // `dead_letter_purged`, not just observed.
    onDeadLetterPurged: (event) => {
      opts.auditLog.append(event);
      opts.retry?.onDeadLetterPurged?.(event);
    },
    // WR-100: wrap the caller's hook so every stale-endpoint auto-pause
    // is audited as `endpoint_auto_paused` (the full event carries
    // endpoint/idleDays/staleAfterDays/lastSuccessfulDeliveryAt), not
    // just observed. This audit event is the operator alert channel for
    // the feature — edge-triggered, one per transition.
    onStalePauseAudit: (event) => {
      opts.auditLog.append(event);
      opts.retry?.onStalePauseAudit?.(event);
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
    // WR-97: an explicit server-level `tenantRateLimit` wins over the
    // nested `retry.tenantRateLimit`; either way the queue owns the
    // limiter (the intake consults it via `admitTenantDelivery()` in
    // `reject-429` mode).
    tenantRateLimit: opts.tenantRateLimit ?? opts.retry?.tenantRateLimit,
    // WR-154: an explicit server-level `outboundRateLimit` wins over the
    // nested `retry.outboundRateLimit`; either way the queue owns the
    // limiter.
    outboundRateLimit: opts.outboundRateLimit ?? opts.retry?.outboundRateLimit,
    // WR-155: an explicit server-level `deliveryReceipts` wins over the
    // nested `retry.deliveryReceipts`; either way the queue owns the
    // store.
    deliveryReceipts: opts.deliveryReceipts ?? opts.retry?.deliveryReceipts,
    // WR-113: an explicit server-level `ordered` wins over the nested
    // `retry.ordered`; either way the queue owns the line state. WR-114:
    // registry `ordered` records supply the whole ordered config when
    // no static ordered config is enabled (a conflict is a startup
    // error, checked above).
    ordered: registryOrdered ?? opts.ordered ?? opts.retry?.ordered,
    // Wrap the caller's hook so every urgent bypass and every
    // poison-parked head is audited as `ordered_bypassed` /
    // `head_of_line_parked`, not just observed.
    onOrderedAudit: (event: OrderedAuditEvent) => {
      opts.auditLog.append({
        event: event.kind,
        id: event.id,
        traceId: event.traceId,
        ...(event.tenant !== undefined ? { tenant: event.tenant } : {}),
        targetUrl: event.endpoint,
        ...(event.blockedMs !== undefined ? { blockedMs: event.blockedMs } : {}),
        ...(event.maxHeadOfLineHoldMs !== undefined
          ? { maxHeadOfLineHoldMs: event.maxHeadOfLineHoldMs }
          : {}),
      });
      opts.retry?.onOrderedAudit?.(event);
    },
    // WR-98: an explicit server-level `traceContext` wins over the nested
    // `retry.traceContext`; either way the queue owns span-reference
    // resolution for delivery events and the OTLP export.
    traceContext: opts.traceContext ?? opts.retry?.traceContext,
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
    // WR-106: quorum fan-out (M-of-N downstream acknowledgement). An
    // explicit server-level `quorum` wins over the nested `retry.quorum`;
    // either way the queue owns the fan-out set. Wrap the caller's hooks
    // so every quorum outcome is audited, not just observed.
    quorum: opts.quorum ?? opts.retry?.quorum,
    // WR-109: retention window + LRU cap ride through to the queue's
    // fan-out set (which validates fail-fast); server-level wins over
    // nested `retry.*`, mirroring the `quorum` option itself.
    quorumRetentionMs: opts.quorumRetentionMs ?? opts.retry?.quorumRetentionMs,
    quorumMaxFanouts: opts.quorumMaxFanouts ?? opts.retry?.quorumMaxFanouts,
    onQuorumDispatched: (info: QuorumDispatchedInfo) => {
      opts.auditLog.append({
        event: "quorum_dispatched",
        id: info.fanoutId,
        traceId: info.traceId,
        ...(info.tenant !== undefined ? { tenant: info.tenant } : {}),
        targetUrl: info.endpoint,
        targets: info.targets,
        quorum: info.quorum,
      });
      opts.retry?.onQuorumDispatched?.(info);
    },
    onQuorumAcknowledged: (info: QuorumAcknowledgedInfo) => {
      opts.auditLog.append({
        event: "quorum_acknowledged",
        id: info.fanoutId,
        traceId: info.traceId,
        ...(info.tenant !== undefined ? { tenant: info.tenant } : {}),
        targetUrl: info.endpoint,
        ackTarget: info.targetUrl,
        acked: info.acked,
        targets: info.targets,
      });
      opts.retry?.onQuorumAcknowledged?.(info);
    },
    onQuorumSatisfied: (info: QuorumSatisfiedInfo) => {
      opts.auditLog.append({
        event: "quorum_satisfied",
        id: info.fanoutId,
        traceId: info.traceId,
        ...(info.tenant !== undefined ? { tenant: info.tenant } : {}),
        targetUrl: info.endpoint,
        acked: info.acked,
        targets: info.targets,
      });
      opts.retry?.onQuorumSatisfied?.(info);
    },
    onQuorumFailed: (info: QuorumFailedInfo) => {
      opts.auditLog.append({
        event: "quorum_failed",
        id: info.fanoutId,
        traceId: info.traceId,
        ...(info.tenant !== undefined ? { tenant: info.tenant } : {}),
        targetUrl: info.endpoint,
        acked: info.acked,
        targets: info.targets,
        reason: info.reason,
      });
      opts.retry?.onQuorumFailed?.(info);
    },
    onQuorumTargetDeadLettered: (info: QuorumTargetDeadLetteredInfo) => {
      opts.auditLog.append({
        event: "quorum_target_dead_lettered",
        id: info.fanoutId,
        traceId: info.traceId,
        ...(info.tenant !== undefined ? { tenant: info.tenant } : {}),
        targetUrl: info.endpoint,
        deadTarget: info.targetUrl,
        failureClass: info.failureClass,
        error: info.lastError,
        acked: info.acked,
        targets: info.targets,
      });
      opts.retry?.onQuorumTargetDeadLettered?.(info);
    },
    // WR-109: wrap the caller's hook so every retention eviction is
    // archived in the audit trail as `quorum_evicted` (operator
    // metadata only: fan-out id, endpoint, tenant, terminal status,
    // acked/targets/lost-target counts, dispatch/verdict/eviction
    // timestamps, eviction reason — no payloads), not just observed.
    onQuorumEvicted: (info: QuorumEvictedInfo) => {
      opts.auditLog.append({
        event: "quorum_evicted",
        id: info.fanoutId,
        traceId: info.traceId,
        ...(info.tenant !== undefined ? { tenant: info.tenant } : {}),
        targetUrl: info.endpoint,
        status: info.status,
        acked: info.acked,
        targets: info.targets,
        deadLettered: info.deadLettered,
        dispatchedAt: info.dispatchedAt,
        settledAt: info.settledAt,
        evictedAt: info.evictedAt,
        reason: info.reason,
      });
      opts.retry?.onQuorumEvicted?.(info);
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
    // WR-137: wrap the caller's hook so every tenant budget exceedance
    // is audited as `budget_exceeded`, not just observed.
    onBudgetExceeded: (event) => {
      opts.auditLog.append(event);
      opts.retry?.onBudgetExceeded?.(event);
    },
    // Wrap the caller's hook so every urgent fast-lane starvation-guard
    // downgrade (WR-121) is audited, not just observed.
    onUrgentDowngraded: (event) => {
      opts.auditLog.append(event);
      opts.retry?.onUrgentDowngraded?.(event);
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
    // WR-93: an explicit server-level `deadLetterEscalation` wins over
    // the nested `retry.escalation`; either way the queue owns the
    // escalator. Wrap the caller's hooks so every dispatched alert is
    // audited as `dead_letter_escalated` and every exhausted alert as
    // `dead_letter_escalation_failed`, not just observed. A failing
    // alert never enters the retry queue or the dead-letter list — it
    // cannot recurse into the machinery it observes.
    escalation: opts.deadLetterEscalation ?? opts.retry?.escalation,
    onDeadLetterEscalated: (info: DeadLetterEscalatedInfo) => {
      opts.auditLog.append({
        event: "dead_letter_escalated",
        ...(info.tenant !== undefined ? { tenant: info.tenant } : {}),
        endpoint: info.endpoint,
        deadLetters: info.deadLetters,
        threshold: info.threshold,
        windowMs: info.windowMs,
        alertedAt: info.alertedAt,
      });
      opts.retry?.onDeadLetterEscalated?.(info);
    },
    onDeadLetterEscalationFailed: (info: DeadLetterEscalationFailedInfo) => {
      opts.auditLog.append({
        event: "dead_letter_escalation_failed",
        ...(info.tenant !== undefined ? { tenant: info.tenant } : {}),
        endpoint: info.endpoint,
        attempts: info.attempts,
        error: info.error,
      });
      opts.retry?.onDeadLetterEscalationFailed?.(info);
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
      // WR-89: the rotation certificate id that authenticated this
      // delivery — absent for WR-36 single-identity and non-mTLS
      // endpoints (legacy audit shape).
      const clientCertId = defaultSender?.takeRotationClientCertId?.(item.id);
      // WR-146: a delivery that launched a hedge attempt carries the
      // marker (take-and-clear — the flag is consumed here, exactly
      // once, like the rotation certificate id above).
      const hedged = hedgedSender.takeHedgedFlag?.(item.id) === true;
      opts.auditLog.append({
        event: "delivered",
        id: item.id,
        traceId: item.traceId,
        ...(item.tenantId !== undefined ? { tenant: item.tenantId } : {}),
        targetUrl: item.targetUrl,
        attempts,
        ...(hedged ? { hedged: true } : {}),
        // WR-107: the mesh hop count the event arrived with — the audit
        // trail shows how deep into the mesh the delivery traveled.
        ...(item.meshHops !== undefined ? { meshHops: item.meshHops } : {}),
        ...(clientCertId !== undefined ? { clientCertId } : {}),
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
    // Wrap the caller's onAssertionFailure so every assertion failure
    // is audited as `failed` with reason `assertion_failed`, not just
    // observed — mirroring the WR-37 semantic-failure audit above.
    onAssertionFailure: (info) => {
      opts.auditLog.append({
        event: "failed",
        id: info.id,
        traceId: info.traceId,
        ...(info.tenant !== undefined ? { tenant: info.tenant } : {}),
        targetUrl: info.endpoint,
        attempts: info.attempts,
        reason: "assertion_failed",
        assertionReason: info.reason,
      });
      opts.retry?.onAssertionFailure?.(info);
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
        // WR-125: which budget parked the retry — "endpoint" means only
        // that endpoint's own override bucket was exhausted.
        budgetScope: info.scope,
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
      // WR-89: the rotation certificate id used by this delivery's
      // latest handshake attempt — absent when the endpoint has no
      // rotation or no handshake ran (legacy audit shape).
      const clientCertId = defaultSender?.takeRotationClientCertId?.(item.id);
      opts.auditLog.append({
        event: "dead_letter",
        id: item.id,
        traceId: item.traceId,
        ...(item.tenantId !== undefined ? { tenant: item.tenantId } : {}),
        targetUrl: item.targetUrl,
        attempts,
        // WR-107: the mesh hop count the event arrived with.
        ...(item.meshHops !== undefined ? { meshHops: item.meshHops } : {}),
        ...(clientCertId !== undefined ? { clientCertId } : {}),
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
      // WR-115: a transform failure gets its own audit line on top of the
      // `dead_letter` above — the operator sees *why* the item died
      // (event id, error, endpoint), not just that it died. The
      // `failure_class` on the `dead_letter` event is "non_retryable":
      // the wire request was never built, so retrying was futile.
      if (lastError instanceof PayloadTransformError) {
        opts.auditLog.append({
          event: "transform_failed",
          id: item.id,
          traceId: item.traceId,
          ...(item.tenantId !== undefined ? { tenant: item.tenantId } : {}),
          targetUrl: item.targetUrl,
          error: lastError.message,
        });
      }
      // WR-117: an outbound schema violation gets its own audit line on
      // top of the `dead_letter` above — the operator sees *why* the
      // item died (event id, error, endpoint, schema name/version), not
      // just that it died. The `failure_class` on the `dead_letter`
      // event is "non_retryable": the wire request was never built, so
      // retrying was futile.
      if (lastError instanceof OutboundSchemaViolationError) {
        opts.auditLog.append({
          event: "schema_violation",
          id: item.id,
          traceId: item.traceId,
          ...(item.tenantId !== undefined ? { tenant: item.tenantId } : {}),
          targetUrl: item.targetUrl,
          schema: lastError.schemaName,
          schemaVersion: lastError.schemaVersion,
          error: lastError.message,
        });
      }
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
    // WR-149: audit replay-idempotency guard decisions; the caller's own
    // hooks still fire afterwards.
    onReplaySkipped: (info) => {
      opts.auditLog.append({ event: "replay_skipped_delivered", ...info });
      opts.retry?.onReplaySkipped?.(info);
    },
    onReplayForced: (info) => {
      opts.auditLog.append({ event: "replay_forced", ...info });
      opts.retry?.onReplayForced?.(info);
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
    // nothing. WR-100: auto-pauses (cause "auto") are NOT audited here
    // as `endpoint_paused` — the richer `endpoint_auto_paused` event
    // from `onStalePauseAudit` already covers the transition, so each
    // pause audits exactly one event with the cause in its name.
    onEndpointPaused: ({ endpoint, cause }) => {
      if (cause !== "auto") {
        opts.auditLog.append({
          event: "endpoint_paused",
          endpoint,
          ...(activeOperatorKeyId !== undefined ? { keyId: activeOperatorKeyId } : {}),
        });
      }
      opts.retry?.onEndpointPaused?.({ endpoint, cause });
    },
    onEndpointResumed: ({ endpoint }) => {
      opts.auditLog.append({
        event: "endpoint_resumed",
        endpoint,
        ...(activeOperatorKeyId !== undefined ? { keyId: activeOperatorKeyId } : {}),
      });
      opts.retry?.onEndpointResumed?.({ endpoint });
    },
    // WR-150: audit the auto-disable transition and operator re-enables.
    // Edge-triggered in the queue — each transition audits exactly one
    // event. The disable carries the streak that tripped it so the
    // operator sees *why* the gate fired.
    onEndpointAutoDisabled: ({ endpoint, consecutiveFailures, failureThreshold }) => {
      opts.auditLog.append({
        event: "endpoint_auto_disabled",
        endpoint,
        consecutiveFailures,
        failureThreshold,
        ...(activeOperatorKeyId !== undefined ? { keyId: activeOperatorKeyId } : {}),
      });
      opts.retry?.onEndpointAutoDisabled?.({ endpoint, consecutiveFailures, failureThreshold });
    },
    onEndpointEnabled: ({ endpoint }) => {
      opts.auditLog.append({
        event: "endpoint_enabled",
        endpoint,
        ...(activeOperatorKeyId !== undefined ? { keyId: activeOperatorKeyId } : {}),
      });
      opts.retry?.onEndpointEnabled?.({ endpoint });
    },
    // WR-153: audit each queue-depth breach episode. Edge-triggered in
    // the queue — one event per episode (endpoint, depth, threshold).
    // Unlike the auto-disable above this is pure observation: the
    // breach never pauses or gates deliveries, it only notifies.
    onQueueDepthBreach: ({ endpoint, depth, threshold }) => {
      opts.auditLog.append({
        event: "queue_depth_breached",
        endpoint,
        depth,
        threshold,
        ...(activeOperatorKeyId !== undefined ? { keyId: activeOperatorKeyId } : {}),
      });
      opts.retry?.onQueueDepthBreach?.({ endpoint, depth, threshold });
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
  // WR-114: apply the registry's deliver-policy fields into the queue.
  // Structural validation already ran in the registry constructor; the
  // remaining failure mode is a disabled subsystem (e.g. breaker
  // thresholds with no breaker configured). Apply endpoint by endpoint
  // and roll back the ones already applied on the first failure — a
  // startup error must leave zero partial application behind.
  // (`applied` is hoisted: a `const` declared inside `try` is invisible
  // in `catch` on this Node/V8 — see AGENTS.md.)
  const appliedRegistryEndpoints: EndpointRecord[] = [];
  try {
    for (const record of endpointRegistry.list()) {
      if (hasDeliverPolicy(record)) {
        queue.updateEndpointConfig(record.targetUrl, deliverPolicyPatch(record));
        appliedRegistryEndpoints.push(record);
      }
    }
  } catch (err) {
    for (const record of appliedRegistryEndpoints) {
      if (record.maxConcurrentPerEndpoint !== undefined) {
        queue.clearEndpointConfigOverride(undefined, record.targetUrl, "maxConcurrentPerEndpoint");
      }
      if (record.circuitBreaker !== undefined) {
        queue.clearEndpointConfigOverride(undefined, record.targetUrl, "circuitBreaker");
      }
      if (record.quota !== undefined) {
        queue.clearEndpointConfigOverride(undefined, record.targetUrl, "quota");
      }
    }
    throw new RangeError(
      `createRelayServer: invalid \`endpoints\` deliver policy: ${(err as Error).message}`
    );
  }
  // WR-88: declarative inventory for config snapshots — the wiring
  // `updateEndpointConfig` cannot hot-reload, as identifiers only. Signing
  // keys contribute key ids (never the HMAC secrets); mTLS contributes the
  // client-cert identity fingerprint (never PEM bytes); proxies contribute
  // presence + a credentials flag (never the proxy URL). Snapshot restore
  // refuses fail-closed when any secret-bearing dimension diverged.
  const readConfigInventory = (): ConfigSnapshotInventory => ({
    routing:
      contentRouteTable === undefined
        ? null
        : {
            rules: contentRouteTable.getRules(),
            ...(contentRouteTable.getDefaultTargetUrl() !== undefined
              ? { defaultTargetUrl: contentRouteTable.getDefaultTargetUrl() as string }
              : {}),
          },
    signingKeys: (opts.signingKeys ?? []).map((k) => ({ id: k.id })),
    mtls: Object.fromEntries([
      ...Object.entries(opts.tlsClientCerts ?? {}).map(([endpoint, cert]) => [
        endpoint,
        { certIdentity: clientCertIdentity(cert) },
      ]),
      // WR-89: rotation endpoints enter the inventory under their
      // primary certificate's identity fingerprint — the identity new
      // handshakes present — so a primary swap is visible to snapshot
      // restore's fail-closed drift comparison.
      ...[...(clientCertRotations ?? [])].map(([endpoint, set]) => [
        endpoint,
        { certIdentity: clientCertIdentity(set.primary().cert) },
      ]),
    ]),
    tlsPins: { ...(opts.tlsPins ?? {}) },
    proxies: Object.fromEntries(
      Object.entries(opts.proxies ?? {}).map(([endpoint, proxyUrl]) => {
        let hasCredentials = false;
        try {
          const u = new URL(proxyUrl);
          hasCredentials = u.username !== "" || u.password !== "";
        } catch {
          hasCredentials = false;
        }
        return [endpoint, { configured: true, hasCredentials }];
      })
    ),
    compression: { ...(opts.compressOutbound ?? {}) },
    tenants: [
      ...new Set(
        queue
          .configuredEndpoints()
          .map((e) => e.tenant)
          .filter((t): t is string => t !== undefined)
      ),
    ],
    // WR-156: revoked-key inventory is id-only (never key bytes) — safe
    // to capture in the snapshot; applyConfig can re-apply it (append
    // only) through the runtime revoke hooks below.
    revokedApiKeys: (apiKeyAuth?.revokedKeys() ?? []).reduce<
      Array<{ pattern: string; keyIds: string[] }>
    >((acc, { pattern, keyId }) => {
      const row = acc.find((r) => r.pattern === pattern);
      if (row === undefined) acc.push({ pattern, keyIds: [keyId] });
      else row.keyIds.push(keyId);
      return acc;
    }, []),
    revokedOperatorKeys: [...operatorKeyRing.revokedIds()],
  });
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
  // WR-138: the signature-algorithm allowlist is validated once at
  // startup for the same reason — an unknown name or a bad verifier
  // can never fail a request mid-flight.
  assertValidSignatureAlgorithmRules(opts.signatureAlgorithms);
  // WR-102: per-endpoint body limit rules are validated once at startup
  // for the same reason — a bad pattern or budget can never fail a
  // request mid-flight.
  assertValidEndpointBodyLimitRules(opts.endpointBodyLimits);
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
  // WR-96: the schema registry compiles the rules once at startup —
  // registration runs the opt-in compatibility gate (a failing gate is a
  // startup RangeError, fail fast) and wires per-pattern auto-accumulated
  // corpora that later registrations are gated against.
  const schemaRegistry =
    opts.payloadSchemas !== undefined ? new InboundSchemaRegistry(opts.payloadSchemas) : undefined;
  const schemaMetrics = new SchemaMetrics();
  const deduplicator = opts.dedup ? new DeliveryDeduplicator(opts.dedup) : undefined;
  // WR-136: the adaptive inbound throttle (when `rateLimit.adaptiveInbound`
  // is set) reads the live retry-queue depth, so a wide downstream outage
  // slows the intake instead of piling the backlog deeper. `queue` is
  // built above; the provider is never called when adaptive is off.
  const rateLimiter = opts.rateLimit
    ? new InboundRateLimiter(opts.rateLimit, () => queue.pendingCount())
    : undefined;
  // WR-141: per-tenant inbound rate limiter (one token bucket per
  // x-tenant-id), checked after the WR-22 limiter and before signature
  // verification. Unset = unlimited: the intake path is byte-identical.
  // The metrics renderer is always built — it renders "" until the first
  // denial, so an untouched relay's /metrics stays byte-identical.
  const inboundTenantRateLimiter = opts.inboundTenantRateLimit
    ? new InboundTenantRateLimiter(opts.inboundTenantRateLimit)
    : undefined;
  const inboundTenantRateLimitMetrics = new InboundTenantRateLimitMetrics();
  // Inbound IP allowlist/denylist (WR-53): rules and trusted proxies are
  // validated (and every CIDR pre-parsed) once at startup, so a bad CIDR
  // can never fail a request mid-flight.
  const ipAcl = opts.ipAcl !== undefined ? new InboundIpAcl(opts.ipAcl) : undefined;
  const ipAclMetrics = new IpAclMetrics();
  // Inbound GeoIP country policy (WR-158): the table and policy are
  // validated (and every CIDR pre-parsed) once at startup, so a bad
  // country code or CIDR can never fail a request mid-flight. Unset =
  // off: intake behavior is byte-identical to the legacy one.
  const geoIpPolicy = opts.geoIp !== undefined ? new GeoIpInboundPolicy(opts.geoIp) : undefined;
  // Inbound per-endpoint API key authentication (WR-65): rules are
  // validated (constant-time comparison needs no precomputation, so this
  // is pure validation) once at startup, so a bad pattern or key entry
  // can never fail a request mid-flight. WR-156 wires the revocation
  // hook: every successful revokeKey audits `api_key_revoked`
  // (pattern + key id — identifiers, never key bytes).
  const apiKeyAuth =
    opts.apiKeys !== undefined
      ? new InboundApiKeyAuth({
          ...opts.apiKeys,
          onRevoked: ({ pattern, keyId }) =>
            opts.auditLog.append({ event: "api_key_revoked", pattern, keyId }),
        })
      : undefined;
  // Inbound sender reputation scoring (WR-119): validated once at
  // startup so bad config can never fail a request mid-flight. Opt-in:
  // unset means the tracker is never constructed and intake is
  // byte-identical.
  assertValidReputationOptions(opts.senderReputation);
  const reputation =
    opts.senderReputation !== undefined ? new SenderReputationTracker(opts.senderReputation) : undefined;
  // WR-119 tightening (c): degraded senders admit through a second,
  // doubled dedup window. Built only when dedup itself is configured —
  // otherwise there is no window to lengthen — and in-memory only (no
  // journal, no custom store): the tightening path must never share the
  // base window's durability state.
  const tightenedDeduplicator =
    reputation !== undefined && opts.dedup !== undefined
      ? new DeliveryDeduplicator({
          windowMs: (opts.dedup.windowMs ?? 300_000) * 2,
          maxEntries: opts.dedup.maxEntries,
          now: opts.dedup.now,
        })
      : undefined;
  // WR-119 tightening (a): the degraded-sender budget is half the
  // configured inbound budget (per-IP first, else per-endpoint). Unset
  // when no inbound rate limiter is configured — halving "no budget" is
  // meaningless, so the tightening is a documented no-op there.
  const tightenedBudgetPerSecond =
    reputation !== undefined && opts.rateLimit !== undefined
      ? (opts.rateLimit.perIpPerSecond ?? opts.rateLimit.perEndpointPerSecond) !== undefined
        ? ((opts.rateLimit.perIpPerSecond ?? opts.rateLimit.perEndpointPerSecond) as number) / 2
        : undefined
      : undefined;
  // Scoped operator API keys (WR-82): validated once at startup so a bad
  // scope, empty id/key, or duplicate id/key can never fail a request
  // mid-flight. WR-156 wraps the ring in OperatorKeyRing so a
  // compromised operator key can be revoked at runtime; every successful
  // revokeKey audits `operator_key_revoked` (key id only, never the key).
  const operatorKeyRing = new OperatorKeyRing(opts.operatorKeys ?? [], {
    onRevoked: ({ id }) => opts.auditLog.append({ event: "operator_key_revoked", keyId: id }),
  });
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
    const params = new URL(req.url ?? "/events", "http://internal").searchParams;
    const tenantFilter = params.get("tenant") ?? undefined;
    // WR-162: opt-in subscription filters — `?endpoint=` (exact match on
    // the event's `targetUrl`, same semantics as `GET /events/archive`)
    // and `?event=` (one of `delivered` / `retrying` / `dead_letter`; any
    // other value answers 400 `invalid event`, same as the archive).
    // All filters are ANDed and applied server-side before emit, so the
    // slow-consumer guard, heartbeat, and `unref` behavior below are
    // untouched.
    const endpointFilter = params.get("endpoint") ?? undefined;
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
    const eventFilter = (eventRaw ?? undefined) as DeliveryEventType | undefined;
    const matchesFilter = (event: DeliveryEvent): boolean =>
      (tenantFilter === undefined || event.tenant === tenantFilter) &&
      (endpointFilter === undefined || event.targetUrl === endpointFilter) &&
      (eventFilter === undefined || event.type === eventFilter);

    // WR-123: opt-in reconnect resume via the standard SSE `Last-Event-ID`
    // header. The cursor is the archiver-assigned monotonic `eventSeq`
    // (NOT `DeliveryEvent.id`, which is a per-delivery UUID shared by that
    // delivery's delivered/retrying/dead_letter events). Resume requires
    // the event archive (`eventArchive` option — the durable source of the
    // missed events) plus `events.sseReplay: true`. With either unset, a
    // `Last-Event-ID` header is ignored and the stream stays live-only,
    // exactly the pre-WR-123 behavior.
    const lastEventIdRaw = req.headers["last-event-id"];
    const lastEventId = Array.isArray(lastEventIdRaw) ? lastEventIdRaw[0] : lastEventIdRaw;
    let replayCursor: number | undefined;
    if (typeof lastEventId === "string" && lastEventId.length > 0) {
      if (opts.events?.sseReplay === true && eventArchiver !== undefined) {
        if (!/^\d+$/.test(lastEventId)) {
          respondJson(res, 400, { error: "invalid_last_event_id" });
          return;
        }
        const cursor = Number(lastEventId);
        const range = eventArchiver.seqRange();
        // 0 = "from the start of retained history". Any other cursor must
        // name a retained seq: older (retention-rotated), newer (never
        // produced), or an empty archive all mean continuity cannot be
        // established — 210 Gone tells the client to rebuild from
        // `GET /events/archive` instead of silently missing events.
        if (range.total === 0 || cursor > range.maxSeq || (cursor !== 0 && cursor < range.minSeq)) {
          respondJson(res, 210, {
            error: "events_gone",
            message:
              "Last-Event-ID is older than the retained archive, newer than anything produced, or the archive is empty; rebuild from GET /events/archive",
          });
          return;
        }
        replayCursor = cursor;
      }
    }

    let closed = false;
    // Assigned exactly once below, before any event can arrive.
    let unsubscribe: () => void = () => {};
    let heartbeat: ReturnType<typeof setInterval> | undefined;
    const cleanup = (): void => {
      if (closed) return;
      closed = true;
      if (heartbeat !== undefined) clearInterval(heartbeat);
      unsubscribe();
    };
    const writeFrame = (event: DeliveryEvent): void => {
      // The `id:` field is what SSE clients echo back as `Last-Event-ID`
      // on reconnect; it is absent without an archive (zero behavior
      // change there).
      const idField = event.eventSeq !== undefined ? `id: ${event.eventSeq}\n` : "";
      res.write(`${idField}event: delivery\ndata: ${JSON.stringify(event)}\n\n`);
    };
    // Slow-consumer guard: a dashboard that cannot keep up gets
    // disconnected instead of buffering without bound. Shared by the
    // live and replay paths.
    const guardSlowConsumer = (): boolean => {
      if (res.writableLength > 1_048_576) {
        cleanup();
        res.end();
        return true;
      }
      return false;
    };
    const openStream = (): void => {
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
      heartbeat = setInterval(() => {
        if (!closed) res.write(": ping\n\n");
      }, opts.events?.heartbeatMs ?? 15_000);
      // Never let an idle dashboard pin the process open.
      (heartbeat as unknown as { unref?: () => unknown }).unref?.();
    };

    if (replayCursor !== undefined && eventArchiver !== undefined) {
      // Reconnect resume. The live listener attaches FIRST, in buffering
      // mode: the archive query below races with newly emitted events, and
      // the archiver appends each event to the file before our listener
      // runs, so an event emitted mid-query is both in the file and in the
      // buffer — deduped below by seq, never lost, never doubled.
      const buffered: DeliveryEvent[] = [];
      let live = false;
      unsubscribe = queue.subscribeDeliveryEvents((event) => {
        if (closed || !matchesFilter(event)) return;
        if (!live) {
          buffered.push(event);
          return;
        }
        if (guardSlowConsumer()) return;
        writeFrame(event);
      });
      const replayed = eventArchiver.eventsAfter(replayCursor, SSE_REPLAY_MAX_EVENTS);
      if (replayed.truncated) {
        // The gap is larger than one reconnect may pull — replaying a
        // partial gap would silently drop the middle. 210 instead; the
        // client rebuilds from `GET /events/archive`.
        cleanup();
        respondJson(res, 210, {
          error: "events_gone",
          message: `gap exceeds the per-reconnect replay limit (${SSE_REPLAY_MAX_EVENTS} events); rebuild from GET /events/archive`,
        });
        return;
      }
      openStream();
      let lastReplayed = replayCursor;
      for (const event of replayed.events) {
        if (closed || !matchesFilter(event)) continue;
        if (guardSlowConsumer()) return;
        writeFrame(event);
        if (event.eventSeq !== undefined && event.eventSeq > lastReplayed) {
          lastReplayed = event.eventSeq;
        }
      }
      for (const event of buffered) {
        if (closed) break;
        // At-least-once, never a gap: an unstamped event (cannot happen
        // with an archive present, but fail-safe) is treated as newer.
        const seq = event.eventSeq ?? Number.MAX_SAFE_INTEGER;
        if (seq <= lastReplayed) continue;
        if (guardSlowConsumer()) return;
        writeFrame(event);
      }
      live = true;
    } else {
      openStream();
      unsubscribe = queue.subscribeDeliveryEvents((event) => {
        if (closed || !matchesFilter(event)) return;
        if (guardSlowConsumer()) return;
        writeFrame(event);
      });
    }
    req.on("close", cleanup);
    res.on("close", cleanup);
  };

  /** Operator surface: dead-letter queue + audit-log queries + live event stream. */
  /**
   * WR-135: read an optional JSON object body for the replay-approval
   * operator routes. Answers 413/400 itself and returns `undefined` on
   * failure — the caller returns right away.
   */
  const readOptionalJsonBody = async (
    req: Parameters<Parameters<typeof createServer>[0]>[0],
    res: Parameters<Parameters<typeof createServer>[0]>[1],
    maxBodyBytes: number
  ): Promise<Record<string, unknown> | undefined> => {
    let body: Record<string, unknown>;
    try {
      const raw = (await readRawBody(req, maxBodyBytes)).toString("utf8");
      body = raw.trim() === "" ? {} : JSON.parse(raw);
    } catch (err) {
      if (err instanceof BodyTooLargeError) {
        respondJson(res, 413, { error: "request body too large" });
      } else {
        respondJson(res, 400, { error: "invalid JSON body" });
      }
      return undefined;
    }
    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      respondJson(res, 400, { error: "body must be a JSON object" });
      return undefined;
    }
    return body;
  };

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
    // constant-time (see `src/operator-keys.ts`). WR-156: the ring skips
    // revoked keys, so a revoked operator key authenticates exactly like
    // a wrong key — 403 fail-closed, with no oracle distinguishing
    // "revoked" from "unknown".
    const operatorEnabled =
      (opts.operatorToken !== undefined && opts.operatorToken !== "") ||
      operatorKeyRing.size > 0;
    if (!operatorEnabled) {
      respondJson(res, 404, { error: "operator endpoints disabled" });
      return;
    }
    const identity = operatorKeyRing.match(
      bearerToken(req.headers["authorization"]),
      opts.operatorToken
    );
    if (identity === null) {
      respondJson(res, 403, { error: "forbidden" });
      return;
    }
    const operatorKeyId = identity.id;
    const isOpenApiJson = pathname === "/openapi.json";
    const isList = pathname === "/dead-letter";
    const isExport = pathname === "/dead-letter/export";
    const isStats = pathname === "/dead-letter/stats";
    const isBatchReplay = pathname === "/dead-letter/replay";
    // WR-135: one-shot approval token issuance for two-phase replays.
    const isApproveRequest = pathname === "/dead-letter/replay/approve-request";
    const isAudit = pathname === "/audit";
    const isAuditVerify = pathname === "/audit/verify";
    const isLatency = pathname === "/latency";
    // WR-127: one-shot per-endpoint maintenance windows.
    const isMaintenanceWindows = pathname === "/maintenance/windows";
    const isSloRisk = pathname === "/slo-risk";
    const isQuorum = pathname === "/quorum";
    const isQuorumStats = pathname === "/quorum/stats";
    const isUsage = pathname === "/usage";
    const isHealthSummary = pathname === "/health/summary";
    const isEvents = pathname === "/events";
    const isEventsArchive = pathname === "/events/archive";
    const isMetrics = pathname === "/metrics";
    const isAutoStatus = pathname === "/dead-letter/auto-replay/status";
    const isAutoPause = pathname === "/dead-letter/auto-replay/pause";
    const isAutoResume = pathname === "/dead-letter/auto-replay/resume";
    const isAutoTrigger = pathname === "/dead-letter/auto-replay/trigger";
    const isConfigEndpoint = pathname === "/config/endpoint";
    const isConfigSnapshot = pathname === "/config/snapshot";
    // WR-144: per-version sunset hot updates (GET = inspect, POST = set/clear).
    const isVersionSunset = pathname === "/config/version-sunset";
    const isRoutingRules = pathname === "/routing/rules";
    const isEndpointsPause = pathname === "/endpoints/pause";
    const isEndpointsResume = pathname === "/endpoints/resume";
    // WR-150: operator re-enable for an auto-disabled endpoint.
    const isEndpointsEnable = pathname === "/endpoints/enable";
    // WR-145: per-endpoint drill-mode toggle.
    const isEndpointsDryRun = pathname === "/endpoints/dry-run";
    // WR-114: dynamic endpoint registry. The negative lookahead keeps
    // `/endpoints/pause`, `/endpoints/resume`, and `/endpoints/enable`
    // on their exact routes (mirrors the registry pattern in
    // `src/operator-routes.ts`).
    const isEndpointsRegistry = pathname === "/endpoints";
    const endpointIdMatch = /^\/endpoints\/(?!pause$|resume$|enable$)(.+)$/.exec(pathname);
    const isScheduledList = pathname === "/scheduled";
    const scheduleActionMatch = /^\/scheduled\/([^/]+)\/(pause|resume)$/.exec(pathname);
    const deliveryMatch = /^\/deliveries\/([^/]+)$/.exec(pathname);
    const replayMatch = /^\/dead-letter\/([^/]+)\/replay$/.exec(pathname);
    // WR-111: route recognition is driven by the operator route
    // registry (`src/operator-routes.ts`) — the same registry
    // `GET /openapi.json` documents, so the 404 surface and the published
    // spec cannot drift apart.
    if (findOperatorRoute(pathname) === undefined) {
      respondJson(res, 404, { error: "not found" });
      return;
    }
    // WR-111: method allowance likewise comes from the registry.
    if (matchOperatorRoute(pathname, req.method ?? "") === undefined) {
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
    if (isOpenApiJson) {
      // WR-111: the operator API surface as an OpenAPI 3.1 document,
      // generated from the route registry that also drives the 404/405
      // dispatch above. Same operator authentication as every other
      // operator route (fail-closed 404 without a credential, 403 on a
      // bad bearer); read scope, like all GET operator routes.
      respondJson(res, 200, buildOpenApiDocument());
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
      const { endpoint, tenant, ids, dryRun, approvalToken, force } = body;
      if (endpoint !== undefined && typeof endpoint !== "string") {
        respondJson(res, 400, { error: "endpoint must be a string" });
        return;
      }
      if (tenant !== undefined && typeof tenant !== "string") {
        respondJson(res, 400, { error: "tenant must be a string" });
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
      if (approvalToken !== undefined && typeof approvalToken !== "string") {
        respondJson(res, 400, { error: "approvalToken must be a string" });
        return;
      }
      if (force !== undefined && typeof force !== "boolean") {
        respondJson(res, 400, { error: "force must be a boolean" });
        return;
      }
      const filter = {
        ...(endpoint !== undefined ? { endpoint } : {}),
        // WR-86: tenant-scoped replay — only this tenant's dead letters
        // are re-queued; the default tenant's entries stay untouched.
        ...(tenant !== undefined ? { tenant } : {}),
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
      // WR-135: two-phase replay approval (opt-in). A replay re-fires the
      // downstream handler, so with approval enabled the execution side
      // consumes a one-shot token issued by
      // `POST /dead-letter/replay/approve-request` — missing, expired,
      // reused, or scope-mismatched tokens all answer 403. The token
      // rides `approvalToken` or the `x-replay-approval-token` header and
      // is never written to the audit log (bearer material). Dry runs
      // never need approval — they returned above.
      const headerToken = req.headers["x-replay-approval-token"];
      const batchApprovalToken =
        approvalToken ?? (typeof headerToken === "string" ? headerToken : undefined);
      let result: { replayed: string[]; failed: { id: string; error: string }[]; throttled: string[]; skipped: string[] };
      try {
        result = queue.replayDeadLetters(filter, { approvalToken: batchApprovalToken, force });
      } catch (err) {
        if (err instanceof ReplayApprovalError) {
          if (err.reason === "expired") {
            opts.auditLog.append({
              event: "replay_approval_expired",
              keyId: operatorKeyId,
              reason: "approval_token_expired",
              ...(endpoint !== undefined ? { endpoint } : {}),
              ...(tenant !== undefined ? { tenant } : {}),
            });
          }
          respondJson(res, 403, { error: approvalDenyMessage(err.reason) });
          return;
        }
        throw err;
      }
      opts.auditLog.append({
        event: "dead_letter_batch_replayed",
        keyId: operatorKeyId,
        replayed: result.replayed,
        failed: result.failed,
        skipped: result.skipped,
        ...(endpoint !== undefined ? { endpoint } : {}),
        ...(tenant !== undefined ? { tenant } : {}),
      });
      // WR-135: the token that paid for this execution. Only audited when
      // the gate is on — without approval there is no token to report.
      if (queue.getReplayApprovalStore() !== undefined) {
        opts.auditLog.append({
          event: "replay_approved",
          keyId: operatorKeyId,
          replayed: result.replayed,
          ...(endpoint !== undefined ? { endpoint } : {}),
          ...(tenant !== undefined ? { tenant } : {}),
        });
      }
      respondJson(res, 200, { replayed: result.replayed, failed: result.failed, skipped: result.skipped });
      return;
    }
    if (isApproveRequest) {
      // WR-135: issue a one-shot replay approval token scoped to the
      // requested filter. 404 when two-phase approval is not configured —
      // there is no token ledger to issue from.
      if (queue.getReplayApprovalStore() === undefined) {
        respondJson(res, 404, { error: "replay approval is not configured" });
        return;
      }
      const approveBody = await readOptionalJsonBody(req, res, maxBodyBytes);
      if (approveBody === undefined) return;
      const { endpoint, tenant, ids } = approveBody;
      if (endpoint !== undefined && typeof endpoint !== "string") {
        respondJson(res, 400, { error: "endpoint must be a string" });
        return;
      }
      if (tenant !== undefined && typeof tenant !== "string") {
        respondJson(res, 400, { error: "tenant must be a string" });
        return;
      }
      if (
        ids !== undefined &&
        (!Array.isArray(ids) || ids.some((i) => typeof i !== "string"))
      ) {
        respondJson(res, 400, { error: "ids must be an array of strings" });
        return;
      }
      const issued = queue.issueReplayApprovalToken({
        ...(endpoint !== undefined ? { endpoint } : {}),
        ...(tenant !== undefined ? { tenant } : {}),
        ...(ids !== undefined ? { ids: ids as string[] } : {}),
      });
      // The store existed (checked above); this is only unreachable when a
      // concurrent reconfiguration removed it mid-request.
      if (issued === undefined) {
        respondJson(res, 404, { error: "replay approval is not configured" });
        return;
      }
      respondJson(res, 200, {
        approvalToken: issued.approvalToken,
        expiresAt: issued.expiresAt,
      });
      return;
    }
    if (isMetrics) {
      // Prometheus scrapes this; it sits behind the same bearer token as
      // the other operator endpoints (fail closed without operatorToken).
      // The version-routing counters render "" when versioning was never
      // configured, keeping the output byte-identical to the legacy shape.
      // WR-105: the WebSocket pool renders "" until the first ws:/wss:
      // delivery runs, so a relay that never touches WebSocket sees no
      // new series. Absent entirely with a custom sender (no pool).
      res
        .writeHead(200, { "content-type": "text/plain; version=0.0.4" })
        .end(queue.renderMetrics() + versionMetrics.render() + schemaMetrics.render() + (schemaRegistry?.renderMetrics() ?? "") + ipAclMetrics.render() + inboundTenantRateLimitMetrics.render() + certExpiryMonitor.render() + tlsVersionMonitor.render() + (ocspMonitor?.render() ?? "") + (usageMeter?.render() ?? "") + (defaultSender?.compressionStats.render() ?? "") + (defaultSender?.dnsCache?.render() ?? "") + (defaultSender?.wsPool.renderMetrics() ?? "") + meshMetrics.render() + (defaultSender?.outboundSchemaMetrics?.render() ?? "") + (defaultSender?.chaosMetrics?.render() ?? "") + (reputation?.renderMetrics() ?? "") + hedgeMetrics.render() + (queue.getErrorBudgetMonitor()?.render() ?? ""));
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
    if (isMaintenanceWindows) {
      // WR-127: `GET` lists the live one-shot maintenance windows per
      // endpoint (read scope); `POST` adds one window (admin scope).
      if (req.method === "GET") {
        respondJson(res, 200, queue.getMaintenanceWindows());
        return;
      }
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
      const { endpoint, start, end } = body;
      if (typeof endpoint !== "string" || endpoint.length === 0) {
        respondJson(res, 400, { error: "endpoint must be a non-empty string" });
        return;
      }
      if (typeof start !== "string" || typeof end !== "string") {
        respondJson(res, 400, { error: "start and end must be RFC3339 strings" });
        return;
      }
      let added: { start: string; end: string; startMs: number; endMs: number } | null;
      try {
        added = queue.addMaintenanceWindow(endpoint, start, end);
      } catch (err) {
        if (err instanceof RangeError) {
          respondJson(res, 400, { error: (err as Error).message });
          return;
        }
        throw err;
      }
      if (added === null) {
        respondJson(res, 404, { error: "maintenance windows are not enabled" });
        return;
      }
      respondJson(res, 200, { ok: true, window: added });
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
    if (isQuorum) {
      // WR-106: per-fanout acknowledgement progress (`fanoutId`,
      // `endpoint`, `targets`, `acked`, `status`, lost targets), in
      // dispatch order. Same operator-token guard as the other operator
      // endpoints (fail-closed without operatorToken).
      respondJson(res, 200, queue.getQuorumStats());
      return;
    }
    if (isQuorumStats) {
      // WR-109: object-shaped quorum companion to the array-shaped
      // `GET /quorum` (whose array response is pinned by clients and
      // tests, so it cannot grow a top-level `evicted` field): the same
      // per-fanout progress plus the cumulative retention-eviction
      // count. Same operator-token guard (fail-closed without
      // operatorToken).
      respondJson(res, 200, { fanouts: queue.getQuorumStats(), evicted: queue.getQuorumEvictedCount() });
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
    if (isHealthSummary) {
      // WR-87: operator health dashboard — one human-readable aggregate
      // over the relay's health signals (per-endpoint circuit state and
      // consecutive-failure streaks, quota exhaustion, downstream probe
      // state, the global retry-budget headroom, and the top-N tenants by
      // delivery volume). Same operator-token guard as the other operator
      // endpoints (404 when no operatorToken — fail closed). Pure read
      // aggregation with zero write impact; the usage meter is optional —
      // its rows are empty when unconfigured rather than failing the
      // whole endpoint.
      respondJson(
        res,
        200,
        buildHealthSummary({
          circuits: queue.getCircuitStats(),
          quotas: queue.getQuotaStats(),
          probes: queue.getProbeStats(),
          // WR-153: per-endpoint current queue depth (absent when
          // nothing is queued) — read-only observation for operators.
          queueDepth: queue.getQueueDepthStats(),
          retryBudget: queue.getRetryBudgetStats(),
          usage: usageMeter?.snapshot(),
          // WR-136: surface the adaptive inbound throttle state (absent
          // when the adaptive limiter is unconfigured). Only the
          // operator-token-guarded health summary grows — no new
          // operator route.
          inboundRateLimit: (() => {
            const s = rateLimiter?.adaptiveStats();
            return s !== undefined && s.enabled
              ? {
                  throttled: s.throttled,
                  effectivePerEndpointPerSecond: s.effectivePerEndpointPerSecond!,
                  pendingDepth: s.pendingDepth!,
                }
              : undefined;
          })(),
        })
      );
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
    if (isExport) {
      // WR-128: dead-letter export — filtered (endpoint/tenant/since/
      // until) streaming download as JSONL or CSV. Sealed payloads
      // (WR-11) are transparently decrypted through the queue; per-row
      // payloads are truncated past 64 KiB so one giant payload cannot
      // blow the export's memory. A filter matching more than
      // DEAD_LETTER_EXPORT_ROW_LIMIT rows, requested without a `cursor`,
      // answers 409 and asks the operator to page — the export never
      // silently truncates.
      const params = new URL(req.url ?? "/dead-letter/export", "http://internal").searchParams;
      const param = (name: string): string | undefined => {
        const v = params.get(name);
        return v === null ? undefined : v;
      };
      const formatRaw = param("format") ?? "jsonl";
      if (formatRaw !== "jsonl" && formatRaw !== "csv") {
        respondJson(res, 400, { error: 'format must be "jsonl" or "csv"' });
        return;
      }
      const format = formatRaw as DeadLetterExportFormat;
      let filter: DeadLetterExportFilter;
      try {
        const endpoint = param("endpoint");
        const tenant = param("tenant");
        filter = {
          ...(endpoint !== undefined ? { endpoint } : {}),
          ...(tenant !== undefined ? { tenant } : {}),
          since: parseDeadLetterExportTime(param("since"), "since"),
          until: parseDeadLetterExportTime(param("until"), "until"),
        };
      } catch (err) {
        respondJson(res, 400, { error: (err as Error).message });
        return;
      }
      let plan: DeadLetterExportPlan;
      try {
        plan = planDeadLetterExport(
          {
            entries: () => queue.getDeadLetter(),
            decrypt: (e) => queue.decryptDeadLetterPayload(e),
          },
          filter,
          { format, cursor: param("cursor") }
        );
      } catch (err) {
        if (err instanceof InvalidExportCursorError) {
          respondJson(res, 400, { error: err.message });
          return;
        }
        throw err;
      }
      if (plan.needsPaging) {
        respondJson(res, 409, {
          error: "export_exceeds_row_limit",
          matched: plan.totalMatched,
          limit: DEAD_LETTER_EXPORT_ROW_LIMIT,
          hint: "re-request with ?cursor=<firstCursor> to page through the export; each page holds at most 10000 rows in dead-letter order",
          firstCursor: plan.firstCursor,
        });
        return;
      }
      const writeChunk = async (chunk: string): Promise<boolean> => {
        if (res.destroyed || res.writableEnded) return false;
        if (res.write(chunk)) return true;
        // Backpressure: wait for drain, but never hang on a client that
        // went away mid-export.
        return await new Promise<boolean>((resolve) => {
          const onDrain = (): void => {
            cleanup();
            resolve(true);
          };
          const onClose = (): void => {
            cleanup();
            resolve(false);
          };
          const cleanup = (): void => {
            res.off("drain", onDrain);
            res.off("close", onClose);
          };
          res.once("drain", onDrain);
          res.once("close", onClose);
        });
      };
      res.writeHead(200, {
        "content-type": format === "csv" ? "text/csv; charset=utf-8" : "application/x-ndjson",
        "x-export-has-more": plan.hasMore ? "true" : "false",
        ...(plan.nextCursor !== undefined ? { "x-export-next-cursor": plan.nextCursor } : {}),
      });
      let rows = 0;
      let chunk = renderDeadLetterExportHeader(format);
      for (const entry of plan.entries) {
        const row = buildDeadLetterExportRow(
          entry,
          (e) => queue.decryptDeadLetterPayload(e),
          plan.maxPayloadBytes
        );
        rows += 1;
        chunk += renderDeadLetterExportRow(row, format);
        // Stream in bounded chunks: a 10k-row page of 64 KiB-truncated
        // payloads must never sit on the heap as one giant string.
        if (rows % 128 === 0) {
          if (!(await writeChunk(chunk))) break;
          chunk = "";
        }
      }
      if (chunk !== "" && !res.destroyed && !res.writableEnded) {
        await writeChunk(chunk);
      }
      if (!res.destroyed && !res.writableEnded) res.end();
      // Audited on completion with the row count actually streamed, the
      // filter, the format, and the operator key id — never the payloads.
      opts.auditLog.append({
        event: "dead_letter_exported",
        keyId: operatorKeyId,
        rows,
        format,
        hasMore: plan.hasMore,
        ...(filter.endpoint !== undefined ? { endpoint: filter.endpoint } : {}),
        ...(filter.tenant !== undefined ? { tenant: filter.tenant } : {}),
        ...(filter.since !== undefined ? { since: filter.since } : {}),
        ...(filter.until !== undefined ? { until: filter.until } : {}),
        ...(plan.nextCursor !== undefined ? { nextCursor: plan.nextCursor } : {}),
      });
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
    if (isVersionSunset) {
      // WR-144: per-version sunset hot updates (the WR-32 convention).
      // `GET` inspects every route's effective sunset (read scope);
      // `POST` sets or clears one version's sunset (admin scope, body
      // `{ prefix, sunsetAt }` where `sunsetAt` is epoch-ms, an
      // ISO-8601 string, or `null` to clear). The change takes effect
      // on the next intake — no restart — and is audited as
      // `version_sunset_updated` with the operator's `keyId`. A
      // RangeError from the router (unknown prefix, invalid moment)
      // surfaces as a 400 and means "nothing changed".
      if (versionRouter === undefined) {
        respondJson(res, 404, { error: "API versioning is not configured" });
        return;
      }
      if (req.method === "GET") {
        respondJson(res, 200, {
          sunsets: versionRouter.sunsetEntries().map((e) => ({
            prefix: e.prefix,
            version: e.version,
            sunsetAt: e.sunsetAt === null ? null : new Date(e.sunsetAt).toISOString(),
            source: e.source,
          })),
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
      const { prefix, sunsetAt } = body;
      if (typeof prefix !== "string" || prefix.length === 0) {
        respondJson(res, 400, { error: "prefix must be a non-empty string" });
        return;
      }
      if (sunsetAt === undefined) {
        respondJson(res, 400, { error: "sunsetAt is required (epoch-ms, ISO-8601 string, or null to clear)" });
        return;
      }
      try {
        // `null` clears the sunset entirely (explicit "never sunset"),
        // valid moments set it; the override wins over any configured
        // `sunsetAt` on the route.
        versionRouter.setSunset(prefix, sunsetAt as number | string | null);
        const effective = versionRouter.effectiveSunset(prefix);
        const route = versionRouter.sunsetEntries().find((e) => e.prefix === prefix);
        opts.auditLog.append({
          event: "version_sunset_updated",
          prefix,
          version: route?.version,
          sunsetAt: effective === undefined ? null : new Date(effective).toISOString(),
          ...(operatorKeyId !== undefined ? { keyId: operatorKeyId } : {}),
        });
        respondJson(res, 200, {
          prefix,
          version: route?.version,
          sunsetAt: effective === undefined ? null : new Date(effective).toISOString(),
        });
      } catch (err) {
        if (err instanceof RangeError) {
          respondJson(res, 400, { error: err.message });
          return;
        }
        throw err;
      }
      return;
    }
    if (isConfigSnapshot) {
      // Declarative config snapshots (WR-88). `GET` exports the current
      // declarative config (`{ snapshot }`, read scope); `POST` applies a
      // snapshot (`{ snapshot, dryRun? }`, admin scope) through the WR-32
      // imperative setter, item by item, rolling back to the pre-apply
      // state on any mid-apply failure. `dryRun: true` returns the plan
      // without mutating anything. Secret-bearing inventory (signing
      // keys, mTLS identities, proxies) refuses the whole apply
      // fail-closed when it diverged; snapshots carry identifiers only,
      // never key bytes. The body limit applies here too. Applied and
      // rolled-back applies are audited as `config_applied` /
      // `config_rolled_back` with the operator's `keyId`.
      if (req.method === "GET") {
        respondJson(res, 200, {
          snapshot: exportConfig(queue, { readInventory: readConfigInventory }),
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
      if (body.snapshot === undefined) {
        respondJson(res, 400, { error: "body.snapshot is required" });
        return;
      }
      if (body.dryRun !== undefined && typeof body.dryRun !== "boolean") {
        respondJson(res, 400, { error: "body.dryRun must be a boolean" });
        return;
      }
      try {
        // WR-82: run as this operator so the `config_applied` /
        // `config_rolled_back` audit events carry the right `keyId`.
        const result = runAsOperator(operatorKeyId, () =>
          applyConfig(queue, body.snapshot, {
            dryRun: body.dryRun === true,
            readInventory: readConfigInventory,
            // WR-156: revocation diffs (`inventory.revokedApiKeys` /
            // `inventory.revokedOperatorKeys`) apply through these hooks —
            // the hot-reload path for key revocation. A missing ring
            // refuses the apply (`unsupported`); revocation is one-way and
            // is never rolled back, even on a later endpoint-item failure.
            revokeApiKey: (pattern, keyId) => apiKeyAuth?.revokeKey(pattern, keyId) ?? false,
            revokeOperatorKey: (id) => operatorKeyRing.revokeKey(id),
            audit: (event) =>
              opts.auditLog.append({
                ...event,
                ...(activeOperatorKeyId !== undefined ? { keyId: activeOperatorKeyId } : {}),
              }),
          })
        );
        respondJson(res, 200, result);
      } catch (err) {
        if (err instanceof ConfigApplyError) {
          const status = err.kind === "apply_failed" ? 500 : 400;
          respondJson(res, status, {
            error: err.message,
            kind: err.kind,
            ...(err.items.length > 0 ? { items: err.items } : {}),
            ...(err.applied.length > 0 ? { applied: err.applied } : {}),
            ...(err.rolledBack.length > 0 ? { rolledBack: err.rolledBack } : {}),
          });
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
    if (isEndpointsEnable) {
      // WR-150: operator re-enable for an auto-disabled endpoint. Body
      // is `{ endpoint }`. Re-enabling clears the disable gate and
      // resets the endpoint's failure streak — queued deliveries dispatch
      // normally again and the next failure starts a new streak. It does
      // not touch the pause set (orthogonal states). Transitions are
      // audited as `endpoint_enabled` by the queue hook. Unknown
      // endpoints are a fail-closed 404, like pause/resume. Enabling a
      // non-disabled endpoint is a no-op 200 (idempotent).
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
      const wasDisabled = queue.isEndpointDisabled(endpoint);
      runAsOperator(operatorKeyId, () => queue.enableEndpoint(endpoint));
      respondJson(res, 200, { endpoint, disabled: false, wasDisabled });
      return;
    }
    if (isEndpointsDryRun) {
      // WR-145: per-endpoint drill-mode toggle (operator, admin scope).
      // Body `{ endpoint, enabled, canned? }`: `enabled: true` installs
      // (or replaces) the drill config, `false` removes it. Unlike
      // pause/resume, any endpoint string is accepted — a drill config
      // applies the first time a delivery to it dispatches. Audited as
      // `endpoint_dry_run_enabled` / `endpoint_dry_run_disabled` with
      // the operator's `keyId`. A RangeError from `setEndpointDryRun`
      // (illegal canned response) surfaces as a 400 and means
      // "nothing changed".
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
      const { endpoint, enabled, canned } = body;
      if (typeof endpoint !== "string" || endpoint.length === 0) {
        respondJson(res, 400, { error: "endpoint must be a non-empty string" });
        return;
      }
      if (typeof enabled !== "boolean") {
        respondJson(res, 400, { error: "enabled must be a boolean" });
        return;
      }
      try {
        const applied = queue.setEndpointDryRun(
          endpoint,
          enabled
            ? { enabled: true, canned: canned as EndpointDryRunConfig["canned"] }
            : undefined
        );
        opts.auditLog.append({
          event: enabled ? "endpoint_dry_run_enabled" : "endpoint_dry_run_disabled",
          endpoint,
          // The canned body is operator test data — the audit carries
          // only the classification-relevant fields, never the body.
          ...(applied !== undefined
            ? { canned: { status: applied.canned.status, delayMs: applied.canned.delayMs } }
            : {}),
          ...(operatorKeyId !== undefined ? { keyId: operatorKeyId } : {}),
        });
        respondJson(res, 200, {
          endpoint,
          dryRun: enabled,
          ...(applied !== undefined ? { canned: applied.canned } : {}),
        });
      } catch (err) {
        if (err instanceof RangeError) {
          respondJson(res, 400, { error: err.message });
          return;
        }
        throw err;
      }
      return;
    }
    if (isEndpointsRegistry || endpointIdMatch !== null) {
      // WR-114: dynamic endpoint registry CRUD. The registry itself
      // validates every write before mutating (a 400 always means
      // "nothing changed"); deliver-policy fields
      // (`maxConcurrentPerEndpoint`, `circuitBreaker`, `quota`) then
      // apply through `queue.updateEndpointConfig`, which carries the
      // WR-32 hot-reload semantics — in-flight deliveries keep the
      // config they started with, only future scheduling decisions see
      // the new values — and audits its own `endpoint_config_updated`
      // with the field-level diff. The registry-level audit below adds
      // the operation (`created`/`updated`/`deleted`) and the full
      // old/new config summary (secrets redacted). Sender-side fields
      // (`verifier`, `proxy`, `tlsPins`) resolve per delivery attempt in
      // the default sender, so the same in-flight rule holds for them.
      // `ordered` is startup-only: the operator API rejects runtime
      // changes to it (400) because the queue builds its
      // ordered-delivery tracker once at construction.
      const readRegistryBody = async (): Promise<
        { body: Record<string, unknown> } | { responded: true }
      > => {
        let raw: string;
        try {
          raw = (await readRawBody(req, maxBodyBytes)).toString("utf8");
        } catch (err) {
          if (err instanceof BodyTooLargeError) {
            respondJson(res, 413, { error: "request body too large" });
          } else {
            respondJson(res, 400, { error: "invalid JSON body" });
          }
          return { responded: true };
        }
        if (raw.trim() === "") return { body: {} };
        let parsed: unknown;
        try {
          parsed = JSON.parse(raw);
        } catch {
          respondJson(res, 400, { error: "invalid JSON body" });
          return { responded: true };
        }
        if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
          respondJson(res, 400, { error: "body must be a JSON object" });
          return { responded: true };
        }
        return { body: parsed as Record<string, unknown> };
      };
      const auditRegistryChange = (
        operation: "created" | "updated" | "deleted",
        oldRecord: EndpointRecord | null,
        newRecord: EndpointRecord | null
      ): void => {
        const record = (newRecord ?? oldRecord)!;
        opts.auditLog.append({
          event: "endpoint_config_updated",
          endpoint: record.targetUrl,
          endpointId: record.id,
          operation,
          keyId: operatorKeyId,
          changes: diffEndpointConfigs(oldRecord, newRecord),
        });
      };
      // WR-82: the queue's `onConfigChange` hook fires synchronously
      // inside `updateEndpointConfig`, so running it as this operator
      // stamps the queue-level `endpoint_config_updated` audit with the
      // right `keyId`.
      const applyDeliverPolicy = (targetUrl: string, config: EndpointConfig): void => {
        if (hasDeliverPolicy(config)) {
          runAsOperator(operatorKeyId, () =>
            queue.updateEndpointConfig(targetUrl, deliverPolicyPatch(config))
          );
        }
      };
      const clearDeliverPolicy = (targetUrl: string, config: EndpointConfig): void => {
        if (config.maxConcurrentPerEndpoint !== undefined) {
          queue.clearEndpointConfigOverride(undefined, targetUrl, "maxConcurrentPerEndpoint");
        }
        if (config.circuitBreaker !== undefined) {
          queue.clearEndpointConfigOverride(undefined, targetUrl, "circuitBreaker");
        }
        if (config.quota !== undefined) {
          queue.clearEndpointConfigOverride(undefined, targetUrl, "quota");
        }
      };
      if (req.method === "GET") {
        // GET /endpoints — registry metadata only. Secrets never leave
        // the registry (a verifier renders as `{ keyId }`).
        respondJson(res, 200, { endpoints: endpointRegistry.list() });
        return;
      }
      if (req.method === "POST") {
        // POST /endpoints — register a new endpoint.
        const parsed = await readRegistryBody();
        if ("responded" in parsed) return;
        let record: EndpointRecord;
        try {
          record = endpointRegistry.create(parsed.body as EndpointConfig);
        } catch (err) {
          if (err instanceof RangeError) {
            respondJson(res, 400, { error: (err as Error).message });
            return;
          }
          throw err;
        }
        try {
          applyDeliverPolicy(record.targetUrl, record);
        } catch (err) {
          // The queue refused the policy (e.g. a disabled subsystem):
          // roll the registry record back so the 400 means "nothing
          // changed" end to end.
          endpointRegistry.remove(record.id);
          if (err instanceof RangeError) {
            respondJson(res, 400, { error: (err as Error).message });
            return;
          }
          throw err;
        }
        auditRegistryChange("created", null, record);
        respondJson(res, 201, {
          id: record.id,
          targetUrl: record.targetUrl,
          endpoint: summarizeEndpointConfig(record),
        });
        return;
      }
      // PUT / DELETE /endpoints/{id}. The 405 dispatch above guarantees
      // only those two methods reach this branch with an id.
      const registryId = decodeURIComponent(endpointIdMatch![1]);
      if (req.method === "PUT") {
        const existing = endpointRegistry.get(registryId);
        if (existing === undefined) {
          respondJson(res, 404, { error: "unknown endpoint" });
          return;
        }
        const parsed = await readRegistryBody();
        if ("responded" in parsed) return;
        if (parsed.body.ordered !== undefined) {
          respondJson(res, 400, {
            error: "`ordered` cannot be changed at runtime; configure it via the static `endpoints` option",
          });
          return;
        }
        let updated: { old: EndpointRecord; new: EndpointRecord };
        try {
          updated = endpointRegistry.update(registryId, parsed.body as Partial<EndpointConfig>);
        } catch (err) {
          if (err instanceof RangeError) {
            respondJson(res, 400, { error: (err as Error).message });
            return;
          }
          throw err;
        }
        const targetMoved = updated.new.targetUrl !== updated.old.targetUrl;
        try {
          // A targetUrl change re-keys the deliver-policy overrides:
          // drop the old endpoint's overrides before applying the new
          // ones. `updateEndpointConfig` is atomic per call, so a
          // failure here applied nothing to the queue.
          if (targetMoved) clearDeliverPolicy(updated.old.targetUrl, updated.old);
          applyDeliverPolicy(updated.new.targetUrl, updated.new);
        } catch (err) {
          // Roll back: restore the registry record, then the old
          // endpoint's policy (its values applied cleanly before, so
          // this cannot fail on validation).
          endpointRegistry.update(registryId, { ...updated.old });
          if (targetMoved) applyDeliverPolicy(updated.old.targetUrl, updated.old);
          if (err instanceof RangeError) {
            respondJson(res, 400, { error: (err as Error).message });
            return;
          }
          throw err;
        }
        auditRegistryChange("updated", updated.old, updated.new);
        respondJson(res, 200, {
          id: updated.new.id,
          targetUrl: updated.new.targetUrl,
          endpoint: summarizeEndpointConfig(updated.new),
          changes: diffEndpointConfigs(updated.old, updated.new),
        });
        return;
      }
      if (req.method === "DELETE") {
        const record = endpointRegistry.get(registryId);
        if (record === undefined) {
          respondJson(res, 404, { error: "unknown endpoint" });
          return;
        }
        const params = new URL(req.url ?? "/endpoints", "http://internal").searchParams;
        const parsed = await readRegistryBody();
        if ("responded" in parsed) return;
        const force =
          params.get("force") === "true" || parsed.body.force === true;
        // `drained` reports whether a drain actually ran and completed:
        // with `force` the drain is skipped, so it stays false.
        let drained = false;
        let waitedMs = 0;
        if (!force) {
          // Drain first: wait until the endpoint has no in-flight or
          // slot-queued deliveries, so no delivery outlives the config
          // it started with into retries resolved against a removed
          // record. Bounded — a stuck downstream answers 409 with the
          // remaining count instead of hanging the operator call.
          const drain = await waitForEndpointDrain(
            () => queue.getConcurrencyStats(),
            record.targetUrl,
            opts.endpointDrainTimeoutMs !== undefined
              ? { timeoutMs: opts.endpointDrainTimeoutMs }
              : {}
          );
          drained = drain.drained;
          waitedMs = drain.waitedMs;
          if (!drained) {
            respondJson(res, 409, {
              error: `endpoint has ${drain.remaining} in-flight deliveries; retry later or delete with ?force=true`,
              inFlight: drain.remaining,
            });
            return;
          }
        }
        endpointRegistry.remove(registryId);
        clearDeliverPolicy(record.targetUrl, record);
        auditRegistryChange("deleted", record, null);
        respondJson(res, 200, {
          id: registryId,
          deleted: true,
          drained,
          ...(force ? {} : { waitedMs }),
        });
        return;
      }
      respondJson(res, 405, { error: "method not allowed" });
      return;
    }
    const id = decodeURIComponent(replayMatch![1]);
    // WR-135: the single replay honors the two-phase gate when enabled —
    // same 403 semantics as the batch endpoint. The approval token may
    // ride the (optional) JSON body or the `x-replay-approval-token`
    // header. WR-149: the body also carries `force` (override the
    // replay-idempotency guard); the optional body is always read when
    // present, so `force` works with or without approval enabled — a
    // bodyless request behaves exactly like the legacy path.
    let singleApprovalToken: string | undefined;
    let singleForce: boolean | undefined;
    const singleBody = await readOptionalJsonBody(req, res, maxBodyBytes);
    if (singleBody === undefined) return;
    if (queue.getReplayApprovalStore() !== undefined) {
      const bodyToken = singleBody.approvalToken;
      if (bodyToken !== undefined && typeof bodyToken !== "string") {
        respondJson(res, 400, { error: "approvalToken must be a string" });
        return;
      }
      const headerToken = req.headers["x-replay-approval-token"];
      singleApprovalToken =
        bodyToken ?? (typeof headerToken === "string" ? headerToken : undefined);
    }
    const bodyForce = singleBody.force;
    if (bodyForce !== undefined && typeof bodyForce !== "boolean") {
      respondJson(res, 400, { error: "force must be a boolean" });
      return;
    }
    singleForce = bodyForce;
    // WR-149: a `false` return is ambiguous — the id may be unknown, or
    // the replay-idempotency guard may have suppressed the replay. Check
    // liveness first so the response can tell the two apart.
    const knownBefore = queue.getDeadLetter().some((e) => e.id === id);
    let singleReplayed: boolean;
    try {
      singleReplayed = queue.replayDeadLetter(id, { approvalToken: singleApprovalToken, force: singleForce });
    } catch (err) {
      if (err instanceof ReplayApprovalError) {
        if (err.reason === "expired") {
          opts.auditLog.append({
            event: "replay_approval_expired",
            keyId: operatorKeyId,
            id,
            reason: "approval_token_expired",
          });
        }
        respondJson(res, 403, { error: approvalDenyMessage(err.reason) });
        return;
      }
      throw err;
    }
    if (singleReplayed) {
      opts.auditLog.append({ event: "dead_letter_replayed", keyId: operatorKeyId, id });
      // WR-135: the token that paid for this execution — only when the
      // gate is on; without approval there is no token to report.
      if (queue.getReplayApprovalStore() !== undefined) {
        opts.auditLog.append({ event: "replay_approved", keyId: operatorKeyId, id });
      }
      respondJson(res, 200, { id, replayed: true });
    } else if (knownBefore) {
      // WR-149: the id exists but the replay-idempotency guard suppressed
      // the replay — the downstream already holds a newer copy of the
      // same (endpoint, payload). 200, not 404: the request was processed
      // and the replay was intentionally skipped; the audit log carries
      // the `replay_skipped_delivered` event.
      respondJson(res, 200, { id, replayed: false, skipped: true, reason: "replay_suppressed_delivered" });
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
     * WR-102: the body budget that actually governed this request's
     * intake — the matching `endpointBodyLimits` rule's budget, or the
     * global `maxBodyBytes` when no rule matched. Travels with the body
     * so `admitOneEvent` can apply the same budget to the WR-40 gzip
     * decompression cap.
     */
    maxBodyBytes: number;
    /**
     * The matched API key id and the guarding rule. The rule travels
     * with it so the admission pipeline knows whether the signature
     * check still applies (`requireSignature`) and which `keyId` to
     * audit. Absent when no API-key rule matched this endpoint.
     */
    apiKey?: { keyId: string; rule: EndpointApiKeyRule };
  }

  /**
   * WR-119: audit one reputation threshold crossing. `extra` carries the
   * request correlation (id, traceId, ...); the event itself carries only
   * the sender key id and the score — never a secret. A no-op when
   * `transition` is undefined (no crossing) or the feature is off.
   */
  const auditReputationTransition = (
    transition: ReputationTransition | undefined,
    extra: Record<string, unknown>
  ): void => {
    if (reputation === undefined || transition === undefined) return;
    opts.auditLog.append({
      ...extra,
      event: transition.kind === "downgraded" ? "reputation_downgraded" : "reputation_upgraded",
      keyId: transition.key,
      // Two decimals: the float tail carries no more signal than that.
      score: Math.round(transition.score * 100) / 100,
      at: transition.at,
    });
  };

  /**
   * WR-119: record one reputation penalty event for the intake sender
   * and audit the threshold crossing when one happened. A no-op when
   * the feature is off.
   */
  const recordReputationPenalty = (
    key: string,
    kind: ReputationPenaltyKind,
    extra: Record<string, unknown>
  ): void => {
    if (reputation === undefined) return;
    auditReputationTransition(reputation.recordPenalty(key, kind), extra);
  };

  /**
   * WR-22 base inbound rate-limit check, shared by the HTTP intake gates
   * and the WR-130 WebSocket intake: per-sender-IP + per-endpoint token
   * buckets, checked before signature verification so a flood costs
   * almost nothing. Audits the rejection and records the WR-119
   * reputation penalty; the caller renders the transport-specific
   * rejection (HTTP 429 vs. a WS `event-ack`). A no-op when no limiter
   * is configured.
   */
  const checkInboundRateLimit = (
    ip: string,
    senderKey: string,
    id: string,
    traceId: string
  ): { ok: true } | { ok: false; retryAfterMs: number; dimension: string } => {
    if (rateLimiter === undefined) return { ok: true };
    const verdict = rateLimiter.take(ip, opts.forwardUrl);
    if (verdict.ok) return { ok: true };
    // WR-119: a rate-limit hit is a reputation penalty event.
    recordReputationPenalty(senderKey, "rate_limit", { id, traceId });
    opts.auditLog.append({
      event: "rejected",
      id,
      traceId,
      reason: "rate_limited",
      dimension: verdict.dimension,
      retryAfterMs: verdict.retryAfterMs,
    });
    return { ok: false, retryAfterMs: verdict.retryAfterMs, dimension: verdict.dimension };
  };

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

    // Inbound GeoIP country policy (WR-158): the coarse geography filter
    // layered *after* the WR-53 IP ACL and before the body is read — the
    // same header-only admission tier. Ordering rationale: the WR-53 gate
    // is the more specific, explicitly configured per-endpoint rule (an
    // operator's allow/deny list), so it runs first; the GeoIP policy is
    // the coarser country-level layer on top of it. A denial is 403 with
    // `connection: close`, audited as `rejected` with reason
    // `geo_blocked` — it never enqueues, so it burns no retry budget and
    // never trips the breaker. The client IP reuses the WR-53
    // `clientIp` resolution when an IP ACL is configured
    // (x-forwarded-for through trustedProxies), otherwise the direct
    // socket peer — the trusted-proxy semantics stay identical whether or
    // not the ACL is configured. Unset = off: zero behavior change.
    if (geoIpPolicy !== undefined) {
      const geoClientIp = ipAcl
        ? ipAcl.clientIp(req.socket.remoteAddress, req.headers["x-forwarded-for"])
        : (req.socket.remoteAddress ?? "unknown");
      const geo = geoIpPolicy.classify(geoClientIp);
      if (geo.verdict === "deny") {
        opts.auditLog.append({
          event: "rejected",
          id,
          traceId,
          reason: "geo_blocked",
          ip: geoClientIp,
          country: geo.country ?? "unknown",
        });
        // `connection: close` like the other pre-body rejections: the
        // caller is denied before the body is read, so don't let it stream
        // a flood into a dead request.
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
      // WR-119: the sender dimension is the matched API key id, or
      // "anonymous" when no key guards the endpoint.
      const senderKey = apiKey?.keyId ?? "anonymous";
      const limitCheck = checkInboundRateLimit(ip, senderKey, id, traceId);
      if (!limitCheck.ok) {
        res
          .writeHead(429, {
            "content-type": "text/plain",
            // Ceiling seconds, minimum 1: a Retry-After of 0 is meaningless.
            "retry-after": String(Math.max(1, Math.ceil(limitCheck.retryAfterMs / 1000))),
          })
          .end("Too many requests");
        return undefined;
      }
      // WR-119 tightening (a): a degraded sender faces a halved
      // per-sender budget on top of the normal limiter. The main limiter
      // already passed, so this only ever *adds* rejections for senders
      // already in the degraded state. `observe` decays first, so a
      // sender quiet long enough upgrades back here and skips the extra
      // budget entirely; the transition audits exactly once.
      if (tightenedBudgetPerSecond !== undefined && reputation !== undefined) {
        const view = reputation.observe(senderKey);
        auditReputationTransition(view.transition, { id, traceId });
        if (view.degraded && !reputation.takeTightenedBudget(senderKey, tightenedBudgetPerSecond)) {
          recordReputationPenalty(senderKey, "rate_limit", { id, traceId });
          const retryAfterMs = Math.ceil(1000 / tightenedBudgetPerSecond);
          opts.auditLog.append({
            event: "rejected",
            id,
            traceId,
            reason: "rate_limited",
            dimension: "reputation",
            retryAfterMs,
          });
          res
            .writeHead(429, {
              "content-type": "text/plain",
              "retry-after": String(Math.max(1, Math.ceil(retryAfterMs / 1000))),
            })
            .end("Too many requests");
          return undefined;
        }
      }
    }

    // Per-tenant inbound rate limiting (WR-141): the x-tenant-id token
    // bucket, checked after the WR-22 limiter and before signature
    // verification, so one abusive tenant's flood is rejected before it
    // burns verifier CPU. The tenant id format is validated with the
    // WR-48 validator; an invalid id skips this check — the request still
    // fails verification/validation downstream exactly as before, so
    // unauthenticated callers learn nothing new. No header or unconfigured
    // limiter: zero behavior change.
    if (inboundTenantRateLimiter !== undefined) {
      const tenantHeader = req.headers[TENANT_ID_HEADER];
      const tenantRaw = Array.isArray(tenantHeader) ? tenantHeader[0] : tenantHeader;
      if (typeof tenantRaw === "string" && tenantRaw !== "") {
        let limitedTenant: string | undefined;
        try {
          assertValidTenantId(tenantRaw);
          limitedTenant = tenantRaw;
        } catch {
          // Invalid tenant id: not rate-limited here; the WR-48 400
          // below (after verification) still applies unchanged.
        }
        if (limitedTenant !== undefined) {
          const tenantCheck = inboundTenantRateLimiter.take(limitedTenant);
          if (!tenantCheck.ok) {
            inboundTenantRateLimitMetrics.record(limitedTenant);
            opts.auditLog.append({
              event: "rejected",
              id,
              traceId,
              reason: "tenant_rate_limited",
              tenant: limitedTenant,
              retryAfterMs: tenantCheck.retryAfterMs,
            });
            res
              .writeHead(429, {
                "content-type": "text/plain",
                // Ceiling seconds, minimum 1: a Retry-After of 0 is meaningless.
                "retry-after": String(Math.max(1, Math.ceil(tenantCheck.retryAfterMs / 1000))),
              })
              .end("Too many requests");
            return undefined;
          }
        }
      }
    }

    // Inbound per-endpoint body size override (WR-102): resolved from
    // headers alone — before a single body byte is read — so the
    // endpoint's own budget governs all three enforcement points: the
    // declared Content-Length pre-check below, the `readRawBody`
    // streaming cap, and the WR-40 gzip decompression cap in
    // `admitOneEvent` (the budget rides along on the gate result).
    // `undefined` when no rule matched: exact global behavior. This is
    // the transport layer — it runs before signature verification and
    // before WR-41 schema validation (semantic validation); the two are
    // orthogonal.
    const effectiveMaxBodyBytes =
      selectEndpointBodyLimit(pathname, opts.endpointBodyLimits) ?? maxBodyBytes;

    // Inbound body size limit (WR-25), first line of defense: the declared
    // Content-Length is checked before a single body byte is read, so a
    // giant payload is rejected without touching memory or the verifier. A
    // missing or unparseable header falls through to the streaming cap.
    const declaredLength = req.headers["content-length"];
    if (typeof declaredLength === "string") {
      const n = Number(declaredLength);
      if (Number.isInteger(n) && n > effectiveMaxBodyBytes) {
        opts.auditLog.append({
          event: "rejected",
          id,
          traceId,
          reason: "body_too_large",
          maxBodyBytes: effectiveMaxBodyBytes,
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
      body = await readRawBody(req, effectiveMaxBodyBytes);
    } catch (err) {
      if (err instanceof BodyTooLargeError) {
        opts.auditLog.append({
          event: "rejected",
          id,
          traceId,
          reason: "body_too_large",
          maxBodyBytes: effectiveMaxBodyBytes,
        });
        res
          .writeHead(413, { "content-type": "text/plain", connection: "close" })
          .end("Request body too large");
        return undefined;
      }
      res.writeHead(400, { "content-type": "text/plain" }).end("Bad request");
      return undefined;
    }
    return { body, maxBodyBytes: effectiveMaxBodyBytes, apiKey };
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
    /**
     * WR-97: honest retry delay in ms for a 429 rejection — rendered as
     * the `retry-after` response header (ceiling seconds, minimum 1).
     */
    retryAfterMs?: number;
    /**
     * WR-144: extra response headers for a rejection — rendered
     * verbatim on the rejection response (e.g. the RFC 8594 `Sunset`
     * header on a version-sunset 410).
     */
    responseHeaders?: Record<string, string>;
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
    apiKey?: { keyId: string; rule: EndpointApiKeyRule },
    /**
     * WR-98: caller-propagated W3C trace context for this event (from the
     * inbound `traceparent` / `tracestate`); rides the queued item so
     * outbound deliveries propagate it. `undefined` = no caller context.
     */
    inboundTrace?: TraceContext,
    /**
     * WR-102: the body budget the intake gates resolved for this
     * request (the matching `endpointBodyLimits` rule's budget, or the
     * global `maxBodyBytes`). Caps the WR-40 gzip decompression here —
     * the third enforcement point of the same per-endpoint budget.
     * Defaults to the global so unset means zero behavior change.
     */
    bodyBudgetBytes: number = maxBodyBytes
  ): Promise<AdmitOutcome> => {
    const signatureHeader = headers["x-signature"];
    const keyIdHeader = headers["x-key-id"];
    const keyIdHint = Array.isArray(keyIdHeader) ? keyIdHeader[0] : keyIdHeader;

    // Inbound sender reputation (WR-119): the sender dimension is the
    // matched API key id, or "anonymous" when no key guards the endpoint
    // (batch items always land here — per-item admission carries no key).
    // `observe` decays past demerit to now and reports a threshold
    // crossing (a quiet degraded sender can recover here); the crossing
    // audits exactly once, on this request.
    const senderKey = apiKey?.keyId ?? "anonymous";
    const reputationView = reputation?.observe(senderKey);
    auditReputationTransition(reputationView?.transition, { ...correlation, id, traceId });

    // Per-endpoint verifier selection (WR-29): the request path picks the
    // trusted verifier; anything unmatched falls back to the global one.
    // A mismatch here is answered 401 below and never enqueues, so it can
    // never trip the downstream circuit breaker.
    let activeVerifier = selectEndpointVerifier(pathname, opts.endpointVerifiers) ?? verifier;
    // WR-138: inbound signature algorithm negotiation — the
    // `x-signature-alg` header names the algorithm the upstream used
    // ("hmac-sha256" | "ed25519") and the allowlisted rule's verifier
    // replaces the default for this request's signature check. Unset
    // `signatureAlgorithms` (the default) disables negotiation entirely:
    // the header is ignored and the legacy default applies, fully
    // backward compatible. Negotiation never widens a per-endpoint
    // verifier rule: a pinned path keeps its verifier. An allowlisted-
    // but-unknown name is answered 400 and audited as `rejected` with
    // reason `unsupported_algorithm` — never enqueued.
    let negotiatedAlg: string | undefined;
    if (activeVerifier === verifier && opts.signatureAlgorithms !== undefined) {
      const algRaw = headers[SIGNATURE_ALG_HEADER];
      const alg = normalizeSignatureAlg(Array.isArray(algRaw) ? algRaw[0] : algRaw);
      if (alg !== undefined) {
        const negotiated = selectSignatureAlgorithmVerifier(alg, opts.signatureAlgorithms);
        if (negotiated === undefined) {
          opts.auditLog.append({ ...correlation,
            event: "rejected",
            id,
            traceId,
            reason: "unsupported_algorithm",
            algorithm: alg,
          });
          return {
            status: 400,
            id,
            traceId,
            reason: "unsupported_algorithm",
            detail: `Unsupported signature algorithm: ${alg}`,
          };
        }
        activeVerifier = negotiated;
        negotiatedAlg = alg;
      }
    }
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
    // WR-119 tightening (b): a degraded sender is forced through
    // signature verification even where the API key alone would
    // authenticate — the same as `requireSignature: true` on the rule.
    // Only meaningful where a verifier is configured; the relay always
    // configures one (the default HMAC verifier over `secret`), so the
    // forced check always takes effect.
    const forceSignature = reputationView?.degraded ?? false;
    const apiKeyAuthenticates =
      apiKey !== undefined && apiKey.rule.requireSignature !== true && !forceSignature;
    // WR-110: RSA-PSS rotation joins the HMAC rotation here — both expose
    // verifyDetailed() -> { ok, keyId }, so the accepted-audit keyId
    // attribution below works unchanged (for RSA the keyId is the
    // SHA-256 fingerprint of the verifying public key).
    const rotatingVerifier =
      activeVerifier instanceof RotatingHmacVerifier ||
      activeVerifier instanceof RotatingRsaPssVerifier;
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

    // WR-107: mesh peer authentication — a relay forwarding over the mesh
    // proves itself with `x-relay-signature` (WR-26 outbound signing on the
    // sending relay) instead of the producer `x-signature`. Verified with
    // the same active verifier, so the mesh runs on a shared relay
    // secret: anything accepted here would verify identically as
    // `x-signature` — the fallback grants no new capability, it only
    // names the trust domain in the audit trail. Gated on mesh being
    // enabled; disabled = zero behavior change.
    let meshPeerAuth = false;
    if (!verified && meshCfg !== undefined) {
      const relaySigRaw = headers["x-relay-signature"];
      const relaySig = Array.isArray(relaySigRaw) ? relaySigRaw[0] : relaySigRaw;
      if (typeof relaySig === "string" && relaySig !== "") {
        if (rotatingVerifier) {
          const relayKeyIdRaw = headers["x-relay-key-id"];
          const detail = activeVerifier.verifyDetailed(body, relaySig, {
            keyId: Array.isArray(relayKeyIdRaw) ? relayKeyIdRaw[0] : relayKeyIdRaw,
          });
          verified = detail.ok;
          if (verified) verifiedKeyId = detail.keyId;
        } else {
          verified = activeVerifier.verify(body, relaySig);
        }
        meshPeerAuth = verified;
      }
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
      // WR-138: name the negotiated algorithm, so a multi-algorithm
      // relay's audit trail shows which algorithm the upstream claimed.
      if (negotiatedAlg !== undefined) rejectedEvent.algorithm = negotiatedAlg;
      opts.auditLog.append(rejectedEvent);
      // WR-119: a signature verification failure is a reputation penalty
      // event for the sender dimension.
      recordReputationPenalty(senderKey, "verify_failure", { ...correlation, id, traceId });
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
    // payload. Decompression is streaming and capped at the request's
    // effective body budget (WR-102: the endpoint's own budget when a
    // rule matched, else the global `maxBodyBytes`) — a gzip bomb is
    // answered 413 exactly like an oversized plain body.
    let inboundGzip = false;
    if (isGzipContentEncoding(headers["content-encoding"])) {
      try {
        body = await gunzipCapped(body, bodyBudgetBytes);
        inboundGzip = true;
      } catch (err) {
        if (err instanceof DecompressionTooLargeError) {
          opts.auditLog.append({ ...correlation,
            event: "rejected",
            id,
            traceId,
            reason: "body_too_large",
            maxBodyBytes: bodyBudgetBytes,
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
        // WR-144: per-version sunset. Once the configured (or hot-updated)
        // sunset moment is reached, the version is gone: answer 410 with
        // the RFC 8594 `Sunset` header and audit `rejected` with reason
        // `version_sunset`. A sunset version never reaches the adapter
        // (the adapter may already be retired) and never enters the
        // retry queue. Unset versions behave exactly as before.
        const sunsetMs = versionRouter.effectiveSunset(versionRoute.prefix);
        if (sunsetMs !== undefined && Date.now() >= sunsetMs) {
          const sunsetIso = new Date(sunsetMs).toISOString();
          versionMetrics.record(version, "rejected");
          opts.auditLog.append({ ...correlation,
            event: "rejected",
            id,
            traceId,
            ...tenantLabel,
            reason: "version_sunset",
            version,
            sunsetAt: sunsetIso,
          });
          return {
            status: 410,
            id,
            traceId,
            reason: "version_sunset",
            detail: `API version ${version} was sunset at ${sunsetIso}; migrate to a current version`,
            responseHeaders: { Sunset: new Date(sunsetMs).toUTCString() },
          };
        }
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
    // WR-96: the active registry registration (for corpus auto-accumulate
    // bookkeeping) and the parsed adapted payload it validated — both
    // recorded into the corpus only when the request is accepted below.
    let schemaRegistration: SchemaRegistration | undefined;
    let schemaPayload: unknown;
    if (opts.payloadSchemas !== undefined && schemaRegistry !== undefined) {
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
      const registration =
        schemaRegistry.select(strippedPath) ??
        (strippedPath === pathname ? undefined : schemaRegistry.select(pathname));
      if (registration !== undefined) {
        schema = registration.schema;
        schemaRegistration = registration;
        let payload: unknown;
        let parseError: string | undefined;
        try {
          payload = JSON.parse(body.toString("utf8"));
        } catch {
          parseError = "body is not valid JSON";
        }
        schemaPayload = payload;
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
          // WR-119: a schema validation failure is a reputation penalty
          // event for the sender dimension.
          recordReputationPenalty(senderKey, "schema_violation", { ...correlation, id, traceId });
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

    // WR-107: relay mesh hop accounting. Placement is deliberate: after
    // signature verification and tenant validation (an unauthenticated
    // caller learns nothing about the mesh), and after content routing
    // so `targetUrl` is known for the audit event and the metric label.
    // A malformed header is fail-closed 400 (`mesh_hops_invalid`); an
    // event that already traversed `maxHops` relays is rejected 400
    // (`mesh_hop_limit_exceeded`) — the loop guard against a
    // misconfigured A → B → A cycle. Otherwise the hop count rides the
    // item and is stamped back out incremented on the wire.
    let meshHops: number | undefined;
    if (meshCfg !== undefined) {
      const hopsRaw = headers[RELAY_HOPS_HEADER];
      try {
        meshHops = parseRelayHops(Array.isArray(hopsRaw) ? hopsRaw[0] : hopsRaw);
      } catch {
        opts.auditLog.append({ ...correlation,
          event: "rejected",
          id,
          traceId,
          ...tenantLabel,
          targetUrl,
          reason: "mesh_hops_invalid",
        });
        return { status: 400, id, traceId, reason: "mesh_hops_invalid", detail: "Invalid x-relay-hops" };
      }
      if (meshHops >= meshCfg.maxHops) {
        meshMetrics.recordHopLimitRejected(targetUrl);
        opts.auditLog.append({ ...correlation,
          event: "rejected",
          id,
          traceId,
          ...tenantLabel,
          targetUrl,
          reason: "mesh_hop_limit_exceeded",
          meshHops,
          maxHops: meshCfg.maxHops,
        });
        return { status: 400, id, traceId, reason: "mesh_hop_limit_exceeded", detail: "Mesh hop limit exceeded" };
      }
    }

    if (opts.replay) {
      const nonceHeader = headers["x-nonce"];
      const nonce = Array.isArray(nonceHeader) ? nonceHeader[0] : nonceHeader;
      const tsHeader = headers["x-timestamp"];
      const tsRaw = Array.isArray(tsHeader) ? tsHeader[0] : tsHeader;
      // x-timestamp is unix seconds (same unit as the `t=` signature field);
      // the guard works in ms. A non-numeric value fails the window check.
      const timestampMs = tsRaw === undefined ? undefined : Number(tsRaw) * 1000;
      // WR-122: scope the nonce by the resolved targetUrl — the same nonce
      // value reused for an unrelated target is not a replay of this
      // delivery, so it must not false-positive. (targetUrl is resolved
      // above via content routing; it falls back to opts.forwardUrl.)
      const verdict = opts.replay.check(nonce, timestampMs, targetUrl);
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
    // WR-119 tightening (c): a degraded sender's duplicates are
    // suppressed over the doubled window — a misbehaving sender's
    // retries stay collapsed longer. The base window is untouched for
    // healthy senders.
    const activeDeduplicator =
      tightenedDeduplicator !== undefined && (reputationView?.degraded ?? false)
        ? tightenedDeduplicator
        : deduplicator;
    if (activeDeduplicator) {
      const payloadHash = DeliveryDeduplicator.hashPayload(body);
      // WR-108: `check()` is async — a custom DedupStore may answer from
      // across the network (e.g. Redis). `admitOneEvent` is already async.
      if (await activeDeduplicator.check(tenantScopeKey(tenantId, targetUrl), payloadHash)) {
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
      // `x-relay-signature` / `x-relay-key-id` /
      // `x-relay-ed25519-signature` / `x-relay-ed25519-key-id` /
      // `x-relay-idempotency-key` are this relay's own namespace: an
      // inbound client asserting them would impersonate the relay
      // downstream. Strip them always; when outbound signing /
      // idempotency keys are enabled the sender stamps fresh ones below.
      // `x-tenant-id` is likewise relay-internal routing state (WR-48):
      // the tenant is already on the queued item, and the downstream
      // never asked for the caller's tenancy claim.
      if (
        k === "x-relay-signature" ||
        k === "x-relay-key-id" ||
        k === ED25519_SIGNATURE_HEADER ||
        k === ED25519_KEY_ID_HEADER ||
        k === IDEMPOTENCY_KEY_HEADER
      )
        continue;
      if (k === TENANT_ID_HEADER) continue;
      // WR-107: `x-relay-hops` is relay-internal mesh accounting, like
      // `x-tenant-id` above. The inbound value is consumed into
      // `item.meshHops` at admission; the sender stamps a fresh
      // incremented value below, so a stale/forged header never travels
      // downstream verbatim. Stripped even when mesh is disabled.
      if (k === RELAY_HOPS_HEADER) continue;
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

    // WR-97: per-(tenant, endpoint) outbound rate limiting, `reject-429`
    // mode. The check runs against the content-route-resolved `targetUrl`
    // (the same endpoint the dispatch path would pace) and after the
    // dedup gate, so duplicates suppressed above consume no token — no
    // new delivery will be attempted for them. On denial the webhook is
    // answered 429 with `retry-after` (the WR-22 convention) and audited
    // as `rejected` with reason `rate_limited`; the decision is also
    // recorded to OTLP as a `rate_limited` event. The token is consumed
    // now, at admission, so the dispatch path never re-checks in this
    // mode. In `queue` mode (or when the feature is off)
    // `admitTenantDelivery` returns undefined and admission proceeds.
    // WR-80: a cron registration is an admission too — it consumes one
    // token for the template; per-cycle minted deliveries are paced at
    // dispatch in `queue` mode and not re-checked here.
    const tenantVerdict = queue.admitTenantDelivery(tenantId, targetUrl);
    if (tenantVerdict !== undefined && !tenantVerdict.ok) {
      opts.auditLog.append({ ...correlation,
        event: "rejected",
        id,
        traceId,
        ...tenantLabel,
        targetUrl,
        reason: "rate_limited",
        retryAfterMs: tenantVerdict.retryAfterMs,
      });
      queue.recordTenantRateLimitedEvent({
        eventId: id,
        traceId,
        ...(tenantId === undefined ? {} : { tenant: tenantId }),
        endpoint: targetUrl,
        retryAfterMs: tenantVerdict.retryAfterMs,
      });
      return {
        status: 429,
        id,
        traceId,
        reason: "rate_limited",
        detail: "Too many requests",
        retryAfterMs: tenantVerdict.retryAfterMs,
      };
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
        // WR-107: the mesh hop count rides the cron template so every
        // per-cycle minted delivery re-enters the mesh at the same count.
        ...(meshHops !== undefined ? { meshHops } : {}),
      }, cronSource);
      nextAt = queue.nextScheduleFire(scheduleId);
    } else if (queue.hasQuorumConfig(targetUrl)) {
      // WR-106: one admission fans out to every configured target; each
      // member keeps the admitted priority (WR-12: an urgent admission
      // puts every member on the fast lane) and the shared trace id.
      queue.enqueueFanout({
        id,
        traceId,
        // WR-48: the validated tenant rides the item into the per-tenant
        // isolation scope (breaker/quota/limiter/latency instances).
        ...(tenantId !== undefined ? { tenantId } : {}),
        // WR-98: the caller-propagated W3C trace context rides the item
        // so every delivery attempt propagates it downstream.
        ...(inboundTrace !== undefined ? { traceContext: inboundTrace } : {}),
        // WR-107: the mesh hop count rides every fan-out member.
        ...(meshHops !== undefined ? { meshHops } : {}),
        payload: body,
        targetUrl,
        headers: passthrough,
        ...(priority ? { priority } : {}),
        ...(deliverAt !== undefined ? { deliverAt } : {}),
      });
    } else {
      queue.enqueue({
        id,
        traceId,
        // WR-48: the validated tenant rides the item into the per-tenant
        // isolation scope (breaker/quota/limiter/latency instances).
        ...(tenantId !== undefined ? { tenantId } : {}),
        // WR-98: the caller-propagated W3C trace context rides the item
        // so every delivery attempt propagates it downstream.
        ...(inboundTrace !== undefined ? { traceContext: inboundTrace } : {}),
        // WR-107: the mesh hop count rides the queued item.
        ...(meshHops !== undefined ? { meshHops } : {}),
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
      // WR-96: feed the opt-in compatibility corpus — accepted payloads
      // only, so a later schema registration for the same pattern is
      // gated against shapes the current schema really admitted. A no-op
      // unless the rule opted into `accumulate`.
      if (schemaRegistration !== undefined) {
        schemaRegistry?.noteAcceptedPayload(schemaRegistration, schemaPayload);
      }
    }
    const acceptedEvent: Record<string, unknown> = { ...correlation,
      event: "accepted",
      id,
      traceId,
      ...tenantLabel,
      targetUrl,
      // WR-107: the mesh hop count at admission (absent when mesh is
      // disabled) — the audit trail shows how deep into the mesh the
      // event arrived.
      ...(meshHops !== undefined ? { meshHops } : {}),
      // WR-107: the event arrived over an authenticated mesh peer leg
      // (`x-relay-signature` verified) rather than a producer signature.
      ...(meshPeerAuth ? { meshPeer: true } : {}),
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
    // WR-138: the negotiated algorithm, so operators can see which
    // algorithm each accepted webhook verified under.
    if (negotiatedAlg !== undefined) acceptedEvent.algorithm = negotiatedAlg;
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
    pathname: string,
    /**
     * WR-103: the verified client identity from the inbound mTLS gate.
     * Rides every `accepted` / `rejected` audit event through the
     * admission correlation spread.
     */
    mtlsIdentity?: InboundMtlsIdentity
  ): Promise<void> => {
    if (req.method !== "POST") {
      res.writeHead(405, { "content-type": "text/plain" }).end("Method not allowed");
      return;
    }
    // WR-61: batch ingestion rides the intake plane like any webhook —
    // one envelope signature, then per-item admission.
    if (pathname === "/ingest/batch") {
      await handleIngestBatch(req, res, mtlsIdentity);
      return;
    }
    // WR-139: lightweight batch ingestion — per-item signatures only,
    // no envelope signature; auth follows the inbound intake rules.
    if (pathname === "/batch") {
      await handleBatch(req, res, mtlsIdentity);
      return;
    }
    const id = randomUUID();
    // WR-98: parse the inbound W3C trace context before any admission
    // decision — gated on the option, so an unset option means zero
    // parsing overhead. A valid `traceparent` promotes its trace-id to
    // the event's trace ID, so the relay's OTLP span, audit trail, and
    // the downstream trace share one trace id; an invalid `traceparent`
    // is ignored outright, never a 400.
    const inboundTrace =
      traceContextOpts === undefined
        ? undefined
        : parseInboundTraceContext(req.headers[TRACEPARENT_HEADER], req.headers[TRACESTATE_HEADER]);
    // Resolve the trace ID before any admission decision so even rejections
    // are traceable; a propagated W3C trace id wins, then a client-supplied
    // x-trace-id is honored, otherwise fresh.
    const traceId = inboundTrace?.traceId ?? resolveTraceId(req.headers[TRACE_ID_HEADER]);
    const gates = await runIntakeGates(req, res, pathname, id, traceId);
    if (gates === undefined) return;
    // WR-103: the verified client identity rides every `accepted` /
    // `rejected` audit event through the admission correlation spread.
    // WR-112: a mesh-mTLS-verified peer identity rides along the same
    // way when the global gate left the request anonymous (the listener
    // passes gate.identity ?? meshGate.identity).
    const mtlsCorrelation =
      mtlsIdentity === undefined
        ? {}
        : {
            clientCertFingerprint: mtlsIdentity.fingerprint,
            clientCertSubject: mtlsIdentity.subject,
          };
    const outcome = await admitOneEvent(id, traceId, gates.body, req.headers, pathname, mtlsCorrelation, gates.apiKey, inboundTrace, gates.maxBodyBytes);
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
    // WR-97: a 429 from per-tenant rate limiting carries the honest
    // retry-after — ceiling seconds, minimum 1 (the WR-22 convention; a
    // Retry-After of 0 is meaningless).
    if (outcome.retryAfterMs !== undefined) {
      rejHeaders["retry-after"] = String(Math.max(1, Math.ceil(outcome.retryAfterMs / 1000)));
    }
    // WR-144: extra rejection headers (e.g. the RFC 8594 `Sunset` header
    // on a version-sunset 410).
    if (outcome.responseHeaders !== undefined) {
      Object.assign(rejHeaders, outcome.responseHeaders);
    }
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
    res: Parameters<Parameters<typeof createServer>[0]>[1],
    /**
     * WR-103: the verified client identity from the inbound mTLS gate
     * (undefined when mTLS is unconfigured or the request presented no
     * verifiable certificate). Rides the `batch_ingested` event and every
     * per-item `accepted` / `rejected` event via `correlation`.
     */
    mtlsIdentity?: InboundMtlsIdentity
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

    const correlation = { batchId,
      // WR-103: the verified client identity rides every per-item audit
      // event (`accepted` / `rejected`) through the correlation spread.
      ...(mtlsIdentity !== undefined
        ? { clientCertFingerprint: mtlsIdentity.fingerprint, clientCertSubject: mtlsIdentity.subject }
        : {}),
    };
    const results: Array<Record<string, unknown>> = [];
    let accepted = 0;
    for (let index = 0; index < events.length; index++) {
      const itemId = randomUUID();
      const checked = checkIngestBatchItem(events[index]);
      // WR-98: per-item W3C trace context, like the single-event intake —
      // gated on the option; an invalid item-level `traceparent` is
      // ignored, never a 400 for the item.
      const itemTrace =
        traceContextOpts === undefined || !("item" in checked) || checked.item.headers === undefined
          ? undefined
          : parseInboundTraceContext(
              checked.item.headers[TRACEPARENT_HEADER],
              checked.item.headers[TRACESTATE_HEADER]
            );
      // Per-item trace IDs are independent: a valid item-level W3C
      // traceparent promotes its trace-id, then an item's own
      // `x-trace-id` is honored, otherwise a fresh one — never the
      // batch's.
      const itemTraceId =
        itemTrace?.traceId ??
        resolveTraceId(
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
        correlation,
        undefined,
        itemTrace,
        gates.maxBodyBytes
      );
      const result: Record<string, unknown> = {
        index,
        status: outcome.status,
        id: outcome.id,
        traceId: outcome.traceId,
      };
      if (outcome.reason !== undefined) result.reason = outcome.reason;
      if (outcome.detail !== undefined) result.detail = outcome.detail;
      // WR-97: a 429'd batch item carries the honest retry delay in the
      // per-item result (batch responses have no per-item headers).
      if (outcome.retryAfterMs !== undefined) result.retryAfterMs = outcome.retryAfterMs;
      // WR-144: a 410'd batch item carries the version's sunset moment
      // (batch responses have no per-item headers).
      if (outcome.responseHeaders?.["Sunset"] !== undefined) {
        result.sunset = outcome.responseHeaders["Sunset"];
      }
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
      // WR-103: verified client identity on the batch-level audit event.
      ...(mtlsIdentity !== undefined
        ? { clientCertFingerprint: mtlsIdentity.fingerprint, clientCertSubject: mtlsIdentity.subject }
        : {}),
    });
    res
      .writeHead(accepted === events.length ? 202 : 207, {
        "content-type": "application/json",
      })
      .end(JSON.stringify({ batchId, traceId: batchTraceId, results }));
  };

  /**
   * Lightweight batch ingestion (WR-139): `POST /batch` accepts one JSON
   * envelope carrying many events, each walking the full per-item
   * admission chain through `admitOneEvent` (signature — including the
   * WR-138 `x-signature-alg` negotiation — → tenant → gzip → version →
   * schema → replay guard → dedup → rate limit → enqueue).
   *
   * Trust model vs `POST /ingest/batch` (WR-61): there is NO envelope
   * signature here. The batcher is authenticated by the intake gates
   * (IP allowlist, API key, mTLS — "auth follows the inbound rules")
   * and each event authenticates itself with its own `x-signature`.
   * This serves producers that aggregate events but cannot hold a
   * batch-signing key; WR-61 stays the choice when the batcher itself
   * must be authenticated.
   *
   * Fail-fast size gate: any single item whose decoded body exceeds the
   * global per-event body budget rejects the WHOLE batch with 413 before
   * any per-item admission runs — zero side effects, no partial
   * processing. The envelope itself is still capped by the resolved
   * (possibly per-endpoint) budget; the per-item budget stays global so
   * an `endpointBodyLimits` rule that widens `/batch` transport cannot
   * smuggle an oversized event. (WR-61 has no per-item size gate.)
   *
   * Envelope shape: `{ "events": [{ "payload": "<base64>", "headers":
   * { "x-signature": "sha256=…", … } }, …] }`, same as WR-61.
   * Per-item header names are lowercased before admission (HTTP
   * semantics; WR-61 passes them through verbatim).
   *
   * Responses: 202 when every item was accepted, 207 Multi-Status
   * otherwise, with `{ batchId, traceId, accepted,
   * rejected: [{ index, reason }] }`. A malformed envelope is 400 and
   * never touches per-item admission. The batch is audited once as
   * `batch_received` (totals), plus the normal per-item `accepted` /
   * `rejected` / `duplicate_suppressed` events, each carrying `batchId`
   * for correlation.
   */
  const handleBatch = async (
    req: Parameters<Parameters<typeof createServer>[0]>[0],
    res: Parameters<Parameters<typeof createServer>[0]>[1],
    /**
     * WR-103: the verified client identity from the inbound mTLS gate
     * (undefined when mTLS is unconfigured or the request presented no
     * verifiable certificate). Rides the `batch_received` event and every
     * per-item `accepted` / `rejected` event via `correlation`.
     */
    mtlsIdentity?: InboundMtlsIdentity
  ): Promise<void> => {
    const batchId = randomUUID();
    const batchTraceId = resolveTraceId(req.headers[TRACE_ID_HEADER]);
    const gates = await runIntakeGates(req, res, "/batch", batchId, batchTraceId);
    if (gates === undefined) return;
    const body = gates.body;

    // A batch-level tenant is validated once here; a per-item
    // `x-tenant-id` overrides it for that item (WR-48, same as WR-61).
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
          path: "/batch",
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
        path: "/batch",
        reason: !Array.isArray(events) ? "invalid_batch_shape" : "empty_batch",
      });
      res.writeHead(400, { "content-type": "text/plain" }).end("Invalid batch envelope");
      return;
    }

    // Validate every item's shape first, then fail the whole batch fast
    // when any single item exceeds the per-event body budget — before any
    // per-item admission runs, so an oversized item can never cause
    // partial processing. Malformed items are NOT a batch failure: like
    // WR-61 they are reported per item and the rest of the batch is
    // still admitted.
    //
    // The per-item budget is the GLOBAL maxBodyBytes (the WR-25
    // per-event invariant), not the resolved per-endpoint budget: an
    // `endpointBodyLimits` rule for `/batch` sizes the envelope
    // (transport — big batches of normal-sized events stay welcome),
    // while a single event over the global event cap still fails the
    // batch fast. (Checking against the resolved budget would be dead
    // code: base64 inflates every item, so the envelope gate would
    // always fire first.)
    const correlation = { batchId,
      // WR-103: the verified client identity rides every per-item audit
      // event (`accepted` / `rejected`) through the correlation spread.
      ...(mtlsIdentity !== undefined
        ? { clientCertFingerprint: mtlsIdentity.fingerprint, clientCertSubject: mtlsIdentity.subject }
        : {}),
    };
    const bodies: Array<Buffer | undefined> = new Array(events.length);
    const headerMaps: Record<number, Record<string, string | string[]>> = {};
    const rejected: Array<{ index: number; reason: string }> = [];
    for (let index = 0; index < events.length; index++) {
      const checked = checkIngestBatchItem(events[index]);
      if (!("item" in checked)) {
        opts.auditLog.append({
          event: "rejected",
          ...correlation,
          id: randomUUID(),
          traceId: resolveTraceId(undefined),
          path: "/batch",
          reason: "invalid_item",
          index,
          detail: checked.problem,
        });
        rejected.push({ index, reason: "invalid_item" });
        continue;
      }
      bodies[index] = checked.body;
      const lowered: Record<string, string | string[]> = {};
      for (const [k, v] of Object.entries(checked.item.headers ?? {})) {
        lowered[k.toLowerCase()] = v;
      }
      headerMaps[index] = lowered;
    }
    const oversizedIndex = bodies.findIndex(
      (b) => b !== undefined && b.length > maxBodyBytes
    );
    if (oversizedIndex !== -1) {
      opts.auditLog.append({
        event: "rejected",
        id: batchId,
        traceId: batchTraceId,
        path: "/batch",
        reason: "item_too_large",
        index: oversizedIndex,
        itemBytes: (bodies[oversizedIndex] as Buffer).length,
        maxBodyBytes,
      });
      // `connection: close` like the WR-25 413: the sender already proved
      // it will push oversized items, don't let it stream more into a
      // dead request.
      res
        .writeHead(413, { "content-type": "text/plain", connection: "close" })
        .end("Batch item exceeds body size limit");
      return;
    }

    let accepted = 0;
    for (let index = 0; index < events.length; index++) {
      const itemBody = bodies[index];
      if (itemBody === undefined) continue; // already recorded as invalid_item above
      const itemHeaderMap = headerMaps[index] ?? {};
      const itemId = randomUUID();
      // WR-98: per-item W3C trace context, like the single-event intake —
      // gated on the option; an invalid item-level `traceparent` is
      // ignored, never a 400 for the item.
      const itemTrace =
        traceContextOpts === undefined
          ? undefined
          : parseInboundTraceContext(
              itemHeaderMap[TRACEPARENT_HEADER],
              itemHeaderMap[TRACESTATE_HEADER]
            );
      const itemTraceId =
        itemTrace?.traceId ?? resolveTraceId(itemHeaderMap[TRACE_ID_HEADER]);
      const itemHeaders: Record<string, string | string[] | undefined> = {
        ...itemHeaderMap,
      };
      if (itemHeaders[TENANT_ID_HEADER] === undefined && batchTenantId !== undefined) {
        itemHeaders[TENANT_ID_HEADER] = batchTenantId;
      }
      const outcome = await admitOneEvent(
        itemId,
        itemTraceId,
        itemBody,
        itemHeaders,
        "/batch",
        correlation,
        undefined,
        itemTrace,
        gates.maxBodyBytes
      );
      if (outcome.status === 202) {
        accepted++;
      } else {
        rejected.push({ index, reason: outcome.reason ?? "unknown" });
      }
    }

    opts.auditLog.append({
      event: "batch_received",
      id: batchId,
      traceId: batchTraceId,
      path: "/batch",
      total: events.length,
      accepted,
      rejected: rejected.length,
      ...(batchTenantId !== undefined ? { tenant: batchTenantId } : {}),
      // WR-103: verified client identity on the batch-level audit event.
      ...(mtlsIdentity !== undefined
        ? { clientCertFingerprint: mtlsIdentity.fingerprint, clientCertSubject: mtlsIdentity.subject }
        : {}),
    });
    res
      .writeHead(accepted === events.length ? 202 : 207, {
        "content-type": "application/json",
      })
      .end(JSON.stringify({ batchId, traceId: batchTraceId, accepted, rejected }));
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

  /**
   * WR-103: inbound mTLS gate — the outermost check on every request a
   * listener serves, before plane dispatch, operator auth, and the intake
   * gates, so an unauthenticated caller costs zero bandwidth and zero
   * downstream state. `isOperatorRoute` selects the independent
   * operator-route policy (`operatorMtls`); on the split intake plane the
   * cross-plane 404 above runs first, so the operator plane's existence
   * is never revealed by a 401.
   *
   * A missing certificate where one is required is answered 401
   * (`client_cert_required`); a presented certificate whose chain does
   * not verify against the configured CA — or whose fingerprint is not
   * whitelisted — is answered 401 (`client_cert_invalid`). Both are
   * audited as `rejected` with the reason code (the presented
   * certificate's fingerprint/subject ride along when there is one), and
   * both close the connection: the caller must re-handshake with a
   * different certificate, which needs a fresh connection anyway.
   *
   * Returns the verified client identity for the audit trail when the
   * request may proceed.
   */
  const enforceInboundMtls = (
    req: Parameters<Parameters<typeof createServer>[0]>[0],
    res: Parameters<Parameters<typeof createServer>[0]>[1],
    pathname: string,
    isOperatorRoute: boolean
  ): { proceed: true; identity?: InboundMtlsIdentity } | { proceed: false } => {
    const cfg = inboundMtls;
    if (cfg === undefined) return { proceed: true };
    const peer = extractPeerCertInfo(req.socket as TLSSocket);
    const decision = decideInboundMtls(cfg, peer, isOperatorRoute);
    if (decision.allowed) {
      return decision.identity === undefined ? { proceed: true } : { proceed: true, identity: decision.identity };
    }
    const id = randomUUID();
    // Resolve the trace ID the same way the intake pipeline does, so the
    // rejection stays traceable.
    const inboundTrace =
      traceContextOpts === undefined
        ? undefined
        : parseInboundTraceContext(req.headers[TRACEPARENT_HEADER], req.headers[TRACESTATE_HEADER]);
    const traceId = inboundTrace?.traceId ?? resolveTraceId(req.headers[TRACE_ID_HEADER]);
    opts.auditLog.append({
      event: "rejected",
      id,
      traceId,
      reason: decision.reason,
      path: pathname,
      ...(decision.fingerprint !== undefined
        ? { clientCertFingerprint: decision.fingerprint, clientCertSubject: decision.subject ?? "" }
        : {}),
    });
    res
      .writeHead(401, { "content-type": "application/json", connection: "close" })
      .end(
        JSON.stringify({
          error:
            decision.reason === "client_cert_required"
              ? "client certificate required"
              : "client certificate invalid",
          reason: decision.reason,
        })
      );
    return { proceed: false };
  };

  /**
   * WR-112: mesh-link mTLS (opt-in) inbound gate.
   *
   * A request that presents `x-relay-signature` claims to be a mesh
   * peer; when `mesh.mtls` is enabled that claim is only honored with a
   * client certificate verified through the inbound-mtls chain
   * (`decideInboundMtls` against the CA + fingerprint whitelist, with
   * the certificate required on the mesh path — `meshMtlsInbound`).
   * Plain producers (`x-signature`, no relay signature) never enter this
   * gate: mesh mTLS authenticates the relay-to-relay link, not webhook
   * ingest.
   *
   * Like the WR-103 gate this enforces at request time (the listener
   * runs `rejectUnauthorized: false`), so a rejection is a proper 401
   * with a machine-readable reason instead of a bare TLS alert. Denials
   * are audited as `rejected` with reason `mesh_mtls_reject` and counted
   * on `relay_mesh_mtls_rejects_total{path}`; the connection is closed,
   * since the caller must re-handshake with a different certificate.
   *
   * Returns the verified peer identity for the audit trail when the
   * request may proceed.
   */
  const enforceMeshMtls = (
    req: Parameters<Parameters<typeof createServer>[0]>[0],
    res: Parameters<Parameters<typeof createServer>[0]>[1],
    pathname: string
  ): { proceed: true; identity?: InboundMtlsIdentity } | { proceed: false } => {
    if (meshMtlsInbound === undefined) return { proceed: true };
    const rawSig = req.headers["x-relay-signature"];
    const firstSig = Array.isArray(rawSig) ? rawSig[0] : rawSig;
    if (typeof firstSig !== "string" || firstSig === "") return { proceed: true };
    const peer = extractPeerCertInfo(req.socket as TLSSocket);
    const decision = decideInboundMtls(meshMtlsInbound, peer, false);
    if (decision.allowed) {
      return decision.identity === undefined
        ? { proceed: true }
        : { proceed: true, identity: decision.identity };
    }
    const id = randomUUID();
    const traceId = resolveTraceId(req.headers[TRACE_ID_HEADER]);
    meshMetrics.recordMtlsRejected(pathname);
    opts.auditLog.append({
      event: "rejected",
      id,
      traceId,
      reason: "mesh_mtls_reject",
      path: pathname,
      ...(decision.fingerprint !== undefined
        ? { clientCertFingerprint: decision.fingerprint, clientCertSubject: decision.subject ?? "" }
        : {}),
    });
    res
      .writeHead(401, { "content-type": "application/json", connection: "close" })
      .end(
        JSON.stringify({
          error: "mesh peer client certificate required",
          reason: "mesh_mtls_reject",
        })
      );
    return { proceed: false };
  };

  // WR-103: which listeners terminate TLS. The mTLS gate above is
  // enforced at request time, so a listener only needs TLS when some
  // route it serves can require a client certificate:
  // - `requireCert` → every route on every listener requires one, so
  //   both planes become HTTPS;
  // - `operatorMtls` alone → only the operator listener becomes HTTPS;
  //   on the legacy single plane the shared listener must become HTTPS
  //   (operator paths live on it) while ingest routes stay open without
  //   a certificate.
  // Untouched when `inboundMtls` is unconfigured: plain HTTP everywhere,
  // exactly the pre-WR-103 behavior.
  const mtlsCfg = inboundMtls;
  const inboundMtlsListenerOpts =
    mtlsCfg !== undefined ? inboundMtlsServerOptions(mtlsCfg) : undefined;
  const intakeListenerTls =
    mtlsCfg !== undefined &&
    (mtlsCfg.requireCert || (operatorPlane === undefined && mtlsCfg.operatorMtls));
  const operatorListenerTls =
    mtlsCfg !== undefined && (mtlsCfg.requireCert || mtlsCfg.operatorMtls);
  /** HTTPS listeners, for `setSecureContext()` on hot-reload. */
  const tlsListeners: TlsServer[] = [];
  const createListener = (
    handler: (
      req: Parameters<Parameters<typeof createServer>[0]>[0],
      res: Parameters<Parameters<typeof createServer>[0]>[1]
    ) => Promise<void>,
    useTls: boolean
  ): RelayServer => {
    // WR-160: `maxHeaderSize` is construction-time only, so it rides the
    // createServer/createHttpsServer options; the timeouts + clientError
    // audit hook are applied after construction.
    const serverOptions =
      hardening?.maxHeaderSizeBytes !== undefined
        ? { maxHeaderSize: hardening.maxHeaderSizeBytes }
        : undefined;
    let listener: RelayServer;
    if (useTls && inboundMtlsListenerOpts !== undefined) {
      const httpsServer =
        serverOptions !== undefined
          ? createHttpsServer({ ...inboundMtlsListenerOpts, ...serverOptions }, handler)
          : createHttpsServer(inboundMtlsListenerOpts, handler);
      tlsListeners.push(httpsServer);
      listener = httpsServer as unknown as RelayServer;
    } else {
      listener = (
        serverOptions !== undefined ? createServer(serverOptions, handler) : createServer(handler)
      ) as RelayServer;
    }
    if (hardening !== undefined) {
      applyHttpHardening(listener, hardening, opts.auditLog);
    }
    return listener;
  };

  let server: RelayServer;
  let operatorServer: Server | undefined;
  if (operatorPlane === undefined) {
    // Legacy single-plane behavior: one listener serves operator paths
    // and webhooks alike.
    server = createListener(async (req, res) => {
      const pathname = new URL(req.url ?? "/", "http://internal").pathname;
      if (isOperatorPath(pathname)) {
        // WR-159: CORS preflight short-circuits before auth (browsers
        // never send credentials/client certs on preflights); actual
        // operator responses to allowlisted origins carry the CORS
        // headers. Disabled when no `cors` policy is configured.
        if (corsPolicy !== undefined && answerCorsPreflight(req, res, corsPolicy)) return;
        if (corsPolicy !== undefined) setCorsResponseHeaders(req, res, corsPolicy);
        const gate = enforceInboundMtls(req, res, pathname, true);
        if (!gate.proceed) return;
        await guardOperator(req, res, pathname);
        return;
      }
      // WR-112: mesh-link mTLS runs before the WR-103 gate — a request
      // claiming to be a mesh peer (x-relay-signature) is judged by the
      // mesh gate alone (missing/invalid cert → 401 mesh_mtls_reject);
      // anything without the claim falls through untouched.
      const meshGate = enforceMeshMtls(req, res, pathname);
      if (!meshGate.proceed) return;
      const gate = enforceInboundMtls(req, res, pathname, false);
      if (!gate.proceed) return;
      await handleInbound(req, res, pathname, gate.identity ?? meshGate.identity);
    }, intakeListenerTls);
  } else {
    // Split plane (WR-56): operator paths hit on the intake listener are
    // indistinguishable from unknown paths — the operator plane's
    // existence is not revealed — and the operator listener 404s anything
    // that is not an operator path, so it can never accept a webhook.
    server = createListener(async (req, res) => {
      const pathname = new URL(req.url ?? "/", "http://internal").pathname;
      if (isOperatorPath(pathname)) {
        crossPlaneNotFound(res);
        return;
      }
      // WR-112: mesh-link mTLS before the WR-103 gate (same rationale as
      // the single-plane listener above).
      const meshGate = enforceMeshMtls(req, res, pathname);
      if (!meshGate.proceed) return;
      const gate = enforceInboundMtls(req, res, pathname, false);
      if (!gate.proceed) return;
      await handleInbound(req, res, pathname, gate.identity ?? meshGate.identity);
    }, intakeListenerTls);
    operatorServer = createListener(async (req, res) => {
      const pathname = new URL(req.url ?? "/", "http://internal").pathname;
      if (!isOperatorPath(pathname)) {
        crossPlaneNotFound(res);
        return;
      }
      // WR-159: CORS preflight short-circuits before auth; see the
      // single-plane listener above for the rationale.
      if (corsPolicy !== undefined && answerCorsPreflight(req, res, corsPolicy)) return;
      if (corsPolicy !== undefined) setCorsResponseHeaders(req, res, corsPolicy);
      const gate = enforceInboundMtls(req, res, pathname, true);
      if (!gate.proceed) return;
      await guardOperator(req, res, pathname);
    }, operatorListenerTls) as unknown as Server;
    server.operatorServer = operatorServer;
    // The operator port is fully specified in the options, so the relay
    // binds it itself at creation; the caller only ever binds the intake
    // plane with `listen()`.
    operatorServer.listen(operatorPlane.port, operatorPlane.host ?? "127.0.0.1");
  }

  /**
   * Inbound WebSocket event intake (WR-130).
   *
   * `ws(s)://` upgrade endpoint: one long-lived client connection pushes
   * one text frame per event (a JSON envelope shaped exactly like a WR-61
   * batch item: `{ "payload": "<base64>", "headers": { … } }`). Each event
   * walks the full intake pipeline through `admitOneEvent` — signature
   * verification (HMAC/Ed25519/rotation), per-endpoint API keys, tenant,
   * gzip budget, schema, replay guard, dedup, enqueue — and the server
   * answers with a text frame `{ "type": "event-ack", "status":
   * "accepted" | "rejected", … }` mirroring the HTTP 202 / 4xx outcome.
   *
   * Transport mapping vs. HTTP:
   * - the upgrade request carries the connection-level headers
   *   (`x-relay-*`, `x-api-key`, `x-trace-id`); each envelope's headers
   *   overlay them per event (lowercased — JSON gets no node header
   *   normalization);
   * - the WR-53 IP ACL and WR-65 API-key gates run once at upgrade (they
   *   see headers only); the WR-22 rate limiter runs per event, before
   *   signature verification, like one HTTP request's gate check;
   * - the `maxBodyBytes` / `endpointBodyLimits` budget caps each decoded
   *   event body (413 + close, like the HTTP `connection: close`);
   * - server pings keep the connection alive, an idle connection is
   *   closed, and a client whose outbound buffer passes 1MiB is dropped
   *   like a slow SSE `/events` consumer.
   *
   * The handler is attached to the intake listener only — in split-plane
   * mode the operator plane never upgrades — and a TLS-terminating
   * intake listener serves `wss://` on the same port with no extra
   * configuration.
   */
  interface InboundWsHandle {
    /** Tear the connection down: audit once, send a close frame, destroy. */
    tearDown: (auditReason: string, code: number, reasonText: string) => void;
  }
  /** Live inbound WS connections — the server close path drains them. */
  const inboundWsHandles = new Set<InboundWsHandle>();
  /** Slow-consumer guard shared with SSE `/events`: 1MiB of unflushed bytes. */
  const INBOUND_WS_SLOW_CONSUMER_BYTES = 1_048_576;

  const openInboundWsConnection = (
    wsOpts: ResolvedInboundWsOptions,
    req: IncomingMessage,
    socket: Socket,
    mtlsIdentity?: InboundMtlsIdentity
  ): void => {
    const connId = randomUUID();
    // WR-98: a propagated W3C trace id wins, then a client-supplied
    // x-trace-id, otherwise fresh — resolved before any admission
    // decision so even rejections stay traceable, like the HTTP intake.
    const inboundTrace =
      traceContextOpts === undefined
        ? undefined
        : parseInboundTraceContext(req.headers[TRACEPARENT_HEADER], req.headers[TRACESTATE_HEADER]);
    const connTraceId = inboundTrace?.traceId ?? resolveTraceId(req.headers[TRACE_ID_HEADER]);
    const clientIp = socket.remoteAddress ?? "unknown";

    const rejectUpgradeHttp = (status: number, statusText: string, body: string): void => {
      if (!socket.destroyed) {
        socket.write(
          `HTTP/1.1 ${status} ${statusText}\r\n` +
            "content-type: text/plain\r\n" +
            `content-length: ${Buffer.byteLength(body)}\r\n` +
            "connection: close\r\n\r\n" +
            body
        );
      }
      socket.destroy();
    };

    // Inbound IP allowlist/denylist (WR-53): the outermost admission gate —
    // on the upgrade headers alone, before the handshake completes, so a
    // hostile IP costs zero bandwidth and zero downstream state.
    if (ipAcl !== undefined) {
      const aclIp = ipAcl.clientIp(socket.remoteAddress, req.headers["x-forwarded-for"]);
      const aclVerdict = ipAcl.check(wsOpts.path, aclIp);
      if (!aclVerdict.ok) {
        ipAclMetrics.record(aclVerdict.pattern);
        opts.auditLog.append({
          event: "rejected",
          id: connId,
          traceId: connTraceId,
          reason: "ip_denied",
          ip: aclIp,
          endpoint: aclVerdict.pattern,
        });
        rejectUpgradeHttp(403, "Forbidden", "Forbidden");
        return;
      }
    }

    // Inbound per-endpoint API key authentication (WR-65): the second
    // admission gate — on the upgrade headers alone, like the WR-53 gate.
    // The matched key rides `admitOneEvent` per event, exactly as if each
    // frame were its own HTTP request.
    let wsApiKey: { keyId: string; rule: EndpointApiKeyRule } | undefined;
    if (apiKeyAuth !== undefined) {
      const rule = apiKeyAuth.ruleFor(wsOpts.path);
      if (rule !== undefined) {
        const presentedRaw = req.headers["x-api-key"];
        const presented = Array.isArray(presentedRaw) ? presentedRaw[0] : presentedRaw;
        if (typeof presented !== "string" || presented === "") {
          opts.auditLog.append({
            event: "rejected",
            id: connId,
            traceId: connTraceId,
            reason: "api_key_missing",
            keyId: "unknown",
            endpoint: rule.pattern,
          });
          rejectUpgradeHttp(401, "Unauthorized", "Unauthorized");
          return;
        }
        const matchedId = apiKeyAuth.verifyKey(rule, presented);
        if (matchedId === null) {
          opts.auditLog.append({
            event: "rejected",
            id: connId,
            traceId: connTraceId,
            reason: "api_key_invalid",
            keyId: "unknown",
            endpoint: rule.pattern,
          });
          rejectUpgradeHttp(401, "Unauthorized", "Unauthorized");
          return;
        }
        wsApiKey = { keyId: matchedId, rule };
      }
    }

    // Inbound per-endpoint body size budget (WR-102): resolved from headers
    // alone, so the endpoint's own budget governs every frame on the
    // connection — the transport layer, orthogonal to schema validation.
    const bodyBudget = selectEndpointBodyLimit(wsOpts.path, opts.endpointBodyLimits) ?? maxBodyBytes;

    // WR-152: inbound permessage-deflate negotiation — only when opted
    // in, and only when the client offers it. The offer must carry both
    // no-context-takeover parameters (strict, like the WR-46 outbound
    // convention); a violating offer fails the upgrade with 400, like any
    // other handshake violation — never silently mis-negotiated.
    let inboundDeflate: NegotiatedInboundDeflate | null = null;
    if (wsOpts.permessageDeflate !== undefined) {
      const extRaw = req.headers["sec-websocket-extensions"];
      const extHeader = Array.isArray(extRaw) ? extRaw[0] : extRaw;
      try {
        inboundDeflate = negotiateInboundPerMessageDeflate(extHeader);
      } catch (err) {
        const detail = (err as Error).message;
        opts.auditLog.append({
          event: "rejected",
          id: connId,
          traceId: connTraceId,
          reason: "ws_deflate_negotiation_failed",
          detail,
          path: wsOpts.path,
        });
        rejectUpgradeHttp(400, "Bad Request", `permessage-deflate negotiation failed: ${detail}`);
        return;
      }
    }

    const keyRaw = req.headers["sec-websocket-key"];
    const clientKey = (Array.isArray(keyRaw) ? keyRaw[0] : keyRaw) ?? "";
    socket.write(
      "HTTP/1.1 101 Switching Protocols\r\n" +
        "Upgrade: websocket\r\n" +
        "Connection: Upgrade\r\n" +
        `Sec-WebSocket-Accept: ${inboundWsAcceptKey(clientKey)}\r\n` +
        (inboundDeflate === null ? "" : `Sec-WebSocket-Extensions: ${INBOUND_DEFLATE_ACCEPT}\r\n`) +
        "\r\n"
    );
    socket.setNoDelay(true);

    opts.auditLog.append({
      event: "ws_connected",
      id: connId,
      traceId: connTraceId,
      path: wsOpts.path,
      ip: clientIp,
      ...(wsApiKey === undefined ? {} : { keyId: wsApiKey.keyId }),
      // WR-132: the verified client identity rides the connection audit,
      // exactly as it rides `accepted` events on the HTTP intake.
      ...(mtlsIdentity === undefined
        ? {}
        : {
            clientCertFingerprint: mtlsIdentity.fingerprint,
            clientCertSubject: mtlsIdentity.subject,
          }),
    });

    // WR-152: the parser knows whether permessage-deflate was negotiated —
    // RSV1 on a data frame then marks a compressed message.
    const parser = new InboundWsParser(wsOpts.maxMessageBytes, inboundDeflate !== null);
    let lastActivity = Date.now();
    let tornDown = false;
    let timer: ReturnType<typeof setInterval> | undefined;
    // WR-152: ordered outbound frame queue — ack compression is async, so
    // every outbound data frame *and* the close frame ride one chain and
    // keep call order on the wire (a 413 ack is never overtaken by the
    // close that follows it).
    let sendQueue: Promise<void> = Promise.resolve();

    const tearDown = (auditReason: string, code: number, reasonText: string): void => {
      if (tornDown) return;
      tornDown = true;
      if (timer !== undefined) clearInterval(timer);
      inboundWsHandles.delete(handle);
      opts.auditLog.append({
        event: "ws_disconnected",
        id: connId,
        traceId: connTraceId,
        reason: auditReason,
        path: wsOpts.path,
      });
      // Drain through the frame queue so pending acks land before the
      // close frame, preserving call order across async compression.
      sendQueue = sendQueue.then(() => {
        if (socket.destroyed) return;
        try {
          socket.write(wsCloseFrame(code, reasonText), () => socket.destroy());
          // If the peer never drains, don't linger: the audit is written.
          const killer = setTimeout(() => socket.destroy(), 1000);
          (killer as unknown as { unref?: () => unknown }).unref?.();
        } catch {
          socket.destroy();
        }
      });
    };
    const handle: InboundWsHandle = { tearDown };
    inboundWsHandles.add(handle);

    const sendJson = (obj: Record<string, unknown>): boolean => {
      // Slow-consumer guard — the same 1MiB policy as SSE `/events`: a
      // client that cannot keep up is disconnected instead of buffering
      // without bound.
      if (socket.writableLength > INBOUND_WS_SLOW_CONSUMER_BYTES) {
        tearDown("slow_consumer", 1011, "slow consumer");
        return false;
      }
      if (tornDown || socket.destroyed) return false;
      // WR-152: opportunistically deflate the ack when permessage-deflate
      // was negotiated — small acks ride untouched, large ones compress;
      // deflate never expands the wire.
      const frame = wsDeflatedTextFrame(
        JSON.stringify(obj),
        inboundDeflate === null ? undefined : wsOpts.permessageDeflate
      );
      sendQueue = sendQueue.then(async () => {
        try {
          // No tornDown check here: a frame queued before tearDown (e.g.
          // the 413 ack ahead of its 1009 close) must still go out — the
          // queue order is the correctness mechanism, and a dead socket
          // is covered by the destroyed check below.
          if (socket.destroyed) return;
          socket.write(await frame);
        } catch {
          // Best-effort: one failed ack must not stall later frames.
        }
      });
      return true;
    };

    const touch = (): void => {
      lastActivity = Date.now();
    };

    const onTextMessage = (data: Buffer): void => {
      let raw: unknown;
      try {
        raw = JSON.parse(data.toString("utf8"));
      } catch {
        sendJson({
          type: "event-error",
          code: 400,
          reason: "malformed_envelope",
          id: randomUUID(),
          traceId: connTraceId,
        });
        return;
      }
      const eventId = randomUUID();
      const checked = checkIngestBatchItem(raw);
      if (!("item" in checked)) {
        opts.auditLog.append({
          event: "rejected",
          id: eventId,
          traceId: connTraceId,
          reason: "invalid_item",
          detail: checked.problem,
          path: wsOpts.path,
        });
        sendJson({
          type: "event-error",
          code: 400,
          reason: checked.problem,
          id: eventId,
          traceId: connTraceId,
        });
        return;
      }
      if (checked.body.length > bodyBudget) {
        // Like the HTTP intake's 413: the event is dead and the
        // connection goes with it (flood protection).
        opts.auditLog.append({
          event: "rejected",
          id: eventId,
          traceId: connTraceId,
          reason: "body_too_large",
          path: wsOpts.path,
        });
        sendJson({
          type: "event-ack",
          status: "rejected",
          id: eventId,
          traceId: connTraceId,
          code: 413,
          reason: "body_too_large",
        });
        tearDown("message_too_large", 1009, "message exceeds the intake body budget");
        return;
      }
      // Per-event headers: the upgrade request's headers with the
      // envelope's per-event headers overlaid (lowercased — a JSON object
      // gets none of node's header normalization). `x-relay-*` and other
      // connection-level headers ride the upgrade request and apply to
      // every event on the connection.
      const headers: Record<string, string | string[] | undefined> = { ...req.headers };
      for (const [k, v] of Object.entries(checked.item.headers ?? {})) {
        headers[k.toLowerCase()] = v;
      }
      // WR-98: per-event W3C trace context, like the batch items — gated
      // on the option, never a 400. A per-event x-trace-id wins, then the
      // connection's trace id (never a fresh one per event — the frames
      // share the connection's trace by default).
      const itemTrace =
        traceContextOpts === undefined
          ? undefined
          : parseInboundTraceContext(headers[TRACEPARENT_HEADER], headers[TRACESTATE_HEADER]);
      const traceId = itemTrace?.traceId ?? resolveTraceId(headers[TRACE_ID_HEADER] ?? connTraceId);
      // WR-22 per-event inbound rate limit — the WS analogue of one HTTP
      // request's gate check, before signature verification.
      const limitCheck = checkInboundRateLimit(
        clientIp,
        wsApiKey?.keyId ?? "anonymous",
        eventId,
        traceId
      );
      if (!limitCheck.ok) {
        sendJson({
          type: "event-ack",
          status: "rejected",
          id: eventId,
          traceId,
          code: 429,
          reason: "rate_limited",
          // Ceiling seconds, minimum 1: a Retry-After of 0 is meaningless
          // (the WR-22 convention, without a header to carry it).
          retryAfter: Math.max(1, Math.ceil(limitCheck.retryAfterMs / 1000)),
        });
        return;
      }
      void admitOneEvent(
        eventId,
        traceId,
        checked.body,
        headers,
        wsOpts.path,
        {},
        wsApiKey,
        itemTrace,
        bodyBudget
      )
        .then((outcome) => {
          if (tornDown) return;
          const ack: Record<string, unknown> =
            outcome.status === 202
              ? {
                  type: "event-ack",
                  status: "accepted",
                  id: outcome.id,
                  traceId: outcome.traceId,
                  ...(outcome.duplicate === true ? { duplicate: true } : {}),
                  ...(outcome.tenantId === undefined ? {} : { tenant: outcome.tenantId }),
                  ...(outcome.scheduledAt === undefined
                    ? {}
                    : {
                        scheduled: true,
                        deliverAt: new Date(outcome.scheduledAt).toISOString(),
                      }),
                  ...(outcome.scheduleId === undefined
                    ? {}
                    : {
                        scheduled: true,
                        recurring: true,
                        scheduleId: outcome.scheduleId,
                        cron: outcome.cron,
                        ...(outcome.nextAt === undefined
                          ? {}
                          : { nextAt: new Date(outcome.nextAt).toISOString() }),
                      }),
                }
              : {
                  type: "event-ack",
                  status: "rejected",
                  id: outcome.id,
                  traceId: outcome.traceId,
                  code: outcome.status,
                  ...(outcome.reason === undefined ? {} : { reason: outcome.reason }),
                  ...(outcome.retryAfterMs === undefined
                    ? {}
                    : {
                        retryAfter: Math.max(1, Math.ceil(outcome.retryAfterMs / 1000)),
                      }),
                };
          if (!sendJson(ack)) return;
          if (outcome.closeConnection === true) {
            // The admission wants the connection gone (the HTTP intake
            // would have answered `connection: close`).
            tearDown("admission_close", 1000, "rejected");
          }
        })
        .catch(() => {
          if (tornDown) return;
          opts.auditLog.append({
            event: "rejected",
            id: eventId,
            traceId,
            reason: "internal_error",
            path: wsOpts.path,
          });
          sendJson({
            type: "event-error",
            code: 500,
            reason: "internal_error",
            id: eventId,
            traceId,
          });
        });
    };

    const onMessage = (msg: InboundWsMessage): void => {
      switch (msg.kind) {
        case "ping":
          touch();
          if (!tornDown && !socket.destroyed) socket.write(wsPongFrame(msg.data));
          return;
        case "pong":
          touch();
          return;
        case "close":
          tearDown("client_close", 1000, "");
          return;
        case "binary":
          opts.auditLog.append({
            event: "rejected",
            id: randomUUID(),
            traceId: connTraceId,
            reason: "ws_binary_unsupported",
            path: wsOpts.path,
          });
          tearDown("unsupported_data", 1003, "binary frames are not supported");
          return;
        case "text":
          touch();
          onTextMessage(msg.data);
          return;
      }
    };

    // WR-152: ordered message delivery — decompression is async, so
    // compressed messages inflate on this chain and keep their arrival
    // order against later uncompressed ones. A corrupt or truncated
    // compressed frame fails the connection on the WR-130 protocol-error
    // channel (1002); an inflated message past the reassembly cap fails
    // with 1009 (decompression-bomb guard). WR-161 adds the inflate-time
    // guard: a frame that expands past `maxInflatedBytes` is destroyed
    // mid-accumulation and fails with 1009 before it can materialize as
    // a full Buffer.
    let processQueue: Promise<void> = Promise.resolve();
    const deliverMessage = (msg: InboundWsMessage): void => {
      const run = async (): Promise<void> => {
        if (tornDown) return;
        if ((msg.kind === "text" || msg.kind === "binary") && msg.compressed) {
          let data: Buffer;
          try {
            data = await decompressMessage(msg.data, wsOpts.permessageDeflate?.maxInflatedBytes);
          } catch (err) {
            if (err instanceof WsInflateBombError) {
              opts.auditLog.append({
                event: "rejected",
                id: randomUUID(),
                traceId: connTraceId,
                reason: "ws_inflate_bomb",
                path: wsOpts.path,
              });
              tearDown("inflate_bomb", 1009, "decompressed message exceeds maxInflatedBytes");
              return;
            }
            opts.auditLog.append({
              event: "rejected",
              id: randomUUID(),
              traceId: connTraceId,
              reason: "ws_protocol_error",
              detail: "permessage-deflate decompression failed",
              path: wsOpts.path,
            });
            tearDown("protocol_error", 1002, "permessage-deflate decompression failed");
            return;
          }
          if (data.length > wsOpts.maxMessageBytes) {
            opts.auditLog.append({
              event: "rejected",
              id: randomUUID(),
              traceId: connTraceId,
              reason: "ws_protocol_error",
              detail: "decompressed message exceeds the cap",
              path: wsOpts.path,
            });
            tearDown("protocol_error", 1009, "decompressed message exceeds the cap");
            return;
          }
          msg = { ...msg, data, compressed: false };
        }
        onMessage(msg);
      };
      // Keep the chain alive even if one link throws — no unhandled
      // rejections, no stalled delivery.
      processQueue = processQueue.then(run, run).then(undefined, () => undefined);
    };

    socket.on("data", (chunk: Buffer) => {
      if (tornDown) return;
      let messages: InboundWsMessage[];
      try {
        messages = parser.push(chunk);
      } catch (err) {
        if (err instanceof WsProtocolError) {
          opts.auditLog.append({
            event: "rejected",
            id: randomUUID(),
            traceId: connTraceId,
            reason: "ws_protocol_error",
            detail: err.message,
            path: wsOpts.path,
          });
          tearDown("protocol_error", err.closeCode, err.message);
        } else {
          tearDown("transport_error", 1011, "internal error");
        }
        return;
      }
      for (const msg of messages) {
        if (tornDown) break;
        deliverMessage(msg);
      }
    });
    socket.on("close", () => tearDown("transport_close", 1000, ""));
    socket.on("error", () => {});

    // Ping/pong keep-alive + idle timeout. The timer ticks at the finer of
    // the two configured intervals so an idle connection is reaped
    // promptly even when server pings are disabled. Only inbound frames
    // count as activity — our own pings never keep a dead peer alive.
    const tickMs = Math.min(
      wsOpts.pingIntervalMs > 0 ? wsOpts.pingIntervalMs : wsOpts.idleTimeoutMs,
      wsOpts.idleTimeoutMs
    );
    timer = setInterval(() => {
      if (tornDown) return;
      if (wsOpts.pingIntervalMs > 0 && !socket.destroyed) {
        socket.write(wsPingFrame());
      }
      if (Date.now() - lastActivity > wsOpts.idleTimeoutMs) {
        tearDown("idle_timeout", 1000, "idle timeout");
      }
    }, tickMs);
    (timer as unknown as { unref?: () => unknown }).unref?.();
  };

  /**
   * WR-132: the WR-103 inbound-mTLS gate for the `ws(s)://` upgrade
   * path. HTTP upgrade requests never reach `createListener`'s
   * (req, res) handler, so `enforceInboundMtls` cannot run on them —
   * without this gate a WS client could upgrade anonymously while
   * `requireCert: true` rejects the identical HTTP request. Same
   * `decideInboundMtls` semantics and the same `rejected` audit event,
   * but the 401 is written directly on the upgrade socket (an upgrade
   * can never produce a normal HTTP response; the connection closes
   * either way). Runs right after the path check, before handshake
   * validation — authentication precedes protocol details, exactly as
   * the WR-103 gate runs before routing on the HTTP intake.
   */
  const enforceInboundMtlsForWsUpgrade = (
    req: IncomingMessage,
    socket: Socket,
    pathname: string
  ): { proceed: true; identity?: InboundMtlsIdentity } | { proceed: false } => {
    const cfg = inboundMtls;
    if (cfg === undefined) return { proceed: true };
    const peer = extractPeerCertInfo(req.socket as TLSSocket);
    const decision = decideInboundMtls(cfg, peer, false);
    if (decision.allowed) {
      return decision.identity === undefined
        ? { proceed: true }
        : { proceed: true, identity: decision.identity };
    }
    const id = randomUUID();
    const inboundTrace =
      traceContextOpts === undefined
        ? undefined
        : parseInboundTraceContext(req.headers[TRACEPARENT_HEADER], req.headers[TRACESTATE_HEADER]);
    const traceId = inboundTrace?.traceId ?? resolveTraceId(req.headers[TRACE_ID_HEADER]);
    opts.auditLog.append({
      event: "rejected",
      id,
      traceId,
      reason: decision.reason,
      path: pathname,
      ...(decision.fingerprint !== undefined
        ? { clientCertFingerprint: decision.fingerprint, clientCertSubject: decision.subject ?? "" }
        : {}),
    });
    const body = JSON.stringify({
      error:
        decision.reason === "client_cert_required"
          ? "client certificate required"
          : "client certificate invalid",
      reason: decision.reason,
    });
    if (!socket.destroyed) {
      socket.write(
        "HTTP/1.1 401 Unauthorized\r\n" +
          "content-type: application/json\r\n" +
          `content-length: ${Buffer.byteLength(body)}\r\n` +
          "connection: close\r\n\r\n" +
          body
      );
    }
    socket.destroy();
    return { proceed: false };
  };

  const handleInboundWsUpgrade = (req: IncomingMessage, rawSocket: unknown): void => {
    const wsOpts = inboundWs;
    const socket = rawSocket as Socket;
    if (wsOpts === undefined) {
      socket.destroy();
      return;
    }
    let pathname = "/";
    try {
      pathname = new URL(req.url ?? "/", "http://internal").pathname;
    } catch {
      socket.destroy();
      return;
    }
    if (pathname !== wsOpts.path) {
      // Not our upgrade endpoint — nothing else serves upgrades, so drop
      // it instead of leaking a half-open socket.
      socket.destroy();
      return;
    }
    // WR-132: the WR-103 mTLS gate applies to upgrades too — a client
    // without (or with an invalid) certificate is rejected here, with
    // the same 401 semantics and `rejected` audit event as the HTTP
    // intake.
    const mtlsGate = enforceInboundMtlsForWsUpgrade(req, socket, pathname);
    if (!mtlsGate.proceed) return;
    const hs = checkInboundWsHandshake(req.headers);
    if (!hs.ok) {
      const connId = randomUUID();
      const traceId = resolveTraceId(req.headers[TRACE_ID_HEADER]);
      opts.auditLog.append({
        event: "rejected",
        id: connId,
        traceId,
        reason: "ws_handshake_invalid",
        detail: hs.reason,
        path: wsOpts.path,
      });
      // RFC 6455 §4.2.1: an unsupported version gets 426 with the version
      // the server speaks; anything else is a plain 400.
      const versionMismatch = hs.reason === "unsupported_version";
      const status = versionMismatch ? 426 : 400;
      const statusText = versionMismatch ? "Upgrade Required" : "Bad Request";
      const body = `websocket upgrade required (${hs.reason})`;
      const versionHeader = versionMismatch ? "sec-websocket-version: 13\r\n" : "";
      socket.write(
        `HTTP/1.1 ${status} ${statusText}\r\n` +
          "content-type: text/plain\r\n" +
          versionHeader +
          `content-length: ${Buffer.byteLength(body)}\r\n` +
          "connection: close\r\n\r\n" +
          body
      );
      socket.destroy();
      return;
    }
    try {
      openInboundWsConnection(wsOpts, req, socket, mtlsGate.identity);
    } catch {
      socket.destroy();
    }
  };

  if (inboundWs !== undefined) {
    server.on("upgrade", (req, socket) => {
      handleInboundWsUpgrade(req, socket as unknown as Socket);
    });
  }

  server.on("close", () => {
    queue.stop();
    // WR-90: halt the audit-sink worker with the server — no new polls,
    // in-flight POSTs abandoned (the cursor does not advance, so the
    // next start redelivers them).
    auditSink?.stop();
    // WR-157: same for the syslog sink — in-flight sends abandoned,
    // sockets destroyed, the cursor left for the next start.
    syslogSink?.stop();
    // Pooled outbound connections must not outlive the server: close them
    // (and stop the idle reaper) on the same close path that stops the
    // queue — this covers stop() and the graceful-shutdown drain alike.
    // Idle pool sockets are unref'd anyway, so even a missed close cannot
    // pin process exit.
    // WR-56: the returned (intake) server owns the operator plane's
    // lifecycle — closing it closes the operator listener too.
    if (operatorServer?.listening) operatorServer.close();
    defaultSender?.destroy();
    // WR-130: drain inbound WebSocket intake connections with the server —
    // each gets a 1001 close frame before its socket is destroyed.
    for (const handle of [...inboundWsHandles]) {
      handle.tearDown("server_shutdown", 1001, "server shutting down");
    }
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

  // WR-93 runtime loop check: a storm-alert URL that resolves to this
  // relay's own listener would re-enter intake on every threshold
  // crossing and amplify the storm it reports. Same derivation as the
  // WR-47 check above — the configuration-time check (declared
  // `selfOrigins`) ran at queue construction.
  queue.setEscalationSelfCheck(
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
        // WR-89: rotation endpoints warm the primary identity's agent —
        // the agent new handshakes will actually use.
        tlsClientCertRotations: clientCertRotations,
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

  // WR-90: opt-in audit-event webhook sink. Constructed (and started)
  // only when configured — unset means zero forwarding and
  // byte-identical behavior. Invalid options throw RangeError here,
  // never mid-run. Stopped on the same close path as the queue.
  let auditSink: AuditSink | undefined;
  if (opts.auditSink !== undefined) {
    auditSink = new AuditSink(opts.auditLog, opts.auditSink);
    auditSink.start();
  }

  // WR-157: opt-in audit-event syslog sink (SIEM). Same construction
  // contract as the webhook sink above: built and started only when
  // configured, invalid options throw RangeError here, stopped on the
  // same close path as the queue.
  let syslogSink: SyslogAuditSink | undefined;
  if (opts.syslogSink !== undefined) {
    syslogSink = new SyslogAuditSink(opts.auditLog, opts.syslogSink);
    syslogSink.start();
  }

  // WR-103: inbound mTLS hot-reload. The request-time policy
  // (`requireCert` / `operatorMtls` / whitelist) swaps atomically for
  // every subsequent request; the TLS material (key/cert/CA) is pushed
  // into the live HTTPS listeners via `setSecureContext()`, so new
  // handshakes pick it up while already-established connections keep
  // the previous secure context until they reconnect. Enabling or
  // disabling inbound mTLS is NOT hot-swappable (a bound listener
  // cannot change between plain HTTP and HTTPS) and throws `Error`.
  server.updateInboundMtlsConfig = (patch: InboundMtlsConfigPatch): ConfigChange[] => {
    const cfg = inboundMtls;
    if (cfg === undefined) {
      throw new Error(
        "updateInboundMtlsConfig: inbound mTLS is not configured — enabling it requires a restart: " +
          "the listener is created as plain HTTP or HTTPS at startup and a bound socket cannot change modes at runtime"
      );
    }
    // Validate-then-apply: an illegal patch throws RangeError and the
    // live config is left completely intact.
    const { next, changes } = applyInboundMtlsConfigPatch(cfg, patch);
    inboundMtls = next;
    const secureContext = inboundMtlsSecureContext(next);
    for (const listener of tlsListeners) listener.setSecureContext(secureContext);
    // Key material never lands in the audit trail — only field names.
    opts.auditLog.append({
      event: "inbound_mtls_config_updated",
      fields: changes.map((c) => c.field),
    });
    return changes;
  };

  return server;
}
