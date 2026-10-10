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
import type { CompletionCallbackOptions } from "./callback.ts";
import { createBoundAddressSelfCheck } from "./callback.ts";
import { TENANT_ID_HEADER, assertValidTenantId, tenantScopeKey } from "./tenant.ts";
import type { AutoReplayOptions } from "./autoreplay.ts";
import { HttpDeliveryError, parseRetryAfterMs } from "./failure.ts";
import { installGracefulShutdown } from "./shutdown.ts";
import type { PayloadEncryptor } from "./encrypt.ts";
import type { ReplayGuard } from "./replay.ts";
import { DeliveryDeduplicator, type DedupOptions } from "./dedup.ts";
import { InboundRateLimiter, type InboundRateLimitOptions } from "./ratelimit.ts";
import { resolveTraceId, TRACE_ID_HEADER } from "./trace.ts";
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
import { OutboundConnectionPool, type KeepAlivePoolOptions } from "./keepalive.ts";
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
import type { AuditLog } from "./audit.ts";
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
import {
  assertValidCompressOutboundConfig,
  DecompressionFailedError,
  DecompressionTooLargeError,
  gunzipCapped,
  isGzipContentEncoding,
  maybeCompressOutbound,
  type CompressOutboundOptions,
} from "./gzip.ts";

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
   * `POST /dead-letter/:id/replay`, `POST /dead-letter/replay`,
   * the `/dead-letter/auto-replay/*` controls, `GET /audit`,
   * `GET /latency`, `GET /events`, `GET /metrics`,
   * `GET /deliveries/:traceId`). When unset, those
   * endpoints are disabled and answer 404 (fail closed).
   */
  operatorToken?: string;
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
 */
export interface PooledSender extends Sender {
  /** The keep-alive pool, or `undefined` when pooling is disabled. */
  pool: OutboundConnectionPool | undefined;
  /** The HTTP/2 session pool, or `undefined` when H2 is not enabled. */
  http2Pool: Http2SessionPool | undefined;
  /** The WebSocket connection pool (always created). */
  wsPool: WebSocketPool;
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
  websocket?: WebSocketPoolOptions
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
  const wsPool = new WebSocketPool(websocket);

  /**
   * Shared outbound request material: passthrough headers, trace id,
   * compression, the relay signature, and (WR-44) the idempotency key.
   * Both transports stamp the same wire bytes, so an H2 delivery is
   * indistinguishable downstream from an HTTP/1.1 one (a forged inbound
   * `x-relay-signature` was already stripped from the passthrough
   * headers at intake).
   */
  const buildWireRequest = (
    item: RetryItem
  ): { headers: Record<string, string | string[]>; body: Buffer } => {
    const headers: Record<string, string | string[]> = {};
    for (const [k, v] of Object.entries(item.headers)) {
      if (v !== undefined) headers[k] = v;
    }
    // Propagate the trace ID downstream so the next hop can correlate the
    // delivery with this relay's audit trail (overrides a stale inbound
    // value, which is identical anyway after `resolveTraceId`).
    if (item.traceId) headers[TRACE_ID_HEADER] = item.traceId;
    // WR-40: per-endpoint opt-in gzip. Compression happens before
    // signing so `x-relay-signature` covers the exact wire bytes the
    // downstream receives.
    const { body: wireBody, contentEncoding } = maybeCompressOutbound(
      item.payload,
      compressOutbound?.[item.targetUrl]
    );
    if (outboundSigning !== undefined) {
      // Stamp AFTER the passthrough headers: this guarantees the relay's
      // own signature always wins.
      headers["x-relay-signature"] = signSha256(wireBody, outboundSigning.secret);
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
    if (contentEncoding !== undefined) headers["content-encoding"] = contentEncoding;
    headers["content-length"] = String(wireBody.length);
    return { headers, body: wireBody };
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
    proxyUrl: string | undefined
  ): Promise<DownstreamResponse | void> =>
    new Promise((resolve, reject) => {
      // Pooled keep-alive agent for this origin (dedicated agent per pin
      // whitelist, per proxy, and per client identity, so a connection
      // pinned, tunneled, or authenticated for one endpoint can never serve
      // another's). With pooling disabled but a proxy configured, each
      // delivery gets a one-off tunneled agent —
      // fresh tunnel per delivery, destroyed when the request settles.
      let oneOffAgent: HttpAgent | undefined;
      const agent =
        pool?.agentFor(
          url,
          pins,
          proxyUrl,
          clientCert !== undefined ? clientCertIdentity(clientCert) : undefined
        ) ??
        (proxyUrl !== undefined
          ? (oneOffAgent = createProxiedAgent(
              url.protocol === "https:" ? "https" : "http",
              proxyUrl,
              { keepAlive: false, maxSockets: 1, maxFreeSockets: 0 }
            ))
          : undefined);
      const onResponse = (res: Parameters<Parameters<typeof httpsRequest>[2]>[0]): void => {
        // WR-37: capture the response body (capped) so a per-endpoint
        // responseValidator can check its semantics after a 2xx
        // transport success. Non-2xx responses still reject on the
        // status code alone — the validator never sees them.
        const chunks: Buffer[] = [];
        let captured = 0;
        let truncated = false;
        res.on("data", (chunk: Buffer) => {
          if (captured < RESPONSE_CAPTURE_MAX_BYTES) {
            const room = RESPONSE_CAPTURE_MAX_BYTES - captured;
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
            resolve({
              statusCode: res.statusCode,
              body: Buffer.concat(chunks),
              truncated,
            });
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
        const { headers, body: wireBody } = buildWireRequest(item);
        for (const [k, v] of Object.entries(headers)) req.setHeader(k, v);
        req.end(wireBody);
      };

      if (pins === undefined) {
        writePayload();
        return;
      }
      // Normalized once, up front, so the per-handshake path is a plain compare.
      const allowed = pins.map(normalizePin);
      const verifyFreshPin = (tlsSocket: TLSSocket): void => {
        let presented: string;
        try {
          const raw = (tlsSocket.getPeerCertificate() as { raw?: unknown }).raw;
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
          // socket, so fail loudly instead of delivering over it.
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

  /**
   * HTTP/2 delivery (WR-42): one multiplexed stream on the origin's
   * session, stamping the same wire bytes as the HTTP/1.1 path. Any
   * H2-level failure throws Http2UnavailableError, and the dispatcher
   * below retries the delivery over HTTP/1.1 — a delivery is never lost
   * because of H2.
   */
  const deliverViaHttp2 = async (
    item: RetryItem,
    url: URL,
    pins: string[] | undefined,
    clientCert: TlsClientCert | undefined
  ): Promise<DownstreamResponse> => {
    const session = await h2pool!.sessionFor(url, pins, clientCert);
    h2pool!.acquireStream(session);
    try {
      const { headers, body } = buildWireRequest(item);
      const res = await runHttp2Stream(session, {
        method: "POST",
        path: `${url.pathname}${url.search}`,
        headers,
        body,
        captureMaxBytes: RESPONSE_CAPTURE_MAX_BYTES,
      });
      if (res.statusCode >= 200 && res.statusCode < 300) {
        return { statusCode: res.statusCode, body: res.body, truncated: res.truncated };
      }
      // Structured failure, same as the HTTP/1.1 path: the retry queue
      // classifies on the status code and honors a 429's Retry-After.
      throw new HttpDeliveryError(res.statusCode, parseRetryAfterMs(res.headers["retry-after"]));
    } finally {
      h2pool!.releaseStream(session);
    }
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
    const { headers, body } = buildWireRequest(item);
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
      return deliverViaHttp2(item, url, pins, clientCert).catch((err) => {
        if (err instanceof Http2UnavailableError) {
          h2pool!.noteFallback();
          return deliverViaHttp1(item, url, pins, clientCert, proxyUrl);
        }
        throw err;
      });
    }
    return deliverViaHttp1(item, url, pins, clientCert, proxyUrl);
  } as PooledSender;
  sender.pool = pool;
  sender.http2Pool = h2pool;
  sender.wsPool = wsPool;
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
 * Create a minimal webhook relay: verify the `x-signature` header, enqueue
 * the payload into a retry queue, and forward it to `forwardUrl`.
 * Both accepted deliveries and signature rejections are written to the audit log.
 */
export function createRelayServer(opts: RelayServerOptions): Server {
  const latencyOpts = opts.retry?.latency;
  // RangeError on invalid values, at startup — never mid-request.
  const maxBodyBytes = opts.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  if (!Number.isInteger(maxBodyBytes) || maxBodyBytes <= 0) {
    throw new RangeError("createRelayServer: `maxBodyBytes` must be a positive integer");
  }
  // When the caller does not inject a sender, the server owns the default
  // sender — and with it the keep-alive pool, which is closed on server
  // close so pooled outbound connections never outlive the server. The
  // outbound-signing config (validated by createDefaultSender) applies to
  // the default sender only; an injected sender signs on its own.
  const defaultSender =
    opts.sender === undefined
      ? createDefaultSender(opts.tlsPins, opts.outboundKeepAlive, opts.outboundSigning, opts.proxies, opts.tlsClientCerts, opts.compressOutbound, opts.outboundHttp2, opts.outboundIdempotencyKey)
      : undefined;
  const queue = new RetryQueue({
    sender: opts.sender ?? defaultSender,
    ...(opts.retry ?? {}),
    payloadEncryptor: opts.payloadEncryptor ?? opts.retry?.payloadEncryptor,
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
    // Wrap the caller's hook so rounds-exhaustion is always audited, not
    // just observed.
    onAutoReplayAudit: (event) => {
      opts.auditLog.append(event);
      opts.retry?.onAutoReplayAudit?.(event);
    },
    // An explicit server-level `probe` wins over the nested `retry.probe`;
    // either way the queue owns the prober. Wrap the caller's hook so
    // every probe outcome worth auditing lands in the audit log.
    probe: opts.probe ?? opts.retry?.probe,
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
    latency: latencyOpts
      ? {
          ...latencyOpts,
          onSloMiss: (info) => {
            opts.auditLog.append({ event: "slo_missed", ...info });
            latencyOpts.onSloMiss?.(info);
          },
        }
      : undefined,
    onDelivered: (item, attempts) => {
      opts.auditLog.append({
        event: "delivered",
        id: item.id,
        traceId: item.traceId,
        ...(item.tenantId !== undefined ? { tenant: item.tenantId } : {}),
        targetUrl: item.targetUrl,
        attempts,
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
    onDeadLetter: (item, attempts, lastError, failureClass) => {
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
      opts.auditLog.append({ event: "endpoint_config_updated", endpoint, changes });
      opts.retry?.onConfigChange?.(endpoint, changes);
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
  // API version routes are validated once at startup for the same reason.
  const versionRouter =
    opts.versions !== undefined ? new ApiVersionRouter(opts.versions.routes) : undefined;
  const versionMetrics = new VersionMetrics();
  // Schema registry rules are validated once at startup for the same reason.
  assertValidEndpointSchemaRules(opts.payloadSchemas);
  const schemaMetrics = new SchemaMetrics();
  const deduplicator = opts.dedup ? new DeliveryDeduplicator(opts.dedup) : undefined;
  const rateLimiter = opts.rateLimit ? new InboundRateLimiter(opts.rateLimit) : undefined;

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
    if (!opts.operatorToken) {
      respondJson(res, 404, { error: "operator endpoints disabled" });
      return;
    }
    if (req.headers["authorization"] !== `Bearer ${opts.operatorToken}`) {
      respondJson(res, 403, { error: "forbidden" });
      return;
    }
    const isList = pathname === "/dead-letter";
    const isBatchReplay = pathname === "/dead-letter/replay";
    const isAudit = pathname === "/audit";
    const isLatency = pathname === "/latency";
    const isEvents = pathname === "/events";
    const isMetrics = pathname === "/metrics";
    const isAutoStatus = pathname === "/dead-letter/auto-replay/status";
    const isAutoPause = pathname === "/dead-letter/auto-replay/pause";
    const isAutoResume = pathname === "/dead-letter/auto-replay/resume";
    const isAutoTrigger = pathname === "/dead-letter/auto-replay/trigger";
    const isConfigEndpoint = pathname === "/config/endpoint";
    const deliveryMatch = /^\/deliveries\/([^/]+)$/.exec(pathname);
    const replayMatch = /^\/dead-letter\/([^/]+)\/replay$/.exec(pathname);
    if (
      !isList &&
      !isBatchReplay &&
      !isAudit &&
      !isLatency &&
      !isEvents &&
      !isMetrics &&
      !isAutoStatus &&
      !isAutoPause &&
      !isAutoResume &&
      !isAutoTrigger &&
      !isConfigEndpoint &&
      !deliveryMatch &&
      !replayMatch
    ) {
      respondJson(res, 404, { error: "not found" });
      return;
    }
    if (
      !(
        (isList && req.method === "GET") ||
        (isBatchReplay && req.method === "POST") ||
        (isAudit && req.method === "GET") ||
        (isLatency && req.method === "GET") ||
        (isEvents && req.method === "GET") ||
        (isMetrics && req.method === "GET") ||
        (isAutoStatus && req.method === "GET") ||
        (isAutoPause && req.method === "POST") ||
        (isAutoResume && req.method === "POST") ||
        (isAutoTrigger && req.method === "POST") ||
        (isConfigEndpoint && req.method === "POST") ||
        (deliveryMatch && req.method === "GET") ||
        (replayMatch && req.method === "POST")
      )
    ) {
      respondJson(res, 405, { error: "method not allowed" });
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
        .end(queue.renderMetrics() + versionMetrics.render() + schemaMetrics.render());
      return;
    }
    if (isEvents) {
      streamDeliveryEvents(req, res);
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
        const changes = queue.updateEndpointConfig(
          endpoint,
          patch as EndpointConfigPatch,
          tenant as string | undefined
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
    const id = decodeURIComponent(replayMatch![1]);
    if (queue.replayDeadLetter(id)) {
      opts.auditLog.append({ event: "dead_letter_replayed", id });
      respondJson(res, 200, { id, replayed: true });
    } else {
      respondJson(res, 404, { error: "unknown dead-letter id" });
    }
  };

  const server = createServer(async (req, res) => {
    const pathname = new URL(req.url ?? "/", "http://internal").pathname;
    if (
      pathname === "/dead-letter" ||
      pathname.startsWith("/dead-letter/") ||
      pathname === "/audit" ||
      pathname === "/latency" ||
      pathname === "/events" ||
      pathname === "/metrics" ||
      pathname === "/config/endpoint" ||
      pathname.startsWith("/deliveries/")
    ) {
      try {
        await handleOperator(req, res, pathname);
      } catch {
        // Never let an operator-endpoint failure crash the process as an
        // unhandled rejection; the batch replay path rethrows per-item
        // decrypt errors internally, so this is a last-resort guard.
        if (!res.headersSent) {
          respondJson(res, 500, { error: "internal server error" });
        }
      }
      return;
    }
    if (req.method !== "POST") {
      res.writeHead(405, { "content-type": "text/plain" }).end("Method not allowed");
      return;
    }
    const id = randomUUID();
    // Resolve the trace ID before any admission decision so even rejections
    // are traceable; a client-supplied x-trace-id is honored, otherwise fresh.
    const traceId = resolveTraceId(req.headers[TRACE_ID_HEADER]);

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
        return;
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
        return;
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
        return;
      }
      res.writeHead(400, { "content-type": "text/plain" }).end("Bad request");
      return;
    }

    const signatureHeader = req.headers["x-signature"];
    const keyIdHeader = req.headers["x-key-id"];
    const keyIdHint = Array.isArray(keyIdHeader) ? keyIdHeader[0] : keyIdHeader;

    // Per-endpoint verifier selection (WR-29): the request path picks the
    // trusted verifier; anything unmatched falls back to the global one.
    // A mismatch here is answered 401 below and never enqueues, so it can
    // never trip the downstream circuit breaker.
    const activeVerifier = selectEndpointVerifier(pathname, opts.endpointVerifiers) ?? verifier;
    const perEndpointVerifier = activeVerifier !== verifier;

    // With key rotation, learn which key id verified so it can go on the
    // audit trail; otherwise keep the legacy boolean contract.
    let verified = false;
    let verifiedKeyId: string | undefined;
    const rotating = activeVerifier instanceof RotatingHmacVerifier;
    if (rotating) {
      const detail = activeVerifier.verifyDetailed(body, signatureHeader ?? "", { keyId: keyIdHint });
      verified = detail.ok;
      verifiedKeyId = detail.keyId;
    } else {
      verified = activeVerifier.verify(body, signatureHeader ?? "");
    }

    if (!verified) {
      const rejectedEvent: Record<string, unknown> = {
        event: "rejected",
        id,
        traceId,
        reason: "invalid_signature",
      };
      if (rotating) rejectedEvent.keyId = "unknown";
      // Name the verifier that rejected, so a multi-scheme relay's audit
      // trail shows which trust rule fired.
      if (perEndpointVerifier) rejectedEvent.verifier = activeVerifier.name;
      opts.auditLog.append(rejectedEvent);
      res.writeHead(401, { "content-type": "text/plain" }).end("Invalid signature");
      return;
    }

    // Multi-tenant isolation (WR-48): the inbound `x-tenant-id` header
    // claims the tenant for this webhook. It is validated here — after
    // signature verification, so unauthenticated callers learn nothing —
    // and an invalid value is answered 400, never enqueued. Everything
    // below (dedup, the queue, audits) sees the validated tenant.
    const tenantHeader = req.headers[TENANT_ID_HEADER];
    const tenantRaw = Array.isArray(tenantHeader) ? tenantHeader[0] : tenantHeader;
    let tenantId: string | undefined;
    if (tenantRaw !== undefined) {
      try {
        assertValidTenantId(tenantRaw);
        tenantId = tenantRaw;
      } catch {
        opts.auditLog.append({ event: "rejected", id, traceId, reason: "invalid_tenant_id" });
        res.writeHead(400, { "content-type": "text/plain" }).end("Invalid x-tenant-id");
        return;
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
    if (isGzipContentEncoding(req.headers["content-encoding"])) {
      try {
        body = await gunzipCapped(body, maxBodyBytes);
        inboundGzip = true;
      } catch (err) {
        if (err instanceof DecompressionTooLargeError) {
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
          return;
        }
        opts.auditLog.append({
          event: "rejected",
          id,
          traceId,
          reason: "decompression_failed",
          error: err instanceof Error ? err.message : String(err),
        });
        res.writeHead(400, { "content-type": "text/plain" }).end("Invalid gzip body");
        return;
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
          opts.auditLog.append({
            event: "rejected",
            id,
            traceId,
            ...tenantLabel,
            reason: "version_adapt_failed",
            version,
            error: err instanceof Error ? err.message : String(err),
          });
          res.writeHead(400, { "content-type": "text/plain" }).end("Invalid versioned payload");
          return;
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
          opts.auditLog.append({
            event: "rejected",
            id,
            traceId,
            ...tenantLabel,
            reason: "schema_failed",
            schema: schema.name,
            schemaVersion: schema.version,
            errors: errors.slice(0, 10),
          });
          res.writeHead(400, { "content-type": "text/plain" }).end("Schema validation failed");
          return;
        }
      }
    }

    if (opts.replay) {
      const nonceHeader = req.headers["x-nonce"];
      const nonce = Array.isArray(nonceHeader) ? nonceHeader[0] : nonceHeader;
      const tsHeader = req.headers["x-timestamp"];
      const tsRaw = Array.isArray(tsHeader) ? tsHeader[0] : tsHeader;
      // x-timestamp is unix seconds (same unit as the `t=` signature field);
      // the guard works in ms. A non-numeric value fails the window check.
      const timestampMs = tsRaw === undefined ? undefined : Number(tsRaw) * 1000;
      const verdict = opts.replay.check(nonce, timestampMs);
      if (!verdict.ok) {
        const reason = verdict.reason as string;
        opts.auditLog.append({ event: "rejected", id, traceId, ...tenantLabel, reason });
        const status = reason === "duplicate_nonce" ? 409 : 400;
        res.writeHead(status, { "content-type": "text/plain" }).end(`Rejected: ${reason}`);
        return;
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
      if (deduplicator.check(tenantScopeKey(tenantId, opts.forwardUrl), payloadHash)) {
        opts.auditLog.append({
          event: "duplicate_suppressed",
          id,
          traceId,
          ...tenantLabel,
          targetUrl: opts.forwardUrl,
        });
        res
          .writeHead(202, { "content-type": "application/json" })
          .end(
            JSON.stringify({
              id,
              traceId,
              status: "accepted",
              duplicate: true,
              ...tenantLabel,
            })
          );
        return;
      }
    }

    const passthrough: Record<string, string | string[] | undefined> = {};
    for (const [k, v] of Object.entries(req.headers)) {
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
      passthrough[k] = v;
    }

    // `x-priority: urgent` opts the delivery into the fast lane: it skips
    // the exponential backoff and the per-endpoint concurrency limiter, and
    // is instead bounded by the per-endpoint urgent token bucket
    // (`retry.urgent`, defaults: immediate retries, 100/sec per endpoint).
    const priorityHeader = req.headers["x-priority"];
    const priorityValue = Array.isArray(priorityHeader) ? priorityHeader[0] : priorityHeader;
    const priority: DeliveryPriority | undefined =
      priorityValue?.toLowerCase() === "urgent" ? "urgent" : undefined;

    queue.enqueue({
      id,
      traceId,
      // WR-48: the validated tenant rides the item into the per-tenant
      // isolation scope (breaker/quota/limiter/latency instances).
      ...(tenantId !== undefined ? { tenantId } : {}),
      payload: body,
      targetUrl: opts.forwardUrl,
      headers: passthrough,
      ...(priority ? { priority } : {}),
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
    const acceptedEvent: Record<string, unknown> = {
      event: "accepted",
      id,
      traceId,
      ...tenantLabel,
      targetUrl: opts.forwardUrl,
    };
    if (version !== undefined) acceptedEvent.version = version;
    if (schema !== undefined) {
      acceptedEvent.schema = schema.name;
      acceptedEvent.schemaVersion = schema.version;
    }
    if (rotating) acceptedEvent.keyId = verifiedKeyId ?? "unknown";
    if (perEndpointVerifier) acceptedEvent.verifier = activeVerifier.name;
    if (priority) acceptedEvent.priority = priority;
    if (inboundGzip) acceptedEvent.contentEncoding = "gzip";
    if (opts.auditPayloads) acceptedEvent.payload = body;
    opts.auditLog.append(acceptedEvent);
    res
      .writeHead(202, { "content-type": "application/json" })
      .end(JSON.stringify({ id, traceId, status: "accepted", ...tenantLabel }));
  });

  server.on("close", () => {
    queue.stop();
    // Pooled outbound connections must not outlive the server: close them
    // (and stop the idle reaper) on the same close path that stops the
    // queue — this covers stop() and the graceful-shutdown drain alike.
    // Idle pool sockets are unref'd anyway, so even a missed close cannot
    // pin process exit.
    defaultSender?.destroy();
  });

  // WR-47 runtime loop check: a callback URL that resolves to this relay's
  // own listener would re-enter intake on every terminal delivery and
  // ping-pong forever. The configuration-time check (declared
  // `selfOrigins`) ran at queue construction; this re-checks against the
  // actually bound address before every receipt POST, so even an
  // undeclared self-target (e.g. an ephemeral test port) is refused.
  queue.setCompletionCallbackSelfCheck(
    createBoundAddressSelfCheck(() => {
      const addr = server.address();
      if (addr === null || typeof addr === "string") return addr;
      return { address: addr.address, port: addr.port };
    })
  );

  if (opts.gracefulShutdown) {
    const timeoutMs = opts.gracefulShutdown.timeoutMs ?? 30_000;
    const uninstall = installGracefulShutdown(server, () => queue.shutdown(timeoutMs), {
      exit: opts.gracefulShutdown.exit,
    });
    // Remove the signal listeners once the server is gone so an embedded
    // server does not leave process-level handlers behind.
    server.on("close", () => uninstall());
  }

  return server;
}
