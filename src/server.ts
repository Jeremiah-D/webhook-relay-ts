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
import { RetryQueue, type DeliveryPriority, type RetryItem, type Sender } from "./retry.ts";
import type { AutoReplayOptions } from "./autoreplay.ts";
import { HttpDeliveryError, parseRetryAfterMs } from "./failure.ts";
import { installGracefulShutdown } from "./shutdown.ts";
import type { PayloadEncryptor } from "./encrypt.ts";
import type { ReplayGuard } from "./replay.ts";
import { DeliveryDeduplicator, type DedupOptions } from "./dedup.ts";
import { InboundRateLimiter, type InboundRateLimitOptions } from "./ratelimit.ts";
import { resolveTraceId, TRACE_ID_HEADER } from "./trace.ts";
import type { TLSSocket } from "node:tls";
import { assertValidPins, normalizePin, spkiFingerprint, TlsPinMismatchError } from "./pinning.ts";
import { OutboundConnectionPool, type KeepAlivePoolOptions } from "./keepalive.ts";
import {
  assertValidProxyUrl,
  createProxiedAgent,
  resolveProxyUrl,
} from "./proxy.ts";
import type { AuditLog } from "./audit.ts";
import type { EndpointConfigPatch } from "./hotreload.ts";

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
   * Outbound keep-alive connection pool (see `src/keepalive.ts`): outbound
   * deliveries reuse TCP/TLS connections per `(scheme, host, port)` instead
   * of paying a handshake per attempt. Enabled by default with sane limits
   * (`maxSocketsPerHost: 64`, idle reaping after 30s); pass `false` to
   * disable pooling entirely (one fresh connection per delivery, the legacy
   * behavior), or tune with `KeepAlivePoolOptions`. Endpoints with a TLS pin
   * whitelist get a dedicated agent per pin set, so a connection pinned for
   * one whitelist can never serve an endpoint with a different one; the
   * pin is still verified on `secureConnect` for every new connection.
   * Pooled connections are closed when the server closes
   * (`stop()`/`shutdown()` path), and idle sockets are unref'd so a
   * forgotten pool never pins process exit. Invalid option values throw
   * `RangeError` at startup.
   */
  outboundKeepAlive?: KeepAlivePoolOptions | false;
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
   * Bearer token guarding the operator endpoints (`GET /dead-letter`,
   * `POST /dead-letter/:id/replay`, `POST /dead-letter/replay`,
   * the `/dead-letter/auto-replay/*` controls, `GET /audit`,
   * `GET /latency`, `GET /events`, `GET /metrics`). When unset, those
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
 */
export interface PooledSender extends Sender {
  /** The keep-alive pool, or `undefined` when pooling is disabled. */
  pool: OutboundConnectionPool | undefined;
  /** Close all pooled connections and stop the idle reaper. Idempotent. */
  destroy(): void;
}

export function createDefaultSender(
  tlsPins?: Record<string, string[]>,
  keepAlive?: KeepAlivePoolOptions | false,
  outboundSigning?: OutboundSigningConfig,
  proxies?: Record<string, string>
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
  const pool = keepAlive === false ? undefined : new OutboundConnectionPool(keepAlive);
  const sender = function defaultSender(item: RetryItem): Promise<void> {
    return new Promise((resolve, reject) => {
      const url = new URL(item.targetUrl);
      // Pinning is per endpoint (exact targetUrl match). When pins are
      // configured for the endpoint, the whitelist is the trust anchor: it
      // replaces Node's PKI chain verification, and the peer certificate is
      // verified on `secureConnect` before a single payload byte is written
      // (a MITM must not even see the request body). See `src/pinning.ts`
      // for why `checkServerIdentity` cannot do this job.
      const pins = url.protocol === "https:" ? tlsPins?.[item.targetUrl] : undefined;
      // Outbound proxy for this endpoint: explicit per-endpoint config
      // first, then the environment (read per delivery, so proxy rotation
      // needs no restart; `NO_PROXY` bypasses the env fallback only — an
      // explicit entry always wins). An invalid *environment* value throws
      // here and fails the delivery through the normal retry path; explicit
      // values were validated at startup.
      const proxyUrl = resolveProxyUrl(item.targetUrl, proxies);
      if (proxyUrl === undefined && proxies?.[item.targetUrl] !== undefined) {
        reject(
          new Error(`outbound proxy: proxy configured for non-HTTP(S) target ${item.targetUrl}`)
        );
        return;
      }
      // Pooled keep-alive agent for this origin (dedicated agent per pin
      // whitelist and per proxy, so a connection pinned or tunneled for
      // one endpoint can never serve another's). With pooling disabled but
      // a proxy configured, each delivery gets a one-off tunneled agent —
      // fresh tunnel per delivery, destroyed when the request settles.
      let oneOffAgent: HttpAgent | undefined;
      const agent =
        pool?.agentFor(url, pins, proxyUrl) ??
        (proxyUrl !== undefined
          ? (oneOffAgent = createProxiedAgent(
              url.protocol === "https:" ? "https" : "http",
              proxyUrl,
              { keepAlive: false, maxSockets: 1, maxFreeSockets: 0 }
            ))
          : undefined);
      const onResponse = (res: Parameters<Parameters<typeof httpsRequest>[2]>[0]): void => {
        res.resume();
        res.on("end", () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            resolve();
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
              { method: "POST", agent: agent ?? false, ...(pins ? { rejectUnauthorized: false } : {}) },
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
        for (const [k, v] of Object.entries(item.headers)) {
          if (v !== undefined) req.setHeader(k, v as string | string[]);
        }
        // Propagate the trace ID downstream so the next hop can correlate the
        // delivery with this relay's audit trail (overrides a stale inbound
        // value, which is identical anyway after `resolveTraceId`).
        if (item.traceId) req.setHeader(TRACE_ID_HEADER, item.traceId);
        if (outboundSigning !== undefined) {
          // Stamp AFTER the passthrough headers: a forged inbound
          // `x-relay-signature` was already stripped from them above, and
          // this guarantees the relay's own signature always wins.
          req.setHeader("x-relay-signature", signSha256(item.payload, outboundSigning.secret));
          if (outboundSigning.keyId !== undefined) {
            req.setHeader("x-relay-key-id", outboundSigning.keyId);
          }
        }
        req.setHeader("content-length", item.payload.length);
        req.end(item.payload);
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
  } as PooledSender;
  sender.pool = pool;
  sender.destroy = () => pool?.destroy();
  return sender;
}

/** Default inbound request body size limit: 1 MiB. */
export const DEFAULT_MAX_BODY_BYTES = 1_048_576;

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
      ? createDefaultSender(opts.tlsPins, opts.outboundKeepAlive, opts.outboundSigning, opts.proxies)
      : undefined;
  const queue = new RetryQueue({
    sender: opts.sender ?? defaultSender,
    ...(opts.retry ?? {}),
    payloadEncryptor: opts.payloadEncryptor ?? opts.retry?.payloadEncryptor,
    // An explicit server-level `autoReplay` wins over the nested
    // `retry.autoReplay`; either way the queue owns the scheduler.
    autoReplay: opts.autoReplay ?? opts.retry?.autoReplay,
    // Wrap the caller's hook so rounds-exhaustion is always audited, not
    // just observed.
    onAutoReplayAudit: (event) => {
      opts.auditLog.append(event);
      opts.retry?.onAutoReplayAudit?.(event);
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
        targetUrl: item.targetUrl,
        attempts,
      });
    },
    onDeadLetter: (item, attempts, lastError, failureClass) => {
      opts.auditLog.append({
        event: "dead_letter",
        id: item.id,
        traceId: item.traceId,
        targetUrl: item.targetUrl,
        attempts,
        error: lastError instanceof Error ? lastError.message : String(lastError),
        // "non_retryable" = poison payload dead-lettered on the first
        // attempt (no retry budget burned); "retryable" = every attempt
        // spent against a transient failure.
        failure_class: failureClass ?? "retryable",
      });
    },
    onCircuitStateChange: (endpoint, from, to) => {
      const event =
        to === "open" ? "circuit_open" : to === "half_open" ? "circuit_half_open" : "circuit_closed";
      opts.auditLog.append({ event, endpoint, from, to });
      opts.retry?.onCircuitStateChange?.(endpoint, from, to);
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
      res
        .writeHead(200, { "content-type": "text/plain; version=0.0.4" })
        .end(queue.renderMetrics());
      return;
    }
    if (isEvents) {
      streamDeliveryEvents(req, res);
      return;
    }
    if (isLatency) {
      const params = new URL(req.url ?? "/latency", "http://internal").searchParams;
      respondJson(res, 200, queue.getLatencyStats(params.get("endpoint") ?? undefined));
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
    if (isList) {
      respondJson(
        res,
        200,
        queue.getDeadLetter().map((e) => ({
          id: e.id,
          targetUrl: e.targetUrl,
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
      const { endpoint, ...patch } = body;
      if (typeof endpoint !== "string" || endpoint.length === 0) {
        respondJson(res, 400, { error: "endpoint must be a non-empty string" });
        return;
      }
      try {
        const changes = queue.updateEndpointConfig(endpoint, patch as EndpointConfigPatch);
        respondJson(res, 200, { endpoint, changes });
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
      pathname === "/config/endpoint"
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
        opts.auditLog.append({ event: "rejected", id, traceId, reason });
        const status = reason === "duplicate_nonce" ? 409 : 400;
        res.writeHead(status, { "content-type": "text/plain" }).end(`Rejected: ${reason}`);
        return;
      }
    }

    // Payload-hash dedup (WR-14): the same business event re-pushed inside
    // the window is acknowledged but never delivered — the duplicate
    // business action (e.g. a repeated payment callback charging twice) is
    // what we are protecting against. 202, not 409, so upstream treats the
    // event as handled instead of retrying again.
    if (deduplicator) {
      const payloadHash = DeliveryDeduplicator.hashPayload(body);
      if (deduplicator.check(opts.forwardUrl, payloadHash)) {
        opts.auditLog.append({ event: "duplicate_suppressed", id, traceId, targetUrl: opts.forwardUrl });
        res
          .writeHead(202, { "content-type": "application/json" })
          .end(JSON.stringify({ id, traceId, status: "accepted", duplicate: true }));
        return;
      }
    }

    const passthrough: Record<string, string | string[] | undefined> = {};
    for (const [k, v] of Object.entries(req.headers)) {
      if (k === "host" || k === "content-length") continue;
      // `x-relay-signature` / `x-relay-key-id` are this relay's own
      // namespace: an inbound client asserting them would impersonate the
      // relay downstream. Strip them always; when outbound signing is
      // enabled the sender stamps fresh ones below.
      if (k === "x-relay-signature" || k === "x-relay-key-id") continue;
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
      payload: body,
      targetUrl: opts.forwardUrl,
      headers: passthrough,
      ...(priority ? { priority } : {}),
    });
    const acceptedEvent: Record<string, unknown> = {
      event: "accepted",
      id,
      traceId,
      targetUrl: opts.forwardUrl,
    };
    if (rotating) acceptedEvent.keyId = verifiedKeyId ?? "unknown";
    if (perEndpointVerifier) acceptedEvent.verifier = activeVerifier.name;
    if (priority) acceptedEvent.priority = priority;
    if (opts.auditPayloads) acceptedEvent.payload = body;
    opts.auditLog.append(acceptedEvent);
    res.writeHead(202, { "content-type": "application/json" }).end(JSON.stringify({ id, traceId, status: "accepted" }));
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
