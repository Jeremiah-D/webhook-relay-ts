import { createServer, request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import type { Server } from "node:http";
import { randomUUID } from "node:crypto";
import { HmacSha256Verifier, RotatingHmacVerifier, type SigningKey, type Verifier } from "./verify.ts";
import { RetryQueue, type DeliveryPriority, type RetryItem, type Sender } from "./retry.ts";
import { installGracefulShutdown } from "./shutdown.ts";
import type { PayloadEncryptor } from "./encrypt.ts";
import type { ReplayGuard } from "./replay.ts";
import { DeliveryDeduplicator, type DedupOptions } from "./dedup.ts";
import { InboundRateLimiter, type InboundRateLimitOptions } from "./ratelimit.ts";
import { resolveTraceId, TRACE_ID_HEADER } from "./trace.ts";
import type { TLSSocket } from "node:tls";
import { assertValidPins, normalizePin, spkiFingerprint, TlsPinMismatchError } from "./pinning.ts";
import type { AuditLog } from "./audit.ts";

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
   * Bearer token guarding the operator endpoints (`GET /dead-letter`,
   * `POST /dead-letter/:id/replay`, `GET /audit`, `GET /latency`,
   * `GET /events`, `GET /metrics`). When unset, those endpoints are
   * disabled and answer 404 (fail closed).
   */
  operatorToken?: string;
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
 */
export function createDefaultSender(tlsPins?: Record<string, string[]>): Sender {
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
  return function defaultSender(item: RetryItem): Promise<void> {
    return new Promise((resolve, reject) => {
      const url = new URL(item.targetUrl);
      // Pinning is per endpoint (exact targetUrl match). When pins are
      // configured for the endpoint, the whitelist is the trust anchor: it
      // replaces Node's PKI chain verification, and the peer certificate is
      // verified on `secureConnect` before a single payload byte is written
      // (a MITM must not even see the request body). See `src/pinning.ts`
      // for why `checkServerIdentity` cannot do this job.
      const pins = url.protocol === "https:" ? tlsPins?.[item.targetUrl] : undefined;
      const onResponse = (res: Parameters<Parameters<typeof httpsRequest>[2]>[0]): void => {
        res.resume();
        res.on("end", () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            resolve();
          } else {
            reject(new Error(`Forward failed with status ${res.statusCode}`));
          }
        });
        res.on("error", reject);
      };
      const req =
        url.protocol === "https:"
          ? httpsRequest(url, { method: "POST", ...(pins ? { rejectUnauthorized: false } : {}) }, onResponse)
          : httpRequest(url, { method: "POST" }, onResponse);
      req.on("error", reject);

      const writePayload = (): void => {
        for (const [k, v] of Object.entries(item.headers)) {
          if (v !== undefined) req.setHeader(k, v as string | string[]);
        }
        // Propagate the trace ID downstream so the next hop can correlate the
        // delivery with this relay's audit trail (overrides a stale inbound
        // value, which is identical anyway after `resolveTraceId`).
        if (item.traceId) req.setHeader(TRACE_ID_HEADER, item.traceId);
        req.setHeader("content-length", item.payload.length);
        req.end(item.payload);
      };

      if (pins === undefined) {
        writePayload();
        return;
      }
      // Normalized once, up front, so the per-handshake path is a plain compare.
      const allowed = pins.map(normalizePin);
      let verified = false;
      const verifyPin = (socket: TLSSocket): void => {
        if (verified) return;
        verified = true;
        let presented: string;
        try {
          const raw = (socket.getPeerCertificate() as { raw?: unknown }).raw;
          presented = spkiFingerprint(Buffer.from(raw as Buffer));
        } catch {
          presented = "<unreadable certificate>";
        }
        if (allowed.includes(presented)) {
          writePayload();
        } else {
          // Fail the delivery attempt: it follows the normal retry /
          // dead-letter path and the mismatch lands in the audit trail.
          req.destroy(new TlsPinMismatchError(item.targetUrl, presented));
        }
      };
      req.on("socket", (socket) => {
        const tlsSocket = socket as TLSSocket;
        const already = tlsSocket.getPeerCertificate() as { raw?: unknown };
        if (already && already.raw) {
          // Defensive: a reused agent socket may already be secure.
          verifyPin(tlsSocket);
        } else {
          tlsSocket.once("secureConnect", () => verifyPin(tlsSocket));
        }
      });
    });
  };
}

function readRawBody(req: Parameters<Parameters<typeof createServer>[0]>[0]): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

/**
 * Create a minimal webhook relay: verify the `x-signature` header, enqueue
 * the payload into a retry queue, and forward it to `forwardUrl`.
 * Both accepted deliveries and signature rejections are written to the audit log.
 */
export function createRelayServer(opts: RelayServerOptions): Server {
  const latencyOpts = opts.retry?.latency;
  const queue = new RetryQueue({
    sender: opts.sender ?? createDefaultSender(opts.tlsPins),
    ...(opts.retry ?? {}),
    payloadEncryptor: opts.payloadEncryptor ?? opts.retry?.payloadEncryptor,
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
    onDeadLetter: (item, attempts, lastError) => {
      opts.auditLog.append({
        event: "dead_letter",
        id: item.id,
        traceId: item.traceId,
        targetUrl: item.targetUrl,
        attempts,
        error: lastError instanceof Error ? lastError.message : String(lastError),
      });
    },
    onCircuitStateChange: (endpoint, from, to) => {
      const event =
        to === "open" ? "circuit_open" : to === "half_open" ? "circuit_half_open" : "circuit_closed";
      opts.auditLog.append({ event, endpoint, from, to });
      opts.retry?.onCircuitStateChange?.(endpoint, from, to);
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
  const handleOperator = (
    req: Parameters<Parameters<typeof createServer>[0]>[0],
    res: Parameters<Parameters<typeof createServer>[0]>[1],
    pathname: string
  ): void => {
    if (!opts.operatorToken) {
      respondJson(res, 404, { error: "operator endpoints disabled" });
      return;
    }
    if (req.headers["authorization"] !== `Bearer ${opts.operatorToken}`) {
      respondJson(res, 403, { error: "forbidden" });
      return;
    }
    const isList = pathname === "/dead-letter";
    const isAudit = pathname === "/audit";
    const isLatency = pathname === "/latency";
    const isEvents = pathname === "/events";
    const isMetrics = pathname === "/metrics";
    const replayMatch = /^\/dead-letter\/([^/]+)\/replay$/.exec(pathname);
    if (!isList && !isAudit && !isLatency && !isEvents && !isMetrics && !replayMatch) {
      respondJson(res, 404, { error: "not found" });
      return;
    }
    if (
      !(
        (isList && req.method === "GET") ||
        (isAudit && req.method === "GET") ||
        (isLatency && req.method === "GET") ||
        (isEvents && req.method === "GET") ||
        (isMetrics && req.method === "GET") ||
        (replayMatch && req.method === "POST")
      )
    ) {
      respondJson(res, 405, { error: "method not allowed" });
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
      pathname === "/metrics"
    ) {
      handleOperator(req, res, pathname);
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

    let body: Buffer;
    try {
      body = await readRawBody(req);
    } catch {
      res.writeHead(400, { "content-type": "text/plain" }).end("Bad request");
      return;
    }

    const signatureHeader = req.headers["x-signature"];
    const keyIdHeader = req.headers["x-key-id"];
    const keyIdHint = Array.isArray(keyIdHeader) ? keyIdHeader[0] : keyIdHeader;

    // With key rotation, learn which key id verified so it can go on the
    // audit trail; otherwise keep the legacy boolean contract.
    let verified = false;
    let verifiedKeyId: string | undefined;
    const rotating = verifier instanceof RotatingHmacVerifier;
    if (rotating) {
      const detail = verifier.verifyDetailed(body, signatureHeader ?? "", { keyId: keyIdHint });
      verified = detail.ok;
      verifiedKeyId = detail.keyId;
    } else {
      verified = verifier.verify(body, signatureHeader ?? "");
    }

    if (!verified) {
      const rejectedEvent: Record<string, unknown> = {
        event: "rejected",
        id,
        traceId,
        reason: "invalid_signature",
      };
      if (rotating) rejectedEvent.keyId = "unknown";
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
    if (priority) acceptedEvent.priority = priority;
    if (opts.auditPayloads) acceptedEvent.payload = body;
    opts.auditLog.append(acceptedEvent);
    res.writeHead(202, { "content-type": "application/json" }).end(JSON.stringify({ id, traceId, status: "accepted" }));
  });

  server.on("close", () => queue.stop());

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
