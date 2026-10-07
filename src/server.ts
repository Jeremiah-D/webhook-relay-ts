import { createServer, request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import type { Server } from "node:http";
import { randomUUID } from "node:crypto";
import { HmacSha256Verifier, type Verifier } from "./verify.ts";
import { RetryQueue, type DeliveryPriority, type RetryItem, type Sender } from "./retry.ts";
import { installGracefulShutdown } from "./shutdown.ts";
import type { PayloadEncryptor } from "./encrypt.ts";
import type { ReplayGuard } from "./replay.ts";
import { DeliveryDeduplicator, type DedupOptions } from "./dedup.ts";
import { resolveTraceId, TRACE_ID_HEADER } from "./trace.ts";
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
   */
  verifier?: Verifier;
  /** Retry queue tuning, passed through to RetryQueue. */
  retry?: ConstructorParameters<typeof RetryQueue>[0];
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

function defaultSender(item: RetryItem): Promise<void> {
  return new Promise((resolve, reject) => {
    const url = new URL(item.targetUrl);
    const req =
      url.protocol === "https:"
        ? httpsRequest(url, { method: "POST" }, (res) => {
            res.resume();
            res.on("end", () => {
              if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                resolve();
              } else {
                reject(new Error(`Forward failed with status ${res.statusCode}`));
              }
            });
            res.on("error", reject);
          })
        : httpRequest(url, { method: "POST" }, (res) => {
            res.resume();
            res.on("end", () => {
              if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                resolve();
              } else {
                reject(new Error(`Forward failed with status ${res.statusCode}`));
              }
            });
            res.on("error", reject);
          });
    req.on("error", reject);
    for (const [k, v] of Object.entries(item.headers)) {
      if (v !== undefined) req.setHeader(k, v as string | string[]);
    }
    // Propagate the trace ID downstream so the next hop can correlate the
    // delivery with this relay's audit trail (overrides a stale inbound
    // value, which is identical anyway after `resolveTraceId`).
    if (item.traceId) req.setHeader(TRACE_ID_HEADER, item.traceId);
    req.setHeader("content-length", item.payload.length);
    req.end(item.payload);
  });
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
    sender: opts.sender ?? defaultSender,
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

  const verifier = opts.verifier ?? new HmacSha256Verifier(opts.secret);
  const deduplicator = opts.dedup ? new DeliveryDeduplicator(opts.dedup) : undefined;

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
    let body: Buffer;
    try {
      body = await readRawBody(req);
    } catch {
      res.writeHead(400, { "content-type": "text/plain" }).end("Bad request");
      return;
    }

    const signatureHeader = req.headers["x-signature"];
    const id = randomUUID();
    // Resolve the trace ID before verification so even rejections are
    // traceable; a client-supplied x-trace-id is honored, otherwise fresh.
    const traceId = resolveTraceId(req.headers[TRACE_ID_HEADER]);

    if (!verifier.verify(body, signatureHeader ?? "")) {
      opts.auditLog.append({ event: "rejected", id, traceId, reason: "invalid_signature" });
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
