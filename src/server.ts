import { createServer, request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import type { Server } from "node:http";
import { randomUUID } from "node:crypto";
import { HmacSha256Verifier, type Verifier } from "./verify.ts";
import { RetryQueue, type RetryItem, type Sender } from "./retry.ts";
import type { ReplayGuard } from "./replay.ts";
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
   * `POST /dead-letter/:id/replay`, `GET /audit`). When unset, those
   * endpoints are disabled and answer 404 (fail closed).
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
  /** Inject queue hooks (e.g. to fail the server fast on dead letters). */
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
  const queue = new RetryQueue({
    sender: opts.sender ?? defaultSender,
    ...(opts.retry ?? {}),
    onDelivered: (item, attempts) => {
      opts.auditLog.append({ event: "delivered", id: item.id, targetUrl: item.targetUrl, attempts });
    },
    onDeadLetter: (item, attempts, lastError) => {
      opts.auditLog.append({
        event: "dead_letter",
        id: item.id,
        targetUrl: item.targetUrl,
        attempts,
        error: lastError instanceof Error ? lastError.message : String(lastError),
      });
    },
  });
  queue.start();

  const verifier = opts.verifier ?? new HmacSha256Verifier(opts.secret);

  const respondJson = (
    res: Parameters<Parameters<typeof createServer>[0]>[1],
    status: number,
    body: unknown
  ): void => {
    res.writeHead(status, { "content-type": "application/json" }).end(JSON.stringify(body));
  };

  /** Operator surface: dead-letter queue + audit-log queries. */
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
    const replayMatch = /^\/dead-letter\/([^/]+)\/replay$/.exec(pathname);
    if (!isList && !isAudit && !replayMatch) {
      respondJson(res, 404, { error: "not found" });
      return;
    }
    if (
      !(
        (isList && req.method === "GET") ||
        (isAudit && req.method === "GET") ||
        (replayMatch && req.method === "POST")
      )
    ) {
      respondJson(res, 405, { error: "method not allowed" });
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
          payloadBytes: e.payload.length,
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
    if (pathname === "/dead-letter" || pathname.startsWith("/dead-letter/") || pathname === "/audit") {
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

    if (!verifier.verify(body, signatureHeader ?? "")) {
      opts.auditLog.append({ event: "rejected", id, reason: "invalid_signature" });
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
        opts.auditLog.append({ event: "rejected", id, reason });
        const status = reason === "duplicate_nonce" ? 409 : 400;
        res.writeHead(status, { "content-type": "text/plain" }).end(`Rejected: ${reason}`);
        return;
      }
    }

    const passthrough: Record<string, string | string[] | undefined> = {};
    for (const [k, v] of Object.entries(req.headers)) {
      if (k === "host" || k === "content-length") continue;
      passthrough[k] = v;
    }

    queue.enqueue({ id, payload: body, targetUrl: opts.forwardUrl, headers: passthrough });
    opts.auditLog.append({ event: "accepted", id, targetUrl: opts.forwardUrl });
    res.writeHead(202, { "content-type": "application/json" }).end(JSON.stringify({ id, status: "accepted" }));
  });

  server.on("close", () => queue.stop());
  return server;
}
