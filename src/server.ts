import { createServer, request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import type { Server } from "node:http";
import { randomUUID } from "node:crypto";
import { HmacSha256Verifier, type Verifier } from "./verify.ts";
import { RetryQueue, type RetryItem, type Sender } from "./retry.ts";
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

  const server = createServer(async (req, res) => {
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
