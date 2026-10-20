/**
 * WR-160: inbound HTTP server timeout hardening (slowloris protection).
 *
 * Wraps Node's server-level knobs — `headersTimeout`, `requestTimeout`
 * (slow headers / slow body → 408) and `maxHeaderSize` (oversized headers
 * → 431) — as one opt-in `httpHardening` option applied to every
 * listener the relay binds (intake + operator, HTTP and HTTPS alike).
 *
 * Why a module instead of three server options: Node only enforces the
 * header/body timeouts via a coarse connections-sweep
 * (`connectionsCheckingInterval`, 30s default) and never forwards a
 * timed-out request to the request listener — so the audit trail has to
 * live here, on the server's `clientError` event. Adding that listener
 * disables Node's default error reply, so this module replicates it
 * (408/431/413/400 + destroy) and audits timeouts as
 * `rejected`/`reason=http_timeout`.
 *
 * Unconfigured: nothing is touched — Node defaults, zero behavior
 * change. A timed-out request never reaches the intake pipeline, so it
 * burns no retry budget and never trips the breaker: the rejection is
 * purely inbound-side.
 */

import type { Server } from "node:http";
import type { Socket } from "node:net";
import type { AuditLog } from "./audit.ts";

export interface HttpHardeningOptions {
  /**
   * Max time to receive the complete request headers. 0 disables.
   * Default: Node's default (min(requestTimeout, 60000)).
   */
  headersTimeoutMs?: number;
  /**
   * Max time to receive the entire request (headers + body). 0 disables.
   * Default: Node's default (300000).
   */
  requestTimeoutMs?: number;
  /** Max total request header bytes; over → 431. Default: Node's 16384. */
  maxHeaderSizeBytes?: number;
}

export interface ResolvedHttpHardening {
  headersTimeoutMs?: number;
  requestTimeoutMs?: number;
  maxHeaderSizeBytes?: number;
}

/**
 * Validate once at startup. Returns `undefined` when unconfigured.
 * Throws `RangeError` on invalid config — never mid-request.
 */
export function assertValidHttpHardening(
  opts: HttpHardeningOptions | undefined
): ResolvedHttpHardening | undefined {
  if (opts === undefined) return undefined;
  if (typeof opts !== "object" || opts === null) {
    throw new RangeError("`httpHardening` must be an object");
  }
  const { headersTimeoutMs, requestTimeoutMs, maxHeaderSizeBytes } = opts;
  if (
    headersTimeoutMs !== undefined &&
    (!Number.isInteger(headersTimeoutMs) || headersTimeoutMs < 0)
  ) {
    throw new RangeError(
      "`httpHardening.headersTimeoutMs` must be a non-negative integer (0 disables the timeout)"
    );
  }
  if (
    requestTimeoutMs !== undefined &&
    (!Number.isInteger(requestTimeoutMs) || requestTimeoutMs < 0)
  ) {
    throw new RangeError(
      "`httpHardening.requestTimeoutMs` must be a non-negative integer (0 disables the timeout)"
    );
  }
  if (
    maxHeaderSizeBytes !== undefined &&
    (!Number.isInteger(maxHeaderSizeBytes) || maxHeaderSizeBytes <= 0)
  ) {
    throw new RangeError("`httpHardening.maxHeaderSizeBytes` must be a positive integer");
  }
  // Node's connection sweep swaps the two timeouts when
  // headersTimeout > requestTimeout (see `ConnectionsList::Expired`),
  // silently inverting the operator's intent — and its constructor
  // throws ERR_OUT_OF_RANGE for the same combination. Fail fast here
  // instead, at startup, never mid-request.
  if (
    headersTimeoutMs !== undefined &&
    requestTimeoutMs !== undefined &&
    requestTimeoutMs > 0 &&
    headersTimeoutMs > requestTimeoutMs
  ) {
    throw new RangeError(
      "`httpHardening.headersTimeoutMs` must be <= `httpHardening.requestTimeoutMs`"
    );
  }
  return { headersTimeoutMs, requestTimeoutMs, maxHeaderSizeBytes };
}

const STATUS_TEXT: Record<number, string> = {
  400: "Bad Request",
  408: "Request Timeout",
  413: "Payload Too Large",
  431: "Request Header Fields Too Large",
};

/**
 * Apply timeouts to a bound listener and install the `clientError`
 * audit hook. `maxHeaderSizeBytes` is NOT applied here — `maxHeaderSize`
 * is a construction-time option, so the caller passes it to
 * `createServer`/`createHttpsServer` when building the listener.
 */
export function applyHttpHardening(
  server: Server,
  hardening: ResolvedHttpHardening,
  auditLog: AuditLog
): void {
  // Applied via properties (the listeners already exist), so mirror
  // Node's construction semantics: an explicit requestTimeout lowers the
  // default headersTimeout to min(60000, requestTimeout). Without this,
  // the C++ sweep would see (headers=60000, request=X<60000), swap them,
  // and the body phase would time out at 60s instead of X.
  if (hardening.requestTimeoutMs !== undefined) {
    server.requestTimeout = hardening.requestTimeoutMs;
    if (hardening.headersTimeoutMs === undefined) {
      server.headersTimeout = Math.min(60000, hardening.requestTimeoutMs);
    }
  }
  if (hardening.headersTimeoutMs !== undefined) {
    server.headersTimeout = hardening.headersTimeoutMs;
  }
  // Registering any `clientError` listener disables Node's default
  // error reply, so replicate it here (status by error code, then
  // destroy) and audit slow-client timeouts.
  server.on("clientError", (err: Error, socket: Socket) => {
    const code = (err as { code?: string }).code;
    if (code === "ERR_HTTP_REQUEST_TIMEOUT") {
      // The request never reached the intake pipeline: no id, no
      // trace, no retry budget — a pure inbound-side rejection.
      auditLog.append({ event: "rejected", reason: "http_timeout" });
    }
    const status =
      code === "HPE_HEADER_OVERFLOW"
        ? 431
        : code === "HPE_CHUNK_EXTENSIONS_OVERFLOW"
          ? 413
          : code === "ERR_HTTP_REQUEST_TIMEOUT"
            ? 408
            : 400;
    const httpMessage = (
      socket as unknown as { _httpMessage?: { _headerSent?: boolean } }
    )._httpMessage;
    if (socket.writable && (!httpMessage || !httpMessage._headerSent)) {
      socket.write(`HTTP/1.1 ${status} ${STATUS_TEXT[status]}\r\nConnection: close\r\n\r\n`);
    }
    socket.destroy();
  });
}
