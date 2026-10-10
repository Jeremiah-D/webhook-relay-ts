import { connect as netConnect, type Socket } from "node:net";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { createHash, randomBytes } from "node:crypto";
import { normalizePin, spkiFingerprint, TlsPinMismatchError } from "./pinning.ts";
import { HttpDeliveryError } from "./failure.ts";
import type { DownstreamResponse } from "./retry.ts";

/**
 * WebSocket downstream delivery (WR-45).
 *
 * Some downstreams prefer a persistent bidirectional channel over
 * request/response HTTP: the relay speaks RFC 6455 to `ws://` / `wss://`
 * endpoints with zero dependencies (`node:net` + `node:tls` +
 * `node:crypto` only — no `ws` package, so the handshake, masking, and
 * frame codec are hand-rolled here and covered by `test/websocket.test.ts`
 * against a raw-socket test server).
 *
 * Delivery model: one delivery borrows a pooled connection *exclusively*,
 * sends the payload as a single masked text frame, and waits for the
 * downstream's reply — a text frame becomes the response body, a clean
 * close with no reply counts as accepted (fire-and-forget endpoints
 * close right after reading). Control frames are handled inline: pings
 * are auto-ponged, unsolicited frames on an idle pooled connection
 * destroy it (fail-safe — a stray frame must never be mistaken for a
 * later delivery's response).
 *
 * Failure mapping keeps the retry layer honest:
 * - handshake completes with a non-101 status → `HttpDeliveryError`
 *   with that status code: the retry queue classifies on the code
 *   (4xx-except-408/429 → immediate dead letter, never retried) and
 *   honors `Retry-After`, exactly like the HTTP paths;
 * - anything else (refused connection, TLS error, handshake timeout, no
 *   reply before the timeout) → a plain `Error`: not an HTTP response
 *   at all, so the classifier treats it as retryable.
 *
 * Combinations:
 * - WR-21 pinning: for `wss:` endpoints with a pin whitelist, the whitelist
 *   replaces PKI verification and the peer's SPKI fingerprint is verified
 *   before the handshake bytes are written — a MITM never sees the
 *   payload. A mismatched peer fails the attempt with
 *   `TlsPinMismatchError` through the normal retry path.
 * - WR-24 keep-alive: connections are pooled per `(scheme, host, port,
 *   pin-whitelist)` and reused across deliveries; idle connections are
 *   ping/pong-probed and reaped, so a dead socket never serves a delivery.
 *
 * `x-relay-*` headers (idempotency key, trace, …) ride the upgrade
 * request as plain HTTP headers — the WebSocket handshake *is* an HTTP
 * request, so no new framing is needed for them.
 */

/** Tuning for {@link WebSocketPool}. All values are validated up front. */
export interface WebSocketPoolOptions {
  /**
   * Milliseconds for the TCP+TLS+handshake phase and, separately, for
   * waiting for the reply after the text frame is sent. Default: 10000.
   * Must be a positive integer.
   */
  timeoutMs?: number;
  /**
   * Cap on a single inbound text message in bytes (64 KiB default, matching
   * `RESPONSE_CAPTURE_MAX_BYTES`): beyond the cap the body is truncated and
   * `truncated` is set. Must be a positive integer.
   */
  maxMessageBytes?: number;
  /**
   * How often idle pooled connections are pinged (milliseconds).
   * Default: 30000. `0` disables the keep-alive prober. Must be a
   * non-negative integer.
   */
  pingIntervalMs?: number;
  /**
   * How long an idle pooled connection may sit before it is reaped
   * (milliseconds). Default: 60000. Must be a positive integer.
   */
  idleTimeoutMs?: number;
}

/** Validated {@link WebSocketPoolOptions} with defaults applied. */
export interface ResolvedWebSocketPoolOptions {
  timeoutMs: number;
  maxMessageBytes: number;
  pingIntervalMs: number;
  idleTimeoutMs: number;
}

/** Validate pool options once, at startup — never mid-delivery. */
export function resolveWebSocketOptions(opts: WebSocketPoolOptions = {}): ResolvedWebSocketPoolOptions {
  const fail = (msg: string): never => {
    throw new RangeError(`invalid WebSocket pool options: ${msg}`);
  };
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const maxMessageBytes = opts.maxMessageBytes ?? 64 * 1024;
  const pingIntervalMs = opts.pingIntervalMs ?? 30_000;
  const idleTimeoutMs = opts.idleTimeoutMs ?? 60_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) fail("timeoutMs must be a positive integer");
  if (!Number.isInteger(maxMessageBytes) || maxMessageBytes <= 0)
    fail("maxMessageBytes must be a positive integer");
  if (!Number.isInteger(pingIntervalMs) || pingIntervalMs < 0)
    fail("pingIntervalMs must be a non-negative integer");
  if (!Number.isInteger(idleTimeoutMs) || idleTimeoutMs <= 0)
    fail("idleTimeoutMs must be a positive integer");
  return { timeoutMs, maxMessageBytes, pingIntervalMs, idleTimeoutMs };
}

// --- RFC 6455 frame codec -------------------------------------------------

const OP_TEXT = 0x1;
const OP_CLOSE = 0x8;
const OP_PING = 0x9;
const OP_PONG = 0xa;
const OP_CONT = 0x0;
const WS_GUID = "258EAFA5-E91447DA-C5AB0DC85B11";

/** Encode one frame. Client-to-server frames are always masked (RFC 6455 §5.3). */
export function encodeWsFrame(opcode: number, payload: Buffer, masked: boolean): Buffer {
  const len = payload.length;
  let header: Buffer;
  if (len < 126) {
    header = Buffer.from([0x80 | opcode, (masked ? 0x80 : 0) | len]);
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x80 | opcode;
    header[1] = (masked ? 0x80 : 0) | 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | opcode;
    header[1] = (masked ? 0x80 : 0) | 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  if (!masked) return Buffer.concat([header, payload]);
  const mask = randomBytes(4);
  const out = Buffer.alloc(len);
  for (let i = 0; i < len; i++) out[i] = payload[i] ^ mask[i % 4];
  return Buffer.concat([header, mask, out]);
}

/** One decoded frame (payload already unmasked when the mask bit was set). */
export interface WsFrame {
  fin: boolean;
  opcode: number;
  payload: Buffer;
}

/**
 * Incremental frame parser: feed socket chunks, pull out complete frames.
 * Handles partial headers and 16/64-bit extended lengths; unmasks masked
 * frames (tolerated inbound, though servers must not mask).
 */
export class WsFrameReader {
  private buf = Buffer.alloc(0);

  push(chunk: Buffer): void {
    this.buf = this.buf.length === 0 ? chunk : Buffer.concat([this.buf, chunk]);
  }

  next(): WsFrame | undefined {
    const b = this.buf;
    if (b.length < 2) return undefined;
    const fin = (b[0] & 0x80) !== 0;
    const opcode = b[0] & 0x0f;
    const masked = (b[1] & 0x80) !== 0;
    let len = b[1] & 0x7f;
    let off = 2;
    if (len === 126) {
      if (b.length < 4) return undefined;
      len = b.readUInt16BE(2);
      off = 4;
    } else if (len === 127) {
      if (b.length < 10) return undefined;
      const hi = b.readUInt32BE(2);
      const lo = b.readUInt32BE(6);
      if (hi !== 0 || lo > 0x7fffffff) throw new Error("websocket: frame too large");
      len = lo;
      off = 10;
    }
    const maskOff = masked ? 4 : 0;
    if (b.length < off + maskOff + len) return undefined;
    let payload = b.subarray(off + maskOff, off + maskOff + len);
    if (masked) {
      const mask = b.subarray(off, off + 4);
      const out = Buffer.alloc(len);
      for (let i = 0; i < len; i++) out[i] = payload[i] ^ mask[i % 4];
      payload = out;
    }
    this.buf = b.subarray(off + maskOff + len);
    return { fin, opcode, payload };
  }
}

/** Expected `Sec-WebSocket-Accept` value for a client key. */
export function wsAcceptKey(key: string): string {
  return createHash("sha1").update(key + WS_GUID).digest("base64");
}

// --- connection ------------------------------------------------------------

/** Per-origin pool key: reused connections never cross origins or pin sets. */
function poolKey(url: URL, pins: string[] | undefined): string {
  const pinHash =
    pins === undefined
      ? "-"
      : createHash("sha256").update(pins.map(normalizePin).sort().join(",")).digest("hex");
  return `${url.protocol}//${url.host}/${pinHash}`;
}

interface PooledWsConnection {
  socket: Socket;
  reader: WsFrameReader;
  /** Last time this connection was checked back in (ms epoch). */
  idleSince: number;
  /** True while a delivery owns it. */
  busy: boolean;
  /** True once the socket is dead or must not be reused. */
  dead: boolean;
  /** Resolve for an in-flight ping probe, if any. */
  pongWaiter?: () => void;
}

/** Observable pool counters. */
export interface WebSocketPoolStats {
  created: number;
  reused: number;
  destroyed: number;
  pingTimeouts: number;
  idle: number;
  busy: number;
}

/**
 * Pooled RFC 6455 connections (WR-24 combo for the WebSocket path).
 *
 * `deliver()` borrows one connection *exclusively*: the text frame goes
 * out, the next inbound text frame (or a clean close) is the response,
 * and the connection is checked back in. Exclusivity is what makes the
 * correlation sound — no message IDs are needed because only one
 * delivery is ever in flight on a connection.
 */
export class WebSocketPool {
  private readonly opts: ResolvedWebSocketPoolOptions;
  private readonly conns = new Map<string, PooledWsConnection[]>();
  private readonly stats = { created: 0, reused: 0, destroyed: 0, pingTimeouts: 0 };
  private probeTimer?: NodeJS.Timeout;
  private destroyed = false;

  constructor(opts: WebSocketPoolOptions = {}) {
    this.opts = resolveWebSocketOptions(opts);
    if (this.opts.pingIntervalMs > 0) {
      this.probeTimer = setInterval(() => void this.probeIdle(), this.opts.pingIntervalMs);
      this.probeTimer.unref();
    }
  }

  getStats(): WebSocketPoolStats {
    let idle = 0;
    let busy = 0;
    for (const list of this.conns.values()) {
      for (const c of list) {
        if (c.busy) busy++;
        else idle++;
      }
    }
    return { ...this.stats, idle, busy };
  }

  /** Close every pooled connection and stop the prober. Idempotent. */
  destroy(): void {
    if (this.destroyed) return;
    this.destroyed = true;
    if (this.probeTimer !== undefined) clearInterval(this.probeTimer);
    for (const list of this.conns.values()) {
      for (const c of list) this.kill(c);
    }
    this.conns.clear();
  }

  /**
   * Deliver one payload over a pooled `ws:`/`wss:` connection.
   * `relayHeaders` are the `x-relay-*` headers, sent as upgrade request
   * headers on the connection this delivery opens; `pins` is the WR-21
   * whitelist for `wss:` (undefined for `ws:`); `targetUrl` names the
   * endpoint in errors.
   *
   * Note: the upgrade handshake is connection-scoped — a pooled
   * connection that is reused keeps the handshake headers of the
   * delivery that opened it. Per-delivery `x-relay-*` values (signature,
   * idempotency key) therefore describe the opening delivery; this is
   * inherent to WebSocket (there are no per-message headers on the
   * wire) and is documented here so downstream contracts can rely on
   * it: read per-delivery metadata from the handshake, per-message
   * bytes from the text frames.
   */
  async deliver(
    url: URL,
    body: Buffer,
    relayHeaders: Record<string, string>,
    pins: string[] | undefined,
    targetUrl: string
  ): Promise<DownstreamResponse> {
    if (this.destroyed) throw new Error("websocket: pool destroyed");
    const conn = await this.checkout(url, relayHeaders, pins, targetUrl);
    try {
      return await this.roundTrip(conn, body, targetUrl);
    } finally {
      this.checkin(url, pins, conn);
    }
  }

  // --- pool internals -------------------------------------------------------

  private async checkout(
    url: URL,
    relayHeaders: Record<string, string>,
    pins: string[] | undefined,
    targetUrl: string
  ): Promise<PooledWsConnection> {
    const key = poolKey(url, pins);
    const list = this.conns.get(key);
    if (list !== undefined) {
      for (const c of list) {
        if (!c.busy && !c.dead && !c.socket.destroyed) {
          c.busy = true;
          // Drop the idle drain handler: the round trip installs its
          // own frame handlers.
          const idle = (c as { idleHandler?: (chunk: Buffer) => void }).idleHandler;
          if (idle !== undefined) c.socket.off("data", idle);
          this.stats.reused++;
          return c;
        }
      }
    }
    const conn = await this.open(url, relayHeaders, pins, targetUrl);
    conn.busy = true;
    const arr = this.conns.get(key) ?? [];
    arr.push(conn);
    this.conns.set(key, arr);
    this.stats.created++;
    return conn;
  }

  private checkin(url: URL, pins: string[] | undefined, conn: PooledWsConnection): void {
    conn.busy = false;
    if (conn.dead || conn.socket.destroyed) {
      this.remove(url, pins, conn);
      this.kill(conn);
      return;
    }
    conn.idleSince = Date.now();
    void this.pumpIdle(conn);
  }

  private remove(url: URL, pins: string[] | undefined, conn: PooledWsConnection): void {
    const key = poolKey(url, pins);
    const list = this.conns.get(key);
    if (list === undefined) return;
    const i = list.indexOf(conn);
    if (i >= 0) list.splice(i, 1);
    if (list.length === 0) this.conns.delete(key);
  }

  private kill(conn: PooledWsConnection): void {
    if (!conn.dead) {
      conn.dead = true;
      this.stats.destroyed++;
    }
    conn.socket.destroy();
  }

  /**
   * One delivery round trip on an exclusively-held connection: send the
   * masked text frame, then consume frames until a text message (the
   * response) or a clean close. Pings are auto-ponged inline.
   */
  private roundTrip(
    conn: PooledWsConnection,
    body: Buffer,
    targetUrl: string
  ): Promise<DownstreamResponse> {
    return new Promise<DownstreamResponse>((resolve, reject) => {
      const { socket, reader } = conn;
      const timer = setTimeout(() => {
        cleanup();
        conn.dead = true;
        reject(new Error(`websocket: reply timeout after ${this.opts.timeoutMs}ms for ${targetUrl}`));
      }, this.opts.timeoutMs);
      // A message fragmented across frames accumulates here; the relay
      // never fragments outbound, but a downstream may.
      let text: Buffer[] = [];
      let textLen = 0;
      let truncated = false;
      let settled = false;

      const cleanup = (): void => {
        clearTimeout(timer);
        socket.off("data", onData);
        socket.off("error", onError);
        socket.off("close", onClose);
      };
      const done = (res: DownstreamResponse): void => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve(res);
      };
      const fail = (err: Error): void => {
        if (settled) return;
        settled = true;
        cleanup();
        conn.dead = true;
        reject(err);
      };
      const onError = (err: Error): void => fail(err);
      const onClose = (): void => {
        // Clean close with no text reply: the downstream accepted the
        // payload and hung up (fire-and-forget) — a successful delivery
        // with an empty body.
        if (text.length === 0) done({ statusCode: 200, body: Buffer.alloc(0), truncated: false });
        else done({ statusCode: 200, body: Buffer.concat(text), truncated });
      };
      const onData = (chunk: Buffer): void => {
        reader.push(chunk);
        for (;;) {
          let frame: WsFrame | undefined;
          try {
            frame = reader.next();
          } catch (err) {
            fail(err as Error);
            return;
          }
          if (frame === undefined) break;
          if (frame.opcode === OP_PING) {
            socket.write(encodeWsFrame(OP_PONG, frame.payload, true));
          } else if (frame.opcode === OP_PONG) {
            conn.pongWaiter?.();
            conn.pongWaiter = undefined;
          } else if (frame.opcode === OP_TEXT || frame.opcode === OP_CONT) {
            // Continuation frames must follow an open text message;
            // a stray continuation is a protocol violation — fail the
            // delivery rather than misattribute bytes.
            if (frame.opcode === OP_CONT && textLen === 0 && text.length === 0) {
              fail(new Error(`websocket: stray continuation frame from ${targetUrl}`));
              return;
            }
            const room = this.opts.maxMessageBytes - textLen;
            if (frame.payload.length > room) {
              text.push(frame.payload.subarray(0, room));
              textLen += room;
              truncated = true;
            } else {
              text.push(frame.payload);
              textLen += frame.payload.length;
            }
            if (frame.fin) {
              done({ statusCode: 200, body: Buffer.concat(text), truncated });
              return;
            }
          } else if (frame.opcode === OP_CLOSE) {
            // Echo the close if the peer is still waiting for one, then
            // treat it like a socket close (handled by onClose).
            if (!socket.destroyed) socket.write(encodeWsFrame(OP_CLOSE, Buffer.alloc(0), true));
            return;
          }
          // Other opcodes (binary) are ignored: the relay's contract is
          // text frames; a binary frame is never a delivery response.
        }
      };
      socket.on("data", onData);
      socket.once("error", onError);
      socket.once("close", onClose);
      socket.write(encodeWsFrame(OP_TEXT, body, true), (err) => {
        if (err) fail(err);
      });
    });
  }

  /**
   * Drain frames arriving on an idle pooled connection: pings are
   * auto-ponged (that is the keep-alive), anything else marks the
   * connection dirty — it is destroyed instead of risking a
   * misattributed response on the next checkout.
   */
  private async pumpIdle(conn: PooledWsConnection): Promise<void> {
    // pumpIdle is only called from checkin, where the connection is
    // idle and not busy.
    const { socket, reader } = conn;
    const onData = (chunk: Buffer): void => {
      if (conn.busy || conn.dead) return;
      reader.push(chunk);
      for (;;) {
        let frame: WsFrame | undefined;
        try {
          frame = reader.next();
        } catch {
          conn.dead = true;
          socket.destroy();
          return;
        }
        if (frame === undefined) break;
        if (frame.opcode === OP_PING) {
          socket.write(encodeWsFrame(OP_PONG, frame.payload, true));
        } else if (frame.opcode === OP_PONG) {
          conn.pongWaiter?.();
          conn.pongWaiter = undefined;
        } else {
          // Unsolicited data or close on an idle connection: do not
          // try to interpret it — drop the connection.
          conn.dead = true;
          socket.destroy();
          return;
        }
      }
    };
    // Swap the round-trip handlers for the idle drain. The socket had
    // its round-trip listeners removed by cleanup(); attach ours until
    // the next checkout replaces them (checkout removes idleHandler).
    socket.on("data", onData);
    // Remember the handler so checkout can remove it.
    (conn as { idleHandler?: (c: Buffer) => void }).idleHandler = onData;
  }

  private async probeIdle(): Promise<void> {
    const now = Date.now();
    for (const [key, list] of this.conns) {
      for (const conn of [...list]) {
        if (conn.busy || conn.dead) continue;
        if (now - conn.idleSince > this.opts.idleTimeoutMs) {
          this.removeByKey(key, conn);
          this.kill(conn);
          continue;
        }
        // Active liveness check: ping, and destroy the connection if
        // no pong arrives within the delivery timeout. The probe is a
        // real round trip on an otherwise idle socket, so a black-holed
        // peer is detected here instead of failing a delivery.
        const ponged = await this.ping(conn);
        if (!ponged) {
          this.removeByKey(key, conn);
          this.stats.pingTimeouts++;
          this.kill(conn);
        }
      }
    }
  }

  private removeByKey(key: string, conn: PooledWsConnection): void {
    const list = this.conns.get(key);
    if (list === undefined) return;
    const i = list.indexOf(conn);
    if (i >= 0) list.splice(i, 1);
    if (list.length === 0) this.conns.delete(key);
  }

  private ping(conn: PooledWsConnection): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
      if (conn.dead || conn.socket.destroyed) {
        resolve(false);
        return;
      }
      const timer = setTimeout(() => {
        conn.pongWaiter = undefined;
        resolve(false);
      }, this.opts.timeoutMs);
      conn.pongWaiter = () => {
        clearTimeout(timer);
        resolve(true);
      };
      conn.socket.write(encodeWsFrame(OP_PING, Buffer.alloc(0), true), (err) => {
        if (err) {
          clearTimeout(timer);
          conn.pongWaiter = undefined;
          resolve(false);
        }
      });
    });
  }

  /**
   * Open a fresh connection: TCP (or TLS for `wss:`), then the RFC 6455
   * upgrade handshake. `relayHeaders` become upgrade request headers.
   */
  private open(
    url: URL,
    relayHeaders: Record<string, string>,
    pins: string[] | undefined,
    targetUrl: string
  ): Promise<PooledWsConnection> {
    return new Promise<PooledWsConnection>((resolve, reject) => {
      const secure = url.protocol === "wss:";
      const port = url.port !== "" ? Number(url.port) : secure ? 443 : 80;
      const host = url.hostname;
      let settled = false;
      const done = (conn: PooledWsConnection): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.off("error", onOpenError);
        socket.off("close", onOpenClose);
        resolve(conn);
      };
      const fail = (err: Error): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        reject(err);
      };
      const timer = setTimeout(() => {
        fail(new Error(`websocket: handshake timeout after ${this.opts.timeoutMs}ms for ${targetUrl}`));
      }, this.opts.timeoutMs);
      const socket: Socket = secure
        ? tlsConnect({
            host,
            port,
            servername: host,
            // WR-21: with a pin whitelist the pins are the trust anchor
            // and replace PKI verification (same as the HTTP/1.1 path).
            rejectUnauthorized: pins === undefined,
          })
        : netConnect({ host, port });
      const reader = new WsFrameReader();
      const conn: PooledWsConnection = { socket, reader, idleSince: Date.now(), busy: false, dead: false };

      const verifyPins = (): void => {
        if (pins === undefined) {
          handshake();
          return;
        }
        const tlsSocket = socket as TLSSocket;
        const allowed = pins.map(normalizePin);
        let presented: string;
        try {
          const raw = (tlsSocket.getPeerCertificate() as { raw?: unknown }).raw;
          presented = spkiFingerprint(Buffer.from(raw as Buffer));
        } catch {
          presented = "<unreadable certificate>";
        }
        if (allowed.includes(presented)) {
          handshake();
        } else {
          fail(new TlsPinMismatchError(targetUrl, presented));
        }
      };

      const handshake = (): void => {
        const key = randomBytes(16).toString("base64");
        const lines = [
          `GET ${url.pathname}${url.search} HTTP/1.1`,
          `Host: ${url.host}`,
          "Upgrade: websocket",
          "Connection: Upgrade",
          `Sec-WebSocket-Key: ${key}`,
          "Sec-WebSocket-Version: 13",
        ];
        for (const [name, value] of Object.entries(relayHeaders)) {
          lines.push(`${name}: ${value}`);
        }
        lines.push("", "");
        let head = Buffer.alloc(0);
        const onData = (chunk: Buffer): void => {
          head = Buffer.concat([head, chunk]);
          const end = head.indexOf("\r\n\r\n");
          if (end < 0) {
            if (head.length > 16 * 1024) fail(new Error(`websocket: handshake header too large for ${targetUrl}`));
            return;
          }
          const headerText = head.subarray(0, end).toString("latin1");
          const rest = head.subarray(end + 4);
          socket.off("data", onData);
          // Any bytes after the handshake belong to the frame stream —
          // a fast downstream may already have sent a ping.
          if (rest.length > 0) reader.push(rest);
          const [statusLine, ...headerLines] = headerText.split("\r\n");
          const status = Number(statusLine.split(" ")[1]);
          const headers: Record<string, string> = {};
          for (const line of headerLines) {
            const i = line.indexOf(":");
            if (i > 0) headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
          }
          if (status !== 101) {
            // Structured failure: the retry queue classifies on the
            // status code exactly like the HTTP paths.
            fail(new HttpDeliveryError(status));
            return;
          }
          if (
            headers["upgrade"]?.toLowerCase() !== "websocket" ||
            headers["sec-websocket-accept"] !== wsAcceptKey(key)
          ) {
            fail(new Error(`websocket: bad upgrade response from ${targetUrl}`));
            return;
          }
          done(conn);
        };
        socket.on("data", onData);
        socket.write(lines.join("\r\n"), (err) => {
          if (err) fail(err);
        });
      };

      const onOpenError = (err: Error): void => {
        fail(err);
      };
      const onOpenClose = (): void => {
        if (!settled) fail(new Error(`websocket: connection closed during handshake for ${targetUrl}`));
      };
      socket.once("error", onOpenError);
      socket.once("close", onOpenClose);
      if (secure) {
        const tlsSocket = socket as TLSSocket;
        // Defensive: the socket may already be secure (session reuse).
        const cert = tlsSocket.getPeerCertificate() as { raw?: unknown };
        if (cert && cert.raw) verifyPins();
        else tlsSocket.once("secureConnect", verifyPins);
      } else {
        socket.once("connect", handshake);
      }
    });
  }
}
