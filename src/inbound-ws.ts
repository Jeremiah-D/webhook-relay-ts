import { createHash } from "node:crypto";
import { encodeWsFrame } from "./websocket.ts";

/**
 * Inbound WebSocket event intake (WR-130): RFC 6455 *server-side*
 * handshake and frame codec for the `ws(s)://` intake endpoint.
 *
 * Zero dependencies (`node:crypto` only, plus the frame encoder borrowed
 * from the WR-45 outbound client in `src/websocket.ts` — encoding is
 * direction-neutral, so sharing it is not mixing client/server
 * semantics). The semantics here are strictly server-side:
 *
 * - the server never masks outbound frames; clients MUST mask inbound
 *   ones (RFC 6455 §5.1) — an unmasked client frame is a protocol error
 *   (close 1002), where the outbound client merely tolerates it;
 * - no extensions are negotiated, so any RSV bit set is a protocol
 *   error (the outbound client speaks permessage-deflate);
 * - fragmented messages are reassembled with a byte cap — oversize
 *   reassembly fails with close 1009 (message too big).
 *
 * Wire protocol (documented in the README):
 * - `GET <path>` with `Upgrade: websocket` → `101 Switching Protocols`;
 * - client → server: one text frame per event, a JSON envelope shaped
 *   exactly like a WR-61 `POST /ingest/batch` item:
 *   `{ "payload": "<base64>", "headers": { "x-signature": "…", … } }`;
 *   the per-event headers ride inside the envelope while `x-relay-*`
 *   and connection-level headers ride the upgrade request;
 * - server → client: one text frame per event,
 *   `{ "type": "event-ack", "status": "accepted" | "rejected", … }`,
 *   mirroring the HTTP intake's 202 / 4xx semantics.
 */

/** The RFC 6455 §1.3 magic GUID, spelled exactly as the spec has it. */
const WS_MAGIC_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/** Expected `Sec-WebSocket-Accept` value for a client key. */
export function inboundWsAcceptKey(clientKey: string): string {
  return createHash("sha1").update(clientKey + WS_MAGIC_GUID).digest("base64");
}

/** Why an upgrade request is not a valid WebSocket handshake. */
export type InboundWsHandshakeRejection =
  | "missing_upgrade"
  | "missing_key"
  | "unsupported_version";

function firstHeader(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) return value[0];
  return value;
}

/**
 * Validate the client's opening handshake headers (RFC 6455 §4.2.1).
 * A missing/non-websocket `Upgrade` or a missing `Sec-WebSocket-Key` is
 * a 400; a missing or non-13 `Sec-WebSocket-Version` is a 426 with
 * `Sec-WebSocket-Version: 13` (the server speaks exactly one version).
 */
export function checkInboundWsHandshake(
  headers: Record<string, string | string[] | undefined>
): { ok: true } | { ok: false; reason: InboundWsHandshakeRejection } {
  const tokens = (firstHeader(headers["upgrade"]) ?? "")
    .toLowerCase()
    .split(",")
    .map((t) => t.trim());
  if (!tokens.includes("websocket")) return { ok: false, reason: "missing_upgrade" };
  if (firstHeader(headers["sec-websocket-key"]) === undefined) {
    return { ok: false, reason: "missing_key" };
  }
  if ((firstHeader(headers["sec-websocket-version"]) ?? "").trim() !== "13") {
    return { ok: false, reason: "unsupported_version" };
  }
  return { ok: true };
}

/** A fatal framing violation, carrying the close code to send. */
export class WsProtocolError extends Error {
  readonly closeCode: number;
  constructor(closeCode: number, message: string) {
    super(message);
    this.name = "WsProtocolError";
    this.closeCode = closeCode;
  }
}

/** One fully reassembled inbound message. */
export type InboundWsMessage =
  | { kind: "text"; data: Buffer }
  | { kind: "binary"; data: Buffer }
  | { kind: "ping"; data: Buffer }
  | { kind: "pong"; data: Buffer }
  | { kind: "close"; code: number; reason: string };

/**
 * Incremental server-side frame parser: feed socket chunks, pull out
 * complete messages. Enforces masking (1002 on violation), control-frame
 * rules, and the reassembly byte cap (1009 past it).
 */
export class InboundWsParser {
  private buf = Buffer.alloc(0);
  private fragOpcode: 0x1 | 0x2 | null = null;
  private fragParts: Buffer[] = [];
  private fragLen = 0;
  private readonly maxMessageBytes: number;

  constructor(maxMessageBytes: number) {
    if (!Number.isInteger(maxMessageBytes) || maxMessageBytes <= 0) {
      throw new RangeError("InboundWsParser: maxMessageBytes must be a positive integer");
    }
    this.maxMessageBytes = maxMessageBytes;
  }

  push(chunk: Buffer): InboundWsMessage[] {
    this.buf = this.buf.length === 0 ? chunk : Buffer.concat([this.buf, chunk]);
    const out: InboundWsMessage[] = [];
    for (;;) {
      const msg = this.nextMessage();
      if (msg === undefined) return out;
      out.push(msg);
    }
  }

  private nextMessage(): InboundWsMessage | undefined {
    const b = this.buf;
    if (b.length < 2) return undefined;
    const fin = (b[0] & 0x80) !== 0;
    const rsv = b[0] & 0x70;
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
      if (hi !== 0 || lo > 0x7fff_ffff) {
        throw new WsProtocolError(1009, "frame declares an absurd length");
      }
      len = lo;
      off = 10;
    }
    // RFC 6455 §5.1: a server MUST close when a client sends unmasked data.
    if (!masked) throw new WsProtocolError(1002, "client frames must be masked");
    // No extensions are negotiated on this endpoint.
    if (rsv !== 0) throw new WsProtocolError(1002, "RSV bits set without a negotiated extension");
    if (b.length < off + 4 + len) return undefined;
    const mask = b.subarray(off, off + 4);
    const enc = b.subarray(off + 4, off + 4 + len);
    const payload = Buffer.alloc(len);
    for (let i = 0; i < len; i++) payload[i] = enc[i] ^ mask[i % 4];
    this.buf = b.subarray(off + 4 + len);

    if (opcode >= 0x8) {
      if (!fin) throw new WsProtocolError(1002, "fragmented control frame");
      if (len > 125) throw new WsProtocolError(1002, "control frame payload exceeds 125 bytes");
      if (opcode === 0x9) return { kind: "ping", data: payload };
      if (opcode === 0xa) return { kind: "pong", data: payload };
      if (opcode === 0x8) {
        return {
          kind: "close",
          code: payload.length >= 2 ? payload.readUInt16BE(0) : 1000,
          reason: payload.length > 2 ? payload.subarray(2).toString("utf8") : "",
        };
      }
      throw new WsProtocolError(1002, `unknown control opcode ${opcode}`);
    }

    if (this.fragOpcode !== null) {
      if (opcode !== 0x0) throw new WsProtocolError(1002, "expected a continuation frame");
    } else if (opcode !== 0x1 && opcode !== 0x2) {
      throw new WsProtocolError(1002, `unexpected data opcode ${opcode}`);
    }
    if (opcode === 0x1 || opcode === 0x2) {
      this.fragOpcode = opcode;
      this.fragParts = [];
      this.fragLen = 0;
    }
    this.fragLen += payload.length;
    if (this.fragLen > this.maxMessageBytes) {
      throw new WsProtocolError(1009, `message exceeds ${this.maxMessageBytes} bytes`);
    }
    this.fragParts.push(payload);
    if (!fin) return undefined;
    const data = Buffer.concat(this.fragParts, this.fragLen);
    const kind = this.fragOpcode === 0x1 ? "text" : "binary";
    this.fragOpcode = null;
    this.fragParts = [];
    this.fragLen = 0;
    return { kind, data };
  }
}

/** One server→client text frame. Servers never mask (RFC 6455 §5.3). */
export function wsTextFrame(text: string): Buffer {
  return encodeWsFrame(0x1, Buffer.from(text, "utf8"), false);
}

/** Server ping (empty payload unless given). */
export function wsPingFrame(data: Buffer = Buffer.alloc(0)): Buffer {
  return encodeWsFrame(0x9, data, false);
}

/** Pong echoing the ping's payload, as RFC 6455 §5.5.3 requires. */
export function wsPongFrame(data: Buffer): Buffer {
  return encodeWsFrame(0xa, data, false);
}

/** Close frame with a code and optional UTF-8 reason. */
export function wsCloseFrame(code: number, reason = ""): Buffer {
  const reasonBytes = Buffer.from(reason, "utf8");
  const body = Buffer.alloc(2 + reasonBytes.length);
  body.writeUInt16BE(code, 0);
  reasonBytes.copy(body, 2);
  return encodeWsFrame(0x8, body, false);
}

/** Tuning for the inbound WebSocket intake endpoint. All values are validated up front. */
export interface InboundWsOptions {
  /**
   * Upgrade path for the `ws(s)://` intake endpoint. Default `"/ingest/ws"`.
   * Must start with `/` and must not be an operator path.
   */
  path?: string;
  /**
   * How often the server pings idle connections (milliseconds).
   * Default: 30000. `0` disables server pings (the idle timeout still
   * applies to inbound traffic). Must be a non-negative integer.
   */
  pingIntervalMs?: number;
  /**
   * How long a connection may go without any inbound frame (data, ping,
   * or pong) before the server closes it (milliseconds). Default:
   * 120000. Must be a positive integer.
   */
  idleTimeoutMs?: number;
  /**
   * Cap on one reassembled inbound text message in bytes (the base64
   * envelope, not the decoded body — the body itself is capped by the
   * intake `maxBodyBytes` budget like the HTTP intake). Default:
   * 1048576. Must be a positive integer.
   */
  maxMessageBytes?: number;
}

/** Validated {@link InboundWsOptions} with defaults applied. */
export interface ResolvedInboundWsOptions {
  path: string;
  pingIntervalMs: number;
  idleTimeoutMs: number;
  maxMessageBytes: number;
}

export const DEFAULT_INBOUND_WS_PATH = "/ingest/ws";
export const DEFAULT_INBOUND_WS_PING_INTERVAL_MS = 30_000;
export const DEFAULT_INBOUND_WS_IDLE_TIMEOUT_MS = 120_000;
export const DEFAULT_INBOUND_WS_MAX_MESSAGE_BYTES = 1_048_576;

/** Validate {@link InboundWsOptions}; throws `RangeError` on anything illegal. */
export function resolveInboundWsOptions(opts: InboundWsOptions = {}): ResolvedInboundWsOptions {
  const path = opts.path ?? DEFAULT_INBOUND_WS_PATH;
  if (typeof path !== "string" || !path.startsWith("/")) {
    throw new RangeError("inboundWs: `path` must be a string starting with \"/\"");
  }
  const pingIntervalMs = opts.pingIntervalMs ?? DEFAULT_INBOUND_WS_PING_INTERVAL_MS;
  if (!Number.isInteger(pingIntervalMs) || pingIntervalMs < 0) {
    throw new RangeError(
      "inboundWs: `pingIntervalMs` must be a non-negative integer (0 disables server pings)"
    );
  }
  const idleTimeoutMs = opts.idleTimeoutMs ?? DEFAULT_INBOUND_WS_IDLE_TIMEOUT_MS;
  if (!Number.isInteger(idleTimeoutMs) || idleTimeoutMs <= 0) {
    throw new RangeError("inboundWs: `idleTimeoutMs` must be a positive integer");
  }
  const maxMessageBytes = opts.maxMessageBytes ?? DEFAULT_INBOUND_WS_MAX_MESSAGE_BYTES;
  if (!Number.isInteger(maxMessageBytes) || maxMessageBytes <= 0) {
    throw new RangeError("inboundWs: `maxMessageBytes` must be a positive integer");
  }
  return { path, pingIntervalMs, idleTimeoutMs, maxMessageBytes };
}
