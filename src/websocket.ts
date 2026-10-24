import { connect as netConnect, type Socket } from "node:net";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import { createHash, randomBytes } from "node:crypto";
import { normalizePin, spkiFingerprint, TlsPinMismatchError } from "./pinning.ts";
import { HttpDeliveryError } from "./failure.ts";
import {
  PERMESSAGE_DEFLATE_OFFER,
  decompressMessage,
  maybeCompressMessage,
  negotiatePerMessageDeflate,
  resolvePerMessageDeflate,
  type NegotiatedDeflate,
  type PerMessageDeflateOptions,
  type ResolvedPerMessageDeflate,
} from "./deflate.ts";
import type { DownstreamResponse } from "./retry.ts";
import { renderWebSocketBlock, type WebSocketOriginMetricsInput } from "./metrics.ts";

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
 * - WR-46 permessage-deflate: opt-in per-pool (`permessageDeflate`
 *   option); negotiated per connection at handshake, opportunistic per
 *   message (threshold + never-expand), RSV1-marked frames both ways.
 *   Negotiation is strict — see `src/deflate.ts`.
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
  /**
   * WebSocket permessage-deflate (RFC 7692) for downstream deliveries
   * (WR-46, see `src/deflate.ts`): `true` enables with defaults,
   * `{ thresholdBytes? }` tunes the payload size at which compression
   * kicks in (default 1024). Disabled by default. The relay offers
   * `permessage-deflate` with both no-context-takeover parameters
   * required; a downstream that answers without them fails the handshake
   * instead of negotiating parameters the relay cannot honor.
   */
  permessageDeflate?: boolean | PerMessageDeflateOptions;
  /**
   * WebSocket downstream multiplexing (WR-204): `true` enables with
   * defaults, `{ maxInFlight? }` tunes the per-connection in-flight cap.
   * Disabled by default — when off, each delivery borrows a pooled
   * connection exclusively (the WR-45 model).
   *
   * When enabled, concurrent deliveries share ONE connection per pool
   * key: each delivery is sent as a JSON envelope text frame
   * `{"cid":"<32-hex>","body":"<base64 payload>","headers":{...}}` and the
   * downstream replies per delivery with `{"cid":"<same>","body":"<base64
   * reply>"}` — out-of-order replies are routed back by correlation ID.
   * The envelope's `headers` carry that delivery's own `x-relay-*`
   * values (upgrade handshake headers stay those of the connection's
   * first delivery — inherent to WebSocket, there are no per-message
   * headers on the wire). Downstreams that want multiplexing must speak
   * this envelope contract; the exclusive path keeps the old raw-text
   * contract.
   *
   * Connection-level backpressure: at most `maxInFlight` deliveries are
   * in flight per connection (default 32); beyond that, deliveries queue
   * FIFO on the connection — the pool never opens a second connection
   * for the same key while one is alive. A disconnect fails every
   * in-flight and queued delivery with a plain retryable `Error`, so the
   * retry queue re-attempts them (at-least-once); downstream dedup rides
   * the WR-44 `x-relay-idempotency-key`, which is per (event id, attempt)
   * and therefore stable across the re-attempt.
   *
   * Protocol hygiene mirrors the exclusive path: ping/pong keep-alive
   * interleaves, RSV1 is only legal with negotiated permessage-deflate
   * (WR-46, applied to the envelope), and any protocol violation (bad
   * envelope, unknown `cid`, oversized message) fails the whole
   * connection — misattribution is worse than a retryable failure.
   */
  multiplex?: boolean | WsMultiplexOptions;
  /**
   * WR-73 downstream TLS certificate expiry monitoring (see
   * `src/cert-expiry.ts`): called with the TLS socket and the delivery
   * `targetUrl` right after the TLS handshake — the same moment the pin
   * check reads the peer certificate — so the monitor can capture the
   * peer's `notAfter`. Optional; the hook must never throw (an observer
   * must not break a delivery).
   */
  onTlsPeerCertificate?: (socket: TLSSocket, targetUrl: string) => void;
}

/** Tuning for multiplexed WebSocket deliveries (WR-204). */
export interface WsMultiplexOptions {
  /**
   * Max concurrent in-flight deliveries per connection. Default 32.
   * Must be a positive integer. Beyond the cap, deliveries queue FIFO
   * on the connection instead of opening a new one.
   */
  maxInFlight?: number;
}

/** Validated {@link WsMultiplexOptions} with defaults applied. */
export interface ResolvedWsMultiplexOptions {
  maxInFlight: number;
}

/** Validated {@link WebSocketPoolOptions} with defaults applied. */
export interface ResolvedWebSocketPoolOptions {
  timeoutMs: number;
  maxMessageBytes: number;
  pingIntervalMs: number;
  idleTimeoutMs: number;
  permessageDeflate: ResolvedPerMessageDeflate | undefined;
  multiplex: ResolvedWsMultiplexOptions | undefined;
  onTlsPeerCertificate: ((socket: TLSSocket, targetUrl: string) => void) | undefined;
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
  let permessageDeflate: ResolvedPerMessageDeflate | undefined;
  try {
    permessageDeflate = resolvePerMessageDeflate(opts.permessageDeflate);
  } catch (err) {
    fail((err as Error).message);
  }
  let multiplex: ResolvedWsMultiplexOptions | undefined;
  if (opts.multiplex !== undefined && opts.multiplex !== false) {
    const muxOpts: WsMultiplexOptions =
      opts.multiplex === true ? {} : (opts.multiplex as WsMultiplexOptions);
    if (muxOpts === null || typeof muxOpts !== "object") {
      fail("multiplex must be a boolean or an options object");
    }
    const maxInFlight = muxOpts.maxInFlight ?? 32;
    if (!Number.isInteger(maxInFlight) || maxInFlight <= 0) {
      fail("multiplex.maxInFlight must be a positive integer");
    }
    multiplex = { maxInFlight };
  }
  const onTlsPeerCertificate = opts.onTlsPeerCertificate;
  if (onTlsPeerCertificate !== undefined && typeof onTlsPeerCertificate !== "function") {
    fail("onTlsPeerCertificate must be a function");
  }
  return {
    timeoutMs,
    maxMessageBytes,
    pingIntervalMs,
    idleTimeoutMs,
    permessageDeflate,
    multiplex,
    onTlsPeerCertificate,
  };
}

// --- RFC 6455 frame codec -------------------------------------------------

const OP_TEXT = 0x1;
const OP_CLOSE = 0x8;
const OP_PING = 0x9;
const OP_PONG = 0xa;
const OP_CONT = 0x0;
const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/** Encode one frame. Client-to-server frames are always masked (RFC 6455 §5.3). */
export function encodeWsFrame(opcode: number, payload: Buffer, masked: boolean, rsv1 = false): Buffer {
  const len = payload.length;
  let header: Buffer;
  const b0 = 0x80 | (rsv1 ? 0x40 : 0) | opcode;
  if (len < 126) {
    header = Buffer.from([b0, (masked ? 0x80 : 0) | len]);
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = b0;
    header[1] = (masked ? 0x80 : 0) | 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = b0;
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
  /** RSV1: set on the first frame of a permessage-deflate message (RFC 7692). */
  rsv1: boolean;
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
    const rsv1 = (b[0] & 0x40) !== 0;
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
    return { fin, rsv1, opcode, payload };
  }
}

/** Expected `Sec-WebSocket-Accept` value for a client key. */
export function wsAcceptKey(key: string): string {
  return createHash("sha1").update(key + WS_GUID).digest("base64");
}

/** Arithmetic mean of a non-empty sample list. */
function mean(samples: number[]): number {
  let sum = 0;
  for (const s of samples) sum += s;
  return sum / samples.length;
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
  /** Origin grouping key (`<scheme>//<host>`) for WR-105 per-origin metrics. */
  origin: string;
  /** Last time this connection was checked back in (ms epoch). */
  idleSince: number;
  /** True while a delivery owns it. */
  busy: boolean;
  /** True once the socket is dead or must not be reused. */
  dead: boolean;
  /** Resolve for an in-flight ping probe, if any. */
  pongWaiter?: () => void;
  /**
   * permessage-deflate parameters negotiated on this connection's
   * handshake (WR-46), or `null` when the downstream did not select the
   * extension — the connection then carries plain text frames.
   */
  deflate: NegotiatedDeflate | null;
  /**
   * Multiplexing state (WR-204). Present only on connections opened while
   * the pool's `multiplex` option is enabled: such a connection is
   * shared by concurrent deliveries and never marked `busy`.
   */
  mux?: MuxConnectionState;
}

/**
 * Per-connection multiplexing state (WR-204): the correlation table,
 * the in-flight backpressure queue, and the reassembly buffer for the
 * shared frame pump.
 */
interface MuxConnectionState {
  /** Deliveries awaiting their correlated reply, keyed by `cid`. */
  inFlight: Map<string, MuxDelivery>;
  /** Deliveries parked FIFO while `inFlight.size >= maxInFlight`. */
  queue: MuxQueuedDelivery[];
  /** Shared handshake promise: concurrent first deliveries await one open. */
  opening: Promise<void> | null;
  /** Inbound message reassembly (the shared pump owns the socket). */
  text: Buffer[];
  textLen: number;
  /** First frame of the pending message carried RSV1 (WR-46). */
  replyCompressed: boolean;
  /** The pump's `data` handler, so it can be detached on teardown. */
  pump?: (chunk: Buffer) => void;
}

/** One in-flight multiplexed delivery (WR-204). */
interface MuxDelivery {
  /** Correlation ID: 32 lowercase hex chars. */
  cid: string;
  targetUrl: string;
  resolve: (res: DownstreamResponse) => void;
  reject: (err: Error) => void;
  /** Reply timer: armed when the envelope hits the wire. */
  timer: NodeJS.Timeout;
}

/** A delivery parked on a connection's backpressure queue (WR-204). */
interface MuxQueuedDelivery {
  body: Buffer;
  relayHeaders: Record<string, string>;
  targetUrl: string;
  resolve: (res: DownstreamResponse) => void;
  reject: (err: Error) => void;
}

/**
 * Multiplexed envelope on the wire (WR-204). `cid` is the correlation
 * ID, `body` the base64 payload (request) or base64 reply, `headers`
 * the delivery's own `x-relay-*` values — the upgrade handshake only
 * carries the connection's first delivery's headers, so per-delivery
 * metadata rides here instead.
 */
interface MuxEnvelope {
  v: 1;
  cid: string;
  body: string;
  headers?: Record<string, string>;
}

/** 32 lowercase hex chars. */
const MUX_CID_RE = /^[0-9a-f]{32}$/;
/**
 * Hard cap on one inbound multiplexed message in multiples of
 * `maxMessageBytes` (WR-204). The decoded body is still truncated at
 * `maxMessageBytes` with `truncated: true` (mirroring the exclusive
 * path); the 4x wire headroom covers base64 expansion plus envelope
 * overhead, and anything beyond it is a protocol violation, not a
 * truncation — unbounded accumulation is not an option.
 */
const MUX_WIRE_CAP_MULTIPLE = 4;

/** Observable pool counters. */
export interface WebSocketPoolStats {
  created: number;
  reused: number;
  destroyed: number;
  pingTimeouts: number;
  idle: number;
  busy: number;
  /** Deliveries sent with RSV1 (permessage-deflate compressed). */
  deflatedOut: number;
  /** Deliveries whose reply arrived RSV1-compressed and was inflated. */
  deflatedIn: number;
  /** Deliveries sent as multiplexed envelope frames (WR-204). */
  muxOut: number;
  /** Multiplexed replies routed back by correlation ID (WR-204). */
  muxIn: number;
  /** Deliveries that waited in a connection's in-flight queue (WR-204). */
  muxQueued: number;
  /** Deliveries currently in flight on multiplexed connections (WR-204). */
  muxInFlight: number;
  /** Per-origin breakdown (WR-105), sorted by origin. */
  origins: WebSocketOriginStats[];
}

/**
 * One origin's WebSocket gateway counters (WR-105). The origin grouping
 * key is `<scheme>//<host>` (host includes the port); connections to
 * the same origin under different pin whitelists share the row — pins
 * are a trust detail, not a traffic identity.
 */
export interface WebSocketOriginStats {
  /** Origin grouping key: `<scheme>//<host>`. */
  origin: string;
  /** Live pooled connections for this origin right now (idle + busy). */
  activeConnections: number;
  /** Delivery messages sent over this origin's connections. */
  messagesOut: number;
  /** Delivery replies received over this origin's connections. */
  messagesIn: number;
  /** Pool checkouts that opened a fresh connection. */
  created: number;
  /** Pool checkouts that reused a pooled connection. */
  reused: number;
  /** Deliveries whose outbound frame was permessage-deflate compressed. */
  deflatedOut: number;
  /** Replies that arrived permessage-deflate compressed and were inflated. */
  deflatedIn: number;
  /**
   * Mean recent keep-alive ping RTT in ms (bounded recent window).
   * Absent when no probe has completed yet for this origin.
   */
  pingRttMs?: number;
  /**
   * Mean permessage-deflate wire/plain byte ratio over compressed
   * outbound deliveries, in (0, 1] — smaller means better compression.
   * Absent when nothing was compressed for this origin yet.
   */
  compressionRatio?: number;
  /**
   * Deliveries sent as multiplexed envelope frames on this origin's
   * connections (WR-204). Absent (not zero) when multiplexing never ran
   * here, so untouched origins keep their old shape.
   */
  muxOut?: number;
  /**
   * Multiplexed replies routed back by correlation ID (WR-204).
   * Absent when multiplexing never ran here.
   */
  muxIn?: number;
}

/** Cumulative per-origin counters behind {@link WebSocketOriginStats}. */
interface OriginCounters {
  messagesOut: number;
  messagesIn: number;
  created: number;
  reused: number;
  deflatedOut: number;
  deflatedIn: number;
  /** Plaintext bytes of compressed outbound messages (for the ratio). */
  deflatePlainBytes: number;
  /** Wire bytes of compressed outbound messages (for the ratio). */
  deflateWireBytes: number;
  /** Recent keep-alive ping RTTs in ms, oldest-first, bounded. */
  pingRtts: number[];
  /** Deliveries sent as multiplexed envelope frames (WR-204). */
  muxOut: number;
  /** Multiplexed replies routed back by correlation ID (WR-204). */
  muxIn: number;
}

/** Recent ping RTT samples kept per origin (WR-105). */
const MAX_PING_RTT_SAMPLES = 32;

/**
 * Pooled RFC 6455 connections (WR-24 combo for the WebSocket path).
 *
 * Default (exclusive) mode: `deliver()` borrows one connection
 * *exclusively*: the text frame goes out, the next inbound text frame
 * (or a clean close) is the response, and the connection is checked back
 * in. Exclusivity is what makes the correlation sound — no message IDs
 * are needed because only one delivery is ever in flight on a
 * connection.
 *
 * Multiplexed mode (WR-204, opt-in via `multiplex`): one connection per
 * pool key is shared by concurrent deliveries, each carried in a JSON
 * envelope text frame with a correlation ID (`cid`) and answered by a
 * correlated envelope. Replies may arrive in any order. At most
 * `maxInFlight` deliveries are in flight per connection; the rest queue
 * FIFO on the connection — the pool never opens a second connection for
 * the same key while one is alive. See the `multiplex` option docs for
 * the envelope contract and failure semantics.
 */
export class WebSocketPool {
  private readonly opts: ResolvedWebSocketPoolOptions;
  private readonly conns = new Map<string, PooledWsConnection[]>();
  /**
   * In-progress multiplexed handshakes by pool key (WR-204): concurrent
   * first deliveries on a key await the same promise, so exactly one
   * socket is ever opened per key.
   */
  private readonly muxOpening = new Map<string, Promise<PooledWsConnection>>();
  private readonly stats = {
    created: 0,
    reused: 0,
    destroyed: 0,
    pingTimeouts: 0,
    deflatedOut: 0,
    deflatedIn: 0,
    muxOut: 0,
    muxIn: 0,
    muxQueued: 0,
  };
  /** Cumulative per-origin counters (WR-105); rows survive connection churn. */
  private readonly originCounters = new Map<string, OriginCounters>();
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
    let muxInFlight = 0;
    for (const list of this.conns.values()) {
      for (const c of list) {
        // WR-204: a multiplexed connection is "busy" while it carries
        // in-flight deliveries or a parked queue — it is never
        // exclusively held, but it is not idle either.
        const muxLoad =
          c.mux === undefined ? 0 : c.mux.inFlight.size + c.mux.queue.length;
        muxInFlight += c.mux === undefined ? 0 : c.mux.inFlight.size;
        if (c.busy || muxLoad > 0) busy++;
        else idle++;
      }
    }
    return { ...this.stats, idle, busy, muxInFlight, origins: this.getOriginStats() };
  }

  /**
   * Per-origin gateway counters (WR-105), sorted by origin. Rows exist
   * for every origin the pool has ever served; `activeConnections` is
   * the live count right now, the rest are cumulative.
   */
  getOriginStats(): WebSocketOriginStats[] {
    const active = new Map<string, number>();
    for (const list of this.conns.values()) {
      for (const c of list) {
        if (!c.dead && !c.socket.destroyed) {
          active.set(c.origin, (active.get(c.origin) ?? 0) + 1);
        }
      }
    }
    const out: WebSocketOriginStats[] = [];
    for (const [origin, row] of this.originCounters) {
      out.push({
        origin,
        activeConnections: active.get(origin) ?? 0,
        messagesOut: row.messagesOut,
        messagesIn: row.messagesIn,
        created: row.created,
        reused: row.reused,
        deflatedOut: row.deflatedOut,
        deflatedIn: row.deflatedIn,
        ...(row.pingRtts.length > 0 ? { pingRttMs: mean(row.pingRtts) } : {}),
        ...(row.deflatePlainBytes > 0
          ? { compressionRatio: row.deflateWireBytes / row.deflatePlainBytes }
          : {}),
        ...(row.muxOut > 0 ? { muxOut: row.muxOut } : {}),
        ...(row.muxIn > 0 ? { muxIn: row.muxIn } : {}),
      });
    }
    out.sort((a, b) => (a.origin < b.origin ? -1 : a.origin > b.origin ? 1 : 0));
    return out;
  }

  /**
   * Prometheus exposition block for the WebSocket gateway (WR-105):
   * per-origin connections, message counters, ping RTT, deflate ratio,
   * and pool checkout/reuse. Empty string while no origin has been
   * observed, so an untouched relay's `/metrics` output stays
   * byte-identical.
   */
  renderMetrics(): string {
    const series: WebSocketOriginMetricsInput[] = this.getOriginStats().map((s) => ({
      origin: s.origin,
      activeConnections: s.activeConnections,
      messagesOut: s.messagesOut,
      messagesIn: s.messagesIn,
      created: s.created,
      reused: s.reused,
      ...(s.pingRttMs !== undefined ? { pingRttSeconds: s.pingRttMs / 1000 } : {}),
      ...(s.compressionRatio !== undefined ? { compressionRatio: s.compressionRatio } : {}),
      // WR-204: pass through only when multiplexing ran on this origin.
      ...(s.muxOut !== undefined ? { muxOut: s.muxOut } : {}),
      ...(s.muxIn !== undefined ? { muxIn: s.muxIn } : {}),
    }));
    const lines = renderWebSocketBlock(series);
    return lines.length === 0 ? "" : lines.join("\n") + "\n";
  }

  /** Origin grouping key for `url`: `<scheme>//<host>` (WR-105). */
  private static originOf(url: URL): string {
    return `${url.protocol}//${url.host}`;
  }

  /** Cumulative per-origin counter row, created on first use. */
  private originRow(origin: string): OriginCounters {
    let row = this.originCounters.get(origin);
    if (row === undefined) {
      row = {
        messagesOut: 0,
        messagesIn: 0,
        created: 0,
        reused: 0,
        deflatedOut: 0,
        deflatedIn: 0,
        deflatePlainBytes: 0,
        deflateWireBytes: 0,
        pingRtts: [],
        muxOut: 0,
        muxIn: 0,
      };
      this.originCounters.set(origin, row);
    }
    return row;
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
   * bytes from the text frames. (In WR-204 multiplexed mode the
   * envelope's `headers` carry each delivery's own values instead.)
   */
  async deliver(
    url: URL,
    body: Buffer,
    relayHeaders: Record<string, string>,
    pins: string[] | undefined,
    targetUrl: string
  ): Promise<DownstreamResponse> {
    if (this.destroyed) throw new Error("websocket: pool destroyed");
    if (this.opts.multiplex !== undefined) {
      return this.deliverMux(url, body, relayHeaders, pins, targetUrl);
    }
    const conn = await this.checkout(url, relayHeaders, pins, targetUrl);
    try {
      return await this.roundTrip(conn, body, targetUrl);
    } finally {
      this.checkin(url, pins, conn);
    }
  }

  // --- WR-204 multiplexed delivery -----------------------------------------

  /**
   * Deliver one payload on a shared multiplexed connection: the payload
   * goes out as a correlated envelope text frame and the reply is
   * routed back when the downstream's envelope with the same `cid`
   * arrives — replies may arrive in any order.
   *
   * Exactly one connection exists per pool key while multiplexing: a
   * fresh delivery either joins its in-flight table, parks FIFO on its
   * backpressure queue (at `maxInFlight`), or — when no live connection
   * exists — awaits the same shared handshake as any concurrent first
   * deliveries. The pool never opens a second connection for the key.
   */
  private async deliverMux(
    url: URL,
    body: Buffer,
    relayHeaders: Record<string, string>,
    pins: string[] | undefined,
    targetUrl: string
  ): Promise<DownstreamResponse> {
    const conn = await this.checkoutMux(url, relayHeaders, pins, targetUrl);
    const mux = conn.mux;
    if (mux === undefined || conn.dead || conn.socket.destroyed) {
      // Lost the race with a teardown: fail retryable, the retry queue
      // re-attempts (at-least-once) on a fresh connection.
      throw new Error(`websocket: multiplexed connection unavailable for ${targetUrl}`);
    }
    return new Promise<DownstreamResponse>((resolve, reject) => {
      const queued: MuxQueuedDelivery = { body, relayHeaders, targetUrl, resolve, reject };
      if (mux.inFlight.size < this.opts.multiplex!.maxInFlight && mux.queue.length === 0) {
        this.sendMuxEnvelope(conn, queued);
      } else {
        // Connection-level backpressure: park FIFO, never open another
        // connection. The slot is taken when a delivery settles.
        mux.queue.push(queued);
        this.stats.muxQueued++;
      }
    });
  }

  /**
   * Get the shared multiplexed connection for the pool key, opening it
   * (once) when none is alive. Concurrent first deliveries share the
   * same handshake promise — exactly one socket is ever opened.
   */
  private async checkoutMux(
    url: URL,
    relayHeaders: Record<string, string>,
    pins: string[] | undefined,
    targetUrl: string
  ): Promise<PooledWsConnection> {
    const key = poolKey(url, pins);
    const list = this.conns.get(key);
    if (list !== undefined) {
      for (const c of list) {
        if (c.mux !== undefined && !c.dead && !c.socket.destroyed) {
          this.stats.reused++;
          this.originRow(WebSocketPool.originOf(url)).reused++;
          return c;
        }
      }
    }
    // No live multiplexed connection: open exactly one and share the
    // handshake. A second concurrent caller must not open another.
    let opening = this.muxOpening.get(key);
    if (opening === undefined) {
      opening = (async (): Promise<PooledWsConnection> => {
        const conn = await this.open(url, relayHeaders, pins, targetUrl);
        if (this.destroyed) {
          // Same orphan-socket guard as the exclusive checkout path:
          // the fresh connection never entered `this.conns`, so
          // `destroy()` could not kill it — do it here.
          this.kill(conn);
          throw new Error("websocket: pool destroyed");
        }
        conn.mux = {
          inFlight: new Map(),
          queue: [],
          opening: null,
          text: [],
          textLen: 0,
          replyCompressed: false,
        };
        this.attachMuxPump(url, pins, conn);
        const arr = this.conns.get(key) ?? [];
        arr.push(conn);
        this.conns.set(key, arr);
        this.stats.created++;
        this.originRow(conn.origin).created++;
        return conn;
      })();
      this.muxOpening.set(key, opening);
      try {
        return await opening;
      } finally {
        this.muxOpening.delete(key);
      }
    }
    const conn = await opening;
    this.stats.reused++;
    this.originRow(WebSocketPool.originOf(url)).reused++;
    return conn;
  }

  /**
   * Serialize and send one multiplexed envelope: `cid` first in the
   * JSON so a truncated read could still identify it, then base64 body
   * and the delivery's own `x-relay-*` headers. Registers the delivery
   * in the correlation table and arms its reply timer when the frame
   * hits the wire.
   */
  private sendMuxEnvelope(conn: PooledWsConnection, queued: MuxQueuedDelivery): void {
    const mux = conn.mux;
    if (mux === undefined) {
      queued.reject(new Error(`websocket: multiplexed connection unavailable for ${queued.targetUrl}`));
      return;
    }
    const cid = randomBytes(16).toString("hex");
    const envelope: MuxEnvelope = {
      cid,
      v: 1,
      body: queued.body.toString("base64"),
      ...(Object.keys(queued.relayHeaders).length > 0 ? { headers: queued.relayHeaders } : {}),
    };
    const plain = Buffer.from(JSON.stringify(envelope), "utf8");
    const send = (wire: Buffer, rsv1: boolean): void => {
      const delivery: MuxDelivery = {
        cid,
        targetUrl: queued.targetUrl,
        resolve: queued.resolve,
        reject: queued.reject,
        timer: setTimeout(() => {
          this.failMuxDelivery(conn, cid, new Error(
            `websocket: multiplexed reply timeout after ${this.opts.timeoutMs}ms for ${queued.targetUrl}`
          ));
        }, this.opts.timeoutMs),
      };
      mux.inFlight.set(cid, delivery);
      conn.socket.write(encodeWsFrame(OP_TEXT, wire, true, rsv1), (err) => {
        if (err) {
          this.failMuxDelivery(conn, cid, err);
          return;
        }
        this.stats.muxOut++;
        const row = this.originRow(conn.origin);
        row.muxOut++;
        row.messagesOut++;
        if (rsv1) {
          this.stats.deflatedOut++;
          row.deflatedOut++;
          row.deflatePlainBytes += plain.length;
          row.deflateWireBytes += wire.length;
        }
      });
    };
    // WR-46: opportunistic permessage-deflate on the envelope when the
    // connection negotiated it — maybeCompressMessage never expands.
    // The compression is async: re-check liveness before registering,
    // or a delivery compressed across a disconnect would never settle
    // (failAllMux only knows deliveries already in the table/queue).
    if (conn.deflate !== null && this.opts.permessageDeflate !== undefined) {
      void maybeCompressMessage(plain, this.opts.permessageDeflate.thresholdBytes, conn.deflate.windowBits).then(
        (out) => {
          if (conn.dead || conn.socket.destroyed) {
            queued.reject(
              new Error(`websocket: multiplexed connection unavailable for ${queued.targetUrl}`)
            );
            return;
          }
          send(out.bytes, out.compressed);
        },
        (err) => queued.reject(err as Error)
      );
    } else {
      send(plain, false);
    }
  }

  /** Settle one delivery's waiters and pump the backpressure queue. */
  private settleMuxDelivery(conn: PooledWsConnection, cid: string, res: DownstreamResponse): void {
    const mux = conn.mux;
    if (mux === undefined) return;
    const delivery = mux.inFlight.get(cid);
    if (delivery === undefined) return;
    mux.inFlight.delete(cid);
    clearTimeout(delivery.timer);
    delivery.resolve(res);
    this.afterMuxSlotFreed(conn);
  }

  /** Fail one delivery (retryable) and pump the backpressure queue. */
  private failMuxDelivery(conn: PooledWsConnection, cid: string, err: Error): void {
    const mux = conn.mux;
    if (mux === undefined) return;
    const delivery = mux.inFlight.get(cid);
    if (delivery === undefined) return;
    mux.inFlight.delete(cid);
    clearTimeout(delivery.timer);
    delivery.reject(err);
    this.afterMuxSlotFreed(conn);
  }

  /**
   * After a multiplexed slot frees: pump the backpressure queue, and
   * when the connection is fully drained mark it idle so the
   * keep-alive reaper treats it like any other idle connection.
   */
  private afterMuxSlotFreed(conn: PooledWsConnection): void {
    this.pumpMuxQueue(conn);
    const mux = conn.mux;
    if (mux !== undefined && mux.inFlight.size === 0 && mux.queue.length === 0) {
      conn.idleSince = Date.now();
    }
  }

  /**
   * Move queued deliveries into freed in-flight slots, FIFO. Slots open
   * when a delivery settles or fails; the queue never jumps the line.
   */
  private pumpMuxQueue(conn: PooledWsConnection): void {
    const mux = conn.mux;
    if (mux === undefined || conn.dead || conn.socket.destroyed) return;
    const maxInFlight = this.opts.multiplex?.maxInFlight ?? 32;
    while (mux.queue.length > 0 && mux.inFlight.size < maxInFlight) {
      const next = mux.queue.shift();
      if (next === undefined) break;
      this.sendMuxEnvelope(conn, next);
    }
  }

  /**
   * Fail every in-flight and queued delivery on a dead multiplexed
   * connection with a plain retryable `Error`. The retry queue
   * re-attempts them (at-least-once); downstream dedup rides the WR-44
   * `x-relay-idempotency-key`, which is stable across the re-attempt
   * because it derives from (event id, attempt).
   */
  private failAllMux(conn: PooledWsConnection, reason: string): void {
    const mux = conn.mux;
    if (mux === undefined) return;
    const err = new Error(`websocket: ${reason}`);
    for (const [, delivery] of [...mux.inFlight]) {
      clearTimeout(delivery.timer);
      delivery.reject(err);
    }
    mux.inFlight.clear();
    for (const queued of mux.queue.splice(0)) {
      queued.reject(err);
    }
  }

  /**
   * The shared frame pump for a multiplexed connection: reassembles one
   * inbound message at a time, parses the correlated envelope, and
   * routes the reply to the waiting delivery. Control frames stay
   * connection-scoped (ping → pong, pong → the keep-alive waiter).
   *
   * Protocol violations (bad envelope, unknown `cid`, oversized
   * message, stray continuation, RSV1 misuse) fail the whole
   * connection: a misattributed reply is worse than a retryable
   * failure, and every pending delivery fails retryable so the retry
   * queue re-attempts them.
   */
  private attachMuxPump(url: URL, pins: string[] | undefined, conn: PooledWsConnection): void {
    const mux = conn.mux;
    if (mux === undefined) return;
    const target = `${url.protocol}//${url.host}${url.pathname}`;
    const wireCap = this.opts.maxMessageBytes * MUX_WIRE_CAP_MULTIPLE;

    const protocolViolation = (detail: string): void => {
      if (conn.dead) return;
      conn.dead = true;
      this.failAllMux(conn, `multiplexed protocol violation (${detail}) for ${target}`);
      this.remove(url, pins, conn);
      this.kill(conn);
    };

    const onConnError = (err: Error): void => {
      if (conn.dead) return;
      conn.dead = true;
      this.failAllMux(conn, `multiplexed connection error (${err.message}) for ${target}`);
      this.remove(url, pins, conn);
      this.kill(conn);
    };

    const onConnClose = (): void => {
      if (conn.dead) return;
      conn.dead = true;
      this.failAllMux(conn, `multiplexed connection closed with ${mux.inFlight.size} in-flight for ${target}`);
      this.remove(url, pins, conn);
      // The socket is already closed — kill() would be a no-op on it —
      // but the connection is gone, so count it destroyed like the
      // exclusive path does via checkin → kill.
      this.stats.destroyed++;
    };

    /** Route one fully reassembled message to its delivery. */
    const routeMessage = (payload: Buffer, wasCompressed: boolean): void => {
      if (wasCompressed) {
        // WR-46: the reply arrived RSV1-compressed — inflate before
        // parsing. A deflate stream that will not inflate fails the
        // connection rather than corrupting a delivery.
        void decompressMessage(payload).then(
          (plain) => {
            this.stats.deflatedIn++;
            this.originRow(conn.origin).deflatedIn++;
            routePlain(plain);
          },
          () => protocolViolation("compressed reply failed to inflate")
        );
        return;
      }
      routePlain(payload);
    };

    const routePlain = (text: Buffer): void => {
      let env: MuxEnvelope;
      try {
        env = JSON.parse(text.toString("utf8")) as MuxEnvelope;
      } catch {
        protocolViolation("reply is not a JSON envelope");
        return;
      }
      if (
        env === null ||
        typeof env !== "object" ||
        env.v !== 1 ||
        typeof env.cid !== "string" ||
        !MUX_CID_RE.test(env.cid) ||
        typeof env.body !== "string"
      ) {
        protocolViolation("malformed reply envelope");
        return;
      }
      if (!mux.inFlight.has(env.cid)) {
        protocolViolation(`reply for unknown correlation id ${env.cid}`);
        return;
      }
      let body: Buffer;
      try {
        body = Buffer.from(env.body, "base64");
      } catch {
        protocolViolation("reply body is not base64");
        return;
      }
      // The cap applies to the decoded reply body (mirroring the
      // exclusive path's truncation contract on the payload); the wire
      // cap above already bounded accumulation.
      let truncated = false;
      if (body.length > this.opts.maxMessageBytes) {
        body = body.subarray(0, this.opts.maxMessageBytes);
        truncated = true;
      }
      this.stats.muxIn++;
      const row = this.originRow(conn.origin);
      row.muxIn++;
      row.messagesIn++;
      this.settleMuxDelivery(conn, env.cid, { statusCode: 200, body, truncated });
    };

    const onData = (chunk: Buffer): void => {
      if (conn.dead) return;
      conn.reader.push(chunk);
      for (;;) {
        let frame: WsFrame | undefined;
        try {
          frame = conn.reader.next();
        } catch (err) {
          protocolViolation(`frame decode failed (${(err as Error).message})`);
          return;
        }
        if (frame === undefined) break;
        if (frame.opcode === OP_PING) {
          if (frame.rsv1) {
            protocolViolation("compressed control frame");
            return;
          }
          conn.socket.write(encodeWsFrame(OP_PONG, frame.payload, true));
        } else if (frame.opcode === OP_PONG) {
          if (frame.rsv1) {
            protocolViolation("compressed control frame");
            return;
          }
          conn.pongWaiter?.();
          conn.pongWaiter = undefined;
        } else if (frame.opcode === OP_TEXT || frame.opcode === OP_CONT) {
          if (frame.opcode === OP_CONT && mux.textLen === 0 && mux.text.length === 0) {
            protocolViolation("stray continuation frame");
            return;
          }
          if (frame.rsv1) {
            if (frame.opcode !== OP_TEXT || mux.text.length !== 0 || mux.textLen !== 0) {
              protocolViolation("RSV1 on non-first frame");
              return;
            }
            if (conn.deflate === null) {
              protocolViolation("compressed frame without negotiated deflate");
              return;
            }
            mux.replyCompressed = true;
          }
          if (mux.textLen + frame.payload.length > wireCap) {
            protocolViolation(`message exceeded ${wireCap} wire bytes`);
            return;
          }
          mux.text.push(frame.payload);
          mux.textLen += frame.payload.length;
          if (frame.fin) {
            const payload = Buffer.concat(mux.text);
            const wasCompressed = mux.replyCompressed;
            mux.text = [];
            mux.textLen = 0;
            mux.replyCompressed = false;
            routeMessage(payload, wasCompressed);
            if (conn.dead) return;
          }
        } else if (frame.opcode === OP_CLOSE) {
          if (frame.rsv1) {
            protocolViolation("compressed control frame");
            return;
          }
          // A close frame is the peer hanging up: echo it when the
          // socket is still open, then treat it like a close.
          if (!conn.socket.destroyed) {
            conn.socket.write(encodeWsFrame(OP_CLOSE, Buffer.alloc(0), true));
          }
          onConnClose();
          return;
        }
        // Other opcodes (binary) are ignored: the multiplexed contract
        // is envelope text frames, matching the exclusive path.
      }
    };

    mux.pump = onData;
    conn.socket.on("data", onData);
    conn.socket.once("error", onConnError);
    conn.socket.once("close", onConnClose);
  }

  /**
   * Detach the multiplexed pump and fail anything still waiting. Called
   * from `destroy()` and before a multiplexed connection is torn down
   * any other way, so no waiter is ever left hanging.
   */
  private detachMuxPump(conn: PooledWsConnection): void {
    const mux = conn.mux;
    if (mux === undefined) return;
    if (mux.pump !== undefined) {
      conn.socket.off("data", mux.pump);
      mux.pump = undefined;
    }
    this.failAllMux(conn, "multiplexed connection torn down");
  }

  // --- pool internals -------------------------------------------------------

  private async checkout(
    url: URL,
    relayHeaders: Record<string, string>,
    pins: string[] | undefined,
    targetUrl: string
  ): Promise<PooledWsConnection> {
    const key = poolKey(url, pins);
    const origin = WebSocketPool.originOf(url);
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
          this.originRow(origin).reused++;
          return c;
        }
      }
    }
    const conn = await this.open(url, relayHeaders, pins, targetUrl);
    if (this.destroyed) {
      // The pool was destroyed while the handshake was in flight: the
      // fresh connection never entered `this.conns`, so `destroy()` could
      // not kill it — do it here instead of leaking an orphan socket that
      // would pin the peer's server close forever.
      this.kill(conn);
      throw new Error("websocket: pool destroyed");
    }
    conn.busy = true;
    const arr = this.conns.get(key) ?? [];
    arr.push(conn);
    this.conns.set(key, arr);
    this.stats.created++;
    this.originRow(origin).created++;
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
    // WR-204: detach the multiplexed pump first — failAllMux rejects
    // every in-flight/queued waiter immediately instead of leaving them
    // hanging until their reply timers fire. No-op for exclusive
    // connections (mux === undefined).
    this.detachMuxPump(conn);
    if (!conn.dead) {
      conn.dead = true;
      this.stats.destroyed++;
    }
    conn.socket.destroy();
  }

  /**
   * One delivery round trip on an exclusively-held connection: send the
   * text frame (RSV1 + permessage-deflate when negotiated and worthwhile,
   * WR-46), then consume frames until a text message (the response) or a
   * clean close. Pings are auto-ponged inline.
   *
   * Inbound RSV1 marks a compressed reply: it is inflated after the final
   * fragment arrives. RSV1 on a connection without negotiated deflate, on
   * a continuation frame, or on a control frame is a protocol violation
   * and fails the delivery. A compressed reply truncated at
   * `maxMessageBytes` fails the delivery too — a partial deflate stream
   * cannot be inflated or truncated safely, so the truncation contract
   * only applies to plain text.
   */
  private async roundTrip(
    conn: PooledWsConnection,
    body: Buffer,
    targetUrl: string
  ): Promise<DownstreamResponse> {
    // WR-46: opportunistic permessage-deflate on a negotiated connection.
    // maybeCompressMessage never expands the wire: small or incompressible
    // payloads go out as plain text with RSV1 clear.
    let wire = body;
    let rsv1 = false;
    if (conn.deflate !== null && this.opts.permessageDeflate !== undefined) {
      const out = await maybeCompressMessage(
        body,
        this.opts.permessageDeflate.thresholdBytes,
        conn.deflate.windowBits
      );
      wire = out.bytes;
      rsv1 = out.compressed;
      if (rsv1) {
        this.stats.deflatedOut++;
        // WR-105: per-origin deflate accounting for the compression ratio.
        const row = this.originRow(conn.origin);
        row.deflatedOut++;
        row.deflatePlainBytes += body.length;
        row.deflateWireBytes += wire.length;
      }
    }
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
      // True once the first frame of the reply carried RSV1: the whole
      // message is one deflate stream, inflated at FIN.
      let replyCompressed = false;

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
        else finishText();
      };
      /** Complete a text reply: inflate when the message was RSV1-marked. */
      const finishText = (): void => {
        const payload = Buffer.concat(text);
        if (!replyCompressed) {
          this.originRow(conn.origin).messagesIn++;
          done({ statusCode: 200, body: payload, truncated });
          return;
        }
        if (truncated) {
          // The wire cap cut a deflate stream mid-way: it cannot be
          // inflated or truncated safely — fail, don't corrupt.
          fail(
            new Error(
              `websocket: compressed reply from ${targetUrl} exceeded maxMessageBytes ${this.opts.maxMessageBytes}`
            )
          );
          return;
        }
        this.stats.deflatedIn++;
        this.originRow(conn.origin).deflatedIn++;
        decompressMessage(payload).then(
          (plain) => {
            this.originRow(conn.origin).messagesIn++;
            done({ statusCode: 200, body: plain, truncated: false });
          },
          (err) => fail(err as Error)
        );
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
            if (frame.rsv1) {
              fail(new Error(`websocket: compressed control frame from ${targetUrl}`));
              return;
            }
            socket.write(encodeWsFrame(OP_PONG, frame.payload, true));
          } else if (frame.opcode === OP_PONG) {
            if (frame.rsv1) {
              fail(new Error(`websocket: compressed control frame from ${targetUrl}`));
              return;
            }
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
            if (frame.rsv1) {
              // RSV1 is only legal on the first frame of a message, and
              // only when deflate was negotiated for this connection.
              if (frame.opcode !== OP_TEXT || text.length !== 0 || textLen !== 0) {
                fail(new Error(`websocket: RSV1 on non-first frame from ${targetUrl}`));
                return;
              }
              if (conn.deflate === null) {
                fail(new Error(`websocket: compressed frame without negotiated deflate from ${targetUrl}`));
                return;
              }
              replyCompressed = true;
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
              finishText();
              return;
            }
          } else if (frame.opcode === OP_CLOSE) {
            if (frame.rsv1) {
              fail(new Error(`websocket: compressed control frame from ${targetUrl}`));
              return;
            }
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
      socket.write(encodeWsFrame(OP_TEXT, wire, true, rsv1), (err) => {
        if (err) fail(err);
        // WR-105: the delivery frame is on the wire — count it as sent.
        else this.originRow(conn.origin).messagesOut++;
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
        // WR-204: a multiplexed connection carrying in-flight
        // deliveries or a parked queue is not idle — never reap or
        // probe-ping it out from under its deliveries. (Pinging is
        // fine — control frames interleave — but reaping is not.)
        const muxLoad =
          conn.mux === undefined ? 0 : conn.mux.inFlight.size + conn.mux.queue.length;
        if (muxLoad > 0) continue;
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
      // WR-105: measure the keep-alive round trip for the per-origin
      // ping-RTT gauge (bounded recent window).
      const start = Date.now();
      const timer = setTimeout(() => {
        conn.pongWaiter = undefined;
        resolve(false);
      }, this.opts.timeoutMs);
      conn.pongWaiter = () => {
        clearTimeout(timer);
        const rtt = Date.now() - start;
        const row = this.originRow(conn.origin);
        row.pingRtts.push(rtt);
        if (row.pingRtts.length > MAX_PING_RTT_SAMPLES) row.pingRtts.shift();
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
      const conn: PooledWsConnection = {
        socket,
        reader,
        origin: WebSocketPool.originOf(url),
        idleSince: Date.now(),
        busy: false,
        dead: false,
        deflate: null,
      };

      const verifyPins = (): void => {
        // WR-73: capture the peer certificate's expiry at handshake time
        // (the same getPeerCertificate read the pin check below uses) —
        // runs before pinning so unpinned endpoints are covered too. The
        // hook is an observer: it must never break the delivery.
        if (secure) {
          try {
            this.opts.onTlsPeerCertificate?.(socket as TLSSocket, targetUrl);
          } catch {
            // Swallowed on purpose — expiry telemetry is never a gate.
          }
        }
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
        // WR-46: offer permessage-deflate with both no-context-takeover
        // parameters required (see src/deflate.ts for the strict
        // negotiation model).
        if (this.opts.permessageDeflate !== undefined) {
          lines.push(`Sec-WebSocket-Extensions: ${PERMESSAGE_DEFLATE_OFFER}`);
        }
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
          // WR-46: settle permessage-deflate. No offer was sent → ignore
          // any extension the server volunteers; offer sent but no
          // permessage-deflate in the response → plain text connection.
          // A violating permessage-deflate answer fails the handshake
          // (plain Error → retryable) rather than mis-negotiating.
          if (this.opts.permessageDeflate !== undefined) {
            try {
              conn.deflate = negotiatePerMessageDeflate(headers["sec-websocket-extensions"]);
            } catch (err) {
              fail(err as Error);
              return;
            }
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
