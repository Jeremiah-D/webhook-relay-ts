import { describe, it, after } from "node:test";
import assert from "node:assert/strict";
import { connect, type Socket } from "node:net";
import { randomBytes } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import { compressMessage, decompressMessage, maybeCompressMessage } from "../src/deflate.ts";
import {
  INBOUND_DEFLATE_ACCEPT,
  InboundWsParser,
  negotiateInboundPerMessageDeflate,
  resolveInboundWsOptions,
  wsDeflatedTextFrame,
  WsProtocolError,
} from "../src/inbound-ws.ts";
import type { RetryItem } from "../src/retry.ts";

// Never name a constant SECRET here: the runtime secret redaction rewrites
// `secret: SECRET` occurrences and breaks the TS syntax (see AGENTS.md).
const TEST_KEY = "ws-deflate-test-key";
const RFC_WS_KEY = "dGhlIHNhbXBsZSBub25jZQ==";
const FULL_OFFER =
  "permessage-deflate; client_no_context_takeover; server_no_context_takeover";

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

async function closeRelay(relay: Server): Promise<void> {
  relay.close();
  await new Promise<void>((r) => relay.once("close", r));
}

async function waitFor(cond: () => boolean, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!cond() && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.ok(cond(), "timed out waiting for condition");
}

// --- raw RFC 6455 test client (zero dependencies) ---------------------------

interface ServerFrame {
  opcode: number;
  rsv1: boolean;
  payload: Buffer;
}

/** Client→server frame with full FIN/RSV1 control. Always masked. */
function clientFrame(
  opcode: number,
  payload: Buffer,
  opts: { fin?: boolean; rsv1?: boolean } = {}
): Buffer {
  const b0 = (opts.fin === false ? 0x00 : 0x80) | (opts.rsv1 === true ? 0x40 : 0) | opcode;
  const len = payload.length;
  let header: Buffer;
  if (len < 126) {
    header = Buffer.from([b0, 0x80 | len]);
  } else {
    header = Buffer.alloc(4);
    header[0] = b0;
    header[1] = 0x80 | 126;
    header.writeUInt16BE(len, 2);
  }
  const mask = randomBytes(4);
  const masked = Buffer.alloc(len);
  for (let i = 0; i < len; i++) masked[i] = payload[i] ^ mask[i % 4];
  return Buffer.concat([header, mask, masked]);
}

function rawUpgrade(
  port: number,
  requestText: string
): Promise<{ status: number; headers: Record<string, string>; socket: Socket }> {
  return new Promise((resolve, reject) => {
    const socket = connect(port, "127.0.0.1");
    let buf = Buffer.alloc(0);
    let done = false;
    const timer = setTimeout(() => {
      if (!done) {
        done = true;
        socket.destroy();
        reject(new Error("upgrade response timeout"));
      }
    }, 5000);
    socket.on("data", (c: Buffer) => {
      if (done) return;
      buf = Buffer.concat([buf, c]);
      const idx = buf.indexOf("\r\n\r\n");
      if (idx < 0) return;
      done = true;
      clearTimeout(timer);
      const head = buf.subarray(0, idx).toString("latin1").split("\r\n");
      const status = Number(head[0].split(" ")[1]);
      const headers: Record<string, string> = {};
      for (const line of head.slice(1)) {
        const i = line.indexOf(":");
        if (i > 0) headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
      }
      socket.removeAllListeners("data");
      resolve({ status, headers, socket });
    });
    socket.on("error", (err) => {
      if (!done) {
        done = true;
        clearTimeout(timer);
        reject(err);
      }
    });
    socket.on("close", () => {
      if (!done) {
        done = true;
        clearTimeout(timer);
        resolve({ status: 0, headers: {}, socket });
      }
    });
    socket.write(requestText);
  });
}

function handshakeRequest(extraHeaders: Record<string, string> = {}): string {
  const lines = [
    "GET /ingest/ws HTTP/1.1",
    "Host: 127.0.0.1",
    "Upgrade: websocket",
    "Connection: Upgrade",
    `Sec-WebSocket-Key: ${RFC_WS_KEY}`,
    "Sec-WebSocket-Version: 13",
  ];
  for (const [k, v] of Object.entries(extraHeaders)) lines.push(`${k}: ${v}`);
  return lines.join("\r\n") + "\r\n\r\n";
}

interface TestClient {
  socket: Socket;
  nextFrame: () => Promise<ServerFrame>;
  nextText: () => Promise<any>;
  destroy: () => void;
}

async function wsConnect(port: number, extraHeaders: Record<string, string> = {}): Promise<TestClient> {
  const { status, socket } = await rawUpgrade(port, handshakeRequest(extraHeaders));
  assert.equal(status, 101, `expected 101, got ${status}`);
  let buf = Buffer.alloc(0);
  const pending: Array<(f: ServerFrame) => void> = [];
  const queued: ServerFrame[] = [];
  socket.on("data", (c: Buffer) => {
    buf = Buffer.concat([buf, c]);
    for (;;) {
      if (buf.length < 2) break;
      const b0 = buf[0];
      const opcode = b0 & 0x0f;
      const rsv1 = (b0 & 0x40) !== 0;
      let len = buf[1] & 0x7f;
      let off = 2;
      if (len === 126) {
        if (buf.length < 4) break;
        len = buf.readUInt16BE(2);
        off = 4;
      } else if (len === 127) {
        if (buf.length < 10) break;
        len = Number(buf.readBigUInt64BE(2));
        off = 10;
      }
      // The server never masks (RFC 6455 §5.3).
      if (buf.length < off + len) break;
      const frame = { opcode, rsv1, payload: buf.subarray(off, off + len) };
      buf = buf.subarray(off + len);
      const waiter = pending.shift();
      if (waiter !== undefined) waiter(frame);
      else queued.push(frame);
    }
  });
  socket.on("error", () => {});
  const nextFrame = (): Promise<ServerFrame> =>
    new Promise((resolve, reject) => {
      const q = queued.shift();
      if (q !== undefined) {
        resolve(q);
        return;
      }
      const timer = setTimeout(() => reject(new Error("frame timeout")), 10000);
      pending.push((f) => {
        clearTimeout(timer);
        resolve(f);
      });
    });
  return {
    socket,
    nextFrame,
    nextText: async () => {
      const f = await nextFrame();
      assert.equal(f.opcode, 1, `expected text frame, got opcode ${f.opcode}`);
      return JSON.parse(f.payload.toString("utf8"));
    },
    destroy: () => socket.destroy(),
  };
}

// --- relay factory -----------------------------------------------------------

const relays: Server[] = [];
const clients: TestClient[] = [];

function makeRelay(extraOpts: Record<string, unknown> = {}): Promise<{ port: number; seen: RetryItem[] }> {
  const dir = mkdtempSync(join(tmpdir(), "audit-ws-deflate-"));
  const audit = new AuditLog(join(dir, "audit.jsonl"));
  const seen: RetryItem[] = [];
  const relay = createRelayServer({
    secret: TEST_KEY,
    forwardUrl: "http://127.0.0.1:1/unused",
    auditLog: audit,
    sender: async (item: RetryItem) => {
      seen.push(item);
    },
    retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 3 },
    inboundWs: { permessageDeflate: true },
    ...extraOpts,
  });
  relays.push(relay);
  return listen(relay).then((port) => ({ port, seen }));
}

/** One signed event envelope, shaped like a WR-61 batch item. */
function envelope(payload: unknown, headers: Record<string, string> = {}): string {
  const raw = Buffer.from(JSON.stringify(payload));
  return JSON.stringify({
    payload: raw.toString("base64"),
    headers: { "x-signature": signSha256(raw, TEST_KEY), ...headers },
  });
}

// --- option validation -------------------------------------------------------

describe("resolveInboundWsOptions permessageDeflate (WR-152)", () => {
  it("stays off by default", () => {
    assert.equal(resolveInboundWsOptions({}).permessageDeflate, undefined);
    assert.equal(resolveInboundWsOptions({ permessageDeflate: false }).permessageDeflate, undefined);
  });

  it("enables with defaults on `true`", () => {
    assert.deepEqual(resolveInboundWsOptions({ permessageDeflate: true }).permessageDeflate, {
      thresholdBytes: 1024,
      maxInflatedBytes: 8388608,
    });
  });

  it("honors an explicit thresholdBytes", () => {
    assert.deepEqual(
      resolveInboundWsOptions({ permessageDeflate: { thresholdBytes: 2048 } }).permessageDeflate,
      { thresholdBytes: 2048, maxInflatedBytes: 8388608 }
    );
  });

  it("rejects illegal values with RangeError", () => {
    for (const bad of [0, -1, 1.5, Number.NaN, "1024", null, [], "yes"] as unknown[]) {
      assert.throws(
        () => resolveInboundWsOptions({ permessageDeflate: bad as never }),
        RangeError,
        `expected RangeError for ${JSON.stringify(bad)}`
      );
    }
  });
});

// --- strict server-side negotiation ------------------------------------------

describe("negotiateInboundPerMessageDeflate (WR-152)", () => {
  it("returns null when the client offers nothing", () => {
    assert.equal(negotiateInboundPerMessageDeflate(undefined), null);
    assert.equal(negotiateInboundPerMessageDeflate(""), null);
    assert.equal(negotiateInboundPerMessageDeflate("   "), null);
    assert.equal(negotiateInboundPerMessageDeflate("gzip"), null);
    assert.equal(negotiateInboundPerMessageDeflate("deflate, gzip"), null);
  });

  it("rejects an offer missing either no_context_takeover parameter", () => {
    assert.throws(() => negotiateInboundPerMessageDeflate("permessage-deflate"), /no_context_takeover/);
    assert.throws(
      () => negotiateInboundPerMessageDeflate("permessage-deflate; client_no_context_takeover"),
      /no_context_takeover/
    );
    assert.throws(
      () => negotiateInboundPerMessageDeflate("permessage-deflate; server_no_context_takeover"),
      /no_context_takeover/
    );
  });

  it("accepts the strict offer", () => {
    assert.deepEqual(negotiateInboundPerMessageDeflate(FULL_OFFER), { clientWindowBits: 15 });
  });

  it("honors client_max_window_bits 8–15 and rejects the rest", () => {
    assert.deepEqual(negotiateInboundPerMessageDeflate(`${FULL_OFFER}; client_max_window_bits=10`), {
      clientWindowBits: 10,
    });
    assert.deepEqual(negotiateInboundPerMessageDeflate(`${FULL_OFFER}; client_max_window_bits=8`), {
      clientWindowBits: 8,
    });
    for (const bad of ["7", "16", "abc", "9.5", ""]) {
      assert.throws(
        () => negotiateInboundPerMessageDeflate(`${FULL_OFFER}; client_max_window_bits=${bad}`),
        /client_max_window_bits/
      );
    }
  });

  it("accepts server_max_window_bits but ignores it", () => {
    assert.deepEqual(negotiateInboundPerMessageDeflate(`${FULL_OFFER}; server_max_window_bits=12`), {
      clientWindowBits: 15,
    });
  });

  it("rejects unknown parameters", () => {
    assert.throws(
      () => negotiateInboundPerMessageDeflate(`${FULL_OFFER}; foo=bar`),
      /unsupported/
    );
    assert.throws(
      () => negotiateInboundPerMessageDeflate(`${FULL_OFFER}; context_takeover`),
      /unsupported/
    );
  });

  it("is case-insensitive and tolerates quoted values and sibling extensions", () => {
    assert.deepEqual(
      negotiateInboundPerMessageDeflate(
        "Permessage-Deflate; Client_No_Context_Takeover; Server_No_Context_Takeover"
      ),
      { clientWindowBits: 15 }
    );
    assert.deepEqual(
      negotiateInboundPerMessageDeflate(`${FULL_OFFER}; client_max_window_bits="10"`),
      { clientWindowBits: 10 }
    );
    assert.deepEqual(
      negotiateInboundPerMessageDeflate(
        `x-custom; a=b, ${FULL_OFFER}`
      ),
      { clientWindowBits: 15 }
    );
  });
});

// --- parser: RSV1 handling ----------------------------------------------------

describe("InboundWsParser permessage-deflate (WR-152)", () => {
  const payload = Buffer.from(envelope({ hello: "world" }), "utf8");

  it("rejects RSV1 when nothing was negotiated", () => {
    const parser = new InboundWsParser(1024);
    assert.throws(
      () => parser.push(clientFrame(0x1, payload, { rsv1: true })),
      (err: unknown) =>
        err instanceof WsProtocolError &&
        err.closeCode === 1002 &&
        /without a negotiated extension/.test(err.message)
    );
  });

  it("rejects RSV1 on a binary frame when nothing was negotiated", () => {
    const parser = new InboundWsParser(1024);
    assert.throws(() => parser.push(clientFrame(0x2, payload, { rsv1: true })), WsProtocolError);
  });

  it("marks an RSV1 data frame compressed once negotiated", async () => {
    const parser = new InboundWsParser(1024, true);
    const compressed = await compressMessage(payload);
    const [msg] = parser.push(clientFrame(0x1, compressed, { rsv1: true }));
    assert.equal(msg.kind, "text");
    assert.equal(msg.compressed, true);
    assert.ok(msg.data.equals(compressed));
    // The caller inflates with the deflate.ts primitive (oracle check).
    assert.ok((await decompressMessage(msg.data)).equals(payload));
  });

  it("passes uncompressed frames through once negotiated", () => {
    const parser = new InboundWsParser(1024, true);
    const [msg] = parser.push(clientFrame(0x1, payload));
    assert.equal(msg.kind, "text");
    assert.equal(msg.compressed, false);
    assert.ok(msg.data.equals(payload));
  });

  it("rejects RSV1 on a control frame even when negotiated", () => {
    const parser = new InboundWsParser(1024, true);
    assert.throws(
      () => parser.push(clientFrame(0x9, Buffer.alloc(0), { rsv1: true })),
      (err: unknown) =>
        err instanceof WsProtocolError && err.closeCode === 1002 && /control frame/.test(err.message)
    );
  });

  it("rejects RSV1 on a continuation frame", async () => {
    const parser = new InboundWsParser(1024, true);
    const compressed = await compressMessage(payload);
    const half = Math.floor(compressed.length / 2);
    const out = parser.push(
      clientFrame(0x1, compressed.subarray(0, half), { fin: false, rsv1: true })
    );
    assert.equal(out.length, 0);
    assert.throws(
      () =>
        parser.push(clientFrame(0x0, compressed.subarray(half), { rsv1: true })),
      (err: unknown) =>
        err instanceof WsProtocolError &&
        err.closeCode === 1002 &&
        /continuation/.test(err.message)
    );
  });

  it("rejects RSV2/RSV3 even when negotiated", () => {
    const parser = new InboundWsParser(1024, true);
    // Hand-set RSV2 (0x20) on an otherwise valid masked text frame.
    const frame = clientFrame(0x1, payload);
    frame[0] |= 0x20;
    assert.throws(() => parser.push(frame), WsProtocolError);
  });

  it("reassembles a fragmented RSV1 message with the first frame deciding", async () => {
    const parser = new InboundWsParser(1024, true);
    const compressed = await compressMessage(payload);
    const half = Math.floor(compressed.length / 2);
    assert.equal(
      parser.push(clientFrame(0x1, compressed.subarray(0, half), { fin: false, rsv1: true })).length,
      0
    );
    const [msg] = parser.push(clientFrame(0x0, compressed.subarray(half)));
    assert.equal(msg.kind, "text");
    assert.equal(msg.compressed, true);
    assert.ok((await decompressMessage(msg.data)).equals(payload));
  });
});

// --- outbound ack compression --------------------------------------------------

describe("wsDeflatedTextFrame (WR-152)", () => {
  it("sends plain frames when deflate is off", async () => {
    const frame = await wsDeflatedTextFrame("hello", undefined);
    assert.equal(frame[0] & 0x40, 0, "RSV1 must be clear");
    assert.equal(frame[0] & 0x0f, 0x1);
  });

  it("leaves small acks uncompressed when negotiated", async () => {
    const frame = await wsDeflatedTextFrame('{"type":"event-ack"}', { thresholdBytes: 1024 });
    assert.equal(frame[0] & 0x40, 0, "RSV1 must be clear below the threshold");
  });

  it("compresses a large ack and the peer can inflate it", async () => {
    const text = JSON.stringify({ type: "event-ack", data: "a".repeat(3000) });
    const frame = await wsDeflatedTextFrame(text, { thresholdBytes: 1024 });
    assert.notEqual(frame[0] & 0x40, 0, "RSV1 must be set on a compressed frame");
    assert.ok(frame.length < Buffer.byteLength(text), "compressed frame must be smaller");
    const len = frame[1] & 0x7f;
    const off = len === 126 ? 4 : 2;
    const payload = frame.subarray(off, off + (len === 126 ? frame.readUInt16BE(2) : len));
    assert.equal((await decompressMessage(payload)).toString("utf8"), text);
  });

  it("never expands the wire: incompressible payloads ride plain", async () => {
    // maybeCompressMessage owns the never-expand guarantee: 1100
    // uniformly-random bytes cannot deflate below their input size
    // (stored-block overhead only grows them), so they must come back
    // untouched. (Tested at this level rather than through
    // wsDeflatedTextFrame because any JS string with high bytes gains
    // compressible structure from its UTF-8 encoding.)
    const { bytes, compressed } = await maybeCompressMessage(randomBytes(1100), 1024);
    assert.equal(compressed, false);
    assert.equal(bytes.length, 1100);
  });
});

// --- end-to-end ------------------------------------------------------------------

describe("inbound permessage-deflate end-to-end (WR-152)", () => {
  after(async () => {
    for (const c of clients.splice(0)) c.destroy();
    for (const r of relays.splice(0)) await closeRelay(r);
  });

  it("answers the strict offer with the accept header", async () => {
    const { port } = await makeRelay();
    const { status, headers, socket } = await rawUpgrade(
      port,
      handshakeRequest({ "Sec-WebSocket-Extensions": FULL_OFFER })
    );
    assert.equal(status, 101);
    assert.equal(headers["sec-websocket-extensions"], INBOUND_DEFLATE_ACCEPT);
    socket.destroy();
  });

  it("omits the extension header when the client offers nothing", async () => {
    const { port } = await makeRelay();
    const { status, headers, socket } = await rawUpgrade(port, handshakeRequest());
    assert.equal(status, 101);
    assert.equal(headers["sec-websocket-extensions"], undefined);
    socket.destroy();
  });

  it("fails the upgrade with 400 on a violating offer", async () => {
    const { port } = await makeRelay();
    const { status, socket } = await rawUpgrade(
      port,
      handshakeRequest({
        "Sec-WebSocket-Extensions": "permessage-deflate; client_no_context_takeover",
      })
    );
    assert.equal(status, 400);
    socket.destroy();
  });

  it("accepts a compressed event and acks it", async () => {
    const { port, seen } = await makeRelay();
    const client = await wsConnect(port, { "Sec-WebSocket-Extensions": FULL_OFFER });
    clients.push(client);
    const compressed = await compressMessage(Buffer.from(envelope({ n: 1 }), "utf8"));
    client.socket.write(clientFrame(0x1, compressed, { rsv1: true }));
    const ack = await client.nextText();
    assert.equal(ack.type, "event-ack");
    assert.equal(ack.status, "accepted");
    // The sender runs on the queue's async dispatch loop — it lands after
    // the ack, so wait for it instead of asserting synchronously.
    await waitFor(() => seen.length === 1);
  });

  it("still accepts uncompressed events on a negotiated connection", async () => {
    const { port, seen } = await makeRelay();
    const client = await wsConnect(port, { "Sec-WebSocket-Extensions": FULL_OFFER });
    clients.push(client);
    client.socket.write(clientFrame(0x1, Buffer.from(envelope({ n: 2 }), "utf8")));
    const ack = await client.nextText();
    assert.equal(ack.status, "accepted");
    await waitFor(() => seen.length === 1);
  });

  it("closes with 1002 when RSV1 arrives without negotiation", async () => {
    const { port } = await makeRelay({ inboundWs: {} });
    const client = await wsConnect(port);
    clients.push(client);
    client.socket.write(clientFrame(0x1, Buffer.from("x"), { rsv1: true }));
    const frame = await client.nextFrame();
    assert.equal(frame.opcode, 0x8);
    assert.equal(frame.payload.readUInt16BE(0), 1002);
  });

  it("closes with 1002 on an undecodable compressed frame", async () => {
    const { port } = await makeRelay();
    const client = await wsConnect(port, { "Sec-WebSocket-Extensions": FULL_OFFER });
    clients.push(client);
    // 0xff… starts with BTYPE=11 (reserved) — deterministically invalid deflate.
    client.socket.write(clientFrame(0x1, Buffer.from([0xff, 0xff, 0xff, 0xff]), { rsv1: true }));
    const frame = await client.nextFrame();
    assert.equal(frame.opcode, 0x8);
    assert.equal(frame.payload.readUInt16BE(0), 1002);
  });

  it("never accepts a truncated compressed frame as a valid event", async () => {
    // RFC 7692's sync-flush marker is a *non-final* empty stored block
    // (BFINAL=0) by design, so whether a truncated stream still decodes
    // depends on where it was cut: an encoding-breaking cut fails the
    // inflate (1002 via the protocol-error channel); a cleanly-decodable
    // cut inflates to partial data and fails the envelope parse
    // (event-error 400). Either way the partial event is never accepted —
    // the WR-61 HMAC envelope (never the compressor) is the integrity
    // backstop. The reference `ws` implementation behaves the same.
    const { port, seen } = await makeRelay();
    const client = await wsConnect(port, { "Sec-WebSocket-Extensions": FULL_OFFER });
    clients.push(client);
    const compressed = await compressMessage(Buffer.from(envelope({ n: 3 }), "utf8"));
    client.socket.write(
      clientFrame(0x1, compressed.subarray(0, Math.floor(compressed.length / 2)), { rsv1: true })
    );
    const first = await client.nextFrame();
    if (first.opcode === 0x8) {
      assert.equal(first.payload.readUInt16BE(0), 1002, "close code must be 1002");
    } else {
      const body = JSON.parse(first.payload.toString("utf8"));
      assert.equal(body.type, "event-error");
      assert.equal(body.code, 400);
      // The connection survives a cleanly-decodable truncation: a later
      // valid event is still accepted.
      client.socket.write(clientFrame(0x1, Buffer.from(envelope({ n: 4 }), "utf8")));
      const ack = await client.nextText();
      assert.equal(ack.status, "accepted");
      await waitFor(() => seen.length === 1);
      return;
    }
    assert.equal(seen.length, 0);
  });
});
