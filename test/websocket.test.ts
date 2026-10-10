import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server, type Socket } from "node:net";
import { createServer as createTlsServer, type TLSSocket } from "node:tls";
import { createHash } from "node:crypto";
import { WebSocketPool, encodeWsFrame, wsAcceptKey, WsFrameReader } from "../src/websocket.ts";
import { createDefaultSender } from "../src/server.ts";
import { HttpDeliveryError } from "../src/failure.ts";
import { TlsPinMismatchError } from "../src/pinning.ts";
import { TLS_FIXTURE_CERT_PEM, TLS_FIXTURE_KEY_PEM, TLS_FIXTURE_SPKI_PIN } from "./tls-fixture.ts";
import type { RetryItem } from "../src/retry.ts";

// --- minimal RFC 6455 test server (raw sockets, no dependencies) -----------

interface ServerFrame {
  fin: boolean;
  opcode: number;
  masked: boolean;
  payload: Buffer;
}

function readFrame(buf: Buffer, off: number): { frame: ServerFrame; next: number } | undefined {
  if (buf.length - off < 2) return undefined;
  const fin = (buf[off] & 0x80) !== 0;
  const opcode = buf[off] & 0x0f;
  const masked = (buf[off + 1] & 0x80) !== 0;
  let len = buf[off + 1] & 0x7f;
  let hlen = 2;
  if (len === 126) {
    if (buf.length - off < 4) return undefined;
    len = buf.readUInt16BE(off + 2);
    hlen = 4;
  } else if (len === 127) {
    if (buf.length - off < 10) return undefined;
    len = Number(buf.readBigUInt64BE(off + 2));
    hlen = 10;
  }
  const mlen = masked ? 4 : 0;
  if (buf.length - off < hlen + mlen + len) return undefined;
  let payload = buf.subarray(off + hlen + mlen, off + hlen + mlen + len);
  if (masked) {
    const mask = buf.subarray(off + hlen, off + hlen + 4);
    const out = Buffer.alloc(len);
    for (let i = 0; i < len; i++) out[i] = payload[i] ^ mask[i % 4];
    payload = out;
  }
  return { frame: { fin, opcode, masked, payload }, next: off + hlen + mlen + len };
}

function serverFrame(opcode: number, payload: Buffer): Buffer {
  // Servers never mask.
  return encodeWsFrame(opcode, payload, false);
}

interface TestServer {
  url: (path?: string) => string;
  connections: () => number;
  lastUpgradeHeaders: () => Record<string, string> | undefined;
  lastClientMasked: () => boolean | undefined;
  /** True once the server received a pong for a ping it sent. */
  gotPong: () => boolean;
  close: () => Promise<void>;
  onText: (fn: (text: Buffer, reply: (data: Buffer) => void) => void) => void;
  sendPingOnHandshake: () => void;
  respond404: () => void;
}

/** Raw-socket WebSocket server for tests. */
async function startTestServer(opts: { tls?: boolean; respond404?: boolean } = {}): Promise<TestServer> {
  let connectionCount = 0;
  let lastHeaders: Record<string, string> | undefined;
  let lastMasked: boolean | undefined;
  let pongReceived = false;
  let textHandler: ((text: Buffer, reply: (data: Buffer) => void) => void) | undefined;
  let pingOnHandshake = false;
  const server: Server = opts.tls
    ? createTlsServer({ cert: TLS_FIXTURE_CERT_PEM, key: TLS_FIXTURE_KEY_PEM })
    : createServer();

  server.on("secureConnection", (s: TLSSocket) => void handleSocket(s as unknown as Socket));
  server.on("connection", (s: Socket) => void handleSocket(s));

  async function handleSocket(socket: Socket): Promise<void> {
    connectionCount++;
    let head = Buffer.alloc(0);
    let handshook = false;
    let buf = Buffer.alloc(0);
    const onData = (chunk: Buffer): void => {
      if (!handshook) {
        head = Buffer.concat([head, chunk]);
        const end = head.indexOf("\r\n\r\n");
        if (end < 0) return;
        const text = head.subarray(0, end).toString("latin1");
        const [requestLine, ...lines] = text.split("\r\n");
        const headers: Record<string, string> = {};
        for (const line of lines) {
          const i = line.indexOf(":");
          if (i > 0) headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
        }
        lastHeaders = headers;
        const key = headers["sec-websocket-key"] ?? "";
        if (opts.respond404 || !requestLine.startsWith("GET")) {
          socket.write("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
          socket.end();
          return;
        }
        socket.write(
          "HTTP/1.1 101 Switching Protocols\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            `Sec-WebSocket-Accept: ${wsAcceptKey(key)}\r\n\r\n`
        );
        handshook = true;
        buf = head.subarray(end + 4);
        if (pingOnHandshake) socket.write(serverFrame(0x9, Buffer.from("keepalive")));
        drain();
        return;
      }
      buf = Buffer.concat([buf, chunk]);
      drain();
    };
    function drain(): void {
      let off = 0;
      for (;;) {
        const r = readFrame(buf, off);
        if (r === undefined) break;
        off = r.next;
        const { frame } = r;
        if (frame.opcode === 0x1) {
          lastMasked = frame.masked;
          const reply = (data: Buffer): void => {
            socket.write(serverFrame(0x1, data));
          };
          textHandler?.(frame.payload, reply);
        } else if (frame.opcode === 0x9) {
          socket.write(serverFrame(0xa, frame.payload));
        } else if (frame.opcode === 0xa) {
          pongReceived = true;
        } else if (frame.opcode === 0x8) {
          socket.write(serverFrame(0x8, Buffer.alloc(0)));
          socket.end();
        }
      }
      buf = buf.subarray(off);
    }
    socket.on("data", onData);
  }

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  if (addr === null || typeof addr === "string") throw new Error("no address");
  const scheme = opts.tls ? "wss" : "ws";
  return {
    url: (path = "/hook") => `${scheme}://127.0.0.1:${addr.port}${path}`,
    connections: () => connectionCount,
    lastUpgradeHeaders: () => lastHeaders,
    lastClientMasked: () => lastMasked,
    gotPong: () => pongReceived,
    close: () => new Promise<void>((resolve, reject) => server.close((e) => (e ? reject(e) : resolve()))),
    onText: (fn) => {
      textHandler = fn;
    },
    sendPingOnHandshake: () => {
      pingOnHandshake = true;
    },
    respond404: () => {},
  };
}

function itemFor(targetUrl: string, payload = "hello"): RetryItem {
  return {
    id: "evt-1",
    targetUrl,
    payload: Buffer.from(payload),
    headers: {},
    attempt: 0,
  } as RetryItem;
}

const pools: WebSocketPool[] = [];
const servers: TestServer[] = [];
afterEach(async () => {
  for (const p of pools.splice(0)) p.destroy();
  for (const s of servers.splice(0)) await s.close();
});

function trackPool(p: WebSocketPool): WebSocketPool {
  pools.push(p);
  return p;
}

async function trackServer(s: TestServer): Promise<TestServer> {
  servers.push(s);
  return s;
}

test("echo: text frame in, text frame out, 200", async () => {
  const srv = await trackServer(await startTestServer());
  srv.onText((text, reply) => reply(Buffer.concat([Buffer.from("echo:"), text])));
  const pool = trackPool(new WebSocketPool({ pingIntervalMs: 0 }));
  const res = await pool.deliver(new URL(srv.url()), Buffer.from("ping-body"), {}, undefined, srv.url());
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.toString(), "echo:ping-body");
  assert.equal(res.truncated, false);
  assert.equal(srv.lastClientMasked(), true, "client frames must be masked");
});

test("x-relay-* headers ride the upgrade request", async () => {
  const srv = await trackServer(await startTestServer());
  srv.onText((_text, reply) => reply(Buffer.from("ok")));
  const pool = trackPool(new WebSocketPool({ pingIntervalMs: 0 }));
  await pool.deliver(
    new URL(srv.url()),
    Buffer.from("{}"),
    { "x-relay-idempotency-key": "k1", "x-relay-signature": "sig" },
    undefined,
    srv.url()
  );
  const h = srv.lastUpgradeHeaders();
  assert.equal(h?.["x-relay-idempotency-key"], "k1");
  assert.equal(h?.["x-relay-signature"], "sig");
  assert.equal(h?.["upgrade"]?.toLowerCase(), "websocket");
  assert.equal(h?.["sec-websocket-version"], "13");
});

test("non-101 handshake becomes HttpDeliveryError (dead-letter path)", async () => {
  const srv = await trackServer(await startTestServer({ respond404: true }));
  const pool = trackPool(new WebSocketPool({ pingIntervalMs: 0 }));
  await assert.rejects(
    pool.deliver(new URL(srv.url()), Buffer.from("{}"), {}, undefined, srv.url()),
    (err: unknown) => err instanceof HttpDeliveryError && err.statusCode === 404
  );
});

test("connection refused rejects with a retryable plain error", async () => {
  const pool = trackPool(new WebSocketPool({ pingIntervalMs: 0 }));
  await assert.rejects(
    pool.deliver(new URL("ws://127.0.0.1:1/hook"), Buffer.from("{}"), {}, undefined, "ws://127.0.0.1:1/hook"),
    (err: unknown) => err instanceof Error && !(err instanceof HttpDeliveryError)
  );
});

test("server ping is auto-ponged, delivery still completes", async () => {
  const srv = await trackServer(await startTestServer());
  srv.sendPingOnHandshake();
  srv.onText((_text, reply) => reply(Buffer.from("ok")));
  const pool = trackPool(new WebSocketPool({ pingIntervalMs: 0 }));
  const res = await pool.deliver(new URL(srv.url()), Buffer.from("{}"), {}, undefined, srv.url());
  assert.equal(res.statusCode, 200);
  // Give the pong a tick to arrive back at the server.
  await new Promise((r) => setTimeout(r, 50));
  assert.equal(srv.gotPong(), true, "client must answer ping with pong");
});

test("connections are reused across deliveries (WR-24 combo)", async () => {
  const srv = await trackServer(await startTestServer());
  srv.onText((_text, reply) => reply(Buffer.from("ok")));
  const pool = trackPool(new WebSocketPool({ pingIntervalMs: 0 }));
  const url = new URL(srv.url());
  await pool.deliver(url, Buffer.from("one"), {}, undefined, srv.url());
  await pool.deliver(url, Buffer.from("two"), {}, undefined, srv.url());
  assert.equal(srv.connections(), 1, "second delivery must reuse the pooled connection");
  const stats = pool.getStats();
  assert.equal(stats.created, 1);
  assert.equal(stats.reused, 1);
});

test("clean close with no reply counts as accepted (200, empty body)", async () => {
  // Fire-and-forget downstream: reads the text frame, then closes
  // without replying.
  const raw: Server = createServer((socket: Socket) => {
    let head = Buffer.alloc(0);
    let buf = Buffer.alloc(0);
    let handshook = false;
    let closed = false;
    socket.on("data", (chunk: Buffer) => {
      if (closed) return;
      if (!handshook) {
        head = Buffer.concat([head, chunk]);
        const end = head.indexOf("\r\n\r\n");
        if (end < 0) return;
        const key = head.subarray(0, end).toString("latin1").match(/sec-websocket-key:\s*(\S+)/i)?.[1] ?? "";
        socket.write(
          `HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${wsAcceptKey(key)}\r\n\r\n`
        );
        handshook = true;
        buf = head.subarray(end + 4);
      } else {
        buf = Buffer.concat([buf, chunk]);
      }
      if (buf.length >= 2) {
        closed = true;
        socket.write(encodeWsFrame(0x8, Buffer.alloc(0), false));
        socket.end();
      }
    });
  });
  await new Promise<void>((r) => raw.listen(0, "127.0.0.1", r));
  const addr = raw.address();
  if (addr === null || typeof addr === "string") throw new Error("no address");
  const target = `ws://127.0.0.1:${(addr as { port: number }).port}/hook`;
  const closer = { close: () => new Promise<void>((r2, j2) => raw.close((e) => (e ? j2(e) : r2()))) };
  servers.push(closer as unknown as TestServer);
  const pool = trackPool(new WebSocketPool({ pingIntervalMs: 0 }));
  const res = await pool.deliver(new URL(target), Buffer.from("fire"), {}, undefined, target);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.length, 0);
});

test("oversized reply is truncated at maxMessageBytes", async () => {
  const srv = await trackServer(await startTestServer());
  srv.onText((_text, reply) => reply(Buffer.alloc(100, 0x61)));
  const pool = trackPool(new WebSocketPool({ pingIntervalMs: 0, maxMessageBytes: 10 }));
  const res = await pool.deliver(new URL(srv.url()), Buffer.from("{}"), {}, undefined, srv.url());
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.length, 10);
  assert.equal(res.truncated, true);
});

test("wss pin mismatch fails the attempt (WR-21 combo)", async () => {
  const srv = await trackServer(await startTestServer({ tls: true }));
  srv.onText((_text, reply) => reply(Buffer.from("ok")));
  const pool = trackPool(new WebSocketPool({ pingIntervalMs: 0 }));
  await assert.rejects(
    pool.deliver(new URL(srv.url()), Buffer.from("{}"), {}, ["sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="], srv.url()),
    (err: unknown) => err instanceof TlsPinMismatchError
  );
});

test("wss with correct pin delivers", async () => {
  const srv = await trackServer(await startTestServer({ tls: true }));
  srv.onText((_text, reply) => reply(Buffer.from("secure-ok")));
  const pool = trackPool(new WebSocketPool({ pingIntervalMs: 0 }));
  const res = await pool.deliver(new URL(srv.url()), Buffer.from("{}"), {}, [TLS_FIXTURE_SPKI_PIN], srv.url());
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.toString(), "secure-ok");
});

test("sender integration: ws: target dispatches to the WebSocket path", async () => {
  const srv = await trackServer(await startTestServer());
  srv.onText((text, reply) => reply(Buffer.concat([Buffer.from("got:"), text])));
  const sender = createDefaultSender();
  try {
    const res = await sender(itemFor(srv.url(), "via-sender"));
    assert.ok(res);
    assert.equal(res.statusCode, 200);
    assert.equal((res.body as Buffer).toString(), "got:via-sender");
    assert.ok(sender.wsPool instanceof WebSocketPool);
  } finally {
    sender.destroy();
  }
});

test("sender integration: wss: target honors pins", async () => {
  const srv = await trackServer(await startTestServer({ tls: true }));
  srv.onText((_text, reply) => reply(Buffer.from("ok")));
  const sender = createDefaultSender({ [srv.url()]: [TLS_FIXTURE_SPKI_PIN] });
  try {
    const res = await sender(itemFor(srv.url(), "x"));
    assert.ok(res && res.statusCode === 200);
  } finally {
    sender.destroy();
  }
});

test("invalid pool options throw RangeError at startup", () => {
  assert.throws(() => new WebSocketPool({ timeoutMs: 0 }), RangeError);
  assert.throws(() => new WebSocketPool({ maxMessageBytes: -1 }), RangeError);
  assert.throws(() => createDefaultSender(undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined, { timeoutMs: -5 }), RangeError);
});

test("frame reader handles split headers and 16-bit lengths", () => {
  const reader = new WsFrameReader();
  const payload = Buffer.alloc(300, 0x62);
  const frame = encodeWsFrame(0x1, payload, false);
  reader.push(frame.subarray(0, 3));
  assert.equal(reader.next(), undefined, "partial header yields nothing");
  reader.push(frame.subarray(3));
  const f = reader.next();
  assert.ok(f);
  assert.equal(f.opcode, 0x1);
  assert.deepEqual(f.payload, payload);
});

test("frame reader unmasks masked frames", () => {
  const reader = new WsFrameReader();
  const frame = encodeWsFrame(0x1, Buffer.from("secret"), true);
  // Server-side frames must not be masked, but the reader tolerates it.
  assert.ok((frame[1] & 0x80) !== 0);
  reader.push(frame);
  const f = reader.next();
  assert.ok(f);
  assert.equal(f.payload.toString(), "secret");
});
