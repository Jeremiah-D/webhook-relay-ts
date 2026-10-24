import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server, type Socket } from "node:net";
import { WebSocketPool, encodeWsFrame } from "../src/websocket.ts";
import { inboundWsAcceptKey } from "../src/inbound-ws.ts";
import { HttpDeliveryError } from "../src/failure.ts";
import { compressMessage, decompressMessage } from "../src/deflate.ts";

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

interface MuxEnvelopeMsg {
  v: number;
  cid: string;
  body: string;
  headers?: Record<string, string>;
}

/** One received envelope plus the callbacks to answer it. */
interface InboundDelivery {
  env: MuxEnvelopeMsg;
  raw: Buffer;
  /** Send a correlated envelope reply. */
  reply: (body: Buffer) => void;
  /** Send a correlated RSV1-compressed envelope reply (needs negotiated deflate). */
  replyCompressed: (body: Buffer) => Promise<void>;
  /** Send an arbitrary text frame (for protocol-violation tests). */
  replyRaw: (data: Buffer) => void;
  /** Abruptly destroy the underlying TCP connection. */
  destroy: () => void;
  /** Send a ping control frame. */
  ping: () => void;
}

interface MuxTestServer {
  url: (path?: string) => string;
  connections: () => number;
  /** Envelopes received, in arrival order. */
  received: () => InboundDelivery[];
  /** The client's Sec-WebSocket-Extensions offer, if any. */
  clientOffer: () => string | undefined;
  /** RSV1 bit of the first client text frame received, if any. */
  clientFirstRsv1: () => boolean | undefined;
  /** Wire payload bytes of the first client text frame, if any. */
  clientFirstWireBytes: () => number | undefined;
  close: () => Promise<void>;
}

/** Raw-socket WebSocket server that speaks the WR-204 envelope contract. */
async function startMuxServer(
  opts: { respond404?: boolean; negotiateDeflate?: boolean } = {}
): Promise<MuxTestServer> {
  let connectionCount = 0;
  const received: InboundDelivery[] = [];
  let offer: string | undefined;
  let firstRsv1: boolean | undefined;
  let firstWireBytes: number | undefined;
  const server: Server = createServer();

  server.on("connection", (socket: Socket) => void handleSocket(socket));

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
        void requestLine;
        const headers: Record<string, string> = {};
        for (const line of lines) {
          const i = line.indexOf(":");
          if (i > 0) headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
        }
        const key = headers["sec-websocket-key"] ?? "";
        if (opts.respond404) {
          socket.write("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
          socket.end();
          return;
        }
        offer = headers["sec-websocket-extensions"];
        const extLine = opts.negotiateDeflate
          ? "Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n"
          : "";
        socket.write(
          "HTTP/1.1 101 Switching Protocols\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            `Sec-WebSocket-Accept: ${inboundWsAcceptKey(key)}\r\n` +
            extLine +
            "\r\n"
        );
        handshook = true;
        buf = head.subarray(end + 4);
        drain();
        return;
      }
      buf = Buffer.concat([buf, chunk]);
      drain();
    };
    function drain(): void {
      // Carve complete frames out of `buf` synchronously (no awaits),
      // then process them — a later `onData` can never re-read a frame
      // an in-flight async inflate is still working on.
      const frames: { frame: ServerFrame; rsv1: boolean }[] = [];
      let off = 0;
      for (;;) {
        const frameStart = off;
        const r = readFrame(buf, off);
        if (r === undefined) break;
        frames.push({ frame: r.frame, rsv1: (buf[frameStart] & 0x40) !== 0 });
        off = r.next;
      }
      buf = buf.subarray(off);
      void processFrames(frames);
    }
    async function processFrames(frames: { frame: ServerFrame; rsv1: boolean }[]): Promise<void> {
      for (const { frame, rsv1 } of frames) {
        if (frame.opcode === 0x1) {
          const raw = frame.payload;
          if (firstRsv1 === undefined) {
            firstRsv1 = rsv1;
            firstWireBytes = raw.length;
          }
          // The client may send RSV1-compressed envelopes (WR-46):
          // inflate before parsing so the test sees the real envelope.
          let text = raw;
          if (rsv1) {
            try {
              text = await decompressMessage(raw);
            } catch {
              text = raw; // parse fails below; surfaces as a bad envelope
            }
          }
          let env: MuxEnvelopeMsg;
          try {
            env = JSON.parse(text.toString("utf8")) as MuxEnvelopeMsg;
          } catch {
            env = { v: -1, cid: "", body: "" };
          }
          const inbound: InboundDelivery = {
            env,
            raw,
            reply: (body: Buffer) => {
              socket.write(
                serverFrame(
                  0x1,
                  Buffer.from(
                    JSON.stringify({ v: 1, cid: env.cid, body: body.toString("base64") }),
                    "utf8"
                  )
                )
              );
            },
            replyCompressed: async (body: Buffer) => {
              const plain = Buffer.from(
                JSON.stringify({ v: 1, cid: env.cid, body: body.toString("base64") }),
                "utf8"
              );
              const wire = await compressMessage(plain);
              socket.write(encodeWsFrame(0x1, wire, false, true));
            },
            replyRaw: (data: Buffer) => {
              socket.write(serverFrame(0x1, data));
            },
            destroy: () => socket.destroy(),
            ping: () => socket.write(serverFrame(0x9, Buffer.from("ka"))),
          };
          received.push(inbound);
        } else if (frame.opcode === 0x9) {
          socket.write(serverFrame(0xa, frame.payload));
        } else if (frame.opcode === 0x8) {
          socket.write(serverFrame(0x8, Buffer.alloc(0)));
          socket.end();
        }
      }
    }
    socket.on("data", onData);
  }

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  if (addr === null || typeof addr === "string") throw new Error("no address");
  return {
    url: (path = "/hook") => `ws://127.0.0.1:${addr.port}${path}`,
    connections: () => connectionCount,
    received: () => received,
    clientOffer: () => offer,
    clientFirstRsv1: () => firstRsv1,
    clientFirstWireBytes: () => firstWireBytes,
    close: () => new Promise<void>((resolve, reject) => server.close((e) => (e ? reject(e) : resolve()))),
  };
}

const pools: WebSocketPool[] = [];
const servers: MuxTestServer[] = [];
afterEach(async () => {
  for (const p of pools.splice(0)) p.destroy();
  for (const s of servers.splice(0)) await s.close();
});

function trackPool(p: WebSocketPool): WebSocketPool {
  pools.push(p);
  return p;
}

async function trackServer(s: MuxTestServer): Promise<MuxTestServer> {
  servers.push(s);
  return s;
}

async function waitFor(cond: () => boolean, what: string, ms = 5000): Promise<void> {
  const start = Date.now();
  for (;;) {
    if (cond()) return;
    if (Date.now() - start > ms) throw new Error(`timed out waiting for: ${what}`);
    await new Promise((r) => setTimeout(r, 10));
  }
}

function deliver(
  pool: WebSocketPool,
  server: MuxTestServer,
  payload: string,
  headers: Record<string, string> = {}
): Promise<{ statusCode: number; body: Buffer; truncated: boolean }> {
  return pool.deliver(new URL(server.url()), Buffer.from(payload), headers, undefined, server.url());
}

function decodedBody(inbound: InboundDelivery): string {
  return Buffer.from(inbound.env.body, "base64").toString("utf8");
}

// --- tests ------------------------------------------------------------------

test("multiplexes concurrent deliveries on one connection; out-of-order replies route by cid", async () => {
  const server = await trackServer(await startMuxServer());
  const pool = trackPool(new WebSocketPool({ multiplex: true, pingIntervalMs: 0 }));
  const p1 = deliver(pool, server, "one");
  const p2 = deliver(pool, server, "two");
  const p3 = deliver(pool, server, "three");
  await waitFor(() => server.received().length === 3, "3 envelopes");
  assert.equal(server.connections(), 1, "exactly one connection for all deliveries");

  const cids = server.received().map((d) => d.env.cid);
  assert.equal(new Set(cids).size, 3, "distinct correlation ids");
  for (const d of server.received()) {
    assert.match(d.env.cid, /^[0-9a-f]{32}$/);
    assert.equal(d.env.v, 1);
  }
  assert.deepEqual(
    server.received().map(decodedBody).sort(),
    ["one", "three", "two"],
    "payloads arrive base64-encoded in the envelope"
  );

  // Reply out of order: last arrival first. Each reply must land on the
  // delivery whose cid it carries.
  const [first, second, third] = server.received();
  third.reply(Buffer.from("r-three"));
  second.reply(Buffer.from("r-two"));
  first.reply(Buffer.from("r-one"));
  const [r1, r2, r3] = await Promise.all([p1, p2, p3]);
  assert.equal(r1.body.toString(), "r-one");
  assert.equal(r2.body.toString(), "r-two");
  assert.equal(r3.body.toString(), "r-three");
  assert.equal(r1.statusCode, 200);

  const stats = pool.getStats();
  assert.equal(stats.muxOut, 3);
  assert.equal(stats.muxIn, 3);
  assert.equal(stats.muxInFlight, 0);
});

test("queues deliveries past maxInFlight on the same connection (no second connection)", async () => {
  const server = await trackServer(await startMuxServer());
  const pool = trackPool(new WebSocketPool({ multiplex: { maxInFlight: 1 }, pingIntervalMs: 0 }));
  const p1 = deliver(pool, server, "first");
  const p2 = deliver(pool, server, "second");
  await waitFor(() => server.received().length === 1, "first envelope");
  // Second delivery must be parked: no second connection, no second frame.
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(server.connections(), 1, "pool never opens a second connection");
  assert.equal(server.received().length, 1, "second delivery waits for a slot");
  assert.equal(pool.getStats().muxQueued, 1);

  server.received()[0].reply(Buffer.from("ok-1"));
  await waitFor(() => server.received().length === 2, "second envelope after slot frees");
  assert.equal(decodedBody(server.received()[1]), "second");
  server.received()[1].reply(Buffer.from("ok-2"));
  const [r1, r2] = await Promise.all([p1, p2]);
  assert.equal(r1.body.toString(), "ok-1");
  assert.equal(r2.body.toString(), "ok-2");
  assert.equal(server.connections(), 1);
});

test("fails in-flight deliveries retryable when the connection drops", async () => {
  const server = await trackServer(await startMuxServer());
  const pool = trackPool(new WebSocketPool({ multiplex: true, pingIntervalMs: 0 }));
  const p1 = deliver(pool, server, "a");
  const p2 = deliver(pool, server, "b");
  await waitFor(() => server.received().length === 2, "2 envelopes");
  server.received()[0].destroy();
  const errs = await Promise.all([p1.then(() => null, (e) => e), p2.then(() => null, (e) => e)]);
  for (const err of errs) {
    assert.ok(err instanceof Error, "delivery rejects");
    assert.ok(!(err instanceof HttpDeliveryError), "plain Error = retryable, not an HTTP classification");
    assert.match((err as Error).message, /multiplexed connection closed/);
  }
  // The dead connection is gone from the pool: the next delivery opens a
  // fresh one and succeeds (at-least-once continues on the retry path).
  const p3 = deliver(pool, server, "c");
  await waitFor(() => server.received().length === 3, "third envelope");
  assert.equal(server.connections(), 2);
  server.received()[2].reply(Buffer.from("ok"));
  const r = await p3;
  assert.equal(r.statusCode, 200);
});

test("unknown correlation id is a protocol violation: connection dies, next delivery recovers", async () => {
  const server = await trackServer(await startMuxServer());
  const pool = trackPool(new WebSocketPool({ multiplex: true, pingIntervalMs: 0 }));
  const p1 = deliver(pool, server, "x");
  await waitFor(() => server.received().length === 1, "envelope");
  server.received()[0].replyRaw(
    Buffer.from(JSON.stringify({ v: 1, cid: "0".repeat(32), body: Buffer.from("bogus").toString("base64") }), "utf8")
  );
  await assert.rejects(p1, /protocol violation/, "pending delivery fails on the violation");
  // The violating connection is removed from the pool (protocol-violation
  // deaths are not counted in `destroyed`, same as the exclusive path —
  // that counter tracks reaped/destroyed connections).
  assert.equal(pool.getStats().idle, 0);
  assert.equal(pool.getStats().busy, 0);
  const p2 = deliver(pool, server, "y");
  await waitFor(() => server.received().length === 2, "second envelope");
  assert.equal(server.connections(), 2, "recovery opens a fresh connection");
  server.received()[1].reply(Buffer.from("ok"));
  const r = await p2;
  assert.equal(r.statusCode, 200);
});

test("handshake failures still surface as HttpDeliveryError in mux mode", async () => {
  const server = await trackServer(await startMuxServer({ respond404: true }));
  const pool = trackPool(new WebSocketPool({ multiplex: true, pingIntervalMs: 0 }));
  await assert.rejects(deliver(pool, server, "x"), (err: unknown) => {
    assert.ok(err instanceof HttpDeliveryError);
    assert.equal((err as HttpDeliveryError).statusCode, 404);
    return true;
  });
});

test("rejects invalid multiplex options at startup", async () => {
  assert.throws(() => new WebSocketPool({ multiplex: { maxInFlight: 0 } }), RangeError);
  assert.throws(() => new WebSocketPool({ multiplex: { maxInFlight: -2 } }), RangeError);
  assert.throws(() => new WebSocketPool({ multiplex: { maxInFlight: 1.5 } }), RangeError);
  assert.throws(
    () => new WebSocketPool({ multiplex: "yes" as unknown as boolean }),
    RangeError
  );
  // Valid forms do not throw.
  trackPool(new WebSocketPool({ multiplex: true, pingIntervalMs: 0 }));
  trackPool(new WebSocketPool({ multiplex: { maxInFlight: 4 }, pingIntervalMs: 0 }));
  trackPool(new WebSocketPool({ pingIntervalMs: 0 }));
});

test("carries each delivery's own x-relay-* headers in its envelope", async () => {
  const server = await trackServer(await startMuxServer());
  const pool = trackPool(new WebSocketPool({ multiplex: true, pingIntervalMs: 0 }));
  const p1 = deliver(pool, server, "a", { "x-relay-idempotency-key": "key-one", "x-trace-id": "t1" });
  const p2 = deliver(pool, server, "b", { "x-relay-idempotency-key": "key-two", "x-trace-id": "t2" });
  await waitFor(() => server.received().length === 2, "2 envelopes");
  assert.equal(server.connections(), 1);
  const byBody = new Map(server.received().map((d) => [decodedBody(d), d.env.headers]));
  assert.equal(byBody.get("a")?.["x-relay-idempotency-key"], "key-one");
  assert.equal(byBody.get("b")?.["x-relay-idempotency-key"], "key-two");
  // Envelope shape: cid first, then v/body/headers.
  const raw = server.received()[0].raw.toString("utf8");
  assert.ok(raw.startsWith('{"cid":"'), `cid first in envelope, got: ${raw.slice(0, 20)}`);
  for (const d of server.received()) d.reply(Buffer.from("ok"));
  await Promise.all([p1, p2]);
});

test("truncates oversized replies at maxMessageBytes; wire-cap breach is a protocol violation", async () => {
  const server = await trackServer(await startMuxServer());
  const pool = trackPool(
    new WebSocketPool({ multiplex: true, pingIntervalMs: 0, maxMessageBytes: 64 })
  );
  // 100-byte reply: over maxMessageBytes (64) but under the 4x wire cap.
  const p1 = deliver(pool, server, "small");
  await waitFor(() => server.received().length === 1, "envelope");
  server.received()[0].reply(Buffer.alloc(100, 0x61));
  const r1 = await p1;
  assert.equal(r1.truncated, true);
  assert.equal(r1.body.length, 64);

  // 300-byte reply: over the 4x wire cap (256) -> protocol violation.
  const p2 = deliver(pool, server, "big");
  await waitFor(() => server.received().length === 2, "second envelope");
  server.received()[1].reply(Buffer.alloc(300, 0x62));
  await assert.rejects(p2, /protocol violation/);
});

test("interleaves ping/pong keep-alive with in-flight deliveries", async () => {
  const server = await trackServer(await startMuxServer());
  const pool = trackPool(new WebSocketPool({ multiplex: true, pingIntervalMs: 0 }));
  const p1 = deliver(pool, server, "pinged");
  await waitFor(() => server.received().length === 1, "envelope");
  // Server-initiated ping while the delivery is in flight: the client
  // must pong it without disturbing the pending delivery.
  server.received()[0].ping();
  await new Promise((r) => setTimeout(r, 50));
  server.received()[0].reply(Buffer.from("still-here"));
  const r = await p1;
  assert.equal(r.body.toString(), "still-here");
});

test("composes with WR-46 permessage-deflate: compressed envelopes both ways", async () => {
  const server = await trackServer(await startMuxServer({ negotiateDeflate: true }));
  const pool = trackPool(
    new WebSocketPool({ multiplex: true, permessageDeflate: true, pingIntervalMs: 0 })
  );
  const big = "a".repeat(4096);
  const p = deliver(pool, server, big);
  await waitFor(() => server.received().length === 1, "envelope");
  assert.match(server.clientOffer() ?? "", /permessage-deflate/);
  assert.equal(server.clientFirstRsv1(), true, "compressible envelope goes out RSV1");
  const inbound = server.received()[0];
  // Plain envelope for 4096 'a's is ~5.5KB (base64); the wire must be a
  // small fraction of that. RSV1=true already proves maybeCompressMessage
  // chose to compress (it never sets RSV1 otherwise).
  assert.ok(
    (server.clientFirstWireBytes() ?? Infinity) < 1000,
    `wire ${server.clientFirstWireBytes()} << plain envelope`
  );
  assert.equal(decodedBody(inbound), big, "server inflated the real envelope");
  // Server answers RSV1-compressed; the client must inflate and route by cid.
  await inbound.replyCompressed(Buffer.from("deflated-reply"));
  const r = await p;
  assert.equal(r.body.toString(), "deflated-reply");
  assert.equal(pool.getStats().deflatedOut, 1);
  assert.equal(pool.getStats().deflatedIn, 1);

  // Small payloads stay plain text even with deflate negotiated (opportunistic).
  const p2 = deliver(pool, server, "tiny");
  await waitFor(() => server.received().length === 2, "second envelope");
  server.received()[1].reply(Buffer.from("ok"));
  const r2 = await p2;
  assert.equal(r2.body.toString(), "ok");
});

test("exposes mux counters in getStats and the Prometheus block", async () => {
  const server = await trackServer(await startMuxServer());
  const pool = trackPool(new WebSocketPool({ multiplex: true, pingIntervalMs: 0 }));
  const p = deliver(pool, server, "metrics");
  await waitFor(() => server.received().length === 1, "envelope");
  assert.equal(pool.getStats().muxInFlight, 1);
  server.received()[0].reply(Buffer.from("ok"));
  await p;
  const stats = pool.getStats();
  assert.equal(stats.muxOut, 1);
  assert.equal(stats.muxIn, 1);
  assert.equal(stats.muxQueued, 0);
  assert.equal(stats.muxInFlight, 0);
  const exposition = pool.renderMetrics();
  assert.match(exposition, /relay_websocket_multiplexed_total\{origin="ws:\/\/127\.0\.0\.1:\d+",direction="out"\} 1/);
  assert.match(exposition, /relay_websocket_multiplexed_total\{[^}]*direction="in"\} 1/);

  // A pool that never multiplexed keeps byte-identical exposition.
  const plain = trackPool(new WebSocketPool({ pingIntervalMs: 0 }));
  const pp = deliver(plain, server, "plain");
  await waitFor(() => server.received().length === 2, "plain envelope");
  // The exclusive path gets a raw-text reply; the envelope JSON is just
  // its response body — the point here is only the exposition shape.
  server.received()[1].reply(Buffer.from("ok"));
  await pp;
  assert.doesNotMatch(plain.renderMetrics(), /multiplexed/);
});
