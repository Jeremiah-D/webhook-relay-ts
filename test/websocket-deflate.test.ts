import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server, type Socket } from "node:net";
import { randomBytes } from "node:crypto";
import { WebSocketPool, encodeWsFrame, wsAcceptKey } from "../src/websocket.ts";
import {
  PERMESSAGE_DEFLATE_OFFER,
  compressMessage,
  decompressMessage,
  maybeCompressMessage,
  negotiatePerMessageDeflate,
  resolvePerMessageDeflate,
} from "../src/deflate.ts";

// --- unit: option validation ------------------------------------------------

test("resolvePerMessageDeflate: true/false/undefined/object", () => {
  assert.equal(resolvePerMessageDeflate(undefined), undefined);
  assert.equal(resolvePerMessageDeflate(false), undefined);
  assert.deepEqual(resolvePerMessageDeflate(true), { thresholdBytes: 1024 });
  assert.deepEqual(resolvePerMessageDeflate({}), { thresholdBytes: 1024 });
  assert.deepEqual(resolvePerMessageDeflate({ thresholdBytes: 1 }), { thresholdBytes: 1 });
  for (const bad of [0, -5, 1.5, Number.NaN, "1024", null, []] as unknown[]) {
  assert.throws(
      () => resolvePerMessageDeflate({ thresholdBytes: bad as number }),
      RangeError,
      `threshold ${JSON.stringify(bad)}`
  );
  }
  assert.throws(() => resolvePerMessageDeflate("yes" as unknown as boolean), RangeError);
});

// --- unit: negotiation parsing ----------------------------------------------

test("negotiatePerMessageDeflate: accepts a well-formed answer", () => {
  const good = [
  "permessage-deflate; client_no_context_takeover; server_no_context_takeover",
  "permessage-deflate;server_no_context_takeover;client_no_context_takeover",
  "  Permessage-Deflate ; CLIENT_no_context_takeover ; Server_No_Context_Takeover  ",
  "x-other-ext, permessage-deflate; client_no_context_takeover; server_no_context_takeover",
  'permessage-deflate; client_no_context_takeover; server_no_context_takeover; server_max_window_bits=12',
  'permessage-deflate; client_no_context_takeover; server_no_context_takeover; client_max_window_bits="12"',
  ];
  for (const h of good) {
  const n = negotiatePerMessageDeflate(h);
  assert.ok(n, `must negotiate: ${h}`);
  }
  const wb = negotiatePerMessageDeflate(
  "permessage-deflate; client_no_context_takeover; server_no_context_takeover; client_max_window_bits=12"
  );
  assert.equal(wb?.windowBits, 12);
  // server_max_window_bits is accepted but ignored (safe for inflation).
  const swb = negotiatePerMessageDeflate(
  "permessage-deflate; client_no_context_takeover; server_no_context_takeover; server_max_window_bits=10"
  );
  assert.equal(swb?.windowBits, 15);
});

test("negotiatePerMessageDeflate: absent extension means plain", () => {
  assert.equal(negotiatePerMessageDeflate(undefined), null);
  assert.equal(negotiatePerMessageDeflate(""), null);
  assert.equal(negotiatePerMessageDeflate("x-other-ext; foo=1"), null);
});

test("negotiatePerMessageDeflate: violations throw", () => {
  const bad = [
  "permessage-deflate", // missing both required params
  "permessage-deflate; client_no_context_takeover", // missing server's
  "permessage-deflate; server_no_context_takeover", // missing client's
  "permessage-deflate; client_no_context_takeover; server_no_context_takeover; client_max_window_bits=7",
  "permessage-deflate; client_no_context_takeover; server_no_context_takeover; client_max_window_bits=16",
  "permessage-deflate; client_no_context_takeover; server_no_context_takeover; client_max_window_bits=abc",
  "permessage-deflate; client_no_context_takeover; server_no_context_takeover; mystery_param=1",
  ];
  for (const h of bad) {
  assert.throws(() => negotiatePerMessageDeflate(h), Error, `must reject: ${h}`);
  }
});

// --- unit: wire form ----------------------------------------------------------

test("compress/decompress round-trip (RFC 7692 wire form)", async () => {
  const cases = [
  Buffer.from("hello world ".repeat(200)),
  Buffer.alloc(0),
  randomBytes(3000),
  Buffer.from(JSON.stringify({ event: "payment.succeeded", amount_cents: 1099 }).repeat(50)),
  ];
  for (const c of cases) {
  const wire = await compressMessage(c);
  // RFC 7692 §7.2.1: the trailing empty stored block is stripped.
  assert.ok(
      !wire.subarray(-4).equals(Buffer.from([0, 0, 255, 255])) || wire.length === 0,
      "compressed bytes must not end with the 0000ffff trailer"
  );
  const back = await decompressMessage(wire);
  assert.ok(back.equals(c), "round-trip must be lossless");
  }
});

test("decompressMessage rejects corrupt input", async () => {
  const wire = await compressMessage(Buffer.from("x".repeat(5000)));
  const corrupt = Buffer.from(wire);
  corrupt[10] ^= 0xff;
  await assert.rejects(() => decompressMessage(corrupt), /decompression failed/);
  await assert.rejects(() => decompressMessage(randomBytes(64)), /decompression failed/);
});

test("maybeCompressMessage: threshold and never-expand", async () => {
  const small = Buffer.from("tiny");
  const r1 = await maybeCompressMessage(small, 1024);
  assert.equal(r1.compressed, false);
  assert.ok(r1.bytes.equals(small));

  const big = Buffer.from("a".repeat(5000));
  const r2 = await maybeCompressMessage(big, 1024);
  assert.equal(r2.compressed, true);
  assert.ok(r2.bytes.length < big.length);

  // Incompressible payload above threshold: must not expand the wire.
  const rnd = randomBytes(5000);
  const r3 = await maybeCompressMessage(rnd, 1024);
  assert.equal(r3.compressed, false);
  assert.ok(r3.bytes.equals(rnd));
});

// --- integration: raw-socket stub server --------------------------------------

interface StubOpts {
  /** Answer the deflate offer with both no-context-takeover params. */
  negotiate?: boolean;
  /** Raw Sec-WebSocket-Extensions response value (overrides `negotiate`). */
  extensionsResponse?: string;
  /** Send the reply RSV1-compressed even though nothing was negotiated. */
  rogueRsv1?: boolean;
}

interface StubServer {
  url: () => string;
  /** The client's Sec-WebSocket-Extensions offer, if any. */
  clientOffer: () => string | undefined;
  /** RSV1 bit of the first client frame received. */
  clientRsv1: () => boolean | undefined;
  /** Wire byte length of the first client frame's payload. */
  clientWireBytes: () => number | undefined;
  close: () => Promise<void>;
}

async function startStub(opts: StubOpts = {}): Promise<StubServer> {
  let offer: string | undefined;
  let rsv1: boolean | undefined;
  let wireBytes: number | undefined;
  const server: Server = createServer();
  server.on("connection", (socket: Socket) => {
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
        offer = headers["sec-websocket-extensions"];
        const key = headers["sec-websocket-key"] ?? "";
        let extLine = "";
        const resp =
          opts.extensionsResponse !== undefined
            ? opts.extensionsResponse
            : opts.negotiate
              ? "permessage-deflate; server_no_context_takeover; client_no_context_takeover"
              : "";
        if (resp !== "") extLine = `Sec-WebSocket-Extensions: ${resp}\r\n`;
        socket.write(
          "HTTP/1.1 101 Switching Protocols\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            `Sec-WebSocket-Accept: ${wsAcceptKey(key)}\r\n` +
            extLine +
            "\r\n"
        );
        handshook = true;
        buf = head.subarray(end + 4);
        if (!requestLine.startsWith("GET")) socket.destroy();
        drain();
        return;
      }
      buf = Buffer.concat([buf, chunk]);
      drain();
  };
  const drain = (): void => {
      // Minimal frame parse: single unfragmented client frame.
      if (buf.length < 2) return;
      const first = buf[0];
      const frsv1 = (first & 0x40) !== 0;
      const masked = (buf[1] & 0x80) !== 0;
      let len = buf[1] & 0x7f;
      let off = 2;
      if (len === 126) {
        if (buf.length < 4) return;
        len = buf.readUInt16BE(2);
        off = 4;
      }
      const mlen = masked ? 4 : 0;
      if (buf.length < off + mlen + len) return;
      let payload = buf.subarray(off + mlen, off + mlen + len);
      if (masked) {
        const mask = buf.subarray(off, off + 4);
        const out = Buffer.alloc(len);
        for (let i = 0; i < len; i++) out[i] = payload[i] ^ mask[i % 4];
        payload = out;
      }
      buf = buf.subarray(off + mlen + len);
      if (rsv1 === undefined) {
        rsv1 = frsv1;
        wireBytes = len;
      }
      void (async () => {
        // Echo the (decompressed) payload back.
        let plain = payload;
        if (frsv1 && !opts.rogueRsv1) plain = await decompressMessage(payload);
        const reply = Buffer.concat([Buffer.from("echo:"), plain]);
        if (opts.rogueRsv1) {
          // Protocol violation: RSV1 without negotiation.
          socket.write(encodeWsFrame(0x1, reply, false, true));
        } else if (opts.negotiate || opts.extensionsResponse !== undefined) {
          const wire = await compressMessage(reply);
          socket.write(encodeWsFrame(0x1, wire, false, true));
        } else {
          socket.write(encodeWsFrame(0x1, reply, false));
        }
      })();
  };
  socket.on("data", onData);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  const port = typeof addr === "object" && addr !== null ? addr.port : 0;
  return {
  url: () => `ws://127.0.0.1:${port}/hook`,
  clientOffer: () => offer,
  clientRsv1: () => rsv1,
  clientWireBytes: () => wireBytes,
  close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

const pools: WebSocketPool[] = [];
const servers: StubServer[] = [];
afterEach(async () => {
  // Pools first: server.close() waits for open keep-alive connections.
  for (const p of pools.splice(0)) p.destroy();
  for (const s of servers.splice(0)) await s.close();
});
function trackPool(p: WebSocketPool): WebSocketPool {
  pools.push(p);
  return p;
}
async function trackServer(s: StubServer): Promise<StubServer> {
  servers.push(s);
  return s;
}

test("pool offers permessage-deflate and compresses large payloads", async () => {
  const srv = await trackServer(await startStub({ negotiate: true }));
  const pool = trackPool(new WebSocketPool({ pingIntervalMs: 0, permessageDeflate: true }));
  const body = Buffer.from("event-payload ".repeat(500)); // 7000 bytes, compressible
  const res = await pool.deliver(new URL(srv.url()), body, {}, undefined, srv.url());
  assert.equal(res.statusCode, 200);
  assert.ok(res.body.equals(Buffer.concat([Buffer.from("echo:"), body])), "reply must round-trip");
  // The client offered the extension…
  assert.ok(
    srv.clientOffer()?.includes("permessage-deflate"),
    `client offer: ${srv.clientOffer()}`
  );
  assert.ok(srv.clientOffer()?.includes("client_no_context_takeover"));
  assert.ok(srv.clientOffer()?.includes("server_no_context_takeover"));
  // …and sent the payload RSV1-compressed, smaller than the original.
  assert.equal(srv.clientRsv1(), true);
  assert.ok((srv.clientWireBytes() ?? Infinity) < body.length, "wire must shrink");
  const stats = pool.getStats();
  assert.equal(stats.deflatedOut, 1);
  assert.equal(stats.deflatedIn, 1);
});

test("small payloads go out uncompressed (RSV1 clear)", async () => {
  const srv = await trackServer(await startStub({ negotiate: true }));
  const pool = trackPool(new WebSocketPool({ pingIntervalMs: 0, permessageDeflate: true }));
  const body = Buffer.from("small");
  const res = await pool.deliver(new URL(srv.url()), body, {}, undefined, srv.url());
  assert.ok(res.body.equals(Buffer.concat([Buffer.from("echo:"), body])));
  assert.equal(srv.clientRsv1(), false);
  assert.equal(pool.getStats().deflatedOut, 0);
});

test("incompressible large payloads go out uncompressed (never expand)", async () => {
  const srv = await trackServer(await startStub({ negotiate: true }));
  const pool = trackPool(new WebSocketPool({ pingIntervalMs: 0, permessageDeflate: true }));
  const body = randomBytes(5000);
  const res = await pool.deliver(new URL(srv.url()), body, {}, undefined, srv.url());
  assert.ok(res.body.equals(Buffer.concat([Buffer.from("echo:"), body])));
  assert.equal(srv.clientRsv1(), false);
  assert.equal(srv.clientWireBytes(), body.length);
});

test("no extension offer when the option is off; plain interop", async () => {
  const srv = await trackServer(await startStub({ negotiate: false }));
  const pool = trackPool(new WebSocketPool({ pingIntervalMs: 0 }));
  const body = Buffer.from("event-payload ".repeat(500));
  const res = await pool.deliver(new URL(srv.url()), body, {}, undefined, srv.url());
  assert.ok(res.body.equals(Buffer.concat([Buffer.from("echo:"), body])));
  assert.equal(srv.clientOffer(), undefined);
  assert.equal(srv.clientRsv1(), false);
});

test("server ignoring the offer: connection works uncompressed", async () => {
  const srv = await trackServer(await startStub({ negotiate: false }));
  const pool = trackPool(new WebSocketPool({ pingIntervalMs: 0, permessageDeflate: true }));
  const body = Buffer.from("event-payload ".repeat(500));
  const res = await pool.deliver(new URL(srv.url()), body, {}, undefined, srv.url());
  assert.ok(res.body.equals(Buffer.concat([Buffer.from("echo:"), body])));
  // Offered, but the server stayed silent: plain text both ways.
  assert.ok(srv.clientOffer()?.includes("permessage-deflate"));
  assert.equal(srv.clientRsv1(), false);
  assert.equal(pool.getStats().deflatedOut, 0);
  assert.equal(pool.getStats().deflatedIn, 0);
});

test("violating extension answer fails the handshake", async () => {
  const srv = await trackServer(
  await startStub({
      extensionsResponse: "permessage-deflate; client_no_context_takeover",
  })
  );
  const pool = trackPool(new WebSocketPool({ pingIntervalMs: 0, permessageDeflate: true }));
  await assert.rejects(
      pool.deliver(new URL(srv.url()), Buffer.from("x".repeat(2000)), {}, undefined, srv.url()),
      /no_context_takeover/
  );
});

test("rogue RSV1 frame without negotiation fails the delivery", async () => {
  const srv = await trackServer(await startStub({ rogueRsv1: true }));
  const pool = trackPool(new WebSocketPool({ pingIntervalMs: 0 }));
  await assert.rejects(
      pool.deliver(new URL(srv.url()), Buffer.from("ping"), {}, undefined, srv.url()),
      /without negotiated deflate/
  );
});

test("custom threshold is honored", async () => {
  const srv = await trackServer(await startStub({ negotiate: true }));
  const pool = trackPool(
      new WebSocketPool({ pingIntervalMs: 0, permessageDeflate: { thresholdBytes: 10000 } })
  );
  const body = Buffer.from("event-payload ".repeat(500)); // 7000 < 10000
  const res = await pool.deliver(new URL(srv.url()), body, {}, undefined, srv.url());
  assert.ok(res.body.equals(Buffer.concat([Buffer.from("echo:"), body])));
  assert.equal(srv.clientRsv1(), false);
});

test("pooled connection reuses the negotiated deflate", async () => {
  const srv = await trackServer(await startStub({ negotiate: true }));
  const pool = trackPool(new WebSocketPool({ pingIntervalMs: 0, permessageDeflate: true }));
  const body = Buffer.from("event-payload ".repeat(500));
  for (let i = 0; i < 3; i++) {
      const res = await pool.deliver(new URL(srv.url()), body, {}, undefined, srv.url());
      assert.ok(res.body.equals(Buffer.concat([Buffer.from("echo:"), body])));
  }
  const stats = pool.getStats();
  assert.equal(stats.created, 1);
  assert.equal(stats.reused, 2);
  assert.equal(stats.deflatedOut, 3);
  assert.equal(stats.deflatedIn, 3);
});
