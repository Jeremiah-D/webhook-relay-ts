import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server, type Socket } from "node:net";
import { WebSocketPool, encodeWsFrame, wsAcceptKey } from "../src/websocket.ts";

// --- minimal RFC 6455 stub: handshake, echo text frames, auto-pong ------

interface StubServer {
  url: (path?: string) => string;
  close: () => Promise<void>;
}

async function startStub(): Promise<StubServer> {
  const server: Server = createServer();
  server.on("connection", (socket: Socket) => {
    let head = Buffer.alloc(0);
    let handshook = false;
    let buf = Buffer.alloc(0);
    const drain = (): void => {
      for (;;) {
        if (buf.length < 2) return;
        const opcode = buf[0] & 0x0f;
        const len = buf[1] & 0x7f;
        let hlen = 2;
        let plen = len;
        if (len === 126) {
          if (buf.length < 4) return;
          plen = buf.readUInt16BE(2);
          hlen = 4;
        }
        const mlen = buf[1] & 0x80 ? 4 : 0;
        if (buf.length < hlen + mlen + plen) return;
        let payload = buf.subarray(hlen + mlen, hlen + mlen + plen);
        if (mlen === 4) {
          const mask = buf.subarray(hlen, hlen + 4);
          const out = Buffer.alloc(plen);
          for (let i = 0; i < plen; i++) out[i] = payload[i] ^ mask[i % 4];
          payload = out;
        }
        buf = buf.subarray(hlen + mlen + plen);
        if (opcode === 0x1) socket.write(encodeWsFrame(0x1, payload, false));
        else if (opcode === 0x9) socket.write(encodeWsFrame(0xa, payload, false));
        else if (opcode === 0x8) socket.end();
      }
    };
    socket.on("data", (chunk: Buffer) => {
      if (!handshook) {
        head = Buffer.concat([head, chunk]);
        const end = head.indexOf("\r\n\r\n");
        if (end < 0) return;
        const key = head
          .subarray(0, end)
          .toString("latin1")
          .split("\r\n")
          .find((l) => l.toLowerCase().startsWith("sec-websocket-key:"))
          ?.split(":")[1]
          .trim();
        socket.write(
          "HTTP/1.1 101 Switching Protocols\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            `Sec-WebSocket-Accept: ${wsAcceptKey(key ?? "")}\r\n\r\n`
        );
        handshook = true;
        buf = head.subarray(end + 4);
        drain();
        return;
      }
      buf = Buffer.concat([buf, chunk]);
      drain();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  if (addr === null || typeof addr === "string") throw new Error("no address");
  return {
    url: (path = "/hook") => `ws://127.0.0.1:${addr.port}${path}`,
    close: () => new Promise<void>((resolve, reject) => server.close((e) => (e ? reject(e) : resolve()))),
  };
}

const pools: WebSocketPool[] = [];
const servers: StubServer[] = [];
afterEach(async () => {
  for (const p of pools.splice(0)) p.destroy();
  for (const s of servers.splice(0)) await s.close();
});

async function deliverTwice(pool: WebSocketPool, srv: StubServer): Promise<string> {
  const urlA = new URL(srv.url("/a"));
  const urlB = new URL(srv.url("/b"));
  const r1 = await pool.deliver(urlA, Buffer.from("one"), {}, undefined, srv.url("/a"));
  const r2 = await pool.deliver(urlB, Buffer.from("two"), {}, undefined, srv.url("/b"));
  assert.equal(r1.statusCode, 200);
  assert.equal(r2.statusCode, 200);
  return `${urlA.protocol}//${urlA.host}`;
}

test("per-origin stats: messages, checkout results, active connections (WR-105)", async () => {
  const srv = servers[servers.push(await startStub()) - 1];
  const pool = pools[pools.push(new WebSocketPool({ pingIntervalMs: 0 })) - 1];
  const origin = await deliverTwice(pool, srv);
  // Two paths on the same scheme://host:port share one origin row, and the
  // second delivery reuses the pooled connection.
  const rows = pool.getOriginStats();
  assert.equal(rows.length, 1);
  const row = rows[0];
  assert.deepEqual(row, {
    origin,
    activeConnections: 1,
    messagesOut: 2,
    messagesIn: 2,
    created: 1,
    reused: 1,
    deflatedOut: 0,
    deflatedIn: 0,
  });
  // getStats() carries the same per-origin breakdown.
  assert.deepEqual(pool.getStats().origins, rows);
  // Prometheus block: base series present, RTT/ratio absent (no probe, no deflate).
  const exposition = pool.renderMetrics();
  assert.ok(
    exposition.includes(`relay_websocket_messages_out_total{origin="${origin}"} 2`),
    exposition
  );
  assert.ok(
    exposition.includes(
      `relay_websocket_checkouts_total{origin="${origin}",result="reused"} 1`
    ),
    exposition
  );
  assert.ok(!exposition.includes("relay_websocket_ping_rtt_seconds"));
  assert.ok(!exposition.includes("relay_websocket_deflate_ratio"));
});

test("untouched pool renders an empty metrics block", () => {
  const pool = pools[pools.push(new WebSocketPool({ pingIntervalMs: 0 })) - 1];
  assert.deepEqual(pool.getOriginStats(), []);
  assert.equal(pool.renderMetrics(), "");
});

test("destroyed pool reports zero active connections, keeps cumulative counters", async () => {
  const srv = servers[servers.push(await startStub()) - 1];
  const pool = pools[pools.push(new WebSocketPool({ pingIntervalMs: 0 })) - 1];
  const origin = await deliverTwice(pool, srv);
  pool.destroy();
  const rows = pool.getOriginStats();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].origin, origin);
  assert.equal(rows[0].activeConnections, 0);
  assert.equal(rows[0].messagesOut, 2);
});

test("keep-alive probes feed the ping RTT gauge (WR-105)", async () => {
  const srv = servers[servers.push(await startStub()) - 1];
  const pool = pools[pools.push(new WebSocketPool({ pingIntervalMs: 30 })) - 1];
  const origin = await deliverTwice(pool, srv);
  // Let a few probe cycles run against the idle connection.
  await new Promise((r) => setTimeout(r, 250));
  const row = pool.getOriginStats().find((x) => x.origin === origin)!;
  assert.ok(row.pingRttMs !== undefined, "expected a ping RTT sample");
  assert.ok(row.pingRttMs > 0 && row.pingRttMs < 5000, `rtt=${row.pingRttMs}`);
  const exposition = pool.renderMetrics();
  assert.ok(
    exposition.includes(`relay_websocket_ping_rtt_seconds{origin="${origin}"}`),
    exposition
  );
});

test("destroy during an in-flight handshake kills the fresh connection (no orphan socket)", async () => {
  // Stub that accepts TCP but only completes the WebSocket handshake on
  // demand, so the test can destroy the pool mid-handshake.
  let releaseHandshake: () => void = () => {};
  let conns = 0;
  let closedConns = 0;
  const server: Server = createServer();
  server.on("connection", (socket: Socket) => {
    conns++;
    let head = Buffer.alloc(0);
    let handshook = false;
    socket.on("close", () => {
      closedConns++;
    });
    socket.on("data", (chunk: Buffer) => {
      if (handshook) return;
      head = Buffer.concat([head, chunk]);
      const end = head.indexOf("\r\n\r\n");
      if (end < 0) return;
      handshook = true;
      const key = head
        .subarray(0, end)
        .toString("latin1")
        .split("\r\n")
        .find((l) => l.toLowerCase().startsWith("sec-websocket-key:"))
        ?.split(":")[1]
        .trim();
      const reply = (): void => {
        socket.write(
          "HTTP/1.1 101 Switching Protocols\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            `Sec-WebSocket-Accept: ${wsAcceptKey(key ?? "")}\r\n\r\n`
        );
      };
      releaseHandshake = reply;
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  if (addr === null || typeof addr === "string") throw new Error("no address");
  const target = `ws://127.0.0.1:${addr.port}/hook`;
  servers.push({
    url: () => target,
    close: () =>
      new Promise<void>((resolve, reject) => server.close((e) => (e ? reject(e) : resolve()))),
  });

  const pool = pools[pools.push(new WebSocketPool({ pingIntervalMs: 0 })) - 1];
  const pending = pool.deliver(new URL(target), Buffer.from("x"), {}, undefined, target);
  // Wait for the TCP connection to land, handshake still withheld.
  const deadline = Date.now() + 5000;
  while (conns === 0 && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 10));
  }
  assert.equal(conns, 1);
  pool.destroy();
  // Now let the handshake complete: the pool is gone, so the fresh
  // connection must be killed instead of leaking into the pool.
  releaseHandshake();
  await assert.rejects(pending, /pool destroyed/);
  const deadline2 = Date.now() + 5000;
  while (closedConns === 0 && Date.now() < deadline2) {
    await new Promise((r) => setTimeout(r, 10));
  }
  assert.equal(closedConns, 1, "the orphan socket must be destroyed");
  assert.equal(pool.getOriginStats()[0]?.activeConnections ?? 0, 0);
});
