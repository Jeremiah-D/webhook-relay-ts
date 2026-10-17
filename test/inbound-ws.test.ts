import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { connect, type Socket } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Server } from "node:http";
import { createRelayServer } from "../src/server.ts";
import { signSha256, signEd25519, Ed25519Verifier } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import { HttpDeliveryError } from "../src/failure.ts";
import { createRequiredFieldsSchema } from "../src/schema.ts";
import { generateInboundMtlsFixture } from "./inbound-mtls-fixture.ts";
import type { RetryItem } from "../src/retry.ts";

// Never name a constant SECRET here: the runtime secret redaction rewrites
// `secret: SECRET` occurrences and breaks the TS syntax (see AGENTS.md).
const TEST_KEY = "ws-intake-test-key";
// RFC 6455 §1.3 example vector — the server must reproduce it exactly.
const RFC_WS_KEY = "dGhlIHNhbXBsZSBub25jZQ==";
const RFC_WS_ACCEPT = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";

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
  payload: Buffer;
}

function encodeClientFrame(opcode: number, payload: Buffer, fin = true): Buffer {
  const len = payload.length;
  let header: Buffer;
  const b0 = (fin ? 0x80 : 0) | opcode;
  if (len < 126) {
    header = Buffer.from([b0, 0x80 | len]);
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = b0;
    header[1] = 0x80 | 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = b0;
    header[1] = 0x80 | 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  const mask = randomBytes(4);
  const masked = Buffer.alloc(len);
  for (let i = 0; i < len; i++) masked[i] = payload[i] ^ mask[i % 4];
  return Buffer.concat([header, mask, masked]);
}

interface WsClient {
  socket: Socket;
  nextFrame: () => Promise<ServerFrame>;
  nextText: () => Promise<any>;
  sendText: (text: string) => void;
  sendPing: (data?: Buffer) => void;
  sendClose: (code?: number) => void;
  sendBinary: (data: Buffer) => void;
  pause: () => void;
  resume: () => void;
  closed: Promise<void>;
  destroy: () => void;
}

/** Raw upgrade: returns the status line, headers, and the live socket. */
function rawUpgrade(
  port: number,
  requestText: string,
  mkSocket: () => Socket = () => connect(port, "127.0.0.1")
): Promise<{ status: number; headers: Record<string, string>; socket: Socket }> {
  return new Promise((resolve, reject) => {
    const socket = mkSocket();
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
    // The peer may close without any response (unknown path): surface that
    // as status 0 instead of hanging.
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

function handshakeRequest(path: string, extraHeaders: Record<string, string> = {}): string {
  const lines = [
    `GET ${path} HTTP/1.1`,
    "Host: 127.0.0.1",
    "Upgrade: websocket",
    "Connection: Upgrade",
    `Sec-WebSocket-Key: ${RFC_WS_KEY}`,
    "Sec-WebSocket-Version: 13",
  ];
  for (const [k, v] of Object.entries(extraHeaders)) lines.push(`${k}: ${v}`);
  return lines.join("\r\n") + "\r\n\r\n";
}

async function wsConnect(
  port: number,
  path = "/ingest/ws",
  extraHeaders: Record<string, string> = {},
  mkSocket?: () => Socket
): Promise<WsClient> {
  const { status, socket } = await rawUpgrade(port, handshakeRequest(path, extraHeaders), mkSocket);
  assert.equal(status, 101, `expected 101, got ${status}`);
  let buf = Buffer.alloc(0);
  const pending: Array<(f: ServerFrame) => void> = [];
  const queued: ServerFrame[] = [];
  let closedResolve!: () => void;
  const closed = new Promise<void>((r) => (closedResolve = r));
  socket.on("data", (c: Buffer) => {
    buf = Buffer.concat([buf, c]);
    for (;;) {
      if (buf.length < 2) break;
      const opcode = buf[0] & 0x0f;
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
      if (buf.length < off + len) break;
      const frame = { opcode, payload: buf.subarray(off, off + len) };
      buf = buf.subarray(off + len);
      const waiter = pending.shift();
      if (waiter !== undefined) waiter(frame);
      else queued.push(frame);
    }
  });
  socket.on("close", () => closedResolve());
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
    sendText: (text: string) => {
      socket.write(encodeClientFrame(0x1, Buffer.from(text, "utf8")));
    },
    sendPing: (data: Buffer = Buffer.alloc(0)) => {
      socket.write(encodeClientFrame(0x9, data));
    },
    sendClose: (code = 1000) => {
      const body = Buffer.alloc(2);
      body.writeUInt16BE(code, 0);
      socket.write(encodeClientFrame(0x8, body));
    },
    sendBinary: (data: Buffer) => {
      socket.write(encodeClientFrame(0x2, data));
    },
    pause: () => socket.pause(),
    resume: () => socket.resume(),
    closed,
    destroy: () => socket.destroy(),
  };
}

// --- relay factory -----------------------------------------------------------

/** TLS socket factory for wss:// tests (same listener, no second port). */
function tlsSocketFactory(port: number, ca: string): () => Socket {
  return () => {
    const s = tlsConnect({ host: "127.0.0.1", port, ca, servername: "localhost" });
    return s as unknown as Socket;
  };
}

interface TestRelay {
  relay: Server;
  port: number;
  seen: RetryItem[];
}

const relays: Server[] = [];
const clients: WsClient[] = [];

function makeRelay(extraOpts: Record<string, unknown> = {}): Promise<TestRelay> {
  const dir = mkdtempSync(join(tmpdir(), "audit-ws-"));
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
    inboundWs: {},
    ...extraOpts,
  });
  relays.push(relay);
  return listen(relay).then((port) => ({ relay, port, seen }));
}

/** One signed event envelope, shaped like a WR-61 batch item. */
function envelope(payload: unknown, headers: Record<string, string> = {}): string {
  const raw = Buffer.from(JSON.stringify(payload));
  return JSON.stringify({
    payload: raw.toString("base64"),
    headers: { "x-signature": signSha256(raw, TEST_KEY), ...headers },
  });
}

function ed25519KeyPair(): { privatePem: string; publicPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

describe("inbound WebSocket intake (WR-130)", () => {
  after(async () => {
    for (const c of clients.splice(0)) c.destroy();
    for (const r of relays.splice(0)) await closeRelay(r);
  });

  it("completes the RFC 6455 handshake with the correct accept key", async () => {
    const { port } = await makeRelay();
    const { status, headers, socket } = await rawUpgrade(port, handshakeRequest("/ingest/ws"));
    assert.equal(status, 101);
    assert.equal(headers["sec-websocket-accept"], RFC_WS_ACCEPT);
    socket.destroy();
  });

  it("destroys upgrades to unknown paths without a response", async () => {
    const { port } = await makeRelay();
    const { status } = await rawUpgrade(port, handshakeRequest("/nope"));
    assert.equal(status, 0);
  });

  it("rejects non-websocket upgrades with 400", async () => {
    const { port } = await makeRelay();
    const { status, socket } = await rawUpgrade(
      port,
      "GET /ingest/ws HTTP/1.1\r\nHost: x\r\nUpgrade: bogus\r\nConnection: Upgrade\r\n" +
        `Sec-WebSocket-Key: ${RFC_WS_KEY}\r\nSec-WebSocket-Version: 13\r\n\r\n`
    );
    assert.equal(status, 400);
    socket.destroy();
  });

  it("rejects unsupported versions with 426 and Sec-WebSocket-Version: 13", async () => {
    const { port } = await makeRelay();
    const { status, headers, socket } = await rawUpgrade(
      port,
      "GET /ingest/ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
        `Sec-WebSocket-Key: ${RFC_WS_KEY}\r\nSec-WebSocket-Version: 12\r\n\r\n`
    );
    assert.equal(status, 426);
    assert.equal(headers["sec-websocket-version"], "13");
    socket.destroy();
  });

  it("accepts a signed event and delivers it through the retry queue", async () => {
    const { port, seen } = await makeRelay();
    const client = await wsConnect(port, "/ingest/ws", { "x-relay-idempotency-key": "forged" });
    clients.push(client);
    client.sendText(envelope({ hello: "ws" }, { "x-custom-note": "ws-test" }));
    const ack = await client.nextText();
    assert.equal(ack.type, "event-ack");
    assert.equal(ack.status, "accepted");
    assert.match(ack.id, /^[0-9a-f-]{36}$/);
    assert.match(ack.traceId, /^[A-Za-z0-9_-]{1,64}$/);
    await waitFor(() => seen.length === 1);
    assert.equal(seen[0].payload.toString("utf8"), JSON.stringify({ hello: "ws" }));
    // The envelope's custom header rides through; the relay-namespace
    // x-relay-* header from the upgrade request is stripped at intake.
    assert.equal(seen[0].headers["x-custom-note"], "ws-test");
    assert.equal(seen[0].headers["x-relay-idempotency-key"], undefined);
  });

  it("rejects a forged signature with a 401 ack and delivers nothing", async () => {
    const { port, seen } = await makeRelay();
    const client = await wsConnect(port);
    clients.push(client);
    const raw = Buffer.from(JSON.stringify({ hello: "ws" }));
    client.sendText(
      JSON.stringify({
        payload: raw.toString("base64"),
        headers: { "x-signature": signSha256(raw, "wrong-key") },
      })
    );
    const ack = await client.nextText();
    assert.equal(ack.status, "rejected");
    assert.equal(ack.code, 401);
    assert.equal(ack.reason, "invalid_signature");
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(seen.length, 0);
  });

  it("verifies Ed25519 signatures through a custom verifier", async () => {
    const pair = ed25519KeyPair();
    const { port, seen } = await makeRelay({ verifier: new Ed25519Verifier(pair.publicPem) });
    const client = await wsConnect(port);
    clients.push(client);
    const raw = Buffer.from(JSON.stringify({ coin: "ed" }));
    client.sendText(
      JSON.stringify({
        payload: raw.toString("base64"),
        headers: { "x-signature": signEd25519(raw, pair.privatePem) },
      })
    );
    const ack = await client.nextText();
    assert.equal(ack.status, "accepted");
    await waitFor(() => seen.length === 1);
    assert.equal(seen[0].payload.toString("utf8"), JSON.stringify({ coin: "ed" }));
  });

  it("enforces the inbound rate limiter per event", async () => {
    const { port } = await makeRelay({ rateLimit: { perIpPerSecond: 1 } });
    const client = await wsConnect(port);
    clients.push(client);
    client.sendText(envelope({ n: 1 }));
    const first = await client.nextText();
    assert.equal(first.status, "accepted");
    client.sendText(envelope({ n: 2 }));
    const second = await client.nextText();
    assert.equal(second.status, "rejected");
    assert.equal(second.code, 429);
    assert.equal(second.reason, "rate_limited");
    assert.ok(second.retryAfter >= 1, "honest retry-after in whole seconds");
    // The connection survives the 429 — the client can back off and retry.
    await new Promise((r) => setTimeout(r, 1200));
    client.sendText(envelope({ n: 3 }));
    const third = await client.nextText();
    assert.equal(third.status, "accepted");
  });

  it("dedups identical events like the HTTP intake", async () => {
    const { port, seen } = await makeRelay({ dedup: { windowMs: 60_000 } });
    const client = await wsConnect(port);
    clients.push(client);
    const env = envelope({ payment: "once" });
    client.sendText(env);
    const first = await client.nextText();
    assert.equal(first.status, "accepted");
    assert.equal(first.duplicate, undefined);
    client.sendText(env);
    const second = await client.nextText();
    assert.equal(second.status, "accepted");
    assert.equal(second.duplicate, true);
    await waitFor(() => seen.length === 1);
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(seen.length, 1);
  });

  it("rejects events that fail schema validation", async () => {
    const { port, seen } = await makeRelay({
      payloadSchemas: [
        { pattern: "/ingest/ws", schema: createRequiredFieldsSchema("pay", "1", ["amount_cents"]) },
      ],
    });
    const client = await wsConnect(port);
    clients.push(client);
    client.sendText(envelope({ amount_cents: 100 }));
    const ok = await client.nextText();
    assert.equal(ok.status, "accepted");
    client.sendText(envelope({ currency: "usd" }));
    const bad = await client.nextText();
    assert.equal(bad.status, "rejected");
    assert.equal(bad.code, 400);
    assert.equal(bad.reason, "schema_failed");
    await waitFor(() => seen.length === 1);
  });

  it("rejects malformed envelopes without killing the connection", async () => {
    const { port } = await makeRelay();
    const client = await wsConnect(port);
    clients.push(client);
    client.sendText("this is not json");
    const err = await client.nextText();
    assert.equal(err.type, "event-error");
    assert.equal(err.code, 400);
    assert.equal(err.reason, "malformed_envelope");
    // The connection is still usable afterwards.
    client.sendText(envelope({ after: "bad-frame" }));
    const ack = await client.nextText();
    assert.equal(ack.status, "accepted");
  });

  it("gates the endpoint with per-endpoint API keys at upgrade", async () => {
    const { port } = await makeRelay({
      apiKeys: { rules: [{ pattern: "/ingest/ws", keys: [{ id: "k1", key: "key-value-1" }] }] },
    });
    // No key → 401 at upgrade.
    const denied = await rawUpgrade(port, handshakeRequest("/ingest/ws"));
    assert.equal(denied.status, 401);
    denied.socket.destroy();
    // With the key → 101, and the key alone authenticates the event
    // (requireSignature defaults to false, so no x-signature is needed).
    const client = await wsConnect(port, "/ingest/ws", { "x-api-key": "key-value-1" });
    clients.push(client);
    const raw = Buffer.from(JSON.stringify({ keyed: true }));
    client.sendText(JSON.stringify({ payload: raw.toString("base64"), headers: {} }));
    const ack = await client.nextText();
    assert.equal(ack.status, "accepted");
  });

  it("reassembles fragmented text messages", async () => {
    const { port, seen } = await makeRelay();
    const client = await wsConnect(port);
    clients.push(client);
    const env = Buffer.from(envelope({ frag: "mented" }));
    const a = env.subarray(0, 37);
    const b = env.subarray(37);
    client.socket.write(encodeClientFrame(0x1, a, false));
    client.socket.write(encodeClientFrame(0x0, b, true));
    const ack = await client.nextText();
    assert.equal(ack.status, "accepted");
    await waitFor(() => seen.length === 1);
  });

  it("answers client pings with pongs and sends server pings", async () => {
    const { port } = await makeRelay({
      inboundWs: { pingIntervalMs: 60, idleTimeoutMs: 5000 },
    });
    const client = await wsConnect(port);
    clients.push(client);
    client.sendPing(Buffer.from("abc"));
    const pong = await client.nextFrame();
    assert.equal(pong.opcode, 0xa);
    assert.equal(pong.payload.toString(), "abc");
    // A server-initiated ping arrives on its own.
    const serverPing = await client.nextFrame();
    assert.equal(serverPing.opcode, 0x9);
    // Answering it keeps the connection alive past the ping interval.
    client.sendPing(Buffer.from("keep"));
    const pong2 = await client.nextFrame();
    assert.equal(pong2.opcode, 0xa);
  });

  it("closes connections idle past idleTimeoutMs", async () => {
    const { port } = await makeRelay({
      inboundWs: { pingIntervalMs: 0, idleTimeoutMs: 250 },
    });
    const client = await wsConnect(port);
    clients.push(client);
    const close = await client.nextFrame();
    assert.equal(close.opcode, 0x8);
    assert.equal(close.payload.readUInt16BE(0), 1000);
    await client.closed;
  });

  it("disconnects slow consumers past 1MiB of buffered acks", async () => {
    const { port } = await makeRelay();
    const client = await wsConnect(port);
    clients.push(client);
    // Never read: the server's outbound buffer grows until the 1MiB
    // slow-consumer guard (shared with SSE /events) fires. ~40k small
    // acks ≈ 6MB, enough to fill the kernel send buffer and push node's
    // own buffer past the threshold.
    client.pause();
    const raw = Buffer.from(JSON.stringify({ junk: 1 }));
    const badEnv = JSON.stringify({
      payload: raw.toString("base64"),
      headers: { "x-signature": signSha256(raw, "wrong-key") },
    });
    for (let i = 0; i < 40000; i++) {
      client.sendText(badEnv);
    }
    client.resume();
    let code = 0;
    const deadline = Date.now() + 60000;
    while (code !== 1011 && Date.now() < deadline) {
      const f = await client.nextFrame();
      if (f.opcode === 0x8) code = f.payload.readUInt16BE(0);
    }
    assert.equal(code, 1011);
    await client.closed;
  });

  it("retries a failed delivery through the normal retry pipeline", async () => {
    let attempts = 0;
    const dir = mkdtempSync(join(tmpdir(), "audit-ws-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const seen: RetryItem[] = [];
    const relay = createRelayServer({
      secret: TEST_KEY,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog: audit,
      sender: async (item: RetryItem) => {
        attempts++;
        if (attempts === 1) throw new HttpDeliveryError(500);
        seen.push(item);
      },
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 3 },
      inboundWs: {},
    });
    relays.push(relay);
    const port = await listen(relay);
    const client = await wsConnect(port);
    clients.push(client);
    client.sendText(envelope({ retry: "me" }));
    const ack = await client.nextText();
    assert.equal(ack.status, "accepted");
    await waitFor(() => seen.length === 1);
    assert.equal(attempts, 2, "first attempt failed, retry delivered");
    assert.equal(seen[0].payload.toString("utf8"), JSON.stringify({ retry: "me" }));
  });

  it("rejects oversize event bodies with 413 and closes the connection", async () => {
    const { port } = await makeRelay({ maxBodyBytes: 64 });
    const client = await wsConnect(port);
    clients.push(client);
    client.sendText(envelope({ big: "x".repeat(1000) }));
    const ack = await client.nextText();
    assert.equal(ack.status, "rejected");
    assert.equal(ack.code, 413);
    assert.equal(ack.reason, "body_too_large");
    const close = await client.nextFrame();
    assert.equal(close.opcode, 0x8);
    assert.equal(close.payload.readUInt16BE(0), 1009);
    await client.closed;
  });

  it("rejects unmasked client frames as a protocol error", async () => {
    const { port } = await makeRelay();
    const { socket } = await rawUpgrade(port, handshakeRequest("/ingest/ws"));
    // A deliberately unmasked text frame (RFC 6455 §5.1 violation).
    const payload = Buffer.from("hi");
    socket.write(Buffer.concat([Buffer.from([0x81, payload.length]), payload]));
    let buf = Buffer.alloc(0);
    const closeFrame = await new Promise<Buffer>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("close timeout")), 5000);
      socket.on("data", (c: Buffer) => {
        buf = Buffer.concat([buf, c]);
        if (buf.length >= 4 && (buf[0] & 0x0f) === 0x8) {
          clearTimeout(timer);
          resolve(buf);
        }
      });
      socket.on("error", () => {});
    });
    assert.equal(closeFrame.readUInt16BE(2), 1002);
    socket.destroy();
  });

  it("rejects binary frames with 1003", async () => {
    const { port } = await makeRelay();
    const client = await wsConnect(port);
    clients.push(client);
    client.sendBinary(Buffer.from([1, 2, 3]));
    const close = await client.nextFrame();
    assert.equal(close.opcode, 0x8);
    assert.equal(close.payload.readUInt16BE(0), 1003);
    await client.closed;
  });

  it("fails fast on invalid inboundWs config", () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-ws-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const base = {
      secret: TEST_KEY,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog: audit,
    };
    assert.throws(() => createRelayServer({ ...base, inboundWs: { pingIntervalMs: -1 } }), RangeError);
    assert.throws(() => createRelayServer({ ...base, inboundWs: { idleTimeoutMs: 0 } }), RangeError);
    assert.throws(
      () => createRelayServer({ ...base, inboundWs: { maxMessageBytes: 1.5 } }),
      RangeError
    );
    assert.throws(() => createRelayServer({ ...base, inboundWs: { path: "no-slash" } }), RangeError);
    assert.throws(
      () => createRelayServer({ ...base, inboundWs: { path: "/dead-letter" } }),
      RangeError
    );
  });

  it("leaves the endpoint disabled by default", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-ws-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: TEST_KEY,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog: audit,
    });
    relays.push(relay);
    const port = await listen(relay);
    // No upgrade handler when disabled: the upgrade falls through to the
    // normal request handler, which answers 405 for a GET.
    const { status } = await rawUpgrade(port, handshakeRequest("/ingest/ws"));
    assert.equal(status, 405);
  });

  it("serves wss:// on the same TLS listener, no second port", async () => {
    const FIX = generateInboundMtlsFixture();
    const dir = mkdtempSync(join(tmpdir(), "audit-ws-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const seen: RetryItem[] = [];
    const relay = createRelayServer({
      secret: TEST_KEY,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog: audit,
      sender: async (item: RetryItem) => {
        seen.push(item);
      },
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
      inboundWs: {},
      // operatorMtls on the single-plane listener terminates TLS on the
      // intake port; requireCert stays false so anonymous WS producers
      // are admitted exactly like anonymous HTTP ones.
      inboundMtls: {
        key: FIX.serverKeyPem,
        cert: FIX.serverCertPem,
        ca: FIX.caCertPem,
        requireCert: false,
        operatorMtls: true,
      },
    });
    relays.push(relay);
    const port = await listen(relay);
    const client = await wsConnect(port, "/ingest/ws", {}, tlsSocketFactory(port, FIX.caCertPem));
    clients.push(client);
    // The TLS session is genuinely verified: the server presented the
    // fixture leaf (rejectUnauthorized would have failed the connect).
    client.sendText(envelope({ secure: "ws" }));
    const ack = await client.nextText();
    assert.equal(ack.status, "accepted");
    await waitFor(() => seen.length === 1);
    assert.equal(seen[0].payload.toString("utf8"), JSON.stringify({ secure: "ws" }));
  });
});
