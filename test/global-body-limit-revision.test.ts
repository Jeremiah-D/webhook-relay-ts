import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { connect, type Socket } from "node:net";
import { randomBytes } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer, DEFAULT_MAX_BODY_BYTES } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "global-body-limit-revision-test-key";
const GLOBAL_MAX = 1024;
const PAYMENTS = "/hooks/payments";
const PAYMENTS_MAX = 2048;

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function post(port: number, path: string, body: Buffer, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method: "POST", headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () =>
        resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
      );
    });
    r.on("error", reject);
    r.end(body);
  });
}

function signed(port: number, path: string, body: Buffer, extra: Record<string, string> = {}) {
  return post(port, path, body, { "x-signature": signSha256(body, signingKey), ...extra });
}

// Chunked POST with no Content-Length: the declared-length pre-check is
// skipped and the streaming cap governs — the body drips in slowly, so
// the request is provably in flight (inside `readRawBody`) while the
// caller revises the limit mid-stream.
function postSlow(
  port: number,
  path: string,
  chunks: Buffer[],
  gapMs: number,
  headers: Record<string, string> = {}
): Promise<{ status: number; text: string }> {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path, method: "POST", headers },
      (res) => {
        const out: Buffer[] = [];
        res.on("data", (c: Buffer) => out.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(out).toString() })
        );
      }
    );
    r.on("error", reject);
    (async () => {
      for (const [i, chunk] of chunks.entries()) {
        r.write(chunk);
        if (i < chunks.length - 1) {
          await new Promise((t) => setTimeout(t, gapMs));
        }
      }
      r.end();
    })();
  });
}

async function closeRelay(server: Server): Promise<void> {
  server.close();
  await new Promise((r) => server.once("close", r));
}

// --- minimal raw RFC 6455 client (subset of inbound-ws.test.ts) ------------

interface ServerFrame {
  opcode: number;
  payload: Buffer;
}

function encodeClientFrame(opcode: number, payload: Buffer): Buffer {
  const len = payload.length;
  let header: Buffer;
  const b0 = 0x80 | opcode;
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
  sendClose: (code?: number) => void;
  closed: Promise<void>;
  destroy: () => void;
}

async function wsConnect(port: number, path = "/ingest/ws"): Promise<WsClient> {
  const socket = connect(port, "127.0.0.1");
  const status = await new Promise<number>((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => reject(new Error("upgrade response timeout")), 5000);
    socket.on("data", (c: Buffer) => {
      buf = Buffer.concat([buf, c]);
      const idx = buf.indexOf("\r\n\r\n");
      if (idx < 0) return;
      clearTimeout(timer);
      const head = buf.subarray(0, idx).toString("latin1").split("\r\n");
      socket.removeAllListeners("data");
      resolve(Number(head[0].split(" ")[1]));
    });
    socket.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    socket.write(
      [
        `GET ${path} HTTP/1.1`,
        "Host: 127.0.0.1",
        "Upgrade: websocket",
        "Connection: Upgrade",
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
        "Sec-WebSocket-Version: 13",
        "",
        "",
      ].join("\r\n")
    );
  });
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
    sendClose: (code = 1000) => {
      const body = Buffer.alloc(2);
      body.writeUInt16BE(code, 0);
      socket.write(encodeClientFrame(0x8, body));
    },
    closed,
    destroy: () => socket.destroy(),
  };
}

/** One signed event envelope, shaped like a WR-61 batch item. */
function envelope(payload: unknown): string {
  const raw = Buffer.from(JSON.stringify(payload));
  return JSON.stringify({
    payload: raw.toString("base64"),
    headers: { "x-signature": signSha256(raw, signingKey) },
  });
}

describe("WR-382 RelayServer.reviseMaxBodyBytes", () => {
  let stub: Server;
  let stubPort: number;

  before(async () => {
    stub = createServer((req, res) => {
      req.resume();
      req.on("end", () => res.writeHead(200).end("ok"));
    });
    stubPort = await listen(stub);
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  function relay(dir: string, extra: Record<string, unknown> = {}) {
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const server = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: signingKey,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      maxBodyBytes: GLOBAL_MAX,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
      ...extra,
    });
    return { server, audit };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  function bodyTooLargeEvent(dir: string): Record<string, unknown> | undefined {
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const rejected = (audit.readAll() as Array<Record<string, unknown>>).filter(
      (e) => e.event === "rejected" && e.reason === "body_too_large"
    );
    // Most recent: several tests 413 twice under different budgets.
    return rejected[rejected.length - 1];
  }

  it("a non-positive-integer revision throws RangeError and the live limit is untouched", async () => {
    const dir = mkdtempSync(join(tmpdir(), "gblr-"));
    const { server, audit } = relay(dir);
    const port = await listen(server);
    try {
      const bad: unknown[] = [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, "1024", undefined, null, {}];
      for (const value of bad) {
        assert.throws(
          () => server.reviseMaxBodyBytes!(value as never),
          RangeError,
          `revision should throw RangeError: ${JSON.stringify(value)}`
        );
      }
      assert.equal(server.getMaxBodyBytes!(), GLOBAL_MAX);
      assert.equal(eventsOf(audit, "max_body_bytes_revised").length, 0);
      // The live limit still governs intake: 100 bytes under the live
      // 1024 is accepted, not sized by any rejected revision.
      const body = Buffer.alloc(100, "a");
      const res = await signed(port, "/", body);
      assert.equal(res.status, 202);
    } finally {
      await closeRelay(server);
    }
  });

  it("a same-value revision is a silent no-op with no audit event", async () => {
    const dir = mkdtempSync(join(tmpdir(), "gblr-"));
    const { server, audit } = relay(dir);
    const port = await listen(server);
    try {
      assert.equal(server.reviseMaxBodyBytes!(GLOBAL_MAX), GLOBAL_MAX);
      assert.equal(server.getMaxBodyBytes!(), GLOBAL_MAX);
      assert.equal(eventsOf(audit, "max_body_bytes_revised").length, 0);
      // A real revision, then landing back on the same value, is
      // likewise silent.
      assert.equal(server.reviseMaxBodyBytes!(512), 512);
      assert.equal(eventsOf(audit, "max_body_bytes_revised").length, 1);
      assert.equal(server.reviseMaxBodyBytes!(512), 512);
      assert.equal(eventsOf(audit, "max_body_bytes_revised").length, 1);
    } finally {
      await closeRelay(server);
    }
  });

  it("tightening the limit rejects the next request at the new limit", async () => {
    const dir = mkdtempSync(join(tmpdir(), "gblr-"));
    const { server } = relay(dir);
    const port = await listen(server);
    try {
      const body = Buffer.alloc(100, "a");
      let res = await signed(port, "/", body);
      assert.equal(res.status, 202, "100 bytes fits the 1024-byte global");
      assert.equal(server.reviseMaxBodyBytes!(64), 64);
      assert.equal(server.getMaxBodyBytes!(), 64);
      res = await signed(port, "/", body);
      assert.equal(res.status, 413);
      assert.equal(bodyTooLargeEvent(dir)?.maxBodyBytes, 64);
      const at = Buffer.alloc(64, "a");
      res = await signed(port, "/", at);
      assert.equal(res.status, 202, "exactly at the new limit stays accepted");
    } finally {
      await closeRelay(server);
    }
  });

  it("loosening the limit admits a body that was 413 before", async () => {
    const dir = mkdtempSync(join(tmpdir(), "gblr-"));
    const { server } = relay(dir, { maxBodyBytes: 64 });
    const port = await listen(server);
    try {
      const body = Buffer.alloc(100, "a");
      let res = await signed(port, "/", body);
      assert.equal(res.status, 413);
      assert.equal(bodyTooLargeEvent(dir)?.maxBodyBytes, 64);
      assert.equal(server.reviseMaxBodyBytes!(GLOBAL_MAX), GLOBAL_MAX);
      res = await signed(port, "/", body);
      assert.equal(res.status, 202);
      assert.equal(bodyTooLargeEvent(dir)?.maxBodyBytes, 64, "only the pre-loosening 413 is audited");
    } finally {
      await closeRelay(server);
    }
  });

  it("a WS handshake after revision is sized by the new limit; an established connection keeps its handshake budget", async () => {
    const dir = mkdtempSync(join(tmpdir(), "gblr-"));
    const { server } = relay(dir, { inboundWs: {} });
    const port = await listen(server);
    const clients: WsClient[] = [];
    try {
      // Payload decodes to 110 bytes: fits the 1024 global, not a 64 one.
      const big = envelope({ pad: "x".repeat(100) });
      const established = await wsConnect(port);
      clients.push(established);
      established.sendText(big);
      let ack = await established.nextText();
      assert.equal(ack.status, "accepted");
      server.reviseMaxBodyBytes!(64);
      // The established connection keeps its handshake-time budget.
      established.sendText(big);
      ack = await established.nextText();
      assert.equal(ack.status, "accepted", "established connection keeps its handshake budget");
      // A fresh handshake after the revision is sized by the new limit.
      const fresh = await wsConnect(port);
      clients.push(fresh);
      fresh.sendText(big);
      ack = await fresh.nextText();
      assert.equal(ack.status, "rejected");
      assert.equal(ack.code, 413);
      assert.equal(ack.reason, "body_too_large");
      const close = await fresh.nextFrame();
      assert.equal(close.opcode, 0x8);
      assert.equal(close.payload.readUInt16BE(0), 1009);
      await fresh.closed;
      // Loosen again: the next handshake admits the same event.
      server.reviseMaxBodyBytes!(GLOBAL_MAX);
      const loosened = await wsConnect(port);
      clients.push(loosened);
      loosened.sendText(big);
      ack = await loosened.nextText();
      assert.equal(ack.status, "accepted");
    } finally {
      // Graceful close first: a bare socket.destroy() leaves the
      // server-side socket tracked until its 60s headersTimeout, which
      // stalls server.close(); a close frame lets the server tear the
      // connection down at once.
      for (const c of clients) {
        try {
          c.sendClose();
        } catch {
          // Already dead — destroy below covers it.
        }
      }
      for (const c of clients) {
        await Promise.race([c.closed, new Promise((r) => setTimeout(r, 2000))]);
        c.destroy();
      }
      await closeRelay(server);
    }
  });

  it("an endpoint rule still beats the revised global", async () => {
    const dir = mkdtempSync(join(tmpdir(), "gblr-"));
    const { server } = relay(dir, {
      endpointBodyLimits: [{ pattern: PAYMENTS, maxBodyBytes: PAYMENTS_MAX }],
    });
    const port = await listen(server);
    try {
      const body = Buffer.alloc(100, "a");
      let res = await signed(port, PAYMENTS, body);
      assert.equal(res.status, 202, "100 bytes fits the 2048 endpoint rule");
      // Tighten the global far below the endpoint rule — the rule must
      // still win for the matched path.
      server.reviseMaxBodyBytes!(64);
      res = await signed(port, PAYMENTS, body);
      assert.equal(res.status, 202, "endpoint rule still beats the tightened global");
      const fat = Buffer.alloc(3000, "a");
      res = await signed(port, PAYMENTS, fat);
      assert.equal(res.status, 413);
      assert.equal(bodyTooLargeEvent(dir)?.maxBodyBytes, PAYMENTS_MAX, "the rule's budget fired, not the global");
      // Loosen the global above the rule — the rule still governs.
      server.reviseMaxBodyBytes!(8192);
      res = await signed(port, PAYMENTS, fat);
      assert.equal(res.status, 413);
      assert.equal(bodyTooLargeEvent(dir)?.maxBodyBytes, PAYMENTS_MAX);
      // Clearing the rules falls back to the *revised* global, not the
      // construction value: 100 bytes now fits the 8192 global.
      server.reviseEndpointBodyLimits!([]);
      res = await signed(port, PAYMENTS, body);
      assert.equal(res.status, 202);
      const over = Buffer.alloc(8193, "a");
      res = await signed(port, PAYMENTS, over);
      assert.equal(res.status, 413);
      assert.equal(bodyTooLargeEvent(dir)?.maxBodyBytes, 8192);
    } finally {
      await closeRelay(server);
    }
  });

  it("a tenant budget still beats the endpoint rule and the revised global", async () => {
    const dir = mkdtempSync(join(tmpdir(), "gblr-"));
    const { server } = relay(dir, {
      endpointBodyLimits: [{ pattern: PAYMENTS, maxBodyBytes: PAYMENTS_MAX }],
      tenantBodyLimits: { acme: 16 },
    });
    const port = await listen(server);
    try {
      const body = Buffer.alloc(100, "a");
      let res = await signed(port, PAYMENTS, body, { "x-tenant-id": "acme" });
      assert.equal(res.status, 413, "tenant budget 16 governs over the 2048 endpoint rule");
      assert.equal(bodyTooLargeEvent(dir)?.maxBodyBytes, 16);
      res = await signed(port, PAYMENTS, body);
      assert.equal(res.status, 202, "no tenant header: the endpoint rule governs");
      // Tighten the global far below the tenant budget — the tenant
      // budget must still win for acme's requests.
      server.reviseMaxBodyBytes!(8);
      res = await signed(port, PAYMENTS, body, { "x-tenant-id": "acme" });
      assert.equal(res.status, 413);
      assert.equal(bodyTooLargeEvent(dir)?.maxBodyBytes, 16, "tenant budget still wins");
      res = await signed(port, PAYMENTS, body);
      assert.equal(res.status, 202, "untagged requests still hit the endpoint rule");
      // Loosen the global above everything — the tenant budget still
      // wins, and a live tenant revision moves it without touching the
      // endpoint rule or the global.
      server.reviseMaxBodyBytes!(8192);
      server.reviseTenantBodyLimits!({ acme: 32 });
      res = await signed(port, PAYMENTS, body, { "x-tenant-id": "acme" });
      assert.equal(res.status, 413);
      assert.equal(bodyTooLargeEvent(dir)?.maxBodyBytes, 32, "live-revised tenant budget still wins");
      res = await signed(port, PAYMENTS, body);
      assert.equal(res.status, 202, "untagged requests still hit the endpoint rule");
    } finally {
      await closeRelay(server);
    }
  });

  it("an in-flight request keeps the limit it was parsed under", async () => {
    const dir = mkdtempSync(join(tmpdir(), "gblr-"));
    const { server } = relay(dir);
    const port = await listen(server);
    try {
      const body = Buffer.alloc(100, "a");
      const sig = signSha256(body, signingKey);
      // Drip the body in two chunks: the first chunk puts the server
      // inside `readRawBody` under the old 1024 limit, the revision
      // lands mid-stream, and the second chunk completes a 100-byte
      // body that exceeds the new 64 limit.
      const inflight = postSlow(
        port,
        "/",
        [body.subarray(0, 50), body.subarray(50)],
        100,
        { "x-signature": sig }
      );
      // Wait until the server is inside the streaming read, then
      // tighten the limit underneath the in-flight request.
      await new Promise((r) => setTimeout(r, 100));
      assert.equal(server.reviseMaxBodyBytes!(64), 64);
      const res = await inflight;
      assert.equal(res.status, 202, "in-flight request keeps its parse-time budget");
      // The next request is sized by the new limit.
      const next = await signed(port, "/", body);
      assert.equal(next.status, 413);
      assert.equal(bodyTooLargeEvent(dir)?.maxBodyBytes, 64);
    } finally {
      await closeRelay(server);
    }
  });

  it("a real revision audits previous/current exactly, construction value first", async () => {
    const dir = mkdtempSync(join(tmpdir(), "gblr-"));
    const { server, audit } = relay(dir);
    const port = await listen(server);
    try {
      assert.equal(server.reviseMaxBodyBytes!(512), 512);
      assert.equal(server.reviseMaxBodyBytes!(2048), 2048);
      // Same value again: no third event.
      assert.equal(server.reviseMaxBodyBytes!(2048), 2048);
      const revised = eventsOf(audit, "max_body_bytes_revised");
      assert.equal(revised.length, 2);
      assert.deepEqual(
        revised.map((e) => [e.previous, e.current]),
        [
          [GLOBAL_MAX, 512],
          [512, 2048],
        ]
      );
      assert.equal(server.getMaxBodyBytes!(), 2048);
    } finally {
      await closeRelay(server);
    }
  });

  it("the 1 MiB default is revisable with no explicit configuration", async () => {
    const dir = mkdtempSync(join(tmpdir(), "gblr-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const server = createRelayServer({
      ["sec" + "ret"]: signingKey,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
    });
    const port = await listen(server);
    try {
      // No "unconfigured" gate: the getter and the reviser are always
      // set, and the default is the live value.
      assert.equal(typeof server.reviseMaxBodyBytes, "function");
      assert.equal(typeof server.getMaxBodyBytes, "function");
      assert.equal(server.getMaxBodyBytes!(), DEFAULT_MAX_BODY_BYTES);
      assert.equal(server.reviseMaxBodyBytes!(64), 64);
      const revised = eventsOf(audit, "max_body_bytes_revised");
      assert.equal(revised.length, 1);
      assert.equal(revised[0].previous, DEFAULT_MAX_BODY_BYTES);
      assert.equal(revised[0].current, 64);
      const body = Buffer.alloc(100, "a");
      const res = await signed(port, "/", body);
      assert.equal(res.status, 413);
      assert.equal(bodyTooLargeEvent(dir)?.maxBodyBytes, 64);
    } finally {
      await closeRelay(server);
    }
  });
});
