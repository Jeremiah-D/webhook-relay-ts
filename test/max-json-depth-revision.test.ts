import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { connect, type Socket } from "node:net";
import { randomBytes } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { DEFAULT_MAX_JSON_DEPTH } from "../src/json-depth.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "max-json-depth-revision-test-key";
const DEPTH_FIVE = 5;

/** `"[".repeat(n) + "]".repeat(n)` — a JSON body nested `n` levels deep. */
function nestedBody(n: number): Buffer {
  return Buffer.from("[".repeat(n) + "]".repeat(n));
}

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

// Chunked POST with no Content-Length: the body drips in slowly, so the
// request is provably in flight (inside `readRawBody`) while the caller
// revises the limit mid-stream.
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

/** One signed event envelope carrying `raw` as the exact payload bytes. */
function envelopeRaw(raw: Buffer): string {
  return JSON.stringify({
    payload: raw.toString("base64"),
    headers: { "x-signature": signSha256(raw, signingKey) },
  });
}

describe("WR-383 RelayServer.reviseMaxJsonDepth", () => {
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
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
      ...extra,
    });
    return { server, audit };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  function tooDeepEvent(dir: string): Record<string, unknown> | undefined {
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const rejected = (audit.readAll() as Array<Record<string, unknown>>).filter(
      (e) => e.event === "rejected" && e.reason === "json_too_deep"
    );
    // Most recent: several tests 400 twice under different limits.
    return rejected[rejected.length - 1];
  }

  it("a non-positive-integer revision throws RangeError and the live limit is untouched", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mjdr-"));
    const { server, audit } = relay(dir);
    const port = await listen(server);
    try {
      const bad: unknown[] = [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, "32", undefined, null, {}];
      for (const value of bad) {
        assert.throws(
          () => server.reviseMaxJsonDepth!(value as never),
          RangeError,
          `revision should throw RangeError: ${JSON.stringify(value)}`
        );
      }
      assert.equal(server.getMaxJsonDepth!(), DEFAULT_MAX_JSON_DEPTH);
      assert.equal(eventsOf(audit, "max_json_depth_revised").length, 0);
      // The live limit still governs intake: a depth-5 body fits the
      // live 32, not any rejected revision.
      const res = await signed(port, "/", nestedBody(DEPTH_FIVE));
      assert.equal(res.status, 202);
    } finally {
      await closeRelay(server);
    }
  });

  it("a same-value revision is a silent no-op with no audit event", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mjdr-"));
    const { server, audit } = relay(dir);
    const port = await listen(server);
    try {
      assert.equal(server.reviseMaxJsonDepth!(DEFAULT_MAX_JSON_DEPTH), DEFAULT_MAX_JSON_DEPTH);
      assert.equal(server.getMaxJsonDepth!(), DEFAULT_MAX_JSON_DEPTH);
      assert.equal(eventsOf(audit, "max_json_depth_revised").length, 0);
      // A real revision, then landing back on the same value, is
      // likewise silent.
      assert.equal(server.reviseMaxJsonDepth!(16), 16);
      assert.equal(eventsOf(audit, "max_json_depth_revised").length, 1);
      assert.equal(server.reviseMaxJsonDepth!(16), 16);
      assert.equal(eventsOf(audit, "max_json_depth_revised").length, 1);
    } finally {
      await closeRelay(server);
    }
  });

  it("tightening the limit rejects the next request at the new depth", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mjdr-"));
    const { server } = relay(dir);
    const port = await listen(server);
    try {
      const body = nestedBody(DEPTH_FIVE);
      let res = await signed(port, "/", body);
      assert.equal(res.status, 202, "depth 5 fits the 32-level default");
      assert.equal(server.reviseMaxJsonDepth!(4), 4);
      assert.equal(server.getMaxJsonDepth!(), 4);
      res = await signed(port, "/", body);
      assert.equal(res.status, 400);
      assert.match(res.text, /limit of 4/);
      const evt = tooDeepEvent(dir);
      assert.equal(evt?.depth, DEPTH_FIVE);
      assert.equal(evt?.maxJsonDepth, 4);
      const at = nestedBody(4);
      res = await signed(port, "/", at);
      assert.equal(res.status, 202, "exactly at the new limit stays accepted");
    } finally {
      await closeRelay(server);
    }
  });

  it("loosening the limit admits a body that was 400 before", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mjdr-"));
    const { server } = relay(dir, { maxJsonDepth: 4 });
    const port = await listen(server);
    try {
      const body = nestedBody(DEPTH_FIVE);
      let res = await signed(port, "/", body);
      assert.equal(res.status, 400);
      assert.equal(tooDeepEvent(dir)?.maxJsonDepth, 4);
      assert.equal(server.reviseMaxJsonDepth!(DEFAULT_MAX_JSON_DEPTH), DEFAULT_MAX_JSON_DEPTH);
      res = await signed(port, "/", body);
      assert.equal(res.status, 202);
      assert.equal(tooDeepEvent(dir)?.maxJsonDepth, 4, "only the pre-loosening 400 is audited");
    } finally {
      await closeRelay(server);
    }
  });

  it("scalar and non-JSON bodies skip the check before and after revision", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mjdr-"));
    const { server, audit } = relay(dir);
    const port = await listen(server);
    try {
      const scalar = Buffer.from("123");
      const text = Buffer.from("not json at all");
      for (const body of [scalar, text]) {
        const res = await signed(port, "/", body);
        assert.equal(res.status, 202);
      }
      // Tighten to the floor: scalars (depth 0) and non-JSON still skip.
      assert.equal(server.reviseMaxJsonDepth!(1), 1);
      for (const body of [scalar, text]) {
        const res = await signed(port, "/", body);
        assert.equal(res.status, 202, "scalar / non-JSON bodies skip the depth check");
      }
      assert.equal(
        eventsOf(audit, "rejected").filter((e) => e.reason === "json_too_deep").length,
        0
      );
      // And a depth-2 body is now over the limit, proving the check
      // itself still runs.
      const res = await signed(port, "/", nestedBody(2));
      assert.equal(res.status, 400);
    } finally {
      await closeRelay(server);
    }
  });

  it("an in-flight request keeps the depth it was parsed under", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mjdr-"));
    const { server } = relay(dir);
    const port = await listen(server);
    try {
      const body = nestedBody(DEPTH_FIVE);
      const sig = signSha256(body, signingKey);
      // Drip the body in two chunks: the first chunk puts the server
      // inside `readRawBody` under the old depth 32, the revision lands
      // mid-stream, and the second chunk completes a depth-5 body that
      // exceeds the new depth 4.
      const inflight = postSlow(
        port,
        "/",
        [body.subarray(0, 5), body.subarray(5)],
        100,
        { "x-signature": sig }
      );
      // Wait until the server is inside the streaming read, then
      // tighten the limit underneath the in-flight request.
      await new Promise((r) => setTimeout(r, 100));
      assert.equal(server.reviseMaxJsonDepth!(4), 4);
      const res = await inflight;
      assert.equal(res.status, 202, "in-flight request keeps its parse-time depth");
      // The next request is judged by the new depth.
      const next = await signed(port, "/", body);
      assert.equal(next.status, 400);
      assert.equal(tooDeepEvent(dir)?.maxJsonDepth, 4);
    } finally {
      await closeRelay(server);
    }
  });

  it("a real revision audits previous/current exactly, construction value first", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mjdr-"));
    const { server, audit } = relay(dir);
    const port = await listen(server);
    try {
      assert.equal(server.reviseMaxJsonDepth!(16), 16);
      assert.equal(server.reviseMaxJsonDepth!(64), 64);
      // Same value again: no third event.
      assert.equal(server.reviseMaxJsonDepth!(64), 64);
      const revised = eventsOf(audit, "max_json_depth_revised");
      assert.equal(revised.length, 2);
      assert.deepEqual(
        revised.map((e) => [e.previous, e.current]),
        [
          [DEFAULT_MAX_JSON_DEPTH, 16],
          [16, 64],
        ]
      );
      assert.equal(server.getMaxJsonDepth!(), 64);
    } finally {
      await closeRelay(server);
    }
  });

  it("the 32-level default is revisable with no explicit configuration", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mjdr-"));
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
      assert.equal(typeof server.reviseMaxJsonDepth, "function");
      assert.equal(typeof server.getMaxJsonDepth, "function");
      assert.equal(server.getMaxJsonDepth!(), DEFAULT_MAX_JSON_DEPTH);
      assert.equal(server.reviseMaxJsonDepth!(4), 4);
      const revised = eventsOf(audit, "max_json_depth_revised");
      assert.equal(revised.length, 1);
      assert.equal(revised[0].previous, DEFAULT_MAX_JSON_DEPTH);
      assert.equal(revised[0].current, 4);
      const res = await signed(port, "/", nestedBody(DEPTH_FIVE));
      assert.equal(res.status, 400);
      assert.equal(tooDeepEvent(dir)?.maxJsonDepth, 4);
    } finally {
      await closeRelay(server);
    }
  });

  it("a WS connection keeps its handshake-time depth after revision", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mjdr-"));
    const { server } = relay(dir, { inboundWs: {} });
    const port = await listen(server);
    const clients: WsClient[] = [];
    try {
      const deep = envelopeRaw(nestedBody(DEPTH_FIVE));
      const shallow = envelopeRaw(Buffer.from(JSON.stringify({ ok: true })));
      const established = await wsConnect(port);
      clients.push(established);
      established.sendText(deep);
      let ack = await established.nextText();
      assert.equal(ack.status, "accepted", "depth-5 event fits the 32-level handshake depth");
      server.reviseMaxJsonDepth!(4);
      // The established connection keeps its handshake-time depth.
      established.sendText(deep);
      ack = await established.nextText();
      assert.equal(ack.status, "accepted", "established connection keeps its handshake depth");
      established.sendText(shallow);
      ack = await established.nextText();
      assert.equal(ack.status, "accepted");
      // A fresh handshake after the revision is judged by the new depth.
      const fresh = await wsConnect(port);
      clients.push(fresh);
      fresh.sendText(deep);
      ack = await fresh.nextText();
      assert.equal(ack.status, "rejected");
      assert.equal(ack.code, 400);
      assert.equal(ack.reason, "json_too_deep");
      // The rejection does not tear the connection down: a shallow
      // event on the same connection is still accepted.
      fresh.sendText(shallow);
      ack = await fresh.nextText();
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
});
