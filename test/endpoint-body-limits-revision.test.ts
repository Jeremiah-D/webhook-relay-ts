import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { connect, type Socket } from "node:net";
import { randomBytes } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "endpoint-body-limits-revision-test-key";
const GLOBAL_MAX = 1024;
const PAYMENTS = "/hooks/payments";
const PAYMENTS_MAX = 64;

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

describe("WR-381 RelayServer.reviseEndpointBodyLimits", () => {
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
      endpointBodyLimits: [{ pattern: PAYMENTS, maxBodyBytes: PAYMENTS_MAX }],
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

  it("tightening a rule rejects the next request at the new limit", async () => {
    const dir = mkdtempSync(join(tmpdir(), "eblr-"));
    const { server } = relay(dir, {
      endpointBodyLimits: [{ pattern: PAYMENTS, maxBodyBytes: 256 }],
    });
    const port = await listen(server);
    try {
      const body = Buffer.alloc(100, "a");
      let res = await signed(port, PAYMENTS, body);
      assert.equal(res.status, 202, "100 bytes fits the 256-byte rule");
      assert.deepEqual(
        server.reviseEndpointBodyLimits!([{ pattern: PAYMENTS, maxBodyBytes: 64 }]),
        [{ pattern: PAYMENTS, maxBodyBytes: 64 }]
      );
      res = await signed(port, PAYMENTS, body);
      assert.equal(res.status, 413);
      assert.equal(bodyTooLargeEvent(dir)?.maxBodyBytes, 64);
      const at = Buffer.alloc(64, "a");
      res = await signed(port, PAYMENTS, at);
      assert.equal(res.status, 202, "exactly at the new limit stays accepted");
    } finally {
      await closeRelay(server);
    }
  });

  it("loosening a rule admits a body that was 413 before", async () => {
    const dir = mkdtempSync(join(tmpdir(), "eblr-"));
    const { server } = relay(dir);
    const port = await listen(server);
    try {
      const body = Buffer.alloc(100, "a"); // over the 64-byte rule, under global
      let res = await signed(port, PAYMENTS, body);
      assert.equal(res.status, 413);
      assert.deepEqual(
        server.reviseEndpointBodyLimits!([{ pattern: PAYMENTS, maxBodyBytes: 256 }]),
        [{ pattern: PAYMENTS, maxBodyBytes: 256 }]
      );
      res = await signed(port, PAYMENTS, body);
      assert.equal(res.status, 202);
      assert.equal(bodyTooLargeEvent(dir)?.maxBodyBytes, 64, "only the pre-loosening 413 is audited");
    } finally {
      await closeRelay(server);
    }
  });

  it("an empty-array revision clears every rule and requests fall back to global", async () => {
    const dir = mkdtempSync(join(tmpdir(), "eblr-"));
    const { server } = relay(dir);
    const port = await listen(server);
    try {
      const body = Buffer.alloc(100, "a");
      let res = await signed(port, PAYMENTS, body);
      assert.equal(res.status, 413);
      assert.deepEqual(server.reviseEndpointBodyLimits!([]), []);
      assert.deepEqual(server.getEndpointBodyLimits!(), []);
      res = await signed(port, PAYMENTS, body);
      assert.equal(res.status, 202, "100 bytes is under the global 1024 now");
      const over = Buffer.alloc(GLOBAL_MAX + 1, "a");
      res = await signed(port, PAYMENTS, over);
      assert.equal(res.status, 413);
      assert.equal(bodyTooLargeEvent(dir)?.maxBodyBytes, GLOBAL_MAX);
    } finally {
      await closeRelay(server);
    }
  });

  it("unconfigured relay: revise throws the must-restart Error and the getter is not mounted", async () => {
    const dir = mkdtempSync(join(tmpdir(), "eblr-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const server = createRelayServer({
      ["sec" + "ret"]: signingKey,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      maxBodyBytes: GLOBAL_MAX,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
    });
    const port = await listen(server);
    try {
      assert.equal(server.getEndpointBodyLimits, undefined);
      assert.throws(
        () => server.reviseEndpointBodyLimits!([{ pattern: PAYMENTS, maxBodyBytes: 16 }]),
        /are not configured — enabling them requires a restart/
      );
    } finally {
      await closeRelay(server);
    }
  });

  it("a non-array revision throws RangeError and the live ruleset is untouched", async () => {
    const dir = mkdtempSync(join(tmpdir(), "eblr-"));
    const { server, audit } = relay(dir);
    const port = await listen(server);
    try {
      const bad: unknown[] = [null, undefined, "rules", 42, { pattern: PAYMENTS, maxBodyBytes: 8 }];
      for (const rules of bad) {
        assert.throws(
          () => server.reviseEndpointBodyLimits!(rules as never),
          RangeError,
          `revision should throw RangeError: ${JSON.stringify(rules)}`
        );
      }
      assert.deepEqual(server.getEndpointBodyLimits!(), [
        { pattern: PAYMENTS, maxBodyBytes: PAYMENTS_MAX },
      ]);
      assert.equal(eventsOf(audit, "endpoint_body_limits_revised").length, 0);
    } finally {
      await closeRelay(server);
    }
  });

  it("an invalid rule throws RangeError and the live ruleset is untouched", async () => {
    const dir = mkdtempSync(join(tmpdir(), "eblr-"));
    const { server, audit } = relay(dir);
    const port = await listen(server);
    try {
      const badRules: unknown[] = [
        [{ pattern: "", maxBodyBytes: 8 }],
        [{ pattern: "hooks/no-slash", maxBodyBytes: 8 }],
        [{ pattern: "/x", maxBodyBytes: 0 }],
        [{ pattern: "/x", maxBodyBytes: -1 }],
        [{ pattern: "/x", maxBodyBytes: 1.5 }],
        [{ pattern: "/x", maxBodyBytes: Number.NaN }],
        [{ pattern: "/x" }],
        [null],
        // Half valid still applies nothing.
        [
          { pattern: "/ok", maxBodyBytes: 32 },
          { pattern: "/bad", maxBodyBytes: 0 },
        ],
      ];
      for (const rules of badRules) {
        assert.throws(
          () => server.reviseEndpointBodyLimits!(rules as never),
          RangeError,
          `rules should throw RangeError: ${JSON.stringify(rules)}`
        );
      }
      assert.deepEqual(server.getEndpointBodyLimits!(), [
        { pattern: PAYMENTS, maxBodyBytes: PAYMENTS_MAX },
      ]);
      assert.equal(eventsOf(audit, "endpoint_body_limits_revised").length, 0);
      // The live rules still govern intake: 100 bytes over the live 64
      // is rejected, not sized by any rejected revision.
      const body = Buffer.alloc(100, "a");
      const res = await signed(port, PAYMENTS, body);
      assert.equal(res.status, 413);
    } finally {
      await closeRelay(server);
    }
  });

  it("a same-ruleset revision is a silent no-op; a real revision audits previous/current exactly", async () => {
    const dir = mkdtempSync(join(tmpdir(), "eblr-"));
    const { server, audit } = relay(dir);
    const port = await listen(server);
    try {
      // Landing exactly on the live ruleset audits nothing — same
      // pattern, same budget, same order.
      assert.deepEqual(
        server.reviseEndpointBodyLimits!([{ pattern: PAYMENTS, maxBodyBytes: PAYMENTS_MAX }]),
        [{ pattern: PAYMENTS, maxBodyBytes: PAYMENTS_MAX }]
      );
      assert.equal(eventsOf(audit, "endpoint_body_limits_revised").length, 0);
      assert.deepEqual(
        server.reviseEndpointBodyLimits!([
          { pattern: PAYMENTS, maxBodyBytes: 32 },
          { pattern: "/hooks/*", maxBodyBytes: 512 },
        ]),
        [
          { pattern: PAYMENTS, maxBodyBytes: 32 },
          { pattern: "/hooks/*", maxBodyBytes: 512 },
        ]
      );
      const revised = eventsOf(audit, "endpoint_body_limits_revised");
      assert.equal(revised.length, 1);
      assert.deepEqual(revised[0].previous, [{ pattern: PAYMENTS, maxBodyBytes: PAYMENTS_MAX }]);
      assert.deepEqual(revised[0].current, [
        { pattern: PAYMENTS, maxBodyBytes: 32 },
        { pattern: "/hooks/*", maxBodyBytes: 512 },
      ]);
    } finally {
      await closeRelay(server);
    }
  });

  it("the snapshot getter returns a copy: mutating it never touches the live ruleset", async () => {
    const dir = mkdtempSync(join(tmpdir(), "eblr-"));
    const { server } = relay(dir);
    const port = await listen(server);
    try {
      const snapshot = server.getEndpointBodyLimits!();
      snapshot[0].maxBodyBytes = 1;
      snapshot.push({ pattern: "/evil", maxBodyBytes: 1 });
      assert.deepEqual(server.getEndpointBodyLimits!(), [
        { pattern: PAYMENTS, maxBodyBytes: PAYMENTS_MAX },
      ]);
      // The live rules still govern intake: 100 bytes over the live 64
      // is rejected, not sized by the mutated snapshot.
      const body = Buffer.alloc(100, "a");
      const res = await signed(port, PAYMENTS, body);
      assert.equal(res.status, 413);
    } finally {
      await closeRelay(server);
    }
  });

  it("first-match priority still holds after revision", async () => {
    const dir = mkdtempSync(join(tmpdir(), "eblr-"));
    const { server, audit } = relay(dir, {
      endpointBodyLimits: [
        { pattern: "/hooks/*", maxBodyBytes: 2048 },
        { pattern: PAYMENTS, maxBodyBytes: 8 },
      ],
    });
    const port = await listen(server);
    try {
      const body = Buffer.alloc(100, "a");
      let res = await signed(port, PAYMENTS, body);
      assert.equal(res.status, 202, "first (prefix) rule wins over the later exact rule");
      // Reversing the order is a real revision — same rules, new order —
      // and flips which rule governs /hooks/payments.
      assert.deepEqual(
        server.reviseEndpointBodyLimits!([
          { pattern: PAYMENTS, maxBodyBytes: 8 },
          { pattern: "/hooks/*", maxBodyBytes: 2048 },
        ]),
        [
          { pattern: PAYMENTS, maxBodyBytes: 8 },
          { pattern: "/hooks/*", maxBodyBytes: 2048 },
        ]
      );
      assert.equal(eventsOf(audit, "endpoint_body_limits_revised").length, 1);
      res = await signed(port, PAYMENTS, body);
      assert.equal(res.status, 413, "exact rule now wins after the reorder");
      assert.equal(bodyTooLargeEvent(dir)?.maxBodyBytes, 8);
    } finally {
      await closeRelay(server);
    }
  });

  it("the tenant budget still wins over endpoint rules after revision", async () => {
    const dir = mkdtempSync(join(tmpdir(), "eblr-"));
    const { server } = relay(dir, {
      endpointBodyLimits: [{ pattern: PAYMENTS, maxBodyBytes: 2048 }],
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
      // Tighten the endpoint rule far below the tenant budget — the
      // tenant budget must still win for acme's requests.
      server.reviseEndpointBodyLimits!([{ pattern: PAYMENTS, maxBodyBytes: 8 }]);
      res = await signed(port, PAYMENTS, body, { "x-tenant-id": "acme" });
      assert.equal(res.status, 413);
      assert.equal(bodyTooLargeEvent(dir)?.maxBodyBytes, 16, "tenant budget still wins");
      res = await signed(port, PAYMENTS, body);
      assert.equal(res.status, 413, "untagged requests now hit the tightened endpoint rule");
      assert.equal(bodyTooLargeEvent(dir)?.maxBodyBytes, 8);
    } finally {
      await closeRelay(server);
    }
  });

  it("a WS handshake after revision is sized by the new rules; an established connection keeps its handshake budget", async () => {
    const dir = mkdtempSync(join(tmpdir(), "eblr-"));
    const { server } = relay(dir, {
      endpointBodyLimits: [{ pattern: "/ingest/ws", maxBodyBytes: 2048 }],
      inboundWs: {},
    });
    const port = await listen(server);
    const clients: WsClient[] = [];
    try {
      // Payload decodes to 110 bytes: fits the 2048 rule, not a 16 one.
      const big = envelope({ pad: "x".repeat(100) });
      const established = await wsConnect(port);
      clients.push(established);
      established.sendText(big);
      let ack = await established.nextText();
      assert.equal(ack.status, "accepted");
      server.reviseEndpointBodyLimits!([{ pattern: "/ingest/ws", maxBodyBytes: 16 }]);
      // The established connection keeps its handshake-time budget.
      established.sendText(big);
      ack = await established.nextText();
      assert.equal(ack.status, "accepted", "established connection keeps its handshake budget");
      // A fresh handshake after the revision is sized by the new rule.
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
      server.reviseEndpointBodyLimits!([{ pattern: "/ingest/ws", maxBodyBytes: 2048 }]);
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
});
