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
import {
  compressMessage,
  decompressMessage,
  resolvePerMessageDeflate,
  WsInflateBombError,
} from "../src/deflate.ts";
import { resolveInboundWsOptions } from "../src/inbound-ws.ts";
import type { RetryItem } from "../src/retry.ts";

// Never name a constant SECRET here: the runtime secret redaction rewrites
// `secret: SECRET` occurrences and breaks the TS syntax (see AGENTS.md).
const TEST_KEY = "ws-inflate-bomb-test-key";
const RFC_WS_KEY = "dGhlIHNhbXBsZSBub25jZQ==";
const FULL_OFFER =
  "permessage-deflate; client_no_context_takeover; server_no_context_takeover";
// gzip-bomb style: 20k zero bytes compress to tens of bytes on the wire.
const BOMB_PLAIN_BYTES = 20_000;

async function bombWire(): Promise<Buffer> {
  return compressMessage(Buffer.alloc(BOMB_PLAIN_BYTES, 0));
}

// --- inflate cap unit tests ---------------------------------------------------

describe("decompressMessage inflate cap (WR-161)", () => {
  it("intercepts a decompression bomb before it materializes", async () => {
    const wire = await bombWire();
    assert.ok(
      wire.length < BOMB_PLAIN_BYTES / 10,
      `bomb should compress well, got ${wire.length} wire bytes`
    );
    await assert.rejects(
      () => decompressMessage(wire, 4096),
      (err: unknown) =>
        err instanceof WsInflateBombError && /maxInflatedBytes 4096/.test(err.message)
    );
  });

  it("leaves a legal large message within the cap untouched", async () => {
    const wire = await bombWire();
    const back = await decompressMessage(wire, 1_000_000);
    assert.equal(back.length, BOMB_PLAIN_BYTES);
    assert.ok(back.equals(Buffer.alloc(BOMB_PLAIN_BYTES, 0)));
  });

  it("treats exactly-at-cap as legal, one byte over as a bomb", async () => {
    const wire = await bombWire();
    await assert.doesNotReject(() => decompressMessage(wire, BOMB_PLAIN_BYTES));
    await assert.rejects(
      () => decompressMessage(wire, BOMB_PLAIN_BYTES - 1),
      (err: unknown) => err instanceof WsInflateBombError
    );
  });

  it("rejects illegal caps with RangeError", async () => {
    const wire = await bombWire();
    for (const bad of [0, -1, 1.5, Number.NaN] as number[]) {
      await assert.rejects(
        () => decompressMessage(wire, bad),
        RangeError,
        `expected RangeError for cap ${JSON.stringify(bad)}`
      );
    }
  });

  it("still rejects corrupt input as a protocol error, not a bomb", async () => {
    await assert.rejects(
      () => decompressMessage(randomBytes(64), 4096),
      (err: unknown) =>
        err instanceof Error &&
        !(err instanceof WsInflateBombError) &&
        /decompression failed/.test(err.message)
    );
  });
});

// --- option validation -------------------------------------------------------

describe("resolvePerMessageDeflate maxInflatedBytes (WR-161)", () => {
  it("defaults to 8MiB", () => {
    assert.deepEqual(resolvePerMessageDeflate(true), {
      thresholdBytes: 1024,
      maxInflatedBytes: 8 * 1024 * 1024,
    });
    assert.deepEqual(resolvePerMessageDeflate({}), {
      thresholdBytes: 1024,
      maxInflatedBytes: 8 * 1024 * 1024,
    });
  });

  it("honors an explicit cap", () => {
    assert.deepEqual(resolvePerMessageDeflate({ maxInflatedBytes: 4096 }), {
      thresholdBytes: 1024,
      maxInflatedBytes: 4096,
    });
  });

  it("rejects illegal caps with RangeError", () => {
    for (const bad of [0, -8, 1.5, Number.NaN, "8192", null, []] as unknown[]) {
      assert.throws(
        () => resolvePerMessageDeflate({ maxInflatedBytes: bad as number }),
        RangeError,
        `expected RangeError for cap ${JSON.stringify(bad)}`
      );
    }
  });

  it("surfaces through resolveInboundWsOptions", () => {
    assert.deepEqual(
      resolveInboundWsOptions({ permessageDeflate: { maxInflatedBytes: 4096 } })
        .permessageDeflate,
      { thresholdBytes: 1024, maxInflatedBytes: 4096 }
    );
    assert.throws(
      () => resolveInboundWsOptions({ permessageDeflate: { maxInflatedBytes: 0 } }),
      RangeError
    );
  });
});

// --- raw RFC 6455 test client (zero dependencies) -----------------------------

const relays: Server[] = [];

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

interface ServerFrame {
  opcode: number;
  payload: Buffer;
}

/** Client→server frame with RSV1 control. Always masked. */
function clientFrame(opcode: number, payload: Buffer, rsv1 = false): Buffer {
  const b0 = 0x80 | (rsv1 ? 0x40 : 0) | opcode;
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

function wsConnect(
  port: number
): Promise<{ socket: Socket; nextFrame: () => Promise<ServerFrame> }> {
  return new Promise((resolve, reject) => {
    const socket = connect(port, "127.0.0.1");
    let buf = Buffer.alloc(0);
    let done = false;
    const request = [
      "GET /ingest/ws HTTP/1.1",
      "Host: 127.0.0.1",
      "Upgrade: websocket",
      "Connection: Upgrade",
      `Sec-WebSocket-Key: ${RFC_WS_KEY}`,
      "Sec-WebSocket-Version: 13",
      `Sec-WebSocket-Extensions: ${FULL_OFFER}`,
      "",
      "",
    ].join("\r\n");
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
      const status = Number(buf.subarray(0, idx).toString("latin1").split("\r\n")[0].split(" ")[1]);
      if (status !== 101) {
        done = true;
        clearTimeout(timer);
        socket.destroy();
        reject(new Error(`expected 101, got ${status}`));
        return;
      }
      done = true;
      clearTimeout(timer);
      socket.removeAllListeners("data");
      let rest = buf.subarray(idx + 4);
      const pending: Array<(f: ServerFrame) => void> = [];
      const queued: ServerFrame[] = [];
      socket.on("data", (d: Buffer) => {
        rest = Buffer.concat([rest, d]);
        for (;;) {
          if (rest.length < 2) break;
          const opcode = rest[0] & 0x0f;
          let len = rest[1] & 0x7f;
          let off = 2;
          if (len === 126) {
            if (rest.length < 4) break;
            len = rest.readUInt16BE(2);
            off = 4;
          } else if (len === 127) {
            if (rest.length < 10) break;
            len = Number(rest.readBigUInt64BE(2));
            off = 10;
          }
          // The server never masks (RFC 6455 §5.3).
          if (rest.length < off + len) break;
          const frame = { opcode, payload: rest.subarray(off, off + len) };
          rest = rest.subarray(off + len);
          const waiter = pending.shift();
          if (waiter !== undefined) waiter(frame);
          else queued.push(frame);
        }
      });
      socket.on("error", () => {});
      const nextFrame = (): Promise<ServerFrame> =>
        new Promise((res, rej) => {
          const q = queued.shift();
          if (q !== undefined) {
            res(q);
            return;
          }
          const t = setTimeout(() => rej(new Error("frame timeout")), 10000);
          pending.push((f) => {
            clearTimeout(t);
            res(f);
          });
        });
      resolve({ socket, nextFrame });
    });
    socket.on("error", (err) => {
      if (!done) {
        done = true;
        clearTimeout(timer);
        reject(err);
      }
    });
    socket.write(request);
  });
}

/** One signed event envelope, shaped like a WR-61 batch item. */
function envelope(payload: unknown): string {
  const raw = Buffer.from(JSON.stringify(payload));
  return JSON.stringify({
    payload: raw.toString("base64"),
    headers: { "x-signature": signSha256(raw, TEST_KEY) },
  });
}

function makeRelay(maxInflatedBytes: number): Promise<{ port: number; audit: AuditLog }> {
  const dir = mkdtempSync(join(tmpdir(), "audit-ws-inflate-bomb-"));
  const audit = new AuditLog(join(dir, "audit.jsonl"));
  const relay = createRelayServer({
    secret: TEST_KEY,
    forwardUrl: "http://127.0.0.1:1/unused",
    auditLog: audit,
    sender: async (_item: RetryItem) => undefined,
    retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 3 },
    inboundWs: { permessageDeflate: { maxInflatedBytes } },
  });
  relays.push(relay);
  return listen(relay).then((port) => ({ port, audit }));
}

// --- server behavior ----------------------------------------------------------

describe("inbound WS inflate bomb (WR-161, server)", () => {
  after(async () => {
    for (const r of relays.splice(0)) await closeRelay(r);
  });

  it("closes 1009 and audits rejected/ws_inflate_bomb on a bomb", async () => {
    const { port, audit } = await makeRelay(4096);
    const client = await wsConnect(port);
    // 20k zero bytes ride tens of wire bytes — the classic bomb shape.
    const wire = await bombWire();
    client.socket.write(clientFrame(0x1, wire, true));
    const close = await client.nextFrame();
    assert.equal(close.opcode, 0x8);
    assert.equal(close.payload.readUInt16BE(0), 1009);
    const rejected = audit.query({ event: "rejected" }) as Record<string, unknown>[];
    const bomb = rejected.find((e) => e.reason === "ws_inflate_bomb");
    assert.ok(bomb, "expected a rejected audit event with reason ws_inflate_bomb");
    client.socket.destroy();
  });

  it("still accepts a legal compressed message within the cap", async () => {
    const { port } = await makeRelay(4096);
    const client = await wsConnect(port);
    const body = envelope({ data: "x".repeat(2000) });
    assert.ok(Buffer.byteLength(body) < 4096, "fixture must stay under the test cap");
    const compressed = await compressMessage(Buffer.from(body, "utf8"));
    client.socket.write(clientFrame(0x1, compressed, true));
    const ack = await client.nextFrame();
    assert.equal(ack.opcode, 0x1);
    const parsed = JSON.parse(ack.payload.toString("utf8"));
    assert.equal(parsed.type, "event-ack");
    assert.equal(parsed.status, "accepted");
    client.socket.destroy();
  });
});
