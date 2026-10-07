import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server, type ClientRequest } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import type { Sender } from "../src/retry.ts";

const SECRET = "sse-secret";
const TOKEN = "op-token";
const BODY = Buffer.from(JSON.stringify({ event: "payment.succeeded" }));
const FORWARD_URL = "http://127.0.0.1:1/hook"; // never called; the sender is injected

type RelayOptions = Parameters<typeof createRelayServer>[0];

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

async function close(server: Server): Promise<void> {
  server.close();
  await new Promise((r) => server.once("close", r));
}

function post(port: number, path: string, body: Buffer, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method: "POST", headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
    });
    r.on("error", reject);
    r.end(body);
  });
}

function get(port: number, path: string, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method: "GET", headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
    });
    r.on("error", reject);
    r.end();
  });
}

interface SseFrame {
  event?: string;
  data?: string;
  comment?: string;
}

interface Stream {
  req: ClientRequest;
  frames: SseFrame[];
  destroy: () => void;
}

/** Open an SSE stream; frames accumulate in `frames` as they arrive. */
function openStream(port: number, token?: string): Stream {
  const frames: SseFrame[] = [];
  let buf = "";
  const headers: Record<string, string> = {};
  if (token !== undefined) headers["authorization"] = `Bearer ${token}`;
  const req = httpRequest({ host: "127.0.0.1", port, path: "/events", method: "GET", headers }, (res) => {
    res.on("data", (c: Buffer) => {
      buf += c.toString();
      let idx: number;
      while ((idx = buf.indexOf("\n\n")) >= 0) {
        const raw = buf.slice(0, idx);
        buf = buf.slice(idx + 2);
        const frame: SseFrame = {};
        for (const line of raw.split("\n")) {
          if (line.startsWith(":")) frame.comment = line.slice(1).trim();
          else if (line.startsWith("event:")) frame.event = line.slice(6).trim();
          else if (line.startsWith("data:")) frame.data = line.slice(5).trim();
        }
        frames.push(frame);
      }
    });
  });
  req.on("error", () => {});
  req.end();
  return { req, frames, destroy: () => req.destroy() };
}

async function waitFor(
  frames: SseFrame[],
  pred: (f: SseFrame) => boolean,
  timeoutMs = 5000
): Promise<SseFrame> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const hit = frames.find(pred);
    if (hit) return hit;
    await new Promise((r) => setTimeout(r, 10));
  }
  throw new Error("timed out waiting for SSE frame");
}

function makeServer(partial: Partial<RelayOptions> & { sender: Sender }): Server {
  const dir = mkdtempSync(join(tmpdir(), "sse-audit-"));
  const { sender, ...rest } = partial;
  return createRelayServer({
    secret: SECRET,
    forwardUrl: FORWARD_URL,
    auditLog: new AuditLog(join(dir, "audit.jsonl")),
    operatorToken: TOKEN,
    ...rest,
    retry: { sender, baseDelayMs: 10, jitterMs: 0, maxAttempts: 3, ...(rest.retry ?? {}) },
  });
}

async function acceptOne(port: number): Promise<string> {
  const res = await post(port, "/", BODY, { "x-signature": signSha256(BODY, SECRET) });
  assert.equal(res.status, 202);
  return (JSON.parse(res.text) as { id: string }).id;
}

describe("sse delivery stream", () => {
  it("is guarded like the other operator endpoints", async () => {
    const dir = mkdtempSync(join(tmpdir(), "sse-audit-"));
    const disabled = createRelayServer({
      secret: SECRET,
      forwardUrl: FORWARD_URL,
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      retry: { sender: async () => {} },
    });
    const p0 = await listen(disabled);
    try {
      // No operatorToken configured: fail closed.
      assert.equal((await get(p0, "/events", { authorization: `Bearer ${TOKEN}` })).status, 404);
    } finally {
      await close(disabled);
    }

    const relay = makeServer({ sender: async () => {} });
    const port = await listen(relay);
    try {
      assert.equal((await get(port, "/events")).status, 403);
      assert.equal((await get(port, "/events", { authorization: "Bearer wrong" })).status, 403);
      assert.equal(
        (await post(port, "/events", Buffer.alloc(0), { authorization: `Bearer ${TOKEN}` })).status,
        405
      );
    } finally {
      await close(relay);
    }
  });

  it("streams delivered events with the delivery id", async () => {
    const relay = makeServer({ sender: async () => {} });
    const port = await listen(relay);
    const stream = openStream(port, TOKEN);
    try {
      const id = await acceptOne(port);
      const frame = await waitFor(stream.frames, (f) => f.event === "delivery" && !!f.data);
      const evt = JSON.parse(frame.data!);
      assert.equal(evt.type, "delivered");
      assert.equal(evt.id, id);
      assert.equal(evt.attempts, 1);
      assert.equal(evt.targetUrl, FORWARD_URL);
      assert.match(evt.at, /^\d{4}-\d{2}-\d{2}T/);
      assert.equal(evt.error, undefined);
    } finally {
      stream.destroy();
      await close(relay);
    }
  });

  it("streams retrying then dead_letter on persistent failure", async () => {
    const relay = makeServer({
      sender: async () => {
        throw new Error("downstream boom");
      },
      retry: { maxAttempts: 2 },
    });
    const port = await listen(relay);
    const stream = openStream(port, TOKEN);
    try {
      const id = await acceptOne(port);
      const retrying = await waitFor(
        stream.frames,
        (f) => !!f.data && JSON.parse(f.data).type === "retrying"
      );
      const r = JSON.parse(retrying.data!);
      assert.equal(r.id, id);
      assert.equal(r.attempts, 1);
      assert.equal(r.error, "downstream boom");
      const dead = await waitFor(
        stream.frames,
        (f) => !!f.data && JSON.parse(f.data).type === "dead_letter"
      );
      const d = JSON.parse(dead.data!);
      assert.equal(d.id, id);
      assert.equal(d.attempts, 2);
      assert.equal(d.error, "downstream boom");
    } finally {
      stream.destroy();
      await close(relay);
    }
  });

  it("sends heartbeat comments on idle connections", async () => {
    const relay = makeServer({ sender: async () => {}, events: { heartbeatMs: 30 } });
    const port = await listen(relay);
    const stream = openStream(port, TOKEN);
    try {
      // The opening comment arrives first.
      await waitFor(stream.frames, (f) => f.comment === "connected");
      const ping = await waitFor(stream.frames, (f) => f.comment === "ping", 3000);
      assert.ok(ping);
    } finally {
      stream.destroy();
      await close(relay);
    }
  });

  it("a disconnected client stops receiving without breaking the server", async () => {
    const relay = makeServer({ sender: async () => {} });
    const port = await listen(relay);
    const dead = openStream(port, TOKEN);
    const live = openStream(port, TOKEN);
    try {
      await waitFor(dead.frames, (f) => f.comment === "connected");
      await waitFor(live.frames, (f) => f.comment === "connected");
      dead.destroy();
      // Give the server a beat to observe the disconnect and clean up.
      await new Promise((r) => setTimeout(r, 100));
      await acceptOne(port);
      const frame = await waitFor(live.frames, (f) => f.event === "delivery");
      assert.ok(frame.data);
      // The dead stream got nothing after it was destroyed.
      assert.ok(!dead.frames.some((f) => f.event === "delivery"));
    } finally {
      live.destroy();
      await close(relay);
    }
  });
});
