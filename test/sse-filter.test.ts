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

const SECRET = "sse-filter-secret";
const TOKEN = "op-token";
const URL_A = "http://127.0.0.1:1/hook"; // never called; the sender is injected
const URL_B = "http://127.0.0.1:1/other"; // never called; reached via content routing

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

function post(port: number, body: Buffer): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const r = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path: "/",
        method: "POST",
        headers: { "x-signature": signSha256(body, SECRET) },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
        );
      }
    );
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
  id?: string;
  event?: string;
  data?: string;
  comment?: string;
}

interface Stream {
  req: ClientRequest;
  frames: SseFrame[];
  destroy: () => void;
}

/** Open an SSE stream with an optional query string; frames accumulate as they arrive. */
function openStream(port: number, token: string | undefined, query = "", lastEventId?: string): Stream {
  const frames: SseFrame[] = [];
  let buf = "";
  const headers: Record<string, string> = {};
  if (token !== undefined) headers["authorization"] = `Bearer ${token}`;
  if (lastEventId !== undefined) headers["last-event-id"] = lastEventId;
  const req = httpRequest(
    { host: "127.0.0.1", port, path: `/events${query}`, method: "GET", headers },
    (res) => {
      res.on("data", (c: Buffer) => {
        buf += c.toString();
        let idx: number;
        while ((idx = buf.indexOf("\n\n")) >= 0) {
          const raw = buf.slice(0, idx);
          buf = buf.slice(idx + 2);
          const frame: SseFrame = {};
          for (const line of raw.split("\n")) {
            if (line.startsWith(":")) frame.comment = line.slice(1).trim();
            else if (line.startsWith("id:")) frame.id = line.slice(3).trim();
            else if (line.startsWith("event:")) frame.event = line.slice(6).trim();
            else if (line.startsWith("data:")) frame.data = line.slice(5).trim();
          }
          frames.push(frame);
        }
      });
    }
  );
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

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

function deliveryFrames(frames: SseFrame[]): SseFrame[] {
  return frames.filter((f) => f.event === "delivery");
}

function makeServer(partial: Partial<RelayOptions> & { sender: Sender }): Server {
  const dir = mkdtempSync(join(tmpdir(), "sse-filter-audit-"));
  const { sender, ...rest } = partial;
  return createRelayServer({
    secret: SECRET,
    forwardUrl: URL_A,
    auditLog: new AuditLog(join(dir, "audit.jsonl")),
    operatorToken: TOKEN,
    ...rest,
    retry: { sender, baseDelayMs: 10, jitterMs: 0, maxAttempts: 2, ...(rest.retry ?? {}) },
  });
}

const payload = (kind: string): Buffer => Buffer.from(JSON.stringify({ kind }));

const ROUTES = [
  {
    id: "b-route",
    matchers: [{ field: "kind", op: "equals" as const, value: "b" }],
    targetUrl: URL_B,
  },
];

describe("sse subscription filters (WR-162)", () => {
  it("answers 400 on an invalid ?event= value", async () => {
    const relay = makeServer({ sender: async () => {} });
    const port = await listen(relay);
    try {
      const res = await get(port, "/events?event=bogus", { authorization: `Bearer ${TOKEN}` });
      assert.equal(res.status, 400);
      assert.deepEqual(JSON.parse(res.text), { error: "invalid event" });
      // An empty value is also not one of the three kinds.
      const empty = await get(port, "/events?event=", { authorization: `Bearer ${TOKEN}` });
      assert.equal(empty.status, 400);
    } finally {
      await close(relay);
    }
  });

  it("?event= filters live frames by delivery-event kind", async () => {
    const relay = makeServer({
      sender: async () => {
        throw new Error("downstream boom");
      },
      retry: { maxAttempts: 2 },
    });
    const port = await listen(relay);
    const stream = openStream(port, TOKEN, "?event=retrying");
    try {
      await post(port, payload("a"));
      // The retrying frame arrives (attempt 1 fails with maxAttempts 2).
      const retrying = await waitFor(stream.frames, (f) => !!f.data);
      assert.equal(JSON.parse(retrying.data!).type, "retrying");
      // The dead_letter that follows (~10ms later) is filtered out: no
      // second delivery frame ever arrives.
      await sleep(500);
      const delivered = deliveryFrames(stream.frames);
      assert.equal(delivered.length, 1);
      assert.equal(JSON.parse(delivered[0].data!).type, "retrying");
    } finally {
      stream.destroy();
      await close(relay);
    }
  });

  it("?endpoint= matches the exact targetUrl only", async () => {
    const relay = makeServer({ sender: async () => {}, contentRoutes: ROUTES });
    const port = await listen(relay);
    const streamA = openStream(port, TOKEN, `?endpoint=${encodeURIComponent(URL_A)}`);
    try {
      await post(port, payload("a"));
      const f = await waitFor(streamA.frames, (fr) => fr.event === "delivery" && !!fr.data);
      assert.equal(JSON.parse(f.data!).targetUrl, URL_A);
      // The same stream never sees the URL_B delivery.
      await post(port, payload("b"));
      await sleep(400);
      const framesA = deliveryFrames(streamA.frames);
      assert.equal(framesA.length, 1);
      assert.equal(JSON.parse(framesA[0].data!).targetUrl, URL_A);
    } finally {
      streamA.destroy();
    }
    // A second stream scoped to URL_B sees only the b-delivery.
    const streamB = openStream(port, TOKEN, `?endpoint=${encodeURIComponent(URL_B)}`);
    try {
      await post(port, payload("b"));
      const f = await waitFor(streamB.frames, (fr) => fr.event === "delivery" && !!fr.data);
      assert.equal(JSON.parse(f.data!).targetUrl, URL_B);
      await sleep(400);
      assert.equal(deliveryFrames(streamB.frames).length, 1);
    } finally {
      streamB.destroy();
    }
    // A prefix that is not the exact URL matches nothing (no substring match).
    const streamPrefix = openStream(port, TOKEN, `?endpoint=${encodeURIComponent("http://127.0.0.1:1")}`);
    try {
      await post(port, payload("a"));
      await sleep(400);
      assert.equal(deliveryFrames(streamPrefix.frames).length, 0);
    } finally {
      streamPrefix.destroy();
      await close(relay);
    }
  });

  it("filters AND: ?event=dead_letter&endpoint= only passes matching dead_letters", async () => {
    const relay = makeServer({
      sender: async () => {
        throw new Error("downstream boom");
      },
      retry: { maxAttempts: 2 },
      contentRoutes: ROUTES,
    });
    const port = await listen(relay);
    const q = `?event=dead_letter&endpoint=${encodeURIComponent(URL_B)}`;
    const stream = openStream(port, TOKEN, q);
    try {
      // kind "a" -> URL_A: filtered by endpoint.
      await post(port, payload("a"));
      await sleep(300);
      // kind "b" -> URL_B: retrying filtered by event, dead_letter passes.
      await post(port, payload("b"));
      const dead = await waitFor(stream.frames, (f) => !!f.data);
      const evt = JSON.parse(dead.data!);
      assert.equal(evt.type, "dead_letter");
      assert.equal(evt.targetUrl, URL_B);
      await sleep(400);
      assert.equal(deliveryFrames(stream.frames).length, 1);
    } finally {
      stream.destroy();
      await close(relay);
    }
  });

  it("the Last-Event-ID replay path applies the same filters", async () => {
    const archiveDir = mkdtempSync(join(tmpdir(), "sse-filter-arch-"));
    const relay = makeServer({
      sender: async () => {
        throw new Error("downstream boom");
      },
      retry: { maxAttempts: 2 },
      eventArchive: { dir: archiveDir },
      events: { sseReplay: true },
    });
    const port = await listen(relay);
    try {
      // Archive: seq 1 = retrying, seq 2 = dead_letter.
      await post(port, payload("a"));
      for (;;) {
        const arch = await get(port, "/events/archive", { authorization: `Bearer ${TOKEN}` });
        assert.equal(arch.status, 200);
        if ((JSON.parse(arch.text) as unknown[]).length >= 2) break;
        await sleep(20);
      }
      // Reconnect from the start, scoped to dead_letter: only seq 2 replays.
      const stream = openStream(port, TOKEN, "?event=dead_letter", "0");
      try {
        const f = await waitFor(stream.frames, (fr) => fr.id === "2");
        assert.equal(JSON.parse(f.data!).type, "dead_letter");
        await sleep(400);
        const ids = deliveryFrames(stream.frames).map((fr) => fr.id);
        assert.deepEqual(ids, ["2"]);
      } finally {
        stream.destroy();
      }
    } finally {
      await close(relay);
    }
  });
});
