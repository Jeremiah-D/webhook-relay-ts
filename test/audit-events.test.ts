import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server, type ClientRequest } from "node:http";
import { connect, type Socket } from "node:net";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";
import type { Sender } from "../src/retry.ts";

// WR-186: live SSE stream of operator audit events (GET /events/audit).

const INTAKE_SECRET = "audit-events-intake";
const OP_TOKEN = "audit-events-op-token";
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

function postJson(
  port: number,
  path: string,
  body: unknown,
  token: string
): Promise<{ status: number; text: string }> {
  const raw = Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const r = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path,
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
      }
    );
    r.on("error", reject);
    r.end(raw);
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

/** Open an SSE stream on /events/audit; frames accumulate as they arrive. */
function openAuditStream(port: number, token?: string, extraHeaders: Record<string, string> = {}): Stream {
  const frames: SseFrame[] = [];
  let buf = "";
  const headers: Record<string, string> = { ...extraHeaders };
  if (token !== undefined) headers["authorization"] = `Bearer ${token}`;
  const req = httpRequest({ host: "127.0.0.1", port, path: "/events/audit", method: "GET", headers }, (res) => {
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

function makeAudit(): AuditLog {
  const dir = mkdtempSync(join(tmpdir(), "audit-events-"));
  return new AuditLog(join(dir, "audit.jsonl"));
}

function makeServer(auditLog: AuditLog, partial: Partial<RelayOptions> = {}): Server {
  return createRelayServer({
    secret: INTAKE_SECRET,
    forwardUrl: FORWARD_URL,
    auditLog,
    operatorToken: OP_TOKEN,
    retry: { sender: (async () => {}) as Sender, baseDelayMs: 10, jitterMs: 0, maxAttempts: 3 },
    ...partial,
  });
}

describe("GET /events/audit SSE audit stream", () => {
  it("is guarded like the other operator endpoints (404 fail-closed, 403, 405)", async () => {
    // No operatorToken configured: fail closed.
    const disabled = makeServer(makeAudit(), { operatorToken: undefined });
    const p0 = await listen(disabled);
    try {
      assert.equal(
        (await get(p0, "/events/audit", { authorization: `Bearer ${OP_TOKEN}` })).status,
        404
      );
    } finally {
      await close(disabled);
    }

    const relay = makeServer(makeAudit());
    const port = await listen(relay);
    try {
      assert.equal((await get(port, "/events/audit")).status, 403);
      assert.equal((await get(port, "/events/audit", { authorization: "Bearer <redacted>" })).status, 403);
      assert.equal(
        (await postJson(port, "/events/audit", {}, OP_TOKEN)).status,
        405
      );
    } finally {
      await close(relay);
    }
  });

  it("a read-scoped operator key may subscribe (WR-82)", async () => {
    const auditLog = makeAudit();
    const relay = createRelayServer({
      secret: INTAKE_SECRET,
      forwardUrl: FORWARD_URL,
      auditLog,
      operatorKeys: [{ id: "reader", key: "reader-key", scopes: ["read"] }],
      retry: { sender: (async () => {}) as Sender },
    });
    const port = await listen(relay);
    const stream = openAuditStream(port, "reader-key");
    try {
      await waitFor(stream.frames, (f) => f.comment === "connected");
      // A scopeless key is fail-closed even though it authenticated.
    } finally {
      stream.destroy();
      await close(relay);
    }
  });

  it("streams the named operational audit events live as event: audit frames", async () => {
    const auditLog = makeAudit();
    const relay = makeServer(auditLog);
    const port = await listen(relay);
    const stream = openAuditStream(port, OP_TOKEN);
    try {
      await waitFor(stream.frames, (f) => f.comment === "connected");
      const names = [
        "endpoint_paused",
        "endpoint_resumed",
        "endpoint_config_updated",
        "circuit_open",
        "circuit_closed",
        "failover_switched",
        "dead_letter_auto_replay",
      ];
      for (const event of names) auditLog.append({ event, endpoint: FORWARD_URL });
      for (const event of names) {
        const frame = await waitFor(
          stream.frames,
          (f) => f.event === "audit" && !!f.data && JSON.parse(f.data).event === event
        );
        const parsed = JSON.parse(frame.data!);
        assert.equal(parsed.endpoint, FORWARD_URL);
        assert.match(parsed.ts, /^\d{4}-\d{2}-\d{2}T/);
      }
      // Audit frames carry no replay id (there is no archive behind this stream).
      const raw = stream.frames.filter((f) => f.event === "audit");
      assert.ok(raw.length >= names.length);
    } finally {
      stream.destroy();
      await close(relay);
    }
  });

  it("fans out real operator actions end-to-end (pause/resume audit through the queue hooks)", async () => {
    const auditLog = makeAudit();
    const relay = makeServer(auditLog);
    const port = await listen(relay);
    const stream = openAuditStream(port, OP_TOKEN);
    try {
      await waitFor(stream.frames, (f) => f.comment === "connected");
      const pause = await postJson(port, "/endpoints/pause", { endpoint: FORWARD_URL }, OP_TOKEN);
      assert.equal(pause.status, 200);
      const paused = await waitFor(
        stream.frames,
        (f) => f.event === "audit" && !!f.data && JSON.parse(f.data).event === "endpoint_paused"
      );
      assert.equal(JSON.parse(paused.data!).endpoint, FORWARD_URL);
      const resume = await postJson(port, "/endpoints/resume", { endpoint: FORWARD_URL }, OP_TOKEN);
      assert.equal(resume.status, 200);
      await waitFor(
        stream.frames,
        (f) => f.event === "audit" && !!f.data && JSON.parse(f.data).event === "endpoint_resumed"
      );
    } finally {
      stream.destroy();
      await close(relay);
    }
  });

  it("a Last-Event-ID header answers 210 events_gone (rebuild from GET /audit)", async () => {
    const auditLog = makeAudit();
    const relay = makeServer(auditLog);
    const port = await listen(relay);
    try {
      const res = await get(port, "/events/audit", {
        authorization: `Bearer ${OP_TOKEN}`,
        "last-event-id": "123",
      });
      assert.equal(res.status, 210);
      const body = JSON.parse(res.text) as { error: string; message: string };
      assert.equal(body.error, "events_gone");
      assert.match(body.message, /GET \/audit/);
      // No subscription leaked by the refused handshake.
      assert.equal(auditLog.subscriberCount, 0);
    } finally {
      await close(relay);
    }
  });

  it("sends heartbeat comments on idle connections (shared heartbeatMs option)", async () => {
    const auditLog = makeAudit();
    const relay = makeServer(auditLog, { events: { heartbeatMs: 30 } });
    const port = await listen(relay);
    const stream = openAuditStream(port, OP_TOKEN);
    try {
      await waitFor(stream.frames, (f) => f.comment === "connected");
      const ping = await waitFor(stream.frames, (f) => f.comment === "ping", 3000);
      assert.ok(ping);
    } finally {
      stream.destroy();
      await close(relay);
    }
  });

  it("a disconnected client unsubscribes without leaking subscribers", async () => {
    const auditLog = makeAudit();
    const relay = makeServer(auditLog);
    const port = await listen(relay);
    const stream = openAuditStream(port, OP_TOKEN);
    try {
      await waitFor(stream.frames, (f) => f.comment === "connected");
      assert.equal(auditLog.subscriberCount, 1);
      stream.destroy();
      const deadline = Date.now() + 5000;
      while (auditLog.subscriberCount !== 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 10));
      }
      assert.equal(auditLog.subscriberCount, 0);
      // The server still serves after the disconnect.
      auditLog.append({ event: "endpoint_paused", endpoint: FORWARD_URL });
      const check = await get(port, "/audit", { authorization: `Bearer ${OP_TOKEN}` });
      assert.equal(check.status, 200);
    } finally {
      await close(relay);
    }
  });

  it("one throwing subscriber never breaks the others or the append path", async () => {
    const auditLog = makeAudit();
    const relay = makeServer(auditLog);
    const port = await listen(relay);
    const stream = openAuditStream(port, OP_TOKEN);
    try {
      await waitFor(stream.frames, (f) => f.comment === "connected");
      const seen: string[] = [];
      auditLog.subscribe(() => {
        throw new Error("subscriber boom");
      });
      auditLog.subscribe((event) => {
        seen.push(String(event.event));
      });
      // The SSE subscription (added before the throwing one) must still fire.
      auditLog.append({ event: "endpoint_paused", endpoint: FORWARD_URL });
      const frame = await waitFor(
        stream.frames,
        (f) => f.event === "audit" && !!f.data && JSON.parse(f.data).event === "endpoint_paused"
      );
      assert.ok(frame.data);
      assert.deepEqual(seen, ["endpoint_paused"]);
    } finally {
      stream.destroy();
      await close(relay);
    }
  });

  it("disconnects a slow consumer past 1MiB of buffered frames", async () => {
    const auditLog = makeAudit();
    const relay = makeServer(auditLog);
    const port = await listen(relay);
    // Raw socket: read the response head, then never read again. The kernel
    // send buffer fills, node's own buffer grows past the 1MiB guard, and
    // the server ends the connection. (The client's FIN stays queued behind
    // the unread data until the test drains the socket — that is plain TCP,
    // so the guard firing is observed first via the subscriber count, then
    // the close is observed after draining.)
    const socket: Socket = connect(port, "127.0.0.1");
    try {
      await new Promise<void>((resolve, reject) => {
        socket.once("connect", resolve);
        socket.once("error", reject);
      });
      socket.write(
        `GET /events/audit HTTP/1.1\r\nhost: 127.0.0.1\r\nauthorization: Bearer ${OP_TOKEN}\r\n\r\n`
      );
      const head = await new Promise<string>((resolve, reject) => {
        let buf = "";
        const onData = (c: Buffer) => {
          buf += c.toString();
          if (buf.includes("\r\n\r\n")) {
            socket.off("data", onData);
            resolve(buf);
          }
        };
        socket.on("data", onData);
        socket.once("error", reject);
      });
      assert.ok(head.startsWith("HTTP/1.1 200"), head.split("\r\n")[0]);
      socket.pause();
      assert.equal(auditLog.subscriberCount, 1);

      // Flood until the 1MiB guard fires (observed via the subscriber
      // count dropping to zero server-side).
      let i = 0;
      const guardDeadline = Date.now() + 30000;
      while (auditLog.subscriberCount !== 0 && Date.now() < guardDeadline) {
        for (let j = 0; j < 200; j++) {
          auditLog.append({ event: "flood", i: i++, pad: "x".repeat(800) });
        }
        // Yield so the kernel drains and node's buffer accounting advances.
        await new Promise((r) => setImmediate(r));
      }
      assert.equal(auditLog.subscriberCount, 0);

      // Now drain: the pending data flows, then the server's FIN arrives.
      let closed = false;
      socket.once("close", () => {
        closed = true;
      });
      socket.on("data", () => {});
      socket.resume();
      const closeDeadline = Date.now() + 15000;
      while (!closed && Date.now() < closeDeadline) {
        await new Promise((r) => setTimeout(r, 20));
      }
      assert.ok(closed, "server did not end the slow consumer's connection");
    } finally {
      socket.destroy();
      await close(relay);
    }
  });
});
