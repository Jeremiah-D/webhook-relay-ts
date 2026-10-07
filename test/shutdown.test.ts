import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type RetryItem } from "../src/retry.ts";
import { installGracefulShutdown, type ShutdownEvent } from "../src/shutdown.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const SECRET = "relay-secret";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));

function item(id: string): RetryItem {
  return { id, payload: BODY, targetUrl: "http://127.0.0.1:1/hook", headers: {} };
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function poll(cond: () => boolean, timeoutMs = 3000): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > timeoutMs) throw new Error("poll timed out");
    await sleep(5);
  }
}

function post(port: number, path: string, body: Buffer, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path, method: "POST", headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
      }
    );
    r.on("error", reject);
    r.end(body);
  });
}

describe("RetryQueue.shutdown", () => {
  it("waits for an in-flight delivery to settle, then reports drained", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const q = new RetryQueue({ sender: async () => gate, jitterMs: 0 });
    q.start();
    q.enqueue(item("a"));
    await poll(() => q.inFlightCount() === 1);

    let settled: boolean | undefined;
    const done = q.shutdown(5000).then((ok) => (settled = ok));
    await sleep(30);
    assert.equal(settled, undefined, "shutdown must not resolve while a delivery is in flight");
    release();
    assert.equal(await done, true);
    assert.equal(settled, true);
  });

  it("resolves true immediately when nothing is in flight", async () => {
    const q = new RetryQueue({ jitterMs: 0 });
    q.start();
    assert.equal(await q.shutdown(1000), true);
  });

  it("cancels pending backoff retries: no new attempts start after shutdown", async () => {
    let calls = 0;
    const q = new RetryQueue({
      sender: async () => {
        calls += 1;
        throw new Error("down");
      },
      baseDelayMs: 50,
      jitterMs: 0,
      maxAttempts: 5,
    });
    q.start();
    q.enqueue(item("a"));
    await poll(() => calls === 1);
    assert.equal(await q.shutdown(1000), true);
    await sleep(200);
    assert.equal(calls, 1, "retry timer must have been cancelled");
  });

  it("times out and reports false when a delivery hangs", async () => {
    const q = new RetryQueue({ sender: () => new Promise<void>(() => {}), jitterMs: 0 });
    q.start();
    q.enqueue(item("a"));
    await poll(() => q.inFlightCount() === 1);
    assert.equal(await q.shutdown(40), false);
  });

  it("does not hang on a delivery parked waiting for a concurrency slot", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const q = new RetryQueue({
      sender: async () => gate,
      jitterMs: 0,
      maxConcurrentPerEndpoint: 1,
    });
    q.start();
    q.enqueue(item("a"));
    q.enqueue(item("b"));
    await poll(() => q.inFlightCount() === 2); // second parks on the limiter
    const done = q.shutdown(5000);
    await sleep(20);
    release(); // first delivery finishes; the parked one bails out instead of hanging
    assert.equal(await done, true);
  });
});

describe("installGracefulShutdown", () => {
  it("stops accepting, drains, then exits 0 with events in order", async () => {
    const srv = createServer((_req, res) => res.writeHead(200).end("ok"));
    const port = await listen(srv);
    const events: ShutdownEvent["type"][] = [];
    const exits: number[] = [];
    let drainCalls = 0;
    const uninstall = installGracefulShutdown(
      srv,
      async () => {
        drainCalls += 1;
        return true;
      },
      {
        signals: ["SIGTERM"],
        exit: (code) => exits.push(code),
        onEvent: (e) => events.push(e.type),
      }
    );

    process.emit("SIGTERM");
    process.emit("SIGTERM"); // second signal is ignored
    await poll(() => exits.length > 0);

    assert.deepEqual(events, ["signal", "server-closed", "drained"]);
    assert.equal(drainCalls, 1);
    assert.deepEqual(exits, [0]);
    // The listener is closed: new connections are refused.
    await assert.rejects(
      post(port, "/", BODY),
      (err: unknown) => (err as NodeJS.ErrnoException).code === "ECONNREFUSED"
    );
    uninstall();
  });

  it("exits 1 when the drain times out", async () => {
    const srv = createServer((_req, res) => res.writeHead(200).end("ok"));
    await listen(srv);
    const exits: number[] = [];
    const uninstall = installGracefulShutdown(srv, async () => false, {
      signals: ["SIGTERM"],
      exit: (code) => exits.push(code),
    });
    process.emit("SIGTERM");
    await poll(() => exits.length > 0);
    assert.deepEqual(exits, [1]);
    uninstall();
  });

  it("lets an in-flight HTTP request finish before exiting", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const srv = createServer((_req, res) => {
      void gate.then(() => res.writeHead(200).end("done"));
    });
    const port = await listen(srv);
    const exits: number[] = [];
    const uninstall = installGracefulShutdown(srv, async () => true, {
      signals: ["SIGTERM"],
      exit: (code) => exits.push(code),
    });

    const reqPromise = post(port, "/", BODY, { connection: "close" });
    await sleep(30); // the request is now in flight, parked on the gate
    process.emit("SIGTERM");
    await sleep(30);
    assert.equal(exits.length, 0, "must not exit while a request is in flight");
    release();
    const res = await reqPromise;
    assert.equal(res.status, 200);
    assert.equal(res.text, "done");
    await poll(() => exits.length > 0);
    assert.deepEqual(exits, [0]);
    uninstall();
  });

  it("uninstall removes the signal listeners", async () => {
    const srv = createServer((_req, res) => res.writeHead(200).end("ok"));
    await listen(srv);
    const exits: number[] = [];
    const uninstall = installGracefulShutdown(srv, async () => true, {
      signals: ["SIGTERM"],
      exit: (code) => exits.push(code),
    });
    uninstall();
    process.emit("SIGTERM");
    await sleep(50);
    assert.equal(exits.length, 0);
    srv.close();
  });
});

describe("createRelayServer gracefulShutdown wiring", () => {
  it("drains in-flight deliveries on SIGTERM before exiting", async () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    let releaseSender!: () => void;
    const senderGate = new Promise<void>((r) => (releaseSender = r));
    let senderCalls = 0;
    const exits: number[] = [];
    const relay = createRelayServer({
      secret: SECRET,
      forwardUrl: "http://127.0.0.1:1/unused",
      auditLog: audit,
      sender: async () => {
        senderCalls += 1;
        await senderGate;
      }, // delivery stays in flight until released
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
      gracefulShutdown: { timeoutMs: 5000, exit: (code) => exits.push(code) },
    });
    const port = await listen(relay);

    const res = await post(port, "/", BODY, { "x-signature": signSha256(BODY, SECRET) });
    assert.equal(res.status, 202);
    await poll(() => senderCalls === 1); // the delivery is now in flight
    process.emit("SIGTERM");
    await sleep(30);
    assert.equal(exits.length, 0, "must not exit while a delivery is in flight");
    // New connections are refused once shutdown starts.
    await assert.rejects(post(port, "/", BODY, { "x-signature": signSha256(BODY, SECRET) }));

    releaseSender();
    await poll(() => exits.length > 0);
    assert.deepEqual(exits, [0], "drained shutdown exits 0");
    // The shutdown closed the server, which auto-uninstalled the listeners.
  });
});
