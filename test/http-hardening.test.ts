import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { connect } from "node:net";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import type { HttpHardeningOptions } from "../src/http-hardening.ts";

const hookSecret = "relay-secret";
const BODY = Buffer.from(JSON.stringify({ event: "payment.succeeded" }));

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

/**
 * Re-listen with a short connections sweep so Node's coarse
 * `connectionsCheckingInterval` (30s default) fires timeouts fast in
 * tests. `setupConnectionsTracking` re-reads
 * `server.connectionsCheckingInterval` on every 'listening' event.
 */
async function listenFastSweep(server: Server): Promise<number> {
  const port = await listen(server);
  (server as unknown as { connectionsCheckingInterval: number }).connectionsCheckingInterval = 50;
  await new Promise<void>((resolve, reject) => server.close((e) => (e ? reject(e) : resolve())));
  await new Promise<void>((resolve) => server.listen(port, "127.0.0.1", resolve));
  return port;
}

function relay(opts: { httpHardening?: HttpHardeningOptions; dir?: string }) {
  const dir = opts.dir ?? mkdtempSync(join(tmpdir(), "hardening-"));
  const audit = new AuditLog(join(dir, "audit.jsonl"));
  const server = createRelayServer({
    forwardUrl: "http://localhost:9999/hook",
    auditLog: audit,
    secret: hookSecret,
    httpHardening: opts.httpHardening,
    sender: async () => {},
  });
  return { server, dir };
}

function httpTimeoutReasons(dir: string): string[] {
  const audit = new AuditLog(join(dir, "audit.jsonl"));
  return (audit.readAll() as Array<Record<string, unknown>>)
    .filter((e) => e.event === "rejected" && e.reason === "http_timeout")
    .map(() => "http_timeout");
}

/** Raw-socket probe: writes chunks with delays, captures the first response bytes. */
function rawProbe(
  port: number,
  chunks: string[],
  delaysMs: number[],
  settleMs = 3000
): Promise<{ data: string }> {
  return new Promise((resolve) => {
    const sock = connect(port, "127.0.0.1");
    let data = "";
    let settled = false;
    const done = () => {
      if (!settled) {
        settled = true;
        sock.destroy();
        resolve({ data });
      }
    };
    sock.on("data", (d: Buffer) => {
      data += d.toString();
    });
    sock.on("close", done);
    sock.on("error", done);
    (async () => {
      for (let i = 0; i < chunks.length; i++) {
        await new Promise((r) => setTimeout(r, delaysMs[i] ?? 0));
        if (settled) return;
        sock.write(chunks[i]);
      }
    })();
    setTimeout(done, settleMs);
  });
}

async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((err?: Error) => (err ? reject(err) : resolve()));
  });
}

describe("WR-160 httpHardening config validation", () => {
  it("rejects negative timeouts", () => {
    assert.throws(
      () => relay({ httpHardening: { headersTimeoutMs: -1 } }),
      (err: unknown) => err instanceof RangeError
    );
    assert.throws(
      () => relay({ httpHardening: { requestTimeoutMs: -5 } }),
      (err: unknown) => err instanceof RangeError
    );
  });

  it("rejects non-integer timeouts", () => {
    assert.throws(
      () => relay({ httpHardening: { headersTimeoutMs: 1.5 } }),
      (err: unknown) => err instanceof RangeError
    );
  });

  it("rejects non-positive maxHeaderSizeBytes", () => {
    assert.throws(
      () => relay({ httpHardening: { maxHeaderSizeBytes: 0 } }),
      (err: unknown) => err instanceof RangeError
    );
  });

  it("rejects a non-object option", () => {
    assert.throws(
      () => relay({ httpHardening: "fast" as unknown as HttpHardeningOptions }),
      (err: unknown) => err instanceof RangeError
    );
  });

  it("rejects headersTimeoutMs > requestTimeoutMs (Node would swap them)", () => {
    assert.throws(
      () => relay({ httpHardening: { headersTimeoutMs: 5000, requestTimeoutMs: 1000 } }),
      (err: unknown) => err instanceof RangeError
    );
  });

  it("accepts explicit 0 timeouts (disable)", () => {
    const { server } = relay({
      httpHardening: { headersTimeoutMs: 0, requestTimeoutMs: 0 },
    });
    assert.equal(server.headersTimeout, 0);
    assert.equal(server.requestTimeout, 0);
  });

  it("an explicit requestTimeoutMs lowers the default headersTimeout like Node's constructor", () => {
    // Guards the C++ sweep's silent swap: without this, a body-stalled
    // request would time out at 60s instead of requestTimeoutMs.
    const { server } = relay({ httpHardening: { requestTimeoutMs: 5000 } });
    assert.equal(server.requestTimeout, 5000);
    assert.equal(server.headersTimeout, 5000);
  });
});

describe("WR-160 defaults are untouched without the option", () => {
  let server: Server;
  let port: number;

  before(async () => {
    ({ server } = relay({}));
    port = await listen(server);
  });

  after(async () => {
    await close(server);
  });

  it("keeps Node's default timeouts and adds no clientError listener", () => {
    assert.equal(server.headersTimeout, 60000);
    assert.equal(server.requestTimeout, 300000);
    assert.equal(server.listenerCount("clientError"), 0);
  });

  it("still serves webhooks normally", async () => {
    const status = await new Promise<number>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/",
          method: "POST",
          headers: { "x-signature": signSha256(BODY, hookSecret) },
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve(res.statusCode ?? 0));
        }
      );
      r.on("error", reject);
      r.end(BODY);
    });
    assert.equal(status, 202);
  });
});

describe("WR-160 oversized headers are answered 431", () => {
  let server: Server;
  let port: number;

  before(async () => {
    ({ server } = relay({ httpHardening: { maxHeaderSizeBytes: 512 } }));
    port = await listen(server);
  });

  after(async () => {
    await close(server);
  });

  it("answers 431 and closes the connection", async () => {
    const { data } = await rawProbe(
      port,
      [`GET / HTTP/1.1\r\nHost: x\r\nX-Big: ${"a".repeat(2000)}\r\n\r\n`],
      [0]
    );
    assert.match(data, /^HTTP\/1\.1 431 /);
  });

  it("normal-sized headers still pass", async () => {
    const { data } = await rawProbe(
      port,
      [`POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n`],
      [0]
    );
    // No webhook signature → 401 from the intake gates, which proves the
    // request reached the handler (not rejected at the parser).
    assert.match(data, /^HTTP\/1\.1 401 /);
  });
});

describe("WR-160 slow headers are answered 408 and audited", () => {
  let server: Server;
  let port: number;
  let dir: string;

  before(async () => {
    ({ server, dir } = relay({ httpHardening: { headersTimeoutMs: 300 } }));
    port = await listenFastSweep(server);
  });

  after(async () => {
    await close(server);
  });

  it("installs the timeout and the clientError audit hook", () => {
    assert.equal(server.headersTimeout, 300);
    assert.equal(server.listenerCount("clientError"), 1);
  });

  it("answers 408 and audits rejected/http_timeout", async () => {
    const { data } = await rawProbe(port, [`POST / HTTP/1.1\r\nHost: x\r\n`], [0]);
    assert.match(data, /^HTTP\/1\.1 408 /);
    // The audit line is appended synchronously in the clientError
    // handler, before the 408 is written — it must be on disk now.
    assert.deepEqual(httpTimeoutReasons(dir), ["http_timeout"]);
  });
});

describe("WR-160 slow bodies are answered 408 and audited", () => {
  let server: Server;
  let port: number;
  let dir: string;

  before(async () => {
    ({ server, dir } = relay({ httpHardening: { requestTimeoutMs: 300 } }));
    port = await listenFastSweep(server);
  });

  after(async () => {
    await close(server);
  });

  it("answers 408 and audits rejected/http_timeout", async () => {
    // runIntakeGates reads the body before signature verification, so a
    // stalled body blocks the handler and the server-level requestTimeout
    // fires (the signature value is irrelevant — the body never completes).
    const { data } = await rawProbe(
      port,
      [`POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\nX-Signature: deadbeef\r\n\r\nhello`],
      [0]
    );
    assert.match(data, /^HTTP\/1\.1 408 /);
    assert.deepEqual(httpTimeoutReasons(dir), ["http_timeout"]);
  });

  it("a fast complete request is unaffected", async () => {
    const status = await new Promise<number>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/",
          method: "POST",
          headers: { "x-signature": signSha256(BODY, hookSecret) },
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve(res.statusCode ?? 0));
        }
      );
      r.on("error", reject);
      r.end(BODY);
    });
    assert.equal(status, 202);
  });
});

describe("WR-160 hardening applies to the split-plane operator listener", () => {
  it("sets timeouts and the audit hook on both listeners", async () => {
    const dir = mkdtempSync(join(tmpdir(), "hardening-split-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const srv = createRelayServer({
      forwardUrl: "http://localhost:9999/hook",
      auditLog: audit,
      secret: hookSecret,
      operatorToken: "op-token",
      operatorPort: { port: 0 },
      httpHardening: { headersTimeoutMs: 5000, requestTimeoutMs: 10000 },
      sender: async () => {},
    });
    const op = (srv as { operatorServer?: Server }).operatorServer;
    assert.ok(op);
    try {
      await listen(srv);
      assert.equal(srv.headersTimeout, 5000);
      assert.equal(srv.requestTimeout, 10000);
      assert.equal(op.headersTimeout, 5000);
      assert.equal(op.requestTimeout, 10000);
      assert.equal(op.listenerCount("clientError"), 1);
    } finally {
      const opClosed =
        op.listening
          ? new Promise<void>((resolve) => op.once("close", () => resolve()))
          : Promise.resolve();
      await close(srv);
      await opClosed;
    }
  });
});
