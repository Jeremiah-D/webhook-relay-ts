import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer, DEFAULT_MAX_BODY_BYTES } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const SECRET = "relay-secret";
const MAX = 32; // tiny budget so tests stay small

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function post(port: number, body: Buffer, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path: "/", method: "POST", headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
    });
    r.on("error", reject);
    r.end(body);
  });
}

// Sends a declared Content-Length bigger than the body actually written:
// the server must reject before the (tiny) body even matters.
function postWithDeclaredLength(
  port: number,
  declaredLength: number,
  body: Buffer,
  headers: Record<string, string> = {}
) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path: "/", method: "POST", headers: { ...headers, "content-length": String(declaredLength) } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          r.destroy();
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() });
        });
      }
    );
    r.on("error", reject);
    r.write(body); // deliberately short of the declared length
  });
}

function readRejectedReasons(dir: string): string[] {
  const audit = new AuditLog(join(dir, "audit.jsonl"));
  return (audit.readAll() as Array<Record<string, unknown>>)
    .filter((e) => e.event === "rejected")
    .map((e) => String(e.reason));
}

describe("WR-25 inbound body size limit", () => {
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
    return createRelayServer({
      secret: SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      maxBodyBytes: MAX,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
      ...extra,
    });
  }

  it("rejects a body past the Content-Length pre-check with 413", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bodylimit-"));
    const server = relay(dir);
    const port = await listen(server);
    try {
      const body = Buffer.from("tiny");
      const res = await postWithDeclaredLength(port, MAX + 1, body, {
        "x-signature": signSha256(body, SECRET),
      });
      assert.equal(res.status, 413);
      assert.ok(readRejectedReasons(dir).includes("body_too_large"));
    } finally {
      server.close();
      await new Promise((r) => server.once("close", r));
    }
  });

  it("caps a chunked body while streaming with 413", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bodylimit-"));
    const server = relay(dir);
    const port = await listen(server);
    try {
      const body = Buffer.alloc(MAX + 1, "a"); // no content-length -> chunked
      const res = await post(port, body, { "x-signature": signSha256(body, SECRET) });
      assert.equal(res.status, 413);
      assert.ok(readRejectedReasons(dir).includes("body_too_large"));
    } finally {
      server.close();
      await new Promise((r) => server.once("close", r));
    }
  });

  it("accepts a body exactly at the limit", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bodylimit-"));
    const server = relay(dir);
    const port = await listen(server);
    try {
      const body = Buffer.alloc(MAX, "a");
      const res = await post(port, body, { "x-signature": signSha256(body, SECRET) });
      assert.equal(res.status, 202);
      assert.ok(!readRejectedReasons(dir).includes("body_too_large"));
    } finally {
      server.close();
      await new Promise((r) => server.once("close", r));
    }
  });

  it("never lets an unparseable Content-Length bypass the budget (Node parser rejects it)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bodylimit-"));
    const server = relay(dir);
    const port = await listen(server);
    try {
      const body = Buffer.from("ok");
      const res = await post(port, body, {
        "x-signature": signSha256(body, SECRET),
        "content-length": "not-a-number",
      });
      // Node's own HTTP parser answers 400 before the handler runs: an
      // unparseable Content-Length can never smuggle a giant body past
      // the pre-check.
      assert.equal(res.status, 400);
      assert.ok(!readRejectedReasons(dir).includes("body_too_large"));
    } finally {
      server.close();
      await new Promise((r) => server.once("close", r));
    }
  });

  it("rejects invalid maxBodyBytes with RangeError at startup", () => {
    for (const bad of [0, -1, 1.5, Number.NaN]) {
      const dir = mkdtempSync(join(tmpdir(), "bodylimit-"));
      assert.throws(
        () =>
          createRelayServer({
            secret: SECRET,
            forwardUrl: "http://127.0.0.1:1/hook",
            auditLog: new AuditLog(join(dir, "audit.jsonl")),
            maxBodyBytes: bad,
          }),
        RangeError
      );
    }
  });

  it("defaults to a 1 MiB limit", () => {
    assert.equal(DEFAULT_MAX_BODY_BYTES, 1_048_576);
  });
});
