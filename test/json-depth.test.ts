import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  jsonDepth,
  checkJsonDepth,
  assertValidMaxJsonDepth,
  DEFAULT_MAX_JSON_DEPTH,
} from "../src/json-depth.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

/** `"[".repeat(n) + "]".repeat(n)` — a JSON body nested `n` levels deep. */
function nestedBody(n: number): Buffer {
  return Buffer.from("[".repeat(n) + "]".repeat(n));
}

function listen(server: Server): Promise<number> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve((server.address() as { port: number }).port);
    });
  });
}

function post(port: number, body: Buffer, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path: "/", method: "POST", headers },
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

describe("json-depth unit", () => {
  it("jsonDepth counts nested arrays and objects identically", () => {
    assert.equal(jsonDepth(42), 0);
    assert.equal(jsonDepth("s"), 0);
    assert.equal(jsonDepth(null), 0);
    assert.equal(jsonDepth([]), 1);
    assert.equal(jsonDepth({}), 1);
    assert.equal(jsonDepth([[]]), 2);
    assert.equal(jsonDepth({ a: { b: { c: 1 } } }), 3);
    assert.equal(jsonDepth([{ a: [{ b: 2 }] }]), 4);
    assert.equal(DEFAULT_MAX_JSON_DEPTH, 32);
  });

  it("checkJsonDepth skips non-JSON and scalar bodies", () => {
    assert.deepEqual(checkJsonDepth(Buffer.from("plain text"), 32), {
      skipped: true, depth: 0, ok: true,
    });
    assert.deepEqual(checkJsonDepth(Buffer.from("   "), 32), {
      skipped: true, depth: 0, ok: true,
    });
    assert.deepEqual(checkJsonDepth(Buffer.from("123"), 32), {
      skipped: true, depth: 0, ok: true,
    });
    // Malformed JSON starting with a container char: skipped, not a depth problem.
    assert.deepEqual(checkJsonDepth(Buffer.from("{oops"), 32), {
      skipped: true, depth: 0, ok: true,
    });
  });

  it("checkJsonDepth enforces the limit, boundary inclusive", () => {
    const at = checkJsonDepth(nestedBody(32), 32);
    assert.equal(at.skipped, false);
    assert.equal(at.depth, 32);
    assert.equal(at.ok, true);
    const over = checkJsonDepth(nestedBody(33), 32);
    assert.equal(over.depth, 33);
    assert.equal(over.ok, false);
  });

  it("checkJsonDepth treats a JSON.parse stack overflow as over-limit", () => {
    // 100k nesting levels blow V8's own JSON.parse stack budget —
    // the intake must reject, not crash.
    const bomb = checkJsonDepth(nestedBody(100000), 32);
    assert.equal(bomb.ok, false);
    assert.equal(bomb.skipped, false);
  });

  it("assertValidMaxJsonDepth rejects invalid values", () => {
    assert.throws(() => assertValidMaxJsonDepth(0), RangeError);
    assert.throws(() => assertValidMaxJsonDepth(-3), RangeError);
    assert.throws(() => assertValidMaxJsonDepth(1.5), RangeError);
    assert.throws(() => assertValidMaxJsonDepth("32"), RangeError);
    assert.throws(() => assertValidMaxJsonDepth(NaN), RangeError);
    assert.equal(assertValidMaxJsonDepth(32), 32);
  });
});

describe("server json depth gate", () => {
  it("rejects invalid maxJsonDepth at startup", () => {
    const dir = mkdtempSync(join(tmpdir(), "audit-depth-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    assert.throws(
      () =>
        createRelayServer({
          secret: "relay-secret",
          forwardUrl: "http://127.0.0.1:1/hook",
          auditLog: audit,
          maxJsonDepth: 0,
        }),
      RangeError
    );
  });

  it("answers 400 and audits json_too_deep for over-limit JSON", async () => {
    const stub: Server = createServer((_req, res) => res.writeHead(200).end("ok"));
    const stubPort = await listen(stub);
    const dir = mkdtempSync(join(tmpdir(), "audit-depth-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: "relay-secret",
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
    });
    const port = await listen(relay);
    try {
      let forwarded = 0;
      stub.on("request", () => { forwarded += 1; });
      const body = nestedBody(40);
      const res = await post(port, body, {
        "x-signature": signSha256(body, "relay-secret"),
        "content-type": "application/json",
      });
      assert.equal(res.status, 400);
      // Never forwarded: the stub saw nothing.
      await new Promise((r) => setTimeout(r, 300));
      assert.equal(forwarded, 0);
      const events = audit.readAll() as Array<Record<string, unknown>>;
      const rejected = events.filter(
        (e) => e.event === "rejected" && e.reason === "json_too_deep"
      );
      assert.equal(rejected.length, 1);
      assert.equal(rejected[0].depth, 40);
      assert.equal(rejected[0].maxJsonDepth, 32);
      assert.ok(!events.some((e) => e.event === "accepted"));
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
      stub.close();
      await new Promise((r) => stub.once("close", r));
    }
  });

  it("accepts JSON at exactly the limit and non-JSON bodies", async () => {
    const stub: Server = createServer((_req, res) => res.writeHead(200).end("ok"));
    const stubPort = await listen(stub);
    const received: Buffer[] = [];
    stub.on("request", (req) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => received.push(Buffer.concat(chunks)));
    });
    const dir = mkdtempSync(join(tmpdir(), "audit-depth-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: "relay-secret",
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
    });
    const port = await listen(relay);
    try {
      const deep = nestedBody(32);
      const r1 = await post(port, deep, {
        "x-signature": signSha256(deep, "relay-secret"),
        "content-type": "application/json",
      });
      assert.equal(r1.status, 202);
      const text = Buffer.from("not json at all");
      const r2 = await post(port, text, {
        "x-signature": signSha256(text, "relay-secret"),
        "content-type": "text/plain",
      });
      assert.equal(r2.status, 202);
      const deadline = Date.now() + 5000;
      while (received.length < 2 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(received.length, 2);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
      stub.close();
      await new Promise((r) => stub.once("close", r));
    }
  });

  it("honors a custom maxJsonDepth", async () => {
    const stub: Server = createServer((_req, res) => res.writeHead(200).end("ok"));
    const stubPort = await listen(stub);
    const dir = mkdtempSync(join(tmpdir(), "audit-depth-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: "relay-secret",
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      maxJsonDepth: 5,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
    });
    const port = await listen(relay);
    try {
      const body = nestedBody(6);
      const res = await post(port, body, {
        "x-signature": signSha256(body, "relay-secret"),
        "content-type": "application/json",
      });
      assert.equal(res.status, 400);
      const events = audit.readAll() as Array<Record<string, unknown>>;
      const rejected = events.find(
        (e) => e.event === "rejected" && e.reason === "json_too_deep"
      ) as Record<string, unknown>;
      assert.ok(rejected);
      assert.equal(rejected.maxJsonDepth, 5);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
      stub.close();
      await new Promise((r) => stub.once("close", r));
    }
  });
});
