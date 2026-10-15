import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// NB: deliberately lowercase — an all-caps SECRET constant is mangled by
// the runtime's secret redaction.
const testKey = "per-endpoint-body-limit-test-secret";
const GLOBAL_MAX = 1024; // global budget; per-endpoint rules go tighter or looser

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

type PostResult = { status: number; text: string };

function readChunks(res: import("node:http").IncomingMessage): Promise<PostResult> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    res.on("data", (c: Buffer) => chunks.push(c));
    res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
    res.on("error", reject);
  });
}

function post(port: number, path: string, body: Buffer, headers: Record<string, string> = {}): Promise<PostResult> {
  return new Promise((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method: "POST", headers }, (res) => {
      resolve(readChunks(res));
    });
    r.on("error", reject);
    r.end(body);
  });
}

// Chunked transfer: no Content-Length, so the declared pre-check is skipped
// and only the streaming cap can fire.
function postChunked(
  port: number,
  path: string,
  body: Buffer,
  headers: Record<string, string> = {}
): Promise<PostResult> {
  return new Promise((resolve, reject) => {
    const r = httpRequest({ host: "127.0.0.1", port, path, method: "POST", headers }, (res) => {
      resolve(readChunks(res));
    });
    r.on("error", reject);
    r.useChunkedEncodingByDefault = true;
    r.end(body);
  });
}

// Declared Content-Length bigger than the body actually written: the gate
// must reject before the (tiny) body even matters.
function postWithDeclaredLength(
  port: number,
  path: string,
  declaredLength: number,
  body: Buffer,
  headers: Record<string, string> = {}
): Promise<PostResult> {
  return new Promise((resolve, reject) => {
    const r = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path,
        method: "POST",
        headers: { ...headers, "content-length": String(declaredLength) },
      },
      (res) => {
        r.destroy();
        resolve(readChunks(res));
      }
    );
    r.on("error", reject);
    r.write(body); // deliberately short of the declared length
  });
}

function readRejectedEvents(dir: string): Array<Record<string, unknown>> {
  const audit = new AuditLog(join(dir, "audit.jsonl"));
  return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === "rejected");
}

function bodyTooLargeEvent(dir: string): Record<string, unknown> | undefined {
  return readRejectedEvents(dir).find((e) => e.reason === "body_too_large");
}

async function closeRelay(server: Server): Promise<void> {
  server.close();
  await new Promise<void>((r) => server.once("close", r));
}

describe("WR-102 per-endpoint inbound body size limits", () => {
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
      secret: testKey,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      maxBodyBytes: GLOBAL_MAX,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
      ...extra,
    });
  }

  it("rejects a chunked body over the endpoint cap that the global limit would accept", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bodylimit-per-endpoint-"));
    const server = relay(dir, { endpointBodyLimits: [{ pattern: "/tight", maxBodyBytes: 8 }] });
    const port = await listen(server);
    try {
      const body = Buffer.alloc(16, "a"); // under GLOBAL_MAX, over the /tight cap of 8
      const res = await postChunked(port, "/tight", body, { "x-signature": signSha256(body, testKey) });
      assert.equal(res.status, 413);
      const ev = bodyTooLargeEvent(dir);
      assert.ok(ev, "expected a body_too_large audit event");
      assert.equal(ev.maxBodyBytes, 8, "audit must carry the effective endpoint budget");
    } finally {
      await closeRelay(server);
    }
  });

  it("rejects via the declared Content-Length pre-check under the endpoint cap", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bodylimit-per-endpoint-"));
    const server = relay(dir, { endpointBodyLimits: [{ pattern: "/tight", maxBodyBytes: 8 }] });
    const port = await listen(server);
    try {
      const body = Buffer.from("tiny");
      const res = await postWithDeclaredLength(port, "/tight", GLOBAL_MAX + 1, body, {
        "x-signature": signSha256(body, testKey),
      });
      // Declared length (1025) exceeds the endpoint cap (8) — resolved
      // before a single body byte is read.
      assert.equal(res.status, 413);
      assert.equal(bodyTooLargeEvent(dir)?.maxBodyBytes, 8);
    } finally {
      await closeRelay(server);
    }
  });

  it("accepts a body over the global cap when a looser per-endpoint rule matches", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bodylimit-per-endpoint-"));
    const server = relay(dir, { endpointBodyLimits: [{ pattern: "/loose/*", maxBodyBytes: 2048 }] });
    const port = await listen(server);
    try {
      const body = Buffer.alloc(GLOBAL_MAX + 500, "b"); // global would 413
      const res = await post(port, "/loose/x", body, { "x-signature": signSha256(body, testKey) });
      assert.equal(res.status, 202);
      assert.equal(bodyTooLargeEvent(dir), undefined);
    } finally {
      await closeRelay(server);
    }
  });

  it("paths with no matching rule keep exact global behavior", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bodylimit-per-endpoint-"));
    const server = relay(dir, { endpointBodyLimits: [{ pattern: "/tight", maxBodyBytes: 8 }] });
    const port = await listen(server);
    try {
      const over = Buffer.alloc(GLOBAL_MAX + 1, "c");
      const res = await postChunked(port, "/unmatched", over, {
        "x-signature": signSha256(over, testKey),
      });
      assert.equal(res.status, 413);
      assert.equal(bodyTooLargeEvent(dir)?.maxBodyBytes, GLOBAL_MAX);

      const at = Buffer.alloc(GLOBAL_MAX, "c");
      const ok = await post(port, "/unmatched", at, { "x-signature": signSha256(at, testKey) });
      assert.equal(ok.status, 202, "exactly-at-global-limit stays accepted");
    } finally {
      await closeRelay(server);
    }
  });

  it("first matching rule wins, like WR-29 endpoint verifiers", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bodylimit-per-endpoint-"));
    const server = relay(dir, {
      endpointBodyLimits: [
        { pattern: "/hooks/*", maxBodyBytes: 8 },
        { pattern: "/hooks/big", maxBodyBytes: 4096 },
      ],
    });
    const port = await listen(server);
    try {
      const body = Buffer.alloc(64, "d");
      const res = await postChunked(port, "/hooks/big", body, {
        "x-signature": signSha256(body, testKey),
      });
      assert.equal(res.status, 413, "first (prefix) rule wins over the later exact rule");
      assert.equal(bodyTooLargeEvent(dir)?.maxBodyBytes, 8);
    } finally {
      await closeRelay(server);
    }
  });

  it("matches a prefix rule against the bare prefix path", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bodylimit-per-endpoint-"));
    const server = relay(dir, { endpointBodyLimits: [{ pattern: "/hooks/*", maxBodyBytes: 8 }] });
    const port = await listen(server);
    try {
      const body = Buffer.alloc(64, "e");
      const res = await postChunked(port, "/hooks", body, {
        "x-signature": signSha256(body, testKey),
      });
      assert.equal(res.status, 413);
      assert.equal(bodyTooLargeEvent(dir)?.maxBodyBytes, 8);
    } finally {
      await closeRelay(server);
    }
  });

  it("answers a gzip bomb 413 under the endpoint cap and audits the effective budget", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bodylimit-per-endpoint-"));
    const server = relay(dir, { endpointBodyLimits: [{ pattern: "/gzip/*", maxBodyBytes: 64 }] });
    const port = await listen(server);
    try {
      const plain = Buffer.alloc(256, "f");
      const wire = gzipSync(plain);
      assert.ok(wire.length < 64, "wire bytes must fit the endpoint intake budget");
      const res = await post(port, "/gzip/x", wire, {
        "x-signature": signSha256(wire, testKey),
        "content-encoding": "gzip",
      });
      // Decompressed 256 bytes exceeds the endpoint cap (64) but is under
      // the global cap (1024): a 413 here proves gunzipCapped honored the
      // per-endpoint budget.
      assert.equal(res.status, 413);
      const ev = bodyTooLargeEvent(dir);
      assert.ok(ev, "expected a body_too_large audit event");
      assert.equal(ev.maxBodyBytes, 64, "audit must carry the effective endpoint budget");
    } finally {
      await closeRelay(server);
    }
  });

  it("rejects invalid endpointBodyLimits with RangeError at startup", () => {
    const badRules: unknown[] = [
      "not-an-array",
      [{ pattern: "hooks/no-slash", maxBodyBytes: 8 }], // pattern must start with /
      [{ pattern: "", maxBodyBytes: 8 }],
      [{ pattern: "/x", maxBodyBytes: 0 }],
      [{ pattern: "/x", maxBodyBytes: -1 }],
      [{ pattern: "/x", maxBodyBytes: 1.5 }],
      [{ pattern: "/x", maxBodyBytes: Number.NaN }],
      [{ pattern: "/x" }], // missing maxBodyBytes
      [null],
    ];
    for (const rules of badRules) {
      const dir = mkdtempSync(join(tmpdir(), "bodylimit-per-endpoint-"));
      assert.throws(
        () =>
          createRelayServer({
            secret: testKey,
            forwardUrl: "http://127.0.0.1:1/hook",
            auditLog: new AuditLog(join(dir, "audit.jsonl")),
            endpointBodyLimits: rules as never,
          }),
        RangeError,
        `rules should throw RangeError: ${JSON.stringify(rules)}`
      );
    }
  });

  it("batch envelope is gated by its rule; per-item payloads stay bounded by the envelope", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bodylimit-per-endpoint-"));
    const server = relay(dir, {
      endpointBodyLimits: [{ pattern: "/ingest/batch", maxBodyBytes: 4096 }],
    });
    const port = await listen(server);
    try {
      // Envelope over the GLOBAL cap (1024) but under the /ingest/batch
      // rule (4096): accepted with all items admitted — per-item payloads
      // were decoded from the already-gated envelope, so no extra budget
      // is needed (or applied) per item.
      const raw = Buffer.from(JSON.stringify({ n: "x".repeat(200) }));
      const item = {
        payload: raw.toString("base64"),
        headers: { "x-signature": signSha256(raw, testKey) },
      };
      const envelope = Buffer.from(JSON.stringify({ events: [item, item, item] }));
      assert.ok(envelope.length > GLOBAL_MAX, "envelope must exceed the global cap");
      assert.ok(envelope.length < 4096, "envelope must fit the endpoint rule");
      const res = await post(port, "/ingest/batch", envelope, {
        "x-signature": signSha256(envelope, testKey),
      });
      assert.equal(res.status, 202, `expected 202, got ${res.status}: ${res.text}`);
      assert.equal(bodyTooLargeEvent(dir), undefined);
    } finally {
      await closeRelay(server);
    }
  });

  it("batch envelope over its rule's budget is answered 413", async () => {
    const dir = mkdtempSync(join(tmpdir(), "bodylimit-per-endpoint-"));
    const server = relay(dir, {
      endpointBodyLimits: [{ pattern: "/ingest/batch", maxBodyBytes: 64 }],
    });
    const port = await listen(server);
    try {
      const envelope = Buffer.from(
        JSON.stringify({ events: [{ payload: Buffer.alloc(200, "g").toString("base64"), headers: {} }] })
      );
      assert.ok(envelope.length > 64, "envelope must exceed the batch rule");
      const res = await postWithDeclaredLength(port, "/ingest/batch", envelope.length, envelope, {
        "x-signature": signSha256(envelope, testKey),
      });
      assert.equal(res.status, 413);
      assert.equal(bodyTooLargeEvent(dir)?.maxBodyBytes, 64);
    } finally {
      await closeRelay(server);
    }
  });
});
