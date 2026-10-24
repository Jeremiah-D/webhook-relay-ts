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
import {
  assertValidTenantBodyLimits,
  resolveTenantBodyBudget,
  selectTenantBodyLimit,
} from "../src/tenant-body-limit.ts";

const SECRET = "relay-secret";
const GLOBAL_MAX = 64;
const TENANT = "acme";
const TENANT_MAX = 16;

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function post(port: number, body: Buffer, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string; connection: string | undefined }>(
    (resolve, reject) => {
      const r = httpRequest({ host: "127.0.0.1", port, path: "/", method: "POST", headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            text: Buffer.concat(chunks).toString(),
            connection: res.headers["connection"] as string | undefined,
          })
        );
      });
      r.on("error", reject);
      r.end(body);
    }
  );
}

// Declared Content-Length bigger than the body written: the server must
// reject before the body even matters.
function postWithDeclaredLength(
  port: number,
  declaredLength: number,
  body: Buffer,
  headers: Record<string, string> = {}
) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path: "/",
        method: "POST",
        headers: { ...headers, "content-length": String(declaredLength) },
      },
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

function readRejected(dir: string): Array<Record<string, unknown>> {
  const audit = new AuditLog(join(dir, "audit.jsonl"));
  return (audit.readAll() as Array<Record<string, unknown>>).filter(
    (e) => e.event === "rejected" && e.reason === "body_too_large"
  );
}

describe("tenant-body-limit validation", () => {
  it("accepts a valid map", () => {
    assertValidTenantBodyLimits({ acme: 1024, "t-2": 1 });
    assertValidTenantBodyLimits({});
  });

  it("rejects non-record maps", () => {
    assert.throws(() => assertValidTenantBodyLimits(null), RangeError);
    assert.throws(() => assertValidTenantBodyLimits([]), RangeError);
    assert.throws(() => assertValidTenantBodyLimits("x"), RangeError);
  });

  it("rejects non-positive or non-integer budgets", () => {
    assert.throws(() => assertValidTenantBodyLimits({ acme: 0 }), RangeError);
    assert.throws(() => assertValidTenantBodyLimits({ acme: -5 }), RangeError);
    assert.throws(() => assertValidTenantBodyLimits({ acme: 1.5 }), RangeError);
    assert.throws(() => assertValidTenantBodyLimits({ acme: "big" }), RangeError);
  });

  it("rejects invalid tenant id keys fail-fast", () => {
    assert.throws(() => assertValidTenantBodyLimits({ "bad id!": 100 }), RangeError);
    assert.throws(() => assertValidTenantBodyLimits({ "": 100 }), RangeError);
  });

  it("createRelayServer rejects an invalid map at construction", () => {
    const dir = mkdtempSync(join(tmpdir(), "tbl-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    assert.throws(
      () =>
        createRelayServer({
          secret: SECRET,
          forwardUrl: "http://127.0.0.1:9/hook",
          auditLog: audit,
          tenantBodyLimits: { "bad id!": 100 },
        }),
      RangeError
    );
    assert.throws(
      () =>
        createRelayServer({
          secret: SECRET,
          forwardUrl: "http://127.0.0.1:9/hook",
          auditLog: audit,
          tenantBodyLimits: { acme: 0 },
        }),
      RangeError
    );
  });
});

describe("resolveTenantBodyBudget", () => {
  const limits = { acme: 16 };
  it("resolves the first header value", () => {
    assert.deepEqual(resolveTenantBodyBudget("acme", limits), { tenant: "acme", bytes: 16 });
    assert.deepEqual(resolveTenantBodyBudget(["acme", "other"], limits), {
      tenant: "acme",
      bytes: 16,
    });
  });

  it("returns undefined for absent / invalid / unconfigured tenants", () => {
    assert.equal(resolveTenantBodyBudget(undefined, limits), undefined);
    assert.equal(resolveTenantBodyBudget("", limits), undefined);
    assert.equal(resolveTenantBodyBudget("other", limits), undefined);
    assert.equal(resolveTenantBodyBudget("bad id!", limits), undefined);
    assert.equal(resolveTenantBodyBudget("acme", undefined), undefined);
  });

  it("never resolves through the prototype chain", () => {
    assert.equal(resolveTenantBodyBudget("__proto__", limits), undefined);
    assert.equal(selectTenantBodyLimit("__proto__", limits), undefined);
    assert.equal(selectTenantBodyLimit("constructor", limits), undefined);
  });
});

describe("WR-203 per-tenant inbound body budget", () => {
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
      maxBodyBytes: GLOBAL_MAX,
      tenantBodyLimits: { [TENANT]: TENANT_MAX },
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
      ...extra,
    });
  }

  it("applies the tenant budget to the streaming cap", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tbl-"));
    const server = relay(dir);
    const port = await listen(server);
    try {
      const body = Buffer.alloc(TENANT_MAX + 1, "a"); // 17 > 16, chunked
      const res = await post(port, body, {
        "x-signature": signSha256(body, SECRET),
        "x-tenant-id": TENANT,
      });
      assert.equal(res.status, 413);
      assert.equal(res.connection, "close");
      const rejected = readRejected(dir);
      assert.equal(rejected.length, 1);
      assert.equal(rejected[0].tenant, TENANT);
      assert.equal(rejected[0].maxBodyBytes, TENANT_MAX);
    } finally {
      server.close();
      await new Promise((r) => server.once("close", r));
    }
  });

  it("applies the tenant budget to the Content-Length pre-check", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tbl-"));
    const server = relay(dir);
    const port = await listen(server);
    try {
      const body = Buffer.from("tiny");
      const res = await postWithDeclaredLength(port, TENANT_MAX + 100, body, {
        "x-signature": signSha256(body, SECRET),
        "x-tenant-id": TENANT,
      });
      assert.equal(res.status, 413);
      const rejected = readRejected(dir);
      assert.equal(rejected.length, 1);
      assert.equal(rejected[0].tenant, TENANT);
    } finally {
      server.close();
      await new Promise((r) => server.once("close", r));
    }
  });

  it("accepts a tenant body exactly at its budget", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tbl-"));
    const server = relay(dir);
    const port = await listen(server);
    try {
      const body = Buffer.alloc(TENANT_MAX, "a");
      const res = await post(port, body, {
        "x-signature": signSha256(body, SECRET),
        "x-tenant-id": TENANT,
      });
      assert.equal(res.status, 202);
      assert.equal(readRejected(dir).length, 0);
    } finally {
      server.close();
      await new Promise((r) => server.once("close", r));
    }
  });

  it("falls back to the global budget without a tenant header", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tbl-"));
    const server = relay(dir);
    const port = await listen(server);
    try {
      const body = Buffer.alloc(TENANT_MAX + 1, "a"); // over tenant budget, under global
      const res = await post(port, body, { "x-signature": signSha256(body, SECRET) });
      assert.equal(res.status, 202);
      assert.equal(readRejected(dir).length, 0);
    } finally {
      server.close();
      await new Promise((r) => server.once("close", r));
    }
  });

  it("falls back to the global budget for an unconfigured tenant", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tbl-"));
    const server = relay(dir);
    const port = await listen(server);
    try {
      const body = Buffer.alloc(TENANT_MAX + 1, "a");
      const res = await post(port, body, {
        "x-signature": signSha256(body, SECRET),
        "x-tenant-id": "stranger",
      });
      assert.equal(res.status, 202);
      assert.equal(readRejected(dir).length, 0);
    } finally {
      server.close();
      await new Promise((r) => server.once("close", r));
    }
  });

  it("caps the gzip decompression under the tenant budget", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tbl-"));
    // A bigger tenant budget here: gzip's fixed framing overhead (~20B)
    // alone exceeds the 16B budget used elsewhere.
    const server = relay(dir, { tenantBodyLimits: { [TENANT]: 64 } });
    const port = await listen(server);
    try {
      const plain = Buffer.alloc(512, "a");
      const wire = gzipSync(plain); // compresses well under the budget
      assert.ok(wire.length < 64, "sanity: the wire bytes must fit the tenant budget");
      const res = await post(port, wire, {
        "x-signature": signSha256(wire, SECRET),
        "x-tenant-id": TENANT,
        "content-encoding": "gzip",
      });
      assert.equal(res.status, 413);
      const rejected = readRejected(dir);
      assert.equal(rejected.length, 1);
      assert.equal(rejected[0].tenant, TENANT);
      assert.equal(rejected[0].maxBodyBytes, 64);
    } finally {
      server.close();
      await new Promise((r) => server.once("close", r));
    }
  });

  it("the tenant budget wins over the per-endpoint rule", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tbl-"));
    const server = relay(dir, {
      endpointBodyLimits: [{ pattern: "/*", maxBodyBytes: 128 }],
    });
    const port = await listen(server);
    try {
      // 32 bytes: over the tenant budget (16) but under the endpoint rule (128).
      const body = Buffer.alloc(32, "a");
      const res = await post(port, body, {
        "x-signature": signSha256(body, SECRET),
        "x-tenant-id": TENANT,
      });
      assert.equal(res.status, 413);
      assert.equal(readRejected(dir)[0].maxBodyBytes, TENANT_MAX);
      // Another tenant rides the endpoint rule instead.
      const res2 = await post(port, body, {
        "x-signature": signSha256(body, SECRET),
        "x-tenant-id": "stranger",
      });
      assert.equal(res2.status, 202);
    } finally {
      server.close();
      await new Promise((r) => server.once("close", r));
    }
  });

  it("a global 413 without tenant override carries no tenant dimension", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tbl-"));
    const server = relay(dir);
    const port = await listen(server);
    try {
      const body = Buffer.alloc(GLOBAL_MAX + 1, "a");
      const res = await post(port, body, { "x-signature": signSha256(body, SECRET) });
      assert.equal(res.status, 413);
      const rejected = readRejected(dir);
      assert.equal(rejected.length, 1);
      assert.ok(!("tenant" in rejected[0]), "no tenant dimension when no tenant budget applied");
    } finally {
      server.close();
      await new Promise((r) => server.once("close", r));
    }
  });
});
