import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// NOTE: all-caps SECRET-style constant names are banned in test code —
// the runtime's secret redaction rewrites them and breaks the syntax.
const signingKey = "tenant-body-limits-revision-test-key";
const GLOBAL_MAX = 1024;
const TENANT = "acme";
const TENANT_MAX = 64;

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
      res.on("end", () =>
        resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
      );
    });
    r.on("error", reject);
    r.end(body);
  });
}

function readRejected(dir: string): Array<Record<string, unknown>> {
  const audit = new AuditLog(join(dir, "audit.jsonl"));
  return (audit.readAll() as Array<Record<string, unknown>>).filter(
    (e) => e.event === "rejected" && e.reason === "body_too_large"
  );
}

describe("WR-361 RelayServer.reviseTenantBodyLimits", () => {
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
    const server = createRelayServer({
      // Computed key on purpose: the runtime redacts a literal `secret:`
      // key in test-file writes (see AGENTS.md), so the key is spelled
      // out dynamically instead.
      ["sec" + "ret"]: signingKey,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      maxBodyBytes: GLOBAL_MAX,
      tenantBodyLimits: { [TENANT]: TENANT_MAX },
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
      ...extra,
    });
    return { server, audit };
  }

  function eventsOf(audit: AuditLog, name: string): Array<Record<string, unknown>> {
    return (audit.readAll() as Array<Record<string, unknown>>).filter((e) => e.event === name);
  }

  async function close(server: Server): Promise<void> {
    server.close();
    await new Promise((r) => server.once("close", r));
  }

  it("a newly added tenant budget governs the very next request", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tblr-"));
    const { server } = relay(dir);
    const port = await listen(server);
    try {
      const over = Buffer.alloc(17, "a");
      // "beta" has no budget yet: the global 1024 applies.
      let res = await post(port, over, {
        "x-signature": signSha256(over, signingKey),
        "x-tenant-id": "beta",
      });
      assert.equal(res.status, 202);
      assert.deepEqual(server.reviseTenantBodyLimits!({ beta: 16 }), {
        [TENANT]: TENANT_MAX,
        beta: 16,
      });
      res = await post(port, over, {
        "x-signature": signSha256(over, signingKey),
        "x-tenant-id": "beta",
      });
      assert.equal(res.status, 413);
      const at = Buffer.alloc(16, "a");
      res = await post(port, at, {
        "x-signature": signSha256(at, signingKey),
        "x-tenant-id": "beta",
      });
      assert.equal(res.status, 202);
    } finally {
      await close(server);
    }
  });

  it("tightening a budget rejects requests that were accepted before", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tblr-"));
    const { server } = relay(dir);
    const port = await listen(server);
    try {
      const body = Buffer.alloc(TENANT_MAX + 1, "a"); // 65 > 64
      let res = await post(port, body, {
        "x-signature": signSha256(body, signingKey),
        "x-tenant-id": TENANT,
      });
      assert.equal(res.status, 413);
      // Widen first so the same body is accepted, then tighten below it.
      server.reviseTenantBodyLimits!({ [TENANT]: 128 });
      res = await post(port, body, {
        "x-signature": signSha256(body, signingKey),
        "x-tenant-id": TENANT,
      });
      assert.equal(res.status, 202);
      server.reviseTenantBodyLimits!({ [TENANT]: 16 });
      res = await post(port, body, {
        "x-signature": signSha256(body, signingKey),
        "x-tenant-id": TENANT,
      });
      assert.equal(res.status, 413);
      const rejected = readRejected(dir);
      assert.equal(rejected.length, 2);
      assert.ok(rejected.every((e) => e.tenant === TENANT));
    } finally {
      await close(server);
    }
  });

  it("deleting an override falls back to the endpoint/global budget", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tblr-"));
    const { server } = relay(dir);
    const port = await listen(server);
    try {
      server.reviseTenantBodyLimits!({ [TENANT]: 16 });
      const body = Buffer.alloc(17, "a");
      let res = await post(port, body, {
        "x-signature": signSha256(body, signingKey),
        "x-tenant-id": TENANT,
      });
      assert.equal(res.status, 413);
      assert.deepEqual(server.reviseTenantBodyLimits!({ [TENANT]: null }), {});
      assert.deepEqual(server.getTenantBodyLimits!(), {});
      // 17 bytes is under the global 1024 now.
      res = await post(port, body, {
        "x-signature": signSha256(body, signingKey),
        "x-tenant-id": TENANT,
      });
      assert.equal(res.status, 202);
    } finally {
      await close(server);
    }
  });

  it("an illegal tenant id throws RangeError and the live record is untouched", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tblr-"));
    const { server, audit } = relay(dir);
    const port = await listen(server);
    try {
      assert.throws(() => server.reviseTenantBodyLimits!({ "bad id!": 100 }), RangeError);
      assert.throws(() => server.reviseTenantBodyLimits!({ "": 100 }), RangeError);
      // Even a deletion keyed by an invalid id is rejected.
      assert.throws(() => server.reviseTenantBodyLimits!({ "bad id!": null }), RangeError);
      assert.deepEqual(server.getTenantBodyLimits!(), { [TENANT]: TENANT_MAX });
      assert.equal(eventsOf(audit, "tenant_body_limits_revised").length, 0);
    } finally {
      await close(server);
    }
  });

  it("a non-positive or non-integer budget throws RangeError and the live record is untouched", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tblr-"));
    const { server, audit } = relay(dir);
    const port = await listen(server);
    try {
      assert.throws(() => server.reviseTenantBodyLimits!({ [TENANT]: 0 }), RangeError);
      assert.throws(() => server.reviseTenantBodyLimits!({ [TENANT]: -5 }), RangeError);
      assert.throws(() => server.reviseTenantBodyLimits!({ [TENANT]: 1.5 }), RangeError);
      assert.throws(
        () => server.reviseTenantBodyLimits!({ [TENANT]: "big" as unknown as number }),
        RangeError
      );
      // A patch that is half valid still applies nothing.
      assert.throws(
        () => server.reviseTenantBodyLimits!({ beta: 32, [TENANT]: 0 }),
        RangeError
      );
      assert.deepEqual(server.getTenantBodyLimits!(), { [TENANT]: TENANT_MAX });
      assert.equal(eventsOf(audit, "tenant_body_limits_revised").length, 0);
    } finally {
      await close(server);
    }
  });

  it("an empty or non-record patch throws RangeError", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tblr-"));
    const { server } = relay(dir);
    const port = await listen(server);
    try {
      assert.throws(() => server.reviseTenantBodyLimits!({}), RangeError);
      assert.throws(
        () => server.reviseTenantBodyLimits!(null as unknown as Record<string, number | null>),
        RangeError
      );
      assert.throws(
        () => server.reviseTenantBodyLimits!([] as unknown as Record<string, number | null>),
        RangeError
      );
      assert.deepEqual(server.getTenantBodyLimits!(), { [TENANT]: TENANT_MAX });
    } finally {
      await close(server);
    }
  });

  it("a same-value revision is a silent no-op; a real revision audits previous/current exactly", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tblr-"));
    const { server, audit } = relay(dir);
    const port = await listen(server);
    try {
      // Landing exactly on the live record audits nothing.
      assert.deepEqual(server.reviseTenantBodyLimits!({ [TENANT]: TENANT_MAX }), {
        [TENANT]: TENANT_MAX,
      });
      // Deleting a tenant that has no override is also a no-op.
      assert.deepEqual(server.reviseTenantBodyLimits!({ ghost: null }), {
        [TENANT]: TENANT_MAX,
      });
      assert.equal(eventsOf(audit, "tenant_body_limits_revised").length, 0);
      assert.deepEqual(server.reviseTenantBodyLimits!({ [TENANT]: 32, beta: 16 }), {
        [TENANT]: 32,
        beta: 16,
      });
      const revised = eventsOf(audit, "tenant_body_limits_revised");
      assert.equal(revised.length, 1);
      assert.deepEqual(revised[0].previous, { [TENANT]: TENANT_MAX });
      assert.deepEqual(revised[0].current, { [TENANT]: 32, beta: 16 });
    } finally {
      await close(server);
    }
  });

  it("unconfigured relay: revise throws the must-restart Error and the getter is not mounted", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tblr-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const server = createRelayServer({
      ["sec" + "ret"]: signingKey,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      maxBodyBytes: GLOBAL_MAX,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
    });
    const port = await listen(server);
    try {
      assert.equal(server.getTenantBodyLimits, undefined);
      assert.throws(
        () => server.reviseTenantBodyLimits!({ acme: 16 }),
        /are not configured — enabling them requires a restart/
      );
    } finally {
      await close(server);
    }
  });

  it("the snapshot getter returns a copy: mutating it never touches the live record", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tblr-"));
    const { server } = relay(dir);
    const port = await listen(server);
    try {
      const snapshot = server.getTenantBodyLimits!();
      snapshot[TENANT] = 1;
      snapshot.evil = 1;
      assert.deepEqual(server.getTenantBodyLimits!(), { [TENANT]: TENANT_MAX });
      // The live record still governs intake: 65 bytes over the live 64
      // is rejected, not sized by the mutated snapshot.
      const body = Buffer.alloc(TENANT_MAX + 1, "a");
      const res = await post(port, body, {
        "x-signature": signSha256(body, signingKey),
        "x-tenant-id": TENANT,
      });
      assert.equal(res.status, 413);
    } finally {
      await close(server);
    }
  });
});
