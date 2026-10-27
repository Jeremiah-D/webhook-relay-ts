import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  applyBulkEndpointOperation,
  normalizeBulkEndpoints,
} from "../src/endpoint-bulk.ts";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const URL = "http://localhost:9999/hook";
const UNKNOWN = "http://unknown/hook";
const hookSecret = "relay-secret";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));
const TOKEN = "op-token";

describe("normalizeBulkEndpoints", () => {
  it("rejects a non-array, an empty list, and illegal members", () => {
    assert.throws(() => normalizeBulkEndpoints("x"), RangeError);
    assert.throws(() => normalizeBulkEndpoints({}), RangeError);
    assert.throws(() => normalizeBulkEndpoints([]), RangeError);
    assert.throws(() => normalizeBulkEndpoints([""]), RangeError);
    assert.throws(() => normalizeBulkEndpoints([URL, 42]), RangeError);
    assert.throws(() => normalizeBulkEndpoints([null]), RangeError);
  });

  it("deduplicates, keeping the first occurrence in order", () => {
    assert.deepEqual(normalizeBulkEndpoints([URL, UNKNOWN, URL, UNKNOWN]), [URL, UNKNOWN]);
    assert.deepEqual(normalizeBulkEndpoints([URL]), [URL]);
  });
});

describe("applyBulkEndpointOperation", () => {
  it("applies in order, reports unknown rows, and never aborts on a row failure", () => {
    const applied: string[] = [];
    const rows = applyBulkEndpointOperation([URL, UNKNOWN, "http://boom/hook"], {
      isKnown: (e) => e !== UNKNOWN,
      apply: (e) => {
        if (e === "http://boom/hook") throw new Error("boom");
        applied.push(e);
        return true;
      },
    });
    assert.deepEqual(rows, [
      { endpoint: URL, ok: true },
      { endpoint: UNKNOWN, ok: false, error: "unknown endpoint" },
      { endpoint: "http://boom/hook", ok: false, error: "boom" },
    ]);
    assert.deepEqual(applied, [URL]);
  });

  it("treats an idempotent no-op apply as a success row", () => {
    const rows = applyBulkEndpointOperation([URL], {
      isKnown: () => true,
      apply: () => false,
    });
    assert.deepEqual(rows, [{ endpoint: URL, ok: true }]);
  });
});

describe("POST /endpoints/bulk-enable + /endpoints/bulk-disable operator routes", () => {
  let servers: Server[] = [];
  afterEach(async () => {
    for (const s of servers) {
      s.close();
      await new Promise((r) => s.once("close", r));
    }
    servers = [];
  });

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  function postJson(port: number, path: string, body: unknown, token?: string, method = "POST") {
    return new Promise<{ status: number; json: unknown }>((resolve, reject) => {
      const headers: Record<string, string> = { "content-type": "application/json" };
      if (token !== undefined) headers["authorization"] = `Bearer ${token}`;
      const r = httpRequest({ host: "127.0.0.1", port, path, method, headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            json: JSON.parse(Buffer.concat(chunks).toString() || "{}"),
          })
        );
      });
      r.on("error", reject);
      r.end(JSON.stringify(body));
    });
  }

  function postWebhook(port: number) {
    return new Promise<number>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/hook",
          method: "POST",
          headers: {
            "x-signature": signSha256(BODY, hookSecret),
            "content-type": "application/json",
            "content-length": String(BODY.length),
          },
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve(res.statusCode ?? 0));
        }
      );
      r.on("error", reject);
      r.end(BODY);
    });
  }

  async function makeRelay(failing: boolean) {
    const dir = mkdtempSync(join(tmpdir(), "bulk-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    let calls = 0;
    const relay = createRelayServer({
      // Computed key on purpose: a literal `secret:` key here is
      // rewritten by the runtime's secret redaction when writing
      // test sources, which breaks parsing (see AGENTS.md).
      ["sec" + "ret"]: hookSecret,
      forwardUrl: URL,
      auditLog: audit,
      operatorToken: TOKEN,
      sender: async () => {
        calls += 1;
        if (failing) throw new Error("downstream down");
      },
      retry: {
        baseDelayMs: 10,
        maxAttempts: 1,
        jitterMs: 0,
        endpointAutoDisable: { failureThreshold: 2 },
      },
    });
    servers.push(relay);
    return { port: await listen(relay), audit, calls: () => calls };
  }

  it("bulk-enables a tripped endpoint, deduplicates, and reports unknown rows", async () => {
    const { port, audit, calls } = await makeRelay(true);
    assert.equal(await postWebhook(port), 202);
    assert.equal(await postWebhook(port), 202);
    const deadline = Date.now() + 5000;
    while (calls() < 2 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(calls(), 2);
    assert.equal(audit.query({ event: "endpoint_auto_disabled" }).length, 1);

    const res = await postJson(
      port,
      "/endpoints/bulk-enable",
      { endpoints: [URL, URL, UNKNOWN] },
      TOKEN
    );
    assert.equal(res.status, 200);
    assert.deepEqual(res.json, {
      results: [
        { endpoint: URL, ok: true },
        { endpoint: UNKNOWN, ok: false, error: "unknown endpoint" },
      ],
    });
    const enabled = audit.query({ event: "endpoint_enabled" }) as Array<{ endpoint: string }>;
    assert.equal(enabled.length, 1);
    assert.equal(enabled[0].endpoint, URL);

    // Re-enabling an already-enabled endpoint is an idempotent ok row, no new audit.
    const again = await postJson(port, "/endpoints/bulk-enable", { endpoints: [URL] }, TOKEN);
    assert.equal(again.status, 200);
    assert.deepEqual(again.json, { results: [{ endpoint: URL, ok: true }] });
    assert.equal(audit.query({ event: "endpoint_enabled" }).length, 1);
  });

  it("bulk-disables, parks deliveries, and fails closed on malformed lists", async () => {
    const { port, audit, calls } = await makeRelay(false);
    const res = await postJson(port, "/endpoints/bulk-disable", { endpoints: [URL] }, TOKEN);
    assert.equal(res.status, 200);
    assert.deepEqual(res.json, { results: [{ endpoint: URL, ok: true }] });
    const paused = audit.query({ event: "endpoint_paused" }) as Array<{ endpoint: string }>;
    assert.equal(paused.length, 1);
    assert.equal(paused[0].endpoint, URL);

    // A parked endpoint is accepted but never attempted.
    assert.equal(await postWebhook(port), 202);
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(calls(), 0);

    // Unknown rows are reported, not silent; malformed lists are 400 with nothing changed.
    const mixed = await postJson(
      port,
      "/endpoints/bulk-disable",
      { endpoints: [UNKNOWN, URL] },
      TOKEN
    );
    assert.equal(mixed.status, 200);
    assert.deepEqual(mixed.json, {
      results: [
        { endpoint: UNKNOWN, ok: false, error: "unknown endpoint" },
        { endpoint: URL, ok: true },
      ],
    });
    assert.equal(audit.query({ event: "endpoint_paused" }).length, 1);
    for (const bad of [[], "x", [""], [URL, 42]]) {
      const badRes = await postJson(port, "/endpoints/bulk-disable", { endpoints: bad }, TOKEN);
      assert.equal(badRes.status, 400);
    }
    assert.equal(audit.query({ event: "endpoint_paused" }).length, 1);

    // Auth and method gates match the single routes: no token -> 403, GET -> 405.
    assert.equal(
      (await postJson(port, "/endpoints/bulk-disable", { endpoints: [URL] })).status,
      403
    );
    assert.equal(
      (await postJson(port, "/endpoints/bulk-enable", {}, TOKEN, "GET")).status,
      405
    );
  });
});

describe("POST /endpoints/bulk-delete operator route", () => {
  let servers: Server[] = [];
  afterEach(async () => {
    for (const s of servers) {
      s.close();
      await new Promise((r) => s.once("close", r));
    }
    servers = [];
  });

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

  function httpJson(
    port: number,
    method: string,
    path: string,
    body?: unknown,
    token?: string
  ): Promise<{ status: number; json: unknown }> {
    return new Promise((resolve, reject) => {
      const headers: Record<string, string> = {};
      if (token !== undefined) headers["authorization"] = `Bearer ${token}`;
      let payload: string | undefined;
      if (body !== undefined) {
        headers["content-type"] = "application/json";
        payload = JSON.stringify(body);
      }
      const r = httpRequest({ host: "127.0.0.1", port, path, method, headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            json: JSON.parse(Buffer.concat(chunks).toString() || "{}"),
          })
        );
      });
      r.on("error", reject);
      if (payload !== undefined) r.end(payload);
      else r.end();
    });
  }

  async function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "bulk-delete-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      // Computed key on purpose: a literal `secret:` key here is
      // rewritten by the runtime's secret redaction when writing
      // test sources, which breaks parsing (see AGENTS.md).
      ["sec" + "ret"]: hookSecret,
      forwardUrl: URL,
      auditLog: audit,
      operatorToken: TOKEN,
      ...extra,
    } as Parameters<typeof createRelayServer>[0]);
    servers.push(relay);
    return { port: await listen(relay), audit };
  }

  async function waitFor(cond: () => boolean, timeoutMs: number, what: string): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (!cond() && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok(cond(), `timed out waiting for: ${what}`);
  }

  /** Downstream stub whose responses can be held open (for in-flight tests). */
  function blockingStub() {
    interface Hit {
      respond: () => void;
    }
    const hits: Hit[] = [];
    const server = createServer((_req, res) => {
      const hit: Hit = { respond: () => res.writeHead(200).end("ok") };
      hits.push(hit);
    });
    return {
      server,
      hits,
      releaseAll: () => {
        for (const h of hits) h.respond();
      },
    };
  }

  function postWebhook(port: number) {
    return new Promise<number>((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path: "/hook",
          method: "POST",
          headers: {
            "x-signature": signSha256(BODY, hookSecret),
            "content-type": "application/json",
            "content-length": String(BODY.length),
          },
        },
        (res) => {
          res.resume();
          res.on("end", () => resolve(res.statusCode ?? 0));
        }
      );
      r.on("error", reject);
      r.end(BODY);
    });
  }

  const A = "https://a.example/hook";
  const B = "https://b.example/hook";
  const C = "https://c.example/hook";

  it("deletes registry endpoints in bulk, deduplicates, reports unknown rows, audits each deletion", async () => {
    const { port, audit } = await makeRelay();
    for (const target of [A, B, C]) {
      const created = await httpJson(port, "POST", "/endpoints", { targetUrl: target }, TOKEN);
      assert.equal(created.status, 201);
    }
    const res = await httpJson(port, "POST", "/endpoints/bulk-delete", { endpoints: [A, A, UNKNOWN, B] }, TOKEN);
    assert.equal(res.status, 200);
    assert.deepEqual(res.json, {
      results: [
        { endpoint: A, ok: true },
        { endpoint: UNKNOWN, ok: false, error: "unknown endpoint" },
        { endpoint: B, ok: true },
      ],
    });
    const listed = await httpJson(port, "GET", "/endpoints", undefined, TOKEN);
    assert.deepEqual(
      (listed.json as { endpoints: Array<{ targetUrl: string }> }).endpoints.map((e) => e.targetUrl),
      [C]
    );
    const deleted = audit.query({ event: "endpoint_config_updated" }) as Array<{
      endpoint: string;
      operation: string;
    }>;
    assert.deepEqual(
      deleted.filter((e) => e.operation === "deleted").map((e) => e.endpoint),
      [A, B]
    );

    // A static endpoint (the forwardUrl, no registry record) is reported
    // unknown, never silently skipped — and a deleted endpoint stays unknown.
    const staticRes = await httpJson(port, "POST", "/endpoints/bulk-delete", { endpoints: [URL, A] }, TOKEN);
    assert.deepEqual(staticRes.json, {
      results: [
        { endpoint: URL, ok: false, error: "unknown endpoint" },
        { endpoint: A, ok: false, error: "unknown endpoint" },
      ],
    });

    // Malformed lists are 400 with nothing changed: C survives them all.
    for (const bad of [[], "x", [""], [C, 42]]) {
      const badRes = await httpJson(port, "POST", "/endpoints/bulk-delete", { endpoints: bad }, TOKEN);
      assert.equal(badRes.status, 400);
    }
    const after = await httpJson(port, "GET", "/endpoints", undefined, TOKEN);
    assert.equal((after.json as { endpoints: unknown[] }).endpoints.length, 1);

    // Auth and method gates match the single routes: no token -> 403, GET -> 405.
    assert.equal(
      (await httpJson(port, "POST", "/endpoints/bulk-delete", { endpoints: [C] })).status,
      403
    );
    assert.equal(
      (await httpJson(port, "GET", "/endpoints/bulk-delete", undefined, TOKEN)).status,
      405
    );

    // C itself deletes cleanly once the gates are satisfied.
    const last = await httpJson(port, "POST", "/endpoints/bulk-delete", { endpoints: [C] }, TOKEN);
    assert.deepEqual(last.json, { results: [{ endpoint: C, ok: true }] });
  });

  it("waits for in-flight deliveries to drain, and fails only that row on drain timeout", async () => {
    const stub = blockingStub();
    const stubPort = await listen(stub.server);
    servers.push(stub.server);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const { port, audit } = await makeRelay({ forwardUrl: target, endpointDrainTimeoutMs: 250 });
    const created = await httpJson(port, "POST", "/endpoints", { targetUrl: target }, TOKEN);
    assert.equal(created.status, 201);

    assert.equal(await postWebhook(port), 202);
    await waitFor(() => stub.hits.length >= 1, 5000, "delivery attempt started");

    // The drain times out while the downstream holds the attempt: that
    // row fails, the unknown row is still reported, and the record survives.
    const timedOut = await httpJson(
      port,
      "POST",
      "/endpoints/bulk-delete",
      { endpoints: [target, UNKNOWN] },
      TOKEN
    );
    assert.equal(timedOut.status, 200);
    const rows = (timedOut.json as { results: Array<{ endpoint: string; ok: boolean; error?: string }> }).results;
    assert.equal(rows.length, 2);
    assert.equal(rows[0].endpoint, target);
    assert.equal(rows[0].ok, false);
    assert.match(rows[0].error ?? "", /in-flight deliveries/);
    assert.deepEqual(rows[1], { endpoint: UNKNOWN, ok: false, error: "unknown endpoint" });
    const listed = await httpJson(port, "GET", "/endpoints", undefined, TOKEN);
    assert.equal((listed.json as { endpoints: unknown[] }).endpoints.length, 1);
    assert.equal(
      (audit.query({ event: "endpoint_config_updated" }) as Array<{ operation: string }>).filter(
        (e) => e.operation === "deleted"
      ).length,
      0
    );

    // Once the attempt settles, the same endpoint deletes cleanly.
    stub.releaseAll();
    const retried = await httpJson(port, "POST", "/endpoints/bulk-delete", { endpoints: [target] }, TOKEN);
    assert.deepEqual(retried.json, { results: [{ endpoint: target, ok: true }] });
    const empty = await httpJson(port, "GET", "/endpoints", undefined, TOKEN);
    assert.equal((empty.json as { endpoints: unknown[] }).endpoints.length, 0);
  });
});
