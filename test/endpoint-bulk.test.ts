import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
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
