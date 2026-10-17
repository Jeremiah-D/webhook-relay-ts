import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  OPERATOR_ROUTES,
  buildOpenApiDocument,
  findOperatorRoute,
  matchOperatorRoute,
  requiredScopeForMethod,
} from "../src/operator-routes.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

const OPERATOR_TOKEN = "openapi-operator-token";

/**
 * WR-111: the operator API route registry, the OpenAPI 3.1 document it
 * generates, and the `/openapi.json` endpoint that serves it.
 *
 * The inline INVENTORY below is the snapshot: it pins the registry's
 * route list, so adding/removing/retargeting an operator route without
 * updating the registry (and this snapshot) fails loudly instead of
 * silently drifting the published spec.
 */
const INVENTORY: Array<[string, Array<"GET" | "POST" | "PUT" | "DELETE">]> = [
  ["/dead-letter", ["GET"]],
  ["/dead-letter/stats", ["GET"]],
  ["/dead-letter/replay", ["POST"]],
  ["/dead-letter/{id}/replay", ["POST"]],
  ["/dead-letter/auto-replay/status", ["GET"]],
  ["/dead-letter/auto-replay/pause", ["POST"]],
  ["/dead-letter/auto-replay/resume", ["POST"]],
  ["/dead-letter/auto-replay/trigger", ["POST"]],
  ["/audit", ["GET"]],
  ["/audit/verify", ["GET"]],
  ["/latency", ["GET"]],
  ["/maintenance/windows", ["GET", "POST"]],
  ["/slo-risk", ["GET"]],
  ["/quorum", ["GET"]],
  ["/quorum/stats", ["GET"]],
  ["/usage", ["GET"]],
  ["/health/summary", ["GET"]],
  ["/events", ["GET"]],
  ["/events/archive", ["GET"]],
  ["/metrics", ["GET"]],
  ["/config/endpoint", ["POST"]],
  ["/config/snapshot", ["GET", "POST"]],
  ["/routing/rules", ["GET", "POST"]],
  ["/endpoints/pause", ["POST"]],
  ["/endpoints/resume", ["POST"]],
  ["/endpoints", ["GET", "POST"]],
  ["/endpoints/{id}", ["PUT", "DELETE"]],
  ["/scheduled", ["GET"]],
  ["/scheduled/{id}/{action}", ["POST"]],
  ["/deliveries/{traceId}", ["GET"]],
  ["/openapi.json", ["GET"]],
];

describe("WR-111 operator route registry", () => {
  it("matches the pinned route inventory exactly (snapshot against drift)", () => {
    assert.deepEqual(
      OPERATOR_ROUTES.map((r) => [r.path, r.methods]),
      INVENTORY
    );
  });

  it("every route has a summary, description, and okDescription", () => {
    for (const r of OPERATOR_ROUTES) {
      assert.ok(r.summary.length > 0, `${r.path}: summary`);
      assert.ok(r.description.length > 0, `${r.path}: description`);
      assert.ok(r.okDescription.length > 0, `${r.path}: okDescription`);
    }
  });

  it("no two routes overlap on the same pathname", () => {
    const probes = [
      "/dead-letter",
      "/dead-letter/stats",
      "/dead-letter/replay",
      "/dead-letter/abc/replay",
      "/dead-letter/auto-replay/status",
      "/scheduled",
      "/scheduled/abc/pause",
      "/scheduled/abc/resume",
      "/deliveries/trace-1",
      "/endpoints",
      "/endpoints/pause",
      "/endpoints/resume",
      "/endpoints/some-id",
      "/openapi.json",
    ];
    for (const probe of probes) {
      const hits = OPERATOR_ROUTES.filter((r) => r.pattern.test(probe));
      assert.equal(hits.length, 1, `${probe}: matched ${hits.map((h) => h.path).join(",")}`);
    }
  });

  it("findOperatorRoute / matchOperatorRoute mirror the server's 404/405 dispatch", () => {
    assert.equal(findOperatorRoute("/nope"), undefined);
    assert.equal(findOperatorRoute("/dead-letter")?.path, "/dead-letter");
    // Path known, wrong method -> undefined (the server answers 405).
    assert.equal(matchOperatorRoute("/dead-letter", "POST"), undefined);
    assert.equal(matchOperatorRoute("/metrics", "POST"), undefined);
    assert.equal(matchOperatorRoute("/dead-letter/abc/replay", "GET"), undefined);
    // Both methods served where the server allows both.
    assert.equal(matchOperatorRoute("/config/snapshot", "GET")?.path, "/config/snapshot");
    assert.equal(matchOperatorRoute("/config/snapshot", "POST")?.path, "/config/snapshot");
    assert.equal(matchOperatorRoute("/config/snapshot", "DELETE"), undefined);
  });

  it("requiredScopeForMethod follows WR-82 (GET=read, mutating=admin)", () => {
    assert.equal(requiredScopeForMethod("GET"), "read");
    assert.equal(requiredScopeForMethod("POST"), "admin");
    assert.equal(requiredScopeForMethod("PUT"), "admin");
    assert.equal(requiredScopeForMethod("DELETE"), "admin");
  });
});

describe("WR-111 OpenAPI 3.1 document", () => {
  const doc = buildOpenApiDocument() as {
    openapi: string;
    info: { title: string; version: string };
    paths: Record<string, Record<string, Record<string, unknown>>>;
    components: { securitySchemes: Record<string, { type: string; scheme: string }> };
    security: unknown[];
  };

  it("is a valid OpenAPI 3.1 document with the operatorToken scheme", () => {
    assert.equal(doc.openapi, "3.1.0");
    assert.ok(doc.info.title.length > 0);
    assert.deepEqual(doc.security, [{ operatorToken: [] }]);
    assert.equal(doc.components.securitySchemes.operatorToken.type, "http");
    assert.equal(doc.components.securitySchemes.operatorToken.scheme, "bearer");
  });

  it("covers every registered route, no more and no fewer", () => {
    assert.deepEqual(Object.keys(doc.paths).sort(), INVENTORY.map(([p]) => p).sort());
  });

  it("every operation carries x-required-scope matching its method", () => {
    for (const [path, methods] of INVENTORY) {
      for (const method of methods) {
        const op = doc.paths[path][method.toLowerCase()];
        assert.ok(op, `${method} ${path}`);
        const want = method === "GET" ? "read" : "admin";
        assert.equal(op["x-required-scope"], want, `${method} ${path}`);
        assert.deepEqual(op.security, [{ operatorToken: [] }]);
        assert.ok(typeof op.summary === "string" && (op.summary as string).length > 0);
        const responses = op.responses as Record<string, { description: string }>;
        for (const code of ["200", "400", "401", "403", "404", "405"]) {
          assert.ok(responses[code]?.description, `${method} ${path}: ${code}`);
        }
      }
    }
  });

  it("documents query, path, and body parameters faithfully", () => {
    const auditGet = doc.paths["/audit"].get;
    const params = auditGet.parameters as Array<{ name: string; in: string; required: boolean }>;
    const byName = Object.fromEntries(params.map((p) => [p.name, p]));
    for (const name of ["event", "endpoint", "tenant", "traceId", "since", "until", "limit"]) {
      assert.equal(byName[name]?.in, "query", `audit ?${name}`);
      assert.equal(byName[name]?.required, false);
    }
    const replayPost = doc.paths["/dead-letter/replay"].post;
    const body = (
      replayPost.requestBody as {
        content: { "application/json": { schema: { required: string[]; properties: object } } };
      }
    ).content["application/json"].schema;
    assert.deepEqual(body.required, []);
    assert.ok("dryRun" in body.properties && "ids" in body.properties);
    const schedPost = doc.paths["/scheduled/{id}/{action}"].post;
    const schedParams = schedPost.parameters as Array<{ name: string; in: string; required: boolean }>;
    assert.deepEqual(
      schedParams.map((p) => [p.name, p.in, p.required]),
      [
        ["id", "path", true],
        ["action", "path", true],
      ]
    );
    const endpointPost = doc.paths["/config/endpoint"].post;
    const epBody = (
      endpointPost.requestBody as {
        content: { "application/json": { schema: { required: string[] } } };
      }
    ).content["application/json"].schema;
    assert.deepEqual(epBody.required, ["endpoint"]);
  });

  it("generation is deterministic", () => {
    assert.equal(
      JSON.stringify(buildOpenApiDocument()),
      JSON.stringify(buildOpenApiDocument())
    );
  });
});

describe("WR-111 GET /openapi.json endpoint", () => {
  let relay: Server;
  let port: number;
  let plainRelay: Server;
  let plainPort: number;

  function req(
    targetPort: number,
    method: string,
    path: string,
    headers: Record<string, string> = {}
  ): Promise<{ status: number; text: string; contentType: string }> {
    return new Promise((resolve, reject) => {
      const r = httpRequest({ host: "127.0.0.1", port: targetPort, path, method, headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode ?? 0,
            text: Buffer.concat(chunks).toString(),
            contentType: String(res.headers["content-type"] ?? ""),
          })
        );
      });
      r.on("error", reject);
      r.end();
    });
  }

  before(async () => {
    const dir = mkdtempSync(join(tmpdir(), "openapi-"));
    relay = createRelayServer({
      secret: "openapi-secret",
      forwardUrl: "http://127.0.0.1:9/hook",
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      operatorToken: OPERATOR_TOKEN,
    }) as unknown as Server;
    await new Promise<void>((resolve) => relay.listen(0, "127.0.0.1", resolve));
    port = (relay.address() as { port: number }).port;
    // No operator credential: the whole operator plane is fail-closed.
    const dir2 = mkdtempSync(join(tmpdir(), "openapi-"));
    plainRelay = createRelayServer({
      secret: "openapi-secret",
      forwardUrl: "http://127.0.0.1:9/hook",
      auditLog: new AuditLog(join(dir2, "audit.jsonl")),
    }) as unknown as Server;
    await new Promise<void>((resolve) => plainRelay.listen(0, "127.0.0.1", resolve));
    plainPort = (plainRelay.address() as { port: number }).port;
  });

  after(async () => {
    relay.close();
    plainRelay.close();
    await Promise.all([
      new Promise((r) => relay.once("close", r)),
      new Promise((r) => plainRelay.once("close", r)),
    ]);
  });

  const auth = { authorization: `Bearer ${OPERATOR_TOKEN}` };

  it("serves the generated document, byte-identical to buildOpenApiDocument()", async () => {
    const res = await req(port, "GET", "/openapi.json", auth);
    assert.equal(res.status, 200);
    assert.match(res.contentType, /application\/json/);
    assert.deepEqual(JSON.parse(res.text), buildOpenApiDocument());
  });

  it("is fail-closed without an operator credential (404), 403 on a bad bearer", async () => {
    const missing = await req(plainPort, "GET", "/openapi.json", auth);
    assert.equal(missing.status, 404);
    const bad = await req(port, "GET", "/openapi.json", { authorization: "Bearer wrong" });
    assert.equal(bad.status, 403);
    const none = await req(port, "GET", "/openapi.json");
    assert.equal(none.status, 403);
  });

  it("rejects non-GET methods with 405", async () => {
    const res = await req(port, "POST", "/openapi.json", auth);
    assert.equal(res.status, 405);
  });

  it("a read-scoped operator key may fetch it (WR-82)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "openapi-"));
    const scoped = createRelayServer({
      secret: "openapi-secret",
      forwardUrl: "http://127.0.0.1:9/hook",
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      operatorKeys: [{ id: "reader", key: "read-key-1", scopes: ["read"] }],
    }) as unknown as Server;
    await new Promise<void>((resolve) => scoped.listen(0, "127.0.0.1", resolve));
    const scopedPort = (scoped.address() as { port: number }).port;
    try {
      const ok = await req(scopedPort, "GET", "/openapi.json", {
        authorization: "Bearer read-key-1",
      });
      assert.equal(ok.status, 200);
      // ...but the same key cannot POST an admin route.
      const denied = await req(scopedPort, "POST", "/dead-letter/replay", {
        authorization: "Bearer read-key-1",
      });
      assert.equal(denied.status, 403);
    } finally {
      scoped.close();
      await new Promise((r) => scoped.once("close", r));
    }
  });

  it("live dispatch honors the registry: wrong method on every route is 405, never 404", async () => {
    // A concrete pathname per registry entry (path params substituted).
    const concrete: Record<string, string> = {
      "/dead-letter/{id}/replay": "/dead-letter/probe-id/replay",
      "/scheduled/{id}/{action}": "/scheduled/probe-id/pause",
      "/deliveries/{traceId}": "/deliveries/probe-trace",
    };
    for (const [path, methods] of INVENTORY) {
      const url = concrete[path] ?? path;
      const wrong = methods.includes("GET") && methods.includes("POST") ? "DELETE" : methods.includes("GET") ? "POST" : "GET";
      const res = await req(port, wrong, url, auth);
      assert.equal(
        res.status,
        405,
        `${wrong} ${url}: expected 405 (registry says ${methods.join("/")} only)`
      );
    }
  });

  it("unknown operator-ish paths still 404", async () => {
    const res = await req(port, "GET", "/dead-letter/nope/deeper", auth);
    assert.equal(res.status, 404);
  });
});
