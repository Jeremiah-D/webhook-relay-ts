import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import {
  EndpointRegistry,
  assertValidEndpointConfig,
  deliverPolicyPatch,
  diffEndpointConfigs,
  hasDeliverPolicy,
  waitForEndpointDrain,
  type EndpointConfig,
} from "../src/endpoints.ts";

const TOKEN = "endpoints-operator-token";
const TEST_KEY = "test-ingest-secret";
const BODY = Buffer.from(JSON.stringify({ event: "ping", n: 1 }));

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

async function close(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) =>
    server.close((err) => (err ? reject(err) : resolve()))
  );
}

interface HttpResult {
  status: number;
  json: unknown;
  text: string;
}

function httpJson(
  port: number,
  method: string,
  path: string,
  body?: unknown,
  token?: string
): Promise<HttpResult> {
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
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        let json: unknown = null;
        try {
          json = text === "" ? null : JSON.parse(text);
        } catch {
          json = null;
        }
        resolve({ status: res.statusCode ?? 0, json, text });
      });
    });
    r.on("error", reject);
    if (payload !== undefined) r.end(payload);
    else r.end();
  });
}

function ingest(port: number, body: Buffer = BODY): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const r = httpRequest(
      {
        host: "127.0.0.1",
        port,
        path: "/",
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-signature": signSha256(body, TEST_KEY),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, json: null, text: Buffer.concat(chunks).toString() })
        );
      }
    );
    r.on("error", reject);
    r.end(body);
  });
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
    headers: Record<string, string | string[] | undefined>;
    body: Buffer;
    respond: () => void;
  }
  const hits: Hit[] = [];
  let blocking = true;
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const hit: Hit = {
        headers: { ...req.headers },
        body: Buffer.concat(chunks),
        respond: () => res.writeHead(200).end("ok"),
      };
      hits.push(hit);
      if (!blocking) hit.respond();
    });
  });
  return {
    server,
    hits,
    setBlocking: (v: boolean) => {
      blocking = v;
    },
    releaseAll: () => {
      for (const h of hits) h.respond();
    },
  };
}

describe("EndpointRegistry (unit)", () => {
  it("accepts valid configs; id defaults to targetUrl", () => {
    const r = new EndpointRegistry([
      { targetUrl: "https://a.example/hook", maxConcurrentPerEndpoint: 4 },
      { id: "ep-b", targetUrl: "https://b.example/hook", proxy: "http://proxy:8080" },
    ]);
    assert.equal(r.size(), 2);
    assert.equal(r.get("https://a.example/hook")?.id, "https://a.example/hook");
    assert.equal(r.get("ep-b")?.targetUrl, "https://b.example/hook");
  });

  it("constructor validates everything before inserting anything", () => {
    assert.throws(
      () =>
        new EndpointRegistry([
          { targetUrl: "https://a.example/hook" },
          { targetUrl: "notaurl", maxConcurrentPerEndpoint: -2 },
        ]),
      RangeError
    );
    // The failed construction leaked nothing: a fresh registry with the
    // valid record alone works.
    const r = new EndpointRegistry([{ targetUrl: "https://a.example/hook" }]);
    assert.equal(r.size(), 1);
  });

  it("create rejects duplicates and invalid configs without mutating", () => {
    const r = new EndpointRegistry();
    r.create({ targetUrl: "https://a.example/hook" });
    assert.throws(() => r.create({ targetUrl: "https://a.example/hook" }), RangeError);
    assert.throws(() => r.create({ targetUrl: "https://a.example/hook", maxConcurrentPerEndpoint: 0 } as EndpointConfig), RangeError);
    assert.throws(() => r.create({ targetUrl: "ftp://a.example/x" } as EndpointConfig), RangeError);
    assert.equal(r.size(), 1);
  });

  it("update merges, validates the merged config, and rejects unknown ids / id changes", () => {
    const r = new EndpointRegistry([
      { id: "ep", targetUrl: "https://a.example/hook", maxConcurrentPerEndpoint: 2 },
    ]);
    const { old, new: next } = r.update("ep", { maxConcurrentPerEndpoint: 9, proxy: "http://p:8080" });
    assert.equal(old.maxConcurrentPerEndpoint, 2);
    assert.equal(next.maxConcurrentPerEndpoint, 9);
    assert.equal(next.proxy, "http://p:8080");
    assert.equal(next.targetUrl, "https://a.example/hook");
    // Invalid patch: RangeError, old record intact.
    assert.throws(() => r.update("ep", { maxConcurrentPerEndpoint: -1 }), RangeError);
    assert.equal(r.get("ep")?.maxConcurrentPerEndpoint, 9);
    assert.throws(() => r.update("nope", { proxy: "http://p:8080" }), RangeError);
    assert.throws(() => r.update("ep", { id: "other" }), RangeError);
    assert.equal(r.get("ep")?.id, "ep");
  });

  it("remove returns the record; unknown ids return undefined", () => {
    const r = new EndpointRegistry([{ id: "ep", targetUrl: "https://a.example/hook" }]);
    const removed = r.remove("ep");
    assert.equal(removed?.targetUrl, "https://a.example/hook");
    assert.equal(r.size(), 0);
    assert.equal(r.remove("ep"), undefined);
  });

  it("list exposes metadata only — secrets never leak", () => {
    const r = new EndpointRegistry([
      {
        targetUrl: "https://a.example/hook",
        verifier: { secret: "super-secret-value", keyId: "k1" },
        tlsPins: ["sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],
      },
    ]);
    const listed = r.list();
    assert.equal(listed.length, 1);
    assert.deepEqual(listed[0].verifier, { keyId: "k1" });
    assert.ok(!JSON.stringify(listed).includes("super-secret-value"));
  });

  it("getByTargetUrl and the sender resolution helpers", () => {
    const r = new EndpointRegistry([
      {
        id: "ep",
        targetUrl: "https://a.example/hook",
        verifier: { secret: "s", keyId: "k" },
        proxy: "http://p:8080",
        tlsPins: ["sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],
      },
    ]);
    assert.equal(r.getByTargetUrl("https://a.example/hook")?.id, "ep");
    assert.equal(r.getByTargetUrl("https://other.example/") , undefined);
    assert.deepEqual(r.getSigning("https://a.example/hook"), { secret: "s", keyId: "k" });
    assert.equal(r.getProxy("https://a.example/hook"), "http://p:8080");
    assert.deepEqual(r.getTlsPins("https://a.example/hook"), [
      "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    ]);
    assert.equal(r.getSigning("https://other.example/"), undefined);
  });

  it("diffEndpointConfigs diffs fields and redacts secrets", () => {
    const oldC: EndpointConfig = {
      targetUrl: "https://a.example/hook",
      verifier: { secret: "old", keyId: "k1" },
      maxConcurrentPerEndpoint: 2,
    };
    const newC: EndpointConfig = {
      targetUrl: "https://a.example/hook",
      verifier: { secret: "new", keyId: "k1" },
      maxConcurrentPerEndpoint: 5,
      proxy: "http://p:8080",
    };
    const changes = diffEndpointConfigs(oldC, newC);
    const byField = new Map(changes.map((c) => [c.field, c]));
    assert.equal(byField.get("verifier.secret")?.from, "[redacted]");
    assert.equal(byField.get("verifier.secret")?.to, "[redacted]");
    assert.deepEqual(byField.get("maxConcurrentPerEndpoint"), {
      field: "maxConcurrentPerEndpoint",
      from: 2,
      to: 5,
    });
    assert.deepEqual(byField.get("proxy"), { field: "proxy", from: null, to: "http://p:8080" });
    // Unchanged fields are absent.
    assert.ok(!byField.has("targetUrl"));
    assert.ok(!byField.has("verifier.keyId"));
    // Create: every field is an addition from null. Delete: the reverse.
    const created = diffEndpointConfigs(null, newC);
    assert.ok(created.length > 0 && created.every((c) => c.from === null));
    const deleted = diffEndpointConfigs(oldC, null);
    assert.ok(deleted.length > 0 && deleted.every((c) => c.to === null));
  });

  it("assertValidEndpointConfig rejects bad shapes", () => {
    const bad: unknown[] = [
      null,
      "x",
      {},
      { targetUrl: "" },
      { targetUrl: "notaurl" },
      { targetUrl: "gopher://a.example/" },
      { id: "", targetUrl: "https://a.example/" },
      { id: "pause", targetUrl: "https://a.example/" },
      { targetUrl: "https://a.example/", verifier: { secret: "" } },
      { targetUrl: "https://a.example/", maxConcurrentPerEndpoint: 1.5 },
      { targetUrl: "https://a.example/", circuitBreaker: { failureThreshold: 0 } },
      { targetUrl: "https://a.example/", quota: { deliveriesPerMinute: -1 } },
      { targetUrl: "https://a.example/", proxy: "https://p:8080" },
      { targetUrl: "https://a.example/", tlsPins: [] },
      { targetUrl: "https://a.example/", tlsPins: ["bogus"] },
      { targetUrl: "https://a.example/", ordered: { enabled: "yes" } },
      { targetUrl: "https://a.example/", ordered: { enabled: true, maxHeadOfLineHoldMs: -5 } },
      { targetUrl: "https://a.example/", bogusField: 1 },
    ];
    for (const cfg of bad) {
      assert.throws(() => assertValidEndpointConfig(cfg), RangeError, JSON.stringify(cfg));
    }
    // Valid shapes pass.
    assertValidEndpointConfig({ targetUrl: "https://a.example/" });
    assertValidEndpointConfig({
      id: "ep",
      targetUrl: "wss://a.example/ws",
      verifier: { secret: "s" },
      circuitBreaker: { failureThreshold: 3, cooldownMs: 1000 },
      quota: { deliveriesPerMinute: 60 },
      maxConcurrentPerEndpoint: Infinity,
      proxy: "http://p:8080",
      tlsPins: ["sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],
      ordered: { enabled: true, maxHeadOfLineHoldMs: 5000 },
    });
  });

  it("deliverPolicyPatch / hasDeliverPolicy select the WR-32 subset", () => {
    const cfg: EndpointConfig = {
      targetUrl: "https://a.example/",
      maxConcurrentPerEndpoint: 3,
      circuitBreaker: { failureThreshold: 2 },
      proxy: "http://p:8080",
    };
    assert.ok(hasDeliverPolicy(cfg));
    assert.deepEqual(deliverPolicyPatch(cfg), {
      maxConcurrentPerEndpoint: 3,
      circuitBreaker: { failureThreshold: 2 },
    });
    assert.ok(!hasDeliverPolicy({ targetUrl: "https://a.example/", proxy: "http://p:8080" }));
    assert.deepEqual(deliverPolicyPatch({ targetUrl: "https://a.example/" }), {});
  });
});

describe("waitForEndpointDrain", () => {
  it("returns drained immediately when idle", async () => {
    const res = await waitForEndpointDrain(() => [], "https://a.example/");
    assert.equal(res.drained, true);
    assert.equal(res.remaining, 0);
  });

  it("waits until the endpoint drains", async () => {
    let calls = 0;
    const res = await waitForEndpointDrain(
      () => {
        calls += 1;
        return calls < 4 ? [{ endpoint: "https://a.example/", inFlight: 1, queued: 0 }] : [];
      },
      "https://a.example/",
      { pollIntervalMs: 5 }
    );
    assert.equal(res.drained, true);
    assert.ok(calls >= 4);
  });

  it("times out with the remaining count", async () => {
    const res = await waitForEndpointDrain(
      () => [{ endpoint: "https://a.example/", inFlight: 2, queued: 1 }],
      "https://a.example/",
      { timeoutMs: 120, pollIntervalMs: 20 }
    );
    assert.equal(res.drained, false);
    assert.equal(res.remaining, 3);
    assert.ok(res.waitedMs >= 100);
  });

  it("only watches the named endpoint", async () => {
    const res = await waitForEndpointDrain(
      () => [{ endpoint: "https://other.example/", inFlight: 5, queued: 5 }],
      "https://a.example/"
    );
    assert.equal(res.drained, true);
  });

  it("rejects invalid options", async () => {
    await assert.rejects(
      waitForEndpointDrain(() => [], "https://a.example/", { timeoutMs: 0 }),
      RangeError
    );
    await assert.rejects(
      waitForEndpointDrain(() => [], "https://a.example/", { pollIntervalMs: -1 }),
      RangeError
    );
  });
});

describe("operator API: endpoint registry (WR-114)", () => {
  const servers: Server[] = [];
  afterEach(async () => {
    while (servers.length > 0) await close(servers.pop()!);
  });

  async function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "endpoints-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: TEST_KEY,
      forwardUrl: "http://127.0.0.1:9/unused",
      auditLog: audit,
      operatorToken: TOKEN,
      ...extra,
    } as Parameters<typeof createRelayServer>[0]);
    servers.push(relay);
    return { port: await listen(relay), audit };
  }

  const post = (port: number, body: unknown, token: string | undefined = TOKEN) =>
    httpJson(port, "POST", "/endpoints", body, token);
  const put = (port: number, id: string, body: unknown, token: string | undefined = TOKEN) =>
    httpJson(port, "PUT", `/endpoints/${id}`, body, token);
  const del = (port: number, id: string, opts: { force?: boolean; body?: unknown; token?: string } = {}) =>
    httpJson(
      port,
      "DELETE",
      `/endpoints/${id}${opts.force === true ? "?force=true" : ""}`,
      opts.body,
      opts.token ?? TOKEN
    );
  const list = (port: number, token: string | undefined = TOKEN) =>
    httpJson(port, "GET", "/endpoints", undefined, token);

  it("POST creates (201), GET lists metadata without secrets, create is audited", async () => {
    const { port, audit } = await makeRelay();
    const res = await post(port, {
      id: "ep-1",
      targetUrl: "https://downstream.example/hook",
      verifier: { secret: "downstream-signing-key", keyId: "k1" },
      maxConcurrentPerEndpoint: 4,
      proxy: "http://proxy:8080",
    });
    assert.equal(res.status, 201);
    const created = res.json as { id: string; targetUrl: string; endpoint: Record<string, unknown> };
    assert.equal(created.id, "ep-1");
    assert.equal(created.targetUrl, "https://downstream.example/hook");
    assert.deepEqual(created.endpoint.verifier, { keyId: "k1" });

    const listed = await list(port);
    assert.equal(listed.status, 200);
    const endpoints = (listed.json as { endpoints: unknown[] }).endpoints;
    assert.equal(endpoints.length, 1);
    assert.ok(!JSON.stringify(listed.json).includes("downstream-signing-key"));

    const events = audit.query({ event: "endpoint_config_updated" }) as Array<{
      endpointId: string;
      operation: string;
      keyId: string;
      changes: Array<{ field: string; from: unknown; to: unknown }>;
    }>;
    const createdEvents = events.filter((e) => e.operation === "created");
    assert.equal(createdEvents.length, 1);
    assert.equal(createdEvents[0].endpointId, "ep-1");
    assert.equal(createdEvents[0].keyId, "legacy");
    const fields = new Map(createdEvents[0].changes.map((c) => [c.field, c]));
    assert.equal(fields.get("verifier.secret")?.to, "[redacted]");
    assert.equal(fields.get("maxConcurrentPerEndpoint")?.to, 4);
  });

  it("POST applies deliver-policy through the WR-32 path (queue-level audit too)", async () => {
    const { port, audit } = await makeRelay({
      retry: {
        maxConcurrentPerEndpoint: 4,
        circuitBreaker: { failureThreshold: 5 },
        quota: { deliveriesPerMinute: 60 },
      },
    });
    const target = "https://downstream.example/hook";
    const res = await post(port, { targetUrl: target, maxConcurrentPerEndpoint: 8 });
    assert.equal(res.status, 201);
    // The WR-32 queue hook fires with the field-level diff, alongside the
    // registry-level created event.
    const events = audit.query({ event: "endpoint_config_updated" }) as Array<{
      operation?: string;
      endpoint: string;
      keyId?: string;
      changes: Array<{ field: string; from: unknown; to: unknown }>;
    }>;
    const queueLevel = events.filter((e) => e.operation === undefined);
    assert.equal(queueLevel.length, 1);
    assert.equal(queueLevel[0].endpoint, target);
    assert.equal(queueLevel[0].keyId, "legacy");
    assert.deepEqual(queueLevel[0].changes, [
      { field: "maxConcurrentPerEndpoint", from: 4, to: 8 },
    ]);
  });

  it("POST rejects invalid configs with 400 and changes nothing", async () => {
    const { port } = await makeRelay();
    const badBodies: unknown[] = [
      {},
      { targetUrl: "notaurl" },
      { targetUrl: "https://a.example/", maxConcurrentPerEndpoint: -1 },
      { targetUrl: "https://a.example/", circuitBreaker: { failureThreshold: 0 } },
      { targetUrl: "https://a.example/", proxy: "socks5://p:1080" },
      { targetUrl: "https://a.example/", nope: true },
    ];
    for (const body of badBodies) {
      const res = await post(port, body);
      assert.equal(res.status, 400, JSON.stringify(body));
    }
    // Duplicate id is a 400 as well.
    assert.equal((await post(port, { id: "dup", targetUrl: "https://a.example/" })).status, 201);
    assert.equal((await post(port, { id: "dup", targetUrl: "https://b.example/" })).status, 400);
    const listed = (await list(port)).json as { endpoints: unknown[] };
    assert.equal(listed.endpoints.length, 1);
  });

  it("POST rolls the registry record back when the queue refuses the policy", async () => {
    // No circuit breaker configured: the deliver-policy apply throws,
    // so the 400 must mean "nothing changed" end to end.
    const { port, audit } = await makeRelay();
    const res = await post(port, {
      targetUrl: "https://a.example/",
      circuitBreaker: { failureThreshold: 2 },
    });
    assert.equal(res.status, 400);
    const listed = (await list(port)).json as { endpoints: unknown[] };
    assert.equal(listed.endpoints.length, 0);
    assert.equal(audit.query({ event: "endpoint_config_updated" }).length, 0);
  });

  it("PUT updates config, returns the diff, and audits", async () => {
    const { port, audit } = await makeRelay({
      retry: { maxConcurrentPerEndpoint: 4, quota: { deliveriesPerMinute: 60 } },
    });
    await post(port, {
      id: "ep-1",
      targetUrl: "https://a.example/",
      maxConcurrentPerEndpoint: 4,
      proxy: "http://p1:8080",
    });
    const res = await put(port, "ep-1", {
      maxConcurrentPerEndpoint: 10,
      quota: { deliveriesPerMinute: 120 },
    });
    assert.equal(res.status, 200);
    const body = res.json as {
      changes: Array<{ field: string; from: unknown; to: unknown }>;
      endpoint: { maxConcurrentPerEndpoint: number; proxy: string };
    };
    const fields = new Map(body.changes.map((c) => [c.field, c]));
    assert.deepEqual(fields.get("maxConcurrentPerEndpoint"), {
      field: "maxConcurrentPerEndpoint",
      from: 4,
      to: 10,
    });
    assert.deepEqual(fields.get("quota.deliveriesPerMinute"), {
      field: "quota.deliveriesPerMinute",
      from: null,
      to: 120,
    });
    assert.ok(!fields.has("proxy"));
    assert.equal(body.endpoint.maxConcurrentPerEndpoint, 10);

    const events = audit.query({ event: "endpoint_config_updated" }) as Array<{ operation?: string }>;
    assert.ok(events.some((e) => e.operation === "updated"));
  });

  it("PUT: unknown id 404s; invalid values 400 with the old config intact; ordered 400s", async () => {
    const { port } = await makeRelay();
    await post(port, { id: "ep-1", targetUrl: "https://a.example/", maxConcurrentPerEndpoint: 4 });
    assert.equal((await put(port, "nope", { maxConcurrentPerEndpoint: 2 })).status, 404);
    assert.equal((await put(port, "ep-1", { maxConcurrentPerEndpoint: -3 })).status, 400);
    assert.equal((await put(port, "ep-1", { ordered: { enabled: true } })).status, 400);
    assert.equal((await put(port, "ep-1", { id: "other" })).status, 400);
    const listed = (await list(port)).json as {
      endpoints: Array<{ id: string; maxConcurrentPerEndpoint: number; ordered?: unknown }>;
    };
    assert.equal(listed.endpoints[0].maxConcurrentPerEndpoint, 4);
    assert.equal(listed.endpoints[0].ordered, undefined);
  });

  it("PUT with a targetUrl change re-keys the deliver-policy overrides", async () => {
    const { port, audit } = await makeRelay({ retry: { maxConcurrentPerEndpoint: 4 } });
    await post(port, { id: "ep-1", targetUrl: "https://a.example/", maxConcurrentPerEndpoint: 3 });
    const res = await put(port, "ep-1", {
      targetUrl: "https://b.example/",
      maxConcurrentPerEndpoint: 7,
    });
    assert.equal(res.status, 200);
    const body = res.json as { targetUrl: string; changes: Array<{ field: string }> };
    assert.equal(body.targetUrl, "https://b.example/");
    assert.ok(body.changes.some((c) => c.field === "targetUrl"));
    // The new endpoint's policy applied through WR-32 (queue-level audit
    // shows the new targetUrl with the new limit).
    const events = audit.query({ event: "endpoint_config_updated" }) as Array<{
      operation?: string;
      endpoint: string;
      changes: Array<{ field: string; to: unknown }>;
    }>;
    const applied = events.filter(
      (e) => e.operation === undefined && e.endpoint === "https://b.example/"
    );
    assert.equal(applied.length, 1);
    assert.deepEqual(
      applied[0].changes.map((c) => [c.field, c.to]),
      [["maxConcurrentPerEndpoint", 7]]
    );
  });

  it("DELETE drains in-flight deliveries before removing", async () => {
    const stub = blockingStub();
    const stubPort = await listen(stub.server);
    servers.push(stub.server);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const { port, audit } = await makeRelay({ forwardUrl: target });
    await post(port, { targetUrl: target, maxConcurrentPerEndpoint: 2 });

    const ingested = await ingest(port);
    assert.equal(ingested.status, 202);
    await waitFor(() => stub.hits.length >= 1, 5000, "delivery attempt started");

    let deleteDone = false;
    const delPromise = del(port, encodeURIComponent(target)).then((r) => {
      deleteDone = true;
      return r;
    });
    // The DELETE waits for the drain: still pending while the downstream holds the attempt.
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(deleteDone, false);
    assert.equal(stub.hits.length, 1);
    stub.releaseAll();
    const res = await delPromise;
    assert.equal(res.status, 200);
    const body = res.json as { deleted: boolean; drained: boolean; waitedMs: number };
    assert.equal(body.deleted, true);
    assert.equal(body.drained, true);
    assert.ok(body.waitedMs >= 250);
    const listed = (await list(port)).json as { endpoints: unknown[] };
    assert.equal(listed.endpoints.length, 0);
    const deleted = audit.query({ event: "endpoint_config_updated" }) as Array<{ operation?: string }>;
    assert.ok(deleted.some((e) => e.operation === "deleted"));
  });

  it("DELETE with ?force=true skips the drain", async () => {
    const stub = blockingStub();
    const stubPort = await listen(stub.server);
    servers.push(stub.server);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const { port } = await makeRelay({ forwardUrl: target });
    await post(port, { targetUrl: target });

    const ingested = await ingest(port);
    assert.equal(ingested.status, 202);
    await waitFor(() => stub.hits.length >= 1, 5000, "delivery attempt started");

    const res = await del(port, encodeURIComponent(target), { force: true });
    assert.equal(res.status, 200);
    assert.equal((res.json as { deleted: boolean }).deleted, true);
    assert.equal((res.json as { drained: boolean }).drained, false);
    stub.releaseAll();
    const listed = (await list(port)).json as { endpoints: unknown[] };
    assert.equal(listed.endpoints.length, 0);
  });

  it("DELETE answers 409 when the drain times out", async () => {
    const stub = blockingStub();
    const stubPort = await listen(stub.server);
    servers.push(stub.server);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const { port } = await makeRelay({ forwardUrl: target, endpointDrainTimeoutMs: 250 });
    await post(port, { targetUrl: target });

    const ingested = await ingest(port);
    assert.equal(ingested.status, 202);
    await waitFor(() => stub.hits.length >= 1, 5000, "delivery attempt started");

    const res = await del(port, encodeURIComponent(target));
    assert.equal(res.status, 409);
    assert.equal((res.json as { inFlight: number }).inFlight, 1);
    // The record survives the failed delete.
    const listed = (await list(port)).json as { endpoints: unknown[] };
    assert.equal(listed.endpoints.length, 1);
    stub.releaseAll();
  });

  it("DELETE of an unknown id 404s", async () => {
    const { port } = await makeRelay();
    assert.equal((await del(port, "nope")).status, 404);
  });

  it("fails closed without an operator credential; wrong bearer is 403", async () => {
    const dir = mkdtempSync(join(tmpdir(), "endpoints-nocred-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({ secret: TEST_KEY, forwardUrl: "http://127.0.0.1:9/x", auditLog: audit });
    servers.push(relay);
    const port = await listen(relay);
    for (const [method, path, body] of [
      ["GET", "/endpoints", undefined],
      ["POST", "/endpoints", { targetUrl: "https://a.example/" }],
      ["PUT", "/endpoints/x", { proxy: "http://p:8080" }],
      ["DELETE", "/endpoints/x", undefined],
    ] as Array<[string, string, unknown]>) {
      const res = await httpJson(port, method, path, body, TOKEN);
      assert.equal(res.status, 404, `${method} ${path}`);
    }
    // Wrong bearer on a credentialed relay is 403.
    const { port: port2 } = await makeRelay();
    const bad = await post(port2, { targetUrl: "https://a.example/" }, "wrong-token");
    assert.equal(bad.status, 403);
    const noToken = await httpJson(port2, "GET", "/endpoints");
    assert.equal(noToken.status, 403);
  });

  it("read-scoped operator keys can list but not mutate", async () => {
    const { port } = await makeRelay({
      operatorToken: undefined,
      operatorKeys: [{ id: "reader", key: "reader-key", scopes: ["read"] }],
    });
    const listed = await list(port, "reader-key");
    assert.equal(listed.status, 200);
    assert.equal((await post(port, { targetUrl: "https://a.example/" }, "reader-key")).status, 403);
    assert.equal((await put(port, "x", { proxy: "http://p:8080" }, "reader-key")).status, 403);
    assert.equal((await del(port, "x", { token: "reader-key" })).status, 403);
  });

  it("wrong methods answer 405; /endpoints/pause still routes to pause", async () => {
    const { port } = await makeRelay();
    assert.equal((await httpJson(port, "PUT", "/endpoints", {}, TOKEN)).status, 405);
    assert.equal((await httpJson(port, "GET", "/endpoints/x", undefined, TOKEN)).status, 405);
    assert.equal((await httpJson(port, "DELETE", "/endpoints", undefined, TOKEN)).status, 405);
    // The pre-existing pause route is unaffected by the /endpoints/{id} pattern.
    const pause = await httpJson(port, "POST", "/endpoints/pause", { endpoint: "x" }, TOKEN);
    assert.equal(pause.status, 404); // unknown endpoint, but routed to pause — not to the registry
    assert.ok(!(pause.json as { error: string }).error.includes("unknown endpoint id"));
  });

  it("in-flight deliveries keep the config they started with across a registry update", async () => {
    const stub = blockingStub();
    const stubPort = await listen(stub.server);
    servers.push(stub.server);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const { port } = await makeRelay({
      forwardUrl: target,
      endpoints: [{ targetUrl: target, verifier: { secret: "old-signing-key", keyId: "k1" } }],
    });

    const ingested = await ingest(port);
    assert.equal(ingested.status, 202);
    await waitFor(() => stub.hits.length >= 1, 5000, "first delivery attempt started");

    // Rotate the signing secret mid-flight.
    const updated = await put(port, encodeURIComponent(target), {
      verifier: { secret: "new-signing-key", keyId: "k2" },
    });
    assert.equal(updated.status, 200);

    stub.releaseAll();
    await waitFor(() => stub.hits.length >= 1, 5000, "first attempt recorded");
    const first = stub.hits[0];
    // The in-flight attempt signed with the OLD secret.
    assert.equal(first.headers["x-relay-signature"], signSha256(first.body, "old-signing-key"));
    assert.equal(first.headers["x-relay-key-id"], "k1");

    // A new delivery after the update signs with the NEW secret.
    stub.setBlocking(false);
    const ingested2 = await ingest(port);
    assert.equal(ingested2.status, 202);
    await waitFor(() => stub.hits.length >= 2, 5000, "second delivery attempt");
    const second = stub.hits[1];
    assert.equal(second.headers["x-relay-signature"], signSha256(second.body, "new-signing-key"));
    assert.equal(second.headers["x-relay-key-id"], "k2");
  });

  it("startup: static endpoints are validated, applied, and ordered is folded", async () => {
    // Invalid static config fails fast at startup.
    const mkAudit = () => new AuditLog(join(mkdtempSync(join(tmpdir(), "endpoints-a-")), "audit.jsonl"));
    assert.throws(
      () =>
        createRelayServer({
          secret: TEST_KEY,
          forwardUrl: "http://127.0.0.1:9/x",
          auditLog: mkAudit(),
          endpoints: [{ targetUrl: "notaurl" }],
        }),
      RangeError
    );
    // Deliver-policy for a disabled subsystem fails fast with zero partial application.
    assert.throws(
      () =>
        createRelayServer({
          secret: TEST_KEY,
          forwardUrl: "http://127.0.0.1:9/x",
          auditLog: mkAudit(),
          endpoints: [
            { targetUrl: "https://a.example/", maxConcurrentPerEndpoint: 2 },
            { targetUrl: "https://b.example/", circuitBreaker: { failureThreshold: 2 } },
          ],
        }),
      (err: unknown) =>
        err instanceof RangeError && err.message.includes("deliver policy"),
      "expected a deliver-policy RangeError"
    );
    // Ordered in both static config and the registry is a conflict.
    assert.throws(
      () =>
        createRelayServer({
          secret: TEST_KEY,
          forwardUrl: "http://127.0.0.1:9/x",
          auditLog: mkAudit(),
          retry: { ordered: { "https://a.example/": true } },
          endpoints: [{ targetUrl: "https://a.example/", ordered: { enabled: true } }],
        }),
      RangeError
    );
    // A valid static record applies its deliver-policy at startup (audited
    // by the queue's onConfigChange hook, without an operator keyId).
    const audit = mkAudit();
    const relay = createRelayServer({
      secret: TEST_KEY,
      forwardUrl: "http://127.0.0.1:9/x",
      auditLog: audit,
      operatorToken: TOKEN,
      retry: { maxConcurrentPerEndpoint: 4 },
      endpoints: [
        {
          targetUrl: "https://a.example/",
          maxConcurrentPerEndpoint: 2,
          ordered: { enabled: true, maxHeadOfLineHoldMs: 5000 },
        },
      ],
    });
    servers.push(relay);
    const port = await listen(relay);
    const events = audit.query({ event: "endpoint_config_updated" }) as Array<{
      endpoint: string;
      keyId?: string;
      changes: Array<{ field: string; from: unknown; to: unknown }>;
    }>;
    assert.equal(events.length, 1);
    assert.equal(events[0].endpoint, "https://a.example/");
    assert.equal(events[0].keyId, undefined);
    assert.deepEqual(events[0].changes, [{ field: "maxConcurrentPerEndpoint", from: 4, to: 2 }]);
    const listed = (await list(port)).json as {
      endpoints: Array<{ targetUrl: string; ordered: { enabled: boolean } }>;
    };
    assert.equal(listed.endpoints.length, 1);
    assert.deepEqual(listed.endpoints[0].ordered, { enabled: true, maxHeadOfLineHoldMs: 5000 });
  });

  it("an empty static config is behaviorally invisible", async () => {
    const stub = blockingStub();
    stub.setBlocking(false);
    const stubPort = await listen(stub.server);
    servers.push(stub.server);
    const target = `http://127.0.0.1:${stubPort}/hook`;
    const { port } = await makeRelay({ forwardUrl: target, endpoints: [] });
    const listed = (await list(port)).json as { endpoints: unknown[] };
    assert.deepEqual(listed.endpoints, []);
    const ingested = await ingest(port);
    assert.equal(ingested.status, 202);
    await waitFor(() => stub.hits.length >= 1, 5000, "delivery through the default sender");
    // No relay signature without any signing configured — the sender's
    // resolution is byte-identical to the pre-WR-114 path.
    assert.equal(stub.hits[0].headers["x-relay-signature"], undefined);
  });
});
