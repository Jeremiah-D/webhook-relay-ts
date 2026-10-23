import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";
import {
  OperatorAuditLog,
  assertValidOperatorAuditLogOptions,
  DEFAULT_OPERATOR_AUDIT_MAX_ENTRIES,
} from "../src/operator-audit.ts";

const URL = "http://localhost:9999/hook";
const relaySecret = "relay-secret";
const TOKEN = "op-token";

function manualClock(start = 0) {
  let t = start;
  return {
    now: () => t,
    advance: (ms: number) => {
      t += ms;
    },
  };
}

describe("OperatorAuditLog", () => {
  it("records entries with seq and ISO timestamps", () => {
    const clock = manualClock(1_700_000_000_000);
    const log = new OperatorAuditLog({ now: clock.now });
    const e1 = log.record({ keyId: "admin", action: "endpoints.pause", target: URL });
    const e2 = log.record({
      keyId: "admin",
      action: "endpoints.resume",
      target: URL,
      before: { paused: true },
      after: { paused: false },
    });
    assert.equal(e1.seq, 1);
    assert.equal(e2.seq, 2);
    assert.equal(e1.at, new Date(1_700_000_000_000).toISOString());
    assert.equal(e1.result, "ok");
    assert.deepEqual(e2.before, { paused: true });
    assert.deepEqual(e2.after, { paused: false });
    assert.deepEqual(log.stats(), { entries: 2, maxEntries: DEFAULT_OPERATOR_AUDIT_MAX_ENTRIES });
  });

  it("rejects empty keyId/action", () => {
    const log = new OperatorAuditLog();
    assert.throws(() => log.record({ keyId: "", action: "x" }), RangeError);
    assert.throws(() => log.record({ keyId: "a", action: "" }), RangeError);
  });

  it("queries newest-first, filterable by keyId and action", () => {
    const log = new OperatorAuditLog();
    log.record({ keyId: "a", action: "endpoints.pause", target: URL });
    log.record({ keyId: "b", action: "endpoints.pause", target: URL });
    log.record({ keyId: "a", action: "config.endpoint.update", target: URL });
    assert.deepEqual(
      log.query({ keyId: "a" }).map((e) => e.action),
      ["config.endpoint.update", "endpoints.pause"]
    );
    assert.deepEqual(
      log.query({ action: "endpoints.pause" }).map((e) => e.keyId),
      ["b", "a"]
    );
    assert.deepEqual(
      log.query({ keyId: "a", action: "endpoints.pause" }).map((e) => e.seq),
      [1]
    );
    assert.deepEqual(log.query({ keyId: "nobody" }), []);
  });

  it("limits results (default 100) and rejects non-positive limits", () => {
    const log = new OperatorAuditLog();
    for (let i = 0; i < 5; i++) log.record({ keyId: "a", action: `act${i}` });
    assert.equal(log.query().length, 5);
    assert.equal(log.query({ limit: 2 }).length, 2);
    assert.equal(log.query({ limit: 2 })[0].action, "act4");
    assert.deepEqual(log.query({ limit: 0 }), []);
    assert.deepEqual(log.query({ limit: -3 }), []);
  });

  it("evicts the oldest entries past maxEntries", () => {
    const log = new OperatorAuditLog({ maxEntries: 3 });
    for (let i = 0; i < 5; i++) log.record({ keyId: "a", action: `act${i}` });
    assert.deepEqual(log.stats(), { entries: 3, maxEntries: 3 });
    assert.deepEqual(
      log.query().map((e) => e.action),
      ["act4", "act3", "act2"]
    );
  });

  it("validates options", () => {
    assert.throws(() => assertValidOperatorAuditLogOptions(null), RangeError);
    assert.throws(() => assertValidOperatorAuditLogOptions([]), RangeError);
    assert.throws(() => assertValidOperatorAuditLogOptions({ maxEntries: 0 }), RangeError);
    assert.throws(() => assertValidOperatorAuditLogOptions({ maxEntries: 1.5 }), RangeError);
    assert.throws(() => assertValidOperatorAuditLogOptions({ now: 42 }), RangeError);
    assertValidOperatorAuditLogOptions({});
    assertValidOperatorAuditLogOptions({ maxEntries: 10 });
  });
});

describe("relay operator audit integration", () => {
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

  function req(port: number, method: string, path: string, body?: unknown, token?: string) {
    return new Promise<{ status: number; json: unknown }>((resolve, reject) => {
      const headers: Record<string, string> = { "content-type": "application/json" };
      if (token !== undefined) headers["authorization"] = `Bearer ${token}`;
      const r = httpRequest({ host: "127.0.0.1", port, path, method, headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, json: JSON.parse(Buffer.concat(chunks).toString() || "{}") })
        );
      });
      r.on("error", reject);
      r.end(body === undefined ? undefined : JSON.stringify(body));
    });
  }

  async function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "op-audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: relaySecret,
      forwardUrl: URL,
      auditLog: audit,
      operatorToken: TOKEN,
      sender: async () => {},
      retry: { baseDelayMs: 10, maxAttempts: 3, jitterMs: 0 },
      ...extra,
    });
    servers.push(relay);
    return { port: await listen(relay), audit };
  }

  type Entry = {
    seq: number;
    at: string;
    keyId: string;
    action: string;
    target?: string;
    before?: unknown;
    after?: unknown;
    result: string;
  };

  async function operatorAudit(port: number, qs = "", token: string = TOKEN) {
    const res = await req(port, "GET", `/operator-audit${qs}`, undefined, token);
    assert.equal(res.status, 200);
    return (res.json as { entries: Entry[] }).entries;
  }

  it("records pause/resume with actor keyId and before/after diff", async () => {
    const { port } = await makeRelay();
    const paused = await req(port, "POST", "/endpoints/pause", { endpoint: URL }, TOKEN);
    assert.equal(paused.status, 200);
    const resumed = await req(port, "POST", "/endpoints/resume", { endpoint: URL }, TOKEN);
    assert.equal(resumed.status, 200);

    const entries = await operatorAudit(port);
    assert.equal(entries.length, 2);
    // Newest first.
    assert.equal(entries[0].action, "endpoints.resume");
    assert.equal(entries[0].keyId, "legacy");
    assert.equal(entries[0].target, URL);
    assert.deepEqual(entries[0].before, { paused: true });
    assert.deepEqual(entries[0].after, { paused: false });
    assert.equal(entries[1].action, "endpoints.pause");
    assert.deepEqual(entries[1].before, { paused: false });
    assert.deepEqual(entries[1].after, { paused: true });
    for (const e of entries) {
      assert.equal(e.result, "ok");
      assert.ok(typeof e.seq === "number" && e.seq > 0);
      assert.ok(!Number.isNaN(Date.parse(e.at)));
    }
  });

  it("records endpoint enable and config reloads", async () => {
    const { port } = await makeRelay();
    const enabled = await req(port, "POST", "/endpoints/enable", { endpoint: URL }, TOKEN);
    assert.equal(enabled.status, 200);
    const updated = await req(
      port,
      "POST",
      "/config/endpoint",
      { endpoint: URL, maxConcurrentPerEndpoint: 7 },
      TOKEN
    );
    assert.equal(updated.status, 200);

    const entries = await operatorAudit(port);
    const byAction = Object.fromEntries(entries.map((e) => [e.action, e]));
    assert.equal(byAction["endpoints.enable"].keyId, "legacy");
    assert.deepEqual(byAction["endpoints.enable"].before, { disabled: false });
    assert.deepEqual(byAction["endpoints.enable"].after, { disabled: false });
    assert.equal(byAction["config.endpoint.update"].target, URL);
    assert.equal(
      (byAction["config.endpoint.update"].after as Record<string, unknown>).maxConcurrentPerEndpoint,
      7
    );
    assert.ok("maxConcurrentPerEndpoint" in (byAction["config.endpoint.update"].before as object));
  });

  it("records version-sunset changes with before/after", async () => {
    const { port } = await makeRelay({
      versions: {
        routes: [{ prefix: "/v1", adapter: { version: "v1", adapt: (p: Buffer) => p } }],
      },
    });
    const set = await req(
      port,
      "POST",
      "/config/version-sunset",
      { prefix: "/v1", sunsetAt: "2030-01-01T00:00:00.000Z" },
      TOKEN
    );
    assert.equal(set.status, 200);
    const entries = await operatorAudit(port, "?action=config.version-sunset.set");
    assert.equal(entries.length, 1);
    assert.equal(entries[0].target, "/v1");
    assert.deepEqual(entries[0].before, { sunsetAt: null });
    assert.deepEqual(entries[0].after, { sunsetAt: "2030-01-01T00:00:00.000Z" });
  });

  it("filters by keyId and action, validates limit", async () => {
    const { port } = await makeRelay();
    await req(port, "POST", "/endpoints/pause", { endpoint: URL }, TOKEN);
    await req(port, "POST", "/endpoints/resume", { endpoint: URL }, TOKEN);

    assert.equal((await operatorAudit(port, "?keyId=legacy")).length, 2);
    assert.equal((await operatorAudit(port, "?keyId=nobody")).length, 0);
    assert.equal((await operatorAudit(port, "?action=endpoints.pause")).length, 1);
    assert.equal((await operatorAudit(port, "?limit=1")).length, 1);
    const bad = await req(port, "GET", "/operator-audit?limit=nope", undefined, TOKEN);
    assert.equal(bad.status, 400);
  });

  it("stamps the acting scoped key's id, not the legacy token", async () => {
    const { port } = await makeRelay({
      operatorToken: undefined,
      operatorKeys: [
        { id: "ops1", key: "ops1-key", scopes: ["admin"] },
        { id: "reader1", key: "reader1-key", scopes: ["read"] },
      ],
    });
    const paused = await req(port, "POST", "/endpoints/pause", { endpoint: URL }, "ops1-key");
    assert.equal(paused.status, 200);
    const asReader = await operatorAudit(port, "", "reader1-key");
    assert.equal(asReader.length, 1);
    assert.equal(asReader[0].keyId, "ops1");
    assert.equal(asReader[0].action, "endpoints.pause");
    // A read-scoped key cannot mutate.
    const denied = await req(port, "POST", "/endpoints/resume", { endpoint: URL }, "reader1-key");
    assert.equal(denied.status, 403);
    assert.equal((await operatorAudit(port, "", "reader1-key")).length, 1);
  });

  it("records operator key revocation via config snapshot", async () => {
    const { port } = await makeRelay({
      operatorToken: undefined,
      operatorKeys: [
        { id: "admin", key: "admin-key", scopes: ["admin"] },
        { id: "victim", key: "victim-key", scopes: ["read"] },
      ],
    });
    const get = await req(port, "GET", "/config/snapshot", undefined, "admin-key");
    assert.equal(get.status, 200);
    const snapshot = JSON.parse(JSON.stringify((get.json as { snapshot: unknown }).snapshot)) as {
      inventory?: Record<string, unknown>;
    };
    snapshot.inventory = { ...(snapshot.inventory ?? {}), revokedOperatorKeys: ["victim"] };
    const applied = await req(port, "POST", "/config/snapshot", { snapshot }, "admin-key");
    assert.equal(applied.status, 200);

    const entries = await operatorAudit(port, "?action=operator.key.revoke", "admin-key");
    assert.equal(entries.length, 1);
    assert.equal(entries[0].keyId, "admin");
    assert.equal(entries[0].target, "victim");
    assert.deepEqual(entries[0].before, { revoked: false });
    assert.deepEqual(entries[0].after, { revoked: true });
    // The revoked key is dead: it now authenticates like a wrong key.
    const dead = await req(port, "GET", "/operator-audit", undefined, "victim-key");
    assert.equal(dead.status, 403);
  });

  it("is separate from the delivery audit stream", async () => {
    const { port, audit } = await makeRelay();
    await req(port, "POST", "/endpoints/pause", { endpoint: URL }, TOKEN);
    // The scattered delivery-stream event still exists...
    assert.equal(audit.query({ event: "endpoint_paused" }).length, 1);
    // ...and the centralized ledger has its own entry too.
    const entries = await operatorAudit(port, "?action=endpoints.pause");
    assert.equal(entries.length, 1);
    assert.equal(entries[0].keyId, "legacy");
  });

  it("404s when no operator credential is configured, 403 on a bad bearer", async () => {
    const dir = mkdtempSync(join(tmpdir(), "op-audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: relaySecret,
      forwardUrl: URL,
      auditLog: audit,
      sender: async () => {},
    });
    servers.push(relay);
    const port = await listen(relay);
    const disabled = await req(port, "GET", "/operator-audit");
    assert.equal(disabled.status, 404);

    const { port: port2 } = await makeRelay();
    const wrong = await req(port2, "GET", "/operator-audit", undefined, "wrong");
    assert.equal(wrong.status, 403);
  });
});
