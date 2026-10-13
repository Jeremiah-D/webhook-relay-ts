import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";
import {
  exportConfig,
  applyConfig,
  detectConfigDrift,
  ConfigApplyError,
  CONFIG_SNAPSHOT_FORMAT,
  CONFIG_SNAPSHOT_VERSION,
  type ConfigSnapshot,
} from "../src/config-snapshot.ts";

const URL_A = "http://localhost:9999/hook-a";
const URL_B = "http://localhost:9999/hook-b";
const TOKEN = "op-token";

const okSender: Sender = async () => {};

function makeQueue(extra: Record<string, unknown> = {}): RetryQueue {
  return new RetryQueue({ sender: okSender, ...extra });
}

function baseSnapshot(q: RetryQueue, nowMs = () => 1_700_000_000_000): ConfigSnapshot {
  return exportConfig(q, { nowMs });
}

describe("exportConfig", () => {
  it("captures hot-reloadable config per endpoint and queue-global retry", () => {
    const q = makeQueue({
      baseDelayMs: 1000,
      maxAttempts: 5,
      jitterMs: 0,
      maxConcurrentPerEndpoint: 4,
      circuitBreaker: { failureThreshold: 5, cooldownMs: 30_000 },
      quota: { deliveriesPerMinute: 60 },
    });
    q.updateEndpointConfig(URL_A, {
      maxConcurrentPerEndpoint: 8,
      circuitBreaker: { failureThreshold: 2 },
      quota: { deliveriesPerMinute: 120 },
    });
    const snap = baseSnapshot(q);
    assert.equal(snap.format, CONFIG_SNAPSHOT_FORMAT);
    assert.equal(snap.version, CONFIG_SNAPSHOT_VERSION);
    assert.equal(snap.takenAtMs, 1_700_000_000_000);
    assert.deepEqual(snap.retry, {
      baseDelayMs: 1000,
      maxDelayMs: 60_000,
      maxAttempts: 5,
      jitterMs: 0,
      jitterStrategy: "additive",
    });
    const row = snap.endpoints[URL_A];
    assert.equal(row.maxConcurrentPerEndpoint, 8);
    // Partial circuit override: only failureThreshold overridden; the
    // cooldown falls back to the constructor default but the row keeps
    // the effective value (it is an override row).
    assert.deepEqual(row.circuitBreaker, { failureThreshold: 2, cooldownMs: 30_000 });
    assert.deepEqual(row.quota, { deliveriesPerMinute: 120 });
    // An endpoint with no overrides is absent from the keyspace.
    assert.equal(snap.endpoints[URL_B], undefined);
  });

  it("encodes Infinity as a JSON-safe string and round-trips", () => {
    const q = makeQueue({});
    q.updateEndpointConfig(URL_A, { maxConcurrentPerEndpoint: Infinity });
    const snap = baseSnapshot(q);
    assert.equal(snap.endpoints[URL_A].maxConcurrentPerEndpoint, "Infinity");
    // Valid JSON: JSON.stringify never sees a real Infinity.
    const revived = JSON.parse(JSON.stringify(snap)) as ConfigSnapshot;
    assert.equal(revived.endpoints[URL_A].maxConcurrentPerEndpoint, "Infinity");
  });

  it("scopes rows per tenant (WR-48)", () => {
    const q = makeQueue({ maxConcurrentPerEndpoint: 4 });
    q.updateEndpointConfig(URL_A, { maxConcurrentPerEndpoint: 7 }, "acme");
    q.updateEndpointConfig(URL_A, { maxConcurrentPerEndpoint: 9 });
    const snap = baseSnapshot(q);
    assert.equal(snap.endpoints[URL_A].maxConcurrentPerEndpoint, 9);
    assert.equal(snap.endpoints["acme\n" + URL_A].maxConcurrentPerEndpoint, 7);
  });

  it("omits inventory when no provider is supplied", () => {
    const q = makeQueue({});
    assert.equal(baseSnapshot(q).inventory, null);
  });

  it("carries key inventory as identifiers only, never key bytes", () => {
    const q = makeQueue({});
    const snap = exportConfig(q, {
      readInventory: () => ({
        routing: null,
        signingKeys: [{ id: "k1" }],
        mtls: { [URL_A]: { certIdentity: "deadbeef" } },
        tlsPins: {},
        proxies: { [URL_A]: { configured: true, hasCredentials: true } },
        compression: {},
        tenants: [],
      }),
    });
    const text = JSON.stringify(snap);
    assert.ok(!text.includes("BEGIN CERTIFICATE"));
    assert.deepEqual(snap.inventory?.signingKeys, [{ id: "k1" }]);
    assert.deepEqual(snap.inventory?.mtls[URL_A], { certIdentity: "deadbeef" });
  });
});

describe("applyConfig", () => {
  it("applies a diff through updateEndpointConfig and reports applied items", () => {
    const q = makeQueue({
      baseDelayMs: 1000,
      maxAttempts: 5,
      jitterMs: 0,
      maxConcurrentPerEndpoint: 4,
      circuitBreaker: { failureThreshold: 5 },
    });
    q.updateEndpointConfig(URL_A, { maxConcurrentPerEndpoint: 8 });
    const snap = baseSnapshot(q);
    // Diverge from the snapshot.
    q.updateEndpointConfig(URL_A, {
      maxConcurrentPerEndpoint: 2,
      circuitBreaker: { failureThreshold: 9 },
      retry: { baseDelayMs: 250 },
    });
    const result = applyConfig(q, snap);
    assert.equal(result.dryRun, false);
    assert.deepEqual(
      result.applied.map((a) => `${a.scope}:${a.field}`).sort(),
      [
        `${URL_A}:circuitBreaker`,
        `${URL_A}:maxConcurrentPerEndpoint`,
        `queue:retry.baseDelayMs`,
      ]
    );
    // The snapshot carried no circuit override (it was added after the
    // export), so apply *removes* the override instead of inventing a
    // value — the endpoint falls back to the queue default.
    const removal = result.applied.find((a) => a.field === "circuitBreaker")!;
    assert.deepEqual(removal.from, { failureThreshold: 9, cooldownMs: 30_000 });
    assert.equal(removal.to, null);
    const restored = q.endpointConfig(undefined, URL_A);
    assert.equal(restored.maxConcurrentPerEndpoint, 8);
    assert.equal(restored.circuitBreaker, undefined);
    assert.equal(q.retryConfig().baseDelayMs, 1000);
    assert.deepEqual(result.pending, []);
  });

  it("is a no-op when the snapshot matches live config", () => {
    const q = makeQueue({ baseDelayMs: 1000, maxAttempts: 5, jitterMs: 0 });
    const result = applyConfig(q, baseSnapshot(q));
    assert.deepEqual(result.applied, []);
    assert.deepEqual(result.pending, []);
  });

  it("dryRun returns the plan without mutating anything", () => {
    const q = makeQueue({ baseDelayMs: 1000, maxAttempts: 5, jitterMs: 0 });
    const snap = baseSnapshot(q);
    q.updateEndpointConfig(URL_A, { maxConcurrentPerEndpoint: 3, retry: { baseDelayMs: 50 } });
    const before = JSON.stringify(baseSnapshot(q));
    const result = applyConfig(q, snap, { dryRun: true });
    assert.equal(result.dryRun, true);
    assert.deepEqual(result.applied, []);
    assert.ok(result.plan.length > 0);
    assert.equal(JSON.stringify(baseSnapshot(q)), before);
  });

  it("restores a snapshot-only endpoint from effective defaults", () => {
    const q = makeQueue({ baseDelayMs: 1000, maxAttempts: 5, jitterMs: 0, maxConcurrentPerEndpoint: 4 });
    q.updateEndpointConfig(URL_A, { maxConcurrentPerEndpoint: 8 });
    const snap = baseSnapshot(q);
    // Snapshot-only endpoint: live has no override; the diff's `from`
    // must be the effective default (4), not a fabricated value.
    const mutated = JSON.parse(JSON.stringify(snap)) as ConfigSnapshot;
    mutated.endpoints[URL_B] = { maxConcurrentPerEndpoint: 11 };
    const result = applyConfig(q, mutated);
    assert.ok(result.applied.some((a) => a.scope === URL_B && a.field === "maxConcurrentPerEndpoint" && a.from === 4));
    assert.equal(q.endpointConfig(undefined, URL_B).maxConcurrentPerEndpoint, 11);
  });

  it("rejects malformed snapshots as invalid_snapshot", () => {
    const q = makeQueue({});
    for (const bad of [
      null,
      42,
      { format: "nope", version: 1 },
      { format: CONFIG_SNAPSHOT_FORMAT, version: 999, takenAtMs: 1, retry: {}, endpoints: {}, inventory: null },
      (() => {
        const s = baseSnapshot(q) as unknown as Record<string, unknown>;
        (s.endpoints as Record<string, unknown>)[URL_A] = { maxConcurrentPerEndpoint: 0 };
        return s;
      })(),
    ]) {
      assert.throws(() => applyConfig(q, bad), (e: unknown) => {
        assert.ok(e instanceof ConfigApplyError);
        assert.equal(e.kind, "invalid_snapshot");
        return true;
      });
    }
  });

  it("refuses snapshots that claim to carry key bytes (fail-closed)", () => {
    const q = makeQueue({});
    const poisoned = JSON.parse(JSON.stringify(baseSnapshot(q))) as unknown as Record<string, unknown>;
    poisoned.inventory = {
      routing: null,
      signingKeys: [{ id: "k1", secret: "hunter2-bytes" }],
      mtls: {},
      tlsPins: {},
      proxies: {},
      compression: {},
      tenants: [],
    };
    assert.throws(() => applyConfig(q, poisoned), (e: unknown) => {
      assert.ok(e instanceof ConfigApplyError);
      assert.equal(e.kind, "secret_material_refused");
      return true;
    });
    // Zero mutation: the queue is untouched and nothing was audited.
    assert.deepEqual(q.configuredEndpoints(), []);
  });

  it("refuses when live secret-bearing inventory diverged (fail-closed)", () => {
    const q = makeQueue({});
    const snap = exportConfig(q, {
      readInventory: () => ({
        routing: null,
        signingKeys: [{ id: "k1" }],
        mtls: {},
        tlsPins: {},
        proxies: {},
        compression: {},
        tenants: [],
      }),
    });
    // A key rotation happened after the snapshot was taken.
    assert.throws(
      () =>
        applyConfig(q, snap, {
          readInventory: () => ({
            routing: null,
            signingKeys: [{ id: "k1" }, { id: "k2" }],
            mtls: {},
            tlsPins: {},
            proxies: {},
            compression: {},
            tenants: [],
          }),
        }),
      (e: unknown) => {
        assert.ok(e instanceof ConfigApplyError);
        assert.equal(e.kind, "secret_material_refused");
        assert.ok(e.items.some((i) => i.field === "signingKeys" && i.secretBearing));
        return true;
      }
    );
  });

  it("refuses to patch a disabled subsystem (unsupported), nothing applied", () => {
    const q = makeQueue({ baseDelayMs: 1000, maxAttempts: 5, jitterMs: 0 });
    const snap = baseSnapshot(q);
    const withCircuit = JSON.parse(JSON.stringify(snap)) as ConfigSnapshot;
    withCircuit.endpoints[URL_A] = {
      maxConcurrentPerEndpoint: 4,
      circuitBreaker: { failureThreshold: 2, cooldownMs: 1000 },
    };
    assert.throws(() => applyConfig(q, withCircuit), (e: unknown) => {
      assert.ok(e instanceof ConfigApplyError);
      assert.equal(e.kind, "unsupported");
      return true;
    });
    assert.deepEqual(q.configuredEndpoints(), []);
  });

  it("rolls back applied items when a later item fails mid-apply", () => {
    const q = makeQueue({
      baseDelayMs: 1000,
      maxAttempts: 5,
      jitterMs: 0,
      maxConcurrentPerEndpoint: 4,
    });
    q.updateEndpointConfig(URL_A, { maxConcurrentPerEndpoint: 8 });
    q.updateEndpointConfig(URL_B, { maxConcurrentPerEndpoint: 8 });
    const snap = baseSnapshot(q);
    q.updateEndpointConfig(URL_A, { maxConcurrentPerEndpoint: 2 });
    q.updateEndpointConfig(URL_B, { maxConcurrentPerEndpoint: 2 });
    const beforeA = q.endpointConfig(undefined, URL_A);
    const beforeB = q.endpointConfig(undefined, URL_B);

    // Sabotage the second imperative call to simulate a mid-apply
    // setter failure after the first item already applied.
    const orig = q.updateEndpointConfig.bind(q);
    let calls = 0;
    (q as unknown as { updateEndpointConfig: unknown }).updateEndpointConfig = (
      endpoint: string,
      patch: unknown,
      tenant?: string
    ) => {
      calls += 1;
      if (calls === 2) throw new Error("setter exploded mid-apply");
      return (orig as (...a: unknown[]) => unknown)(endpoint, patch, tenant);
    };
    const audited: unknown[] = [];
    try {
      assert.throws(() => applyConfig(q, snap, { audit: (e) => audited.push(e) }), (e: unknown) => {
        assert.ok(e instanceof ConfigApplyError);
        assert.equal(e.kind, "apply_failed");
        assert.equal(e.applied.length, 1);
        assert.equal(e.rolledBack.length, 1);
        return true;
      });
    } finally {
      (q as unknown as { updateEndpointConfig: unknown }).updateEndpointConfig = orig;
    }
    // Exact pre-apply state restored on both endpoints…
    assert.deepEqual(q.endpointConfig(undefined, URL_A), beforeA);
    assert.deepEqual(q.endpointConfig(undefined, URL_B), beforeB);
    // …including override removal: URL_B had no override before this
    // test's first updateEndpointConfig? It did (set to 8 above) — so
    // instead assert a fresh endpoint's override is cleaned up: apply a
    // snapshot-only endpoint and fail there.
    assert.equal(
      audited.filter((e) => (e as { event: string }).event === "config_rolled_back").length,
      1
    );
    assert.equal(
      audited.filter((e) => (e as { event: string }).event === "config_applied").length,
      0
    );
  });

  it("rollback removes overrides the apply introduced", () => {
    const q = makeQueue({ baseDelayMs: 1000, maxAttempts: 5, jitterMs: 0, maxConcurrentPerEndpoint: 4 });
    // URL_B has no override pre-apply; the snapshot introduces one.
    const snap = baseSnapshot(q);
    const mutated = JSON.parse(JSON.stringify(snap)) as ConfigSnapshot;
    mutated.endpoints[URL_B] = { maxConcurrentPerEndpoint: 11 };
    mutated.endpoints[URL_A] = { maxConcurrentPerEndpoint: 12 };

    const orig = q.updateEndpointConfig.bind(q);
    let calls = 0;
    (q as unknown as { updateEndpointConfig: unknown }).updateEndpointConfig = (
      endpoint: string,
      patch: unknown,
      tenant?: string
    ) => {
      calls += 1;
      if (calls === 2) throw new Error("boom");
      return (orig as (...a: unknown[]) => unknown)(endpoint, patch, tenant);
    };
    try {
      assert.throws(() => applyConfig(q, mutated), (e: unknown) => e instanceof ConfigApplyError && e.kind === "apply_failed");
    } finally {
      (q as unknown as { updateEndpointConfig: unknown }).updateEndpointConfig = orig;
    }
    // URL_A applied then rolled back; URL_B never got its override.
    assert.deepEqual(q.configuredEndpoints(), []);
    // Pre-apply state restored exactly: no drift against the original
    // snapshot (drift against the *mutated* snapshot is expected — the
    // apply was refused/rolled back).
    assert.deepEqual(detectConfigDrift(q, snap), []);
    assert.equal(detectConfigDrift(q, mutated).length, 2);
  });

  it("reports declarative-only inventory diffs as pending, not applied", () => {
    const q = makeQueue({});
    const inv = () => ({
      routing: null as null,
      signingKeys: [],
      mtls: {},
      tlsPins: {},
      proxies: {},
      compression: {},
      tenants: [],
    });
    const snap = exportConfig(q, { readInventory: inv });
    const result = applyConfig(q, snap, {
      readInventory: () => ({ ...inv(), tlsPins: { [URL_A]: ["sha256/abc="] } }),
    });
    assert.deepEqual(result.applied, []);
    assert.deepEqual(
      result.pending.map((p) => p.field),
      [`tlsPins.${URL_A}`]
    );
  });

  it("audits config_applied on success", () => {
    const q = makeQueue({ baseDelayMs: 1000, maxAttempts: 5, jitterMs: 0 });
    const snap = baseSnapshot(q);
    q.updateEndpointConfig(URL_A, { maxConcurrentPerEndpoint: 3 });
    const audited: Array<Record<string, unknown>> = [];
    applyConfig(q, snap, { audit: (e) => audited.push(e) });
    assert.equal(audited.length, 1);
    assert.equal(audited[0].event, "config_applied");
  });
});

describe("detectConfigDrift", () => {
  it("reports live-vs-snapshot diffs without mutating", () => {
    const q = makeQueue({
      baseDelayMs: 1000,
      maxAttempts: 5,
      jitterMs: 0,
      maxConcurrentPerEndpoint: 4,
      circuitBreaker: { failureThreshold: 5 },
    });
    q.updateEndpointConfig(URL_A, { maxConcurrentPerEndpoint: 8 });
    const snap = baseSnapshot(q);
    q.updateEndpointConfig(URL_A, { maxConcurrentPerEndpoint: 2, retry: { baseDelayMs: 500 } });
    const drift = detectConfigDrift(q, snap);
    const fields = drift.map((d) => `${d.scope}:${d.field}`).sort();
    assert.deepEqual(fields, [
      `${URL_A}:maxConcurrentPerEndpoint`,
      "queue:retry.baseDelayMs",
    ]);
    const mc = drift.find((d) => d.field === "maxConcurrentPerEndpoint")!;
    assert.equal(mc.from, 2);
    assert.equal(mc.to, 8);
    // Pure read: nothing changed by the detection itself.
    assert.equal(q.endpointConfig(undefined, URL_A).maxConcurrentPerEndpoint, 2);
    assert.equal(q.retryConfig().baseDelayMs, 500);
  });

  it("is empty when nothing drifted, and flags inventory drift", () => {
    const q = makeQueue({});
    const invA = {
      routing: null as null,
      signingKeys: [],
      mtls: {},
      tlsPins: {} as Record<string, string[]>,
      proxies: {},
      compression: {},
      tenants: [],
    };
    const snap = exportConfig(q, { readInventory: () => invA });
    assert.deepEqual(detectConfigDrift(q, snap, { readInventory: () => ({ ...invA }) }), []);
    const drifted = detectConfigDrift(q, snap, {
      readInventory: () => ({ ...invA, tlsPins: { [URL_A]: ["sha256/abc="] } }),
    });
    assert.deepEqual(
      drifted.map((d) => d.field),
      [`tlsPins.${URL_A}`]
    );
  });

  it("rejects malformed snapshots", () => {
    const q = makeQueue({});
    assert.throws(() => detectConfigDrift(q, { nope: true }), ConfigApplyError);
  });
});

describe("operator endpoints GET/POST /config/snapshot", () => {
  const servers: Server[] = [];
  afterEach(async () => {
    for (const s of servers.splice(0)) {
      await new Promise<void>((resolve) => s.close(() => resolve()));
    }
  });

  function listen(server: Server): Promise<number> {
    return new Promise((resolve) => {
      server.listen(0, "127.0.0.1", () => {
        resolve((server.address() as { port: number }).port);
      });
    });
  }

  function req(
    port: number,
    method: string,
    path: string,
    body?: unknown,
    token?: string
  ): Promise<{ status: number; json: unknown }> {
    return new Promise((resolve, reject) => {
      const data = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path,
          method,
          headers: {
            ...(data ? { "content-type": "application/json", "content-length": data.length } : {}),
            ...(token ? { authorization: `Bearer ${token}` } : {}),
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => {
            const text = Buffer.concat(chunks).toString("utf8");
            resolve({ status: res.statusCode ?? 0, json: text ? JSON.parse(text) : null });
          });
        }
      );
      r.on("error", reject);
      if (data) r.end(data);
      else r.end();
    });
  }

  async function makeRelay(extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "cfgsnap-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: "test-inbound-key",
      forwardUrl: URL_A,
      auditLog: audit,
      operatorToken: TOKEN,
      retry: { maxConcurrentPerEndpoint: 4, circuitBreaker: { failureThreshold: 5 }, quota: { deliveriesPerMinute: 60 } },
      ...extra,
    });
    servers.push(relay);
    return { port: await listen(relay), audit };
  }

  it("GET exports the snapshot; POST applies it with admin scope", async () => {
    const { port, audit } = await makeRelay();
    const get = await req(port, "GET", "/config/snapshot", undefined, TOKEN);
    assert.equal(get.status, 200);
    const snapshot = (get.json as { snapshot: ConfigSnapshot }).snapshot;
    assert.equal(snapshot.format, CONFIG_SNAPSHOT_FORMAT);
    assert.deepEqual(snapshot.retry.maxAttempts, 5);

    const mutated = JSON.parse(JSON.stringify(snapshot)) as ConfigSnapshot;
    mutated.endpoints[URL_A] = { maxConcurrentPerEndpoint: 16 };
    const dry = await req(port, "POST", "/config/snapshot", { snapshot: mutated, dryRun: true }, TOKEN);
    assert.equal(dry.status, 200);
    assert.equal((dry.json as { dryRun: boolean }).dryRun, true);
    assert.ok(((dry.json as { plan: unknown[] }).plan.length > 0));
    assert.equal(audit.query({ event: "config_applied" }).length, 0);

    const applied = await req(port, "POST", "/config/snapshot", { snapshot: mutated }, TOKEN);
    assert.equal(applied.status, 200);
    assert.ok(((applied.json as { applied: unknown[] }).applied.length > 0));
    const events = audit.query({ event: "config_applied" });
    assert.equal(events.length, 1);
    assert.equal((events[0] as { keyId: string }).keyId, "legacy");
  });

  it("POST refuses disabled-subsystem patches as unsupported with 400, nothing applied", async () => {
    const { port, audit } = await makeRelay();
    const get = await req(port, "GET", "/config/snapshot", undefined, TOKEN);
    const snapshot = (get.json as { snapshot: ConfigSnapshot }).snapshot;
    // Weighted dispatch is not enabled: the weighted pre-check fires
    // before any mutation — unsupported, fail-closed.
    const mutated = JSON.parse(JSON.stringify(snapshot)) as ConfigSnapshot;
    mutated.endpoints[URL_A] = { maxConcurrentPerEndpoint: 16 };
    mutated.endpoints[URL_B] = {
      maxConcurrentPerEndpoint: 4,
      weighted: { targets: [{ targetUrl: URL_A, weight: 1 }] },
    };
    const res = await req(port, "POST", "/config/snapshot", { snapshot: mutated }, TOKEN);
    assert.equal(res.status, 400);
    assert.equal((res.json as { kind: string }).kind, "unsupported");
    assert.equal(audit.query({ event: "config_applied" }).length, 0);
    assert.equal(audit.query({ event: "config_rolled_back" }).length, 0);
  });

  it("POST rejects malformed bodies and bad snapshots with 400", async () => {
    const { port } = await makeRelay();
    const missing = await req(port, "POST", "/config/snapshot", {}, TOKEN);
    assert.equal(missing.status, 400);
    const badSnap = await req(port, "POST", "/config/snapshot", { snapshot: { nope: true } }, TOKEN);
    assert.equal(badSnap.status, 400);
    assert.equal((badSnap.json as { kind: string }).kind, "invalid_snapshot");
    const badDry = await req(port, "POST", "/config/snapshot", { snapshot: {}, dryRun: "yes" }, TOKEN);
    assert.equal(badDry.status, 400);
  });

  it("fails closed: 404 without operator auth configured, 403 without credentials", async () => {
    const dir = mkdtempSync(join(tmpdir(), "cfgsnap-naked-"));
    const relay = createRelayServer({
      secret: "test-inbound-key",
      forwardUrl: URL_A,
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
    });
    servers.push(relay);
    const naked = await listen(relay);
    const get404 = await req(naked, "GET", "/config/snapshot", undefined, TOKEN);
    assert.equal(get404.status, 404);
    const post404 = await req(naked, "POST", "/config/snapshot", { snapshot: {} }, TOKEN);
    assert.equal(post404.status, 404);

    const { port } = await makeRelay();
    const noCred = await req(port, "GET", "/config/snapshot");
    assert.equal(noCred.status, 403);
    const wrong = await req(port, "GET", "/config/snapshot", undefined, "wrong");
    assert.equal(wrong.status, 403);
  });

  it("enforces WR-82 scopes: GET read, POST admin", async () => {
    const dir = mkdtempSync(join(tmpdir(), "cfgsnap-scopes-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: "test-inbound-key",
      forwardUrl: URL_A,
      auditLog: audit,
      operatorKeys: [
        { id: "reader", key: "reader-key", scopes: ["read"] },
        { id: "admin", key: "admin-key", scopes: ["admin"] },
      ],
    });
    servers.push(relay);
    const port = await listen(relay);

    const getRead = await req(port, "GET", "/config/snapshot", undefined, "reader-key");
    assert.equal(getRead.status, 200);
    const snapshot = (getRead.json as { snapshot: ConfigSnapshot }).snapshot;

    const postRead = await req(port, "POST", "/config/snapshot", { snapshot, dryRun: true }, "reader-key");
    assert.equal(postRead.status, 403);

    const postAdmin = await req(port, "POST", "/config/snapshot", { snapshot, dryRun: true }, "admin-key");
    assert.equal(postAdmin.status, 200);
    const events = audit.query({ event: "config_applied" });
    assert.equal(events.length, 0); // dryRun audits nothing
  });

  it("reports secret-material refusal as 400 and audits nothing", async () => {
    const { port, audit } = await makeRelay({ signingKeys: [{ id: "k1", secret: "live-key-bytes" }] });
    const get = await req(port, "GET", "/config/snapshot", undefined, TOKEN);
    const snapshot = (get.json as { snapshot: ConfigSnapshot }).snapshot;
    assert.deepEqual(snapshot.inventory?.signingKeys, [{ id: "k1" }]);

    const poisoned = JSON.parse(JSON.stringify(snapshot)) as unknown as Record<string, unknown>;
    (poisoned.inventory as Record<string, unknown>).signingKeys = [
      { id: "k1", secret: "smuggled-bytes" },
    ];
    const res = await req(port, "POST", "/config/snapshot", { snapshot: poisoned }, TOKEN);
    assert.equal(res.status, 400);
    assert.equal((res.json as { kind: string }).kind, "secret_material_refused");
    assert.equal(audit.query({ event: "config_applied" }).length, 0);
    assert.equal(audit.query({ event: "config_rolled_back" }).length, 0);
  });
});
