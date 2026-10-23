import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  TenantKeyStore,
  DEFAULT_TENANT_KEY_GRACE_MS,
} from "../src/tenant-keys.ts";
import { signSha256, signTimestamped, HmacSha256Verifier, type Verifier } from "../src/verify.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";

const BODY = Buffer.from(JSON.stringify({ event: "payment.succeeded" }));
const T0 = 1_700_000_000_000;
const GRACE = 60_000;

function store(now: () => number = () => T0): TenantKeyStore {
  return new TenantKeyStore({ nowMs: now });
}

describe("TenantKeyStore", () => {
  it("fails fast on a bad nowMs", () => {
    assert.throws(() => new TenantKeyStore({ nowMs: "nope" as never }), RangeError);
  });

  it("set/verify: sha256= and timestamped headers both work", () => {
    const s = store();
    const keyId = s.setTenantSecret("acme", "s3cr3t");
    assert.equal(keyId, "acme:1");
    assert.ok(s.hasTenantSecret("acme"));
    assert.equal(s.getCurrentKeyId("acme"), "acme:1");
    assert.deepEqual(s.getKeyIds("acme"), ["acme:1"]);
    assert.deepEqual(s.verifyDetailed("acme", BODY, signSha256(BODY, "s3cr3t")), {
      ok: true,
      keyId: "acme:1",
    });
    assert.ok(s.verify("acme", BODY, signTimestamped(BODY, "s3cr3t")));
    assert.ok(!s.verify("acme", BODY, signSha256(BODY, "wrong")));
    assert.ok(!s.verify("acme", BODY, "not-a-signature"));
  });

  it("fails fast on invalid setTenantSecret arguments", () => {
    const s = store();
    for (const bad of ["", "with space", "has!bang", "x".repeat(65), 42, null, undefined]) {
      assert.throws(() => s.setTenantSecret(bad as string, "secret"), RangeError, String(bad));
    }
    assert.throws(() => s.setTenantSecret("acme", ""), RangeError);
    assert.throws(() => s.setTenantSecret("acme", 42 as never), RangeError);
    // Setting twice never silently overwrites a live trust anchor.
    s.setTenantSecret("acme", "first");
    assert.throws(() => s.setTenantSecret("acme", "second"), RangeError);
    // The first key is still the one that verifies.
    assert.ok(s.verify("acme", BODY, signSha256(BODY, "first")));
    assert.ok(!s.verify("acme", BODY, signSha256(BODY, "second")));
  });

  it("fails fast on invalid rotateTenantSecret arguments", () => {
    const s = store();
    // No key yet: set first.
    assert.throws(() => s.rotateTenantSecret("acme", "new"), RangeError);
    s.setTenantSecret("acme", "old");
    assert.throws(() => s.rotateTenantSecret("acme", ""), RangeError);
    assert.throws(() => s.rotateTenantSecret("acme", 42 as never), RangeError);
    assert.throws(() => s.rotateTenantSecret("acme", "new", -1), RangeError);
    assert.throws(() => s.rotateTenantSecret("acme", "new", NaN), RangeError);
    assert.throws(() => s.rotateTenantSecret("acme", "new", Infinity), RangeError);
    assert.throws(() => s.rotateTenantSecret("bad id!", "new"), RangeError);
  });

  it("rotate: both keys verify inside the grace window, attributed by key id", () => {
    const s = store();
    s.setTenantSecret("acme", "old-key");
    const newId = s.rotateTenantSecret("acme", "new-key", GRACE);
    assert.equal(newId, "acme:2");
    assert.equal(s.getCurrentKeyId("acme"), "acme:2");
    assert.deepEqual(s.getKeyIds("acme"), ["acme:1", "acme:2"]);
    assert.deepEqual(s.verifyDetailed("acme", BODY, signSha256(BODY, "new-key")), {
      ok: true,
      keyId: "acme:2",
    });
    assert.deepEqual(s.verifyDetailed("acme", BODY, signSha256(BODY, "old-key")), {
      ok: true,
      keyId: "acme:1",
    });
    assert.ok(s.previousInGrace("acme"));
    assert.ok(!s.rotationComplete("acme"));
  });

  it("rotate: grace boundary is inclusive; past it the old key is dead", () => {
    let now = T0;
    const s = new TenantKeyStore({ nowMs: () => now });
    s.setTenantSecret("acme", "old-key");
    s.rotateTenantSecret("acme", "new-key", GRACE);
    // Exactly at the deadline: still valid (inclusive, WR-20 convention).
    now = T0 + GRACE;
    assert.ok(s.previousInGrace("acme"));
    assert.ok(s.verify("acme", BODY, signSha256(BODY, "old-key")));
    // One millisecond past: dead. New key unaffected.
    now = T0 + GRACE + 1;
    assert.ok(!s.previousInGrace("acme"));
    assert.ok(!s.verify("acme", BODY, signSha256(BODY, "old-key")));
    assert.ok(s.verify("acme", BODY, signSha256(BODY, "new-key")));
    assert.ok(s.rotationComplete("acme"));
  });

  it("rotate: graceMs=0 retires the old key immediately", () => {
    let now = T0;
    const s = new TenantKeyStore({ nowMs: () => now });
    s.setTenantSecret("acme", "old-key");
    s.rotateTenantSecret("acme", "new-key", 0);
    now = T0 + 1;
    assert.ok(!s.verify("acme", BODY, signSha256(BODY, "old-key")));
    assert.ok(s.verify("acme", BODY, signSha256(BODY, "new-key")));
    assert.ok(s.rotationComplete("acme"));
  });

  it("rotate: default grace is 24h", () => {
    assert.equal(DEFAULT_TENANT_KEY_GRACE_MS, 86_400_000);
    let now = T0;
    const s = new TenantKeyStore({ nowMs: () => now });
    s.setTenantSecret("acme", "old-key");
    s.rotateTenantSecret("acme", "new-key"); // no graceMs
    now = T0 + 86_400_000;
    assert.ok(s.verify("acme", BODY, signSha256(BODY, "old-key")));
    now = T0 + 86_400_000 + 1;
    assert.ok(!s.verify("acme", BODY, signSha256(BODY, "old-key")));
  });

  it("rotate: a second rotation drops the oldest key — at most two verify", () => {
    const s = store();
    s.setTenantSecret("acme", "gen1");
    s.rotateTenantSecret("acme", "gen2", GRACE);
    s.rotateTenantSecret("acme", "gen3", GRACE);
    assert.equal(s.getCurrentKeyId("acme"), "acme:3");
    assert.ok(s.verify("acme", BODY, signSha256(BODY, "gen3")));
    assert.ok(s.verify("acme", BODY, signSha256(BODY, "gen2")));
    assert.ok(!s.verify("acme", BODY, signSha256(BODY, "gen1")));
    assert.deepEqual(s.getKeyIds("acme"), ["acme:2", "acme:3"]);
  });

  it("removeTenantSecret clears the key and reports whether one existed", () => {
    const s = store();
    assert.ok(!s.removeTenantSecret("acme"));
    s.setTenantSecret("acme", "secret");
    assert.ok(s.removeTenantSecret("acme"));
    assert.ok(!s.hasTenantSecret("acme"));
    assert.ok(!s.verify("acme", BODY, signSha256(BODY, "secret")));
    assert.equal(s.getVerifier("acme"), undefined);
    assert.ok(!s.removeTenantSecret("acme"));
    // A fresh set starts a new generation line at :1.
    assert.equal(s.setTenantSecret("acme", "other"), "acme:1");
  });

  it("unknown tenants and garbage input never throw from verify paths", () => {
    const s = store();
    s.setTenantSecret("acme", "secret");
    assert.ok(!s.hasTenantSecret("ghost"));
    assert.equal(s.getVerifier("ghost"), undefined);
    assert.equal(s.getCurrentKeyId("ghost"), undefined);
    assert.deepEqual(s.getKeyIds("ghost"), []);
    assert.ok(!s.previousInGrace("ghost"));
    assert.ok(!s.rotationComplete("ghost"));
    assert.deepEqual(s.verifyDetailed("ghost", BODY, signSha256(BODY, "secret")), { ok: false });
    assert.ok(!s.verify("ghost", BODY, signSha256(BODY, "secret")));
    assert.deepEqual(s.verifyDetailed("bad id!", BODY, "x"), { ok: false });
    assert.ok(!s.verify("bad id!", BODY, "x"));
    assert.deepEqual(s.tenantIds(), ["acme"]);
  });

  it("key ids are audit-safe: they never contain the secret", () => {
    const s = store();
    const secret = "super-secret-value";
    s.setTenantSecret("acme", secret);
    s.rotateTenantSecret("acme", "another-secret-value", GRACE);
    const detail = s.verifyDetailed("acme", BODY, signSha256(BODY, "another-secret-value"));
    assert.ok(detail.ok);
    for (const id of [detail.keyId!, ...s.getKeyIds("acme")]) {
      assert.ok(!id.includes("secret"), `key id leaked secret material: ${id}`);
    }
    assert.equal(TenantKeyStore.keyIdFor("acme", 7), "acme:7");
  });

  it("tenant ids share the WR-48 namespace: x-tenant-id charset applies", () => {
    const s = store();
    // Trace-id-shaped ids are legal; uppercase and digits too.
    assert.equal(s.setTenantSecret("tenant-01_ABC", "k"), "tenant-01_ABC:1");
    assert.ok(s.hasTenantSecret("tenant-01_ABC"));
  });
});

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function post(port: number, path: string, body: Buffer, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path, method: "POST", headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
      }
    );
    r.on("error", reject);
    r.end(body);
  });
}

describe("server per-tenant inbound HMAC keys", () => {
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

  function makeRelay(keys: TenantKeyStore, extra: Record<string, unknown> = {}) {
    const dir = mkdtempSync(join(tmpdir(), "audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: "global-secret",
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
      tenantKeys: keys,
      ...extra,
    });
    return { relay, audit };
  }

  async function withRelay(keys: TenantKeyStore, extra: Record<string, unknown> = {}) {
    const { relay, audit } = makeRelay(keys, extra);
    const port = await listen(relay as unknown as Server);
    return {
      port,
      audit,
      close: async () => {
        (relay as unknown as Server).close();
        await new Promise((r) => (relay as unknown as Server).once("close", r));
      },
    };
  }

  it("tenant key verifies; accepted audit carries tenant + key id, never the secret", async () => {
    const keys = store();
    keys.setTenantSecret("acme", "tenant-secret");
    const r = await withRelay(keys);
    try {
      const ok = await post(r.port, "/hooks", BODY, {
        "x-signature": signSha256(BODY, "tenant-secret"),
        "x-tenant-id": "acme",
      });
      assert.equal(ok.status, 202);
      const bad = await post(r.port, "/hooks", BODY, {
        "x-signature": signSha256(BODY, "global-secret"),
        "x-tenant-id": "acme",
      });
      assert.equal(bad.status, 401); // global secret does not authenticate the tenant
      const wrong = await post(r.port, "/hooks", BODY, {
        "x-signature": signSha256(BODY, "wrong"),
        "x-tenant-id": "acme",
      });
      assert.equal(wrong.status, 401);

      const events = r.audit.readAll() as Array<Record<string, unknown>>;
      const accepted = events.filter((e) => e.event === "accepted");
      assert.equal(accepted.length, 1);
      assert.equal(accepted[0].tenant, "acme");
      assert.equal(accepted[0].keyId, "acme:1");
      // No audit event anywhere carries the secret.
      const dumped = JSON.stringify(events);
      assert.ok(!dumped.includes("tenant-secret"));
      // Rejections name no key.
      const rejected = events.filter((e) => e.event === "rejected" && e.reason === "invalid_signature");
      assert.equal(rejected.length, 2);
      assert.ok(rejected.every((e) => e.keyId === "unknown"));
    } finally {
      await r.close();
    }
  });

  it("tenants without a key walk the legacy global path", async () => {
    const keys = store();
    keys.setTenantSecret("acme", "tenant-secret");
    const r = await withRelay(keys);
    try {
      // Unknown tenant: the global secret still verifies (backward compatible).
      const ok = await post(r.port, "/hooks", BODY, {
        "x-signature": signSha256(BODY, "global-secret"),
        "x-tenant-id": "other",
      });
      assert.equal(ok.status, 202);
      // No tenant header at all: legacy.
      const plain = await post(r.port, "/hooks", BODY, {
        "x-signature": signSha256(BODY, "global-secret"),
      });
      assert.equal(plain.status, 202);
      const events = r.audit.readAll() as Array<Record<string, unknown>>;
      const accepted = events.filter((e) => e.event === "accepted");
      assert.equal(accepted.length, 2);
      assert.equal(accepted[0].tenant, "other");
      assert.ok(!("keyId" in accepted[0])); // non-rotating global verifier: no keyId
      assert.ok(!("tenant" in accepted[1]));
    } finally {
      await r.close();
    }
  });

  it("without tenantKeys the feature is off: tenant header, global secret, legacy path", async () => {
    const r = await withRelay(store(), { tenantKeys: undefined } as Record<string, unknown>);
    try {
      const ok = await post(r.port, "/hooks", BODY, {
        "x-signature": signSha256(BODY, "global-secret"),
        "x-tenant-id": "acme",
      });
      assert.equal(ok.status, 202);
      const events = r.audit.readAll() as Array<Record<string, unknown>>;
      const accepted = events.filter((e) => e.event === "accepted");
      assert.equal(accepted.length, 1);
      assert.equal(accepted[0].tenant, "acme");
    } finally {
      await r.close();
    }
  });

  it("rotation: old key verifies inside grace and audits tenant_key_previous_used", async () => {
    let now = T0;
    const keys = new TenantKeyStore({ nowMs: () => now });
    keys.setTenantSecret("acme", "old-secret");
    const r = await withRelay(keys);
    try {
      keys.rotateTenantSecret("acme", "new-secret", GRACE);
      const prev = await post(r.port, "/hooks", BODY, {
        "x-signature": signSha256(BODY, "old-secret"),
        "x-tenant-id": "acme",
      });
      assert.equal(prev.status, 202);
      const cur = await post(r.port, "/hooks", BODY, {
        "x-signature": signSha256(BODY, "new-secret"),
        "x-tenant-id": "acme",
      });
      assert.equal(cur.status, 202);

      const events = r.audit.readAll() as Array<Record<string, unknown>>;
      const prevEvents = events.filter((e) => e.event === "tenant_key_previous_used");
      assert.equal(prevEvents.length, 1);
      assert.equal(prevEvents[0].tenant, "acme");
      assert.equal(prevEvents[0].keyId, "acme:1");
      const accepted = events.filter((e) => e.event === "accepted");
      assert.deepEqual(
        accepted.map((e) => e.keyId),
        ["acme:1", "acme:2"]
      );
    } finally {
      await r.close();
    }
  });

  it("rotation: old key is rejected after its grace elapses", async () => {
    let now = T0;
    const keys = new TenantKeyStore({ nowMs: () => now });
    keys.setTenantSecret("acme", "old-secret");
    const r = await withRelay(keys);
    try {
      keys.rotateTenantSecret("acme", "new-secret", GRACE);
      now = T0 + GRACE + 1;
      const prev = await post(r.port, "/hooks", BODY, {
        "x-signature": signSha256(BODY, "old-secret"),
        "x-tenant-id": "acme",
      });
      assert.equal(prev.status, 401);
      const cur = await post(r.port, "/hooks", BODY, {
        "x-signature": signSha256(BODY, "new-secret"),
        "x-tenant-id": "acme",
      });
      assert.equal(cur.status, 202);
      const events = r.audit.readAll() as Array<Record<string, unknown>>;
      assert.ok(!events.some((e) => e.event === "tenant_key_previous_used"));
    } finally {
      await r.close();
    }
  });

  it("a pinned per-endpoint verifier rule wins over the tenant key", async () => {
    const keys = store();
    keys.setTenantSecret("acme", "tenant-secret");
    const ed = new HmacSha256Verifier("path-secret") as Verifier;
    const r = await withRelay(keys, { endpointVerifiers: [{ pattern: "/hooks", verifier: ed }] });
    try {
      const tenantOk = await post(r.port, "/hooks", BODY, {
        "x-signature": signSha256(BODY, "tenant-secret"),
        "x-tenant-id": "acme",
      });
      assert.equal(tenantOk.status, 401); // path rule keeps its verifier
      const pathOk = await post(r.port, "/hooks", BODY, {
        "x-signature": signSha256(BODY, "path-secret"),
        "x-tenant-id": "acme",
      });
      assert.equal(pathOk.status, 202);
    } finally {
      await r.close();
    }
  });

  it("invalid x-tenant-id still answers 400 after the legacy verifier runs", async () => {
    const keys = store();
    keys.setTenantSecret("acme", "tenant-secret");
    const r = await withRelay(keys);
    try {
      const res = await post(r.port, "/hooks", BODY, {
        "x-signature": signSha256(BODY, "global-secret"),
        "x-tenant-id": "bad id!",
      });
      assert.equal(res.status, 400);
      const events = r.audit.readAll() as Array<Record<string, unknown>>;
      assert.ok(events.some((e) => e.event === "rejected" && e.reason === "invalid_tenant_id"));
    } finally {
      await r.close();
    }
  });

  it("rejects a non-TenantKeyStore tenantKeys at startup", () => {
    assert.throws(
      () =>
        createRelayServer({
          secret: "global-secret",
          forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
          tenantKeys: {} as never,
        }),
      RangeError
    );
  });
});
