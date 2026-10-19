import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { InboundApiKeyAuth, type EndpointApiKeyRule } from "../src/api-key.ts";
import {
  OperatorKeyRing,
  matchOperatorKey,
  type OperatorKeyEntry,
} from "../src/operator-keys.ts";
import { createRelayServer } from "../src/server.ts";
import { RetryQueue, type Sender } from "../src/retry.ts";
import { AuditLog } from "../src/audit.ts";
import {
  exportConfig,
  applyConfig,
  ConfigApplyError,
  type ConfigSnapshot,
  type ConfigSnapshotInventory,
} from "../src/config-snapshot.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET/API_KEY-style names here.
const keyOld = "old-api-key-aaa111";
const keyNew = "new-api-key-bbb222";
const keyWrong = "wrong-api-key-zzz999";
const opRead = "operator-read-key-111";
const opAdmin = "operator-admin-key-222";
const opWrong = "operator-wrong-key-999";
const legacyOp = "legacy-operator-token-xyz";
const forwardTarget = "http://127.0.0.1:1/hook";
const probeBody = Buffer.from(JSON.stringify({ event: "key-revoke.probe" }));

function apiKeyRule(): EndpointApiKeyRule {
  return {
    pattern: "/hooks/keyed",
    keys: [
      { id: "old", key: keyOld },
      { id: "new", key: keyNew },
    ],
  };
}

function operatorEntries(): OperatorKeyEntry[] {
  return [
    { id: "reader", key: opRead, scopes: ["read"] },
    { id: "adminer", key: opAdmin, scopes: ["admin"] },
  ];
}

describe("InboundApiKeyAuth.revokeKey", () => {
  it("newly revokes: verifyKey stops matching, isKeyRevoked flips, onRevoked fires once", () => {
    const seen: Array<{ pattern: string; keyId: string }> = [];
    const auth = new InboundApiKeyAuth({
      rules: [apiKeyRule()],
      onRevoked: (info) => seen.push(info),
    });
    const rule = auth.ruleFor("/hooks/keyed");
    assert.ok(rule);
    assert.equal(auth.verifyKey(rule, keyOld), "old");
    assert.equal(auth.isKeyRevoked("/hooks/keyed", "old"), false);

    assert.equal(auth.revokeKey("/hooks/keyed", "old"), true);
    assert.equal(auth.isKeyRevoked("/hooks/keyed", "old"), true);
    // Fail-closed: a revoked key verifies exactly like a wrong key.
    assert.equal(auth.verifyKey(rule, keyOld), null);
    assert.equal(auth.verifyKey(rule, keyWrong), null);
    assert.deepEqual(seen, [{ pattern: "/hooks/keyed", keyId: "old" }]);
    // The other key in the same rule is unaffected.
    assert.equal(auth.verifyKey(rule, keyNew), "new");
  });

  it("returns false for unknown pattern, unknown key id, and double revoke", () => {
    const seen: Array<{ pattern: string; keyId: string }> = [];
    const auth = new InboundApiKeyAuth({ rules: [apiKeyRule()], onRevoked: (i) => seen.push(i) });
    assert.equal(auth.revokeKey("/hooks/nope", "old"), false);
    assert.equal(auth.revokeKey("/hooks/keyed", "ghost"), false);
    assert.equal(auth.revokeKey("/hooks/keyed", "old"), true);
    assert.equal(auth.revokeKey("/hooks/keyed", "old"), false);
    assert.equal(seen.length, 1);
  });

  it("revokeKey never throws on hostile input", () => {
    const auth = new InboundApiKeyAuth({ rules: [apiKeyRule()] });
    assert.equal(auth.revokeKey(null as unknown as string, "old"), false);
    assert.equal(auth.revokeKey("/hooks/keyed", null as unknown as string), false);
  });

  it("revokedKeys returns sorted id-only rows (never key bytes)", () => {
    const auth = new InboundApiKeyAuth({
      rules: [
        { pattern: "/hooks/b", keys: [{ id: "k2", key: keyNew }] },
        apiKeyRule(),
      ],
    });
    assert.equal(auth.revokeKey("/hooks/keyed", "new"), true);
    assert.equal(auth.revokeKey("/hooks/b", "k2"), true);
    const rows = auth.revokedKeys();
    assert.deepEqual(rows, [
      { pattern: "/hooks/b", keyId: "k2" },
      { pattern: "/hooks/keyed", keyId: "new" },
    ]);
    for (const row of rows) {
      assert.ok(!JSON.stringify(row).includes(keyOld));
      assert.ok(!JSON.stringify(row).includes(keyNew));
    }
  });
});

describe("OperatorKeyRing", () => {
  it("match works before revoke; returns null after (fail-closed, like a wrong key)", () => {
    const seen: Array<{ id: string }> = [];
    const ring = new OperatorKeyRing(operatorEntries(), { onRevoked: (i) => seen.push(i) });
    assert.deepEqual(ring.match(opAdmin, undefined), { id: "adminer", scopes: ["admin"] });
    assert.equal(ring.revokeKey("adminer"), true);
    assert.equal(ring.isRevoked("adminer"), true);
    assert.equal(ring.match(opAdmin, undefined), null);
    assert.equal(ring.match(opWrong, undefined), null);
    assert.deepEqual(seen, [{ id: "adminer" }]);
    // The other key is unaffected.
    assert.deepEqual(ring.match(opRead, undefined), { id: "reader", scopes: ["read"] });
  });

  it("revokeKey returns false for unknown ids, double revoke, and the legacy token", () => {
    const ring = new OperatorKeyRing(operatorEntries());
    assert.equal(ring.revokeKey("ghost"), false);
    assert.equal(ring.revokeKey("legacy"), false);
    assert.equal(ring.revokeKey("adminer"), true);
    assert.equal(ring.revokeKey("adminer"), false);
    // The legacy operatorToken is not a ring entry: it keeps
    // authenticating (rotate it out of config to kill it).
    assert.deepEqual(ring.match(legacyOp, legacyOp), { id: "legacy", scopes: ["admin"] });
  });

  it("revokedIds is sorted and id-only; onRevoked never throws the revoke", () => {
    const ring = new OperatorKeyRing(operatorEntries(), {
      onRevoked: () => {
        throw new Error("hook exploded");
      },
    });
    assert.equal(ring.revokeKey("adminer"), true);
    assert.equal(ring.isRevoked("adminer"), true);
    assert.deepEqual(ring.revokedIds(), ["adminer"]);
    const ring2 = new OperatorKeyRing([
      { id: "zeta", key: "zeta-key", scopes: ["read"] },
      { id: "alpha", key: "alpha-key", scopes: ["read"] },
    ]);
    ring2.revokeKey("zeta");
    ring2.revokeKey("alpha");
    assert.deepEqual(ring2.revokedIds(), ["alpha", "zeta"]);
  });

  it("the pure matchOperatorKey matcher is unchanged (no revocation state)", () => {
    const entries = operatorEntries();
    assert.deepEqual(matchOperatorKey(opAdmin, undefined, entries), {
      id: "adminer",
      scopes: ["admin"],
    });
  });
});

const okSender: Sender = async () => {};

function liveInventory(extra: Partial<ConfigSnapshotInventory> = {}): ConfigSnapshotInventory {
  return {
    routing: null,
    signingKeys: [],
    mtls: {},
    tlsPins: {},
    proxies: {},
    compression: {},
    tenants: [],
    revokedApiKeys: [],
    revokedOperatorKeys: [],
    ...extra,
  };
}

describe("config snapshot captures and applies key revocation", () => {
  it("exportConfig carries revoked ids when the inventory reader provides them", () => {
    const q = new RetryQueue({ sender: okSender });
    const snap = exportConfig(q, {
      nowMs: () => 1,
      readInventory: () =>
        liveInventory({
          revokedApiKeys: [{ pattern: "/hooks/keyed", keyIds: ["old"] }],
          revokedOperatorKeys: ["adminer"],
        }),
    });
    assert.deepEqual(snap.inventory?.revokedApiKeys, [{ pattern: "/hooks/keyed", keyIds: ["old"] }]);
    assert.deepEqual(snap.inventory?.revokedOperatorKeys, ["adminer"]);
  });

  it("applyConfig routes revocation diffs through the runtime revoke hooks", () => {
    const q = new RetryQueue({ sender: okSender });
    const snap = exportConfig(q, { nowMs: () => 1, readInventory: () => liveInventory({}) });
    const mutated = JSON.parse(JSON.stringify(snap)) as ConfigSnapshot;
    mutated.inventory!.revokedApiKeys = [{ pattern: "/hooks/keyed", keyIds: ["old"] }];
    mutated.inventory!.revokedOperatorKeys = ["adminer"];
    const calls: string[] = [];
    const res = applyConfig(q, mutated, {
      nowMs: () => 1,
      readInventory: () => liveInventory({}),
      revokeApiKey: (pattern, keyId) => {
        calls.push(`api:${pattern}:${keyId}`);
        return true;
      },
      revokeOperatorKey: (id) => {
        calls.push(`op:${id}`);
        return true;
      },
    });
    assert.deepEqual(calls.sort(), ["api:/hooks/keyed:old", "op:adminer"]);
    const fields = res.applied.map((a) => `${a.scope}:${a.field}`).sort();
    assert.deepEqual(fields, ["inventory:revokedApiKeys", "inventory:revokedOperatorKeys"]);
  });

  it("applyConfig refuses revocation diffs without hooks (unsupported, fail-closed)", () => {
    const q = new RetryQueue({ sender: okSender });
    const snap = exportConfig(q, { nowMs: () => 1, readInventory: () => liveInventory({}) });
    const mutated = JSON.parse(JSON.stringify(snap)) as ConfigSnapshot;
    mutated.inventory!.revokedOperatorKeys = ["adminer"];
    assert.throws(
      () => applyConfig(q, mutated, { nowMs: () => 1, readInventory: () => liveInventory({}) }),
      (err: unknown) => err instanceof ConfigApplyError && err.kind === "unsupported"
    );
  });

  it("dryRun plans revocation diffs without calling the hooks", () => {
    const q = new RetryQueue({ sender: okSender });
    const snap = exportConfig(q, { nowMs: () => 1, readInventory: () => liveInventory({}) });
    const mutated = JSON.parse(JSON.stringify(snap)) as ConfigSnapshot;
    mutated.inventory!.revokedOperatorKeys = ["adminer"];
    let called = 0;
    const res = applyConfig(q, mutated, {
      nowMs: () => 1,
      readInventory: () => liveInventory({}),
      dryRun: true,
      revokeOperatorKey: () => {
        called++;
        return true;
      },
    });
    assert.equal(called, 0);
    assert.ok(res.plan.some((p) => p.scope === "inventory" && p.field === "revokedOperatorKeys"));
  });

  it("revocation is append-only: a snapshot lacking live revocations is a no-op", () => {
    const q = new RetryQueue({ sender: okSender });
    const liveWithRevoke = () => liveInventory({ revokedOperatorKeys: ["adminer"] });
    const snap = exportConfig(q, { nowMs: () => 1, readInventory: liveWithRevoke });
    const res = applyConfig(q, snap, {
      nowMs: () => 1,
      readInventory: liveWithRevoke,
      revokeOperatorKey: () => {
        throw new Error("must not be called");
      },
    });
    assert.deepEqual(res.applied, []);
  });

  it("snapshot validation rejects non-id revocation rows", () => {
    const q = new RetryQueue({ sender: okSender });
    const snap = exportConfig(q, { nowMs: () => 1, readInventory: () => liveInventory({}) });
    const mutated = JSON.parse(JSON.stringify(snap)) as ConfigSnapshot;
    (mutated.inventory!.revokedApiKeys as unknown[]) = [{ pattern: "/x", keyIds: ["k"], key: "bytes" }];
    assert.throws(
      () => applyConfig(q, mutated, { nowMs: () => 1, readInventory: () => liveInventory({}) }),
      (err: unknown) => err instanceof ConfigApplyError && err.kind === "invalid_snapshot"
    );
  });
});

describe("server: revocation is fail-closed end to end", () => {
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

  function postHook(
    port: number,
    path: string,
    apiKey?: string
  ): Promise<{ status: number; text: string }> {
    return new Promise((resolve, reject) => {
      const r = httpRequest(
        {
          host: "127.0.0.1",
          port,
          path,
          method: "POST",
          headers: {
            "content-type": "application/json",
            ...(apiKey ? { "x-api-key": apiKey } : {}),
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
        }
      );
      r.on("error", reject);
      r.end(probeBody);
    });
  }

  function opReq(
    port: number,
    method: string,
    path: string,
    bearer?: string,
    body?: unknown
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
            ...(bearer ? { authorization: `Bearer ${bearer}` } : {}),
          },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
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

  async function makeRelay() {
    const dir = mkdtempSync(join(tmpdir(), "keyrevoke-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      forwardUrl: forwardTarget,
      auditLog: audit,
      operatorToken: legacyOp,
      operatorKeys: operatorEntries(),
      apiKeys: { rules: [apiKeyRule()] },
    });
    servers.push(relay);
    return { port: await listen(relay), audit };
  }

  it("revoking an intake API key via /config/snapshot makes it 401 fail-closed", async () => {
    const { port, audit } = await makeRelay();
    assert.equal((await postHook(port, "/hooks/keyed", keyOld)).status, 202);

    const get = await opReq(port, "GET", "/config/snapshot", legacyOp);
    assert.equal(get.status, 200);
    const snapshot = JSON.parse(JSON.stringify((get.json as { snapshot: ConfigSnapshot }).snapshot));
    snapshot.inventory.revokedApiKeys = [{ pattern: "/hooks/keyed", keyIds: ["old"] }];
    const applied = await opReq(port, "POST", "/config/snapshot", legacyOp, { snapshot });
    assert.equal(applied.status, 200);
    assert.ok(
      ((applied.json as { applied: Array<{ field: string }> }).applied).some(
        (a) => a.field === "revokedApiKeys"
      )
    );

    // The revoked key now fails exactly like a wrong key: 401.
    assert.equal((await postHook(port, "/hooks/keyed", keyOld)).status, 401);
    assert.equal((await postHook(port, "/hooks/keyed", keyWrong)).status, 401);
    // The surviving key in the same rule still works.
    assert.equal((await postHook(port, "/hooks/keyed", keyNew)).status, 202);

    const revoked = audit.query({ event: "api_key_revoked" });
    assert.equal(revoked.length, 1);
    assert.equal((revoked[0] as { keyId: string }).keyId, "old");
    assert.equal((revoked[0] as { pattern: string }).pattern, "/hooks/keyed");
    const rejected = audit.query({ event: "rejected" }) as Array<Record<string, unknown>>;
    assert.ok(rejected.some((e) => e.reason === "api_key_invalid" && e.keyId === "unknown"));
  });

  it("revoking an operator key via /config/snapshot makes it 403 fail-closed", async () => {
    const { port, audit } = await makeRelay();
    const before = await opReq(port, "GET", "/config/snapshot", opAdmin);
    assert.equal(before.status, 200);

    const snapshot = JSON.parse(JSON.stringify((before.json as { snapshot: ConfigSnapshot }).snapshot));
    snapshot.inventory.revokedOperatorKeys = ["adminer"];
    const applied = await opReq(port, "POST", "/config/snapshot", legacyOp, { snapshot });
    assert.equal(applied.status, 200);

    // Revoked operator key: 403, indistinguishable from a wrong key.
    assert.equal((await opReq(port, "GET", "/config/snapshot", opAdmin)).status, 403);
    assert.equal((await opReq(port, "GET", "/config/snapshot", opWrong)).status, 403);
    // The other operator key and the legacy token still work.
    assert.equal((await opReq(port, "GET", "/config/snapshot", opRead)).status, 200);
    assert.equal((await opReq(port, "GET", "/config/snapshot", legacyOp)).status, 200);

    const revoked = audit.query({ event: "operator_key_revoked" });
    assert.equal(revoked.length, 1);
    assert.equal((revoked[0] as { keyId: string }).keyId, "adminer");
  });

  it("the exported snapshot captures live revocation state (id-only)", async () => {
    const { port } = await makeRelay();
    const first = await opReq(port, "GET", "/config/snapshot", legacyOp);
    const snapshot = JSON.parse(JSON.stringify((first.json as { snapshot: ConfigSnapshot }).snapshot));
    snapshot.inventory.revokedOperatorKeys = ["reader"];
    await opReq(port, "POST", "/config/snapshot", legacyOp, { snapshot });

    const second = await opReq(port, "GET", "/config/snapshot", legacyOp);
    const inventory = (second.json as { snapshot: ConfigSnapshot }).snapshot.inventory!;
    assert.deepEqual(inventory.revokedOperatorKeys, ["reader"]);
    assert.deepEqual(inventory.revokedApiKeys, []);
    const serialized = JSON.stringify(inventory);
    assert.ok(!serialized.includes(opRead));
  });
});
