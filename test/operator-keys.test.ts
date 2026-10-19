import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import {
  assertValidOperatorKeys,
  bearerToken,
  matchOperatorKey,
  operatorMay,
  type OperatorIdentity,
  type OperatorKeyEntry,
} from "../src/operator-keys.ts";
import { AuditLog } from "../src/audit.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET/API_KEY-style names here.
const legacyToken = "legacy-operator-token-xyz";
const readKey = "read-scoped-key-aaa111";
const adminKey = "admin-scoped-key-bbb222";
const scopedLessKey = "scopeless-key-ccc333";
const emptyScopesKey = "empty-scopes-key-ddd444";
const wrongKey = "wrong-key-zzz999";
const forwardTarget = "http://127.0.0.1:1/hook";

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function call(
  port: number,
  method: string,
  path: string,
  bearer?: string,
  body?: string
): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = {};
    if (bearer !== undefined) headers["authorization"] = `Bearer ${bearer}`;
    const r = httpRequest({ host: "127.0.0.1", port, path, method, headers }, (res) => {
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

function makeRelay(opts: { operatorToken?: string; operatorKeys?: OperatorKeyEntry[] }) {
  const dir = mkdtempSync(join(tmpdir(), "operator-keys-"));
  const audit = new AuditLog(join(dir, "audit.jsonl"));
  const server = createRelayServer({
    forwardUrl: forwardTarget,
    auditLog: audit,
    retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
    operatorToken: opts.operatorToken,
    operatorKeys: opts.operatorKeys,
  });
  return { server, audit };
}

async function closeRelay(server: Server) {
  server.close();
  await new Promise((r) => server.once("close", r));
}

function readEvents(audit: AuditLog): Array<Record<string, unknown>> {
  return audit.readAll() as Array<Record<string, unknown>>;
}

describe("assertValidOperatorKeys", () => {
  it("accepts undefined, empty arrays, and valid entries", () => {
    assertValidOperatorKeys(undefined);
    assertValidOperatorKeys([]);
    assertValidOperatorKeys([
      { id: "monitor", key: readKey, scopes: ["read"] },
      { id: "human", key: adminKey, scopes: ["admin"] },
      { id: "bare", key: scopedLessKey },
      { id: "empty", key: emptyScopesKey, scopes: [] },
      { id: "both", key: "key-eee", scopes: ["read", "admin"] },
    ]);
  });

  it("rejects a non-array", () => {
    assert.throws(() => assertValidOperatorKeys("nope" as never), RangeError);
  });

  it("rejects empty ids and keys", () => {
    assert.throws(() => assertValidOperatorKeys([{ id: "", key: readKey }]), RangeError);
    assert.throws(() => assertValidOperatorKeys([{ id: "x", key: "" }]), RangeError);
    assert.throws(
      () => assertValidOperatorKeys([{ id: 42 as never, key: readKey }]),
      RangeError
    );
  });

  it("rejects duplicate ids and duplicate key values", () => {
    assert.throws(
      () =>
        assertValidOperatorKeys([
          { id: "dup", key: readKey },
          { id: "dup", key: adminKey },
        ]),
      RangeError
    );
    assert.throws(
      () =>
        assertValidOperatorKeys([
          { id: "a", key: readKey },
          { id: "b", key: readKey },
        ]),
      RangeError
    );
  });

  it("rejects unknown or mis-cased scopes", () => {
    for (const scopes of [["READ"], ["write"], [""], ["read", "superuser"]]) {
      assert.throws(
        () =>
          assertValidOperatorKeys([
            { id: "x", key: readKey, scopes: scopes as never },
          ]),
        RangeError,
        `scopes ${JSON.stringify(scopes)} should be rejected`
      );
    }
    assert.throws(
      () =>
        assertValidOperatorKeys([{ id: "x", key: readKey, scopes: "read" as never }]),
      RangeError
    );
  });

  it("throws RangeError from createRelayServer on bad operatorKeys", () => {
    const base = {
      forwardUrl: forwardTarget,
      auditLog: new AuditLog(join(mkdtempSync(join(tmpdir(), "ok-")), "audit.jsonl")),
    };
    assert.throws(
      () =>
        createRelayServer({
          ...base,
          operatorKeys: [{ id: "x", key: readKey, scopes: ["bogus"] as never }],
        }),
      RangeError
    );
    assert.throws(
      () =>
        createRelayServer({
          ...base,
          operatorKeys: [
            { id: "dup", key: readKey },
            { id: "dup", key: adminKey },
          ],
        }),
      RangeError
    );
    assert.throws(
      () => createRelayServer({ ...base, operatorKeys: [{ id: "x", key: "" }] }),
      RangeError
    );
  });
});

describe("bearerToken", () => {
  it("extracts the token from a Bearer header", () => {
    assert.equal(bearerToken("Bearer abc"), "abc");
    assert.equal(bearerToken(["Bearer abc"]), "abc");
  });

  it("returns null for missing, non-bearer, or empty bearer headers", () => {
    assert.equal(bearerToken(undefined), null);
    assert.equal(bearerToken("Basic abc"), null);
    assert.equal(bearerToken("Bearer "), null);
    assert.equal(bearerToken(42), null);
  });
});

describe("matchOperatorKey", () => {
  const ring: OperatorKeyEntry[] = [
    { id: "monitor", key: readKey, scopes: ["read"] },
    { id: "human", key: adminKey, scopes: ["admin"] },
    { id: "bare", key: scopedLessKey },
  ];

  it("matches the legacy token with full admin semantics", () => {
    assert.deepEqual(matchOperatorKey(legacyToken, legacyToken, ring), {
      id: "legacy",
      scopes: ["admin"],
    });
  });

  it("matches ring entries and reports their scopes (fail-closed when absent)", () => {
    const read: OperatorIdentity | null = matchOperatorKey(readKey, undefined, ring);
    assert.deepEqual(read, { id: "monitor", scopes: ["read"] });
    const bare: OperatorIdentity | null = matchOperatorKey(scopedLessKey, undefined, ring);
    assert.deepEqual(bare, { id: "bare", scopes: [] });
  });

  it("returns null for unknown keys and null presentations", () => {
    assert.equal(matchOperatorKey(wrongKey, legacyToken, ring), null);
    assert.equal(matchOperatorKey(null, legacyToken, ring), null);
    assert.equal(matchOperatorKey("", legacyToken, ring), null);
  });

  it("legacy wins when both are configured", () => {
    assert.deepEqual(matchOperatorKey(legacyToken, legacyToken, ring)?.id, "legacy");
  });
});

describe("operatorMay", () => {
  const read: OperatorIdentity = { id: "r", scopes: ["read"] };
  const admin: OperatorIdentity = { id: "a", scopes: ["admin"] };
  const none: OperatorIdentity = { id: "n", scopes: [] };

  it("read covers read paths, admin covers everything", () => {
    assert.equal(operatorMay(read, "GET"), true);
    assert.equal(operatorMay(admin, "GET"), true);
    assert.equal(operatorMay(read, "POST"), false);
    assert.equal(operatorMay(admin, "POST"), true);
  });

  it("a scopeless identity is authorized for nothing", () => {
    assert.equal(operatorMay(none, "GET"), false);
    assert.equal(operatorMay(none, "POST"), false);
  });
});

describe("server operator key ring", () => {
  const readOnlyKeys: OperatorKeyEntry[] = [
    { id: "monitor", key: readKey, scopes: ["read"] },
    { id: "operator", key: adminKey, scopes: ["admin"] },
    { id: "bare", key: scopedLessKey },
    { id: "empty", key: emptyScopesKey, scopes: [] },
  ];

  it("legacy operatorToken keeps full admin semantics", async () => {
    const { server, audit } = makeRelay({ operatorToken: legacyToken });
    const port = await listen(server);
    try {
      const metrics = await call(port, "GET", "/metrics", legacyToken);
      assert.equal(metrics.status, 200);
      const replay = await call(port, "POST", "/dead-letter/replay", legacyToken, "{}");
      assert.equal(replay.status, 200);
      assert.equal((await call(port, "GET", "/metrics", wrongKey)).status, 403);
      assert.equal((await call(port, "GET", "/metrics")).status, 403);
      // The audit trail names the legacy path as "legacy".
      const batch = readEvents(audit).filter((e) => e.event === "dead_letter_batch_replayed");
      assert.equal(batch.length, 1);
      assert.equal(batch[0].keyId, "legacy");
    } finally {
      await closeRelay(server);
    }
  });

  it("read key can GET read-only paths but gets 403 on mutating paths", async () => {
    const { server } = makeRelay({ operatorKeys: readOnlyKeys });
    const port = await listen(server);
    try {
      assert.equal((await call(port, "GET", "/metrics", readKey)).status, 200);
      assert.equal((await call(port, "GET", "/audit", readKey)).status, 200);
      assert.equal((await call(port, "GET", "/audit/verify", readKey)).status, 200);
      assert.equal((await call(port, "GET", "/latency", readKey)).status, 200);
      assert.equal((await call(port, "GET", "/slo-risk", readKey)).status, 200);
      assert.equal((await call(port, "GET", "/dead-letter", readKey)).status, 200);
      assert.equal((await call(port, "GET", "/dead-letter/stats", readKey)).status, 200);
      assert.equal((await call(port, "GET", "/dead-letter/auto-replay/status", readKey)).status, 200);
      assert.equal((await call(port, "GET", "/scheduled", readKey)).status, 200);
      const dl = await call(port, "GET", "/dead-letter", readKey);
      assert.equal(dl.text, "[]");

      assert.equal((await call(port, "POST", "/dead-letter/replay", readKey, "{}")).status, 403);
      assert.equal(
        (await call(port, "POST", "/dead-letter/auto-replay/trigger", readKey)).status,
        403
      );
      assert.equal(
        (await call(port, "POST", "/config/endpoint", readKey, "{}")).status,
        403
      );
      assert.equal(
        (await call(port, "POST", "/endpoints/pause", readKey, "{}")).status,
        403
      );
      assert.equal(
        (await call(port, "POST", "/scheduled/nope/pause", readKey)).status,
        403
      );
      // Method mismatch still answers 405 before the scope check.
      assert.equal((await call(port, "POST", "/metrics", readKey)).status, 405);
      // Unknown operator paths (still under an operator prefix) answer 404.
      assert.equal((await call(port, "GET", "/dead-letter/nope", readKey)).status, 404);
      assert.equal((await call(port, "GET", "/dead-letter/nope", scopedLessKey)).status, 404);
    } finally {
      await closeRelay(server);
    }
  });

  it("admin key can read and mutate", async () => {
    const { server, audit } = makeRelay({ operatorKeys: readOnlyKeys });
    const port = await listen(server);
    try {
      assert.equal((await call(port, "GET", "/metrics", adminKey)).status, 200);
      const replay = await call(port, "POST", "/dead-letter/replay", adminKey, "{}");
      assert.equal(replay.status, 200);
      // `replayed` is the id list (empty here), not a count.
      assert.deepEqual(JSON.parse(replay.text), { replayed: [], failed: [], skipped: [] });
      // Unknown schedule: scope passes, then the operator 404.
      assert.equal((await call(port, "POST", "/scheduled/nope/pause", adminKey)).status, 404);
      const batch = readEvents(audit).filter((e) => e.event === "dead_letter_batch_replayed");
      assert.equal(batch.length, 1);
      assert.equal(batch[0].keyId, "operator");
    } finally {
      await closeRelay(server);
    }
  });

  it("keys with no scopes (or empty scopes) are fail-closed", async () => {
    const { server } = makeRelay({ operatorKeys: readOnlyKeys });
    const port = await listen(server);
    try {
      for (const key of [scopedLessKey, emptyScopesKey]) {
        assert.equal((await call(port, "GET", "/metrics", key)).status, 403);
        assert.equal((await call(port, "GET", "/audit", key)).status, 403);
        assert.equal((await call(port, "GET", "/dead-letter", key)).status, 403);
        assert.equal((await call(port, "POST", "/dead-letter/replay", key, "{}")).status, 403);
      }
    } finally {
      await closeRelay(server);
    }
  });

  it("unknown key gets 403; no keys configured gets 404", async () => {
    const { server } = makeRelay({ operatorKeys: readOnlyKeys });
    const port = await listen(server);
    try {
      assert.equal((await call(port, "GET", "/metrics", wrongKey)).status, 403);
      assert.equal((await call(port, "GET", "/metrics")).status, 403);
    } finally {
      await closeRelay(server);
    }

    const bare = makeRelay({});
    const barePort = await listen(bare.server);
    try {
      assert.equal((await call(barePort, "GET", "/metrics", readKey)).status, 404);
      assert.equal((await call(barePort, "POST", "/dead-letter/replay", readKey, "{}")).status, 404);
    } finally {
      await closeRelay(bare.server);
    }
  });

  it("legacy token and key ring coexist; read-key responses match legacy bodies", async () => {
    const { server } = makeRelay({ operatorToken: legacyToken, operatorKeys: readOnlyKeys });
    const port = await listen(server);
    try {
      // Either credential authenticates; the legacy one is full admin.
      assert.equal((await call(port, "GET", "/metrics", legacyToken)).status, 200);
      assert.equal((await call(port, "GET", "/metrics", readKey)).status, 200);
      assert.equal(
        (await call(port, "POST", "/dead-letter/replay", legacyToken, "{}")).status,
        200
      );
      assert.equal((await call(port, "POST", "/dead-letter/replay", readKey, "{}")).status, 403);
      // Byte-identical read responses across credentials on one instance.
      const viaLegacy = await call(port, "GET", "/metrics", legacyToken);
      const viaRead = await call(port, "GET", "/metrics", readKey);
      assert.equal(viaRead.text, viaLegacy.text);
      const dlLegacy = await call(port, "GET", "/dead-letter", legacyToken);
      const dlRead = await call(port, "GET", "/dead-letter", readKey);
      assert.equal(dlRead.text, dlLegacy.text);
    } finally {
      await closeRelay(server);
    }
  });

  it("hook-fired operator audits (endpoint pause) carry the keyId", async () => {
    const { server, audit } = makeRelay({ operatorKeys: readOnlyKeys });
    const port = await listen(server);
    try {
      const paused = await call(
        port,
        "POST",
        "/endpoints/pause",
        adminKey,
        JSON.stringify({ endpoint: forwardTarget })
      );
      assert.equal(paused.status, 200);
      const pauseEvents = readEvents(audit).filter((e) => e.event === "endpoint_paused");
      assert.equal(pauseEvents.length, 1);
      assert.equal(pauseEvents[0].keyId, "operator");
      // Resume audits the transition with the same keyId.
      const resumed = await call(
        port,
        "POST",
        "/endpoints/resume",
        adminKey,
        JSON.stringify({ endpoint: forwardTarget })
      );
      assert.equal(resumed.status, 200);
      const resumeEvents = readEvents(audit).filter((e) => e.event === "endpoint_resumed");
      assert.equal(resumeEvents.length, 1);
      assert.equal(resumeEvents[0].keyId, "operator");
    } finally {
      await closeRelay(server);
    }
  });
});
