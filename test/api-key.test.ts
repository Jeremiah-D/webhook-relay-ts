import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import {
  InboundApiKeyAuth,
  assertValidEndpointApiKeyRules,
  selectEndpointApiKeyRule,
  type EndpointApiKeyRule,
} from "../src/api-key.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

// camelCase on purpose: the runtime redacts ALL-CAPS constants in test
// files (see AGENTS.md), so no SECRET/API_KEY-style names here.
const relaySecret = "api-key-relay-hmac-secret";
const keyA = "first-api-key-abc123";
const keyB = "second-api-key-def456";
const wrongKey = "wrong-api-key-zzz999";
const probeBody = Buffer.from(JSON.stringify({ event: "api-key.probe" }));

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function post(port: number, path: string, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path, method: "POST", headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          r.destroy();
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() });
        });
      }
    );
    r.on("error", reject);
    r.end(probeBody);
  });
}

function readEvents(audit: AuditLog): Array<Record<string, unknown>> {
  return audit.readAll() as Array<Record<string, unknown>>;
}

describe("assertValidEndpointApiKeyRules", () => {
  const good: EndpointApiKeyRule = { pattern: "/hooks/keyed", keys: [{ id: "k1", key: keyA }] };

  it("accepts undefined, empty arrays, and valid rules", () => {
    assertValidEndpointApiKeyRules(undefined);
    assertValidEndpointApiKeyRules([]);
    assertValidEndpointApiKeyRules([good]);
    assertValidEndpointApiKeyRules([
      { pattern: "/hooks/*", keys: [{ id: "a", key: keyA }, { id: "b", key: keyB }], requireSignature: true },
      { pattern: "/hooks/other", keys: [{ id: "c", key: keyB }], requireSignature: false },
    ]);
  });

  it("rejects non-arrays, bad patterns, and empty key lists", () => {
    assert.throws(() => assertValidEndpointApiKeyRules("nope" as never), RangeError);
    assert.throws(() => assertValidEndpointApiKeyRules([{ pattern: "no-slash", keys: [{ id: "k", key: keyA }] }]), RangeError);
    assert.throws(() => assertValidEndpointApiKeyRules([{ pattern: "", keys: [{ id: "k", key: keyA }] }]), RangeError);
    assert.throws(() => assertValidEndpointApiKeyRules([{ pattern: "/x", keys: [] }]), RangeError);
    assert.throws(() => assertValidEndpointApiKeyRules([{ pattern: "/x" } as never]), RangeError);
  });

  it("rejects empty ids, empty keys, and duplicate ids", () => {
    assert.throws(
      () => assertValidEndpointApiKeyRules([{ pattern: "/x", keys: [{ id: "", key: keyA }] }]),
      RangeError
    );
    assert.throws(
      () => assertValidEndpointApiKeyRules([{ pattern: "/x", keys: [{ id: "k", key: "" }] }]),
      RangeError
    );
    assert.throws(
      () =>
        assertValidEndpointApiKeyRules([
          { pattern: "/x", keys: [{ id: "dup", key: keyA }, { id: "dup", key: keyB }] },
        ]),
      RangeError
    );
    assert.throws(
      () =>
        assertValidEndpointApiKeyRules([
          { pattern: "/x", keys: [{ id: "k", key: keyA }], requireSignature: "yes" as never },
        ]),
      RangeError
    );
  });
});

describe("selectEndpointApiKeyRule", () => {
  const rules: EndpointApiKeyRule[] = [
    { pattern: "/hooks/keyed", keys: [{ id: "k1", key: keyA }] },
    { pattern: "/hooks/*", keys: [{ id: "k2", key: keyB }] },
  ];

  it("matches exact paths", () => {
    assert.equal(selectEndpointApiKeyRule("/hooks/keyed", rules), rules[0]);
    // A trailing slash misses the exact rule but still hits the prefix rule.
    assert.equal(selectEndpointApiKeyRule("/hooks/keyed/", rules), rules[1]);
    assert.equal(selectEndpointApiKeyRule("/other", rules), undefined);
  });

  it("matches prefix patterns, including the bare prefix", () => {
    assert.equal(selectEndpointApiKeyRule("/hooks/other", rules), rules[1]);
    assert.equal(selectEndpointApiKeyRule("/hooks", rules), rules[1]);
    assert.equal(selectEndpointApiKeyRule("/hooksx", rules), undefined);
  });

  it("first matching rule wins", () => {
    // "/hooks/keyed" matches both rules; the exact rule comes first.
    assert.equal(selectEndpointApiKeyRule("/hooks/keyed", [...rules].reverse()), rules[1]);
  });

  it("returns undefined when nothing matches or no rules are configured", () => {
    assert.equal(selectEndpointApiKeyRule("/other", rules), undefined);
    assert.equal(selectEndpointApiKeyRule("/hooks/keyed", undefined), undefined);
    assert.equal(selectEndpointApiKeyRule("/hooks/keyed", []), undefined);
  });
});

describe("InboundApiKeyAuth.verifyKey", () => {
  const auth = new InboundApiKeyAuth({
    rules: [{ pattern: "/hooks/*", keys: [{ id: "k1", key: keyA }, { id: "k2", key: keyB }] }],
  });
  const rule = auth.ruleFor("/hooks/x")!;

  it("returns the matched key id", () => {
    assert.equal(auth.verifyKey(rule, keyA), "k1");
    assert.equal(auth.verifyKey(rule, keyB), "k2");
  });

  it("returns null for a wrong key", () => {
    assert.equal(auth.verifyKey(rule, wrongKey), null);
    assert.equal(auth.verifyKey(rule, ""), null);
    assert.equal(auth.verifyKey(rule, keyA.slice(1)), null);
  });

  it("never throws on garbage input", () => {
    assert.equal(auth.verifyKey(rule, undefined as never), null);
    assert.equal(auth.verifyKey(rule, 42 as never), null);
  });

  it("ruleFor returns undefined for unguarded paths", () => {
    assert.equal(new InboundApiKeyAuth().ruleFor("/hooks/x"), undefined);
    assert.equal(auth.ruleFor("/other"), undefined);
  });
});

describe("server api key gate", () => {
  let stub: Server;
  let stubPort: number;
  let received: number;
  let forwardedApiKey: unknown;

  before(async () => {
    stub = createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        received++;
        forwardedApiKey = req.headers["x-api-key"];
        res.writeHead(200).end("ok");
      });
    });
    stubPort = await listen(stub);
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  function makeRelay(rules: EndpointApiKeyRule[]) {
    const dir = mkdtempSync(join(tmpdir(), "api-key-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: relaySecret,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
      apiKeys: { rules },
    });
    return { relay, audit };
  }

  async function closeRelay(relay: Server) {
    relay.close();
    await new Promise((r) => relay.once("close", r));
  }

  /** Wait until the stub has received at least `n` deliveries (bounded). */
  async function waitForDeliveries(n: number) {
    const deadline = Date.now() + 5000;
    while (received < n && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.ok(received >= n, `stub received ${received}, wanted ${n}`);
  }

  it("accepts a valid key with 202, skips the signature check, and audits keyId", async () => {
    const { relay, audit } = makeRelay([{ pattern: "/hooks/keyed", keys: [{ id: "k1", key: keyA }] }]);
    const port = await listen(relay);
    try {
      received = 0;
      forwardedApiKey = "unset";
      // A garbage x-signature proves the key alone authenticates in the
      // default (api-key-only) mode.
      const res = await post(port, "/hooks/keyed", {
        "x-api-key": keyA,
        "x-signature": "sha256=00",
      });
      assert.equal(res.status, 202);
      const accepted = readEvents(audit).filter((e) => e.event === "accepted");
      assert.equal(accepted.length, 1);
      assert.equal(accepted[0].keyId, "k1");
      await waitForDeliveries(1);
      // The inbound credential never travels downstream.
      assert.equal(forwardedApiKey, undefined);
    } finally {
      await closeRelay(relay);
    }
  });

  it("rejects a wrong key with 401 and audits api_key_invalid", async () => {
    const { relay, audit } = makeRelay([{ pattern: "/hooks/keyed", keys: [{ id: "k1", key: keyA }] }]);
    const port = await listen(relay);
    try {
      received = 0;
      const res = await post(port, "/hooks/keyed", { "x-api-key": wrongKey });
      assert.equal(res.status, 401);
      const rejected = readEvents(audit).filter((e) => e.event === "rejected");
      assert.equal(rejected.length, 1);
      assert.equal(rejected[0].reason, "api_key_invalid");
      assert.equal(rejected[0].keyId, "unknown");
      assert.equal(rejected[0].endpoint, "/hooks/keyed");
      assert.equal(received, 0);
    } finally {
      await closeRelay(relay);
    }
  });

  it("rejects a missing x-api-key with 401 and audits api_key_missing", async () => {
    const { relay, audit } = makeRelay([{ pattern: "/hooks/keyed", keys: [{ id: "k1", key: keyA }] }]);
    const port = await listen(relay);
    try {
      const res = await post(port, "/hooks/keyed", { "x-signature": signSha256(probeBody, relaySecret) });
      assert.equal(res.status, 401);
      const rejected = readEvents(audit).filter((e) => e.event === "rejected");
      assert.equal(rejected.length, 1);
      assert.equal(rejected[0].reason, "api_key_missing");
      assert.equal(rejected[0].keyId, "unknown");
    } finally {
      await closeRelay(relay);
    }
  });

  it("rotation: two keys coexist, both accepted, audit shows respective ids", async () => {
    const { relay, audit } = makeRelay([
      { pattern: "/hooks/keyed", keys: [{ id: "k1", key: keyA }, { id: "k2", key: keyB }] },
    ]);
    const port = await listen(relay);
    try {
      const first = await post(port, "/hooks/keyed", { "x-api-key": keyA });
      assert.equal(first.status, 202);
      const second = await post(port, "/hooks/keyed", { "x-api-key": keyB });
      assert.equal(second.status, 202);
      const accepted = readEvents(audit).filter((e) => e.event === "accepted");
      assert.deepEqual(
        accepted.map((e) => e.keyId),
        ["k1", "k2"]
      );
    } finally {
      await closeRelay(relay);
    }
  });

  it("prefix rules match subpaths and the bare prefix", async () => {
    const { relay, audit } = makeRelay([{ pattern: "/hooks/*", keys: [{ id: "k1", key: keyA }] }]);
    const port = await listen(relay);
    try {
      assert.equal((await post(port, "/hooks/a", { "x-api-key": keyA })).status, 202);
      assert.equal((await post(port, "/hooks", { "x-api-key": keyA })).status, 202);
      assert.equal((await post(port, "/hooks/a")).status, 401);
      const accepted = readEvents(audit).filter((e) => e.event === "accepted");
      assert.equal(accepted.length, 2);
    } finally {
      await closeRelay(relay);
    }
  });

  it("unguarded paths need no key: signature behavior is exactly the legacy one", async () => {
    const { relay, audit } = makeRelay([{ pattern: "/hooks/keyed", keys: [{ id: "k1", key: keyA }] }]);
    const port = await listen(relay);
    try {
      // No x-api-key at all: the path has no rule, so the legacy
      // signature check (and only it) decides.
      const ok = await post(port, "/", { "x-signature": signSha256(probeBody, relaySecret) });
      assert.equal(ok.status, 202);
      const accepted = readEvents(audit).filter((e) => e.event === "accepted");
      assert.equal(accepted.length, 1);
      assert.equal(accepted[0].keyId, undefined);
      const bad = await post(port, "/", { "x-signature": "sha256=00" });
      assert.equal(bad.status, 401);
    } finally {
      await closeRelay(relay);
    }
  });

  it("requireSignature: true demands BOTH the key and a valid signature", async () => {
    const { relay, audit } = makeRelay([
      { pattern: "/hooks/keyed", keys: [{ id: "k1", key: keyA }], requireSignature: true },
    ]);
    const port = await listen(relay);
    try {
      // Key ok, signature bad → 401 from the signature gate; the
      // rejection names the key that passed the pre-body gate.
      const badSig = await post(port, "/hooks/keyed", {
        "x-api-key": keyA,
        "x-signature": "sha256=00",
      });
      assert.equal(badSig.status, 401);
      // Signature ok, key bad → 401 from the pre-body key gate.
      const badKey = await post(port, "/hooks/keyed", {
        "x-api-key": wrongKey,
        "x-signature": signSha256(probeBody, relaySecret),
      });
      assert.equal(badKey.status, 401);
      // Both ok → 202, audit names the API key.
      const both = await post(port, "/hooks/keyed", {
        "x-api-key": keyA,
        "x-signature": signSha256(probeBody, relaySecret),
      });
      assert.equal(both.status, 202);

      const events = readEvents(audit);
      const rejected = events.filter((e) => e.event === "rejected");
      assert.equal(rejected.length, 2);
      assert.equal(rejected[0].reason, "invalid_signature");
      assert.equal(rejected[0].keyId, "k1");
      assert.equal(rejected[1].reason, "api_key_invalid");
      const accepted = events.filter((e) => e.event === "accepted");
      assert.equal(accepted.length, 1);
      assert.equal(accepted[0].keyId, "k1");
    } finally {
      await closeRelay(relay);
    }
  });

  it("repeated 401s never touch the circuit breaker", async () => {
    const { relay, audit } = makeRelay([{ pattern: "/hooks/keyed", keys: [{ id: "k1", key: keyA }] }]);
    const port = await listen(relay);
    try {
      received = 0;
      for (let i = 0; i < 5; i++) {
        const res = await post(port, "/hooks/keyed", { "x-api-key": wrongKey });
        assert.equal(res.status, 401);
      }
      const events = readEvents(audit);
      assert.ok(!events.some((e) => e.event === "circuit_open" || e.event === "circuit_half_open"));
      assert.equal(received, 0);

      // The endpoint still delivers immediately after: nothing tripped.
      const ok = await post(port, "/hooks/keyed", { "x-api-key": keyA });
      assert.equal(ok.status, 202);
      await waitForDeliveries(1);
      const fresh = readEvents(audit);
      assert.ok(fresh.some((e) => e.event === "delivered"));
    } finally {
      await closeRelay(relay);
    }
  });

  it("rejects invalid apiKeys config at startup", () => {
    const dir = mkdtempSync(join(tmpdir(), "api-key-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const base = {
      secret: relaySecret,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
    };
    assert.throws(
      () =>
        createRelayServer({
          ...base,
          apiKeys: {
            rules: [{ pattern: "/x", keys: [{ id: "dup", key: keyA }, { id: "dup", key: keyB }] }],
          },
        }),
      RangeError
    );
    assert.throws(
      () => createRelayServer({ ...base, apiKeys: { rules: [{ pattern: "/x", keys: [] }] } }),
      RangeError
    );
    assert.throws(
      () =>
        createRelayServer({
          ...base,
          apiKeys: { rules: [{ pattern: "/x", keys: [{ id: "k", key: "" }] }] },
        }),
      RangeError
    );
    assert.throws(
      () =>
        createRelayServer({
          ...base,
          apiKeys: { rules: [{ pattern: "no-slash", keys: [{ id: "k", key: keyA }] }] },
        }),
      RangeError
    );
  });
});
