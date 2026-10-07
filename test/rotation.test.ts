import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import {
  DEFAULT_KEY_GRACE_MS,
  RotatingHmacVerifier,
  signSha256,
  type SigningKey,
} from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import type { RetryItem } from "../src/retry.ts";

const BODY = Buffer.from(JSON.stringify({ event: "payment.succeeded", id: "evt_9" }));
const OLD_SECRET = "old-signing-secret";
const MID_SECRET = "mid-signing-secret";
const NEW_SECRET = "new-signing-secret";

// Deterministic clock: tests advance `now` explicitly.
let now = 1_000_000;
const nowMs = () => now;

function rotator(overrides: Partial<{ keys: SigningKey[]; graceMs: number }> = {}) {
  return new RotatingHmacVerifier({
    keys: [
      { id: "old", secret: OLD_SECRET, retiredAtMs: 900_000 },
      { id: "mid", secret: MID_SECRET },
      { id: "new", secret: NEW_SECRET, primary: true },
    ],
    graceMs: 200_000,
    nowMs,
    ...overrides,
  });
}

describe("key rotation", () => {
  it("verifies with the primary key and reports its id", () => {
    const v = rotator();
    const detail = v.verifyDetailed(BODY, signSha256(BODY, NEW_SECRET));
    assert.deepEqual(detail, { ok: true, keyId: "new" });
    assert.equal(v.verify(BODY, signSha256(BODY, NEW_SECRET)), true);
  });

  it("verifies a retired key inside the grace window and reports its id", () => {
    now = 1_000_000; // retired 100_000ms ago, grace is 200_000ms
    const v = rotator();
    const detail = v.verifyDetailed(BODY, signSha256(BODY, OLD_SECRET));
    assert.deepEqual(detail, { ok: true, keyId: "old" });
  });

  it("rejects a retired key outside the grace window", () => {
    now = 1_100_001; // retired 200_001ms ago, past the 200_000ms grace
    const v = rotator();
    const detail = v.verifyDetailed(BODY, signSha256(BODY, OLD_SECRET));
    assert.deepEqual(detail, { ok: false });
    assert.equal(v.verify(BODY, signSha256(BODY, OLD_SECRET)), false);
  });

  it("honors the grace boundary exactly (inclusive)", () => {
    now = 1_100_000; // retired exactly 200_000ms ago = graceMs
    const v = rotator();
    assert.deepEqual(v.verifyDetailed(BODY, signSha256(BODY, OLD_SECRET)), {
      ok: true,
      keyId: "old",
    });
    now = 1_100_001; // one ms past
    assert.deepEqual(v.verifyDetailed(BODY, signSha256(BODY, OLD_SECRET)), { ok: false });
  });

  it("treats a key retired in the future as still active", () => {
    now = 1_000_000;
    const v = rotator({
      keys: [
        { id: "old", secret: OLD_SECRET, retiredAtMs: 2_000_000 },
        { id: "new", secret: NEW_SECRET, primary: true },
      ],
    });
    assert.deepEqual(v.verifyDetailed(BODY, signSha256(BODY, OLD_SECRET)), {
      ok: true,
      keyId: "old",
    });
  });

  it("falls back through all active keys without a hint", () => {
    now = 1_000_000;
    const v = rotator();
    // `mid` is neither primary nor retired: found by the fallback sweep.
    assert.deepEqual(v.verifyDetailed(BODY, signSha256(BODY, MID_SECRET)), {
      ok: true,
      keyId: "mid",
    });
    // An unknown secret matches nothing.
    assert.deepEqual(v.verifyDetailed(BODY, signSha256(BODY, "bogus")), { ok: false });
  });

  it("the x-key-id hint selects exactly one key, no fallback", () => {
    now = 1_000_000;
    const v = rotator();
    // Correct hint: verifies.
    assert.deepEqual(v.verifyDetailed(BODY, signSha256(BODY, OLD_SECRET), { keyId: "old" }), {
      ok: true,
      keyId: "old",
    });
    // Hint names `new` but the signature is `old`'s: fails, no sweep.
    assert.deepEqual(v.verifyDetailed(BODY, signSha256(BODY, OLD_SECRET), { keyId: "new" }), {
      ok: false,
    });
    // Unknown key id: fails even though another key would verify.
    assert.deepEqual(v.verifyDetailed(BODY, signSha256(BODY, NEW_SECRET), { keyId: "nope" }), {
      ok: false,
    });
  });

  it("a hint naming a retired-past-grace key fails without fallback", () => {
    now = 1_100_001; // `old` is past its grace
    const v = rotator();
    assert.deepEqual(v.verifyDetailed(BODY, signSha256(BODY, OLD_SECRET), { keyId: "old" }), {
      ok: false,
    });
  });

  it("never throws on garbage input", () => {
    const v = rotator();
    assert.deepEqual(v.verifyDetailed(BODY, ""), { ok: false });
    assert.deepEqual(v.verifyDetailed(BODY, "garbage"), { ok: false });
    assert.deepEqual(v.verifyDetailed(BODY, "sha256=zzz"), { ok: false });
    assert.deepEqual(v.verifyDetailed(BODY, signSha256(BODY, NEW_SECRET), { keyId: "" }), {
      ok: true,
      keyId: "new",
    });
  });

  it("rejects invalid configs at construction", () => {
    assert.throws(() => new RotatingHmacVerifier({ keys: [] }), /non-empty array/);
    assert.throws(
      () =>
        new RotatingHmacVerifier({
          keys: [
            { id: "a", secret: "x" },
            { id: "a", secret: "y" },
          ],
        }),
      /duplicate key id/
    );
    assert.throws(
      () => new RotatingHmacVerifier({ keys: [{ id: "", secret: "x" }] }),
      /non-empty id/
    );
    assert.throws(
      () => new RotatingHmacVerifier({ keys: [{ id: "a", secret: "" }] }),
      /non-empty secret/
    );
    assert.throws(
      () =>
        new RotatingHmacVerifier({
          keys: [
            { id: "a", secret: "x", primary: true },
            { id: "b", secret: "y", primary: true },
          ],
        }),
      /at most one/
    );
    assert.throws(
      () => new RotatingHmacVerifier({ keys: [{ id: "a", secret: "x" }], graceMs: -1 }),
      /graceMs/
    );
    assert.throws(
      () =>
        new RotatingHmacVerifier({
          keys: [{ id: "a", secret: "x", retiredAtMs: Number.NaN }],
        }),
      /retiredAtMs/
    );
  });

  it("exposes the default grace period constant", () => {
    assert.equal(DEFAULT_KEY_GRACE_MS, 86_400_000);
    const v = new RotatingHmacVerifier({ keys: [{ id: "a", secret: "x" }] });
    assert.equal(v.verify(BODY, signSha256(BODY, "x")), true);
  });
});

describe("key rotation via server", () => {
  let stub: Server;
  let stubPort: number;
  const received: RetryItem[] = [];

  before(async () => {
    stub = createServer((req, res) => {
      req.resume();
      req.on("end", () => {
        received.push({} as RetryItem);
        res.writeHead(200).end("ok");
      });
    });
    await new Promise<void>((resolve) => stub.listen(0, "127.0.0.1", resolve));
    const addr = stub.address();
    assert.ok(addr && typeof addr === "object");
    stubPort = addr.port;
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  function post(port: number, body: Buffer, headers: Record<string, string>) {
    return new Promise<{ status: number; text: string }>((resolve, reject) => {
      const r = httpRequest({ host: "127.0.0.1", port, path: "/", method: "POST", headers }, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() }));
      });
      r.on("error", reject);
      r.end(body);
    });
  }

  function relayWithKeys(graceNow: number) {
    const dir = mkdtempSync(join(tmpdir(), "rotation-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
secret: "rotation-test-secret",
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 3 },
      signingKeys: [
        { id: "old", secret: OLD_SECRET, retiredAtMs: 900_000 },
        { id: "new", secret: NEW_SECRET, primary: true },
      ],
      keyGraceMs: 200_000,
      keyNowMs: () => graceNow,
    });
    return { relay, audit };
  }

  it("accepts an in-grace rotated key and audits its keyId", async () => {
    const { relay, audit } = relayWithKeys(1_000_000);
    await new Promise<void>((resolve) => relay.listen(0, "127.0.0.1", resolve));
    const port = (relay.address() as { port: number }).port;
    try {
      const res = await post(port, BODY, {
        "x-signature": signSha256(BODY, OLD_SECRET),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
      const accepted = (audit.readAll() as Array<Record<string, unknown>>).filter(
        (e) => e.event === "accepted"
      );
      assert.equal(accepted.length, 1);
      assert.equal(accepted[0].keyId, "old");
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("accepts the primary key without a hint and audits its keyId", async () => {
    const { relay, audit } = relayWithKeys(1_000_000);
    await new Promise<void>((resolve) => relay.listen(0, "127.0.0.1", resolve));
    const port = (relay.address() as { port: number }).port;
    try {
      const res = await post(port, BODY, {
        "x-signature": signSha256(BODY, NEW_SECRET),
        "content-type": "application/json",
      });
      assert.equal(res.status, 202);
      const accepted = (audit.readAll() as Array<Record<string, unknown>>).filter(
        (e) => e.event === "accepted"
      );
      assert.equal(accepted.length, 1);
      assert.equal(accepted[0].keyId, "new");
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("rejects a past-grace rotated key with 401 and audits keyId unknown", async () => {
    const { relay, audit } = relayWithKeys(1_100_001);
    await new Promise<void>((resolve) => relay.listen(0, "127.0.0.1", resolve));
    const port = (relay.address() as { port: number }).port;
    try {
      const res = await post(port, BODY, {
        "x-signature": signSha256(BODY, OLD_SECRET),
        "content-type": "application/json",
      });
      assert.equal(res.status, 401);
      const rejected = (audit.readAll() as Array<Record<string, unknown>>).filter(
        (e) => e.event === "rejected"
      );
      assert.equal(rejected.length, 1);
      assert.equal(rejected[0].reason, "invalid_signature");
      assert.equal(rejected[0].keyId, "unknown");
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("honors the x-key-id hint: a mismatched hint is 401", async () => {
    const { relay, audit } = relayWithKeys(1_000_000);
    await new Promise<void>((resolve) => relay.listen(0, "127.0.0.1", resolve));
    const port = (relay.address() as { port: number }).port;
    try {
      // Signature is valid for `new`, but the hint names `old`.
      const res = await post(port, BODY, {
        "x-signature": signSha256(BODY, NEW_SECRET),
        "x-key-id": "old",
        "content-type": "application/json",
      });
      assert.equal(res.status, 401);
      const rejected = (audit.readAll() as Array<Record<string, unknown>>).filter(
        (e) => e.event === "rejected"
      );
      assert.equal(rejected.length, 1);
      assert.equal(rejected[0].keyId, "unknown");
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("plain-secret servers keep audit events free of keyId", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rotation-plain-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: NEW_SECRET,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 3 },
    });
    await new Promise<void>((resolve) => relay.listen(0, "127.0.0.1", resolve));
    const port = (relay.address() as { port: number }).port;
    try {
      const ok = await post(port, BODY, { "x-signature": signSha256(BODY, NEW_SECRET) });
      assert.equal(ok.status, 202);
      const bad = await post(port, BODY, { "x-signature": signSha256(BODY, "wrong") });
      assert.equal(bad.status, 401);
      for (const e of audit.readAll() as Array<Record<string, unknown>>) {
        assert.ok(!("keyId" in e), `legacy audit event must not carry keyId: ${JSON.stringify(e)}`);
      }
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("rejects combining verifier and signingKeys", () => {
    const dir = mkdtempSync(join(tmpdir(), "rotation-conflict-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    assert.throws(
      () =>
        createRelayServer({
secret: "rotation-test-secret",
          forwardUrl: "http://127.0.0.1:1/hook",
          auditLog: audit,
          verifier: new RotatingHmacVerifier({ keys: [{ id: "a", secret: "x" }] }),
          signingKeys: [{ id: "a", secret: "x" }],
        }),
      /cannot be combined/
    );
  });
});
