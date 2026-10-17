import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDefaultSender, createRelayServer } from "../src/server.ts";
import { Ed25519Verifier, signSha256, verifySignature } from "../src/verify.ts";
import {
  compileEd25519OutboundKey,
  ED25519_KEY_ID_HEADER,
  ED25519_SIGNATURE_HEADER,
  RotatingEd25519Verifier,
  signEd25519Outbound,
} from "../src/outbound-ed25519.ts";
import { AuditLog } from "../src/audit.ts";
import type { RetryItem } from "../src/retry.ts";

const hmacKey = "test-hmac-key";
const inboundKey = "inbound-test-key";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook" }));

function ed25519KeyPair(): { privatePem: string; publicPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

describe("WR-124 outbound Ed25519 asymmetric signing", () => {
  let stub: Server;
  let stubPort: number;
  const seen: Array<{ headers: Record<string, unknown>; body: Buffer }> = [];

  before(async () => {
    stub = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        seen.push({ headers: { ...req.headers }, body: Buffer.concat(chunks) });
        res.writeHead(200).end("ok");
      });
    });
    stubPort = await listen(stub);
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  function item(): RetryItem {
    return {
      id: "item-1",
      traceId: "trace-1",
      payload: BODY,
      targetUrl: `http://127.0.0.1:${stubPort}/hook`,
      headers: {},
    };
  }

  async function deliverAndWait(sender: { (i: RetryItem): Promise<void>; destroy(): void }) {
    seen.length = 0;
    await sender(item());
    const deadline = Date.now() + 5000;
    while (seen.length === 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    sender.destroy();
    assert.equal(seen.length, 1);
    return seen[0];
  }

  it("stamps x-relay-ed25519-signature + key id; downstream verifies with the public key alone", async () => {
    const pair = ed25519KeyPair();
    const sender = createDefaultSender(undefined, false, {
      secret: hmacKey,
      keyId: "hmac-1",
      ed25519: { privateKey: pair.privatePem, keyId: "ed1" },
    });
    try {
      const got = await deliverAndWait(sender);
      // Ed25519 signatures are deterministic: recomputing must match.
      const expected = signEd25519Outbound(
        BODY,
        compileEd25519OutboundKey({ privateKey: pair.privatePem }, "test")
      );
      assert.equal(got.headers[ED25519_SIGNATURE_HEADER], expected);
      assert.equal(got.headers[ED25519_KEY_ID_HEADER], "ed1");
      // The downstream contract: public key alone is enough.
      const verifier = new Ed25519Verifier(pair.publicPem);
      assert.ok(verifier.verify(got.body, String(got.headers[ED25519_SIGNATURE_HEADER])));
      // Wrong public key rejects.
      assert.ok(!new Ed25519Verifier(ed25519KeyPair().publicPem).verify(got.body, String(got.headers[ED25519_SIGNATURE_HEADER])));
    } finally {
      sender.destroy();
    }
  });

  it("coexists with the HMAC stamp: either signature verifies the delivery", async () => {
    const pair = ed25519KeyPair();
    const sender = createDefaultSender(undefined, false, {
      secret: hmacKey,
      ed25519: { privateKey: pair.privatePem },
    });
    try {
      const got = await deliverAndWait(sender);
      const hmacHeader = String(got.headers["x-relay-signature"]);
      const edHeader = String(got.headers[ED25519_SIGNATURE_HEADER]);
      // HMAC leg: shared secret.
      assert.ok(verifySignature(got.body, hmacHeader, hmacKey));
      assert.ok(!verifySignature(got.body, hmacHeader, "wrong-key"));
      // Ed25519 leg: public key only.
      assert.ok(new Ed25519Verifier(pair.publicPem).verify(got.body, edHeader));
      // Cross-scheme isolation: neither verifier accepts the other's header.
      assert.ok(!new Ed25519Verifier(pair.publicPem).verify(got.body, hmacHeader));
      assert.ok(!verifySignature(got.body, edHeader, hmacKey));
    } finally {
      sender.destroy();
    }
  });

  it("rejects a tampered body under Ed25519", async () => {
    const pair = ed25519KeyPair();
    const compiled = compileEd25519OutboundKey({ privateKey: pair.privatePem }, "test");
    const header = signEd25519Outbound(BODY, compiled);
    const verifier = new Ed25519Verifier(pair.publicPem);
    assert.ok(verifier.verify(BODY, header));
    const tampered = Buffer.from(BODY);
    tampered[tampered.length - 1] ^= 0x01;
    assert.ok(!verifier.verify(tampered, header));
  });

  it("omits Ed25519 headers when not configured (WR-26-only behavior is byte-identical)", async () => {
    const sender = createDefaultSender(undefined, false, { secret: hmacKey, keyId: "hmac-1" });
    try {
      const got = await deliverAndWait(sender);
      assert.equal(got.headers["x-relay-signature"], signSha256(BODY, hmacKey));
      assert.equal(got.headers["x-relay-key-id"], "hmac-1");
      assert.equal(got.headers[ED25519_SIGNATURE_HEADER], undefined);
      assert.equal(got.headers[ED25519_KEY_ID_HEADER], undefined);
    } finally {
      sender.destroy();
    }
  });

  it("overwrites a forged inbound x-relay-ed25519-signature with the relay's own", async () => {
    const pair = ed25519KeyPair();
    const dir = mkdtempSync(join(tmpdir(), "outed-"));
    const relay = createRelayServer({
      secret: inboundKey,
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      outboundSigning: { secret: hmacKey, ed25519: { privateKey: pair.privatePem, keyId: "ed1" } },
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
    });
    const port = await listen(relay);
    try {
      seen.length = 0;
      await new Promise<void>((resolve, reject) => {
        const r = httpRequest(
          {
            host: "127.0.0.1",
            port,
            path: "/",
            method: "POST",
            headers: {
              "x-signature": signSha256(BODY, inboundKey),
              [ED25519_SIGNATURE_HEADER]: "ed25519=" + "ab".repeat(64),
              [ED25519_KEY_ID_HEADER]: "attacker-key",
            },
          },
          (res) => {
            res.resume();
            res.on("end", resolve);
          }
        );
        r.on("error", reject);
        r.end(BODY);
      });
      const deadline = Date.now() + 5000;
      while (seen.length === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(seen.length, 1);
      const expected = signEd25519Outbound(
        BODY,
        compileEd25519OutboundKey({ privateKey: pair.privatePem }, "test")
      );
      // The forged headers never reach the downstream; the relay's own win.
      assert.equal(seen[0].headers[ED25519_SIGNATURE_HEADER], expected);
      assert.equal(seen[0].headers[ED25519_KEY_ID_HEADER], "ed1");
      // HMAC still stamped alongside.
      assert.equal(seen[0].headers["x-relay-signature"], signSha256(BODY, hmacKey));
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("fails fast at startup on an invalid Ed25519 config", () => {
    assert.throws(
      () => createDefaultSender(undefined, false, { secret: hmacKey, ed25519: { privateKey: "not-a-pem" } }),
      RangeError
    );
    assert.throws(
      () => createDefaultSender(undefined, false, { secret: hmacKey, ed25519: { privateKey: "" } }),
      RangeError
    );
    assert.throws(
      () => compileEd25519OutboundKey({ privateKey: "not-a-pem" }, "test"),
      RangeError
    );
    // A non-Ed25519 private key is rejected, not silently misused.
    const { privateKey: rsaKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    assert.throws(
      () =>
        compileEd25519OutboundKey(
          { privateKey: rsaKey.export({ type: "pkcs8", format: "pem" }).toString() },
          "test"
        ),
      RangeError
    );
  });
});

describe("WR-124 RotatingEd25519Verifier", () => {
  const oldPair = ed25519KeyPair();
  const newPair = ed25519KeyPair();

  function oldSig(): string {
    return signEd25519Outbound(
      BODY,
      compileEd25519OutboundKey({ privateKey: oldPair.privatePem }, "test")
    );
  }

  function newSig(): string {
    return signEd25519Outbound(
      BODY,
      compileEd25519OutboundKey({ privateKey: newPair.privatePem }, "test")
    );
  }

  it("keeps the retired key verifiable inside the grace window", () => {
    let now = Date.now();
    const verifier = new RotatingEd25519Verifier({
      currentPublicKey: newPair.publicPem,
      currentKeyId: "ed-new",
      previousPublicKey: oldPair.publicPem,
      previousKeyId: "ed-old",
      previousRetiredAtMs: now - 3600_000, // retired 1h ago
      graceMs: 24 * 3600_000,
      nowMs: () => now,
    });
    assert.equal(verifier.previousInGrace(), true);
    assert.equal(verifier.isRotationComplete(), false);
    // Old-key signatures still verify, attributed to the previous key.
    assert.deepEqual(verifier.verifyDetailed(BODY, oldSig()), { ok: true, version: "previous" });
    assert.ok(verifier.verify(BODY, oldSig()));
    // New-key signatures verify as current.
    assert.deepEqual(verifier.verifyDetailed(BODY, newSig()), { ok: true, version: "current" });
    // The key-id hint selects a side; an unknown id fails closed.
    assert.deepEqual(verifier.verifyDetailed(BODY, oldSig(), { keyId: "ed-old" }), {
      ok: true,
      version: "previous",
    });
    assert.deepEqual(verifier.verifyDetailed(BODY, oldSig(), { keyId: "ed-new" }), { ok: false });
    assert.deepEqual(verifier.verifyDetailed(BODY, oldSig(), { keyId: "nope" }), { ok: false });
    // Past the grace window the old key is dead; the rotation is complete.
    now += 24 * 3600_000 + 1;
    assert.equal(verifier.previousInGrace(), false);
    assert.ok(!verifier.verify(BODY, oldSig()));
    assert.equal(verifier.isRotationComplete(), true);
    // The current key is unaffected.
    assert.ok(verifier.verify(BODY, newSig()));
  });

  it("a verifier with no previous key only trusts the current key", () => {
    const verifier = new RotatingEd25519Verifier({ currentPublicKey: newPair.publicPem });
    assert.ok(verifier.verify(BODY, newSig()));
    assert.ok(!verifier.verify(BODY, oldSig()));
    assert.equal(verifier.previousInGrace(), false);
    assert.equal(verifier.isRotationComplete(), false);
  });

  it("never throws on garbage input", () => {
    const verifier = new RotatingEd25519Verifier({ currentPublicKey: newPair.publicPem });
    assert.ok(!verifier.verify(BODY, "ed25519=zz"));
    assert.ok(!verifier.verify(BODY, ""));
    assert.ok(!verifier.verify(BODY, "sha256=deadbeef"));
    assert.deepEqual(verifier.verifyDetailed(BODY, "ed25519=zz"), { ok: false });
  });

  it("rejects invalid rotation configs at construction", () => {
    assert.throws(() => new RotatingEd25519Verifier({ currentPublicKey: "" }), RangeError);
    assert.throws(() => new RotatingEd25519Verifier({ currentPublicKey: "nope" }), RangeError);
    assert.throws(
      () =>
        new RotatingEd25519Verifier({
          currentPublicKey: newPair.publicPem,
          currentKeyId: "same",
          previousPublicKey: oldPair.publicPem,
          previousKeyId: "same",
        }),
      RangeError
    );
    const { publicKey: rsaPub } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    assert.throws(
      () =>
        new RotatingEd25519Verifier({
          currentPublicKey: rsaPub.export({ type: "spki", format: "pem" }).toString(),
        }),
      RangeError
    );
  });
});
