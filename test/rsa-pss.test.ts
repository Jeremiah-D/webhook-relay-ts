import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { generateKeyPairSync, createPublicKey } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import {
  RotatingRsaPssVerifier,
  RsaPssVerifier,
  publicKeyFingerprint,
  registerVerifier,
  signRsaPss,
  verifyWith,
} from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";

const BODY = Buffer.from(JSON.stringify({ event: "payment.succeeded", amount: 100 }));

function makeRsaKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  return {
    pubPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
  };
}

const HEX64_RE = /^[0-9a-f]{64}$/;

describe("RsaPssVerifier", () => {
  const { pubPem, privPem } = makeRsaKeypair();

  it("has the rsa-pss scheme name and verifies a signRsaPss header", () => {
    const v = new RsaPssVerifier(pubPem);
    assert.equal(v.name, "rsa-pss");
    const header = signRsaPss(BODY, privPem);
    assert.ok(header.startsWith("rsa-sha256="));
    assert.equal(v.verify(BODY, header), true);
  });

  it("accepts both signatures when the PSS salt randomizes them", () => {
    const v = new RsaPssVerifier(pubPem);
    const h1 = signRsaPss(BODY, privPem);
    const h2 = signRsaPss(BODY, privPem);
    assert.notEqual(h1, h2); // random salt per signature
    assert.equal(v.verify(BODY, h1), true);
    assert.equal(v.verify(BODY, h2), true);
  });

  it("rejects a signature from a different key and a tampered body", () => {
    const v = new RsaPssVerifier(pubPem);
    const other = makeRsaKeypair();
    assert.equal(v.verify(BODY, signRsaPss(BODY, other.privPem)), false);
    assert.equal(v.verify(Buffer.from("tampered"), signRsaPss(BODY, privPem)), false);
  });

  it("never throws on malformed headers", () => {
    const v = new RsaPssVerifier(pubPem);
    for (const bad of [
      "",
      "rsa-sha256=",
      "rsa-sha256=!!!",
      "rsa-sha256=zz", // bad length for base64
      "sha256=deadbeef",
      "ed25519=deadbeef",
      "Bearer token",
    ]) {
      assert.equal(v.verify(BODY, bad), false, JSON.stringify(bad));
    }
  });

  it("rejects construction with an empty or invalid PEM", () => {
    assert.throws(() => new RsaPssVerifier(""), /non-empty PEM/);
    assert.throws(() => new RsaPssVerifier("not a pem at all"));
  });

  it("exposes a stable 64-hex SHA-256 fingerprint of the public key", () => {
    const v = new RsaPssVerifier(pubPem);
    assert.ok(HEX64_RE.test(v.fingerprint));
    assert.equal(v.fingerprint, new RsaPssVerifier(pubPem).fingerprint);
    assert.notEqual(v.fingerprint, new RsaPssVerifier(makeRsaKeypair().pubPem).fingerprint);
  });

  it("publicKeyFingerprint matches the verifier fingerprint", () => {
    const v = new RsaPssVerifier(pubPem);
    assert.equal(publicKeyFingerprint(createPublicKey(pubPem)), v.fingerprint);
  });
});

describe("RotatingRsaPssVerifier", () => {
  const oldKeys = makeRsaKeypair();
  const newKeys = makeRsaKeypair();
  const stranger = makeRsaKeypair();

  function makeRotating() {
    return new RotatingRsaPssVerifier([oldKeys.pubPem, newKeys.pubPem]);
  }

  it("verifies signatures from old and new keys in parallel during rotation", () => {
    const v = makeRotating();
    assert.equal(v.name, "rsa-pss-rotating");
    assert.equal(v.verify(BODY, signRsaPss(BODY, oldKeys.privPem)), true);
    assert.equal(v.verify(BODY, signRsaPss(BODY, newKeys.privPem)), true);
  });

  it("verifyDetailed attributes the match to the right key fingerprint", () => {
    const v = makeRotating();
    const oldFp = new RsaPssVerifier(oldKeys.pubPem).fingerprint;
    const newFp = new RsaPssVerifier(newKeys.pubPem).fingerprint;
    assert.notEqual(oldFp, newFp);
    assert.deepEqual(v.verifyDetailed(BODY, signRsaPss(BODY, oldKeys.privPem)), {
      ok: true,
      keyId: oldFp,
    });
    assert.deepEqual(v.verifyDetailed(BODY, signRsaPss(BODY, newKeys.privPem)), {
      ok: true,
      keyId: newFp,
    });
    assert.deepEqual(v.keyFingerprints, [oldFp, newFp]);
  });

  it("rejects signatures from an unknown key", () => {
    const v = makeRotating();
    assert.equal(v.verify(BODY, signRsaPss(BODY, stranger.privPem)), false);
    assert.deepEqual(v.verifyDetailed(BODY, signRsaPss(BODY, stranger.privPem)), { ok: false });
  });

  it("rejects empty, duplicate, and invalid key lists at construction", () => {
    assert.throws(() => new RotatingRsaPssVerifier([]), /non-empty array/);
    assert.throws(() => new RotatingRsaPssVerifier([oldKeys.pubPem, oldKeys.pubPem]), /duplicates/);
    assert.throws(() => new RotatingRsaPssVerifier(["garbage"]), /valid PEM/);
    assert.throws(() => new RotatingRsaPssVerifier(["" as string]), /non-empty PEM/);
  });
});

describe("RSA-PSS registry dispatch", () => {
  it("a registered RsaPssVerifier dispatches by name", () => {
    const { pubPem, privPem } = makeRsaKeypair();
    registerVerifier(new RsaPssVerifier(pubPem));
    assert.equal(verifyWith(BODY, signRsaPss(BODY, privPem), "rsa-pss"), true);
    assert.equal(verifyWith(BODY, "rsa-sha256=AA==", "rsa-pss"), false);
  });
});

describe("server RSA-PSS verifier wiring (WR-110)", () => {
  let stub: Server;
  let stubPort: number;

  const { pubPem, privPem } = makeRsaKeypair();
  const otherKeys = makeRsaKeypair();

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

  function makeRelay(opts: Record<string, unknown>) {
    const dir = mkdtempSync(join(tmpdir(), "audit-rsa-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: "unused-when-custom-verifier",
      forwardUrl: `http://127.0.0.1:${stubPort}/hook`,
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
      ...opts,
    });
    return { relay, audit };
  }

  it("a global RsaPssVerifier accepts rsa-sha256 and rejects anything else", async () => {
    const { relay, audit } = makeRelay({ verifier: new RsaPssVerifier(pubPem) });
    const port = await listen(relay);
    try {
      const ok = await post(port, "/hooks/bank", BODY, { "x-signature": signRsaPss(BODY, privPem) });
      assert.equal(ok.status, 202);
      const wrongKey = await post(port, "/hooks/bank", BODY, {
        "x-signature": signRsaPss(BODY, otherKeys.privPem),
      });
      assert.equal(wrongKey.status, 401);
      const events = audit.readAll() as Array<Record<string, unknown>>;
      const accepted = events.filter((e) => e.event === "accepted");
      assert.equal(accepted.length, 1);
      // The global verifier path does not name the verifier on the audit
      // event (only per-endpoint rules do); the 202/401 split is the assertion.
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });

  it("a per-endpoint RotatingRsaPssVerifier attributes the key fingerprint in audit", async () => {
    const rotating = new RotatingRsaPssVerifier([pubPem, otherKeys.pubPem]);
    const { relay, audit } = makeRelay({
      endpointVerifiers: [{ pattern: "/hooks/bank", verifier: rotating }],
    });
    const port = await listen(relay);
    try {
      const ok = await post(port, "/hooks/bank", BODY, { "x-signature": signRsaPss(BODY, privPem) });
      assert.equal(ok.status, 202);
      const events = audit.readAll() as Array<Record<string, unknown>>;
      const accepted = events.filter((e) => e.event === "accepted");
      assert.equal(accepted.length, 1);
      assert.equal(accepted[0].verifier, "rsa-pss-rotating");
      assert.equal(accepted[0].keyId, new RsaPssVerifier(pubPem).fingerprint);
    } finally {
      relay.close();
      await new Promise((r) => relay.once("close", r));
    }
  });
});
