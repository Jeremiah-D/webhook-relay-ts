import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHmac, generateKeyPairSync } from "node:crypto";
import {
  Ed25519Verifier,
  HmacSha256Verifier,
  getVerifier,
  parseSignatureHeader,
  registerVerifier,
  signEd25519,
  signSha256,
  signTimestamped,
  verifierNames,
  verifySignature,
  verifyWith,
  type Verifier,
} from "../src/verify.ts";

const SECRET = "test-secret-123";
const BODY = Buffer.from(JSON.stringify({ event: "payment.succeeded", id: "evt_1" }));

describe("verify", () => {
  it("accepts a valid sha256 signature", () => {
    const header = signSha256(BODY, SECRET);
    assert.equal(verifySignature(BODY, header, SECRET), true);
  });

  it("accepts a valid timestamped signature", () => {
    const header = signTimestamped(BODY, SECRET);
    assert.equal(verifySignature(BODY, header, SECRET), true);
  });

  it("rejects a tampered body", () => {
    const header = signSha256(BODY, SECRET);
    const tampered = Buffer.from(JSON.stringify({ event: "payment.succeeded", id: "evt_2" }));
    assert.equal(verifySignature(tampered, header, SECRET), false);
  });

  it("rejects a wrong secret", () => {
    const header = signSha256(BODY, SECRET);
    assert.equal(verifySignature(BODY, header, "wrong-secret"), false);
  });

  it("rejects an expired timestamp", () => {
    const oldTs = Math.floor(Date.now() / 1000) - 3600; // 1h ago
    const header = signTimestamped(BODY, SECRET, oldTs);
    assert.equal(verifySignature(BODY, header, SECRET, { toleranceSec: 300 }), false);
  });

  it("rejects a missing header", () => {
    assert.equal(verifySignature(BODY, "", SECRET), false);
  });

  it("rejects malformed headers", () => {
    assert.equal(verifySignature(BODY, "not-a-signature", SECRET), false);
    assert.equal(verifySignature(BODY, "sha256=zzz", SECRET), false);
  });

  it("parses both header formats", () => {
    const a = parseSignatureHeader(signSha256(BODY, SECRET));
    assert.equal(a.scheme, "sha256");
    assert.equal(a.timestamp, undefined);

    const ts = Math.floor(Date.now() / 1000);
    const b = parseSignatureHeader(signTimestamped(BODY, SECRET, ts));
    assert.equal(b.scheme, "timestamped");
    assert.equal(b.timestamp, ts);
  });

  it("uses constant-time comparison", () => {
    // Same-length but different signature must fail without throwing.
    const header = signSha256(BODY, SECRET);
    const bytes = Buffer.from(header.slice("sha256=".length), "hex");
    bytes[0] ^= 0xff;
    assert.equal(verifySignature(BODY, `sha256=${bytes.toString("hex")}`, SECRET), false);
    // Length mismatch must fail without throwing (timingSafeEqual guard).
    assert.equal(verifySignature(BODY, "sha256=ab", SECRET), false);
  });

  it("timestamped signature covers `<ts>.<rawBody>`", () => {
    const ts = Math.floor(Date.now() / 1000);
    const signed = Buffer.concat([Buffer.from(`${ts}.`), BODY]);
    const sig = createHmac("sha256", SECRET).update(signed).digest("hex");
    assert.equal(verifySignature(BODY, `t=${ts},v1=${sig}`, SECRET), true);
  });
});

describe("pluggable verifiers", () => {
  it("HmacSha256Verifier accepts and rejects like verifySignature", () => {
    const v = new HmacSha256Verifier(SECRET);
    assert.equal(v.name, "hmac-sha256");
    assert.equal(v.verify(BODY, signSha256(BODY, SECRET)), true);
    assert.equal(v.verify(BODY, signTimestamped(BODY, SECRET)), true);

    const tampered = Buffer.from(JSON.stringify({ event: "payment.succeeded", id: "evt_2" }));
    assert.equal(v.verify(tampered, signSha256(BODY, SECRET)), false);
    assert.equal(v.verify(BODY, signSha256(BODY, "wrong-secret")), false);
    assert.equal(v.verify(BODY, "not-a-signature"), false); // never throws
  });

  it("Ed25519Verifier checks an asymmetric signature over the raw body", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const pubPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const privPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const v = new Ed25519Verifier(pubPem);
    assert.equal(v.name, "ed25519");

    const header = signEd25519(BODY, privPem);
    assert.ok(header.startsWith("ed25519="));
    assert.equal(v.verify(BODY, header), true);

    const tampered = Buffer.from(JSON.stringify({ event: "payment.succeeded", id: "evt_2" }));
    assert.equal(v.verify(tampered, header), false);

    // A different key must fail.
    const other = generateKeyPairSync("ed25519");
    const otherPem = other.publicKey.export({ type: "spki", format: "pem" }).toString();
    assert.equal(new Ed25519Verifier(otherPem).verify(BODY, header), false);

    // Malformed headers and foreign schemes never throw.
    assert.equal(v.verify(BODY, ""), false);
    assert.equal(v.verify(BODY, "ed25519=zzz"), false);
    assert.equal(v.verify(BODY, signSha256(BODY, SECRET)), false);
  });

  it("registry registers, resolves, and dispatches by name", () => {
    const stub: Verifier = {
      name: "test-stub",
      verify: (_rawBody, header) => header === "ok",
    };
    registerVerifier(stub);
    assert.equal(getVerifier("test-stub"), stub);
    assert.ok(verifierNames().includes("test-stub"));
    assert.equal(verifyWith(BODY, "ok", "test-stub"), true);
    assert.equal(verifyWith(BODY, "nope", "test-stub"), false);
    // Unknown scheme names fail closed.
    assert.equal(verifyWith(BODY, "ok", "no-such-scheme"), false);
  });

  it("verifyWith never throws, even for a misbehaving verifier", () => {
    registerVerifier({
      name: "test-thrower",
      verify: () => {
        throw new Error("boom");
      },
    });
    assert.equal(verifyWith(BODY, "ok", "test-thrower"), false);
  });

  it("registerVerifier validates its input", () => {
    assert.throws(() => registerVerifier({ name: "", verify: () => true } as Verifier));
  });

  it("an Ed25519Verifier can be registered and dispatched by name", () => {
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    const pubPem = publicKey.export({ type: "spki", format: "pem" }).toString();
    const privPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    registerVerifier(new Ed25519Verifier(pubPem));
    assert.equal(verifyWith(BODY, signEd25519(BODY, privPem), "ed25519"), true);
    assert.equal(verifyWith(BODY, "ed25519=00", "ed25519"), false);
  });
});
