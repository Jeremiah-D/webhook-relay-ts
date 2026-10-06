import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { parseSignatureHeader, signSha256, signTimestamped, verifySignature } from "../src/verify.ts";

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
