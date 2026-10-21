import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import {
  Ed25519Verifier,
  HmacSha256Verifier,
  StripeSignatureVerifier,
  getVerifier,
  parseStripeSignatureHeader,
  registerVerifier,
  selectEndpointVerifier,
  signStripe,
  verifyWith,
  type Verifier,
} from "../src/verify.ts";

const BODY = Buffer.from(JSON.stringify({ event: "payment.succeeded", id: "evt_9" }));
const stripeKey = "whsec_test_relay_secret";
const oldKey = "whsec_old_rotation_secret";
const newKey = "whsec_new_rotation_secret";

// Deterministic clock: tests advance `now` explicitly.
let now = 1_700_000_000_000;
const nowMs = () => now;
const nowSec = () => Math.floor(now / 1000);

function verifier(overrides: Partial<{ secrets: string | string[]; toleranceSec: number }> = {}) {
  return new StripeSignatureVerifier({ secrets: stripeKey, nowMs, ...overrides });
}

describe("parseStripeSignatureHeader", () => {
  it("parses t=,v1= and multiple v1 values", () => {
    const parsed = parseStripeSignatureHeader(
      `t=${nowSec()},v1=${"ab".repeat(32)},v1=${"cd".repeat(32)}`
    );
    assert.equal(parsed.timestamp, nowSec());
    assert.equal(parsed.signatures.length, 2);
    assert.equal(parsed.signatures[0].toString("hex"), "ab".repeat(32));
  });

  it("throws on malformed headers", () => {
    for (const bad of [
      "",
      "v1=abcd", // missing t=
      "t=abc,v1=abcd", // non-numeric t
      "t=0,v1=abcd", // non-positive t
      "t=1700000000", // no v1 at all
      "t=1700000000,v0=abcd", // wrong field name
      "t=1700000000,v1=xyz", // non-hex
      "t=1700000000,v1=abc", // odd-length hex
    ]) {
      assert.throws(() => parseStripeSignatureHeader(bad), /StripeSignatureVerifier/);
    }
  });
});

describe("StripeSignatureVerifier", () => {
  it("verifies a well-formed Stripe-style header", () => {
    const v = verifier();
    const header = signStripe(BODY, stripeKey, nowSec());
    assert.equal(v.verify(BODY, header), true);
  });

  it("rejects a tampered body", () => {
    const v = verifier();
    const header = signStripe(BODY, stripeKey, nowSec());
    assert.equal(v.verify(Buffer.from("tampered"), header), false);
  });

  it("rejects a wrong secret", () => {
    const v = verifier();
    const header = signStripe(BODY, "whsec_attacker", nowSec());
    assert.equal(v.verify(BODY, header), false);
  });

  it("accepts any of several v1 values (header-side rotation)", () => {
    const v = verifier({ secrets: newKey });
    // Upstream signs with both old and new keys during rotation.
    const header = signStripe(BODY, oldKey, nowSec(), [newKey]);
    assert.ok(header.includes(",v1="));
    assert.equal(v.verify(BODY, header), true);
  });

  it("accepts any of several configured secrets (relay-side rotation)", () => {
    const v = verifier({ secrets: [oldKey, newKey] });
    const header = signStripe(BODY, oldKey, nowSec());
    assert.equal(v.verify(BODY, header), true);
  });

  it("rejects a missing timestamp explicitly (no silent pass)", () => {
    const v = verifier();
    assert.equal(v.verify(BODY, "v1=abcd"), false);
  });

  it("rejects an expired timestamp (replay protection)", () => {
    const v = verifier();
    const header = signStripe(BODY, stripeKey, nowSec() - 301);
    assert.equal(v.verify(BODY, header), false);
  });

  it("accepts a timestamp exactly at the tolerance boundary", () => {
    const v = verifier();
    const header = signStripe(BODY, stripeKey, nowSec() - 300);
    assert.equal(v.verify(BODY, header), true);
  });

  it("rejects a future timestamp beyond tolerance", () => {
    const v = verifier();
    const header = signStripe(BODY, stripeKey, nowSec() + 301);
    assert.equal(v.verify(BODY, header), false);
  });

  it("honours a custom toleranceSec", () => {
    const v = verifier({ toleranceSec: 60 });
    assert.equal(v.verify(BODY, signStripe(BODY, stripeKey, nowSec() - 61)), false);
    assert.equal(v.verify(BODY, signStripe(BODY, stripeKey, nowSec() - 60)), true);
  });

  it("per-call opts override the configured clock/tolerance", () => {
    const v = verifier({ toleranceSec: 300 });
    const header = signStripe(BODY, stripeKey, nowSec() - 120);
    assert.equal(v.verify(BODY, header, { toleranceSec: 60 }), false);
    assert.equal(
      v.verify(BODY, header, { toleranceSec: 60, nowMs: () => (nowSec() - 120) * 1000 }),
      true
    );
  });

  it("never throws on malformed headers", () => {
    const v = verifier();
    for (const bad of ["", "garbage", "t=,v1=", "sha256=abcd"]) {
      assert.equal(v.verify(BODY, bad), false);
    }
  });

  it("validates constructor config", () => {
    assert.throws(() => new StripeSignatureVerifier({ secrets: "" } as never), /secrets/);
    assert.throws(() => new StripeSignatureVerifier({ secrets: [] }), /secrets/);
    assert.throws(
      () => new StripeSignatureVerifier({ secrets: [stripeKey, ""] }),
      /secrets/
    );
    assert.throws(
      () => new StripeSignatureVerifier({ secrets: stripeKey, toleranceSec: -1 }),
      /toleranceSec/
    );
    assert.throws(
      () => new StripeSignatureVerifier({ secrets: stripeKey, toleranceSec: NaN }),
      /toleranceSec/
    );
  });

  it("signed payload is `<t>.<rawBody>`, not the raw body", () => {
    // Proves the scheme binds the timestamp into the MAC: a plain
    // HMAC-SHA256 of the body is not a valid Stripe-style signature.
    const v = verifier();
    const mac = createHmac("sha256", stripeKey).update(BODY).digest("hex");
    assert.equal(v.verify(BODY, `t=${nowSec()},v1=${mac}`), false);
  });
});

describe("registry + per-endpoint routing", () => {
  it("registers under the stripe-signature scheme name", () => {
    const v: Verifier = new StripeSignatureVerifier({ secrets: stripeKey, nowMs });
    registerVerifier(v);
    assert.equal(getVerifier("stripe-signature"), v);
    const header = signStripe(BODY, stripeKey, nowSec());
    assert.equal(verifyWith(BODY, header, "stripe-signature", { nowMs }), true);
    assert.equal(verifyWith(BODY, header, "no-such-verifier"), false);
  });

  it("coexists with HMAC and Ed25519 verifiers on different path patterns", () => {
    const stripe = new StripeSignatureVerifier({ secrets: stripeKey, nowMs });
    const hmac = new HmacSha256Verifier("global_hmac_secret");
    const rules = [
      { pattern: "/hooks/stripe", verifier: stripe },
      { pattern: "/hooks/*", verifier: hmac },
    ];
    assert.equal(selectEndpointVerifier("/hooks/stripe", rules), stripe);
    assert.equal(selectEndpointVerifier("/hooks/legacy", rules), hmac);
    assert.equal(selectEndpointVerifier("/other", rules), undefined);

    // Each verifier only accepts its own scheme on its own path.
    const stripeHeader = signStripe(BODY, stripeKey, nowSec());
    assert.equal(stripe.verify(BODY, stripeHeader), true);
    assert.equal(hmac.verify(BODY, stripeHeader), false);
    // And the Ed25519 slot exists in the same registry family.
    assert.equal(typeof Ed25519Verifier, "function");
  });
});
