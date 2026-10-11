import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { gunzipSync } from "node:zlib";
import { createDefaultSender } from "../src/server.ts";
import { verifySignature } from "../src/verify.ts";
import {
  E2EE_ALGORITHM,
  E2EE_HEADER,
  generateX25519KeyPair,
  isSealedOutboundEnvelope,
  parseX25519PrivateKey,
  parseX25519PublicKey,
  sealOutboundPayload,
  unsealOutboundPayload,
  type SealedOutboundEnvelope,
} from "../src/e2ee.ts";
import type { RetryItem } from "../src/retry.ts";

const SECRET = "relay-secret";
const BODY = Buffer.from(JSON.stringify({ hello: "webhook", secretField: "s3cr3t-payload-marker" }));

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

describe("WR-58 key handling", () => {
  it("generates 32-byte base64 keypairs that parse back", () => {
    const kp = generateX25519KeyPair();
    assert.equal(Buffer.from(kp.publicKey, "base64").length, 32);
    assert.equal(Buffer.from(kp.privateKey, "base64").length, 32);
    assert.ok(parseX25519PublicKey(kp.publicKey));
    assert.ok(parseX25519PrivateKey(kp.privateKey));
  });

  it("rejects invalid public keys with RangeError (startup fail-fast)", () => {
    assert.throws(() => parseX25519PublicKey("!!!not-base64!!!"), RangeError);
    assert.throws(() => parseX25519PublicKey(""), RangeError);
    // valid base64 but wrong length
    assert.throws(
      () => parseX25519PublicKey(Buffer.alloc(16, 7).toString("base64")),
      RangeError
    );
    // note: for X25519 every 32-byte string is a valid u-coordinate, so a
    // 32-byte key is always accepted — "invalid" means bad encoding/length
    assert.ok(parseX25519PublicKey(Buffer.alloc(32).toString("base64")));
  });

  it("rejects invalid private keys with RangeError", () => {
    assert.throws(() => parseX25519PrivateKey("garbage!!"), RangeError);
    assert.throws(
      () => parseX25519PrivateKey(Buffer.alloc(31, 1).toString("base64")),
      RangeError
    );
  });
});

describe("WR-58 seal/unseal round trip", () => {
  const kp = generateX25519KeyPair();
  const pub = parseX25519PublicKey(kp.publicKey);
  const priv = parseX25519PrivateKey(kp.privateKey);

  it("round-trips through a real ECDH+HKDF+AES-GCM seal", () => {
    const sealed = sealOutboundPayload(BODY, pub);
    const envelope = JSON.parse(sealed.toString("utf8")) as SealedOutboundEnvelope;
    assert.ok(isSealedOutboundEnvelope(envelope));
    assert.equal(envelope.alg, "x25519-hkdf-sha256+aes-256-gcm");
    assert.equal(envelope.innerEncoding, undefined);
    const opened = unsealOutboundPayload(sealed, priv);
    assert.ok(opened.plaintext.equals(BODY));
  });

  it("carries the pre-seal content encoding inside the envelope", () => {
    const sealed = sealOutboundPayload(BODY, pub, "gzip");
    const opened = unsealOutboundPayload(sealed, priv);
    assert.equal(opened.innerEncoding, "gzip");
    assert.ok(opened.plaintext.equals(BODY));
  });

  it("ciphertext does not contain the plaintext (not readable on the wire)", () => {
    const sealed = sealOutboundPayload(BODY, pub);
    const wire = sealed.toString("utf8");
    assert.ok(!wire.includes("s3cr3t-payload-marker"), "plaintext leaked into sealed body");
    assert.ok(!wire.includes("webhook"), "plaintext leaked into sealed body");
  });

  it("uses a fresh ephemeral key and IV per seal", () => {
    const a = sealOutboundPayload(BODY, pub);
    const b = sealOutboundPayload(BODY, pub);
    assert.ok(!a.equals(b), "two seals of the same plaintext must differ");
  });

  it("fails loudly on tampered ciphertext", () => {
    const sealed = sealOutboundPayload(BODY, pub);
    const envelope = JSON.parse(sealed.toString("utf8")) as SealedOutboundEnvelope;
    const ct = Buffer.from(envelope.ct, "base64");
    ct[0] ^= 0xff;
    envelope.ct = ct.toString("base64");
    assert.throws(
      () => unsealOutboundPayload(Buffer.from(JSON.stringify(envelope), "utf8"), priv),
      /unsealOutboundPayload failed/
    );
  });

  it("fails loudly with the wrong private key", () => {
    const other = generateX25519KeyPair();
    const sealed = sealOutboundPayload(BODY, pub);
    assert.throws(
      () => unsealOutboundPayload(sealed, parseX25519PrivateKey(other.privateKey)),
      /unsealOutboundPayload failed/
    );
  });

  it("fails loudly on non-envelope input", () => {
    assert.throws(() => unsealOutboundPayload(Buffer.from("not json"), priv), /not valid JSON/);
    assert.throws(
      () => unsealOutboundPayload(Buffer.from(JSON.stringify({ alg: "none" }), "utf8"), priv),
      /not a sealed outbound envelope/
    );
  });
});

describe("WR-58 default-sender integration", () => {
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

  const kp = generateX25519KeyPair();
  const priv = parseX25519PrivateKey(kp.privateKey);
  const encUrl = () => `http://127.0.0.1:${stubPort}/encrypted`;
  const plainUrl = () => `http://127.0.0.1:${stubPort}/plain`;

  function item(targetUrl: string): RetryItem {
    return { id: "item-1", traceId: "trace-1", payload: BODY, targetUrl, headers: {} };
  }

  async function deliverAndCapture(
    sender: (i: RetryItem) => Promise<unknown>,
    targetUrl: string
  ): Promise<{ headers: Record<string, unknown>; body: Buffer }> {
    seen.length = 0;
    await sender(item(targetUrl));
    const deadline = Date.now() + 5000;
    while (seen.length === 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(seen.length, 1);
    return seen[0];
  }

  it("seals the body, stamps the header, and the signature covers the ciphertext", async () => {
    const sender = createDefaultSender(
      undefined, // tlsPins
      false, // keepAlive
      { secret: SECRET }, // outboundSigning (WR-26)
      undefined, undefined, undefined, undefined, undefined, undefined,
      { [encUrl()]: { publicKey: kp.publicKey } } // outboundEncryption (WR-58)
    );
    try {
      const { headers, body } = await deliverAndCapture(sender, encUrl());
      assert.equal(headers[E2EE_HEADER], E2EE_ALGORITHM);
      const opened = unsealOutboundPayload(body, priv);
      assert.ok(opened.plaintext.equals(BODY));
      // WR-26 orthogonality: the signature covers the ciphertext wire bytes.
      assert.ok(
        verifySignature(body, String(headers["x-relay-signature"]), SECRET),
        "x-relay-signature must verify over the sealed body"
      );
      assert.ok(!body.toString("utf8").includes("s3cr3t-payload-marker"));
    } finally {
      sender.destroy();
    }
  });

  it("leaves endpoints without a key exactly as before", async () => {
    const sender = createDefaultSender(
      undefined, false, { secret: SECRET },
      undefined, undefined, undefined, undefined, undefined, undefined,
      { [encUrl()]: { publicKey: kp.publicKey } }
    );
    try {
      const { headers, body } = await deliverAndCapture(sender, plainUrl());
      assert.equal(headers[E2EE_HEADER], undefined);
      assert.ok(body.equals(BODY));
      assert.ok(verifySignature(body, String(headers["x-relay-signature"]), SECRET));
    } finally {
      sender.destroy();
    }
  });

  it("seals the compressed bytes and records the inner encoding in the envelope", async () => {
    const big = Buffer.from(JSON.stringify({ data: "x".repeat(4000) }));
    const sender = createDefaultSender(
      undefined, false, undefined, undefined, undefined,
      { [encUrl()]: { thresholdBytes: 64 } }, // compressOutbound (WR-40)
      undefined, undefined, undefined,
      { [encUrl()]: { publicKey: kp.publicKey } }
    );
    try {
      seen.length = 0;
      await sender({ id: "item-2", traceId: "trace-2", payload: big, targetUrl: encUrl(), headers: {} });
      const deadline = Date.now() + 5000;
      while (seen.length === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(seen.length, 1);
      const { headers, body } = seen[0];
      assert.equal(headers[E2EE_HEADER], E2EE_ALGORITHM);
      // the wire body is the JSON envelope, not a gzip stream
      assert.equal(headers["content-encoding"], undefined);
      const opened = unsealOutboundPayload(body, priv);
      assert.equal(opened.innerEncoding, "gzip");
      assert.ok(gunzipSync(opened.plaintext).equals(big));
    } finally {
      sender.destroy();
    }
  });

  it("throws RangeError at startup for invalid configured keys", () => {
    assert.throws(
      () =>
        createDefaultSender(
          undefined, false, undefined, undefined, undefined, undefined, undefined, undefined, undefined,
          { "http://x/hook": { publicKey: "!!!not-a-key!!!" } }
        ),
      RangeError
    );
    assert.throws(
      () =>
        createDefaultSender(
          undefined, false, undefined, undefined, undefined, undefined, undefined, undefined, undefined,
          { "http://x/hook": { publicKey: Buffer.alloc(16).toString("base64") } }
        ),
      RangeError
    );
    assert.throws(
      () =>
        createDefaultSender(
          undefined, false, undefined, undefined, undefined, undefined, undefined, undefined, undefined,
          // @ts-expect-error - non-string publicKey must fail validation
          { "http://x/hook": { publicKey: 42 } }
        ),
      RangeError
    );
  });
});
