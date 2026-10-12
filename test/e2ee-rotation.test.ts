import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { createDefaultSender } from "../src/server.ts";
import {
  DEFAULT_E2EE_KEY_GRACE_MS,
  E2EE_HEADER,
  RotatingE2eeSealer,
  generateX25519KeyPair,
  isSealedOutboundEnvelope,
  parseX25519PrivateKey,
  parseX25519PublicKey,
  sealOutboundPayload,
  unsealOutboundPayload,
  unsealOutboundPayloadWithKeys,
  type KeyObject,
  type SealedOutboundEnvelope,
} from "../src/e2ee.ts";
import type { RetryItem } from "../src/retry.ts";

// NOTE: no all-caps SECRET constant here — the runtime redaction rewrites
// `secret: SECRET` in test code into invalid syntax. Use TEST_KEY instead.
const BODY = Buffer.from(JSON.stringify({ hello: "rotation", n: 81 }));

function kp() {
  const k = generateX25519KeyPair();
  return { pub: parseX25519PublicKey(k.publicKey), priv: parseX25519PrivateKey(k.privateKey), raw: k };
}

describe("WR-81 RotatingE2eeSealer", () => {
  it("seals with the primary key and stamps its kid in the envelope", () => {
    const a = kp();
    const b = kp();
    const sealer = new RotatingE2eeSealer({
      keys: [
        { id: "k-old", publicKey: b.raw.publicKey, retiredAtMs: Date.now() },
        { id: "k-new", publicKey: a.raw.publicKey, primary: true },
      ],
    });
    assert.equal(sealer.primaryKeyId, "k-new");
    const sealed = sealer.seal(BODY);
    const envelope = JSON.parse(sealed.toString("utf8")) as SealedOutboundEnvelope;
    assert.ok(isSealedOutboundEnvelope(envelope));
    assert.equal(envelope.kid, "k-new");
    const opened = unsealOutboundPayloadWithKeys(sealed, new Map([["k-new", a.priv]]));
    assert.ok(opened.plaintext.equals(BODY));
  });

  it("defaults the primary to the first key when none is marked", () => {
    const a = kp();
    const sealer = new RotatingE2eeSealer({ keys: [{ id: "only", publicKey: a.raw.publicKey }] });
    assert.equal(sealer.primaryKeyId, "only");
    const envelope = JSON.parse(sealer.seal(BODY).toString("utf8")) as SealedOutboundEnvelope;
    assert.equal(envelope.kid, "only");
  });

  it("rejects invalid configs at construction (startup fail-fast)", () => {
    const a = kp();
    assert.throws(() => new RotatingE2eeSealer({ keys: [] }), /non-empty array/);
    assert.throws(
      () => new RotatingE2eeSealer({ keys: [{ id: "x", publicKey: a.raw.publicKey }, { id: "x", publicKey: a.raw.publicKey }] }),
      /duplicate key id/
    );
    assert.throws(
      () => new RotatingE2eeSealer({ keys: [{ id: "x", publicKey: "!!!not-base64!!!" }] }),
      /not valid base64/
    );
    assert.throws(
      () =>
        new RotatingE2eeSealer({
          keys: [
            { id: "a", publicKey: a.raw.publicKey, primary: true },
            { id: "b", publicKey: a.raw.publicKey, primary: true },
          ],
        }),
      /at most one key may be primary/
    );
    assert.throws(
      () => new RotatingE2eeSealer({ keys: [{ id: "a", publicKey: a.raw.publicKey, primary: true, retiredAtMs: 1 }] }),
      /primary key .* is retired/
    );
    assert.throws(
      () => new RotatingE2eeSealer({ keys: [{ id: "a", publicKey: a.raw.publicKey }], graceMs: -1 }),
      /non-negative/
    );
    assert.throws(
      () => new RotatingE2eeSealer({ keys: [{ id: "a", publicKey: a.raw.publicKey, retiredAtMs: -5 }] }),
      /invalid retiredAtMs/
    );
  });

  it("treats the grace boundary as inclusive (WR-20 convention): exactly graceMs old is still in, 1ms older is out", () => {
    const a = kp();
    const b = kp();
    const now = 4 * DEFAULT_E2EE_KEY_GRACE_MS;
    const nowMs = () => now;
    const retiredExact = new RotatingE2eeSealer({
      keys: [
        { id: "new", publicKey: a.raw.publicKey, primary: true },
        { id: "old", publicKey: b.raw.publicKey, retiredAtMs: now - DEFAULT_E2EE_KEY_GRACE_MS },
      ],
      nowMs,
    });
    assert.deepEqual(retiredExact.activeKeyIds(), ["new", "old"]);
    assert.equal(retiredExact.rotationInProgress, true);

    const retiredOutside = new RotatingE2eeSealer({
      keys: [
        { id: "new", publicKey: a.raw.publicKey, primary: true },
        { id: "old", publicKey: b.raw.publicKey, retiredAtMs: now - DEFAULT_E2EE_KEY_GRACE_MS - 1 },
      ],
      nowMs,
    });
    assert.deepEqual(retiredOutside.activeKeyIds(), ["new"]);
    assert.equal(retiredOutside.rotationInProgress, false);
  });

  it("reports rotationInProgress only while a retired key is inside grace", () => {
    const a = kp();
    const b = kp();
    const steady = new RotatingE2eeSealer({ keys: [{ id: "only", publicKey: a.raw.publicKey }] });
    assert.equal(steady.rotationInProgress, false);
    const inFlight = new RotatingE2eeSealer({
      keys: [
        { id: "new", publicKey: a.raw.publicKey, primary: true },
        { id: "old", publicKey: b.raw.publicKey, retiredAtMs: Date.now() },
      ],
    });
    assert.equal(inFlight.rotationInProgress, true);
  });
});

describe("WR-81 unsealOutboundPayloadWithKeys", () => {
  it("opens a kid envelope with that kid's key only", () => {
    const a = kp();
    const sealed = sealOutboundPayload(BODY, a.pub, undefined, "k-a");
    const opened = unsealOutboundPayloadWithKeys(sealed, new Map([["k-a", a.priv]]));
    assert.ok(opened.plaintext.equals(BODY));
  });

  it("throws on an unknown kid instead of falling back", () => {
    const a = kp();
    const sealed = sealOutboundPayload(BODY, a.pub, undefined, "k-a");
    assert.throws(
      () => unsealOutboundPayloadWithKeys(sealed, new Map([["k-b", a.priv]])),
      /unknown kid "k-a"/
    );
  });

  it("never falls back when the kid's key is wrong", () => {
    const a = kp();
    const b = kp();
    const sealed = sealOutboundPayload(BODY, a.pub, undefined, "k-a");
    // the ring also holds b's key, which is wrong for this envelope —
    // the sealer must not silently try it.
    assert.throws(
      () => unsealOutboundPayloadWithKeys(sealed, new Map<string, KeyObject>([["k-a", b.priv], ["k-b", b.priv]])),
      /unsealOutboundPayload failed/
    );
  });

  it("opens a legacy kid-less envelope trying newest-first", () => {
    const a = kp();
    const b = kp();
    const sealed = sealOutboundPayload(BODY, b.pub); // no kid: pre-WR-81 envelope
    const envelope = JSON.parse(sealed.toString("utf8")) as SealedOutboundEnvelope;
    assert.equal(envelope.kid, undefined);
    const opened = unsealOutboundPayloadWithKeys(
      sealed,
      new Map<string, KeyObject>([["k-new", a.priv], ["k-old", b.priv]])
    );
    assert.ok(opened.plaintext.equals(BODY));
  });

  it("throws when no key in the ring opens a legacy envelope", () => {
    const a = kp();
    const b = kp();
    const sealed = sealOutboundPayload(BODY, b.pub);
    assert.throws(
      () => unsealOutboundPayloadWithKeys(sealed, new Map([["k-new", a.priv]])),
      /unsealOutboundPayload failed/
    );
    assert.throws(() => unsealOutboundPayloadWithKeys(sealed, new Map()), /unsealOutboundPayload failed/);
  });

  it("legacy single-key unseal still works on kid envelopes (ignores kid)", () => {
    const a = kp();
    const sealed = sealOutboundPayload(BODY, a.pub, undefined, "k-a");
    const opened = unsealOutboundPayload(sealed, a.priv);
    assert.ok(opened.plaintext.equals(BODY));
  });
});

describe("WR-81 default-sender integration", () => {
  let stub: Server;
  let stubPort: number;
  const seen: Array<{ headers: Record<string, unknown>; body: Buffer }> = [];

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === "object");
    return addr.port;
  }

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

  const url = () => `http://127.0.0.1:${stubPort}/rot`;
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

  it("stamps kid on the wire and fires the rotation hook once at startup", async () => {
    const kNew = kp();
    const kOld = kp();
    const hookCalls: Array<{ endpoint: string; primaryKeyId: string; previousKeyIds: string[] }> = [];
    const sender = createDefaultSender(
      undefined, false, undefined,
      undefined, undefined, undefined, undefined, undefined, undefined,
      {
        [url()]: {
          publicKey: kNew.raw.publicKey,
          keyId: "k-2026-10",
          previousKeys: [{ id: "k-2026-09", publicKey: kOld.raw.publicKey, retiredAtMs: Date.now() }],
        },
        [plainUrl()]: { publicKey: kNew.raw.publicKey },
      },
      undefined, undefined, undefined, undefined, undefined, undefined, undefined, undefined,
      (info) => {
        hookCalls.push({ endpoint: info.endpoint, primaryKeyId: info.primaryKeyId, previousKeyIds: info.previousKeyIds });
      }
    );
    try {
      assert.equal(hookCalls.length, 1);
      assert.equal(hookCalls[0].endpoint, url());
      assert.equal(hookCalls[0].primaryKeyId, "k-2026-10");
      assert.deepEqual(hookCalls[0].previousKeyIds, ["k-2026-09"]);

      const { headers, body } = await deliverAndCapture(sender, url());
      const envelope = JSON.parse(body.toString("utf8")) as SealedOutboundEnvelope;
      assert.ok(isSealedOutboundEnvelope(envelope));
      assert.equal(envelope.kid, "k-2026-10");
      assert.ok(String(headers[E2EE_HEADER]).length > 0);
      const opened = unsealOutboundPayloadWithKeys(
        body,
        new Map<string, KeyObject>([["k-2026-10", kNew.priv], ["k-2026-09", kOld.priv]])
      );
      assert.ok(opened.plaintext.equals(BODY));

      // the plain { publicKey } endpoint keeps the WR-58 behavior: no kid, no hook.
      const { body: plainBody } = await deliverAndCapture(sender, plainUrl());
      const plainEnvelope = JSON.parse(plainBody.toString("utf8")) as SealedOutboundEnvelope;
      assert.equal(plainEnvelope.kid, undefined);
      assert.equal(hookCalls.length, 1);
    } finally {
      sender.destroy();
    }
  });

  it("wraps invalid rotation configs in RangeError at startup", () => {
    const k = kp();
    const bad = (cfg: object) =>
      () =>
        createDefaultSender(
          undefined, false, undefined,
          undefined, undefined, undefined, undefined, undefined, undefined,
          { "http://127.0.0.1:1/x": cfg as never }
        );
    assert.throws(bad({ publicKey: k.raw.publicKey, previousKeys: [{ id: "o", publicKey: k.raw.publicKey }] }), RangeError); // keyId required
    assert.throws(
      bad({ publicKey: k.raw.publicKey, keyId: "n", previousKeys: [{ id: "n", publicKey: k.raw.publicKey }] }),
      RangeError // duplicate id
    );
    assert.throws(bad({ publicKey: k.raw.publicKey, keyId: "n", graceMs: -1 }), RangeError);
    assert.throws(bad({ publicKey: "!!!not-base64!!!", keyId: "n" }), RangeError);
  });
});
