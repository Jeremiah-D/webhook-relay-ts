import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { randomBytes } from "node:crypto";
import { brotliDecompressSync } from "node:zlib";
import {
  assertValidBrotliCompressConfig,
  maybeCompressBrotliOutbound,
} from "../src/brotli.ts";
import { DEFAULT_COMPRESS_THRESHOLD_BYTES } from "../src/gzip.ts";
import { createDefaultSender } from "../src/server.ts";
import { HttpDeliveryError } from "../src/retry.ts";
import { HmacSha256Verifier } from "../src/verify.ts";
import {
  E2EE_ALGORITHM,
  E2EE_HEADER,
  generateX25519KeyPair,
  parseX25519PrivateKey,
  unsealOutboundPayload,
} from "../src/e2ee.ts";

// `createDefaultSender` takes positional options; `compressBrotli` is the
// 34th parameter (after oauth2TokenCache). The spread fills every slot
// from `from` (1-based) up to it so only the interesting arguments are
// written out.
const restFrom = (from: number, compressBrotli: Record<string, unknown>) => [
  ...Array<undefined>(34 - from).fill(undefined),
  compressBrotli,
] as unknown as [];

const TEST_KEY = "test-signing-key";

const bigJson = () =>
  Buffer.from(JSON.stringify({ event: "payment.succeeded", data: "x".repeat(4000) }));

describe("maybeCompressBrotliOutbound", () => {
  it("passes through when the endpoint did not opt in", () => {
    const p = bigJson();
    const out = maybeCompressBrotliOutbound(p);
    assert.equal(out.body, p);
    assert.equal(out.contentEncoding, undefined);
    assert.equal(out.bytesSaved, 0);
  });

  it("compresses above the threshold, never produces a larger body, and reports bytes saved", () => {
    const p = bigJson();
    const out = maybeCompressBrotliOutbound(p, {});
    assert.equal(out.contentEncoding, "br");
    assert.ok(out.body.length < p.length);
    assert.equal(out.bytesSaved, p.length - out.body.length);
    assert.ok(out.bytesSaved > 0);
    assert.ok(brotliDecompressSync(out.body).equals(p));
  });

  it("uses the shared default threshold (1024)", () => {
    const justUnder = Buffer.from("z".repeat(DEFAULT_COMPRESS_THRESHOLD_BYTES - 1));
    assert.equal(maybeCompressBrotliOutbound(justUnder, {}).contentEncoding, undefined);
    const justOver = Buffer.from("z".repeat(DEFAULT_COMPRESS_THRESHOLD_BYTES + 100));
    assert.equal(maybeCompressBrotliOutbound(justOver, {}).contentEncoding, "br");
  });

  it("honors a custom threshold", () => {
    const p = Buffer.from("y".repeat(2000));
    assert.equal(
      maybeCompressBrotliOutbound(p, { thresholdBytes: 10_000 }).contentEncoding,
      undefined
    );
    assert.equal(
      maybeCompressBrotliOutbound(p, { thresholdBytes: 100 }).contentEncoding,
      "br"
    );
  });

  it("skips incompressible payloads that would grow", () => {
    const p = randomBytes(5000);
    const out = maybeCompressBrotliOutbound(p, { thresholdBytes: 1 });
    assert.equal(out.body, p);
    assert.equal(out.contentEncoding, undefined);
    assert.equal(out.bytesSaved, 0);
  });
});

describe("assertValidBrotliCompressConfig", () => {
  it("rejects bad thresholds", () => {
    for (const thresholdBytes of [0, -5, 1.5, Number.NaN]) {
      assert.throws(
        () => assertValidBrotliCompressConfig({ u: { thresholdBytes } }),
        RangeError,
        `thresholdBytes=${String(thresholdBytes)}`
      );
    }
  });

  it("rejects non-record configs", () => {
    assert.throws(
      () => assertValidBrotliCompressConfig(null as unknown as Record<string, never>),
      RangeError
    );
    assert.throws(
      () => assertValidBrotliCompressConfig({ u: null as unknown as never }),
      RangeError
    );
  });

  it("accepts valid configs", () => {
    assertValidBrotliCompressConfig({
      a: {},
      b: { thresholdBytes: 2048 },
    });
  });

  it("createDefaultSender rejects a bad compressBrotli config at startup", () => {
    assert.throws(
      () => createDefaultSender(...restFrom(1, { u: { thresholdBytes: 0 } })),
      RangeError
    );
  });
});

describe("brotli compression via createDefaultSender", () => {
  interface Seen {
    headers: Record<string, string | string[]>;
    body: Buffer;
  }

  async function withStub(
    handler: (seen: Seen, count: number) => { status: number; body?: string },
    fn: (url: string, seen: Seen[]) => Promise<void>
  ): Promise<void> {
    const seen: Seen[] = [];
    const server: Server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        const headers: Record<string, string | string[]> = {};
        for (const [k, v] of Object.entries(req.headers)) {
          if (v !== undefined) headers[k] = v;
        }
        const rec = { headers, body: Buffer.concat(chunks) };
        seen.push(rec);
        const { status, body } = handler(rec, seen.length);
        res.writeHead(status).end(body ?? "");
      });
    });
    await new Promise<void>((r) => server.listen(0, r));
    try {
      await fn(`http://127.0.0.1:${(server.address() as { port: number }).port}/hook`, seen);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  }

  const item = (url: string, payload: Buffer) => ({
    id: "b1",
    payload,
    targetUrl: url,
    headers: { "content-type": "application/json" },
    traceId: "trace-1",
  });

  it("compresses opt-in endpoints, sets content-length, verifies the signature over the compressed bytes, and counts bytes saved", async () => {
    await withStub(
      () => ({ status: 200 }),
      async (url, seen) => {
        const sender = createDefaultSender(
          undefined, // tlsPins
          false, // keepAlive
          { secret: TEST_KEY }, // outboundSigning (WR-26)
          ...restFrom(4, { [url]: {} })
        );
        const payload = bigJson();
        await sender(item(url, payload));
        assert.equal(seen.length, 1);
        assert.equal(seen[0].headers["content-encoding"], "br");
        assert.equal(Number(seen[0].headers["content-length"]), seen[0].body.length);
        assert.ok(seen[0].body.length < payload.length);
        assert.ok(brotliDecompressSync(seen[0].body).equals(payload));
        // The relay signature covers the compressed wire bytes — exactly
        // what the downstream receives.
        const sig = seen[0].headers["x-relay-signature"];
        assert.ok(typeof sig === "string");
        assert.ok(new HmacSha256Verifier(TEST_KEY).verify(seen[0].body, sig as string));
        // Byte savings feed the shared tracker (`relay_compressed_bytes_saved_total`).
        const stats = sender.compressionStats.stats();
        assert.equal(stats.length, 1);
        assert.equal(stats[0].endpoint, url);
        assert.equal(stats[0].bytesSaved, payload.length - seen[0].body.length);
        assert.ok(
          sender.compressionStats.render().includes(`relay_compressed_bytes_saved_total{endpoint="${url}"}`)
        );
        sender.destroy();
      }
    );
  });

  it("leaves unconfigured endpoints byte-identical", async () => {
    await withStub(
      () => ({ status: 200 }),
      async (url, seen) => {
        const sender = createDefaultSender(
          undefined,
          false,
          { secret: TEST_KEY },
          ...restFrom(4, { [url + "/other"]: {} }) // a *different* endpoint opts in
        );
        const payload = bigJson();
        await sender(item(url, payload));
        assert.equal(seen.length, 1);
        assert.equal(seen[0].headers["content-encoding"], undefined);
        assert.ok(seen[0].body.equals(payload));
        assert.equal(Number(seen[0].headers["content-length"]), payload.length);
        assert.deepEqual(sender.compressionStats.stats(), []);
        assert.equal(sender.compressionStats.render(), "");
        sender.destroy();
      }
    );
  });

  it("brotli wins over the legacy gzip path when both configure an endpoint", async () => {
    await withStub(
      () => ({ status: 200 }),
      async (url, seen) => {
        const sender = createDefaultSender(
          undefined,
          false,
          undefined,
          undefined,
          undefined,
          { [url]: { thresholdBytes: 1 } }, // WR-40: would gzip anything
          ...restFrom(7, { [url]: {} }) // WR-142
        );
        const payload = bigJson();
        await sender(item(url, payload));
        assert.equal(seen.length, 1);
        // Never stacked, never gzip: brotli takes the whole endpoint.
        assert.equal(seen[0].headers["content-encoding"], "br");
        assert.ok(brotliDecompressSync(seen[0].body).equals(payload));
        sender.destroy();
      }
    );
  });

  it("brotli wins over the guarded gzip path when both configure an endpoint", async () => {
    await withStub(
      () => ({ status: 200 }),
      async (url, seen) => {
        const sender = createDefaultSender(
          undefined,
          false,
          undefined,
          undefined,
          undefined,
          undefined,
          undefined,
          undefined,
          undefined,
          undefined,
          undefined,
          undefined,
          undefined,
          undefined,
          undefined,
          undefined,
          { [url]: {} }, // WR-75: would gzip this JSON payload
          ...restFrom(18, { [url]: {} }) // WR-142
        );
        const payload = bigJson();
        await sender(item(url, payload));
        assert.equal(seen.length, 1);
        assert.equal(seen[0].headers["content-encoding"], "br");
        assert.ok(brotliDecompressSync(seen[0].body).equals(payload));
        sender.destroy();
      }
    );
  });

  it("does not 415-fallback like the guarded path (fire-and-forget)", async () => {
    await withStub(
      (rec) => (rec.headers["content-encoding"] === "br" ? { status: 415 } : { status: 200 }),
      async (url, seen) => {
        const sender = createDefaultSender(undefined, false, undefined, ...restFrom(4, { [url]: {} }));
        await assert.rejects(
          sender(item(url, bigJson())),
          (err: unknown) => err instanceof HttpDeliveryError && err.statusCode === 415
        );
        // No plaintext resend: a single compressed request, rejected as before.
        assert.equal(seen.length, 1);
        sender.destroy();
      }
    );
  });

  it("combines with E2EE: the envelope carries innerEncoding br and the signature covers the ciphertext", async () => {
    const kp = generateX25519KeyPair();
    const priv = parseX25519PrivateKey(kp.privateKey);
    await withStub(
      () => ({ status: 200 }),
      async (url, seen) => {
        const sender = createDefaultSender(
          undefined, // tlsPins
          false, // keepAlive
          { secret: TEST_KEY }, // outboundSigning (WR-26)
          undefined, // proxies
          undefined, // tlsClientCerts
          undefined, // compressOutbound
          undefined, // http2
          undefined, // idempotencyKey
          undefined, // websocket
          { [url]: { publicKey: kp.publicKey } }, // outboundEncryption (WR-58)
          ...restFrom(11, { [url]: {} }) // compressBrotli (WR-142)
        );
        const payload = bigJson();
        await sender(item(url, payload));
        assert.equal(seen.length, 1);
        // Sealed: the wire bytes are the JSON envelope, so no
        // content-encoding header — the pre-seal encoding travels inside
        // the envelope.
        assert.equal(seen[0].headers["content-encoding"], undefined);
        assert.equal(seen[0].headers[E2EE_HEADER], E2EE_ALGORITHM);
        const opened = unsealOutboundPayload(seen[0].body, priv);
        assert.equal(opened.innerEncoding, "br");
        assert.ok(brotliDecompressSync(opened.plaintext).equals(payload));
        // The signature covers the ciphertext wire bytes.
        const sig = seen[0].headers["x-relay-signature"];
        assert.ok(typeof sig === "string");
        assert.ok(new HmacSha256Verifier(TEST_KEY).verify(seen[0].body, sig as string));
        sender.destroy();
      }
    );
  });
});
