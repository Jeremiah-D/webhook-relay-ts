import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { randomBytes } from "node:crypto";
import { gunzipSync } from "node:zlib";
import {
  assertValidGuardedCompressConfig,
  guardedCompressOutbound,
  outboundContentType,
  OutboundCompressionTracker,
  DEFAULT_GUARDED_COMPRESS_CONTENT_TYPES,
  type GzipFallbackInfo,
} from "../src/gzip.ts";
import { createDefaultSender } from "../src/server.ts";
import { HttpDeliveryError } from "../src/retry.ts";
import { HmacSha256Verifier } from "../src/verify.ts";

const TEST_KEY = "test-signing-key";

const bigJson = () => Buffer.from(JSON.stringify({ event: "payment.succeeded", data: "x".repeat(4000) }));

describe("guardedCompressOutbound", () => {
  it("passes through when the endpoint did not opt in", () => {
    const p = bigJson();
    const out = guardedCompressOutbound(p, "application/json");
    assert.equal(out.body, p);
    assert.equal(out.contentEncoding, undefined);
    assert.equal(out.bytesSaved, 0);
  });

  it("compresses JSON payloads above the threshold and reports bytes saved", () => {
    const p = bigJson();
    const out = guardedCompressOutbound(p, "application/json", {});
    assert.equal(out.contentEncoding, "gzip");
    assert.ok(out.body.length < p.length);
    assert.equal(out.bytesSaved, p.length - out.body.length);
    assert.ok(out.bytesSaved > 0);
    assert.ok(gunzipSync(out.body).equals(p));
  });

  it("defaults an absent content-type to application/json", () => {
    const p = bigJson();
    const out = guardedCompressOutbound(p, undefined, {});
    assert.equal(out.contentEncoding, "gzip");
  });

  it("matches content types with parameters (charset)", () => {
    const p = bigJson();
    const out = guardedCompressOutbound(p, "application/json; charset=utf-8", {});
    assert.equal(out.contentEncoding, "gzip");
  });

  it("skips content types outside the whitelist", () => {
    const p = bigJson();
    const out = guardedCompressOutbound(p, "text/csv", {});
    assert.equal(out.body, p);
    assert.equal(out.contentEncoding, undefined);
    assert.equal(out.bytesSaved, 0);
  });

  it("honors a custom content-type whitelist", () => {
    const p = bigJson();
    const csv = guardedCompressOutbound(p, "text/csv", { contentTypeWhitelist: ["text/csv"] });
    assert.equal(csv.contentEncoding, "gzip");
    const json = guardedCompressOutbound(p, "application/json", { contentTypeWhitelist: ["text/csv"] });
    assert.equal(json.contentEncoding, undefined);
  });

  it("passes through below the threshold", () => {
    const p = Buffer.from(JSON.stringify({ a: 1 }));
    const out = guardedCompressOutbound(p, "application/json", {});
    assert.equal(out.body, p);
    assert.equal(out.contentEncoding, undefined);
  });

  it("honors a custom threshold", () => {
    const p = Buffer.from("y".repeat(2000));
    assert.equal(
      guardedCompressOutbound(p, "application/json", { thresholdBytes: 10_000 }).contentEncoding,
      undefined
    );
    assert.equal(
      guardedCompressOutbound(p, "application/json", { thresholdBytes: 100 }).contentEncoding,
      "gzip"
    );
  });

  it("skips incompressible payloads that would grow", () => {
    const p = randomBytes(5000);
    const out = guardedCompressOutbound(p, "application/json", { thresholdBytes: 1 });
    assert.equal(out.body, p);
    assert.equal(out.contentEncoding, undefined);
    assert.equal(out.bytesSaved, 0);
  });

  it("default whitelist is application/json", () => {
    assert.deepEqual(DEFAULT_GUARDED_COMPRESS_CONTENT_TYPES, ["application/json"]);
  });
});

describe("assertValidGuardedCompressConfig", () => {
  it("rejects bad thresholds", () => {
    for (const thresholdBytes of [0, -5, 1.5, Number.NaN]) {
      assert.throws(
        () => assertValidGuardedCompressConfig({ u: { thresholdBytes } }),
        RangeError,
        `thresholdBytes=${String(thresholdBytes)}`
      );
    }
  });

  it("rejects bad whitelists", () => {
    assert.throws(() => assertValidGuardedCompressConfig({ u: { contentTypeWhitelist: [] } }), RangeError);
    assert.throws(
      () => assertValidGuardedCompressConfig({ u: { contentTypeWhitelist: "application/json" as unknown as string[] } }),
      RangeError
    );
    assert.throws(
      () => assertValidGuardedCompressConfig({ u: { contentTypeWhitelist: ["application/json", "  "] } }),
      RangeError
    );
  });

  it("rejects non-record configs", () => {
    assert.throws(
      () => assertValidGuardedCompressConfig(null as unknown as Record<string, never>),
      RangeError
    );
    assert.throws(
      () => assertValidGuardedCompressConfig({ u: null as unknown as never }),
      RangeError
    );
  });

  it("accepts valid configs", () => {
    assertValidGuardedCompressConfig({
      a: {},
      b: { thresholdBytes: 2048 },
      c: { contentTypeWhitelist: ["application/json", "application/problem+json"] },
      d: { thresholdBytes: 512, contentTypeWhitelist: ["text/csv"] },
    });
  });

  it("createDefaultSender rejects a bad compressThreshold config at startup", () => {
    assert.throws(
      () =>
        createDefaultSender(
          undefined, false, undefined, undefined, undefined, undefined, undefined,
          undefined, undefined, undefined, undefined, undefined, undefined, undefined,
          undefined, undefined,
          { u: { thresholdBytes: 0 } }
        ),
      RangeError
    );
  });
});

describe("outboundContentType", () => {
  it("reads the content-type header, defaulting to application/json", () => {
    assert.equal(outboundContentType({ "content-type": "text/csv" }), "text/csv");
    assert.equal(outboundContentType({ "content-type": ["text/csv", "x"] }), "text/csv");
    assert.equal(outboundContentType({}), "application/json");
    assert.equal(outboundContentType({ "content-type": undefined }), "application/json");
  });
});

describe("OutboundCompressionTracker", () => {
  it("accumulates per-endpoint savings and renders Prometheus exposition", () => {
    const t = new OutboundCompressionTracker();
    assert.deepEqual(t.stats(), []);
    assert.equal(t.render(), "");
    t.noteSaved("https://a/hook", 100);
    t.noteSaved("https://a/hook", 50);
    t.noteSaved("https://b/hook", 7);
    t.noteSaved("https://c/hook", 0); // non-positive savings are ignored
    t.noteSaved("https://c/hook", -3);
    assert.deepEqual(t.stats(), [
      { endpoint: "https://a/hook", bytesSaved: 150 },
      { endpoint: "https://b/hook", bytesSaved: 7 },
    ]);
    const out = t.render();
    assert.ok(out.includes("# HELP relay_compressed_bytes_saved_total"));
    assert.ok(out.includes("# TYPE relay_compressed_bytes_saved_total counter"));
    assert.ok(out.includes('relay_compressed_bytes_saved_total{endpoint="https://a/hook"} 150'));
    assert.ok(out.includes('relay_compressed_bytes_saved_total{endpoint="https://b/hook"} 7'));
    assert.ok(!out.includes("https://c/hook"));
  });
});

describe("guarded compression via createDefaultSender", () => {
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

  const item = (url: string, payload: Buffer, contentType = "application/json") => ({
    id: "g1",
    payload,
    targetUrl: url,
    headers: { "content-type": contentType },
    traceId: "trace-1",
  });

  it("compresses opt-in endpoints, sets content-length, and counts bytes saved", async () => {
    await withStub(
      () => ({ status: 200 }),
      async (url, seen) => {
        const sender = createDefaultSender(
          undefined, false, undefined, undefined, undefined, undefined, undefined,
          undefined, undefined, undefined, undefined, undefined, undefined, undefined,
          undefined, undefined,
          { [url]: {} }
        );
        const payload = bigJson();
        await sender(item(url, payload));
        assert.equal(seen.length, 1);
        assert.equal(seen[0].headers["content-encoding"], "gzip");
        assert.equal(Number(seen[0].headers["content-length"]), seen[0].body.length);
        assert.ok(seen[0].body.length < payload.length);
        assert.ok(gunzipSync(seen[0].body).equals(payload));
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

  it("does not compress content types outside the whitelist", async () => {
    await withStub(
      () => ({ status: 200 }),
      async (url, seen) => {
        const sender = createDefaultSender(
          undefined, false, undefined, undefined, undefined, undefined, undefined,
          undefined, undefined, undefined, undefined, undefined, undefined, undefined,
          undefined, undefined,
          { [url]: {} }
        );
        const payload = bigJson();
        await sender(item(url, payload, "text/csv"));
        assert.equal(seen[0].headers["content-encoding"], undefined);
        assert.ok(seen[0].body.equals(payload));
        assert.deepEqual(sender.compressionStats.stats(), []);
        sender.destroy();
      }
    );
  });

  it("falls back to a plaintext resend inside the same attempt on 415", async () => {
    await withStub(
      (rec) => (rec.headers["content-encoding"] === "gzip" ? { status: 415 } : { status: 200 }),
      async (url, seen) => {
        const fallbacks: GzipFallbackInfo[] = [];
        const sender = createDefaultSender(
          undefined, false, { secret: TEST_KEY }, undefined, undefined, undefined, undefined,
          undefined, undefined, undefined, undefined, undefined, undefined, undefined,
          undefined, undefined,
          { [url]: {} },
          (info) => fallbacks.push(info)
        );
        const payload = bigJson();
        // Must resolve: the 415 triggers the plaintext resend, which the
        // stub answers 200 — one delivery attempt as far as the queue is
        // concerned.
        await sender(item(url, payload));
        assert.equal(seen.length, 2);
        // First request went out compressed...
        assert.equal(seen[0].headers["content-encoding"], "gzip");
        // ...the fallback went out fully plaintext, with a signature that
        // verifies against the plaintext bytes (not the gzip stream).
        assert.equal(seen[1].headers["content-encoding"], undefined);
        assert.ok(seen[1].body.equals(payload));
        const sig = seen[1].headers["x-relay-signature"];
        assert.ok(typeof sig === "string");
        assert.ok(new HmacSha256Verifier(TEST_KEY).verify(seen[1].body, sig as string));
        assert.equal(Number(seen[1].headers["content-length"]), payload.length);
        assert.equal(fallbacks.length, 1);
        assert.equal(fallbacks[0].endpoint, url);
        assert.equal(fallbacks[0].id, "g1");
        assert.ok(fallbacks[0].bytesSaved > 0);
        sender.destroy();
      }
    );
  });

  it("a 415 on the plaintext resend follows the normal failure path (no loop)", async () => {
    await withStub(
      () => ({ status: 415 }),
      async (url, seen) => {
        let fallbacks = 0;
        const sender = createDefaultSender(
          undefined, false, undefined, undefined, undefined, undefined, undefined,
          undefined, undefined, undefined, undefined, undefined, undefined, undefined,
          undefined, undefined,
          { [url]: {} },
          () => { fallbacks += 1; }
        );
        await assert.rejects(
          sender(item(url, bigJson())),
          (err: unknown) => err instanceof HttpDeliveryError && err.statusCode === 415
        );
        // Exactly one compressed attempt + one plaintext resend.
        assert.equal(seen.length, 2);
        assert.equal(fallbacks, 1);
        sender.destroy();
      }
    );
  });

  it("non-415 failures never trigger the fallback", async () => {
    await withStub(
      () => ({ status: 500 }),
      async (url, seen) => {
        let fallbacks = 0;
        const sender = createDefaultSender(
          undefined, false, undefined, undefined, undefined, undefined, undefined,
          undefined, undefined, undefined, undefined, undefined, undefined, undefined,
          undefined, undefined,
          { [url]: {} },
          () => { fallbacks += 1; }
        );
        await assert.rejects(sender(item(url, bigJson())), HttpDeliveryError);
        assert.equal(seen.length, 1);
        assert.equal(fallbacks, 0);
        sender.destroy();
      }
    );
  });

  it("the WR-40 path keeps its fire-and-forget behavior (no fallback)", async () => {
    await withStub(
      (rec) => (rec.headers["content-encoding"] === "gzip" ? { status: 415 } : { status: 200 }),
      async (url, seen) => {
        const sender = createDefaultSender(
          undefined, false, undefined, undefined, undefined,
          { [url]: {} } // WR-40 only
        );
        await assert.rejects(
          sender(item(url, bigJson())),
          (err: unknown) => err instanceof HttpDeliveryError && err.statusCode === 415
        );
        // No resend: a single compressed request, rejected as before.
        assert.equal(seen.length, 1);
        assert.deepEqual(sender.compressionStats.stats(), []);
        sender.destroy();
      }
    );
  });

  it("the guarded path wins when both records configure an endpoint", async () => {
    await withStub(
      () => ({ status: 200 }),
      async (url, seen) => {
        const sender = createDefaultSender(
          undefined, false, undefined, undefined, undefined,
          { [url]: { thresholdBytes: 1 } }, // WR-40 would compress anything
          undefined, undefined, undefined, undefined, undefined, undefined, undefined,
          undefined, undefined, undefined,
          { [url]: { contentTypeWhitelist: ["text/csv"] } } // guarded: JSON not whitelisted
        );
        const payload = bigJson();
        await sender(item(url, payload)); // content-type: application/json
        assert.equal(seen[0].headers["content-encoding"], undefined);
        assert.ok(seen[0].body.equals(payload));
        sender.destroy();
      }
    );
  });
});
