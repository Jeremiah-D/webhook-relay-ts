import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { randomBytes } from "node:crypto";
import { gzipSync, gunzipSync } from "node:zlib";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  assertValidCompressOutboundConfig,
  DecompressionFailedError,
  DecompressionTooLargeError,
  gunzipCapped,
  isGzipContentEncoding,
  maybeCompressOutbound,
} from "../src/gzip.ts";
import { createDefaultSender, createRelayServer } from "../src/server.ts";
import { HmacSha256Verifier, signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import type { RetryItem } from "../src/retry.ts";

const SECRET = "test-secret";

describe("gzip helpers", () => {
  it("maybeCompressOutbound passes through when not opted in", () => {
    const p = Buffer.from("x".repeat(5000));
    const out = maybeCompressOutbound(p);
    assert.equal(out.body, p);
    assert.equal(out.contentEncoding, undefined);
  });

  it("maybeCompressOutbound passes through below the threshold", () => {
    const p = Buffer.from("x".repeat(100));
    const out = maybeCompressOutbound(p, {});
    assert.equal(out.body, p);
    assert.equal(out.contentEncoding, undefined);
  });

  it("maybeCompressOutbound gzips compressible payloads above the threshold", () => {
    const p = Buffer.from(JSON.stringify({ event: "x".repeat(5000) }));
    const out = maybeCompressOutbound(p, {});
    assert.equal(out.contentEncoding, "gzip");
    assert.ok(out.body.length < p.length);
    assert.ok(gunzipSync(out.body).equals(p));
  });

  it("maybeCompressOutbound skips incompressible payloads that would grow", () => {
    const p = randomBytes(5000); // high entropy: gzip barely helps
    const out = maybeCompressOutbound(p, { thresholdBytes: 1 });
    assert.equal(out.body, p);
    assert.equal(out.contentEncoding, undefined);
  });

  it("maybeCompressOutbound honors a custom threshold", () => {
    const p = Buffer.from("y".repeat(2000));
    assert.equal(maybeCompressOutbound(p, { thresholdBytes: 10_000 }).contentEncoding, undefined);
    assert.equal(maybeCompressOutbound(p, { thresholdBytes: 100 }).contentEncoding, "gzip");
  });

  it("assertValidCompressOutboundConfig rejects bad values", () => {
    assert.throws(
      () => assertValidCompressOutboundConfig({ u: { thresholdBytes: 0 } }),
      RangeError
    );
    assert.throws(
      () => assertValidCompressOutboundConfig({ u: { thresholdBytes: -5 } }),
      RangeError
    );
    assert.throws(
      () => assertValidCompressOutboundConfig({ u: { thresholdBytes: 1.5 } }),
      RangeError
    );
    assert.throws(
      () => assertValidCompressOutboundConfig(null as unknown as Record<string, never>),
      RangeError
    );
    assertValidCompressOutboundConfig({ u: {}, v: { thresholdBytes: 1 } });
  });

  it("createDefaultSender rejects a bad compressOutbound config at startup", () => {
    assert.throws(
      () =>
        createDefaultSender(undefined, false, undefined, undefined, undefined, {
          u: { thresholdBytes: 0 },
        }),
      RangeError
    );
  });

  it("isGzipContentEncoding parses header variants", () => {
    assert.equal(isGzipContentEncoding(undefined), false);
    assert.equal(isGzipContentEncoding("gzip"), true);
    assert.equal(isGzipContentEncoding("GZip"), true);
    assert.equal(isGzipContentEncoding("gzip, br"), true);
    assert.equal(isGzipContentEncoding("br"), false);
    assert.equal(isGzipContentEncoding(["br", "gzip"]), true);
    assert.equal(isGzipContentEncoding("x-gzip"), false);
  });

  it("gunzipCapped round-trips", async () => {
    const p = Buffer.from("hello world".repeat(100));
    assert.ok((await gunzipCapped(gzipSync(p), 1_000_000)).equals(p));
  });

  it("gunzipCapped rejects a decompression bomb past the cap", async () => {
    const bomb = gzipSync(Buffer.alloc(5_000_000, 0)); // compresses tiny
    assert.ok(bomb.length < 100_000, "test premise: the bomb compresses small");
    await assert.rejects(gunzipCapped(bomb, 1_000_000), DecompressionTooLargeError);
  });

  it("gunzipCapped rejects corrupt input", async () => {
    await assert.rejects(
      gunzipCapped(Buffer.from("not gzip at all"), 1_000_000),
      DecompressionFailedError
    );
  });
});

describe("outbound gzip via createDefaultSender", () => {
  async function withStub(
    fn: (url: string, seen: { headers: Record<string, string | string[]>; body: Buffer }) => Promise<void>
  ): Promise<void> {
    const seen = { headers: {} as Record<string, string | string[]>, body: Buffer.alloc(0) };
    const server: Server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        seen.body = Buffer.concat(chunks);
        for (const [k, v] of Object.entries(req.headers)) {
          if (v !== undefined) seen.headers[k] = v;
        }
        res.writeHead(200).end("ok");
      });
    });
    await new Promise<void>((r) => server.listen(0, r));
    try {
      await fn(`http://127.0.0.1:${(server.address() as { port: number }).port}/hook`, seen);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  }

  const bigPayload = () => Buffer.from(JSON.stringify({ data: "z".repeat(4000) }));

  it("compresses opt-in endpoints and sets content-encoding/content-length", async () => {
    await withStub(async (url, seen) => {
      const sender = createDefaultSender(undefined, false, undefined, undefined, undefined, {
        [url]: {},
      });
      const payload = bigPayload();
      await sender({ id: "a", payload, targetUrl: url, headers: {}, traceId: "t" });
      assert.equal(seen.headers["content-encoding"], "gzip");
      assert.equal(Number(seen.headers["content-length"]), seen.body.length);
      assert.ok(seen.body.length < payload.length);
      assert.ok(gunzipSync(seen.body).equals(payload));
    });
  });

  it("leaves non-opted-in endpoints untouched", async () => {
    await withStub(async (url, seen) => {
      const sender = createDefaultSender(undefined, false);
      const payload = bigPayload();
      await sender({ id: "a", payload, targetUrl: url, headers: {}, traceId: "t" });
      assert.equal(seen.headers["content-encoding"], undefined);
      assert.ok(seen.body.equals(payload));
    });
  });

  it("signs the compressed wire bytes", async () => {
    await withStub(async (url, seen) => {
      const sender = createDefaultSender(
        undefined,
        false,
        { secret: SECRET },
        undefined,
        undefined,
        { [url]: {} }
      );
      const payload = bigPayload();
      await sender({ id: "a", payload, targetUrl: url, headers: {}, traceId: "t" });
      assert.equal(seen.headers["content-encoding"], "gzip");
      const sig = seen.headers["x-relay-signature"];
      assert.ok(typeof sig === "string" && sig.length > 0);
      // The signature must verify against the bytes actually received
      // (the compressed form), not the pre-compression payload.
      assert.ok(new HmacSha256Verifier(SECRET).verify(seen.body, sig as string));
      assert.ok(!new HmacSha256Verifier(SECRET).verify(payload, sig as string));
    });
  });
});

describe("inbound gzip via createRelayServer", () => {
  async function withRelay(
    opts: { maxBodyBytes?: number } = {},
    fn: (
      port: number,
      delivered: RetryItem[],
      audit: AuditLog
    ) => Promise<void>
  ): Promise<void> {
    const dir = mkdtempSync(join(tmpdir(), "gzip-inbound-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const delivered: RetryItem[] = [];
    const server = createRelayServer({
      secret: SECRET,
      forwardUrl: "http://127.0.0.1:9/hook",
      auditLog: audit,
      sender: async (item) => {
        delivered.push(item);
      },
      maxBodyBytes: opts.maxBodyBytes,
    });
    await new Promise<void>((r) => server.listen(0, r));
    try {
      await fn((server.address() as { port: number }).port, delivered, audit);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  }

  function post(port: number, body: Buffer, headers: Record<string, string>): Promise<number> {
    return new Promise((resolve, reject) => {
      const req = httpRequest(
        { port, method: "POST", path: "/hook", headers },
        (res) => {
          res.resume();
          res.on("end", () => resolve(res.statusCode ?? 0));
        }
      );
      req.on("error", reject);
      req.end(body);
    });
  }

  const plain = Buffer.from(JSON.stringify({ hello: "gzip world", n: 42 }));

  it("decompresses a gzipped webhook after verifying the wire signature", async () => {
    await withRelay({}, async (port, delivered, audit) => {
      const wire = gzipSync(plain);
      const status = await post(port, wire, {
        "content-type": "application/json",
        "content-encoding": "gzip",
        "x-signature": signSha256(wire, SECRET),
      });
      assert.equal(status, 202);
      await new Promise((r) => setTimeout(r, 100));
      assert.equal(delivered.length, 1);
      assert.ok(delivered[0].payload.equals(plain), "downstream gets the plain payload");
      assert.equal(
        delivered[0].headers["content-encoding"],
        undefined,
        "stale content-encoding is stripped"
      );
      const accepted = (
        audit.readAll() as Array<Record<string, unknown>>
      ).find((e) => e.event === "accepted");
      assert.equal(accepted?.contentEncoding, "gzip");
    });
  });

  it("answers 413 for a gzip bomb past the body budget", async () => {
    await withRelay({ maxBodyBytes: 1024 }, async (port, delivered, audit) => {
      const bomb = gzipSync(Buffer.alloc(100_000, 0)); // 100 KiB of zeros
      assert.ok(bomb.length < 1024, "test premise: the bomb fits the wire budget");
      const status = await post(port, bomb, {
        "content-type": "application/json",
        "content-encoding": "gzip",
        "x-signature": signSha256(bomb, SECRET),
      });
      assert.equal(status, 413);
      assert.equal(delivered.length, 0);
      const rejected = (
        audit.readAll() as Array<Record<string, unknown>>
      ).find((e) => e.event === "rejected");
      assert.equal(rejected?.reason, "body_too_large");
    });
  });

  it("answers 400 for a corrupt gzip body", async () => {
    await withRelay({}, async (port, delivered, audit) => {
      const bogus = Buffer.from("this is not gzip data");
      const status = await post(port, bogus, {
        "content-type": "application/json",
        "content-encoding": "gzip",
        "x-signature": signSha256(bogus, SECRET),
      });
      assert.equal(status, 400);
      assert.equal(delivered.length, 0);
      const rejected = (
        audit.readAll() as Array<Record<string, unknown>>
      ).find((e) => e.event === "rejected");
      assert.equal(rejected?.reason, "decompression_failed");
    });
  });

  it("leaves plain (non-gzip) webhooks untouched", async () => {
    await withRelay({}, async (port, delivered) => {
      const status = await post(port, plain, {
        "content-type": "application/json",
        "x-signature": signSha256(plain, SECRET),
      });
      assert.equal(status, 202);
      await new Promise((r) => setTimeout(r, 100));
      assert.equal(delivered.length, 1);
      assert.ok(delivered[0].payload.equals(plain));
    });
  });
});
