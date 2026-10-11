import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import {
  createServer,
  request as httpRequest,
  type Server,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { gzipSync, deflateSync, brotliCompressSync } from "node:zlib";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRelayServer } from "../src/server.ts";
import { signSha256 } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import { classifyFailure } from "../src/retry.ts";
import {
  decodeResponseBody,
  inflateCapped,
  brotliDecompressCapped,
  assertValidResponseCompressionConfig,
  DEFAULT_OUTBOUND_ACCEPT_ENCODING,
} from "../src/response-encoding.ts";
import { DecompressionFailedError, DecompressionTooLargeError } from "../src/gzip.ts";

const KEY = "response-encoding-test-key";
const PLAIN = Buffer.from(JSON.stringify({ ok: true, charge: "ch_123" }));

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

async function closeServer(server: Server): Promise<void> {
  server.close();
  await new Promise<void>((r) => server.once("close", r));
}

function post(port: number, body: Buffer, headers: Record<string, string> = {}) {
  return new Promise<{ status: number; text: string }>((resolve, reject) => {
    const r = httpRequest(
      { host: "127.0.0.1", port, path: "/", method: "POST", headers },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString() })
        );
      }
    );
    r.on("error", reject);
    r.end(body);
  });
}

/** Stub downstream: records the request's Accept-Encoding, answers per `behavior`. */
function stubDownstream(
  behavior: (req: IncomingMessage, res: ServerResponse) => void,
  seen: { acceptEncoding?: string; hits: number }
): Server {
  return createServer((req, res) => {
    seen.hits++;
    const ae = req.headers["accept-encoding"];
    seen.acceptEncoding = Array.isArray(ae) ? ae.join(", ") : ae;
    // Drain the request body before answering.
    req.resume();
    req.on("end", () => behavior(req, res));
  });
}

function makeRelay(
  forwardUrl: string,
  extra: Record<string, unknown> = {}
): { relay: Server; audit: AuditLog } {
  const dir = mkdtempSync(join(tmpdir(), "audit-respenc-"));
  const audit = new AuditLog(join(dir, "audit.jsonl"));
  const relay = createRelayServer({
    secret: KEY,
    forwardUrl,
    auditLog: audit,
    retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
    responseCompression: { [forwardUrl]: {} },
    ...extra,
  });
  return { relay, audit };
}

async function waitForAudit(
  audit: AuditLog,
  event: string,
  timeoutMs = 8000
): Promise<Record<string, unknown>> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const found = (audit.readAll() as Array<Record<string, unknown>>).find(
      (e) => e.event === event
    );
    if (found) return found;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error(`timed out waiting for audit event ${event}`);
}

describe("WR-62 outbound response compression negotiation", () => {
  describe("decodeResponseBody", () => {
    it("decodes gzip/deflate/br", async () => {
      for (const [coding, wire] of [
        ["gzip", gzipSync(PLAIN)],
        ["deflate", deflateSync(PLAIN)],
        ["br", brotliCompressSync(PLAIN)],
      ] as Array<[string, Buffer]>) {
        const out = await decodeResponseBody(wire, coding, 65536);
        assert.deepEqual(out.body, PLAIN);
        assert.equal(out.decoded, true);
        assert.equal(out.contentEncoding, coding);
      }
    });

    it("treats x-gzip as gzip and identity as a no-op", async () => {
      const gz = await decodeResponseBody(gzipSync(PLAIN), "x-gzip", 65536);
      assert.deepEqual(gz.body, PLAIN);
      const id = await decodeResponseBody(PLAIN, "identity", 65536);
      assert.deepEqual(id.body, PLAIN);
      assert.equal(id.decoded, false);
    });

    it("passes through when there is no content-encoding or it is unknown", async () => {
      const none = await decodeResponseBody(PLAIN, undefined, 65536);
      assert.deepEqual(none.body, PLAIN);
      assert.equal(none.decoded, false);
      assert.equal(none.contentEncoding, undefined);
      const weird = await decodeResponseBody(PLAIN, "compress", 65536);
      assert.deepEqual(weird.body, PLAIN);
      assert.equal(weird.decoded, false);
      assert.equal(weird.contentEncoding, "compress");
    });

    it("decodes stacked codings in reverse application order", async () => {
      // Applied gzip first, then br: header lists "gzip, br".
      const wire = brotliCompressSync(gzipSync(PLAIN));
      const out = await decodeResponseBody(wire, "gzip, br", 65536);
      assert.deepEqual(out.body, PLAIN);
      assert.equal(out.decoded, true);
    });

    it("cuts a compression bomb off at the cap", async () => {
      const bomb = gzipSync(Buffer.alloc(1024 * 1024, "a")); // ~1 KiB wire
      await assert.rejects(decodeResponseBody(bomb, "gzip", 1024), DecompressionTooLargeError);
      await assert.rejects(inflateCapped(deflateSync(PLAIN), 4), DecompressionTooLargeError);
      await assert.rejects(
        brotliDecompressCapped(brotliCompressSync(PLAIN), 4),
        DecompressionTooLargeError
      );
    });

    it("rejects corrupt input with a coding-named error (retryable)", async () => {
      const bad = Buffer.from("definitely not compressed");
      const err = await decodeResponseBody(bad, "gzip", 65536).catch((e) => e);
      assert.ok(err instanceof DecompressionFailedError);
      assert.match(err.message, /gzip decompression failed/);
      const brErr = await brotliDecompressCapped(bad, 65536).catch((e) => e);
      assert.match((brErr as Error).message, /br decompression failed/);
      // A corrupt downstream body is a retryable delivery failure.
      assert.equal(classifyFailure(err).failureClass, "retryable");
    });
  });

  describe("assertValidResponseCompressionConfig", () => {
    it("accepts valid configs and rejects bad ones at startup", () => {
      assert.doesNotThrow(() =>
        assertValidResponseCompressionConfig({
          "https://x/hook": {},
          "https://y/hook": { acceptEncoding: "gzip", maxDecompressedBytes: 1024 },
        })
      );
      assert.throws(() => assertValidResponseCompressionConfig(null as never), RangeError);
      assert.throws(
        () => assertValidResponseCompressionConfig({ "https://x": { acceptEncoding: "  " } }),
        RangeError
      );
      assert.throws(
        () =>
          assertValidResponseCompressionConfig({ "https://x": { maxDecompressedBytes: 0 } }),
        RangeError
      );
      assert.throws(
        () => createRelayServer(makeRelayArgs("https://x/hook", { responseCompression: { "https://x/hook": { maxDecompressedBytes: -1 } } })),
        RangeError
      );
    });
  });

  describe("default sender integration", () => {
    it("advertises Accept-Encoding and hands the validator the decoded body", async () => {
      const seen = { acceptEncoding: undefined as string | undefined, hits: 0 };
      const stub = stubDownstream((req, res) => {
        res.writeHead(200, { "content-type": "application/json", "content-encoding": "gzip" });
        res.end(gzipSync(PLAIN));
      }, seen);
      const stubPort = await listen(stub);
      const forwardUrl = `http://127.0.0.1:${stubPort}/hook`;
      let validatorBody = "";
      const { relay, audit } = makeRelay(forwardUrl, {
        retry: {
          baseDelayMs: 10,
          jitterMs: 0,
          maxAttempts: 2,
          responseValidators: (r: { body: Buffer }) => {
            validatorBody = r.body.toString();
            return true;
          },
        },
      });
      const port = await listen(relay);
      try {
        const body = Buffer.from(JSON.stringify({ event: "ping" }));
        const res = await post(port, body, { "x-signature": signSha256(body, KEY) });
        assert.equal(res.status, 202);
        const delivered = await waitForAudit(audit, "delivered");
        assert.equal(seen.hits, 1);
        assert.equal(seen.acceptEncoding, DEFAULT_OUTBOUND_ACCEPT_ENCODING);
        // The validator saw the DECODED body, not gzip bytes.
        assert.equal(validatorBody, PLAIN.toString());
        const summary = delivered.response_summary as Record<string, unknown>;
        assert.equal(summary.contentEncoding, "gzip");
      } finally {
        await closeServer(relay);
        await closeServer(stub);
      }
    });

    it("falls back to plaintext when the downstream ignores Accept-Encoding", async () => {
      const seen = { acceptEncoding: undefined as string | undefined, hits: 0 };
      const stub = stubDownstream((req, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(PLAIN);
      }, seen);
      const stubPort = await listen(stub);
      const forwardUrl = `http://127.0.0.1:${stubPort}/hook`;
      let validatorBody = "";
      const { relay, audit } = makeRelay(forwardUrl, {
        retry: {
          baseDelayMs: 10,
          jitterMs: 0,
          maxAttempts: 2,
          responseValidators: (r: { body: Buffer }) => {
            validatorBody = r.body.toString();
            return true;
          },
        },
      });
      const port = await listen(relay);
      try {
        const body = Buffer.from(JSON.stringify({ event: "ping" }));
        assert.equal((await post(port, body, { "x-signature": signSha256(body, KEY) })).status, 202);
        const delivered = await waitForAudit(audit, "delivered");
        assert.equal(validatorBody, PLAIN.toString());
        const summary = delivered.response_summary as Record<string, unknown>;
        assert.equal(summary.contentEncoding, undefined);
      } finally {
        await closeServer(relay);
        await closeServer(stub);
      }
    });

    it("decodes brotli and deflate too", async () => {
      for (const [coding, encode] of [
        ["br", brotliCompressSync],
        ["deflate", deflateSync],
      ] as Array<[string, (b: Buffer) => Buffer]>) {
        const seen = { acceptEncoding: undefined as string | undefined, hits: 0 };
        const stub = stubDownstream((req, res) => {
          res.writeHead(200, { "content-type": "application/json", "content-encoding": coding });
          res.end(encode(PLAIN));
        }, seen);
        const stubPort = await listen(stub);
        const forwardUrl = `http://127.0.0.1:${stubPort}/hook`;
        let validatorBody = "";
        const { relay, audit } = makeRelay(forwardUrl, {
          retry: {
            baseDelayMs: 10,
            jitterMs: 0,
            maxAttempts: 2,
            responseValidators: (r: { body: Buffer }) => {
              validatorBody = r.body.toString();
              return true;
            },
          },
        });
        const port = await listen(relay);
        try {
          const body = Buffer.from(JSON.stringify({ event: "ping" }));
          assert.equal(
            (await post(port, body, { "x-signature": signSha256(body, KEY) })).status,
            202
          );
          await waitForAudit(audit, "delivered");
          assert.equal(validatorBody, PLAIN.toString());
        } finally {
          await closeServer(relay);
          await closeServer(stub);
        }
      }
    });

    it("a corrupt compressed body fails the attempt and dead-letters", async () => {
      const seen = { acceptEncoding: undefined as string | undefined, hits: 0 };
      const stub = stubDownstream((req, res) => {
        res.writeHead(200, { "content-type": "application/json", "content-encoding": "gzip" });
        res.end(Buffer.from("not actually gzip"));
      }, seen);
      const stubPort = await listen(stub);
      const forwardUrl = `http://127.0.0.1:${stubPort}/hook`;
      const { relay, audit } = makeRelay(forwardUrl, {
        retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 1 },
      });
      const port = await listen(relay);
      try {
        const body = Buffer.from(JSON.stringify({ event: "ping" }));
        assert.equal((await post(port, body, { "x-signature": signSha256(body, KEY) })).status, 202);
        const dead = await waitForAudit(audit, "dead_letter");
        assert.match(String(dead.lastError ?? dead.error ?? ""), /decompression failed/);
      } finally {
        await closeServer(relay);
        await closeServer(stub);
      }
    });

    it("endpoints without an entry send no Accept-Encoding (byte-identical behavior)", async () => {
      const seen = { acceptEncoding: undefined as string | undefined, hits: 0 };
      const stub = stubDownstream((req, res) => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(PLAIN);
      }, seen);
      const stubPort = await listen(stub);
      const forwardUrl = `http://127.0.0.1:${stubPort}/hook`;
      const dir = mkdtempSync(join(tmpdir(), "audit-respenc-"));
      const audit = new AuditLog(join(dir, "audit.jsonl"));
      const relay = createRelayServer({
        secret: KEY,
        forwardUrl,
        auditLog: audit,
        retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 2 },
        // no responseCompression entry: the header must not be sent
      });
      const port = await listen(relay);
      try {
        const body = Buffer.from(JSON.stringify({ event: "ping" }));
        assert.equal((await post(port, body, { "x-signature": signSha256(body, KEY) })).status, 202);
        await waitForAudit(audit, "delivered");
        assert.equal(seen.acceptEncoding, undefined);
      } finally {
        await closeServer(relay);
        await closeServer(stub);
      }
    });
  });
});

// Helper to build server args for the startup-validation test above.
function makeRelayArgs(forwardUrl: string, extra: Record<string, unknown>) {
  const dir = mkdtempSync(join(tmpdir(), "audit-respenc-"));
  return {
    secret: KEY,
    forwardUrl,
    auditLog: new AuditLog(join(dir, "audit.jsonl")),
    ...extra,
  };
}
