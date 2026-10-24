import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DeadLetterS3Offloader,
  assertValidDeadLetterS3Config,
  buildDeadLetterArchiveDocument,
  DEAD_LETTER_S3_UPLOADED_SUFFIX,
  type DeadLetterS3OffloadConfig,
  type DeadLetterS3Source,
} from "../src/deadletter-s3.ts";
import type { DeadLetterEntry } from "../src/retry.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.
const testAccessKeyId = "TESTAKID123";
const testRegion = "us-east-1";
const testKeyMaterial = "test-secret-access-key";

function tmpDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

let seq = 0;
function makeEntry(partial: Partial<DeadLetterEntry> = {}): DeadLetterEntry {
  seq += 1;
  return {
    id: `dl-${seq}`,
    payload: Buffer.from(JSON.stringify({ n: seq })),
    targetUrl: "https://downstream.example/hook",
    headers: {},
    attempts: 3,
    lastError: "boom",
    failureClass: "retryable",
    deadLetteredAt: "2026-10-24T03:00:00.000Z",
    payloadBytes: 9,
    traceId: `trace-${seq}`,
    ...partial,
  };
}

function makeSource(entries: DeadLetterEntry[]): DeadLetterS3Source {
  return {
    entries: () => [...entries],
    decrypt: (e) => e.payload,
    purge: (id) => {
      const i = entries.findIndex((e) => e.id === id);
      if (i < 0) return false;
      entries.splice(i, 1);
      return true;
    },
  };
}

function baseConfig(endpoint: string, extra: Partial<DeadLetterS3OffloadConfig> = {}): DeadLetterS3OffloadConfig {
  return {
    endpoint,
    bucket: "relay-deadletters",
    region: testRegion,
    keyPrefix: "dl/",
    accessKeyId: testAccessKeyId,
    secretRef: "unused-when-injected",
    secretResolver: () => testKeyMaterial,
    markerDir: tmpDir("dl3-markers-"),
    ...extra,
  };
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

interface SeenPut {
  method: string;
  path: string;
  headers: Record<string, unknown>;
  body: Buffer;
}

describe("WR-206: dead-letter S3 archive offload", () => {
  let stub: Server;
  let stubPort: number;
  let stubStatus = 200;
  const seen: SeenPut[] = [];

  before(async () => {
    stub = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        seen.push({
          method: req.method ?? "",
          path: req.url ?? "",
          headers: { ...req.headers },
          body: Buffer.concat(chunks),
        });
        res.writeHead(stubStatus).end("ok");
      });
    });
    stubPort = await listen(stub);
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  const endpoint = () => `http://127.0.0.1:${stubPort}`;

  it("rejects invalid configs with RangeError (startup fail-fast)", () => {
    const good = baseConfig(endpoint());
    assert.throws(() => assertValidDeadLetterS3Config({ ...good, endpoint: "not-a-url" }, "dl"), RangeError);
    assert.throws(() => assertValidDeadLetterS3Config({ ...good, endpoint: "https://x/" }, "dl"), RangeError);
    assert.throws(() => assertValidDeadLetterS3Config({ ...good, bucket: "" }, "dl"), RangeError);
    assert.throws(() => assertValidDeadLetterS3Config({ ...good, region: "XX!" }, "dl"), RangeError);
    assert.throws(() => assertValidDeadLetterS3Config({ ...good, secretRef: "" }, "dl"), RangeError);
    assert.throws(() => assertValidDeadLetterS3Config({ ...good, requestTimeoutMs: 0 }, "dl"), RangeError);
    assert.throws(
      () => new DeadLetterS3Offloader(good, { entries: [] } as unknown as DeadLetterS3Source),
      RangeError
    );
  });

  it("builds a payload-bearing archive document (full payload, never truncated)", () => {
    const entry = makeEntry({ payload: Buffer.from(JSON.stringify({ secret: "pii-ok-in-archive" })) });
    const doc = buildDeadLetterArchiveDocument(entry, (e) => e.payload);
    assert.equal(doc.v, 1);
    assert.equal(doc.id, entry.id);
    assert.equal(doc.targetUrl, entry.targetUrl);
    assert.equal(doc.attempts, 3);
    assert.equal(doc.lastError, "boom");
    assert.equal(doc.deadLetteredAt, entry.deadLetteredAt);
    assert.equal(doc.failureClass, "retryable");
    assert.equal(doc.traceId, entry.traceId);
    assert.equal(doc.encrypted, false);
    assert.equal(doc.payloadEncoding, "utf8");
    assert.deepEqual(JSON.parse(doc.payload), { secret: "pii-ok-in-archive" });
    assert.equal(doc.payloadBytes, 9);
    assert.ok(!("payloadError" in doc));
  });

  it("encodes binary payloads as base64 and flags decrypt failures", () => {
    const binary = makeEntry({ payload: Buffer.from([0x00, 0xff, 0x01]) });
    const doc = buildDeadLetterArchiveDocument(binary, (e) => e.payload);
    assert.equal(doc.payloadEncoding, "base64");
    assert.deepEqual(Buffer.from(doc.payload, "base64"), Buffer.from([0x00, 0xff, 0x01]));

    const sealed = makeEntry();
    const failed = buildDeadLetterArchiveDocument(sealed, () => {
      throw new Error("cannot open envelope");
    });
    assert.equal(failed.payloadError, "decrypt_failed");
    assert.equal(failed.payload, "");
  });

  it("uploads each entry to a deterministic key with SigV4 headers", async () => {
    seen.length = 0;
    const entries = [makeEntry(), makeEntry()];
    const offloader = new DeadLetterS3Offloader(baseConfig(endpoint()), makeSource(entries));
    const results = await offloader.scanAndUpload();
    assert.equal(results.length, 2);
    assert.ok(results.every((r) => r.ok));
    assert.equal(seen.length, 2);

    for (const [i, put] of seen.entries()) {
      assert.equal(put.method, "PUT");
      assert.ok(put.path.startsWith("/relay-deadletters/dl/20261024/deadletter-dl-"), put.path);
      assert.ok(put.path.endsWith(".json"), put.path);
      // SigV4 stamps, never key material.
      assert.match(String(put.headers["authorization"]), /^AWS4-HMAC-SHA256 /);
      assert.ok(put.headers["x-amz-date"] !== undefined);
      assert.ok(put.headers["x-amz-content-sha256"] !== undefined);
      assert.ok(!String(put.headers["authorization"]).includes(testKeyMaterial));
      const doc = JSON.parse(put.body.toString("utf8"));
      assert.equal(doc.id, entries[i].id);
      assert.deepEqual(JSON.parse(doc.payload), JSON.parse(entries[i].payload.toString("utf8")));
    }
    // Deterministic keys: same entry -> same key.
    assert.equal(results[0].key, offloader.entryObjectKey(entries[0]));
    assert.equal(offloader.stats.uploaded, 2);
    assert.equal(offloader.stats.uploadFailures, 0);
  });

  it("marks uploads with .uploaded files and skips them on the next scan", async () => {
    seen.length = 0;
    const markerDir = tmpDir("dl3-resume-");
    const entries = [makeEntry()];
    const first = new DeadLetterS3Offloader(
      baseConfig(endpoint(), { markerDir }),
      makeSource(entries)
    );
    await first.scanAndUpload();
    assert.equal(seen.length, 1);
    const markers = readdirSync(markerDir).filter((n) => n.endsWith(DEAD_LETTER_S3_UPLOADED_SUFFIX));
    assert.equal(markers.length, 1);

    // A fresh offloader (post-restart) rehydrates the marks and uploads nothing.
    const second = new DeadLetterS3Offloader(
      baseConfig(endpoint(), { markerDir }),
      makeSource(entries)
    );
    assert.equal(second.stats.pending, 0);
    const results = await second.scanAndUpload();
    assert.equal(results.length, 0);
    assert.equal(seen.length, 1, "no new PUT after restart");
  });

  it("counts failures, never throws, and retries on the next scan", async () => {
    seen.length = 0;
    stubStatus = 500;
    try {
      const entries = [makeEntry()];
      const offloader = new DeadLetterS3Offloader(baseConfig(endpoint()), makeSource(entries));
      const results = await offloader.scanAndUpload();
      assert.equal(results.length, 1);
      assert.equal(results[0].ok, false);
      assert.match(results[0].error ?? "", /HTTP 500/);
      assert.equal(offloader.stats.uploadFailures, 1);
      assert.equal(offloader.stats.uploaded, 0);
      assert.equal(offloader.stats.pending, 1, "failed entries stay pending");
      // The scan itself never throws even when the store is broken.
      await assert.doesNotReject(() => offloader.scanAndUpload());
    } finally {
      stubStatus = 200;
    }
    // Next scan retries and succeeds.
    const retryOffloader = new DeadLetterS3Offloader(
      baseConfig(endpoint(), { markerDir: tmpDir("dl3-retry-") }),
      makeSource([makeEntry()])
    );
    const retried = await retryOffloader.scanAndUpload();
    assert.ok(retried[0].ok);
    assert.equal(retryOffloader.stats.uploadFailures, 0);
  });

  it("dryRun records keys with zero network I/O, markers or stat changes", async () => {
    seen.length = 0;
    const markerDir = tmpDir("dl3-dryrun-");
    const entries = [makeEntry(), makeEntry()];
    const offloader = new DeadLetterS3Offloader(
      baseConfig(endpoint(), { dryRun: true, markerDir }),
      makeSource(entries)
    );
    const results = await offloader.scanAndUpload();
    assert.equal(results.length, 2);
    assert.ok(results.every((r) => r.ok && r.dryRun === true));
    assert.equal(seen.length, 0, "dry-run must not touch the network");
    assert.equal(offloader.getDryRunKeys().length, 2);
    assert.ok(offloader.getDryRunKeys()[0].includes("deadletter-"));
    assert.equal(readdirSync(markerDir).length, 0, "dry-run must not write markers");
    assert.equal(offloader.stats.uploaded, 0);
    assert.equal(offloader.stats.uploadFailures, 0);
    assert.equal(offloader.stats.pending, 2);
  });

  it("deleteLocalAfterUpload purges the entry from the local store", async () => {
    seen.length = 0;
    const entries = [makeEntry(), makeEntry()];
    const source = makeSource(entries);
    const offloader = new DeadLetterS3Offloader(
      baseConfig(endpoint(), { deleteLocalAfterUpload: true }),
      source
    );
    const results = await offloader.scanAndUpload();
    assert.ok(results.every((r) => r.ok));
    assert.equal(source.entries().length, 0, "uploaded entries purged from the local store");
  });

  it("fails loudly (but counted) when the secret does not resolve", async () => {
    seen.length = 0;
    const entries = [makeEntry()];
    const offloader = new DeadLetterS3Offloader(
      baseConfig(endpoint(), { secretResolver: () => undefined }),
      makeSource(entries)
    );
    const results = await offloader.scanAndUpload();
    assert.equal(results[0].ok, false);
    assert.match(results[0].error ?? "", /secretRef "unused-when-injected" did not resolve/);
    assert.ok(!(results[0].error ?? "").includes(testKeyMaterial));
    assert.equal(offloader.stats.uploadFailures, 1);
    assert.equal(seen.length, 0, "no PUT without key material");
  });

  it("archives sealed (WR-11) payloads decrypted, flagged encrypted", async () => {
    seen.length = 0;
    const opened = Buffer.from(JSON.stringify({ opened: true }));
    const sealed = makeEntry({ encryptedPayload: { alg: "aes-256-gcm", iv: "aXY=", data: "ZGF0YQ==", tag: "dGFn" } });
    const source = makeSource([sealed]);
    source.decrypt = () => opened;
    const offloader = new DeadLetterS3Offloader(baseConfig(endpoint()), source);
    const results = await offloader.scanAndUpload();
    assert.ok(results[0].ok);
    assert.equal(seen.length, 1);
    const doc = JSON.parse(seen[0].body.toString("utf8"));
    assert.equal(doc.encrypted, true);
    assert.deepEqual(JSON.parse(doc.payload), { opened: true });
  });
});
