import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { mkdtempSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DeliveryEventArchiver,
  parseSealedSegmentName,
} from "../src/event-archive.ts";
import {
  ArchiveS3Offloader,
  assertValidArchiveS3Config,
  type ArchiveS3OffloadConfig,
} from "../src/archive-s3.ts";
import { createRelayServer } from "../src/server.ts";
import { AuditLog } from "../src/audit.ts";
import type { DeliveryEvent, DeliveryEventType } from "../src/retry.ts";

const TEST_AKID = "TESTAKID123";
const TEST_REGION = "us-east-1";
const TEST_SECRET = "wr188-test-aws-secret";
const relaySignSecret = "relay-inbound-test-secret";

function tmpDir(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

function makeEvent(partial: Partial<DeliveryEvent> & { type: DeliveryEventType }): DeliveryEvent {
  return {
    id: `id-${Math.random().toString(36).slice(2)}`,
    traceId: `trace-${Math.random().toString(36).slice(2)}`,
    targetUrl: "https://downstream.example/hook",
    attempts: 1,
    at: new Date().toISOString(),
    ...partial,
  };
}

function utcDate(): string {
  const d = new Date();
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}`;
}

function baseConfig(dir: string, extra: Partial<ArchiveS3OffloadConfig> = {}): ArchiveS3OffloadConfig {
  return {
    sealedDir: join(dir, "sealed"),
    endpoint: "http://127.0.0.1:9", // replaced per test
    bucket: "relay-archives",
    region: TEST_REGION,
    accessKeyId: TEST_AKID,
    secretRef: "unused-when-injected",
    secretResolver: () => TEST_SECRET,
    ...extra,
  };
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

async function close(server: Server): Promise<void> {
  server.close();
  await new Promise((r) => server.once("close", r));
}

describe("WR-188: segment sealing", () => {
  it("seals evicted lines into a deterministic date/seq-range segment", () => {
    const dir = tmpDir("archive-seal-");
    const sealed: string[] = [];
    const archiver = new DeliveryEventArchiver({
      dir,
      maxBytes: 400,
      sealedDir: join(dir, "sealed"),
      onSegmentSealed: (p) => sealed.push(p),
    });
    for (let i = 0; i < 10; i += 1) {
      archiver.record(makeEvent({ type: "delivered", id: `ev-${i}` }));
    }
    archiver.compactNow();
    const files = readdirSync(join(dir, "sealed")).filter((n) => n.endsWith(".jsonl"));
    assert.ok(files.length >= 1, `expected sealed segments, got ${files.length}`);
    const parsed = parseSealedSegmentName(files[0]);
    assert.ok(parsed !== undefined, `segment name must parse: ${files[0]}`);
    assert.equal(parsed.date, utcDate());
    assert.ok(parsed.seqMax >= parsed.seqMin, "sealed range must be non-empty");
    const sealedLines = readFileSync(join(dir, "sealed", files[0]), "utf8")
      .split("\n")
      .filter((l) => l.trim() !== "");
    assert.equal(sealedLines.length, parsed.seqMax - parsed.seqMin + 1);
    for (const line of sealedLines) {
      const obj = JSON.parse(line) as { id: string; seq: number };
      assert.match(obj.id, /^ev-\d+$/);
      assert.ok(obj.seq >= parsed.seqMin && obj.seq <= parsed.seqMax);
    }
    // The live file still honors maxBytes — sealing does not disable retention.
    const live = readFileSync(join(dir, "events.jsonl"), "utf8");
    assert.ok(live.length <= 400, `live file must stay within maxBytes, got ${live.length}`);
    // The notification fired with the sealed path (error-isolated path below proves it is optional).
    assert.ok(sealed.length >= 1 && sealed[0].endsWith(files[0]));
    assert.ok(archiver.stats.sealedSegments >= 1);
    archiver.close();
  });

  it("onSegmentSealed is error-isolated: a throwing listener never fails retention", () => {
    const dir = tmpDir("archive-seal-isolated-");
    const archiver = new DeliveryEventArchiver({
      dir,
      maxBytes: 400,
      sealedDir: join(dir, "sealed"),
      onSegmentSealed: () => {
        throw new Error("boom");
      },
    });
    for (let i = 0; i < 10; i += 1) {
      archiver.record(makeEvent({ type: "delivered" }));
    }
    assert.doesNotThrow(() => archiver.compactNow());
    const files = readdirSync(join(dir, "sealed")).filter((n) => n.endsWith(".jsonl"));
    assert.ok(files.length >= 1, "seal must still be written despite the throwing listener");
    archiver.close();
  });

  it("without sealedDir, retention drops lines exactly as before", () => {
    const dir = tmpDir("archive-noseal-");
    const archiver = new DeliveryEventArchiver({ dir, maxBytes: 400 });
    for (let i = 0; i < 10; i += 1) {
      archiver.record(makeEvent({ type: "delivered" }));
    }
    archiver.compactNow();
    const live = readFileSync(join(dir, "events.jsonl"), "utf8");
    assert.ok(live.length <= 400);
    assert.equal(archiver.stats.sealedSegments, 0);
    archiver.close();
  });

  it("parseSealedSegmentName rejects non-segment names", () => {
    assert.equal(parseSealedSegmentName("events.jsonl"), undefined);
    assert.equal(parseSealedSegmentName("20261022-seq-1-3.jsonl.tmp"), undefined);
    assert.equal(parseSealedSegmentName("20261022-seq-3-1.jsonl"), undefined);
    assert.equal(parseSealedSegmentName("20261022-noseq-5.jsonl"), undefined);
  });
});

describe("WR-188: S3 offload", () => {
  it("PUTs sealed segments via SigV4 to a deterministic key and marks them uploaded", async () => {
    const dir = tmpDir("archive-s3-put-");
    const captured: Array<{
      method: string;
      url: string;
      headers: Record<string, string | string[] | undefined>;
      body: Buffer;
    }> = [];
    const stub = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        captured.push({
          method: req.method ?? "",
          url: req.url ?? "",
          headers: req.headers,
          body: Buffer.concat(chunks),
        });
        res.writeHead(200);
        res.end();
      });
    });
    const port = await listen(stub);
    const sealedDir = join(dir, "sealed");
    const archiver = new DeliveryEventArchiver({
      dir,
      maxBytes: 400,
      sealedDir,
      onSegmentSealed: () => undefined,
    });
    for (let i = 0; i < 10; i += 1) {
      archiver.record(makeEvent({ type: "delivered", id: `up-${i}` }));
    }
    archiver.compactNow();
    archiver.close();
    const segments = readdirSync(sealedDir).filter((n) => n.endsWith(".jsonl"));
    assert.ok(segments.length >= 1);

    const offloader = new ArchiveS3Offloader(
      baseConfig(dir, { endpoint: `http://127.0.0.1:${port}`, keyPrefix: "relay/" })
    );
    const parsed = parseSealedSegmentName(segments[0])!;
    const expectedKey = `relay/${parsed.date}/events-${parsed.seqMin}-${parsed.seqMax}.jsonl`;
    const results = await offloader.scanAndUpload();
    assert.equal(results.length, segments.length);
    for (const r of results) assert.ok(r.ok, `upload failed: ${r.error}`);
    assert.equal(results[0].key, expectedKey);

    // Wire assertions: SigV4 Authorization + date header + exact bytes.
    assert.equal(captured.length, segments.length);
    const req = captured[0];
    assert.equal(req.method, "PUT");
    // Path-style URL: /<bucket>/<key> with each key segment encoded, slashes preserved.
    assert.equal(req.url, `/relay-archives/${expectedKey}`);
    const auth = String(req.headers["authorization"] ?? "");
    assert.match(auth, new RegExp(`^AWS4-HMAC-SHA256 Credential=${TEST_AKID}/`));
    assert.ok(req.headers["x-amz-date"] !== undefined, "x-amz-date must be stamped");
    assert.ok(req.headers["x-amz-content-sha256"] !== undefined, "payload hash must be stamped");
    const original = readFileSync(join(sealedDir, segments[0] + ".uploaded"));
    assert.ok(req.body.equals(original), "the PUT body must be the exact sealed bytes");

    // Marker: local bytes kept under .uploaded, rescan finds nothing pending.
    const stats = offloader.stats;
    assert.equal(stats.uploaded, segments.length);
    assert.equal(stats.pending, 0);
    const second = await offloader.scanAndUpload();
    assert.equal(second.length, 0, "uploaded segments must not be re-uploaded");
    await close(stub);
  });

  it("dryRun records intended keys with zero network I/O", async () => {
    const dir = tmpDir("archive-s3-dryrun-");
    const sealedDir = join(dir, "sealed");
    const archiver = new DeliveryEventArchiver({ dir, maxBytes: 400, sealedDir });
    for (let i = 0; i < 8; i += 1) {
      archiver.record(makeEvent({ type: "dead_letter" }));
    }
    archiver.compactNow();
    archiver.close();
    const segments = readdirSync(sealedDir).filter((n) => n.endsWith(".jsonl"));
    assert.ok(segments.length >= 1);

    // An unroutable endpoint proves no I/O happens: a real attempt would fail.
    const offloader = new ArchiveS3Offloader(
      baseConfig(dir, { endpoint: "http://127.0.0.1:9", dryRun: true, keyPrefix: "dry/" })
    );
    const results = await offloader.scanAndUpload();
    assert.equal(results.length, segments.length);
    for (const r of results) {
      assert.ok(r.ok && r.dryRun === true);
    }
    assert.equal(offloader.stats.uploaded, 0, "dry-run must not count uploads");
    assert.equal(offloader.stats.pending, segments.length, "dry-run must not consume the queue");
    const keys = offloader.getDryRunKeys();
    assert.equal(keys.length, segments.length);
    for (const key of keys) {
      assert.match(key, /^dry\/\d{8}\/events-\d+-\d+\.jsonl$/);
    }
    // Files untouched: still pending, no markers.
    assert.ok(readdirSync(sealedDir).every((n) => !n.endsWith(".uploaded")));
  });

  it("upload failures are counted, never thrown, and retried on the next scan", async () => {
    const dir = tmpDir("archive-s3-fail-");
    const sealedDir = join(dir, "sealed");
    const archiver = new DeliveryEventArchiver({ dir, maxBytes: 400, sealedDir });
    for (let i = 0; i < 8; i += 1) {
      archiver.record(makeEvent({ type: "retrying" }));
    }
    archiver.compactNow();
    archiver.close();
    const segments = readdirSync(sealedDir).filter((n) => n.endsWith(".jsonl"));
    assert.ok(segments.length >= 1);

    const offloader = new ArchiveS3Offloader(
      baseConfig(dir, { endpoint: "http://127.0.0.1:9", requestTimeoutMs: 2000 })
    );
    const results = await offloader.scanAndUpload();
    assert.equal(results.length, segments.length);
    for (const r of results) {
      assert.equal(r.ok, false);
      assert.ok(r.error !== undefined, "failure must carry a reason, not key material");
      assert.ok(!r.error.includes(TEST_SECRET), "key material must never leak into errors");
    }
    assert.equal(offloader.stats.uploadFailures, segments.length);
    assert.equal(offloader.stats.uploaded, 0);
    assert.equal(offloader.stats.pending, segments.length, "failed segments stay pending");
  });

  it("deleteLocalAfterUpload removes the local file on success", async () => {
    const dir = tmpDir("archive-s3-delete-");
    const stub = createServer((req, res) => {
      req.on("data", () => undefined);
      req.on("end", () => {
        res.writeHead(200);
        res.end();
      });
    });
    const port = await listen(stub);
    const sealedDir = join(dir, "sealed");
    const archiver = new DeliveryEventArchiver({ dir, maxBytes: 400, sealedDir });
    for (let i = 0; i < 8; i += 1) {
      archiver.record(makeEvent({ type: "delivered" }));
    }
    archiver.compactNow();
    archiver.close();
    const offloader = new ArchiveS3Offloader(
      baseConfig(dir, { endpoint: `http://127.0.0.1:${port}`, deleteLocalAfterUpload: true })
    );
    const results = await offloader.scanAndUpload();
    assert.ok(results.length >= 1 && results.every((r) => r.ok));
    assert.equal(readdirSync(sealedDir).length, 0, "local copies must be gone");
    await close(stub);
  });

  it("rejects invalid configs at startup", () => {
    const dir = tmpDir("archive-s3-cfg-");
    assert.throws(
      () => new ArchiveS3Offloader(baseConfig(dir, { endpoint: "ftp://x/y" })),
      RangeError
    );
    assert.throws(() => new ArchiveS3Offloader(baseConfig(dir, { endpoint: "http://x/" })), RangeError);
    assert.throws(() => new ArchiveS3Offloader(baseConfig(dir, { bucket: "" })), RangeError);
    assert.throws(() => new ArchiveS3Offloader(baseConfig(dir, { region: "BAD REGION" })), RangeError);
    assert.throws(() => new ArchiveS3Offloader(baseConfig(dir, { accessKeyId: "" })), RangeError);
    assert.throws(() => new ArchiveS3Offloader(baseConfig(dir, { secretRef: "" })), RangeError);
    assert.throws(
      () => assertValidArchiveS3Config(null, "x"),
      RangeError
    );
  });

  it("segmentObjectKey is deterministic and falls back for non-segment names", () => {
    const dir = tmpDir("archive-s3-key-");
    const offloader = new ArchiveS3Offloader(baseConfig(dir, { keyPrefix: "p/" }));
    assert.equal(
      offloader.segmentObjectKey("20261022-seq-41-120.jsonl"),
      "p/20261022/events-41-120.jsonl"
    );
    assert.equal(
      offloader.segmentObjectKey("20261022-seq-41-120-2.jsonl"),
      "p/20261022/events-41-120.jsonl"
    );
    assert.equal(
      offloader.segmentObjectKey("weird.jsonl"),
      "p/misc/weird.jsonl"
    );
  });
});

describe("WR-188: server wiring", () => {
  it("rejects archiveS3 without eventArchive.sealedDir at startup", () => {
    const dir = tmpDir("archive-s3-server-");
    assert.throws(
      () =>
        createRelayServer({
          secret: relaySignSecret,
          forwardUrl: "http://127.0.0.1:1/hook",
          auditLog: new AuditLog(join(dir, "audit.jsonl")),
          operatorToken: "op",
          eventArchive: { dir: join(dir, "archive") },
          archiveS3: baseConfig(dir),
        }),
      RangeError
    );
  });

  it("accepts archiveS3 with a sealedDir and closes cleanly", () => {
    const dir = tmpDir("archive-s3-server-ok-");
    const relay = createRelayServer({
      secret: relaySignSecret,
      forwardUrl: "http://127.0.0.1:1/hook",
      auditLog: new AuditLog(join(dir, "audit.jsonl")),
      operatorToken: "op",
      eventArchive: { dir: join(dir, "archive"), sealedDir: join(dir, "sealed") },
      archiveS3: baseConfig(dir, { endpoint: "http://127.0.0.1:9", dryRun: true }),
    });
    relay.close();
  });
});
