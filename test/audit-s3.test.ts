import { describe, it, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, readdirSync, writeFileSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AuditLog,
  parseAuditSealedSegmentName,
} from "../src/audit.ts";
import {
  AuditS3Error,
  AuditS3Offloader,
  AUDIT_UPLOADED_SUFFIX,
  assertValidAuditS3Config,
  type AuditS3OffloadConfig,
} from "../src/audit-s3.ts";
import { createRelayServer } from "../src/server.ts";

const testKey = "audit-s3-test-secret-key";

function tmpRoot(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

function validConfig(sealedDir: string, overrides: Partial<AuditS3OffloadConfig> = {}): AuditS3OffloadConfig {
  return {
    sealedDir,
    endpoint: "http://127.0.0.1:1",
    bucket: "audit-bucket",
    region: "us-east-1",
    keyPrefix: "audits/",
    accessKeyId: "test-key-id",
    secretRef: "AUDIT_S3_TEST_SECRET",
    ...overrides,
  };
}

function writeSegment(dir: string, name: string, lines: string[]): string {
  const path = join(dir, name);
  writeFileSync(path, lines.map((l) => l + "\n").join(""), "utf8");
  return path;
}

describe("assertValidAuditS3Config", () => {
  it("rejects every bad shape with RangeError", () => {
    const dir = tmpRoot("audit-s3-cfg-");
    const good = validConfig(dir);
    assert.doesNotThrow(() => assertValidAuditS3Config(good, "t"));
    const bad: [string, Partial<AuditS3OffloadConfig>][] = [
      ["null", undefined as unknown as Partial<AuditS3OffloadConfig>],
      ["empty sealedDir", { sealedDir: "" }],
      ["empty endpoint", { endpoint: "" }],
      ["endpoint not a URL", { endpoint: "not-a-url" }],
      ["endpoint wrong scheme", { endpoint: "ftp://x" }],
      ["endpoint trailing slash", { endpoint: "http://x/" }],
      ["empty bucket", { bucket: "" }],
      ["bad region", { region: "us_east" }],
      ["non-string keyPrefix", { keyPrefix: 7 as unknown as string }],
      ["empty accessKeyId", { accessKeyId: "" }],
      ["empty secretRef", { secretRef: "" }],
      ["non-function secretResolver", { secretResolver: 7 as unknown as () => string }],
      ["non-positive requestTimeoutMs", { requestTimeoutMs: 0 }],
      ["NaN requestTimeoutMs", { requestTimeoutMs: NaN }],
    ];
    for (const [label, patch] of bad) {
      const cfg = patch === undefined ? undefined : { ...good, ...patch };
      assert.throws(() => assertValidAuditS3Config(cfg, "t"), RangeError, label);
    }
  });

  it("accepts a minimal config without keyPrefix", () => {
    const dir = tmpRoot("audit-s3-cfg-min-");
    const cfg = validConfig(dir);
    delete cfg.keyPrefix;
    assert.doesNotThrow(() => assertValidAuditS3Config(cfg, "t"));
    const offloader = new AuditS3Offloader(cfg);
    assert.equal(offloader.segmentObjectKey("20261022-seq-1-3.jsonl"), "20261022/audit-1-3.jsonl");
  });
});

describe("segmentObjectKey", () => {
  it("derives deterministic keys and preserves the dup suffix", () => {
    const dir = tmpRoot("audit-s3-key-");
    const offloader = new AuditS3Offloader(validConfig(dir));
    assert.equal(
      offloader.segmentObjectKey("20261022-seq-1-5.jsonl"),
      "audits/20261022/audit-1-5.jsonl"
    );
    assert.equal(
      offloader.segmentObjectKey("20261022-seq-1-5-2.jsonl"),
      "audits/20261022/audit-1-5-2.jsonl"
    );
    // Unparseable names still upload under misc/ — never silently skipped.
    assert.equal(
      offloader.segmentObjectKey("weird-name.jsonl"),
      "audits/misc/weird-name.jsonl"
    );
    assert.equal(
      offloader.segmentObjectKey("20261022-seq-0-5.jsonl"),
      "audits/misc/20261022-seq-0-5.jsonl"
    );
  });

  it("normalizes the key prefix", () => {
    const dir = tmpRoot("audit-s3-keypfx-");
    for (const [prefix, want] of [
      [undefined, "20261022/audit-1-2.jsonl"],
      ["", "20261022/audit-1-2.jsonl"],
      ["root", "root/20261022/audit-1-2.jsonl"],
      ["root/", "root/20261022/audit-1-2.jsonl"],
      ["/root/", "root/20261022/audit-1-2.jsonl"],
    ] as const) {
      const cfg = validConfig(dir);
      if (prefix === undefined) delete cfg.keyPrefix;
      else cfg.keyPrefix = prefix;
      const offloader = new AuditS3Offloader(cfg);
      assert.equal(offloader.segmentObjectKey("20261022-seq-1-2.jsonl"), want, `prefix ${prefix}`);
    }
  });
});

describe("parseAuditSealedSegmentName", () => {
  it("parses names and rejects non-conforming ones", () => {
    assert.deepEqual(parseAuditSealedSegmentName("20261022-seq-1-5.jsonl"), {
      date: "20261022",
      seqMin: 1,
      seqMax: 5,
    });
    assert.deepEqual(parseAuditSealedSegmentName("20261022-seq-1-5-2.jsonl"), {
      date: "20261022",
      seqMin: 1,
      seqMax: 5,
      dup: 2,
    });
    assert.equal(parseAuditSealedSegmentName("20261022-seq-0-5.jsonl"), undefined);
    assert.equal(parseAuditSealedSegmentName("20261022-seq-5-1.jsonl"), undefined);
    assert.equal(parseAuditSealedSegmentName("20261022-seq-1-5-1.jsonl"), undefined);
    assert.equal(parseAuditSealedSegmentName("events.jsonl"), undefined);
    assert.equal(parseAuditSealedSegmentName("20261022-seq-1-5.txt"), undefined);
  });
});

describe("pendingSegments", () => {
  it("lists segments sorted, skips markers and tmp files, tolerates a missing dir", () => {
    const dir = tmpRoot("audit-s3-pending-");
    writeSegment(dir, "20261022-seq-1-2.jsonl", ['{"a":1}']);
    writeSegment(dir, "20261021-seq-1-9.jsonl", ['{"a":1}']);
    writeSegment(dir, `20261022-seq-1-2.jsonl${AUDIT_UPLOADED_SUFFIX}`, ['{"a":1}']);
    writeSegment(dir, "20261022-seq-1-2.jsonl.123.tmp", ['{"a":1}']);
    const offloader = new AuditS3Offloader(validConfig(dir));
    assert.deepEqual(offloader.pendingSegments(), [
      "20261021-seq-1-9.jsonl",
      "20261022-seq-1-2.jsonl",
    ]);
    const missing = new AuditS3Offloader(validConfig(join(dir, "nope")));
    assert.deepEqual(missing.pendingSegments(), []);
    assert.equal(missing.stats.pending, 0);
  });
});

describe("dry-run", () => {
  it("records keys with zero I/O: no network, no markers, no counter changes", async () => {
    const dir = tmpRoot("audit-s3-dryrun-");
    writeSegment(dir, "20261022-seq-1-2.jsonl", ['{"a":1}', '{"a":2}']);
    const offloader = new AuditS3Offloader(
      validConfig(dir, {
        dryRun: true,
        secretResolver: () => {
          throw new Error("must not be called in dry-run");
        },
      })
    );
    const results = await offloader.scanAndUpload();
    assert.equal(results.length, 1);
    assert.equal(results[0].ok, true);
    assert.equal(results[0].dryRun, true);
    assert.deepEqual(offloader.getDryRunKeys(), ["audits/20261022/audit-1-2.jsonl"]);
    // Zero I/O: no marker written, segment untouched, counters still zero.
    assert.deepEqual(readdirSync(dir), ["20261022-seq-1-2.jsonl"]);
    assert.deepEqual(offloader.stats, { uploaded: 0, uploadFailures: 0, pending: 1 });
  });
});

describe("uploadSegment over HTTP", () => {
  interface Seen { headers: Record<string, string | string[] | undefined>; body: Buffer; path: string }
  let seen: Seen[] = [];
  let status = 200;
  let server: ReturnType<typeof createServer> | undefined;

  async function startStub(): Promise<number> {
    server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c) => chunks.push(c as Buffer));
      req.on("end", () => {
        seen.push({ headers: req.headers, body: Buffer.concat(chunks), path: req.url ?? "" });
        res.writeHead(status, { "content-type": "text/plain" });
        res.end("ok");
      });
    });
    await new Promise<void>((r) => server!.listen(0, "127.0.0.1", r));
    const addr = server!.address();
    if (addr === null || typeof addr === "string") throw new Error("stub did not bind");
    return addr.port;
  }

  afterEach(async () => {
    seen = [];
    status = 200;
    if (server !== undefined) {
      await new Promise<void>((r) => server!.close(() => r()));
      server = undefined;
    }
  });

  it("PUTs with SigV4 headers and marks the segment .uploaded by default", async () => {
    const port = await startStub();
    const dir = tmpRoot("audit-s3-put-");
    writeSegment(dir, "20261022-seq-1-2.jsonl", ['{"a":1}', '{"a":2}']);
    const offloader = new AuditS3Offloader(
      validConfig(dir, { endpoint: `http://127.0.0.1:${port}`, secretResolver: () => testKey })
    );
    const result = await offloader.uploadSegment("20261022-seq-1-2.jsonl");
    assert.equal(result.ok, true);
    assert.equal(result.key, "audits/20261022/audit-1-2.jsonl");
    assert.equal(seen.length, 1);
    const { headers, body: sent, path } = seen[0];
    assert.equal(path, "/audit-bucket/audits/20261022/audit-1-2.jsonl");
    assert.match(String(headers["authorization"]), /^AWS4-HMAC-SHA256 /);
    assert.ok(headers["x-amz-date"], "x-amz-date header present");
    assert.ok(headers["x-amz-content-sha256"], "x-amz-content-sha256 header present");
    assert.deepEqual(sent, readFileSync(join(dir, "20261022-seq-1-2.jsonl" + AUDIT_UPLOADED_SUFFIX)));
    // Default: local bytes kept under the .uploaded marker.
    assert.deepEqual(readdirSync(dir), [`20261022-seq-1-2.jsonl${AUDIT_UPLOADED_SUFFIX}`]);
    assert.deepEqual(offloader.stats, { uploaded: 1, uploadFailures: 0, pending: 0 });
  });

  it("deleteLocalAfterUpload removes the local segment", async () => {
    const port = await startStub();
    const dir = tmpRoot("audit-s3-del-");
    writeSegment(dir, "20261022-seq-3-4.jsonl", ['{"a":3}']);
    const offloader = new AuditS3Offloader(
      validConfig(dir, {
        endpoint: `http://127.0.0.1:${port}`,
        secretResolver: () => testKey,
        deleteLocalAfterUpload: true,
      })
    );
    const result = await offloader.uploadSegment("20261022-seq-3-4.jsonl");
    assert.equal(result.ok, true);
    assert.deepEqual(readdirSync(dir), []);
    assert.equal(offloader.stats.uploaded, 1);
  });

  it("counts failures and retries on the next scan; scanAndUpload never throws", async () => {
    const port = await startStub();
    const dir = tmpRoot("audit-s3-retry-");
    writeSegment(dir, "20261022-seq-1-1.jsonl", ['{"a":1}']);
    const offloader = new AuditS3Offloader(
      validConfig(dir, { endpoint: `http://127.0.0.1:${port}`, secretResolver: () => testKey })
    );
    status = 500;
    const first = await offloader.scanAndUpload();
    assert.equal(first.length, 1);
    assert.equal(first[0].ok, false);
    assert.match(first[0].error ?? "", /HTTP 500/);
    assert.deepEqual(offloader.stats, { uploaded: 0, uploadFailures: 1, pending: 1 });
    // The failed segment is not marked: it stays pending for the retry.
    assert.deepEqual(readdirSync(dir), ["20261022-seq-1-1.jsonl"]);
    status = 200;
    const second = await offloader.scanAndUpload();
    assert.equal(second.length, 1);
    assert.equal(second[0].ok, true);
    assert.deepEqual(offloader.stats, { uploaded: 1, uploadFailures: 1, pending: 0 });
  });

  it("throws AuditS3Error on missing secret and on missing file", async () => {
    const port = await startStub();
    const dir = tmpRoot("audit-s3-err-");
    writeSegment(dir, "20261022-seq-1-1.jsonl", ['{"a":1}']);
    const noSecret = new AuditS3Offloader(
      validConfig(dir, { endpoint: `http://127.0.0.1:${port}`, secretResolver: () => undefined })
    );
    await assert.rejects(() => noSecret.uploadSegment("20261022-seq-1-1.jsonl"), AuditS3Error);
    const offloader = new AuditS3Offloader(
      validConfig(dir, { endpoint: `http://127.0.0.1:${port}`, secretResolver: () => testKey })
    );
    await assert.rejects(() => offloader.uploadSegment("missing.jsonl"), AuditS3Error);
    assert.equal(offloader.stats.uploadFailures, 0, "explicit path throws; it does not count");
  });
});

describe("AuditLog segment sealing (WR-190)", () => {
  function sealedLog(opts: Record<string, unknown>): { audit: AuditLog; dir: string; sealedDir: string } {
    const dir = tmpRoot("audit-seal-");
    const sealedDir = join(dir, "sealed");
    const audit = new AuditLog(join(dir, "audit.jsonl"), { sealedDir, ...opts });
    return { audit, dir, sealedDir };
  }

  function utcDateOfNow(): string {
    const d = new Date();
    const pad = (n: number) => String(n).padStart(2, "0");
    return `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}`;
  }

  it("seals on sealMaxBytes with the WR-188 name convention and fires handlers", () => {
    const { audit, dir, sealedDir } = sealedLog({ sealMaxBytes: 10 });
    const seen: string[] = [];
    const unsub = audit.onAuditSegmentSealed((p) => seen.push(p));
    const throwing = audit.onAuditSegmentSealed(() => {
      throw new Error("a bad handler must not break appends");
    });

    audit.append({ event: "one", id: "a" });
    audit.append({ event: "two", id: "b" });
    audit.append({ event: "three", id: "c" });

    // Each tripping append sealed the previous line: two 1-line segments,
    // the second with a dedupe suffix, and the last line still live.
    const names = readdirSync(sealedDir).sort();
    const date = utcDateOfNow();
    assert.deepEqual(names, [`${date}-seq-1-1.jsonl`, `${date}-seq-1-1-2.jsonl`].sort());
    assert.deepEqual(
      seen,
      [`${date}-seq-1-1.jsonl`, `${date}-seq-1-1-2.jsonl`].map((n) => join(sealedDir, n)),
      "handler fired once per seal with the local path, in seal order"
    );
    const live = readFileSync(join(dir, "audit.jsonl"), "utf8").split("\n").filter((l) => l.length > 0);
    assert.equal(live.length, 1);
    assert.equal((JSON.parse(live[0]) as { id: string }).id, "c");

    // Each sealed segment is independently chain-verifiable.
    for (const n of names) {
      const seg = new AuditLog(join(sealedDir, n));
      const v = seg.verifyChain();
      assert.equal(v.ok, true, `sealed ${n} verifies`);
      assert.equal(v.lines, 1);
      const hv = seg.verifyHmacChain();
      assert.equal(hv.ok, false, "a fresh key era cannot verify an old segment's HMAC links");
      assert.equal(hv.firstBreak?.reason, "unknown_key");
    }
    // The new live file verifies on its own chain too.
    const liveCheck = audit.verifyChain();
    assert.equal(liveCheck.ok, true);
    assert.equal(liveCheck.lines, 1);

    unsub();
    throwing();
    audit.append({ event: "four", id: "d" });
    assert.equal(seen.length, 2, "unsubscribed handler no longer fires");
  });

  it("seals on sealMaxAgeMs using the file mtime at construction", () => {
    const dir = tmpRoot("audit-age-");
    const livePath = join(dir, "audit.jsonl");
    writeFileSync(livePath, JSON.stringify({ event: "old", ts: new Date().toISOString() }) + "\n", "utf8");
    // Age the file two days back.
    const old = Date.now() - 2 * 24 * 60 * 60 * 1000;
    utimesSync(livePath, new Date(old), new Date(old));
    const sealedDir = join(dir, "sealed");
    const audit = new AuditLog(livePath, { sealedDir, sealMaxAgeMs: 60_000 });
    audit.append({ event: "new" });
    const names = readdirSync(sealedDir);
    assert.equal(names.length, 1);
    assert.match(names[0], /^\d{8}-seq-1-1\.jsonl$/);
    const live = readFileSync(livePath, "utf8").split("\n").filter((l) => l.length > 0);
    assert.equal(live.length, 1);
    assert.equal((JSON.parse(live[0]) as { event: string }).event, "new");
  });

  it("does nothing without thresholds, and nothing at all without sealedDir", () => {
    const dir = tmpRoot("audit-noseal-");
    const noSeal = new AuditLog(join(dir, "a.jsonl"));
    assert.equal(noSeal.sealedDir, undefined);
    noSeal.append({ event: "x" });
    assert.deepEqual(readdirSync(dir), ["a.jsonl"]);

    const sealedDir = join(dir, "sealed");
    const noThreshold = new AuditLog(join(dir, "b.jsonl"), { sealedDir });
    noThreshold.append({ event: "x" });
    noThreshold.append({ event: "y" });
    assert.deepEqual(readdirSync(sealedDir), [], "no thresholds: nothing sealed");
    assert.equal(noThreshold.sealedDir, sealedDir);
    const live = readFileSync(join(dir, "b.jsonl"), "utf8").split("\n").filter((l) => l.length > 0);
    assert.equal(live.length, 2);
  });

  it("rejects bad sealing options with RangeError, fail-fast", () => {
    const dir = tmpRoot("audit-badcfg-");
    const mk = (opts: Record<string, unknown>) => new AuditLog(join(dir, "a.jsonl"), opts);
    assert.throws(() => mk({ sealedDir: "" }), RangeError);
    assert.throws(() => mk({ sealedDir: 7 as unknown as string }), RangeError);
    assert.throws(() => mk({ sealMaxBytes: 10 }), RangeError, "thresholds require sealedDir");
    assert.throws(() => mk({ sealMaxAgeMs: 10 }), RangeError, "thresholds require sealedDir");
    for (const bad of [0, -1, NaN, Infinity]) {
      assert.throws(() => mk({ sealedDir: join(dir, "s"), sealMaxBytes: bad }), RangeError);
      assert.throws(() => mk({ sealedDir: join(dir, "s"), sealMaxAgeMs: bad }), RangeError);
    }
    assert.throws(
      () => mk({ sealedDir: join(dir, "s"), onAuditSegmentSealed: 7 as unknown as () => void }),
      RangeError
    );
    const audit = new AuditLog(join(dir, "b.jsonl"));
    assert.throws(() => audit.onAuditSegmentSealed(7 as unknown as () => void), RangeError);
  });

  it("supports several lines per seal and keeps chain order across seals", () => {
    const { audit, dir, sealedDir } = sealedLog({ sealMaxBytes: 10_000 });
    for (let i = 0; i < 5; i++) audit.append({ event: "fill", n: i });
    // No seal yet: 5 lines live.
    assert.deepEqual(readdirSync(sealedDir), []);
    // A fresh instance with a tiny byte threshold seals all 5 lines at once.
    const audit2 = new AuditLog(join(dir, "audit.jsonl"), {
      sealedDir,
      sealMaxBytes: 1,
    });
    audit2.append({ event: "trip" });
    const names = readdirSync(sealedDir);
    assert.equal(names.length, 1);
    const date = utcDateOfNow();
    assert.equal(names[0], `${date}-seq-1-5.jsonl`);
    const seg = new AuditLog(join(sealedDir, names[0]));
    assert.equal(seg.verifyChain().ok, true);
    assert.deepEqual(
      (seg.readAll() as { n: number }[]).map((e) => e.n),
      [0, 1, 2, 3, 4],
      "sealed lines land in order"
    );
    void audit;
  });
});

describe("server auditS3 option", () => {
  it("requires the AuditLog to be constructed with sealedDir", () => {
    const dir = tmpRoot("audit-srv-");
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    assert.throws(
      () =>
        createRelayServer({
          secret: "op-secret",
          forwardUrl: "http://127.0.0.1:1/hook",
          auditLog: audit,
          auditS3: validConfig(join(dir, "sealed")),
        }),
      (err: unknown) =>
        err instanceof RangeError &&
        /`auditS3` requires the AuditLog to be constructed with `sealedDir`/.test(err.message)
    );
  });

  it("accepts auditS3 when the AuditLog has sealedDir", () => {
    const dir = tmpRoot("audit-srv-ok-");
    const audit = new AuditLog(join(dir, "audit.jsonl"), { sealedDir: join(dir, "sealed") });
    const relay = createRelayServer({
      secret: "op-secret",
      forwardUrl: "http://127.0.0.1:1/hook",
      auditLog: audit,
      auditS3: validConfig(join(dir, "sealed"), { dryRun: true }),
    });
    relay.close();
  });
});
