import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import {
  KinesisSink,
  KinesisSinkConfigError,
  KinesisSinkError,
  assertValidKinesisSinkConfig,
  buildKinesisPutRecordsBody,
  classifyKinesisRecordFailure,
  parseKinesisPutRecordsResponse,
  resolveKinesisPartitionKey,
  resolveKinesisRecord,
  splitKinesisPutRecordsChunks,
  type KinesisRecord,
  type KinesisResolvedRecord,
  type KinesisSinkConfig,
} from "../src/kinesis-sink.ts";
import { classifyFailure } from "../src/failure.ts";
import { signAwsSigV4 } from "../src/sigv4.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.
const testAccessKeyId = "TESTAKID123";
const testRegion = "us-east-1";
const testKeyMaterial = "test-secret-access-key";
const testStream = "events-stream";

function baseConfig(endpointUrl: string, extra: Partial<KinesisSinkConfig> = {}): KinesisSinkConfig {
  return {
    endpointUrl,
    streamName: testStream,
    region: testRegion,
    accessKeyId: testAccessKeyId,
    secretRef: "unused-when-injected",
    secretResolver: () => testKeyMaterial,
    ...extra,
  };
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

interface SeenPost {
  method: string | undefined;
  path: string | undefined;
  headers: Record<string, string | string[] | undefined>;
  rawBody: string;
}

function stubKinesis(
  seen: SeenPost[],
  respond: (seenSoFar: SeenPost[]) => { status: number; body: string; headers?: Record<string, string> }
): Server {
  return createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const post: SeenPost = {
        method: req.method,
        path: req.url,
        headers: req.headers,
        rawBody: Buffer.concat(chunks).toString("utf8"),
      };
      seen.push(post);
      const r = respond(seen);
      res.writeHead(r.status, { "content-type": "application/x-amz-json-1.1", ...(r.headers ?? {}) });
      res.end(r.body);
    });
  });
}

function amzDateToMs(amzDate: string): number {
  // "20261024T123456Z" -> UTC ms.
  const y = Number(amzDate.slice(0, 4));
  const mo = Number(amzDate.slice(4, 6)) - 1;
  const d = Number(amzDate.slice(6, 8));
  const h = Number(amzDate.slice(9, 11));
  const mi = Number(amzDate.slice(11, 13));
  const s = Number(amzDate.slice(13, 15));
  return Date.UTC(y, mo, d, h, mi, s);
}

function putRecordsOk(count: number): string {
  return JSON.stringify({
    FailedRecordCount: 0,
    Records: Array.from({ length: count }, (_, i) => ({
      SequenceNumber: `seq-${i}`,
      ShardId: "shardId-000000000000",
    })),
  });
}

describe("kinesis-sink config validation", () => {
  it("rejects a non-object, an empty endpoint URL, and a non-URL endpoint URL", () => {
    assert.throws(() => assertValidKinesisSinkConfig(null, "x"), RangeError);
    assert.throws(() => assertValidKinesisSinkConfig(baseConfig(""), "x"), /endpointUrl.*non-empty/);
    assert.throws(() => assertValidKinesisSinkConfig(baseConfig("not-a-url"), "x"), /endpointUrl.*valid URL/);
  });

  it("rejects non-http(s) endpoint URLs", () => {
    assert.throws(() => assertValidKinesisSinkConfig(baseConfig("ftp://example.com/"), "x"), /http\(s\)/);
  });

  it("rejects bad stream names", () => {
    assert.throws(() => assertValidKinesisSinkConfig(baseConfig("http://localhost:4566/", { streamName: "" }), "x"), /streamName/);
    assert.throws(() => assertValidKinesisSinkConfig(baseConfig("http://localhost:4566/", { streamName: "bad name!" }), "x"), /streamName/);
    assert.throws(
      () => assertValidKinesisSinkConfig(baseConfig("http://localhost:4566/", { streamName: "s".repeat(129) }), "x"),
      /streamName/
    );
  });

  it("rejects a bad region, empty access key id, and empty secret ref", () => {
    assert.throws(() => assertValidKinesisSinkConfig(baseConfig("http://localhost:4566/", { region: "BAD REGION" }), "x"), /region/);
    assert.throws(() => assertValidKinesisSinkConfig(baseConfig("http://localhost:4566/", { accessKeyId: "" }), "x"), /accessKeyId/);
    assert.throws(() => assertValidKinesisSinkConfig(baseConfig("http://localhost:4566/", { secretRef: "" }), "x"), /secretRef/);
  });

  it("rejects a non-function secret resolver and a non-positive timeout", () => {
    assert.throws(
      () => assertValidKinesisSinkConfig(baseConfig("http://localhost:4566/", { secretResolver: "x" as never }), "x"),
      /secretResolver/
    );
    assert.throws(
      () => assertValidKinesisSinkConfig(baseConfig("http://localhost:4566/", { requestTimeoutMs: 0 }), "x"),
      /requestTimeoutMs/
    );
  });
});

describe("kinesis-sink partition keys", () => {
  it("prefers explicit partitionKey, then key, then traceId", () => {
    assert.equal(resolveKinesisPartitionKey({ data: "{}", partitionKey: "pk", key: "k", traceId: "t" }, 0), "pk");
    assert.equal(resolveKinesisPartitionKey({ data: "{}", key: "k", traceId: "t" }, 1), "k");
    assert.equal(resolveKinesisPartitionKey({ data: "{}", traceId: "t" }, 2), "t");
  });

  it("rejects a record with no key source instead of inventing one", () => {
    assert.throws(() => resolveKinesisPartitionKey({ data: "{}" }, 3), /no partition key/);
    assert.throws(() => resolveKinesisPartitionKey({ data: "{}", key: "" }, 4), /no partition key/);
  });

  it("rejects a partition key over 256 characters and empty data", () => {
    assert.throws(() => resolveKinesisPartitionKey({ data: "{}", key: "k".repeat(257) }, 0), /256/);
    assert.throws(() => resolveKinesisRecord({ data: "", key: "k" }, 0), /data.*non-empty/);
  });
});

describe("kinesis-sink batching", () => {
  const mk = (n: number, data = "{}"): KinesisResolvedRecord[] =>
    Array.from({ length: n }, (_, i) => ({ data, partitionKey: `k-${i}` }));

  it("splits at 500 records", () => {
    const chunks = splitKinesisPutRecordsChunks(mk(501));
    assert.deepEqual(chunks.map((c) => c.length), [500, 1]);
    assert.equal(chunks[1][0].partitionKey, "k-500");
  });

  it("splits at the 1 MiB byte cap, preserving order", () => {
    const big = "x".repeat(400 * 1024);
    const chunks = splitKinesisPutRecordsChunks(mk(3, big));
    assert.deepEqual(chunks.map((c) => c.length), [2, 1]);
    assert.equal(chunks[1][0].partitionKey, "k-2");
  });

  it("rejects a single record over the byte cap instead of truncating it", () => {
    assert.throws(
      () => splitKinesisPutRecordsChunks([{ data: "x".repeat(2 * 1024 * 1024), partitionKey: "k" }]),
      /byte batch cap/
    );
  });

  it("returns no chunks for an empty input", () => {
    assert.deepEqual(splitKinesisPutRecordsChunks([]), []);
  });
});

describe("kinesis-sink wire body and response parsing", () => {
  it("builds a PutRecords JSON body with base64 data and resolved keys", () => {
    const body = buildKinesisPutRecordsBody(testStream, [
      { data: '{"event":"order.created"}', partitionKey: "order-1" },
    ]);
    const parsed = JSON.parse(body) as {
      StreamName: string;
      Records: Array<{ Data: string; PartitionKey: string }>;
    };
    assert.equal(parsed.StreamName, testStream);
    assert.equal(parsed.Records.length, 1);
    assert.equal(Buffer.from(parsed.Records[0].Data, "base64").toString("utf8"), '{"event":"order.created"}');
    assert.equal(parsed.Records[0].PartitionKey, "order-1");
  });

  it("maps per-record failures with indices rebased onto the caller array", () => {
    const body = JSON.stringify({
      FailedRecordCount: 2,
      Records: [
        { SequenceNumber: "s0", ShardId: "shard-0" },
        { ErrorCode: "ProvisionedThroughputExceededException", ErrorMessage: "slow down" },
        { ErrorCode: "ValidationException", ErrorMessage: "bad key" },
      ],
    });
    const { failedRecords, accepted } = parseKinesisPutRecordsResponse(body, 500);
    assert.equal(accepted, 1);
    assert.deepEqual(
      failedRecords.map((f) => [f.index, f.errorCode, f.retryable]),
      [
        [501, "ProvisionedThroughputExceededException", true],
        [502, "ValidationException", false],
      ]
    );
    assert.equal(failedRecords[0].errorMessage, "slow down");
  });

  it("classifies throttling and internal failures retryable, other codes not", () => {
    assert.equal(classifyKinesisRecordFailure("ProvisionedThroughputExceededException"), true);
    assert.equal(classifyKinesisRecordFailure("InternalFailure"), true);
    assert.equal(classifyKinesisRecordFailure("ValidationException"), false);
    assert.equal(classifyKinesisRecordFailure("AccessDeniedException"), false);
  });

  it("rejects malformed PutRecords responses instead of reporting silent success", () => {
    assert.throws(() => parseKinesisPutRecordsResponse("not json", 0), KinesisSinkError);
    assert.throws(() => parseKinesisPutRecordsResponse(JSON.stringify({}), 0), /Records array/);
    assert.throws(
      () => parseKinesisPutRecordsResponse(JSON.stringify({ Records: [{ ErrorCode: 42 }] }), 0),
      /non-string ErrorCode/
    );
  });
});

describe("kinesis-sink live delivery", () => {
  it("sends a signed PutRecords request with the event key as partition key", async () => {
    const seen: SeenPost[] = [];
    const server = stubKinesis(seen, () => ({ status: 200, body: putRecordsOk(1) }));
    const port = await listen(server);
    try {
      const sink = new KinesisSink(baseConfig(`http://127.0.0.1:${port}/`));
      const record: KinesisRecord = { data: JSON.stringify({ event: "order.created" }), key: "order-9" };
      const result = await sink.putRecords([record]);
      assert.equal(result.ok, true);
      assert.equal(result.sent, 1);
      assert.deepEqual(result.failedRecords, []);
      assert.deepEqual(sink.stats, { sent: 1, failed: 0, sendFailures: 0 });
      assert.equal(seen.length, 1);
      const post = seen[0];
      assert.equal(post.method, "POST");
      assert.equal(post.headers["x-amz-target"], "Kinesis_20131202.PutRecords");
      assert.equal(post.headers["content-type"], "application/x-amz-json-1.1");
      const authorization = post.headers["authorization"];
      assert.ok(typeof authorization === "string");
      assert.ok(authorization.startsWith("AWS4-HMAC-SHA256 "));
      assert.ok(authorization.includes(`Credential=${testAccessKeyId}/`));
      assert.ok(authorization.includes(`/${testRegion}/kinesis/aws4_request`));
      assert.ok(authorization.includes("SignedHeaders=content-type;host;x-amz-date;x-amz-target"));
      // Independent check: re-sign the exact wire bytes at the exact
      // second the sink stamped, and the Authorization must match.
      const amzDate = post.headers["x-amz-date"];
      assert.ok(typeof amzDate === "string");
      const recomputed = signAwsSigV4({
        method: "POST",
        url: `http://127.0.0.1:${port}/`,
        body: Buffer.from(post.rawBody, "utf8"),
        credentials: { accessKeyId: testAccessKeyId, secretAccessKey: testKeyMaterial },
        region: testRegion,
        service: "kinesis",
        extraSignedHeaders: {
          "content-type": "application/x-amz-json-1.1",
          "x-amz-target": "Kinesis_20131202.PutRecords",
        },
        nowMs: amzDateToMs(amzDate),
      });
      assert.equal(authorization, recomputed.authorization);
      assert.equal(amzDate, recomputed.amzDate);
      const parsed = JSON.parse(post.rawBody) as {
        StreamName: string;
        Records: Array<{ Data: string; PartitionKey: string }>;
      };
      assert.equal(parsed.StreamName, testStream);
      assert.equal(Buffer.from(parsed.Records[0].Data, "base64").toString("utf8"), record.data);
      assert.equal(parsed.Records[0].PartitionKey, "order-9");
    } finally {
      server.close();
    }
  });

  it("splits 501 records into two PutRecords calls over the wire", async () => {
    const seen: SeenPost[] = [];
    const server = stubKinesis(seen, (all) => ({
      status: 200,
      body: putRecordsOk(all.length === 1 ? 500 : 1),
    }));
    const port = await listen(server);
    try {
      const sink = new KinesisSink(baseConfig(`http://127.0.0.1:${port}/`));
      const records: KinesisRecord[] = Array.from({ length: 501 }, (_, i) => ({
        data: "{}",
        key: `k-${i}`,
      }));
      const result = await sink.putRecords(records);
      assert.equal(result.sent, 501);
      assert.deepEqual(result.failedRecords, []);
      assert.equal(seen.length, 2);
      assert.equal(JSON.parse(seen[0].rawBody).Records.length, 500);
      assert.equal(JSON.parse(seen[1].rawBody).Records.length, 1);
    } finally {
      server.close();
    }
  });

  it("reports partial failures with their retry lane and counts them", async () => {
    const seen: SeenPost[] = [];
    const server = stubKinesis(seen, () => ({
      status: 200,
      body: JSON.stringify({
        FailedRecordCount: 1,
        Records: [
          { SequenceNumber: "s0", ShardId: "shard-0" },
          { ErrorCode: "ProvisionedThroughputExceededException", ErrorMessage: "slow down" },
        ],
      }),
    }));
    const port = await listen(server);
    try {
      const sink = new KinesisSink(baseConfig(`http://127.0.0.1:${port}/`));
      const result = await sink.putRecords([
        { data: "{}", key: "a" },
        { data: "{}", key: "b" },
      ]);
      assert.equal(result.sent, 1);
      assert.deepEqual(
        result.failedRecords.map((f) => [f.index, f.errorCode, f.retryable]),
        [[1, "ProvisionedThroughputExceededException", true]]
      );
      assert.deepEqual(sink.stats, { sent: 1, failed: 1, sendFailures: 0 });
      assert.equal(seen.length, 1);
    } finally {
      server.close();
    }
  });

  it("maps a 503 + Retry-After to retryable and a 400 to non_retryable", async () => {
    const seen: SeenPost[] = [];
    const server = stubKinesis(seen, (all) =>
      all.length === 1
        ? { status: 503, body: "{}", headers: { "retry-after": "2" } }
        : { status: 400, body: "{}" }
    );
    const port = await listen(server);
    try {
      const sink = new KinesisSink(baseConfig(`http://127.0.0.1:${port}/`));
      await assert.rejects(sink.putRecords([{ data: "{}", key: "a" }]), (err: unknown) => {
        assert.ok(err instanceof KinesisSinkError);
        assert.equal((err as KinesisSinkError).statusCode, 503);
        assert.equal((err as KinesisSinkError).retryAfterMs, 2000);
        assert.equal(classifyFailure(err).failureClass, "retryable");
        assert.equal(classifyFailure(err).retryAfterMs, 2000);
        return true;
      });
      await assert.rejects(sink.putRecords([{ data: "{}", key: "a" }]), (err: unknown) => {
        assert.ok(err instanceof KinesisSinkError);
        assert.equal((err as KinesisSinkError).statusCode, 400);
        assert.equal(classifyFailure(err).failureClass, "non_retryable");
        return true;
      });
      assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 2 });
    } finally {
      server.close();
    }
  });

  it("maps a missing secret to non_retryable without any network I/O", async () => {
    const seen: SeenPost[] = [];
    const server = stubKinesis(seen, () => ({ status: 200, body: putRecordsOk(1) }));
    const port = await listen(server);
    try {
      const sink = new KinesisSink(
        baseConfig(`http://127.0.0.1:${port}/`, { secretResolver: () => undefined })
      );
      await assert.rejects(sink.putRecords([{ data: "{}", key: "a" }]), (err: unknown) => {
        assert.ok(err instanceof KinesisSinkConfigError);
        assert.equal(classifyFailure(err).failureClass, "non_retryable");
        return true;
      });
      assert.equal(seen.length, 0);
    } finally {
      server.close();
    }
  });

  it("dryRun performs zero network I/O and changes no stats", async () => {
    const seen: SeenPost[] = [];
    const server = stubKinesis(seen, () => ({ status: 200, body: putRecordsOk(1) }));
    const port = await listen(server);
    try {
      const sink = new KinesisSink(baseConfig(`http://127.0.0.1:${port}/`, { dryRun: true }));
      const result = await sink.putRecords([{ data: "{}", key: "a" }]);
      assert.deepEqual(result, { ok: true, sent: 0, failedRecords: [], dryRun: true });
      assert.equal(seen.length, 0);
      assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    } finally {
      server.close();
    }
  });
});
