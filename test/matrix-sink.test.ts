import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  MatrixSink,
  MatrixSinkConfigError,
  MatrixSinkError,
  assertValidMatrixSinkConfig,
  classifyMatrixRecordFailure,
  normalizeMatrixHomeserver,
  resolveMatrixNotification,
  resolveMatrixRecord,
  resolveMatrixText,
  truncateMatrixPayload,
  MATRIX_DEFAULT_PAYLOAD_MAX_CHARS,
  MATRIX_FALLBACK_SUMMARY,
  MATRIX_MESSAGE_TYPE,
  type MatrixMessageClient,
  type MatrixMessagePostRequest,
  type MatrixMessagePostResponse,
  type MatrixSinkConfig,
} from "../src/matrix-sink.ts";
import { classifyFailure } from "../src/failure.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements MatrixMessageClient {
  posts: MatrixMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: MatrixMessagePostRequest): Promise<MatrixMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200 };
  }
}

const homeserver = "https://matrix.example.org";
const roomId = "!roomid:matrix.example.org";

function baseConfig(
  client: MatrixMessageClient,
  extra: Partial<MatrixSinkConfig> = {}
): MatrixSinkConfig {
  return { homeserver, roomId, client, ...extra };
}

describe("matrix-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidMatrixSinkConfig(null, "MatrixSink"), RangeError);
    assert.throws(() => assertValidMatrixSinkConfig("x", "MatrixSink"), RangeError);
  });

  it("rejects a malformed homeserver or room id shape", () => {
    assert.throws(
      () => assertValidMatrixSinkConfig({ homeserver: "" }, "MatrixSink"),
      RangeError
    );
    assert.throws(
      () => assertValidMatrixSinkConfig({ homeserver: "https://a b.example" }, "MatrixSink"),
      RangeError
    );
    assert.throws(
      () => assertValidMatrixSinkConfig({ roomId: "" }, "MatrixSink"),
      RangeError
    );
    assert.throws(
      () => assertValidMatrixSinkConfig({ roomId: "room\nid" }, "MatrixSink"),
      RangeError
    );
  });

  it("rejects a client without a post function", () => {
    assert.throws(
      () => assertValidMatrixSinkConfig({ client: {} }, "MatrixSink"),
      RangeError
    );
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(
      () => assertValidMatrixSinkConfig({ payloadMaxChars: 0 }, "MatrixSink"),
      RangeError
    );
    assert.throws(
      () => assertValidMatrixSinkConfig({ payloadMaxChars: 1.5 }, "MatrixSink"),
      RangeError
    );
  });

  it("accepts a config with no homeserver or room id yet (send-time config error)", () => {
    assert.doesNotThrow(() => new MatrixSink({}));
  });
});

describe("matrix-sink text derivation", () => {
  it("prefers subject, then key, then traceId, then the fallback summary", () => {
    assert.equal(
      resolveMatrixText({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveMatrixText({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveMatrixText({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveMatrixText({ body: "{}" }), MATRIX_FALLBACK_SUMMARY);
    assert.equal(
      resolveMatrixText({ body: "{}", subject: "", key: "", traceId: "" }),
      MATRIX_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateMatrixPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    const cut = truncateMatrixPayload(long, 2000);
    assert.equal(cut, `${"x".repeat(2000)}… (truncated)`);
    assert.equal(truncateMatrixPayload(long, 10), `${"x".repeat(10)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveMatrixNotification(record, {}), { text: "order.created" });
    assert.deepEqual(resolveMatrixNotification(record, { includePayload: true }), {
      text: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveMatrixNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { text: "order.created\n\n{\"a… (truncated)" }
    );
  });

  it("rejects an empty record body and serializes msgtype m.text", () => {
    assert.throws(
      () => resolveMatrixRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
    const resolved = resolveMatrixRecord(
      { body: '{"a":1}', subject: "order.created" },
      0,
      {}
    );
    assert.deepEqual(JSON.parse(resolved.body), {
      msgtype: MATRIX_MESSAGE_TYPE,
      body: "order.created",
    });
  });
});

describe("matrix-sink homeserver normalization", () => {
  it("strips trailing slashes so client path concatenation cannot double one", () => {
    assert.equal(normalizeMatrixHomeserver("https://matrix.example.org/"), "https://matrix.example.org");
    assert.equal(normalizeMatrixHomeserver("https://matrix.example.org///"), "https://matrix.example.org");
    assert.equal(normalizeMatrixHomeserver("https://matrix.example.org"), "https://matrix.example.org");
  });
});

describe("matrix-sink send", () => {
  it("posts one message per record with the room and serialized body, no credential", async () => {
    const client = new FakeClient();
    const sink = new MatrixSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    assert.deepEqual(client.posts[0], {
      homeserver,
      roomId,
      body: JSON.stringify({ msgtype: "m.text", body: "order.created" }),
    });
    assert.deepEqual(client.posts[1], {
      homeserver,
      roomId,
      body: JSON.stringify({ msgtype: "m.text", body: "agg-8" }),
    });
    // The request carries no credential anywhere: the access token is
    // held by the client alone, and no txnId is generated by the sink.
    for (const post of client.posts) {
      assert.equal("token" in post, false);
      assert.equal("txnId" in post, false);
    }
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new MatrixSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([
          { body: '{"a":1}' },
          { body: '{"b":2}' },
          { body: '{"c":3}' },
        ]),
      (err: unknown) => {
        assert.ok(err instanceof MatrixSinkError);
        assert.equal(err.failedRecords.length, 3);
        assert.deepEqual(
          err.failedRecords.map((r) => [r.index, r.errorCode, r.retryable]),
          [
            [0, "HTTP_429", true],
            [1, "HTTP_503", true],
            [2, "HTTP_400", false],
          ]
        );
        return true;
      }
    );
    assert.deepEqual(sink.stats, { sent: 0, failed: 3, sendFailures: 1 });
  });

  it("maps a client throw to a retryable transport failure and keeps partial success out", async () => {
    const client = new FakeClient();
    client.failOn.set(1, new Error("socket hangup"));
    const sink = new MatrixSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof MatrixSinkError);
        assert.equal(err.failedRecords.length, 1);
        assert.equal(err.failedRecords[0].index, 1);
        assert.equal(err.failedRecords[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(err.failedRecords[0].errorMessage, "socket hangup");
        assert.equal(err.failedRecords[0].retryable, true);
        return true;
      }
    );
    assert.deepEqual(sink.stats, { sent: 1, failed: 1, sendFailures: 1 });
  });

  it("fails closed without a client, homeserver, or room id", async () => {
    await assert.rejects(
      () => new MatrixSink({ homeserver, roomId }).send([{ body: '{"a":1}' }]),
      MatrixSinkConfigError
    );
    await assert.rejects(
      () => new MatrixSink(baseConfig(new FakeClient(), { homeserver: undefined })).send([{ body: '{"a":1}' }]),
      MatrixSinkConfigError
    );
    await assert.rejects(
      () => new MatrixSink(baseConfig(new FakeClient(), { roomId: undefined })).send([{ body: '{"a":1}' }]),
      MatrixSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new MatrixSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new MatrixSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new MatrixSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyMatrixRecordFailure(429), true);
    assert.equal(classifyMatrixRecordFailure(500), true);
    assert.equal(classifyMatrixRecordFailure(503), true);
    assert.equal(classifyMatrixRecordFailure(400), false);
    assert.equal(classifyMatrixRecordFailure(401), false);
    assert.equal(classifyMatrixRecordFailure(404), false);
    assert.equal(MATRIX_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
