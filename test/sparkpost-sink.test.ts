import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  SparkPostSink,
  SparkPostSinkConfigError,
  SparkPostSinkError,
  assertValidSparkPostSinkConfig,
  buildSparkPostMessageBody,
  classifySparkPostRecordFailure,
  resolveSparkPostNotification,
  resolveSparkPostRecord,
  resolveSparkPostSubject,
  resolveSparkPostText,
  truncateSparkPostPayload,
  SPARKPOST_DEFAULT_PAYLOAD_MAX_CHARS,
  SPARKPOST_FALLBACK_SUMMARY,
  SPARKPOST_TRANSMISSIONS_URL,
  type SparkPostMessageClient,
  type SparkPostMessagePostRequest,
  type SparkPostMessagePostResponse,
  type SparkPostSinkConfig,
} from "../src/sparkpost-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements SparkPostMessageClient {
  posts: SparkPostMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: SparkPostMessagePostRequest): Promise<SparkPostMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200 };
  }
}

const from = "alerts@example.com";
const to = "ops@example.com";

function baseConfig(
  client: SparkPostMessageClient,
  extra: Partial<SparkPostSinkConfig> = {}
): SparkPostSinkConfig {
  return { from, to, client, ...extra };
}

describe("sparkpost-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidSparkPostSinkConfig(null, "SparkPostSink"), RangeError);
    assert.throws(() => assertValidSparkPostSinkConfig("x", "SparkPostSink"), RangeError);
  });

  it("rejects a malformed sender or recipient shape", () => {
    assert.throws(() => assertValidSparkPostSinkConfig({ from: "" }, "SparkPostSink"), RangeError);
    assert.throws(() => assertValidSparkPostSinkConfig({ from: "has space" }, "SparkPostSink"), RangeError);
    assert.throws(() => assertValidSparkPostSinkConfig({ to: "" }, "SparkPostSink"), RangeError);
    assert.throws(() => assertValidSparkPostSinkConfig({ to: "has space" }, "SparkPostSink"), RangeError);
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidSparkPostSinkConfig({ client: {} }, "SparkPostSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidSparkPostSinkConfig({ payloadMaxChars: 0 }, "SparkPostSink"), RangeError);
    assert.throws(() => assertValidSparkPostSinkConfig({ payloadMaxChars: 2.5 }, "SparkPostSink"), RangeError);
  });

  it("accepts a config with no sender or recipient yet (send-time config error)", () => {
    assert.doesNotThrow(() => new SparkPostSink({}));
  });
});

describe("sparkpost-sink text derivation", () => {
  it("derives the subject from subject, then key, then the fallback — never the trace id", () => {
    assert.equal(
      resolveSparkPostSubject({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveSparkPostSubject({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveSparkPostSubject({ body: "{}", traceId: "t-1" }), SPARKPOST_FALLBACK_SUMMARY);
    assert.equal(resolveSparkPostSubject({ body: "{}" }), SPARKPOST_FALLBACK_SUMMARY);
  });

  it("derives the text from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveSparkPostText({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveSparkPostText({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveSparkPostText({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveSparkPostText({ body: "{}" }), SPARKPOST_FALLBACK_SUMMARY);
    assert.equal(
      resolveSparkPostText({ body: "{}", subject: "", key: "", traceId: "" }),
      SPARKPOST_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateSparkPostPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateSparkPostPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveSparkPostNotification(record, {}), {
      subject: "order.created",
      text: "order.created",
    });
    assert.deepEqual(resolveSparkPostNotification(record, { includePayload: true }), {
      subject: "order.created",
      text: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveSparkPostNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { subject: "order.created", text: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveSparkPostRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("sparkpost-sink wire shape", () => {
  it("posts to the fixed SparkPost Transmissions endpoint", () => {
    assert.equal(SPARKPOST_TRANSMISSIONS_URL, "https://api.sparkpost.com/api/v1/transmissions");
  });

  it("builds the JSON body with recipients array and nested content — and no credential", () => {
    assert.equal(
      buildSparkPostMessageBody(from, to, "order.created", "order.created"),
      JSON.stringify({ recipients: [{ address: to }], content: { from, subject: "order.created", text: "order.created" } })
    );
    // The API key never appears in the body: the client alone
    // holds it and sends it bare in the Authorization header.
    assert.equal(buildSparkPostMessageBody(from, to, "x", "y").includes("Bearer"), false);
    assert.equal(buildSparkPostMessageBody(from, to, "x", "y").includes("api_key"), false);
    assert.equal(buildSparkPostMessageBody(from, to, "x", "y").includes("api_key"), false);
  });
});

describe("sparkpost-sink send", () => {
  it("posts one message per record to the fixed endpoint with the envelope and text, no credential", async () => {
    const client = new FakeClient();
    const sink = new SparkPostSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: SPARKPOST_TRANSMISSIONS_URL,
      body: JSON.stringify({ recipients: [{ address: to }], content: { from, subject: "order.created", text: "order.created" } }),
    });
    assert.deepEqual(JSON.parse(client.posts[1].body).content.subject, "agg-8");
    // A trace-id-only record gets the fallback subject but the
    // trace id as its text.
    assert.deepEqual(JSON.parse(client.posts[2].body).content.subject, SPARKPOST_FALLBACK_SUMMARY);
    assert.deepEqual(JSON.parse(client.posts[2].body).content.text, "t-9");
    // The request carries no credential anywhere: the API key
    // is held by the client alone.
    for (const post of client.posts) {
      assert.equal(post.body.includes("Bearer"), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new SparkPostSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof SparkPostSinkError);
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
    const sink = new SparkPostSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof SparkPostSinkError);
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

  it("fails closed without a client, sender, or recipient", async () => {
    await assert.rejects(
      () => new SparkPostSink({ from, to }).send([{ body: '{"a":1}' }]),
      SparkPostSinkConfigError
    );
    await assert.rejects(
      () => new SparkPostSink(baseConfig(new FakeClient(), { from: undefined })).send([{ body: '{"a":1}' }]),
      SparkPostSinkConfigError
    );
    await assert.rejects(
      () => new SparkPostSink(baseConfig(new FakeClient(), { to: undefined })).send([{ body: '{"a":1}' }]),
      SparkPostSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new SparkPostSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new SparkPostSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new SparkPostSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifySparkPostRecordFailure(429), true);
    assert.equal(classifySparkPostRecordFailure(500), true);
    assert.equal(classifySparkPostRecordFailure(503), true);
    assert.equal(classifySparkPostRecordFailure(400), false);
    assert.equal(classifySparkPostRecordFailure(401), false);
    assert.equal(classifySparkPostRecordFailure(404), false);
    assert.equal(SPARKPOST_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
