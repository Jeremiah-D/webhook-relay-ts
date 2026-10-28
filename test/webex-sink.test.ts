import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  WebexSink,
  WebexSinkConfigError,
  WebexSinkError,
  assertValidWebexSinkConfig,
  buildWebexMessageBody,
  classifyWebexRecordFailure,
  resolveWebexNotification,
  resolveWebexRecord,
  resolveWebexContent,
  truncateWebexPayload,
  WEBEX_DEFAULT_PAYLOAD_MAX_CHARS,
  WEBEX_FALLBACK_SUMMARY,
  WEBEX_MESSAGES_URL,
  type WebexMessageClient,
  type WebexMessagePostRequest,
  type WebexMessagePostResponse,
  type WebexSinkConfig,
} from "../src/webex-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements WebexMessageClient {
  posts: WebexMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: WebexMessagePostRequest): Promise<WebexMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200 };
  }
}

const roomId = "Y2lzY29zcGFyL2Nfc2Vzc2lvbjpjY2NjY2NjYy00MDAw";

function baseConfig(
  client: WebexMessageClient,
  extra: Partial<WebexSinkConfig> = {}
): WebexSinkConfig {
  return { roomId, client, ...extra };
}

describe("webex-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidWebexSinkConfig(null, "WebexSink"), RangeError);
    assert.throws(() => assertValidWebexSinkConfig("x", "WebexSink"), RangeError);
  });

  it("rejects a malformed room id shape", () => {
    assert.throws(
      () => assertValidWebexSinkConfig({ roomId: "" }, "WebexSink"),
      RangeError
    );
    assert.throws(
      () => assertValidWebexSinkConfig({ roomId: "has space" }, "WebexSink"),
      RangeError
    );
  });

  it("rejects a client without a post function", () => {
    assert.throws(
      () => assertValidWebexSinkConfig({ client: {} }, "WebexSink"),
      RangeError
    );
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(
      () => assertValidWebexSinkConfig({ payloadMaxChars: 0 }, "WebexSink"),
      RangeError
    );
    assert.throws(
      () => assertValidWebexSinkConfig({ payloadMaxChars: 2.5 }, "WebexSink"),
      RangeError
    );
  });

  it("accepts a config with no room yet (send-time config error)", () => {
    assert.doesNotThrow(() => new WebexSink({}));
  });
});

describe("webex-sink content derivation", () => {
  it("prefers subject, then key, then traceId, then the fallback summary", () => {
    assert.equal(
      resolveWebexContent({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveWebexContent({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveWebexContent({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveWebexContent({ body: "{}" }), WEBEX_FALLBACK_SUMMARY);
    assert.equal(
      resolveWebexContent({ body: "{}", subject: "", key: "", traceId: "" }),
      WEBEX_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateWebexPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateWebexPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveWebexNotification(record, {}), { text: "order.created" });
    assert.deepEqual(resolveWebexNotification(record, { includePayload: true }), {
      text: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveWebexNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { text: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveWebexRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("webex-sink wire shape", () => {
  it("targets the fixed messages endpoint", () => {
    assert.equal(WEBEX_MESSAGES_URL, "https://webexapis.com/v1/messages");
  });

  it("builds the JSON body with roomId and text in order, no credential", () => {
    assert.equal(
      buildWebexMessageBody(roomId, "order.created"),
      JSON.stringify({ roomId, text: "order.created" })
    );
    assert.equal(
      buildWebexMessageBody(roomId, 'a"b\nc'),
      JSON.stringify({ roomId, text: 'a"b\nc' })
    );
  });
});

describe("webex-sink send", () => {
  it("posts one message per record with the room id and JSON body, no credential", async () => {
    const client = new FakeClient();
    const sink = new WebexSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    assert.deepEqual(client.posts[0], {
      roomId,
      body: JSON.stringify({ roomId, text: "order.created" }),
    });
    assert.deepEqual(client.posts[1].body, JSON.stringify({ roomId, text: "agg-8" }));
    // The request carries no credential anywhere: the bot
    // token is held by the client alone.
    for (const post of client.posts) {
      assert.equal("token" in post, false);
      assert.equal(post.body.includes("Bearer"), false);
    }
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new WebexSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof WebexSinkError);
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
    const sink = new WebexSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof WebexSinkError);
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

  it("fails closed without a client or room", async () => {
    await assert.rejects(
      () => new WebexSink({ roomId }).send([{ body: '{"a":1}' }]),
      WebexSinkConfigError
    );
    await assert.rejects(
      () => new WebexSink(baseConfig(new FakeClient(), { roomId: undefined })).send([{ body: '{"a":1}' }]),
      WebexSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new WebexSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new WebexSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new WebexSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyWebexRecordFailure(429), true);
    assert.equal(classifyWebexRecordFailure(500), true);
    assert.equal(classifyWebexRecordFailure(503), true);
    assert.equal(classifyWebexRecordFailure(400), false);
    assert.equal(classifyWebexRecordFailure(401), false);
    assert.equal(classifyWebexRecordFailure(404), false);
    assert.equal(WEBEX_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
