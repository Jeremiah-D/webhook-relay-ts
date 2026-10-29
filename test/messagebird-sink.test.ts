import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  MessageBirdSink,
  MessageBirdSinkConfigError,
  MessageBirdSinkError,
  assertValidMessageBirdSinkConfig,
  buildMessageBirdMessageBody,
  classifyMessageBirdRecordFailure,
  resolveMessageBirdBody,
  resolveMessageBirdNotification,
  resolveMessageBirdRecord,
  truncateMessageBirdPayload,
  MESSAGEBIRD_DEFAULT_PAYLOAD_MAX_CHARS,
  MESSAGEBIRD_FALLBACK_SUMMARY,
  MESSAGEBIRD_MESSAGES_URL,
  type MessageBirdMessageClient,
  type MessageBirdMessagePostRequest,
  type MessageBirdMessagePostResponse,
  type MessageBirdSinkConfig,
} from "../src/messagebird-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements MessageBirdMessageClient {
  posts: MessageBirdMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: MessageBirdMessagePostRequest): Promise<MessageBirdMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 201 };
  }
}

const originator = "RelayAlert";
const recipient = "+14155550101";

function baseConfig(
  client: MessageBirdMessageClient,
  extra: Partial<MessageBirdSinkConfig> = {}
): MessageBirdSinkConfig {
  return { originator, recipient, client, ...extra };
}

describe("messagebird-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidMessageBirdSinkConfig(null, "MessageBirdSink"), RangeError);
    assert.throws(() => assertValidMessageBirdSinkConfig("x", "MessageBirdSink"), RangeError);
  });

  it("rejects a malformed originator or recipient shape", () => {
    assert.throws(() => assertValidMessageBirdSinkConfig({ originator: "" }, "MessageBirdSink"), RangeError);
    assert.throws(() => assertValidMessageBirdSinkConfig({ originator: "has space" }, "MessageBirdSink"), RangeError);
    assert.throws(() => assertValidMessageBirdSinkConfig({ recipient: "" }, "MessageBirdSink"), RangeError);
    assert.throws(() => assertValidMessageBirdSinkConfig({ recipient: "has space" }, "MessageBirdSink"), RangeError);
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidMessageBirdSinkConfig({ client: {} }, "MessageBirdSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidMessageBirdSinkConfig({ payloadMaxChars: 0 }, "MessageBirdSink"), RangeError);
    assert.throws(() => assertValidMessageBirdSinkConfig({ payloadMaxChars: 2.5 }, "MessageBirdSink"), RangeError);
  });

  it("accepts a config with no originator or recipient yet (send-time config error)", () => {
    assert.doesNotThrow(() => new MessageBirdSink({}));
  });
});

describe("messagebird-sink body derivation", () => {
  it("derives the body from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveMessageBirdBody({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveMessageBirdBody({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveMessageBirdBody({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveMessageBirdBody({ body: "{}" }), MESSAGEBIRD_FALLBACK_SUMMARY);
    assert.equal(
      resolveMessageBirdBody({ body: "{}", subject: "", key: "", traceId: "" }),
      MESSAGEBIRD_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateMessageBirdPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateMessageBirdPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveMessageBirdNotification(record, {}), { body: "order.created" });
    assert.deepEqual(resolveMessageBirdNotification(record, { includePayload: true }), {
      body: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveMessageBirdNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { body: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveMessageBirdRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("messagebird-sink wire shape", () => {
  it("uses the fixed Messages endpoint", () => {
    assert.equal(MESSAGEBIRD_MESSAGES_URL, "https://rest.messagebird.com/messages");
  });

  it("builds the JSON body with originator, recipients array, and body — and no credential", () => {
    assert.equal(
      buildMessageBirdMessageBody(originator, recipient, "order.created"),
      JSON.stringify({ originator, recipients: [recipient], body: "order.created" })
    );
    assert.equal(buildMessageBirdMessageBody(originator, recipient, "x").includes("AccessKey"), false);
    assert.equal(buildMessageBirdMessageBody(originator, recipient, "x").includes("api_key"), false);
  });
});

describe("messagebird-sink send", () => {
  it("posts one message per record to the fixed endpoint with the JSON body, no credential", async () => {
    const client = new FakeClient();
    const sink = new MessageBirdSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: "https://rest.messagebird.com/messages",
      body: JSON.stringify({ originator, recipients: [recipient], body: "order.created" }),
    });
    assert.deepEqual(JSON.parse(client.posts[1].body).body, "agg-8");
    assert.deepEqual(JSON.parse(client.posts[2].body).body, "t-9");
    for (const post of client.posts) {
      assert.equal(post.body.includes("AccessKey"), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new MessageBirdSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof MessageBirdSinkError);
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
    const sink = new MessageBirdSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof MessageBirdSinkError);
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

  it("fails closed without a client, originator, or recipient", async () => {
    await assert.rejects(
      () => new MessageBirdSink({ originator, recipient }).send([{ body: '{"a":1}' }]),
      MessageBirdSinkConfigError
    );
    await assert.rejects(
      () => new MessageBirdSink(baseConfig(new FakeClient(), { originator: undefined })).send([{ body: '{"a":1}' }]),
      MessageBirdSinkConfigError
    );
    await assert.rejects(
      () => new MessageBirdSink(baseConfig(new FakeClient(), { recipient: undefined })).send([{ body: '{"a":1}' }]),
      MessageBirdSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new MessageBirdSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new MessageBirdSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new MessageBirdSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyMessageBirdRecordFailure(429), true);
    assert.equal(classifyMessageBirdRecordFailure(500), true);
    assert.equal(classifyMessageBirdRecordFailure(503), true);
    assert.equal(classifyMessageBirdRecordFailure(400), false);
    assert.equal(classifyMessageBirdRecordFailure(401), false);
    assert.equal(classifyMessageBirdRecordFailure(404), false);
    assert.equal(MESSAGEBIRD_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
