import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  FcmSink,
  FcmSinkConfigError,
  FcmSinkError,
  assertValidFcmSinkConfig,
  buildFcmMessageBody,
  buildFcmSendUrl,
  classifyFcmRecordFailure,
  resolveFcmBody,
  resolveFcmNotification,
  resolveFcmRecord,
  truncateFcmPayload,
  FCM_SEND_URL_PREFIX,
  FCM_SEND_URL_SUFFIX,
  FCM_DEFAULT_PAYLOAD_MAX_CHARS,
  FCM_FALLBACK_SUMMARY,
  type FcmMessageClient,
  type FcmMessagePostRequest,
  type FcmMessagePostResponse,
  type FcmSinkConfig,
} from "../src/fcm-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements FcmMessageClient {
  posts: FcmMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: FcmMessagePostRequest): Promise<FcmMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200 };
  }
}

const project = "my-project";
const token = "device-token-abc";
const sendUrl = "https://fcm.googleapis.com/v1/projects/my-project/messages:send";

function baseConfig(
  client: FcmMessageClient,
  extra: Partial<FcmSinkConfig> = {}
): FcmSinkConfig {
  return { project, token, client, ...extra };
}

describe("fcm-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidFcmSinkConfig(null, "FcmSink"), RangeError);
    assert.throws(() => assertValidFcmSinkConfig("x", "FcmSink"), RangeError);
  });

  it("rejects a malformed project id shape", () => {
    assert.throws(() => assertValidFcmSinkConfig({ project: "" }, "FcmSink"), RangeError);
    assert.throws(
      () => assertValidFcmSinkConfig({ project: "has space" }, "FcmSink"),
      RangeError
    );
    assert.throws(() => assertValidFcmSinkConfig({ project: 42 }, "FcmSink"), RangeError);
  });

  it("rejects a malformed device token shape", () => {
    assert.throws(() => assertValidFcmSinkConfig({ token: "" }, "FcmSink"), RangeError);
    assert.throws(
      () => assertValidFcmSinkConfig({ token: "has space" }, "FcmSink"),
      RangeError
    );
    assert.throws(() => assertValidFcmSinkConfig({ token: 42 }, "FcmSink"), RangeError);
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidFcmSinkConfig({ client: {} }, "FcmSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidFcmSinkConfig({ payloadMaxChars: 0 }, "FcmSink"), RangeError);
    assert.throws(
      () => assertValidFcmSinkConfig({ payloadMaxChars: 2.5 }, "FcmSink"),
      RangeError
    );
  });

  it("accepts a config with no project or token yet (send-time config error)", () => {
    assert.doesNotThrow(() => new FcmSink({}));
  });
});

describe("fcm-sink notification derivation", () => {
  it("derives body from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveFcmBody({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveFcmBody({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveFcmBody({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveFcmBody({ body: "{}" }), FCM_FALLBACK_SUMMARY);
    assert.equal(
      resolveFcmBody({ body: "{}", subject: "", key: "", traceId: "" }),
      FCM_FALLBACK_SUMMARY
    );
  });

  it("splits subject into title and body, key-only events carry body alone", () => {
    assert.deepEqual(resolveFcmNotification({ body: "{}", subject: "order.created" }), {
      title: "order.created",
      body: "order.created",
    });
    assert.deepEqual(resolveFcmNotification({ body: "{}", key: "agg-7" }), {
      body: "agg-7",
    });
    assert.deepEqual(resolveFcmNotification({ body: "{}" }), {
      body: FCM_FALLBACK_SUMMARY,
    });
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateFcmPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateFcmPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveFcmRecord({ body: "" }, 2),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("fcm-sink wire shape", () => {
  it("exposes the fixed FCM HTTP v1 send endpoint for a project", () => {
    assert.equal(buildFcmSendUrl("my-project"), sendUrl);
    assert.equal(
      FCM_SEND_URL_PREFIX,
      "https://fcm.googleapis.com/v1/projects/"
    );
    assert.equal(FCM_SEND_URL_SUFFIX, "/messages:send");
  });

  it("builds the message envelope with token, notification, and no credential", () => {
    assert.equal(
      buildFcmMessageBody(token, { title: "order.created", body: "order.created" }, {}),
      JSON.stringify({
        message: {
          token,
          notification: { title: "order.created", body: "order.created" },
        },
      })
    );
    assert.equal(
      buildFcmMessageBody(token, { body: "agg-7" }, {}),
      JSON.stringify({
        message: {
          token,
          notification: { body: "agg-7" },
        },
      })
    );
    const body = buildFcmMessageBody(token, { title: "x", body: "x" }, {});
    assert.equal(body.includes("Bearer"), false);
    assert.equal(body.includes("Authorization"), false);
    assert.equal(body.includes("access_token"), false);
    assert.equal(body.includes("server_key"), false);
    assert.deepEqual(Object.keys(JSON.parse(body)), ["message"]);
    assert.deepEqual(Object.keys(JSON.parse(body).message), ["token", "notification"]);
  });

  it("appends the payload as data.payload only on opt-in, truncated", () => {
    assert.equal(
      buildFcmMessageBody(
        token,
        { title: "order.created", body: "order.created" },
        { includePayload: true },
        '{"a":1}'
      ),
      JSON.stringify({
        message: {
          token,
          notification: { title: "order.created", body: "order.created" },
          data: { payload: '{"a":1}' },
        },
      })
    );
    const long = "x".repeat(2005);
    assert.equal(
      JSON.parse(
        buildFcmMessageBody(
          token,
          { body: "order.created" },
          { includePayload: true, payloadMaxChars: 3 },
          long
        )
      ).message.data.payload,
      "xxx… (truncated)"
    );
    // Without the opt-in, no data field at all — the notification stays summary-only.
    assert.equal(
      JSON.parse(buildFcmMessageBody(token, { body: "order.created" }, {}, long)).message
        .data,
      undefined
    );
  });
});

describe("fcm-sink send", () => {
  it("posts one message per record to the fixed project endpoint with the envelope, no credential", async () => {
    const client = new FakeClient();
    const sink = new FcmSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: sendUrl,
      body: JSON.stringify({
        message: {
          token,
          notification: { title: "order.created", body: "order.created" },
        },
      }),
    });
    assert.deepEqual(JSON.parse(client.posts[1].body), {
      message: { token, notification: { body: "agg-8" } },
    });
    assert.deepEqual(JSON.parse(client.posts[2].body).message.notification, { body: "t-9" });
    for (const post of client.posts) {
      assert.equal(post.url, sendUrl);
      assert.equal(post.body.includes("Authorization"), false);
      assert.equal(post.body.includes("Bearer"), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("applies the payload opt-in truncation on send", async () => {
    const client = new FakeClient();
    const sink = new FcmSink(baseConfig(client, { includePayload: true, payloadMaxChars: 3 }));
    await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.equal(
      JSON.parse(client.posts[0].body).message.data.payload,
      `{"a… (truncated)`
    );
    assert.equal(
      JSON.parse(client.posts[0].body).message.notification.body,
      "order.created"
    );
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new FcmSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof FcmSinkError);
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

  it("maps a codeless transport failure to retryable with the client message", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 200);
    client.failOn.set(1, new Error("socket hangup"));
    const sink = new FcmSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof FcmSinkError);
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

  it("fails closed without a client, project, or device token", async () => {
    await assert.rejects(
      () => new FcmSink({ project, token }).send([{ body: '{"a":1}' }]),
      FcmSinkConfigError
    );
    await assert.rejects(
      () =>
        new FcmSink(baseConfig(new FakeClient(), { project: undefined })).send([
          { body: '{"a":1}' },
        ]),
      FcmSinkConfigError
    );
    await assert.rejects(
      () =>
        new FcmSink(baseConfig(new FakeClient(), { token: undefined })).send([
          { body: '{"a":1}' },
        ]),
      FcmSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new FcmSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new FcmSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new FcmSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyFcmRecordFailure(429), true);
    assert.equal(classifyFcmRecordFailure(500), true);
    assert.equal(classifyFcmRecordFailure(503), true);
    assert.equal(classifyFcmRecordFailure(400), false);
    assert.equal(classifyFcmRecordFailure(401), false);
    assert.equal(classifyFcmRecordFailure(404), false);
    assert.equal(FCM_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
