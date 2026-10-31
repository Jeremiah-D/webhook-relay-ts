import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  PushwooshSink,
  PushwooshSinkConfigError,
  PushwooshSinkError,
  assertValidPushwooshSinkConfig,
  buildPushwooshMessageBody,
  buildPushwooshNotification,
  classifyPushwooshRecordFailure,
  pushwooshVerdictToFailedRecord,
  resolvePushwooshContent,
  resolvePushwooshRecord,
  truncatePushwooshPayload,
  PUSHWOOSH_CREATE_MESSAGE_URL,
  PUSHWOOSH_DEFAULT_PAYLOAD_MAX_CHARS,
  PUSHWOOSH_FALLBACK_SUMMARY,
  type PushwooshMessageClient,
  type PushwooshMessagePostRequest,
  type PushwooshMessagePostResponse,
  type PushwooshSinkConfig,
} from "../src/pushwoosh-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status and verdict per call. */
class FakeClient implements PushwooshMessageClient {
  posts: PushwooshMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  /** Call-count (0-based) → verdict to return for that post. */
  verdictOn = new Map<number, { statusCode?: number; statusMessage?: string; messageIds?: string[] }>();
  async post(request: PushwooshMessagePostRequest): Promise<PushwooshMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    const verdict = this.verdictOn.get(n);
    return verdict === undefined
      ? { status: this.statusOn.get(n) ?? 200, statusCode: 200, statusMessage: "OK", messageIds: [`msg-${n}`] }
      : { status: this.statusOn.get(n) ?? 200, ...verdict };
  }
}

const application = "XXXXX-XXXXX";
const auth = "pushwoosh-api-token-123";

function baseConfig(
  client: PushwooshMessageClient,
  extra: Partial<PushwooshSinkConfig> = {}
): PushwooshSinkConfig {
  return { application, auth, client, ...extra };
}

describe("pushwoosh-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidPushwooshSinkConfig(null, "PushwooshSink"), RangeError);
    assert.throws(() => assertValidPushwooshSinkConfig("x", "PushwooshSink"), RangeError);
  });

  it("rejects a malformed application code shape", () => {
    assert.throws(() => assertValidPushwooshSinkConfig({ application: "" }, "PushwooshSink"), RangeError);
    assert.throws(
      () => assertValidPushwooshSinkConfig({ application: "has space" }, "PushwooshSink"),
      RangeError
    );
    assert.throws(() => assertValidPushwooshSinkConfig({ application: 42 }, "PushwooshSink"), RangeError);
  });

  it("rejects a malformed API token shape", () => {
    assert.throws(() => assertValidPushwooshSinkConfig({ auth: "" }, "PushwooshSink"), RangeError);
    assert.throws(
      () => assertValidPushwooshSinkConfig({ auth: "has space" }, "PushwooshSink"),
      RangeError
    );
    assert.throws(() => assertValidPushwooshSinkConfig({ auth: 42 }, "PushwooshSink"), RangeError);
  });

  it("rejects malformed devices / conditions targeting", () => {
    assert.throws(
      () => assertValidPushwooshSinkConfig({ devices: "not-an-array" }, "PushwooshSink"),
      RangeError
    );
    assert.throws(
      () => assertValidPushwooshSinkConfig({ devices: [""] }, "PushwooshSink"),
      RangeError
    );
    assert.throws(
      () => assertValidPushwooshSinkConfig({ devices: ["has space"] }, "PushwooshSink"),
      RangeError
    );
    assert.throws(
      () => assertValidPushwooshSinkConfig({ conditions: "not-an-array" }, "PushwooshSink"),
      RangeError
    );
    assert.doesNotThrow(() =>
      assertValidPushwooshSinkConfig(
        { devices: ["hwid_1"], conditions: [["Country", "EQ", "fr"]] },
        "PushwooshSink"
      )
    );
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidPushwooshSinkConfig({ client: {} }, "PushwooshSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidPushwooshSinkConfig({ payloadMaxChars: 0 }, "PushwooshSink"), RangeError);
    assert.throws(
      () => assertValidPushwooshSinkConfig({ payloadMaxChars: 2.5 }, "PushwooshSink"),
      RangeError
    );
  });

  it("accepts a config with no credentials yet (send-time config error)", () => {
    assert.doesNotThrow(() => new PushwooshSink({}));
  });
});

describe("pushwoosh-sink content derivation", () => {
  it("derives the content from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolvePushwooshContent({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolvePushwooshContent({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolvePushwooshContent({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolvePushwooshContent({ body: "{}" }), PUSHWOOSH_FALLBACK_SUMMARY);
    assert.equal(
      resolvePushwooshContent({ body: "{}", subject: "", key: "", traceId: "" }),
      PUSHWOOSH_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncatePushwooshPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncatePushwooshPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("builds a notification with send_date now and the derived content, no targeting by default", () => {
    assert.deepEqual(
      buildPushwooshNotification({ body: "{}", subject: "order.created" }, {}),
      { send_date: "now", content: "order.created" }
    );
  });

  it("passes devices / conditions through verbatim when configured", () => {
    assert.deepEqual(
      buildPushwooshNotification(
        { body: "{}", subject: "order.created" },
        { devices: ["hwid_1"], conditions: [["Country", "EQ", "fr"]] }
      ),
      {
        send_date: "now",
        content: "order.created",
        devices: ["hwid_1"],
        conditions: [["Country", "EQ", "fr"]],
      }
    );
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(buildPushwooshNotification(record, {}), {
      send_date: "now",
      content: "order.created",
    });
    assert.deepEqual(
      buildPushwooshNotification(record, { includePayload: true }),
      { send_date: "now", content: `order.created\n\n{"a":1}` }
    );
    assert.deepEqual(
      buildPushwooshNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { send_date: "now", content: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolvePushwooshRecord({ body: "" }, 2),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("pushwoosh-sink wire shape", () => {
  it("exposes the fixed Pushwoosh createMessage endpoint", () => {
    assert.equal(
      PUSHWOOSH_CREATE_MESSAGE_URL,
      "https://api.pushwoosh.com/json/1.3/createMessage"
    );
  });

  it("builds the {request: {application, auth, notifications}} envelope — and no credential in the headers", () => {
    const parsed = JSON.parse(
      buildPushwooshMessageBody(application, auth, {
        send_date: "now",
        content: "order.created",
      })
    );
    assert.deepEqual(parsed, {
      request: {
        application,
        auth,
        notifications: [{ send_date: "now", content: "order.created" }],
      },
    });
    // The token rides in the body by design (Pushwoosh's auth shape),
    // never in a header and never in the URL.
    assert.equal(PUSHWOOSH_CREATE_MESSAGE_URL.includes(auth), false);
  });
});

describe("pushwoosh-sink verdict mapping", () => {
  it("accepts a 200 / OK verdict", () => {
    assert.equal(
      pushwooshVerdictToFailedRecord(
        { status: 200, statusCode: 200, statusMessage: "OK", messageIds: ["C3F8-1"] },
        0
      ),
      null
    );
  });

  it("maps a missing verdict on a 2xx to retryable", () => {
    assert.deepEqual(pushwooshVerdictToFailedRecord({ status: 200 }, 0), {
      index: 0,
      errorCode: "RESPONSE_MISSING",
      errorMessage: "Pushwoosh answered 2xx but surfaced no API verdict",
      retryable: true,
    });
  });

  it("maps a non-200 status_code to PUSHWOOSH_<code>, transient codes retryable", () => {
    assert.deepEqual(
      pushwooshVerdictToFailedRecord(
        { status: 200, statusCode: 210, statusMessage: "Access denied" },
        3
      ),
      {
        index: 3,
        errorCode: "PUSHWOOSH_210",
        statusCode: 210,
        errorMessage: "Access denied",
        retryable: false,
      }
    );
    assert.deepEqual(
      pushwooshVerdictToFailedRecord(
        { status: 200, statusCode: 500, statusMessage: "Internal error" },
        1
      ),
      {
        index: 1,
        errorCode: "PUSHWOOSH_500",
        statusCode: 500,
        errorMessage: "Internal error",
        retryable: true,
      }
    );
    assert.deepEqual(
      pushwooshVerdictToFailedRecord(
        { status: 200, statusCode: 429, statusMessage: "Too many requests" },
        2
      ),
      {
        index: 2,
        errorCode: "PUSHWOOSH_429",
        statusCode: 429,
        errorMessage: "Too many requests",
        retryable: true,
      }
    );
  });

  it("maps a 200 with a non-OK status_message to fail-closed", () => {
    assert.deepEqual(
      pushwooshVerdictToFailedRecord(
        { status: 200, statusCode: 200, statusMessage: "Created" },
        0
      ),
      {
        index: 0,
        errorCode: "PUSHWOOSH_STATUS_MESSAGE",
        errorMessage: 'Pushwoosh answered status_code 200 with status_message "Created"',
        retryable: false,
      }
    );
  });
});

describe("pushwoosh-sink send", () => {
  it("posts one message per record to the fixed endpoint with the createMessage envelope", async () => {
    const client = new FakeClient();
    const sink = new PushwooshSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: PUSHWOOSH_CREATE_MESSAGE_URL,
      headers: {},
      body: JSON.stringify({
        request: {
          application,
          auth,
          notifications: [{ send_date: "now", content: "order.created" }],
        },
      }),
    });
    // The key lands in the content, never as a separate field.
    assert.deepEqual(JSON.parse(client.posts[1].body).request.notifications, [
      { send_date: "now", content: "agg-8" },
    ]);
    // The trace id belongs in the content, never in the title.
    assert.deepEqual(JSON.parse(client.posts[2].body).request.notifications, [
      { send_date: "now", content: "t-9" },
    ]);
    for (const post of client.posts) {
      assert.deepEqual(post.headers, {});
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("passes configured devices / conditions into the notification", async () => {
    const client = new FakeClient();
    const sink = new PushwooshSink(
      baseConfig(client, { devices: ["hwid_1"], conditions: [["Country", "EQ", "fr"]] })
    );
    await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(JSON.parse(client.posts[0].body).request.notifications, [
      {
        send_date: "now",
        content: "order.created",
        devices: ["hwid_1"],
        conditions: [["Country", "EQ", "fr"]],
      },
    ]);
  });

  it("applies the payload opt-in truncation on send", async () => {
    const client = new FakeClient();
    const sink = new PushwooshSink(baseConfig(client, { includePayload: true, payloadMaxChars: 3 }));
    await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.equal(
      JSON.parse(client.posts[0].body).request.notifications[0].content,
      `order.created\n\n{"a… (truncated)`
    );
  });

  it("treats the Messages ids as acceptance receipts, not delivery results", async () => {
    const client = new FakeClient();
    client.verdictOn.set(0, {
      statusCode: 200,
      statusMessage: "OK",
      messageIds: ["C3F8-C3863ED4-334AD4F1"],
    });
    const sink = new PushwooshSink(baseConfig(client));
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 1 });
    assert.deepEqual(sink.stats, { sent: 1, failed: 0, sendFailures: 0 });
  });

  it("dead-letters a 210 access-denied verdict without retry, retries a 500 verdict", async () => {
    const client = new FakeClient();
    client.verdictOn.set(0, { statusCode: 210, statusMessage: "Access denied" });
    client.verdictOn.set(1, { statusCode: 500, statusMessage: "Internal error" });
    const sink = new PushwooshSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof PushwooshSinkError);
        assert.equal(err.failedRecords.length, 2);
        assert.deepEqual(
          err.failedRecords.map((r) => [r.index, r.errorCode, r.retryable]),
          [
            [0, "PUSHWOOSH_210", false],
            [1, "PUSHWOOSH_500", true],
          ]
        );
        return true;
      }
    );
    assert.deepEqual(sink.stats, { sent: 0, failed: 2, sendFailures: 1 });
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new PushwooshSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof PushwooshSinkError);
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
    const sink = new PushwooshSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof PushwooshSinkError);
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

  it("fails closed without a client, application code, or API token", async () => {
    await assert.rejects(
      () => new PushwooshSink({ application, auth }).send([{ body: '{"a":1}' }]),
      PushwooshSinkConfigError
    );
    await assert.rejects(
      () =>
        new PushwooshSink(baseConfig(new FakeClient(), { application: undefined })).send([
          { body: '{"a":1}' },
        ]),
      PushwooshSinkConfigError
    );
    await assert.rejects(
      () =>
        new PushwooshSink(baseConfig(new FakeClient(), { auth: undefined })).send([
          { body: '{"a":1}' },
        ]),
      PushwooshSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new PushwooshSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new PushwooshSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new PushwooshSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyPushwooshRecordFailure(429), true);
    assert.equal(classifyPushwooshRecordFailure(500), true);
    assert.equal(classifyPushwooshRecordFailure(503), true);
    assert.equal(classifyPushwooshRecordFailure(400), false);
    assert.equal(classifyPushwooshRecordFailure(401), false);
    assert.equal(classifyPushwooshRecordFailure(404), false);
    assert.equal(PUSHWOOSH_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
