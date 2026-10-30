import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  CourierSink,
  CourierSinkConfigError,
  CourierSinkError,
  assertValidCourierSinkConfig,
  buildCourierMessageBody,
  classifyCourierRecordFailure,
  resolveCourierBody,
  resolveCourierNotification,
  resolveCourierRecord,
  resolveCourierTitle,
  truncateCourierPayload,
  COURIER_SEND_URL,
  COURIER_DEFAULT_PAYLOAD_MAX_CHARS,
  COURIER_FALLBACK_SUMMARY,
  type CourierMessageClient,
  type CourierMessagePostRequest,
  type CourierMessagePostResponse,
  type CourierSinkConfig,
} from "../src/courier-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements CourierMessageClient {
  posts: CourierMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  /** Call-count (0-based) → requestId to return for that post. */
  requestIdOn = new Map<number, string>();
  async post(request: CourierMessagePostRequest): Promise<CourierMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    const requestId = this.requestIdOn.get(n);
    return requestId === undefined
      ? { status: this.statusOn.get(n) ?? 200 }
      : { status: this.statusOn.get(n) ?? 200, requestId };
  }
}

const to = "alerts@example.com";

function baseConfig(
  client: CourierMessageClient,
  extra: Partial<CourierSinkConfig> = {}
): CourierSinkConfig {
  return { to, client, ...extra };
}

describe("courier-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidCourierSinkConfig(null, "CourierSink"), RangeError);
    assert.throws(() => assertValidCourierSinkConfig("x", "CourierSink"), RangeError);
  });

  it("rejects a malformed recipient shape", () => {
    assert.throws(() => assertValidCourierSinkConfig({ to: "" }, "CourierSink"), RangeError);
    assert.throws(
      () => assertValidCourierSinkConfig({ to: "has space" }, "CourierSink"),
      RangeError
    );
    assert.throws(() => assertValidCourierSinkConfig({ to: 42 }, "CourierSink"), RangeError);
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidCourierSinkConfig({ client: {} }, "CourierSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidCourierSinkConfig({ payloadMaxChars: 0 }, "CourierSink"), RangeError);
    assert.throws(
      () => assertValidCourierSinkConfig({ payloadMaxChars: 2.5 }, "CourierSink"),
      RangeError
    );
  });

  it("accepts a config with no recipient yet (send-time config error)", () => {
    assert.doesNotThrow(() => new CourierSink({}));
  });
});

describe("courier-sink text derivation", () => {
  it("derives the title from subject, then key, then the fallback (never traceId)", () => {
    assert.equal(
      resolveCourierTitle({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveCourierTitle({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveCourierTitle({ body: "{}", traceId: "t-1" }), COURIER_FALLBACK_SUMMARY);
    assert.equal(resolveCourierTitle({ body: "{}" }), COURIER_FALLBACK_SUMMARY);
  });

  it("derives the body from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveCourierBody({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveCourierBody({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveCourierBody({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveCourierBody({ body: "{}" }), COURIER_FALLBACK_SUMMARY);
    assert.equal(
      resolveCourierBody({ body: "{}", subject: "", key: "", traceId: "" }),
      COURIER_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateCourierPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateCourierPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveCourierNotification(record, {}), {
      title: "order.created",
      body: "order.created",
    });
    assert.deepEqual(resolveCourierNotification(record, { includePayload: true }), {
      title: "order.created",
      body: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveCourierNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { title: "order.created", body: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveCourierRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("courier-sink wire shape", () => {
  it("exposes the fixed Courier send endpoint", () => {
    assert.equal(COURIER_SEND_URL, "https://api.courier.com/send");
  });

  it("builds the message/to/content envelope — and no credential", () => {
    const parsed = JSON.parse(
      buildCourierMessageBody(to, "order.created", "order.created")
    );
    assert.deepEqual(parsed, {
      message: {
        to: { email: "alerts@example.com" },
        content: { title: "order.created", body: "order.created" },
      },
    });
    const body = buildCourierMessageBody(to, "s", "b");
    assert.equal(body.includes("Authorization"), false);
    assert.equal(body.includes("Bearer"), false);
    assert.equal(body.includes("api_key"), false);
    assert.equal(body.includes("API key"), false);
  });
});

describe("courier-sink send", () => {
  it("posts one message per record to the fixed endpoint with the Courier envelope, no credential", async () => {
    const client = new FakeClient();
    const sink = new CourierSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: COURIER_SEND_URL,
      body: JSON.stringify({
        message: {
          to: { email: to },
          content: { title: "order.created", body: "order.created" },
        },
      }),
    });
    assert.deepEqual(JSON.parse(client.posts[1].body).message.content, {
      title: "agg-8",
      body: "agg-8",
    });
    // The trace id belongs in the body, never in the title.
    assert.deepEqual(JSON.parse(client.posts[2].body).message.content, {
      title: COURIER_FALLBACK_SUMMARY,
      body: "t-9",
    });
    for (const post of client.posts) {
      assert.equal(post.body.includes("Authorization"), false);
      assert.equal(post.body.includes("Bearer"), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("treats a 2xx requestId as an acceptance receipt, not a delivery result", async () => {
    const client = new FakeClient();
    client.requestIdOn.set(0, "req-abc-123");
    const sink = new CourierSink(baseConfig(client));
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 1 });
    assert.deepEqual(sink.stats, { sent: 1, failed: 0, sendFailures: 0 });
  });

  it("applies the payload opt-in truncation on send", async () => {
    const client = new FakeClient();
    const sink = new CourierSink(baseConfig(client, { includePayload: true, payloadMaxChars: 3 }));
    await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.equal(
      JSON.parse(client.posts[0].body).message.content.body,
      `order.created\n\n{"a… (truncated)`
    );
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new CourierSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof CourierSinkError);
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
    const sink = new CourierSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof CourierSinkError);
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

  it("fails closed without a client or recipient", async () => {
    await assert.rejects(
      () => new CourierSink({ to }).send([{ body: '{"a":1}' }]),
      CourierSinkConfigError
    );
    await assert.rejects(
      () =>
        new CourierSink(baseConfig(new FakeClient(), { to: undefined })).send([
          { body: '{"a":1}' },
        ]),
      CourierSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new CourierSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new CourierSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new CourierSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyCourierRecordFailure(429), true);
    assert.equal(classifyCourierRecordFailure(500), true);
    assert.equal(classifyCourierRecordFailure(503), true);
    assert.equal(classifyCourierRecordFailure(400), false);
    assert.equal(classifyCourierRecordFailure(401), false);
    assert.equal(classifyCourierRecordFailure(404), false);
    assert.equal(COURIER_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
