import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  TelesignSink,
  TelesignSinkConfigError,
  TelesignSinkError,
  assertValidTelesignSinkConfig,
  buildTelesignMessageBody,
  classifyTelesignRecordFailure,
  resolveTelesignContent,
  resolveTelesignMessage,
  resolveTelesignRecord,
  telesignResponseToFailedRecord,
  truncateTelesignPayload,
  TELESIGN_SEND_URL,
  TELESIGN_MESSAGE_TYPE,
  TELESIGN_DEFAULT_PAYLOAD_MAX_CHARS,
  TELESIGN_FALLBACK_SUMMARY,
  type TelesignMessageClient,
  type TelesignMessagePostRequest,
  type TelesignMessagePostResponse,
  type TelesignSinkConfig,
} from "../src/telesign-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status and reference id per call. */
class FakeClient implements TelesignMessageClient {
  posts: TelesignMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  /** Call-count (0-based) → reference id to return for that post (undefined = none surfaced). */
  referenceIdOn = new Map<number, string | undefined>();
  async post(request: TelesignMessagePostRequest): Promise<TelesignMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return {
      status: this.statusOn.get(n) ?? 200,
      referenceId: this.referenceIdOn.has(n) ? this.referenceIdOn.get(n) : `ref-${n}`,
    };
  }
}

const phoneNumber = "+14155550100";

function baseConfig(
  client: TelesignMessageClient,
  extra: Partial<TelesignSinkConfig> = {}
): TelesignSinkConfig {
  return { phoneNumber, client, ...extra };
}

/** Parse a form body back into a field map for assertions. */
function parseForm(body: string): Record<string, string> {
  return Object.fromEntries(new URLSearchParams(body));
}

describe("telesign-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidTelesignSinkConfig(null, "TelesignSink"), RangeError);
    assert.throws(() => assertValidTelesignSinkConfig("x", "TelesignSink"), RangeError);
  });

  it("rejects a malformed recipient shape", () => {
    assert.throws(() => assertValidTelesignSinkConfig({ phoneNumber: "" }, "TelesignSink"), RangeError);
    assert.throws(
      () => assertValidTelesignSinkConfig({ phoneNumber: "has space" }, "TelesignSink"),
      RangeError
    );
    assert.throws(
      () => assertValidTelesignSinkConfig({ phoneNumber: 42 }, "TelesignSink"),
      RangeError
    );
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidTelesignSinkConfig({ client: {} }, "TelesignSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidTelesignSinkConfig({ payloadMaxChars: 0 }, "TelesignSink"), RangeError);
    assert.throws(
      () => assertValidTelesignSinkConfig({ payloadMaxChars: 2.5 }, "TelesignSink"),
      RangeError
    );
  });

  it("accepts a config with no recipient yet (send-time config error)", () => {
    assert.doesNotThrow(() => new TelesignSink({}));
  });
});

describe("telesign-sink content derivation", () => {
  it("derives content from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveTelesignContent({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveTelesignContent({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveTelesignContent({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveTelesignContent({ body: "{}" }), TELESIGN_FALLBACK_SUMMARY);
    assert.equal(
      resolveTelesignContent({ body: "{}", subject: "", key: "", traceId: "" }),
      TELESIGN_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateTelesignPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateTelesignPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveTelesignMessage(record, {}), { message: "order.created" });
    assert.deepEqual(resolveTelesignMessage(record, { includePayload: true }), {
      message: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveTelesignMessage(record, { includePayload: true, payloadMaxChars: 3 }),
      { message: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveTelesignRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("telesign-sink wire shape", () => {
  it("exposes the fixed Telesign Messaging endpoint and the ARN message type", () => {
    assert.equal(TELESIGN_SEND_URL, "https://rest-ww.telesign.com/v1/messaging");
    assert.equal(TELESIGN_MESSAGE_TYPE, "ARN");
  });

  it("builds the form-encoded body with phone_number, message, message_type=ARN — and no credential", () => {
    assert.equal(
      buildTelesignMessageBody(phoneNumber, "order.created"),
      "phone_number=%2B14155550100&message=order.created&message_type=ARN"
    );
    assert.equal(
      buildTelesignMessageBody(phoneNumber, "hello world & friends"),
      "phone_number=%2B14155550100&message=hello%20world%20%26%20friends&message_type=ARN"
    );
    const body = buildTelesignMessageBody(phoneNumber, "x");
    assert.equal(body.includes("Authorization"), false);
    assert.equal(body.includes("Basic"), false);
    assert.equal(body.includes("customer_id"), false);
    assert.equal(body.includes("api_key"), false);
    // OTP is out of scope: the message type is always ARN, never OTP.
    assert.equal(body.includes("message_type=OTP"), false);
  });
});

describe("telesign-sink reference-id mapping", () => {
  it("accepts a 2xx with a reference id", () => {
    assert.equal(
      telesignResponseToFailedRecord({ status: 200, referenceId: "ref-1" }, 0),
      null
    );
  });

  it("maps a missing reference id on a 2xx to retryable", () => {
    assert.deepEqual(telesignResponseToFailedRecord({ status: 200 }, 0), {
      index: 0,
      errorCode: "REFERENCE_ID_MISSING",
      errorMessage: "Telesign answered 2xx but surfaced no reference_id",
      retryable: true,
    });
    assert.deepEqual(telesignResponseToFailedRecord({ status: 200, referenceId: "" }, 1), {
      index: 1,
      errorCode: "REFERENCE_ID_MISSING",
      errorMessage: "Telesign answered 2xx but surfaced no reference_id",
      retryable: true,
    });
  });
});

describe("telesign-sink send", () => {
  it("posts one message per record to the fixed endpoint with the form body, no credential", async () => {
    const client = new FakeClient();
    const sink = new TelesignSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: TELESIGN_SEND_URL,
      body: "phone_number=%2B14155550100&message=order.created&message_type=ARN",
    });
    assert.deepEqual(client.posts[1], {
      url: TELESIGN_SEND_URL,
      body: "phone_number=%2B14155550100&message=agg-8&message_type=ARN",
    });
    assert.deepEqual(client.posts[2], {
      url: TELESIGN_SEND_URL,
      body: "phone_number=%2B14155550100&message=t-9&message_type=ARN",
    });
    for (const post of client.posts) {
      assert.equal(post.body.includes("Authorization"), false);
      assert.equal(post.body.includes("Basic"), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("applies the payload opt-in truncation on send", async () => {
    const client = new FakeClient();
    const sink = new TelesignSink(baseConfig(client, { includePayload: true, payloadMaxChars: 3 }));
    await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.equal(
      parseForm(client.posts[0].body).message,
      `order.created\n\n{"a… (truncated)`
    );
  });

  it("treats a reference id as an acceptance receipt, not a delivery result", async () => {
    const client = new FakeClient();
    client.referenceIdOn.set(0, "35C8B5D509BC10689196FED2AD551B8A");
    const sink = new TelesignSink(baseConfig(client));
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 1 });
    assert.deepEqual(sink.stats, { sent: 1, failed: 0, sendFailures: 0 });
  });

  it("retries a 2xx with no reference id surfaced", async () => {
    const client = new FakeClient();
    client.referenceIdOn.set(0, undefined);
    const sink = new TelesignSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }]),
      (err: unknown) => {
        assert.ok(err instanceof TelesignSinkError);
        assert.equal(err.failedRecords.length, 1);
        assert.deepEqual(
          err.failedRecords.map((r) => [r.index, r.errorCode, r.retryable]),
          [[0, "REFERENCE_ID_MISSING", true]]
        );
        return true;
      }
    );
    assert.deepEqual(sink.stats, { sent: 0, failed: 1, sendFailures: 1 });
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new TelesignSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof TelesignSinkError);
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
    const sink = new TelesignSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof TelesignSinkError);
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
      () => new TelesignSink({ phoneNumber }).send([{ body: '{"a":1}' }]),
      TelesignSinkConfigError
    );
    await assert.rejects(
      () =>
        new TelesignSink(baseConfig(new FakeClient(), { phoneNumber: undefined })).send([
          { body: '{"a":1}' },
        ]),
      TelesignSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new TelesignSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new TelesignSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new TelesignSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyTelesignRecordFailure(429), true);
    assert.equal(classifyTelesignRecordFailure(500), true);
    assert.equal(classifyTelesignRecordFailure(503), true);
    assert.equal(classifyTelesignRecordFailure(400), false);
    assert.equal(classifyTelesignRecordFailure(401), false);
    assert.equal(classifyTelesignRecordFailure(404), false);
    assert.equal(TELESIGN_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
