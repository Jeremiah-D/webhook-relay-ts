import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  IterableSink,
  IterableSinkConfigError,
  IterableSinkError,
  assertValidIterableSinkConfig,
  buildIterableDataFields,
  buildIterablePushTargetBody,
  buildIterablePushTargetUrl,
  classifyIterableRecordFailure,
  resolveIterableContent,
  resolveIterableHost,
  resolveIterableRecipient,
  resolveIterableRecord,
  resolveIterableSummary,
  truncateIterablePayload,
  ITERABLE_DEFAULT_HOST,
  ITERABLE_DEFAULT_PAYLOAD_MAX_CHARS,
  ITERABLE_EDC_HOST,
  ITERABLE_FALLBACK_SUMMARY,
  ITERABLE_JSON_CONTENT_TYPE,
  ITERABLE_PUSH_TARGET_PATH,
  type IterableMessageClient,
  type IterableMessagePostRequest,
  type IterableMessagePostResponse,
  type IterableRecipient,
  type IterableSinkConfig,
} from "../src/iterable-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements IterableMessageClient {
  posts: IterableMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: IterableMessagePostRequest): Promise<IterableMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200 };
  }
}

const recipient: IterableRecipient = { email: "person@example.com" };

function baseConfig(
  client: IterableMessageClient,
  extra: Partial<IterableSinkConfig> = {}
): IterableSinkConfig {
  return { campaignId: 123, recipient, client, ...extra };
}

describe("iterable-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidIterableSinkConfig(null, "IterableSink"), RangeError);
    assert.throws(() => assertValidIterableSinkConfig("x", "IterableSink"), RangeError);
  });

  it("rejects a malformed region host", () => {
    assert.throws(
      () => assertValidIterableSinkConfig(baseConfig(new FakeClient(), { regionHost: "https://api.iterable.com" }), "IterableSink"),
      RangeError
    );
    assert.throws(
      () => assertValidIterableSinkConfig(baseConfig(new FakeClient(), { regionHost: "api.iterable.com/api" }), "IterableSink"),
      RangeError
    );
    assert.equal(ITERABLE_EDC_HOST, "api.eu.iterable.com");
    assertValidIterableSinkConfig(baseConfig(new FakeClient(), { regionHost: ITERABLE_EDC_HOST }), "IterableSink");
  });

  it("requires an integer campaign id", () => {
    assert.throws(
      () => assertValidIterableSinkConfig({ recipient, client: new FakeClient() }, "IterableSink"),
      RangeError
    );
    assert.throws(
      () => assertValidIterableSinkConfig(baseConfig(new FakeClient(), { campaignId: 123.5 }), "IterableSink"),
      RangeError
    );
    assert.throws(
      () => assertValidIterableSinkConfig(baseConfig(new FakeClient(), { campaignId: "123" as never }), "IterableSink"),
      RangeError
    );
    assertValidIterableSinkConfig(baseConfig(new FakeClient(), { campaignId: 123 }), "IterableSink");
  });

  it("requires exactly one recipient, email or userId", () => {
    assert.throws(
      () => assertValidIterableSinkConfig({ campaignId: 123, client: new FakeClient() }, "IterableSink"),
      RangeError
    );
    assert.throws(
      () => assertValidIterableSinkConfig(baseConfig(new FakeClient(), { recipient: {} }), "IterableSink"),
      RangeError
    );
    assert.throws(
      () =>
        assertValidIterableSinkConfig(
          baseConfig(new FakeClient(), { recipient: { email: "person@example.com", userId: "u-1" } }),
          "IterableSink"
        ),
      RangeError
    );
    assert.throws(
      () => assertValidIterableSinkConfig(baseConfig(new FakeClient(), { recipient: { email: "" } }), "IterableSink"),
      RangeError
    );
    assert.deepEqual(resolveIterableRecipient({ email: "person@example.com" }, "IterableSink"), {
      email: "person@example.com",
    });
    assert.deepEqual(resolveIterableRecipient({ userId: "u-1" }, "IterableSink"), { userId: "u-1" });
    assertValidIterableSinkConfig(baseConfig(new FakeClient(), { recipient: { userId: "u-1" } }), "IterableSink");
  });

  it("rejects a malformed client and payloadMaxChars", () => {
    assert.throws(
      () => assertValidIterableSinkConfig(baseConfig(new FakeClient(), { client: {} as never }), "IterableSink"),
      RangeError
    );
    assert.throws(
      () => assertValidIterableSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 0 }), "IterableSink"),
      RangeError
    );
    assert.throws(
      () => assertValidIterableSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 1.5 }), "IterableSink"),
      RangeError
    );
  });
});

describe("iterable-sink resolvers", () => {
  it("resolves the default and configured host", () => {
    assert.equal(resolveIterableHost({}), ITERABLE_DEFAULT_HOST);
    assert.equal(resolveIterableHost({ regionHost: "api.eu.iterable.com" }), "api.eu.iterable.com");
    assert.equal(buildIterablePushTargetUrl("api.iterable.com"), "https://api.iterable.com/api/push/target");
    assert.equal(ITERABLE_PUSH_TARGET_PATH, "/api/push/target");
  });

  it("derives the summary from subject, key, then traceId", () => {
    assert.equal(resolveIterableSummary({ body: "{}", subject: "Price drop", key: "k", traceId: "t" }), "Price drop");
    assert.equal(resolveIterableSummary({ body: "{}", key: "order-1", traceId: "t" }), "order-1");
    assert.equal(resolveIterableSummary({ body: "{}", traceId: "trace-9" }), "trace-9");
    assert.equal(resolveIterableSummary({ body: "{}" }), ITERABLE_FALLBACK_SUMMARY);
  });

  it("derives title/message and appends the payload only under the opt-in", () => {
    const content = resolveIterableContent({ body: '{"a":1}', subject: "Price drop" }, {});
    assert.deepEqual(content, { title: "Price drop", message: "Price drop" });
    const withPayload = resolveIterableContent({ body: '{"a":1}', subject: "Price drop" }, { includePayload: true });
    assert.equal(withPayload.message, 'Price drop\n\n{"a":1}');
    assert.equal(ITERABLE_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
    assert.equal(truncateIterablePayload("abcdef", 4), "abcd… (truncated)");
    assert.equal(truncateIterablePayload("abc", 4), "abc");
  });

  it("builds dataFields with the derived title and message", () => {
    assert.deepEqual(buildIterableDataFields({ title: "Price drop", message: "Price drop" }), {
      title: "Price drop",
      message: "Price drop",
    });
  });

  it("builds the push/target body with campaign id, recipient email, and dataFields", () => {
    const body = JSON.parse(
      buildIterablePushTargetBody(123, recipient, { title: "Price drop", message: "Price drop" })
    );
    assert.equal(body.campaignId, 123);
    assert.equal(body.recipientEmail, "person@example.com");
    assert.equal(body.recipientUserId, undefined);
    assert.deepEqual(body.dataFields, { title: "Price drop", message: "Price drop" });
    // sendAt is never sent: omitting it means immediate send.
    assert.equal(body.sendAt, undefined);
    // No credential ever enters the body.
    assert.equal(JSON.stringify(body).includes("Api-Key"), false);
    assert.equal(JSON.stringify(body).includes("api_key"), false);
  });

  it("uses recipientUserId when the recipient is identified by userId", () => {
    const body = JSON.parse(
      buildIterablePushTargetBody(123, { userId: "u-1" }, { title: "Reset", message: "Reset" })
    );
    assert.equal(body.campaignId, 123);
    assert.equal(body.recipientUserId, "u-1");
    assert.equal(body.recipientEmail, undefined);
    assert.equal(body.sendAt, undefined);
  });

  it("rejects an empty record body", () => {
    assert.throws(() => resolveIterableRecord({ body: "" }, 0), RangeError);
    assert.deepEqual(resolveIterableRecord({ body: "{}" }, 2), { index: 2 });
  });
});

describe("iterable-sink failure mapping", () => {
  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", () => {
    assert.equal(classifyIterableRecordFailure(429), true);
    assert.equal(classifyIterableRecordFailure(500), true);
    assert.equal(classifyIterableRecordFailure(503), true);
    assert.equal(classifyIterableRecordFailure(400), false);
    assert.equal(classifyIterableRecordFailure(401), false);
    assert.equal(classifyIterableRecordFailure(403), false);
    assert.equal(classifyIterableRecordFailure(404), false);
  });
});

describe("iterable-sink send", () => {
  it("posts one triggered push per message with no credentials", async () => {
    const client = new FakeClient();
    const sink = new IterableSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "Price drop", key: "order-1" },
      { body: '{"b":2}', key: "order-2" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    const first = client.posts[0];
    assert.equal(first.url, "https://api.iterable.com/api/push/target");
    assert.equal(first.headers["Content-Type"], ITERABLE_JSON_CONTENT_TYPE);
    assert.equal(first.headers["Api-Key"], undefined);
    assert.equal(first.headers["Authorization"], undefined);
    const body = JSON.parse(first.body);
    assert.equal(body.campaignId, 123);
    assert.equal(body.recipientEmail, "person@example.com");
    assert.deepEqual(body.dataFields, { title: "Price drop", message: "Price drop" });
    assert.equal(body.sendAt, undefined);
    // No credential ever enters the handed request.
    assert.equal(JSON.stringify(first).includes("Api-Key"), false);
    assert.equal(JSON.stringify(first).includes("api_key"), false);
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("accepts a 200 as acceptance with no response-body field to read", async () => {
    const client = new FakeClient();
    const sink = new IterableSink(baseConfig(client));
    const result = await sink.send([{ body: "{}", key: "k1" }]);
    assert.deepEqual(result, { ok: true, sent: 1 });
    assert.deepEqual(sink.stats, { sent: 1, failed: 0, sendFailures: 0 });
  });

  it("throws with exactly the failed messages and their retry lanes", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 429);
    client.statusOn.set(2, 503);
    const sink = new IterableSink(baseConfig(client));
    await assert.rejects(
      sink.send([
        { body: "{}", key: "k1" },
        { body: "{}", key: "k2" },
        { body: "{}", key: "k3" },
      ]),
      (err: unknown) => {
        assert.ok(err instanceof IterableSinkError);
        assert.deepEqual(
          (err as IterableSinkError).failedRecords.map((f) => [f.index, f.errorCode, f.retryable]),
          [
            [1, "HTTP_429", true],
            [2, "HTTP_503", true],
          ]
        );
        return true;
      }
    );
    assert.deepEqual(sink.stats, { sent: 1, failed: 2, sendFailures: 1 });
  });

  it("treats an unknown campaign (400) as fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 400);
    const sink = new IterableSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as IterableSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_400");
        assert.equal(failed[0].statusCode, 400);
        assert.equal(failed[0].retryable, false);
        return true;
      }
    );
  });

  it("treats a bad API key (401) as fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 401);
    const sink = new IterableSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as IterableSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_401");
        assert.equal(failed[0].retryable, false);
        return true;
      }
    );
  });

  it("treats a client throw as a retryable transport failure", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hang up"));
    const sink = new IterableSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as IterableSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(failed[0].retryable, true);
        assert.equal(failed[0].errorMessage, "socket hang up");
        return true;
      }
    );
  });

  it("throws a config error with no client, mapped non_retryable", async () => {
    const sink = new IterableSink({ campaignId: 123, recipient });
    await assert.rejects(sink.send([{ body: "{}", key: "k1" }]), IterableSinkConfigError);
    assert.equal(classifyFailure(new IterableSinkConfigError("no client injected")).failureClass, "non_retryable");
  });

  it("dry-runs with zero client I/O and untouched stats", async () => {
    const client = new FakeClient();
    const sink = new IterableSink(baseConfig(client, { dryRun: true }));
    const result = await sink.send([{ body: "{}", subject: "Price drop" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("dry-runs still validate the config and the records", async () => {
    const client = new FakeClient();
    const sink = new IterableSink(baseConfig(client, { dryRun: true }));
    await assert.rejects(sink.send([{ body: "" }]), RangeError);
    assert.equal(client.posts.length, 0);
    assert.throws(
      () => new IterableSink({ campaignId: 123, recipient: {}, dryRun: true }),
      RangeError
    );
  });

  it("appends the payload under the opt-in, truncated at the default 2000", async () => {
    const client = new FakeClient();
    const sink = new IterableSink(baseConfig(client, { includePayload: true, payloadMaxChars: 10 }));
    await sink.send([{ body: "0123456789ABCDEF", subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.dataFields.message, "Alert\n\n0123456789… (truncated)");
    assert.equal(body.dataFields.title, "Alert");

    const defaultClient = new FakeClient();
    const defaultSink = new IterableSink(baseConfig(defaultClient, { includePayload: true }));
    await defaultSink.send([{ body: "x".repeat(2001), subject: "Alert" }]);
    const defaultBody = JSON.parse(defaultClient.posts[0].body);
    assert.equal(defaultBody.dataFields.message, `Alert\n\n${"x".repeat(2000)}… (truncated)`);
  });

  it("omits the payload by default", async () => {
    const client = new FakeClient();
    const sink = new IterableSink(baseConfig(client));
    await sink.send([{ body: '{"secret":"s3cr3t"}', subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.dataFields.message, "Alert");
    assert.equal(JSON.stringify(body).includes("s3cr3t"), false);
  });

  it("uses the configured EDC host and userId recipient", async () => {
    const client = new FakeClient();
    const sink = new IterableSink(
      baseConfig(client, { regionHost: "api.eu.iterable.com", recipient: { userId: "u-1" } })
    );
    await sink.send([{ body: "{}", key: "k1" }]);
    assert.equal(client.posts[0].url, "https://api.eu.iterable.com/api/push/target");
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.recipientUserId, "u-1");
    assert.equal(body.recipientEmail, undefined);
  });
});
