import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  BatchSink,
  BatchSinkConfigError,
  BatchSinkError,
  assertValidBatchSinkConfig,
  buildBatchTransactionalBody,
  classifyBatchRecordFailure,
  resolveBatchGroupId,
  resolveBatchMessage,
  resolveBatchRecipientList,
  resolveBatchRecipients,
  resolveBatchRecord,
  resolveBatchSummary,
  truncateBatchPayload,
  BATCH_DEFAULT_GROUP_ID,
  BATCH_DEFAULT_PAYLOAD_MAX_CHARS,
  BATCH_FALLBACK_SUMMARY,
  BATCH_JSON_CONTENT_TYPE,
  BATCH_TRANSACTIONAL_SEND_URL_TEMPLATE,
  type BatchMessageClient,
  type BatchMessagePostRequest,
  type BatchMessagePostResponse,
  type BatchSinkConfig,
} from "../src/batch-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements BatchMessageClient {
  posts: BatchMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → transactional token to return for that post. */
  tokenOn = new Map<number, string>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: BatchMessagePostRequest): Promise<BatchMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 201, token: this.tokenOn.get(n) };
  }
}

function baseConfig(
  client: BatchMessageClient,
  extra: Partial<BatchSinkConfig> = {}
): BatchSinkConfig {
  return { recipients: { custom_ids: ["user-1"] }, client, ...extra };
}

describe("batch-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidBatchSinkConfig(null, "BatchSink"), RangeError);
    assert.throws(() => assertValidBatchSinkConfig("x", "BatchSink"), RangeError);
  });

  it("requires at least one recipient kind and validates each list", () => {
    assert.throws(
      () => assertValidBatchSinkConfig({ client: new FakeClient() }, "BatchSink"),
      RangeError
    );
    assert.throws(
      () => assertValidBatchSinkConfig(baseConfig(new FakeClient(), { recipients: {} }), "BatchSink"),
      RangeError
    );
    assert.throws(
      () =>
        assertValidBatchSinkConfig(
          baseConfig(new FakeClient(), { recipients: { tokens: [] } }),
          "BatchSink"
        ),
      RangeError
    );
    assert.throws(
      () =>
        assertValidBatchSinkConfig(
          baseConfig(new FakeClient(), { recipients: { custom_ids: [""] } }),
          "BatchSink"
        ),
      RangeError
    );
    assert.throws(
      () =>
        assertValidBatchSinkConfig(
          baseConfig(new FakeClient(), { recipients: { install_ids: ["ok", 7] as never } }),
          "BatchSink"
        ),
      RangeError
    );
    assert.throws(
      () =>
        assertValidBatchSinkConfig(
          baseConfig(new FakeClient(), { recipients: "user-1" as never }),
          "BatchSink"
        ),
      RangeError
    );
    assert.deepEqual(resolveBatchRecipients({ tokens: ["t1"], custom_ids: ["u1"] }, "BatchSink"), {
      tokens: ["t1"],
      custom_ids: ["u1"],
    });
    assert.deepEqual(resolveBatchRecipientList(["i1", "i2"], "install_ids", "BatchSink"), ["i1", "i2"]);
    assertValidBatchSinkConfig(baseConfig(new FakeClient()), "BatchSink");
    assertValidBatchSinkConfig(
      baseConfig(new FakeClient(), {
        recipients: { tokens: ["t1"], custom_ids: ["u1"], install_ids: ["i1"] },
      }),
      "BatchSink"
    );
  });

  it("defaults the group id and validates it when set", () => {
    assert.equal(BATCH_DEFAULT_GROUP_ID, "webhook-relay");
    assert.equal(resolveBatchGroupId(undefined, "BatchSink"), "webhook-relay");
    assert.equal(resolveBatchGroupId("orders", "BatchSink"), "orders");
    assert.throws(() => resolveBatchGroupId("", "BatchSink"), RangeError);
    assert.throws(() => resolveBatchGroupId(7, "BatchSink"), RangeError);
    assertValidBatchSinkConfig(baseConfig(new FakeClient(), { groupId: "orders" }), "BatchSink");
  });

  it("rejects a malformed client and payloadMaxChars", () => {
    assert.throws(
      () => assertValidBatchSinkConfig(baseConfig(new FakeClient(), { client: {} as never }), "BatchSink"),
      RangeError
    );
    assert.throws(
      () => assertValidBatchSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 0 }), "BatchSink"),
      RangeError
    );
    assert.throws(
      () => assertValidBatchSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 1.5 }), "BatchSink"),
      RangeError
    );
  });
});

describe("batch-sink resolvers", () => {
  it("hands the client the transactional send URL as a template", () => {
    assert.equal(
      BATCH_TRANSACTIONAL_SEND_URL_TEMPLATE,
      "https://api.batch.com/1.1/{apiKey}/transactional/send"
    );
    // The template carries a placeholder, never a real key.
    assert.equal(BATCH_TRANSACTIONAL_SEND_URL_TEMPLATE.includes("{apiKey}"), true);
  });

  it("derives the summary from subject, key, then traceId", () => {
    assert.equal(resolveBatchSummary({ body: "{}", subject: "Price drop", key: "k", traceId: "t" }), "Price drop");
    assert.equal(resolveBatchSummary({ body: "{}", key: "order-1", traceId: "t" }), "order-1");
    assert.equal(resolveBatchSummary({ body: "{}", traceId: "trace-9" }), "trace-9");
    assert.equal(resolveBatchSummary({ body: "{}" }), BATCH_FALLBACK_SUMMARY);
  });

  it("derives the message with title from subject only and body from the chain", () => {
    assert.deepEqual(resolveBatchMessage({ body: "{}", subject: "Price drop", key: "k" }, {}), {
      body: "Price drop",
      title: "Price drop",
    });
    // No subject: the title is omitted, the body falls back to the chain.
    assert.deepEqual(resolveBatchMessage({ body: "{}", key: "order-1" }, {}), { body: "order-1" });
    assert.deepEqual(resolveBatchMessage({ body: "{}" }, {}), { body: BATCH_FALLBACK_SUMMARY });
  });

  it("appends custom_payload only under the opt-in, truncated at the default 2000", () => {
    const withPayload = resolveBatchMessage({ body: '{"a":1}', subject: "Price drop" }, { includePayload: true });
    assert.equal(withPayload.customPayload, '{"a":1}');
    assert.equal(BATCH_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
    assert.equal(truncateBatchPayload("abcdef", 4), "abcd… (truncated)");
    assert.equal(truncateBatchPayload("abc", 4), "abc");
    const long = resolveBatchMessage({ body: "x".repeat(2001), subject: "Alert" }, { includePayload: true });
    assert.equal(long.customPayload, `${"x".repeat(2000)}… (truncated)`);
    const short = resolveBatchMessage({ body: "0123456789ABCDEF", subject: "Alert" }, { includePayload: true, payloadMaxChars: 10 });
    assert.equal(short.customPayload, "0123456789… (truncated)");
  });

  it("builds the transactional body with group, recipients, and message", () => {
    const body = JSON.parse(
      buildBatchTransactionalBody(
        "orders",
        { tokens: ["t1"], custom_ids: ["u1"] },
        { title: "Price drop", body: "Price drop" }
      )
    );
    assert.equal(body.group_id, "orders");
    assert.deepEqual(body.recipients, { tokens: ["t1"], custom_ids: ["u1"] });
    assert.deepEqual(body.message, { title: "Price drop", body: "Price drop" });
    assert.equal(body.custom_payload, undefined);
    // No credential ever enters the body.
    assert.equal(JSON.stringify(body).includes("Authorization"), false);
    assert.equal(JSON.stringify(body).includes("apiKey"), false);
    assert.equal(JSON.stringify(body).includes("secret"), false);
  });

  it("omits the title when the event carries no subject", () => {
    const body = JSON.parse(
      buildBatchTransactionalBody("webhook-relay", { install_ids: ["i1"] }, { body: "order-1" })
    );
    assert.deepEqual(body.message, { body: "order-1" });
  });

  it("appends custom_payload as a JSON string under the opt-in", () => {
    const body = JSON.parse(
      buildBatchTransactionalBody(
        "webhook-relay",
        { custom_ids: ["u1"] },
        { body: "Alert", customPayload: '{"a":1}' }
      )
    );
    assert.equal(body.custom_payload, '{"a":1}');
    assert.equal(typeof body.custom_payload, "string");
  });

  it("rejects an empty record body", () => {
    assert.throws(() => resolveBatchRecord({ body: "" }, 0), RangeError);
    assert.deepEqual(resolveBatchRecord({ body: "{}" }, 2), { index: 2 });
  });
});

describe("batch-sink failure mapping", () => {
  it("maps 429 and 5xx to retryable, other non-201 to fail-closed", () => {
    assert.equal(classifyBatchRecordFailure(429), true);
    assert.equal(classifyBatchRecordFailure(500), true);
    assert.equal(classifyBatchRecordFailure(503), true);
    assert.equal(classifyBatchRecordFailure(400), false);
    assert.equal(classifyBatchRecordFailure(401), false);
    assert.equal(classifyBatchRecordFailure(402), false);
    assert.equal(classifyBatchRecordFailure(404), false);
    assert.equal(classifyBatchRecordFailure(200), false);
  });
});

describe("batch-sink send", () => {
  it("posts one send per message with no credentials", async () => {
    const client = new FakeClient();
    client.tokenOn.set(0, "tok-1111");
    client.tokenOn.set(1, "tok-2222");
    const sink = new BatchSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "Price drop", key: "order-1" },
      { body: '{"b":2}', key: "order-2" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2, tokens: ["tok-1111", "tok-2222"] });
    assert.equal(client.posts.length, 2);
    const first = client.posts[0];
    assert.equal(first.url, BATCH_TRANSACTIONAL_SEND_URL_TEMPLATE);
    assert.equal(first.headers["Content-Type"], BATCH_JSON_CONTENT_TYPE);
    assert.equal(first.headers["X-Authorization"], undefined);
    const body = JSON.parse(first.body);
    assert.equal(body.group_id, "webhook-relay");
    assert.deepEqual(body.recipients, { custom_ids: ["user-1"] });
    assert.deepEqual(body.message, { title: "Price drop", body: "Price drop" });
    assert.equal(body.custom_payload, undefined);
    // No credential ever enters the handed request: the URL
    // carries only the `{apiKey}` placeholder (already
    // asserted equal to the template above), never a real key.
    assert.equal(JSON.stringify(first).includes("Authorization"), false);
    assert.equal(JSON.stringify(first).includes("secret"), false);
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("accepts a 201 as acceptance and returns its transactional token receipt", async () => {
    const client = new FakeClient();
    client.tokenOn.set(0, "tok-9e5f");
    const sink = new BatchSink(baseConfig(client));
    const result = await sink.send([{ body: "{}", key: "k1" }]);
    assert.deepEqual(result, { ok: true, sent: 1, tokens: ["tok-9e5f"] });
    assert.deepEqual(sink.stats, { sent: 1, failed: 0, sendFailures: 0 });
  });

  it("accepts a 201 without a token as acceptance with no receipt", async () => {
    const client = new FakeClient();
    const sink = new BatchSink(baseConfig(client));
    const result = await sink.send([{ body: "{}", key: "k1" }]);
    assert.deepEqual(result, { ok: true, sent: 1, tokens: [] });
  });

  it("treats a non-201 2xx as a failure, since the docs promise 201", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 200);
    const sink = new BatchSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as BatchSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_200");
        assert.equal(failed[0].statusCode, 200);
        assert.equal(failed[0].retryable, false);
        return true;
      }
    );
  });

  it("throws with exactly the failed messages and their retry lanes", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 429);
    client.statusOn.set(2, 503);
    const sink = new BatchSink(baseConfig(client));
    await assert.rejects(
      sink.send([
        { body: "{}", key: "k1" },
        { body: "{}", key: "k2" },
        { body: "{}", key: "k3" },
      ]),
      (err: unknown) => {
        assert.ok(err instanceof BatchSinkError);
        assert.deepEqual(
          (err as BatchSinkError).failedRecords.map((f) => [f.index, f.errorCode, f.retryable]),
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

  it("treats bad recipients (400) as fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 400);
    const sink = new BatchSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as BatchSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_400");
        assert.equal(failed[0].statusCode, 400);
        assert.equal(failed[0].retryable, false);
        return true;
      }
    );
  });

  it("treats a bad REST API key (401) as fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 401);
    const sink = new BatchSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        assert.equal((err as BatchSinkError).failedRecords[0].retryable, false);
        return true;
      }
    );
  });

  it("treats a client throw as a retryable transport failure", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hang up"));
    const sink = new BatchSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as BatchSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(failed[0].retryable, true);
        assert.equal(failed[0].errorMessage, "socket hang up");
        return true;
      }
    );
  });

  it("throws a config error with no client, mapped non_retryable", async () => {
    const sink = new BatchSink({ recipients: { custom_ids: ["user-1"] } });
    await assert.rejects(sink.send([{ body: "{}", key: "k1" }]), BatchSinkConfigError);
    assert.equal(classifyFailure(new BatchSinkConfigError("no client injected")).failureClass, "non_retryable");
  });

  it("dry-runs with zero client I/O and untouched stats", async () => {
    const client = new FakeClient();
    const sink = new BatchSink(baseConfig(client, { dryRun: true }));
    const result = await sink.send([{ body: "{}", subject: "Price drop" }]);
    assert.deepEqual(result, { ok: true, sent: 0, tokens: [], dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("dry-runs still validate the config and the records", async () => {
    const client = new FakeClient();
    const sink = new BatchSink(baseConfig(client, { dryRun: true }));
    await assert.rejects(sink.send([{ body: "" }]), RangeError);
    assert.equal(client.posts.length, 0);
    assert.throws(
      () => new BatchSink({ recipients: {}, dryRun: true }),
      RangeError
    );
  });

  it("appends custom_payload under the opt-in, truncated at the default 2000", async () => {
    const client = new FakeClient();
    const sink = new BatchSink(baseConfig(client, { includePayload: true, payloadMaxChars: 10 }));
    await sink.send([{ body: "0123456789ABCDEF", subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.custom_payload, "0123456789… (truncated)");
    assert.equal(body.message.body, "Alert");

    const defaultClient = new FakeClient();
    const defaultSink = new BatchSink(baseConfig(defaultClient, { includePayload: true }));
    await defaultSink.send([{ body: "x".repeat(2001), subject: "Alert" }]);
    const defaultBody = JSON.parse(defaultClient.posts[0].body);
    assert.equal(defaultBody.custom_payload, `${"x".repeat(2000)}… (truncated)`);
  });

  it("omits custom_payload by default", async () => {
    const client = new FakeClient();
    const sink = new BatchSink(baseConfig(client));
    await sink.send([{ body: '{"secret":"s3cr3t"}', subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.message.body, "Alert");
    assert.equal(body.custom_payload, undefined);
    assert.equal(JSON.stringify(body).includes("s3cr3t"), false);
  });

  it("sends the configured group and all three recipient kinds", async () => {
    const client = new FakeClient();
    const sink = new BatchSink(
      baseConfig(client, {
        groupId: "orders",
        recipients: { tokens: ["t1"], custom_ids: ["u1"], install_ids: ["i1"] },
      })
    );
    await sink.send([{ body: "{}", key: "k1" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.group_id, "orders");
    assert.deepEqual(body.recipients, { tokens: ["t1"], custom_ids: ["u1"], install_ids: ["i1"] });
  });
});
