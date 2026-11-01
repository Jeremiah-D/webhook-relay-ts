import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  NovuSink,
  NovuSinkConfigError,
  NovuSinkError,
  assertValidNovuSinkConfig,
  buildNovuTriggerBody,
  classifyNovuRecordFailure,
  classifyNovuTriggerResponse,
  resolveNovuIdempotencyKey,
  resolveNovuPayload,
  resolveNovuRecipient,
  resolveNovuRecipients,
  resolveNovuRecord,
  resolveNovuSummary,
  resolveNovuWorkflowName,
  truncateNovuPayload,
  NOVU_DEFAULT_PAYLOAD_MAX_CHARS,
  NOVU_FALLBACK_SUMMARY,
  NOVU_JSON_CONTENT_TYPE,
  NOVU_MAX_RECIPIENTS,
  NOVU_TRIGGER_URL,
  type NovuRecipient,
  type NovuSinkConfig,
  type NovuTriggerClient,
  type NovuTriggerPostRequest,
  type NovuTriggerPostResponse,
} from "../src/novu-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements NovuTriggerClient {
  posts: NovuTriggerPostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → transaction id to return for that post. */
  transactionIdOn = new Map<number, string>();
  /** Call-count (0-based) → acknowledged flag to return for that post. */
  acknowledgedOn = new Map<number, boolean>();
  /** Call-count (0-based) → trigger status to return for that post. */
  triggerStatusOn = new Map<number, string>();
  /** Call-count (0-based) → error messages to return for that post. */
  errorsOn = new Map<number, string[]>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: NovuTriggerPostRequest): Promise<NovuTriggerPostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return {
      status: this.statusOn.get(n) ?? 201,
      transactionId: this.transactionIdOn.get(n),
      acknowledged: this.acknowledgedOn.get(n),
      triggerStatus: this.triggerStatusOn.get(n),
      errors: this.errorsOn.get(n),
    };
  }
}

function baseConfig(
  client: NovuTriggerClient,
  extra: Partial<NovuSinkConfig> = {}
): NovuSinkConfig {
  return { name: "order-shipped", to: "user-1", client, ...extra };
}

describe("novu-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidNovuSinkConfig(null, "NovuSink"), RangeError);
    assert.throws(() => assertValidNovuSinkConfig("x", "NovuSink"), RangeError);
  });

  it("requires a non-empty workflow name", () => {
    assert.throws(
      () => assertValidNovuSinkConfig({ to: "user-1", client: new FakeClient() }, "NovuSink"),
      RangeError
    );
    assert.throws(
      () => assertValidNovuSinkConfig(baseConfig(new FakeClient(), { name: "" }), "NovuSink"),
      RangeError
    );
    assert.throws(
      () => assertValidNovuSinkConfig(baseConfig(new FakeClient(), { name: 7 as never }), "NovuSink"),
      RangeError
    );
    assert.equal(resolveNovuWorkflowName("order-shipped", "NovuSink"), "order-shipped");
    assertValidNovuSinkConfig(baseConfig(new FakeClient()), "NovuSink");
  });

  it("requires at least one recipient and validates each form", () => {
    assert.throws(
      () => assertValidNovuSinkConfig({ name: "w", client: new FakeClient() }, "NovuSink"),
      RangeError
    );
    assert.throws(
      () => assertValidNovuSinkConfig(baseConfig(new FakeClient(), { to: "" }), "NovuSink"),
      RangeError
    );
    assert.throws(
      () => assertValidNovuSinkConfig(baseConfig(new FakeClient(), { to: [] }), "NovuSink"),
      RangeError
    );
    assert.throws(
      () => assertValidNovuSinkConfig(baseConfig(new FakeClient(), { to: {} }), "NovuSink"),
      RangeError
    );
    assert.throws(
      () =>
        assertValidNovuSinkConfig(
          baseConfig(new FakeClient(), { to: { subscriberId: "" } }),
          "NovuSink"
        ),
      RangeError
    );
    assert.throws(
      () =>
        assertValidNovuSinkConfig(
          baseConfig(new FakeClient(), { to: { type: "Topic", topicKey: "" } }),
          "NovuSink"
        ),
      RangeError
    );
    // There is no broadcast form: any other `type` fails.
    assert.throws(
      () =>
        assertValidNovuSinkConfig(
          baseConfig(new FakeClient(), { to: { type: "Broadcast" } as never }),
          "NovuSink"
        ),
      RangeError
    );
    assert.throws(
      () =>
        assertValidNovuSinkConfig(
          baseConfig(new FakeClient(), { to: { email: "a@example.com" } as never }),
          "NovuSink"
        ),
      RangeError
    );
    // More than the docs' 100-recipient cap fails.
    assert.throws(
      () =>
        assertValidNovuSinkConfig(
          baseConfig(new FakeClient(), {
            to: Array.from({ length: NOVU_MAX_RECIPIENTS + 1 }, (_, i) => `user-${i}`),
          }),
          "NovuSink"
        ),
      RangeError
    );
    assert.throws(
      () =>
        assertValidNovuSinkConfig(
          baseConfig(new FakeClient(), {
            to: { subscriberId: "u1", email: 7 as never },
          }),
          "NovuSink"
        ),
      RangeError
    );
    assert.throws(
      () =>
        assertValidNovuSinkConfig(
          baseConfig(new FakeClient(), {
            to: { subscriberId: "u1", data: "x" as never },
          }),
          "NovuSink"
        ),
      RangeError
    );
    assert.equal(NOVU_MAX_RECIPIENTS, 100);
    assert.deepEqual(resolveNovuRecipient("user-1", "NovuSink"), "user-1");
    assert.deepEqual(resolveNovuRecipient({ subscriberId: "u1", email: "a@example.com" }, "NovuSink"), {
      subscriberId: "u1",
      email: "a@example.com",
    });
    assert.deepEqual(resolveNovuRecipient({ type: "Topic", topicKey: "orders" }, "NovuSink"), {
      type: "Topic",
      topicKey: "orders",
    });
    assert.deepEqual(
      resolveNovuRecipients(["u1", { type: "Topic", topicKey: "orders" }], "NovuSink"),
      ["u1", { type: "Topic", topicKey: "orders" }]
    );
    assertValidNovuSinkConfig(
      baseConfig(new FakeClient(), {
        to: ["u1", { subscriberId: "u2", firstName: "Ada" }, { type: "Topic", topicKey: "orders" }],
      }),
      "NovuSink"
    );
  });

  it("rejects a malformed client and payloadMaxChars", () => {
    assert.throws(
      () => assertValidNovuSinkConfig(baseConfig(new FakeClient(), { client: {} as never }), "NovuSink"),
      RangeError
    );
    assert.throws(
      () => assertValidNovuSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 0 }), "NovuSink"),
      RangeError
    );
    assert.throws(
      () => assertValidNovuSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 1.5 }), "NovuSink"),
      RangeError
    );
  });
});

describe("novu-sink resolvers", () => {
  it("hands the client the trigger URL (no credential in it)", () => {
    assert.equal(NOVU_TRIGGER_URL, "https://api.novu.co/v1/events/trigger");
    assert.equal(NOVU_TRIGGER_URL.includes("ApiKey"), false);
    assert.equal(NOVU_TRIGGER_URL.includes("secret"), false);
  });

  it("derives the summary from subject, key, then traceId", () => {
    assert.equal(resolveNovuSummary({ body: "{}", subject: "Price drop", key: "k", traceId: "t" }), "Price drop");
    assert.equal(resolveNovuSummary({ body: "{}", key: "order-1", traceId: "t" }), "order-1");
    assert.equal(resolveNovuSummary({ body: "{}", traceId: "trace-9" }), "trace-9");
    assert.equal(resolveNovuSummary({ body: "{}" }), NOVU_FALLBACK_SUMMARY);
  });

  it("derives the payload with title from subject only and body from the chain", () => {
    assert.deepEqual(resolveNovuPayload({ body: "{}", subject: "Price drop", key: "k" }, {}), {
      body: "Price drop",
      title: "Price drop",
    });
    // No subject: the title is omitted, the body falls back to the chain.
    assert.deepEqual(resolveNovuPayload({ body: "{}", key: "order-1" }, {}), { body: "order-1" });
    assert.deepEqual(resolveNovuPayload({ body: "{}" }, {}), { body: NOVU_FALLBACK_SUMMARY });
  });

  it("appends eventBody only under the opt-in, truncated at the default 2000", () => {
    const withPayload = resolveNovuPayload({ body: '{"a":1}', subject: "Price drop" }, { includePayload: true });
    assert.equal(withPayload.eventBody, '{"a":1}');
    assert.equal(NOVU_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
    assert.equal(truncateNovuPayload("abcdef", 4), "abcd… (truncated)");
    assert.equal(truncateNovuPayload("abc", 4), "abc");
    const long = resolveNovuPayload({ body: "x".repeat(2001), subject: "Alert" }, { includePayload: true });
    assert.equal(long.eventBody, `${"x".repeat(2000)}… (truncated)`);
    const short = resolveNovuPayload({ body: "0123456789ABCDEF", subject: "Alert" }, { includePayload: true, payloadMaxChars: 10 });
    assert.equal(short.eventBody, "0123456789… (truncated)");
  });

  it("builds the trigger body with name, to, and payload", () => {
    const body = JSON.parse(
      buildNovuTriggerBody(
        "order-shipped",
        "user-1",
        { title: "Price drop", body: "Price drop" }
      )
    );
    assert.equal(body.name, "order-shipped");
    assert.equal(body.to, "user-1");
    assert.deepEqual(body.payload, { title: "Price drop", body: "Price drop" });
    assert.equal(body.payload.eventBody, undefined);
    // No credential ever enters the body.
    assert.equal(JSON.stringify(body).includes("Authorization"), false);
    assert.equal(JSON.stringify(body).includes("ApiKey"), false);
    assert.equal(JSON.stringify(body).includes("secret"), false);
  });

  it("builds the trigger body for a topic recipient and an array", () => {
    const topic = JSON.parse(
      buildNovuTriggerBody("announce", { type: "Topic", topicKey: "orders" }, { body: "order-1" })
    );
    assert.deepEqual(topic.to, { type: "Topic", topicKey: "orders" });
    const multi = JSON.parse(
      buildNovuTriggerBody("announce", ["u1", { subscriberId: "u2", email: "a@example.com" }], { body: "x" })
    );
    assert.deepEqual(multi.to, ["u1", { subscriberId: "u2", email: "a@example.com" }]);
  });

  it("appends eventBody inside payload under the opt-in", () => {
    const body = JSON.parse(
      buildNovuTriggerBody("w", "u1", { body: "Alert", eventBody: '{"a":1}' })
    );
    assert.equal(body.payload.eventBody, '{"a":1}');
    assert.equal(typeof body.payload.eventBody, "string");
  });

  it("derives a deterministic idempotency key, distinct per record and per target", () => {
    const record = { body: '{"a":1}', subject: "Alert", traceId: "t1" };
    const key1 = resolveNovuIdempotencyKey("w", "u1", record);
    const key2 = resolveNovuIdempotencyKey("w", "u1", record);
    assert.equal(key1, key2);
    assert.equal(key1.startsWith("novu-trigger-"), true);
    assert.equal(key1.length <= 255, true);
    // A different record gets a different key.
    assert.notEqual(
      key1,
      resolveNovuIdempotencyKey("w", "u1", { body: '{"a":2}', subject: "Alert", traceId: "t1" })
    );
    // The same event sent to a different workflow or recipient set gets a different key.
    assert.notEqual(key1, resolveNovuIdempotencyKey("other-workflow", "u1", record));
    assert.notEqual(key1, resolveNovuIdempotencyKey("w", "u2", record));
  });

  it("rejects an empty record body", () => {
    assert.throws(() => resolveNovuRecord({ body: "" }, 0), RangeError);
    assert.deepEqual(resolveNovuRecord({ body: "{}" }, 2), { index: 2 });
  });
});

describe("novu-sink failure mapping", () => {
  it("maps 429 and 5xx to retryable, other non-201 to fail-closed", () => {
    assert.equal(classifyNovuRecordFailure(429), true);
    assert.equal(classifyNovuRecordFailure(500), true);
    assert.equal(classifyNovuRecordFailure(503), true);
    assert.equal(classifyNovuRecordFailure(400), false);
    assert.equal(classifyNovuRecordFailure(401), false);
    assert.equal(classifyNovuRecordFailure(404), false);
    assert.equal(classifyNovuRecordFailure(409), false);
    assert.equal(classifyNovuRecordFailure(200), false);
  });

  it("accepts a 201, with or without the body's verdict surfaced", () => {
    assert.deepEqual(classifyNovuTriggerResponse({ status: 201 }), { accepted: true });
    assert.deepEqual(
      classifyNovuTriggerResponse({ status: 201, acknowledged: true, triggerStatus: "processed", transactionId: "tx-1" }),
      { accepted: true }
    );
  });

  it("rejects a 201 whose body says the trigger was not processed", () => {
    assert.deepEqual(
      classifyNovuTriggerResponse({ status: 201, acknowledged: true, triggerStatus: "trigger_not_active" }),
      { accepted: false, errorCode: "NOVU_TRIGGER_NOT_ACTIVE", retryable: false }
    );
    assert.deepEqual(
      classifyNovuTriggerResponse({
        status: 201,
        acknowledged: true,
        triggerStatus: "invalid_recipients",
        errors: ["subscriber not found"],
      }),
      {
        accepted: false,
        errorCode: "NOVU_INVALID_RECIPIENTS",
        retryable: false,
        errorMessage: "subscriber not found",
      }
    );
    assert.deepEqual(
      classifyNovuTriggerResponse({ status: 201, acknowledged: false, triggerStatus: "error" }),
      { accepted: false, errorCode: "NOVU_NOT_ACKNOWLEDGED", retryable: false }
    );
    assert.deepEqual(
      classifyNovuTriggerResponse({ status: 201, acknowledged: true, triggerStatus: "no_workflow_steps_defined" }),
      { accepted: false, errorCode: "NOVU_NO_WORKFLOW_STEPS_DEFINED", retryable: false }
    );
  });

  it("maps a non-201 status to its HTTP code and lane", () => {
    assert.deepEqual(classifyNovuTriggerResponse({ status: 429 }), {
      accepted: false,
      errorCode: "HTTP_429",
      retryable: true,
    });
    assert.deepEqual(classifyNovuTriggerResponse({ status: 409 }), {
      accepted: false,
      errorCode: "HTTP_409",
      retryable: false,
    });
    assert.deepEqual(classifyNovuTriggerResponse({ status: 200 }), {
      accepted: false,
      errorCode: "HTTP_200",
      retryable: false,
    });
  });
});

describe("novu-sink send", () => {
  it("posts one trigger per message with no credentials", async () => {
    const client = new FakeClient();
    client.transactionIdOn.set(0, "tx-1111");
    client.transactionIdOn.set(1, "tx-2222");
    const sink = new NovuSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "Price drop", key: "order-1" },
      { body: '{"b":2}', key: "order-2" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2, transactionIds: ["tx-1111", "tx-2222"] });
    assert.equal(client.posts.length, 2);
    const first = client.posts[0];
    assert.equal(first.url, NOVU_TRIGGER_URL);
    assert.equal(first.headers["Content-Type"], NOVU_JSON_CONTENT_TYPE);
    assert.equal(typeof first.headers["Idempotency-Key"], "string");
    assert.equal(first.headers["Idempotency-Key"].startsWith("novu-trigger-"), true);
    assert.equal(first.headers["Authorization"], undefined);
    const body = JSON.parse(first.body);
    assert.equal(body.name, "order-shipped");
    assert.equal(body.to, "user-1");
    assert.deepEqual(body.payload, { title: "Price drop", body: "Price drop" });
    assert.equal(body.payload.eventBody, undefined);
    // The two messages carry distinct idempotency keys.
    assert.notEqual(first.headers["Idempotency-Key"], client.posts[1].headers["Idempotency-Key"]);
    // No credential ever enters the handed request.
    assert.equal(JSON.stringify(first).includes("Authorization"), false);
    assert.equal(JSON.stringify(first).includes("ApiKey"), false);
    assert.equal(JSON.stringify(first).includes("secret"), false);
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("accepts a 201 as acceptance and returns its transaction id receipt", async () => {
    const client = new FakeClient();
    client.transactionIdOn.set(0, "tx-9e5f");
    client.triggerStatusOn.set(0, "processed");
    client.acknowledgedOn.set(0, true);
    const sink = new NovuSink(baseConfig(client));
    const result = await sink.send([{ body: "{}", key: "k1" }]);
    assert.deepEqual(result, { ok: true, sent: 1, transactionIds: ["tx-9e5f"] });
    assert.deepEqual(sink.stats, { sent: 1, failed: 0, sendFailures: 0 });
  });

  it("accepts a 201 without a transaction id as acceptance with no receipt", async () => {
    const client = new FakeClient();
    const sink = new NovuSink(baseConfig(client));
    const result = await sink.send([{ body: "{}", key: "k1" }]);
    assert.deepEqual(result, { ok: true, sent: 1, transactionIds: [] });
  });

  it("treats a non-201 2xx as a failure, since the docs promise 201", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 200);
    const sink = new NovuSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as NovuSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_200");
        assert.equal(failed[0].statusCode, 200);
        assert.equal(failed[0].retryable, false);
        return true;
      }
    );
  });

  it("treats a 201 with an unpublished workflow as a fail-closed failure", async () => {
    const client = new FakeClient();
    client.triggerStatusOn.set(0, "trigger_not_active");
    client.acknowledgedOn.set(0, true);
    const sink = new NovuSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as NovuSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "NOVU_TRIGGER_NOT_ACTIVE");
        assert.equal(failed[0].statusCode, undefined);
        assert.equal(failed[0].retryable, false);
        return true;
      }
    );
    assert.deepEqual(sink.stats, { sent: 0, failed: 1, sendFailures: 1 });
  });

  it("throws with exactly the failed messages and their retry lanes", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 429);
    client.statusOn.set(2, 503);
    const sink = new NovuSink(baseConfig(client));
    await assert.rejects(
      sink.send([
        { body: "{}", key: "k1" },
        { body: "{}", key: "k2" },
        { body: "{}", key: "k3" },
      ]),
      (err: unknown) => {
        assert.ok(err instanceof NovuSinkError);
        assert.deepEqual(
          (err as NovuSinkError).failedRecords.map((f) => [f.index, f.errorCode, f.retryable]),
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
    const sink = new NovuSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as NovuSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_400");
        assert.equal(failed[0].statusCode, 400);
        assert.equal(failed[0].retryable, false);
        return true;
      }
    );
  });

  it("treats a bad secret key (401) as fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 401);
    const sink = new NovuSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        assert.equal((err as NovuSinkError).failedRecords[0].retryable, false);
        return true;
      }
    );
  });

  it("treats an in-progress duplicate (409) as fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 409);
    const sink = new NovuSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as NovuSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_409");
        assert.equal(failed[0].statusCode, 409);
        assert.equal(failed[0].retryable, false);
        return true;
      }
    );
  });

  it("treats a client throw as a retryable transport failure", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hang up"));
    const sink = new NovuSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as NovuSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(failed[0].retryable, true);
        assert.equal(failed[0].errorMessage, "socket hang up");
        return true;
      }
    );
  });

  it("throws a config error with no client, mapped non_retryable", async () => {
    const sink = new NovuSink({ name: "order-shipped", to: "user-1" });
    await assert.rejects(sink.send([{ body: "{}", key: "k1" }]), NovuSinkConfigError);
    assert.equal(classifyFailure(new NovuSinkConfigError("no client injected")).failureClass, "non_retryable");
  });

  it("dry-runs with zero client I/O and untouched stats", async () => {
    const client = new FakeClient();
    const sink = new NovuSink(baseConfig(client, { dryRun: true }));
    const result = await sink.send([{ body: "{}", subject: "Price drop" }]);
    assert.deepEqual(result, { ok: true, sent: 0, transactionIds: [], dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("dry-runs still validate the config and the records", async () => {
    const client = new FakeClient();
    const sink = new NovuSink(baseConfig(client, { dryRun: true }));
    await assert.rejects(sink.send([{ body: "" }]), RangeError);
    assert.equal(client.posts.length, 0);
    assert.throws(
      () => new NovuSink({ name: "w", to: [], dryRun: true }),
      RangeError
    );
  });

  it("appends eventBody under the opt-in, truncated at the default 2000", async () => {
    const client = new FakeClient();
    const sink = new NovuSink(baseConfig(client, { includePayload: true, payloadMaxChars: 10 }));
    await sink.send([{ body: "0123456789ABCDEF", subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.payload.eventBody, "0123456789… (truncated)");
    assert.equal(body.payload.body, "Alert");

    const defaultClient = new FakeClient();
    const defaultSink = new NovuSink(baseConfig(defaultClient, { includePayload: true }));
    await defaultSink.send([{ body: "x".repeat(2001), subject: "Alert" }]);
    const defaultBody = JSON.parse(defaultClient.posts[0].body);
    assert.equal(defaultBody.payload.eventBody, `${"x".repeat(2000)}… (truncated)`);
  });

  it("omits eventBody by default", async () => {
    const client = new FakeClient();
    const sink = new NovuSink(baseConfig(client));
    await sink.send([{ body: '{"secret":"s3cr3t"}', subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.payload.body, "Alert");
    assert.equal(body.payload.eventBody, undefined);
    assert.equal(JSON.stringify(body).includes("s3cr3t"), false);
  });

  it("sends to a topic recipient and a subscriber object", async () => {
    const client = new FakeClient();
    const sink = new NovuSink(
      baseConfig(client, {
        to: { type: "Topic", topicKey: "orders" },
      })
    );
    await sink.send([{ body: "{}", key: "k1" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.deepEqual(body.to, { type: "Topic", topicKey: "orders" });

    const objectClient = new FakeClient();
    const objectSink = new NovuSink(
      baseConfig(objectClient, {
        to: { subscriberId: "u2", firstName: "Ada", email: "a@example.com" },
      })
    );
    await objectSink.send([{ body: "{}", key: "k1" }]);
    const objectBody = JSON.parse(objectClient.posts[0].body);
    assert.deepEqual(objectBody.to, { subscriberId: "u2", firstName: "Ada", email: "a@example.com" });
  });

  it("replays the same idempotency key for the same record", async () => {
    const client = new FakeClient();
    const sink = new NovuSink(baseConfig(client));
    const record = { body: '{"a":1}', subject: "Alert", traceId: "t1" };
    await sink.send([record]);
    await sink.send([record]);
    assert.equal(client.posts.length, 2);
    assert.equal(client.posts[0].headers["Idempotency-Key"], client.posts[1].headers["Idempotency-Key"]);
  });
});
