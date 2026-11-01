import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  SuprSendSink,
  SuprSendSinkConfigError,
  SuprSendSinkError,
  assertValidSuprSendSinkConfig,
  buildSuprSendTriggerBody,
  classifySuprSendRecordFailure,
  classifySuprSendTriggerResponse,
  resolveSuprSendCancellationKey,
  resolveSuprSendData,
  resolveSuprSendIdempotencyKey,
  resolveSuprSendRecipient,
  resolveSuprSendRecipients,
  resolveSuprSendRecord,
  resolveSuprSendSummary,
  resolveSuprSendTenantId,
  resolveSuprSendWorkflow,
  truncateSuprSendPayload,
  SUPRSEND_API_BASE_URL,
  SUPRSEND_DEFAULT_PAYLOAD_MAX_CHARS,
  SUPRSEND_FALLBACK_SUMMARY,
  SUPRSEND_JSON_CONTENT_TYPE,
  SUPRSEND_MAX_RECIPIENTS,
  SUPRSEND_TRIGGER_URL,
  type SuprSendRecipient,
  type SuprSendSinkConfig,
  type SuprSendTriggerClient,
  type SuprSendTriggerPostRequest,
  type SuprSendTriggerPostResponse,
} from "../src/suprsend-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status and body verdict per call. */
class FakeClient implements SuprSendTriggerClient {
  posts: SuprSendTriggerPostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → body `success` verdict to return for that post. */
  successOn = new Map<number, boolean>();
  /** Call-count (0-based) → body `message` to return for that post. */
  messageOn = new Map<number, string>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: SuprSendTriggerPostRequest): Promise<SuprSendTriggerPostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return {
      status: this.statusOn.get(n) ?? 201,
      success: this.successOn.get(n) ?? true,
      bodyStatus: (this.successOn.get(n) ?? true) ? "success" : "fail",
      message: this.messageOn.get(n),
    };
  }
}

function baseConfig(
  client: SuprSendTriggerClient,
  extra: Partial<SuprSendSinkConfig> = {}
): SuprSendSinkConfig {
  return { workflow: "purchase-made", recipients: ["user-1"], client, ...extra };
}

describe("suprsend-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidSuprSendSinkConfig(null, "SuprSendSink"), RangeError);
    assert.throws(() => assertValidSuprSendSinkConfig("x", "SuprSendSink"), RangeError);
  });

  it("requires a non-empty workflow slug", () => {
    assert.throws(
      () => assertValidSuprSendSinkConfig({ recipients: ["user-1"], client: new FakeClient() }, "SuprSendSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSuprSendSinkConfig(baseConfig(new FakeClient(), { workflow: "" }), "SuprSendSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSuprSendSinkConfig(baseConfig(new FakeClient(), { workflow: 7 as never }), "SuprSendSink"),
      RangeError
    );
    assert.equal(resolveSuprSendWorkflow("purchase-made", "SuprSendSink"), "purchase-made");
    assertValidSuprSendSinkConfig(baseConfig(new FakeClient()), "SuprSendSink");
  });

  it("requires at least one recipient and validates each form", () => {
    assert.throws(
      () => assertValidSuprSendSinkConfig({ workflow: "w", client: new FakeClient() }, "SuprSendSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSuprSendSinkConfig(baseConfig(new FakeClient(), { recipients: [] }), "SuprSendSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSuprSendSinkConfig(baseConfig(new FakeClient(), { recipients: "user-1" as never }), "SuprSendSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSuprSendSinkConfig(baseConfig(new FakeClient(), { recipients: [""] }), "SuprSendSink"),
      RangeError
    );
    assert.throws(
      () =>
        assertValidSuprSendSinkConfig(
          baseConfig(new FakeClient(), { recipients: [{}] }),
          "SuprSendSink"
        ),
      RangeError
    );
    assert.throws(
      () =>
        assertValidSuprSendSinkConfig(
          baseConfig(new FakeClient(), { recipients: [{ distinct_id: "" }] }),
          "SuprSendSink"
        ),
      RangeError
    );
    // An object keyed by `id` (the Knock shape) is not a
    // SuprSend recipient: SuprSend identifies recipients by
    // `distinct_id`.
    assert.throws(
      () =>
        assertValidSuprSendSinkConfig(
          baseConfig(new FakeClient(), { recipients: [{ id: "u1" } as never] }),
          "SuprSendSink"
        ),
      RangeError
    );
    // More than the docs' 100-recipient cap fails.
    assert.throws(
      () =>
        assertValidSuprSendSinkConfig(
          baseConfig(new FakeClient(), {
            recipients: Array.from({ length: SUPRSEND_MAX_RECIPIENTS + 1 }, (_, i) => `user-${i}`),
          }),
          "SuprSendSink"
        ),
      RangeError
    );
    assert.equal(SUPRSEND_MAX_RECIPIENTS, 100);
    assert.deepEqual(resolveSuprSendRecipient("user-1", "SuprSendSink"), "user-1");
    assert.deepEqual(resolveSuprSendRecipient({ distinct_id: "u1", name: "Ada" }, "SuprSendSink"), {
      distinct_id: "u1",
      name: "Ada",
    });
    assert.deepEqual(
      resolveSuprSendRecipient({ distinct_id: "u1", $email: ["a@example.com"] }, "SuprSendSink"),
      { distinct_id: "u1", $email: ["a@example.com"] }
    );
    assert.deepEqual(
      resolveSuprSendRecipients(["u1", { distinct_id: "u2", name: "Ada" }], "SuprSendSink"),
      ["u1", { distinct_id: "u2", name: "Ada" }]
    );
    assertValidSuprSendSinkConfig(
      baseConfig(new FakeClient(), {
        recipients: ["u1", { distinct_id: "u2", $email: ["a@example.com"] }],
      }),
      "SuprSendSink"
    );
  });

  it("validates the optional actor, tenant id, and cancellation key", () => {
    assert.throws(
      () => assertValidSuprSendSinkConfig(baseConfig(new FakeClient(), { actor: "" }), "SuprSendSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSuprSendSinkConfig(baseConfig(new FakeClient(), { actor: {} as never }), "SuprSendSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSuprSendSinkConfig(baseConfig(new FakeClient(), { tenantId: "" }), "SuprSendSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSuprSendSinkConfig(baseConfig(new FakeClient(), { tenantId: 7 as never }), "SuprSendSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSuprSendSinkConfig(baseConfig(new FakeClient(), { cancellationKey: "" }), "SuprSendSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSuprSendSinkConfig(baseConfig(new FakeClient(), { cancellationKey: 7 as never }), "SuprSendSink"),
      RangeError
    );
    assert.equal(resolveSuprSendTenantId("brand-01", "SuprSendSink"), "brand-01");
    assert.equal(resolveSuprSendTenantId(undefined, "SuprSendSink"), undefined);
    assert.equal(resolveSuprSendCancellationKey("cancel_123", "SuprSendSink"), "cancel_123");
    assert.equal(resolveSuprSendCancellationKey(undefined, "SuprSendSink"), undefined);
    assertValidSuprSendSinkConfig(
      baseConfig(new FakeClient(), { actor: "admin-1", tenantId: "brand-01", cancellationKey: "cancel_123" }),
      "SuprSendSink"
    );
    assertValidSuprSendSinkConfig(
      baseConfig(new FakeClient(), { actor: { distinct_id: "admin-1", name: "Ada" } }),
      "SuprSendSink"
    );
  });

  it("rejects a malformed client and payloadMaxChars", () => {
    assert.throws(
      () => assertValidSuprSendSinkConfig(baseConfig(new FakeClient(), { client: {} as never }), "SuprSendSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSuprSendSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 0 }), "SuprSendSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSuprSendSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 1.5 }), "SuprSendSink"),
      RangeError
    );
  });
});

describe("suprsend-sink resolvers", () => {
  it("uses the fixed trigger URL with no credential in it", () => {
    assert.equal(SUPRSEND_API_BASE_URL, "https://hub.suprsend.com");
    assert.equal(SUPRSEND_TRIGGER_URL, "https://hub.suprsend.com/trigger/");
    assert.equal(SUPRSEND_TRIGGER_URL.includes("Bearer"), false);
    assert.equal(SUPRSEND_TRIGGER_URL.includes("secret"), false);
    assert.equal(SUPRSEND_TRIGGER_URL.includes("purchase-made"), false);
  });

  it("derives the summary from subject, key, then traceId", () => {
    assert.equal(resolveSuprSendSummary({ body: "{}", subject: "Price drop", key: "k", traceId: "t" }), "Price drop");
    assert.equal(resolveSuprSendSummary({ body: "{}", key: "order-1", traceId: "t" }), "order-1");
    assert.equal(resolveSuprSendSummary({ body: "{}", traceId: "trace-9" }), "trace-9");
    assert.equal(resolveSuprSendSummary({ body: "{}" }), SUPRSEND_FALLBACK_SUMMARY);
  });

  it("derives the data map with title from subject only and body from the chain", () => {
    assert.deepEqual(resolveSuprSendData({ body: "{}", subject: "Price drop", key: "k" }, {}), {
      body: "Price drop",
      title: "Price drop",
    });
    // No subject: the title is omitted, the body falls back to the chain.
    assert.deepEqual(resolveSuprSendData({ body: "{}", key: "order-1" }, {}), { body: "order-1" });
    assert.deepEqual(resolveSuprSendData({ body: "{}" }, {}), { body: SUPRSEND_FALLBACK_SUMMARY });
  });

  it("appends eventBody only under the opt-in, truncated at the default 2000", () => {
    const withPayload = resolveSuprSendData({ body: '{"a":1}', subject: "Price drop" }, { includePayload: true });
    assert.equal(withPayload.eventBody, '{"a":1}');
    assert.equal(SUPRSEND_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
    assert.equal(truncateSuprSendPayload("abcdef", 4), "abcd… (truncated)");
    assert.equal(truncateSuprSendPayload("abc", 4), "abc");
    const long = resolveSuprSendData({ body: "x".repeat(2001), subject: "Alert" }, { includePayload: true });
    assert.equal(long.eventBody, `${"x".repeat(2000)}… (truncated)`);
    const short = resolveSuprSendData({ body: "0123456789ABCDEF", subject: "Alert" }, { includePayload: true, payloadMaxChars: 10 });
    assert.equal(short.eventBody, "0123456789… (truncated)");
  });

  it("builds the trigger body with workflow, recipients, data, and idempotency key", () => {
    const body = JSON.parse(
      buildSuprSendTriggerBody(
        "purchase-made",
        ["user-1"],
        { title: "Price drop", body: "Price drop" },
        "suprsend-trigger-abc123"
      )
    );
    assert.equal(body.workflow, "purchase-made");
    assert.deepEqual(body.recipients, ["user-1"]);
    assert.deepEqual(body.data, { title: "Price drop", body: "Price drop" });
    assert.equal(body.idempotency_key, "suprsend-trigger-abc123");
    assert.equal(body.data.eventBody, undefined);
    assert.equal(body.actor, undefined);
    assert.equal(body.tenant_id, undefined);
    assert.equal(body.cancellation_key, undefined);
    // No credential ever enters the body.
    assert.equal(JSON.stringify(body).includes("Authorization"), false);
    assert.equal(JSON.stringify(body).includes("Bearer"), false);
    assert.equal(JSON.stringify(body).includes("secret"), false);
  });

  it("builds the trigger body with an object recipient, actor, tenant, and cancellation key", () => {
    const body = JSON.parse(
      buildSuprSendTriggerBody(
        "purchase-made",
        [{ distinct_id: "u1", name: "Ada", $email: ["a@example.com"] }],
        { body: "order-1" },
        "suprsend-trigger-abc123",
        { distinct_id: "admin-1" },
        "brand-01",
        "cancel_123"
      )
    );
    assert.deepEqual(body.recipients, [
      { distinct_id: "u1", name: "Ada", $email: ["a@example.com"] },
    ]);
    assert.deepEqual(body.actor, { distinct_id: "admin-1" });
    assert.equal(body.tenant_id, "brand-01");
    assert.equal(body.cancellation_key, "cancel_123");
  });

  it("appends eventBody inside data under the opt-in", () => {
    const body = JSON.parse(
      buildSuprSendTriggerBody("w", ["u1"], { body: "Alert", eventBody: '{"a":1}' }, "suprsend-trigger-k")
    );
    assert.equal(body.data.eventBody, '{"a":1}');
    assert.equal(typeof body.data.eventBody, "string");
  });

  it("derives a deterministic idempotency key, distinct per record and per target", () => {
    const record = { body: '{"a":1}', subject: "Alert", traceId: "t1" };
    const key1 = resolveSuprSendIdempotencyKey("w", ["u1"], record);
    const key2 = resolveSuprSendIdempotencyKey("w", ["u1"], record);
    assert.equal(key1, key2);
    assert.equal(key1.startsWith("suprsend-trigger-"), true);
    assert.equal(key1.length <= 255, true);
    assert.equal(key1.includes(" "), false);
    // A different record gets a different key.
    assert.notEqual(
      key1,
      resolveSuprSendIdempotencyKey("w", ["u1"], { body: '{"a":2}', subject: "Alert", traceId: "t1" })
    );
    // The same event sent to a different workflow or recipient set gets a different key.
    assert.notEqual(key1, resolveSuprSendIdempotencyKey("other-workflow", ["u1"], record));
    assert.notEqual(key1, resolveSuprSendIdempotencyKey("w", ["u2"], record));
  });

  it("rejects an empty record body", () => {
    assert.throws(() => resolveSuprSendRecord({ body: "" }, 0), RangeError);
    assert.deepEqual(resolveSuprSendRecord({ body: "{}" }, 2), { index: 2 });
  });
});

describe("suprsend-sink failure mapping", () => {
  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", () => {
    assert.equal(classifySuprSendRecordFailure(429), true);
    assert.equal(classifySuprSendRecordFailure(500), true);
    assert.equal(classifySuprSendRecordFailure(503), true);
    assert.equal(classifySuprSendRecordFailure(400), false);
    assert.equal(classifySuprSendRecordFailure(401), false);
    assert.equal(classifySuprSendRecordFailure(403), false);
    assert.equal(classifySuprSendRecordFailure(404), false);
    assert.equal(classifySuprSendRecordFailure(201), false);
  });

  it("accepts a 2xx with success true, on 200 and on 201", () => {
    assert.deepEqual(classifySuprSendTriggerResponse({ status: 201, success: true }), { accepted: true });
    assert.deepEqual(classifySuprSendTriggerResponse({ status: 200, success: true, bodyStatus: "success" }), { accepted: true });
  });

  it("rejects a 2xx whose body does not say success", () => {
    assert.deepEqual(classifySuprSendTriggerResponse({ status: 201, success: false, bodyStatus: "fail", message: "workflow not found" }), {
      accepted: false,
      errorCode: "SUPRSEND_NOT_SUCCESS",
      retryable: false,
      errorMessage: "workflow not found",
    });
    // No body verdict at all is not an acceptance either.
    assert.deepEqual(classifySuprSendTriggerResponse({ status: 201 }), {
      accepted: false,
      errorCode: "SUPRSEND_NOT_SUCCESS",
      retryable: false,
    });
  });

  it("maps a non-2xx status to its HTTP code and lane", () => {
    assert.deepEqual(classifySuprSendTriggerResponse({ status: 429, message: "slow down" }), {
      accepted: false,
      errorCode: "HTTP_429",
      retryable: true,
      errorMessage: "slow down",
    });
    assert.deepEqual(classifySuprSendTriggerResponse({ status: 403 }), {
      accepted: false,
      errorCode: "HTTP_403",
      retryable: false,
    });
    assert.deepEqual(
      classifySuprSendTriggerResponse({ status: 400, success: false, message: "recipients is required" }),
      {
        accepted: false,
        errorCode: "HTTP_400",
        retryable: false,
        errorMessage: "recipients is required",
      }
    );
  });
});

describe("suprsend-sink send", () => {
  it("posts one trigger per message with no credentials", async () => {
    const client = new FakeClient();
    const sink = new SuprSendSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "Price drop", key: "order-1" },
      { body: '{"b":2}', key: "order-2" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    const first = client.posts[0];
    assert.equal(first.url, "https://hub.suprsend.com/trigger/");
    assert.equal(first.headers["Content-Type"], SUPRSEND_JSON_CONTENT_TYPE);
    assert.equal(first.headers["Authorization"], undefined);
    const body = JSON.parse(first.body);
    assert.equal(body.workflow, "purchase-made");
    assert.deepEqual(body.recipients, ["user-1"]);
    assert.deepEqual(body.data, { title: "Price drop", body: "Price drop" });
    assert.equal(body.data.eventBody, undefined);
    // The idempotency key rides in the body (not a header),
    // and the two messages carry distinct keys.
    assert.equal(typeof body.idempotency_key, "string");
    assert.equal(body.idempotency_key.startsWith("suprsend-trigger-"), true);
    assert.notEqual(body.idempotency_key, JSON.parse(client.posts[1].body).idempotency_key);
    // No credential ever enters the handed request.
    assert.equal(JSON.stringify(first).includes("Authorization"), false);
    assert.equal(JSON.stringify(first).includes("Bearer"), false);
    assert.equal(JSON.stringify(first).includes("secret"), false);
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("accepts a 200 with success true as acceptance", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 200);
    const sink = new SuprSendSink(baseConfig(client));
    const result = await sink.send([{ body: "{}", key: "k1" }]);
    assert.deepEqual(result, { ok: true, sent: 1 });
    assert.deepEqual(sink.stats, { sent: 1, failed: 0, sendFailures: 0 });
  });

  it("treats a 2xx with success false as a fail-closed failure", async () => {
    const client = new FakeClient();
    client.successOn.set(0, false);
    client.messageOn.set(0, "workflow not found");
    const sink = new SuprSendSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as SuprSendSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "SUPRSEND_NOT_SUCCESS");
        assert.equal(failed[0].statusCode, undefined);
        assert.equal(failed[0].retryable, false);
        assert.equal(failed[0].errorMessage, "workflow not found");
        return true;
      }
    );
  });

  it("throws with exactly the failed messages and their retry lanes", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 429);
    client.statusOn.set(2, 503);
    const sink = new SuprSendSink(baseConfig(client));
    await assert.rejects(
      sink.send([
        { body: "{}", key: "k1" },
        { body: "{}", key: "k2" },
        { body: "{}", key: "k3" },
      ]),
      (err: unknown) => {
        assert.ok(err instanceof SuprSendSinkError);
        assert.deepEqual(
          (err as SuprSendSinkError).failedRecords.map((f) => [f.index, f.errorCode, f.retryable]),
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

  it("treats bad recipients (400) as fail-closed, surfacing the body's message", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 400);
    client.messageOn.set(0, "recipients is required");
    const sink = new SuprSendSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as SuprSendSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_400");
        assert.equal(failed[0].statusCode, 400);
        assert.equal(failed[0].retryable, false);
        assert.equal(failed[0].errorMessage, "recipients is required");
        return true;
      }
    );
  });

  it("treats a bad API key (401) and insufficient permissions (403) as fail-closed", async () => {
    const client401 = new FakeClient();
    client401.statusOn.set(0, 401);
    const sink401 = new SuprSendSink(baseConfig(client401));
    await assert.rejects(
      sink401.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        assert.equal((err as SuprSendSinkError).failedRecords[0].retryable, false);
        return true;
      }
    );
    const client403 = new FakeClient();
    client403.statusOn.set(0, 403);
    const sink403 = new SuprSendSink(baseConfig(client403));
    await assert.rejects(
      sink403.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        assert.equal((err as SuprSendSinkError).failedRecords[0].errorCode, "HTTP_403");
        assert.equal((err as SuprSendSinkError).failedRecords[0].retryable, false);
        return true;
      }
    );
  });

  it("treats an unknown workflow (404) as fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 404);
    const sink = new SuprSendSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as SuprSendSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_404");
        assert.equal(failed[0].statusCode, 404);
        assert.equal(failed[0].retryable, false);
        return true;
      }
    );
  });

  it("treats a client throw as a retryable transport failure", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hang up"));
    const sink = new SuprSendSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as SuprSendSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(failed[0].retryable, true);
        assert.equal(failed[0].errorMessage, "socket hang up");
        return true;
      }
    );
  });

  it("throws a config error with no client, mapped non_retryable", async () => {
    const sink = new SuprSendSink({ workflow: "purchase-made", recipients: ["user-1"] });
    await assert.rejects(sink.send([{ body: "{}", key: "k1" }]), SuprSendSinkConfigError);
    assert.equal(classifyFailure(new SuprSendSinkConfigError("no client injected")).failureClass, "non_retryable");
  });

  it("dry-runs with zero client I/O and untouched stats", async () => {
    const client = new FakeClient();
    const sink = new SuprSendSink(baseConfig(client, { dryRun: true }));
    const result = await sink.send([{ body: "{}", subject: "Price drop" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("dry-runs still validate the config and the records", async () => {
    const client = new FakeClient();
    const sink = new SuprSendSink(baseConfig(client, { dryRun: true }));
    await assert.rejects(sink.send([{ body: "" }]), RangeError);
    assert.equal(client.posts.length, 0);
    assert.throws(
      () => new SuprSendSink({ workflow: "w", recipients: [], dryRun: true }),
      RangeError
    );
  });

  it("appends eventBody under the opt-in, truncated at the default 2000", async () => {
    const client = new FakeClient();
    const sink = new SuprSendSink(baseConfig(client, { includePayload: true, payloadMaxChars: 10 }));
    await sink.send([{ body: "0123456789ABCDEF", subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.data.eventBody, "0123456789… (truncated)");
    assert.equal(body.data.body, "Alert");

    const defaultClient = new FakeClient();
    const defaultSink = new SuprSendSink(baseConfig(defaultClient, { includePayload: true }));
    await defaultSink.send([{ body: "x".repeat(2001), subject: "Alert" }]);
    const defaultBody = JSON.parse(defaultClient.posts[0].body);
    assert.equal(defaultBody.data.eventBody, `${"x".repeat(2000)}… (truncated)`);
  });

  it("omits eventBody by default", async () => {
    const client = new FakeClient();
    const sink = new SuprSendSink(baseConfig(client));
    await sink.send([{ body: '{"secret":"s3cr3t"}', subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.data.body, "Alert");
    assert.equal(body.data.eventBody, undefined);
    assert.equal(JSON.stringify(body).includes("s3cr3t"), false);
  });

  it("sends to object recipients with actor, tenant, and cancellation key", async () => {
    const client = new FakeClient();
    const sink = new SuprSendSink(
      baseConfig(client, {
        recipients: [{ distinct_id: "u1", name: "Ada", $email: ["a@example.com"] }],
        actor: "admin-1",
        tenantId: "brand-01",
        cancellationKey: "cancel_123",
      })
    );
    await sink.send([{ body: "{}", key: "k1" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.deepEqual(body.recipients, [
      { distinct_id: "u1", name: "Ada", $email: ["a@example.com"] },
    ]);
    assert.equal(body.actor, "admin-1");
    assert.equal(body.tenant_id, "brand-01");
    assert.equal(body.cancellation_key, "cancel_123");
  });

  it("replays the same idempotency key in the body for the same record", async () => {
    const client = new FakeClient();
    const sink = new SuprSendSink(baseConfig(client));
    const record = { body: '{"a":1}', subject: "Alert", traceId: "t1" };
    await sink.send([record]);
    await sink.send([record]);
    assert.equal(client.posts.length, 2);
    assert.equal(
      JSON.parse(client.posts[0].body).idempotency_key,
      JSON.parse(client.posts[1].body).idempotency_key
    );
  });
});
