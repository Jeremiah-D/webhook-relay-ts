import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  KnockSink,
  KnockSinkConfigError,
  KnockSinkError,
  assertValidKnockSinkConfig,
  buildKnockTriggerBody,
  classifyKnockRecordFailure,
  classifyKnockTriggerResponse,
  knockTriggerUrl,
  resolveKnockCancellationKey,
  resolveKnockData,
  resolveKnockIdempotencyKey,
  resolveKnockRecipient,
  resolveKnockRecipients,
  resolveKnockRecord,
  resolveKnockSummary,
  resolveKnockWorkflowKey,
  truncateKnockPayload,
  KNOCK_API_BASE_URL,
  KNOCK_DEFAULT_PAYLOAD_MAX_CHARS,
  KNOCK_FALLBACK_SUMMARY,
  KNOCK_JSON_CONTENT_TYPE,
  KNOCK_MAX_RECIPIENTS,
  type KnockRecipient,
  type KnockSinkConfig,
  type KnockTriggerClient,
  type KnockTriggerPostRequest,
  type KnockTriggerPostResponse,
} from "../src/knock-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements KnockTriggerClient {
  posts: KnockTriggerPostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → workflow run id to return for that post. */
  workflowRunIdOn = new Map<number, string>();
  /** Call-count (0-based) → error messages to return for that post. */
  errorsOn = new Map<number, string[]>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: KnockTriggerPostRequest): Promise<KnockTriggerPostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return {
      status: this.statusOn.get(n) ?? 200,
      workflowRunId: this.workflowRunIdOn.get(n),
      errors: this.errorsOn.get(n),
    };
  }
}

function baseConfig(
  client: KnockTriggerClient,
  extra: Partial<KnockSinkConfig> = {}
): KnockSinkConfig {
  return { key: "new-comment", recipients: ["user-1"], client, ...extra };
}

describe("knock-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidKnockSinkConfig(null, "KnockSink"), RangeError);
    assert.throws(() => assertValidKnockSinkConfig("x", "KnockSink"), RangeError);
  });

  it("requires a non-empty workflow key", () => {
    assert.throws(
      () => assertValidKnockSinkConfig({ recipients: ["user-1"], client: new FakeClient() }, "KnockSink"),
      RangeError
    );
    assert.throws(
      () => assertValidKnockSinkConfig(baseConfig(new FakeClient(), { key: "" }), "KnockSink"),
      RangeError
    );
    assert.throws(
      () => assertValidKnockSinkConfig(baseConfig(new FakeClient(), { key: 7 as never }), "KnockSink"),
      RangeError
    );
    assert.equal(resolveKnockWorkflowKey("new-comment", "KnockSink"), "new-comment");
    assertValidKnockSinkConfig(baseConfig(new FakeClient()), "KnockSink");
  });

  it("requires at least one recipient and validates each form", () => {
    assert.throws(
      () => assertValidKnockSinkConfig({ key: "w", client: new FakeClient() }, "KnockSink"),
      RangeError
    );
    assert.throws(
      () => assertValidKnockSinkConfig(baseConfig(new FakeClient(), { recipients: [] }), "KnockSink"),
      RangeError
    );
    assert.throws(
      () => assertValidKnockSinkConfig(baseConfig(new FakeClient(), { recipients: "user-1" as never }), "KnockSink"),
      RangeError
    );
    assert.throws(
      () => assertValidKnockSinkConfig(baseConfig(new FakeClient(), { recipients: [""] }), "KnockSink"),
      RangeError
    );
    assert.throws(
      () =>
        assertValidKnockSinkConfig(
          baseConfig(new FakeClient(), { recipients: [{}] }),
          "KnockSink"
        ),
      RangeError
    );
    assert.throws(
      () =>
        assertValidKnockSinkConfig(
          baseConfig(new FakeClient(), { recipients: [{ id: "" }] }),
          "KnockSink"
        ),
      RangeError
    );
    assert.throws(
      () =>
        assertValidKnockSinkConfig(
          baseConfig(new FakeClient(), { recipients: [{ id: "u1", collection: "" }] }),
          "KnockSink"
        ),
      RangeError
    );
    // There is no broadcast form: an object without an `id` fails.
    assert.throws(
      () =>
        assertValidKnockSinkConfig(
          baseConfig(new FakeClient(), { recipients: [{ email: "a@example.com" } as never] }),
          "KnockSink"
        ),
      RangeError
    );
    // More than the docs' 1000-recipient cap fails.
    assert.throws(
      () =>
        assertValidKnockSinkConfig(
          baseConfig(new FakeClient(), {
            recipients: Array.from({ length: KNOCK_MAX_RECIPIENTS + 1 }, (_, i) => `user-${i}`),
          }),
          "KnockSink"
        ),
      RangeError
    );
    assert.equal(KNOCK_MAX_RECIPIENTS, 1000);
    assert.deepEqual(resolveKnockRecipient("user-1", "KnockSink"), "user-1");
    assert.deepEqual(resolveKnockRecipient({ id: "u1", name: "Ada" }, "KnockSink"), {
      id: "u1",
      name: "Ada",
    });
    assert.deepEqual(
      resolveKnockRecipient({ id: "project-1", collection: "projects" }, "KnockSink"),
      { id: "project-1", collection: "projects" }
    );
    assert.deepEqual(
      resolveKnockRecipients(["u1", { id: "u2", email: "a@example.com" }], "KnockSink"),
      ["u1", { id: "u2", email: "a@example.com" }]
    );
    assertValidKnockSinkConfig(
      baseConfig(new FakeClient(), {
        recipients: ["u1", { id: "u2", name: "Ada" }, { id: "p1", collection: "projects" }],
      }),
      "KnockSink"
    );
  });

  it("validates the optional actor and cancellation key", () => {
    assert.throws(
      () => assertValidKnockSinkConfig(baseConfig(new FakeClient(), { actor: "" }), "KnockSink"),
      RangeError
    );
    assert.throws(
      () => assertValidKnockSinkConfig(baseConfig(new FakeClient(), { actor: {} as never }), "KnockSink"),
      RangeError
    );
    assert.throws(
      () => assertValidKnockSinkConfig(baseConfig(new FakeClient(), { cancellationKey: "" }), "KnockSink"),
      RangeError
    );
    assert.throws(
      () => assertValidKnockSinkConfig(baseConfig(new FakeClient(), { cancellationKey: 7 as never }), "KnockSink"),
      RangeError
    );
    assert.equal(resolveKnockCancellationKey("cancel_123", "KnockSink"), "cancel_123");
    assert.equal(resolveKnockCancellationKey(undefined, "KnockSink"), undefined);
    assertValidKnockSinkConfig(
      baseConfig(new FakeClient(), { actor: "admin-1", cancellationKey: "cancel_123" }),
      "KnockSink"
    );
    assertValidKnockSinkConfig(
      baseConfig(new FakeClient(), { actor: { id: "admin-1", name: "Ada" } }),
      "KnockSink"
    );
  });

  it("rejects a malformed client and payloadMaxChars", () => {
    assert.throws(
      () => assertValidKnockSinkConfig(baseConfig(new FakeClient(), { client: {} as never }), "KnockSink"),
      RangeError
    );
    assert.throws(
      () => assertValidKnockSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 0 }), "KnockSink"),
      RangeError
    );
    assert.throws(
      () => assertValidKnockSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 1.5 }), "KnockSink"),
      RangeError
    );
  });
});

describe("knock-sink resolvers", () => {
  it("builds the trigger URL with the key in the path (no credential in it)", () => {
    assert.equal(KNOCK_API_BASE_URL, "https://api.knock.app/v1");
    assert.equal(
      knockTriggerUrl("new-comment"),
      "https://api.knock.app/v1/workflows/new-comment/trigger"
    );
    assert.equal(knockTriggerUrl("my workflow"), "https://api.knock.app/v1/workflows/my%20workflow/trigger");
    assert.equal(knockTriggerUrl("new-comment").includes("Bearer"), false);
    assert.equal(knockTriggerUrl("new-comment").includes("secret"), false);
  });

  it("derives the summary from subject, key, then traceId", () => {
    assert.equal(resolveKnockSummary({ body: "{}", subject: "Price drop", key: "k", traceId: "t" }), "Price drop");
    assert.equal(resolveKnockSummary({ body: "{}", key: "order-1", traceId: "t" }), "order-1");
    assert.equal(resolveKnockSummary({ body: "{}", traceId: "trace-9" }), "trace-9");
    assert.equal(resolveKnockSummary({ body: "{}" }), KNOCK_FALLBACK_SUMMARY);
  });

  it("derives the data map with title from subject only and body from the chain", () => {
    assert.deepEqual(resolveKnockData({ body: "{}", subject: "Price drop", key: "k" }, {}), {
      body: "Price drop",
      title: "Price drop",
    });
    // No subject: the title is omitted, the body falls back to the chain.
    assert.deepEqual(resolveKnockData({ body: "{}", key: "order-1" }, {}), { body: "order-1" });
    assert.deepEqual(resolveKnockData({ body: "{}" }, {}), { body: KNOCK_FALLBACK_SUMMARY });
  });

  it("appends eventBody only under the opt-in, truncated at the default 2000", () => {
    const withPayload = resolveKnockData({ body: '{"a":1}', subject: "Price drop" }, { includePayload: true });
    assert.equal(withPayload.eventBody, '{"a":1}');
    assert.equal(KNOCK_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
    assert.equal(truncateKnockPayload("abcdef", 4), "abcd… (truncated)");
    assert.equal(truncateKnockPayload("abc", 4), "abc");
    const long = resolveKnockData({ body: "x".repeat(2001), subject: "Alert" }, { includePayload: true });
    assert.equal(long.eventBody, `${"x".repeat(2000)}… (truncated)`);
    const short = resolveKnockData({ body: "0123456789ABCDEF", subject: "Alert" }, { includePayload: true, payloadMaxChars: 10 });
    assert.equal(short.eventBody, "0123456789… (truncated)");
  });

  it("builds the trigger body with key, recipients, and data", () => {
    const body = JSON.parse(
      buildKnockTriggerBody(
        "new-comment",
        ["user-1"],
        { title: "Price drop", body: "Price drop" }
      )
    );
    assert.equal(body.key, "new-comment");
    assert.deepEqual(body.recipients, ["user-1"]);
    assert.deepEqual(body.data, { title: "Price drop", body: "Price drop" });
    assert.equal(body.data.eventBody, undefined);
    assert.equal(body.actor, undefined);
    assert.equal(body.cancellation_key, undefined);
    // No credential ever enters the body.
    assert.equal(JSON.stringify(body).includes("Authorization"), false);
    assert.equal(JSON.stringify(body).includes("Bearer"), false);
    assert.equal(JSON.stringify(body).includes("secret"), false);
  });

  it("builds the trigger body with an object recipient, actor, and cancellation key", () => {
    const body = JSON.parse(
      buildKnockTriggerBody(
        "new-comment",
        [{ id: "u1", name: "Ada" }, { id: "p1", collection: "projects" }],
        { body: "order-1" },
        { id: "admin-1" },
        "cancel_123"
      )
    );
    assert.deepEqual(body.recipients, [
      { id: "u1", name: "Ada" },
      { id: "p1", collection: "projects" },
    ]);
    assert.deepEqual(body.actor, { id: "admin-1" });
    assert.equal(body.cancellation_key, "cancel_123");
  });

  it("appends eventBody inside data under the opt-in", () => {
    const body = JSON.parse(
      buildKnockTriggerBody("w", ["u1"], { body: "Alert", eventBody: '{"a":1}' })
    );
    assert.equal(body.data.eventBody, '{"a":1}');
    assert.equal(typeof body.data.eventBody, "string");
  });

  it("derives a deterministic idempotency key, distinct per record and per target", () => {
    const record = { body: '{"a":1}', subject: "Alert", traceId: "t1" };
    const key1 = resolveKnockIdempotencyKey("w", ["u1"], record);
    const key2 = resolveKnockIdempotencyKey("w", ["u1"], record);
    assert.equal(key1, key2);
    assert.equal(key1.startsWith("knock-trigger-"), true);
    assert.equal(key1.length <= 255, true);
    // A different record gets a different key.
    assert.notEqual(
      key1,
      resolveKnockIdempotencyKey("w", ["u1"], { body: '{"a":2}', subject: "Alert", traceId: "t1" })
    );
    // The same event sent to a different workflow or recipient set gets a different key.
    assert.notEqual(key1, resolveKnockIdempotencyKey("other-workflow", ["u1"], record));
    assert.notEqual(key1, resolveKnockIdempotencyKey("w", ["u2"], record));
  });

  it("rejects an empty record body", () => {
    assert.throws(() => resolveKnockRecord({ body: "" }, 0), RangeError);
    assert.deepEqual(resolveKnockRecord({ body: "{}" }, 2), { index: 2 });
  });
});

describe("knock-sink failure mapping", () => {
  it("maps 429 and 5xx to retryable, other non-200 to fail-closed", () => {
    assert.equal(classifyKnockRecordFailure(429), true);
    assert.equal(classifyKnockRecordFailure(500), true);
    assert.equal(classifyKnockRecordFailure(503), true);
    assert.equal(classifyKnockRecordFailure(400), false);
    assert.equal(classifyKnockRecordFailure(401), false);
    assert.equal(classifyKnockRecordFailure(403), false);
    assert.equal(classifyKnockRecordFailure(404), false);
    assert.equal(classifyKnockRecordFailure(201), false);
  });

  it("accepts a 200, with or without the workflow run id surfaced", () => {
    assert.deepEqual(classifyKnockTriggerResponse({ status: 200 }), { accepted: true });
    assert.deepEqual(
      classifyKnockTriggerResponse({ status: 200, workflowRunId: "123e4567-e89b-12d3-a456-426614174000" }),
      { accepted: true }
    );
  });

  it("maps a non-200 status to its HTTP code and lane", () => {
    assert.deepEqual(classifyKnockTriggerResponse({ status: 429 }), {
      accepted: false,
      errorCode: "HTTP_429",
      retryable: true,
    });
    assert.deepEqual(classifyKnockTriggerResponse({ status: 403 }), {
      accepted: false,
      errorCode: "HTTP_403",
      retryable: false,
    });
    assert.deepEqual(classifyKnockTriggerResponse({ status: 201 }), {
      accepted: false,
      errorCode: "HTTP_201",
      retryable: false,
    });
    assert.deepEqual(
      classifyKnockTriggerResponse({ status: 400, errors: ["recipients is required"] }),
      {
        accepted: false,
        errorCode: "HTTP_400",
        retryable: false,
        errorMessage: "recipients is required",
      }
    );
  });
});

describe("knock-sink send", () => {
  it("posts one trigger per message with no credentials", async () => {
    const client = new FakeClient();
    client.workflowRunIdOn.set(0, "run-1111");
    client.workflowRunIdOn.set(1, "run-2222");
    const sink = new KnockSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "Price drop", key: "order-1" },
      { body: '{"b":2}', key: "order-2" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2, workflowRunIds: ["run-1111", "run-2222"] });
    assert.equal(client.posts.length, 2);
    const first = client.posts[0];
    assert.equal(first.url, "https://api.knock.app/v1/workflows/new-comment/trigger");
    assert.equal(first.headers["Content-Type"], KNOCK_JSON_CONTENT_TYPE);
    assert.equal(typeof first.headers["Idempotency-Key"], "string");
    assert.equal(first.headers["Idempotency-Key"].startsWith("knock-trigger-"), true);
    assert.equal(first.headers["Authorization"], undefined);
    const body = JSON.parse(first.body);
    assert.equal(body.key, "new-comment");
    assert.deepEqual(body.recipients, ["user-1"]);
    assert.deepEqual(body.data, { title: "Price drop", body: "Price drop" });
    assert.equal(body.data.eventBody, undefined);
    // The two messages carry distinct idempotency keys.
    assert.notEqual(first.headers["Idempotency-Key"], client.posts[1].headers["Idempotency-Key"]);
    // No credential ever enters the handed request.
    assert.equal(JSON.stringify(first).includes("Authorization"), false);
    assert.equal(JSON.stringify(first).includes("Bearer"), false);
    assert.equal(JSON.stringify(first).includes("secret"), false);
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("accepts a 200 as acceptance and returns its workflow run id receipt", async () => {
    const client = new FakeClient();
    client.workflowRunIdOn.set(0, "123e4567-e89b-12d3-a456-426614174000");
    const sink = new KnockSink(baseConfig(client));
    const result = await sink.send([{ body: "{}", key: "k1" }]);
    assert.deepEqual(result, { ok: true, sent: 1, workflowRunIds: ["123e4567-e89b-12d3-a456-426614174000"] });
    assert.deepEqual(sink.stats, { sent: 1, failed: 0, sendFailures: 0 });
  });

  it("accepts a 200 without a workflow run id as acceptance with no receipt", async () => {
    const client = new FakeClient();
    const sink = new KnockSink(baseConfig(client));
    const result = await sink.send([{ body: "{}", key: "k1" }]);
    assert.deepEqual(result, { ok: true, sent: 1, workflowRunIds: [] });
  });

  it("treats a non-200 2xx as a failure, since the docs promise 200", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 201);
    const sink = new KnockSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as KnockSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_201");
        assert.equal(failed[0].statusCode, 201);
        assert.equal(failed[0].retryable, false);
        return true;
      }
    );
  });

  it("throws with exactly the failed messages and their retry lanes", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 429);
    client.statusOn.set(2, 503);
    const sink = new KnockSink(baseConfig(client));
    await assert.rejects(
      sink.send([
        { body: "{}", key: "k1" },
        { body: "{}", key: "k2" },
        { body: "{}", key: "k3" },
      ]),
      (err: unknown) => {
        assert.ok(err instanceof KnockSinkError);
        assert.deepEqual(
          (err as KnockSinkError).failedRecords.map((f) => [f.index, f.errorCode, f.retryable]),
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

  it("treats bad recipients (400) as fail-closed, surfacing the body's errors", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 400);
    client.errorsOn.set(0, ["recipients is required"]);
    const sink = new KnockSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as KnockSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_400");
        assert.equal(failed[0].statusCode, 400);
        assert.equal(failed[0].retryable, false);
        assert.equal(failed[0].errorMessage, "recipients is required");
        return true;
      }
    );
  });

  it("treats a bad secret key (401) and insufficient permissions (403) as fail-closed", async () => {
    const client401 = new FakeClient();
    client401.statusOn.set(0, 401);
    const sink401 = new KnockSink(baseConfig(client401));
    await assert.rejects(
      sink401.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        assert.equal((err as KnockSinkError).failedRecords[0].retryable, false);
        return true;
      }
    );
    const client403 = new FakeClient();
    client403.statusOn.set(0, 403);
    const sink403 = new KnockSink(baseConfig(client403));
    await assert.rejects(
      sink403.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        assert.equal((err as KnockSinkError).failedRecords[0].errorCode, "HTTP_403");
        assert.equal((err as KnockSinkError).failedRecords[0].retryable, false);
        return true;
      }
    );
  });

  it("treats an unknown workflow (404) as fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 404);
    const sink = new KnockSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as KnockSinkError).failedRecords;
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
    const sink = new KnockSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as KnockSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(failed[0].retryable, true);
        assert.equal(failed[0].errorMessage, "socket hang up");
        return true;
      }
    );
  });

  it("throws a config error with no client, mapped non_retryable", async () => {
    const sink = new KnockSink({ key: "new-comment", recipients: ["user-1"] });
    await assert.rejects(sink.send([{ body: "{}", key: "k1" }]), KnockSinkConfigError);
    assert.equal(classifyFailure(new KnockSinkConfigError("no client injected")).failureClass, "non_retryable");
  });

  it("dry-runs with zero client I/O and untouched stats", async () => {
    const client = new FakeClient();
    const sink = new KnockSink(baseConfig(client, { dryRun: true }));
    const result = await sink.send([{ body: "{}", subject: "Price drop" }]);
    assert.deepEqual(result, { ok: true, sent: 0, workflowRunIds: [], dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("dry-runs still validate the config and the records", async () => {
    const client = new FakeClient();
    const sink = new KnockSink(baseConfig(client, { dryRun: true }));
    await assert.rejects(sink.send([{ body: "" }]), RangeError);
    assert.equal(client.posts.length, 0);
    assert.throws(
      () => new KnockSink({ key: "w", recipients: [], dryRun: true }),
      RangeError
    );
  });

  it("appends eventBody under the opt-in, truncated at the default 2000", async () => {
    const client = new FakeClient();
    const sink = new KnockSink(baseConfig(client, { includePayload: true, payloadMaxChars: 10 }));
    await sink.send([{ body: "0123456789ABCDEF", subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.data.eventBody, "0123456789… (truncated)");
    assert.equal(body.data.body, "Alert");

    const defaultClient = new FakeClient();
    const defaultSink = new KnockSink(baseConfig(defaultClient, { includePayload: true }));
    await defaultSink.send([{ body: "x".repeat(2001), subject: "Alert" }]);
    const defaultBody = JSON.parse(defaultClient.posts[0].body);
    assert.equal(defaultBody.data.eventBody, `${"x".repeat(2000)}… (truncated)`);
  });

  it("omits eventBody by default", async () => {
    const client = new FakeClient();
    const sink = new KnockSink(baseConfig(client));
    await sink.send([{ body: '{"secret":"s3cr3t"}', subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.data.body, "Alert");
    assert.equal(body.data.eventBody, undefined);
    assert.equal(JSON.stringify(body).includes("s3cr3t"), false);
  });

  it("sends to object recipients with actor and cancellation key", async () => {
    const client = new FakeClient();
    const sink = new KnockSink(
      baseConfig(client, {
        recipients: [{ id: "u1", name: "Ada" }, { id: "p1", collection: "projects" }],
        actor: "admin-1",
        cancellationKey: "cancel_123",
      })
    );
    await sink.send([{ body: "{}", key: "k1" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.deepEqual(body.recipients, [
      { id: "u1", name: "Ada" },
      { id: "p1", collection: "projects" },
    ]);
    assert.equal(body.actor, "admin-1");
    assert.equal(body.cancellation_key, "cancel_123");
  });

  it("replays the same idempotency key for the same record", async () => {
    const client = new FakeClient();
    const sink = new KnockSink(baseConfig(client));
    const record = { body: '{"a":1}', subject: "Alert", traceId: "t1" };
    await sink.send([record]);
    await sink.send([record]);
    assert.equal(client.posts.length, 2);
    assert.equal(client.posts[0].headers["Idempotency-Key"], client.posts[1].headers["Idempotency-Key"]);
  });
});
