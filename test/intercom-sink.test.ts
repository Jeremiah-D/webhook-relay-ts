import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  IntercomSink,
  IntercomSinkConfigError,
  IntercomSinkError,
  assertValidIntercomSinkConfig,
  buildIntercomMessageBody,
  classifyIntercomMessageResponse,
  classifyIntercomRecordFailure,
  resolveIntercomBody,
  resolveIntercomIdentity,
  resolveIntercomRecord,
  resolveIntercomSummary,
  truncateIntercomPayload,
  INTERCOM_API_BASE_URL,
  INTERCOM_API_VERSION,
  INTERCOM_DEFAULT_PAYLOAD_MAX_CHARS,
  INTERCOM_FALLBACK_SUMMARY,
  INTERCOM_JSON_CONTENT_TYPE,
  INTERCOM_MESSAGES_URL,
  INTERCOM_RATE_LIMIT_PER_MINUTE_PER_APP,
  INTERCOM_RATE_LIMIT_PER_MINUTE_PER_WORKSPACE,
  INTERCOM_RATE_LIMIT_PER_WINDOW_PER_APP,
  INTERCOM_RATE_LIMIT_WINDOW_SECONDS,
  type IntercomMessageClient,
  type IntercomMessagePostRequest,
  type IntercomMessagePostResponse,
  type IntercomSinkConfig,
} from "../src/intercom-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status and message id per call. */
class FakeClient implements IntercomMessageClient {
  posts: IntercomMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → message id to return for that post. */
  messageIdOn = new Map<number, string>();
  /** Call-count (0-based) → conversation id to return for that post. */
  conversationIdOn = new Map<number, string>();
  /** Call-count (0-based) → error messages to return for that post. */
  errorsOn = new Map<number, string[]>();
  /** Call-count (0-based) → body `message` to return for that post. */
  messageOn = new Map<number, string>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: IntercomMessagePostRequest): Promise<IntercomMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return {
      status: this.statusOn.get(n) ?? 200,
      messageId: this.messageIdOn.get(n) ?? `msg-${n + 1}`,
      conversationId: this.conversationIdOn.get(n),
      errors: this.errorsOn.get(n),
      message: this.messageOn.get(n),
    };
  }
}

function baseConfig(
  client: IntercomMessageClient,
  extra: Partial<IntercomSinkConfig> = {}
): IntercomSinkConfig {
  return { adminId: "admin-123", contactId: "contact-456", client, ...extra };
}

describe("intercom-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidIntercomSinkConfig(null, "IntercomSink"), RangeError);
    assert.throws(() => assertValidIntercomSinkConfig("x", "IntercomSink"), RangeError);
  });

  it("requires a non-empty admin id", () => {
    assert.throws(
      () => assertValidIntercomSinkConfig({ contactId: "contact-456" }, "IntercomSink"),
      RangeError
    );
    assert.throws(
      () => assertValidIntercomSinkConfig(baseConfig(new FakeClient(), { adminId: "" }), "IntercomSink"),
      RangeError
    );
    assert.throws(
      () => assertValidIntercomSinkConfig(baseConfig(new FakeClient(), { adminId: 7 as never }), "IntercomSink"),
      RangeError
    );
    assert.equal(resolveIntercomIdentity("admin-123", "IntercomSink: `adminId`"), "admin-123");
    assertValidIntercomSinkConfig(baseConfig(new FakeClient()), "IntercomSink");
  });

  it("requires a non-empty contact id", () => {
    assert.throws(
      () => assertValidIntercomSinkConfig({ adminId: "admin-123" }, "IntercomSink"),
      RangeError
    );
    assert.throws(
      () => assertValidIntercomSinkConfig(baseConfig(new FakeClient(), { contactId: "" }), "IntercomSink"),
      RangeError
    );
    assert.throws(
      () => assertValidIntercomSinkConfig(baseConfig(new FakeClient(), { contactId: 7 as never }), "IntercomSink"),
      RangeError
    );
    assert.equal(resolveIntercomIdentity("contact-456", "IntercomSink: `contactId`"), "contact-456");
  });

  it("rejects a malformed client and payloadMaxChars", () => {
    assert.throws(
      () => assertValidIntercomSinkConfig(baseConfig(new FakeClient(), { client: {} as never }), "IntercomSink"),
      RangeError
    );
    assert.throws(
      () => assertValidIntercomSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 0 }), "IntercomSink"),
      RangeError
    );
    assert.throws(
      () => assertValidIntercomSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 1.5 }), "IntercomSink"),
      RangeError
    );
  });
});

describe("intercom-sink resolvers", () => {
  it("uses the fixed messages URL with no credential in it", () => {
    assert.equal(INTERCOM_API_BASE_URL, "https://api.intercom.io");
    assert.equal(INTERCOM_MESSAGES_URL, "https://api.intercom.io/messages");
    assert.equal(INTERCOM_MESSAGES_URL.includes("Bearer"), false);
    assert.equal(INTERCOM_MESSAGES_URL.includes("secret"), false);
    assert.equal(INTERCOM_MESSAGES_URL.includes("admin-123"), false);
  });

  it("pins the Intercom-Version header and the documented rate limits", () => {
    assert.equal(INTERCOM_API_VERSION, "2.17");
    assert.equal(INTERCOM_RATE_LIMIT_PER_MINUTE_PER_APP, 10000);
    assert.equal(INTERCOM_RATE_LIMIT_PER_MINUTE_PER_WORKSPACE, 25000);
    assert.equal(INTERCOM_RATE_LIMIT_WINDOW_SECONDS, 10);
    assert.equal(INTERCOM_RATE_LIMIT_PER_WINDOW_PER_APP, 1667);
  });

  it("derives the summary from subject, key, then traceId", () => {
    assert.equal(resolveIntercomSummary({ body: "{}", subject: "Price drop", key: "k", traceId: "t" }), "Price drop");
    assert.equal(resolveIntercomSummary({ body: "{}", key: "order-1", traceId: "t" }), "order-1");
    assert.equal(resolveIntercomSummary({ body: "{}", traceId: "trace-9" }), "trace-9");
    assert.equal(resolveIntercomSummary({ body: "{}" }), INTERCOM_FALLBACK_SUMMARY);
  });

  it("derives the body from the chain, appending the payload only under the opt-in", () => {
    assert.equal(resolveIntercomBody({ body: "{}", subject: "Price drop", key: "k" }, {}), "Price drop");
    // No subject: the body falls back to the chain.
    assert.equal(resolveIntercomBody({ body: "{}", key: "order-1" }, {}), "order-1");
    assert.equal(resolveIntercomBody({ body: "{}" }, {}), INTERCOM_FALLBACK_SUMMARY);
    assert.equal(
      resolveIntercomBody({ body: '{"a":1}', subject: "Price drop" }, { includePayload: true }),
      'Price drop\n\n{"a":1}'
    );
    assert.equal(INTERCOM_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
    assert.equal(truncateIntercomPayload("abcdef", 4), "abcd… (truncated)");
    assert.equal(truncateIntercomPayload("abc", 4), "abc");
    const long = resolveIntercomBody({ body: "x".repeat(2001), subject: "Alert" }, { includePayload: true });
    assert.equal(long, `Alert\n\n${"x".repeat(2000)}… (truncated)`);
    const short = resolveIntercomBody({ body: "0123456789ABCDEF", subject: "Alert" }, { includePayload: true, payloadMaxChars: 10 });
    assert.equal(short, "Alert\n\n0123456789… (truncated)");
  });

  it("builds the message body with admin from, single user to, fixed type and template", () => {
    const body = JSON.parse(buildIntercomMessageBody("admin-123", "contact-456", "Price drop"));
    assert.equal(body.message_type, "in_app");
    assert.equal(body.body, "Price drop");
    assert.equal(body.template, "plain");
    assert.deepEqual(body.from, { type: "admin", id: "admin-123" });
    assert.deepEqual(body.to, { type: "user", id: "contact-456" });
    // No subject field: it is only present for email messages.
    assert.equal(body.subject, undefined);
    // No audience fallback: exactly one recipient, no cc/bcc.
    assert.equal(body.cc, undefined);
    assert.equal(body.bcc, undefined);
    assert.equal(Array.isArray(body.to), false);
    // No credential ever enters the body.
    assert.equal(JSON.stringify(body).includes("Authorization"), false);
    assert.equal(JSON.stringify(body).includes("Bearer"), false);
    assert.equal(JSON.stringify(body).includes("secret"), false);
  });

  it("rejects an empty record body", () => {
    assert.throws(() => resolveIntercomRecord({ body: "" }, 0), RangeError);
    assert.deepEqual(resolveIntercomRecord({ body: "{}" }, 2), { index: 2 });
  });
});

describe("intercom-sink failure mapping", () => {
  it("maps 429 and 5xx to retryable, other non-200 to fail-closed", () => {
    assert.equal(classifyIntercomRecordFailure(429), true);
    assert.equal(classifyIntercomRecordFailure(500), true);
    assert.equal(classifyIntercomRecordFailure(503), true);
    assert.equal(classifyIntercomRecordFailure(400), false);
    assert.equal(classifyIntercomRecordFailure(401), false);
    assert.equal(classifyIntercomRecordFailure(403), false);
    assert.equal(classifyIntercomRecordFailure(404), false);
    assert.equal(classifyIntercomRecordFailure(201), false);
  });

  it("accepts a 200 carrying a message id, with or without a conversation id", () => {
    assert.deepEqual(classifyIntercomMessageResponse({ status: 200, messageId: "msg-abc" }), { accepted: true });
    // No conversation exists until the contact responds, so a
    // missing conversation_id says nothing about acceptance.
    assert.deepEqual(
      classifyIntercomMessageResponse({ status: 200, messageId: "msg-abc", conversationId: undefined }),
      { accepted: true }
    );
    assert.deepEqual(
      classifyIntercomMessageResponse({ status: 200, messageId: "msg-abc", conversationId: "conv-1" }),
      { accepted: true }
    );
  });

  it("rejects a 200 whose body carries no message id", () => {
    assert.deepEqual(classifyIntercomMessageResponse({ status: 200 }), {
      accepted: false,
      errorCode: "INTERCOM_NO_MESSAGE_ID",
      retryable: false,
    });
    assert.deepEqual(classifyIntercomMessageResponse({ status: 200, messageId: "" }), {
      accepted: false,
      errorCode: "INTERCOM_NO_MESSAGE_ID",
      retryable: false,
    });
  });

  it("rejects a 201: the reference documents 200 as the success status", () => {
    assert.deepEqual(classifyIntercomMessageResponse({ status: 201, messageId: "msg-abc" }), {
      accepted: false,
      errorCode: "HTTP_201",
      retryable: false,
    });
  });

  it("maps a non-200 status to its HTTP code and lane, surfacing the docs' errors array", () => {
    assert.deepEqual(
      classifyIntercomMessageResponse({ status: 429, errors: ["rate limit exceeded"] }),
      {
        accepted: false,
        errorCode: "HTTP_429",
        retryable: true,
        errorMessage: "rate limit exceeded",
      }
    );
    assert.deepEqual(classifyIntercomMessageResponse({ status: 403 }), {
      accepted: false,
      errorCode: "HTTP_403",
      retryable: false,
    });
    assert.deepEqual(
      classifyIntercomMessageResponse({ status: 400, errors: ["invalid message"], message: "bad request" }),
      {
        accepted: false,
        errorCode: "HTTP_400",
        retryable: false,
        errorMessage: "invalid message; bad request",
      }
    );
    assert.deepEqual(
      classifyIntercomMessageResponse({ status: 401, errors: ["unauthorized"] }),
      {
        accepted: false,
        errorCode: "HTTP_401",
        retryable: false,
        errorMessage: "unauthorized",
      }
    );
  });
});

describe("intercom-sink send", () => {
  it("posts one message per record with no credentials and no Idempotency-Key header", async () => {
    const client = new FakeClient();
    const sink = new IntercomSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "Price drop", key: "order-1" },
      { body: '{"b":2}', key: "order-2" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2, messageIds: ["msg-1", "msg-2"] });
    assert.equal(client.posts.length, 2);
    const first = client.posts[0];
    assert.equal(first.url, "https://api.intercom.io/messages");
    assert.equal(first.headers["Content-Type"], INTERCOM_JSON_CONTENT_TYPE);
    assert.equal(first.headers["Intercom-Version"], "2.17");
    assert.equal(first.headers["Authorization"], undefined);
    // The docs do not verify Idempotency-Key for this
    // endpoint, so the sink deliberately sends none.
    assert.equal(first.headers["Idempotency-Key"], undefined);
    assert.deepEqual(Object.keys(first.headers), ["Content-Type", "Intercom-Version"]);
    const body = JSON.parse(first.body);
    assert.equal(body.message_type, "in_app");
    assert.equal(body.body, "Price drop");
    assert.equal(body.template, "plain");
    assert.deepEqual(body.from, { type: "admin", id: "admin-123" });
    assert.deepEqual(body.to, { type: "user", id: "contact-456" });
    assert.equal(body.subject, undefined);
    assert.equal(body.cc, undefined);
    assert.equal(body.bcc, undefined);
    // No credential ever enters the handed request.
    assert.equal(JSON.stringify(first).includes("Authorization"), false);
    assert.equal(JSON.stringify(first).includes("Bearer"), false);
    assert.equal(JSON.stringify(first).includes("secret"), false);
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("treats a 200 without a message id as a fail-closed failure", async () => {
    const client = new FakeClient();
    client.messageIdOn.set(0, "");
    const sink = new IntercomSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as IntercomSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "INTERCOM_NO_MESSAGE_ID");
        assert.equal(failed[0].statusCode, undefined);
        assert.equal(failed[0].retryable, false);
        return true;
      }
    );
  });

  it("throws with exactly the failed messages and their retry lanes", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 429);
    client.statusOn.set(2, 503);
    const sink = new IntercomSink(baseConfig(client));
    await assert.rejects(
      sink.send([
        { body: "{}", key: "k1" },
        { body: "{}", key: "k2" },
        { body: "{}", key: "k3" },
      ]),
      (err: unknown) => {
        assert.ok(err instanceof IntercomSinkError);
        assert.deepEqual(
          (err as IntercomSinkError).failedRecords.map((f) => [f.index, f.errorCode, f.retryable]),
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

  it("treats a bad request (400) as fail-closed, surfacing the body's errors array", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 400);
    client.errorsOn.set(0, ["invalid message"]);
    const sink = new IntercomSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as IntercomSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_400");
        assert.equal(failed[0].statusCode, 400);
        assert.equal(failed[0].retryable, false);
        assert.equal(failed[0].errorMessage, "invalid message");
        return true;
      }
    );
  });

  it("treats a bad access token (401) and insufficient permissions (403) as fail-closed", async () => {
    const client401 = new FakeClient();
    client401.statusOn.set(0, 401);
    client401.errorsOn.set(0, ["unauthorized"]);
    const sink401 = new IntercomSink(baseConfig(client401));
    await assert.rejects(
      sink401.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        assert.equal((err as IntercomSinkError).failedRecords[0].retryable, false);
        assert.equal((err as IntercomSinkError).failedRecords[0].errorMessage, "unauthorized");
        return true;
      }
    );
    const client403 = new FakeClient();
    client403.statusOn.set(0, 403);
    const sink403 = new IntercomSink(baseConfig(client403));
    await assert.rejects(
      sink403.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        assert.equal((err as IntercomSinkError).failedRecords[0].errorCode, "HTTP_403");
        assert.equal((err as IntercomSinkError).failedRecords[0].retryable, false);
        return true;
      }
    );
  });

  it("treats an unknown or not-yet-messageable contact (404) as fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 404);
    client.errorsOn.set(0, ["contact not found"]);
    const sink = new IntercomSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as IntercomSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_404");
        assert.equal(failed[0].statusCode, 404);
        assert.equal(failed[0].retryable, false);
        assert.equal(failed[0].errorMessage, "contact not found");
        return true;
      }
    );
  });

  it("treats a client throw as a retryable transport failure", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hang up"));
    const sink = new IntercomSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as IntercomSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(failed[0].retryable, true);
        assert.equal(failed[0].errorMessage, "socket hang up");
        return true;
      }
    );
  });

  it("throws a config error with no client, mapped non_retryable", async () => {
    const sink = new IntercomSink({ adminId: "admin-123", contactId: "contact-456" });
    await assert.rejects(sink.send([{ body: "{}", key: "k1" }]), IntercomSinkConfigError);
    assert.equal(classifyFailure(new IntercomSinkConfigError("no client injected")).failureClass, "non_retryable");
  });

  it("dry-runs with zero client I/O and untouched stats", async () => {
    const client = new FakeClient();
    const sink = new IntercomSink(baseConfig(client, { dryRun: true }));
    const result = await sink.send([{ body: "{}", subject: "Price drop" }]);
    assert.deepEqual(result, { ok: true, sent: 0, messageIds: [], dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("dry-runs still validate the config and the records", async () => {
    const client = new FakeClient();
    const sink = new IntercomSink(baseConfig(client, { dryRun: true }));
    await assert.rejects(sink.send([{ body: "" }]), RangeError);
    assert.equal(client.posts.length, 0);
    assert.throws(
      () => new IntercomSink({ adminId: "", contactId: "contact-456", dryRun: true }),
      RangeError
    );
    assert.throws(
      () => new IntercomSink({ adminId: "admin-123", contactId: "", dryRun: true }),
      RangeError
    );
  });

  it("appends the payload to the body under the opt-in, truncated at the default 2000", async () => {
    const client = new FakeClient();
    const sink = new IntercomSink(baseConfig(client, { includePayload: true, payloadMaxChars: 10 }));
    await sink.send([{ body: "0123456789ABCDEF", subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.body, "Alert\n\n0123456789… (truncated)");

    const defaultClient = new FakeClient();
    const defaultSink = new IntercomSink(baseConfig(defaultClient, { includePayload: true }));
    await defaultSink.send([{ body: "x".repeat(2001), subject: "Alert" }]);
    const defaultBody = JSON.parse(defaultClient.posts[0].body);
    assert.equal(defaultBody.body, `Alert\n\n${"x".repeat(2000)}… (truncated)`);
  });

  it("omits the payload by default", async () => {
    const client = new FakeClient();
    const sink = new IntercomSink(baseConfig(client));
    await sink.send([{ body: '{"secret":"s3cr3t"}', subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.body, "Alert");
    assert.equal(JSON.stringify(body).includes("s3cr3t"), false);
  });

  it("collects message ids in send order across messages", async () => {
    const client = new FakeClient();
    client.messageIdOn.set(0, "msg-first");
    client.messageIdOn.set(1, "msg-second");
    const sink = new IntercomSink(baseConfig(client));
    const result = await sink.send([
      { body: "{}", key: "k1" },
      { body: "{}", key: "k2" },
    ]);
    assert.deepEqual(result.messageIds, ["msg-first", "msg-second"]);
  });
});
