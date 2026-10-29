import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  MailerSendSink,
  MailerSendSinkConfigError,
  MailerSendSinkError,
  assertValidMailerSendSinkConfig,
  buildMailerSendMessageBody,
  classifyMailerSendRecordFailure,
  resolveMailerSendNotification,
  resolveMailerSendRecord,
  resolveMailerSendSubject,
  resolveMailerSendContent,
  truncateMailerSendPayload,
  MAILERSEND_DEFAULT_PAYLOAD_MAX_CHARS,
  MAILERSEND_FALLBACK_SUMMARY,
  MAILERSEND_SEND_URL,
  type MailerSendMessageClient,
  type MailerSendMessagePostRequest,
  type MailerSendMessagePostResponse,
  type MailerSendSinkConfig,
} from "../src/mailersend-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements MailerSendMessageClient {
  posts: MailerSendMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: MailerSendMessagePostRequest): Promise<MailerSendMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200 };
  }
}

const from = "alerts@example.com";
const to = "ops@example.com";

function baseConfig(
  client: MailerSendMessageClient,
  extra: Partial<MailerSendSinkConfig> = {}
): MailerSendSinkConfig {
  return { from, to, client, ...extra };
}

describe("mailersend-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidMailerSendSinkConfig(null, "MailerSendSink"), RangeError);
    assert.throws(() => assertValidMailerSendSinkConfig("x", "MailerSendSink"), RangeError);
  });

  it("rejects a malformed sender or recipient shape", () => {
    assert.throws(() => assertValidMailerSendSinkConfig({ from: "" }, "MailerSendSink"), RangeError);
    assert.throws(() => assertValidMailerSendSinkConfig({ from: "has space" }, "MailerSendSink"), RangeError);
    assert.throws(() => assertValidMailerSendSinkConfig({ to: "" }, "MailerSendSink"), RangeError);
    assert.throws(() => assertValidMailerSendSinkConfig({ to: "has space" }, "MailerSendSink"), RangeError);
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidMailerSendSinkConfig({ client: {} }, "MailerSendSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidMailerSendSinkConfig({ payloadMaxChars: 0 }, "MailerSendSink"), RangeError);
    assert.throws(() => assertValidMailerSendSinkConfig({ payloadMaxChars: 2.5 }, "MailerSendSink"), RangeError);
  });

  it("accepts a config with no sender or recipient yet (send-time config error)", () => {
    assert.doesNotThrow(() => new MailerSendSink({}));
  });
});

describe("mailersend-sink text derivation", () => {
  it("derives the subject from subject, then key, then the fallback — never the trace id", () => {
    assert.equal(
      resolveMailerSendSubject({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveMailerSendSubject({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveMailerSendSubject({ body: "{}", traceId: "t-1" }), MAILERSEND_FALLBACK_SUMMARY);
    assert.equal(resolveMailerSendSubject({ body: "{}" }), MAILERSEND_FALLBACK_SUMMARY);
  });

  it("derives the content from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveMailerSendContent({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveMailerSendContent({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveMailerSendContent({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveMailerSendContent({ body: "{}" }), MAILERSEND_FALLBACK_SUMMARY);
    assert.equal(
      resolveMailerSendContent({ body: "{}", subject: "", key: "", traceId: "" }),
      MAILERSEND_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateMailerSendPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateMailerSendPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveMailerSendNotification(record, {}), {
      subject: "order.created",
      content: "order.created",
    });
    assert.deepEqual(resolveMailerSendNotification(record, { includePayload: true }), {
      subject: "order.created",
      content: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveMailerSendNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { subject: "order.created", content: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveMailerSendRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("mailersend-sink wire shape", () => {
  it("posts to the fixed MailerSend email endpoint", () => {
    assert.equal(MAILERSEND_SEND_URL, "https://api.mailersend.com/v1/email");
  });

  it("builds the JSON body with a flat from/to/subject/text envelope — and no credential (the client sends the header)", () => {
    assert.equal(
      buildMailerSendMessageBody(from, to, "order.created", "order.created"),
      JSON.stringify({
        from: { email: from },
        to: [{ email: to }],
        subject: "order.created",
        text: "order.created",
      })
    );
    // No credential appears in the body: the client alone
    // holds the API key and sends it as the
    // `Authorization: Bearer` header.
    assert.equal(buildMailerSendMessageBody(from, to, "x", "y").includes("Authorization"), false);
    assert.equal(buildMailerSendMessageBody(from, to, "x", "y").includes("api_key"), false);
    assert.equal(buildMailerSendMessageBody(from, to, "x", "y").includes("api-key"), false);
    assert.equal(buildMailerSendMessageBody(from, to, "x", "y").includes("ApiKey"), false);
    assert.equal(buildMailerSendMessageBody(from, to, "x", "y").includes('"key":'), false);
    assert.equal(Object.keys(JSON.parse(buildMailerSendMessageBody(from, to, "x", "y"))).join(","), "from,to,subject,text");
    assert.deepEqual(JSON.parse(buildMailerSendMessageBody(from, to, "x", "y")).from, { email: from });
    assert.deepEqual(JSON.parse(buildMailerSendMessageBody(from, to, "x", "y")).to, [{ email: to }]);
    assert.equal(JSON.parse(buildMailerSendMessageBody(from, to, "x", "y")).text, "y");
  });
});

describe("mailersend-sink send", () => {
  it("posts one message per record to the fixed endpoint with the envelope and content, no credential", async () => {
    const client = new FakeClient();
    const sink = new MailerSendSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: MAILERSEND_SEND_URL,
      body: JSON.stringify({
        from: { email: from },
        to: [{ email: to }],
        subject: "order.created",
        text: "order.created",
      }),
    });
    assert.deepEqual(JSON.parse(client.posts[1].body).subject, "agg-8");
    // A trace-id-only record gets the fallback subject but the
    // trace id as its content.
    assert.deepEqual(JSON.parse(client.posts[2].body).subject, MAILERSEND_FALLBACK_SUMMARY);
    assert.deepEqual(JSON.parse(client.posts[2].body).text, "t-9");
    // The message envelope carries the configured sender and recipient.
    assert.deepEqual(JSON.parse(client.posts[0].body).from, { email: from });
    assert.deepEqual(JSON.parse(client.posts[0].body).to, [{ email: to }]);
    // The request carries no credential anywhere: the API key
    // is held by the client alone and travels as the
    // `Authorization: Bearer` header, never in the handed body.
    for (const post of client.posts) {
      assert.equal(post.body.includes("Authorization"), false);
      assert.equal(post.body.includes("api_key"), false);
      assert.equal(post.body.includes("api-key"), false);
      assert.equal(post.body.includes("ApiKey"), false);
      assert.equal(post.body.includes('"key":'), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new MailerSendSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof MailerSendSinkError);
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

  it("maps a client throw to a retryable transport failure and keeps partial success out", async () => {
    const client = new FakeClient();
    client.failOn.set(1, new Error("socket hangup"));
    const sink = new MailerSendSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof MailerSendSinkError);
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

  it("fails closed without a client, sender, or recipient", async () => {
    await assert.rejects(
      () => new MailerSendSink({ from, to }).send([{ body: '{"a":1}' }]),
      MailerSendSinkConfigError
    );
    await assert.rejects(
      () => new MailerSendSink(baseConfig(new FakeClient(), { from: undefined })).send([{ body: '{"a":1}' }]),
      MailerSendSinkConfigError
    );
    await assert.rejects(
      () => new MailerSendSink(baseConfig(new FakeClient(), { to: undefined })).send([{ body: '{"a":1}' }]),
      MailerSendSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new MailerSendSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new MailerSendSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new MailerSendSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyMailerSendRecordFailure(429), true);
    assert.equal(classifyMailerSendRecordFailure(500), true);
    assert.equal(classifyMailerSendRecordFailure(503), true);
    assert.equal(classifyMailerSendRecordFailure(400), false);
    assert.equal(classifyMailerSendRecordFailure(401), false);
    assert.equal(classifyMailerSendRecordFailure(404), false);
    assert.equal(MAILERSEND_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
