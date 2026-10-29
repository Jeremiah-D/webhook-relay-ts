import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  PostmarkSink,
  PostmarkSinkConfigError,
  PostmarkSinkError,
  assertValidPostmarkSinkConfig,
  buildPostmarkMessageBody,
  classifyPostmarkRecordFailure,
  resolvePostmarkNotification,
  resolvePostmarkRecord,
  resolvePostmarkSubject,
  resolvePostmarkText,
  truncatePostmarkPayload,
  POSTMARK_DEFAULT_PAYLOAD_MAX_CHARS,
  POSTMARK_FALLBACK_SUMMARY,
  POSTMARK_EMAIL_URL,
  type PostmarkMessageClient,
  type PostmarkMessagePostRequest,
  type PostmarkMessagePostResponse,
  type PostmarkSinkConfig,
} from "../src/postmark-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements PostmarkMessageClient {
  posts: PostmarkMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: PostmarkMessagePostRequest): Promise<PostmarkMessagePostResponse> {
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
  client: PostmarkMessageClient,
  extra: Partial<PostmarkSinkConfig> = {}
): PostmarkSinkConfig {
  return { from, to, client, ...extra };
}

describe("postmark-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidPostmarkSinkConfig(null, "PostmarkSink"), RangeError);
    assert.throws(() => assertValidPostmarkSinkConfig("x", "PostmarkSink"), RangeError);
  });

  it("rejects a malformed sender or recipient shape", () => {
    assert.throws(() => assertValidPostmarkSinkConfig({ from: "" }, "PostmarkSink"), RangeError);
    assert.throws(() => assertValidPostmarkSinkConfig({ from: "has space" }, "PostmarkSink"), RangeError);
    assert.throws(() => assertValidPostmarkSinkConfig({ to: "" }, "PostmarkSink"), RangeError);
    assert.throws(() => assertValidPostmarkSinkConfig({ to: "has space" }, "PostmarkSink"), RangeError);
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidPostmarkSinkConfig({ client: {} }, "PostmarkSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidPostmarkSinkConfig({ payloadMaxChars: 0 }, "PostmarkSink"), RangeError);
    assert.throws(() => assertValidPostmarkSinkConfig({ payloadMaxChars: 2.5 }, "PostmarkSink"), RangeError);
  });

  it("accepts a config with no sender or recipient yet (send-time config error)", () => {
    assert.doesNotThrow(() => new PostmarkSink({}));
  });
});

describe("postmark-sink text derivation", () => {
  it("derives the subject from subject, then key, then the fallback — never the trace id", () => {
    assert.equal(
      resolvePostmarkSubject({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolvePostmarkSubject({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolvePostmarkSubject({ body: "{}", traceId: "t-1" }), POSTMARK_FALLBACK_SUMMARY);
    assert.equal(resolvePostmarkSubject({ body: "{}" }), POSTMARK_FALLBACK_SUMMARY);
  });

  it("derives the text from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolvePostmarkText({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolvePostmarkText({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolvePostmarkText({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolvePostmarkText({ body: "{}" }), POSTMARK_FALLBACK_SUMMARY);
    assert.equal(
      resolvePostmarkText({ body: "{}", subject: "", key: "", traceId: "" }),
      POSTMARK_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncatePostmarkPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncatePostmarkPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolvePostmarkNotification(record, {}), {
      subject: "order.created",
      text: "order.created",
    });
    assert.deepEqual(resolvePostmarkNotification(record, { includePayload: true }), {
      subject: "order.created",
      text: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolvePostmarkNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { subject: "order.created", text: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolvePostmarkRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("postmark-sink wire shape", () => {
  it("posts to the fixed Postmark Email endpoint", () => {
    assert.equal(POSTMARK_EMAIL_URL, "https://api.postmarkapp.com/email");
  });

  it("builds the JSON body with From, To, Subject, TextBody, and MessageStream — and no credential", () => {
    assert.equal(
      buildPostmarkMessageBody(from, to, "order.created", "order.created"),
      JSON.stringify({ From: from, To: to, Subject: "order.created", TextBody: "order.created", MessageStream: "outbound" })
    );
    // The API key never appears in the body: the client alone
    // holds it and sends it as the X-Postmark-Server-Token header.
    assert.equal(buildPostmarkMessageBody(from, to, "x", "y").includes("X-Postmark"), false);
    assert.equal(buildPostmarkMessageBody(from, to, "x", "y").includes("Server-Token"), false);
    assert.equal(buildPostmarkMessageBody(from, to, "x", "y").includes("api_key"), false);
  });
});

describe("postmark-sink send", () => {
  it("posts one message per record to the fixed endpoint with the envelope and text, no credential", async () => {
    const client = new FakeClient();
    const sink = new PostmarkSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: POSTMARK_EMAIL_URL,
      body: JSON.stringify({ From: from, To: to, Subject: "order.created", TextBody: "order.created", MessageStream: "outbound" }),
    });
    assert.deepEqual(JSON.parse(client.posts[1].body).Subject, "agg-8");
    // A trace-id-only record gets the fallback subject but the
    // trace id as its text.
    assert.deepEqual(JSON.parse(client.posts[2].body).Subject, POSTMARK_FALLBACK_SUMMARY);
    assert.deepEqual(JSON.parse(client.posts[2].body).TextBody, "t-9");
    // The request carries no credential anywhere: the API key
    // is held by the client alone.
    for (const post of client.posts) {
      assert.equal(post.body.includes("X-Postmark"), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new PostmarkSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof PostmarkSinkError);
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
    const sink = new PostmarkSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof PostmarkSinkError);
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
      () => new PostmarkSink({ from, to }).send([{ body: '{"a":1}' }]),
      PostmarkSinkConfigError
    );
    await assert.rejects(
      () => new PostmarkSink(baseConfig(new FakeClient(), { from: undefined })).send([{ body: '{"a":1}' }]),
      PostmarkSinkConfigError
    );
    await assert.rejects(
      () => new PostmarkSink(baseConfig(new FakeClient(), { to: undefined })).send([{ body: '{"a":1}' }]),
      PostmarkSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new PostmarkSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new PostmarkSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new PostmarkSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyPostmarkRecordFailure(429), true);
    assert.equal(classifyPostmarkRecordFailure(500), true);
    assert.equal(classifyPostmarkRecordFailure(503), true);
    assert.equal(classifyPostmarkRecordFailure(400), false);
    assert.equal(classifyPostmarkRecordFailure(401), false);
    assert.equal(classifyPostmarkRecordFailure(404), false);
    assert.equal(POSTMARK_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
