import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  ElasticEmailSink,
  ElasticEmailSinkConfigError,
  ElasticEmailSinkError,
  assertValidElasticEmailSinkConfig,
  buildElasticEmailMessageBody,
  classifyElasticEmailRecordFailure,
  resolveElasticEmailNotification,
  resolveElasticEmailRecord,
  resolveElasticEmailSubject,
  resolveElasticEmailContent,
  truncateElasticEmailPayload,
  ELASTICEMAIL_DEFAULT_PAYLOAD_MAX_CHARS,
  ELASTICEMAIL_FALLBACK_SUMMARY,
  ELASTICEMAIL_SEND_URL,
  type ElasticEmailMessageClient,
  type ElasticEmailMessagePostRequest,
  type ElasticEmailMessagePostResponse,
  type ElasticEmailSinkConfig,
} from "../src/elasticemail-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements ElasticEmailMessageClient {
  posts: ElasticEmailMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: ElasticEmailMessagePostRequest): Promise<ElasticEmailMessagePostResponse> {
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
  client: ElasticEmailMessageClient,
  extra: Partial<ElasticEmailSinkConfig> = {}
): ElasticEmailSinkConfig {
  return { from, to, client, ...extra };
}

describe("elasticemail-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidElasticEmailSinkConfig(null, "ElasticEmailSink"), RangeError);
    assert.throws(() => assertValidElasticEmailSinkConfig("x", "ElasticEmailSink"), RangeError);
  });

  it("rejects a malformed sender or recipient shape", () => {
    assert.throws(() => assertValidElasticEmailSinkConfig({ from: "" }, "ElasticEmailSink"), RangeError);
    assert.throws(() => assertValidElasticEmailSinkConfig({ from: "has space" }, "ElasticEmailSink"), RangeError);
    assert.throws(() => assertValidElasticEmailSinkConfig({ to: "" }, "ElasticEmailSink"), RangeError);
    assert.throws(() => assertValidElasticEmailSinkConfig({ to: "has space" }, "ElasticEmailSink"), RangeError);
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidElasticEmailSinkConfig({ client: {} }, "ElasticEmailSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidElasticEmailSinkConfig({ payloadMaxChars: 0 }, "ElasticEmailSink"), RangeError);
    assert.throws(() => assertValidElasticEmailSinkConfig({ payloadMaxChars: 2.5 }, "ElasticEmailSink"), RangeError);
  });

  it("accepts a config with no sender or recipient yet (send-time config error)", () => {
    assert.doesNotThrow(() => new ElasticEmailSink({}));
  });
});

describe("elasticemail-sink text derivation", () => {
  it("derives the subject from subject, then key, then the fallback — never the trace id", () => {
    assert.equal(
      resolveElasticEmailSubject({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveElasticEmailSubject({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveElasticEmailSubject({ body: "{}", traceId: "t-1" }), ELASTICEMAIL_FALLBACK_SUMMARY);
    assert.equal(resolveElasticEmailSubject({ body: "{}" }), ELASTICEMAIL_FALLBACK_SUMMARY);
  });

  it("derives the content from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveElasticEmailContent({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveElasticEmailContent({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveElasticEmailContent({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveElasticEmailContent({ body: "{}" }), ELASTICEMAIL_FALLBACK_SUMMARY);
    assert.equal(
      resolveElasticEmailContent({ body: "{}", subject: "", key: "", traceId: "" }),
      ELASTICEMAIL_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateElasticEmailPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateElasticEmailPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveElasticEmailNotification(record, {}), {
      subject: "order.created",
      content: "order.created",
    });
    assert.deepEqual(resolveElasticEmailNotification(record, { includePayload: true }), {
      subject: "order.created",
      content: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveElasticEmailNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { subject: "order.created", content: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveElasticEmailRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("elasticemail-sink wire shape", () => {
  it("posts to the fixed Elastic Email transactional endpoint", () => {
    assert.equal(ELASTICEMAIL_SEND_URL, "https://api.elasticemail.com/v4/emails/transactional");
  });

  it("builds the JSON body with a Recipients/Content/Body array envelope — and no credential (the client sends the header)", () => {
    assert.equal(
      buildElasticEmailMessageBody(from, to, "order.created", "order.created"),
      JSON.stringify({
        Recipients: { To: [to] },
        Content: {
          From: from,
          Subject: "order.created",
          Body: [{ ContentType: "PlainText", Content: "order.created" }],
        },
      })
    );
    // No credential appears in the body: the client alone
    // holds the API key and sends it as the
    // `X-ElasticEmail-ApiKey` header.
    assert.equal(buildElasticEmailMessageBody(from, to, "x", "y").includes("Authorization"), false);
    assert.equal(buildElasticEmailMessageBody(from, to, "x", "y").includes("api_key"), false);
    assert.equal(buildElasticEmailMessageBody(from, to, "x", "y").includes("api-key"), false);
    assert.equal(buildElasticEmailMessageBody(from, to, "x", "y").includes("ApiKey"), false);
    assert.equal(buildElasticEmailMessageBody(from, to, "x", "y").includes('"key":'), false);
    assert.equal(Object.keys(JSON.parse(buildElasticEmailMessageBody(from, to, "x", "y"))).join(","), "Recipients,Content");
    assert.equal(Object.keys(JSON.parse(buildElasticEmailMessageBody(from, to, "x", "y")).Content).join(","), "From,Subject,Body");
    assert.deepEqual(JSON.parse(buildElasticEmailMessageBody(from, to, "x", "y")).Content.Body, [{ ContentType: "PlainText", Content: "y" }]);
  });
});

describe("elasticemail-sink send", () => {
  it("posts one message per record to the fixed endpoint with the envelope and content, no credential", async () => {
    const client = new FakeClient();
    const sink = new ElasticEmailSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: ELASTICEMAIL_SEND_URL,
      body: JSON.stringify({
        Recipients: { To: [to] },
        Content: {
          From: from,
          Subject: "order.created",
          Body: [{ ContentType: "PlainText", Content: "order.created" }],
        },
      }),
    });
    assert.deepEqual(JSON.parse(client.posts[1].body).Content.Subject, "agg-8");
    // A trace-id-only record gets the fallback subject but the
    // trace id as its content.
    assert.deepEqual(JSON.parse(client.posts[2].body).Content.Subject, ELASTICEMAIL_FALLBACK_SUMMARY);
    assert.deepEqual(JSON.parse(client.posts[2].body).Content.Body[0].Content, "t-9");
    // The message envelope carries the configured sender and recipient.
    assert.deepEqual(JSON.parse(client.posts[0].body).Content.From, from);
    assert.deepEqual(JSON.parse(client.posts[0].body).Recipients, { To: [to] });
    // The request carries no credential anywhere: the API key
    // is held by the client alone and travels as the
    // `X-ElasticEmail-ApiKey` header, never in the handed body.
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
    const sink = new ElasticEmailSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof ElasticEmailSinkError);
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
    const sink = new ElasticEmailSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof ElasticEmailSinkError);
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
      () => new ElasticEmailSink({ from, to }).send([{ body: '{"a":1}' }]),
      ElasticEmailSinkConfigError
    );
    await assert.rejects(
      () => new ElasticEmailSink(baseConfig(new FakeClient(), { from: undefined })).send([{ body: '{"a":1}' }]),
      ElasticEmailSinkConfigError
    );
    await assert.rejects(
      () => new ElasticEmailSink(baseConfig(new FakeClient(), { to: undefined })).send([{ body: '{"a":1}' }]),
      ElasticEmailSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new ElasticEmailSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new ElasticEmailSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new ElasticEmailSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyElasticEmailRecordFailure(429), true);
    assert.equal(classifyElasticEmailRecordFailure(500), true);
    assert.equal(classifyElasticEmailRecordFailure(503), true);
    assert.equal(classifyElasticEmailRecordFailure(400), false);
    assert.equal(classifyElasticEmailRecordFailure(401), false);
    assert.equal(classifyElasticEmailRecordFailure(404), false);
    assert.equal(ELASTICEMAIL_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
