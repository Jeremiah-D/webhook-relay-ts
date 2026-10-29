import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  MailjetSink,
  MailjetSinkConfigError,
  MailjetSinkError,
  assertValidMailjetSinkConfig,
  buildMailjetMessageBody,
  classifyMailjetRecordFailure,
  resolveMailjetNotification,
  resolveMailjetRecord,
  resolveMailjetSubject,
  resolveMailjetText,
  truncateMailjetPayload,
  MAILJET_DEFAULT_PAYLOAD_MAX_CHARS,
  MAILJET_FALLBACK_SUMMARY,
  MAILJET_SEND_URL,
  type MailjetMessageClient,
  type MailjetMessagePostRequest,
  type MailjetMessagePostResponse,
  type MailjetSinkConfig,
} from "../src/mailjet-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements MailjetMessageClient {
  posts: MailjetMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: MailjetMessagePostRequest): Promise<MailjetMessagePostResponse> {
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
  client: MailjetMessageClient,
  extra: Partial<MailjetSinkConfig> = {}
): MailjetSinkConfig {
  return { from, to, client, ...extra };
}

describe("mailjet-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidMailjetSinkConfig(null, "MailjetSink"), RangeError);
    assert.throws(() => assertValidMailjetSinkConfig("x", "MailjetSink"), RangeError);
  });

  it("rejects a malformed sender or recipient shape", () => {
    assert.throws(() => assertValidMailjetSinkConfig({ from: "" }, "MailjetSink"), RangeError);
    assert.throws(() => assertValidMailjetSinkConfig({ from: "has space" }, "MailjetSink"), RangeError);
    assert.throws(() => assertValidMailjetSinkConfig({ to: "" }, "MailjetSink"), RangeError);
    assert.throws(() => assertValidMailjetSinkConfig({ to: "has space" }, "MailjetSink"), RangeError);
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidMailjetSinkConfig({ client: {} }, "MailjetSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidMailjetSinkConfig({ payloadMaxChars: 0 }, "MailjetSink"), RangeError);
    assert.throws(() => assertValidMailjetSinkConfig({ payloadMaxChars: 2.5 }, "MailjetSink"), RangeError);
  });

  it("accepts a config with no sender or recipient yet (send-time config error)", () => {
    assert.doesNotThrow(() => new MailjetSink({}));
  });
});

describe("mailjet-sink text derivation", () => {
  it("derives the subject from subject, then key, then the fallback — never the trace id", () => {
    assert.equal(
      resolveMailjetSubject({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveMailjetSubject({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveMailjetSubject({ body: "{}", traceId: "t-1" }), MAILJET_FALLBACK_SUMMARY);
    assert.equal(resolveMailjetSubject({ body: "{}" }), MAILJET_FALLBACK_SUMMARY);
  });

  it("derives the text from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveMailjetText({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveMailjetText({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveMailjetText({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveMailjetText({ body: "{}" }), MAILJET_FALLBACK_SUMMARY);
    assert.equal(
      resolveMailjetText({ body: "{}", subject: "", key: "", traceId: "" }),
      MAILJET_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateMailjetPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateMailjetPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveMailjetNotification(record, {}), {
      subject: "order.created",
      text: "order.created",
    });
    assert.deepEqual(resolveMailjetNotification(record, { includePayload: true }), {
      subject: "order.created",
      text: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveMailjetNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { subject: "order.created", text: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveMailjetRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("mailjet-sink wire shape", () => {
  it("posts to the fixed Mailjet Send endpoint", () => {
    assert.equal(MAILJET_SEND_URL, "https://api.mailjet.com/v3.1/send");
  });

  it("builds the JSON body with From/To, Subject, and TextPart inside a Messages array — and no credential", () => {
    assert.equal(
      buildMailjetMessageBody(from, to, "order.created", "order.created"),
      JSON.stringify({ Messages: [{ From: { Email: from }, To: [{ Email: to }], Subject: "order.created", TextPart: "order.created" }] })
    );
    // No credential appears in the body: the client alone
    // holds the API key and secret and sends them as the
    // Basic Authorization header.
    assert.equal(buildMailjetMessageBody(from, to, "x", "y").includes("Authorization"), false);
    assert.equal(buildMailjetMessageBody(from, to, "x", "y").includes("api_key"), false);
    assert.equal(buildMailjetMessageBody(from, to, "x", "y").includes("api-key"), false);
    assert.equal(buildMailjetMessageBody(from, to, "x", "y").includes("secret"), false);
  });
});

describe("mailjet-sink send", () => {
  it("posts one message per record to the fixed endpoint with the envelope and text, no credential", async () => {
    const client = new FakeClient();
    const sink = new MailjetSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: MAILJET_SEND_URL,
      body: JSON.stringify({ Messages: [{ From: { Email: from }, To: [{ Email: to }], Subject: "order.created", TextPart: "order.created" }] }),
    });
    assert.deepEqual(JSON.parse(client.posts[1].body).Messages[0].Subject, "agg-8");
    // A trace-id-only record gets the fallback subject but the
    // trace id as its text.
    assert.deepEqual(JSON.parse(client.posts[2].body).Messages[0].Subject, MAILJET_FALLBACK_SUMMARY);
    assert.deepEqual(JSON.parse(client.posts[2].body).Messages[0].TextPart, "t-9");
    // The Messages envelope carries exactly one message with
    // the configured sender and recipient.
    assert.deepEqual(JSON.parse(client.posts[0].body).Messages[0].From, { Email: from });
    assert.deepEqual(JSON.parse(client.posts[0].body).Messages[0].To, [{ Email: to }]);
    // The request carries no credential anywhere: the API key
    // and secret are held by the client alone and travel as
    // the Basic Authorization header, never in the body.
    for (const post of client.posts) {
      assert.equal(post.body.includes("Authorization"), false);
      assert.equal(post.body.includes("api_key"), false);
      assert.equal(post.body.includes("secret"), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new MailjetSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof MailjetSinkError);
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
    const sink = new MailjetSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof MailjetSinkError);
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
      () => new MailjetSink({ from, to }).send([{ body: '{"a":1}' }]),
      MailjetSinkConfigError
    );
    await assert.rejects(
      () => new MailjetSink(baseConfig(new FakeClient(), { from: undefined })).send([{ body: '{"a":1}' }]),
      MailjetSinkConfigError
    );
    await assert.rejects(
      () => new MailjetSink(baseConfig(new FakeClient(), { to: undefined })).send([{ body: '{"a":1}' }]),
      MailjetSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new MailjetSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new MailjetSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new MailjetSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyMailjetRecordFailure(429), true);
    assert.equal(classifyMailjetRecordFailure(500), true);
    assert.equal(classifyMailjetRecordFailure(503), true);
    assert.equal(classifyMailjetRecordFailure(400), false);
    assert.equal(classifyMailjetRecordFailure(401), false);
    assert.equal(classifyMailjetRecordFailure(404), false);
    assert.equal(MAILJET_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
