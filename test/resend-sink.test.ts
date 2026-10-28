import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  ResendSink,
  ResendSinkConfigError,
  ResendSinkError,
  assertValidResendSinkConfig,
  buildResendMessageBody,
  classifyResendRecordFailure,
  resolveResendNotification,
  resolveResendRecord,
  resolveResendSubject,
  resolveResendText,
  truncateResendPayload,
  RESEND_DEFAULT_PAYLOAD_MAX_CHARS,
  RESEND_FALLBACK_SUMMARY,
  RESEND_EMAILS_URL,
  type ResendMessageClient,
  type ResendMessagePostRequest,
  type ResendMessagePostResponse,
  type ResendSinkConfig,
} from "../src/resend-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements ResendMessageClient {
  posts: ResendMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: ResendMessagePostRequest): Promise<ResendMessagePostResponse> {
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
  client: ResendMessageClient,
  extra: Partial<ResendSinkConfig> = {}
): ResendSinkConfig {
  return { from, to, client, ...extra };
}

describe("resend-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidResendSinkConfig(null, "ResendSink"), RangeError);
    assert.throws(() => assertValidResendSinkConfig("x", "ResendSink"), RangeError);
  });

  it("rejects a malformed sender or recipient shape", () => {
    assert.throws(() => assertValidResendSinkConfig({ from: "" }, "ResendSink"), RangeError);
    assert.throws(() => assertValidResendSinkConfig({ from: "has space" }, "ResendSink"), RangeError);
    assert.throws(() => assertValidResendSinkConfig({ to: "" }, "ResendSink"), RangeError);
    assert.throws(() => assertValidResendSinkConfig({ to: "has space" }, "ResendSink"), RangeError);
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidResendSinkConfig({ client: {} }, "ResendSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidResendSinkConfig({ payloadMaxChars: 0 }, "ResendSink"), RangeError);
    assert.throws(() => assertValidResendSinkConfig({ payloadMaxChars: 2.5 }, "ResendSink"), RangeError);
  });

  it("accepts a config with no sender or recipient yet (send-time config error)", () => {
    assert.doesNotThrow(() => new ResendSink({}));
  });
});

describe("resend-sink text derivation", () => {
  it("derives the subject from subject, then key, then the fallback — never the trace id", () => {
    assert.equal(
      resolveResendSubject({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveResendSubject({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveResendSubject({ body: "{}", traceId: "t-1" }), RESEND_FALLBACK_SUMMARY);
    assert.equal(resolveResendSubject({ body: "{}" }), RESEND_FALLBACK_SUMMARY);
  });

  it("derives the text from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveResendText({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveResendText({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveResendText({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveResendText({ body: "{}" }), RESEND_FALLBACK_SUMMARY);
    assert.equal(
      resolveResendText({ body: "{}", subject: "", key: "", traceId: "" }),
      RESEND_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateResendPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateResendPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveResendNotification(record, {}), {
      subject: "order.created",
      text: "order.created",
    });
    assert.deepEqual(resolveResendNotification(record, { includePayload: true }), {
      subject: "order.created",
      text: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveResendNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { subject: "order.created", text: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveResendRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("resend-sink wire shape", () => {
  it("posts to the fixed Resend Emails endpoint", () => {
    assert.equal(RESEND_EMAILS_URL, "https://api.resend.com/emails");
  });

  it("builds the JSON body with from, to array, subject, and text — and no credential", () => {
    assert.equal(
      buildResendMessageBody(from, to, "order.created", "order.created"),
      JSON.stringify({ from, to: [to], subject: "order.created", text: "order.created" })
    );
    // The API key never appears in the body: the client alone
    // holds it and sends it as the Authorization header.
    assert.equal(buildResendMessageBody(from, to, "x", "y").includes("Bearer"), false);
    assert.equal(buildResendMessageBody(from, to, "x", "y").includes("api_key"), false);
  });
});

describe("resend-sink send", () => {
  it("posts one message per record to the fixed endpoint with the envelope and text, no credential", async () => {
    const client = new FakeClient();
    const sink = new ResendSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: RESEND_EMAILS_URL,
      body: JSON.stringify({ from, to: [to], subject: "order.created", text: "order.created" }),
    });
    assert.deepEqual(JSON.parse(client.posts[1].body).subject, "agg-8");
    // A trace-id-only record gets the fallback subject but the
    // trace id as its text.
    assert.deepEqual(JSON.parse(client.posts[2].body).subject, RESEND_FALLBACK_SUMMARY);
    assert.deepEqual(JSON.parse(client.posts[2].body).text, "t-9");
    // The request carries no credential anywhere: the API key
    // is held by the client alone.
    for (const post of client.posts) {
      assert.equal(post.body.includes("Bearer"), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new ResendSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof ResendSinkError);
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
    const sink = new ResendSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof ResendSinkError);
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
      () => new ResendSink({ from, to }).send([{ body: '{"a":1}' }]),
      ResendSinkConfigError
    );
    await assert.rejects(
      () => new ResendSink(baseConfig(new FakeClient(), { from: undefined })).send([{ body: '{"a":1}' }]),
      ResendSinkConfigError
    );
    await assert.rejects(
      () => new ResendSink(baseConfig(new FakeClient(), { to: undefined })).send([{ body: '{"a":1}' }]),
      ResendSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new ResendSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new ResendSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new ResendSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyResendRecordFailure(429), true);
    assert.equal(classifyResendRecordFailure(500), true);
    assert.equal(classifyResendRecordFailure(503), true);
    assert.equal(classifyResendRecordFailure(400), false);
    assert.equal(classifyResendRecordFailure(401), false);
    assert.equal(classifyResendRecordFailure(404), false);
    assert.equal(RESEND_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
