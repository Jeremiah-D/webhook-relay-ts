import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  SendGridSink,
  SendGridSinkConfigError,
  SendGridSinkError,
  assertValidSendGridSinkConfig,
  buildSendGridMessageBody,
  classifySendGridRecordFailure,
  resolveSendGridNotification,
  resolveSendGridRecord,
  resolveSendGridSubject,
  resolveSendGridValue,
  truncateSendGridPayload,
  SENDGRID_DEFAULT_PAYLOAD_MAX_CHARS,
  SENDGRID_FALLBACK_SUMMARY,
  SENDGRID_MAIL_SEND_URL,
  type SendGridMessageClient,
  type SendGridMessagePostRequest,
  type SendGridMessagePostResponse,
  type SendGridSinkConfig,
} from "../src/sendgrid-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements SendGridMessageClient {
  posts: SendGridMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: SendGridMessagePostRequest): Promise<SendGridMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 202 };
  }
}

const from = "alerts@example.com";
const to = "ops@example.com";

function baseConfig(
  client: SendGridMessageClient,
  extra: Partial<SendGridSinkConfig> = {}
): SendGridSinkConfig {
  return { from, to, client, ...extra };
}

describe("sendgrid-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidSendGridSinkConfig(null, "SendGridSink"), RangeError);
    assert.throws(() => assertValidSendGridSinkConfig("x", "SendGridSink"), RangeError);
  });

  it("rejects a malformed sender or recipient shape", () => {
    assert.throws(() => assertValidSendGridSinkConfig({ from: "" }, "SendGridSink"), RangeError);
    assert.throws(() => assertValidSendGridSinkConfig({ from: "has space" }, "SendGridSink"), RangeError);
    assert.throws(() => assertValidSendGridSinkConfig({ to: "" }, "SendGridSink"), RangeError);
    assert.throws(() => assertValidSendGridSinkConfig({ to: "has space" }, "SendGridSink"), RangeError);
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidSendGridSinkConfig({ client: {} }, "SendGridSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidSendGridSinkConfig({ payloadMaxChars: 0 }, "SendGridSink"), RangeError);
    assert.throws(() => assertValidSendGridSinkConfig({ payloadMaxChars: 2.5 }, "SendGridSink"), RangeError);
  });

  it("accepts a config with no sender or recipient yet (send-time config error)", () => {
    assert.doesNotThrow(() => new SendGridSink({}));
  });
});

describe("sendgrid-sink text derivation", () => {
  it("derives the subject from subject, then key, then the fallback — never the trace id", () => {
    assert.equal(
      resolveSendGridSubject({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveSendGridSubject({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveSendGridSubject({ body: "{}", traceId: "t-1" }), SENDGRID_FALLBACK_SUMMARY);
    assert.equal(resolveSendGridSubject({ body: "{}" }), SENDGRID_FALLBACK_SUMMARY);
  });

  it("derives the value from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveSendGridValue({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveSendGridValue({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveSendGridValue({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveSendGridValue({ body: "{}" }), SENDGRID_FALLBACK_SUMMARY);
    assert.equal(
      resolveSendGridValue({ body: "{}", subject: "", key: "", traceId: "" }),
      SENDGRID_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateSendGridPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateSendGridPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveSendGridNotification(record, {}), {
      subject: "order.created",
      value: "order.created",
    });
    assert.deepEqual(resolveSendGridNotification(record, { includePayload: true }), {
      subject: "order.created",
      value: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveSendGridNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { subject: "order.created", value: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveSendGridRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("sendgrid-sink wire shape", () => {
  it("posts to the fixed SendGrid Mail Send endpoint", () => {
    assert.equal(SENDGRID_MAIL_SEND_URL, "https://api.sendgrid.com/v3/mail/send");
  });

  it("builds the JSON body with personalizations, from, and content — and no credential", () => {
    assert.equal(
      buildSendGridMessageBody(from, to, "order.created", "order.created"),
      JSON.stringify({
        personalizations: [{ to: [{ email: to }], subject: "order.created" }],
        from: { email: from },
        content: [{ type: "text/plain", value: "order.created" }],
      })
    );
    // The API key never appears in the body: the client alone
    // holds it and sends it as the Authorization header.
    assert.equal(buildSendGridMessageBody(from, to, "x", "y").includes("Bearer"), false);
    assert.equal(buildSendGridMessageBody(from, to, "x", "y").includes("api_key"), false);
  });
});

describe("sendgrid-sink send", () => {
  it("posts one message per record to the fixed endpoint with the envelope and content, no credential", async () => {
    const client = new FakeClient();
    const sink = new SendGridSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: SENDGRID_MAIL_SEND_URL,
      body: JSON.stringify({
        personalizations: [{ to: [{ email: to }], subject: "order.created" }],
        from: { email: from },
        content: [{ type: "text/plain", value: "order.created" }],
      }),
    });
    assert.deepEqual(JSON.parse(client.posts[1].body).personalizations, [
      { to: [{ email: to }], subject: "agg-8" },
    ]);
    // A trace-id-only record gets the fallback subject but the
    // trace id as its content value.
    assert.deepEqual(JSON.parse(client.posts[2].body).personalizations, [
      { to: [{ email: to }], subject: SENDGRID_FALLBACK_SUMMARY },
    ]);
    assert.deepEqual(JSON.parse(client.posts[2].body).content, [
      { type: "text/plain", value: "t-9" },
    ]);
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
    const sink = new SendGridSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof SendGridSinkError);
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
    const sink = new SendGridSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof SendGridSinkError);
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
      () => new SendGridSink({ from, to }).send([{ body: '{"a":1}' }]),
      SendGridSinkConfigError
    );
    await assert.rejects(
      () => new SendGridSink(baseConfig(new FakeClient(), { from: undefined })).send([{ body: '{"a":1}' }]),
      SendGridSinkConfigError
    );
    await assert.rejects(
      () => new SendGridSink(baseConfig(new FakeClient(), { to: undefined })).send([{ body: '{"a":1}' }]),
      SendGridSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new SendGridSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new SendGridSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new SendGridSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifySendGridRecordFailure(429), true);
    assert.equal(classifySendGridRecordFailure(500), true);
    assert.equal(classifySendGridRecordFailure(503), true);
    assert.equal(classifySendGridRecordFailure(400), false);
    assert.equal(classifySendGridRecordFailure(401), false);
    assert.equal(classifySendGridRecordFailure(404), false);
    assert.equal(SENDGRID_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
