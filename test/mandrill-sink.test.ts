import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  MandrillSink,
  MandrillSinkConfigError,
  MandrillSinkError,
  assertValidMandrillSinkConfig,
  buildMandrillMessageBody,
  classifyMandrillRecordFailure,
  resolveMandrillNotification,
  resolveMandrillRecord,
  resolveMandrillSubject,
  resolveMandrillText,
  truncateMandrillPayload,
  MANDRILL_DEFAULT_PAYLOAD_MAX_CHARS,
  MANDRILL_FALLBACK_SUMMARY,
  MANDRILL_SEND_URL,
  type MandrillMessageClient,
  type MandrillMessagePostRequest,
  type MandrillMessagePostResponse,
  type MandrillSinkConfig,
} from "../src/mandrill-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements MandrillMessageClient {
  posts: MandrillMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: MandrillMessagePostRequest): Promise<MandrillMessagePostResponse> {
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
  client: MandrillMessageClient,
  extra: Partial<MandrillSinkConfig> = {}
): MandrillSinkConfig {
  return { from, to, client, ...extra };
}

describe("mandrill-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidMandrillSinkConfig(null, "MandrillSink"), RangeError);
    assert.throws(() => assertValidMandrillSinkConfig("x", "MandrillSink"), RangeError);
  });

  it("rejects a malformed sender or recipient shape", () => {
    assert.throws(() => assertValidMandrillSinkConfig({ from: "" }, "MandrillSink"), RangeError);
    assert.throws(() => assertValidMandrillSinkConfig({ from: "has space" }, "MandrillSink"), RangeError);
    assert.throws(() => assertValidMandrillSinkConfig({ to: "" }, "MandrillSink"), RangeError);
    assert.throws(() => assertValidMandrillSinkConfig({ to: "has space" }, "MandrillSink"), RangeError);
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidMandrillSinkConfig({ client: {} }, "MandrillSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidMandrillSinkConfig({ payloadMaxChars: 0 }, "MandrillSink"), RangeError);
    assert.throws(() => assertValidMandrillSinkConfig({ payloadMaxChars: 2.5 }, "MandrillSink"), RangeError);
  });

  it("accepts a config with no sender or recipient yet (send-time config error)", () => {
    assert.doesNotThrow(() => new MandrillSink({}));
  });
});

describe("mandrill-sink text derivation", () => {
  it("derives the subject from subject, then key, then the fallback — never the trace id", () => {
    assert.equal(
      resolveMandrillSubject({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveMandrillSubject({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveMandrillSubject({ body: "{}", traceId: "t-1" }), MANDRILL_FALLBACK_SUMMARY);
    assert.equal(resolveMandrillSubject({ body: "{}" }), MANDRILL_FALLBACK_SUMMARY);
  });

  it("derives the text from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveMandrillText({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveMandrillText({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveMandrillText({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveMandrillText({ body: "{}" }), MANDRILL_FALLBACK_SUMMARY);
    assert.equal(
      resolveMandrillText({ body: "{}", subject: "", key: "", traceId: "" }),
      MANDRILL_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateMandrillPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateMandrillPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveMandrillNotification(record, {}), {
      subject: "order.created",
      text: "order.created",
    });
    assert.deepEqual(resolveMandrillNotification(record, { includePayload: true }), {
      subject: "order.created",
      text: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveMandrillNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { subject: "order.created", text: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveMandrillRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("mandrill-sink wire shape", () => {
  it("posts to the fixed Mandrill messages endpoint", () => {
    assert.equal(MANDRILL_SEND_URL, "https://mandrillapp.com/api/1.0/messages/send.json");
  });

  it("builds the JSON body with a message envelope — and no key field (the client inserts it)", () => {
    assert.equal(
      buildMandrillMessageBody(from, to, "order.created", "order.created"),
      JSON.stringify({ message: { from_email: from, to: [{ email: to }], subject: "order.created", text: "order.created" } })
    );
    // No credential appears in the body: the client alone
    // holds the API key and inserts it as the `key` field at wire time.
    assert.equal(buildMandrillMessageBody(from, to, "x", "y").includes("Authorization"), false);
    assert.equal(buildMandrillMessageBody(from, to, "x", "y").includes("api_key"), false);
    assert.equal(buildMandrillMessageBody(from, to, "x", "y").includes("api-key"), false);
    assert.equal(buildMandrillMessageBody(from, to, "x", "y").includes('"key":'), false);
    assert.equal(Object.keys(JSON.parse(buildMandrillMessageBody(from, to, "x", "y"))).join(","), "message");
    assert.equal(Object.keys(JSON.parse(buildMandrillMessageBody(from, to, "x", "y")).message).join(","), "from_email,to,subject,text");
  });
});

describe("mandrill-sink send", () => {
  it("posts one message per record to the fixed endpoint with the envelope and text, no credential", async () => {
    const client = new FakeClient();
    const sink = new MandrillSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: MANDRILL_SEND_URL,
      body: JSON.stringify({ message: { from_email: from, to: [{ email: to }], subject: "order.created", text: "order.created" } }),
    });
    assert.deepEqual(JSON.parse(client.posts[1].body).message.subject, "agg-8");
    // A trace-id-only record gets the fallback subject but the
    // trace id as its text.
    assert.deepEqual(JSON.parse(client.posts[2].body).message.subject, MANDRILL_FALLBACK_SUMMARY);
    assert.deepEqual(JSON.parse(client.posts[2].body).message.text, "t-9");
    // The message envelope carries the configured sender and recipient.
    assert.deepEqual(JSON.parse(client.posts[0].body).message.from_email, from);
    assert.deepEqual(JSON.parse(client.posts[0].body).message.to, [{ email: to }]);
    // The request carries no credential anywhere: the API key
    // is held by the client alone and travels as the
    // `key` field at wire time, never in the handed body.
    for (const post of client.posts) {
      assert.equal(post.body.includes("Authorization"), false);
      assert.equal(post.body.includes("api_key"), false);
      assert.equal(post.body.includes("api-key"), false);
      assert.equal(post.body.includes('"key":'), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new MandrillSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof MandrillSinkError);
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
    const sink = new MandrillSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof MandrillSinkError);
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
      () => new MandrillSink({ from, to }).send([{ body: '{"a":1}' }]),
      MandrillSinkConfigError
    );
    await assert.rejects(
      () => new MandrillSink(baseConfig(new FakeClient(), { from: undefined })).send([{ body: '{"a":1}' }]),
      MandrillSinkConfigError
    );
    await assert.rejects(
      () => new MandrillSink(baseConfig(new FakeClient(), { to: undefined })).send([{ body: '{"a":1}' }]),
      MandrillSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new MandrillSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new MandrillSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new MandrillSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyMandrillRecordFailure(429), true);
    assert.equal(classifyMandrillRecordFailure(500), true);
    assert.equal(classifyMandrillRecordFailure(503), true);
    assert.equal(classifyMandrillRecordFailure(400), false);
    assert.equal(classifyMandrillRecordFailure(401), false);
    assert.equal(classifyMandrillRecordFailure(404), false);
    assert.equal(MANDRILL_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
