import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  Smtp2goSink,
  Smtp2goSinkConfigError,
  Smtp2goSinkError,
  assertValidSmtp2goSinkConfig,
  buildSmtp2goMessageBody,
  classifySmtp2goRecordFailure,
  resolveSmtp2goNotification,
  resolveSmtp2goRecord,
  resolveSmtp2goSubject,
  resolveSmtp2goContent,
  truncateSmtp2goPayload,
  SMTP2GO_DEFAULT_PAYLOAD_MAX_CHARS,
  SMTP2GO_FALLBACK_SUMMARY,
  SMTP2GO_SEND_URL,
  type Smtp2goMessageClient,
  type Smtp2goMessagePostRequest,
  type Smtp2goMessagePostResponse,
  type Smtp2goSinkConfig,
} from "../src/smtp2go-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements Smtp2goMessageClient {
  posts: Smtp2goMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: Smtp2goMessagePostRequest): Promise<Smtp2goMessagePostResponse> {
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
  client: Smtp2goMessageClient,
  extra: Partial<Smtp2goSinkConfig> = {}
): Smtp2goSinkConfig {
  return { from, to, client, ...extra };
}

describe("smtp2go-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidSmtp2goSinkConfig(null, "Smtp2goSink"), RangeError);
    assert.throws(() => assertValidSmtp2goSinkConfig("x", "Smtp2goSink"), RangeError);
  });

  it("rejects a malformed sender or recipient shape", () => {
    assert.throws(() => assertValidSmtp2goSinkConfig({ from: "" }, "Smtp2goSink"), RangeError);
    assert.throws(() => assertValidSmtp2goSinkConfig({ from: "has space" }, "Smtp2goSink"), RangeError);
    assert.throws(() => assertValidSmtp2goSinkConfig({ to: "" }, "Smtp2goSink"), RangeError);
    assert.throws(() => assertValidSmtp2goSinkConfig({ to: "has space" }, "Smtp2goSink"), RangeError);
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidSmtp2goSinkConfig({ client: {} }, "Smtp2goSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidSmtp2goSinkConfig({ payloadMaxChars: 0 }, "Smtp2goSink"), RangeError);
    assert.throws(() => assertValidSmtp2goSinkConfig({ payloadMaxChars: 2.5 }, "Smtp2goSink"), RangeError);
  });

  it("accepts a config with no sender or recipient yet (send-time config error)", () => {
    assert.doesNotThrow(() => new Smtp2goSink({}));
  });
});

describe("smtp2go-sink text derivation", () => {
  it("derives the subject from subject, then key, then the fallback — never the trace id", () => {
    assert.equal(
      resolveSmtp2goSubject({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveSmtp2goSubject({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveSmtp2goSubject({ body: "{}", traceId: "t-1" }), SMTP2GO_FALLBACK_SUMMARY);
    assert.equal(resolveSmtp2goSubject({ body: "{}" }), SMTP2GO_FALLBACK_SUMMARY);
  });

  it("derives the content from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveSmtp2goContent({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveSmtp2goContent({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveSmtp2goContent({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveSmtp2goContent({ body: "{}" }), SMTP2GO_FALLBACK_SUMMARY);
    assert.equal(
      resolveSmtp2goContent({ body: "{}", subject: "", key: "", traceId: "" }),
      SMTP2GO_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateSmtp2goPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateSmtp2goPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveSmtp2goNotification(record, {}), {
      subject: "order.created",
      content: "order.created",
    });
    assert.deepEqual(resolveSmtp2goNotification(record, { includePayload: true }), {
      subject: "order.created",
      content: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveSmtp2goNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { subject: "order.created", content: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveSmtp2goRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("smtp2go-sink wire shape", () => {
  it("posts to the fixed Smtp2go email endpoint", () => {
    assert.equal(SMTP2GO_SEND_URL, "https://api.smtp2go.com/v3/email/send");
  });

  it("builds the JSON body with a flat to/sender/subject/text_body envelope — and no credential (the client inserts the api_key at wire time)", () => {
    assert.equal(
      buildSmtp2goMessageBody(from, to, "order.created", "order.created"),
      JSON.stringify({
        to: [to],
        sender: from,
        subject: "order.created",
        text_body: "order.created",
      })
    );
    // No credential appears in the handed body: the client alone
    // holds the API key and inserts it as the `api_key`
    // field at wire time.
    assert.equal(buildSmtp2goMessageBody(from, to, "x", "y").includes("Authorization"), false);
    assert.equal(buildSmtp2goMessageBody(from, to, "x", "y").includes("api_key"), false);
    assert.equal(buildSmtp2goMessageBody(from, to, "x", "y").includes("api-key"), false);
    assert.equal(buildSmtp2goMessageBody(from, to, "x", "y").includes("ApiKey"), false);
    assert.equal(buildSmtp2goMessageBody(from, to, "x", "y").includes('"key":'), false);
    assert.equal(Object.keys(JSON.parse(buildSmtp2goMessageBody(from, to, "x", "y"))).join(","), "to,sender,subject,text_body");
    assert.equal(JSON.parse(buildSmtp2goMessageBody(from, to, "x", "y")).sender, from);
    assert.deepEqual(JSON.parse(buildSmtp2goMessageBody(from, to, "x", "y")).to, [to]);
    assert.equal(JSON.parse(buildSmtp2goMessageBody(from, to, "x", "y")).text_body, "y");
  });
});

describe("smtp2go-sink send", () => {
  it("posts one message per record to the fixed endpoint with the envelope and content, no credential", async () => {
    const client = new FakeClient();
    const sink = new Smtp2goSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: SMTP2GO_SEND_URL,
      body: JSON.stringify({
        to: [to],
        sender: from,
        subject: "order.created",
        text_body: "order.created",
      }),
    });
    assert.deepEqual(JSON.parse(client.posts[1].body).subject, "agg-8");
    // A trace-id-only record gets the fallback subject but the
    // trace id as its content.
    assert.deepEqual(JSON.parse(client.posts[2].body).subject, SMTP2GO_FALLBACK_SUMMARY);
    assert.deepEqual(JSON.parse(client.posts[2].body).text_body, "t-9");
    // The message envelope carries the configured sender and recipient.
    assert.equal(JSON.parse(client.posts[0].body).sender, from);
    assert.deepEqual(JSON.parse(client.posts[0].body).to, [to]);
    // The request carries no credential anywhere: the API key
    // is held by the client alone and inserted as the
    // `api_key` field at wire time, never in the handed body.
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
    const sink = new Smtp2goSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof Smtp2goSinkError);
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
    const sink = new Smtp2goSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof Smtp2goSinkError);
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
      () => new Smtp2goSink({ from, to }).send([{ body: '{"a":1}' }]),
      Smtp2goSinkConfigError
    );
    await assert.rejects(
      () => new Smtp2goSink(baseConfig(new FakeClient(), { from: undefined })).send([{ body: '{"a":1}' }]),
      Smtp2goSinkConfigError
    );
    await assert.rejects(
      () => new Smtp2goSink(baseConfig(new FakeClient(), { to: undefined })).send([{ body: '{"a":1}' }]),
      Smtp2goSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new Smtp2goSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new Smtp2goSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new Smtp2goSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifySmtp2goRecordFailure(429), true);
    assert.equal(classifySmtp2goRecordFailure(500), true);
    assert.equal(classifySmtp2goRecordFailure(503), true);
    assert.equal(classifySmtp2goRecordFailure(400), false);
    assert.equal(classifySmtp2goRecordFailure(401), false);
    assert.equal(classifySmtp2goRecordFailure(404), false);
    assert.equal(SMTP2GO_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
