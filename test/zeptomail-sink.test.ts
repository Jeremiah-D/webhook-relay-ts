import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  ZeptoMailSink,
  ZeptoMailSinkConfigError,
  ZeptoMailSinkError,
  assertValidZeptoMailSinkConfig,
  buildZeptoMailMessageBody,
  classifyZeptoMailRecordFailure,
  resolveZeptoMailNotification,
  resolveZeptoMailRecord,
  resolveZeptoMailSubject,
  resolveZeptoMailContent,
  truncateZeptoMailPayload,
  ZEPTOMAIL_DEFAULT_PAYLOAD_MAX_CHARS,
  ZEPTOMAIL_FALLBACK_SUMMARY,
  ZEPTOMAIL_SEND_URL,
  type ZeptoMailMessageClient,
  type ZeptoMailMessagePostRequest,
  type ZeptoMailMessagePostResponse,
  type ZeptoMailSinkConfig,
} from "../src/zeptomail-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements ZeptoMailMessageClient {
  posts: ZeptoMailMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: ZeptoMailMessagePostRequest): Promise<ZeptoMailMessagePostResponse> {
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
  client: ZeptoMailMessageClient,
  extra: Partial<ZeptoMailSinkConfig> = {}
): ZeptoMailSinkConfig {
  return { from, to, client, ...extra };
}

describe("zeptomail-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidZeptoMailSinkConfig(null, "ZeptoMailSink"), RangeError);
    assert.throws(() => assertValidZeptoMailSinkConfig("x", "ZeptoMailSink"), RangeError);
  });

  it("rejects a malformed sender or recipient shape", () => {
    assert.throws(() => assertValidZeptoMailSinkConfig({ from: "" }, "ZeptoMailSink"), RangeError);
    assert.throws(() => assertValidZeptoMailSinkConfig({ from: "has space" }, "ZeptoMailSink"), RangeError);
    assert.throws(() => assertValidZeptoMailSinkConfig({ to: "" }, "ZeptoMailSink"), RangeError);
    assert.throws(() => assertValidZeptoMailSinkConfig({ to: "has space" }, "ZeptoMailSink"), RangeError);
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidZeptoMailSinkConfig({ client: {} }, "ZeptoMailSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidZeptoMailSinkConfig({ payloadMaxChars: 0 }, "ZeptoMailSink"), RangeError);
    assert.throws(() => assertValidZeptoMailSinkConfig({ payloadMaxChars: 2.5 }, "ZeptoMailSink"), RangeError);
  });

  it("accepts a config with no sender or recipient yet (send-time config error)", () => {
    assert.doesNotThrow(() => new ZeptoMailSink({}));
  });
});

describe("zeptomail-sink text derivation", () => {
  it("derives the subject from subject, then key, then the fallback — never the trace id", () => {
    assert.equal(
      resolveZeptoMailSubject({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveZeptoMailSubject({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveZeptoMailSubject({ body: "{}", traceId: "t-1" }), ZEPTOMAIL_FALLBACK_SUMMARY);
    assert.equal(resolveZeptoMailSubject({ body: "{}" }), ZEPTOMAIL_FALLBACK_SUMMARY);
  });

  it("derives the content from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveZeptoMailContent({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveZeptoMailContent({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveZeptoMailContent({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveZeptoMailContent({ body: "{}" }), ZEPTOMAIL_FALLBACK_SUMMARY);
    assert.equal(
      resolveZeptoMailContent({ body: "{}", subject: "", key: "", traceId: "" }),
      ZEPTOMAIL_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateZeptoMailPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateZeptoMailPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveZeptoMailNotification(record, {}), {
      subject: "order.created",
      content: "order.created",
    });
    assert.deepEqual(resolveZeptoMailNotification(record, { includePayload: true }), {
      subject: "order.created",
      content: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveZeptoMailNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { subject: "order.created", content: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveZeptoMailRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("zeptomail-sink wire shape", () => {
  it("posts to the fixed ZeptoMail email endpoint", () => {
    assert.equal(ZEPTOMAIL_SEND_URL, "https://cpaas.zoho.com/v1.1/email");
  });

  it("builds the JSON body with a nested from/to/subject/textbody envelope — and no credential (the client sends the header)", () => {
    assert.equal(
      buildZeptoMailMessageBody(from, to, "order.created", "order.created"),
      JSON.stringify({
        from: { address: from },
        to: [{ email_address: { address: to } }],
        subject: "order.created",
        textbody: "order.created",
      })
    );
    // No credential appears in the body: the client alone
    // holds the API key and sends it as the
    // `Authorization: Zoho-enczapikey` header.
    assert.equal(buildZeptoMailMessageBody(from, to, "x", "y").includes("Authorization"), false);
    assert.equal(buildZeptoMailMessageBody(from, to, "x", "y").includes("api_key"), false);
    assert.equal(buildZeptoMailMessageBody(from, to, "x", "y").includes("api-key"), false);
    assert.equal(buildZeptoMailMessageBody(from, to, "x", "y").includes("ApiKey"), false);
    assert.equal(buildZeptoMailMessageBody(from, to, "x", "y").includes('"key":'), false);
    assert.equal(Object.keys(JSON.parse(buildZeptoMailMessageBody(from, to, "x", "y"))).join(","), "from,to,subject,textbody");
    assert.deepEqual(JSON.parse(buildZeptoMailMessageBody(from, to, "x", "y")).from, { address: from });
    assert.deepEqual(JSON.parse(buildZeptoMailMessageBody(from, to, "x", "y")).to, [{ email_address: { address: to } }]);
    assert.equal(JSON.parse(buildZeptoMailMessageBody(from, to, "x", "y")).textbody, "y");
  });
});

describe("zeptomail-sink send", () => {
  it("posts one message per record to the fixed endpoint with the envelope and content, no credential", async () => {
    const client = new FakeClient();
    const sink = new ZeptoMailSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: ZEPTOMAIL_SEND_URL,
      body: JSON.stringify({
        from: { address: from },
        to: [{ email_address: { address: to } }],
        subject: "order.created",
        textbody: "order.created",
      }),
    });
    assert.deepEqual(JSON.parse(client.posts[1].body).subject, "agg-8");
    // A trace-id-only record gets the fallback subject but the
    // trace id as its content.
    assert.deepEqual(JSON.parse(client.posts[2].body).subject, ZEPTOMAIL_FALLBACK_SUMMARY);
    assert.deepEqual(JSON.parse(client.posts[2].body).textbody, "t-9");
    // The message envelope carries the configured sender and recipient.
    assert.deepEqual(JSON.parse(client.posts[0].body).from, { address: from });
    assert.deepEqual(JSON.parse(client.posts[0].body).to, [{ email_address: { address: to } }]);
    // The request carries no credential anywhere: the API key
    // is held by the client alone and travels as the
    // `Authorization: Zoho-enczapikey` header, never in the handed body.
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
    const sink = new ZeptoMailSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof ZeptoMailSinkError);
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
    const sink = new ZeptoMailSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof ZeptoMailSinkError);
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
      () => new ZeptoMailSink({ from, to }).send([{ body: '{"a":1}' }]),
      ZeptoMailSinkConfigError
    );
    await assert.rejects(
      () => new ZeptoMailSink(baseConfig(new FakeClient(), { from: undefined })).send([{ body: '{"a":1}' }]),
      ZeptoMailSinkConfigError
    );
    await assert.rejects(
      () => new ZeptoMailSink(baseConfig(new FakeClient(), { to: undefined })).send([{ body: '{"a":1}' }]),
      ZeptoMailSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new ZeptoMailSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new ZeptoMailSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new ZeptoMailSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyZeptoMailRecordFailure(429), true);
    assert.equal(classifyZeptoMailRecordFailure(500), true);
    assert.equal(classifyZeptoMailRecordFailure(503), true);
    assert.equal(classifyZeptoMailRecordFailure(400), false);
    assert.equal(classifyZeptoMailRecordFailure(401), false);
    assert.equal(classifyZeptoMailRecordFailure(404), false);
    assert.equal(ZEPTOMAIL_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
