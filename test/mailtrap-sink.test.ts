import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  MailtrapSink,
  MailtrapSinkConfigError,
  MailtrapSinkError,
  assertValidMailtrapSinkConfig,
  buildMailtrapMessageBody,
  classifyMailtrapRecordFailure,
  resolveMailtrapSubject,
  resolveMailtrapText,
  resolveMailtrapNotification,
  resolveMailtrapRecord,
  truncateMailtrapPayload,
  MAILTRAP_SEND_URL,
  MAILTRAP_DEFAULT_PAYLOAD_MAX_CHARS,
  MAILTRAP_FALLBACK_SUMMARY,
  type MailtrapMessageClient,
  type MailtrapMessagePostRequest,
  type MailtrapMessagePostResponse,
  type MailtrapSinkConfig,
} from "../src/mailtrap-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements MailtrapMessageClient {
  posts: MailtrapMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: MailtrapMessagePostRequest): Promise<MailtrapMessagePostResponse> {
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
  client: MailtrapMessageClient,
  extra: Partial<MailtrapSinkConfig> = {}
): MailtrapSinkConfig {
  return { from, to, client, ...extra };
}

describe("mailtrap-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidMailtrapSinkConfig(null, "MailtrapSink"), RangeError);
    assert.throws(() => assertValidMailtrapSinkConfig("x", "MailtrapSink"), RangeError);
  });

  it("rejects a malformed sender or recipient shape", () => {
    assert.throws(() => assertValidMailtrapSinkConfig({ from: "" }, "MailtrapSink"), RangeError);
    assert.throws(
      () => assertValidMailtrapSinkConfig({ from: "has space" }, "MailtrapSink"),
      RangeError
    );
    assert.throws(() => assertValidMailtrapSinkConfig({ to: 42 }, "MailtrapSink"), RangeError);
    assert.throws(
      () => assertValidMailtrapSinkConfig({ to: "a\0b" }, "MailtrapSink"),
      RangeError
    );
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidMailtrapSinkConfig({ client: {} }, "MailtrapSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidMailtrapSinkConfig({ payloadMaxChars: 0 }, "MailtrapSink"), RangeError);
    assert.throws(() => assertValidMailtrapSinkConfig({ payloadMaxChars: 2.5 }, "MailtrapSink"), RangeError);
  });

  it("accepts a config with no addresses yet (send-time config error)", () => {
    assert.doesNotThrow(() => new MailtrapSink({}));
  });
});

describe("mailtrap-sink text derivation", () => {
  it("derives the subject from subject, then key, then the fallback (never traceId)", () => {
    assert.equal(
      resolveMailtrapSubject({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveMailtrapSubject({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveMailtrapSubject({ body: "{}", traceId: "t-1" }), MAILTRAP_FALLBACK_SUMMARY);
    assert.equal(resolveMailtrapSubject({ body: "{}" }), MAILTRAP_FALLBACK_SUMMARY);
  });

  it("derives the text from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveMailtrapText({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveMailtrapText({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveMailtrapText({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveMailtrapText({ body: "{}" }), MAILTRAP_FALLBACK_SUMMARY);
    assert.equal(
      resolveMailtrapText({ body: "{}", subject: "", key: "", traceId: "" }),
      MAILTRAP_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateMailtrapPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateMailtrapPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveMailtrapNotification(record, {}), {
      subject: "order.created",
      text: "order.created",
    });
    assert.deepEqual(resolveMailtrapNotification(record, { includePayload: true }), {
      subject: "order.created",
      text: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveMailtrapNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { subject: "order.created", text: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveMailtrapRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("mailtrap-sink wire shape", () => {
  it("exposes the fixed Mailtrap send endpoint", () => {
    assert.equal(MAILTRAP_SEND_URL, "https://send.api.mailtrap.io/api/send");
  });

  it("builds the flat JSON body with from object, to object array, subject, text — and no credential", () => {
    assert.equal(
      buildMailtrapMessageBody(from, to, "order.created", "order.created"),
      JSON.stringify({
        from: { email: from },
        to: [{ email: to }],
        subject: "order.created",
        text: "order.created",
      })
    );
    const body = buildMailtrapMessageBody(from, to, "x", "x");
    assert.equal(body.includes("Bearer"), false);
    assert.equal(body.includes("Authorization"), false);
    assert.equal(body.includes("api_key"), false);
    assert.equal(body.includes("apiKey"), false);
    assert.equal(body.includes("password"), false);
    assert.equal(body.includes("html"), false);
    assert.equal(Object.keys(JSON.parse(body)).join(","), "from,to,subject,text");
    assert.deepEqual(JSON.parse(body).from, { email: from });
    assert.deepEqual(JSON.parse(body).to, [{ email: to }]);
  });
});

describe("mailtrap-sink send", () => {
  it("posts one message per record to the fixed send endpoint with the JSON body, no credential", async () => {
    const client = new FakeClient();
    const sink = new MailtrapSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: MAILTRAP_SEND_URL,
      body: JSON.stringify({
        from: { email: from },
        to: [{ email: to }],
        subject: "order.created",
        text: "order.created",
      }),
    });
    assert.deepEqual(JSON.parse(client.posts[1].body).subject, "agg-8");
    assert.deepEqual(JSON.parse(client.posts[1].body).text, "agg-8");
    assert.deepEqual(JSON.parse(client.posts[2].body).subject, MAILTRAP_FALLBACK_SUMMARY);
    assert.deepEqual(JSON.parse(client.posts[2].body).text, "t-9");
    for (const post of client.posts) {
      assert.equal(post.body.includes("Bearer"), false);
      assert.equal(post.body.includes("Authorization"), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("applies the payload opt-in truncation on send", async () => {
    const client = new FakeClient();
    const sink = new MailtrapSink(
      baseConfig(client, { includePayload: true, payloadMaxChars: 3 })
    );
    await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.equal(
      JSON.parse(client.posts[0].body).text,
      `order.created\n\n{"a… (truncated)`
    );
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new MailtrapSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof MailtrapSinkError);
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

  it("maps a codeless transport failure to retryable with the client message", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 200);
    client.failOn.set(1, new Error("socket hangup"));
    const sink = new MailtrapSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof MailtrapSinkError);
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

  it("fails closed without a client or addresses", async () => {
    await assert.rejects(
      () => new MailtrapSink({ from, to }).send([{ body: '{"a":1}' }]),
      MailtrapSinkConfigError
    );
    await assert.rejects(
      () =>
        new MailtrapSink(baseConfig(new FakeClient(), { from: undefined })).send([
          { body: '{"a":1}' },
        ]),
      MailtrapSinkConfigError
    );
    await assert.rejects(
      () =>
        new MailtrapSink(baseConfig(new FakeClient(), { to: undefined })).send([
          { body: '{"a":1}' },
        ]),
      MailtrapSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new MailtrapSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new MailtrapSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new MailtrapSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies record failures directly", () => {
    assert.equal(classifyMailtrapRecordFailure(429), true);
    assert.equal(classifyMailtrapRecordFailure(500), true);
    assert.equal(classifyMailtrapRecordFailure(503), true);
    assert.equal(classifyMailtrapRecordFailure(400), false);
    assert.equal(classifyMailtrapRecordFailure(401), false);
    assert.equal(MAILTRAP_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
