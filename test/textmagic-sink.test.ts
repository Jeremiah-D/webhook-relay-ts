import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  TextMagicSink,
  TextMagicSinkConfigError,
  TextMagicSinkError,
  assertValidTextMagicSinkConfig,
  buildTextMagicMessageBody,
  classifyTextMagicRecordFailure,
  resolveTextMagicText,
  resolveTextMagicNotification,
  resolveTextMagicRecord,
  truncateTextMagicPayload,
  TEXTMAGIC_SEND_URL,
  TEXTMAGIC_DEFAULT_PAYLOAD_MAX_CHARS,
  TEXTMAGIC_FALLBACK_SUMMARY,
  type TextMagicMessageClient,
  type TextMagicMessagePostRequest,
  type TextMagicMessagePostResponse,
  type TextMagicSinkConfig,
} from "../src/textmagic-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements TextMagicMessageClient {
  posts: TextMagicMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: TextMagicMessagePostRequest): Promise<TextMagicMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200 };
  }
}

const phones = ["+14155550100", "+14155550101"];

function baseConfig(
  client: TextMagicMessageClient,
  extra: Partial<TextMagicSinkConfig> = {}
): TextMagicSinkConfig {
  return { phones, client, ...extra };
}

describe("textmagic-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidTextMagicSinkConfig(null, "TextMagicSink"), RangeError);
    assert.throws(() => assertValidTextMagicSinkConfig("x", "TextMagicSink"), RangeError);
  });

  it("rejects a malformed recipient set shape", () => {
    assert.throws(() => assertValidTextMagicSinkConfig({ phones: "x" }, "TextMagicSink"), RangeError);
    assert.throws(() => assertValidTextMagicSinkConfig({ phones: [] }, "TextMagicSink"), RangeError);
    assert.throws(() => assertValidTextMagicSinkConfig({ phones: [""] }, "TextMagicSink"), RangeError);
    assert.throws(
      () => assertValidTextMagicSinkConfig({ phones: ["has space"] }, "TextMagicSink"),
      RangeError
    );
    assert.throws(
      () => assertValidTextMagicSinkConfig({ phones: ["+14155550100", 42] }, "TextMagicSink"),
      RangeError
    );
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidTextMagicSinkConfig({ client: {} }, "TextMagicSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidTextMagicSinkConfig({ payloadMaxChars: 0 }, "TextMagicSink"), RangeError);
    assert.throws(() => assertValidTextMagicSinkConfig({ payloadMaxChars: 2.5 }, "TextMagicSink"), RangeError);
  });

  it("accepts a config with no recipient set yet (send-time config error)", () => {
    assert.doesNotThrow(() => new TextMagicSink({}));
  });
});

describe("textmagic-sink text derivation", () => {
  it("derives the text from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveTextMagicText({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveTextMagicText({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveTextMagicText({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveTextMagicText({ body: "{}" }), TEXTMAGIC_FALLBACK_SUMMARY);
    assert.equal(
      resolveTextMagicText({ body: "{}", subject: "", key: "", traceId: "" }),
      TEXTMAGIC_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateTextMagicPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateTextMagicPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveTextMagicNotification(record, {}), { text: "order.created" });
    assert.deepEqual(resolveTextMagicNotification(record, { includePayload: true }), {
      text: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveTextMagicNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { text: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveTextMagicRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("textmagic-sink wire shape", () => {
  it("exposes the fixed TextMagic SMS endpoint", () => {
    assert.equal(TEXTMAGIC_SEND_URL, "https://rest.textmagic.com/api/v2/messages");
  });

  it("builds the flat JSON body with text and phones — and no credential", () => {
    assert.equal(
      buildTextMagicMessageBody("order.created", phones),
      JSON.stringify({ text: "order.created", phones })
    );
    const body = buildTextMagicMessageBody("x", phones);
    assert.equal(body.includes("X-TM-Username"), false);
    assert.equal(body.includes("X-TM-Key"), false);
    assert.equal(body.includes("username"), false);
    assert.equal(body.includes("apiKey"), false);
    assert.equal(body.includes("password"), false);
    assert.equal(Object.keys(JSON.parse(body)).join(","), "text,phones");
    assert.deepEqual(JSON.parse(body).phones, phones);
  });
});

describe("textmagic-sink send", () => {
  it("posts one message per record to the fixed SMS endpoint with the JSON body, no credential", async () => {
    const client = new FakeClient();
    const sink = new TextMagicSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: TEXTMAGIC_SEND_URL,
      body: JSON.stringify({ text: "order.created", phones }),
    });
    assert.deepEqual(JSON.parse(client.posts[1].body).text, "agg-8");
    assert.deepEqual(JSON.parse(client.posts[2].body).text, "t-9");
    for (const post of client.posts) {
      assert.equal(post.body.includes("X-TM-Username"), false);
      assert.equal(post.body.includes("X-TM-Key"), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("applies the payload opt-in truncation on send", async () => {
    const client = new FakeClient();
    const sink = new TextMagicSink(
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
    const sink = new TextMagicSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof TextMagicSinkError);
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
    const sink = new TextMagicSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof TextMagicSinkError);
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

  it("fails closed without a client or recipient set", async () => {
    await assert.rejects(
      () => new TextMagicSink({ phones }).send([{ body: '{"a":1}' }]),
      TextMagicSinkConfigError
    );
    await assert.rejects(
      () =>
        new TextMagicSink(baseConfig(new FakeClient(), { phones: undefined })).send([
          { body: '{"a":1}' },
        ]),
      TextMagicSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new TextMagicSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new TextMagicSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new TextMagicSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyTextMagicRecordFailure(429), true);
    assert.equal(classifyTextMagicRecordFailure(500), true);
    assert.equal(classifyTextMagicRecordFailure(503), true);
    assert.equal(classifyTextMagicRecordFailure(400), false);
    assert.equal(classifyTextMagicRecordFailure(401), false);
    assert.equal(classifyTextMagicRecordFailure(404), false);
    assert.equal(TEXTMAGIC_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
