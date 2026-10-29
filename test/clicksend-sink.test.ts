import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  ClickSendSink,
  ClickSendSinkConfigError,
  ClickSendSinkError,
  assertValidClickSendSinkConfig,
  buildClickSendMessageBody,
  classifyClickSendRecordFailure,
  resolveClickSendText,
  resolveClickSendNotification,
  resolveClickSendRecord,
  truncateClickSendPayload,
  CLICKSEND_SEND_URL,
  CLICKSEND_DEFAULT_PAYLOAD_MAX_CHARS,
  CLICKSEND_DEFAULT_SOURCE,
  CLICKSEND_FALLBACK_SUMMARY,
  type ClickSendMessageClient,
  type ClickSendMessagePostRequest,
  type ClickSendMessagePostResponse,
  type ClickSendSinkConfig,
} from "../src/clicksend-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements ClickSendMessageClient {
  posts: ClickSendMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: ClickSendMessagePostRequest): Promise<ClickSendMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200 };
  }
}

const from = "+14155550100";
const to = "+14155550101";

function baseConfig(
  client: ClickSendMessageClient,
  extra: Partial<ClickSendSinkConfig> = {}
): ClickSendSinkConfig {
  return { from, to, client, ...extra };
}

describe("clicksend-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidClickSendSinkConfig(null, "ClickSendSink"), RangeError);
    assert.throws(() => assertValidClickSendSinkConfig("x", "ClickSendSink"), RangeError);
  });

  it("rejects a malformed sender or recipient shape", () => {
    assert.throws(() => assertValidClickSendSinkConfig({ from: "" }, "ClickSendSink"), RangeError);
    assert.throws(() => assertValidClickSendSinkConfig({ from: "has space" }, "ClickSendSink"), RangeError);
    assert.throws(() => assertValidClickSendSinkConfig({ to: "" }, "ClickSendSink"), RangeError);
    assert.throws(() => assertValidClickSendSinkConfig({ to: "has space" }, "ClickSendSink"), RangeError);
    assert.throws(() => assertValidClickSendSinkConfig({ source: "" }, "ClickSendSink"), RangeError);
    assert.throws(() => assertValidClickSendSinkConfig({ source: "has space" }, "ClickSendSink"), RangeError);
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidClickSendSinkConfig({ client: {} }, "ClickSendSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidClickSendSinkConfig({ payloadMaxChars: 0 }, "ClickSendSink"), RangeError);
    assert.throws(() => assertValidClickSendSinkConfig({ payloadMaxChars: 2.5 }, "ClickSendSink"), RangeError);
  });

  it("accepts a config with no sender or recipient yet (send-time config error)", () => {
    assert.doesNotThrow(() => new ClickSendSink({}));
  });
});

describe("clicksend-sink text derivation", () => {
  it("derives the text from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveClickSendText({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveClickSendText({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveClickSendText({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveClickSendText({ body: "{}" }), CLICKSEND_FALLBACK_SUMMARY);
    assert.equal(
      resolveClickSendText({ body: "{}", subject: "", key: "", traceId: "" }),
      CLICKSEND_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateClickSendPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateClickSendPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveClickSendNotification(record, {}), { body: "order.created" });
    assert.deepEqual(resolveClickSendNotification(record, { includePayload: true }), {
      body: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveClickSendNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { body: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveClickSendRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("clicksend-sink wire shape", () => {
  it("exposes the fixed ClickSend SMS endpoint", () => {
    assert.equal(CLICKSEND_SEND_URL, "https://rest.clicksend.com/v3/sms/send");
    assert.equal(CLICKSEND_DEFAULT_SOURCE, "webhook-relay");
  });

  it("builds the JSON body with a messages envelope — and no credential", () => {
    assert.equal(
      buildClickSendMessageBody(from, to, "order.created", "webhook-relay"),
      JSON.stringify({
        messages: [{ source: "webhook-relay", from, to, body: "order.created" }],
      })
    );
    const body = buildClickSendMessageBody(from, to, "x", "webhook-relay");
    assert.equal(body.includes("Basic"), false);
    assert.equal(body.includes("password"), false);
    assert.equal(body.includes("apiKey"), false);
    assert.equal(Object.keys(JSON.parse(body)).join(","), "messages");
    assert.equal(
      Object.keys(JSON.parse(body).messages[0]).join(","),
      "source,from,to,body"
    );
  });
});

describe("clicksend-sink send", () => {
  it("posts one message per record to the fixed SMS endpoint with the JSON body, no credential", async () => {
    const client = new FakeClient();
    const sink = new ClickSendSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: CLICKSEND_SEND_URL,
      body: JSON.stringify({
        messages: [{ source: "webhook-relay", from, to, body: "order.created" }],
      }),
    });
    assert.deepEqual(JSON.parse(client.posts[1].body).messages[0].body, "agg-8");
    assert.deepEqual(JSON.parse(client.posts[2].body).messages[0].body, "t-9");
    for (const post of client.posts) {
      assert.equal(post.body.includes("Basic"), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("applies the payload opt-in truncation on send", async () => {
    const client = new FakeClient();
    const sink = new ClickSendSink(
      baseConfig(client, { includePayload: true, payloadMaxChars: 3 })
    );
    await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.equal(
      JSON.parse(client.posts[0].body).messages[0].body,
      `order.created\n\n{"a… (truncated)`
    );
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new ClickSendSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof ClickSendSinkError);
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
    const sink = new ClickSendSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof ClickSendSinkError);
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
      () =>
        new ClickSendSink({ from, to }).send([{ body: '{"a":1}' }]),
      ClickSendSinkConfigError
    );
    await assert.rejects(
      () =>
        new ClickSendSink(baseConfig(new FakeClient(), { from: undefined })).send([
          { body: '{"a":1}' },
        ]),
      ClickSendSinkConfigError
    );
    await assert.rejects(
      () =>
        new ClickSendSink(baseConfig(new FakeClient(), { to: undefined })).send([
          { body: '{"a":1}' },
        ]),
      ClickSendSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new ClickSendSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new ClickSendSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new ClickSendSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyClickSendRecordFailure(429), true);
    assert.equal(classifyClickSendRecordFailure(500), true);
    assert.equal(classifyClickSendRecordFailure(503), true);
    assert.equal(classifyClickSendRecordFailure(400), false);
    assert.equal(classifyClickSendRecordFailure(401), false);
    assert.equal(classifyClickSendRecordFailure(404), false);
    assert.equal(CLICKSEND_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
