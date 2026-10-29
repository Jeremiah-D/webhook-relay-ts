import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  InfobipSink,
  InfobipSinkConfigError,
  InfobipSinkError,
  assertValidInfobipSinkConfig,
  buildInfobipMessageBody,
  classifyInfobipRecordFailure,
  resolveInfobipText,
  resolveInfobipNotification,
  resolveInfobipRecord,
  truncateInfobipPayload,
  INFOBIP_SEND_PATH,
  buildInfobipSendUrl,
  INFOBIP_DEFAULT_PAYLOAD_MAX_CHARS,
  INFOBIP_FALLBACK_SUMMARY,
  type InfobipMessageClient,
  type InfobipMessagePostRequest,
  type InfobipMessagePostResponse,
  type InfobipSinkConfig,
} from "../src/infobip-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements InfobipMessageClient {
  posts: InfobipMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: InfobipMessagePostRequest): Promise<InfobipMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200 };
  }
}

const from = "+14155550100";
const to = "+14155550101";
const baseUrl = "https://xxx.api.infobip.com";

function baseConfig(
  client: InfobipMessageClient,
  extra: Partial<InfobipSinkConfig> = {}
): InfobipSinkConfig {
  return { from, to, baseUrl, client, ...extra };
}

describe("infobip-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidInfobipSinkConfig(null, "InfobipSink"), RangeError);
    assert.throws(() => assertValidInfobipSinkConfig("x", "InfobipSink"), RangeError);
  });

  it("rejects a malformed sender, recipient, or base URL shape", () => {
    assert.throws(() => assertValidInfobipSinkConfig({ from: "" }, "InfobipSink"), RangeError);
    assert.throws(() => assertValidInfobipSinkConfig({ from: "has space" }, "InfobipSink"), RangeError);
    assert.throws(() => assertValidInfobipSinkConfig({ to: "" }, "InfobipSink"), RangeError);
    assert.throws(() => assertValidInfobipSinkConfig({ to: "has space" }, "InfobipSink"), RangeError);
    assert.throws(() => assertValidInfobipSinkConfig({ baseUrl: "" }, "InfobipSink"), RangeError);
    assert.throws(() => assertValidInfobipSinkConfig({ baseUrl: "has space" }, "InfobipSink"), RangeError);
  });

  it("builds the account endpoint from the base URL without adding a protocol prefix", () => {
    assert.equal(
      buildInfobipSendUrl("https://xxx.api.infobip.com"),
      "https://xxx.api.infobip.com/sms/2/text/advanced"
    );
    assert.equal(
      buildInfobipSendUrl("https://xxx.api.infobip.com/"),
      "https://xxx.api.infobip.com/sms/2/text/advanced"
    );
    assert.equal(INFOBIP_SEND_PATH, "/sms/2/text/advanced");
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidInfobipSinkConfig({ client: {} }, "InfobipSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidInfobipSinkConfig({ payloadMaxChars: 0 }, "InfobipSink"), RangeError);
    assert.throws(() => assertValidInfobipSinkConfig({ payloadMaxChars: 2.5 }, "InfobipSink"), RangeError);
  });

  it("accepts a config with no sender, recipient, or base URL yet (send-time config error)", () => {
    assert.doesNotThrow(() => new InfobipSink({}));
  });
});

describe("infobip-sink text derivation", () => {
  it("derives the text from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveInfobipText({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveInfobipText({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveInfobipText({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveInfobipText({ body: "{}" }), INFOBIP_FALLBACK_SUMMARY);
    assert.equal(
      resolveInfobipText({ body: "{}", subject: "", key: "", traceId: "" }),
      INFOBIP_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateInfobipPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateInfobipPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveInfobipNotification(record, {}), { text: "order.created" });
    assert.deepEqual(resolveInfobipNotification(record, { includePayload: true }), {
      text: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveInfobipNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { text: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveInfobipRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("infobip-sink wire shape", () => {
  it("builds the JSON body with a messages envelope — and no credential", () => {
    assert.equal(
      buildInfobipMessageBody(from, to, "order.created"),
      JSON.stringify({
        messages: [{ from, destinations: [{ to }], text: "order.created" }],
      })
    );
    const body = buildInfobipMessageBody(from, to, "x");
    assert.equal(body.includes("App"), false);
    assert.equal(body.includes("apiKey"), false);
    assert.equal(body.includes("password"), false);
    assert.equal(Object.keys(JSON.parse(body)).join(","), "messages");
    assert.equal(Object.keys(JSON.parse(body).messages[0]).join(","), "from,destinations,text");
    assert.deepEqual(JSON.parse(body).messages[0].destinations, [{ to }]);
  });
});

describe("infobip-sink send", () => {
  it("posts one message per record to the account endpoint with the JSON body, no credential", async () => {
    const client = new FakeClient();
    const sink = new InfobipSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: buildInfobipSendUrl(baseUrl),
      body: JSON.stringify({
        messages: [{ from, destinations: [{ to }], text: "order.created" }],
      }),
    });
    assert.deepEqual(JSON.parse(client.posts[1].body).messages[0].text, "agg-8");
    assert.deepEqual(JSON.parse(client.posts[2].body).messages[0].text, "t-9");
    for (const post of client.posts) {
      assert.equal(post.body.includes("App"), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("applies the payload opt-in truncation on send", async () => {
    const client = new FakeClient();
    const sink = new InfobipSink(
      baseConfig(client, { includePayload: true, payloadMaxChars: 3 })
    );
    await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.equal(
      JSON.parse(client.posts[0].body).messages[0].text,
      `order.created\n\n{"a… (truncated)`
    );
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new InfobipSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof InfobipSinkError);
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
    const sink = new InfobipSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof InfobipSinkError);
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

  it("fails closed without a client, sender, recipient, or base URL", async () => {
    await assert.rejects(
      () =>
        new InfobipSink({ from, to }).send([{ body: '{"a":1}' }]),
      InfobipSinkConfigError
    );
    await assert.rejects(
      () =>
        new InfobipSink(baseConfig(new FakeClient(), { from: undefined })).send([
          { body: '{"a":1}' },
        ]),
      InfobipSinkConfigError
    );
    await assert.rejects(
      () =>
        new InfobipSink(baseConfig(new FakeClient(), { to: undefined })).send([
          { body: '{"a":1}' },
        ]),
      InfobipSinkConfigError
    );
    await assert.rejects(
      () =>
        new InfobipSink(baseConfig(new FakeClient(), { baseUrl: undefined })).send([
          { body: '{"a":1}' },
        ]),
      InfobipSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new InfobipSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new InfobipSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new InfobipSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyInfobipRecordFailure(429), true);
    assert.equal(classifyInfobipRecordFailure(500), true);
    assert.equal(classifyInfobipRecordFailure(503), true);
    assert.equal(classifyInfobipRecordFailure(400), false);
    assert.equal(classifyInfobipRecordFailure(401), false);
    assert.equal(classifyInfobipRecordFailure(404), false);
    assert.equal(INFOBIP_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
