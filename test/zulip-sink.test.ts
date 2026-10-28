import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  ZulipSink,
  ZulipSinkConfigError,
  ZulipSinkError,
  assertValidZulipSinkConfig,
  buildZulipFormBody,
  classifyZulipRecordFailure,
  normalizeZulipSite,
  resolveZulipNotification,
  resolveZulipRecord,
  resolveZulipContent,
  truncateZulipPayload,
  zulipMessagesUrl,
  ZULIP_DEFAULT_PAYLOAD_MAX_CHARS,
  ZULIP_FALLBACK_SUMMARY,
  ZULIP_MESSAGES_PATH,
  type ZulipMessageClient,
  type ZulipMessagePostRequest,
  type ZulipMessagePostResponse,
  type ZulipSinkConfig,
} from "../src/zulip-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements ZulipMessageClient {
  posts: ZulipMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: ZulipMessagePostRequest): Promise<ZulipMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 201 };
  }
}

const site = "https://zulip.example.com";
const to = "alerts";
const subject = "webhook events";

function baseConfig(
  client: ZulipMessageClient,
  extra: Partial<ZulipSinkConfig> = {}
): ZulipSinkConfig {
  return { site, to, subject, client, ...extra };
}

describe("zulip-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidZulipSinkConfig(null, "ZulipSink"), RangeError);
    assert.throws(() => assertValidZulipSinkConfig("x", "ZulipSink"), RangeError);
  });

  it("rejects a malformed site, stream, or topic shape", () => {
    assert.throws(
      () => assertValidZulipSinkConfig({ site: "" }, "ZulipSink"),
      RangeError
    );
    assert.throws(
      () => assertValidZulipSinkConfig({ site: "has space" }, "ZulipSink"),
      RangeError
    );
    assert.throws(
      () => assertValidZulipSinkConfig({ to: "" }, "ZulipSink"),
      RangeError
    );
    assert.throws(
      () => assertValidZulipSinkConfig({ subject: "" }, "ZulipSink"),
      RangeError
    );
  });

  it("accepts spaces in stream and topic names (human names, not identifiers)", () => {
    assert.doesNotThrow(() =>
      assertValidZulipSinkConfig({ to: "general chat", subject: "webhook events" }, "ZulipSink")
    );
  });

  it("rejects a client without a post function", () => {
    assert.throws(
      () => assertValidZulipSinkConfig({ client: {} }, "ZulipSink"),
      RangeError
    );
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(
      () => assertValidZulipSinkConfig({ payloadMaxChars: 0 }, "ZulipSink"),
      RangeError
    );
    assert.throws(
      () => assertValidZulipSinkConfig({ payloadMaxChars: 2.5 }, "ZulipSink"),
      RangeError
    );
  });

  it("accepts a config with no site or stream yet (send-time config error)", () => {
    assert.doesNotThrow(() => new ZulipSink({}));
  });
});

describe("zulip-sink content derivation", () => {
  it("prefers subject, then key, then traceId, then the fallback summary", () => {
    assert.equal(
      resolveZulipContent({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveZulipContent({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveZulipContent({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveZulipContent({ body: "{}" }), ZULIP_FALLBACK_SUMMARY);
    assert.equal(
      resolveZulipContent({ body: "{}", subject: "", key: "", traceId: "" }),
      ZULIP_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateZulipPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateZulipPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveZulipNotification(record, {}), { content: "order.created" });
    assert.deepEqual(resolveZulipNotification(record, { includePayload: true }), {
      content: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveZulipNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { content: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveZulipRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("zulip-sink wire shape", () => {
  it("builds the site-scoped messages URL with trailing slashes stripped", () => {
    assert.equal(ZULIP_MESSAGES_PATH, "/api/v1/messages");
    assert.equal(zulipMessagesUrl(site), "https://zulip.example.com/api/v1/messages");
    assert.equal(zulipMessagesUrl("https://zulip.example.com///"), "https://zulip.example.com/api/v1/messages");
    assert.equal(normalizeZulipSite("https://zulip.example.com/"), "https://zulip.example.com");
  });

  it("form-encodes type, to, subject, and content in order, escaping reserved characters", () => {
    assert.equal(
      buildZulipFormBody(to, subject, "order.created"),
      "type=stream&to=alerts&subject=webhook%20events&content=order.created"
    );
    assert.equal(
      buildZulipFormBody("general chat", "a&b", "x=y\nz"),
      "type=stream&to=general%20chat&subject=a%26b&content=x%3Dy%0Az"
    );
  });
});

describe("zulip-sink send", () => {
  it("posts one message per record with the site, stream, topic, and form body, no credential", async () => {
    const client = new FakeClient();
    const sink = new ZulipSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    assert.deepEqual(client.posts[0], {
      site,
      to,
      subject,
      body: "type=stream&to=alerts&subject=webhook%20events&content=order.created",
    });
    assert.deepEqual(client.posts[1].body, "type=stream&to=alerts&subject=webhook%20events&content=agg-8");
    // The request carries no credential anywhere: the bot email and
    // API key are held by the client alone.
    for (const post of client.posts) {
      assert.equal("apiKey" in post, false);
      assert.equal("email" in post, false);
      assert.equal(post.body.includes("Basic"), false);
    }
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new ZulipSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof ZulipSinkError);
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
    const sink = new ZulipSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof ZulipSinkError);
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

  it("fails closed without a client, site, stream, or topic", async () => {
    await assert.rejects(
      () => new ZulipSink({ site, to, subject }).send([{ body: '{"a":1}' }]),
      ZulipSinkConfigError
    );
    await assert.rejects(
      () => new ZulipSink(baseConfig(new FakeClient(), { site: undefined })).send([{ body: '{"a":1}' }]),
      ZulipSinkConfigError
    );
    await assert.rejects(
      () => new ZulipSink(baseConfig(new FakeClient(), { to: undefined })).send([{ body: '{"a":1}' }]),
      ZulipSinkConfigError
    );
    await assert.rejects(
      () => new ZulipSink(baseConfig(new FakeClient(), { subject: undefined })).send([{ body: '{"a":1}' }]),
      ZulipSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new ZulipSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new ZulipSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new ZulipSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyZulipRecordFailure(429), true);
    assert.equal(classifyZulipRecordFailure(500), true);
    assert.equal(classifyZulipRecordFailure(503), true);
    assert.equal(classifyZulipRecordFailure(400), false);
    assert.equal(classifyZulipRecordFailure(401), false);
    assert.equal(classifyZulipRecordFailure(404), false);
    assert.equal(ZULIP_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
