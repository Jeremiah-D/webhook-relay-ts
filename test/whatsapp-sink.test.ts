import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  WhatsAppSink,
  WhatsAppSinkConfigError,
  WhatsAppSinkError,
  assertValidWhatsAppSinkConfig,
  buildWhatsAppMessageBody,
  classifyWhatsAppRecordFailure,
  resolveWhatsAppNotification,
  resolveWhatsAppRecord,
  resolveWhatsAppContent,
  truncateWhatsAppPayload,
  whatsappMessagesUrl,
  WHATSAPP_DEFAULT_PAYLOAD_MAX_CHARS,
  WHATSAPP_FALLBACK_SUMMARY,
  WHATSAPP_GRAPH_API_HOST,
  WHATSAPP_GRAPH_API_VERSION,
  type WhatsAppMessageClient,
  type WhatsAppMessagePostRequest,
  type WhatsAppMessagePostResponse,
  type WhatsAppSinkConfig,
} from "../src/whatsapp-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements WhatsAppMessageClient {
  posts: WhatsAppMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: WhatsAppMessagePostRequest): Promise<WhatsAppMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200 };
  }
}

const phoneNumberId = "123456789012345";
const to = "14155551234";

function baseConfig(
  client: WhatsAppMessageClient,
  extra: Partial<WhatsAppSinkConfig> = {}
): WhatsAppSinkConfig {
  return { phoneNumberId, to, client, ...extra };
}

describe("whatsapp-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidWhatsAppSinkConfig(null, "WhatsAppSink"), RangeError);
    assert.throws(() => assertValidWhatsAppSinkConfig("x", "WhatsAppSink"), RangeError);
  });

  it("rejects a malformed phone-number id or recipient shape", () => {
    assert.throws(
      () => assertValidWhatsAppSinkConfig({ phoneNumberId: "" }, "WhatsAppSink"),
      RangeError
    );
    assert.throws(
      () => assertValidWhatsAppSinkConfig({ phoneNumberId: "has space" }, "WhatsAppSink"),
      RangeError
    );
    assert.throws(
      () => assertValidWhatsAppSinkConfig({ to: "" }, "WhatsAppSink"),
      RangeError
    );
    assert.throws(
      () => assertValidWhatsAppSinkConfig({ to: "has space" }, "WhatsAppSink"),
      RangeError
    );
  });

  it("rejects a client without a post function", () => {
    assert.throws(
      () => assertValidWhatsAppSinkConfig({ client: {} }, "WhatsAppSink"),
      RangeError
    );
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(
      () => assertValidWhatsAppSinkConfig({ payloadMaxChars: 0 }, "WhatsAppSink"),
      RangeError
    );
    assert.throws(
      () => assertValidWhatsAppSinkConfig({ payloadMaxChars: 2.5 }, "WhatsAppSink"),
      RangeError
    );
  });

  it("accepts a config with no phone-number id or recipient yet (send-time config error)", () => {
    assert.doesNotThrow(() => new WhatsAppSink({}));
  });
});

describe("whatsapp-sink content derivation", () => {
  it("prefers subject, then key, then traceId, then the fallback summary", () => {
    assert.equal(
      resolveWhatsAppContent({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveWhatsAppContent({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveWhatsAppContent({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveWhatsAppContent({ body: "{}" }), WHATSAPP_FALLBACK_SUMMARY);
    assert.equal(
      resolveWhatsAppContent({ body: "{}", subject: "", key: "", traceId: "" }),
      WHATSAPP_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateWhatsAppPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateWhatsAppPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveWhatsAppNotification(record, {}), { text: "order.created" });
    assert.deepEqual(resolveWhatsAppNotification(record, { includePayload: true }), {
      text: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveWhatsAppNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { text: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveWhatsAppRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("whatsapp-sink wire shape", () => {
  it("builds the pinned-version messages URL with the id only in the path", () => {
    assert.equal(WHATSAPP_GRAPH_API_HOST, "graph.facebook.com");
    assert.equal(WHATSAPP_GRAPH_API_VERSION, "v26.0");
    assert.equal(
      whatsappMessagesUrl(phoneNumberId),
      "https://graph.facebook.com/v26.0/123456789012345/messages"
    );
  });

  it("builds the JSON body with messaging_product, recipient_type, to, type, and text, no credential or id", () => {
    assert.equal(
      buildWhatsAppMessageBody(to, "order.created"),
      JSON.stringify({
        messaging_product: "whatsapp",
        recipient_type: "individual",
        to,
        type: "text",
        text: { body: "order.created", preview_url: false },
      })
    );
    // The phone-number id never appears in the body — only in the URL path.
    assert.equal(buildWhatsAppMessageBody(to, "x").includes(phoneNumberId), false);
  });
});

describe("whatsapp-sink send", () => {
  it("posts one message per record with the id, recipient, and JSON body, no credential", async () => {
    const client = new FakeClient();
    const sink = new WhatsAppSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    assert.deepEqual(client.posts[0], {
      phoneNumberId,
      to,
      body: JSON.stringify({
        messaging_product: "whatsapp",
        recipient_type: "individual",
        to,
        type: "text",
        text: { body: "order.created", preview_url: false },
      }),
    });
    assert.deepEqual(
      JSON.parse(client.posts[1].body).text,
      { body: "agg-8", preview_url: false }
    );
    // The request carries no credential anywhere: the access
    // token is held by the client alone, and the body never
    // carries the phone-number id either.
    for (const post of client.posts) {
      assert.equal("token" in post, false);
      assert.equal(post.body.includes("Bearer"), false);
      assert.equal(post.body.includes(phoneNumberId), false);
    }
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new WhatsAppSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof WhatsAppSinkError);
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
    const sink = new WhatsAppSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof WhatsAppSinkError);
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

  it("fails closed without a client, phone-number id, or recipient", async () => {
    await assert.rejects(
      () => new WhatsAppSink({ phoneNumberId, to }).send([{ body: '{"a":1}' }]),
      WhatsAppSinkConfigError
    );
    await assert.rejects(
      () => new WhatsAppSink(baseConfig(new FakeClient(), { phoneNumberId: undefined })).send([{ body: '{"a":1}' }]),
      WhatsAppSinkConfigError
    );
    await assert.rejects(
      () => new WhatsAppSink(baseConfig(new FakeClient(), { to: undefined })).send([{ body: '{"a":1}' }]),
      WhatsAppSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new WhatsAppSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new WhatsAppSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new WhatsAppSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyWhatsAppRecordFailure(429), true);
    assert.equal(classifyWhatsAppRecordFailure(500), true);
    assert.equal(classifyWhatsAppRecordFailure(503), true);
    assert.equal(classifyWhatsAppRecordFailure(400), false);
    assert.equal(classifyWhatsAppRecordFailure(401), false);
    assert.equal(classifyWhatsAppRecordFailure(404), false);
    assert.equal(WHATSAPP_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
