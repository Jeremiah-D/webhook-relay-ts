import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  OneSignalSink,
  OneSignalSinkConfigError,
  OneSignalSinkError,
  assertValidOneSignalSinkConfig,
  buildOneSignalMessageBody,
  classifyOneSignalRecordFailure,
  resolveOneSignalContent,
  resolveOneSignalHeadings,
  resolveOneSignalNotification,
  resolveOneSignalRecord,
  truncateOneSignalPayload,
  ONESIGNAL_SEND_URL,
  ONESIGNAL_DEFAULT_PAYLOAD_MAX_CHARS,
  ONESIGNAL_FALLBACK_SUMMARY,
  type OneSignalMessageClient,
  type OneSignalMessagePostRequest,
  type OneSignalMessagePostResponse,
  type OneSignalSinkConfig,
} from "../src/onesignal-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements OneSignalMessageClient {
  posts: OneSignalMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: OneSignalMessagePostRequest): Promise<OneSignalMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200 };
  }
}

const appId = "app-123";
const includePlayerIds = ["player-1", "player-2"];

function baseConfig(
  client: OneSignalMessageClient,
  extra: Partial<OneSignalSinkConfig> = {}
): OneSignalSinkConfig {
  return { appId, includePlayerIds, client, ...extra };
}

describe("onesignal-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidOneSignalSinkConfig(null, "OneSignalSink"), RangeError);
    assert.throws(() => assertValidOneSignalSinkConfig("x", "OneSignalSink"), RangeError);
  });

  it("rejects a malformed app id shape", () => {
    assert.throws(() => assertValidOneSignalSinkConfig({ appId: "" }, "OneSignalSink"), RangeError);
    assert.throws(
      () => assertValidOneSignalSinkConfig({ appId: "has space" }, "OneSignalSink"),
      RangeError
    );
    assert.throws(() => assertValidOneSignalSinkConfig({ appId: 42 }, "OneSignalSink"), RangeError);
  });

  it("rejects a malformed player id set shape", () => {
    assert.throws(
      () => assertValidOneSignalSinkConfig({ includePlayerIds: "x" }, "OneSignalSink"),
      RangeError
    );
    assert.throws(
      () => assertValidOneSignalSinkConfig({ includePlayerIds: [] }, "OneSignalSink"),
      RangeError
    );
    assert.throws(
      () => assertValidOneSignalSinkConfig({ includePlayerIds: [""] }, "OneSignalSink"),
      RangeError
    );
    assert.throws(
      () =>
        assertValidOneSignalSinkConfig({ includePlayerIds: ["has space"] }, "OneSignalSink"),
      RangeError
    );
    assert.throws(
      () =>
        assertValidOneSignalSinkConfig({ includePlayerIds: ["player-1", 42] }, "OneSignalSink"),
      RangeError
    );
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidOneSignalSinkConfig({ client: {} }, "OneSignalSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidOneSignalSinkConfig({ payloadMaxChars: 0 }, "OneSignalSink"), RangeError);
    assert.throws(
      () => assertValidOneSignalSinkConfig({ payloadMaxChars: 2.5 }, "OneSignalSink"),
      RangeError
    );
  });

  it("accepts a config with no app id or player set yet (send-time config error)", () => {
    assert.doesNotThrow(() => new OneSignalSink({}));
  });
});

describe("onesignal-sink headings/contents derivation", () => {
  it("derives contents from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveOneSignalContent({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveOneSignalContent({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveOneSignalContent({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveOneSignalContent({ body: "{}" }), ONESIGNAL_FALLBACK_SUMMARY);
    assert.equal(
      resolveOneSignalContent({ body: "{}", subject: "", key: "", traceId: "" }),
      ONESIGNAL_FALLBACK_SUMMARY
    );
  });

  it("takes headings from the subject alone and omits them without one", () => {
    assert.deepEqual(resolveOneSignalHeadings({ body: "{}", subject: "order.created" }), {
      en: "order.created",
    });
    assert.equal(resolveOneSignalHeadings({ body: "{}", key: "agg-7" }), undefined);
    assert.equal(resolveOneSignalHeadings({ body: "{}" }), undefined);
    assert.equal(resolveOneSignalHeadings({ body: "{}", subject: "" }), undefined);
  });

  it("splits subject into headings and contents, key-only events carry contents alone", () => {
    assert.deepEqual(resolveOneSignalNotification({ body: "{}", subject: "order.created" }, {}), {
      headings: { en: "order.created" },
      contents: { en: "order.created" },
    });
    assert.deepEqual(resolveOneSignalNotification({ body: "{}", key: "agg-7" }, {}), {
      contents: { en: "agg-7" },
    });
    assert.deepEqual(resolveOneSignalNotification({ body: "{}" }, {}), {
      contents: { en: ONESIGNAL_FALLBACK_SUMMARY },
    });
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateOneSignalPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateOneSignalPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveOneSignalNotification(record, {}), {
      headings: { en: "order.created" },
      contents: { en: "order.created" },
    });
    assert.deepEqual(resolveOneSignalNotification(record, { includePayload: true }), {
      headings: { en: "order.created" },
      contents: { en: `order.created\n\n{"a":1}` },
    });
    assert.deepEqual(
      resolveOneSignalNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      {
        headings: { en: "order.created" },
        contents: { en: `order.created\n\n{"a… (truncated)` },
      }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveOneSignalRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("onesignal-sink wire shape", () => {
  it("exposes the fixed OneSignal notifications endpoint", () => {
    assert.equal(ONESIGNAL_SEND_URL, "https://api.onesignal.com/notifications");
  });

  it("builds the JSON body with app_id, include_player_ids, headings, contents — and no credential", () => {
    assert.equal(
      buildOneSignalMessageBody(appId, includePlayerIds, {
        headings: { en: "order.created" },
        contents: { en: "order.created" },
      }),
      JSON.stringify({
        app_id: appId,
        include_player_ids: includePlayerIds,
        headings: { en: "order.created" },
        contents: { en: "order.created" },
      })
    );
    assert.equal(
      buildOneSignalMessageBody(appId, includePlayerIds, { contents: { en: "agg-7" } }),
      JSON.stringify({
        app_id: appId,
        include_player_ids: includePlayerIds,
        contents: { en: "agg-7" },
      })
    );
    const body = buildOneSignalMessageBody(appId, includePlayerIds, {
      headings: { en: "x" },
      contents: { en: "x" },
    });
    assert.equal(body.includes("REST API key"), false);
    assert.equal(body.includes("api_key"), false);
    assert.equal(body.includes("Authorization"), false);
    assert.equal(body.includes("Basic"), false);
    assert.equal(Object.keys(JSON.parse(body)).join(","), "app_id,include_player_ids,headings,contents");
    assert.deepEqual(JSON.parse(body).include_player_ids, includePlayerIds);
  });
});

describe("onesignal-sink send", () => {
  it("posts one message per record to the fixed endpoint with the JSON body, no credential", async () => {
    const client = new FakeClient();
    const sink = new OneSignalSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: ONESIGNAL_SEND_URL,
      body: JSON.stringify({
        app_id: appId,
        include_player_ids: includePlayerIds,
        headings: { en: "order.created" },
        contents: { en: "order.created" },
      }),
    });
    assert.deepEqual(JSON.parse(client.posts[1].body), {
      app_id: appId,
      include_player_ids: includePlayerIds,
      contents: { en: "agg-8" },
    });
    assert.deepEqual(JSON.parse(client.posts[2].body).contents, { en: "t-9" });
    for (const post of client.posts) {
      assert.equal(post.body.includes("Authorization"), false);
      assert.equal(post.body.includes("Basic"), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("applies the payload opt-in truncation on send", async () => {
    const client = new FakeClient();
    const sink = new OneSignalSink(
      baseConfig(client, { includePayload: true, payloadMaxChars: 3 })
    );
    await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.equal(
      JSON.parse(client.posts[0].body).contents.en,
      `order.created\n\n{"a… (truncated)`
    );
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new OneSignalSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof OneSignalSinkError);
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
    const sink = new OneSignalSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof OneSignalSinkError);
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

  it("fails closed without a client, app id, or player set", async () => {
    await assert.rejects(
      () => new OneSignalSink({ appId, includePlayerIds }).send([{ body: '{"a":1}' }]),
      OneSignalSinkConfigError
    );
    await assert.rejects(
      () =>
        new OneSignalSink(baseConfig(new FakeClient(), { appId: undefined })).send([
          { body: '{"a":1}' },
        ]),
      OneSignalSinkConfigError
    );
    await assert.rejects(
      () =>
        new OneSignalSink(baseConfig(new FakeClient(), { includePlayerIds: undefined })).send([
          { body: '{"a":1}' },
        ]),
      OneSignalSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new OneSignalSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new OneSignalSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new OneSignalSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyOneSignalRecordFailure(429), true);
    assert.equal(classifyOneSignalRecordFailure(500), true);
    assert.equal(classifyOneSignalRecordFailure(503), true);
    assert.equal(classifyOneSignalRecordFailure(400), false);
    assert.equal(classifyOneSignalRecordFailure(401), false);
    assert.equal(classifyOneSignalRecordFailure(404), false);
    assert.equal(ONESIGNAL_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
