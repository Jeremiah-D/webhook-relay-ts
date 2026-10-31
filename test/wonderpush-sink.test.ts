import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  WonderPushSink,
  WonderPushSinkConfigError,
  WonderPushSinkError,
  assertValidWonderPushSinkConfig,
  buildWonderPushFormBody,
  classifyWonderPushRecordFailure,
  hasWonderPushTargeting,
  resolveWonderPushNotification,
  resolveWonderPushRecord,
  resolveWonderPushText,
  serializeWonderPushTargetValue,
  truncateWonderPushPayload,
  wonderPushResponseToFailedRecord,
  WONDERPUSH_DEFAULT_PAYLOAD_MAX_CHARS,
  WONDERPUSH_DELIVERIES_URL,
  WONDERPUSH_FALLBACK_SUMMARY,
  WONDERPUSH_FORM_CONTENT_TYPE,
  type WonderPushMessageClient,
  type WonderPushMessagePostRequest,
  type WonderPushMessagePostResponse,
  type WonderPushSinkConfig,
  type WonderPushTargeting,
} from "../src/wonderpush-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status and delivery id per call. */
class FakeClient implements WonderPushMessageClient {
  posts: WonderPushMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  /** Call-count (0-based) → delivery id to return for that post (undefined = none surfaced). */
  deliveryIdOn = new Map<number, string | undefined>();
  async post(request: WonderPushMessagePostRequest): Promise<WonderPushMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return {
      status: this.statusOn.get(n) ?? 201,
      deliveryId: this.deliveryIdOn.has(n) ? this.deliveryIdOn.get(n) : `delivery-${n}`,
    };
  }
}

const accessToken = "wonderpush-access-token-123";
const targeting: WonderPushTargeting = { targetSegmentIds: "segment-1" };

function baseConfig(
  client: WonderPushMessageClient,
  extra: Partial<WonderPushSinkConfig> = {}
): WonderPushSinkConfig {
  return { accessToken, targeting, client, ...extra };
}

/** Parse a form body back into a field map for assertions. */
function parseForm(body: string): Record<string, string> {
  return Object.fromEntries(new URLSearchParams(body));
}

describe("wonderpush-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidWonderPushSinkConfig(null, "WonderPushSink"), RangeError);
    assert.throws(() => assertValidWonderPushSinkConfig("x", "WonderPushSink"), RangeError);
  });

  it("rejects a malformed access token shape", () => {
    assert.throws(() => assertValidWonderPushSinkConfig({ accessToken: "" }, "WonderPushSink"), RangeError);
    assert.throws(
      () => assertValidWonderPushSinkConfig({ accessToken: "has space" }, "WonderPushSink"),
      RangeError
    );
    assert.throws(
      () => assertValidWonderPushSinkConfig({ accessToken: 42 }, "WonderPushSink"),
      RangeError
    );
  });

  it("rejects malformed targeting", () => {
    assert.throws(
      () => assertValidWonderPushSinkConfig({ targeting: "not-an-object" }, "WonderPushSink"),
      RangeError
    );
    assert.throws(
      () => assertValidWonderPushSinkConfig({ targeting: ["segment-1"] }, "WonderPushSink"),
      RangeError
    );
    assert.throws(
      () => assertValidWonderPushSinkConfig({ targeting: { targetSegmentIds: "" } }, "WonderPushSink"),
      RangeError
    );
    assert.throws(
      () =>
        assertValidWonderPushSinkConfig(
          { targeting: { targetSegmentIds: [""] } },
          "WonderPushSink"
        ),
      RangeError
    );
    assert.throws(
      () =>
        assertValidWonderPushSinkConfig(
          { targeting: { targetSegmentIds: "has space" } },
          "WonderPushSink"
        ),
      RangeError
    );
    assert.doesNotThrow(() =>
      assertValidWonderPushSinkConfig(
        { targeting: { targetSegmentIds: ["seg-a", "seg-b"], targetTags: "news" } },
        "WonderPushSink"
      )
    );
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidWonderPushSinkConfig({ client: {} }, "WonderPushSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidWonderPushSinkConfig({ payloadMaxChars: 0 }, "WonderPushSink"), RangeError);
    assert.throws(
      () => assertValidWonderPushSinkConfig({ payloadMaxChars: 2.5 }, "WonderPushSink"),
      RangeError
    );
  });

  it("accepts a config with no credentials yet (send-time config error)", () => {
    assert.doesNotThrow(() => new WonderPushSink({}));
  });
});

describe("wonderpush-sink text derivation", () => {
  it("derives the title from subject only — omitted when absent (never key or traceId)", () => {
    assert.deepEqual(
      resolveWonderPushNotification({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }, {}),
      { title: "order.created", text: "order.created" }
    );
    assert.deepEqual(resolveWonderPushNotification({ body: "{}", key: "agg-7", traceId: "t-1" }, {}), {
      text: "agg-7",
    });
    assert.deepEqual(resolveWonderPushNotification({ body: "{}", traceId: "t-1" }, {}), { text: "t-1" });
    assert.deepEqual(resolveWonderPushNotification({ body: "{}" }, {}), {
      text: WONDERPUSH_FALLBACK_SUMMARY,
    });
  });

  it("derives the text from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveWonderPushText({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveWonderPushText({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveWonderPushText({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveWonderPushText({ body: "{}" }), WONDERPUSH_FALLBACK_SUMMARY);
    assert.equal(
      resolveWonderPushText({ body: "{}", subject: "", key: "", traceId: "" }),
      WONDERPUSH_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateWonderPushPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateWonderPushPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveWonderPushNotification(record, {}), {
      title: "order.created",
      text: "order.created",
    });
    assert.deepEqual(resolveWonderPushNotification(record, { includePayload: true }), {
      title: "order.created",
      text: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveWonderPushNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { title: "order.created", text: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveWonderPushRecord({ body: "" }, 2),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("wonderpush-sink wire shape", () => {
  it("exposes the fixed WonderPush deliveries endpoint", () => {
    assert.equal(
      WONDERPUSH_DELIVERIES_URL,
      "https://management-api.wonderpush.com/v1/deliveries"
    );
  });

  it("builds a form-encoded body: accessToken, targeting, then the notification JSON string", () => {
    const fields = parseForm(
      buildWonderPushFormBody(accessToken, targeting, {
        title: "order.created",
        text: "order.created",
      })
    );
    assert.equal(fields.accessToken, accessToken);
    assert.equal(fields.targetSegmentIds, "segment-1");
    assert.equal(
      fields.notification,
      JSON.stringify({ alert: { title: "order.created", text: "order.created" } })
    );
    // The token rides in the form body per the documented auth shape,
    // never in a header and never in the URL.
    assert.equal(WONDERPUSH_DELIVERIES_URL.includes(accessToken), false);
  });

  it("joins array targeting values with commas and omits the title when absent", () => {
    const fields = parseForm(
      buildWonderPushFormBody(
        accessToken,
        { targetSegmentIds: ["seg-a", "seg-b"], targetTags: "news" },
        { text: "agg-7" }
      )
    );
    assert.equal(fields.targetSegmentIds, "seg-a,seg-b");
    assert.equal(fields.targetTags, "news");
    assert.equal(
      fields.notification,
      JSON.stringify({ alert: { text: "agg-7" } })
    );
  });

  it("serializes targeting values", () => {
    assert.equal(serializeWonderPushTargetValue("seg-a"), "seg-a");
    assert.equal(serializeWonderPushTargetValue(["seg-a", "seg-b"]), "seg-a,seg-b");
  });

  it("requires at least one targeting field", () => {
    assert.equal(hasWonderPushTargeting(undefined), false);
    assert.equal(hasWonderPushTargeting({}), false);
    assert.equal(hasWonderPushTargeting({ targetSegmentIds: [] }), false);
    assert.equal(hasWonderPushTargeting({ targetSegmentIds: "" }), false);
    assert.equal(hasWonderPushTargeting({ targetSegmentIds: "seg-1" }), true);
    assert.equal(hasWonderPushTargeting({ targetUserIds: ["u-1"] }), true);
  });
});

describe("wonderpush-sink delivery-id mapping", () => {
  it("accepts a 2xx with a delivery id", () => {
    assert.equal(
      wonderPushResponseToFailedRecord({ status: 201, deliveryId: "del-1" }, 0),
      null
    );
  });

  it("maps a missing delivery id on a 2xx to retryable", () => {
    assert.deepEqual(wonderPushResponseToFailedRecord({ status: 201 }, 0), {
      index: 0,
      errorCode: "DELIVERY_ID_MISSING",
      errorMessage: "WonderPush answered 2xx but surfaced no delivery id",
      retryable: true,
    });
    assert.deepEqual(wonderPushResponseToFailedRecord({ status: 200, deliveryId: "" }, 1), {
      index: 1,
      errorCode: "DELIVERY_ID_MISSING",
      errorMessage: "WonderPush answered 2xx but surfaced no delivery id",
      retryable: true,
    });
  });
});

describe("wonderpush-sink send", () => {
  it("posts one message per record to the fixed endpoint with the form-encoded delivery", async () => {
    const client = new FakeClient();
    const sink = new WonderPushSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.equal(client.posts[0].url, WONDERPUSH_DELIVERIES_URL);
    assert.deepEqual(client.posts[0].headers, {
      "Content-Type": WONDERPUSH_FORM_CONTENT_TYPE,
    });
    const fields0 = parseForm(client.posts[0].body);
    assert.equal(fields0.accessToken, accessToken);
    assert.equal(fields0.targetSegmentIds, "segment-1");
    assert.equal(
      fields0.notification,
      JSON.stringify({ alert: { title: "order.created", text: "order.created" } })
    );
    // No subject → no title key; the key lands in the text.
    assert.equal(
      parseForm(client.posts[1].body).notification,
      JSON.stringify({ alert: { text: "agg-8" } })
    );
    // The trace id belongs in the text, never in the title.
    assert.equal(
      parseForm(client.posts[2].body).notification,
      JSON.stringify({ alert: { text: "t-9" } })
    );
    for (const post of client.posts) {
      assert.equal(post.body.includes("Authorization"), false);
      assert.equal(post.body.includes("Bearer"), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("applies the payload opt-in truncation on send", async () => {
    const client = new FakeClient();
    const sink = new WonderPushSink(baseConfig(client, { includePayload: true, payloadMaxChars: 3 }));
    await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.equal(
      JSON.parse(parseForm(client.posts[0].body).notification).alert.text,
      `order.created\n\n{"a… (truncated)`
    );
  });

  it("treats a delivery id as an acceptance receipt, not a delivery result", async () => {
    const client = new FakeClient();
    client.deliveryIdOn.set(0, "delivery-abc-123");
    const sink = new WonderPushSink(baseConfig(client));
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 1 });
    assert.deepEqual(sink.stats, { sent: 1, failed: 0, sendFailures: 0 });
  });

  it("retries a 2xx with no delivery id surfaced", async () => {
    const client = new FakeClient();
    client.deliveryIdOn.set(0, undefined);
    const sink = new WonderPushSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }]),
      (err: unknown) => {
        assert.ok(err instanceof WonderPushSinkError);
        assert.equal(err.failedRecords.length, 1);
        assert.deepEqual(
          err.failedRecords.map((r) => [r.index, r.errorCode, r.retryable]),
          [[0, "DELIVERY_ID_MISSING", true]]
        );
        return true;
      }
    );
    assert.deepEqual(sink.stats, { sent: 0, failed: 1, sendFailures: 1 });
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new WonderPushSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof WonderPushSinkError);
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
    client.statusOn.set(0, 201);
    client.failOn.set(1, new Error("socket hangup"));
    const sink = new WonderPushSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof WonderPushSinkError);
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

  it("fails closed without a client, access token, or targeting", async () => {
    await assert.rejects(
      () => new WonderPushSink({ accessToken, targeting }).send([{ body: '{"a":1}' }]),
      WonderPushSinkConfigError
    );
    await assert.rejects(
      () =>
        new WonderPushSink(baseConfig(new FakeClient(), { accessToken: undefined })).send([
          { body: '{"a":1}' },
        ]),
      WonderPushSinkConfigError
    );
    await assert.rejects(
      () =>
        new WonderPushSink(baseConfig(new FakeClient(), { targeting: undefined })).send([
          { body: '{"a":1}' },
        ]),
      WonderPushSinkConfigError
    );
    await assert.rejects(
      () =>
        new WonderPushSink(baseConfig(new FakeClient(), { targeting: {} })).send([
          { body: '{"a":1}' },
        ]),
      WonderPushSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new WonderPushSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new WonderPushSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new WonderPushSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyWonderPushRecordFailure(429), true);
    assert.equal(classifyWonderPushRecordFailure(500), true);
    assert.equal(classifyWonderPushRecordFailure(503), true);
    assert.equal(classifyWonderPushRecordFailure(400), false);
    assert.equal(classifyWonderPushRecordFailure(401), false);
    assert.equal(classifyWonderPushRecordFailure(404), false);
    assert.equal(WONDERPUSH_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
