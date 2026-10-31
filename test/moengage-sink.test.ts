import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  MoEngageSink,
  MoEngageSinkConfigError,
  MoEngageSinkError,
  assertValidMoEngageSinkConfig,
  buildMoEngageNotificationsBody,
  buildMoEngageNotificationsUrl,
  buildMoEngagePayload,
  classifyMoEngageRecordFailure,
  moEngageResponseToFailedRecord,
  resolveMoEngageCampaignName,
  resolveMoEngageContent,
  resolveMoEngageHost,
  resolveMoEngageQueryType,
  resolveMoEngageRecord,
  resolveMoEngageSummary,
  resolveMoEngageTargetAudience,
  resolveMoEngageTargetPlatform,
  truncateMoEngagePayload,
  MOENGAGE_DEFAULT_HOST,
  MOENGAGE_DEFAULT_PAYLOAD_MAX_CHARS,
  MOENGAGE_FALLBACK_SUMMARY,
  MOENGAGE_JSON_CONTENT_TYPE,
  MOENGAGE_MIN_CAMPAIGN_NAME_LENGTH,
  MOENGAGE_REQUEST_TYPE,
  type MoEngageMessageClient,
  type MoEngageMessagePostRequest,
  type MoEngageMessagePostResponse,
  type MoEngageSinkConfig,
  type MoEngageTargetUserAttributes,
} from "../src/moengage-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status and type per call. */
class FakeClient implements MoEngageMessageClient {
  posts: MoEngageMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  /** Call-count (0-based) → `type` field to surface for that post (undefined = none surfaced). */
  typeOn = new Map<number, string | undefined>();
  /** Call-count (0-based) → `response_id` to surface for that post. */
  responseIdOn = new Map<number, string>();
  async post(request: MoEngageMessagePostRequest): Promise<MoEngageMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return {
      status: this.statusOn.get(n) ?? 200,
      type: this.typeOn.has(n) ? this.typeOn.get(n) : "push_notification",
      responseId: this.responseIdOn.get(n),
    };
  }
}

const targetUserAttributes: MoEngageTargetUserAttributes = {
  email: "user@example.com",
};

function baseConfig(
  client: MoEngageMessageClient,
  extra: Partial<MoEngageSinkConfig> = {}
): MoEngageSinkConfig {
  return { targetUserAttributes, client, ...extra };
}

describe("moengage-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidMoEngageSinkConfig(null, "MoEngageSink"), RangeError);
    assert.throws(() => assertValidMoEngageSinkConfig("x", "MoEngageSink"), RangeError);
  });

  it("rejects a malformed region host", () => {
    assert.throws(
      () => assertValidMoEngageSinkConfig(baseConfig(new FakeClient(), { regionHost: "https://api-01.moengage.com" }), "MoEngageSink"),
      RangeError
    );
    assert.throws(
      () => assertValidMoEngageSinkConfig(baseConfig(new FakeClient(), { regionHost: "api-01.moengage.com/v5" }), "MoEngageSink"),
      RangeError
    );
  });

  it("rejects an unknown audience and normalizes case", () => {
    assert.throws(
      () => assertValidMoEngageSinkConfig(baseConfig(new FakeClient(), { targetAudience: "Everyone" }), "MoEngageSink"),
      RangeError
    );
    assert.equal(resolveMoEngageTargetAudience("user"), "User");
    assert.equal(resolveMoEngageTargetAudience("CUSTOM SEGMENT"), "Custom Segment");
    assert.equal(resolveMoEngageTargetAudience("all users"), "All Users");
    assert.equal(resolveMoEngageTargetAudience(undefined), "User");
  });

  it("rejects a short campaign name", () => {
    assert.throws(
      () => assertValidMoEngageSinkConfig(baseConfig(new FakeClient(), { campaignName: "abc" }), "MoEngageSink"),
      RangeError
    );
    assert.equal(MOENGAGE_MIN_CAMPAIGN_NAME_LENGTH, 5);
    assertValidMoEngageSinkConfig(baseConfig(new FakeClient(), { campaignName: "abcde" }), "MoEngageSink");
  });

  it("rejects a malformed platform list", () => {
    assert.throws(
      () => assertValidMoEngageSinkConfig(baseConfig(new FakeClient(), { targetPlatform: [] }), "MoEngageSink"),
      RangeError
    );
    assert.throws(
      () =>
        assertValidMoEngageSinkConfig(
          baseConfig(new FakeClient(), { targetPlatform: ["ANDROID", "WINDOWS"] as never }),
          "MoEngageSink"
        ),
      RangeError
    );
    assertValidMoEngageSinkConfig(baseConfig(new FakeClient(), { targetPlatform: ["WEB"] }), "MoEngageSink");
  });

  it("requires targetUserAttributes for User and rejects it for other audiences", () => {
    assert.throws(
      () => assertValidMoEngageSinkConfig({ client: new FakeClient() }, "MoEngageSink"),
      RangeError
    );
    assert.throws(
      () =>
        assertValidMoEngageSinkConfig(
          baseConfig(new FakeClient(), { targetAudience: "All Users" }),
          "MoEngageSink"
        ),
      RangeError
    );
    assert.throws(
      () =>
        assertValidMoEngageSinkConfig(
          baseConfig(new FakeClient(), { targetAudience: "Custom Segment", customSegmentName: "Churned" }),
          "MoEngageSink"
        ),
      RangeError
    );
  });

  it("requires customSegmentName for Custom Segment and rejects it elsewhere", () => {
    assert.throws(
      () =>
        assertValidMoEngageSinkConfig(
          { client: new FakeClient(), targetAudience: "Custom Segment" },
          "MoEngageSink"
        ),
      RangeError
    );
    assert.throws(
      () => assertValidMoEngageSinkConfig(baseConfig(new FakeClient(), { customSegmentName: "Churned" }), "MoEngageSink"),
      RangeError
    );
    assertValidMoEngageSinkConfig(
      { client: new FakeClient(), targetAudience: "Custom Segment", customSegmentName: "Churned" },
      "MoEngageSink"
    );
  });

  it("requires requestId for bulk user requests and rejects bulk for other audiences", () => {
    assert.throws(
      () => assertValidMoEngageSinkConfig(baseConfig(new FakeClient(), { bulkUserRequest: true }), "MoEngageSink"),
      RangeError
    );
    assert.throws(
      () =>
        assertValidMoEngageSinkConfig(
          { client: new FakeClient(), targetAudience: "All Users", bulkUserRequest: true, requestId: "req-1" },
          "MoEngageSink"
        ),
      RangeError
    );
    assertValidMoEngageSinkConfig(
      baseConfig(new FakeClient(), { bulkUserRequest: true, requestId: "req-1" }),
      "MoEngageSink"
    );
  });

  it("rejects a malformed client and payloadMaxChars", () => {
    assert.throws(
      () => assertValidMoEngageSinkConfig(baseConfig(new FakeClient(), { client: {} as never }), "MoEngageSink"),
      RangeError
    );
    assert.throws(
      () => assertValidMoEngageSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 0 }), "MoEngageSink"),
      RangeError
    );
  });
});

describe("moengage-sink resolvers", () => {
  it("resolves the default and configured host", () => {
    assert.equal(resolveMoEngageHost({}), MOENGAGE_DEFAULT_HOST);
    assert.equal(resolveMoEngageHost({ regionHost: "api-02.moengage.com" }), "api-02.moengage.com");
    assert.equal(buildMoEngageNotificationsUrl("api-01.moengage.com"), "https://api-01.moengage.com/v5/push/notifications");
  });

  it("maps audiences to their X-MOE-Query-Type values", () => {
    assert.equal(resolveMoEngageQueryType("User", false), "user");
    assert.equal(resolveMoEngageQueryType("User", true), "bulk users");
    assert.equal(resolveMoEngageQueryType("Custom Segment", false), "custom segment");
    assert.equal(resolveMoEngageQueryType("All Users", false), "all users");
  });

  it("resolves the default platforms", () => {
    assert.deepEqual(resolveMoEngageTargetPlatform({}), ["ANDROID", "IOS", "WEB"]);
    assert.deepEqual(resolveMoEngageTargetPlatform({ targetPlatform: ["WEB"] }), ["WEB"]);
  });

  it("derives the summary from subject, key, then traceId", () => {
    assert.equal(resolveMoEngageSummary({ body: "{}", subject: "Price drop", key: "k", traceId: "t" }), "Price drop");
    assert.equal(resolveMoEngageSummary({ body: "{}", key: "order-1", traceId: "t" }), "order-1");
    assert.equal(resolveMoEngageSummary({ body: "{}", traceId: "trace-9" }), "trace-9");
    assert.equal(resolveMoEngageSummary({ body: "{}" }), MOENGAGE_FALLBACK_SUMMARY);
  });

  it("derives the campaign name from config, key, then the fallback", () => {
    assert.equal(resolveMoEngageCampaignName({ body: "{}", key: "order-1" }, { campaignName: "Price drop" }), "Price drop");
    assert.equal(resolveMoEngageCampaignName({ body: "{}", key: "order-1" }, {}), "webhook-order-1");
    assert.equal(resolveMoEngageCampaignName({ body: "{}" }, {}), MOENGAGE_FALLBACK_SUMMARY);
  });

  it("derives title/message and appends the payload only under the opt-in", () => {
    const content = resolveMoEngageContent({ body: '{"a":1}', subject: "Price drop" }, {});
    assert.deepEqual(content, { title: "Price drop", message: "Price drop" });
    const withPayload = resolveMoEngageContent({ body: '{"a":1}', subject: "Price drop" }, { includePayload: true });
    assert.equal(withPayload.message, 'Price drop\n\n{"a":1}');
    assert.equal(MOENGAGE_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
    assert.equal(truncateMoEngagePayload("abcdef", 4), "abcd… (truncated)");
    assert.equal(truncateMoEngagePayload("abc", 4), "abc");
  });

  it("builds one payload block per listed platform", () => {
    assert.deepEqual(buildMoEngagePayload(["ANDROID", "WEB"], { title: "t", message: "m" }), {
      ANDROID: { title: "t", message: "m" },
      WEB: { title: "t", message: "m" },
    });
  });

  it("builds the V5 body with camelCase fields and audience targeting", () => {
    const body = JSON.parse(
      buildMoEngageNotificationsBody(
        "webhook-order-1",
        ["ANDROID", "IOS", "WEB"],
        "User",
        { title: "Price drop", message: "Price drop" },
        { targetUserAttributes }
      )
    );
    assert.equal(body.campaignName, "webhook-order-1");
    assert.deepEqual(body.targetPlatform, ["ANDROID", "IOS", "WEB"]);
    assert.equal(body.targetAudience, "User");
    assert.equal(body.requestType, MOENGAGE_REQUEST_TYPE);
    assert.deepEqual(body.payload.ANDROID, { title: "Price drop", message: "Price drop" });
    assert.deepEqual(body.payload.IOS, { title: "Price drop", message: "Price drop" });
    assert.deepEqual(body.payload.WEB, { title: "Price drop", message: "Price drop" });
    assert.deepEqual(body.targetUserAttributes, targetUserAttributes);
    assert.equal(body.customSegmentName, undefined);
  });

  it("includes customSegmentName for Custom Segment and bulk fields for bulk users", () => {
    const segment = JSON.parse(
      buildMoEngageNotificationsBody("Spring sale", ["WEB"], "Custom Segment", { title: "t", message: "m" }, {
        customSegmentName: "Churned",
      })
    );
    assert.equal(segment.customSegmentName, "Churned");
    assert.equal(segment.targetUserAttributes, undefined);
    const bulk = JSON.parse(
      buildMoEngageNotificationsBody("Bulk alert", ["ANDROID"], "User", { title: "t", message: "m" }, {
        targetUserAttributes,
        bulkUserRequest: true,
        requestId: "req-1",
      })
    );
    assert.equal(bulk.bulkUserRequest, true);
    assert.equal(bulk.requestId, "req-1");
  });

  it("rejects an empty record body", () => {
    assert.throws(() => resolveMoEngageRecord({ body: "" }, 0), RangeError);
    assert.deepEqual(resolveMoEngageRecord({ body: "{}" }, 2), { index: 2 });
  });
});

describe("moengage-sink failure mapping", () => {
  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", () => {
    assert.equal(classifyMoEngageRecordFailure(429), true);
    assert.equal(classifyMoEngageRecordFailure(500), true);
    assert.equal(classifyMoEngageRecordFailure(503), true);
    assert.equal(classifyMoEngageRecordFailure(400), false);
    assert.equal(classifyMoEngageRecordFailure(401), false);
    assert.equal(classifyMoEngageRecordFailure(404), false);
    assert.equal(classifyMoEngageRecordFailure(409), false);
  });

  it("accepts a 2xx with type push_notification", () => {
    assert.equal(moEngageResponseToFailedRecord({ status: 200, type: "push_notification", responseId: "r-1" }, 0), null);
  });

  it("fails a 2xx with a mismatched type as non-retryable", () => {
    const failed = moEngageResponseToFailedRecord({ status: 200, type: "email" }, 1);
    assert.equal(failed?.errorCode, "TYPE_MISMATCH");
    assert.equal(failed?.retryable, false);
  });

  it("fails a 2xx with no type surfaced as retryable", () => {
    const failed = moEngageResponseToFailedRecord({ status: 200 }, 2);
    assert.equal(failed?.errorCode, "TYPE_MISSING");
    assert.equal(failed?.retryable, true);
  });
});

describe("moengage-sink send", () => {
  it("posts one V5 request per message with the query-type header and no credentials", async () => {
    const client = new FakeClient();
    const sink = new MoEngageSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "Price drop", key: "order-1" },
      { body: '{"b":2}', key: "order-2" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    const first = client.posts[0];
    assert.equal(first.url, "https://api-01.moengage.com/v5/push/notifications");
    assert.equal(first.headers["Content-Type"], MOENGAGE_JSON_CONTENT_TYPE);
    assert.equal(first.headers["X-MOE-Query-Type"], "user");
    assert.equal(first.headers["Authorization"], undefined);
    const body = JSON.parse(first.body);
    assert.equal(body.campaignName, "webhook-order-1");
    assert.equal(body.targetAudience, "User");
    assert.deepEqual(body.payload.ANDROID, { title: "Price drop", message: "Price drop" });
    assert.deepEqual(body.targetUserAttributes, targetUserAttributes);
    // No credential ever enters the handed request body.
    assert.equal(JSON.stringify(first).includes("workspace"), false);
    assert.equal(JSON.stringify(first).includes("api_key"), false);
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("sends bulk users query type and requestId for bulk requests", async () => {
    const client = new FakeClient();
    const sink = new MoEngageSink(baseConfig(client, { bulkUserRequest: true, requestId: "req-1" }));
    await sink.send([{ body: "{}", key: "k1" }]);
    assert.equal(client.posts[0].headers["X-MOE-Query-Type"], "bulk users");
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.bulkUserRequest, true);
    assert.equal(body.requestId, "req-1");
  });

  it("sends custom segment and all users query types", async () => {
    const segmentClient = new FakeClient();
    const segmentSink = new MoEngageSink({
      client: segmentClient,
      targetAudience: "Custom Segment",
      customSegmentName: "Churned",
    });
    await segmentSink.send([{ body: "{}", key: "k1" }]);
    assert.equal(segmentClient.posts[0].headers["X-MOE-Query-Type"], "custom segment");
    assert.equal(JSON.parse(segmentClient.posts[0].body).customSegmentName, "Churned");

    const allClient = new FakeClient();
    const allSink = new MoEngageSink({ client: allClient, targetAudience: "All Users" });
    await allSink.send([{ body: "{}", key: "k1" }]);
    assert.equal(allClient.posts[0].headers["X-MOE-Query-Type"], "all users");
    assert.equal(JSON.parse(allClient.posts[0].body).targetAudience, "All Users");
  });

  it("throws with exactly the failed messages and their retry lanes", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 429);
    client.typeOn.set(2, "email");
    const sink = new MoEngageSink(baseConfig(client));
    await assert.rejects(
      sink.send([
        { body: "{}", key: "k1" },
        { body: "{}", key: "k2" },
        { body: "{}", key: "k3" },
      ]),
      (err: unknown) => {
        assert.ok(err instanceof MoEngageSinkError);
        assert.deepEqual(
          (err as MoEngageSinkError).failedRecords.map((f) => [f.index, f.errorCode, f.retryable]),
          [
            [1, "HTTP_429", true],
            [2, "TYPE_MISMATCH", false],
          ]
        );
        return true;
      }
    );
    assert.deepEqual(sink.stats, { sent: 1, failed: 2, sendFailures: 1 });
  });

  it("treats a duplicate campaign name (409) as fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 409);
    const sink = new MoEngageSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as MoEngageSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_409");
        assert.equal(failed[0].retryable, false);
        return true;
      }
    );
  });

  it("treats a client throw as a retryable transport failure", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hang up"));
    const sink = new MoEngageSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as MoEngageSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(failed[0].retryable, true);
        assert.equal(failed[0].errorMessage, "socket hang up");
        return true;
      }
    );
  });

  it("throws a config error with no client, mapped non_retryable", async () => {
    const sink = new MoEngageSink({ targetUserAttributes });
    await assert.rejects(sink.send([{ body: "{}", key: "k1" }]), MoEngageSinkConfigError);
    assert.equal(classifyFailure(new MoEngageSinkConfigError("no client injected")).failureClass, "non_retryable");
  });

  it("dry-runs with zero client I/O and untouched stats", async () => {
    const client = new FakeClient();
    const sink = new MoEngageSink(baseConfig(client, { dryRun: true }));
    const result = await sink.send([{ body: "{}", subject: "Price drop" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("appends the payload under the opt-in, truncated", async () => {
    const client = new FakeClient();
    const sink = new MoEngageSink(baseConfig(client, { includePayload: true, payloadMaxChars: 10 }));
    await sink.send([{ body: "0123456789ABCDEF", subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.payload.ANDROID.message, "Alert\n\n0123456789… (truncated)");
  });

  it("uses the configured region host and campaign name", async () => {
    const client = new FakeClient();
    const sink = new MoEngageSink(
      baseConfig(client, { regionHost: "api-02.moengage.com", campaignName: "Spring sale" })
    );
    await sink.send([{ body: "{}", key: "k1" }]);
    assert.equal(client.posts[0].url, "https://api-02.moengage.com/v5/push/notifications");
    assert.equal(JSON.parse(client.posts[0].body).campaignName, "Spring sale");
  });
});
