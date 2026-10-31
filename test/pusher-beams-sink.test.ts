import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  PusherBeamsSink,
  PusherBeamsSinkConfigError,
  PusherBeamsSinkError,
  assertValidPusherBeamsSinkConfig,
  buildPusherBeamsPlatformPayload,
  buildPusherBeamsPublishBody,
  buildPusherBeamsPublishUrl,
  classifyPusherBeamsRecordFailure,
  resolvePusherBeamsContent,
  resolvePusherBeamsInterest,
  resolvePusherBeamsInterests,
  resolvePusherBeamsPlatforms,
  resolvePusherBeamsRecord,
  resolvePusherBeamsSummary,
  truncatePusherBeamsPayload,
  PUSHER_BEAMS_ALL_PLATFORMS,
  PUSHER_BEAMS_DEFAULT_PAYLOAD_MAX_CHARS,
  PUSHER_BEAMS_FALLBACK_SUMMARY,
  PUSHER_BEAMS_JSON_CONTENT_TYPE,
  PUSHER_BEAMS_MAX_INTERESTS,
  PUSHER_BEAMS_MAX_INTEREST_LENGTH,
  PUSHER_BEAMS_PUBLISH_PATH,
  type PusherBeamsMessageClient,
  type PusherBeamsMessagePostRequest,
  type PusherBeamsMessagePostResponse,
  type PusherBeamsSinkConfig,
} from "../src/pusher-beams-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements PusherBeamsMessageClient {
  posts: PusherBeamsMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → publishId to return for that post. */
  publishIdOn = new Map<number, string>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: PusherBeamsMessagePostRequest): Promise<PusherBeamsMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200, publishId: this.publishIdOn.get(n) };
  }
}

const instanceId = "a1b2c3d4-0000-1111-2222-333344445555";

function baseConfig(
  client: PusherBeamsMessageClient,
  extra: Partial<PusherBeamsSinkConfig> = {}
): PusherBeamsSinkConfig {
  return { instanceId, interests: ["hello"], client, ...extra };
}

describe("pusher-beams-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidPusherBeamsSinkConfig(null, "PusherBeamsSink"), RangeError);
    assert.throws(() => assertValidPusherBeamsSinkConfig("x", "PusherBeamsSink"), RangeError);
  });

  it("requires a bare instance id", () => {
    assert.throws(
      () => assertValidPusherBeamsSinkConfig({ interests: ["hello"] }, "PusherBeamsSink"),
      RangeError
    );
    assert.throws(
      () =>
        assertValidPusherBeamsSinkConfig(
          baseConfig(new FakeClient(), { instanceId: "https://x.pushnotifications.pusher.com" }),
          "PusherBeamsSink"
        ),
      RangeError
    );
    assert.throws(
      () => assertValidPusherBeamsSinkConfig(baseConfig(new FakeClient(), { instanceId: "a/b" }), "PusherBeamsSink"),
      RangeError
    );
    assert.throws(
      () => assertValidPusherBeamsSinkConfig(baseConfig(new FakeClient(), { instanceId: "" }), "PusherBeamsSink"),
      RangeError
    );
    assertValidPusherBeamsSinkConfig(baseConfig(new FakeClient()), "PusherBeamsSink");
  });

  it("requires 1-100 interests and validates each name", () => {
    assert.equal(PUSHER_BEAMS_MAX_INTERESTS, 100);
    assert.equal(PUSHER_BEAMS_MAX_INTEREST_LENGTH, 164);
    assert.throws(
      () => assertValidPusherBeamsSinkConfig({ instanceId, client: new FakeClient() }, "PusherBeamsSink"),
      RangeError
    );
    assert.throws(
      () => assertValidPusherBeamsSinkConfig(baseConfig(new FakeClient(), { interests: [] }), "PusherBeamsSink"),
      RangeError
    );
    assert.throws(
      () =>
        assertValidPusherBeamsSinkConfig(
          baseConfig(new FakeClient(), { interests: Array.from({ length: 101 }, (_, i) => `i${i}`) }),
          "PusherBeamsSink"
        ),
      RangeError
    );
    assert.throws(
      () => assertValidPusherBeamsSinkConfig(baseConfig(new FakeClient(), { interests: [""] }), "PusherBeamsSink"),
      RangeError
    );
    assert.throws(
      () =>
        assertValidPusherBeamsSinkConfig(
          baseConfig(new FakeClient(), { interests: ["bad interest!"] }),
          "PusherBeamsSink"
        ),
      RangeError
    );
    assert.throws(
      () =>
        assertValidPusherBeamsSinkConfig(
          baseConfig(new FakeClient(), { interests: ["x".repeat(165)] }),
          "PusherBeamsSink"
        ),
      RangeError
    );
    assert.deepEqual(resolvePusherBeamsInterests(["hello", "news-1", "a@b,c;d=e"], "PusherBeamsSink"), [
      "hello",
      "news-1",
      "a@b,c;d=e",
    ]);
    assert.equal(resolvePusherBeamsInterest("x".repeat(164), 0, "PusherBeamsSink"), "x".repeat(164));
    assertValidPusherBeamsSinkConfig(baseConfig(new FakeClient()), "PusherBeamsSink");
  });

  it("validates the platforms list when set", () => {
    assert.deepEqual([...PUSHER_BEAMS_ALL_PLATFORMS], ["fcm", "apns", "web"]);
    assert.throws(
      () => assertValidPusherBeamsSinkConfig(baseConfig(new FakeClient(), { platforms: [] }), "PusherBeamsSink"),
      RangeError
    );
    assert.throws(
      () =>
        assertValidPusherBeamsSinkConfig(
          baseConfig(new FakeClient(), { platforms: ["fcm", "fcm"] as never }),
          "PusherBeamsSink"
        ),
      RangeError
    );
    assert.throws(
      () =>
        assertValidPusherBeamsSinkConfig(
          baseConfig(new FakeClient(), { platforms: ["sms"] as never }),
          "PusherBeamsSink"
        ),
      RangeError
    );
    assert.deepEqual(resolvePusherBeamsPlatforms(["web", "fcm"], "PusherBeamsSink"), ["web", "fcm"]);
    assertValidPusherBeamsSinkConfig(
      baseConfig(new FakeClient(), { platforms: ["apns"] }),
      "PusherBeamsSink"
    );
  });

  it("rejects a malformed client and payloadMaxChars", () => {
    assert.throws(
      () => assertValidPusherBeamsSinkConfig(baseConfig(new FakeClient(), { client: {} as never }), "PusherBeamsSink"),
      RangeError
    );
    assert.throws(
      () => assertValidPusherBeamsSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 0 }), "PusherBeamsSink"),
      RangeError
    );
    assert.throws(
      () => assertValidPusherBeamsSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 1.5 }), "PusherBeamsSink"),
      RangeError
    );
  });
});

describe("pusher-beams-sink resolvers", () => {
  it("builds the publish URL from the instance id", () => {
    assert.equal(PUSHER_BEAMS_PUBLISH_PATH, "/publish_api/v1/instances");
    assert.equal(
      buildPusherBeamsPublishUrl(instanceId),
      `https://${instanceId}.pushnotifications.pusher.com/publish_api/v1/instances/${instanceId}/publishes`
    );
  });

  it("derives the summary from subject, key, then traceId", () => {
    assert.equal(resolvePusherBeamsSummary({ body: "{}", subject: "Price drop", key: "k", traceId: "t" }), "Price drop");
    assert.equal(resolvePusherBeamsSummary({ body: "{}", key: "order-1", traceId: "t" }), "order-1");
    assert.equal(resolvePusherBeamsSummary({ body: "{}", traceId: "trace-9" }), "trace-9");
    assert.equal(resolvePusherBeamsSummary({ body: "{}" }), PUSHER_BEAMS_FALLBACK_SUMMARY);
  });

  it("derives title/body and appends the payload only under the opt-in", () => {
    const content = resolvePusherBeamsContent({ body: '{"a":1}', subject: "Price drop" }, {});
    assert.deepEqual(content, { title: "Price drop", body: "Price drop" });
    const withPayload = resolvePusherBeamsContent({ body: '{"a":1}', subject: "Price drop" }, { includePayload: true });
    assert.equal(withPayload.body, 'Price drop\n\n{"a":1}');
    assert.equal(PUSHER_BEAMS_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
    assert.equal(truncatePusherBeamsPayload("abcdef", 4), "abcd… (truncated)");
    assert.equal(truncatePusherBeamsPayload("abc", 4), "abc");
  });

  it("builds per-platform payloads from the derived content", () => {
    assert.deepEqual(buildPusherBeamsPlatformPayload("fcm", { title: "T", body: "B" }), {
      notification: { title: "T", body: "B" },
    });
    assert.deepEqual(buildPusherBeamsPlatformPayload("web", { title: "T", body: "B" }), {
      notification: { title: "T", body: "B" },
    });
    assert.deepEqual(buildPusherBeamsPlatformPayload("apns", { title: "T", body: "B" }), {
      aps: { alert: { title: "T", body: "B" } },
    });
  });

  it("builds the publish body with interests and all three platform payloads", () => {
    const body = JSON.parse(
      buildPusherBeamsPublishBody(["hello", "news"], ["fcm", "apns", "web"], { title: "Price drop", body: "Price drop" })
    );
    assert.deepEqual(body.interests, ["hello", "news"]);
    assert.deepEqual(body.fcm, { notification: { title: "Price drop", body: "Price drop" } });
    assert.deepEqual(body.apns, { aps: { alert: { title: "Price drop", body: "Price drop" } } });
    assert.deepEqual(body.web, { notification: { title: "Price drop", body: "Price drop" } });
    // No webhook URL is ever sent, and no credential ever enters the body.
    assert.equal(body.webhookUrl, undefined);
    assert.equal(JSON.stringify(body).includes("Authorization"), false);
    assert.equal(JSON.stringify(body).includes("secret"), false);
  });

  it("builds the publish body with only the configured platforms", () => {
    const body = JSON.parse(
      buildPusherBeamsPublishBody(["hello"], ["fcm"], { title: "T", body: "B" })
    );
    assert.deepEqual(body.fcm, { notification: { title: "T", body: "B" } });
    assert.equal(body.apns, undefined);
    assert.equal(body.web, undefined);
  });

  it("rejects an empty record body", () => {
    assert.throws(() => resolvePusherBeamsRecord({ body: "" }, 0), RangeError);
    assert.deepEqual(resolvePusherBeamsRecord({ body: "{}" }, 2), { index: 2 });
  });
});

describe("pusher-beams-sink failure mapping", () => {
  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", () => {
    assert.equal(classifyPusherBeamsRecordFailure(429), true);
    assert.equal(classifyPusherBeamsRecordFailure(500), true);
    assert.equal(classifyPusherBeamsRecordFailure(503), true);
    assert.equal(classifyPusherBeamsRecordFailure(400), false);
    assert.equal(classifyPusherBeamsRecordFailure(401), false);
    assert.equal(classifyPusherBeamsRecordFailure(402), false);
    assert.equal(classifyPusherBeamsRecordFailure(404), false);
  });
});

describe("pusher-beams-sink send", () => {
  it("posts one publish per message with no credentials", async () => {
    const client = new FakeClient();
    client.publishIdOn.set(0, "pubid-1111");
    client.publishIdOn.set(1, "pubid-2222");
    const sink = new PusherBeamsSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "Price drop", key: "order-1" },
      { body: '{"b":2}', key: "order-2" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2, publishIds: ["pubid-1111", "pubid-2222"] });
    assert.equal(client.posts.length, 2);
    const first = client.posts[0];
    assert.equal(
      first.url,
      `https://${instanceId}.pushnotifications.pusher.com/publish_api/v1/instances/${instanceId}/publishes`
    );
    assert.equal(first.headers["Content-Type"], PUSHER_BEAMS_JSON_CONTENT_TYPE);
    assert.equal(first.headers["Authorization"], undefined);
    const body = JSON.parse(first.body);
    assert.deepEqual(body.interests, ["hello"]);
    assert.deepEqual(body.fcm, { notification: { title: "Price drop", body: "Price drop" } });
    assert.deepEqual(body.apns, { aps: { alert: { title: "Price drop", body: "Price drop" } } });
    assert.deepEqual(body.web, { notification: { title: "Price drop", body: "Price drop" } });
    // No credential ever enters the handed request.
    assert.equal(JSON.stringify(first).includes("Authorization"), false);
    assert.equal(JSON.stringify(first).includes("secret"), false);
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("accepts a 2xx as acceptance and returns its publishId receipt", async () => {
    const client = new FakeClient();
    client.publishIdOn.set(0, "pubid-9e5f");
    const sink = new PusherBeamsSink(baseConfig(client));
    const result = await sink.send([{ body: "{}", key: "k1" }]);
    assert.deepEqual(result, { ok: true, sent: 1, publishIds: ["pubid-9e5f"] });
    assert.deepEqual(sink.stats, { sent: 1, failed: 0, sendFailures: 0 });
  });

  it("accepts a 2xx without a publishId as acceptance with no receipt", async () => {
    const client = new FakeClient();
    const sink = new PusherBeamsSink(baseConfig(client));
    const result = await sink.send([{ body: "{}", key: "k1" }]);
    assert.deepEqual(result, { ok: true, sent: 1, publishIds: [] });
  });

  it("throws with exactly the failed messages and their retry lanes", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 429);
    client.statusOn.set(2, 503);
    const sink = new PusherBeamsSink(baseConfig(client));
    await assert.rejects(
      sink.send([
        { body: "{}", key: "k1" },
        { body: "{}", key: "k2" },
        { body: "{}", key: "k3" },
      ]),
      (err: unknown) => {
        assert.ok(err instanceof PusherBeamsSinkError);
        assert.deepEqual(
          (err as PusherBeamsSinkError).failedRecords.map((f) => [f.index, f.errorCode, f.retryable]),
          [
            [1, "HTTP_429", true],
            [2, "HTTP_503", true],
          ]
        );
        return true;
      }
    );
    assert.deepEqual(sink.stats, { sent: 1, failed: 2, sendFailures: 1 });
  });

  it("treats bad interests (400) as fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 400);
    const sink = new PusherBeamsSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as PusherBeamsSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_400");
        assert.equal(failed[0].statusCode, 400);
        assert.equal(failed[0].retryable, false);
        return true;
      }
    );
  });

  it("treats a bad secret key (401) and over-plan-limits (402) as fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 401);
    const sink = new PusherBeamsSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        assert.equal((err as PusherBeamsSinkError).failedRecords[0].retryable, false);
        return true;
      }
    );
    const overPlan = new FakeClient();
    overPlan.statusOn.set(0, 402);
    const overPlanSink = new PusherBeamsSink(baseConfig(overPlan));
    await assert.rejects(
      overPlanSink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as PusherBeamsSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_402");
        assert.equal(failed[0].retryable, false);
        return true;
      }
    );
  });

  it("treats a client throw as a retryable transport failure", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hang up"));
    const sink = new PusherBeamsSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as PusherBeamsSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(failed[0].retryable, true);
        assert.equal(failed[0].errorMessage, "socket hang up");
        return true;
      }
    );
  });

  it("throws a config error with no client, mapped non_retryable", async () => {
    const sink = new PusherBeamsSink({ instanceId, interests: ["hello"] });
    await assert.rejects(sink.send([{ body: "{}", key: "k1" }]), PusherBeamsSinkConfigError);
    assert.equal(classifyFailure(new PusherBeamsSinkConfigError("no client injected")).failureClass, "non_retryable");
  });

  it("dry-runs with zero client I/O and untouched stats", async () => {
    const client = new FakeClient();
    const sink = new PusherBeamsSink(baseConfig(client, { dryRun: true }));
    const result = await sink.send([{ body: "{}", subject: "Price drop" }]);
    assert.deepEqual(result, { ok: true, sent: 0, publishIds: [], dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("dry-runs still validate the config and the records", async () => {
    const client = new FakeClient();
    const sink = new PusherBeamsSink(baseConfig(client, { dryRun: true }));
    await assert.rejects(sink.send([{ body: "" }]), RangeError);
    assert.equal(client.posts.length, 0);
    assert.throws(
      () => new PusherBeamsSink({ instanceId, interests: [], dryRun: true }),
      RangeError
    );
  });

  it("appends the payload under the opt-in, truncated at the default 2000", async () => {
    const client = new FakeClient();
    const sink = new PusherBeamsSink(baseConfig(client, { includePayload: true, payloadMaxChars: 10 }));
    await sink.send([{ body: "0123456789ABCDEF", subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.fcm.notification.body, "Alert\n\n0123456789… (truncated)");
    assert.equal(body.apns.aps.alert.body, "Alert\n\n0123456789… (truncated)");
    assert.equal(body.fcm.notification.title, "Alert");

    const defaultClient = new FakeClient();
    const defaultSink = new PusherBeamsSink(baseConfig(defaultClient, { includePayload: true }));
    await defaultSink.send([{ body: "x".repeat(2001), subject: "Alert" }]);
    const defaultBody = JSON.parse(defaultClient.posts[0].body);
    assert.equal(defaultBody.fcm.notification.body, `Alert\n\n${"x".repeat(2000)}… (truncated)`);
  });

  it("omits the payload by default", async () => {
    const client = new FakeClient();
    const sink = new PusherBeamsSink(baseConfig(client));
    await sink.send([{ body: '{"secret":"s3cr3t"}', subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.fcm.notification.body, "Alert");
    assert.equal(JSON.stringify(body).includes("s3cr3t"), false);
  });

  it("sends only the configured platforms", async () => {
    const client = new FakeClient();
    const sink = new PusherBeamsSink(baseConfig(client, { platforms: ["fcm"] }));
    await sink.send([{ body: "{}", key: "k1" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.deepEqual(body.fcm, { notification: { title: "k1", body: "k1" } });
    assert.equal(body.apns, undefined);
    assert.equal(body.web, undefined);
  });
});
