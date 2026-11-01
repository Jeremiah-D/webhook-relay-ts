import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  PushySink,
  PushySinkConfigError,
  PushySinkError,
  assertValidPushySinkConfig,
  buildPushyPushBody,
  classifyPushyPushResponse,
  classifyPushyRecordFailure,
  resolvePushyData,
  resolvePushyDeviceToken,
  resolvePushyNotification,
  resolvePushyRecord,
  resolvePushySummary,
  truncatePushyPayload,
  PUSHY_API_BASE_URL,
  PUSHY_DATA_LIMIT_CHARS,
  PUSHY_DEFAULT_PAYLOAD_MAX_CHARS,
  PUSHY_FALLBACK_SUMMARY,
  PUSHY_JSON_CONTENT_TYPE,
  PUSHY_PUSH_URL,
  PUSHY_RATE_LIMIT_PER_MINUTE_PRO,
  PUSHY_RATE_LIMIT_PER_MINUTE_TRIAL,
  type PushyPushClient,
  type PushyPushPostRequest,
  type PushyPushPostResponse,
  type PushySinkConfig,
} from "../src/pushy-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status and push id per call. */
class FakeClient implements PushyPushClient {
  posts: PushyPushPostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → push id to return for that post. */
  pushIdOn = new Map<number, string>();
  /** Call-count (0-based) → error `code` to return for that post. */
  codeOn = new Map<number, string>();
  /** Call-count (0-based) → error description to return for that post. */
  errorOn = new Map<number, string>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: PushyPushPostRequest): Promise<PushyPushPostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return {
      status: this.statusOn.get(n) ?? 200,
      pushId: this.pushIdOn.get(n) ?? `push-${n + 1}`,
      code: this.codeOn.get(n),
      error: this.errorOn.get(n),
    };
  }
}

function baseConfig(
  client: PushyPushClient,
  extra: Partial<PushySinkConfig> = {}
): PushySinkConfig {
  return { deviceToken: "a6345d0278adc55d3474f5", client, ...extra };
}

describe("pushy-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidPushySinkConfig(null, "PushySink"), RangeError);
    assert.throws(() => assertValidPushySinkConfig("x", "PushySink"), RangeError);
  });

  it("requires a non-empty device token", () => {
    assert.throws(
      () => assertValidPushySinkConfig({ client: new FakeClient() }, "PushySink"),
      RangeError
    );
    assert.throws(
      () => assertValidPushySinkConfig(baseConfig(new FakeClient(), { deviceToken: "" }), "PushySink"),
      RangeError
    );
    assert.throws(
      () => assertValidPushySinkConfig(baseConfig(new FakeClient(), { deviceToken: 7 as never }), "PushySink"),
      RangeError
    );
    assert.equal(
      resolvePushyDeviceToken("a6345d0278adc55d3474f5", "PushySink"),
      "a6345d0278adc55d3474f5"
    );
    assertValidPushySinkConfig(baseConfig(new FakeClient()), "PushySink");
  });

  it("rejects a /topics/<name> topic value: topic broadcast is out of scope", () => {
    assert.throws(
      () => assertValidPushySinkConfig(baseConfig(new FakeClient(), { deviceToken: "/topics/news" }), "PushySink"),
      RangeError
    );
    assert.throws(
      () => resolvePushyDeviceToken("/topics/news", "PushySink"),
      RangeError
    );
  });

  it("rejects a malformed client, payloadMaxChars, sound, and badge", () => {
    assert.throws(
      () => assertValidPushySinkConfig(baseConfig(new FakeClient(), { client: {} as never }), "PushySink"),
      RangeError
    );
    assert.throws(
      () => assertValidPushySinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 0 }), "PushySink"),
      RangeError
    );
    assert.throws(
      () => assertValidPushySinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 1.5 }), "PushySink"),
      RangeError
    );
    assert.throws(
      () => assertValidPushySinkConfig(baseConfig(new FakeClient(), { sound: "" }), "PushySink"),
      RangeError
    );
    assert.throws(
      () => assertValidPushySinkConfig(baseConfig(new FakeClient(), { badge: -1 }), "PushySink"),
      RangeError
    );
    assert.throws(
      () => assertValidPushySinkConfig(baseConfig(new FakeClient(), { badge: 1.5 }), "PushySink"),
      RangeError
    );
    assertValidPushySinkConfig(baseConfig(new FakeClient(), { sound: "ping.aiff", badge: 1 }), "PushySink");
    assertValidPushySinkConfig(baseConfig(new FakeClient(), { badge: 0 }), "PushySink");
  });
});

describe("pushy-sink resolvers", () => {
  it("uses the fixed push URL with no credential in it — the client appends ?api_key=", () => {
    assert.equal(PUSHY_API_BASE_URL, "https://api.pushy.me");
    assert.equal(PUSHY_PUSH_URL, "https://api.pushy.me/push");
    assert.equal(PUSHY_PUSH_URL.includes("api_key"), false);
    assert.equal(PUSHY_PUSH_URL.includes("SECRET"), false);
    assert.equal(PUSHY_PUSH_URL.includes("a6345d02"), false);
  });

  it("pins the documented rate limits: 800 req/min Pro, 60 req/min Trial", () => {
    assert.equal(PUSHY_RATE_LIMIT_PER_MINUTE_PRO, 800);
    assert.equal(PUSHY_RATE_LIMIT_PER_MINUTE_TRIAL, 60);
    assert.equal(PUSHY_DATA_LIMIT_CHARS, 4096);
  });

  it("derives the summary from subject, key, then traceId", () => {
    assert.equal(resolvePushySummary({ body: "{}", subject: "Price drop", key: "k", traceId: "t" }), "Price drop");
    assert.equal(resolvePushySummary({ body: "{}", key: "order-1", traceId: "t" }), "order-1");
    assert.equal(resolvePushySummary({ body: "{}", traceId: "trace-9" }), "trace-9");
    assert.equal(resolvePushySummary({ body: "{}" }), PUSHY_FALLBACK_SUMMARY);
  });

  it("derives data with message from the chain and eventBody only under the opt-in", () => {
    assert.deepEqual(resolvePushyData({ body: "{}", subject: "Price drop", key: "k" }, {}), {
      message: "Price drop",
    });
    assert.deepEqual(resolvePushyData({ body: "{}", key: "order-1" }, {}), { message: "order-1" });
    assert.deepEqual(resolvePushyData({ body: "{}" }, {}), { message: PUSHY_FALLBACK_SUMMARY });
    const withPayload = resolvePushyData({ body: '{"a":1}', subject: "Price drop" }, { includePayload: true });
    assert.equal(withPayload.eventBody, '{"a":1}');
    assert.equal(PUSHY_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
    assert.equal(truncatePushyPayload("abcdef", 4), "abcd… (truncated)");
    assert.equal(truncatePushyPayload("abc", 4), "abc");
    const long = resolvePushyData({ body: "x".repeat(2001), subject: "Alert" }, { includePayload: true });
    assert.equal(long.eventBody, `${"x".repeat(2000)}… (truncated)`);
    const short = resolvePushyData({ body: "0123456789ABCDEF", subject: "Alert" }, { includePayload: true, payloadMaxChars: 10 });
    assert.equal(short.eventBody, "0123456789… (truncated)");
  });

  it("derives the notification with title from subject only and body from the chain", () => {
    assert.deepEqual(resolvePushyNotification({ body: "{}", subject: "Price drop", key: "k" }, {}), {
      body: "Price drop",
      title: "Price drop",
    });
    // No subject: the title is omitted, the body falls back to the chain.
    assert.deepEqual(resolvePushyNotification({ body: "{}", key: "order-1" }, {}), { body: "order-1" });
    assert.deepEqual(resolvePushyNotification({ body: "{}" }, {}), { body: PUSHY_FALLBACK_SUMMARY });
  });

  it("adds sound and badge to the notification only when configured — never invented", () => {
    assert.deepEqual(
      resolvePushyNotification({ body: "{}", subject: "Alert" }, { sound: "ping.aiff", badge: 1 }),
      { body: "Alert", title: "Alert", sound: "ping.aiff", badge: 1 }
    );
    assert.deepEqual(
      resolvePushyNotification({ body: "{}", subject: "Alert" }, { badge: 0 }),
      { body: "Alert", title: "Alert", badge: 0 }
    );
    const plain = resolvePushyNotification({ body: "{}", subject: "Alert" }, {});
    assert.equal(plain.sound, undefined);
    assert.equal(plain.badge, undefined);
  });

  it("builds the push body with to/data/notification only — no topic, no credential", () => {
    const body = JSON.parse(
      buildPushyPushBody(
        "a6345d0278adc55d3474f5",
        { message: "Price drop" },
        { title: "Price drop", body: "Price drop" }
      )
    );
    assert.equal(body.to, "a6345d0278adc55d3474f5");
    assert.deepEqual(body.data, { message: "Price drop" });
    assert.deepEqual(body.notification, { title: "Price drop", body: "Price drop" });
    assert.equal(body.notification.sound, undefined);
    assert.equal(body.notification.badge, undefined);
    assert.equal(body.topics, undefined);
    // No credential ever enters the body.
    assert.equal(JSON.stringify(body).includes("api_key"), false);
    assert.equal(JSON.stringify(body).includes("Authorization"), false);
    assert.equal(JSON.stringify(body).includes("Bearer"), false);
    assert.equal(JSON.stringify(body).includes("secret"), false);
  });

  it("appends eventBody inside data under the opt-in, sound/badge when configured", () => {
    const body = JSON.parse(
      buildPushyPushBody(
        "a6345d0278adc55d3474f5",
        { message: "Alert", eventBody: '{"a":1}' },
        { title: "Alert", body: "Alert", sound: "ping.aiff", badge: 1 }
      )
    );
    assert.equal(body.data.eventBody, '{"a":1}');
    assert.equal(typeof body.data.eventBody, "string");
    assert.equal(body.notification.sound, "ping.aiff");
    assert.equal(body.notification.badge, 1);
  });

  it("rejects an empty record body", () => {
    assert.throws(() => resolvePushyRecord({ body: "" }, 0), RangeError);
    assert.deepEqual(resolvePushyRecord({ body: "{}" }, 2), { index: 2 });
  });
});

describe("pushy-sink failure mapping", () => {
  it("maps 429 and 5xx to retryable, other non-200 to fail-closed", () => {
    assert.equal(classifyPushyRecordFailure(429), true);
    assert.equal(classifyPushyRecordFailure(500), true);
    assert.equal(classifyPushyRecordFailure(503), true);
    assert.equal(classifyPushyRecordFailure(400), false);
    assert.equal(classifyPushyRecordFailure(403), false);
    assert.equal(classifyPushyRecordFailure(404), false);
    assert.equal(classifyPushyRecordFailure(201), false);
  });

  it("accepts a 200 carrying a push id", () => {
    assert.deepEqual(classifyPushyPushResponse({ status: 200, pushId: "5ea9b214b47cad768a35f13a" }), { accepted: true });
  });

  it("rejects a 200 whose body carries no push id", () => {
    assert.deepEqual(classifyPushyPushResponse({ status: 200 }), {
      accepted: false,
      errorCode: "PUSHY_NO_PUSH_ID",
      retryable: false,
    });
    assert.deepEqual(classifyPushyPushResponse({ status: 200, pushId: "" }), {
      accepted: false,
      errorCode: "PUSHY_NO_PUSH_ID",
      retryable: false,
    });
  });

  it("rejects a 201: the reference pins success to 200 OK", () => {
    assert.deepEqual(classifyPushyPushResponse({ status: 201, pushId: "push-1" }), {
      accepted: false,
      errorCode: "HTTP_201",
      retryable: false,
    });
  });

  it("maps a non-200 status to its HTTP code and lane, surfacing the docs' {code, error} shape", () => {
    assert.deepEqual(
      classifyPushyPushResponse({ status: 429, code: "RATE_LIMIT_EXCEEDED", error: "Your account has exceeded the API requests per minute limit." }),
      {
        accepted: false,
        errorCode: "HTTP_429",
        retryable: true,
        errorMessage: "RATE_LIMIT_EXCEEDED: Your account has exceeded the API requests per minute limit.",
      }
    );
    assert.deepEqual(classifyPushyPushResponse({ status: 403 }), {
      accepted: false,
      errorCode: "HTTP_403",
      retryable: false,
    });
    assert.deepEqual(
      classifyPushyPushResponse({ status: 400, code: "NO_RECIPIENTS", error: "No devices matched the specified condition." }),
      {
        accepted: false,
        errorCode: "HTTP_400",
        retryable: false,
        errorMessage: "NO_RECIPIENTS: No devices matched the specified condition.",
      }
    );
    assert.deepEqual(
      classifyPushyPushResponse({ status: 403, code: "INVALID_API_KEY", error: "The Secret API Key you used to authenticate is invalid." }),
      {
        accepted: false,
        errorCode: "HTTP_403",
        retryable: false,
        errorMessage: "INVALID_API_KEY: The Secret API Key you used to authenticate is invalid.",
      }
    );
    assert.deepEqual(
      classifyPushyPushResponse({ status: 500, code: "INTERNAL_SERVER_ERROR" }),
      {
        accepted: false,
        errorCode: "HTTP_500",
        retryable: true,
        errorMessage: "INTERNAL_SERVER_ERROR",
      }
    );
  });
});

describe("pushy-sink send", () => {
  it("posts one push per message with no credentials and no Idempotency-Key header", async () => {
    const client = new FakeClient();
    const sink = new PushySink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "Price drop", key: "order-1" },
      { body: '{"b":2}', key: "order-2" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2, pushIds: ["push-1", "push-2"] });
    assert.equal(client.posts.length, 2);
    const first = client.posts[0];
    assert.equal(first.url, "https://api.pushy.me/push");
    assert.equal(first.url.includes("api_key"), false);
    assert.equal(first.headers["Content-Type"], PUSHY_JSON_CONTENT_TYPE);
    assert.equal(first.headers["Authorization"], undefined);
    // The docs do not verify Idempotency-Key for this
    // endpoint, so the sink deliberately sends none.
    assert.equal(first.headers["Idempotency-Key"], undefined);
    assert.deepEqual(Object.keys(first.headers), ["Content-Type"]);
    const body = JSON.parse(first.body);
    assert.equal(body.to, "a6345d0278adc55d3474f5");
    assert.deepEqual(body.data, { message: "Price drop" });
    assert.deepEqual(body.notification, { title: "Price drop", body: "Price drop" });
    assert.equal(body.data.eventBody, undefined);
    assert.equal(body.notification.sound, undefined);
    // No credential ever enters the handed request.
    assert.equal(JSON.stringify(first).includes("api_key"), false);
    assert.equal(JSON.stringify(first).includes("Authorization"), false);
    assert.equal(JSON.stringify(first).includes("Bearer"), false);
    assert.equal(JSON.stringify(first).includes("secret"), false);
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("throws with exactly the failed messages and their retry lanes", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 429);
    client.statusOn.set(2, 500);
    const sink = new PushySink(baseConfig(client));
    await assert.rejects(
      sink.send([
        { body: "{}", key: "k1" },
        { body: "{}", key: "k2" },
        { body: "{}", key: "k3" },
      ]),
      (err: unknown) => {
        assert.ok(err instanceof PushySinkError);
        assert.deepEqual(
          (err as PushySinkError).failedRecords.map((f) => [f.index, f.errorCode, f.retryable]),
          [
            [1, "HTTP_429", true],
            [2, "HTTP_500", true],
          ]
        );
        return true;
      }
    );
    assert.deepEqual(sink.stats, { sent: 1, failed: 2, sendFailures: 1 });
  });

  it("treats a 200 without a push id as a fail-closed failure", async () => {
    const client = new FakeClient();
    client.pushIdOn.set(0, "");
    const sink = new PushySink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as PushySinkError).failedRecords;
        assert.equal(failed[0].errorCode, "PUSHY_NO_PUSH_ID");
        assert.equal(failed[0].statusCode, undefined);
        assert.equal(failed[0].retryable, false);
        return true;
      }
    );
  });

  it("treats no recipients (400 NO_RECIPIENTS) as fail-closed, surfacing code and error", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 400);
    client.codeOn.set(0, "NO_RECIPIENTS");
    client.errorOn.set(0, "No devices matched the specified condition.");
    const sink = new PushySink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as PushySinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_400");
        assert.equal(failed[0].statusCode, 400);
        assert.equal(failed[0].retryable, false);
        assert.equal(failed[0].errorMessage, "NO_RECIPIENTS: No devices matched the specified condition.");
        return true;
      }
    );
  });

  it("treats a bad Secret API Key (403 INVALID_API_KEY) as fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 403);
    client.codeOn.set(0, "INVALID_API_KEY");
    client.errorOn.set(0, "The Secret API Key you used to authenticate is invalid.");
    const sink = new PushySink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as PushySinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_403");
        assert.equal(failed[0].retryable, false);
        assert.equal(failed[0].errorMessage, "INVALID_API_KEY: The Secret API Key you used to authenticate is invalid.");
        return true;
      }
    );
  });

  it("treats a payload over the 4kb limit (400 PAYLOAD_LIMIT_EXCEEDED) as fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 400);
    client.codeOn.set(0, "PAYLOAD_LIMIT_EXCEEDED");
    const sink = new PushySink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as PushySinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_400");
        assert.equal(failed[0].retryable, false);
        return true;
      }
    );
  });

  it("treats a client throw as a retryable transport failure", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hang up"));
    const sink = new PushySink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as PushySinkError).failedRecords;
        assert.equal(failed[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(failed[0].retryable, true);
        assert.equal(failed[0].errorMessage, "socket hang up");
        return true;
      }
    );
  });

  it("throws a config error with no client, mapped non_retryable", async () => {
    const sink = new PushySink({ deviceToken: "a6345d0278adc55d3474f5" });
    await assert.rejects(sink.send([{ body: "{}", key: "k1" }]), PushySinkConfigError);
    assert.equal(classifyFailure(new PushySinkConfigError("no client injected")).failureClass, "non_retryable");
  });

  it("dry-runs with zero client I/O and untouched stats", async () => {
    const client = new FakeClient();
    const sink = new PushySink(baseConfig(client, { dryRun: true }));
    const result = await sink.send([{ body: "{}", subject: "Price drop" }]);
    assert.deepEqual(result, { ok: true, sent: 0, pushIds: [], dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("dry-runs still validate the config and the records", async () => {
    const client = new FakeClient();
    const sink = new PushySink(baseConfig(client, { dryRun: true }));
    await assert.rejects(sink.send([{ body: "" }]), RangeError);
    assert.equal(client.posts.length, 0);
    assert.throws(
      () => new PushySink({ deviceToken: "/topics/news", dryRun: true }),
      RangeError
    );
  });

  it("appends eventBody under the opt-in, truncated at the default 2000", async () => {
    const client = new FakeClient();
    const sink = new PushySink(baseConfig(client, { includePayload: true, payloadMaxChars: 10 }));
    await sink.send([{ body: "0123456789ABCDEF", subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.data.eventBody, "0123456789… (truncated)");
    assert.equal(body.data.message, "Alert");
    assert.equal(body.notification.body, "Alert");

    const defaultClient = new FakeClient();
    const defaultSink = new PushySink(baseConfig(defaultClient, { includePayload: true }));
    await defaultSink.send([{ body: "x".repeat(2001), subject: "Alert" }]);
    const defaultBody = JSON.parse(defaultClient.posts[0].body);
    assert.equal(defaultBody.data.eventBody, `${"x".repeat(2000)}… (truncated)`);
  });

  it("omits eventBody by default", async () => {
    const client = new FakeClient();
    const sink = new PushySink(baseConfig(client));
    await sink.send([{ body: '{"secret":"s3cr3t"}', subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.data.message, "Alert");
    assert.equal(body.data.eventBody, undefined);
    assert.equal(JSON.stringify(body).includes("s3cr3t"), false);
  });

  it("sends configured sound and badge in the notification, omits both by default", async () => {
    const client = new FakeClient();
    const sink = new PushySink(baseConfig(client, { sound: "ping.aiff", badge: 1 }));
    await sink.send([{ body: "{}", subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.notification.sound, "ping.aiff");
    assert.equal(body.notification.badge, 1);
  });

  it("collects push ids in send order across messages", async () => {
    const client = new FakeClient();
    client.pushIdOn.set(0, "push-first");
    client.pushIdOn.set(1, "push-second");
    const sink = new PushySink(baseConfig(client));
    const result = await sink.send([
      { body: "{}", key: "k1" },
      { body: "{}", key: "k2" },
    ]);
    assert.deepEqual(result.pushIds, ["push-first", "push-second"]);
  });
});
