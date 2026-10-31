import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  AirshipSink,
  AirshipSinkConfigError,
  AirshipSinkError,
  airshipResponseToFailedRecord,
  assertValidAirshipSinkConfig,
  buildAirshipPushBody,
  classifyAirshipRecordFailure,
  resolveAirshipAlert,
  resolveAirshipAudience,
  resolveAirshipNotification,
  resolveAirshipRecord,
  truncateAirshipPayload,
  AIRSHIP_ACCEPT_HEADER,
  AIRSHIP_DEFAULT_PAYLOAD_MAX_CHARS,
  AIRSHIP_DEVICE_TYPES,
  AIRSHIP_FALLBACK_SUMMARY,
  AIRSHIP_JSON_CONTENT_TYPE,
  AIRSHIP_PUSH_URL,
  type AirshipAudience,
  type AirshipMessageClient,
  type AirshipMessagePostRequest,
  type AirshipMessagePostResponse,
  type AirshipSinkConfig,
} from "../src/airship-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status and push ids per call. */
class FakeClient implements AirshipMessageClient {
  posts: AirshipMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  /** Call-count (0-based) → push ids to return for that post (undefined = none surfaced). */
  pushIdsOn = new Map<number, string[] | undefined>();
  async post(request: AirshipMessagePostRequest): Promise<AirshipMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return {
      status: this.statusOn.get(n) ?? 202,
      pushIds: this.pushIdsOn.has(n) ? this.pushIdsOn.get(n) : [`push-${n}`],
    };
  }
}

const audience: AirshipAudience = { named_user: "user-1" };

function baseConfig(
  client: AirshipMessageClient,
  extra: Partial<AirshipSinkConfig> = {}
): AirshipSinkConfig {
  return { audience, client, ...extra };
}

describe("airship-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidAirshipSinkConfig(null, "AirshipSink"), RangeError);
    assert.throws(() => assertValidAirshipSinkConfig("x", "AirshipSink"), RangeError);
  });

  it("rejects a malformed audience shape", () => {
    assert.throws(
      () => assertValidAirshipSinkConfig({ audience: "everyone" }, "AirshipSink"),
      RangeError
    );
    assert.throws(
      () => assertValidAirshipSinkConfig({ audience: "" }, "AirshipSink"),
      RangeError
    );
    assert.throws(
      () => assertValidAirshipSinkConfig({ audience: {} }, "AirshipSink"),
      RangeError
    );
    assert.throws(
      () => assertValidAirshipSinkConfig({ audience: ["tag-a"] }, "AirshipSink"),
      RangeError
    );
    assert.throws(
      () => assertValidAirshipSinkConfig({ audience: 42 }, "AirshipSink"),
      RangeError
    );
    assert.doesNotThrow(() =>
      assertValidAirshipSinkConfig({ audience: "all" }, "AirshipSink")
    );
    assert.doesNotThrow(() =>
      assertValidAirshipSinkConfig({ audience: { tag: "news" } }, "AirshipSink")
    );
    assert.doesNotThrow(() =>
      assertValidAirshipSinkConfig(
        { audience: { and: [{ tag: "news" }, { named_user: "u-1" }] } },
        "AirshipSink"
      )
    );
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidAirshipSinkConfig({ client: {} }, "AirshipSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidAirshipSinkConfig({ payloadMaxChars: 0 }, "AirshipSink"), RangeError);
    assert.throws(
      () => assertValidAirshipSinkConfig({ payloadMaxChars: 2.5 }, "AirshipSink"),
      RangeError
    );
  });

  it("accepts a config with no client or audience yet (send-time config error only for the client)", () => {
    assert.doesNotThrow(() => new AirshipSink({}));
  });
});

describe("airship-sink audience resolution", () => {
  it("defaults the audience to \"all\" when the config sets none", () => {
    assert.equal(resolveAirshipAudience({}), "all");
    assert.equal(resolveAirshipAudience({ audience: undefined }), "all");
    assert.equal(resolveAirshipAudience({ audience: "all" }), "all");
    assert.deepEqual(resolveAirshipAudience({ audience }), audience);
  });
});

describe("airship-sink alert derivation", () => {
  it("derives the alert from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveAirshipAlert({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveAirshipAlert({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveAirshipAlert({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveAirshipAlert({ body: "{}" }), AIRSHIP_FALLBACK_SUMMARY);
    assert.equal(
      resolveAirshipAlert({ body: "{}", subject: "", key: "", traceId: "" }),
      AIRSHIP_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateAirshipPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateAirshipPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveAirshipNotification(record, {}), { alert: "order.created" });
    assert.deepEqual(resolveAirshipNotification(record, { includePayload: true }), {
      alert: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveAirshipNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { alert: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveAirshipRecord({ body: "" }, 2),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("airship-sink wire shape", () => {
  it("exposes the fixed Airship Push endpoint, the v3 Accept header, and device_types all", () => {
    assert.equal(AIRSHIP_PUSH_URL, "https://go.urbanairship.com/api/push");
    assert.equal(AIRSHIP_ACCEPT_HEADER, "application/vnd.urbanairship+json; version=3");
    assert.equal(AIRSHIP_JSON_CONTENT_TYPE, "application/json");
    assert.equal(AIRSHIP_DEVICE_TYPES, "all");
  });

  it("builds a JSON body: audience, notification.alert, device_types all — and no credential", () => {
    assert.deepEqual(
      JSON.parse(buildAirshipPushBody(audience, { alert: "order.created" })),
      {
        audience: { named_user: "user-1" },
        notification: { alert: "order.created" },
        device_types: "all",
      }
    );
    assert.deepEqual(
      JSON.parse(buildAirshipPushBody("all", { alert: "agg-7" })),
      {
        audience: "all",
        notification: { alert: "agg-7" },
        device_types: "all",
      }
    );
    const body = buildAirshipPushBody(audience, { alert: "x" });
    assert.equal(body.includes("Authorization"), false);
    assert.equal(body.includes("Basic"), false);
    assert.equal(body.includes("app key"), false);
    assert.equal(body.includes("master secret"), false);
  });
});

describe("airship-sink push-ids mapping", () => {
  it("accepts a 2xx with push ids", () => {
    assert.equal(
      airshipResponseToFailedRecord({ status: 202, pushIds: ["push-1"] }, 0),
      null
    );
  });

  it("maps missing push ids on a 2xx to retryable", () => {
    assert.deepEqual(airshipResponseToFailedRecord({ status: 202 }, 0), {
      index: 0,
      errorCode: "PUSH_IDS_MISSING",
      errorMessage: "Airship answered 2xx but surfaced no push_ids",
      retryable: true,
    });
    assert.deepEqual(airshipResponseToFailedRecord({ status: 202, pushIds: [] }, 1), {
      index: 1,
      errorCode: "PUSH_IDS_MISSING",
      errorMessage: "Airship answered 2xx but surfaced no push_ids",
      retryable: true,
    });
    assert.deepEqual(airshipResponseToFailedRecord({ status: 200, pushIds: [""] }, 2), {
      index: 2,
      errorCode: "PUSH_IDS_MISSING",
      errorMessage: "Airship answered 2xx but surfaced no push_ids",
      retryable: true,
    });
  });
});

describe("airship-sink send", () => {
  it("posts one message per record to the fixed endpoint with the JSON push, no credential", async () => {
    const client = new FakeClient();
    const sink = new AirshipSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.equal(client.posts[0].url, AIRSHIP_PUSH_URL);
    assert.deepEqual(client.posts[0].headers, {
      "Content-Type": AIRSHIP_JSON_CONTENT_TYPE,
      Accept: AIRSHIP_ACCEPT_HEADER,
    });
    assert.deepEqual(JSON.parse(client.posts[0].body), {
      audience: { named_user: "user-1" },
      notification: { alert: "order.created" },
      device_types: "all",
    });
    assert.deepEqual(JSON.parse(client.posts[1].body).notification, { alert: "agg-8" });
    assert.deepEqual(JSON.parse(client.posts[2].body).notification, { alert: "t-9" });
    for (const post of client.posts) {
      assert.equal(post.body.includes("Authorization"), false);
      assert.equal(post.body.includes("Basic"), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("defaults the audience to \"all\" when the config sets none", async () => {
    const client = new FakeClient();
    const sink = new AirshipSink({ client });
    await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.equal(JSON.parse(client.posts[0].body).audience, "all");
  });

  it("applies the payload opt-in truncation on send", async () => {
    const client = new FakeClient();
    const sink = new AirshipSink(baseConfig(client, { includePayload: true, payloadMaxChars: 3 }));
    await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.equal(
      JSON.parse(client.posts[0].body).notification.alert,
      `order.created\n\n{"a… (truncated)`
    );
  });

  it("treats push ids as an acceptance receipt, not a delivery result", async () => {
    const client = new FakeClient();
    client.pushIdsOn.set(0, ["9d78a53b-b16a-c58f-b78d-181d5e242078"]);
    const sink = new AirshipSink(baseConfig(client));
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 1 });
    assert.deepEqual(sink.stats, { sent: 1, failed: 0, sendFailures: 0 });
  });

  it("retries a 2xx with no push ids surfaced", async () => {
    const client = new FakeClient();
    client.pushIdsOn.set(0, undefined);
    const sink = new AirshipSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }]),
      (err: unknown) => {
        assert.ok(err instanceof AirshipSinkError);
        assert.equal(err.failedRecords.length, 1);
        assert.deepEqual(
          err.failedRecords.map((r) => [r.index, r.errorCode, r.retryable]),
          [[0, "PUSH_IDS_MISSING", true]]
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
    const sink = new AirshipSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof AirshipSinkError);
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
    client.statusOn.set(0, 202);
    client.failOn.set(1, new Error("socket hangup"));
    const sink = new AirshipSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof AirshipSinkError);
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

  it("fails closed without a client", async () => {
    await assert.rejects(
      () => new AirshipSink({ audience }).send([{ body: '{"a":1}' }]),
      AirshipSinkConfigError
    );
  });

  it("does not fail closed for a missing audience — it broadcasts to \"all\"", async () => {
    const client = new FakeClient();
    const sink = new AirshipSink({ client });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 1 });
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new AirshipSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new AirshipSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new AirshipSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyAirshipRecordFailure(429), true);
    assert.equal(classifyAirshipRecordFailure(500), true);
    assert.equal(classifyAirshipRecordFailure(503), true);
    assert.equal(classifyAirshipRecordFailure(400), false);
    assert.equal(classifyAirshipRecordFailure(401), false);
    assert.equal(classifyAirshipRecordFailure(404), false);
    assert.equal(AIRSHIP_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
