import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  SinchSink,
  SinchSinkConfigError,
  SinchSinkError,
  assertValidSinchSinkConfig,
  buildSinchBatchesUrl,
  buildSinchMessageBody,
  classifySinchRecordFailure,
  resolveSinchBody,
  resolveSinchNotification,
  resolveSinchRecord,
  truncateSinchPayload,
  SINCH_DEFAULT_PAYLOAD_MAX_CHARS,
  SINCH_DEFAULT_REGION,
  SINCH_FALLBACK_SUMMARY,
  type SinchMessageClient,
  type SinchMessagePostRequest,
  type SinchMessagePostResponse,
  type SinchSinkConfig,
} from "../src/sinch-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements SinchMessageClient {
  posts: SinchMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: SinchMessagePostRequest): Promise<SinchMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 201 };
  }
}

const from = "RelayAlert";
const recipient = "+14155550101";
const servicePlanId = "01W4FFTRDVT4V8V2X7Y9Z0ABC";

function baseConfig(
  client: SinchMessageClient,
  extra: Partial<SinchSinkConfig> = {}
): SinchSinkConfig {
  return { from, recipient, servicePlanId, client, ...extra };
}

describe("sinch-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidSinchSinkConfig(null, "SinchSink"), RangeError);
    assert.throws(() => assertValidSinchSinkConfig("x", "SinchSink"), RangeError);
  });

  it("rejects a malformed sender, recipient, region, or service plan id shape", () => {
    assert.throws(() => assertValidSinchSinkConfig({ from: "" }, "SinchSink"), RangeError);
    assert.throws(() => assertValidSinchSinkConfig({ from: "has space" }, "SinchSink"), RangeError);
    assert.throws(() => assertValidSinchSinkConfig({ recipient: "" }, "SinchSink"), RangeError);
    assert.throws(() => assertValidSinchSinkConfig({ recipient: "has space" }, "SinchSink"), RangeError);
    assert.throws(() => assertValidSinchSinkConfig({ region: "" }, "SinchSink"), RangeError);
    assert.throws(() => assertValidSinchSinkConfig({ region: "has space" }, "SinchSink"), RangeError);
    assert.throws(() => assertValidSinchSinkConfig({ servicePlanId: "" }, "SinchSink"), RangeError);
    assert.throws(() => assertValidSinchSinkConfig({ servicePlanId: "has space" }, "SinchSink"), RangeError);
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidSinchSinkConfig({ client: {} }, "SinchSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidSinchSinkConfig({ payloadMaxChars: 0 }, "SinchSink"), RangeError);
    assert.throws(() => assertValidSinchSinkConfig({ payloadMaxChars: 2.5 }, "SinchSink"), RangeError);
  });

  it("accepts a config with no sender, recipient, or service plan id yet (send-time config error)", () => {
    assert.doesNotThrow(() => new SinchSink({}));
  });
});

describe("sinch-sink body derivation", () => {
  it("derives the body from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveSinchBody({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveSinchBody({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveSinchBody({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveSinchBody({ body: "{}" }), SINCH_FALLBACK_SUMMARY);
    assert.equal(
      resolveSinchBody({ body: "{}", subject: "", key: "", traceId: "" }),
      SINCH_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateSinchPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateSinchPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveSinchNotification(record, {}), { body: "order.created" });
    assert.deepEqual(resolveSinchNotification(record, { includePayload: true }), {
      body: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveSinchNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { body: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveSinchRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("sinch-sink wire shape", () => {
  it("builds the region-derived batches URL with the percent-encoded service plan id in the path", () => {
    assert.equal(
      buildSinchBatchesUrl("us", servicePlanId),
      `https://us.sms.api.sinch.com/xms/v1/${servicePlanId}/batches`
    );
    assert.equal(
      buildSinchBatchesUrl("eu", "plan/with slash"),
      "https://eu.sms.api.sinch.com/xms/v1/plan%2Fwith%20slash/batches"
    );
    assert.equal(SINCH_DEFAULT_REGION, "us");
  });

  it("builds the JSON body with from, to array, and body — and no credential or plan id", () => {
    assert.equal(
      buildSinchMessageBody(from, recipient, "order.created"),
      JSON.stringify({ from, to: [recipient], body: "order.created" })
    );
    assert.equal(buildSinchMessageBody(from, recipient, "x").includes("Bearer"), false);
    assert.equal(buildSinchMessageBody(from, recipient, "x").includes(servicePlanId), false);
    assert.equal(buildSinchMessageBody(from, recipient, "x").includes("api_token"), false);
  });
});

describe("sinch-sink send", () => {
  it("posts one message per record to the region batches endpoint with the JSON body, no credential", async () => {
    const client = new FakeClient();
    const sink = new SinchSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: `https://us.sms.api.sinch.com/xms/v1/${servicePlanId}/batches`,
      body: JSON.stringify({ from, to: [recipient], body: "order.created" }),
    });
    assert.deepEqual(JSON.parse(client.posts[1].body).body, "agg-8");
    assert.deepEqual(JSON.parse(client.posts[2].body).body, "t-9");
    for (const post of client.posts) {
      assert.equal(post.body.includes("Bearer"), false);
      assert.equal(post.body.includes(servicePlanId), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("uses the configured region in the host when set", async () => {
    const client = new FakeClient();
    const sink = new SinchSink(baseConfig(client, { region: "eu" }));
    await sink.send([{ body: '{"a":1}' }]);
    assert.equal(
      client.posts[0].url,
      `https://eu.sms.api.sinch.com/xms/v1/${servicePlanId}/batches`
    );
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new SinchSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof SinchSinkError);
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
    const sink = new SinchSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof SinchSinkError);
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

  it("fails closed without a client, sender, recipient, or service plan id", async () => {
    await assert.rejects(
      () => new SinchSink({ from, recipient, servicePlanId }).send([{ body: '{"a":1}' }]),
      SinchSinkConfigError
    );
    await assert.rejects(
      () => new SinchSink(baseConfig(new FakeClient(), { from: undefined })).send([{ body: '{"a":1}' }]),
      SinchSinkConfigError
    );
    await assert.rejects(
      () => new SinchSink(baseConfig(new FakeClient(), { recipient: undefined })).send([{ body: '{"a":1}' }]),
      SinchSinkConfigError
    );
    await assert.rejects(
      () => new SinchSink(baseConfig(new FakeClient(), { servicePlanId: undefined })).send([{ body: '{"a":1}' }]),
      SinchSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new SinchSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new SinchSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new SinchSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifySinchRecordFailure(429), true);
    assert.equal(classifySinchRecordFailure(500), true);
    assert.equal(classifySinchRecordFailure(503), true);
    assert.equal(classifySinchRecordFailure(400), false);
    assert.equal(classifySinchRecordFailure(401), false);
    assert.equal(classifySinchRecordFailure(404), false);
    assert.equal(SINCH_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
