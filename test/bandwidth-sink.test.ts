import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  BandwidthSink,
  BandwidthSinkConfigError,
  BandwidthSinkError,
  assertValidBandwidthSinkConfig,
  bandwidthMessagesUrl,
  buildBandwidthMessageBody,
  classifyBandwidthRecordFailure,
  resolveBandwidthText,
  resolveBandwidthNotification,
  resolveBandwidthRecord,
  truncateBandwidthPayload,
  BANDWIDTH_API_HOST,
  BANDWIDTH_DEFAULT_PAYLOAD_MAX_CHARS,
  BANDWIDTH_FALLBACK_SUMMARY,
  type BandwidthMessageClient,
  type BandwidthMessagePostRequest,
  type BandwidthMessagePostResponse,
  type BandwidthSinkConfig,
} from "../src/bandwidth-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements BandwidthMessageClient {
  posts: BandwidthMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: BandwidthMessagePostRequest): Promise<BandwidthMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 201 };
  }
}

const accountId = "5000000";
const applicationId = "7fc9698a-1234-4a12-9abc-1234567890ab";
const from = "+14155550100";
const to = "+14155550101";

function baseConfig(
  client: BandwidthMessageClient,
  extra: Partial<BandwidthSinkConfig> = {}
): BandwidthSinkConfig {
  return { accountId, applicationId, from, to, client, ...extra };
}

describe("bandwidth-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidBandwidthSinkConfig(null, "BandwidthSink"), RangeError);
    assert.throws(() => assertValidBandwidthSinkConfig("x", "BandwidthSink"), RangeError);
  });

  it("rejects a malformed account id, application id, sender, or recipient shape", () => {
    assert.throws(() => assertValidBandwidthSinkConfig({ accountId: "" }, "BandwidthSink"), RangeError);
    assert.throws(() => assertValidBandwidthSinkConfig({ accountId: "has space" }, "BandwidthSink"), RangeError);
    assert.throws(() => assertValidBandwidthSinkConfig({ applicationId: "" }, "BandwidthSink"), RangeError);
    assert.throws(() => assertValidBandwidthSinkConfig({ applicationId: "has space" }, "BandwidthSink"), RangeError);
    assert.throws(() => assertValidBandwidthSinkConfig({ from: "" }, "BandwidthSink"), RangeError);
    assert.throws(() => assertValidBandwidthSinkConfig({ from: "has space" }, "BandwidthSink"), RangeError);
    assert.throws(() => assertValidBandwidthSinkConfig({ to: "" }, "BandwidthSink"), RangeError);
    assert.throws(() => assertValidBandwidthSinkConfig({ to: "has space" }, "BandwidthSink"), RangeError);
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidBandwidthSinkConfig({ client: {} }, "BandwidthSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidBandwidthSinkConfig({ payloadMaxChars: 0 }, "BandwidthSink"), RangeError);
    assert.throws(() => assertValidBandwidthSinkConfig({ payloadMaxChars: 2.5 }, "BandwidthSink"), RangeError);
  });

  it("accepts a config with no account id, application id, sender, or recipient yet (send-time config error)", () => {
    assert.doesNotThrow(() => new BandwidthSink({}));
  });
});

describe("bandwidth-sink text derivation", () => {
  it("derives the text from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveBandwidthText({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveBandwidthText({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveBandwidthText({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveBandwidthText({ body: "{}" }), BANDWIDTH_FALLBACK_SUMMARY);
    assert.equal(
      resolveBandwidthText({ body: "{}", subject: "", key: "", traceId: "" }),
      BANDWIDTH_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateBandwidthPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateBandwidthPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveBandwidthNotification(record, {}), { text: "order.created" });
    assert.deepEqual(resolveBandwidthNotification(record, { includePayload: true }), {
      text: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveBandwidthNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { text: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveBandwidthRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("bandwidth-sink wire shape", () => {
  it("builds the fixed-host messages URL with the percent-encoded account id in the path", () => {
    assert.equal(
      bandwidthMessagesUrl(accountId),
      `https://messaging.bandwidth.com/api/v2/users/${accountId}/messages`
    );
    assert.equal(
      bandwidthMessagesUrl("acct/with slash"),
      "https://messaging.bandwidth.com/api/v2/users/acct%2Fwith%20slash/messages"
    );
    assert.equal(BANDWIDTH_API_HOST, "https://messaging.bandwidth.com");
  });

  it("builds the JSON body with applicationId, to array, from, and text — and no credential or account id", () => {
    assert.equal(
      buildBandwidthMessageBody(applicationId, to, from, "order.created"),
      JSON.stringify({ applicationId, to: [to], from, text: "order.created" })
    );
    const body = buildBandwidthMessageBody(applicationId, to, from, "x");
    assert.equal(body.includes("Basic"), false);
    assert.equal(body.includes("password"), false);
    assert.equal(body.includes(accountId), false);
    assert.equal(Object.keys(JSON.parse(body)).join(","), "applicationId,to,from,text");
  });
});

describe("bandwidth-sink send", () => {
  it("posts one message per record to the account messages endpoint with the JSON body, no credential", async () => {
    const client = new FakeClient();
    const sink = new BandwidthSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: `https://messaging.bandwidth.com/api/v2/users/${accountId}/messages`,
      body: JSON.stringify({ applicationId, to: [to], from, text: "order.created" }),
    });
    assert.deepEqual(JSON.parse(client.posts[1].body).text, "agg-8");
    assert.deepEqual(JSON.parse(client.posts[2].body).text, "t-9");
    for (const post of client.posts) {
      assert.equal(post.body.includes("Basic"), false);
      assert.equal(post.body.includes(accountId), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("applies the payload opt-in truncation on send", async () => {
    const client = new FakeClient();
    const sink = new BandwidthSink(
      baseConfig(client, { includePayload: true, payloadMaxChars: 3 })
    );
    await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.equal(
      JSON.parse(client.posts[0].body).text,
      `order.created\n\n{"a… (truncated)`
    );
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new BandwidthSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof BandwidthSinkError);
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
    const sink = new BandwidthSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof BandwidthSinkError);
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

  it("fails closed without a client, account id, application id, sender, or recipient", async () => {
    await assert.rejects(
      () =>
        new BandwidthSink({ accountId, applicationId, from, to }).send([{ body: '{"a":1}' }]),
      BandwidthSinkConfigError
    );
    await assert.rejects(
      () =>
        new BandwidthSink(baseConfig(new FakeClient(), { accountId: undefined })).send([
          { body: '{"a":1}' },
        ]),
      BandwidthSinkConfigError
    );
    await assert.rejects(
      () =>
        new BandwidthSink(baseConfig(new FakeClient(), { applicationId: undefined })).send([
          { body: '{"a":1}' },
        ]),
      BandwidthSinkConfigError
    );
    await assert.rejects(
      () =>
        new BandwidthSink(baseConfig(new FakeClient(), { from: undefined })).send([
          { body: '{"a":1}' },
        ]),
      BandwidthSinkConfigError
    );
    await assert.rejects(
      () =>
        new BandwidthSink(baseConfig(new FakeClient(), { to: undefined })).send([
          { body: '{"a":1}' },
        ]),
      BandwidthSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new BandwidthSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new BandwidthSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new BandwidthSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyBandwidthRecordFailure(429), true);
    assert.equal(classifyBandwidthRecordFailure(500), true);
    assert.equal(classifyBandwidthRecordFailure(503), true);
    assert.equal(classifyBandwidthRecordFailure(400), false);
    assert.equal(classifyBandwidthRecordFailure(401), false);
    assert.equal(classifyBandwidthRecordFailure(404), false);
    assert.equal(BANDWIDTH_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
