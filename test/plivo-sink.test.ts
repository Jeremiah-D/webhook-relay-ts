import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  PlivoSink,
  PlivoSinkConfigError,
  PlivoSinkError,
  assertValidPlivoSinkConfig,
  buildPlivoMessageBody,
  classifyPlivoRecordFailure,
  plivoMessageUrl,
  resolvePlivoNotification,
  resolvePlivoRecord,
  resolvePlivoText,
  truncatePlivoPayload,
  PLIVO_DEFAULT_PAYLOAD_MAX_CHARS,
  PLIVO_FALLBACK_SUMMARY,
  type PlivoMessageClient,
  type PlivoMessagePostRequest,
  type PlivoMessagePostResponse,
  type PlivoSinkConfig,
} from "../src/plivo-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements PlivoMessageClient {
  posts: PlivoMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: PlivoMessagePostRequest): Promise<PlivoMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 201 };
  }
}

const authId = "MAXXXXXXXXXXXXXXXX";
const src = "+14155550100";
const dst = "+14155550101";

function baseConfig(
  client: PlivoMessageClient,
  extra: Partial<PlivoSinkConfig> = {}
): PlivoSinkConfig {
  return { authId, src, dst, client, ...extra };
}

describe("plivo-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidPlivoSinkConfig(null, "PlivoSink"), RangeError);
    assert.throws(() => assertValidPlivoSinkConfig("x", "PlivoSink"), RangeError);
  });

  it("rejects a malformed auth id, sender, or recipient shape", () => {
    assert.throws(() => assertValidPlivoSinkConfig({ authId: "" }, "PlivoSink"), RangeError);
    assert.throws(() => assertValidPlivoSinkConfig({ authId: "has space" }, "PlivoSink"), RangeError);
    assert.throws(() => assertValidPlivoSinkConfig({ src: "" }, "PlivoSink"), RangeError);
    assert.throws(() => assertValidPlivoSinkConfig({ src: "has space" }, "PlivoSink"), RangeError);
    assert.throws(() => assertValidPlivoSinkConfig({ dst: "" }, "PlivoSink"), RangeError);
    assert.throws(() => assertValidPlivoSinkConfig({ dst: "has space" }, "PlivoSink"), RangeError);
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidPlivoSinkConfig({ client: {} }, "PlivoSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidPlivoSinkConfig({ payloadMaxChars: 0 }, "PlivoSink"), RangeError);
    assert.throws(() => assertValidPlivoSinkConfig({ payloadMaxChars: 2.5 }, "PlivoSink"), RangeError);
  });

  it("accepts a config with no auth id, sender, or recipient yet (send-time config error)", () => {
    assert.doesNotThrow(() => new PlivoSink({}));
  });
});

describe("plivo-sink text derivation", () => {
  it("derives the text from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolvePlivoText({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolvePlivoText({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolvePlivoText({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolvePlivoText({ body: "{}" }), PLIVO_FALLBACK_SUMMARY);
    assert.equal(
      resolvePlivoText({ body: "{}", subject: "", key: "", traceId: "" }),
      PLIVO_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncatePlivoPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncatePlivoPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolvePlivoNotification(record, {}), { text: "order.created" });
    assert.deepEqual(resolvePlivoNotification(record, { includePayload: true }), {
      text: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolvePlivoNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { text: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolvePlivoRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("plivo-sink wire shape", () => {
  it("builds the account Message endpoint with the auth id in the path only", () => {
    assert.equal(
      plivoMessageUrl(authId),
      `https://api.plivo.com/v1/Account/${authId}/Message/`
    );
    assert.equal(
      plivoMessageUrl("id with space"),
      "https://api.plivo.com/v1/Account/id%20with%20space/Message/"
    );
  });

  it("builds the JSON body with src, dst, and text — and no credential or auth id", () => {
    assert.equal(
      buildPlivoMessageBody(src, dst, "order.created"),
      JSON.stringify({ src, dst, text: "order.created" })
    );
    // The auth token never appears in the body, and neither
    // does the auth id: the id lives in the URL path only.
    assert.equal(buildPlivoMessageBody(src, dst, "x").includes("Basic"), false);
    assert.equal(buildPlivoMessageBody(src, dst, "x").includes("auth_token"), false);
    assert.equal(buildPlivoMessageBody(src, dst, "x").includes(authId), false);
  });
});

describe("plivo-sink send", () => {
  it("posts one message per record to the account endpoint with the JSON body, no credential", async () => {
    const client = new FakeClient();
    const sink = new PlivoSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: `https://api.plivo.com/v1/Account/${authId}/Message/`,
      body: JSON.stringify({ src, dst, text: "order.created" }),
    });
    assert.deepEqual(JSON.parse(client.posts[1].body).text, "agg-8");
    assert.deepEqual(JSON.parse(client.posts[2].body).text, "t-9");
    // The request carries no credential anywhere: the auth
    // token is held by the client alone, and the auth id is
    // in the URL path, never the body.
    for (const post of client.posts) {
      assert.equal(post.body.includes("Basic"), false);
      assert.equal(post.body.includes(authId), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new PlivoSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof PlivoSinkError);
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
    const sink = new PlivoSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof PlivoSinkError);
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

  it("fails closed without a client, auth id, sender, or recipient", async () => {
    await assert.rejects(
      () => new PlivoSink({ authId, src, dst }).send([{ body: '{"a":1}' }]),
      PlivoSinkConfigError
    );
    await assert.rejects(
      () => new PlivoSink(baseConfig(new FakeClient(), { authId: undefined })).send([{ body: '{"a":1}' }]),
      PlivoSinkConfigError
    );
    await assert.rejects(
      () => new PlivoSink(baseConfig(new FakeClient(), { src: undefined })).send([{ body: '{"a":1}' }]),
      PlivoSinkConfigError
    );
    await assert.rejects(
      () => new PlivoSink(baseConfig(new FakeClient(), { dst: undefined })).send([{ body: '{"a":1}' }]),
      PlivoSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new PlivoSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new PlivoSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new PlivoSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyPlivoRecordFailure(429), true);
    assert.equal(classifyPlivoRecordFailure(500), true);
    assert.equal(classifyPlivoRecordFailure(503), true);
    assert.equal(classifyPlivoRecordFailure(400), false);
    assert.equal(classifyPlivoRecordFailure(401), false);
    assert.equal(classifyPlivoRecordFailure(404), false);
    assert.equal(PLIVO_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
