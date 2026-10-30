import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  BrazeSink,
  BrazeSinkConfigError,
  BrazeSinkError,
  assertValidBrazeSinkConfig,
  buildBrazeMessageBody,
  classifyBrazeRecordFailure,
  resolveBrazeBody,
  resolveBrazeNotification,
  resolveBrazeRecord,
  resolveBrazeSubject,
  truncateBrazePayload,
  BRAZE_SEND_URL,
  BRAZE_DEFAULT_PAYLOAD_MAX_CHARS,
  BRAZE_FALLBACK_SUMMARY,
  type BrazeMessageClient,
  type BrazeMessagePostRequest,
  type BrazeMessagePostResponse,
  type BrazeSinkConfig,
} from "../src/braze-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements BrazeMessageClient {
  posts: BrazeMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: BrazeMessagePostRequest): Promise<BrazeMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200 };
  }
}

const appId = "braze-app-123";
const from = "alerts@example.com";
const externalUserIds = ["user-1", "user-2"];

function baseConfig(
  client: BrazeMessageClient,
  extra: Partial<BrazeSinkConfig> = {}
): BrazeSinkConfig {
  return { appId, from, externalUserIds, client, ...extra };
}

describe("braze-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidBrazeSinkConfig(null, "BrazeSink"), RangeError);
    assert.throws(() => assertValidBrazeSinkConfig("x", "BrazeSink"), RangeError);
  });

  it("rejects a malformed app id shape", () => {
    assert.throws(() => assertValidBrazeSinkConfig({ appId: "" }, "BrazeSink"), RangeError);
    assert.throws(
      () => assertValidBrazeSinkConfig({ appId: "has space" }, "BrazeSink"),
      RangeError
    );
    assert.throws(() => assertValidBrazeSinkConfig({ appId: 42 }, "BrazeSink"), RangeError);
  });

  it("rejects a malformed sender shape", () => {
    assert.throws(() => assertValidBrazeSinkConfig({ from: "" }, "BrazeSink"), RangeError);
    assert.throws(
      () => assertValidBrazeSinkConfig({ from: "has space" }, "BrazeSink"),
      RangeError
    );
    assert.throws(() => assertValidBrazeSinkConfig({ from: 42 }, "BrazeSink"), RangeError);
  });

  it("rejects a malformed recipient set", () => {
    assert.throws(
      () => assertValidBrazeSinkConfig({ externalUserIds: [] }, "BrazeSink"),
      RangeError
    );
    assert.throws(
      () => assertValidBrazeSinkConfig({ externalUserIds: "user-1" }, "BrazeSink"),
      RangeError
    );
    assert.throws(
      () => assertValidBrazeSinkConfig({ externalUserIds: [""] }, "BrazeSink"),
      RangeError
    );
    assert.throws(
      () => assertValidBrazeSinkConfig({ externalUserIds: ["has space"] }, "BrazeSink"),
      RangeError
    );
    assert.throws(
      () => assertValidBrazeSinkConfig({ externalUserIds: [42] }, "BrazeSink"),
      RangeError
    );
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidBrazeSinkConfig({ client: {} }, "BrazeSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidBrazeSinkConfig({ payloadMaxChars: 0 }, "BrazeSink"), RangeError);
    assert.throws(
      () => assertValidBrazeSinkConfig({ payloadMaxChars: 2.5 }, "BrazeSink"),
      RangeError
    );
  });

  it("accepts a config with no app id, sender, or recipients yet (send-time config error)", () => {
    assert.doesNotThrow(() => new BrazeSink({}));
  });
});

describe("braze-sink text derivation", () => {
  it("derives the subject from subject, then key, then the fallback (never traceId)", () => {
    assert.equal(
      resolveBrazeSubject({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveBrazeSubject({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveBrazeSubject({ body: "{}", traceId: "t-1" }), BRAZE_FALLBACK_SUMMARY);
    assert.equal(resolveBrazeSubject({ body: "{}" }), BRAZE_FALLBACK_SUMMARY);
  });

  it("derives the body from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveBrazeBody({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveBrazeBody({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveBrazeBody({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveBrazeBody({ body: "{}" }), BRAZE_FALLBACK_SUMMARY);
    assert.equal(
      resolveBrazeBody({ body: "{}", subject: "", key: "", traceId: "" }),
      BRAZE_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateBrazePayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateBrazePayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveBrazeNotification(record, {}), {
      subject: "order.created",
      body: "order.created",
    });
    assert.deepEqual(resolveBrazeNotification(record, { includePayload: true }), {
      subject: "order.created",
      body: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveBrazeNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { subject: "order.created", body: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveBrazeRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("braze-sink wire shape", () => {
  it("exposes the fixed Braze US-01 send endpoint", () => {
    assert.equal(BRAZE_SEND_URL, "https://rest.iad-01.braze.com/messages/send");
  });

  it("builds the external_user_ids + messages.email envelope — and no credential", () => {
    const parsed = JSON.parse(
      buildBrazeMessageBody(appId, from, externalUserIds, "order.created", "order.created")
    );
    assert.deepEqual(parsed, {
      external_user_ids: ["user-1", "user-2"],
      messages: {
        email: {
          app_id: "braze-app-123",
          subject: "order.created",
          body: "order.created",
          from: "alerts@example.com",
        },
      },
    });
    const body = buildBrazeMessageBody(appId, from, ["user-1"], "s", "b");
    assert.equal(body.includes("Authorization"), false);
    assert.equal(body.includes("Bearer"), false);
    assert.equal(body.includes("api_key"), false);
    assert.equal(body.includes("REST API key"), false);
  });
});

describe("braze-sink send", () => {
  it("posts one message per record to the fixed endpoint with the Braze envelope, no credential", async () => {
    const client = new FakeClient();
    const sink = new BrazeSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: BRAZE_SEND_URL,
      body: JSON.stringify({
        external_user_ids: externalUserIds,
        messages: {
          email: { app_id: appId, subject: "order.created", body: "order.created", from },
        },
      }),
    });
    assert.deepEqual(JSON.parse(client.posts[1].body).messages.email, {
      app_id: appId,
      subject: "agg-8",
      body: "agg-8",
      from,
    });
    // The trace id belongs in the body, never in the subject.
    assert.deepEqual(JSON.parse(client.posts[2].body).messages.email, {
      app_id: appId,
      subject: BRAZE_FALLBACK_SUMMARY,
      body: "t-9",
      from,
    });
    for (const post of client.posts) {
      assert.equal(post.body.includes("Authorization"), false);
      assert.equal(post.body.includes("Bearer"), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("applies the payload opt-in truncation on send", async () => {
    const client = new FakeClient();
    const sink = new BrazeSink(baseConfig(client, { includePayload: true, payloadMaxChars: 3 }));
    await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.equal(
      JSON.parse(client.posts[0].body).messages.email.body,
      `order.created\n\n{"a… (truncated)`
    );
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new BrazeSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof BrazeSinkError);
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
    const sink = new BrazeSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof BrazeSinkError);
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

  it("fails closed without a client, app id, sender, or recipient set", async () => {
    await assert.rejects(
      () => new BrazeSink({ appId, from, externalUserIds }).send([{ body: '{"a":1}' }]),
      BrazeSinkConfigError
    );
    await assert.rejects(
      () =>
        new BrazeSink(baseConfig(new FakeClient(), { appId: undefined })).send([
          { body: '{"a":1}' },
        ]),
      BrazeSinkConfigError
    );
    await assert.rejects(
      () =>
        new BrazeSink(baseConfig(new FakeClient(), { from: undefined })).send([
          { body: '{"a":1}' },
        ]),
      BrazeSinkConfigError
    );
    await assert.rejects(
      () =>
        new BrazeSink(baseConfig(new FakeClient(), { externalUserIds: undefined })).send([
          { body: '{"a":1}' },
        ]),
      BrazeSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new BrazeSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new BrazeSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new BrazeSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyBrazeRecordFailure(429), true);
    assert.equal(classifyBrazeRecordFailure(500), true);
    assert.equal(classifyBrazeRecordFailure(503), true);
    assert.equal(classifyBrazeRecordFailure(400), false);
    assert.equal(classifyBrazeRecordFailure(401), false);
    assert.equal(classifyBrazeRecordFailure(404), false);
    assert.equal(BRAZE_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
