import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  VonageSink,
  VonageSinkConfigError,
  VonageSinkError,
  assertValidVonageSinkConfig,
  buildVonageFormBody,
  classifyVonageRecordFailure,
  resolveVonageNotification,
  resolveVonageRecord,
  resolveVonageText,
  truncateVonagePayload,
  VONAGE_DEFAULT_PAYLOAD_MAX_CHARS,
  VONAGE_FALLBACK_SUMMARY,
  VONAGE_SMS_URL,
  type VonageMessageClient,
  type VonageMessagePostRequest,
  type VonageMessagePostResponse,
  type VonageSinkConfig,
} from "../src/vonage-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements VonageMessageClient {
  posts: VonageMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: VonageMessagePostRequest): Promise<VonageMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200 };
  }
}

const from = "14155550000";
const to = "14155551234";

function baseConfig(
  client: VonageMessageClient,
  extra: Partial<VonageSinkConfig> = {}
): VonageSinkConfig {
  return { from, to, client, ...extra };
}

describe("vonage-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidVonageSinkConfig(null, "VonageSink"), RangeError);
    assert.throws(() => assertValidVonageSinkConfig("x", "VonageSink"), RangeError);
  });

  it("rejects a malformed sender or recipient shape", () => {
    assert.throws(() => assertValidVonageSinkConfig({ from: "" }, "VonageSink"), RangeError);
    assert.throws(() => assertValidVonageSinkConfig({ from: "has space" }, "VonageSink"), RangeError);
    assert.throws(() => assertValidVonageSinkConfig({ to: "" }, "VonageSink"), RangeError);
    assert.throws(() => assertValidVonageSinkConfig({ to: "has space" }, "VonageSink"), RangeError);
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidVonageSinkConfig({ client: {} }, "VonageSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidVonageSinkConfig({ payloadMaxChars: 0 }, "VonageSink"), RangeError);
    assert.throws(() => assertValidVonageSinkConfig({ payloadMaxChars: 2.5 }, "VonageSink"), RangeError);
  });

  it("accepts a config with no sender or recipient yet (send-time config error)", () => {
    assert.doesNotThrow(() => new VonageSink({}));
  });
});

describe("vonage-sink text derivation", () => {
  it("prefers subject, then key, then traceId, then the fallback summary", () => {
    assert.equal(
      resolveVonageText({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveVonageText({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveVonageText({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveVonageText({ body: "{}" }), VONAGE_FALLBACK_SUMMARY);
    assert.equal(
      resolveVonageText({ body: "{}", subject: "", key: "", traceId: "" }),
      VONAGE_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateVonagePayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateVonagePayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveVonageNotification(record, {}), { text: "order.created" });
    assert.deepEqual(resolveVonageNotification(record, { includePayload: true }), {
      text: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveVonageNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { text: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveVonageRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("vonage-sink wire shape", () => {
  it("posts to the fixed Vonage SMS endpoint", () => {
    assert.equal(VONAGE_SMS_URL, "https://rest.nexmo.com/sms/json");
  });

  it("builds the form body with from, to, and text — and no credential", () => {
    assert.equal(
      buildVonageFormBody(from, to, "order.created"),
      `from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}&text=order.created`
    );
    // The API key and secret never appear in the sink's body:
    // the client alone holds them and prepends them on the wire.
    assert.equal(buildVonageFormBody(from, to, "x").includes("api_key"), false);
    assert.equal(buildVonageFormBody(from, to, "x").includes("api_secret"), false);
  });

  it("percent-encodes form values so text cannot break the form", () => {
    assert.equal(
      buildVonageFormBody(from, to, "a&b=c"),
      `from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}&text=${encodeURIComponent("a&b=c")}`
    );
  });
});

describe("vonage-sink send", () => {
  it("posts one message per record to the fixed endpoint with from, to, and text, no credential", async () => {
    const client = new FakeClient();
    const sink = new VonageSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    assert.deepEqual(client.posts[0], {
      url: VONAGE_SMS_URL,
      body: `from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}&text=order.created`,
    });
    assert.equal(client.posts[1].body.includes("text=agg-8"), true);
    // The request carries no credential anywhere: the key and
    // secret are held by the client alone.
    for (const post of client.posts) {
      assert.equal(post.body.includes("api_key"), false);
      assert.equal(post.body.includes("api_secret"), false);
    }
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new VonageSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof VonageSinkError);
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
    const sink = new VonageSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof VonageSinkError);
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

  it("fails closed without a client, sender, or recipient", async () => {
    await assert.rejects(
      () => new VonageSink({ from, to }).send([{ body: '{"a":1}' }]),
      VonageSinkConfigError
    );
    await assert.rejects(
      () => new VonageSink(baseConfig(new FakeClient(), { from: undefined })).send([{ body: '{"a":1}' }]),
      VonageSinkConfigError
    );
    await assert.rejects(
      () => new VonageSink(baseConfig(new FakeClient(), { to: undefined })).send([{ body: '{"a":1}' }]),
      VonageSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new VonageSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new VonageSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new VonageSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyVonageRecordFailure(429), true);
    assert.equal(classifyVonageRecordFailure(500), true);
    assert.equal(classifyVonageRecordFailure(503), true);
    assert.equal(classifyVonageRecordFailure(400), false);
    assert.equal(classifyVonageRecordFailure(401), false);
    assert.equal(classifyVonageRecordFailure(404), false);
    assert.equal(VONAGE_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
