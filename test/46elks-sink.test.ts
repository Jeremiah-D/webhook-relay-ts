import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  ElksSink,
  ElksSinkConfigError,
  ElksSinkError,
  assertValidElksSinkConfig,
  buildElksMessageBody,
  classifyElksRecordFailure,
  resolveElksContent,
  resolveElksMessage,
  resolveElksRecord,
  truncateElksPayload,
  ELKS_SEND_URL,
  ELKS_MAX_ALPHANUMERIC_SENDER_LENGTH,
  ELKS_DEFAULT_PAYLOAD_MAX_CHARS,
  ELKS_FALLBACK_SUMMARY,
  type ElksMessageClient,
  type ElksMessagePostRequest,
  type ElksMessagePostResponse,
  type ElksSinkConfig,
} from "../src/46elks-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements ElksMessageClient {
  posts: ElksMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: ElksMessagePostRequest): Promise<ElksMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200 };
  }
}

const from = "+46700000000";
const to = "+14155550100";

function baseConfig(
  client: ElksMessageClient,
  extra: Partial<ElksSinkConfig> = {}
): ElksSinkConfig {
  return { from, to, client, ...extra };
}

describe("46elks-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidElksSinkConfig(null, "ElksSink"), RangeError);
    assert.throws(() => assertValidElksSinkConfig("x", "ElksSink"), RangeError);
  });

  it("rejects a malformed sender shape", () => {
    assert.throws(() => assertValidElksSinkConfig({ from: "" }, "ElksSink"), RangeError);
    assert.throws(
      () => assertValidElksSinkConfig({ from: "has space" }, "ElksSink"),
      RangeError
    );
    assert.throws(() => assertValidElksSinkConfig({ from: 42 }, "ElksSink"), RangeError);
  });

  it("rejects an alphanumeric sender id longer than 11 characters, accepts an 11-char one", () => {
    assert.equal(ELKS_MAX_ALPHANUMERIC_SENDER_LENGTH, 11);
    assert.throws(
      () => assertValidElksSinkConfig({ from: "MySenderName" }, "ElksSink"),
      /at most 11 characters/
    );
    assert.doesNotThrow(() =>
      assertValidElksSinkConfig({ from: "MySenderNam" }, "ElksSink")
    );
    // A phone-number sender is not an alphanumeric sender id: no length cap applies.
    assert.doesNotThrow(() =>
      assertValidElksSinkConfig({ from: "+467000000001234" }, "ElksSink")
    );
  });

  it("rejects a malformed recipient shape", () => {
    assert.throws(() => assertValidElksSinkConfig({ to: "" }, "ElksSink"), RangeError);
    assert.throws(
      () => assertValidElksSinkConfig({ to: "has space" }, "ElksSink"),
      RangeError
    );
    assert.throws(() => assertValidElksSinkConfig({ to: 42 }, "ElksSink"), RangeError);
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidElksSinkConfig({ client: {} }, "ElksSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidElksSinkConfig({ payloadMaxChars: 0 }, "ElksSink"), RangeError);
    assert.throws(
      () => assertValidElksSinkConfig({ payloadMaxChars: 2.5 }, "ElksSink"),
      RangeError
    );
  });

  it("accepts a config with no sender or recipient yet (send-time config error)", () => {
    assert.doesNotThrow(() => new ElksSink({}));
  });
});

describe("46elks-sink content derivation", () => {
  it("derives content from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveElksContent({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveElksContent({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveElksContent({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveElksContent({ body: "{}" }), ELKS_FALLBACK_SUMMARY);
    assert.equal(
      resolveElksContent({ body: "{}", subject: "", key: "", traceId: "" }),
      ELKS_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateElksPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateElksPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveElksMessage(record, {}), { message: "order.created" });
    assert.deepEqual(resolveElksMessage(record, { includePayload: true }), {
      message: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveElksMessage(record, { includePayload: true, payloadMaxChars: 3 }),
      { message: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveElksRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("46elks-sink wire shape", () => {
  it("exposes the fixed 46elks SMS endpoint", () => {
    assert.equal(ELKS_SEND_URL, "https://api.46elks.com/a1/sms");
  });

  it("builds the form-encoded body with from, to, message — and no credential", () => {
    assert.equal(
      buildElksMessageBody(from, to, "order.created"),
      "from=%2B46700000000&to=%2B14155550100&message=order.created"
    );
    assert.equal(
      buildElksMessageBody("MySender", to, "hello world & friends"),
      "from=MySender&to=%2B14155550100&message=hello%20world%20%26%20friends"
    );
    const body = buildElksMessageBody(from, to, "x");
    assert.equal(body.includes("Authorization"), false);
    assert.equal(body.includes("Basic"), false);
    assert.equal(body.includes("password"), false);
    assert.equal(body.includes("username"), false);
  });
});

describe("46elks-sink send", () => {
  it("posts one message per record to the fixed endpoint with the form body, no credential", async () => {
    const client = new FakeClient();
    const sink = new ElksSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: ELKS_SEND_URL,
      body: "from=%2B46700000000&to=%2B14155550100&message=order.created",
    });
    assert.deepEqual(client.posts[1], {
      url: ELKS_SEND_URL,
      body: "from=%2B46700000000&to=%2B14155550100&message=agg-8",
    });
    assert.deepEqual(client.posts[2], {
      url: ELKS_SEND_URL,
      body: "from=%2B46700000000&to=%2B14155550100&message=t-9",
    });
    for (const post of client.posts) {
      assert.equal(post.body.includes("Authorization"), false);
      assert.equal(post.body.includes("Basic"), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("applies the payload opt-in truncation on send", async () => {
    const client = new FakeClient();
    const sink = new ElksSink(baseConfig(client, { includePayload: true, payloadMaxChars: 3 }));
    await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.equal(
      client.posts[0].body,
      `from=%2B46700000000&to=%2B14155550100&message=${encodeURIComponent(
        `order.created\n\n{"a… (truncated)`
      )}`
    );
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new ElksSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof ElksSinkError);
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
    const sink = new ElksSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof ElksSinkError);
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
      () => new ElksSink({ from, to }).send([{ body: '{"a":1}' }]),
      ElksSinkConfigError
    );
    await assert.rejects(
      () =>
        new ElksSink(baseConfig(new FakeClient(), { from: undefined })).send([
          { body: '{"a":1}' },
        ]),
      ElksSinkConfigError
    );
    await assert.rejects(
      () =>
        new ElksSink(baseConfig(new FakeClient(), { to: undefined })).send([
          { body: '{"a":1}' },
        ]),
      ElksSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new ElksSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new ElksSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new ElksSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyElksRecordFailure(429), true);
    assert.equal(classifyElksRecordFailure(500), true);
    assert.equal(classifyElksRecordFailure(503), true);
    assert.equal(classifyElksRecordFailure(400), false);
    assert.equal(classifyElksRecordFailure(401), false);
    assert.equal(classifyElksRecordFailure(404), false);
    assert.equal(ELKS_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
