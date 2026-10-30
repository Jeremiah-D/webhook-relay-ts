import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  ClickatellSink,
  ClickatellSinkConfigError,
  ClickatellSinkError,
  assertValidClickatellSinkConfig,
  buildClickatellMessageBody,
  classifyClickatellRecordFailure,
  resolveClickatellContent,
  resolveClickatellNotification,
  resolveClickatellRecord,
  truncateClickatellPayload,
  CLICKATELL_SEND_URL,
  CLICKATELL_DEFAULT_PAYLOAD_MAX_CHARS,
  CLICKATELL_FALLBACK_SUMMARY,
  type ClickatellMessageClient,
  type ClickatellMessagePostRequest,
  type ClickatellMessagePostResponse,
  type ClickatellSinkConfig,
} from "../src/clickatell-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements ClickatellMessageClient {
  posts: ClickatellMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: ClickatellMessagePostRequest): Promise<ClickatellMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200 };
  }
}

const to = ["+14155550100", "+14155550101"];

function baseConfig(
  client: ClickatellMessageClient,
  extra: Partial<ClickatellSinkConfig> = {}
): ClickatellSinkConfig {
  return { to, client, ...extra };
}

describe("clickatell-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidClickatellSinkConfig(null, "ClickatellSink"), RangeError);
    assert.throws(() => assertValidClickatellSinkConfig("x", "ClickatellSink"), RangeError);
  });

  it("rejects a malformed recipient set shape", () => {
    assert.throws(() => assertValidClickatellSinkConfig({ to: "x" }, "ClickatellSink"), RangeError);
    assert.throws(() => assertValidClickatellSinkConfig({ to: [] }, "ClickatellSink"), RangeError);
    assert.throws(() => assertValidClickatellSinkConfig({ to: [""] }, "ClickatellSink"), RangeError);
    assert.throws(
      () => assertValidClickatellSinkConfig({ to: ["has space"] }, "ClickatellSink"),
      RangeError
    );
    assert.throws(
      () => assertValidClickatellSinkConfig({ to: ["+14155550100", 42] }, "ClickatellSink"),
      RangeError
    );
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidClickatellSinkConfig({ client: {} }, "ClickatellSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidClickatellSinkConfig({ payloadMaxChars: 0 }, "ClickatellSink"), RangeError);
    assert.throws(() => assertValidClickatellSinkConfig({ payloadMaxChars: 2.5 }, "ClickatellSink"), RangeError);
  });

  it("accepts a config with no recipient set yet (send-time config error)", () => {
    assert.doesNotThrow(() => new ClickatellSink({}));
  });
});

describe("clickatell-sink content derivation", () => {
  it("derives the content from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveClickatellContent({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveClickatellContent({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveClickatellContent({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveClickatellContent({ body: "{}" }), CLICKATELL_FALLBACK_SUMMARY);
    assert.equal(
      resolveClickatellContent({ body: "{}", subject: "", key: "", traceId: "" }),
      CLICKATELL_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateClickatellPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateClickatellPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveClickatellNotification(record, {}), { content: "order.created" });
    assert.deepEqual(resolveClickatellNotification(record, { includePayload: true }), {
      content: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveClickatellNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { content: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveClickatellRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("clickatell-sink wire shape", () => {
  it("exposes the fixed Clickatell platform endpoint", () => {
    assert.equal(CLICKATELL_SEND_URL, "https://platform.clickatell.com/messages");
  });

  it("builds the flat JSON body with content and to — and no credential, no sender id", () => {
    assert.equal(
      buildClickatellMessageBody("order.created", to),
      JSON.stringify({ content: "order.created", to })
    );
    const body = buildClickatellMessageBody("x", to);
    assert.equal(body.includes("Bearer"), false);
    assert.equal(body.includes("Basic"), false);
    assert.equal(body.includes("Authorization"), false);
    assert.equal(body.includes("apiKey"), false);
    assert.equal(body.includes("password"), false);
    assert.equal(body.includes("from"), false);
    assert.equal(Object.keys(JSON.parse(body)).join(","), "content,to");
    assert.deepEqual(JSON.parse(body).to, to);
  });
});

describe("clickatell-sink send", () => {
  it("posts one message per record to the fixed platform endpoint with the JSON body, no credential", async () => {
    const client = new FakeClient();
    const sink = new ClickatellSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: CLICKATELL_SEND_URL,
      body: JSON.stringify({ content: "order.created", to }),
    });
    assert.deepEqual(JSON.parse(client.posts[1].body).content, "agg-8");
    assert.deepEqual(JSON.parse(client.posts[2].body).content, "t-9");
    for (const post of client.posts) {
      assert.equal(post.body.includes("Bearer"), false);
      assert.equal(post.body.includes("Authorization"), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("applies the payload opt-in truncation on send", async () => {
    const client = new FakeClient();
    const sink = new ClickatellSink(
      baseConfig(client, { includePayload: true, payloadMaxChars: 3 })
    );
    await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.equal(
      JSON.parse(client.posts[0].body).content,
      `order.created\n\n{"a… (truncated)`
    );
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new ClickatellSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof ClickatellSinkError);
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
    const sink = new ClickatellSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof ClickatellSinkError);
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

  it("fails closed without a client or recipient set", async () => {
    await assert.rejects(
      () => new ClickatellSink({ to }).send([{ body: '{"a":1}' }]),
      ClickatellSinkConfigError
    );
    await assert.rejects(
      () =>
        new ClickatellSink(baseConfig(new FakeClient(), { to: undefined })).send([
          { body: '{"a":1}' },
        ]),
      ClickatellSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new ClickatellSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new ClickatellSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new ClickatellSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies record failures directly", () => {
    assert.equal(classifyClickatellRecordFailure(429), true);
    assert.equal(classifyClickatellRecordFailure(500), true);
    assert.equal(classifyClickatellRecordFailure(503), true);
    assert.equal(classifyClickatellRecordFailure(400), false);
    assert.equal(classifyClickatellRecordFailure(401), false);
    assert.equal(CLICKATELL_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
