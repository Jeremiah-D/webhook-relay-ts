import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  TelnyxSink,
  TelnyxSinkConfigError,
  TelnyxSinkError,
  assertValidTelnyxSinkConfig,
  buildTelnyxMessageBody,
  classifyTelnyxRecordFailure,
  resolveTelnyxText,
  resolveTelnyxNotification,
  resolveTelnyxRecord,
  truncateTelnyxPayload,
  TELNYX_SEND_URL,
  TELNYX_DEFAULT_PAYLOAD_MAX_CHARS,
  TELNYX_FALLBACK_SUMMARY,
  type TelnyxMessageClient,
  type TelnyxMessagePostRequest,
  type TelnyxMessagePostResponse,
  type TelnyxSinkConfig,
} from "../src/telnyx-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements TelnyxMessageClient {
  posts: TelnyxMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: TelnyxMessagePostRequest): Promise<TelnyxMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 201 };
  }
}

const from = "+14155550100";
const to = "+14155550101";

function baseConfig(
  client: TelnyxMessageClient,
  extra: Partial<TelnyxSinkConfig> = {}
): TelnyxSinkConfig {
  return { from, to, client, ...extra };
}

describe("telnyx-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidTelnyxSinkConfig(null, "TelnyxSink"), RangeError);
    assert.throws(() => assertValidTelnyxSinkConfig("x", "TelnyxSink"), RangeError);
  });

  it("rejects a malformed sender or recipient shape", () => {
    assert.throws(() => assertValidTelnyxSinkConfig({ from: "" }, "TelnyxSink"), RangeError);
    assert.throws(() => assertValidTelnyxSinkConfig({ from: "has space" }, "TelnyxSink"), RangeError);
    assert.throws(() => assertValidTelnyxSinkConfig({ to: "" }, "TelnyxSink"), RangeError);
    assert.throws(() => assertValidTelnyxSinkConfig({ to: "has space" }, "TelnyxSink"), RangeError);
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidTelnyxSinkConfig({ client: {} }, "TelnyxSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidTelnyxSinkConfig({ payloadMaxChars: 0 }, "TelnyxSink"), RangeError);
    assert.throws(() => assertValidTelnyxSinkConfig({ payloadMaxChars: 2.5 }, "TelnyxSink"), RangeError);
  });

  it("accepts a config with no sender or recipient yet (send-time config error)", () => {
    assert.doesNotThrow(() => new TelnyxSink({}));
  });
});

describe("telnyx-sink text derivation", () => {
  it("derives the text from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveTelnyxText({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveTelnyxText({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveTelnyxText({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveTelnyxText({ body: "{}" }), TELNYX_FALLBACK_SUMMARY);
    assert.equal(
      resolveTelnyxText({ body: "{}", subject: "", key: "", traceId: "" }),
      TELNYX_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateTelnyxPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateTelnyxPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveTelnyxNotification(record, {}), { text: "order.created" });
    assert.deepEqual(resolveTelnyxNotification(record, { includePayload: true }), {
      text: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveTelnyxNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { text: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveTelnyxRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("telnyx-sink wire shape", () => {
  it("exposes the fixed Telnyx messages endpoint", () => {
    assert.equal(TELNYX_SEND_URL, "https://api.telnyx.com/v2/messages");
  });

  it("builds the JSON body with from, to string, and text — and no credential", () => {
    assert.equal(
      buildTelnyxMessageBody(from, to, "order.created"),
      JSON.stringify({ from, to, text: "order.created" })
    );
    const body = buildTelnyxMessageBody(from, to, "x");
    assert.equal(body.includes("Bearer"), false);
    assert.equal(body.includes("password"), false);
    assert.equal(Object.keys(JSON.parse(body)).join(","), "from,to,text");
  });
});

describe("telnyx-sink send", () => {
  it("posts one message per record to the fixed messages endpoint with the JSON body, no credential", async () => {
    const client = new FakeClient();
    const sink = new TelnyxSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: TELNYX_SEND_URL,
      body: JSON.stringify({ from, to, text: "order.created" }),
    });
    assert.deepEqual(JSON.parse(client.posts[1].body).text, "agg-8");
    assert.deepEqual(JSON.parse(client.posts[2].body).text, "t-9");
    for (const post of client.posts) {
      assert.equal(post.body.includes("Bearer"), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("applies the payload opt-in truncation on send", async () => {
    const client = new FakeClient();
    const sink = new TelnyxSink(
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
    const sink = new TelnyxSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof TelnyxSinkError);
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
    const sink = new TelnyxSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof TelnyxSinkError);
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
      () =>
        new TelnyxSink({ from, to }).send([{ body: '{"a":1}' }]),
      TelnyxSinkConfigError
    );
    await assert.rejects(
      () =>
        new TelnyxSink(baseConfig(new FakeClient(), { from: undefined })).send([
          { body: '{"a":1}' },
        ]),
      TelnyxSinkConfigError
    );
    await assert.rejects(
      () =>
        new TelnyxSink(baseConfig(new FakeClient(), { to: undefined })).send([
          { body: '{"a":1}' },
        ]),
      TelnyxSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new TelnyxSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new TelnyxSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new TelnyxSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyTelnyxRecordFailure(429), true);
    assert.equal(classifyTelnyxRecordFailure(500), true);
    assert.equal(classifyTelnyxRecordFailure(503), true);
    assert.equal(classifyTelnyxRecordFailure(400), false);
    assert.equal(classifyTelnyxRecordFailure(401), false);
    assert.equal(classifyTelnyxRecordFailure(404), false);
    assert.equal(TELNYX_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
