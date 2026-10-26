import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import {
  FeishuSink,
  FeishuSinkConfigError,
  FeishuSinkError,
  assertValidFeishuSinkConfig,
  classifyFeishuRecordFailure,
  computeFeishuSign,
  isValidFeishuWebhookUrl,
  resolveFeishuRecord,
  resolveFeishuSummary,
  resolveFeishuText,
  truncateFeishuPayload,
  FEISHU_DEFAULT_PAYLOAD_MAX_CHARS,
  FEISHU_FALLBACK_SUMMARY,
  type FeishuWebhookClient,
  type FeishuWebhookPostRequest,
  type FeishuWebhookPostResponse,
  type FeishuSinkConfig,
} from "../src/feishu-sink.ts";
import { classifyFailure } from "../src/failure.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements FeishuWebhookClient {
  posts: FeishuWebhookPostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: FeishuWebhookPostRequest): Promise<FeishuWebhookPostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200 };
  }
}

const hook = "https://open.feishu.cn/open-apis/bot/v2/hook/test-webhook-id";
const signKey = "test-sign-key";

function baseConfig(
  client: FeishuWebhookClient,
  extra: Partial<FeishuSinkConfig> = {}
): FeishuSinkConfig {
  return { webhookUrl: hook, client, ...extra };
}

describe("feishu-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidFeishuSinkConfig(null, "FeishuSink"), RangeError);
    assert.throws(() => assertValidFeishuSinkConfig("x", "FeishuSink"), RangeError);
  });

  it("rejects a malformed webhook URL shape", () => {
    assert.throws(() => assertValidFeishuSinkConfig({ webhookUrl: "" }, "FeishuSink"), RangeError);
    assert.throws(
      () => assertValidFeishuSinkConfig({ webhookUrl: "has space" }, "FeishuSink"),
      RangeError
    );
    assert.throws(
      () => assertValidFeishuSinkConfig({ webhookUrl: "has\0nul" }, "FeishuSink"),
      RangeError
    );
  });

  it("rejects a malformed signing secret shape", () => {
    assert.throws(() => assertValidFeishuSinkConfig({ signSecret: "" }, "FeishuSink"), RangeError);
    assert.throws(
      () => assertValidFeishuSinkConfig({ signSecret: "has space" }, "FeishuSink"),
      RangeError
    );
  });

  it("rejects a client without a post function", () => {
    assert.throws(
      () => assertValidFeishuSinkConfig({ client: {} }, "FeishuSink"),
      RangeError
    );
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(
      () => assertValidFeishuSinkConfig({ payloadMaxChars: 0 }, "FeishuSink"),
      RangeError
    );
    assert.throws(
      () => assertValidFeishuSinkConfig({ payloadMaxChars: 1.5 }, "FeishuSink"),
      RangeError
    );
  });

  it("accepts a minimal config with no URL, secret, or client", () => {
    assert.doesNotThrow(() => assertValidFeishuSinkConfig({}, "FeishuSink"));
  });
});

describe("feishu-sink URL validation", () => {
  it("accepts a parseable https URL", () => {
    assert.equal(isValidFeishuWebhookUrl(hook), true);
  });

  it("rejects plaintext and unparseable URLs", () => {
    assert.equal(isValidFeishuWebhookUrl("http://open.feishu.cn/x"), false);
    assert.equal(isValidFeishuWebhookUrl("not a url"), false);
  });
});

describe("feishu-sink signature", () => {
  it("matches an independently computed HMAC-SHA256 over timestamp-newline-secret", () => {
    const timestamp = 1761500000;
    const expected = createHmac("sha256", signKey)
      .update(`${timestamp}\n${signKey}`, "utf8")
      .digest("base64");
    assert.equal(computeFeishuSign(signKey, timestamp), expected);
  });

  it("differs from the millisecond-timestamp value: Feishu counts seconds", () => {
    const seconds = 1761500000;
    assert.notEqual(computeFeishuSign(signKey, seconds), computeFeishuSign(signKey, seconds * 1000));
  });
});

describe("feishu-sink text derivation", () => {
  it("prefers subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveFeishuSummary({ body: "{}", subject: "s", key: "k", traceId: "t" }),
      "s"
    );
    assert.equal(resolveFeishuSummary({ body: "{}", key: "k", traceId: "t" }), "k");
    assert.equal(resolveFeishuSummary({ body: "{}", traceId: "t" }), "t");
    assert.equal(resolveFeishuSummary({ body: "{}" }), FEISHU_FALLBACK_SUMMARY);
  });

  it("skips empty derivation sources", () => {
    assert.equal(
      resolveFeishuSummary({ body: "{}", subject: "", key: "k" }),
      "k"
    );
  });

  it("rejects an empty body", () => {
    assert.throws(() => resolveFeishuRecord({ body: "" }, 0, {}), RangeError);
  });

  it("carries the summary only by default", () => {
    assert.equal(
      resolveFeishuText({ body: '{"a":1}', subject: "order.created" }, {}),
      "order.created"
    );
  });

  it("appends an opted-in payload inside a fenced block", () => {
    assert.equal(
      resolveFeishuText({ body: '{"a":1}', subject: "order.created" }, { includePayload: true }),
      "order.created\n```\n{\"a\":1}\n```"
    );
  });

  it("truncates an opted-in payload at the default limit with a marker", () => {
    const long = "x".repeat(FEISHU_DEFAULT_PAYLOAD_MAX_CHARS + 50);
    const text = resolveFeishuText({ body: long, subject: "s" }, { includePayload: true });
    assert.ok(text.endsWith("… (truncated)\n```"));
    assert.ok(text.length < long.length + 100);
  });

  it("honours a custom payloadMaxChars", () => {
    assert.equal(truncateFeishuPayload("abcdef", 3), "abc… (truncated)");
    assert.equal(truncateFeishuPayload("ab", 3), "ab");
  });
});

describe("feishu-sink send", () => {
  it("posts the configured URL verbatim with the derived text, unsigned", async () => {
    const client = new FakeClient();
    const sink = new FeishuSink(baseConfig(client));
    const result = await sink.send([
      { body: "{}", subject: "order.created" },
      { body: "{}", traceId: "trace-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    assert.equal(client.posts[0].url, hook);
    assert.equal(client.posts[0].text, "order.created");
    assert.equal(client.posts[0].timestamp, undefined);
    assert.equal(client.posts[0].sign, undefined);
    assert.equal(client.posts[1].text, "trace-9");
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("signs every message of a send with one seconds timestamp", async () => {
    const client = new FakeClient();
    const sink = new FeishuSink(baseConfig(client, { signSecret: signKey }));
    await sink.send([{ body: "{}" }, { body: "{}" }]);
    assert.equal(client.posts.length, 2);
    const [first, second] = client.posts;
    assert.ok(first.timestamp !== undefined && /^\d{10}$/.test(first.timestamp));
    assert.equal(second.timestamp, first.timestamp);
    assert.equal(
      first.sign,
      createHmac("sha256", signKey).update(`${first.timestamp}\n${signKey}`, "utf8").digest("base64")
    );
    assert.equal(second.sign, first.sign);
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    client.statusOn.set(3, 404);
    const sink = new FeishuSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}" }, { body: "{}" }, { body: "{}" }, { body: "{}" }]),
      (err: unknown) => {
        assert.ok(err instanceof FeishuSinkError);
        assert.deepEqual(
          err.failedRecords.map((r) => [r.index, r.errorCode, r.retryable]),
          [
            [0, "HTTP_429", true],
            [1, "HTTP_503", true],
            [2, "HTTP_400", false],
            [3, "HTTP_404", false],
          ]
        );
        return true;
      }
    );
    assert.deepEqual(sink.stats, { sent: 0, failed: 4, sendFailures: 1 });
  });

  it("keeps partial success out of failedRecords", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 500);
    const sink = new FeishuSink(baseConfig(client));
    await assert.rejects(sink.send([{ body: "{}" }, { body: "{}" }]), (err: unknown) => {
      assert.ok(err instanceof FeishuSinkError);
      assert.deepEqual(
        err.failedRecords.map((r) => r.index),
        [1]
      );
      return true;
    });
    assert.deepEqual(sink.stats, { sent: 1, failed: 1, sendFailures: 1 });
  });

  it("treats a client throw as a retryable transport failure", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hangup"));
    const sink = new FeishuSink(baseConfig(client));
    await assert.rejects(sink.send([{ body: "{}" }]), (err: unknown) => {
      assert.ok(err instanceof FeishuSinkError);
      assert.deepEqual(err.failedRecords, [
        { index: 0, errorCode: "TRANSPORT_ERROR", retryable: true, errorMessage: "socket hangup" },
      ]);
      return true;
    });
  });

  it("fails closed without a client, URL, or valid URL", async () => {
    await assert.rejects(
      new FeishuSink({ webhookUrl: hook }).send([{ body: "{}" }]),
      FeishuSinkConfigError
    );
    await assert.rejects(
      new FeishuSink({ client: new FakeClient() }).send([{ body: "{}" }]),
      FeishuSinkConfigError
    );
    await assert.rejects(
      new FeishuSink(baseConfig(new FakeClient(), { webhookUrl: "http://plain/x" })).send([
        { body: "{}" },
      ]),
      FeishuSinkConfigError
    );
  });

  it("maps the config error to non_retryable under the WR-116 rule", async () => {
    await assert.rejects(
      new FeishuSink({ webhookUrl: hook }).send([{ body: "{}" }]),
      (err: unknown) => {
        assert.deepEqual(classifyFailure(err), { failureClass: "non_retryable" });
        return true;
      }
    );
  });

  it("dryRun validates with zero client I/O and no stat changes", async () => {
    const client = new FakeClient();
    const sink = new FeishuSink({ dryRun: true, client });
    const result = await sink.send([{ body: "{}", subject: "s" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(sink.send([{ body: "" }]), RangeError);
  });

  it("dryRun needs neither URL nor client", async () => {
    const result = await new FeishuSink({ dryRun: true }).send([{ body: "{}" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
  });
});

describe("feishu-sink failure classification", () => {
  it("classifies 429 and 5xx retryable, the rest not", () => {
    assert.equal(classifyFeishuRecordFailure(429), true);
    assert.equal(classifyFeishuRecordFailure(500), true);
    assert.equal(classifyFeishuRecordFailure(503), true);
    assert.equal(classifyFeishuRecordFailure(400), false);
    assert.equal(classifyFeishuRecordFailure(404), false);
  });
});
