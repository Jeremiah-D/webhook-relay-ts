import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import {
  DingTalkSink,
  DingTalkSinkConfigError,
  DingTalkSinkError,
  assertValidDingTalkSinkConfig,
  buildDingTalkWebhookUrl,
  classifyDingTalkRecordFailure,
  computeDingTalkSign,
  isValidDingTalkWebhookUrl,
  resolveDingTalkRecord,
  resolveDingTalkSummary,
  resolveDingTalkText,
  truncateDingTalkPayload,
  DINGTALK_DEFAULT_PAYLOAD_MAX_CHARS,
  DINGTALK_FALLBACK_SUMMARY,
  type DingTalkWebhookClient,
  type DingTalkWebhookPostRequest,
  type DingTalkWebhookPostResponse,
  type DingTalkSinkConfig,
} from "../src/dingtalk-sink.ts";
import { classifyFailure } from "../src/failure.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements DingTalkWebhookClient {
  posts: DingTalkWebhookPostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: DingTalkWebhookPostRequest): Promise<DingTalkWebhookPostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200 };
  }
}

const hook = "https://oapi.dingtalk.com/robot/send";
const token = "test-access-token";

function baseConfig(
  client: DingTalkWebhookClient,
  extra: Partial<DingTalkSinkConfig> = {}
): DingTalkSinkConfig {
  return { webhookUrl: hook, accessToken: token, client, ...extra };
}

describe("dingtalk-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidDingTalkSinkConfig(null, "DingTalkSink"), RangeError);
    assert.throws(() => assertValidDingTalkSinkConfig("x", "DingTalkSink"), RangeError);
  });

  it("rejects a malformed webhook URL shape", () => {
    assert.throws(() => assertValidDingTalkSinkConfig({ webhookUrl: "" }, "DingTalkSink"), RangeError);
    assert.throws(
      () => assertValidDingTalkSinkConfig({ webhookUrl: "has space" }, "DingTalkSink"),
      RangeError
    );
    assert.throws(
      () => assertValidDingTalkSinkConfig({ webhookUrl: "has\0nul" }, "DingTalkSink"),
      RangeError
    );
  });

  it("rejects a malformed access token shape", () => {
    assert.throws(() => assertValidDingTalkSinkConfig({ accessToken: "" }, "DingTalkSink"), RangeError);
    assert.throws(
      () => assertValidDingTalkSinkConfig({ accessToken: "has space" }, "DingTalkSink"),
      RangeError
    );
  });

  it("rejects a malformed signing secret shape", () => {
    assert.throws(() => assertValidDingTalkSinkConfig({ signSecret: "" }, "DingTalkSink"), RangeError);
    assert.throws(
      () => assertValidDingTalkSinkConfig({ signSecret: "has space" }, "DingTalkSink"),
      RangeError
    );
  });

  it("rejects a client without a post function", () => {
    assert.throws(
      () => assertValidDingTalkSinkConfig({ webhookUrl: hook, client: {} }, "DingTalkSink"),
      RangeError
    );
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(
      () => assertValidDingTalkSinkConfig({ webhookUrl: hook, payloadMaxChars: 0 }, "DingTalkSink"),
      RangeError
    );
  });
});

describe("dingtalk-sink webhook URL validity", () => {
  it("accepts https URLs and rejects http and unparseable URLs", () => {
    assert.equal(isValidDingTalkWebhookUrl(hook), true);
    assert.equal(isValidDingTalkWebhookUrl("http://oapi.dingtalk.com/robot/send"), false);
    assert.equal(isValidDingTalkWebhookUrl("://bad"), false);
  });
});

describe("dingtalk-sink signing", () => {
  it("computes the documented HMAC-SHA256 signature bytes", () => {
    // Independent recomputation: the sink's sign must be exactly
    // base64(HMAC-SHA256(secret, "<timestamp>\\n<secret>")).
    const secret = "sign-secret";
    const timestamp = 1_700_000_000_000;
    const expected = createHmac("sha256", secret)
      .update(`${timestamp}\n${secret}`, "utf8")
      .digest("base64");
    assert.equal(computeDingTalkSign(secret, timestamp), expected);
  });

  it("appends access_token, and timestamp + sign only when signed", () => {
    const unsigned = buildDingTalkWebhookUrl(hook, token, undefined, 1_700_000_000_000);
    assert.equal(unsigned, `${hook}?access_token=${token}`);
    const secret = "sign-secret";
    const signed = buildDingTalkWebhookUrl(hook, token, secret, 1_700_000_000_000);
    const url = new URL(signed);
    assert.equal(url.searchParams.get("access_token"), token);
    assert.equal(url.searchParams.get("timestamp"), "1700000000000");
    assert.equal(url.searchParams.get("sign"), computeDingTalkSign(secret, 1_700_000_000_000));
  });

  it("uses & when the base URL already carries a query string", () => {
    const withQuery = `${hook}?debug=1`;
    const built = buildDingTalkWebhookUrl(withQuery, token, undefined, 1_700_000_000_000);
    assert.equal(built, `${withQuery}&access_token=${token}`);
  });

  it("URL-encodes a token with reserved characters", () => {
    const built = buildDingTalkWebhookUrl(hook, "a+b/c=d", undefined, 1_700_000_000_000);
    assert.equal(built, `${hook}?access_token=a%2Bb%2Fc%3Dd`);
  });
});

describe("dingtalk-sink text derivation", () => {
  it("prefers subject, then key, then traceId, then the fallback summary", () => {
    assert.equal(resolveDingTalkSummary({ body: "{}", subject: "s", key: "k", traceId: "t" }), "s");
    assert.equal(resolveDingTalkSummary({ body: "{}", key: "k", traceId: "t" }), "k");
    assert.equal(resolveDingTalkSummary({ body: "{}", traceId: "t" }), "t");
    assert.equal(resolveDingTalkSummary({ body: "{}" }), DINGTALK_FALLBACK_SUMMARY);
    assert.equal(resolveDingTalkSummary({ body: "{}", subject: "" }), DINGTALK_FALLBACK_SUMMARY);
  });

  it("carries the summary only by default, never the payload", () => {
    assert.equal(
      resolveDingTalkText({ body: '{"secret":"x"}', subject: "order.created" }, {}),
      "order.created"
    );
  });

  it("appends an opted-in payload verbatim inside a fenced block, truncated", () => {
    const long = "x".repeat(DINGTALK_DEFAULT_PAYLOAD_MAX_CHARS + 10);
    const text = resolveDingTalkText(
      { body: long, subject: "s" },
      { includePayload: true }
    );
    assert.equal(
      text,
      `s\n\`\`\`\n${"x".repeat(DINGTALK_DEFAULT_PAYLOAD_MAX_CHARS)}… (truncated)\n\`\`\``
    );
    const short = resolveDingTalkText(
      { body: "{}", subject: "s" },
      { includePayload: true, payloadMaxChars: 10 }
    );
    assert.equal(short, "s\n```\n{}\n```");
  });

  it("rejects an empty body", () => {
    assert.throws(() => resolveDingTalkRecord({ body: "" }, 0, {}), RangeError);
  });
});

describe("dingtalk-sink send", () => {
  it("posts one message per record to the token URL with derived text and counts stats", async () => {
    const client = new FakeClient();
    const sink = new DingTalkSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created" },
      { body: '{"b":2}', key: "agg-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    assert.deepEqual(client.posts[0], {
      url: `${hook}?access_token=${token}`,
      text: "order.created",
    });
    assert.deepEqual(client.posts[1], {
      url: `${hook}?access_token=${token}`,
      text: "agg-9",
    });
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("signs the URL when a signing secret is configured", async () => {
    const client = new FakeClient();
    const secret = "sign-secret";
    const sink = new DingTalkSink(baseConfig(client, { signSecret: secret }));
    await sink.send([{ body: "{}", subject: "s" }]);
    assert.equal(client.posts.length, 1);
    const url = new URL(client.posts[0].url);
    assert.equal(url.searchParams.get("access_token"), token);
    const timestamp = Number(url.searchParams.get("timestamp"));
    assert.ok(Number.isInteger(timestamp) && timestamp > 0);
    assert.equal(url.searchParams.get("sign"), computeDingTalkSign(secret, timestamp));
    assert.equal(client.posts[0].text, "s");
  });

  it("dryRun validates with zero client I/O and zero stat changes", async () => {
    const client = new FakeClient();
    const sink = new DingTalkSink(baseConfig(client, { dryRun: true }));
    const result = await sink.send([{ body: "{}", subject: "s" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    // But a malformed record still fails closed in a dry run.
    await assert.rejects(() => sink.send([{ body: "" }]), RangeError);
    // And a dry run needs no client, URL, or token at all.
    const bare = new DingTalkSink({ dryRun: true });
    assert.deepEqual(await bare.send([{ body: "{}" }]), { ok: true, sent: 0, dryRun: true });
  });

  it("throws a config error without a client, mapped to non_retryable", async () => {
    const sink = new DingTalkSink({ webhookUrl: hook, accessToken: token });
    await assert.rejects(() => sink.send([{ body: "{}" }]), DingTalkSinkConfigError);
    assert.deepEqual(classifyFailure(new DingTalkSinkConfigError("no client")), {
      failureClass: "non_retryable",
    });
  });

  it("throws a config error for a missing webhook URL, mapped to non_retryable", async () => {
    const sink = new DingTalkSink({ accessToken: token, client: new FakeClient() });
    await assert.rejects(() => sink.send([{ body: "{}" }]), DingTalkSinkConfigError);
  });

  it("throws a config error for a missing access token, mapped to non_retryable", async () => {
    const sink = new DingTalkSink({ webhookUrl: hook, client: new FakeClient() });
    await assert.rejects(() => sink.send([{ body: "{}" }]), DingTalkSinkConfigError);
    assert.deepEqual(classifyFailure(new DingTalkSinkConfigError("no token")), {
      failureClass: "non_retryable",
    });
  });

  it("throws a config error for an invalid webhook URL, mapped to non_retryable", async () => {
    const client = new FakeClient();
    const plain = new DingTalkSink({
      webhookUrl: "http://oapi.dingtalk.com/robot/send",
      accessToken: token,
      client,
    });
    await assert.rejects(() => plain.send([{ body: "{}" }]), DingTalkSinkConfigError);
    const unparseable = new DingTalkSink({ webhookUrl: "://bad", accessToken: token, client });
    await assert.rejects(() => unparseable.send([{ body: "{}" }]), DingTalkSinkConfigError);
    assert.equal(client.posts.length, 0);
  });

  it("maps 429 and 5xx to retryable and other non-2xx to non-retryable, keeping accepted messages out", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 429);
    client.statusOn.set(2, 503);
    client.statusOn.set(3, 404);
    const sink = new DingTalkSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([
          { body: "a", subject: "ok" },
          { body: "b", subject: "limited" },
          { body: "c", subject: "down" },
          { body: "d", subject: "unknown-hook" },
        ]),
      (err: unknown) => {
        assert.ok(err instanceof DingTalkSinkError);
        assert.deepEqual(
          err.failedRecords.map((r) => [r.index, r.errorCode, r.statusCode, r.retryable]),
          [
            [1, "HTTP_429", 429, true],
            [2, "HTTP_503", 503, true],
            [3, "HTTP_404", 404, false],
          ]
        );
        return true;
      }
    );
    // The accepted message is not in the failure list; stats stay honest.
    assert.deepEqual(sink.stats, { sent: 1, failed: 3, sendFailures: 1 });
  });

  it("maps a 4xx unknown-robot failure to fail-closed non-retryable", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 400);
    const sink = new DingTalkSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: "a", subject: "bad" }]),
      (err: unknown) => {
        assert.ok(err instanceof DingTalkSinkError);
        assert.deepEqual(
          err.failedRecords.map((r) => [r.index, r.errorCode, r.retryable]),
          [[0, "HTTP_400", false]]
        );
        return true;
      }
    );
  });

  it("maps a codeless transport failure to retryable TRANSPORT_ERROR", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hangup"));
    client.failOn.set(1, new Error("socket hangup"));
    const sink = new DingTalkSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: "a" }, { body: "b" }]),
      (err: unknown) => {
        assert.ok(err instanceof DingTalkSinkError);
        assert.deepEqual(
          err.failedRecords.map((r) => [r.index, r.errorCode, r.retryable]),
          [
            [0, "TRANSPORT_ERROR", true],
            [1, "TRANSPORT_ERROR", true],
          ]
        );
        return true;
      }
    );
  });
});

describe("dingtalk-sink failure classification", () => {
  it("maps 429 and 5xx to retryable and every other non-2xx to non-retryable", () => {
    for (const status of [429, 500, 502, 503, 504]) {
      assert.equal(classifyDingTalkRecordFailure(status), true, String(status));
    }
    for (const status of [400, 401, 403, 404, 409, 413]) {
      assert.equal(classifyDingTalkRecordFailure(status), false, String(status));
    }
  });
});
