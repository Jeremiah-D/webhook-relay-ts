import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  SlackSink,
  SlackSinkConfigError,
  SlackSinkError,
  assertValidSlackSinkConfig,
  classifySlackRecordFailure,
  isValidSlackWebhookUrl,
  resolveSlackRecord,
  resolveSlackSummary,
  resolveSlackText,
  truncateSlackPayload,
  SLACK_DEFAULT_PAYLOAD_MAX_CHARS,
  SLACK_FALLBACK_SUMMARY,
  type SlackWebhookClient,
  type SlackWebhookPostRequest,
  type SlackWebhookPostResponse,
  type SlackSinkConfig,
} from "../src/slack-sink.ts";
import { classifyFailure } from "../src/failure.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements SlackWebhookClient {
  posts: SlackWebhookPostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: SlackWebhookPostRequest): Promise<SlackWebhookPostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200 };
  }
}

const hook = "https://hooks.slack.com/services/t000/b000/xxxx";

function baseConfig(
  client: SlackWebhookClient,
  extra: Partial<SlackSinkConfig> = {}
): SlackSinkConfig {
  return { webhookUrl: hook, client, ...extra };
}

describe("slack-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidSlackSinkConfig(null, "SlackSink"), RangeError);
    assert.throws(() => assertValidSlackSinkConfig("x", "SlackSink"), RangeError);
  });

  it("rejects a malformed webhook URL shape", () => {
    assert.throws(() => assertValidSlackSinkConfig({ webhookUrl: "" }, "SlackSink"), RangeError);
    assert.throws(
      () => assertValidSlackSinkConfig({ webhookUrl: "has space" }, "SlackSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSlackSinkConfig({ webhookUrl: "has\0nul" }, "SlackSink"),
      RangeError
    );
  });

  it("rejects a client without a post function", () => {
    assert.throws(
      () => assertValidSlackSinkConfig({ webhookUrl: hook, client: {} }, "SlackSink"),
      RangeError
    );
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(
      () => assertValidSlackSinkConfig({ webhookUrl: hook, payloadMaxChars: 0 }, "SlackSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSlackSinkConfig({ webhookUrl: hook, payloadMaxChars: 1.5 }, "SlackSink"),
      RangeError
    );
  });

  it("accepts a URL-less config (config error at send time instead)", () => {
    assertValidSlackSinkConfig({ client: new FakeClient() }, "SlackSink");
  });
});

describe("slack-sink webhook URL validity", () => {
  it("accepts a parseable https URL, including a proxied host", () => {
    assert.equal(isValidSlackWebhookUrl(hook), true);
    assert.equal(isValidSlackWebhookUrl("https://proxy.internal/slack-hook"), true);
  });

  it("rejects unparseable and non-https URLs", () => {
    assert.equal(isValidSlackWebhookUrl("not a url"), false);
    assert.equal(isValidSlackWebhookUrl("http://hooks.slack.com/services/x"), false);
    assert.equal(isValidSlackWebhookUrl(""), false);
  });
});

describe("slack-sink text derivation", () => {
  it("derives subject, then key, then traceId, then the generic fallback", () => {
    assert.equal(
      resolveSlackSummary({ body: "{}", subject: "s", key: "k", traceId: "t" }),
      "s"
    );
    assert.equal(resolveSlackSummary({ body: "{}", key: "k", traceId: "t" }), "k");
    assert.equal(resolveSlackSummary({ body: "{}", traceId: "t" }), "t");
    assert.equal(resolveSlackSummary({ body: "{}" }), SLACK_FALLBACK_SUMMARY);
  });

  it("skips empty sources in the chain", () => {
    assert.equal(
      resolveSlackSummary({ body: "{}", subject: "", key: "", traceId: "t" }),
      "t"
    );
  });

  it("carries the summary only by default, never the full payload", () => {
    assert.equal(
      resolveSlackText({ body: '{"secret":"pii"}', subject: "order.created" }, {}),
      "order.created"
    );
    assert.equal(
      resolveSlackText({ body: '{"secret":"pii"}', subject: "order.created" }, { includePayload: false }),
      "order.created"
    );
  });

  it("appends the body verbatim under the opt-in, inside a fenced block", () => {
    assert.equal(
      resolveSlackText({ body: '{"a":1}', subject: "order.created" }, { includePayload: true }),
      "order.created\n```\n{\"a\":1}\n```"
    );
  });

  it("truncates an opted-in payload at the default limit with a marker", () => {
    const body = "x".repeat(SLACK_DEFAULT_PAYLOAD_MAX_CHARS + 50);
    const text = resolveSlackText({ body, subject: "s" }, { includePayload: true });
    assert.equal(text, `s\n\`\`\`\n${"x".repeat(SLACK_DEFAULT_PAYLOAD_MAX_CHARS)}… (truncated)\n\`\`\``);
  });

  it("honors a custom payloadMaxChars", () => {
    assert.equal(
      truncateSlackPayload("abcdefgh", 3),
      "abc… (truncated)"
    );
    assert.equal(truncateSlackPayload("ab", 3), "ab");
  });

  it("fails closed on an empty body", () => {
    assert.throws(() => resolveSlackRecord({ body: "", subject: "s" }, 0, {}), RangeError);
  });
});

describe("slack-sink send", () => {
  it("posts one message per record to the configured URL with derived text and counts stats", async () => {
    const client = new FakeClient();
    const sink = new SlackSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created" },
      { body: '{"b":2}', key: "agg-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    assert.deepEqual(client.posts[0], { url: hook, text: "order.created" });
    assert.deepEqual(client.posts[1], { url: hook, text: "agg-9" });
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("dryRun validates with zero client I/O and zero stat changes", async () => {
    const client = new FakeClient();
    const sink = new SlackSink(baseConfig(client, { dryRun: true }));
    const result = await sink.send([{ body: "{}", subject: "s" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    // But a malformed record still fails closed in a dry run.
    await assert.rejects(() => sink.send([{ body: "" }]), RangeError);
  });

  it("throws a config error without a client, mapped to non_retryable", async () => {
    const sink = new SlackSink({ webhookUrl: hook });
    await assert.rejects(() => sink.send([{ body: "{}" }]), SlackSinkConfigError);
    assert.deepEqual(classifyFailure(new SlackSinkConfigError("no client")), {
      failureClass: "non_retryable",
    });
  });

  it("throws a config error for a missing webhook URL, mapped to non_retryable", async () => {
    const sink = new SlackSink({ client: new FakeClient() });
    await assert.rejects(() => sink.send([{ body: "{}" }]), SlackSinkConfigError);
    assert.deepEqual(classifyFailure(new SlackSinkConfigError("no url")), {
      failureClass: "non_retryable",
    });
  });

  it("throws a config error for an invalid webhook URL, mapped to non_retryable", async () => {
    const client = new FakeClient();
    const plain = new SlackSink({ webhookUrl: "http://hooks.slack.com/x", client });
    await assert.rejects(() => plain.send([{ body: "{}" }]), SlackSinkConfigError);
    const unparseable = new SlackSink({ webhookUrl: "://bad", client });
    await assert.rejects(() => unparseable.send([{ body: "{}" }]), SlackSinkConfigError);
    assert.equal(client.posts.length, 0);
  });

  it("maps 429 and 5xx to retryable and other non-2xx to non-retryable, keeping accepted messages out", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 429);
    client.statusOn.set(2, 503);
    client.statusOn.set(3, 404);
    const sink = new SlackSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([
          { body: "a", subject: "ok" },
          { body: "b", subject: "limited" },
          { body: "c", subject: "down" },
          { body: "d", subject: "unknown-hook" },
        ]),
      (err: unknown) => {
        assert.ok(err instanceof SlackSinkError);
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

  it("maps a 4xx unknown-webhook failure to fail-closed non-retryable", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 400);
    const sink = new SlackSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: "a", subject: "bad" }]),
      (err: unknown) => {
        assert.ok(err instanceof SlackSinkError);
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
    const sink = new SlackSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: "a" }, { body: "b" }]),
      (err: unknown) => {
        assert.ok(err instanceof SlackSinkError);
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

describe("slack-sink failure classification", () => {
  it("maps 429 and 5xx to retryable and every other non-2xx to non-retryable", () => {
    for (const status of [429, 500, 502, 503, 504]) {
      assert.equal(classifySlackRecordFailure(status), true, String(status));
    }
    for (const status of [400, 401, 403, 404, 409, 413]) {
      assert.equal(classifySlackRecordFailure(status), false, String(status));
    }
  });
});
