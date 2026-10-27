import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  NtfySink,
  NtfySinkConfigError,
  NtfySinkError,
  assertValidNtfySinkConfig,
  classifyNtfyRecordFailure,
  isValidNtfyTopicUrl,
  resolveNtfyRecord,
  resolveNtfySummary,
  resolveNtfyText,
  truncateNtfyPayload,
  NTFY_DEFAULT_PAYLOAD_MAX_CHARS,
  NTFY_FALLBACK_SUMMARY,
  type NtfyTopicClient,
  type NtfyTopicPostRequest,
  type NtfyTopicPostResponse,
  type NtfySinkConfig,
} from "../src/ntfy-sink.ts";
import { classifyFailure } from "../src/failure.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements NtfyTopicClient {
  posts: NtfyTopicPostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: NtfyTopicPostRequest): Promise<NtfyTopicPostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200 };
  }
}

const topic = "https://ntfy.sh/relay-alerts";

function baseConfig(
  client: NtfyTopicClient,
  extra: Partial<NtfySinkConfig> = {}
): NtfySinkConfig {
  return { topicUrl: topic, client, ...extra };
}

describe("ntfy-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidNtfySinkConfig(null, "NtfySink"), RangeError);
    assert.throws(() => assertValidNtfySinkConfig("x", "NtfySink"), RangeError);
  });

  it("rejects a malformed topic URL shape", () => {
    assert.throws(() => assertValidNtfySinkConfig({ topicUrl: "" }, "NtfySink"), RangeError);
    assert.throws(
      () => assertValidNtfySinkConfig({ topicUrl: "has space" }, "NtfySink"),
      RangeError
    );
    assert.throws(
      () => assertValidNtfySinkConfig({ topicUrl: "has\0nul" }, "NtfySink"),
      RangeError
    );
    assert.throws(
      () => assertValidNtfySinkConfig({ topicUrl: 123 }, "NtfySink"),
      RangeError
    );
  });

  it("accepts a missing topic URL at construction (send-time config error)", () => {
    assert.doesNotThrow(() => assertValidNtfySinkConfig({}, "NtfySink"));
    assert.doesNotThrow(() => assertValidNtfySinkConfig({ topicUrl: topic }, "NtfySink"));
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidNtfySinkConfig({ client: {} }, "NtfySink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(
      () => assertValidNtfySinkConfig({ payloadMaxChars: 0 }, "NtfySink"),
      RangeError
    );
    assert.throws(
      () => assertValidNtfySinkConfig({ payloadMaxChars: 1.5 }, "NtfySink"),
      RangeError
    );
  });

  it("accepts https URLs and rejects http or unparseable URLs at send time", () => {
    assert.equal(isValidNtfyTopicUrl(topic), true);
    assert.equal(isValidNtfyTopicUrl("https://ntfy.example.com/ops"), true);
    assert.equal(isValidNtfyTopicUrl("http://ntfy.sh/relay-alerts"), false);
    assert.equal(isValidNtfyTopicUrl("not a url"), false);
    assert.equal(isValidNtfyTopicUrl(""), false);
  });
});

describe("ntfy-sink text derivation", () => {
  it("prefers subject, then key, then traceId", () => {
    assert.equal(
      resolveNtfySummary({ body: "{}", subject: "s", key: "k", traceId: "t" }),
      "s"
    );
    assert.equal(resolveNtfySummary({ body: "{}", key: "k", traceId: "t" }), "k");
    assert.equal(resolveNtfySummary({ body: "{}", traceId: "t" }), "t");
    assert.equal(resolveNtfySummary({ body: "{}", subject: "" }), NTFY_FALLBACK_SUMMARY);
  });

  it("falls back to the generic summary for sourceless events", () => {
    assert.equal(resolveNtfySummary({ body: "{}" }), "webhook event");
    assert.equal(NTFY_FALLBACK_SUMMARY, "webhook event");
  });

  it("carries the summary only by default, never the payload", () => {
    const text = resolveNtfyText(
      { body: '{"card":"4111"}', subject: "order.created" },
      {}
    );
    assert.equal(text, "order.created");
    assert.ok(!text.includes("4111"), "payload must not leak by default");
  });

  it("appends the payload as plain text under the opt-in, truncated with a marker", () => {
    const text = resolveNtfyText(
      { body: "x".repeat(50), subject: "s" },
      { includePayload: true, payloadMaxChars: 10 }
    );
    assert.equal(text, "s\n\nxxxxxxxxxx… (truncated)");
    assert.equal(NTFY_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });

  it("does not truncate a short opted-in payload", () => {
    assert.equal(truncateNtfyPayload("short", 2000), "short");
    const text = resolveNtfyText(
      { body: '{"a":1}', subject: "s" },
      { includePayload: true }
    );
    assert.equal(text, 's\n\n{"a":1}');
  });

  it("rejects an empty body even without the opt-in", () => {
    assert.throws(() => resolveNtfyRecord({ body: "" }, 0, {}), RangeError);
    assert.throws(() => resolveNtfyRecord({ body: "" }, 2, {}), /record 2/);
  });
});

describe("ntfy-sink send", () => {
  it("posts one plain-text message per record to the configured topic URL verbatim", async () => {
    const client = new FakeClient();
    const sink = new NtfySink(baseConfig(client));
    const result = await sink.send([
      { body: "{}", subject: "order.created" },
      { body: "{}", key: "agg-7" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    assert.deepEqual(client.posts[0], { url: topic, body: "order.created" });
    assert.deepEqual(client.posts[1], { url: topic, body: "agg-7" });
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("carries only url + body in the client request, never a JSON envelope or header override", async () => {
    // No token is ever appended or extracted, and no title, tag,
    // or priority header is ever set: the request the client
    // receives is the opaque topic URL plus the plain-text body,
    // and the subscription on the server decides presentation.
    // The body is raw text, not a JSON envelope: a client that
    // JSON-wrapped it would deliver literal quotes and braces
    // to the subscriber's screen.
    const client = new FakeClient();
    const sink = new NtfySink(baseConfig(client));
    await sink.send([{ body: "{}", subject: "s" }]);
    assert.equal(Object.keys(client.posts[0]).sort().join(","), "body,url");
    assert.equal(client.posts[0].body, "s");
    assert.ok(!client.posts[0].body.startsWith("{"), "body must not be a JSON envelope");
  });

  it("dry-run validates with zero client I/O and untouched stats", async () => {
    const client = new FakeClient();
    const sink = new NtfySink({ dryRun: true });
    const result = await sink.send([{ body: "{}", subject: "s" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    // ...but still validates: a malformed record fails even dry.
    await assert.rejects(() => sink.send([{ body: "" }]), RangeError);
    assert.equal(client.posts.length, 0);
  });

  it("fails closed without a client", async () => {
    const sink = new NtfySink({ topicUrl: topic });
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) => err instanceof NtfySinkConfigError
    );
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("fails closed without a topic URL", async () => {
    const client = new FakeClient();
    const sink = new NtfySink({ client });
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) =>
        err instanceof NtfySinkConfigError && /topic URL/.test(err.message)
    );
    assert.equal(client.posts.length, 0);
  });

  it("fails closed on a plaintext or unparseable topic URL", async () => {
    const client = new FakeClient();
    const sink = new NtfySink({
      topicUrl: "http://ntfy.sh/relay-alerts",
      client,
    });
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) => err instanceof NtfySinkConfigError
    );
    assert.equal(client.posts.length, 0);
  });

  it("throws carrying exactly the failed messages, keeping partial success", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 404);
    const sink = new NtfySink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: "{}" }, { body: "{}" }, { body: "{}" }]),
      (err: unknown) => {
        assert.ok(err instanceof NtfySinkError);
        assert.equal(err.failedRecords.length, 1);
        assert.equal(err.failedRecords[0].index, 1);
        assert.equal(err.failedRecords[0].errorCode, "HTTP_404");
        assert.equal(err.failedRecords[0].retryable, false);
        return true;
      }
    );
    // Partial success stays out of failedRecords; stats stay honest.
    assert.deepEqual(sink.stats, { sent: 2, failed: 1, sendFailures: 1 });
  });

  it("maps a codeless transport failure to retryable", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hangup"));
    const sink = new NtfySink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) => {
        assert.ok(err instanceof NtfySinkError);
        assert.equal(err.failedRecords[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(err.failedRecords[0].errorMessage, "socket hangup");
        assert.equal(err.failedRecords[0].retryable, true);
        return true;
      }
    );
  });
});

describe("ntfy-sink failure classification", () => {
  it("treats 429 and 5xx as retryable, other non-2xx as fail-closed", () => {
    assert.equal(classifyNtfyRecordFailure(429), true);
    assert.equal(classifyNtfyRecordFailure(500), true);
    assert.equal(classifyNtfyRecordFailure(503), true);
    assert.equal(classifyNtfyRecordFailure(400), false);
    assert.equal(classifyNtfyRecordFailure(401), false);
    assert.equal(classifyNtfyRecordFailure(403), false);
    assert.equal(classifyNtfyRecordFailure(404), false);
  });

  it("maps the config error to non_retryable through classifyFailure", () => {
    assert.deepEqual(classifyFailure(new NtfySinkConfigError("no client")), {
      failureClass: "non_retryable",
    });
  });

  it("does not map the per-message error itself to non_retryable", () => {
    const err = new NtfySinkError("ntfy-sink: send failed for 1 of 1 messages", [
      { index: 0, errorCode: "HTTP_429", statusCode: 429, retryable: true },
    ]);
    assert.notDeepEqual(classifyFailure(err), { failureClass: "non_retryable" });
  });
});
