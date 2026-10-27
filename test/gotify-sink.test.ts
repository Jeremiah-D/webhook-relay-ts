import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  GotifySink,
  GotifySinkConfigError,
  GotifySinkError,
  assertValidGotifySinkConfig,
  classifyGotifyRecordFailure,
  isValidGotifyMessageUrl,
  resolveGotifyMessageSummary,
  resolveGotifyNotification,
  resolveGotifyRecord,
  resolveGotifyTitle,
  truncateGotifyPayload,
  GOTIFY_DEFAULT_PAYLOAD_MAX_CHARS,
  GOTIFY_FALLBACK_SUMMARY,
  GOTIFY_PRIORITY,
  type GotifyMessageClient,
  type GotifyMessagePostRequest,
  type GotifyMessagePostResponse,
  type GotifySinkConfig,
} from "../src/gotify-sink.ts";
import { classifyFailure } from "../src/failure.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements GotifyMessageClient {
  posts: GotifyMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: GotifyMessagePostRequest): Promise<GotifyMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200 };
  }
}

const messageUrl = "https://gotify.example.com/message?token=app-token-1";

function baseConfig(
  client: GotifyMessageClient,
  extra: Partial<GotifySinkConfig> = {}
): GotifySinkConfig {
  return { messageUrl, client, ...extra };
}

describe("gotify-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidGotifySinkConfig(null, "GotifySink"), RangeError);
    assert.throws(() => assertValidGotifySinkConfig("x", "GotifySink"), RangeError);
  });

  it("rejects a malformed message URL shape", () => {
    assert.throws(() => assertValidGotifySinkConfig({ messageUrl: "" }, "GotifySink"), RangeError);
    assert.throws(
      () => assertValidGotifySinkConfig({ messageUrl: "has space" }, "GotifySink"),
      RangeError
    );
    assert.throws(
      () => assertValidGotifySinkConfig({ messageUrl: "has\0nul" }, "GotifySink"),
      RangeError
    );
    assert.throws(
      () => assertValidGotifySinkConfig({ messageUrl: 123 }, "GotifySink"),
      RangeError
    );
  });

  it("accepts a missing message URL at construction (send-time config error)", () => {
    assert.doesNotThrow(() => assertValidGotifySinkConfig({}, "GotifySink"));
    assert.doesNotThrow(() => assertValidGotifySinkConfig({ messageUrl }, "GotifySink"));
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidGotifySinkConfig({ client: {} }, "GotifySink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(
      () => assertValidGotifySinkConfig({ payloadMaxChars: 0 }, "GotifySink"),
      RangeError
    );
    assert.throws(
      () => assertValidGotifySinkConfig({ payloadMaxChars: 1.5 }, "GotifySink"),
      RangeError
    );
  });

  it("accepts https URLs and rejects http or unparseable URLs at send time", () => {
    assert.equal(isValidGotifyMessageUrl(messageUrl), true);
    assert.equal(isValidGotifyMessageUrl("https://gotify.example.com/message"), true);
    assert.equal(isValidGotifyMessageUrl("http://gotify.example.com/message?token=x"), false);
    assert.equal(isValidGotifyMessageUrl("not a url"), false);
    assert.equal(isValidGotifyMessageUrl(""), false);
  });
});

describe("gotify-sink text derivation", () => {
  it("derives title from subject, falling back to key", () => {
    assert.equal(
      resolveGotifyTitle({ body: "{}", subject: "s", key: "k" }),
      "s"
    );
    assert.equal(resolveGotifyTitle({ body: "{}", key: "k" }), "k");
    assert.equal(resolveGotifyTitle({ body: "{}", subject: "" }), GOTIFY_FALLBACK_SUMMARY);
    assert.equal(resolveGotifyTitle({ body: "{}" }), "webhook event");
  });

  it("derives the message summary from key, falling back to traceId", () => {
    assert.equal(
      resolveGotifyMessageSummary({ body: "{}", key: "k", traceId: "t" }),
      "k"
    );
    assert.equal(resolveGotifyMessageSummary({ body: "{}", traceId: "t" }), "t");
    assert.equal(resolveGotifyMessageSummary({ body: "{}" }), GOTIFY_FALLBACK_SUMMARY);
  });

  it("builds the notification with fixed priority 5", () => {
    assert.deepEqual(
      resolveGotifyNotification({ body: "{}", subject: "order.created", key: "agg-7" }, {}),
      { title: "order.created", message: "agg-7", priority: 5 }
    );
    assert.equal(GOTIFY_PRIORITY, 5);
  });

  it("carries the summary only by default, never the payload", () => {
    const note = resolveGotifyNotification(
      { body: '{"card":"4111"}', subject: "order.created", key: "agg-7" },
      {}
    );
    assert.equal(note.message, "agg-7");
    assert.ok(!note.message.includes("4111"), "payload must not leak by default");
  });

  it("appends the payload as plain text under the opt-in, truncated with a marker", () => {
    const note = resolveGotifyNotification(
      { body: "x".repeat(50), subject: "s", key: "k" },
      { includePayload: true, payloadMaxChars: 10 }
    );
    assert.equal(note.message, "k\n\nxxxxxxxxxx… (truncated)");
    assert.equal(GOTIFY_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });

  it("does not truncate a short opted-in payload", () => {
    assert.equal(truncateGotifyPayload("short", 2000), "short");
    const note = resolveGotifyNotification(
      { body: '{"a":1}', subject: "s", key: "k" },
      { includePayload: true }
    );
    assert.equal(note.message, 'k\n\n{"a":1}');
  });

  it("rejects an empty body even without the opt-in", () => {
    assert.throws(() => resolveGotifyRecord({ body: "" }, 0, {}), RangeError);
    assert.throws(() => resolveGotifyRecord({ body: "" }, 2, {}), /record 2/);
  });
});

describe("gotify-sink send", () => {
  it("posts one JSON message per record to the configured message URL verbatim", async () => {
    const client = new FakeClient();
    const sink = new GotifySink(baseConfig(client));
    const result = await sink.send([
      { body: "{}", subject: "order.created", key: "agg-7" },
      { body: "{}", key: "agg-8", traceId: "trace-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    assert.deepEqual(client.posts[0], {
      url: messageUrl,
      body: JSON.stringify({ title: "order.created", message: "agg-7", priority: 5 }),
    });
    assert.deepEqual(client.posts[1], {
      url: messageUrl,
      body: JSON.stringify({ title: "agg-8", message: "agg-8", priority: 5 }),
    });
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("posts the URL verbatim, query string included — no token is ever appended or extracted", async () => {
    // The app token lives in the URL's query string: a client that
    // stripped it would silently break authentication, and a sink
    // that appended its own token would double-authenticate.
    const client = new FakeClient();
    const sink = new GotifySink(baseConfig(client));
    await sink.send([{ body: "{}", subject: "s", key: "k" }]);
    assert.equal(client.posts[0].url, messageUrl);
    assert.ok(client.posts[0].url.includes("token=app-token-1"));
    assert.equal(Object.keys(client.posts[0]).sort().join(","), "body,url");
  });

  it("dry-run validates with zero client I/O and untouched stats", async () => {
    const client = new FakeClient();
    const sink = new GotifySink({ dryRun: true });
    const result = await sink.send([{ body: "{}", subject: "s" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    // ...but still validates: a malformed record fails even dry.
    await assert.rejects(() => sink.send([{ body: "" }]), RangeError);
    assert.equal(client.posts.length, 0);
  });

  it("fails closed without a client", async () => {
    const sink = new GotifySink({ messageUrl });
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) => err instanceof GotifySinkConfigError
    );
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("fails closed without a message URL", async () => {
    const client = new FakeClient();
    const sink = new GotifySink({ client });
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) =>
        err instanceof GotifySinkConfigError && /message URL/.test(err.message)
    );
    assert.equal(client.posts.length, 0);
  });

  it("fails closed on a plaintext or unparseable message URL", async () => {
    const client = new FakeClient();
    const sink = new GotifySink({
      messageUrl: "http://gotify.example.com/message?token=x",
      client,
    });
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) => err instanceof GotifySinkConfigError
    );
    assert.equal(client.posts.length, 0);
  });

  it("throws carrying exactly the failed messages, keeping partial success", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 401);
    const sink = new GotifySink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: "{}" }, { body: "{}" }, { body: "{}" }]),
      (err: unknown) => {
        assert.ok(err instanceof GotifySinkError);
        assert.equal(err.failedRecords.length, 1);
        assert.equal(err.failedRecords[0].index, 1);
        assert.equal(err.failedRecords[0].errorCode, "HTTP_401");
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
    const sink = new GotifySink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) => {
        assert.ok(err instanceof GotifySinkError);
        assert.equal(err.failedRecords[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(err.failedRecords[0].errorMessage, "socket hangup");
        assert.equal(err.failedRecords[0].retryable, true);
        return true;
      }
    );
  });
});

describe("gotify-sink failure classification", () => {
  it("treats 429 and 5xx as retryable, other non-2xx as fail-closed", () => {
    assert.equal(classifyGotifyRecordFailure(429), true);
    assert.equal(classifyGotifyRecordFailure(500), true);
    assert.equal(classifyGotifyRecordFailure(503), true);
    assert.equal(classifyGotifyRecordFailure(400), false);
    assert.equal(classifyGotifyRecordFailure(401), false);
    assert.equal(classifyGotifyRecordFailure(403), false);
    assert.equal(classifyGotifyRecordFailure(404), false);
  });

  it("maps the config error to non_retryable through classifyFailure", () => {
    assert.deepEqual(classifyFailure(new GotifySinkConfigError("no client")), {
      failureClass: "non_retryable",
    });
  });

  it("does not map the per-message error itself to non_retryable", () => {
    const err = new GotifySinkError("gotify-sink: send failed for 1 of 1 messages", [
      { index: 0, errorCode: "HTTP_429", statusCode: 429, retryable: true },
    ]);
    assert.notDeepEqual(classifyFailure(err), { failureClass: "non_retryable" });
  });
});
