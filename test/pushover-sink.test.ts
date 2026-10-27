import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  PushoverSink,
  PushoverSinkConfigError,
  PushoverSinkError,
  assertValidPushoverSinkConfig,
  buildPushoverMessageBody,
  classifyPushoverRecordFailure,
  resolvePushoverMessageSummary,
  resolvePushoverNotification,
  resolvePushoverRecord,
  resolvePushoverTitle,
  truncatePushoverPayload,
  PUSHOVER_DEFAULT_PAYLOAD_MAX_CHARS,
  PUSHOVER_FALLBACK_SUMMARY,
  PUSHOVER_MESSAGES_URL,
  PUSHOVER_PRIORITY,
  type PushoverMessageClient,
  type PushoverMessagePostRequest,
  type PushoverMessagePostResponse,
  type PushoverSinkConfig,
} from "../src/pushover-sink.ts";
import { classifyFailure } from "../src/failure.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements PushoverMessageClient {
  posts: PushoverMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: PushoverMessagePostRequest): Promise<PushoverMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200 };
  }
}

const appToken = "app-token-1";
const userKey = "user-key-1";

function baseConfig(
  client: PushoverMessageClient,
  extra: Partial<PushoverSinkConfig> = {}
): PushoverSinkConfig {
  return { appToken, userKey, client, ...extra };
}

describe("pushover-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidPushoverSinkConfig(null, "PushoverSink"), RangeError);
    assert.throws(() => assertValidPushoverSinkConfig("x", "PushoverSink"), RangeError);
  });

  it("rejects a malformed credential shape", () => {
    assert.throws(() => assertValidPushoverSinkConfig({ appToken: "" }, "PushoverSink"), RangeError);
    assert.throws(
      () => assertValidPushoverSinkConfig({ userKey: "has space" }, "PushoverSink"),
      RangeError
    );
    assert.throws(
      () => assertValidPushoverSinkConfig({ appToken: "has\0nul" }, "PushoverSink"),
      RangeError
    );
    assert.throws(
      () => assertValidPushoverSinkConfig({ appToken: 123 }, "PushoverSink"),
      RangeError
    );
  });

  it("accepts missing credentials at construction (send-time config error)", () => {
    assert.doesNotThrow(() => assertValidPushoverSinkConfig({}, "PushoverSink"));
    assert.doesNotThrow(() => assertValidPushoverSinkConfig({ appToken, userKey }, "PushoverSink"));
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidPushoverSinkConfig({ client: {} }, "PushoverSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(
      () => assertValidPushoverSinkConfig({ payloadMaxChars: 0 }, "PushoverSink"),
      RangeError
    );
    assert.throws(
      () => assertValidPushoverSinkConfig({ payloadMaxChars: 1.5 }, "PushoverSink"),
      RangeError
    );
  });

  it("pins the messages endpoint to the single hosted service", () => {
    assert.equal(PUSHOVER_MESSAGES_URL, "https://api.pushover.net/1/messages.json");
    assert.equal(PUSHOVER_PRIORITY, 0);
  });
});

describe("pushover-sink text derivation", () => {
  it("derives title from subject, falling back to key", () => {
    assert.equal(
      resolvePushoverTitle({ body: "{}", subject: "s", key: "k" }),
      "s"
    );
    assert.equal(resolvePushoverTitle({ body: "{}", key: "k" }), "k");
    assert.equal(resolvePushoverTitle({ body: "{}", subject: "" }), PUSHOVER_FALLBACK_SUMMARY);
    assert.equal(resolvePushoverTitle({ body: "{}" }), "webhook event");
  });

  it("derives the message summary from key, falling back to traceId", () => {
    assert.equal(
      resolvePushoverMessageSummary({ body: "{}", key: "k", traceId: "t" }),
      "k"
    );
    assert.equal(resolvePushoverMessageSummary({ body: "{}", traceId: "t" }), "t");
    assert.equal(resolvePushoverMessageSummary({ body: "{}" }), PUSHOVER_FALLBACK_SUMMARY);
  });

  it("builds the notification with title and message only — credentials join at body build time", () => {
    const note = resolvePushoverNotification(
      { body: "{}", subject: "order.created", key: "agg-7" },
      {}
    );
    assert.deepEqual(note, { title: "order.created", message: "agg-7" });
    assert.equal(Object.keys(note).sort().join(","), "message,title");
    const body = buildPushoverMessageBody(note, appToken, userKey);
    assert.deepEqual(JSON.parse(body), {
      token: appToken,
      user: userKey,
      title: "order.created",
      message: "agg-7",
      priority: 0,
    });
    assert.equal(Object.keys(JSON.parse(body)).sort().join(","), "message,priority,title,token,user");
  });

  it("carries the summary only by default, never the payload", () => {
    const note = resolvePushoverNotification(
      { body: '{"card":"4111"}', subject: "order.created", key: "agg-7" },
      {}
    );
    assert.equal(note.message, "agg-7");
    assert.ok(!note.message.includes("4111"), "payload must not leak by default");
  });

  it("appends the payload as plain text under the opt-in, truncated with a marker", () => {
    const note = resolvePushoverNotification(
      { body: "x".repeat(50), subject: "s", key: "k" },
      { includePayload: true, payloadMaxChars: 10 }
    );
    assert.equal(note.message, "k\n\nxxxxxxxxxx… (truncated)");
    assert.equal(PUSHOVER_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });

  it("does not truncate a short opted-in payload", () => {
    assert.equal(truncatePushoverPayload("short", 2000), "short");
    const note = resolvePushoverNotification(
      { body: '{"a":1}', subject: "s", key: "k" },
      { includePayload: true }
    );
    assert.equal(note.message, 'k\n\n{"a":1}');
  });

  it("rejects an empty body even without the opt-in", () => {
    assert.throws(() => resolvePushoverRecord({ body: "" }, 0, {}), RangeError);
    assert.throws(() => resolvePushoverRecord({ body: "" }, 2, {}), /record 2/);
  });
});

describe("pushover-sink send", () => {
  it("posts one JSON message per record to the fixed messages endpoint", async () => {
    const client = new FakeClient();
    const sink = new PushoverSink(baseConfig(client));
    const result = await sink.send([
      { body: "{}", subject: "order.created", key: "agg-7" },
      { body: "{}", key: "agg-8", traceId: "trace-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    assert.deepEqual(client.posts[0], {
      url: PUSHOVER_MESSAGES_URL,
      body: JSON.stringify({
        token: appToken,
        user: userKey,
        title: "order.created",
        message: "agg-7",
        priority: 0,
      }),
    });
    assert.deepEqual(client.posts[1], {
      url: PUSHOVER_MESSAGES_URL,
      body: JSON.stringify({
        token: appToken,
        user: userKey,
        title: "agg-8",
        message: "agg-8",
        priority: 0,
      }),
    });
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("carries credentials in the body, never in the URL", async () => {
    const client = new FakeClient();
    const sink = new PushoverSink(baseConfig(client));
    await sink.send([{ body: "{}", subject: "s", key: "k" }]);
    assert.equal(client.posts[0].url, PUSHOVER_MESSAGES_URL);
    assert.ok(!client.posts[0].url.includes(appToken));
    assert.ok(!client.posts[0].url.includes(userKey));
    assert.equal(Object.keys(client.posts[0]).sort().join(","), "body,url");
  });

  it("dry-run validates with zero client I/O and untouched stats", async () => {
    const client = new FakeClient();
    const sink = new PushoverSink({ dryRun: true });
    const result = await sink.send([{ body: "{}", subject: "s" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    // ...but still validates: a malformed record fails even dry.
    await assert.rejects(() => sink.send([{ body: "" }]), RangeError);
    assert.equal(client.posts.length, 0);
  });

  it("fails closed without a client", async () => {
    const sink = new PushoverSink({ appToken, userKey });
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) => err instanceof PushoverSinkConfigError
    );
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("fails closed without credentials", async () => {
    const client = new FakeClient();
    const noToken = new PushoverSink({ userKey, client });
    await assert.rejects(
      () => noToken.send([{ body: "{}" }]),
      (err: unknown) =>
        err instanceof PushoverSinkConfigError && /app token/.test(err.message)
    );
    const noUser = new PushoverSink({ appToken, client });
    await assert.rejects(
      () => noUser.send([{ body: "{}" }]),
      (err: unknown) =>
        err instanceof PushoverSinkConfigError && /user key/.test(err.message)
    );
    assert.equal(client.posts.length, 0);
  });

  it("throws carrying exactly the failed messages, keeping partial success", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 404);
    const sink = new PushoverSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: "{}" }, { body: "{}" }, { body: "{}" }]),
      (err: unknown) => {
        assert.ok(err instanceof PushoverSinkError);
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
    const sink = new PushoverSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) => {
        assert.ok(err instanceof PushoverSinkError);
        assert.equal(err.failedRecords[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(err.failedRecords[0].errorMessage, "socket hangup");
        assert.equal(err.failedRecords[0].retryable, true);
        return true;
      }
    );
  });
});

describe("pushover-sink failure classification", () => {
  it("treats 429 and 5xx as retryable, other non-2xx as fail-closed", () => {
    assert.equal(classifyPushoverRecordFailure(429), true);
    assert.equal(classifyPushoverRecordFailure(500), true);
    assert.equal(classifyPushoverRecordFailure(503), true);
    assert.equal(classifyPushoverRecordFailure(400), false);
    assert.equal(classifyPushoverRecordFailure(401), false);
    assert.equal(classifyPushoverRecordFailure(403), false);
    assert.equal(classifyPushoverRecordFailure(404), false);
  });

  it("maps the config error to non_retryable through classifyFailure", () => {
    assert.deepEqual(classifyFailure(new PushoverSinkConfigError("no client")), {
      failureClass: "non_retryable",
    });
  });

  it("does not map the per-message error itself to non_retryable", () => {
    const err = new PushoverSinkError("pushover-sink: send failed for 1 of 1 messages", [
      { index: 0, errorCode: "HTTP_429", statusCode: 429, retryable: true },
    ]);
    assert.notDeepEqual(classifyFailure(err), { failureClass: "non_retryable" });
  });
});
