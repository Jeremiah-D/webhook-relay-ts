import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  BarkSink,
  BarkSinkConfigError,
  BarkSinkError,
  assertValidBarkSinkConfig,
  classifyBarkRecordFailure,
  isValidBarkPushUrl,
  resolveBarkBodySummary,
  resolveBarkNotification,
  resolveBarkRecord,
  resolveBarkTitle,
  truncateBarkPayload,
  BARK_DEFAULT_PAYLOAD_MAX_CHARS,
  BARK_FALLBACK_SUMMARY,
  type BarkPushClient,
  type BarkPushPostRequest,
  type BarkPushPostResponse,
  type BarkSinkConfig,
} from "../src/bark-sink.ts";
import { classifyFailure } from "../src/failure.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements BarkPushClient {
  posts: BarkPushPostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: BarkPushPostRequest): Promise<BarkPushPostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200 };
  }
}

const pushUrl = "https://api.day.app/device-key-1/";

function baseConfig(
  client: BarkPushClient,
  extra: Partial<BarkSinkConfig> = {}
): BarkSinkConfig {
  return { pushUrl, client, ...extra };
}

describe("bark-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidBarkSinkConfig(null, "BarkSink"), RangeError);
    assert.throws(() => assertValidBarkSinkConfig("x", "BarkSink"), RangeError);
  });

  it("rejects a malformed push URL shape", () => {
    assert.throws(() => assertValidBarkSinkConfig({ pushUrl: "" }, "BarkSink"), RangeError);
    assert.throws(
      () => assertValidBarkSinkConfig({ pushUrl: "has space" }, "BarkSink"),
      RangeError
    );
    assert.throws(
      () => assertValidBarkSinkConfig({ pushUrl: "has\0nul" }, "BarkSink"),
      RangeError
    );
    assert.throws(
      () => assertValidBarkSinkConfig({ pushUrl: 123 }, "BarkSink"),
      RangeError
    );
  });

  it("accepts a missing push URL at construction (send-time config error)", () => {
    assert.doesNotThrow(() => assertValidBarkSinkConfig({}, "BarkSink"));
    assert.doesNotThrow(() => assertValidBarkSinkConfig({ pushUrl }, "BarkSink"));
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidBarkSinkConfig({ client: {} }, "BarkSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(
      () => assertValidBarkSinkConfig({ payloadMaxChars: 0 }, "BarkSink"),
      RangeError
    );
    assert.throws(
      () => assertValidBarkSinkConfig({ payloadMaxChars: 1.5 }, "BarkSink"),
      RangeError
    );
  });

  it("accepts https URLs and rejects http or unparseable URLs at send time", () => {
    assert.equal(isValidBarkPushUrl(pushUrl), true);
    assert.equal(isValidBarkPushUrl("https://bark.example.com/device-key-2/"), true);
    assert.equal(isValidBarkPushUrl("http://api.day.app/device-key-1/"), false);
    assert.equal(isValidBarkPushUrl("not a url"), false);
    assert.equal(isValidBarkPushUrl(""), false);
  });
});

describe("bark-sink text derivation", () => {
  it("derives title from subject, falling back to key", () => {
    assert.equal(
      resolveBarkTitle({ body: "{}", subject: "s", key: "k" }),
      "s"
    );
    assert.equal(resolveBarkTitle({ body: "{}", key: "k" }), "k");
    assert.equal(resolveBarkTitle({ body: "{}", subject: "" }), BARK_FALLBACK_SUMMARY);
    assert.equal(resolveBarkTitle({ body: "{}" }), "webhook event");
  });

  it("derives the body summary from key, falling back to traceId", () => {
    assert.equal(
      resolveBarkBodySummary({ body: "{}", key: "k", traceId: "t" }),
      "k"
    );
    assert.equal(resolveBarkBodySummary({ body: "{}", traceId: "t" }), "t");
    assert.equal(resolveBarkBodySummary({ body: "{}" }), BARK_FALLBACK_SUMMARY);
  });

  it("builds the notification with title and body only — no badge, sound, or grouping field", () => {
    const note = resolveBarkNotification(
      { body: "{}", subject: "order.created", key: "agg-7" },
      {}
    );
    assert.deepEqual(note, { title: "order.created", body: "agg-7" });
    assert.equal(Object.keys(note).sort().join(","), "body,title");
  });

  it("carries the summary only by default, never the payload", () => {
    const note = resolveBarkNotification(
      { body: '{"card":"4111"}', subject: "order.created", key: "agg-7" },
      {}
    );
    assert.equal(note.body, "agg-7");
    assert.ok(!note.body.includes("4111"), "payload must not leak by default");
  });

  it("appends the payload as plain text under the opt-in, truncated with a marker", () => {
    const note = resolveBarkNotification(
      { body: "x".repeat(50), subject: "s", key: "k" },
      { includePayload: true, payloadMaxChars: 10 }
    );
    assert.equal(note.body, "k\n\nxxxxxxxxxx… (truncated)");
    assert.equal(BARK_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });

  it("does not truncate a short opted-in payload", () => {
    assert.equal(truncateBarkPayload("short", 2000), "short");
    const note = resolveBarkNotification(
      { body: '{"a":1}', subject: "s", key: "k" },
      { includePayload: true }
    );
    assert.equal(note.body, 'k\n\n{"a":1}');
  });

  it("rejects an empty body even without the opt-in", () => {
    assert.throws(() => resolveBarkRecord({ body: "" }, 0, {}), RangeError);
    assert.throws(() => resolveBarkRecord({ body: "" }, 2, {}), /record 2/);
  });
});

describe("bark-sink send", () => {
  it("posts one JSON message per record to the configured push URL verbatim", async () => {
    const client = new FakeClient();
    const sink = new BarkSink(baseConfig(client));
    const result = await sink.send([
      { body: "{}", subject: "order.created", key: "agg-7" },
      { body: "{}", key: "agg-8", traceId: "trace-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    assert.deepEqual(client.posts[0], {
      url: pushUrl,
      body: JSON.stringify({ title: "order.created", body: "agg-7" }),
    });
    assert.deepEqual(client.posts[1], {
      url: pushUrl,
      body: JSON.stringify({ title: "agg-8", body: "agg-8" }),
    });
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("posts the URL verbatim, device key included — no token is ever appended or extracted", async () => {
    // The device key lives in the URL path: a client that
    // stripped it would silently break routing, and a sink
    // that appended its own key would double-authenticate.
    const client = new FakeClient();
    const sink = new BarkSink(baseConfig(client));
    await sink.send([{ body: "{}", subject: "s", key: "k" }]);
    assert.equal(client.posts[0].url, pushUrl);
    assert.ok(client.posts[0].url.includes("device-key-1"));
    assert.equal(Object.keys(client.posts[0]).sort().join(","), "body,url");
  });

  it("dry-run validates with zero client I/O and untouched stats", async () => {
    const client = new FakeClient();
    const sink = new BarkSink({ dryRun: true });
    const result = await sink.send([{ body: "{}", subject: "s" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    // ...but still validates: a malformed record fails even dry.
    await assert.rejects(() => sink.send([{ body: "" }]), RangeError);
    assert.equal(client.posts.length, 0);
  });

  it("fails closed without a client", async () => {
    const sink = new BarkSink({ pushUrl });
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) => err instanceof BarkSinkConfigError
    );
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("fails closed without a push URL", async () => {
    const client = new FakeClient();
    const sink = new BarkSink({ client });
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) =>
        err instanceof BarkSinkConfigError && /push URL/.test(err.message)
    );
    assert.equal(client.posts.length, 0);
  });

  it("fails closed on a plaintext or unparseable push URL", async () => {
    const client = new FakeClient();
    const sink = new BarkSink({
      pushUrl: "http://api.day.app/device-key-1/",
      client,
    });
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) => err instanceof BarkSinkConfigError
    );
    assert.equal(client.posts.length, 0);
  });

  it("throws carrying exactly the failed messages, keeping partial success", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 404);
    const sink = new BarkSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: "{}" }, { body: "{}" }, { body: "{}" }]),
      (err: unknown) => {
        assert.ok(err instanceof BarkSinkError);
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
    const sink = new BarkSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) => {
        assert.ok(err instanceof BarkSinkError);
        assert.equal(err.failedRecords[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(err.failedRecords[0].errorMessage, "socket hangup");
        assert.equal(err.failedRecords[0].retryable, true);
        return true;
      }
    );
  });
});

describe("bark-sink failure classification", () => {
  it("treats 429 and 5xx as retryable, other non-2xx as fail-closed", () => {
    assert.equal(classifyBarkRecordFailure(429), true);
    assert.equal(classifyBarkRecordFailure(500), true);
    assert.equal(classifyBarkRecordFailure(503), true);
    assert.equal(classifyBarkRecordFailure(400), false);
    assert.equal(classifyBarkRecordFailure(401), false);
    assert.equal(classifyBarkRecordFailure(403), false);
    assert.equal(classifyBarkRecordFailure(404), false);
  });

  it("maps the config error to non_retryable through classifyFailure", () => {
    assert.deepEqual(classifyFailure(new BarkSinkConfigError("no client")), {
      failureClass: "non_retryable",
    });
  });

  it("does not map the per-message error itself to non_retryable", () => {
    const err = new BarkSinkError("bark-sink: send failed for 1 of 1 messages", [
      { index: 0, errorCode: "HTTP_429", statusCode: 429, retryable: true },
    ]);
    assert.notDeepEqual(classifyFailure(err), { failureClass: "non_retryable" });
  });
});
