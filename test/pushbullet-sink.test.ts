import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  PushbulletSink,
  PushbulletSinkConfigError,
  PushbulletSinkError,
  assertValidPushbulletSinkConfig,
  classifyPushbulletRecordFailure,
  resolvePushbulletBodySummary,
  resolvePushbulletNotification,
  resolvePushbulletRecord,
  resolvePushbulletTitle,
  truncatePushbulletPayload,
  PUSHBULLET_ACCESS_TOKEN_HEADER,
  PUSHBULLET_DEFAULT_PAYLOAD_MAX_CHARS,
  PUSHBULLET_FALLBACK_SUMMARY,
  PUSHBULLET_PUSHES_URL,
  PUSHBULLET_PUSH_TYPE,
  type PushbulletPushClient,
  type PushbulletPushPostRequest,
  type PushbulletPushPostResponse,
  type PushbulletSinkConfig,
} from "../src/pushbullet-sink.ts";
import { classifyFailure } from "../src/failure.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements PushbulletPushClient {
  posts: PushbulletPushPostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: PushbulletPushPostRequest): Promise<PushbulletPushPostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200 };
  }
}

const accessToken = "access-token-1";

function baseConfig(
  client: PushbulletPushClient,
  extra: Partial<PushbulletSinkConfig> = {}
): PushbulletSinkConfig {
  return { accessToken, client, ...extra };
}

describe("pushbullet-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidPushbulletSinkConfig(null, "PushbulletSink"), RangeError);
    assert.throws(() => assertValidPushbulletSinkConfig("x", "PushbulletSink"), RangeError);
  });

  it("rejects a malformed access token shape", () => {
    assert.throws(() => assertValidPushbulletSinkConfig({ accessToken: "" }, "PushbulletSink"), RangeError);
    assert.throws(
      () => assertValidPushbulletSinkConfig({ accessToken: "has space" }, "PushbulletSink"),
      RangeError
    );
    assert.throws(
      () => assertValidPushbulletSinkConfig({ accessToken: "has\0nul" }, "PushbulletSink"),
      RangeError
    );
    assert.throws(
      () => assertValidPushbulletSinkConfig({ accessToken: 123 }, "PushbulletSink"),
      RangeError
    );
  });

  it("accepts a missing access token at construction (send-time config error)", () => {
    assert.doesNotThrow(() => assertValidPushbulletSinkConfig({}, "PushbulletSink"));
    assert.doesNotThrow(() => assertValidPushbulletSinkConfig({ accessToken }, "PushbulletSink"));
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidPushbulletSinkConfig({ client: {} }, "PushbulletSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(
      () => assertValidPushbulletSinkConfig({ payloadMaxChars: 0 }, "PushbulletSink"),
      RangeError
    );
    assert.throws(
      () => assertValidPushbulletSinkConfig({ payloadMaxChars: 1.5 }, "PushbulletSink"),
      RangeError
    );
  });

  it("pins the pushes endpoint, the note type, and the header name", () => {
    assert.equal(PUSHBULLET_PUSHES_URL, "https://api.pushbullet.com/v2/pushes");
    assert.equal(PUSHBULLET_PUSH_TYPE, "note");
    assert.equal(PUSHBULLET_ACCESS_TOKEN_HEADER, "Access-Token");
  });
});

describe("pushbullet-sink text derivation", () => {
  it("derives title from subject, falling back to key", () => {
    assert.equal(
      resolvePushbulletTitle({ body: "{}", subject: "s", key: "k" }),
      "s"
    );
    assert.equal(resolvePushbulletTitle({ body: "{}", key: "k" }), "k");
    assert.equal(resolvePushbulletTitle({ body: "{}", subject: "" }), PUSHBULLET_FALLBACK_SUMMARY);
    assert.equal(resolvePushbulletTitle({ body: "{}" }), "webhook event");
  });

  it("derives the body summary from key, falling back to traceId", () => {
    assert.equal(
      resolvePushbulletBodySummary({ body: "{}", key: "k", traceId: "t" }),
      "k"
    );
    assert.equal(resolvePushbulletBodySummary({ body: "{}", traceId: "t" }), "t");
    assert.equal(resolvePushbulletBodySummary({ body: "{}" }), PUSHBULLET_FALLBACK_SUMMARY);
  });

  it("builds the notification with type note, title, and body only", () => {
    const note = resolvePushbulletNotification(
      { body: "{}", subject: "order.created", key: "agg-7" },
      {}
    );
    assert.deepEqual(note, { title: "order.created", body: "agg-7" });
    assert.equal(Object.keys(note).sort().join(","), "body,title");
    const record = resolvePushbulletRecord(
      { body: "{}", subject: "order.created", key: "agg-7" },
      0,
      {}
    );
    assert.deepEqual(JSON.parse(record.body), {
      type: "note",
      title: "order.created",
      body: "agg-7",
    });
    assert.equal(Object.keys(JSON.parse(record.body)).sort().join(","), "body,title,type");
  });

  it("carries the summary only by default, never the payload", () => {
    const note = resolvePushbulletNotification(
      { body: '{"card":"4111"}', subject: "order.created", key: "agg-7" },
      {}
    );
    assert.equal(note.body, "agg-7");
    assert.ok(!note.body.includes("4111"), "payload must not leak by default");
  });

  it("appends the payload as plain text under the opt-in, truncated with a marker", () => {
    const note = resolvePushbulletNotification(
      { body: "x".repeat(50), subject: "s", key: "k" },
      { includePayload: true, payloadMaxChars: 10 }
    );
    assert.equal(note.body, "k\n\nxxxxxxxxxx… (truncated)");
    assert.equal(PUSHBULLET_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });

  it("does not truncate a short opted-in payload", () => {
    assert.equal(truncatePushbulletPayload("short", 2000), "short");
    const note = resolvePushbulletNotification(
      { body: '{"a":1}', subject: "s", key: "k" },
      { includePayload: true }
    );
    assert.equal(note.body, 'k\n\n{"a":1}');
  });

  it("rejects an empty body even without the opt-in", () => {
    assert.throws(() => resolvePushbulletRecord({ body: "" }, 0, {}), RangeError);
    assert.throws(() => resolvePushbulletRecord({ body: "" }, 2, {}), /record 2/);
  });
});

describe("pushbullet-sink send", () => {
  it("posts one JSON note per record to the fixed pushes endpoint with the header", async () => {
    const client = new FakeClient();
    const sink = new PushbulletSink(baseConfig(client));
    const result = await sink.send([
      { body: "{}", subject: "order.created", key: "agg-7" },
      { body: "{}", key: "agg-8", traceId: "trace-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    assert.deepEqual(client.posts[0], {
      url: PUSHBULLET_PUSHES_URL,
      headers: { "Access-Token": accessToken },
      body: JSON.stringify({ type: "note", title: "order.created", body: "agg-7" }),
    });
    assert.deepEqual(client.posts[1], {
      url: PUSHBULLET_PUSHES_URL,
      headers: { "Access-Token": accessToken },
      body: JSON.stringify({ type: "note", title: "agg-8", body: "agg-8" }),
    });
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("carries the token in the header only — never in the URL or the body", async () => {
    const client = new FakeClient();
    const sink = new PushbulletSink(baseConfig(client));
    await sink.send([{ body: "{}", subject: "s", key: "k" }]);
    assert.equal(client.posts[0].url, PUSHBULLET_PUSHES_URL);
    assert.ok(!client.posts[0].url.includes(accessToken));
    assert.ok(!client.posts[0].body.includes(accessToken));
    assert.deepEqual(client.posts[0].headers, { "Access-Token": accessToken });
    assert.equal(Object.keys(client.posts[0]).sort().join(","), "body,headers,url");
  });

  it("dry-run validates with zero client I/O and untouched stats", async () => {
    const client = new FakeClient();
    const sink = new PushbulletSink({ dryRun: true });
    const result = await sink.send([{ body: "{}", subject: "s" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    // ...but still validates: a malformed record fails even dry.
    await assert.rejects(() => sink.send([{ body: "" }]), RangeError);
    assert.equal(client.posts.length, 0);
  });

  it("fails closed without a client", async () => {
    const sink = new PushbulletSink({ accessToken });
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) => err instanceof PushbulletSinkConfigError
    );
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("fails closed without an access token", async () => {
    const client = new FakeClient();
    const sink = new PushbulletSink({ client });
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) =>
        err instanceof PushbulletSinkConfigError && /access token/.test(err.message)
    );
    assert.equal(client.posts.length, 0);
  });

  it("throws carrying exactly the failed messages, keeping partial success", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 404);
    const sink = new PushbulletSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: "{}" }, { body: "{}" }, { body: "{}" }]),
      (err: unknown) => {
        assert.ok(err instanceof PushbulletSinkError);
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
    const sink = new PushbulletSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) => {
        assert.ok(err instanceof PushbulletSinkError);
        assert.equal(err.failedRecords[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(err.failedRecords[0].errorMessage, "socket hangup");
        assert.equal(err.failedRecords[0].retryable, true);
        return true;
      }
    );
  });
});

describe("pushbullet-sink failure classification", () => {
  it("treats 429 and 5xx as retryable, other non-2xx as fail-closed", () => {
    assert.equal(classifyPushbulletRecordFailure(429), true);
    assert.equal(classifyPushbulletRecordFailure(500), true);
    assert.equal(classifyPushbulletRecordFailure(503), true);
    assert.equal(classifyPushbulletRecordFailure(400), false);
    assert.equal(classifyPushbulletRecordFailure(401), false);
    assert.equal(classifyPushbulletRecordFailure(403), false);
    assert.equal(classifyPushbulletRecordFailure(404), false);
  });

  it("maps the config error to non_retryable through classifyFailure", () => {
    assert.deepEqual(classifyFailure(new PushbulletSinkConfigError("no client")), {
      failureClass: "non_retryable",
    });
  });

  it("does not map the per-message error itself to non_retryable", () => {
    const err = new PushbulletSinkError("pushbullet-sink: send failed for 1 of 1 messages", [
      { index: 0, errorCode: "HTTP_429", statusCode: 429, retryable: true },
    ]);
    assert.notDeepEqual(classifyFailure(err), { failureClass: "non_retryable" });
  });
});
