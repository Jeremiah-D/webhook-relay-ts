import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  BrevoSink,
  BrevoSinkConfigError,
  BrevoSinkError,
  assertValidBrevoSinkConfig,
  buildBrevoMessageBody,
  classifyBrevoRecordFailure,
  resolveBrevoNotification,
  resolveBrevoRecord,
  resolveBrevoSubject,
  resolveBrevoText,
  truncateBrevoPayload,
  BREVO_DEFAULT_PAYLOAD_MAX_CHARS,
  BREVO_FALLBACK_SUMMARY,
  BREVO_SEND_URL,
  type BrevoMessageClient,
  type BrevoMessagePostRequest,
  type BrevoMessagePostResponse,
  type BrevoSinkConfig,
} from "../src/brevo-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements BrevoMessageClient {
  posts: BrevoMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: BrevoMessagePostRequest): Promise<BrevoMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200 };
  }
}

const from = "alerts@example.com";
const to = "ops@example.com";

function baseConfig(
  client: BrevoMessageClient,
  extra: Partial<BrevoSinkConfig> = {}
): BrevoSinkConfig {
  return { from, to, client, ...extra };
}

describe("brevo-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidBrevoSinkConfig(null, "BrevoSink"), RangeError);
    assert.throws(() => assertValidBrevoSinkConfig("x", "BrevoSink"), RangeError);
  });

  it("rejects a malformed sender or recipient shape", () => {
    assert.throws(() => assertValidBrevoSinkConfig({ from: "" }, "BrevoSink"), RangeError);
    assert.throws(() => assertValidBrevoSinkConfig({ from: "has space" }, "BrevoSink"), RangeError);
    assert.throws(() => assertValidBrevoSinkConfig({ to: "" }, "BrevoSink"), RangeError);
    assert.throws(() => assertValidBrevoSinkConfig({ to: "has space" }, "BrevoSink"), RangeError);
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidBrevoSinkConfig({ client: {} }, "BrevoSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidBrevoSinkConfig({ payloadMaxChars: 0 }, "BrevoSink"), RangeError);
    assert.throws(() => assertValidBrevoSinkConfig({ payloadMaxChars: 2.5 }, "BrevoSink"), RangeError);
  });

  it("accepts a config with no sender or recipient yet (send-time config error)", () => {
    assert.doesNotThrow(() => new BrevoSink({}));
  });
});

describe("brevo-sink text derivation", () => {
  it("derives the subject from subject, then key, then the fallback — never the trace id", () => {
    assert.equal(
      resolveBrevoSubject({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveBrevoSubject({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveBrevoSubject({ body: "{}", traceId: "t-1" }), BREVO_FALLBACK_SUMMARY);
    assert.equal(resolveBrevoSubject({ body: "{}" }), BREVO_FALLBACK_SUMMARY);
  });

  it("derives the text from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveBrevoText({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveBrevoText({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveBrevoText({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveBrevoText({ body: "{}" }), BREVO_FALLBACK_SUMMARY);
    assert.equal(
      resolveBrevoText({ body: "{}", subject: "", key: "", traceId: "" }),
      BREVO_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateBrevoPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateBrevoPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveBrevoNotification(record, {}), {
      subject: "order.created",
      text: "order.created",
    });
    assert.deepEqual(resolveBrevoNotification(record, { includePayload: true }), {
      subject: "order.created",
      text: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveBrevoNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { subject: "order.created", text: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveBrevoRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("brevo-sink wire shape", () => {
  it("posts to the fixed Brevo SMTP email endpoint", () => {
    assert.equal(BREVO_SEND_URL, "https://api.brevo.com/v3/smtp/email");
  });

  it("builds the JSON body with sender/to, subject, and textContent — and no credential", () => {
    assert.equal(
      buildBrevoMessageBody(from, to, "order.created", "order.created"),
      JSON.stringify({ sender: { email: from }, to: [{ email: to }], subject: "order.created", textContent: "order.created" })
    );
    // No credential appears in the body: the client alone
    // holds the API key and sends it as the api-key header.
    assert.equal(buildBrevoMessageBody(from, to, "x", "y").includes("Authorization"), false);
    assert.equal(buildBrevoMessageBody(from, to, "x", "y").includes("api_key"), false);
    assert.equal(buildBrevoMessageBody(from, to, "x", "y").includes("api-key"), false);
  });
});

describe("brevo-sink send", () => {
  it("posts one message per record to the fixed endpoint with the envelope and text, no credential", async () => {
    const client = new FakeClient();
    const sink = new BrevoSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: BREVO_SEND_URL,
      body: JSON.stringify({ sender: { email: from }, to: [{ email: to }], subject: "order.created", textContent: "order.created" }),
    });
    assert.deepEqual(JSON.parse(client.posts[1].body).subject, "agg-8");
    // A trace-id-only record gets the fallback subject but the
    // trace id as its text.
    assert.deepEqual(JSON.parse(client.posts[2].body).subject, BREVO_FALLBACK_SUMMARY);
    assert.deepEqual(JSON.parse(client.posts[2].body).textContent, "t-9");
    // The flat envelope carries the configured sender and recipient.
    assert.deepEqual(JSON.parse(client.posts[0].body).sender, { email: from });
    assert.deepEqual(JSON.parse(client.posts[0].body).to, [{ email: to }]);
    // The request carries no credential anywhere: the API key
    // is held by the client alone and travels as the
    // api-key header, never in the body.
    for (const post of client.posts) {
      assert.equal(post.body.includes("Authorization"), false);
      assert.equal(post.body.includes("api_key"), false);
      assert.equal(post.body.includes("api-key"), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new BrevoSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof BrevoSinkError);
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
    const sink = new BrevoSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof BrevoSinkError);
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
      () => new BrevoSink({ from, to }).send([{ body: '{"a":1}' }]),
      BrevoSinkConfigError
    );
    await assert.rejects(
      () => new BrevoSink(baseConfig(new FakeClient(), { from: undefined })).send([{ body: '{"a":1}' }]),
      BrevoSinkConfigError
    );
    await assert.rejects(
      () => new BrevoSink(baseConfig(new FakeClient(), { to: undefined })).send([{ body: '{"a":1}' }]),
      BrevoSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new BrevoSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new BrevoSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new BrevoSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyBrevoRecordFailure(429), true);
    assert.equal(classifyBrevoRecordFailure(500), true);
    assert.equal(classifyBrevoRecordFailure(503), true);
    assert.equal(classifyBrevoRecordFailure(400), false);
    assert.equal(classifyBrevoRecordFailure(401), false);
    assert.equal(classifyBrevoRecordFailure(404), false);
    assert.equal(BREVO_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
