import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  MailgunSink,
  MailgunSinkConfigError,
  MailgunSinkError,
  assertValidMailgunSinkConfig,
  buildMailgunFormBody,
  classifyMailgunRecordFailure,
  mailgunMessagesUrl,
  resolveMailgunNotification,
  resolveMailgunRecord,
  resolveMailgunSubject,
  resolveMailgunText,
  truncateMailgunPayload,
  MAILGUN_DEFAULT_PAYLOAD_MAX_CHARS,
  MAILGUN_FALLBACK_SUMMARY,
  type MailgunMessageClient,
  type MailgunMessagePostRequest,
  type MailgunMessagePostResponse,
  type MailgunSinkConfig,
} from "../src/mailgun-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements MailgunMessageClient {
  posts: MailgunMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: MailgunMessagePostRequest): Promise<MailgunMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200 };
  }
}

const domain = "mg.example.com";
const from = "alerts@example.com";
const to = "ops@example.com";

function baseConfig(
  client: MailgunMessageClient,
  extra: Partial<MailgunSinkConfig> = {}
): MailgunSinkConfig {
  return { domain, from, to, client, ...extra };
}

describe("mailgun-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidMailgunSinkConfig(null, "MailgunSink"), RangeError);
    assert.throws(() => assertValidMailgunSinkConfig("x", "MailgunSink"), RangeError);
  });

  it("rejects a malformed domain, sender, or recipient shape", () => {
    assert.throws(() => assertValidMailgunSinkConfig({ domain: "" }, "MailgunSink"), RangeError);
    assert.throws(() => assertValidMailgunSinkConfig({ domain: "has space" }, "MailgunSink"), RangeError);
    assert.throws(() => assertValidMailgunSinkConfig({ from: "" }, "MailgunSink"), RangeError);
    assert.throws(() => assertValidMailgunSinkConfig({ from: "has space" }, "MailgunSink"), RangeError);
    assert.throws(() => assertValidMailgunSinkConfig({ to: "" }, "MailgunSink"), RangeError);
    assert.throws(() => assertValidMailgunSinkConfig({ to: "has space" }, "MailgunSink"), RangeError);
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidMailgunSinkConfig({ client: {} }, "MailgunSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidMailgunSinkConfig({ payloadMaxChars: 0 }, "MailgunSink"), RangeError);
    assert.throws(() => assertValidMailgunSinkConfig({ payloadMaxChars: 2.5 }, "MailgunSink"), RangeError);
  });

  it("accepts a config with no domain, sender, or recipient yet (send-time config error)", () => {
    assert.doesNotThrow(() => new MailgunSink({}));
  });
});

describe("mailgun-sink text derivation", () => {
  it("derives the subject from subject, then key, then the fallback (never traceId)", () => {
    assert.equal(
      resolveMailgunSubject({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveMailgunSubject({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveMailgunSubject({ body: "{}", traceId: "t-1" }), MAILGUN_FALLBACK_SUMMARY);
    assert.equal(resolveMailgunSubject({ body: "{}" }), MAILGUN_FALLBACK_SUMMARY);
  });

  it("derives the text from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveMailgunText({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveMailgunText({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveMailgunText({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveMailgunText({ body: "{}" }), MAILGUN_FALLBACK_SUMMARY);
    assert.equal(
      resolveMailgunText({ body: "{}", subject: "", key: "", traceId: "" }),
      MAILGUN_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateMailgunPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateMailgunPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveMailgunNotification(record, {}), {
      subject: "order.created",
      text: "order.created",
    });
    assert.deepEqual(resolveMailgunNotification(record, { includePayload: true }), {
      subject: "order.created",
      text: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveMailgunNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { subject: "order.created", text: `order.created\n\n{"a… (truncated)` }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveMailgunRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("mailgun-sink wire shape", () => {
  it("builds the domain Messages endpoint with the domain in the path only", () => {
    assert.equal(
      mailgunMessagesUrl(domain),
      `https://api.mailgun.net/v3/${domain}/messages`
    );
  });

  it("builds the urlencoded form with from, to, subject, and text — and no credential", () => {
    assert.equal(
      buildMailgunFormBody(from, to, "order.created", "order.created"),
      `from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}&subject=order.created&text=order.created`
    );
    assert.equal(buildMailgunFormBody(from, to, "x", "x").includes("api:"), false);
    assert.equal(buildMailgunFormBody(from, to, "x", "x").includes(domain), false);
  });

  it("percent-encodes form values that contain & or =", () => {
    const body = buildMailgunFormBody(from, to, "a&b", "x=y");
    assert.equal(body.includes("subject=a%26b"), true);
    assert.equal(body.includes("text=x%3Dy"), true);
  });
});

describe("mailgun-sink send", () => {
  it("posts one message per record to the domain endpoint with the form body, no credential", async () => {
    const client = new FakeClient();
    const sink = new MailgunSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: `https://api.mailgun.net/v3/${domain}/messages`,
      body: `from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}&subject=order.created&text=order.created`,
    });
    const params1 = new URLSearchParams(client.posts[1].body);
    assert.equal(params1.get("text"), "agg-8");
    const params2 = new URLSearchParams(client.posts[2].body);
    assert.equal(params2.get("subject"), MAILGUN_FALLBACK_SUMMARY);
    assert.equal(params2.get("text"), "t-9");
    for (const post of client.posts) {
      assert.equal(post.body.includes("api:"), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new MailgunSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof MailgunSinkError);
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
    const sink = new MailgunSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof MailgunSinkError);
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

  it("fails closed without a client, domain, sender, or recipient", async () => {
    await assert.rejects(
      () => new MailgunSink({ domain, from, to }).send([{ body: '{"a":1}' }]),
      MailgunSinkConfigError
    );
    await assert.rejects(
      () => new MailgunSink(baseConfig(new FakeClient(), { domain: undefined })).send([{ body: '{"a":1}' }]),
      MailgunSinkConfigError
    );
    await assert.rejects(
      () => new MailgunSink(baseConfig(new FakeClient(), { from: undefined })).send([{ body: '{"a":1}' }]),
      MailgunSinkConfigError
    );
    await assert.rejects(
      () => new MailgunSink(baseConfig(new FakeClient(), { to: undefined })).send([{ body: '{"a":1}' }]),
      MailgunSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new MailgunSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new MailgunSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new MailgunSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyMailgunRecordFailure(429), true);
    assert.equal(classifyMailgunRecordFailure(500), true);
    assert.equal(classifyMailgunRecordFailure(503), true);
    assert.equal(classifyMailgunRecordFailure(400), false);
    assert.equal(classifyMailgunRecordFailure(401), false);
    assert.equal(classifyMailgunRecordFailure(404), false);
    assert.equal(MAILGUN_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
