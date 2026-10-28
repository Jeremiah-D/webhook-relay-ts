import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  TwilioSink,
  TwilioSinkConfigError,
  TwilioSinkError,
  assertValidTwilioSinkConfig,
  buildTwilioFormBody,
  classifyTwilioRecordFailure,
  resolveTwilioNotification,
  resolveTwilioRecord,
  resolveTwilioText,
  truncateTwilioPayload,
  twilioMessagesUrl,
  TWILIO_API_HOST,
  TWILIO_DEFAULT_PAYLOAD_MAX_CHARS,
  TWILIO_FALLBACK_SUMMARY,
  type TwilioMessageClient,
  type TwilioMessagePostRequest,
  type TwilioMessagePostResponse,
  type TwilioSinkConfig,
} from "../src/twilio-sink.ts";
import { classifyFailure } from "../src/failure.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements TwilioMessageClient {
  posts: TwilioMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: TwilioMessagePostRequest): Promise<TwilioMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 201 };
  }
}

const accountSid = "account-sid-1";
const from = "+15550001111";
const to = "+15550002222";

function baseConfig(
  client: TwilioMessageClient,
  extra: Partial<TwilioSinkConfig> = {}
): TwilioSinkConfig {
  return { accountSid, from, to, client, ...extra };
}

describe("twilio-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidTwilioSinkConfig(null, "TwilioSink"), RangeError);
    assert.throws(() => assertValidTwilioSinkConfig("x", "TwilioSink"), RangeError);
  });

  it("rejects a malformed account SID, sender, or recipient shape", () => {
    assert.throws(
      () => assertValidTwilioSinkConfig({ accountSid: "" }, "TwilioSink"),
      RangeError
    );
    assert.throws(
      () => assertValidTwilioSinkConfig({ from: "+1 555 000 1111" }, "TwilioSink"),
      RangeError
    );
    assert.throws(
      () => assertValidTwilioSinkConfig({ to: "" }, "TwilioSink"),
      RangeError
    );
  });

  it("rejects a client without a post function", () => {
    assert.throws(
      () => assertValidTwilioSinkConfig({ client: {} }, "TwilioSink"),
      RangeError
    );
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(
      () => assertValidTwilioSinkConfig({ payloadMaxChars: 0 }, "TwilioSink"),
      RangeError
    );
    assert.throws(
      () => assertValidTwilioSinkConfig({ payloadMaxChars: 2.5 }, "TwilioSink"),
      RangeError
    );
  });

  it("accepts a config with no account or numbers yet (send-time config error)", () => {
    assert.doesNotThrow(() => new TwilioSink({}));
  });
});

describe("twilio-sink text derivation", () => {
  it("prefers subject, then key, then traceId, then the fallback summary", () => {
    assert.equal(
      resolveTwilioText({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveTwilioText({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveTwilioText({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveTwilioText({ body: "{}" }), TWILIO_FALLBACK_SUMMARY);
    assert.equal(
      resolveTwilioText({ body: "{}", subject: "", key: "", traceId: "" }),
      TWILIO_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateTwilioPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateTwilioPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveTwilioNotification(record, {}), { text: "order.created" });
    assert.deepEqual(resolveTwilioNotification(record, { includePayload: true }), {
      text: `order.created\n\n{"a":1}`,
    });
    assert.deepEqual(
      resolveTwilioNotification(record, { includePayload: true, payloadMaxChars: 3 }),
      { text: "order.created\n\n{\"a… (truncated)" }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveTwilioRecord({ body: "" }, 2, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("twilio-sink wire shape", () => {
  it("builds the fixed account-scoped URL with the SID in the path only", () => {
    assert.equal(
      twilioMessagesUrl(accountSid),
      "https://api.twilio.com/2010-04-01/Accounts/account-sid-1/Messages.json"
    );
    assert.equal(TWILIO_API_HOST, "https://api.twilio.com");
    // A SID with reserved characters cannot break the path.
    assert.equal(
      twilioMessagesUrl("AC/a b"),
      "https://api.twilio.com/2010-04-01/Accounts/AC%2Fa%20b/Messages.json"
    );
  });

  it("form-encodes To, From, and Body in order, escaping reserved characters", () => {
    assert.equal(
      buildTwilioFormBody(to, from, "order.created"),
      "To=%2B15550002222&From=%2B15550001111&Body=order.created"
    );
    assert.equal(
      buildTwilioFormBody(to, from, "a&b=c\nd"),
      "To=%2B15550002222&From=%2B15550001111&Body=a%26b%3Dc%0Ad"
    );
  });
});

describe("twilio-sink send", () => {
  it("posts one message per record with the account URL and form body, no credential", async () => {
    const client = new FakeClient();
    const sink = new TwilioSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    assert.deepEqual(client.posts[0], {
      url: "https://api.twilio.com/2010-04-01/Accounts/account-sid-1/Messages.json",
      body: "To=%2B15550002222&From=%2B15550001111&Body=order.created",
    });
    assert.deepEqual(client.posts[1], {
      url: "https://api.twilio.com/2010-04-01/Accounts/account-sid-1/Messages.json",
      body: "To=%2B15550002222&From=%2B15550001111&Body=agg-8",
    });
    // The request carries no credential anywhere: the auth token is
    // held by the client alone, and the SID appears in the URL only.
    for (const post of client.posts) {
      assert.equal("token" in post, false);
      assert.equal(post.body.includes("account-sid-1"), false);
    }
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new TwilioSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([
          { body: '{"a":1}' },
          { body: '{"b":2}' },
          { body: '{"c":3}' },
        ]),
      (err: unknown) => {
        assert.ok(err instanceof TwilioSinkError);
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
    const sink = new TwilioSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof TwilioSinkError);
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

  it("fails closed without a client, account SID, sender, or recipient", async () => {
    await assert.rejects(
      () => new TwilioSink({ accountSid, from, to }).send([{ body: '{"a":1}' }]),
      TwilioSinkConfigError
    );
    await assert.rejects(
      () => new TwilioSink(baseConfig(new FakeClient(), { accountSid: undefined })).send([{ body: '{"a":1}' }]),
      TwilioSinkConfigError
    );
    await assert.rejects(
      () => new TwilioSink(baseConfig(new FakeClient(), { from: undefined })).send([{ body: '{"a":1}' }]),
      TwilioSinkConfigError
    );
    await assert.rejects(
      () => new TwilioSink(baseConfig(new FakeClient(), { to: undefined })).send([{ body: '{"a":1}' }]),
      TwilioSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new TwilioSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new TwilioSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new TwilioSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyTwilioRecordFailure(429), true);
    assert.equal(classifyTwilioRecordFailure(500), true);
    assert.equal(classifyTwilioRecordFailure(503), true);
    assert.equal(classifyTwilioRecordFailure(400), false);
    assert.equal(classifyTwilioRecordFailure(401), false);
    assert.equal(classifyTwilioRecordFailure(404), false);
    assert.equal(TWILIO_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
