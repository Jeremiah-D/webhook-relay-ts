import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  ExpoSink,
  ExpoSinkConfigError,
  ExpoSinkError,
  assertValidExpoSinkConfig,
  buildExpoMessageBody,
  buildExpoRequestHeaders,
  classifyExpoRecordFailure,
  resolveExpoBody,
  resolveExpoNotification,
  resolveExpoRecord,
  ticketToExpoFailedRecord,
  truncateExpoPayload,
  EXPO_SEND_URL,
  EXPO_DEFAULT_PAYLOAD_MAX_CHARS,
  EXPO_FALLBACK_SUMMARY,
  EXPO_DEVICE_NOT_REGISTERED,
  type ExpoMessageClient,
  type ExpoMessagePostRequest,
  type ExpoMessagePostResponse,
  type ExpoPushTicket,
  type ExpoSinkConfig,
} from "../src/expo-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status and ticket per call. */
class FakeClient implements ExpoMessageClient {
  posts: ExpoMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  /** Call-count (0-based) → ticket to return for that post. */
  ticketOn = new Map<number, ExpoPushTicket>();
  async post(request: ExpoMessagePostRequest): Promise<ExpoMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    const ticket = this.ticketOn.get(n);
    return ticket === undefined
      ? { status: this.statusOn.get(n) ?? 200, ticket: { status: "ok", id: `ticket-${n}` } }
      : { status: this.statusOn.get(n) ?? 200, ticket };
  }
}

const to = "ExponentPushToken[xxxxxxxxxxxxxxxxxxxxxx]";

function baseConfig(
  client: ExpoMessageClient,
  extra: Partial<ExpoSinkConfig> = {}
): ExpoSinkConfig {
  return { to, client, ...extra };
}

describe("expo-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidExpoSinkConfig(null, "ExpoSink"), RangeError);
    assert.throws(() => assertValidExpoSinkConfig("x", "ExpoSink"), RangeError);
  });

  it("rejects a malformed push token shape", () => {
    assert.throws(() => assertValidExpoSinkConfig({ to: "" }, "ExpoSink"), RangeError);
    assert.throws(
      () => assertValidExpoSinkConfig({ to: "has space" }, "ExpoSink"),
      RangeError
    );
    assert.throws(() => assertValidExpoSinkConfig({ to: 42 }, "ExpoSink"), RangeError);
  });

  it("rejects a malformed access token shape", () => {
    assert.throws(() => assertValidExpoSinkConfig({ accessToken: "" }, "ExpoSink"), RangeError);
    assert.throws(
      () => assertValidExpoSinkConfig({ accessToken: "has space" }, "ExpoSink"),
      RangeError
    );
    assert.throws(
      () => assertValidExpoSinkConfig({ accessToken: 42 }, "ExpoSink"),
      RangeError
    );
  });

  it("rejects a client without a post function", () => {
    assert.throws(() => assertValidExpoSinkConfig({ client: {} }, "ExpoSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(() => assertValidExpoSinkConfig({ payloadMaxChars: 0 }, "ExpoSink"), RangeError);
    assert.throws(
      () => assertValidExpoSinkConfig({ payloadMaxChars: 2.5 }, "ExpoSink"),
      RangeError
    );
  });

  it("accepts a config with no push token yet (send-time config error)", () => {
    assert.doesNotThrow(() => new ExpoSink({}));
  });
});

describe("expo-sink text derivation", () => {
  it("derives the title from subject only — omitted when absent (never key or traceId)", () => {
    assert.deepEqual(
      resolveExpoNotification({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      { title: "order.created", body: "order.created" }
    );
    assert.deepEqual(resolveExpoNotification({ body: "{}", key: "agg-7", traceId: "t-1" }), {
      body: "agg-7",
    });
    assert.deepEqual(resolveExpoNotification({ body: "{}", traceId: "t-1" }), { body: "t-1" });
    assert.deepEqual(resolveExpoNotification({ body: "{}" }), {
      body: EXPO_FALLBACK_SUMMARY,
    });
  });

  it("derives the body from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveExpoBody({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveExpoBody({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveExpoBody({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveExpoBody({ body: "{}" }), EXPO_FALLBACK_SUMMARY);
    assert.equal(
      resolveExpoBody({ body: "{}", subject: "", key: "", traceId: "" }),
      EXPO_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateExpoPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncateExpoPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.equal(
      buildExpoMessageBody(to, resolveExpoNotification(record), {}),
      JSON.stringify({ to, title: "order.created", body: "order.created" })
    );
    assert.equal(
      buildExpoMessageBody(to, resolveExpoNotification(record), { includePayload: true }, record.body),
      JSON.stringify({ to, title: "order.created", body: `order.created\n\n{"a":1}` })
    );
    assert.equal(
      buildExpoMessageBody(
        to,
        resolveExpoNotification(record),
        { includePayload: true, payloadMaxChars: 3 },
        record.body
      ),
      JSON.stringify({ to, title: "order.created", body: `order.created\n\n{"a… (truncated)` })
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolveExpoRecord({ body: "" }, 2),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("expo-sink wire shape", () => {
  it("exposes the fixed Expo push send endpoint", () => {
    assert.equal(EXPO_SEND_URL, "https://exp.host/--/api/v2/push/send");
  });

  it("builds the flat {to, title, body} envelope — and no credential in the body", () => {
    const parsed = JSON.parse(
      buildExpoMessageBody(to, { title: "order.created", body: "order.created" }, {})
    );
    assert.deepEqual(parsed, {
      to,
      title: "order.created",
      body: "order.created",
    });
    const body = buildExpoMessageBody(to, { title: "s", body: "b" }, {});
    assert.equal(body.includes("Authorization"), false);
    assert.equal(body.includes("Bearer"), false);
    assert.equal(body.includes("accessToken"), false);
    assert.equal(body.includes("access_token"), false);
  });

  it("omits the title from the envelope when the event has no subject", () => {
    const parsed = JSON.parse(
      buildExpoMessageBody(to, resolveExpoNotification({ body: "{}", key: "agg-7" }), {})
    );
    assert.deepEqual(parsed, { to, body: "agg-7" });
    assert.equal("title" in parsed, false);
  });

  it("sends no auth header by default, Bearer only under the accessToken opt-in", () => {
    assert.deepEqual(buildExpoRequestHeaders({}), {});
    assert.deepEqual(buildExpoRequestHeaders({ accessToken: "expo-token-123" }), {
      Authorization: "Bearer expo-token-123",
    });
  });
});

describe("expo-sink ticket mapping", () => {
  it("accepts an ok ticket", () => {
    assert.equal(
      ticketToExpoFailedRecord({ status: "ok", id: "ticket-1" }, 0),
      null
    );
  });

  it("maps a DeviceNotRegistered ticket to non-retryable with the ticket message", () => {
    assert.deepEqual(
      ticketToExpoFailedRecord(
        {
          status: "error",
          message: "The recipient device is not registered with Expo.",
          details: { error: EXPO_DEVICE_NOT_REGISTERED },
        },
        3
      ),
      {
        index: 3,
        errorCode: "DEVICE_NOT_REGISTERED",
        errorMessage: "The recipient device is not registered with Expo.",
        retryable: false,
      }
    );
  });

  it("maps any other ticket error to retryable", () => {
    assert.deepEqual(
      ticketToExpoFailedRecord(
        {
          status: "error",
          message: "An unknown error occurred.",
          details: { error: "MessageTooBig" },
        },
        1
      ),
      {
        index: 1,
        errorCode: "TICKET_ERROR",
        errorMessage: "An unknown error occurred.",
        retryable: true,
      }
    );
    // A ticket error without a message still reports its error name.
    assert.deepEqual(
      ticketToExpoFailedRecord({ status: "error", details: { error: "MessageRateExceeded" } }, 2),
      {
        index: 2,
        errorCode: "TICKET_ERROR",
        errorMessage: "MessageRateExceeded",
        retryable: true,
      }
    );
  });

  it("maps a missing ticket on a 2xx to retryable", () => {
    assert.deepEqual(ticketToExpoFailedRecord(undefined, 0), {
      index: 0,
      errorCode: "TICKET_MISSING",
      errorMessage: "Expo answered 2xx but surfaced no push ticket",
      retryable: true,
    });
  });
});

describe("expo-sink send", () => {
  it("posts one message per record to the fixed endpoint with the Expo envelope, no credential by default", async () => {
    const client = new FakeClient();
    const sink = new ExpoSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
      { body: '{"c":3}', traceId: "t-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 3 });
    assert.equal(client.posts.length, 3);
    assert.deepEqual(client.posts[0], {
      url: EXPO_SEND_URL,
      headers: {},
      body: JSON.stringify({
        to,
        title: "order.created",
        body: "order.created",
      }),
    });
    // No subject → no title key; the key lands in the body.
    assert.deepEqual(JSON.parse(client.posts[1].body), { to, body: "agg-8" });
    // The trace id belongs in the body, never in the title.
    assert.deepEqual(JSON.parse(client.posts[2].body), { to, body: "t-9" });
    for (const post of client.posts) {
      assert.deepEqual(post.headers, {});
      assert.equal(post.body.includes("Authorization"), false);
      assert.equal(post.body.includes("Bearer"), false);
    }
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, sendFailures: 0 });
  });

  it("sends the Bearer header only when the accessToken opt-in is set", async () => {
    const client = new FakeClient();
    const sink = new ExpoSink(baseConfig(client, { accessToken: "expo-token-123" }));
    await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(client.posts[0].headers, {
      Authorization: "Bearer expo-token-123",
    });
    assert.equal(client.posts[0].body.includes("expo-token-123"), false);
  });

  it("treats an ok ticket id as an acceptance receipt, not a delivery result", async () => {
    const client = new FakeClient();
    client.ticketOn.set(0, { status: "ok", id: "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" });
    const sink = new ExpoSink(baseConfig(client));
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 1 });
    assert.deepEqual(sink.stats, { sent: 1, failed: 0, sendFailures: 0 });
  });

  it("applies the payload opt-in truncation on send", async () => {
    const client = new FakeClient();
    const sink = new ExpoSink(baseConfig(client, { includePayload: true, payloadMaxChars: 3 }));
    await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.equal(
      JSON.parse(client.posts[0].body).body,
      `order.created\n\n{"a… (truncated)`
    );
  });

  it("dead-letters a DeviceNotRegistered ticket without retry, retries other ticket errors", async () => {
    const client = new FakeClient();
    client.ticketOn.set(0, {
      status: "error",
      message: "The recipient device is not registered with Expo.",
      details: { error: EXPO_DEVICE_NOT_REGISTERED },
    });
    client.ticketOn.set(1, {
      status: "error",
      message: "An unknown error occurred.",
      details: { error: "MessageTooBig" },
    });
    const sink = new ExpoSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof ExpoSinkError);
        assert.equal(err.failedRecords.length, 2);
        assert.deepEqual(
          err.failedRecords.map((r) => [r.index, r.errorCode, r.retryable]),
          [
            [0, "DEVICE_NOT_REGISTERED", false],
            [1, "TICKET_ERROR", true],
          ]
        );
        return true;
      }
    );
    assert.deepEqual(sink.stats, { sent: 0, failed: 2, sendFailures: 1 });
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new ExpoSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof ExpoSinkError);
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

  it("maps a codeless transport failure to retryable with the client message", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 200);
    client.failOn.set(1, new Error("socket hangup"));
    const sink = new ExpoSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof ExpoSinkError);
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

  it("fails closed without a client or push token", async () => {
    await assert.rejects(
      () => new ExpoSink({ to }).send([{ body: '{"a":1}' }]),
      ExpoSinkConfigError
    );
    await assert.rejects(
      () =>
        new ExpoSink(baseConfig(new FakeClient(), { to: undefined })).send([
          { body: '{"a":1}' },
        ]),
      ExpoSinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new ExpoSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new ExpoSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new ExpoSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyExpoRecordFailure(429), true);
    assert.equal(classifyExpoRecordFailure(500), true);
    assert.equal(classifyExpoRecordFailure(503), true);
    assert.equal(classifyExpoRecordFailure(400), false);
    assert.equal(classifyExpoRecordFailure(401), false);
    assert.equal(classifyExpoRecordFailure(404), false);
    assert.equal(EXPO_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
