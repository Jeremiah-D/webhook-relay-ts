import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  IlertSink,
  IlertSinkConfigError,
  IlertSinkError,
  assertValidIlertSinkConfig,
  buildIlertEventBody,
  classifyIlertEventResponse,
  classifyIlertRecordFailure,
  resolveIlertDetails,
  resolveIlertEventType,
  resolveIlertPriority,
  resolveIlertRecord,
  resolveIlertSummary,
  truncateIlertPayload,
  ILERT_API_BASE_URL,
  ILERT_DEFAULT_EVENT_TYPE,
  ILERT_DEFAULT_PAYLOAD_MAX_CHARS,
  ILERT_DEFAULT_PRIORITY,
  ILERT_EVENTS_PATH_TEMPLATE,
  ILERT_EVENT_TYPES,
  ILERT_FALLBACK_SUMMARY,
  ILERT_JSON_CONTENT_TYPE,
  ILERT_PRIORITIES,
  type IlertEventClient,
  type IlertEventPostRequest,
  type IlertEventPostResponse,
  type IlertSinkConfig,
} from "../src/ilert-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements IlertEventClient {
  posts: IlertEventPostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error text to return for that post. */
  errorOn = new Map<number, string>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: IlertEventPostRequest): Promise<IlertEventPostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return {
      status: this.statusOn.get(n) ?? 200,
      errorMessage: this.errorOn.get(n),
    };
  }
}

function baseConfig(
  client: IlertEventClient,
  extra: Partial<IlertSinkConfig> = {}
): IlertSinkConfig {
  return { client, ...extra };
}

describe("ilert-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidIlertSinkConfig(null, "IlertSink"), RangeError);
    assert.throws(() => assertValidIlertSinkConfig("x", "IlertSink"), RangeError);
  });

  it("rejects a malformed client, payloadMaxChars, priority, and eventType", () => {
    assert.throws(
      () => assertValidIlertSinkConfig(baseConfig(new FakeClient(), { client: {} as never }), "IlertSink"),
      RangeError
    );
    assert.throws(
      () => assertValidIlertSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 0 }), "IlertSink"),
      RangeError
    );
    assert.throws(
      () => assertValidIlertSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 1.5 }), "IlertSink"),
      RangeError
    );
    assert.throws(
      () => assertValidIlertSinkConfig(baseConfig(new FakeClient(), { priority: "MEDIUM" as never }), "IlertSink"),
      RangeError
    );
    assert.throws(
      () => assertValidIlertSinkConfig(baseConfig(new FakeClient(), { priority: "P3" as never }), "IlertSink"),
      RangeError
    );
    assert.throws(
      () => assertValidIlertSinkConfig(baseConfig(new FakeClient(), { priority: "" as never }), "IlertSink"),
      RangeError
    );
    assert.throws(
      () => assertValidIlertSinkConfig(baseConfig(new FakeClient(), { eventType: "alert" as never }), "IlertSink"),
      RangeError
    );
    assert.throws(
      () => assertValidIlertSinkConfig(baseConfig(new FakeClient(), { eventType: "CREATE" as never }), "IlertSink"),
      RangeError
    );
    assert.throws(
      () => assertValidIlertSinkConfig(baseConfig(new FakeClient(), { eventType: "" as never }), "IlertSink"),
      RangeError
    );
    assertValidIlertSinkConfig(baseConfig(new FakeClient(), { priority: "HIGH" }), "IlertSink");
    assertValidIlertSinkConfig(baseConfig(new FakeClient(), { priority: "LOW" }), "IlertSink");
    assertValidIlertSinkConfig(baseConfig(new FakeClient(), { eventType: "ALERT" }), "IlertSink");
    assertValidIlertSinkConfig(baseConfig(new FakeClient(), { eventType: "ACCEPT" }), "IlertSink");
    assertValidIlertSinkConfig(baseConfig(new FakeClient(), { eventType: "RESOLVE" }), "IlertSink");
    assertValidIlertSinkConfig(baseConfig(new FakeClient()), "IlertSink");
  });

  it("has no apiKey field: the client alone holds the alert-source URL", () => {
    // The config type carries no apiKey: a config object that
    // smuggles one in is not part of the sink's contract, and
    // the sink never reads it — the handed request carries no
    // URL at all, let alone a credential (see the send tests).
    const cfg = baseConfig(new FakeClient(), { apiKey: "deadbeef-0000-1111-2222-333344445555" } as never);
    assert.equal((cfg as Record<string, unknown>).apiKey, "deadbeef-0000-1111-2222-333344445555");
    assertValidIlertSinkConfig(cfg, "IlertSink");
  });
});

describe("ilert-sink resolvers", () => {
  it("pins the API base URL and the events path template — integration and key are client-held placeholders, never a real key", () => {
    assert.equal(ILERT_API_BASE_URL, "https://api.ilert.com");
    assert.equal(ILERT_EVENTS_PATH_TEMPLATE, "/api/v1/events/{integration}/{apiKey}");
    assert.equal(ILERT_EVENTS_PATH_TEMPLATE.includes("{integration}"), true);
    assert.equal(ILERT_EVENTS_PATH_TEMPLATE.includes("{apiKey}"), true);
    // No real key, no URL, no credential anywhere in the constants.
    assert.equal(ILERT_API_BASE_URL.includes("apiKey"), false);
    assert.equal(ILERT_EVENTS_PATH_TEMPLATE.includes("deadbeef"), false);
  });

  it("pins the documented priority range and default: HIGH/LOW, default LOW", () => {
    assert.deepEqual([...ILERT_PRIORITIES], ["HIGH", "LOW"]);
    assert.equal(ILERT_DEFAULT_PRIORITY, "LOW");
    assert.equal(resolveIlertPriority({}), "LOW");
    assert.equal(resolveIlertPriority({ priority: "HIGH" }), "HIGH");
    assert.equal(resolveIlertPriority({ priority: "LOW" }), "LOW");
  });

  it("pins the documented event types and default: ALERT/ACCEPT/RESOLVE, default ALERT", () => {
    assert.deepEqual([...ILERT_EVENT_TYPES], ["ALERT", "ACCEPT", "RESOLVE"]);
    assert.equal(ILERT_DEFAULT_EVENT_TYPE, "ALERT");
    assert.equal(resolveIlertEventType({ body: "{}" }, {}), "ALERT");
    assert.equal(resolveIlertEventType({ body: "{}" }, { eventType: "RESOLVE" }), "RESOLVE");
    assert.equal(resolveIlertEventType({ body: "{}", eventType: "ACCEPT" }, { eventType: "RESOLVE" }), "ACCEPT");
    assert.equal(resolveIlertEventType({ body: "{}", eventType: "ALERT" }, {}), "ALERT");
  });

  it("derives the summary from subject, key, then traceId", () => {
    assert.equal(resolveIlertSummary({ body: "{}", subject: "Price drop", key: "k", traceId: "t" }), "Price drop");
    assert.equal(resolveIlertSummary({ body: "{}", key: "order-1", traceId: "t" }), "order-1");
    assert.equal(resolveIlertSummary({ body: "{}", traceId: "trace-9" }), "trace-9");
    assert.equal(resolveIlertSummary({ body: "{}" }), ILERT_FALLBACK_SUMMARY);
  });

  it("does not truncate the summary: the re-checked docs state no summary length limit", () => {
    const long = "s".repeat(5000);
    assert.equal(resolveIlertSummary({ body: "{}", subject: long }), long);
    const body = JSON.parse(buildIlertEventBody({ body: "{}", subject: long }, {}));
    assert.equal(body.summary, long);
    assert.equal(body.summary.length, 5000);
  });

  it("derives details from only the key/traceId identifiers that exist", () => {
    assert.equal(resolveIlertDetails({ body: "{}", key: "order-1", traceId: "trace-9" }, {}), "key=order-1; traceId=trace-9");
    assert.equal(resolveIlertDetails({ body: "{}", key: "order-1" }, {}), "key=order-1");
    assert.equal(resolveIlertDetails({ body: "{}", traceId: "trace-9" }, {}), "traceId=trace-9");
    assert.equal(resolveIlertDetails({ body: "{}" }, {}), undefined);
  });

  it("appends the payload to details only under the opt-in, truncated at the default 2000", () => {
    assert.equal(ILERT_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
    assert.equal(truncateIlertPayload("abcdef", 4), "abcd… (truncated)");
    assert.equal(truncateIlertPayload("abc", 4), "abc");
    const withPayload = resolveIlertDetails({ body: '{"a":1}', subject: "Price drop", key: "k" }, { includePayload: true });
    assert.equal(withPayload, 'key=k\n\n{"a":1}');
    // No identifiers: the payload alone becomes the details.
    assert.equal(resolveIlertDetails({ body: '{"a":1}' }, { includePayload: true }), '{"a":1}');
    const long = resolveIlertDetails({ body: "x".repeat(2001), key: "k1" }, { includePayload: true });
    assert.equal(long, `key=k1\n\n${"x".repeat(2000)}… (truncated)`);
    const short = resolveIlertDetails({ body: "0123456789ABCDEF", key: "k1" }, { includePayload: true, payloadMaxChars: 10 });
    assert.equal(short, "key=k1\n\n0123456789… (truncated)");
  });

  it("builds the event body with eventType/summary/details/alertKey/priority — no credential, no customDetails, no images", () => {
    const body = JSON.parse(
      buildIlertEventBody(
        { body: "{}", subject: "Price drop", key: "order-1", traceId: "trace-9" },
        {}
      )
    );
    assert.equal(body.eventType, "ALERT");
    assert.equal(body.summary, "Price drop");
    assert.equal(body.details, "key=order-1; traceId=trace-9");
    assert.equal(body.alertKey, "order-1");
    assert.equal(body.priority, "LOW");
    assert.equal(body.customDetails, undefined);
    assert.equal(body.images, undefined);
    // No credential ever enters the body.
    assert.equal(JSON.stringify(body).includes("apiKey"), false);
    assert.equal(JSON.stringify(body).includes("Authorization"), false);
    assert.equal(JSON.stringify(body).includes("Bearer"), false);
  });

  it("omits alertKey and details when the event carries no key or identifiers, keeps the rest of the envelope", () => {
    const body = JSON.parse(
      buildIlertEventBody({ body: "{}", subject: "Price drop" }, {})
    );
    assert.equal(body.eventType, "ALERT");
    assert.equal(body.summary, "Price drop");
    assert.equal(body.alertKey, undefined);
    assert.equal("alertKey" in body, false);
    assert.equal(body.details, undefined);
    assert.equal("details" in body, false);
    assert.equal(body.priority, "LOW");
  });

  it("sends the configured priority and event type, including a per-record override", () => {
    const body = JSON.parse(
      buildIlertEventBody(
        { body: '{"a":1}', subject: "Alert", key: "k1" },
        { priority: "HIGH", eventType: "RESOLVE" }
      )
    );
    assert.equal(body.priority, "HIGH");
    assert.equal(body.eventType, "RESOLVE");
    assert.equal(body.alertKey, "k1");
    const overridden = JSON.parse(
      buildIlertEventBody(
        { body: "{}", subject: "Alert", key: "k1", eventType: "ACCEPT" },
        { eventType: "ALERT" }
      )
    );
    assert.equal(overridden.eventType, "ACCEPT");
  });

  it("rejects an empty record body", () => {
    assert.throws(() => resolveIlertRecord({ body: "" }, 0, {}), RangeError);
    assert.deepEqual(resolveIlertRecord({ body: "{}" }, 2, {}), { index: 2 });
  });

  it("rejects ACCEPT and RESOLVE without an alert key — keyless, and under a config default", () => {
    assert.throws(
      () => resolveIlertRecord({ body: "{}", eventType: "ACCEPT" }, 0, {}),
      /requires an alert key/
    );
    assert.throws(
      () => resolveIlertRecord({ body: "{}", eventType: "RESOLVE" }, 1, {}),
      /requires an alert key/
    );
    // A config default of RESOLVE still needs a key on every record.
    assert.throws(
      () => resolveIlertRecord({ body: "{}" }, 2, { eventType: "RESOLVE" }),
      /requires an alert key/
    );
    assert.throws(
      () => resolveIlertRecord({ body: "{}", key: "" }, 3, { eventType: "ACCEPT" }),
      /requires an alert key/
    );
    // ALERT needs no key, and ACCEPT/RESOLVE with a key pass.
    assert.deepEqual(resolveIlertRecord({ body: "{}" }, 4, {}), { index: 4 });
    assert.deepEqual(resolveIlertRecord({ body: "{}", key: "k1", eventType: "ACCEPT" }, 5, {}), { index: 5 });
    assert.deepEqual(resolveIlertRecord({ body: "{}", key: "k1", eventType: "RESOLVE" }, 6, {}), { index: 6 });
    assert.deepEqual(resolveIlertRecord({ body: "{}", key: "k1" }, 7, { eventType: "RESOLVE" }), { index: 7 });
  });

  it("rejects a bad per-record eventType value", () => {
    assert.throws(
      () => resolveIlertRecord({ body: "{}", eventType: "alert" as never }, 0, {}),
      RangeError
    );
  });
});

describe("ilert-sink failure mapping", () => {
  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", () => {
    assert.equal(classifyIlertRecordFailure(429), true);
    assert.equal(classifyIlertRecordFailure(500), true);
    assert.equal(classifyIlertRecordFailure(503), true);
    assert.equal(classifyIlertRecordFailure(400), false);
    assert.equal(classifyIlertRecordFailure(401), false);
    assert.equal(classifyIlertRecordFailure(403), false);
    assert.equal(classifyIlertRecordFailure(404), false);
    assert.equal(classifyIlertRecordFailure(422), false);
  });

  it("accepts any 2xx as an acceptance receipt — 200, 201, and 202 alike, with no receipt id", () => {
    assert.deepEqual(classifyIlertEventResponse({ status: 200 }), { accepted: true });
    assert.deepEqual(classifyIlertEventResponse({ status: 201 }), { accepted: true });
    assert.deepEqual(classifyIlertEventResponse({ status: 202 }), { accepted: true });
  });

  it("maps a non-2xx status to its HTTP code and lane, surfacing the client's error text", () => {
    assert.deepEqual(
      classifyIlertEventResponse({ status: 429, errorMessage: "Rate limit exceeded" }),
      {
        accepted: false,
        errorCode: "HTTP_429",
        retryable: true,
        errorMessage: "Rate limit exceeded",
      }
    );
    assert.deepEqual(classifyIlertEventResponse({ status: 401 }), {
      accepted: false,
      errorCode: "HTTP_401",
      retryable: false,
    });
    assert.deepEqual(
      classifyIlertEventResponse({ status: 400, errorMessage: "Summary is required" }),
      {
        accepted: false,
        errorCode: "HTTP_400",
        retryable: false,
        errorMessage: "Summary is required",
      }
    );
    assert.deepEqual(classifyIlertEventResponse({ status: 500 }), {
      accepted: false,
      errorCode: "HTTP_500",
      retryable: true,
    });
  });
});

describe("ilert-sink send", () => {
  it("posts one event per message with no URL and no credentials in the handed request", async () => {
    const client = new FakeClient();
    const sink = new IlertSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "Price drop", key: "order-1", traceId: "trace-9" },
      { body: '{"b":2}', key: "order-2" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    const first = client.posts[0];
    // The alert-source URL — integration segment and API key
    // alike — is held by the client alone: the sink hands
    // over no URL at all, so there is nothing to leak.
    assert.equal("url" in first, false);
    assert.equal(first.headers["Content-Type"], ILERT_JSON_CONTENT_TYPE);
    assert.equal(first.headers["Authorization"], undefined);
    assert.equal(first.headers["Idempotency-Key"], undefined);
    assert.deepEqual(Object.keys(first.headers), ["Content-Type"]);
    const body = JSON.parse(first.body);
    assert.equal(body.eventType, "ALERT");
    assert.equal(body.summary, "Price drop");
    assert.equal(body.details, "key=order-1; traceId=trace-9");
    assert.equal(body.alertKey, "order-1");
    assert.equal(body.priority, "LOW");
    assert.equal(body.customDetails, undefined);
    assert.equal(body.images, undefined);
    // No credential ever enters the handed request.
    assert.equal(JSON.stringify(first).includes("apiKey"), false);
    assert.equal(JSON.stringify(first).includes("Authorization"), false);
    assert.equal(JSON.stringify(first).includes("Bearer"), false);
    assert.equal(JSON.stringify(first).includes("secret"), false);
    assert.equal(JSON.stringify(first).includes("api.ilert.com"), false);
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("throws with exactly the failed messages and their retry lanes", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 429);
    client.statusOn.set(2, 500);
    const sink = new IlertSink(baseConfig(client));
    await assert.rejects(
      sink.send([
        { body: "{}", key: "k1" },
        { body: "{}", key: "k2" },
        { body: "{}", key: "k3" },
      ]),
      (err: unknown) => {
        assert.ok(err instanceof IlertSinkError);
        assert.deepEqual(
          (err as IlertSinkError).failedRecords.map((f) => [f.index, f.errorCode, f.retryable]),
          [
            [1, "HTTP_429", true],
            [2, "HTTP_500", true],
          ]
        );
        return true;
      }
    );
    assert.deepEqual(sink.stats, { sent: 1, failed: 2, sendFailures: 1 });
  });

  it("treats a bad API key (401) as fail-closed, surfacing the client's error text", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 401);
    client.errorOn.set(0, "API key is not valid");
    const sink = new IlertSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as IlertSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_401");
        assert.equal(failed[0].statusCode, 401);
        assert.equal(failed[0].retryable, false);
        assert.equal(failed[0].errorMessage, "API key is not valid");
        return true;
      }
    );
  });

  it("treats a bad request (400) as fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 400);
    client.errorOn.set(0, "Summary is required");
    const sink = new IlertSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as IlertSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_400");
        assert.equal(failed[0].retryable, false);
        assert.equal(failed[0].errorMessage, "Summary is required");
        return true;
      }
    );
  });

  it("treats a client throw as a retryable transport failure", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hang up"));
    const sink = new IlertSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as IlertSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(failed[0].retryable, true);
        assert.equal(failed[0].errorMessage, "socket hang up");
        return true;
      }
    );
  });

  it("throws a config error with no client, mapped non_retryable", async () => {
    const sink = new IlertSink({});
    await assert.rejects(sink.send([{ body: "{}", key: "k1" }]), IlertSinkConfigError);
    assert.equal(classifyFailure(new IlertSinkConfigError("no client injected")).failureClass, "non_retryable");
  });

  it("dry-runs with zero client I/O and untouched stats", async () => {
    const client = new FakeClient();
    const sink = new IlertSink(baseConfig(client, { dryRun: true }));
    const result = await sink.send([{ body: "{}", subject: "Price drop" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("dry-runs still validate the config and the records", async () => {
    const client = new FakeClient();
    const sink = new IlertSink(baseConfig(client, { dryRun: true }));
    await assert.rejects(sink.send([{ body: "" }]), RangeError);
    assert.equal(client.posts.length, 0);
    // A keyless ACCEPT is caught in rehearsal, before any POST.
    await assert.rejects(sink.send([{ body: "{}", eventType: "ACCEPT" }]), RangeError);
    assert.equal(client.posts.length, 0);
    assert.throws(
      () => new IlertSink({ priority: "MEDIUM" as never, dryRun: true }),
      RangeError
    );
    assert.throws(
      () => new IlertSink({ eventType: "CREATE" as never, dryRun: true }),
      RangeError
    );
  });

  it("refuses to send a keyless ACCEPT or RESOLVE even outside dry-run mode", async () => {
    const client = new FakeClient();
    const sink = new IlertSink(baseConfig(client));
    await assert.rejects(sink.send([{ body: "{}", eventType: "RESOLVE" }]), RangeError);
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("appends the payload to details under the opt-in, truncated at the default 2000", async () => {
    const client = new FakeClient();
    const sink = new IlertSink(baseConfig(client, { includePayload: true, payloadMaxChars: 10 }));
    await sink.send([{ body: "0123456789ABCDEF", subject: "Alert", key: "k1" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.details, "key=k1\n\n0123456789… (truncated)");
    assert.equal(body.summary, "Alert");

    const defaultClient = new FakeClient();
    const defaultSink = new IlertSink(baseConfig(defaultClient, { includePayload: true }));
    await defaultSink.send([{ body: "x".repeat(2001), subject: "Alert", key: "k1" }]);
    const defaultBody = JSON.parse(defaultClient.posts[0].body);
    assert.equal(defaultBody.details, `key=k1\n\n${"x".repeat(2000)}… (truncated)`);
  });

  it("omits the payload by default — details carry the identifiers only", async () => {
    const client = new FakeClient();
    const sink = new IlertSink(baseConfig(client));
    await sink.send([{ body: '{"secret":"s3cr3t"}', subject: "Alert", key: "k1" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.details, "key=k1");
    assert.equal(JSON.stringify(body).includes("s3cr3t"), false);
  });

  it("sends a configured priority and event type and omits alertKey for a keyless ALERT", async () => {
    const client = new FakeClient();
    const sink = new IlertSink(baseConfig(client, { priority: "HIGH", eventType: "ALERT" }));
    await sink.send([{ body: "{}", subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.priority, "HIGH");
    assert.equal(body.eventType, "ALERT");
    assert.equal(body.alertKey, undefined);
    assert.equal("alertKey" in body, false);
    assert.equal(body.details, undefined);
  });

  it("sends ACCEPT and RESOLVE with the alert key when one exists", async () => {
    const client = new FakeClient();
    const sink = new IlertSink(baseConfig(client));
    await sink.send([
      { body: "{}", key: "k1", eventType: "ACCEPT" },
      { body: "{}", key: "k1", eventType: "RESOLVE" },
    ]);
    assert.equal(client.posts.length, 2);
    assert.equal(JSON.parse(client.posts[0].body).eventType, "ACCEPT");
    assert.equal(JSON.parse(client.posts[0].body).alertKey, "k1");
    assert.equal(JSON.parse(client.posts[1].body).eventType, "RESOLVE");
    assert.equal(JSON.parse(client.posts[1].body).alertKey, "k1");
  });

  it("sends a later same-key ALERT after a RESOLVE as a normal event — a resolved alert is never reopened by the sink", async () => {
    const client = new FakeClient();
    const sink = new IlertSink(baseConfig(client));
    const result = await sink.send([
      { body: "{}", key: "k1", eventType: "RESOLVE" },
      { body: "{}", key: "k1", eventType: "ALERT" },
    ]);
    // No sink-side suppression or state: both events go out
    // with the same alertKey, and ilert creates a new alert
    // for the later one instead of reopening the resolved one.
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    assert.equal(JSON.parse(client.posts[1].body).eventType, "ALERT");
    assert.equal(JSON.parse(client.posts[1].body).alertKey, "k1");
  });

  it("falls back to 'webhook event' for a sourceless event", async () => {
    const client = new FakeClient();
    const sink = new IlertSink(baseConfig(client));
    await sink.send([{ body: "{}" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.eventType, "ALERT");
    assert.equal(body.summary, "webhook event");
    assert.equal(body.alertKey, undefined);
    assert.equal(body.details, undefined);
  });
});
