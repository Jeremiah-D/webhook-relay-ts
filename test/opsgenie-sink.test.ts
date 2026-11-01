import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  OpsgenieSink,
  OpsgenieSinkConfigError,
  OpsgenieSinkError,
  assertValidOpsgenieSinkConfig,
  buildOpsgenieAlertBody,
  classifyOpsgenieAlertResponse,
  classifyOpsgenieRecordFailure,
  resolveOpsgenieDescription,
  resolveOpsgenieDetails,
  resolveOpsgeniePriority,
  resolveOpsgenieRecord,
  resolveOpsgenieSummary,
  truncateOpsgenieMessage,
  truncateOpsgeniePayload,
  OPSGENIE_ALERTS_URL,
  OPSGENIE_ALIAS_MAX_CHARS,
  OPSGENIE_API_BASE_URL,
  OPSGENIE_DEFAULT_PAYLOAD_MAX_CHARS,
  OPSGENIE_DEFAULT_PRIORITY,
  OPSGENIE_FALLBACK_SUMMARY,
  OPSGENIE_JSON_CONTENT_TYPE,
  OPSGENIE_MESSAGE_MAX_CHARS,
  OPSGENIE_PRIORITIES,
  OPSGENIE_SOURCE,
  type OpsgenieAlertClient,
  type OpsgenieAlertPostRequest,
  type OpsgenieAlertPostResponse,
  type OpsgenieSinkConfig,
} from "../src/opsgenie-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status and request id per call. */
class FakeClient implements OpsgenieAlertClient {
  posts: OpsgenieAlertPostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → request id to return for that post. */
  requestIdOn = new Map<number, string>();
  /** Call-count (0-based) → error text to return for that post. */
  errorOn = new Map<number, string>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: OpsgenieAlertPostRequest): Promise<OpsgenieAlertPostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return {
      status: this.statusOn.get(n) ?? 202,
      requestId: this.requestIdOn.get(n) ?? `req-${n + 1}`,
      errorMessage: this.errorOn.get(n),
    };
  }
}

function baseConfig(
  client: OpsgenieAlertClient,
  extra: Partial<OpsgenieSinkConfig> = {}
): OpsgenieSinkConfig {
  return { client, ...extra };
}

describe("opsgenie-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidOpsgenieSinkConfig(null, "OpsgenieSink"), RangeError);
    assert.throws(() => assertValidOpsgenieSinkConfig("x", "OpsgenieSink"), RangeError);
  });

  it("rejects a malformed client, payloadMaxChars, and priority", () => {
    assert.throws(
      () => assertValidOpsgenieSinkConfig(baseConfig(new FakeClient(), { client: {} as never }), "OpsgenieSink"),
      RangeError
    );
    assert.throws(
      () => assertValidOpsgenieSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 0 }), "OpsgenieSink"),
      RangeError
    );
    assert.throws(
      () => assertValidOpsgenieSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 1.5 }), "OpsgenieSink"),
      RangeError
    );
    assert.throws(
      () => assertValidOpsgenieSinkConfig(baseConfig(new FakeClient(), { priority: "P0" as never }), "OpsgenieSink"),
      RangeError
    );
    assert.throws(
      () => assertValidOpsgenieSinkConfig(baseConfig(new FakeClient(), { priority: "critical" as never }), "OpsgenieSink"),
      RangeError
    );
    assert.throws(
      () => assertValidOpsgenieSinkConfig(baseConfig(new FakeClient(), { priority: "" as never }), "OpsgenieSink"),
      RangeError
    );
    assertValidOpsgenieSinkConfig(baseConfig(new FakeClient(), { priority: "P1" }), "OpsgenieSink");
    assertValidOpsgenieSinkConfig(baseConfig(new FakeClient(), { priority: "P5" }), "OpsgenieSink");
    assertValidOpsgenieSinkConfig(baseConfig(new FakeClient()), "OpsgenieSink");
  });

  it("has no apiKey field: the client alone holds the key", () => {
    // The config type carries no apiKey: a config object that
    // smuggles one in is not part of the sink's contract, and
    // the sink never reads it — the handed request carries no
    // credential either way (see the send tests).
    const cfg = baseConfig(new FakeClient(), { apiKey: "eb243592-faa2-4ba2-a551q-1afdf565c889" } as never);
    assert.equal((cfg as Record<string, unknown>).apiKey, "eb243592-faa2-4ba2-a551q-1afdf565c889");
    assertValidOpsgenieSinkConfig(cfg, "OpsgenieSink");
  });
});

describe("opsgenie-sink resolvers", () => {
  it("uses the fixed US host URL with no credential in it — the client adds the GenieKey header", () => {
    assert.equal(OPSGENIE_API_BASE_URL, "https://api.opsgenie.com");
    assert.equal(OPSGENIE_ALERTS_URL, "https://api.opsgenie.com/v2/alerts");
    assert.equal(OPSGENIE_ALERTS_URL.includes("api.eu.opsgenie.com"), false);
    assert.equal(OPSGENIE_ALERTS_URL.includes("GenieKey"), false);
    assert.equal(OPSGENIE_ALERTS_URL.includes("apiKey"), false);
    assert.equal(OPSGENIE_SOURCE, "webhook-relay");
    assert.equal(OPSGENIE_MESSAGE_MAX_CHARS, 130);
    assert.equal(OPSGENIE_ALIAS_MAX_CHARS, 512);
  });

  it("pins the documented priority range and default: P1–P5, default P3", () => {
    assert.deepEqual([...OPSGENIE_PRIORITIES], ["P1", "P2", "P3", "P4", "P5"]);
    assert.equal(OPSGENIE_DEFAULT_PRIORITY, "P3");
    assert.equal(resolveOpsgeniePriority({}), "P3");
    assert.equal(resolveOpsgeniePriority({ priority: "P1" }), "P1");
    assert.equal(resolveOpsgeniePriority({ priority: "P5" }), "P5");
  });

  it("derives the summary from subject, key, then traceId", () => {
    assert.equal(resolveOpsgenieSummary({ body: "{}", subject: "Price drop", key: "k", traceId: "t" }), "Price drop");
    assert.equal(resolveOpsgenieSummary({ body: "{}", key: "order-1", traceId: "t" }), "order-1");
    assert.equal(resolveOpsgenieSummary({ body: "{}", traceId: "trace-9" }), "trace-9");
    assert.equal(resolveOpsgenieSummary({ body: "{}" }), OPSGENIE_FALLBACK_SUMMARY);
  });

  it("truncates the message to exactly the official 130 characters, with no marker", () => {
    assert.equal(truncateOpsgenieMessage("short"), "short");
    assert.equal(truncateOpsgenieMessage("x".repeat(130)), "x".repeat(130));
    const long = truncateOpsgenieMessage("x".repeat(131));
    assert.equal(long, "x".repeat(130));
    assert.equal(long.length, 130);
    // No marker: a marker would push the message over the limit.
    assert.equal(long.includes("truncated"), false);
  });

  it("derives the description from the summary in full, payload appended only under the opt-in", () => {
    assert.equal(resolveOpsgenieDescription({ body: "{}", subject: "Price drop", key: "k" }, {}), "Price drop");
    assert.equal(resolveOpsgenieDescription({ body: "{}", key: "order-1" }, {}), "order-1");
    assert.equal(resolveOpsgenieDescription({ body: "{}" }, {}), OPSGENIE_FALLBACK_SUMMARY);
    // The description keeps the full summary even when the
    // message is truncated to 130.
    const longSubject = "s".repeat(200);
    assert.equal(resolveOpsgenieDescription({ body: "{}", subject: longSubject }, {}), longSubject);
    const withPayload = resolveOpsgenieDescription({ body: '{"a":1}', subject: "Price drop" }, { includePayload: true });
    assert.equal(withPayload, 'Price drop\n\n{"a":1}');
    assert.equal(OPSGENIE_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
    assert.equal(truncateOpsgeniePayload("abcdef", 4), "abcd… (truncated)");
    assert.equal(truncateOpsgeniePayload("abc", 4), "abc");
    const long = resolveOpsgenieDescription({ body: "x".repeat(2001), subject: "Alert" }, { includePayload: true });
    assert.equal(long, `Alert\n\n${"x".repeat(2000)}… (truncated)`);
    const short = resolveOpsgenieDescription({ body: "0123456789ABCDEF", subject: "Alert" }, { includePayload: true, payloadMaxChars: 10 });
    assert.equal(short, "Alert\n\n0123456789… (truncated)");
  });

  it("derives details with only the key/traceId identifiers that exist", () => {
    assert.deepEqual(resolveOpsgenieDetails({ body: "{}", key: "order-1", traceId: "trace-9" }), { key: "order-1", traceId: "trace-9" });
    assert.deepEqual(resolveOpsgenieDetails({ body: "{}", key: "order-1" }), { key: "order-1" });
    assert.deepEqual(resolveOpsgenieDetails({ body: "{}", traceId: "trace-9" }), { traceId: "trace-9" });
    assert.deepEqual(resolveOpsgenieDetails({ body: "{}" }), {});
  });

  it("builds the alert body with message/alias/description/details/priority/source — no credential, no responders", () => {
    const body = JSON.parse(
      buildOpsgenieAlertBody(
        { body: "{}", subject: "Price drop", key: "order-1", traceId: "trace-9" },
        {}
      )
    );
    assert.equal(body.message, "Price drop");
    assert.equal(body.alias, "order-1");
    assert.equal(body.description, "Price drop");
    assert.deepEqual(body.details, { key: "order-1", traceId: "trace-9" });
    assert.equal(body.priority, "P3");
    assert.equal(body.source, "webhook-relay");
    assert.equal(body.responders, undefined);
    assert.equal(body.visibleTo, undefined);
    assert.equal(body.actions, undefined);
    assert.equal(body.tags, undefined);
    // No credential ever enters the body.
    assert.equal(JSON.stringify(body).includes("GenieKey"), false);
    assert.equal(JSON.stringify(body).includes("apiKey"), false);
    assert.equal(JSON.stringify(body).includes("Authorization"), false);
    assert.equal(JSON.stringify(body).includes("Bearer"), false);
  });

  it("omits alias when the event carries no key, keeps the rest of the envelope", () => {
    const body = JSON.parse(
      buildOpsgenieAlertBody({ body: "{}", subject: "Price drop" }, {})
    );
    assert.equal(body.message, "Price drop");
    assert.equal(body.alias, undefined);
    assert.equal("alias" in body, false);
    assert.equal(body.description, "Price drop");
    assert.deepEqual(body.details, {});
    assert.equal(body.priority, "P3");
    assert.equal(body.source, "webhook-relay");
  });

  it("truncates a long message in the body but keeps the full summary in the description", () => {
    const subject = "s".repeat(200);
    const body = JSON.parse(buildOpsgenieAlertBody({ body: "{}", subject }, {}));
    assert.equal(body.message, "s".repeat(130));
    assert.equal(body.message.length, 130);
    assert.equal(body.description, subject);
  });

  it("sends the configured priority, appends the payload to the description under the opt-in", () => {
    const body = JSON.parse(
      buildOpsgenieAlertBody(
        { body: '{"a":1}', subject: "Alert", key: "k1" },
        { priority: "P1", includePayload: true }
      )
    );
    assert.equal(body.priority, "P1");
    assert.equal(body.description, 'Alert\n\n{"a":1}');
    assert.equal(body.alias, "k1");
  });

  it("rejects an empty record body", () => {
    assert.throws(() => resolveOpsgenieRecord({ body: "" }, 0), RangeError);
    assert.deepEqual(resolveOpsgenieRecord({ body: "{}" }, 2), { index: 2 });
  });
});

describe("opsgenie-sink failure mapping", () => {
  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", () => {
    assert.equal(classifyOpsgenieRecordFailure(429), true);
    assert.equal(classifyOpsgenieRecordFailure(500), true);
    assert.equal(classifyOpsgenieRecordFailure(503), true);
    assert.equal(classifyOpsgenieRecordFailure(400), false);
    assert.equal(classifyOpsgenieRecordFailure(401), false);
    assert.equal(classifyOpsgenieRecordFailure(403), false);
    assert.equal(classifyOpsgenieRecordFailure(404), false);
    assert.equal(classifyOpsgenieRecordFailure(422), false);
  });

  it("accepts any 2xx as an acceptance receipt — 202, 200, and 201 alike", () => {
    assert.deepEqual(classifyOpsgenieAlertResponse({ status: 202, requestId: "43a29c5c-3dbf-4fa4-9c26-f4f71023e120" }), { accepted: true });
    assert.deepEqual(classifyOpsgenieAlertResponse({ status: 200, requestId: "req-1" }), { accepted: true });
    assert.deepEqual(classifyOpsgenieAlertResponse({ status: 201 }), { accepted: true });
    // A 2xx without a request id is still an acceptance: the
    // status is the acceptance credential, just with no
    // later tracking.
    assert.deepEqual(classifyOpsgenieAlertResponse({ status: 202 }), { accepted: true });
  });

  it("maps a non-2xx status to its HTTP code and lane, surfacing the client's error text", () => {
    assert.deepEqual(
      classifyOpsgenieAlertResponse({ status: 429, errorMessage: "Rate limit exceeded" }),
      {
        accepted: false,
        errorCode: "HTTP_429",
        retryable: true,
        errorMessage: "Rate limit exceeded",
      }
    );
    assert.deepEqual(classifyOpsgenieAlertResponse({ status: 401 }), {
      accepted: false,
      errorCode: "HTTP_401",
      retryable: false,
    });
    assert.deepEqual(
      classifyOpsgenieAlertResponse({ status: 400, errorMessage: "Message is mandatory" }),
      {
        accepted: false,
        errorCode: "HTTP_400",
        retryable: false,
        errorMessage: "Message is mandatory",
      }
    );
    assert.deepEqual(classifyOpsgenieAlertResponse({ status: 500 }), {
      accepted: false,
      errorCode: "HTTP_500",
      retryable: true,
    });
  });
});

describe("opsgenie-sink send", () => {
  it("posts one alert per message with no credentials and no Idempotency-Key header", async () => {
    const client = new FakeClient();
    const sink = new OpsgenieSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "Price drop", key: "order-1", traceId: "trace-9" },
      { body: '{"b":2}', key: "order-2" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2, requestIds: ["req-1", "req-2"] });
    assert.equal(client.posts.length, 2);
    const first = client.posts[0];
    assert.equal(first.url, "https://api.opsgenie.com/v2/alerts");
    assert.equal(first.url.includes("eu.opsgenie.com"), false);
    assert.equal(first.url.includes("GenieKey"), false);
    assert.equal(first.headers["Content-Type"], OPSGENIE_JSON_CONTENT_TYPE);
    assert.equal(first.headers["Authorization"], undefined);
    // The docs do not verify Idempotency-Key for this
    // endpoint, so the sink deliberately sends none — the
    // alias is the retry's de-duplication key instead.
    assert.equal(first.headers["Idempotency-Key"], undefined);
    assert.deepEqual(Object.keys(first.headers), ["Content-Type"]);
    const body = JSON.parse(first.body);
    assert.equal(body.message, "Price drop");
    assert.equal(body.alias, "order-1");
    assert.equal(body.description, "Price drop");
    assert.deepEqual(body.details, { key: "order-1", traceId: "trace-9" });
    assert.equal(body.priority, "P3");
    assert.equal(body.source, "webhook-relay");
    assert.equal(body.responders, undefined);
    assert.equal(body.visibleTo, undefined);
    // No credential ever enters the handed request.
    assert.equal(JSON.stringify(first).includes("GenieKey"), false);
    assert.equal(JSON.stringify(first).includes("apiKey"), false);
    assert.equal(JSON.stringify(first).includes("Authorization"), false);
    assert.equal(JSON.stringify(first).includes("Bearer"), false);
    assert.equal(JSON.stringify(first).includes("secret"), false);
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("throws with exactly the failed messages and their retry lanes", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 429);
    client.statusOn.set(2, 500);
    const sink = new OpsgenieSink(baseConfig(client));
    await assert.rejects(
      sink.send([
        { body: "{}", key: "k1" },
        { body: "{}", key: "k2" },
        { body: "{}", key: "k3" },
      ]),
      (err: unknown) => {
        assert.ok(err instanceof OpsgenieSinkError);
        assert.deepEqual(
          (err as OpsgenieSinkError).failedRecords.map((f) => [f.index, f.errorCode, f.retryable]),
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
    const sink = new OpsgenieSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as OpsgenieSinkError).failedRecords;
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
    client.errorOn.set(0, "Message is mandatory");
    const sink = new OpsgenieSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as OpsgenieSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_400");
        assert.equal(failed[0].retryable, false);
        assert.equal(failed[0].errorMessage, "Message is mandatory");
        return true;
      }
    );
  });

  it("treats a client throw as a retryable transport failure", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hang up"));
    const sink = new OpsgenieSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as OpsgenieSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(failed[0].retryable, true);
        assert.equal(failed[0].errorMessage, "socket hang up");
        return true;
      }
    );
  });

  it("throws a config error with no client, mapped non_retryable", async () => {
    const sink = new OpsgenieSink({});
    await assert.rejects(sink.send([{ body: "{}", key: "k1" }]), OpsgenieSinkConfigError);
    assert.equal(classifyFailure(new OpsgenieSinkConfigError("no client injected")).failureClass, "non_retryable");
  });

  it("dry-runs with zero client I/O and untouched stats", async () => {
    const client = new FakeClient();
    const sink = new OpsgenieSink(baseConfig(client, { dryRun: true }));
    const result = await sink.send([{ body: "{}", subject: "Price drop" }]);
    assert.deepEqual(result, { ok: true, sent: 0, requestIds: [], dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("dry-runs still validate the config and the records", async () => {
    const client = new FakeClient();
    const sink = new OpsgenieSink(baseConfig(client, { dryRun: true }));
    await assert.rejects(sink.send([{ body: "" }]), RangeError);
    assert.equal(client.posts.length, 0);
    assert.throws(
      () => new OpsgenieSink({ priority: "P0" as never, dryRun: true }),
      RangeError
    );
  });

  it("appends the payload to the description under the opt-in, truncated at the default 2000", async () => {
    const client = new FakeClient();
    const sink = new OpsgenieSink(baseConfig(client, { includePayload: true, payloadMaxChars: 10 }));
    await sink.send([{ body: "0123456789ABCDEF", subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.description, "Alert\n\n0123456789… (truncated)");
    assert.equal(body.message, "Alert");

    const defaultClient = new FakeClient();
    const defaultSink = new OpsgenieSink(baseConfig(defaultClient, { includePayload: true }));
    await defaultSink.send([{ body: "x".repeat(2001), subject: "Alert" }]);
    const defaultBody = JSON.parse(defaultClient.posts[0].body);
    assert.equal(defaultBody.description, `Alert\n\n${"x".repeat(2000)}… (truncated)`);
  });

  it("omits the payload by default — description carries the summary only", async () => {
    const client = new FakeClient();
    const sink = new OpsgenieSink(baseConfig(client));
    await sink.send([{ body: '{"secret":"s3cr3t"}', subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.description, "Alert");
    assert.equal(JSON.stringify(body).includes("s3cr3t"), false);
  });

  it("sends a configured priority and omits alias for a keyless event", async () => {
    const client = new FakeClient();
    const sink = new OpsgenieSink(baseConfig(client, { priority: "P1" }));
    await sink.send([{ body: "{}", subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.priority, "P1");
    assert.equal(body.alias, undefined);
    assert.equal("alias" in body, false);
    assert.deepEqual(body.details, {});
  });

  it("collects request ids in send order across messages, skipping a 2xx with no id", async () => {
    const client = new FakeClient();
    client.requestIdOn.set(0, "req-first");
    client.requestIdOn.set(1, "");
    const sink = new OpsgenieSink(baseConfig(client));
    const result = await sink.send([
      { body: "{}", key: "k1" },
      { body: "{}", key: "k2" },
      { body: "{}", key: "k3" },
    ]);
    // The second message was accepted (202) but reported no
    // request id, so it contributes no entry — it is still
    // accepted, just untracked.
    assert.deepEqual(result, { ok: true, sent: 3, requestIds: ["req-first", "req-3"] });
  });

  it("falls back to 'webhook event' for a sourceless event", async () => {
    const client = new FakeClient();
    const sink = new OpsgenieSink(baseConfig(client));
    await sink.send([{ body: "{}" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.message, "webhook event");
    assert.equal(body.description, "webhook event");
    assert.equal(body.alias, undefined);
    assert.deepEqual(body.details, {});
  });
});
