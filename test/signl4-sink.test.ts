import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  Signl4Sink,
  Signl4SinkConfigError,
  Signl4SinkError,
  assertValidSignl4SinkConfig,
  buildSignl4AlertBody,
  classifySignl4AlertResponse,
  classifySignl4RecordFailure,
  resolveSignl4Message,
  resolveSignl4Record,
  resolveSignl4Status,
  resolveSignl4Title,
  truncateSignl4Payload,
  SIGNL4_API_BASE_URL,
  SIGNL4_DEFAULT_PAYLOAD_MAX_CHARS,
  SIGNL4_DEFAULT_STATUS,
  SIGNL4_FALLBACK_TITLE,
  SIGNL4_JSON_CONTENT_TYPE,
  SIGNL4_SOURCE_SYSTEM,
  SIGNL4_STATUSES,
  SIGNL4_SUCCESS_STATUSES,
  SIGNL4_WEBHOOK_URL_TEMPLATE,
  type Signl4AlertClient,
  type Signl4AlertPostRequest,
  type Signl4AlertPostResponse,
  type Signl4SinkConfig,
} from "../src/signl4-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements Signl4AlertClient {
  posts: Signl4AlertPostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → event id to return for that post. */
  eventIdOn = new Map<number, string>();
  /** Call-count (0-based) → error text to return for that post. */
  errorOn = new Map<number, string>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: Signl4AlertPostRequest): Promise<Signl4AlertPostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return {
      status: this.statusOn.get(n) ?? 200,
      eventId: this.eventIdOn.get(n),
      errorMessage: this.errorOn.get(n),
    };
  }
}

function baseConfig(
  client: Signl4AlertClient,
  extra: Partial<Signl4SinkConfig> = {}
): Signl4SinkConfig {
  return { client, ...extra };
}

describe("signl4-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidSignl4SinkConfig(null, "Signl4Sink"), RangeError);
    assert.throws(() => assertValidSignl4SinkConfig("x", "Signl4Sink"), RangeError);
  });

  it("rejects a malformed client, payloadMaxChars, and status", () => {
    assert.throws(
      () => assertValidSignl4SinkConfig(baseConfig(new FakeClient(), { client: {} as never }), "Signl4Sink"),
      RangeError
    );
    assert.throws(
      () => assertValidSignl4SinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 0 }), "Signl4Sink"),
      RangeError
    );
    assert.throws(
      () => assertValidSignl4SinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 1.5 }), "Signl4Sink"),
      RangeError
    );
    assert.throws(
      () => assertValidSignl4SinkConfig(baseConfig(new FakeClient(), { status: "NEW" as never }), "Signl4Sink"),
      RangeError
    );
    assert.throws(
      () => assertValidSignl4SinkConfig(baseConfig(new FakeClient(), { status: "acknowledged" as never }), "Signl4Sink"),
      RangeError
    );
    assert.throws(
      () => assertValidSignl4SinkConfig(baseConfig(new FakeClient(), { status: "" as never }), "Signl4Sink"),
      RangeError
    );
    assertValidSignl4SinkConfig(baseConfig(new FakeClient(), { status: "new" }), "Signl4Sink");
    assertValidSignl4SinkConfig(baseConfig(new FakeClient(), { status: "resolved" }), "Signl4Sink");
    assertValidSignl4SinkConfig(baseConfig(new FakeClient()), "Signl4Sink");
  });

  it("has no apiKey field: the client alone holds the team webhook URL", () => {
    // The config type carries no apiKey: a config object that
    // smuggles one in is not part of the sink's contract, and
    // the sink never reads it — the handed request carries no
    // URL at all, let alone a credential (see the send tests).
    const cfg = baseConfig(new FakeClient(), { apiKey: "deadbeef-0000-1111-2222-333344445555" } as never);
    assert.equal((cfg as Record<string, unknown>).apiKey, "deadbeef-0000-1111-2222-333344445555");
    assertValidSignl4SinkConfig(cfg, "Signl4Sink");
  });
});

describe("signl4-sink resolvers", () => {
  it("pins the webhook URL template, the connect host, the source system, and the documented statuses and default", () => {
    assert.equal(SIGNL4_WEBHOOK_URL_TEMPLATE, "https://connect.signl4.com/webhook/{team-secret}");
    assert.equal(SIGNL4_API_BASE_URL, "https://connect.signl4.com");
    assert.equal(SIGNL4_SOURCE_SYSTEM, "webhook-relay");
    assert.deepEqual([...SIGNL4_STATUSES], ["new", "resolved"]);
    assert.deepEqual([...SIGNL4_SUCCESS_STATUSES], [200, 201]);
    assert.equal(SIGNL4_DEFAULT_STATUS, "new");
    assert.equal(resolveSignl4Status({ body: "{}" }, {}), "new");
    assert.equal(resolveSignl4Status({ body: "{}" }, { status: "resolved" }), "resolved");
    assert.equal(resolveSignl4Status({ body: "{}", status: "new" }, { status: "resolved" }), "new");
    assert.equal(resolveSignl4Status({ body: "{}", status: "resolved" }, {}), "resolved");
  });

  it("derives the title from subject, key, then traceId", () => {
    assert.equal(resolveSignl4Title({ body: "{}", subject: "Payments failing", key: "k", traceId: "t" }), "Payments failing");
    assert.equal(resolveSignl4Title({ body: "{}", key: "order-1", traceId: "t" }), "order-1");
    assert.equal(resolveSignl4Title({ body: "{}", traceId: "trace-9" }), "trace-9");
    assert.equal(resolveSignl4Title({ body: "{}" }), SIGNL4_FALLBACK_TITLE);
  });

  it("does not truncate the title: the re-checked docs state no length limit", () => {
    const long = "s".repeat(5000);
    assert.equal(resolveSignl4Title({ body: "{}", subject: long }), long);
    const body = JSON.parse(buildSignl4AlertBody({ body: "{}", subject: long, key: long }, {}));
    assert.equal(body.Title, long);
    assert.equal(body.Title.length, 5000);
  });

  it("derives the message from the key/traceId identifiers, and never leaves it empty", () => {
    assert.equal(
      resolveSignl4Message({ body: "{}", key: "order-1", traceId: "trace-9" }, {}),
      "key=order-1; traceId=trace-9"
    );
    assert.equal(resolveSignl4Message({ body: "{}", key: "order-1" }, {}), "key=order-1");
    assert.equal(resolveSignl4Message({ body: "{}", traceId: "trace-9" }, {}), "traceId=trace-9");
    // No identifiers: falls back to the title text, never empty.
    assert.equal(
      resolveSignl4Message({ body: "{}", subject: "Payments failing" }, {}),
      "Payments failing"
    );
    assert.equal(resolveSignl4Message({ body: "{}" }, {}), SIGNL4_FALLBACK_TITLE);
    assert.notEqual(resolveSignl4Message({ body: "{}" }, {}), "");
  });

  it("does not truncate the message identifiers or fallback text: the re-checked docs state no length limit", () => {
    const long = "s".repeat(5000);
    assert.equal(resolveSignl4Message({ body: "{}", key: long }, {}), `key=${long}`);
    assert.equal(resolveSignl4Message({ body: "{}", subject: long }, {}), long);
  });

  it("appends the payload body only under the opt-in, truncated at the default 2000", () => {
    assert.equal(SIGNL4_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
    assert.equal(truncateSignl4Payload("abcdef", 4), "abcd… (truncated)");
    assert.equal(truncateSignl4Payload("abc", 4), "abc");
    const withPayload = resolveSignl4Message(
      { body: '{"a":1}', subject: "Payments failing", key: "k" },
      { includePayload: true }
    );
    assert.equal(withPayload, 'key=k\n\n{"a":1}');
    // No identifiers: the payload body is appended after the title-text fallback.
    assert.equal(
      resolveSignl4Message({ body: '{"a":1}', subject: "Payments failing" }, { includePayload: true }),
      'Payments failing\n\n{"a":1}'
    );
    const long = resolveSignl4Message({ body: "x".repeat(2001), key: "k1" }, { includePayload: true });
    assert.equal(long, `key=k1\n\n${"x".repeat(2000)}… (truncated)`);
    const short = resolveSignl4Message(
      { body: "0123456789ABCDEF", key: "k1" },
      { includePayload: true, payloadMaxChars: 10 }
    );
    assert.equal(short, "key=k1\n\n0123456789… (truncated)");
  });

  it("builds the alert body with Title/Message/X-S4-ExternalID/X-S4-Status/X-S4-SourceSystem — no credential, no Severity/Service/Location", () => {
    const body = JSON.parse(
      buildSignl4AlertBody(
        { body: "{}", subject: "Payments failing", key: "order-1", traceId: "trace-9" },
        {}
      )
    );
    assert.equal(body.Title, "Payments failing");
    assert.equal(body.Message, "key=order-1; traceId=trace-9");
    assert.equal(body["X-S4-ExternalID"], "order-1");
    assert.equal(body["X-S4-Status"], "new");
    assert.equal(body["X-S4-SourceSystem"], "webhook-relay");
    assert.equal(body.Severity, undefined);
    assert.equal(body.Service, undefined);
    assert.equal(body.Location, undefined);
    assert.equal("Severity" in body, false);
    assert.equal("Service" in body, false);
    assert.equal("Location" in body, false);
    // No credential ever enters the body.
    assert.equal(JSON.stringify(body).includes("apiKey"), false);
    assert.equal(JSON.stringify(body).includes("Authorization"), false);
    assert.equal(JSON.stringify(body).includes("Bearer"), false);
  });

  it("omits X-S4-ExternalID when the event carries no key, and falls the message back to the title text", () => {
    const body = JSON.parse(
      buildSignl4AlertBody({ body: "{}", subject: "Payments failing" }, {})
    );
    assert.equal(body.Title, "Payments failing");
    assert.equal(body.Message, "Payments failing");
    assert.equal(body["X-S4-Status"], "new");
    assert.equal(body["X-S4-ExternalID"], undefined);
    assert.equal("X-S4-ExternalID" in body, false);
  });

  it("sends a configured status, including a per-record override", () => {
    const body = JSON.parse(
      buildSignl4AlertBody(
        { body: '{"a":1}', subject: "Alert", key: "k1" },
        { status: "resolved" }
      )
    );
    assert.equal(body["X-S4-Status"], "resolved");
    assert.equal(body["X-S4-ExternalID"], "k1");
    const overridden = JSON.parse(
      buildSignl4AlertBody(
        { body: "{}", subject: "Alert", key: "k1", status: "new" },
        { status: "resolved" }
      )
    );
    assert.equal(overridden["X-S4-Status"], "new");
  });

  it("rejects an empty record body", () => {
    assert.throws(() => resolveSignl4Record({ body: "" }, 0, {}), RangeError);
    assert.deepEqual(resolveSignl4Record({ body: "{}" }, 2, {}), { index: 2 });
  });

  it("rejects a bad per-record status value", () => {
    assert.throws(
      () => resolveSignl4Record({ body: "{}", status: "acknowledged" as never }, 0, {}),
      RangeError
    );
  });

  it("rejects a resolved without a key — per-record override and config default alike", () => {
    assert.throws(
      () => resolveSignl4Record({ body: "{}", status: "resolved" }, 0, {}),
      RangeError
    );
    assert.throws(
      () => resolveSignl4Record({ body: "{}" }, 0, { status: "resolved" }),
      RangeError
    );
    // A keyed resolve passes validation.
    assert.deepEqual(resolveSignl4Record({ body: "{}", key: "k1", status: "resolved" }, 0, {}), { index: 0 });
    assert.deepEqual(resolveSignl4Record({ body: "{}", key: "k1" }, 0, { status: "resolved" }), { index: 0 });
  });

  it("does not reject a keyless new — the reference pins the key rule for resolved only", () => {
    assert.deepEqual(resolveSignl4Record({ body: "{}" }, 0, {}), { index: 0 });
    assert.deepEqual(resolveSignl4Record({ body: "{}", status: "new" }, 0, {}), { index: 0 });
  });
});

describe("signl4-sink failure mapping", () => {
  it("maps 429 and 5xx to retryable, other non-200/201 to fail-closed — including the documented 400 and 404", () => {
    assert.equal(classifySignl4RecordFailure(429), true);
    assert.equal(classifySignl4RecordFailure(500), true);
    assert.equal(classifySignl4RecordFailure(503), true);
    assert.equal(classifySignl4RecordFailure(400), false);
    assert.equal(classifySignl4RecordFailure(401), false);
    assert.equal(classifySignl4RecordFailure(403), false);
    assert.equal(classifySignl4RecordFailure(404), false);
    assert.equal(classifySignl4RecordFailure(413), false);
    assert.equal(classifySignl4RecordFailure(422), false);
  });

  it("accepts exactly 200 and 201 as acceptance receipts — the two documented success statuses", () => {
    assert.deepEqual(classifySignl4AlertResponse({ status: 200 }), { accepted: true });
    assert.deepEqual(classifySignl4AlertResponse({ status: 201 }), { accepted: true });
    // A 202 or 204 is not a documented success status: fail-closed.
    assert.deepEqual(classifySignl4AlertResponse({ status: 202 }), {
      accepted: false,
      errorCode: "HTTP_202",
      retryable: false,
    });
    assert.deepEqual(classifySignl4AlertResponse({ status: 204 }), {
      accepted: false,
      errorCode: "HTTP_204",
      retryable: false,
    });
  });

  it("maps a non-200/201 status to its HTTP code and lane, surfacing the client's error text", () => {
    assert.deepEqual(
      classifySignl4AlertResponse({ status: 429, errorMessage: "Rate limit exceeded" }),
      {
        accepted: false,
        errorCode: "HTTP_429",
        retryable: true,
        errorMessage: "Rate limit exceeded",
      }
    );
    assert.deepEqual(
      classifySignl4AlertResponse({ status: 400, errorMessage: "Invalid body" }),
      {
        accepted: false,
        errorCode: "HTTP_400",
        retryable: false,
        errorMessage: "Invalid body",
      }
    );
    assert.deepEqual(classifySignl4AlertResponse({ status: 404 }), {
      accepted: false,
      errorCode: "HTTP_404",
      retryable: false,
    });
    assert.deepEqual(
      classifySignl4AlertResponse({ status: 500, errorMessage: "Internal error" }),
      {
        accepted: false,
        errorCode: "HTTP_500",
        retryable: true,
        errorMessage: "Internal error",
      }
    );
  });
});

describe("signl4-sink send", () => {
  it("posts one alert per message with no URL and no credentials in the handed request", async () => {
    const client = new FakeClient();
    const sink = new Signl4Sink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "Payments failing", key: "order-1", traceId: "trace-9" },
      { body: '{"b":2}', key: "order-2" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2, eventIds: [] });
    assert.equal(client.posts.length, 2);
    const first = client.posts[0];
    // The team webhook URL — team secret alike — is held
    // by the client alone: the sink hands over no URL at
    // all, so there is nothing to leak.
    assert.equal("url" in first, false);
    assert.equal(first.headers["Content-Type"], SIGNL4_JSON_CONTENT_TYPE);
    assert.equal(first.headers["Authorization"], undefined);
    assert.equal(first.headers["Idempotency-Key"], undefined);
    assert.deepEqual(Object.keys(first.headers), ["Content-Type"]);
    const body = JSON.parse(first.body);
    assert.equal(body.Title, "Payments failing");
    assert.equal(body.Message, "key=order-1; traceId=trace-9");
    assert.equal(body["X-S4-ExternalID"], "order-1");
    assert.equal(body["X-S4-Status"], "new");
    assert.equal(body["X-S4-SourceSystem"], "webhook-relay");
    // No credential ever enters the handed request.
    assert.equal(JSON.stringify(first).includes("apiKey"), false);
    assert.equal(JSON.stringify(first).includes("Authorization"), false);
    assert.equal(JSON.stringify(first).includes("Bearer"), false);
    assert.equal(JSON.stringify(first).includes("secret"), false);
    assert.equal(JSON.stringify(first).includes("connect.signl4.com"), false);
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("accepts a 201 as an acceptance receipt and collects its eventId", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 201);
    client.eventIdOn.set(0, "2517274649921256161_619fe071-2c15-4258-b939-8a3abccb233e");
    const sink = new Signl4Sink(baseConfig(client));
    const result = await sink.send([{ body: "{}", key: "k1" }]);
    assert.deepEqual(result, {
      ok: true,
      sent: 1,
      eventIds: ["2517274649921256161_619fe071-2c15-4258-b939-8a3abccb233e"],
    });
  });

  it("accepts a 200 without an eventId — the status is the acceptance credential", async () => {
    const client = new FakeClient();
    const sink = new Signl4Sink(baseConfig(client));
    const result = await sink.send([{ body: "{}", key: "k1" }]);
    assert.deepEqual(result, { ok: true, sent: 1, eventIds: [] });
  });

  it("throws with exactly the failed messages and their retry lanes", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 429);
    client.statusOn.set(2, 500);
    const sink = new Signl4Sink(baseConfig(client));
    await assert.rejects(
      sink.send([
        { body: "{}", key: "k1" },
        { body: "{}", key: "k2" },
        { body: "{}", key: "k3" },
      ]),
      (err: unknown) => {
        assert.ok(err instanceof Signl4SinkError);
        assert.deepEqual(
          (err as Signl4SinkError).failedRecords.map((f) => [f.index, f.errorCode, f.retryable]),
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

  it("treats an invalid body (400) as fail-closed, surfacing the client's error text", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 400);
    client.errorOn.set(0, "Invalid body");
    const sink = new Signl4Sink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as Signl4SinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_400");
        assert.equal(failed[0].statusCode, 400);
        assert.equal(failed[0].retryable, false);
        assert.equal(failed[0].errorMessage, "Invalid body");
        return true;
      }
    );
  });

  it("treats a wrong webhook URL (404) as fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 404);
    client.errorOn.set(0, "Webhook URL is wrong");
    const sink = new Signl4Sink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as Signl4SinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_404");
        assert.equal(failed[0].retryable, false);
        assert.equal(failed[0].errorMessage, "Webhook URL is wrong");
        return true;
      }
    );
  });

  it("treats a client throw as a retryable transport failure", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hang up"));
    const sink = new Signl4Sink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as Signl4SinkError).failedRecords;
        assert.equal(failed[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(failed[0].retryable, true);
        assert.equal(failed[0].errorMessage, "socket hang up");
        return true;
      }
    );
  });

  it("throws a config error with no client, mapped non_retryable", async () => {
    const sink = new Signl4Sink({});
    await assert.rejects(sink.send([{ body: "{}", key: "k1" }]), Signl4SinkConfigError);
    assert.equal(classifyFailure(new Signl4SinkConfigError("no client injected")).failureClass, "non_retryable");
  });

  it("dry-runs with zero client I/O and untouched stats", async () => {
    const client = new FakeClient();
    const sink = new Signl4Sink(baseConfig(client, { dryRun: true }));
    const result = await sink.send([{ body: "{}", subject: "Payments failing" }]);
    assert.deepEqual(result, { ok: true, sent: 0, eventIds: [], dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("dry-runs still validate the config and the records, including the resolve key rule", async () => {
    const client = new FakeClient();
    const sink = new Signl4Sink(baseConfig(client, { dryRun: true }));
    await assert.rejects(sink.send([{ body: "" }]), RangeError);
    assert.equal(client.posts.length, 0);
    await assert.rejects(sink.send([{ body: "{}", status: "acknowledged" as never }]), RangeError);
    assert.equal(client.posts.length, 0);
    await assert.rejects(sink.send([{ body: "{}", status: "resolved" }]), RangeError);
    assert.equal(client.posts.length, 0);
    assert.throws(
      () => new Signl4Sink({ status: "acknowledged" as never, dryRun: true }),
      RangeError
    );
  });

  it("appends the payload body under the opt-in, truncated at the default 2000", async () => {
    const client = new FakeClient();
    const sink = new Signl4Sink(baseConfig(client, { includePayload: true, payloadMaxChars: 10 }));
    await sink.send([{ body: "0123456789ABCDEF", subject: "Alert", key: "k1" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.Message, "key=k1\n\n0123456789… (truncated)");
    assert.equal(body.Title, "Alert");

    const defaultClient = new FakeClient();
    const defaultSink = new Signl4Sink(baseConfig(defaultClient, { includePayload: true }));
    await defaultSink.send([{ body: "x".repeat(2001), subject: "Alert", key: "k1" }]);
    const defaultBody = JSON.parse(defaultClient.posts[0].body);
    assert.equal(defaultBody.Message, `key=k1\n\n${"x".repeat(2000)}… (truncated)`);
  });

  it("omits the payload body by default — Message carries the identifiers only", async () => {
    const client = new FakeClient();
    const sink = new Signl4Sink(baseConfig(client));
    await sink.send([{ body: '{"secret":"s3cr3t"}', subject: "Alert", key: "k1" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.Message, "key=k1");
    assert.equal(JSON.stringify(body).includes("s3cr3t"), false);
  });

  it("sends a configured status and omits X-S4-ExternalID for a keyless new", async () => {
    const client = new FakeClient();
    const sink = new Signl4Sink(baseConfig(client, { status: "new" }));
    await sink.send([{ body: "{}", subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body["X-S4-Status"], "new");
    assert.equal(body["X-S4-ExternalID"], undefined);
    assert.equal("X-S4-ExternalID" in body, false);
    assert.equal(body.Message, "Alert");
  });

  it("sends a resolve with the same X-S4-ExternalID as a normal alert — SIGNL4 resolves the alert, the sink tracks nothing", async () => {
    const client = new FakeClient();
    const sink = new Signl4Sink(baseConfig(client));
    const result = await sink.send([
      { body: "{}", key: "k1", status: "new" },
      { body: "{}", key: "k1", status: "resolved" },
    ]);
    // No sink-side suppression or state: both alerts go out
    // with the same external id, and SIGNL4 resolves the
    // alert for the later one instead of creating a new one.
    assert.deepEqual(result, { ok: true, sent: 2, eventIds: [] });
    assert.equal(client.posts.length, 2);
    assert.equal(JSON.parse(client.posts[0].body)["X-S4-Status"], "new");
    assert.equal(JSON.parse(client.posts[1].body)["X-S4-Status"], "resolved");
    assert.equal(JSON.parse(client.posts[1].body)["X-S4-ExternalID"], "k1");
    // The resolve still carries the derived title and a
    // non-empty message: the reference says they are not
    // required for a resolve, not that they must be omitted.
    assert.equal(JSON.parse(client.posts[1].body).Title, "k1");
    assert.equal(JSON.parse(client.posts[1].body).Message, "key=k1");
  });

  it("falls back to 'webhook event' for a sourceless event, with a non-empty message", async () => {
    const client = new FakeClient();
    const sink = new Signl4Sink(baseConfig(client));
    await sink.send([{ body: "{}" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body["X-S4-Status"], "new");
    assert.equal(body.Title, "webhook event");
    assert.equal(body.Message, "webhook event");
    assert.equal(body["X-S4-ExternalID"], undefined);
  });
});
