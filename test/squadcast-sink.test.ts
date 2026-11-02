import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  SquadcastSink,
  SquadcastSinkConfigError,
  SquadcastSinkError,
  assertValidSquadcastSinkConfig,
  buildSquadcastIncidentBody,
  classifySquadcastIncidentResponse,
  classifySquadcastRecordFailure,
  resolveSquadcastDescription,
  resolveSquadcastMessage,
  resolveSquadcastRecord,
  resolveSquadcastStatus,
  truncateSquadcastPayload,
  SQUADCAST_API_BASE_URL,
  SQUADCAST_DEFAULT_PAYLOAD_MAX_CHARS,
  SQUADCAST_DEFAULT_STATUS,
  SQUADCAST_FALLBACK_MESSAGE,
  SQUADCAST_JSON_CONTENT_TYPE,
  SQUADCAST_STATUSES,
  type SquadcastIncidentClient,
  type SquadcastIncidentPostRequest,
  type SquadcastIncidentPostResponse,
  type SquadcastSinkConfig,
} from "../src/squadcast-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements SquadcastIncidentClient {
  posts: SquadcastIncidentPostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error text to return for that post. */
  errorOn = new Map<number, string>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: SquadcastIncidentPostRequest): Promise<SquadcastIncidentPostResponse> {
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
  client: SquadcastIncidentClient,
  extra: Partial<SquadcastSinkConfig> = {}
): SquadcastSinkConfig {
  return { client, ...extra };
}

describe("squadcast-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidSquadcastSinkConfig(null, "SquadcastSink"), RangeError);
    assert.throws(() => assertValidSquadcastSinkConfig("x", "SquadcastSink"), RangeError);
  });

  it("rejects a malformed client, payloadMaxChars, and status", () => {
    assert.throws(
      () => assertValidSquadcastSinkConfig(baseConfig(new FakeClient(), { client: {} as never }), "SquadcastSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSquadcastSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 0 }), "SquadcastSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSquadcastSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 1.5 }), "SquadcastSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSquadcastSinkConfig(baseConfig(new FakeClient(), { status: "TRIGGER" as never }), "SquadcastSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSquadcastSinkConfig(baseConfig(new FakeClient(), { status: "acknowledge" as never }), "SquadcastSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSquadcastSinkConfig(baseConfig(new FakeClient(), { status: "" as never }), "SquadcastSink"),
      RangeError
    );
    assertValidSquadcastSinkConfig(baseConfig(new FakeClient(), { status: "trigger" }), "SquadcastSink");
    assertValidSquadcastSinkConfig(baseConfig(new FakeClient(), { status: "resolve" }), "SquadcastSink");
    assertValidSquadcastSinkConfig(baseConfig(new FakeClient()), "SquadcastSink");
  });

  it("has no apiKey field: the client alone holds the per-service Incident Webhook URL", () => {
    // The config type carries no apiKey: a config object that
    // smuggles one in is not part of the sink's contract, and
    // the sink never reads it — the handed request carries no
    // URL at all, let alone a credential (see the send tests).
    const cfg = baseConfig(new FakeClient(), { apiKey: "deadbeef-0000-1111-2222-333344445555" } as never);
    assert.equal((cfg as Record<string, unknown>).apiKey, "deadbeef-0000-1111-2222-333344445555");
    assertValidSquadcastSinkConfig(cfg, "SquadcastSink");
  });
});

describe("squadcast-sink resolvers", () => {
  it("pins the API base host and the documented statuses and default: two values, default trigger", () => {
    assert.equal(SQUADCAST_API_BASE_URL, "https://api.squadcast.com");
    assert.deepEqual([...SQUADCAST_STATUSES], ["trigger", "resolve"]);
    assert.equal(SQUADCAST_DEFAULT_STATUS, "trigger");
    assert.equal(resolveSquadcastStatus({ body: "{}" }, {}), "trigger");
    assert.equal(resolveSquadcastStatus({ body: "{}" }, { status: "resolve" }), "resolve");
    assert.equal(resolveSquadcastStatus({ body: "{}", status: "trigger" }, { status: "resolve" }), "trigger");
    assert.equal(resolveSquadcastStatus({ body: "{}", status: "resolve" }, {}), "resolve");
  });

  it("derives the message from subject, key, then traceId", () => {
    assert.equal(resolveSquadcastMessage({ body: "{}", subject: "Payments failing", key: "k", traceId: "t" }), "Payments failing");
    assert.equal(resolveSquadcastMessage({ body: "{}", key: "order-1", traceId: "t" }), "order-1");
    assert.equal(resolveSquadcastMessage({ body: "{}", traceId: "trace-9" }), "trace-9");
    assert.equal(resolveSquadcastMessage({ body: "{}" }), SQUADCAST_FALLBACK_MESSAGE);
  });

  it("does not truncate the message: the re-checked docs state no length limit", () => {
    const long = "s".repeat(5000);
    assert.equal(resolveSquadcastMessage({ body: "{}", subject: long }), long);
    const body = JSON.parse(buildSquadcastIncidentBody({ body: "{}", subject: long, key: long }, {}));
    assert.equal(body.message, long);
    assert.equal(body.message.length, 5000);
  });

  it("derives the description from the key/traceId identifiers, and never leaves it empty", () => {
    assert.equal(
      resolveSquadcastDescription({ body: "{}", key: "order-1", traceId: "trace-9" }, {}),
      "key=order-1; traceId=trace-9"
    );
    assert.equal(resolveSquadcastDescription({ body: "{}", key: "order-1" }, {}), "key=order-1");
    assert.equal(resolveSquadcastDescription({ body: "{}", traceId: "trace-9" }, {}), "traceId=trace-9");
    // No identifiers: falls back to the message text, never empty.
    assert.equal(
      resolveSquadcastDescription({ body: "{}", subject: "Payments failing" }, {}),
      "Payments failing"
    );
    assert.equal(resolveSquadcastDescription({ body: "{}" }, {}), SQUADCAST_FALLBACK_MESSAGE);
    assert.notEqual(resolveSquadcastDescription({ body: "{}" }, {}), "");
  });

  it("does not truncate the description identifiers or fallback text: the re-checked docs state no length limit", () => {
    const long = "s".repeat(5000);
    assert.equal(resolveSquadcastDescription({ body: "{}", key: long }, {}), `key=${long}`);
    assert.equal(resolveSquadcastDescription({ body: "{}", subject: long }, {}), long);
  });

  it("appends the payload body only under the opt-in, truncated at the default 2000", () => {
    assert.equal(SQUADCAST_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
    assert.equal(truncateSquadcastPayload("abcdef", 4), "abcd… (truncated)");
    assert.equal(truncateSquadcastPayload("abc", 4), "abc");
    const withPayload = resolveSquadcastDescription(
      { body: '{"a":1}', subject: "Payments failing", key: "k" },
      { includePayload: true }
    );
    assert.equal(withPayload, 'key=k\n\n{"a":1}');
    // No identifiers: the payload body is appended after the message-text fallback.
    assert.equal(
      resolveSquadcastDescription({ body: '{"a":1}', subject: "Payments failing" }, { includePayload: true }),
      'Payments failing\n\n{"a":1}'
    );
    const long = resolveSquadcastDescription({ body: "x".repeat(2001), key: "k1" }, { includePayload: true });
    assert.equal(long, `key=k1\n\n${"x".repeat(2000)}… (truncated)`);
    const short = resolveSquadcastDescription(
      { body: "0123456789ABCDEF", key: "k1" },
      { includePayload: true, payloadMaxChars: 10 }
    );
    assert.equal(short, "key=k1\n\n0123456789… (truncated)");
  });

  it("builds the incident body with message/description/status/event_id — no credential, no tags", () => {
    const body = JSON.parse(
      buildSquadcastIncidentBody(
        { body: "{}", subject: "Payments failing", key: "order-1", traceId: "trace-9" },
        {}
      )
    );
    assert.equal(body.message, "Payments failing");
    assert.equal(body.description, "key=order-1; traceId=trace-9");
    assert.equal(body.status, "trigger");
    assert.equal(body.event_id, "order-1");
    assert.equal(body.tags, undefined);
    assert.equal("tags" in body, false);
    // No credential ever enters the body.
    assert.equal(JSON.stringify(body).includes("apiKey"), false);
    assert.equal(JSON.stringify(body).includes("Authorization"), false);
    assert.equal(JSON.stringify(body).includes("Bearer"), false);
  });

  it("omits event_id when the event carries no key, and falls the description back to the message text", () => {
    const body = JSON.parse(
      buildSquadcastIncidentBody({ body: "{}", subject: "Payments failing" }, {})
    );
    assert.equal(body.message, "Payments failing");
    assert.equal(body.description, "Payments failing");
    assert.equal(body.status, "trigger");
    assert.equal(body.event_id, undefined);
    assert.equal("event_id" in body, false);
  });

  it("sends a configured status, including a per-record override", () => {
    const body = JSON.parse(
      buildSquadcastIncidentBody(
        { body: '{"a":1}', subject: "Alert", key: "k1" },
        { status: "resolve" }
      )
    );
    assert.equal(body.status, "resolve");
    assert.equal(body.event_id, "k1");
    const overridden = JSON.parse(
      buildSquadcastIncidentBody(
        { body: "{}", subject: "Alert", key: "k1", status: "trigger" },
        { status: "resolve" }
      )
    );
    assert.equal(overridden.status, "trigger");
  });

  it("rejects an empty record body", () => {
    assert.throws(() => resolveSquadcastRecord({ body: "" }, 0, {}), RangeError);
    assert.deepEqual(resolveSquadcastRecord({ body: "{}" }, 2, {}), { index: 2 });
  });

  it("rejects a bad per-record status value", () => {
    assert.throws(
      () => resolveSquadcastRecord({ body: "{}", status: "acknowledge" as never }, 0, {}),
      RangeError
    );
  });

  it("rejects a resolve without a key — per-record override and config default alike", () => {
    assert.throws(
      () => resolveSquadcastRecord({ body: "{}", status: "resolve" }, 0, {}),
      RangeError
    );
    assert.throws(
      () => resolveSquadcastRecord({ body: "{}" }, 0, { status: "resolve" }),
      RangeError
    );
    // A keyed resolve passes validation.
    assert.deepEqual(resolveSquadcastRecord({ body: "{}", key: "k1", status: "resolve" }, 0, {}), { index: 0 });
    assert.deepEqual(resolveSquadcastRecord({ body: "{}", key: "k1" }, 0, { status: "resolve" }), { index: 0 });
  });

  it("does not reject a keyless trigger — the reference pins the key rule for resolve only", () => {
    assert.deepEqual(resolveSquadcastRecord({ body: "{}" }, 0, {}), { index: 0 });
    assert.deepEqual(resolveSquadcastRecord({ body: "{}", status: "trigger" }, 0, {}), { index: 0 });
  });
});

describe("squadcast-sink failure mapping", () => {
  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed — including the documented 413", () => {
    assert.equal(classifySquadcastRecordFailure(429), true);
    assert.equal(classifySquadcastRecordFailure(500), true);
    assert.equal(classifySquadcastRecordFailure(503), true);
    assert.equal(classifySquadcastRecordFailure(400), false);
    assert.equal(classifySquadcastRecordFailure(401), false);
    assert.equal(classifySquadcastRecordFailure(403), false);
    assert.equal(classifySquadcastRecordFailure(404), false);
    assert.equal(classifySquadcastRecordFailure(413), false);
    assert.equal(classifySquadcastRecordFailure(422), false);
  });

  it("accepts any 2xx as an acceptance receipt — 200 and 201 alike", () => {
    assert.deepEqual(classifySquadcastIncidentResponse({ status: 200 }), { accepted: true });
    assert.deepEqual(classifySquadcastIncidentResponse({ status: 201 }), { accepted: true });
    assert.deepEqual(classifySquadcastIncidentResponse({ status: 202 }), { accepted: true });
    assert.deepEqual(classifySquadcastIncidentResponse({ status: 204 }), { accepted: true });
  });

  it("maps a non-2xx status to its HTTP code and lane, surfacing the client's error text", () => {
    assert.deepEqual(
      classifySquadcastIncidentResponse({ status: 429, errorMessage: "Rate limit exceeded" }),
      {
        accepted: false,
        errorCode: "HTTP_429",
        retryable: true,
        errorMessage: "Rate limit exceeded",
      }
    );
    assert.deepEqual(
      classifySquadcastIncidentResponse({ status: 413, errorMessage: "Payload Too Large" }),
      {
        accepted: false,
        errorCode: "HTTP_413",
        retryable: false,
        errorMessage: "Payload Too Large",
      }
    );
    assert.deepEqual(classifySquadcastIncidentResponse({ status: 404 }), {
      accepted: false,
      errorCode: "HTTP_404",
      retryable: false,
    });
    assert.deepEqual(
      classifySquadcastIncidentResponse({ status: 400, errorMessage: "Bad request" }),
      {
        accepted: false,
        errorCode: "HTTP_400",
        retryable: false,
        errorMessage: "Bad request",
      }
    );
    assert.deepEqual(classifySquadcastIncidentResponse({ status: 500 }), {
      accepted: false,
      errorCode: "HTTP_500",
      retryable: true,
    });
  });
});

describe("squadcast-sink send", () => {
  it("posts one incident per message with no URL and no credentials in the handed request", async () => {
    const client = new FakeClient();
    const sink = new SquadcastSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "Payments failing", key: "order-1", traceId: "trace-9" },
      { body: '{"b":2}', key: "order-2" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    const first = client.posts[0];
    // The Incident Webhook URL — per-service key/UUID alike —
    // is held by the client alone: the sink hands over no
    // URL at all, so there is nothing to leak.
    assert.equal("url" in first, false);
    assert.equal(first.headers["Content-Type"], SQUADCAST_JSON_CONTENT_TYPE);
    assert.equal(first.headers["Authorization"], undefined);
    assert.equal(first.headers["Idempotency-Key"], undefined);
    assert.deepEqual(Object.keys(first.headers), ["Content-Type"]);
    const body = JSON.parse(first.body);
    assert.equal(body.message, "Payments failing");
    assert.equal(body.description, "key=order-1; traceId=trace-9");
    assert.equal(body.status, "trigger");
    assert.equal(body.event_id, "order-1");
    assert.equal(body.tags, undefined);
    // No credential ever enters the handed request.
    assert.equal(JSON.stringify(first).includes("apiKey"), false);
    assert.equal(JSON.stringify(first).includes("Authorization"), false);
    assert.equal(JSON.stringify(first).includes("Bearer"), false);
    assert.equal(JSON.stringify(first).includes("secret"), false);
    assert.equal(JSON.stringify(first).includes("api.squadcast.com"), false);
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("accepts a 201 as an acceptance receipt — the success status is any 2xx, a slot convention", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 201);
    const sink = new SquadcastSink(baseConfig(client));
    const result = await sink.send([{ body: "{}", key: "k1" }]);
    assert.deepEqual(result, { ok: true, sent: 1 });
  });

  it("throws with exactly the failed messages and their retry lanes", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 429);
    client.statusOn.set(2, 500);
    const sink = new SquadcastSink(baseConfig(client));
    await assert.rejects(
      sink.send([
        { body: "{}", key: "k1" },
        { body: "{}", key: "k2" },
        { body: "{}", key: "k3" },
      ]),
      (err: unknown) => {
        assert.ok(err instanceof SquadcastSinkError);
        assert.deepEqual(
          (err as SquadcastSinkError).failedRecords.map((f) => [f.index, f.errorCode, f.retryable]),
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

  it("treats a payload over the documented 30KB limit (413) as fail-closed, surfacing the client's error text", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 413);
    client.errorOn.set(0, "Payload Too Large");
    const sink = new SquadcastSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as SquadcastSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_413");
        assert.equal(failed[0].statusCode, 413);
        assert.equal(failed[0].retryable, false);
        assert.equal(failed[0].errorMessage, "Payload Too Large");
        return true;
      }
    );
  });

  it("treats a bad request (400) as fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 400);
    client.errorOn.set(0, "Bad request");
    const sink = new SquadcastSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as SquadcastSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_400");
        assert.equal(failed[0].retryable, false);
        assert.equal(failed[0].errorMessage, "Bad request");
        return true;
      }
    );
  });

  it("treats a client throw as a retryable transport failure", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hang up"));
    const sink = new SquadcastSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as SquadcastSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(failed[0].retryable, true);
        assert.equal(failed[0].errorMessage, "socket hang up");
        return true;
      }
    );
  });

  it("throws a config error with no client, mapped non_retryable", async () => {
    const sink = new SquadcastSink({});
    await assert.rejects(sink.send([{ body: "{}", key: "k1" }]), SquadcastSinkConfigError);
    assert.equal(classifyFailure(new SquadcastSinkConfigError("no client injected")).failureClass, "non_retryable");
  });

  it("dry-runs with zero client I/O and untouched stats", async () => {
    const client = new FakeClient();
    const sink = new SquadcastSink(baseConfig(client, { dryRun: true }));
    const result = await sink.send([{ body: "{}", subject: "Payments failing" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("dry-runs still validate the config and the records, including the resolve key rule", async () => {
    const client = new FakeClient();
    const sink = new SquadcastSink(baseConfig(client, { dryRun: true }));
    await assert.rejects(sink.send([{ body: "" }]), RangeError);
    assert.equal(client.posts.length, 0);
    await assert.rejects(sink.send([{ body: "{}", status: "acknowledge" as never }]), RangeError);
    assert.equal(client.posts.length, 0);
    await assert.rejects(sink.send([{ body: "{}", status: "resolve" }]), RangeError);
    assert.equal(client.posts.length, 0);
    assert.throws(
      () => new SquadcastSink({ status: "acknowledge" as never, dryRun: true }),
      RangeError
    );
  });

  it("appends the payload body under the opt-in, truncated at the default 2000", async () => {
    const client = new FakeClient();
    const sink = new SquadcastSink(baseConfig(client, { includePayload: true, payloadMaxChars: 10 }));
    await sink.send([{ body: "0123456789ABCDEF", subject: "Alert", key: "k1" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.description, "key=k1\n\n0123456789… (truncated)");
    assert.equal(body.message, "Alert");

    const defaultClient = new FakeClient();
    const defaultSink = new SquadcastSink(baseConfig(defaultClient, { includePayload: true }));
    await defaultSink.send([{ body: "x".repeat(2001), subject: "Alert", key: "k1" }]);
    const defaultBody = JSON.parse(defaultClient.posts[0].body);
    assert.equal(defaultBody.description, `key=k1\n\n${"x".repeat(2000)}… (truncated)`);
  });

  it("omits the payload body by default — description carries the identifiers only", async () => {
    const client = new FakeClient();
    const sink = new SquadcastSink(baseConfig(client));
    await sink.send([{ body: '{"secret":"s3cr3t"}', subject: "Alert", key: "k1" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.description, "key=k1");
    assert.equal(JSON.stringify(body).includes("s3cr3t"), false);
  });

  it("sends a configured status and omits event_id for a keyless trigger", async () => {
    const client = new FakeClient();
    const sink = new SquadcastSink(baseConfig(client, { status: "trigger" }));
    await sink.send([{ body: "{}", subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.status, "trigger");
    assert.equal(body.event_id, undefined);
    assert.equal("event_id" in body, false);
    assert.equal(body.description, "Alert");
  });

  it("sends a resolve with the same event_id as a normal incident — Squadcast resolves the incident, the sink tracks nothing", async () => {
    const client = new FakeClient();
    const sink = new SquadcastSink(baseConfig(client));
    const result = await sink.send([
      { body: "{}", key: "k1", status: "trigger" },
      { body: "{}", key: "k1", status: "resolve" },
    ]);
    // No sink-side suppression or state: both incidents go out
    // with the same event_id, and Squadcast resolves the
    // incident for the later one instead of creating a new one.
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    assert.equal(JSON.parse(client.posts[0].body).status, "trigger");
    assert.equal(JSON.parse(client.posts[1].body).status, "resolve");
    assert.equal(JSON.parse(client.posts[1].body).event_id, "k1");
    // The resolve still carries the derived message and a
    // non-empty description: the reference says they are not
    // required for a resolve, not that they must be omitted.
    assert.equal(JSON.parse(client.posts[1].body).message, "k1");
    assert.equal(JSON.parse(client.posts[1].body).description, "key=k1");
  });

  it("falls back to 'webhook event' for a sourceless event, with a non-empty description", async () => {
    const client = new FakeClient();
    const sink = new SquadcastSink(baseConfig(client));
    await sink.send([{ body: "{}" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.status, "trigger");
    assert.equal(body.message, "webhook event");
    assert.equal(body.description, "webhook event");
    assert.equal(body.event_id, undefined);
  });
});
