import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  ZendutySink,
  ZendutySinkConfigError,
  ZendutySinkError,
  assertValidZendutySinkConfig,
  buildZendutyAlertBody,
  classifyZendutyAlertResponse,
  classifyZendutyRecordFailure,
  resolveZendutyAlertType,
  resolveZendutyMessage,
  resolveZendutyPayload,
  resolveZendutyRecord,
  resolveZendutySummary,
  truncateZendutyPayload,
  ZENDUTY_ALERT_STATUS_URL_TEMPLATE,
  ZENDUTY_ALERT_TYPES,
  ZENDUTY_API_BASE_URL,
  ZENDUTY_DEFAULT_ALERT_TYPE,
  ZENDUTY_DEFAULT_PAYLOAD_MAX_CHARS,
  ZENDUTY_FALLBACK_MESSAGE,
  ZENDUTY_GENERIC_WEBHOOK_URL_TEMPLATE,
  ZENDUTY_JSON_CONTENT_TYPE,
  type ZendutyAlertClient,
  type ZendutyAlertPostRequest,
  type ZendutyAlertPostResponse,
  type ZendutySinkConfig,
} from "../src/zenduty-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements ZendutyAlertClient {
  posts: ZendutyAlertPostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → trace id to return for that post. */
  traceOn = new Map<number, string>();
  /** Call-count (0-based) → error text to return for that post. */
  errorOn = new Map<number, string>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: ZendutyAlertPostRequest): Promise<ZendutyAlertPostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return {
      status: this.statusOn.get(n) ?? 200,
      traceId: this.traceOn.get(n),
      errorMessage: this.errorOn.get(n),
    };
  }
}

function baseConfig(
  client: ZendutyAlertClient,
  extra: Partial<ZendutySinkConfig> = {}
): ZendutySinkConfig {
  return { client, ...extra };
}

describe("zenduty-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidZendutySinkConfig(null, "ZendutySink"), RangeError);
    assert.throws(() => assertValidZendutySinkConfig("x", "ZendutySink"), RangeError);
  });

  it("rejects a malformed client, payloadMaxChars, and alertType", () => {
    assert.throws(
      () => assertValidZendutySinkConfig(baseConfig(new FakeClient(), { client: {} as never }), "ZendutySink"),
      RangeError
    );
    assert.throws(
      () => assertValidZendutySinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 0 }), "ZendutySink"),
      RangeError
    );
    assert.throws(
      () => assertValidZendutySinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 1.5 }), "ZendutySink"),
      RangeError
    );
    assert.throws(
      () => assertValidZendutySinkConfig(baseConfig(new FakeClient(), { alertType: "CRITICAL" as never }), "ZendutySink"),
      RangeError
    );
    assert.throws(
      () => assertValidZendutySinkConfig(baseConfig(new FakeClient(), { alertType: "fatal" as never }), "ZendutySink"),
      RangeError
    );
    assert.throws(
      () => assertValidZendutySinkConfig(baseConfig(new FakeClient(), { alertType: "" as never }), "ZendutySink"),
      RangeError
    );
    assertValidZendutySinkConfig(baseConfig(new FakeClient(), { alertType: "critical" }), "ZendutySink");
    assertValidZendutySinkConfig(baseConfig(new FakeClient(), { alertType: "error" }), "ZendutySink");
    assertValidZendutySinkConfig(baseConfig(new FakeClient(), { alertType: "warning" }), "ZendutySink");
    assertValidZendutySinkConfig(baseConfig(new FakeClient(), { alertType: "info" }), "ZendutySink");
    assertValidZendutySinkConfig(baseConfig(new FakeClient(), { alertType: "acknowledged" }), "ZendutySink");
    assertValidZendutySinkConfig(baseConfig(new FakeClient(), { alertType: "resolved" }), "ZendutySink");
    assertValidZendutySinkConfig(baseConfig(new FakeClient()), "ZendutySink");
  });

  it("has no apiKey field: the client alone holds the Generic Integration webhook URL", () => {
    // The config type carries no apiKey: a config object that
    // smuggles one in is not part of the sink's contract, and
    // the sink never reads it — the handed request carries no
    // URL at all, let alone a credential (see the send tests).
    const cfg = baseConfig(new FakeClient(), { apiKey: "deadbeef-0000-1111-2222-333344445555" } as never);
    assert.equal((cfg as Record<string, unknown>).apiKey, "deadbeef-0000-1111-2222-333344445555");
    assertValidZendutySinkConfig(cfg, "ZendutySink");
  });
});

describe("zenduty-sink resolvers", () => {
  it("pins the events base URL, the webhook URL template, and the alert-status URL template — integration and UUID are client-held placeholders, never a real key", () => {
    assert.equal(ZENDUTY_API_BASE_URL, "https://events.zenduty.com");
    assert.equal(
      ZENDUTY_GENERIC_WEBHOOK_URL_TEMPLATE,
      "https://events.zenduty.com/integration/{integration}/generic/{uuid}/"
    );
    assert.equal(ZENDUTY_GENERIC_WEBHOOK_URL_TEMPLATE.includes("{integration}"), true);
    assert.equal(ZENDUTY_GENERIC_WEBHOOK_URL_TEMPLATE.includes("{uuid}"), true);
    assert.equal(
      ZENDUTY_ALERT_STATUS_URL_TEMPLATE,
      "https://events.zenduty.com/api/alert/status/{trace_id}/"
    );
    assert.equal(ZENDUTY_ALERT_STATUS_URL_TEMPLATE.includes("{trace_id}"), true);
    // No real key, no URL, no credential anywhere in the constants.
    assert.equal(ZENDUTY_API_BASE_URL.includes("apiKey"), false);
    assert.equal(ZENDUTY_GENERIC_WEBHOOK_URL_TEMPLATE.includes("deadbeef"), false);
    assert.equal(ZENDUTY_ALERT_STATUS_URL_TEMPLATE.includes("deadbeef"), false);
  });

  it("pins the documented alert types and default: six values, default critical", () => {
    assert.deepEqual([...ZENDUTY_ALERT_TYPES], [
      "critical",
      "error",
      "warning",
      "info",
      "acknowledged",
      "resolved",
    ]);
    assert.equal(ZENDUTY_DEFAULT_ALERT_TYPE, "critical");
    assert.equal(resolveZendutyAlertType({ body: "{}" }, {}), "critical");
    assert.equal(resolveZendutyAlertType({ body: "{}" }, { alertType: "resolved" }), "resolved");
    assert.equal(resolveZendutyAlertType({ body: "{}", alertType: "info" }, { alertType: "resolved" }), "info");
    assert.equal(resolveZendutyAlertType({ body: "{}", alertType: "warning" }, {}), "warning");
  });

  it("derives the message from subject, key, then traceId", () => {
    assert.equal(resolveZendutyMessage({ body: "{}", subject: "Payments failing", key: "k", traceId: "t" }), "Payments failing");
    assert.equal(resolveZendutyMessage({ body: "{}", key: "order-1", traceId: "t" }), "order-1");
    assert.equal(resolveZendutyMessage({ body: "{}", traceId: "trace-9" }), "trace-9");
    assert.equal(resolveZendutyMessage({ body: "{}" }), ZENDUTY_FALLBACK_MESSAGE);
  });

  it("derives the summary from key, then traceId, and omits it when neither exists", () => {
    assert.equal(resolveZendutySummary({ body: "{}", key: "order-1", traceId: "trace-9" }), "order-1");
    assert.equal(resolveZendutySummary({ body: "{}", traceId: "trace-9" }), "trace-9");
    assert.equal(resolveZendutySummary({ body: "{}", subject: "Payments failing" }), undefined);
    assert.equal(resolveZendutySummary({ body: "{}" }), undefined);
  });

  it("does not truncate the message or the summary: the re-checked docs state no length limit for either", () => {
    const long = "s".repeat(5000);
    assert.equal(resolveZendutyMessage({ body: "{}", subject: long }), long);
    assert.equal(resolveZendutySummary({ body: "{}", key: long }), long);
    const body = JSON.parse(buildZendutyAlertBody({ body: "{}", subject: long, key: long }, {}));
    assert.equal(body.message, long);
    assert.equal(body.message.length, 5000);
    assert.equal(body.summary, long);
  });

  it("derives payload from only the key/traceId identifiers that exist", () => {
    assert.deepEqual(resolveZendutyPayload({ body: "{}", key: "order-1", traceId: "trace-9" }, {}), {
      key: "order-1",
      traceId: "trace-9",
    });
    assert.deepEqual(resolveZendutyPayload({ body: "{}", key: "order-1" }, {}), { key: "order-1" });
    assert.deepEqual(resolveZendutyPayload({ body: "{}", traceId: "trace-9" }, {}), { traceId: "trace-9" });
    assert.equal(resolveZendutyPayload({ body: "{}" }, {}), undefined);
  });

  it("appends the payload body only under the opt-in, truncated at the default 2000", () => {
    assert.equal(ZENDUTY_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
    assert.equal(truncateZendutyPayload("abcdef", 4), "abcd… (truncated)");
    assert.equal(truncateZendutyPayload("abc", 4), "abc");
    const withPayload = resolveZendutyPayload({ body: '{"a":1}', subject: "Payments failing", key: "k" }, { includePayload: true });
    assert.deepEqual(withPayload, { key: "k", body: '{"a":1}' });
    // No identifiers: the payload body alone becomes the payload.
    assert.deepEqual(resolveZendutyPayload({ body: '{"a":1}' }, { includePayload: true }), { body: '{"a":1}' });
    const long = resolveZendutyPayload({ body: "x".repeat(2001), key: "k1" }, { includePayload: true });
    assert.deepEqual(long, { key: "k1", body: `${"x".repeat(2000)}… (truncated)` });
    const short = resolveZendutyPayload({ body: "0123456789ABCDEF", key: "k1" }, { includePayload: true, payloadMaxChars: 10 });
    assert.deepEqual(short, { key: "k1", body: "0123456789… (truncated)" });
  });

  it("builds the alert body with alert_type/message/summary/entity_id/payload — no credential, no urls, no sla, no priority, no tags", () => {
    const body = JSON.parse(
      buildZendutyAlertBody(
        { body: "{}", subject: "Payments failing", key: "order-1", traceId: "trace-9" },
        {}
      )
    );
    assert.equal(body.alert_type, "critical");
    assert.equal(body.message, "Payments failing");
    assert.equal(body.summary, "order-1");
    assert.equal(body.entity_id, "order-1");
    assert.deepEqual(body.payload, { key: "order-1", traceId: "trace-9" });
    assert.equal(body.urls, undefined);
    assert.equal(body.sla, undefined);
    assert.equal(body.escalation_policy, undefined);
    assert.equal(body.priority, undefined);
    assert.equal(body.stakeholders, undefined);
    assert.equal(body.tags, undefined);
    // No credential ever enters the body.
    assert.equal(JSON.stringify(body).includes("apiKey"), false);
    assert.equal(JSON.stringify(body).includes("Authorization"), false);
    assert.equal(JSON.stringify(body).includes("Bearer"), false);
  });

  it("omits summary, entity_id, and payload when the event carries no key or identifiers, keeps the rest of the envelope", () => {
    const body = JSON.parse(
      buildZendutyAlertBody({ body: "{}", subject: "Payments failing" }, {})
    );
    assert.equal(body.alert_type, "critical");
    assert.equal(body.message, "Payments failing");
    assert.equal(body.summary, undefined);
    assert.equal("summary" in body, false);
    assert.equal(body.entity_id, undefined);
    assert.equal("entity_id" in body, false);
    assert.equal(body.payload, undefined);
    assert.equal("payload" in body, false);
  });

  it("sends the configured alert type, including a per-record override", () => {
    const body = JSON.parse(
      buildZendutyAlertBody(
        { body: '{"a":1}', subject: "Alert", key: "k1" },
        { alertType: "resolved" }
      )
    );
    assert.equal(body.alert_type, "resolved");
    assert.equal(body.entity_id, "k1");
    const overridden = JSON.parse(
      buildZendutyAlertBody(
        { body: "{}", subject: "Alert", key: "k1", alertType: "info" },
        { alertType: "critical" }
      )
    );
    assert.equal(overridden.alert_type, "info");
  });

  it("rejects an empty record body", () => {
    assert.throws(() => resolveZendutyRecord({ body: "" }, 0), RangeError);
    assert.deepEqual(resolveZendutyRecord({ body: "{}" }, 2), { index: 2 });
  });

  it("rejects a bad per-record alertType value", () => {
    assert.throws(
      () => resolveZendutyRecord({ body: "{}", alertType: "fatal" as never }, 0),
      RangeError
    );
  });

  it("does not reject a resolved alert without a key — the reference pins no such rule", () => {
    assert.deepEqual(resolveZendutyRecord({ body: "{}", alertType: "resolved" }, 0), { index: 0 });
  });
});

describe("zenduty-sink failure mapping", () => {
  it("maps 429 and 5xx to retryable, other non-200 to fail-closed", () => {
    assert.equal(classifyZendutyRecordFailure(429), true);
    assert.equal(classifyZendutyRecordFailure(500), true);
    assert.equal(classifyZendutyRecordFailure(503), true);
    assert.equal(classifyZendutyRecordFailure(400), false);
    assert.equal(classifyZendutyRecordFailure(401), false);
    assert.equal(classifyZendutyRecordFailure(403), false);
    assert.equal(classifyZendutyRecordFailure(404), false);
    assert.equal(classifyZendutyRecordFailure(422), false);
  });

  it("accepts exactly 200 as an acceptance receipt — 201 and 202 are failures, fail-closed", () => {
    assert.deepEqual(classifyZendutyAlertResponse({ status: 200 }), { accepted: true });
    assert.deepEqual(classifyZendutyAlertResponse({ status: 201 }), {
      accepted: false,
      errorCode: "HTTP_201",
      retryable: false,
    });
    assert.deepEqual(classifyZendutyAlertResponse({ status: 202 }), {
      accepted: false,
      errorCode: "HTTP_202",
      retryable: false,
    });
  });

  it("maps a non-200 status to its HTTP code and lane, surfacing the client's error text", () => {
    assert.deepEqual(
      classifyZendutyAlertResponse({ status: 429, errorMessage: "Rate limit exceeded" }),
      {
        accepted: false,
        errorCode: "HTTP_429",
        retryable: true,
        errorMessage: "Rate limit exceeded",
      }
    );
    assert.deepEqual(classifyZendutyAlertResponse({ status: 404 }), {
      accepted: false,
      errorCode: "HTTP_404",
      retryable: false,
    });
    assert.deepEqual(
      classifyZendutyAlertResponse({ status: 400, errorMessage: "Incorrect payload" }),
      {
        accepted: false,
        errorCode: "HTTP_400",
        retryable: false,
        errorMessage: "Incorrect payload",
      }
    );
    assert.deepEqual(classifyZendutyAlertResponse({ status: 500 }), {
      accepted: false,
      errorCode: "HTTP_500",
      retryable: true,
    });
  });
});

describe("zenduty-sink send", () => {
  it("posts one alert per message with no URL and no credentials in the handed request, collecting trace ids", async () => {
    const client = new FakeClient();
    client.traceOn.set(0, "cadfe35f-e3b1-4175-b118-a595bff9a214");
    client.traceOn.set(1, "b0a1c2d3-e4f5-4678-89ab-cdef01234567");
    const sink = new ZendutySink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "Payments failing", key: "order-1", traceId: "trace-9" },
      { body: '{"b":2}', key: "order-2" },
    ]);
    assert.deepEqual(result, {
      ok: true,
      sent: 2,
      traceIds: ["cadfe35f-e3b1-4175-b118-a595bff9a214", "b0a1c2d3-e4f5-4678-89ab-cdef01234567"],
    });
    assert.equal(client.posts.length, 2);
    const first = client.posts[0];
    // The webhook URL — integration segment and UUID alike —
    // is held by the client alone: the sink hands over no
    // URL at all, so there is nothing to leak.
    assert.equal("url" in first, false);
    assert.equal(first.headers["Content-Type"], ZENDUTY_JSON_CONTENT_TYPE);
    assert.equal(first.headers["Authorization"], undefined);
    assert.equal(first.headers["Idempotency-Key"], undefined);
    assert.deepEqual(Object.keys(first.headers), ["Content-Type"]);
    const body = JSON.parse(first.body);
    assert.equal(body.alert_type, "critical");
    assert.equal(body.message, "Payments failing");
    assert.equal(body.summary, "order-1");
    assert.equal(body.entity_id, "order-1");
    assert.deepEqual(body.payload, { key: "order-1", traceId: "trace-9" });
    assert.equal(body.urls, undefined);
    assert.equal(body.sla, undefined);
    assert.equal(body.priority, undefined);
    assert.equal(body.tags, undefined);
    // No credential ever enters the handed request.
    assert.equal(JSON.stringify(first).includes("apiKey"), false);
    assert.equal(JSON.stringify(first).includes("Authorization"), false);
    assert.equal(JSON.stringify(first).includes("Bearer"), false);
    assert.equal(JSON.stringify(first).includes("secret"), false);
    assert.equal(JSON.stringify(first).includes("events.zenduty.com"), false);
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("accepts a 200 without a trace id — the status is the acceptance credential", async () => {
    const client = new FakeClient();
    const sink = new ZendutySink(baseConfig(client));
    const result = await sink.send([{ body: "{}", key: "k1" }]);
    assert.deepEqual(result, { ok: true, sent: 1, traceIds: [] });
  });

  it("throws with exactly the failed messages and their retry lanes", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 429);
    client.statusOn.set(2, 500);
    const sink = new ZendutySink(baseConfig(client));
    await assert.rejects(
      sink.send([
        { body: "{}", key: "k1" },
        { body: "{}", key: "k2" },
        { body: "{}", key: "k3" },
      ]),
      (err: unknown) => {
        assert.ok(err instanceof ZendutySinkError);
        assert.deepEqual(
          (err as ZendutySinkError).failedRecords.map((f) => [f.index, f.errorCode, f.retryable]),
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

  it("treats an invalid integration key or disabled integration (404) as fail-closed, surfacing the client's error text", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 404);
    client.errorOn.set(0, "Invalid integration key");
    const sink = new ZendutySink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as ZendutySinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_404");
        assert.equal(failed[0].statusCode, 404);
        assert.equal(failed[0].retryable, false);
        assert.equal(failed[0].errorMessage, "Invalid integration key");
        return true;
      }
    );
  });

  it("treats an incorrect payload (400) as fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 400);
    client.errorOn.set(0, "Incorrect payload");
    const sink = new ZendutySink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as ZendutySinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_400");
        assert.equal(failed[0].retryable, false);
        assert.equal(failed[0].errorMessage, "Incorrect payload");
        return true;
      }
    );
  });

  it("treats a 201 as a fail-closed failure — the success status is pinned to exactly 200", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 201);
    const sink = new ZendutySink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as ZendutySinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_201");
        assert.equal(failed[0].statusCode, 201);
        assert.equal(failed[0].retryable, false);
        return true;
      }
    );
  });

  it("treats a client throw as a retryable transport failure", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hang up"));
    const sink = new ZendutySink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as ZendutySinkError).failedRecords;
        assert.equal(failed[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(failed[0].retryable, true);
        assert.equal(failed[0].errorMessage, "socket hang up");
        return true;
      }
    );
  });

  it("throws a config error with no client, mapped non_retryable", async () => {
    const sink = new ZendutySink({});
    await assert.rejects(sink.send([{ body: "{}", key: "k1" }]), ZendutySinkConfigError);
    assert.equal(classifyFailure(new ZendutySinkConfigError("no client injected")).failureClass, "non_retryable");
  });

  it("dry-runs with zero client I/O and untouched stats", async () => {
    const client = new FakeClient();
    const sink = new ZendutySink(baseConfig(client, { dryRun: true }));
    const result = await sink.send([{ body: "{}", subject: "Payments failing" }]);
    assert.deepEqual(result, { ok: true, sent: 0, traceIds: [], dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("dry-runs still validate the config and the records", async () => {
    const client = new FakeClient();
    const sink = new ZendutySink(baseConfig(client, { dryRun: true }));
    await assert.rejects(sink.send([{ body: "" }]), RangeError);
    assert.equal(client.posts.length, 0);
    await assert.rejects(sink.send([{ body: "{}", alertType: "fatal" as never }]), RangeError);
    assert.equal(client.posts.length, 0);
    assert.throws(
      () => new ZendutySink({ alertType: "fatal" as never, dryRun: true }),
      RangeError
    );
  });

  it("appends the payload body under the opt-in, truncated at the default 2000", async () => {
    const client = new FakeClient();
    const sink = new ZendutySink(baseConfig(client, { includePayload: true, payloadMaxChars: 10 }));
    await sink.send([{ body: "0123456789ABCDEF", subject: "Alert", key: "k1" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.deepEqual(body.payload, { key: "k1", body: "0123456789… (truncated)" });
    assert.equal(body.message, "Alert");

    const defaultClient = new FakeClient();
    const defaultSink = new ZendutySink(baseConfig(defaultClient, { includePayload: true }));
    await defaultSink.send([{ body: "x".repeat(2001), subject: "Alert", key: "k1" }]);
    const defaultBody = JSON.parse(defaultClient.posts[0].body);
    assert.deepEqual(defaultBody.payload, { key: "k1", body: `${"x".repeat(2000)}… (truncated)` });
  });

  it("omits the payload body by default — payload carries the identifiers only", async () => {
    const client = new FakeClient();
    const sink = new ZendutySink(baseConfig(client));
    await sink.send([{ body: '{"secret":"s3cr3t"}', subject: "Alert", key: "k1" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.deepEqual(body.payload, { key: "k1" });
    assert.equal(JSON.stringify(body).includes("s3cr3t"), false);
  });

  it("sends a configured alert type and omits entity_id for a keyless alert", async () => {
    const client = new FakeClient();
    const sink = new ZendutySink(baseConfig(client, { alertType: "warning" }));
    await sink.send([{ body: "{}", subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.alert_type, "warning");
    assert.equal(body.entity_id, undefined);
    assert.equal("entity_id" in body, false);
    assert.equal(body.summary, undefined);
    assert.equal(body.payload, undefined);
  });

  it("sends a resolved alert with the same entity_id as a normal alert — Zenduty resolves the incident, the sink tracks nothing", async () => {
    const client = new FakeClient();
    const sink = new ZendutySink(baseConfig(client));
    const result = await sink.send([
      { body: "{}", key: "k1", alertType: "critical" },
      { body: "{}", key: "k1", alertType: "resolved" },
    ]);
    // No sink-side suppression or state: both alerts go out
    // with the same entity_id, and Zenduty resolves the
    // incident for the later one instead of creating a new one.
    assert.deepEqual(result, { ok: true, sent: 2, traceIds: [] });
    assert.equal(client.posts.length, 2);
    assert.equal(JSON.parse(client.posts[0].body).alert_type, "critical");
    assert.equal(JSON.parse(client.posts[1].body).alert_type, "resolved");
    assert.equal(JSON.parse(client.posts[1].body).entity_id, "k1");
  });

  it("falls back to 'webhook event' for a sourceless event", async () => {
    const client = new FakeClient();
    const sink = new ZendutySink(baseConfig(client));
    await sink.send([{ body: "{}" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.alert_type, "critical");
    assert.equal(body.message, "webhook event");
    assert.equal(body.entity_id, undefined);
    assert.equal(body.summary, undefined);
    assert.equal(body.payload, undefined);
  });
});
