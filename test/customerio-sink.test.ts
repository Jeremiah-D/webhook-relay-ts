import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  CustomerIoSink,
  CustomerIoSinkConfigError,
  CustomerIoSinkError,
  assertValidCustomerIoSinkConfig,
  buildCustomerIoMessageData,
  buildCustomerIoSendPushBody,
  buildCustomerIoSendPushUrl,
  classifyCustomerIoRecordFailure,
  customerIoResponseToFailedRecord,
  resolveCustomerIoContent,
  resolveCustomerIoHost,
  resolveCustomerIoIdentifiers,
  resolveCustomerIoRecord,
  resolveCustomerIoSummary,
  truncateCustomerIoPayload,
  CUSTOMERIO_DEFAULT_HOST,
  CUSTOMERIO_DEFAULT_PAYLOAD_MAX_CHARS,
  CUSTOMERIO_EU_HOST,
  CUSTOMERIO_FALLBACK_SUMMARY,
  CUSTOMERIO_JSON_CONTENT_TYPE,
  CUSTOMERIO_SEND_PUSH_PATH,
  CUSTOMERIO_TO_ALL,
  CUSTOMERIO_TO_LAST_USED,
  type CustomerIoIdentifiers,
  type CustomerIoMessageClient,
  type CustomerIoMessagePostRequest,
  type CustomerIoMessagePostResponse,
  type CustomerIoSinkConfig,
} from "../src/customerio-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status and delivery_id per call. */
class FakeClient implements CustomerIoMessageClient {
  posts: CustomerIoMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  /** Call-count (0-based) → `delivery_id` to surface for that post (undefined = none surfaced). */
  deliveryIdOn = new Map<number, string | undefined>();
  /** Call-count (0-based) → `queued_at` to surface for that post. */
  queuedAtOn = new Map<number, number>();
  async post(request: CustomerIoMessagePostRequest): Promise<CustomerIoMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return {
      status: this.statusOn.get(n) ?? 200,
      deliveryId: this.deliveryIdOn.has(n) ? this.deliveryIdOn.get(n) : "A1C2E3jdieDks7zXdyz8XCFn1888",
      queuedAt: this.queuedAtOn.get(n),
    };
  }
}

const identifiers: CustomerIoIdentifiers = { email: "person@example.com" };

function baseConfig(
  client: CustomerIoMessageClient,
  extra: Partial<CustomerIoSinkConfig> = {}
): CustomerIoSinkConfig {
  return { transactionalMessageId: 44, identifiers, client, ...extra };
}

describe("customerio-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidCustomerIoSinkConfig(null, "CustomerIoSink"), RangeError);
    assert.throws(() => assertValidCustomerIoSinkConfig("x", "CustomerIoSink"), RangeError);
  });

  it("rejects a malformed region host", () => {
    assert.throws(
      () => assertValidCustomerIoSinkConfig(baseConfig(new FakeClient(), { regionHost: "https://api.customer.io" }), "CustomerIoSink"),
      RangeError
    );
    assert.throws(
      () => assertValidCustomerIoSinkConfig(baseConfig(new FakeClient(), { regionHost: "api.customer.io/v1" }), "CustomerIoSink"),
      RangeError
    );
    assert.equal(CUSTOMERIO_EU_HOST, "api-eu.customer.io");
    assertValidCustomerIoSinkConfig(baseConfig(new FakeClient(), { regionHost: CUSTOMERIO_EU_HOST }), "CustomerIoSink");
  });

  it("requires a transactional message id, numeric or trigger name", () => {
    assert.throws(
      () => assertValidCustomerIoSinkConfig({ identifiers, client: new FakeClient() }, "CustomerIoSink"),
      RangeError
    );
    assert.throws(
      () => assertValidCustomerIoSinkConfig(baseConfig(new FakeClient(), { transactionalMessageId: "" }), "CustomerIoSink"),
      RangeError
    );
    assert.throws(
      () => assertValidCustomerIoSinkConfig(baseConfig(new FakeClient(), { transactionalMessageId: 44.5 }), "CustomerIoSink"),
      RangeError
    );
    assertValidCustomerIoSinkConfig(baseConfig(new FakeClient(), { transactionalMessageId: "password reset" }), "CustomerIoSink");
    assertValidCustomerIoSinkConfig(baseConfig(new FakeClient(), { transactionalMessageId: 44 }), "CustomerIoSink");
  });

  it("requires exactly one recipient identifier", () => {
    assert.throws(
      () => assertValidCustomerIoSinkConfig({ transactionalMessageId: 44, client: new FakeClient() }, "CustomerIoSink"),
      RangeError
    );
    assert.throws(
      () => assertValidCustomerIoSinkConfig(baseConfig(new FakeClient(), { identifiers: {} }), "CustomerIoSink"),
      RangeError
    );
    assert.throws(
      () =>
        assertValidCustomerIoSinkConfig(
          baseConfig(new FakeClient(), { identifiers: { id: "u-1", email: "person@example.com" } }),
          "CustomerIoSink"
        ),
      RangeError
    );
    assert.throws(
      () => assertValidCustomerIoSinkConfig(baseConfig(new FakeClient(), { identifiers: { email: "" } }), "CustomerIoSink"),
      RangeError
    );
    assert.deepEqual(resolveCustomerIoIdentifiers({ id: "u-1" }, "CustomerIoSink"), { id: "u-1" });
    assert.deepEqual(resolveCustomerIoIdentifiers({ cio_id: "cio-9" }, "CustomerIoSink"), { cio_id: "cio-9" });
    assertValidCustomerIoSinkConfig(baseConfig(new FakeClient(), { identifiers: { id: "u-1" } }), "CustomerIoSink");
  });

  it("rejects a malformed device selection, client, and payloadMaxChars", () => {
    assert.throws(
      () => assertValidCustomerIoSinkConfig(baseConfig(new FakeClient(), { to: "" }), "CustomerIoSink"),
      RangeError
    );
    assert.throws(
      () => assertValidCustomerIoSinkConfig(baseConfig(new FakeClient(), { client: {} as never }), "CustomerIoSink"),
      RangeError
    );
    assert.throws(
      () => assertValidCustomerIoSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 0 }), "CustomerIoSink"),
      RangeError
    );
    assert.equal(CUSTOMERIO_TO_ALL, "all");
    assert.equal(CUSTOMERIO_TO_LAST_USED, "last_used");
    assertValidCustomerIoSinkConfig(baseConfig(new FakeClient(), { to: CUSTOMERIO_TO_LAST_USED }), "CustomerIoSink");
  });
});

describe("customerio-sink resolvers", () => {
  it("resolves the default and configured host", () => {
    assert.equal(resolveCustomerIoHost({}), CUSTOMERIO_DEFAULT_HOST);
    assert.equal(resolveCustomerIoHost({ regionHost: "api-eu.customer.io" }), "api-eu.customer.io");
    assert.equal(buildCustomerIoSendPushUrl("api.customer.io"), "https://api.customer.io/v1/send/push");
    assert.equal(CUSTOMERIO_SEND_PUSH_PATH, "/v1/send/push");
  });

  it("derives the summary from subject, key, then traceId", () => {
    assert.equal(resolveCustomerIoSummary({ body: "{}", subject: "Price drop", key: "k", traceId: "t" }), "Price drop");
    assert.equal(resolveCustomerIoSummary({ body: "{}", key: "order-1", traceId: "t" }), "order-1");
    assert.equal(resolveCustomerIoSummary({ body: "{}", traceId: "trace-9" }), "trace-9");
    assert.equal(resolveCustomerIoSummary({ body: "{}" }), CUSTOMERIO_FALLBACK_SUMMARY);
  });

  it("derives title/message and appends the payload only under the opt-in", () => {
    const content = resolveCustomerIoContent({ body: '{"a":1}', subject: "Price drop" }, {});
    assert.deepEqual(content, { title: "Price drop", message: "Price drop" });
    const withPayload = resolveCustomerIoContent({ body: '{"a":1}', subject: "Price drop" }, { includePayload: true });
    assert.equal(withPayload.message, 'Price drop\n\n{"a":1}');
    assert.equal(CUSTOMERIO_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
    assert.equal(truncateCustomerIoPayload("abcdef", 4), "abcd… (truncated)");
    assert.equal(truncateCustomerIoPayload("abc", 4), "abc");
  });

  it("builds message_data with the derived title and message", () => {
    assert.deepEqual(buildCustomerIoMessageData({ title: "Price drop", message: "Price drop" }), {
      title: "Price drop",
      message: "Price drop",
    });
  });

  it("builds the send/push body with template id, identifiers, and message_data", () => {
    const body = JSON.parse(
      buildCustomerIoSendPushBody(44, identifiers, { title: "Price drop", message: "Price drop" }, {})
    );
    assert.equal(body.transactional_message_id, 44);
    assert.deepEqual(body.identifiers, { email: "person@example.com" });
    assert.deepEqual(body.message_data, { title: "Price drop", message: "Price drop" });
    assert.equal(body.to, undefined);
    // No credential ever enters the body.
    assert.equal(JSON.stringify(body).includes("Bearer"), false);
    assert.equal(JSON.stringify(body).includes("sk_"), false);
  });

  it("includes the device selection and trigger name when configured", () => {
    const body = JSON.parse(
      buildCustomerIoSendPushBody(
        "password reset",
        { id: "u-1" },
        { title: "Reset", message: "Reset" },
        { to: "last_used" }
      )
    );
    assert.equal(body.transactional_message_id, "password reset");
    assert.deepEqual(body.identifiers, { id: "u-1" });
    assert.equal(body.to, "last_used");
  });

  it("rejects an empty record body", () => {
    assert.throws(() => resolveCustomerIoRecord({ body: "" }, 0), RangeError);
    assert.deepEqual(resolveCustomerIoRecord({ body: "{}" }, 2), { index: 2 });
  });
});

describe("customerio-sink failure mapping", () => {
  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", () => {
    assert.equal(classifyCustomerIoRecordFailure(429), true);
    assert.equal(classifyCustomerIoRecordFailure(500), true);
    assert.equal(classifyCustomerIoRecordFailure(503), true);
    assert.equal(classifyCustomerIoRecordFailure(400), false);
    assert.equal(classifyCustomerIoRecordFailure(401), false);
    assert.equal(classifyCustomerIoRecordFailure(403), false);
    assert.equal(classifyCustomerIoRecordFailure(404), false);
    assert.equal(classifyCustomerIoRecordFailure(405), false);
  });

  it("accepts a 2xx with a surfaced delivery_id", () => {
    assert.equal(
      customerIoResponseToFailedRecord({ status: 200, deliveryId: "A1C2E3", queuedAt: 1604977406 }, 0),
      null
    );
  });

  it("fails a 2xx with no delivery_id surfaced as retryable", () => {
    const failed = customerIoResponseToFailedRecord({ status: 200 }, 2);
    assert.equal(failed?.errorCode, "DELIVERY_ID_MISSING");
    assert.equal(failed?.retryable, true);
  });
});

describe("customerio-sink send", () => {
  it("posts one transactional push per message with no credentials", async () => {
    const client = new FakeClient();
    const sink = new CustomerIoSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "Price drop", key: "order-1" },
      { body: '{"b":2}', key: "order-2" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    const first = client.posts[0];
    assert.equal(first.url, "https://api.customer.io/v1/send/push");
    assert.equal(first.headers["Content-Type"], CUSTOMERIO_JSON_CONTENT_TYPE);
    assert.equal(first.headers["Authorization"], undefined);
    const body = JSON.parse(first.body);
    assert.equal(body.transactional_message_id, 44);
    assert.deepEqual(body.identifiers, { email: "person@example.com" });
    assert.deepEqual(body.message_data, { title: "Price drop", message: "Price drop" });
    assert.equal(body.to, undefined);
    // No credential ever enters the handed request.
    assert.equal(JSON.stringify(first).includes("Bearer"), false);
    assert.equal(JSON.stringify(first).includes("sk_"), false);
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("throws with exactly the failed messages and their retry lanes", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 429);
    client.deliveryIdOn.set(2, undefined);
    const sink = new CustomerIoSink(baseConfig(client));
    await assert.rejects(
      sink.send([
        { body: "{}", key: "k1" },
        { body: "{}", key: "k2" },
        { body: "{}", key: "k3" },
      ]),
      (err: unknown) => {
        assert.ok(err instanceof CustomerIoSinkError);
        assert.deepEqual(
          (err as CustomerIoSinkError).failedRecords.map((f) => [f.index, f.errorCode, f.retryable]),
          [
            [1, "HTTP_429", true],
            [2, "DELIVERY_ID_MISSING", true],
          ]
        );
        return true;
      }
    );
    assert.deepEqual(sink.stats, { sent: 1, failed: 2, sendFailures: 1 });
  });

  it("treats an unknown template (400) as fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 400);
    const sink = new CustomerIoSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as CustomerIoSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_400");
        assert.equal(failed[0].statusCode, 400);
        assert.equal(failed[0].retryable, false);
        return true;
      }
    );
  });

  it("treats a client throw as a retryable transport failure", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hang up"));
    const sink = new CustomerIoSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as CustomerIoSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(failed[0].retryable, true);
        assert.equal(failed[0].errorMessage, "socket hang up");
        return true;
      }
    );
  });

  it("throws a config error with no client, mapped non_retryable", async () => {
    const sink = new CustomerIoSink({ transactionalMessageId: 44, identifiers });
    await assert.rejects(sink.send([{ body: "{}", key: "k1" }]), CustomerIoSinkConfigError);
    assert.equal(classifyFailure(new CustomerIoSinkConfigError("no client injected")).failureClass, "non_retryable");
  });

  it("dry-runs with zero client I/O and untouched stats", async () => {
    const client = new FakeClient();
    const sink = new CustomerIoSink(baseConfig(client, { dryRun: true }));
    const result = await sink.send([{ body: "{}", subject: "Price drop" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("appends the payload under the opt-in, truncated", async () => {
    const client = new FakeClient();
    const sink = new CustomerIoSink(baseConfig(client, { includePayload: true, payloadMaxChars: 10 }));
    await sink.send([{ body: "0123456789ABCDEF", subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.message_data.message, "Alert\n\n0123456789… (truncated)");
    assert.equal(body.message_data.title, "Alert");
  });

  it("uses the configured EU host, trigger name, and device selection", async () => {
    const client = new FakeClient();
    const sink = new CustomerIoSink(
      baseConfig(client, { regionHost: "api-eu.customer.io", transactionalMessageId: "password reset", to: "last_used" })
    );
    await sink.send([{ body: "{}", key: "k1" }]);
    assert.equal(client.posts[0].url, "https://api-eu.customer.io/v1/send/push");
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.transactional_message_id, "password reset");
    assert.equal(body.to, "last_used");
  });
});
