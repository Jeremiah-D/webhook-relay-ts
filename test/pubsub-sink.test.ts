import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  PubSubSink,
  PubSubSinkConfigError,
  PubSubSinkError,
  PubSubPublishError,
  assertValidPubSubSinkConfig,
  classifyPubSubRecordFailure,
  resolvePubSubAttributes,
  resolvePubSubOrderingKey,
  resolvePubSubRecord,
  type PubSubClient,
  type PubSubPublishRequest,
  type PubSubSinkConfig,
} from "../src/pubsub-sink.ts";
import { classifyFailure } from "../src/failure.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.

/** In-memory fake client: records every publish, fails on demand. */
class FakeClient implements PubSubClient {
  published: PubSubPublishRequest[] = [];
  /** Call-count (0-based) → error to throw for that publish. */
  failOn = new Map<number, Error>();
  async publish(request: PubSubPublishRequest): Promise<string> {
    const n = this.published.length;
    this.published.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return `msg-${n}`;
  }
}

function baseConfig(
  client: PubSubClient,
  extra: Partial<PubSubSinkConfig> = {}
): PubSubSinkConfig {
  return { topic: "projects/p/topics/events", client, ...extra };
}

describe("pubsub-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidPubSubSinkConfig(null, "PubSubSink"), RangeError);
    assert.throws(() => assertValidPubSubSinkConfig("x", "PubSubSink"), RangeError);
  });

  it("rejects a malformed topic", () => {
    assert.throws(
      () => assertValidPubSubSinkConfig({ topic: "" }, "PubSubSink"),
      RangeError
    );
    assert.throws(
      () => assertValidPubSubSinkConfig({ topic: "has space" }, "PubSubSink"),
      RangeError
    );
    assert.throws(
      () => assertValidPubSubSinkConfig({ topic: "has\0nul" }, "PubSubSink"),
      RangeError
    );
  });

  it("rejects a client without a publish function", () => {
    assert.throws(
      () => assertValidPubSubSinkConfig({ topic: "t", client: {} }, "PubSubSink"),
      RangeError
    );
  });

  it("accepts a topic-less config (topic missing fails closed at publish)", () => {
    assertValidPubSubSinkConfig({ client: new FakeClient() }, "PubSubSink");
  });
});

describe("pubsub-sink attribute pass-through", () => {
  it("passes tenant, endpoint, and trace-id verbatim", () => {
    assert.deepEqual(
      resolvePubSubAttributes({
        body: "{}",
        tenant: "tenant-1",
        endpoint: "ep-9",
        traceId: "trace-9",
      }),
      { tenant: "tenant-1", endpoint: "ep-9", "trace-id": "trace-9" }
    );
  });

  it("invents no attribute for a missing value", () => {
    assert.deepEqual(resolvePubSubAttributes({ body: "{}" }), {});
    assert.deepEqual(
      resolvePubSubAttributes({ body: "{}", tenant: "" }),
      {}
    );
  });
});

describe("pubsub-sink ordering keys", () => {
  it("attaches the event key only when opted in and the topic is ordering-enabled", () => {
    assert.equal(
      resolvePubSubOrderingKey(
        { body: "{}", key: "order-9" },
        { orderingKey: true, orderingEnabled: true }
      ),
      "order-9"
    );
  });

  it("ignores the key when the opt-in is absent", () => {
    assert.equal(
      resolvePubSubOrderingKey({ body: "{}", key: "order-9" }, {}),
      undefined
    );
  });

  it("ignores the key on a topic without ordering enabled", () => {
    assert.equal(
      resolvePubSubOrderingKey(
        { body: "{}", key: "order-9" },
        { orderingKey: true, orderingEnabled: false }
      ),
      undefined
    );
    assert.equal(
      resolvePubSubOrderingKey(
        { body: "{}", key: "order-9" },
        { orderingKey: true }
      ),
      undefined
    );
  });

  it("attaches no ordering key for a keyless record even when opted in", () => {
    assert.equal(
      resolvePubSubOrderingKey(
        { body: "{}" },
        { orderingKey: true, orderingEnabled: true }
      ),
      undefined
    );
  });
});

describe("pubsub-sink record resolution", () => {
  it("rejects an empty body", () => {
    assert.throws(() => resolvePubSubRecord({ body: "" }, 0, {}), RangeError);
  });

  it("resolves attributes and ordering key together", () => {
    const resolved = resolvePubSubRecord(
      { body: '{"a":1}', tenant: "t1", traceId: "tr1", key: "k1" },
      0,
      { orderingKey: true, orderingEnabled: true }
    );
    assert.equal(resolved.data, '{"a":1}');
    assert.deepEqual(resolved.attributes, { tenant: "t1", "trace-id": "tr1" });
    assert.equal(resolved.orderingKey, "k1");
  });
});

describe("pubsub-sink publish", () => {
  it("publishes messages in order with pass-through attributes", async () => {
    const client = new FakeClient();
    const sink = new PubSubSink(baseConfig(client));
    const result = await sink.publish([
      { body: '{"n":1}', tenant: "t1", traceId: "tr1" },
      { body: '{"n":2}', endpoint: "ep2" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.published.length, 2);
    assert.equal(client.published[0]?.topic, "projects/p/topics/events");
    assert.equal(client.published[0]?.data, '{"n":1}');
    assert.deepEqual(client.published[0]?.attributes, {
      tenant: "t1",
      "trace-id": "tr1",
    });
    assert.equal(client.published[0]?.orderingKey, undefined);
    assert.deepEqual(client.published[1]?.attributes, { endpoint: "ep2" });
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, publishFailures: 0 });
  });

  it("attaches ordering keys only under the full opt-in", async () => {
    const client = new FakeClient();
    const sink = new PubSubSink(
      baseConfig(client, { orderingKey: true, orderingEnabled: true })
    );
    await sink.publish([{ body: "{}", key: "order-9" }]);
    assert.equal(client.published[0]?.orderingKey, "order-9");

    const plain = new FakeClient();
    const plainSink = new PubSubSink(baseConfig(plain));
    await plainSink.publish([{ body: "{}", key: "order-9" }]);
    assert.equal(plain.published[0]?.orderingKey, undefined);
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new PubSubSink(baseConfig(client, { dryRun: true }));
    const result = await sink.publish([{ body: "{}", tenant: "t1" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.published.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, publishFailures: 0 });
  });

  it("dry run still rejects a malformed record", async () => {
    const client = new FakeClient();
    const sink = new PubSubSink(baseConfig(client, { dryRun: true }));
    await assert.rejects(sink.publish([{ body: "" }]), RangeError);
  });

  it("dry run needs no client at all", async () => {
    const sink = new PubSubSink({ topic: "t", dryRun: true });
    const result = await sink.publish([{ body: "{}" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
  });

  it("missing client fails closed as a config error", async () => {
    const sink = new PubSubSink({ topic: "projects/p/topics/events" });
    await assert.rejects(sink.publish([{ body: "{}" }]), PubSubSinkConfigError);
    assert.deepEqual(classifyFailure(new PubSubSinkConfigError("no client")), {
      failureClass: "non_retryable",
    });
  });

  it("missing topic fails closed as a config error", async () => {
    const sink = new PubSubSink({ client: new FakeClient() });
    await assert.rejects(sink.publish([{ body: "{}" }]), PubSubSinkConfigError);
    assert.deepEqual(classifyFailure(new PubSubSinkConfigError("no topic")), {
      failureClass: "non_retryable",
    });
  });

  it("carries exactly the failed messages with mapped retry lanes", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new PubSubPublishError("UNAVAILABLE", "down"));
    client.failOn.set(2, new PubSubPublishError("PERMISSION_DENIED", "denied"));
    const sink = new PubSubSink(baseConfig(client));
    await assert.rejects(
      sink.publish([{ body: "a" }, { body: "b" }, { body: "c" }]),
      (err: unknown) => {
        assert.ok(err instanceof PubSubSinkError);
        assert.equal(err.failedRecords.length, 2);
        assert.deepEqual(err.failedRecords[0], {
          index: 0,
          errorCode: "UNAVAILABLE",
          errorMessage: "down",
          retryable: true,
        });
        assert.deepEqual(err.failedRecords[1], {
          index: 2,
          errorCode: "PERMISSION_DENIED",
          errorMessage: "denied",
          retryable: false,
        });
        return true;
      }
    );
    assert.deepEqual(sink.stats, { sent: 1, failed: 2, publishFailures: 1 });
  });

  it("treats a codeless transport failure as retryable", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hangup"));
    const sink = new PubSubSink(baseConfig(client));
    await assert.rejects(sink.publish([{ body: "a" }]), (err: unknown) => {
      assert.ok(err instanceof PubSubSinkError);
      assert.deepEqual(err.failedRecords[0], {
        index: 0,
        errorCode: "TRANSPORT_ERROR",
        errorMessage: "socket hangup",
        retryable: true,
      });
      return true;
    });
  });
});

describe("pubsub-sink failure classification", () => {
  it("maps quota and transient failures to retryable", () => {
    for (const code of [
      "TRANSPORT_ERROR",
      "RESOURCE_EXHAUSTED",
      "UNAVAILABLE",
      "DEADLINE_EXCEEDED",
      "INTERNAL",
      "ABORTED",
    ]) {
      assert.equal(classifyPubSubRecordFailure(code), true, code);
    }
  });

  it("maps fail-closed failures to non-retryable", () => {
    for (const code of [
      "PERMISSION_DENIED",
      "NOT_FOUND",
      "INVALID_ARGUMENT",
      "FAILED_PRECONDITION",
    ]) {
      assert.equal(classifyPubSubRecordFailure(code), false, code);
    }
  });
});
