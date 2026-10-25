import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  MqttSink,
  MqttSinkConfigError,
  MqttSinkError,
  MqttPublishError,
  assertValidMqttSinkConfig,
  classifyMqttRecordFailure,
  resolveMqttTopicSegment,
  resolveMqttRecord,
  type MqttClient,
  type MqttPublishRequest,
  type MqttSinkConfig,
} from "../src/mqtt-sink.ts";
import { classifyFailure } from "../src/failure.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.

/** In-memory fake client: records every publish, fails on demand. */
class FakeClient implements MqttClient {
  published: MqttPublishRequest[] = [];
  /** Call-count (0-based) → error to throw for that publish. */
  failOn = new Map<number, Error>();
  connectCalls = 0;
  async publish(request: MqttPublishRequest): Promise<void> {
    const n = this.published.length;
    this.published.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
  }
  async connect(): Promise<void> {
    this.connectCalls += 1;
  }
}

function baseConfig(
  client: MqttClient,
  extra: Partial<MqttSinkConfig> = {}
): MqttSinkConfig {
  return { topicPrefix: "events", client, ...extra };
}

describe("mqtt-sink config validation", () => {
  it("accepts a minimal valid config", () => {
    assertValidMqttSinkConfig({ client: new FakeClient() }, "MqttSink");
  });

  it("rejects a wildcard topic prefix", () => {
    assert.throws(
      () => assertValidMqttSinkConfig({ topicPrefix: "events/+" }, "MqttSink"),
      RangeError
    );
    assert.throws(
      () => assertValidMqttSinkConfig({ topicPrefix: "events/#" }, "MqttSink"),
      RangeError
    );
  });

  it("rejects an empty prefix level", () => {
    assert.throws(
      () => assertValidMqttSinkConfig({ topicPrefix: "events//orders" }, "MqttSink"),
      RangeError
    );
  });

  it("rejects an out-of-range qos", () => {
    assert.throws(
      () =>
        assertValidMqttSinkConfig(
          { qos: 3, client: new FakeClient() },
          "MqttSink"
        ),
      RangeError
    );
  });

  it("rejects a non-boolean retain", () => {
    assert.throws(
      () =>
        assertValidMqttSinkConfig(
          { retain: "yes", client: new FakeClient() },
          "MqttSink"
        ),
      RangeError
    );
  });

  it("rejects a client without a publish function", () => {
    assert.throws(
      () => assertValidMqttSinkConfig({ client: {} }, "MqttSink"),
      RangeError
    );
  });
});

describe("mqtt-sink topic resolution", () => {
  it("prefers an explicit topicKey over key and traceId", () => {
    assert.equal(
      resolveMqttTopicSegment(
        { payload: "{}", topicKey: "orders", key: "k", traceId: "t" },
        0
      ),
      "orders"
    );
  });

  it("falls back from key to traceId", () => {
    assert.equal(
      resolveMqttTopicSegment({ payload: "{}", key: "order-9" }, 0),
      "order-9"
    );
    assert.equal(
      resolveMqttTopicSegment({ payload: "{}", traceId: "trace-1" }, 0),
      "trace-1"
    );
  });

  it("rejects a record with no topic source (fail-closed)", () => {
    assert.throws(
      () => resolveMqttTopicSegment({ payload: "{}" }, 2),
      /record 2 has no topic segment/
    );
  });

  it("rejects a segment that would fan out into sub-levels", () => {
    assert.throws(
      () => resolveMqttTopicSegment({ payload: "{}", key: "a/b" }, 0),
      /must not contain/
    );
  });

  it("rejects wildcard segments", () => {
    assert.throws(
      () => resolveMqttTopicSegment({ payload: "{}", key: "a+b" }, 0),
      RangeError
    );
  });

  it("prepends the prefix as one level, or uses the segment alone", () => {
    assert.equal(
      resolveMqttRecord({ payload: "{}", key: "order-9" }, 0, "events").topic,
      "events/order-9"
    );
    assert.equal(
      resolveMqttRecord({ payload: "{}", key: "order-9" }, 0).topic,
      "order-9"
    );
  });

  it("rejects an empty payload", () => {
    assert.throws(
      () => resolveMqttRecord({ payload: "", key: "k" }, 0),
      /payload/
    );
  });
});

describe("mqtt-sink publish", () => {
  it("publishes with the configured qos and retain flag", async () => {
    const client = new FakeClient();
    const sink = new MqttSink(baseConfig(client, { qos: 2, retain: true }));
    const result = await sink.publish([
      { payload: '{"a":1}', key: "order-9" },
      { payload: '{"b":2}', traceId: "trace-1" },
    ]);
    assert.equal(result.ok, true);
    assert.equal(result.sent, 2);
    assert.deepEqual(result.downgrades, []);
    assert.deepEqual(
      client.published.map((p) => [p.topic, p.qos, p.retain]),
      [
        ["events/order-9", 2, true],
        ["events/trace-1", 2, true],
      ]
    );
    assert.deepEqual(sink.stats, {
      sent: 2,
      failed: 0,
      downgrades: 0,
      publishFailures: 0,
    });
  });

  it("defaults to qos 1 and retain false", async () => {
    const client = new FakeClient();
    const sink = new MqttSink(baseConfig(client));
    await sink.publish([{ payload: "{}", key: "k" }]);
    assert.deepEqual(
      client.published.map((p) => [p.qos, p.retain]),
      [[1, false]]
    );
  });

  it("downgrades qos inside the call and reports the delivered level", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new MqttPublishError("QOS_NOT_SUPPORTED"));
    const sink = new MqttSink(baseConfig(client, { qos: 2 }));
    const result = await sink.publish([{ payload: "{}", key: "k" }]);
    assert.equal(result.sent, 1);
    assert.deepEqual(result.downgrades, [
      { index: 0, requested: 2, delivered: 1 },
    ]);
    assert.deepEqual(
      client.published.map((p) => p.qos),
      [2, 1]
    );
    assert.equal(sink.stats.downgrades, 1);
  });

  it("steps down twice when the broker only honours qos 0", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new MqttPublishError("QOS_NOT_SUPPORTED"));
    client.failOn.set(1, new MqttPublishError("QOS_NOT_SUPPORTED"));
    const sink = new MqttSink(baseConfig(client, { qos: 2 }));
    const result = await sink.publish([{ payload: "{}", key: "k" }]);
    assert.deepEqual(result.downgrades, [
      { index: 0, requested: 2, delivered: 0 },
    ]);
    assert.deepEqual(
      client.published.map((p) => p.qos),
      [2, 1, 0]
    );
  });

  it("treats a qos 0 rejection as a poison record (no lower level)", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new MqttPublishError("QOS_NOT_SUPPORTED"));
    const sink = new MqttSink(baseConfig(client, { qos: 0 }));
    await assert.rejects(
      sink.publish([{ payload: "{}", key: "k" }]),
      (err: unknown) => {
        assert.ok(err instanceof MqttSinkError);
        assert.equal(err.failedRecords.length, 1);
        assert.equal(err.failedRecords[0]?.errorCode, "QOS_NOT_SUPPORTED");
        assert.equal(err.failedRecords[0]?.retryable, false);
        return true;
      }
    );
  });

  it("maps connection failures to the retryable lane and marks disconnected", async () => {
    const client = new FakeClient();
    client.failOn.set(1, new MqttPublishError("CONNECTION_LOST"));
    const sink = new MqttSink(baseConfig(client));
    assert.equal(sink.isConnected, true);
    await assert.rejects(
      sink.publish([
        { payload: "{}", key: "a" },
        { payload: "{}", key: "b" },
        { payload: "{}", key: "c" },
      ]),
      (err: unknown) => {
        assert.ok(err instanceof MqttSinkError);
        assert.equal(err.failedRecords.length, 1);
        assert.equal(err.failedRecords[0]?.index, 1);
        assert.equal(err.failedRecords[0]?.retryable, true);
        return true;
      }
    );
    assert.equal(sink.isConnected, false);
    // The accepted record before the failure is not in the failed set.
    assert.equal(client.published.length, 3);
    assert.equal(sink.stats.sent, 2);
    assert.equal(sink.stats.failed, 1);
    assert.equal(sink.stats.publishFailures, 1);
  });

  it("reconnect re-arms the sink after the client is restored", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hung up"));
    const sink = new MqttSink(baseConfig(client));
    await assert.rejects(sink.publish([{ payload: "{}", key: "k" }]));
    assert.equal(sink.isConnected, false);
    await sink.reconnect();
    assert.equal(sink.isConnected, true);
    assert.equal(client.connectCalls, 1);
    // The replayed record now lands.
    const result = await sink.publish([{ payload: "{}", key: "k" }]);
    assert.equal(result.sent, 1);
  });

  it("treats a codeless failure as a retryable transport error", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("boom"));
    const sink = new MqttSink(baseConfig(client));
    await assert.rejects(
      sink.publish([{ payload: "{}", key: "k" }]),
      (err: unknown) => {
        assert.ok(err instanceof MqttSinkError);
        assert.equal(err.failedRecords[0]?.errorCode, "TRANSPORT_ERROR");
        assert.equal(err.failedRecords[0]?.retryable, true);
        return true;
      }
    );
    assert.equal(sink.isConnected, false);
  });

  it("throws a config error with no client, mapped non_retryable", async () => {
    const sink = new MqttSink({ topicPrefix: "events" });
    await assert.rejects(sink.publish([{ payload: "{}", key: "k" }]), MqttSinkConfigError);
    assert.equal(
      classifyFailure(new MqttSinkConfigError()).failureClass,
      "non_retryable"
    );
  });

  it("dryRun validates with zero client I/O and no stat changes", async () => {
    const client = new FakeClient();
    const sink = new MqttSink(baseConfig(client, { dryRun: true }));
    const result = await sink.publish([{ payload: "{}", key: "k" }]);
    assert.deepEqual(result, { ok: true, sent: 0, downgrades: [], dryRun: true });
    assert.equal(client.published.length, 0);
    assert.deepEqual(sink.stats, {
      sent: 0,
      failed: 0,
      downgrades: 0,
      publishFailures: 0,
    });
    // A dry run still catches a malformed record.
    await assert.rejects(
      sink.publish([{ payload: "{}", key: "" }]),
      RangeError
    );
  });
});

describe("mqtt-sink failure classification", () => {
  it("classifies transient broker states retryable, poison non-retryable", () => {
    for (const code of [
      "TRANSPORT_ERROR",
      "CONNECTION_LOST",
      "NOT_CONNECTED",
      "SERVER_UNAVAILABLE",
    ]) {
      assert.equal(classifyMqttRecordFailure(code), true, code);
    }
    for (const code of [
      "PAYLOAD_TOO_LARGE",
      "INVALID_TOPIC",
      "NOT_AUTHORIZED",
      "QOS_NOT_SUPPORTED",
      "SOMETHING_ELSE",
    ]) {
      assert.equal(classifyMqttRecordFailure(code), false, code);
    }
  });
});
