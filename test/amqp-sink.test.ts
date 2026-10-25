import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  AmqpSink,
  AmqpSinkConfigError,
  AmqpSinkError,
  AmqpPublishError,
  assertValidAmqpSinkConfig,
  classifyAmqpRecordFailure,
  resolveAmqpRoutingKey,
  resolveAmqpRecord,
  type AmqpClient,
  type AmqpPublishRequest,
  type AmqpSinkConfig,
} from "../src/amqp-sink.ts";
import { classifyFailure } from "../src/failure.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.

/** In-memory fake client: records every publish, fails on demand. */
class FakeClient implements AmqpClient {
  published: AmqpPublishRequest[] = [];
  /** Call-count (0-based) → error to throw for that publish. */
  failOn = new Map<number, Error>();
  async publish(request: AmqpPublishRequest): Promise<void> {
    const n = this.published.length;
    this.published.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
  }
}

function baseConfig(
  client: AmqpClient,
  extra: Partial<AmqpSinkConfig> = {}
): AmqpSinkConfig {
  return { exchange: "events", client, ...extra };
}

describe("amqp-sink config validation", () => {
  it("accepts a minimal valid config", () => {
    assertValidAmqpSinkConfig({ exchange: "events", client: new FakeClient() }, "AmqpSink");
  });

  it("rejects an empty exchange", () => {
    assert.throws(
      () => assertValidAmqpSinkConfig({ exchange: "" }, "AmqpSink"),
      RangeError
    );
  });

  it("rejects an over-long exchange", () => {
    assert.throws(
      () => assertValidAmqpSinkConfig({ exchange: "x".repeat(128) }, "AmqpSink"),
      RangeError
    );
  });

  it("rejects an exchange with NUL", () => {
    assert.throws(
      () => assertValidAmqpSinkConfig({ exchange: "ev\0ents" }, "AmqpSink"),
      RangeError
    );
  });

  it("rejects a non-boolean persistent flag", () => {
    assert.throws(
      () =>
        assertValidAmqpSinkConfig(
          { exchange: "events", persistent: "yes", client: new FakeClient() },
          "AmqpSink"
        ),
      RangeError
    );
  });

  it("rejects a client without a publish function", () => {
    assert.throws(
      () => assertValidAmqpSinkConfig({ exchange: "events", client: {} }, "AmqpSink"),
      RangeError
    );
  });
});

describe("amqp-sink routing-key resolution", () => {
  it("prefers an explicit routingKey over key and traceId", () => {
    assert.equal(
      resolveAmqpRoutingKey(
        { body: "{}", routingKey: "orders", key: "k", traceId: "t" },
        0
      ),
      "orders"
    );
  });

  it("falls back from key to traceId", () => {
    assert.equal(
      resolveAmqpRoutingKey({ body: "{}", key: "order-9" }, 0),
      "order-9"
    );
    assert.equal(
      resolveAmqpRoutingKey({ body: "{}", traceId: "trace-1" }, 0),
      "trace-1"
    );
  });

  it("rejects a record with no routing-key source (fail-closed)", () => {
    assert.throws(
      () => resolveAmqpRoutingKey({ body: "{}" }, 2),
      /record 2 has no routing key/
    );
  });

  it("rejects an over-long routing key", () => {
    assert.throws(
      () => resolveAmqpRoutingKey({ body: "{}", key: "k".repeat(256) }, 0),
      /1–255/
    );
  });

  it("rejects a routing key with NUL", () => {
    assert.throws(
      () => resolveAmqpRoutingKey({ body: "{}", key: "or\0ders" }, 0),
      RangeError
    );
  });

  it("rejects an empty body", () => {
    assert.throws(
      () => resolveAmqpRecord({ body: "", key: "k" }, 0),
      /body/
    );
  });
});

describe("amqp-sink publish", () => {
  it("publishes with the configured exchange and persistent flag", async () => {
    const client = new FakeClient();
    const sink = new AmqpSink(baseConfig(client, { persistent: true }));
    const result = await sink.publish([
      { body: '{"a":1}', key: "order-9" },
      { body: '{"b":2}', traceId: "trace-1" },
    ]);
    assert.equal(result.ok, true);
    assert.equal(result.sent, 2);
    assert.deepEqual(
      client.published.map((p) => [p.exchange, p.routingKey, p.persistent]),
      [
        ["events", "order-9", true],
        ["events", "trace-1", true],
      ]
    );
    assert.deepEqual(sink.stats, {
      sent: 2,
      failed: 0,
      publishFailures: 0,
    });
  });

  it("defaults to non-persistent delivery", async () => {
    const client = new FakeClient();
    const sink = new AmqpSink(baseConfig(client));
    await sink.publish([{ body: "{}", key: "k" }]);
    assert.deepEqual(
      client.published.map((p) => p.persistent),
      [false]
    );
  });

  it("maps a confirm nack to the retryable lane, keeping earlier sends", async () => {
    const client = new FakeClient();
    client.failOn.set(1, new AmqpPublishError("PUBLISH_NACKED"));
    const sink = new AmqpSink(baseConfig(client));
    await assert.rejects(
      sink.publish([
        { body: "{}", key: "a" },
        { body: "{}", key: "b" },
        { body: "{}", key: "c" },
      ]),
      (err: unknown) => {
        assert.ok(err instanceof AmqpSinkError);
        assert.equal(err.failedRecords.length, 1);
        assert.equal(err.failedRecords[0]?.index, 1);
        assert.equal(err.failedRecords[0]?.errorCode, "PUBLISH_NACKED");
        assert.equal(err.failedRecords[0]?.retryable, true);
        return true;
      }
    );
    // The accepted record before the failure is not in the failed set.
    assert.equal(client.published.length, 3);
    assert.equal(sink.stats.sent, 2);
    assert.equal(sink.stats.failed, 1);
    assert.equal(sink.stats.publishFailures, 1);
  });

  it("maps a confirm timeout to the retryable lane", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new AmqpPublishError("CONFIRM_TIMEOUT"));
    const sink = new AmqpSink(baseConfig(client));
    await assert.rejects(
      sink.publish([{ body: "{}", key: "k" }]),
      (err: unknown) => {
        assert.ok(err instanceof AmqpSinkError);
        assert.equal(err.failedRecords[0]?.errorCode, "CONFIRM_TIMEOUT");
        assert.equal(err.failedRecords[0]?.retryable, true);
        return true;
      }
    );
  });

  it("maps a channel close to the retryable lane", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new AmqpPublishError("CHANNEL_CLOSED"));
    const sink = new AmqpSink(baseConfig(client));
    await assert.rejects(
      sink.publish([{ body: "{}", key: "k" }]),
      (err: unknown) => {
        assert.ok(err instanceof AmqpSinkError);
        assert.equal(err.failedRecords[0]?.retryable, true);
        return true;
      }
    );
  });

  it("treats a codeless failure as a retryable transport error", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("boom"));
    const sink = new AmqpSink(baseConfig(client));
    await assert.rejects(
      sink.publish([{ body: "{}", key: "k" }]),
      (err: unknown) => {
        assert.ok(err instanceof AmqpSinkError);
        assert.equal(err.failedRecords[0]?.errorCode, "TRANSPORT_ERROR");
        assert.equal(err.failedRecords[0]?.retryable, true);
        return true;
      }
    );
  });

  it("treats an invalid routing key failure as poison", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new AmqpPublishError("INVALID_ROUTING_KEY"));
    const sink = new AmqpSink(baseConfig(client));
    await assert.rejects(
      sink.publish([{ body: "{}", key: "k" }]),
      (err: unknown) => {
        assert.ok(err instanceof AmqpSinkError);
        assert.equal(err.failedRecords[0]?.retryable, false);
        return true;
      }
    );
  });

  it("throws a config error with no client, mapped non_retryable", async () => {
    const sink = new AmqpSink({ exchange: "events" });
    await assert.rejects(sink.publish([{ body: "{}", key: "k" }]), AmqpSinkConfigError);
    assert.equal(
      classifyFailure(new AmqpSinkConfigError()).failureClass,
      "non_retryable"
    );
  });

  it("dryRun validates with zero client I/O and no stat changes", async () => {
    const client = new FakeClient();
    const sink = new AmqpSink(baseConfig(client, { dryRun: true }));
    const result = await sink.publish([{ body: "{}", key: "k" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.published.length, 0);
    assert.deepEqual(sink.stats, {
      sent: 0,
      failed: 0,
      publishFailures: 0,
    });
    // A dry run still catches a malformed record.
    await assert.rejects(
      sink.publish([{ body: "{}", key: "" }]),
      RangeError
    );
  });
});

describe("amqp-sink failure classification", () => {
  it("classifies transient broker states retryable, poison non-retryable", () => {
    for (const code of [
      "TRANSPORT_ERROR",
      "CONNECTION_LOST",
      "NOT_CONNECTED",
      "CHANNEL_CLOSED",
      "SERVER_UNAVAILABLE",
      "PUBLISH_NACKED",
      "CONFIRM_TIMEOUT",
    ]) {
      assert.equal(classifyAmqpRecordFailure(code), true, code);
    }
    for (const code of [
      "BODY_TOO_LARGE",
      "INVALID_EXCHANGE",
      "INVALID_ROUTING_KEY",
      "NOT_AUTHORIZED",
      "SOMETHING_ELSE",
    ]) {
      assert.equal(classifyAmqpRecordFailure(code), false, code);
    }
  });
});
