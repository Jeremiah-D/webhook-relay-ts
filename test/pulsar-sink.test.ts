import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  PulsarSink,
  PulsarSinkConfigError,
  PulsarSinkError,
  PulsarProduceError,
  assertValidPulsarSinkConfig,
  classifyPulsarRecordFailure,
  resolvePulsarProperties,
  resolvePulsarTopic,
  resolvePulsarPartitionKey,
  resolvePulsarRecord,
  type PulsarClient,
  type PulsarProduceRequest,
  type PulsarSinkConfig,
} from "../src/pulsar-sink.ts";
import { classifyFailure } from "../src/failure.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.

/** In-memory fake client: records every produce, fails on demand, returns ids. */
class FakeClient implements PulsarClient {
  sent: PulsarProduceRequest[] = [];
  /** Call-count (0-based) → error to throw for that produce. */
  failOn = new Map<number, Error>();
  async produce(request: PulsarProduceRequest): Promise<string> {
    const n = this.sent.length;
    this.sent.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return `msg-${n}`;
  }
}

function baseConfig(
  client: PulsarClient,
  extra: Partial<PulsarSinkConfig> = {}
): PulsarSinkConfig {
  return { topic: "persistent://public/default/events", client, ...extra };
}

describe("pulsar-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidPulsarSinkConfig(null, "PulsarSink"), RangeError);
    assert.throws(() => assertValidPulsarSinkConfig("x", "PulsarSink"), RangeError);
  });

  it("rejects a malformed topic name", () => {
    assert.throws(
      () => assertValidPulsarSinkConfig({ topic: "" }, "PulsarSink"),
      RangeError
    );
    assert.throws(
      () => assertValidPulsarSinkConfig({ topic: "has space" }, "PulsarSink"),
      RangeError
    );
    assert.throws(
      () => assertValidPulsarSinkConfig({ topic: "has\0nul" }, "PulsarSink"),
      RangeError
    );
  });

  it("rejects a client without a produce function", () => {
    assert.throws(
      () => assertValidPulsarSinkConfig({ topic: "t", client: {} }, "PulsarSink"),
      RangeError
    );
  });

  it("accepts a topic-less config (per-record resolution instead)", () => {
    assertValidPulsarSinkConfig({ client: new FakeClient() }, "PulsarSink");
  });
});

describe("pulsar-sink topic resolution", () => {
  it("prefers the configured topic over any record source", () => {
    assert.equal(
      resolvePulsarTopic(
        { body: "{}", subject: "s", key: "k", traceId: "t" },
        { topic: "persistent://public/default/events" }
      ),
      "persistent://public/default/events"
    );
  });

  it("resolves subject, then key, then traceId when unconfigured", () => {
    assert.equal(resolvePulsarTopic({ body: "{}", subject: "s", key: "k", traceId: "t" }, {}), "s");
    assert.equal(resolvePulsarTopic({ body: "{}", key: "k", traceId: "t" }, {}), "k");
    assert.equal(resolvePulsarTopic({ body: "{}", traceId: "t" }, {}), "t");
  });

  it("skips empty sources in the chain", () => {
    assert.equal(
      resolvePulsarTopic({ body: "{}", subject: "", key: "", traceId: "t" }, {}),
      "t"
    );
  });

  it("returns undefined when no source exists", () => {
    assert.equal(resolvePulsarTopic({ body: "{}" }, {}), undefined);
  });

  it("fails closed on a topic-less record instead of inventing a topic", () => {
    assert.throws(() => resolvePulsarRecord({ body: "{}" }, 1, {}), RangeError);
  });

  it("fails closed on an empty body", () => {
    assert.throws(() => resolvePulsarRecord({ body: "", subject: "s" }, 0, {}), RangeError);
  });
});

describe("pulsar-sink property pass-through and partition keys", () => {
  it("passes tenant, endpoint, and trace verbatim", () => {
    assert.deepEqual(
      resolvePulsarProperties({
        body: "{}",
        tenant: "tenant-1",
        endpoint: "ep-9",
        traceId: "trace-9",
      }),
      { tenant: "tenant-1", endpoint: "ep-9", trace: "trace-9" }
    );
  });

  it("invents no property for a missing value", () => {
    assert.deepEqual(resolvePulsarProperties({ body: "{}" }), {});
    assert.deepEqual(resolvePulsarProperties({ body: "{}", tenant: "" }), {});
  });

  it("attaches the key as partition key only under the opt-in", () => {
    assert.equal(
      resolvePulsarPartitionKey({ body: "{}", key: "k-1" }, { partitionKey: true }),
      "k-1"
    );
    assert.equal(
      resolvePulsarPartitionKey({ body: "{}", key: "k-1" }, {}),
      undefined
    );
    assert.equal(
      resolvePulsarPartitionKey({ body: "{}", key: "k-1" }, { partitionKey: false }),
      undefined
    );
    assert.equal(
      resolvePulsarPartitionKey({ body: "{}" }, { partitionKey: true }),
      undefined
    );
  });

  it("resolves a full record: topic, properties, partition key", () => {
    assert.deepEqual(
      resolvePulsarRecord(
        { body: "{}", subject: "s", key: "k-1", tenant: "t1", traceId: "tr-1" },
        0,
        { partitionKey: true }
      ),
      {
        topic: "s",
        data: "{}",
        properties: { tenant: "t1", trace: "tr-1" },
        partitionKey: "k-1",
      }
    );
  });
});

describe("pulsar-sink failure classification", () => {
  it("marks connection, produce, timeout, and transport failures retryable", () => {
    for (const code of [
      "TRANSPORT_ERROR",
      "ConnectionFailed",
      "ProduceFailed",
      "TimeoutError",
      "ServiceNotReady",
    ]) {
      assert.equal(classifyPulsarRecordFailure(code), true, code);
    }
  });

  it("marks permission, unknown topic, and malformed message fail-closed", () => {
    for (const code of [
      "AuthenticationError",
      "AuthorizationError",
      "TopicNotFound",
      "InvalidMessage",
      "SchemaError",
    ]) {
      assert.equal(classifyPulsarRecordFailure(code), false, code);
    }
  });
});

describe("pulsar-sink produce", () => {
  it("produces one message per record to the configured topic", async () => {
    const client = new FakeClient();
    const sink = new PulsarSink(baseConfig(client, { partitionKey: true }));
    const result = await sink.produce([
      { body: '{"a":1}', tenant: "t1", traceId: "tr-1", key: "k-1" },
      { body: '{"b":2}' },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.deepEqual(client.sent, [
      {
        topic: "persistent://public/default/events",
        data: '{"a":1}',
        properties: { tenant: "t1", trace: "tr-1" },
        partitionKey: "k-1",
      },
      { topic: "persistent://public/default/events", data: '{"b":2}', properties: {} },
    ]);
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, produceFailures: 0 });
  });

  it("resolves topics per record when unconfigured", async () => {
    const client = new FakeClient();
    const sink = new PulsarSink({ client });
    await sink.produce([
      { body: "{}", subject: "orders" },
      { body: "{}", key: "k-2" },
      { body: "{}", traceId: "tr-3" },
    ]);
    assert.deepEqual(
      client.sent.map((r) => r.topic),
      ["orders", "k-2", "tr-3"]
    );
  });

  it("dry-runs with zero client I/O and untouched stats, but still validates", async () => {
    const client = new FakeClient();
    const sink = new PulsarSink(baseConfig(client, { dryRun: true }));
    const result = await sink.produce([{ body: "{}", subject: "s" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.sent.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, produceFailures: 0 });
    const unconfiguredDry = new PulsarSink({ client, dryRun: true });
    await assert.rejects(() => unconfiguredDry.produce([{ body: "{}" }]), RangeError);
  });

  it("throws a config error with no client", async () => {
    const noClient = new PulsarSink({ topic: "t" });
    await assert.rejects(() => noClient.produce([{ body: "{}", subject: "s" }]), PulsarSinkConfigError);
  });

  it("does not treat a missing topic as a config error", async () => {
    const client = new FakeClient();
    const sink = new PulsarSink({ client });
    const result = await sink.produce([{ body: "{}", subject: "s" }]);
    assert.deepEqual(result, { ok: true, sent: 1 });
  });

  it("maps a config error to non_retryable via classifyFailure", () => {
    assert.deepEqual(
      classifyFailure(new PulsarSinkConfigError("no client injected")),
      { failureClass: "non_retryable" }
    );
  });

  it("carries exactly the failed messages with their retry lanes", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new PulsarProduceError("ConnectionFailed", "broker down"));
    client.failOn.set(2, new PulsarProduceError("AuthorizationError", "denied"));
    const sink = new PulsarSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.produce([
          { body: "{}", subject: "a" },
          { body: "{}", subject: "b" },
          { body: "{}", subject: "c" },
        ]),
      (err: unknown) => {
        assert.ok(err instanceof PulsarSinkError);
        assert.deepEqual(err.failedRecords, [
          { index: 0, errorCode: "ConnectionFailed", errorMessage: "broker down", retryable: true },
          { index: 2, errorCode: "AuthorizationError", errorMessage: "denied", retryable: false },
        ]);
        return true;
      }
    );
    assert.deepEqual(sink.stats, { sent: 1, failed: 2, produceFailures: 1 });
  });

  it("treats a codeless throw as a retryable transport failure", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hung up"));
    const sink = new PulsarSink(baseConfig(client));
    await assert.rejects(
      () => sink.produce([{ body: "{}", subject: "a" }]),
      (err: unknown) => {
        assert.ok(err instanceof PulsarSinkError);
        assert.deepEqual(err.failedRecords, [
          { index: 0, errorCode: "TRANSPORT_ERROR", errorMessage: "socket hung up", retryable: true },
        ]);
        return true;
      }
    );
  });
});
