import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  KafkaSink,
  KafkaSinkConfigError,
  KafkaSinkError,
  KafkaProduceError,
  assertValidKafkaSinkConfig,
  classifyKafkaRecordFailure,
  resolveKafkaPartitionKey,
  resolveKafkaRecord,
  type KafkaAcks,
  type KafkaProducer,
  type KafkaProduceRequest,
  type KafkaSinkConfig,
} from "../src/kafka-sink.ts";
import { classifyFailure } from "../src/failure.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.
const testTopic = "events-topic";

/** In-memory fake producer: records every send, fails on demand. */
class FakeProducer implements KafkaProducer {
  sent: KafkaProduceRequest[] = [];
  /** Call-count (0-based) → error to throw for that send. */
  failOn = new Map<number, Error>();
  async send(request: KafkaProduceRequest): Promise<{ partition: number; offset: number }> {
    const n = this.sent.length;
    this.sent.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { partition: 0, offset: n };
  }
}

function baseConfig(
  producer: KafkaProducer,
  extra: Partial<KafkaSinkConfig> = {}
): KafkaSinkConfig {
  return { topic: testTopic, producer, ...extra };
}

describe("kafka-sink config validation", () => {
  it("rejects a non-object, an empty topic, and a bad topic name", () => {
    assert.throws(() => assertValidKafkaSinkConfig(null, "x"), RangeError);
    assert.throws(() => assertValidKafkaSinkConfig(baseConfig(new FakeProducer(), { topic: "" }), "x"), /topic/);
    assert.throws(() => assertValidKafkaSinkConfig(baseConfig(new FakeProducer(), { topic: "bad topic!" }), "x"), /topic/);
  });

  it("rejects bad acks, a producer without send, and a negative dedup window", () => {
    const producer = new FakeProducer();
    assert.throws(
      () => assertValidKafkaSinkConfig(baseConfig(producer, { acks: "2" as KafkaAcks }), "x"),
      /acks/
    );
    assert.throws(
      () => assertValidKafkaSinkConfig(baseConfig(producer, { producer: {} as KafkaProducer }), "x"),
      /producer/
    );
    assert.throws(
      () => assertValidKafkaSinkConfig(baseConfig(producer, { dedupWindowMs: -1 }), "x"),
      /dedupWindowMs/
    );
  });

  it("accepts every acks level and a zero dedup window (dedup off)", () => {
    const producer = new FakeProducer();
    for (const acks of ["all", "1", "0"] as KafkaAcks[]) {
      assert.doesNotThrow(() => assertValidKafkaSinkConfig(baseConfig(producer, { acks }), "x"));
    }
    assert.doesNotThrow(() => assertValidKafkaSinkConfig(baseConfig(producer, { dedupWindowMs: 0 }), "x"));
  });
});

describe("kafka-sink partition key resolution", () => {
  it("prefers explicit partitionKey, then key, then traceId", () => {
    assert.equal(
      resolveKafkaPartitionKey({ value: "{}", partitionKey: "explicit", key: "k", traceId: "t" }, 0),
      "explicit"
    );
    assert.equal(resolveKafkaPartitionKey({ value: "{}", key: "k", traceId: "t" }, 1), "k");
    assert.equal(resolveKafkaPartitionKey({ value: "{}", traceId: "t" }, 2), "t");
  });

  it("rejects a record with no key source and an empty resolved key", () => {
    assert.throws(() => resolveKafkaPartitionKey({ value: "{}" }, 3), /no partition key/);
    assert.throws(() => resolveKafkaPartitionKey({ value: "{}", key: "" }, 4), /no partition key/);
  });

  it("rejects an empty value and a non-string header value", () => {
    assert.throws(() => resolveKafkaRecord({ value: "", key: "k" }, 0), /value/);
    assert.throws(
      () => resolveKafkaRecord({ value: "{}", key: "k", headers: { h: 1 as unknown as string } }, 1),
      /header/
    );
  });

  it("carries headers through resolution", () => {
    const resolved = resolveKafkaRecord({ value: "{}", key: "k", headers: { tenant: "t-1" } }, 0);
    assert.deepEqual(resolved.headers, { tenant: "t-1" });
  });
});

describe("kafka-sink produce", () => {
  it("passes the resolved key, value, and default acks to the producer", async () => {
    const producer = new FakeProducer();
    const sink = new KafkaSink(baseConfig(producer));
    const result = await sink.produce([
      { value: '{"a":1}', key: "order-9" },
      { value: '{"b":2}', traceId: "trace-1" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2, duplicates: [] });
    assert.equal(producer.sent.length, 2);
    assert.equal(producer.sent[0]?.topic, testTopic);
    assert.equal(producer.sent[0]?.key, "order-9");
    assert.equal(producer.sent[0]?.value, '{"a":1}');
    assert.equal(producer.sent[0]?.acks, "all");
    assert.equal(producer.sent[1]?.key, "trace-1");
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, duplicates: 0, sendFailures: 0 });
  });

  it("passes configured acks levels through to the producer", async () => {
    for (const acks of ["1", "0"] as KafkaAcks[]) {
      const producer = new FakeProducer();
      const sink = new KafkaSink(baseConfig(producer, { acks }));
      await sink.produce([{ value: "{}", key: "k" }]);
      assert.equal(producer.sent[0]?.acks, acks);
    }
  });

  it("passes headers through to the producer", async () => {
    const producer = new FakeProducer();
    const sink = new KafkaSink(baseConfig(producer));
    await sink.produce([{ value: "{}", key: "k", headers: { tenant: "t-1" } }]);
    assert.deepEqual(producer.sent[0]?.headers, { tenant: "t-1" });
  });

  it("dryRun performs zero producer I/O and changes no stats", async () => {
    const producer = new FakeProducer();
    const sink = new KafkaSink(baseConfig(producer, { dryRun: true }));
    const result = await sink.produce([{ value: "{}", key: "k" }]);
    assert.deepEqual(result, { ok: true, sent: 0, duplicates: [], dryRun: true });
    assert.equal(producer.sent.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, duplicates: 0, sendFailures: 0 });
  });

  it("dryRun still validates records before anything else", async () => {
    const producer = new FakeProducer();
    const sink = new KafkaSink(baseConfig(producer, { dryRun: true }));
    await assert.rejects(() => sink.produce([{ value: "{}", key: "" }]), RangeError);
    assert.equal(producer.sent.length, 0);
  });

  it("throws a config error when no producer was injected", async () => {
    const sink = new KafkaSink({ topic: testTopic });
    await assert.rejects(() => sink.produce([{ value: "{}", key: "k" }]), (err: unknown) => {
      assert.ok(err instanceof KafkaSinkConfigError);
      assert.ok(err instanceof KafkaSinkError);
      return true;
    });
    assert.equal(classifyFailure(new KafkaSinkConfigError()).failureClass, "non_retryable");
  });

  it("dryRun needs no producer at all", async () => {
    const sink = new KafkaSink({ topic: testTopic, dryRun: true });
    const result = await sink.produce([{ value: "{}", key: "k" }]);
    assert.equal(result.dryRun, true);
  });
});

describe("kafka-sink dedup window", () => {
  it("skips a repeat key inside the window and reports its index", async () => {
    const producer = new FakeProducer();
    let clock = 1_000;
    const sink = new KafkaSink(baseConfig(producer, { dedupWindowMs: 60_000, now: () => clock }));
    const first = await sink.produce([
      { value: '{"n":1}', key: "order-9" },
      { value: '{"n":2}', key: "order-10" },
    ]);
    assert.deepEqual(first.duplicates, []);
    const second = await sink.produce([
      { value: '{"n":3}', key: "order-9" },
      { value: '{"n":4}', key: "order-11" },
    ]);
    assert.deepEqual(second, { ok: true, sent: 1, duplicates: [0] });
    assert.equal(producer.sent.length, 3);
    assert.equal(producer.sent[2]?.key, "order-11");
    assert.deepEqual(sink.stats, { sent: 3, failed: 0, duplicates: 1, sendFailures: 0 });
    clock += 60_000;
    const third = await sink.produce([{ value: '{"n":5}', key: "order-9" }]);
    assert.deepEqual(third.duplicates, []);
    assert.equal(producer.sent.length, 4);
  });

  it("does not dedup when the window is unset", async () => {
    const producer = new FakeProducer();
    const sink = new KafkaSink(baseConfig(producer));
    await sink.produce([{ value: "{}", key: "k" }]);
    const second = await sink.produce([{ value: "{}", key: "k" }]);
    assert.deepEqual(second.duplicates, []);
    assert.equal(producer.sent.length, 2);
  });

  it("a failed produce does not arm the dedup window", async () => {
    const producer = new FakeProducer();
    producer.failOn.set(0, new KafkaProduceError("REQUEST_TIMED_OUT"));
    const sink = new KafkaSink(baseConfig(producer, { dedupWindowMs: 60_000 }));
    await assert.rejects(() => sink.produce([{ value: "{}", key: "k" }]), KafkaSinkError);
    producer.failOn.clear();
    const retry = await sink.produce([{ value: "{}", key: "k" }]);
    assert.deepEqual(retry.duplicates, []);
    assert.equal(producer.sent.length, 2);
  });
});

describe("kafka-sink failure mapping", () => {
  it("maps transient broker codes to retryable and poison codes to non-retryable", () => {
    for (const code of [
      "NOT_LEADER_OR_FOLLOWER",
      "LEADER_NOT_AVAILABLE",
      "REQUEST_TIMED_OUT",
      "NETWORK_EXCEPTION",
      "UNKNOWN_TOPIC_OR_PARTITION",
      "TRANSPORT_ERROR",
    ]) {
      assert.equal(classifyKafkaRecordFailure(code), true, code);
    }
    for (const code of ["MESSAGE_TOO_LARGE", "RECORD_TOO_LARGE", "INVALID_TOPIC", "INVALID_RECORD"]) {
      assert.equal(classifyKafkaRecordFailure(code), false, code);
    }
  });

  it("throws SinkError carrying exactly the failed records with retry lanes", async () => {
    const producer = new FakeProducer();
    producer.failOn.set(1, new KafkaProduceError("NOT_LEADER_OR_FOLLOWER", "not the leader"));
    producer.failOn.set(2, new KafkaProduceError("MESSAGE_TOO_LARGE", "too big"));
    const sink = new KafkaSink(baseConfig(producer));
    await assert.rejects(
      () =>
        sink.produce([
          { value: '{"n":1}', key: "a" },
          { value: '{"n":2}', key: "b" },
          { value: '{"n":3}', key: "c" },
        ]),
      (err: unknown) => {
        assert.ok(err instanceof KafkaSinkError);
        assert.equal(err.failedRecords.length, 2);
        assert.deepEqual(err.failedRecords[0], {
          index: 1,
          errorCode: "NOT_LEADER_OR_FOLLOWER",
          errorMessage: "not the leader",
          retryable: true,
        });
        assert.deepEqual(err.failedRecords[1], {
          index: 2,
          errorCode: "MESSAGE_TOO_LARGE",
          errorMessage: "too big",
          retryable: false,
        });
        return true;
      }
    );
    // The accepted record is already in the topic and is not retried.
    assert.equal(producer.sent.length, 3);
    assert.deepEqual(sink.stats, { sent: 1, failed: 2, duplicates: 0, sendFailures: 1 });
  });

  it("maps a codeless producer throw to a retryable transport failure", async () => {
    const producer = new FakeProducer();
    producer.failOn.set(0, new Error("connection reset"));
    const sink = new KafkaSink(baseConfig(producer));
    await assert.rejects(
      () => sink.produce([{ value: "{}", key: "k" }]),
      (err: unknown) => {
        assert.ok(err instanceof KafkaSinkError);
        assert.deepEqual(err.failedRecords, [
          { index: 0, errorCode: "TRANSPORT_ERROR", errorMessage: "connection reset", retryable: true },
        ]);
        return true;
      }
    );
  });
});
