import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  RedisSink,
  RedisSinkConfigError,
  RedisSinkError,
  RedisXAddError,
  assertValidRedisSinkConfig,
  classifyRedisRecordFailure,
  resolveRedisStreamKey,
  resolveRedisFields,
  resolveRedisRecord,
  type RedisStreamsClient,
  type RedisXAddRequest,
  type RedisSinkConfig,
} from "../src/redis-sink.ts";
import { classifyFailure } from "../src/failure.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.

/** In-memory fake client: records every XADD, fails on demand. */
class FakeClient implements RedisStreamsClient {
  xadded: RedisXAddRequest[] = [];
  /** Call-count (0-based) → error to throw for that XADD. */
  failOn = new Map<number, Error>();
  async xadd(request: RedisXAddRequest): Promise<string> {
    const n = this.xadded.length;
    this.xadded.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return `${Date.now()}-${n}`;
  }
}

function baseConfig(
  client: RedisStreamsClient,
  extra: Partial<RedisSinkConfig> = {}
): RedisSinkConfig {
  return { client, ...extra };
}

describe("redis-sink config validation", () => {
  it("accepts a minimal valid config (no fixed stream)", () => {
    assertValidRedisSinkConfig({ client: new FakeClient() }, "RedisSink");
  });

  it("accepts a fixed stream config", () => {
    assertValidRedisSinkConfig({ stream: "events", client: new FakeClient() }, "RedisSink");
  });

  it("rejects an empty fixed stream", () => {
    assert.throws(() => assertValidRedisSinkConfig({ stream: "" }, "RedisSink"), RangeError);
  });

  it("rejects an over-long fixed stream", () => {
    assert.throws(
      () => assertValidRedisSinkConfig({ stream: "x".repeat(256) }, "RedisSink"),
      RangeError
    );
  });

  it("rejects a fixed stream with NUL", () => {
    assert.throws(
      () => assertValidRedisSinkConfig({ stream: "ev\0ents" }, "RedisSink"),
      RangeError
    );
  });

  it("rejects a fixed stream with whitespace", () => {
    assert.throws(
      () => assertValidRedisSinkConfig({ stream: "ev ents" }, "RedisSink"),
      RangeError
    );
  });

  it("rejects a client without an xadd function", () => {
    assert.throws(
      () => assertValidRedisSinkConfig({ client: {} }, "RedisSink"),
      RangeError
    );
  });
});

describe("redis-sink stream-key resolution", () => {
  it("prefers an explicit subject over key and traceId", () => {
    assert.equal(
      resolveRedisStreamKey({ body: "{}", subject: "orders.created", key: "k", traceId: "t" }, 0),
      "orders.created"
    );
  });

  it("falls back from key to traceId", () => {
    assert.equal(resolveRedisStreamKey({ body: "{}", key: "order-9" }, 0), "order-9");
    assert.equal(resolveRedisStreamKey({ body: "{}", traceId: "trace-1" }, 0), "trace-1");
  });

  it("rejects a record with no stream-key source (fail-closed)", () => {
    assert.throws(() => resolveRedisStreamKey({ body: "{}" }, 2), /record 2 has no stream key/);
  });

  it("rejects an over-long stream key", () => {
    assert.throws(
      () => resolveRedisStreamKey({ body: "{}", key: "k".repeat(256) }, 0),
      /1–255/
    );
  });

  it("rejects a stream key with NUL", () => {
    assert.throws(
      () => resolveRedisStreamKey({ body: "{}", key: "or\0ders" }, 0),
      RangeError
    );
  });

  it("rejects a stream key with whitespace", () => {
    assert.throws(
      () => resolveRedisStreamKey({ body: "{}", key: "or ders" }, 0),
      RangeError
    );
  });

  it("a fixed stream wins over per-record resolution", () => {
    const resolved = resolveRedisRecord({ body: "{}", key: "order-9" }, 0, "events");
    assert.equal(resolved.stream, "events");
  });

  it("without a fixed stream the record resolves its own key", () => {
    const resolved = resolveRedisRecord({ body: "{}", key: "order-9" }, 0);
    assert.equal(resolved.stream, "order-9");
  });

  it("rejects an empty body", () => {
    assert.throws(() => resolveRedisRecord({ body: "" }, 1), /record 1 `body`/);
  });
});

describe("redis-sink trace-id fields", () => {
  it("passes traceId through as the trace-id field", () => {
    assert.deepEqual(resolveRedisFields({ body: "{}", traceId: "trace-9" }), {
      body: "{}",
      "trace-id": "trace-9",
    });
  });

  it("never invents a trace-id field", () => {
    assert.deepEqual(resolveRedisFields({ body: "{}" }), { body: "{}" });
  });
});

describe("redis-sink failure classification", () => {
  it("maps transient Redis states to retryable", () => {
    for (const code of [
      "TRANSPORT_ERROR",
      "CONNECTION_LOST",
      "NOT_CONNECTED",
      "XADD_FAILED",
      "TIMEOUT",
      "STREAM_UNAVAILABLE",
    ]) {
      assert.equal(classifyRedisRecordFailure(code), true, code);
    }
  });

  it("maps fail-closed states to non-retryable", () => {
    for (const code of ["WRONGTYPE", "MESSAGE_TOO_LARGE", "NOAUTH", "UNKNOWN_CODE"]) {
      assert.equal(classifyRedisRecordFailure(code), false, code);
    }
  });
});

describe("redis-sink publish", () => {
  it("xadds each record to its resolved stream with body and trace-id fields", async () => {
    const client = new FakeClient();
    const sink = new RedisSink(baseConfig(client));
    const result = await sink.publish([
      { body: '{"a":1}', key: "order-9", traceId: "trace-9" },
      { body: '{"b":2}', traceId: "trace-1" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.xadded.length, 2);
    assert.equal(client.xadded[0]?.stream, "order-9");
    assert.deepEqual(client.xadded[0]?.fields, { body: '{"a":1}', "trace-id": "trace-9" });
    assert.equal(client.xadded[1]?.stream, "trace-1");
    assert.deepEqual(client.xadded[1]?.fields, { body: '{"b":2}', "trace-id": "trace-1" });
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, publishFailures: 0 });
  });

  it("xadds every record to the fixed stream when one is configured", async () => {
    const client = new FakeClient();
    const sink = new RedisSink(baseConfig(client, { stream: "events" }));
    await sink.publish([{ body: "{}", key: "order-9" }]);
    assert.equal(client.xadded[0]?.stream, "events");
  });

  it("throws RedisSinkConfigError with no client, mapped non_retryable", async () => {
    const sink = new RedisSink({});
    await assert.rejects(() => sink.publish([{ body: "{}", key: "k" }]), RedisSinkConfigError);
    assert.deepEqual(classifyFailure(new RedisSinkConfigError()), {
      failureClass: "non_retryable",
    });
  });

  it("carries exactly the failed records with retry lanes, in order", async () => {
    const client = new FakeClient();
    client.failOn.set(1, new RedisXAddError("CONNECTION_LOST", "conn dropped"));
    client.failOn.set(2, new RedisXAddError("WRONGTYPE", "key holds a string"));
    const sink = new RedisSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.publish([
          { body: "{}", key: "k0" },
          { body: "{}", key: "k1" },
          { body: "{}", key: "k2" },
          { body: "{}", key: "k3" },
        ]),
      (err: unknown) => {
        assert.ok(err instanceof RedisSinkError);
        assert.deepEqual(err.failedRecords, [
          { index: 1, errorCode: "CONNECTION_LOST", errorMessage: "conn dropped", retryable: true },
          { index: 2, errorCode: "WRONGTYPE", errorMessage: "key holds a string", retryable: false },
        ]);
        return true;
      }
    );
    // Accepted records are not in failedRecords; counters stay honest.
    assert.deepEqual(sink.stats, { sent: 2, failed: 2, publishFailures: 1 });
  });

  it("treats a codeless throw as a retryable transport failure", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hangup"));
    const sink = new RedisSink(baseConfig(client));
    await assert.rejects(
      () => sink.publish([{ body: "{}", key: "k" }]),
      (err: unknown) => {
        assert.ok(err instanceof RedisSinkError);
        assert.deepEqual(err.failedRecords, [
          { index: 0, errorCode: "TRANSPORT_ERROR", errorMessage: "socket hangup", retryable: true },
        ]);
        return true;
      }
    );
  });

  it("dryRun validates with zero client I/O and zero stat changes", async () => {
    const client = new FakeClient();
    const sink = new RedisSink(baseConfig(client, { dryRun: true }));
    const result = await sink.publish([{ body: "{}", key: "k" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.xadded.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, publishFailures: 0 });
    // ...but still catches a malformed record.
    await assert.rejects(() => sink.publish([{ body: "{}" }]), /has no stream key/);
  });

  it("dryRun needs no client at all", async () => {
    const sink = new RedisSink({ dryRun: true });
    const result = await sink.publish([{ body: "{}", key: "k" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
  });
});
