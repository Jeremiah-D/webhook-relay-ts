import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  JetStreamSink,
  JetStreamSinkConfigError,
  JetStreamSinkError,
  JetStreamPublishError,
  assertValidJetStreamSinkConfig,
  classifyJetStreamRecordFailure,
  resolveJetStreamSubject,
  resolveJetStreamHeaders,
  resolveJetStreamRecord,
  type JetStreamClient,
  type JetStreamPublishRequest,
  type JetStreamSinkConfig,
} from "../src/jetstream-sink.ts";
import { classifyFailure } from "../src/failure.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.

/** In-memory fake client: records every publish, fails on demand. */
class FakeClient implements JetStreamClient {
  published: JetStreamPublishRequest[] = [];
  /** Call-count (0-based) → error to throw for that publish. */
  failOn = new Map<number, Error>();
  async publish(request: JetStreamPublishRequest): Promise<void> {
    const n = this.published.length;
    this.published.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
  }
}

function baseConfig(
  client: JetStreamClient,
  extra: Partial<JetStreamSinkConfig> = {}
): JetStreamSinkConfig {
  return { stream: "events", client, ...extra };
}

describe("jetstream-sink config validation", () => {
  it("accepts a minimal valid config", () => {
    assertValidJetStreamSinkConfig({ stream: "events", client: new FakeClient() }, "JetStreamSink");
  });

  it("rejects an empty stream", () => {
    assert.throws(
      () => assertValidJetStreamSinkConfig({ stream: "" }, "JetStreamSink"),
      RangeError
    );
  });

  it("rejects an over-long stream", () => {
    assert.throws(
      () => assertValidJetStreamSinkConfig({ stream: "x".repeat(129) }, "JetStreamSink"),
      RangeError
    );
  });

  it("rejects a stream with NUL", () => {
    assert.throws(
      () => assertValidJetStreamSinkConfig({ stream: "ev\0ents" }, "JetStreamSink"),
      RangeError
    );
  });

  it("rejects a stream with whitespace", () => {
    assert.throws(
      () => assertValidJetStreamSinkConfig({ stream: "ev ents" }, "JetStreamSink"),
      RangeError
    );
  });

  it("rejects a client without a publish function", () => {
    assert.throws(
      () => assertValidJetStreamSinkConfig({ stream: "events", client: {} }, "JetStreamSink"),
      RangeError
    );
  });
});

describe("jetstream-sink subject resolution", () => {
  it("prefers an explicit subject over key and traceId", () => {
    assert.equal(
      resolveJetStreamSubject(
        { body: "{}", subject: "orders.created", key: "k", traceId: "t" },
        0
      ),
      "orders.created"
    );
  });

  it("falls back from key to traceId", () => {
    assert.equal(resolveJetStreamSubject({ body: "{}", key: "order-9" }, 0), "order-9");
    assert.equal(resolveJetStreamSubject({ body: "{}", traceId: "trace-1" }, 0), "trace-1");
  });

  it("rejects a record with no subject source (fail-closed)", () => {
    assert.throws(
      () => resolveJetStreamSubject({ body: "{}" }, 2),
      /record 2 has no subject/
    );
  });

  it("rejects an over-long subject", () => {
    assert.throws(
      () => resolveJetStreamSubject({ body: "{}", key: "k".repeat(256) }, 0),
      /1–255/
    );
  });

  it("rejects a subject with NUL", () => {
    assert.throws(
      () => resolveJetStreamSubject({ body: "{}", key: "or\0ders" }, 0),
      RangeError
    );
  });

  it("rejects a subject with whitespace", () => {
    assert.throws(
      () => resolveJetStreamSubject({ body: "{}", key: "or ders" }, 0),
      RangeError
    );
  });

  it("rejects an empty body", () => {
    assert.throws(
      () => resolveJetStreamRecord({ body: "", key: "k" }, 0),
      /body/
    );
  });
});

describe("jetstream-sink trace-id headers", () => {
  it("passes traceId through as the trace-id header", () => {
    assert.deepEqual(
      resolveJetStreamHeaders({ body: "{}", key: "k", traceId: "trace-1" }),
      { "trace-id": "trace-1" }
    );
  });

  it("carries no trace-id header without a traceId", () => {
    assert.deepEqual(resolveJetStreamHeaders({ body: "{}", key: "k" }), {});
  });

  it("never invents a trace id for a record that has none", () => {
    const resolved = resolveJetStreamRecord({ body: "{}", key: "k" }, 0);
    assert.deepEqual(resolved.headers, {});
  });
});

describe("jetstream-sink publish", () => {
  it("publishes with the configured stream, resolved subjects, and headers", async () => {
    const client = new FakeClient();
    const sink = new JetStreamSink(baseConfig(client));
    const result = await sink.publish([
      { body: '{"a":1}', key: "order-9", traceId: "trace-9" },
      { body: '{"b":2}', traceId: "trace-1" },
      { body: '{"c":3}', subject: "orders.created" },
    ]);
    assert.equal(result.ok, true);
    assert.equal(result.sent, 3);
    assert.deepEqual(
      client.published.map((p) => [p.stream, p.subject, p.headers]),
      [
        ["events", "order-9", { "trace-id": "trace-9" }],
        ["events", "trace-1", { "trace-id": "trace-1" }],
        ["events", "orders.created", {}],
      ]
    );
    assert.deepEqual(sink.stats, {
      sent: 3,
      failed: 0,
      publishFailures: 0,
    });
  });

  it("maps a publish failure to the retryable lane, keeping earlier sends", async () => {
    const client = new FakeClient();
    client.failOn.set(1, new JetStreamPublishError("PUBLISH_FAILED"));
    const sink = new JetStreamSink(baseConfig(client));
    await assert.rejects(
      sink.publish([
        { body: "{}", key: "a" },
        { body: "{}", key: "b" },
        { body: "{}", key: "c" },
      ]),
      (err: unknown) => {
        assert.ok(err instanceof JetStreamSinkError);
        assert.equal(err.failedRecords.length, 1);
        assert.equal(err.failedRecords[0]?.index, 1);
        assert.equal(err.failedRecords[0]?.errorCode, "PUBLISH_FAILED");
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

  it("maps stream unavailability to the retryable lane", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new JetStreamPublishError("STREAM_UNAVAILABLE"));
    const sink = new JetStreamSink(baseConfig(client));
    await assert.rejects(
      sink.publish([{ body: "{}", key: "k" }]),
      (err: unknown) => {
        assert.ok(err instanceof JetStreamSinkError);
        assert.equal(err.failedRecords[0]?.errorCode, "STREAM_UNAVAILABLE");
        assert.equal(err.failedRecords[0]?.retryable, true);
        return true;
      }
    );
  });

  it("maps a publish ack timeout to the retryable lane", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new JetStreamPublishError("NO_ACK"));
    const sink = new JetStreamSink(baseConfig(client));
    await assert.rejects(
      sink.publish([{ body: "{}", key: "k" }]),
      (err: unknown) => {
        assert.ok(err instanceof JetStreamSinkError);
        assert.equal(err.failedRecords[0]?.retryable, true);
        return true;
      }
    );
  });

  it("treats a codeless failure as a retryable transport error", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("boom"));
    const sink = new JetStreamSink(baseConfig(client));
    await assert.rejects(
      sink.publish([{ body: "{}", key: "k" }]),
      (err: unknown) => {
        assert.ok(err instanceof JetStreamSinkError);
        assert.equal(err.failedRecords[0]?.errorCode, "TRANSPORT_ERROR");
        assert.equal(err.failedRecords[0]?.retryable, true);
        return true;
      }
    );
  });

  it("treats an unknown stream as fail-closed, not retried", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new JetStreamPublishError("STREAM_NOT_FOUND"));
    const sink = new JetStreamSink(baseConfig(client));
    await assert.rejects(
      sink.publish([{ body: "{}", key: "k" }]),
      (err: unknown) => {
        assert.ok(err instanceof JetStreamSinkError);
        assert.equal(err.failedRecords[0]?.errorCode, "STREAM_NOT_FOUND");
        assert.equal(err.failedRecords[0]?.retryable, false);
        return true;
      }
    );
  });

  it("treats an unknown subject as fail-closed, not retried", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new JetStreamPublishError("SUBJECT_NOT_FOUND"));
    const sink = new JetStreamSink(baseConfig(client));
    await assert.rejects(
      sink.publish([{ body: "{}", key: "k" }]),
      (err: unknown) => {
        assert.ok(err instanceof JetStreamSinkError);
        assert.equal(err.failedRecords[0]?.retryable, false);
        return true;
      }
    );
  });

  it("throws a config error with no client, mapped non_retryable", async () => {
    const sink = new JetStreamSink({ stream: "events" });
    await assert.rejects(sink.publish([{ body: "{}", key: "k" }]), JetStreamSinkConfigError);
    assert.equal(
      classifyFailure(new JetStreamSinkConfigError()).failureClass,
      "non_retryable"
    );
  });

  it("dryRun validates with zero client I/O and no stat changes", async () => {
    const client = new FakeClient();
    const sink = new JetStreamSink(baseConfig(client, { dryRun: true }));
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

describe("jetstream-sink failure classification", () => {
  it("classifies transient stream states retryable, fail-closed non-retryable", () => {
    for (const code of [
      "TRANSPORT_ERROR",
      "CONNECTION_LOST",
      "NOT_CONNECTED",
      "STREAM_UNAVAILABLE",
      "PUBLISH_FAILED",
      "PUBLISH_TIMEOUT",
      "NO_ACK",
    ]) {
      assert.equal(classifyJetStreamRecordFailure(code), true, code);
    }
    for (const code of [
      "STREAM_NOT_FOUND",
      "SUBJECT_NOT_FOUND",
      "INVALID_SUBJECT",
      "MESSAGE_TOO_LARGE",
      "NOT_AUTHORIZED",
      "SOMETHING_ELSE",
    ]) {
      assert.equal(classifyJetStreamRecordFailure(code), false, code);
    }
  });
});
