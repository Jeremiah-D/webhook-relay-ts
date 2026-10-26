import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  SnsSink,
  SnsSinkConfigError,
  SnsSinkError,
  SnsPublishError,
  assertValidSnsSinkConfig,
  classifySnsRecordFailure,
  isSnsFifoTopic,
  resolveSnsMessageAttributes,
  resolveSnsTopic,
  resolveSnsMessageGroupId,
  resolveSnsMessageDeduplicationId,
  resolveSnsRecord,
  type SnsClient,
  type SnsPublishRequest,
  type SnsSinkConfig,
} from "../src/sns-sink.ts";
import { classifyFailure } from "../src/failure.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.

/** In-memory fake client: records every publish, fails on demand, returns ids. */
class FakeClient implements SnsClient {
  sent: SnsPublishRequest[] = [];
  /** Call-count (0-based) → error to throw for that publish. */
  failOn = new Map<number, Error>();
  async publish(request: SnsPublishRequest): Promise<string> {
    const n = this.sent.length;
    this.sent.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return `msg-${n}`;
  }
}

const TOPIC = "arn:aws:sns:us-east-1:123456789012:events";
const FIFO_TOPIC = "arn:aws:sns:us-east-1:123456789012:events.fifo";

function baseConfig(
  client: SnsClient,
  extra: Partial<SnsSinkConfig> = {}
): SnsSinkConfig {
  return { topicArn: TOPIC, client, ...extra };
}

describe("sns-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidSnsSinkConfig(null, "SnsSink"), RangeError);
    assert.throws(() => assertValidSnsSinkConfig("x", "SnsSink"), RangeError);
  });

  it("rejects a malformed topic ARN", () => {
    assert.throws(() => assertValidSnsSinkConfig({ topicArn: "" }, "SnsSink"), RangeError);
    assert.throws(
      () => assertValidSnsSinkConfig({ topicArn: "has space" }, "SnsSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSnsSinkConfig({ topicArn: "has\0nul" }, "SnsSink"),
      RangeError
    );
  });

  it("rejects a client without a publish function", () => {
    assert.throws(
      () => assertValidSnsSinkConfig({ topicArn: TOPIC, client: {} }, "SnsSink"),
      RangeError
    );
  });

  it("accepts a topic-less config (per-record resolution instead)", () => {
    assertValidSnsSinkConfig({ client: new FakeClient() }, "SnsSink");
  });
});

describe("sns-sink topic resolution", () => {
  it("prefers the configured topic ARN over any record source", () => {
    assert.equal(
      resolveSnsTopic({ body: "{}", subject: "s", key: "k", traceId: "t" }, { topicArn: TOPIC }),
      TOPIC
    );
  });

  it("resolves subject, then key, then traceId when unconfigured", () => {
    assert.equal(resolveSnsTopic({ body: "{}", subject: "s", key: "k", traceId: "t" }, {}), "s");
    assert.equal(resolveSnsTopic({ body: "{}", key: "k", traceId: "t" }, {}), "k");
    assert.equal(resolveSnsTopic({ body: "{}", traceId: "t" }, {}), "t");
  });

  it("skips empty sources in the chain", () => {
    assert.equal(
      resolveSnsTopic({ body: "{}", subject: "", key: "", traceId: "t" }, {}),
      "t"
    );
  });

  it("returns undefined when no source exists", () => {
    assert.equal(resolveSnsTopic({ body: "{}" }, {}), undefined);
  });

  it("fails closed on a topic-less record instead of inventing a topic", () => {
    assert.throws(() => resolveSnsRecord({ body: "{}" }, 1, {}), RangeError);
  });

  it("fails closed on an empty body", () => {
    assert.throws(() => resolveSnsRecord({ body: "", subject: "s" }, 0, {}), RangeError);
  });
});

describe("sns-sink attribute pass-through and FIFO fields", () => {
  it("passes tenant, endpoint, and trace verbatim", () => {
    assert.deepEqual(
      resolveSnsMessageAttributes({
        body: "{}",
        tenant: "tenant-1",
        endpoint: "ep-9",
        traceId: "trace-9",
      }),
      { tenant: "tenant-1", endpoint: "ep-9", trace: "trace-9" }
    );
  });

  it("omits empty attributes instead of inventing them", () => {
    assert.deepEqual(
      resolveSnsMessageAttributes({ body: "{}", tenant: "", traceId: "trace-9" }),
      { trace: "trace-9" }
    );
    assert.deepEqual(resolveSnsMessageAttributes({ body: "{}" }), {});
  });

  it("detects FIFO topics by the .fifo suffix", () => {
    assert.equal(isSnsFifoTopic(FIFO_TOPIC), true);
    assert.equal(isSnsFifoTopic(TOPIC), false);
  });

  it("attaches a group id only on FIFO topics under the opt-in with a key", () => {
    const record = { body: "{}", key: "agg-9" };
    assert.equal(resolveSnsMessageGroupId(record, { messageGroupId: true }, FIFO_TOPIC), "agg-9");
    assert.equal(resolveSnsMessageGroupId(record, {}, FIFO_TOPIC), undefined);
    assert.equal(resolveSnsMessageGroupId(record, { messageGroupId: true }, TOPIC), undefined);
    assert.equal(
      resolveSnsMessageGroupId({ body: "{}" }, { messageGroupId: true }, FIFO_TOPIC),
      undefined
    );
  });

  it("attaches a deduplication id only on FIFO topics with an event id", () => {
    assert.equal(
      resolveSnsMessageDeduplicationId({ body: "{}", id: "evt-1" }, FIFO_TOPIC),
      "evt-1"
    );
    assert.equal(resolveSnsMessageDeduplicationId({ body: "{}", id: "evt-1" }, TOPIC), undefined);
    assert.equal(resolveSnsMessageDeduplicationId({ body: "{}" }, FIFO_TOPIC), undefined);
  });

  it("resolves a full FIFO record with both FIFO fields", () => {
    const resolved = resolveSnsRecord(
      { body: "{}", key: "agg-9", id: "evt-1", tenant: "t1" },
      0,
      { topicArn: FIFO_TOPIC, messageGroupId: true }
    );
    assert.equal(resolved.topicArn, FIFO_TOPIC);
    assert.equal(resolved.messageGroupId, "agg-9");
    assert.equal(resolved.messageDeduplicationId, "evt-1");
    assert.deepEqual(resolved.messageAttributes, { tenant: "t1" });
  });

  it("attaches neither FIFO field on a standard topic even with key and id", () => {
    const resolved = resolveSnsRecord(
      { body: "{}", key: "agg-9", id: "evt-1" },
      0,
      { topicArn: TOPIC, messageGroupId: true }
    );
    assert.equal(resolved.messageGroupId, undefined);
    assert.equal(resolved.messageDeduplicationId, undefined);
  });
});

describe("sns-sink publish", () => {
  it("publishes in order with attributes and counts stats", async () => {
    const client = new FakeClient();
    const sink = new SnsSink(baseConfig(client));
    const result = await sink.publish([
      { body: '{"a":1}', subject: "ignored", tenant: "t1", traceId: "tr-1" },
      { body: '{"b":2}' },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.sent.length, 2);
    assert.equal(client.sent[0]?.topicArn, TOPIC);
    assert.equal(client.sent[0]?.message, '{"a":1}');
    assert.deepEqual(client.sent[0]?.messageAttributes, { tenant: "t1", trace: "tr-1" });
    assert.equal(client.sent[1]?.message, '{"b":2}');
    assert.deepEqual(client.sent[1]?.messageAttributes, {});
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, publishFailures: 0 });
  });

  it("publishes FIFO fields only on FIFO topics", async () => {
    const client = new FakeClient();
    const sink = new SnsSink(baseConfig(client, { topicArn: FIFO_TOPIC, messageGroupId: true }));
    await sink.publish([{ body: "{}", key: "agg-9", id: "evt-1" }]);
    assert.equal(client.sent[0]?.messageGroupId, "agg-9");
    assert.equal(client.sent[0]?.messageDeduplicationId, "evt-1");
  });

  it("dryRun validates with zero client I/O and zero stat changes", async () => {
    const client = new FakeClient();
    const sink = new SnsSink(baseConfig(client, { dryRun: true }));
    const result = await sink.publish([{ body: "{}", tenant: "t1" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.sent.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, publishFailures: 0 });
    // But a topic-less record still fails closed in a dry run.
    const unconfigured = new SnsSink({ client, dryRun: true });
    await assert.rejects(() => unconfigured.publish([{ body: "{}" }]), RangeError);
  });

  it("throws a config error without a client, mapped to non_retryable", async () => {
    const sink = new SnsSink({ topicArn: TOPIC });
    await assert.rejects(() => sink.publish([{ body: "{}" }]), SnsSinkConfigError);
    assert.deepEqual(classifyFailure(new SnsSinkConfigError("no client")), {
      failureClass: "non_retryable",
    });
  });

  it("carries exactly the failed messages with their retry lanes", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new SnsPublishError("ThrottlingException", "slow down"));
    client.failOn.set(1, new SnsPublishError("AuthorizationErrorException", "denied"));
    client.failOn.set(2, new Error("socket hangup"));
    const sink = new SnsSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.publish([{ body: "a" }, { body: "b" }, { body: "c" }, { body: "d" }]),
      (err: unknown) => {
        assert.ok(err instanceof SnsSinkError);
        assert.deepEqual(
          err.failedRecords.map((r) => [r.index, r.errorCode, r.retryable]),
          [
            [0, "ThrottlingException", true],
            [1, "AuthorizationErrorException", false],
            [2, "TRANSPORT_ERROR", true],
          ]
        );
        return true;
      }
    );
    // The accepted message is not in the failure list; stats stay honest.
    assert.deepEqual(sink.stats, { sent: 1, failed: 3, publishFailures: 1 });
  });
});

describe("sns-sink failure classification", () => {
  it("maps transient SNS states to retryable and fail-closed states to non-retryable", () => {
    for (const code of [
      "TRANSPORT_ERROR",
      "ThrottlingException",
      "TooManyRequestsException",
      "InternalError",
      "ServiceUnavailableException",
    ]) {
      assert.equal(classifySnsRecordFailure(code), true, code);
    }
    for (const code of [
      "AuthorizationErrorException",
      "NotFoundException",
      "InvalidParameterException",
      "InvalidParameterValueException",
    ]) {
      assert.equal(classifySnsRecordFailure(code), false, code);
    }
  });
});
