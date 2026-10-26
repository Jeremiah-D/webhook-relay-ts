import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  EventHubsSink,
  EventHubsSinkConfigError,
  EventHubsSinkError,
  EventHubsSendError,
  assertValidEventHubsSinkConfig,
  classifyEventHubsRecordFailure,
  resolveEventHubsProperties,
  resolveEventHubsHub,
  resolveEventHubsPartitionKey,
  resolveEventHubsRecord,
  type EventHubsClient,
  type EventHubsSendBatchRequest,
  type EventHubsSinkConfig,
} from "../src/eventhubs-sink.ts";
import { classifyFailure } from "../src/failure.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.

/** In-memory fake client: records every batch, fails on demand. */
class FakeClient implements EventHubsClient {
  sent: EventHubsSendBatchRequest[] = [];
  /** Call-count (0-based) → error to throw for that batch. */
  failOn = new Map<number, Error>();
  async sendBatch(batch: EventHubsSendBatchRequest): Promise<void> {
    const n = this.sent.length;
    this.sent.push(batch);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
  }
}

const HUB = "events";

function baseConfig(
  client: EventHubsClient,
  extra: Partial<EventHubsSinkConfig> = {}
): EventHubsSinkConfig {
  return { eventHubName: HUB, client, ...extra };
}

describe("eventhubs-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidEventHubsSinkConfig(null, "EventHubsSink"), RangeError);
    assert.throws(() => assertValidEventHubsSinkConfig("x", "EventHubsSink"), RangeError);
  });

  it("rejects a malformed event hub name", () => {
    assert.throws(() => assertValidEventHubsSinkConfig({ eventHubName: "" }, "EventHubsSink"), RangeError);
    assert.throws(
      () => assertValidEventHubsSinkConfig({ eventHubName: "has space" }, "EventHubsSink"),
      RangeError
    );
    assert.throws(
      () => assertValidEventHubsSinkConfig({ eventHubName: "has\0nul" }, "EventHubsSink"),
      RangeError
    );
  });

  it("rejects a client without a sendBatch function", () => {
    assert.throws(
      () => assertValidEventHubsSinkConfig({ eventHubName: HUB, client: {} }, "EventHubsSink"),
      RangeError
    );
  });

  it("accepts a hub-less config (per-event resolution instead)", () => {
    assertValidEventHubsSinkConfig({ client: new FakeClient() }, "EventHubsSink");
  });
});

describe("eventhubs-sink hub resolution", () => {
  it("prefers the configured hub over any event source", () => {
    assert.equal(
      resolveEventHubsHub({ body: "{}", subject: "s", key: "k", traceId: "t" }, { eventHubName: HUB }),
      HUB
    );
  });

  it("resolves subject, then key, then traceId when unconfigured", () => {
    assert.equal(resolveEventHubsHub({ body: "{}", subject: "s", key: "k", traceId: "t" }, {}), "s");
    assert.equal(resolveEventHubsHub({ body: "{}", key: "k", traceId: "t" }, {}), "k");
    assert.equal(resolveEventHubsHub({ body: "{}", traceId: "t" }, {}), "t");
  });

  it("skips empty sources in the chain", () => {
    assert.equal(
      resolveEventHubsHub({ body: "{}", subject: "", key: "", traceId: "t" }, {}),
      "t"
    );
  });

  it("returns undefined when no source exists", () => {
    assert.equal(resolveEventHubsHub({ body: "{}" }, {}), undefined);
  });

  it("fails closed on a hub-less event instead of inventing a hub", () => {
    assert.throws(() => resolveEventHubsRecord({ body: "{}" }, 1, {}), RangeError);
  });

  it("fails closed on an empty body", () => {
    assert.throws(() => resolveEventHubsRecord({ body: "", subject: "s" }, 0, {}), RangeError);
  });
});

describe("eventhubs-sink properties and partition keys", () => {
  it("passes tenant, endpoint, and trace verbatim", () => {
    assert.deepEqual(
      resolveEventHubsProperties({
        body: "{}",
        tenant: "tenant-1",
        endpoint: "ep-9",
        traceId: "trace-9",
      }),
      { tenant: "tenant-1", endpoint: "ep-9", trace: "trace-9" }
    );
  });

  it("omits empty properties instead of inventing them", () => {
    assert.deepEqual(
      resolveEventHubsProperties({ body: "{}", tenant: "", traceId: "trace-9" }),
      { trace: "trace-9" }
    );
    assert.deepEqual(resolveEventHubsProperties({ body: "{}" }), {});
  });

  it("attaches a partition key only under the opt-in with a key", () => {
    const record = { body: "{}", key: "agg-9" };
    assert.equal(resolveEventHubsPartitionKey(record, { partitionKey: true }), "agg-9");
    assert.equal(resolveEventHubsPartitionKey(record, {}), undefined);
    assert.equal(
      resolveEventHubsPartitionKey({ body: "{}" }, { partitionKey: true }),
      undefined
    );
    assert.equal(
      resolveEventHubsPartitionKey({ body: "{}", key: "" }, { partitionKey: true }),
      undefined
    );
  });

  it("resolves a full record with properties and partition key", () => {
    const resolved = resolveEventHubsRecord(
      { body: "{}", key: "agg-9", tenant: "t1", traceId: "tr-1" },
      2,
      { eventHubName: HUB, partitionKey: true }
    );
    assert.equal(resolved.eventHubName, HUB);
    assert.equal(resolved.partitionKey, "agg-9");
    assert.equal(resolved.index, 2);
    assert.deepEqual(resolved.properties, { tenant: "t1", trace: "tr-1" });
  });

  it("attaches no partition key without the opt-in even with a key", () => {
    const resolved = resolveEventHubsRecord(
      { body: "{}", key: "agg-9" },
      0,
      { eventHubName: HUB }
    );
    assert.equal(resolved.partitionKey, undefined);
  });
});

describe("eventhubs-sink sendBatch", () => {
  it("sends one batch to the configured hub with bodies verbatim and counts stats", async () => {
    const client = new FakeClient();
    const sink = new EventHubsSink(baseConfig(client, { partitionKey: true }));
    const result = await sink.sendBatch([
      { body: '{"a":1}', tenant: "t1", traceId: "tr-1", key: "agg-9" },
      { body: '{"b":2}' },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.sent.length, 1);
    assert.equal(client.sent[0]?.eventHubName, HUB);
    assert.equal(client.sent[0]?.events.length, 2);
    assert.equal(client.sent[0]?.events[0]?.body, '{"a":1}');
    assert.deepEqual(client.sent[0]?.events[0]?.properties, { tenant: "t1", trace: "tr-1" });
    assert.equal(client.sent[0]?.events[0]?.partitionKey, "agg-9");
    assert.equal(client.sent[0]?.events[1]?.body, '{"b":2}');
    assert.deepEqual(client.sent[0]?.events[1]?.properties, {});
    assert.equal(client.sent[0]?.events[1]?.partitionKey, undefined);
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendBatchFailures: 0 });
  });

  it("groups unconfigured events into one batch per resolved hub, in first-appearance order", async () => {
    const client = new FakeClient();
    const sink = new EventHubsSink({ client });
    const result = await sink.sendBatch([
      { body: "a", subject: "hub-a" },
      { body: "b", key: "hub-b" },
      { body: "c", subject: "hub-a" },
      { body: "d", traceId: "hub-c" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 4 });
    assert.equal(client.sent.length, 3);
    assert.deepEqual(
      client.sent.map((b) => [b.eventHubName, b.events.map((e) => e.body)]),
      [
        ["hub-a", ["a", "c"]],
        ["hub-b", ["b"]],
        ["hub-c", ["d"]],
      ]
    );
  });

  it("dryRun validates with zero client I/O and zero stat changes", async () => {
    const client = new FakeClient();
    const sink = new EventHubsSink(baseConfig(client, { dryRun: true }));
    const result = await sink.sendBatch([{ body: "{}", tenant: "t1" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.sent.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendBatchFailures: 0 });
    // But a hub-less event still fails closed in a dry run.
    const unconfigured = new EventHubsSink({ client, dryRun: true });
    await assert.rejects(() => unconfigured.sendBatch([{ body: "{}" }]), RangeError);
  });

  it("throws a config error without a client, mapped to non_retryable", async () => {
    const sink = new EventHubsSink({ eventHubName: HUB });
    await assert.rejects(() => sink.sendBatch([{ body: "{}" }]), EventHubsSinkConfigError);
    assert.deepEqual(classifyFailure(new EventHubsSinkConfigError("no client")), {
      failureClass: "non_retryable",
    });
  });

  it("fails every event in a failed batch with the batch retry lane, keeping accepted batches out", async () => {
    const client = new FakeClient();
    client.failOn.set(1, new EventHubsSendError("UnauthorizedError", "denied"));
    const sink = new EventHubsSink({ client });
    await assert.rejects(
      () =>
        sink.sendBatch([
          { body: "a", subject: "hub-ok" },
          { body: "b", subject: "hub-bad" },
          { body: "c", subject: "hub-bad" },
        ]),
      (err: unknown) => {
        assert.ok(err instanceof EventHubsSinkError);
        assert.deepEqual(
          err.failedRecords.map((r) => [r.index, r.errorCode, r.retryable]),
          [
            [1, "UnauthorizedError", false],
            [2, "UnauthorizedError", false],
          ]
        );
        return true;
      }
    );
    // The accepted batch's event is not in the failure list; stats stay honest.
    assert.deepEqual(sink.stats, { sent: 1, failed: 2, sendBatchFailures: 1 });
  });

  it("maps a codeless transport failure to retryable TRANSPORT_ERROR", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hangup"));
    const sink = new EventHubsSink(baseConfig(client));
    await assert.rejects(
      () => sink.sendBatch([{ body: "a" }, { body: "b" }]),
      (err: unknown) => {
        assert.ok(err instanceof EventHubsSinkError);
        assert.deepEqual(
          err.failedRecords.map((r) => [r.index, r.errorCode, r.retryable]),
          [
            [0, "TRANSPORT_ERROR", true],
            [1, "TRANSPORT_ERROR", true],
          ]
        );
        return true;
      }
    );
  });
});

describe("eventhubs-sink failure classification", () => {
  it("maps transient Event Hubs states to retryable and fail-closed states to non-retryable", () => {
    for (const code of [
      "TRANSPORT_ERROR",
      "ThrottlingError",
      "ServerBusyError",
      "ServiceUnavailable",
      "OperationTimeout",
      "InternalError",
    ]) {
      assert.equal(classifyEventHubsRecordFailure(code), true, code);
    }
    for (const code of [
      "UnauthorizedError",
      "ForbiddenError",
      "AccessDenied",
      "HubNotFound",
      "NotFound",
      "InvalidEventData",
      "MessageTooLarge",
    ]) {
      assert.equal(classifyEventHubsRecordFailure(code), false, code);
    }
  });
});
