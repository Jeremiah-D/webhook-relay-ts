import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  EventBridgeSink,
  EventBridgeSinkConfigError,
  EventBridgeSinkError,
  EventBridgePutError,
  assertValidEventBridgeSinkConfig,
  classifyEventBridgeRecordFailure,
  resolveEventBridgeDetailType,
  resolveEventBridgeRecord,
  type EventBridgeClient,
  type EventBridgePutEventsEntry,
  type EventBridgeSinkConfig,
} from "../src/eventbridge-sink.ts";
import { classifyFailure } from "../src/failure.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.

/** In-memory fake client: records every entry, fails on demand. */
class FakeClient implements EventBridgeClient {
  sent: EventBridgePutEventsEntry[] = [];
  /** Call-count (0-based) → error to throw for that entry. */
  failOn = new Map<number, Error>();
  async putEvents(entry: EventBridgePutEventsEntry): Promise<void> {
    const n = this.sent.length;
    this.sent.push(entry);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
  }
}

function baseConfig(
  client: EventBridgeClient,
  extra: Partial<EventBridgeSinkConfig> = {}
): EventBridgeSinkConfig {
  return { eventBusName: "events", client, ...extra };
}

describe("eventbridge-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidEventBridgeSinkConfig(null, "EventBridgeSink"), RangeError);
    assert.throws(() => assertValidEventBridgeSinkConfig("x", "EventBridgeSink"), RangeError);
  });

  it("rejects a malformed bus name", () => {
    assert.throws(
      () => assertValidEventBridgeSinkConfig({ eventBusName: "" }, "EventBridgeSink"),
      RangeError
    );
    assert.throws(
      () => assertValidEventBridgeSinkConfig({ eventBusName: "has space" }, "EventBridgeSink"),
      RangeError
    );
    assert.throws(
      () => assertValidEventBridgeSinkConfig({ eventBusName: "has\0nul" }, "EventBridgeSink"),
      RangeError
    );
  });

  it("rejects a client without a putEvents function", () => {
    assert.throws(
      () => assertValidEventBridgeSinkConfig({ eventBusName: "b", client: {} }, "EventBridgeSink"),
      RangeError
    );
  });

  it("accepts a bus-less config (missing bus fails closed at send)", () => {
    assertValidEventBridgeSinkConfig({ client: new FakeClient() }, "EventBridgeSink");
  });
});

describe("eventbridge-sink DetailType resolution", () => {
  it("prefers subject over key and traceId", () => {
    assert.equal(
      resolveEventBridgeDetailType({ body: "{}", subject: "order.created", key: "k-1", traceId: "t-1" }),
      "order.created"
    );
  });

  it("falls back to key, then to traceId", () => {
    assert.equal(resolveEventBridgeDetailType({ body: "{}", key: "k-1", traceId: "t-1" }), "k-1");
    assert.equal(resolveEventBridgeDetailType({ body: "{}", traceId: "t-1" }), "t-1");
  });

  it("skips empty sources in the chain", () => {
    assert.equal(
      resolveEventBridgeDetailType({ body: "{}", subject: "", key: "", traceId: "t-1" }),
      "t-1"
    );
  });

  it("returns undefined when no source exists", () => {
    assert.equal(resolveEventBridgeDetailType({ body: "{}" }), undefined);
    assert.equal(
      resolveEventBridgeDetailType({ body: "{}", subject: "", key: "" }),
      undefined
    );
  });

  it("fails closed on a sourceless record instead of inventing a DetailType", () => {
    assert.throws(() => resolveEventBridgeRecord({ body: "{}" }, 2), RangeError);
  });

  it("fails closed on an empty body", () => {
    assert.throws(() => resolveEventBridgeRecord({ body: "", subject: "s" }, 0), RangeError);
  });

  it("passes the trace id through alongside Detail, never inventing one", () => {
    assert.deepEqual(resolveEventBridgeRecord({ body: "{}", subject: "s", traceId: "t-1" }, 0), {
      detail: "{}",
      detailType: "s",
      traceId: "t-1",
    });
    assert.deepEqual(resolveEventBridgeRecord({ body: "{}", subject: "s" }, 0), {
      detail: "{}",
      detailType: "s",
    });
  });

  it("reuses the trace id as DetailType and still passes it through", () => {
    assert.deepEqual(resolveEventBridgeRecord({ body: "{}", traceId: "t-1" }, 0), {
      detail: "{}",
      detailType: "t-1",
      traceId: "t-1",
    });
  });
});

describe("eventbridge-sink failure classification", () => {
  it("marks throttling, quota, internal, and transport failures retryable", () => {
    for (const code of [
      "TRANSPORT_ERROR",
      "ThrottlingException",
      "TooManyRequestsException",
      "LimitExceededException",
      "InternalError",
    ]) {
      assert.equal(classifyEventBridgeRecordFailure(code), true, code);
    }
  });

  it("marks permission, unknown bus, and malformed detail fail-closed", () => {
    for (const code of [
      "AccessDeniedException",
      "ValidationException",
      "ResourceNotFoundException",
      "InvalidParameterValueException",
    ]) {
      assert.equal(classifyEventBridgeRecordFailure(code), false, code);
    }
  });
});

describe("eventbridge-sink send", () => {
  it("sends one entry per message with bus, DetailType, and verbatim Detail", async () => {
    const client = new FakeClient();
    const sink = new EventBridgeSink(baseConfig(client));
    const result = await sink.putEvents([
      { body: '{"a":1}', subject: "order.created", traceId: "t-1" },
      { body: '{"b":2}', key: "k-2" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.deepEqual(client.sent, [
      { eventBusName: "events", detailType: "order.created", detail: '{"a":1}', traceId: "t-1" },
      { eventBusName: "events", detailType: "k-2", detail: '{"b":2}' },
    ]);
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, putFailures: 0 });
  });

  it("dry-runs with zero client I/O and untouched stats, but still validates", async () => {
    const client = new FakeClient();
    const sink = new EventBridgeSink(baseConfig(client, { dryRun: true }));
    const result = await sink.putEvents([{ body: "{}", subject: "s" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.sent.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, putFailures: 0 });
    await assert.rejects(
      () => sink.putEvents([{ body: "{}" }]),
      RangeError
    );
  });

  it("throws a config error with no client or no bus", async () => {
    const noClient = new EventBridgeSink({ eventBusName: "events" });
    await assert.rejects(() => noClient.putEvents([{ body: "{}", subject: "s" }]), EventBridgeSinkConfigError);
    const noBus = new EventBridgeSink({ client: new FakeClient() });
    await assert.rejects(() => noBus.putEvents([{ body: "{}", subject: "s" }]), EventBridgeSinkConfigError);
  });

  it("maps a config error to non_retryable via classifyFailure", () => {
    assert.deepEqual(
      classifyFailure(new EventBridgeSinkConfigError("no client injected")),
      { failureClass: "non_retryable" }
    );
  });

  it("carries exactly the failed messages with their retry lanes", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new EventBridgePutError("ThrottlingException", "slow down"));
    client.failOn.set(2, new EventBridgePutError("AccessDeniedException", "denied"));
    const sink = new EventBridgeSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.putEvents([
          { body: "{}", subject: "a" },
          { body: "{}", subject: "b" },
          { body: "{}", subject: "c" },
        ]),
      (err: unknown) => {
        assert.ok(err instanceof EventBridgeSinkError);
        assert.deepEqual(err.failedRecords, [
          { index: 0, errorCode: "ThrottlingException", errorMessage: "slow down", retryable: true },
          { index: 2, errorCode: "AccessDeniedException", errorMessage: "denied", retryable: false },
        ]);
        return true;
      }
    );
    assert.deepEqual(sink.stats, { sent: 1, failed: 2, putFailures: 1 });
  });

  it("treats a codeless throw as a retryable transport failure", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hung up"));
    const sink = new EventBridgeSink(baseConfig(client));
    await assert.rejects(
      () => sink.putEvents([{ body: "{}", subject: "a" }]),
      (err: unknown) => {
        assert.ok(err instanceof EventBridgeSinkError);
        assert.deepEqual(err.failedRecords, [
          { index: 0, errorCode: "TRANSPORT_ERROR", errorMessage: "socket hung up", retryable: true },
        ]);
        return true;
      }
    );
  });

  it("keeps Detail verbatim even when it is not a JSON object", async () => {
    const client = new FakeClient();
    const sink = new EventBridgeSink(baseConfig(client));
    await sink.putEvents([{ body: "[1,2]", subject: "s" }]);
    assert.equal(client.sent[0]?.detail, "[1,2]");
  });
});
