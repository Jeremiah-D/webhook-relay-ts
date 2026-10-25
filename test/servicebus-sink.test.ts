import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  ServiceBusSink,
  ServiceBusSinkConfigError,
  ServiceBusSinkError,
  ServiceBusSendError,
  assertValidServiceBusSinkConfig,
  classifyServiceBusRecordFailure,
  resolveServiceBusProperties,
  resolveServiceBusSessionId,
  resolveServiceBusRecord,
  type ServiceBusClient,
  type ServiceBusSendRequest,
  type ServiceBusSinkConfig,
} from "../src/servicebus-sink.ts";
import { classifyFailure } from "../src/failure.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.

/** In-memory fake client: records every send, fails on demand. */
class FakeClient implements ServiceBusClient {
  sent: ServiceBusSendRequest[] = [];
  /** Call-count (0-based) → error to throw for that send. */
  failOn = new Map<number, Error>();
  async send(request: ServiceBusSendRequest): Promise<void> {
    const n = this.sent.length;
    this.sent.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
  }
}

function baseConfig(
  client: ServiceBusClient,
  extra: Partial<ServiceBusSinkConfig> = {}
): ServiceBusSinkConfig {
  return { queue: "events", client, ...extra };
}

describe("servicebus-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidServiceBusSinkConfig(null, "ServiceBusSink"), RangeError);
    assert.throws(() => assertValidServiceBusSinkConfig("x", "ServiceBusSink"), RangeError);
  });

  it("rejects a malformed entity name", () => {
    assert.throws(
      () => assertValidServiceBusSinkConfig({ queue: "" }, "ServiceBusSink"),
      RangeError
    );
    assert.throws(
      () => assertValidServiceBusSinkConfig({ topic: "has space" }, "ServiceBusSink"),
      RangeError
    );
    assert.throws(
      () => assertValidServiceBusSinkConfig({ queue: "has\0nul" }, "ServiceBusSink"),
      RangeError
    );
  });

  it("rejects both a queue and a topic (one sink, one entity)", () => {
    assert.throws(
      () => assertValidServiceBusSinkConfig({ queue: "q", topic: "t" }, "ServiceBusSink"),
      RangeError
    );
  });

  it("rejects a client without a send function", () => {
    assert.throws(
      () => assertValidServiceBusSinkConfig({ queue: "q", client: {} }, "ServiceBusSink"),
      RangeError
    );
  });

  it("accepts an entity-less config (entity missing fails closed at send)", () => {
    assertValidServiceBusSinkConfig({ client: new FakeClient() }, "ServiceBusSink");
  });
});

describe("servicebus-sink property pass-through", () => {
  it("passes tenant, endpoint, and trace-id verbatim", () => {
    assert.deepEqual(
      resolveServiceBusProperties({
        body: "{}",
        tenant: "tenant-1",
        endpoint: "ep-9",
        traceId: "trace-9",
      }),
      { tenant: "tenant-1", endpoint: "ep-9", "trace-id": "trace-9" }
    );
  });

  it("invents no property for a missing value", () => {
    assert.deepEqual(resolveServiceBusProperties({ body: "{}" }), {});
    assert.deepEqual(
      resolveServiceBusProperties({ body: "{}", tenant: "" }),
      {}
    );
  });
});

describe("servicebus-sink session ids", () => {
  it("attaches the event key only when opted in and the entity is session-enabled", () => {
    assert.equal(
      resolveServiceBusSessionId(
        { body: "{}", key: "session-9" },
        { sessionId: true, sessionEnabled: true }
      ),
      "session-9"
    );
  });

  it("ignores the key when the opt-in is absent", () => {
    assert.equal(
      resolveServiceBusSessionId({ body: "{}", key: "session-9" }, {}),
      undefined
    );
  });

  it("ignores the key on an entity without sessions enabled", () => {
    assert.equal(
      resolveServiceBusSessionId(
        { body: "{}", key: "session-9" },
        { sessionId: true, sessionEnabled: false }
      ),
      undefined
    );
    assert.equal(
      resolveServiceBusSessionId(
        { body: "{}", key: "session-9" },
        { sessionId: true }
      ),
      undefined
    );
  });

  it("attaches no session id for a keyless record even when opted in", () => {
    assert.equal(
      resolveServiceBusSessionId(
        { body: "{}" },
        { sessionId: true, sessionEnabled: true }
      ),
      undefined
    );
  });
});

describe("servicebus-sink record resolution", () => {
  it("rejects an empty body", () => {
    assert.throws(() => resolveServiceBusRecord({ body: "" }, 0, {}), RangeError);
  });

  it("resolves properties and session id together", () => {
    const resolved = resolveServiceBusRecord(
      { body: '{"a":1}', tenant: "t1", traceId: "tr1", key: "k1" },
      0,
      { sessionId: true, sessionEnabled: true }
    );
    assert.equal(resolved.body, '{"a":1}');
    assert.deepEqual(resolved.properties, { tenant: "t1", "trace-id": "tr1" });
    assert.equal(resolved.sessionId, "k1");
  });
});

describe("servicebus-sink send", () => {
  it("sends messages in order with pass-through properties", async () => {
    const client = new FakeClient();
    const sink = new ServiceBusSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"n":1}', tenant: "t1", traceId: "tr1" },
      { body: '{"n":2}', endpoint: "ep2" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.sent.length, 2);
    assert.equal(client.sent[0]?.entity, "events");
    assert.equal(client.sent[0]?.body, '{"n":1}');
    assert.deepEqual(client.sent[0]?.properties, {
      tenant: "t1",
      "trace-id": "tr1",
    });
    assert.equal(client.sent[0]?.sessionId, undefined);
    assert.deepEqual(client.sent[1]?.properties, { endpoint: "ep2" });
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("sends to a topic when configured (subscriptions stay downstream)", async () => {
    const client = new FakeClient();
    const sink = new ServiceBusSink({ topic: "events", client });
    await sink.send([{ body: "{}" }]);
    assert.equal(client.sent[0]?.entity, "events");
  });

  it("attaches session ids only under the full opt-in", async () => {
    const client = new FakeClient();
    const sink = new ServiceBusSink(
      baseConfig(client, { sessionId: true, sessionEnabled: true })
    );
    await sink.send([{ body: "{}", key: "session-9" }]);
    assert.equal(client.sent[0]?.sessionId, "session-9");

    const plain = new FakeClient();
    const plainSink = new ServiceBusSink(baseConfig(plain));
    await plainSink.send([{ body: "{}", key: "session-9" }]);
    assert.equal(plain.sent[0]?.sessionId, undefined);
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new ServiceBusSink(baseConfig(client, { dryRun: true }));
    const result = await sink.send([{ body: "{}", tenant: "t1" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.sent.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("dry run still rejects a malformed record", async () => {
    const client = new FakeClient();
    const sink = new ServiceBusSink(baseConfig(client, { dryRun: true }));
    await assert.rejects(sink.send([{ body: "" }]), RangeError);
  });

  it("dry run needs no client at all", async () => {
    const sink = new ServiceBusSink({ queue: "q", dryRun: true });
    const result = await sink.send([{ body: "{}" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
  });

  it("missing client fails closed as a config error", async () => {
    const sink = new ServiceBusSink({ queue: "events" });
    await assert.rejects(sink.send([{ body: "{}" }]), ServiceBusSinkConfigError);
    assert.deepEqual(classifyFailure(new ServiceBusSinkConfigError("no client")), {
      failureClass: "non_retryable",
    });
  });

  it("missing entity fails closed as a config error", async () => {
    const sink = new ServiceBusSink({ client: new FakeClient() });
    await assert.rejects(sink.send([{ body: "{}" }]), ServiceBusSinkConfigError);
    assert.deepEqual(classifyFailure(new ServiceBusSinkConfigError("no entity")), {
      failureClass: "non_retryable",
    });
  });

  it("carries exactly the failed messages with mapped retry lanes", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new ServiceBusSendError("ServiceBusy", "busy"));
    client.failOn.set(2, new ServiceBusSendError("Unauthorized", "denied"));
    const sink = new ServiceBusSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "a" }, { body: "b" }, { body: "c" }]),
      (err: unknown) => {
        assert.ok(err instanceof ServiceBusSinkError);
        assert.equal(err.failedRecords.length, 2);
        assert.deepEqual(err.failedRecords[0], {
          index: 0,
          errorCode: "ServiceBusy",
          errorMessage: "busy",
          retryable: true,
        });
        assert.deepEqual(err.failedRecords[1], {
          index: 2,
          errorCode: "Unauthorized",
          errorMessage: "denied",
          retryable: false,
        });
        return true;
      }
    );
    assert.deepEqual(sink.stats, { sent: 1, failed: 2, sendFailures: 1 });
  });

  it("treats a codeless transport failure as retryable", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hangup"));
    const sink = new ServiceBusSink(baseConfig(client));
    await assert.rejects(sink.send([{ body: "a" }]), (err: unknown) => {
      assert.ok(err instanceof ServiceBusSinkError);
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

describe("servicebus-sink failure classification", () => {
  it("maps quota and transient failures to retryable", () => {
    for (const code of [
      "TRANSPORT_ERROR",
      "QuotaExceeded",
      "ServiceBusy",
      "OperationTimeout",
    ]) {
      assert.equal(classifyServiceBusRecordFailure(code), true, code);
    }
  });

  it("maps fail-closed failures to non-retryable", () => {
    for (const code of [
      "Unauthorized",
      "MessagingEntityNotFound",
      "MessagingEntityDisabled",
      "InvalidOperation",
    ]) {
      assert.equal(classifyServiceBusRecordFailure(code), false, code);
    }
  });
});
