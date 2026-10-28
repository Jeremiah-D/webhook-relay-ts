import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  PagerDutySink,
  PagerDutySinkConfigError,
  PagerDutySinkError,
  assertValidPagerDutySinkConfig,
  buildPagerDutyEnvelope,
  classifyPagerDutyRecordFailure,
  resolvePagerDutyCustomDetails,
  resolvePagerDutyRecord,
  resolvePagerDutySeverity,
  resolvePagerDutySummary,
  truncatePagerDutyPayload,
  PAGERDUTY_DEFAULT_PAYLOAD_MAX_CHARS,
  PAGERDUTY_DEFAULT_SEVERITY,
  PAGERDUTY_EVENTS_URL,
  PAGERDUTY_FALLBACK_SUMMARY,
  PAGERDUTY_SOURCE,
  type PagerDutyEventClient,
  type PagerDutyEventPostRequest,
  type PagerDutyEventPostResponse,
  type PagerDutySinkConfig,
} from "../src/pagerduty-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements PagerDutyEventClient {
  posts: PagerDutyEventPostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: PagerDutyEventPostRequest): Promise<PagerDutyEventPostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 202 };
  }
}

const routingKey = "routing-key-1";

function baseConfig(
  client: PagerDutyEventClient,
  extra: Partial<PagerDutySinkConfig> = {}
): PagerDutySinkConfig {
  return { routingKey, client, ...extra };
}

describe("pagerduty-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidPagerDutySinkConfig(null, "PagerDutySink"), RangeError);
    assert.throws(() => assertValidPagerDutySinkConfig("x", "PagerDutySink"), RangeError);
  });

  it("rejects a malformed routing key or severity shape", () => {
    assert.throws(
      () => assertValidPagerDutySinkConfig({ routingKey: "" }, "PagerDutySink"),
      RangeError
    );
    assert.throws(
      () => assertValidPagerDutySinkConfig({ routingKey: "has space" }, "PagerDutySink"),
      RangeError
    );
    assert.throws(
      () => assertValidPagerDutySinkConfig({ severity: "fatal" }, "PagerDutySink"),
      RangeError
    );
    assert.throws(
      () => assertValidPagerDutySinkConfig({ severity: "CRITICAL" }, "PagerDutySink"),
      RangeError
    );
  });

  it("rejects a client without a post function", () => {
    assert.throws(
      () => assertValidPagerDutySinkConfig({ client: {} }, "PagerDutySink"),
      RangeError
    );
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(
      () => assertValidPagerDutySinkConfig({ payloadMaxChars: 0 }, "PagerDutySink"),
      RangeError
    );
    assert.throws(
      () => assertValidPagerDutySinkConfig({ payloadMaxChars: 2.5 }, "PagerDutySink"),
      RangeError
    );
  });

  it("accepts a config with no routing key yet (send-time config error)", () => {
    assert.doesNotThrow(() => new PagerDutySink({}));
  });
});

describe("pagerduty-sink summary and severity derivation", () => {
  it("prefers subject, then key, then traceId, then the fallback summary", () => {
    assert.equal(
      resolvePagerDutySummary({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolvePagerDutySummary({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolvePagerDutySummary({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolvePagerDutySummary({ body: "{}" }), PAGERDUTY_FALLBACK_SUMMARY);
    assert.equal(
      resolvePagerDutySummary({ body: "{}", subject: "", key: "", traceId: "" }),
      PAGERDUTY_FALLBACK_SUMMARY
    );
  });

  it("defaults severity to error and honours an explicit critical", () => {
    assert.equal(PAGERDUTY_DEFAULT_SEVERITY, "error");
    assert.equal(resolvePagerDutySeverity({}), "error");
    assert.equal(resolvePagerDutySeverity({ severity: "critical" }), "critical");
    assert.equal(resolvePagerDutySeverity({ severity: "warning" }), "warning");
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncatePagerDutyPayload("abc", 2000), "abc");
    const long = "x".repeat(2005);
    assert.equal(truncatePagerDutyPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
  });

  it("carries identifiers by default and the body only on opt-in", () => {
    const record = { body: '{"a":1}', key: "agg-7", traceId: "t-1" };
    assert.deepEqual(resolvePagerDutyCustomDetails(record, {}), { key: "agg-7", traceId: "t-1" });
    assert.deepEqual(resolvePagerDutyCustomDetails(record, { includePayload: true }), {
      key: "agg-7",
      traceId: "t-1",
      body: '{"a":1}',
    });
    assert.deepEqual(
      resolvePagerDutyCustomDetails(record, { includePayload: true, payloadMaxChars: 3 }),
      { key: "agg-7", traceId: "t-1", body: '{"a… (truncated)' }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(
      () => resolvePagerDutyRecord({ body: "" }, 2, routingKey, {}),
      /record 2 `body` must be a non-empty event JSON string/
    );
  });
});

describe("pagerduty-sink wire shape", () => {
  it("builds the fixed Events API v2 envelope with trigger, dedup key, and default severity", () => {
    assert.equal(PAGERDUTY_EVENTS_URL, "https://events.pagerduty.com/v2/enqueue");
    assert.deepEqual(
      buildPagerDutyEnvelope(routingKey, { body: '{"a":1}', subject: "order.created", key: "agg-7", traceId: "t-1" }, {}),
      {
        routing_key: routingKey,
        event_action: "trigger",
        dedup_key: "agg-7",
        payload: {
          summary: "order.created",
          source: PAGERDUTY_SOURCE,
          severity: "error",
          custom_details: { key: "agg-7", traceId: "t-1" },
        },
      }
    );
  });

  it("omits dedup_key for a keyless event and uses the configured severity", () => {
    const envelope = buildPagerDutyEnvelope(
      routingKey,
      { body: '{"a":1}', traceId: "t-1" },
      { severity: "critical" }
    );
    assert.equal("dedup_key" in envelope, false);
    assert.equal(envelope.payload.severity, "critical");
    assert.equal(envelope.payload.summary, "t-1");
  });
});

describe("pagerduty-sink send", () => {
  it("posts one event per record to the fixed endpoint with the envelope body", async () => {
    const client = new FakeClient();
    const sink = new PagerDutySink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    assert.equal(client.posts[0].url, PAGERDUTY_EVENTS_URL);
    assert.deepEqual(JSON.parse(client.posts[0].body), {
      routing_key: routingKey,
      event_action: "trigger",
      dedup_key: "agg-7",
      payload: {
        summary: "order.created",
        source: "webhook-relay",
        severity: "error",
        custom_details: { key: "agg-7" },
      },
    });
    assert.deepEqual(JSON.parse(client.posts[1].body).payload.summary, "agg-8");
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 429);
    client.statusOn.set(1, 503);
    client.statusOn.set(2, 400);
    const sink = new PagerDutySink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }, { body: '{"c":3}' }]),
      (err: unknown) => {
        assert.ok(err instanceof PagerDutySinkError);
        assert.equal(err.failedRecords.length, 3);
        assert.deepEqual(
          err.failedRecords.map((r) => [r.index, r.errorCode, r.retryable]),
          [
            [0, "HTTP_429", true],
            [1, "HTTP_503", true],
            [2, "HTTP_400", false],
          ]
        );
        return true;
      }
    );
    assert.deepEqual(sink.stats, { sent: 0, failed: 3, sendFailures: 1 });
  });

  it("maps a client throw to a retryable transport failure and keeps partial success out", async () => {
    const client = new FakeClient();
    client.failOn.set(1, new Error("socket hangup"));
    const sink = new PagerDutySink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}' }, { body: '{"b":2}' }]),
      (err: unknown) => {
        assert.ok(err instanceof PagerDutySinkError);
        assert.equal(err.failedRecords.length, 1);
        assert.equal(err.failedRecords[0].index, 1);
        assert.equal(err.failedRecords[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(err.failedRecords[0].errorMessage, "socket hangup");
        assert.equal(err.failedRecords[0].retryable, true);
        return true;
      }
    );
    assert.deepEqual(sink.stats, { sent: 1, failed: 1, sendFailures: 1 });
  });

  it("fails closed without a client or routing key", async () => {
    await assert.rejects(
      () => new PagerDutySink({ routingKey }).send([{ body: '{"a":1}' }]),
      PagerDutySinkConfigError
    );
    await assert.rejects(
      () => new PagerDutySink(baseConfig(new FakeClient(), { routingKey: undefined })).send([{ body: '{"a":1}' }]),
      PagerDutySinkConfigError
    );
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new PagerDutySink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new PagerDutySink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new PagerDutySink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyPagerDutyRecordFailure(429), true);
    assert.equal(classifyPagerDutyRecordFailure(500), true);
    assert.equal(classifyPagerDutyRecordFailure(503), true);
    assert.equal(classifyPagerDutyRecordFailure(400), false);
    assert.equal(classifyPagerDutyRecordFailure(401), false);
    assert.equal(classifyPagerDutyRecordFailure(404), false);
    assert.equal(PAGERDUTY_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
