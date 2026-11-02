import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  SplunkOnCallSink,
  SplunkOnCallSinkConfigError,
  SplunkOnCallSinkError,
  assertValidSplunkOnCallSinkConfig,
  buildSplunkOnCallAlertBody,
  classifySplunkOnCallIncidentResponse,
  classifySplunkOnCallRecordFailure,
  resolveSplunkOnCallDisplayName,
  resolveSplunkOnCallMessageType,
  resolveSplunkOnCallRecord,
  resolveSplunkOnCallStateMessage,
  resolveSplunkOnCallStatus,
  truncateSplunkOnCallPayload,
  SPLUNK_ONCALL_DEFAULT_MESSAGE_TYPE,
  SPLUNK_ONCALL_DEFAULT_PAYLOAD_MAX_CHARS,
  SPLUNK_ONCALL_DEFAULT_STATUS,
  SPLUNK_ONCALL_FALLBACK_DISPLAY_NAME,
  SPLUNK_ONCALL_JSON_CONTENT_TYPE,
  SPLUNK_ONCALL_MESSAGE_TYPES,
  SPLUNK_ONCALL_MONITORING_TOOL,
  SPLUNK_ONCALL_RESOLVED_MESSAGE_TYPE,
  SPLUNK_ONCALL_REST_GENERIC_URL_TEMPLATE,
  SPLUNK_ONCALL_STATUSES,
  type SplunkOnCallAlertClient,
  type SplunkOnCallAlertPostRequest,
  type SplunkOnCallAlertPostResponse,
  type SplunkOnCallSinkConfig,
} from "../src/splunk-oncall-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements SplunkOnCallAlertClient {
  posts: SplunkOnCallAlertPostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error text to return for that post. */
  errorOn = new Map<number, string>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: SplunkOnCallAlertPostRequest): Promise<SplunkOnCallAlertPostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return {
      status: this.statusOn.get(n) ?? 200,
      errorMessage: this.errorOn.get(n),
    };
  }
}

function baseConfig(
  client: SplunkOnCallAlertClient,
  extra: Partial<SplunkOnCallSinkConfig> = {}
): SplunkOnCallSinkConfig {
  return { client, ...extra };
}

function bodyOf(request: SplunkOnCallAlertPostRequest): Record<string, unknown> {
  return JSON.parse(request.body) as Record<string, unknown>;
}

describe("splunk-oncall-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidSplunkOnCallSinkConfig(null, "SplunkOnCallSink"), RangeError);
    assert.throws(() => assertValidSplunkOnCallSinkConfig("x", "SplunkOnCallSink"), RangeError);
  });

  it("rejects a malformed client, payloadMaxChars, status, and messageType", () => {
    assert.throws(
      () => assertValidSplunkOnCallSinkConfig(baseConfig(new FakeClient(), { client: {} as never }), "SplunkOnCallSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSplunkOnCallSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 0 }), "SplunkOnCallSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSplunkOnCallSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 1.5 }), "SplunkOnCallSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSplunkOnCallSinkConfig(baseConfig(new FakeClient(), { status: "FIRING" as never }), "SplunkOnCallSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSplunkOnCallSinkConfig(baseConfig(new FakeClient(), { status: "acknowledged" as never }), "SplunkOnCallSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSplunkOnCallSinkConfig(baseConfig(new FakeClient(), { status: "" as never }), "SplunkOnCallSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSplunkOnCallSinkConfig(baseConfig(new FakeClient(), { messageType: "critical" as never }), "SplunkOnCallSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSplunkOnCallSinkConfig(baseConfig(new FakeClient(), { messageType: "SEV1" as never }), "SplunkOnCallSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSplunkOnCallSinkConfig(baseConfig(new FakeClient(), { messageType: "" as never }), "SplunkOnCallSink"),
      RangeError
    );
  });

  it("rejects ACKNOWLEDGE and RECOVERY as a configured messageType (out of scope)", () => {
    assert.throws(
      () => assertValidSplunkOnCallSinkConfig(baseConfig(new FakeClient(), { messageType: "ACKNOWLEDGE" as never }), "SplunkOnCallSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSplunkOnCallSinkConfig(baseConfig(new FakeClient(), { messageType: "RECOVERY" as never }), "SplunkOnCallSink"),
      RangeError
    );
  });

  it("accepts the three firing message types and both statuses", () => {
    for (const messageType of SPLUNK_ONCALL_MESSAGE_TYPES) {
      assert.doesNotThrow(() =>
        assertValidSplunkOnCallSinkConfig(baseConfig(new FakeClient(), { messageType }), "SplunkOnCallSink")
      );
    }
    for (const status of SPLUNK_ONCALL_STATUSES) {
      assert.doesNotThrow(() =>
        assertValidSplunkOnCallSinkConfig(baseConfig(new FakeClient(), { status }), "SplunkOnCallSink")
      );
    }
  });

  it("pins the REST Generic URL template (api_key + routing_key in the path, fixed 20131114 segment)", () => {
    assert.equal(
      SPLUNK_ONCALL_REST_GENERIC_URL_TEMPLATE,
      "https://alert.victorops.com/integrations/generic/20131114/alert/{api_key}/{routing_key}"
    );
  });
});

describe("splunk-oncall-sink display name derivation", () => {
  it("prefers subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveSplunkOnCallDisplayName({ body: "{}", subject: "disk full", key: "k-1", traceId: "t-1" }),
      "disk full"
    );
    assert.equal(
      resolveSplunkOnCallDisplayName({ body: "{}", key: "k-1", traceId: "t-1" }),
      "k-1"
    );
    assert.equal(
      resolveSplunkOnCallDisplayName({ body: "{}", traceId: "t-1" }),
      "t-1"
    );
    assert.equal(
      resolveSplunkOnCallDisplayName({ body: "{}" }),
      SPLUNK_ONCALL_FALLBACK_DISPLAY_NAME
    );
  });

  it("skips empty-string values when deriving the display name", () => {
    assert.equal(
      resolveSplunkOnCallDisplayName({ body: "{}", subject: "", key: "", traceId: "t-1" }),
      "t-1"
    );
    assert.equal(
      resolveSplunkOnCallDisplayName({ body: "{}", subject: "", key: "", traceId: "" }),
      SPLUNK_ONCALL_FALLBACK_DISPLAY_NAME
    );
  });
});

describe("splunk-oncall-sink status and message type resolution", () => {
  it("defaults to firing / CRITICAL", () => {
    assert.equal(resolveSplunkOnCallStatus({ body: "{}" }, {}), SPLUNK_ONCALL_DEFAULT_STATUS);
    assert.equal(resolveSplunkOnCallMessageType({ body: "{}" }, {}), SPLUNK_ONCALL_DEFAULT_MESSAGE_TYPE);
    assert.equal(SPLUNK_ONCALL_DEFAULT_STATUS, "firing");
    assert.equal(SPLUNK_ONCALL_DEFAULT_MESSAGE_TYPE, "CRITICAL");
  });

  it("prefers the per-record override over the config value", () => {
    assert.equal(
      resolveSplunkOnCallStatus({ body: "{}", status: "resolved" }, { status: "firing" }),
      "resolved"
    );
    assert.equal(
      resolveSplunkOnCallMessageType({ body: "{}", messageType: "WARNING" }, { messageType: "INFO" }),
      "WARNING"
    );
    assert.equal(
      resolveSplunkOnCallMessageType({ body: "{}" }, { messageType: "INFO" }),
      "INFO"
    );
  });
});

describe("splunk-oncall-sink state message derivation", () => {
  it("carries the key/traceId identifiers, falling back to the display-name text", () => {
    assert.equal(
      resolveSplunkOnCallStateMessage({ body: "{}", key: "k-1", traceId: "t-1" }, {}),
      "key=k-1; traceId=t-1"
    );
    assert.equal(
      resolveSplunkOnCallStateMessage({ body: "{}", key: "k-1" }, {}),
      "key=k-1"
    );
    assert.equal(
      resolveSplunkOnCallStateMessage({ body: "{}", traceId: "t-1" }, {}),
      "traceId=t-1"
    );
    assert.equal(
      resolveSplunkOnCallStateMessage({ body: "{}", subject: "disk full" }, {}),
      "disk full"
    );
    assert.equal(
      resolveSplunkOnCallStateMessage({ body: "{}" }, {}),
      SPLUNK_ONCALL_FALLBACK_DISPLAY_NAME
    );
  });

  it("appends the payload only under the includePayload opt-in, truncated to the limit", () => {
    const record = { body: '{"a":1}', key: "k-1" };
    assert.equal(
      resolveSplunkOnCallStateMessage(record, { includePayload: true, payloadMaxChars: 4 }),
      "key=k-1\n\n{\"a\"… (truncated)"
    );
    assert.equal(
      resolveSplunkOnCallStateMessage(record, { includePayload: true }),
      `key=k-1\n\n${record.body}`
    );
    assert.equal(resolveSplunkOnCallStateMessage(record, {}), "key=k-1");
  });

  it("truncates a payload snippet at the default 2000 characters", () => {
    assert.equal(SPLUNK_ONCALL_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
    const long = "x".repeat(2001);
    assert.equal(truncateSplunkOnCallPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
    assert.equal(truncateSplunkOnCallPayload("short", 2000), "short");
  });
});

describe("splunk-oncall-sink body building", () => {
  it("builds the firing body with CRITICAL, entity_id, and the fixed monitoring_tool", () => {
    const parsed = JSON.parse(
      buildSplunkOnCallAlertBody({ body: "{}", subject: "disk full", key: "k-1", traceId: "t-1" }, {})
    ) as Record<string, unknown>;
    assert.deepEqual(parsed, {
      message_type: "CRITICAL",
      entity_id: "k-1",
      entity_display_name: "disk full",
      state_message: "key=k-1; traceId=t-1",
      monitoring_tool: SPLUNK_ONCALL_MONITORING_TOOL,
    });
    assert.equal(SPLUNK_ONCALL_MONITORING_TOOL, "webhook-relay");
  });

  it("omits entity_id when the event carries no key", () => {
    const parsed = JSON.parse(
      buildSplunkOnCallAlertBody({ body: "{}", subject: "disk full" }, {})
    ) as Record<string, unknown>;
    assert.equal("entity_id" in parsed, false);
    assert.equal(parsed.entity_display_name, "disk full");
    assert.equal(parsed.state_message, "disk full");
  });

  it("honours the config and per-record message type", () => {
    const withConfig = JSON.parse(
      buildSplunkOnCallAlertBody({ body: "{}", key: "k-1" }, { messageType: "WARNING" })
    ) as Record<string, unknown>;
    assert.equal(withConfig.message_type, "WARNING");
    const withRecord = JSON.parse(
      buildSplunkOnCallAlertBody({ body: "{}", key: "k-1", messageType: "INFO" }, { messageType: "WARNING" })
    ) as Record<string, unknown>;
    assert.equal(withRecord.message_type, "INFO");
  });

  it("sends RECOVERY for a resolved alert and ignores the firing message type", () => {
    const parsed = JSON.parse(
      buildSplunkOnCallAlertBody(
        { body: "{}", key: "k-1", status: "resolved", messageType: "WARNING" },
        { messageType: "INFO" }
      )
    ) as Record<string, unknown>;
    assert.equal(parsed.message_type, SPLUNK_ONCALL_RESOLVED_MESSAGE_TYPE);
    assert.equal(parsed.message_type, "RECOVERY");
    assert.equal(parsed.entity_id, "k-1");
  });

  it("sends RECOVERY when the config status is resolved", () => {
    const parsed = JSON.parse(
      buildSplunkOnCallAlertBody({ body: "{}", key: "k-1" }, { status: "resolved" })
    ) as Record<string, unknown>;
    assert.equal(parsed.message_type, "RECOVERY");
  });
});

describe("splunk-oncall-sink record validation", () => {
  it("rejects an empty body string", () => {
    assert.throws(() => resolveSplunkOnCallRecord({ body: "" }, 0, {}), RangeError);
    assert.throws(() => resolveSplunkOnCallRecord({ body: 1 as never }, 0, {}), RangeError);
  });

  it("rejects a bad per-record status or messageType", () => {
    assert.throws(
      () => resolveSplunkOnCallRecord({ body: "{}", status: "acknowledged" as never }, 0, {}),
      RangeError
    );
    assert.throws(
      () => resolveSplunkOnCallRecord({ body: "{}", messageType: "critical" as never }, 0, {}),
      RangeError
    );
    assert.throws(
      () => resolveSplunkOnCallRecord({ body: "{}", messageType: "ACKNOWLEDGE" as never }, 0, {}),
      RangeError
    );
    assert.throws(
      () => resolveSplunkOnCallRecord({ body: "{}", messageType: "RECOVERY" as never }, 0, {}),
      RangeError
    );
  });

  it("fails a keyless resolve closed, whether the status comes from the record or the config", () => {
    assert.throws(
      () => resolveSplunkOnCallRecord({ body: "{}", status: "resolved" }, 2, {}),
      /requires `key`/
    );
    assert.throws(
      () => resolveSplunkOnCallRecord({ body: "{}", traceId: "t-1", status: "resolved" }, 2, {}),
      /requires `key`/
    );
    assert.throws(
      () => resolveSplunkOnCallRecord({ body: "{}" }, 2, { status: "resolved" }),
      /requires `key`/
    );
    assert.doesNotThrow(() =>
      resolveSplunkOnCallRecord({ body: "{}", key: "k-1", status: "resolved" }, 2, {})
    );
  });
});

describe("splunk-oncall-sink failure classification", () => {
  it("accepts any 2xx status (tentative rule) and rejects the rest", () => {
    for (const status of [200, 201, 202, 204]) {
      assert.deepEqual(classifySplunkOnCallIncidentResponse({ status }), { accepted: true });
    }
    assert.deepEqual(classifySplunkOnCallIncidentResponse({ status: 400 }), {
      accepted: false,
      errorCode: "HTTP_400",
      retryable: false,
    });
    assert.deepEqual(classifySplunkOnCallIncidentResponse({ status: 404 }), {
      accepted: false,
      errorCode: "HTTP_404",
      retryable: false,
    });
  });

  it("maps 429 and 5xx to retryable and other 4xx to fail-closed", () => {
    assert.equal(classifySplunkOnCallRecordFailure(429), true);
    assert.equal(classifySplunkOnCallRecordFailure(500), true);
    assert.equal(classifySplunkOnCallRecordFailure(503), true);
    assert.equal(classifySplunkOnCallRecordFailure(400), false);
    assert.equal(classifySplunkOnCallRecordFailure(404), false);
    assert.equal(classifySplunkOnCallRecordFailure(422), false);
  });

  it("carries the client error text on a failure record, dropping an empty one", () => {
    assert.deepEqual(
      classifySplunkOnCallIncidentResponse({ status: 500, errorMessage: "boom" }),
      { accepted: false, errorCode: "HTTP_500", retryable: true, errorMessage: "boom" }
    );
    assert.deepEqual(
      classifySplunkOnCallIncidentResponse({ status: 400, errorMessage: "" }),
      { accepted: false, errorCode: "HTTP_400", retryable: false }
    );
  });
});

describe("splunk-oncall-sink send", () => {
  it("posts one alert per record with the exact headers and no URL or Authorization", async () => {
    const client = new FakeClient();
    const sink = new SplunkOnCallSink(baseConfig(client));
    const result = await sink.send([
      { body: "{}", subject: "disk full", key: "k-1", traceId: "t-1" },
      { body: "{}", key: "k-2" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    for (const post of client.posts) {
      assert.deepEqual(post.headers, { "Content-Type": SPLUNK_ONCALL_JSON_CONTENT_TYPE });
      assert.equal("url" in post, false);
      assert.equal("Authorization" in post.headers, false);
      assert.equal(JSON.stringify(post).includes("victorops"), false);
      assert.equal(JSON.stringify(post).includes("alert.victorops.com"), false);
    }
    assert.equal(bodyOf(client.posts[0]).entity_id, "k-1");
    assert.equal(bodyOf(client.posts[1]).entity_id, "k-2");
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("throws a config error with no client, mapped non_retryable by classifyFailure", async () => {
    const sink = new SplunkOnCallSink({});
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) => err instanceof SplunkOnCallSinkConfigError
    );
    assert.deepEqual(classifyFailure(new SplunkOnCallSinkConfigError("no client injected")), {
      failureClass: "non_retryable",
    });
  });

  it("throws carrying exactly the failed records with their retry lanes", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 400);
    client.statusOn.set(2, 503);
    client.errorOn.set(2, "down");
    const sink = new SplunkOnCallSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([
          { body: "{}", key: "k-1" },
          { body: "{}", key: "k-2" },
          { body: "{}", key: "k-3" },
        ]),
      (err: unknown) => {
        assert.ok(err instanceof SplunkOnCallSinkError);
        assert.deepEqual(err.failedRecords, [
          { index: 1, errorCode: "HTTP_400", statusCode: 400, retryable: false },
          { index: 2, errorCode: "HTTP_503", statusCode: 503, retryable: true, errorMessage: "down" },
        ]);
        return true;
      }
    );
    assert.deepEqual(sink.stats, { sent: 1, failed: 2, sendFailures: 1 });
  });

  it("maps a client throw to a retryable TRANSPORT_ERROR with the message", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hang up"));
    const sink = new SplunkOnCallSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: "{}", key: "k-1" }]),
      (err: unknown) => {
        assert.ok(err instanceof SplunkOnCallSinkError);
        assert.deepEqual(err.failedRecords, [
          { index: 0, errorCode: "TRANSPORT_ERROR", retryable: true, errorMessage: "socket hang up" },
        ]);
        return true;
      }
    );
  });

  it("validates a keyless resolve before any POST, even in dry-run mode", async () => {
    const client = new FakeClient();
    const sink = new SplunkOnCallSink(baseConfig(client, { dryRun: true }));
    await assert.rejects(
      () => sink.send([{ body: "{}", status: "resolved" }]),
      RangeError
    );
    assert.equal(client.posts.length, 0);
  });

  it("dry-run validates and performs zero client I/O with no stats change", async () => {
    const sink = new SplunkOnCallSink({ dryRun: true });
    const result = await sink.send([{ body: "{}", key: "k-1", messageType: "WARNING" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(
      () => sink.send([{ body: "{}", messageType: "nope" as never }]),
      RangeError
    );
  });

  it("sends a resolved alert as RECOVERY with the same entity_id", async () => {
    const client = new FakeClient();
    const sink = new SplunkOnCallSink(baseConfig(client));
    await sink.send([{ body: "{}", key: "k-1", status: "resolved" }]);
    assert.equal(client.posts.length, 1);
    assert.equal(bodyOf(client.posts[0]).message_type, "RECOVERY");
    assert.equal(bodyOf(client.posts[0]).entity_id, "k-1");
  });
});
