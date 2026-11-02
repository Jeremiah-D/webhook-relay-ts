import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  SpikeSink,
  SpikeSinkConfigError,
  SpikeSinkError,
  assertValidSpikeSinkConfig,
  buildSpikeIncidentBody,
  classifySpikeIncidentResponse,
  classifySpikeRecordFailure,
  resolveSpikeBody,
  resolveSpikePriority,
  resolveSpikeRecord,
  resolveSpikeSeverity,
  resolveSpikeStatus,
  resolveSpikeTitle,
  truncateSpikePayload,
  SPIKE_DEFAULT_PAYLOAD_MAX_CHARS,
  SPIKE_DEFAULT_STATUS,
  SPIKE_FALLBACK_TITLE,
  SPIKE_JSON_CONTENT_TYPE,
  SPIKE_PRIORITIES,
  SPIKE_RESOLVED_STATUS,
  SPIKE_SEVERITIES,
  SPIKE_STATUSES,
  SPIKE_SUCCESS_STATUS,
  SPIKE_WEBHOOK_URL_TEMPLATE,
  type SpikeIncidentClient,
  type SpikeIncidentPostRequest,
  type SpikeIncidentPostResponse,
  type SpikeSinkConfig,
} from "../src/spike-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements SpikeIncidentClient {
  posts: SpikeIncidentPostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error text to return for that post. */
  errorOn = new Map<number, string>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: SpikeIncidentPostRequest): Promise<SpikeIncidentPostResponse> {
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
  client: SpikeIncidentClient,
  extra: Partial<SpikeSinkConfig> = {}
): SpikeSinkConfig {
  return { client, ...extra };
}

describe("spike-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidSpikeSinkConfig(null, "SpikeSink"), RangeError);
    assert.throws(() => assertValidSpikeSinkConfig("x", "SpikeSink"), RangeError);
  });

  it("rejects a malformed client, payloadMaxChars, status, severity, and priority", () => {
    assert.throws(
      () => assertValidSpikeSinkConfig(baseConfig(new FakeClient(), { client: {} as never }), "SpikeSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSpikeSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 0 }), "SpikeSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSpikeSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 1.5 }), "SpikeSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSpikeSinkConfig(baseConfig(new FakeClient(), { status: "FIRING" as never }), "SpikeSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSpikeSinkConfig(baseConfig(new FakeClient(), { status: "acknowledged" as never }), "SpikeSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSpikeSinkConfig(baseConfig(new FakeClient(), { status: "" as never }), "SpikeSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSpikeSinkConfig(baseConfig(new FakeClient(), { severity: "critical" as never }), "SpikeSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSpikeSinkConfig(baseConfig(new FakeClient(), { severity: "sev4" as never }), "SpikeSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSpikeSinkConfig(baseConfig(new FakeClient(), { severity: "" as never }), "SpikeSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSpikeSinkConfig(baseConfig(new FakeClient(), { priority: "p0" as never }), "SpikeSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSpikeSinkConfig(baseConfig(new FakeClient(), { priority: "p6" as never }), "SpikeSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSpikeSinkConfig(baseConfig(new FakeClient(), { priority: "high" as never }), "SpikeSink"),
      RangeError
    );
    assert.throws(
      () => assertValidSpikeSinkConfig(baseConfig(new FakeClient(), { priority: "" as never }), "SpikeSink"),
      RangeError
    );
    assertValidSpikeSinkConfig(baseConfig(new FakeClient(), { status: "firing" }), "SpikeSink");
    assertValidSpikeSinkConfig(baseConfig(new FakeClient(), { status: "resolved" }), "SpikeSink");
    assertValidSpikeSinkConfig(baseConfig(new FakeClient(), { severity: "sev1" }), "SpikeSink");
    assertValidSpikeSinkConfig(baseConfig(new FakeClient(), { severity: "sev2" }), "SpikeSink");
    assertValidSpikeSinkConfig(baseConfig(new FakeClient(), { severity: "sev3" }), "SpikeSink");
    assertValidSpikeSinkConfig(baseConfig(new FakeClient(), { priority: "p1" }), "SpikeSink");
    assertValidSpikeSinkConfig(baseConfig(new FakeClient(), { priority: "p5" }), "SpikeSink");
    assertValidSpikeSinkConfig(baseConfig(new FakeClient()), "SpikeSink");
  });

  it("has no apiKey field: the client alone holds the webhook integration URL", () => {
    // The config type carries no apiKey: a config object that
    // smuggles one in is not part of the sink's contract, and
    // the sink never reads it — the handed request carries no
    // URL at all, let alone a credential (see the send tests).
    const cfg = baseConfig(new FakeClient(), { apiKey: "spike-token-placeholder" } as never);
    assert.equal((cfg as Record<string, unknown>).apiKey, "spike-token-placeholder");
    assertValidSpikeSinkConfig(cfg, "SpikeSink");
  });
});

describe("spike-sink resolvers", () => {
  it("pins the webhook URL template, the documented enums and default, and the resolve wire value", () => {
    assert.equal(SPIKE_WEBHOOK_URL_TEMPLATE, "https://hooks.spike.sh/{token}/push-events");
    assert.deepEqual([...SPIKE_STATUSES], ["firing", "resolved"]);
    assert.equal(SPIKE_DEFAULT_STATUS, "firing");
    assert.deepEqual([...SPIKE_SEVERITIES], ["sev1", "sev2", "sev3"]);
    assert.deepEqual([...SPIKE_PRIORITIES], ["p1", "p2", "p3", "p4", "p5"]);
    assert.equal(SPIKE_RESOLVED_STATUS, "resolve");
    assert.equal(SPIKE_SUCCESS_STATUS, 200);
    assert.equal(resolveSpikeStatus({ body: "{}" }, {}), "firing");
    assert.equal(resolveSpikeStatus({ body: "{}" }, { status: "resolved" }), "resolved");
    assert.equal(resolveSpikeStatus({ body: "{}", status: "firing" }, { status: "resolved" }), "firing");
    assert.equal(resolveSpikeStatus({ body: "{}", status: "resolved" }, {}), "resolved");
    assert.equal(resolveSpikeSeverity({ body: "{}" }, {}), undefined);
    assert.equal(resolveSpikeSeverity({ body: "{}" }, { severity: "sev2" }), "sev2");
    assert.equal(resolveSpikeSeverity({ body: "{}", severity: "sev1" }, { severity: "sev3" }), "sev1");
    assert.equal(resolveSpikePriority({ body: "{}" }, {}), undefined);
    assert.equal(resolveSpikePriority({ body: "{}" }, { priority: "p4" }), "p4");
    assert.equal(resolveSpikePriority({ body: "{}", priority: "p2" }, { priority: "p5" }), "p2");
  });

  it("derives the title from subject, key, then traceId", () => {
    assert.equal(resolveSpikeTitle({ body: "{}", subject: "Payments failing", key: "k", traceId: "t" }), "Payments failing");
    assert.equal(resolveSpikeTitle({ body: "{}", key: "order-1", traceId: "t" }), "order-1");
    assert.equal(resolveSpikeTitle({ body: "{}", traceId: "trace-9" }), "trace-9");
    assert.equal(resolveSpikeTitle({ body: "{}" }), SPIKE_FALLBACK_TITLE);
  });

  it("does not truncate the title: the re-checked docs state no length limit", () => {
    const long = "s".repeat(5000);
    assert.equal(resolveSpikeTitle({ body: "{}", subject: long }), long);
    const body = JSON.parse(buildSpikeIncidentBody({ body: "{}", subject: long, key: long }, {}));
    assert.equal(body.title, long);
    assert.equal(body.title.length, 5000);
  });

  it("derives the body from the key/traceId identifiers, and never leaves it empty", () => {
    assert.equal(
      resolveSpikeBody({ body: "{}", key: "order-1", traceId: "trace-9" }, {}),
      "key=order-1; traceId=trace-9"
    );
    assert.equal(resolveSpikeBody({ body: "{}", key: "order-1" }, {}), "key=order-1");
    assert.equal(resolveSpikeBody({ body: "{}", traceId: "trace-9" }, {}), "traceId=trace-9");
    // No identifiers: falls back to the title text, never empty.
    assert.equal(
      resolveSpikeBody({ body: "{}", subject: "Payments failing" }, {}),
      "Payments failing"
    );
    assert.equal(resolveSpikeBody({ body: "{}" }, {}), SPIKE_FALLBACK_TITLE);
    assert.notEqual(resolveSpikeBody({ body: "{}" }, {}), "");
  });

  it("does not truncate the body identifiers or fallback text: the re-checked docs state no length limit", () => {
    const long = "s".repeat(5000);
    assert.equal(resolveSpikeBody({ body: "{}", key: long }, {}), `key=${long}`);
    assert.equal(resolveSpikeBody({ body: "{}", subject: long }, {}), long);
  });

  it("appends the payload body only under the opt-in, truncated at the default 2000", () => {
    assert.equal(SPIKE_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
    assert.equal(truncateSpikePayload("abcdef", 4), "abcd… (truncated)");
    assert.equal(truncateSpikePayload("abc", 4), "abc");
    const withPayload = resolveSpikeBody(
      { body: '{"a":1}', subject: "Payments failing", key: "k" },
      { includePayload: true }
    );
    assert.equal(withPayload, 'key=k\n\n{"a":1}');
    // No identifiers: the payload body is appended after the title-text fallback.
    assert.equal(
      resolveSpikeBody({ body: '{"a":1}', subject: "Payments failing" }, { includePayload: true }),
      'Payments failing\n\n{"a":1}'
    );
    const long = resolveSpikeBody({ body: "x".repeat(2001), key: "k1" }, { includePayload: true });
    assert.equal(long, `key=k1\n\n${"x".repeat(2000)}… (truncated)`);
    const short = resolveSpikeBody(
      { body: "0123456789ABCDEF", key: "k1" },
      { includePayload: true, payloadMaxChars: 10 }
    );
    assert.equal(short, "key=k1\n\n0123456789… (truncated)");
  });

  it("builds the incident body with title/body — no credential, no invented fields", () => {
    const body = JSON.parse(
      buildSpikeIncidentBody(
        { body: "{}", subject: "Payments failing", key: "order-1", traceId: "trace-9" },
        {}
      )
    );
    assert.equal(body.title, "Payments failing");
    assert.equal(body.body, "key=order-1; traceId=trace-9");
    assert.equal(body.severity, undefined);
    assert.equal("severity" in body, false);
    assert.equal(body.priority, undefined);
    assert.equal("priority" in body, false);
    assert.equal(body.status, undefined);
    assert.equal("status" in body, false);
    // No credential ever enters the body.
    assert.equal(JSON.stringify(body).includes("apiKey"), false);
    assert.equal(JSON.stringify(body).includes("Authorization"), false);
    assert.equal(JSON.stringify(body).includes("Bearer"), false);
    assert.equal(JSON.stringify(body).includes("token"), false);
  });

  it("omits severity and priority by default — the docs state no defaults, so none are invented", () => {
    const body = JSON.parse(
      buildSpikeIncidentBody({ body: "{}", subject: "Payments failing" }, {})
    );
    assert.equal(body.title, "Payments failing");
    assert.equal(body.body, "Payments failing");
    assert.equal("severity" in body, false);
    assert.equal("priority" in body, false);
  });

  it("sends a configured severity and priority, including per-record overrides", () => {
    const body = JSON.parse(
      buildSpikeIncidentBody(
        { body: "{}", subject: "Alert", key: "k1" },
        { severity: "sev1", priority: "p1" }
      )
    );
    assert.equal(body.severity, "sev1");
    assert.equal(body.priority, "p1");
    const overridden = JSON.parse(
      buildSpikeIncidentBody(
        { body: "{}", subject: "Alert", key: "k1", severity: "sev3", priority: "p5" },
        { severity: "sev1", priority: "p1" }
      )
    );
    assert.equal(overridden.severity, "sev3");
    assert.equal(overridden.priority, "p5");
    const each = JSON.parse(
      buildSpikeIncidentBody(
        { body: "{}", subject: "Alert", key: "k1", severity: "sev2", priority: "p3" },
        {}
      )
    );
    assert.equal(each.severity, "sev2");
    assert.equal(each.priority, "p3");
  });

  it("sends no status for a firing alert and exactly 'resolve' for a resolved one", () => {
    const firing = JSON.parse(
      buildSpikeIncidentBody({ body: "{}", subject: "Alert", key: "k1" }, {})
    );
    assert.equal("status" in firing, false);
    const resolved = JSON.parse(
      buildSpikeIncidentBody(
        { body: '{"a":1}', subject: "Alert", key: "k1" },
        { status: "resolved" }
      )
    );
    assert.equal(resolved.status, "resolve");
    assert.equal(resolved.title, "Alert");
    assert.equal(resolved.body, "key=k1");
    const overridden = JSON.parse(
      buildSpikeIncidentBody(
        { body: "{}", subject: "Alert", key: "k1", status: "firing" },
        { status: "resolved" }
      )
    );
    assert.equal("status" in overridden, false);
  });

  it("rejects an empty record body", () => {
    assert.throws(() => resolveSpikeRecord({ body: "" }, 0, {}), RangeError);
    assert.deepEqual(resolveSpikeRecord({ body: "{}" }, 2, {}), { index: 2 });
  });

  it("rejects a bad per-record status, severity, and priority value", () => {
    assert.throws(
      () => resolveSpikeRecord({ body: "{}", status: "acknowledged" as never }, 0, {}),
      RangeError
    );
    assert.throws(
      () => resolveSpikeRecord({ body: "{}", severity: "critical" as never }, 0, {}),
      RangeError
    );
    assert.throws(
      () => resolveSpikeRecord({ body: "{}", severity: "sev4" as never }, 0, {}),
      RangeError
    );
    assert.throws(
      () => resolveSpikeRecord({ body: "{}", severity: "" as never }, 0, {}),
      RangeError
    );
    assert.throws(
      () => resolveSpikeRecord({ body: "{}", priority: "high" as never }, 0, {}),
      RangeError
    );
    assert.throws(
      () => resolveSpikeRecord({ body: "{}", priority: "p0" as never }, 0, {}),
      RangeError
    );
    assert.throws(
      () => resolveSpikeRecord({ body: "{}", priority: "p6" as never }, 0, {}),
      RangeError
    );
  });

  it("does not reject a keyless resolve — the title is always non-empty, so the call is well-formed", () => {
    // Unlike the Squadcast/ilert resolve rules, Spike.sh
    // resolves by title plus token and the title is never
    // empty — so a keyless resolve is sent with the
    // fallback title (see the README warning: it almost
    // certainly matches no open incident).
    assert.deepEqual(resolveSpikeRecord({ body: "{}", status: "resolved" }, 0, {}), { index: 0 });
    assert.deepEqual(resolveSpikeRecord({ body: "{}" }, 0, { status: "resolved" }), { index: 0 });
    const body = JSON.parse(
      buildSpikeIncidentBody({ body: "{}", status: "resolved" }, {})
    );
    assert.equal(body.title, SPIKE_FALLBACK_TITLE);
    assert.equal(body.status, "resolve");
  });
});

describe("spike-sink failure mapping", () => {
  it("maps 429 and 5xx to retryable, other non-200 to fail-closed — including 400 and 404", () => {
    assert.equal(classifySpikeRecordFailure(429), true);
    assert.equal(classifySpikeRecordFailure(500), true);
    assert.equal(classifySpikeRecordFailure(503), true);
    assert.equal(classifySpikeRecordFailure(400), false);
    assert.equal(classifySpikeRecordFailure(401), false);
    assert.equal(classifySpikeRecordFailure(403), false);
    assert.equal(classifySpikeRecordFailure(404), false);
    assert.equal(classifySpikeRecordFailure(413), false);
    assert.equal(classifySpikeRecordFailure(422), false);
    // 201 is not a documented success: fail-closed.
    assert.equal(classifySpikeRecordFailure(201), false);
  });

  it("accepts exactly 200 as an acceptance receipt — the one documented success status", () => {
    assert.deepEqual(classifySpikeIncidentResponse({ status: 200 }), { accepted: true });
    // A 201 from a proxy or a future revision is not a
    // documented success: an HTTP_201 failure, fail-closed.
    assert.deepEqual(classifySpikeIncidentResponse({ status: 201 }), {
      accepted: false,
      errorCode: "HTTP_201",
      retryable: false,
    });
    // A 3xx is not an acceptance: fail-closed.
    assert.deepEqual(classifySpikeIncidentResponse({ status: 302 }), {
      accepted: false,
      errorCode: "HTTP_302",
      retryable: false,
    });
  });

  it("maps a non-200 status to its HTTP code and lane, surfacing the client's error text", () => {
    assert.deepEqual(
      classifySpikeIncidentResponse({ status: 429, errorMessage: "Rate limit exceeded" }),
      {
        accepted: false,
        errorCode: "HTTP_429",
        retryable: true,
        errorMessage: "Rate limit exceeded",
      }
    );
    assert.deepEqual(
      classifySpikeIncidentResponse({ status: 400, errorMessage: "Invalid body" }),
      {
        accepted: false,
        errorCode: "HTTP_400",
        retryable: false,
        errorMessage: "Invalid body",
      }
    );
    assert.deepEqual(classifySpikeIncidentResponse({ status: 404 }), {
      accepted: false,
      errorCode: "HTTP_404",
      retryable: false,
    });
    assert.deepEqual(
      classifySpikeIncidentResponse({ status: 500, errorMessage: "Could not process your request" }),
      {
        accepted: false,
        errorCode: "HTTP_500",
        retryable: true,
        errorMessage: "Could not process your request",
      }
    );
  });
});

describe("spike-sink send", () => {
  it("posts one incident per message with no URL and no credentials in the handed request", async () => {
    const client = new FakeClient();
    const sink = new SpikeSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "Payments failing", key: "order-1", traceId: "trace-9" },
      { body: '{"b":2}', key: "order-2" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    const first = client.posts[0];
    // The webhook integration URL — token alike — is held
    // by the client alone: the sink hands over no URL at
    // all, so there is nothing to leak.
    assert.equal("url" in first, false);
    assert.equal(first.headers["Content-Type"], SPIKE_JSON_CONTENT_TYPE);
    assert.equal(first.headers["Authorization"], undefined);
    assert.equal(first.headers["Idempotency-Key"], undefined);
    assert.deepEqual(Object.keys(first.headers), ["Content-Type"]);
    const body = JSON.parse(first.body);
    assert.equal(body.title, "Payments failing");
    assert.equal(body.body, "key=order-1; traceId=trace-9");
    assert.equal("severity" in body, false);
    assert.equal("priority" in body, false);
    assert.equal("status" in body, false);
    // No credential ever enters the handed request.
    assert.equal(JSON.stringify(first).includes("apiKey"), false);
    assert.equal(JSON.stringify(first).includes("Authorization"), false);
    assert.equal(JSON.stringify(first).includes("Bearer"), false);
    assert.equal(JSON.stringify(first).includes("token"), false);
    assert.equal(JSON.stringify(first).includes("hooks.spike.sh"), false);
    assert.equal(JSON.stringify(first).includes("push-events"), false);
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("rejects a 201 as a failure — only 200 is the documented success", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 201);
    const sink = new SpikeSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as SpikeSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_201");
        assert.equal(failed[0].retryable, false);
        return true;
      }
    );
  });

  it("accepts a 200 without any receipt id — the status is the acceptance credential", async () => {
    const client = new FakeClient();
    const sink = new SpikeSink(baseConfig(client));
    const result = await sink.send([{ body: "{}", key: "k1" }]);
    assert.deepEqual(result, { ok: true, sent: 1 });
  });

  it("throws with exactly the failed messages and their retry lanes", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 429);
    client.statusOn.set(2, 500);
    const sink = new SpikeSink(baseConfig(client));
    await assert.rejects(
      sink.send([
        { body: "{}", key: "k1" },
        { body: "{}", key: "k2" },
        { body: "{}", key: "k3" },
      ]),
      (err: unknown) => {
        assert.ok(err instanceof SpikeSinkError);
        assert.deepEqual(
          (err as SpikeSinkError).failedRecords.map((f) => [f.index, f.errorCode, f.retryable]),
          [
            [1, "HTTP_429", true],
            [2, "HTTP_500", true],
          ]
        );
        return true;
      }
    );
    assert.deepEqual(sink.stats, { sent: 1, failed: 2, sendFailures: 1 });
  });

  it("treats an invalid body (400) as fail-closed, surfacing the client's error text", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 400);
    client.errorOn.set(0, "Invalid body");
    const sink = new SpikeSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as SpikeSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_400");
        assert.equal(failed[0].statusCode, 400);
        assert.equal(failed[0].retryable, false);
        assert.equal(failed[0].errorMessage, "Invalid body");
        return true;
      }
    );
  });

  it("treats a wrong webhook URL (404) as fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 404);
    client.errorOn.set(0, "Webhook URL is wrong");
    const sink = new SpikeSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as SpikeSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_404");
        assert.equal(failed[0].retryable, false);
        assert.equal(failed[0].errorMessage, "Webhook URL is wrong");
        return true;
      }
    );
  });

  it("treats a client throw as a retryable transport failure", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hang up"));
    const sink = new SpikeSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as SpikeSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(failed[0].retryable, true);
        assert.equal(failed[0].errorMessage, "socket hang up");
        return true;
      }
    );
  });

  it("throws a config error with no client, mapped non_retryable", async () => {
    const sink = new SpikeSink({});
    await assert.rejects(sink.send([{ body: "{}", key: "k1" }]), SpikeSinkConfigError);
    assert.equal(classifyFailure(new SpikeSinkConfigError("no client injected")).failureClass, "non_retryable");
  });

  it("dry-runs with zero client I/O and untouched stats", async () => {
    const client = new FakeClient();
    const sink = new SpikeSink(baseConfig(client, { dryRun: true }));
    const result = await sink.send([{ body: "{}", subject: "Payments failing" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("dry-runs still validate the config and the records, including severity and priority", async () => {
    const client = new FakeClient();
    const sink = new SpikeSink(baseConfig(client, { dryRun: true }));
    await assert.rejects(sink.send([{ body: "" }]), RangeError);
    assert.equal(client.posts.length, 0);
    await assert.rejects(sink.send([{ body: "{}", status: "acknowledged" as never }]), RangeError);
    assert.equal(client.posts.length, 0);
    await assert.rejects(sink.send([{ body: "{}", severity: "critical" as never }]), RangeError);
    assert.equal(client.posts.length, 0);
    await assert.rejects(sink.send([{ body: "{}", priority: "high" as never }]), RangeError);
    assert.equal(client.posts.length, 0);
    assert.throws(
      () => new SpikeSink({ severity: "sev4" as never, dryRun: true }),
      RangeError
    );
    assert.throws(
      () => new SpikeSink({ priority: "p6" as never, dryRun: true }),
      RangeError
    );
  });

  it("appends the payload body under the opt-in, truncated at the default 2000", async () => {
    const client = new FakeClient();
    const sink = new SpikeSink(baseConfig(client, { includePayload: true, payloadMaxChars: 10 }));
    await sink.send([{ body: "0123456789ABCDEF", subject: "Alert", key: "k1" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.body, "key=k1\n\n0123456789… (truncated)");
    assert.equal(body.title, "Alert");

    const defaultClient = new FakeClient();
    const defaultSink = new SpikeSink(baseConfig(defaultClient, { includePayload: true }));
    await defaultSink.send([{ body: "x".repeat(2001), subject: "Alert", key: "k1" }]);
    const defaultBody = JSON.parse(defaultClient.posts[0].body);
    assert.equal(defaultBody.body, `key=k1\n\n${"x".repeat(2000)}… (truncated)`);
  });

  it("omits the payload body by default — body carries the identifiers only", async () => {
    const client = new FakeClient();
    const sink = new SpikeSink(baseConfig(client));
    await sink.send([{ body: '{"secret":"s3cr3t"}', subject: "Alert", key: "k1" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.body, "key=k1");
    assert.equal(JSON.stringify(body).includes("s3cr3t"), false);
  });

  it("sends a configured severity and priority, and omits both for a keyless firing", async () => {
    const client = new FakeClient();
    const sink = new SpikeSink(baseConfig(client, { severity: "sev1", priority: "p2" }));
    await sink.send([{ body: "{}", subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.severity, "sev1");
    assert.equal(body.priority, "p2");
    assert.equal("status" in body, false);
    assert.equal(body.body, "Alert");
  });

  it("sends a resolve with the same title as a normal incident — Spike.sh resolves the open incident, the sink tracks nothing", async () => {
    const client = new FakeClient();
    const sink = new SpikeSink(baseConfig(client));
    const result = await sink.send([
      { body: "{}", key: "k1", status: "firing" },
      { body: "{}", key: "k1", status: "resolved" },
    ]);
    // No sink-side suppression or state: both incidents go out
    // with the same title, and Spike.sh resolves the open
    // incident for the later one instead of creating a new one.
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    assert.equal("status" in JSON.parse(client.posts[0].body), false);
    assert.equal(JSON.parse(client.posts[1].body).status, "resolve");
    assert.equal(JSON.parse(client.posts[1].body).title, "k1");
    // The resolve still carries the derived title and a
    // non-empty body, keeping one uniform envelope.
    assert.equal(JSON.parse(client.posts[1].body).body, "key=k1");
  });

  it("sends a keyless resolve with the fallback title — it resolves by that title, so the operator must use the same key", async () => {
    const client = new FakeClient();
    const sink = new SpikeSink(baseConfig(client));
    const result = await sink.send([{ body: "{}", status: "resolved" }]);
    assert.deepEqual(result, { ok: true, sent: 1 });
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.title, SPIKE_FALLBACK_TITLE);
    assert.equal(body.status, "resolve");
    assert.equal(body.body, SPIKE_FALLBACK_TITLE);
  });

  it("falls back to 'webhook event' for a sourceless event, with a non-empty body", async () => {
    const client = new FakeClient();
    const sink = new SpikeSink(baseConfig(client));
    await sink.send([{ body: "{}" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal("status" in body, false);
    assert.equal(body.title, "webhook event");
    assert.equal(body.body, "webhook event");
    assert.equal("severity" in body, false);
    assert.equal("priority" in body, false);
  });
});
