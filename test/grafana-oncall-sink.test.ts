import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  GrafanaOnCallSink,
  GrafanaOnCallSinkConfigError,
  GrafanaOnCallSinkError,
  assertValidGrafanaOnCallSinkConfig,
  buildGrafanaOnCallAlertBody,
  classifyGrafanaOnCallAlertResponse,
  classifyGrafanaOnCallRecordFailure,
  resolveGrafanaOnCallMessage,
  resolveGrafanaOnCallRecord,
  resolveGrafanaOnCallState,
  resolveGrafanaOnCallStatus,
  resolveGrafanaOnCallTitle,
  truncateGrafanaOnCallPayload,
  GRAFANA_ONCALL_DEFAULT_PAYLOAD_MAX_CHARS,
  GRAFANA_ONCALL_DEFAULT_STATUS,
  GRAFANA_ONCALL_FALLBACK_TITLE,
  GRAFANA_ONCALL_FIRING_STATE,
  GRAFANA_ONCALL_FORMATTED_WEBHOOK_URL_TEMPLATE,
  GRAFANA_ONCALL_JSON_CONTENT_TYPE,
  GRAFANA_ONCALL_RESOLVED_STATE,
  GRAFANA_ONCALL_STATUSES,
  GRAFANA_ONCALL_WEBHOOK_URL_TEMPLATE,
  type GrafanaOnCallAlertClient,
  type GrafanaOnCallAlertPostRequest,
  type GrafanaOnCallAlertPostResponse,
  type GrafanaOnCallSinkConfig,
} from "../src/grafana-oncall-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements GrafanaOnCallAlertClient {
  posts: GrafanaOnCallAlertPostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error text to return for that post. */
  errorOn = new Map<number, string>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: GrafanaOnCallAlertPostRequest): Promise<GrafanaOnCallAlertPostResponse> {
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
  client: GrafanaOnCallAlertClient,
  extra: Partial<GrafanaOnCallSinkConfig> = {}
): GrafanaOnCallSinkConfig {
  return { client, ...extra };
}

describe("grafana-oncall-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidGrafanaOnCallSinkConfig(null, "GrafanaOnCallSink"), RangeError);
    assert.throws(() => assertValidGrafanaOnCallSinkConfig("x", "GrafanaOnCallSink"), RangeError);
  });

  it("rejects a malformed client, payloadMaxChars, and status", () => {
    assert.throws(
      () => assertValidGrafanaOnCallSinkConfig(baseConfig(new FakeClient(), { client: {} as never }), "GrafanaOnCallSink"),
      RangeError
    );
    assert.throws(
      () => assertValidGrafanaOnCallSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 0 }), "GrafanaOnCallSink"),
      RangeError
    );
    assert.throws(
      () => assertValidGrafanaOnCallSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 1.5 }), "GrafanaOnCallSink"),
      RangeError
    );
    assert.throws(
      () => assertValidGrafanaOnCallSinkConfig(baseConfig(new FakeClient(), { status: "FIRING" as never }), "GrafanaOnCallSink"),
      RangeError
    );
    assert.throws(
      () => assertValidGrafanaOnCallSinkConfig(baseConfig(new FakeClient(), { status: "acknowledged" as never }), "GrafanaOnCallSink"),
      RangeError
    );
    assert.throws(
      () => assertValidGrafanaOnCallSinkConfig(baseConfig(new FakeClient(), { status: "" as never }), "GrafanaOnCallSink"),
      RangeError
    );
    assertValidGrafanaOnCallSinkConfig(baseConfig(new FakeClient(), { status: "firing" }), "GrafanaOnCallSink");
    assertValidGrafanaOnCallSinkConfig(baseConfig(new FakeClient(), { status: "resolved" }), "GrafanaOnCallSink");
    assertValidGrafanaOnCallSinkConfig(baseConfig(new FakeClient()), "GrafanaOnCallSink");
  });

  it("has no apiKey field: the client alone holds the integration webhook URL", () => {
    // The config type carries no apiKey: a config object that
    // smuggles one in is not part of the sink's contract, and
    // the sink never reads it — the handed request carries no
    // URL at all, let alone a credential (see the send tests).
    const cfg = baseConfig(new FakeClient(), { apiKey: "m12xmIjOcgwH74UF8CN4dk0Dh" } as never);
    assert.equal((cfg as Record<string, unknown>).apiKey, "m12xmIjOcgwH74UF8CN4dk0Dh");
    assertValidGrafanaOnCallSinkConfig(cfg, "GrafanaOnCallSink");
  });
});

describe("grafana-oncall-sink resolvers", () => {
  it("pins the webhook URL templates, the documented statuses and default, and the wire states", () => {
    assert.equal(GRAFANA_ONCALL_WEBHOOK_URL_TEMPLATE, "https://<host>/integrations/v1/webhook/{token}/");
    assert.equal(GRAFANA_ONCALL_FORMATTED_WEBHOOK_URL_TEMPLATE, "https://<host>/integrations/v1/formatted_webhook/{token}/");
    assert.deepEqual([...GRAFANA_ONCALL_STATUSES], ["firing", "resolved"]);
    assert.equal(GRAFANA_ONCALL_DEFAULT_STATUS, "firing");
    assert.equal(GRAFANA_ONCALL_FIRING_STATE, "alerting");
    assert.equal(GRAFANA_ONCALL_RESOLVED_STATE, "OK");
    assert.equal(resolveGrafanaOnCallStatus({ body: "{}" }, {}), "firing");
    assert.equal(resolveGrafanaOnCallStatus({ body: "{}" }, { status: "resolved" }), "resolved");
    assert.equal(resolveGrafanaOnCallStatus({ body: "{}", status: "firing" }, { status: "resolved" }), "firing");
    assert.equal(resolveGrafanaOnCallStatus({ body: "{}", status: "resolved" }, {}), "resolved");
    // The wire state is the documented casing: "OK", not "ok".
    assert.equal(resolveGrafanaOnCallState({ body: "{}" }, {}), "alerting");
    assert.equal(resolveGrafanaOnCallState({ body: "{}", status: "resolved" }, {}), "OK");
    assert.equal(resolveGrafanaOnCallState({ body: "{}" }, { status: "resolved" }), "OK");
  });

  it("derives the title from subject, key, then traceId", () => {
    assert.equal(resolveGrafanaOnCallTitle({ body: "{}", subject: "Payments failing", key: "k", traceId: "t" }), "Payments failing");
    assert.equal(resolveGrafanaOnCallTitle({ body: "{}", key: "order-1", traceId: "t" }), "order-1");
    assert.equal(resolveGrafanaOnCallTitle({ body: "{}", traceId: "trace-9" }), "trace-9");
    assert.equal(resolveGrafanaOnCallTitle({ body: "{}" }), GRAFANA_ONCALL_FALLBACK_TITLE);
  });

  it("does not truncate the title: the re-checked docs state no length limit", () => {
    const long = "s".repeat(5000);
    assert.equal(resolveGrafanaOnCallTitle({ body: "{}", subject: long }), long);
    const body = JSON.parse(buildGrafanaOnCallAlertBody({ body: "{}", subject: long, key: long }, {}));
    assert.equal(body.title, long);
    assert.equal(body.title.length, 5000);
  });

  it("derives the message from the key/traceId identifiers, and never leaves it empty", () => {
    assert.equal(
      resolveGrafanaOnCallMessage({ body: "{}", key: "order-1", traceId: "trace-9" }, {}),
      "key=order-1; traceId=trace-9"
    );
    assert.equal(resolveGrafanaOnCallMessage({ body: "{}", key: "order-1" }, {}), "key=order-1");
    assert.equal(resolveGrafanaOnCallMessage({ body: "{}", traceId: "trace-9" }, {}), "traceId=trace-9");
    // No identifiers: falls back to the title text, never empty.
    assert.equal(
      resolveGrafanaOnCallMessage({ body: "{}", subject: "Payments failing" }, {}),
      "Payments failing"
    );
    assert.equal(resolveGrafanaOnCallMessage({ body: "{}" }, {}), GRAFANA_ONCALL_FALLBACK_TITLE);
    assert.notEqual(resolveGrafanaOnCallMessage({ body: "{}" }, {}), "");
  });

  it("does not truncate the message identifiers or fallback text: the re-checked docs state no length limit", () => {
    const long = "s".repeat(5000);
    assert.equal(resolveGrafanaOnCallMessage({ body: "{}", key: long }, {}), `key=${long}`);
    assert.equal(resolveGrafanaOnCallMessage({ body: "{}", subject: long }, {}), long);
  });

  it("appends the payload body only under the opt-in, truncated at the default 2000", () => {
    assert.equal(GRAFANA_ONCALL_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
    assert.equal(truncateGrafanaOnCallPayload("abcdef", 4), "abcd… (truncated)");
    assert.equal(truncateGrafanaOnCallPayload("abc", 4), "abc");
    const withPayload = resolveGrafanaOnCallMessage(
      { body: '{"a":1}', subject: "Payments failing", key: "k" },
      { includePayload: true }
    );
    assert.equal(withPayload, 'key=k\n\n{"a":1}');
    // No identifiers: the payload body is appended after the title-text fallback.
    assert.equal(
      resolveGrafanaOnCallMessage({ body: '{"a":1}', subject: "Payments failing" }, { includePayload: true }),
      'Payments failing\n\n{"a":1}'
    );
    const long = resolveGrafanaOnCallMessage({ body: "x".repeat(2001), key: "k1" }, { includePayload: true });
    assert.equal(long, `key=k1\n\n${"x".repeat(2000)}… (truncated)`);
    const short = resolveGrafanaOnCallMessage(
      { body: "0123456789ABCDEF", key: "k1" },
      { includePayload: true, payloadMaxChars: 10 }
    );
    assert.equal(short, "key=k1\n\n0123456789… (truncated)");
  });

  it("builds the alert body with title/message/state/ruleId — no credential, no invented fields", () => {
    const body = JSON.parse(
      buildGrafanaOnCallAlertBody(
        { body: "{}", subject: "Payments failing", key: "order-1", traceId: "trace-9" },
        {}
      )
    );
    assert.equal(body.title, "Payments failing");
    assert.equal(body.message, "key=order-1; traceId=trace-9");
    assert.equal(body.state, "alerting");
    assert.equal(body.ruleId, "order-1");
    assert.equal(body.severity, undefined);
    assert.equal("severity" in body, false);
    // No credential ever enters the body.
    assert.equal(JSON.stringify(body).includes("apiKey"), false);
    assert.equal(JSON.stringify(body).includes("Authorization"), false);
    assert.equal(JSON.stringify(body).includes("Bearer"), false);
    assert.equal(JSON.stringify(body).includes("token"), false);
  });

  it("omits ruleId when the event carries no key, and falls the message back to the title text", () => {
    const body = JSON.parse(
      buildGrafanaOnCallAlertBody({ body: "{}", subject: "Payments failing" }, {})
    );
    assert.equal(body.title, "Payments failing");
    assert.equal(body.message, "Payments failing");
    assert.equal(body.state, "alerting");
    assert.equal(body.ruleId, undefined);
    assert.equal("ruleId" in body, false);
  });

  it("sends a configured status, including a per-record override, with the documented wire state", () => {
    const body = JSON.parse(
      buildGrafanaOnCallAlertBody(
        { body: '{"a":1}', subject: "Alert", key: "k1" },
        { status: "resolved" }
      )
    );
    assert.equal(body.state, "OK");
    assert.equal(body.ruleId, "k1");
    const overridden = JSON.parse(
      buildGrafanaOnCallAlertBody(
        { body: "{}", subject: "Alert", key: "k1", status: "firing" },
        { status: "resolved" }
      )
    );
    assert.equal(overridden.state, "alerting");
  });

  it("passes severity through verbatim when supplied, and omits it otherwise — no invented default", () => {
    const withSeverity = JSON.parse(
      buildGrafanaOnCallAlertBody(
        { body: "{}", subject: "Alert", key: "k1", severity: "critical" },
        {}
      )
    );
    assert.equal(withSeverity.severity, "critical");
    const withoutSeverity = JSON.parse(
      buildGrafanaOnCallAlertBody({ body: "{}", subject: "Alert", key: "k1" }, {})
    );
    assert.equal(withoutSeverity.severity, undefined);
    assert.equal("severity" in withoutSeverity, false);
    // No enum is enforced: an unlisted value passes through verbatim.
    const other = JSON.parse(
      buildGrafanaOnCallAlertBody(
        { body: "{}", subject: "Alert", key: "k1", severity: "warning" },
        {}
      )
    );
    assert.equal(other.severity, "warning");
  });

  it("rejects an empty record body", () => {
    assert.throws(() => resolveGrafanaOnCallRecord({ body: "" }, 0, {}), RangeError);
    assert.deepEqual(resolveGrafanaOnCallRecord({ body: "{}" }, 2, {}), { index: 2 });
  });

  it("rejects a bad per-record status value and a non-string or empty severity", () => {
    assert.throws(
      () => resolveGrafanaOnCallRecord({ body: "{}", status: "acknowledged" as never }, 0, {}),
      RangeError
    );
    assert.throws(
      () => resolveGrafanaOnCallRecord({ body: "{}", severity: "" }, 0, {}),
      RangeError
    );
    assert.throws(
      () => resolveGrafanaOnCallRecord({ body: "{}", severity: 5 as never }, 0, {}),
      RangeError
    );
  });

  it("rejects a resolved without a key — per-record override and config default alike", () => {
    assert.throws(
      () => resolveGrafanaOnCallRecord({ body: "{}", status: "resolved" }, 0, {}),
      RangeError
    );
    assert.throws(
      () => resolveGrafanaOnCallRecord({ body: "{}" }, 0, { status: "resolved" }),
      RangeError
    );
    // A keyed resolve passes validation.
    assert.deepEqual(resolveGrafanaOnCallRecord({ body: "{}", key: "k1", status: "resolved" }, 0, {}), { index: 0 });
    assert.deepEqual(resolveGrafanaOnCallRecord({ body: "{}", key: "k1" }, 0, { status: "resolved" }), { index: 0 });
  });

  it("does not reject a keyless firing — the key rule is for resolved only", () => {
    assert.deepEqual(resolveGrafanaOnCallRecord({ body: "{}" }, 0, {}), { index: 0 });
    assert.deepEqual(resolveGrafanaOnCallRecord({ body: "{}", status: "firing" }, 0, {}), { index: 0 });
  });
});

describe("grafana-oncall-sink failure mapping", () => {
  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed — including 400 and 404", () => {
    assert.equal(classifyGrafanaOnCallRecordFailure(429), true);
    assert.equal(classifyGrafanaOnCallRecordFailure(500), true);
    assert.equal(classifyGrafanaOnCallRecordFailure(503), true);
    assert.equal(classifyGrafanaOnCallRecordFailure(400), false);
    assert.equal(classifyGrafanaOnCallRecordFailure(401), false);
    assert.equal(classifyGrafanaOnCallRecordFailure(403), false);
    assert.equal(classifyGrafanaOnCallRecordFailure(404), false);
    assert.equal(classifyGrafanaOnCallRecordFailure(413), false);
    assert.equal(classifyGrafanaOnCallRecordFailure(422), false);
  });

  it("accepts any 2xx as an acceptance receipt — 200 is the documented success, the rest follow the 2xx rule", () => {
    assert.deepEqual(classifyGrafanaOnCallAlertResponse({ status: 200 }), { accepted: true });
    assert.deepEqual(classifyGrafanaOnCallAlertResponse({ status: 201 }), { accepted: true });
    assert.deepEqual(classifyGrafanaOnCallAlertResponse({ status: 204 }), { accepted: true });
    // A 3xx is not an acceptance: fail-closed.
    assert.deepEqual(classifyGrafanaOnCallAlertResponse({ status: 302 }), {
      accepted: false,
      errorCode: "HTTP_302",
      retryable: false,
    });
  });

  it("maps a non-2xx status to its HTTP code and lane, surfacing the client's error text", () => {
    assert.deepEqual(
      classifyGrafanaOnCallAlertResponse({ status: 429, errorMessage: "Rate limit exceeded" }),
      {
        accepted: false,
        errorCode: "HTTP_429",
        retryable: true,
        errorMessage: "Rate limit exceeded",
      }
    );
    assert.deepEqual(
      classifyGrafanaOnCallAlertResponse({ status: 400, errorMessage: "Invalid body" }),
      {
        accepted: false,
        errorCode: "HTTP_400",
        retryable: false,
        errorMessage: "Invalid body",
      }
    );
    assert.deepEqual(classifyGrafanaOnCallAlertResponse({ status: 404 }), {
      accepted: false,
      errorCode: "HTTP_404",
      retryable: false,
    });
    assert.deepEqual(
      classifyGrafanaOnCallAlertResponse({ status: 500, errorMessage: "Internal error" }),
      {
        accepted: false,
        errorCode: "HTTP_500",
        retryable: true,
        errorMessage: "Internal error",
      }
    );
  });
});

describe("grafana-oncall-sink send", () => {
  it("posts one alert per message with no URL and no credentials in the handed request", async () => {
    const client = new FakeClient();
    const sink = new GrafanaOnCallSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "Payments failing", key: "order-1", traceId: "trace-9" },
      { body: '{"b":2}', key: "order-2" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    const first = client.posts[0];
    // The integration webhook URL — token alike — is held
    // by the client alone: the sink hands over no URL at
    // all, so there is nothing to leak.
    assert.equal("url" in first, false);
    assert.equal(first.headers["Content-Type"], GRAFANA_ONCALL_JSON_CONTENT_TYPE);
    assert.equal(first.headers["Authorization"], undefined);
    assert.equal(first.headers["Idempotency-Key"], undefined);
    assert.deepEqual(Object.keys(first.headers), ["Content-Type"]);
    const body = JSON.parse(first.body);
    assert.equal(body.title, "Payments failing");
    assert.equal(body.message, "key=order-1; traceId=trace-9");
    assert.equal(body.state, "alerting");
    assert.equal(body.ruleId, "order-1");
    // No credential ever enters the handed request.
    assert.equal(JSON.stringify(first).includes("apiKey"), false);
    assert.equal(JSON.stringify(first).includes("Authorization"), false);
    assert.equal(JSON.stringify(first).includes("Bearer"), false);
    assert.equal(JSON.stringify(first).includes("token"), false);
    assert.equal(JSON.stringify(first).includes("grafana.net"), false);
    assert.equal(JSON.stringify(first).includes("integrations/v1"), false);
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("accepts a 201 as an acceptance receipt — the 2xx rule, with no receipt id claimed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 201);
    const sink = new GrafanaOnCallSink(baseConfig(client));
    const result = await sink.send([{ body: "{}", key: "k1" }]);
    assert.deepEqual(result, { ok: true, sent: 1 });
  });

  it("accepts a 200 without any receipt id — the status is the acceptance credential", async () => {
    const client = new FakeClient();
    const sink = new GrafanaOnCallSink(baseConfig(client));
    const result = await sink.send([{ body: "{}", key: "k1" }]);
    assert.deepEqual(result, { ok: true, sent: 1 });
  });

  it("throws with exactly the failed messages and their retry lanes", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 429);
    client.statusOn.set(2, 500);
    const sink = new GrafanaOnCallSink(baseConfig(client));
    await assert.rejects(
      sink.send([
        { body: "{}", key: "k1" },
        { body: "{}", key: "k2" },
        { body: "{}", key: "k3" },
      ]),
      (err: unknown) => {
        assert.ok(err instanceof GrafanaOnCallSinkError);
        assert.deepEqual(
          (err as GrafanaOnCallSinkError).failedRecords.map((f) => [f.index, f.errorCode, f.retryable]),
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
    const sink = new GrafanaOnCallSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as GrafanaOnCallSinkError).failedRecords;
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
    const sink = new GrafanaOnCallSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as GrafanaOnCallSinkError).failedRecords;
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
    const sink = new GrafanaOnCallSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as GrafanaOnCallSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(failed[0].retryable, true);
        assert.equal(failed[0].errorMessage, "socket hang up");
        return true;
      }
    );
  });

  it("throws a config error with no client, mapped non_retryable", async () => {
    const sink = new GrafanaOnCallSink({});
    await assert.rejects(sink.send([{ body: "{}", key: "k1" }]), GrafanaOnCallSinkConfigError);
    assert.equal(classifyFailure(new GrafanaOnCallSinkConfigError("no client injected")).failureClass, "non_retryable");
  });

  it("dry-runs with zero client I/O and untouched stats", async () => {
    const client = new FakeClient();
    const sink = new GrafanaOnCallSink(baseConfig(client, { dryRun: true }));
    const result = await sink.send([{ body: "{}", subject: "Payments failing" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("dry-runs still validate the config and the records, including the resolve key rule", async () => {
    const client = new FakeClient();
    const sink = new GrafanaOnCallSink(baseConfig(client, { dryRun: true }));
    await assert.rejects(sink.send([{ body: "" }]), RangeError);
    assert.equal(client.posts.length, 0);
    await assert.rejects(sink.send([{ body: "{}", status: "acknowledged" as never }]), RangeError);
    assert.equal(client.posts.length, 0);
    await assert.rejects(sink.send([{ body: "{}", status: "resolved" }]), RangeError);
    assert.equal(client.posts.length, 0);
    assert.throws(
      () => new GrafanaOnCallSink({ status: "acknowledged" as never, dryRun: true }),
      RangeError
    );
  });

  it("appends the payload body under the opt-in, truncated at the default 2000", async () => {
    const client = new FakeClient();
    const sink = new GrafanaOnCallSink(baseConfig(client, { includePayload: true, payloadMaxChars: 10 }));
    await sink.send([{ body: "0123456789ABCDEF", subject: "Alert", key: "k1" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.message, "key=k1\n\n0123456789… (truncated)");
    assert.equal(body.title, "Alert");

    const defaultClient = new FakeClient();
    const defaultSink = new GrafanaOnCallSink(baseConfig(defaultClient, { includePayload: true }));
    await defaultSink.send([{ body: "x".repeat(2001), subject: "Alert", key: "k1" }]);
    const defaultBody = JSON.parse(defaultClient.posts[0].body);
    assert.equal(defaultBody.message, `key=k1\n\n${"x".repeat(2000)}… (truncated)`);
  });

  it("omits the payload body by default — message carries the identifiers only", async () => {
    const client = new FakeClient();
    const sink = new GrafanaOnCallSink(baseConfig(client));
    await sink.send([{ body: '{"secret":"s3cr3t"}', subject: "Alert", key: "k1" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.message, "key=k1");
    assert.equal(JSON.stringify(body).includes("s3cr3t"), false);
  });

  it("sends a configured status and omits ruleId for a keyless firing", async () => {
    const client = new FakeClient();
    const sink = new GrafanaOnCallSink(baseConfig(client, { status: "firing" }));
    await sink.send([{ body: "{}", subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.state, "alerting");
    assert.equal(body.ruleId, undefined);
    assert.equal("ruleId" in body, false);
    assert.equal(body.message, "Alert");
  });

  it("sends a resolve with the same ruleId as a normal alert — Grafana OnCall resolves the group, the sink tracks nothing", async () => {
    const client = new FakeClient();
    const sink = new GrafanaOnCallSink(baseConfig(client));
    const result = await sink.send([
      { body: "{}", key: "k1", status: "firing" },
      { body: "{}", key: "k1", status: "resolved" },
    ]);
    // No sink-side suppression or state: both alerts go out
    // with the same rule id, and Grafana OnCall resolves the
    // alert group for the later one instead of creating a new one.
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    assert.equal(JSON.parse(client.posts[0].body).state, "alerting");
    assert.equal(JSON.parse(client.posts[1].body).state, "OK");
    assert.equal(JSON.parse(client.posts[1].body).ruleId, "k1");
    // The resolve still carries the derived title and a
    // non-empty message, keeping one uniform envelope.
    assert.equal(JSON.parse(client.posts[1].body).title, "k1");
    assert.equal(JSON.parse(client.posts[1].body).message, "key=k1");
  });

  it("falls back to 'webhook event' for a sourceless event, with a non-empty message", async () => {
    const client = new FakeClient();
    const sink = new GrafanaOnCallSink(baseConfig(client));
    await sink.send([{ body: "{}" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.state, "alerting");
    assert.equal(body.title, "webhook event");
    assert.equal(body.message, "webhook event");
    assert.equal(body.ruleId, undefined);
  });
});
