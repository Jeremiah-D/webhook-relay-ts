import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  MagicBellSink,
  MagicBellSinkConfigError,
  MagicBellSinkError,
  assertValidMagicBellSinkConfig,
  buildMagicBellTriggerBody,
  classifyMagicBellRecordFailure,
  classifyMagicBellTriggerResponse,
  resolveMagicBellInput,
  resolveMagicBellRecord,
  resolveMagicBellSummary,
  resolveMagicBellWorkflowKey,
  truncateMagicBellPayload,
  MAGICBELL_API_BASE_URL,
  MAGICBELL_DEFAULT_PAYLOAD_MAX_CHARS,
  MAGICBELL_FALLBACK_SUMMARY,
  MAGICBELL_JSON_CONTENT_TYPE,
  MAGICBELL_RATE_LIMIT_BLOCK_SECONDS,
  MAGICBELL_RATE_LIMIT_PER_MINUTE_PER_IP,
  MAGICBELL_TRIGGER_URL,
  type MagicBellSinkConfig,
  type MagicBellTriggerClient,
  type MagicBellTriggerPostRequest,
  type MagicBellTriggerPostResponse,
} from "../src/magicbell-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status and run id per call. */
class FakeClient implements MagicBellTriggerClient {
  posts: MagicBellTriggerPostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → run id to return for that post. */
  runIdOn = new Map<number, string>();
  /** Call-count (0-based) → error messages to return for that post. */
  errorsOn = new Map<number, string[]>();
  /** Call-count (0-based) → body `message` to return for that post. */
  messageOn = new Map<number, string>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: MagicBellTriggerPostRequest): Promise<MagicBellTriggerPostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return {
      status: this.statusOn.get(n) ?? 201,
      runId: this.runIdOn.get(n) ?? `run-${n + 1}`,
      errors: this.errorsOn.get(n),
      message: this.messageOn.get(n),
    };
  }
}

function baseConfig(
  client: MagicBellTriggerClient,
  extra: Partial<MagicBellSinkConfig> = {}
): MagicBellSinkConfig {
  return { key: "integration.stripe.charge.succeeded", client, ...extra };
}

describe("magicbell-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidMagicBellSinkConfig(null, "MagicBellSink"), RangeError);
    assert.throws(() => assertValidMagicBellSinkConfig("x", "MagicBellSink"), RangeError);
  });

  it("requires a non-empty workflow key", () => {
    assert.throws(
      () => assertValidMagicBellSinkConfig({ client: new FakeClient() }, "MagicBellSink"),
      RangeError
    );
    assert.throws(
      () => assertValidMagicBellSinkConfig(baseConfig(new FakeClient(), { key: "" }), "MagicBellSink"),
      RangeError
    );
    assert.throws(
      () => assertValidMagicBellSinkConfig(baseConfig(new FakeClient(), { key: 7 as never }), "MagicBellSink"),
      RangeError
    );
    assert.equal(
      resolveMagicBellWorkflowKey("integration.stripe.charge.succeeded", "MagicBellSink"),
      "integration.stripe.charge.succeeded"
    );
    assertValidMagicBellSinkConfig(baseConfig(new FakeClient()), "MagicBellSink");
  });

  it("rejects a malformed client and payloadMaxChars", () => {
    assert.throws(
      () => assertValidMagicBellSinkConfig(baseConfig(new FakeClient(), { client: {} as never }), "MagicBellSink"),
      RangeError
    );
    assert.throws(
      () => assertValidMagicBellSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 0 }), "MagicBellSink"),
      RangeError
    );
    assert.throws(
      () => assertValidMagicBellSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 1.5 }), "MagicBellSink"),
      RangeError
    );
  });
});

describe("magicbell-sink resolvers", () => {
  it("uses the fixed trigger URL with no credential in it", () => {
    assert.equal(MAGICBELL_API_BASE_URL, "https://api.magicbell.com/v2");
    assert.equal(MAGICBELL_TRIGGER_URL, "https://api.magicbell.com/v2/workflows/runs");
    assert.equal(MAGICBELL_TRIGGER_URL.includes("Bearer"), false);
    assert.equal(MAGICBELL_TRIGGER_URL.includes("secret"), false);
    assert.equal(MAGICBELL_TRIGGER_URL.includes("integration.stripe"), false);
  });

  it("pins the documented rate limit: 500 req/min/IP, 429 block removed after 60s", () => {
    assert.equal(MAGICBELL_RATE_LIMIT_PER_MINUTE_PER_IP, 500);
    assert.equal(MAGICBELL_RATE_LIMIT_BLOCK_SECONDS, 60);
  });

  it("derives the summary from subject, key, then traceId", () => {
    assert.equal(resolveMagicBellSummary({ body: "{}", subject: "Price drop", key: "k", traceId: "t" }), "Price drop");
    assert.equal(resolveMagicBellSummary({ body: "{}", key: "order-1", traceId: "t" }), "order-1");
    assert.equal(resolveMagicBellSummary({ body: "{}", traceId: "trace-9" }), "trace-9");
    assert.equal(resolveMagicBellSummary({ body: "{}" }), MAGICBELL_FALLBACK_SUMMARY);
  });

  it("derives the input map with title from subject only and body from the chain", () => {
    assert.deepEqual(resolveMagicBellInput({ body: "{}", subject: "Price drop", key: "k" }, {}), {
      body: "Price drop",
      title: "Price drop",
    });
    // No subject: the title is omitted, the body falls back to the chain.
    assert.deepEqual(resolveMagicBellInput({ body: "{}", key: "order-1" }, {}), { body: "order-1" });
    assert.deepEqual(resolveMagicBellInput({ body: "{}" }, {}), { body: MAGICBELL_FALLBACK_SUMMARY });
  });

  it("appends eventBody only under the opt-in, truncated at the default 2000", () => {
    const withPayload = resolveMagicBellInput({ body: '{"a":1}', subject: "Price drop" }, { includePayload: true });
    assert.equal(withPayload.eventBody, '{"a":1}');
    assert.equal(MAGICBELL_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
    assert.equal(truncateMagicBellPayload("abcdef", 4), "abcd… (truncated)");
    assert.equal(truncateMagicBellPayload("abc", 4), "abc");
    const long = resolveMagicBellInput({ body: "x".repeat(2001), subject: "Alert" }, { includePayload: true });
    assert.equal(long.eventBody, `${"x".repeat(2000)}… (truncated)`);
    const short = resolveMagicBellInput({ body: "0123456789ABCDEF", subject: "Alert" }, { includePayload: true, payloadMaxChars: 10 });
    assert.equal(short.eventBody, "0123456789… (truncated)");
  });

  it("builds the trigger body with key and input only — no recipients envelope", () => {
    const body = JSON.parse(
      buildMagicBellTriggerBody("integration.stripe.charge.succeeded", { title: "Price drop", body: "Price drop" })
    );
    assert.equal(body.key, "integration.stripe.charge.succeeded");
    assert.deepEqual(body.input, { title: "Price drop", body: "Price drop" });
    assert.equal(body.input.eventBody, undefined);
    // No recipients envelope: recipients live inside the workflow's steps.
    assert.equal(body.recipients, undefined);
    assert.equal(body.to, undefined);
    assert.equal(body.workflow, undefined);
    // No credential ever enters the body.
    assert.equal(JSON.stringify(body).includes("Authorization"), false);
    assert.equal(JSON.stringify(body).includes("Bearer"), false);
    assert.equal(JSON.stringify(body).includes("secret"), false);
  });

  it("appends eventBody inside input under the opt-in", () => {
    const body = JSON.parse(
      buildMagicBellTriggerBody("w", { body: "Alert", eventBody: '{"a":1}' })
    );
    assert.equal(body.input.eventBody, '{"a":1}');
    assert.equal(typeof body.input.eventBody, "string");
  });

  it("rejects an empty record body", () => {
    assert.throws(() => resolveMagicBellRecord({ body: "" }, 0), RangeError);
    assert.deepEqual(resolveMagicBellRecord({ body: "{}" }, 2), { index: 2 });
  });
});

describe("magicbell-sink failure mapping", () => {
  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", () => {
    assert.equal(classifyMagicBellRecordFailure(429), true);
    assert.equal(classifyMagicBellRecordFailure(500), true);
    assert.equal(classifyMagicBellRecordFailure(503), true);
    assert.equal(classifyMagicBellRecordFailure(400), false);
    assert.equal(classifyMagicBellRecordFailure(401), false);
    assert.equal(classifyMagicBellRecordFailure(403), false);
    assert.equal(classifyMagicBellRecordFailure(404), false);
    assert.equal(classifyMagicBellRecordFailure(201), false);
  });

  it("accepts a 2xx carrying a run id, on 200 and on 201", () => {
    assert.deepEqual(classifyMagicBellTriggerResponse({ status: 201, runId: "run-abc" }), { accepted: true });
    assert.deepEqual(classifyMagicBellTriggerResponse({ status: 200, runId: "run-abc" }), { accepted: true });
  });

  it("rejects a 2xx whose body carries no run id", () => {
    assert.deepEqual(classifyMagicBellTriggerResponse({ status: 201 }), {
      accepted: false,
      errorCode: "MAGICBELL_NO_RUN_ID",
      retryable: false,
    });
    assert.deepEqual(classifyMagicBellTriggerResponse({ status: 200, runId: "" }), {
      accepted: false,
      errorCode: "MAGICBELL_NO_RUN_ID",
      retryable: false,
    });
  });

  it("maps a non-2xx status to its HTTP code and lane, surfacing the docs' errors array", () => {
    assert.deepEqual(
      classifyMagicBellTriggerResponse({ status: 429, errors: ["rate limit exceeded"] }),
      {
        accepted: false,
        errorCode: "HTTP_429",
        retryable: true,
        errorMessage: "rate limit exceeded",
      }
    );
    assert.deepEqual(classifyMagicBellTriggerResponse({ status: 403 }), {
      accepted: false,
      errorCode: "HTTP_403",
      retryable: false,
    });
    assert.deepEqual(
      classifyMagicBellTriggerResponse({ status: 400, errors: ["key is required"], message: "bad request" }),
      {
        accepted: false,
        errorCode: "HTTP_400",
        retryable: false,
        errorMessage: "key is required; bad request",
      }
    );
    assert.deepEqual(
      classifyMagicBellTriggerResponse({ status: 401, errors: ["invalid_jwt_format"], message: "expected authorization header format: Bearer <token>" }),
      {
        accepted: false,
        errorCode: "HTTP_401",
        retryable: false,
        errorMessage: "invalid_jwt_format; expected authorization header format: Bearer <token>",
      }
    );
  });
});

describe("magicbell-sink send", () => {
  it("posts one trigger per message with no credentials and no Idempotency-Key header", async () => {
    const client = new FakeClient();
    const sink = new MagicBellSink(baseConfig(client));
    const result = await sink.send([
      { body: '{"a":1}', subject: "Price drop", key: "order-1" },
      { body: '{"b":2}', key: "order-2" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2, runIds: ["run-1", "run-2"] });
    assert.equal(client.posts.length, 2);
    const first = client.posts[0];
    assert.equal(first.url, "https://api.magicbell.com/v2/workflows/runs");
    assert.equal(first.headers["Content-Type"], MAGICBELL_JSON_CONTENT_TYPE);
    assert.equal(first.headers["Authorization"], undefined);
    // The docs do not verify Idempotency-Key for this
    // endpoint, so the sink deliberately sends none.
    assert.equal(first.headers["Idempotency-Key"], undefined);
    assert.deepEqual(Object.keys(first.headers), ["Content-Type"]);
    const body = JSON.parse(first.body);
    assert.equal(body.key, "integration.stripe.charge.succeeded");
    assert.deepEqual(body.input, { title: "Price drop", body: "Price drop" });
    assert.equal(body.input.eventBody, undefined);
    assert.equal(body.recipients, undefined);
    // No credential ever enters the handed request.
    assert.equal(JSON.stringify(first).includes("Authorization"), false);
    assert.equal(JSON.stringify(first).includes("Bearer"), false);
    assert.equal(JSON.stringify(first).includes("secret"), false);
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("accepts a 200 carrying a run id as acceptance", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 200);
    client.runIdOn.set(0, "run-xyz");
    const sink = new MagicBellSink(baseConfig(client));
    const result = await sink.send([{ body: "{}", key: "k1" }]);
    assert.deepEqual(result, { ok: true, sent: 1, runIds: ["run-xyz"] });
    assert.deepEqual(sink.stats, { sent: 1, failed: 0, sendFailures: 0 });
  });

  it("treats a 2xx without a run id as a fail-closed failure", async () => {
    const client = new FakeClient();
    client.runIdOn.set(0, "");
    const sink = new MagicBellSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as MagicBellSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "MAGICBELL_NO_RUN_ID");
        assert.equal(failed[0].statusCode, undefined);
        assert.equal(failed[0].retryable, false);
        return true;
      }
    );
  });

  it("throws with exactly the failed messages and their retry lanes", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 429);
    client.statusOn.set(2, 503);
    const sink = new MagicBellSink(baseConfig(client));
    await assert.rejects(
      sink.send([
        { body: "{}", key: "k1" },
        { body: "{}", key: "k2" },
        { body: "{}", key: "k3" },
      ]),
      (err: unknown) => {
        assert.ok(err instanceof MagicBellSinkError);
        assert.deepEqual(
          (err as MagicBellSinkError).failedRecords.map((f) => [f.index, f.errorCode, f.retryable]),
          [
            [1, "HTTP_429", true],
            [2, "HTTP_503", true],
          ]
        );
        return true;
      }
    );
    assert.deepEqual(sink.stats, { sent: 1, failed: 2, sendFailures: 1 });
  });

  it("treats a bad key (400) as fail-closed, surfacing the body's errors array", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 400);
    client.errorsOn.set(0, ["key is required"]);
    const sink = new MagicBellSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as MagicBellSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_400");
        assert.equal(failed[0].statusCode, 400);
        assert.equal(failed[0].retryable, false);
        assert.equal(failed[0].errorMessage, "key is required");
        return true;
      }
    );
  });

  it("treats a bad Project JWT (401) and insufficient permissions (403) as fail-closed", async () => {
    const client401 = new FakeClient();
    client401.statusOn.set(0, 401);
    client401.errorsOn.set(0, ["invalid_jwt_format"]);
    const sink401 = new MagicBellSink(baseConfig(client401));
    await assert.rejects(
      sink401.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        assert.equal((err as MagicBellSinkError).failedRecords[0].retryable, false);
        assert.equal((err as MagicBellSinkError).failedRecords[0].errorMessage, "invalid_jwt_format");
        return true;
      }
    );
    const client403 = new FakeClient();
    client403.statusOn.set(0, 403);
    const sink403 = new MagicBellSink(baseConfig(client403));
    await assert.rejects(
      sink403.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        assert.equal((err as MagicBellSinkError).failedRecords[0].errorCode, "HTTP_403");
        assert.equal((err as MagicBellSinkError).failedRecords[0].retryable, false);
        return true;
      }
    );
  });

  it("treats an unknown workflow (404) as fail-closed", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 404);
    const sink = new MagicBellSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as MagicBellSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "HTTP_404");
        assert.equal(failed[0].statusCode, 404);
        assert.equal(failed[0].retryable, false);
        return true;
      }
    );
  });

  it("treats a client throw as a retryable transport failure", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hang up"));
    const sink = new MagicBellSink(baseConfig(client));
    await assert.rejects(
      sink.send([{ body: "{}", key: "k1" }]),
      (err: unknown) => {
        const failed = (err as MagicBellSinkError).failedRecords;
        assert.equal(failed[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(failed[0].retryable, true);
        assert.equal(failed[0].errorMessage, "socket hang up");
        return true;
      }
    );
  });

  it("throws a config error with no client, mapped non_retryable", async () => {
    const sink = new MagicBellSink({ key: "integration.stripe.charge.succeeded" });
    await assert.rejects(sink.send([{ body: "{}", key: "k1" }]), MagicBellSinkConfigError);
    assert.equal(classifyFailure(new MagicBellSinkConfigError("no client injected")).failureClass, "non_retryable");
  });

  it("dry-runs with zero client I/O and untouched stats", async () => {
    const client = new FakeClient();
    const sink = new MagicBellSink(baseConfig(client, { dryRun: true }));
    const result = await sink.send([{ body: "{}", subject: "Price drop" }]);
    assert.deepEqual(result, { ok: true, sent: 0, runIds: [], dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("dry-runs still validate the config and the records", async () => {
    const client = new FakeClient();
    const sink = new MagicBellSink(baseConfig(client, { dryRun: true }));
    await assert.rejects(sink.send([{ body: "" }]), RangeError);
    assert.equal(client.posts.length, 0);
    assert.throws(
      () => new MagicBellSink({ key: "", dryRun: true }),
      RangeError
    );
  });

  it("appends eventBody under the opt-in, truncated at the default 2000", async () => {
    const client = new FakeClient();
    const sink = new MagicBellSink(baseConfig(client, { includePayload: true, payloadMaxChars: 10 }));
    await sink.send([{ body: "0123456789ABCDEF", subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.input.eventBody, "0123456789… (truncated)");
    assert.equal(body.input.body, "Alert");

    const defaultClient = new FakeClient();
    const defaultSink = new MagicBellSink(baseConfig(defaultClient, { includePayload: true }));
    await defaultSink.send([{ body: "x".repeat(2001), subject: "Alert" }]);
    const defaultBody = JSON.parse(defaultClient.posts[0].body);
    assert.equal(defaultBody.input.eventBody, `${"x".repeat(2000)}… (truncated)`);
  });

  it("omits eventBody by default", async () => {
    const client = new FakeClient();
    const sink = new MagicBellSink(baseConfig(client));
    await sink.send([{ body: '{"secret":"s3cr3t"}', subject: "Alert" }]);
    const body = JSON.parse(client.posts[0].body);
    assert.equal(body.input.body, "Alert");
    assert.equal(body.input.eventBody, undefined);
    assert.equal(JSON.stringify(body).includes("s3cr3t"), false);
  });

  it("collects run ids in send order across messages", async () => {
    const client = new FakeClient();
    client.runIdOn.set(0, "run-first");
    client.runIdOn.set(1, "run-second");
    const sink = new MagicBellSink(baseConfig(client));
    const result = await sink.send([
      { body: "{}", key: "k1" },
      { body: "{}", key: "k2" },
    ]);
    assert.deepEqual(result.runIds, ["run-first", "run-second"]);
  });
});
