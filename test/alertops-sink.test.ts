import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  AlertOpsSink,
  AlertOpsSinkConfigError,
  AlertOpsSinkError,
  assertValidAlertOpsSinkConfig,
  buildAlertOpsAlertBody,
  classifyAlertOpsAlertResponse,
  classifyAlertOpsRecordFailure,
  resolveAlertOpsDescription,
  resolveAlertOpsRecord,
  resolveAlertOpsSourceStatus,
  resolveAlertOpsStatus,
  resolveAlertOpsSubject,
  truncateAlertOpsPayload,
  ALERTOPS_DEFAULT_FIRING_STATUS,
  ALERTOPS_DEFAULT_PAYLOAD_MAX_CHARS,
  ALERTOPS_DEFAULT_RESOLVED_STATUS,
  ALERTOPS_DEFAULT_STATUS,
  ALERTOPS_FALLBACK_TITLE,
  ALERTOPS_JSON_CONTENT_TYPE,
  ALERTOPS_STATUSES,
  type AlertOpsAlertClient,
  type AlertOpsAlertPostRequest,
  type AlertOpsAlertPostResponse,
  type AlertOpsSinkConfig,
} from "../src/alertops-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements AlertOpsAlertClient {
  posts: AlertOpsAlertPostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error text to return for that post. */
  errorOn = new Map<number, string>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: AlertOpsAlertPostRequest): Promise<AlertOpsAlertPostResponse> {
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
  client: AlertOpsAlertClient,
  extra: Partial<AlertOpsSinkConfig> = {}
): AlertOpsSinkConfig {
  return { client, ...extra };
}

function bodyOf(request: AlertOpsAlertPostRequest): Record<string, unknown> {
  return JSON.parse(request.body) as Record<string, unknown>;
}

describe("alertops-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidAlertOpsSinkConfig(null, "AlertOpsSink"), RangeError);
    assert.throws(() => assertValidAlertOpsSinkConfig("x", "AlertOpsSink"), RangeError);
  });

  it("rejects a malformed client, payloadMaxChars, and statusValues", () => {
    assert.throws(
      () => assertValidAlertOpsSinkConfig(baseConfig(new FakeClient(), { client: {} as never }), "AlertOpsSink"),
      RangeError
    );
    assert.throws(
      () => assertValidAlertOpsSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 0 }), "AlertOpsSink"),
      RangeError
    );
    assert.throws(
      () => assertValidAlertOpsSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 1.5 }), "AlertOpsSink"),
      RangeError
    );
    assert.throws(
      () =>
        assertValidAlertOpsSinkConfig(
          baseConfig(new FakeClient(), { statusValues: { firing: "" } }),
          "AlertOpsSink"
        ),
      RangeError
    );
    assert.throws(
      () =>
        assertValidAlertOpsSinkConfig(
          baseConfig(new FakeClient(), { statusValues: { resolved: 3 as never } }),
          "AlertOpsSink"
        ),
      RangeError
    );
    assert.throws(
      () =>
        assertValidAlertOpsSinkConfig(
          baseConfig(new FakeClient(), { statusValues: "open" as never }),
          "AlertOpsSink"
        ),
      RangeError
    );
  });

  it("accepts the documented default status values", () => {
    assert.equal(ALERTOPS_DEFAULT_FIRING_STATUS, "open");
    assert.equal(ALERTOPS_DEFAULT_RESOLVED_STATUS, "close");
    assert.equal(ALERTOPS_DEFAULT_STATUS, "firing");
    assert.deepEqual([...ALERTOPS_STATUSES], ["firing", "resolved"]);
    assert.equal(ALERTOPS_FALLBACK_TITLE, "webhook event");
    assert.equal(ALERTOPS_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
    assert.doesNotThrow(() =>
      assertValidAlertOpsSinkConfig(
        baseConfig(new FakeClient(), { statusValues: { firing: "triggered", resolved: "ok" } }),
        "AlertOpsSink"
      )
    );
  });
});

describe("alertops-sink subject derivation", () => {
  it("prefers subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveAlertOpsSubject({ body: "{}", subject: "disk full", key: "k-1", traceId: "t-1" }),
      "disk full"
    );
    assert.equal(resolveAlertOpsSubject({ body: "{}", key: "k-1", traceId: "t-1" }), "k-1");
    assert.equal(resolveAlertOpsSubject({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveAlertOpsSubject({ body: "{}" }), "webhook event");
    assert.equal(
      resolveAlertOpsSubject({ body: "{}", subject: "", key: "", traceId: "" }),
      "webhook event"
    );
  });

  it("does not truncate a long subject", () => {
    const long = "x".repeat(5000);
    assert.equal(resolveAlertOpsSubject({ body: "{}", subject: long }), long);
  });
});

describe("alertops-sink description derivation", () => {
  it("uses the key/traceId identifiers, falling back to the subject text", () => {
    assert.equal(
      resolveAlertOpsDescription({ body: "{}", subject: "disk full", key: "k-1", traceId: "t-1" }, {}),
      "key=k-1; traceId=t-1"
    );
    assert.equal(resolveAlertOpsDescription({ body: "{}", key: "k-1" }, {}), "key=k-1");
    assert.equal(resolveAlertOpsDescription({ body: "{}", traceId: "t-1" }, {}), "traceId=t-1");
    assert.equal(
      resolveAlertOpsDescription({ body: "{}", subject: "disk full" }, {}),
      "disk full"
    );
    assert.equal(resolveAlertOpsDescription({ body: "{}" }, {}), "webhook event");
  });

  it("appends the truncated payload only under the includePayload opt-in", () => {
    const record = { body: '{"a":1}', key: "k-1" };
    assert.equal(resolveAlertOpsDescription(record, {}), "key=k-1");
    assert.equal(
      resolveAlertOpsDescription(record, { includePayload: true }),
      'key=k-1\n\n{"a":1}'
    );
    const longBody = "x".repeat(3000);
    const appended = resolveAlertOpsDescription(
      { body: longBody, key: "k-1" },
      { includePayload: true }
    );
    assert.equal(appended, `key=k-1\n\n${"x".repeat(2000)}… (truncated)`);
    const custom = resolveAlertOpsDescription(
      { body: longBody, key: "k-1" },
      { includePayload: true, payloadMaxChars: 10 }
    );
    assert.equal(custom, `key=k-1\n\n${"x".repeat(10)}… (truncated)`);
  });

  it("truncates only past the limit, verbatim at or under it", () => {
    assert.equal(truncateAlertOpsPayload("abc", 3), "abc");
    assert.equal(truncateAlertOpsPayload("abcd", 3), "abc… (truncated)");
  });
});

describe("alertops-sink source status derivation", () => {
  it("defaults firing to open and resolved to close", () => {
    assert.equal(resolveAlertOpsSourceStatus({ body: "{}" }, {}), "open");
    assert.equal(
      resolveAlertOpsSourceStatus({ body: "{}", status: "firing" }, {}),
      "open"
    );
    assert.equal(
      resolveAlertOpsSourceStatus({ body: "{}", status: "resolved" }, {}),
      "close"
    );
  });

  it("sends configured status values verbatim, never re-cased", () => {
    const config = { statusValues: { firing: "triggered", resolved: "ok" } };
    assert.equal(resolveAlertOpsSourceStatus({ body: "{}" }, config), "triggered");
    assert.equal(
      resolveAlertOpsSourceStatus({ body: "{}", status: "resolved" }, config),
      "ok"
    );
    const mixed = { statusValues: { firing: "TRIGGERED" } };
    assert.equal(resolveAlertOpsSourceStatus({ body: "{}" }, mixed), "TRIGGERED");
    assert.equal(
      resolveAlertOpsSourceStatus({ body: "{}", status: "resolved" }, mixed),
      "close"
    );
  });

  it("rejects an unknown status, normalizing case", () => {
    assert.equal(resolveAlertOpsStatus({ body: "{}", status: "Firing" as never }), "firing");
    assert.equal(resolveAlertOpsStatus({ body: "{}", status: "Resolved" as never }), "resolved");
    assert.throws(() => resolveAlertOpsStatus({ body: "{}", status: "ack" as never }), RangeError);
    assert.throws(() => resolveAlertOpsStatus({ body: "{}", status: "" as never }), RangeError);
  });
});

describe("alertops-sink body building", () => {
  it("builds the source_id/source_status/subject/description envelope", () => {
    const built = JSON.parse(
      buildAlertOpsAlertBody(
        { body: "{}", subject: "disk full", key: "k-1", traceId: "t-1" },
        {}
      )
    ) as Record<string, unknown>;
    assert.deepEqual(built, {
      source_id: "k-1",
      source_status: "open",
      subject: "disk full",
      description: "key=k-1; traceId=t-1",
    });
  });

  it("omits source_id when the event carries no key, and never sends source", () => {
    const built = JSON.parse(
      buildAlertOpsAlertBody({ body: "{}", subject: "disk full" }, {})
    ) as Record<string, unknown>;
    assert.equal("source_id" in built, false);
    assert.equal("source" in built, false);
    assert.equal(built.source_status, "open");
    assert.equal(built.subject, "disk full");
    assert.equal(built.description, "disk full");
  });

  it("sends a resolved alert with the close value and the same source id", () => {
    const built = JSON.parse(
      buildAlertOpsAlertBody({ body: "{}", key: "k-1", status: "resolved" }, {})
    ) as Record<string, unknown>;
    assert.equal(built.source_id, "k-1");
    assert.equal(built.source_status, "close");
    assert.equal(built.subject, "k-1");
  });

  it("sends configured status values through the body builder", () => {
    const built = JSON.parse(
      buildAlertOpsAlertBody(
        { body: "{}", key: "k-1", status: "resolved" },
        { statusValues: { resolved: "ok" } }
      )
    ) as Record<string, unknown>;
    assert.equal(built.source_status, "ok");
  });
});

describe("alertops-sink record validation", () => {
  it("rejects an empty body string", () => {
    assert.throws(() => resolveAlertOpsRecord({ body: "" }, 0, {}), RangeError);
    assert.throws(() => resolveAlertOpsRecord({ body: 1 as never }, 0, {}), RangeError);
  });

  it("rejects a bad per-record status", () => {
    assert.throws(
      () => resolveAlertOpsRecord({ body: "{}", status: "ack" as never }, 0, {}),
      RangeError
    );
  });

  it("fails a keyless resolve closed — the close cannot match an open alert", () => {
    assert.throws(
      () => resolveAlertOpsRecord({ body: "{}", status: "resolved" }, 2, {}),
      /no source id to match an open alert/
    );
    assert.throws(
      () => resolveAlertOpsRecord({ body: "{}", key: "", status: "resolved" }, 2, {}),
      /no source id to match an open alert/
    );
    assert.doesNotThrow(() =>
      resolveAlertOpsRecord({ body: "{}", key: "k-1", status: "resolved" }, 2, {})
    );
    assert.doesNotThrow(() =>
      resolveAlertOpsRecord({ body: "{}", key: "k-1", status: "Resolved" as never }, 2, {})
    );
    assert.doesNotThrow(() => resolveAlertOpsRecord({ body: "{}", key: "k-1" }, 2, {}));
    assert.doesNotThrow(() => resolveAlertOpsRecord({ body: "{}" }, 2, {}));
  });
});

describe("alertops-sink failure classification", () => {
  it("accepts any 2xx status (tentative rule) and rejects the rest", () => {
    for (const status of [200, 201, 202, 204]) {
      assert.deepEqual(classifyAlertOpsAlertResponse({ status }), { accepted: true });
    }
    assert.deepEqual(classifyAlertOpsAlertResponse({ status: 400 }), {
      accepted: false,
      errorCode: "HTTP_400",
      retryable: false,
    });
    assert.deepEqual(classifyAlertOpsAlertResponse({ status: 401 }), {
      accepted: false,
      errorCode: "HTTP_401",
      retryable: false,
    });
    assert.deepEqual(classifyAlertOpsAlertResponse({ status: 404 }), {
      accepted: false,
      errorCode: "HTTP_404",
      retryable: false,
    });
  });

  it("maps 429 and 5xx to retryable and other 4xx to fail-closed", () => {
    assert.equal(classifyAlertOpsRecordFailure(429), true);
    assert.equal(classifyAlertOpsRecordFailure(500), true);
    assert.equal(classifyAlertOpsRecordFailure(503), true);
    assert.equal(classifyAlertOpsRecordFailure(400), false);
    assert.equal(classifyAlertOpsRecordFailure(401), false);
    assert.equal(classifyAlertOpsRecordFailure(404), false);
    assert.equal(classifyAlertOpsRecordFailure(422), false);
  });

  it("carries the client error text on a failure record, dropping an empty one", () => {
    assert.deepEqual(
      classifyAlertOpsAlertResponse({ status: 500, errorMessage: "boom" }),
      { accepted: false, errorCode: "HTTP_500", retryable: true, errorMessage: "boom" }
    );
    assert.deepEqual(
      classifyAlertOpsAlertResponse({ status: 400, errorMessage: "" }),
      { accepted: false, errorCode: "HTTP_400", retryable: false }
    );
  });
});

describe("alertops-sink send", () => {
  it("posts one alert per record with the exact headers and no URL or Authorization", async () => {
    const client = new FakeClient();
    const sink = new AlertOpsSink(baseConfig(client));
    const result = await sink.send([
      { body: "{}", subject: "disk full", key: "k-1", traceId: "t-1" },
      { body: "{}", key: "k-2" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    for (const post of client.posts) {
      assert.deepEqual(post.headers, { "Content-Type": ALERTOPS_JSON_CONTENT_TYPE });
      assert.equal("url" in post, false);
      assert.equal("Authorization" in post.headers, false);
      assert.equal(JSON.stringify(post).includes("alertops"), false);
    }
    assert.equal(bodyOf(client.posts[0]).subject, "disk full");
    assert.equal(bodyOf(client.posts[0]).source_id, "k-1");
    assert.equal(bodyOf(client.posts[0]).source_status, "open");
    assert.equal(bodyOf(client.posts[0]).description, "key=k-1; traceId=t-1");
    assert.equal(bodyOf(client.posts[1]).subject, "k-2");
    assert.equal(bodyOf(client.posts[1]).source_id, "k-2");
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("throws a config error with no client, mapped non_retryable by classifyFailure", async () => {
    const sink = new AlertOpsSink({});
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) => err instanceof AlertOpsSinkConfigError
    );
    assert.deepEqual(classifyFailure(new AlertOpsSinkConfigError("no client injected")), {
      failureClass: "non_retryable",
    });
  });

  it("throws carrying exactly the failed records with their retry lanes", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 400);
    client.statusOn.set(2, 429);
    client.errorOn.set(2, "rate limited");
    const sink = new AlertOpsSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([
          { body: "{}", key: "k-1" },
          { body: "{}", key: "k-2" },
          { body: "{}", key: "k-3" },
        ]),
      (err: unknown) => {
        assert.ok(err instanceof AlertOpsSinkError);
        assert.deepEqual(err.failedRecords, [
          { index: 1, errorCode: "HTTP_400", statusCode: 400, retryable: false },
          { index: 2, errorCode: "HTTP_429", statusCode: 429, retryable: true, errorMessage: "rate limited" },
        ]);
        return true;
      }
    );
    assert.deepEqual(sink.stats, { sent: 1, failed: 2, sendFailures: 1 });
  });

  it("maps a client throw to a retryable TRANSPORT_ERROR with the message", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hang up"));
    const sink = new AlertOpsSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: "{}", key: "k-1" }]),
      (err: unknown) => {
        assert.ok(err instanceof AlertOpsSinkError);
        assert.deepEqual(err.failedRecords, [
          { index: 0, errorCode: "TRANSPORT_ERROR", retryable: true, errorMessage: "socket hang up" },
        ]);
        return true;
      }
    );
  });

  it("sends a resolved alert with the close value and the same source id", async () => {
    const client = new FakeClient();
    const sink = new AlertOpsSink(baseConfig(client));
    await sink.send([{ body: "{}", key: "k-1", status: "resolved" }]);
    assert.equal(client.posts.length, 1);
    assert.equal(bodyOf(client.posts[0]).source_id, "k-1");
    assert.equal(bodyOf(client.posts[0]).source_status, "close");
  });

  it("sends configured status values for an integration that agreed another pair", async () => {
    const client = new FakeClient();
    const sink = new AlertOpsSink(
      baseConfig(client, { statusValues: { firing: "triggered", resolved: "ok" } })
    );
    await sink.send([
      { body: "{}", key: "k-1" },
      { body: "{}", key: "k-1", status: "resolved" },
    ]);
    assert.equal(bodyOf(client.posts[0]).source_status, "triggered");
    assert.equal(bodyOf(client.posts[1]).source_status, "ok");
  });

  it("validates a keyless resolve before any POST, even in dry-run mode", async () => {
    const client = new FakeClient();
    const sink = new AlertOpsSink(baseConfig(client, { dryRun: true }));
    await assert.rejects(
      () => sink.send([{ body: "{}", status: "resolved" }]),
      RangeError
    );
    assert.equal(client.posts.length, 0);
  });

  it("dry-run validates and performs zero client I/O with no stats change", async () => {
    const sink = new AlertOpsSink({ dryRun: true });
    const result = await sink.send([{ body: "{}", key: "k-1", status: "resolved" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(
      () => sink.send([{ body: "{}", status: "bogus" as never }]),
      RangeError
    );
  });
});
