import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  XMattersSink,
  XMattersSinkConfigError,
  XMattersSinkError,
  assertValidXMattersSinkConfig,
  buildXMattersAlertBody,
  classifyXMattersAlertResponse,
  classifyXMattersRecordFailure,
  resolveXMattersMessage,
  resolveXMattersPriority,
  resolveXMattersRecipients,
  resolveXMattersRecord,
  resolveXMattersStatus,
  resolveXMattersSummary,
  truncateXMattersPayload,
  XMATTERS_DEFAULT_PAYLOAD_MAX_CHARS,
  XMATTERS_DEFAULT_STATUS,
  XMATTERS_FALLBACK_TITLE,
  XMATTERS_JSON_CONTENT_TYPE,
  XMATTERS_PRIORITIES,
  XMATTERS_RECIPIENTS_PARAM,
  type XMattersAlertClient,
  type XMattersAlertPostRequest,
  type XMattersAlertPostResponse,
  type XMattersSinkConfig,
} from "../src/xmatters-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements XMattersAlertClient {
  posts: XMattersAlertPostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error text to return for that post. */
  errorOn = new Map<number, string>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: XMattersAlertPostRequest): Promise<XMattersAlertPostResponse> {
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
  client: XMattersAlertClient,
  extra: Partial<XMattersSinkConfig> = {}
): XMattersSinkConfig {
  return { client, ...extra };
}

function bodyOf(request: XMattersAlertPostRequest): Record<string, unknown> {
  return JSON.parse(request.body) as Record<string, unknown>;
}

describe("xmatters-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidXMattersSinkConfig(null, "XMattersSink"), RangeError);
    assert.throws(() => assertValidXMattersSinkConfig("x", "XMattersSink"), RangeError);
  });

  it("rejects a malformed client, payloadMaxChars, recipients, and priority", () => {
    assert.throws(
      () => assertValidXMattersSinkConfig(baseConfig(new FakeClient(), { client: {} as never }), "XMattersSink"),
      RangeError
    );
    assert.throws(
      () => assertValidXMattersSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 0 }), "XMattersSink"),
      RangeError
    );
    assert.throws(
      () => assertValidXMattersSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 1.5 }), "XMattersSink"),
      RangeError
    );
    assert.throws(
      () => assertValidXMattersSinkConfig(baseConfig(new FakeClient(), { recipients: "" }), "XMattersSink"),
      RangeError
    );
    assert.throws(
      () => assertValidXMattersSinkConfig(baseConfig(new FakeClient(), { recipients: 3 as never }), "XMattersSink"),
      RangeError
    );
    assert.throws(
      () => assertValidXMattersSinkConfig(baseConfig(new FakeClient(), { priority: "P1" as never }), "XMattersSink"),
      RangeError
    );
    assert.throws(
      () => assertValidXMattersSinkConfig(baseConfig(new FakeClient(), { priority: "urgent" as never }), "XMattersSink"),
      RangeError
    );
    assert.throws(
      () => assertValidXMattersSinkConfig(baseConfig(new FakeClient(), { priority: "" as never }), "XMattersSink"),
      RangeError
    );
  });

  it("accepts the three priorities", () => {
    for (const priority of XMATTERS_PRIORITIES) {
      assert.doesNotThrow(() =>
        assertValidXMattersSinkConfig(baseConfig(new FakeClient(), { priority }), "XMattersSink")
      );
    }
  });

  it("accepts mixed-case priorities (normalized to uppercase)", () => {
    assert.doesNotThrow(() =>
      assertValidXMattersSinkConfig(baseConfig(new FakeClient(), { priority: "high" as never }), "XMattersSink")
    );
    assert.doesNotThrow(() =>
      assertValidXMattersSinkConfig(baseConfig(new FakeClient(), { priority: "Medium" as never }), "XMattersSink")
    );
  });

  it("pins the recipients query parameter name (the trigger URL carries it)", () => {
    assert.equal(XMATTERS_RECIPIENTS_PARAM, "recipients");
  });
});

describe("xmatters-sink summary derivation", () => {
  it("prefers subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveXMattersSummary({ body: "{}", subject: "disk full", key: "k-1", traceId: "t-1" }),
      "disk full"
    );
    assert.equal(
      resolveXMattersSummary({ body: "{}", key: "k-1", traceId: "t-1" }),
      "k-1"
    );
    assert.equal(
      resolveXMattersSummary({ body: "{}", traceId: "t-1" }),
      "t-1"
    );
    assert.equal(
      resolveXMattersSummary({ body: "{}" }),
      XMATTERS_FALLBACK_TITLE
    );
  });

  it("skips empty-string values when deriving the summary", () => {
    assert.equal(
      resolveXMattersSummary({ body: "{}", subject: "", key: "", traceId: "t-1" }),
      "t-1"
    );
    assert.equal(
      resolveXMattersSummary({ body: "{}", subject: "", key: "", traceId: "" }),
      XMATTERS_FALLBACK_TITLE
    );
  });
});

describe("xmatters-sink recipients and priority resolution", () => {
  it("defaults to no recipients and no priority (both omitted from the body)", () => {
    assert.equal(resolveXMattersRecipients({ body: "{}" }, {}), undefined);
    assert.equal(resolveXMattersPriority({ body: "{}" }, {}), undefined);
  });

  it("prefers the per-record override over the config value", () => {
    assert.equal(
      resolveXMattersRecipients({ body: "{}", recipients: "oncall" }, { recipients: "teamrigel" }),
      "oncall"
    );
    assert.equal(
      resolveXMattersRecipients({ body: "{}" }, { recipients: "teamrigel, mmcbride" }),
      "teamrigel, mmcbride"
    );
    assert.equal(
      resolveXMattersPriority({ body: "{}", priority: "LOW" }, { priority: "HIGH" }),
      "LOW"
    );
    assert.equal(
      resolveXMattersPriority({ body: "{}" }, { priority: "MEDIUM" }),
      "MEDIUM"
    );
  });

  it("normalizes mixed-case priorities to uppercase (docs pin uppercase)", () => {
    assert.equal(
      resolveXMattersPriority({ body: "{}", priority: "high" as never }, {}),
      "HIGH"
    );
    assert.equal(
      resolveXMattersPriority({ body: "{}" }, { priority: "Medium" as never }),
      "MEDIUM"
    );
  });

  it("rejects a priority the trigger would not recognize", () => {
    assert.throws(() => resolveXMattersPriority({ body: "{}", priority: "urgent" as never }, {}), RangeError);
    assert.throws(() => resolveXMattersPriority({ body: "{}", priority: "P1" as never }, {}), RangeError);
  });

  it("rejects an empty recipients value", () => {
    assert.throws(() => resolveXMattersRecipients({ body: "{}", recipients: "" }, {}), RangeError);
    assert.throws(() => resolveXMattersRecipients({ body: "{}" }, { recipients: "" }), RangeError);
  });
});

describe("xmatters-sink status resolution", () => {
  it("defaults to firing", () => {
    assert.equal(resolveXMattersStatus({ body: "{}" }), XMATTERS_DEFAULT_STATUS);
    assert.equal(XMATTERS_DEFAULT_STATUS, "firing");
  });

  it("normalizes a resolved status to lowercase", () => {
    assert.equal(resolveXMattersStatus({ body: "{}", status: "Resolved" as never }), "resolved");
  });

  it("rejects a status the workflow has no meaning for", () => {
    assert.throws(() => resolveXMattersStatus({ body: "{}", status: "acked" as never }), RangeError);
    assert.throws(() => resolveXMattersStatus({ body: "{}", status: "open" as never }), RangeError);
  });
});

describe("xmatters-sink message derivation", () => {
  it("carries the key/traceId identifiers, falling back to the summary text", () => {
    assert.equal(
      resolveXMattersMessage({ body: "{}", key: "k-1", traceId: "t-1" }, {}),
      "key=k-1; traceId=t-1"
    );
    assert.equal(
      resolveXMattersMessage({ body: "{}", key: "k-1" }, {}),
      "key=k-1"
    );
    assert.equal(
      resolveXMattersMessage({ body: "{}", traceId: "t-1" }, {}),
      "traceId=t-1"
    );
    assert.equal(
      resolveXMattersMessage({ body: "{}", subject: "disk full" }, {}),
      "disk full"
    );
    assert.equal(
      resolveXMattersMessage({ body: "{}" }, {}),
      XMATTERS_FALLBACK_TITLE
    );
  });

  it("appends the payload only under the includePayload opt-in, truncated to the limit", () => {
    const record = { body: '{"a":1}', key: "k-1" };
    assert.equal(
      resolveXMattersMessage(record, { includePayload: true, payloadMaxChars: 4 }),
      "key=k-1\n\n{\"a\"… (truncated)"
    );
    assert.equal(
      resolveXMattersMessage(record, { includePayload: true }),
      `key=k-1\n\n${record.body}`
    );
    assert.equal(resolveXMattersMessage(record, {}), "key=k-1");
  });

  it("truncates a payload snippet at the default 2000 characters", () => {
    assert.equal(XMATTERS_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
    const long = "x".repeat(2001);
    assert.equal(truncateXMattersPayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
    assert.equal(truncateXMattersPayload("short", 2000), "short");
  });
});

describe("xmatters-sink body building", () => {
  it("builds the firing body with summary, message, recipients, and priority", () => {
    const parsed = JSON.parse(
      buildXMattersAlertBody(
        { body: "{}", subject: "disk full", key: "k-1", traceId: "t-1", recipients: "oncall", priority: "HIGH" },
        {}
      )
    ) as Record<string, unknown>;
    assert.deepEqual(parsed, {
      summary: "disk full",
      message: "key=k-1; traceId=t-1",
      recipients: "oncall",
      priority: "HIGH",
    });
  });

  it("matches the workflow page's sample shape (summary, message, recipients)", () => {
    const parsed = JSON.parse(
      buildXMattersAlertBody(
        { body: "{}", subject: "Enter the text you want to use as the summary of the alert notification", key: "k-1" },
        { recipients: "teamrigel, mmcbride" }
      )
    ) as Record<string, unknown>;
    assert.equal(parsed.summary, "Enter the text you want to use as the summary of the alert notification");
    assert.equal(parsed.message, "key=k-1");
    assert.equal(parsed.recipients, "teamrigel, mmcbride");
    assert.equal("priority" in parsed, false);
  });

  it("omits recipients and priority when neither the config nor the record sets them", () => {
    const parsed = JSON.parse(
      buildXMattersAlertBody({ body: "{}", subject: "disk full" }, {})
    ) as Record<string, unknown>;
    assert.equal("recipients" in parsed, false);
    assert.equal("priority" in parsed, false);
    assert.equal(parsed.summary, "disk full");
    assert.equal(parsed.message, "disk full");
  });

  it("never sends an id, dedup, or status field — the workflow accepts none", () => {
    const parsed = JSON.parse(
      buildXMattersAlertBody({ body: "{}", subject: "disk full", key: "k-1", traceId: "t-1" }, {})
    ) as Record<string, unknown>;
    assert.equal("id" in parsed, false);
    assert.equal("dedup_key" in parsed, false);
    assert.equal("status" in parsed, false);
    assert.equal("event_type" in parsed, false);
  });

  it("honours the config and per-record recipients and priority", () => {
    const withConfig = JSON.parse(
      buildXMattersAlertBody({ body: "{}", key: "k-1" }, { recipients: "teamrigel", priority: "HIGH" })
    ) as Record<string, unknown>;
    assert.equal(withConfig.recipients, "teamrigel");
    assert.equal(withConfig.priority, "HIGH");
    const withRecord = JSON.parse(
      buildXMattersAlertBody(
        { body: "{}", key: "k-1", recipients: "oncall", priority: "LOW" },
        { recipients: "teamrigel", priority: "HIGH" }
      )
    ) as Record<string, unknown>;
    assert.equal(withRecord.recipients, "oncall");
    assert.equal(withRecord.priority, "LOW");
  });
});

describe("xmatters-sink record validation", () => {
  it("rejects an empty body string", () => {
    assert.throws(() => resolveXMattersRecord({ body: "" }, 0, {}), RangeError);
    assert.throws(() => resolveXMattersRecord({ body: 1 as never }, 0, {}), RangeError);
  });

  it("rejects a bad per-record recipients or priority", () => {
    assert.throws(
      () => resolveXMattersRecord({ body: "{}", recipients: "" }, 0, {}),
      RangeError
    );
    assert.throws(
      () => resolveXMattersRecord({ body: "{}", priority: "urgent" as never }, 0, {}),
      RangeError
    );
    assert.throws(
      () => resolveXMattersRecord({ body: "{}", priority: "P1" as never }, 0, {}),
      RangeError
    );
  });

  it("fails a resolved record closed — the workflow payload carries no status field", () => {
    assert.throws(
      () => resolveXMattersRecord({ body: "{}", status: "resolved" }, 2, {}),
      /no status field/
    );
    assert.throws(
      () => resolveXMattersRecord({ body: "{}", key: "k-1", status: "Resolved" as never }, 2, {}),
      /no status field/
    );
    assert.doesNotThrow(() =>
      resolveXMattersRecord({ body: "{}", key: "k-1", status: "firing" }, 2, {})
    );
    assert.doesNotThrow(() => resolveXMattersRecord({ body: "{}", key: "k-1" }, 2, {}));
  });
});

describe("xmatters-sink failure classification", () => {
  it("accepts any 2xx status (tentative rule) and rejects the rest", () => {
    for (const status of [200, 201, 202, 204]) {
      assert.deepEqual(classifyXMattersAlertResponse({ status }), { accepted: true });
    }
    assert.deepEqual(classifyXMattersAlertResponse({ status: 400 }), {
      accepted: false,
      errorCode: "HTTP_400",
      retryable: false,
    });
    assert.deepEqual(classifyXMattersAlertResponse({ status: 401 }), {
      accepted: false,
      errorCode: "HTTP_401",
      retryable: false,
    });
    assert.deepEqual(classifyXMattersAlertResponse({ status: 404 }), {
      accepted: false,
      errorCode: "HTTP_404",
      retryable: false,
    });
  });

  it("maps 429 and 5xx to retryable and other 4xx to fail-closed", () => {
    assert.equal(classifyXMattersRecordFailure(429), true);
    assert.equal(classifyXMattersRecordFailure(500), true);
    assert.equal(classifyXMattersRecordFailure(503), true);
    assert.equal(classifyXMattersRecordFailure(400), false);
    assert.equal(classifyXMattersRecordFailure(401), false);
    assert.equal(classifyXMattersRecordFailure(404), false);
    assert.equal(classifyXMattersRecordFailure(422), false);
  });

  it("carries the client error text on a failure record, dropping an empty one", () => {
    assert.deepEqual(
      classifyXMattersAlertResponse({ status: 500, errorMessage: "boom" }),
      { accepted: false, errorCode: "HTTP_500", retryable: true, errorMessage: "boom" }
    );
    assert.deepEqual(
      classifyXMattersAlertResponse({ status: 400, errorMessage: "" }),
      { accepted: false, errorCode: "HTTP_400", retryable: false }
    );
  });
});

describe("xmatters-sink send", () => {
  it("posts one alert per record with the exact headers and no URL or Authorization", async () => {
    const client = new FakeClient();
    const sink = new XMattersSink(baseConfig(client, { recipients: "teamrigel, mmcbride" }));
    const result = await sink.send([
      { body: "{}", subject: "disk full", key: "k-1", traceId: "t-1" },
      { body: "{}", key: "k-2" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    for (const post of client.posts) {
      assert.deepEqual(post.headers, { "Content-Type": XMATTERS_JSON_CONTENT_TYPE });
      assert.equal("url" in post, false);
      assert.equal("Authorization" in post.headers, false);
      assert.equal(JSON.stringify(post).includes("xmatters"), false);
    }
    assert.equal(bodyOf(client.posts[0]).summary, "disk full");
    assert.equal(bodyOf(client.posts[0]).message, "key=k-1; traceId=t-1");
    assert.equal(bodyOf(client.posts[0]).recipients, "teamrigel, mmcbride");
    assert.equal(bodyOf(client.posts[1]).summary, "k-2");
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("throws a config error with no client, mapped non_retryable by classifyFailure", async () => {
    const sink = new XMattersSink({});
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) => err instanceof XMattersSinkConfigError
    );
    assert.deepEqual(classifyFailure(new XMattersSinkConfigError("no client injected")), {
      failureClass: "non_retryable",
    });
  });

  it("throws carrying exactly the failed records with their retry lanes", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 400);
    client.statusOn.set(2, 429);
    client.errorOn.set(2, "rate limited");
    const sink = new XMattersSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([
          { body: "{}", key: "k-1" },
          { body: "{}", key: "k-2" },
          { body: "{}", key: "k-3" },
        ]),
      (err: unknown) => {
        assert.ok(err instanceof XMattersSinkError);
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
    const sink = new XMattersSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: "{}", key: "k-1" }]),
      (err: unknown) => {
        assert.ok(err instanceof XMattersSinkError);
        assert.deepEqual(err.failedRecords, [
          { index: 0, errorCode: "TRANSPORT_ERROR", retryable: true, errorMessage: "socket hang up" },
        ]);
        return true;
      }
    );
  });

  it("validates a resolved record before any POST, even in dry-run mode", async () => {
    const client = new FakeClient();
    const sink = new XMattersSink(baseConfig(client, { dryRun: true }));
    await assert.rejects(
      () => sink.send([{ body: "{}", status: "resolved" }]),
      RangeError
    );
    assert.equal(client.posts.length, 0);
  });

  it("dry-run validates and performs zero client I/O with no stats change", async () => {
    const sink = new XMattersSink({ dryRun: true });
    const result = await sink.send([{ body: "{}", key: "k-1", priority: "HIGH" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(
      () => sink.send([{ body: "{}", priority: "nope" as never }]),
      RangeError
    );
  });

  it("sends a firing alert with recipients and priority", async () => {
    const client = new FakeClient();
    const sink = new XMattersSink(baseConfig(client));
    await sink.send([{ body: "{}", key: "k-1", recipients: "oncall", priority: "HIGH" }]);
    assert.equal(client.posts.length, 1);
    assert.equal(bodyOf(client.posts[0]).summary, "k-1");
    assert.equal(bodyOf(client.posts[0]).recipients, "oncall");
    assert.equal(bodyOf(client.posts[0]).priority, "HIGH");
  });
});
