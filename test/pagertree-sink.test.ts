import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  PagerTreeSink,
  PagerTreeSinkConfigError,
  PagerTreeSinkError,
  assertValidPagerTreeSinkConfig,
  buildPagerTreeAlertBody,
  classifyPagerTreeAlertResponse,
  classifyPagerTreeRecordFailure,
  resolvePagerTreeDescription,
  resolvePagerTreeEventType,
  resolvePagerTreeRecord,
  resolvePagerTreeTitle,
  resolvePagerTreeUrgency,
  truncatePagerTreePayload,
  PAGERTREE_DEFAULT_EVENT_TYPE,
  PAGERTREE_DEFAULT_PAYLOAD_MAX_CHARS,
  PAGERTREE_DEFAULT_URGENCY,
  PAGERTREE_EVENT_TYPES,
  PAGERTREE_FALLBACK_TITLE,
  PAGERTREE_INTEGRATION_URL_TEMPLATE,
  PAGERTREE_JSON_CONTENT_TYPE,
  PAGERTREE_RESOLVED_EVENT_TYPE,
  PAGERTREE_URGENCIES,
  type PagerTreeAlertClient,
  type PagerTreeAlertPostRequest,
  type PagerTreeAlertPostResponse,
  type PagerTreeSinkConfig,
} from "../src/pagertree-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements PagerTreeAlertClient {
  posts: PagerTreeAlertPostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error text to return for that post. */
  errorOn = new Map<number, string>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: PagerTreeAlertPostRequest): Promise<PagerTreeAlertPostResponse> {
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
  client: PagerTreeAlertClient,
  extra: Partial<PagerTreeSinkConfig> = {}
): PagerTreeSinkConfig {
  return { client, ...extra };
}

function bodyOf(request: PagerTreeAlertPostRequest): Record<string, unknown> {
  return JSON.parse(request.body) as Record<string, unknown>;
}

describe("pagertree-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidPagerTreeSinkConfig(null, "PagerTreeSink"), RangeError);
    assert.throws(() => assertValidPagerTreeSinkConfig("x", "PagerTreeSink"), RangeError);
  });

  it("rejects a malformed client, payloadMaxChars, eventType, and urgency", () => {
    assert.throws(
      () => assertValidPagerTreeSinkConfig(baseConfig(new FakeClient(), { client: {} as never }), "PagerTreeSink"),
      RangeError
    );
    assert.throws(
      () => assertValidPagerTreeSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 0 }), "PagerTreeSink"),
      RangeError
    );
    assert.throws(
      () => assertValidPagerTreeSinkConfig(baseConfig(new FakeClient(), { payloadMaxChars: 1.5 }), "PagerTreeSink"),
      RangeError
    );
    assert.throws(
      () => assertValidPagerTreeSinkConfig(baseConfig(new FakeClient(), { eventType: "trigger" as never }), "PagerTreeSink"),
      RangeError
    );
    assert.throws(
      () => assertValidPagerTreeSinkConfig(baseConfig(new FakeClient(), { eventType: "" as never }), "PagerTreeSink"),
      RangeError
    );
    assert.throws(
      () => assertValidPagerTreeSinkConfig(baseConfig(new FakeClient(), { urgency: "urgent" as never }), "PagerTreeSink"),
      RangeError
    );
    assert.throws(
      () => assertValidPagerTreeSinkConfig(baseConfig(new FakeClient(), { urgency: "sev1" as never }), "PagerTreeSink"),
      RangeError
    );
    assert.throws(
      () => assertValidPagerTreeSinkConfig(baseConfig(new FakeClient(), { urgency: "" as never }), "PagerTreeSink"),
      RangeError
    );
  });

  it("accepts the four event types and the four urgencies", () => {
    for (const eventType of PAGERTREE_EVENT_TYPES) {
      assert.doesNotThrow(() =>
        assertValidPagerTreeSinkConfig(baseConfig(new FakeClient(), { eventType }), "PagerTreeSink")
      );
    }
    for (const urgency of PAGERTREE_URGENCIES) {
      assert.doesNotThrow(() =>
        assertValidPagerTreeSinkConfig(baseConfig(new FakeClient(), { urgency }), "PagerTreeSink")
      );
    }
  });

  it("accepts mixed-case event types and urgencies (normalized to lowercase)", () => {
    assert.doesNotThrow(() =>
      assertValidPagerTreeSinkConfig(baseConfig(new FakeClient(), { eventType: "CREATE" as never }), "PagerTreeSink")
    );
    assert.doesNotThrow(() =>
      assertValidPagerTreeSinkConfig(baseConfig(new FakeClient(), { urgency: "High" as never }), "PagerTreeSink")
    );
  });

  it("pins the webhook integration URL template (integration_id in the path)", () => {
    assert.equal(
      PAGERTREE_INTEGRATION_URL_TEMPLATE,
      "https://api.pagertree.com/integration/{integration_id}"
    );
  });
});

describe("pagertree-sink title derivation", () => {
  it("prefers subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolvePagerTreeTitle({ body: "{}", subject: "disk full", key: "k-1", traceId: "t-1" }),
      "disk full"
    );
    assert.equal(
      resolvePagerTreeTitle({ body: "{}", key: "k-1", traceId: "t-1" }),
      "k-1"
    );
    assert.equal(
      resolvePagerTreeTitle({ body: "{}", traceId: "t-1" }),
      "t-1"
    );
    assert.equal(
      resolvePagerTreeTitle({ body: "{}" }),
      PAGERTREE_FALLBACK_TITLE
    );
  });

  it("skips empty-string values when deriving the title", () => {
    assert.equal(
      resolvePagerTreeTitle({ body: "{}", subject: "", key: "", traceId: "t-1" }),
      "t-1"
    );
    assert.equal(
      resolvePagerTreeTitle({ body: "{}", subject: "", key: "", traceId: "" }),
      PAGERTREE_FALLBACK_TITLE
    );
  });
});

describe("pagertree-sink event type and urgency resolution", () => {
  it("defaults to create / critical", () => {
    assert.equal(resolvePagerTreeEventType({ body: "{}" }, {}), PAGERTREE_DEFAULT_EVENT_TYPE);
    assert.equal(resolvePagerTreeUrgency({ body: "{}" }, {}), PAGERTREE_DEFAULT_URGENCY);
    assert.equal(PAGERTREE_DEFAULT_EVENT_TYPE, "create");
    assert.equal(PAGERTREE_DEFAULT_URGENCY, "critical");
  });

  it("prefers the per-record override over the config value", () => {
    assert.equal(
      resolvePagerTreeEventType({ body: "{}", eventType: "resolve" }, { eventType: "update" }),
      "resolve"
    );
    assert.equal(
      resolvePagerTreeEventType({ body: "{}" }, { eventType: "acknowledge" }),
      "acknowledge"
    );
    assert.equal(
      resolvePagerTreeUrgency({ body: "{}", urgency: "low" }, { urgency: "high" }),
      "low"
    );
    assert.equal(
      resolvePagerTreeUrgency({ body: "{}" }, { urgency: "medium" }),
      "medium"
    );
  });

  it("normalizes mixed-case event types and urgencies to lowercase (adapter tolerance)", () => {
    assert.equal(
      resolvePagerTreeEventType({ body: "{}", eventType: "Create" as never }, {}),
      "create"
    );
    assert.equal(
      resolvePagerTreeEventType({ body: "{}" }, { eventType: "RESOLVE" as never }),
      "resolve"
    );
    assert.equal(
      resolvePagerTreeUrgency({ body: "{}", urgency: "Critical" as never }, {}),
      "critical"
    );
    assert.equal(
      resolvePagerTreeUrgency({ body: "{}" }, { urgency: "HIGH" as never }),
      "high"
    );
  });

  it("rejects an event type or urgency the adapter would not recognize", () => {
    assert.throws(() => resolvePagerTreeEventType({ body: "{}", eventType: "trigger" as never }, {}), RangeError);
    assert.throws(() => resolvePagerTreeEventType({ body: "{}", eventType: "other" as never }, {}), RangeError);
    assert.throws(() => resolvePagerTreeUrgency({ body: "{}", urgency: "urgent" as never }, {}), RangeError);
    assert.throws(() => resolvePagerTreeUrgency({ body: "{}", urgency: "p1" as never }, {}), RangeError);
  });
});

describe("pagertree-sink description derivation", () => {
  it("carries the key/traceId identifiers, falling back to the title text", () => {
    assert.equal(
      resolvePagerTreeDescription({ body: "{}", key: "k-1", traceId: "t-1" }, {}),
      "key=k-1; traceId=t-1"
    );
    assert.equal(
      resolvePagerTreeDescription({ body: "{}", key: "k-1" }, {}),
      "key=k-1"
    );
    assert.equal(
      resolvePagerTreeDescription({ body: "{}", traceId: "t-1" }, {}),
      "traceId=t-1"
    );
    assert.equal(
      resolvePagerTreeDescription({ body: "{}", subject: "disk full" }, {}),
      "disk full"
    );
    assert.equal(
      resolvePagerTreeDescription({ body: "{}" }, {}),
      PAGERTREE_FALLBACK_TITLE
    );
  });

  it("appends the payload only under the includePayload opt-in, truncated to the limit", () => {
    const record = { body: '{"a":1}', key: "k-1" };
    assert.equal(
      resolvePagerTreeDescription(record, { includePayload: true, payloadMaxChars: 4 }),
      "key=k-1\n\n{\"a\"… (truncated)"
    );
    assert.equal(
      resolvePagerTreeDescription(record, { includePayload: true }),
      `key=k-1\n\n${record.body}`
    );
    assert.equal(resolvePagerTreeDescription(record, {}), "key=k-1");
  });

  it("truncates a payload snippet at the default 2000 characters", () => {
    assert.equal(PAGERTREE_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
    const long = "x".repeat(2001);
    assert.equal(truncatePagerTreePayload(long, 2000), `${"x".repeat(2000)}… (truncated)`);
    assert.equal(truncatePagerTreePayload("short", 2000), "short");
  });
});

describe("pagertree-sink body building", () => {
  it("builds the firing body with create, id, title, description, and critical urgency", () => {
    const parsed = JSON.parse(
      buildPagerTreeAlertBody({ body: "{}", subject: "disk full", key: "k-1", traceId: "t-1" }, {})
    ) as Record<string, unknown>;
    assert.deepEqual(parsed, {
      event_type: "create",
      id: "k-1",
      title: "disk full",
      description: "key=k-1; traceId=t-1",
      urgency: "critical",
    });
  });

  it("omits id when the event carries no key and never sends tags, meta, or dedup_keys", () => {
    const parsed = JSON.parse(
      buildPagerTreeAlertBody({ body: "{}", subject: "disk full" }, {})
    ) as Record<string, unknown>;
    assert.equal("id" in parsed, false);
    assert.equal(parsed.title, "disk full");
    assert.equal(parsed.description, "disk full");
    assert.equal("tags" in parsed, false);
    assert.equal("meta" in parsed, false);
    assert.equal("dedup_keys" in parsed, false);
  });

  it("honours the config and per-record event type and urgency", () => {
    const withConfig = JSON.parse(
      buildPagerTreeAlertBody({ body: "{}", key: "k-1" }, { eventType: "update", urgency: "high" })
    ) as Record<string, unknown>;
    assert.equal(withConfig.event_type, "update");
    assert.equal(withConfig.urgency, "high");
    const withRecord = JSON.parse(
      buildPagerTreeAlertBody(
        { body: "{}", key: "k-1", eventType: "acknowledge", urgency: "low" },
        { eventType: "update", urgency: "high" }
      )
    ) as Record<string, unknown>;
    assert.equal(withRecord.event_type, "acknowledge");
    assert.equal(withRecord.urgency, "low");
  });

  it("sends resolve with the same id and keeps the uniform envelope", () => {
    const parsed = JSON.parse(
      buildPagerTreeAlertBody(
        { body: "{}", key: "k-1", eventType: "resolve", urgency: "medium" },
        { eventType: "create", urgency: "critical" }
      )
    ) as Record<string, unknown>;
    assert.equal(parsed.event_type, PAGERTREE_RESOLVED_EVENT_TYPE);
    assert.equal(parsed.event_type, "resolve");
    assert.equal(parsed.id, "k-1");
    assert.equal(parsed.title, "k-1");
    assert.equal(parsed.description, "key=k-1");
    assert.equal(parsed.urgency, "medium");
  });

  it("sends resolve when the config event type is resolve", () => {
    const parsed = JSON.parse(
      buildPagerTreeAlertBody({ body: "{}", key: "k-1" }, { eventType: "resolve" })
    ) as Record<string, unknown>;
    assert.equal(parsed.event_type, "resolve");
  });
});

describe("pagertree-sink record validation", () => {
  it("rejects an empty body string", () => {
    assert.throws(() => resolvePagerTreeRecord({ body: "" }, 0, {}), RangeError);
    assert.throws(() => resolvePagerTreeRecord({ body: 1 as never }, 0, {}), RangeError);
  });

  it("rejects a bad per-record eventType or urgency", () => {
    assert.throws(
      () => resolvePagerTreeRecord({ body: "{}", eventType: "trigger" as never }, 0, {}),
      RangeError
    );
    assert.throws(
      () => resolvePagerTreeRecord({ body: "{}", eventType: "other" as never }, 0, {}),
      RangeError
    );
    assert.throws(
      () => resolvePagerTreeRecord({ body: "{}", urgency: "urgent" as never }, 0, {}),
      RangeError
    );
    assert.throws(
      () => resolvePagerTreeRecord({ body: "{}", urgency: "P1" as never }, 0, {}),
      RangeError
    );
  });

  it("fails a keyless resolve closed, whether the event type comes from the record or the config", () => {
    assert.throws(
      () => resolvePagerTreeRecord({ body: "{}", eventType: "resolve" }, 2, {}),
      /requires `key`/
    );
    assert.throws(
      () => resolvePagerTreeRecord({ body: "{}", traceId: "t-1", eventType: "resolve" }, 2, {}),
      /requires `key`/
    );
    assert.throws(
      () => resolvePagerTreeRecord({ body: "{}" }, 2, { eventType: "resolve" }),
      /requires `key`/
    );
    assert.doesNotThrow(() =>
      resolvePagerTreeRecord({ body: "{}", key: "k-1", eventType: "resolve" }, 2, {})
    );
  });
});

describe("pagertree-sink failure classification", () => {
  it("accepts any 2xx status (tentative rule) and rejects the rest", () => {
    for (const status of [200, 201, 202, 204]) {
      assert.deepEqual(classifyPagerTreeAlertResponse({ status }), { accepted: true });
    }
    assert.deepEqual(classifyPagerTreeAlertResponse({ status: 400 }), {
      accepted: false,
      errorCode: "HTTP_400",
      retryable: false,
    });
    assert.deepEqual(classifyPagerTreeAlertResponse({ status: 404 }), {
      accepted: false,
      errorCode: "HTTP_404",
      retryable: false,
    });
  });

  it("maps 429 and 5xx to retryable and other 4xx to fail-closed", () => {
    assert.equal(classifyPagerTreeRecordFailure(429), true);
    assert.equal(classifyPagerTreeRecordFailure(500), true);
    assert.equal(classifyPagerTreeRecordFailure(503), true);
    assert.equal(classifyPagerTreeRecordFailure(400), false);
    assert.equal(classifyPagerTreeRecordFailure(404), false);
    assert.equal(classifyPagerTreeRecordFailure(422), false);
  });

  it("carries the client error text on a failure record, dropping an empty one", () => {
    assert.deepEqual(
      classifyPagerTreeAlertResponse({ status: 500, errorMessage: "boom" }),
      { accepted: false, errorCode: "HTTP_500", retryable: true, errorMessage: "boom" }
    );
    assert.deepEqual(
      classifyPagerTreeAlertResponse({ status: 400, errorMessage: "" }),
      { accepted: false, errorCode: "HTTP_400", retryable: false }
    );
  });
});

describe("pagertree-sink send", () => {
  it("posts one alert per record with the exact headers and no URL or Authorization", async () => {
    const client = new FakeClient();
    const sink = new PagerTreeSink(baseConfig(client));
    const result = await sink.send([
      { body: "{}", subject: "disk full", key: "k-1", traceId: "t-1" },
      { body: "{}", key: "k-2" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    for (const post of client.posts) {
      assert.deepEqual(post.headers, { "Content-Type": PAGERTREE_JSON_CONTENT_TYPE });
      assert.equal("url" in post, false);
      assert.equal("Authorization" in post.headers, false);
      assert.equal(JSON.stringify(post).includes("pagertree"), false);
      assert.equal(JSON.stringify(post).includes("api.pagertree.com"), false);
    }
    assert.equal(bodyOf(client.posts[0]).id, "k-1");
    assert.equal(bodyOf(client.posts[1]).id, "k-2");
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("throws a config error with no client, mapped non_retryable by classifyFailure", async () => {
    const sink = new PagerTreeSink({});
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) => err instanceof PagerTreeSinkConfigError
    );
    assert.deepEqual(classifyFailure(new PagerTreeSinkConfigError("no client injected")), {
      failureClass: "non_retryable",
    });
  });

  it("throws carrying exactly the failed records with their retry lanes", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 400);
    client.statusOn.set(2, 503);
    client.errorOn.set(2, "down");
    const sink = new PagerTreeSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([
          { body: "{}", key: "k-1" },
          { body: "{}", key: "k-2" },
          { body: "{}", key: "k-3" },
        ]),
      (err: unknown) => {
        assert.ok(err instanceof PagerTreeSinkError);
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
    const sink = new PagerTreeSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: "{}", key: "k-1" }]),
      (err: unknown) => {
        assert.ok(err instanceof PagerTreeSinkError);
        assert.deepEqual(err.failedRecords, [
          { index: 0, errorCode: "TRANSPORT_ERROR", retryable: true, errorMessage: "socket hang up" },
        ]);
        return true;
      }
    );
  });

  it("validates a keyless resolve before any POST, even in dry-run mode", async () => {
    const client = new FakeClient();
    const sink = new PagerTreeSink(baseConfig(client, { dryRun: true }));
    await assert.rejects(
      () => sink.send([{ body: "{}", eventType: "resolve" }]),
      RangeError
    );
    assert.equal(client.posts.length, 0);
  });

  it("dry-run validates and performs zero client I/O with no stats change", async () => {
    const sink = new PagerTreeSink({ dryRun: true });
    const result = await sink.send([{ body: "{}", key: "k-1", eventType: "update", urgency: "high" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(
      () => sink.send([{ body: "{}", eventType: "nope" as never }]),
      RangeError
    );
  });

  it("sends a resolved alert as resolve with the same id", async () => {
    const client = new FakeClient();
    const sink = new PagerTreeSink(baseConfig(client));
    await sink.send([{ body: "{}", key: "k-1", eventType: "resolve" }]);
    assert.equal(client.posts.length, 1);
    assert.equal(bodyOf(client.posts[0]).event_type, "resolve");
    assert.equal(bodyOf(client.posts[0]).id, "k-1");
  });
});
