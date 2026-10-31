import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  CleverTapSink,
  CleverTapSinkConfigError,
  CleverTapSinkError,
  assertValidCleverTapSinkConfig,
  buildCleverTapCreateBody,
  buildCleverTapCreateUrl,
  classifyCleverTapRecordFailure,
  cleverTapResponseToFailedRecord,
  resolveCleverTapCampaignName,
  resolveCleverTapContent,
  resolveCleverTapHost,
  resolveCleverTapRecord,
  resolveCleverTapSummary,
  resolveCleverTapWhere,
  truncateCleverTapPayload,
  CLEVERTAP_DEFAULT_HOST,
  CLEVERTAP_DEFAULT_PAYLOAD_MAX_CHARS,
  CLEVERTAP_FALLBACK_SUMMARY,
  CLEVERTAP_JSON_CONTENT_TYPE,
  CLEVERTAP_RETRYABLE_FAIL_CODE,
  CLEVERTAP_TARGET_MODE,
  type CleverTapMessageClient,
  type CleverTapMessagePostRequest,
  type CleverTapMessagePostResponse,
  type CleverTapSinkConfig,
  type CleverTapWhere,
} from "../src/clevertap-sink.ts";
import { classifyFailure } from "../src/failure.ts";

/** In-memory fake client: records every post, answers with a status and status field per call. */
class FakeClient implements CleverTapMessageClient {
  posts: CleverTapMessagePostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  /** Call-count (0-based) → `status` field to surface for that post (undefined = none surfaced). */
  statusFieldOn = new Map<number, string | undefined>();
  /** Call-count (0-based) → `code` field to surface for that post. */
  errorCodeOn = new Map<number, number>();
  /** Call-count (0-based) → `error` message to surface for that post. */
  errorMessageOn = new Map<number, string>();
  async post(request: CleverTapMessagePostRequest): Promise<CleverTapMessagePostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return {
      status: this.statusOn.get(n) ?? 200,
      statusField: this.statusFieldOn.has(n) ? this.statusFieldOn.get(n) : "success",
      errorCode: this.errorCodeOn.get(n),
      errorMessage: this.errorMessageOn.get(n),
    };
  }
}

const where: CleverTapWhere = {
  event_name: "Charged",
  from: 20251001,
  to: 20251220,
};

function baseConfig(
  client: CleverTapMessageClient,
  extra: Partial<CleverTapSinkConfig> = {}
): CleverTapSinkConfig {
  return { where, client, ...extra };
}

describe("clevertap-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidCleverTapSinkConfig(null, "CleverTapSink"), RangeError);
    assert.throws(() => assertValidCleverTapSinkConfig("x", "CleverTapSink"), RangeError);
  });

  it("rejects a malformed region host", () => {
    assert.throws(
      () => assertValidCleverTapSinkConfig({ regionHost: "" }, "CleverTapSink"),
      RangeError
    );
    assert.throws(
      () => assertValidCleverTapSinkConfig({ regionHost: "https://in1.api.clevertap.com" }, "CleverTapSink"),
      RangeError
    );
    assert.throws(
      () => assertValidCleverTapSinkConfig({ regionHost: "in1.api.clevertap.com/1/targets" }, "CleverTapSink"),
      RangeError
    );
    assert.throws(
      () => assertValidCleverTapSinkConfig({ regionHost: 42 }, "CleverTapSink"),
      RangeError
    );
  });

  it("rejects a malformed campaign name", () => {
    assert.throws(
      () => assertValidCleverTapSinkConfig({ campaignName: "" }, "CleverTapSink"),
      RangeError
    );
    assert.throws(
      () => assertValidCleverTapSinkConfig({ campaignName: 7 }, "CleverTapSink"),
      RangeError
    );
  });

  it("rejects a malformed where targeting", () => {
    assert.throws(
      () => assertValidCleverTapSinkConfig({ where: ["Charged"] }, "CleverTapSink"),
      RangeError
    );
    assert.throws(
      () => assertValidCleverTapSinkConfig({ where: null }, "CleverTapSink"),
      RangeError
    );
    assert.throws(
      () => assertValidCleverTapSinkConfig({ where: "Charged" }, "CleverTapSink"),
      RangeError
    );
  });

  it("rejects a client without a post function", () => {
    assert.throws(
      () => assertValidCleverTapSinkConfig({ client: {} }, "CleverTapSink"),
      RangeError
    );
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(
      () => assertValidCleverTapSinkConfig({ payloadMaxChars: 0 }, "CleverTapSink"),
      RangeError
    );
    assert.throws(
      () => assertValidCleverTapSinkConfig({ payloadMaxChars: 1.5 }, "CleverTapSink"),
      RangeError
    );
  });

  it("accepts a config with no client, region host, or targeting yet (send-time config error only for the client)", () => {
    assert.doesNotThrow(() => new CleverTapSink({}));
    assert.doesNotThrow(() => new CleverTapSink({ regionHost: "in1.api.clevertap.com" }));
    assert.doesNotThrow(() => new CleverTapSink({ where: {} }));
  });
});

describe("clevertap-sink host and targeting resolution", () => {
  it("defaults the host to api.clevertap.com (Europe) when the config sets none", () => {
    assert.equal(resolveCleverTapHost({}), CLEVERTAP_DEFAULT_HOST);
    assert.equal(CLEVERTAP_DEFAULT_HOST, "api.clevertap.com");
    assert.equal(resolveCleverTapHost({ regionHost: "in1.api.clevertap.com" }), "in1.api.clevertap.com");
    assert.equal(resolveCleverTapHost({ regionHost: "us1.api.clevertap.com" }), "us1.api.clevertap.com");
  });

  it("defaults the targeting to an empty object (entire user base) when the config sets none", () => {
    assert.deepEqual(resolveCleverTapWhere({}), {});
    assert.deepEqual(resolveCleverTapWhere({ where }), where);
  });

  it("builds the Create Campaign endpoint URL from the host", () => {
    assert.equal(
      buildCleverTapCreateUrl("api.clevertap.com"),
      "https://api.clevertap.com/1/targets/create.json"
    );
    assert.equal(
      buildCleverTapCreateUrl("in1.api.clevertap.com"),
      "https://in1.api.clevertap.com/1/targets/create.json"
    );
  });
});

describe("clevertap-sink summary and campaign-name derivation", () => {
  it("derives the summary from subject, then key, then traceId, then the fallback", () => {
    assert.equal(
      resolveCleverTapSummary({ body: "{}", subject: "order.created", key: "agg-7", traceId: "t-1" }),
      "order.created"
    );
    assert.equal(resolveCleverTapSummary({ body: "{}", key: "agg-7", traceId: "t-1" }), "agg-7");
    assert.equal(resolveCleverTapSummary({ body: "{}", traceId: "t-1" }), "t-1");
    assert.equal(resolveCleverTapSummary({ body: "{}" }), CLEVERTAP_FALLBACK_SUMMARY);
    assert.equal(CLEVERTAP_FALLBACK_SUMMARY, "webhook event");
    // Empty strings fall through, like the Airship sink.
    assert.equal(
      resolveCleverTapSummary({ body: "{}", subject: "", key: "agg-7" }),
      "agg-7"
    );
  });

  it("derives the campaign name from the config, then webhook-<key>, then the fallback", () => {
    assert.equal(
      resolveCleverTapCampaignName({ body: "{}", key: "agg-7" }, { campaignName: "Price drop" }),
      "Price drop"
    );
    assert.equal(
      resolveCleverTapCampaignName({ body: "{}", key: "agg-7" }, {}),
      "webhook-agg-7"
    );
    assert.equal(
      resolveCleverTapCampaignName({ body: "{}", traceId: "t-1" }, {}),
      CLEVERTAP_FALLBACK_SUMMARY
    );
  });

  it("truncates an opted-in payload at the limit with a marker, untouched below it", () => {
    assert.equal(truncateCleverTapPayload("abc", 2000), "abc");
    assert.equal(truncateCleverTapPayload("abcdef", 3), "abc… (truncated)");
  });

  it("keeps the summary alone by default and appends the payload only on opt-in", () => {
    const record = { body: '{"a":1}', subject: "order.created" };
    assert.deepEqual(resolveCleverTapContent(record, {}), {
      title: "order.created",
      body: "order.created",
    });
    assert.deepEqual(resolveCleverTapContent(record, { includePayload: true }), {
      title: "order.created",
      body: 'order.created\n\n{"a":1}',
    });
    assert.deepEqual(
      resolveCleverTapContent({ body: "abcdef", subject: "s" }, { includePayload: true, payloadMaxChars: 3 }),
      { title: "s", body: "s\n\nabc… (truncated)" }
    );
  });

  it("rejects an empty record body", () => {
    assert.throws(() => resolveCleverTapRecord({ body: "" }, 0), RangeError);
    assert.throws(() => resolveCleverTapRecord({ body: "" }, 2), /record 2/);
  });
});

describe("clevertap-sink wire shape", () => {
  it("exposes the region Create Campaign endpoint and the JSON content type", () => {
    assert.equal(CLEVERTAP_TARGET_MODE, "Push");
    assert.equal(CLEVERTAP_JSON_CONTENT_TYPE, "application/json");
  });

  it("builds a JSON body: name, target_mode Push, where, content title/body — and no credential", () => {
    const body = buildCleverTapCreateBody("Price drop", where, {
      title: "order.created",
      body: "order.created",
    });
    const parsed = JSON.parse(body) as Record<string, unknown>;
    assert.deepEqual(parsed, {
      name: "Price drop",
      target_mode: "Push",
      where,
      content: { title: "order.created", body: "order.created" },
    });
    // No credential anywhere in the handed body: the account id and
    // passcode are the client's alone.
    assert.equal(body.includes("X-CleverTap-Account-Id"), false);
    assert.equal(body.includes("X-CleverTap-Passcode"), false);
    assert.equal(body.includes("ACCOUNT_ID"), false);
    assert.equal(body.includes("PASSCODE"), false);
  });
});

describe("clevertap-sink status-field mapping", () => {
  it("accepts a 2xx with status success", () => {
    assert.equal(
      cleverTapResponseToFailedRecord({ status: 200, statusField: "success" }, 0),
      null
    );
  });

  it("maps a 2xx with status fail and code 89 to retryable", () => {
    const failed = cleverTapResponseToFailedRecord(
      { status: 200, statusField: "fail", errorCode: 89, errorMessage: "Unexpected error, please try again" },
      1
    );
    assert.deepEqual(failed, {
      index: 1,
      errorCode: "CLEVERTAP_89",
      errorMessage: "Unexpected error, please try again",
      retryable: true,
    });
    assert.equal(CLEVERTAP_RETRYABLE_FAIL_CODE, 89);
  });

  it("maps a 2xx with status fail and a validation code to fail-closed", () => {
    for (const code of [21, 78, 84]) {
      const failed = cleverTapResponseToFailedRecord(
        { status: 200, statusField: "fail", errorCode: code, errorMessage: "validation" },
        0
      );
      assert.deepEqual(failed, {
        index: 0,
        errorCode: `CLEVERTAP_${code}`,
        errorMessage: "validation",
        retryable: false,
      });
    }
    const noCode = cleverTapResponseToFailedRecord({ status: 200, statusField: "fail" }, 2);
    assert.deepEqual(noCode, {
      index: 2,
      errorCode: "STATUS_FAIL",
      errorMessage: undefined,
      retryable: false,
    });
  });

  it("maps a missing status field on a 2xx to retryable", () => {
    const failed = cleverTapResponseToFailedRecord({ status: 200 }, 0);
    assert.deepEqual(failed, {
      index: 0,
      errorCode: "STATUS_MISSING",
      errorMessage: "CleverTap answered 2xx but surfaced no status field",
      retryable: true,
    });
  });
});

describe("clevertap-sink send", () => {
  it("posts one message per record to the region endpoint with the JSON campaign, no credential", async () => {
    const client = new FakeClient();
    const sink = new CleverTapSink(baseConfig(client, { regionHost: "in1.api.clevertap.com" }));
    const result = await sink.send([
      { body: '{"a":1}', subject: "order.created", key: "agg-7" },
      { body: '{"b":2}', key: "agg-8" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    for (const post of client.posts) {
      assert.equal(post.url, "https://in1.api.clevertap.com/1/targets/create.json");
      // Only the JSON content type is handed over: the account id and
      // passcode headers are the client's alone.
      assert.deepEqual(post.headers, { "Content-Type": "application/json" });
    }
    const first = JSON.parse(client.posts[0].body) as Record<string, unknown>;
    assert.deepEqual(first, {
      name: "webhook-agg-7",
      target_mode: "Push",
      where,
      content: { title: "order.created", body: "order.created" },
    });
    const second = JSON.parse(client.posts[1].body) as Record<string, unknown>;
    assert.deepEqual(second, {
      name: "webhook-agg-8",
      target_mode: "Push",
      where,
      content: { title: "agg-8", body: "agg-8" },
    });
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("defaults the host to api.clevertap.com and the targeting to {} when the config sets none", async () => {
    const client = new FakeClient();
    const sink = new CleverTapSink({ client });
    await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.equal(client.posts[0].url, "https://api.clevertap.com/1/targets/create.json");
    const body = JSON.parse(client.posts[0].body) as Record<string, unknown>;
    assert.deepEqual(body.where, {});
    assert.equal(body.name, "webhook event");
  });

  it("applies the payload opt-in truncation on send", async () => {
    const client = new FakeClient();
    const sink = new CleverTapSink(
      baseConfig(client, { campaignName: "Price drop", includePayload: true, payloadMaxChars: 3 })
    );
    await sink.send([{ body: "abcdef", subject: "s" }]);
    const body = JSON.parse(client.posts[0].body) as {
      name: string;
      content: { title: string; body: string };
    };
    assert.equal(body.name, "Price drop");
    assert.deepEqual(body.content, { title: "s", body: "s\n\nabc… (truncated)" });
  });

  it("treats the status field as an acceptance receipt, not a delivery result", async () => {
    const client = new FakeClient();
    const sink = new CleverTapSink(baseConfig(client));
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    // A 2xx with status "success" is accepted even though no campaign
    // id is surfaced: the field is the acceptance receipt.
    assert.deepEqual(result, { ok: true, sent: 1 });
  });

  it("retries a 2xx with status fail code 89, fails closed on code 84", async () => {
    const client = new FakeClient();
    client.statusFieldOn.set(0, "fail");
    client.errorCodeOn.set(0, 89);
    client.statusFieldOn.set(1, "fail");
    client.errorCodeOn.set(1, 84);
    client.errorMessageOn.set(1, "Invalid recipients");
    const sink = new CleverTapSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([
          { body: '{"a":1}', subject: "one" },
          { body: '{"b":2}', subject: "two" },
        ]),
      (err: unknown) => {
        assert.ok(err instanceof CleverTapSinkError);
        assert.equal(err.failedRecords.length, 2);
        assert.deepEqual(err.failedRecords[0], {
          index: 0,
          errorCode: "CLEVERTAP_89",
          errorMessage: undefined,
          retryable: true,
        });
        assert.deepEqual(err.failedRecords[1], {
          index: 1,
          errorCode: "CLEVERTAP_84",
          errorMessage: "Invalid recipients",
          retryable: false,
        });
        return true;
      }
    );
    assert.deepEqual(sink.stats, { sent: 0, failed: 2, sendFailures: 1 });
  });

  it("retries a 2xx with no status field surfaced", async () => {
    const client = new FakeClient();
    client.statusFieldOn.set(0, undefined);
    const sink = new CleverTapSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: '{"a":1}', subject: "order.created" }]),
      (err: unknown) => {
        assert.ok(err instanceof CleverTapSinkError);
        assert.equal(err.failedRecords.length, 1);
        assert.equal(err.failedRecords[0].errorCode, "STATUS_MISSING");
        assert.equal(err.failedRecords[0].retryable, true);
        return true;
      }
    );
  });

  it("maps 429 and 5xx to retryable, other non-2xx to fail-closed", async () => {
    const cases: Array<[number, boolean]> = [
      [429, true],
      [500, true],
      [503, true],
      [400, false],
      [401, false],
      [403, false],
      [404, false],
    ];
    for (const [status, retryable] of cases) {
      const client = new FakeClient();
      client.statusOn.set(0, status);
      const sink = new CleverTapSink(baseConfig(client));
      await assert.rejects(
        () => sink.send([{ body: '{"a":1}', subject: "order.created" }]),
        (err: unknown) => {
          assert.ok(err instanceof CleverTapSinkError);
          assert.equal(err.failedRecords.length, 1);
          assert.equal(err.failedRecords[0].errorCode, `HTTP_${status}`);
          assert.equal(err.failedRecords[0].statusCode, status);
          assert.equal(err.failedRecords[0].retryable, retryable);
          return true;
        }
      );
    }
  });

  it("maps a codeless transport failure to retryable with the client message", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hangup"));
    const sink = new CleverTapSink(baseConfig(client));
    await assert.rejects(
      () =>
        sink.send([
          { body: '{"a":1}', subject: "one" },
          { body: '{"b":2}', subject: "two" },
        ]),
      (err: unknown) => {
        assert.ok(err instanceof CleverTapSinkError);
        assert.equal(err.failedRecords.length, 1);
        assert.equal(err.failedRecords[0].index, 0);
        assert.equal(err.failedRecords[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(err.failedRecords[0].errorMessage, "socket hangup");
        assert.equal(err.failedRecords[0].retryable, true);
        return true;
      }
    );
    assert.deepEqual(sink.stats, { sent: 1, failed: 1, sendFailures: 1 });
  });

  it("fails closed without a client", async () => {
    await assert.rejects(
      () => new CleverTapSink({ where }).send([{ body: '{"a":1}' }]),
      CleverTapSinkConfigError
    );
  });

  it("does not fail closed for a missing targeting — it sends where {} (entire user base)", async () => {
    const client = new FakeClient();
    const sink = new CleverTapSink({ client });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 1 });
  });

  it("maps a config error to non_retryable through classifyFailure", async () => {
    const sink = new CleverTapSink({});
    await assert.rejects(() => sink.send([{ body: '{"a":1}' }]), (err: unknown) => {
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
  });

  it("dry run validates but performs zero client I/O and touches no stats", async () => {
    const client = new FakeClient();
    const sink = new CleverTapSink({ dryRun: true });
    const result = await sink.send([{ body: '{"a":1}', subject: "order.created" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    await assert.rejects(() =>
      new CleverTapSink({ dryRun: true }).send([{ body: "" }])
    );
  });

  it("classifies statuses directly", () => {
    assert.equal(classifyCleverTapRecordFailure(429), true);
    assert.equal(classifyCleverTapRecordFailure(500), true);
    assert.equal(classifyCleverTapRecordFailure(503), true);
    assert.equal(classifyCleverTapRecordFailure(400), false);
    assert.equal(classifyCleverTapRecordFailure(401), false);
    assert.equal(classifyCleverTapRecordFailure(404), false);
    assert.equal(CLEVERTAP_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });
});
