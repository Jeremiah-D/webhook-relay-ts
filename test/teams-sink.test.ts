import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  TeamsSink,
  TeamsSinkConfigError,
  TeamsSinkError,
  assertValidTeamsSinkConfig,
  classifyTeamsRecordFailure,
  isValidTeamsWebhookUrl,
  resolveTeamsRecord,
  resolveTeamsSummary,
  resolveTeamsText,
  truncateTeamsPayload,
  TEAMS_DEFAULT_PAYLOAD_MAX_CHARS,
  TEAMS_FALLBACK_SUMMARY,
  type TeamsWebhookClient,
  type TeamsWebhookPostRequest,
  type TeamsWebhookPostResponse,
  type TeamsSinkConfig,
} from "../src/teams-sink.ts";
import { classifyFailure } from "../src/failure.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.

/** In-memory fake client: records every post, answers with a status per call. */
class FakeClient implements TeamsWebhookClient {
  posts: TeamsWebhookPostRequest[] = [];
  /** Call-count (0-based) → status to return for that post. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that post. */
  failOn = new Map<number, Error>();
  async post(request: TeamsWebhookPostRequest): Promise<TeamsWebhookPostResponse> {
    const n = this.posts.length;
    this.posts.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 200 };
  }
}

const hook = "https://outlook.office.com/webhook/abc123/IncomingWebhook/def456";

function baseConfig(
  client: TeamsWebhookClient,
  extra: Partial<TeamsSinkConfig> = {}
): TeamsSinkConfig {
  return { webhookUrl: hook, client, ...extra };
}

describe("teams-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidTeamsSinkConfig(null, "TeamsSink"), RangeError);
    assert.throws(() => assertValidTeamsSinkConfig("x", "TeamsSink"), RangeError);
  });

  it("rejects a malformed webhook URL shape", () => {
    assert.throws(() => assertValidTeamsSinkConfig({ webhookUrl: "" }, "TeamsSink"), RangeError);
    assert.throws(
      () => assertValidTeamsSinkConfig({ webhookUrl: "has space" }, "TeamsSink"),
      RangeError
    );
    assert.throws(
      () => assertValidTeamsSinkConfig({ webhookUrl: "has\0nul" }, "TeamsSink"),
      RangeError
    );
    assert.throws(
      () => assertValidTeamsSinkConfig({ webhookUrl: 123 }, "TeamsSink"),
      RangeError
    );
  });

  it("accepts a missing webhook URL at construction (send-time config error)", () => {
    assert.doesNotThrow(() => assertValidTeamsSinkConfig({}, "TeamsSink"));
    assert.doesNotThrow(() => assertValidTeamsSinkConfig({ webhookUrl: hook }, "TeamsSink"));
  });

  it("rejects a client without a post function", () => {
    assert.throws(
      () => assertValidTeamsSinkConfig({ client: {} }, "TeamsSink"),
      RangeError
    );
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(
      () => assertValidTeamsSinkConfig({ payloadMaxChars: 0 }, "TeamsSink"),
      RangeError
    );
    assert.throws(
      () => assertValidTeamsSinkConfig({ payloadMaxChars: 1.5 }, "TeamsSink"),
      RangeError
    );
  });

  it("accepts https URLs and rejects http or unparseable URLs at send time", () => {
    assert.equal(isValidTeamsWebhookUrl(hook), true);
    assert.equal(isValidTeamsWebhookUrl("http://outlook.office.com/webhook/1/2"), false);
    assert.equal(isValidTeamsWebhookUrl("not a url"), false);
    assert.equal(isValidTeamsWebhookUrl(""), false);
  });
});

describe("teams-sink text derivation", () => {
  it("prefers subject, then key, then traceId", () => {
    assert.equal(
      resolveTeamsSummary({ body: "{}", subject: "s", key: "k", traceId: "t" }),
      "s"
    );
    assert.equal(resolveTeamsSummary({ body: "{}", key: "k", traceId: "t" }), "k");
    assert.equal(resolveTeamsSummary({ body: "{}", traceId: "t" }), "t");
    assert.equal(resolveTeamsSummary({ body: "{}", subject: "" }), TEAMS_FALLBACK_SUMMARY);
  });

  it("falls back to the generic summary for sourceless events", () => {
    assert.equal(resolveTeamsSummary({ body: "{}" }), "webhook event");
    assert.equal(TEAMS_FALLBACK_SUMMARY, "webhook event");
  });

  it("carries the summary only by default, never the payload", () => {
    const text = resolveTeamsText(
      { body: '{"card":"4111"}', subject: "order.created" },
      {}
    );
    assert.equal(text, "order.created");
    assert.ok(!text.includes("4111"), "payload must not leak by default");
  });

  it("appends the payload verbatim under the opt-in, truncated with a marker", () => {
    const text = resolveTeamsText(
      { body: "x".repeat(50), subject: "s" },
      { includePayload: true, payloadMaxChars: 10 }
    );
    assert.equal(text, "s\n```\nxxxxxxxxxx… (truncated)\n```");
    assert.equal(TEAMS_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });

  it("does not truncate a short opted-in payload", () => {
    assert.equal(truncateTeamsPayload("short", 2000), "short");
    const text = resolveTeamsText(
      { body: '{"a":1}', subject: "s" },
      { includePayload: true }
    );
    assert.equal(text, 's\n```\n{"a":1}\n```');
  });

  it("rejects an empty body even without the opt-in", () => {
    assert.throws(() => resolveTeamsRecord({ body: "" }, 0, {}), RangeError);
    assert.throws(() => resolveTeamsRecord({ body: "" }, 2, {}), /record 2/);
  });
});

describe("teams-sink send", () => {
  it("posts one message per record to the configured webhook URL verbatim", async () => {
    const client = new FakeClient();
    const sink = new TeamsSink(baseConfig(client));
    const result = await sink.send([
      { body: "{}", subject: "order.created" },
      { body: "{}", key: "agg-7" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.posts.length, 2);
    assert.deepEqual(client.posts[0], { url: hook, text: "order.created" });
    assert.deepEqual(client.posts[1], { url: hook, text: "agg-7" });
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("carries only url + text in the client request", async () => {
    // No token is ever appended or extracted: the request the
    // client receives is the opaque webhook URL plus the text.
    const client = new FakeClient();
    const sink = new TeamsSink(baseConfig(client));
    await sink.send([{ body: "{}", subject: "s" }]);
    assert.equal(Object.keys(client.posts[0]).sort().join(","), "text,url");
  });

  it("dry-run validates with zero client I/O and untouched stats", async () => {
    const client = new FakeClient();
    const sink = new TeamsSink({ dryRun: true });
    const result = await sink.send([{ body: "{}", subject: "s" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.posts.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    // ...but still validates: a malformed record fails even dry.
    await assert.rejects(() => sink.send([{ body: "" }]), RangeError);
    assert.equal(client.posts.length, 0);
  });

  it("fails closed without a client", async () => {
    const sink = new TeamsSink({ webhookUrl: hook });
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) => err instanceof TeamsSinkConfigError
    );
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("fails closed without a webhook URL", async () => {
    const client = new FakeClient();
    const sink = new TeamsSink({ client });
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) =>
        err instanceof TeamsSinkConfigError && /webhook URL/.test(err.message)
    );
    assert.equal(client.posts.length, 0);
  });

  it("fails closed on a plaintext or unparseable webhook URL", async () => {
    const client = new FakeClient();
    const sink = new TeamsSink({
      webhookUrl: "http://outlook.office.com/webhook/1/2",
      client,
    });
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) => err instanceof TeamsSinkConfigError
    );
    assert.equal(client.posts.length, 0);
  });

  it("throws carrying exactly the failed messages, keeping partial success", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 404);
    const sink = new TeamsSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: "{}" }, { body: "{}" }, { body: "{}" }]),
      (err: unknown) => {
        assert.ok(err instanceof TeamsSinkError);
        assert.equal(err.failedRecords.length, 1);
        assert.equal(err.failedRecords[0].index, 1);
        assert.equal(err.failedRecords[0].errorCode, "HTTP_404");
        assert.equal(err.failedRecords[0].retryable, false);
        return true;
      }
    );
    // Partial success stays out of failedRecords; stats stay honest.
    assert.deepEqual(sink.stats, { sent: 2, failed: 1, sendFailures: 1 });
  });

  it("maps a codeless transport failure to retryable", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("socket hangup"));
    const sink = new TeamsSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) => {
        assert.ok(err instanceof TeamsSinkError);
        assert.equal(err.failedRecords[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(err.failedRecords[0].errorMessage, "socket hangup");
        assert.equal(err.failedRecords[0].retryable, true);
        return true;
      }
    );
  });
});

describe("teams-sink failure classification", () => {
  it("treats 429 and 5xx as retryable, other non-2xx as fail-closed", () => {
    assert.equal(classifyTeamsRecordFailure(429), true);
    assert.equal(classifyTeamsRecordFailure(500), true);
    assert.equal(classifyTeamsRecordFailure(503), true);
    assert.equal(classifyTeamsRecordFailure(400), false);
    assert.equal(classifyTeamsRecordFailure(401), false);
    assert.equal(classifyTeamsRecordFailure(403), false);
    assert.equal(classifyTeamsRecordFailure(404), false);
  });

  it("maps the config error to non_retryable through classifyFailure", () => {
    assert.deepEqual(classifyFailure(new TeamsSinkConfigError("no client")), {
      failureClass: "non_retryable",
    });
  });

  it("does not map the per-message error itself to non_retryable", () => {
    const err = new TeamsSinkError("teams-sink: send failed for 1 of 1 messages", [
      { index: 0, errorCode: "HTTP_429", statusCode: 429, retryable: true },
    ]);
    assert.notDeepEqual(classifyFailure(err), { failureClass: "non_retryable" });
  });
});
