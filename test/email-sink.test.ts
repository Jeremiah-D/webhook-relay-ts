import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  EmailSink,
  EmailSinkConfigError,
  EmailSinkError,
  assertValidEmailSinkConfig,
  classifyEmailRecordFailure,
  extractSmtpCodeFromError,
  resolveEmailRecord,
  resolveEmailSubject,
  resolveEmailSummary,
  resolveEmailText,
  truncateEmailPayload,
  EMAIL_DEFAULT_PAYLOAD_MAX_CHARS,
  EMAIL_FALLBACK_SUMMARY,
  type EmailSmtpClient,
  type EmailSendRequest,
  type EmailSendResponse,
  type EmailSinkConfig,
} from "../src/email-sink.ts";
import { classifyFailure } from "../src/failure.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.

/** In-memory fake client: records every send, answers with a reply code per call. */
class FakeClient implements EmailSmtpClient {
  sends: EmailSendRequest[] = [];
  /** Call-count (0-based) → SMTP reply code to return for that send. */
  statusOn = new Map<number, number>();
  /** Call-count (0-based) → error to throw for that send. */
  failOn = new Map<number, Error>();
  async send(request: EmailSendRequest): Promise<EmailSendResponse> {
    const n = this.sends.length;
    this.sends.push(request);
    const err = this.failOn.get(n);
    if (err !== undefined) throw err;
    return { status: this.statusOn.get(n) ?? 250 };
  }
}

/** An error carrying an SMTP reply code, like a real SMTP library's auth failure. */
class CodedError extends Error {
  code: number;
  constructor(message: string, code: number) {
    super(message);
    this.name = "CodedError";
    this.code = code;
  }
}

const recipient = "ops@example.com";

function baseConfig(
  client: EmailSmtpClient,
  extra: Partial<EmailSinkConfig> = {}
): EmailSinkConfig {
  return { to: recipient, client, ...extra };
}

describe("email-sink config validation", () => {
  it("rejects a non-object config", () => {
    assert.throws(() => assertValidEmailSinkConfig(null, "EmailSink"), RangeError);
    assert.throws(() => assertValidEmailSinkConfig("x", "EmailSink"), RangeError);
  });

  it("rejects a malformed recipient shape", () => {
    assert.throws(() => assertValidEmailSinkConfig({ to: "" }, "EmailSink"), RangeError);
    assert.throws(
      () => assertValidEmailSinkConfig({ to: "has space" }, "EmailSink"),
      RangeError
    );
    assert.throws(
      () => assertValidEmailSinkConfig({ to: "has\0nul" }, "EmailSink"),
      RangeError
    );
    assert.throws(() => assertValidEmailSinkConfig({ to: 123 }, "EmailSink"), RangeError);
  });

  it("accepts a missing recipient at construction (send-time config error)", () => {
    assert.doesNotThrow(() => assertValidEmailSinkConfig({}, "EmailSink"));
    assert.doesNotThrow(() => assertValidEmailSinkConfig({ to: recipient }, "EmailSink"));
  });

  it("rejects a client without a send function", () => {
    assert.throws(() => assertValidEmailSinkConfig({ client: {} }, "EmailSink"), RangeError);
  });

  it("rejects a non-positive payloadMaxChars", () => {
    assert.throws(
      () => assertValidEmailSinkConfig({ payloadMaxChars: 0 }, "EmailSink"),
      RangeError
    );
    assert.throws(
      () => assertValidEmailSinkConfig({ payloadMaxChars: 1.5 }, "EmailSink"),
      RangeError
    );
  });
});

describe("email-sink subject and body derivation", () => {
  it("takes the subject from the event subject, falling back to generic", () => {
    assert.equal(resolveEmailSubject({ body: "{}", subject: "order.created" }), "order.created");
    assert.equal(resolveEmailSubject({ body: "{}", subject: "" }), "webhook event");
    assert.equal(resolveEmailSubject({ body: "{}" }), "webhook event");
    assert.equal(EMAIL_FALLBACK_SUMMARY, "webhook event");
  });

  it("derives the body from key, then traceId — never repeating the subject", () => {
    assert.equal(
      resolveEmailSummary({ body: "{}", subject: "s", key: "k", traceId: "t" }),
      "k"
    );
    assert.equal(resolveEmailSummary({ body: "{}", subject: "s", traceId: "t" }), "t");
    assert.equal(resolveEmailSummary({ body: "{}", subject: "s" }), "webhook event");
  });

  it("carries the summary only by default, never the payload", () => {
    const text = resolveEmailText(
      { body: '{"card":"4111"}', subject: "order.created", key: "agg-7" },
      {}
    );
    assert.equal(text, "agg-7");
    assert.ok(!text.includes("4111"), "payload must not leak by default");
  });

  it("appends the payload verbatim under the opt-in, truncated with a marker", () => {
    const text = resolveEmailText(
      { body: "x".repeat(50), key: "k" },
      { includePayload: true, payloadMaxChars: 10 }
    );
    assert.equal(text, "k\n```\nxxxxxxxxxx… (truncated)\n```");
    assert.equal(EMAIL_DEFAULT_PAYLOAD_MAX_CHARS, 2000);
  });

  it("does not truncate a short opted-in payload", () => {
    assert.equal(truncateEmailPayload("short", 2000), "short");
    const text = resolveEmailText(
      { body: '{"a":1}', key: "k" },
      { includePayload: true }
    );
    assert.equal(text, 'k\n```\n{"a":1}\n```');
  });

  it("rejects an empty body even without the opt-in", () => {
    assert.throws(() => resolveEmailRecord({ body: "" }, 0, {}), RangeError);
    assert.throws(() => resolveEmailRecord({ body: "" }, 2, {}), /record 2/);
  });
});

describe("email-sink send", () => {
  it("sends one message per record to the configured recipient", async () => {
    const client = new FakeClient();
    const sink = new EmailSink(baseConfig(client));
    const result = await sink.send([
      { body: "{}", subject: "order.created", key: "agg-7" },
      { body: "{}", traceId: "trace-9" },
    ]);
    assert.deepEqual(result, { ok: true, sent: 2 });
    assert.equal(client.sends.length, 2);
    assert.deepEqual(client.sends[0], {
      to: recipient,
      subject: "order.created",
      text: "agg-7",
    });
    assert.deepEqual(client.sends[1], {
      to: recipient,
      subject: "webhook event",
      text: "trace-9",
    });
    assert.deepEqual(sink.stats, { sent: 2, failed: 0, sendFailures: 0 });
  });

  it("carries only to + subject + text in the client request", async () => {
    // No credentials are ever held by the sink: the request
    // carries only addressing and content, so a credential
    // cannot leak through a sink log or a failed-record report.
    const client = new FakeClient();
    const sink = new EmailSink(baseConfig(client));
    await sink.send([{ body: "{}", subject: "s", key: "k" }]);
    assert.equal(Object.keys(client.sends[0]).sort().join(","), "subject,text,to");
  });

  it("dry-run validates with zero client I/O and untouched stats", async () => {
    const client = new FakeClient();
    const sink = new EmailSink({ dryRun: true });
    const result = await sink.send([{ body: "{}", subject: "s", key: "k" }]);
    assert.deepEqual(result, { ok: true, sent: 0, dryRun: true });
    assert.equal(client.sends.length, 0);
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
    // ...but still validates: a malformed record fails even dry.
    await assert.rejects(() => sink.send([{ body: "" }]), RangeError);
    assert.equal(client.sends.length, 0);
  });

  it("fails closed without a client", async () => {
    const sink = new EmailSink({ to: recipient });
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) => err instanceof EmailSinkConfigError
    );
    assert.deepEqual(sink.stats, { sent: 0, failed: 0, sendFailures: 0 });
  });

  it("fails closed without a recipient", async () => {
    const client = new FakeClient();
    const sink = new EmailSink({ client });
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) =>
        err instanceof EmailSinkConfigError && /recipient/.test(err.message)
    );
    assert.equal(client.sends.length, 0);
  });

  it("throws carrying exactly the failed messages, keeping partial success", async () => {
    const client = new FakeClient();
    client.statusOn.set(1, 550);
    const sink = new EmailSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: "{}" }, { body: "{}" }, { body: "{}" }]),
      (err: unknown) => {
        assert.ok(err instanceof EmailSinkError);
        assert.equal(err.failedRecords.length, 1);
        assert.equal(err.failedRecords[0].index, 1);
        assert.equal(err.failedRecords[0].errorCode, "SMTP_550");
        assert.equal(err.failedRecords[0].retryable, false);
        return true;
      }
    );
    // Partial success stays out of failedRecords; stats stay honest.
    assert.deepEqual(sink.stats, { sent: 2, failed: 1, sendFailures: 1 });
  });

  it("maps a transient 4xx reply to retryable", async () => {
    const client = new FakeClient();
    client.statusOn.set(0, 450);
    const sink = new EmailSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) => {
        assert.ok(err instanceof EmailSinkError);
        assert.equal(err.failedRecords[0].errorCode, "SMTP_450");
        assert.equal(err.failedRecords[0].retryable, true);
        return true;
      }
    );
  });

  it("maps a codeless transport failure to retryable", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new Error("connection reset"));
    const sink = new EmailSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) => {
        assert.ok(err instanceof EmailSinkError);
        assert.equal(err.failedRecords[0].errorCode, "TRANSPORT_ERROR");
        assert.equal(err.failedRecords[0].errorMessage, "connection reset");
        assert.equal(err.failedRecords[0].retryable, true);
        return true;
      }
    );
  });

  it("maps a thrown 535 auth failure to fail-closed, not retryable", async () => {
    const client = new FakeClient();
    client.failOn.set(0, new CodedError("authentication failed", 535));
    const sink = new EmailSink(baseConfig(client));
    await assert.rejects(
      () => sink.send([{ body: "{}" }]),
      (err: unknown) => {
        assert.ok(err instanceof EmailSinkError);
        assert.equal(err.failedRecords[0].errorCode, "SMTP_535");
        assert.equal(err.failedRecords[0].statusCode, 535);
        assert.equal(err.failedRecords[0].retryable, false);
        return true;
      }
    );
  });
});

describe("email-sink failure classification", () => {
  it("treats 4xx as retryable and 5xx as fail-closed", () => {
    assert.equal(classifyEmailRecordFailure(421), true);
    assert.equal(classifyEmailRecordFailure(450), true);
    assert.equal(classifyEmailRecordFailure(451), true);
    assert.equal(classifyEmailRecordFailure(500), false);
    assert.equal(classifyEmailRecordFailure(535), false);
    assert.equal(classifyEmailRecordFailure(550), false);
    assert.equal(classifyEmailRecordFailure(553), false);
  });

  it("extracts SMTP codes from thrown errors, codeless otherwise", () => {
    assert.equal(extractSmtpCodeFromError(new CodedError("auth", 535)), 535);
    assert.equal(extractSmtpCodeFromError({ code: "450" }), 450);
    assert.equal(extractSmtpCodeFromError({ status: 550 }), 550);
    assert.equal(extractSmtpCodeFromError(new Error("plain")), undefined);
    assert.equal(extractSmtpCodeFromError(null), undefined);
  });

  it("maps the config error to non_retryable through classifyFailure", () => {
    assert.deepEqual(classifyFailure(new EmailSinkConfigError("no client")), {
      failureClass: "non_retryable",
    });
  });

  it("does not map the per-message error itself to non_retryable", () => {
    const err = new EmailSinkError("email-sink: send failed for 1 of 1 messages", [
      { index: 0, errorCode: "SMTP_450", statusCode: 450, retryable: true },
    ]);
    assert.notDeepEqual(classifyFailure(err), { failureClass: "non_retryable" });
  });
});
