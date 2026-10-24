import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import {
  SqsSink,
  SqsSinkConfigError,
  SqsSinkError,
  assertValidSqsSinkConfig,
  buildSqsSendMessageBody,
  parseSqsSendMessageId,
  type SqsDelivery,
  type SqsSinkConfig,
} from "../src/sqs-sink.ts";
import { classifyFailure } from "../src/failure.ts";
import { signAwsSigV4 } from "../src/sigv4.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.
const testAccessKeyId = "TESTAKID123";
const testRegion = "us-east-1";
const testKeyMaterial = "test-secret-access-key";
const testMessageId = "5fea7756-0ea4-451a-a703-a558b933e274";

function baseConfig(queueUrl: string, extra: Partial<SqsSinkConfig> = {}): SqsSinkConfig {
  return {
    queueUrl,
    region: testRegion,
    accessKeyId: testAccessKeyId,
    secretRef: "unused-when-injected",
    secretResolver: () => testKeyMaterial,
    ...extra,
  };
}

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

interface SeenPost {
  method: string | undefined;
  path: string | undefined;
  headers: Record<string, string | string[] | undefined>;
  rawBody: string;
}

function stubQueue(
  seen: SeenPost[],
  respond: (seenSoFar: SeenPost[]) => { status: number; body: string; headers?: Record<string, string> }
): Server {
  return createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const post: SeenPost = {
        method: req.method,
        path: req.url,
        headers: req.headers,
        rawBody: Buffer.concat(chunks).toString("utf8"),
      };
      seen.push(post);
      const r = respond(seen);
      res.writeHead(r.status, { "content-type": "text/xml", ...(r.headers ?? {}) });
      res.end(r.body);
    });
  });
}

function sendMessageXml(messageId: string): string {
  return (
    `<SendMessageResponse><SendMessageResult><MessageId>${messageId}</MessageId>` +
    `<MD5OfMessageBody>9bb58f26192e4ba00f01e2e7b136bb2</MD5OfMessageBody></SendMessageResult>` +
    `<ResponseMetadata><RequestId>test-request-id</RequestId></ResponseMetadata></SendMessageResponse>`
  );
}

function amzDateToMs(amzDate: string): number {
  // "20261024T123456Z" -> UTC ms.
  const y = Number(amzDate.slice(0, 4));
  const mo = Number(amzDate.slice(4, 6)) - 1;
  const d = Number(amzDate.slice(6, 8));
  const h = Number(amzDate.slice(9, 11));
  const mi = Number(amzDate.slice(11, 13));
  const s = Number(amzDate.slice(13, 15));
  return Date.UTC(y, mo, d, h, mi, s);
}

describe("sqs-sink config validation", () => {
  it("rejects a non-object, an empty queue URL, and a non-URL queue URL", () => {
    assert.throws(() => assertValidSqsSinkConfig(null, "x"), RangeError);
    assert.throws(
      () => assertValidSqsSinkConfig(baseConfig(""), "x"),
      /queueUrl.*non-empty/
    );
    assert.throws(
      () => assertValidSqsSinkConfig(baseConfig("not-a-url"), "x"),
      /queueUrl.*valid URL/
    );
  });

  it("rejects non-http(s) queue URLs and URLs without a queue path", () => {
    assert.throws(
      () => assertValidSqsSinkConfig(baseConfig("ftp://example.com/q"), "x"),
      /http\(s\)/
    );
    assert.throws(
      () => assertValidSqsSinkConfig(baseConfig("https://sqs.us-east-1.amazonaws.com"), "x"),
      /queue path/
    );
    assert.throws(
      () => assertValidSqsSinkConfig(baseConfig("https://sqs.us-east-1.amazonaws.com/"), "x"),
      /queue path/
    );
  });

  it("rejects FIFO queue URLs instead of silently mis-delivering", () => {
    assert.throws(
      () =>
        assertValidSqsSinkConfig(
          baseConfig("https://sqs.us-east-1.amazonaws.com/123456789012/events.fifo"),
          "x"
        ),
      /FIFO/
    );
  });

  it("rejects a bad region, empty key material refs, and a bad timeout", () => {
    assert.throws(
      () => assertValidSqsSinkConfig(baseConfig("http://127.0.0.1/q", { region: "US_EAST_1" }), "x"),
      /region/
    );
    assert.throws(
      () => assertValidSqsSinkConfig(baseConfig("http://127.0.0.1/q", { accessKeyId: "" }), "x"),
      /accessKeyId/
    );
    assert.throws(
      () => assertValidSqsSinkConfig(baseConfig("http://127.0.0.1/q", { secretRef: "" }), "x"),
      /secretRef/
    );
    assert.throws(
      () => assertValidSqsSinkConfig(baseConfig("http://127.0.0.1/q", { requestTimeoutMs: 0 }), "x"),
      /requestTimeoutMs/
    );
    assert.throws(
      () => new SqsSink(baseConfig("https://sqs.us-east-1.amazonaws.com/1/q.fifo")),
      /FIFO/
    );
  });
});

describe("buildSqsSendMessageBody", () => {
  it("encodes Action + MessageBody with tenant/endpoint/trace attributes in order", () => {
    const delivery: SqsDelivery = {
      body: JSON.stringify({ event: "order.created", amount_cents: 1200 }),
      tenantId: "tenant-7",
      endpoint: "https://downstream.example/hook",
      traceId: "trace-1",
      attributes: { source: "relay" },
    };
    const params = new URLSearchParams(buildSqsSendMessageBody(delivery));
    assert.equal(params.get("Action"), "SendMessage");
    assert.equal(params.get("MessageBody"), delivery.body);
    assert.equal(params.get("MessageAttribute.1.Name"), "tenant");
    assert.equal(params.get("MessageAttribute.1.DataType"), "String");
    assert.equal(params.get("MessageAttribute.1.StringValue"), "tenant-7");
    assert.equal(params.get("MessageAttribute.2.Name"), "endpoint");
    assert.equal(params.get("MessageAttribute.2.StringValue"), "https://downstream.example/hook");
    assert.equal(params.get("MessageAttribute.3.Name"), "trace");
    assert.equal(params.get("MessageAttribute.3.StringValue"), "trace-1");
    assert.equal(params.get("MessageAttribute.4.Name"), "source");
    assert.equal(params.get("MessageAttribute.4.StringValue"), "relay");
  });

  it("omits absent attributes and rejects an empty body or a non-string attribute", () => {
    const params = new URLSearchParams(buildSqsSendMessageBody({ body: "{}" }));
    assert.equal(params.get("Action"), "SendMessage");
    assert.equal(params.get("MessageAttribute.1.Name"), null);
    assert.throws(() => buildSqsSendMessageBody({ body: "" }), /body.*non-empty/);
    assert.throws(
      () => buildSqsSendMessageBody({ body: "{}", attributes: { n: 42 as unknown as string } }),
      /must be a string/
    );
  });
});

describe("parseSqsSendMessageId", () => {
  it("extracts the message id and returns undefined when absent", () => {
    assert.equal(parseSqsSendMessageId(sendMessageXml(testMessageId)), testMessageId);
    assert.equal(parseSqsSendMessageId("<SendMessageResponse/>"), undefined);
  });
});

describe("SqsSink.send", () => {
  it("POSTs a SigV4-signed SendMessage and returns the SQS message id", async () => {
    const seen: SeenPost[] = [];
    const server = stubQueue(seen, () => ({ status: 200, body: sendMessageXml(testMessageId) }));
    const port = await listen(server);
    try {
      const sink = new SqsSink(baseConfig(`http://127.0.0.1:${port}/000000000000/events`));
      const delivery: SqsDelivery = {
        body: JSON.stringify({ event: "order.created" }),
        tenantId: "tenant-7",
        traceId: "trace-1",
      };
      const result = await sink.send(delivery);
      assert.equal(result.ok, true);
      assert.equal(result.messageId, testMessageId);
      assert.deepEqual(sink.stats, { sent: 1, sendFailures: 0 });
      assert.equal(seen.length, 1);
      const post = seen[0];
      assert.equal(post.method, "POST");
      assert.equal(post.path, "/000000000000/events");
      const headers = post.headers;
      const authorization = headers["authorization"];
      assert.ok(typeof authorization === "string");
      assert.ok(authorization.startsWith("AWS4-HMAC-SHA256 "));
      assert.ok(authorization.includes(`Credential=${testAccessKeyId}/`));
      assert.ok(authorization.includes(`/${testRegion}/sqs/aws4_request`));
      assert.ok(authorization.includes("SignedHeaders=content-type;host;x-amz-date"));
      assert.equal(headers["content-type"], "application/x-www-form-urlencoded");
      // Independent check: re-sign the exact wire bytes at the exact
      // second the sink stamped, and the Authorization must match.
      const amzDate = headers["x-amz-date"];
      assert.ok(typeof amzDate === "string");
      const recomputed = signAwsSigV4({
        method: "POST",
        url: `http://127.0.0.1:${port}/000000000000/events`,
        body: Buffer.from(post.rawBody, "utf8"),
        credentials: { accessKeyId: testAccessKeyId, secretAccessKey: testKeyMaterial },
        region: testRegion,
        service: "sqs",
        extraSignedHeaders: { "content-type": "application/x-www-form-urlencoded" },
        nowMs: amzDateToMs(amzDate),
      });
      assert.equal(authorization, recomputed.authorization);
      assert.equal(amzDate, recomputed.amzDate);
      const params = new URLSearchParams(post.rawBody);
      assert.equal(params.get("Action"), "SendMessage");
      assert.equal(params.get("MessageBody"), delivery.body);
      assert.equal(params.get("MessageAttribute.1.StringValue"), "tenant-7");
      assert.equal(params.get("MessageAttribute.2.StringValue"), "trace-1");
    } finally {
      server.close();
    }
  });

  it("maps a 503 + Retry-After to retryable and a 400 to non_retryable", async () => {
    const seen: SeenPost[] = [];
    const server = stubQueue(seen, (all) =>
      all.length === 1
        ? { status: 503, body: "<Error/>", headers: { "retry-after": "2" } }
        : { status: 400, body: "<Error/>" }
    );
    const port = await listen(server);
    try {
      const sink = new SqsSink(baseConfig(`http://127.0.0.1:${port}/000000000000/events`));
      await assert.rejects(sink.send({ body: "{}" }), (err: unknown) => {
        assert.ok(err instanceof SqsSinkError);
        assert.equal(err.statusCode, 503);
        assert.equal(err.retryAfterMs, 2000);
        const classified = classifyFailure(err);
        assert.equal(classified.failureClass, "retryable");
        assert.equal(classified.retryAfterMs, 2000);
        return true;
      });
      await assert.rejects(sink.send({ body: "{}" }), (err: unknown) => {
        assert.ok(err instanceof SqsSinkError);
        assert.equal(err.statusCode, 400);
        assert.equal(classifyFailure(err).failureClass, "non_retryable");
        return true;
      });
      assert.deepEqual(sink.stats, { sent: 0, sendFailures: 2 });
    } finally {
      server.close();
    }
  });

  it("maps a missing secret to non_retryable without counting a send failure", async () => {
    const sink = new SqsSink(
      baseConfig("http://127.0.0.1:1/000000000000/events", {
        secretResolver: () => undefined,
      })
    );
    await assert.rejects(sink.send({ body: "{}" }), (err: unknown) => {
      assert.ok(err instanceof SqsSinkConfigError);
      assert.equal(err.secretRef, "unused-when-injected");
      assert.equal(classifyFailure(err).failureClass, "non_retryable");
      return true;
    });
    assert.deepEqual(sink.stats, { sent: 0, sendFailures: 0 });
  });

  it("maps a transport failure to retryable", async () => {
    // A port that was listening and is now closed: deterministic
    // connection-refused without depending on a real SQS endpoint.
    const probe = createServer();
    const port = await listen(probe);
    probe.close();
    const sink = new SqsSink(baseConfig(`http://127.0.0.1:${port}/000000000000/events`));
    await assert.rejects(sink.send({ body: "{}" }), (err: unknown) => {
      assert.ok(err instanceof SqsSinkError);
      assert.equal(err.statusCode, undefined);
      assert.equal(classifyFailure(err).failureClass, "retryable");
      return true;
    });
    assert.deepEqual(sink.stats, { sent: 0, sendFailures: 1 });
  });

  it("times out a hung queue instead of hanging the delivery", async () => {
    const server = createServer(() => {
      // Never responds: the sink's request timeout must fire.
    });
    const port = await listen(server);
    try {
      const sink = new SqsSink(
        baseConfig(`http://127.0.0.1:${port}/000000000000/events`, { requestTimeoutMs: 50 })
      );
      await assert.rejects(sink.send({ body: "{}" }), /timed out after 50ms/);
    } finally {
      server.close();
    }
  });

  it("dryRun performs zero I/O and still validates the delivery shape", async () => {
    const sink = new SqsSink(
      baseConfig("http://127.0.0.1:1/000000000000/events", { dryRun: true })
    );
    assert.deepEqual(await sink.send({ body: "{}" }), { ok: true, dryRun: true });
    assert.deepEqual(sink.stats, { sent: 0, sendFailures: 0 });
    await assert.rejects(sink.send({ body: "" }), /body.*non-empty/);
  });
});

