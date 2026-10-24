import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, request as httpRequest, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  buildCloudEventEnvelope,
  assertValidCloudEventsConfig,
  CLOUD_EVENTS_STRUCTURED_CONTENT_TYPE,
  CLOUD_EVENTS_SPEC_VERSION,
  type CloudEventsEndpointConfig,
} from "../src/cloudevents.ts";
import { createDefaultSender, createRelayServer } from "../src/server.ts";
import { signSha256, verifySignature } from "../src/verify.ts";
import { AuditLog } from "../src/audit.ts";
import type { RetryItem } from "../src/retry.ts";

// Lowercase names on purpose: the runtime's secret redaction rewrites
// all-caps SECRET-like identifiers in test sources.
const inboundSecret = "relay-inbound-test-secret";
const outboundKey = "relay-outbound-signing-key";
const ceSource = "https://relay.example.com";
const ceType = "com.example.relay.webhook.delivered";

async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");
  return addr.port;
}

function baseConfig(extra: Partial<CloudEventsEndpointConfig> = {}): CloudEventsEndpointConfig {
  return {
    source: ceSource,
    type: ceType,
    nowMs: () => 1_700_000_000_000,
    randomId: () => "fixed-random-id",
    ...extra,
  };
}

describe("WR-207: CloudEvents 1.0 structured envelope", () => {
  it("wraps a JSON payload as `data` with the required attributes", () => {
    const payload = Buffer.from(JSON.stringify({ order: 42, tags: ["a", "b"] }));
    const env = JSON.parse(
      buildCloudEventEnvelope(payload, { id: "item-1", traceId: "trace-9" }, baseConfig()).toString("utf8")
    );
    assert.equal(env.specversion, CLOUD_EVENTS_SPEC_VERSION);
    assert.equal(env.id, "trace-9"); // the delivery traceId becomes ce-id
    assert.equal(env.source, ceSource);
    assert.equal(env.type, ceType);
    assert.equal(env.time, new Date(1_700_000_000_000).toISOString());
    assert.equal(env.datacontenttype, "application/json");
    assert.deepEqual(env.data, { order: 42, tags: ["a", "b"] });
    assert.ok(!("data_base64" in env), "data and data_base64 are mutually exclusive");
    assert.ok(!("subject" in env));
  });

  it("wraps a non-JSON payload as `data_base64` (binary-safe)", () => {
    const raw = Buffer.from([0x00, 0xff, 0x01, 0xfe]);
    const env = JSON.parse(
      buildCloudEventEnvelope(raw, { traceId: "trace-b" }, baseConfig()).toString("utf8")
    );
    assert.equal(env.datacontenttype, "application/octet-stream");
    assert.equal(env.data_base64, raw.toString("base64"));
    assert.ok(!("data" in env), "data and data_base64 are mutually exclusive");
    assert.deepEqual(Buffer.from(env.data_base64, "base64"), raw);
  });

  it("falls back to a generated id with idPrefix when no traceId is known", () => {
    const env = JSON.parse(
      buildCloudEventEnvelope(
        Buffer.from("{}"),
        {},
        baseConfig({ idPrefix: "evt-" })
      ).toString("utf8")
    );
    assert.equal(env.id, "evt-fixed-random-id");
  });

  it("stamps subject, extensions and a datacontenttype override", () => {
    const env = JSON.parse(
      buildCloudEventEnvelope(
        Buffer.from(JSON.stringify({ x: 1 })),
        { traceId: "t" },
        baseConfig({
          subject: "orders/42",
          datacontenttype: "application/vnd.example+json",
          extensions: { partitionkey: "p1", redelivered: true, seq: 7 },
        })
      ).toString("utf8")
    );
    assert.equal(env.subject, "orders/42");
    assert.equal(env.datacontenttype, "application/vnd.example+json");
    assert.equal(env.partitionkey, "p1");
    assert.equal(env.redelivered, true);
    assert.equal(env.seq, 7);
  });

  it("rejects invalid configs with RangeError (startup fail-fast)", () => {
    assert.throws(() => assertValidCloudEventsConfig({}, "ce"), RangeError);
    assert.throws(
      () => assertValidCloudEventsConfig({ source: "", type: ceType }, "ce"),
      RangeError
    );
    assert.throws(
      () => assertValidCloudEventsConfig({ source: ceSource, type: "" }, "ce"),
      RangeError
    );
    assert.throws(
      () =>
        assertValidCloudEventsConfig(
          { source: ceSource, type: ceType, extensions: { "Bad Name": 1 } },
          "ce"
        ),
      RangeError
    );
    assert.throws(
      () =>
        assertValidCloudEventsConfig(
          { source: ceSource, type: ceType, extensions: { data: "shadow" } },
          "ce"
        ),
      /reserved/
    );
    assert.throws(
      () =>
        assertValidCloudEventsConfig(
          { source: ceSource, type: ceType, extensions: { ok: null } },
          "ce"
        ),
      RangeError
    );
    assert.throws(
      () =>
        assertValidCloudEventsConfig(
          { source: ceSource, type: ceType, nowMs: "nope" },
          "ce"
        ),
      RangeError
    );
    // The envelope builder validates too: a bad config never emits a
    // malformed envelope mid-delivery.
    assert.throws(
      () => buildCloudEventEnvelope(Buffer.from("{}"), {}, { source: "", type: ceType }),
      RangeError
    );
  });
});

describe("WR-207: sender integration (envelope before signing)", () => {
  let stub: Server;
  let stubPort: number;
  const seen: Array<{ headers: Record<string, unknown>; body: Buffer }> = [];

  before(async () => {
    stub = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        seen.push({ headers: { ...req.headers }, body: Buffer.concat(chunks) });
        res.writeHead(200).end("ok");
      });
    });
    stubPort = await listen(stub);
  });

  after(async () => {
    stub.close();
    await new Promise((r) => stub.once("close", r));
  });

  const endpoint = () => `http://127.0.0.1:${stubPort}/hook`;

  function item(): RetryItem {
    return {
      id: "item-ce-1",
      traceId: "trace-ce-1",
      payload: Buffer.from(JSON.stringify({ hello: "cloudevents" })),
      targetUrl: endpoint(),
      headers: {},
    };
  }

  async function deliverAndWait(
    sender: (i: RetryItem) => Promise<void>
  ): Promise<{ headers: Record<string, unknown>; body: Buffer }> {
    seen.length = 0;
    await sender(item());
    const deadline = Date.now() + 5000;
    while (seen.length === 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    assert.equal(seen.length, 1);
    return seen[0];
  }

  // createDefaultSender's cloudEvents is the last of 46 positional
  // params; everything between outboundSigning and it stays default.
  function senderWithCloudEvents(
    ce: Record<string, CloudEventsEndpointConfig>,
    signing?: { secret: string }
  ) {
    return createDefaultSender(
      undefined,
      false,
      signing,
      ...Array<undefined>(42).fill(undefined),
      ce
    );
  }

  it("sends the CloudEvents envelope and x-relay-signature covers the envelope bytes", async () => {
    const sender = senderWithCloudEvents(
      { [endpoint()]: { source: ceSource, type: ceType } },
      { secret: outboundKey }
    );
    try {
      const got = await deliverAndWait(sender);
      assert.equal(got.headers["content-type"], CLOUD_EVENTS_STRUCTURED_CONTENT_TYPE);
      const env = JSON.parse(got.body.toString("utf8"));
      assert.equal(env.specversion, "1.0");
      assert.equal(env.id, "trace-ce-1");
      assert.deepEqual(env.data, { hello: "cloudevents" });
      // The downstream contract: the relay signature verifies over the
      // exact envelope bytes received — never over the raw payload.
      const sig = String(got.headers["x-relay-signature"]);
      assert.equal(sig, signSha256(got.body, outboundKey));
      assert.ok(verifySignature(got.body, sig, outboundKey));
      assert.ok(!verifySignature(got.body, sig, "wrong-key"));
    } finally {
      sender.destroy();
    }
  });

  it("leaves the payload byte-identical when the endpoint has no CloudEvents record", async () => {
    const sender = senderWithCloudEvents({ "http://other.example/hook": { source: ceSource, type: ceType } });
    try {
      const got = await deliverAndWait(sender);
      assert.deepEqual(got.body, item().payload);
      assert.notEqual(got.headers["content-type"], CLOUD_EVENTS_STRUCTURED_CONTENT_TYPE);
    } finally {
      sender.destroy();
    }
  });

  it("createDefaultSender fails fast on an invalid CloudEvents config", () => {
    assert.throws(
      () =>
        senderWithCloudEvents({
          [endpoint()]: { source: "", type: ceType } as CloudEventsEndpointConfig,
        }),
      (err: unknown) =>
        err instanceof RangeError && /CloudEvents config/.test((err as Error).message)
    );
  });

  it("end-to-end through createRelayServer: intake -> envelope -> signed delivery", async () => {
    const dir = mkdtempSync(join(tmpdir(), "ce-audit-"));
    const audit = new AuditLog(join(dir, "audit.jsonl"));
    const relay = createRelayServer({
      secret: inboundSecret,
      forwardUrl: endpoint(),
      auditLog: audit,
      retry: { baseDelayMs: 10, jitterMs: 0, maxAttempts: 3 },
      cloudEvents: { [endpoint()]: { source: ceSource, type: ceType } },
      outboundSigning: { secret: outboundKey },
    });
    const relayPort = await listen(relay);
    try {
      seen.length = 0;
      const body = Buffer.from(JSON.stringify({ via: "relay" }));
      const res = await new Promise<{ status: number }>((resolve, reject) => {
        const r = httpRequest(
          {
            host: "127.0.0.1",
            port: relayPort,
            path: "/",
            method: "POST",
            headers: {
              "x-signature": signSha256(body, inboundSecret),
              "content-type": "application/json",
            },
          },
          (resp) => {
            resp.on("data", () => undefined);
            resp.on("end", () => resolve({ status: resp.statusCode ?? 0 }));
          }
        );
        r.on("error", reject);
        r.end(body);
      });
      assert.equal(res.status, 202);
      const deadline = Date.now() + 8000;
      while (seen.length === 0 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 25));
      }
      assert.equal(seen.length, 1);
      const env = JSON.parse(seen[0].body.toString("utf8"));
      assert.equal(env.specversion, "1.0");
      assert.deepEqual(env.data, { via: "relay" });
      assert.ok(
        verifySignature(seen[0].body, String(seen[0].headers["x-relay-signature"]), outboundKey),
        "server-level: x-relay-signature must cover the envelope bytes"
      );
    } finally {
      relay.close();
    }
  });
});
